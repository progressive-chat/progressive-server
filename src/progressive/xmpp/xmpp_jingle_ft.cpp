// =============================================================================
// xmpp_jingle_ft.cpp
// XMPP Jingle, File Transfer, and HTTP Upload Implementation
// =============================================================================
// Implements:
//   XEP-0166 (Jingle) - session management, content-add/remove, security preconditions
//   XEP-0167 (Jingle RTP Sessions) - codec negotiation, parameters
//   XEP-0176 (Jingle ICE-UDP Transport) - candidates, credentials
//   XEP-0261 (Jingle IBB Transport) - in-band bytestream fallback
//   XEP-0260 (Jingle SOCKS5 Transport) - SOCKS5 bytestream proxy
//   XEP-0234 (Jingle File Transfer) - file description, hash, size
//   XEP-0264 (Jingle FT Thumbnails) - thumbnail previews
//   XEP-0363 (HTTP File Upload) - slot request, upload, download
//   XEP-0047 (In-Band Bytestreams) - base64 data chunks
//   XEP-0065 (SOCKS5 Bytestreams) - proxy negotiation
//   XEP-0095 (Stream Initiation)
//   XEP-0096 (SI File Transfer)
// =============================================================================

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <ctime>
#include <algorithm>
#include <mutex>
#include <functional>
#include <sstream>
#include <cstdint>
#include <cstring>
#include <random>
#include <iomanip>
#include <set>
#include <deque>
#include <chrono>
#include <stdexcept>
#include <cassert>

namespace progressive {
namespace xmpp {

// ============================================================================
// Forward declarations
// ============================================================================

class JingleSession;
class JingleContent;
class JingleTransport;
class JingleDescription;
class IceCandidate;
class FileTransferOffer;
class HttpUploadSlot;
class HttpUploadService;
class Socks5BytestreamProxy;
class IBBStream;
class SIStream;
class JingleManager;

// ============================================================================
// XMPP Namespace URIs for Jingle and File Transfer
// ============================================================================

namespace XMPPNS {
    const char* JINGLE                    = "urn:xmpp:jingle:1";
    const char* JINGLE_ERRORS             = "urn:xmpp:jingle:errors:1";
    const char* JINGLE_APPS_RTP           = "urn:xmpp:jingle:apps:rtp:1";
    const char* JINGLE_APPS_RTP_INFO      = "urn:xmpp:jingle:apps:rtp:info:1";
    const char* JINGLE_APPS_RTP_AUDIO     = "urn:xmpp:jingle:apps:rtp:audio";
    const char* JINGLE_APPS_RTP_VIDEO     = "urn:xmpp:jingle:apps:rtp:video";
    const char* JINGLE_APPS_FILE_TRANSFER = "urn:xmpp:jingle:apps:file-transfer:5";
    const char* JINGLE_APPS_FT_THUMB      = "urn:xmpp:thumbs:1";
    const char* JINGLE_TRANSPORT_ICE      = "urn:xmpp:jingle:transports:ice-udp:1";
    const char* JINGLE_TRANSPORT_IBB      = "urn:xmpp:jingle:transports:ibb:1";
    const char* JINGLE_TRANSPORT_S5B      = "urn:xmpp:jingle:transports:s5b:1";
    const char* JINGLE_SECURITY           = "urn:xmpp:jingle:security:1";
    const char* JINGLE_DTLS               = "urn:xmpp:jingle:apps:dtls:0";
    const char* JINGLE_CONTENT            = "urn:xmpp:jingle:content:1";
    const char* IBB                       = "http://jabber.org/protocol/ibb";
    const char* SOCKS5                    = "http://jabber.org/protocol/bytestreams";
    const char* SI                        = "http://jabber.org/protocol/si";
    const char* SI_FILE_TRANSFER          = "http://jabber.org/protocol/si/profile/file-transfer";
    const char* HTTP_UPLOAD               = "urn:xmpp:http:upload:0";
    const char* HTTP_UPLOAD_OLD           = "urn:xmpp:http:upload";
    const char* HASH                      = "urn:xmpp:hashes:2";
    const char* HASH_SHA256               = "urn:xmpp:hash-function-text-names:sha-256";
    const char* HASH_SHA512               = "urn:xmpp:hash-function-text-names:sha-512";
    const char* HASH_SHA1                 = "urn:xmpp:hash-function-text-names:sha-1";
    const char* DISCO_INFO                = "http://jabber.org/protocol/disco#info";
    const char* DISCO_ITEMS               = "http://jabber.org/protocol/disco#items";
    const char* X_DATA                    = "jabber:x:data";
    const char* DELAY2                    = "urn:xmpp:delay";
}

// ============================================================================
// Jingle Error Conditions per XEP-0166
// ============================================================================

namespace JingleError {
    const char* OUT_OF_ORDER             = "out-of-order";
    const char* UNKNOWN_SESSION          = "unknown-session";
    const char* UNSUPPORTED_CONTENT      = "unsupported-content";
    const char* UNSUPPORTED_TRANSPORTS   = "unsupported-transports";
    const char* UNSUPPORTED_INFO         = "unsupported-info";
    const char* NO_GROUP                 = "no-group";
    const char* MISMATCHED_CONTENT       = "mismatched-content";
    const char* SECURITY_REQUIRED        = "security-required";
    const char* TIE_BREAK                = "tie-break";
    const char* EXPIRED                  = "expired";
}

// ============================================================================
// Jingle Session States
// ============================================================================

enum class JingleState {
    IDLE            = 0,
    PENDING         = 1,
    ACTIVE          = 2,
    ENDING          = 3,
    ENDED           = 4
};

enum class JingleAction {
    UNKNOWN,
    CONTENT_ACCEPT,
    CONTENT_ADD,
    CONTENT_MODIFY,
    CONTENT_REJECT,
    CONTENT_REMOVE,
    DESCRIPTION_INFO,
    SECURITY_INFO,
    SESSION_ACCEPT,
    SESSION_INFO,
    SESSION_INITIATE,
    SESSION_TERMINATE,
    TRANSPORT_ACCEPT,
    TRANSPORT_INFO,
    TRANSPORT_REJECT,
    TRANSPORT_REPLACE
};

enum class JingleReason {
    UNKNOWN_REASON,
    SUCCESS,
    DECLINE,
    CANCEL,
    EXPIRED,
    GONE,
    MEDIA_FAILURE,
    NO_CONNECTIVITY,
    INCOMPATIBLE_PARAMETERS,
    GENERAL_ERROR,
    FAILED_APPLICATION,
    FAILED_TRANSPORT,
    ALTERNATIVE_SESSION,
    SECURITY_ERROR,
    CONNECTIVITY_ERROR,
    TIMEOUT
};

enum class JingleRole {
    INITIATOR,
    RESPONDER
};

enum class IceCandidateType {
    HOST,
    SRFLX,
    PRFLX,
    RELAY
};

enum class TransportType {
    ICE_UDP,
    IBB,
    SOCKS5,
    RAW_UDP,
    UNKNOWN
};

enum class FileTransferState {
    OFFERED,
    NEGOTIATING,
    IN_PROGRESS,
    COMPLETED,
    CANCELLED,
    FAILED
};

enum class HttpUploadSlotState {
    ALLOCATED,
    UPLOADING,
    COMPLETED,
    EXPIRED,
    ERROR
};

// ============================================================================
// Utility: xml_escape
// ============================================================================

static std::string xml_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '\"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:   out += c; break;
        }
    }
    return out;
}

// ============================================================================
// Utility: random ID generation
// ============================================================================

static std::string generate_id(const std::string& prefix = "") {
    static std::mutex mtx;
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dist;

    std::lock_guard<std::mutex> lock(mtx);
    uint64_t val = dist(gen);
    std::ostringstream oss;
    oss << prefix << std::hex << std::setfill('0') << std::setw(16) << val;
    return oss.str();
}

static std::string generate_ufrag(int length = 8) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
    static std::mutex mtx;
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dist(0, 63);

    std::lock_guard<std::mutex> lock(mtx);
    std::string out;
    out.reserve(length);
    for (int i = 0; i < length; ++i) {
        out += chars[dist(gen)];
    }
    return out;
}

static std::string generate_password(int length = 32) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
    static std::mutex mtx;
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dist(0, 63);

    std::lock_guard<std::mutex> lock(mtx);
    std::string out;
    out.reserve(length);
    for (int i = 0; i < length; ++i) {
        out += chars[dist(gen)];
    }
    return out;
}

// ============================================================================
// Utility: Base64 encoding/decoding for IBB
// ============================================================================

static const char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        out += base64_table[(n >> 18) & 0x3F];
        out += base64_table[(n >> 12) & 0x3F];
        out += (i + 1 < len) ? base64_table[(n >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? base64_table[n & 0x3F] : '=';
    }
    return out;
}

static std::string base64_encode(const std::string& data) {
    return base64_encode(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

static std::vector<uint8_t> base64_decode(const std::string& encoded) {
    static int decode_table[256];
    static bool initialized = false;
    if (!initialized) {
        for (int i = 0; i < 256; ++i) decode_table[i] = -1;
        for (int i = 0; i < 64; ++i) decode_table[(uint8_t)base64_table[i]] = i;
        initialized = true;
    }

    std::vector<uint8_t> out;
    out.reserve((encoded.size() / 4) * 3);
    int val = 0, valb = -8;
    for (char c : encoded) {
        if (c == '=') break;
        int idx = decode_table[(uint8_t)c];
        if (idx == -1) continue;
        val = (val << 6) + idx;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// ============================================================================
// SHA-256 Implementation (for file hashing per XEP-0300)
// ============================================================================

class SHA256 {
public:
    SHA256() { reset(); }

    void reset() {
        h_[0] = 0x6a09e667; h_[1] = 0xbb67ae85;
        h_[2] = 0x3c6ef372; h_[3] = 0xa54ff53a;
        h_[4] = 0x510e527f; h_[5] = 0x9b05688c;
        h_[6] = 0x1f83d9ab; h_[7] = 0x5be0cd19;
        total_bits_ = 0;
        buf_index_ = 0;
    }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            block_[buf_index_++] = data[i];
            total_bits_ += 8;
            if (buf_index_ == 64) {
                transform_block();
                buf_index_ = 0;
            }
        }
    }

    void update(const std::string& s) {
        update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    std::string finalize() {
        block_[buf_index_++] = 0x80;
        if (buf_index_ > 56) {
            while (buf_index_ < 64) block_[buf_index_++] = 0;
            transform_block();
            buf_index_ = 0;
        }
        while (buf_index_ < 56) block_[buf_index_++] = 0;
        uint64_t bits = total_bits_;
        for (int i = 7; i >= 0; --i) {
            block_[56 + i] = static_cast<uint8_t>(bits & 0xFF);
            bits >>= 8;
        }
        transform_block();
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (int i = 0; i < 8; ++i) {
            oss << std::setw(8) << h_[i];
        }
        std::string hex = oss.str();
        reset();
        return hex;
    }

    static std::string hash(const std::string& data) {
        SHA256 s;
        s.update(data);
        return s.finalize();
    }

private:
    void transform_block() {
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block_[i * 4]) << 24) |
                   (static_cast<uint32_t>(block_[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block_[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(block_[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        uint32_t e = h_[4], f = h_[5], g = h_[6], i_val = h_[7];

        for (int j = 0; j < 64; ++j) {
            uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = i_val + S1 + ch + k[j] + w[j];
            uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            i_val = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
        h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += i_val;
    }

    static uint32_t rotr32(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }

    uint32_t h_[8];
    uint64_t total_bits_;
    uint8_t block_[64];
    int buf_index_;
};

// ============================================================================
// SHA-512 Implementation (for file hashing)
// ============================================================================

class SHA512 {
public:
    SHA512() { reset(); }

    void reset() {
        h_[0] = 0x6a09e667f3bcc908ULL; h_[1] = 0xbb67ae8584caa73bULL;
        h_[2] = 0x3c6ef372fe94f82bULL; h_[3] = 0xa54ff53a5f1d36f1ULL;
        h_[4] = 0x510e527fade682d1ULL; h_[5] = 0x9b05688c2b3e6c1fULL;
        h_[6] = 0x1f83d9abfb41bd6bULL; h_[7] = 0x5be0cd19137e2179ULL;
        total_bits_ = 0;
        buf_index_ = 0;
    }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            block_[buf_index_++] = data[i];
            total_bits_ += 8;
            if (buf_index_ == 128) {
                transform_block();
                buf_index_ = 0;
            }
        }
    }

    void update(const std::string& s) {
        update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    std::string finalize() {
        block_[buf_index_++] = 0x80;
        if (buf_index_ > 112) {
            while (buf_index_ < 128) block_[buf_index_++] = 0;
            transform_block();
            buf_index_ = 0;
        }
        while (buf_index_ < 112) block_[buf_index_++] = 0;
        uint64_t bits = total_bits_;
        for (int i = 7; i >= 0; --i) {
            block_[120 + i] = static_cast<uint8_t>(bits & 0xFF);
            bits >>= 8;
        }
        transform_block();
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (int i = 0; i < 8; ++i) {
            oss << std::setw(16) << h_[i];
        }
        std::string hex = oss.str();
        reset();
        return hex;
    }

    static std::string hash(const std::string& data) {
        SHA512 s;
        s.update(data);
        return s.finalize();
    }

private:
    void transform_block() {
        static const uint64_t k[80] = {
            0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
            0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
            0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
            0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
            0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
            0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
            0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
            0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
            0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
            0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
            0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
            0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
            0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
            0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
            0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
            0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
            0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
            0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
            0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
            0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
            0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
            0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
            0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
            0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
            0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
            0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
            0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
            0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
            0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
            0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
            0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
            0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
            0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
            0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
            0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
            0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
        };

        uint64_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint64_t>(block_[i * 8]) << 56) |
                   (static_cast<uint64_t>(block_[i * 8 + 1]) << 48) |
                   (static_cast<uint64_t>(block_[i * 8 + 2]) << 40) |
                   (static_cast<uint64_t>(block_[i * 8 + 3]) << 32) |
                   (static_cast<uint64_t>(block_[i * 8 + 4]) << 24) |
                   (static_cast<uint64_t>(block_[i * 8 + 5]) << 16) |
                   (static_cast<uint64_t>(block_[i * 8 + 6]) << 8) |
                   static_cast<uint64_t>(block_[i * 8 + 7]);
        }
        for (int i = 16; i < 80; ++i) {
            uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
            uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint64_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        uint64_t e = h_[4], f = h_[5], g = h_[6], i_val = h_[7];

        for (int j = 0; j < 80; ++j) {
            uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
            uint64_t ch = (e & f) ^ ((~e) & g);
            uint64_t temp1 = i_val + S1 + ch + k[j] + w[j];
            uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t temp2 = S0 + maj;

            i_val = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
        h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += i_val;
    }

    static uint64_t rotr64(uint64_t x, int n) {
        return (x >> n) | (x << (64 - n));
    }

    uint64_t h_[8];
    uint64_t total_bits_;
    uint8_t block_[128];
    int buf_index_;
};

// ============================================================================
// Utility: Hex encoding
// ============================================================================

static std::string hex_encode(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += hex_chars[(data[i] >> 4) & 0xF];
        out += hex_chars[data[i] & 0xF];
    }
    return out;
}

// ============================================================================
// Utility: Timestamp helpers
// ============================================================================

static std::string timestamp_now() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    gmtime_r(&t, &tm_buf);
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

static int64_t now_ms() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

// ============================================================================
// Jingle action to/from string
// ============================================================================

static JingleAction jingle_action_from_string(const std::string& action) {
    if (action == "content-accept")     return JingleAction::CONTENT_ACCEPT;
    if (action == "content-add")        return JingleAction::CONTENT_ADD;
    if (action == "content-modify")     return JingleAction::CONTENT_MODIFY;
    if (action == "content-reject")     return JingleAction::CONTENT_REJECT;
    if (action == "content-remove")     return JingleAction::CONTENT_REMOVE;
    if (action == "description-info")   return JingleAction::DESCRIPTION_INFO;
    if (action == "security-info")      return JingleAction::SECURITY_INFO;
    if (action == "session-accept")     return JingleAction::SESSION_ACCEPT;
    if (action == "session-info")       return JingleAction::SESSION_INFO;
    if (action == "session-initiate")   return JingleAction::SESSION_INITIATE;
    if (action == "session-terminate")  return JingleAction::SESSION_TERMINATE;
    if (action == "transport-accept")   return JingleAction::TRANSPORT_ACCEPT;
    if (action == "transport-info")     return JingleAction::TRANSPORT_INFO;
    if (action == "transport-reject")   return JingleAction::TRANSPORT_REJECT;
    if (action == "transport-replace")  return JingleAction::TRANSPORT_REPLACE;
    return JingleAction::UNKNOWN;
}

static std::string jingle_action_to_string(JingleAction action) {
    switch (action) {
        case JingleAction::CONTENT_ACCEPT:    return "content-accept";
        case JingleAction::CONTENT_ADD:       return "content-add";
        case JingleAction::CONTENT_MODIFY:    return "content-modify";
        case JingleAction::CONTENT_REJECT:    return "content-reject";
        case JingleAction::CONTENT_REMOVE:    return "content-remove";
        case JingleAction::DESCRIPTION_INFO:  return "description-info";
        case JingleAction::SECURITY_INFO:     return "security-info";
        case JingleAction::SESSION_ACCEPT:    return "session-accept";
        case JingleAction::SESSION_INFO:      return "session-info";
        case JingleAction::SESSION_INITIATE:  return "session-initiate";
        case JingleAction::SESSION_TERMINATE: return "session-terminate";
        case JingleAction::TRANSPORT_ACCEPT:  return "transport-accept";
        case JingleAction::TRANSPORT_INFO:    return "transport-info";
        case JingleAction::TRANSPORT_REJECT:  return "transport-reject";
        case JingleAction::TRANSPORT_REPLACE: return "transport-replace";
        default: return "unknown";
    }
}

static JingleReason jingle_reason_from_string(const std::string& reason) {
    if (reason == "success")                return JingleReason::SUCCESS;
    if (reason == "decline")                return JingleReason::DECLINE;
    if (reason == "cancel")                 return JingleReason::CANCEL;
    if (reason == "expired")                return JingleReason::EXPIRED;
    if (reason == "gone")                   return JingleReason::GONE;
    if (reason == "media-failure" ||
        reason == "media failure")          return JingleReason::MEDIA_FAILURE;
    if (reason == "no-connectivity" ||
        reason == "connectivity-error")     return JingleReason::NO_CONNECTIVITY;
    if (reason == "incompatible-parameters") return JingleReason::INCOMPATIBLE_PARAMETERS;
    if (reason == "general-error")          return JingleReason::GENERAL_ERROR;
    if (reason == "failed-application")     return JingleReason::FAILED_APPLICATION;
    if (reason == "failed-transport")       return JingleReason::FAILED_TRANSPORT;
    if (reason == "alternative-session")    return JingleReason::ALTERNATIVE_SESSION;
    if (reason == "security-error")         return JingleReason::SECURITY_ERROR;
    if (reason == "timeout")                return JingleReason::TIMEOUT;
    return JingleReason::UNKNOWN_REASON;
}

static std::string jingle_reason_to_string(JingleReason reason) {
    switch (reason) {
        case JingleReason::SUCCESS:                return "success";
        case JingleReason::DECLINE:                return "decline";
        case JingleReason::CANCEL:                 return "cancel";
        case JingleReason::EXPIRED:                return "expired";
        case JingleReason::GONE:                   return "gone";
        case JingleReason::MEDIA_FAILURE:          return "media-failure";
        case JingleReason::NO_CONNECTIVITY:        return "connectivity-error";
        case JingleReason::INCOMPATIBLE_PARAMETERS:return "incompatible-parameters";
        case JingleReason::GENERAL_ERROR:          return "general-error";
        case JingleReason::FAILED_APPLICATION:     return "failed-application";
        case JingleReason::FAILED_TRANSPORT:       return "failed-transport";
        case JingleReason::ALTERNATIVE_SESSION:    return "alternative-session";
        case JingleReason::SECURITY_ERROR:         return "security-error";
        case JingleReason::TIMEOUT:                return "timeout";
        default: return "general-error";
    }
}

// ============================================================================
// RTP Codec Definitions per XEP-0167
// ============================================================================

struct RTPCodec {
    std::string name;
    int id;
    int clock_rate;
    int channels;
    std::unordered_map<std::string, std::string> parameters;
    std::vector<std::string> feedback_types;

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<description xmlns=\"" << XMPPNS::JINGLE_APPS_RTP << "\"";
        if (!name.empty()) oss << " media=\"" << xml_escape(name) << "\"";
        oss << ">";

        for (const auto& [key, val] : parameters) {
            if (key != "pt" && key != "name" && key != "clockrate" && key != "channels") {
                oss << "<parameter name=\"" << xml_escape(key)
                    << "\" value=\"" << xml_escape(val) << "\"/>";
            }
        }

        oss << "<payload-type id=\"" << id
            << "\" name=\"" << xml_escape(name) << "\""
            << " clockrate=\"" << clock_rate << "\"";
        if (channels > 1) {
            oss << " channels=\"" << channels << "\"";
        }
        oss << ">";

        for (const auto& [key, val] : parameters) {
            if (key != "pt" && key != "name" && key != "clockrate" && key != "channels") {
                oss << "<parameter name=\"" << xml_escape(key)
                    << "\" value=\"" << xml_escape(val) << "\"/>";
            }
        }

        for (const auto& fb : feedback_types) {
            oss << "<rtcp-fb type=\"" << xml_escape(fb) << "\"/>";
        }

        oss << "</payload-type>";
        oss << "</description>";
        return oss.str();
    }
};

// ============================================================================
// Standard RTP Codecs
// ============================================================================

static std::vector<RTPCodec> get_standard_audio_codecs() {
    std::vector<RTPCodec> codecs;

    // PCMU (G.711 mu-law)
    {
        RTPCodec c;
        c.name = "audio";
        c.id = 0;
        c.clock_rate = 8000;
        c.channels = 1;
        c.parameters["pt"] = "0";
        c.parameters["name"] = "PCMU";
        codecs.push_back(c);
    }

    // PCMA (G.711 A-law)
    {
        RTPCodec c;
        c.name = "audio";
        c.id = 8;
        c.clock_rate = 8000;
        c.channels = 1;
        c.parameters["pt"] = "8";
        c.parameters["name"] = "PCMA";
        codecs.push_back(c);
    }

    // Opus
    {
        RTPCodec c;
        c.name = "audio";
        c.id = 111;
        c.clock_rate = 48000;
        c.channels = 2;
        c.parameters["pt"] = "111";
        c.parameters["name"] = "opus";
        c.parameters["minptime"] = "10";
        c.parameters["useinbandfec"] = "1";
        c.feedback_types = {"transport-cc"};
        codecs.push_back(c);
    }

    // G.722
    {
        RTPCodec c;
        c.name = "audio";
        c.id = 9;
        c.clock_rate = 8000;
        c.channels = 1;
        c.parameters["pt"] = "9";
        c.parameters["name"] = "G722";
        codecs.push_back(c);
    }

    // Speex narrowband
    {
        RTPCodec c;
        c.name = "audio";
        c.id = 110;
        c.clock_rate = 8000;
        c.channels = 1;
        c.parameters["pt"] = "110";
        c.parameters["name"] = "speex";
        codecs.push_back(c);
    }

    // Speex wideband
    {
        RTPCodec c;
        c.name = "audio";
        c.id = 112;
        c.clock_rate = 16000;
        c.channels = 1;
        c.parameters["pt"] = "112";
        c.parameters["name"] = "speex";
        codecs.push_back(c);
    }

    // GSM
    {
        RTPCodec c;
        c.name = "audio";
        c.id = 3;
        c.clock_rate = 8000;
        c.channels = 1;
        c.parameters["pt"] = "3";
        c.parameters["name"] = "GSM";
        codecs.push_back(c);
    }

    return codecs;
}

static std::vector<RTPCodec> get_standard_video_codecs() {
    std::vector<RTPCodec> codecs;

    // VP8
    {
        RTPCodec c;
        c.name = "video";
        c.id = 100;
        c.clock_rate = 90000;
        c.channels = 1;
        c.parameters["pt"] = "100";
        c.parameters["name"] = "VP8";
        c.feedback_types = {"ccm fir", "nack", "nack pli", "transport-cc"};
        codecs.push_back(c);
    }

    // VP9
    {
        RTPCodec c;
        c.name = "video";
        c.id = 101;
        c.clock_rate = 90000;
        c.channels = 1;
        c.parameters["pt"] = "101";
        c.parameters["name"] = "VP9";
        c.feedback_types = {"ccm fir", "nack", "nack pli", "transport-cc"};
        codecs.push_back(c);
    }

    // H.264/AVC
    {
        RTPCodec c;
        c.name = "video";
        c.id = 102;
        c.clock_rate = 90000;
        c.channels = 1;
        c.parameters["pt"] = "102";
        c.parameters["name"] = "H264";
        c.parameters["profile-level-id"] = "42e01f";
        c.parameters["packetization-mode"] = "0";
        c.feedback_types = {"ccm fir", "nack", "nack pli", "transport-cc"};
        codecs.push_back(c);
    }

    // H.265/HEVC
    {
        RTPCodec c;
        c.name = "video";
        c.id = 103;
        c.clock_rate = 90000;
        c.channels = 1;
        c.parameters["pt"] = "103";
        c.parameters["name"] = "H265";
        c.feedback_types = {"ccm fir", "nack", "nack pli"};
        codecs.push_back(c);
    }

    return codecs;
}

// ============================================================================
// ICE Candidate per XEP-0176
// ============================================================================

class IceCandidate {
public:
    IceCandidate()
        : component_(1), priority_(0), port_(0), type_(IceCandidateType::HOST) {}

    IceCandidate(const std::string& foundation, int component,
                  const std::string& protocol, int priority,
                  const std::string& ip, int port,
                  IceCandidateType type)
        : foundation_(foundation), component_(component),
          protocol_(protocol), priority_(priority),
          ip_(ip), port_(port), type_(type) {}

    const std::string& foundation() const { return foundation_; }
    void set_foundation(const std::string& f) { foundation_ = f; }

    int component() const { return component_; }
    void set_component(int c) { component_ = c; }

    const std::string& protocol() const { return protocol_; }
    void set_protocol(const std::string& p) { protocol_ = p; }

    int priority() const { return priority_; }
    void set_priority(int p) { priority_ = p; }

    const std::string& ip() const { return ip_; }
    void set_ip(const std::string& ip) { ip_ = ip; }

    int port() const { return port_; }
    void set_port(int p) { port_ = p; }

    IceCandidateType type() const { return type_; }
    void set_type(IceCandidateType t) { type_ = t; }

    const std::string& id() const { return id_; }
    void set_id(const std::string& id) { id_ = id; }

    const std::string& tcptype() const { return tcptype_; }
    void set_tcptype(const std::string& t) { tcptype_ = t; }

    const std::string& generation() const { return generation_; }
    void set_generation(const std::string& g) { generation_ = g; }

    const std::string& rel_addr() const { return rel_addr_; }
    void set_rel_addr(const std::string& addr) { rel_addr_ = addr; }

    int rel_port() const { return rel_port_; }
    void set_rel_port(int p) { rel_port_ = p; }

    static std::string type_to_string(IceCandidateType t) {
        switch (t) {
            case IceCandidateType::HOST:  return "host";
            case IceCandidateType::SRFLX: return "srflx";
            case IceCandidateType::PRFLX: return "prflx";
            case IceCandidateType::RELAY: return "relay";
        }
        return "host";
    }

    static IceCandidateType type_from_string(const std::string& s) {
        if (s == "srflx") return IceCandidateType::SRFLX;
        if (s == "prflx") return IceCandidateType::PRFLX;
        if (s == "relay") return IceCandidateType::RELAY;
        return IceCandidateType::HOST;
    }

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<candidate";
        if (!id_.empty()) oss << " id=\"" << xml_escape(id_) << "\"";
        oss << " component=\"" << component_ << "\"";
        oss << " foundation=\"" << xml_escape(foundation_) << "\"";
        oss << " ip=\"" << xml_escape(ip_) << "\"";
        oss << " port=\"" << port_ << "\"";
        oss << " priority=\"" << priority_ << "\"";
        oss << " protocol=\"" << xml_escape(protocol_) << "\"";
        oss << " type=\"" << type_to_string(type_) << "\"";
        if (!generation_.empty()) {
            oss << " generation=\"" << xml_escape(generation_) << "\"";
        }
        if (!tcptype_.empty()) {
            oss << " tcptype=\"" << xml_escape(tcptype_) << "\"";
        }
        if (!rel_addr_.empty()) {
            oss << " rel-addr=\"" << xml_escape(rel_addr_) << "\"";
            oss << " rel-port=\"" << rel_port_ << "\"";
        }
        oss << "/>";
        return oss.str();
    }

private:
    std::string foundation_;
    int component_;
    std::string protocol_;
    int priority_;
    std::string ip_;
    int port_;
    IceCandidateType type_;
    std::string id_;
    std::string tcptype_;
    std::string generation_;
    std::string rel_addr_;
    int rel_port_;
};

// ============================================================================
// Jingle Content - Represents a content element within a Jingle session
// ============================================================================

class JingleContent {
public:
    JingleContent()
        : senders_("both"), disposition_("session") {}

    JingleContent(const std::string& name, const std::string& creator)
        : name_(name), creator_(creator), senders_("both"), disposition_("session") {}

    const std::string& name() const { return name_; }
    void set_name(const std::string& n) { name_ = n; }

    const std::string& creator() const { return creator_; }
    void set_creator(const std::string& c) { creator_ = c; }

    const std::string& senders() const { return senders_; }
    void set_senders(const std::string& s) { senders_ = s; }

    const std::string& disposition() const { return disposition_; }
    void set_disposition(const std::string& d) { disposition_ = d; }

    const std::string& description_xml() const { return description_xml_; }
    void set_description_xml(const std::string& d) { description_xml_ = d; }

    const std::string& transport_xml() const { return transport_xml_; }
    void set_transport_xml(const std::string& t) { transport_xml_ = t; }

    const std::string& security_xml() const { return security_xml_; }
    void set_security_xml(const std::string& s) { security_xml_ = s; }

    const std::string& description_ns() const { return description_ns_; }
    void set_description_ns(const std::string& ns) { description_ns_ = ns; }

    const std::vector<std::string>& transport_ns() const { return transport_ns_; }
    void add_transport_ns(const std::string& ns) { transport_ns_.push_back(ns); }

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<content creator=\"" << xml_escape(creator_) << "\"";
        oss << " disposition=\"" << xml_escape(disposition_) << "\"";
        oss << " name=\"" << xml_escape(name_) << "\"";
        oss << " senders=\"" << xml_escape(senders_) << "\">";

        if (!description_xml_.empty()) {
            oss << description_xml_;
        }

        for (const auto& t : transport_xml_list_) {
            oss << t;
        }
        if (!transport_xml_.empty() && transport_xml_list_.empty()) {
            oss << transport_xml_;
        }

        if (!security_xml_.empty()) {
            oss << security_xml_;
        }

        oss << "</content>";
        return oss.str();
    }

    void add_transport_xml(const std::string& xml) {
        transport_xml_list_.push_back(xml);
    }

    const std::vector<std::string>& transport_xml_list() const {
        return transport_xml_list_;
    }

private:
    std::string name_;
    std::string creator_;
    std::string senders_;
    std::string disposition_;
    std::string description_xml_;
    std::string transport_xml_;
    std::string security_xml_;
    std::string description_ns_;
    std::vector<std::string> transport_ns_;
    std::vector<std::string> transport_xml_list_;
};

// ============================================================================
// FileTransferOffer - File description per XEP-0234
// ============================================================================

class FileTransferOffer {
public:
    FileTransferOffer()
        : size_(0), date_(""), media_type_("application/octet-stream") {}

    const std::string& name() const { return name_; }
    void set_name(const std::string& n) { name_ = n; }

    const std::string& description() const { return description_; }
    void set_description(const std::string& d) { description_ = d; }

    int64_t size() const { return size_; }
    void set_size(int64_t s) { size_ = s; }

    const std::string& date() const { return date_; }
    void set_date(const std::string& d) { date_ = d; }

    const std::string& media_type() const { return media_type_; }
    void set_media_type(const std::string& m) { media_type_ = m; }

    const std::string& hash_sha256() const { return hash_sha256_; }
    void set_hash_sha256(const std::string& h) { hash_sha256_ = h; }

    const std::string& hash_sha512() const { return hash_sha512_; }
    void set_hash_sha512(const std::string& h) { hash_sha512_ = h; }

    const std::string& hash_sha1() const { return hash_sha1_; }
    void set_hash_sha1(const std::string& h) { hash_sha1_ = h; }

    const std::vector<uint8_t>& thumbnail_data() const { return thumbnail_data_; }
    void set_thumbnail_data(const std::vector<uint8_t>& d) { thumbnail_data_ = d; }

    const std::string& thumbnail_media_type() const { return thumbnail_media_type_; }
    void set_thumbnail_media_type(const std::string& m) { thumbnail_media_type_ = m; }

    int thumbnail_width() const { return thumbnail_width_; }
    void set_thumbnail_width(int w) { thumbnail_width_ = w; }

    int thumbnail_height() const { return thumbnail_height_; }
    void set_thumbnail_height(int h) { thumbnail_height_ = h; }

    bool has_hash() const {
        return !hash_sha256_.empty() || !hash_sha512_.empty() || !hash_sha1_.empty();
    }

    std::string generate_hash_sha256(const std::string& file_data) {
        SHA256 sha;
        sha.update(file_data);
        hash_sha256_ = sha.finalize();
        return hash_sha256_;
    }

    std::string generate_hash_sha512(const std::string& file_data) {
        SHA512 sha;
        sha.update(file_data);
        hash_sha512_ = sha.finalize();
        return hash_sha512_;
    }

    std::string to_description_xml() const {
        std::ostringstream oss;
        oss << "<description xmlns=\"" << XMPPNS::JINGLE_APPS_FILE_TRANSFER << "\">";
        oss << "<offer>";
        oss << "<file>";

        if (!date_.empty()) {
            oss << "<date>" << xml_escape(date_) << "</date>";
        }
        if (!description_.empty()) {
            oss << "<desc>" << xml_escape(description_) << "</desc>";
        }
        if (!media_type_.empty()) {
            oss << "<media-type>" << xml_escape(media_type_) << "</media-type>";
        }
        if (!name_.empty()) {
            oss << "<name>" << xml_escape(name_) << "</name>";
        }

        if (size_ > 0) {
            oss << "<size>" << size_ << "</size>";
        }

        // Hashes
        if (!hash_sha256_.empty()) {
            oss << "<hash xmlns=\"" << XMPPNS::HASH
                << "\" algo=\"" << XMPPNS::HASH_SHA256
                << "\">" << xml_escape(hash_sha256_) << "</hash>";
        }
        if (!hash_sha512_.empty()) {
            oss << "<hash xmlns=\"" << XMPPNS::HASH
                << "\" algo=\"" << XMPPNS::HASH_SHA512
                << "\">" << xml_escape(hash_sha512_) << "</hash>";
        }
        if (!hash_sha1_.empty()) {
            oss << "<hash xmlns=\"" << XMPPNS::HASH
                << "\" algo=\"" << XMPPNS::HASH_SHA1
                << "\">" << xml_escape(hash_sha1_) << "</hash>";
        }

        oss << "</file>";

        // Thumbnail per XEP-0264
        if (!thumbnail_data_.empty()) {
            oss << "<thumbnail xmlns=\"" << XMPPNS::JINGLE_APPS_FT_THUMB << "\"";
            if (!thumbnail_media_type_.empty()) {
                oss << " media-type=\"" << xml_escape(thumbnail_media_type_) << "\"";
            }
            if (thumbnail_width_ > 0) {
                oss << " width=\"" << thumbnail_width_ << "\"";
            }
            if (thumbnail_height_ > 0) {
                oss << " height=\"" << thumbnail_height_ << "\"";
            }
            oss << ">" << base64_encode(thumbnail_data_.data(), thumbnail_data_.size())
                << "</thumbnail>";
        }

        oss << "</offer>";
        oss << "</description>";
        return oss.str();
    }

    std::string to_si_file_xml() const {
        std::ostringstream oss;
        oss << "<file xmlns=\"" << XMPPNS::SI_FILE_TRANSFER << "\"";
        if (!name_.empty()) {
            oss << " name=\"" << xml_escape(name_) << "\"";
        }
        if (size_ > 0) {
            oss << " size=\"" << size_ << "\"";
        }
        oss << ">";
        if (!date_.empty()) {
            oss << "<date>" << xml_escape(date_) << "</date>";
        }
        if (!description_.empty()) {
            oss << "<desc>" << xml_escape(description_) << "</desc>";
        }
        if (!media_type_.empty()) {
            oss << "<media-type>" << xml_escape(media_type_) << "</media-type>";
        }
        if (!hash_sha256_.empty()) {
            oss << "<hash xmlns=\"" << XMPPNS::HASH
                << "\" algo=\"" << XMPPNS::HASH_SHA256
                << "\">" << xml_escape(hash_sha256_) << "</hash>";
        }
        if (!hash_sha1_.empty()) {
            oss << "<hash xmlns=\"" << XMPPNS::HASH
                << "\" algo=\"" << XMPPNS::HASH_SHA1
                << "\">" << xml_escape(hash_sha1_) << "</hash>";
        }
        oss << "</file>";
        return oss.str();
    }

private:
    std::string name_;
    std::string description_;
    int64_t size_;
    std::string date_;
    std::string media_type_;
    std::string hash_sha256_;
    std::string hash_sha512_;
    std::string hash_sha1_;
    std::vector<uint8_t> thumbnail_data_;
    std::string thumbnail_media_type_;
    int thumbnail_width_;
    int thumbnail_height_;
};

// ============================================================================
// Jingle Session - Full session state per XEP-0166
// ============================================================================

class JingleSession {
public:
    JingleSession()
        : state_(JingleState::PENDING)
        , role_(JingleRole::INITIATOR)
        , created_at_(now_ms())
        , last_activity_(now_ms())
        , timeout_ms_(30000)
    {}

    JingleSession(const std::string& sid, const std::string& initiator,
                  const std::string& responder)
        : sid_(sid), initiator_(initiator), responder_(responder)
        , state_(JingleState::PENDING)
        , role_(JingleRole::INITIATOR)
        , created_at_(now_ms())
        , last_activity_(now_ms())
        , timeout_ms_(30000) {}

    const std::string& sid() const { return sid_; }
    void set_sid(const std::string& s) { sid_ = s; }

    const std::string& initiator() const { return initiator_; }
    void set_initiator(const std::string& i) { initiator_ = i; }

    const std::string& responder() const { return responder_; }
    void set_responder(const std::string& r) { responder_ = r; }

    JingleState state() const { return state_; }
    void set_state(JingleState s) { state_ = s; }

    JingleRole role() const { return role_; }
    void set_role(JingleRole r) { role_ = r; }

    int64_t created_at() const { return created_at_; }
    int64_t last_activity() const { return last_activity_; }
    void update_activity() { last_activity_ = now_ms(); }

    int timeout_ms() const { return timeout_ms_; }
    void set_timeout_ms(int ms) { timeout_ms_ = ms; }

    bool is_expired() const {
        return (now_ms() - last_activity_) > timeout_ms_;
    }

    const std::string& tie_breaker() const { return tie_breaker_; }
    void set_tie_breaker(const std::string& t) { tie_breaker_ = t; }

    // Content management
    JingleContent* add_content(const std::string& name, const std::string& creator) {
        auto c = std::make_unique<JingleContent>(name, creator);
        JingleContent* ptr = c.get();
        contents_.push_back(std::move(c));
        content_map_[name] = ptr;
        return ptr;
    }

    JingleContent* get_content(const std::string& name) {
        auto it = content_map_.find(name);
        return it != content_map_.end() ? it->second : nullptr;
    }

    bool remove_content(const std::string& name) {
        auto it = content_map_.find(name);
        if (it != content_map_.end()) {
            contents_.erase(
                std::remove_if(contents_.begin(), contents_.end(),
                    [&](const auto& c) { return c->name() == name; }),
                contents_.end());
            content_map_.erase(it);
            return true;
        }
        return false;
    }

    const std::vector<std::unique_ptr<JingleContent>>& contents() const {
        return contents_;
    }

    // Security preconditions
    bool security_required() const { return security_required_; }
    void set_security_required(bool r) { security_required_ = r; }

    const std::string& security_fingerprint() const { return security_fingerprint_; }
    void set_security_fingerprint(const std::string& fp) { security_fingerprint_ = fp; }

    const std::string& security_hash() const { return security_hash_; }
    void set_security_hash(const std::string& h) { security_hash_ = h; }

    const std::string& security_setup() const { return security_setup_; }
    void set_security_setup(const std::string& s) { security_setup_ = s; }

    // Generate session-initiate IQ
    std::string to_initiate_xml(const std::string& from_jid,
                                const std::string& to_jid) const {
        std::ostringstream oss;
        oss << "<iq type=\"set\" id=\"" << xml_escape(generate_id("jingle_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<jingle xmlns=\"" << XMPPNS::JINGLE << "\"";
        oss << " action=\"session-initiate\"";
        oss << " initiator=\"" << xml_escape(initiator_) << "\"";
        oss << " sid=\"" << xml_escape(sid_) << "\">";

        for (const auto& content : contents_) {
            oss << content->to_xml();
        }

        oss << "</jingle>";
        oss << "</iq>";
        return oss.str();
    }

    // Generate session-accept XML
    std::string to_accept_xml(const std::string& from_jid,
                              const std::string& to_jid) const {
        std::ostringstream oss;
        oss << "<iq type=\"set\" id=\"" << xml_escape(generate_id("jingle_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<jingle xmlns=\"" << XMPPNS::JINGLE << "\"";
        oss << " action=\"session-accept\"";
        oss << " initiator=\"" << xml_escape(initiator_) << "\"";
        oss << " responder=\"" << xml_escape(responder_) << "\"";
        oss << " sid=\"" << xml_escape(sid_) << "\">";

        for (const auto& content : contents_) {
            oss << content->to_xml();
        }

        oss << "</jingle>";
        oss << "</iq>";
        return oss.str();
    }

    // Generate session-terminate XML
    std::string to_terminate_xml(const std::string& from_jid,
                                 const std::string& to_jid,
                                 JingleReason reason,
                                 const std::string& reason_text = "") const {
        std::ostringstream oss;
        oss << "<iq type=\"set\" id=\"" << xml_escape(generate_id("jingle_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<jingle xmlns=\"" << XMPPNS::JINGLE << "\"";
        oss << " action=\"session-terminate\"";
        oss << " sid=\"" << xml_escape(sid_) << "\">";
        oss << "<reason>";
        oss << "<" << jingle_reason_to_string(reason) << "/>";
        if (!reason_text.empty()) {
            oss << "<text>" << xml_escape(reason_text) << "</text>";
        }
        oss << "</reason>";
        oss << "</jingle>";
        oss << "</iq>";
        return oss.str();
    }

    // Generate session-info XML
    std::string to_info_xml(const std::string& from_jid,
                            const std::string& to_jid,
                            const std::string& payload_xml = "") const {
        std::ostringstream oss;
        oss << "<iq type=\"set\" id=\"" << xml_escape(generate_id("jingle_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<jingle xmlns=\"" << XMPPNS::JINGLE << "\"";
        oss << " action=\"session-info\"";
        oss << " sid=\"" << xml_escape(sid_) << "\">";
        if (!payload_xml.empty()) {
            oss << payload_xml;
        }
        oss << "</jingle>";
        oss << "</iq>";
        return oss.str();
    }

    // Generate content-add XML
    std::string to_content_add_xml(const std::string& from_jid,
                                   const std::string& to_jid,
                                   const JingleContent& content) const {
        std::ostringstream oss;
        oss << "<iq type=\"set\" id=\"" << xml_escape(generate_id("jingle_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<jingle xmlns=\"" << XMPPNS::JINGLE << "\"";
        oss << " action=\"content-add\"";
        oss << " sid=\"" << xml_escape(sid_) << "\">";
        oss << content.to_xml();
        oss << "</jingle>";
        oss << "</iq>";
        return oss.str();
    }

    // Generate content-remove XML
    std::string to_content_remove_xml(const std::string& from_jid,
                                      const std::string& to_jid,
                                      const std::string& content_name) const {
        std::ostringstream oss;
        oss << "<iq type=\"set\" id=\"" << xml_escape(generate_id("jingle_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<jingle xmlns=\"" << XMPPNS::JINGLE << "\"";
        oss << " action=\"content-remove\"";
        oss << " sid=\"" << xml_escape(sid_) << "\">";
        oss << "<content name=\"" << xml_escape(content_name) << "\"/>";
        oss << "</jingle>";
        oss << "</iq>";
        return oss.str();
    }

    // Generate transport-info XML (for ICE candidates, etc.)
    std::string to_transport_info_xml(const std::string& from_jid,
                                      const std::string& to_jid,
                                      const std::string& content_name,
                                      const std::string& transport_xml) const {
        std::ostringstream oss;
        oss << "<iq type=\"set\" id=\"" << xml_escape(generate_id("jingle_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<jingle xmlns=\"" << XMPPNS::JINGLE << "\"";
        oss << " action=\"transport-info\"";
        oss << " sid=\"" << xml_escape(sid_) << "\">";
        oss << "<content name=\"" << xml_escape(content_name) << "\"";
        oss << " creator=\"" << xml_escape(initiator_) << "\">";
        oss << transport_xml;
        oss << "</content>";
        oss << "</jingle>";
        oss << "</iq>";
        return oss.str();
    }

    // Generate security-info XML per XEP-0166
    std::string to_security_info_xml(const std::string& from_jid,
                                     const std::string& to_jid,
                                     const std::string& content_name,
                                     const std::string& security_xml) const {
        std::ostringstream oss;
        oss << "<iq type=\"set\" id=\"" << xml_escape(generate_id("jingle_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<jingle xmlns=\"" << XMPPNS::JINGLE << "\"";
        oss << " action=\"security-info\"";
        oss << " sid=\"" << xml_escape(sid_) << "\">";
        oss << "<content name=\"" << xml_escape(content_name) << "\">";
        oss << security_xml;
        oss << "</content>";
        oss << "</jingle>";
        oss << "</iq>";
        return oss.str();
    }

private:
    std::string sid_;
    std::string initiator_;
    std::string responder_;
    JingleState state_;
    JingleRole role_;
    int64_t created_at_;
    int64_t last_activity_;
    int timeout_ms_;
    std::string tie_breaker_;
    bool security_required_ = false;
    std::string security_fingerprint_;
    std::string security_hash_;
    std::string security_setup_;
    std::vector<std::unique_ptr<JingleContent>> contents_;
    std::unordered_map<std::string, JingleContent*> content_map_;
};

// ============================================================================
// ICE-UDP Transport Helper per XEP-0176
// ============================================================================

class IceUdpTransport {
public:
    IceUdpTransport()
        : pwd_(generate_password())
        , ufrag_(generate_ufrag())
    {}

    const std::string& ufrag() const { return ufrag_; }
    void set_ufrag(const std::string& u) { ufrag_ = u; }

    const std::string& pwd() const { return pwd_; }
    void set_pwd(const std::string& p) { pwd_ = p; }

    const std::vector<IceCandidate>& candidates() const { return candidates_; }
    void add_candidate(const IceCandidate& c) { candidates_.push_back(c); }
    void set_candidates(const std::vector<IceCandidate>& c) { candidates_ = c; }

    bool rtcp_mux() const { return rtcp_mux_; }
    void set_rtcp_mux(bool m) { rtcp_mux_ = m; }

    const std::vector<IceCandidate>& remote_candidates() const { return remote_candidates_; }
    void add_remote_candidate(const IceCandidate& c) { remote_candidates_.push_back(c); }

    const std::string& fingerprint() const { return fingerprint_; }
    void set_fingerprint(const std::string& f) { fingerprint_ = f; }

    const std::string& fingerprint_hash() const { return fingerprint_hash_; }
    void set_fingerprint_hash(const std::string& h) { fingerprint_hash_ = h; }

    const std::string& fingerprint_setup() const { return fingerprint_setup_; }
    void set_fingerprint_setup(const std::string& s) { fingerprint_setup_ = s; }

    std::string to_transport_xml() const {
        std::ostringstream oss;
        oss << "<transport xmlns=\"" << XMPPNS::JINGLE_TRANSPORT_ICE << "\"";
        oss << " ufrag=\"" << xml_escape(ufrag_) << "\"";
        oss << " pwd=\"" << xml_escape(pwd_) << "\"";
        oss << ">";

        // DTLS fingerprint if set
        if (!fingerprint_.empty()) {
            oss << "<fingerprint xmlns=\"" << XMPPNS::JINGLE_DTLS << "\"";
            oss << " hash=\"" << xml_escape(fingerprint_hash_) << "\"";
            if (!fingerprint_setup_.empty()) {
                oss << " setup=\"" << xml_escape(fingerprint_setup_) << "\"";
            }
            oss << ">" << xml_escape(fingerprint_) << "</fingerprint>";
        }

        for (const auto& c : candidates_) {
            oss << c.to_xml();
        }

        if (rtcp_mux_) {
            oss << "<rtcp-mux/>";
        }

        oss << "</transport>";
        return oss.str();
    }

    std::string to_transport_info_xml() const {
        std::ostringstream oss;
        oss << "<transport xmlns=\"" << XMPPNS::JINGLE_TRANSPORT_ICE << "\">";
        for (const auto& c : candidates_) {
            oss << c.to_xml();
        }
        oss << "</transport>";
        return oss.str();
    }

    std::string to_remote_candidate_xml() const {
        std::ostringstream oss;
        oss << "<transport xmlns=\"" << XMPPNS::JINGLE_TRANSPORT_ICE << "\">";
        for (const auto& c : remote_candidates_) {
            oss << "<remote-candidate";
            oss << " component=\"" << c.component() << "\"";
            oss << " ip=\"" << xml_escape(c.ip()) << "\"";
            oss << " port=\"" << c.port() << "\"";
            oss << "/>";
        }
        oss << "</transport>";
        return oss.str();
    }

private:
    std::string pwd_;
    std::string ufrag_;
    std::vector<IceCandidate> candidates_;
    std::vector<IceCandidate> remote_candidates_;
    bool rtcp_mux_ = false;
    std::string fingerprint_;
    std::string fingerprint_hash_;
    std::string fingerprint_setup_;
};

// ============================================================================
// IBB Transport per XEP-0047 / XEP-0261
// ============================================================================

class IBBStream {
public:
    IBBStream()
        : block_size_(4096), seq_(0), sid_(""), open_(false)
        , bytes_sent_(0), max_blocks_(65535) {}

    IBBStream(const std::string& sid, int block_size = 4096)
        : block_size_(block_size), seq_(0), sid_(sid), open_(false)
        , bytes_sent_(0), max_blocks_(65535) {}

    const std::string& sid() const { return sid_; }
    void set_sid(const std::string& s) { sid_ = s; }

    int block_size() const { return block_size_; }
    void set_block_size(int bs) { block_size_ = bs; }

    int64_t bytes_sent() const { return bytes_sent_; }
    int seq() const { return seq_; }
    int max_blocks() const { return max_blocks_; }

    bool is_open() const { return open_; }
    void set_open(bool o) { open_ = o; }

    const std::string& peer_jid() const { return peer_jid_; }
    void set_peer_jid(const std::string& j) { peer_jid_ = j; }

    const std::string& local_jid() const { return local_jid_; }
    void set_local_jid(const std::string& j) { local_jid_ = j; }

    std::string to_open_xml(const std::string& from_jid,
                            const std::string& to_jid) const {
        std::ostringstream oss;
        oss << "<iq type=\"set\" id=\"" << xml_escape(generate_id("ibb_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<open xmlns=\"" << XMPPNS::IBB << "\"";
        oss << " block-size=\"" << block_size_ << "\"";
        oss << " sid=\"" << xml_escape(sid_) << "\"";
        oss << " stanza=\"iq\"/>";
        oss << "</iq>";
        return oss.str();
    }

    std::string to_open_message_xml(const std::string& from_jid,
                                    const std::string& to_jid) const {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\"";
        oss << " id=\"" << xml_escape(generate_id("ibb_")) << "\">";
        oss << "<open xmlns=\"" << XMPPNS::IBB << "\"";
        oss << " block-size=\"" << block_size_ << "\"";
        oss << " sid=\"" << xml_escape(sid_) << "\"";
        oss << " stanza=\"message\"/>";
        oss << "</message>";
        return oss.str();
    }

    std::string to_close_xml(const std::string& from_jid,
                             const std::string& to_jid) const {
        std::ostringstream oss;
        oss << "<iq type=\"set\" id=\"" << xml_escape(generate_id("ibb_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<close xmlns=\"" << XMPPNS::IBB << "\"";
        oss << " sid=\"" << xml_escape(sid_) << "\"/>";
        oss << "</iq>";
        return oss.str();
    }

    std::string to_data_xml(const std::string& from_jid,
                            const std::string& to_jid,
                            const std::string& data) const {
        std::ostringstream oss;
        oss << "<iq type=\"set\" id=\"" << xml_escape(generate_id("ibb_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<data xmlns=\"" << XMPPNS::IBB << "\"";
        oss << " seq=\"" << seq_ << "\"";
        oss << " sid=\"" << xml_escape(sid_) << "\">";
        oss << base64_encode(reinterpret_cast<const uint8_t*>(data.data()), data.size());
        oss << "</data>";
        oss << "</iq>";
        return oss.str();
    }

    std::string to_data_message_xml(const std::string& from_jid,
                                    const std::string& to_jid,
                                    const std::string& data) const {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\"";
        oss << " id=\"" << xml_escape(generate_id("ibb_")) << "\">";
        oss << "<data xmlns=\"" << XMPPNS::IBB << "\"";
        oss << " seq=\"" << seq_ << "\"";
        oss << " sid=\"" << xml_escape(sid_) << "\">";
        oss << base64_encode(reinterpret_cast<const uint8_t*>(data.data()), data.size());
        oss << "</data>";
        oss << "</message>";
        return oss.str();
    }

    // Jingle IBB transport XML per XEP-0261
    std::string to_jingle_transport_xml() const {
        std::ostringstream oss;
        oss << "<transport xmlns=\"" << XMPPNS::JINGLE_TRANSPORT_IBB << "\"";
        oss << " block-size=\"" << block_size_ << "\"";
        oss << " sid=\"" << xml_escape(sid_) << "\"/>";
        return oss.str();
    }

    // Split data into blocks and generate all data stanzas
    std::vector<std::string> generate_data_blocks(const std::string& from_jid,
                                                   const std::string& to_jid,
                                                   const std::string& data) {
        std::vector<std::string> blocks;
        size_t offset = 0;
        while (offset < data.size()) {
            size_t chunk_size = std::min(static_cast<size_t>(block_size_), data.size() - offset);
            std::string chunk = data.substr(offset, chunk_size);
            blocks.push_back(to_data_xml(from_jid, to_jid, chunk));
            offset += chunk_size;
        }
        return blocks;
    }

private:
    int block_size_;
    mutable int seq_;
    std::string sid_;
    bool open_;
    int64_t bytes_sent_;
    int max_blocks_;
    std::string peer_jid_;
    std::string local_jid_;
};

// ============================================================================
// SOCKS5 Bytestream Transport per XEP-0065 / XEP-0260
// ============================================================================

class Socks5BytestreamProxy {
public:
    Socks5BytestreamProxy()
        : port_(1080), priority_(0) {}

    Socks5BytestreamProxy(const std::string& jid, const std::string& host,
                          int port, int priority = 0)
        : jid_(jid), host_(host), port_(port), priority_(priority) {}

    const std::string& jid() const { return jid_; }
    void set_jid(const std::string& j) { jid_ = j; }

    const std::string& host() const { return host_; }
    void set_host(const std::string& h) { host_ = h; }

    int port() const { return port_; }
    void set_port(int p) { port_ = p; }

    int priority() const { return priority_; }
    void set_priority(int p) { priority_ = p; }

    std::string to_streamhost_xml() const {
        std::ostringstream oss;
        oss << "<streamhost";
        oss << " jid=\"" << xml_escape(jid_) << "\"";
        oss << " host=\"" << xml_escape(host_) << "\"";
        oss << " port=\"" << port_ << "\"";
        if (priority_ > 0) {
            oss << " priority=\"" << priority_ << "\"";
        }
        oss << "/>";
        return oss.str();
    }

private:
    std::string jid_;
    std::string host_;
    int port_;
    int priority_;
};

class Socks5BytestreamSession {
public:
    Socks5BytestreamSession()
        : sid_(""), mode_("tcp"), activated_(false)
        , target_jid_("") {}

    Socks5BytestreamSession(const std::string& sid)
        : sid_(sid), mode_("tcp"), activated_(false), target_jid_("") {}

    const std::string& sid() const { return sid_; }
    void set_sid(const std::string& s) { sid_ = s; }

    const std::string& mode() const { return mode_; }
    void set_mode(const std::string& m) { mode_ = m; }

    bool activated() const { return activated_; }
    void set_activated(bool a) { activated_ = a; }

    const std::string& target_jid() const { return target_jid_; }
    void set_target_jid(const std::string& j) { target_jid_ = j; }

    const std::vector<Socks5BytestreamProxy>& proxies() const { return proxies_; }
    void add_proxy(const Socks5BytestreamProxy& p) { proxies_.push_back(p); }
    void set_proxies(const std::vector<Socks5BytestreamProxy>& p) { proxies_ = p; }

    const Socks5BytestreamProxy* used_proxy() const { return used_proxy_; }
    void set_used_proxy(const Socks5BytestreamProxy* p) { used_proxy_ = p; }

    const std::string& zeroconf_service() const { return zeroconf_service_; }
    void set_zeroconf_service(const std::string& s) { zeroconf_service_ = s; }

    std::string to_query_xml(const std::string& from_jid,
                             const std::string& to_jid) const {
        std::ostringstream oss;
        oss << "<iq type=\"get\" id=\"" << xml_escape(generate_id("s5b_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<query xmlns=\"" << XMPPNS::SOCKS5 << "\"";
        oss << " sid=\"" << xml_escape(sid_) << "\"/>";
        oss << "</iq>";
        return oss.str();
    }

    std::string to_response_xml(const std::string& from_jid,
                                const std::string& to_jid) const {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(generate_id("s5b_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<query xmlns=\"" << XMPPNS::SOCKS5 << "\"";
        oss << " sid=\"" << xml_escape(sid_) << "\"";
        if (!mode_.empty() && mode_ != "tcp") {
            oss << " mode=\"" << xml_escape(mode_) << "\"";
        }
        oss << ">";

        for (const auto& proxy : proxies_) {
            oss << proxy.to_streamhost_xml();
        }

        oss << "</query>";
        oss << "</iq>";
        return oss.str();
    }

    std::string to_activate_xml(const std::string& from_jid,
                                const std::string& to_jid,
                                const std::string& proxy_jid) const {
        std::ostringstream oss;
        oss << "<iq type=\"set\" id=\"" << xml_escape(generate_id("s5b_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(proxy_jid) << "\">";
        oss << "<query xmlns=\"" << XMPPNS::SOCKS5 << "\"";
        oss << " sid=\"" << xml_escape(sid_) << "\">";
        oss << "<activate>" << xml_escape(target_jid_) << "</activate>";
        oss << "</query>";
        oss << "</iq>";
        return oss.str();
    }

    // Jingle SOCKS5 transport XML per XEP-0260
    std::string to_jingle_transport_xml() const {
        std::ostringstream oss;
        oss << "<transport xmlns=\"" << XMPPNS::JINGLE_TRANSPORT_S5B << "\"";
        oss << " sid=\"" << xml_escape(sid_) << "\"";
        if (!mode_.empty() && mode_ != "tcp") {
            oss << " mode=\"" << xml_escape(mode_) << "\"";
        }
        oss << ">";

        for (const auto& proxy : proxies_) {
            oss << "<candidate";
            oss << " cid=\"" << xml_escape(proxy.jid()) << "\"";
            oss << " host=\"" << xml_escape(proxy.host()) << "\"";
            oss << " jid=\"" << xml_escape(proxy.jid()) << "\"";
            oss << " port=\"" << proxy.port() << "\"";
            oss << " priority=\"" << proxy.priority() << "\"";
            oss << " type=\"proxy\"/>";
        }

        oss << "</transport>";
        return oss.str();
    }

    std::string to_jingle_candidate_used_xml(const std::string& cid) const {
        std::ostringstream oss;
        oss << "<transport xmlns=\"" << XMPPNS::JINGLE_TRANSPORT_S5B << "\">";
        oss << "<candidate-used cid=\"" << xml_escape(cid) << "\"/>";
        oss << "</transport>";
        return oss.str();
    }

    std::string to_jingle_candidate_error_xml() const {
        std::ostringstream oss;
        oss << "<transport xmlns=\"" << XMPPNS::JINGLE_TRANSPORT_S5B << "\">";
        oss << "<candidate-error/>";
        oss << "</transport>";
        return oss.str();
    }

private:
    std::string sid_;
    std::string mode_;
    bool activated_;
    std::string target_jid_;
    std::vector<Socks5BytestreamProxy> proxies_;
    const Socks5BytestreamProxy* used_proxy_ = nullptr;
    std::string zeroconf_service_;
};

// ============================================================================
// HTTP File Upload Slot per XEP-0363
// ============================================================================

class HttpUploadSlot {
public:
    HttpUploadSlot()
        : state_(HttpUploadSlotState::ALLOCATED)
        , size_(0), allocated_at_(now_ms())
        , expires_at_(now_ms() + 3600000) // 1 hour default
    {}

    HttpUploadSlot(const std::string& upload_url, const std::string& download_url,
                   int64_t size, const std::string& mime_type = "")
        : upload_url_(upload_url), download_url_(download_url)
        , state_(HttpUploadSlotState::ALLOCATED)
        , size_(size), mime_type_(mime_type)
        , allocated_at_(now_ms())
        , expires_at_(now_ms() + 3600000) {}

    const std::string& upload_url() const { return upload_url_; }
    void set_upload_url(const std::string& u) { upload_url_ = u; }

    const std::string& download_url() const { return download_url_; }
    void set_download_url(const std::string& d) { download_url_ = d; }

    HttpUploadSlotState state() const { return state_; }
    void set_state(HttpUploadSlotState s) { state_ = s; }

    int64_t size() const { return size_; }
    void set_size(int64_t s) { size_ = s; }

    const std::string& mime_type() const { return mime_type_; }
    void set_mime_type(const std::string& m) { mime_type_ = m; }

    const std::string& requester_jid() const { return requester_jid_; }
    void set_requester_jid(const std::string& j) { requester_jid_ = j; }

    int64_t allocated_at() const { return allocated_at_; }
    int64_t expires_at() const { return expires_at_; }
    void set_expires_at(int64_t t) { expires_at_ = t; }

    const std::string& file_name() const { return file_name_; }
    void set_file_name(const std::string& n) { file_name_ = n; }

    const std::string& slot_id() const { return slot_id_; }
    void set_slot_id(const std::string& id) { slot_id_ = id; }

    const std::string& hash_sha256() const { return hash_sha256_; }
    void set_hash_sha256(const std::string& h) { hash_sha256_ = h; }

    bool is_expired() const {
        return now_ms() > expires_at_;
    }

    std::string to_slot_xml() const {
        std::ostringstream oss;
        oss << "<slot xmlns=\"" << XMPPNS::HTTP_UPLOAD << "\">";
        oss << "<put url=\"" << xml_escape(upload_url_) << "\">";
        oss << "<header name=\"Content-Type\">" << xml_escape(mime_type_) << "</header>";
        if (size_ > 0) {
            oss << "<header name=\"Content-Length\">" << size_ << "</header>";
        }
        oss << "</put>";
        oss << "<get url=\"" << xml_escape(download_url_) << "\"/>";
        oss << "</slot>";
        return oss.str();
    }

    std::string to_request_xml(const std::string& from_jid,
                               const std::string& to_jid,
                               const std::string& filename,
                               int64_t size,
                               const std::string& content_type = "") const {
        std::ostringstream oss;
        oss << "<iq type=\"get\" id=\"" << xml_escape(generate_id("upload_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<request xmlns=\"" << XMPPNS::HTTP_UPLOAD << "\"";
        if (!filename.empty()) {
            oss << " filename=\"" << xml_escape(filename) << "\"";
        }
        oss << " size=\"" << size << "\"";
        if (!content_type.empty()) {
            oss << " content-type=\"" << xml_escape(content_type) << "\"";
        }
        oss << "/>";
        oss << "</iq>";
        return oss.str();
    }

    std::string to_result_xml(const std::string& from_jid,
                              const std::string& to_jid,
                              const std::string& iq_id) const {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(iq_id) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << to_slot_xml();
        oss << "</iq>";
        return oss.str();
    }

private:
    std::string upload_url_;
    std::string download_url_;
    HttpUploadSlotState state_;
    int64_t size_;
    std::string mime_type_;
    std::string requester_jid_;
    int64_t allocated_at_;
    int64_t expires_at_;
    std::string file_name_;
    std::string slot_id_;
    std::string hash_sha256_;
};

// ============================================================================
// HTTP Upload Service Component per XEP-0363
// ============================================================================

class HttpUploadService {
public:
    struct Config {
        int64_t max_file_size = 100 * 1024 * 1024; // 100MB default
        int64_t max_slot_lifetime_ms = 3600000;     // 1 hour
        int max_slots_per_user = 10;
        int max_total_slots = 1000;
        std::string base_upload_url = "https://upload.example.com/";
        std::string base_download_url = "https://download.example.com/";
        std::string service_jid = "upload.example.com";
        std::vector<std::string> allowed_mime_types;
        bool enforce_mime_types = false;
    };

    HttpUploadService() {
        config_.allowed_mime_types = {
            "image/jpeg", "image/png", "image/gif", "image/webp",
            "image/svg+xml", "audio/mpeg", "audio/ogg", "audio/wav",
            "audio/webm", "video/mp4", "video/webm", "application/pdf",
            "application/zip", "application/x-tar", "application/gzip",
            "text/plain", "text/html", "text/css", "text/javascript",
            "application/json", "application/xml"
        };
    }

    HttpUploadService(const Config& config) : config_(config) {}

    const Config& config() const { return config_; }
    void set_config(const Config& c) { config_ = c; }

    // Allocate a new upload slot
    HttpUploadSlot* allocate_slot(const std::string& requester_jid,
                                  const std::string& filename,
                                  int64_t size,
                                  const std::string& content_type) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Check file size limit
        if (size > config_.max_file_size) {
            return nullptr; // File too large
        }
        if (size <= 0) {
            return nullptr; // Invalid size
        }

        // Check MIME type restrictions
        if (config_.enforce_mime_types && !content_type.empty()) {
            bool allowed = false;
            for (const auto& mt : config_.allowed_mime_types) {
                if (mt == content_type) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                return nullptr; // MIME type not allowed
            }
        }

        // Check per-user slot limit
        int user_slots = 0;
        for (const auto& slot : slots_) {
            if (slot->requester_jid() == requester_jid &&
                !slot->is_expired()) {
                user_slots++;
            }
        }
        if (user_slots >= config_.max_slots_per_user) {
            return nullptr; // Too many slots for this user
        }

        // Check total slot limit
        if (slots_.size() >= static_cast<size_t>(config_.max_total_slots)) {
            // Expire old slots first
            expire_slots_internal();
            if (slots_.size() >= static_cast<size_t>(config_.max_total_slots)) {
                return nullptr; // Still too many
            }
        }

        std::string slot_id = generate_id("slot_");
        std::string upload_url = config_.base_upload_url + slot_id + "/" + filename;
        std::string download_url = config_.base_download_url + slot_id + "/" + filename;

        auto slot = std::make_unique<HttpUploadSlot>(
            upload_url, download_url, size, content_type);
        slot->set_requester_jid(requester_jid);
        slot->set_file_name(filename);
        slot->set_slot_id(slot_id);
        slot->set_state(HttpUploadSlotState::ALLOCATED);
        slot->set_expires_at(now_ms() + config_.max_slot_lifetime_ms);

        HttpUploadSlot* ptr = slot.get();
        slots_.push_back(std::move(slot));
        return ptr;
    }

    // Get a slot by ID
    HttpUploadSlot* get_slot(const std::string& slot_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        expire_slots_internal();
        for (auto& slot : slots_) {
            if (slot->slot_id() == slot_id) {
                return slot.get();
            }
        }
        return nullptr;
    }

    // Mark a slot as completed (upload finished)
    bool complete_slot(const std::string& slot_id,
                       const std::string& sha256_hash = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& slot : slots_) {
            if (slot->slot_id() == slot_id) {
                slot->set_state(HttpUploadSlotState::COMPLETED);
                if (!sha256_hash.empty()) {
                    slot->set_hash_sha256(sha256_hash);
                }
                return true;
            }
        }
        return false;
    }

    // Expire old slots
    void expire_slots() {
        std::lock_guard<std::mutex> lock(mutex_);
        expire_slots_internal();
    }

    // Get active slot count
    int active_slot_count() const {
        int count = 0;
        for (const auto& slot : slots_) {
            if (!slot->is_expired() &&
                slot->state() != HttpUploadSlotState::EXPIRED) {
                count++;
            }
        }
        return count;
    }

    // Check if user has available slots
    bool user_has_available_slot(const std::string& jid) const {
        int count = 0;
        for (const auto& slot : slots_) {
            if (slot->requester_jid() == jid &&
                !slot->is_expired() &&
                slot->state() != HttpUploadSlotState::EXPIRED) {
                count++;
            }
        }
        return count < config_.max_slots_per_user;
    }

    // Service discovery info
    std::string disco_info_xml() const {
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::DISCO_INFO << "\">";
        oss << "<identity category=\"store\" type=\"file\" name=\"HTTP File Upload\"/>";
        oss << "<feature var=\"" << XMPPNS::HTTP_UPLOAD << "\"/>";
        oss << "<feature var=\"" << XMPPNS::DISCO_INFO << "\"/>";
        oss << "<x xmlns=\"" << XMPPNS::X_DATA << "\" type=\"result\">";
        oss << "<field var=\"FORM_TYPE\" type=\"hidden\">";
        oss << "<value>" << XMPPNS::HTTP_UPLOAD << "</value>";
        oss << "</field>";
        oss << "<field var=\"max-file-size\" type=\"text-single\">";
        oss << "<value>" << config_.max_file_size << "</value>";
        oss << "</field>";
        oss << "<field var=\"max-file-size-human\">";
        oss << "<value>" << format_file_size(config_.max_file_size) << "</value>";
        oss << "</field>";
        oss << "</x>";
        oss << "</query>";
        return oss.str();
    }

    // Get MIME type restrictions as XML
    std::string mime_types_xml() const {
        if (!config_.enforce_mime_types || config_.allowed_mime_types.empty()) {
            return "";
        }
        std::ostringstream oss;
        oss << "<x xmlns=\"" << XMPPNS::X_DATA << "\" type=\"result\">";
        oss << "<field var=\"allowed-mime-types\" type=\"list-multi\">";
        for (const auto& mt : config_.allowed_mime_types) {
            oss << "<value>" << xml_escape(mt) << "</value>";
        }
        oss << "</field>";
        oss << "</x>";
        return oss.str();
    }

private:
    void expire_slots_internal() {
        slots_.erase(
            std::remove_if(slots_.begin(), slots_.end(),
                [](const auto& slot) {
                    return slot->is_expired();
                }),
            slots_.end());
    }

    static std::string format_file_size(int64_t bytes) {
        const char* units[] = {"B", "KB", "MB", "GB", "TB"};
        int i = 0;
        double size = static_cast<double>(bytes);
        while (size >= 1024.0 && i < 4) {
            size /= 1024.0;
            i++;
        }
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << size << " " << units[i];
        return oss.str();
    }

    Config config_;
    std::vector<std::unique_ptr<HttpUploadSlot>> slots_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Stream Initiation per XEP-0095 / XEP-0096
// ============================================================================

class SIStream {
public:
    SIStream()
        : id_(""), mime_type_("application/octet-stream"), profile_("") {}

    SIStream(const std::string& id, const std::string& mime_type,
             const std::string& profile)
        : id_(id), mime_type_(mime_type), profile_(profile) {}

    const std::string& id() const { return id_; }
    void set_id(const std::string& id) { id_ = id; }

    const std::string& mime_type() const { return mime_type_; }
    void set_mime_type(const std::string& m) { mime_type_ = m; }

    const std::string& profile() const { return profile_; }
    void set_profile(const std::string& p) { profile_ = p; }

    const std::string& profile_xml() const { return profile_xml_; }
    void set_profile_xml(const std::string& xml) { profile_xml_ = xml; }

    const std::vector<std::string>& features() const { return features_; }
    void add_feature(const std::string& f) { features_.push_back(f); }

    std::string to_si_xml(const std::string& from_jid,
                          const std::string& to_jid) const {
        std::ostringstream oss;
        oss << "<iq type=\"set\" id=\"" << xml_escape(generate_id("si_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<si xmlns=\"" << XMPPNS::SI << "\"";
        oss << " id=\"" << xml_escape(id_) << "\"";
        oss << " mime-type=\"" << xml_escape(mime_type_) << "\"";
        oss << " profile=\"" << xml_escape(profile_) << "\">";

        // File transfer profile
        if (!profile_xml_.empty()) {
            oss << profile_xml_;
        }

        // Features
        if (!features_.empty()) {
            oss << "<feature xmlns=\"" << XMPPNS::SI << "\">";
            oss << "<x xmlns=\"" << XMPPNS::X_DATA << "\" type=\"form\">";
            for (const auto& f : features_) {
                oss << "<field var=\"stream-method\" type=\"list-single\">";
                oss << "<option><value>" << xml_escape(f) << "</value></option>";
                oss << "</field>";
            }
            oss << "</x>";
            oss << "</feature>";
        }

        oss << "</si>";
        oss << "</iq>";
        return oss.str();
    }

    std::string to_si_result_xml(const std::string& from_jid,
                                 const std::string& to_jid,
                                 const std::string& iq_id) const {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(iq_id) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<si xmlns=\"" << XMPPNS::SI << "\">";
        oss << "<feature xmlns=\"" << XMPPNS::SI << "\">";
        oss << "<x xmlns=\"" << XMPPNS::X_DATA << "\" type=\"submit\">";
        oss << "<field var=\"stream-method\">";
        oss << "<value>" << xml_escape(profile_) << "</value>";
        oss << "</field>";
        oss << "</x>";
        oss << "</feature>";
        oss << "</si>";
        oss << "</iq>";
        return oss.str();
    }

private:
    std::string id_;
    std::string mime_type_;
    std::string profile_;
    std::string profile_xml_;
    std::vector<std::string> features_;
};

// ============================================================================
// XML Parser Helpers (minimal, hand-rolled for Jingle stanzas)
// ============================================================================

static std::string extract_attr(const std::string& xml, const std::string& attr) {
    std::string pattern = attr + "=\"";
    size_t pos = xml.find(pattern);
    if (pos == std::string::npos) {
        pattern = attr + "='";
        pos = xml.find(pattern);
    }
    if (pos == std::string::npos) return "";
    pos += pattern.length();
    size_t end = xml.find(pattern[pattern.length() - 1], pos);
    if (end == std::string::npos) return "";
    return xml.substr(pos, end - pos);
}

static std::string extract_tag_content(const std::string& xml,
                                        const std::string& tag) {
    std::string open_tag = "<" + tag;
    size_t start = xml.find(open_tag);
    if (start == std::string::npos) return "";
    start = xml.find('>', start);
    if (start == std::string::npos) return "";
    start++;
    std::string close_tag = "</" + tag + ">";
    size_t end = xml.find(close_tag, start);
    if (end == std::string::npos) return "";
    return xml.substr(start, end - start);
}

static std::string extract_jingle_sid(const std::string& xml) {
    size_t pos = xml.find("jingle ");
    if (pos == std::string::npos) pos = xml.find("jingle>");
    if (pos == std::string::npos) return "";
    return extract_attr(xml.substr(pos), "sid");
}

static JingleAction extract_jingle_action(const std::string& xml) {
    size_t pos = xml.find("jingle ");
    if (pos == std::string::npos) {
        pos = xml.find("jingle>");
        if (pos == std::string::npos) return JingleAction::UNKNOWN;
        // Empty jingle element, might be a session-terminate
        return JingleAction::UNKNOWN;
    }
    std::string action = extract_attr(xml.substr(pos), "action");
    return jingle_action_from_string(action);
}

static JingleReason extract_jingle_reason(const std::string& xml) {
    size_t pos = xml.find("<reason>");
    if (pos == std::string::npos) return JingleReason::UNKNOWN_REASON;
    size_t end = xml.find("</reason>", pos);
    if (end == std::string::npos) return JingleReason::UNKNOWN_REASON;
    std::string reason_block = xml.substr(pos, end - pos + 9);

    // Check each known reason
    static const char* reason_names[] = {
        "success", "decline", "cancel", "expired", "gone",
        "media-failure", "connectivity-error", "incompatible-parameters",
        "general-error", "failed-application", "failed-transport",
        "alternative-session", "security-error", "timeout"
    };
    for (const auto& rn : reason_names) {
        if (reason_block.find("<" + std::string(rn) + "/>") != std::string::npos ||
            reason_block.find("<" + std::string(rn) + " ") != std::string::npos ||
            reason_block.find("<" + std::string(rn) + ">") != std::string::npos) {
            return jingle_reason_from_string(rn);
        }
    }
    return JingleReason::UNKNOWN_REASON;
}

static std::string extract_jingle_reason_text(const std::string& xml) {
    return extract_tag_content(xml, "text");
}

// ============================================================================
// Jingle Session Manager - Central session and stanza handling
// ============================================================================

class JingleManager {
public:
    JingleManager() {}

    // Session lifecycle
    JingleSession* create_session(const std::string& initiator,
                                  const std::string& responder) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string sid = generate_id("jingle_session_");
        auto session = std::make_unique<JingleSession>(sid, initiator, responder);
        JingleSession* ptr = session.get();
        sessions_[sid] = std::move(session);
        return ptr;
    }

    JingleSession* get_session(const std::string& sid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(sid);
        if (it != sessions_.end()) {
            return it->second.get();
        }
        return nullptr;
    }

    bool remove_session(const std::string& sid) {
        std::lock_guard<std::mutex> lock(mutex_);
        return sessions_.erase(sid) > 0;
    }

    void expire_sessions() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.begin();
        while (it != sessions_.end()) {
            if (it->second->is_expired()) {
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Parse and handle incoming Jingle IQ stanzas
    struct JingleParseResult {
        JingleAction action;
        std::string sid;
        std::string initiator;
        std::string responder;
        JingleReason reason;
        std::string reason_text;
        std::string raw_xml;
        bool parse_success;
    };

    JingleParseResult parse_jingle_stanza(const std::string& xml) {
        JingleParseResult result;
        result.raw_xml = xml;
        result.parse_success = false;

        // Extract basic attributes
        result.sid = extract_jingle_sid(xml);
        result.action = extract_jingle_action(xml);
        result.reason = extract_jingle_reason(xml);
        result.reason_text = extract_jingle_reason_text(xml);

        size_t jingle_pos = xml.find("jingle ");
        if (jingle_pos == std::string::npos) {
            jingle_pos = xml.find("jingle>");
            if (jingle_pos != std::string::npos) {
                result.parse_success = true; // Might be terminate with reason
            }
            return result;
        }

        std::string jingle_attrs = xml.substr(jingle_pos, xml.find('>', jingle_pos) - jingle_pos);
        result.initiator = extract_attr(jingle_attrs, "initiator");
        result.responder = extract_attr(jingle_attrs, "responder");
        result.parse_success = true;

        return result;
    }

    // Handle an incoming Jingle IQ set
    std::string handle_jingle_iq_set(const std::string& xml) {
        auto parsed = parse_jingle_stanza(xml);
        if (!parsed.parse_success) {
            return generate_jingle_error(xml, "bad-request", "Invalid Jingle stanza");
        }

        switch (parsed.action) {
            case JingleAction::SESSION_INITIATE:
                return handle_session_initiate(xml, parsed);
            case JingleAction::SESSION_ACCEPT:
                return handle_session_accept(xml, parsed);
            case JingleAction::SESSION_TERMINATE:
                return handle_session_terminate(xml, parsed);
            case JingleAction::SESSION_INFO:
                return handle_session_info(xml, parsed);
            case JingleAction::TRANSPORT_INFO:
                return handle_transport_info(xml, parsed);
            case JingleAction::CONTENT_ADD:
                return handle_content_add(xml, parsed);
            case JingleAction::CONTENT_REMOVE:
                return handle_content_remove(xml, parsed);
            case JingleAction::CONTENT_ACCEPT:
                return handle_content_accept(xml, parsed);
            case JingleAction::CONTENT_REJECT:
                return handle_content_reject(xml, parsed);
            case JingleAction::CONTENT_MODIFY:
                return handle_content_modify(xml, parsed);
            case JingleAction::TRANSPORT_ACCEPT:
                return handle_transport_accept(xml, parsed);
            case JingleAction::TRANSPORT_REJECT:
                return handle_transport_reject(xml, parsed);
            case JingleAction::TRANSPORT_REPLACE:
                return handle_transport_replace(xml, parsed);
            case JingleAction::DESCRIPTION_INFO:
                return handle_description_info(xml, parsed);
            case JingleAction::SECURITY_INFO:
                return handle_security_info(xml, parsed);
            default:
                return generate_jingle_error(xml, "bad-request",
                    "Unknown Jingle action");
        }
    }

    // Handle HTTP upload slot request
    std::string handle_upload_request(const std::string& xml,
                                      HttpUploadService& upload_service) {
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");
        std::string id = extract_attr(xml, "id");

        // Extract request parameters
        std::string filename = extract_attr(xml, "filename");
        std::string content_type = extract_attr(xml, "content-type");

        std::string size_str = extract_attr(xml, "size");
        int64_t size = 0;
        try {
            size = std::stoll(size_str);
        } catch (...) {
            return generate_iq_error(from, to, id, "bad-request",
                "Invalid file size");
        }

        // Allocate slot
        HttpUploadSlot* slot = upload_service.allocate_slot(
            from, filename, size, content_type);

        if (!slot) {
            // Check specific error conditions
            if (size > upload_service.config().max_file_size) {
                return generate_iq_error(from, to, id, "not-acceptable",
                    "File too large. Maximum size: " +
                    std::to_string(upload_service.config().max_file_size));
            }
            return generate_iq_error(from, to, id, "resource-constraint",
                "Upload slot not available");
        }

        return slot->to_result_xml(to, from, id);
    }

    // Handle SOCKS5 bytestream query
    std::string handle_s5b_query(const std::string& xml,
                                 Socks5BytestreamSession& session) {
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");
        return session.to_response_xml(to, from);
    }

    // Handle IBB open
    std::string handle_ibb_open(const std::string& xml, IBBStream& stream) {
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");
        std::string id = extract_attr(xml, "id");

        std::string block_size_str = extract_attr(xml, "block-size");
        try {
            stream.set_block_size(std::stoi(block_size_str));
        } catch (...) {
            return generate_iq_error(from, to, id, "bad-request",
                "Invalid block size");
        }
        stream.set_peer_jid(from);
        stream.set_open(true);

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

private:
    // Individual Jingle action handlers
    std::string handle_session_initiate(const std::string& xml,
                                        const JingleParseResult& parsed) {
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");
        std::string id = extract_attr(xml, "id");

        // Check for tie-breaking
        auto* existing = get_session(parsed.sid);
        if (existing) {
            // Session already exists - tie-break
            return generate_jingle_error(xml, "conflict",
                "Tie-break: session already exists");
        }

        // Create new session
        auto* session = create_session(parsed.initiator, parsed.responder);
        if (!session) {
            return generate_jingle_error(xml, "internal-server-error",
                "Failed to create session");
        }

        // Parse content descriptions and transports
        parse_content_from_initiate(session, xml);

        // Acknowledge receipt
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_session_accept(const std::string& xml,
                                      const JingleParseResult& parsed) {
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");
        std::string id = extract_attr(xml, "id");

        auto* session = get_session(parsed.sid);
        if (!session) {
            return generate_jingle_error(xml, "item-not-found",
                "Unknown session: " + parsed.sid);
        }

        session->set_state(JingleState::ACTIVE);
        session->update_activity();

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_session_terminate(const std::string& xml,
                                         const JingleParseResult& parsed) {
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");
        std::string id = extract_attr(xml, "id");

        auto* session = get_session(parsed.sid);
        if (session) {
            session->set_state(JingleState::ENDED);
        }

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_session_info(const std::string& xml,
                                    const JingleParseResult& parsed) {
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");
        std::string id = extract_attr(xml, "id");

        auto* session = get_session(parsed.sid);
        if (session) {
            session->update_activity();
        }

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_transport_info(const std::string& xml,
                                      const JingleParseResult& parsed) {
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");
        std::string id = extract_attr(xml, "id");

        auto* session = get_session(parsed.sid);
        if (session) {
            session->update_activity();
        }

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_content_add(const std::string& xml,
                                   const JingleParseResult& parsed) {
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");
        std::string id = extract_attr(xml, "id");

        auto* session = get_session(parsed.sid);
        if (!session) {
            return generate_jingle_error(xml, "item-not-found",
                "Unknown session");
        }
        session->update_activity();

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_content_remove(const std::string& xml,
                                      const JingleParseResult& parsed) {
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");
        std::string id = extract_attr(xml, "id");

        auto* session = get_session(parsed.sid);
        if (session) {
            session->update_activity();
        }

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_content_accept(const std::string& xml,
                                      const JingleParseResult& parsed) {
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");
        std::string id = extract_attr(xml, "id");

        auto* session = get_session(parsed.sid);
        if (session) {
            session->update_activity();
        }

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_content_reject(const std::string& xml,
                                      const JingleParseResult& parsed) {
        std::string id = extract_attr(xml, "id");
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_content_modify(const std::string& xml,
                                      const JingleParseResult& parsed) {
        std::string id = extract_attr(xml, "id");
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_transport_accept(const std::string& xml,
                                        const JingleParseResult& parsed) {
        std::string id = extract_attr(xml, "id");
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");

        auto* session = get_session(parsed.sid);
        if (session) {
            session->update_activity();
        }

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_transport_reject(const std::string& xml,
                                        const JingleParseResult& parsed) {
        std::string id = extract_attr(xml, "id");
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_transport_replace(const std::string& xml,
                                         const JingleParseResult& parsed) {
        std::string id = extract_attr(xml, "id");
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");

        auto* session = get_session(parsed.sid);
        if (session) {
            session->update_activity();
        }

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_description_info(const std::string& xml,
                                        const JingleParseResult& parsed) {
        std::string id = extract_attr(xml, "id");
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");

        auto* session = get_session(parsed.sid);
        if (session) {
            session->update_activity();
        }

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    std::string handle_security_info(const std::string& xml,
                                     const JingleParseResult& parsed) {
        std::string id = extract_attr(xml, "id");
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");

        auto* session = get_session(parsed.sid);
        if (session) {
            session->update_activity();
        }

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\"/>";
        return oss.str();
    }

    // Parse content descriptions and transports from session-initiate
    void parse_content_from_initiate(JingleSession* session, const std::string& xml) {
        // Find all content elements
        size_t pos = 0;
        while (true) {
            size_t content_start = xml.find("<content ", pos);
            if (content_start == std::string::npos) break;

            size_t content_end = xml.find("</content>", content_start);
            if (content_end == std::string::npos) break;

            std::string content_block = xml.substr(content_start,
                content_end - content_start + 10);

            std::string name = extract_attr(content_block, "name");
            std::string creator = extract_attr(content_block, "creator");
            std::string senders = extract_attr(content_block, "senders");
            std::string disposition = extract_attr(content_block, "disposition");

            auto* content = session->add_content(name, creator);
            if (content) {
                if (!senders.empty()) content->set_senders(senders);
                if (!disposition.empty()) content->set_disposition(disposition);

                // Extract description and transport XML
                if (content_block.find("<description ") != std::string::npos) {
                    content->set_description_xml(content_block);
                }
                if (content_block.find("<transport ") != std::string::npos) {
                    content->set_transport_xml(content_block);
                }
            }

            pos = content_end + 10;
        }
    }

    // Error response generators
    static std::string generate_jingle_error(const std::string& original_xml,
                                             const std::string& error_type,
                                             const std::string& error_text) {
        std::string id = extract_attr(original_xml, "id");
        std::string from = extract_attr(original_xml, "from");
        std::string to = extract_attr(original_xml, "to");

        std::ostringstream oss;
        oss << "<iq type=\"error\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\">";
        oss << "<error type=\"" << xml_escape(error_type) << "\">";
        oss << "<" << error_type << " xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/>";
        if (!error_text.empty()) {
            oss << "<text xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\">"
                << xml_escape(error_text) << "</text>";
        }
        oss << "</error>";
        oss << "</iq>";
        return oss.str();
    }

    static std::string generate_iq_error(const std::string& from,
                                         const std::string& to,
                                         const std::string& id,
                                         const std::string& error_type,
                                         const std::string& error_text) {
        std::ostringstream oss;
        oss << "<iq type=\"error\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(to) << "\"";
        oss << " to=\"" << xml_escape(from) << "\">";
        oss << "<error type=\"" << xml_escape(error_type) << "\">";
        oss << "<" << error_type << " xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/>";
        if (!error_text.empty()) {
            oss << "<text xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\">"
                << xml_escape(error_text) << "</text>";
        }
        oss << "</error>";
        oss << "</iq>";
        return oss.str();
    }

    std::unordered_map<std::string, std::unique_ptr<JingleSession>> sessions_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Jingle Security Preconditions per XEP-0166 Section 11
// ============================================================================

class JingleSecurityPrecondition {
public:
    JingleSecurityPrecondition() {}

    // Generate DTLS-SRTP security XML for content
    static std::string generate_dtls_srtp_xml(const std::string& fingerprint,
                                              const std::string& hash_algo = "sha-256",
                                              const std::string& setup = "actpass") {
        std::ostringstream oss;
        oss << "<security xmlns=\"" << XMPPNS::JINGLE_SECURITY << "\">";
        oss << "<fingerprint xmlns=\"" << XMPPNS::JINGLE_DTLS << "\"";
        oss << " hash=\"" << xml_escape(hash_algo) << "\"";
        oss << " setup=\"" << xml_escape(setup) << "\">";
        oss << xml_escape(fingerprint) << "</fingerprint>";
        oss << "</security>";
        return oss.str();
    }

    // Check if security precondition is met
    static bool is_security_satisfied(const JingleSession& session) {
        if (!session.security_required()) {
            return true; // Security not required
        }
        // Both sides must have fingerprints
        return !session.security_fingerprint().empty() &&
               !session.security_hash().empty();
    }

    // Negotiate security setup
    static std::string negotiate_setup(const std::string& initiator_setup,
                                        const std::string& responder_setup) {
        // Standard DTLS setup negotiation
        if (initiator_setup == "actpass") {
            if (responder_setup == "active") return "active";
            if (responder_setup == "passive") return "passive";
            // Default: responder becomes active
            return "active";
        }
        if (initiator_setup == "active") {
            return "passive"; // Responder must be passive
        }
        if (initiator_setup == "passive") {
            return "active"; // Responder must be active
        }
        return "actpass";
    }
};

// ============================================================================
// File Transfer Session - High-level file transfer orchestrator
// ============================================================================

class FileTransferSession {
public:
    FileTransferSession()
        : state_(FileTransferState::OFFERED)
        , bytes_transferred_(0), progress_callback_(nullptr)
    {}

    FileTransferSession(const std::string& session_id,
                        const FileTransferOffer& offer)
        : session_id_(session_id), offer_(offer)
        , state_(FileTransferState::OFFERED)
        , bytes_transferred_(0), progress_callback_(nullptr)
    {}

    const std::string& session_id() const { return session_id_; }
    void set_session_id(const std::string& id) { session_id_ = id; }

    const FileTransferOffer& offer() const { return offer_; }
    void set_offer(const FileTransferOffer& o) { offer_ = o; }

    FileTransferState state() const { return state_; }
    void set_state(FileTransferState s) { state_ = s; }

    int64_t bytes_transferred() const { return bytes_transferred_; }
    void add_bytes_transferred(int64_t bytes) {
        bytes_transferred_ += bytes;
        if (progress_callback_) {
            double progress = offer_.size() > 0
                ? static_cast<double>(bytes_transferred_) / offer_.size()
                : 0.0;
            progress_callback_(progress);
        }
    }

    const std::string& transport_type() const { return transport_type_; }
    void set_transport_type(const std::string& t) { transport_type_ = t; }

    bool is_complete() const {
        return state_ == FileTransferState::COMPLETED ||
               state_ == FileTransferState::CANCELLED ||
               state_ == FileTransferState::FAILED;
    }

    double progress() const {
        if (offer_.size() <= 0) return 0.0;
        return static_cast<double>(bytes_transferred_) / offer_.size();
    }

    void on_progress(std::function<void(double)> callback) {
        progress_callback_ = callback;
    }

    // Get IBB configuration
    int ibb_block_size() const { return ibb_block_size_; }
    void set_ibb_block_size(int bs) { ibb_block_size_ = bs; }

    // Verify received hashes
    bool verify_sha256(const std::string& data) const {
        if (offer_.hash_sha256().empty()) return true;
        SHA256 sha;
        sha.update(data);
        return sha.finalize() == offer_.hash_sha256();
    }

    bool verify_sha512(const std::string& data) const {
        if (offer_.hash_sha512().empty()) return true;
        SHA512 sha;
        sha.update(data);
        return sha.finalize() == offer_.hash_sha512();
    }

    // Hash the file data
    void compute_hashes(const std::string& data) {
        SHA256 sha256;
        sha256.update(data);
        computed_sha256_ = sha256.finalize();

        SHA512 sha512;
        sha512.update(data);
        computed_sha512_ = sha512.finalize();
    }

    const std::string& computed_sha256() const { return computed_sha256_; }
    const std::string& computed_sha512() const { return computed_sha512_; }

private:
    std::string session_id_;
    FileTransferOffer offer_;
    FileTransferState state_;
    int64_t bytes_transferred_;
    std::function<void(double)> progress_callback_;
    std::string transport_type_;
    int ibb_block_size_ = 4096;
    std::string computed_sha256_;
    std::string computed_sha512_;
};

// ============================================================================
// Jingle File Transfer Orchestrator - ties together Jingle + FT
// ============================================================================

class JingleFileTransfer {
public:
    JingleFileTransfer() {
        jingle_manager_ = std::make_unique<JingleManager>();
        upload_service_ = std::make_unique<HttpUploadService>();
    }

    // Initiate a file transfer
    JingleSession* initiate_file_transfer(const std::string& from_jid,
                                          const std::string& to_jid,
                                          const FileTransferOffer& offer,
                                          const std::string& preferred_transport = "ice-udp") {
        auto* session = jingle_manager_->create_session(from_jid, to_jid);
        if (!session) return nullptr;

        // Create content with file description
        auto* content = session->add_content("file-offer", from_jid);
        content->set_senders("initiator");
        content->set_description_xml(offer.to_description_xml());

        // Add transport based on preference
        if (preferred_transport == "ibb") {
            // IBB fallback
            IBBStream ibb(generate_id("ibb_"), 4096);
            ibb.set_peer_jid(to_jid);
            ibb.set_local_jid(from_jid);
            content->set_transport_xml(ibb.to_jingle_transport_xml());
        } else if (preferred_transport == "s5b") {
            // SOCKS5
            Socks5BytestreamSession s5b(generate_id("s5b_"));
            content->set_transport_xml(s5b.to_jingle_transport_xml());
        } else {
            // Default: ICE-UDP
            IceUdpTransport ice;
            // Add some host candidates
            IceCandidate cand1("1", 1, "udp", 2130706431, "192.168.1.100", 5000,
                               IceCandidateType::HOST);
            ice.add_candidate(cand1);
            content->set_transport_xml(ice.to_transport_xml());
        }

        // Also add IBB as a fallback transport
        IBBStream ibb_fallback(generate_id("ibb_fallback_"), 4096);
        content->add_transport_xml(ibb_fallback.to_jingle_transport_xml());

        return session;
    }

    // Initiate file transfer via Stream Initiation (SI) for legacy clients
    SIStream* initiate_si_file_transfer(const std::string& from_jid,
                                        const std::string& to_jid,
                                        const FileTransferOffer& offer,
                                        const std::vector<std::string>& methods) {
        auto si = std::make_unique<SIStream>(
            generate_id("si_"),
            offer.media_type(),
            XMPPNS::SI_FILE_TRANSFER
        );
        si->set_profile_xml(offer.to_si_file_xml());
        for (const auto& m : methods) {
            si->add_feature(m);
        }
        SIStream* ptr = si.get();
        si_streams_[si->id()] = std::move(si);
        return ptr;
    }

    // Get Jingle manager
    JingleManager* jingle_manager() { return jingle_manager_.get(); }

    // Get upload service
    HttpUploadService* upload_service() { return upload_service_.get(); }

    // Create a file transfer session
    FileTransferSession* create_ft_session(const std::string& id,
                                           const FileTransferOffer& offer) {
        auto ft = std::make_unique<FileTransferSession>(id, offer);
        FileTransferSession* ptr = ft.get();
        ft_sessions_[id] = std::move(ft);
        return ptr;
    }

    FileTransferSession* get_ft_session(const std::string& id) {
        auto it = ft_sessions_.find(id);
        return it != ft_sessions_.end() ? it->second.get() : nullptr;
    }

    bool remove_ft_session(const std::string& id) {
        return ft_sessions_.erase(id) > 0;
    }

    // Generate the full session-initiate with file transfer
    std::string generate_ft_initiate_xml(const std::string& from_jid,
                                          const std::string& to_jid,
                                          const FileTransferOffer& offer) {
        auto* session = initiate_file_transfer(from_jid, to_jid, offer);
        if (!session) return "";
        return session->to_initiate_xml(from_jid, to_jid);
    }

    // Generate the HTTP upload request for sharing a file
    std::string generate_upload_request_xml(const std::string& from_jid,
                                            const std::string& upload_service_jid,
                                            const std::string& filename,
                                            int64_t size,
                                            const std::string& content_type) {
        HttpUploadSlot dummy_slot;
        return dummy_slot.to_request_xml(from_jid, upload_service_jid,
                                          filename, size, content_type);
    }

    // Generate message with download link after upload
    static std::string generate_share_message(const std::string& from_jid,
                                               const std::string& to_jid,
                                               const HttpUploadSlot& slot) {
        std::ostringstream oss;
        oss << "<message type=\"chat\" id=\"" << xml_escape(generate_id("msg_")) << "\"";
        oss << " from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<body>" << xml_escape(slot.file_name())
            << " (" << slot.size() << " bytes) - "
            << xml_escape(slot.download_url()) << "</body>";
        oss << "<x xmlns=\"" << XMPPNS::JINGLE_APPS_FILE_TRANSFER << "\">";
        oss << "<file>";
        oss << "<name>" << xml_escape(slot.file_name()) << "</name>";
        oss << "<size>" << slot.size() << "</size>";
        oss << "<url>" << xml_escape(slot.download_url()) << "</url>";
        if (!slot.mime_type().empty()) {
            oss << "<media-type>" << xml_escape(slot.mime_type()) << "</media-type>";
        }
        if (!slot.hash_sha256().empty()) {
            oss << "<hash xmlns=\"" << XMPPNS::HASH
                << "\" algo=\"" << XMPPNS::HASH_SHA256
                << "\">" << xml_escape(slot.hash_sha256()) << "</hash>";
        }
        oss << "</file>";
        oss << "</x>";
        oss << "</message>";
        return oss.str();
    }

    // Generate SOCKS5 bytestream initiation
    static std::string generate_s5b_initiate(const std::string& from_jid,
                                              const std::string& to_jid,
                                              const Socks5BytestreamSession& session) {
        return session.to_query_xml(from_jid, to_jid);
    }

    // Generate IBB stream initiation
    static std::string generate_ibb_initiate(const std::string& from_jid,
                                              const std::string& to_jid,
                                              const IBBStream& stream) {
        return stream.to_open_xml(from_jid, to_jid);
    }

    // Send file data via IBB
    static std::vector<std::string> send_file_via_ibb(const std::string& from_jid,
                                                       const std::string& to_jid,
                                                       const std::string& file_data,
                                                       int block_size = 4096) {
        IBBStream stream(generate_id("ibb_"), block_size);
        stream.set_peer_jid(to_jid);
        stream.set_local_jid(from_jid);

        std::vector<std::string> stanzas;

        // Open stream
        stanzas.push_back(stream.to_open_xml(from_jid, to_jid));

        // Send data blocks
        auto data_stanzas = stream.generate_data_blocks(from_jid, to_jid, file_data);
        stanzas.insert(stanzas.end(), data_stanzas.begin(), data_stanzas.end());

        // Close stream
        stanzas.push_back(stream.to_close_xml(from_jid, to_jid));

        return stanzas;
    }

    // Validate file hash
    static bool validate_file_hash(const std::string& file_data,
                                   const FileTransferOffer& offer) {
        if (!offer.hash_sha256().empty()) {
            SHA256 sha;
            sha.update(file_data);
            if (sha.finalize() != offer.hash_sha256()) {
                return false;
            }
        }
        if (!offer.hash_sha512().empty()) {
            SHA512 sha;
            sha.update(file_data);
            if (sha.finalize() != offer.hash_sha512()) {
                return false;
            }
        }
        return true;
    }

    // Jingle RTP session helper: build RTP description for audio call
    static std::string build_audio_rtp_description() {
        std::ostringstream oss;
        oss << "<description xmlns=\"" << XMPPNS::JINGLE_APPS_RTP << "\" media=\"audio\">";
        for (const auto& codec : get_standard_audio_codecs()) {
            oss << codec.to_xml();
        }
        oss << "</description>";
        return oss.str();
    }

    // Jingle RTP session helper: build RTP description for video call
    static std::string build_video_rtp_description() {
        std::ostringstream oss;
        oss << "<description xmlns=\"" << XMPPNS::JINGLE_APPS_RTP << "\" media=\"video\">";
        for (const auto& codec : get_standard_video_codecs()) {
            oss << codec.to_xml();
        }
        oss << "</description>";
        return oss.str();
    }

    // Build ICE transport with full details
    static IceUdpTransport build_default_ice_transport() {
        IceUdpTransport transport;
        transport.set_ufrag(generate_ufrag());
        transport.set_pwd(generate_password());

        // Add common candidates
        transport.add_candidate(IceCandidate("1", 1, "udp", 2130706431,
            "192.168.1.100", 5000, IceCandidateType::HOST));
        transport.add_candidate(IceCandidate("2", 1, "udp", 2113932031,
            "10.0.0.1", 5001, IceCandidateType::HOST));
        transport.add_candidate(IceCandidate("3", 1, "udp", 1694498815,
            "203.0.113.1", 5000, IceCandidateType::SRFLX));

        return transport;
    }

    // Initiate a Jingle audio call
    JingleSession* initiate_audio_call(const std::string& from_jid,
                                       const std::string& to_jid) {
        auto* session = jingle_manager_->create_session(from_jid, to_jid);
        if (!session) return nullptr;

        auto* content = session->add_content("audio", from_jid);
        content->set_senders("initiator");
        content->set_description_xml(build_audio_rtp_description());

        auto ice = build_default_ice_transport();
        content->set_transport_xml(ice.to_transport_xml());

        return session;
    }

    // Initiate a Jingle video call
    JingleSession* initiate_video_call(const std::string& from_jid,
                                       const std::string& to_jid) {
        auto* session = jingle_manager_->create_session(from_jid, to_jid);
        if (!session) return nullptr;

        auto* content = session->add_content("video", from_jid);
        content->set_senders("initiator");
        content->set_description_xml(build_video_rtp_description());

        auto ice = build_default_ice_transport();
        content->set_transport_xml(ice.to_transport_xml());

        return session;
    }

    // Initiate a Jingle audio+video call
    JingleSession* initiate_av_call(const std::string& from_jid,
                                    const std::string& to_jid) {
        auto* session = jingle_manager_->create_session(from_jid, to_jid);
        if (!session) return nullptr;

        // Audio content
        auto* audio = session->add_content("audio", from_jid);
        audio->set_senders("initiator");
        audio->set_description_xml(build_audio_rtp_description());
        auto ice1 = build_default_ice_transport();
        audio->set_transport_xml(ice1.to_transport_xml());

        // Video content (bundled with same ICE transport group)
        auto* video = session->add_content("video", from_jid);
        video->set_senders("initiator");
        video->set_description_xml(build_video_rtp_description());
        auto ice2 = build_default_ice_transport();
        video->set_transport_xml(ice2.to_transport_xml());

        return session;
    }

private:
    std::unique_ptr<JingleManager> jingle_manager_;
    std::unique_ptr<HttpUploadService> upload_service_;
    std::unordered_map<std::string, std::unique_ptr<FileTransferSession>> ft_sessions_;
    std::unordered_map<std::string, std::unique_ptr<SIStream>> si_streams_;
    std::unordered_map<std::string, std::unique_ptr<IBBStream>> ibb_streams_;
    std::unordered_map<std::string, std::unique_ptr<Socks5BytestreamSession>> s5b_sessions_;
};

// ============================================================================
// XMPP Jingle File Transfer Disco Handler
// ============================================================================

class JingleFTDiscoHandler {
public:
    // Generate disco#info response for the services
    static std::string jingle_disco_info() {
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::DISCO_INFO << "\">";
        oss << "<identity category=\"client\" type=\"pc\" name=\"Progressive Jingle Client\"/>";
        oss << "<feature var=\"" << XMPPNS::JINGLE << "\"/>";
        oss << "<feature var=\"" << XMPPNS::JINGLE_APPS_RTP << "\"/>";
        oss << "<feature var=\"" << XMPPNS::JINGLE_APPS_RTP_AUDIO << "\"/>";
        oss << "<feature var=\"" << XMPPNS::JINGLE_APPS_RTP_VIDEO << "\"/>";
        oss << "<feature var=\"" << XMPPNS::JINGLE_APPS_FILE_TRANSFER << "\"/>";
        oss << "<feature var=\"" << XMPPNS::JINGLE_APPS_FT_THUMB << "\"/>";
        oss << "<feature var=\"" << XMPPNS::JINGLE_TRANSPORT_ICE << "\"/>";
        oss << "<feature var=\"" << XMPPNS::JINGLE_TRANSPORT_IBB << "\"/>";
        oss << "<feature var=\"" << XMPPNS::JINGLE_TRANSPORT_S5B << "\"/>";
        oss << "<feature var=\"" << XMPPNS::IBB << "\"/>";
        oss << "<feature var=\"" << XMPPNS::SOCKS5 << "\"/>";
        oss << "<feature var=\"" << XMPPNS::SI << "\"/>";
        oss << "<feature var=\"" << XMPPNS::SI_FILE_TRANSFER << "\"/>";
        oss << "<feature var=\"" << XMPPNS::HTTP_UPLOAD << "\"/>";
        oss << "<feature var=\"" << XMPPNS::HASH << "\"/>";
        oss << "</query>";
        return oss.str();
    }

    static std::string upload_service_disco_info() {
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::DISCO_INFO << "\">";
        oss << "<identity category=\"store\" type=\"file\" name=\"HTTP File Upload\"/>";
        oss << "<feature var=\"" << XMPPNS::HTTP_UPLOAD << "\"/>";
        oss << "</query>";
        return oss.str();
    }

    static std::string proxy_disco_info() {
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::DISCO_INFO << "\">";
        oss << "<identity category=\"proxy\" type=\"bytestreams\" name=\"SOCKS5 Bytestream Proxy\"/>";
        oss << "<feature var=\"" << XMPPNS::SOCKS5 << "\"/>";
        oss << "</query>";
        return oss.str();
    }
};

// ============================================================================
// MIME Type Validation Helpers
// ============================================================================

static bool is_valid_mime_type(const std::string& mime_type) {
    // Basic format: type/subtype
    size_t slash = mime_type.find('/');
    if (slash == std::string::npos || slash == 0 ||
        slash == mime_type.length() - 1) {
        return false;
    }
    // Must not contain invalid characters
    for (char c : mime_type) {
        if (c < 32 || c > 126) return false;
        if (c == '"' || c == '\\') return false;
    }
    return true;
}

static bool is_mime_type_allowed(const std::string& mime_type,
                                  const std::vector<std::string>& allowed) {
    if (allowed.empty()) return true;
    for (const auto& m : allowed) {
        if (m == mime_type) return true;
        // Support wildcard matching: "image/*" matches "image/jpeg"
        if (m.size() >= 2 && m[m.size() - 1] == '*') {
            std::string prefix = m.substr(0, m.size() - 1);
            if (mime_type.compare(0, prefix.size(), prefix) == 0) {
                return true;
            }
        }
    }
    return false;
}

// ============================================================================
// Upload Slot Cleanup / Expiry Daemon
// ============================================================================

class UploadSlotExpiryDaemon {
public:
    UploadSlotExpiryDaemon(HttpUploadService& service, int check_interval_ms = 60000)
        : service_(service), check_interval_ms_(check_interval_ms), running_(false) {}

    ~UploadSlotExpiryDaemon() {
        stop();
    }

    void start() {
        running_ = true;
        // Note: In real implementation this would spawn a thread.
        // For this file, we just set the flag.
    }

    void stop() {
        running_ = false;
    }

    void check_and_clean() {
        if (!running_) return;
        service_.expire_slots();
    }

    bool is_running() const { return running_; }

private:
    HttpUploadService& service_;
    int check_interval_ms_;
    bool running_;
};

// ============================================================================
// Utility: Format bytes for human-readable display
// ============================================================================

static std::string format_bytes(int64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024.0 && i < 4) {
        size /= 1024.0;
        i++;
    }
    std::ostringstream oss;
    if (i == 0) {
        oss << bytes << " " << units[i];
    } else {
        oss << std::fixed << std::setprecision(1) << size << " " << units[i];
    }
    return oss.str();
}

// ============================================================================
// Sanity test - verify basic functionality
// ============================================================================

static void sanity_test_jingle_ft() {
    // Test Jingle session creation
    JingleSession session("test-sid-1", "alice@example.com", "bob@example.com");
    assert(!session.sid().empty());

    // Test content creation
    auto* content = session.add_content("audio", "alice@example.com");
    assert(content != nullptr);
    assert(content->name() == "audio");

    // Test XML generation
    std::string initiate_xml = session.to_initiate_xml("alice@example.com", "bob@example.com");
    assert(!initiate_xml.empty());
    assert(initiate_xml.find("session-initiate") != std::string::npos);

    // Test ICE transport
    IceUdpTransport ice;
    ice.set_ufrag("test1234");
    ice.set_pwd("password1234567890123456789012");
    std::string ice_xml = ice.to_transport_xml();
    assert(!ice_xml.empty());
    assert(ice_xml.find("ice-udp") != std::string::npos);

    // Test File Transfer Offer
    FileTransferOffer offer;
    offer.set_name("test.jpg");
    offer.set_size(12345);
    offer.set_media_type("image/jpeg");
    offer.set_hash_sha256(SHA256::hash("test data"));
    std::string offer_xml = offer.to_description_xml();
    assert(!offer_xml.empty());
    assert(offer_xml.find("file-transfer") != std::string::npos);

    // Test HTTP Upload
    HttpUploadService upload_service;
    auto* slot = upload_service.allocate_slot("user@example.com",
        "photo.jpg", 1024000, "image/jpeg");
    assert(slot != nullptr);
    assert(!slot->upload_url().empty());

    // Test IBB
    IBBStream ibb("ibb-test-1", 4096);
    std::string ibb_xml = ibb.to_jingle_transport_xml();
    assert(!ibb_xml.empty());
    assert(ibb_xml.find("ibb") != std::string::npos);

    // Test SOCKS5
    Socks5BytestreamSession s5b("s5b-test-1");
    s5b.add_proxy(Socks5BytestreamProxy("proxy.example.com", "10.0.0.1", 1080));
    std::string s5b_xml = s5b.to_jingle_transport_xml();
    assert(!s5b_xml.empty());
    assert(s5b_xml.find("s5b") != std::string::npos);

    // Test SHA-256
    std::string hash_hex = SHA256::hash("hello world");
    assert(!hash_hex.empty());
    assert(hash_hex.size() == 64);

    // Test SHA-512
    std::string hash512_hex = SHA512::hash("hello world");
    assert(!hash512_hex.empty());
    assert(hash512_hex.size() == 128);

    // Test Base64
    std::string encoded = base64_encode("hello");
    assert(encoded == "aGVsbG8=");
    auto decoded = base64_decode(encoded);
    assert(std::string(decoded.begin(), decoded.end()) == "hello");

    // Test Jingle Manager
    JingleManager manager;
    auto* jsession = manager.create_session("alice@example.com", "bob@example.com");
    assert(jsession != nullptr);
    assert(manager.get_session(jsession->sid()) == jsession);

    // Test session terminate XML
    std::string term_xml = jsession->to_terminate_xml("alice@example.com", "bob@example.com",
        JingleReason::SUCCESS);
    assert(!term_xml.empty());
    assert(term_xml.find("session-terminate") != std::string::npos);
    assert(term_xml.find("success") != std::string::npos);

    // Test RTP codecs
    auto audio_codecs = get_standard_audio_codecs();
    assert(!audio_codecs.empty());
    auto video_codecs = get_standard_video_codecs();
    assert(!video_codecs.empty());

    // Test JingleFileTransfer orchestrator
    JingleFileTransfer jft;
    auto* ft_session = jft.create_ft_session("ft-1", offer);
    assert(ft_session != nullptr);
    assert(ft_session->progress() == 0.0);

    // Test hash verification
    std::string test_data = "file content for hash verification";
    SHA256 sha;
    sha.update(test_data);
    FileTransferOffer verify_offer;
    verify_offer.set_hash_sha256(sha.finalize());
    assert(JingleFileTransfer::validate_file_hash(test_data, verify_offer));
}

// ============================================================================
// End of File
// ============================================================================

}  // namespace xmpp
}  // namespace progressive
