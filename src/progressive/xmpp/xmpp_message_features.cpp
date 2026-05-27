// xmpp_message_features.cpp - Advanced XMPP message features
// Implements: XEP-0184 (Delivery Receipts), XEP-0333 (Chat Markers),
// XEP-0085 (Chat State Notifications), XEP-0280 (Message Carbons),
// XEP-0313 (Message Archive Management), XEP-0308 (Message Correction),
// XEP-0334 (Processing Hints), XEP-0224 (Attention),
// XEP-0393 (Message Styling), XEP-0428 (Fallback Indication),
// XEP-0422 (Fastening), XEP-0424 (Message Retraction),
// XEP-0444 (Reactions), XEP-0380 (Explicit Encryption),
// XEP-0420 (Stanza Content Encryption), Message Expiration
// 3500+ lines of production-grade message feature handling

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <deque>
#include <memory>
#include <functional>
#include <optional>
#include <variant>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>
#include <cstring>
#include <ctime>
#include <regex>
#include <set>
#include <thread>
#include <type_traits>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <nlohmann/json.hpp>

// =============================================================================
// progressive::xmpp namespace
// =============================================================================
namespace progressive {
namespace xmpp {

using json = nlohmann::json;

// =============================================================================
// XML namespace URIs for message features
// =============================================================================
namespace ns {
    // Core message namespaces
    constexpr const char* JABBER_CLIENT       = "jabber:client";
    constexpr const char* STREAMS             = "http://etherx.jabber.org/streams";

    // XEP-0184: Message Delivery Receipts
    constexpr const char* RECEIPTS            = "urn:xmpp:receipts";

    // XEP-0333: Chat Markers
    constexpr const char* CHAT_MARKERS        = "urn:xmpp:chat-markers:0";

    // XEP-0085: Chat State Notifications
    constexpr const char* CHAT_STATES         = "http://jabber.org/protocol/chatstates";

    // XEP-0280: Message Carbons
    constexpr const char* CARBONS             = "urn:xmpp:carbons:2";

    // XEP-0313: Message Archive Management
    constexpr const char* MAM                 = "urn:xmpp:mam:2";
    constexpr const char* MAM_TMP             = "urn:xmpp:mam:tmp";
    constexpr const char* MAM_1               = "urn:xmpp:mam:1";
    constexpr const char* MAM_2               = "urn:xmpp:mam:2";

    // XEP-0308: Last Message Correction
    constexpr const char* MESSAGE_CORRECT     = "urn:xmpp:message-correct:0";

    // XEP-0334: Message Processing Hints
    constexpr const char* HINTS               = "urn:xmpp:hints";

    // XEP-0224: Attention
    constexpr const char* ATTENTION           = "urn:xmpp:attention:0";

    // XEP-0393: Message Styling / References
    constexpr const char* REFERENCE           = "urn:xmpp:reference:0";
    constexpr const char* REPLY               = "urn:xmpp:reply:0";

    // XEP-0428: Fallback Indication
    constexpr const char* FALLBACK            = "urn:xmpp:fallback:0";

    // XEP-0422: Fastening
    constexpr const char* FASTEN              = "urn:xmpp:fasten:0";

    // XEP-0424: Message Retraction
    constexpr const char* RETRACT             = "urn:xmpp:retract:0";

    // XEP-0444: Reactions
    constexpr const char* REACTIONS           = "urn:xmpp:reactions:0";

    // XEP-0380: Explicit Message Encryption
    constexpr const char* EME                 = "urn:xmpp:eme:0";

    // XEP-0420: Stanza Content Encryption
    constexpr const char* SCE                 = "urn:xmpp:sce:0";

    // XEP-0335: JSON Containers
    constexpr const char* JSON_CONTAINER      = "urn:xmpp:json-container:0";

    // Other
    constexpr const char* DELAY               = "urn:xmpp:delay";
    constexpr const char* FORWARD             = "urn:xmpp:forward:0";
    constexpr const char* STABLE_ID           = "urn:xmpp:sid:0";
    constexpr const char* HASHES              = "urn:xmpp:hashes:2";
    constexpr const char* DATA                = "jabber:x:data";
    constexpr const char* STANZAS             = "urn:ietf:params:xml:ns:xmpp-stanzas";

    // Expiration (custom placeholder before formal XEP)
    constexpr const char* EXPIRE              = "urn:xmpp:expire:0";
}

// =============================================================================
// Forward declarations
// =============================================================================
struct Jid;
class MessageFeaturesEngine;
class MessageArchiveManager;
class MessageReactionManager;
class MessageRetractionManager;
class MessageEncryptionManager;
class ChatStateTracker;
class DeliveryReceiptManager;
class ChatMarkerManager;
class MessageCarbonManager;
class MessageCorrectionManager;

// =============================================================================
// JID (Jabber Identifier) - minimal inline for self-containedness
// =============================================================================
struct Jid {
    std::string node;
    std::string domain;
    std::string resource;

    Jid() = default;
    Jid(const std::string& bare) { parse(bare); }
    Jid(const std::string& n, const std::string& d, const std::string& r = "")
        : node(n), domain(d), resource(r) {}

    static std::optional<Jid> from_string(const std::string& str) {
        Jid j;
        if (j.parse(str)) return j;
        return std::nullopt;
    }

    bool parse(const std::string& str) {
        if (str.empty()) return false;
        std::string s = str;
        size_t slash = s.find('/');
        if (slash != std::string::npos) {
            resource = s.substr(slash + 1);
            s = s.substr(0, slash);
        }
        size_t at = s.find('@');
        if (at != std::string::npos) {
            node = s.substr(0, at);
            domain = s.substr(at + 1);
        } else {
            domain = s;
        }
        return !domain.empty();
    }

    std::string bare() const {
        if (node.empty()) return domain;
        return node + "@" + domain;
    }

    std::string full() const {
        std::string result = bare();
        if (!resource.empty()) result += "/" + resource;
        return result;
    }

    bool operator==(const Jid& o) const {
        return node == o.node && domain == o.domain && resource == o.resource;
    }

    bool bare_eq(const Jid& o) const {
        return node == o.node && domain == o.domain;
    }

    bool empty() const { return domain.empty(); }
};

// =============================================================================
// Utility functions
// =============================================================================
namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t now_sec() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string xml_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default: out += c;
        }
    }
    return out;
}

std::string gen_message_id() {
    static std::atomic<int64_t> counter{1};
    std::ostringstream oss;
    oss << "msg-" << std::hex << now_ms() << "-"
        << std::dec << counter.fetch_add(1, std::memory_order_relaxed);
    return oss.str();
}

std::string gen_unique_id() {
    static std::atomic<int64_t> counter{1};
    std::ostringstream oss;
    oss << "uid-" << std::hex << now_ms() << "-"
        << std::dec << counter.fetch_add(1, std::memory_order_relaxed);
    return oss.str();
}

std::string gen_nonce(size_t len = 32) {
    static const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static thread_local std::mt19937 rng(
        static_cast<unsigned>(now_ms() ^
        std::hash<std::thread::id>{}(std::this_thread::get_id())));
    std::uniform_int_distribution<> dist(0, 61);
    std::string nonce(len, 'A');
    for (auto& c : nonce) c = charset[dist(rng)];
    return nonce;
}

std::string sha256_hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(hash, &ctx);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        oss << std::setw(2) << (int)hash[i];
    return oss.str();
}

std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()),
         data.size(), result, &len);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < len; i++)
        oss << std::setw(2) << (int)result[i];
    return oss.str();
}

std::string base64_encode(const std::string& data) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    int val = 0, valb = -6;
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string base64_decode(const std::string& s) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(unsigned char)table[i]] = i;
    int val = 0, valb = -8;
    for (unsigned char c : s) {
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

// Simple XML attribute extraction
std::string xml_get_attr(const std::string& xml, const std::string& attr) {
    std::string search = attr + "=\"";
    size_t pos = xml.find(search);
    if (pos == std::string::npos) {
        search = attr + "='";
        pos = xml.find(search);
        if (pos == std::string::npos) return "";
    }
    pos += search.size();
    char delim = (xml[pos - 1] == '"') ? '"' : '\'';
    size_t end = xml.find(delim, pos);
    if (end == std::string::npos) return "";
    return xml.substr(pos, end - pos);
}

// Check if XML contains a child element with a given namespace
bool xml_has_child_ns(const std::string& xml, const std::string& xmlns,
                       const std::string& child) {
    std::string pattern = "<" + child;
    size_t pos = xml.find(pattern);
    while (pos != std::string::npos) {
        size_t end = xml.find('>', pos);
        if (end == std::string::npos) return false;
        std::string tag = xml.substr(pos, end - pos + 1);
        if (tag.find("xmlns=\"" + xmlns + "\"") != std::string::npos ||
            tag.find("xmlns='" + xmlns + "'") != std::string::npos) {
            return true;
        }
        pos = xml.find(pattern, end);
    }
    return false;
}

// Extract XML child text content by element name
std::string xml_get_child(const std::string& xml, const std::string& child,
                           const std::string& xmlns) {
    std::string pattern = "<" + child;
    size_t pos = xml.find(pattern);
    while (pos != std::string::npos) {
        size_t tag_end = xml.find('>', pos);
        if (tag_end == std::string::npos) break;
        std::string open_tag = xml.substr(pos, tag_end - pos + 1);
        bool ns_match = xmlns.empty() ||
            open_tag.find(xmlns) != std::string::npos;
        if (ns_match) {
            std::string close_tag = "</" + child + ">";
            size_t close = xml.find(close_tag, tag_end);
            if (close != std::string::npos) {
                return xml.substr(tag_end + 1, close - tag_end - 1);
            }
            // Self-closing
            if (xml[tag_end - 1] == '/') return "";
        }
        pos = xml.find(pattern, tag_end);
    }
    return "";
}

// Simple XML tag builder
std::string xml_tag(const std::string& name, const std::string& content,
                     const std::string& xmlns = "",
                     const std::map<std::string, std::string>& attrs = {}) {
    std::ostringstream oss;
    oss << "<" << name;
    if (!xmlns.empty()) oss << " xmlns='" << xmlns << "'";
    for (const auto& [k, v] : attrs) {
        oss << " " << k << "='" << xml_escape(v) << "'";
    }
    if (content.empty()) {
        oss << "/>";
    } else {
        oss << ">" << content << "</" << name << ">";
    }
    return oss.str();
}

// Build XML element with attributes, and optional child content
std::string xml_element_start(const std::string& name,
                               const std::string& xmlns = "",
                               const std::map<std::string, std::string>& attrs = {}) {
    std::ostringstream oss;
    oss << "<" << name;
    if (!xmlns.empty()) oss << " xmlns='" << xmlns << "'";
    for (const auto& [k, v] : attrs) {
        oss << " " << k << "='" << xml_escape(v) << "'";
    }
    oss << ">";
    return oss.str();
}

std::string xml_element_end(const std::string& name) {
    return "</" + name + ">";
}

std::string xml_element(const std::string& name,
                         const std::string& xmlns,
                         const std::map<std::string, std::string>& attrs,
                         const std::string& inner) {
    std::ostringstream oss;
    oss << xml_element_start(name, xmlns, attrs);
    oss << inner;
    oss << xml_element_end(name);
    return oss.str();
}

// =============================================================================
// Timestamp formatting for XMPP (XEP-0082: XMPP Date/Time Profiles)
// =============================================================================
std::string format_xmpp_timestamp(int64_t ts_ms) {
    time_t t = ts_ms / 1000;
    struct tm tm_buf;
    gmtime_r(&t, &tm_buf);
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << (ts_ms % 1000) << "Z";
    return oss.str();
}

int64_t parse_xmpp_timestamp(const std::string& ts) {
    std::tm tm = {};
    int ms = 0;
    std::istringstream iss(ts);
    char sep;
    iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    if (iss.peek() == '.') {
        iss >> sep >> ms;
    }
    time_t t = timegm(&tm);
    return static_cast<int64_t>(t) * 1000 + ms;
}

} // anonymous namespace

// =============================================================================
// Message Types enum
// =============================================================================
enum class MessageType : uint8_t {
    NORMAL,
    CHAT,
    GROUPCHAT,
    HEADLINE,
    ERROR
};

// =============================================================================
// Delivery Receipt state
// =============================================================================
enum class ReceiptState : uint8_t {
    NONE,       // No receipt requested
    REQUESTED,  // Receipt requested by sender
    RECEIVED,   // Recipient acknowledged
    DELIVERED   // Delivered to client
};

// =============================================================================
// Chat Marker types
// =============================================================================
enum class ChatMarker : uint8_t {
    NONE,
    RECEIVED,      // Message arrived at client
    DISPLAYED,     // Message shown to user
    ACKNOWLEDGED   // User interacted with message
};

// =============================================================================
// Chat State types
// =============================================================================
enum class ChatState : uint8_t {
    NONE,
    ACTIVE,        // User is actively participating
    INACTIVE,      // User has not interacted for some time
    GONE,          // User has closed the chat interface
    COMPOSING,     // User is composing a message
    PAUSED         // User has paused composition
};

// =============================================================================
// Processing hint types
// =============================================================================
enum class ProcessingHint : uint8_t {
    NONE,
    NO_PERMANENT_STORE,  // Do not store permanently
    NO_STORE,             // Do not store at all
    NO_COPY,              // Do not copy to other resources
    STORE                 // Store (makes no-storage explicit override clear)
};

// =============================================================================
// Message Archive query structure (XEP-0313)
// =============================================================================
struct MamQuery {
    std::string query_id;
    Jid from;
    Jid to;
    std::optional<int64_t> start_time;
    std::optional<int64_t> end_time;
    std::optional<std::string> before_id;
    std::optional<std::string> after_id;
    std::optional<std::string> with_jid;
    std::optional<int> max_results;
    bool complete = false;
    bool flip_page = false;
    std::vector<std::string> result_ids;
};

// =============================================================================
// Archived message result (XEP-0313)
// =============================================================================
struct ArchivedMessage {
    std::string archive_id;
    std::string stanza_id;
    std::string by;
    Jid from;
    Jid to;
    std::string body;
    std::string html_body;
    std::string thread;
    int64_t timestamp;
    MessageType msg_type;
    bool has_receipt_request;
    bool has_chat_marker;
    ChatMarker marker_type;
    std::string replace_id;
    std::vector<std::string> reaction_emojis;
    std::map<std::string, std::string> extra_attrs;
};

// =============================================================================
// Message reaction (XEP-0444)
// =============================================================================
struct MessageReaction {
    std::string message_id;
    std::string reactor_jid;
    std::vector<std::string> emojis;
    int64_t timestamp;
};

// =============================================================================
// Message retraction (XEP-0424)
// =============================================================================
struct MessageRetraction {
    std::string message_id;
    std::string retractor_jid;
    std::string reason;
    int64_t timestamp;
};

// =============================================================================
// Message correction (XEP-0308)
// =============================================================================
struct MessageCorrection {
    std::string original_id;
    std::string new_body;
    std::string new_html_body;
    std::string corrector_jid;
    int64_t timestamp;
};

// =============================================================================
// Encrypted content info (XEP-0380)
// =============================================================================
struct EncryptionInfo {
    std::string namespace_uri;  // e.g., urn:xmpp:omemo:1
    std::string name;           // e.g., OMEMO
    bool is_trusted;
    std::string key_fingerprint;
};

// =============================================================================
// Fastening reference (XEP-0422)
// =============================================================================
struct FasteningReference {
    std::string apply_to_id;       // message id being fastened to
    std::string source_jid;
    std::string type;              // reaction, retraction, etc.
    json payload;                  // type-specific payload
    int64_t timestamp;
    bool external = false;
};

// =============================================================================
// Reply data (XEP-0393)
// =============================================================================
struct ReplyData {
    std::string to_message_id;
    std::string to_sender_jid;
    std::string to_body_preview;
    int64_t to_timestamp;
    std::vector<std::string> to_media_ids;
};

// =============================================================================
// Fallback indication data (XEP-0428)
// =============================================================================
struct FallbackData {
    bool is_fallback = false;
    std::string for_namespace;
    std::vector<std::string> original_tags;
};

// =============================================================================
// Rendered message (for display/styling)
// =============================================================================
struct StyledMessage {
    std::string plain_body;
    std::string xhtml_im_body;
    std::string markdown_body;
    std::vector<ReplyData> quoted_replies;
    std::vector<std::string> mentions;
    bool has_styling = false;
    std::string styling_engine;
};

// =============================================================================
// Full message context
// =============================================================================
struct MessageContext {
    // Core
    std::string message_id;
    std::string stanza_id;
    Jid from;
    Jid to;
    std::string body;
    std::string html_body;
    std::string thread;
    MessageType msg_type;
    int64_t timestamp;

    // Delivery Receipts (XEP-0184)
    ReceiptState receipt_state;
    std::string receipt_id;

    // Chat Markers (XEP-0333)
    ChatMarker marker;
    std::string marker_id;

    // Chat States (XEP-0085)
    ChatState chat_state;

    // Carbons (XEP-0280)
    bool is_carbon_copy;
    bool carbon_sent;

    // MAM (XEP-0313)
    bool is_archived;
    std::string archive_id;

    // Correction (XEP-0308)
    std::optional<MessageCorrection> correction;

    // Processing Hints (XEP-0334)
    std::vector<ProcessingHint> hints;

    // Attention (XEP-0224)
    bool requires_attention;

    // Reply/References (XEP-0393)
    std::optional<ReplyData> reply;

    // Fallback (XEP-0428)
    FallbackData fallback;

    // Fastening (XEP-0422)
    std::vector<FasteningReference> fastenings;

    // Retraction (XEP-0424)
    std::optional<MessageRetraction> retraction;

    // Reactions (XEP-0444)
    std::vector<MessageReaction> reactions;

    // Encryption (XEP-0380 / XEP-0420)
    std::optional<EncryptionInfo> encryption;
    bool is_content_encrypted;
    std::string encrypted_content_ns;

    // Styling
    StyledMessage styled;

    // Expiration
    std::optional<int64_t> expires_at;
    int ttl_seconds;

    // Misc
    std::string lang;
    std::string origin_id;
    bool is_muc_pm;
    std::string muc_room;
    std::map<std::string, std::string> extended_attrs;
};

// =============================================================================
// XML Builder for Message Features
// =============================================================================
class MessageXmlBuilder {
public:
    // --- XEP-0184: Delivery Receipts ---
    static std::string build_receipt_request() {
        return "<request xmlns='urn:xmpp:receipts'/>";
    }

    static std::string build_receipt_received(const std::string& msg_id) {
        return "<received xmlns='urn:xmpp:receipts' id='" +
               xml_escape(msg_id) + "'/>";
    }

    // --- XEP-0333: Chat Markers ---
    static std::string build_chat_marker(ChatMarker marker,
                                          const std::string& msg_id,
                                          const std::string& marker_type_hint = "") {
        std::string tag;
        switch (marker) {
            case ChatMarker::RECEIVED:     tag = "received"; break;
            case ChatMarker::DISPLAYED:    tag = "displayed"; break;
            case ChatMarker::ACKNOWLEDGED: tag = "acknowledged"; break;
            default: return "";
        }
        std::ostringstream oss;
        oss << "<" << tag << " xmlns='urn:xmpp:chat-markers:0' id='"
            << xml_escape(msg_id) << "'";
        if (!marker_type_hint.empty()) {
            oss << " type='" << xml_escape(marker_type_hint) << "'";
        }
        oss << "/>";
        return oss.str();
    }

    // --- XEP-0085: Chat State Notifications ---
    static std::string build_chat_state(ChatState state) {
        switch (state) {
            case ChatState::ACTIVE:    return "<active xmlns='http://jabber.org/protocol/chatstates'/>";
            case ChatState::INACTIVE:  return "<inactive xmlns='http://jabber.org/protocol/chatstates'/>";
            case ChatState::GONE:      return "<gone xmlns='http://jabber.org/protocol/chatstates'/>";
            case ChatState::COMPOSING: return "<composing xmlns='http://jabber.org/protocol/chatstates'/>";
            case ChatState::PAUSED:    return "<paused xmlns='http://jabber.org/protocol/chatstates'/>";
            default: return "";
        }
    }

    // --- XEP-0280: Message Carbons ---
    static std::string build_carbon_enable() {
        return "<enable xmlns='urn:xmpp:carbons:2'/>";
    }

    static std::string build_carbon_disable() {
        return "<disable xmlns='urn:xmpp:carbons:2'/>";
    }

    static std::string build_carbon_forward(const std::string& inner_message_xml,
                                              bool sent) {
        std::string tag = sent ? "sent" : "received";
        std::ostringstream oss;
        oss << "<" << tag << " xmlns='urn:xmpp:carbons:2'>"
            << "<forwarded xmlns='urn:xmpp:forward:0'>"
            << inner_message_xml
            << "</forwarded>"
            << "</" << tag << ">";
        return oss.str();
    }

    // --- XEP-0313: Message Archive Management ---
    static std::string build_mam_query(const MamQuery& q) {
        std::ostringstream oss;
        oss << "<query xmlns='urn:xmpp:mam:2' queryid='" << xml_escape(q.query_id) << "'>";

        // RSM paging
        if (q.after_id.has_value()) {
            oss << "<set xmlns='http://jabber.org/protocol/rsm'>"
                << "<after>" << xml_escape(*q.after_id) << "</after>";
            if (q.max_results.has_value()) {
                oss << "<max>" << *q.max_results << "</max>";
            }
            oss << "</set>";
        } else if (q.before_id.has_value()) {
            oss << "<set xmlns='http://jabber.org/protocol/rsm'>"
                << "<before>" << xml_escape(*q.before_id) << "</before>";
            if (q.max_results.has_value()) {
                oss << "<max>" << *q.max_results << "</max>";
            }
            oss << "</set>";
        } else if (q.max_results.has_value()) {
            oss << "<set xmlns='http://jabber.org/protocol/rsm'>"
                << "<max>" << *q.max_results << "</max>"
                << "</set>";
        }

        // Data form filters
        oss << "<x xmlns='jabber:x:data' type='submit'>"
            << "<field var='FORM_TYPE' type='hidden'>"
            << "<value>urn:xmpp:mam:2</value>"
            << "</field>";

        if (q.start_time.has_value()) {
            oss << "<field var='start'>"
                << "<value>" << format_xmpp_timestamp(*q.start_time) << "</value>"
                << "</field>";
        }
        if (q.end_time.has_value()) {
            oss << "<field var='end'>"
                << "<value>" << format_xmpp_timestamp(*q.end_time) << "</value>"
                << "</field>";
        }
        if (q.with_jid.has_value()) {
            oss << "<field var='with'>"
                << "<value>" << xml_escape(*q.with_jid) << "</value>"
                << "</field>";
        }

        oss << "</x></query>";
        return oss.str();
    }

    static std::string build_mam_message(const ArchivedMessage& msg) {
        std::ostringstream oss;
        oss << "<forwarded xmlns='urn:xmpp:forward:0'>"
            << "<delay xmlns='urn:xmpp:delay' stamp='"
            << format_xmpp_timestamp(msg.timestamp) << "'/>"
            << "<message xmlns='jabber:client'";

        if (msg.msg_type != MessageType::NORMAL) {
            std::string mtype;
            switch (msg.msg_type) {
                case MessageType::CHAT: mtype = "chat"; break;
                case MessageType::GROUPCHAT: mtype = "groupchat"; break;
                case MessageType::HEADLINE: mtype = "headline"; break;
                case MessageType::ERROR: mtype = "error"; break;
                default: mtype = "normal";
            }
            oss << " type='" << mtype << "'";
        }

        if (!msg.from.empty()) oss << " from='" << xml_escape(msg.from.full()) << "'";
        if (!msg.to.empty()) oss << " to='" << xml_escape(msg.to.full()) << "'";
        oss << " id='" << xml_escape(msg.stanza_id) << "'>";

        if (!msg.body.empty()) {
            oss << "<body>" << xml_escape(msg.body) << "</body>";
        }
        if (!msg.html_body.empty()) {
            oss << "<html xmlns='http://jabber.org/protocol/xhtml-im'>"
                << "<body xmlns='http://www.w3.org/1999/xhtml'>"
                << msg.html_body
                << "</body></html>";
        }
        if (!msg.thread.empty()) {
            oss << "<thread>" << xml_escape(msg.thread) << "</thread>";
        }

        // Stable ID
        oss << "<stanza-id xmlns='urn:xmpp:sid:0' id='"
            << xml_escape(msg.archive_id) << "' by='" << xml_escape(msg.by) << "'/>";

        if (msg.has_receipt_request) {
            oss << "<request xmlns='urn:xmpp:receipts'/>";
        }

        oss << "</message></forwarded>";
        return oss.str();
    }

    static std::string build_mam_result(const std::string& query_id,
                                          const std::string& message_id,
                                          const std::string& forwarded) {
        std::ostringstream oss;
        oss << "<result xmlns='urn:xmpp:mam:2' queryid='"
            << xml_escape(query_id) << "' id='" << xml_escape(message_id) << "'>"
            << forwarded
            << "</result>";
        return oss.str();
    }

    static std::string build_mam_fin(const std::string& query_id,
                                       bool complete,
                                       const std::string& first = "",
                                       const std::string& last = "",
                                       int64_t count = 0) {
        std::ostringstream oss;
        oss << "<fin xmlns='urn:xmpp:mam:2'";
        if (!query_id.empty()) oss << " queryid='" << xml_escape(query_id) << "'";
        oss << " complete='" << (complete ? "true" : "false") << "'>";

        if (!first.empty() || !last.empty() || count > 0) {
            oss << "<set xmlns='http://jabber.org/protocol/rsm'>";
            if (!first.empty()) oss << "<first index='0'>" << xml_escape(first) << "</first>";
            if (!last.empty()) oss << "<last>" << xml_escape(last) << "</last>";
            if (count > 0) oss << "<count>" << count << "</count>";
            oss << "</set>";
        }

        oss << "</fin>";
        return oss.str();
    }

    static std::string build_mam_prefs_default() {
        return "<prefs xmlns='urn:xmpp:mam:2' default='always'/>";
    }

    static std::string build_mam_prefs_update(const std::string& default_rule,
                                                const std::vector<std::pair<std::string, std::string>>& jid_rules) {
        std::ostringstream oss;
        oss << "<prefs xmlns='urn:xmpp:mam:2' default='" << xml_escape(default_rule) << "'>";
        for (const auto& [jid, rule] : jid_rules) {
            oss << "<always jid='" << xml_escape(jid) << "'/>";
        }
        oss << "</prefs>";
        return oss.str();
    }

    // --- XEP-0308: Message Correction ---
    static std::string build_correction(const std::string& original_id) {
        return "<replace xmlns='urn:xmpp:message-correct:0' id='" +
               xml_escape(original_id) + "'/>";
    }

    // --- XEP-0334: Processing Hints ---
    static std::string build_processing_hint(ProcessingHint hint) {
        switch (hint) {
            case ProcessingHint::NO_PERMANENT_STORE:
                return "<no-permanent-store xmlns='urn:xmpp:hints'/>";
            case ProcessingHint::NO_STORE:
                return "<no-store xmlns='urn:xmpp:hints'/>";
            case ProcessingHint::NO_COPY:
                return "<no-copy xmlns='urn:xmpp:hints'/>";
            case ProcessingHint::STORE:
                return "<store xmlns='urn:xmpp:hints'/>";
            default: return "";
        }
    }

    static std::string build_hints(const std::vector<ProcessingHint>& hints) {
        std::ostringstream oss;
        for (auto hint : hints) {
            oss << build_processing_hint(hint);
        }
        return oss.str();
    }

    // --- XEP-0224: Attention ---
    static std::string build_attention() {
        return "<attention xmlns='urn:xmpp:attention:0'/>";
    }

    // --- XEP-0393: Message Styling / Reply ---
    static std::string build_reply_reference(const ReplyData& reply) {
        std::ostringstream oss;
        oss << "<reply xmlns='urn:xmpp:reply:0' to='"
            << xml_escape(reply.to_message_id) << "'>";
        if (!reply.to_sender_jid.empty()) {
            oss << "<to xmlns='urn:xmpp:reply:0' jid='"
                << xml_escape(reply.to_sender_jid) << "'/>";
        }
        if (!reply.to_body_preview.empty()) {
            oss << "<body xmlns='urn:xmpp:reply:0'>"
                << xml_escape(reply.to_body_preview)
                << "</body>";
        }
        oss << "</reply>";
        return oss.str();
    }

    static std::string build_styled_body(const std::string& plain_body,
                                           const std::string& markdown = "",
                                           const std::string& xhtml = "") {
        std::ostringstream oss;
        oss << "<body>" << xml_escape(plain_body) << "</body>";

        if (!xhtml.empty()) {
            oss << "<html xmlns='http://jabber.org/protocol/xhtml-im'>"
                << "<body xmlns='http://www.w3.org/1999/xhtml'>"
                << xhtml
                << "</body></html>";
        }
        return oss.str();
    }

    // --- XEP-0428: Fallback Indication ---
    static std::string build_fallback(const std::string& for_ns = "",
                                        const std::vector<std::string>& tags = {}) {
        std::ostringstream oss;
        oss << "<fallback xmlns='urn:xmpp:fallback:0'";
        if (!for_ns.empty()) oss << " for='" << xml_escape(for_ns) << "'";
        oss << ">";
        for (const auto& t : tags) {
            oss << "<tag>" << xml_escape(t) << "</tag>";
        }
        oss << "</fallback>";
        return oss.str();
    }

    // --- XEP-0422: Fastening ---
    static std::string build_fastening(const FasteningReference& f) {
        std::ostringstream oss;
        oss << "<apply-to xmlns='urn:xmpp:fasten:0' id='"
            << xml_escape(f.apply_to_id) << "'";
        if (f.external) {
            oss << " xmlns:fasten='urn:xmpp:fasten:0'";
        }
        oss << ">";
        oss << f.payload.dump();
        oss << "</apply-to>";
        return oss.str();
    }

    // --- XEP-0424: Message Retraction ---
    static std::string build_retraction(const std::string& message_id,
                                          const std::string& reason = "") {
        std::ostringstream oss;
        oss << "<retract xmlns='urn:xmpp:retract:0' id='"
            << xml_escape(message_id) << "'";
        if (!reason.empty()) {
            oss << " reason='" << xml_escape(reason) << "'";
        }
        oss << "/>";
        return oss.str();
    }

    static std::string build_retraction_tombstone(const std::string& message_id,
                                                    const std::string& by,
                                                    int64_t timestamp) {
        std::ostringstream oss;
        oss << "<retracted xmlns='urn:xmpp:retract:0' id='"
            << xml_escape(message_id) << "' by='" << xml_escape(by)
            << "' stamp='" << format_xmpp_timestamp(timestamp) << "'/>";
        return oss.str();
    }

    // --- XEP-0444: Reactions ---
    static std::string build_reaction(const std::string& to_message_id,
                                        const std::vector<std::string>& emojis) {
        std::ostringstream oss;
        oss << "<reactions xmlns='urn:xmpp:reactions:0' id='"
            << xml_escape(to_message_id) << "'>";
        for (const auto& e : emojis) {
            oss << "<reaction>" << xml_escape(e) << "</reaction>";
        }
        oss << "</reactions>";
        return oss.str();
    }

    static std::string build_reaction_update(const std::string& to_message_id,
                                               const std::map<std::string, std::vector<std::string>>& jid_reactions) {
        std::ostringstream oss;
        oss << "<reactions xmlns='urn:xmpp:reactions:0' id='"
            << xml_escape(to_message_id) << "'>";
        for (const auto& [jid, emojis] : jid_reactions) {
            for (const auto& e : emojis) {
                oss << "<reaction jid='" << xml_escape(jid) << "'>"
                    << xml_escape(e) << "</reaction>";
            }
        }
        oss << "</reactions>";
        return oss.str();
    }

    // --- XEP-0380: Explicit Message Encryption ---
    static std::string build_eme(const std::string& enc_namespace,
                                   const std::string& name = "",
                                   const std::string& fingerprint = "") {
        std::ostringstream oss;
        oss << "<encryption xmlns='urn:xmpp:eme:0' namespace='"
            << xml_escape(enc_namespace) << "'";
        if (!name.empty()) oss << " name='" << xml_escape(name) << "'";
        if (!fingerprint.empty()) oss << " fingerprint='" << xml_escape(fingerprint) << "'";
        oss << "/>";
        return oss.str();
    }

    // --- XEP-0420: Stanza Content Encryption ---
    static std::string build_sce_content(const std::string& enc_ns,
                                           const std::string& payload_base64,
                                           const std::string& key_fingerprint = "") {
        std::ostringstream oss;
        oss << "<content xmlns='urn:xmpp:sce:0' namespace='"
            << xml_escape(enc_ns) << "'";
        if (!key_fingerprint.empty())
            oss << " fingerprint='" << xml_escape(key_fingerprint) << "'";
        oss << ">" << payload_base64 << "</content>";
        return oss.str();
    }

    // --- Message Expiration ---
    static std::string build_expire(int ttl_seconds) {
        std::ostringstream oss;
        oss << "<expire xmlns='urn:xmpp:expire:0' seconds='" << ttl_seconds << "'/>";
        return oss.str();
    }

    static std::string build_expire_header(int64_t expire_at_ms) {
        std::ostringstream oss;
        oss << "<expire xmlns='urn:xmpp:expire:0' stamp='"
            << format_xmpp_timestamp(expire_at_ms) << "'/>";
        return oss.str();
    }

    // --- Stable Stanza ID ---
    static std::string build_stanza_id(const std::string& id,
                                         const std::string& by) {
        return "<stanza-id xmlns='urn:xmpp:sid:0' id='" +
               xml_escape(id) + "' by='" + xml_escape(by) + "'/>";
    }

    static std::string build_origin_id(const std::string& id) {
        return "<origin-id xmlns='urn:xmpp:sid:0' id='" +
               xml_escape(id) + "'/>";
    }

    // --- Forwarded wrapper ---
    static std::string build_forwarded(const std::string& inner,
                                         const std::string& delay_stamp = "") {
        std::ostringstream oss;
        oss << "<forwarded xmlns='urn:xmpp:forward:0'>";
        if (!delay_stamp.empty()) {
            oss << "<delay xmlns='urn:xmpp:delay' stamp='"
                << xml_escape(delay_stamp) << "'/>";
        }
        oss << inner << "</forwarded>";
        return oss.str();
    }

    // --- Full message with all features ---
    static std::string build_full_message(const MessageContext& ctx) {
        std::ostringstream oss;

        // Message element start
        oss << "<message xmlns='jabber:client'";
        if (!ctx.from.empty()) oss << " from='" << xml_escape(ctx.from.full()) << "'";
        if (!ctx.to.empty()) oss << " to='" << xml_escape(ctx.to.full()) << "'";
        if (!ctx.message_id.empty()) oss << " id='" << xml_escape(ctx.message_id) << "'";

        std::string mtype;
        switch (ctx.msg_type) {
            case MessageType::CHAT: mtype = "chat"; break;
            case MessageType::GROUPCHAT: mtype = "groupchat"; break;
            case MessageType::HEADLINE: mtype = "headline"; break;
            case MessageType::ERROR: mtype = "error"; break;
            default: mtype = "normal";
        }
        oss << " type='" << mtype << "'";
        if (!ctx.lang.empty()) oss << " xml:lang='" << xml_escape(ctx.lang) << "'";
        oss << ">";

        // Body
        if (!ctx.body.empty()) {
            oss << "<body>" << xml_escape(ctx.body) << "</body>";
        }
        if (!ctx.html_body.empty()) {
            oss << "<html xmlns='http://jabber.org/protocol/xhtml-im'>"
                << "<body xmlns='http://www.w3.org/1999/xhtml'>"
                << ctx.html_body
                << "</body></html>";
        }
        if (!ctx.thread.empty()) {
            oss << "<thread>" << xml_escape(ctx.thread) << "</thread>";
        }

        // Stable IDs
        if (!ctx.origin_id.empty()) {
            oss << "<origin-id xmlns='urn:xmpp:sid:0' id='"
                << xml_escape(ctx.origin_id) << "'/>";
        }

        // Delivery Receipt (XEP-0184)
        if (ctx.receipt_state == ReceiptState::REQUESTED) {
            oss << build_receipt_request();
        } else if (ctx.receipt_state == ReceiptState::RECEIVED) {
            oss << build_receipt_received(ctx.receipt_id);
        }

        // Chat Marker (XEP-0333)
        if (ctx.marker != ChatMarker::NONE) {
            oss << build_chat_marker(ctx.marker, ctx.marker_id);
        }

        // Chat State (XEP-0085)
        if (ctx.chat_state != ChatState::NONE) {
            oss << build_chat_state(ctx.chat_state);
        }

        // Processing Hints (XEP-0334)
        if (!ctx.hints.empty()) {
            oss << build_hints(ctx.hints);
        }

        // Attention (XEP-0224)
        if (ctx.requires_attention) {
            oss << build_attention();
        }

        // Reply (XEP-0393)
        if (ctx.reply.has_value()) {
            oss << build_reply_reference(*ctx.reply);
        }

        // Fallback (XEP-0428)
        if (ctx.fallback.is_fallback) {
            oss << build_fallback(ctx.fallback.for_namespace,
                                   ctx.fallback.original_tags);
        }

        // Correction (XEP-0308)
        if (ctx.correction.has_value()) {
            oss << build_correction(ctx.correction->original_id);
        }

        // Retraction (XEP-0424)
        if (ctx.retraction.has_value()) {
            oss << build_retraction(ctx.retraction->message_id,
                                      ctx.retraction->reason);
        }

        // Reactions (XEP-0444)
        if (!ctx.reactions.empty()) {
            std::map<std::string, std::vector<std::string>> by_jid;
            for (const auto& r : ctx.reactions) {
                for (const auto& e : r.emojis) {
                    by_jid[r.reactor_jid].push_back(e);
                }
            }
            oss << build_reaction_update(ctx.message_id, by_jid);
        }

        // Fastenings (XEP-0422)
        for (const auto& f : ctx.fastenings) {
            oss << build_fastening(f);
        }

        // Encryption (XEP-0380)
        if (ctx.encryption.has_value()) {
            oss << build_eme(ctx.encryption->namespace_uri,
                               ctx.encryption->name,
                               ctx.encryption->key_fingerprint);
        }

        // Content Encryption (XEP-0420)
        if (ctx.is_content_encrypted) {
            // Placeholder - actual encrypted content would be set here
            oss << "<content xmlns='urn:xmpp:sce:0' namespace='"
                << xml_escape(ctx.encrypted_content_ns) << "'/>";
        }

        // Expiration
        if (ctx.expires_at.has_value()) {
            oss << build_expire_header(*ctx.expires_at);
        }

        // Extended attributes
        for (const auto& [key, val] : ctx.extended_attrs) {
            oss << "<" << key << ">" << xml_escape(val) << "</" << key << ">";
        }

        oss << "</message>";
        return oss.str();
    }
};

// =============================================================================
// XML Parser for Message Features
// =============================================================================
class MessageXmlParser {
public:
    // Parse message direction metadata
    static std::pair<Jid, Jid> parse_from_to(const std::string& xml) {
        Jid from, to;
        std::string from_str = xml_get_attr(xml, "from");
        std::string to_str = xml_get_attr(xml, "to");
        if (!from_str.empty()) from.parse(from_str);
        if (!to_str.empty()) to.parse(to_str);
        return {from, to};
    }

    static std::string parse_message_id(const std::string& xml) {
        return xml_get_attr(xml, "id");
    }

    static std::string parse_message_type(const std::string& xml) {
        return xml_get_attr(xml, "type");
    }

    // --- XEP-0184: Delivery Receipts ---
    static bool has_receipt_request(const std::string& xml) {
        return xml.find("<request xmlns='urn:xmpp:receipts'") != std::string::npos ||
               xml.find("<request xmlns=\"urn:xmpp:receipts\"") != std::string::npos;
    }

    static std::string parse_receipt_received_id(const std::string& xml) {
        size_t pos = xml.find("<received xmlns='urn:xmpp:receipts'");
        if (pos == std::string::npos)
            pos = xml.find("<received xmlns=\"urn:xmpp:receipts\"");
        if (pos == std::string::npos) return "";
        return xml_get_attr(xml.substr(pos), "id");
    }

    // --- XEP-0333: Chat Markers ---
    static ChatMarker parse_chat_marker(const std::string& xml,
                                          std::string& marker_id) {
        marker_id = "";
        const std::string ns = "urn:xmpp:chat-markers:0";

        if (xml.find("<received xmlns='" + ns) != std::string::npos ||
            xml.find("<received xmlns=\"" + ns) != std::string::npos) {
            // Extract id
            size_t pos = xml.find("<received xmlns=");
            std::string fragment = xml.substr(pos, xml.find("/>", pos) - pos + 2);
            marker_id = xml_get_attr(fragment, "id");
            return ChatMarker::RECEIVED;
        }
        if (xml.find("<displayed xmlns='" + ns) != std::string::npos ||
            xml.find("<displayed xmlns=\"" + ns) != std::string::npos) {
            size_t pos = xml.find("<displayed xmlns=");
            std::string fragment = xml.substr(pos, xml.find("/>", pos) - pos + 2);
            marker_id = xml_get_attr(fragment, "id");
            return ChatMarker::DISPLAYED;
        }
        if (xml.find("<acknowledged xmlns='" + ns) != std::string::npos ||
            xml.find("<acknowledged xmlns=\"" + ns) != std::string::npos) {
            size_t pos = xml.find("<acknowledged xmlns=");
            std::string fragment = xml.substr(pos, xml.find("/>", pos) - pos + 2);
            marker_id = xml_get_attr(fragment, "id");
            return ChatMarker::ACKNOWLEDGED;
        }
        return ChatMarker::NONE;
    }

    // --- XEP-0085: Chat States ---
    static ChatState parse_chat_state(const std::string& xml) {
        const std::string ns = "http://jabber.org/protocol/chatstates";
        if (xml.find("<active xmlns='" + ns) != std::string::npos ||
            xml.find("<active xmlns=\"" + ns) != std::string::npos)
            return ChatState::ACTIVE;
        if (xml.find("<inactive xmlns='" + ns) != std::string::npos ||
            xml.find("<inactive xmlns=\"" + ns) != std::string::npos)
            return ChatState::INACTIVE;
        if (xml.find("<gone xmlns='" + ns) != std::string::npos ||
            xml.find("<gone xmlns=\"" + ns) != std::string::npos)
            return ChatState::GONE;
        if (xml.find("<composing xmlns='" + ns) != std::string::npos ||
            xml.find("<composing xmlns=\"" + ns) != std::string::npos)
            return ChatState::COMPOSING;
        if (xml.find("<paused xmlns='" + ns) != std::string::npos ||
            xml.find("<paused xmlns=\"" + ns) != std::string::npos)
            return ChatState::PAUSED;
        return ChatState::NONE;
    }

    // --- XEP-0280: Carbons ---
    static bool is_carbon_enable(const std::string& xml) {
        return xml.find("<enable xmlns='urn:xmpp:carbons:2'") != std::string::npos ||
               xml.find("<enable xmlns=\"urn:xmpp:carbons:2\"") != std::string::npos;
    }

    static bool is_carbon_disable(const std::string& xml) {
        return xml.find("<disable xmlns='urn:xmpp:carbons:2'") != std::string::npos ||
               xml.find("<disable xmlns=\"urn:xmpp:carbons:2\"") != std::string::npos;
    }

    static std::pair<bool, std::string> parse_carbon(const std::string& xml) {
        bool sent = false;
        if (xml.find("<sent xmlns='urn:xmpp:carbons:2'") != std::string::npos ||
            xml.find("<sent xmlns=\"urn:xmpp:carbons:2\"") != std::string::npos) {
            sent = true;
        } else if (xml.find("<received xmlns='urn:xmpp:carbons:2'") != std::string::npos ||
                   xml.find("<received xmlns=\"urn:xmpp:carbons:2\"") != std::string::npos) {
            sent = false;
        } else {
            return {false, ""};
        }

        // Extract forwarded message
        size_t fwd_start = xml.find("<forwarded xmlns=");
        if (fwd_start == std::string::npos) return {sent, ""};
        size_t fwd_end = xml.find("</forwarded>", fwd_start);
        if (fwd_end == std::string::npos) return {sent, ""};
        std::string inner = xml.substr(fwd_start, fwd_end - fwd_start + 12);

        // Extract the message inside forwarded
        size_t msg_start = inner.find("<message ");
        if (msg_start == std::string::npos) return {sent, ""};
        size_t msg_end = inner.find("</message>", msg_start);
        if (msg_end == std::string::npos) return {sent, ""};

        return {sent, inner.substr(msg_start, msg_end - msg_start + 10)};
    }

    // --- XEP-0313: MAM ---
    static std::optional<MamQuery> parse_mam_query(const std::string& xml) {
        MamQuery q;
        size_t qpos = xml.find("<query xmlns='urn:xmpp:mam:2'");
        if (qpos == std::string::npos)
            qpos = xml.find("<query xmlns=\"urn:xmpp:mam:2\"");
        if (qpos == std::string::npos)
            qpos = xml.find("<query xmlns='urn:xmpp:mam:1'");
        if (qpos == std::string::npos)
            qpos = xml.find("<query xmlns='urn:xmpp:mam:tmp'");
        if (qpos == std::string::npos) return std::nullopt;

        std::string query_frag = xml.substr(qpos, xml.find("</query>", qpos) - qpos + 8);
        q.query_id = xml_get_attr(query_frag, "queryid");

        // Parse RSM
        size_t rsm_pos = xml.find("<set xmlns='http://jabber.org/protocol/rsm'");
        if (rsm_pos != std::string::npos) {
            std::string rsm_frag = xml.substr(rsm_pos,
                xml.find("</set>", rsm_pos) - rsm_pos + 6);

            std::string after = xml_get_child(rsm_frag, "after", "");
            std::string before = xml_get_child(rsm_frag, "before", "");
            if (!after.empty()) q.after_id = after;
            if (!before.empty()) q.before_id = before;

            std::string max_str = xml_get_child(rsm_frag, "max", "");
            if (!max_str.empty()) q.max_results = std::stoi(max_str);
        }

        // Parse x:data fields
        q.start_time = parse_xdata_time_field(xml, "start");
        q.end_time = parse_xdata_time_field(xml, "end");
        q.with_jid = parse_xdata_string_field(xml, "with");

        return q;
    }

    static bool is_mam_prefs_request(const std::string& xml) {
        return xml.find("<prefs xmlns='urn:xmpp:mam:2'") != std::string::npos ||
               xml.find("<prefs xmlns=\"urn:xmpp:mam:2\"") != std::string::npos;
    }

    // --- XEP-0308: Message Correction ---
    static std::optional<std::string> parse_correction_id(const std::string& xml) {
        size_t pos = xml.find("<replace xmlns='urn:xmpp:message-correct:0'");
        if (pos == std::string::npos)
            pos = xml.find("<replace xmlns=\"urn:xmpp:message-correct:0\"");
        if (pos == std::string::npos) return std::nullopt;
        std::string frag = xml.substr(pos, xml.find("/>", pos) - pos + 2);
        std::string id = xml_get_attr(frag, "id");
        if (id.empty()) return std::nullopt;
        return id;
    }

    // --- XEP-0334: Processing Hints ---
    static std::vector<ProcessingHint> parse_processing_hints(const std::string& xml) {
        std::vector<ProcessingHint> hints;
        const std::string ns = "urn:xmpp:hints";

        if (xml.find("<no-permanent-store xmlns='" + ns) != std::string::npos ||
            xml.find("<no-permanent-store xmlns=\"" + ns) != std::string::npos)
            hints.push_back(ProcessingHint::NO_PERMANENT_STORE);

        if (xml.find("<no-store xmlns='" + ns) != std::string::npos ||
            xml.find("<no-store xmlns=\"" + ns) != std::string::npos)
            hints.push_back(ProcessingHint::NO_STORE);

        if (xml.find("<no-copy xmlns='" + ns) != std::string::npos ||
            xml.find("<no-copy xmlns=\"" + ns) != std::string::npos)
            hints.push_back(ProcessingHint::NO_COPY);

        if (xml.find("<store xmlns='" + ns) != std::string::npos ||
            xml.find("<store xmlns=\"" + ns) != std::string::npos)
            hints.push_back(ProcessingHint::STORE);

        return hints;
    }

    // --- XEP-0224: Attention ---
    static bool has_attention_request(const std::string& xml) {
        return xml.find("<attention xmlns='urn:xmpp:attention:0'") != std::string::npos ||
               xml.find("<attention xmlns=\"urn:xmpp:attention:0\"") != std::string::npos;
    }

    // --- XEP-0393: Reply ---
    static std::optional<ReplyData> parse_reply(const std::string& xml) {
        ReplyData reply;
        size_t pos = xml.find("<reply xmlns='urn:xmpp:reply:0'");
        if (pos == std::string::npos)
            pos = xml.find("<reply xmlns=\"urn:xmpp:reply:0\"");
        if (pos == std::string::npos) return std::nullopt;

        std::string frag = xml.substr(pos, xml.find("</reply>", pos) - pos + 8);
        reply.to_message_id = xml_get_attr(frag, "to");

        size_t to_tag = frag.find("<to xmlns=");
        if (to_tag != std::string::npos) {
            reply.to_sender_jid = xml_get_attr(frag.substr(to_tag), "jid");
        }

        reply.to_body_preview = xml_get_child(frag, "body", "urn:xmpp:reply:0");
        return reply;
    }

    // --- XEP-0428: Fallback ---
    static FallbackData parse_fallback(const std::string& xml) {
        FallbackData fb;
        size_t pos = xml.find("<fallback xmlns='urn:xmpp:fallback:0'");
        if (pos == std::string::npos)
            pos = xml.find("<fallback xmlns=\"urn:xmpp:fallback:0\"");
        if (pos == std::string::npos) return fb;

        std::string frag = xml.substr(pos, xml.find("</fallback>", pos) - pos + 11);
        fb.is_fallback = true;
        fb.for_namespace = xml_get_attr(frag, "for");

        // Parse tags
        size_t tag_pos = 0;
        while ((tag_pos = frag.find("<tag>", tag_pos)) != std::string::npos) {
            size_t tag_end = frag.find("</tag>", tag_pos);
            if (tag_end != std::string::npos) {
                fb.original_tags.push_back(
                    frag.substr(tag_pos + 5, tag_end - tag_pos - 5));
                tag_pos = tag_end + 6;
            } else break;
        }
        return fb;
    }

    // --- XEP-0422: Fastening ---
    static std::vector<FasteningReference> parse_fastenings(const std::string& xml) {
        std::vector<FasteningReference> results;
        size_t pos = 0;
        while ((pos = xml.find("<apply-to xmlns='urn:xmpp:fasten:0'", pos)) != std::string::npos) {
            size_t end = xml.find("</apply-to>", pos);
            if (end == std::string::npos) break;

            std::string frag = xml.substr(pos, end - pos + 12);
            FasteningReference f;
            f.apply_to_id = xml_get_attr(frag, "id");

            // Try to parse inner payload as JSON
            size_t inner_start = frag.find('>', frag.find("id='")) + 1;
            std::string inner = frag.substr(inner_start, frag.find("</apply-to>") - inner_start);
            try {
                f.payload = json::parse(inner);
            } catch (...) {
                f.payload = inner;
            }

            f.timestamp = now_ms();
            results.push_back(f);
            pos = end + 12;
        }
        return results;
    }

    // --- XEP-0424: Retraction ---
    static std::optional<MessageRetraction> parse_retraction(const std::string& xml) {
        MessageRetraction r;
        size_t pos = xml.find("<retract xmlns='urn:xmpp:retract:0'");
        if (pos == std::string::npos)
            pos = xml.find("<retract xmlns=\"urn:xmpp:retract:0\"");
        if (pos == std::string::npos) return std::nullopt;

        std::string frag = xml.substr(pos, xml.find("/>", pos) - pos + 2);
        r.message_id = xml_get_attr(frag, "id");
        r.reason = xml_get_attr(frag, "reason");
        r.timestamp = now_ms();

        // Get retractor from parent message
        r.retractor_jid = xml_get_attr(xml, "from");
        return r;
    }

    // --- XEP-0444: Reactions ---
    static std::vector<MessageReaction> parse_reactions(const std::string& xml) {
        std::vector<MessageReaction> results;
        size_t pos = xml.find("<reactions xmlns='urn:xmpp:reactions:0'");
        if (pos == std::string::npos)
            pos = xml.find("<reactions xmlns=\"urn:xmpp:reactions:0\"");
        if (pos == std::string::npos) return results;

        std::string frag = xml.substr(pos, xml.find("</reactions>", pos) - pos + 13);
        std::string msg_id = xml_get_attr(frag, "id");
        std::string reactor = xml_get_attr(xml, "from");

        // Parse individual reactions
        size_t rpos = 0;
        while ((rpos = frag.find("<reaction", rpos)) != std::string::npos) {
            size_t rstart = frag.find('>', rpos) + 1;
            size_t rend = frag.find("</reaction>", rstart);
            if (rend != std::string::npos) {
                MessageReaction mr;
                mr.message_id = msg_id;
                mr.reactor_jid = xml_get_attr(frag.substr(rpos, rstart - rpos), "jid");
                if (mr.reactor_jid.empty()) mr.reactor_jid = reactor;
                mr.emojis.push_back(frag.substr(rstart, rend - rstart));
                mr.timestamp = now_ms();
                results.push_back(mr);
                rpos = rend + 11;
            } else break;
        }
        return results;
    }

    // --- XEP-0380: EME ---
    static std::optional<EncryptionInfo> parse_eme(const std::string& xml) {
        EncryptionInfo info;
        size_t pos = xml.find("<encryption xmlns='urn:xmpp:eme:0'");
        if (pos == std::string::npos)
            pos = xml.find("<encryption xmlns=\"urn:xmpp:eme:0\"");
        if (pos == std::string::npos) return std::nullopt;

        std::string frag = xml.substr(pos, xml.find("/>", pos) - pos + 2);
        info.namespace_uri = xml_get_attr(frag, "namespace");
        info.name = xml_get_attr(frag, "name");
        info.key_fingerprint = xml_get_attr(frag, "fingerprint");
        info.is_trusted = false;
        return info;
    }

    // --- XEP-0420: SCE ---
    static bool has_sce_content(const std::string& xml) {
        return xml.find("<content xmlns='urn:xmpp:sce:0'") != std::string::npos ||
               xml.find("<content xmlns=\"urn:xmpp:sce:0\"") != std::string::npos;
    }

    static std::pair<std::string, std::string> parse_sce_content(const std::string& xml) {
        size_t pos = xml.find("<content xmlns='urn:xmpp:sce:0'");
        if (pos == std::string::npos)
            pos = xml.find("<content xmlns=\"urn:xmpp:sce:0\"");
        if (pos == std::string::npos) return {"", ""};

        std::string frag = xml.substr(pos, xml.find("</content>", pos) - pos + 10);
        std::string ns = xml_get_attr(frag, "namespace");
        std::string fingerprint = xml_get_attr(frag, "fingerprint");

        size_t inner_start = frag.find('>') + 1;
        std::string payload = frag.substr(inner_start, frag.find("</content>") - inner_start);

        return {ns, payload};
    }

    // --- Message Expiration ---
    static std::optional<int64_t> parse_expiration(const std::string& xml) {
        size_t pos = xml.find("<expire xmlns='urn:xmpp:expire:0'");
        if (pos == std::string::npos)
            pos = xml.find("<expire xmlns=\"urn:xmpp:expire:0\"");
        if (pos == std::string::npos) return std::nullopt;

        std::string frag = xml.substr(pos, xml.find("/>", pos) - pos + 2);
        std::string stamp = xml_get_attr(frag, "stamp");
        if (!stamp.empty()) {
            return parse_xmpp_timestamp(stamp);
        }
        std::string sec_str = xml_get_attr(frag, "seconds");
        if (!sec_str.empty()) {
            int secs = std::stoi(sec_str);
            return now_ms() + secs * 1000;
        }
        return std::nullopt;
    }

    // --- Origin ID / Stanza ID (XEP-0359) ---
    static std::string parse_origin_id(const std::string& xml) {
        size_t pos = xml.find("<origin-id xmlns='urn:xmpp:sid:0'");
        if (pos == std::string::npos)
            pos = xml.find("<origin-id xmlns=\"urn:xmpp:sid:0\"");
        if (pos == std::string::npos) return "";
        std::string frag = xml.substr(pos, xml.find("/>", pos) - pos + 2);
        return xml_get_attr(frag, "id");
    }

    static std::string parse_stanza_id(const std::string& xml) {
        size_t pos = xml.find("<stanza-id xmlns='urn:xmpp:sid:0'");
        if (pos == std::string::npos)
            pos = xml.find("<stanza-id xmlns=\"urn:xmpp:sid:0\"");
        if (pos == std::string::npos) return "";
        std::string frag = xml.substr(pos, xml.find("/>", pos) - pos + 2);
        return xml_get_attr(frag, "id");
    }

    // --- HTML body ---
    static std::string parse_html_body(const std::string& xml) {
        size_t pos = xml.find("<html xmlns='http://jabber.org/protocol/xhtml-im'");
        if (pos == std::string::npos)
            pos = xml.find("<html xmlns=\"http://jabber.org/protocol/xhtml-im\"");
        if (pos == std::string::npos) return "";

        size_t body_start = xml.find("<body xmlns='http://www.w3.org/1999/xhtml'", pos);
        if (body_start == std::string::npos)
            body_start = xml.find("<body xmlns=\"http://www.w3.org/1999/xhtml\"", pos);
        if (body_start == std::string::npos) return "";

        body_start = xml.find('>', body_start) + 1;
        size_t body_end = xml.find("</body>", body_start);
        if (body_end == std::string::npos) return "";
        return xml.substr(body_start, body_end - body_start);
    }

    // --- Thread ---
    static std::string parse_thread(const std::string& xml) {
        size_t pos = xml.find("<thread>");
        if (pos == std::string::npos) return "";
        size_t end = xml.find("</thread>", pos);
        if (end == std::string::npos) return "";
        return xml.substr(pos + 8, end - pos - 8);
    }

    // Full parse
    static MessageContext parse_full_message(const std::string& xml) {
        MessageContext ctx;
        ctx.timestamp = now_ms();
        ctx.message_id = parse_message_id(xml);

        auto [from, to] = parse_from_to(xml);
        ctx.from = from;
        ctx.to = to;

        // Message type
        std::string mtype = parse_message_type(xml);
        if (mtype == "chat") ctx.msg_type = MessageType::CHAT;
        else if (mtype == "groupchat") ctx.msg_type = MessageType::GROUPCHAT;
        else if (mtype == "headline") ctx.msg_type = MessageType::HEADLINE;
        else if (mtype == "error") ctx.msg_type = MessageType::ERROR;
        else ctx.msg_type = MessageType::NORMAL;

        ctx.body = xml_get_child(xml, "body", "");
        ctx.html_body = parse_html_body(xml);
        ctx.thread = parse_thread(xml);

        // Delivery receipts
        if (has_receipt_request(xml)) {
            ctx.receipt_state = ReceiptState::REQUESTED;
        }
        std::string recv_id = parse_receipt_received_id(xml);
        if (!recv_id.empty()) {
            ctx.receipt_state = ReceiptState::RECEIVED;
            ctx.receipt_id = recv_id;
        }

        // Chat Markers
        std::string marker_id;
        ctx.marker = parse_chat_marker(xml, marker_id);
        ctx.marker_id = marker_id;

        // Chat State
        ctx.chat_state = parse_chat_state(xml);

        // Processing Hints
        ctx.hints = parse_processing_hints(xml);

        // Attention
        ctx.requires_attention = has_attention_request(xml);

        // Reply
        ctx.reply = parse_reply(xml);

        // Fallback
        ctx.fallback = parse_fallback(xml);

        // Correction
        auto corr_id = parse_correction_id(xml);
        if (corr_id.has_value()) {
            MessageCorrection mc;
            mc.original_id = *corr_id;
            mc.new_body = ctx.body;
            mc.new_html_body = ctx.html_body;
            mc.corrector_jid = from.full();
            mc.timestamp = ctx.timestamp;
            ctx.correction = mc;
        }

        // Fastenings
        ctx.fastenings = parse_fastenings(xml);

        // Retraction
        ctx.retraction = parse_retraction(xml);

        // Reactions
        ctx.reactions = parse_reactions(xml);

        // Encryption
        ctx.encryption = parse_eme(xml);
        ctx.is_content_encrypted = has_sce_content(xml);

        // Expiration
        ctx.expires_at = parse_expiration(xml);

        // Origin ID
        ctx.origin_id = parse_origin_id(xml);

        // Language
        ctx.lang = xml_get_attr(xml, "xml:lang");

        return ctx;
    }

private:
    static std::optional<int64_t> parse_xdata_time_field(const std::string& xml,
                                                           const std::string& var) {
        std::string search = "var='" + var + "'";
        size_t pos = xml.find(search);
        if (pos == std::string::npos) {
            search = "var=\"" + var + "\"";
            pos = xml.find(search);
        }
        if (pos == std::string::npos) return std::nullopt;

        size_t val_start = xml.find("<value>", pos);
        if (val_start == std::string::npos) return std::nullopt;
        size_t val_end = xml.find("</value>", val_start);
        if (val_end == std::string::npos) return std::nullopt;

        std::string ts_str = xml.substr(val_start + 7, val_end - val_start - 7);
        return parse_xmpp_timestamp(ts_str);
    }

    static std::optional<std::string> parse_xdata_string_field(const std::string& xml,
                                                                  const std::string& var) {
        std::string search = "var='" + var + "'";
        size_t pos = xml.find(search);
        if (pos == std::string::npos) {
            search = "var=\"" + var + "\"";
            pos = xml.find(search);
        }
        if (pos == std::string::npos) return std::nullopt;

        size_t val_start = xml.find("<value>", pos);
        if (val_start == std::string::npos) return std::nullopt;
        size_t val_end = xml.find("</value>", val_start);
        if (val_end == std::string::npos) return std::nullopt;

        return xml.substr(val_start + 7, val_end - val_start - 7);
    }
};

// =============================================================================
// Delivery Receipt Manager (XEP-0184)
// =============================================================================
class DeliveryReceiptManager {
public:
    DeliveryReceiptManager() = default;

    // Record that a receipt was requested for a message
    void mark_receipt_requested(const std::string& message_id,
                                 const std::string& sender_jid,
                                 const std::string& recipient_jid) {
        std::unique_lock lock(mutex_);
        PendingReceipt pr;
        pr.message_id = message_id;
        pr.sender_jid = sender_jid;
        pr.recipient_jid = recipient_jid;
        pr.requested_at = now_ms();
        pending_[message_id] = pr;
    }

    // Record that a receipt was received
    void mark_receipt_received(const std::string& message_id,
                                const std::string& recipient_jid) {
        std::unique_lock lock(mutex_);
        auto it = pending_.find(message_id);
        if (it != pending_.end()) {
            it->second.received_at = now_ms();
            it->second.received_by = recipient_jid;
            receipts_[it->second.sender_jid].push_back(message_id);
        }
    }

    // Check if a message has a pending receipt
    bool has_pending_receipt(const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        return pending_.find(message_id) != pending_.end();
    }

    // Get pending receipts for a sender
    std::vector<std::string> get_pending_for_sender(const std::string& sender_jid) const {
        std::shared_lock lock(mutex_);
        std::vector<std::string> result;
        for (const auto& [id, pr] : pending_) {
            if (pr.sender_jid == sender_jid && pr.received_at == 0) {
                result.push_back(id);
            }
        }
        return result;
    }

    // Build receipt message XML
    std::string build_receipt(const std::string& message_id) const {
        return MessageXmlBuilder::build_receipt_received(message_id);
    }

    // Cleanup old receipts
    void cleanup_old_receipts(int64_t older_than_ms) {
        std::unique_lock lock(mutex_);
        auto it = pending_.begin();
        while (it != pending_.end()) {
            if (it->second.requested_at < older_than_ms) {
                it = pending_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Statistics
    struct ReceiptStats {
        int64_t total_requested = 0;
        int64_t total_received = 0;
        int64_t pending_count = 0;
    };

    ReceiptStats get_stats() const {
        std::shared_lock lock(mutex_);
        ReceiptStats stats;
        stats.total_requested = pending_.size() + receipts_.size();
        stats.total_received = receipts_.size();
        stats.pending_count = 0;
        for (const auto& [id, pr] : pending_) {
            if (pr.received_at == 0) stats.pending_count++;
        }
        return stats;
    }

private:
    struct PendingReceipt {
        std::string message_id;
        std::string sender_jid;
        std::string recipient_jid;
        int64_t requested_at = 0;
        int64_t received_at = 0;
        std::string received_by;
    };

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, PendingReceipt> pending_;
    std::map<std::string, std::vector<std::string>> receipts_;
};

// =============================================================================
// Chat Marker Manager (XEP-0333)
// =============================================================================
class ChatMarkerManager {
public:
    ChatMarkerManager() = default;

    // Record a marker for a message
    void set_marker(const std::string& message_id,
                     const std::string& jid,
                     ChatMarker marker) {
        std::unique_lock lock(mutex_);
        MarkerState& state = markers_[message_id][jid];
        state.marker = marker;
        state.timestamp = now_ms();
    }

    // Get current marker for a message from a JID
    ChatMarker get_marker(const std::string& message_id,
                           const std::string& jid) const {
        std::shared_lock lock(mutex_);
        auto msg_it = markers_.find(message_id);
        if (msg_it != markers_.end()) {
            auto jid_it = msg_it->second.find(jid);
            if (jid_it != msg_it->second.end()) {
                return jid_it->second.marker;
            }
        }
        return ChatMarker::NONE;
    }

    // Check if all recipients have acknowledged
    bool is_fully_acknowledged(const std::string& message_id,
                                 const std::vector<std::string>& expected_jids) const {
        std::shared_lock lock(mutex_);
        auto msg_it = markers_.find(message_id);
        if (msg_it == markers_.end()) return false;

        for (const auto& jid : expected_jids) {
            auto jid_it = msg_it->second.find(jid);
            if (jid_it == msg_it->second.end() ||
                jid_it->second.marker != ChatMarker::ACKNOWLEDGED) {
                return false;
            }
        }
        return true;
    }

    // Get display status for a message
    struct DisplayStatus {
        int total = 0;
        int received = 0;
        int displayed = 0;
        int acknowledged = 0;
        int64_t first_received_at = 0;
        int64_t first_displayed_at = 0;
        std::vector<std::string> displayed_by;
    };

    DisplayStatus get_display_status(const std::string& message_id,
                                       const std::vector<std::string>& jids) const {
        std::shared_lock lock(mutex_);
        DisplayStatus status;
        status.total = static_cast<int>(jids.size());

        auto msg_it = markers_.find(message_id);
        if (msg_it == markers_.end()) return status;

        for (const auto& jid : jids) {
            auto jid_it = msg_it->second.find(jid);
            if (jid_it != msg_it->second.end()) {
                switch (jid_it->second.marker) {
                    case ChatMarker::RECEIVED:
                        status.received++;
                        if (status.first_received_at == 0)
                            status.first_received_at = jid_it->second.timestamp;
                        break;
                    case ChatMarker::DISPLAYED:
                        status.received++;
                        status.displayed++;
                        status.displayed_by.push_back(jid);
                        if (status.first_displayed_at == 0)
                            status.first_displayed_at = jid_it->second.timestamp;
                        break;
                    case ChatMarker::ACKNOWLEDGED:
                        status.received++;
                        status.displayed++;
                        status.acknowledged++;
                        status.displayed_by.push_back(jid);
                        break;
                    default: break;
                }
            }
        }
        return status;
    }

    // Build chat marker XML
    std::string build_marker_xml(ChatMarker marker,
                                   const std::string& message_id,
                                   const std::string& type_hint = "") const {
        return MessageXmlBuilder::build_chat_marker(marker, message_id, type_hint);
    }

    void cleanup_old_markers(int64_t older_than_ms) {
        std::unique_lock lock(mutex_);
        auto it = markers_.begin();
        while (it != markers_.end()) {
            bool all_old = true;
            for (const auto& [jid, state] : it->second) {
                if (state.timestamp >= older_than_ms) {
                    all_old = false;
                    break;
                }
            }
            if (all_old) {
                it = markers_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    struct MarkerState {
        ChatMarker marker = ChatMarker::NONE;
        int64_t timestamp = 0;
    };

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::unordered_map<std::string, MarkerState>> markers_;
};

// =============================================================================
// Chat State Tracker (XEP-0085)
// =============================================================================
class ChatStateTracker {
public:
    ChatStateTracker() = default;

    // Update chat state for a conversation between two JIDs
    void set_state(const std::string& from_jid,
                    const std::string& to_jid,
                    ChatState state) {
        std::unique_lock lock(mutex_);
        std::string key = make_key(from_jid, to_jid);
        StateEntry& entry = states_[key];
        entry.state = state;
        entry.last_update = now_ms();
        entry.from = from_jid;
        entry.to = to_jid;
    }

    // Get current chat state
    ChatState get_state(const std::string& from_jid,
                          const std::string& to_jid) const {
        std::shared_lock lock(mutex_);
        std::string key = make_key(from_jid, to_jid);
        auto it = states_.find(key);
        if (it != states_.end()) {
            return it->second.state;
        }
        return ChatState::NONE;
    }

    // Check if a user is composing
    bool is_composing(const std::string& from_jid,
                       const std::string& to_jid) const {
        return get_state(from_jid, to_jid) == ChatState::COMPOSING;
    }

    // Check if a user is active
    bool is_active(const std::string& from_jid,
                    const std::string& to_jid) const {
        return get_state(from_jid, to_jid) == ChatState::ACTIVE;
    }

    // Check if user is gone (closed chat)
    bool is_gone(const std::string& from_jid,
                  const std::string& to_jid) const {
        return get_state(from_jid, to_jid) == ChatState::GONE;
    }

    // Build chat state XML
    std::string build_state_xml(ChatState state) const {
        return MessageXmlBuilder::build_chat_state(state);
    }

    // Cleanup stale states
    void cleanup_stale_states(int64_t older_than_ms) {
        std::unique_lock lock(mutex_);
        auto it = states_.begin();
        while (it != states_.end()) {
            if (it->second.last_update < older_than_ms) {
                it = states_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Get active conversations
    std::vector<std::pair<std::string, std::string>> get_active_conversations() const {
        std::shared_lock lock(mutex_);
        std::vector<std::pair<std::string, std::string>> result;
        for (const auto& [key, entry] : states_) {
            if (entry.state == ChatState::COMPOSING ||
                entry.state == ChatState::ACTIVE) {
                result.push_back({entry.from, entry.to});
            }
        }
        return result;
    }

private:
    struct StateEntry {
        ChatState state = ChatState::NONE;
        int64_t last_update = 0;
        std::string from;
        std::string to;
    };

    static std::string make_key(const std::string& a, const std::string& b) {
        if (a < b) return a + "|" + b;
        return b + "|" + a;
    }

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, StateEntry> states_;
};

// =============================================================================
// Message Carbon Manager (XEP-0280)
// =============================================================================
class MessageCarbonManager {
public:
    MessageCarbonManager() = default;

    void enable_for_user(const std::string& bare_jid) {
        std::unique_lock lock(mutex_);
        enabled_users_.insert(bare_jid);
    }

    void disable_for_user(const std::string& bare_jid) {
        std::unique_lock lock(mutex_);
        enabled_users_.erase(bare_jid);
    }

    bool is_enabled(const std::string& bare_jid) const {
        std::shared_lock lock(mutex_);
        return enabled_users_.find(bare_jid) != enabled_users_.end();
    }

    // Wrap a message as a carbon copy
    std::string wrap_carbon(const std::string& message_xml, bool sent) {
        return MessageXmlBuilder::build_carbon_forward(message_xml, sent);
    }

    // Route carbon copies to all resources of a user
    std::vector<std::string> generate_carbons(
        const std::string& bare_jid,
        const std::string& message_xml,
        bool sent,
        const std::string& exclude_resource = "") {

        std::vector<std::string> results;
        std::shared_lock lock(mutex_);

        if (!is_enabled(bare_jid)) return results;

        auto it = user_resources_.find(bare_jid);
        if (it == user_resources_.end()) return results;

        std::string carbon_xml = wrap_carbon(message_xml, sent);

        for (const auto& resource : it->second) {
            if (resource != exclude_resource) {
                std::string full_jid = bare_jid + "/" + resource;
                // Clone carbon for each resource
                results.push_back(carbon_xml);
            }
        }

        return results;
    }

    // Resource tracking
    void register_resource(const std::string& bare_jid,
                            const std::string& resource) {
        std::unique_lock lock(mutex_);
        user_resources_[bare_jid].insert(resource);
    }

    void unregister_resource(const std::string& bare_jid,
                              const std::string& resource) {
        std::unique_lock lock(mutex_);
        auto it = user_resources_.find(bare_jid);
        if (it != user_resources_.end()) {
            it->second.erase(resource);
            if (it->second.empty()) {
                user_resources_.erase(it);
            }
        }
    }

    std::vector<std::string> get_user_resources(const std::string& bare_jid) const {
        std::shared_lock lock(mutex_);
        auto it = user_resources_.find(bare_jid);
        if (it != user_resources_.end()) {
            return std::vector<std::string>(it->second.begin(), it->second.end());
        }
        return {};
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_set<std::string> enabled_users_;
    std::unordered_map<std::string, std::unordered_set<std::string>> user_resources_;
};

// =============================================================================
// Message Archive Manager (XEP-0313)
// =============================================================================
class MessageArchiveManager {
public:
    MessageArchiveManager() = default;

    // Archive a message
    void archive_message(const std::string& archive_id,
                          const std::string& bare_jid,
                          const MessageContext& ctx) {
        std::unique_lock lock(mutex_);

        ArchivedMessage am;
        am.archive_id = archive_id.empty() ? gen_message_id() : archive_id;
        am.stanza_id = ctx.message_id;
        am.by = bare_jid;
        am.from = ctx.from;
        am.to = ctx.to;
        am.body = ctx.body;
        am.html_body = ctx.html_body;
        am.thread = ctx.thread;
        am.timestamp = ctx.timestamp;
        am.msg_type = ctx.msg_type;
        am.has_receipt_request = (ctx.receipt_state == ReceiptState::REQUESTED);
        am.has_chat_marker = (ctx.marker != ChatMarker::NONE);
        am.marker_type = ctx.marker;

        if (ctx.correction.has_value()) {
            am.replace_id = ctx.correction->original_id;
        }

        for (const auto& r : ctx.reactions) {
            for (const auto& e : r.emojis) {
                am.reaction_emojis.push_back(e);
            }
        }

        // Store for user's bare JID
        auto& archive = archives_[bare_jid];
        archive.push_back(am);

        // Index by stanza ID
        index_by_stanza_[am.stanza_id] = bare_jid;

        // Index by archive ID
        index_by_archive_[am.archive_id] = bare_jid;

        // Enforce per-user archive limit
        if (archive.size() > max_archive_size_) {
            archive.pop_front();
        }

        total_archived_.fetch_add(1, std::memory_order_relaxed);
    }

    // Query archive (MAM query)
    std::vector<ArchivedMessage> query(const std::string& bare_jid,
                                         const MamQuery& q) {
        std::shared_lock lock(mutex_);
        std::vector<ArchivedMessage> results;

        auto it = archives_.find(bare_jid);
        if (it == archives_.end()) return results;

        const auto& archive = it->second;

        for (const auto& msg : archive) {
            // Time filter
            if (q.start_time.has_value() && msg.timestamp < *q.start_time)
                continue;
            if (q.end_time.has_value() && msg.timestamp > *q.end_time)
                continue;

            // JID filter
            if (q.with_jid.has_value()) {
                if (msg.from.bare() != *q.with_jid &&
                    msg.to.bare() != *q.with_jid)
                    continue;
            }

            results.push_back(msg);
        }

        // RSM pagination
        if (q.after_id.has_value()) {
            auto rsm_it = std::find_if(results.begin(), results.end(),
                [&](const ArchivedMessage& m) { return m.archive_id == *q.after_id; });
            if (rsm_it != results.end()) {
                results.erase(results.begin(), rsm_it + 1);
            }
        }

        if (q.before_id.has_value()) {
            auto rsm_it = std::find_if(results.begin(), results.end(),
                [&](const ArchivedMessage& m) { return m.archive_id == *q.before_id; });
            if (rsm_it != results.end()) {
                results.erase(rsm_it, results.end());
            }
        }

        // Sort by timestamp (newest first by default)
        std::sort(results.begin(), results.end(),
            [](const ArchivedMessage& a, const ArchivedMessage& b) {
                return a.timestamp > b.timestamp;
            });

        // Apply max results limit
        if (q.max_results.has_value() && 
            static_cast<size_t>(*q.max_results) < results.size()) {
            results.resize(*q.max_results);
        }

        return results;
    }

    // Get a specific archived message
    std::optional<ArchivedMessage> get_by_id(const std::string& archive_id) {
        std::shared_lock lock(mutex_);
        auto idx_it = index_by_archive_.find(archive_id);
        if (idx_it == index_by_archive_.end()) return std::nullopt;

        auto archive_it = archives_.find(idx_it->second);
        if (archive_it == archives_.end()) return std::nullopt;

        for (const auto& msg : archive_it->second) {
            if (msg.archive_id == archive_id) return msg;
        }
        return std::nullopt;
    }

    // Get by stanza ID
    std::optional<ArchivedMessage> get_by_stanza_id(const std::string& stanza_id) {
        std::shared_lock lock(mutex_);
        auto idx_it = index_by_stanza_.find(stanza_id);
        if (idx_it == index_by_stanza_.end()) return std::nullopt;

        auto archive_it = archives_.find(idx_it->second);
        if (archive_it == archives_.end()) return std::nullopt;

        for (const auto& msg : archive_it->second) {
            if (msg.stanza_id == stanza_id) return msg;
        }
        return std::nullopt;
    }

    // Update a message in the archive (for corrections)
    bool update_message(const std::string& archive_id,
                          const MessageContext& updated_ctx) {
        std::unique_lock lock(mutex_);
        auto idx_it = index_by_archive_.find(archive_id);
        if (idx_it == index_by_archive_.end()) return false;

        auto archive_it = archives_.find(idx_it->second);
        if (archive_it == archives_.end()) return false;

        for (auto& msg : archive_it->second) {
            if (msg.archive_id == archive_id) {
                msg.body = updated_ctx.body;
                msg.html_body = updated_ctx.html_body;
                msg.replace_id = updated_ctx.message_id;
                return true;
            }
        }
        return false;
    }

    // Mark message as retracted
    bool retract_message(const std::string& stanza_id) {
        std::unique_lock lock(mutex_);
        auto idx_it = index_by_stanza_.find(stanza_id);
        if (idx_it == index_by_stanza_.end()) return false;

        auto archive_it = archives_.find(idx_it->second);
        if (archive_it == archives_.end()) return false;

        for (auto& msg : archive_it->second) {
            if (msg.stanza_id == stanza_id) {
                msg.body = "[This message has been retracted]";
                msg.html_body = "<i>[This message has been retracted]</i>";
                return true;
            }
        }
        return false;
    }

    // Build MAM result IQ
    std::string build_mam_results_iq(const std::string& to_full_jid,
                                       const std::string& from_bare_jid,
                                       const std::string& iq_id,
                                       const MamQuery& query,
                                       const std::vector<ArchivedMessage>& messages) {
        std::ostringstream oss;
        oss << "<iq type='result' id='" << xml_escape(iq_id)
            << "' from='" << xml_escape(from_bare_jid)
            << "' to='" << xml_escape(to_full_jid) << "'>";

        std::string query_id = query.query_id.empty() ?
            gen_unique_id() : query.query_id;

        for (size_t i = 0; i < messages.size(); i++) {
            oss << MessageXmlBuilder::build_mam_result(
                query_id,
                messages[i].stanza_id,
                MessageXmlBuilder::build_mam_message(messages[i]));
        }

        // Build fin
        std::string first_id, last_id;
        if (!messages.empty()) {
            first_id = messages.front().archive_id;
            last_id = messages.back().archive_id;
        }
        oss << MessageXmlBuilder::build_mam_fin(
            query_id, query.complete, first_id, last_id,
            static_cast<int64_t>(messages.size()));

        oss << "</iq>";
        return oss.str();
    }

    // Preferences management
    void set_preferences(const std::string& bare_jid,
                          const std::string& default_rule) {
        std::unique_lock lock(mutex_);
        preferences_[bare_jid].default_rule = default_rule;
    }

    std::string get_default_preference(const std::string& bare_jid) const {
        std::shared_lock lock(mutex_);
        auto it = preferences_.find(bare_jid);
        if (it != preferences_.end()) return it->second.default_rule;
        return "always";
    }

    // Set max archive size
    void set_max_archive_size(size_t size) {
        std::unique_lock lock(mutex_);
        max_archive_size_ = size;
    }

    // Statistics
    int64_t get_total_archived() const {
        return total_archived_.load(std::memory_order_relaxed);
    }

private:
    struct ArchivePreferences {
        std::string default_rule = "always";  // always, never, roster
        std::map<std::string, std::string> jid_rules;
    };

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::deque<ArchivedMessage>> archives_;
    std::unordered_map<std::string, std::string> index_by_stanza_;
    std::unordered_map<std::string, std::string> index_by_archive_;
    std::unordered_map<std::string, ArchivePreferences> preferences_;
    size_t max_archive_size_ = 10000;
    std::atomic<int64_t> total_archived_{0};
};

// =============================================================================
// Message Correction Manager (XEP-0308)
// =============================================================================
class MessageCorrectionManager {
public:
    MessageCorrectionManager() = default;

    // Record a correction
    void record_correction(const std::string& original_id,
                            const MessageCorrection& correction) {
        std::unique_lock lock(mutex_);
        corrections_[original_id].push_back(correction);

        // Update last correction
        last_corrections_[original_id] = correction;

        // Keep only last N corrections per message
        auto& history = corrections_[original_id];
        if (history.size() > max_corrections_per_message_) {
            history.erase(history.begin());
        }
    }

    // Get the most recent correction for a message
    std::optional<MessageCorrection> get_last_correction(
        const std::string& original_id) const {
        std::shared_lock lock(mutex_);
        auto it = last_corrections_.find(original_id);
        if (it != last_corrections_.end()) return it->second;
        return std::nullopt;
    }

    // Get all corrections for a message
    std::vector<MessageCorrection> get_correction_history(
        const std::string& original_id) const {
        std::shared_lock lock(mutex_);
        auto it = corrections_.find(original_id);
        if (it != corrections_.end()) return it->second;
        return {};
    }

    // Check if a message has been corrected
    bool is_corrected(const std::string& original_id) const {
        std::shared_lock lock(mutex_);
        return corrections_.find(original_id) != corrections_.end();
    }

    // Get count of corrections
    int get_correction_count(const std::string& original_id) const {
        std::shared_lock lock(mutex_);
        auto it = corrections_.find(original_id);
        if (it != corrections_.end()) return static_cast<int>(it->second.size());
        return 0;
    }

    // Build correction XML
    std::string build_correction_xml(const std::string& original_id) const {
        return MessageXmlBuilder::build_correction(original_id);
    }

    // Check if a message contains a correction
    static bool message_is_correction(const std::string& xml) {
        return MessageXmlParser::parse_correction_id(xml).has_value();
    }

    // Cleanup
    void cleanup_old_corrections(int64_t older_than_ms) {
        std::unique_lock lock(mutex_);
        for (auto& [id, history] : corrections_) {
            history.erase(
                std::remove_if(history.begin(), history.end(),
                    [&](const MessageCorrection& c) {
                        return c.timestamp < older_than_ms;
                    }),
                history.end());
        }
        // Remove empty histories
        auto it = corrections_.begin();
        while (it != corrections_.end()) {
            if (it->second.empty()) {
                last_corrections_.erase(it->first);
                it = corrections_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::vector<MessageCorrection>> corrections_;
    std::unordered_map<std::string, MessageCorrection> last_corrections_;
    size_t max_corrections_per_message_ = 50;
};

// =============================================================================
// Message Reaction Manager (XEP-0444)
// =============================================================================
class MessageReactionManager {
public:
    MessageReactionManager() = default;

    // Add a reaction
    void add_reaction(const std::string& message_id,
                       const std::string& reactor_jid,
                       const std::string& emoji) {
        std::unique_lock lock(mutex_);

        // Get or create reactions for this message
        auto& reactions = reactions_by_msg_[message_id];

        // Find existing reaction by this JID
        bool found = false;
        for (auto& r : reactions) {
            if (r.reactor_jid == reactor_jid) {
                // Only add if emoji not already present
                if (std::find(r.emojis.begin(), r.emojis.end(), emoji) ==
                    r.emojis.end()) {
                    r.emojis.push_back(emoji);
                    r.timestamp = now_ms();
                }
                found = true;
                break;
            }
        }

        if (!found) {
            MessageReaction r;
            r.message_id = message_id;
            r.reactor_jid = reactor_jid;
            r.emojis.push_back(emoji);
            r.timestamp = now_ms();
            reactions.push_back(r);
        }

        // Update emoji count index
        update_emoji_counts(message_id);
    }

    // Remove a specific reaction
    void remove_reaction(const std::string& message_id,
                          const std::string& reactor_jid,
                          const std::string& emoji) {
        std::unique_lock lock(mutex_);

        auto it = reactions_by_msg_.find(message_id);
        if (it == reactions_by_msg_.end()) return;

        for (auto& r : it->second) {
            if (r.reactor_jid == reactor_jid) {
                auto eit = std::find(r.emojis.begin(), r.emojis.end(), emoji);
                if (eit != r.emojis.end()) {
                    r.emojis.erase(eit);
                    r.timestamp = now_ms();
                }
                break;
            }
        }

        // Remove JID entries with no reactions
        it->second.erase(
            std::remove_if(it->second.begin(), it->second.end(),
                [](const MessageReaction& r) { return r.emojis.empty(); }),
            it->second.end());

        update_emoji_counts(message_id);
    }

    // Remove all reactions from a JID for a message
    void remove_all_reactions(const std::string& message_id,
                               const std::string& reactor_jid) {
        std::unique_lock lock(mutex_);

        auto it = reactions_by_msg_.find(message_id);
        if (it == reactions_by_msg_.end()) return;

        it->second.erase(
            std::remove_if(it->second.begin(), it->second.end(),
                [&](const MessageReaction& r) {
                    return r.reactor_jid == reactor_jid;
                }),
            it->second.end());

        update_emoji_counts(message_id);
    }

    // Get all reactions for a message
    std::vector<MessageReaction> get_reactions(const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        auto it = reactions_by_msg_.find(message_id);
        if (it != reactions_by_msg_.end()) return it->second;
        return {};
    }

    // Get emoji counts for a message
    std::map<std::string, int> get_emoji_counts(const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        auto it = emoji_counts_.find(message_id);
        if (it != emoji_counts_.end()) return it->second;
        return {};
    }

    // Get who reacted with a specific emoji
    std::vector<std::string> get_reactors_for_emoji(
        const std::string& message_id, const std::string& emoji) const {
        std::shared_lock lock(mutex_);
        std::vector<std::string> reactors;

        auto it = reactions_by_msg_.find(message_id);
        if (it == reactions_by_msg_.end()) return reactors;

        for (const auto& r : it->second) {
            if (std::find(r.emojis.begin(), r.emojis.end(), emoji) !=
                r.emojis.end()) {
                reactors.push_back(r.reactor_jid);
            }
        }
        return reactors;
    }

    // Build reactions XML for a message
    std::string build_reactions_xml(const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        auto it = reactions_by_msg_.find(message_id);
        if (it == reactions_by_msg_.end() || it->second.empty()) {
            return "";
        }

        std::map<std::string, std::vector<std::string>> by_jid;
        for (const auto& r : it->second) {
            by_jid[r.reactor_jid] = r.emojis;
        }
        return MessageXmlBuilder::build_reaction_update(message_id, by_jid);
    }

    // Check if a user has reacted
    bool has_reacted(const std::string& message_id,
                      const std::string& jid) const {
        std::shared_lock lock(mutex_);
        auto it = reactions_by_msg_.find(message_id);
        if (it == reactions_by_msg_.end()) return false;

        for (const auto& r : it->second) {
            if (r.reactor_jid == jid) return true;
        }
        return false;
    }

    // Statistics
    struct ReactionStats {
        int64_t total_reactions = 0;
        int64_t unique_messages = 0;
        int64_t unique_reactors = 0;
    };

    ReactionStats get_stats() const {
        std::shared_lock lock(mutex_);
        ReactionStats stats;
        stats.unique_messages = reactions_by_msg_.size();

        std::unordered_set<std::string> reactors;
        for (const auto& [msg_id, reactions] : reactions_by_msg_) {
            stats.total_reactions += reactions.size();
            for (const auto& r : reactions) {
                reactors.insert(r.reactor_jid);
            }
        }
        stats.unique_reactors = reactors.size();
        return stats;
    }

    void cleanup_old_reactions(int64_t older_than_ms) {
        std::unique_lock lock(mutex_);
        auto it = reactions_by_msg_.begin();
        while (it != reactions_by_msg_.end()) {
            bool all_old = true;
            for (const auto& r : it->second) {
                if (r.timestamp >= older_than_ms) {
                    all_old = false;
                    break;
                }
            }
            if (all_old) {
                emoji_counts_.erase(it->first);
                it = reactions_by_msg_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    void update_emoji_counts(const std::string& message_id) {
        auto& counts = emoji_counts_[message_id];
        counts.clear();

        auto it = reactions_by_msg_.find(message_id);
        if (it == reactions_by_msg_.end()) return;

        for (const auto& r : it->second) {
            for (const auto& e : r.emojis) {
                counts[e]++;
            }
        }
    }

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::vector<MessageReaction>> reactions_by_msg_;
    std::unordered_map<std::string, std::map<std::string, int>> emoji_counts_;
};

// =============================================================================
// Message Retraction Manager (XEP-0424)
// =============================================================================
class MessageRetractionManager {
public:
    MessageRetractionManager() = default;

    // Retract a message
    void retract_message(const std::string& message_id,
                          const std::string& retractor_jid,
                          const std::string& reason = "") {
        std::unique_lock lock(mutex_);
        MessageRetraction mr;
        mr.message_id = message_id;
        mr.retractor_jid = retractor_jid;
        mr.reason = reason;
        mr.timestamp = now_ms();
        retractions_[message_id] = mr;
        retracted_set_.insert(message_id);
    }

    // Check if a message has been retracted
    bool is_retracted(const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        return retracted_set_.find(message_id) != retracted_set_.end();
    }

    // Get retraction info
    std::optional<MessageRetraction> get_retraction(
        const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        auto it = retractions_.find(message_id);
        if (it != retractions_.end()) return it->second;
        return std::nullopt;
    }

    // Allow a message (undo retraction)
    void allow_message(const std::string& message_id) {
        std::unique_lock lock(mutex_);
        retractions_.erase(message_id);
        retracted_set_.erase(message_id);
    }

    // Build retraction XML
    std::string build_retraction_xml(const std::string& message_id,
                                       const std::string& reason = "") const {
        return MessageXmlBuilder::build_retraction(message_id, reason);
    }

    // Build retraction tombstone
    std::string build_tombstone_xml(const std::string& message_id,
                                      const std::string& by) const {
        return MessageXmlBuilder::build_retraction_tombstone(
            message_id, by, now_ms());
    }

    // Get all retracted message IDs
    std::vector<std::string> get_retracted_ids() const {
        std::shared_lock lock(mutex_);
        return std::vector<std::string>(retracted_set_.begin(),
                                          retracted_set_.end());
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, MessageRetraction> retractions_;
    std::unordered_set<std::string> retracted_set_;
};

// =============================================================================
// Message Encryption Manager (XEP-0380 / XEP-0420)
// =============================================================================
class MessageEncryptionManager {
public:
    MessageEncryptionManager() = default;

    // Register an encryption scheme
    void register_scheme(const std::string& namespace_uri,
                          const std::string& name) {
        std::unique_lock lock(mutex_);
        schemes_[namespace_uri] = name;
    }

    // Check if an encryption namespace is known
    bool is_known_scheme(const std::string& namespace_uri) const {
        std::shared_lock lock(mutex_);
        return schemes_.find(namespace_uri) != schemes_.end();
    }

    // Get encryption scheme name
    std::string get_scheme_name(const std::string& namespace_uri) const {
        std::shared_lock lock(mutex_);
        auto it = schemes_.find(namespace_uri);
        return it != schemes_.end() ? it->second : "Unknown";
    }

    // Build EME element
    std::string build_eme(const std::string& namespace_uri,
                            const std::string& fingerprint = "") const {
        std::string name = get_scheme_name(namespace_uri);
        return MessageXmlBuilder::build_eme(namespace_uri, name, fingerprint);
    }

    // Build SCE content element
    std::string build_sce_content(const std::string& enc_ns,
                                    const std::string& ciphertext_base64,
                                    const std::string& fingerprint = "") const {
        return MessageXmlBuilder::build_sce_content(
            enc_ns, ciphertext_base64, fingerprint);
    }

    // Get supported schemes
    std::vector<std::pair<std::string, std::string>> get_supported_schemes() const {
        std::shared_lock lock(mutex_);
        std::vector<std::pair<std::string, std::string>> result;
        for (const auto& [ns, name] : schemes_) {
            result.push_back({ns, name});
        }
        return result;
    }

    // Check if a message uses explicit encryption
    static std::optional<EncryptionInfo> detect_eme(const std::string& xml) {
        return MessageXmlParser::parse_eme(xml);
    }

    // Check if a message uses stanza content encryption
    static bool detect_sce(const std::string& xml) {
        return MessageXmlParser::has_sce_content(xml);
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::string> schemes_;
};

// =============================================================================
// Message Styling Engine (XEP-0393 / XHTML-IM)
// =============================================================================
class MessageStylingEngine {
public:
    MessageStylingEngine() = default;

    // Detect if a message body contains styling directives
    bool has_styling(const std::string& body) const {
        // Check for XEP-0393 styling directives
        return body.find('*') != std::string::npos ||
               body.find('_') != std::string::npos ||
               body.find('~') != std::string::npos ||
               body.find('`') != std::string::npos ||
               body.find("```") != std::string::npos;
    }

    // Convert styled plaintext to XHTML-IM
    std::string style_to_xhtml(const std::string& body) const {
        std::ostringstream xhtml;
        xhtml << "<p>";

        std::string escaped = xml_escape(body);

        // Bold: *text*
        escaped = apply_format(escaped, "\\*", "strong");

        // Italic: _text_ (but not __text__)
        escaped = apply_format(escaped, "_", "em");

        // Strikethrough: ~text~
        escaped = apply_format(escaped, "~", "span style='text-decoration:line-through'");

        // Inline code: `text`
        escaped = apply_format(escaped, "`", "code");

        // Replace newlines with <br/>
        size_t pos = 0;
        while ((pos = escaped.find('\n', pos)) != std::string::npos) {
            escaped.replace(pos, 1, "<br/>");
            pos += 5;
        }

        xhtml << escaped << "</p>";
        return xhtml.str();
    }

    // Generate styled message
    StyledMessage generate_styled(const std::string& plain_body) const {
        StyledMessage sm;
        sm.plain_body = plain_body;
        sm.has_styling = has_styling(plain_body);

        if (sm.has_styling) {
            sm.xhtml_im_body = style_to_xhtml(plain_body);
            sm.styling_engine = "XEP-0393";
        }

        // Extract mentions (@user@domain)
        extract_mentions(plain_body, sm.mentions);

        return sm;
    }

    // Extract @mentions from body
    std::vector<std::string> extract_mentions(const std::string& body) const {
        std::vector<std::string> mentions;
        std::regex mention_regex(R"(@([a-zA-Z0-9._\-]+@[a-zA-Z0-9.\-]+))");
        std::smatch match;
        std::string::const_iterator start = body.begin();
        while (std::regex_search(start, body.end(), match, mention_regex)) {
            mentions.push_back(match[1].str());
            start = match.suffix().first;
        }
        return mentions;
    }

    // Generate reply body with quoted content
    std::string build_reply_body(const std::string& original_body,
                                   const std::string& original_sender,
                                   int max_quote_chars = 140) const {
        std::string quote = original_body;
        if (quote.size() > static_cast<size_t>(max_quote_chars)) {
            quote = quote.substr(0, max_quote_chars) + "...";
        }

        std::ostringstream oss;
        oss << "> " << original_sender << ": ";
        size_t line_start = 0;
        oss << quote.substr(0, 50);
        for (size_t i = 50; i < quote.size(); i++) {
            if (quote[i] == '\n') {
                oss << "\n> ";
            } else {
                oss << quote[i];
            }
        }
        oss << "\n\n";
        return oss.str();
    }

private:
    std::string apply_format(const std::string& text,
                               const std::string& marker,
                               const std::string& tag) const {
        std::string result = text;
        std::string pattern_str = marker + "(.+?)" + marker;
        std::regex pattern(pattern_str);
        std::string replacement = "<" + tag + ">$1</" + tag;
        // Extract end tag
        size_t space_pos = tag.find(' ');
        std::string tag_name = space_pos != std::string::npos ?
            tag.substr(0, space_pos) : tag;
        replacement += ">";

        result = std::regex_replace(result, pattern,
            "<" + tag + ">$1</" + tag_name + ">",
            std::regex_constants::format_default);
        return result;
    }

    void extract_mentions(const std::string& plain_body,
                           std::vector<std::string>& mentions_out) const {
        mentions_out = extract_mentions(plain_body);
    }
};

// =============================================================================
// Message Expiration Manager
// =============================================================================
class MessageExpirationManager {
public:
    MessageExpirationManager() = default;

    // Set expiration for a message
    void set_expiration(const std::string& message_id, int ttl_seconds) {
        std::unique_lock lock(mutex_);
        int64_t expire_at = now_ms() + ttl_seconds * 1000;
        expirations_[message_id] = expire_at;
        ttl_map_[message_id] = ttl_seconds;
    }

    // Check if a message has expired
    bool is_expired(const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        auto it = expirations_.find(message_id);
        if (it == expirations_.end()) return false;
        return now_ms() >= it->second;
    }

    // Get remaining TTL in seconds
    int get_remaining_ttl(const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        auto it = expirations_.find(message_id);
        if (it == expirations_.end()) return -1;
        int64_t remaining = it->second - now_ms();
        if (remaining <= 0) return 0;
        return static_cast<int>(remaining / 1000);
    }

    // Get expiration timestamp
    std::optional<int64_t> get_expires_at(const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        auto it = expirations_.find(message_id);
        if (it != expirations_.end()) return it->second;
        return std::nullopt;
    }

    // Remove expiration
    void remove_expiration(const std::string& message_id) {
        std::unique_lock lock(mutex_);
        expirations_.erase(message_id);
        ttl_map_.erase(message_id);
    }

    // Find all expired messages
    std::vector<std::string> find_expired() const {
        std::shared_lock lock(mutex_);
        std::vector<std::string> expired;
        int64_t now = now_ms();
        for (const auto& [id, expire_at] : expirations_) {
            if (now >= expire_at) {
                expired.push_back(id);
            }
        }
        return expired;
    }

    // Cleanup expired entries
    void cleanup_expired() {
        std::unique_lock lock(mutex_);
        int64_t now = now_ms();
        auto it = expirations_.begin();
        while (it != expirations_.end()) {
            if (now >= it->second) {
                ttl_map_.erase(it->first);
                it = expirations_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Build expire XML element
    std::string build_expire_xml(int ttl_seconds) const {
        return MessageXmlBuilder::build_expire(ttl_seconds);
    }

    std::string build_expire_header_xml(int64_t expire_at_ms) const {
        return MessageXmlBuilder::build_expire_header(expire_at_ms);
    }

    // Statistics
    struct ExpireStats {
        int64_t active_count = 0;
        int64_t expired_count = 0;
    };

    ExpireStats get_stats() const {
        std::shared_lock lock(mutex_);
        ExpireStats stats;
        int64_t now = now_ms();
        for (const auto& [id, expire_at] : expirations_) {
            if (now >= expire_at) stats.expired_count++;
            else stats.active_count++;
        }
        return stats;
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, int64_t> expirations_;
    std::unordered_map<std::string, int> ttl_map_;
};

// =============================================================================
// Message Features Engine - Master Coordinator
// =============================================================================
class MessageFeaturesEngine {
public:
    MessageFeaturesEngine()
        : receipt_manager_(std::make_shared<DeliveryReceiptManager>()),
          marker_manager_(std::make_shared<ChatMarkerManager>()),
          state_tracker_(std::make_shared<ChatStateTracker>()),
          carbon_manager_(std::make_shared<MessageCarbonManager>()),
          archive_manager_(std::make_shared<MessageArchiveManager>()),
          correction_manager_(std::make_shared<MessageCorrectionManager>()),
          reaction_manager_(std::make_shared<MessageReactionManager>()),
          retraction_manager_(std::make_shared<MessageRetractionManager>()),
          encryption_manager_(std::make_shared<MessageEncryptionManager>()),
          styling_engine_(std::make_shared<MessageStylingEngine>()),
          expiration_manager_(std::make_shared<MessageExpirationManager>()) {

        // Register known encryption schemes
        encryption_manager_->register_scheme("eu.siacs.conversations.axolotl", "OMEMO");
        encryption_manager_->register_scheme("urn:xmpp:omemo:1", "OMEMOv1");
        encryption_manager_->register_scheme("urn:xmpp:omemo:2", "OMEMOv2");
        encryption_manager_->register_scheme("urn:xmpp:openpgp:0", "OpenPGP");
        encryption_manager_->register_scheme("jabber:x:encrypted", "Legacy OpenPGP");
        encryption_manager_->register_scheme("urn:xmpp:otr:0", "OTR");
        encryption_manager_->register_scheme("urn:xmpp:sce:0", "SCE");
    }

    // --- Access sub-managers ---
    std::shared_ptr<DeliveryReceiptManager> receipts() { return receipt_manager_; }
    std::shared_ptr<ChatMarkerManager> markers() { return marker_manager_; }
    std::shared_ptr<ChatStateTracker> states() { return state_tracker_; }
    std::shared_ptr<MessageCarbonManager> carbons() { return carbon_manager_; }
    std::shared_ptr<MessageArchiveManager> archive() { return archive_manager_; }
    std::shared_ptr<MessageCorrectionManager> corrections() { return correction_manager_; }
    std::shared_ptr<MessageReactionManager> reactions() { return reaction_manager_; }
    std::shared_ptr<MessageRetractionManager> retractions() { return retraction_manager_; }
    std::shared_ptr<MessageEncryptionManager> encryption() { return encryption_manager_; }
    std::shared_ptr<MessageStylingEngine> styling() { return styling_engine_; }
    std::shared_ptr<MessageExpirationManager> expiration() { return expiration_manager_; }

    // --- Process an incoming message ---
    MessageContext process_incoming(const std::string& xml) {
        MessageContext ctx = MessageXmlParser::parse_full_message(xml);

        // Handle delivery receipts
        if (ctx.receipt_state == ReceiptState::REQUESTED) {
            receipt_manager_->mark_receipt_requested(
                ctx.message_id, ctx.from.full(), ctx.to.full());
        } else if (ctx.receipt_state == ReceiptState::RECEIVED) {
            receipt_manager_->mark_receipt_received(
                ctx.receipt_id, ctx.from.full());
        }

        // Handle chat markers
        if (ctx.marker != ChatMarker::NONE) {
            marker_manager_->set_marker(
                ctx.marker_id, ctx.from.full(), ctx.marker);
        }

        // Handle chat states
        if (ctx.chat_state != ChatState::NONE) {
            state_tracker_->set_state(ctx.from.full(), ctx.to.full(), ctx.chat_state);
        }

        // Handle corrections
        if (ctx.correction.has_value()) {
            correction_manager_->record_correction(
                ctx.correction->original_id, *ctx.correction);
        }

        // Handle retractions
        if (ctx.retraction.has_value()) {
            retraction_manager_->retract_message(
                ctx.retraction->message_id,
                ctx.from.full(),
                ctx.retraction->reason);
            archive_manager_->retract_message(ctx.retraction->message_id);
        }

        // Handle reactions
        for (const auto& r : ctx.reactions) {
            for (const auto& e : r.emojis) {
                reaction_manager_->add_reaction(ctx.message_id, r.reactor_jid, e);
            }
        }

        // Handle expiration
        if (ctx.ttl_seconds > 0) {
            expiration_manager_->set_expiration(ctx.message_id, ctx.ttl_seconds);
        }

        // Generate styling if needed
        if (!ctx.body.empty() && styling_engine_->has_styling(ctx.body)) {
            ctx.styled = styling_engine_->generate_styled(ctx.body);
        }

        // Archive the message (unless NO_STORE hint)
        bool should_archive = true;
        for (auto hint : ctx.hints) {
            if (hint == ProcessingHint::NO_STORE ||
                hint == ProcessingHint::NO_PERMANENT_STORE) {
                should_archive = false;
                break;
            }
        }

        if (should_archive && !ctx.body.empty()) {
            archive_manager_->archive_message(
                ctx.stanza_id.empty() ? ctx.message_id : ctx.stanza_id,
                ctx.to.bare(),
                ctx);
        }

        return ctx;
    }

    // --- Build an outgoing message ---
    std::string build_outgoing(const MessageContext& ctx) {
        return MessageXmlBuilder::build_full_message(ctx);
    }

    // --- Generate receipt for a message ---
    std::string generate_receipt(const std::string& message_id,
                                   const Jid& from, const Jid& to) {
        std::ostringstream oss;
        oss << "<message from='" << xml_escape(from.full())
            << "' to='" << xml_escape(to.full())
            << "' id='" << gen_unique_id() << "'>";
        oss << MessageXmlBuilder::build_receipt_received(message_id);
        oss << "</message>";
        return oss.str();
    }

    // --- Generate chat state notification ---
    std::string generate_chat_state(const Jid& from, const Jid& to,
                                      ChatState state) {
        std::ostringstream oss;
        oss << "<message from='" << xml_escape(from.full())
            << "' to='" << xml_escape(to.full())
            << "' type='chat' id='" << gen_unique_id() << "'>";
        oss << MessageXmlBuilder::build_chat_state(state);
        oss << "</message>";
        return oss.str();
    }

    // --- Generate carbon copy for a resource ---
    std::string generate_carbon(const std::string& message_xml, bool sent) {
        return carbon_manager_->wrap_carbon(message_xml, sent);
    }

    // --- Process MAM query ---
    std::vector<ArchivedMessage> query_archive(const std::string& bare_jid,
                                                  const MamQuery& query) {
        return archive_manager_->query(bare_jid, query);
    }

    // --- Generate MAM query response ---
    std::string generate_mam_response(const std::string& responder_jid,
                                        const std::string& requester_full_jid,
                                        const std::string& iq_id,
                                        const MamQuery& query,
                                        const std::vector<ArchivedMessage>& results) {
        return archive_manager_->build_mam_results_iq(
            requester_full_jid, responder_jid, iq_id, query, results);
    }

    // --- Process message correction ---
    void process_correction(const std::string& original_id,
                             const std::string& new_body,
                             const std::string& corrector_jid) {
        MessageCorrection mc;
        mc.original_id = original_id;
        mc.new_body = new_body;
        mc.corrector_jid = corrector_jid;
        mc.timestamp = now_ms();
        correction_manager_->record_correction(original_id, mc);
    }

    // --- Handle reaction toggle ---
    void toggle_reaction(const std::string& message_id,
                          const std::string& reactor_jid,
                          const std::string& emoji) {
        if (reaction_manager_->has_reacted(message_id, reactor_jid)) {
            // Check if this specific emoji is already set
            auto reactions = reaction_manager_->get_reactions(message_id);
            for (const auto& r : reactions) {
                if (r.reactor_jid == reactor_jid) {
                    auto it = std::find(r.emojis.begin(), r.emojis.end(), emoji);
                    if (it != r.emojis.end()) {
                        reaction_manager_->remove_reaction(message_id, reactor_jid, emoji);
                        return;
                    }
                }
            }
        }
        reaction_manager_->add_reaction(message_id, reactor_jid, emoji);
    }

    // --- Check if a message should be suppressed (retracted/expired) ---
    bool should_suppress_message(const std::string& message_id) const {
        if (retraction_manager_->is_retracted(message_id)) return true;
        if (expiration_manager_->is_expired(message_id)) return true;
        return false;
    }

    // --- Periodic cleanup ---
    void cleanup_old_data(int64_t max_age_ms) {
        int64_t cutoff = now_ms() - max_age_ms;
        receipt_manager_->cleanup_old_receipts(cutoff);
        marker_manager_->cleanup_old_markers(cutoff);
        state_tracker_->cleanup_stale_states(cutoff);
        correction_manager_->cleanup_old_corrections(cutoff);
        reaction_manager_->cleanup_old_reactions(cutoff);
        expiration_manager_->cleanup_expired();
    }

    // --- Global statistics ---
    json get_global_stats() const {
        json j;

        // Receipt stats
        auto rs = receipt_manager_->get_stats();
        j["receipts"]["total_requested"] = rs.total_requested;
        j["receipts"]["total_received"] = rs.total_received;
        j["receipts"]["pending"] = rs.pending_count;

        // Reaction stats
        auto rxs = reaction_manager_->get_stats();
        j["reactions"]["total"] = rxs.total_reactions;
        j["reactions"]["unique_messages"] = rxs.unique_messages;
        j["reactions"]["unique_reactors"] = rxs.unique_reactors;

        // Archive stats
        j["archive"]["total_messages"] = archive_manager_->get_total_archived();

        // Expiration stats
        auto es = expiration_manager_->get_stats();
        j["expiration"]["active"] = es.active_count;
        j["expiration"]["expired"] = es.expired_count;

        // Encryption schemes
        auto schemes = encryption_manager_->get_supported_schemes();
        j["encryption"] = json::array();
        for (const auto& [ns, name] : schemes) {
            json scheme;
            scheme["namespace"] = ns;
            scheme["name"] = name;
            j["encryption"].push_back(scheme);
        }

        return j;
    }

private:
    std::shared_ptr<DeliveryReceiptManager> receipt_manager_;
    std::shared_ptr<ChatMarkerManager> marker_manager_;
    std::shared_ptr<ChatStateTracker> state_tracker_;
    std::shared_ptr<MessageCarbonManager> carbon_manager_;
    std::shared_ptr<MessageArchiveManager> archive_manager_;
    std::shared_ptr<MessageCorrectionManager> correction_manager_;
    std::shared_ptr<MessageReactionManager> reaction_manager_;
    std::shared_ptr<MessageRetractionManager> retraction_manager_;
    std::shared_ptr<MessageEncryptionManager> encryption_manager_;
    std::shared_ptr<MessageStylingEngine> styling_engine_;
    std::shared_ptr<MessageExpirationManager> expiration_manager_;
};

// =============================================================================
// Read-Only Marker Handler
// Handles display-only / sent-only markers for message status indicators
// =============================================================================
class ReadOnlyMarkerHandler {
public:
    ReadOnlyMarkerHandler() = default;

    // Set a display-only marker (read receipt without privacy implications)
    void mark_displayed_readonly(const std::string& message_id,
                                   const std::string& viewer_jid) {
        std::unique_lock lock(mutex_);
        displayed_readonly_[message_id].insert(viewer_jid);
        display_timestamps_[message_id] = now_ms();
    }

    // Set a sent-only marker (delivered to server but not yet to client)
    void mark_sent_only(const std::string& message_id) {
        std::unique_lock lock(mutex_);
        sent_only_[message_id] = now_ms();
    }

    // Get display count for a message
    int get_display_count(const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        auto it = displayed_readonly_.find(message_id);
        if (it != displayed_readonly_.end()) {
            return static_cast<int>(it->second.size());
        }
        return 0;
    }

    // Get viewers of a message
    std::vector<std::string> get_viewers(const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        auto it = displayed_readonly_.find(message_id);
        if (it != displayed_readonly_.end()) {
            return std::vector<std::string>(it->second.begin(), it->second.end());
        }
        return {};
    }

    // Check if a message was sent
    bool was_sent(const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        return sent_only_.find(message_id) != sent_only_.end();
    }

    // Get sent timestamp
    std::optional<int64_t> get_sent_timestamp(const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        auto it = sent_only_.find(message_id);
        if (it != sent_only_.end()) return it->second;
        return std::nullopt;
    }

    // Get display timestamp
    std::optional<int64_t> get_display_timestamp(const std::string& message_id) const {
        std::shared_lock lock(mutex_);
        auto it = display_timestamps_.find(message_id);
        if (it != display_timestamps_.end()) return it->second;
        return std::nullopt;
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::unordered_set<std::string>> displayed_readonly_;
    std::unordered_map<std::string, int64_t> display_timestamps_;
    std::unordered_map<std::string, int64_t> sent_only_;
};

// =============================================================================
// Last Message Correction Handler
// Tracks the most recent correction across all conversations
// =============================================================================
class LastMessageCorrectionHandler {
public:
    LastMessageCorrectionHandler() = default;

    // Record a correction as the "last" for a conversation
    void set_last_correction(const std::string& conversation_id,
                              const MessageCorrection& correction) {
        std::unique_lock lock(mutex_);
        last_corrections_[conversation_id] = correction;
        correction_history_[conversation_id].push_back(correction);

        if (correction_history_[conversation_id].size() > max_history_) {
            correction_history_[conversation_id].erase(
                correction_history_[conversation_id].begin());
        }
    }

    // Get last correction for a conversation
    std::optional<MessageCorrection> get_last_correction(
        const std::string& conversation_id) const {
        std::shared_lock lock(mutex_);
        auto it = last_corrections_.find(conversation_id);
        if (it != last_corrections_.end()) return it->second;
        return std::nullopt;
    }

    // Get last N corrections for a conversation
    std::vector<MessageCorrection> get_recent_corrections(
        const std::string& conversation_id, int limit = 10) const {
        std::shared_lock lock(mutex_);
        auto it = correction_history_.find(conversation_id);
        if (it == correction_history_.end()) return {};

        const auto& history = it->second;
        if (static_cast<int>(history.size()) <= limit) return history;

        return std::vector<MessageCorrection>(
            history.end() - limit, history.end());
    }

    // Clear corrections for a conversation
    void clear_conversation(const std::string& conversation_id) {
        std::unique_lock lock(mutex_);
        last_corrections_.erase(conversation_id);
        correction_history_.erase(conversation_id);
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, MessageCorrection> last_corrections_;
    std::unordered_map<std::string, std::vector<MessageCorrection>> correction_history_;
    size_t max_history_ = 100;
};

// =============================================================================
// Data form builder for MAM query forms
// =============================================================================
class MamDataFormBuilder {
public:
    static std::string build_query_form() {
        std::ostringstream oss;
        oss << "<x xmlns='jabber:x:data' type='form'>"
            << "<title>Message Archive Management Query</title>"
            << "<instructions>Fill in one or more fields to search the archive</instructions>"
            << "<field var='FORM_TYPE' type='hidden'>"
            << "<value>urn:xmpp:mam:2</value>"
            << "</field>"
            << "<field var='with' type='jid-single' label='With JID'/>"
            << "<field var='start' type='text-single' label='Start Date (e.g. 2024-01-01T00:00:00Z)'/>"
            << "<field var='end' type='text-single' label='End Date'/>"
            << "</x>";
        return oss.str();
    }

    static std::string build_prefs_form(const std::string& current_default) {
        std::ostringstream oss;
        oss << "<x xmlns='jabber:x:data' type='form'>"
            << "<title>Archive Preferences</title>"
            << "<field var='FORM_TYPE' type='hidden'>"
            << "<value>urn:xmpp:mam:2</value>"
            << "</field>"
            << "<field var='default' type='list-single' label='Default behavior'>"
            << "<value>" << xml_escape(current_default) << "</value>"
            << "<option label='Always'><value>always</value></option>"
            << "<option label='Never'><value>never</value></option>"
            << "<option label='Roster'><value>roster</value></option>"
            << "</field>"
            << "</x>";
        return oss.str();
    }
};

// =============================================================================
// Message router helper for feature-aware routing
// =============================================================================
class MessageFeatureRouter {
public:
    MessageFeatureRouter(
        std::shared_ptr<MessageFeaturesEngine> engine)
        : engine_(engine) {}

    // Route a message applying all feature logic
    struct RouteResult {
        std::string primary_delivery_xml;
        std::vector<std::string> carbon_copies;
        std::vector<std::string> mam_results;
        bool should_suppress;
        std::string suppression_reason;
    };

    RouteResult route_message(const std::string& xml) {
        RouteResult result;
        result.should_suppress = false;

        MessageContext ctx = engine_->process_incoming(xml);

        // Check suppression
        if (engine_->should_suppress_message(ctx.message_id)) {
            result.should_suppress = true;
            result.suppression_reason = "Message retracted or expired";
            return result;
        }

        // Generate primary delivery
        result.primary_delivery_xml = engine_->build_outgoing(ctx);

        // Generate carbon copies
        if (!ctx.to.bare().empty()) {
            auto resources = engine_->carbons()->get_user_resources(ctx.to.bare());
            bool has_no_copy = false;
            for (auto hint : ctx.hints) {
                if (hint == ProcessingHint::NO_COPY) {
                    has_no_copy = true;
                    break;
                }
            }
            if (!has_no_copy) {
                for (const auto& res : resources) {
                    std::string carbon = engine_->carbons()->wrap_carbon(
                        result.primary_delivery_xml, false);
                    result.carbon_copies.push_back(carbon);
                }
            }
        }

        return result;
    }

    // Process an IQ containing MAM query
    std::string handle_mam_query(const std::string& iq_xml,
                                   const std::string& requester_bare_jid) {
        MamQuery query;
        size_t qpos = iq_xml.find("<query xmlns='urn:xmpp:mam:2'");
        if (qpos == std::string::npos)
            qpos = iq_xml.find("<query xmlns=\"urn:xmpp:mam:2\"");
        if (qpos != std::string::npos) {
            std::string query_frag = iq_xml.substr(qpos,
                iq_xml.find("</query>", qpos) - qpos + 8);
            auto parsed = MessageXmlParser::parse_mam_query(iq_xml);
            if (parsed.has_value()) query = *parsed;
        }

        std::string iq_id = xml_get_attr(iq_xml, "id");
        std::string from = xml_get_attr(iq_xml, "from");

        auto results = engine_->query_archive(requester_bare_jid, query);
        return engine_->generate_mam_response(
            requester_bare_jid, from, iq_id, query, results);
    }

private:
    std::shared_ptr<MessageFeaturesEngine> engine_;
};

// =============================================================================
// Session-level message feature context
// =============================================================================
struct SessionMessageContext {
    std::string bare_jid;
    std::string resource;
    std::string full_jid;
    bool carbons_enabled = false;
    bool mam_enabled = true;
    int64_t last_message_at = 0;
    int64_t messages_sent = 0;
    int64_t messages_received = 0;
    std::deque<std::string> recent_message_ids;
};

// =============================================================================
// Per-session message processing
// =============================================================================
class SessionMessageProcessor {
public:
    SessionMessageProcessor(
        std::shared_ptr<MessageFeaturesEngine> engine)
        : engine_(engine) {}

    // Create session
    void create_session(const std::string& bare_jid,
                          const std::string& resource) {
        std::unique_lock lock(mutex_);
        SessionMessageContext& ctx = sessions_[bare_jid + "/" + resource];
        ctx.bare_jid = bare_jid;
        ctx.resource = resource;
        ctx.full_jid = bare_jid + "/" + resource;
        ctx.last_message_at = now_ms();

        engine_->carbons()->register_resource(bare_jid, resource);
    }

    // Destroy session
    void destroy_session(const std::string& bare_jid,
                           const std::string& resource) {
        std::unique_lock lock(mutex_);
        sessions_.erase(bare_jid + "/" + resource);
        engine_->carbons()->unregister_resource(bare_jid, resource);
    }

    // Process stanza
    std::string process_stanza(const std::string& full_jid,
                                 const std::string& xml) {
        // Parse
        Jid from;
        from.parse(full_jid);

        // Update session
        {
            std::unique_lock lock(mutex_);
            auto it = sessions_.find(full_jid);
            if (it != sessions_.end()) {
                it->second.messages_sent++;
                it->second.last_message_at = now_ms();
            }
        }

        // Process through engine
        MessageContext ctx = engine_->process_incoming(xml);

        // If this is a chat state notification, generate proper response
        if (ctx.chat_state != ChatState::NONE) {
            return engine_->build_outgoing(ctx);
        }

        // If this is a delivery receipt, acknowledge
        if (ctx.receipt_state == ReceiptState::REQUESTED) {
            return engine_->generate_receipt(
                ctx.message_id,
                from,  // to becomes from in response
                ctx.from); // from becomes to
        }

        // If this is a retraction, apply
        if (ctx.retraction.has_value()) {
            engine_->retractions()->retract_message(
                ctx.retraction->message_id,
                from.full(),
                ctx.retraction->reason);
        }

        return engine_->build_outgoing(ctx);
    }

    // Enable carbons for a session
    void enable_carbons(const std::string& full_jid) {
        std::unique_lock lock(mutex_);
        auto it = sessions_.find(full_jid);
        if (it != sessions_.end()) {
            it->second.carbons_enabled = true;
            Jid j;
            j.parse(full_jid);
            engine_->carbons()->enable_for_user(j.bare());
        }
    }

    // Disable carbons
    void disable_carbons(const std::string& full_jid) {
        std::unique_lock lock(mutex_);
        auto it = sessions_.find(full_jid);
        if (it != sessions_.end()) {
            it->second.carbons_enabled = false;
            Jid j;
            j.parse(full_jid);
            engine_->carbons()->disable_for_user(j.bare());
        }
    }

    // Get session
    SessionMessageContext* get_session(const std::string& full_jid) {
        std::shared_lock lock(mutex_);
        auto it = sessions_.find(full_jid);
        return it != sessions_.end() ? &it->second : nullptr;
    }

    // Session count
    size_t session_count() const {
        std::shared_lock lock(mutex_);
        return sessions_.size();
    }

private:
    std::shared_ptr<MessageFeaturesEngine> engine_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, SessionMessageContext> sessions_;
};

// =============================================================================
// Server-level message features dispatcher
// =============================================================================
class MessageFeaturesDispatcher {
public:
    MessageFeaturesDispatcher() {
        engine_ = std::make_shared<MessageFeaturesEngine>();
        session_processor_ = std::make_shared<SessionMessageProcessor>(engine_);
        router_ = std::make_shared<MessageFeatureRouter>(engine_);
    }

    // Get core engine
    std::shared_ptr<MessageFeaturesEngine> engine() { return engine_; }
    std::shared_ptr<SessionMessageProcessor> sessions() { return session_processor_; }
    std::shared_ptr<MessageFeatureRouter> router() { return router_; }

    // Handle an incoming XMPP stanza
    std::string handle_stanza(const std::string& full_jid,
                                const std::string& xml) {
        // Determine stanza type
        if (xml.find("<message ") == std::string::npos &&
            xml.find("<message>") == std::string::npos &&
            xml.find("<message xmlns") == std::string::npos) {
            // Not a message stanza - pass through
            return "";
        }

        return session_processor_->process_stanza(full_jid, xml);
    }

    // Handle IQ stanzas related to message features
    std::string handle_iq(const std::string& xml,
                            const std::string& requester_bare_jid) {
        // Carbon enable/disable
        if (MessageXmlParser::is_carbon_enable(xml)) {
            std::string from = xml_get_attr(xml, "from");
            engine_->carbons()->enable_for_user(requester_bare_jid);
            return build_iq_result(xml, "");
        }

        if (MessageXmlParser::is_carbon_disable(xml)) {
            engine_->carbons()->disable_for_user(requester_bare_jid);
            return build_iq_result(xml, "");
        }

        // MAM query
        if (xml.find("urn:xmpp:mam:2") != std::string::npos) {
            return router_->handle_mam_query(xml, requester_bare_jid);
        }

        // MAM prefs
        if (xml.find("<prefs xmlns='urn:xmpp:mam:2'") != std::string::npos) {
            return build_iq_result(xml,
                MessageXmlBuilder::build_mam_prefs_default());
        }

        return "";
    }

    // Periodic cleanup
    void periodic_cleanup() {
        engine_->cleanup_old_data(86400000); // 24 hours
    }

private:
    std::string build_iq_result(const std::string& iq_xml,
                                  const std::string& inner_xml) {
        std::string id = xml_get_attr(iq_xml, "id");
        std::string from = xml_get_attr(iq_xml, "from");
        std::string to = xml_get_attr(iq_xml, "to");

        std::ostringstream oss;
        oss << "<iq type='result' id='" << xml_escape(id) << "'";
        if (!to.empty()) oss << " to='" << xml_escape(to) << "'";
        if (!from.empty()) oss << " from='" << xml_escape(from) << "'";
        oss << ">" << inner_xml << "</iq>";
        return oss.str();
    }

    std::shared_ptr<MessageFeaturesEngine> engine_;
    std::shared_ptr<SessionMessageProcessor> session_processor_;
    std::shared_ptr<MessageFeatureRouter> router_;
};

} // namespace xmpp
} // namespace progressive

// =============================================================================
// End: xmpp_message_features.cpp - 3500+ lines
// =============================================================================
