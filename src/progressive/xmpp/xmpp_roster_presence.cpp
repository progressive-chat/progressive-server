// =============================================================================
// xmpp_roster_presence.cpp
// XMPP Roster, Presence, and Message Routing Implementation
// =============================================================================
// Implements: XEP-0237 (Roster Versioning), XEP-0012 (Last Activity),
//   XEP-0054/XEP-0153 (vCard Avatar), XEP-0115 (Entity Capabilities),
//   XEP-0280 (Message Carbons), XEP-0333 (Chat Markers),
//   XEP-0085 (Chat State Notifications), XEP-0184 (Delivery Receipts),
//   Message Archive Preferences, Stream Resumption, Message Pipeline
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
#include <cstring>
#include <cstdint>
#include <random>
#include <iomanip>
#include <queue>

// =============================================================================
// SHA1 / Digest utilities for Entity Capabilities (XEP-0115)
// =============================================================================

namespace progressive { namespace xmpp { namespace detail {

namespace {

// ---------------------------------------------------------------------------
// SHA1 - Simplified implementation for cap hash computation
// We implement a minimal SHA1 for computing XEP-0115 verification strings
// without pulling in external crypto libraries.
// ---------------------------------------------------------------------------

class sha1 {
public:
    sha1() { reset(); }

    void reset() {
        h_[0] = 0x67452301;
        h_[1] = 0xEFCDAB89;
        h_[2] = 0x98BADCFE;
        h_[3] = 0x10325476;
        h_[4] = 0xC3D2E1F0;
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
        // padding
        block_[buf_index_++] = 0x80;
        if (buf_index_ > 56) {
            while (buf_index_ < 64) block_[buf_index_++] = 0;
            transform_block();
            buf_index_ = 0;
        }
        while (buf_index_ < 56) block_[buf_index_++] = 0;
        // append total bits as 64-bit big-endian
        uint64_t bits = total_bits_;
        for (int i = 7; i >= 0; --i) {
            block_[56 + i] = static_cast<uint8_t>(bits & 0xFF);
            bits >>= 8;
        }
        transform_block();
        // produce hex string
        std::ostringstream oss;
        for (int i = 0; i < 5; ++i) {
            oss << std::hex << std::setfill('0') << std::setw(8) << h_[i];
        }
        std::string hex = oss.str();
        reset();
        return hex;
    }

private:
    uint32_t h_[5];
    uint64_t total_bits_;
    uint8_t block_[64];
    size_t buf_index_;

    static uint32_t rotl(uint32_t v, int n) {
        return (v << n) | (v >> (32 - n));
    }

    void transform_block() {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block_[i * 4]) << 24) |
                   (static_cast<uint32_t>(block_[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block_[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(block_[i * 4 + 3]));
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];

        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t temp = rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }
        h_[0] += a;
        h_[1] += b;
        h_[2] += c;
        h_[3] += d;
        h_[4] += e;
    }
};

} // anonymous namespace

// ---------------------------------------------------------------------------
// Base64 encode/decode for vCard avatar binary data (XEP-0054/XEP-0153)
// ---------------------------------------------------------------------------

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& input) {
    std::string output;
    output.reserve(((input.size() + 2) / 3) * 4);
    int val = 0;
    int valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            output.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        output.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (output.size() % 4) {
        output.push_back('=');
    }
    return output;
}

std::string base64_decode(const std::string& input) {
    // Strip padding
    size_t in_len = input.size();
    size_t pad = 0;
    if (in_len > 0 && input[in_len - 1] == '=') pad++;
    if (in_len > 1 && input[in_len - 2] == '=') pad++;

    std::string output;
    output.reserve(((in_len * 3) / 4) - pad);

    static const int decode_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    int val = 0;
    int valb = -8;
    for (size_t i = 0; i < in_len; ++i) {
        int d = decode_table[static_cast<unsigned char>(input[i])];
        if (d == -1) continue;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            output.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return output;
}

// =============================================================================
// XML string escaping helpers
// =============================================================================

std::string xml_escape(const std::string& s) {
    std::string result;
    result.reserve(s.size() + s.size() / 4);
    for (char c : s) {
        switch (c) {
            case '&':  result += "&amp;";  break;
            case '<':  result += "&lt;";   break;
            case '>':  result += "&gt;";   break;
            case '"':  result += "&quot;"; break;
            case '\'': result += "&apos;"; break;
            default:   result += c;        break;
        }
    }
    return result;
}

std::string xml_unescape(const std::string& s) {
    std::string result;
    result.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '&') {
            if (s.compare(i, 5, "&amp;") == 0)  { result += '&'; i += 4; }
            else if (s.compare(i, 4, "&lt;") == 0)  { result += '<'; i += 3; }
            else if (s.compare(i, 4, "&gt;") == 0)  { result += '>'; i += 3; }
            else if (s.compare(i, 6, "&quot;") == 0) { result += '"'; i += 5; }
            else if (s.compare(i, 6, "&apos;") == 0) { result += '\''; i += 5; }
            else { result += s[i]; }
        } else {
            result += s[i];
        }
    }
    return result;
}

// =============================================================================
// Timestamp utilities
// =============================================================================

std::string current_iso8601() {
    time_t now = time(nullptr);
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return std::string(buf);
}

std::string seconds_to_duration(int64_t seconds) {
    int64_t s = seconds;
    int days = s / 86400; s %= 86400;
    int hours = s / 3600; s %= 3600;
    int mins = s / 60; s %= 60;
    std::ostringstream oss;
    if (days > 0) oss << days << "d ";
    if (hours > 0 || days > 0) oss << hours << "h ";
    if (mins > 0 || hours > 0 || days > 0) oss << mins << "m ";
    oss << s << "s";
    return oss.str();
}

std::string generate_id() {
    static std::mt19937_64 rng(std::random_device{}());
    static std::uniform_int_distribution<uint64_t> dist;
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << dist(rng);
    return oss.str();
}

// =============================================================================
// JID parsing utilities
// =============================================================================

struct jid_parts {
    std::string local;
    std::string domain;
    std::string resource;
};

jid_parts parse_jid(const std::string& jid) {
    jid_parts result;
    std::string rest = jid;
    // Extract resource (after /)
    size_t slash = rest.find('/');
    if (slash != std::string::npos) {
        result.resource = rest.substr(slash + 1);
        rest = rest.substr(0, slash);
    }
    // Extract local part (before @)
    size_t at = rest.find('@');
    if (at != std::string::npos) {
        result.local = rest.substr(0, at);
        result.domain = rest.substr(at + 1);
    } else {
        result.domain = rest;
    }
    return result;
}

std::string bare_jid(const std::string& jid) {
    size_t slash = jid.find('/');
    if (slash != std::string::npos) {
        return jid.substr(0, slash);
    }
    return jid;
}

std::string make_full_jid(const std::string& bare, const std::string& resource) {
    if (resource.empty()) return bare;
    return bare + "/" + resource;
}

} } } // namespace progressive::xmpp::detail

// =============================================================================
// Main namespace with forward declarations
// =============================================================================

namespace progressive { namespace xmpp {

// Forward declarations
class xmpp_connection;
class xmpp_stream;

// Bring detail helpers into scope for convenience within this namespace
using detail::bare_jid;
using detail::make_full_jid;
using detail::xml_escape;
using detail::xml_unescape;
using detail::parse_jid;
using detail::generate_id;
using detail::current_iso8601;
using detail::base64_encode;
using detail::base64_decode;

// =========================================================================
// Roster structures (XEP-0237 Roster Versioning)
// =========================================================================

enum class subscription_state {
    none,
    to,
    from,
    both,
    remove
};

const char* subscription_state_string(subscription_state s) {
    switch (s) {
        case subscription_state::none:   return "none";
        case subscription_state::to:     return "to";
        case subscription_state::from:   return "from";
        case subscription_state::both:   return "both";
        case subscription_state::remove: return "remove";
    }
    return "none";
}

subscription_state subscription_state_from_string(const std::string& s) {
    if (s == "none")   return subscription_state::none;
    if (s == "to")     return subscription_state::to;
    if (s == "from")   return subscription_state::from;
    if (s == "both")   return subscription_state::both;
    if (s == "remove") return subscription_state::remove;
    return subscription_state::none;
}

struct roster_item {
    std::string jid;                  // Bare JID of the contact
    std::string name;                 // Display name (nickname)
    subscription_state subscription;  // Subscription state
    std::vector<std::string> groups;  // Roster groups

    // Extended fields from various XEPs
    std::string ask;                  // "subscribe" if pending outgoing sub request
    bool approved;                    // Whether pre-approved (XEP-0379)
    std::string avatar_hash;          // SHA1 hash of avatar for this contact

    roster_item() : subscription(subscription_state::none), approved(false) {}

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<item jid='" << detail::xml_escape(jid) << "'";
        if (!name.empty()) {
            oss << " name='" << detail::xml_escape(name) << "'";
        }
        oss << " subscription='" << subscription_state_string(subscription) << "'";
        if (!ask.empty()) {
            oss << " ask='" << detail::xml_escape(ask) << "'";
        }
        oss << ">";
        for (const auto& g : groups) {
            oss << "<group>" << detail::xml_escape(g) << "</group>";
        }
        oss << "</item>";
        return oss.str();
    }
};

// =========================================================================
// Presence state
// =========================================================================

enum class presence_show {
    online,     // available
    away,       // away
    xa,         // extended away
    dnd,        // do not disturb
    chat,       // free for chat
    offline
};

const char* presence_show_string(presence_show s) {
    switch (s) {
        case presence_show::online:  return "chat";  // we use 'chat' as the default available show
        case presence_show::away:    return "away";
        case presence_show::xa:      return "xa";
        case presence_show::dnd:     return "dnd";
        case presence_show::chat:    return "chat";
        case presence_show::offline: return "unavailable";
    }
    return "chat";
}

presence_show presence_show_from_string(const std::string& s) {
    if (s == "chat" || s.empty()) return presence_show::chat;
    if (s == "away")   return presence_show::away;
    if (s == "xa")     return presence_show::xa;
    if (s == "dnd")    return presence_show::dnd;
    return presence_show::online;
}

struct presence_info {
    std::string jid;              // Full JID
    std::string bare_jid;         // Bare JID
    std::string resource;         // Resource
    presence_show show;           // Availability
    std::string status;           // Status message
    int priority;                 // Priority (-128 to 127)
    int64_t last_seen;            // Last activity timestamp (epoch seconds)
    std::string avatar_hash;      // vCard avatar hash (XEP-0153)
    std::string caps_node;        // Entity capabilities node
    std::string caps_ver;         // Entity capabilities verification
    std::string caps_hash;        // Entity capabilities hash algorithm
    std::vector<std::string> caps_features; // Resolved features from caps

    presence_info()
        : show(presence_show::offline)
        , priority(0)
        , last_seen(0)
        , caps_hash("sha-1") {}

    bool is_online() const {
        return show != presence_show::offline && priority >= 0;
    }

    std::string to_xml(const std::string& to_jid) const {
        std::ostringstream oss;
        oss << "<presence";
        if (!to_jid.empty()) {
            oss << " to='" << detail::xml_escape(to_jid) << "'";
        }
        oss << " from='" << detail::xml_escape(jid) << "'";
        if (!is_online()) {
            oss << " type='unavailable'";
        }
        oss << ">";
        if (is_online()) {
            oss << "<show>" << presence_show_string(show) << "</show>";
        }
        if (!status.empty()) {
            oss << "<status>" << detail::xml_escape(status) << "</status>";
        }
        if (priority != 0) {
            oss << "<priority>" << priority << "</priority>";
        }
        if (!caps_node.empty() && !caps_ver.empty()) {
            oss << "<c xmlns='http://jabber.org/protocol/caps'"
                << " hash='" << detail::xml_escape(caps_hash) << "'"
                << " node='" << detail::xml_escape(caps_node) << "'"
                << " ver='" << detail::xml_escape(caps_ver) << "'/>";
        }
        if (!avatar_hash.empty()) {
            oss << "<x xmlns='vcard-temp:x:update'><photo>"
                << detail::xml_escape(avatar_hash) << "</photo></x>";
        }
        oss << "</presence>";
        return oss.str();
    }
};

// =========================================================================
// Message structures
// =========================================================================

enum class chat_state {
    active,
    inactive,
    composing,
    paused,
    gone,
    none
};

const char* chat_state_string(chat_state s) {
    switch (s) {
        case chat_state::active:     return "active";
        case chat_state::inactive:   return "inactive";
        case chat_state::composing:  return "composing";
        case chat_state::paused:     return "paused";
        case chat_state::gone:       return "gone";
        case chat_state::none:       return "";
    }
    return "";
}

chat_state chat_state_from_string(const std::string& s) {
    if (s == "active")    return chat_state::active;
    if (s == "inactive")  return chat_state::inactive;
    if (s == "composing") return chat_state::composing;
    if (s == "paused")    return chat_state::paused;
    if (s == "gone")      return chat_state::gone;
    return chat_state::none;
}

enum class chat_marker {
    received,
    displayed,
    acknowledged
};

const char* chat_marker_string(chat_marker m) {
    switch (m) {
        case chat_marker::received:      return "received";
        case chat_marker::displayed:     return "displayed";
        case chat_marker::acknowledged:  return "acknowledged";
    }
    return "received";
}

enum class message_type {
    normal,
    chat,
    groupchat,
    headline,
    error
};

const char* message_type_string(message_type t) {
    switch (t) {
        case message_type::normal:    return "normal";
        case message_type::chat:      return "chat";
        case message_type::groupchat: return "groupchat";
        case message_type::headline:  return "headline";
        case message_type::error:     return "error";
    }
    return "normal";
}

message_type message_type_from_string(const std::string& s) {
    if (s == "normal")    return message_type::normal;
    if (s == "chat")      return message_type::chat;
    if (s == "groupchat") return message_type::groupchat;
    if (s == "headline")  return message_type::headline;
    if (s == "error")     return message_type::error;
    return message_type::normal;
}

struct xmpp_message {
    std::string id;                    // Message ID
    std::string from;                  // Sender JID (full)
    std::string to;                    // Recipient JID (full)
    message_type type;                 // Message type
    std::string body;                  // Message body text
    std::string thread;                // Thread ID for conversations
    std::string subject;               // Message subject

    // XEP-0085 Chat State Notifications
    chat_state chat_state_flag;

    // XEP-0184 Message Delivery Receipts
    std::string receipt_id;            // ID of message we are receipting
    bool request_receipt;              // Whether sender requests a receipt

    // XEP-0280 Message Carbons
    bool is_carbon;                    // Whether this is a carbon copy
    std::string carbon_direction;      // "sent" or "received"

    // XEP-0333 Chat Markers
    chat_marker marker;                // Chat marker type
    std::string marker_id;             // ID of message being marked
    bool has_marker;

    // Store stanza
    std::string store_hint;            // "store" or "no-store" or empty
    bool no_permanent_store;           // From XEP-0313 MAM preferences

    // Raw XML / extension payloads
    std::vector<std::string> extensions;

    // Timestamp
    std::string timestamp;

    xmpp_message()
        : type(message_type::chat)
        , chat_state_flag(chat_state::none)
        , request_receipt(false)
        , is_carbon(false)
        , has_marker(false)
        , marker(chat_marker::received)
        , no_permanent_store(false) {}

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<message";
        if (!id.empty()) {
            oss << " id='" << detail::xml_escape(id) << "'";
        }
        if (!from.empty()) {
            oss << " from='" << detail::xml_escape(from) << "'";
        }
        if (!to.empty()) {
            oss << " to='" << detail::xml_escape(to) << "'";
        }
        if (type != message_type::normal) {
            oss << " type='" << message_type_string(type) << "'";
        }
        oss << ">";

        // Carbon wrapping
        if (is_carbon && !carbon_direction.empty()) {
            oss << "<" << detail::xml_escape(carbon_direction)
                << " xmlns='urn:xmpp:carbons:2'>";
            // Forwarded wrapper
            oss << "<forwarded xmlns='urn:xmpp:forward:0'>";
            oss << "<delay xmlns='urn:xmpp:delay' stamp='"
                << (timestamp.empty() ? detail::current_iso8601() : detail::xml_escape(timestamp))
                << "'/>";
            // Re-emit the inner message
        }

        if (!body.empty()) {
            oss << "<body>" << detail::xml_escape(body) << "</body>";
        }
        if (!subject.empty()) {
            oss << "<subject>" << detail::xml_escape(subject) << "</subject>";
        }
        if (!thread.empty()) {
            oss << "<thread>" << detail::xml_escape(thread) << "</thread>";
        }

        // Chat state (XEP-0085)
        if (chat_state_flag != chat_state::none) {
            oss << "<" << chat_state_string(chat_state_flag)
                << " xmlns='http://jabber.org/protocol/chatstates'/>";
        }

        // Delivery receipt request (XEP-0184)
        if (request_receipt) {
            oss << "<request xmlns='urn:xmpp:receipts'/>";
        }

        // Delivery receipt response (XEP-0184)
        if (!receipt_id.empty()) {
            oss << "<received xmlns='urn:xmpp:receipts' id='"
                << detail::xml_escape(receipt_id) << "'/>";
        }

        // Chat markers (XEP-0333)
        if (has_marker && !marker_id.empty()) {
            oss << "<" << chat_marker_string(marker)
                << " xmlns='urn:xmpp:chat-markers:0' id='"
                << detail::xml_escape(marker_id) << "'/>";
        }

        // Store hint
        if (!store_hint.empty()) {
            oss << "<" << detail::xml_escape(store_hint)
                << " xmlns='urn:xmpp:hints'/>";
        }

        // Extensions
        for (const auto& ext : extensions) {
            oss << ext;
        }

        if (is_carbon && !carbon_direction.empty()) {
            oss << "</forwarded></" << detail::xml_escape(carbon_direction) << ">";
        }

        oss << "</message>";
        return oss.str();
    }
};

// =========================================================================
// Stream resumption data (XEP-0198)
// =========================================================================

struct stream_resumption_entry {
    std::string id;                // Stream ID for resumption
    std::string bare_jid;
    uint64_t h_handled;            // Number of stanzas handled by client
    uint64_t h_sent;               // Number of stanzas sent by server
    int64_t created_at;
    int64_t max_age;               // Maximum resume time in seconds
    std::string location;          // SM location hint
    std::queue<std::string> unacked_stanzas; // Unacknowledged stanzas to replay
    std::string previous_id;       // Previous stream ID
    std::string prev_location;

    stream_resumption_entry()
        : h_handled(0), h_sent(0), created_at(0), max_age(300) {}

    bool is_expired() const {
        return (time(nullptr) - created_at) > max_age;
    }
};

// =========================================================================
// Message Archive Preferences (XEP-0313)
// =========================================================================

enum class archive_pref_mode {
    always,
    never,
    roster
};

struct archive_preferences {
    archive_pref_mode default_mode;
    // Per-JID overrides: key = bare JID, value = always/never/roster
    std::unordered_map<std::string, archive_pref_mode> jid_overrides;
    // Conditions for archiving (match type, otr)
    std::vector<std::string> method_conditions;
    bool auto_save;

    archive_preferences() : default_mode(archive_pref_mode::roster), auto_save(true) {}

    bool should_archive(const std::string& bare_from, const std::string& bare_to) const {
        // Check JID-specific override for the "from" JID
        auto it = jid_overrides.find(bare_from);
        if (it != jid_overrides.end()) {
            return it->second == archive_pref_mode::always;
        }
        switch (default_mode) {
            case archive_pref_mode::always: return true;
            case archive_pref_mode::never:  return false;
            case archive_pref_mode::roster: return true; // Assume roster
        }
        return true;
    }

    archive_pref_mode resolve_for_jid(const std::string& jid) const {
        auto it = jid_overrides.find(jid);
        if (it != jid_overrides.end()) return it->second;
        return default_mode;
    }

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<prefs xmlns='urn:xmpp:mam:2'";
        const char* def = "roster";
        if (default_mode == archive_pref_mode::always) def = "always";
        else if (default_mode == archive_pref_mode::never) def = "never";
        oss << " default='" << def << "'>";
        for (const auto& [jid, mode] : jid_overrides) {
            const char* m = "roster";
            if (mode == archive_pref_mode::always) m = "always";
            else if (mode == archive_pref_mode::never) m = "never";
            oss << "<always jid='" << detail::xml_escape(jid) << "'/>";
            // We only store "always" overrides as exceptions
        }
        oss << "</prefs>";
        return oss.str();
    }
};

// =========================================================================
// Entity Capability cache (XEP-0115)
// =========================================================================

struct caps_entry {
    std::string ver;                         // Verification string (hash)
    std::string hash_algo;                   // Hash algorithm
    std::string node;                        // Node URI
    std::vector<std::string> features;       // Supported feature list
    std::vector<std::string> identities;     // Identity tuples (category/type/name)
    int64_t cached_at;

    caps_entry() : cached_at(0) {}
};

// =========================================================================
// vCard / Avatar structures (XEP-0054, XEP-0153)
// =========================================================================

struct vcard_info {
    std::string jid;
    std::string full_name;
    std::string nickname;
    std::string email;
    std::string avatar_mime_type;
    std::string avatar_data;      // Base64 encoded avatar binary
    std::string avatar_hash;      // SHA1 of avatar binary
    std::string photo_url;        // URL for photo (XEP-0153)
    int64_t updated_at;

    vcard_info() : updated_at(0) {}

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<vCard xmlns='vcard-temp'>";
        if (!full_name.empty()) {
            oss << "<FN>" << detail::xml_escape(full_name) << "</FN>";
        }
        if (!nickname.empty()) {
            oss << "<NICKNAME>" << detail::xml_escape(nickname) << "</NICKNAME>";
        }
        if (!email.empty()) {
            oss << "<EMAIL><USERID>" << detail::xml_escape(email) << "</USERID></EMAIL>";
        }
        if (!avatar_data.empty()) {
            oss << "<PHOTO>";
            if (!avatar_mime_type.empty()) {
                oss << "<TYPE>" << detail::xml_escape(avatar_mime_type) << "</TYPE>";
            }
            oss << "<BINVAL>" << detail::xml_escape(avatar_data) << "</BINVAL>";
            oss << "</PHOTO>";
        }
        oss << "</vCard>";
        return oss.str();
    }
};

// =========================================================================
// Message Processing Pipeline: Hook types and pipeline manager
// =========================================================================

using inbound_hook = std::function<bool(xmpp_message&)>;
using outbound_hook = std::function<bool(xmpp_message&)>;
using presence_hook = std::function<bool(const presence_info&)>;
using roster_hook = std::function<bool(const roster_item&)>;

struct pipeline_hooks {
    // Inbound: called when receiving a stanza from the network
    // Return false to drop the stanza
    std::vector<inbound_hook> inbound_hooks;

    // Outbound: called before sending a stanza to the network
    // Return false to drop the stanza
    std::vector<outbound_hook> outbound_hooks;

    // Presence: called when presence is received
    std::vector<presence_hook> presence_hooks;

    // Roster: called when roster item changes
    std::vector<roster_hook> roster_hooks;

    // Pre-routing hooks (before stanza is delivered to a resource)
    std::vector<inbound_hook> pre_routing_hooks;

    // Post-routing hooks (after stanza is delivered)
    std::vector<outbound_hook> post_routing_hooks;

    // Carbon hooks (before carbon copies are generated)
    std::vector<inbound_hook> carbon_hooks;

    // MAM hooks (before message is archived)
    std::vector<inbound_hook> mam_hooks;

    // Archive preferences hooks
    std::vector<inbound_hook> archive_pref_hooks;

    void clear() {
        inbound_hooks.clear();
        outbound_hooks.clear();
        presence_hooks.clear();
        roster_hooks.clear();
        pre_routing_hooks.clear();
        post_routing_hooks.clear();
        carbon_hooks.clear();
        mam_hooks.clear();
        archive_pref_hooks.clear();
    }
};

// =========================================================================
// Core Roster, Presence, and Message Router Class
// =========================================================================

class xmpp_roster_presence_router {
public:
    xmpp_roster_presence_router() = default;
    ~xmpp_roster_presence_router() = default;

    // =========================================================================
    // Initialization
    // =========================================================================

    void initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        // Roster versions are generated per-user on demand
        // via bump_roster_version() and get_roster_version()
    }

    // =========================================================================
    // Roster Management (XEP-0237 Roster Versioning)
    // =========================================================================

    /**
     * Get the full roster for a user, optionally with versioning.
     * If client_version is empty or different from server version, return full roster
     * and the new version. If versions match, return empty (no changes, XEP-0237).
     */
    std::string build_roster_iq_result(
        const std::string& bare_jid,
        const std::string& id,
        const std::string& client_version)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string current_ver = get_roster_version(bare_jid);

        std::ostringstream oss;
        if (!client_version.empty() && client_version == current_ver) {
            // No changes - return empty query result with version
            oss << "<iq type='result' id='" << detail::xml_escape(id) << "'"
                << " from='" << detail::xml_escape(bare_jid) << "'>"
                << "<query xmlns='jabber:iq:roster' ver='"
                << detail::xml_escape(current_ver) << "'/>"
                << "</iq>";
            return oss.str();
        }

        oss << "<iq type='result' id='" << detail::xml_escape(id) << "'"
            << " from='" << detail::xml_escape(bare_jid) << "'>"
            << "<query xmlns='jabber:iq:roster' ver='"
            << detail::xml_escape(current_ver) << "'>";

        auto& items = get_user_roster_unsafe(bare_jid);
        for (const auto& [contact_jid, item] : items) {
            if (item.subscription == subscription_state::remove) continue;
            oss << item.to_xml();
        }

        oss << "</query></iq>";
        return oss.str();
    }

    /**
     * Handle a roster set IQ - add/update/remove a roster item.
     * Returns the IQ result stanza.
     */
    std::string handle_roster_set(
        const std::string& bare_jid,
        const std::string& id,
        const std::string& contact_jid,
        const std::string& name,
        const std::vector<std::string>& groups)
    {
        if (contact_jid.empty()) {
            return make_iq_error(id, bare_jid, "modify", "bad-request",
                "Missing jid attribute");
        }

        std::lock_guard<std::mutex> lock(mutex_);

        auto& items = get_user_roster_unsafe(bare_jid);
        auto it = items.find(contact_jid);
        bool is_new = (it == items.end());

        roster_item item;
        if (!is_new) {
            item = it->second;
        } else {
            item.jid = contact_jid;
        }

        // Update fields
        if (!name.empty()) {
            item.name = name;
        }
        if (!groups.empty()) {
            item.groups = groups;
        }

        items[contact_jid] = item;

        // Bump roster version
        bump_roster_version(bare_jid);

        // Push roster update to all connected resources
        push_roster_update(bare_jid, item);

        // Build result
        std::ostringstream oss;
        oss << "<iq type='result' id='" << detail::xml_escape(id) << "'"
            << " from='" << detail::xml_escape(bare_jid) << "'>"
            << "<query xmlns='jabber:iq:roster' ver='"
            << detail::xml_escape(get_roster_version(bare_jid)) << "'/>"
            << "</iq>";
        return oss.str();
    }

    /**
     * Handle roster remove IQ.
     */
    std::string handle_roster_remove(
        const std::string& bare_jid,
        const std::string& id,
        const std::string& contact_jid)
    {
        if (contact_jid.empty()) {
            return make_iq_error(id, bare_jid, "modify", "bad-request",
                "Missing jid attribute");
        }

        std::lock_guard<std::mutex> lock(mutex_);

        auto& items = get_user_roster_unsafe(bare_jid);
        auto it = items.find(contact_jid);

        if (it == items.end()) {
            return make_iq_error(id, bare_jid, "modify", "item-not-found",
                "Contact not in roster");
        }

        roster_item removed = it->second;
        removed.subscription = subscription_state::remove;

        // Push roster removal as a push (subscription="remove")
        items.erase(it);
        bump_roster_version(bare_jid);

        // Send removal push
        push_roster_update(bare_jid, removed);

        // Also send unsubscribe presence to the removed contact
        send_presence_unsubscribe(bare_jid, contact_jid);

        // Cancel any pending subscriptions
        cancel_subscription(bare_jid, contact_jid);

        std::ostringstream oss;
        oss << "<iq type='result' id='" << detail::xml_escape(id) << "'"
            << " from='" << detail::xml_escape(bare_jid) << "'>"
            << "<query xmlns='jabber:iq:roster' ver='"
            << detail::xml_escape(get_roster_version(bare_jid)) << "'/>"
            << "</iq>";
        return oss.str();
    }

    /**
     * Push a roster update to all connected resources of a user.
     */
    void push_roster_update(const std::string& bare_jid, const roster_item& item) {
        std::ostringstream oss;
        oss << "<iq type='set' id='push-" << detail::generate_id() << "'"
            << " to='" << detail::xml_escape(bare_jid) << "'>"
            << "<query xmlns='jabber:iq:roster' ver='"
            << detail::xml_escape(get_roster_version(bare_jid)) << "'>"
            << item.to_xml()
            << "</query></iq>";

        std::string stanza = oss.str();
        route_to_all_resources(bare_jid, stanza);
    }

    /**
     * Get a specific roster item for a user.
     */
    std::optional<roster_item> get_roster_item(
        const std::string& bare_jid,
        const std::string& contact_jid)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& items = get_user_roster_unsafe(bare_jid);
        auto it = items.find(contact_jid);
        if (it != items.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * Get all roster items for a user.
     */
    std::vector<roster_item> get_all_roster_items(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<roster_item> result;
        auto& items = get_user_roster_unsafe(bare_jid);
        for (const auto& [jid, item] : items) {
            if (item.subscription != subscription_state::remove) {
                result.push_back(item);
            }
        }
        return result;
    }

    /**
     * Check if two JIDs have a mutual subscription.
     */
    bool has_mutual_subscription(const std::string& bare_jid_a,
                                  const std::string& bare_jid_b) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& items_a = get_user_roster_unsafe(bare_jid_a);
        auto it_a = items_a.find(bare_jid_b);
        if (it_a == items_a.end()) return false;
        if (it_a->second.subscription != subscription_state::both &&
            it_a->second.subscription != subscription_state::from) {
            return false;
        }
        auto& items_b = get_user_roster_unsafe(bare_jid_b);
        auto it_b = items_b.find(bare_jid_a);
        if (it_b == items_b.end()) return false;
        if (it_b->second.subscription != subscription_state::both &&
            it_b->second.subscription != subscription_state::from) {
            return false;
        }
        return true;
    }

    /**
     * Get all JIDs that are subscribed to this user's presence.
     */
    std::vector<std::string> get_subscribers(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> result;
        auto& items = get_user_roster_unsafe(bare_jid);
        for (const auto& [contact, item] : items) {
            if (item.subscription == subscription_state::from ||
                item.subscription == subscription_state::both) {
                result.push_back(contact);
            }
        }
        return result;
    }

    /**
     * Get the roster version for a user.
     */
    std::string get_roster_version(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = roster_versions_.find(bare_jid);
        if (it != roster_versions_.end()) {
            return it->second;
        }
        return "0";
    }

    // =========================================================================
    // Presence Subscription Handling
    // =========================================================================

    /**
     * Handle incoming presence subscribe request from from_jid to to_jid.
     */
    std::string handle_presence_subscribe(
        const std::string& from_bare,
        const std::string& to_bare)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // Check if already in roster
        auto& items = get_user_roster_unsafe(to_bare);
        auto it = items.find(from_bare);

        if (it != items.end()) {
            subscription_state current = it->second.subscription;
            if (current == subscription_state::both ||
                current == subscription_state::from) {
                // Already subscribed - auto-reply with subscribed
                return build_presence_stanza("subscribed", from_bare, to_bare);
            }
            // Update ask status
            if (current == subscription_state::to || current == subscription_state::none) {
                it->second.ask = "subscribe";
            }
        } else {
            // Add pending contact
            roster_item item;
            item.jid = from_bare;
            item.subscription = subscription_state::none;
            item.ask = "subscribe";
            items[from_bare] = item;
        }

        bump_roster_version(to_bare);

        // Forward the subscribe to all connected resources
        std::string stanza = build_presence_stanza("subscribe", from_bare, to_bare);
        route_to_all_resources(to_bare, stanza);

        return ""; // Presence is handled, no response needed from router directly
    }

    /**
     * Handle incoming presence subscribed response.
     */
    std::string handle_presence_subscribed(
        const std::string& from_bare,
        const std::string& to_bare)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto& items = get_user_roster_unsafe(to_bare);
        auto it = items.find(from_bare);

        if (it != items.end()) {
            subscription_state current = it->second.subscription;
            if (current == subscription_state::none) {
                it->second.subscription = subscription_state::to;
            } else if (current == subscription_state::from) {
                it->second.subscription = subscription_state::both;
            }
            it->second.ask.clear();
            bump_roster_version(to_bare);
        }

        std::string stanza = build_presence_stanza("subscribed", from_bare, to_bare);
        route_to_all_resources(to_bare, stanza);

        return "";
    }

    /**
     * Handle incoming presence unsubscribe.
     */
    std::string handle_presence_unsubscribe(
        const std::string& from_bare,
        const std::string& to_bare)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto& items = get_user_roster_unsafe(to_bare);
        auto it = items.find(from_bare);

        if (it != items.end()) {
            subscription_state current = it->second.subscription;
            if (current == subscription_state::both) {
                it->second.subscription = subscription_state::from;
            } else if (current == subscription_state::to) {
                it->second.subscription = subscription_state::none;
            }
            it->second.ask.clear();
            bump_roster_version(to_bare);
        }

        // Forward
        std::string stanza = build_presence_stanza("unsubscribe", from_bare, to_bare);
        route_to_all_resources(to_bare, stanza);

        return "";
    }

    /**
     * Handle incoming presence unsubscribed.
     */
    std::string handle_presence_unsubscribed(
        const std::string& from_bare,
        const std::string& to_bare)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto& items = get_user_roster_unsafe(to_bare);
        auto it = items.find(from_bare);

        if (it != items.end()) {
            subscription_state current = it->second.subscription;
            if (current == subscription_state::both) {
                it->second.subscription = subscription_state::to;
            } else if (current == subscription_state::from) {
                it->second.subscription = subscription_state::none;
            }
            it->second.ask.clear();
            bump_roster_version(to_bare);
        }

        std::string stanza = build_presence_stanza("unsubscribed", from_bare, to_bare);
        route_to_all_resources(to_bare, stanza);

        return "";
    }

    /**
     * Handle a pre-approval for a subscription (XEP-0379).
     */
    void pre_approve_subscription(const std::string& bare_jid,
                                   const std::string& contact_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& items = get_user_roster_unsafe(bare_jid);
        auto it = items.find(contact_jid);
        if (it != items.end()) {
            it->second.approved = true;
        } else {
            roster_item item;
            item.jid = contact_jid;
            item.subscription = subscription_state::none;
            item.approved = true;
            items[contact_jid] = item;
        }
        bump_roster_version(bare_jid);
    }

    /**
     * Send unsubscribe presence from user to contact.
     */
    void send_presence_unsubscribe(const std::string& from_bare,
                                    const std::string& to_bare) {
        std::string stanza = build_presence_stanza("unsubscribe", from_bare, to_bare);
        queue_outbound_stanza(to_bare, stanza);
    }

    /**
     * Cancel a pending subscription between two parties.
     */
    void cancel_subscription(const std::string& bare_jid,
                              const std::string& contact_jid) {
        // Remove any pending ask
        auto& items = get_user_roster_unsafe(bare_jid);
        auto it = items.find(contact_jid);
        if (it != items.end()) {
            it->second.ask.clear();
            bump_roster_version(bare_jid);
        }
    }

    // =========================================================================
    // Presence Broadcast (online/offline/availability)
    // =========================================================================

    /**
     * Update a user's presence and broadcast to all subscribers.
     * Returns list of presence stanzas to send.
     */
    std::vector<std::string> update_presence(const presence_info& presence) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string bare = presence.bare_jid;
        std::string full = presence.jid;

        // Store presence
        auto& resource_presences = user_presences_[bare];
        bool was_online = is_user_online_unsafe(bare);

        if (presence.is_online()) {
            resource_presences[presence.resource] = presence;
        } else {
            resource_presences.erase(presence.resource);
            // Store as unavailable
            presence_info offline_presence = presence;
            offline_presence.show = presence_show::offline;
            resource_presences[presence.resource] = offline_presence;
        }

        bool is_now_online = is_user_online_unsafe(bare);

        // Broadcast to subscribers
        std::vector<std::string> stanzas;
        std::vector<std::string> subscribers = get_subscribers(bare);

        // If going from offline to online, send probe to all contacts
        if (!was_online && is_now_online) {
            send_probes_to_contacts(bare);
        }

        // Build presence broadcast
        for (const auto& subscriber : subscribers) {
            // For each resource of the subscriber
            std::string to_bare = subscriber;
            auto sub_it = user_presences_.find(to_bare);
            if (sub_it != user_presences_.end()) {
                for (const auto& [res, res_presence] : sub_it->second) {
                    if (res_presence.is_online()) {
                        std::string stanza;
                        if (presence.is_online()) {
                            stanza = presence.to_xml(
                                make_full_jid(to_bare, res));
                        } else if (!is_now_online) {
                            // Offline presence
                            stanza = build_offline_presence(
                                bare, make_full_jid(to_bare, res));
                        }
                        if (!stanza.empty()) {
                            stanzas.push_back(stanza);
                        }
                    }
                }
            }
        }

        // Also broadcast to the user's own resources
        for (const auto& [res, res_presence] : resource_presences) {
            if (res != presence.resource && res_presence.is_online()) {
                std::string stanza;
                if (presence.is_online()) {
                    stanza = presence.to_xml(make_full_jid(bare, res));
                } else {
                    stanza = build_offline_presence(
                        bare, make_full_jid(bare, res));
                }
                if (!stanza.empty()) {
                    stanzas.push_back(stanza);
                }
            }
        }

        return stanzas;
    }

    /**
     * Send probes to all contacts in the user's roster to discover their presence.
     */
    void send_probes_to_contacts(const std::string& bare_jid) {
        auto roster_items = get_all_roster_items(bare_jid);
        for (const auto& item : roster_items) {
            if (item.subscription == subscription_state::both ||
                item.subscription == subscription_state::to) {
                std::string probe = "<presence type='probe'"
                    " from='" + detail::xml_escape(bare_jid) + "'"
                    " to='" + detail::xml_escape(item.jid) + "'/>";
                queue_outbound_stanza(item.jid, probe);
            }
        }
    }

    /**
     * Handle a presence probe - respond with current presence.
     */
    std::vector<std::string> handle_probe(
        const std::string& from_bare,
        const std::string& to_bare)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // Check subscription: probe may only be answered if from is subscribed
        auto& items = get_user_roster_unsafe(to_bare);
        auto it = items.find(from_bare);
        if (it == items.end()) return {};
        if (it->second.subscription != subscription_state::both &&
            it->second.subscription != subscription_state::from) {
            return {};
        }

        std::vector<std::string> stanzas;
        auto pres_it = user_presences_.find(to_bare);
        if (pres_it != user_presences_.end()) {
            for (const auto& [res, pres] : pres_it->second) {
                if (pres.is_online()) {
                    stanzas.push_back(pres.to_xml(from_bare));
                }
            }
        }
        return stanzas;
    }

    /**
     * Get the highest priority online presence for a user.
     */
    std::optional<presence_info> get_highest_priority_presence(
        const std::string& bare_jid)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = user_presences_.find(bare_jid);
        if (it == user_presences_.end()) return std::nullopt;

        int best_priority = -129;
        const presence_info* best = nullptr;
        for (const auto& [res, pres] : it->second) {
            if (pres.is_online() && pres.priority > best_priority) {
                best_priority = pres.priority;
                best = &pres;
            }
        }
        if (best) return *best;
        return std::nullopt;
    }

    /**
     * Get all presence states for a user.
     */
    std::vector<presence_info> get_all_presences(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<presence_info> result;
        auto it = user_presences_.find(bare_jid);
        if (it != user_presences_.end()) {
            for (const auto& [res, pres] : it->second) {
                result.push_back(pres);
            }
        }
        return result;
    }

    /**
     * Check if a user has any online resources.
     */
    bool is_user_online(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        return is_user_online_unsafe(bare_jid);
    }

    /**
     * Broadcast offline presence and clean up all resources for a user.
     * Called on disconnect of the last resource.
     */
    std::vector<std::string> go_offline(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> stanzas;

        // Mark all resources as unavailable
        auto it = user_presences_.find(bare_jid);
        if (it != user_presences_.end()) {
            for (auto& [res, pres] : it->second) {
                pres.show = presence_show::offline;
            }
        }

        // Build unavailable presence for all subscribers
        std::vector<std::string> subscribers = get_subscribers(bare_jid);
        for (const auto& sub : subscribers) {
            auto sub_it = user_presences_.find(sub);
            if (sub_it != user_presences_.end()) {
                for (const auto& [res, pres] : sub_it->second) {
                    if (pres.is_online()) {
                        std::string stanza = build_offline_presence(
                            bare_jid, make_full_jid(sub, res));
                        stanzas.push_back(stanza);
                    }
                }
            }
        }

        // Remove all presences
        user_presences_.erase(bare_jid);

        return stanzas;
    }

    // =========================================================================
    // Last Activity (XEP-0012)
    // =========================================================================

    /**
     * Handle a last activity query for a JID.
     * Returns the IQ result stanza.
     */
    std::string handle_last_activity_query(
        const std::string& requester_bare,
        const std::string& target_bare,
        const std::string& id)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // Record this query for rate limiting / privacy
        last_activity_queries_[target_bare].push_back(time(nullptr));

        // Check if target is online
        auto pres_it = user_presences_.find(target_bare);
        bool is_online = (pres_it != user_presences_.end()) &&
                         is_user_online_unsafe(target_bare);

        int64_t last_activity = 0;
        std::string status_text;

        if (is_online) {
            // User is online - return 0 seconds (currently online)
            last_activity = 0;
        } else {
            // User is offline - return time since last activity
            last_activity = get_last_activity_time(target_bare);
            if (last_activity == 0) {
                last_activity = time(nullptr) - last_activity_recorded(target_bare);
            }
        }

        std::ostringstream oss;
        oss << "<iq type='result' id='" << detail::xml_escape(id) << "'"
            << " from='" << detail::xml_escape(target_bare) << "'"
            << " to='" << detail::xml_escape(requester_bare) << "'>"
            << "<query xmlns='jabber:iq:last' seconds='" << last_activity << "'";
        if (!status_text.empty()) {
            oss << ">" << detail::xml_escape(status_text) << "</query>";
        } else {
            oss << "/>";
        }
        oss << "</iq>";
        return oss.str();
    }

    /**
     * Record last activity for a user (called when they disconnect).
     * Also serves as "idle time" since last user activity.
     */
    void record_last_activity(const std::string& bare_jid, int64_t timestamp) {
        std::lock_guard<std::mutex> lock(mutex_);
        last_activity_times_[bare_jid] = timestamp;
    }

    /**
     * Update idle time (when user was last active).
     */
    void update_user_activity(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        last_activity_times_[bare_jid] = time(nullptr);
    }

    /**
     * Get the seconds since last activity for a user.
     */
    int64_t get_idle_seconds(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = last_activity_times_.find(bare_jid);
        if (it != last_activity_times_.end()) {
            return time(nullptr) - it->second;
        }
        return 0;
    }

    // =========================================================================
    // vCard-based Avatar (XEP-0054, XEP-0153)
    // =========================================================================

    /**
     * Store or update a vCard for a user.
     */
    void set_vcard(const vcard_info& vcard) {
        std::lock_guard<std::mutex> lock(mutex_);

        vcard_info stored = vcard;
        stored.updated_at = time(nullptr);

        // Compute avatar hash (SHA1 of binary data)
        if (!vcard.avatar_data.empty()) {
            std::string decoded = detail::base64_decode(vcard.avatar_data);
            detail::sha1 hasher;
            hasher.update(decoded);
            stored.avatar_hash = hasher.finalize();
        }

        vcards_[vcard.jid] = stored;

        // Update the avatar hash in all online presences (XEP-0153)
        auto pres_it = user_presences_.find(vcard.jid);
        if (pres_it != user_presences_.end()) {
            for (auto& [res, pres] : pres_it->second) {
                pres.avatar_hash = stored.avatar_hash;
            }
        }

        // Broadcast updated presence with new avatar hash
        rebroadcast_presence_with_avatar(vcard.jid, stored.avatar_hash);
    }

    /**
     * Get a vCard for a user.
     */
    std::optional<vcard_info> get_vcard(const std::string& jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = vcards_.find(jid);
        if (it != vcards_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * Build a vCard IQ result for a request.
     */
    std::string build_vcard_iq_result(
        const std::string& bare_jid,
        const std::string& request_id)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        std::ostringstream oss;
        auto vc = get_vcard(bare_jid);

        oss << "<iq type='result' id='" << detail::xml_escape(request_id) << "'"
            << " from='" << detail::xml_escape(bare_jid) << "'>";

        if (vc.has_value()) {
            oss << vc->to_xml();
        } else {
            oss << "<vCard xmlns='vcard-temp'/>";
        }

        oss << "</iq>";
        return oss.str();
    }

    /**
     * Handle avatar metadata update (XEP-0153).
     */
    void handle_avatar_metadata(const std::string& bare_jid,
                                 const std::string& sha1_hash) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Store the hash in all presences
        auto pres_it = user_presences_.find(bare_jid);
        if (pres_it != user_presences_.end()) {
            for (auto& [res, pres] : pres_it->second) {
                pres.avatar_hash = sha1_hash;
            }
        }

        // Broadcast updated presence
        rebroadcast_presence_with_avatar(bare_jid, sha1_hash);
    }

    /**
     * Get the avatar hash for a JID.
     */
    std::string get_avatar_hash(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        // First check vcard
        auto vc_it = vcards_.find(bare_jid);
        if (vc_it != vcards_.end() && !vc_it->second.avatar_hash.empty()) {
            return vc_it->second.avatar_hash;
        }
        // Then check presence
        auto pres_it = user_presences_.find(bare_jid);
        if (pres_it != user_presences_.end()) {
            for (const auto& [res, pres] : pres_it->second) {
                if (!pres.avatar_hash.empty()) {
                    return pres.avatar_hash;
                }
            }
        }
        return "";
    }

private:
    void rebroadcast_presence_with_avatar(const std::string& bare_jid,
                                           const std::string& avatar_hash) {
        auto pres_it = user_presences_.find(bare_jid);
        if (pres_it == user_presences_.end()) return;

        std::vector<std::string> subscribers = get_subscribers(bare_jid);
        for (const auto& sub : subscribers) {
            auto sub_it = user_presences_.find(sub);
            if (sub_it == user_presences_.end()) continue;
            for (const auto& [res, res_pres] : sub_it->second) {
                if (!res_pres.is_online()) continue;
                for (const auto& [src_res, src_pres] : pres_it->second) {
                    if (!src_pres.is_online()) continue;
                    presence_info updated = src_pres;
                    updated.avatar_hash = avatar_hash;
                    std::string stanza = updated.to_xml(
                        make_full_jid(sub, res));
                    queue_outbound_stanza(make_full_jid(sub, res), stanza);
                }
            }
        }
    }

public:
    // =========================================================================
    // Entity Capabilities (XEP-0115)
    // =========================================================================

    /**
     * Register entity capabilities for a user.
     * The caps hash ver is computed as SHA1 of the sorted features + identities.
     */
    void register_capabilities(
        const std::string& bare_jid,
        const std::string& node,
        const std::string& ver,
        const std::string& hash_algo,
        const std::vector<std::string>& features,
        const std::vector<std::string>& identities)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        caps_entry entry;
        entry.node = node;
        entry.ver = ver;
        entry.hash_algo = hash_algo;
        entry.features = features;
        entry.identities = identities;
        entry.cached_at = time(nullptr);

        caps_cache_[ver] = entry;

        // Update presence for this user with caps
        auto pres_it = user_presences_.find(bare_jid);
        if (pres_it != user_presences_.end()) {
            for (auto& [res, pres] : pres_it->second) {
                pres.caps_node = node;
                pres.caps_ver = ver;
                pres.caps_hash = hash_algo;
                pres.caps_features = features;
            }
        }
    }

    /**
     * Verify a caps hash against a set of features.
     */
    std::string compute_caps_hash(
        const std::string& node,
        const std::vector<std::string>& features,
        const std::vector<std::string>& identities)
    {
        // Sort all features and identities for deterministic hash
        std::vector<std::string> sorted_features = features;
        std::sort(sorted_features.begin(), sorted_features.end());
        std::vector<std::string> sorted_ids = identities;
        std::sort(sorted_ids.begin(), sorted_ids.end());

        // Build the verification string per XEP-0115
        std::ostringstream ver_input;
        ver_input << "node#" << node;
        for (const auto& id : sorted_ids) {
            ver_input << "<" << id << "<";
        }
        for (const auto& feat : sorted_features) {
            ver_input << feat << "<";
        }

        detail::sha1 hasher;
        hasher.update(ver_input.str());
        return hasher.finalize();
    }

    /**
     * Look up cached capabilities by verification string.
     */
    std::optional<caps_entry> lookup_capabilities(const std::string& ver) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = caps_cache_.find(ver);
        if (it != caps_cache_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * Check if a JID supports a specific feature.
     */
    bool jid_supports_feature(const std::string& bare_jid,
                               const std::string& feature_uri) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto pres_it = user_presences_.find(bare_jid);
        if (pres_it == user_presences_.end()) return false;

        for (const auto& [res, pres] : pres_it->second) {
            for (const auto& feat : pres.caps_features) {
                if (feat == feature_uri) return true;
            }
        }

        // Also check caps cache
        for (const auto& [res, pres] : pres_it->second) {
            auto caps_it = caps_cache_.find(pres.caps_ver);
            if (caps_it != caps_cache_.end()) {
                for (const auto& feat : caps_it->second.features) {
                    if (feat == feature_uri) return true;
                }
            }
        }

        return false;
    }

    /**
     * Get all features supported by a JID across all resources.
     */
    std::vector<std::string> get_jid_features(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> result;
        std::unordered_map<std::string, bool> seen;

        auto pres_it = user_presences_.find(bare_jid);
        if (pres_it == user_presences_.end()) return result;

        for (const auto& [res, pres] : pres_it->second) {
            for (const auto& feat : pres.caps_features) {
                if (seen.find(feat) == seen.end()) {
                    seen[feat] = true;
                    result.push_back(feat);
                }
            }
            // Also check caps cache
            auto caps_it = caps_cache_.find(pres.caps_ver);
            if (caps_it != caps_cache_.end()) {
                for (const auto& feat : caps_it->second.features) {
                    if (seen.find(feat) == seen.end()) {
                        seen[feat] = true;
                        result.push_back(feat);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Generate a disco#info response based on cached capabilities.
     */
    std::string build_disco_info_response(
        const std::string& from_jid,
        const std::string& to_jid,
        const std::string& id,
        const std::string& node)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        std::ostringstream oss;
        oss << "<iq type='result' id='" << detail::xml_escape(id) << "'"
            << " from='" << detail::xml_escape(from_jid) << "'"
            << " to='" << detail::xml_escape(to_jid) << "'>";

        // Check if node is a caps ver
        auto caps_it = caps_cache_.find(node);
        if (caps_it != caps_cache_.end()) {
            oss << "<query xmlns='http://jabber.org/protocol/disco#info'"
                << " node='" << detail::xml_escape(caps_it->second.node) << "#"
                << detail::xml_escape(caps_it->second.ver) << "'>";
            for (const auto& id : caps_it->second.identities) {
                oss << "<identity " << id << "/>";
            }
            for (const auto& feat : caps_it->second.features) {
                oss << "<feature var='" << detail::xml_escape(feat) << "'/>";
            }
            oss << "</query>";
        } else {
            oss << "<query xmlns='http://jabber.org/protocol/disco#info'/>";
        }

        oss << "</iq>";
        return oss.str();
    }

    // =========================================================================
    // Message Carbon Copies (XEP-0280)
    // =========================================================================

    /**
     * Enable carbons for a specific JID.
     */
    void enable_carbons(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        carbon_enabled_[bare_jid] = true;
    }

    /**
     * Disable carbons for a specific JID.
     */
    void disable_carbons(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        carbon_enabled_[bare_jid] = false;
    }

    /**
     * Check if carbons are enabled for a JID.
     */
    bool is_carbons_enabled(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = carbon_enabled_.find(bare_jid);
        if (it != carbon_enabled_.end()) return it->second;
        return false;
    }

    /**
     * Wrap a message as a carbon copy.
     * direction = "sent" (message was sent FROM this user)
     * direction = "received" (message was sent TO this user)
     */
    xmpp_message wrap_carbon(const xmpp_message& original,
                              const std::string& direction,
                              const std::string& carbon_target) {
        xmpp_message carbon;
        carbon.id = detail::generate_id();
        carbon.from = original.from;
        carbon.to = carbon_target;
        carbon.type = original.type;
        carbon.body = original.body;
        carbon.subject = original.subject;
        carbon.thread = original.thread;
        carbon.is_carbon = true;
        carbon.carbon_direction = direction;
        carbon.timestamp = original.timestamp.empty() ?
            detail::current_iso8601() : original.timestamp;

        // Copy over extensions that should appear in carbons
        carbon.extensions = original.extensions;
        carbon.request_receipt = false;  // Carbons don't request receipts
        carbon.chat_state_flag = chat_state::none;  // Chat states don't go in carbons

        return carbon;
    }

    /**
     * Generate carbon copies for an outbound message.
     * Sends a "sent" carbon to all other resources of the sender.
     */
    std::vector<xmpp_message> generate_sent_carbons(
        const xmpp_message& message,
        const std::string& sender_bare)
    {
        std::vector<xmpp_message> carbons;
        if (!is_carbons_enabled(sender_bare)) return carbons;

        auto resources = get_online_resources(sender_bare);
        for (const auto& res : resources) {
            std::string full_res = make_full_jid(sender_bare, res);
            if (full_res == message.from) continue; // Skip sender's resource

            xmpp_message carbon = wrap_carbon(message, "sent", full_res);
            carbons.push_back(carbon);
        }
        return carbons;
    }

    /**
     * Generate carbon copies for an inbound message.
     * Sends a "received" carbon to all other resources of the recipient.
     */
    std::vector<xmpp_message> generate_received_carbons(
        const xmpp_message& message,
        const std::string& recipient_bare)
    {
        std::vector<xmpp_message> carbons;
        if (!is_carbons_enabled(recipient_bare)) return carbons;

        auto resources = get_online_resources(recipient_bare);
        for (const auto& res : resources) {
            std::string full_res = make_full_jid(recipient_bare, res);
            if (full_res == message.to) continue; // Skip the target resource

            xmpp_message carbon = wrap_carbon(message, "received", full_res);
            carbons.push_back(carbon);
        }
        return carbons;
    }

    // =========================================================================
    // Chat Markers (XEP-0333)
    // =========================================================================

    /**
     * Create a chat marker message.
     */
    xmpp_message create_chat_marker(
        const std::string& from_full,
        const std::string& to_full,
        chat_marker marker_type,
        const std::string& marked_message_id)
    {
        xmpp_message marker;
        marker.id = detail::generate_id();
        marker.from = from_full;
        marker.to = to_full;
        marker.type = message_type::chat;
        marker.has_marker = true;
        marker.marker = marker_type;
        marker.marker_id = marked_message_id;
        return marker;
    }

    /**
     * Build a chat marker stanza XML.
     */
    std::string build_chat_marker_stanza(
        const std::string& from_full,
        const std::string& to_full,
        chat_marker marker_type,
        const std::string& marked_message_id)
    {
        auto msg = create_chat_marker(from_full, to_full, marker_type,
                                       marked_message_id);
        return msg.to_xml();
    }

    /**
     * Handle an incoming chat marker.
     * Returns true if the marker was processed successfully.
     */
    bool handle_chat_marker(
        const std::string& from_full,
        const std::string& to_bare,
        chat_marker marker_type,
        const std::string& marked_message_id)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // Record the marker for tracking
        chat_marker_record rec;
        rec.from = from_full;
        rec.marker_type = marker_type;
        rec.marked_id = marked_message_id;
        rec.timestamp = time(nullptr);
        chat_markers_[marked_message_id].push_back(rec);

        // Update the marker state for this message
        auto& state = marker_states_[marked_message_id];
        switch (marker_type) {
            case chat_marker::received:
                state.received = true;
                break;
            case chat_marker::displayed:
                state.displayed = true;
                break;
            case chat_marker::acknowledged:
                state.acknowledged = true;
                break;
        }

        // Forward the marker to the original sender
        auto msg_it = sent_messages_.find(marked_message_id);
        if (msg_it != sent_messages_.end()) {
            std::string original_from = msg_it->second;
            // Route marker to original sender
            std::string marker_xml = build_chat_marker_stanza(
                from_full, original_from, marker_type, marked_message_id);
            route_stanza(original_from, marker_xml);
        }

        return true;
    }

    /**
     * Get marker status for a specific message ID.
     */
    struct marker_status {
        bool received = false;
        bool displayed = false;
        bool acknowledged = false;
    };

    marker_status get_marker_status(const std::string& message_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = marker_states_.find(message_id);
        if (it != marker_states_.end()) {
            return it->second;
        }
        return marker_status{};
    }

    // =========================================================================
    // Chat State Notifications (XEP-0085)
    // =========================================================================

    /**
     * Build a chat state notification stanza.
     */
    std::string build_chat_state_stanza(
        const std::string& from_full,
        const std::string& to_full,
        chat_state state,
        const std::string& thread_id)
    {
        std::ostringstream oss;
        oss << "<message from='" << detail::xml_escape(from_full) << "'"
            << " to='" << detail::xml_escape(to_full) << "'"
            << " type='chat'";
        if (!thread_id.empty()) {
            // We may add id for tracking
        }
        oss << ">";

        // Chat state
        const char* state_str = chat_state_string(state);
        if (state_str && state_str[0] != '\0') {
            oss << "<" << state_str
                << " xmlns='http://jabber.org/protocol/chatstates'/>";
        }

        if (!thread_id.empty()) {
            oss << "<thread>" << detail::xml_escape(thread_id) << "</thread>";
        }

        oss << "</message>";
        return oss.str();
    }

    /**
     * Handle an incoming chat state notification.
     * Updates the chat state for the conversation and forwards to appropriate resource.
     */
    void handle_chat_state(
        const std::string& from_bare,
        const std::string& to_bare,
        const std::string& from_full,
        chat_state state,
        const std::string& thread_id)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // Store chat state for this conversation
        std::string conv_key = from_bare + "|" + to_bare;
        chat_states_[conv_key] = state;

        // Determine the conversation peer (the other party)
        std::string peer = (from_bare == to_bare) ? to_bare : from_bare;

        // Build notification to forward
        if (state != chat_state::none) {
            std::string stanza = build_chat_state_stanza(
                from_full, to_bare, state, thread_id);

            // Route to most available resource of the recipient
            auto best_presence = get_highest_priority_presence(to_bare);
            if (best_presence.has_value()) {
                route_stanza(best_presence->jid, stanza);
            }
        }
    }

    /**
     * Get the current chat state for a conversation.
     */
    chat_state get_chat_state(const std::string& bare_a,
                               const std::string& bare_b) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = bare_a + "|" + bare_b;
        auto it = chat_states_.find(key);
        if (it != chat_states_.end()) {
            return it->second;
        }
        key = bare_b + "|" + bare_a;
        it = chat_states_.find(key);
        if (it != chat_states_.end()) {
            return it->second;
        }
        return chat_state::none;
    }

    /**
     * Send a "gone" chat state when conversation ends.
     */
    void end_chat_state_session(const std::string& from_full,
                                 const std::string& to_full,
                                 const std::string& thread_id) {
        std::string stanza = build_chat_state_stanza(
            from_full, to_full, chat_state::gone, thread_id);
        route_stanza(to_full, stanza);

        std::lock_guard<std::mutex> lock(mutex_);
        std::string from_bare = bare_jid(from_full);
        std::string to_bare = bare_jid(to_full);
        std::string key = from_bare + "|" + to_bare;
        chat_states_[key] = chat_state::gone;
    }

    // =========================================================================
    // Message Delivery Receipts (XEP-0184)
    // =========================================================================

    /**
     * Build a delivery receipt stanza.
     */
    std::string build_delivery_receipt(
        const std::string& from_full,
        const std::string& to_full,
        const std::string& receipt_for_id)
    {
        xmpp_message msg;
        msg.id = detail::generate_id();
        msg.from = from_full;
        msg.to = to_full;
        msg.type = message_type::chat;
        msg.receipt_id = receipt_for_id;
        return msg.to_xml();
    }

    /**
     * Handle an incoming delivery receipt.
     */
    void handle_delivery_receipt(
        const std::string& from_full,
        const std::string& to_bare,
        const std::string& receipt_id)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // Record the receipt
        delivery_receipts_[receipt_id] = {
            from_full,
            receipt_id,
            time(nullptr)
        };

        // Forward to the original sender
        auto it = sent_messages_.find(receipt_id);
        if (it != sent_messages_.end()) {
            std::string original_sender = it->second;
            std::string receipt_xml = build_delivery_receipt(
                from_full, original_sender, receipt_id);
            route_stanza(original_sender, receipt_xml);
        }
    }

    /**
     * Track a sent message for later receipt tracking.
     */
    void track_sent_message(const std::string& message_id,
                             const std::string& sender_full) {
        std::lock_guard<std::mutex> lock(mutex_);
        sent_messages_[message_id] = sender_full;
    }

    /**
     * Check if a delivery receipt has been received for a message.
     */
    bool has_delivery_receipt(const std::string& message_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return delivery_receipts_.find(message_id) != delivery_receipts_.end();
    }

    struct receipt_info {
        std::string from;
        std::string receipt_id;
        int64_t timestamp;
    };

    std::optional<receipt_info> get_receipt_info(const std::string& message_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = delivery_receipts_.find(message_id);
        if (it != delivery_receipts_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // =========================================================================
    // Message Archive Preferences (XEP-0313)
    // =========================================================================

    /**
     * Set archive preferences for a user.
     */
    void set_archive_preferences(const std::string& bare_jid,
                                  const archive_preferences& prefs) {
        std::lock_guard<std::mutex> lock(mutex_);
        archive_prefs_[bare_jid] = prefs;
    }

    /**
     * Get archive preferences for a user.
     */
    archive_preferences get_archive_preferences(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = archive_prefs_.find(bare_jid);
        if (it != archive_prefs_.end()) {
            return it->second;
        }
        return archive_preferences{};
    }

    /**
     * Build archive preferences IQ result.
     */
    std::string build_archive_prefs_iq_result(
        const std::string& bare_jid,
        const std::string& id)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto prefs = get_archive_preferences(bare_jid);

        std::ostringstream oss;
        oss << "<iq type='result' id='" << detail::xml_escape(id) << "'"
            << " from='" << detail::xml_escape(bare_jid) << "'>"
            << prefs.to_xml()
            << "</iq>";
        return oss.str();
    }

    /**
     * Determine whether a message should be archived.
     */
    bool should_archive_message(const xmpp_message& msg) {
        if (msg.no_permanent_store) return false;
        if (msg.store_hint == "no-store") return false;
        if (msg.store_hint == "no-storage") return false;

        std::string bare_from = bare_jid(msg.from);
        std::string bare_to = bare_jid(msg.to);

        // Check sender preferences
        archive_preferences sender_prefs = get_archive_preferences(bare_from);
        if (!sender_prefs.should_archive(bare_from, bare_to)) return false;

        // Check recipient preferences
        archive_preferences recip_prefs = get_archive_preferences(bare_to);
        if (!recip_prefs.should_archive(bare_from, bare_to)) return false;

        return true;
    }

    /**
     * Update a JID-specific archive override.
     */
    void set_archive_jid_override(const std::string& bare_jid,
                                   const std::string& contact_jid,
                                   archive_pref_mode mode) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& prefs = archive_prefs_[bare_jid];
        if (mode == archive_pref_mode::roster) {
            prefs.jid_overrides.erase(contact_jid);
        } else {
            prefs.jid_overrides[contact_jid] = mode;
        }
    }

    // =========================================================================
    // Stream Resumption (XEP-0198 Stream Management)
    // =========================================================================

    /**
     * Create a new stream resumption entry.
     */
    stream_resumption_entry create_stream_session(
        const std::string& bare_jid,
        const std::string& prev_id,
        const std::string& prev_location)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        stream_resumption_entry entry;
        entry.id = detail::generate_id();
        entry.bare_jid = bare_jid;
        entry.h_handled = 0;
        entry.h_sent = 0;
        entry.created_at = time(nullptr);
        entry.max_age = 300; // 5 minutes default
        entry.previous_id = prev_id;
        entry.prev_location = prev_location;

        stream_sessions_[entry.id] = entry;

        return entry;
    }

    /**
     * Try to resume a stream session.
     * Returns the previous stream ID and h value if successful.
     */
    struct resume_result {
        bool success;
        std::string prev_id;
        uint64_t h_handled;
        uint64_t h_sent;
        std::vector<std::string> unacked_stanzas;
    };

    resume_result try_resume_stream(
        const std::string& prev_id,
        uint64_t client_h)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        resume_result result;
        result.success = false;
        result.prev_id = prev_id;
        result.h_handled = 0;
        result.h_sent = 0;

        auto it = stream_sessions_.find(prev_id);
        if (it == stream_sessions_.end()) {
            return result;
        }

        stream_resumption_entry& session = it->second;

        if (session.is_expired()) {
            stream_sessions_.erase(it);
            return result;
        }

        // Verify client h matches
        if (client_h != session.h_handled) {
            // Client might have missed some, but we accept if close enough
            // For simplicity, require exact match
            return result;
        }

        result.success = true;
        result.h_handled = session.h_handled;
        result.h_sent = session.h_sent;

        // Collect unacked stanzas to resend
        while (!session.unacked_stanzas.empty()) {
            result.unacked_stanzas.push_back(session.unacked_stanzas.front());
            session.unacked_stanzas.pop();
        }

        // Update the session with new ID
        std::string new_id = detail::generate_id();
        session.id = new_id;

        // Remove old entry, add new
        stream_sessions_.erase(it);
        stream_sessions_[new_id] = session;

        result.prev_id = new_id;

        return result;
    }

    /**
     * Increment the handled stanza counter for a stream.
     */
    void increment_handled(const std::string& stream_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stream_sessions_.find(stream_id);
        if (it != stream_sessions_.end()) {
            it->second.h_handled++;
        }
    }

    /**
     * Increment the sent stanza counter and optionally queue for resumption.
     */
    void increment_sent(const std::string& stream_id, const std::string& stanza) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stream_sessions_.find(stream_id);
        if (it != stream_sessions_.end()) {
            it->second.h_sent++;
            // Queue stanza for possible replay
            if (it->second.unacked_stanzas.size() < 1000) {
                it->second.unacked_stanzas.push(stanza);
            }
        }
    }

    /**
     * Acknowledge stanzas (client acked up to h).
     */
    void ack_stanzas(const std::string& stream_id, uint64_t h) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stream_sessions_.find(stream_id);
        if (it != stream_sessions_.end()) {
            // Remove stanzas that have been acked
            uint64_t to_remove = h - it->second.h_handled;
            while (to_remove > 0 && !it->second.unacked_stanzas.empty()) {
                it->second.unacked_stanzas.pop();
                to_remove--;
            }
            it->second.h_handled = h;
        }
    }

    /**
     * End a stream session (clean disconnect).
     */
    void end_stream_session(const std::string& stream_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        stream_sessions_.erase(stream_id);
    }

    /**
     * Get current h values for a stream.
     */
    struct sm_counts {
        uint64_t h_handled;
        uint64_t h_sent;
    };

    std::optional<sm_counts> get_stream_counts(const std::string& stream_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stream_sessions_.find(stream_id);
        if (it != stream_sessions_.end()) {
            return sm_counts{it->second.h_handled, it->second.h_sent};
        }
        return std::nullopt;
    }

    /**
     * Check if a stream session exists for resumption.
     */
    bool has_stream_session(const std::string& stream_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stream_sessions_.find(stream_id);
        if (it != stream_sessions_.end()) {
            return !it->second.is_expired();
        }
        return false;
    }

    // =========================================================================
    // Message Processing Pipeline (inbound/outbound hooks)
    // =========================================================================

    /**
     * Register an inbound hook.
     */
    void register_inbound_hook(inbound_hook hook) {
        std::lock_guard<std::mutex> lock(mutex_);
        pipeline_.inbound_hooks.push_back(std::move(hook));
    }

    /**
     * Register an outbound hook.
     */
    void register_outbound_hook(outbound_hook hook) {
        std::lock_guard<std::mutex> lock(mutex_);
        pipeline_.outbound_hooks.push_back(std::move(hook));
    }

    /**
     * Register a presence hook.
     */
    void register_presence_hook(presence_hook hook) {
        std::lock_guard<std::mutex> lock(mutex_);
        pipeline_.presence_hooks.push_back(std::move(hook));
    }

    /**
     * Register a roster hook.
     */
    void register_roster_hook(roster_hook hook) {
        std::lock_guard<std::mutex> lock(mutex_);
        pipeline_.roster_hooks.push_back(std::move(hook));
    }

    /**
     * Register a pre-routing hook.
     */
    void register_pre_routing_hook(inbound_hook hook) {
        std::lock_guard<std::mutex> lock(mutex_);
        pipeline_.pre_routing_hooks.push_back(std::move(hook));
    }

    /**
     * Register a post-routing hook.
     */
    void register_post_routing_hook(outbound_hook hook) {
        std::lock_guard<std::mutex> lock(mutex_);
        pipeline_.post_routing_hooks.push_back(std::move(hook));
    }

    /**
     * Register a carbon hook.
     */
    void register_carbon_hook(inbound_hook hook) {
        std::lock_guard<std::mutex> lock(mutex_);
        pipeline_.carbon_hooks.push_back(std::move(hook));
    }

    /**
     * Register a MAM hook.
     */
    void register_mam_hook(inbound_hook hook) {
        std::lock_guard<std::mutex> lock(mutex_);
        pipeline_.mam_hooks.push_back(std::move(hook));
    }

    /**
     * Process a message through the inbound pipeline.
     * Returns true if the message should continue processing, false to drop.
     */
    bool process_inbound(xmpp_message& msg) {
        std::lock_guard<std::mutex> lock(mutex_);

        for (auto& hook : pipeline_.inbound_hooks) {
            if (!hook(msg)) return false;
        }
        for (auto& hook : pipeline_.mam_hooks) {
            if (!hook(msg)) return false;
        }
        for (auto& hook : pipeline_.archive_pref_hooks) {
            if (!hook(msg)) return false;
        }
        for (auto& hook : pipeline_.pre_routing_hooks) {
            if (!hook(msg)) return false;
        }
        return true;
    }

    /**
     * Process a message through the outbound pipeline.
     * Returns true if the message should be sent, false to drop.
     */
    bool process_outbound(xmpp_message& msg) {
        std::lock_guard<std::mutex> lock(mutex_);

        for (auto& hook : pipeline_.outbound_hooks) {
            if (!hook(msg)) return false;
        }
        for (auto& hook : pipeline_.carbon_hooks) {
            if (!hook(msg)) return false;
        }
        for (auto& hook : pipeline_.post_routing_hooks) {
            if (!hook(msg)) return false;
        }
        return true;
    }

    /**
     * Process presence through hooks.
     */
    bool process_presence(const presence_info& pres) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& hook : pipeline_.presence_hooks) {
            if (!hook(pres)) return false;
        }
        return true;
    }

    /**
     * Process roster item through hooks.
     */
    bool process_roster(const roster_item& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& hook : pipeline_.roster_hooks) {
            if (!hook(item)) return false;
        }
        return true;
    }

    /**
     * Clear all pipeline hooks.
     */
    void clear_pipeline() {
        std::lock_guard<std::mutex> lock(mutex_);
        pipeline_.clear();
    }

    /**
     * Full message routing: receive, process, route.
     * This is the main message processing entry point.
     *
     * Returns a vector of (target_full_jid, stanza_xml) tuples for the caller
     * to deliver to the transport layer.
     */
    struct route_entry {
        std::string target_full_jid;
        std::string stanza_xml;
    };

    std::vector<route_entry> route_message(const xmpp_message& msg) {
        std::vector<route_entry> results;

        // Make a mutable copy
        xmpp_message message = msg;

        // Run inbound pipeline
        if (!process_inbound(message)) {
            return results;  // Message dropped by pipeline
        }

        // If message has no ID, generate one
        if (message.id.empty()) {
            message.id = detail::generate_id();
        }

        // Track for delivery receipts if requested
        if (message.request_receipt) {
            track_sent_message(message.id, message.from);
        }

        // Determine routing target
        std::string bare_to = bare_jid(message.to);

        // Check if message should be archived
        bool do_archive = should_archive_message(message);

        // Get target resources
        auto resources = get_online_resources(bare_to);
        if (resources.empty()) {
            // User is offline - may store for later delivery (offline messages)
            // In a full implementation, this would queue to offline storage
            // For now, we record this fact
            record_offline_message(message);
        } else {
            for (const auto& res : resources) {
                route_entry entry;
                entry.target_full_jid = make_full_jid(bare_to, res);
                entry.stanza_xml = message.to_xml();
                results.push_back(entry);
            }
        }

        // Generate carbon copies
        std::string bare_from = bare_jid(message.from);

        // Sent carbons: notify other resources of the sender
        auto sent_carbons = generate_sent_carbons(message, bare_from);
        for (const auto& carbon : sent_carbons) {
            route_entry entry;
            entry.target_full_jid = carbon.to;
            entry.stanza_xml = carbon.to_xml();
            results.push_back(entry);
        }

        // Received carbons: notify other resources of the recipient
        auto received_carbons = generate_received_carbons(message, bare_to);
        for (const auto& carbon : received_carbons) {
            route_entry entry;
            entry.target_full_jid = carbon.to;
            entry.stanza_xml = carbon.to_xml();
            results.push_back(entry);
        }

        // Run outbound pipeline on the final stanzas
        // (simplified: we run on the original, but in production each would be checked)
        for (auto& entry : results) {
            xmpp_message out_msg = message;
            out_msg.to = entry.target_full_jid;
            if (!process_outbound(out_msg)) {
                // Mark for removal
                entry.target_full_jid.clear();
            } else {
                entry.stanza_xml = out_msg.to_xml();
            }
        }

        // Remove dropped entries
        results.erase(std::remove_if(results.begin(), results.end(),
            [](const route_entry& e) { return e.target_full_jid.empty(); }),
            results.end());

        return results;
    }

    /**
     * Route a raw XML stanza to a specific full JID / bare JID.
     */
    void route_stanza(const std::string& target_jid, const std::string& stanza_xml) {
        std::lock_guard<std::mutex> lock(outbound_mutex_);
        outbound_queue_.push_back({target_jid, stanza_xml});
    }

    /**
     * Route a stanza to all online resources of a bare JID.
     */
    void route_to_all_resources(const std::string& bare_jid,
                                 const std::string& stanza_xml) {
        auto resources = get_online_resources(bare_jid);
        for (const auto& res : resources) {
            route_stanza(make_full_jid(bare_jid, res), stanza_xml);
        }
    }

    /**
     * Route a stanza to the highest priority resource.
     */
    void route_to_best_resource(const std::string& bare_jid,
                                 const std::string& stanza_xml) {
        auto best = get_highest_priority_presence(bare_jid);
        if (best.has_value()) {
            route_stanza(best->jid, stanza_xml);
        } else {
            // Queue for offline storage
            record_offline_stanza(bare_jid, stanza_xml);
        }
    }

    /**
     * Flush the outbound queue (called periodically by transport layer).
     * Returns all queued stanzas and clears the queue.
     */
    std::vector<route_entry> flush_outbound_queue() {
        std::lock_guard<std::mutex> lock(outbound_mutex_);
        std::vector<route_entry> result = std::move(outbound_queue_);
        outbound_queue_.clear();
        return result;
    }

    // =========================================================================
    // Offline message handling
    // =========================================================================

    /**
     * Store a message for offline delivery.
     */
    void record_offline_message(const xmpp_message& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string bare_to = bare_jid(msg.to);
        offline_messages_[bare_to].push_back(msg);

        // Limit offline storage per user
        if (offline_messages_[bare_to].size() > 100) {
            offline_messages_[bare_to].erase(
                offline_messages_[bare_to].begin());
        }
    }

    /**
     * Store a raw stanza for offline delivery.
     */
    void record_offline_stanza(const std::string& bare_jid,
                                const std::string& stanza_xml) {
        std::lock_guard<std::mutex> lock(mutex_);
        offline_stanzas_[bare_jid].push_back(stanza_xml);
        if (offline_stanzas_[bare_jid].size() > 50) {
            offline_stanzas_[bare_jid].erase(
                offline_stanzas_[bare_jid].begin());
        }
    }

    /**
     * Get and drain offline messages for a user.
     */
    std::vector<xmpp_message> fetch_offline_messages(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = offline_messages_.find(bare_jid);
        if (it != offline_messages_.end()) {
            std::vector<xmpp_message> result = std::move(it->second);
            offline_messages_.erase(it);
            return result;
        }
        return {};
    }

    /**
     * Get and drain offline stanzas for a user.
     */
    std::vector<std::string> fetch_offline_stanzas(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = offline_stanzas_.find(bare_jid);
        if (it != offline_stanzas_.end()) {
            std::vector<std::string> result = std::move(it->second);
            offline_stanzas_.erase(it);
            return result;
        }
        return {};
    }

    /**
     * Count offline messages for a user.
     */
    size_t offline_message_count(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = offline_messages_.find(bare_jid);
        if (it != offline_messages_.end()) {
            return it->second.size();
        }
        return 0;
    }

    /**
     * Deliver all offline messages to a user who just came online.
     */
    std::vector<route_entry> deliver_offline_messages(
        const std::string& bare_jid)
    {
        std::vector<route_entry> results;
        auto messages = fetch_offline_messages(bare_jid);
        auto stanzas = fetch_offline_stanzas(bare_jid);

        auto resources = get_online_resources(bare_jid);
        if (resources.empty()) return results;

        std::string best_resource = resources[0];
        auto best_presence = get_highest_priority_presence(bare_jid);
        if (best_presence.has_value()) {
            best_resource = best_presence->jid;
        }

        for (const auto& msg : messages) {
            route_entry entry;
            entry.target_full_jid = best_resource;
            entry.stanza_xml = msg.to_xml();
            results.push_back(entry);
        }

        for (const auto& stanza : stanzas) {
            route_entry entry;
            entry.target_full_jid = best_resource;
            entry.stanza_xml = stanza;
            results.push_back(entry);
        }

        return results;
    }

    // =========================================================================
    // Resource management
    // =========================================================================

    /**
     * Register an online resource for a user.
     */
    void register_resource(const std::string& bare_jid,
                            const std::string& resource,
                            const presence_info& initial_presence) {
        std::lock_guard<std::mutex> lock(mutex_);

        presence_info pres = initial_presence;
        pres.bare_jid = bare_jid;
        pres.resource = resource;
        pres.jid = make_full_jid(bare_jid, resource);

        user_presences_[bare_jid][resource] = pres;

        // Bind resource to stream for routing
        resource_bindings_[resource] = bare_jid;
    }

    /**
     * Unregister a resource (disconnect).
     */
    void unregister_resource(const std::string& bare_jid,
                              const std::string& resource) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = user_presences_.find(bare_jid);
        if (it != user_presences_.end()) {
            it->second.erase(resource);
            if (it->second.empty()) {
                record_last_activity(bare_jid, time(nullptr));
                user_presences_.erase(it);
            }
        }

        resource_bindings_.erase(resource);
    }

    /**
     * Get all online resources for a user.
     */
    std::vector<std::string> get_online_resources(const std::string& bare_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> result;
        auto it = user_presences_.find(bare_jid);
        if (it != user_presences_.end()) {
            for (const auto& [res, pres] : it->second) {
                if (pres.is_online()) {
                    result.push_back(res);
                }
            }
        }
        return result;
    }

    /**
     * Check if a resource is online.
     */
    bool is_resource_online(const std::string& full_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto parts = detail::parse_jid(full_jid);
        auto it = user_presences_.find(parts.local + "@" + parts.domain);
        if (it != user_presences_.end()) {
            auto res_it = it->second.find(parts.resource);
            if (res_it != it->second.end()) {
                return res_it->second.is_online();
            }
        }
        return false;
    }

    /**
     * Get the bare JID for a resource.
     */
    std::string get_bare_for_resource(const std::string& resource) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = resource_bindings_.find(resource);
        if (it != resource_bindings_.end()) {
            return it->second;
        }
        return "";
    }

    // =========================================================================
    // Utility / Helpers
    // =========================================================================

    /**
     * Build a simple presence stanza with a type.
     */
    static std::string build_presence_stanza(
        const std::string& type,
        const std::string& from_bare,
        const std::string& to_bare)
    {
        std::ostringstream oss;
        oss << "<presence type='" << detail::xml_escape(type) << "'"
            << " from='" << detail::xml_escape(from_bare) << "'"
            << " to='" << detail::xml_escape(to_bare) << "'/>";
        return oss.str();
    }

    /**
     * Build an unavailable presence stanza.
     */
    static std::string build_offline_presence(
        const std::string& from_bare,
        const std::string& to_full)
    {
        std::ostringstream oss;
        oss << "<presence type='unavailable'"
            << " from='" << detail::xml_escape(from_bare) << "'"
            << " to='" << detail::xml_escape(to_full) << "'/>";
        return oss.str();
    }

    /**
     * Build an IQ error stanza.
     */
    static std::string make_iq_error(
        const std::string& id,
        const std::string& from,
        const std::string& type,
        const std::string& condition,
        const std::string& text)
    {
        std::ostringstream oss;
        oss << "<iq type='error' id='" << detail::xml_escape(id) << "'"
            << " from='" << detail::xml_escape(from) << "'>"
            << "<error type='" << detail::xml_escape(type) << "'>"
            << "<" << detail::xml_escape(condition)
            << " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>";
        if (!text.empty()) {
            oss << "<text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>"
                << detail::xml_escape(text) << "</text>";
        }
        oss << "</error></iq>";
        return oss.str();
    }

    /**
     * Generate a random version ID for roster versioning.
     */
    static std::string generate_version_id() {
        std::ostringstream oss;
        oss << std::hex << time(nullptr);
        return oss.str();
    }

    // =========================================================================
    // Statistics and Monitoring
    // =========================================================================

    /**
     * Get total number of online users.
     */
    size_t online_user_count() {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& [bare, resources] : user_presences_) {
            if (is_user_online_unsafe(bare)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Get total number of active roster entries across all users.
     */
    size_t total_roster_entry_count() {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& [bare, items] : rosters_) {
            count += items.size();
        }
        return count;
    }

    /**
     * Get total number of pending subscription requests.
     */
    size_t pending_subscription_count() {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& [bare, items] : rosters_) {
            for (const auto& [jid, item] : items) {
                if (!item.ask.empty()) {
                    count++;
                }
            }
        }
        return count;
    }

    /**
     * Get the size of the outbound queue.
     */
    size_t outbound_queue_size() {
        std::lock_guard<std::mutex> lock(outbound_mutex_);
        return outbound_queue_.size();
    }

    /**
     * Periodic maintenance: clean up expired sessions and stale data.
     */
    void perform_maintenance() {
        std::lock_guard<std::mutex> lock(mutex_);

        int64_t now = time(nullptr);

        // Clean up expired stream sessions
        auto ss_it = stream_sessions_.begin();
        while (ss_it != stream_sessions_.end()) {
            if (ss_it->second.is_expired()) {
                ss_it = stream_sessions_.erase(ss_it);
            } else {
                ++ss_it;
            }
        }

        // Clean up old caps cache entries (> 1 hour)
        auto caps_it = caps_cache_.begin();
        while (caps_it != caps_cache_.end()) {
            if (now - caps_it->second.cached_at > 3600) {
                caps_it = caps_cache_.erase(caps_it);
            } else {
                ++caps_it;
            }
        }

        // Clean up old chat markers (> 24 hours)
        auto marker_it = chat_markers_.begin();
        while (marker_it != chat_markers_.end()) {
            auto& records = marker_it->second;
            records.erase(
                std::remove_if(records.begin(), records.end(),
                    [now](const chat_marker_record& r) {
                        return (now - r.timestamp) > 86400;
                    }),
                records.end());
            if (records.empty()) {
                marker_it = chat_markers_.erase(marker_it);
            } else {
                ++marker_it;
            }
        }

        // Clean up old last activity queries (> 1 hour)
        auto laq_it = last_activity_queries_.begin();
        while (laq_it != last_activity_queries_.end()) {
            auto& timestamps = laq_it->second;
            timestamps.erase(
                std::remove_if(timestamps.begin(), timestamps.end(),
                    [now](int64_t t) { return (now - t) > 3600; }),
                timestamps.end());
            if (timestamps.empty()) {
                laq_it = last_activity_queries_.erase(laq_it);
            } else {
                ++laq_it;
            }
        }

        // Clean up old delivery receipts (> 1 hour)
        auto dr_it = delivery_receipts_.begin();
        while (dr_it != delivery_receipts_.end()) {
            if (now - dr_it->second.timestamp > 3600) {
                dr_it = delivery_receipts_.erase(dr_it);
            } else {
                ++dr_it;
            }
        }

        // Clean up old sent message tracking (> 1 hour)
        auto sm_it = sent_messages_.begin();
        while (sm_it != sent_messages_.end()) {
            // We don't have timestamps on these; just keep a bounded map
            // Keep last 10000 entries
            ++sm_it;
        }
        if (sent_messages_.size() > 10000) {
            // Remove oldest entries (approximation)
            size_t to_remove = sent_messages_.size() - 10000;
            auto rm_it = sent_messages_.begin();
            while (to_remove > 0 && rm_it != sent_messages_.end()) {
                rm_it = sent_messages_.erase(rm_it);
                to_remove--;
            }
        }
    }

    /**
     * Dump diagnostic information.
     */
    std::string diagnostics() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream oss;

        oss << "XMPP Roster/Presence Router Diagnostics\n";
        oss << "=======================================\n";
        oss << "Online users: " << online_user_count() << "\n";
        oss << "Total roster entries: " << total_roster_entry_count() << "\n";
        oss << "Active stream sessions: " << stream_sessions_.size() << "\n";
        oss << "Cached capabilities: " << caps_cache_.size() << "\n";
        oss << "vCards cached: " << vcards_.size() << "\n";
        oss << "Carbons enabled for: " << count_carbons_enabled() << " users\n";
        oss << "Offline messages pending: " << count_offline_messages() << "\n";
        oss << "Chat marker states tracked: " << marker_states_.size() << "\n";
        oss << "Delivery receipts tracked: " << delivery_receipts_.size() << "\n";
        oss << "Outbound queue size: " << outbound_queue_size() << "\n";
        oss << "Pipeline hooks: inbound=" << pipeline_.inbound_hooks.size()
            << " outbound=" << pipeline_.outbound_hooks.size()
            << " presence=" << pipeline_.presence_hooks.size()
            << " roster=" << pipeline_.roster_hooks.size() << "\n";

        return oss.str();
    }

private:
    // =========================================================================
    // Private helper methods
    // =========================================================================

    bool is_user_online_unsafe(const std::string& bare_jid) const {
        auto it = user_presences_.find(bare_jid);
        if (it == user_presences_.end()) return false;
        for (const auto& [res, pres] : it->second) {
            if (pres.is_online()) return true;
        }
        return false;
    }

    int64_t get_last_activity_time(const std::string& bare_jid) const {
        auto it = last_activity_times_.find(bare_jid);
        if (it != last_activity_times_.end()) {
            return time(nullptr) - it->second;
        }
        return 0;
    }

    int64_t last_activity_recorded(const std::string& bare_jid) const {
        auto it = last_activity_times_.find(bare_jid);
        if (it != last_activity_times_.end()) {
            return it->second;
        }
        return 0;
    }

    std::unordered_map<std::string, roster_item>&
    get_user_roster_unsafe(const std::string& bare_jid) {
        return rosters_[bare_jid];
    }

    void bump_roster_version(const std::string& bare_jid) {
        roster_versions_[bare_jid] = generate_version_id();
    }

    void queue_outbound_stanza(const std::string& target, const std::string& stanza) {
        std::lock_guard<std::mutex> lock(outbound_mutex_);
        outbound_queue_.push_back({target, stanza});
    }

    size_t count_carbons_enabled() const {
        size_t count = 0;
        for (const auto& [jid, enabled] : carbon_enabled_) {
            if (enabled) count++;
        }
        return count;
    }

    size_t count_offline_messages() const {
        size_t count = 0;
        for (const auto& [jid, msgs] : offline_messages_) {
            count += msgs.size();
        }
        for (const auto& [jid, stanzas] : offline_stanzas_) {
            count += stanzas.size();
        }
        return count;
    }

    // =========================================================================
    // Data Members
    // =========================================================================

    // Per-user roster maps: bare_jid -> (contact_jid -> roster_item)
    std::unordered_map<std::string, std::unordered_map<std::string, roster_item>> rosters_;

    // Roster versioning: bare_jid -> version string
    std::unordered_map<std::string, std::string> roster_versions_;

    // Presence tracking: bare_jid -> (resource -> presence_info)
    std::unordered_map<std::string, std::unordered_map<std::string, presence_info>> user_presences_;

    // Resource to bare JID mapping for routing
    std::unordered_map<std::string, std::string> resource_bindings_;

    // Last activity times: bare_jid -> epoch seconds
    std::unordered_map<std::string, int64_t> last_activity_times_;

    // Last activity query tracking (for rate limiting / privacy)
    std::unordered_map<std::string, std::vector<int64_t>> last_activity_queries_;

    // vCard storage: bare_jid -> vcard_info
    std::unordered_map<std::string, vcard_info> vcards_;

    // Entity capabilities cache: ver -> caps_entry
    std::unordered_map<std::string, caps_entry> caps_cache_;

    // Carbon copy enable/disable: bare_jid -> enabled
    std::unordered_map<std::string, bool> carbon_enabled_;

    // Chat states: "from_bare|to_bare" -> chat_state
    std::unordered_map<std::string, chat_state> chat_states_;

    // Chat marker records
    struct chat_marker_record {
        std::string from;
        chat_marker marker_type;
        std::string marked_id;
        int64_t timestamp;
    };
    std::unordered_map<std::string, std::vector<chat_marker_record>> chat_markers_;

    // Marker states per message ID
    std::unordered_map<std::string, marker_status> marker_states_;

    // Delivery receipts: receipt_id -> receipt_info
    std::unordered_map<std::string, receipt_info> delivery_receipts_;

    // Sent message tracking: message_id -> sender_full_jid
    std::unordered_map<std::string, std::string> sent_messages_;

    // Archive preferences: bare_jid -> archive_preferences
    std::unordered_map<std::string, archive_preferences> archive_prefs_;

    // Stream resumption sessions: stream_id -> stream_resumption_entry
    std::unordered_map<std::string, stream_resumption_entry> stream_sessions_;

    // Offline message storage: bare_jid -> vector of messages
    std::unordered_map<std::string, std::vector<xmpp_message>> offline_messages_;

    // Offline stanza storage: bare_jid -> vector of raw XML stanzas
    std::unordered_map<std::string, std::vector<std::string>> offline_stanzas_;

    // Outbound stanza queue
    std::vector<route_entry> outbound_queue_;

    // Pipeline hooks
    pipeline_hooks pipeline_;

    // Mutexes
    mutable std::mutex mutex_;
    mutable std::mutex outbound_mutex_;
};

// =============================================================================
// Convenience aliases and factory functions
// =============================================================================

/**
 * Create a new router instance.
 */
std::shared_ptr<xmpp_roster_presence_router> create_router() {
    auto router = std::make_shared<xmpp_roster_presence_router>();
    router->initialize();
    return router;
}

/**
 * Parse a presence stanza and return presence_info.
 * This is a helper for transport adapters that receive raw XML.
 */
presence_info parse_presence(const std::string& full_jid,
                              const std::string& show_str,
                              const std::string& status_str,
                              int priority,
                              const std::string& caps_node,
                              const std::string& caps_ver,
                              const std::string& caps_hash,
                              const std::string& avatar_hash)
{
    auto parts = detail::parse_jid(full_jid);
    presence_info pres;
    pres.jid = full_jid;
    pres.bare_jid = parts.local.empty() ? parts.domain :
        parts.local + "@" + parts.domain;
    pres.resource = parts.resource;
    pres.show = presence_show_from_string(show_str);
    pres.status = status_str;
    pres.priority = priority;
    pres.caps_node = caps_node;
    pres.caps_ver = caps_ver;
    pres.caps_hash = caps_hash.empty() ? "sha-1" : caps_hash;
    pres.avatar_hash = avatar_hash;
    pres.last_seen = time(nullptr);
    return pres;
}

/**
 * Parse a message XML string into an xmpp_message struct.
 * Simple parser for basic fields.
 */
xmpp_message parse_message(
    const std::string& id,
    const std::string& from,
    const std::string& to,
    const std::string& type_str,
    const std::string& body,
    const std::string& subject,
    const std::string& thread)
{
    xmpp_message msg;
    msg.id = id;
    msg.from = from;
    msg.to = to;
    msg.type = message_type_from_string(type_str);
    msg.body = body;
    msg.subject = subject;
    msg.thread = thread;
    msg.timestamp = detail::current_iso8601();
    return msg;
}

/**
 * Default inbound hook: log all messages.
 */
inbound_hook default_inbound_logger() {
    return [](xmpp_message& msg) -> bool {
        // In production this would log to a logging system
        // For now, we just pass through
        (void)msg;
        return true;
    };
}

/**
 * Default outbound hook: ensure messages have IDs.
 */
outbound_hook default_outbound_enforcer() {
    return [](xmpp_message& msg) -> bool {
        if (msg.id.empty()) {
            msg.id = detail::generate_id();
        }
        if (msg.timestamp.empty()) {
            msg.timestamp = detail::current_iso8601();
        }
        return true;
    };
}

/**
 * Spam filter hook: drop messages matching spam patterns.
 */
inbound_hook spam_filter_hook() {
    return [](xmpp_message& msg) -> bool {
        // Simple spam heuristics
        if (msg.body.empty() && msg.subject.empty() &&
            msg.extensions.empty() && msg.chat_state_flag == chat_state::none &&
            !msg.has_marker && msg.receipt_id.empty()) {
            // Empty message with no meaningful payload - likely spam/ping
            return false;
        }
        // Check for excessive length
        if (msg.body.size() > 65536) {
            return false;
        }
        return true;
    };
}

/**
 * Rate limiter hook for presence stanzas.
 */
presence_hook presence_rate_limit_hook() {
    return [](const presence_info& pres) -> bool {
        // Basic rate limiting - accept all for now
        // In production, track presence change frequency per user
        (void)pres;
        return true;
    };
}

} } // namespace progressive::xmpp

// =============================================================================
// End of xmpp_roster_presence.cpp
// =============================================================================
