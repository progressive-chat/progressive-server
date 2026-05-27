// progressive-server: XMPP Stanza Processing Engine
// Reference: ejabberd jlib.erl, xmpp_codec.erl, mod_muc_room.erl (155,521 lines)
// Core XML stanza parsing, routing, JID handling, MUC, PubSub, XEP implementations

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <functional>
#include <optional>
#include <variant>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <regex>
#include <random>
#include <atomic>
#include <mutex>

namespace progressive {
namespace xmpp {

// =============================================================================
// JID (Jabber ID) handling
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
        // Extract resource (after last /)
        size_t slash = s.find('/');
        if (slash != std::string::npos) {
            resource = s.substr(slash + 1);
            s = s.substr(0, slash);
        }
        // Extract node (before @)
        size_t at = s.find('@');
        if (at != std::string::npos) {
            node = s.substr(0, at);
            domain = s.substr(at + 1);
        } else {
            domain = s;
        }
        return !domain.empty() && is_valid_domain(domain);
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

    bool operator==(const Jid& other) const {
        return node == other.node && domain == other.domain &&
               resource == other.resource;
    }

    bool bare_eq(const Jid& other) const {
        return node == other.node && domain == other.domain;
    }

    static bool is_valid_domain(const std::string& d) {
        if (d.empty() || d.length() > 1023) return false;
        for (char c : d) {
            if (!isalnum(c) && c != '.' && c != '-' && c != ':') return false;
        }
        return true;
    }
};

// =============================================================================
// XML namespace constants (XMPP)
// =============================================================================
namespace ns {
    constexpr const char* JABBER_CLIENT   = "jabber:client";
    constexpr const char* JABBER_SERVER   = "jabber:server";
    constexpr const char* STREAMS         = "http://etherx.jabber.org/streams";
    constexpr const char* TLS             = "urn:ietf:params:xml:ns:xmpp-tls";
    constexpr const char* SASL            = "urn:ietf:params:xml:ns:xmpp-sasl";
    constexpr const char* BIND            = "urn:ietf:params:xml:ns:xmpp-bind";
    constexpr const char* SESSION         = "urn:ietf:params:xml:ns:xmpp-session";
    constexpr const char* ROSTER          = "jabber:iq:roster";
    constexpr const char* DISCO_INFO      = "http://jabber.org/protocol/disco#info";
    constexpr const char* DISCO_ITEMS     = "http://jabber.org/protocol/disco#items";
    constexpr const char* MUC             = "http://jabber.org/protocol/muc";
    constexpr const char* MUC_USER        = "http://jabber.org/protocol/muc#user";
    constexpr const char* MUC_ADMIN       = "http://jabber.org/protocol/muc#admin";
    constexpr const char* MUC_OWNER       = "http://jabber.org/protocol/muc#owner";
    constexpr const char* PUBSUB          = "http://jabber.org/protocol/pubsub";
    constexpr const char* PUBSUB_EVENT    = "http://jabber.org/protocol/pubsub#event";
    constexpr const char* PUBSUB_OWNER    = "http://jabber.org/protocol/pubsub#owner";
    constexpr const char* VCARD           = "vcard-temp";
    constexpr const char* PRIVACY         = "jabber:iq:privacy";
    constexpr const char* PRIVATE         = "jabber:iq:private";
    constexpr const char* VERSION         = "jabber:iq:version";
    constexpr const char* LAST            = "jabber:iq:last";
    constexpr const char* REGISTER        = "jabber:iq:register";
    constexpr const char* SEARCH          = "jabber:iq:search";
    constexpr const char* DATA            = "jabber:x:data";
    constexpr const char* OOB             = "jabber:x:oob";
    constexpr const char* DELAY           = "urn:xmpp:delay";
    constexpr const char* FORWARD         = "urn:xmpp:forward:0";
    constexpr const char* CARBONS         = "urn:xmpp:carbons:2";
    constexpr const char* MAM             = "urn:xmpp:mam:2";
    constexpr const char* BLOCKING        = "urn:xmpp:blocking";
    constexpr const char* PING            = "urn:xmpp:ping";
    constexpr const char* RECEIPTS        = "urn:xmpp:receipts";
    constexpr const char* CHAT_MARKERS    = "urn:xmpp:chat-markers:0";
    constexpr const char* CHAT_STATES     = "http://jabber.org/protocol/chatstates";
    constexpr const char* CAPS            = "http://jabber.org/protocol/caps";
    constexpr const char* STREAM_MGMT     = "urn:xmpp:sm:3";
    constexpr const char* CSI             = "urn:xmpp:csi:0";
    constexpr const char* HINTS           = "urn:xmpp:hints";
    constexpr const char* RSM             = "http://jabber.org/protocol/rsm";
    constexpr const char* COMPRESSION     = "http://jabber.org/features/compress";
    constexpr const char* HTTP_BIND       = "http://jabber.org/protocol/httpbind";
    constexpr const char* BOSH            = "urn:xmpp:bosh";
    constexpr const char* WEBSOCKET       = "urn:ietf:params:xml:ns:xmpp-framing";
    constexpr const char* JINGLE          = "urn:xmpp:jingle:1";
    constexpr const char* JINGLE_RTP      = "urn:xmpp:jingle:apps:rtp:1";
    constexpr const char* JINGLE_ICE      = "urn:xmpp:jingle:transports:ice-udp:1";
    constexpr const char* OMEMO           = "eu.siacs.conversations.axolotl";
    constexpr const char* OMEMO_DEVICES   = "urn:xmpp:omemo:1";
    constexpr const char* AVATAR          = "urn:xmpp:avatar:metadata";
    constexpr const char* AVATAR_DATA     = "urn:xmpp:avatar:data";
    constexpr const char* NICK            = "http://jabber.org/protocol/nick";
    constexpr const char* MIX_CORE        = "urn:xmpp:mix:core:0";
    constexpr const char* MIX_PAM         = "urn:xmpp:mix:pam:2";
    constexpr const char* BOOKMARKS       = "storage:bookmarks";
    constexpr const char* BOOKMARKS2      = "urn:xmpp:bookmarks:1";
    constexpr const char* ADHOC           = "http://jabber.org/protocol/commands";
    constexpr const char* ATTENTION       = "urn:xmpp:attention:0";
    constexpr const char* BOB             = "urn:xmpp:bob";
    constexpr const char* CONTAINER       = "urn:xmpp:json-container:0";
    constexpr const char* EME             = "urn:xmpp:eme:0";
    constexpr const char* EXTERNAL_SD     = "urn:xmpp:sdp:1";
    constexpr const char* FILE_METADATA   = "urn:xmpp:file:metadata:0";
    constexpr const char* GEOLOC          = "http://jabber.org/protocol/geoloc";
    constexpr const char* HASHES          = "urn:xmpp:hashes:2";
    constexpr const char* HTTP_UPLOAD     = "urn:xmpp:http:upload:0";
    constexpr const char* IB              = "http://jabber.org/protocol/ibb";
    constexpr const char* JINGLE_FT       = "urn:xmpp:jingle:apps:file-transfer:5";
    constexpr const char* JINGLE_IBB      = "urn:xmpp:jingle:transports:ibb:1";
    constexpr const char* JINGLE_S5B      = "urn:xmpp:jingle:transports:s5b:1";
    constexpr const char* MESSAGE_CORRECT = "urn:xmpp:message-correct:0";
    constexpr const char* MOOD            = "http://jabber.org/protocol/mood";
    constexpr const char* MUC_UNIQUE      = "http://jabber.org/protocol/muc#unique";
    constexpr const char* PEPSI           = "urn:xmpp:pep-dialog:0";
    constexpr const char* PEP_NATIVE      = "http://jabber.org/protocol/pubsub#owner";
    constexpr const char* PUSH            = "urn:xmpp:push:0";
    constexpr const char* REFERENCE       = "urn:xmpp:reference:0";
    constexpr const char* ROSTER_EXCHANGE = "http://jabber.org/protocol/rosterx";
    constexpr const char* RTT             = "urn:xmpp:rtt:0";
    constexpr const char* SASL2           = "urn:xmpp:sasl:2";
    constexpr const char* SHIM            = "http://jabber.org/protocol/shim";
    constexpr const char* SIC             = "urn:xmpp:sic:1";
    constexpr const char* SID             = "urn:xmpp:sid:0";
    constexpr const char* SIMS            = "urn:xmpp:sims:1";
    constexpr const char* SSI             = "urn:xmpp:ssi:0";
    constexpr const char* STABLE_ID       = "urn:xmpp:sid:0";
    constexpr const char* THUMBS          = "urn:xmpp:thumbs:1";
    constexpr const char* TUNE            = "http://jabber.org/protocol/tune";
    constexpr const char* UPLOAD          = "urn:xmpp:http:upload:0";
    constexpr const char* VERSION_2       = "urn:xmpp:features:version";
    constexpr const char* XCONFERENCE     = "jabber:x:conference";
    constexpr const char* XDATA_VALIDATE  = "http://jabber.org/protocol/xdata-validate";
    constexpr const char* XDATA_LAYOUT    = "http://jabber.org/protocol/xdata-layout";
}

// =============================================================================
// XMPP Stanza
// =============================================================================
enum class StanzaType : uint8_t {
    MESSAGE,      // <message>
    PRESENCE,     // <presence>
    IQ,           // <iq>
    STREAM_OPEN,  // <stream:stream>
    STREAM_CLOSE, // </stream:stream>
    STREAM_ERROR, // <stream:error>
    TLS_PROCEED,  // <proceed>
    TLS_FAILURE,  // <failure>
    SASL_AUTH,    // <auth>
    SASL_CHALLENGE, // <challenge>
    SASL_RESPONSE,  // <response>
    SASL_SUCCESS,   // <success>
    SASL_FAILURE,   // <failure>
};

enum class IqType : uint8_t {
    GET, SET, RESULT, ERROR
};

enum class MessageType : uint8_t {
    NORMAL, CHAT, GROUPCHAT, HEADLINE, ERROR
};

enum class PresenceType : uint8_t {
    AVAILABLE, UNAVAILABLE, SUBSCRIBE, SUBSCRIBED,
    UNSUBSCRIBE, UNSUBSCRIBED, PROBE, ERROR
};

enum class PresenceShow : uint8_t {
    ONLINE, CHAT, AWAY, XA, DND
};

// =============================================================================
// Stanza error codes (RFC 6120)
// =============================================================================
enum class StanzaErrorCondition : uint8_t {
    BAD_REQUEST,
    CONFLICT,
    FEATURE_NOT_IMPLEMENTED,
    FORBIDDEN,
    GONE,
    INTERNAL_SERVER_ERROR,
    ITEM_NOT_FOUND,
    JID_MALFORMED,
    NOT_ACCEPTABLE,
    NOT_ALLOWED,
    NOT_AUTHORIZED,
    POLICY_VIOLATION,
    RECIPIENT_UNAVAILABLE,
    REDIRECT,
    REGISTRATION_REQUIRED,
    REMOTE_SERVER_NOT_FOUND,
    REMOTE_SERVER_TIMEOUT,
    RESOURCE_CONSTRAINT,
    SERVICE_UNAVAILABLE,
    SUBSCRIPTION_REQUIRED,
    UNDEFINED_CONDITION,
    UNEXPECTED_REQUEST,
};

// =============================================================================
// Stanza class
// =============================================================================
class XmppStanza {
public:
    using ptr = std::shared_ptr<XmppStanza>;

    StanzaType type() const { return type_; }
    void set_type(StanzaType t) { type_ = t; }

    const Jid& from() const { return from_; }
    void set_from(const Jid& j) { from_ = j; }
    const Jid& to() const { return to_; }
    void set_to(const Jid& j) { to_ = j; }

    const std::string& id() const { return id_; }
    void set_id(const std::string& i) { id_ = i; }

    // IQ-specific
    IqType iq_type() const { return iq_type_; }
    void set_iq_type(IqType t) { iq_type_ = t; }

    // Message-specific
    MessageType msg_type() const { return msg_type_; }
    void set_msg_type(MessageType t) { msg_type_ = t; }
    const std::string& subject() const { return subject_; }
    void set_subject(const std::string& s) { subject_ = s; }
    const std::string& body() const { return body_; }
    void set_body(const std::string& b) { body_ = b; }
    const std::string& thread() const { return thread_; }
    void set_thread(const std::string& t) { thread_ = t; }

    // Presence-specific
    PresenceType presence_type() const { return presence_type_; }
    void set_presence_type(PresenceType t) { presence_type_ = t; }
    PresenceShow show() const { return show_; }
    void set_show(PresenceShow s) { show_ = s; }
    const std::string& status() const { return status_; }
    void set_status(const std::string& s) { status_ = s; }
    int priority() const { return priority_; }
    void set_priority(int p) { priority_ = p; }

    // Error
    StanzaErrorCondition error_condition() const { return error_cond_; }
    void set_error(StanzaErrorCondition c, const std::string& text = "") {
        error_cond_ = c;
        error_text_ = text;
        has_error_ = true;
    }
    bool is_error() const { return has_error_; }

    // Extensions (XEP payloads)
    struct Extension {
        std::string xmlns;
        std::string tag;
        std::string content;
        std::unordered_map<std::string, std::string> attrs;
    };

    void add_extension(const Extension& e) { extensions_.push_back(e); }
    void add_extension(const std::string& xmlns, const std::string& tag,
                       const std::string& content = "") {
        extensions_.push_back({xmlns, tag, content, {}});
    }
    const std::vector<Extension>& extensions() const { return extensions_; }

    Extension* find_extension(const std::string& xmlns, const std::string& tag = "") {
        for (auto& e : extensions_) {
            if (e.xmlns == xmlns && (tag.empty() || e.tag == tag)) return &e;
        }
        return nullptr;
    }

    // Serialization
    std::string to_xml() const {
        std::stringstream ss;
        switch (type_) {
        case StanzaType::MESSAGE:
            serialize_message(ss);
            break;
        case StanzaType::PRESENCE:
            serialize_presence(ss);
            break;
        case StanzaType::IQ:
            serialize_iq(ss);
            break;
        default:
            break;
        }
        return ss.str();
    }

    // Factory methods
    static ptr make_message(const Jid& from, const Jid& to, const std::string& body,
                            MessageType mtype = MessageType::CHAT) {
        auto stanza = std::make_shared<XmppStanza>();
        stanza->type_ = StanzaType::MESSAGE;
        stanza->from_ = from;
        stanza->to_ = to;
        stanza->body_ = body;
        stanza->msg_type_ = mtype;
        stanza->id_ = generate_id();
        return stanza;
    }

    static ptr make_presence(const Jid& from, const Jid& to = {},
                             PresenceType ptype = PresenceType::AVAILABLE) {
        auto stanza = std::make_shared<XmppStanza>();
        stanza->type_ = StanzaType::PRESENCE;
        stanza->from_ = from;
        stanza->to_ = to;
        stanza->presence_type_ = ptype;
        return stanza;
    }

    static ptr make_iq(const Jid& from, const Jid& to, IqType itype) {
        auto stanza = std::make_shared<XmppStanza>();
        stanza->type_ = StanzaType::IQ;
        stanza->from_ = from;
        stanza->to_ = to;
        stanza->iq_type_ = itype;
        stanza->id_ = generate_id();
        return stanza;
    }

    static ptr make_iq_result(const XmppStanza& request) {
        auto result = std::make_shared<XmppStanza>();
        result->type_ = StanzaType::IQ;
        result->from_ = request.to_;
        result->to_ = request.from_;
        result->iq_type_ = IqType::RESULT;
        result->id_ = request.id_;
        return result;
    }

    static ptr make_iq_error(const XmppStanza& request,
                              StanzaErrorCondition cond,
                              const std::string& text = "") {
        auto result = std::make_shared<XmppStanza>();
        result->type_ = StanzaType::IQ;
        result->from_ = request.to_;
        result->to_ = request.from_;
        result->iq_type_ = IqType::ERROR;
        result->id_ = request.id_;
        result->set_error(cond, text);
        // Include original request for reference
        result->error_original_id_ = request.id_;
        return result;
    }

private:
    StanzaType type_ = StanzaType::MESSAGE;
    Jid from_;
    Jid to_;
    std::string id_;
    std::string lang_;

    // IQ
    IqType iq_type_ = IqType::GET;

    // Message
    MessageType msg_type_ = MessageType::NORMAL;
    std::string subject_;
    std::string body_;
    std::string thread_;

    // Presence
    PresenceType presence_type_ = PresenceType::AVAILABLE;
    PresenceShow show_ = PresenceShow::ONLINE;
    std::string status_;
    int priority_ = 0;

    // Error
    bool has_error_ = false;
    StanzaErrorCondition error_cond_ = StanzaErrorCondition::UNDEFINED_CONDITION;
    std::string error_text_;
    std::string error_original_id_;

    // Extensions
    std::vector<Extension> extensions_;

    static std::string generate_id() {
        static thread_local std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<uint64_t> dist;
        char buf[32];
        snprintf(buf, sizeof(buf), "%016lx", (unsigned long)dist(rng));
        return std::string(buf);
    }

    std::string show_to_string() const {
        switch (show_) {
        case PresenceShow::CHAT: return "chat";
        case PresenceShow::AWAY: return "away";
        case PresenceShow::XA:   return "xa";
        case PresenceShow::DND:  return "dnd";
        default: return "";
        }
    }

    void serialize_message(std::stringstream& ss) const {
        ss << "<message";
        if (!from_.full().empty()) ss << " from='" << xml_escape(from_.full()) << "'";
        if (!to_.full().empty()) ss << " to='" << xml_escape(to_.full()) << "'";
        if (!id_.empty()) ss << " id='" << xml_escape(id_) << "'";
        if (msg_type_ != MessageType::NORMAL) {
            ss << " type='";
            switch (msg_type_) {
            case MessageType::CHAT:      ss << "chat"; break;
            case MessageType::GROUPCHAT: ss << "groupchat"; break;
            case MessageType::HEADLINE:  ss << "headline"; break;
            case MessageType::ERROR:     ss << "error"; break;
            default: ss << "normal"; break;
            }
            ss << "'";
        }
        ss << ">";

        if (!subject_.empty()) ss << "<subject>" << xml_escape(subject_) << "</subject>";
        if (!body_.empty()) ss << "<body>" << xml_escape(body_) << "</body>";
        if (!thread_.empty()) ss << "<thread>" << xml_escape(thread_) << "</thread>";

        for (auto& ext : extensions_) {
            serialize_extension(ss, ext);
        }

        if (has_error_) serialize_error(ss);

        ss << "</message>";
    }

    void serialize_presence(std::stringstream& ss) const {
        ss << "<presence";
        if (!from_.full().empty()) ss << " from='" << xml_escape(from_.full()) << "'";
        if (!to_.full().empty()) ss << " to='" << xml_escape(to_.full()) << "'";
        if (!id_.empty()) ss << " id='" << xml_escape(id_) << "'";

        if (presence_type_ != PresenceType::AVAILABLE) {
            ss << " type='";
            switch (presence_type_) {
            case PresenceType::UNAVAILABLE:    ss << "unavailable"; break;
            case PresenceType::SUBSCRIBE:      ss << "subscribe"; break;
            case PresenceType::SUBSCRIBED:     ss << "subscribed"; break;
            case PresenceType::UNSUBSCRIBE:    ss << "unsubscribe"; break;
            case PresenceType::UNSUBSCRIBED:   ss << "unsubscribed"; break;
            case PresenceType::PROBE:          ss << "probe"; break;
            case PresenceType::ERROR:          ss << "error"; break;
            default: break;
            }
            ss << "'";
        }
        ss << ">";

        if (presence_type_ == PresenceType::AVAILABLE) {
            if (show_ != PresenceShow::ONLINE) {
                ss << "<show>" << show_to_string() << "</show>";
            }
            if (!status_.empty()) ss << "<status>" << xml_escape(status_) << "</status>";
            if (priority_ != 0) ss << "<priority>" << priority_ << "</priority>";
        }

        for (auto& ext : extensions_) {
            serialize_extension(ss, ext);
        }

        if (has_error_) serialize_error(ss);

        ss << "</presence>";
    }

    void serialize_iq(std::stringstream& ss) const {
        ss << "<iq";
        if (!from_.full().empty()) ss << " from='" << xml_escape(from_.full()) << "'";
        if (!to_.full().empty()) ss << " to='" << xml_escape(to_.full()) << "'";
        if (!id_.empty()) ss << " id='" << xml_escape(id_) << "'";

        ss << " type='";
        switch (iq_type_) {
        case IqType::GET:    ss << "get"; break;
        case IqType::SET:    ss << "set"; break;
        case IqType::RESULT: ss << "result"; break;
        case IqType::ERROR:  ss << "error"; break;
        }
        ss << "'";
        ss << ">";

        for (auto& ext : extensions_) {
            serialize_extension(ss, ext);
        }

        if (has_error_) serialize_error(ss);

        ss << "</iq>";
    }

    void serialize_extension(std::stringstream& ss, const Extension& ext) const {
        ss << "<" << ext.tag;
        if (!ext.xmlns.empty()) ss << " xmlns='" << xml_escape(ext.xmlns) << "'";
        for (auto& [attr, val] : ext.attrs) {
            ss << " " << attr << "='" << xml_escape(val) << "'";
        }
        if (ext.content.empty()) {
            ss << "/>";
        } else {
            ss << ">" << ext.content << "</" << ext.tag << ">";
        }
    }

    void serialize_error(std::stringstream& ss) const {
        ss << "<error type='";
        switch (error_cond_) {
        case StanzaErrorCondition::BAD_REQUEST:
        case StanzaErrorCondition::JID_MALFORMED:
        case StanzaErrorCondition::NOT_ACCEPTABLE:
        case StanzaErrorCondition::NOT_ALLOWED:
        case StanzaErrorCondition::REGISTRATION_REQUIRED:
        case StanzaErrorCondition::UNEXPECTED_REQUEST:
            ss << "modify"; break;
        case StanzaErrorCondition::NOT_AUTHORIZED:
        case StanzaErrorCondition::FORBIDDEN:
            ss << "auth"; break;
        case StanzaErrorCondition::ITEM_NOT_FOUND:
        case StanzaErrorCondition::REMOTE_SERVER_NOT_FOUND:
            ss << "cancel"; break;
        case StanzaErrorCondition::FEATURE_NOT_IMPLEMENTED:
        case StanzaErrorCondition::SERVICE_UNAVAILABLE:
        case StanzaErrorCondition::RESOURCE_CONSTRAINT:
            ss << "cancel"; break;
        case StanzaErrorCondition::RECIPIENT_UNAVAILABLE:
        case StanzaErrorCondition::REMOTE_SERVER_TIMEOUT:
        case StanzaErrorCondition::REDIRECT:
            ss << "wait"; break;
        default:
            ss << "cancel"; break;
        }
        ss << "'>";

        ss << "<" << error_condition_name() << " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>";
        if (!error_text_.empty()) {
            ss << "<text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas' xml:lang='en'>"
               << xml_escape(error_text_) << "</text>";
        }
        ss << "</error>";
    }

    std::string error_condition_name() const {
        switch (error_cond_) {
        case StanzaErrorCondition::BAD_REQUEST:               return "bad-request";
        case StanzaErrorCondition::CONFLICT:                  return "conflict";
        case StanzaErrorCondition::FEATURE_NOT_IMPLEMENTED:   return "feature-not-implemented";
        case StanzaErrorCondition::FORBIDDEN:                  return "forbidden";
        case StanzaErrorCondition::GONE:                       return "gone";
        case StanzaErrorCondition::INTERNAL_SERVER_ERROR:      return "internal-server-error";
        case StanzaErrorCondition::ITEM_NOT_FOUND:             return "item-not-found";
        case StanzaErrorCondition::JID_MALFORMED:              return "jid-malformed";
        case StanzaErrorCondition::NOT_ACCEPTABLE:             return "not-acceptable";
        case StanzaErrorCondition::NOT_ALLOWED:                return "not-allowed";
        case StanzaErrorCondition::NOT_AUTHORIZED:             return "not-authorized";
        case StanzaErrorCondition::POLICY_VIOLATION:           return "policy-violation";
        case StanzaErrorCondition::RECIPIENT_UNAVAILABLE:      return "recipient-unavailable";
        case StanzaErrorCondition::REDIRECT:                   return "redirect";
        case StanzaErrorCondition::REGISTRATION_REQUIRED:      return "registration-required";
        case StanzaErrorCondition::REMOTE_SERVER_NOT_FOUND:    return "remote-server-not-found";
        case StanzaErrorCondition::REMOTE_SERVER_TIMEOUT:      return "remote-server-timeout";
        case StanzaErrorCondition::RESOURCE_CONSTRAINT:        return "resource-constraint";
        case StanzaErrorCondition::SERVICE_UNAVAILABLE:        return "service-unavailable";
        case StanzaErrorCondition::SUBSCRIPTION_REQUIRED:      return "subscription-required";
        case StanzaErrorCondition::UNDEFINED_CONDITION:        return "undefined-condition";
        case StanzaErrorCondition::UNEXPECTED_REQUEST:         return "unexpected-request";
        default: return "undefined-condition";
        }
    }

    static std::string xml_escape(const std::string& s) {
        std::string result;
        result.reserve(s.size());
        for (char c : s) {
            switch (c) {
            case '&':  result += "&amp;"; break;
            case '<':  result += "&lt;"; break;
            case '>':  result += "&gt;"; break;
            case '\'': result += "&apos;"; break;
            case '"':  result += "&quot;"; break;
            default:   result += c;
            }
        }
        return result;
    }
};

// =============================================================================
// Roster item
// =============================================================================
struct RosterItem {
    Jid jid;
    std::string name;
    std::string subscription; // none, to, from, both, remove
    std::string ask;          // subscribe, unsubscribe
    std::vector<std::string> groups;

    bool is_none() const { return subscription == "none"; }
    bool is_to() const { return subscription == "to"; }
    bool is_from() const { return subscription == "from"; }
    bool is_both() const { return subscription == "both"; }
    bool is_pending_in() const { return subscription == "none" && ask == "subscribe"; }
    bool is_pending_out() const { return subscription == "to" && ask == "subscribe"; }
};

// =============================================================================
// Roster versioning
// =============================================================================
class RosterManager {
public:
    struct RosterVersion {
        std::string user_jid;
        std::string ver;
        time_t updated_at;
    };

    bool set_item(const std::string& owner_jid, const RosterItem& item) {
        auto& items = rosters_[owner_jid];
        bool found = false;
        for (auto& existing : items) {
            if (existing.jid.bare_eq(item.jid)) {
                existing = item;
                found = true;
                break;
            }
        }
        if (!found) {
            items.push_back(item);
        }

        update_version(owner_jid);
        return true;
    }

    bool remove_item(const std::string& owner_jid, const std::string& jid) {
        auto it = rosters_.find(owner_jid);
        if (it == rosters_.end()) return false;
        auto& items = it->second;
        items.erase(std::remove_if(items.begin(), items.end(),
            [&](const RosterItem& i) { return i.jid.bare() == jid; }), items.end());
        update_version(owner_jid);
        return true;
    }

    std::vector<RosterItem> get_items(const std::string& owner_jid) const {
        auto it = rosters_.find(owner_jid);
        if (it != rosters_.end()) return it->second;
        return {};
    }

    std::string get_version(const std::string& owner_jid) const {
        auto it = versions_.find(owner_jid);
        if (it != versions_.end()) return it->second.ver;
        return "";
    }

    bool process_push(const std::string& owner_jid,
                      std::function<void(const RosterItem&)> cb) {
        auto items = get_items(owner_jid);
        for (auto& item : items) {
            if (cb) cb(item);
        }
        return true;
    }

    std::vector<std::string> get_subscribed_jids(const std::string& owner_jid) const {
        std::vector<std::string> result;
        auto items = get_items(owner_jid);
        for (auto& item : items) {
            if (item.is_from() || item.is_both()) {
                result.push_back(item.jid.bare());
            }
        }
        return result;
    }

private:
    std::unordered_map<std::string, std::vector<RosterItem>> rosters_;
    std::unordered_map<std::string, RosterVersion> versions_;

    void update_version(const std::string& jid) {
        auto& ver = versions_[jid];
        ver.user_jid = jid;
        ver.ver = generate_ver();
        ver.updated_at = std::time(nullptr);
    }

    static std::string generate_ver() {
        static std::atomic<uint64_t> counter{0};
        char buf[32];
        snprintf(buf, sizeof(buf), "v%lx-%lx",
                 (unsigned long)std::time(nullptr),
                 (unsigned long)counter.fetch_add(1));
        return std::string(buf);
    }
};

// =============================================================================
// MUC Room Role and Affiliation
// =============================================================================
enum class MucRole : uint8_t {
    NONE, VISITOR, PARTICIPANT, MODERATOR
};

enum class MucAffiliation : uint8_t {
    NONE, OUTCAST, MEMBER, ADMIN, OWNER
};

struct MucOccupant {
    Jid real_jid;
    std::string nick;
    MucRole role = MucRole::PARTICIPANT;
    MucAffiliation affiliation = MucAffiliation::MEMBER;
    Jid occupant_jid;   // room@service/nick
    time_t joined_at;
};

// =============================================================================
// MUC Room
// =============================================================================
class MucRoom {
public:
    explicit MucRoom(const Jid& room_jid) : jid_(room_jid) {
        created_at_ = std::time(nullptr);
    }

    const Jid& jid() const { return jid_; }
    const std::string& subject() const { return subject_; }
    void set_subject(const std::string& s) { subject_ = s; }

    // Config
    bool is_persistent() const { return config_.persistent; }
    bool is_members_only() const { return config_.members_only; }
    bool is_moderated() const { return config_.moderated; }
    bool is_non_anonymous() const { return config_.non_anonymous; }
    bool is_password_protected() const { return !config_.password.empty(); }
    int max_users() const { return config_.max_users; }

    struct RoomConfig {
        bool persistent = false;
        bool members_only = false;
        bool moderated = false;
        bool non_anonymous = false;
        bool allow_invites = true;
        bool allow_private_messages = true;
        bool allow_voice_requests = true;
        bool allow_subscription = false;
        bool public_room = true;
        bool logging_enabled = false;
        std::string password;
        std::string title;
        std::string description;
        std::string language;
        int max_users = 200;
        int max_history = 20;
    };

    RoomConfig& config() { return config_; }

    // Presence broadcast
    void broadcast_presence(const XmppStanza& presence, const std::string& skip_nick = "") {
        for (auto& [nick, occupant] : occupants_) {
            if (nick == skip_nick) continue;
            auto p = XmppStanza::make_presence(jid_, occupant.real_jid);
            // the handler would send this to the occupant
        }
    }

    // Occupants
    void add_occupant(const Jid& real_jid, const std::string& nick,
                      MucAffiliation aff = MucAffiliation::MEMBER) {
        MucOccupant occ;
        occ.real_jid = real_jid;
        occ.nick = nick;
        occ.affiliation = aff;
        occ.role = (aff == MucAffiliation::OWNER || aff == MucAffiliation::ADMIN)
                   ? MucRole::MODERATOR : MucRole::PARTICIPANT;
        Jid room_jid = jid_;
        room_jid.resource = nick;
        occ.occupant_jid = room_jid;
        occ.joined_at = std::time(nullptr);
        occupants_[nick] = occ;
    }

    void remove_occupant(const std::string& nick) {
        occupants_.erase(nick);
    }

    MucOccupant* find_occupant_by_nick(const std::string& nick) {
        auto it = occupants_.find(nick);
        return (it != occupants_.end()) ? &it->second : nullptr;
    }

    MucOccupant* find_occupant_by_real_jid(const Jid& jid) {
        for (auto& [nick, occ] : occupants_) {
            if (occ.real_jid.bare_eq(jid)) return &occ;
        }
        return nullptr;
    }

    size_t occupant_count() const { return occupants_.size(); }
    const std::unordered_map<std::string, MucOccupant>& occupants() const {
        return occupants_;
    }

    // Ban list
    void add_ban(const Jid& jid) { banned_.insert(jid.bare()); }
    void remove_ban(const Jid& jid) { banned_.erase(jid.bare()); }
    bool is_banned(const Jid& jid) const { return banned_.count(jid.bare()) > 0; }

    // Member list
    void add_member(const Jid& jid) { members_.insert(jid.bare()); }
    void remove_member(const Jid& jid) { members_.erase(jid.bare()); }
    bool is_member(const Jid& jid) const { return members_.count(jid.bare()) > 0; }

private:
    Jid jid_;
    std::string subject_;
    time_t created_at_;
    RoomConfig config_;
    std::unordered_map<std::string, MucOccupant> occupants_;
    std::unordered_set<std::string> banned_;
    std::unordered_set<std::string> members_;
};

// =============================================================================
// PubSub Node
// =============================================================================
class PubSubNode {
public:
    struct PubSubConfig {
        int max_items = 100;
        bool persist_items = true;
        bool deliver_payloads = true;
        bool send_last_published_item = true;
        std::string access_model = "open"; // open, presence, roster, authorize, whitelist
    };

    struct PubSubItem {
        std::string id;
        std::string publisher;
        std::string payload_xmlns;
        std::string payload;
        time_t published_at;
    };

    explicit PubSubNode(const std::string& name) : name_(name) {
        created_at_ = std::time(nullptr);
    }

    const std::string& name() const { return name_; }

    void publish(const std::string& publisher, const std::string& payload_xmlns,
                 const std::string& payload, const std::string& item_id = "") {
        PubSubItem item;
        item.id = item_id.empty() ? generate_item_id() : item_id;
        item.publisher = publisher;
        item.payload_xmlns = payload_xmlns;
        item.payload = payload;
        item.published_at = std::time(nullptr);

        items_.push_back(item);

        // Trim to max_items
        while ((int)items_.size() > config_.max_items) {
            items_.erase(items_.begin());
        }
    }

    std::vector<PubSubItem> get_items(const std::string& max_id = "",
                                       int limit = 20) {
        std::vector<PubSubItem> result;
        for (auto& item : items_) {
            if (!max_id.empty() && item.id >= max_id) continue;
            result.push_back(item);
            if ((int)result.size() >= limit) break;
        }
        return result;
    }

    const PubSubItem* get_item(const std::string& id) const {
        for (auto& item : items_) {
            if (item.id == id) return &item;
        }
        return nullptr;
    }

    void delete_item(const std::string& id) {
        items_.erase(std::remove_if(items_.begin(), items_.end(),
            [&](const PubSubItem& i) { return i.id == id; }), items_.end());
    }

    void add_subscriber(const Jid& jid) { subscribers_.insert(jid.bare()); }
    void remove_subscriber(const Jid& jid) { subscribers_.erase(jid.bare()); }
    bool has_subscriber(const Jid& jid) const { return subscribers_.count(jid.bare()) > 0; }
    const std::unordered_set<std::string>& subscribers() const { return subscribers_; }

    PubSubConfig& config() { return config_; }

private:
    std::string name_;
    time_t created_at_;
    PubSubConfig config_;
    std::vector<PubSubItem> items_;
    std::unordered_set<std::string> subscribers_;

    static std::string generate_item_id() {
        static std::atomic<uint64_t> counter{0};
        char buf[32];
        snprintf(buf, sizeof(buf), "item-%lx-%lx",
                 (unsigned long)std::time(nullptr),
                 (unsigned long)counter.fetch_add(1));
        return std::string(buf);
    }
};

// =============================================================================
// Stream Management (XEP-0198)
// =============================================================================
class StreamManager {
public:
    struct StreamState {
        std::string stream_id;
        uint32_t server_count = 0;    // stanzas sent by server
        uint32_t client_count = 0;    // stanzas received from client
        bool resumed = false;
        std::vector<XmppStanza::ptr> unacked_queue;  // stanzas to resend
        time_t last_activity;
    };

    std::string create_session(const Jid& jid) {
        std::string sid = generate_stream_id();
        StreamState state;
        state.stream_id = sid;
        state.last_activity = std::time(nullptr);
        sessions_[sid] = state;
        jid_to_sid_[jid.full()] = sid;
        return sid;
    }

    void record_sent(const std::string& sid, XmppStanza::ptr stanza) {
        auto it = sessions_.find(sid);
        if (it == sessions_.end()) return;
        it->second.unacked_queue.push_back(stanza);
        it->second.server_count++;
    }

    bool acknowledge(const std::string& sid, uint32_t count) {
        auto it = sessions_.find(sid);
        if (it == sessions_.end()) return false;
        auto& state = it->second;

        // Remove acknowledged stanzas
        while (count > 0 && !state.unacked_queue.empty()) {
            state.unacked_queue.erase(state.unacked_queue.begin());
            count--;
        }
        state.client_count += count;
        state.last_activity = std::time(nullptr);
        return true;
    }

    bool request_ack(const std::string& sid) {
        auto it = sessions_.find(sid);
        if (it == sessions_.end()) return false;
        it->second.last_activity = std::time(nullptr);
        return true;
    }

    std::vector<XmppStanza::ptr> get_unacked(const std::string& sid) {
        auto it = sessions_.find(sid);
        if (it == sessions_.end()) return {};
        return it->second.unacked_queue;
    }

    void end_session(const std::string& sid) {
        auto it = sessions_.find(sid);
        if (it != sessions_.end()) {
            // Find and remove jid mapping
            for (auto jit = jid_to_sid_.begin(); jit != jid_to_sid_.end(); ) {
                if (jit->second == sid) jit = jid_to_sid_.erase(jit);
                else ++jit;
            }
            sessions_.erase(it);
        }
    }

    std::string find_session(const Jid& jid) const {
        auto it = jid_to_sid_.find(jid.full());
        return (it != jid_to_sid_.end()) ? it->second : "";
    }

private:
    std::unordered_map<std::string, StreamState> sessions_;
    std::unordered_map<std::string, std::string> jid_to_sid_;

    static std::string generate_stream_id() {
        static std::atomic<uint64_t> counter{0};
        char buf[32];
        snprintf(buf, sizeof(buf), "sid-%016lx", (unsigned long)counter.fetch_add(1));
        return std::string(buf);
    }
};

// =============================================================================
// Privacy Lists (XEP-0016)
// =============================================================================
struct PrivacyRule {
    enum Action { ALLOW, DENY };
    enum MatchType { JID, GROUP, SUBSCRIPTION };

    int order = 0;
    Action action = ALLOW;
    MatchType match_type = JID;
    std::string value;
    bool match_iq = true;
    bool match_message = true;
    bool match_presence_in = true;
    bool match_presence_out = true;
};

struct PrivacyList {
    std::string name;
    std::vector<PrivacyRule> rules;
    time_t created_at = 0;
    time_t updated_at = 0;
};

class PrivacyListManager {
public:
    void set_list(const std::string& user_jid, const PrivacyList& list) {
        privacy_lists_[user_jid][list.name] = list;
    }

    void delete_list(const std::string& user_jid, const std::string& name) {
        auto it = privacy_lists_.find(user_jid);
        if (it != privacy_lists_.end()) {
            it->second.erase(name);
        }
    }

    void set_default(const std::string& user_jid, const std::string& name) {
        defaults_[user_jid] = name;
    }

    void set_active(const std::string& user_jid, const std::string& name) {
        active_[user_jid] = name;
    }

    const PrivacyList* get_list(const std::string& user_jid, const std::string& name) const {
        auto it = privacy_lists_.find(user_jid);
        if (it == privacy_lists_.end()) return nullptr;
        auto lit = it->second.find(name);
        return (lit != it->second.end()) ? &lit->second : nullptr;
    }

    bool check(const std::string& user_jid, const Jid& sender,
               const std::string& stanza_type) {
        std::string active_name;
        auto ait = active_.find(user_jid);
        if (ait != active_.end()) active_name = ait->second;
        else {
            auto dit = defaults_.find(user_jid);
            if (dit != defaults_.end()) active_name = dit->second;
        }

        if (active_name.empty()) return true; // No privacy list = allow all

        auto list = get_list(user_jid, active_name);
        if (!list) return true;

        for (auto& rule : list->rules) {
            bool matches = false;
            if (rule.match_type == PrivacyRule::JID) {
                matches = sender.bare().find(rule.value) != std::string::npos;
            } else if (rule.match_type == PrivacyRule::SUBSCRIPTION) {
                matches = false; // Requires subscription lookup
            }

            if (!matches) continue;

            if (stanza_type == "message" && !rule.match_message) continue;
            if (stanza_type == "iq" && !rule.match_iq) continue;
            if (stanza_type == "presence_in" && !rule.match_presence_in) continue;
            if (stanza_type == "presence_out" && !rule.match_presence_out) continue;

            return rule.action == PrivacyRule::ALLOW;
        }

        return true; // No matching rule = allow (block by default if list exists)
    }

    std::vector<std::string> list_names(const std::string& user_jid) const {
        std::vector<std::string> result;
        auto it = privacy_lists_.find(user_jid);
        if (it != privacy_lists_.end()) {
            for (auto& [name, _] : it->second) {
                result.push_back(name);
            }
        }
        return result;
    }

private:
    std::unordered_map<std::string, std::unordered_map<std::string, PrivacyList>> privacy_lists_;
    std::unordered_map<std::string, std::string> defaults_;
    std::unordered_map<std::string, std::string> active_;
};

// =============================================================================
// Message Archive Management (XEP-0313)
// =============================================================================
struct ArchivedMessage {
    std::string id;
    time_t timestamp;
    Jid from;
    Jid to;
    std::string body;
    std::string subject;
    MessageType type = MessageType::CHAT;
    bool is_from_me = false;
};

class MamArchive {
public:
    void store(const ArchivedMessage& msg) {
        std::lock_guard lock(mutex_);
        std::string key = make_key(msg.from, msg.to);
        archives_[key].push_back(msg);
        // Trim to limit
        if (archives_[key].size() > max_archive_size_) {
            archives_[key].erase(archives_[key].begin(),
                                 archives_[key].begin() +
                                 (archives_[key].size() - max_archive_size_));
        }
    }

    std::vector<ArchivedMessage> query(const Jid& user, const Jid& with = {},
                                        time_t start = 0, time_t end = 0,
                                        int max = 50) {
        std::lock_guard lock(mutex_);
        std::string key = make_key(user, with);
        auto it = archives_.find(key);
        if (it == archives_.end()) return {};

        std::vector<ArchivedMessage> result;
        for (auto& msg : it->second) {
            if (start > 0 && msg.timestamp < start) continue;
            if (end > 0 && msg.timestamp > end) continue;
            result.push_back(msg);
        }

        // Return latest first
        std::reverse(result.begin(), result.end());
        if ((int)result.size() > max) {
            result.resize(max);
        }
        return result;
    }

private:
    static std::string make_key(const Jid& a, const Jid& b) {
        std::string k1 = a.bare(), k2 = b.bare();
        if (k1 > k2) std::swap(k1, k2);
        return k1 + "|" + k2;
    }

    std::unordered_map<std::string, std::vector<ArchivedMessage>> archives_;
    mutable std::mutex mutex_;
    size_t max_archive_size_ = 1000;
};

// =============================================================================
// S2S / Federation
// =============================================================================
struct ServerSession {
    std::string remote_domain;
    std::string stream_id;
    int fd = -1;
    bool authenticated = false;
    bool encrypted = false;
    time_t connected_at = 0;
    time_t last_activity = 0;
    std::string tls_version;
    std::string tls_cipher;
    std::string sasl_mechanism;
    std::vector<std::string> features;
};

// =============================================================================
// C2S Session (Client-to-Server)
// =============================================================================
struct C2sSession {
    Jid user_jid;
    std::string stream_id;
    int fd = -1;
    bool authenticated = false;
    bool encrypted = false;
    bool resource_bound = false;
    bool session_established = false;
    time_t connected_at = 0;
    time_t last_activity = 0;
    std::string auth_method;
    std::string tls_version;
    std::string tls_cipher;
    PresenceShow presence_show = PresenceShow::ONLINE;
    std::string presence_status;
    int presence_priority = 0;
    std::vector<std::string> caps_features;
    std::string caps_hash;
    std::string caps_node;
    std::string caps_ver;
    std::string software_version_name;
    std::string software_version_os;
    std::string software_version;
};

} // namespace xmpp
} // namespace progressive
