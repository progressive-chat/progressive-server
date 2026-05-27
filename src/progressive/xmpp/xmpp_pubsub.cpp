/*
 * progressive-server - XMPP PubSub (XEP-0060) and PEP (XEP-0163) Implementation
 *
 * This file implements a comprehensive XMPP PubSub service including:
 *   - Node creation, deletion, purging, and lifecycle management
 *   - Node configuration via XEP-0004 data forms
 *   - Subscribe, unsubscribe, and subscription option management
 *   - Item publishing with auto-generated IDs and item retraction
 *   - Event notifications (XEP-0060 pubsub#event)
 *   - Last published item caching per XEP-0060 Section 12.20
 *   - Collection nodes (XEP-0248)
 *   - Access models: open, presence, roster, authorize, whitelist
 *   - Affiliations: owner, publisher, publisher-only, member, none, outcast
 *   - Subscriptions: subscribed, pending, unconfigured, none
 *   - PEP (Personal Eventing Protocol) with auto-subscribe and presence-based delivery
 *   - DISCO#items and DISCO#info for nodes and service
 *   - Default node configuration
 *   - Node types: leaf and collection
 *   - Subscription state machine
 */

#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <memory>
#include <optional>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <mutex>
#include <functional>
#include <chrono>
#include <random>
#include <set>
#include <deque>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <atomic>
#include <cstring>
#include <cctype>

namespace progressive {
namespace xmpp {

// ============================================================================
// Forward declarations
// ============================================================================

class PubSubNode;
class PubSubItemRecord;
class PubSubSubscription;
class PubSubService;
class PEPHandler;
class PubSubManager;

// ============================================================================
// Enumerations and Constants
// ============================================================================

enum class PubSubAffiliation {
    NONE            = 0,
    OWNER           = 1,
    PUBLISHER       = 2,
    PUBLISHER_ONLY  = 3,
    MEMBER          = 4,
    OUTCAST         = 5
};

enum class PubSubSubscriptionState {
    NONE            = 0,
    SUBSCRIBED      = 1,
    PENDING         = 2,
    UNCONFIGURED    = 3
};

enum class PubSubAccessModel {
    OPEN            = 0,
    PRESENCE        = 1,
    ROSTER          = 2,
    AUTHORIZE       = 3,
    WHITELIST       = 4
};

enum class PubSubNodeType {
    LEAF            = 0,
    COLLECTION      = 1
};

enum class PubSubNodeState {
    CREATING        = 0,
    ACTIVE          = 1,
    PURGED          = 2,
    DELETED         = 3
};

enum class PubSubIQAction {
    UNKNOWN,
    CREATE,
    CONFIGURE,
    DEFAULT_CONFIG,
    SUBSCRIBE,
    UNSUBSCRIBE,
    PUBLISH,
    RETRACT,
    ITEMS,
    DELETE_NODE,
    PURGE,
    AFFILIATIONS_GET,
    AFFILIATIONS_SET,
    SUBSCRIPTIONS_GET,
    SUBSCRIPTIONS_SET,
    SUBSCRIPTION_OPTIONS_GET,
    SUBSCRIPTION_OPTIONS_SET,
    DISCO_INFO,
    DISCO_ITEMS,
    OWNER_CONFIG_GET,
    OWNER_CONFIG_SET,
    OWNER_DELETE,
    OWNER_PURGE,
    OWNER_DEFAULT
};

inline const char* pubsub_affiliation_to_string(PubSubAffiliation aff) {
    switch (aff) {
        case PubSubAffiliation::NONE:            return "none";
        case PubSubAffiliation::OWNER:           return "owner";
        case PubSubAffiliation::PUBLISHER:       return "publisher";
        case PubSubAffiliation::PUBLISHER_ONLY:  return "publisher-only";
        case PubSubAffiliation::MEMBER:          return "member";
        case PubSubAffiliation::OUTCAST:         return "outcast";
        default: return "none";
    }
}

inline PubSubAffiliation pubsub_affiliation_from_string(const std::string& s) {
    if (s == "owner")           return PubSubAffiliation::OWNER;
    if (s == "publisher")       return PubSubAffiliation::PUBLISHER;
    if (s == "publisher-only")  return PubSubAffiliation::PUBLISHER_ONLY;
    if (s == "member")          return PubSubAffiliation::MEMBER;
    if (s == "outcast")         return PubSubAffiliation::OUTCAST;
    return PubSubAffiliation::NONE;
}

inline const char* pubsub_subscription_state_to_string(PubSubSubscriptionState st) {
    switch (st) {
        case PubSubSubscriptionState::NONE:          return "none";
        case PubSubSubscriptionState::SUBSCRIBED:    return "subscribed";
        case PubSubSubscriptionState::PENDING:       return "pending";
        case PubSubSubscriptionState::UNCONFIGURED:  return "unconfigured";
        default: return "none";
    }
}

inline PubSubSubscriptionState pubsub_subscription_state_from_string(const std::string& s) {
    if (s == "subscribed")   return PubSubSubscriptionState::SUBSCRIBED;
    if (s == "pending")      return PubSubSubscriptionState::PENDING;
    if (s == "unconfigured") return PubSubSubscriptionState::UNCONFIGURED;
    return PubSubSubscriptionState::NONE;
}

inline const char* pubsub_access_model_to_string(PubSubAccessModel am) {
    switch (am) {
        case PubSubAccessModel::OPEN:       return "open";
        case PubSubAccessModel::PRESENCE:   return "presence";
        case PubSubAccessModel::ROSTER:     return "roster";
        case PubSubAccessModel::AUTHORIZE:  return "authorize";
        case PubSubAccessModel::WHITELIST:  return "whitelist";
        default: return "open";
    }
}

inline PubSubAccessModel pubsub_access_model_from_string(const std::string& s) {
    if (s == "presence")   return PubSubAccessModel::PRESENCE;
    if (s == "roster")     return PubSubAccessModel::ROSTER;
    if (s == "authorize")  return PubSubAccessModel::AUTHORIZE;
    if (s == "whitelist")  return PubSubAccessModel::WHITELIST;
    return PubSubAccessModel::OPEN;
}

inline const char* pubsub_node_type_to_string(PubSubNodeType nt) {
    switch (nt) {
        case PubSubNodeType::LEAF:       return "leaf";
        case PubSubNodeType::COLLECTION: return "collection";
        default: return "leaf";
    }
}

inline PubSubNodeType pubsub_node_type_from_string(const std::string& s) {
    if (s == "collection") return PubSubNodeType::COLLECTION;
    return PubSubNodeType::LEAF;
}

// ============================================================================
// XMPP Namespaces
// ============================================================================

namespace XMPPNS {
    const char* PUBSUB             = "http://jabber.org/protocol/pubsub";
    const char* PUBSUB_EVENT       = "http://jabber.org/protocol/pubsub#event";
    const char* PUBSUB_OWNER       = "http://jabber.org/protocol/pubsub#owner";
    const char* PUBSUB_NODE_CONFIG = "http://jabber.org/protocol/pubsub#node_config";
    const char* PUBSUB_META_DATA   = "http://jabber.org/protocol/pubsub#meta-data";
    const char* PUBSUB_SUBSCRIBE_OPTIONS = "http://jabber.org/protocol/pubsub#subscribe_options";
    const char* PUBSUB_ERRORS      = "http://jabber.org/protocol/pubsub#errors";
    const char* PUBSUB_COLLECTIONS = "http://jabber.org/protocol/pubsub#collections";
    const char* DISCO_INFO         = "http://jabber.org/protocol/disco#info";
    const char* DISCO_ITEMS        = "http://jabber.org/protocol/disco#items";
    const char* X_DATA             = "jabber:x:data";
    const char* DELAY2             = "urn:xmpp:delay";
    const char* SHIM               = "http://jabber.org/protocol/shim";
    const char* PEP                = "http://jabber.org/protocol/pubsub#event";
}

// ============================================================================
// PubSubCondition - Error condition codes per XEP-0060
// ============================================================================

namespace PubSubError {
    const char* CLOSED_NODE           = "closed-node";
    const char* CONFIGURATION_REQUIRED = "configuration-required";
    const char* INVALID_JID           = "invalid-jid";
    const char* ITEM_FORBIDDEN        = "item-forbidden";
    const char* ITEM_REQUIRED         = "item-required";
    const char* JID_REQUIRED          = "jid-required";
    const char* MAX_ITEMS_EXCEEDED    = "max-items-exceeded";
    const char* MAX_NODES_EXCEEDED    = "max-nodes-exceeded";
    const char* NODEID_REQUIRED       = "nodeid-required";
    const char* NOT_IN_ROSTER_GROUP   = "not-in-roster-group";
    const char* NOT_SUBSCRIBED        = "not-subscribed";
    const char* PAYLOAD_TOO_BIG       = "payload-too-big";
    const char* PAYLOAD_REQUIRED      = "payload-required";
    const char* PENDING_SUBSCRIPTION  = "pending-subscription";
    const char* PRESENCE_SUBSCRIPTION_REQUIRED = "presence-subscription-required";
    const char* SUBID_REQUIRED        = "subid-required";
    const char* TOO_MANY_SUBSCRIPTIONS = "too-many-subscriptions";
    const char* UNSUPPORTED           = "unsupported";
    const char* UNSUPPORTED_ACCESS_MODEL = "unsupported-access-model";
}

// ============================================================================
// PubSubItemRecord - A single published item
// ============================================================================

class PubSubItemRecord {
public:
    PubSubItemRecord()
        : creation_time_(std::chrono::system_clock::now())
        , payload_size_(0)
    {}

    PubSubItemRecord(const std::string& id, const std::string& publisher,
                     const std::string& payload)
        : id_(id)
        , publisher_(publisher)
        , payload_(payload)
        , creation_time_(std::chrono::system_clock::now())
        , payload_size_(payload.size())
    {}

    const std::string& id() const { return id_; }
    void set_id(const std::string& id) { id_ = id; }

    const std::string& publisher() const { return publisher_; }
    void set_publisher(const std::string& p) { publisher_ = p; }

    const std::string& payload() const { return payload_; }
    void set_payload(const std::string& p) { payload_ = p; payload_size_ = p.size(); }

    std::chrono::system_clock::time_point creation_time() const { return creation_time_; }
    void set_creation_time(std::chrono::system_clock::time_point t) { creation_time_ = t; }

    size_t payload_size() const { return payload_size_; }

    std::string to_stamp() const {
        auto t = std::chrono::system_clock::to_time_t(creation_time_);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<item";
        if (!id_.empty()) {
            oss << " id=\"" << xml_escape(id_) << "\"";
        }
        if (!publisher_.empty()) {
            oss << " publisher=\"" << xml_escape(publisher_) << "\"";
        }
        oss << ">";
        if (!payload_.empty()) {
            oss << payload_;
        }
        oss << "</item>";
        return oss.str();
    }

    std::string to_event_xml(bool include_payload) const {
        std::ostringstream oss;
        oss << "<item";
        if (!id_.empty()) {
            oss << " id=\"" << xml_escape(id_) << "\"";
        }
        if (!publisher_.empty()) {
            oss << " publisher=\"" << xml_escape(publisher_) << "\"";
        }
        oss << ">";
        if (include_payload && !payload_.empty()) {
            oss << payload_;
        }
        oss << "</item>";
        return oss.str();
    }

private:
    static std::string xml_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '\"':  out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default:   out += c; break;
            }
        }
        return out;
    }

    std::string id_;
    std::string publisher_;
    std::string payload_;
    std::chrono::system_clock::time_point creation_time_;
    size_t payload_size_;
};

// ============================================================================
// PubSubSubscription - Represents a subscription to a node
// ============================================================================

class PubSubSubscription {
public:
    PubSubSubscription()
        : state_(PubSubSubscriptionState::NONE)
        , subscription_id_("")
    {}

    PubSubSubscription(const std::string& jid, PubSubSubscriptionState state,
                       const std::string& subid = "")
        : jid_(jid)
        , state_(state)
        , subscription_id_(subid)
        , created_at_(std::chrono::system_clock::now())
        , digest_enabled_(false)
        , digest_frequency_(0)
        , include_body_(true)
        , expires_never_(true)
    {}

    const std::string& jid() const { return jid_; }
    void set_jid(const std::string& j) { jid_ = j; }

    PubSubSubscriptionState state() const { return state_; }
    void set_state(PubSubSubscriptionState s) { state_ = s; }

    const std::string& subscription_id() const { return subscription_id_; }
    void set_subscription_id(const std::string& sid) { subscription_id_ = sid; }

    std::chrono::system_clock::time_point created_at() const { return created_at_; }

    bool digest_enabled() const { return digest_enabled_; }
    void set_digest_enabled(bool d) { digest_enabled_ = d; }

    int digest_frequency() const { return digest_frequency_; }
    void set_digest_frequency(int f) { digest_frequency_ = f; }

    bool include_body() const { return include_body_; }
    void set_include_body(bool b) { include_body_ = b; }

    bool expires_never() const { return expires_never_; }
    void set_expires_never(bool e) { expires_never_ = e; }

    std::chrono::system_clock::time_point expires_at() const { return expires_at_; }
    void set_expires_at(std::chrono::system_clock::time_point t) { expires_at_ = t; expires_never_ = false; }

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<subscription";
        oss << " jid=\"" << xml_escape(jid_) << "\"";
        oss << " subscription=\"" << pubsub_subscription_state_to_string(state_) << "\"";
        if (!subscription_id_.empty()) {
            oss << " subid=\"" << xml_escape(subscription_id_) << "\"";
        }
        oss << "/>";
        return oss.str();
    }

    std::string to_affiliation_xml() const {
        std::ostringstream oss;
        oss << "<subscription";
        oss << " jid=\"" << xml_escape(jid_) << "\"";
        oss << " subscription=\"" << pubsub_subscription_state_to_string(state_) << "\"";
        if (!subscription_id_.empty()) {
            oss << " subid=\"" << xml_escape(subscription_id_) << "\"";
        }
        oss << "/>";
        return oss.str();
    }

private:
    static std::string xml_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '\"':  out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default:   out += c; break;
            }
        }
        return out;
    }

    std::string jid_;
    PubSubSubscriptionState state_;
    std::string subscription_id_;
    std::chrono::system_clock::time_point created_at_;
    bool digest_enabled_;
    int digest_frequency_;
    bool include_body_;
    bool expires_never_;
    std::chrono::system_clock::time_point expires_at_;
};

// ============================================================================
// PubSubNodeConfig - Configuration for a PubSub node
// ============================================================================

struct PubSubNodeConfig {
    // General options
    std::string title;
    std::string description;
    std::string language;

    // Access options
    PubSubAccessModel access_model = PubSubAccessModel::OPEN;
    std::set<std::string> roster_groups_allowed;

    // Publishing options
    bool persist_items = false;
    int max_items = 0;  // 0 = unlimited
    int max_payload_size = 0;  // 0 = unlimited
    bool deliver_payloads = true;
    bool deliver_notifications = true;
    bool send_last_published_item = true;

    // Subscription options
    bool subscribe = true;
    bool subscription_required = false;

    // Item expiry
    int item_expire_seconds = 0;  // 0 = never

    // Notification types
    bool notify_config = false;
    bool notify_delete = false;
    bool notify_retract = false;
    bool notify_sub = false;
    bool notify_unsub = false;

    // Collection options
    std::string collection_parent_id;  // empty = no parent

    // PEP options
    bool is_pep_node = false;

    // Misc
    std::string data_form_xml;  // raw form XML for pass-through

    // Creator
    std::string creator;

    // Creation time
    std::chrono::system_clock::time_point created_at;

    PubSubNodeConfig() : created_at(std::chrono::system_clock::now()) {}

    // Generate a default configuration data form
    std::string to_config_form_xml() const {
        std::ostringstream oss;
        oss << "<x xmlns=\"" << XMPPNS::X_DATA << "\" type=\"form\">";
        oss << "<title>Node Configuration</title>";
        oss << "<instructions>Configure the PubSub node</instructions>";

        // FORM_TYPE
        oss << "<field var=\"FORM_TYPE\" type=\"hidden\">";
        oss << "<value>" << xml_escape(XMPPNS::PUBSUB_NODE_CONFIG) << "</value>";
        oss << "</field>";

        // pubsub#title
        oss << "<field var=\"pubsub#title\" type=\"text-single\" label=\"Title\">";
        oss << "<value>" << xml_escape(title) << "</value>";
        oss << "</field>";

        // pubsub#description
        oss << "<field var=\"pubsub#description\" type=\"text-single\" label=\"Description\">";
        oss << "<value>" << xml_escape(description) << "</value>";
        oss << "</field>";

        // pubsub#access_model
        oss << "<field var=\"pubsub#access_model\" type=\"list-single\" label=\"Access Model\">";
        oss << "<value>" << pubsub_access_model_to_string(access_model) << "</value>";
        oss << "<option label=\"Open\"><value>open</value></option>";
        oss << "<option label=\"Presence\"><value>presence</value></option>";
        oss << "<option label=\"Roster\"><value>roster</value></option>";
        oss << "<option label=\"Authorize\"><value>authorize</value></option>";
        oss << "<option label=\"Whitelist\"><value>whitelist</value></option>";
        oss << "</field>";

        // pubsub#persist_items
        oss << "<field var=\"pubsub#persist_items\" type=\"boolean\" label=\"Persist Items\">";
        oss << "<value>" << (persist_items ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#max_items
        oss << "<field var=\"pubsub#max_items\" type=\"text-single\" label=\"Max Items\">";
        oss << "<value>" << max_items << "</value>";
        oss << "</field>";

        // pubsub#deliver_payloads
        oss << "<field var=\"pubsub#deliver_payloads\" type=\"boolean\" label=\"Deliver payloads with event notifications\">";
        oss << "<value>" << (deliver_payloads ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#deliver_notifications
        oss << "<field var=\"pubsub#deliver_notifications\" type=\"boolean\">";
        oss << "<value>" << (deliver_notifications ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#send_last_published_item
        oss << "<field var=\"pubsub#send_last_published_item\" type=\"list-single\" label=\"Send last published item\">";
        oss << "<value>" << (send_last_published_item ? "on_sub_and_presence" : "never") << "</value>";
        oss << "<option label=\"Never\"><value>never</value></option>";
        oss << "<option label=\"On sub and presence\"><value>on_sub_and_presence</value></option>";
        oss << "<option label=\"On sub\"><value>on_sub</value></option>";
        oss << "<option label=\"On presence\"><value>on_presence</value></option>";
        oss << "</field>";

        // pubsub#subscribe
        oss << "<field var=\"pubsub#subscribe\" type=\"boolean\" label=\"Whether to subscribe\">";
        oss << "<value>" << (subscribe ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#subscription_required
        oss << "<field var=\"pubsub#subscription_required\" type=\"boolean\">";
        oss << "<value>" << (subscription_required ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#notify_config
        oss << "<field var=\"pubsub#notify_config\" type=\"boolean\">";
        oss << "<value>" << (notify_config ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#notify_delete
        oss << "<field var=\"pubsub#notify_delete\" type=\"boolean\">";
        oss << "<value>" << (notify_delete ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#notify_retract
        oss << "<field var=\"pubsub#notify_retract\" type=\"boolean\">";
        oss << "<value>" << (notify_retract ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#item_expire
        oss << "<field var=\"pubsub#item_expire\" type=\"text-single\">";
        oss << "<value>" << item_expire_seconds << "</value>";
        oss << "</field>";

        // pubsub#max_payload_size
        oss << "<field var=\"pubsub#max_payload_size\" type=\"text-single\">";
        oss << "<value>" << max_payload_size << "</value>";
        oss << "</field>";

        // pubsub#collection
        if (!collection_parent_id.empty()) {
            oss << "<field var=\"pubsub#collection\" type=\"text-single\">";
            oss << "<value>" << xml_escape(collection_parent_id) << "</value>";
            oss << "</field>";
        }

        oss << "</x>";
        return oss.str();
    }

    // Generate a submit form for the current config
    std::string to_submit_form_xml() const {
        std::ostringstream oss;
        oss << "<x xmlns=\"" << XMPPNS::X_DATA << "\" type=\"submit\">";
        oss << "<field var=\"FORM_TYPE\"><value>" << xml_escape(XMPPNS::PUBSUB_NODE_CONFIG) << "</value></field>";
        if (!title.empty())
            oss << "<field var=\"pubsub#title\"><value>" << xml_escape(title) << "</value></field>";
        if (!description.empty())
            oss << "<field var=\"pubsub#description\"><value>" << xml_escape(description) << "</value></field>";
        oss << "<field var=\"pubsub#access_model\"><value>" << pubsub_access_model_to_string(access_model) << "</value></field>";
        oss << "<field var=\"pubsub#persist_items\"><value>" << (persist_items ? "1" : "0") << "</value></field>";
        oss << "<field var=\"pubsub#max_items\"><value>" << max_items << "</value></field>";
        oss << "<field var=\"pubsub#deliver_payloads\"><value>" << (deliver_payloads ? "1" : "0") << "</value></field>";
        oss << "<field var=\"pubsub#deliver_notifications\"><value>" << (deliver_notifications ? "1" : "0") << "</value></field>";
        oss << "<field var=\"pubsub#send_last_published_item\"><value>" << (send_last_published_item ? "on_sub_and_presence" : "never") << "</value></field>";
        oss << "<field var=\"pubsub#notify_config\"><value>" << (notify_config ? "1" : "0") << "</value></field>";
        oss << "<field var=\"pubsub#notify_delete\"><value>" << (notify_delete ? "1" : "0") << "</value></field>";
        oss << "<field var=\"pubsub#notify_retract\"><value>" << (notify_retract ? "1" : "0") << "</value></field>";
        oss << "</x>";
        return oss.str();
    }

    // Parse config from a data form
    void apply_form_fields(const std::map<std::string, std::vector<std::string>>& fields) {
        for (const auto& [var, values] : fields) {
            if (values.empty()) continue;
            const std::string& val = values[0];

            if (var == "pubsub#title") title = val;
            else if (var == "pubsub#description") description = val;
            else if (var == "pubsub#access_model") access_model = pubsub_access_model_from_string(val);
            else if (var == "pubsub#persist_items") persist_items = (val == "1" || val == "true");
            else if (var == "pubsub#max_items") {
                try { max_items = std::stoi(val); }
                catch (...) { max_items = 0; }
            }
            else if (var == "pubsub#deliver_payloads") deliver_payloads = (val == "1" || val == "true");
            else if (var == "pubsub#deliver_notifications") deliver_notifications = (val == "1" || val == "true");
            else if (var == "pubsub#send_last_published_item") {
                send_last_published_item = (val != "never");
            }
            else if (var == "pubsub#subscribe") subscribe = (val == "1" || val == "true");
            else if (var == "pubsub#subscription_required") subscription_required = (val == "1" || val == "true");
            else if (var == "pubsub#notify_config") notify_config = (val == "1" || val == "true");
            else if (var == "pubsub#notify_delete") notify_delete = (val == "1" || val == "true");
            else if (var == "pubsub#notify_retract") notify_retract = (val == "1" || val == "true");
            else if (var == "pubsub#item_expire") {
                try { item_expire_seconds = std::stoi(val); }
                catch (...) { item_expire_seconds = 0; }
            }
            else if (var == "pubsub#max_payload_size") {
                try { max_payload_size = std::stoi(val); }
                catch (...) { max_payload_size = 0; }
            }
            else if (var == "pubsub#collection") {
                collection_parent_id = val;
            }
            else if (var == "pubsub#notify_sub") notify_sub = (val == "1" || val == "true");
            else if (var == "pubsub#notify_unsub") notify_unsub = (val == "1" || val == "true");
        }
    }

private:
    static std::string xml_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&': out += "&amp;"; break;
                case '<': out += "&lt;"; break;
                case '>': out += "&gt;"; break;
                case '\"': out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default: out += c; break;
            }
        }
        return out;
    }
};

// ============================================================================
// PubSubNode - Represents a single PubSub node (leaf or collection)
// ============================================================================

class PubSubNode {
public:
    using ItemPtr = std::shared_ptr<PubSubItemRecord>;
    using SubscriptionPtr = std::shared_ptr<PubSubSubscription>;
    using SendCallback = std::function<void(const std::string& stanza_xml)>;

    PubSubNode(const std::string& node_id, const std::string& service_jid,
               const std::string& creator_jid, PubSubNodeType type,
               SendCallback send_cb)
        : node_id_(node_id)
        , service_jid_(service_jid)
        , type_(type)
        , state_(PubSubNodeState::CREATING)
        , send_callback_(send_cb)
        , next_item_sequence_(0)
    {
        config_.creator = creator_jid;
        config_.access_model = PubSubAccessModel::OPEN;
        config_.persist_items = true;
        config_.max_items = 0;
        config_.deliver_payloads = true;
        config_.deliver_notifications = true;
        config_.send_last_published_item = true;

        // Creator is always an owner
        affiliations_[bare_jid(creator_jid)] = PubSubAffiliation::OWNER;
    }

    // ========================================================================
    // Node identity
    // ========================================================================

    const std::string& node_id() const { return node_id_; }

    PubSubNodeType type() const { return type_; }
    void set_type(PubSubNodeType t) { type_ = t; }

    PubSubNodeState state() const { return state_; }
    void set_state(PubSubNodeState s) { state_ = s; }

    bool is_leaf() const { return type_ == PubSubNodeType::LEAF; }
    bool is_collection() const { return type_ == PubSubNodeType::COLLECTION; }
    bool is_active() const { return state_ == PubSubNodeState::ACTIVE; }
    bool is_deleted() const { return state_ == PubSubNodeState::DELETED; }

    const std::string& service_jid() const { return service_jid_; }

    PubSubNodeConfig& config() { return config_; }
    const PubSubNodeConfig& config() const { return config_; }
    void set_config(const PubSubNodeConfig& c) { config_ = c; }

    // ========================================================================
    // Affiliation management
    // ========================================================================

    PubSubAffiliation get_affiliation(const std::string& jid) const {
        std::lock_guard<std::mutex> lock(node_mutex_);
        std::string bare = bare_jid(jid);
        auto it = affiliations_.find(bare);
        if (it != affiliations_.end()) {
            return it->second;
        }
        return PubSubAffiliation::NONE;
    }

    void set_affiliation(const std::string& jid, PubSubAffiliation aff) {
        std::lock_guard<std::mutex> lock(node_mutex_);
        std::string bare = bare_jid(jid);
        if (aff == PubSubAffiliation::NONE) {
            affiliations_.erase(bare);
        } else {
            affiliations_[bare] = aff;
        }
    }

    bool is_owner(const std::string& jid) const {
        return get_affiliation(jid) == PubSubAffiliation::OWNER;
    }

    bool can_publish(const std::string& jid) const {
        PubSubAffiliation aff = get_affiliation(jid);
        return aff == PubSubAffiliation::OWNER ||
               aff == PubSubAffiliation::PUBLISHER ||
               (aff == PubSubAffiliation::MEMBER && config_.access_model == PubSubAccessModel::OPEN) ||
               (aff == PubSubAffiliation::NONE && config_.access_model == PubSubAccessModel::OPEN);
    }

    bool can_subscribe(const std::string& jid) const {
        if (config_.subscription_required) {
            PubSubAffiliation aff = get_affiliation(jid);
            if (aff != PubSubAffiliation::OWNER && aff != PubSubAffiliation::MEMBER) {
                return false;
            }
        }

        PubSubAffiliation aff = get_affiliation(jid);
        if (aff == PubSubAffiliation::OUTCAST) return false;

        switch (config_.access_model) {
            case PubSubAccessModel::OPEN:
                return true;
            case PubSubAccessModel::PRESENCE:
                return aff == PubSubAffiliation::OWNER ||
                       aff == PubSubAffiliation::PUBLISHER ||
                       aff == PubSubAffiliation::MEMBER;
            case PubSubAccessModel::ROSTER:
                return aff != PubSubAffiliation::NONE;
            case PubSubAccessModel::WHITELIST:
                return aff == PubSubAffiliation::OWNER ||
                       aff == PubSubAffiliation::PUBLISHER ||
                       aff == PubSubAffiliation::MEMBER;
            case PubSubAccessModel::AUTHORIZE:
                return true;  // Authorization handled at subscribe time
        }
        return false;
    }

    std::map<std::string, PubSubAffiliation> get_all_affiliations() const {
        std::lock_guard<std::mutex> lock(node_mutex_);
        return affiliations_;
    }

    // ========================================================================
    // Subscription management
    // ========================================================================

    std::vector<SubscriptionPtr> get_subscriptions() const {
        std::lock_guard<std::mutex> lock(node_mutex_);
        std::vector<SubscriptionPtr> result;
        for (const auto& pair : subscriptions_) {
            result.push_back(pair.second);
        }
        return result;
    }

    SubscriptionPtr get_subscription(const std::string& jid) const {
        std::lock_guard<std::mutex> lock(node_mutex_);
        std::string bare = bare_jid(jid);
        auto it = subscriptions_.find(bare);
        if (it != subscriptions_.end()) {
            return it->second;
        }
        return nullptr;
    }

    PubSubSubscriptionState get_subscription_state(const std::string& jid) const {
        auto sub = get_subscription(jid);
        if (sub) return sub->state();
        return PubSubSubscriptionState::NONE;
    }

    bool is_subscribed(const std::string& jid) const {
        auto sub = get_subscription(jid);
        return sub && sub->state() == PubSubSubscriptionState::SUBSCRIBED;
    }

    bool add_subscription(const std::string& jid, PubSubSubscriptionState state,
                          const std::string& subid = "") {
        std::lock_guard<std::mutex> lock(node_mutex_);
        std::string bare = bare_jid(jid);
        auto it = subscriptions_.find(bare);
        if (it != subscriptions_.end()) {
            it->second->set_state(state);
            return true;
        }

        auto sub = std::make_shared<PubSubSubscription>(bare, state, subid);
        subscriptions_[bare] = sub;
        return true;
    }

    bool remove_subscription(const std::string& jid) {
        std::lock_guard<std::mutex> lock(node_mutex_);
        std::string bare = bare_jid(jid);
        auto it = subscriptions_.find(bare);
        if (it != subscriptions_.end()) {
            subscriptions_.erase(it);
            return true;
        }
        return false;
    }

    int subscription_count() const {
        std::lock_guard<std::mutex> lock(node_mutex_);
        int count = 0;
        for (const auto& pair : subscriptions_) {
            if (pair.second->state() == PubSubSubscriptionState::SUBSCRIBED) {
                ++count;
            }
        }
        return count;
    }

    // ========================================================================
    // Item management
    // ========================================================================

    std::string publish_item(const std::string& publisher, const std::string& payload,
                             const std::string& item_id = "") {
        std::lock_guard<std::mutex> lock(node_mutex_);

        if (!can_publish(publisher)) {
            return "";  // Not authorized
        }

        // Check payload size limit
        if (config_.max_payload_size > 0 &&
            payload.size() > static_cast<size_t>(config_.max_payload_size)) {
            return "";  // Payload too big, signaled via empty return
        }

        std::string actual_id = item_id;
        if (actual_id.empty()) {
            actual_id = generate_item_id();
        }

        auto item = std::make_shared<PubSubItemRecord>(actual_id, publisher, payload);

        // Check if this is an update to an existing item
        bool is_update = false;
        for (size_t i = 0; i < items_.size(); ++i) {
            if (items_[i]->id() == actual_id) {
                items_[i] = item;
                is_update = true;
                break;
            }
        }

        if (!is_update) {
            items_.push_back(item);

            // Enforce max_items
            if (config_.max_items > 0) {
                while (items_.size() > static_cast<size_t>(config_.max_items)) {
                    items_.erase(items_.begin());
                }
            }
        }

        // Update last published item cache
        last_published_item_ = item;

        return actual_id;
    }

    bool retract_item(const std::string& requester, const std::string& item_id) {
        std::lock_guard<std::mutex> lock(node_mutex_);

        if (!can_publish(requester)) {
            return false;
        }

        for (auto it = items_.begin(); it != items_.end(); ++it) {
            if ((*it)->id() == item_id) {
                retracted_ids_.insert(item_id);
                items_.erase(it);

                // Clear last published item if it was retracted
                if (last_published_item_ && last_published_item_->id() == item_id) {
                    if (!items_.empty()) {
                        last_published_item_ = items_.back();
                    } else {
                        last_published_item_.reset();
                    }
                }
                return true;
            }
        }
        return false;
    }

    std::vector<ItemPtr> get_items(const std::string& requester,
                                   const std::string& max_items_str = "",
                                   const std::string& item_id = "") const {
        std::lock_guard<std::mutex> lock(node_mutex_);

        std::vector<ItemPtr> result;

        if (!item_id.empty()) {
            // Return a specific item
            for (const auto& item : items_) {
                if (item->id() == item_id) {
                    result.push_back(item);
                    break;
                }
            }
        } else {
            int max_count = items_.size();
            if (!max_items_str.empty()) {
                try { max_count = std::min(max_count, std::stoi(max_items_str)); }
                catch (...) {}
            }

            // Return most recent items first
            int start = std::max(0, static_cast<int>(items_.size()) - max_count);
            for (size_t i = static_cast<size_t>(start); i < items_.size(); ++i) {
                result.push_back(items_[i]);
            }
        }

        return result;
    }

    ItemPtr get_last_published_item() const {
        std::lock_guard<std::mutex> lock(node_mutex_);
        return last_published_item_;
    }

    int item_count() const {
        std::lock_guard<std::mutex> lock(node_mutex_);
        return static_cast<int>(items_.size());
    }

    bool is_item_retracted(const std::string& item_id) const {
        std::lock_guard<std::mutex> lock(node_mutex_);
        return retracted_ids_.find(item_id) != retracted_ids_.end();
    }

    // ========================================================================
    // Purge and delete
    // ========================================================================

    void purge() {
        std::lock_guard<std::mutex> lock(node_mutex_);
        items_.clear();
        last_published_item_.reset();
        retracted_ids_.clear();
        next_item_sequence_ = 0;
    }

    void mark_deleted() {
        state_ = PubSubNodeState::DELETED;
    }

    // ========================================================================
    // Collection node support
    // ========================================================================

    void add_child_node_id(const std::string& child_id) {
        std::lock_guard<std::mutex> lock(node_mutex_);
        child_node_ids_.insert(child_id);
    }

    void remove_child_node_id(const std::string& child_id) {
        std::lock_guard<std::mutex> lock(node_mutex_);
        child_node_ids_.erase(child_id);
    }

    const std::set<std::string>& child_node_ids() const {
        return child_node_ids_;
    }

    void set_parent_collection_id(const std::string& parent_id) {
        config_.collection_parent_id = parent_id;
    }

    const std::string& parent_collection_id() const {
        return config_.collection_parent_id;
    }

    // ========================================================================
    // Notification building
    // ========================================================================

    std::string build_publish_notification(const std::string& item_id,
                                           const std::string& publisher) const {
        std::lock_guard<std::mutex> lock(node_mutex_);

        auto item = find_item_by_id(item_id);
        if (!item) return "";

        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(get_node_jid()) << "\"";
        oss << " to=\"" << xml_escape(publisher) << "\"";
        oss << " id=\"" << xml_escape(generate_message_id()) << "\">";
        oss << "<event xmlns=\"" << XMPPNS::PUBSUB_EVENT << "\">";
        oss << "<items node=\"" << xml_escape(node_id_) << "\">";
        oss << item->to_event_xml(config_.deliver_payloads);
        oss << "</items>";
        oss << "</event>";
        oss << "</message>";
        return oss.str();
    }

    std::string build_retract_notification(const std::string& item_id) const {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(get_node_jid()) << "\"";
        oss << " id=\"" << xml_escape(generate_message_id()) << "\">";
        oss << "<event xmlns=\"" << XMPPNS::PUBSUB_EVENT << "\">";
        oss << "<items node=\"" << xml_escape(node_id_) << "\">";
        oss << "<retract id=\"" << xml_escape(item_id) << "\"/>";
        oss << "</items>";
        oss << "</event>";
        oss << "</message>";
        return oss.str();
    }

    std::string build_delete_notification() const {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(get_node_jid()) << "\">";
        oss << "<event xmlns=\"" << XMPPNS::PUBSUB_EVENT << "\">";
        oss << "<delete node=\"" << xml_escape(node_id_) << "\"/>";
        oss << "</event>";
        oss << "</message>";
        return oss.str();
    }

    std::string build_purge_notification() const {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(get_node_jid()) << "\">";
        oss << "<event xmlns=\"" << XMPPNS::PUBSUB_EVENT << "\">";
        oss << "<purge node=\"" << xml_escape(node_id_) << "\"/>";
        oss << "</event>";
        oss << "</message>";
        return oss.str();
    }

    std::string build_config_notification() const {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(get_node_jid()) << "\">";
        oss << "<event xmlns=\"" << XMPPNS::PUBSUB_EVENT << "\">";
        oss << "<configuration node=\"" << xml_escape(node_id_) << "\">";
        oss << config_.to_config_form_xml();
        oss << "</configuration>";
        oss << "</event>";
        oss << "</message>";
        return oss.str();
    }

    std::string build_subscription_notification(const std::string& jid,
                                                  PubSubSubscriptionState state) const {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(get_node_jid()) << "\"";
        oss << " to=\"" << xml_escape(jid) << "\">";
        oss << "<event xmlns=\"" << XMPPNS::PUBSUB_EVENT << "\">";
        oss << "<subscription";
        oss << " node=\"" << xml_escape(node_id_) << "\"";
        oss << " jid=\"" << xml_escape(jid) << "\"";
        oss << " subscription=\"" << pubsub_subscription_state_to_string(state) << "\"/>";
        oss << "</event>";
        oss << "</message>";
        return oss.str();
    }

    std::string build_last_published_notification(const std::string& target_jid) const {
        std::lock_guard<std::mutex> lock(node_mutex_);
        if (!last_published_item_) return "";

        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(get_node_jid()) << "\"";
        oss << " to=\"" << xml_escape(target_jid) << "\">";
        oss << "<event xmlns=\"" << XMPPNS::PUBSUB_EVENT << "\">";
        oss << "<items node=\"" << xml_escape(node_id_) << "\">";
        oss << last_published_item_->to_event_xml(config_.deliver_payloads);
        oss << "</items>";
        oss << "</event>";
        oss << "</message>";
        return oss.str();
    }

    // ========================================================================
    // DISCO helpers
    // ========================================================================

    std::string generate_disco_info() const {
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::DISCO_INFO << "\">";
        oss << "<identity category=\"pubsub\" type=\"" << pubsub_node_type_to_string(type_) << "\"";
        if (!config_.title.empty()) {
            oss << " name=\"" << xml_escape(config_.title) << "\"";
        }
        oss << "/>";

        // Standard pubsub features
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#subscribe\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#unsubscribe\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#publish\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#retract\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#items\"/>";

        if (config_.persist_items) {
            oss << "<feature var=\"" << XMPPNS::PUBSUB << "#persistent-items\"/>";
        }

        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#access-open\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#access-presence\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#access-authorize\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#access-whitelist\"/>";

        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#config-node\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#affiliations\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#retrieve-affiliations\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#manage-subscriptions\"/>";

        if (type_ == PubSubNodeType::COLLECTION) {
            oss << "<feature var=\"" << XMPPNS::PUBSUB_COLLECTIONS << "\"/>";
        }

        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#meta-data\"/>";

        oss << "</query>";
        return oss.str();
    }

    std::string generate_disco_items() const {
        std::lock_guard<std::mutex> lock(node_mutex_);
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::DISCO_ITEMS << "\">";

        if (type_ == PubSubNodeType::COLLECTION) {
            for (const auto& child_id : child_node_ids_) {
                oss << "<item jid=\"" << xml_escape(service_jid_) << "\"";
                oss << " node=\"" << xml_escape(child_id) << "\"/>";
            }
        } else {
            // Leaf nodes: list items if persist_items is on
            if (config_.persist_items) {
                for (const auto& item : items_) {
                    oss << "<item jid=\"" << xml_escape(service_jid_) << "\"";
                    oss << " name=\"" << xml_escape(item->id()) << "\"/>";
                }
            }
        }

        oss << "</query>";
        return oss.str();
    }

    // ========================================================================
    // Generate subscription list XML
    // ========================================================================

    std::string generate_subscriptions_xml() const {
        std::lock_guard<std::mutex> lock(node_mutex_);
        std::ostringstream oss;
        for (const auto& pair : subscriptions_) {
            oss << pair.second->to_xml();
        }
        return oss.str();
    }

    std::string generate_affiliations_xml() const {
        std::lock_guard<std::mutex> lock(node_mutex_);
        std::ostringstream oss;
        for (const auto& pair : affiliations_) {
            oss << "<affiliation";
            oss << " jid=\"" << xml_escape(pair.first) << "\"";
            oss << " affiliation=\"" << pubsub_affiliation_to_string(pair.second) << "\"";
            oss << "/>";
        }
        return oss.str();
    }

    std::string generate_items_xml(const std::vector<ItemPtr>& items,
                                    const std::string& max_items = "") const {
        std::ostringstream oss;
        for (const auto& item : items) {
            oss << item->to_xml();
        }
        return oss.str();
    }

private:
    std::string get_node_jid() const {
        return service_jid_;
    }

    ItemPtr find_item_by_id(const std::string& item_id) const {
        for (const auto& item : items_) {
            if (item->id() == item_id) return item;
        }
        return nullptr;
    }

    static std::string bare_jid(const std::string& jid) {
        size_t slash = jid.find('/');
        if (slash != std::string::npos) {
            return jid.substr(0, slash);
        }
        return jid;
    }

    static std::string xml_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '\"':  out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default:   out += c; break;
            }
        }
        return out;
    }

    std::string generate_item_id() {
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        std::ostringstream oss;
        oss << "item_" << ms << "_" << (++next_item_sequence_);
        return oss.str();
    }

    static std::string generate_message_id() {
        static std::atomic<uint64_t> counter{0};
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        std::ostringstream oss;
        oss << "ps_" << ms << "_" << (++counter);
        return oss.str();
    }

    std::string node_id_;
    std::string service_jid_;
    PubSubNodeType type_;
    PubSubNodeState state_;
    PubSubNodeConfig config_;
    SendCallback send_callback_;

    mutable std::mutex node_mutex_;
    std::vector<ItemPtr> items_;
    std::unordered_map<std::string, SubscriptionPtr> subscriptions_;
    std::map<std::string, PubSubAffiliation> affiliations_;
    std::set<std::string> retracted_ids_;
    std::set<std::string> child_node_ids_;
    ItemPtr last_published_item_;
    uint64_t next_item_sequence_;
};

// ============================================================================
// PubSubService - Main PubSub service orchestrating all nodes
// ============================================================================

class PubSubService {
public:
    using NodePtr = std::shared_ptr<PubSubNode>;
    using MessageCallback = std::function<void(const std::string& stanza_xml)>;
    using Logger = std::function<void(const std::string& level, const std::string& message)>;

    PubSubService(const std::string& service_jid,
                  MessageCallback send_callback)
        : service_jid_(service_jid)
        , send_callback_(send_callback)
        , service_enabled_(true)
        , max_total_nodes_(0)
        , max_nodes_per_user_(0)
        , default_max_items_(50)
        , pep_enabled_(true)
        , logging_enabled_(true)
    {
        log_info("PubSubService initialized for: " + service_jid_);
    }

    ~PubSubService() {
        shutdown();
    }

    // ========================================================================
    // Service lifecycle
    // ========================================================================

    void shutdown() {
        std::lock_guard<std::mutex> lock(service_mutex_);
        service_enabled_ = false;

        for (auto& pair : nodes_) {
            if (pair.second->is_active()) {
                if (pair.second->config().notify_delete) {
                    notify_all_subscribers(pair.second,
                        pair.second->build_delete_notification());
                }
                pair.second->mark_deleted();
            }
        }

        nodes_.clear();
        log_info("PubSubService shut down");
    }

    bool is_enabled() const { return service_enabled_; }
    void set_enabled(bool e) { service_enabled_ = e; }

    // ========================================================================
    // Logging
    // ========================================================================

    void set_logger(Logger logger) { logger_ = logger; }

    void log_info(const std::string& msg) {
        if (logging_enabled_ && logger_) {
            logger_("INFO", msg);
        }
    }

    void log_warn(const std::string& msg) {
        if (logging_enabled_ && logger_) {
            logger_("WARN", msg);
        }
    }

    void log_error(const std::string& msg) {
        if (logging_enabled_ && logger_) {
            logger_("ERROR", msg);
        }
    }

    // ========================================================================
    // Configuration
    // ========================================================================

    void set_max_total_nodes(int max) { max_total_nodes_ = max; }
    void set_max_nodes_per_user(int max) { max_nodes_per_user_ = max; }
    void set_default_max_items(int max) { default_max_items_ = max; }
    void set_pep_enabled(bool enabled) { pep_enabled_ = enabled; }

    const std::string& service_jid() const { return service_jid_; }

    // ========================================================================
    // Node creation
    // ========================================================================

    NodePtr create_node(const std::string& node_id,
                        const std::string& creator_jid,
                        PubSubNodeType node_type = PubSubNodeType::LEAF,
                        const PubSubNodeConfig& initial_config = PubSubNodeConfig()) {
        std::lock_guard<std::mutex> lock(service_mutex_);

        if (!service_enabled_) {
            log_error("Cannot create node: service disabled");
            return nullptr;
        }

        if (node_id.empty()) {
            log_error("Cannot create node: empty node ID");
            return nullptr;
        }

        if (nodes_.find(node_id) != nodes_.end()) {
            log_warn("Node already exists: " + node_id);
            return nullptr;
        }

        if (max_total_nodes_ > 0 && nodes_.size() >= static_cast<size_t>(max_total_nodes_)) {
            log_error("Cannot create node: max total nodes (" +
                      std::to_string(max_total_nodes_) + ") reached");
            return nullptr;
        }

        if (max_nodes_per_user_ > 0) {
            int user_nodes = count_user_nodes(creator_jid);
            if (user_nodes >= max_nodes_per_user_) {
                log_error("Cannot create node: user max nodes (" +
                          std::to_string(max_nodes_per_user_) + ") reached");
                return nullptr;
            }
        }

        auto node = std::make_shared<PubSubNode>(
            node_id, service_jid_, creator_jid, node_type,
            [this](const std::string& xml) {
                send_callback_(xml);
            }
        );

        // Apply initial config
        node->config() = initial_config;
        node->config().creator = creator_jid;
        if (node->config().max_items == 0 && default_max_items_ > 0) {
            node->config().max_items = default_max_items_;
        }

        // If this is a collection child, link it
        if (!initial_config.collection_parent_id.empty()) {
            auto parent = get_node(initial_config.collection_parent_id);
            if (parent && parent->is_collection()) {
                parent->add_child_node_id(node_id);
            }
        }

        node->set_state(PubSubNodeState::ACTIVE);
        nodes_[node_id] = node;

        // Auto-subscribe creator if subscribe option is enabled
        if (node->config().subscribe) {
            node->add_subscription(creator_jid, PubSubSubscriptionState::SUBSCRIBED);
        }

        log_info("Node created: " + node_id + " by " + creator_jid +
                 " type=" + pubsub_node_type_to_string(node_type));

        return node;
    }

    NodePtr create_pep_node(const std::string& node_id,
                            const std::string& owner_jid) {
        PubSubNodeConfig pep_config;
        pep_config.access_model = PubSubAccessModel::WHITELIST;
        pep_config.persist_items = true;
        pep_config.max_items = 1;
        pep_config.deliver_payloads = true;
        pep_config.send_last_published_item = true;
        pep_config.is_pep_node = true;
        pep_config.notify_retract = false;

        auto node = create_node(node_id, owner_jid, PubSubNodeType::LEAF, pep_config);
        if (node) {
            node->set_affiliation(owner_jid, PubSubAffiliation::OWNER);

            // Auto-subscribe all resources of the owner
            node->add_subscription(owner_jid, PubSubSubscriptionState::SUBSCRIBED);

            log_info("PEP node created: " + node_id + " for " + owner_jid);
        }
        return node;
    }

    // ========================================================================
    // Node lookup
    // ========================================================================

    NodePtr get_node(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto it = nodes_.find(node_id);
        if (it != nodes_.end()) {
            return it->second;
        }
        return nullptr;
    }

    bool node_exists(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        return nodes_.find(node_id) != nodes_.end();
    }

    std::vector<NodePtr> get_all_nodes() {
        std::lock_guard<std::mutex> lock(service_mutex_);
        std::vector<NodePtr> result;
        for (const auto& pair : nodes_) {
            result.push_back(pair.second);
        }
        return result;
    }

    std::vector<NodePtr> get_user_nodes(const std::string& jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        std::vector<NodePtr> result;
        std::string bare = bare_jid(jid);
        for (const auto& pair : nodes_) {
            if (pair.second->is_owner(bare)) {
                result.push_back(pair.second);
            }
        }
        return result;
    }

    // ========================================================================
    // Node deletion
    // ========================================================================

    bool delete_node(const std::string& node_id, const std::string& requester) {
        std::lock_guard<std::mutex> lock(service_mutex_);

        auto node = get_node(node_id);
        if (!node) {
            log_error("Cannot delete: node not found: " + node_id);
            return false;
        }

        if (!node->is_owner(requester)) {
            log_warn("Delete denied: " + requester + " is not owner of " + node_id);
            return false;
        }

        // Notify delete if configured
        if (node->config().notify_delete) {
            std::string delete_notif = node->build_delete_notification();
            notify_all_subscribers(node, delete_notif);
        }

        // Remove from parent collection
        if (!node->parent_collection_id().empty()) {
            auto parent = get_node(node->parent_collection_id());
            if (parent) {
                parent->remove_child_node_id(node_id);
            }
        }

        // Remove child nodes if this is a collection
        if (node->is_collection()) {
            for (const auto& child_id : node->child_node_ids()) {
                delete_node(child_id, requester);
            }
        }

        node->mark_deleted();

        log_info("Node deleted: " + node_id + " by " + requester);

        // If it's a PEP non-persistent node, remove entirely
        if (node->config().is_pep_node || !node->config().persist_items) {
            nodes_.erase(node_id);
        }

        return true;
    }

    // ========================================================================
    // Node purging
    // ========================================================================

    bool purge_node(const std::string& node_id, const std::string& requester) {
        auto node = get_node(node_id);
        if (!node) {
            log_error("Cannot purge: node not found: " + node_id);
            return false;
        }

        if (!node->is_owner(requester)) {
            log_warn("Purge denied: " + requester + " is not owner of " + node_id);
            return false;
        }

        node->purge();

        // Notify subscribers
        if (node->config().notify_retract) {
            std::string purge_notif = node->build_purge_notification();
            notify_all_subscribers(node, purge_notif);
        }

        log_info("Node purged: " + node_id + " by " + requester);
        return true;
    }

    // ========================================================================
    // Subscription management
    // ========================================================================

    PubSubSubscriptionState subscribe(const std::string& node_id,
                                       const std::string& subscriber_jid,
                                       bool& needs_configuration) {
        auto node = get_node(node_id);
        if (!node) {
            log_error("Cannot subscribe: node not found: " + node_id);
            return PubSubSubscriptionState::NONE;
        }

        if (!node->can_subscribe(subscriber_jid)) {
            log_warn("Subscribe denied for " + subscriber_jid + " to " + node_id);
            return PubSubSubscriptionState::NONE;
        }

        PubSubSubscriptionState state;
        needs_configuration = false;

        switch (node->config().access_model) {
            case PubSubAccessModel::AUTHORIZE:
                state = PubSubSubscriptionState::PENDING;
                break;
            case PubSubAccessModel::OPEN:
            case PubSubAccessModel::PRESENCE:
            case PubSubAccessModel::WHITELIST:
                state = PubSubSubscriptionState::SUBSCRIBED;
                break;
            case PubSubAccessModel::ROSTER:
                needs_configuration = true;
                state = PubSubSubscriptionState::UNCONFIGURED;
                break;
            default:
                state = PubSubSubscriptionState::SUBSCRIBED;
        }

        std::string subid = generate_subid();
        node->add_subscription(subscriber_jid, state, subid);

        // Notify config change if configured
        if (node->config().notify_sub) {
            std::string sub_notif = node->build_subscription_notification(
                subscriber_jid, state);
            notify_all_subscribers(node, sub_notif);
        }

        // Send last published item if configured
        if (node->config().send_last_published_item &&
            state == PubSubSubscriptionState::SUBSCRIBED) {
            std::string last_notif = node->build_last_published_notification(subscriber_jid);
            if (!last_notif.empty()) {
                send_callback_(last_notif);
            }
        }

        log_info("Subscribed: " + subscriber_jid + " to " + node_id +
                 " state=" + pubsub_subscription_state_to_string(state));
        return state;
    }

    bool unsubscribe(const std::string& node_id, const std::string& requester_jid,
                     const std::string& subscriber_jid = "",
                     const std::string& subid = "") {
        auto node = get_node(node_id);
        if (!node) {
            log_error("Cannot unsubscribe: node not found: " + node_id);
            return false;
        }

        std::string target = subscriber_jid.empty() ? requester_jid : subscriber_jid;

        // Only allow self-unsubscribe or owner
        if (requester_jid != target && !node->is_owner(requester_jid)) {
            log_warn("Unsubscribe denied: insufficient privileges");
            return false;
        }

        // Notify unsub if configured
        if (node->config().notify_unsub) {
            auto sub = node->get_subscription(target);
            if (sub) {
                std::string unsub_notif = node->build_subscription_notification(
                    target, PubSubSubscriptionState::NONE);
                notify_all_subscribers(node, unsub_notif);
            }
        }

        bool result = node->remove_subscription(target);

        if (result) {
            log_info("Unsubscribed: " + target + " from " + node_id);
        }

        return result;
    }

    std::vector<std::shared_ptr<PubSubSubscription>> get_subscriptions(
        const std::string& node_id, const std::string& requester) {
        auto node = get_node(node_id);
        if (!node) return {};

        if (!node->is_owner(requester)) {
            log_warn("Get subscriptions denied: not owner");
            return {};
        }

        return node->get_subscriptions();
    }

    // ========================================================================
    // Publishing
    // ========================================================================

    std::string publish(const std::string& node_id,
                        const std::string& publisher_jid,
                        const std::string& payload,
                        const std::string& item_id = "") {
        auto node = get_node(node_id);
        if (!node) {
            log_error("Cannot publish: node not found: " + node_id);
            return "";
        }

        if (!node->can_publish(publisher_jid)) {
            log_warn("Publish denied for " + publisher_jid + " to " + node_id);
            return "";
        }

        std::string actual_id = node->publish_item(publisher_jid, payload, item_id);
        if (actual_id.empty()) {
            log_error("Publish failed for item in node " + node_id);
            return "";
        }

        // Notify all subscribers
        if (node->config().deliver_notifications) {
            std::string notif = node->build_publish_notification(actual_id, publisher_jid);
            notify_all_subscribers(node, notif);
        }

        log_info("Published item " + actual_id + " to " + node_id +
                 " by " + publisher_jid);
        return actual_id;
    }

    bool retract(const std::string& node_id,
                 const std::string& requester_jid,
                 const std::string& item_id) {
        auto node = get_node(node_id);
        if (!node) {
            log_error("Cannot retract: node not found: " + node_id);
            return false;
        }

        bool result = node->retract_item(requester_jid, item_id);
        if (!result) {
            log_warn("Retract failed for " + item_id + " in " + node_id);
            return false;
        }

        // Notify retract if configured
        if (node->config().notify_retract) {
            std::string retract_notif = node->build_retract_notification(item_id);
            notify_all_subscribers(node, retract_notif);
        }

        log_info("Retracted item " + item_id + " from " + node_id +
                 " by " + requester_jid);
        return true;
    }

    // ========================================================================
    // Item retrieval
    // ========================================================================

    std::vector<std::shared_ptr<PubSubItemRecord>> get_items(
        const std::string& node_id,
        const std::string& requester,
        const std::string& max_items = "",
        const std::string& item_id = "") {
        auto node = get_node(node_id);
        if (!node) return {};

        return node->get_items(requester, max_items, item_id);
    }

    std::shared_ptr<PubSubItemRecord> get_last_published_item(
        const std::string& node_id) {
        auto node = get_node(node_id);
        if (!node) return nullptr;
        return node->get_last_published_item();
    }

    // ========================================================================
    // Node configuration
    // ========================================================================

    bool configure_node(const std::string& node_id,
                        const std::string& requester,
                        const std::map<std::string, std::vector<std::string>>& fields) {
        auto node = get_node(node_id);
        if (!node) {
            log_error("Cannot configure: node not found: " + node_id);
            return false;
        }

        if (!node->is_owner(requester)) {
            log_warn("Configure denied: not owner of " + node_id);
            return false;
        }

        node->config().apply_form_fields(fields);

        // Notify config change
        if (node->config().notify_config) {
            std::string config_notif = node->build_config_notification();
            notify_all_subscribers(node, config_notif);
        }

        log_info("Node configured: " + node_id + " by " + requester);
        return true;
    }

    PubSubNodeConfig get_default_config() {
        PubSubNodeConfig config;
        config.access_model = PubSubAccessModel::OPEN;
        config.persist_items = false;
        config.max_items = default_max_items_;
        config.deliver_payloads = true;
        config.deliver_notifications = true;
        config.send_last_published_item = true;
        config.subscribe = true;
        return config;
    }

    // ========================================================================
    // Affiliation management
    // ========================================================================

    bool set_affiliation(const std::string& node_id,
                         const std::string& requester,
                         const std::string& target_jid,
                         PubSubAffiliation affiliation) {
        auto node = get_node(node_id);
        if (!node) {
            log_error("Cannot set affiliation: node not found: " + node_id);
            return false;
        }

        if (!node->is_owner(requester)) {
            log_warn("Set affiliation denied: not owner of " + node_id);
            return false;
        }

        // Can't change own affiliation away from owner
        if (requester == target_jid &&
            affiliation != PubSubAffiliation::OWNER) {
            log_warn("Cannot remove own owner affiliation");
            return false;
        }

        node->set_affiliation(target_jid, affiliation);
        log_info("Affiliation set: " + target_jid + " -> " +
                 pubsub_affiliation_to_string(affiliation) + " on " + node_id);
        return true;
    }

    std::map<std::string, PubSubAffiliation> get_affiliations(
        const std::string& node_id, const std::string& requester) {
        auto node = get_node(node_id);
        if (!node) return {};

        if (!node->is_owner(requester)) {
            return {};
        }

        return node->get_all_affiliations();
    }

    // ========================================================================
    // DISCO
    // ========================================================================

    std::string generate_service_disco_info() {
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::DISCO_INFO << "\">";
        oss << "<identity category=\"pubsub\" type=\"service\" name=\"PubSub Service\"/>";
        oss << "<feature var=\"" << XMPPNS::DISCO_INFO << "\"/>";
        oss << "<feature var=\"" << XMPPNS::DISCO_ITEMS << "\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#create-nodes\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#create-and-configure\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#delete-nodes\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#instant-nodes\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#subscribe\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#auto-create\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#auto-subscribe\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#access-open\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#access-presence\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#access-authorize\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#access-whitelist\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#collections\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#config-node\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#default-config\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#publish\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#retract-items\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#persistent-items\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#item-ids\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#retrieve-items\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#retrieve-default\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#meta-data\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#affiliations\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#manage-subscriptions\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#multi-subscribe\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#publisher-affiliation\"/>";
        oss << "<feature var=\"" << XMPPNS::PUBSUB << "#outcast-affiliation\"/>";
        oss << "</query>";
        return oss.str();
    }

    std::string generate_service_disco_items() {
        std::lock_guard<std::mutex> lock(service_mutex_);
        std::ostringstream oss;
        oss << "<query xmlns=\"" << XMPPNS::DISCO_ITEMS << "\">";
        for (const auto& pair : nodes_) {
            if (!pair.second->is_deleted()) {
                oss << "<item jid=\"" << xml_escape(service_jid_) << "\"";
                oss << " node=\"" << xml_escape(pair.first) << "\"";
                if (!pair.second->config().title.empty()) {
                    oss << " name=\"" << xml_escape(pair.second->config().title) << "\"";
                }
                oss << "/>";
            }
        }
        oss << "</query>";
        return oss.str();
    }

    // ========================================================================
    // PEP (Personal Eventing Protocol) handlers
    // ========================================================================

    bool is_pep_enabled() const { return pep_enabled_; }

    // Handle PEP presence: when a user comes online, notify their contacts
    // about their PEP nodes (auto-subscribe for contacts)
    void handle_pep_presence(const std::string& user_jid,
                             const std::string& presence_type) {
        if (!pep_enabled_) return;

        std::string bare = bare_jid(user_jid);

        if (presence_type == "available" || presence_type.empty()) {
            // User came online - ensure PEP nodes exist and auto-subscribe contacts
            ensure_pep_nodes(bare);
        }

        // Notify contacts about presence-based PEP
        // In a full implementation, this would consult the roster
    }

    void ensure_pep_nodes(const std::string& user_jid) {
        std::string bare = bare_jid(user_jid);

        // Create standard PEP nodes if they don't exist
        std::vector<std::string> standard_pep_nodes = {
            "urn:xmpp:avatar:data",
            "urn:xmpp:avatar:metadata",
            "http://jabber.org/protocol/tune",
            "http://jabber.org/protocol/activity",
            "http://jabber.org/protocol/mood",
            "http://jabber.org/protocol/geoloc",
            "http://jabber.org/protocol/nick",
            "urn:xmpp:microblog:0"
        };

        for (const auto& node_name : standard_pep_nodes) {
            std::string full_node_id = bare + "#" + node_name;
            if (!node_exists(full_node_id)) {
                create_pep_node(full_node_id, bare);
            }
        }
    }

    // Get a list of affiliations across all nodes for a given JID
    std::string get_user_affiliations_xml(const std::string& jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        std::string bare = bare_jid(jid);
        std::ostringstream oss;

        for (const auto& pair : nodes_) {
            auto& node = pair.second;
            PubSubAffiliation aff = node->get_affiliation(bare);
            if (aff != PubSubAffiliation::NONE) {
                oss << "<affiliation";
                oss << " node=\"" << xml_escape(pair.first) << "\"";
                oss << " affiliation=\"" << pubsub_affiliation_to_string(aff) << "\"";
                oss << "/>";
            }
        }

        return oss.str();
    }

    // Get a list of subscriptions across all nodes for a given JID
    std::string get_user_subscriptions_xml(const std::string& jid) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        std::string bare = bare_jid(jid);
        std::ostringstream oss;

        for (const auto& pair : nodes_) {
            auto sub = pair.second->get_subscription(bare);
            if (sub && sub->state() != PubSubSubscriptionState::NONE) {
                oss << "<subscription";
                oss << " node=\"" << xml_escape(pair.first) << "\"";
                oss << " jid=\"" << xml_escape(bare) << "\"";
                oss << " subscription=\"" << pubsub_subscription_state_to_string(sub->state()) << "\"";
                if (!sub->subscription_id().empty()) {
                    oss << " subid=\"" << xml_escape(sub->subscription_id()) << "\"";
                }
                oss << "/>";
            }
        }
        return oss.str();
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    struct PubSubStats {
        int total_nodes;
        int leaf_nodes;
        int collection_nodes;
        int active_nodes;
        int deleted_nodes;
        int total_subscriptions;
        int total_items;
        int pep_nodes;
    };

    PubSubStats get_stats() {
        std::lock_guard<std::mutex> lock(service_mutex_);

        PubSubStats stats;
        stats.total_nodes = 0;
        stats.leaf_nodes = 0;
        stats.collection_nodes = 0;
        stats.active_nodes = 0;
        stats.deleted_nodes = 0;
        stats.total_subscriptions = 0;
        stats.total_items = 0;
        stats.pep_nodes = 0;

        for (const auto& pair : nodes_) {
            auto& node = pair.second;
            ++stats.total_nodes;

            if (node->is_leaf()) ++stats.leaf_nodes;
            if (node->is_collection()) ++stats.collection_nodes;
            if (node->is_active()) ++stats.active_nodes;
            if (node->is_deleted()) ++stats.deleted_nodes;
            if (node->config().is_pep_node) ++stats.pep_nodes;

            stats.total_subscriptions += node->subscription_count();
            stats.total_items += node->item_count();
        }

        return stats;
    }

    // ========================================================================
    // Cleanup
    // ========================================================================

    int cleanup_deleted_nodes() {
        std::lock_guard<std::mutex> lock(service_mutex_);
        int cleaned = 0;

        std::vector<std::string> to_remove;
        for (auto& pair : nodes_) {
            if (pair.second->is_deleted()) {
                to_remove.push_back(pair.first);
            }
        }

        for (auto& id : to_remove) {
            nodes_.erase(id);
            ++cleaned;
        }

        if (cleaned > 0) {
            log_info("Cleaned up " + std::to_string(cleaned) + " deleted nodes");
        }

        return cleaned;
    }

    void expire_stale_items() {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto now = std::chrono::system_clock::now();

        for (auto& pair : nodes_) {
            auto& node = pair.second;
            if (node->config().item_expire_seconds <= 0) continue;

            auto items = node->get_items("", "", "");
            for (const auto& item : items) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - item->creation_time()).count();
                if (age > node->config().item_expire_seconds) {
                    node->retract_item(node->config().creator, item->id());
                }
            }
        }
    }

private:
    // ========================================================================
    // Private helpers
    // ========================================================================

    static std::string xml_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '\"':  out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default:   out += c; break;
            }
        }
        return out;
    }

    static std::string bare_jid(const std::string& jid) {
        size_t slash = jid.find('/');
        if (slash != std::string::npos) {
            return jid.substr(0, slash);
        }
        return jid;
    }

    static std::string generate_subid() {
        static std::atomic<uint64_t> counter{0};
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        std::ostringstream oss;
        oss << "sub_" << ms << "_" << (++counter);
        return oss.str();
    }

    void notify_all_subscribers(NodePtr node, const std::string& notification_xml) {
        if (!node || notification_xml.empty()) return;

        auto subs = node->get_subscriptions();
        for (const auto& sub : subs) {
            if (sub->state() == PubSubSubscriptionState::SUBSCRIBED) {
                // Re-target the notification to the subscriber
                std::string target_xml = retarget_message(notification_xml, sub->jid());
                send_callback_(target_xml);
            }
        }
    }

    static std::string retarget_message(const std::string& xml, const std::string& target_jid) {
        // Simple: replace the first to=" attribute
        std::string result = xml;
        size_t pos = result.find(" to=\"");
        if (pos != std::string::npos) {
            size_t end = result.find('\"', pos + 6);
            if (end != std::string::npos) {
                std::string before = result.substr(0, pos + 6);
                std::string after = result.substr(end);
                result = before + xml_escape(target_jid) + after;
            }
        } else {
            // Insert to="..." after from="..."
            pos = result.find("from=\"");
            if (pos != std::string::npos) {
                size_t from_end = result.find('\"', pos + 7);
                if (from_end != std::string::npos) {
                    result.insert(from_end + 1, " to=\"" + xml_escape(target_jid) + "\"");
                }
            }
        }
        return result;
    }

    int count_user_nodes(const std::string& real_jid) {
        int count = 0;
        for (auto& pair : nodes_) {
            if (pair.second->is_owner(real_jid)) ++count;
        }
        return count;
    }

    std::string service_jid_;
    MessageCallback send_callback_;
    bool service_enabled_;
    int max_total_nodes_;
    int max_nodes_per_user_;
    int default_max_items_;
    bool pep_enabled_;
    bool logging_enabled_;
    Logger logger_;

    mutable std::mutex service_mutex_;
    std::unordered_map<std::string, NodePtr> nodes_;
};

// ============================================================================
// PEPHandler - Personal Eventing Protocol dedicated handler
// ============================================================================

class PEPHandler {
public:
    using PubSubServicePtr = std::shared_ptr<PubSubService>;
    using SendCallback = std::function<void(const std::string& stanza_xml)>;

    PEPHandler(PubSubServicePtr pubsub_service,
               SendCallback send_callback)
        : pubsub_service_(pubsub_service)
        , send_callback_(send_callback)
        , enabled_(true)
    {}

    void set_enabled(bool enabled) { enabled_ = enabled; }
    bool is_enabled() const { return enabled_; }

    // ========================================================================
    // Handle incoming PEP stanzas
    // ========================================================================

    struct PEPStanza {
        std::string from;
        std::string to;
        std::string type;  // "get", "set", "result", "error"
        std::string id;
        std::string node;
        std::string item_id;
        std::string payload;
        PubSubIQAction action;
        std::map<std::string, std::vector<std::string>> config_fields;
    };

    std::string handle_pep_iq(const PEPStanza& stanza) {
        if (!enabled_ || !pubsub_service_) {
            return make_error_iq(stanza.id, stanza.from, "500", "wait",
                                 "internal-server-error");
        }

        std::string bare_user = bare_jid(stanza.from);

        switch (stanza.action) {
            case PubSubIQAction::PUBLISH:
                return handle_pep_publish(stanza, bare_user);
            case PubSubIQAction::ITEMS:
                return handle_pep_items(stanza, bare_user);
            case PubSubIQAction::RETRACT:
                return handle_pep_retract(stanza, bare_user);
            case PubSubIQAction::SUBSCRIBE:
                return handle_pep_subscribe(stanza, bare_user);
            case PubSubIQAction::UNSUBSCRIBE:
                return handle_pep_unsubscribe(stanza, bare_user);
            case PubSubIQAction::DISCO_INFO:
                return handle_pep_disco_info(stanza, bare_user);
            case PubSubIQAction::DISCO_ITEMS:
                return handle_pep_disco_items(stanza, bare_user);
            default:
                return make_error_iq(stanza.id, stanza.from, "501", "cancel",
                                     "feature-not-implemented");
        }
    }

    // ========================================================================
    // Broadcast PEP update to auto-subscribed contacts
    // ========================================================================

    void broadcast_pep_update(const std::string& user_jid,
                              const std::string& node,
                              const std::string& item_xml) {
        if (!enabled_) return;

        std::string bare = bare_jid(user_jid);
        std::string full_node_id = bare + "#" + node;

        auto pubsub_node = pubsub_service_->get_node(full_node_id);
        if (!pubsub_node) return;

        // Get all subscribers and send them the notification
        auto subs = pubsub_node->get_subscriptions();
        for (const auto& sub : subs) {
            if (sub->state() == PubSubSubscriptionState::SUBSCRIBED) {
                std::ostringstream oss;
                oss << "<message from=\"" << xml_escape(bare) << "\"";
                oss << " to=\"" << xml_escape(sub->jid()) << "\"";
                oss << "><event xmlns=\"" << XMPPNS::PEP << "\">";
                oss << "<items node=\"" << xml_escape(node) << "\">";
                oss << item_xml;
                oss << "</items>";
                oss << "</event></message>";
                send_callback_(oss.str());
            }
        }
    }

    // ========================================================================
    // Handle presence-based PEP auto-subscription
    // ========================================================================

    void handle_pep_caps_presence(const std::string& user_jid,
                                  const std::string& caps_node,
                                  const std::string& caps_ver) {
        // Process XEP-0115 entity capabilities for PEP
        // In a full implementation, this would check feature lists
        // and auto-subscribe the user to relevant PEP nodes
        (void)caps_node;
        (void)caps_ver;
    }

private:
    // ========================================================================
    // PEP action handlers
    // ========================================================================

    std::string handle_pep_publish(const PEPStanza& stanza, const std::string& bare_user) {
        std::string full_node_id = bare_user + "#" + stanza.node;

        // Auto-create PEP node if it doesn't exist
        if (!pubsub_service_->node_exists(full_node_id)) {
            pubsub_service_->create_pep_node(full_node_id, bare_user);
        }

        std::string result_id = pubsub_service_->publish(
            full_node_id, bare_user, stanza.payload, stanza.item_id);

        if (result_id.empty()) {
            return make_error_iq(stanza.id, stanza.from, "403", "auth",
                                 "forbidden");
        }

        // Build success response
        return make_pep_publish_result(stanza.id, stanza.from, stanza.node, result_id);
    }

    std::string handle_pep_items(const PEPStanza& stanza, const std::string& bare_user) {
        std::string full_node_id = bare_user + "#" + stanza.node;
        auto items = pubsub_service_->get_items(full_node_id, bare_user, stanza.item_id);

        return make_pep_items_result(stanza.id, stanza.from, stanza.node, items);
    }

    std::string handle_pep_retract(const PEPStanza& stanza, const std::string& bare_user) {
        std::string full_node_id = bare_user + "#" + stanza.node;

        bool ok = pubsub_service_->retract(full_node_id, bare_user, stanza.item_id);
        if (!ok) {
            return make_error_iq(stanza.id, stanza.from, "404", "cancel",
                                 "item-not-found");
        }

        return make_result_iq(stanza.id, stanza.from);
    }

    std::string handle_pep_subscribe(const PEPStanza& stanza, const std::string& bare_user) {
        std::string full_node_id = bare_user + "#" + stanza.node;

        bool needs_config = false;
        PubSubSubscriptionState state = pubsub_service_->subscribe(
            full_node_id, stanza.from, needs_config);

        if (state == PubSubSubscriptionState::NONE) {
            return make_error_iq(stanza.id, stanza.from, "403", "auth",
                                 "forbidden");
        }

        return make_subscription_result_iq(stanza.id, stanza.from,
                                           stanza.node, stanza.from, state);
    }

    std::string handle_pep_unsubscribe(const PEPStanza& stanza, const std::string& bare_user) {
        std::string full_node_id = bare_user + "#" + stanza.node;

        bool ok = pubsub_service_->unsubscribe(full_node_id, stanza.from);
        if (!ok) {
            return make_error_iq(stanza.id, stanza.from, "404", "cancel",
                                 "item-not-found");
        }

        return make_result_iq(stanza.id, stanza.from);
    }

    std::string handle_pep_disco_info(const PEPStanza& stanza, const std::string& bare_user) {
        std::string full_node_id = bare_user + "#" + stanza.node;
        auto node = pubsub_service_->get_node(full_node_id);

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(stanza.id) << "\"";
        oss << " from=\"" << xml_escape(bare_user) << "\"";
        oss << " to=\"" << xml_escape(stanza.from) << "\">";

        if (node) {
            oss << node->generate_disco_info();
        } else {
            oss << "<query xmlns=\"" << XMPPNS::DISCO_INFO << "\">";
            oss << "<identity category=\"pubsub\" type=\"pep\" name=\"PEP Service\"/>";
            oss << "<feature var=\"" << XMPPNS::PUBSUB << "\"/>";
            oss << "<feature var=\"" << XMPPNS::PUBSUB << "#auto-create\"/>";
            oss << "<feature var=\"" << XMPPNS::PUBSUB << "#auto-subscribe\"/>";
            oss << "</query>";
        }

        oss << "</iq>";
        return oss.str();
    }

    std::string handle_pep_disco_items(const PEPStanza& stanza, const std::string& bare_user) {
        auto user_nodes = pubsub_service_->get_user_nodes(bare_user);

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(stanza.id) << "\"";
        oss << " from=\"" << xml_escape(bare_user) << "\"";
        oss << " to=\"" << xml_escape(stanza.from) << "\">";
        oss << "<query xmlns=\"" << XMPPNS::DISCO_ITEMS << "\">";

        for (const auto& node : user_nodes) {
            if (node->config().is_pep_node && !node->is_deleted()) {
                // Strip the bare JID prefix to get the PEP node name
                std::string node_id = node->node_id();
                std::string bare_prefix = bare_user + "#";
                std::string pep_node = node_id;
                if (node_id.find(bare_prefix) == 0) {
                    pep_node = node_id.substr(bare_prefix.length());
                }

                oss << "<item jid=\"" << xml_escape(bare_user) << "\"";
                oss << " node=\"" << xml_escape(pep_node) << "\"";
                if (!node->config().title.empty()) {
                    oss << " name=\"" << xml_escape(node->config().title) << "\"";
                }
                oss << "/>";
            }
        }

        oss << "</query></iq>";
        return oss.str();
    }

    // ========================================================================
    // Stanza builders
    // ========================================================================

    static std::string xml_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '\"':  out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default:   out += c; break;
            }
        }
        return out;
    }

    static std::string bare_jid(const std::string& jid) {
        size_t slash = jid.find('/');
        if (slash != std::string::npos) {
            return jid.substr(0, slash);
        }
        return jid;
    }

    static std::string make_result_iq(const std::string& id, const std::string& to) {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        if (!to.empty()) {
            oss << " to=\"" << xml_escape(to) << "\"";
        }
        oss << "/>";
        return oss.str();
    }

    static std::string make_error_iq(const std::string& id, const std::string& to,
                                      const std::string& code, const std::string& type,
                                      const std::string& condition) {
        std::ostringstream oss;
        oss << "<iq type=\"error\" id=\"" << xml_escape(id) << "\"";
        oss << " to=\"" << xml_escape(to) << "\">";
        oss << "<error code=\"" << code << "\" type=\"" << type << "\">";
        oss << "<" << condition << " xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/>";

        // Add pubsub-specific error if applicable
        if (condition == "forbidden" || condition == "not-authorized") {
            oss << "<closed-node xmlns=\"" << XMPPNS::PUBSUB_ERRORS << "\"/>";
        }

        oss << "</error></iq>";
        return oss.str();
    }

    static std::string make_pep_publish_result(const std::string& id,
                                                 const std::string& to,
                                                 const std::string& node,
                                                 const std::string& item_id) {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " to=\"" << xml_escape(to) << "\">";
        oss << "<pubsub xmlns=\"" << XMPPNS::PUBSUB << "\">";
        oss << "<publish node=\"" << xml_escape(node) << "\">";
        oss << "<item id=\"" << xml_escape(item_id) << "\"/>";
        oss << "</publish>";
        oss << "</pubsub></iq>";
        return oss.str();
    }

    static std::string make_pep_items_result(const std::string& id,
                                              const std::string& to,
                                              const std::string& node,
                                              const std::vector<std::shared_ptr<PubSubItemRecord>>& items) {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " to=\"" << xml_escape(to) << "\">";
        oss << "<pubsub xmlns=\"" << XMPPNS::PUBSUB << "\">";
        oss << "<items node=\"" << xml_escape(node) << "\">";
        for (const auto& item : items) {
            oss << item->to_xml();
        }
        oss << "</items></pubsub></iq>";
        return oss.str();
    }

    static std::string make_subscription_result_iq(const std::string& id,
                                                    const std::string& to,
                                                    const std::string& node,
                                                    const std::string& jid,
                                                    PubSubSubscriptionState state) {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " to=\"" << xml_escape(to) << "\">";
        oss << "<pubsub xmlns=\"" << XMPPNS::PUBSUB << "\">";
        oss << "<subscription";
        oss << " node=\"" << xml_escape(node) << "\"";
        oss << " jid=\"" << xml_escape(jid) << "\"";
        oss << " subscription=\"" << pubsub_subscription_state_to_string(state) << "\"";
        oss << "/>";
        oss << "</pubsub></iq>";
        return oss.str();
    }

    PubSubServicePtr pubsub_service_;
    SendCallback send_callback_;
    bool enabled_;
};

// ============================================================================
// PubSubStanzaParser - Parse PubSub-related IQ stanzas
// ============================================================================

class PubSubStanzaParser {
public:
    struct ParsedPubSubStanza {
        PubSubIQAction action;
        std::string from_jid;
        std::string to_jid;
        std::string id;
        std::string node;
        std::string item_id;
        std::string payload;
        std::string subid;
        std::string subscriber_jid;
        PubSubAffiliation affiliation;
        std::map<std::string, std::vector<std::string>> config_fields;
        bool is_owner_namespace;
    };

    static ParsedPubSubStanza parse(const std::string& xml) {
        ParsedPubSubStanza result;
        result.action = PubSubIQAction::UNKNOWN;
        result.affiliation = PubSubAffiliation::NONE;
        result.is_owner_namespace = false;

        result.from_jid = extract_attr(xml, "from");
        result.to_jid = extract_attr(xml, "to");
        result.id = extract_attr(xml, "id");

        // Detect namespace
        bool is_pubsub = xml.find(XMPPNS::PUBSUB) != std::string::npos;
        result.is_owner_namespace = xml.find(XMPPNS::PUBSUB_OWNER) != std::string::npos;

        if (!is_pubsub && !result.is_owner_namespace) {
            return result;
        }

        // Extract node
        result.node = extract_attr_inside(xml, "node");

        // Determine action by looking for child elements
        if (xml.find("<create") != std::string::npos) {
            result.action = PubSubIQAction::CREATE;
        } else if (xml.find("<configure") != std::string::npos) {
            if (result.is_owner_namespace) {
                result.action = !result.node.empty() ?
                    PubSubIQAction::OWNER_CONFIG_GET : PubSubIQAction::OWNER_DEFAULT;
            } else {
                result.action = PubSubIQAction::CONFIGURE;
            }
            result.config_fields = parse_data_form(xml);
        } else if (xml.find("<default>") != std::string::npos) {
            result.action = PubSubIQAction::DEFAULT_CONFIG;
        } else if (xml.find("<subscribe") != std::string::npos) {
            result.action = PubSubIQAction::SUBSCRIBE;
            result.subscriber_jid = extract_attr_inside(xml, "jid", "subscribe");
        } else if (xml.find("<unsubscribe") != std::string::npos) {
            result.action = PubSubIQAction::UNSUBSCRIBE;
            result.subscriber_jid = extract_attr_inside(xml, "jid", "unsubscribe");
            result.subid = extract_attr_inside(xml, "subid", "unsubscribe");
        } else if (xml.find("<publish") != std::string::npos) {
            result.action = PubSubIQAction::PUBLISH;
            result.item_id = extract_attr_inside(xml, "id", "item");
            result.payload = extract_child_content(xml, "item");
        } else if (xml.find("<retract") != std::string::npos) {
            result.action = PubSubIQAction::RETRACT;
            result.item_id = extract_attr_inside(xml, "id", "retract");
        } else if (xml.find("<items") != std::string::npos) {
            result.action = PubSubIQAction::ITEMS;
            result.item_id = extract_attr_inside(xml, "max_items", "items");
        } else if (xml.find("<delete") != std::string::npos) {
            result.action = PubSubIQAction::DELETE_NODE;
        } else if (xml.find("<purge") != std::string::npos) {
            result.action = PubSubIQAction::PURGE;
        } else if (xml.find("<affiliations") != std::string::npos) {
            if (result.is_owner_namespace) {
                result.action = PubSubIQAction::AFFILIATIONS_SET;
                result.subscriber_jid = extract_attr_inside(xml, "jid", "affiliation");
                result.affiliation = pubsub_affiliation_from_string(
                    extract_attr_inside(xml, "affiliation", "affiliation"));
            } else {
                result.action = PubSubIQAction::AFFILIATIONS_GET;
            }
        } else if (xml.find("<subscriptions") != std::string::npos) {
            result.action = PubSubIQAction::SUBSCRIPTIONS_GET;
        } else if (xml.find("<subscription-options") != std::string::npos) {
            result.action = PubSubIQAction::SUBSCRIPTION_OPTIONS_GET;
        }

        return result;
    }

private:
    static std::string extract_attr(const std::string& xml, const std::string& attr) {
        std::string search = attr + "=\"";
        size_t pos = xml.find(search);
        if (pos == std::string::npos) {
            search = attr + "='";
            pos = xml.find(search);
            if (pos == std::string::npos) return "";
        }
        pos += search.length();
        size_t end = xml.find(xml[pos - 1], pos);
        if (end == std::string::npos) return "";
        return unescape_xml(xml.substr(pos, end - pos));
    }

    static std::string extract_attr_inside(const std::string& xml,
                                            const std::string& attr,
                                            const std::string& tag_hint = "") {
        // Search for the attribute inside a specific tag or any tag
        std::string result;

        if (!tag_hint.empty()) {
            // Find the tag, then search within it
            std::string open = "<" + tag_hint;
            size_t pos = xml.find(open);
            if (pos != std::string::npos) {
                size_t tag_end = xml.find('>', pos);
                if (tag_end == std::string::npos) {
                    // Self-closing tag: find />
                    tag_end = xml.find("/>", pos);
                    if (tag_end == std::string::npos) return "";
                }
                std::string tag_content = xml.substr(pos, tag_end - pos + 1);
                return extract_attr(tag_content, attr);
            }
            return "";
        }

        return extract_attr(xml, attr);
    }

    static std::string extract_child_content(const std::string& xml,
                                              const std::string& tag) {
        std::string open = "<" + tag;
        size_t pos = xml.find(open);
        if (pos == std::string::npos) return "";

        // Find the end of this opening tag
        size_t open_end = xml.find('>', pos);
        if (open_end == std::string::npos) return "";

        // Check if self-closing
        if (open_end > 0 && xml[open_end - 1] == '/') return "";

        pos = open_end + 1;

        // Find the closing tag, handling nested tags with the same name
        std::string close = "</" + tag + ">";
        size_t close_pos = find_matching_close(xml, open, close, pos);
        if (close_pos == std::string::npos) return "";

        return xml.substr(pos, close_pos - pos);
    }

    static size_t find_matching_close(const std::string& xml,
                                       const std::string& open_tag,
                                       const std::string& close_tag,
                                       size_t start) {
        int depth = 1;
        size_t pos = start;
        std::string open_prefix = open_tag.substr(0, open_tag.find(' ') == std::string::npos
                                                   ? open_tag.length() - 1 : open_tag.find(' '));
        std::string short_open = "<" + open_prefix.substr(1);  // Without the "<"
        std::string short_close = close_tag;

        while (depth > 0 && pos < xml.length()) {
            size_t next_open = xml.find(short_open, pos);
            size_t next_close = xml.find(short_close, pos);

            if (next_close == std::string::npos) return std::string::npos;

            if (next_open != std::string::npos && next_open < next_close) {
                // Check it's actually an open tag
                char after = xml[next_open + short_open.length()];
                if (after == ' ' || after == '>' || after == '/') {
                    if (xml[next_open + short_open.length()] != '/' ||
                        xml[next_open + short_open.length() - 1] == '/') {
                        ++depth;
                    }
                }
                pos = next_open + 1;
            } else {
                --depth;
                if (depth == 0) {
                    return next_close;
                }
                pos = next_close + 1;
            }
        }
        return std::string::npos;
    }

    static std::map<std::string, std::vector<std::string>> parse_data_form(
        const std::string& xml) {
        std::map<std::string, std::vector<std::string>> fields;

        // Find the x xmlns="jabber:x:data" element
        size_t x_start = xml.find("<x xmlns=\"jabber:x:data\"");
        if (x_start == std::string::npos) {
            x_start = xml.find("<x xmlns='jabber:x:data'");
            if (x_start == std::string::npos) return fields;
        }

        size_t x_end = xml.find("</x>", x_start);
        if (x_end == std::string::npos) return fields;

        std::string x_content = xml.substr(x_start, x_end - x_start + 4);

        // Parse individual fields
        size_t field_pos = 0;
        while ((field_pos = x_content.find("<field", field_pos)) != std::string::npos) {
            size_t field_end = x_content.find("</field>", field_pos);
            if (field_end == std::string::npos) break;

            std::string field_xml = x_content.substr(field_pos, field_end - field_pos + 9);
            std::string var = extract_attr(field_xml, "var");

            if (!var.empty() && var != "FORM_TYPE") {
                std::vector<std::string> values;

                // Find all <value>...</value> elements
                size_t val_pos = 0;
                while ((val_pos = field_xml.find("<value>", val_pos)) != std::string::npos) {
                    size_t val_end = field_xml.find("</value>", val_pos);
                    if (val_end == std::string::npos) break;
                    std::string val = field_xml.substr(val_pos + 7, val_end - val_pos - 7);
                    values.push_back(unescape_xml(trim(val)));
                    val_pos = val_end + 8;
                }

                fields[var] = values;
            }

            field_pos = field_end + 9;
        }

        return fields;
    }

    static std::string unescape_xml(const std::string& s) {
        std::string result = s;
        size_t pos;
        while ((pos = result.find("&amp;")) != std::string::npos)
            result.replace(pos, 5, "&");
        while ((pos = result.find("&lt;")) != std::string::npos)
            result.replace(pos, 4, "<");
        while ((pos = result.find("&gt;")) != std::string::npos)
            result.replace(pos, 4, ">");
        while ((pos = result.find("&quot;")) != std::string::npos)
            result.replace(pos, 6, "\"");
        while ((pos = result.find("&apos;")) != std::string::npos)
            result.replace(pos, 6, "'");
        return result;
    }

    static std::string trim(const std::string& s) {
        size_t start = s.find_first_not_of(" \t\n\r");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\n\r");
        return s.substr(start, end - start + 1);
    }
};

// ============================================================================
// PubSubIQHandler - Handles all PubSub IQ stanzas
// ============================================================================

class PubSubIQHandler {
public:
    friend class PubSubManager;

    using PubSubServicePtr = std::shared_ptr<PubSubService>;
    using PEPHandlerPtr = std::shared_ptr<PEPHandler>;
    using SendCallback = std::function<void(const std::string& stanza_xml)>;

    PubSubIQHandler(PubSubServicePtr pubsub_service,
                    PEPHandlerPtr pep_handler,
                    const std::string& service_jid)
        : pubsub_service_(pubsub_service)
        , pep_handler_(pep_handler)
        , service_jid_(service_jid)
    {}

    // Main entry point: handles an incoming IQ stanza and returns the response
    std::string handle_iq(const std::string& xml) {
        auto parsed = PubSubStanzaParser::parse(xml);

        // Route PEP stanzas
        if (is_pep_stanza(parsed)) {
            PEPHandler::PEPStanza pep_stanza;
            pep_stanza.from = parsed.from_jid;
            pep_stanza.to = parsed.to_jid;
            pep_stanza.id = parsed.id;
            pep_stanza.node = parsed.node;
            pep_stanza.item_id = parsed.item_id;
            pep_stanza.payload = parsed.payload;
            pep_stanza.action = parsed.action;
            pep_stanza.config_fields = parsed.config_fields;

            return pep_handler_->handle_pep_iq(pep_stanza);
        }

        return handle_pubsub_iq(parsed);
    }

private:
    bool is_pep_stanza(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        // PEP stanzas go to user@domain (not service JID)
        if (parsed.to_jid.find(service_jid_) == std::string::npos &&
            !parsed.to_jid.empty()) {
            return true;
        }
        return false;
    }

    std::string handle_pubsub_iq(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        switch (parsed.action) {
            case PubSubIQAction::CREATE:
                return handle_create(parsed);
            case PubSubIQAction::SUBSCRIBE:
                return handle_subscribe(parsed);
            case PubSubIQAction::UNSUBSCRIBE:
                return handle_unsubscribe(parsed);
            case PubSubIQAction::PUBLISH:
                return handle_publish(parsed);
            case PubSubIQAction::RETRACT:
                return handle_retract(parsed);
            case PubSubIQAction::ITEMS:
                return handle_items(parsed);
            case PubSubIQAction::DELETE_NODE:
                return handle_delete(parsed);
            case PubSubIQAction::PURGE:
                return handle_purge(parsed);
            case PubSubIQAction::CONFIGURE:
                return handle_configure(parsed);
            case PubSubIQAction::DEFAULT_CONFIG:
                return handle_default_config(parsed);
            case PubSubIQAction::AFFILIATIONS_GET:
                return handle_affiliations_get(parsed);
            case PubSubIQAction::AFFILIATIONS_SET:
                return handle_affiliations_set(parsed);
            case PubSubIQAction::SUBSCRIPTIONS_GET:
                return handle_subscriptions_get(parsed);
            case PubSubIQAction::SUBSCRIPTION_OPTIONS_GET:
                return handle_subscription_options_get(parsed);
            case PubSubIQAction::OWNER_CONFIG_GET:
                return handle_owner_config_get(parsed);
            case PubSubIQAction::OWNER_CONFIG_SET:
                return handle_owner_config_set(parsed);
            case PubSubIQAction::OWNER_DELETE:
                return handle_owner_delete(parsed);
            case PubSubIQAction::OWNER_PURGE:
                return handle_owner_purge(parsed);
            case PubSubIQAction::OWNER_DEFAULT:
                return handle_owner_default(parsed);
            default:
                return make_error_iq(parsed.id, parsed.from_jid,
                                     "501", "cancel", "feature-not-implemented");
        }
    }

    // ========================================================================
    // Action handlers
    // ========================================================================

    std::string handle_create(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        if (parsed.node.empty()) {
            // Instant node: generate a node ID
            std::string node_id = generate_instant_node_id();
            auto node = pubsub_service_->create_node(node_id, parsed.from_jid);
            if (!node) {
                return make_error_iq(parsed.id, parsed.from_jid,
                                     "500", "wait", "internal-server-error");
            }

            return make_create_result(parsed.id, parsed.from_jid, node_id);
        }

        PubSubNodeType node_type = PubSubNodeType::LEAF;
        if (parsed.payload.find("collection") != std::string::npos) {
            node_type = PubSubNodeType::COLLECTION;
        }

        PubSubNodeConfig config;
        if (!parsed.config_fields.empty()) {
            config.apply_form_fields(parsed.config_fields);
        }

        auto node = pubsub_service_->create_node(parsed.node, parsed.from_jid,
                                                   node_type, config);
        if (!node) {
            return make_error_iq(parsed.id, parsed.from_jid,
                                 "409", "cancel", "conflict");
        }

        return make_create_result(parsed.id, parsed.from_jid, parsed.node);
    }

    std::string handle_subscribe(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        bool needs_config = false;
        PubSubSubscriptionState state = pubsub_service_->subscribe(
            parsed.node, parsed.from_jid, needs_config);

        if (state == PubSubSubscriptionState::NONE) {
            return make_error_iq(parsed.id, parsed.from_jid,
                                 "403", "auth", "forbidden");
        }

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(parsed.id) << "\"";
        oss << " to=\"" << xml_escape(parsed.from_jid) << "\">";
        oss << "<pubsub xmlns=\"" << XMPPNS::PUBSUB << "\">";
        oss << "<subscription";
        oss << " node=\"" << xml_escape(parsed.node) << "\"";
        oss << " jid=\"" << xml_escape(parsed.from_jid) << "\"";
        oss << " subscription=\"" << pubsub_subscription_state_to_string(state) << "\"";
        oss << "/>";
        oss << "</pubsub></iq>";
        return oss.str();
    }

    std::string handle_unsubscribe(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        bool ok = pubsub_service_->unsubscribe(
            parsed.node, parsed.from_jid,
            parsed.subscriber_jid, parsed.subid);

        if (!ok) {
            return make_error_iq(parsed.id, parsed.from_jid,
                                 "404", "cancel", "item-not-found");
        }

        return make_result_iq(parsed.id, parsed.from_jid);
    }

    std::string handle_publish(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        std::string item_id = pubsub_service_->publish(
            parsed.node, parsed.from_jid, parsed.payload, parsed.item_id);

        if (item_id.empty()) {
            return make_error_iq(parsed.id, parsed.from_jid,
                                 "403", "auth", "forbidden");
        }

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(parsed.id) << "\"";
        oss << " to=\"" << xml_escape(parsed.from_jid) << "\">";
        oss << "<pubsub xmlns=\"" << XMPPNS::PUBSUB << "\">";
        oss << "<publish node=\"" << xml_escape(parsed.node) << "\">";
        oss << "<item id=\"" << xml_escape(item_id) << "\"/>";
        oss << "</publish>";
        oss << "</pubsub></iq>";
        return oss.str();
    }

    std::string handle_retract(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        bool ok = pubsub_service_->retract(parsed.node, parsed.from_jid, parsed.item_id);
        if (!ok) {
            return make_error_iq(parsed.id, parsed.from_jid,
                                 "404", "cancel", "item-not-found");
        }

        return make_result_iq(parsed.id, parsed.from_jid);
    }

    std::string handle_items(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        auto items = pubsub_service_->get_items(parsed.node, parsed.from_jid,
                                                  parsed.item_id);

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(parsed.id) << "\"";
        oss << " to=\"" << xml_escape(parsed.from_jid) << "\">";
        oss << "<pubsub xmlns=\"" << XMPPNS::PUBSUB << "\">";
        oss << "<items node=\"" << xml_escape(parsed.node) << "\">";

        for (const auto& item : items) {
            oss << item->to_xml();
        }

        oss << "</items></pubsub></iq>";
        return oss.str();
    }

    std::string handle_delete(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        bool ok = pubsub_service_->delete_node(parsed.node, parsed.from_jid);
        if (!ok) {
            return make_error_iq(parsed.id, parsed.from_jid,
                                 "403", "auth", "forbidden");
        }

        return make_result_iq(parsed.id, parsed.from_jid);
    }

    std::string handle_purge(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        bool ok = pubsub_service_->purge_node(parsed.node, parsed.from_jid);
        if (!ok) {
            return make_error_iq(parsed.id, parsed.from_jid,
                                 "403", "auth", "forbidden");
        }

        return make_result_iq(parsed.id, parsed.from_jid);
    }

    std::string handle_configure(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        if (parsed.config_fields.empty()) {
            // GET: return current config
            auto node = pubsub_service_->get_node(parsed.node);
            if (!node) {
                return make_error_iq(parsed.id, parsed.from_jid,
                                     "404", "cancel", "item-not-found");
            }

            std::ostringstream oss;
            oss << "<iq type=\"result\" id=\"" << xml_escape(parsed.id) << "\"";
            oss << " to=\"" << xml_escape(parsed.from_jid) << "\">";
            oss << "<pubsub xmlns=\"" << XMPPNS::PUBSUB_OWNER << "\">";
            oss << "<configure node=\"" << xml_escape(parsed.node) << "\">";
            oss << node->config().to_config_form_xml();
            oss << "</configure>";
            oss << "</pubsub></iq>";
            return oss.str();
        } else {
            // SET: apply config
            bool ok = pubsub_service_->configure_node(parsed.node, parsed.from_jid,
                                                        parsed.config_fields);
            if (!ok) {
                return make_error_iq(parsed.id, parsed.from_jid,
                                     "403", "auth", "forbidden");
            }
            return make_result_iq(parsed.id, parsed.from_jid);
        }
    }

    std::string handle_default_config(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        auto default_config = pubsub_service_->get_default_config();

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(parsed.id) << "\"";
        oss << " to=\"" << xml_escape(parsed.from_jid) << "\">";
        oss << "<pubsub xmlns=\"" << XMPPNS::PUBSUB_OWNER << "\">";
        oss << "<default>";
        oss << default_config.to_config_form_xml();
        oss << "</default>";
        oss << "</pubsub></iq>";
        return oss.str();
    }

    std::string handle_affiliations_get(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        auto affiliations = pubsub_service_->get_affiliations(parsed.node,
                                                                parsed.from_jid);

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(parsed.id) << "\"";
        oss << " to=\"" << xml_escape(parsed.from_jid) << "\">";
        oss << "<pubsub xmlns=\"" << XMPPNS::PUBSUB << "\">";
        oss << "<affiliations node=\"" << xml_escape(parsed.node) << "\">";

        for (const auto& [jid, aff] : affiliations) {
            oss << "<affiliation jid=\"" << xml_escape(jid) << "\"";
            oss << " affiliation=\"" << pubsub_affiliation_to_string(aff) << "\"/>";
        }

        oss << "</affiliations></pubsub></iq>";
        return oss.str();
    }

    std::string handle_affiliations_set(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        if (parsed.subscriber_jid.empty()) {
            return make_error_iq(parsed.id, parsed.from_jid,
                                 "400", "modify", "bad-request");
        }

        bool ok = pubsub_service_->set_affiliation(
            parsed.node, parsed.from_jid, parsed.subscriber_jid, parsed.affiliation);
        if (!ok) {
            return make_error_iq(parsed.id, parsed.from_jid,
                                 "403", "auth", "forbidden");
        }

        return make_result_iq(parsed.id, parsed.from_jid);
    }

    std::string handle_subscriptions_get(const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        auto subs = pubsub_service_->get_subscriptions(parsed.node, parsed.from_jid);

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(parsed.id) << "\"";
        oss << " to=\"" << xml_escape(parsed.from_jid) << "\">";
        oss << "<pubsub xmlns=\"" << XMPPNS::PUBSUB_OWNER << "\">";
        oss << "<subscriptions node=\"" << xml_escape(parsed.node) << "\">";

        for (const auto& sub : subs) {
            oss << sub->to_xml();
        }

        oss << "</subscriptions></pubsub></iq>";
        return oss.str();
    }

    std::string handle_subscription_options_get(
        const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        // Return subscription options form
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(parsed.id) << "\"";
        oss << " to=\"" << xml_escape(parsed.from_jid) << "\">";
        oss << "<pubsub xmlns=\"" << XMPPNS::PUBSUB << "\">";
        oss << "<options node=\"" << xml_escape(parsed.node) << "\"";
        if (!parsed.subscriber_jid.empty()) {
            oss << " jid=\"" << xml_escape(parsed.subscriber_jid) << "\"";
        }
        oss << ">";
        oss << "<x xmlns=\"" << XMPPNS::X_DATA << "\" type=\"form\">";
        oss << "<field var=\"FORM_TYPE\" type=\"hidden\">";
        oss << "<value>" << XMPPNS::PUBSUB_SUBSCRIBE_OPTIONS << "</value>";
        oss << "</field>";
        oss << "<field var=\"pubsub#deliver\" type=\"boolean\" label=\"Enable delivery\">";
        oss << "<value>1</value>";
        oss << "</field>";
        oss << "<field var=\"pubsub#digest\" type=\"boolean\" label=\"Receive digest\">";
        oss << "<value>0</value>";
        oss << "</field>";
        oss << "<field var=\"pubsub#digest_frequency\" type=\"text-single\"";
        oss << " label=\"Digest frequency (milliseconds)\">";
        oss << "<value>86400000</value>";
        oss << "</field>";
        oss << "<field var=\"pubsub#include_body\" type=\"boolean\"";
        oss << " label=\"Include body in notifications\">";
        oss << "<value>0</value>";
        oss << "</field>";
        oss << "</x>";
        oss << "</options></pubsub></iq>";
        return oss.str();
    }

    std::string handle_owner_config_get(
        const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        return handle_configure(parsed);
    }

    std::string handle_owner_config_set(
        const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        return handle_configure(parsed);
    }

    std::string handle_owner_delete(
        const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        return handle_delete(parsed);
    }

    std::string handle_owner_purge(
        const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        return handle_purge(parsed);
    }

    std::string handle_owner_default(
        const PubSubStanzaParser::ParsedPubSubStanza& parsed) {
        return handle_default_config(parsed);
    }

    // ========================================================================
    // Stanza builders
    // ========================================================================

    static std::string xml_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '\"':  out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default:   out += c; break;
            }
        }
        return out;
    }

    static std::string make_result_iq(const std::string& id, const std::string& to) {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        if (!to.empty()) {
            oss << " to=\"" << xml_escape(to) << "\"";
        }
        oss << "/>";
        return oss.str();
    }

    static std::string make_error_iq(const std::string& id, const std::string& to,
                                      const std::string& code, const std::string& type,
                                      const std::string& condition) {
        std::ostringstream oss;
        oss << "<iq type=\"error\" id=\"" << xml_escape(id) << "\"";
        oss << " to=\"" << xml_escape(to) << "\">";
        oss << "<error code=\"" << code << "\" type=\"" << type << "\">";
        oss << "<" << condition << " xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/>";

        // Add pubsub-specific condition
        if (condition == "forbidden") {
            oss << "<closed-node xmlns=\"" << XMPPNS::PUBSUB_ERRORS << "\"/>";
        } else if (condition == "item-not-found") {
            oss << "<item-not-found xmlns=\"" << XMPPNS::PUBSUB_ERRORS << "\"/>";
        } else if (condition == "not-acceptable") {
            oss << "<not-subscribed xmlns=\"" << XMPPNS::PUBSUB_ERRORS << "\"/>";
        }

        oss << "</error></iq>";
        return oss.str();
    }

    static std::string make_create_result(const std::string& id,
                                           const std::string& to,
                                           const std::string& node_id) {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " to=\"" << xml_escape(to) << "\">";
        oss << "<pubsub xmlns=\"" << XMPPNS::PUBSUB << "\">";
        oss << "<create node=\"" << xml_escape(node_id) << "\"/>";
        oss << "</pubsub></iq>";
        return oss.str();
    }

    static std::string generate_instant_node_id() {
        static std::atomic<uint64_t> counter{0};
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        std::ostringstream oss;
        oss << "instant_" << ms << "_" << (++counter);
        return oss.str();
    }

    // ========================================================================
    // DISCO handlers
    // ========================================================================

    std::string handle_disco_info(const std::string& node_id) {
        if (node_id.empty()) {
            return pubsub_service_->generate_service_disco_info();
        }

        auto node = pubsub_service_->get_node(node_id);
        if (!node) {
            return "<query xmlns=\"" + std::string(XMPPNS::DISCO_INFO) +
                   "\"><identity category=\"pubsub\" type=\"leaf\"/></query>";
        }

        return node->generate_disco_info();
    }

    std::string handle_disco_items(const std::string& node_id) {
        if (node_id.empty()) {
            return pubsub_service_->generate_service_disco_items();
        }

        auto node = pubsub_service_->get_node(node_id);
        if (!node) {
            return "<query xmlns=\"" + std::string(XMPPNS::DISCO_ITEMS) + "\"/>";
        }

        return node->generate_disco_items();
    }

    PubSubServicePtr pubsub_service_;
    PEPHandlerPtr pep_handler_;
    std::string service_jid_;
};

// ============================================================================
// PubSubManager - Top-level manager combining service + PEP + handler
// ============================================================================

class PubSubManager {
public:
    using SendCallback = std::function<void(const std::string& stanza_xml)>;
    using Logger = std::function<void(const std::string& level, const std::string& message)>;

    PubSubManager(const std::string& service_jid,
                  SendCallback send_callback)
        : service_jid_(service_jid)
        , send_callback_(send_callback)
        , logging_enabled_(true)
    {
        pubsub_service_ = std::make_shared<PubSubService>(service_jid, send_callback);
        pep_handler_ = std::make_shared<PEPHandler>(pubsub_service_, send_callback);
        iq_handler_ = std::make_shared<PubSubIQHandler>(
            pubsub_service_, pep_handler_, service_jid);

        log_info("PubSubManager initialized for: " + service_jid);
    }

    ~PubSubManager() {
        shutdown();
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    std::shared_ptr<PubSubService> service() { return pubsub_service_; }
    std::shared_ptr<PEPHandler> pep() { return pep_handler_; }
    std::shared_ptr<PubSubIQHandler> iq_handler() { return iq_handler_; }

    const std::string& service_jid() const { return service_jid_; }

    // ========================================================================
    // Logging
    // ========================================================================

    void set_logger(Logger logger) {
        logger_ = logger;
        pubsub_service_->set_logger(logger);
    }

    void log_info(const std::string& msg) {
        if (logging_enabled_ && logger_) {
            logger_("INFO", msg);
        }
    }

    void log_warn(const std::string& msg) {
        if (logging_enabled_ && logger_) {
            logger_("WARN", msg);
        }
    }

    void log_error(const std::string& msg) {
        if (logging_enabled_ && logger_) {
            logger_("ERROR", msg);
        }
    }

    // ========================================================================
    // Stanza handling
    // ========================================================================

    std::string handle_stanza(const std::string& xml) {
        if (!pubsub_service_ || !pubsub_service_->is_enabled()) {
            return make_error_response(xml, "503", "cancel", "service-unavailable");
        }

        // Detect stanza type
        if (xml.find("<iq") != std::string::npos) {
            return handle_iq_stanza(xml);
        } else if (xml.find("<presence") != std::string::npos) {
            return handle_presence_stanza(xml);
        } else if (xml.find("<message") != std::string::npos) {
            return handle_message_stanza(xml);
        }

        return "";
    }

    // ========================================================================
    // Shutdown
    // ========================================================================

    void shutdown() {
        if (pubsub_service_) {
            pubsub_service_->shutdown();
        }
        log_info("PubSubManager shut down");
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    struct ManagerStats {
        PubSubService::PubSubStats service_stats;
        bool pep_enabled;
        bool service_enabled;
    };

    ManagerStats get_stats() {
        ManagerStats stats;
        stats.service_stats = pubsub_service_->get_stats();
        stats.pep_enabled = pep_handler_->is_enabled();
        stats.service_enabled = pubsub_service_->is_enabled();
        return stats;
    }

private:
    std::string handle_iq_stanza(const std::string& xml) {
        // Check if this is a DISCO request
        if (xml.find(XMPPNS::DISCO_INFO) != std::string::npos ||
            xml.find(XMPPNS::DISCO_ITEMS) != std::string::npos) {
            return handle_disco_stanza(xml);
        }

        // Check if it's a PubSub IQ
        if (xml.find(XMPPNS::PUBSUB) != std::string::npos ||
            xml.find(XMPPNS::PUBSUB_OWNER) != std::string::npos) {
            return iq_handler_->handle_iq(xml);
        }

        return make_error_response(xml, "501", "cancel",
                                    "feature-not-implemented");
    }

    std::string handle_presence_stanza(const std::string& xml) {
        std::string from = extract_attr(xml, "from");
        std::string type = extract_attr(xml, "type");

        if (from.empty()) return "";

        // Handle PEP presence
        pep_handler_->set_enabled(pubsub_service_->is_pep_enabled());
        pubsub_service_->handle_pep_presence(from, type);

        return "";  // No direct response for presence
    }

    std::string handle_message_stanza(const std::string& xml) {
        // PubSub doesn't typically handle messages directly,
        // except for subscription-related messages
        (void)xml;
        return "";
    }

    std::string handle_disco_stanza(const std::string& xml) {
        std::string id = extract_attr(xml, "id");
        std::string from = extract_attr(xml, "from");
        std::string to = extract_attr(xml, "to");

        // Extract node from disco request
        std::string node;
        size_t node_pos = xml.find("node=\"");
        if (node_pos != std::string::npos) {
            size_t start = node_pos + 6;
            size_t end = xml.find('"', start);
            if (end != std::string::npos) {
                node = xml.substr(start, end - start);
            }
        }

        std::string query_xml;
        if (xml.find(XMPPNS::DISCO_INFO) != std::string::npos) {
            query_xml = iq_handler_->handle_disco_info(node);
        } else {
            query_xml = iq_handler_->handle_disco_items(node);
        }

        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        oss << " from=\"" << xml_escape(service_jid_) << "\"";
        if (!from.empty()) {
            oss << " to=\"" << xml_escape(from) << "\"";
        }
        oss << ">" << query_xml << "</iq>";

        return oss.str();
    }

    static std::string extract_attr(const std::string& xml, const std::string& attr) {
        std::string search = attr + "=\"";
        size_t pos = xml.find(search);
        if (pos == std::string::npos) {
            search = attr + "='";
            pos = xml.find(search);
            if (pos == std::string::npos) return "";
        }
        pos += search.length();
        size_t end = xml.find(xml[pos - 1], pos);
        if (end == std::string::npos) return "";
        return xml.substr(pos, end - pos);
    }

    static std::string xml_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '\"':  out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default:   out += c; break;
            }
        }
        return out;
    }

    static std::string make_error_response(const std::string& original_xml,
                                            const std::string& code,
                                            const std::string& type,
                                            const std::string& condition) {
        std::string id = extract_attr(original_xml, "id");
        std::string from = extract_attr(original_xml, "from");

        std::ostringstream oss;
        oss << "<iq type=\"error\" id=\"" << xml_escape(id) << "\"";
        if (!from.empty()) {
            oss << " to=\"" << xml_escape(from) << "\"";
        }
        oss << ">";
        oss << "<error code=\"" << code << "\" type=\"" << type << "\">";
        oss << "<" << condition << " xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/>";
        oss << "</error></iq>";
        return oss.str();
    }

    std::string service_jid_;
    SendCallback send_callback_;
    std::shared_ptr<PubSubService> pubsub_service_;
    std::shared_ptr<PEPHandler> pep_handler_;
    std::shared_ptr<PubSubIQHandler> iq_handler_;
    Logger logger_;
    bool logging_enabled_;
};

// ============================================================================
// Utility: standalone PubSub notification sender
// ============================================================================

class PubSubNotificationSender {
public:
    using SendCallback = std::function<void(const std::string& stanza_xml)>;

    explicit PubSubNotificationSender(SendCallback callback)
        : send_callback_(callback) {}

    void send_items_event(const std::string& from, const std::string& to,
                          const std::string& node,
                          const std::vector<std::shared_ptr<PubSubItemRecord>>& items,
                          bool include_payload = true) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(from) << "\"";
        oss << " to=\"" << xml_escape(to) << "\">";
        oss << "<event xmlns=\"" << XMPPNS::PUBSUB_EVENT << "\">";
        oss << "<items node=\"" << xml_escape(node) << "\">";

        for (const auto& item : items) {
            oss << item->to_event_xml(include_payload);
        }

        oss << "</items></event></message>";
        send_callback_(oss.str());
    }

    void send_delete_event(const std::string& from, const std::string& to,
                           const std::string& node,
                           const std::string& redirect_uri = "") {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(from) << "\"";
        oss << " to=\"" << xml_escape(to) << "\">";
        oss << "<event xmlns=\"" << XMPPNS::PUBSUB_EVENT << "\">";
        oss << "<delete node=\"" << xml_escape(node) << "\">";
        if (!redirect_uri.empty()) {
            oss << "<redirect uri=\"" << xml_escape(redirect_uri) << "\"/>";
        }
        oss << "</delete></event></message>";
        send_callback_(oss.str());
    }

    void send_purge_event(const std::string& from, const std::string& to,
                          const std::string& node) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(from) << "\"";
        oss << " to=\"" << xml_escape(to) << "\">";
        oss << "<event xmlns=\"" << XMPPNS::PUBSUB_EVENT << "\">";
        oss << "<purge node=\"" << xml_escape(node) << "\"/>";
        oss << "</event></message>";
        send_callback_(oss.str());
    }

    void send_retract_event(const std::string& from, const std::string& to,
                            const std::string& node, const std::string& item_id) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(from) << "\"";
        oss << " to=\"" << xml_escape(to) << "\">";
        oss << "<event xmlns=\"" << XMPPNS::PUBSUB_EVENT << "\">";
        oss << "<items node=\"" << xml_escape(node) << "\">";
        oss << "<retract id=\"" << xml_escape(item_id) << "\"/>";
        oss << "</items></event></message>";
        send_callback_(oss.str());
    }

    void send_subscription_event(const std::string& from, const std::string& to,
                                  const std::string& node, const std::string& jid,
                                  PubSubSubscriptionState state) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(from) << "\"";
        oss << " to=\"" << xml_escape(to) << "\">";
        oss << "<event xmlns=\"" << XMPPNS::PUBSUB_EVENT << "\">";
        oss << "<subscription node=\"" << xml_escape(node) << "\"";
        oss << " jid=\"" << xml_escape(jid) << "\"";
        oss << " subscription=\"" << pubsub_subscription_state_to_string(state) << "\"/>";
        oss << "</event></message>";
        send_callback_(oss.str());
    }

    void send_config_event(const std::string& from, const std::string& to,
                           const std::string& node,
                           const PubSubNodeConfig& config) {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(from) << "\"";
        oss << " to=\"" << xml_escape(to) << "\">";
        oss << "<event xmlns=\"" << XMPPNS::PUBSUB_EVENT << "\">";
        oss << "<configuration node=\"" << xml_escape(node) << "\">";
        oss << config.to_config_form_xml();
        oss << "</configuration></event></message>";
        send_callback_(oss.str());
    }

private:
    static std::string xml_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '\"':  out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default:   out += c; break;
            }
        }
        return out;
    }

    SendCallback send_callback_;
};

// ============================================================================
// Utility: Subscription State Machine
// ============================================================================

class SubscriptionStateMachine {
public:
    static bool can_transition(PubSubSubscriptionState from, PubSubSubscriptionState to) {
        switch (from) {
            case PubSubSubscriptionState::NONE:
                return to == PubSubSubscriptionState::SUBSCRIBED ||
                       to == PubSubSubscriptionState::PENDING ||
                       to == PubSubSubscriptionState::UNCONFIGURED;
            case PubSubSubscriptionState::PENDING:
                return to == PubSubSubscriptionState::SUBSCRIBED ||
                       to == PubSubSubscriptionState::NONE;
            case PubSubSubscriptionState::UNCONFIGURED:
                return to == PubSubSubscriptionState::SUBSCRIBED ||
                       to == PubSubSubscriptionState::NONE;
            case PubSubSubscriptionState::SUBSCRIBED:
                return to == PubSubSubscriptionState::NONE;
            default:
                return false;
        }
    }

    static bool is_active(PubSubSubscriptionState state) {
        return state == PubSubSubscriptionState::SUBSCRIBED;
    }

    static bool is_pending(PubSubSubscriptionState state) {
        return state == PubSubSubscriptionState::PENDING ||
               state == PubSubSubscriptionState::UNCONFIGURED;
    }
};

// ============================================================================
// Utility: Access Model Checker
// ============================================================================

class AccessModelChecker {
public:
    struct CheckResult {
        bool can_subscribe = false;
        bool can_publish = false;
        bool can_view_items = false;
        bool can_configure = false;
        bool requires_approval = false;
        std::string reason;
    };

    static CheckResult check(PubSubAccessModel model,
                              PubSubAffiliation affiliation,
                              bool has_presence_subscription = false,
                              bool in_roster_group = false) {
        CheckResult result;

        if (affiliation == PubSubAffiliation::OUTCAST) {
            result.reason = "Entity is banned (outcast)";
            return result;
        }

        if (affiliation == PubSubAffiliation::OWNER) {
            result.can_subscribe = true;
            result.can_publish = true;
            result.can_view_items = true;
            result.can_configure = true;
            return result;
        }

        switch (model) {
            case PubSubAccessModel::OPEN:
                result.can_subscribe = true;
                result.can_publish = true;
                result.can_view_items = true;
                break;

            case PubSubAccessModel::PRESENCE:
                if (has_presence_subscription) {
                    result.can_subscribe = true;
                    result.can_publish = true;
                    result.can_view_items = true;
                } else if (affiliation == PubSubAffiliation::PUBLISHER ||
                           affiliation == PubSubAffiliation::MEMBER) {
                    result.can_subscribe = true;
                    result.can_publish = true;
                    result.can_view_items = true;
                } else {
                    result.reason = "Presence subscription required";
                }
                break;

            case PubSubAccessModel::ROSTER:
                if (in_roster_group) {
                    result.can_subscribe = true;
                    result.can_view_items = true;
                }
                if (affiliation == PubSubAffiliation::PUBLISHER ||
                    affiliation == PubSubAffiliation::PUBLISHER_ONLY) {
                    result.can_publish = true;
                }
                break;

            case PubSubAccessModel::AUTHORIZE:
                if (affiliation == PubSubAffiliation::PUBLISHER ||
                    affiliation == PubSubAffiliation::MEMBER) {
                    result.can_subscribe = true;
                    result.can_publish = true;
                    result.can_view_items = true;
                } else {
                    result.requires_approval = true;
                    result.reason = "Subscription requires owner approval";
                }
                break;

            case PubSubAccessModel::WHITELIST:
                if (affiliation == PubSubAffiliation::PUBLISHER ||
                    affiliation == PubSubAffiliation::PUBLISHER_ONLY) {
                    result.can_publish = true;
                }
                if (affiliation == PubSubAffiliation::MEMBER ||
                    affiliation == PubSubAffiliation::PUBLISHER) {
                    result.can_subscribe = true;
                    result.can_view_items = true;
                }
                if (affiliation == PubSubAffiliation::NONE) {
                    result.reason = "Not on whitelist";
                }
                break;
        }

        // Publisher-only can publish but not subscribe
        if (affiliation == PubSubAffiliation::PUBLISHER_ONLY) {
            result.can_subscribe = false;
            result.can_view_items = result.can_publish;
        }

        return result;
    }
};

}  // namespace xmpp
}  // namespace progressive
