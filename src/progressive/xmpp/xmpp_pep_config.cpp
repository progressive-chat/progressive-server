/*
 * progressive-server - XMPP PEP/PubSub Node Configuration, Access Models,
 *                       and Subscription Management
 *
 * This file provides the PEP-specific node configuration layer including:
 *   - PEP node creation with auto-subscribe (XEP-0163)
 *   - Detailed node configuration via XEP-0004 data forms
 *     (max_items, persist, deliver_payloads, access_model, send_last)
 *   - Access model enforcement: open, presence, roster, authorize, whitelist
 *   - Affiliation management: owner, publisher, publisher-only, member, none, outcast
 *   - Subscription states and state machine
 *   - Subscription options (digest, include_body, expiry, frequency)
 *   - DISCO#info and DISCO#items for PEP nodes
 *   - Default node configuration templates
 *   - Collection node support (XEP-0248)
 *   - Node purge and deletion with cascade
 *   - Event notifications: items, retract, delete, purge, configuration, subscription
 *   - Last published item cache with send-last-published-item support
 *   - Notification filtering (type, payload delivery, digest mode)
 *   - Subscription renewal and expiry management
 *   - Node metadata (XEP-0060 Section 12.19)
 *   - PEP service discovery including identity, features, and node listing
 *   - PEP+ presence integration and auto-subscription
 *   - Node ownership transfer and delegation
 *   - Subscription pending/approval workflow for authorize access model
 *   - Roster integration for roster access model
 *   - Whitelist maintenance for whitelist access model
 *   - Publisher-only affiliation enforcement
 *   - Instant node generation
 *   - Node indexing and lookup by type, owner, and access model
 *   - PEP node migration and upgrade
 *   - Access model migration with subscription state preservation
 *   - Notification batching and throttling
 *   - Payload size limit enforcement
 *   - Item expiry and automatic cleanup
 *   - Subscription state change event notifications
 *   - Node configuration change event notifications
 *   - Owner configuration management
 *   - Multi-subscription support with subid tracking
 *   - Subscription JID mapping and resolution
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
#include <limits>
#include <tuple>
#include <regex>
#include <shared_mutex>
#include <condition_variable>
#include <thread>

namespace progressive {
namespace xmpp {

// ============================================================================
// Forward declarations
// ============================================================================

class PEPNodeConfig;
class PEPNodeManager;
class PEPAccessController;
class PEPSubscriptionManager;
class PEPNotificationEngine;
class PEPDiscoveryHandler;
class PEPConfigSerializer;
class PEPConfigCache;
class PEPWhitelistManager;
class PEPRosterBridge;
class PEPPresenceTracker;
class PEPStateMachine;
class PEPAffiliationResolver;

// ============================================================================
// Constants and well-known PEP namespaces
// ============================================================================

namespace PEPConstants {
    // Standard PEP node namespaces per XEP-0163
    const char* AVATAR_DATA      = "urn:xmpp:avatar:data";
    const char* AVATAR_METADATA  = "urn:xmpp:avatar:metadata";
    const char* TUNE             = "http://jabber.org/protocol/tune";
    const char* ACTIVITY         = "http://jabber.org/protocol/activity";
    const char* MOOD             = "http://jabber.org/protocol/mood";
    const char* GEOLOC           = "http://jabber.org/protocol/geoloc";
    const char* NICK             = "http://jabber.org/protocol/nick";
    const char* MICROBLOG        = "urn:xmpp:microblog:0";
    const char* OMB_XMPP         = "urn:xmpp:omb:0";
    const char* BOOKMARKS        = "storage:bookmarks";
    const char* VCARD4_PEP       = "urn:xmpp:vcard4";
    const char* USER_LOCATION    = "urn:xmpp:location:0";
    const char* USER_PRESENCE    = "urn:xmpp:pep:extended-presence:0";

    // Default configuration values
    constexpr int DEFAULT_MAX_ITEMS_PEP        = 1;
    constexpr int DEFAULT_MAX_ITEMS_GENERAL    = 50;
    constexpr int DEFAULT_MAX_PAYLOAD_SIZE     = 65536;  // 64KB
    constexpr int DEFAULT_ITEM_EXPIRE_SECONDS  = 0;      // never expire
    constexpr int DEFAULT_NOTIFICATION_TIMEOUT = 30000;  // 30 seconds
    constexpr int MAX_SUBSCRIPTIONS_PER_NODE   = 10000;
    constexpr int MAX_NODES_PER_USER           = 1000;
    constexpr int MAX_TOTAL_NODES              = 1000000;

    // PEP-specific configuration defaults
    const char* DEFAULT_ACCESS_MODEL_PEP       = "presence";
    const char* DEFAULT_ACCESS_MODEL_GENERAL   = "open";

    // Node configuration field names per XEP-0060
    const char* FIELD_ACCESS_MODEL              = "pubsub#access_model";
    const char* FIELD_PERSIST_ITEMS             = "pubsub#persist_items";
    const char* FIELD_MAX_ITEMS                 = "pubsub#max_items";
    const char* FIELD_DELIVER_PAYLOADS          = "pubsub#deliver_payloads";
    const char* FIELD_DELIVER_NOTIFICATIONS     = "pubsub#deliver_notifications";
    const char* FIELD_SEND_LAST_PUBLISHED       = "pubsub#send_last_published_item";
    const char* FIELD_SUBSCRIBE                 = "pubsub#subscribe";
    const char* FIELD_SUBSCRIPTION_REQUIRED     = "pubsub#subscription_required";
    const char* FIELD_NOTIFY_CONFIG             = "pubsub#notify_config";
    const char* FIELD_NOTIFY_DELETE             = "pubsub#notify_delete";
    const char* FIELD_NOTIFY_RETRACT            = "pubsub#notify_retract";
    const char* FIELD_NOTIFY_SUB                = "pubsub#notify_sub";
    const char* FIELD_NOTIFY_UNSUB              = "pubsub#notify_unsub";
    const char* FIELD_TITLE                     = "pubsub#title";
    const char* FIELD_DESCRIPTION               = "pubsub#description";
    const char* FIELD_ITEM_EXPIRE               = "pubsub#item_expire";
    const char* FIELD_MAX_PAYLOAD_SIZE          = "pubsub#max_payload_size";
    const char* FIELD_COLLECTION                = "pubsub#collection";
    const char* FIELD_ROSTER_GROUPS_ALLOWED     = "pubsub#roster_groups_allowed";
    const char* FIELD_CONTACT                   = "pubsub#contact";
    const char* FIELD_LANGUAGE                  = "pubsub#language";
    const char* FIELD_PUBSUB_TYPE               = "pubsub#type";
    const char* FIELD_BODY_XSLT                 = "pubsub#body_xslt";
    const char* FIELD_PRESENCE_BASED_DELIVERY   = "pubsub#presence_based_delivery";
    const char* FIELD_CHILDREN                  = "pubsub#children";
    const char* FIELD_CHILD_ASSOCIATION_POLICY  = "pubsub#children_association_policy";
    const char* FIELD_MAX_CHILDREN              = "pubsub#children_max";
    const char* FIELD_ACCESS_MODEL_PEP          = "pubsub#access_model_pep";

    // Subscription option field names
    const char* SUBOPT_DELIVER           = "pubsub#deliver";
    const char* SUBOPT_DIGEST            = "pubsub#digest";
    const char* SUBOPT_DIGEST_FREQUENCY  = "pubsub#digest_frequency";
    const char* SUBOPT_INCLUDE_BODY      = "pubsub#include_body";
    const char* SUBOPT_SHOW_VALUES       = "pubsub#show-values";
    const char* SUBOPT_SUBSCRIPTION_TYPE = "pubsub#subscription_type";
    const char* SUBOPT_SUBSCRIPTION_DEPTH= "pubsub#subscription_depth";
    const char* SUBOPT_EXPIRE            = "pubsub#expire";

    // DISCO features
    const char* DISCO_FEATURE_PEP         = "http://jabber.org/protocol/pubsub#pep";
    const char* DISCO_FEATURE_AUTOCREATE  = "http://jabber.org/protocol/pubsub#auto-create";
    const char* DISCO_FEATURE_AUTOSUB     = "http://jabber.org/protocol/pubsub#auto-subscribe";
    const char* DISCO_FEATURE_FILTERED    = "http://jabber.org/protocol/pubsub#filtered-notifications";
    const char* DISCO_FEATURE_LAST_PUB    = "http://jabber.org/protocol/pubsub#last-published";
    const char* DISCO_FEATURE_PRESENCE    = "http://jabber.org/protocol/pubsub#presence-notifications";
    const char* DISCO_FEATURE_CONFIG      = "http://jabber.org/protocol/pubsub#config-node";
    const char* DISCO_FEATURE_CREATE      = "http://jabber.org/protocol/pubsub#create-nodes";
    const char* DISCO_FEATURE_CREATE_CONF = "http://jabber.org/protocol/pubsub#create-and-configure";
    const char* DISCO_FEATURE_DELETE      = "http://jabber.org/protocol/pubsub#delete-nodes";
    const char* DISCO_FEATURE_INSTANT     = "http://jabber.org/protocol/pubsub#instant-nodes";
    const char* DISCO_FEATURE_PUBLISH     = "http://jabber.org/protocol/pubsub#publish";
    const char* DISCO_FEATURE_RETRACT     = "http://jabber.org/protocol/pubsub#retract-items";
    const char* DISCO_FEATURE_RETRIEVE    = "http://jabber.org/protocol/pubsub#retrieve-items";
    const char* DISCO_FEATURE_SUBSCRIBE   = "http://jabber.org/protocol/pubsub#subscribe";
    const char* DISCO_FEATURE_AFFILIATIONS = "http://jabber.org/protocol/pubsub#affiliations";
    const char* DISCO_FEATURE_MANAGE_SUBS = "http://jabber.org/protocol/pubsub#manage-subscriptions";
    const char* DISCO_FEATURE_MULTI_SUB   = "http://jabber.org/protocol/pubsub#multi-subscribe";
    const char* DISCO_FEATURE_COLLECTIONS = "http://jabber.org/protocol/pubsub#collections";
    const char* DISCO_FEATURE_METADATA    = "http://jabber.org/protocol/pubsub#meta-data";
    const char* DISCO_FEATURE_PERSIST     = "http://jabber.org/protocol/pubsub#persistent-items";
    const char* DISCO_FEATURE_ITEM_IDS    = "http://jabber.org/protocol/pubsub#item-ids";
    const char* DISCO_FEATURE_PUB_AFF     = "http://jabber.org/protocol/pubsub#publisher-affiliation";
    const char* DISCO_FEATURE_OUTCAST     = "http://jabber.org/protocol/pubsub#outcast-affiliation";

    // Access model feature strings
    const char* FEATURE_ACCESS_OPEN      = "http://jabber.org/protocol/pubsub#access-open";
    const char* FEATURE_ACCESS_PRESENCE  = "http://jabber.org/protocol/pubsub#access-presence";
    const char* FEATURE_ACCESS_ROSTER    = "http://jabber.org/protocol/pubsub#access-roster";
    const char* FEATURE_ACCESS_AUTHORIZE = "http://jabber.org/protocol/pubsub#access-authorize";
    const char* FEATURE_ACCESS_WHITELIST = "http://jabber.org/protocol/pubsub#access-whitelist";
}

// ============================================================================
// Affiliations per XEP-0060 Section 3.1
// ============================================================================

enum class PEPAffiliation : int {
    NONE            = 0,
    OWNER           = 1,
    PUBLISHER       = 2,
    PUBLISHER_ONLY  = 3,
    MEMBER          = 4,
    OUTCAST         = 5
};

inline const char* pep_affiliation_str(PEPAffiliation aff) {
    switch (aff) {
        case PEPAffiliation::NONE:           return "none";
        case PEPAffiliation::OWNER:          return "owner";
        case PEPAffiliation::PUBLISHER:      return "publisher";
        case PEPAffiliation::PUBLISHER_ONLY: return "publisher-only";
        case PEPAffiliation::MEMBER:         return "member";
        case PEPAffiliation::OUTCAST:        return "outcast";
        default:                             return "none";
    }
}

inline PEPAffiliation pep_affiliation_from_str(const std::string& s) {
    if (s == "owner")           return PEPAffiliation::OWNER;
    if (s == "publisher")       return PEPAffiliation::PUBLISHER;
    if (s == "publisher-only")  return PEPAffiliation::PUBLISHER_ONLY;
    if (s == "member")          return PEPAffiliation::MEMBER;
    if (s == "outcast")         return PEPAffiliation::OUTCAST;
    return PEPAffiliation::NONE;
}

// ============================================================================
// Access models per XEP-0060 Section 4.1
// ============================================================================

enum class PEPAccessModel : int {
    OPEN            = 0,
    PRESENCE        = 1,
    ROSTER          = 2,
    AUTHORIZE       = 3,
    WHITELIST       = 4
};

inline const char* pep_access_model_str(PEPAccessModel am) {
    switch (am) {
        case PEPAccessModel::OPEN:       return "open";
        case PEPAccessModel::PRESENCE:   return "presence";
        case PEPAccessModel::ROSTER:     return "roster";
        case PEPAccessModel::AUTHORIZE:  return "authorize";
        case PEPAccessModel::WHITELIST:  return "whitelist";
        default:                         return "open";
    }
}

inline PEPAccessModel pep_access_model_from_str(const std::string& s) {
    if (s == "open")       return PEPAccessModel::OPEN;
    if (s == "presence")   return PEPAccessModel::PRESENCE;
    if (s == "roster")     return PEPAccessModel::ROSTER;
    if (s == "authorize")  return PEPAccessModel::AUTHORIZE;
    if (s == "whitelist")  return PEPAccessModel::WHITELIST;
    return PEPAccessModel::OPEN;
}

// ============================================================================
// Subscription states per XEP-0060 Section 6.1
// ============================================================================

enum class PEPSubscriptionState : int {
    NONE            = 0,
    SUBSCRIBED      = 1,
    PENDING         = 2,
    UNCONFIGURED    = 3
};

inline const char* pep_subscription_state_str(PEPSubscriptionState st) {
    switch (st) {
        case PEPSubscriptionState::NONE:         return "none";
        case PEPSubscriptionState::SUBSCRIBED:   return "subscribed";
        case PEPSubscriptionState::PENDING:      return "pending";
        case PEPSubscriptionState::UNCONFIGURED: return "unconfigured";
        default:                                 return "none";
    }
}

inline PEPSubscriptionState pep_subscription_state_from_str(const std::string& s) {
    if (s == "subscribed")   return PEPSubscriptionState::SUBSCRIBED;
    if (s == "pending")      return PEPSubscriptionState::PENDING;
    if (s == "unconfigured") return PEPSubscriptionState::UNCONFIGURED;
    return PEPSubscriptionState::NONE;
}

// ============================================================================
// Node types
// ============================================================================

enum class PEPNodeType : int {
    LEAF       = 0,
    COLLECTION = 1
};

inline const char* pep_node_type_str(PEPNodeType nt) {
    switch (nt) {
        case PEPNodeType::LEAF:       return "leaf";
        case PEPNodeType::COLLECTION: return "collection";
        default:                      return "leaf";
    }
}

inline PEPNodeType pep_node_type_from_str(const std::string& s) {
    if (s == "collection") return PEPNodeType::COLLECTION;
    return PEPNodeType::LEAF;
}

// ============================================================================
// Notification types for filtering
// ============================================================================

enum class PEPNotificationType : int {
    ITEMS          = 0,
    RETRACT        = 1,
    DELETE         = 2,
    PURGE          = 3,
    CONFIGURATION  = 4,
    SUBSCRIPTION   = 5
};

// ============================================================================
// Send-last-published-item modes
// ============================================================================

enum class PEPSendLastMode : int {
    NEVER               = 0,
    ON_SUB              = 1,
    ON_SUB_AND_PRESENCE = 2
};

inline const char* pep_send_last_str(PEPSendLastMode mode) {
    switch (mode) {
        case PEPSendLastMode::NEVER:                return "never";
        case PEPSendLastMode::ON_SUB:               return "on_sub";
        case PEPSendLastMode::ON_SUB_AND_PRESENCE:  return "on_sub_and_presence";
        default:                                    return "never";
    }
}

inline PEPSendLastMode pep_send_last_from_str(const std::string& s) {
    if (s == "on_sub_and_presence") return PEPSendLastMode::ON_SUB_AND_PRESENCE;
    if (s == "on_sub")              return PEPSendLastMode::ON_SUB;
    return PEPSendLastMode::NEVER;
}

// ============================================================================
// XML Namespaces
// ============================================================================

namespace PEPNS {
    const char* PUBSUB              = "http://jabber.org/protocol/pubsub";
    const char* PUBSUB_EVENT        = "http://jabber.org/protocol/pubsub#event";
    const char* PUBSUB_OWNER        = "http://jabber.org/protocol/pubsub#owner";
    const char* PUBSUB_NODE_CONFIG  = "http://jabber.org/protocol/pubsub#node_config";
    const char* PUBSUB_META_DATA    = "http://jabber.org/protocol/pubsub#meta-data";
    const char* PUBSUB_SUB_OPTIONS  = "http://jabber.org/protocol/pubsub#subscribe_options";
    const char* PUBSUB_ERRORS       = "http://jabber.org/protocol/pubsub#errors";
    const char* PUBSUB_COLLECTIONS  = "http://jabber.org/protocol/pubsub#collections";
    const char* DISCO_INFO          = "http://jabber.org/protocol/disco#info";
    const char* DISCO_ITEMS         = "http://jabber.org/protocol/disco#items";
    const char* X_DATA              = "jabber:x:data";
    const char* DELAY               = "urn:xmpp:delay";
    const char* SHIM                = "http://jabber.org/protocol/shim";
    const char* PEP                 = "http://jabber.org/protocol/pubsub#event";
    const char* CAPS                = "http://jabber.org/protocol/caps";
    const char* STANZAS             = "urn:ietf:params:xml:ns:xmpp-stanzas";
}

// ============================================================================
// Error conditions
// ============================================================================

namespace PEPError {
    const char* CLOSED_NODE             = "closed-node";
    const char* CONFIGURATION_REQUIRED  = "configuration-required";
    const char* INVALID_JID             = "invalid-jid";
    const char* ITEM_FORBIDDEN          = "item-forbidden";
    const char* ITEM_REQUIRED           = "item-required";
    const char* JID_REQUIRED            = "jid-required";
    const char* MAX_ITEMS_EXCEEDED      = "max-items-exceeded";
    const char* MAX_NODES_EXCEEDED      = "max-nodes-exceeded";
    const char* NODEID_REQUIRED         = "nodeid-required";
    const char* NOT_IN_ROSTER_GROUP     = "not-in-roster-group";
    const char* NOT_SUBSCRIBED          = "not-subscribed";
    const char* PAYLOAD_TOO_BIG         = "payload-too-big";
    const char* PAYLOAD_REQUIRED        = "payload-required";
    const char* PENDING_SUBSCRIPTION    = "pending-subscription";
    const char* PRESENCE_SUB_REQUIRED   = "presence-subscription-required";
    const char* SUBID_REQUIRED          = "subid-required";
    const char* TOO_MANY_SUBSCRIPTIONS  = "too-many-subscriptions";
    const char* UNSUPPORTED             = "unsupported";
    const char* UNSUPPORTED_ACCESS      = "unsupported-access-model";
    const char* NOT_AUTHORIZED          = "not-authorized";
    const char* ITEM_NOT_FOUND          = "item-not-found";
    const char* CONFLICT                = "conflict";
    const char* FORBIDDEN               = "forbidden";
    const char* SERVICE_UNAVAILABLE     = "service-unavailable";
    const char* REGISTRATION_REQUIRED   = "registration-required";
    const char* INTERNAL_ERROR          = "internal-server-error";
}

// ============================================================================
// XML utility
// ============================================================================

namespace {

std::string xml_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:   out += c; break;
        }
    }
    return out;
}

std::string xml_unescape(const std::string& s) {
    std::string result = s;
    size_t pos;
    while ((pos = result.find("&amp;"))  != std::string::npos) result.replace(pos, 5, "&");
    while ((pos = result.find("&lt;"))   != std::string::npos) result.replace(pos, 4, "<");
    while ((pos = result.find("&gt;"))   != std::string::npos) result.replace(pos, 4, ">");
    while ((pos = result.find("&quot;")) != std::string::npos) result.replace(pos, 6, "\"");
    while ((pos = result.find("&apos;")) != std::string::npos) result.replace(pos, 6, "'");
    return result;
}

std::string bare_jid(const std::string& jid) {
    size_t slash = jid.find('/');
    if (slash != std::string::npos) {
        return jid.substr(0, slash);
    }
    return jid;
}

std::string extract_attr(const std::string& xml, const std::string& attr) {
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
    return xml_unescape(xml.substr(pos, end - pos));
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\n\r");
    return s.substr(start, end - start + 1);
}

std::string timestamp_iso8601() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

}  // anonymous namespace

// ============================================================================
// PEPNodeConfig - Comprehensive PEP node configuration (XEP-0060 Section 16)
// ============================================================================

class PEPNodeConfig {
public:
    // Identity
    std::string node_id;
    std::string title;
    std::string description;
    std::string language;
    std::string contact;

    // Type
    PEPNodeType node_type = PEPNodeType::LEAF;
    bool is_pep_node = false;

    // Access
    PEPAccessModel access_model = PEPAccessModel::OPEN;
    std::set<std::string> roster_groups_allowed;

    // Publishing
    bool persist_items = false;
    int max_items = 0;               // 0 = unlimited
    int max_payload_size = 0;        // 0 = unlimited
    bool deliver_payloads = true;
    bool deliver_notifications = true;
    PEPSendLastMode send_last_published = PEPSendLastMode::ON_SUB_AND_PRESENCE;

    // Subscription
    bool subscribe = true;
    bool subscription_required = false;

    // Notifications
    bool notify_config = false;
    bool notify_delete = false;
    bool notify_retract = false;
    bool notify_sub = false;
    bool notify_unsub = false;

    // Item management
    int item_expire_seconds = 0;     // 0 = never
    bool purge_offline = false;

    // Collection
    std::string parent_collection_id;
    std::string children_association_policy;
    int max_children = 0;

    // Metadata
    std::string creator;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point updated_at;
    std::map<std::string, std::string> custom_metadata;

    // Body XSLT
    std::string body_xslt;

    // Presence-based delivery
    bool presence_based_delivery = false;

    // Payload type restrictions
    std::set<std::string> allowed_payload_types;

    PEPNodeConfig() {
        created_at = std::chrono::system_clock::now();
        updated_at = created_at;
    }

    // ========================================================================
    // Generate default PEP node configuration
    // ========================================================================
    static PEPNodeConfig default_pep_config() {
        PEPNodeConfig cfg;
        cfg.access_model = PEPAccessModel::PRESENCE;
        cfg.persist_items = true;
        cfg.max_items = PEPConstants::DEFAULT_MAX_ITEMS_PEP;
        cfg.deliver_payloads = true;
        cfg.deliver_notifications = true;
        cfg.send_last_published = PEPSendLastMode::ON_SUB_AND_PRESENCE;
        cfg.is_pep_node = true;
        cfg.subscribe = true;
        cfg.notify_retract = false;
        cfg.presence_based_delivery = true;
        return cfg;
    }

    static PEPNodeConfig default_pubsub_config() {
        PEPNodeConfig cfg;
        cfg.access_model = PEPAccessModel::OPEN;
        cfg.persist_items = false;
        cfg.max_items = PEPConstants::DEFAULT_MAX_ITEMS_GENERAL;
        cfg.deliver_payloads = true;
        cfg.deliver_notifications = true;
        cfg.send_last_published = PEPSendLastMode::ON_SUB_AND_PRESENCE;
        cfg.subscribe = true;
        return cfg;
    }

    // ========================================================================
    // Generate data form XML for this configuration (XEP-0004)
    // ========================================================================
    std::string to_config_form_xml(bool is_owner = false) const {
        std::ostringstream oss;
        oss << "<x xmlns=\"" << PEPNS::X_DATA << "\" type=\"form\">";
        oss << "<title>Node Configuration</title>";
        oss << "<instructions>Configure this PubSub node</instructions>";

        // FORM_TYPE
        oss << "<field var=\"FORM_TYPE\" type=\"hidden\">";
        oss << "<value>" << xml_escape(PEPNS::PUBSUB_NODE_CONFIG) << "</value>";
        oss << "</field>";

        // pubsub#title
        oss << "<field var=\"" << PEPConstants::FIELD_TITLE
            << "\" type=\"text-single\" label=\"Title\">";
        oss << "<value>" << xml_escape(title) << "</value>";
        oss << "</field>";

        // pubsub#description
        oss << "<field var=\"" << PEPConstants::FIELD_DESCRIPTION
            << "\" type=\"text-single\" label=\"Description\">";
        oss << "<value>" << xml_escape(description) << "</value>";
        oss << "</field>";

        // pubsub#language
        oss << "<field var=\"" << PEPConstants::FIELD_LANGUAGE
            << "\" type=\"text-single\" label=\"Language\">";
        oss << "<value>" << xml_escape(language) << "</value>";
        oss << "</field>";

        // pubsub#contact
        oss << "<field var=\"" << PEPConstants::FIELD_CONTACT
            << "\" type=\"jid-single\" label=\"Contact\">";
        oss << "<value>" << xml_escape(contact) << "</value>";
        oss << "</field>";

        // pubsub#access_model
        oss << "<field var=\"" << PEPConstants::FIELD_ACCESS_MODEL
            << "\" type=\"list-single\" label=\"Access Model\">";
        oss << "<value>" << pep_access_model_str(access_model) << "</value>";
        oss << "<option label=\"Open\"><value>open</value></option>";
        oss << "<option label=\"Presence\"><value>presence</value></option>";
        oss << "<option label=\"Roster\"><value>roster</value></option>";
        oss << "<option label=\"Authorize\"><value>authorize</value></option>";
        oss << "<option label=\"Whitelist\"><value>whitelist</value></option>";
        oss << "</field>";

        // pubsub#persist_items
        oss << "<field var=\"" << PEPConstants::FIELD_PERSIST_ITEMS
            << "\" type=\"boolean\" label=\"Persist Items\">";
        oss << "<value>" << (persist_items ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#max_items
        oss << "<field var=\"" << PEPConstants::FIELD_MAX_ITEMS
            << "\" type=\"text-single\" label=\"Max Items\">";
        oss << "<value>" << max_items << "</value>";
        oss << "</field>";

        // pubsub#deliver_payloads
        oss << "<field var=\"" << PEPConstants::FIELD_DELIVER_PAYLOADS
            << "\" type=\"boolean\" label=\"Deliver payloads\">";
        oss << "<value>" << (deliver_payloads ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#deliver_notifications
        oss << "<field var=\"" << PEPConstants::FIELD_DELIVER_NOTIFICATIONS
            << "\" type=\"boolean\" label=\"Deliver notifications\">";
        oss << "<value>" << (deliver_notifications ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#send_last_published_item
        oss << "<field var=\"" << PEPConstants::FIELD_SEND_LAST_PUBLISHED
            << "\" type=\"list-single\" label=\"Send last published item\">";
        oss << "<value>" << pep_send_last_str(send_last_published) << "</value>";
        oss << "<option label=\"Never\"><value>never</value></option>";
        oss << "<option label=\"On sub\"><value>on_sub</value></option>";
        oss << "<option label=\"On sub and presence\"><value>on_sub_and_presence</value></option>";
        oss << "</field>";

        // pubsub#subscribe
        oss << "<field var=\"" << PEPConstants::FIELD_SUBSCRIBE
            << "\" type=\"boolean\" label=\"Auto-subscribe creator\">";
        oss << "<value>" << (subscribe ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#subscription_required
        oss << "<field var=\"" << PEPConstants::FIELD_SUBSCRIPTION_REQUIRED
            << "\" type=\"boolean\" label=\"Subscription required\">";
        oss << "<value>" << (subscription_required ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#notify_config
        oss << "<field var=\"" << PEPConstants::FIELD_NOTIFY_CONFIG
            << "\" type=\"boolean\" label=\"Notify on config change\">";
        oss << "<value>" << (notify_config ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#notify_delete
        oss << "<field var=\"" << PEPConstants::FIELD_NOTIFY_DELETE
            << "\" type=\"boolean\" label=\"Notify on delete\">";
        oss << "<value>" << (notify_delete ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#notify_retract
        oss << "<field var=\"" << PEPConstants::FIELD_NOTIFY_RETRACT
            << "\" type=\"boolean\" label=\"Notify on retract\">";
        oss << "<value>" << (notify_retract ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#notify_sub
        oss << "<field var=\"" << PEPConstants::FIELD_NOTIFY_SUB
            << "\" type=\"boolean\" label=\"Notify on subscribe\">";
        oss << "<value>" << (notify_sub ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#notify_unsub
        oss << "<field var=\"" << PEPConstants::FIELD_NOTIFY_UNSUB
            << "\" type=\"boolean\" label=\"Notify on unsubscribe\">";
        oss << "<value>" << (notify_unsub ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#item_expire
        oss << "<field var=\"" << PEPConstants::FIELD_ITEM_EXPIRE
            << "\" type=\"text-single\" label=\"Item expiry (seconds)\">";
        oss << "<value>" << item_expire_seconds << "</value>";
        oss << "</field>";

        // pubsub#max_payload_size
        oss << "<field var=\"" << PEPConstants::FIELD_MAX_PAYLOAD_SIZE
            << "\" type=\"text-single\" label=\"Max payload size (bytes)\">";
        oss << "<value>" << max_payload_size << "</value>";
        oss << "</field>";

        // pubsub#presence_based_delivery
        oss << "<field var=\"" << PEPConstants::FIELD_PRESENCE_BASED_DELIVERY
            << "\" type=\"boolean\" label=\"Presence-based delivery\">";
        oss << "<value>" << (presence_based_delivery ? "1" : "0") << "</value>";
        oss << "</field>";

        // pubsub#roster_groups_allowed
        if (!roster_groups_allowed.empty()) {
            oss << "<field var=\"" << PEPConstants::FIELD_ROSTER_GROUPS_ALLOWED
                << "\" type=\"list-multi\" label=\"Allowed roster groups\">";
            for (const auto& group : roster_groups_allowed) {
                oss << "<value>" << xml_escape(group) << "</value>";
            }
            oss << "</field>";
        }

        // pubsub#collection (if in a collection)
        if (!parent_collection_id.empty()) {
            oss << "<field var=\"" << PEPConstants::FIELD_COLLECTION
                << "\" type=\"text-single\" label=\"Parent collection\">";
            oss << "<value>" << xml_escape(parent_collection_id) << "</value>";
            oss << "</field>";
        }

        // pubsub#children_max
        if (node_type == PEPNodeType::COLLECTION) {
            oss << "<field var=\"" << PEPConstants::FIELD_MAX_CHILDREN
                << "\" type=\"text-single\" label=\"Max children\">";
            oss << "<value>" << max_children << "</value>";
            oss << "</field>";

            oss << "<field var=\"" << PEPConstants::FIELD_CHILD_ASSOCIATION_POLICY
                << "\" type=\"list-single\" label=\"Child association policy\">";
            oss << "<value>" << xml_escape(children_association_policy) << "</value>";
            oss << "<option label=\"All\"><value>all</value></option>";
            oss << "<option label=\"Owners\"><value>owners</value></option>";
            oss << "<option label=\"Whitelist\"><value>whitelist</value></option>";
            oss << "</field>";
        }

        oss << "</x>";
        return oss.str();
    }

    // ========================================================================
    // Generate submit form XML
    // ========================================================================
    std::string to_submit_form_xml() const {
        std::ostringstream oss;
        oss << "<x xmlns=\"" << PEPNS::X_DATA << "\" type=\"submit\">";
        oss << "<field var=\"FORM_TYPE\"><value>"
            << xml_escape(PEPNS::PUBSUB_NODE_CONFIG) << "</value></field>";

        if (!title.empty())
            oss << "<field var=\"" << PEPConstants::FIELD_TITLE
                << "\"><value>" << xml_escape(title) << "</value></field>";
        if (!description.empty())
            oss << "<field var=\"" << PEPConstants::FIELD_DESCRIPTION
                << "\"><value>" << xml_escape(description) << "</value></field>";
        if (!language.empty())
            oss << "<field var=\"" << PEPConstants::FIELD_LANGUAGE
                << "\"><value>" << xml_escape(language) << "</value></field>";

        oss << "<field var=\"" << PEPConstants::FIELD_ACCESS_MODEL
            << "\"><value>" << pep_access_model_str(access_model) << "</value></field>";
        oss << "<field var=\"" << PEPConstants::FIELD_PERSIST_ITEMS
            << "\"><value>" << (persist_items ? "1" : "0") << "</value></field>";
        oss << "<field var=\"" << PEPConstants::FIELD_MAX_ITEMS
            << "\"><value>" << max_items << "</value></field>";
        oss << "<field var=\"" << PEPConstants::FIELD_DELIVER_PAYLOADS
            << "\"><value>" << (deliver_payloads ? "1" : "0") << "</value></field>";
        oss << "<field var=\"" << PEPConstants::FIELD_DELIVER_NOTIFICATIONS
            << "\"><value>" << (deliver_notifications ? "1" : "0") << "</value></field>";
        oss << "<field var=\"" << PEPConstants::FIELD_SEND_LAST_PUBLISHED
            << "\"><value>" << pep_send_last_str(send_last_published) << "</value></field>";
        oss << "<field var=\"" << PEPConstants::FIELD_NOTIFY_CONFIG
            << "\"><value>" << (notify_config ? "1" : "0") << "</value></field>";
        oss << "<field var=\"" << PEPConstants::FIELD_NOTIFY_DELETE
            << "\"><value>" << (notify_delete ? "1" : "0") << "</value></field>";
        oss << "<field var=\"" << PEPConstants::FIELD_NOTIFY_RETRACT
            << "\"><value>" << (notify_retract ? "1" : "0") << "</value></field>";

        oss << "</x>";
        return oss.str();
    }

    // ========================================================================
    // Generate meta-data form XML (XEP-0060 Section 12.19)
    // ========================================================================
    std::string to_metadata_xml() const {
        std::ostringstream oss;
        oss << "<metadata xmlns=\"" << PEPNS::PUBSUB_META_DATA << "\">";

        auto tc = std::chrono::system_clock::to_time_t(created_at);
        auto tu = std::chrono::system_clock::to_time_t(updated_at);

        oss << "<created>" << std::put_time(std::gmtime(&tc), "%Y-%m-%dT%H:%M:%SZ")
            << "</created>";
        oss << "<updated>" << std::put_time(std::gmtime(&tu), "%Y-%m-%dT%H:%M:%SZ")
            << "</updated>";
        oss << "<creator>" << xml_escape(creator) << "</creator>";
        oss << "<type>" << pep_node_type_str(node_type) << "</type>";

        if (!title.empty())
            oss << "<title>" << xml_escape(title) << "</title>";
        if (!description.empty())
            oss << "<description>" << xml_escape(description) << "</description>";
        if (!contact.empty())
            oss << "<contact>" << xml_escape(contact) << "</contact>";

        oss << "<access_model>" << pep_access_model_str(access_model) << "</access_model>";
        oss << "<persist_items>" << (persist_items ? "true" : "false") << "</persist_items>";
        oss << "<max_items>" << max_items << "</max_items>";

        for (const auto& [key, value] : custom_metadata) {
            oss << "<" << xml_escape(key) << ">" << xml_escape(value)
                << "</" << xml_escape(key) << ">";
        }

        oss << "</metadata>";
        return oss.str();
    }

    // ========================================================================
    // Apply form fields from a parsed data form
    // ========================================================================
    void apply_form_fields(const std::map<std::string, std::vector<std::string>>& fields) {
        for (const auto& [var, values] : fields) {
            if (values.empty()) continue;
            const std::string& val = values[0];

            if (var == PEPConstants::FIELD_TITLE)
                title = val;
            else if (var == PEPConstants::FIELD_DESCRIPTION)
                description = val;
            else if (var == PEPConstants::FIELD_LANGUAGE)
                language = val;
            else if (var == PEPConstants::FIELD_CONTACT)
                contact = val;
            else if (var == PEPConstants::FIELD_ACCESS_MODEL)
                access_model = pep_access_model_from_str(val);
            else if (var == PEPConstants::FIELD_PERSIST_ITEMS)
                persist_items = (val == "1" || val == "true");
            else if (var == PEPConstants::FIELD_MAX_ITEMS) {
                try { max_items = std::stoi(val); }
                catch (...) { max_items = 0; }
            }
            else if (var == PEPConstants::FIELD_DELIVER_PAYLOADS)
                deliver_payloads = (val == "1" || val == "true");
            else if (var == PEPConstants::FIELD_DELIVER_NOTIFICATIONS)
                deliver_notifications = (val == "1" || val == "true");
            else if (var == PEPConstants::FIELD_SEND_LAST_PUBLISHED)
                send_last_published = pep_send_last_from_str(val);
            else if (var == PEPConstants::FIELD_SUBSCRIBE)
                subscribe = (val == "1" || val == "true");
            else if (var == PEPConstants::FIELD_SUBSCRIPTION_REQUIRED)
                subscription_required = (val == "1" || val == "true");
            else if (var == PEPConstants::FIELD_NOTIFY_CONFIG)
                notify_config = (val == "1" || val == "true");
            else if (var == PEPConstants::FIELD_NOTIFY_DELETE)
                notify_delete = (val == "1" || val == "true");
            else if (var == PEPConstants::FIELD_NOTIFY_RETRACT)
                notify_retract = (val == "1" || val == "true");
            else if (var == PEPConstants::FIELD_NOTIFY_SUB)
                notify_sub = (val == "1" || val == "true");
            else if (var == PEPConstants::FIELD_NOTIFY_UNSUB)
                notify_unsub = (val == "1" || val == "true");
            else if (var == PEPConstants::FIELD_ITEM_EXPIRE) {
                try { item_expire_seconds = std::stoi(val); }
                catch (...) { item_expire_seconds = 0; }
            }
            else if (var == PEPConstants::FIELD_MAX_PAYLOAD_SIZE) {
                try { max_payload_size = std::stoi(val); }
                catch (...) { max_payload_size = 0; }
            }
            else if (var == PEPConstants::FIELD_COLLECTION)
                parent_collection_id = val;
            else if (var == PEPConstants::FIELD_ROSTER_GROUPS_ALLOWED) {
                roster_groups_allowed.clear();
                for (const auto& v : values) {
                    roster_groups_allowed.insert(v);
                }
            }
            else if (var == PEPConstants::FIELD_PRESENCE_BASED_DELIVERY)
                presence_based_delivery = (val == "1" || val == "true");
            else if (var == PEPConstants::FIELD_CHILD_ASSOCIATION_POLICY)
                children_association_policy = val;
            else if (var == PEPConstants::FIELD_MAX_CHILDREN) {
                try { max_children = std::stoi(val); }
                catch (...) { max_children = 0; }
            }
            else if (var == PEPConstants::FIELD_PUBSUB_TYPE) {
                if (val == "collection") node_type = PEPNodeType::COLLECTION;
                else node_type = PEPNodeType::LEAF;
            }
            else if (var == PEPConstants::FIELD_BODY_XSLT)
                body_xslt = val;
        }
        updated_at = std::chrono::system_clock::now();
    }

    // ========================================================================
    // Validate configuration
    // ========================================================================
    bool validate(std::string& error) const {
        if (max_items < -1) {
            error = "max_items must be -1 (unlimited) or >= 0";
            return false;
        }
        if (max_payload_size < 0) {
            error = "max_payload_size must be >= 0";
            return false;
        }
        if (item_expire_seconds < 0) {
            error = "item_expire_seconds must be >= 0";
            return false;
        }
        if (max_children < 0) {
            error = "max_children must be >= 0";
            return false;
        }
        if (subscription_required && access_model == PEPAccessModel::OPEN) {
            error = "subscription_required is incompatible with open access model";
            return false;
        }
        if (node_type == PEPNodeType::LEAF && !parent_collection_id.empty()) {
            // Verify that a leaf node can have a parent - this is valid
        }
        if (node_type == PEPNodeType::COLLECTION && !parent_collection_id.empty()) {
            error = "collection nodes cannot have parent collections (nesting not supported)";
            return false;
        }
        return true;
    }

    // ========================================================================
    // Get the default config for a specific access model
    // ========================================================================
    static PEPNodeConfig for_access_model(PEPAccessModel am) {
        PEPNodeConfig cfg;
        cfg.access_model = am;
        switch (am) {
            case PEPAccessModel::OPEN:
                cfg.persist_items = false;
                cfg.subscription_required = false;
                break;
            case PEPAccessModel::PRESENCE:
                cfg.persist_items = true;
                cfg.subscription_required = false;
                cfg.presence_based_delivery = true;
                break;
            case PEPAccessModel::ROSTER:
                cfg.persist_items = false;
                cfg.subscription_required = false;
                break;
            case PEPAccessModel::AUTHORIZE:
                cfg.persist_items = true;
                cfg.subscription_required = true;
                cfg.notify_sub = true;
                break;
            case PEPAccessModel::WHITELIST:
                cfg.persist_items = true;
                cfg.subscription_required = true;
                break;
        }
        return cfg;
    }
};

// ============================================================================
// PEPAffiliationRecord - Affiliation entry
// ============================================================================

struct PEPAffiliationRecord {
    std::string jid;
    PEPAffiliation affiliation;
    std::chrono::system_clock::time_point set_at;
    std::string set_by;

    PEPAffiliationRecord() : affiliation(PEPAffiliation::NONE) {}
    PEPAffiliationRecord(const std::string& j, PEPAffiliation a, const std::string& sb)
        : jid(j), affiliation(a), set_by(sb) {
        set_at = std::chrono::system_clock::now();
    }

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<affiliation jid=\"" << xml_escape(jid) << "\"";
        oss << " affiliation=\"" << pep_affiliation_str(affiliation) << "\"/>";
        return oss.str();
    }
};

// ============================================================================
// PEPSubscriptionOptions - Per-subscription options
// ============================================================================

struct PEPSubscriptionOptions {
    bool deliver = true;
    bool digest = false;
    int digest_frequency = 86400000;  // milliseconds (24h default)
    bool include_body = false;
    std::set<std::string> show_values;
    std::string subscription_type;
    int subscription_depth = 1;
    bool expires_never = true;
    std::chrono::system_clock::time_point expires_at;

    PEPSubscriptionOptions() {
        expires_at = std::chrono::system_clock::now() + std::chrono::hours(365 * 100);
    }

    std::string to_options_form_xml(const std::string& subid = "") const {
        std::ostringstream oss;
        oss << "<x xmlns=\"" << PEPNS::X_DATA << "\" type=\"form\">";
        oss << "<field var=\"FORM_TYPE\" type=\"hidden\">";
        oss << "<value>" << PEPNS::PUBSUB_SUB_OPTIONS << "</value>";
        oss << "</field>";

        oss << "<field var=\"" << PEPConstants::SUBOPT_DELIVER
            << "\" type=\"boolean\" label=\"Enable delivery\">";
        oss << "<value>" << (deliver ? "1" : "0") << "</value>";
        oss << "</field>";

        oss << "<field var=\"" << PEPConstants::SUBOPT_DIGEST
            << "\" type=\"boolean\" label=\"Receive digest\">";
        oss << "<value>" << (digest ? "1" : "0") << "</value>";
        oss << "</field>";

        oss << "<field var=\"" << PEPConstants::SUBOPT_DIGEST_FREQUENCY
            << "\" type=\"text-single\" label=\"Digest frequency (ms)\">";
        oss << "<value>" << digest_frequency << "</value>";
        oss << "</field>";

        oss << "<field var=\"" << PEPConstants::SUBOPT_INCLUDE_BODY
            << "\" type=\"boolean\" label=\"Include body\">";
        oss << "<value>" << (include_body ? "1" : "0") << "</value>";
        oss << "</field>";

        if (!show_values.empty()) {
            oss << "<field var=\"" << PEPConstants::SUBOPT_SHOW_VALUES
                << "\" type=\"list-multi\" label=\"Show values\">";
            for (const auto& sv : show_values) {
                oss << "<value>" << xml_escape(sv) << "</value>";
            }
            oss << "</field>";
        }

        oss << "<field var=\"" << PEPConstants::SUBOPT_SUBSCRIPTION_TYPE
            << "\" type=\"list-single\" label=\"Subscription type\">";
        oss << "<value>" << xml_escape(subscription_type) << "</value>";
        oss << "<option label=\"Items\"><value>items</value></option>";
        oss << "<option label=\"Nodes\"><value>nodes</value></option>";
        oss << "</field>";

        oss << "<field var=\"" << PEPConstants::SUBOPT_SUBSCRIPTION_DEPTH
            << "\" type=\"list-single\" label=\"Subscription depth\">";
        oss << "<value>" << subscription_depth << "</value>";
        oss << "<option label=\"1 (self only)\"><value>1</value></option>";
        oss << "<option label=\"All\"><value>all</value></option>";
        oss << "</field>";

        oss << "</x>";
        return oss.str();
    }

    void apply_options_form(const std::map<std::string, std::vector<std::string>>& fields) {
        for (const auto& [var, values] : fields) {
            if (values.empty()) continue;
            const std::string& val = values[0];

            if (var == PEPConstants::SUBOPT_DELIVER)
                deliver = (val == "1" || val == "true");
            else if (var == PEPConstants::SUBOPT_DIGEST)
                digest = (val == "1" || val == "true");
            else if (var == PEPConstants::SUBOPT_DIGEST_FREQUENCY) {
                try { digest_frequency = std::stoi(val); }
                catch (...) {}
            }
            else if (var == PEPConstants::SUBOPT_INCLUDE_BODY)
                include_body = (val == "1" || val == "true");
            else if (var == PEPConstants::SUBOPT_SHOW_VALUES) {
                show_values.clear();
                for (const auto& v : values) show_values.insert(v);
            }
            else if (var == PEPConstants::SUBOPT_SUBSCRIPTION_TYPE)
                subscription_type = val;
            else if (var == PEPConstants::SUBOPT_SUBSCRIPTION_DEPTH) {
                if (val == "all") subscription_depth = -1;
                else {
                    try { subscription_depth = std::stoi(val); }
                    catch (...) { subscription_depth = 1; }
                }
            }
            else if (var == PEPConstants::SUBOPT_EXPIRE) {
                if (val == "never" || val.empty()) {
                    expires_never = true;
                } else {
                    try {
                        int64_t secs = std::stoll(val);
                        expires_at = std::chrono::system_clock::now() +
                            std::chrono::seconds(secs);
                        expires_never = false;
                    } catch (...) {}
                }
            }
        }
    }
};

// ============================================================================
// PEPSubscriptionRecord - A single subscription
// ============================================================================

class PEPSubscriptionRecord {
public:
    PEPSubscriptionRecord()
        : state_(PEPSubscriptionState::NONE) {}

    PEPSubscriptionRecord(const std::string& jid, PEPSubscriptionState state,
                          const std::string& subid = "")
        : jid_(jid)
        , state_(state)
        , subscription_id_(subid.empty() ? generate_subid() : subid)
        , created_at_(std::chrono::system_clock::now())
        , renewed_at_(created_at_) {}

    const std::string& jid() const { return jid_; }
    void set_jid(const std::string& j) { jid_ = j; }

    PEPSubscriptionState state() const { return state_; }
    void set_state(PEPSubscriptionState s) {
        state_ = s;
        if (s == PEPSubscriptionState::SUBSCRIBED) {
            renewed_at_ = std::chrono::system_clock::now();
        }
    }

    const std::string& subscription_id() const { return subscription_id_; }
    void set_subscription_id(const std::string& sid) { subscription_id_ = sid; }

    std::chrono::system_clock::time_point created_at() const { return created_at_; }
    std::chrono::system_clock::time_point renewed_at() const { return renewed_at_; }

    PEPSubscriptionOptions& options() { return options_; }
    const PEPSubscriptionOptions& options() const { return options_; }
    void set_options(const PEPSubscriptionOptions& opts) { options_ = opts; }

    bool is_active() const { return state_ == PEPSubscriptionState::SUBSCRIBED; }
    bool is_pending() const {
        return state_ == PEPSubscriptionState::PENDING ||
               state_ == PEPSubscriptionState::UNCONFIGURED;
    }

    bool is_expired() const {
        if (options_.expires_never) return false;
        return std::chrono::system_clock::now() > options_.expires_at;
    }

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<subscription";
        oss << " jid=\"" << xml_escape(jid_) << "\"";
        oss << " subscription=\"" << pep_subscription_state_str(state_) << "\"";
        if (!subscription_id_.empty()) {
            oss << " subid=\"" << xml_escape(subscription_id_) << "\"";
        }
        oss << "/>";
        return oss.str();
    }

    std::string to_owner_xml(const std::string& node_id) const {
        std::ostringstream oss;
        oss << "<subscription";
        oss << " node=\"" << xml_escape(node_id) << "\"";
        oss << " jid=\"" << xml_escape(jid_) << "\"";
        oss << " subscription=\"" << pep_subscription_state_str(state_) << "\"";
        if (!subscription_id_.empty()) {
            oss << " subid=\"" << xml_escape(subscription_id_) << "\"";
        }
        oss << "/>";
        return oss.str();
    }

    void renew() {
        renewed_at_ = std::chrono::system_clock::now();
    }

private:
    static std::string generate_subid() {
        static std::atomic<uint64_t> counter{0};
        std::ostringstream oss;
        oss << "sub_" << now_ms() << "_" << (++counter);
        return oss.str();
    }

    std::string jid_;
    PEPSubscriptionState state_;
    std::string subscription_id_;
    std::chrono::system_clock::time_point created_at_;
    std::chrono::system_clock::time_point renewed_at_;
    PEPSubscriptionOptions options_;
};

// ============================================================================
// PEPLastPublishedCache - Last published item cache
// ============================================================================

class PEPLastPublishedCache {
public:
    struct CachedItem {
        std::string item_id;
        std::string publisher;
        std::string payload;
        std::chrono::system_clock::time_point published_at;
        size_t payload_size = 0;

        std::string to_event_xml(bool include_payload) const {
            std::ostringstream oss;
            oss << "<item";
            if (!item_id.empty())
                oss << " id=\"" << xml_escape(item_id) << "\"";
            if (!publisher.empty())
                oss << " publisher=\"" << xml_escape(publisher) << "\"";
            oss << ">";
            if (include_payload && !payload.empty()) {
                oss << payload;
            }
            oss << "</item>";
            return oss.str();
        }
    };

    void set(const std::string& item_id, const std::string& publisher,
             const std::string& payload) {
        std::lock_guard<std::mutex> lock(mutex_);
        cached_item_.item_id = item_id;
        cached_item_.publisher = publisher;
        cached_item_.payload = payload;
        cached_item_.published_at = std::chrono::system_clock::now();
        cached_item_.payload_size = payload.size();
        has_data_ = true;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        has_data_ = false;
        cached_item_ = CachedItem{};
    }

    std::optional<CachedItem> get() const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!has_data_) return std::nullopt;
        return cached_item_;
    }

    bool has_item() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return has_data_;
    }

    std::optional<std::string> get_publisher() const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!has_data_) return std::nullopt;
        return cached_item_.publisher;
    }

    std::string build_last_notification(const std::string& node_id,
                                         const std::string& from_jid,
                                         const std::string& to_jid,
                                         bool include_payload) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!has_data_) return "";

        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(from_jid) << "\"";
        oss << " to=\"" << xml_escape(to_jid) << "\">";
        oss << "<event xmlns=\"" << PEPNS::PUBSUB_EVENT << "\">";
        oss << "<items node=\"" << xml_escape(node_id) << "\">";
        oss << cached_item_.to_event_xml(include_payload);
        oss << "</items></event></message>";
        return oss.str();
    }

private:
    mutable std::mutex mutex_;
    CachedItem cached_item_;
    bool has_data_ = false;
};

// ============================================================================
// PEPNodeInstance - Represents a single PEP node with full config
// ============================================================================

class PEPNodeInstance {
public:
    using SubscriptionPtr = std::shared_ptr<PEPSubscriptionRecord>;
    using AffiliationMap = std::map<std::string, PEPAffiliationRecord>;

    PEPNodeInstance(const std::string& node_id, const std::string& creator_jid)
        : node_id_(node_id)
        , state_(PEPNodeState::CREATING)
    {
        config_.node_id = node_id;
        config_.creator = creator_jid;
    }

    // ========================================================================
    // Identity
    // ========================================================================
    const std::string& node_id() const { return node_id_; }
    PEPNodeState state() const { return state_; }
    void set_state(PEPNodeState s) { state_ = s; }
    bool is_active() const { return state_ == PEPNodeState::ACTIVE; }
    bool is_deleted() const { return state_ == PEPNodeState::DELETED; }
    bool is_purged() const { return state_ == PEPNodeState::PURGED; }
    bool is_leaf() const { return config_.node_type == PEPNodeType::LEAF; }
    bool is_collection() const { return config_.node_type == PEPNodeType::COLLECTION; }
    bool is_pep() const { return config_.is_pep_node; }

    // ========================================================================
    // Configuration
    // ========================================================================
    PEPNodeConfig& config() { return config_; }
    const PEPNodeConfig& config() const { return config_; }
    void set_config(const PEPNodeConfig& c) { config_ = c; }

    // ========================================================================
    // Affiliation management
    // ========================================================================
    PEPAffiliation get_affiliation(const std::string& jid) const {
        std::shared_lock lock(affiliations_mutex_);
        std::string bare = bare_jid(jid);
        auto it = affiliations_.find(bare);
        if (it != affiliations_.end()) return it->second.affiliation;
        return PEPAffiliation::NONE;
    }

    void set_affiliation(const std::string& jid, PEPAffiliation aff,
                         const std::string& set_by = "") {
        std::unique_lock lock(affiliations_mutex_);
        std::string bare = bare_jid(jid);
        if (aff == PEPAffiliation::NONE) {
            affiliations_.erase(bare);
        } else {
            affiliations_[bare] = PEPAffiliationRecord(bare, aff,
                set_by.empty() ? config_.creator : set_by);
        }
    }

    bool is_owner(const std::string& jid) const {
        return get_affiliation(jid) == PEPAffiliation::OWNER;
    }

    bool is_outcast(const std::string& jid) const {
        return get_affiliation(jid) == PEPAffiliation::OUTCAST;
    }

    AffiliationMap get_all_affiliations() const {
        std::shared_lock lock(affiliations_mutex_);
        return affiliations_;
    }

    // ========================================================================
    // Subscription management
    // ========================================================================
    SubscriptionPtr get_subscription(const std::string& jid) const {
        std::shared_lock lock(subscriptions_mutex_);
        std::string bare = bare_jid(jid);
        auto it = subscriptions_.find(bare);
        if (it != subscriptions_.end()) return it->second;
        return nullptr;
    }

    PEPSubscriptionState get_subscription_state(const std::string& jid) const {
        auto sub = get_subscription(jid);
        if (sub) return sub->state();
        return PEPSubscriptionState::NONE;
    }

    bool is_subscribed(const std::string& jid) const {
        auto sub = get_subscription(jid);
        return sub && sub->is_active();
    }

    void add_subscription(const std::string& jid, PEPSubscriptionState state,
                          const std::string& subid = "") {
        std::unique_lock lock(subscriptions_mutex_);
        std::string bare = bare_jid(jid);
        auto it = subscriptions_.find(bare);
        if (it != subscriptions_.end()) {
            it->second->set_state(state);
            return;
        }
        auto sub = std::make_shared<PEPSubscriptionRecord>(bare, state, subid);
        subscriptions_[bare] = sub;
    }

    bool remove_subscription(const std::string& jid) {
        std::unique_lock lock(subscriptions_mutex_);
        std::string bare = bare_jid(jid);
        auto it = subscriptions_.find(bare);
        if (it != subscriptions_.end()) {
            subscriptions_.erase(it);
            return true;
        }
        return false;
    }

    std::vector<SubscriptionPtr> get_all_subscriptions() const {
        std::shared_lock lock(subscriptions_mutex_);
        std::vector<SubscriptionPtr> result;
        for (const auto& [jid, sub] : subscriptions_) {
            result.push_back(sub);
        }
        return result;
    }

    std::vector<SubscriptionPtr> get_active_subscriptions() const {
        std::shared_lock lock(subscriptions_mutex_);
        std::vector<SubscriptionPtr> result;
        for (const auto& [jid, sub] : subscriptions_) {
            if (sub->is_active()) result.push_back(sub);
        }
        return result;
    }

    int subscription_count() const {
        std::shared_lock lock(subscriptions_mutex_);
        return static_cast<int>(subscriptions_.size());
    }

    int active_subscription_count() const {
        std::shared_lock lock(subscriptions_mutex_);
        int count = 0;
        for (const auto& [jid, sub] : subscriptions_) {
            if (sub->is_active()) ++count;
        }
        return count;
    }

    void set_subscription_options(const std::string& jid,
                                   const PEPSubscriptionOptions& opts) {
        std::unique_lock lock(subscriptions_mutex_);
        std::string bare = bare_jid(jid);
        auto it = subscriptions_.find(bare);
        if (it != subscriptions_.end()) {
            it->second->set_options(opts);
        }
    }

    // ========================================================================
    // Item management
    // ========================================================================
    bool add_item(const std::string& item_id, const std::string& publisher,
                  const std::string& payload) {
        std::unique_lock lock(items_mutex_);

        // Check payload size
        if (config_.max_payload_size > 0 &&
            payload.size() > static_cast<size_t>(config_.max_payload_size)) {
            return false;
        }

        auto item = std::make_shared<PEPItemEntry>();
        item->item_id = item_id;
        item->publisher = publisher;
        item->payload = payload;
        item->published_at = std::chrono::system_clock::now();

        // Update existing or append
        bool found = false;
        for (auto& existing : items_) {
            if (existing->item_id == item_id) {
                existing = item;
                found = true;
                break;
            }
        }
        if (!found) {
            items_.push_back(item);
            if (config_.max_items > 0 &&
                items_.size() > static_cast<size_t>(config_.max_items)) {
                items_.erase(items_.begin());
            }
        }

        last_published_cache_.set(item_id, publisher, payload);
        return true;
    }

    bool retract_item(const std::string& item_id) {
        std::unique_lock lock(items_mutex_);
        for (auto it = items_.begin(); it != items_.end(); ++it) {
            if ((*it)->item_id == item_id) {
                retracted_ids_.insert(item_id);
                items_.erase(it);

                auto cached = last_published_cache_.get();
                if (cached && cached->item_id == item_id) {
                    if (!items_.empty()) {
                        last_published_cache_.set(
                            items_.back()->item_id,
                            items_.back()->publisher,
                            items_.back()->payload);
                    } else {
                        last_published_cache_.clear();
                    }
                }
                return true;
            }
        }
        return false;
    }

    std::vector<std::shared_ptr<PEPItemEntry>> get_items(int max_results = 0) const {
        std::shared_lock lock(items_mutex_);
        std::vector<std::shared_ptr<PEPItemEntry>> result;
        int count = max_results > 0 ? std::min(max_results, static_cast<int>(items_.size()))
                                     : static_cast<int>(items_.size());
        int start = std::max(0, static_cast<int>(items_.size()) - count);
        for (size_t i = static_cast<size_t>(start); i < items_.size(); ++i) {
            result.push_back(items_[i]);
        }
        return result;
    }

    std::shared_ptr<PEPItemEntry> get_item(const std::string& item_id) const {
        std::shared_lock lock(items_mutex_);
        for (const auto& item : items_) {
            if (item->item_id == item_id) return item;
        }
        return nullptr;
    }

    std::optional<PEPLastPublishedCache::CachedItem> get_last_published() const {
        return last_published_cache_.get();
    }

    bool has_last_published() const {
        return last_published_cache_.has_item();
    }

    int item_count() const {
        std::shared_lock lock(items_mutex_);
        return static_cast<int>(items_.size());
    }
           std::optional<PEPLastPublishedCache::CachedItem> get_last_published() const {
               return last_published_cache_.get();
           }
           bool has_last_published() const {
               return last_published_cache_.has_item();
           }
           int item_count() const {
               std::shared_lock lock(items_mutex_);
               return static_cast<int>(items_.size());
           }

           bool is_item_retracted(const std::string& item_id) const {
               std::shared_lock lock(items_mutex_);
               return retracted_ids_.find(item_id) != retracted_ids_.end();
           }

           // ========================================================================
           // Purge and delete
           // ========================================================================
           void purge() {
               std::unique_lock lock(items_mutex_);
               items_.clear();
               retracted_ids_.clear();
               last_published_cache_.clear();
               state_ = PEPNodeState::PURGED;
           }
           void mark_deleted() {
               state_ = PEPNodeState::DELETED;
           }
           void set_state_active() {
               state_ = PEPNodeState::ACTIVE;
           }
           // ... rest unchanged

    // ========================================================================
    // Collection support
    // ========================================================================
    void add_child_node(const std::string& child_id) {
        std::unique_lock lock(children_mutex_);
        child_node_ids_.insert(child_id);
    }

    void remove_child_node(const std::string& child_id) {
        std::unique_lock lock(children_mutex_);
        child_node_ids_.erase(child_id);
    }

    std::set<std::string> get_child_nodes() const {
        std::shared_lock lock(children_mutex_);
        return child_node_ids_;
    }

    int child_count() const {
        std::shared_lock lock(children_mutex_);
        return static_cast<int>(child_node_ids_.size());
    }

    // ========================================================================
    // DISCO helpers
    // ========================================================================
    std::string generate_disco_info() const {
        std::ostringstream oss;
        oss << "<query xmlns=\"" << PEPNS::DISCO_INFO << "\">";

        std::string identity_type = config_.is_pep_node ? "pep" : pep_node_type_str(config_.node_type);
        oss << "<identity category=\"pubsub\" type=\"" << identity_type << "\"";
        if (!config_.title.empty()) {
            oss << " name=\"" << xml_escape(config_.title) << "\"";
        }
        oss << "/>";

        // Core features
        oss << "<feature var=\"" << PEPNS::PUBSUB << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_PUBLISH << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_RETRACT << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_SUBSCRIBE << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_RETRIEVE << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_CONFIG << "\"/>";

        if (config_.persist_items) {
            oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_PERSIST << "\"/>";
        }
        if (config_.is_pep_node) {
            oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_AUTOCREATE << "\"/>";
            oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_AUTOSUB << "\"/>";
        }

        // Access model features
        switch (config_.access_model) {
            case PEPAccessModel::OPEN:
                oss << "<feature var=\"" << PEPConstants::FEATURE_ACCESS_OPEN << "\"/>";
                break;
            case PEPAccessModel::PRESENCE:
                oss << "<feature var=\"" << PEPConstants::FEATURE_ACCESS_PRESENCE << "\"/>";
                break;
            case PEPAccessModel::ROSTER:
                oss << "<feature var=\"" << PEPConstants::FEATURE_ACCESS_ROSTER << "\"/>";
                break;
            case PEPAccessModel::AUTHORIZE:
                oss << "<feature var=\"" << PEPConstants::FEATURE_ACCESS_AUTHORIZE << "\"/>";
                break;
            case PEPAccessModel::WHITELIST:
                oss << "<feature var=\"" << PEPConstants::FEATURE_ACCESS_WHITELIST << "\"/>";
                break;
        }

        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_AFFILIATIONS << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_METADATA << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_ITEM_IDS << "\"/>";

        if (config_.node_type == PEPNodeType::COLLECTION) {
            oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_COLLECTIONS << "\"/>";
        }

        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_FILTERED << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_LAST_PUB << "\"/>";

        oss << "</query>";
        return oss.str();
    }

    std::string generate_disco_items(const std::string& service_jid) const {
        std::ostringstream oss;
        oss << "<query xmlns=\"" << PEPNS::DISCO_ITEMS << "\">";

        if (config_.node_type == PEPNodeType::COLLECTION) {
            std::shared_lock lock(children_mutex_);
            for (const auto& child_id : child_node_ids_) {
                oss << "<item jid=\"" << xml_escape(service_jid) << "\"";
                oss << " node=\"" << xml_escape(child_id) << "\"/>";
            }
        } else if (config_.persist_items) {
            std::shared_lock lock(items_mutex_);
            for (const auto& item : items_) {
                oss << "<item jid=\"" << xml_escape(service_jid) << "\"";
                oss << " name=\"" << xml_escape(item->item_id) << "\"/>";
            }
        }

        oss << "</query>";
        return oss.str();
    }

    // ========================================================================
    // Event notification building
    // ========================================================================
    std::string build_items_event(const std::string& from, const std::string& to,
                                   const std::vector<std::string>& item_xmls) const {
        std::ostringstream oss;
        oss << "<message from=\"" << xml_escape(from) << "\"";
        oss << " to=\"" << xml_escape(to) << "\">";
        oss << "<event xmlns=\"" << PEPNS::PUBSUB_EVENT << "\">";
        oss << "<items node=\"" << xml_escape(node_id_) << "\">";
        for (const auto& xml : item_xmls) {
            oss << xml;
        }
        oss << "</items></event></message>";
        return oss.str();
    }

    std::string build_retract_event(const std::string& item_id) const {
        std::ostringstream oss;
        oss << "<event xmlns=\"" << PEPNS::PUBSUB_EVENT << "\">";
        oss << "<items node=\"" << xml_escape(node_id_) << "\">";
        oss << "<retract id=\"" << xml_escape(item_id) << "\"/>";
        oss << "</items></event>";
        return oss.str();
    }

    std::string build_delete_event() const {
        std::ostringstream oss;
        oss << "<event xmlns=\"" << PEPNS::PUBSUB_EVENT << "\">";
        oss << "<delete node=\"" << xml_escape(node_id_) << "\"/>";
        oss << "</event>";
        return oss.str();
    }

    std::string build_purge_event() const {
        std::ostringstream oss;
        oss << "<event xmlns=\"" << PEPNS::PUBSUB_EVENT << "\">";
        oss << "<purge node=\"" << xml_escape(node_id_) << "\"/>";
        oss << "</event>";
        return oss.str();
    }

    std::string build_config_event() const {
        std::ostringstream oss;
        oss << "<event xmlns=\"" << PEPNS::PUBSUB_EVENT << "\">";
        oss << "<configuration node=\"" << xml_escape(node_id_) << "\">";
        oss << config_.to_config_form_xml();
        oss << "</configuration></event>";
        return oss.str();
    }

    std::string build_subscription_event(const std::string& jid,
                                          PEPSubscriptionState state) const {
        std::ostringstream oss;
        oss << "<event xmlns=\"" << PEPNS::PUBSUB_EVENT << "\">";
        oss << "<subscription node=\"" << xml_escape(node_id_) << "\"";
        oss << " jid=\"" << xml_escape(jid) << "\"";
        oss << " subscription=\"" << pep_subscription_state_str(state) << "\"/>";
        oss << "</event>";
        return oss.str();
    }

    std::string build_last_published_message(const std::string& from,
                                              const std::string& to) {
        return last_published_cache_.build_last_notification(
            node_id_, from, to, config_.deliver_payloads);
    }

private:
    struct PEPItemEntry {
        std::string item_id;
        std::string publisher;
        std::string payload;
        std::chrono::system_clock::time_point published_at;
    };

    enum class PEPNodeState {
        CREATING = 0,
        ACTIVE   = 1,
        PURGED   = 2,
        DELETED  = 3
    };

    std::string node_id_;
    PEPNodeState state_;
    PEPNodeConfig config_;
    PEPLastPublishedCache last_published_cache_;

    mutable std::shared_mutex affiliations_mutex_;
    AffiliationMap affiliations_;

    mutable std::shared_mutex subscriptions_mutex_;
    std::map<std::string, SubscriptionPtr> subscriptions_;

    mutable std::shared_mutex items_mutex_;
    std::vector<std::shared_ptr<PEPItemEntry>> items_;
    std::set<std::string> retracted_ids_;

    mutable std::shared_mutex children_mutex_;
    std::set<std::string> child_node_ids_;
};

// ============================================================================
// PEPAccessController - Enforces access model rules
// ============================================================================

class PEPAccessController {
public:
    struct AccessCheckResult {
        bool allowed = false;
        bool requires_approval = false;
        bool needs_configuration = false;
        std::string reason;
    };

    // ========================================================================
    // Check if an entity can subscribe to a node
    // ========================================================================
    static AccessCheckResult can_subscribe(const PEPNodeConfig& config,
                                           const std::string& requester_jid,
                                           PEPAffiliation affiliation,
                                           bool has_presence_sub = false,
                                           bool in_roster_group = false) {
        AccessCheckResult result;
        std::string bare = bare_jid(requester_jid);

        if (affiliation == PEPAffiliation::OUTCAST) {
            result.reason = "Entity is outcast";
            return result;
        }

        if (config.subscription_required) {
            if (affiliation != PEPAffiliation::OWNER &&
                affiliation != PEPAffiliation::MEMBER) {
                result.reason = "Subscription requires member or owner affiliation";
                return result;
            }
        }

        switch (config.access_model) {
            case PEPAccessModel::OPEN:
                result.allowed = true;
                break;

            case PEPAccessModel::PRESENCE:
                if (affiliation == PEPAffiliation::OWNER) {
                    result.allowed = true;
                } else if (has_presence_sub) {
                    result.allowed = true;
                } else if (affiliation == PEPAffiliation::PUBLISHER ||
                           affiliation == PEPAffiliation::MEMBER) {
                    result.allowed = true;
                } else {
                    result.reason = "Presence subscription required";
                }
                break;

            case PEPAccessModel::ROSTER:
                if (affiliation == PEPAffiliation::OWNER) {
                    result.allowed = true;
                } else if (in_roster_group) {
                    result.allowed = true;
                    result.needs_configuration = true;
                } else if (affiliation == PEPAffiliation::MEMBER) {
                    result.allowed = true;
                } else {
                    result.reason = "Not in allowed roster group";
                }
                break;

            case PEPAccessModel::AUTHORIZE:
                if (affiliation == PEPAffiliation::OWNER) {
                    result.allowed = true;
                } else if (affiliation == PEPAffiliation::PUBLISHER ||
                           affiliation == PEPAffiliation::MEMBER) {
                    result.allowed = true;
                } else {
                    result.requires_approval = true;
                    result.allowed = true;  // Allowed to request
                }
                break;

            case PEPAccessModel::WHITELIST:
                if (affiliation == PEPAffiliation::OWNER) {
                    result.allowed = true;
                } else if (affiliation == PEPAffiliation::PUBLISHER ||
                           affiliation == PEPAffiliation::MEMBER) {
                    result.allowed = true;
                } else {
                    result.reason = "Not on whitelist";
                }
                break;
        }

        return result;
    }

    // ========================================================================
    // Check if an entity can publish to a node
    // ========================================================================
    static AccessCheckResult can_publish(const PEPNodeConfig& config,
                                         PEPAffiliation affiliation) {
        AccessCheckResult result;

        if (affiliation == PEPAffiliation::OUTCAST) {
            result.reason = "Entity is outcast";
            return result;
        }

        switch (affiliation) {
            case PEPAffiliation::OWNER:
            case PEPAffiliation::PUBLISHER:
                result.allowed = true;
                break;
            case PEPAffiliation::PUBLISHER_ONLY:
                result.allowed = true;
                break;
            case PEPAffiliation::MEMBER:
                if (config.access_model == PEPAccessModel::OPEN ||
                    config.access_model == PEPAccessModel::PRESENCE) {
                    result.allowed = true;
                }
                break;
            case PEPAffiliation::NONE:
                if (config.access_model == PEPAccessModel::OPEN) {
                    result.allowed = true;
                } else {
                    result.reason = "Publishing requires publisher affiliation";
                }
                break;
        }

        return result;
    }

    // ========================================================================
    // Check if an entity can view items
    // ========================================================================
    static AccessCheckResult can_view_items(const PEPNodeConfig& config,
                                             PEPAffiliation affiliation,
                                             bool has_presence_sub = false,
                                             bool in_roster_group = false) {
        AccessCheckResult result;

        if (affiliation == PEPAffiliation::OUTCAST) {
            result.reason = "Entity is outcast";
            return result;
        }

        if (affiliation == PEPAffiliation::OWNER) {
            result.allowed = true;
            return result;
        }

        switch (config.access_model) {
            case PEPAccessModel::OPEN:
                result.allowed = true;
                break;
            case PEPAccessModel::PRESENCE:
                result.allowed = has_presence_sub ||
                    affiliation >= PEPAffiliation::PUBLISHER;
                break;
            case PEPAccessModel::ROSTER:
                result.allowed = in_roster_group ||
                    affiliation >= PEPAffiliation::MEMBER;
                break;
            case PEPAccessModel::AUTHORIZE:
                result.allowed = affiliation >= PEPAffiliation::MEMBER;
                break;
            case PEPAccessModel::WHITELIST:
                result.allowed = affiliation >= PEPAffiliation::MEMBER;
                break;
        }

        if (!result.allowed && result.reason.empty()) {
            result.reason = "Access denied by access model";
        }
        return result;
    }

    // ========================================================================
    // Check if an entity can configure a node
    // ========================================================================
    static AccessCheckResult can_configure(const PEPNodeConfig& config,
                                            PEPAffiliation affiliation) {
        AccessCheckResult result;
        result.allowed = (affiliation == PEPAffiliation::OWNER);
        if (!result.allowed) {
            result.reason = "Only owners can configure the node";
        }
        return result;
    }

    // ========================================================================
    // Determine the subscription state based on access model
    // ========================================================================
    static PEPSubscriptionState determine_initial_state(
        const PEPNodeConfig& config,
        PEPAffiliation affiliation,
        bool needs_approval) {
        if (needs_approval) {
            return PEPSubscriptionState::PENDING;
        }

        if (config.access_model == PEPAccessModel::AUTHORIZE &&
            affiliation == PEPAffiliation::NONE) {
            return PEPSubscriptionState::PENDING;
        }

        if (config.access_model == PEPAccessModel::ROSTER &&
            affiliation == PEPAffiliation::NONE) {
            return PEPSubscriptionState::UNCONFIGURED;
        }

        return PEPSubscriptionState::SUBSCRIBED;
    }
};

// ============================================================================
// PEPSubscriptionManager - Manages all subscriptions for PEP nodes
// ============================================================================

class PEPSubscriptionManager {
public:
    using NodePtr = std::shared_ptr<PEPNodeInstance>;

    struct SubscribeRequest {
        std::string node_id;
        std::string subscriber_jid;
        std::string requested_subid;
        std::map<std::string, std::vector<std::string>> options_fields;
    };

    struct SubscribeResult {
        bool success = false;
        PEPSubscriptionState state = PEPSubscriptionState::NONE;
        std::string subscription_id;
        bool needs_configuration = false;
        bool requires_approval = false;
        std::string error;
    };

    // ========================================================================
    // Process a subscribe request
    // ========================================================================
    SubscribeResult subscribe(NodePtr node, const std::string& subscriber_jid,
                              bool has_presence_sub = false,
                              bool in_roster_group = false) {
        SubscribeResult result;

        if (!node || !node->is_active()) {
            result.error = "Node not found or not active";
            return result;
        }

        std::string bare = bare_jid(subscriber_jid);
        PEPAffiliation aff = node->get_affiliation(bare);

        auto check = PEPAccessController::can_subscribe(
            node->config(), subscriber_jid, aff,
            has_presence_sub, in_roster_group);

        if (!check.allowed) {
            result.error = check.reason;
            return result;
        }

        // Check max subscriptions
        if (node->subscription_count() >= PEPConstants::MAX_SUBSCRIPTIONS_PER_NODE) {
            result.error = "Too many subscriptions";
            return result;
        }

        result.requires_approval = check.requires_approval;
        result.needs_configuration = check.needs_configuration;
        result.state = PEPAccessController::determine_initial_state(
            node->config(), aff, check.requires_approval);

        // Add subscription
        std::string subid = generate_subid();
        node->add_subscription(bare, result.state, subid);
        result.subscription_id = subid;
        result.success = true;

        // Send last published item on subscribe
        if (result.state == PEPSubscriptionState::SUBSCRIBED &&
            node->config().send_last_published != PEPSendLastMode::NEVER) {
            if (node->has_last_published()) {
                // Deferred: caller sends via notification engine
            }
        }

        return result;
    }

    // ========================================================================
    // Process an unsubscribe request
    // ========================================================================
    bool unsubscribe(NodePtr node, const std::string& subscriber_jid,
                     const std::string& requested_subid = "") {
        if (!node || !node->is_active()) return false;

        std::string bare = bare_jid(subscriber_jid);
        auto sub = node->get_subscription(bare);

        if (!sub) return false;
        if (!requested_subid.empty() && sub->subscription_id() != requested_subid) {
            return false;
        }

        return node->remove_subscription(bare);
    }

    // ========================================================================
    // Approve a pending subscription
    // ========================================================================
    bool approve_subscription(NodePtr node, const std::string& subscriber_jid) {
        if (!node) return false;

        std::string bare = bare_jid(subscriber_jid);
        auto sub = node->get_subscription(bare);
        if (!sub || !sub->is_pending()) return false;

        sub->set_state(PEPSubscriptionState::SUBSCRIBED);
        return true;
    }

    // ========================================================================
    // Reject a pending subscription
    // ========================================================================
    bool reject_subscription(NodePtr node, const std::string& subscriber_jid) {
        if (!node) return false;

        std::string bare = bare_jid(subscriber_jid);
        auto sub = node->get_subscription(bare);
        if (!sub || !sub->is_pending()) return false;

        node->remove_subscription(bare);
        return true;
    }

    // ========================================================================
    // Set subscription options
    // ========================================================================
    bool set_subscription_options(NodePtr node, const std::string& jid,
                                   const PEPSubscriptionOptions& opts) {
        if (!node) return false;

        std::string bare = bare_jid(jid);
        auto sub = node->get_subscription(bare);
        if (!sub) return false;

        sub->set_options(opts);
        return true;
    }

    // ========================================================================
    // Renew a subscription
    // ========================================================================
    bool renew_subscription(NodePtr node, const std::string& jid) {
        if (!node) return false;

        std::string bare = bare_jid(jid);
        auto sub = node->get_subscription(bare);
        if (!sub) return false;

        sub->renew();
        return true;
    }

    // ========================================================================
    // Check for expired subscriptions
    // ========================================================================
    std::vector<std::string> get_expired_subscribers(NodePtr node) {
        std::vector<std::string> expired;
        if (!node) return expired;

        auto subs = node->get_all_subscriptions();
        auto now = std::chrono::system_clock::now();

        for (const auto& sub : subs) {
            if (sub->is_active() && sub->is_expired()) {
                expired.push_back(sub->jid());
            }
        }
        return expired;
    }

    // ========================================================================
    // Cleanup expired subscriptions
    // ========================================================================
    int cleanup_expired(NodePtr node) {
        auto expired = get_expired_subscribers(node);
        for (const auto& jid : expired) {
            node->remove_subscription(jid);
        }
        return static_cast<int>(expired.size());
    }

private:
    static std::string generate_subid() {
        static std::atomic<uint64_t> counter{0};
        std::ostringstream oss;
        oss << "pepsub_" << now_ms() << "_" << (++counter);
        return oss.str();
    }
};

// ============================================================================
// PEPWhitelistManager - Manages whitelist entries
// ============================================================================

class PEPWhitelistManager {
public:
    void add(const std::string& node_id, const std::string& jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        whitelists_[node_id].insert(bare_jid(jid));
    }

    void remove(const std::string& node_id, const std::string& jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = whitelists_.find(node_id);
        if (it != whitelists_.end()) {
            it->second.erase(bare_jid(jid));
            if (it->second.empty()) {
                whitelists_.erase(it);
            }
        }
    }

    bool contains(const std::string& node_id, const std::string& jid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = whitelists_.find(node_id);
        if (it != whitelists_.end()) {
            return it->second.find(bare_jid(jid)) != it->second.end();
        }
        return false;
    }

    std::set<std::string> get_whitelist(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = whitelists_.find(node_id);
        if (it != whitelists_.end()) {
            return it->second;
        }
        return {};
    }

    void clear_node(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        whitelists_.erase(node_id);
    }

    size_t size(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = whitelists_.find(node_id);
        if (it != whitelists_.end()) {
            return it->second.size();
        }
        return 0;
    }

private:
    mutable std::mutex mutex_;
    std::map<std::string, std::set<std::string>> whitelists_;
};

// ============================================================================
// PEPNotificationEngine - Builds and sends PEP event notifications
// ============================================================================

class PEPNotificationEngine {
public:
    using NodePtr = std::shared_ptr<PEPNodeInstance>;
    using SendCallback = std::function<void(const std::string& stanza_xml)>;

    PEPNotificationEngine(SendCallback send_cb)
        : send_callback_(send_cb) {}

    // ========================================================================
    // Send items event to all active subscribers
    // ========================================================================
    void notify_items(NodePtr node, const std::string& item_xml,
                      const std::string& from_jid) {
        if (!node || !node->config().deliver_notifications) return;

        auto subs = node->get_active_subscriptions();
        for (const auto& sub : subs) {
            if (!sub->options().deliver) continue;

            std::ostringstream msg;
            msg << "<message from=\"" << xml_escape(from_jid) << "\"";
            msg << " to=\"" << xml_escape(sub->jid()) << "\">";
            msg << "<event xmlns=\"" << PEPNS::PUBSUB_EVENT << "\">";
            msg << "<items node=\"" << xml_escape(node->node_id()) << "\">";
            msg << item_xml;
            msg << "</items></event></message>";
            send_callback_(msg.str());
        }
    }

    // ========================================================================
    // Send retract event
    // ========================================================================
    void notify_retract(NodePtr node, const std::string& item_id,
                        const std::string& from_jid) {
        if (!node || !node->config().notify_retract) return;

        std::string event_xml = node->build_retract_event(item_id);
        broadcast_event(node, event_xml, from_jid);
    }

    // ========================================================================
    // Send delete event
    // ========================================================================
    void notify_delete(NodePtr node, const std::string& from_jid) {
        if (!node) return;

        std::string event_xml = node->build_delete_event();
        broadcast_event(node, event_xml, from_jid);
    }

    // ========================================================================
    // Send purge event
    // ========================================================================
    void notify_purge(NodePtr node, const std::string& from_jid) {
        if (!node) return;

        std::string event_xml = node->build_purge_event();
        broadcast_event(node, event_xml, from_jid);
    }

    // ========================================================================
    // Send configuration change event
    // ========================================================================
    void notify_config(NodePtr node, const std::string& from_jid) {
        if (!node || !node->config().notify_config) return;

        std::string event_xml = node->build_config_event();
        broadcast_event(node, event_xml, from_jid);
    }

    // ========================================================================
    // Send subscription change event
    // ========================================================================
    void notify_subscription(NodePtr node, const std::string& subscriber_jid,
                             PEPSubscriptionState state, const std::string& from_jid) {
        if (!node) return;

        bool is_sub = (state == PEPSubscriptionState::SUBSCRIBED);
        if (is_sub && !node->config().notify_sub) return;
        if (!is_sub && !node->config().notify_unsub) return;

        std::string event_xml = node->build_subscription_event(subscriber_jid, state);
        broadcast_event(node, event_xml, from_jid);
    }

    // ========================================================================
    // Send last published item to a specific subscriber
    // ========================================================================
    void send_last_published(NodePtr node, const std::string& to_jid,
                             const std::string& from_jid) {
        if (!node) return;

        std::string msg = node->build_last_published_message(from_jid, to_jid);
        if (!msg.empty()) {
            send_callback_(msg);
        }
    }

private:
    void broadcast_event(NodePtr node, const std::string& event_xml,
                         const std::string& from_jid) {
        auto subs = node->get_active_subscriptions();
        for (const auto& sub : subs) {
            if (!sub->options().deliver) continue;

            std::ostringstream msg;
            msg << "<message from=\"" << xml_escape(from_jid) << "\"";
            msg << " to=\"" << xml_escape(sub->jid()) << "\">";
            msg << event_xml;
            msg << "</message>";
            send_callback_(msg.str());
        }
    }

    SendCallback send_callback_;
};

// ============================================================================
// PEPDiscoveryHandler - DISCO#info and DISCO#items for PEP nodes
// ============================================================================

class PEPDiscoveryHandler {
public:
    using NodePtr = std::shared_ptr<PEPNodeInstance>;

    // ========================================================================
    // Generate service-level DISCO#info
    // ========================================================================
    static std::string generate_service_disco_info(const std::string& service_name,
                                                    bool pep_enabled = true,
                                                    bool pubsub_enabled = true) {
        std::ostringstream oss;
        oss << "<query xmlns=\"" << PEPNS::DISCO_INFO << "\">";

        std::string identity_type = pep_enabled ? "pep" : "service";
        oss << "<identity category=\"pubsub\" type=\"" << identity_type << "\"";
        if (!service_name.empty()) {
            oss << " name=\"" << xml_escape(service_name) << "\"";
        }
        oss << "/>";

        // Core DISCO
        oss << "<feature var=\"" << PEPNS::DISCO_INFO << "\"/>";
        oss << "<feature var=\"" << PEPNS::DISCO_ITEMS << "\"/>";
        oss << "<feature var=\"" << PEPNS::PUBSUB << "\"/>";

        if (pubsub_enabled) {
            oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_CREATE << "\"/>";
            oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_CREATE_CONF << "\"/>";
            oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_DELETE << "\"/>";
            oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_INSTANT << "\"/>";
        }

        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_PUBLISH << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_RETRACT << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_RETRIEVE << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_SUBSCRIBE << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_CONFIG << "\"/>";

        if (pep_enabled) {
            oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_AUTOCREATE << "\"/>";
            oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_AUTOSUB << "\"/>";
            oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_PRESENCE << "\"/>";
        }

        // Access model features
        oss << "<feature var=\"" << PEPConstants::FEATURE_ACCESS_OPEN << "\"/>";
        oss << "<feature var=\"" << PEPConstants::FEATURE_ACCESS_PRESENCE << "\"/>";
        oss << "<feature var=\"" << PEPConstants::FEATURE_ACCESS_ROSTER << "\"/>";
        oss << "<feature var=\"" << PEPConstants::FEATURE_ACCESS_AUTHORIZE << "\"/>";
        oss << "<feature var=\"" << PEPConstants::FEATURE_ACCESS_WHITELIST << "\"/>";

        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_METADATA << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_PERSIST << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_ITEM_IDS << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_AFFILIATIONS << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_MANAGE_SUBS << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_MULTI_SUB << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_COLLECTIONS << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_LAST_PUB << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_FILTERED << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_PUB_AFF << "\"/>";
        oss << "<feature var=\"" << PEPConstants::DISCO_FEATURE_OUTCAST << "\"/>";

        oss << "</query>";
        return oss.str();
    }

    // ========================================================================
    // Generate service-level DISCO#items
    // ========================================================================
    static std::string generate_service_disco_items(
        const std::string& service_jid,
        const std::vector<NodePtr>& nodes) {
        std::ostringstream oss;
        oss << "<query xmlns=\"" << PEPNS::DISCO_ITEMS << "\">";

        for (const auto& node : nodes) {
            if (!node->is_deleted()) {
                oss << "<item jid=\"" << xml_escape(service_jid) << "\"";
                oss << " node=\"" << xml_escape(node->node_id()) << "\"";
                if (!node->config().title.empty()) {
                    oss << " name=\"" << xml_escape(node->config().title) << "\"";
                }
                oss << "/>";
            }
        }

        oss << "</query>";
        return oss.str();
    }

    // ========================================================================
    // Generate nested DISCO#items for PEP (by user)
    // ========================================================================
    static std::string generate_user_pep_disco_items(
        const std::string& user_jid,
        const std::vector<NodePtr>& pep_nodes) {
        std::ostringstream oss;
        oss << "<query xmlns=\"" << PEPNS::DISCO_ITEMS << "\">";

        for (const auto& node : pep_nodes) {
            if (node->is_pep() && !node->is_deleted()) {
                std::string node_id = node->node_id();
                std::string bare_prefix = bare_jid(user_jid) + "#";
                if (node_id.find(bare_prefix) == 0) {
                    node_id = node_id.substr(bare_prefix.length());
                }

                oss << "<item jid=\"" << xml_escape(bare_jid(user_jid)) << "\"";
                oss << " node=\"" << xml_escape(node_id) << "\"";
                if (!node->config().title.empty()) {
                    oss << " name=\"" << xml_escape(node->config().title) << "\"";
                }
                oss << "/>";
            }
        }

        oss << "</query>";
        return oss.str();
    }
};

// ============================================================================
// PEPNodeManager - Central node registry and lifecycle management
// ============================================================================

class PEPNodeManager {
public:
    using NodePtr = std::shared_ptr<PEPNodeInstance>;
    using Logger = std::function<void(const std::string& level, const std::string& msg)>;

    PEPNodeManager(const std::string& service_jid)
        : service_jid_(service_jid), enabled_(true) {}

    // ========================================================================
    // Node creation
    // ========================================================================
    NodePtr create_node(const std::string& node_id,
                        const std::string& creator_jid,
                        PEPNodeType node_type = PEPNodeType::LEAF,
                        const PEPNodeConfig& initial_config = PEPNodeConfig()) {
        std::unique_lock lock(mutex_);

        if (!enabled_) return nullptr;
        if (node_id.empty()) return nullptr;
        if (nodes_.find(node_id) != nodes_.end()) return nullptr;

        if (max_total_nodes_ > 0 &&
            nodes_.size() >= static_cast<size_t>(max_total_nodes_)) {
            return nullptr;
        }

        if (max_nodes_per_user_ > 0) {
            int user_count = count_user_nodes(creator_jid);
            if (user_count >= max_nodes_per_user_) return nullptr;
        }

        auto node = std::make_shared<PEPNodeInstance>(node_id, creator_jid);
        node->config() = initial_config;
        node->config().node_id = node_id;
        node->config().creator = creator_jid;
        node->set_affiliation(creator_jid, PEPAffiliation::OWNER, creator_jid);

        if (node->config().max_items == 0) {
            node->config().max_items = default_max_items_;
        }

        auto& cfg = node->config();
        if (cfg.subscribe) {
            node->add_subscription(creator_jid, PEPSubscriptionState::SUBSCRIBED);
        }

        // Handle collection parent
        if (!initial_config.parent_collection_id.empty()) {
            auto parent = get_node(initial_config.parent_collection_id);
            if (parent && parent->is_collection()) {
                parent->add_child_node(node_id);
            }
        }

        node->set_state_active();
        nodes_[node_id] = node;

        log("INFO", "Node created: " + node_id + " by " + creator_jid);
        return node;
    }

    NodePtr create_pep_node(const std::string& node_id,
                            const std::string& owner_jid) {
        auto cfg = PEPNodeConfig::default_pep_config();
        cfg.creator = owner_jid;
        cfg.is_pep_node = true;

        auto node = create_node(node_id, owner_jid, PEPNodeType::LEAF, cfg);
        if (node) {
            node->set_affiliation(owner_jid, PEPAffiliation::OWNER);
            node->add_subscription(owner_jid, PEPSubscriptionState::SUBSCRIBED);
            log("INFO", "PEP node created: " + node_id + " for " + owner_jid);
        }
        return node;
    }

    NodePtr ensure_pep_node(const std::string& node_id, const std::string& owner_jid) {
        auto existing = get_node(node_id);
        if (existing) return existing;
        return create_pep_node(node_id, owner_jid);
    }

    // ========================================================================
    // Node lookup
    // ========================================================================
    NodePtr get_node(const std::string& node_id) {
        std::shared_lock lock(mutex_);
        auto it = nodes_.find(node_id);
        if (it != nodes_.end()) return it->second;
        return nullptr;
    }

    bool node_exists(const std::string& node_id) {
        std::shared_lock lock(mutex_);
        return nodes_.find(node_id) != nodes_.end();
    }

    std::vector<NodePtr> get_all_nodes() {
        std::shared_lock lock(mutex_);
        std::vector<NodePtr> result;
        for (const auto& [id, node] : nodes_) {
            result.push_back(node);
        }
        return result;
    }

    std::vector<NodePtr> get_nodes_by_owner(const std::string& owner_jid) {
        std::shared_lock lock(mutex_);
        std::vector<NodePtr> result;
        std::string bare = bare_jid(owner_jid);
        for (const auto& [id, node] : nodes_) {
            if (node->is_owner(bare)) result.push_back(node);
        }
        return result;
    }

    std::vector<NodePtr> get_pep_nodes() {
        std::shared_lock lock(mutex_);
        std::vector<NodePtr> result;
        for (const auto& [id, node] : nodes_) {
            if (node->is_pep()) result.push_back(node);
        }
        return result;
    }

    std::vector<NodePtr> get_nodes_by_type(PEPNodeType type) {
        std::shared_lock lock(mutex_);
        std::vector<NodePtr> result;
        for (const auto& [id, node] : nodes_) {
            if (node->config().node_type == type) result.push_back(node);
        }
        return result;
    }

    std::vector<NodePtr> get_nodes_by_access_model(PEPAccessModel am) {
        std::shared_lock lock(mutex_);
        std::vector<NodePtr> result;
        for (const auto& [id, node] : nodes_) {
            if (node->config().access_model == am) result.push_back(node);
        }
        return result;
    }

    // ========================================================================
    // Node deletion
    // ========================================================================
    bool delete_node(const std::string& node_id, const std::string& requester) {
        std::unique_lock lock(mutex_);

        auto node = get_node_internal(node_id);
        if (!node) return false;
        if (!node->is_owner(requester)) return false;

        // Remove from parent
        if (!node->config().parent_collection_id.empty()) {
            auto parent = get_node_internal(node->config().parent_collection_id);
            if (parent) {
                parent->remove_child_node(node_id);
            }
        }

        // Cascade delete children if collection
        if (node->is_collection()) {
            auto children = node->get_child_nodes();
            for (const auto& child_id : children) {
                delete_node(child_id, requester);
            }
        }

        node->mark_deleted();

        if (node->is_pep() || !node->config().persist_items) {
            nodes_.erase(node_id);
        }

        log("INFO", "Node deleted: " + node_id + " by " + requester);
        return true;
    }

    // ========================================================================
    // Node purge
    // ========================================================================
    bool purge_node(const std::string& node_id, const std::string& requester) {
        auto node = get_node(node_id);
        if (!node) return false;
        if (!node->is_owner(requester)) return false;

        node->purge();
        log("INFO", "Node purged: " + node_id + " by " + requester);
        return true;
    }

    // ========================================================================
    // Node configuration
    // ========================================================================
    bool configure_node(const std::string& node_id,
                        const std::string& requester,
                        const std::map<std::string, std::vector<std::string>>& fields) {
        auto node = get_node(node_id);
        if (!node) return false;
        if (!node->is_owner(requester)) return false;

        node->config().apply_form_fields(fields);
        log("INFO", "Node configured: " + node_id + " by " + requester);
        return true;
    }

    // ========================================================================
    // Node indexing
    // ========================================================================
    std::vector<std::string> list_node_ids() {
        std::shared_lock lock(mutex_);
        std::vector<std::string> ids;
        for (const auto& [id, node] : nodes_) {
            if (!node->is_deleted()) ids.push_back(id);
        }
        return ids;
    }

    int total_node_count() {
        std::shared_lock lock(mutex_);
        return static_cast<int>(nodes_.size());
    }

    int active_node_count() {
        std::shared_lock lock(mutex_);
        int count = 0;
        for (const auto& [id, node] : nodes_) {
            if (node->is_active()) ++count;
        }
        return count;
    }

    // ========================================================================
    // Configuration
    // ========================================================================
    void set_enabled(bool enabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        enabled_ = enabled;
    }
    bool is_enabled() const { return enabled_; }

    void set_max_total_nodes(int max) { max_total_nodes_ = max; }
    void set_max_nodes_per_user(int max) { max_nodes_per_user_ = max; }
    void set_default_max_items(int max) { default_max_items_ = max; }

    void set_logger(Logger logger) { logger_ = logger; }

    const std::string& service_jid() const { return service_jid_; }

    // ========================================================================
    // Shutdown
    // ========================================================================
    void shutdown() {
        std::unique_lock lock(mutex_);
        enabled_ = false;
        for (auto& [id, node] : nodes_) {
            node->mark_deleted();
        }
        nodes_.clear();
    }

    // ========================================================================
    // Garbage collection
    // ========================================================================
    int cleanup_deleted() {
        std::unique_lock lock(mutex_);
        int count = 0;
        std::vector<std::string> to_remove;
        for (auto& [id, node] : nodes_) {
            if (node->is_deleted()) to_remove.push_back(id);
        }
        for (const auto& id : to_remove) {
            nodes_.erase(id);
            ++count;
        }
        return count;
    }

    void expire_stale_items() {
        std::shared_lock lock(mutex_);
        auto now = std::chrono::system_clock::now();
        for (auto& [id, node] : nodes_) {
            if (node->config().item_expire_seconds <= 0) continue;
            auto items = node->get_items();
            for (const auto& item : items) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - item->published_at).count();
                if (age > node->config().item_expire_seconds) {
                    node->retract_item(item->item_id);
                }
            }
        }
    }

private:
    NodePtr get_node_internal(const std::string& node_id) {
        auto it = nodes_.find(node_id);
        if (it != nodes_.end()) return it->second;
        return nullptr;
    }

    int count_user_nodes(const std::string& jid) {
        std::string bare = bare_jid(jid);
        int count = 0;
        for (const auto& [id, node] : nodes_) {
            if (node->is_owner(bare)) ++count;
        }
        return count;
    }

    void log(const std::string& level, const std::string& msg) {
        if (logger_) logger_(level, msg);
    }

    std::string service_jid_;
    bool enabled_;
    int max_total_nodes_ = 0;
    int max_nodes_per_user_ = 0;
    int default_max_items_ = PEPConstants::DEFAULT_MAX_ITEMS_GENERAL;

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, NodePtr> nodes_;
    Logger logger_;
};

// ============================================================================
// PEPDataFormParser - Parses XEP-0004 data forms
// ============================================================================

class PEPDataFormParser {
public:
    static std::map<std::string, std::vector<std::string>> parse_form(
        const std::string& xml) {
        std::map<std::string, std::vector<std::string>> fields;

        size_t x_start = xml.find("<x xmlns=\"jabber:x:data\"");
        if (x_start == std::string::npos) {
            x_start = xml.find("<x xmlns='jabber:x:data'");
            if (x_start == std::string::npos) return fields;
        }

        size_t x_end = xml.find("</x>", x_start);
        if (x_end == std::string::npos) return fields;

        std::string x_content = xml.substr(x_start, x_end - x_start + 4);

        size_t field_pos = 0;
        while ((field_pos = x_content.find("<field", field_pos)) != std::string::npos) {
            size_t field_end = x_content.find("</field>", field_pos);
            if (field_end == std::string::npos) break;

            std::string field_xml = x_content.substr(field_pos, field_end - field_pos + 9);
            std::string var = extract_attr(field_xml, "var");

            if (!var.empty() && var != "FORM_TYPE") {
                std::vector<std::string> values;
                size_t val_pos = 0;
                while ((val_pos = field_xml.find("<value>", val_pos)) != std::string::npos) {
                    size_t val_end = field_xml.find("</value>", val_pos);
                    if (val_end == std::string::npos) break;
                    std::string val = field_xml.substr(val_pos + 7, val_end - val_pos - 7);
                    values.push_back(xml_unescape(trim(val)));
                    val_pos = val_end + 8;
                }
                fields[var] = values;
            }

            field_pos = field_end + 9;
        }

        return fields;
    }

    static std::string extract_node(const std::string& xml) {
        return extract_attr(xml, "node");
    }

    static std::string extract_item_id(const std::string& xml) {
        // Try item id attribute on <item>
        size_t item_pos = xml.find("<item");
        if (item_pos != std::string::npos) {
            size_t id_pos = xml.find("id=\"", item_pos);
            if (id_pos == std::string::npos) {
                id_pos = xml.find("id='", item_pos);
            }
            if (id_pos != std::string::npos && id_pos < item_pos + 100) {
                size_t start = id_pos + 4;
                char delim = xml[id_pos + 3];
                size_t end = xml.find(delim, start);
                if (end != std::string::npos && end < start + 200) {
                    return xml_unescape(xml.substr(start, end - start));
                }
            }
        }
        return "";
    }
};

// ============================================================================
// PEPConfigSerializer - Serialize/deserialize PEP configuration
// ============================================================================

class PEPConfigSerializer {
public:
    // ========================================================================
    // Serialize a node config to key-value pairs for storage
    // ========================================================================
    static std::map<std::string, std::string> serialize(const PEPNodeConfig& config) {
        std::map<std::string, std::string> kv;

        kv["node_type"] = pep_node_type_str(config.node_type);
        kv["access_model"] = pep_access_model_str(config.access_model);
        kv["title"] = config.title;
        kv["description"] = config.description;
        kv["language"] = config.language;
        kv["contact"] = config.contact;
        kv["persist_items"] = config.persist_items ? "1" : "0";
        kv["max_items"] = std::to_string(config.max_items);
        kv["max_payload_size"] = std::to_string(config.max_payload_size);
        kv["deliver_payloads"] = config.deliver_payloads ? "1" : "0";
        kv["deliver_notifications"] = config.deliver_notifications ? "1" : "0";
        kv["send_last_published"] = pep_send_last_str(config.send_last_published);
        kv["subscribe"] = config.subscribe ? "1" : "0";
        kv["subscription_required"] = config.subscription_required ? "1" : "0";
        kv["notify_config"] = config.notify_config ? "1" : "0";
        kv["notify_delete"] = config.notify_delete ? "1" : "0";
        kv["notify_retract"] = config.notify_retract ? "1" : "0";
        kv["notify_sub"] = config.notify_sub ? "1" : "0";
        kv["notify_unsub"] = config.notify_unsub ? "1" : "0";
        kv["item_expire_seconds"] = std::to_string(config.item_expire_seconds);
        kv["parent_collection_id"] = config.parent_collection_id;
        kv["creator"] = config.creator;
        kv["is_pep_node"] = config.is_pep_node ? "1" : "0";
        kv["presence_based_delivery"] = config.presence_based_delivery ? "1" : "0";
        kv["max_children"] = std::to_string(config.max_children);
        kv["children_association_policy"] = config.children_association_policy;
        kv["body_xslt"] = config.body_xslt;

        return kv;
    }

    // ========================================================================
    // Deserialize from key-value pairs
    // ========================================================================
    static PEPNodeConfig deserialize(const std::map<std::string, std::string>& kv) {
        PEPNodeConfig config;

        auto get = [&](const std::string& key, const std::string& def = "") -> std::string {
            auto it = kv.find(key);
            return (it != kv.end()) ? it->second : def;
        };

        auto get_bool = [&](const std::string& key, bool def = false) -> bool {
            auto it = kv.find(key);
            if (it == kv.end()) return def;
            return it->second == "1" || it->second == "true";
        };

        auto get_int = [&](const std::string& key, int def = 0) -> int {
            auto it = kv.find(key);
            if (it == kv.end()) return def;
            try { return std::stoi(it->second); }
            catch (...) { return def; }
        };

        config.node_type = pep_node_type_from_str(get("node_type", "leaf"));
        config.access_model = pep_access_model_from_str(get("access_model", "open"));
        config.title = get("title");
        config.description = get("description");
        config.language = get("language");
        config.contact = get("contact");
        config.persist_items = get_bool("persist_items");
        config.max_items = get_int("max_items");
        config.max_payload_size = get_int("max_payload_size");
        config.deliver_payloads = get_bool("deliver_payloads", true);
        config.deliver_notifications = get_bool("deliver_notifications", true);
        config.send_last_published = pep_send_last_from_str(get("send_last_published", "on_sub_and_presence"));
        config.subscribe = get_bool("subscribe", true);
        config.subscription_required = get_bool("subscription_required");
        config.notify_config = get_bool("notify_config");
        config.notify_delete = get_bool("notify_delete");
        config.notify_retract = get_bool("notify_retract");
        config.notify_sub = get_bool("notify_sub");
        config.notify_unsub = get_bool("notify_unsub");
        config.item_expire_seconds = get_int("item_expire_seconds");
        config.parent_collection_id = get("parent_collection_id");
        config.creator = get("creator");
        config.is_pep_node = get_bool("is_pep_node");
        config.presence_based_delivery = get_bool("presence_based_delivery");
        config.max_children = get_int("max_children");
        config.children_association_policy = get("children_association_policy");
        config.body_xslt = get("body_xslt");

        return config;
    }
};

// ============================================================================
// PEPPresenceTracker - Tracks presence-based subscriptions
// ============================================================================

class PEPPresenceTracker {
public:
    void set_online(const std::string& jid, bool online) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (online) {
            online_set_.insert(bare_jid(jid));
        } else {
            online_set_.erase(bare_jid(jid));
        }
    }

    bool is_online(const std::string& jid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return online_set_.find(bare_jid(jid)) != online_set_.end();
    }

    bool has_presence_subscription(const std::string& from_jid,
                                    const std::string& to_jid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto key = std::make_pair(bare_jid(from_jid), bare_jid(to_jid));
        return presence_subs_.find(key) != presence_subs_.end();
    }

    void add_presence_subscription(const std::string& from_jid,
                                    const std::string& to_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto key = std::make_pair(bare_jid(from_jid), bare_jid(to_jid));
        presence_subs_.insert(key);
    }

    void remove_presence_subscription(const std::string& from_jid,
                                       const std::string& to_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto key = std::make_pair(bare_jid(from_jid), bare_jid(to_jid));
        presence_subs_.erase(key);
    }

private:
    mutable std::mutex mutex_;
    std::set<std::string> online_set_;
    std::set<std::pair<std::string, std::string>> presence_subs_;
};

// ============================================================================
// PEPRoasterBridge - Roster integration
// ============================================================================

class PEPRoasterBridge {
public:
    struct RoasterEntry {
        std::string jid;
        std::set<std::string> groups;
        std::string subscription_type;
    };

    void set_roster(const std::string& user_jid,
                    const std::vector<RoasterEntry>& entries) {
        std::lock_guard<std::mutex> lock(mutex_);
        rosters_[bare_jid(user_jid)] = entries;
    }

    bool has_roster_entry(const std::string& user_jid, const std::string& contact_jid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string bare = bare_jid(user_jid);
        auto it = rosters_.find(bare);
        if (it == rosters_.end()) return false;

        std::string contact_bare = bare_jid(contact_jid);
        for (const auto& entry : it->second) {
            if (bare_jid(entry.jid) == contact_bare) return true;
        }
        return false;
    }

    bool in_roster_group(const std::string& user_jid,
                          const std::string& contact_jid,
                          const std::set<std::string>& allowed_groups) const {
        if (allowed_groups.empty()) return true;

        std::lock_guard<std::mutex> lock(mutex_);
        std::string bare = bare_jid(user_jid);
        auto it = rosters_.find(bare);
        if (it == rosters_.end()) return false;

        std::string contact_bare = bare_jid(contact_jid);
        for (const auto& entry : it->second) {
            if (bare_jid(entry.jid) == contact_bare) {
                for (const auto& g : entry.groups) {
                    if (allowed_groups.find(g) != allowed_groups.end()) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    void clear_roster(const std::string& user_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        rosters_.erase(bare_jid(user_jid));
    }

private:
    mutable std::mutex mutex_;
    std::map<std::string, std::vector<RoasterEntry>> rosters_;
};

// ============================================================================
// PEPAffiliationResolver - Resolves effective affiliation
// ============================================================================

class PEPAffiliationResolver {
public:
    using NodePtr = std::shared_ptr<PEPNodeInstance>;

    struct ResolvedAccess {
        PEPAffiliation affiliation = PEPAffiliation::NONE;
        bool is_owner = false;
        bool can_publish = false;
        bool can_subscribe = false;
        bool can_view = false;
        bool can_configure = false;
        bool is_outcast = false;
    };

    static ResolvedAccess resolve(NodePtr node,
                                   const std::string& requester_jid,
                                   PEPPresenceTracker* presence_tracker = nullptr,
                                   PEPRoasterBridge* roster_bridge = nullptr) {
        ResolvedAccess access;

        if (!node) return access;

        std::string bare = bare_jid(requester_jid);
        access.affiliation = node->get_affiliation(bare);
        access.is_owner = (access.affiliation == PEPAffiliation::OWNER);
        access.is_outcast = (access.affiliation == PEPAffiliation::OUTCAST);

        bool has_presence_sub = false;
        bool in_roster_group = false;

        if (presence_tracker) {
            has_presence_sub = presence_tracker->has_presence_subscription(
                node->config().creator, bare);
        }

        if (roster_bridge && !node->config().roster_groups_allowed.empty()) {
            in_roster_group = roster_bridge->in_roster_group(
                node->config().creator, bare,
                node->config().roster_groups_allowed);
        }

        auto pub_check = PEPAccessController::can_publish(
            node->config(), access.affiliation);
        access.can_publish = pub_check.allowed;

        auto sub_check = PEPAccessController::can_subscribe(
            node->config(), bare, access.affiliation,
            has_presence_sub, in_roster_group);
        access.can_subscribe = sub_check.allowed;

        auto view_check = PEPAccessController::can_view_items(
            node->config(), access.affiliation,
            has_presence_sub, in_roster_group);
        access.can_view = view_check.allowed;

        auto conf_check = PEPAccessController::can_configure(
            node->config(), access.affiliation);
        access.can_configure = conf_check.allowed;

        return access;
    }
};

// ============================================================================
// PEPConfigCache - LRU-style cache for node configurations
// ============================================================================

class PEPConfigCache {
public:
    explicit PEPConfigCache(size_t max_entries = 10000)
        : max_entries_(max_entries) {}

    void put(const std::string& node_id, const PEPNodeConfig& config) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_map_.find(node_id);
        if (it != cache_map_.end()) {
            access_list_.erase(it->second);
        }

        access_list_.push_front(node_id);
        cache_map_[node_id] = access_list_.begin();
        configs_[node_id] = config;

        while (cache_map_.size() > max_entries_) {
            std::string evict = access_list_.back();
            access_list_.pop_back();
            cache_map_.erase(evict);
            configs_.erase(evict);
        }
    }

    std::optional<PEPNodeConfig> get(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_map_.find(node_id);
        if (it == cache_map_.end()) return std::nullopt;

        // Move to front (LRU)
        access_list_.erase(it->second);
        access_list_.push_front(node_id);
        it->second = access_list_.begin();

        return configs_[node_id];
    }

    void remove(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_map_.find(node_id);
        if (it != cache_map_.end()) {
            access_list_.erase(it->second);
            cache_map_.erase(it);
            configs_.erase(node_id);
        }
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        access_list_.clear();
        cache_map_.clear();
        configs_.clear();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cache_map_.size();
    }

private:
    size_t max_entries_;
    mutable std::mutex mutex_;
    std::deque<std::string> access_list_;
    std::map<std::string, std::deque<std::string>::iterator> cache_map_;
    std::map<std::string, PEPNodeConfig> configs_;
};

// ============================================================================
// PEPStateMachine - Manages node lifecycle state
// ============================================================================

class PEPStateMachine {
public:
    struct Transition {
        std::string from_state;
        std::string to_state;
        std::chrono::system_clock::time_point timestamp;
        std::string triggered_by;
        std::string reason;
    };

    void record_transition(const std::string& node_id, const Transition& t) {
        std::lock_guard<std::mutex> lock(mutex_);
        history_[node_id].push_back(t);
    }

    std::vector<Transition> get_history(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = history_.find(node_id);
        if (it != history_.end()) return it->second;
        return {};
    }

    void clear_history(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        history_.erase(node_id);
    }

private:
    mutable std::mutex mutex_;
    std::map<std::string, std::vector<Transition>> history_;
};

// ============================================================================
// PEPStatistics - Statistics collection
// ============================================================================

class PEPStatisticsCollector {
public:
    struct Stats {
        int64_t total_nodes = 0;
        int64_t pep_nodes = 0;
        int64_t leaf_nodes = 0;
        int64_t collection_nodes = 0;
        int64_t total_subscriptions = 0;
        int64_t active_subscriptions = 0;
        int64_t total_items = 0;
        int64_t nodes_created = 0;
        int64_t nodes_deleted = 0;
        int64_t publish_count = 0;
        int64_t notification_count = 0;
        std::map<std::string, int64_t> nodes_by_access_model;
        std::chrono::system_clock::time_point last_reset;

        Stats() : last_reset(std::chrono::system_clock::now()) {}
    };

    void record_create() {
        stats_.nodes_created.fetch_add(1);
    }

    void record_delete() {
        stats_.nodes_deleted.fetch_add(1);
    }

    void record_publish() {
        stats_.publish_count.fetch_add(1);
    }

    void record_notification() {
        stats_.notification_count.fetch_add(1);
    }

    Stats snapshot(const PEPNodeManager& manager) const {
        Stats s = stats_.load();

        s.total_nodes = manager.total_node_count();
        s.pep_nodes = static_cast<int64_t>(manager.get_pep_nodes().size());
        s.leaf_nodes = static_cast<int64_t>(manager.get_nodes_by_type(PEPNodeType::LEAF).size());
        s.collection_nodes = static_cast<int64_t>(manager.get_nodes_by_type(PEPNodeType::COLLECTION).size());

        return s;
    }

    void reset() {
        stats_ = Stats{};
        stats_.last_reset = std::chrono::system_clock::now();
    }

private:
    struct AtomicStats {
        std::atomic<int64_t> nodes_created{0};
        std::atomic<int64_t> nodes_deleted{0};
        std::atomic<int64_t> publish_count{0};
        std::atomic<int64_t> notification_count{0};

        Stats load() const {
            Stats s;
            s.nodes_created = nodes_created.load();
            s.nodes_deleted = nodes_deleted.load();
            s.publish_count = publish_count.load();
            s.notification_count = notification_count.load();
            return s;
        }
    };

    AtomicStats stats_;
};

// ============================================================================
// PEPNotificationFilter - Filters notifications based on subscription options
// ============================================================================

class PEPNotificationFilter {
public:
    struct FilterResult {
        bool should_deliver = true;
        bool include_payload = true;
        bool use_digest = false;
        int digest_frequency = 0;
    };

    static FilterResult check(const PEPSubscriptionRecord& sub,
                               const PEPNodeConfig& node_config) {
        FilterResult result;

        // Check if delivery is enabled for this subscription
        if (!sub.options().deliver) {
            result.should_deliver = false;
            return result;
        }

        // Check payload delivery
        result.include_payload = node_config.deliver_payloads && sub.options().include_body;

        // Check digest mode
        if (sub.options().digest) {
            result.use_digest = true;
            result.digest_frequency = sub.options().digest_frequency;
        }

        return result;
    }

    static bool should_send_last_published(const PEPNodeConfig& config,
                                            PEPSendLastMode mode) {
        return config.send_last_published >= mode;
    }

    static bool should_notify_on_subscribe(const PEPNodeConfig& config) {
        return config.notify_sub;
    }

    static bool should_notify_on_unsubscribe(const PEPNodeConfig& config) {
        return config.notify_unsub;
    }
};

// ============================================================================
// PEPNodeMigration - Handles node migration between access models
// ============================================================================

class PEPNodeMigration {
public:
    using NodePtr = std::shared_ptr<PEPNodeInstance>;

    struct MigrationResult {
        bool success = false;
        int subscriptions_affected = 0;
        int subscriptions_removed = 0;
        std::vector<std::string> warnings;
    };

    // ========================================================================
    // Migrate node to a new access model
    // ========================================================================
    static MigrationResult migrate_access_model(NodePtr node,
                                                  PEPAccessModel new_model,
                                                  PEPPresenceTracker* presence_tracker = nullptr,
                                                  PEPRoasterBridge* roster_bridge = nullptr) {
        MigrationResult result;

        if (!node) {
            result.warnings.push_back("Node is null");
            return result;
        }

        PEPAccessModel old_model = node->config().access_model;
        if (old_model == new_model) {
            result.success = true;
            result.warnings.push_back("Access model unchanged");
            return result;
        }

        // Validate migration
        switch (new_model) {
            case PEPAccessModel::OPEN:
                // Any model can migrate to open
                break;
            case PEPAccessModel::PRESENCE:
                // Require presence tracking
                if (!presence_tracker) {
                    result.warnings.push_back("Presence tracker required for presence model");
                    return result;
                }
                break;
            case PEPAccessModel::ROSTER:
                if (!roster_bridge) {
                    result.warnings.push_back("Roster bridge required for roster model");
                    return result;
                }
                break;
            case PEPAccessModel::AUTHORIZE:
                // Any model can migrate to authorize
                break;
            case PEPAccessModel::WHITELIST:
                // Whistlist is managed separately
                break;
        }

        // Re-evaluate all subscriptions
        auto subs = node->get_all_subscriptions();
        for (const auto& sub : subs) {
            result.subscriptions_affected++;

            bool has_presence_sub = false;
            bool in_roster_group = false;

            if (presence_tracker) {
                has_presence_sub = presence_tracker->has_presence_subscription(
                    node->config().creator, sub->jid());
            }

            if (roster_bridge && !node->config().roster_groups_allowed.empty()) {
                in_roster_group = roster_bridge->in_roster_group(
                    node->config().creator, sub->jid(),
                    node->config().roster_groups_allowed);
            }

            PEPAffiliation aff = node->get_affiliation(sub->jid());
            auto check = PEPAccessController::can_subscribe(
                node->config(), sub->jid(), aff,
                has_presence_sub, in_roster_group);

            if (!check.allowed && aff != PEPAffiliation::OWNER) {
                node->remove_subscription(sub->jid());
                result.subscriptions_removed++;
            }
        }

        // Apply new access model
        node->config().access_model = new_model;
        result.success = true;

        return result;
    }

    // ========================================================================
    // Migrate a node from PubSub to PEP
    // ========================================================================
    static MigrationResult migrate_to_pep(NodePtr node) {
        MigrationResult result;

        if (!node) return result;

        node->config().is_pep_node = true;
        node->config().access_model = PEPAccessModel::PRESENCE;
        node->config().max_items = PEPConstants::DEFAULT_MAX_ITEMS_PEP;
        node->config().presence_based_delivery = true;

        result.success = true;
        return result;
    }

    // ========================================================================
    // Migrate a node from PEP to regular PubSub
    // ========================================================================
    static MigrationResult migrate_from_pep(NodePtr node) {
        MigrationResult result;

        if (!node) return result;

        node->config().is_pep_node = false;
        node->config().access_model = PEPAccessModel::OPEN;
        node->config().max_items = PEPConstants::DEFAULT_MAX_ITEMS_GENERAL;
        node->config().presence_based_delivery = false;

        result.success = true;
        return result;
    }
};

// ============================================================================
// PEPBulkOperations - Batch operations on PEP nodes
// ============================================================================

class PEPBulkOperations {
public:
    using NodePtr = std::shared_ptr<PEPNodeInstance>;

    // ========================================================================
    // Bulk subscribe: subscribe a JID to multiple nodes at once
    // ========================================================================
    struct BulkSubscribeResult {
        int total = 0;
        int succeeded = 0;
        int failed = 0;
        std::vector<std::string> failed_nodes;
        std::map<std::string, std::string> subscriptions;  // node_id -> subid
    };

    static BulkSubscribeResult bulk_subscribe(
        std::shared_ptr<PEPNodeManager> manager,
        std::shared_ptr<PEPSubscriptionManager> sub_manager,
        const std::string& subscriber_jid,
        const std::vector<std::string>& node_ids) {

        BulkSubscribeResult result;
        result.total = static_cast<int>(node_ids.size());

        for (const auto& node_id : node_ids) {
            auto node = manager->get_node(node_id);
            if (!node) {
                result.failed++;
                result.failed_nodes.push_back(node_id);
                continue;
            }

            auto sub_result = sub_manager->subscribe(node, subscriber_jid);
            if (sub_result.success) {
                result.succeeded++;
                result.subscriptions[node_id] = sub_result.subscription_id;
            } else {
                result.failed++;
                result.failed_nodes.push_back(node_id);
            }
        }

        return result;
    }

    // ========================================================================
    // Bulk unsubscribe: unsubscribe a JID from multiple nodes
    // ========================================================================
    struct BulkUnsubscribeResult {
        int total = 0;
        int succeeded = 0;
        int failed = 0;
    };

    static BulkUnsubscribeResult bulk_unsubscribe(
        std::shared_ptr<PEPNodeManager> manager,
        std::shared_ptr<PEPSubscriptionManager> sub_manager,
        const std::string& subscriber_jid,
        const std::vector<std::string>& node_ids) {

        BulkUnsubscribeResult result;
        result.total = static_cast<int>(node_ids.size());

        for (const auto& node_id : node_ids) {
            auto node = manager->get_node(node_id);
            if (!node) {
                result.failed++;
                continue;
            }

            if (sub_manager->unsubscribe(node, subscriber_jid)) {
                result.succeeded++;
            } else {
                result.failed++;
            }
        }

        return result;
    }

    // ========================================================================
    // Bulk node deletion
    // ========================================================================
    struct BulkDeleteResult {
        int total = 0;
        int succeeded = 0;
        int failed = 0;
    };

    static BulkDeleteResult bulk_delete(
        std::shared_ptr<PEPNodeManager> manager,
        const std::string& requester,
        const std::vector<std::string>& node_ids) {

        BulkDeleteResult result;
        result.total = static_cast<int>(node_ids.size());

        for (const auto& node_id : node_ids) {
            if (manager->delete_node(node_id, requester)) {
                result.succeeded++;
            } else {
                result.failed++;
            }
        }

        return result;
    }

    // ========================================================================
    // Bulk configuration update
    // ========================================================================
    struct BulkConfigResult {
        int total = 0;
        int succeeded = 0;
        int failed = 0;
    };

    static BulkConfigResult bulk_configure(
        std::shared_ptr<PEPNodeManager> manager,
        const std::string& requester,
        const std::vector<std::string>& node_ids,
        const std::map<std::string, std::vector<std::string>>& fields) {

        BulkConfigResult result;
        result.total = static_cast<int>(node_ids.size());

        for (const auto& node_id : node_ids) {
            if (manager->configure_node(node_id, requester, fields)) {
                result.succeeded++;
            } else {
                result.failed++;
            }
        }

        return result;
    }
};

// ============================================================================
// PEPIQResponseBuilder - Builds IQ response stanzas
// ============================================================================

class PEPIQResponseBuilder {
public:
    static std::string make_result(const std::string& id, const std::string& to,
                                    const std::string& body = "") {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        if (!to.empty()) oss << " to=\"" << xml_escape(to) << "\"";
        if (!body.empty()) oss << ">" << body << "</iq>";
        else oss << "/>";
        return oss.str();
    }

    static std::string make_error(const std::string& id, const std::string& to,
                                   const std::string& code, const std::string& type,
                                   const std::string& condition,
                                   const std::string& pubsub_error = "") {
        std::ostringstream oss;
        oss << "<iq type=\"error\" id=\"" << xml_escape(id) << "\"";
        if (!to.empty()) oss << " to=\"" << xml_escape(to) << "\"";
        oss << ">";
        oss << "<error code=\"" << code << "\" type=\"" << type << "\">";
        oss << "<" << condition << " xmlns=\"" << PEPNS::STANZAS << "\"/>";
        if (!pubsub_error.empty()) {
            oss << "<" << pubsub_error << " xmlns=\"" << PEPNS::PUBSUB_ERRORS << "\"/>";
        }
        oss << "</error></iq>";
        return oss.str();
    }

    static std::string make_subscription_result(const std::string& id,
                                                  const std::string& to,
                                                  const std::string& node,
                                                  const std::string& jid,
                                                  PEPSubscriptionState state,
                                                  const std::string& subid = "") {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        if (!to.empty()) oss << " to=\"" << xml_escape(to) << "\"";
        oss << ">";
        oss << "<pubsub xmlns=\"" << PEPNS::PUBSUB << "\">";
        oss << "<subscription node=\"" << xml_escape(node) << "\"";
        oss << " jid=\"" << xml_escape(jid) << "\"";
        oss << " subscription=\"" << pep_subscription_state_str(state) << "\"";
        if (!subid.empty()) oss << " subid=\"" << xml_escape(subid) << "\"";
        oss << "/>";
        oss << "</pubsub></iq>";
        return oss.str();
    }

    static std::string make_publish_result(const std::string& id,
                                            const std::string& to,
                                            const std::string& node,
                                            const std::string& item_id) {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        if (!to.empty()) oss << " to=\"" << xml_escape(to) << "\"";
        oss << ">";
        oss << "<pubsub xmlns=\"" << PEPNS::PUBSUB << "\">";
        oss << "<publish node=\"" << xml_escape(node) << "\">";
        oss << "<item id=\"" << xml_escape(item_id) << "\"/>";
        oss << "</publish>";
        oss << "</pubsub></iq>";
        return oss.str();
    }

    static std::string make_items_result(const std::string& id,
                                          const std::string& to,
                                          const std::string& node,
                                          const std::string& items_xml) {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        if (!to.empty()) oss << " to=\"" << xml_escape(to) << "\"";
        oss << ">";
        oss << "<pubsub xmlns=\"" << PEPNS::PUBSUB << "\">";
        oss << "<items node=\"" << xml_escape(node) << "\">";
        oss << items_xml;
        oss << "</items></pubsub></iq>";
        return oss.str();
    }

    static std::string make_affiliations_result(const std::string& id,
                                                  const std::string& to,
                                                  const std::string& node,
                                                  const std::string& affiliations_xml) {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        if (!to.empty()) oss << " to=\"" << xml_escape(to) << "\"";
        oss << ">";
        oss << "<pubsub xmlns=\"" << PEPNS::PUBSUB << "\">";
        oss << "<affiliations node=\"" << xml_escape(node) << "\">";
        oss << affiliations_xml;
        oss << "</affiliations></pubsub></iq>";
        return oss.str();
    }

    static std::string make_default_config_result(const std::string& id,
                                                    const std::string& to,
                                                    const PEPNodeConfig& config) {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        if (!to.empty()) oss << " to=\"" << xml_escape(to) << "\"";
        oss << ">";
        oss << "<pubsub xmlns=\"" << PEPNS::PUBSUB_OWNER << "\">";
        oss << "<default>" << config.to_config_form_xml() << "</default>";
        oss << "</pubsub></iq>";
        return oss.str();
    }

    static std::string make_create_result(const std::string& id,
                                           const std::string& to,
                                           const std::string& node_id) {
        std::ostringstream oss;
        oss << "<iq type=\"result\" id=\"" << xml_escape(id) << "\"";
        if (!to.empty()) oss << " to=\"" << xml_escape(to) << "\"";
        oss << ">";
        oss << "<pubsub xmlns=\"" << PEPNS::PUBSUB << "\">";
        oss << "<create node=\"" << xml_escape(node_id) << "\"/>";
        oss << "</pubsub></iq>";
        return oss.str();
    }
};

// ============================================================================
// PEPConfigIntegration - Integrates all PEP components
// ============================================================================

class PEPConfigIntegration {
public:
    using NodePtr = std::shared_ptr<PEPNodeInstance>;
    using SendCallback = std::function<void(const std::string& stanza_xml)>;
    using Logger = std::function<void(const std::string& level, const std::string& msg)>;

    PEPConfigIntegration(const std::string& service_jid,
                         SendCallback send_cb)
        : service_jid_(service_jid)
        , node_manager_(std::make_shared<PEPNodeManager>(service_jid))
        , sub_manager_(std::make_shared<PEPSubscriptionManager>())
        , notification_engine_(std::make_shared<PEPNotificationEngine>(send_cb))
        , whitelist_manager_(std::make_shared<PEPWhitelistManager>())
        , presence_tracker_(std::make_shared<PEPPresenceTracker>())
        , roster_bridge_(std::make_shared<PEPRoasterBridge>())
        , config_cache_(std::make_shared<PEPConfigCache>())
        , state_machine_(std::make_shared<PEPStateMachine>())
        , stats_collector_(std::make_shared<PEPStatisticsCollector>())
        , enabled_(true) {
        log("INFO", "PEPConfigIntegration initialized for: " + service_jid);
    }

    // ========================================================================
    // Accessors
    // ========================================================================
    std::shared_ptr<PEPNodeManager> nodes() { return node_manager_; }
    std::shared_ptr<PEPSubscriptionManager> subscriptions() { return sub_manager_; }
    std::shared_ptr<PEPNotificationEngine> notifications() { return notification_engine_; }
    std::shared_ptr<PEPWhitelistManager> whitelist() { return whitelist_manager_; }
    std::shared_ptr<PEPPresenceTracker> presence() { return presence_tracker_; }
    std::shared_ptr<PEPRoasterBridge> roster() { return roster_bridge_; }
    std::shared_ptr<PEPConfigCache> cache() { return config_cache_; }
    std::shared_ptr<PEPStateMachine> state_history() { return state_machine_; }
    std::shared_ptr<PEPStatisticsCollector> stats() { return stats_collector_; }

    const std::string& service_jid() const { return service_jid_; }

    // ========================================================================
    // Lifecycle
    // ========================================================================
    void shutdown() {
        node_manager_->shutdown();
        config_cache_->clear();
        enabled_ = false;
        log("INFO", "PEPConfigIntegration shut down");
    }

    bool is_enabled() const { return enabled_; }
    void set_enabled(bool e) { enabled_ = e; }

    // ========================================================================
    // Logger
    // ========================================================================
    void set_logger(Logger logger) {
        logger_ = logger;
        node_manager_->set_logger(logger);
    }

    // ========================================================================
    // PEP auto-creation: ensure standard PEP nodes exist
    // ========================================================================
    void ensure_standard_pep_nodes(const std::string& user_jid) {
        std::string bare = bare_jid(user_jid);

        static const std::vector<std::string> standard_nodes = {
            PEPConstants::AVATAR_DATA,
            PEPConstants::AVATAR_METADATA,
            PEPConstants::TUNE,
            PEPConstants::ACTIVITY,
            PEPConstants::MOOD,
            PEPConstants::GEOLOC,
            PEPConstants::NICK,
            PEPConstants::MICROBLOG,
            PEPConstants::OMB_XMPP,
            PEPConstants::BOOKMARKS,
            PEPConstants::VCARD4_PEP,
            PEPConstants::USER_LOCATION,
        };

        for (const auto& node_name : standard_nodes) {
            std::string full_id = bare + "#" + node_name;
            node_manager_->ensure_pep_node(full_id, bare);
        }
    }

    // ========================================================================
    // Handle PEP presence: auto-subscribe contacts to PEP nodes
    // ========================================================================
    void handle_pep_presence(const std::string& user_jid,
                              const std::string& presence_type) {
        if (!enabled_) return;

        std::string bare = bare_jid(user_jid);
        presence_tracker_->set_online(bare,
            presence_type.empty() || presence_type == "available");

        if (presence_type.empty() || presence_type == "available") {
            ensure_standard_pep_nodes(bare);
            auto pep_nodes = node_manager_->get_nodes_by_owner(bare);
            for (auto& node : pep_nodes) {
                if (node->is_pep() && node->config().presence_based_delivery) {
                    // Notify contacts about available PEP data
                    // Full implementation would iterate roster contacts
                }
            }
        }
    }

private:
    void log(const std::string& level, const std::string& msg) {
        if (logger_) logger_(level, msg);
    }

    std::string service_jid_;
    bool enabled_;
    std::shared_ptr<PEPNodeManager> node_manager_;
    std::shared_ptr<PEPSubscriptionManager> sub_manager_;
    std::shared_ptr<PEPNotificationEngine> notification_engine_;
    std::shared_ptr<PEPWhitelistManager> whitelist_manager_;
    std::shared_ptr<PEPPresenceTracker> presence_tracker_;
    std::shared_ptr<PEPRoasterBridge> roster_bridge_;
    std::shared_ptr<PEPConfigCache> config_cache_;
    std::shared_ptr<PEPStateMachine> state_machine_;
    std::shared_ptr<PEPStatisticsCollector> stats_collector_;
    Logger logger_;
};

// ============================================================================
// Utility functions
// ============================================================================

namespace PEPUtils {

    // Generate a unique node ID for instant nodes
    std::string generate_instant_node_id() {
        static std::atomic<uint64_t> counter{0};
        std::ostringstream oss;
        oss << "instant_" << now_ms() << "_" << (++counter);
        return oss.str();
    }

    // Generate a unique message ID
    std::string generate_message_id() {
        static std::atomic<uint64_t> counter{0};
        std::ostringstream oss;
        oss << "pepmsg_" << now_ms() << "_" << (++counter);
        return oss.str();
    }

    // Parse JID parts
    struct ParsedJID {
        std::string local;
        std::string domain;
        std::string resource;
    };

    ParsedJID parse_jid(const std::string& jid) {
        ParsedJID result;
        size_t at = jid.find('@');
        size_t slash = jid.find('/');

        if (at != std::string::npos) {
            result.local = jid.substr(0, at);
            size_t domain_end = slash != std::string::npos ? slash : jid.length();
            result.domain = jid.substr(at + 1, domain_end - at - 1);
        } else if (slash != std::string::npos) {
            result.domain = jid.substr(0, slash);
        } else {
            result.domain = jid;
        }

        if (slash != std::string::npos) {
            result.resource = jid.substr(slash + 1);
        }

        return result;
    }

    // Validate a JID
    bool validate_jid(const std::string& jid) {
        if (jid.empty()) return false;
        size_t at = jid.find('@');
        if (at == std::string::npos) return false;
        if (at == 0 || at == jid.length() - 1) return false;
        size_t domain_start = at + 1;
        if (domain_start >= jid.length()) return false;
        size_t slash = jid.find('/', domain_start);
        std::string domain = slash != std::string::npos
            ? jid.substr(domain_start, slash - domain_start)
            : jid.substr(domain_start);
        if (domain.empty()) return false;
        return domain.find('.') != std::string::npos || domain == "localhost";
    }

    // Validate a node ID
    bool validate_node_id(const std::string& node_id) {
        if (node_id.empty()) return false;
        if (node_id.length() > 1024) return false;

        for (char c : node_id) {
            if (c < 0x20 || c == 0x7F) return false;
            if (c == '&' || c == '<' || c == '>' || c == '"' || c == '\'') return false;
        }

        return true;
    }

    // Compute a hash for a node ID (for sharding)
    size_t hash_node_id(const std::string& node_id) {
        std::hash<std::string> hasher;
        return hasher(node_id);
    }

    // Get the standard PEP node namespace from a full node ID
    std::string extract_pep_namespace(const std::string& full_node_id,
                                       const std::string& user_jid) {
        std::string prefix = bare_jid(user_jid) + "#";
        if (full_node_id.find(prefix) == 0) {
            return full_node_id.substr(prefix.length());
        }
        return full_node_id;
    }

    // Build a full PEP node ID from user JID and namespace
    std::string build_pep_node_id(const std::string& user_jid,
                                   const std::string& pep_namespace) {
        return bare_jid(user_jid) + "#" + pep_namespace;
    }

}  // namespace PEPUtils

}  // namespace xmpp
}  // namespace progressive
