/*
 * progressive-server - XMPP PubSub Advanced Features Implementation
 *
 * This file extends the base pubsub implementation (xmpp_pubsub.cpp) with
 * advanced features including:
 *   - Collection node management with full CRUD operations
 *   - Node hierarchy traversal (tree walking, depth-first, breadth-first)
 *   - Per-subscriber subscription options and filtering rules
 *   - Pending subscription management with approve/reject workflow
 *   - Subscription state notification engine
 *   - Node metadata store (XEP-0060 #meta-data)
 *   - Node statistics collection and aggregation
 *   - Event filtering rules for subscriber notifications
 *   - Transient node handling (non-persistent items)
 *   - Access model enforcement with granular permission checks
 *   - Node type conversion (leaf <-> collection)
 *   - Multi-subscribe and bulk operations
 *   - Notification batching and rate limiting
 *   - Node import/export serialization
 *   - Subscription expiry and renewal
 *   - Advanced item expiry policies
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
#include <queue>
#include <stack>

namespace progressive {
namespace xmpp {

// ============================================================================
// Forward declarations (mirror those in xmpp_pubsub.cpp)
// ============================================================================

class PubSubNode;
class PubSubItemRecord;
class PubSubSubscription;
class PubSubService;
class PEPHandler;
class PubSubManager;

// ============================================================================
// Enumerations (mirror those in xmpp_pubsub.cpp)
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

// ============================================================================
// Advanced enumerations
// ============================================================================

enum class SubscriptionOptionKey {
    DELIVER,
    DIGEST,
    DIGEST_FREQUENCY,
    INCLUDE_BODY,
    SHOW_VALUES,
    SUBSCRIPTION_TYPE,
    SUBSCRIPTION_DEPTH,
    EXPIRES,
    SECRET
};

enum class NodeTraversalOrder {
    DEPTH_FIRST,
    BREADTH_FIRST,
    PRE_ORDER,
    POST_ORDER
};

enum class EventFilterType {
    ITEMS_PUBLISH,
    ITEMS_RETRACT,
    NODE_DELETE,
    NODE_PURGE,
    NODE_CONFIG,
    SUBSCRIPTION_CHANGE,
    AFFILIATION_CHANGE
};

enum class PendingAction {
    APPROVE,
    REJECT,
    CANCEL
};

enum class ItemExpiryPolicy {
    NONE,
    TIME_BASED,
    COUNT_BASED,
    SIZE_BASED,
    HYBRID
};

enum class NotificationBatchingMode {
    NONE,
    PER_SUBSCRIBER,
    PER_NODE,
    GLOBAL_BATCH
};

// ============================================================================
// String conversion helpers (mirror those in xmpp_pubsub.cpp)
// ============================================================================

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

inline const char* event_filter_type_to_string(EventFilterType eft) {
    switch (eft) {
        case EventFilterType::ITEMS_PUBLISH:      return "items_publish";
        case EventFilterType::ITEMS_RETRACT:      return "items_retract";
        case EventFilterType::NODE_DELETE:        return "node_delete";
        case EventFilterType::NODE_PURGE:         return "node_purge";
        case EventFilterType::NODE_CONFIG:        return "node_config";
        case EventFilterType::SUBSCRIPTION_CHANGE: return "subscription_change";
        case EventFilterType::AFFILIATION_CHANGE: return "affiliation_change";
        default: return "unknown";
    }
}

inline EventFilterType event_filter_type_from_string(const std::string& s) {
    if (s == "items_publish")       return EventFilterType::ITEMS_PUBLISH;
    if (s == "items_retract")       return EventFilterType::ITEMS_RETRACT;
    if (s == "node_delete")         return EventFilterType::NODE_DELETE;
    if (s == "node_purge")          return EventFilterType::NODE_PURGE;
    if (s == "node_config")         return EventFilterType::NODE_CONFIG;
    if (s == "subscription_change") return EventFilterType::SUBSCRIPTION_CHANGE;
    if (s == "affiliation_change")  return EventFilterType::AFFILIATION_CHANGE;
    return EventFilterType::ITEMS_PUBLISH;
}

// ============================================================================
// XML utility functions
// ============================================================================

namespace XMLUtil {

inline std::string escape(const std::string& s) {
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

inline std::string unescape(const std::string& s) {
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

inline std::string bare_jid(const std::string& jid) {
    size_t slash = jid.find('/');
    if (slash != std::string::npos) {
        return jid.substr(0, slash);
    }
    return jid;
}

inline std::string timestamp_iso8601() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

inline std::string generate_uuid() {
    static std::atomic<uint64_t> counter{0};
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    std::ostringstream oss;
    oss << std::hex << ms << "-" << (gen() & 0xFFFFFFFF) << "-" << (++counter);
    return oss.str();
}

}  // namespace XMLUtil

// ============================================================================
// NodeMetadata - Extended metadata for a PubSub node
// ============================================================================

struct NodeMetadata {
    std::string node_id;
    std::string creator_jid;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_modified_at;
    std::chrono::system_clock::time_point last_published_at;
    std::string last_publisher_jid;
    std::string last_item_id;
    uint64_t total_publish_count = 0;
    uint64_t total_retract_count = 0;
    uint64_t total_item_count_lifetime = 0;
    uint64_t total_notifications_sent = 0;
    uint64_t current_subscriber_count = 0;
    uint64_t peak_subscriber_count = 0;
    uint64_t total_subscriptions_lifetime = 0;
    uint64_t total_unsubscriptions_lifetime = 0;
    PubSubNodeType node_type = PubSubNodeType::LEAF;
    PubSubAccessModel access_model = PubSubAccessModel::OPEN;
    std::map<std::string, std::string> custom_properties;
    std::string contact_jid;
    std::string language;
    std::vector<std::string> discovery_categories;
    std::vector<std::string> discovery_features;
    std::string description;
    std::string title;

    NodeMetadata() : created_at(std::chrono::system_clock::now()),
                     last_modified_at(std::chrono::system_clock::now()),
                     last_published_at(std::chrono::system_clock::now()) {}

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<meta-data xmlns=\"http://jabber.org/protocol/pubsub#meta-data\">";

        oss << "<field var=\"pubsub#creation-date\">"
            << "<value>" << timestamp_to_string(created_at) << "</value></field>";

        oss << "<field var=\"pubsub#last-modified\">"
            << "<value>" << timestamp_to_string(last_modified_at) << "</value></field>";

        oss << "<field var=\"pubsub#creator\">"
            << "<value>" << XMLUtil::escape(creator_jid) << "</value></field>";

        oss << "<field var=\"pubsub#title\">"
            << "<value>" << XMLUtil::escape(title) << "</value></field>";

        oss << "<field var=\"pubsub#description\">"
            << "<value>" << XMLUtil::escape(description) << "</value></field>";

        oss << "<field var=\"pubsub#num-subscribers\">"
            << "<value>" << current_subscriber_count << "</value></field>";

        oss << "<field var=\"pubsub#access_model\">"
            << "<value>" << pubsub_access_model_to_string(access_model) << "</value></field>";

        oss << "<field var=\"pubsub#node_type\">"
            << "<value>" << pubsub_node_type_to_string(node_type) << "</value></field>";

        if (!contact_jid.empty()) {
            oss << "<field var=\"pubsub#contact\">"
                << "<value>" << XMLUtil::escape(contact_jid) << "</value></field>";
        }

        if (!language.empty()) {
            oss << "<field var=\"pubsub#language\">"
                << "<value>" << XMLUtil::escape(language) << "</value></field>";
        }

        // Custom properties
        for (const auto& [key, value] : custom_properties) {
            oss << "<field var=\"" << XMLUtil::escape(key) << "\">"
                << "<value>" << XMLUtil::escape(value) << "</value></field>";
        }

        oss << "</meta-data>";
        return oss.str();
    }

    std::string to_statistics_xml() const {
        std::ostringstream oss;
        oss << "<statistics node=\"" << XMLUtil::escape(node_id) << "\">";

        oss << "<stat name=\"total-publishes\" value=\"" << total_publish_count << "\"/>";
        oss << "<stat name=\"total-retracts\" value=\"" << total_retract_count << "\"/>";
        oss << "<stat name=\"total-items-lifetime\" value=\"" << total_item_count_lifetime << "\"/>";
        oss << "<stat name=\"total-notifications\" value=\"" << total_notifications_sent << "\"/>";
        oss << "<stat name=\"current-subscribers\" value=\"" << current_subscriber_count << "\"/>";
        oss << "<stat name=\"peak-subscribers\" value=\"" << peak_subscriber_count << "\"/>";
        oss << "<stat name=\"total-subscriptions\" value=\"" << total_subscriptions_lifetime << "\"/>";
        oss << "<stat name=\"total-unsubscriptions\" value=\"" << total_unsubscriptions_lifetime << "\"/>";

        if (!last_publisher_jid.empty()) {
            oss << "<stat name=\"last-publisher\" value=\""
                << XMLUtil::escape(last_publisher_jid) << "\"/>";
        }

        oss << "<stat name=\"last-published\" value=\""
            << timestamp_to_string(last_published_at) << "\"/>";

        oss << "</statistics>";
        return oss.str();
    }

private:
    static std::string timestamp_to_string(
        std::chrono::system_clock::time_point tp) {
        auto t = std::chrono::system_clock::to_time_t(tp);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }
};

// ============================================================================
// SubscriptionOptions - Per-subscriber configuration
// ============================================================================

class SubscriptionOptions {
public:
    SubscriptionOptions()
        : deliver_notifications_(true)
        , digest_mode_(false)
        , digest_frequency_ms_(86400000)
        , include_body_(true)
        , subscription_depth_(1)
        , include_payload_(true)
        , notify_on_publish_(true)
        , notify_on_retract_(true)
        , notify_on_delete_(true)
        , notify_on_purge_(true)
        , notify_on_config_(false)
        , notify_on_subscription_(false)
        , notify_on_affiliation_(false)
        , secret_("")
        , expires_at_(std::chrono::system_clock::time_point::max())
        , never_expires_(true)
        , receive_last_published_(true)
        , filtered_namespaces_(std::set<std::string>())
    {}

    // Accessors
    bool deliver_notifications() const { return deliver_notifications_; }
    void set_deliver_notifications(bool d) { deliver_notifications_ = d; }

    bool digest_mode() const { return digest_mode_; }
    void set_digest_mode(bool d) { digest_mode_ = d; }

    int digest_frequency_ms() const { return digest_frequency_ms_; }
    void set_digest_frequency_ms(int ms) { digest_frequency_ms_ = ms; }

    bool include_body() const { return include_body_; }
    void set_include_body(bool b) { include_body_ = b; }

    int subscription_depth() const { return subscription_depth_; }
    void set_subscription_depth(int d) { subscription_depth_ = std::max(0, d); }

    bool include_payload() const { return include_payload_; }
    void set_include_payload(bool p) { include_payload_ = p; }

    bool notify_on_publish() const { return notify_on_publish_; }
    void set_notify_on_publish(bool n) { notify_on_publish_ = n; }

    bool notify_on_retract() const { return notify_on_retract_; }
    void set_notify_on_retract(bool n) { notify_on_retract_ = n; }

    bool notify_on_delete() const { return notify_on_delete_; }
    void set_notify_on_delete(bool n) { notify_on_delete_ = n; }

    bool notify_on_purge() const { return notify_on_purge_; }
    void set_notify_on_purge(bool n) { notify_on_purge_ = n; }

    bool notify_on_config() const { return notify_on_config_; }
    void set_notify_on_config(bool n) { notify_on_config_ = n; }

    bool notify_on_subscription() const { return notify_on_subscription_; }
    void set_notify_on_subscription(bool n) { notify_on_subscription_ = n; }

    bool notify_on_affiliation() const { return notify_on_affiliation_; }
    void set_notify_on_affiliation(bool n) { notify_on_affiliation_ = n; }

    const std::string& secret() const { return secret_; }
    void set_secret(const std::string& s) { secret_ = s; }

    bool never_expires() const { return never_expires_; }
    std::chrono::system_clock::time_point expires_at() const { return expires_at_; }
    void set_expires_at(std::chrono::system_clock::time_point t) {
        expires_at_ = t;
        never_expires_ = false;
    }
    void set_never_expires() { never_expires_ = true; }

    bool receive_last_published() const { return receive_last_published_; }
    void set_receive_last_published(bool r) { receive_last_published_ = r; }

    const std::set<std::string>& filtered_namespaces() const {
        return filtered_namespaces_;
    }
    void add_filtered_namespace(const std::string& ns) {
        filtered_namespaces_.insert(ns);
    }
    void remove_filtered_namespace(const std::string& ns) {
        filtered_namespaces_.erase(ns);
    }

    // Check if this subscription has expired
    bool is_expired() const {
        if (never_expires_) return false;
        return std::chrono::system_clock::now() > expires_at_;
    }

    // Build a subscription options data form (XEP-0004)
    std::string to_options_form_xml() const {
        std::ostringstream oss;
        oss << "<x xmlns=\"jabber:x:data\" type=\"form\">";
        oss << "<title>Subscription Options</title>";
        oss << "<instructions>Configure your subscription options</instructions>";

        oss << "<field var=\"FORM_TYPE\" type=\"hidden\">"
            << "<value>http://jabber.org/protocol/pubsub#subscribe_options</value>"
            << "</field>";

        oss << "<field var=\"pubsub#deliver\" type=\"boolean\" label=\"Enable delivery\">"
            << "<value>" << (deliver_notifications_ ? "1" : "0") << "</value></field>";

        oss << "<field var=\"pubsub#digest\" type=\"boolean\" label=\"Receive digest\">"
            << "<value>" << (digest_mode_ ? "1" : "0") << "</value></field>";

        oss << "<field var=\"pubsub#digest_frequency\" type=\"text-single\""
            << " label=\"Digest frequency (milliseconds)\">"
            << "<value>" << digest_frequency_ms_ << "</value></field>";

        oss << "<field var=\"pubsub#include_body\" type=\"boolean\""
            << " label=\"Include body in notifications\">"
            << "<value>" << (include_body_ ? "1" : "0") << "</value></field>";

        oss << "<field var=\"pubsub#subscription_depth\" type=\"text-single\""
            << " label=\"Subscription depth (0=all, 1=node only)\">"
            << "<value>" << subscription_depth_ << "</value></field>";

        oss << "<field var=\"pubsub#include_payload\" type=\"boolean\""
            << " label=\"Include payload in notifications\">"
            << "<value>" << (include_payload_ ? "1" : "0") << "</value></field>";

        oss << "<field var=\"pubsub#notify_on_publish\" type=\"boolean\""
            << " label=\"Notify on publish\">"
            << "<value>" << (notify_on_publish_ ? "1" : "0") << "</value></field>";

        oss << "<field var=\"pubsub#notify_on_retract\" type=\"boolean\""
            << " label=\"Notify on retract\">"
            << "<value>" << (notify_on_retract_ ? "1" : "0") << "</value></field>";

        oss << "<field var=\"pubsub#notify_on_delete\" type=\"boolean\""
            << " label=\"Notify on delete\">"
            << "<value>" << (notify_on_delete_ ? "1" : "0") << "</value></field>";

        oss << "<field var=\"pubsub#notify_on_purge\" type=\"boolean\""
            << " label=\"Notify on purge\">"
            << "<value>" << (notify_on_purge_ ? "1" : "0") << "</value></field>";

        oss << "<field var=\"pubsub#notify_on_config\" type=\"boolean\""
            << " label=\"Notify on config change\">"
            << "<value>" << (notify_on_config_ ? "1" : "0") << "</value></field>";

        oss << "<field var=\"pubsub#receive_last_published\" type=\"boolean\""
            << " label=\"Receive last published item on subscribe\">"
            << "<value>" << (receive_last_published_ ? "1" : "0") << "</value></field>";

        oss << "</x>";
        return oss.str();
    }

    // Apply configuration from parsed form fields
    void apply_form_fields(
        const std::map<std::string, std::vector<std::string>>& fields) {
        for (const auto& [var, values] : fields) {
            if (values.empty()) continue;
            const std::string& val = values[0];

            if (var == "pubsub#deliver")
                deliver_notifications_ = (val == "1" || val == "true");
            else if (var == "pubsub#digest")
                digest_mode_ = (val == "1" || val == "true");
            else if (var == "pubsub#digest_frequency") {
                try { digest_frequency_ms_ = std::stoi(val); }
                catch (...) { digest_frequency_ms_ = 86400000; }
            }
            else if (var == "pubsub#include_body")
                include_body_ = (val == "1" || val == "true");
            else if (var == "pubsub#subscription_depth") {
                try { subscription_depth_ = std::stoi(val); }
                catch (...) { subscription_depth_ = 1; }
            }
            else if (var == "pubsub#include_payload")
                include_payload_ = (val == "1" || val == "true");
            else if (var == "pubsub#notify_on_publish")
                notify_on_publish_ = (val == "1" || val == "true");
            else if (var == "pubsub#notify_on_retract")
                notify_on_retract_ = (val == "1" || val == "true");
            else if (var == "pubsub#notify_on_delete")
                notify_on_delete_ = (val == "1" || val == "true");
            else if (var == "pubsub#notify_on_purge")
                notify_on_purge_ = (val == "1" || val == "true");
            else if (var == "pubsub#notify_on_config")
                notify_on_config_ = (val == "1" || val == "true");
            else if (var == "pubsub#receive_last_published")
                receive_last_published_ = (val == "1" || val == "true");
            else if (var == "pubsub#secret")
                secret_ = val;
            else if (var == "pubsub#expires") {
                // Parse expiry timestamp or duration
                try {
                    int64_t expire_ms = std::stoll(val);
                    expires_at_ = std::chrono::system_clock::now() +
                        std::chrono::milliseconds(expire_ms);
                    never_expires_ = false;
                } catch (...) {
                    never_expires_ = true;
                }
            }
        }
    }

    // Convert to a serializable map
    std::map<std::string, std::string> to_map() const {
        std::map<std::string, std::string> m;
        m["pubsub#deliver"] = deliver_notifications_ ? "1" : "0";
        m["pubsub#digest"] = digest_mode_ ? "1" : "0";
        m["pubsub#digest_frequency"] = std::to_string(digest_frequency_ms_);
        m["pubsub#include_body"] = include_body_ ? "1" : "0";
        m["pubsub#subscription_depth"] = std::to_string(subscription_depth_);
        m["pubsub#include_payload"] = include_payload_ ? "1" : "0";
        m["pubsub#notify_on_publish"] = notify_on_publish_ ? "1" : "0";
        m["pubsub#notify_on_retract"] = notify_on_retract_ ? "1" : "0";
        m["pubsub#notify_on_delete"] = notify_on_delete_ ? "1" : "0";
        m["pubsub#notify_on_purge"] = notify_on_purge_ ? "1" : "0";
        m["pubsub#notify_on_config"] = notify_on_config_ ? "1" : "0";
        m["pubsub#secret"] = secret_;
        return m;
    }

private:
    bool deliver_notifications_;
    bool digest_mode_;
    int digest_frequency_ms_;
    bool include_body_;
    int subscription_depth_;
    bool include_payload_;
    bool notify_on_publish_;
    bool notify_on_retract_;
    bool notify_on_delete_;
    bool notify_on_purge_;
    bool notify_on_config_;
    bool notify_on_subscription_;
    bool notify_on_affiliation_;
    std::string secret_;
    std::chrono::system_clock::time_point expires_at_;
    bool never_expires_;
    bool receive_last_published_;
    std::set<std::string> filtered_namespaces_;
};

// ============================================================================
// EventFilterRule - A single rule for filtering event notifications
// ============================================================================

class EventFilterRule {
public:
    struct Condition {
        enum class Operator {
            EQUALS,
            NOT_EQUALS,
            CONTAINS,
            STARTS_WITH,
            ENDS_WITH,
            MATCHES_REGEX,
            GREATER_THAN,
            LESS_THAN
        };

        std::string field;
        Operator op = Operator::EQUALS;
        std::string value;
        bool case_sensitive = true;

        bool evaluate(const std::string& field_value) const {
            std::string fv = case_sensitive ? field_value : to_lower(field_value);
            std::string cv = case_sensitive ? value : to_lower(value);

            switch (op) {
                case Operator::EQUALS:
                    return fv == cv;
                case Operator::NOT_EQUALS:
                    return fv != cv;
                case Operator::CONTAINS:
                    return fv.find(cv) != std::string::npos;
                case Operator::STARTS_WITH:
                    return fv.find(cv) == 0;
                case Operator::ENDS_WITH:
                    return fv.size() >= cv.size() &&
                           fv.compare(fv.size() - cv.size(), cv.size(), cv) == 0;
                case Operator::GREATER_THAN:
                    return fv > cv;
                case Operator::LESS_THAN:
                    return fv < cv;
                case Operator::MATCHES_REGEX:
                    return simple_wildcard_match(fv, cv);
                default:
                    return false;
            }
        }

    private:
        static std::string to_lower(const std::string& s) {
            std::string result = s;
            std::transform(result.begin(), result.end(), result.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            return result;
        }

        static bool simple_wildcard_match(const std::string& text,
                                           const std::string& pattern) {
            // Simple glob-style matching (* matches any sequence, ? matches any char)
            size_t ti = 0, pi = 0;
            size_t star_ti = std::string::npos, star_pi = std::string::npos;

            while (ti < text.size()) {
                if (pi < pattern.size() &&
                    (pattern[pi] == '?' ||
                     std::tolower(pattern[pi]) == std::tolower(text[ti]))) {
                    ++ti; ++pi;
                } else if (pi < pattern.size() && pattern[pi] == '*') {
                    star_ti = ti;
                    star_pi = pi;
                    ++pi;
                } else if (star_pi != std::string::npos) {
                    ti = ++star_ti;
                    pi = star_pi + 1;
                } else {
                    return false;
                }
            }

            while (pi < pattern.size() && pattern[pi] == '*') ++pi;
            return pi == pattern.size();
        }
    };

    EventFilterRule()
        : rule_id_(XMLUtil::generate_uuid())
        , enabled_(true)
        , action_(true)  // true = allow, false = deny
        , priority_(0)
        , event_type_(EventFilterType::ITEMS_PUBLISH)
    {}

    EventFilterRule(const std::string& id, EventFilterType event_type,
                    bool allow, int priority = 0)
        : rule_id_(id)
        , enabled_(true)
        , action_(allow)
        , priority_(priority)
        , event_type_(event_type)
    {}

    const std::string& rule_id() const { return rule_id_; }
    bool enabled() const { return enabled_; }
    void set_enabled(bool e) { enabled_ = e; }
    bool action() const { return action_; }
    int priority() const { return priority_; }
    void set_priority(int p) { priority_ = p; }
    EventFilterType event_type() const { return event_type_; }
    void set_event_type(EventFilterType et) { event_type_ = et; }

    void add_condition(const Condition& cond) {
        conditions_.push_back(cond);
    }

    void remove_condition(size_t index) {
        if (index < conditions_.size()) {
            conditions_.erase(conditions_.begin() + static_cast<long>(index));
        }
    }

    const std::vector<Condition>& conditions() const { return conditions_; }

    // Evaluate this rule against a set of field values
    bool evaluate(const std::map<std::string, std::string>& context) const {
        if (!enabled_) return true;  // Disabled rules don't block

        for (const auto& cond : conditions_) {
            auto it = context.find(cond.field);
            if (it == context.end()) {
                // Field not present in context - rule doesn't match
                return true;
            }
            if (!cond.evaluate(it->second)) {
                // Condition not met - rule doesn't apply
                return true;
            }
        }

        // All conditions matched - apply the rule's action
        return action_;
    }

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<rule id=\"" << XMLUtil::escape(rule_id_) << "\"";
        oss << " event=\"" << event_filter_type_to_string(event_type_) << "\"";
        oss << " action=\"" << (action_ ? "allow" : "deny") << "\"";
        oss << " priority=\"" << priority_ << "\"";
        oss << " enabled=\"" << (enabled_ ? "true" : "false") << "\">";

        for (const auto& cond : conditions_) {
            oss << "<condition field=\"" << XMLUtil::escape(cond.field) << "\"";
            oss << " op=\"" << condition_op_to_string(cond.op) << "\"";
            oss << " value=\"" << XMLUtil::escape(cond.value) << "\"/>";
        }

        oss << "</rule>";
        return oss.str();
    }

private:
    static std::string condition_op_to_string(Condition::Operator op) {
        switch (op) {
            case Condition::Operator::EQUALS:       return "equals";
            case Condition::Operator::NOT_EQUALS:   return "not-equals";
            case Condition::Operator::CONTAINS:     return "contains";
            case Condition::Operator::STARTS_WITH:  return "starts-with";
            case Condition::Operator::ENDS_WITH:    return "ends-with";
            case Condition::Operator::MATCHES_REGEX: return "matches";
            case Condition::Operator::GREATER_THAN: return "greater-than";
            case Condition::Operator::LESS_THAN:    return "less-than";
            default: return "equals";
        }
    }

    std::string rule_id_;
    bool enabled_;
    bool action_;
    int priority_;
    EventFilterType event_type_;
    std::vector<Condition> conditions_;
};

// ============================================================================
// EventFilterEngine - Manages event filtering rules for subscribers
// ============================================================================

class EventFilterEngine {
public:
    EventFilterEngine() = default;

    // Add a rule for a specific subscriber on a specific node
    void add_rule(const std::string& subscriber_jid,
                  const std::string& node_id,
                  const EventFilterRule& rule) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(subscriber_jid, node_id);
        rules_[key].push_back(rule);
        // Sort by priority (higher priority first)
        std::sort(rules_[key].begin(), rules_[key].end(),
                  [](const EventFilterRule& a, const EventFilterRule& b) {
                      return a.priority() > b.priority();
                  });
    }

    // Remove a rule by ID
    bool remove_rule(const std::string& subscriber_jid,
                     const std::string& node_id,
                     const std::string& rule_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(subscriber_jid, node_id);
        auto it = rules_.find(key);
        if (it == rules_.end()) return false;

        auto& rules_list = it->second;
        auto rule_it = std::find_if(rules_list.begin(), rules_list.end(),
            [&rule_id](const EventFilterRule& r) {
                return r.rule_id() == rule_id;
            });
        if (rule_it == rules_list.end()) return false;

        rules_list.erase(rule_it);
        return true;
    }

    // Get all rules for a subscriber on a node
    std::vector<EventFilterRule> get_rules(const std::string& subscriber_jid,
                                            const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(subscriber_jid, node_id);
        auto it = rules_.find(key);
        if (it != rules_.end()) {
            return it->second;
        }
        return {};
    }

    // Clear all rules for a subscriber on a node
    void clear_rules(const std::string& subscriber_jid,
                     const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(subscriber_jid, node_id);
        rules_.erase(key);
    }

    // Check if an event should be delivered to a subscriber
    bool should_deliver(const std::string& subscriber_jid,
                        const std::string& node_id,
                        EventFilterType event_type,
                        const std::map<std::string, std::string>& context) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(subscriber_jid, node_id);
        auto it = rules_.find(key);
        if (it == rules_.end()) return true;  // No rules = allow all

        bool allowed = true;  // Default: allow
        for (const auto& rule : it->second) {
            if (rule.event_type() != event_type) continue;

            // Build full context
            std::map<std::string, std::string> full_context = context;
            full_context["event_type"] = event_filter_type_to_string(event_type);
            full_context["subscriber"] = subscriber_jid;
            full_context["node"] = node_id;

            if (!rule.evaluate(full_context)) {
                // If any condition set in the rule was NOT met, rule doesn't apply
                continue;
            }

            // Rule conditions met - apply the rule's action
            allowed = rule.action();
            break;  // First matching rule wins (priority-sorted)
        }

        return allowed;
    }

    // List all subscribers that have rules defined
    std::vector<std::string> get_all_subscribers_with_rules() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::set<std::string> subscribers;
        for (const auto& [key, rules_list] : rules_) {
            size_t sep = key.find('|');
            if (sep != std::string::npos) {
                subscribers.insert(key.substr(0, sep));
            }
        }
        return std::vector<std::string>(subscribers.begin(), subscribers.end());
    }

    size_t total_rule_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& [key, rules_list] : rules_) {
            count += rules_list.size();
        }
        return count;
    }

private:
    static std::string make_key(const std::string& subscriber_jid,
                                const std::string& node_id) {
        return subscriber_jid + "|" + node_id;
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::vector<EventFilterRule>> rules_;
};

// ============================================================================
// PendingSubscription - A subscription awaiting approval
// ============================================================================

class PendingSubscription {
public:
    PendingSubscription()
        : created_at_(std::chrono::system_clock::now())
        , auto_approve_deadline_(std::chrono::system_clock::time_point::max())
        , notification_count_(0)
    {}

    PendingSubscription(const std::string& node_id,
                        const std::string& subscriber_jid,
                        const std::string& subscription_id = "")
        : node_id_(node_id)
        , subscriber_jid_(subscriber_jid)
        , subscription_id_(subscription_id)
        , created_at_(std::chrono::system_clock::now())
        , auto_approve_deadline_(std::chrono::system_clock::time_point::max())
        , notification_count_(0)
    {}

    const std::string& node_id() const { return node_id_; }
    const std::string& subscriber_jid() const { return subscriber_jid_; }
    const std::string& subscription_id() const { return subscription_id_; }
    void set_subscription_id(const std::string& sid) { subscription_id_ = sid; }

    std::chrono::system_clock::time_point created_at() const { return created_at_; }
    int notification_count() const { return notification_count_; }
    void increment_notification_count() { ++notification_count_; }

    void set_auto_approve_deadline(std::chrono::system_clock::time_point deadline) {
        auto_approve_deadline_ = deadline;
    }

    bool is_auto_approve_eligible() const {
        if (auto_approve_deadline_ == std::chrono::system_clock::time_point::max()) {
            return false;
        }
        return std::chrono::system_clock::now() > auto_approve_deadline_;
    }

    const SubscriptionOptions& options() const { return options_; }
    SubscriptionOptions& options() { return options_; }
    void set_options(const SubscriptionOptions& opts) { options_ = opts; }

    std::string to_xml() const {
        std::ostringstream oss;
        oss << "<pending-subscription";
        oss << " node=\"" << XMLUtil::escape(node_id_) << "\"";
        oss << " jid=\"" << XMLUtil::escape(subscriber_jid_) << "\"";
        if (!subscription_id_.empty()) {
            oss << " subid=\"" << XMLUtil::escape(subscription_id_) << "\"";
        }
        oss << " created=\"" << timestamp_iso8601(created_at_) << "\"";
        oss << " notifications=\"" << notification_count_ << "\"";
        oss << "/>";
        return oss.str();
    }

    // Build a notification message to inform subscriber of pending state
    std::string build_pending_notification(const std::string& service_jid) const {
        std::ostringstream oss;
        oss << "<message from=\"" << XMLUtil::escape(service_jid) << "\"";
        oss << " to=\"" << XMLUtil::escape(subscriber_jid_) << "\">";
        oss << "<event xmlns=\"http://jabber.org/protocol/pubsub#event\">";
        oss << "<subscription";
        oss << " node=\"" << XMLUtil::escape(node_id_) << "\"";
        oss << " jid=\"" << XMLUtil::escape(subscriber_jid_) << "\"";
        oss << " subscription=\"pending\"/>";
        oss << "</event></message>";
        return oss.str();
    }

private:
    static std::string timestamp_iso8601(std::chrono::system_clock::time_point tp) {
        auto t = std::chrono::system_clock::to_time_t(tp);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

    std::string node_id_;
    std::string subscriber_jid_;
    std::string subscription_id_;
    std::chrono::system_clock::time_point created_at_;
    std::chrono::system_clock::time_point auto_approve_deadline_;
    int notification_count_;
    SubscriptionOptions options_;
};

// ============================================================================
// PendingSubscriptionManager - Manages pending subscription approvals
// ============================================================================

class PendingSubscriptionManager {
public:
    using SendCallback = std::function<void(const std::string& stanza_xml)>;
    using Logger = std::function<void(const std::string& level, const std::string& msg)>;

    PendingSubscriptionManager(const std::string& service_jid,
                                SendCallback send_cb)
        : service_jid_(service_jid)
        , send_callback_(send_cb)
        , auto_approve_enabled_(false)
        , auto_approve_timeout_seconds_(86400)  // 24 hours default
        , max_notifications_(5)
        , logging_enabled_(true)
    {}

    // Add a pending subscription
    void add_pending(const std::string& node_id,
                     const std::string& subscriber_jid,
                     const std::string& subscription_id = "") {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string key = make_key(node_id, subscriber_jid);

        auto pending = PendingSubscription(node_id, subscriber_jid, subscription_id);

        if (auto_approve_enabled_) {
            auto deadline = std::chrono::system_clock::now() +
                std::chrono::seconds(auto_approve_timeout_seconds_);
            pending.set_auto_approve_deadline(deadline);
        }

        pending_subscriptions_[key] = pending;
        log_info("Pending subscription added: " + subscriber_jid +
                 " -> " + node_id);
    }

    // Approve a pending subscription
    bool approve(const std::string& node_id,
                 const std::string& subscriber_jid,
                 const std::string& approver_jid) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string key = make_key(node_id, subscriber_jid);
        auto it = pending_subscriptions_.find(key);
        if (it == pending_subscriptions_.end()) {
            log_warn("Approve failed: no pending subscription for " +
                     subscriber_jid + " on " + node_id);
            return false;
        }

        auto pending = it->second;
        pending_subscriptions_.erase(it);

        // Send approval notification
        send_approval_notification(node_id, subscriber_jid, pending.subscription_id());

        log_info("Pending subscription approved: " + subscriber_jid +
                 " -> " + node_id + " by " + approver_jid);
        return true;
    }

    // Reject a pending subscription
    bool reject(const std::string& node_id,
                const std::string& subscriber_jid,
                const std::string& rejecter_jid,
                const std::string& reason = "") {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string key = make_key(node_id, subscriber_jid);
        auto it = pending_subscriptions_.find(key);
        if (it == pending_subscriptions_.end()) {
            log_warn("Reject failed: no pending subscription for " +
                     subscriber_jid + " on " + node_id);
            return false;
        }

        pending_subscriptions_.erase(it);

        // Send rejection notification
        send_rejection_notification(node_id, subscriber_jid, reason);

        log_info("Pending subscription rejected: " + subscriber_jid +
                 " -> " + node_id + " by " + rejecter_jid +
                 (reason.empty() ? "" : " reason: " + reason));
        return true;
    }

    // Cancel (self-cancel) a pending subscription
    bool cancel(const std::string& node_id,
                const std::string& subscriber_jid) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string key = make_key(node_id, subscriber_jid);
        auto it = pending_subscriptions_.find(key);
        if (it == pending_subscriptions_.end()) {
            return false;
        }

        pending_subscriptions_.erase(it);
        log_info("Pending subscription cancelled by " + subscriber_jid +
                 " on " + node_id);
        return true;
    }

    // Get a specific pending subscription
    std::optional<PendingSubscription> get_pending(
        const std::string& node_id,
        const std::string& subscriber_jid) const {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string key = make_key(node_id, subscriber_jid);
        auto it = pending_subscriptions_.find(key);
        if (it != pending_subscriptions_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Get all pending subscriptions for a node
    std::vector<PendingSubscription> get_pending_for_node(
        const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<PendingSubscription> result;

        for (const auto& [key, pending] : pending_subscriptions_) {
            if (pending.node_id() == node_id) {
                result.push_back(pending);
            }
        }
        return result;
    }

    // Get all pending subscriptions for a subscriber
    std::vector<PendingSubscription> get_pending_for_subscriber(
        const std::string& subscriber_jid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<PendingSubscription> result;

        for (const auto& [key, pending] : pending_subscriptions_) {
            if (pending.subscriber_jid() == subscriber_jid) {
                result.push_back(pending);
            }
        }
        return result;
    }

    // Get all pending subscriptions
    std::vector<PendingSubscription> get_all_pending() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<PendingSubscription> result;

        for (const auto& [key, pending] : pending_subscriptions_) {
            result.push_back(pending);
        }
        return result;
    }

    // Check if there is a pending subscription
    bool has_pending(const std::string& node_id,
                     const std::string& subscriber_jid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(node_id, subscriber_jid);
        return pending_subscriptions_.find(key) != pending_subscriptions_.end();
    }

    // Auto-approve any subscriptions that have passed their deadline
    int process_auto_approvals() {
        std::lock_guard<std::mutex> lock(mutex_);
        int approved = 0;
        std::vector<std::string> to_approve;

        for (const auto& [key, pending] : pending_subscriptions_) {
            if (pending.is_auto_approve_eligible()) {
                to_approve.push_back(key);
            }
        }

        for (const auto& key : to_approve) {
            auto it = pending_subscriptions_.find(key);
            if (it != pending_subscriptions_.end()) {
                auto pending = it->second;
                send_approval_notification(pending.node_id(),
                    pending.subscriber_jid(), pending.subscription_id());
                pending_subscriptions_.erase(it);
                ++approved;
            }
        }

        if (approved > 0) {
            log_info("Auto-approved " + std::to_string(approved) +
                     " pending subscriptions");
        }
        return approved;
    }

    // Configuration
    void set_auto_approve_enabled(bool enabled) { auto_approve_enabled_ = enabled; }
    bool auto_approve_enabled() const { return auto_approve_enabled_; }

    void set_auto_approve_timeout(int seconds) {
        auto_approve_timeout_seconds_ = seconds;
    }
    int auto_approve_timeout() const { return auto_approve_timeout_seconds_; }

    void set_max_notifications(int max) { max_notifications_ = max; }
    int max_notifications() const { return max_notifications_; }

    void set_logger(Logger logger) { logger_ = logger; }

    size_t pending_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return pending_subscriptions_.size();
    }

    // Generate XML listing all pending subscriptions for a node
    std::string generate_pending_xml(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream oss;

        for (const auto& [key, pending] : pending_subscriptions_) {
            if (pending.node_id() == node_id) {
                oss << pending.to_xml();
            }
        }
        return oss.str();
    }

    // Generate XML listing all pending subscriptions for a subscriber
    std::string generate_subscriber_pending_xml(
        const std::string& subscriber_jid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream oss;

        for (const auto& [key, pending] : pending_subscriptions_) {
            if (pending.subscriber_jid() == subscriber_jid) {
                oss << pending.to_xml();
            }
        }
        return oss.str();
    }

private:
    static std::string make_key(const std::string& node_id,
                                const std::string& subscriber_jid) {
        return node_id + "|" + subscriber_jid;
    }

    void send_approval_notification(const std::string& node_id,
                                     const std::string& subscriber_jid,
                                     const std::string& subid) {
        std::ostringstream oss;
        oss << "<message from=\"" << XMLUtil::escape(service_jid_) << "\"";
        oss << " to=\"" << XMLUtil::escape(subscriber_jid) << "\">";
        oss << "<event xmlns=\"http://jabber.org/protocol/pubsub#event\">";
        oss << "<subscription";
        oss << " node=\"" << XMLUtil::escape(node_id) << "\"";
        oss << " jid=\"" << XMLUtil::escape(subscriber_jid) << "\"";
        oss << " subscription=\"subscribed\"";
        if (!subid.empty()) {
            oss << " subid=\"" << XMLUtil::escape(subid) << "\"";
        }
        oss << "/>";
        oss << "</event></message>";

        if (send_callback_) {
            send_callback_(oss.str());
        }
    }

    void send_rejection_notification(const std::string& node_id,
                                      const std::string& subscriber_jid,
                                      const std::string& reason) {
        std::ostringstream oss;
        oss << "<message from=\"" << XMLUtil::escape(service_jid_) << "\"";
        oss << " to=\"" << XMLUtil::escape(subscriber_jid) << "\">";
        oss << "<event xmlns=\"http://jabber.org/protocol/pubsub#event\">";
        oss << "<subscription";
        oss << " node=\"" << XMLUtil::escape(node_id) << "\"";
        oss << " jid=\"" << XMLUtil::escape(subscriber_jid) << "\"";
        oss << " subscription=\"none\"";
        oss << "/>";
        oss << "</event>";

        if (!reason.empty()) {
            oss << "<body>" << XMLUtil::escape(reason) << "</body>";
        }

        oss << "</message>";

        if (send_callback_) {
            send_callback_(oss.str());
        }
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

    std::string service_jid_;
    SendCallback send_callback_;
    bool auto_approve_enabled_;
    int auto_approve_timeout_seconds_;
    int max_notifications_;
    bool logging_enabled_;
    Logger logger_;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, PendingSubscription> pending_subscriptions_;
};

// ============================================================================
// SubscriptionStateNotifier - Sends subscription state change notifications
// ============================================================================

class SubscriptionStateNotifier {
public:
    using SendCallback = std::function<void(const std::string& stanza_xml)>;

    SubscriptionStateNotifier(const std::string& service_jid,
                               SendCallback send_cb)
        : service_jid_(service_jid)
        , send_callback_(send_cb)
        , notify_owners_on_subscribe_(true)
        , notify_owners_on_unsubscribe_(true)
        , notify_owners_on_pending_(true)
        , notify_subscribers_on_approval_(true)
        , notify_subscribers_on_rejection_(true)
    {}

    // Notify about a subscription state change
    void notify_subscription_change(
        const std::string& node_id,
        const std::string& subscriber_jid,
        PubSubSubscriptionState old_state,
        PubSubSubscriptionState new_state,
        const std::string& subid = "") {
        // Notify the subscriber
        send_subscription_event(node_id, subscriber_jid, subscriber_jid,
                                new_state, subid);

        // Notify node owners
        if (should_notify_owners(old_state, new_state)) {
            std::string owner_notification = build_owner_notification(
                node_id, subscriber_jid, new_state, subid);
            // In a full implementation, the caller would provide owner JIDs
            // This is a stub that would be completed with actual owner list
        }
    }

    // Notify that a pending subscription was approved
    void notify_approval(const std::string& node_id,
                          const std::string& subscriber_jid,
                          const std::string& subid = "") {
        send_subscription_event(node_id, subscriber_jid, subscriber_jid,
                                PubSubSubscriptionState::SUBSCRIBED, subid);
    }

    // Notify that a pending subscription was rejected
    void notify_rejection(const std::string& node_id,
                           const std::string& subscriber_jid,
                           const std::string& reason = "") {
        std::ostringstream oss;
        oss << "<message from=\"" << XMLUtil::escape(service_jid_) << "\"";
        oss << " to=\"" << XMLUtil::escape(subscriber_jid) << "\">";
        oss << "<event xmlns=\"http://jabber.org/protocol/pubsub#event\">";
        oss << "<subscription";
        oss << " node=\"" << XMLUtil::escape(node_id) << "\"";
        oss << " jid=\"" << XMLUtil::escape(subscriber_jid) << "\"";
        oss << " subscription=\"none\"/>";
        oss << "</event>";

        if (!reason.empty()) {
            oss << "<body>" << XMLUtil::escape(reason) << "</body>";
        }

        oss << "</message>";

        if (send_callback_) {
            send_callback_(oss.str());
        }
    }

    // Configuration
    void set_notify_owners_on_subscribe(bool b) { notify_owners_on_subscribe_ = b; }
    void set_notify_owners_on_unsubscribe(bool b) { notify_owners_on_unsubscribe_ = b; }
    void set_notify_owners_on_pending(bool b) { notify_owners_on_pending_ = b; }
    void set_notify_subscribers_on_approval(bool b) { notify_subscribers_on_approval_ = b; }
    void set_notify_subscribers_on_rejection(bool b) { notify_subscribers_on_rejection_ = b; }

private:
    void send_subscription_event(const std::string& node_id,
                                  const std::string& target_jid,
                                  const std::string& subscriber_jid,
                                  PubSubSubscriptionState state,
                                  const std::string& subid) {
        std::ostringstream oss;
        oss << "<message from=\"" << XMLUtil::escape(service_jid_) << "\"";
        oss << " to=\"" << XMLUtil::escape(target_jid) << "\">";
        oss << "<event xmlns=\"http://jabber.org/protocol/pubsub#event\">";
        oss << "<subscription";
        oss << " node=\"" << XMLUtil::escape(node_id) << "\"";
        oss << " jid=\"" << XMLUtil::escape(subscriber_jid) << "\"";
        oss << " subscription=\""
            << pubsub_subscription_state_to_string(state) << "\"";
        if (!subid.empty()) {
            oss << " subid=\"" << XMLUtil::escape(subid) << "\"";
        }
        oss << "/>";
        oss << "</event></message>";

        if (send_callback_) {
            send_callback_(oss.str());
        }
    }

    bool should_notify_owners(PubSubSubscriptionState old_state,
                               PubSubSubscriptionState new_state) const {
        if (old_state == PubSubSubscriptionState::NONE &&
            new_state == PubSubSubscriptionState::PENDING) {
            return notify_owners_on_pending_;
        }
        if (old_state != PubSubSubscriptionState::SUBSCRIBED &&
            new_state == PubSubSubscriptionState::SUBSCRIBED) {
            return notify_owners_on_subscribe_;
        }
        if (old_state == PubSubSubscriptionState::SUBSCRIBED &&
            new_state == PubSubSubscriptionState::NONE) {
            return notify_owners_on_unsubscribe_;
        }
        return false;
    }

    std::string build_owner_notification(const std::string& node_id,
                                           const std::string& subscriber_jid,
                                           PubSubSubscriptionState state,
                                           const std::string& subid) {
        std::ostringstream oss;
        oss << "<message from=\"" << XMLUtil::escape(service_jid_) << "\">";
        oss << "<event xmlns=\"http://jabber.org/protocol/pubsub#event\">";
        oss << "<subscription";
        oss << " node=\"" << XMLUtil::escape(node_id) << "\"";
        oss << " jid=\"" << XMLUtil::escape(subscriber_jid) << "\"";
        oss << " subscription=\""
            << pubsub_subscription_state_to_string(state) << "\"";
        if (!subid.empty()) {
            oss << " subid=\"" << XMLUtil::escape(subid) << "\"";
        }
        oss << "/>";
        oss << "</event></message>";
        return oss.str();
    }

    std::string service_jid_;
    SendCallback send_callback_;
    bool notify_owners_on_subscribe_;
    bool notify_owners_on_unsubscribe_;
    bool notify_owners_on_pending_;
    bool notify_subscribers_on_approval_;
    bool notify_subscribers_on_rejection_;
};

// ============================================================================
// CollectionNodeManager - Full collection node CRUD and hierarchy management
// ============================================================================

class CollectionNodeManager {
public:
    CollectionNodeManager() = default;

    // ========================================================================
    // Collection node operations
    // ========================================================================

    // Add a child node to a collection
    struct AddChildResult {
        bool success = false;
        std::string error;
        bool already_exists = false;
        bool parent_not_collection = false;
        bool parent_not_found = false;
        bool child_not_found = false;
        bool would_create_cycle = false;
    };

    AddChildResult add_child(const std::string& parent_id,
                              const std::string& child_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        AddChildResult result;

        // Ensure parent exists and is a collection
        auto parent_it = collections_.find(parent_id);
        if (parent_it == collections_.end()) {
            result.parent_not_found = true;
            result.error = "Parent collection not found: " + parent_id;
            return result;
        }

        if (parent_it->second.type != PubSubNodeType::COLLECTION) {
            result.parent_not_collection = true;
            result.error = "Parent node is not a collection: " + parent_id;
            return result;
        }

        // Check for cycles
        if (parent_id == child_id) {
            result.would_create_cycle = true;
            result.error = "Cannot add self as child";
            return result;
        }

        if (would_create_cycle(child_id, parent_id)) {
            result.would_create_cycle = true;
            result.error = "Adding child would create a cycle";
            return result;
        }

        // Check if already a child
        if (parent_it->second.children.find(child_id) !=
            parent_it->second.children.end()) {
            result.already_exists = true;
            result.success = true;  // Idempotent
            return result;
        }

        // Add child
        parent_it->second.children.insert(child_id);

        // Ensure child exists in mapping
        if (collections_.find(child_id) == collections_.end()) {
            NodeHierarchyInfo info;
            info.node_id = child_id;
            info.parent_id = parent_id;
            info.type = PubSubNodeType::LEAF;
            info.level = parent_it->second.level + 1;
            collections_[child_id] = info;
        } else {
            // Update existing child's parent
            collections_[child_id].parent_id = parent_id;
            collections_[child_id].level = parent_it->second.level + 1;
        }

        // Recalculate levels for all descendants of child
        recalculate_levels(child_id);

        result.success = true;
        return result;
    }

    // Remove a child from a collection
    struct RemoveChildResult {
        bool success = false;
        std::string error;
        bool parent_not_found = false;
        bool child_not_in_collection = false;
    };

    RemoveChildResult remove_child(const std::string& parent_id,
                                    const std::string& child_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        RemoveChildResult result;

        auto parent_it = collections_.find(parent_id);
        if (parent_it == collections_.end()) {
            result.parent_not_found = true;
            result.error = "Parent collection not found: " + parent_id;
            return result;
        }

        if (parent_it->second.children.erase(child_id) == 0) {
            result.child_not_in_collection = true;
            result.error = "Child not in collection: " + child_id;
            return result;
        }

        // Update child's parent reference
        auto child_it = collections_.find(child_id);
        if (child_it != collections_.end()) {
            child_it->second.parent_id = "";
            child_it->second.level = 0;
            recalculate_levels(child_id);
        }

        result.success = true;
        return result;
    }

    // Get all children of a collection node
    std::vector<std::string> get_children(const std::string& parent_id) const {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = collections_.find(parent_id);
        if (it == collections_.end()) {
            return {};
        }

        return std::vector<std::string>(it->second.children.begin(),
                                        it->second.children.end());
    }

    // Get the parent of a node
    std::string get_parent(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = collections_.find(node_id);
        if (it != collections_.end()) {
            return it->second.parent_id;
        }
        return "";
    }

    // Get all ancestors of a node (from parent to root)
    std::vector<std::string> get_ancestors(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> ancestors;

        std::string current = node_id;
        while (true) {
            auto it = collections_.find(current);
            if (it == collections_.end() || it->second.parent_id.empty()) {
                break;
            }
            ancestors.push_back(it->second.parent_id);
            current = it->second.parent_id;
        }

        return ancestors;
    }

    // Get all descendants of a node (all nodes in its subtree)
    std::vector<std::string> get_descendants(const std::string& node_id,
                                              NodeTraversalOrder order =
                                                  NodeTraversalOrder::BREADTH_FIRST) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> descendants;

        if (order == NodeTraversalOrder::BREADTH_FIRST) {
            std::queue<std::string> queue;
            queue.push(node_id);

            while (!queue.empty()) {
                std::string current = queue.front();
                queue.pop();

                auto it = collections_.find(current);
                if (it == collections_.end()) continue;

                for (const auto& child : it->second.children) {
                    descendants.push_back(child);
                    queue.push(child);
                }
            }
        } else {
            // Depth-first
            std::stack<std::string> stack;
            stack.push(node_id);

            std::vector<std::string> order_list;
            while (!stack.empty()) {
                std::string current = stack.top();
                stack.pop();
                order_list.push_back(current);

                auto it = collections_.find(current);
                if (it == collections_.end()) continue;

                for (const auto& child : it->second.children) {
                    descendants.push_back(child);
                    stack.push(child);
                }
            }
        }

        return descendants;
    }

    // Get the root node of the hierarchy containing the given node
    std::string get_root(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string current = node_id;
        std::string root = node_id;

        while (true) {
            auto it = collections_.find(current);
            if (it == collections_.end() || it->second.parent_id.empty()) {
                root = current;
                break;
            }
            current = it->second.parent_id;
        }

        return root;
    }

    // Check if `ancestor_id` is an ancestor of `node_id`
    bool is_ancestor(const std::string& ancestor_id,
                     const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string current = node_id;
        std::set<std::string> visited;  // Cycle protection

        while (current != ancestor_id && visited.find(current) == visited.end()) {
            visited.insert(current);
            auto it = collections_.find(current);
            if (it == collections_.end() || it->second.parent_id.empty()) {
                return false;
            }
            current = it->second.parent_id;
        }

        return current == ancestor_id;
    }

    // Get the depth of a node in the hierarchy (0 = root)
    int get_level(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = collections_.find(node_id);
        if (it != collections_.end()) {
            return it->second.level;
        }
        return 0;
    }

    // Get the full hierarchy path (from root to node)
    std::vector<std::string> get_path(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);

        std::vector<std::string> path;
        std::string current = node_id;

        // Collect ancestors in reverse order
        while (true) {
            path.insert(path.begin(), current);
            auto it = collections_.find(current);
            if (it == collections_.end() || it->second.parent_id.empty()) {
                break;
            }
            current = it->second.parent_id;
        }

        return path;
    }

    // Get the path as a string (e.g., "/root/child/grandchild")
    std::string get_path_string(const std::string& node_id) const {
        auto path = get_path(node_id);
        std::ostringstream oss;
        for (const auto& segment : path) {
            oss << "/" << segment;
        }
        return oss.str();
    }

    // ========================================================================
    // Hierarchy traversal
    // ========================================================================

    // Walk the entire hierarchy calling the visitor for each node
    using NodeVisitor = std::function<void(const std::string& node_id,
                                            int level,
                                            PubSubNodeType type)>;

    void traverse_hierarchy(const std::string& start_node_id,
                             NodeVisitor visitor,
                             NodeTraversalOrder order =
                                 NodeTraversalOrder::DEPTH_FIRST) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::set<std::string> visited;

        if (order == NodeTraversalOrder::BREADTH_FIRST) {
            traverse_bfs(start_node_id, visitor, visited);
        } else if (order == NodeTraversalOrder::PRE_ORDER) {
            traverse_preorder(start_node_id, visitor, visited);
        } else if (order == NodeTraversalOrder::POST_ORDER) {
            traverse_postorder(start_node_id, visitor, visited);
        } else {
            traverse_dfs(start_node_id, visitor, visited);
        }
    }

    // Find all leaf nodes in a collection (recursively)
    std::vector<std::string> find_all_leaves(const std::string& collection_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> leaves;
        std::set<std::string> visited;
        find_leaves_recursive(collection_id, leaves, visited);
        return leaves;
    }

    // Find all collection nodes in the hierarchy
    std::vector<std::string> find_all_collections(
        const std::string& root_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> collections_list;
        std::set<std::string> visited;

        std::queue<std::string> queue;
        queue.push(root_id);
        visited.insert(root_id);

        while (!queue.empty()) {
            std::string current = queue.front();
            queue.pop();

            auto it = collections_.find(current);
            if (it == collections_.end()) continue;

            if (it->second.type == PubSubNodeType::COLLECTION) {
                collections_list.push_back(current);
            }

            for (const auto& child : it->second.children) {
                if (visited.find(child) == visited.end()) {
                    visited.insert(child);
                    queue.push(child);
                }
            }
        }

        return collections_list;
    }

    // Count all nodes in the subtree
    int count_subtree(const std::string& root_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        int count = 1;  // Include root
        std::set<std::string> visited;
        std::queue<std::string> queue;

        queue.push(root_id);
        visited.insert(root_id);

        while (!queue.empty()) {
            std::string current = queue.front();
            queue.pop();

            auto it = collections_.find(current);
            if (it == collections_.end()) continue;

            for (const auto& child : it->second.children) {
                if (visited.find(child) == visited.end()) {
                    visited.insert(child);
                    ++count;
                    queue.push(child);
                }
            }
        }

        return count;
    }

    // ========================================================================
    // Node type management
    // ========================================================================

    void set_node_type(const std::string& node_id, PubSubNodeType type) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = collections_.find(node_id);
        if (it == collections_.end()) {
            NodeHierarchyInfo info;
            info.node_id = node_id;
            info.type = type;
            collections_[node_id] = info;
        } else {
            it->second.type = type;
        }
    }

    PubSubNodeType get_node_type(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = collections_.find(node_id);
        if (it != collections_.end()) {
            return it->second.type;
        }
        return PubSubNodeType::LEAF;
    }

    // Convert a leaf to a collection (or vice versa)
    struct ConvertResult {
        bool success = false;
        std::string error;
        bool already_type = false;
    };

    ConvertResult convert_node_type(const std::string& node_id,
                                     PubSubNodeType new_type) {
        std::lock_guard<std::mutex> lock(mutex_);

        ConvertResult result;
        auto it = collections_.find(node_id);

        if (it == collections_.end()) {
            NodeHierarchyInfo info;
            info.node_id = node_id;
            info.type = new_type;
            collections_[node_id] = info;
            result.success = true;
            return result;
        }

        if (it->second.type == new_type) {
            result.already_type = true;
            result.success = true;
            return result;
        }

        // If converting from collection to leaf, children become orphaned
        if (new_type == PubSubNodeType::LEAF &&
            !it->second.children.empty()) {
            // Orphan all children
            for (const auto& child : it->second.children) {
                auto child_it = collections_.find(child);
                if (child_it != collections_.end()) {
                    child_it->second.parent_id = "";
                }
            }
            it->second.children.clear();
        }

        it->second.type = new_type;
        result.success = true;
        return result;
    }

    // ========================================================================
    // Bulk operations
    // ========================================================================

    // Move a node to a new parent
    struct MoveResult {
        bool success = false;
        std::string error;
    };

    MoveResult move_node(const std::string& node_id,
                          const std::string& new_parent_id) {
        MoveResult result;

        // Remove from current parent
        std::string current_parent = get_parent(node_id);
        if (!current_parent.empty()) {
            auto remove_result = remove_child(current_parent, node_id);
            if (!remove_result.success) {
                result.error = "Failed to remove from current parent";
                return result;
            }
        }

        // Add to new parent
        auto add_result = add_child(new_parent_id, node_id);
        result.success = add_result.success;
        result.error = add_result.error;
        return result;
    }

    // Copy a subtree to a new parent
    struct CopyResult {
        bool success = false;
        std::map<std::string, std::string> old_to_new_map;  // old_id -> new_id
        std::string error;
    };

    CopyResult copy_subtree(const std::string& root_id,
                             const std::string& new_parent_id,
                             std::function<std::string(const std::string&)> id_generator) {
        std::lock_guard<std::mutex> lock(mutex_);
        CopyResult result;

        if (!id_generator) {
            result.error = "No ID generator provided";
            return result;
        }

        // BFS copy
        std::queue<std::pair<std::string, std::string>> copy_queue;
        // pair: <original_id, copied_id>

        std::string new_root_id = id_generator(root_id);
        copy_queue.push({root_id, new_root_id});
        result.old_to_new_map[root_id] = new_root_id;

        while (!copy_queue.empty()) {
            auto [orig_id, copy_id] = copy_queue.front();
            copy_queue.pop();

            // Create the node in the hierarchy
            auto orig_it = collections_.find(orig_id);
            if (orig_it != collections_.end()) {
                NodeHierarchyInfo info;
                info.node_id = copy_id;
                info.type = orig_it->second.type;
                if (orig_id == root_id) {
                    info.parent_id = new_parent_id;
                }
                collections_[copy_id] = info;

                // Copy children
                for (const auto& child : orig_it->second.children) {
                    std::string new_child_id = id_generator(child);
                    copy_queue.push({child, new_child_id});
                    result.old_to_new_map[child] = new_child_id;
                    collections_[copy_id].children.insert(new_child_id);
                }
            }
        }

        // Link to parent
        if (!new_parent_id.empty()) {
            auto parent_it = collections_.find(new_parent_id);
            if (parent_it != collections_.end()) {
                parent_it->second.children.insert(new_root_id);
            }
        }

        // Recalculate levels from new root
        recalculate_levels(new_root_id);

        result.success = true;
        return result;
    }

    // ========================================================================
    // Hierarchy statistics
    // ========================================================================

    struct HierarchyStats {
        int total_nodes = 0;
        int total_collections = 0;
        int total_leaves = 0;
        int max_depth = 0;
        int root_nodes = 0;       // Nodes with no parent
        int orphan_nodes = 0;     // Nodes without a parent entry
        int max_children = 0;
        int total_relationships = 0;
        std::string deepest_node;
        std::string widest_node;
    };

    HierarchyStats get_hierarchy_stats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        HierarchyStats stats;

        for (const auto& [node_id, info] : collections_) {
            ++stats.total_nodes;
            stats.total_relationships += static_cast<int>(info.children.size());

            if (info.type == PubSubNodeType::COLLECTION) {
                ++stats.total_collections;
            } else {
                ++stats.total_leaves;
            }

            if (info.parent_id.empty()) {
                ++stats.root_nodes;
            }

            if (info.level > stats.max_depth) {
                stats.max_depth = info.level;
                stats.deepest_node = node_id;
            }

            int child_count = static_cast<int>(info.children.size());
            if (child_count > stats.max_children) {
                stats.max_children = child_count;
                stats.widest_node = node_id;
            }
        }

        return stats;
    }

    // ========================================================================
    // Serialization
    // ========================================================================

    // Export the entire hierarchy as XML
    std::string export_hierarchy_xml(const std::string& root_id = "") const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostringstream oss;
        oss << "<hierarchy xmlns=\"http://jabber.org/protocol/pubsub#collections\">";

        if (root_id.empty()) {
            // Export all root nodes
            for (const auto& [node_id, info] : collections_) {
                if (info.parent_id.empty()) {
                    export_node_xml(node_id, info, oss);
                }
            }
        } else {
            auto it = collections_.find(root_id);
            if (it != collections_.end()) {
                export_node_xml(root_id, it->second, oss);
            }
        }

        oss << "</hierarchy>";
        return oss.str();
    }

    // Clear all hierarchy data
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        collections_.clear();
    }

    // Remove a node from the hierarchy entirely
    bool remove_node(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = collections_.find(node_id);
        if (it == collections_.end()) return false;

        // Remove from parent
        if (!it->second.parent_id.empty()) {
            auto parent_it = collections_.find(it->second.parent_id);
            if (parent_it != collections_.end()) {
                parent_it->second.children.erase(node_id);
            }
        }

        // Orphan all children
        for (const auto& child : it->second.children) {
            auto child_it = collections_.find(child);
            if (child_it != collections_.end()) {
                child_it->second.parent_id = "";
            }
        }

        collections_.erase(it);
        return true;
    }

    // Check if a node exists in the hierarchy
    bool node_exists(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return collections_.find(node_id) != collections_.end();
    }

    size_t node_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return collections_.size();
    }

private:
    struct NodeHierarchyInfo {
        std::string node_id;
        std::string parent_id;
        PubSubNodeType type = PubSubNodeType::LEAF;
        int level = 0;
        std::set<std::string> children;
    };

    void recalculate_levels(const std::string& start_node_id) {
        std::set<std::string> visited;
        std::queue<std::string> queue;

        auto start_it = collections_.find(start_node_id);
        if (start_it == collections_.end()) return;

        queue.push(start_node_id);
        visited.insert(start_node_id);

        while (!queue.empty()) {
            std::string current = queue.front();
            queue.pop();

            auto current_it = collections_.find(current);
            if (current_it == collections_.end()) continue;

            for (const auto& child : current_it->second.children) {
                if (visited.find(child) == visited.end()) {
                    visited.insert(child);
                    auto child_it = collections_.find(child);
                    if (child_it != collections_.end()) {
                        child_it->second.level = current_it->second.level + 1;
                        child_it->second.parent_id = current;
                    }
                    queue.push(child);
                }
            }
        }
    }

    void traverse_bfs(const std::string& start_id, NodeVisitor visitor,
                       std::set<std::string>& visited) const {
        std::queue<std::string> queue;
        queue.push(start_id);
        visited.insert(start_id);

        while (!queue.empty()) {
            std::string current = queue.front();
            queue.pop();

            auto it = collections_.find(current);
            if (it == collections_.end()) {
                visitor(current, 0, PubSubNodeType::LEAF);
                continue;
            }

            visitor(current, it->second.level, it->second.type);

            for (const auto& child : it->second.children) {
                if (visited.find(child) == visited.end()) {
                    visited.insert(child);
                    queue.push(child);
                }
            }
        }
    }

    void traverse_dfs(const std::string& start_id, NodeVisitor visitor,
                       std::set<std::string>& visited) const {
        if (visited.find(start_id) != visited.end()) return;
        visited.insert(start_id);

        auto it = collections_.find(start_id);
        if (it != collections_.end()) {
            visitor(start_id, it->second.level, it->second.type);

            for (const auto& child : it->second.children) {
                traverse_dfs(child, visitor, visited);
            }
        } else {
            visitor(start_id, 0, PubSubNodeType::LEAF);
        }
    }

    void traverse_preorder(const std::string& start_id, NodeVisitor visitor,
                            std::set<std::string>& visited) const {
        if (visited.find(start_id) != visited.end()) return;
        visited.insert(start_id);

        auto it = collections_.find(start_id);
        if (it != collections_.end()) {
            visitor(start_id, it->second.level, it->second.type);

            for (const auto& child : it->second.children) {
                traverse_preorder(child, visitor, visited);
            }
        } else {
            visitor(start_id, 0, PubSubNodeType::LEAF);
        }
    }

    void traverse_postorder(const std::string& start_id, NodeVisitor visitor,
                             std::set<std::string>& visited) const {
        if (visited.find(start_id) != visited.end()) return;
        visited.insert(start_id);

        auto it = collections_.find(start_id);
        if (it != collections_.end()) {
            for (const auto& child : it->second.children) {
                traverse_postorder(child, visitor, visited);
            }

            visitor(start_id, it->second.level, it->second.type);
        } else {
            visitor(start_id, 0, PubSubNodeType::LEAF);
        }
    }

    void find_leaves_recursive(const std::string& node_id,
                                std::vector<std::string>& leaves,
                                std::set<std::string>& visited) const {
        if (visited.find(node_id) != visited.end()) return;
        visited.insert(node_id);

        auto it = collections_.find(node_id);
        if (it == collections_.end() || it->second.children.empty()) {
            leaves.push_back(node_id);
            return;
        }

        for (const auto& child : it->second.children) {
            find_leaves_recursive(child, leaves, visited);
        }
    }

    void export_node_xml(const std::string& node_id,
                          const NodeHierarchyInfo& info,
                          std::ostringstream& oss) const {
        oss << "<node id=\"" << XMLUtil::escape(node_id) << "\"";
        oss << " type=\"" << pubsub_node_type_to_string(info.type) << "\"";
        oss << " level=\"" << info.level << "\"";
        if (!info.parent_id.empty()) {
            oss << " parent=\"" << XMLUtil::escape(info.parent_id) << "\"";
        }
        oss << " children=\"" << info.children.size() << "\">";

        for (const auto& child : info.children) {
            auto child_it = collections_.find(child);
            if (child_it != collections_.end()) {
                export_node_xml(child, child_it->second, oss);
            }
        }

        oss << "</node>";
    }

    bool would_create_cycle(const std::string& start_node,
                             const std::string& potential_parent) const {
        // Check if start_node is an ancestor of potential_parent
        std::string current = potential_parent;
        std::set<std::string> visited;

        while (true) {
            if (current == start_node) return true;
            if (visited.find(current) != visited.end()) return false;  // Already visited

            visited.insert(current);
            auto it = collections_.find(current);
            if (it == collections_.end() || it->second.parent_id.empty()) {
                return false;
            }
            current = it->second.parent_id;
        }
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::string, NodeHierarchyInfo> collections_;
};

// ============================================================================
// NodeStatisticsCollector - Collects and aggregates node statistics
// ============================================================================

class NodeStatisticsCollector {
public:
    struct SnapshotStats {
        // Basic counts
        int total_nodes = 0;
        int leaf_nodes = 0;
        int collection_nodes = 0;
        int active_nodes = 0;
        int deleted_nodes = 0;
        int pep_nodes = 0;

        // Subscription stats
        int total_subscriptions = 0;
        int pending_subscriptions = 0;
        int unconfigured_subscriptions = 0;

        // Item stats
        int total_items = 0;
        int total_retracted_items = 0;
        int max_items_in_node = 0;
        std::string node_with_most_items;

        // Activity stats
        int total_publishes_today = 0;
        int total_retracts_today = 0;
        int total_subscriptions_today = 0;
        int total_unsubscriptions_today = 0;

        // Collection stats
        int total_collections = 0;
        int max_hierarchy_depth = 0;
        int total_collection_children = 0;
        int orphan_nodes = 0;

        // Performance
        double avg_items_per_node = 0.0;
        double avg_subscribers_per_node = 0.0;

        // Timestamp
        std::chrono::system_clock::time_point snapshot_time;
    };

    NodeStatisticsCollector()
        : snapshot_time_(std::chrono::system_clock::now())
        , daily_publishes_(0)
        , daily_retracts_(0)
        , daily_subscriptions_(0)
        , daily_unsubscriptions_(0)
    {}

    // Record events
    void record_publish(const std::string& node_id, const std::string& publisher) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& node_stats = node_stats_[node_id];
        ++node_stats.publish_count;
        node_stats.last_publisher = publisher;
        node_stats.last_publish_time = std::chrono::system_clock::now();
        ++daily_publishes_;

        // Track publishers
        ++publisher_stats_[publisher].publish_count;
    }

    void record_retract(const std::string& node_id, const std::string& retractor) {
        std::lock_guard<std::mutex> lock(mutex_);
        ++node_stats_[node_id].retract_count;
        ++daily_retracts_;

        ++publisher_stats_[retractor].retract_count;
    }

    void record_subscription(const std::string& node_id,
                              const std::string& subscriber) {
        std::lock_guard<std::mutex> lock(mutex_);
        ++node_stats_[node_id].subscription_count;
        ++daily_subscriptions_;
    }

    void record_unsubscription(const std::string& node_id,
                                const std::string& subscriber) {
        std::lock_guard<std::mutex> lock(mutex_);
        ++node_stats_[node_id].unsubscription_count;
        ++daily_unsubscriptions_;
    }

    void record_notification_sent(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        ++node_stats_[node_id].notifications_sent;
    }

    void record_item_count(const std::string& node_id, int count) {
        std::lock_guard<std::mutex> lock(mutex_);
        node_stats_[node_id].current_item_count = count;
        if (count > node_stats_[node_id].peak_item_count) {
            node_stats_[node_id].peak_item_count = count;
        }
    }

    void record_subscriber_count(const std::string& node_id, int count) {
        std::lock_guard<std::mutex> lock(mutex_);
        node_stats_[node_id].current_subscriber_count = count;
        if (count > node_stats_[node_id].peak_subscriber_count) {
            node_stats_[node_id].peak_subscriber_count = count;
        }
    }

    void record_node_created(const std::string& node_id, PubSubNodeType type) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& ns = node_stats_[node_id];
        ns.node_type = type;
        ns.created_at = std::chrono::system_clock::now();
    }

    void record_node_deleted(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        node_stats_[node_id].deleted_at = std::chrono::system_clock::now();
        node_stats_[node_id].is_deleted = true;
    }

    // Get per-node statistics
    struct PerNodeStats {
        std::string node_id;
        PubSubNodeType node_type = PubSubNodeType::LEAF;
        uint64_t publish_count = 0;
        uint64_t retract_count = 0;
        uint64_t subscription_count = 0;
        uint64_t unsubscription_count = 0;
        uint64_t notifications_sent = 0;
        int current_item_count = 0;
        int peak_item_count = 0;
        int current_subscriber_count = 0;
        int peak_subscriber_count = 0;
        std::string last_publisher;
        std::chrono::system_clock::time_point last_publish_time;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point deleted_at;
        bool is_deleted = false;
    };

    PerNodeStats get_node_stats(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = node_stats_.find(node_id);
        if (it != node_stats_.end()) {
            PerNodeStats stats;
            stats.node_id = node_id;
            stats.node_type = it->second.node_type;
            stats.publish_count = it->second.publish_count;
            stats.retract_count = it->second.retract_count;
            stats.subscription_count = it->second.subscription_count;
            stats.unsubscription_count = it->second.unsubscription_count;
            stats.notifications_sent = it->second.notifications_sent;
            stats.current_item_count = it->second.current_item_count;
            stats.peak_item_count = it->second.peak_item_count;
            stats.current_subscriber_count = it->second.current_subscriber_count;
            stats.peak_subscriber_count = it->second.peak_subscriber_count;
            stats.last_publisher = it->second.last_publisher;
            stats.last_publish_time = it->second.last_publish_time;
            stats.created_at = it->second.created_at;
            stats.deleted_at = it->second.deleted_at;
            stats.is_deleted = it->second.is_deleted;
            return stats;
        }
        PerNodeStats stats;
        stats.node_id = node_id;
        return stats;
    }

    // Get publisher stats
    struct PublisherStats {
        std::string jid;
        uint64_t publish_count = 0;
        uint64_t retract_count = 0;
    };

    std::vector<PublisherStats> get_top_publishers(int limit = 10) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<PublisherStats> result;

        for (const auto& [jid, stats] : publisher_stats_) {
            result.push_back({jid, stats.publish_count, stats.retract_count});
        }

        std::sort(result.begin(), result.end(),
                  [](const PublisherStats& a, const PublisherStats& b) {
                      return a.publish_count > b.publish_count;
                  });

        if (static_cast<int>(result.size()) > limit) {
            result.resize(limit);
        }
        return result;
    }

    // Get overall snapshot
    SnapshotStats take_snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        SnapshotStats snap;
        snap.snapshot_time = std::chrono::system_clock::now();

        snap.total_nodes = static_cast<int>(node_stats_.size());

        for (const auto& [node_id, stats] : node_stats_) {
            if (stats.is_deleted) {
                ++snap.deleted_nodes;
            } else {
                ++snap.active_nodes;
            }

            if (stats.node_type == PubSubNodeType::LEAF) {
                ++snap.leaf_nodes;
            } else {
                ++snap.collection_nodes;
            }

            snap.total_items += stats.current_item_count;
            snap.total_subscriptions += stats.current_subscriber_count;

            if (stats.current_item_count > snap.max_items_in_node) {
                snap.max_items_in_node = stats.current_item_count;
                snap.node_with_most_items = node_id;
            }
        }

        if (snap.total_nodes > 0) {
            snap.avg_items_per_node = static_cast<double>(snap.total_items) /
                                      snap.total_nodes;
            snap.avg_subscribers_per_node = static_cast<double>(snap.total_subscriptions) /
                                            snap.total_nodes;
        }

        snap.total_publishes_today = daily_publishes_;
        snap.total_retracts_today = daily_retracts_;
        snap.total_subscriptions_today = daily_subscriptions_;
        snap.total_unsubscriptions_today = daily_unsubscriptions_;

        return snap;
    }

    // Reset daily counters
    void reset_daily_counters() {
        std::lock_guard<std::mutex> lock(mutex_);
        daily_publishes_ = 0;
        daily_retracts_ = 0;
        daily_subscriptions_ = 0;
        daily_unsubscriptions_ = 0;
    }

    // Generate XML report
    std::string generate_stats_xml() const {
        auto snap = const_cast<NodeStatisticsCollector*>(this)->take_snapshot();
        std::ostringstream oss;

        oss << "<statistics xmlns=\"http://jabber.org/protocol/pubsub#statistics\"";
        oss << " timestamp=\"" << timestamp_iso8601(snap.snapshot_time) << "\">";

        oss << "<summary>";
        oss << "<stat name=\"total-nodes\" value=\"" << snap.total_nodes << "\"/>";
        oss << "<stat name=\"active-nodes\" value=\"" << snap.active_nodes << "\"/>";
        oss << "<stat name=\"deleted-nodes\" value=\"" << snap.deleted_nodes << "\"/>";
        oss << "<stat name=\"leaf-nodes\" value=\"" << snap.leaf_nodes << "\"/>";
        oss << "<stat name=\"collection-nodes\" value=\"" << snap.collection_nodes << "\"/>";
        oss << "<stat name=\"total-items\" value=\"" << snap.total_items << "\"/>";
        oss << "<stat name=\"total-subscriptions\" value=\"" << snap.total_subscriptions << "\"/>";
        oss << "<stat name=\"publishes-today\" value=\"" << snap.total_publishes_today << "\"/>";
        oss << "<stat name=\"retracts-today\" value=\"" << snap.total_retracts_today << "\"/>";
        oss << "<stat name=\"subscriptions-today\" value=\"" << snap.total_subscriptions_today << "\"/>";
        oss << "<stat name=\"unsubscriptions-today\" value=\"" << snap.total_unsubscriptions_today << "\"/>";
        oss << "<stat name=\"avg-items-per-node\" value=\""
            << std::fixed << std::setprecision(2) << snap.avg_items_per_node << "\"/>";
        oss << "<stat name=\"avg-subscribers-per-node\" value=\""
            << std::fixed << std::setprecision(2) << snap.avg_subscribers_per_node << "\"/>";
        oss << "</summary>";

        oss << "</statistics>";
        return oss.str();
    }

    // Generate per-node XML report
    std::string generate_per_node_stats_xml(
        const std::vector<std::string>& node_ids) const {
        std::ostringstream oss;
        oss << "<node-statistics>";

        for (const auto& node_id : node_ids) {
            auto stats = get_node_stats(node_id);
            oss << "<node-stat node=\"" << XMLUtil::escape(node_id) << "\"";
            oss << " type=\"" << pubsub_node_type_to_string(stats.node_type) << "\"";
            oss << " publish-count=\"" << stats.publish_count << "\"";
            oss << " retract-count=\"" << stats.retract_count << "\"";
            oss << " subscription-count=\"" << stats.subscription_count << "\"";
            oss << " unsubscription-count=\"" << stats.unsubscription_count << "\"";
            oss << " notifications-sent=\"" << stats.notifications_sent << "\"";
            oss << " current-items=\"" << stats.current_item_count << "\"";
            oss << " peak-items=\"" << stats.peak_item_count << "\"";
            oss << " current-subscribers=\"" << stats.current_subscriber_count << "\"";
            oss << " peak-subscribers=\"" << stats.peak_subscriber_count << "\"";
            if (!stats.last_publisher.empty()) {
                oss << " last-publisher=\"" << XMLUtil::escape(stats.last_publisher) << "\"";
            }
            oss << "/>";
        }

        oss << "</node-statistics>";
        return oss.str();
    }

    // Remove stats for a deleted node
    void remove_node_stats(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        node_stats_.erase(node_id);
    }

private:
    struct NodeStatEntry {
        PubSubNodeType node_type = PubSubNodeType::LEAF;
        uint64_t publish_count = 0;
        uint64_t retract_count = 0;
        uint64_t subscription_count = 0;
        uint64_t unsubscription_count = 0;
        uint64_t notifications_sent = 0;
        int current_item_count = 0;
        int peak_item_count = 0;
        int current_subscriber_count = 0;
        int peak_subscriber_count = 0;
        std::string last_publisher;
        std::chrono::system_clock::time_point last_publish_time;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point deleted_at;
        bool is_deleted = false;
    };

    struct PublisherStatEntry {
        uint64_t publish_count = 0;
        uint64_t retract_count = 0;
    };

    static std::string timestamp_iso8601(std::chrono::system_clock::time_point tp) {
        auto t = std::chrono::system_clock::to_time_t(tp);
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::string, NodeStatEntry> node_stats_;
    std::unordered_map<std::string, PublisherStatEntry> publisher_stats_;
    std::chrono::system_clock::time_point snapshot_time_;
    int daily_publishes_;
    int daily_retracts_;
    int daily_subscriptions_;
    int daily_unsubscriptions_;
};

// ============================================================================
// TransientNodeHandler - Management of non-persistent nodes
// ============================================================================

class TransientNodeHandler {
public:
    TransientNodeHandler() = default;

    // Mark a node as transient (non-persistent items)
    void mark_as_transient(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        transient_nodes_.insert(node_id);
        persistent_nodes_.erase(node_id);
    }

    // Mark a node as persistent (items survive restarts)
    void mark_as_persistent(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        persistent_nodes_.insert(node_id);
        transient_nodes_.erase(node_id);
    }

    // Check if a node is transient
    bool is_transient(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return transient_nodes_.find(node_id) != transient_nodes_.end();
    }

    // Check if a node is persistent
    bool is_persistent(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return persistent_nodes_.find(node_id) != persistent_nodes_.end();
    }

    // Get all transient nodes
    std::vector<std::string> get_transient_nodes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return std::vector<std::string>(transient_nodes_.begin(),
                                        transient_nodes_.end());
    }

    // Get all persistent nodes
    std::vector<std::string> get_persistent_nodes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return std::vector<std::string>(persistent_nodes_.begin(),
                                        persistent_nodes_.end());
    }

    // Clean up transient nodes (remove items that shouldn't persist)
    void handle_shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        // In a full implementation, this would purge items from transient nodes
        // Transient nodes' items are not saved between sessions
        last_cleanup_ = std::chrono::system_clock::now();
    }

    // Clear a node's designation
    void clear_designation(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        transient_nodes_.erase(node_id);
        persistent_nodes_.erase(node_id);
    }

    size_t transient_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return transient_nodes_.size();
    }

    size_t persistent_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return persistent_nodes_.size();
    }

private:
    mutable std::mutex mutex_;
    std::set<std::string> transient_nodes_;
    std::set<std::string> persistent_nodes_;
    std::chrono::system_clock::time_point last_cleanup_;
};

// ============================================================================
// ItemExpiryManager - Manages item expiration policies per node
// ============================================================================

class ItemExpiryManager {
public:
    struct ExpiryPolicy {
        ItemExpiryPolicy type = ItemExpiryPolicy::NONE;
        int64_t max_age_seconds = 0;      // For TIME_BASED
        int max_item_count = 0;           // For COUNT_BASED
        int64_t max_total_size_bytes = 0; // For SIZE_BASED
        bool enabled = false;
    };

    ItemExpiryManager() = default;

    // Set the expiry policy for a node
    void set_policy(const std::string& node_id, const ExpiryPolicy& policy) {
        std::lock_guard<std::mutex> lock(mutex_);
        policies_[node_id] = policy;
    }

    // Get the expiry policy for a node
    ExpiryPolicy get_policy(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = policies_.find(node_id);
        if (it != policies_.end()) {
            return it->second;
        }
        return ExpiryPolicy{};
    }

    // Remove the expiry policy
    void remove_policy(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        policies_.erase(node_id);
    }

    // Check if an item should be expired based on the policy
    struct ExpiryCheckResult {
        bool should_expire = false;
        std::string reason;
    };

    ExpiryCheckResult check_item(const std::string& node_id,
                                   std::chrono::system_clock::time_point item_created_at,
                                   int item_position_in_list,
                                   int64_t item_size_bytes) const {
        ExpiryCheckResult result;

        auto policy = get_policy(node_id);
        if (!policy.enabled) return result;

        auto now = std::chrono::system_clock::now();

        switch (policy.type) {
            case ItemExpiryPolicy::TIME_BASED: {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - item_created_at).count();
                if (age > policy.max_age_seconds) {
                    result.should_expire = true;
                    result.reason = "Item exceeded max age of " +
                                    std::to_string(policy.max_age_seconds) + "s";
                }
                break;
            }
            case ItemExpiryPolicy::COUNT_BASED: {
                if (item_position_in_list < 0 &&
                    -item_position_in_list >= policy.max_item_count) {
                    result.should_expire = true;
                    result.reason = "Item exceeds max count of " +
                                    std::to_string(policy.max_item_count);
                }
                break;
            }
            case ItemExpiryPolicy::SIZE_BASED: {
                if (item_size_bytes > policy.max_total_size_bytes) {
                    result.should_expire = true;
                    result.reason = "Item exceeds max size of " +
                                    std::to_string(policy.max_total_size_bytes) + " bytes";
                }
                break;
            }
            case ItemExpiryPolicy::HYBRID: {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - item_created_at).count();
                bool age_expired = policy.max_age_seconds > 0 &&
                                   age > policy.max_age_seconds;
                bool count_expired = policy.max_item_count > 0 &&
                                     item_position_in_list < 0 &&
                                     -item_position_in_list >= policy.max_item_count;
                bool size_expired = policy.max_total_size_bytes > 0 &&
                                    item_size_bytes > policy.max_total_size_bytes;

                result.should_expire = age_expired || count_expired || size_expired;
                if (result.should_expire) {
                    result.reason = "Item expired under hybrid policy";
                }
                break;
            }
            default:
                break;
        }

        return result;
    }

    // Process expired items and return which ones should be removed
    // Returns vector of item IDs to remove
    std::vector<std::string> find_expired_items(
        const std::string& node_id,
        const std::vector<std::pair<std::string, std::chrono::system_clock::time_point>>& items,
        int64_t total_size_bytes = 0) const {
        std::vector<std::string> expired;

        auto policy = get_policy(node_id);
        if (!policy.enabled || policy.type == ItemExpiryPolicy::NONE) {
            return expired;
        }

        auto now = std::chrono::system_clock::now();

        for (size_t i = 0; i < items.size(); ++i) {
            const auto& [item_id, created_at] = items[i];

            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                now - created_at).count();
            int pos_from_end = static_cast<int>(i) - static_cast<int>(items.size());
            int64_t item_size = total_size_bytes > 0
                ? total_size_bytes / static_cast<int64_t>(items.size())
                : 0;

            switch (policy.type) {
                case ItemExpiryPolicy::TIME_BASED:
                    if (policy.max_age_seconds > 0 && age > policy.max_age_seconds) {
                        expired.push_back(item_id);
                    }
                    break;
                case ItemExpiryPolicy::COUNT_BASED:
                    if (policy.max_item_count > 0 &&
                        static_cast<int>(items.size()) > policy.max_item_count &&
                        static_cast<int>(i) < static_cast<int>(items.size()) - policy.max_item_count) {
                        expired.push_back(item_id);
                    }
                    break;
                case ItemExpiryPolicy::SIZE_BASED:
                    if (policy.max_total_size_bytes > 0 &&
                        item_size > policy.max_total_size_bytes) {
                        expired.push_back(item_id);
                    }
                    break;
                case ItemExpiryPolicy::HYBRID: {
                    bool age_expired = policy.max_age_seconds > 0 &&
                                       age > policy.max_age_seconds;
                    bool count_expired = policy.max_item_count > 0 &&
                        static_cast<int>(i) < static_cast<int>(items.size()) - policy.max_item_count;
                    if (age_expired || count_expired) {
                        expired.push_back(item_id);
                    }
                    break;
                }
                default:
                    break;
            }
        }

        return expired;
    }

    // Get all nodes that have expiry policies
    std::vector<std::string> get_nodes_with_policies() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> node_ids;
        for (const auto& [id, policy] : policies_) {
            if (policy.enabled) {
                node_ids.push_back(id);
            }
        }
        return node_ids;
    }

    size_t policy_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return policies_.size();
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, ExpiryPolicy> policies_;
};

// ============================================================================
// AccessModelEnforcer - Granular access control enforcement
// ============================================================================

class AccessModelEnforcer {
public:
    struct AccessContext {
        std::string requester_jid;
        std::string node_id;
        PubSubAccessModel access_model = PubSubAccessModel::OPEN;
        PubSubAffiliation affiliation = PubSubAffiliation::NONE;
        bool has_presence_subscription = false;
        bool is_in_roster_group = false;
        bool subscription_required = false;
        bool node_is_deleted = false;
        std::string node_owner_jid;
    };

    struct AccessResult {
        bool can_subscribe = false;
        bool can_unsubscribe = false;
        bool can_publish = false;
        bool can_retract = false;
        bool can_delete = false;
        bool can_purge = false;
        bool can_configure = false;
        bool can_view_items = false;
        bool can_manage_affiliations = false;
        bool can_manage_subscriptions = false;
        bool requires_approval = false;
        std::vector<std::string> allowed_actions;
        std::vector<std::string> denied_actions;
        std::string deny_reason;
    };

    AccessModelEnforcer() = default;

    // Full access check for a given context
    AccessResult check_access(const AccessContext& ctx) {
        AccessResult result;

        // Owners have full access
        if (ctx.affiliation == PubSubAffiliation::OWNER) {
            grant_all(result);
            return result;
        }

        // Outcasts have no access
        if (ctx.affiliation == PubSubAffiliation::OUTCAST) {
            result.deny_reason = "Entity is banned (outcast affiliation)";
            return result;
        }

        // Deleted nodes are inaccessible except to owners
        if (ctx.node_is_deleted) {
            result.deny_reason = "Node has been deleted";
            return result;
        }

        switch (ctx.access_model) {
            case PubSubAccessModel::OPEN:
                check_open_access(ctx, result);
                break;
            case PubSubAccessModel::PRESENCE:
                check_presence_access(ctx, result);
                break;
            case PubSubAccessModel::ROSTER:
                check_roster_access(ctx, result);
                break;
            case PubSubAccessModel::AUTHORIZE:
                check_authorize_access(ctx, result);
                break;
            case PubSubAccessModel::WHITELIST:
                check_whitelist_access(ctx, result);
                break;
        }

        // Apply affiliation-based overrides
        apply_affiliation_overrides(ctx, result);

        // Check subscription_required flag
        if (ctx.subscription_required &&
            ctx.affiliation != PubSubAffiliation::OWNER &&
            ctx.affiliation != PubSubAffiliation::MEMBER) {
            result.can_subscribe = false;
            result.can_manage_subscriptions = false;
        }

        build_action_lists(result);
        return result;
    }

    // Quick check: can this entity subscribe?
    bool can_subscribe(const AccessContext& ctx) {
        return check_access(ctx).can_subscribe;
    }

    // Quick check: can this entity publish?
    bool can_publish(const AccessContext& ctx) {
        return check_access(ctx).can_publish;
    }

    // Quick check: can this entity configure?
    bool can_configure(const AccessContext& ctx) {
        return check_access(ctx).can_configure;
    }

    // Get a human-readable explanation of access
    std::string explain_access(const AccessContext& ctx) {
        auto result = check_access(ctx);
        std::ostringstream oss;

        oss << "Access for " << ctx.requester_jid << " on node "
            << ctx.node_id << ":" << std::endl;
        oss << "  Model: " << pubsub_access_model_to_string(ctx.access_model) << std::endl;
        oss << "  Affiliation: " << pubsub_affiliation_to_string(ctx.affiliation) << std::endl;

        if (!result.allowed_actions.empty()) {
            oss << "  Allowed: ";
            for (size_t i = 0; i < result.allowed_actions.size(); ++i) {
                if (i > 0) oss << ", ";
                oss << result.allowed_actions[i];
            }
            oss << std::endl;
        }

        if (!result.denied_actions.empty()) {
            oss << "  Denied: ";
            for (size_t i = 0; i < result.denied_actions.size(); ++i) {
                if (i > 0) oss << ", ";
                oss << result.denied_actions[i];
            }
            oss << std::endl;
        }

        if (!result.deny_reason.empty()) {
            oss << "  Reason: " << result.deny_reason << std::endl;
        }

        return oss.str();
    }

private:
    void grant_all(AccessResult& result) {
        result.can_subscribe = true;
        result.can_unsubscribe = true;
        result.can_publish = true;
        result.can_retract = true;
        result.can_delete = true;
        result.can_purge = true;
        result.can_configure = true;
        result.can_view_items = true;
        result.can_manage_affiliations = true;
        result.can_manage_subscriptions = true;
    }

    void check_open_access(const AccessContext& ctx, AccessResult& result) {
        result.can_subscribe = true;
        result.can_unsubscribe = true;
        result.can_publish = true;
        result.can_retract = true;
        result.can_view_items = true;
    }

    void check_presence_access(const AccessContext& ctx, AccessResult& result) {
        if (ctx.has_presence_subscription) {
            result.can_subscribe = true;
            result.can_publish = true;
            result.can_view_items = true;
        } else {
            result.deny_reason = "Presence subscription required";
        }
    }

    void check_roster_access(const AccessContext& ctx, AccessResult& result) {
        if (ctx.is_in_roster_group) {
            result.can_subscribe = true;
            result.can_view_items = true;
        } else {
            result.deny_reason = "Not in roster group";
        }
    }

    void check_authorize_access(const AccessContext& ctx, AccessResult& result) {
        result.requires_approval = true;
        result.can_unsubscribe = true;
        result.can_view_items = true;  // Can request but needs approval
    }

    void check_whitelist_access(const AccessContext& ctx, AccessResult& result) {
        result.deny_reason = "Not on whitelist";
    }

    void apply_affiliation_overrides(const AccessContext& ctx,
                                      AccessResult& result) {
        switch (ctx.affiliation) {
            case PubSubAffiliation::PUBLISHER:
                result.can_publish = true;
                result.can_retract = true;  // Can retract own items
                result.can_subscribe = true;
                result.can_view_items = true;
                break;

            case PubSubAffiliation::PUBLISHER_ONLY:
                result.can_publish = true;
                result.can_retract = true;  // Can retract own items
                result.can_subscribe = false;
                result.can_view_items = true;
                break;

            case PubSubAffiliation::MEMBER:
                result.can_subscribe = true;
                result.can_view_items = true;
                break;

            case PubSubAffiliation::NONE:
            case PubSubAffiliation::OUTCAST:
                // Already handled
                break;

            case PubSubAffiliation::OWNER:
                grant_all(result);
                break;
        }
    }

    void build_action_lists(AccessResult& result) {
        if (result.can_subscribe) result.allowed_actions.push_back("subscribe");
        else result.denied_actions.push_back("subscribe");

        if (result.can_unsubscribe) result.allowed_actions.push_back("unsubscribe");
        else result.denied_actions.push_back("unsubscribe");

        if (result.can_publish) result.allowed_actions.push_back("publish");
        else result.denied_actions.push_back("publish");

        if (result.can_retract) result.allowed_actions.push_back("retract");
        else result.denied_actions.push_back("retract");

        if (result.can_delete) result.allowed_actions.push_back("delete");
        else result.denied_actions.push_back("delete");

        if (result.can_purge) result.allowed_actions.push_back("purge");
        else result.denied_actions.push_back("purge");

        if (result.can_configure) result.allowed_actions.push_back("configure");
        else result.denied_actions.push_back("configure");

        if (result.can_view_items) result.allowed_actions.push_back("view_items");
        else result.denied_actions.push_back("view_items");

        if (result.can_manage_affiliations) result.allowed_actions.push_back("manage_affiliations");
        else result.denied_actions.push_back("manage_affiliations");

        if (result.can_manage_subscriptions) result.allowed_actions.push_back("manage_subscriptions");
        else result.denied_actions.push_back("manage_subscriptions");
    }
};

// ============================================================================
// NotificationBatcher - Batches notifications for efficiency
// ============================================================================

class NotificationBatcher {
public:
    using SendCallback = std::function<void(const std::string& stanza_xml)>;

    struct BatchConfig {
        NotificationBatchingMode mode = NotificationBatchingMode::NONE;
        int max_batch_size = 10;
        int batch_window_ms = 500;  // Max time to wait before flushing
        int max_queued_notifications = 1000;
    };

    NotificationBatcher(SendCallback send_cb)
        : send_callback_(send_cb)
        , enabled_(false)
    {}

    void set_config(const BatchConfig& config) {
        std::lock_guard<std::mutex> lock(mutex_);
        config_ = config;
        enabled_ = (config.mode != NotificationBatchingMode::NONE);
    }

    // Queue a notification for delivery
    void queue_notification(const std::string& subscriber_jid,
                             const std::string& notification_xml) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!enabled_ || config_.mode == NotificationBatchingMode::NONE) {
            // Send immediately
            if (send_callback_) {
                send_callback_(notification_xml);
            }
            return;
        }

        switch (config_.mode) {
            case NotificationBatchingMode::PER_SUBSCRIBER:
                queue_for_subscriber(subscriber_jid, notification_xml);
                break;
            case NotificationBatchingMode::PER_NODE:
                queue_for_node(subscriber_jid, notification_xml);
                break;
            case NotificationBatchingMode::GLOBAL_BATCH:
                queue_global(notification_xml);
                break;
            default:
                break;
        }

        // Check if we should flush
        check_flush_conditions();
    }

    // Flush all pending notifications
    void flush_all() {
        std::lock_guard<std::mutex> lock(mutex_);

        for (auto& [subscriber, queue] : subscriber_batches_) {
            if (!queue.empty()) {
                send_batch_for_subscriber(subscriber, queue);
                queue.clear();
            }
        }

        if (!global_batch_.empty()) {
            send_global_batch();
            global_batch_.clear();
        }
    }

    // Flush notifications for a specific subscriber
    void flush_subscriber(const std::string& subscriber_jid) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = subscriber_batches_.find(subscriber_jid);
        if (it != subscriber_batches_.end() && !it->second.empty()) {
            send_batch_for_subscriber(subscriber_jid, it->second);
            it->second.clear();
        }
    }

    // Get queue sizes
    struct QueueStats {
        int subscriber_queues = 0;
        int total_queued_notifications = 0;
        int global_queue_size = 0;
    };

    QueueStats get_queue_stats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        QueueStats stats;
        stats.subscriber_queues = static_cast<int>(subscriber_batches_.size());
        for (const auto& [sub, queue] : subscriber_batches_) {
            stats.total_queued_notifications += static_cast<int>(queue.size());
        }
        stats.global_queue_size = static_cast<int>(global_batch_.size());
        return stats;
    }

    void set_enabled(bool e) {
        std::lock_guard<std::mutex> lock(mutex_);
        enabled_ = e;
    }

    bool is_enabled() const { return enabled_; }

private:
    void queue_for_subscriber(const std::string& subscriber_jid,
                               const std::string& notification_xml) {
        auto& queue = subscriber_batches_[subscriber_jid];

        if (static_cast<int>(queue.size()) >= config_.max_queued_notifications) {
            // Queue full, flush first
            send_batch_for_subscriber(subscriber_jid, queue);
            queue.clear();
        }

        queue.push_back(notification_xml);

        if (static_cast<int>(queue.size()) >= config_.max_batch_size) {
            send_batch_for_subscriber(subscriber_jid, queue);
            queue.clear();
        }
    }

    void queue_for_node(const std::string& subscriber_jid,
                         const std::string& notification_xml) {
        // Extract node from notification and batch per node
        std::string node_id = extract_node_from_notification(notification_xml);
        std::string key = node_id.empty() ? subscriber_jid : node_id;

        auto& queue = node_batches_[key];

        if (static_cast<int>(queue.size()) >= config_.max_queued_notifications) {
            send_node_batch(key, queue);
            queue.clear();
        }

        queue.push_back(notification_xml);

        if (static_cast<int>(queue.size()) >= config_.max_batch_size) {
            send_node_batch(key, queue);
            queue.clear();
        }
    }

    void queue_global(const std::string& notification_xml) {
        if (static_cast<int>(global_batch_.size()) >= config_.max_queued_notifications) {
            send_global_batch();
            global_batch_.clear();
        }

        global_batch_.push_back(notification_xml);

        if (static_cast<int>(global_batch_.size()) >= config_.max_batch_size) {
            send_global_batch();
            global_batch_.clear();
        }
    }

    void send_batch_for_subscriber(const std::string& subscriber_jid,
                                     const std::vector<std::string>& notifications) {
        if (!send_callback_ || notifications.empty()) return;

        // For simplicity, send each notification separately but with batching wrapper
        // In a full implementation, this could combine multiple items into one message
        for (const auto& notification : notifications) {
            send_callback_(notification);
        }
    }

    void send_node_batch(const std::string& node_id,
                           const std::vector<std::string>& notifications) {
        if (!send_callback_ || notifications.empty()) return;

        for (const auto& notification : notifications) {
            send_callback_(notification);
        }
    }

    void send_global_batch() {
        if (!send_callback_ || global_batch_.empty()) return;

        for (const auto& notification : global_batch_) {
            send_callback_(notification);
        }
    }

    void check_flush_conditions() {
        // Time-based flush would be handled by an external timer
        // This is a simplified version
    }

    static std::string extract_node_from_notification(const std::string& xml) {
        size_t pos = xml.find("node=\"");
        if (pos == std::string::npos) return "";
        pos += 6;
        size_t end = xml.find('"', pos);
        if (end == std::string::npos) return "";
        return xml.substr(pos, end - pos);
    }

    SendCallback send_callback_;
    bool enabled_;
    BatchConfig config_;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::vector<std::string>> subscriber_batches_;
    std::unordered_map<std::string, std::vector<std::string>> node_batches_;
    std::vector<std::string> global_batch_;
};

// ============================================================================
// SubscriptionOptionManager - Per-node subscription options management
// ============================================================================

class SubscriptionOptionManager {
public:
    SubscriptionOptionManager() = default;

    // Set subscription options for a specific subscriber on a node
    void set_options(const std::string& node_id,
                     const std::string& subscriber_jid,
                     const SubscriptionOptions& options) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(node_id, subscriber_jid);
        options_[key] = options;
    }

    // Get subscription options for a specific subscriber on a node
    SubscriptionOptions get_options(const std::string& node_id,
                                     const std::string& subscriber_jid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(node_id, subscriber_jid);
        auto it = options_.find(key);
        if (it != options_.end()) {
            return it->second;
        }
        return SubscriptionOptions();  // Default options
    }

    // Remove subscription options
    void remove_options(const std::string& node_id,
                        const std::string& subscriber_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(node_id, subscriber_jid);
        options_.erase(key);
    }

    // Get all subscribers with custom options on a node
    std::vector<std::string> get_subscribers_with_options(
        const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> subscribers;
        std::string prefix = node_id + "|";

        for (const auto& [key, options] : options_) {
            if (key.find(prefix) == 0) {
                subscribers.push_back(key.substr(prefix.size()));
            }
        }
        return subscribers;
    }

    // Apply subscription option changes from a form
    bool apply_form(const std::string& node_id,
                    const std::string& subscriber_jid,
                    const std::map<std::string, std::vector<std::string>>& fields) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(node_id, subscriber_jid);

        auto it = options_.find(key);
        if (it == options_.end()) {
            SubscriptionOptions opts;
            opts.apply_form_fields(fields);
            options_[key] = opts;
        } else {
            it->second.apply_form_fields(fields);
        }

        return true;
    }

    // Generate options form for a subscriber
    std::string generate_options_form(const std::string& node_id,
                                       const std::string& subscriber_jid) const {
        auto opts = get_options(node_id, subscriber_jid);
        return opts.to_options_form_xml();
    }

    // Check if a subscriber should receive a notification based on their options
    bool should_deliver_notification(const std::string& node_id,
                                      const std::string& subscriber_jid,
                                      EventFilterType event_type) const {
        auto opts = get_options(node_id, subscriber_jid);

        switch (event_type) {
            case EventFilterType::ITEMS_PUBLISH:
                return opts.notify_on_publish() && opts.deliver_notifications();
            case EventFilterType::ITEMS_RETRACT:
                return opts.notify_on_retract() && opts.deliver_notifications();
            case EventFilterType::NODE_DELETE:
                return opts.notify_on_delete() && opts.deliver_notifications();
            case EventFilterType::NODE_PURGE:
                return opts.notify_on_purge() && opts.deliver_notifications();
            case EventFilterType::NODE_CONFIG:
                return opts.notify_on_config() && opts.deliver_notifications();
            default:
                return opts.deliver_notifications();
        }
    }

    size_t options_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return options_.size();
    }

private:
    static std::string make_key(const std::string& node_id,
                                const std::string& subscriber_jid) {
        return node_id + "|" + subscriber_jid;
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::string, SubscriptionOptions> options_;
};

// ============================================================================
// PubSubAdvancedService - Orchestrator tying all advanced features together
// ============================================================================

class PubSubAdvancedService {
public:
    using SendCallback = std::function<void(const std::string& stanza_xml)>;
    using Logger = std::function<void(const std::string& level, const std::string& msg)>;

    PubSubAdvancedService(const std::string& service_jid,
                           SendCallback send_cb)
        : service_jid_(service_jid)
        , send_callback_(send_cb)
        , collection_manager_()
        , pending_manager_(service_jid, send_cb)
        , state_notifier_(service_jid, send_cb)
        , filter_engine_()
        , stats_collector_()
        , transient_handler_()
        , expiry_manager_()
        , access_enforcer_()
        , batcher_(send_cb)
        , subscription_options_()
        , logging_enabled_(true)
    {}

    // ========================================================================
    // Accessors to subsystems
    // ========================================================================

    CollectionNodeManager& collections() { return collection_manager_; }
    const CollectionNodeManager& collections() const { return collection_manager_; }

    PendingSubscriptionManager& pending() { return pending_manager_; }
    const PendingSubscriptionManager& pending() const { return pending_manager_; }

    SubscriptionStateNotifier& notifier() { return state_notifier_; }

    EventFilterEngine& filters() { return filter_engine_; }
    const EventFilterEngine& filters() const { return filter_engine_; }

    NodeStatisticsCollector& stats() { return stats_collector_; }
    const NodeStatisticsCollector& stats() const { return stats_collector_; }

    TransientNodeHandler& transient() { return transient_handler_; }

    ItemExpiryManager& expiry() { return expiry_manager_; }
    const ItemExpiryManager& expiry() const { return expiry_manager_; }

    AccessModelEnforcer& access() { return access_enforcer_; }

    NotificationBatcher& batcher() { return batcher_; }
    const NotificationBatcher& batcher() const { return batcher_; }

    SubscriptionOptionManager& sub_options() { return subscription_options_; }
    const SubscriptionOptionManager& sub_options() const { return subscription_options_; }

    // ========================================================================
    // Convenience compound operations
    // ========================================================================

    // Full subscription workflow with pending management
    struct SubscribeResult {
        bool success = false;
        PubSubSubscriptionState result_state = PubSubSubscriptionState::NONE;
        std::string subscription_id;
        std::string error;
        bool is_pending = false;
    };

    SubscribeResult subscribe_with_approval(
        const std::string& node_id,
        const std::string& subscriber_jid,
        PubSubAccessModel access_model,
        PubSubAffiliation affiliation,
        const SubscriptionOptions& options = SubscriptionOptions()) {

        SubscribeResult result;
        result.subscription_id = XMLUtil::generate_uuid();

        // Check access
        AccessModelEnforcer::AccessContext ctx;
        ctx.requester_jid = subscriber_jid;
        ctx.node_id = node_id;
        ctx.access_model = access_model;
        ctx.affiliation = affiliation;

        auto access_result = access_enforcer_.check_access(ctx);

        if (!access_result.can_subscribe) {
            result.error = access_result.deny_reason;
            return result;
        }

        // Handle authorize model
        if (access_result.requires_approval || access_model == PubSubAccessModel::AUTHORIZE) {
            // Add to pending
            pending_manager_.add_pending(node_id, subscriber_jid, result.subscription_id);

            // Store options
            subscription_options_.set_options(node_id, subscriber_jid, options);

            // Notify
            state_notifier_.notify_subscription_change(
                node_id, subscriber_jid,
                PubSubSubscriptionState::NONE,
                PubSubSubscriptionState::PENDING,
                result.subscription_id);

            result.result_state = PubSubSubscriptionState::PENDING;
            result.is_pending = true;
            result.success = true;

            // Record stats
            stats_collector_.record_subscription(node_id, subscriber_jid);

            return result;
        }

        // Direct subscription
        result.result_state = PubSubSubscriptionState::SUBSCRIBED;

        // Store options
        subscription_options_.set_options(node_id, subscriber_jid, options);

        // Notify
        state_notifier_.notify_subscription_change(
            node_id, subscriber_jid,
            PubSubSubscriptionState::NONE,
            PubSubSubscriptionState::SUBSCRIBED,
            result.subscription_id);

        // Record stats
        stats_collector_.record_subscription(node_id, subscriber_jid);

        result.success = true;
        return result;
    }

    // Approve a pending subscription and activate it
    bool approve_pending_subscription(const std::string& node_id,
                                       const std::string& subscriber_jid,
                                       const std::string& approver_jid) {
        auto pending_opt = pending_manager_.get_pending(node_id, subscriber_jid);
        if (!pending_opt.has_value()) {
            log_warn("No pending subscription to approve for " +
                     subscriber_jid + " on " + node_id);
            return false;
        }

        bool approved = pending_manager_.approve(node_id, subscriber_jid, approver_jid);
        if (approved) {
            state_notifier_.notify_approval(
                node_id, subscriber_jid, pending_opt->subscription_id());
        }

        return approved;
    }

    // Reject a pending subscription
    bool reject_pending_subscription(const std::string& node_id,
                                      const std::string& subscriber_jid,
                                      const std::string& rejecter_jid,
                                      const std::string& reason = "") {
        bool rejected = pending_manager_.reject(
            node_id, subscriber_jid, rejecter_jid, reason);
        if (rejected) {
            state_notifier_.notify_rejection(node_id, subscriber_jid, reason);
        }
        return rejected;
    }

    // Record a publish event with full statistics
    void record_publish_event(const std::string& node_id,
                               const std::string& publisher_jid,
                               const std::string& item_id,
                               int new_item_count) {
        stats_collector_.record_publish(node_id, publisher_jid);
        stats_collector_.record_item_count(node_id, new_item_count);
    }

    // Record a retract event
    void record_retract_event(const std::string& node_id,
                               const std::string& retractor_jid) {
        stats_collector_.record_retract(node_id, retractor_jid);
    }

    // Record subscriber count change
    void record_subscriber_change(const std::string& node_id,
                                   int new_count) {
        stats_collector_.record_subscriber_count(node_id, new_count);
    }

    // Get detailed statistics report
    std::string get_statistics_report() const {
        std::ostringstream oss;

        // Service-level stats
        oss << stats_collector_.generate_stats_xml();

        // Pending subscription stats
        oss << "<pending-subscriptions count=\""
            << pending_manager_.pending_count() << "\"/>";

        // Filter rule stats
        oss << "<filter-rules count=\""
            << filter_engine_.total_rule_count() << "\"/>";

        // Transient node stats
        oss << "<transient-nodes count=\""
            << transient_handler_.transient_count() << "\"/>";

        // Subscription options stats
        oss << "<subscription-options count=\""
            << subscription_options_.options_count() << "\"/>";

        // Expiry policies
        oss << "<expiry-policies count=\""
            << expiry_manager_.policy_count() << "\"/>";

        // Hierarchy stats
        auto hierarchy_stats = collection_manager_.get_hierarchy_stats();
        oss << "<hierarchy-stats";
        oss << " total-nodes=\"" << hierarchy_stats.total_nodes << "\"";
        oss << " collections=\"" << hierarchy_stats.total_collections << "\"";
        oss << " leaves=\"" << hierarchy_stats.total_leaves << "\"";
        oss << " max-depth=\"" << hierarchy_stats.max_depth << "\"";
        oss << " root-nodes=\"" << hierarchy_stats.root_nodes << "\"";
        oss << " max-children=\"" << hierarchy_stats.max_children << "\"";
        oss << "/>";

        return oss.str();
    }

    // Periodic maintenance
    void perform_maintenance() {
        // Process auto-approvals
        int approved = pending_manager_.process_auto_approvals();
        if (approved > 0) {
            log_info("Auto-approved " + std::to_string(approved) +
                     " pending subscriptions");
        }

        // Flush notification batches
        batcher_.flush_all();

        // Reset daily stats counters
        stats_collector_.reset_daily_counters();
    }

    // ========================================================================
    // Logging
    // ========================================================================

    void set_logger(Logger logger) {
        logger_ = logger;
        pending_manager_.set_logger(logger);
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

private:
    std::string service_jid_;
    SendCallback send_callback_;

    CollectionNodeManager collection_manager_;
    PendingSubscriptionManager pending_manager_;
    SubscriptionStateNotifier state_notifier_;
    EventFilterEngine filter_engine_;
    NodeStatisticsCollector stats_collector_;
    TransientNodeHandler transient_handler_;
    ItemExpiryManager expiry_manager_;
    AccessModelEnforcer access_enforcer_;
    NotificationBatcher batcher_;
    SubscriptionOptionManager subscription_options_;

    Logger logger_;
    bool logging_enabled_;
};

// ============================================================================
// Utility: PubSubNodeSerializer - Serialize node data for persistence
// ============================================================================

class PubSubNodeSerializer {
public:
    struct SerializedNode {
        std::string node_id;
        PubSubNodeType type;
        PubSubAccessModel access_model;
        std::string creator_jid;
        std::string parent_collection_id;
        std::vector<std::string> child_ids;
        std::map<std::string, PubSubAffiliation> affiliations;
        std::map<std::string, PubSubSubscriptionState> subscriptions;
        std::string config_xml;
        std::string metadata_xml;
        std::string statistics_xml;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point last_modified;
    };

    PubSubNodeSerializer() = default;

    // Serialize a node to a string (JSON-like format)
    std::string serialize(const SerializedNode& node) const {
        std::ostringstream oss;
        oss << "{";
        oss << "\"node_id\":\"" << XMLUtil::escape(node.node_id) << "\",";
        oss << "\"type\":\"" << pubsub_node_type_to_string(node.type) << "\",";
        oss << "\"access_model\":\"" << pubsub_access_model_to_string(node.access_model) << "\",";
        oss << "\"creator\":\"" << XMLUtil::escape(node.creator_jid) << "\",";
        oss << "\"parent\":\"" << XMLUtil::escape(node.parent_collection_id) << "\",";
        oss << "\"created_at\":\"" << XMLUtil::timestamp_iso8601() << "\",";

        // Children
        oss << "\"children\":[";
        for (size_t i = 0; i < node.child_ids.size(); ++i) {
            if (i > 0) oss << ",";
            oss << "\"" << XMLUtil::escape(node.child_ids[i]) << "\"";
        }
        oss << "],";

        // Affiliations
        oss << "\"affiliations\":[";
        bool first = true;
        for (const auto& [jid, aff] : node.affiliations) {
            if (!first) oss << ",";
            first = false;
            oss << "{\"jid\":\"" << XMLUtil::escape(jid) << "\",";
            oss << "\"affiliation\":\"" << pubsub_affiliation_to_string(aff) << "\"}";
        }
        oss << "],";

        // Subscriptions
        oss << "\"subscriptions\":[";
        first = true;
        for (const auto& [jid, state] : node.subscriptions) {
            if (!first) oss << ",";
            first = false;
            oss << "{\"jid\":\"" << XMLUtil::escape(jid) << "\",";
            oss << "\"state\":\"" << pubsub_subscription_state_to_string(state) << "\"}";
        }
        oss << "],";

        oss << "\"config\":\"" << XMLUtil::escape(node.config_xml) << "\",";
        oss << "\"metadata\":\"" << XMLUtil::escape(node.metadata_xml) << "\"";
        oss << "}";
        return oss.str();
    }

    // Serialize XML for the pubsub#owner export
    std::string serialize_to_pubsub_xml(const SerializedNode& node) const {
        std::ostringstream oss;
        oss << "<node id=\"" << XMLUtil::escape(node.node_id) << "\"";
        oss << " type=\"" << pubsub_node_type_to_string(node.type) << "\"";
        oss << " access_model=\"" << pubsub_access_model_to_string(node.access_model) << "\"";
        oss << " creator=\"" << XMLUtil::escape(node.creator_jid) << "\"";
        if (!node.parent_collection_id.empty()) {
            oss << " collection=\"" << XMLUtil::escape(node.parent_collection_id) << "\"";
        }
        oss << ">";

        // Children
        for (const auto& child : node.child_ids) {
            oss << "<child id=\"" << XMLUtil::escape(child) << "\"/>";
        }

        // Affiliations
        for (const auto& [jid, aff] : node.affiliations) {
            oss << "<affiliation jid=\"" << XMLUtil::escape(jid) << "\"";
            oss << " affiliation=\"" << pubsub_affiliation_to_string(aff) << "\"/>";
        }

        // Subscriptions
        for (const auto& [jid, state] : node.subscriptions) {
            oss << "<subscription jid=\"" << XMLUtil::escape(jid) << "\"";
            oss << " subscription=\"" << pubsub_subscription_state_to_string(state) << "\"/>";
        }

        oss << "</node>";
        return oss.str();
    }
};

// ============================================================================
// Utility: SubscriptionDigestBuilder - Builds subscription digest messages
// ============================================================================

class SubscriptionDigestBuilder {
public:
    struct DigestItem {
        std::string node_id;
        std::string item_id;
        std::string publisher_jid;
        std::string payload;
        std::chrono::system_clock::time_point timestamp;
        bool is_retraction = false;
    };

    SubscriptionDigestBuilder() = default;

    // Add an item to the digest
    void add_item(const DigestItem& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        digests_[item.node_id].push_back(item);
    }

    // Build a digest message for a specific node
    std::string build_digest_message(const std::string& node_id,
                                      const std::string& from_jid,
                                      const std::string& to_jid,
                                      int max_items = 0) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = digests_.find(node_id);
        if (it == digests_.end() || it->second.empty()) {
            return "";
        }

        std::ostringstream oss;
        oss << "<message from=\"" << XMLUtil::escape(from_jid) << "\"";
        oss << " to=\"" << XMLUtil::escape(to_jid) << "\">";
        oss << "<event xmlns=\"http://jabber.org/protocol/pubsub#event\">";
        oss << "<items node=\"" << XMLUtil::escape(node_id) << "\">";

        int count = 0;
        for (const auto& item : it->second) {
            if (max_items > 0 && count >= max_items) break;

            if (item.is_retraction) {
                oss << "<retract id=\"" << XMLUtil::escape(item.item_id) << "\"/>";
            } else {
                oss << "<item";
                if (!item.item_id.empty()) {
                    oss << " id=\"" << XMLUtil::escape(item.item_id) << "\"";
                }
                if (!item.publisher_jid.empty()) {
                    oss << " publisher=\"" << XMLUtil::escape(item.publisher_jid) << "\"";
                }
                oss << ">";
                if (!item.payload.empty()) {
                    oss << item.payload;
                }
                oss << "</item>";
            }
            ++count;
        }

        oss << "</items></event></message>";

        // Clear the digest after building
        it->second.clear();

        return oss.str();
    }

    // Count items in a digest
    int digest_item_count(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = digests_.find(node_id);
        if (it != digests_.end()) {
            return static_cast<int>(it->second.size());
        }
        return 0;
    }

    // Clear a digest
    void clear_digest(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = digests_.find(node_id);
        if (it != digests_.end()) {
            it->second.clear();
        }
    }

    // Clear all digests
    void clear_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        digests_.clear();
    }

    // Check if any digests are pending
    bool has_pending_digest(const std::string& node_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = digests_.find(node_id);
        return it != digests_.end() && !it->second.empty();
    }

    // Get the number of nodes with pending digests
    int pending_digest_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        int count = 0;
        for (const auto& [node_id, items] : digests_) {
            if (!items.empty()) ++count;
        }
        return count;
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::vector<DigestItem>> digests_;
};

// ============================================================================
// Utility: PubSubPresenceHandler - Handles presence-based pubsub features
// ============================================================================

class PubSubPresenceHandler {
public:
    using SendCallback = std::function<void(const std::string& stanza_xml)>;

    PubSubPresenceHandler(const std::string& service_jid,
                           SendCallback send_cb)
        : service_jid_(service_jid)
        , send_callback_(send_cb)
    {}

    // Handle a user coming online
    struct PresenceResult {
        std::vector<std::string> nodes_to_notify;
        bool should_send_last_published = true;
        bool should_auto_subscribe_contacts = true;
    };

    PresenceResult handle_presence_available(
        const std::string& user_jid,
        const std::vector<std::string>& subscribed_nodes,
        const std::vector<std::string>& contact_jids) {

        PresenceResult result;

        // Determine which nodes have send-last-published-item configured
        for (const auto& node_id : subscribed_nodes) {
            result.nodes_to_notify.push_back(node_id);
        }

        return result;
    }

    // Handle a user going offline
    void handle_presence_unavailable(const std::string& user_jid) {
        // In a full implementation:
        // - Cancel transient presence-based subscriptions
        // - Update presence state for access checks
        std::lock_guard<std::mutex> lock(mutex_);
        online_users_.erase(XMLUtil::bare_jid(user_jid));
    }

    // Check if a user is online
    bool is_user_online(const std::string& bare_jid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return online_users_.find(bare_jid) != online_users_.end();
    }

    // Get all online users
    std::vector<std::string> get_online_users() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return std::vector<std::string>(online_users_.begin(),
                                        online_users_.end());
    }

private:
    std::string service_jid_;
    SendCallback send_callback_;
    mutable std::mutex mutex_;
    std::set<std::string> online_users_;
};

// ============================================================================
// Final: PubSubAdvancedManager - Top-level integration class
// ============================================================================

class PubSubAdvancedManager {
public:
    using SendCallback = std::function<void(const std::string& stanza_xml)>;
    using Logger = std::function<void(const std::string& level, const std::string& msg)>;

    PubSubAdvancedManager(const std::string& service_jid,
                           SendCallback send_cb)
        : service_jid_(service_jid)
        , send_callback_(send_cb)
        , advanced_service_(service_jid, send_cb)
        , serializer_()
        , digest_builder_()
        , presence_handler_(service_jid, send_cb)
        , logging_enabled_(true)
    {
        log_info("PubSubAdvancedManager initialized for: " + service_jid);
    }

    // ========================================================================
    // Access to subsystems
    // ========================================================================

    PubSubAdvancedService& advanced() { return advanced_service_; }
    const PubSubAdvancedService& advanced() const { return advanced_service_; }

    PubSubNodeSerializer& serializer() { return serializer_; }

    SubscriptionDigestBuilder& digest() { return digest_builder_; }

    PubSubPresenceHandler& presence() { return presence_handler_; }

    // ========================================================================
    // High-level service management
    // ========================================================================

    void shutdown() {
        log_info("PubSubAdvancedManager shutting down...");
        advanced_service_.batcher().flush_all();
        log_info("PubSubAdvancedManager shut down complete");
    }

    // Periodic maintenance tick
    void maintenance_tick() {
        advanced_service_.perform_maintenance();
    }

    // ========================================================================
    // Convenience: get a full status overview
    // ========================================================================

    std::string get_status_overview() const {
        std::ostringstream oss;

        oss << "=== PubSub Advanced Service Status ===" << std::endl;
        oss << "Service JID: " << service_jid_ << std::endl;

        // Collection hierarchy
        auto hierarchy_stats = advanced_service_.collections().get_hierarchy_stats();
        oss << "Hierarchy: " << hierarchy_stats.total_nodes << " nodes, "
            << hierarchy_stats.total_collections << " collections, "
            << hierarchy_stats.total_leaves << " leaves, "
            << "max depth: " << hierarchy_stats.max_depth << std::endl;

        // Pending subscriptions
        oss << "Pending subscriptions: " << advanced_service_.pending().pending_count() << std::endl;

        // Filter rules
        oss << "Filter rules: " << advanced_service_.filters().total_rule_count() << std::endl;

        // Subscription options
        oss << "Custom subscription options: " << advanced_service_.sub_options().options_count() << std::endl;

        // Expiry policies
        oss << "Expiry policies: " << advanced_service_.expiry().policy_count() << std::endl;

        // Notification batcher
        auto batch_stats = advanced_service_.batcher().get_queue_stats();
        oss << "Notification batches: " << batch_stats.subscriber_queues << " queues, "
            << batch_stats.total_queued_notifications << " queued" << std::endl;

        // Statistics
        auto snap = advanced_service_.stats().take_snapshot();
        oss << "Total nodes: " << snap.total_nodes
            << " (active: " << snap.active_nodes
            << ", deleted: " << snap.deleted_nodes << ")" << std::endl;
        oss << "Total items: " << snap.total_items
            << " (avg: " << std::fixed << std::setprecision(1)
            << snap.avg_items_per_node << "/node)" << std::endl;
        oss << "Total subscriptions: " << snap.total_subscriptions
            << " (avg: " << std::fixed << std::setprecision(1)
            << snap.avg_subscribers_per_node << "/node)" << std::endl;
        oss << "Today: " << snap.total_publishes_today << " publishes, "
            << snap.total_subscriptions_today << " subscriptions" << std::endl;

        return oss.str();
    }

    // ========================================================================
    // Logging
    // ========================================================================

    void set_logger(Logger logger) {
        logger_ = logger;
        advanced_service_.set_logger(logger);
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

private:
    std::string service_jid_;
    SendCallback send_callback_;

    PubSubAdvancedService advanced_service_;
    PubSubNodeSerializer serializer_;
    SubscriptionDigestBuilder digest_builder_;
    PubSubPresenceHandler presence_handler_;

    Logger logger_;
    bool logging_enabled_;
};

// ============================================================================
// End namespace
// ============================================================================

}  // namespace xmpp
}  // namespace progressive
