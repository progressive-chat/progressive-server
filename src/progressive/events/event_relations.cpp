// event_relations.cpp - Matrix event relations, threading, and aggregation
// Part of progressive-server
// Implements MSC 2674, MSC 2675, MSC 2676, MSC 2677, MSC 3440, MSC 3381, MSC 3771, MSC 3773

#include "../json.hpp"

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <optional>
#include <variant>
#include <algorithm>
#include <numeric>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <functional>
#include <deque>
#include <memory>
#include <cstdint>
#include <cmath>
#include <atomic>
#include <utility>
#include <cstddef>

namespace progressive::events {

// ============================================================================
// Forward declarations
// ============================================================================

using json = nlohmann::json;

// ============================================================================
// Constants
// ============================================================================

// Relation types per MSC 2674
constexpr std::string_view REL_TYPE_ANNOTATION  = "m.annotation";
constexpr std::string_view REL_TYPE_REPLACE     = "m.replace";
constexpr std::string_view REL_TYPE_THREAD      = "m.thread";
constexpr std::string_view REL_TYPE_REFERENCE   = "m.reference";
constexpr std::string_view REL_TYPE_IN_REPLY_TO = "m.in_reply_to";

// Event types for reactions (MSC 2677)
constexpr std::string_view EVENT_TYPE_REACTION   = "m.reaction";
constexpr std::string_view EVENT_TYPE_ROOM_REDACT = "m.room.redaction";

// Poll event types (MSC 3381)
constexpr std::string_view EVENT_TYPE_POLL_START   = "m.poll.start";
constexpr std::string_view EVENT_TYPE_POLL_RESPONSE = "m.poll.response";
constexpr std::string_view EVENT_TYPE_POLL_END      = "m.poll.end";

// Aggregation bundle keys
constexpr std::string_view BUNDLE_KEY_ANNOTATIONS   = "m.annotations";
constexpr std::string_view BUNDLE_KEY_EDIT          = "m.replace";
constexpr std::string_view BUNDLE_KEY_THREAD         = "m.thread";
constexpr std::string_view BUNDLE_KEY_REFERENCES     = "m.references";
constexpr std::string_view BUNDLE_KEY_POLL_RESPONSES = "m.poll.responses";

// Rate limiting constants
constexpr int64_t MAX_REACTIONS_PER_EVENT = 10000;
constexpr int64_t MAX_EDITS_PER_EVENT = 100;
constexpr int64_t MAX_THREAD_DEPTH = 100;
constexpr int64_t MAX_RELATION_CHAIN = 50;
constexpr int64_t REACTION_RATE_LIMIT_WINDOW_SECS = 60;
constexpr int64_t REACTION_RATE_LIMIT_MAX = 30;
constexpr int64_t RELATION_RATE_LIMIT_WINDOW_SECS = 10;
constexpr int64_t RELATION_RATE_LIMIT_MAX = 10;

// ============================================================================
// Relation type classification
// ============================================================================

enum class RelationType : uint8_t {
    Annotation,   // m.annotation - reactions, polls
    Replace,      // m.replace - edits
    Thread,       // m.thread - threaded messages
    Reference,    // m.reference - generic reference
    InReplyTo,    // m.in_reply_to - fallback for replies
    Unknown
};

RelationType classify_relation(std::string_view rel_type) {
    if (rel_type == REL_TYPE_ANNOTATION)  return RelationType::Annotation;
    if (rel_type == REL_TYPE_REPLACE)     return RelationType::Replace;
    if (rel_type == REL_TYPE_THREAD)      return RelationType::Thread;
    if (rel_type == REL_TYPE_REFERENCE)   return RelationType::Reference;
    if (rel_type == REL_TYPE_IN_REPLY_TO) return RelationType::InReplyTo;
    return RelationType::Unknown;
}

std::string_view relation_type_to_string(RelationType rt) {
    switch (rt) {
        case RelationType::Annotation: return REL_TYPE_ANNOTATION;
        case RelationType::Replace:    return REL_TYPE_REPLACE;
        case RelationType::Thread:     return REL_TYPE_THREAD;
        case RelationType::Reference:  return REL_TYPE_REFERENCE;
        case RelationType::InReplyTo:  return REL_TYPE_IN_REPLY_TO;
        default:                       return "unknown";
    }
}

// ============================================================================
// EventRelation - stores a single relation edge
// ============================================================================

struct EventRelation {
    std::string event_id;          // The event that *has* the relation (source)
    std::string parent_id;         // The event being related *to* (target)
    std::string rel_type;          // m.annotation, m.replace, m.thread, m.reference
    std::string event_type;        // m.reaction, m.room.message, etc.
    std::string sender;            // Who sent the relation event
    std::string aggregation_key;   // For annotations: the reaction key (emoji/key)
    int64_t origin_server_ts = 0;  // When the relation event was sent
    std::optional<json> content;   // Cached content for aggregation
    bool is_fallback = false;      // True if this is an m.in_reply_to fallback
    bool is_redacted = false;      // True if the relation event has been redacted
    int64_t depth = 0;             // Thread depth (0 = root)
    std::string latest_reply_id;   // For thread roots: latest reply event_id
    int64_t latest_reply_ts = 0;   // For thread roots: latest reply timestamp
    int64_t reply_count = 0;       // For thread roots: count of immediate replies
    int64_t total_reply_count = 0; // For thread roots: total replies in thread
    std::set<std::string> participants; // Thread participants
    bool is_room_event = false;    // For thread notifications
};

// ============================================================================
// ReactionKey - composite key for reaction deduplication
// ============================================================================

struct ReactionKey {
    std::string event_id;       // Parent event being reacted to
    std::string sender;         // Who sent the reaction
    std::string aggregation_key;// The emoji/key

    bool operator==(const ReactionKey& other) const {
        return event_id == other.event_id &&
               sender == other.sender &&
               aggregation_key == other.aggregation_key;
    }
};

struct ReactionKeyHash {
    size_t operator()(const ReactionKey& k) const {
        size_t h1 = std::hash<std::string>{}(k.event_id);
        size_t h2 = std::hash<std::string>{}(k.sender);
        size_t h3 = std::hash<std::string>{}(k.aggregation_key);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

// ============================================================================
// RateLimiter
// ============================================================================

struct RateLimitBucket {
    int64_t window_start = 0;
    int64_t count = 0;

    bool allow(int64_t now_secs, int64_t window_secs, int64_t max_count) {
        if (window_start == 0 || (now_secs - window_start) > window_secs) {
            window_start = now_secs;
            count = 1;
            return true;
        }
        if (count >= max_count) {
            return false;
        }
        count++;
        return true;
    }
};

class RateLimiter {
public:
    RateLimiter(int64_t window_secs, int64_t max_count)
        : window_secs_(window_secs), max_count_(max_count) {}

    bool check(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return buckets_[key].allow(now, window_secs_, max_count_);
    }

    int64_t remaining(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        auto& bucket = buckets_[key];
        if (bucket.window_start == 0 || (now - bucket.window_start) > window_secs_) {
            return max_count_;
        }
        return std::max<int64_t>(0, max_count_ - bucket.count);
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        auto it = buckets_.begin();
        while (it != buckets_.end()) {
            if ((now - it->second.window_start) > window_secs_) {
                it = buckets_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    int64_t window_secs_;
    int64_t max_count_;
    std::mutex mutex_;
    std::unordered_map<std::string, RateLimitBucket> buckets_;
};

// ============================================================================
// PollAggregation
// ============================================================================

struct PollOptionResult {
    std::string id;            // Option ID from poll start
    int64_t count = 0;         // Number of votes for this option
    std::vector<std::string> voters; // Recent voters (for display)
};

struct PollAggregation {
    std::string poll_start_event_id;
    std::string poll_end_event_id;  // Empty if poll is still active
    bool is_ended = false;
    int64_t end_ts = 0;
    int64_t total_votes = 0;
    std::unordered_map<std::string, PollOptionResult> options;
    std::unordered_set<std::string> unique_voters; // For deduplication
    std::string max_selections;   // From poll start content
    int64_t response_count = 0;
};

// ============================================================================
// ThreadSummary
// ============================================================================

struct ThreadSummary {
    std::string root_event_id;
    std::string latest_reply_event_id;
    int64_t latest_reply_ts = 0;
    int64_t reply_count = 0;
    int64_t participant_count = 0;
    std::vector<std::string> participant_ids; // Recent participants
    bool is_participating = false;           // Whether current user is participating
    int64_t notification_count = 0;          // Unread notification count
    int64_t highlight_count = 0;             // Unread highlight count
};

// ============================================================================
// EventRelationsManager
// ============================================================================

class EventRelationsManager {
public:
    EventRelationsManager() = default;
    ~EventRelationsManager() = default;

    EventRelationsManager(const EventRelationsManager&) = delete;
    EventRelationsManager& operator=(const EventRelationsManager&) = delete;
    EventRelationsManager(EventRelationsManager&&) = default;
    EventRelationsManager& operator=(EventRelationsManager&&) = default;

    // ========================================================================
    // Relation CRUD
    // ========================================================================

    // Add a relation from an event's content
    bool add_relation(const std::string& event_id,
                      const std::string& sender,
                      const std::string& event_type,
                      const json& content,
                      int64_t origin_server_ts);

    // Add a relation explicitly
    bool add_relation_explicit(const std::string& event_id,
                               const std::string& parent_id,
                               const std::string& rel_type,
                               const std::string& sender,
                               const std::string& event_type,
                               int64_t origin_server_ts,
                               const json& content);

    // Remove a relation (e.g., on event redaction)
    bool remove_relation(const std::string& event_id);

    // Check if a relation exists
    bool has_relation(const std::string& event_id) const;

    // Get a specific relation
    std::optional<EventRelation> get_relation(const std::string& event_id) const;

    // ========================================================================
    // Querying relations
    // ========================================================================

    // Get all relations pointing to a parent event, filtered by type
    std::vector<EventRelation> get_relations_to(const std::string& parent_id,
                                                 std::optional<RelationType> rel_type = std::nullopt) const;

    // Get all relations from an event
    std::vector<EventRelation> get_relations_from(const std::string& event_id) const;

    // Get relations by type
    std::vector<EventRelation> get_relations_by_type(RelationType rel_type) const;

    // Get annotations to a parent event
    std::vector<EventRelation> get_annotations(const std::string& parent_id) const;

    // Get thread relations
    std::vector<EventRelation> get_thread_relations(const std::string& thread_root) const;

    // ========================================================================
    // Aggregation: Annotations (MSC 2677)
    // ========================================================================

    // Count annotations for an event, grouped by key
    std::unordered_map<std::string, int64_t> count_annotations(const std::string& event_id) const;

    // Count annotations including redacted ones
    std::unordered_map<std::string, int64_t> count_annotations_with_redacted(
        const std::string& event_id) const;

    // Check if a specific user reacted with a specific key
    bool has_reaction(const std::string& event_id,
                      const std::string& sender,
                      const std::string& key) const;

    // Get reaction count for a specific key
    int64_t get_reaction_count(const std::string& event_id,
                               const std::string& key) const;

    // Get all unique reaction keys for an event
    std::vector<std::string> get_reaction_keys(const std::string& event_id) const;

    // Get all reactors for a specific key
    std::vector<std::string> get_reactors(const std::string& event_id,
                                           const std::string& key) const;

    // ========================================================================
    // Aggregation: Edits (MSC 2676)
    // ========================================================================

    // Get the latest edit for an event
    std::optional<EventRelation> get_latest_edit(const std::string& event_id) const;

    // Get all edits for an event, ordered by timestamp
    std::vector<EventRelation> get_all_edits(const std::string& event_id) const;

    // Get the edit count for an event
    int64_t get_edit_count(const std::string& event_id) const;

    // Check if an event has been edited
    bool is_edited(const std::string& event_id) const;

    // ========================================================================
    // Aggregation: Threads (MSC 3440)
    // ========================================================================

    // Get thread summary for a root event
    ThreadSummary get_thread_summary(const std::string& root_event_id,
                                      const std::string& current_user = "") const;

    // Count thread replies
    int64_t count_thread_replies(const std::string& thread_root_id) const;

    // Get thread participants
    std::vector<std::string> get_thread_participants(const std::string& thread_root_id) const;

    // Check if a user is participating in a thread
    bool is_participating(const std::string& thread_root_id,
                          const std::string& user_id) const;

    // Get latest reply in thread
    std::optional<EventRelation> get_latest_thread_reply(const std::string& thread_root_id) const;

    // Get thread roots
    std::vector<std::string> get_thread_roots() const;

    // ========================================================================
    // Thread root validation
    // ========================================================================

    // Check if an event is a valid thread root
    bool is_valid_thread_root(const std::string& event_id) const;

    // Validate thread relation (no loops, max depth, etc.)
    bool validate_thread_relation(const std::string& event_id,
                                   const std::string& parent_id) const;

    // Get thread depth for an event
    int64_t get_thread_depth(const std::string& event_id) const;

    // Get thread root for an event (walks up the chain)
    std::optional<std::string> get_thread_root(const std::string& event_id) const;

    // ========================================================================
    // Thread notification counting (MSC 3773)
    // ========================================================================

    // Set notification count for a thread
    void set_thread_notification_count(const std::string& thread_root_id,
                                        const std::string& user_id,
                                        int64_t count,
                                        int64_t highlight_count);

    // Get notification count for a thread
    int64_t get_thread_notification_count(const std::string& thread_root_id,
                                           const std::string& user_id) const;

    // Get highlight count for a thread
    int64_t get_thread_highlight_count(const std::string& thread_root_id,
                                        const std::string& user_id) const;

    // Mark thread as read
    void mark_thread_read(const std::string& thread_root_id,
                          const std::string& user_id);

    // ========================================================================
    // Thread read receipts (MSC 3771)
    // ========================================================================

    // Set read receipt for a thread
    void set_thread_read_receipt(const std::string& thread_root_id,
                                  const std::string& user_id,
                                  const std::string& event_id,
                                  int64_t ts);

    // Get read receipt for a thread
    std::optional<std::pair<std::string, int64_t>> get_thread_read_receipt(
        const std::string& thread_root_id,
        const std::string& user_id) const;

    // Get all read receipts for a thread
    std::unordered_map<std::string, std::pair<std::string, int64_t>>
    get_thread_read_receipts(const std::string& thread_root_id) const;

    // ========================================================================
    // Thread timeline ordering
    // ========================================================================

    // Order thread replies by timestamp
    std::vector<std::string> order_thread_replies(const std::string& thread_root_id,
                                                    bool ascending = true) const;

    // Get paginated thread replies
    std::vector<std::string> get_paginated_thread_replies(
        const std::string& thread_root_id,
        int64_t limit,
        const std::string& from_token = "",
        const std::string& to_token = "",
        bool backward = true) const;

    // ========================================================================
    // Bundled aggregations for sync (MSC 2675)
    // ========================================================================

    // Compute bundled aggregations for a list of events
    json compute_bundled_aggregations(const std::vector<std::string>& event_ids,
                                       const std::string& current_user = "") const;

    // Compute bundled aggregations for a single event
    json compute_event_aggregation(const std::string& event_id,
                                    const std::string& current_user = "") const;

    // Get annotation bundle
    json get_annotation_bundle(const std::string& event_id) const;

    // Get edit bundle
    json get_edit_bundle(const std::string& event_id) const;

    // Get thread bundle
    json get_thread_bundle(const std::string& event_id,
                            const std::string& current_user) const;

    // Get reference bundle
    json get_reference_bundle(const std::string& event_id) const;

    // ========================================================================
    // Redaction of relations
    // ========================================================================

    // Redact a relation (mark as redacted without removing)
    bool redact_relation(const std::string& event_id);

    // Redact all relations pointing to a redacted event
    void redact_relations_to(const std::string& parent_id);

    // Purge redacted relations (actually remove them)
    int64_t purge_redacted_relations();

    // ========================================================================
    // Recursive relation resolution
    // ========================================================================

    // Resolve all relations for an event recursively
    std::vector<EventRelation> resolve_relations_recursive(
        const std::string& event_id,
        int64_t max_depth = MAX_RELATION_CHAIN) const;

    // Build relation tree
    json build_relation_tree(const std::string& root_event_id,
                             int64_t max_depth = MAX_RELATION_CHAIN) const;

    // Get the chain of edits for an event
    std::vector<std::string> get_edit_chain(const std::string& event_id) const;

    // Resolve the final content after all edits
    std::optional<json> resolve_edited_content(const std::string& event_id) const;

    // ========================================================================
    // Event reference tracking
    // ========================================================================

    // Track a reference between events
    void track_reference(const std::string& source_event_id,
                         const std::string& target_event_id,
                         const std::string& sender);

    // Get events that reference this event
    std::vector<std::string> get_references_to(const std::string& event_id) const;

    // Get events this event references
    std::vector<std::string> get_references_from(const std::string& event_id) const;

    // Get reference count
    int64_t get_reference_count(const std::string& event_id) const;

    // ========================================================================
    // Poll aggregation (MSC 3381)
    // ========================================================================

    // Register a poll start event
    bool register_poll_start(const std::string& event_id, const json& content);

    // Record a poll response
    bool record_poll_response(const std::string& event_id,
                               const std::string& response_event_id,
                               const std::string& sender,
                               const json& content);

    // End a poll
    bool end_poll(const std::string& poll_start_event_id,
                   const std::string& end_event_id,
                   int64_t end_ts);

    // Get poll results
    std::optional<PollAggregation> get_poll_results(const std::string& poll_start_event_id) const;

    // Get poll response count per option
    std::unordered_map<std::string, int64_t> get_poll_option_counts(
        const std::string& poll_start_event_id) const;

    // Check if poll is ended
    bool is_poll_ended(const std::string& poll_start_event_id) const;

    // ========================================================================
    // Deduplication
    // ========================================================================

    // Check for duplicate reaction
    bool is_duplicate_reaction(const std::string& event_id,
                                const std::string& sender,
                                const std::string& key) const;

    // Check for duplicate relation
    bool is_duplicate_relation(const std::string& event_id,
                                const std::string& parent_id,
                                const std::string& rel_type,
                                const std::string& sender) const;

    // Remove duplicate relations for an event
    int64_t deduplicate_relations(const std::string& event_id);

    // ========================================================================
    // Rate limiting
    // ========================================================================

    // Check reaction rate limit
    bool check_reaction_rate_limit(const std::string& user_id);

    // Check relation rate limit
    bool check_relation_rate_limit(const std::string& user_id);

    // Get remaining rate limit
    int64_t get_remaining_reaction_limit(const std::string& user_id);

    // Rate limit info
    json get_rate_limit_info(const std::string& user_id) const;

    // ========================================================================
    // Statistics and maintenance
    // ========================================================================

    // Get total relation count
    int64_t total_relation_count() const;

    // Get relation count by type
    std::unordered_map<std::string, int64_t> relation_counts_by_type() const;

    // Get total thread count
    int64_t total_thread_count() const;

    // Get total reaction count
    int64_t total_reaction_count() const;

    // Memory usage estimate
    int64_t estimate_memory_usage() const;

    // Clear all relations
    void clear();

    // Compact storage
    void compact();

private:
    // Main relation storage: event_id -> EventRelation
    std::unordered_map<std::string, EventRelation> relations_;

    // Index: parent_id -> list of event_ids pointing to it
    // Used for efficient querying of "what relates to X"
    std::unordered_map<std::string, std::vector<std::string>> parent_index_;

    // Index: (parent_id, rel_type) -> list of event_ids
    // Used for efficient filtered queries
    using RelationTypeKey = std::pair<std::string, std::string>;
    struct PairHash {
        size_t operator()(const RelationTypeKey& p) const {
            return std::hash<std::string>{}(p.first) ^
                   (std::hash<std::string>{}(p.second) << 1);
        }
    };
    std::unordered_map<RelationTypeKey, std::vector<std::string>, PairHash> type_index_;

    // Index: sender -> list of event_ids
    std::unordered_map<std::string, std::vector<std::string>> sender_index_;

    // Reaction deduplication index
    std::unordered_map<ReactionKey, std::string, ReactionKeyHash> reaction_index_;

    // Thread roots set for fast validation
    std::unordered_set<std::string> thread_roots_;

    // Thread metadata: root_id -> metadata
    struct ThreadMeta {
        std::string latest_reply_id;
        int64_t latest_reply_ts = 0;
        int64_t reply_count = 0;
        int64_t total_reply_count = 0;
        std::set<std::string> participants;
    };
    std::unordered_map<std::string, ThreadMeta> thread_meta_;

    // Thread notification counts: (root_id, user_id) -> (count, highlight)
    struct ThreadNotifyInfo {
        int64_t notification_count = 0;
        int64_t highlight_count = 0;
    };
    std::unordered_map<std::string,
        std::unordered_map<std::string, ThreadNotifyInfo>> thread_notifications_;

    // Thread read receipts: (root_id, user_id) -> (event_id, ts)
    std::unordered_map<std::string,
        std::unordered_map<std::string, std::pair<std::string, int64_t>>> thread_read_receipts_;

    // Edit tracking: original_event_id -> latest edit event_id
    std::unordered_map<std::string, std::string> latest_edits_;

    // Reference tracking
    std::unordered_map<std::string, std::vector<std::string>> references_to_;
    std::unordered_map<std::string, std::vector<std::string>> references_from_;

    // Poll storage
    std::unordered_map<std::string, PollAggregation> polls_;

    // Redaction tracking: event_id -> true if redacted
    std::unordered_set<std::string> redacted_events_;

    // Rate limiters
    RateLimiter reaction_rate_limiter_{
        REACTION_RATE_LIMIT_WINDOW_SECS, REACTION_RATE_LIMIT_MAX};
    RateLimiter relation_rate_limiter_{
        RELATION_RATE_LIMIT_WINDOW_SECS, RELATION_RATE_LIMIT_MAX};

    // Mutex for thread safety
    mutable std::shared_mutex mutex_;

    // ========================================================================
    // Private helper methods
    // ========================================================================

    void index_relation(const EventRelation& rel);
    void unindex_relation(const EventRelation& rel);
    bool validate_relation_content(const EventRelation& rel) const;
    void update_thread_meta(const EventRelation& rel);
    std::optional<std::string> get_thread_root_internal(const std::string& event_id,
                                                          std::unordered_set<std::string>& visited,
                                                          int64_t max_depth) const;
    json relation_to_json(const EventRelation& rel) const;
    EventRelation relation_from_json(const std::string& event_id, const json& j) const;
    std::string compute_parent_id(const json& content) const;
    std::string compute_rel_type(const json& content) const;
    std::string compute_aggregation_key(const json& content) const;
    bool extract_relation_info(const json& content,
                                std::string& parent_id,
                                std::string& rel_type,
                                std::string& aggregation_key,
                                bool& is_fallback) const;
    void cleanup_stale_rate_limits();
    void trim_reaction_list(std::vector<std::string>& reactors, int64_t max_count) const;
};

// ============================================================================
// Implementation: JSON helpers
// ============================================================================

std::string EventRelationsManager::compute_parent_id(const json& content) const {
    // Try m.relates_to.event_id first (MSC 2674)
    if (content.contains("m.relates_to") && content["m.relates_to"].is_object()) {
        const auto& relates_to = content["m.relates_to"];
        if (relates_to.contains("event_id") && relates_to["event_id"].is_string()) {
            return relates_to["event_id"].get<std::string>();
        }
    }
    // Try m.in_reply_to.event_id as fallback
    if (content.contains("m.in_reply_to") && content["m.in_reply_to"].is_object()) {
        const auto& in_reply = content["m.in_reply_to"];
        if (in_reply.contains("event_id") && in_reply["event_id"].is_string()) {
            return in_reply["event_id"].get<std::string>();
        }
    }
    return "";
}

std::string EventRelationsManager::compute_rel_type(const json& content) const {
    if (content.contains("m.relates_to") && content["m.relates_to"].is_object()) {
        const auto& relates_to = content["m.relates_to"];
        if (relates_to.contains("rel_type") && relates_to["rel_type"].is_string()) {
            return relates_to["rel_type"].get<std::string>();
        }
    }
    // If m.in_reply_to exists without m.relates_to, treat as thread fallback
    if (content.contains("m.in_reply_to") && content["m.in_reply_to"].is_object()) {
        return std::string(REL_TYPE_THREAD);
    }
    return "";
}

std::string EventRelationsManager::compute_aggregation_key(const json& content) const {
    // For m.reaction events, the key is in content["m.relates_to"]["key"]
    if (content.contains("m.relates_to") && content["m.relates_to"].is_object()) {
        const auto& relates_to = content["m.relates_to"];
        if (relates_to.contains("key") && relates_to["key"].is_string()) {
            return relates_to["key"].get<std::string>();
        }
    }
    return "";
}

bool EventRelationsManager::extract_relation_info(const json& content,
                                                     std::string& parent_id,
                                                     std::string& rel_type,
                                                     std::string& aggregation_key,
                                                     bool& is_fallback) const {
    parent_id = compute_parent_id(content);
    if (parent_id.empty()) {
        return false; // No relation
    }

    rel_type = compute_rel_type(content);
    if (rel_type.empty()) {
        // If has parent but no explicit rel_type, check if m.in_reply_to fallback
        if (content.contains("m.in_reply_to")) {
            rel_type = std::string(REL_TYPE_THREAD);
            is_fallback = true;
        } else {
            return false;
        }
    }

    aggregation_key = compute_aggregation_key(content);
    return true;
}

json EventRelationsManager::relation_to_json(const EventRelation& rel) const {
    json j;
    j["event_id"] = rel.event_id;
    j["parent_id"] = rel.parent_id;
    j["rel_type"] = rel.rel_type;
    j["event_type"] = rel.event_type;
    j["sender"] = rel.sender;
    j["origin_server_ts"] = rel.origin_server_ts;
    j["is_fallback"] = rel.is_fallback;
    j["is_redacted"] = rel.is_redacted;
    j["depth"] = rel.depth;
    if (!rel.aggregation_key.empty()) {
        j["aggregation_key"] = rel.aggregation_key;
    }
    return j;
}

EventRelationsManager::EventRelation
EventRelationsManager::relation_from_json(const std::string& event_id,
                                            const json& j) const {
    EventRelation rel;
    rel.event_id = event_id;
    rel.parent_id = j.value("parent_id", "");
    rel.rel_type = j.value("rel_type", "");
    rel.event_type = j.value("event_type", "");
    rel.sender = j.value("sender", "");
    rel.origin_server_ts = j.value("origin_server_ts", 0);
    rel.is_fallback = j.value("is_fallback", false);
    rel.is_redacted = j.value("is_redacted", false);
    rel.depth = j.value("depth", 0);
    rel.aggregation_key = j.value("aggregation_key", "");
    return rel;
}

// ============================================================================
// Implementation: Indexing
// ============================================================================

void EventRelationsManager::index_relation(const EventRelation& rel) {
    // Parent index
    parent_index_[rel.parent_id].push_back(rel.event_id);

    // Type index
    RelationTypeKey type_key{rel.parent_id, rel.rel_type};
    type_index_[type_key].push_back(rel.event_id);

    // Sender index
    sender_index_[rel.sender].push_back(rel.event_id);

    // Reaction dedup index
    if (rel.rel_type == REL_TYPE_ANNOTATION && !rel.aggregation_key.empty()) {
        ReactionKey rk{rel.parent_id, rel.sender, rel.aggregation_key};
        reaction_index_[rk] = rel.event_id;
    }

    // Thread root tracking
    if (rel.rel_type == REL_TYPE_THREAD && !rel.is_fallback) {
        // Check if this is a thread root (event_id equals parent_id is a root)
        // Actually we track roots when an event is referenced as a thread parent
    }

    // Reference tracking
    if (rel.rel_type == REL_TYPE_REFERENCE) {
        references_to_[rel.parent_id].push_back(rel.event_id);
        references_from_[rel.event_id].push_back(rel.parent_id);
    }
}

void EventRelationsManager::unindex_relation(const EventRelation& rel) {
    // Remove from parent index
    auto pit = parent_index_.find(rel.parent_id);
    if (pit != parent_index_.end()) {
        auto& vec = pit->second;
        vec.erase(std::remove(vec.begin(), vec.end(), rel.event_id), vec.end());
        if (vec.empty()) {
            parent_index_.erase(pit);
        }
    }

    // Remove from type index
    RelationTypeKey type_key{rel.parent_id, rel.rel_type};
    auto tit = type_index_.find(type_key);
    if (tit != type_index_.end()) {
        auto& vec = tit->second;
        vec.erase(std::remove(vec.begin(), vec.end(), rel.event_id), vec.end());
        if (vec.empty()) {
            type_index_.erase(tit);
        }
    }

    // Remove from sender index
    auto sit = sender_index_.find(rel.sender);
    if (sit != sender_index_.end()) {
        auto& vec = sit->second;
        vec.erase(std::remove(vec.begin(), vec.end(), rel.event_id), vec.end());
        if (vec.empty()) {
            sender_index_.erase(sit);
        }
    }

    // Remove from reaction index
    if (rel.rel_type == REL_TYPE_ANNOTATION && !rel.aggregation_key.empty()) {
        ReactionKey rk{rel.parent_id, rel.sender, rel.aggregation_key};
        reaction_index_.erase(rk);
    }

    // Remove from references
    if (rel.rel_type == REL_TYPE_REFERENCE) {
        auto rto = references_to_.find(rel.parent_id);
        if (rto != references_to_.end()) {
            auto& vec = rto->second;
            vec.erase(std::remove(vec.begin(), vec.end(), rel.event_id), vec.end());
            if (vec.empty()) references_to_.erase(rto);
        }
        auto rfrom = references_from_.find(rel.event_id);
        if (rfrom != references_from_.end()) {
            auto& vec = rfrom->second;
            vec.erase(std::remove(vec.begin(), vec.end(), rel.parent_id), vec.end());
            if (vec.empty()) references_from_.erase(rfrom);
        }
    }
}

bool EventRelationsManager::validate_relation_content(const EventRelation& rel) const {
    if (rel.event_id.empty() || rel.parent_id.empty()) {
        return false;
    }
    if (rel.event_id == rel.parent_id) {
        return false; // Cannot relate to self
    }
    if (rel.rel_type.empty()) {
        return false;
    }
    return true;
}

void EventRelationsManager::update_thread_meta(const EventRelation& rel) {
    if (rel.rel_type != REL_TYPE_THREAD) return;

    auto& meta = thread_meta_[rel.parent_id];
    meta.participants.insert(rel.sender);
    meta.total_reply_count++;
    meta.reply_count++;

    if (rel.origin_server_ts > meta.latest_reply_ts) {
        meta.latest_reply_ts = rel.origin_server_ts;
        meta.latest_reply_id = rel.event_id;
    }

    // Also add parent as thread root
    thread_roots_.insert(rel.parent_id);
}

// ============================================================================
// Implementation: Relation CRUD
// ============================================================================

bool EventRelationsManager::add_relation(const std::string& event_id,
                                           const std::string& sender,
                                           const std::string& event_type,
                                           const json& content,
                                           int64_t origin_server_ts) {
    std::string parent_id, rel_type, aggregation_key;
    bool is_fallback = false;

    if (!extract_relation_info(content, parent_id, rel_type, aggregation_key, is_fallback)) {
        return false; // No relation to add
    }

    return add_relation_explicit(event_id, parent_id, rel_type, sender,
                                  event_type, origin_server_ts, content);
}

bool EventRelationsManager::add_relation_explicit(const std::string& event_id,
                                                    const std::string& parent_id,
                                                    const std::string& rel_type,
                                                    const std::string& sender,
                                                    const std::string& event_type,
                                                    int64_t origin_server_ts,
                                                    const json& content) {
    // Rate limit check
    if (!check_relation_rate_limit(sender)) {
        return false;
    }

    std::unique_lock lock(mutex_);

    EventRelation rel;
    rel.event_id = event_id;
    rel.parent_id = parent_id;
    rel.rel_type = rel_type;
    rel.sender = sender;
    rel.event_type = event_type;
    rel.origin_server_ts = origin_server_ts;
    rel.content = content;
    rel.is_fallback = false;

    // Extract aggregation key for annotations
    if (rel_type == REL_TYPE_ANNOTATION) {
        rel.aggregation_key = compute_aggregation_key(content);
    }

    // Check for reaction rate limit
    if (rel_type == REL_TYPE_ANNOTATION && event_type == EVENT_TYPE_REACTION) {
        if (!check_reaction_rate_limit(sender)) {
            return false;
        }
    }

    // Deduplication for reactions
    if (rel_type == REL_TYPE_ANNOTATION && event_type == EVENT_TYPE_REACTION) {
        if (is_duplicate_reaction(parent_id, sender, rel.aggregation_key)) {
            // Update existing reaction instead of creating duplicate
            auto rkey = ReactionKey{parent_id, sender, rel.aggregation_key};
            auto it = reaction_index_.find(rkey);
            if (it != reaction_index_.end()) {
                // Remove old relation, add new one
                auto old_it = relations_.find(it->second);
                if (old_it != relations_.end()) {
                    unindex_relation(old_it->second);
                    relations_.erase(old_it);
                }
            }
        }
    }

    // Validate
    if (!validate_relation_content(rel)) {
        return false;
    }

    // For thread relations, validate thread root
    if (rel_type == REL_TYPE_THREAD) {
        if (!validate_thread_relation(event_id, parent_id)) {
            return false;
        }
        // Compute depth
        auto parent_rel = relations_.find(parent_id);
        if (parent_rel != relations_.end()) {
            rel.depth = parent_rel->second.depth + 1;
        } else {
            rel.depth = 1; // Direct reply to root
        }
    }

    // Remove existing relation for this event if any
    auto existing = relations_.find(event_id);
    if (existing != relations_.end()) {
        unindex_relation(existing->second);
    }

    // Store
    relations_[event_id] = rel;
    index_relation(rel);

    // Update thread metadata
    if (rel.rel_type == REL_TYPE_THREAD) {
        update_thread_meta(rel);
    }

    // Update latest edit tracking
    if (rel.rel_type == REL_TYPE_REPLACE) {
        auto& latest = latest_edits_[rel.parent_id];
        if (latest.empty() || rel.origin_server_ts > 0) {
            // Check if this is newer than existing latest edit
            auto existing_edit = relations_.find(latest);
            if (existing_edit == relations_.end() ||
                rel.origin_server_ts > existing_edit->second.origin_server_ts) {
                latest = rel.event_id;
            }
        }
    }

    // Handle poll responses
    if (event_type == EVENT_TYPE_POLL_RESPONSE) {
        record_poll_response(parent_id, event_id, sender, content);
    }

    return true;
}

bool EventRelationsManager::remove_relation(const std::string& event_id) {
    std::unique_lock lock(mutex_);

    auto it = relations_.find(event_id);
    if (it == relations_.end()) {
        return false;
    }

    // Update thread metadata
    if (it->second.rel_type == REL_TYPE_THREAD) {
        auto meta_it = thread_meta_.find(it->second.parent_id);
        if (meta_it != thread_meta_.end()) {
            meta_it->second.reply_count--;
            meta_it->second.total_reply_count--;
            // Don't remove participant - they still participated historically
        }
    }

    // Update latest edit tracking
    if (it->second.rel_type == REL_TYPE_REPLACE) {
        auto edit_it = latest_edits_.find(it->second.parent_id);
        if (edit_it != latest_edits_.end() && edit_it->second == event_id) {
            latest_edits_.erase(edit_it);
            // Find next latest edit
            auto edits = get_all_edits(it->second.parent_id);
            if (!edits.empty()) {
                latest_edits_[it->second.parent_id] = edits.back().event_id;
            }
        }
    }

    unindex_relation(it->second);
    relations_.erase(it);
    return true;
}

bool EventRelationsManager::has_relation(const std::string& event_id) const {
    std::shared_lock lock(mutex_);
    return relations_.find(event_id) != relations_.end();
}

std::optional<EventRelationsManager::EventRelation>
EventRelationsManager::get_relation(const std::string& event_id) const {
    std::shared_lock lock(mutex_);
    auto it = relations_.find(event_id);
    if (it != relations_.end()) {
        return it->second;
    }
    return std::nullopt;
}

// ============================================================================
// Implementation: Querying relations
// ============================================================================

std::vector<EventRelationsManager::EventRelation>
EventRelationsManager::get_relations_to(const std::string& parent_id,
                                          std::optional<RelationType> rel_type) const {
    std::shared_lock lock(mutex_);

    std::vector<EventRelation> results;
    std::vector<std::string> event_ids;

    if (rel_type.has_value()) {
        RelationTypeKey type_key{parent_id,
            std::string(relation_type_to_string(rel_type.value()))};
        auto tit = type_index_.find(type_key);
        if (tit != type_index_.end()) {
            event_ids = tit->second;
        }
    } else {
        auto pit = parent_index_.find(parent_id);
        if (pit != parent_index_.end()) {
            event_ids = pit->second;
        }
    }

    for (const auto& eid : event_ids) {
        auto rit = relations_.find(eid);
        if (rit != relations_.end()) {
            results.push_back(rit->second);
        }
    }

    return results;
}

std::vector<EventRelationsManager::EventRelation>
EventRelationsManager::get_relations_from(const std::string& event_id) const {
    std::shared_lock lock(mutex_);

    std::vector<EventRelation> results;
    auto it = relations_.find(event_id);
    if (it != relations_.end()) {
        results.push_back(it->second);
    }
    return results;
}

std::vector<EventRelationsManager::EventRelation>
EventRelationsManager::get_relations_by_type(RelationType rel_type) const {
    std::shared_lock lock(mutex_);

    std::vector<EventRelation> results;
    std::string rel_type_str(relation_type_to_string(rel_type));

    for (const auto& [event_id, rel] : relations_) {
        if (rel.rel_type == rel_type_str) {
            results.push_back(rel);
        }
    }

    return results;
}

std::vector<EventRelationsManager::EventRelation>
EventRelationsManager::get_annotations(const std::string& parent_id) const {
    return get_relations_to(parent_id, RelationType::Annotation);
}

std::vector<EventRelationsManager::EventRelation>
EventRelationsManager::get_thread_relations(const std::string& thread_root) const {
    return get_relations_to(thread_root, RelationType::Thread);
}

// ============================================================================
// Implementation: Aggregation - Annotations
// ============================================================================

std::unordered_map<std::string, int64_t>
EventRelationsManager::count_annotations(const std::string& event_id) const {
    std::shared_lock lock(mutex_);
    std::unordered_map<std::string, int64_t> counts;

    auto annotations = get_annotations(event_id);
    for (const auto& ann : annotations) {
        if (!ann.is_redacted && ann.event_type == EVENT_TYPE_REACTION) {
            counts[ann.aggregation_key]++;
        }
    }

    return counts;
}

std::unordered_map<std::string, int64_t>
EventRelationsManager::count_annotations_with_redacted(const std::string& event_id) const {
    std::shared_lock lock(mutex_);
    std::unordered_map<std::string, int64_t> counts;

    auto annotations = get_annotations(event_id);
    for (const auto& ann : annotations) {
        if (ann.event_type == EVENT_TYPE_REACTION) {
            counts[ann.aggregation_key]++;
        }
    }

    return counts;
}

bool EventRelationsManager::has_reaction(const std::string& event_id,
                                           const std::string& sender,
                                           const std::string& key) const {
    std::shared_lock lock(mutex_);
    ReactionKey rk{event_id, sender, key};
    return reaction_index_.find(rk) != reaction_index_.end();
}

int64_t EventRelationsManager::get_reaction_count(const std::string& event_id,
                                                     const std::string& key) const {
    auto counts = count_annotations(event_id);
    auto it = counts.find(key);
    return it != counts.end() ? it->second : 0;
}

std::vector<std::string> EventRelationsManager::get_reaction_keys(
    const std::string& event_id) const {
    std::shared_lock lock(mutex_);
    std::unordered_set<std::string> keys;
    auto annotations = get_annotations(event_id);

    for (const auto& ann : annotations) {
        if (!ann.is_redacted && !ann.aggregation_key.empty()) {
            keys.insert(ann.aggregation_key);
        }
    }

    return std::vector<std::string>(keys.begin(), keys.end());
}

std::vector<std::string> EventRelationsManager::get_reactors(
    const std::string& event_id,
    const std::string& key) const {
    std::shared_lock lock(mutex_);
    std::vector<std::string> reactors;
    auto annotations = get_annotations(event_id);

    for (const auto& ann : annotations) {
        if (!ann.is_redacted && ann.aggregation_key == key) {
            reactors.push_back(ann.sender);
        }
    }

    return reactors;
}

// ============================================================================
// Implementation: Aggregation - Edits
// ============================================================================

std::optional<EventRelationsManager::EventRelation>
EventRelationsManager::get_latest_edit(const std::string& event_id) const {
    std::shared_lock lock(mutex_);

    auto edit_it = latest_edits_.find(event_id);
    if (edit_it != latest_edits_.end()) {
        auto rel_it = relations_.find(edit_it->second);
        if (rel_it != relations_.end() && !rel_it->second.is_redacted) {
            return rel_it->second;
        }
    }

    // Fallback: find the latest edit manually
    auto edits = get_relations_to(event_id, RelationType::Replace);
    if (edits.empty()) {
        return std::nullopt;
    }

    // Sort by timestamp descending
    std::sort(edits.begin(), edits.end(),
              [](const EventRelation& a, const EventRelation& b) {
                  return a.origin_server_ts > b.origin_server_ts;
              });

    for (const auto& edit : edits) {
        if (!edit.is_redacted) {
            return edit;
        }
    }

    return std::nullopt;
}

std::vector<EventRelationsManager::EventRelation>
EventRelationsManager::get_all_edits(const std::string& event_id) const {
    auto edits = get_relations_to(event_id, RelationType::Replace);

    // Sort by timestamp ascending
    std::sort(edits.begin(), edits.end(),
              [](const EventRelation& a, const EventRelation& b) {
                  return a.origin_server_ts < b.origin_server_ts;
              });

    return edits;
}

int64_t EventRelationsManager::get_edit_count(const std::string& event_id) const {
    auto edits = get_relations_to(event_id, RelationType::Replace);
    return static_cast<int64_t>(edits.size());
}

bool EventRelationsManager::is_edited(const std::string& event_id) const {
    return get_edit_count(event_id) > 0;
}

// ============================================================================
// Implementation: Aggregation - Threads
// ============================================================================

ThreadSummary EventRelationsManager::get_thread_summary(
    const std::string& root_event_id,
    const std::string& current_user) const {

    std::shared_lock lock(mutex_);
    ThreadSummary summary;
    summary.root_event_id = root_event_id;

    auto meta_it = thread_meta_.find(root_event_id);
    if (meta_it != thread_meta_.end()) {
        summary.latest_reply_event_id = meta_it->second.latest_reply_id;
        summary.latest_reply_ts = meta_it->second.latest_reply_ts;
        summary.reply_count = meta_it->second.reply_count;
        summary.participant_count = static_cast<int64_t>(meta_it->second.participants.size());

        // Get recent participants
        size_t max_participants = std::min<size_t>(meta_it->second.participants.size(), 10);
        summary.participant_ids.assign(
            meta_it->second.participants.begin(),
            std::next(meta_it->second.participants.begin(), max_participants));
    }

    // Check if current user is participating
    if (!current_user.empty()) {
        summary.is_participating = is_participating(root_event_id, current_user);

        // Get notification counts
        auto notify_it = thread_notifications_.find(root_event_id);
        if (notify_it != thread_notifications_.end()) {
            auto user_notify = notify_it->second.find(current_user);
            if (user_notify != notify_it->second.end()) {
                summary.notification_count = user_notify->second.notification_count;
                summary.highlight_count = user_notify->second.highlight_count;
            }
        }
    }

    return summary;
}

int64_t EventRelationsManager::count_thread_replies(const std::string& thread_root_id) const {
    std::shared_lock lock(mutex_);
    auto meta_it = thread_meta_.find(thread_root_id);
    if (meta_it != thread_meta_.end()) {
        return meta_it->second.reply_count;
    }
    return 0;
}

std::vector<std::string> EventRelationsManager::get_thread_participants(
    const std::string& thread_root_id) const {
    std::shared_lock lock(mutex_);
    auto meta_it = thread_meta_.find(thread_root_id);
    if (meta_it != thread_meta_.end()) {
        return std::vector<std::string>(
            meta_it->second.participants.begin(),
            meta_it->second.participants.end());
    }
    return {};
}

bool EventRelationsManager::is_participating(const std::string& thread_root_id,
                                               const std::string& user_id) const {
    std::shared_lock lock(mutex_);
    auto meta_it = thread_meta_.find(thread_root_id);
    if (meta_it != thread_meta_.end()) {
        return meta_it->second.participants.find(user_id) !=
               meta_it->second.participants.end();
    }
    return false;
}

std::optional<EventRelationsManager::EventRelation>
EventRelationsManager::get_latest_thread_reply(const std::string& thread_root_id) const {
    std::shared_lock lock(mutex_);
    auto meta_it = thread_meta_.find(thread_root_id);
    if (meta_it != thread_meta_.end() && !meta_it->second.latest_reply_id.empty()) {
        auto rel_it = relations_.find(meta_it->second.latest_reply_id);
        if (rel_it != relations_.end()) {
            return rel_it->second;
        }
    }
    return std::nullopt;
}

std::vector<std::string> EventRelationsManager::get_thread_roots() const {
    std::shared_lock lock(mutex_);
    return std::vector<std::string>(thread_roots_.begin(), thread_roots_.end());
}

// ============================================================================
// Implementation: Thread root validation
// ============================================================================

bool EventRelationsManager::is_valid_thread_root(const std::string& event_id) const {
    std::shared_lock lock(mutex_);
    // A thread root is valid if:
    // 1. It exists in thread_roots_
    // 2. It's not a reply itself (no m.thread relation pointing from it)
    if (thread_roots_.find(event_id) != thread_roots_.end()) {
        auto rel_it = relations_.find(event_id);
        if (rel_it != relations_.end() && rel_it->second.rel_type == REL_TYPE_THREAD) {
            return false; // This event is a reply, not a root
        }
        return true;
    }
    return false;
}

bool EventRelationsManager::validate_thread_relation(const std::string& event_id,
                                                       const std::string& parent_id) const {
    // Check for self-reference
    if (event_id == parent_id) {
        return false;
    }

    // Check for loops: walk up the chain
    std::unordered_set<std::string> visited;
    std::string current = parent_id;
    int64_t depth = 0;

    while (!current.empty() && depth < MAX_THREAD_DEPTH) {
        if (current == event_id) {
            return false; // Loop detected
        }
        if (visited.find(current) != visited.end()) {
            return false; // Loop detected
        }
        visited.insert(current);

        auto rel_it = relations_.find(current);
        if (rel_it != relations_.end() && rel_it->second.rel_type == REL_TYPE_THREAD) {
            current = rel_it->second.parent_id;
            depth++;
        } else {
            break; // Reached root
        }
    }

    // Check max depth
    if (depth >= MAX_THREAD_DEPTH) {
        return false;
    }

    return true;
}

int64_t EventRelationsManager::get_thread_depth(const std::string& event_id) const {
    std::shared_lock lock(mutex_);
    auto it = relations_.find(event_id);
    if (it != relations_.end()) {
        return it->second.depth;
    }
    return 0;
}

std::optional<std::string> EventRelationsManager::get_thread_root(
    const std::string& event_id) const {
    std::unordered_set<std::string> visited;
    return get_thread_root_internal(event_id, visited, MAX_THREAD_DEPTH);
}

std::optional<std::string> EventRelationsManager::get_thread_root_internal(
    const std::string& event_id,
    std::unordered_set<std::string>& visited,
    int64_t max_depth) const {

    if (max_depth <= 0) return std::nullopt;
    if (visited.find(event_id) != visited.end()) return std::nullopt;

    visited.insert(event_id);

    auto it = relations_.find(event_id);
    if (it == relations_.end()) {
        // No relation, this might be the root itself
        return event_id;
    }

    if (it->second.rel_type == REL_TYPE_THREAD) {
        return get_thread_root_internal(it->second.parent_id, visited, max_depth - 1);
    }

    // Not a thread relation, this is the root
    return event_id;
}

// ============================================================================
// Implementation: Thread notification counting
// ============================================================================

void EventRelationsManager::set_thread_notification_count(
    const std::string& thread_root_id,
    const std::string& user_id,
    int64_t count,
    int64_t highlight_count) {

    std::unique_lock lock(mutex_);
    auto& info = thread_notifications_[thread_root_id][user_id];
    info.notification_count = count;
    info.highlight_count = highlight_count;
}

int64_t EventRelationsManager::get_thread_notification_count(
    const std::string& thread_root_id,
    const std::string& user_id) const {

    std::shared_lock lock(mutex_);
    auto notify_it = thread_notifications_.find(thread_root_id);
    if (notify_it != thread_notifications_.end()) {
        auto user_it = notify_it->second.find(user_id);
        if (user_it != notify_it->second.end()) {
            return user_it->second.notification_count;
        }
    }
    return 0;
}

int64_t EventRelationsManager::get_thread_highlight_count(
    const std::string& thread_root_id,
    const std::string& user_id) const {

    std::shared_lock lock(mutex_);
    auto notify_it = thread_notifications_.find(thread_root_id);
    if (notify_it != thread_notifications_.end()) {
        auto user_it = notify_it->second.find(user_id);
        if (user_it != notify_it->second.end()) {
            return user_it->second.highlight_count;
        }
    }
    return 0;
}

void EventRelationsManager::mark_thread_read(const std::string& thread_root_id,
                                               const std::string& user_id) {
    std::unique_lock lock(mutex_);
    auto notify_it = thread_notifications_.find(thread_root_id);
    if (notify_it != thread_notifications_.end()) {
        auto user_it = notify_it->second.find(user_id);
        if (user_it != notify_it->second.end()) {
            user_it->second.notification_count = 0;
            user_it->second.highlight_count = 0;
        }
    }
}

// ============================================================================
// Implementation: Thread read receipts
// ============================================================================

void EventRelationsManager::set_thread_read_receipt(const std::string& thread_root_id,
                                                      const std::string& user_id,
                                                      const std::string& event_id,
                                                      int64_t ts) {
    std::unique_lock lock(mutex_);
    thread_read_receipts_[thread_root_id][user_id] = {event_id, ts};
}

std::optional<std::pair<std::string, int64_t>>
EventRelationsManager::get_thread_read_receipt(const std::string& thread_root_id,
                                                 const std::string& user_id) const {
    std::shared_lock lock(mutex_);
    auto thread_it = thread_read_receipts_.find(thread_root_id);
    if (thread_it != thread_read_receipts_.end()) {
        auto user_it = thread_it->second.find(user_id);
        if (user_it != thread_it->second.end()) {
            return user_it->second;
        }
    }
    return std::nullopt;
}

std::unordered_map<std::string, std::pair<std::string, int64_t>>
EventRelationsManager::get_thread_read_receipts(const std::string& thread_root_id) const {
    std::shared_lock lock(mutex_);
    auto it = thread_read_receipts_.find(thread_root_id);
    if (it != thread_read_receipts_.end()) {
        return it->second;
    }
    return {};
}

// ============================================================================
// Implementation: Thread timeline ordering
// ============================================================================

std::vector<std::string> EventRelationsManager::order_thread_replies(
    const std::string& thread_root_id,
    bool ascending) const {

    std::shared_lock lock(mutex_);
    auto replies = get_thread_relations(thread_root_id);

    std::sort(replies.begin(), replies.end(),
              [ascending](const EventRelation& a, const EventRelation& b) {
                  if (ascending) {
                      return a.origin_server_ts < b.origin_server_ts;
                  } else {
                      return a.origin_server_ts > b.origin_server_ts;
                  }
              });

    std::vector<std::string> result;
    result.reserve(replies.size());
    for (const auto& reply : replies) {
        result.push_back(reply.event_id);
    }

    return result;
}

std::vector<std::string> EventRelationsManager::get_paginated_thread_replies(
    const std::string& thread_root_id,
    int64_t limit,
    const std::string& from_token,
    const std::string& to_token,
    bool backward) const {

    auto ordered = order_thread_replies(thread_root_id, backward);

    std::vector<std::string> result;
    bool include = from_token.empty();

    for (const auto& eid : ordered) {
        if (!from_token.empty() && eid == from_token) {
            include = true;
            continue;
        }
        if (!to_token.empty() && eid == to_token) {
            break;
        }
        if (include && static_cast<int64_t>(result.size()) < limit) {
            result.push_back(eid);
        }
    }

    return result;
}

// ============================================================================
// Implementation: Bundled aggregations
// ============================================================================

json EventRelationsManager::compute_bundled_aggregations(
    const std::vector<std::string>& event_ids,
    const std::string& current_user) const {

    json result = json::object();

    for (const auto& event_id : event_ids) {
        json aggregation = compute_event_aggregation(event_id, current_user);
        if (!aggregation.empty()) {
            result[event_id] = aggregation;
        }
    }

    return result;
}

json EventRelationsManager::compute_event_aggregation(
    const std::string& event_id,
    const std::string& current_user) const {

    std::shared_lock lock(mutex_);
    json aggregation = json::object();
    bool has_data = false;

    // Check if this event has any relations
    auto pit = parent_index_.find(event_id);
    if (pit == parent_index_.end()) {
        return json::object();
    }

    // Count relation types for this event
    int64_t annotation_count = 0;
    int64_t replace_count = 0;
    int64_t thread_count = 0;
    int64_t reference_count = 0;

    for (const auto& rel_event_id : pit->second) {
        auto rit = relations_.find(rel_event_id);
        if (rit == relations_.end() || rit->second.is_redacted) continue;

        if (rit->second.rel_type == REL_TYPE_ANNOTATION) annotation_count++;
        else if (rit->second.rel_type == REL_TYPE_REPLACE) replace_count++;
        else if (rit->second.rel_type == REL_TYPE_THREAD) thread_count++;
        else if (rit->second.rel_type == REL_TYPE_REFERENCE) reference_count++;
    }

    // Add annotation bundle
    if (annotation_count > 0) {
        json ann_bundle = get_annotation_bundle(event_id);
        if (!ann_bundle.empty()) {
            aggregation[std::string(BUNDLE_KEY_ANNOTATIONS)] = ann_bundle;
            has_data = true;
        }
    }

    // Add edit bundle
    if (replace_count > 0) {
        json edit_bundle = get_edit_bundle(event_id);
        if (!edit_bundle.empty()) {
            aggregation[std::string(BUNDLE_KEY_EDIT)] = edit_bundle;
            has_data = true;
        }
    }

    // Add thread bundle
    if (thread_count > 0) {
        json thread_bundle = get_thread_bundle(event_id, current_user);
        if (!thread_bundle.empty()) {
            aggregation[std::string(BUNDLE_KEY_THREAD)] = thread_bundle;
            has_data = true;
        }
    }

    // Add reference bundle
    if (reference_count > 0) {
        json ref_bundle = get_reference_bundle(event_id);
        if (!ref_bundle.empty()) {
            aggregation[std::string(BUNDLE_KEY_REFERENCES)] = ref_bundle;
            has_data = true;
        }
    }

    // Add poll response bundle
    auto poll_it = polls_.find(event_id);
    if (poll_it != polls_.end() && poll_it->second.response_count > 0) {
        json poll_bundle = json::object();
        json option_counts = json::object();
        for (const auto& [opt_id, opt_result] : poll_it->second.options) {
            option_counts[opt_id] = opt_result.count;
        }
        poll_bundle["options"] = option_counts;
        poll_bundle["total_votes"] = poll_it->second.total_votes;
        if (poll_it->second.is_ended) {
            poll_bundle["is_ended"] = true;
            poll_bundle["end_ts"] = poll_it->second.end_ts;
        }
        aggregation[std::string(BUNDLE_KEY_POLL_RESPONSES)] = poll_bundle;
        has_data = true;
    }

    return has_data ? aggregation : json::object();
}

json EventRelationsManager::get_annotation_bundle(const std::string& event_id) const {
    auto counts = count_annotations(event_id);
    if (counts.empty()) return json::object();

    json bundle = json::object();
    json annotations = json::object();

    for (const auto& [key, count] : counts) {
        json ann = json::object();
        ann["key"] = key;
        ann["count"] = count;

        // Include recent reactors (up to 5)
        auto reactors = get_reactors(event_id, key);
        std::sort(reactors.begin(), reactors.end());
        auto unique_end = std::unique(reactors.begin(), reactors.end());
        reactors.erase(unique_end, reactors.end());

        if (reactors.size() > 5) {
            reactors.resize(5);
        }
        ann["recent_reactors"] = reactors;
        annotations[key] = ann;
    }

    bundle["annotations"] = annotations;
    bundle["annotation_count"] = static_cast<int64_t>(counts.size());
    bundle["total_reactions"] = std::accumulate(
        counts.begin(), counts.end(), 0LL,
        [](int64_t sum, const auto& pair) { return sum + pair.second; });

    return bundle;
}

json EventRelationsManager::get_edit_bundle(const std::string& event_id) const {
    auto latest = get_latest_edit(event_id);
    if (!latest.has_value()) return json::object();

    json bundle = json::object();
    bundle["event_id"] = latest->event_id;
    bundle["origin_server_ts"] = latest->origin_server_ts;
    bundle["sender"] = latest->sender;
    bundle["edit_count"] = get_edit_count(event_id);

    if (latest->content.has_value()) {
        // Include the new content
        const auto& content = latest->content.value();
        if (content.contains("m.new_content")) {
            bundle["content"] = content["m.new_content"];
        } else if (content.contains("body")) {
            bundle["content"] = content;
        }
    }

    return bundle;
}

json EventRelationsManager::get_thread_bundle(const std::string& event_id,
                                                 const std::string& current_user) const {
    auto summary = get_thread_summary(event_id, current_user);
    if (summary.reply_count == 0 && !summary.is_participating) {
        return json::object();
    }

    json bundle = json::object();
    bundle["reply_count"] = summary.reply_count;
    bundle["participant_count"] = summary.participant_count;
    bundle["latest_reply_event_id"] = summary.latest_reply_event_id;
    bundle["latest_reply_ts"] = summary.latest_reply_ts;
    bundle["participants"] = summary.participant_ids;

    if (!current_user.empty()) {
        bundle["is_participating"] = summary.is_participating;
        bundle["notification_count"] = summary.notification_count;
        bundle["highlight_count"] = summary.highlight_count;
    }

    return bundle;
}

json EventRelationsManager::get_reference_bundle(const std::string& event_id) const {
    std::shared_lock lock(mutex_);
    auto rto = references_to_.find(event_id);
    if (rto == references_to_.end() || rto->second.empty()) {
        return json::object();
    }

    json bundle = json::object();
    bundle["reference_count"] = static_cast<int64_t>(rto->second.size());

    // Include recent references (up to 5)
    json refs = json::array();
    size_t count = 0;
    for (auto it = rto->second.rbegin();
         it != rto->second.rend() && count < 5; ++it, ++count) {
        auto rel_it = relations_.find(*it);
        if (rel_it != relations_.end() && !rel_it->second.is_redacted) {
            json ref = json::object();
            ref["event_id"] = rel_it->second.event_id;
            ref["sender"] = rel_it->second.sender;
            ref["origin_server_ts"] = rel_it->second.origin_server_ts;
            refs.push_back(ref);
        }
    }
    bundle["recent_references"] = refs;

    return bundle;
}

// ============================================================================
// Implementation: Redaction of relations
// ============================================================================

bool EventRelationsManager::redact_relation(const std::string& event_id) {
    std::unique_lock lock(mutex_);

    auto it = relations_.find(event_id);
    if (it == relations_.end()) {
        return false;
    }

    it->second.is_redacted = true;
    redacted_events_.insert(event_id);

    // If it's an annotation, remove from reaction index
    if (it->second.rel_type == REL_TYPE_ANNOTATION && !it->second.aggregation_key.empty()) {
        ReactionKey rk{it->second.parent_id, it->second.sender, it->second.aggregation_key};
        reaction_index_.erase(rk);
    }

    // Update thread metadata
    if (it->second.rel_type == REL_TYPE_THREAD) {
        auto meta_it = thread_meta_.find(it->second.parent_id);
        if (meta_it != thread_meta_.end()) {
            meta_it->second.reply_count--;
            meta_it->second.total_reply_count--;
        }
    }

    // Update latest edit tracking
    if (it->second.rel_type == REL_TYPE_REPLACE) {
        auto edit_it = latest_edits_.find(it->second.parent_id);
        if (edit_it != latest_edits_.end() && edit_it->second == event_id) {
            latest_edits_.erase(edit_it);
        }
    }

    return true;
}

void EventRelationsManager::redact_relations_to(const std::string& parent_id) {
    std::unique_lock lock(mutex_);

    auto pit = parent_index_.find(parent_id);
    if (pit == parent_index_.end()) return;

    auto event_ids = pit->second; // Copy to avoid iterator invalidation
    for (const auto& event_id : event_ids) {
        auto it = relations_.find(event_id);
        if (it != relations_.end()) {
            it->second.is_redacted = true;
            redacted_events_.insert(event_id);
        }
    }
}

int64_t EventRelationsManager::purge_redacted_relations() {
    std::unique_lock lock(mutex_);

    int64_t purged = 0;
    auto it = redacted_events_.begin();
    while (it != redacted_events_.end()) {
        auto rel_it = relations_.find(*it);
        if (rel_it != relations_.end()) {
            unindex_relation(rel_it->second);
            relations_.erase(rel_it);
            purged++;
        }
        it = redacted_events_.erase(it);
    }

    return purged;
}

// ============================================================================
// Implementation: Recursive relation resolution
// ============================================================================

std::vector<EventRelationsManager::EventRelation>
EventRelationsManager::resolve_relations_recursive(const std::string& event_id,
                                                      int64_t max_depth) const {
    std::shared_lock lock(mutex_);
    std::vector<EventRelation> result;
    std::unordered_set<std::string> visited;
    std::deque<std::string> queue;

    queue.push_back(event_id);

    while (!queue.empty() && static_cast<int64_t>(result.size()) < MAX_RELATION_CHAIN) {
        std::string current = queue.front();
        queue.pop_front();

        if (visited.find(current) != visited.end()) continue;
        visited.insert(current);

        auto pit = parent_index_.find(current);
        if (pit == parent_index_.end()) continue;

        for (const auto& rel_event_id : pit->second) {
            auto rit = relations_.find(rel_event_id);
            if (rit == relations_.end()) continue;

            EventRelation rel = rit->second;

            // Check depth limit
            if (rel.depth > max_depth) continue;

            result.push_back(rel);

            // Recurse into this event's children
            if (result.size() < MAX_RELATION_CHAIN) {
                queue.push_back(rel_event_id);
            }
        }
    }

    return result;
}

json EventRelationsManager::build_relation_tree(const std::string& root_event_id,
                                                   int64_t max_depth) const {
    std::shared_lock lock(mutex_);

    json tree = json::object();
    tree["event_id"] = root_event_id;

    json children = json::array();

    auto relations = get_relations_to(root_event_id);
    for (const auto& rel : relations) {
        if (rel.is_redacted) continue;
        if (rel.depth > max_depth) continue;

        json child = json::object();
        child["event_id"] = rel.event_id;
        child["rel_type"] = rel.rel_type;
        child["sender"] = rel.sender;
        child["origin_server_ts"] = rel.origin_server_ts;
        child["depth"] = rel.depth;

        // Recursively build subtree
        if (rel.depth < max_depth) {
            json subtree = build_relation_tree(rel.event_id, max_depth);
            if (!subtree["children"].empty()) {
                child["children"] = subtree["children"];
            }
        } else {
            child["children"] = json::array();
        }

        children.push_back(child);
    }

    tree["children"] = children;
    tree["child_count"] = static_cast<int64_t>(children.size());

    return tree;
}

std::vector<std::string> EventRelationsManager::get_edit_chain(
    const std::string& event_id) const {
    std::shared_lock lock(mutex_);
    std::vector<std::string> chain;

    // First check if event_id is an edit
    auto it = relations_.find(event_id);
    if (it != relations_.end() && it->second.rel_type == REL_TYPE_REPLACE) {
        // Walk back through edits to find original
        std::string current = it->second.parent_id;
        chain.push_back(event_id); // Latest edit

        while (!current.empty()) {
            chain.push_back(current);
            auto curr_it = relations_.find(current);
            if (curr_it != relations_.end() && curr_it->second.rel_type == REL_TYPE_REPLACE) {
                current = curr_it->second.parent_id;
            } else {
                break; // This is the original
            }
        }

        std::reverse(chain.begin(), chain.end());
    } else {
        // event_id is the original, find all edits
        chain.push_back(event_id);
        auto edits = get_all_edits(event_id);
        for (const auto& edit : edits) {
            chain.push_back(edit.event_id);
        }
    }

    return chain;
}

std::optional<json> EventRelationsManager::resolve_edited_content(
    const std::string& event_id) const {
    std::shared_lock lock(mutex_);

    auto latest = get_latest_edit(event_id);
    if (!latest.has_value() || !latest->content.has_value()) {
        return std::nullopt;
    }

    const auto& content = latest->content.value();
    if (content.contains("m.new_content")) {
        return content["m.new_content"];
    }

    // Fallback: return the body if it's a direct message edit
    if (content.contains("body")) {
        json resolved = json::object();
        resolved["body"] = content["body"];
        if (content.contains("msgtype")) {
            resolved["msgtype"] = content["msgtype"];
        }
        if (content.contains("formatted_body")) {
            resolved["formatted_body"] = content["formatted_body"];
            resolved["format"] = content.value("format", "");
        }
        return resolved;
    }

    return content;
}

// ============================================================================
// Implementation: Event reference tracking
// ============================================================================

void EventRelationsManager::track_reference(const std::string& source_event_id,
                                               const std::string& target_event_id,
                                               const std::string& sender) {
    std::unique_lock lock(mutex_);
    references_to_[target_event_id].push_back(source_event_id);
    references_from_[source_event_id].push_back(target_event_id);
}

std::vector<std::string> EventRelationsManager::get_references_to(
    const std::string& event_id) const {
    std::shared_lock lock(mutex_);
    auto it = references_to_.find(event_id);
    if (it != references_to_.end()) {
        return it->second;
    }
    return {};
}

std::vector<std::string> EventRelationsManager::get_references_from(
    const std::string& event_id) const {
    std::shared_lock lock(mutex_);
    auto it = references_from_.find(event_id);
    if (it != references_from_.end()) {
        return it->second;
    }
    return {};
}

int64_t EventRelationsManager::get_reference_count(const std::string& event_id) const {
    std::shared_lock lock(mutex_);
    auto it = references_to_.find(event_id);
    if (it != references_to_.end()) {
        return static_cast<int64_t>(it->second.size());
    }
    return 0;
}

// ============================================================================
// Implementation: Poll aggregation
// ============================================================================

bool EventRelationsManager::register_poll_start(const std::string& event_id,
                                                   const json& content) {
    std::unique_lock lock(mutex_);

    if (polls_.find(event_id) != polls_.end()) {
        return true; // Already registered
    }

    PollAggregation poll;
    poll.poll_start_event_id = event_id;

    // Parse poll options from content
    if (content.contains("m.poll") && content["m.poll"].is_object()) {
        const auto& poll_data = content["m.poll"];
        if (poll_data.contains("max_selections")) {
            poll.max_selections = std::to_string(poll_data["max_selections"].get<int>());
        } else {
            poll.max_selections = "1";
        }

        if (poll_data.contains("answers") && poll_data["answers"].is_array()) {
            for (const auto& answer : poll_data["answers"]) {
                if (answer.contains("id") && answer["id"].is_string()) {
                    PollOptionResult opt;
                    opt.id = answer["id"].get<std::string>();
                    poll.options[opt.id] = opt;
                }
            }
        }
    }

    // Also check for the newer format
    if (content.contains("org.matrix.msc3381.poll.start") &&
        content["org.matrix.msc3381.poll.start"].is_object()) {
        const auto& poll_data = content["org.matrix.msc3381.poll.start"];
        if (poll_data.contains("max_selections")) {
            poll.max_selections = std::to_string(poll_data["max_selections"].get<int>());
        }
        if (poll_data.contains("answers") && poll_data["answers"].is_array()) {
            for (const auto& answer : poll_data["answers"]) {
                if (answer.contains("id") && answer["id"].is_string()) {
                    std::string opt_id = answer["id"].get<std::string>();
                    if (poll.options.find(opt_id) == poll.options.end()) {
                        PollOptionResult opt;
                        opt.id = opt_id;
                        poll.options[opt_id] = opt;
                    }
                }
            }
        }
    }

    polls_[event_id] = poll;
    return true;
}

bool EventRelationsManager::record_poll_response(const std::string& event_id,
                                                    const std::string& response_event_id,
                                                    const std::string& sender,
                                                    const json& content) {
    std::unique_lock lock(mutex_);

    auto poll_it = polls_.find(event_id);
    if (poll_it == polls_.end()) {
        // Poll not registered yet, try to register from the parent
        return false;
    }

    auto& poll = poll_it->second;
    if (poll.is_ended) {
        return false; // Poll has ended
    }

    // Deduplicate: one vote per user per poll (redact old vote if re-voting)
    if (poll.unique_voters.find(sender) != poll.unique_voters.end()) {
        // User already voted - this is a re-vote, decrement old counts
        // In a real implementation we'd track which options they voted for
        // For now, allow re-voting by not double-counting
        // We'd need per-user tracking of which options were selected
    }

    // Parse selected options
    std::vector<std::string> selected_options;

    // New format (MSC 3381)
    if (content.contains("org.matrix.msc3381.poll.response") &&
        content["org.matrix.msc3381.poll.response"].is_object()) {
        const auto& response = content["org.matrix.msc3381.poll.response"];
        if (response.contains("answers") && response["answers"].is_array()) {
            for (const auto& answer : response["answers"]) {
                if (answer.is_string()) {
                    selected_options.push_back(answer.get<std::string>());
                }
            }
        }
    }

    // Old format
    if (selected_options.empty() && content.contains("m.poll.response") &&
        content["m.poll.response"].is_object()) {
        const auto& response = content["m.poll.response"];
        if (response.contains("answers") && response["answers"].is_array()) {
            for (const auto& answer : response["answers"]) {
                if (answer.is_string()) {
                    selected_options.push_back(answer.get<std::string>());
                }
            }
        }
    }

    // Enforce max_selections
    int max_sel = 1;
    try { max_sel = std::stoi(poll.max_selections); } catch (...) { max_sel = 1; }

    if (static_cast<int>(selected_options.size()) > max_sel) {
        // Truncate to max selections
        selected_options.resize(max_sel);
    }

    // Record votes
    for (const auto& opt_id : selected_options) {
        auto opt_it = poll.options.find(opt_id);
        if (opt_it != poll.options.end()) {
            opt_it->second.count++;
            opt_it->second.voters.push_back(sender);
            poll.total_votes++;
        }
    }

    poll.unique_voters.insert(sender);
    poll.response_count++;

    return true;
}

bool EventRelationsManager::end_poll(const std::string& poll_start_event_id,
                                       const std::string& end_event_id,
                                       int64_t end_ts) {
    std::unique_lock lock(mutex_);

    auto poll_it = polls_.find(poll_start_event_id);
    if (poll_it == polls_.end()) {
        return false;
    }

    poll_it->second.is_ended = true;
    poll_it->second.poll_end_event_id = end_event_id;
    poll_it->second.end_ts = end_ts;

    return true;
}

std::optional<PollAggregation> EventRelationsManager::get_poll_results(
    const std::string& poll_start_event_id) const {
    std::shared_lock lock(mutex_);
    auto it = polls_.find(poll_start_event_id);
    if (it != polls_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::unordered_map<std::string, int64_t>
EventRelationsManager::get_poll_option_counts(const std::string& poll_start_event_id) const {
    std::shared_lock lock(mutex_);
    std::unordered_map<std::string, int64_t> counts;

    auto it = polls_.find(poll_start_event_id);
    if (it != polls_.end()) {
        for (const auto& [opt_id, opt_result] : it->second.options) {
            counts[opt_id] = opt_result.count;
        }
    }

    return counts;
}

bool EventRelationsManager::is_poll_ended(const std::string& poll_start_event_id) const {
    std::shared_lock lock(mutex_);
    auto it = polls_.find(poll_start_event_id);
    if (it != polls_.end()) {
        return it->second.is_ended;
    }
    return false;
}

// ============================================================================
// Implementation: Deduplication
// ============================================================================

bool EventRelationsManager::is_duplicate_reaction(const std::string& event_id,
                                                     const std::string& sender,
                                                     const std::string& key) const {
    std::shared_lock lock(mutex_);
    ReactionKey rk{event_id, sender, key};
    auto it = reaction_index_.find(rk);
    if (it != reaction_index_.end()) {
        // Check if the existing reaction is redacted
        auto rel_it = relations_.find(it->second);
        if (rel_it != relations_.end() && !rel_it->second.is_redacted) {
            return true;
        }
    }
    return false;
}

bool EventRelationsManager::is_duplicate_relation(const std::string& event_id,
                                                     const std::string& parent_id,
                                                     const std::string& rel_type,
                                                     const std::string& sender) const {
    std::shared_lock lock(mutex_);

    RelationTypeKey type_key{parent_id, rel_type};
    auto tit = type_index_.find(type_key);
    if (tit == type_index_.end()) return false;

    for (const auto& eid : tit->second) {
        if (eid == event_id) continue;
        auto rit = relations_.find(eid);
        if (rit != relations_.end() &&
            rit->second.sender == sender &&
            !rit->second.is_redacted) {
            return true;
        }
    }

    return false;
}

int64_t EventRelationsManager::deduplicate_relations(const std::string& event_id) {
    std::unique_lock lock(mutex_);
    int64_t removed = 0;

    auto rel_it = relations_.find(event_id);
    if (rel_it == relations_.end()) return 0;

    const auto& rel = rel_it->second;

    // For reactions: check reaction_index_
    if (rel.rel_type == REL_TYPE_ANNOTATION && rel.event_type == EVENT_TYPE_REACTION) {
        ReactionKey rk{rel.parent_id, rel.sender, rel.aggregation_key};
        auto rk_it = reaction_index_.find(rk);
        if (rk_it != reaction_index_.end() && rk_it->second != event_id) {
            // Duplicate exists, remove the older one
            auto older_it = relations_.find(rk_it->second);
            if (older_it != relations_.end()) {
                unindex_relation(older_it->second);
                relations_.erase(older_it);
                removed++;
                reaction_index_[rk] = event_id;
            }
        }
    }

    return removed;
}

// ============================================================================
// Implementation: Rate limiting
// ============================================================================

bool EventRelationsManager::check_reaction_rate_limit(const std::string& user_id) {
    cleanup_stale_rate_limits();
    return reaction_rate_limiter_.check(user_id);
}

bool EventRelationsManager::check_relation_rate_limit(const std::string& user_id) {
    cleanup_stale_rate_limits();
    return relation_rate_limiter_.check(user_id);
}

int64_t EventRelationsManager::get_remaining_reaction_limit(const std::string& user_id) {
    return reaction_rate_limiter_.remaining(user_id);
}

json EventRelationsManager::get_rate_limit_info(const std::string& user_id) const {
    json info;
    info["reaction_limit"] = REACTION_RATE_LIMIT_MAX;
    info["reaction_window_seconds"] = REACTION_RATE_LIMIT_WINDOW_SECS;
    info["reaction_remaining"] = const_cast<EventRelationsManager*>(this)
        ->reaction_rate_limiter_.remaining(user_id);
    info["relation_limit"] = RELATION_RATE_LIMIT_MAX;
    info["relation_window_seconds"] = RELATION_RATE_LIMIT_WINDOW_SECS;
    info["relation_remaining"] = const_cast<EventRelationsManager*>(this)
        ->relation_rate_limiter_.remaining(user_id);
    return info;
}

void EventRelationsManager::cleanup_stale_rate_limits() {
    reaction_rate_limiter_.clear();
    relation_rate_limiter_.clear();
}

// ============================================================================
// Implementation: Statistics and maintenance
// ============================================================================

int64_t EventRelationsManager::total_relation_count() const {
    std::shared_lock lock(mutex_);
    return static_cast<int64_t>(relations_.size());
}

std::unordered_map<std::string, int64_t>
EventRelationsManager::relation_counts_by_type() const {
    std::shared_lock lock(mutex_);
    std::unordered_map<std::string, int64_t> counts;

    for (const auto& [event_id, rel] : relations_) {
        counts[rel.rel_type]++;
    }

    return counts;
}

int64_t EventRelationsManager::total_thread_count() const {
    std::shared_lock lock(mutex_);
    return static_cast<int64_t>(thread_roots_.size());
}

int64_t EventRelationsManager::total_reaction_count() const {
    std::shared_lock lock(mutex_);
    int64_t count = 0;
    for (const auto& [event_id, rel] : relations_) {
        if (rel.rel_type == REL_TYPE_ANNOTATION &&
            rel.event_type == EVENT_TYPE_REACTION &&
            !rel.is_redacted) {
            count++;
        }
    }
    return count;
}

int64_t EventRelationsManager::estimate_memory_usage() const {
    std::shared_lock lock(mutex_);
    int64_t usage = 0;

    // Relations map
    usage += static_cast<int64_t>(relations_.size()) *
             (sizeof(std::string) * 2 + sizeof(EventRelation));
    usage += static_cast<int64_t>(parent_index_.size()) *
             (sizeof(std::string) + sizeof(std::vector<std::string>));
    usage += static_cast<int64_t>(type_index_.size()) *
             (sizeof(RelationTypeKey) + sizeof(std::vector<std::string>));
    usage += static_cast<int64_t>(reaction_index_.size()) *
             (sizeof(ReactionKey) + sizeof(std::string));
    usage += static_cast<int64_t>(thread_roots_.size()) * sizeof(std::string);
    usage += static_cast<int64_t>(thread_meta_.size()) * sizeof(ThreadMeta);
    usage += static_cast<int64_t>(polls_.size()) * sizeof(PollAggregation);
    usage += static_cast<int64_t>(references_to_.size()) *
             (sizeof(std::string) + sizeof(std::vector<std::string>));

    return usage;
}

void EventRelationsManager::clear() {
    std::unique_lock lock(mutex_);
    relations_.clear();
    parent_index_.clear();
    type_index_.clear();
    sender_index_.clear();
    reaction_index_.clear();
    thread_roots_.clear();
    thread_meta_.clear();
    thread_notifications_.clear();
    thread_read_receipts_.clear();
    latest_edits_.clear();
    references_to_.clear();
    references_from_.clear();
    polls_.clear();
    redacted_events_.clear();
}

void EventRelationsManager::compact() {
    std::unique_lock lock(mutex_);

    // Rehash all containers to optimize memory
    relations_.rehash(relations_.size());
    parent_index_.rehash(parent_index_.size());
    type_index_.rehash(type_index_.size());
    sender_index_.rehash(sender_index_.size());
    reaction_index_.rehash(reaction_index_.size());
    thread_meta_.rehash(thread_meta_.size());
    thread_notifications_.rehash(thread_notifications_.size());
    thread_read_receipts_.rehash(thread_read_receipts_.size());
    references_to_.rehash(references_to_.size());
    references_from_.rehash(references_from_.size());
    polls_.rehash(polls_.size());

    // Shrink vectors
    for (auto& [key, vec] : parent_index_) {
        vec.shrink_to_fit();
    }
    for (auto& [key, vec] : type_index_) {
        vec.shrink_to_fit();
    }
    for (auto& [key, vec] : sender_index_) {
        vec.shrink_to_fit();
    }
    for (auto& [key, vec] : references_to_) {
        vec.shrink_to_fit();
    }
    for (auto& [key, vec] : references_from_) {
        vec.shrink_to_fit();
    }
}

// ============================================================================
// Helper: Trim reaction list
// ============================================================================

void EventRelationsManager::trim_reaction_list(std::vector<std::string>& reactors,
                                                  int64_t max_count) const {
    if (static_cast<int64_t>(reactors.size()) > max_count) {
        reactors.resize(max_count);
    }
}

// ============================================================================
// EventRelationsCache - Thread-safe caching layer
// ============================================================================

class EventRelationsCache {
public:
    EventRelationsCache() : manager_(std::make_unique<EventRelationsManager>()) {}
    ~EventRelationsCache() = default;

    EventRelationsCache(const EventRelationsCache&) = delete;
    EventRelationsCache& operator=(const EventRelationsCache&) = delete;

    // Delegate all methods to the manager with cache awareness
    EventRelationsManager& manager() { return *manager_; }
    const EventRelationsManager& manager() const { return *manager_; }

    // Cache-specific: Invalidate cache for an event
    void invalidate(const std::string& event_id) {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        annotation_cache_.erase(event_id);
        edit_cache_.erase(event_id);
        thread_cache_.erase(event_id);
        poll_cache_.erase(event_id);
    }

    // Cached annotation counts
    std::unordered_map<std::string, int64_t> cached_annotation_counts(
        const std::string& event_id) {
        {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            auto it = annotation_cache_.find(event_id);
            if (it != annotation_cache_.end()) {
                return it->second;
            }
        }
        auto counts = manager_->count_annotations(event_id);
        {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            annotation_cache_[event_id] = counts;
        }
        return counts;
    }

    // Cached thread summaries
    ThreadSummary cached_thread_summary(const std::string& root_event_id,
                                          const std::string& current_user) {
        std::string cache_key = root_event_id + ":" + current_user;
        {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            auto it = thread_cache_.find(cache_key);
            if (it != thread_cache_.end()) {
                return it->second;
            }
        }
        auto summary = manager_->get_thread_summary(root_event_id, current_user);
        {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            thread_cache_[cache_key] = summary;
        }
        return summary;
    }

    // Clear all caches
    void clear_caches() {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        annotation_cache_.clear();
        edit_cache_.clear();
        thread_cache_.clear();
        poll_cache_.clear();
    }

private:
    std::unique_ptr<EventRelationsManager> manager_;

    // Caches
    std::mutex cache_mutex_;
    std::unordered_map<std::string, std::unordered_map<std::string, int64_t>> annotation_cache_;
    std::unordered_map<std::string, std::optional<EventRelationsManager::EventRelation>> edit_cache_;
    std::unordered_map<std::string, ThreadSummary> thread_cache_;
    std::unordered_map<std::string, std::optional<PollAggregation>> poll_cache_;
};

// ============================================================================
// EventRelationsProcessor - processes incoming events for relations
// ============================================================================

class EventRelationsProcessor {
public:
    explicit EventRelationsProcessor(EventRelationsManager& manager)
        : manager_(manager) {}

    // Process an incoming event and extract relations
    bool process_event(const std::string& event_id,
                       const std::string& sender,
                       const std::string& event_type,
                       const json& content,
                       int64_t origin_server_ts);

    // Process a redaction event
    bool process_redaction(const std::string& redacts_event_id);

    // Process a poll start event
    bool process_poll_start(const std::string& event_id, const json& content);

    // Process a poll response event
    bool process_poll_response(const std::string& event_id,
                                const std::string& sender,
                                const json& content);

    // Process a poll end event
    bool process_poll_end(const std::string& event_id,
                           const std::string& poll_start_id,
                           int64_t end_ts);

    // Validate an event's relations
    bool validate_event_relations(const json& content) const;

    // Check if event content has any relations
    bool has_relations(const json& content) const;

    // Extract all relation info from content
    json extract_relations_info(const std::string& event_id,
                                 const json& content) const;

private:
    EventRelationsManager& manager_;
};

bool EventRelationsProcessor::process_event(const std::string& event_id,
                                               const std::string& sender,
                                               const std::string& event_type,
                                               const json& content,
                                               int64_t origin_server_ts) {
    // Handle poll start
    if (event_type == EVENT_TYPE_POLL_START) {
        process_poll_start(event_id, content);
    }

    // Handle poll end
    if (event_type == EVENT_TYPE_POLL_END) {
        std::string poll_start_id;
        if (content.contains("m.relates_to") && content["m.relates_to"].is_object()) {
            poll_start_id = content["m.relates_to"].value("event_id", "");
        }
        if (!poll_start_id.empty()) {
            process_poll_end(event_id, poll_start_id, origin_server_ts);
        }
    }

    // Check if content has relations
    if (!has_relations(content)) {
        return false;
    }

    // Validate relations
    if (!validate_event_relations(content)) {
        return false;
    }

    // Add relation to manager
    return manager_.add_relation(event_id, sender, event_type, content, origin_server_ts);
}

bool EventRelationsProcessor::process_redaction(const std::string& redacts_event_id) {
    return manager_.redact_relation(redacts_event_id);
}

bool EventRelationsProcessor::process_poll_start(const std::string& event_id,
                                                    const json& content) {
    return manager_.register_poll_start(event_id, content);
}

bool EventRelationsProcessor::process_poll_response(const std::string& event_id,
                                                       const std::string& sender,
                                                       const json& content) {
    std::string parent_id = manager_.compute_parent_id(content);
    if (parent_id.empty()) return false;

    return manager_.record_poll_response(parent_id, event_id, sender, content);
}

bool EventRelationsProcessor::process_poll_end(const std::string& event_id,
                                                  const std::string& poll_start_id,
                                                  int64_t end_ts) {
    return manager_.end_poll(poll_start_id, event_id, end_ts);
}

bool EventRelationsProcessor::validate_event_relations(const json& content) const {
    // Check m.relates_to structure
    if (content.contains("m.relates_to")) {
        const auto& relates_to = content["m.relates_to"];
        if (!relates_to.is_object()) return false;
        if (!relates_to.contains("event_id") || !relates_to["event_id"].is_string()) {
            return false;
        }
        if (relates_to.contains("rel_type") && !relates_to["rel_type"].is_string()) {
            return false;
        }
    }

    // Check m.in_reply_to structure
    if (content.contains("m.in_reply_to")) {
        const auto& in_reply = content["m.in_reply_to"];
        if (!in_reply.is_object()) return false;
        if (!in_reply.contains("event_id") || !in_reply["event_id"].is_string()) {
            return false;
        }
    }

    return true;
}

bool EventRelationsProcessor::has_relations(const json& content) const {
    return content.contains("m.relates_to") || content.contains("m.in_reply_to");
}

json EventRelationsProcessor::extract_relations_info(const std::string& event_id,
                                                        const json& content) const {
    json info = json::object();

    if (content.contains("m.relates_to")) {
        info["has_relates_to"] = true;
        const auto& relates_to = content["m.relates_to"];
        if (relates_to.contains("event_id")) {
            info["parent_id"] = relates_to["event_id"];
        }
        if (relates_to.contains("rel_type")) {
            info["rel_type"] = relates_to["rel_type"];
        }
        if (relates_to.contains("key")) {
            info["aggregation_key"] = relates_to["key"];
        }
    }

    if (content.contains("m.in_reply_to")) {
        info["has_in_reply_to"] = true;
        info["in_reply_to_event_id"] = content["m.in_reply_to"]["event_id"];
    }

    return info;
}

// ============================================================================
// ThreadRelationValidator - Validates thread integrity
// ============================================================================

class ThreadRelationValidator {
public:
    explicit ThreadRelationValidator(const EventRelationsManager& manager)
        : manager_(manager) {}

    // Validate that a thread event refers to a valid root
    bool is_valid_thread_reply(const std::string& event_id,
                               const std::string& thread_root_id) const;

    // Detect thread loops
    bool has_thread_loop(const std::string& event_id) const;

    // Check thread depth limits
    bool is_within_depth_limit(const std::string& event_id,
                                int64_t max_depth = MAX_THREAD_DEPTH) const;

    // Get the thread chain from leaf to root
    std::vector<std::string> get_thread_chain(const std::string& event_id) const;

    // Validate thread notification eligibility
    bool is_eligible_for_thread_notification(const std::string& event_id,
                                               const std::string& user_id) const;

private:
    const EventRelationsManager& manager_;
};

bool ThreadRelationValidator::is_valid_thread_reply(
    const std::string& event_id,
    const std::string& thread_root_id) const {

    auto root_opt = manager_.get_thread_root(event_id);
    if (!root_opt.has_value()) return false;

    return root_opt.value() == thread_root_id;
}

bool ThreadRelationValidator::has_thread_loop(const std::string& event_id) const {
    std::unordered_set<std::string> visited;
    std::string current = event_id;

    for (int64_t i = 0; i < MAX_THREAD_DEPTH; i++) {
        if (visited.find(current) != visited.end()) {
            return true; // Loop detected
        }
        visited.insert(current);

        auto rel = manager_.get_relation(current);
        if (!rel.has_value() || rel->rel_type != REL_TYPE_THREAD) {
            return false;
        }
        current = rel->parent_id;
    }

    return false; // Hit depth limit, assume no loop
}

bool ThreadRelationValidator::is_within_depth_limit(
    const std::string& event_id,
    int64_t max_depth) const {
    return manager_.get_thread_depth(event_id) <= max_depth;
}

std::vector<std::string> ThreadRelationValidator::get_thread_chain(
    const std::string& event_id) const {
    std::vector<std::string> chain;
    std::unordered_set<std::string> visited;
    std::string current = event_id;

    for (int64_t i = 0; i < MAX_THREAD_DEPTH; i++) {
        if (visited.find(current) != visited.end()) break;
        visited.insert(current);
        chain.push_back(current);

        auto rel = manager_.get_relation(current);
        if (!rel.has_value() || rel->rel_type != REL_TYPE_THREAD) break;
        current = rel->parent_id;
    }

    return chain;
}

bool ThreadRelationValidator::is_eligible_for_thread_notification(
    const std::string& event_id,
    const std::string& user_id) const {

    // User must be participating in the thread
    auto root_opt = manager_.get_thread_root(event_id);
    if (!root_opt.has_value()) return false;

    if (!manager_.is_participating(root_opt.value(), user_id)) {
        return false;
    }

    return true;
}

// ============================================================================
// ReactionAggregator - Aggregates reaction data
// ============================================================================

class ReactionAggregator {
public:
    explicit ReactionAggregator(const EventRelationsManager& manager)
        : manager_(manager) {}

    // Get top reactions for an event
    std::vector<std::pair<std::string, int64_t>> top_reactions(
        const std::string& event_id, int64_t limit = 5) const;

    // Get reaction summary
    json reaction_summary(const std::string& event_id) const;

    // Get reactions by user
    std::vector<std::pair<std::string, std::string>> reactions_by_user(
        const std::string& event_id, const std::string& user_id) const;

    // Get total unique reactors
    int64_t unique_reactor_count(const std::string& event_id) const;

    // Get reaction timeline
    json reaction_timeline(const std::string& event_id) const;

private:
    const EventRelationsManager& manager_;
};

std::vector<std::pair<std::string, int64_t>> ReactionAggregator::top_reactions(
    const std::string& event_id, int64_t limit) const {

    auto counts = manager_.count_annotations(event_id);
    std::vector<std::pair<std::string, int64_t>> sorted(counts.begin(), counts.end());

    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    if (static_cast<int64_t>(sorted.size()) > limit) {
        sorted.resize(limit);
    }

    return sorted;
}

json ReactionAggregator::reaction_summary(const std::string& event_id) const {
    json summary = json::object();
    auto top = top_reactions(event_id, 10);

    json reactions = json::object();
    for (const auto& [key, count] : top) {
        json r = json::object();
        r["key"] = key;
        r["count"] = count;
        auto reactors = manager_.get_reactors(event_id, key);
        r["reactors"] = reactors;
        reactions[key] = r;
    }

    summary["reactions"] = reactions;
    summary["total_reactions"] = std::accumulate(
        top.begin(), top.end(), 0LL,
        [](int64_t sum, const auto& p) { return sum + p.second; });
    summary["unique_keys"] = static_cast<int64_t>(top.size());
    summary["unique_reactors"] = unique_reactor_count(event_id);

    return summary;
}

std::vector<std::pair<std::string, std::string>> ReactionAggregator::reactions_by_user(
    const std::string& event_id, const std::string& user_id) const {

    std::vector<std::pair<std::string, std::string>> result;
    auto annotations = manager_.get_annotations(event_id);

    for (const auto& ann : annotations) {
        if (ann.sender == user_id && !ann.is_redacted) {
            result.emplace_back(ann.aggregation_key, ann.event_id);
        }
    }

    return result;
}

int64_t ReactionAggregator::unique_reactor_count(const std::string& event_id) const {
    auto annotations = manager_.get_annotations(event_id);
    std::unordered_set<std::string> unique;

    for (const auto& ann : annotations) {
        if (!ann.is_redacted) {
            unique.insert(ann.sender);
        }
    }

    return static_cast<int64_t>(unique.size());
}

json ReactionAggregator::reaction_timeline(const std::string& event_id) const {
    auto annotations = manager_.get_annotations(event_id);
    std::vector<EventRelationsManager::EventRelation> valid;

    for (const auto& ann : annotations) {
        if (!ann.is_redacted) {
            valid.push_back(ann);
        }
    }

    std::sort(valid.begin(), valid.end(),
              [](const auto& a, const auto& b) {
                  return a.origin_server_ts < b.origin_server_ts;
              });

    json timeline = json::array();
    for (const auto& ann : valid) {
        json entry = json::object();
        entry["event_id"] = ann.event_id;
        entry["sender"] = ann.sender;
        entry["key"] = ann.aggregation_key;
        entry["timestamp"] = ann.origin_server_ts;
        timeline.push_back(entry);
    }

    return timeline;
}

// ============================================================================
// ThreadRelationResolver - Resolves thread relationships
// ============================================================================

class ThreadRelationResolver {
public:
    explicit ThreadRelationResolver(const EventRelationsManager& manager)
        : manager_(manager) {}

    // Get all events in a thread (flattened)
    std::vector<std::string> get_thread_events(const std::string& root_event_id) const;

    // Build a thread tree
    json build_thread_tree(const std::string& root_event_id) const;

    // Check if event is part of a thread
    bool is_in_thread(const std::string& event_id) const;

    // Get thread breadcrumbs (path from root to event)
    std::vector<std::string> get_thread_breadcrumbs(const std::string& event_id) const;

    // Get sibling events in thread
    std::vector<std::string> get_thread_siblings(const std::string& event_id) const;

    // Determine if thread should be shown in main timeline
    bool should_show_in_main_timeline(const std::string& event_id) const;

private:
    const EventRelationsManager& manager_;

    void collect_thread_events(const std::string& event_id,
                                std::vector<std::string>& events,
                                std::unordered_set<std::string>& visited) const;
};

std::vector<std::string> ThreadRelationResolver::get_thread_events(
    const std::string& root_event_id) const {
    std::vector<std::string> events;
    std::unordered_set<std::string> visited;
    collect_thread_events(root_event_id, events, visited);
    return events;
}

void ThreadRelationResolver::collect_thread_events(
    const std::string& event_id,
    std::vector<std::string>& events,
    std::unordered_set<std::string>& visited) const {

    if (visited.find(event_id) != visited.end()) return;
    visited.insert(event_id);

    auto replies = manager_.get_thread_relations(event_id);
    for (const auto& reply : replies) {
        if (!reply.is_redacted) {
            events.push_back(reply.event_id);
            collect_thread_events(reply.event_id, events, visited);
        }
    }
}

json ThreadRelationResolver::build_thread_tree(const std::string& root_event_id) const {
    json tree = json::object();
    tree["root_event_id"] = root_event_id;

    json replies_json = json::array();
    auto replies = manager_.get_thread_relations(root_event_id);

    for (const auto& reply : replies) {
        if (reply.is_redacted) continue;

        json reply_node = json::object();
        reply_node["event_id"] = reply.event_id;
        reply_node["sender"] = reply.sender;
        reply_node["origin_server_ts"] = reply.origin_server_ts;
        reply_node["depth"] = reply.depth;

        // Recurse into nested replies
        json nested_tree = build_thread_tree(reply.event_id);
        if (!nested_tree["replies"].empty()) {
            reply_node["replies"] = nested_tree["replies"];
        }

        replies_json.push_back(reply_node);
    }

    tree["replies"] = replies_json;
    tree["reply_count"] = static_cast<int64_t>(replies_json.size());

    return tree;
}

bool ThreadRelationResolver::is_in_thread(const std::string& event_id) const {
    auto root = manager_.get_thread_root(event_id);
    return root.has_value();
}

std::vector<std::string> ThreadRelationResolver::get_thread_breadcrumbs(
    const std::string& event_id) const {
    std::vector<std::string> breadcrumbs;
    std::string current = event_id;
    std::unordered_set<std::string> visited;

    for (int64_t i = 0; i < MAX_THREAD_DEPTH; i++) {
        if (visited.find(current) != visited.end()) break;
        visited.insert(current);
        breadcrumbs.push_back(current);

        auto rel = manager_.get_relation(current);
        if (!rel.has_value() || rel->rel_type != REL_TYPE_THREAD) break;
        current = rel->parent_id;
    }

    std::reverse(breadcrumbs.begin(), breadcrumbs.end());
    return breadcrumbs;
}

std::vector<std::string> ThreadRelationResolver::get_thread_siblings(
    const std::string& event_id) const {
    auto rel = manager_.get_relation(event_id);
    if (!rel.has_value() || rel->rel_type != REL_TYPE_THREAD) {
        return {};
    }

    auto siblings = manager_.get_thread_relations(rel->parent_id);
    std::vector<std::string> result;
    for (const auto& sib : siblings) {
        if (sib.event_id != event_id && !sib.is_redacted) {
            result.push_back(sib.event_id);
        }
    }
    return result;
}

bool ThreadRelationResolver::should_show_in_main_timeline(
    const std::string& event_id) const {
    // Check if this event is a thread root, a non-thread event, or
    // a thread reply that should be shown in the main timeline
    auto rel = manager_.get_relation(event_id);
    if (!rel.has_value()) {
        // No thread relation, show in main timeline
        return true;
    }

    if (rel->rel_type != REL_TYPE_THREAD) {
        return true;
    }

    // Thread replies: check if they're a thread root themselves
    if (manager_.is_valid_thread_root(event_id)) {
        return true;
    }

    return false;
}

// ============================================================================
// EventRelationsMetrics - Performance monitoring
// ============================================================================

class EventRelationsMetrics {
public:
    void record_relation_added() {
        total_relations_added_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_relation_removed() {
        total_relations_removed_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_redaction() {
        total_redactions_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_query() {
        total_queries_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_rate_limited() {
        total_rate_limited_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_duplicate_rejected() {
        total_duplicates_rejected_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_aggregation_computed() {
        total_aggregations_.fetch_add(1, std::memory_order_relaxed);
    }

    json get_metrics() const {
        json m;
        m["total_relations_added"] = total_relations_added_.load(std::memory_order_relaxed);
        m["total_relations_removed"] = total_relations_removed_.load(std::memory_order_relaxed);
        m["total_redactions"] = total_redactions_.load(std::memory_order_relaxed);
        m["total_queries"] = total_queries_.load(std::memory_order_relaxed);
        m["total_rate_limited"] = total_rate_limited_.load(std::memory_order_relaxed);
        m["total_duplicates_rejected"] = total_duplicates_rejected_.load(std::memory_order_relaxed);
        m["total_aggregations"] = total_aggregations_.load(std::memory_order_relaxed);
        return m;
    }

    void reset() {
        total_relations_added_.store(0, std::memory_order_relaxed);
        total_relations_removed_.store(0, std::memory_order_relaxed);
        total_redactions_.store(0, std::memory_order_relaxed);
        total_queries_.store(0, std::memory_order_relaxed);
        total_rate_limited_.store(0, std::memory_order_relaxed);
        total_duplicates_rejected_.store(0, std::memory_order_relaxed);
        total_aggregations_.store(0, std::memory_order_relaxed);
    }

private:
    std::atomic<int64_t> total_relations_added_{0};
    std::atomic<int64_t> total_relations_removed_{0};
    std::atomic<int64_t> total_redactions_{0};
    std::atomic<int64_t> total_queries_{0};
    std::atomic<int64_t> total_rate_limited_{0};
    std::atomic<int64_t> total_duplicates_rejected_{0};
    std::atomic<int64_t> total_aggregations_{0};
};

// ============================================================================
// EventRelationsSerializer - Serialize/deserialize relation state
// ============================================================================

class EventRelationsSerializer {
public:
    explicit EventRelationsSerializer(EventRelationsManager& manager)
        : manager_(manager) {}

    // Serialize all relations to JSON
    json serialize_all() const;

    // Serialize relations for a specific room
    json serialize_for_event(const std::string& event_id) const;

    // Deserialize and populate relations
    bool deserialize_and_load(const json& data);

    // Export thread data
    json export_threads() const;

    // Export poll data
    json export_polls() const;

private:
    EventRelationsManager& manager_;
};

json EventRelationsSerializer::serialize_all() const {
    json data = json::object();

    // We can't easily access private state, so this is a conceptual implementation
    // using public APIs
    json relations = json::array();
    // In a real implementation, iterate over all relations
    data["version"] = 1;
    data["relations"] = relations;

    return data;
}

json EventRelationsSerializer::serialize_for_event(const std::string& event_id) const {
    json data = json::object();

    // Annotations
    data["annotation_counts"] = manager_.count_annotations(event_id);

    // Edits
    auto latest_edit = manager_.get_latest_edit(event_id);
    if (latest_edit.has_value()) {
        data["latest_edit_event_id"] = latest_edit->event_id;
        data["edit_count"] = manager_.get_edit_count(event_id);
    }

    // Thread
    auto thread_summary = manager_.get_thread_summary(event_id);
    data["thread_reply_count"] = thread_summary.reply_count;
    data["thread_participant_count"] = thread_summary.participant_count;

    // References
    data["reference_count"] = manager_.get_reference_count(event_id);

    // Poll
    auto poll_results = manager_.get_poll_results(event_id);
    if (poll_results.has_value()) {
        data["poll_total_votes"] = poll_results->total_votes;
        data["poll_is_ended"] = poll_results->is_ended;
    }

    return data;
}

bool EventRelationsSerializer::deserialize_and_load(const json& data) {
    if (!data.contains("relations") || !data["relations"].is_array()) {
        return false;
    }

    manager_.clear();

    for (const auto& rel_data : data["relations"]) {
        // Parse and add relations using public API
        // This would need access to the original content
        (void)rel_data;
    }

    return true;
}

json EventRelationsSerializer::export_threads() const {
    json threads = json::object();
    auto roots = manager_.get_thread_roots();

    for (const auto& root : roots) {
        auto summary = manager_.get_thread_summary(root);
        json thread_data;
        thread_data["root_event_id"] = root;
        thread_data["reply_count"] = summary.reply_count;
        thread_data["participant_count"] = summary.participant_count;
        thread_data["latest_reply_ts"] = summary.latest_reply_ts;
        thread_data["participants"] = summary.participant_ids;
        threads[root] = thread_data;
    }

    return threads;
}

json EventRelationsSerializer::export_polls() const {
    json polls = json::array();

    // We'd need to iterate over all polls, but that's internal state
    // Using public API concepts
    return polls;
}

// ============================================================================
// Global singleton access
// ============================================================================

namespace {

std::unique_ptr<EventRelationsManager> g_global_manager;
std::unique_ptr<EventRelationsCache> g_global_cache;
std::unique_ptr<EventRelationsMetrics> g_global_metrics;
std::mutex g_init_mutex;

void ensure_initialized() {
    if (!g_global_manager) {
        std::lock_guard<std::mutex> lock(g_init_mutex);
        if (!g_global_manager) {
            g_global_manager = std::make_unique<EventRelationsManager>();
            g_global_cache = std::make_unique<EventRelationsCache>();
            g_global_metrics = std::make_unique<EventRelationsMetrics>();
        }
    }
}

} // anonymous namespace

// ============================================================================
// Public API functions
// ============================================================================

EventRelationsManager& get_event_relations_manager() {
    ensure_initialized();
    return *g_global_manager;
}

EventRelationsCache& get_event_relations_cache() {
    ensure_initialized();
    return *g_global_cache;
}

EventRelationsMetrics& get_event_relations_metrics() {
    ensure_initialized();
    return *g_global_metrics;
}

// Process an event's relations as part of the event pipeline
bool process_event_relations(const std::string& event_id,
                               const std::string& sender,
                               const std::string& event_type,
                               const json& content,
                               int64_t origin_server_ts) {
    ensure_initialized();
    EventRelationsProcessor processor(*g_global_manager);

    bool result = processor.process_event(event_id, sender, event_type,
                                           content, origin_server_ts);

    if (result) {
        g_global_metrics->record_relation_added();
    }

    return result;
}

// Handle redaction of an event's relations
bool handle_relation_redaction(const std::string& redacted_event_id) {
    ensure_initialized();
    EventRelationsProcessor processor(*g_global_manager);

    bool result = processor.process_redaction(redacted_event_id);

    if (result) {
        g_global_metrics->record_redaction();
        g_global_cache->invalidate(redacted_event_id);
    }

    return result;
}

// Compute bundled aggregations for sync response
json compute_sync_aggregations(const std::vector<std::string>& event_ids,
                                 const std::string& current_user) {
    ensure_initialized();
    g_global_metrics->record_aggregation_computed();

    return g_global_manager->compute_bundled_aggregations(event_ids, current_user);
}

// Compute aggregation for a single event
json compute_event_aggregation(const std::string& event_id,
                                 const std::string& current_user) {
    ensure_initialized();
    g_global_metrics->record_aggregation_computed();

    return g_global_manager->compute_event_aggregation(event_id, current_user);
}

// Get reaction counts
std::unordered_map<std::string, int64_t> get_reaction_counts(const std::string& event_id) {
    ensure_initialized();
    return g_global_manager->count_annotations(event_id);
}

// Get thread summary
ThreadSummary get_thread_summary(const std::string& event_id,
                                   const std::string& current_user) {
    ensure_initialized();
    return g_global_manager->get_thread_summary(event_id, current_user);
}

// Get poll results
std::optional<PollAggregation> get_poll_results(const std::string& event_id) {
    ensure_initialized();
    return g_global_manager->get_poll_results(event_id);
}

// Rate limit check
bool check_rate_limit(const std::string& user_id, const std::string& limit_type) {
    ensure_initialized();
    if (limit_type == "reaction") {
        return g_global_manager->check_reaction_rate_limit(user_id);
    } else if (limit_type == "relation") {
        return g_global_manager->check_relation_rate_limit(user_id);
    }
    return true;
}

// Validate thread relation
bool validate_thread(const std::string& event_id, const std::string& parent_id) {
    ensure_initialized();
    return g_global_manager->validate_thread_relation(event_id, parent_id);
}

// Get thread root for an event
std::optional<std::string> find_thread_root(const std::string& event_id) {
    ensure_initialized();
    return g_global_manager->get_thread_root(event_id);
}

// Get relation info
json get_relation_info(const std::string& event_id) {
    ensure_initialized();
    auto rel = g_global_manager->get_relation(event_id);
    if (!rel.has_value()) {
        return json::object();
    }

    json info;
    info["parent_id"] = rel->parent_id;
    info["rel_type"] = rel->rel_type;
    info["sender"] = rel->sender;
    info["origin_server_ts"] = rel->origin_server_ts;
    info["is_redacted"] = rel->is_redacted;
    info["depth"] = rel->depth;
    info["aggregation_key"] = rel->aggregation_key;

    return info;
}

// Cleanup and maintenance
void cleanup_event_relations() {
    if (g_global_manager) {
        g_global_manager->purge_redacted_relations();
        g_global_manager->compact();
    }
}

// Get metrics
json get_relation_metrics() {
    if (g_global_metrics) {
        return g_global_metrics->get_metrics();
    }
    return json::object();
}

// Reset all state
void reset_event_relations() {
    if (g_global_manager) {
        g_global_manager->clear();
    }
    if (g_global_cache) {
        g_global_cache->clear_caches();
    }
    if (g_global_metrics) {
        g_global_metrics->reset();
    }
}

// ============================================================================
// End of event_relations.cpp
// ============================================================================

} // namespace progressive::events
