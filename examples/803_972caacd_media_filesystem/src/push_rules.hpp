#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <set>

using json = nlohmann::json;

namespace push_rules {

// Push rule kinds
enum class PushRuleKind {
    Override,
    Underride,
    Sender,
    Room,
    Content
};

// Push rule actions
enum class PushActionKind {
    Notify,
    DontNotify,
    Coalesce,
    SetTweak
};

// Tweaks
struct PushTweak {
    std::string kind;  // "highlight", "sound", etc.
    json value;
};

// Push rule conditions
struct PushCondition {
    std::string kind;  // "event_match", "contains_display_name", "room_member_count", etc.
    json content;
};

// Push rule
struct PushRule {
    std::string rule_id;
    PushRuleKind kind;
    std::vector<PushCondition> conditions;
    std::vector<std::string> actions;  // Simplified: action names
    std::vector<PushTweak> tweaks;
    bool enabled = true;
    int priority = 0;  // For ordering
};

// Push rule set for a user
struct PushRuleSet {
    std::vector<PushRule> override_rules;
    std::vector<PushRule> underride_rules;
    std::vector<PushRule> sender_rules;
    std::vector<PushRule> room_rules;
    std::vector<PushRule> content_rules;
    std::vector<PushRule> global_override_rules;
    std::vector<PushRule> global_underride_rules;
};

// Pusher configuration
struct Pusher {
    std::string pusher_id;
    std::string kind;  // "http", "email"
    std::string app_id;
    std::string app_display_name;
    std::string device_display_name;
    std::string pushkey;
    std::string pushkey_ts;
    json data;  // URL for http, email for email
    std::string lang;
    std::vector<std::string> append;  // Event fields to append
    json profile_data;
};

// Push rule evaluation result
struct PushRuleResult {
    bool notify = false;
    bool highlight = false;
    std::string sound = "default";
    bool coalesce = false;
    std::map<std::string, json> tweaks;
};

// Pusher kinds
enum class PusherKind {
    Http,
    Email,
    None
};

// Convert string to PusherKind
PusherKind pusher_kind_from_string(const std::string& kind);

// Convert PushRuleKind to string
std::string push_rule_kind_to_string(PushRuleKind kind);

// Evaluate push rules for an event
PushRuleResult evaluate_push_rules(
    const PushRuleSet& rules,
    const json& event,
    const std::string& user_id,
    const std::string& room_id,
    const std::string& sender,
    bool is_encrypted,
    const std::string& display_name = ""
);

// NEW in 662a0cf1: shared action query (upstream pusher::get_actions).
// Returns just notify/highlight so callers (notification counting, push
// sending) share one evaluation path built with the user's *actual*
// displayname instead of the localpart fallback.
struct PushActions {
    bool notify = false;
    bool highlight = false;
};
PushActions get_actions(
    const std::string& user_id,
    const std::string& display_name,
    const PushRuleSet& rules,
    const json& event,
    const std::string& room_id);

// Parse push rules from JSON
PushRuleSet parse_push_rules(const json& rules_json);

// Default push rules
PushRuleSet get_default_push_rules();

// Push rule condition evaluation
// display_name overrides the localpart fallback for contains_display_name.
bool evaluate_condition(const PushCondition& condition, const json& event, const std::string& user_id, const std::string& room_id, const std::string& display_name = "");

// Apply push rule actions
void apply_actions(PushRuleResult& result, const std::vector<std::string>& actions, const std::vector<PushTweak>& tweaks);

}  // namespace push_rules
