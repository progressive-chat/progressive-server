#include "push_rules.hpp"
#include <algorithm>
#include <cctype>

using json = nlohmann::json;

namespace push_rules {

PusherKind pusher_kind_from_string(const std::string& kind) {
    if (kind == "http") return PusherKind::Http;
    if (kind == "email") return PusherKind::Email;
    return PusherKind::None;
}

std::string push_rule_kind_to_string(PushRuleKind kind) {
    switch (kind) {
        case PushRuleKind::Override: return "override";
        case PushRuleKind::Underride: return "underride";
        case PushRuleKind::Sender: return "sender";
        case PushRuleKind::Room: return "room";
        case PushRuleKind::Content: return "content";
    }
    return "unknown";
}

bool evaluate_condition(const PushCondition& condition, const json& event, const std::string& user_id, const std::string& room_id) {
    // NEW in fe744c85: refactored condition evaluation (ruma Ruleset semantics).
    // Supports dotted keys like "content.msgtype" / "content.body".
    if (condition.kind == "event_match") {
        // Check if event matches pattern
        if (condition.content.contains("key") && condition.content.contains("pattern")) {
            std::string key = condition.content["key"].get<std::string>();
            std::string pattern = condition.content["pattern"].get<std::string>();
            // Resolve dotted key path (e.g. content.msgtype, content.body, type)
            const json* node = &event;
            size_t start = 0;
            bool ok = true;
            while (true) {
                size_t dot = key.find('.', start);
                std::string part = (dot == std::string::npos) ? key.substr(start)
                                                              : key.substr(start, dot - start);
                if (!node->is_object() || !node->contains(part)) { ok = false; break; }
                node = &((*node)[part]);
                if (dot == std::string::npos) break;
                start = dot + 1;
            }
            if (!ok || !node->is_string()) return false;
            std::string value = node->get<std::string>();
            // Simple pattern matching (glob-style substring, ruma uses glob)
            if (pattern.find('*') != std::string::npos) {
                // Strip wildcards for simplified matching
                std::string stripped;
                for (char c : pattern) if (c != '*') stripped += c;
                if (stripped.empty()) return true;
                return value.find(stripped) != std::string::npos;
            }
            return value.find(pattern) != std::string::npos;
        }
        return false;
    } else if (condition.kind == "contains_display_name") {
        // Check if event content contains user's display name
        if (event.contains("content") && event["content"].contains("body")) {
            try {
                std::string body = event["content"]["body"].get<std::string>();
                // Would need user's display name - simplified: match user localpart
                size_t colon = user_id.find(':');
                std::string local = (colon == std::string::npos) ? user_id
                    : user_id.substr(1, colon - 1);
                if (!local.empty() && body.find(local) != std::string::npos) return true;
            } catch (...) {}
            return false;
        }
        return false;
    } else if (condition.kind == "room_member_count") {
        // Check room member count — needs room state, conservatively false
        // (ruma's PushConditionRoomCtx carries member_count; we lack it here).
        return false;
    }
    return false;  // Unknown conditions do not match (ruma semantics)
}

void apply_actions(PushRuleResult& result, const std::vector<std::string>& actions, const std::vector<PushTweak>& tweaks) {
    for (const auto& action : actions) {
        if (action == "notify") {
            result.notify = true;
        } else if (action == "dont_notify") {
            result.notify = false;
        } else if (action == "coalesce") {
            result.coalesce = true;
        } else if (action == "set_tweak") {
            // Tweaks are applied separately
        }
    }
    
    for (const auto& tweak : tweaks) {
        try {
            if (tweak.kind == "highlight") {
                if (tweak.value.is_boolean()) result.highlight = tweak.value.get<bool>();
                else result.highlight = true;
            } else if (tweak.kind == "sound") {
                if (tweak.value.is_string()) result.sound = tweak.value.get<std::string>();
                else result.sound = "default";
            } else {
                result.tweaks[tweak.kind] = tweak.value;
            }
        } catch (...) {}
    }
}

PushRuleSet parse_push_rules(const json& rules_json) {
    PushRuleSet rules;
    
    auto parse_rules = [](const json& arr, PushRuleKind kind) -> std::vector<PushRule> {
        std::vector<PushRule> rules;
        if (!arr.is_array()) return rules;
        
        for (const auto& rule_json : arr) {
            PushRule rule;
            rule.rule_id = rule_json.value("rule_id", "");
            rule.kind = kind;
            rule.enabled = rule_json.value("enabled", true);
            rule.priority = rule_json.value("priority", 0);
            
            if (rule_json.contains("conditions") && rule_json["conditions"].is_array()) {
                for (const auto& cond_json : rule_json["conditions"]) {
                    PushCondition cond;
                    cond.kind = cond_json.value("kind", "");
                    cond.content = cond_json;
                    rule.conditions.push_back(cond);
                }
            }
            
            if (rule_json.contains("actions") && rule_json["actions"].is_array()) {
                for (const auto& action : rule_json["actions"]) {
                    if (action.is_string()) {
                        rule.actions.push_back(action.get<std::string>());
                    }
                }
            }
            
            if (rule_json.contains("tweaks") && rule_json["tweaks"].is_array()) {
                for (const auto& tweak_json : rule_json["tweaks"]) {
                    PushTweak tweak;
                    tweak.kind = tweak_json.value("kind", "");
                    tweak.value = tweak_json.value("value", json());
                    rule.tweaks.push_back(tweak);
                }
            }
            
            rules.push_back(rule);
        }
        return rules;
    };
    
    if (rules_json.contains("override")) {
        rules.override_rules = parse_rules(rules_json["override"], PushRuleKind::Override);
    }
    if (rules_json.contains("underride")) {
        rules.underride_rules = parse_rules(rules_json["underride"], PushRuleKind::Underride);
    }
    if (rules_json.contains("sender")) {
        rules.sender_rules = parse_rules(rules_json["sender"], PushRuleKind::Sender);
    }
    if (rules_json.contains("room")) {
        rules.room_rules = parse_rules(rules_json["room"], PushRuleKind::Room);
    }
    if (rules_json.contains("content")) {
        rules.content_rules = parse_rules(rules_json["content"], PushRuleKind::Content);
    }
    if (rules_json.contains("global_override")) {
        rules.global_override_rules = parse_rules(rules_json["global_override"], PushRuleKind::Override);
    }
    if (rules_json.contains("global_underride")) {
        rules.global_underride_rules = parse_rules(rules_json["global_underride"], PushRuleKind::Underride);
    }
    
    return rules;
}

PushRuleSet get_default_push_rules() {
    PushRuleSet rules;

    // NEW in fe744c85: defaults follow ruma's Ruleset. .m.rule.master is
    // disabled by default (enabling it mutes everything); suppress_notices
    // only matches m.notice messages (ruma uses .get/.replace semantics).
    rules.global_override_rules.clear();
    rules.global_override_rules.push_back(PushRule{
        ".m.rule.master", PushRuleKind::Override, {}, {"dont_notify"}, {}, false, 0});
    rules.global_override_rules.push_back(PushRule{
        ".m.rule.suppress_notices", PushRuleKind::Override,
        {{"event_match", {{"key", "content.msgtype"}, {"pattern", "m.notice"}}}},
        {"dont_notify"}, {}, true, 0});
    
    // Default content rules
    rules.content_rules.clear();
    rules.content_rules.push_back(PushRule{
        ".m.rule.contains_user_name", PushRuleKind::Content,
        {{"contains_display_name", {}}},
        {"notify"}, {}, true, 0});
    rules.content_rules.push_back(PushRule{
        ".m.rule.call", PushRuleKind::Content,
        {{"event_match", {{"key", "type"}, {"pattern", "m.call.invite"}}}},
        {"notify"}, {}, true, 0});
    rules.content_rules.push_back(PushRule{
        ".m.rule.encrypted", PushRuleKind::Content,
        {{"event_match", {{"key", "type"}, {"pattern", "m.room.encrypted"}}}}, {"notify"}, {}, true, 0});
    rules.content_rules.push_back(PushRule{
        ".m.rule.room_one_to_one", PushRuleKind::Content,
        std::vector<PushCondition>{
            PushCondition{"event_match", {{"key", "type"}, {"pattern", "m.room.message"}}},
            PushCondition{"room_member_count", {{"is", "2"}}}
        },
        {"notify"}, {}, true, 0});
    rules.content_rules.push_back(PushRule{
        ".m.rule.room_notification", PushRuleKind::Content,
        std::vector<PushCondition>{
            PushCondition{"event_match", {{"key", "type"}, {"pattern", "m.room.message"}}},
            PushCondition{"room_member_count", {{"is", "2"}}}
        },
        {"notify"}, {}, true, 0});
    rules.content_rules.push_back(PushRule{
        ".m.rule.message", PushRuleKind::Content,
        {{"event_match", {{"key", "type"}, {"pattern", "m.room.message"}}}}, {"notify"}, {}, true, 0});

    // Default room rules
    rules.room_rules.clear();
    rules.room_rules.push_back(PushRule{
        ".m.rule.room_one_to_one", PushRuleKind::Room,
        std::vector<PushCondition>{
            PushCondition{"event_match", {{"key", "type"}, {"pattern", "m.room.message"}}},
            PushCondition{"room_member_count", {{"is", "2"}}}
        },
        {"notify"}, {}, true, 0});
    rules.room_rules.push_back(PushRule{
        ".m.rule.room_notification", PushRuleKind::Room,
        {PushCondition{"event_match", {{"key", "type"}, {"pattern", "m.room.message"}}},
         PushCondition{"room_member_count", {{"is", "2"}}}}, {"notify"}, {}, true, 0});
    
    // Default underride rules
    rules.global_underride_rules.clear();
    rules.global_underride_rules.push_back(PushRule{
        ".m.rule.call", PushRuleKind::Underride,
        {{"event_match", {{"key", "type"}, {"pattern", "m.call.invite"}}}},
        {"notify"}, {}, true, 0});
    rules.global_underride_rules.push_back(PushRule{
        ".m.rule.encrypted_room_one_to_one", PushRuleKind::Underride, {}, {"notify"}, {}, true, 0});
    rules.global_underride_rules.push_back(PushRule{
        ".m.rule.room_one_to_one", PushRuleKind::Underride, {}, {"notify"}, {}, true, 0});
    rules.global_underride_rules.push_back(PushRule{
        ".m.rule.message", PushRuleKind::Underride, {}, {"notify"}, {}, true, 0});
    rules.global_underride_rules.push_back(PushRule{
        ".m.rule.encrypted", PushRuleKind::Underride, {}, {"notify"}, {}, true, 0});

    return rules;
}

PushRuleResult evaluate_push_rules(
    const PushRuleSet& rules,
    const json& event,
    const std::string& user_id,
    const std::string& room_id,
    const std::string& sender,
    bool is_encrypted
) {
    PushRuleResult result;

    // NEW in fe744c85 (pusher.rs refactor): m.notice messages never notify,
    // even before ruleset evaluation (preserves pre-refactor early return).
    try {
        if (event.contains("content") && event["content"].is_object() &&
            event["content"].value("msgtype", "") == "m.notice") {
            result.notify = false;
            return result;
        }
    } catch (...) {}

    // Check global override rules first (highest priority)
    for (const auto& rule : rules.global_override_rules) {
        if (!rule.enabled) continue;
        bool match = true;
        for (const auto& cond : rule.conditions) {
            if (!evaluate_condition(cond, event, user_id, room_id)) {
                match = false;
                break;
            }
        }
        if (match) {
            apply_actions(result, rule.actions, rule.tweaks);
            // Global override rules stop processing
            return result;
        }
    }
    
    // Check override rules
    for (const auto& rule : rules.override_rules) {
        if (!rule.enabled) continue;
        bool match = true;
        for (const auto& cond : rule.conditions) {
            if (!evaluate_condition(cond, event, user_id, room_id)) {
                match = false;
                break;
            }
        }
        if (match) {
            apply_actions(result, rule.actions, rule.tweaks);
            return result;
        }
    }
    
    // Check content rules
    for (const auto& rule : rules.content_rules) {
        if (!rule.enabled) continue;
        bool match = true;
        for (const auto& cond : rule.conditions) {
            if (!evaluate_condition(cond, event, user_id, room_id)) {
                match = false;
                break;
            }
        }
        if (match) {
            apply_actions(result, rule.actions, rule.tweaks);
        }
    }
    
    // Check room rules
    for (const auto& rule : rules.room_rules) {
        if (!rule.enabled) continue;
        bool match = true;
        for (const auto& cond : rule.conditions) {
            if (!evaluate_condition(cond, event, user_id, room_id)) {
                match = false;
                break;
            }
        }
        if (match) {
            apply_actions(result, rule.actions, rule.tweaks);
        }
    }
    
    // Check sender rules
    for (const auto& rule : rules.sender_rules) {
        if (!rule.enabled) continue;
        bool match = true;
        for (const auto& cond : rule.conditions) {
            if (!evaluate_condition(cond, event, user_id, room_id)) {
                match = false;
                break;
            }
        }
        if (match) {
            apply_actions(result, rule.actions, rule.tweaks);
        }
    }
    
    // Check underride rules
    for (const auto& rule : rules.underride_rules) {
        if (!rule.enabled) continue;
        bool match = true;
        for (const auto& cond : rule.conditions) {
            if (!evaluate_condition(cond, event, user_id, room_id)) {
                match = false;
                break;
            }
        }
        if (match) {
            apply_actions(result, rule.actions, rule.tweaks);
        }
    }
    
    // Check global underride rules
    for (const auto& rule : rules.global_underride_rules) {
        if (!rule.enabled) continue;
        bool match = true;
        for (const auto& cond : rule.conditions) {
            if (!evaluate_condition(cond, event, user_id, room_id)) {
                match = false;
                break;
            }
        }
        if (match) {
            apply_actions(result, rule.actions, rule.tweaks);
        }
    }
    
    return result;
}

PushRule parse_push_rule(const json& rule_json) {
    PushRule rule;
    rule.rule_id = rule_json.value("rule_id", "");
    std::string kind_str = rule_json.value("kind", "");
    if (kind_str == "override") rule.kind = PushRuleKind::Override;
    else if (kind_str == "underride") rule.kind = PushRuleKind::Underride;
    else if (kind_str == "sender") rule.kind = PushRuleKind::Sender;
    else if (kind_str == "room") rule.kind = PushRuleKind::Room;
    else if (kind_str == "content") rule.kind = PushRuleKind::Content;
    rule.enabled = rule_json.value("enabled", true);
    rule.priority = rule_json.value("priority", 0);
    
    if (rule_json.contains("conditions") && rule_json["conditions"].is_array()) {
        for (const auto& cond_json : rule_json["conditions"]) {
            PushCondition cond;
            cond.kind = cond_json.value("kind", "");
            cond.content = cond_json;
            rule.conditions.push_back(cond);
        }
    }
    
    if (rule_json.contains("actions") && rule_json["actions"].is_array()) {
        for (const auto& action : rule_json["actions"]) {
            if (action.is_string()) {
                rule.actions.push_back(action.get<std::string>());
            }
        }
    }
    
    if (rule_json.contains("tweaks") && rule_json["tweaks"].is_array()) {
        for (const auto& tweak_json : rule_json["tweaks"]) {
            PushTweak tweak;
            tweak.kind = tweak_json.value("kind", "");
            tweak.value = tweak_json.value("value", json());
            rule.tweaks.push_back(tweak);
        }
    }
    
    return rule;
}

}  // namespace push_rules
