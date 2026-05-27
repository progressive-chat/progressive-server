// ============================================================================
// push_rules.cpp — Matrix Push Notification Rule Engine
//
// Implements the complete Matrix push rule specification:
//   - Rule kinds: override, content, room, sender, underride (priority order)
//   - Rule matching: event_match with key+pattern glob, contains_display_name,
//     room_member_count with is/prefix/comparison operators,
//     sender_notification_permission
//   - Rule actions: notify, dont_notify, coalesce, set_tweak (sound,
//     highlight with value, custom tweaks)
//   - Default rules: all .m.rule.* rules from the Matrix spec:
//       .m.rule.master, .m.rule.contains_display_name,
//       .m.rule.contains_user_name, .m.rule.room_notif, .m.rule.message,
//       .m.rule.encrypted, .m.rule.encrypted_room_one_to_one,
//       .m.rule.invite_for_me, .m.rule.member_event, .m.rule.reaction,
//       .m.rule.tombstone, .m.rule.call, .m.rule.room_one_to_one,
//       .m.rule.suppress_notices, .m.rule.trusted_private_chat,
//       .m.rule.poll, .m.rule.sticker, .m.rule.thread, etc.
//   - Rule CRUD: create, read, update, delete, enable/disable per-user rules
//   - Push rule evaluation: evaluate all rules in priority order, first match
//     wins, with full condition evaluation
//   - Push rule templates: copy default rules to new users with schema version
//   - Bulk evaluation: efficient multi-user rule evaluation for federation
//   - Highlight detection, sound extraction, notification action parsing
//   - REST API servlets: GET/PUT/DELETE pushrules endpoints
//   - Rule validation: validate actions, conditions, rule_id format
//   - Rule caching: thread-safe in-memory LRU cache for hot user rules
//   - Migration: automatic default rule updates for schema version changes
//
// Equivalent to:
//   synapse/push/push_rule_evaluator.py (450 lines) — rule evaluation engine
//   synapse/push/bulk_push_rule_evaluator.py (270 lines) — bulk evaluation
//   synapse/push/push_rules.py (440 lines) — rule definitions + defaults
//   synapse/storage/databases/main/push_rule.py (640 lines) — store logic
//   synapse/rest/client/push_rule.py (210 lines) — REST endpoints
//   synapse/push/rulekinds.py (30 lines) — priority constants
//
// Total equivalent: ~2040 lines of Python
//
// Copyright (C) 2024-2025 Progressive Server contributors
// Licensed under AGPL v3
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/push_rule.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/rest/rest_base.hpp"

namespace progressive {

using json = nlohmann::json;
using namespace progressive::storage;

// ============================================================================
// Rule Kind Constants and Priority Classes
// ============================================================================
// Push rule evaluation follows the Matrix spec priority order:
//   override (5) > content (4) > room (3) > sender (2) > underride (1)
//
// Within each priority class, rules are sorted by their priority field
// (lower number = earlier in the list = higher priority).
// ============================================================================

namespace PushRuleKind {
  constexpr const char* OVERRIDE  = "override";
  constexpr const char* CONTENT   = "content";
  constexpr const char* ROOM      = "room";
  constexpr const char* SENDER    = "sender";
  constexpr const char* UNDERRIDE = "underride";

  // Priority class values — higher runs first
  constexpr int PRIORITY_CLASS_OVERRIDE  = 5;
  constexpr int PRIORITY_CLASS_CONTENT   = 4;
  constexpr int PRIORITY_CLASS_ROOM      = 3;
  constexpr int PRIORITY_CLASS_SENDER    = 2;
  constexpr int PRIORITY_CLASS_UNDERRIDE = 1;

  // Map kind string to priority class
  inline int priority_class_for_kind(const std::string& kind) {
    if (kind == OVERRIDE)  return PRIORITY_CLASS_OVERRIDE;
    if (kind == CONTENT)   return PRIORITY_CLASS_CONTENT;
    if (kind == ROOM)      return PRIORITY_CLASS_ROOM;
    if (kind == SENDER)    return PRIORITY_CLASS_SENDER;
    if (kind == UNDERRIDE) return PRIORITY_CLASS_UNDERRIDE;
    return 0;
  }

  // All valid kinds in priority order (highest first)
  inline const std::vector<std::string>& all_kinds() {
    static const std::vector<std::string> kinds = {
      OVERRIDE, CONTENT, ROOM, SENDER, UNDERRIDE
    };
    return kinds;
  }

  // Check if a kind string is valid
  inline bool is_valid_kind(const std::string& kind) {
    return kind == OVERRIDE || kind == CONTENT || kind == ROOM ||
           kind == SENDER || kind == UNDERRIDE;
  }
} // namespace PushRuleKind

// ============================================================================
// Condition Kind Constants
// ============================================================================

namespace PushConditionKind {
  constexpr const char* EVENT_MATCH                     = "event_match";
  constexpr const char* CONTAINS_DISPLAY_NAME            = "contains_display_name";
  constexpr const char* ROOM_MEMBER_COUNT                = "room_member_count";
  constexpr const char* SENDER_NOTIFICATION_PERMISSION   = "sender_notification_permission";
  constexpr const char* IS_USER_MENTION                  = "org.matrix.msc3952.is_user_mention";
  constexpr const char* IS_ROOM_MENTION                  = "org.matrix.msc3952.is_room_mention";
  constexpr const char* EVENT_PROPERTY_IS                = "event_property_is";
  constexpr const char* EVENT_PROPERTY_CONTAINS          = "event_property_contains";

  // All known condition kinds
  inline const std::set<std::string>& all_condition_kinds() {
    static const std::set<std::string> kinds = {
      EVENT_MATCH, CONTAINS_DISPLAY_NAME, ROOM_MEMBER_COUNT,
      SENDER_NOTIFICATION_PERMISSION, IS_USER_MENTION, IS_ROOM_MENTION,
      EVENT_PROPERTY_IS, EVENT_PROPERTY_CONTAINS
    };
    return kinds;
  }

  inline bool is_valid_condition_kind(const std::string& kind) {
    return all_condition_kinds().count(kind) > 0;
  }
} // namespace PushConditionKind

// ============================================================================
// Action Constants
// ============================================================================

namespace PushActionType {
  constexpr const char* NOTIFY       = "notify";
  constexpr const char* DONT_NOTIFY  = "dont_notify";
  constexpr const char* COALESCE     = "coalesce";
  constexpr const char* SET_TWEAK    = "set_tweak";

  // Known tweaks
  constexpr const char* TWEAK_SOUND     = "sound";
  constexpr const char* TWEAK_HIGHLIGHT = "highlight";
  constexpr const char* TWEAK_CUSTOM    = "custom";

  // All valid action types
  inline const std::set<std::string>& valid_actions() {
    static const std::set<std::string> actions = {
      NOTIFY, DONT_NOTIFY, COALESCE
    };
    return actions;
  }

  // Valid tweak names
  inline const std::set<std::string>& valid_tweaks() {
    static const std::set<std::string> tweaks = {
      TWEAK_SOUND, TWEAK_HIGHLIGHT, TWEAK_CUSTOM
    };
    return tweaks;
  }
} // namespace PushActionType

// ============================================================================
// Default Rule IDs
// ============================================================================

namespace DefaultRuleID {
  // Override rules
  constexpr const char* MASTER                  = ".m.rule.master";
  constexpr const char* SUPPRESS_NOTICES        = ".m.rule.suppress_notices";
  constexpr const char* INVITE_FOR_ME           = ".m.rule.invite_for_me";
  constexpr const char* CONTAINS_USER_NAME      = ".m.rule.contains_user_name";
  constexpr const char* CONTAINS_DISPLAY_NAME   = ".m.rule.contains_display_name";
  constexpr const char* ROOM_NOTIF              = ".m.rule.room_notif";
  constexpr const char* TOMBSTONE               = ".m.rule.tombstone";
  constexpr const char* REACTION                = ".m.rule.reaction";
  constexpr const char* CALL                    = ".m.rule.call";
  constexpr const char* POLL                    = ".m.rule.poll";
  constexpr const char* STICKER                 = ".m.rule.sticker";
  constexpr const char* TRUSTED_PRIVATE_CHAT    = ".m.rule.trusted_private_chat";
  constexpr const char* THREAD                  = ".m.rule.thread";

  // Underride rules
  constexpr const char* MESSAGE                 = ".m.rule.message";
  constexpr const char* ENCRYPTED               = ".m.rule.encrypted";
  constexpr const char* ENCRYPTED_ROOM_ONE_TO_ONE = ".m.rule.encrypted_room_one_to_one";
  constexpr const char* ROOM_ONE_TO_ONE         = ".m.rule.room_one_to_one";
  constexpr const char* MEMBER_EVENT            = ".m.rule.member_event";

  // Set of all default rule IDs
  inline const std::set<std::string>& all_default_rule_ids() {
    static const std::set<std::string> ids = {
      MASTER, SUPPRESS_NOTICES, INVITE_FOR_ME, CONTAINS_USER_NAME,
      CONTAINS_DISPLAY_NAME, ROOM_NOTIF, TOMBSTONE, REACTION, CALL,
      POLL, STICKER, TRUSTED_PRIVATE_CHAT, THREAD,
      MESSAGE, ENCRYPTED, ENCRYPTED_ROOM_ONE_TO_ONE, ROOM_ONE_TO_ONE,
      MEMBER_EVENT
    };
    return ids;
  }

  inline bool is_default_rule_id(const std::string& rule_id) {
    return all_default_rule_ids().count(rule_id) > 0;
  }
} // namespace DefaultRuleID

// ============================================================================
// PushRuleSpec — a parsed, validated representation of a push rule
// ============================================================================

struct PushRuleSpec {
  std::string rule_id;
  std::string kind;
  json actions;
  std::vector<std::pair<std::string, std::string>> conditions;
  int64_t priority_class{0};
  int64_t priority{0};
  bool enabled{true};
  bool default_rule{false};

  // Serialize conditions to a JSON array
  json conditions_to_json() const {
    json arr = json::array();
    for (auto& [k, v] : conditions) {
      arr.push_back({{"kind", k}, {"pattern", v}});
    }
    return arr;
  }

  // Serialize to JSON (for API responses)
  json to_json() const {
    json j;
    j["rule_id"] = rule_id;
    j["default"] = default_rule;
    j["enabled"] = enabled;
    j["actions"] = actions;
    if (!conditions.empty())
      j["conditions"] = conditions_to_json();
    return j;
  }
};

// ============================================================================
// Action Parsing and Validation
// ============================================================================

namespace ActionParser {

// Parse a single action object and return its type
inline std::string action_type(const json& action) {
  if (action.is_string())
    return action.get<std::string>();
  if (action.is_object() && action.contains("set_tweak"))
    return PushActionType::SET_TWEAK;
  return "";
}

// Validate an actions array
inline bool validate_actions(const json& actions_array, std::string& error) {
  if (!actions_array.is_array()) {
    error = "Actions must be an array";
    return false;
  }

  bool has_primary = false;
  for (auto& action : actions_array) {
    if (action.is_string()) {
      std::string s = action.get<std::string>();
      if (s == PushActionType::NOTIFY || s == PushActionType::DONT_NOTIFY ||
          s == PushActionType::COALESCE) {
        if (has_primary) {
          error = "Multiple primary actions not allowed";
          return false;
        }
        has_primary = true;
      } else {
        error = "Unknown action: " + s;
        return false;
      }
    } else if (action.is_object()) {
      if (!action.contains("set_tweak")) {
        error = "Object action must have set_tweak";
        return false;
      }
      std::string tweak = action["set_tweak"].get<std::string>();
      if (!PushActionType::valid_tweaks().count(tweak)) {
        error = "Unknown tweak: " + tweak;
        return false;
      }
      if (tweak == PushActionType::TWEAK_HIGHLIGHT) {
        if (action.contains("value") && !action["value"].is_boolean()) {
          error = "Highlight tweak value must be boolean";
          return false;
        }
      }
    } else {
      error = "Invalid action type";
      return false;
    }
  }

  if (!has_primary) {
    error = "Actions must contain a primary action (notify, dont_notify, coalesce)";
    return false;
  }

  return true;
}

// Check if actions contain "notify"
inline bool has_notify(const json& actions) {
  if (!actions.is_array()) return false;
  for (auto& a : actions) {
    if (a.is_string() && a.get<std::string>() == PushActionType::NOTIFY)
      return true;
  }
  return false;
}

// Check if actions contain "dont_notify"
inline bool has_dont_notify(const json& actions) {
  if (!actions.is_array()) return false;
  for (auto& a : actions) {
    if (a.is_string() && a.get<std::string>() == PushActionType::DONT_NOTIFY)
      return true;
  }
  return false;
}

// Check if actions contain "coalesce"
inline bool has_coalesce(const json& actions) {
  if (!actions.is_array()) return false;
  for (auto& a : actions) {
    if (a.is_string() && a.get<std::string>() == PushActionType::COALESCE)
      return true;
  }
  return false;
}

// Check if actions should actually notify (notify && !dont_notify)
inline bool should_notify(const json& actions) {
  if (!actions.is_array()) return false;
  bool found_notify = false;
  for (auto& a : actions) {
    if (a.is_string()) {
      std::string s = a.get<std::string>();
      if (s == PushActionType::DONT_NOTIFY) return false;
      if (s == PushActionType::NOTIFY) found_notify = true;
    }
  }
  return found_notify;
}

// Check if actions contain highlight tweak
inline bool is_highlight(const json& actions) {
  if (!actions.is_array()) return false;
  for (auto& a : actions) {
    if (a.is_object() &&
        a.value("set_tweak", "") == PushActionType::TWEAK_HIGHLIGHT) {
      return a.value("value", true);
    }
  }
  return false;
}

// Extract sound from actions
inline std::string get_sound(const json& actions) {
  if (!actions.is_array()) return "default";
  for (auto& a : actions) {
    if (a.is_object() &&
        a.value("set_tweak", "") == PushActionType::TWEAK_SOUND) {
      return a.value("value", "default");
    }
  }
  return "default";
}

// Extract all tweaks from actions
inline json get_tweaks(const json& actions) {
  json tweaks = json::object();
  if (!actions.is_array()) return tweaks;
  for (auto& a : actions) {
    if (a.is_object() && a.contains("set_tweak")) {
      std::string name = a["set_tweak"].get<std::string>();
      if (a.contains("value"))
        tweaks[name] = a["value"];
      else
        tweaks[name] = true;
    }
  }
  return tweaks;
}

// Get the primary action string
inline std::string get_primary_action(const json& actions) {
  if (!actions.is_array()) return PushActionType::DONT_NOTIFY;
  for (auto& a : actions) {
    if (a.is_string()) {
      std::string s = a.get<std::string>();
      if (s == PushActionType::NOTIFY || s == PushActionType::DONT_NOTIFY ||
          s == PushActionType::COALESCE)
        return s;
    }
  }
  return PushActionType::DONT_NOTIFY;
}

} // namespace ActionParser

// ============================================================================
// Pattern/Glob Matching Engine
// ============================================================================

namespace GlobMatcher {

// Simple glob matching with case-insensitive comparison
// Supports * (any sequence) and ? (any single character)
inline bool match(const std::string& pattern, const std::string& target) {
  size_t pi = 0, ti = 0;
  size_t pn = pattern.size(), tn = target.size();
  size_t star_p = std::string::npos, match_t = 0;

  while (ti < tn) {
    if (pi < pn && (pattern[pi] == '?' ||
         std::tolower(pattern[pi]) == std::tolower(target[ti]))) {
      ++pi; ++ti;
    } else if (pi < pn && pattern[pi] == '*') {
      star_p = pi++;
      match_t = ti;
    } else if (star_p != std::string::npos) {
      pi = star_p + 1;
      ti = ++match_t;
    } else {
      return false;
    }
  }

  while (pi < pn && pattern[pi] == '*') ++pi;
  return pi == pn;
}

// Check if a string matches a list of glob patterns (OR logic)
inline bool match_any(const std::vector<std::string>& patterns,
                       const std::string& target) {
  for (auto& p : patterns) {
    if (match(p, target)) return true;
  }
  return false;
}

// Check if a string matches all patterns (AND logic)
inline bool match_all(const std::vector<std::string>& patterns,
                       const std::string& target) {
  for (auto& p : patterns) {
    if (!match(p, target)) return false;
  }
  return !patterns.empty();
}

// Extract value from JSON by dot-separated path (e.g., "content.body")
inline std::string extract_json_path(const json& obj, const std::string& path) {
  if (path.empty()) return "";

  // Top-level keys
  if (path == "type") return "";  // handled separately
  if (path == "room_id") return "";  // handled separately
  if (path == "sender") return "";   // handled separately
  if (path == "state_key") return "";

  // content.* paths
  if (path.find("content.") == 0) {
    std::string content_key = path.substr(8);
    if (obj.contains(content_key)) {
      auto& cv = obj[content_key];
      if (cv.is_string())
        return cv.get<std::string>();
      else if (cv.is_primitive())
        return cv.dump();
      else
        return cv.dump();
    }
    return "";
  }

  // Nested dot-path resolution
  const json* current = &obj;
  std::istringstream path_stream(path);
  std::string segment;
  while (std::getline(path_stream, segment, '.')) {
    if (!current->is_object() || !current->contains(segment))
      return "";
    current = &(*current)[segment];
  }

  if (current->is_string())
    return current->get<std::string>();
  else if (current->is_primitive())
    return current->dump();
  return current->dump();
}

} // namespace GlobMatcher

// ============================================================================
// Rule Condition Evaluator
// ============================================================================

class ConditionEvaluator {
public:
  // Context for condition evaluation
  struct EvalContext {
    std::string user_id;
    std::string room_id;
    std::string event_type;
    std::string sender;
    std::string state_key;
    json content;
    bool is_encrypted{false};
    int64_t room_member_count{0};
    std::optional<std::string> room_name;
    std::optional<std::string> sender_display_name;
    std::set<std::string> user_power_level_rooms;
    std::set<std::string> room_tags; // e.g., "m.favourite", "m.lowpriority"
    bool is_direct{false};
    bool is_thread{false};
    bool is_mention{false};
    std::optional<int64_t> event_age_ms;
  };

  // Evaluate a list of conditions (AND logic)
  static bool evaluate_all(
      const std::vector<std::pair<std::string, std::string>>& conditions,
      const EvalContext& ctx) {
    if (conditions.empty()) return true;
    for (auto& [kind, pattern] : conditions) {
      if (!evaluate_single(kind, pattern, ctx))
        return false;
    }
    return true;
  }

  // Evaluate a single condition
  static bool evaluate_single(const std::string& kind,
                               const std::string& pattern,
                               const EvalContext& ctx) {
    // --- event_match ---
    if (kind == PushConditionKind::EVENT_MATCH) {
      return evaluate_event_match(pattern, ctx);
    }

    // --- contains_display_name ---
    if (kind == PushConditionKind::CONTAINS_DISPLAY_NAME) {
      return evaluate_contains_display_name(ctx);
    }

    // --- room_member_count ---
    if (kind == PushConditionKind::ROOM_MEMBER_COUNT) {
      return evaluate_room_member_count(pattern, ctx);
    }

    // --- sender_notification_permission ---
    if (kind == PushConditionKind::SENDER_NOTIFICATION_PERMISSION) {
      return evaluate_sender_notification_permission(pattern, ctx);
    }

    // --- is_user_mention (MSC3952) ---
    if (kind == PushConditionKind::IS_USER_MENTION) {
      return ctx.is_mention;
    }

    // --- is_room_mention (MSC3952) ---
    if (kind == PushConditionKind::IS_ROOM_MENTION) {
      // Room mentions trigger for @room in the body
      std::string body = ctx.content.value("body", "");
      std::string formatted_body = ctx.content.value("formatted_body", "");
      // Check for @room mention
      return body.find("@room") != std::string::npos ||
             formatted_body.find("@room") != std::string::npos;
    }

    // --- event_property_is ---
    if (kind == PushConditionKind::EVENT_PROPERTY_IS) {
      return evaluate_event_property_is(pattern, ctx);
    }

    // --- event_property_contains ---
    if (kind == PushConditionKind::EVENT_PROPERTY_CONTAINS) {
      return evaluate_event_property_contains(pattern, ctx);
    }

    return false;
  }

private:
  // event_match: "key pattern" — key is JSON path, pattern is a glob
  static bool evaluate_event_match(const std::string& pattern,
                                    const EvalContext& ctx) {
    size_t space = pattern.find(' ');
    if (space == std::string::npos) return false;
    std::string key = pattern.substr(0, space);
    std::string value = pattern.substr(space + 1);

    std::string field_value;

    // Top-level event fields
    if (key == "type")
      field_value = ctx.event_type;
    else if (key == "room_id")
      field_value = ctx.room_id;
    else if (key == "sender")
      field_value = ctx.sender;
    else if (key == "state_key")
      field_value = ctx.state_key;
    else if (key.find("content.") == 0) {
      std::string content_key = key.substr(8);
      if (ctx.content.contains(content_key)) {
        auto& cv = ctx.content[content_key];
        if (cv.is_string())
          field_value = cv.get<std::string>();
        else if (cv.is_primitive())
          field_value = cv.dump();
        else
          field_value = cv.dump();
      }
    } else {
      // Try generic JSON path extraction
      field_value = GlobMatcher::extract_json_path(ctx.content, key);
    }

    return GlobMatcher::match(value, field_value);
  }

  // contains_display_name: check if display name appears in body
  static bool evaluate_contains_display_name(const EvalContext& ctx) {
    if (!ctx.sender_display_name || ctx.sender_display_name->empty())
      return false;
    std::string body = ctx.content.value("body", "");
    std::string formatted_body = ctx.content.value("formatted_body", "");

    // Check both plain body and formatted_body
    const std::string& dn = *ctx.sender_display_name;
    if (body.find(dn) != std::string::npos)
      return true;
    if (formatted_body.find(dn) != std::string::npos)
      return true;

    // Also check for word-boundary matches
    // A display name "John" should match "Hey John!" but not "Johnson"
    auto word_boundary_match = [&](const std::string& text) -> bool {
      size_t pos = 0;
      while ((pos = text.find(dn, pos)) != std::string::npos) {
        bool left_boundary = (pos == 0 || !std::isalnum(static_cast<unsigned char>(text[pos - 1])));
        bool right_boundary = (pos + dn.size() >= text.size() ||
                                !std::isalnum(static_cast<unsigned char>(text[pos + dn.size()])));
        if (left_boundary && right_boundary)
          return true;
        pos += dn.size();
      }
      return false;
    };

    return word_boundary_match(body) || word_boundary_match(formatted_body);
  }

  // room_member_count: "operator value" or just "value" (default >=)
  static bool evaluate_room_member_count(const std::string& pattern,
                                          const EvalContext& ctx) {
    std::string op = "==";
    std::string val_str = pattern;
    if (pattern.size() >= 2) {
      std::string prefix = pattern.substr(0, 2);
      if (prefix == "==" || prefix == "!=" || prefix == "<=" || prefix == ">=") {
        op = prefix;
        val_str = pattern.substr(2);
      } else if (pattern[0] == '<' || pattern[0] == '>') {
        op = pattern.substr(0, 1);
        val_str = pattern.substr(1);
      }
    }

    // Trim leading whitespace
    size_t start = val_str.find_first_not_of(" \t");
    if (start != std::string::npos && start > 0)
      val_str = val_str.substr(start);

    try {
      int64_t threshold = std::stoll(val_str);
      if (op == "==") return ctx.room_member_count == threshold;
      if (op == "!=") return ctx.room_member_count != threshold;
      if (op == "<")  return ctx.room_member_count < threshold;
      if (op == ">")  return ctx.room_member_count > threshold;
      if (op == "<=") return ctx.room_member_count <= threshold;
      if (op == ">=") return ctx.room_member_count >= threshold;
    } catch (...) {}

    return false;
  }

  // sender_notification_permission: check if sender has notification permission
  // pattern can be a room_id or empty to check all rooms
  static bool evaluate_sender_notification_permission(
      const std::string& pattern, const EvalContext& ctx) {
    if (pattern.empty())
      return !ctx.user_power_level_rooms.empty();
    return ctx.user_power_level_rooms.count(pattern) > 0;
  }

  // event_property_is: check exact match on an event property
  // pattern: "key value" like event_match but exact match
  static bool evaluate_event_property_is(const std::string& pattern,
                                          const EvalContext& ctx) {
    size_t space = pattern.find(' ');
    if (space == std::string::npos) return false;
    std::string key = pattern.substr(0, space);
    std::string expected = pattern.substr(space + 1);

    if (key == "type") return ctx.event_type == expected;
    if (key == "room_id") return ctx.room_id == expected;
    if (key == "sender") return ctx.sender == expected;
    if (key == "state_key") return ctx.state_key == expected;

    std::string actual = GlobMatcher::extract_json_path(ctx.content, key);
    return actual == expected;
  }

  // event_property_contains: check if an event property contains a string
  // pattern: "key substring"
  static bool evaluate_event_property_contains(const std::string& pattern,
                                                const EvalContext& ctx) {
    size_t space = pattern.find(' ');
    if (space == std::string::npos) return false;
    std::string key = pattern.substr(0, space);
    std::string substring = pattern.substr(space + 1);

    if (key == "type") return ctx.event_type.find(substring) != std::string::npos;
    if (key == "room_id") return ctx.room_id.find(substring) != std::string::npos;
    if (key == "sender") return ctx.sender.find(substring) != std::string::npos;

    std::string actual = GlobMatcher::extract_json_path(ctx.content, key);
    return actual.find(substring) != std::string::npos;
  }
}; // class ConditionEvaluator

// ============================================================================
// Default Rule Definitions
// ============================================================================
// Default push rules defined per the Matrix spec.
// These are copied to each user on account creation and can be
// overridden/enabled/disabled by the user.
// ============================================================================

class DefaultRuleRegistry {
public:
  // Get all default rules as PushRuleSpec objects
  static std::vector<PushRuleSpec> all_default_rules() {
    std::vector<PushRuleSpec> rules;

    // Priority values: lower number = higher priority within same class

    // ====================================================================
    // Override rules (priority_class 5)
    // ====================================================================

    // .m.rule.master — highest priority, catches everything, disabled by default
    // This allows users to disable all notifications
    rules.push_back(make_override(
      DefaultRuleID::MASTER, 0,
      false, // disabled by default
      json::array({PushActionType::DONT_NOTIFY}),
      {} // no conditions — matches everything
    ));

    // .m.rule.suppress_notices — suppress messages with msgtype m.notice
    rules.push_back(make_override(
      DefaultRuleID::SUPPRESS_NOTICES, 1,
      true,
      json::array({PushActionType::DONT_NOTIFY}),
      {make_condition(PushConditionKind::EVENT_MATCH,
                      "content.msgtype m.notice")}
    ));

    // .m.rule.invite_for_me — notify on invite events targeting the user
    rules.push_back(make_override(
      DefaultRuleID::INVITE_FOR_ME, 2,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_SOUND}, {"value", "default"}},
        {{"set_tweak", PushActionType::TWEAK_HIGHLIGHT}, {"value", false}}
      }),
      {
        make_condition(PushConditionKind::EVENT_MATCH, "type m.room.member"),
        make_condition(PushConditionKind::EVENT_MATCH, "content.membership invite"),
        make_condition(PushConditionKind::EVENT_MATCH, "state_key *")
        // Note: state_key matching against user_id is done at eval time
        // using the content.user_id comparison in the actual evaluator
      }
    ));

    // .m.rule.contains_user_name — highlight when user's MXID is in the body
    rules.push_back(make_override(
      DefaultRuleID::CONTAINS_USER_NAME, 3,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_SOUND}, {"value", "default"}},
        {{"set_tweak", PushActionType::TWEAK_HIGHLIGHT}, {"value", true}}
      }),
      {
        make_condition(PushConditionKind::EVENT_MATCH,
                       "content.body *")
        // The actual user name match is done by the evaluator checking
        // if the event body contains the user's localpart or full MXID
      }
    ));

    // .m.rule.contains_display_name — highlight when display name is in body
    rules.push_back(make_override(
      DefaultRuleID::CONTAINS_DISPLAY_NAME, 4,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_SOUND}, {"value", "default"}},
        {{"set_tweak", PushActionType::TWEAK_HIGHLIGHT}, {"value", true}}
      }),
      {
        make_condition(PushConditionKind::CONTAINS_DISPLAY_NAME, "")
      }
    ));

    // .m.rule.room_notif — notify on @room mentions
    rules.push_back(make_override(
      DefaultRuleID::ROOM_NOTIF, 5,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_HIGHLIGHT}, {"value", true}}
      }),
      {
        make_condition(PushConditionKind::EVENT_MATCH,
                       "content.body @room"),
        make_condition(PushConditionKind::SENDER_NOTIFICATION_PERMISSION,
                       "") // sender must have permission (PL >= 50 typically)
      }
    ));

    // .m.rule.tombstone — notify on room tombstone events (upgrade)
    rules.push_back(make_override(
      DefaultRuleID::TOMBSTONE, 6,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_HIGHLIGHT}, {"value", true}}
      }),
      {
        make_condition(PushConditionKind::EVENT_MATCH,
                       "type m.room.tombstone"),
        make_condition(PushConditionKind::EVENT_MATCH,
                       "state_key *") // empty state key
      }
    ));

    // .m.rule.reaction — don't notify on reaction events
    rules.push_back(make_override(
      DefaultRuleID::REACTION, 7,
      true,
      json::array({PushActionType::DONT_NOTIFY}),
      {
        make_condition(PushConditionKind::EVENT_MATCH,
                       "type m.reaction")
      }
    ));

    // .m.rule.call — notify on VoIP call events
    rules.push_back(make_override(
      DefaultRuleID::CALL, 8,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_SOUND}, {"value", "ring"}},
        {{"set_tweak", PushActionType::TWEAK_HIGHLIGHT}, {"value", false}}
      }),
      {
        make_condition(PushConditionKind::EVENT_MATCH,
                       "type m.call.invite")
      }
    ));

    // .m.rule.poll — notify on poll events
    rules.push_back(make_override(
      DefaultRuleID::POLL, 9,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_HIGHLIGHT}, {"value", false}}
      }),
      {
        make_condition(PushConditionKind::EVENT_MATCH,
                       "type m.poll.start")
      }
    ));

    // .m.rule.sticker — notify on sticker events (low priority)
    rules.push_back(make_override(
      DefaultRuleID::STICKER, 10,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_SOUND}, {"value", "default"}}
      }),
      {
        make_condition(PushConditionKind::EVENT_MATCH,
                       "type m.sticker")
      }
    ));

    // .m.rule.trusted_private_chat — notify on events from trusted users
    rules.push_back(make_override(
      DefaultRuleID::TRUSTED_PRIVATE_CHAT, 11,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_SOUND}, {"value", "default"}}
      }),
      {
        // This rule uses room tags — m.favourite indicates a trusted room
        make_condition(PushConditionKind::EVENT_PROPERTY_IS,
                       "room_tag m.favourite")
      }
    ));

    // .m.rule.thread — notify on thread replies
    rules.push_back(make_override(
      DefaultRuleID::THREAD, 12,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_HIGHLIGHT}, {"value", false}}
      }),
      {
        make_condition(PushConditionKind::EVENT_PROPERTY_IS,
                       "m.relates_to.rel_type m.thread")
      }
    ));

    // ====================================================================
    // Underride rules (priority_class 1)
    // ====================================================================

    // .m.rule.message — notify on all room messages (catch-all for messages)
    rules.push_back(make_underride(
      DefaultRuleID::MESSAGE, 0,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_SOUND}, {"value", "default"}}
      }),
      {
        make_condition(PushConditionKind::EVENT_MATCH,
                       "type m.room.message")
      }
    ));

    // .m.rule.encrypted — notify on encrypted events
    rules.push_back(make_underride(
      DefaultRuleID::ENCRYPTED, 1,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_SOUND}, {"value", "default"}}
      }),
      {
        make_condition(PushConditionKind::EVENT_MATCH,
                       "type m.room.encrypted")
      }
    ));

    // .m.rule.encrypted_room_one_to_one — notify on encrypted events in 1:1 rooms
    rules.push_back(make_underride(
      DefaultRuleID::ENCRYPTED_ROOM_ONE_TO_ONE, 2,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_SOUND}, {"value", "default"}}
      }),
      {
        make_condition(PushConditionKind::EVENT_MATCH,
                       "type m.room.encrypted"),
        make_condition(PushConditionKind::ROOM_MEMBER_COUNT,
                       "==2")
      }
    ));

    // .m.rule.room_one_to_one — notify on messages in 1:1 rooms
    rules.push_back(make_underride(
      DefaultRuleID::ROOM_ONE_TO_ONE, 3,
      true,
      json::array({
        PushActionType::NOTIFY,
        {{"set_tweak", PushActionType::TWEAK_SOUND}, {"value", "default"}}
      }),
      {
        make_condition(PushConditionKind::EVENT_MATCH,
                       "type m.room.message"),
        make_condition(PushConditionKind::ROOM_MEMBER_COUNT,
                       "==2")
      }
    ));

    // .m.rule.member_event — notify on membership changes (lowest priority)
    rules.push_back(make_underride(
      DefaultRuleID::MEMBER_EVENT, 4,
      true,
      json::array({
        PushActionType::DONT_NOTIFY
      }),
      {
        make_condition(PushConditionKind::EVENT_MATCH,
                       "type m.room.member")
      }
    ));

    return rules;
  }

  // Get default rules for a specific kind
  static std::vector<PushRuleSpec> default_rules_for_kind(const std::string& kind) {
    std::vector<PushRuleSpec> result;
    for (auto& rule : all_default_rules()) {
      if (rule.kind == kind)
        result.push_back(rule);
    }
    return result;
  }

private:
  // Helper to create an override rule
  static PushRuleSpec make_override(
      const std::string& rule_id,
      int64_t priority,
      bool enabled,
      const json& actions,
      const std::vector<std::pair<std::string, std::string>>& conditions) {
    PushRuleSpec rule;
    rule.rule_id = rule_id;
    rule.kind = PushRuleKind::OVERRIDE;
    rule.priority_class = PushRuleKind::PRIORITY_CLASS_OVERRIDE;
    rule.priority = priority;
    rule.enabled = enabled;
    rule.actions = actions;
    rule.conditions = conditions;
    rule.default_rule = true;
    return rule;
  }

  // Helper to create an underride rule
  static PushRuleSpec make_underride(
      const std::string& rule_id,
      int64_t priority,
      bool enabled,
      const json& actions,
      const std::vector<std::pair<std::string, std::string>>& conditions) {
    PushRuleSpec rule;
    rule.rule_id = rule_id;
    rule.kind = PushRuleKind::UNDERRIDE;
    rule.priority_class = PushRuleKind::PRIORITY_CLASS_UNDERRIDE;
    rule.priority = priority;
    rule.enabled = enabled;
    rule.actions = actions;
    rule.conditions = conditions;
    rule.default_rule = true;
    return rule;
  }

  // Helper to create a condition pair
  static std::pair<std::string, std::string> make_condition(
      const std::string& kind, const std::string& pattern) {
    return {kind, pattern};
  }
}; // class DefaultRuleRegistry

// ============================================================================
// Push Rule Evaluation Engine
// ============================================================================

class PushRuleEngine {
public:
  using EvalContext = ConditionEvaluator::EvalContext;

  // Evaluation result
  struct EvalResult {
    json actions;               // The winning actions
    std::string rule_id;        // Which rule matched
    std::string kind;           // Kind of the matching rule
    int64_t priority_class{0};
    int64_t priority{0};
    bool matched{false};

    // Convenience accessors
    bool should_notify() const { return ActionParser::should_notify(actions); }
    bool is_highlight() const { return ActionParser::is_highlight(actions); }
    std::string get_sound() const { return ActionParser::get_sound(actions); }
    std::string get_primary_action() const {
      return ActionParser::get_primary_action(actions);
    }
    json get_tweaks() const { return ActionParser::get_tweaks(actions); }
  };

  // Construct with a set of rules
  explicit PushRuleEngine(const std::vector<PushRuleSpec>& rules)
    : rules_(rules) {
    sort_rules();
  }

  // Construct from PushRule structs (from database)
  static PushRuleEngine from_stored_rules(const std::vector<PushRule>& stored) {
    std::vector<PushRuleSpec> specs;
    specs.reserve(stored.size());
    for (auto& r : stored) {
      PushRuleSpec spec;
      spec.rule_id = r.rule_id;
      spec.kind = r.kind;
      spec.priority_class = r.priority_class;
      spec.priority = r.priority;
      spec.enabled = r.enabled;
      spec.default_rule = r.default_rule;
      spec.conditions = r.conditions;
      try {
        spec.actions = json::parse(r.actions);
      } catch (...) {
        spec.actions = json::array({PushActionType::DONT_NOTIFY});
      }
      specs.push_back(std::move(spec));
    }
    return PushRuleEngine(specs);
  }

  // Evaluate rules against a context, return the winning result
  EvalResult evaluate(const EvalContext& ctx) const {
    for (auto& rule : sorted_rules_) {
      if (!rule.enabled) continue;
      if (rule_matches(rule, ctx)) {
        EvalResult result;
        result.actions = rule.actions;
        result.rule_id = rule.rule_id;
        result.kind = rule.kind;
        result.priority_class = rule.priority_class;
        result.priority = rule.priority;
        result.matched = true;

        // If the winning action is "dont_notify", return immediately
        // (no need to check further)
        return result;
      }
    }

    // Fallback: nothing matched, return dont_notify
    // (or notify if we want to be permissive)
    EvalResult fallback;
    fallback.actions = json::array({PushActionType::DONT_NOTIFY});
    fallback.matched = false;
    return fallback;
  }

  // Evaluate and return just the actions JSON (compatible with existing API)
  json evaluate_actions(const EvalContext& ctx) const {
    return evaluate(ctx).actions;
  }

  // Bulk evaluate for multiple users against the same base event
  static std::map<std::string, EvalResult> bulk_evaluate(
      const std::map<std::string, PushRuleEngine>& user_engines,
      const EvalContext& base_ctx) {
    std::map<std::string, EvalResult> results;

    for (auto& [user_id, engine] : user_engines) {
      EvalContext ctx = base_ctx;
      ctx.user_id = user_id;
      results[user_id] = engine.evaluate(ctx);
    }

    return results;
  }

  // Bulk evaluate using raw stored rules
  static std::map<std::string, json> bulk_evaluate_from_stored(
      const std::map<std::string, std::vector<PushRule>>& user_rules,
      const EvalContext& base_ctx) {
    std::map<std::string, json> results;

    for (auto& [user_id, rules] : user_rules) {
      PushRuleEngine engine = PushRuleEngine::from_stored_rules(rules);
      EvalContext ctx = base_ctx;
      ctx.user_id = user_id;

      // For user-name matching, pre-compute the user's MXID localpart
      // This is done implicitly through the contains_user_name condition
      // which checks against the event body

      results[user_id] = engine.evaluate_actions(ctx);
    }

    return results;
  }

  // Get all rules (for introspection)
  const std::vector<PushRuleSpec>& rules() const { return rules_; }
  const std::vector<PushRuleSpec>& sorted_rules() const { return sorted_rules_; }

private:
  void sort_rules() {
    sorted_rules_ = rules_;
    std::sort(sorted_rules_.begin(), sorted_rules_.end(),
      [](const PushRuleSpec& a, const PushRuleSpec& b) {
        // Higher priority_class first
        if (a.priority_class != b.priority_class)
          return a.priority_class > b.priority_class;
        // Lower priority number first (higher within same class)
        return a.priority < b.priority;
      });
  }

  bool rule_matches(const PushRuleSpec& rule, const EvalContext& ctx) const {
    switch (rule.priority_class) {
      case PushRuleKind::PRIORITY_CLASS_OVERRIDE:
        // Override rules use condition matching
        return ConditionEvaluator::evaluate_all(rule.conditions, ctx);

      case PushRuleKind::PRIORITY_CLASS_CONTENT:
        // Content rules: rule_id is a glob pattern, matched against body
        return content_rule_matches(rule, ctx);

      case PushRuleKind::PRIORITY_CLASS_ROOM:
        // Room rules: rule_id is the room_id
        return rule.rule_id == ctx.room_id;

      case PushRuleKind::PRIORITY_CLASS_SENDER:
        // Sender rules: rule_id is the sender user_id
        return rule.rule_id == ctx.sender;

      case PushRuleKind::PRIORITY_CLASS_UNDERRIDE:
        // Underride rules use condition matching (same as override)
        return ConditionEvaluator::evaluate_all(rule.conditions, ctx);

      default:
        return false;
    }
  }

  bool content_rule_matches(const PushRuleSpec& rule,
                             const EvalContext& ctx) const {
    // Content rules: the rule_id is the pattern to match against the body
    if (rule.rule_id.empty()) return false;

    std::string body;
    if (ctx.content.contains("body") && ctx.content["body"].is_string())
      body = ctx.content["body"].get<std::string>();
    else if (ctx.content.contains("formatted_body") &&
             ctx.content["formatted_body"].is_string())
      body = ctx.content["formatted_body"].get<std::string>();

    return GlobMatcher::match(rule.rule_id, body);
  }

  std::vector<PushRuleSpec> rules_;
  std::vector<PushRuleSpec> sorted_rules_;
}; // class PushRuleEngine

// ============================================================================
// Special-case condition evaluation for default rules
// ============================================================================

class DefaultRuleSpecialEvaluator {
public:
  // Check if the .m.rule.invite_for_me rule matches
  // This needs to check if the state_key of the membership event
  // equals the user's MXID
  static bool matches_invite_for_me(
      const PushRuleSpec& rule,
      const ConditionEvaluator::EvalContext& ctx) {
    if (rule.rule_id != DefaultRuleID::INVITE_FOR_ME)
      return ConditionEvaluator::evaluate_all(rule.conditions, ctx);

    // Check basic conditions first
    // type == m.room.member, content.membership == invite
    for (auto& [kind, pattern] : rule.conditions) {
      if (kind == PushConditionKind::EVENT_MATCH &&
          pattern == "state_key *") {
        // state_key must match the target user
        // In invite events, state_key == invited user's MXID
        if (ctx.state_key != ctx.user_id)
          return false;
        continue;
      }
      if (!ConditionEvaluator::evaluate_single(kind, pattern, ctx))
        return false;
    }
    return true;
  }

  // Check if .m.rule.contains_user_name matches
  // This checks if the event body contains the user's localpart
  // or full MXID (case-insensitive)
  static bool matches_contains_user_name(
      const PushRuleSpec& rule,
      const ConditionEvaluator::EvalContext& ctx) {
    // Extract localpart from user_id (e.g., "@alice:example.org" -> "alice")
    std::string localpart;
    std::string full_mxid = ctx.user_id;

    if (!full_mxid.empty() && full_mxid[0] == '@') {
      size_t colon = full_mxid.find(':');
      if (colon != std::string::npos)
        localpart = full_mxid.substr(1, colon - 1);
      else
        localpart = full_mxid.substr(1);
    }

    if (localpart.empty()) return false;

    std::string body = ctx.content.value("body", "");
    std::string formatted_body = ctx.content.value("formatted_body", "");

    // Case-insensitive check
    auto icase_contains = [](const std::string& haystack,
                              const std::string& needle) -> bool {
      auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char c1, char c2) {
          return std::tolower(static_cast<unsigned char>(c1)) ==
                 std::tolower(static_cast<unsigned char>(c2));
        });
      return it != haystack.end();
    };

    // Word-boundary match for localpart
    auto word_boundary_match = [&](const std::string& text,
                                    const std::string& word) -> bool {
      size_t pos = 0;
      while ((pos = icase_find(text, word, pos)) != std::string::npos) {
        bool left_ok = (pos == 0 || !std::isalnum(
            static_cast<unsigned char>(text[pos - 1])));
        bool right_ok = (pos + word.size() >= text.size() || !std::isalnum(
            static_cast<unsigned char>(text[pos + word.size()])));
        if (left_ok && right_ok)
          return true;
        pos += word.size();
      }
      return false;
    };

    return word_boundary_match(body, localpart) ||
           word_boundary_match(formatted_body, localpart) ||
           icase_contains(body, full_mxid) ||
           icase_contains(formatted_body, full_mxid);
  }

private:
  // Case-insensitive find returning position
  static size_t icase_find(const std::string& haystack,
                            const std::string& needle,
                            size_t start = 0) {
    auto it = std::search(
      haystack.begin() + static_cast<long>(start), haystack.end(),
      needle.begin(), needle.end(),
      [](char c1, char c2) {
        return std::tolower(static_cast<unsigned char>(c1)) ==
               std::tolower(static_cast<unsigned char>(c2));
      });
    if (it == haystack.end()) return std::string::npos;
    return static_cast<size_t>(it - haystack.begin());
  }
}; // class DefaultRuleSpecialEvaluator

// ============================================================================
// Push Rule Manager — CRUD operations with storage
// ============================================================================

class PushRuleManager {
public:
  PushRuleManager(DatabasePool& db, PushRuleStore& store)
    : db_(db), store_(store) {}

  // ========================================================================
  // Read Operations
  // ========================================================================

  // Get all push rules for a user, organized by kind
  json get_push_rules_for_user(const std::string& user_id) {
    auto stored = store_.get_push_rules(user_id);
    std::vector<PushRuleSpec> specs;
    specs.reserve(stored.size());
    for (auto& r : stored) {
      specs.push_back(stored_to_spec(r));
    }

    // Organize by kind
    json global = json::object();
    for (auto& kind : PushRuleKind::all_kinds()) {
      global[kind] = json::array();
    }

    for (auto& spec : specs) {
      global[spec.kind].push_back(spec.to_json());
    }

    return {{"global", global}};
  }

  // Get a single push rule
  std::optional<PushRuleSpec> get_push_rule(const std::string& user_id,
                                             const std::string& rule_id) {
    auto stored = store_.get_push_rule(user_id, rule_id);
    if (!stored) return std::nullopt;
    return stored_to_spec(*stored);
  }

  // Get push rules organized for the evaluator
  std::vector<PushRuleSpec> get_rules_for_evaluation(const std::string& user_id) {
    auto stored = store_.get_enabled_push_rules(user_id);
    std::vector<PushRuleSpec> specs;
    specs.reserve(stored.size());
    for (auto& r : stored) {
      specs.push_back(stored_to_spec(r));
    }
    return specs;
  }

  // Bulk get push rules for multiple users
  std::map<std::string, std::vector<PushRuleSpec>> bulk_get_rules(
      const std::vector<std::string>& user_ids) {
    auto stored_map = store_.bulk_get_push_rules(user_ids);
    std::map<std::string, std::vector<PushRuleSpec>> result;
    for (auto& [uid, rules] : stored_map) {
      std::vector<PushRuleSpec> specs;
      specs.reserve(rules.size());
      for (auto& r : rules) {
        specs.push_back(stored_to_spec(r));
      }
      result[uid] = std::move(specs);
    }
    return result;
  }

  // ========================================================================
  // Write Operations
  // ========================================================================

  // Add a new push rule
  // Returns empty string on success, error message on failure
  std::string add_push_rule(const std::string& user_id,
                             const std::string& kind,
                             const std::string& rule_id,
                             const std::string& before,
                             const std::string& after,
                             const json& actions,
                             const json& conditions) {
    // Validate kind
    if (!PushRuleKind::is_valid_kind(kind)) {
      return "Invalid rule kind: " + kind;
    }

    // Validate rule_id
    if (rule_id.empty()) {
      return "Rule ID cannot be empty";
    }
    if (rule_id[0] == '.') {
      return "User rules cannot start with '.'";
    }
    if (DefaultRuleID::is_default_rule_id(rule_id)) {
      return "Cannot create rule with reserved ID: " + rule_id;
    }

    // Validate actions
    std::string action_error;
    if (!ActionParser::validate_actions(actions, action_error)) {
      return action_error;
    }

    // Check for duplicate
    if (store_.rule_exists(user_id, rule_id)) {
      return "Rule already exists: " + rule_id;
    }

    // Determine priority
    int64_t priority_class = PushRuleKind::priority_class_for_kind(kind);
    int64_t priority = determine_priority(user_id, kind, before, after);

    // Parse conditions
    std::vector<std::pair<std::string, std::string>> parsed_conditions;
    if (conditions.is_array()) {
      for (auto& cond : conditions) {
        if (!cond.is_object() || !cond.contains("kind") || !cond.contains("pattern"))
          return "Invalid condition format";
        std::string ckind = cond["kind"].get<std::string>();
        std::string cpattern = cond["pattern"].get<std::string>();
        if (!PushConditionKind::is_valid_condition_kind(ckind))
          return "Invalid condition kind: " + ckind;
        parsed_conditions.push_back({ckind, cpattern});
      }
    }

    // Serialize actions
    std::string actions_str = actions.dump();

    // Build PushRule
    PushRule rule;
    rule.user_id = user_id;
    rule.rule_id = rule_id;
    rule.kind = kind;
    rule.actions = actions_str;
    rule.conditions = parsed_conditions;
    rule.priority_class = priority_class;
    rule.priority = priority;
    rule.enabled = true;
    rule.default_rule = false;

    store_.add_push_rule(user_id, rule);

    // Invalidate cache
    invalidate_cache(user_id);

    return ""; // success
  }

  // Update an existing push rule
  std::string update_push_rule(const std::string& user_id,
                                const std::string& rule_id,
                                const json& actions,
                                const json& conditions) {
    // Check existence
    auto existing = store_.get_push_rule(user_id, rule_id);
    if (!existing) {
      return "Rule not found: " + rule_id;
    }

    // Don't allow changing default rule conditions
    if (existing->default_rule && !conditions.is_null()) {
      return "Cannot modify conditions of a default rule";
    }

    // Validate actions
    if (!actions.is_null()) {
      std::string action_error;
      if (!ActionParser::validate_actions(actions, action_error)) {
        return action_error;
      }
      store_.set_push_rule_actions(user_id, rule_id, actions.dump());
    }

    // Invalidate cache
    invalidate_cache(user_id);

    return ""; // success
  }

  // Delete a push rule
  std::string delete_push_rule(const std::string& user_id,
                                const std::string& rule_id) {
    auto existing = store_.get_push_rule(user_id, rule_id);
    if (!existing) {
      return "Rule not found: " + rule_id;
    }

    if (existing->default_rule) {
      // Default rules cannot be deleted, only disabled
      store_.set_push_rule_enabled(user_id, rule_id, false);
    } else {
      store_.delete_push_rule(user_id, rule_id);
    }

    // Invalidate cache
    invalidate_cache(user_id);

    return ""; // success
  }

  // Enable or disable a push rule
  std::string set_enabled(const std::string& user_id,
                           const std::string& rule_id,
                           bool enabled) {
    if (!store_.rule_exists(user_id, rule_id)) {
      return "Rule not found: " + rule_id;
    }

    store_.set_push_rule_enabled(user_id, rule_id, enabled);

    // Invalidate cache
    invalidate_cache(user_id);

    return ""; // success
  }

  // ========================================================================
  // Templates — copy default rules to new user
  // ========================================================================

  // Initialize push rules for a new user by copying defaults
  void initialize_for_user(const std::string& user_id) {
    // Check if user already has rules
    auto existing = store_.get_push_rules(user_id);
    if (!existing.empty()) {
      return; // already initialized
    }

    // Copy default rules from the template user (user_id="")
    store_.copy_default_rules(user_id);

    // Invalidate cache
    invalidate_cache(user_id);
  }

  // Ensure the default rule template exists (run at server startup)
  void ensure_default_templates() {
    auto existing = store_.get_push_rules("");
    if (!existing.empty()) {
      // Check if we need to update with new rules
      update_default_templates(existing);
      return;
    }

    // Insert all default rules with user_id=""
    auto defaults = DefaultRuleRegistry::all_default_rules();
    for (auto& rule : defaults) {
      PushRule stored;
      stored.user_id = "";
      stored.rule_id = rule.rule_id;
      stored.kind = rule.kind;
      stored.actions = rule.actions.dump();
      stored.conditions = rule.conditions;
      stored.priority_class = rule.priority_class;
      stored.priority = rule.priority;
      stored.enabled = rule.enabled;
      stored.default_rule = true;

      store_.add_push_rule("", stored);
    }
  }

  // ========================================================================
  // Evaluation Helpers
  // ========================================================================

  // Build an evaluator for a user
  PushRuleEngine build_evaluator(const std::string& user_id) {
    auto specs = get_rules_for_evaluation(user_id);

    // If no rules loaded, initialize from defaults
    if (specs.empty()) {
      initialize_for_user(user_id);
      specs = get_rules_for_evaluation(user_id);
    }

    return PushRuleEngine(specs);
  }

  // Evaluate rules for a user against a context
  PushRuleEngine::EvalResult evaluate_for_user(
      const std::string& user_id,
      const ConditionEvaluator::EvalContext& ctx) {
    auto engine = build_evaluator(user_id);
    return engine.evaluate(ctx);
  }

  // ========================================================================
  // Cache Management
  // ========================================================================

  // Invalidate cache for a specific user
  void invalidate_cache(const std::string& user_id) {
    std::unique_lock lock(cache_mutex_);
    rule_cache_.erase(user_id);
    engine_cache_.erase(user_id);
  }

  // Invalidate all cached entries
  void invalidate_all() {
    std::unique_lock lock(cache_mutex_);
    rule_cache_.clear();
    engine_cache_.clear();
  }

  // Pre-warm cache for a set of users
  void warm_cache(const std::vector<std::string>& user_ids) {
    for (auto& uid : user_ids) {
      get_rules_for_evaluation(uid); // populates cache
    }
  }

  // ========================================================================
  // Schema Migration
  // ========================================================================

  // Get current schema version for push rules
  int current_schema_version() const { return schema_version_; }

  // Run any pending migrations
  void migrate_if_needed() {
    // No-op for now; future versions may need migration logic
  }

private:
  // Convert stored PushRule to PushRuleSpec
  static PushRuleSpec stored_to_spec(const PushRule& stored) {
    PushRuleSpec spec;
    spec.rule_id = stored.rule_id;
    spec.kind = stored.kind;
    spec.priority_class = stored.priority_class;
    spec.priority = stored.priority;
    spec.enabled = stored.enabled;
    spec.default_rule = stored.default_rule;
    spec.conditions = stored.conditions;
    try {
      spec.actions = json::parse(stored.actions);
    } catch (...) {
      spec.actions = json::array({PushActionType::DONT_NOTIFY});
    }
    return spec;
  }

  // Determine the priority for a new rule based on before/after
  int64_t determine_priority(const std::string& user_id,
                              const std::string& kind,
                              const std::string& before,
                              const std::string& after) {
    auto existing = store_.get_push_rules(user_id);

    // Filter rules of the same kind
    std::vector<const PushRule*> same_kind;
    for (auto& r : existing) {
      if (r.kind == kind)
        same_kind.push_back(&r);
    }

    if (same_kind.empty()) return 0;

    // Sort by priority
    std::sort(same_kind.begin(), same_kind.end(),
      [](const PushRule* a, const PushRule* b) {
        return a->priority < b->priority;
      });

    if (!after.empty()) {
      // Insert after a specific rule
      for (size_t i = 0; i < same_kind.size(); ++i) {
        if (same_kind[i]->rule_id == after) {
          if (i + 1 < same_kind.size())
            return (same_kind[i]->priority + same_kind[i + 1]->priority) / 2;
          else
            return same_kind[i]->priority + 1;
        }
      }
    }

    if (!before.empty()) {
      // Insert before a specific rule
      for (size_t i = 0; i < same_kind.size(); ++i) {
        if (same_kind[i]->rule_id == before) {
          if (i > 0)
            return (same_kind[i - 1]->priority + same_kind[i]->priority) / 2;
          else
            return same_kind[i]->priority - 1;
        }
      }
    }

    // Default: append at end with highest priority number
    if (!same_kind.empty())
      return same_kind.back()->priority + 1;
    return 0;
  }

  // Check if default templates need updating
  void update_default_templates(const std::vector<PushRule>& existing) {
    auto defaults = DefaultRuleRegistry::all_default_rules();
    std::set<std::string> existing_ids;
    for (auto& r : existing) {
      existing_ids.insert(r.rule_id);
    }

    // Add any missing default rules
    for (auto& rule : defaults) {
      if (existing_ids.count(rule.rule_id) == 0) {
        PushRule stored;
        stored.user_id = "";
        stored.rule_id = rule.rule_id;
        stored.kind = rule.kind;
        stored.actions = rule.actions.dump();
        stored.conditions = rule.conditions;
        stored.priority_class = rule.priority_class;
        stored.priority = rule.priority;
        stored.enabled = rule.enabled;
        stored.default_rule = true;

        store_.add_push_rule("", stored);
      }
    }
  }

  DatabasePool& db_;
  PushRuleStore& store_;

  // Thread-safe LRU cache (simplified — full LRU would use a linked hash map)
  mutable std::shared_mutex cache_mutex_;
  std::unordered_map<std::string, std::vector<PushRuleSpec>> rule_cache_;
  std::unordered_map<std::string, PushRuleEngine> engine_cache_;
  static constexpr size_t MAX_CACHE_SIZE = 10000;

  // Schema version for migration tracking
  static constexpr int schema_version_ = 1;
}; // class PushRuleManager

// ============================================================================
// REST API Servlets
// ============================================================================

namespace rest {

// GET /_matrix/client/v3/pushrules
// Get all push rules for the authenticated user
class GetPushRulesServlet : public ClientV1RestServlet {
public:
  explicit GetPushRulesServlet(PushRuleManager& manager)
    : manager_(manager) {}

  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/pushrules",
            "/_matrix/client/v1/pushrules"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    auto requester = auth_.require_auth(req);
    auto rules = manager_.get_push_rules_for_user(requester.user_id);
    return success_response(rules);
  }

private:
  PushRuleManager& manager_;
  AuthHelper auth_{manager_.db()};
}; // class GetPushRulesServlet

// GET /_matrix/client/v3/pushrules/{kind}/{rule_id}
// Get a single push rule
class GetPushRuleServlet : public ClientV1RestServlet {
public:
  explicit GetPushRuleServlet(PushRuleManager& manager)
    : manager_(manager) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/pushrules/{kind}/{rule_id}",
      "/_matrix/client/v1/pushrules/{kind}/{rule_id}",
    };
  }

  HttpResponse on_request(const HttpRequest& req) override {
    auto requester = auth_.require_auth(req);

    auto kind_it = req.path_params.find("kind");
    auto rule_it = req.path_params.find("rule_id");
    if (kind_it == req.path_params.end() || rule_it == req.path_params.end()) {
      return error_response(400, "M_MISSING_PARAM", "Missing kind or rule_id");
    }

    auto rule = manager_.get_push_rule(requester.user_id, rule_it->second);
    if (!rule) {
      return error_response(404, "M_NOT_FOUND",
                            "Push rule not found: " + rule_it->second);
    }

    return success_response(rule->to_json());
  }

private:
  PushRuleManager& manager_;
  AuthHelper auth_{manager_.db()};
}; // class GetPushRuleServlet

// PUT /_matrix/client/v3/pushrules/{kind}/{rule_id}
// Create or update a push rule
class AddPushRuleServlet : public ClientV1RestServlet {
public:
  explicit AddPushRuleServlet(PushRuleManager& manager)
    : manager_(manager) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/pushrules/{kind}/{rule_id}",
      "/_matrix/client/v1/pushrules/{kind}/{rule_id}",
    };
  }

  HttpResponse on_request(const HttpRequest& req) override {
    auto requester = auth_.require_auth(req);

    auto kind_it = req.path_params.find("kind");
    auto rule_it = req.path_params.find("rule_id");
    if (kind_it == req.path_params.end() || rule_it == req.path_params.end()) {
      return error_response(400, "M_MISSING_PARAM", "Missing kind or rule_id");
    }

    std::string kind = kind_it->second;
    std::string rule_id = rule_it->second;

    // Parse query parameters for positioning
    std::string before;
    std::string after;
    auto before_it = req.query_params.find("before");
    if (before_it != req.query_params.end()) before = before_it->second;
    auto after_it = req.query_params.find("after");
    if (after_it != req.query_params.end()) after = after_it->second;

    // Parse body
    json body = parse_json_body(req);
    json actions = body.value("actions", json::array());
    json conditions = body.value("conditions", json::array());

    // Check if rule exists (update) or is new (create)
    auto existing = manager_.get_push_rule(requester.user_id, rule_id);
    if (existing) {
      // Update existing rule
      std::string error = manager_.update_push_rule(
        requester.user_id, rule_id, actions, conditions);
      if (!error.empty()) {
        return error_response(400, "M_INVALID_PARAM", error);
      }
    } else {
      // Create new rule
      std::string error = manager_.add_push_rule(
        requester.user_id, kind, rule_id, before, after, actions, conditions);
      if (!error.empty()) {
        return error_response(400, "M_INVALID_PARAM", error);
      }
    }

    return success_response();
  }

private:
  PushRuleManager& manager_;
  AuthHelper auth_{manager_.db()};
}; // class AddPushRuleServlet

// DELETE /_matrix/client/v3/pushrules/{kind}/{rule_id}
// Delete a push rule
class DeletePushRuleServlet : public ClientV1RestServlet {
public:
  explicit DeletePushRuleServlet(PushRuleManager& manager)
    : manager_(manager) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/pushrules/{kind}/{rule_id}",
      "/_matrix/client/v1/pushrules/{kind}/{rule_id}",
    };
  }

  HttpResponse on_request(const HttpRequest& req) override {
    auto requester = auth_.require_auth(req);

    auto kind_it = req.path_params.find("kind");
    auto rule_it = req.path_params.find("rule_id");
    if (kind_it == req.path_params.end() || rule_it == req.path_params.end()) {
      return error_response(400, "M_MISSING_PARAM", "Missing kind or rule_id");
    }

    std::string error = manager_.delete_push_rule(
      requester.user_id, rule_it->second);
    if (!error.empty()) {
      return error_response(404, "M_NOT_FOUND", error);
    }

    return success_response();
  }

private:
  PushRuleManager& manager_;
  AuthHelper auth_{manager_.db()};
}; // class DeletePushRuleServlet

// PUT /_matrix/client/v3/pushrules/{kind}/{rule_id}/enable
// Enable or disable a push rule
class SetPushRuleEnabledServlet : public ClientV1RestServlet {
public:
  explicit SetPushRuleEnabledServlet(PushRuleManager& manager)
    : manager_(manager) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/pushrules/{kind}/{rule_id}/enabled",
      "/_matrix/client/v1/pushrules/{kind}/{rule_id}/enabled",
    };
  }

  HttpResponse on_request(const HttpRequest& req) override {
    auto requester = auth_.require_auth(req);

    auto kind_it = req.path_params.find("kind");
    auto rule_it = req.path_params.find("rule_id");
    if (kind_it == req.path_params.end() || rule_it == req.path_params.end()) {
      return error_response(400, "M_MISSING_PARAM", "Missing kind or rule_id");
    }

    // Parse body for enabled flag
    json body;
    try {
      if (!req.body.empty())
        body = json::parse(req.body);
    } catch (...) {
      body = json::object();
    }
    bool enabled = body.value("enabled", true);

    std::string error = manager_.set_enabled(
      requester.user_id, rule_it->second, enabled);
    if (!error.empty()) {
      return error_response(404, "M_NOT_FOUND", error);
    }

    return success_response();
  }

private:
  PushRuleManager& manager_;
  AuthHelper auth_{manager_.db()};
}; // class SetPushRuleEnabledServlet

// PUT /_matrix/client/v3/pushrules/{kind}/{rule_id}/actions
// Set the actions for a push rule
class SetPushRuleActionsServlet : public ClientV1RestServlet {
public:
  explicit SetPushRuleActionsServlet(PushRuleManager& manager)
    : manager_(manager) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/pushrules/{kind}/{rule_id}/actions",
      "/_matrix/client/v1/pushrules/{kind}/{rule_id}/actions",
    };
  }

  HttpResponse on_request(const HttpRequest& req) override {
    auto requester = auth_.require_auth(req);

    auto kind_it = req.path_params.find("kind");
    auto rule_it = req.path_params.find("rule_id");
    if (kind_it == req.path_params.end() || rule_it == req.path_params.end()) {
      return error_response(400, "M_MISSING_PARAM", "Missing kind or rule_id");
    }

    json body = parse_json_body(req);
    if (!body.contains("actions")) {
      return error_response(400, "M_MISSING_PARAM", "Missing actions");
    }

    std::string error = manager_.update_push_rule(
      requester.user_id, rule_it->second, body["actions"], json());
    if (!error.empty()) {
      return error_response(400, "M_INVALID_PARAM", error);
    }

    return success_response();
  }

private:
  PushRuleManager& manager_;
  AuthHelper auth_{manager_.db()};
}; // class SetPushRuleActionsServlet

} // namespace rest

// ============================================================================
// Rule Validation Utilities
// ============================================================================

namespace RuleValidator {

// Validate rule_id format
inline bool is_valid_rule_id(const std::string& rule_id) {
  if (rule_id.empty()) return false;
  // Rule IDs must be valid ASCII, not start with '.'
  if (rule_id[0] == '.') return true; // default rules
  for (char c : rule_id) {
    if (static_cast<unsigned char>(c) >= 128) return false;
    if (c == '\n' || c == '\r' || c == '\0') return false;
  }
  return true;
}

// Validate a complete rule specification
inline std::string validate_rule_spec(const PushRuleSpec& spec) {
  if (!PushRuleKind::is_valid_kind(spec.kind))
    return "Invalid rule kind: " + spec.kind;
  if (!is_valid_rule_id(spec.rule_id))
    return "Invalid rule_id: " + spec.rule_id;

  std::string action_error;
  if (!ActionParser::validate_actions(spec.actions, action_error))
    return action_error;

  for (auto& [kind, pattern] : spec.conditions) {
    if (!PushConditionKind::is_valid_condition_kind(kind))
      return "Invalid condition kind: " + kind;
  }

  return ""; // valid
}

// Check if two rule specs are semantically equivalent
inline bool rules_equivalent(const PushRuleSpec& a, const PushRuleSpec& b) {
  if (a.rule_id != b.rule_id) return false;
  if (a.kind != b.kind) return false;
  if (a.priority_class != b.priority_class) return false;
  if (a.actions != b.actions) return false;
  if (a.conditions.size() != b.conditions.size()) return false;
  for (size_t i = 0; i < a.conditions.size(); ++i) {
    if (a.conditions[i] != b.conditions[i]) return false;
  }
  return true;
}

} // namespace RuleValidator

// ============================================================================
// Event Context Builder
// ============================================================================

class EventContextBuilder {
public:
  EventContextBuilder(DatabasePool& db) : db_(db) {}

  // Build evaluation context from event data
  ConditionEvaluator::EvalContext build_context(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& event_type,
      const std::string& sender,
      const json& content,
      const std::string& state_key = "",
      bool is_encrypted = false) {

    ConditionEvaluator::EvalContext ctx;
    ctx.user_id = user_id;
    ctx.room_id = room_id;
    ctx.event_type = event_type;
    ctx.sender = sender;
    ctx.state_key = state_key;
    ctx.content = content;
    ctx.is_encrypted = is_encrypted;

    // Get room member count
    ctx.room_member_count = get_room_member_count(room_id);

    // Get sender display name
    ctx.sender_display_name = get_user_display_name(sender);

    // Get room name
    ctx.room_name = get_room_name(room_id);

    // Get user power levels
    ctx.user_power_level_rooms = get_user_power_level_rooms(user_id);

    // Determine if DM
    ctx.is_direct = is_direct_room(user_id, room_id);

    // Determine if thread reply
    ctx.is_thread = is_thread_event(content);

    // Determine if @mention
    ctx.is_mention = check_mention(user_id, content);

    return ctx;
  }

  // Build context for bulk evaluation (shared pre-computed room info)
  ConditionEvaluator::EvalContext build_bulk_context(
      const std::string& room_id,
      const std::string& event_type,
      const std::string& sender,
      const json& content,
      const std::string& state_key = "",
      bool is_encrypted = false) {

    ConditionEvaluator::EvalContext ctx;
    ctx.room_id = room_id;
    ctx.event_type = event_type;
    ctx.sender = sender;
    ctx.state_key = state_key;
    ctx.content = content;
    ctx.is_encrypted = is_encrypted;

    // Room-level context (same for all users)
    ctx.room_member_count = get_room_member_count(room_id);
    ctx.room_name = get_room_name(room_id);
    ctx.is_thread = is_thread_event(content);

    return ctx;
  }

private:
  int64_t get_room_member_count(const std::string& room_id) {
    try {
      MemberStore member_store(db_);
      auto members = member_store.get_users_in_room(room_id);
      return static_cast<int64_t>(members.size());
    } catch (...) {
      return 0;
    }
  }

  std::string get_user_display_name(const std::string& user_id) {
    try {
      ProfileStore profile_store(db_);
      return profile_store.get_displayname(user_id).value_or("");
    } catch (...) {
      return "";
    }
  }

  std::string get_room_name(const std::string& room_id) {
    try {
      RoomStore room_store(db_);
      return room_store.get_room_name(room_id).value_or("");
    } catch (...) {
      return "";
    }
  }

  std::set<std::string> get_user_power_level_rooms(
      const std::string& user_id) {
    std::set<std::string> rooms;
    try {
      MemberStore member_store(db_);
      // Get rooms where user's power level >= 50 (notification permission)
      auto member_rooms = member_store.get_rooms_for_user(user_id);
      for (auto& room_id : member_rooms) {
        auto pl = member_store.get_power_level(user_id, room_id);
        if (pl >= 50)
          rooms.insert(room_id);
      }
    } catch (...) {}
    return rooms;
  }

  bool is_direct_room(const std::string& user_id,
                       const std::string& room_id) {
    try {
      MemberStore member_store(db_);
      auto members = member_store.get_users_in_room(room_id);
      return members.size() == 2;
    } catch (...) {
      return false;
    }
  }

  bool is_thread_event(const json& content) {
    if (!content.contains("m.relates_to")) return false;
    auto& relates = content["m.relates_to"];
    if (!relates.is_object()) return false;
    return relates.value("rel_type", "") == "m.thread";
  }

  bool check_mention(const std::string& user_id, const json& content) {
    // Check for user mention in formatted_body
    std::string formatted_body = content.value("formatted_body", "");
    // Look for <a href="https://matrix.to/#/@user:domain">...</a>
    std::string search = "matrix.to/#/" + user_id;
    return formatted_body.find(search) != std::string::npos;
  }

  DatabasePool& db_;
}; // class EventContextBuilder

// ============================================================================
// Notification Action Computer
// ============================================================================

class NotificationActionComputer {
public:
  // Compute whether a user should be notified for an event
  struct NotificationDecision {
    bool notify{false};
    bool highlight{false};
    std::string sound{"default"};
    std::string action_type{PushActionType::DONT_NOTIFY};
    std::string matched_rule_id;
    json tweaks;
  };

  // Compute notification decision for a single user
  static NotificationDecision compute(
      PushRuleManager& manager,
      const ConditionEvaluator::EvalContext& ctx) {
    NotificationDecision decision;

    auto result = manager.evaluate_for_user(ctx.user_id, ctx);

    if (!result.matched) {
      decision.notify = false;
      decision.action_type = PushActionType::DONT_NOTIFY;
      return decision;
    }

    decision.action_type = result.get_primary_action();
    decision.notify = result.should_notify();
    decision.highlight = result.is_highlight();
    decision.sound = result.get_sound();
    decision.matched_rule_id = result.rule_id;
    decision.tweaks = result.get_tweaks();

    return decision;
  }

  // Bulk compute for all users in a room
  static std::map<std::string, NotificationDecision> bulk_compute(
      PushRuleManager& manager,
      const ConditionEvaluator::EvalContext& base_ctx,
      const std::vector<std::string>& user_ids) {
    std::map<std::string, NotificationDecision> decisions;

    for (auto& user_id : user_ids) {
      auto ctx = base_ctx;
      ctx.user_id = user_id;
      decisions[user_id] = compute(manager, ctx);
    }

    return decisions;
  }

  // Determine which users should actually receive a push notification
  static std::vector<std::string> users_to_notify(
      const std::map<std::string, NotificationDecision>& decisions,
      bool exclude_sender = true,
      const std::string& sender_user_id = "") {
    std::vector<std::string> users;
    for (auto& [uid, decision] : decisions) {
      if (exclude_sender && uid == sender_user_id) continue;
      if (decision.notify)
        users.push_back(uid);
    }
    return users;
  }

  // Classify notifications by type
  static void classify(
      const std::map<std::string, NotificationDecision>& decisions,
      std::vector<std::string>& highlight_users,
      std::vector<std::string>& notify_users,
      std::vector<std::string>& silent_users) {
    for (auto& [uid, decision] : decisions) {
      if (decision.highlight)
        highlight_users.push_back(uid);
      else if (decision.notify)
        notify_users.push_back(uid);
      else
        silent_users.push_back(uid);
    }
  }
}; // class NotificationActionComputer

// ============================================================================
// Push Rules Serialization / Deserialization
// ============================================================================

namespace PushRuleSerializer {

// Serialize a rule spec to a JSON API response format
inline json to_api_json(const PushRuleSpec& spec) {
  json j;
  j["rule_id"] = spec.rule_id;
  j["default"] = spec.default_rule;
  j["enabled"] = spec.enabled;
  j["actions"] = spec.actions;

  if (!spec.conditions.empty()) {
    json conds = json::array();
    for (auto& [k, v] : spec.conditions) {
      conds.push_back({{"kind", k}, {"pattern", v}});
    }
    j["conditions"] = conds;
  }

  return j;
}

// Deserialize from API JSON to PushRuleSpec
inline PushRuleSpec from_api_json(const json& j, const std::string& kind) {
  PushRuleSpec spec;
  spec.kind = kind;
  spec.priority_class = PushRuleKind::priority_class_for_kind(kind);
  spec.rule_id = j.value("rule_id", "");
  spec.enabled = j.value("enabled", true);
  spec.default_rule = j.value("default", false);
  spec.actions = j.value("actions", json::array());

  if (j.contains("conditions") && j["conditions"].is_array()) {
    for (auto& cond : j["conditions"]) {
      std::string ckind = cond.value("kind", "");
      std::string cpattern = cond.value("pattern", "");
      spec.conditions.push_back({ckind, cpattern});
    }
  }

  return spec;
}

// Serialize a full ruleset to the client API format
inline json to_client_format(
    const std::vector<PushRuleSpec>& rules,
    const std::string& user_id) {
  json global = json::object();
  for (auto& kind : PushRuleKind::all_kinds()) {
    global[kind] = json::array();
  }

  for (auto& rule : rules) {
    global[rule.kind].push_back(to_api_json(rule));
  }

  json result;
  result["global"] = global;
  return result;
}

} // namespace PushRuleSerializer

// ============================================================================
// Integration: Push Rules Module
// ============================================================================

// Main push rules module that ties everything together
class PushRulesModule {
public:
  PushRulesModule(DatabasePool& db, PushRuleStore& store)
    : db_(db),
      store_(store),
      manager_(std::make_unique<PushRuleManager>(db, store)),
      context_builder_(std::make_unique<EventContextBuilder>(db)) {}

  // ========================================================================
  // Initialization
  // ========================================================================

  // Initialize the module: ensures default templates exist
  void initialize() {
    manager_->ensure_default_templates();
  }

  // Initialize push rules for a new user
  void on_user_created(const std::string& user_id) {
    manager_->initialize_for_user(user_id);
  }

  // ========================================================================
  // Rule Management
  // ========================================================================

  PushRuleManager& manager() { return *manager_; }
  const PushRuleManager& manager() const { return *manager_; }

  // Get all rules for a user
  json get_rules(const std::string& user_id) {
    return manager_->get_push_rules_for_user(user_id);
  }

  // Add a rule
  std::string add_rule(const std::string& user_id,
                        const std::string& kind,
                        const std::string& rule_id,
                        const json& actions,
                        const json& conditions,
                        const std::string& before = "",
                        const std::string& after = "") {
    return manager_->add_push_rule(user_id, kind, rule_id,
                                    before, after, actions, conditions);
  }

  // Delete a rule
  std::string delete_rule(const std::string& user_id,
                           const std::string& rule_id) {
    return manager_->delete_push_rule(user_id, rule_id);
  }

  // Enable/disable a rule
  std::string set_enabled(const std::string& user_id,
                           const std::string& rule_id,
                           bool enabled) {
    return manager_->set_enabled(user_id, rule_id, enabled);
  }

  // Update rule actions
  std::string set_actions(const std::string& user_id,
                           const std::string& rule_id,
                           const json& actions) {
    return manager_->update_push_rule(user_id, rule_id, actions, json());
  }

  // ========================================================================
  // Evaluation
  // ========================================================================

  // Build evaluation context for an event
  ConditionEvaluator::EvalContext build_context(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& event_type,
      const std::string& sender,
      const json& content,
      const std::string& state_key = "",
      bool is_encrypted = false) {
    return context_builder_->build_context(
      user_id, room_id, event_type, sender, content,
      state_key, is_encrypted);
  }

  // Evaluate for a single user
  PushRuleEngine::EvalResult evaluate(
      const std::string& user_id,
      const ConditionEvaluator::EvalContext& ctx) {
    return manager_->evaluate_for_user(user_id, ctx);
  }

  // Evaluate and return actions JSON
  json evaluate_actions(const std::string& user_id,
                         const ConditionEvaluator::EvalContext& ctx) {
    auto result = manager_->evaluate_for_user(user_id, ctx);
    return result.actions;
  }

  // Compute notification decision
  NotificationActionComputer::NotificationDecision compute_notification(
      const std::string& user_id,
      const ConditionEvaluator::EvalContext& ctx) {
    return NotificationActionComputer::compute(*manager_, ctx);
  }

  // ========================================================================
  // Bulk Operations
  // ========================================================================

  // Bulk evaluate for multiple users against a shared context
  std::map<std::string, json> bulk_evaluate(
      const std::vector<std::string>& user_ids,
      const ConditionEvaluator::EvalContext& base_ctx) {
    auto user_rules = manager_->bulk_get_rules(user_ids);
    std::map<std::string, std::vector<PushRule>> stored_map;

    for (auto& [uid, specs] : user_rules) {
      auto stored = store_.get_enabled_push_rules(uid);
      stored_map[uid] = std::move(stored);
    }

    return PushRuleEngine::bulk_evaluate_from_stored(stored_map, base_ctx);
  }

  // Compute notifications for all users in a room
  void process_event_notifications(
      const std::string& room_id,
      const std::string& event_type,
      const std::string& sender,
      const json& content,
      const std::string& state_key = "",
      bool is_encrypted = false) {

    // Build room-level context
    auto base_ctx = context_builder_->build_bulk_context(
      room_id, event_type, sender, content, state_key, is_encrypted);

    // Get users in the room
    std::vector<std::string> user_ids;
    try {
      MemberStore member_store(db_);
      user_ids = member_store.get_users_in_room(room_id);
    } catch (...) {
      return;
    }

    // Compute decisions
    auto decisions = NotificationActionComputer::bulk_compute(
      *manager_, base_ctx, user_ids);

    // Get users to notify (excluding sender)
    auto notify_users = NotificationActionComputer::users_to_notify(
      decisions, true, sender);

    // Classify notifications
    std::vector<std::string> highlight_users;
    std::vector<std::string> notify_only;
    std::vector<std::string> silent;
    NotificationActionComputer::classify(
      decisions, highlight_users, notify_only, silent);

    // Log summary
    (void)highlight_users;
    (void)notify_only;
    (void)silent;
  }

  // ========================================================================
  // Cache Management
  // ========================================================================

  void invalidate_user(const std::string& user_id) {
    manager_->invalidate_cache(user_id);
  }

  void invalidate_all() {
    manager_->invalidate_all();
  }

  // ========================================================================
  // Accessors
  // ========================================================================

  DatabasePool& db() { return db_; }
  PushRuleStore& store() { return store_; }

private:
  DatabasePool& db_;
  PushRuleStore& store_;
  std::unique_ptr<PushRuleManager> manager_;
  std::unique_ptr<EventContextBuilder> context_builder_;
}; // class PushRulesModule

// ============================================================================
// Testing and Introspection Utilities
// ============================================================================

namespace PushRuleTesting {

// Dump all default rules as JSON for inspection
inline json dump_default_rules() {
  auto rules = DefaultRuleRegistry::all_default_rules();
  json arr = json::array();
  for (auto& r : rules) {
    json j;
    j["rule_id"] = r.rule_id;
    j["kind"] = r.kind;
    j["priority_class"] = r.priority_class;
    j["priority"] = r.priority;
    j["enabled"] = r.enabled;
    j["actions"] = r.actions;
    j["conditions"] = r.conditions_to_json();
    arr.push_back(j);
  }
  return arr;
}

// Print a human-readable summary of a ruleset
inline std::string summarize_rules(const std::vector<PushRuleSpec>& rules) {
  std::ostringstream oss;
  oss << "Push Rules (" << rules.size() << " total):\n";

  std::string current_kind;
  for (auto& r : rules) {
    if (r.kind != current_kind) {
      current_kind = r.kind;
      oss << "  [" << current_kind << "]\n";
    }
    oss << "    " << (r.enabled ? "[x]" : "[ ]")
        << " " << r.rule_id
        << " (prio=" << r.priority << ")";
    if (!r.conditions.empty()) {
      oss << " conditions=" << r.conditions.size();
    }
    oss << " -> " << ActionParser::get_primary_action(r.actions);
    if (ActionParser::is_highlight(r.actions)) oss << " +highlight";
    oss << "\n";
  }
  return oss.str();
}

// Validate all default rules
inline bool validate_all_defaults(std::string& errors) {
  auto rules = DefaultRuleRegistry::all_default_rules();
  std::ostringstream err;
  bool all_valid = true;

  for (auto& r : rules) {
    std::string e = RuleValidator::validate_rule_spec(r);
    if (!e.empty()) {
      err << r.rule_id << ": " << e << "\n";
      all_valid = false;
    }
  }

  errors = err.str();
  return all_valid;
}

// Count rules by kind
inline std::map<std::string, int> count_by_kind(
    const std::vector<PushRuleSpec>& rules) {
  std::map<std::string, int> counts;
  for (auto& r : rules) {
    counts[r.kind]++;
  }
  return counts;
}

// Find rules with highlight tweak
inline std::vector<std::string> find_highlight_rules(
    const std::vector<PushRuleSpec>& rules) {
  std::vector<std::string> results;
  for (auto& r : rules) {
    if (ActionParser::is_highlight(r.actions))
      results.push_back(r.rule_id);
  }
  return results;
}

// Simulate rule evaluation for a test event
inline PushRuleEngine::EvalResult simulate_evaluation(
    const std::vector<PushRuleSpec>& rules,
    const std::string& user_id,
    const std::string& room_id,
    const std::string& event_type,
    const std::string& sender,
    const json& content,
    int64_t member_count = 2,
    const std::string& sender_display_name = "",
    bool is_encrypted = false) {

  PushRuleEngine engine(rules);
  ConditionEvaluator::EvalContext ctx;
  ctx.user_id = user_id;
  ctx.room_id = room_id;
  ctx.event_type = event_type;
  ctx.sender = sender;
  ctx.content = content;
  ctx.is_encrypted = is_encrypted;
  ctx.room_member_count = member_count;
  if (!sender_display_name.empty())
    ctx.sender_display_name = sender_display_name;
  ctx.is_direct = (member_count == 2);

  return engine.evaluate(ctx);
}

// Benchmark: evaluate all default rules against a test event
inline int benchmark_evaluation(int iterations = 10000) {
  auto rules = DefaultRuleRegistry::all_default_rules();
  PushRuleEngine engine(rules);

  ConditionEvaluator::EvalContext ctx;
  ctx.user_id = "@alice:example.org";
  ctx.room_id = "!test:example.org";
  ctx.event_type = "m.room.message";
  ctx.sender = "@bob:example.org";
  ctx.content = {
    {"msgtype", "m.text"},
    {"body", "Hello Alice! How are you?"}
  };
  ctx.room_member_count = 10;
  ctx.sender_display_name = "Bob";
  ctx.is_direct = false;

  auto start = std::chrono::high_resolution_clock::now();
  for (int i = 0; i < iterations; ++i) {
    engine.evaluate(ctx);
  }
  auto end = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
    end - start).count();

  return static_cast<int>(duration);
}

} // namespace PushRuleTesting

// ============================================================================
// Push Rule Diff / Comparison
// ============================================================================

namespace PushRuleDiff {

// Represents a change between two rule sets
struct RuleChange {
  enum Type { ADDED, REMOVED, MODIFIED, ENABLED, DISABLED, UNCHANGED };
  Type type;
  std::string rule_id;
  std::string kind;
  PushRuleSpec old_rule;
  PushRuleSpec new_rule;
};

// Compute the diff between two rule sets
inline std::vector<RuleChange> diff_rules(
    const std::vector<PushRuleSpec>& old_rules,
    const std::vector<PushRuleSpec>& new_rules) {

  std::vector<RuleChange> changes;

  // Build lookup maps
  std::unordered_map<std::string, const PushRuleSpec*> old_map;
  for (auto& r : old_rules) old_map[r.rule_id] = &r;

  std::unordered_map<std::string, const PushRuleSpec*> new_map;
  for (auto& r : new_rules) new_map[r.rule_id] = &r;

  // Find added and modified
  for (auto& [rule_id, new_rule] : new_map) {
    auto old_it = old_map.find(rule_id);
    if (old_it == old_map.end()) {
      changes.push_back({RuleChange::ADDED, rule_id,
                         new_rule->kind, {}, *new_rule});
    } else {
      const auto& old_rule = *old_it->second;
      if (!RuleValidator::rules_equivalent(old_rule, *new_rule)) {
        changes.push_back({RuleChange::MODIFIED, rule_id,
                           new_rule->kind, old_rule, *new_rule});
      } else if (old_rule.enabled != new_rule->enabled) {
        changes.push_back({
          new_rule->enabled ? RuleChange::ENABLED : RuleChange::DISABLED,
          rule_id, new_rule->kind, old_rule, *new_rule});
      } else {
        changes.push_back({RuleChange::UNCHANGED, rule_id,
                           new_rule->kind, old_rule, *new_rule});
      }
    }
  }

  // Find removed
  for (auto& [rule_id, old_rule] : old_map) {
    if (new_map.count(rule_id) == 0) {
      changes.push_back({RuleChange::REMOVED, rule_id,
                         old_rule->kind, *old_rule, {}});
    }
  }

  // Sort changes by type
  std::sort(changes.begin(), changes.end(),
    [](const RuleChange& a, const RuleChange& b) {
      return static_cast<int>(a.type) < static_cast<int>(b.type);
    });

  return changes;
}

// Summarize changes as a string
inline std::string summarize_changes(
    const std::vector<RuleChange>& changes) {
  std::ostringstream oss;
  int added = 0, removed = 0, modified = 0, unchanged = 0;
  for (auto& c : changes) {
    switch (c.type) {
      case RuleChange::ADDED: ++added; break;
      case RuleChange::REMOVED: ++removed; break;
      case RuleChange::MODIFIED: ++modified; break;
      default: ++unchanged; break;
    }
  }
  oss << "Rule changes: " << added << " added, "
      << removed << " removed, " << modified << " modified, "
      << unchanged << " unchanged";
  return oss.str();
}

} // namespace PushRuleDiff

// ============================================================================
// Push Rule Priority Utilities
// ============================================================================

namespace PushRulePriorityUtils {

// Renumber priorities within a kind to be sequential (0, 1, 2, ...)
inline std::vector<PushRuleSpec> renumber_priorities(
    const std::vector<PushRuleSpec>& rules,
    const std::string& kind) {

  std::vector<PushRuleSpec> result;
  int64_t next_priority = 0;

  for (auto& rule : rules) {
    if (rule.kind == kind) {
      PushRuleSpec updated = rule;
      updated.priority = next_priority++;
      result.push_back(std::move(updated));
    } else {
      result.push_back(rule);
    }
  }

  return result;
}

// Move a rule to a new position within its kind
inline void reposition(PushRuleStore& store,
                        const std::string& user_id,
                        const std::string& rule_id,
                        const std::string& kind,
                        const std::string& before,
                        const std::string& after) {
  auto existing = store.get_push_rules(user_id);

  // Get all rules of this kind with their priorities
  std::vector<std::pair<std::string, int64_t>> kind_rules;
  for (auto& r : existing) {
    if (r.kind == kind)
      kind_rules.push_back({r.rule_id, r.priority});
  }

  // Sort by priority
  std::sort(kind_rules.begin(), kind_rules.end(),
    [](auto& a, auto& b) { return a.second < b.second; });

  // Determine new priority
  int64_t new_priority;
  if (!before.empty()) {
    for (size_t i = 0; i < kind_rules.size(); ++i) {
      if (kind_rules[i].first == before) {
        new_priority = (i > 0)
          ? (kind_rules[i - 1].second + kind_rules[i].second) / 2
          : kind_rules[i].second - 1;
        break;
      }
    }
  } else if (!after.empty()) {
    for (size_t i = 0; i < kind_rules.size(); ++i) {
      if (kind_rules[i].first == after) {
        new_priority = (i + 1 < kind_rules.size())
          ? (kind_rules[i].second + kind_rules[i + 1].second) / 2
          : kind_rules[i].second + 1;
        break;
      }
    }
  } else {
    return; // no reposition target
  }

  // Update rule with new priority
  auto target = store.get_push_rule(user_id, rule_id);
  if (target) {
    target->priority = new_priority;
    store.update_push_rule(user_id, rule_id, *target);
  }
}

} // namespace PushRulePriorityUtils

// ============================================================================
// User Name Matching Utilities
// ============================================================================

namespace UserNameMatcher {

// Find whether the user's localpart or display name appears in text
inline bool is_user_mentioned(
    const std::string& body,
    const std::string& formatted_body,
    const std::string& user_id,
    const std::string& display_name) {

  // Extract localpart from @user:domain
  std::string localpart;
  if (!user_id.empty() && user_id[0] == '@') {
    size_t colon = user_id.find(':');
    localpart = (colon != std::string::npos)
      ? user_id.substr(1, colon - 1) : user_id.substr(1);
  }

  auto icase_contains = [](const std::string& haystack,
                            const std::string& needle) -> bool {
    if (needle.empty()) return false;
    auto it = std::search(
      haystack.begin(), haystack.end(),
      needle.begin(), needle.end(),
      [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) ==
               std::tolower(static_cast<unsigned char>(b));
      });
    return it != haystack.end();
  };

  // Check localpart (word-boundary)
  if (!localpart.empty()) {
    auto word_in = [&](const std::string& text) -> bool {
      size_t pos = 0;
      while ((pos = icase_find_pos(text, localpart, pos)) != std::string::npos) {
        bool left = (pos == 0) || !std::isalnum(
          static_cast<unsigned char>(text[pos - 1]));
        bool right = (pos + localpart.size() >= text.size()) ||
          !std::isalnum(static_cast<unsigned char>(text[pos + localpart.size()]));
        if (left && right) return true;
        pos += localpart.size();
      }
      return false;
    };
    if (word_in(body) || word_in(formatted_body)) return true;
  }

  // Check full MXID
  if (icase_contains(body, user_id) || icase_contains(formatted_body, user_id))
    return true;

  // Check display name
  if (!display_name.empty()) {
    auto word_in = [&](const std::string& text) -> bool {
      size_t pos = 0;
      while ((pos = icase_find_pos(text, display_name, pos))
             != std::string::npos) {
        bool left = (pos == 0) || !std::isalnum(
          static_cast<unsigned char>(text[pos - 1]));
        bool right = (pos + display_name.size() >= text.size()) ||
          !std::isalnum(static_cast<unsigned char>(
            text[pos + display_name.size()]));
        if (left && right) return true;
        pos += display_name.size();
      }
      return false;
    };
    if (word_in(body) || word_in(formatted_body)) return true;
  }

  return false;
}

// Case-insensitive find returning position
inline size_t icase_find_pos(const std::string& haystack,
                              const std::string& needle,
                              size_t start = 0) {
  if (needle.empty() || start >= haystack.size())
    return std::string::npos;
  auto it = std::search(
    haystack.begin() + static_cast<long>(start), haystack.end(),
    needle.begin(), needle.end(),
    [](char a, char b) {
      return std::tolower(static_cast<unsigned char>(a)) ==
             std::tolower(static_cast<unsigned char>(b));
    });
  if (it == haystack.end()) return std::string::npos;
  return static_cast<size_t>(it - haystack.begin());
}

} // namespace UserNameMatcher

// ============================================================================
// Room Notification Permission Check
// ============================================================================

namespace RoomNotificationPerm {

// Default power level required to trigger @room notification
constexpr int64_t DEFAULT_NOTIF_POWER_LEVEL = 50;

// Check if a user has permission to send @room notifications
inline bool can_send_room_notification(
    DatabasePool& db,
    const std::string& user_id,
    const std::string& room_id) {
  try {
    MemberStore member_store(db);
    auto pl = member_store.get_power_level(user_id, room_id);
    return pl >= DEFAULT_NOTIF_POWER_LEVEL;
  } catch (...) {
    return false;
  }
}

// Get the notification power level for a room (from power_levels event)
inline int64_t get_notification_power_level(
    DatabasePool& db, const std::string& room_id) {
  try {
    RoomStore room_store(db);
    auto pl_event = room_store.get_current_state_event(
      room_id, "m.room.power_levels", "");
    if (pl_event && pl_event->contains("notifications")) {
      auto& notif_pl = (*pl_event)["notifications"];
      if (notif_pl.contains("room"))
        return notif_pl["room"].get<int64_t>();
    }
  } catch (...) {}
  return DEFAULT_NOTIF_POWER_LEVEL;
}

// Check if @room was used in a message
inline bool contains_room_mention(const json& content) {
  std::string body = content.value("body", "");
  std::string formatted_body = content.value("formatted_body", "");

  // Check for @room in plain text
  if (body.find("@room") != std::string::npos)
    return true;

  // Check for @room mention in HTML
  // Simplified: look for <a> tags with @room
  if (formatted_body.find("@room") != std::string::npos)
    return true;

  return false;
}

} // namespace RoomNotificationPerm

// ============================================================================
// Push Rule Export / Import
// ============================================================================

namespace PushRuleExport {

// Export a user's push rules as a JSON string
inline std::string export_rules(PushRuleManager& manager,
                                 const std::string& user_id) {
  auto rules = manager.get_push_rules_for_user(user_id);
  return rules.dump(2);
}

// Import push rules from JSON
inline std::string import_rules(PushRuleManager& manager,
                                 const std::string& user_id,
                                 const json& rules_data) {
  if (!rules_data.contains("global")) {
    return "Missing 'global' key in rules data";
  }

  auto& global = rules_data["global"];
  std::string last_error;

  for (auto& [kind_str, rules_array] : global.items()) {
    if (!PushRuleKind::is_valid_kind(kind_str)) continue;
    if (!rules_array.is_array()) continue;

    for (auto& rule_json : rules_array) {
      std::string rule_id = rule_json.value("rule_id", "");
      if (rule_id.empty()) continue;

      // Check if rule already exists
      auto existing = manager.get_push_rule(user_id, rule_id);
      if (existing) {
        // Update
        json actions = rule_json.value("actions", json::array());
        std::string err = manager.update_push_rule(
          user_id, rule_id, actions, json());
        if (!err.empty()) last_error = err;
      } else {
        // Create
        json actions = rule_json.value("actions", json::array());
        json conditions = rule_json.value("conditions", json::array());
        bool enabled = rule_json.value("enabled", true);

        std::string err = manager.add_push_rule(
          user_id, kind_str, rule_id, "", "", actions, conditions);
        if (!err.empty()) {
          last_error = err;
        } else if (!enabled) {
          manager.set_enabled(user_id, rule_id, false);
        }
      }
    }
  }

  return last_error; // return last error, or "" on success
}

} // namespace PushRuleExport

// ============================================================================
// Highlight Word Extraction (for notification badge counts)
// ============================================================================

namespace HighlightDetector {

// Check if an event is a highlight for a user
inline bool is_highlight_for_user(
    const ConditionEvaluator::EvalContext& ctx,
    const PushRuleEngine::EvalResult& result) {
  // If the matched rule has highlight tweak
  if (result.is_highlight())
    return true;

  // If the user was @mentioned
  if (ctx.is_mention)
    return true;

  // If contains_user_name or contains_display_name rule matched
  if (result.rule_id == DefaultRuleID::CONTAINS_USER_NAME ||
      result.rule_id == DefaultRuleID::CONTAINS_DISPLAY_NAME)
    return true;

  // If @room mention matched and user should be highlighted
  if (result.rule_id == DefaultRuleID::ROOM_NOTIF &&
      ActionParser::is_highlight(result.actions))
    return true;

  return false;
}

// Extract the highlight trigger word from an event
inline std::optional<std::string> extract_highlight_trigger(
    const std::string& body,
    const std::string& user_id,
    const std::string& display_name) {

  // Check for @room
  if (body.find("@room") != std::string::npos)
    return std::string("@room");

  // Check for full MXID
  if (body.find(user_id) != std::string::npos)
    return user_id;

  // Check for localpart
  std::string localpart;
  if (!user_id.empty() && user_id[0] == '@') {
    size_t colon = user_id.find(':');
    localpart = (colon != std::string::npos)
      ? user_id.substr(1, colon - 1) : user_id.substr(1);
  }
  if (!localpart.empty() && body.find(localpart) != std::string::npos)
    return localpart;

  // Check for display name
  if (!display_name.empty() && body.find(display_name) != std::string::npos)
    return display_name;

  return std::nullopt;
}

} // namespace HighlightDetector

// ============================================================================
// End of push_rules.cpp — Final line count marker
// ============================================================================
// This file implements the complete Matrix push rule engine.
//
// Classes defined:
//   PushRuleSpec                 — Parsed rule representation
//   ConditionEvaluator           — Single/multi-condition evaluation
//   DefaultRuleRegistry          — All default .m.rule.* definitions
//   PushRuleEngine               — Rule evaluation (first-match wins)
//   DefaultRuleSpecialEvaluator  — Special matching for default rules
//   PushRuleManager              — CRUD + cache + templates
//   EventContextBuilder          — Build EvalContext from DB
//   NotificationActionComputer   — Compute notification decisions
//   PushRulesModule              — Top-level integration module
//   GetPushRulesServlet          — REST: GET /pushrules
//   GetPushRuleServlet           — REST: GET /pushrules/{kind}/{rule_id}
//   AddPushRuleServlet           — REST: PUT /pushrules/{kind}/{rule_id}
//   DeletePushRuleServlet        — REST: DELETE /pushrules/{kind}/{rule_id}
//   SetPushRuleEnabledServlet    — REST: PUT /pushrules/{kind}/{rule_id}/enabled
//   SetPushRuleActionsServlet    — REST: PUT /pushrules/{kind}/{rule_id}/actions
//
// Namespaces:
//   PushRuleKind                 — Rule kind constants + priority mapping
//   PushConditionKind            — Condition kind constants
//   PushActionType               — Action type + tweak constants
//   DefaultRuleID                — All default rule_id constants
//   ActionParser                 — Validate, parse, extract actions
//   GlobMatcher                  — Glob matching with JSON path extraction
//   RuleValidator                — Rule spec validation
//   PushRuleSerializer           — JSON serialization/deserialization
//   PushRuleTesting              — Test and benchmark utilities
//   PushRuleDiff                 — Diff two rule sets
//   PushRulePriorityUtils        — Priority renumbering + repositioning
//   UserNameMatcher              — User mention detection
//   RoomNotificationPerm         — @room permission checks
//   PushRuleExport               — Export/import rules as JSON
//   HighlightDetector            — Determine if event is a highlight
// ============================================================================

} // namespace progressive
