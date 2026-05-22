#pragma once
#include <cstdint>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace progressive::push {

enum class PriorityClass : int8_t {
  Underride = 1,
  Sender = 2,
  Room = 3,
  Content = 4,
  Override = 5,
  PostContent = 6,
};

struct SetTweak {
  std::string key;  // "highlight" or "sound"
  std::optional<std::string> value;

  nlohmann::json to_json() const;
};

using Action = std::variant<std::monostate,  // Notify
                            SetTweak,        // highlight/sound tweak
                            bool             // true=unknown/unsupported (treated as no-op)
                            >;

Action action_notify();
Action action_highlight(bool value = true);
Action action_sound(std::string_view name = "default");

using SimpleJsonValue = std::variant<std::string, int64_t, bool, std::nullptr_t>;
using JsonValue = std::variant<SimpleJsonValue, std::vector<SimpleJsonValue>>;

struct EventMatchCondition {
  std::string key;
  std::string pattern;
};

struct EventMatchTypeCondition {
  std::string key;
  std::string pattern_type;  // "user_id" or "user_localpart"
};

struct EventPropertyIsCondition {
  std::string key;
  SimpleJsonValue value;
};

struct EventPropertyContainsCondition {
  std::string key;
  SimpleJsonValue value;
};

struct ExactEventPropertyContainsType {
  std::string key;
  std::string value_type;  // "user_id" or "user_localpart"
};

struct RoomMemberCount {
  std::string is;  // e.g. "2", ">2", "<=10"
};

struct SenderNotificationPermission {
  std::string key;  // e.g. "room"
};

struct RoomVersionSupports {
  std::string feature;
};

struct Msc4306ThreadSubscription {
  bool subscribed = false;
};

using KnownCondition =
    std::variant<EventMatchCondition, EventMatchTypeCondition, EventPropertyIsCondition,
                 EventPropertyContainsCondition, ExactEventPropertyContainsType, RoomMemberCount,
                 SenderNotificationPermission, RoomVersionSupports, Msc4306ThreadSubscription,
                 std::string  // "contains_display_name" (no payload)
                 >;

struct Condition {
  KnownCondition cond;
};

struct PushRule {
  std::string rule_id;
  PriorityClass priority_class;
  std::vector<Condition> conditions;
  std::vector<Action> actions;
  bool is_default = true;
  bool default_enabled = true;
};

nlohmann::json actions_to_json(const std::vector<Action>& actions);

}  // namespace progressive::push
