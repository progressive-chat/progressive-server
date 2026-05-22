#include "evaluator.hpp"

#include <algorithm>
#include <cctype>

namespace progressive::push {

PushRuleEvaluator::PushRuleEvaluator(const nlohmann::json& event, uint64_t room_member_count,
                                     std::optional<int64_t> sender_power_level)
    : flattened_(flatten_event(event)),
      has_mentions_(event.contains("m.mentions")),
      room_member_count_(room_member_count),
      sender_power_level_(sender_power_level) {
  if (event.contains("content") && event["content"].is_object() &&
      event["content"].contains("body") && event["content"]["body"].is_string())
    body_ = event["content"]["body"].get<std::string>();

  notification_power_levels_["room"] = 50;
}

std::vector<Action> PushRuleEvaluator::run(const std::vector<PushRule>& rules,
                                           std::string_view user_id,
                                           std::optional<std::string_view> display_name) {
  for (auto& rule : rules) {
    if (!rule.default_enabled)
      continue;

    bool all_match = true;
    for (auto& condition : rule.conditions) {
      if (!match_condition(condition, user_id, display_name)) {
        all_match = false;
        break;
      }
    }
    if (!all_match)
      continue;

    // Filter out DontNotify/Coalesce (represented as bool in our variant)
    std::vector<Action> filtered;
    for (auto& action : rule.actions) {
      if (!std::holds_alternative<bool>(action))
        filtered.push_back(action);
    }
    return filtered;
  }
  return {};
}

bool PushRuleEvaluator::match_condition(const Condition& condition, std::string_view user_id,
                                        std::optional<std::string_view> display_name) const {
  return std::visit(
      [&](auto&& cond) -> bool {
        using T = std::decay_t<decltype(cond)>;

        if constexpr (std::is_same_v<T, EventMatchCondition>) {
          GlobMatchType mt =
              (cond.key == "content.body") ? GlobMatchType::Word : GlobMatchType::Whole;
          return match_event_match(cond.key, cond.pattern, mt);
        } else if constexpr (std::is_same_v<T, EventMatchTypeCondition>) {
          if (user_id.empty())
            return false;
          std::string pattern = (cond.pattern_type == "user_id") ? std::string(user_id)
                                                                 : get_localpart_from_id(user_id);
          GlobMatchType mt =
              (cond.key == "content.body") ? GlobMatchType::Word : GlobMatchType::Whole;
          return match_event_match(cond.key, pattern, mt);
        } else if constexpr (std::is_same_v<T, EventPropertyIsCondition>) {
          return match_event_property_is(cond.key, cond.value);
        } else if constexpr (std::is_same_v<T, EventPropertyContainsCondition>) {
          return match_event_property_contains(cond.key, cond.value);
        } else if constexpr (std::is_same_v<T, ExactEventPropertyContainsType>) {
          if (user_id.empty())
            return false;
          std::string val = (cond.value_type == "user_id") ? std::string(user_id)
                                                           : get_localpart_from_id(user_id);
          return match_event_property_contains(cond.key, SimpleJsonValue(val));
        } else if constexpr (std::is_same_v<T, RoomMemberCount>) {
          return match_member_count(cond.is);
        } else if constexpr (std::is_same_v<T, SenderNotificationPermission>) {
          if (!sender_power_level_.has_value())
            return false;
          auto it = notification_power_levels_.find(cond.key);
          int64_t required = (it != notification_power_levels_.end()) ? it->second : 50;
          return *sender_power_level_ >= required;
        } else if constexpr (std::is_same_v<T, RoomVersionSupports>) {
          return false;  // simplified: feature flags not wired in yet
        } else if constexpr (std::is_same_v<T, Msc4306ThreadSubscription>) {
          return false;  // simplified: MSC4306 not wired in
        } else if constexpr (std::is_same_v<T, std::string>) {
          // "contains_display_name"
          if (!display_name.has_value() || display_name->empty())
            return false;
          if (body_.empty())
            return false;
          Matcher matcher(*display_name, GlobMatchType::Word);
          return matcher.is_match(body_);
        }
        return false;
      },
      condition.cond);
}

bool PushRuleEvaluator::match_event_match(std::string_view key, std::string_view pattern,
                                          GlobMatchType match_type) const {
  auto it = flattened_.find(std::string(key));
  if (it == flattened_.end())
    return false;

  const JsonValue& val = it->second;
  if (!std::holds_alternative<SimpleJsonValue>(val))
    return false;
  const SimpleJsonValue& sv = std::get<SimpleJsonValue>(val);
  if (!std::holds_alternative<std::string>(sv))
    return false;

  std::string haystack = std::get<std::string>(sv);
  Matcher matcher(pattern, match_type);
  return matcher.is_match(haystack);
}

bool PushRuleEvaluator::match_event_property_is(std::string_view key,
                                                const SimpleJsonValue& expected) const {
  auto it = flattened_.find(std::string(key));
  if (it == flattened_.end())
    return false;

  const JsonValue& val = it->second;
  if (!std::holds_alternative<SimpleJsonValue>(val))
    return false;

  return std::get<SimpleJsonValue>(val) == expected;
}

bool PushRuleEvaluator::match_event_property_contains(std::string_view key,
                                                      const SimpleJsonValue& needle) const {
  auto it = flattened_.find(std::string(key));
  if (it == flattened_.end())
    return false;

  const JsonValue& val = it->second;
  if (!std::holds_alternative<std::vector<SimpleJsonValue>>(val))
    return false;

  auto& arr = std::get<std::vector<SimpleJsonValue>>(val);
  return std::find(arr.begin(), arr.end(), needle) != arr.end();
}

bool PushRuleEvaluator::match_member_count(std::string_view is) const {
  std::string s(is);
  std::string op = "==";
  size_t num_start = 0;

  if (!s.empty() && (s[0] == '<' || s[0] == '>' || s[0] == '=')) {
    op = "";
    while (num_start < s.size() &&
           (s[num_start] == '<' || s[num_start] == '>' || s[num_start] == '=')) {
      op += s[num_start];
      num_start++;
    }
  }

  int64_t rhs = 0;
  try {
    rhs = std::stoll(s.substr(num_start));
  } catch (...) {
    return false;
  }

  auto count = static_cast<int64_t>(room_member_count_);
  if (op == "==" || op.empty())
    return count == rhs;
  if (op == "<")
    return count < rhs;
  if (op == ">")
    return count > rhs;
  if (op == "<=")
    return count <= rhs;
  if (op == ">=")
    return count >= rhs;
  return false;
}

}  // namespace progressive::push
