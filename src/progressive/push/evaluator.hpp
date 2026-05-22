#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "types.hpp"
#include "utils.hpp"

namespace progressive::push {

class PushRuleEvaluator {
public:
  PushRuleEvaluator(const nlohmann::json& event, uint64_t room_member_count = 0,
                    std::optional<int64_t> sender_power_level = std::nullopt);

  std::vector<Action> run(const std::vector<PushRule>& rules, std::string_view user_id,
                          std::optional<std::string_view> display_name);

  bool has_mentions() const { return has_mentions_; }

public:
  bool match_condition(const Condition& condition, std::string_view user_id,
                       std::optional<std::string_view> display_name) const;

  bool match_event_match(std::string_view key, std::string_view pattern,
                         GlobMatchType match_type) const;

  bool match_event_property_is(std::string_view key, const SimpleJsonValue& val) const;

  bool match_event_property_contains(std::string_view key, const SimpleJsonValue& val) const;

  bool match_member_count(std::string_view is) const;

  std::map<std::string, JsonValue> flattened_;
  std::string body_;
  bool has_mentions_;
  uint64_t room_member_count_;
  std::optional<int64_t> sender_power_level_;
  std::map<std::string, int64_t> notification_power_levels_;
};

}  // namespace progressive::push
