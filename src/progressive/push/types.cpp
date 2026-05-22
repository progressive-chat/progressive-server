#include "types.hpp"

namespace progressive::push {

nlohmann::json SetTweak::to_json() const {
  nlohmann::json j;
  j["set_tweak"] = key;
  if (value.has_value())
    j["value"] = *value;
  return j;
}

Action action_notify() {
  return std::monostate{};
}

Action action_highlight(bool value) {
  SetTweak t;
  t.key = "highlight";
  if (!value)
    t.value = "false";
  return t;
}

Action action_sound(std::string_view name) {
  SetTweak t;
  t.key = "sound";
  t.value = std::string(name);
  return t;
}

nlohmann::json actions_to_json(const std::vector<Action>& actions) {
  nlohmann::json arr = nlohmann::json::array();
  for (auto& action : actions) {
    std::visit(
        [&](auto&& v) {
          using T = std::decay_t<decltype(v)>;
          if constexpr (std::is_same_v<T, std::monostate>)
            arr.push_back("notify");
          else if constexpr (std::is_same_v<T, SetTweak>)
            arr.push_back(v.to_json());
          // skip bool / unknown
        },
        action);
  }
  return arr;
}

}  // namespace progressive::push
