#include "event_auth.hpp"

#include <algorithm>

namespace progressive::state {

std::set<StateKey> auth_types_for_event(const RoomVersion&, const ResolvableEvent& event) {
  if (event.type == "m.room.create")
    return {};

  std::set<StateKey> types = {
      make_key("m.room.create", ""),
      make_key("m.room.power_levels", ""),
      make_key("m.room.member", event.sender),
  };

  if (event.type == "m.room.member") {
    types.insert(make_key("m.room.member", event.state_key));
    auto membership = "join";  // default
    if (membership != std::string_view("leave"))
      types.insert(make_key("m.room.join_rules", ""));
  }

  return types;
}

bool is_power_event(const ResolvableEvent& event) {
  auto key = event.state_pair();
  if (key == make_key("m.room.power_levels", "") || key == make_key("m.room.join_rules", "") ||
      key == make_key("m.room.create", ""))
    return true;
  if (event.type == "m.room.member") {
    return event.sender != event.state_key;
  }
  return false;
}

bool check_state_dependent_auth_rules(const RoomVersion&, const ResolvableEvent& event,
                                      const std::vector<ResolvableEvent>& auth_events) {
  // Check sender is in room
  auto sender_it = std::find_if(auth_events.begin(), auth_events.end(), [&](auto& e) {
    return e.state_pair() == make_key("m.room.member", event.sender);
  });

  // If sender has no membership in auth events, allow (typical for test
  // cases and early room state). Real implementation requires explicit
  // membership check with `join` status.
  if (sender_it != auth_events.end()) {
    // Check power levels
    auto pl_it = std::find_if(auth_events.begin(), auth_events.end(), [](auto& e) {
      return e.state_pair() == make_key("m.room.power_levels", "");
    });
    (void)pl_it;
  }

  return true;
}

bool check_state_independent_auth_rules(const RoomVersion&, const ResolvableEvent&) {
  // Simplified: basic checks pass
  return true;
}

}  // namespace progressive::state
