#pragma once
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "room_version.hpp"
#include "types.hpp"

namespace progressive::state {

std::set<StateKey> auth_types_for_event(const RoomVersion& version, const ResolvableEvent& event);

bool is_power_event(const ResolvableEvent& event);

bool check_state_dependent_auth_rules(const RoomVersion& version, const ResolvableEvent& event,
                                      const std::vector<ResolvableEvent>& auth_events);

bool check_state_independent_auth_rules(const RoomVersion& version, const ResolvableEvent& event);

}  // namespace progressive::state
