#pragma once
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "room_version.hpp"
#include "types.hpp"

namespace progressive::state {

std::pair<StateMap, ConflictedState> separate(const std::vector<StateMap>& state_sets);

StateMap resolve_events_v1(const RoomVersion& version, const std::vector<StateMap>& state_sets,
                           const EventMap& event_map);

StateMap resolve_events_v2(const RoomVersion& version, const std::vector<StateMap>& state_sets,
                           const EventMap& event_map);

StateMap resolve_events(const RoomVersion& version, const std::vector<StateMap>& state_sets,
                        const EventMap& event_map);

int get_power_level(const ResolvableEvent& power_event, std::string_view user_id);

}  // namespace progressive::state
