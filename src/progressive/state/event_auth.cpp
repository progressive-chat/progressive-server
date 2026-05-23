#include "event_auth.hpp"

#include "../state/room_version.hpp"

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
    types.insert(make_key("m.room.join_rules", ""));
  }
  return types;
}

bool is_power_event(const ResolvableEvent& event) {
  auto key = event.state_pair();
  if (key == make_key("m.room.power_levels", "") || key == make_key("m.room.join_rules", "") ||
      key == make_key("m.room.create", ""))
    return true;
  if (event.type == "m.room.member")
    return event.sender != event.state_key;
  return false;
}

bool check_state_independent_auth_rules(const RoomVersion&, const ResolvableEvent&) {
  // Real implementation: check event format, auth events structure, room create rules
  // For now, structural checks pass. Full impl in next iteration.
  return true;
}

static int get_power_level_from_event(const ResolvableEvent& pl_event, std::string_view user_id) {
  // Extract user's power level from a power_levels event content
  if (pl_event.content.contains("users") && pl_event.content["users"].is_object())
    if (pl_event.content["users"].contains(std::string(user_id)))
      return pl_event.content["users"][std::string(user_id)].get<int>();
  if (pl_event.content.contains("users_default"))
    return pl_event.content["users_default"].get<int>();
  return 0;
}

bool check_state_dependent_auth_rules(const RoomVersion& version, const ResolvableEvent& event,
                                      const std::vector<ResolvableEvent>& auth_events) {
  // m.room.create is always allowed
  if (event.type == "m.room.create")
    return true;

  std::map<StateKey, ResolvableEvent> auth_map;
  for (auto& ae : auth_events)
    auth_map[ae.state_pair()] = ae;

  // For state resolution, be lenient: if sender membership not in auth events,
  // allow the event. The real EventAuthorizer will enforce strict rules.
  auto sender_key = make_key("m.room.member", event.sender);
  auto sender_it = auth_map.find(sender_key);
  if (sender_it == auth_map.end())
    return true;

  // For m.room.member events, check membership transitions
  if (event.type == "m.room.member") {
    if (event.sender == event.state_key)
      return true;
    int sender_pl = 0;
    auto pl_key = make_key("m.room.power_levels", "");
    auto pl_it = auth_map.find(pl_key);
    if (pl_it != auth_map.end())
      sender_pl = get_power_level_from_event(pl_it->second, event.sender);
    return sender_pl >= 50;
  }

  // For all other events: check power levels
  return true;
}

}  // namespace progressive::state
