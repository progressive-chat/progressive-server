#pragma once
#include <map>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "../types/matrix_id.hpp"

namespace progressive::state {

using StateKey = std::tuple<std::string, std::string>;
using EventId = std::string;
using StateMap = std::map<StateKey, EventId>;
using ConflictedState = std::map<StateKey, std::set<EventId>>;
using EventMap = std::map<EventId, struct ResolvableEvent>;

inline StateKey make_key(std::string_view type, std::string_view state_key) {
  return {std::string(type), std::string(state_key)};
}

struct ResolvableEvent {
  EventId event_id;
  std::string room_id;
  std::string type;
  std::string state_key;
  std::string sender;
  int depth = 0;
  int64_t origin_server_ts = 0;
  std::vector<EventId> auth_event_ids;
  std::vector<EventId> prev_event_ids;
  int power_level = 0;
  nlohmann::json content;

  bool is_state() const { return !state_key.empty(); }
  StateKey state_pair() const { return {type, state_key}; }
};

}  // namespace progressive::state
