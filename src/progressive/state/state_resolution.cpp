#include "state_resolution.hpp"

#include <algorithm>
#include <map>
#include <queue>
#include <set>
#include <tuple>
#include <vector>

#include "event_auth.hpp"

namespace progressive::state {

static int depth_first(const ResolvableEvent& a, const ResolvableEvent& b) {
  if (a.depth != b.depth)
    return a.depth > b.depth ? 1 : -1;
  return a.event_id < b.event_id ? 1 : -1;
}

int get_power_level(const ResolvableEvent& power_event, std::string_view user_id) {
  if (power_event.content.contains("users") && power_event.content["users"].is_object()) {
    auto& users = power_event.content["users"];
    if (users.contains(std::string(user_id)) && users[std::string(user_id)].is_number())
      return users[std::string(user_id)].get<int>();
  }
  return 0;
}

namespace {

std::vector<EventId> lexicographical_topological_sort(
    const std::map<EventId, std::set<EventId>>& outdegree_map, const EventMap& event_map) {
  std::map<EventId, std::set<EventId>> graph = outdegree_map;
  std::map<EventId, std::set<EventId>> reverse;
  using QItem = std::tuple<int64_t, EventId>;
  std::priority_queue<QItem, std::vector<QItem>, std::greater<QItem>> pq;

  for (auto& [node, edges] : graph)
    for (auto& edge : edges)
      reverse[edge].insert(node);

  for (auto& [node, edges] : graph) {
    if (edges.empty()) {
      auto it = event_map.find(node);
      int64_t k = it != event_map.end() ? it->second.origin_server_ts : 0;
      pq.push({k, node});
    }
  }

  std::vector<EventId> result;
  while (!pq.empty()) {
    auto [_, node] = pq.top();
    pq.pop();
    result.push_back(node);
    for (auto& parent : reverse[node]) {
      graph[parent].erase(node);
      if (graph[parent].empty()) {
        auto it = event_map.find(parent);
        int64_t k = it != event_map.end() ? it->second.origin_server_ts : 0;
        pq.push({k, parent});
      }
    }
  }
  return result;
}

EventId resolve_auth_events_v1(const RoomVersion& version, const std::set<EventId>& event_ids,
                               const EventMap& event_map,
                               std::map<StateKey, ResolvableEvent>& auth_events) {
  std::vector<ResolvableEvent> events;
  for (auto& eid : event_ids) {
    auto it = event_map.find(eid);
    if (it != event_map.end())
      events.push_back(it->second);
  }
  if (events.empty())
    return {};
  std::sort(events.begin(), events.end(), [](auto& a, auto& b) { return depth_first(a, b) > 0; });
  std::reverse(events.begin(), events.end());

  ResolvableEvent prev = events[0];
  for (size_t i = 1; i < events.size(); i++) {
    std::vector<ResolvableEvent> auth_vec;
    for (auto& [k, v] : auth_events)
      auth_vec.push_back(v);
    auth_vec.push_back(prev);
    if (check_state_dependent_auth_rules(version, events[i], auth_vec))
      prev = events[i];
  }
  return prev.event_id;
}

EventId resolve_normal_events_v1(const RoomVersion& version, const std::set<EventId>& event_ids,
                                 const EventMap& event_map,
                                 const std::map<StateKey, ResolvableEvent>& auth_events) {
  std::vector<ResolvableEvent> events;
  for (auto& eid : event_ids) {
    auto it = event_map.find(eid);
    if (it != event_map.end())
      events.push_back(it->second);
  }
  if (events.empty())
    return {};
  std::sort(events.begin(), events.end(), [](auto& a, auto& b) { return depth_first(a, b) > 0; });

  std::vector<ResolvableEvent> auth_vec;
  for (auto& [k, v] : auth_events)
    auth_vec.push_back(v);

  for (auto& e : events) {
    if (check_state_dependent_auth_rules(version, e, auth_vec))
      return e.event_id;
  }
  return events.back().event_id;
}

}  // anonymous namespace

std::pair<StateMap, ConflictedState> separate(const std::vector<StateMap>& state_sets) {
  StateMap unconflicted;
  ConflictedState conflicted;
  if (state_sets.empty())
    return {unconflicted, conflicted};
  unconflicted = state_sets[0];
  for (size_t i = 1; i < state_sets.size(); i++) {
    for (auto& [key, value] : state_sets[i]) {
      auto un_it = unconflicted.find(key);
      if (un_it == unconflicted.end()) {
        auto con_it = conflicted.find(key);
        if (con_it == conflicted.end())
          unconflicted[key] = value;
        else
          con_it->second.insert(value);
      } else if (un_it->second != value) {
        conflicted[key] = {value, un_it->second};
        unconflicted.erase(un_it);
      }
    }
  }
  return {unconflicted, conflicted};
}

StateMap resolve_events_v1(const RoomVersion& version, const std::vector<StateMap>& state_sets,
                           const EventMap& event_map) {
  if (state_sets.size() == 1)
    return state_sets[0];
  auto [unconflicted, conflicted] = separate(state_sets);

  std::map<StateKey, ResolvableEvent> auth_event_objs;
  for (auto& [key, eid] : unconflicted) {
    auto it = event_map.find(eid);
    if (it != event_map.end())
      auth_event_objs[key] = it->second;
  }

  for (auto& [key, event_ids] : conflicted) {
    if (!event_ids.empty()) {
      auto eit = event_map.find(*event_ids.begin());
      if (eit != event_map.end()) {
        for (auto& ak : auth_types_for_event(version, eit->second)) {
          if (auth_event_objs.find(ak) == auth_event_objs.end()) {
            auto ue = unconflicted.find(ak);
            if (ue != unconflicted.end()) {
              auto it = event_map.find(ue->second);
              if (it != event_map.end())
                auth_event_objs[ak] = it->second;
            }
          }
        }
      }
    }
  }

  StateMap resolved = unconflicted;

  auto pl_key = make_key("m.room.power_levels", "");
  auto pl_it = conflicted.find(pl_key);
  if (pl_it != conflicted.end()) {
    resolved[pl_key] = resolve_auth_events_v1(version, pl_it->second, event_map, auth_event_objs);
    auto eit = event_map.find(resolved[pl_key]);
    if (eit != event_map.end())
      auth_event_objs[pl_key] = eit->second;
  }

  for (auto& [key, event_ids] : conflicted) {
    if (std::get<0>(key) == "m.room.join_rules") {
      resolved[key] = resolve_auth_events_v1(version, event_ids, event_map, auth_event_objs);
      auto eit = event_map.find(resolved[key]);
      if (eit != event_map.end())
        auth_event_objs[key] = eit->second;
    }
  }

  for (auto& [key, event_ids] : conflicted) {
    if (std::get<0>(key) == "m.room.member") {
      resolved[key] = resolve_auth_events_v1(version, event_ids, event_map, auth_event_objs);
      auto eit = event_map.find(resolved[key]);
      if (eit != event_map.end())
        auth_event_objs[key] = eit->second;
    }
  }

  for (auto& [key, event_ids] : conflicted) {
    if (resolved.find(key) == resolved.end())
      resolved[key] = resolve_normal_events_v1(version, event_ids, event_map, auth_event_objs);
  }

  return resolved;
}

StateMap resolve_events_v2(const RoomVersion& version, const std::vector<StateMap>& state_sets,
                           const EventMap& event_map) {
  if (state_sets.size() == 1)
    return state_sets[0];
  auto [unconflicted, conflicted] = separate(state_sets);
  if (conflicted.empty())
    return unconflicted;

  std::set<EventId> full_conflicted;
  for (auto& [key, eids] : conflicted)
    full_conflicted.insert(eids.begin(), eids.end());

  std::vector<EventId> power_events;
  std::vector<EventId> other_events;
  for (auto& eid : full_conflicted) {
    auto it = event_map.find(eid);
    if (it != event_map.end() && is_power_event(it->second))
      power_events.push_back(eid);
    else
      other_events.push_back(eid);
  }

  std::map<EventId, std::set<EventId>> outdegree;
  for (auto& eid : full_conflicted) {
    auto it = event_map.find(eid);
    if (it != event_map.end()) {
      for (auto& aid : it->second.auth_event_ids)
        if (full_conflicted.count(aid))
          outdegree[eid].insert(aid);
    }
    if (outdegree.find(eid) == outdegree.end())
      outdegree[eid] = {};
  }

  auto sorted_power = lexicographical_topological_sort(outdegree, event_map);
  std::set<EventId> power_set(power_events.begin(), power_events.end());
  std::vector<EventId> ordered_power;
  for (auto& eid : sorted_power)
    if (power_set.count(eid))
      ordered_power.push_back(eid);

  StateMap resolved = unconflicted;

  for (auto& eid : ordered_power) {
    auto it = event_map.find(eid);
    if (it == event_map.end())
      continue;
    auto& event = it->second;
    std::vector<ResolvableEvent> auth_vec;
    for (auto& aid : event.auth_event_ids) {
      auto ait = event_map.find(aid);
      if (ait != event_map.end())
        auth_vec.push_back(ait->second);
    }
    for (auto& key : auth_types_for_event(version, event)) {
      auto rit = resolved.find(key);
      if (rit != resolved.end()) {
        auto ait = event_map.find(rit->second);
        if (ait != event_map.end())
          auth_vec.push_back(ait->second);
      }
    }
    if (check_state_dependent_auth_rules(version, event, auth_vec))
      resolved[event.state_pair()] = eid;
  }

  for (auto& eid : other_events) {
    auto it = event_map.find(eid);
    if (it == event_map.end())
      continue;
    auto& event = it->second;
    std::vector<ResolvableEvent> auth_vec;
    for (auto& aid : event.auth_event_ids) {
      auto ait = event_map.find(aid);
      if (ait != event_map.end())
        auth_vec.push_back(ait->second);
    }
    for (auto& key : auth_types_for_event(version, event)) {
      auto rit = resolved.find(key);
      if (rit != resolved.end()) {
        auto ait = event_map.find(rit->second);
        if (ait != event_map.end())
          auth_vec.push_back(ait->second);
      }
    }
    if (check_state_dependent_auth_rules(version, event, auth_vec))
      resolved[event.state_pair()] = eid;
  }

  for (auto& [k, v] : unconflicted)
    if (resolved.find(k) == resolved.end())
      resolved[k] = v;

  return resolved;
}

StateMap resolve_events(const RoomVersion& version, const std::vector<StateMap>& state_sets,
                        const EventMap& event_map) {
  if (state_sets.empty())
    return {};
  if (state_sets.size() == 1)
    return state_sets[0];
  if (version.state_res == StateResVersion::V1)
    return resolve_events_v1(version, state_sets, event_map);
  return resolve_events_v2(version, state_sets, event_map);
}

}  // namespace progressive::state
