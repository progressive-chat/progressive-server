#pragma once
// state.hpp - state.py C++ translation
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"
namespace progressive::storage { using json = nlohmann::json;

struct StateEntry {
  std::string type;
  std::string state_key;
  std::string event_id;
  std::string room_id;
};

class StateStore {
public:
  explicit StateStore(DatabasePool& db);
  // Get current state for a room
  std::map<std::pair<std::string,std::string>, std::string> get_current_state(
      const std::string& room_id);
  // Get state ids for event
  std::map<std::pair<std::string,std::string>, std::string> get_state_ids_for_event(
      const std::string& event_id);
  // Get specific state event
  std::optional<StateEntry> get_state_event(
      const std::string& room_id, const std::string& type,
      const std::string& state_key = "");
  // Get state events matching filter
  std::map<std::pair<std::string,std::string>, std::string> get_state_events(
      const std::string& room_id,
      const std::set<std::pair<std::string,std::string>>& types);
  // Get current state event for room + type
  std::optional<std::string> get_current_state_event(
      const std::string& room_id, const std::string& type,
      const std::string& state_key = "");
  // Get room create event
  std::optional<json> get_create_event(const std::string& room_id);
  // Get room version from state
  std::string get_room_version_from_state(const std::string& room_id);
  // Get bulk current state for multiple rooms
  std::map<std::string, std::map<std::pair<std::string,std::string>, std::string>>
  get_bulk_current_state(const std::set<std::string>& room_ids);
  // Get state groups for events
  std::map<std::string, int64_t> get_state_groups(
      const std::set<std::string>& event_ids);
  // Get state for a state group
  std::map<std::pair<std::string,std::string>, std::string> get_state_for_group(
      int64_t state_group, const std::string& room_id);
  // Get state group for event
  std::optional<int64_t> get_state_group_for_event(const std::string& event_id);
  // Store state group
  int64_t store_state_group(const std::string& room_id,
      const std::string& event_id,
      const std::map<std::pair<std::string,std::string>, std::string>& state);
  // Purge old state groups
  void purge_unreferenced_state_groups();
private:
  DatabasePool& db_;
  static int64_t next_state_group_id_;
};
} // namespace progressive::storage
