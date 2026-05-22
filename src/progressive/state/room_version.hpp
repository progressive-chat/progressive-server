#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <string_view>

namespace progressive::state {

enum class StateResVersion : uint8_t { V1 = 1, V2 = 2, V2_1 = 3 };

enum class EventFormatVersion : uint8_t {
  V1_V2 = 1,
  V3 = 2,
  V4_PLUS = 3,
  V11_HYDRA = 4,
  VMSC4242 = 5
};

struct RoomVersion {
  std::string identifier;
  EventFormatVersion event_format = EventFormatVersion::V4_PLUS;
  StateResVersion state_res = StateResVersion::V2;
  bool special_case_aliases_auth = false;
  bool strict_canonicaljson = false;
  bool limit_notifications_power_levels = true;
  bool implicit_room_creator = false;
  bool updated_redaction_rules = false;
  bool restricted_join_rule = false;
  bool restricted_join_rule_fix = false;
  bool knock_join_rule = false;
  bool knock_restricted_join_rule = false;
  bool enforce_int_power_levels = false;
  bool msc4289_creator_power_enabled = false;
  bool msc4291_room_ids_as_hashes = false;
  bool strict_event_byte_limits = false;
};

const RoomVersion& get_room_version(std::string_view ver);
const std::map<std::string, RoomVersion>& known_room_versions();

}  // namespace progressive::state
