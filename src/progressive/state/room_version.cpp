#include "room_version.hpp"

namespace progressive::state {

static const std::map<std::string, RoomVersion> kVersions = {
    {"1",
     {"1", EventFormatVersion::V1_V2, StateResVersion::V1, true, false, false, false, false, false,
      false, false, false, false, false, false, false}},

    {"2",
     {"2", EventFormatVersion::V1_V2, StateResVersion::V2, true, false, false, false, false, false,
      false, false, false, false, false, false, false}},

    {"3",
     {"3", EventFormatVersion::V3, StateResVersion::V2, true, false, false, false, false, false,
      false, false, false, false, false, false, false}},

    {"4",
     {"4", EventFormatVersion::V4_PLUS, StateResVersion::V2, true, false, false, false, false,
      false, false, false, false, false, false, false, false}},

    {"5",
     {"5", EventFormatVersion::V4_PLUS, StateResVersion::V2, true, false, false, false, false,
      false, false, false, false, false, false, false, false}},

    {"6",
     {"6", EventFormatVersion::V4_PLUS, StateResVersion::V2, false, true, true, false, false, false,
      false, false, false, false, false, false, false}},

    {"7",
     {"7", EventFormatVersion::V4_PLUS, StateResVersion::V2, false, true, true, false, false, false,
      true, false, false, false, false, false, false}},

    {"8",
     {"8", EventFormatVersion::V4_PLUS, StateResVersion::V2, false, true, true, false, false, true,
      true, false, false, false, false, false, false}},

    {"9",
     {"9", EventFormatVersion::V4_PLUS, StateResVersion::V2, false, true, true, false, false, true,
      true, true, false, false, false, false, false}},

    {"10",
     {"10", EventFormatVersion::V4_PLUS, StateResVersion::V2, false, true, true, false, false, true,
      true, true, true, true, false, false, false}},

    {"11",
     {"11", EventFormatVersion::V4_PLUS, StateResVersion::V2, false, true, true, true, true, true,
      true, true, true, true, false, false, true}},
};

const RoomVersion& get_room_version(std::string_view ver) {
  auto it = kVersions.find(std::string(ver));
  if (it != kVersions.end())
    return it->second;
  return kVersions.at("10");  // default
}

const std::map<std::string, RoomVersion>& known_room_versions() {
  return kVersions;
}

}  // namespace progressive::state
