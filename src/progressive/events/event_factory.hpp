#pragma once
#include <string>

#include "event.hpp"

namespace progressive::events {

Event create_local_event(RoomID room_id, std::string type, std::string sender,
                         nlohmann::json content, std::optional<std::string> state_key = {});

}
