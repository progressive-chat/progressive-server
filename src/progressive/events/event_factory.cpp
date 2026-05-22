#include "event_factory.hpp"

#include "../util/time.hpp"
#include "../util/token.hpp"

namespace progressive::events {

Event create_local_event(RoomID room_id, std::string type, std::string sender,
                         nlohmann::json content, std::optional<std::string> state_key) {
  Event ev;
  ev.room_id = std::move(room_id);
  ev.type = std::move(type);
  ev.sender = std::move(sender);
  ev.content = std::move(content);
  ev.state_key = std::move(state_key);
  ev.origin_server_ts = util::iso8601();
  ev.depth = 0;
  ev.event_id = EventID::from_string(util::generate_event_id(ev.room_id.domain()));
  return ev;
}

}  // namespace progressive::events
