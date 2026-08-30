// rooms_helpers.hpp — mirrors Conduit's service/rooms/helpers/mod.rs (introduced
// in 21af83e). That module extracts the membership logic (join/invite/leave/knock)
// out of the client_server membership routes into a shared helper. Its
// join_room_by_id also wraps the federation join path (make_join/send_join), which
// our server implements in a LATER commit — so that branch is adapted below to a
// clear "not yet available" error rather than silently broken federation.
#pragma once
#include <optional>
#include <string>
#include "nlohmann/json.hpp"

struct Data;

namespace rooms_helpers {

// Built a fully-signed membership PDU from a /federation/*/make_* template
// (used by both federation joins and knocks). Adapted from Conduit's
// populate_membership_template: fills origin / origin_server_ts / content,
// signs with our server key, and returns (event_id, signed_pdu).
std::pair<std::string, nlohmann::json> populate_membership_template(
    Data* data, const nlohmann::json& member_template,
    const std::string& sender_user, const std::string& reason,
    const std::string& membership, const std::string& room_version);

// Local join. Mirrors the "We can join locally" branch of Conduit's
// join_room_by_id. Returns true on success. Federation join (remote room) is
// adapted: returns false with err_msg set, since make_join/send_join land later.
bool join_room_by_id(Data* data, const std::string& sender_user,
                     const std::string& room_id, const std::string& reason,
                     std::string& err_msg);

}  // namespace rooms_helpers
