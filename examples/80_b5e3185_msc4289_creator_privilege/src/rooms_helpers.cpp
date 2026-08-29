// rooms_helpers.cpp — see rooms_helpers.hpp for the 21af83e correspondence note.
#include "rooms_helpers.hpp"

#include "data.hpp"
#include "crypto.hpp"
#include "utils.hpp"

namespace rooms_helpers {

std::pair<std::string, nlohmann::json> populate_membership_template(
    Data* data, const nlohmann::json& member_template,
    const std::string& sender_user, const std::string& reason,
    const std::string& membership, const std::string& room_version) {
  // Start from the template the remote server handed us (make_knock / make_join).
  nlohmann::json stub =
      member_template.is_object() ? member_template : nlohmann::json::object();

  stub["origin"] = data->hostname();
  stub["origin_server_ts"] = utils::millis_since_unix_epoch();

  nlohmann::json content = {
      {"membership", membership},
  };
  if (auto displayname = data->displayname_get(sender_user))
    content["displayname"] = *displayname;
  if (!reason.empty()) content["reason"] = reason;

  // Preserve any existing content fields the template carried (Conduit merges).
  if (member_template.contains("content") && member_template["content"].is_object()) {
    for (auto it = member_template["content"].begin();
         it != member_template["content"].end(); ++it) {
      if (it.key() == "membership" || it.key() == "displayname" ||
          it.key() == "reason")
        continue;
      content[it.key()] = it.value();
    }
  }
  stub["content"] = content;

  // event_id is (re)computed after signing.
  stub.erase("event_id");

  // Sign with our server key (Conduit's hash_and_sign_event).
  crypto::sign_json(data->hostname(), data->keypair(), stub);

  const std::string event_id = "$" + crypto::reference_hash(stub);
  stub["event_id"] = event_id;
  return {event_id, stub};
}

bool join_room_by_id(Data* data, const std::string& sender_user,
                     const std::string& room_id, const std::string& reason,
                     std::string& err_msg) {
  if (data->is_joined(sender_user, room_id)) return true;

  // Local join only. Remote-room federation join depends on make_join/send_join
  // (a later commit); adapted to a clear error rather than a broken attempt.
  if (data->room_state(room_id).empty()) {
    err_msg = "Room not found.";
    return false;
  }

  if (!data->room_join(room_id, sender_user)) {
    err_msg = "event not authorized";
    return false;
  }
  (void)reason;  // Conduit records a join reason in the member content; our
                 // room_join already builds the member event with displayname.
  return true;
}

}  // namespace rooms_helpers
