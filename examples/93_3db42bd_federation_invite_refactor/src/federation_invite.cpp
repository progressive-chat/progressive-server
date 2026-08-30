// federation_invite.cpp — MSC4291/3db42bd federation invite refactor
//
// Implements handle_member_pdu for federation joins/knocks with room version awareness.

#include "federation_invite.hpp"
#include "data.hpp"
#include "crypto.hpp"
#include "ruma_wrapper.hpp"
#include "utils.hpp"
#include <nlohmann/json.hpp>

namespace federation {

nlohmann::json create_member_event(
    const std::string& sender_servername,
    const std::string& room_id,
    const std::string& sender,
    const std::string& state_key,
    MembershipState membership,
    const nlohmann::json& content
) {
    nlohmann::json event;
    event["type"] = "m.room.member";
    event["content"] = content;
    event["event_id"] = "$thiswillbefilledinlater";
    event["origin_server_ts"] = utils::millis_since_unix_epoch();
    event["room_id"] = room_id;
    event["sender"] = sender;
    event["state_key"] = state_key;
    event["unsigned"] = nlohmann::json::object();
    return event;
}

nlohmann::json handle_member_pdu(
    Data* data,
    const std::string& sender_servername,
    const std::string& room_id,
    const nlohmann::json& pdu,
    const std::optional<Data::RoomVersionRules>& rules_opt,
    MembershipState membership
) {
    (void)data;
    (void)sender_servername;
    // Determine room version rules
    Data::RoomVersionRules rules;
    if (rules_opt) {
        rules = *rules_opt;
    } else {
        // Default to room version 1 rules
        rules = ::Data::get_room_version_rules("1");
    }

    // Extract sender and state_key from PDU
    const std::string sender = pdu.value("sender", "");
    const std::string state_key = pdu.value("state_key", "");

    // For invites, the state_key is the invited user
    // For joins, the state_key should match the sender
    if (state_key != sender && membership != MembershipState::Invite) {
        // Invalid: state_key must match sender for non-invite memberships
        throw std::runtime_error("Invalid state_key for membership type");
    }

    // Check if sender is from the same server as the origin
    if (sender.find(':') != std::string::npos) {
        std::string sender_server = sender.substr(sender.find(':') + 1);
        if (sender_server != sender_servername) {
            // Remote sender - verify they're allowed to send this event
            // In a real implementation, we'd check server ACLs, etc.
        }
    }

    // Check restricted join rules (simplified: always allow)
    if (membership == MembershipState::Join) {
        // In a full implementation, we would check if the room has a restricted
        // join rule and if the user satisfies it. For now, we allow all joins.
        (void)rules;
    }

    // Build the event
    nlohmann::json event;
    event["type"] = "m.room.member";
    event["content"] = pdu.value("content", nlohmann::json::object());
    event["event_id"] = "$thiswillbefilledinlater";
    event["origin_server_ts"] = utils::millis_since_unix_epoch();
    event["room_id"] = pdu.value("room_id", room_id);
    event["sender"] = sender;
    event["state_key"] = state_key;
    event["unsigned"] = nlohmann::json::object();

    // Generate event ID
    const std::string event_id = crypto::reference_hash(event);
    event["event_id"] = event_id;

    return event;
}

bool user_can_perform_restricted_join(
    const std::string& user_id,
    const std::string& room_id,
    const Data::RoomVersionRules& rules
) {
    (void)user_id;
    (void)room_id;
    (void)rules;
    // Simplified: allow all restricted joins
    return true;
}

std::string generate_room_id_v1(const nlohmann::json& create_content, const std::string& hostname) {
    // MSC4291: room ID is SHA256 hash of canonical create event content
    std::string canonical = create_content.dump();
    unsigned char hash[32];
    SHA256(reinterpret_cast<const unsigned char*>(canonical.c_str()), canonical.size(), hash);
    std::string hash_hex;
    for (int i = 0; i < 32; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", hash[i]);
        hash_hex += buf;
    }
    return "!" + hash_hex.substr(0, 12) + ":" + hostname;
}

}  // namespace federation
