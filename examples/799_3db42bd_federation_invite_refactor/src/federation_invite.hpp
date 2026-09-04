// federation_invite.hpp — MSC3575 / 3db42bd federation invite refactor
//
// Implements the handle_member_pdu logic for federation joins and knocks
// with room version awareness.

#pragma once

#include "data.hpp"
#include "crypto.hpp"
#include "ruma_wrapper.hpp"

#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace federation {

enum class MembershipState {
    Join,
    Invite,
    Knock,
    Leave,
    Ban,
};

// MSC4291/3db42bd: handle_member_pdu replaces append_member_pdu
// Handles both join and invite membership events with room version awareness
nlohmann::json handle_member_pdu(
    Data* data,
    const std::string& sender_servername,
    const std::string& room_id,
    const nlohmann::json& pdu,
    const std::optional<Data::RoomVersionRules>& rules,
    MembershipState membership = MembershipState::Join
);

// Helper to check if a user can perform a restricted join
bool user_can_perform_restricted_join(
    const std::string& user_id,
    const std::string& room_id,
    const Data::RoomVersionRules& rules
);

// Create a room ID using MSC4291 hash-based scheme
std::string generate_room_id_v1(const nlohmann::json& create_content, const std::string& hostname);

}  // namespace federation
