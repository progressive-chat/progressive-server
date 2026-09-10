#pragma once

#include "database.hpp"
#include "data.hpp"
#include "data.hpp"
#include "ruma_wrapper.hpp"
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <algorithm>

using json = nlohmann::json;

namespace state_res {

// Forward declarations
struct PduEvent;

using EventId = std::string;
using RoomId = std::string;

struct PduEvent {
    std::string event_id_;
    std::string room_id_;
    std::string sender_;
    std::string kind_;  // event type
    std::optional<std::string> state_key_;
    nlohmann::json content_;
    std::vector<std::string> prev_events_;
    std::vector<std::string> auth_events_;
    std::map<std::string, nlohmann::json> signatures_;
    nlohmann::json unsigned_data_;
    
    std::string room_id() const { return room_id_; }
    std::string event_id() const { return event_id_; }
    const std::vector<std::string>& prev_events() const { return prev_events_; }
    const std::vector<std::string>& auth_events() const { return auth_events_; }
    const std::optional<std::string>& state_key() const { return state_key_; }
    std::string sender() const { return sender_; }
    std::string kind() const { return kind_; }
    nlohmann::json content() const { return content_; }
};

using EventMap = std::map<EventId, std::shared_ptr<PduEvent>>;
using StateMap = std::map<std::pair<std::string, std::string>, EventId>; // (type, state_key) -> event_id

// Event types for power levels
enum class PowerEventType {
    RoomCreate,
    RoomMember,
    RoomPowerLevels,
    RoomJoinRules,
    RoomHistoryVisibility,
    RoomThirdPartyInvite,
    Other
};

PowerEventType get_power_event_type(const std::string& event_type);

// Check if an event is a power event
bool is_power_event(const PduEvent& pdu);

// Auth check for a single event against a state set
bool auth_check(
    const std::string& room_version,
    const PduEvent& event,
    const std::optional<std::shared_ptr<PduEvent>>& prev_event,
    const StateMap& state,
    const std::optional<std::string>& third_party_invite = std::nullopt
);

// Reverse topological power sort
std::vector<EventId> reverse_topological_power_sort(
    const RoomId& room_id,
    const std::vector<EventId>& control_events,
    EventMap& event_map,
    const std::vector<EventId>& event_ids
);

// Mainline sort
std::vector<EventId> mainline_sort(
    const RoomId& room_id,
    const std::vector<EventId>& event_ids,
    const std::optional<EventId>& power_level_event,
    EventMap& event_map
);

// Iterative auth check
std::map<EventId, std::shared_ptr<PduEvent>> iterative_auth_check(
    const RoomId& room_id,
    const std::string& room_version,
    const std::vector<EventId>& event_ids,
    const std::map<EventId, std::shared_ptr<PduEvent>>& resolved_control_events,
    EventMap& event_map
);

// Full state resolution
StateMap resolve(
    const RoomId& room_id,
    const std::string& room_version,
    const std::vector<EventId>& event_ids,
    EventMap& event_map,
    const StateMap& auth_chain
);

// Calculate forward extremities
std::vector<EventId> calculate_forward_extremities(
    Data& db,
    const PduEvent& pdu
);

// Ed25519 signature verification
bool verify_signature(
    const std::string& public_key_b64,
    const std::string& message,
    const std::string& signature_b64
);

// Verify event signatures
bool verify_event_signatures(
    const json& event,
    const std::map<std::string, std::string>& signing_keys, // server -> key
    const std::string& room_version
);

// Fetch signing keys for a server
std::map<std::string, std::string> fetch_signing_keys(
    Data& db,
    const std::string& server_name
);

} // namespace state_res
