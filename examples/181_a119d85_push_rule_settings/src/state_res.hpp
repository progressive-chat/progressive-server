// state_res.hpp — translation of Conduit commit c4f5a0a6's state-res
// integration (Aug 6, 2020).
//
// This is the FIRST commit that introduced state resolution to Conduit
// (via the ruma/state-res crate). It adds the data structures and
// algorithms for tracking room state at each event.
//
// In Conduit, state resolution is the algorithm that determines what
// the room state is at any point in time, given the event graph. The
// `state-res` crate provides `reverse_topological_power_sort` which
// sorts events in the order they should be applied, considering auth
// rules and power levels.
//
// In our C++ translation, this is a SIMPLIFIED version that just
// tracks the latest state hash per room. The full state resolution
// algorithm is implemented in step 83 (d71d94a_msc4297_state_res_v2)
// which uses a more advanced version.

#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <vector>

namespace state_res {

// StateHash: SHA-256 of the sorted PDU ids that make up the state at
// this point. In Conduit this is a String (later Vec<u8>); we use
// std::string for simplicity.
using StateHash = std::string;

// Compute a new state hash from a list of PDU ids. This is the
// SHA-256 of the concatenation of all PDU ids, sorted.
StateHash new_state_hash(const std::vector<std::string>& pdu_ids);

// reverse_topological_power_sort: sort events in the order they
// should be applied for state resolution. This is a SIMPLIFIED version
// that just returns the input events sorted by event_id. The full
// implementation in ruma/state-res uses the auth events graph to
// determine ordering.
std::vector<std::string> reverse_topological_power_sort(
    const std::string& room_id,
    const std::vector<std::string>& event_ids,
    const std::vector<nlohmann::json>& events,
    class Data* db,
    const std::vector<std::string>& auth_diff
);

}  // namespace state_res
