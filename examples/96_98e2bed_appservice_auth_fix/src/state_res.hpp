// state_res.hpp — MSC4297 State Resolution v2.1 implementation
//
// This implements the Matrix Spec MSC4297 State Resolution v2.1 algorithm.
// Key components:
// - Conflicted state subgraph detection
// - Topological ordering of events
// - Canonical event ordering for deterministic resolution

#pragma once

#include "data.hpp"
#include <nlohmann/json.hpp>

#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace state_res {

// StateMap maps state keys to lists of event IDs (for conflicted state)
using StateMap = std::unordered_map<std::string, std::vector<std::string>>;

// EventAuth represents the auth events of a PDU
struct EventAuth {
    std::vector<std::string> auth_events;
};

// Result of conflicted state subgraph computation
struct ConflictedSubgraphResult {
    std::unordered_set<std::string> conflicted_events;
};

// Forward declare the global Data class
class Data;

// Type alias for event ID
using EventId = std::string;

/**
 * Computes the conflicted state subgraph for a given conflicted state set.
 * 
 * This implements the MSC4297 algorithm for finding the conflicted state subgraph:
 * - Start with the conflicted event IDs
 * - Traverse auth event chains backwards
 * - Track paths to detect cycles and conflicts
 * - Return the set of events that are part of the conflicted state subgraph
 */
ConflictedSubgraphResult get_conflicted_state_subgraph(
    ::Data* data,
    const std::string& room_id,
    const std::unordered_map<std::string, std::vector<std::string>>& conflicted_state_set
);

/**
 * Resolves state using the MSC4297 v2.1 algorithm.
 * 
 * Steps:
 * 1. Build the full state map from all events
 * 2. Identify conflicted state keys (multiple events for same state key)
 * 3. Compute conflicted state subgraph
 * 4. Topologically sort the subgraph
 * 4. Apply canonical event ordering for deterministic resolution
 * 5. Return resolved state
 */
std::unordered_map<std::string, std::string> resolve_state_v2(
    ::Data* data,
    const std::string& room_id,
    const std::vector<std::string>& event_ids
);

}  // namespace state_res
