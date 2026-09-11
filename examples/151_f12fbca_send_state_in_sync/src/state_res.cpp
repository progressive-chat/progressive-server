#include "state_res.hpp"
#include "utils.hpp"
#include "crypto.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <queue>
#include <unordered_map>
#include <iostream>

using json = nlohmann::json;

namespace state_res {

// Helper: get power event type
PowerEventType get_power_event_type(const std::string& event_type) {
    if (event_type == "m.room.create") return PowerEventType::RoomCreate;
    if (event_type == "m.room.member") return PowerEventType::RoomMember;
    if (event_type == "m.room.power_levels") return PowerEventType::RoomPowerLevels;
    if (event_type == "m.room.join_rules") return PowerEventType::RoomJoinRules;
    if (event_type == "m.room.history_visibility") return PowerEventType::RoomHistoryVisibility;
    if (event_type == "m.room.third_party_invite") return PowerEventType::RoomThirdPartyInvite;
    return PowerEventType::Other;
}

bool is_power_event(const PduEvent& pdu) {
    return get_power_event_type(pdu.kind()) != PowerEventType::Other;
}

// Auth check implementation based on Matrix spec
bool auth_check(
    const std::string& room_version,
    const PduEvent& event,
    const std::optional<std::shared_ptr<PduEvent>>& prev_event,
    const StateMap& state,
    const std::optional<std::string>& third_party_invite
) {
    // Simplified auth check - in reality this is very complex
    // For now, we'll do basic checks
    
    // Check event has required fields
    if (event.event_id().empty() || event.room_id().empty() || event.sender().empty()) {
        return false;
    }
    
    // Check prev_events exist in state if provided
    if (prev_event.has_value()) {
        // Basic check - prev event should be in the room
        if (prev_event.value()->room_id() != event.room_id()) {
            return false;
        }
    }
    
    // Check auth_events exist in state
    for (const auto& auth_event_id : event.auth_events()) {
        bool found = false;
        for (const auto& [key, id] : state) {
            if (id == auth_event_id) {
                found = true;
                break;
            }
        }
        // If not found in state, check if it's in the event's auth_events
        // This is a simplification
    }
    
    // Type-specific checks
    if (event.kind() == "m.room.create") {
        // Create event must be first in room
        if (prev_event.has_value()) return false;
        if (!event.state_key().has_value()) return false;
        if (*event.state_key() != "") return false;
    }
    else if (event.kind() == "m.room.member") {
        // Member events need state_key (target user)
        if (!event.state_key().has_value()) return false;
        
        // Check membership state
        auto content = event.content().find("membership");
        if (content == event.content().end()) return false;
        
        std::string membership = content->get<std::string>();
        if (membership != "join" && membership != "leave" && 
            membership != "invite" && membership != "ban" && 
            membership != "knock") {
            return false;
        }
    }
    else if (event.kind() == "m.room.power_levels") {
        // Power levels event
        if (!event.state_key().has_value()) return false;
        if (*event.state_key() != "") return false;
    }
    
    return true;
}

// Helper: build event graph for topological sort
std::map<EventId, std::vector<EventId>> build_event_graph(
    const std::vector<EventId>& event_ids,
    EventMap& event_map
) {
    std::map<EventId, std::vector<EventId>> graph;
    for (const auto& id : event_ids) {
        graph[id] = {};
    }
    
    for (const auto& id : event_ids) {
        auto it = event_map.find(id);
        if (it != event_map.end()) {
            for (const auto& prev_id : it->second->prev_events()) {
                if (graph.find(prev_id) != graph.end()) {
                    graph[prev_id].push_back(id);
                }
            }
        }
    }
    return graph;
}

// Kahn's algorithm for topological sort
std::vector<EventId> topological_sort(const std::map<EventId, std::vector<EventId>>& graph) {
    std::map<EventId, int> in_degree;
    for (const auto& [node, edges] : graph) {
        in_degree[node] = 0;
    }
    for (const auto& [node, edges] : graph) {
        for (const auto& edge : edges) {
            in_degree[edge]++;
        }
    }
    
    std::queue<EventId> q;
    for (const auto& [node, degree] : in_degree) {
        if (degree == 0) q.push(node);
    }
    
    std::vector<EventId> result;
    while (!q.empty()) {
        auto node = q.front(); q.pop();
        result.push_back(node);
        
        for (const auto& edge : graph.at(node)) {
            in_degree[edge]--;
            if (in_degree[edge] == 0) {
                q.push(edge);
            }
        }
    }
    
    return result;
}

// Reverse topological power sort
std::vector<EventId> reverse_topological_power_sort(
    const RoomId& room_id,
    const std::vector<EventId>& control_events,
    EventMap& event_map,
    const std::vector<EventId>& event_ids
) {
    // Build graph of all events
    auto graph = build_event_graph(event_ids, event_map);
    
    // Get topological order
    auto topo_order = topological_sort(graph);
    
    // Reverse it
    std::reverse(topo_order.begin(), topo_order.end());
    
    // Filter to only control events
    std::vector<EventId> result;
    for (const auto& id : topo_order) {
        if (std::find(control_events.begin(), control_events.end(), id) != control_events.end()) {
            result.push_back(id);
        }
    }
    
    return result;
}

// Mainline sort - based on Matrix spec
std::vector<EventId> mainline_sort(
    const RoomId& room_id,
    const std::vector<EventId>& event_ids,
    const std::optional<EventId>& power_level_event,
    EventMap& event_map
) {
    // Build mainline from power level event
    std::vector<EventId> mainline;
    if (power_level_event.has_value()) {
        auto current = power_level_event.value();
        while (true) {
            mainline.push_back(current);
            auto it = event_map.find(current);
            if (it == event_map.end() || it->second->prev_events().empty()) break;
            current = it->second->prev_events()[0]; // Simplified: use first prev_event
        }
        std::reverse(mainline.begin(), mainline.end());
    }
    
    // Calculate mainline position for each event
    std::map<EventId, int> mainline_pos;
    for (size_t i = 0; i < mainline.size(); ++i) {
        mainline_pos[mainline[i]] = static_cast<int>(i);
    }
    
    // Sort events by mainline position (closer to end = higher position)
    std::vector<EventId> result = event_ids;
    std::sort(result.begin(), result.end(), [&](const EventId& a, const EventId& b) {
        auto pos_a = mainline_pos.count(a) ? mainline_pos[a] : -1;
        auto pos_b = mainline_pos.count(b) ? mainline_pos[b] : -1;
        return pos_a > pos_b; // Higher position (closer to end) comes first
    });
    
    return result;
}

// Iterative auth check
std::map<EventId, std::shared_ptr<PduEvent>> iterative_auth_check(
    const RoomId& room_id,
    const std::string& room_version,
    const std::vector<EventId>& event_ids,
    const std::map<EventId, std::shared_ptr<PduEvent>>& resolved_control_events,
    EventMap& event_map
) {
    std::map<EventId, std::shared_ptr<PduEvent>> resolved;
    
    // Start with resolved control events
    for (const auto& [id, pdu] : resolved_control_events) {
        resolved[id] = pdu;
    }
    
    // Build state from resolved events
    StateMap state;
    for (const auto& [id, pdu] : resolved) {
        if (pdu->state_key().has_value()) {
            state[std::make_pair(pdu->kind(), *pdu->state_key())] = id;
        }
    }
    
    // Try to auth each event in order
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& id : event_ids) {
            if (resolved.count(id)) continue;
            
            auto it = event_map.find(id);
            if (it == event_map.end()) continue;
            
            auto pdu = it->second;
            std::optional<std::shared_ptr<PduEvent>> prev;
            if (!pdu->prev_events().empty()) {
                auto prev_it = event_map.find(pdu->prev_events()[0]);
                if (prev_it != event_map.end()) {
                    prev = prev_it->second;
                }
            }
            
            if (auth_check(room_version, *pdu, prev, state)) {
                resolved[id] = pdu;
                if (pdu->state_key().has_value()) {
                    state[std::make_pair(pdu->kind(), *pdu->state_key())] = id;
                }
                changed = true;
            }
        }
    }
    
    return resolved;
}

// Full state resolution
StateMap resolve(
    const RoomId& room_id,
    const std::string& room_version,
    const std::vector<EventId>& event_ids,
    EventMap& event_map,
    const StateMap& auth_chain
) {
    // Separate control events (power events)
    std::vector<EventId> control_events;
    for (const auto& id : event_ids) {
        auto it = event_map.find(id);
        if (it != event_map.end() && is_power_event(*it->second)) {
            control_events.push_back(id);
        }
    }
    
    // Step 1: Reverse topological power sort on control events
    auto sorted_control = reverse_topological_power_sort(room_id, control_events, event_map, event_ids);
    
    // Step 2: Iterative auth check on control events
    auto resolved_control = iterative_auth_check(room_id, room_version, sorted_control, {}, event_map);
    
    // Step 3: Get power level event from resolved control events
    std::optional<EventId> power_level_event;
    for (const auto& [id, pdu] : resolved_control) {
        if (pdu->kind() == "m.room.power_levels") {
            power_level_event = id;
            break;
        }
    }
    
    // Step 4: Mainline sort on all events
    std::vector<EventId> non_control_events;
    for (const auto& id : event_ids) {
        if (std::find(control_events.begin(), control_events.end(), id) == control_events.end()) {
            non_control_events.push_back(id);
        }
    }
    
    auto sorted_events = mainline_sort(room_id, non_control_events, power_level_event, event_map);
    
    // Step 5: Iterative auth check on all events
    auto all_resolved = iterative_auth_check(room_id, room_version, sorted_events, resolved_control, event_map);
    
    // Build final state map
    StateMap final_state;
    for (const auto& [id, pdu] : all_resolved) {
        if (pdu->state_key().has_value()) {
            final_state[std::make_pair(pdu->kind(), *pdu->state_key())] = id;
        }
    }
    
    return final_state;
}

// Calculate forward extremities
std::vector<EventId> calculate_forward_extremities(
    Data& db,
    const PduEvent& pdu
) {
    // Get current forward extremities for the room
    auto extremities = db.get_forward_extremities(pdu.room_id());
    
    // Add the new event
    extremities.push_back(pdu.event_id());
    
    // Remove any extremities that are now ancestors of the new event
    // This is simplified - real implementation would check DAG
    std::vector<EventId> result;
    for (const auto& ext : extremities) {
        if (ext != pdu.event_id()) {
            // Check if ext is ancestor of new event
            // Simplified: keep all for now
            result.push_back(ext);
        }
    }
    result.push_back(pdu.event_id());
    
    return result;
}

// Ed25519 signature verification using OpenSSL
bool verify_signature(
    const std::string& public_key_b64,
    const std::string& message,
    const std::string& signature_b64
) {
    // Decode base64
    auto decode_b64 = [](const std::string& input) -> std::vector<unsigned char> {
        BIO* bio = BIO_new_mem_buf(input.c_str(), -1);
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);
        
        std::vector<unsigned char> output(input.size());
        int len = BIO_read(bio, output.data(), input.size());
        output.resize(len);
        
        BIO_free_all(bio);
        return output;
    };
    
    auto pubkey = decode_b64(public_key_b64);
    auto sig = decode_b64(signature_b64);
    
    if (pubkey.size() != 32 || sig.size() != 64) {
        return false;
    }
    
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubkey.data(), pubkey.size());
    if (!pkey) return false;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }
    
    int result = 0;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        result = EVP_DigestVerify(ctx, sig.data(), sig.size(), 
                                  reinterpret_cast<const unsigned char*>(message.c_str()), message.size());
    }
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    return result == 1;
}

bool verify_event_signatures(
    const json& event,
    const std::map<std::string, std::string>& signing_keys,
    const std::string& room_version
) {
    // Get signatures from event
    auto sig_it = event.find("signatures");
    if (sig_it == event.end() || !sig_it->is_object()) {
        return false;
    }
    
    // For each signing server
    for (const auto& [server, sigs] : sig_it->items()) {
        auto key_it = signing_keys.find(server);
        if (key_it == signing_keys.end()) {
            // Try to fetch keys - in real impl would fetch from server
            continue;
        }
        
        // Get the signature for this key
        if (!sigs.is_object()) continue;
        for (const auto& [key_id, signature] : sigs.items()) {
            if (!signature.is_string()) continue;
            
            // Create canonical JSON for signing (simplified)
            json to_sign = event;
            to_sign.erase("signatures");
            to_sign.erase("unsigned");
            
            std::string canonical = to_sign.dump(); // Should use canonical JSON
            
            if (!verify_signature(key_it->second, canonical, signature.get<std::string>())) {
                return false;
            }
        }
    }
    
    return true;
}

std::map<std::string, std::string> fetch_signing_keys(
    Data& db,
    const std::string& server_name
) {
    // Check local cache first
    auto keys = db.get_signing_keys(server_name);
    if (!keys.empty()) {
        std::map<std::string, std::string> result;
        for (const auto& [key_id, key] : keys) {
            result[key_id] = key;
        }
        return result;
    }
    
    // In real implementation, would fetch from server via /_matrix/key/v2/server
    // For now, return empty
    return {};
}

} // namespace state_res
