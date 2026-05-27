// progressive-server: Matrix Federation S2S API - Server-to-Server protocol
// Reference: Synapse federation/* (11,483 lines Python) 
// Key distribution, event signing, transaction sending, backfill, 
// state resolution, room discovery, invites, joins, leaves

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <variant>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <atomic>
#include <mutex>
#include "../json.hpp"

namespace progressive {
namespace federation {

using json = nlohmann::json;

// =============================================================================
// Federation key store
// =============================================================================
struct VerifyKey {
    std::string key_id;
    std::string key_b64;           // base64-encoded ed25519 public key
    uint64_t valid_until_ts = 0;   // milliseconds
    bool expired() const {
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return valid_until_ts > 0 && now > valid_until_ts;
    }
};

struct ServerKeys {
    std::string server_name;
    std::vector<VerifyKey> verify_keys;
    std::string old_verify_keys;   // JSON
    std::string signatures;        // JSON
    uint64_t valid_until_ts = 0;
    time_t fetched_at = 0;

    const VerifyKey* find_key(const std::string& key_id) const {
        for (auto& k : verify_keys) {
            if (k.key_id == key_id) return &k;
        }
        return nullptr;
    }

    std::optional<VerifyKey> find_verify_key(const std::string& key_id) const {
        auto* k = find_key(key_id);
        if (k) return *k;
        return std::nullopt;
    }
};

// =============================================================================
// Public room list
// =============================================================================
struct PublicRoom {
    std::string room_id;
    int num_joined_members = 0;
    std::string room_type;
    std::string name;
    std::string topic;
    std::string canonical_alias;
    std::string world_readable;
    std::string guest_can_join;
    std::string avatar_url;
    std::string join_rule;
    std::string federation_protocols;
};

struct PublicRoomsChunk {
    std::vector<PublicRoom> chunk;
    std::string next_batch;
    std::string prev_batch;
    int total_room_count_estimate = 0;
};

// =============================================================================
// Events that flow between servers
// =============================================================================
struct FederationEvent {
    json event;
    std::string room_id;
    std::string event_id;
    std::string sender;
    std::string origin;
    std::string origin_server_ts;
    std::string event_type;
    json content;
    json unsigned_data;
    json prev_events;
    json auth_events;
    int depth = 0;
    json hashes;
    json signatures;
    json redacts;
};

// =============================================================================
// PDUs and EDUs for federation transactions
// =============================================================================
struct Pdu {
    std::string origin;
    std::string origin_server_ts;
    std::string room_id;
    std::string event_id;
    std::string sender;
    std::string type_;
    json content;
    int depth = 0;
    json prev_events;         // [["$event_id", {"sha256": "..."}], ...]
    json auth_events;
    json redacts;
    json unsigned_data;
    json hashes;
    json signatures;
    std::string state_key;

    json to_json() const {
        json j;
        j["origin"] = origin;
        j["origin_server_ts"] = origin_server_ts;
        j["room_id"] = room_id;
        j["event_id"] = event_id;
        j["sender"] = sender;
        j["type"] = type_;
        j["content"] = content;
        j["depth"] = depth;
        j["prev_events"] = prev_events;
        j["auth_events"] = auth_events;
        if (!redacts.is_null()) j["redacts"] = redacts;
        if (!unsigned_data.is_null()) j["unsigned"] = unsigned_data;
        if (!hashes.is_null()) j["hashes"] = hashes;
        if (!signatures.is_null()) j["signatures"] = signatures;
        if (!state_key.empty()) j["state_key"] = state_key;
        return j;
    }
};

struct Edu {
    std::string origin;
    std::string destination;
    std::string edu_type;
    json content;

    json to_json() const {
        return {
            {"origin", origin},
            {"destination", destination},
            {"edu_type", edu_type},
            {"content", content}
        };
    }
};

struct FederationTransaction {
    std::string origin;
    std::string origin_server_ts;
    std::string destination;
    std::string transaction_id;
    std::vector<Pdu> pdus;
    std::vector<Edu> edus;

    json to_json() const {
        json pdus_arr = json::array();
        for (auto& p : pdus) pdus_arr.push_back(p.to_json());

        json edus_arr = json::array();
        for (auto& e : edus) edus_arr.push_back(e.to_json());

        return {
            {"origin", origin},
            {"origin_server_ts", origin_server_ts},
            {"destination", destination},
            {"transaction_id", transaction_id},
            {"pdus", pdus_arr},
            {"edus", edus_arr}
        };
    }
};

// =============================================================================
// State resolution (Auth chain resolution)
// =============================================================================
struct StateResolutionResult {
    json state;                  // resolved state map
    json auth_chain;            // auth events used
    bool success = false;
    std::string error;
};

class StateResolution {
public:
    // Resolve state conflicts between multiple state sets
    static StateResolutionResult resolve(
        const std::vector<json>& state_sets,
        const std::string& room_version = "10") {

        if (state_sets.empty()) {
            return {{}, {}, false, "No state sets to resolve"};
        }

        StateResolutionResult result;

        // 1. Build power level lookup for each event in each state set
        auto power_levels = compute_power_levels(state_sets);

        // 2. Find all state keys across all state sets
        std::set<std::tuple<std::string, std::string>> all_keys;
        for (auto& state_set : state_sets) {
            for (auto& ev : state_set) {
                std::string type = ev["type"];
                std::string state_key = ev.value("state_key", "");
                all_keys.insert({type, state_key});
            }
        }

        // 3. For each state key, resolve the conflict
        for (auto& [type, state_key] : all_keys) {
            auto winner = resolve_state_key(state_sets, type, state_key,
                                             room_version, power_levels);
            if (!winner.is_null()) {
                result.state[std::string(type + "|" + state_key)] = winner;
            }
        }

        result.success = true;
        return result;
    }

private:
    static std::unordered_map<std::string, int> compute_power_levels(
        const std::vector<json>& state_sets) {
        std::unordered_map<std::string, int> power_levels;

        for (auto& state_set : state_sets) {
            for (auto& ev : state_set) {
                if (ev["type"] == "m.room.power_levels" && ev["state_key"] == "") {
                    auto& content = ev["content"];
                    auto& users = content.value("users", json::object());
                    for (auto& [user, level] : users.items()) {
                        int current = power_levels[user];
                        if (level.is_number() && (int)level > current) {
                            power_levels[user] = (int)level;
                        }
                    }
                }
            }
        }
        return power_levels;
    }

    static json resolve_state_key(
        const std::vector<json>& state_sets,
        const std::string& type, const std::string& state_key,
        const std::string& room_version,
        const std::unordered_map<std::string, int>& power_levels) {

        // Collect all events for this (type, state_key)
        std::vector<json> candidates;
        for (auto& state_set : state_sets) {
            for (auto& ev : state_set) {
                if (ev["type"] == type &&
                    ev.value("state_key", "") == state_key) {
                    candidates.push_back(ev);
                }
            }
        }

        if (candidates.empty()) return json();
        if (candidates.size() == 1) return candidates[0];

        // Resolution algorithm (v2):
        // 1. Higher power level sender wins
        // 2. Higher origin_server_ts wins
        // 3. Lexicographically smaller event_id wins

        std::sort(candidates.begin(), candidates.end(),
            [&](const json& a, const json& b) {
                int pl_a = get_power_level(a["sender"], power_levels);
                int pl_b = get_power_level(b["sender"], power_levels);
                if (pl_a != pl_b) return pl_a > pl_b;

                uint64_t ts_a = a.value("origin_server_ts", 0ULL);
                uint64_t ts_b = b.value("origin_server_ts", 0ULL);
                if (ts_a != ts_b) return ts_a > ts_b;

                return a.value("event_id", "") < b.value("event_id", "");
            });

        return candidates[0];
    }

    static int get_power_level(const std::string& user,
                               const std::unordered_map<std::string, int>& pl) {
        auto it = pl.find(user);
        return (it != pl.end()) ? it->second : 0;
    }
};

// =============================================================================
// Federation request sender
// =============================================================================
struct FederationRequest {
    enum Method { GET, PUT, POST, DELETE };
    Method method = GET;
    std::string destination;        // server name
    std::string path;               // /_matrix/federation/v1/send/...
    std::string query_string;
    json body;
    int timeout_ms = 60000;
    bool ignore_backoff = false;
    bool long_retries = false;      // use longer backoff for PDU pushes
    int retry_on_dns_fail = 1;
};

struct FederationResponse {
    int http_code = 0;
    json body;
    std::string error;
    bool success() const { return http_code >= 200 && http_code < 300; }
};

// Federation client for sending requests
class FederationClient {
public:
    FederationClient(const std::string& server_name,
                     const std::string& signing_key_b64)
        : server_name_(server_name), signing_key_(signing_key_b64) {}

    // Send transaction (PDUs + EDUs) to another server
    FederationResponse send_transaction(const std::string& destination,
                                         const FederationTransaction& txn) {
        FederationRequest req;
        req.method = FederationRequest::PUT;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/send/" + txn.transaction_id;
        req.body = txn.to_json();

        return send_request(req);
    }

    // Make join request (invite another server to a room)
    FederationResponse make_join(const std::string& destination,
                                  const std::string& room_id,
                                  const std::string& user_id,
                                  const std::string& room_version = "10") {
        FederationRequest req;
        req.method = FederationRequest::GET;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/make_join/" +
                    urlencode(room_id) + "/" + urlencode(user_id);
        req.query_string = "ver=" + room_version;
        return send_request(req);
    }

    // Send join event
    FederationResponse send_join(const std::string& destination,
                                  const std::string& room_id,
                                  const std::string& event_id,
                                  const json& event) {
        FederationRequest req;
        req.method = FederationRequest::PUT;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/send_join/" +
                    urlencode(room_id) + "/" + urlencode(event_id);
        req.body = event;
        return send_request(req);
    }

    // Make leave request
    FederationResponse make_leave(const std::string& destination,
                                   const std::string& room_id,
                                   const std::string& user_id) {
        FederationRequest req;
        req.method = FederationRequest::GET;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/make_leave/" +
                    urlencode(room_id) + "/" + urlencode(user_id);
        return send_request(req);
    }

    // Send leave event
    FederationResponse send_leave(const std::string& destination,
                                   const std::string& room_id,
                                   const std::string& event_id,
                                   const json& event) {
        FederationRequest req;
        req.method = FederationRequest::PUT;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/send_leave/" +
                    urlencode(room_id) + "/" + urlencode(event_id);
        req.body = event;
        return send_request(req);
    }

    // Invite user on remote server
    FederationResponse send_invite(const std::string& destination,
                                    const std::string& room_id,
                                    const std::string& event_id,
                                    const json& invite_event) {
        FederationRequest req;
        req.method = FederationRequest::PUT;
        req.destination = destination;
        req.path = "/_matrix/federation/v2/invite/" +
                    urlencode(room_id) + "/" + urlencode(event_id);
        req.body = invite_event;
        return send_request(req);
    }

    // Third-party invite
    FederationResponse exchange_third_party_invite(
        const std::string& destination,
        const std::string& room_id,
        const json& invite_body) {
        FederationRequest req;
        req.method = FederationRequest::PUT;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/exchange_third_party_invite/" +
                    urlencode(room_id);
        req.body = invite_body;
        return send_request(req);
    }

    // Get event from remote server
    FederationResponse get_event(const std::string& destination,
                                  const std::string& event_id,
                                  int timeout_ms = 30000) {
        FederationRequest req;
        req.method = FederationRequest::GET;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/event/" + urlencode(event_id);
        req.timeout_ms = timeout_ms;
        return send_request(req);
    }

    // Get state for a room
    FederationResponse get_room_state(const std::string& destination,
                                       const std::string& room_id,
                                       const std::string& event_id = "") {
        FederationRequest req;
        req.method = FederationRequest::GET;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/state/" + urlencode(room_id);
        if (!event_id.empty()) {
            req.query_string = "event_id=" + urlencode(event_id);
        }
        return send_request(req);
    }

    // Get state IDs (just event IDs, not full events)
    FederationResponse get_room_state_ids(const std::string& destination,
                                           const std::string& room_id,
                                           const std::string& event_id = "") {
        FederationRequest req;
        req.method = FederationRequest::GET;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/state_ids/" + urlencode(room_id);
        if (!event_id.empty()) {
            req.query_string = "event_id=" + urlencode(event_id);
        }
        return send_request(req);
    }

    // Backfill events from a room
    FederationResponse backfill(const std::string& destination,
                                 const std::string& room_id,
                                 const std::vector<std::string>& event_ids,
                                 int limit = 100) {
        FederationRequest req;
        req.method = FederationRequest::GET;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/backfill/" + urlencode(room_id);

        std::string qs = "limit=" + std::to_string(limit);
        for (auto& eid : event_ids) qs += "&v=" + urlencode(eid);
        req.query_string = qs;
        return send_request(req);
    }

    // Get missing events
    FederationResponse get_missing_events(const std::string& destination,
                                           const std::string& room_id,
                                           const std::vector<std::string>& earliest_events,
                                           const std::vector<std::string>& latest_events,
                                           int limit = 10,
                                           int min_depth = 0) {
        FederationRequest req;
        req.method = FederationRequest::POST;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/get_missing_events/" +
                    urlencode(room_id);
        req.body = {
            {"earliest_events", earliest_events},
            {"latest_events", latest_events},
            {"limit", limit},
            {"min_depth", min_depth}
        };
        return send_request(req);
    }

    // Query profile information
    FederationResponse query_profile(const std::string& destination,
                                      const std::string& user_id,
                                      const std::string& field = "") {
        FederationRequest req;
        req.method = FederationRequest::GET;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/query/profile";
        std::string qs = "user_id=" + urlencode(user_id);
        if (!field.empty()) qs += "&field=" + urlencode(field);
        req.query_string = qs;
        return send_request(req);
    }

    // Query directory (user to server mapping)
    FederationResponse query_directory(const std::string& destination,
                                        const std::string& user_id) {
        FederationRequest req;
        req.method = FederationRequest::GET;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/query/directory";
        req.query_string = "user_id=" + urlencode(user_id);
        return send_request(req);
    }

    // Get public rooms
    FederationResponse get_public_rooms(const std::string& destination,
                                         int limit = 50,
                                         const std::string& since = "",
                                         const std::string& server = "",
                                         bool include_all_networks = false) {
        FederationRequest req;
        req.method = FederationRequest::GET;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/publicRooms";
        std::string qs = "limit=" + std::to_string(limit);
        if (!since.empty()) qs += "&since=" + urlencode(since);
        if (!server.empty()) qs += "&server=" + urlencode(server);
        if (include_all_networks) qs += "&include_all_networks=true";
        req.query_string = qs;
        return send_request(req);
    }

    // Query keys from remote server
    FederationResponse query_server_keys(const std::string& destination) {
        FederationRequest req;
        req.method = FederationRequest::GET;
        req.destination = destination;
        req.path = "/_matrix/key/v2/server";
        return send_request(req);
    }

    // Query specific keys
    FederationResponse query_keys(const std::string& destination,
                                   const json& query_body) {
        FederationRequest req;
        req.method = FederationRequest::POST;
        req.destination = destination;
        req.path = "/_matrix/key/v2/query";
        req.body = query_body;
        return send_request(req);
    }

    // Claim one-time keys
    FederationResponse claim_keys(const std::string& destination,
                                   const json& claim_body) {
        FederationRequest req;
        req.method = FederationRequest::POST;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/user/keys/claim";
        req.body = claim_body;
        return send_request(req);
    }

    // Get room hierarchy
    FederationResponse get_room_hierarchy(const std::string& destination,
                                           const std::string& room_id,
                                           bool suggested_only = false) {
        FederationRequest req;
        req.method = FederationRequest::GET;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/hierarchy/" + urlencode(room_id);
        if (suggested_only) req.query_string = "suggested_only=true";
        return send_request(req);
    }

    // Get timestamp to event mapping
    FederationResponse timestamp_to_event(const std::string& destination,
                                           const std::string& room_id,
                                           uint64_t timestamp,
                                           const std::string& direction = "f") {
        FederationRequest req;
        req.method = FederationRequest::GET;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/timestamp_to_event/" +
                    urlencode(room_id);
        req.query_string = "ts=" + std::to_string(timestamp) +
                           "&dir=" + direction;
        return send_request(req);
    }

    // Knock on a room
    FederationResponse make_knock(const std::string& destination,
                                   const std::string& room_id,
                                   const std::string& user_id,
                                   const std::string& room_version = "10") {
        FederationRequest req;
        req.method = FederationRequest::GET;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/make_knock/" +
                    urlencode(room_id) + "/" + urlencode(user_id);
        req.query_string = "ver=" + room_version;
        return send_request(req);
    }

    FederationResponse send_knock(const std::string& destination,
                                   const std::string& room_id,
                                   const std::string& event_id,
                                   const json& knock_event) {
        FederationRequest req;
        req.method = FederationRequest::PUT;
        req.destination = destination;
        req.path = "/_matrix/federation/v1/send_knock/" +
                    urlencode(room_id) + "/" + urlencode(event_id);
        req.body = knock_event;
        return send_request(req);
    }

private:
    std::string server_name_;
    std::string signing_key_;

    FederationResponse send_request(const FederationRequest& req) {
        // Build origin + signature headers
        FederationResponse resp;
        // In a real implementation, this would:
        // 1. Resolve DNS (SRV _matrix._tcp.<destination>)
        // 2. Open TLS connection
        // 3. Sign the request with ed25519 key
        // 4. Send HTTP request
        // 5. Verify response signature
        resp.http_code = 200;
        resp.body = json::object();
        return resp;
    }

    static std::string urlencode(const std::string& s) {
        std::string result;
        result.reserve(s.size() * 3);
        for (char c : s) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                result += c;
            } else {
                char buf[4];
                snprintf(buf, sizeof(buf), "%%%02X", (uint8_t)c);
                result += buf;
            }
        }
        return result;
    }
};

// =============================================================================
// Federation event signing
// =============================================================================
class EventSigner {
public:
    EventSigner(const std::string& server_name, const std::string& key_id,
                const std::string& private_key_b64)
        : server_name_(server_name), key_id_(key_id),
          private_key_(private_key_b64) {}

    // Sign a PDU before sending
    json sign_event(const json& event_dict) {
        json signed_event = event_dict;

        // Add origin and origin_server_ts if not present
        if (!signed_event.contains("origin")) {
            signed_event["origin"] = server_name_;
        }
        if (!signed_event.contains("origin_server_ts")) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            signed_event["origin_server_ts"] = ms;
        }

        // Compute redacted hash
        std::string redacted_json = redact_and_serialize(signed_event);
        std::string hash_b64 = sha256_b64(redacted_json);

        // Add hashes
        json hashes;
        hashes["sha256"] = hash_b64;
        signed_event["hashes"] = hashes;

        // Sign the event
        std::string to_sign = canonical_json(signable_event(signed_event));
        std::string signature_b64 = ed25519_sign(private_key_, to_sign);

        // Add signatures
        json sig;
        sig[key_id_] = signature_b64;
        json signatures;
        signatures[server_name_] = sig;
        signed_event["signatures"] = signatures;

        return signed_event;
    }

    // Verify a received event's signature
    bool verify_event(const json& signed_event, const std::string& origin,
                      const std::string& key_id, const std::string& public_key_b64) {
        if (!signed_event.contains("signatures")) return false;
        if (!signed_event["signatures"].contains(origin)) return false;
        if (!signed_event["signatures"][origin].contains(key_id)) return false;

        std::string signature_b64 = signed_event["signatures"][origin][key_id];
        std::string to_verify = canonical_json(signable_event(signed_event));

        return ed25519_verify(public_key_b64, to_verify, signature_b64);
    }

    // Compute event reference hash (for prev_events/auth_events references)
    static json event_reference(const json& event) {
        json ref;
        ref.push_back(event["event_id"]);
        json hash;
        hash["sha256"] = sha256_b64(canonical_json(event));
        ref.push_back(hash);
        return ref;
    }

private:
    std::string server_name_;
    std::string key_id_;
    std::string private_key_;

    // Build the signable event (without unsigned and signatures)
    static json signable_event(const json& event) {
        json result = event;
        result.erase("unsigned");
        result.erase("signatures");
        return result;
    }

    // Redact an event for hashing
    static json redact_and_serialize(const json& event) {
        json redacted;

        std::set<std::string> keep_keys = {
            "event_id", "type", "room_id", "sender", "state_key",
            "origin", "origin_server_ts", "prev_events", "auth_events",
            "depth", "membership", "content"
        };

        for (auto& [key, value] : event.items()) {
            if (keep_keys.count(key)) {
                if (key == "content") {
                    json redacted_content;

                    // Keep specific content fields based on event type
                    std::string ev_type = event.value("type", "");
                    if (ev_type == "m.room.member") {
                        if (value.contains("membership")) {
                            redacted_content["membership"] = value["membership"];
                        }
                    } else if (ev_type == "m.room.create") {
                        if (value.contains("creator")) {
                            redacted_content["creator"] = value["creator"];
                        }
                    } else if (ev_type == "m.room.join_rules") {
                        if (value.contains("join_rule")) {
                            redacted_content["join_rule"] = value["join_rule"];
                        }
                    } else if (ev_type == "m.room.power_levels") {
                        if (value.contains("ban")) redacted_content["ban"] = value["ban"];
                        if (value.contains("events")) redacted_content["events"] = value["events"];
                        if (value.contains("events_default")) redacted_content["events_default"] = value["events_default"];
                        if (value.contains("kick")) redacted_content["kick"] = value["kick"];
                        if (value.contains("redact")) redacted_content["redact"] = value["redact"];
                        if (value.contains("state_default")) redacted_content["state_default"] = value["state_default"];
                        if (value.contains("users")) redacted_content["users"] = value["users"];
                        if (value.contains("users_default")) redacted_content["users_default"] = value["users_default"];
                    } else if (ev_type == "m.room.history_visibility") {
                        if (value.contains("history_visibility")) {
                            redacted_content["history_visibility"] = value["history_visibility"];
                        }
                    }

                    redacted[key] = redacted_content;
                } else {
                    redacted[key] = value;
                }
            }
        }

        return canonical_json(redacted);
    }

    static std::string canonical_json(const json& obj) {
        return obj.dump();
    }

    static std::string sha256_b64(const std::string& input) {
        // Mock: real implementation uses OpenSSL EVP_Digest
        (void)input;
        return "base64sha256hash==";
    }

    static std::string ed25519_sign(const std::string& key, const std::string& data) {
        (void)key; (void)data;
        return "base64edsignature==";
    }

    static bool ed25519_verify(const std::string& pubkey,
                                const std::string& data,
                                const std::string& sig) {
        (void)pubkey; (void)data; (void)sig;
        return true;
    }
};

// =============================================================================
// Room discovery via .well-known and SRV records
// =============================================================================
struct WellKnownResult {
    std::string homeserver_base_url;
    std::string identity_server_base_url;
    bool valid = false;
    int ttl = 86400;               // seconds to cache
};

class ServerDiscovery {
public:
    static WellKnownResult resolve_well_known(const std::string& domain) {
        // GET https://<domain>/.well-known/matrix/server
        WellKnownResult result;
        result.homeserver_base_url = "https://" + domain;
        result.valid = true;
        return result;
    }

    static std::optional<std::string> resolve_server_name(
        const std::string& server_name) {
        // Try SRV record _matrix._tcp.<server_name> first
        // Fall back to server_name:8448
        return server_name + ":8448";
    }
};

// =============================================================================
// Federation transaction store (persist outgoing transactions)
// =============================================================================
struct StoredTransaction {
    std::string transaction_id;
    std::string destination;
    std::string origin;
    json pdus;
    json edus;
    time_t created_at;
    int retry_count = 0;
    time_t next_retry_at = 0;
    bool delivered = false;
    std::string last_error;
};

class TransactionQueue {
public:
    void enqueue(FederationTransaction&& txn) {
        StoredTransaction stored;
        stored.transaction_id = txn.transaction_id;
        stored.destination = txn.destination;
        stored.origin = txn.origin;
        stored.pdus = json::array();
        for (auto& p : txn.pdus) stored.pdus.push_back(p.to_json());
        stored.edus = json::array();
        for (auto& e : txn.edus) stored.edus.push_back(e.to_json());
        stored.created_at = std::time(nullptr);
        stored.retry_count = 0;
        stored.next_retry_at = stored.created_at;

        std::lock_guard lock(mutex_);
        queue_[txn.destination].push_back(stored);
    }

    std::vector<StoredTransaction> get_pending(const std::string& destination,
                                                 int limit = 50) {
        std::lock_guard lock(mutex_);
        std::vector<StoredTransaction> result;
        auto it = queue_.find(destination);
        if (it != queue_.end()) {
            time_t now = std::time(nullptr);
            for (auto& txn : it->second) {
                if (!txn.delivered && txn.next_retry_at <= now) {
                    result.push_back(txn);
                    if ((int)result.size() >= limit) break;
                }
            }
        }
        return result;
    }

    void mark_delivered(const std::string& destination,
                        const std::string& transaction_id) {
        std::lock_guard lock(mutex_);
        auto it = queue_.find(destination);
        if (it != queue_.end()) {
            for (auto& txn : it->second) {
                if (txn.transaction_id == transaction_id) {
                    txn.delivered = true;
                    break;
                }
            }
        }
    }

    void retry_later(const std::string& destination,
                     const std::string& transaction_id,
                     const std::string& error) {
        std::lock_guard lock(mutex_);
        auto it = queue_.find(destination);
        if (it != queue_.end()) {
            for (auto& txn : it->second) {
                if (txn.transaction_id == transaction_id) {
                    txn.retry_count++;
                    txn.last_error = error;
                    // Exponential backoff: 1min, 2min, 4min, 8min... max 24h
                    int delay = std::min(60 * (1 << std::min(txn.retry_count, 10)), 86400);
                    txn.next_retry_at = std::time(nullptr) + delay;
                    break;
                }
            }
        }
    }

    void prune_old(int max_age_days = 7) {
        std::lock_guard lock(mutex_);
        time_t cutoff = std::time(nullptr) - max_age_days * 86400;
        for (auto& [dest, txns] : queue_) {
            txns.erase(std::remove_if(txns.begin(), txns.end(),
                [cutoff](const StoredTransaction& t) {
                    return t.delivered && t.created_at < cutoff;
                }), txns.end());
        }
        // Remove empty destination queues
        for (auto it = queue_.begin(); it != queue_.end(); ) {
            if (it->second.empty()) it = queue_.erase(it);
            else ++it;
        }
    }

private:
    std::unordered_map<std::string, std::vector<StoredTransaction>> queue_;
    std::mutex mutex_;
};

} // namespace federation
} // namespace progressive
