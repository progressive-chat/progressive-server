// appservice_server.hpp — translation of Conduit commit 6e5b35ea's
// src/appservice_server.rs.
//
// Appservice (bridge) protocol client: when the homeserver receives an
// event (message, state change, membership change, etc.) that an
// appservice has registered interest in, we push it to the appservice
// via a signed HTTPS POST.
//
// Used by the client_server routes (account.rs, alias.rs, membership.rs,
// message.rs, profile.rs, redact.rs, room.rs, state.rs, to_device.rs)
// to dispatch events to bridges like mautrix, heisenbridge, etc.

#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace appservice {

// Send a request to an appservice. The request body is `content` (a JSON
// value). The function:
//  - resolves the appservice's URL + hs_token from `registration`
//  - signs the request body with the homeserver's keypair (X-Matrix auth)
//  - appends ?access_token=<hs_token> to the URL
//  - POSTs the request via httplib::SSLClient with a 30s timeout
//  - returns the parsed JSON response, or nullopt on any error
//
// Mirrors Conduit's appservice_server::send_request which is generic over
// any ruma::OutgoingRequest. Our C++ version takes a flat (method, path,
// body) tuple because we don't have a generic request abstraction.
std::optional<nlohmann::json> send_request(
    const std::string& hostname,
    const std::string& keypair_seed,
    const nlohmann::json& registration,
    const std::string& method,
    const std::string& path,
    const nlohmann::json& body = {});

}  // namespace appservice
