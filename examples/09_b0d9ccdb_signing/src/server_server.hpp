// server_server.hpp — translation of Conduit commit b0d9ccdb's
// src/server_server.rs: send_request signs a federation request with
// X-Matrix authorization and delivers it to the destination server.
//
//   pub async fn send_request<T: Endpoint>(data, destination, request)
//
// C++ keeps it concrete: one function per use site (only publicRooms at this
// commit), taking method/path/content directly.

#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace federation {

// Signs {method, uri, origin, destination, content} and POSTs it to
// https://destination<path>. Returns the parsed JSON response or nullopt.
std::optional<nlohmann::json> send_request(
    const std::string& hostname, const std::string& keypair_seed,
    const std::string& destination, const std::string& path,
    const nlohmann::json& content = {});

}  // namespace federation
