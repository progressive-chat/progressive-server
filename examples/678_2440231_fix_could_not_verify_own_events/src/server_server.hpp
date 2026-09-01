// server_server.hpp — translation of Conduit's src/server_server.rs
// (send_request from b0d9ccdb; server identity routes arrive in 1af6dd98).

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
// NEW in 4cc0a070: request_well_known — fetches
// https://<destination>/.well-known/matrix/server and returns the m.server
// delegation hint. Returns nullopt on any network/parse/format error.
std::optional<std::string> request_well_known(const std::string& destination);



}  // namespace federation
