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

// NEW in 63ba157e: validate the X-Matrix `destination` field of an incoming
// federation request (Conduit's ruma_wrapper axum.rs auth check). Returns
// false when an X-Matrix Authorization header carries a `destination` that
// does not match `self`; requests without an X-Matrix header always pass.
bool xmatrix_destination_ok(const std::string& authorization,
                            const std::string& self);

}  // namespace federation
