// crypto.hpp — reference hash support for fa322689
//
// Upstream called ruma_signatures::reference_hash(event). Under the hood that
// is: redact(event) -> canonical JSON -> SHA-256 -> base64 (url-safe, no
// padding) -> "$" prefix.
//
//   let event_id = EventId::try_from(&*format!(
//       "${}",
//       ruma_signatures::reference_hash(&serde_json::to_value(&event).unwrap())
//           .expect("ruma can calculate reference hashes")))
//
// We implement all three pieces by hand so nothing is magic.

#pragma once

#include <cstdint>
#include <string>

#include "json_value.hpp"

namespace crypto {

std::string sha256_hex(const std::string& input);            // lowercase hex, for tests
std::string sha256(const std::string& input);                // raw 32 bytes
std::string base64_url_nopad(const std::string& raw);

// The Matrix redaction algorithm (room v1-v4 era rules as ruma-signatures
// applied them in 2020): strip top-level keys not on the allowlist, then keep
// only whitelisted keys inside `content` per event type.
json::Value redact(const json::Value& event);

// "$" + base64_url_nopad(sha256(canonical(redact(event))))
std::string reference_hash(const json::Value& event);

}  // namespace crypto
