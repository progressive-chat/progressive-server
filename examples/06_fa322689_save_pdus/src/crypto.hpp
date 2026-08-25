// crypto.hpp — ruma_signatures::reference_hash, translated.
//
//   "$" + base64_url_nopad(sha256(canonical_json(redact(event))))
//
// SHA-256 via OpenSSL; redaction follows the room v1-v4 era algorithm
// ruma-signatures applied in 2020; canonical JSON = nlohmann sorted dump().
#pragma once

#include <nlohmann/json.hpp>

#include <string>

namespace crypto {

using json = nlohmann::json;

std::string sha256(const std::string& input);              // raw 32 bytes
std::string base64_url_nopad(const std::string& raw);
json redact(const json& event);
std::string reference_hash(const json& event);

}  // namespace crypto
