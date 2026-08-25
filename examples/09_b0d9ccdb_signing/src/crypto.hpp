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

// --- NEW in b0d9ccdb: Ed25519 (ruma_signatures::Ed25519KeyPair) --------------
// A keypair is stored as its raw 32-byte seed; the public key is derived.
std::string ed25519_generate_seed();  // 32 random bytes
std::string ed25519_public_b64(const std::string& seed);   // base64url, no pad
std::string ed25519_sign(const std::string& seed, const std::string& msg);
bool ed25519_verify(const std::string& pub_b64, const std::string& msg,
                    const std::string& sig_b64);

// ruma_signatures::hash_and_sign_event(hostname, keypair, event):
//   hashes.sha256 = sha256(canonical(redact(event)))
//   signatures[hostname]["ed25519:" + public_b64] = sign(canonical(event))
void hash_and_sign_event(const std::string& hostname, const std::string& seed,
                         json& event);


}  // namespace crypto
