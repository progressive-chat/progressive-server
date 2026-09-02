// utils.hpp — translation of Conduit's src/utils.rs through fa322689
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace utils {

std::string vec_to_bytes(const std::vector<std::string>& strings);
std::vector<std::string> bytes_to_vec(const std::string& bytes);
uint64_t millis_since_unix_epoch();

// NEW in fa322689:
uint64_t u64_from_bytes(const std::string& bytes);             // u64::from_be_bytes
std::string increment(const std::optional<std::string>& old);  // be counter + 1

// NEW in fa9e127a (utils.rs):
std::string random_string(size_t length);  // Alphanumeric, like upstream's rng
// Calculate a new hash for the given password (Argon2id encoded PHC string).
std::optional<std::string> calculate_hash(const std::string& password);

// NEW in dd749b8: keypair generation with version prefix
/// Returns a versioned keypair: 1 byte version + 0xff + 32-byte Ed25519 key
/// Version 1: 1 byte version (1) + 0xff + 32-byte Ed25519 key
std::string generate_keypair();

}  // namespace utils
