// utils.hpp — translation of Conduit's src/utils.rs as of 533260ed
//
//   pub fn millis_since_unix_epoch() -> js_int::UInt
//   pub fn bytes_to_string / vec_to_bytes / bytes_to_vec  // NUL-joined lists
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace utils {

std::string vec_to_bytes(const std::vector<std::string>& strings);
std::vector<std::string> bytes_to_vec(const std::string& bytes);
uint64_t millis_since_unix_epoch();

// NEW in fa322689 (utils.rs):
uint64_t u64_from_bytes(const std::string& bytes);              // from_be_bytes
std::string increment(const std::optional<std::string>& old);   // be counter + 1

}  // namespace utils
