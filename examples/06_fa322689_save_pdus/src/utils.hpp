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

}  // namespace utils
