// utils.hpp — translation of Conduit's src/utils.rs as of 533260ed
//
// Rust original (new parts in this commit):
//
//   pub fn bytes_to_string(bytes: &[u8]) -> String
//   pub fn vec_to_bytes(vec: Vec<String>) -> Vec<u8>     // join(&0) — NUL-separated!
//   pub fn bytes_to_vec(bytes: &[u8]) -> Vec<String>     // split(|&b| b == 0)
//   pub fn millis_since_unix_epoch() -> js_int::UInt
//
// The NUL-join trick is how early Conduit stored a list of strings (a user's
// devices!) in one KV value. tuwunel still carries descendants of these
// helpers.

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
uint64_t u64_from_bytes(const std::string& bytes);  // u64::from_be_bytes
std::string increment(const std::optional<std::string>& old);  // be counter + 1

}  // namespace utils
