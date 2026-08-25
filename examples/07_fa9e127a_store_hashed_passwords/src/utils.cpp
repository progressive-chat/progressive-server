#include "utils.hpp"

#include <argon2.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <random>
#include <cstring>

namespace utils {

std::string vec_to_bytes(const std::vector<std::string>& strings) {
  std::string out;
  for (const auto& s : strings) {
    if (!out.empty()) out.push_back('\0');  // join(&0)
    out += s;
  }
  return out;
}

std::vector<std::string> bytes_to_vec(const std::string& bytes) {
  std::vector<std::string> out;
  size_t start = 0;
  while (true) {
    const size_t nul = bytes.find('\0', start);
    if (nul == std::string::npos) {
      out.push_back(bytes.substr(start));
      break;
    }
    out.push_back(bytes.substr(start, nul - start));
    start = nul + 1;
  }
  return out;
}

uint64_t millis_since_unix_epoch() {
  const auto now = std::chrono::system_clock::now();
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch())
          .count());
}

uint64_t u64_from_bytes(const std::string& bytes) {
  uint64_t number = 0;
  for (const char b : bytes) number = (number << 8) | static_cast<unsigned char>(b);
  return number;
}

std::string increment(const std::optional<std::string>& old) {
  const uint64_t number = (old ? u64_from_bytes(*old) : 0) + 1;
  std::string out(8, '\0');
  for (int i = 0; i < 8; ++i) {
    out[static_cast<size_t>(i)] =
        static_cast<char>((number >> ((7 - i) * 8)) & 0xFF);
  }
  return out;
}

// pub fn random_string(length: usize) -> String — alphanumeric.
std::string random_string(size_t length) {
  static const char* kAlphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  thread_local std::mt19937_64 rng{std::random_device{}()};
  std::uniform_int_distribution<size_t> dist(0, 63);
  std::string out;
  out.reserve(length);
  for (size_t i = 0; i < length; ++i) {
    // Sample like upstream; wrap keeps distribution uniform over 64 chars.
    out.push_back(kAlphabet[dist(rng)]);
  }
  return out;
}

/// Calculate a new hash for the given password.
/// pub fn calculate_hash(password: &str) -> Result<String, argon2::Error>
/// Config { variant: Variant::Argon2id, ..Default::default() } — i.e.
/// m=4096 KiB, t=2, p=1, hash_len=32, salt as given (32 random chars).
std::optional<std::string> calculate_hash(const std::string& password) {
  const uint32_t t_cost = 2;
  const uint32_t m_cost = 1 << 12;  // KiB
  const uint32_t lanes = 1;
  const std::string salt = random_string(32);

  size_t encoded_len = argon2_encodedlen(t_cost, m_cost, lanes,
                                         static_cast<const uint32_t>(salt.size()),
                                         32, Argon2_id);
  std::string encoded(encoded_len, '\0');

  const int rc = argon2id_hash_encoded(
      t_cost, m_cost, lanes,
      password.data(), password.size(),
      salt.data(), salt.size(),
      32,                      // hash length
      encoded.data(), encoded.size());
  if (rc != ARGON2_OK) return std::nullopt;

  // Trim trailing NUL padding from the fixed-size buffer.
  encoded.resize(std::strlen(encoded.c_str()));
  return encoded;
}

}  // namespace utils
