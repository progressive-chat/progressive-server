#include "random.hpp"

#include <array>
#include <random>

namespace progressive::util {

static thread_local std::mt19937_64 rng(std::random_device{}());

std::string random_token(size_t length) {
  constexpr char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  std::uniform_int_distribution<size_t> dist(0, sizeof(chars) - 2);
  std::string out(length, '\0');
  for (size_t i = 0; i < length; i++)
    out[i] = chars[dist(rng)];
  return out;
}

std::string random_string(size_t length) {
  return random_token(length);
}

uint64_t random_uint64() {
  return rng();
}

}  // namespace progressive::util
