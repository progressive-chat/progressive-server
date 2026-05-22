#pragma once
#include <cstdint>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace progressive::util {

std::string random_token(size_t length = 32);
std::string random_string(size_t length);
uint64_t random_uint64();

}  // namespace progressive::util
