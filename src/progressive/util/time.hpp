#pragma once
#include <cstdint>
#include <string>

namespace progressive::util {

uint64_t now_ms();
std::string iso8601();
uint64_t parse_iso8601(std::string_view s);

}
