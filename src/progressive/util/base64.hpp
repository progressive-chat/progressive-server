#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace base64 {

constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline std::string encode(std::string_view data) {
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  for (size_t i = 0; i < data.size(); i += 3) {
    uint32_t n = (uint32_t)(uint8_t)data[i] << 16;
    if (i + 1 < data.size())
      n |= (uint32_t)(uint8_t)data[i + 1] << 8;
    if (i + 2 < data.size())
      n |= (uint32_t)(uint8_t)data[i + 2];
    int pads = (i + 1 >= data.size()) ? 2 : ((i + 2 >= data.size()) ? 1 : 0);
    out += alphabet[(n >> 18) & 63];
    out += alphabet[(n >> 12) & 63];
    out += (pads == 2) ? '=' : alphabet[(n >> 6) & 63];
    out += (pads >= 1) ? '=' : alphabet[n & 63];
  }
  return out;
}

inline std::vector<uint8_t> decode(std::string_view data) {
  std::vector<uint8_t> out;
  out.reserve((data.size() + 3) / 4 * 3);
  auto idx = [](char c) -> uint8_t {
    if (c >= 'A' && c <= 'Z')
      return c - 'A';
    if (c >= 'a' && c <= 'z')
      return c - 'a' + 26;
    if (c >= '0' && c <= '9')
      return c - '0' + 52;
    if (c == '+')
      return 62;
    if (c == '/')
      return 63;
    throw std::runtime_error("invalid base64 char");
  };
  for (size_t i = 0; i < data.size();) {
    uint32_t n = 0;
    int pads = 0;
    for (int j = 0; j < 4 && i < data.size(); j++, i++) {
      if (data[i] == '=') {
        pads++;
        continue;
      }
      n |= idx(data[i]) << (6 * (3 - j));
    }
    out.push_back((n >> 16) & 0xFF);
    if (pads < 2)
      out.push_back((n >> 8) & 0xFF);
    if (pads < 1)
      out.push_back(n & 0xFF);
  }
  return out;
}

}  // namespace base64
