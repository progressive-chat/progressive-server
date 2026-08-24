#include "utils.hpp"

#include <chrono>

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
  for (const char b : bytes) {
    number = (number << 8) | static_cast<unsigned char>(b);
  }
  return number;
}

std::string increment(const std::optional<std::string>& old) {
  const uint64_t number = (old ? utils::u64_from_bytes(*old) : 0) + 1;
  std::string out(8, '\0');
  for (int i = 0; i < 8; ++i) {
    out[static_cast<size_t>(i)] =
        static_cast<char>((number >> ((7 - i) * 8)) & 0xFF);
  }
  return out;
}

}  // namespace utils
