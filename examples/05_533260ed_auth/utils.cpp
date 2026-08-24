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

}  // namespace utils
