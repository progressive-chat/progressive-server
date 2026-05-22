#include "time.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace progressive::util {

uint64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string iso8601() {
  auto now = std::chrono::system_clock::now();
  auto tt = std::chrono::system_clock::to_time_t(now);
  auto ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
  std::stringstream ss;
  ss << std::put_time(std::gmtime(&tt), "%Y-%m-%dT%H:%M:%S") << '.' << std::setw(3)
     << std::setfill('0') << ms << 'Z';
  return ss.str();
}

uint64_t parse_iso8601(std::string_view s) {
  std::tm tm{};
  int ms = 0;
  std::istringstream ss{std::string(s)};
  ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
  if (s[s.size() - 1] == 'Z') {
    auto dot = s.find('.');
    if (dot != std::string_view::npos)
      ms = std::stoi(std::string(s.substr(dot + 1)));
  }
  auto tp = std::chrono::system_clock::from_time_t(timegm(&tm));
  return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count() + ms;
}

}  // namespace progressive::util
