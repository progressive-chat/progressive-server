#pragma once
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

namespace progressive::log {

inline void info(std::string_view tag, std::string_view msg) {
  std::cerr << "[" << tag << "] " << msg << "\n";
}
inline void warn(std::string_view tag, std::string_view msg) {
  std::cerr << "[" << tag << "] WARN " << msg << "\n";
}
inline void error(std::string_view tag, std::string_view msg) {
  std::cerr << "[" << tag << "] ERROR " << msg << "\n";
}

}  // namespace progressive::log
