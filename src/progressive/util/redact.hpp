#pragma once
#include <string>
#include <string_view>

namespace progressive::util {

inline std::string redact_token(std::string_view token) {
  if (token.size() <= 8)
    return std::string(token);
  return std::string(token.substr(0, 4)) + "..." + std::string(token.substr(token.size() - 4));
}

inline std::string redact_password(std::string_view pw) {
  return "[REDACTED-" + std::to_string(pw.size()) + "chars]";
}

}  // namespace progressive::util
