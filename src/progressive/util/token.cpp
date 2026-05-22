#include "token.hpp"

#include "random.hpp"

namespace progressive::util {

std::string generate_access_token() {
  return "syt_" + random_token(64);
}

std::string generate_event_id(std::string_view origin) {
  return "$" + random_token(43) + ":" + std::string(origin);
}

}  // namespace progressive::util
