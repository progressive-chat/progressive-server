#pragma once
#include <string>
#include <string_view>

namespace progressive::util {

std::string generate_access_token();
std::string generate_event_id(std::string_view origin);

}  // namespace progressive::util
