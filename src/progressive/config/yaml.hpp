#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

namespace progressive::config {

nlohmann::json parse_yaml(std::string_view input);
nlohmann::json load_config_file(std::string_view path);

}  // namespace progressive::config
