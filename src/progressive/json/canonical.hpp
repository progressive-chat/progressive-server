#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

namespace progressive::json {

std::string canonical_json(const nlohmann::json& value);
nlohmann::json parse(std::string_view raw);

}  // namespace progressive::json
