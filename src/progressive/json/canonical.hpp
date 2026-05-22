#pragma once
#include <string>
#include <string_view>
#include <nlohmann/json.hpp>

namespace progressive::json {

std::string canonical_json(const nlohmann::json& value);
nlohmann::json parse(std::string_view raw);

}
