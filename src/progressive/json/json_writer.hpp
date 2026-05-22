#pragma once
#include <string>
#include <string_view>
#include <nlohmann/json.hpp>

namespace progressive::json {

std::string encode_canonical(const nlohmann::json& value);

}
