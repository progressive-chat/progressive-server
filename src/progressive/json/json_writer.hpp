#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

namespace progressive::json {

std::string encode_canonical(const nlohmann::json& value);

}
