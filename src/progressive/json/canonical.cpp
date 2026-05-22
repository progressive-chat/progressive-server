#include "canonical.hpp"

#include <stdexcept>

namespace progressive::json {

std::string canonical_json(const nlohmann::json& value) {
  if (value.is_object()) {
    std::string out = "{";
    bool first = true;
    // nlohmann json objects are ordered by insertion; sort keys for canonical form
    std::map<std::string, nlohmann::json> sorted;
    for (auto& [k, v] : value.items())
      sorted[k] = v;
    for (auto& [k, v] : sorted) {
      if (!first)
        out += ",";
      out += nlohmann::json(k).dump() + ":" + canonical_json(v);
      first = false;
    }
    out += "}";
    return out;
  }
  if (value.is_array()) {
    std::string out = "[";
    bool first = true;
    for (auto& v : value) {
      if (!first)
        out += ",";
      out += canonical_json(v);
      first = false;
    }
    out += "]";
    return out;
  }
  if (value.is_string())
    return nlohmann::json(value.get<std::string>()).dump();
  if (value.is_boolean())
    return value.get<bool>() ? "true" : "false";
  if (value.is_number_integer())
    return std::to_string(value.get<int64_t>());
  if (value.is_number_float()) {
    double d = value.get<double>();
    if (d == 0.0)
      return "0";
    std::string s = std::to_string(d);
    s.erase(s.find_last_not_of('0') + 1, std::string::npos);
    if (s.back() == '.')
      s.pop_back();
    return s;
  }
  if (value.is_null())
    return "null";
  throw std::runtime_error("unexpected JSON type in canonical_json");
}

nlohmann::json parse(std::string_view raw) {
  return nlohmann::json::parse(raw);
}

}  // namespace progressive::json
