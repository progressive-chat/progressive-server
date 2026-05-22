#pragma once
#include <map>
#include <nlohmann/json.hpp>
#include <regex>
#include <string>
#include <string_view>

#include "types.hpp"

namespace progressive::push {

enum class GlobMatchType { Whole, Word };

class Matcher {
public:
  Matcher(std::string_view pattern, GlobMatchType type);
  bool is_match(std::string_view haystack) const;

private:
  std::regex regex_;
  std::string literal_;
  GlobMatchType type_;
  bool is_literal_;
  bool is_regex_;
};

std::string glob_to_regex(std::string_view glob, GlobMatchType type);
std::string get_localpart_from_id(std::string_view id);

std::map<std::string, JsonValue> flatten_event(const nlohmann::json& event);

}  // namespace progressive::push
