#include "utils.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace progressive::push {

static std::string regex_escape(std::string_view s) {
  std::string out;
  for (char c : s) {
    if (c == '.' || c == '+' || c == '*' || c == '?' || c == '[' || c == ']' || c == '(' ||
        c == ')' || c == '{' || c == '}' || c == '^' || c == '$' || c == '|' || c == '\\')
      out += '\\';
    out += c;
  }
  return out;
}

std::string glob_to_regex(std::string_view glob, GlobMatchType type) {
  std::string re_str;
  size_t pos = 0;

  while (pos < glob.size()) {
    // Find runs of literal chars
    size_t lit_end = pos;
    while (lit_end < glob.size() && glob[lit_end] != '*' && glob[lit_end] != '?')
      lit_end++;

    if (lit_end > pos) {
      re_str += regex_escape(glob.substr(pos, lit_end - pos));
      pos = lit_end;
    }

    // Find runs of wildcards
    size_t wc_end = pos;
    int qmarks = 0;
    bool has_star = false;
    while (wc_end < glob.size() && (glob[wc_end] == '*' || glob[wc_end] == '?')) {
      if (glob[wc_end] == '?')
        qmarks++;
      if (glob[wc_end] == '*')
        has_star = true;
      wc_end++;
    }

    if (wc_end > pos) {
      if (has_star) {
        re_str += ".*";
      } else {
        for (int i = 0; i < qmarks; i++)
          re_str += '.';
      }
      pos = wc_end;
    }
  }

  std::string anchored;
  if (type == GlobMatchType::Whole) {
    anchored = "^" + re_str + "$";
  } else {
    anchored = "(?:^|\\b|\\W)" + re_str + "(?:\\b|\\W|$)";
  }

  return anchored;
}

Matcher::Matcher(std::string_view pattern, GlobMatchType type) : type_(type) {
  // Check if pattern has wildcards
  bool has_wc =
      (pattern.find('*') != std::string_view::npos || pattern.find('?') != std::string_view::npos);

  if (has_wc) {
    is_literal_ = false;
    is_regex_ = true;
    regex_ = std::regex(glob_to_regex(pattern, type), std::regex_constants::icase);
  } else {
    is_literal_ = true;
    is_regex_ = false;
    literal_ = std::string(pattern);
    std::transform(literal_.begin(), literal_.end(), literal_.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (type_ == GlobMatchType::Word) {
      // Need regex for word boundary checking
      is_regex_ = true;
      regex_ =
          std::regex(glob_to_regex(literal_, GlobMatchType::Word), std::regex_constants::icase);
    }
  }
}

bool Matcher::is_match(std::string_view haystack) const {
  std::string lower(haystack);
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  if (is_literal_ && type_ == GlobMatchType::Whole) {
    return lower == literal_;
  }

  if (is_literal_ && type_ == GlobMatchType::Word) {
    // Fast path: substring check
    if (lower.find(literal_) == std::string::npos)
      return false;
    // Word boundary check
    return std::regex_search(lower, regex_);
  }

  if (is_regex_) {
    return std::regex_search(lower, regex_);
  }

  return false;
}

std::string get_localpart_from_id(std::string_view id) {
  if (id.empty())
    return {};
  auto colon = id.find(':');
  if (colon == std::string_view::npos)
    return std::string(id.substr(1));
  return std::string(id.substr(1, colon - 1));
}

std::map<std::string, JsonValue> flatten_event(const nlohmann::json& event) {
  std::map<std::string, JsonValue> result;

  std::function<void(const nlohmann::json&, std::string)> flatten = [&](const nlohmann::json& obj,
                                                                        std::string prefix) {
    if (obj.is_object()) {
      for (auto& [k, v] : obj.items()) {
        std::string escaped;
        for (char c : k) {
          if (c == '.')
            escaped += "\\.";
          else if (c == '\\')
            escaped += "\\\\";
          else
            escaped += c;
        }
        std::string key = prefix.empty() ? escaped : prefix + "." + escaped;
        flatten(v, key);
      }
    } else if (obj.is_string()) {
      result[prefix] = SimpleJsonValue(obj.get<std::string>());
    } else if (obj.is_number_integer()) {
      result[prefix] = SimpleJsonValue(obj.get<int64_t>());
    } else if (obj.is_boolean()) {
      result[prefix] = SimpleJsonValue(obj.get<bool>());
    } else if (obj.is_null()) {
      result[prefix] = SimpleJsonValue(nullptr);
    } else if (obj.is_array()) {
      std::vector<SimpleJsonValue> arr;
      for (auto& v : obj) {
        if (v.is_string())
          arr.push_back(v.get<std::string>());
        else if (v.is_number_integer())
          arr.push_back(v.get<int64_t>());
        else if (v.is_boolean())
          arr.push_back(v.get<bool>());
      }
      if (!arr.empty())
        result[prefix] = arr;
    }
  };

  flatten(event, "");
  return result;
}

}  // namespace progressive::push
