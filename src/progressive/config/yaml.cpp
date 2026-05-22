#include "yaml.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace progressive::config {

static std::string trim(std::string_view s) {
  size_t start = 0, end = s.size();
  while (start < end && (s[start] == ' ' || s[start] == '\t'))
    start++;
  while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t'))
    end--;
  return std::string(s.substr(start, end - start));
}

static bool is_comment_or_empty(std::string_view line) {
  auto t = trim(line);
  return t.empty() || t[0] == '#';
}

static int indent_level(std::string_view line) {
  int n = 0;
  for (char c : line) {
    if (c == ' ')
      n++;
    else if (c == '\t')
      n += 2;
    else
      break;
  }
  return n;
}

static std::string unquote(std::string_view s) {
  if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
    return std::string(s.substr(1, s.size() - 2));
  if (s.size() >= 2 && s.front() == '\'' && s.back() == '\'')
    return std::string(s.substr(1, s.size() - 2));
  return std::string(s);
}

static nlohmann::json parse_value(std::string_view val) {
  auto t = trim(val);
  if (t == "true" || t == "True" || t == "TRUE" || t == "yes")
    return true;
  if (t == "false" || t == "False" || t == "FALSE" || t == "no")
    return false;
  if (t == "null" || t == "~")
    return nullptr;
  if ((t.front() == '"' && t.back() == '"') || (t.front() == '\'' && t.back() == '\''))
    return unquote(t);
  bool is_num = true, has_dot = false;
  for (size_t i = 0; i < t.size(); i++) {
    char c = t[i];
    if (c == '.' && !has_dot) {
      has_dot = true;
      continue;
    }
    if (c == '-' && i == 0)
      continue;
    if (c < '0' || c > '9') {
      is_num = false;
      break;
    }
  }
  if (is_num && !t.empty()) {
    try {
      if (has_dot)
        return std::stod(std::string(t));
      return std::stoll(std::string(t));
    } catch (...) {
    }
  }
  return std::string(t);
}

nlohmann::json parse_yaml(std::string_view input) {
  std::vector<std::string> lines;
  std::istringstream ss{std::string(input)};
  std::string line;
  while (std::getline(ss, line)) {
    if (!is_comment_or_empty(line))
      lines.push_back(line);
  }
  if (lines.empty())
    return nlohmann::json::object();

  std::string first = trim(lines[0]);
  if (first[0] == '{' || first[0] == '[')
    return nlohmann::json::parse(input);

  // Stack of (indent, json*) — json* points to the currently active
  // container (object or array) that new keys/items go into.
  struct Frame {
    int indent;
    nlohmann::json* node;
  };

  nlohmann::json root = nlohmann::json::object();
  std::vector<Frame> stack = {{-1, &root}};

  for (size_t i = 0; i < lines.size(); i++) {
    auto& raw = lines[i];
    int indent = indent_level(raw);
    std::string content = trim(raw);

    // Pop stack to the parent that has strictly lower indent
    while (stack.size() > 1 && stack.back().indent >= indent)
      stack.pop_back();

    auto* parent = stack.back().node;

    // List item: "- key: value", "- value", or "- nested"
    if (content.starts_with("- ")) {
      std::string rest = trim(content.substr(2));

      // Ensure parent is an array
      if (!parent->is_array())
        *parent = nlohmann::json::array();

      auto colon = rest.find(':');
      if (colon != std::string::npos) {
        std::string key = trim(rest.substr(0, colon));
        key = unquote(key);
        std::string val = trim(rest.substr(colon + 1));

        nlohmann::json item;
        if (val.empty()) {
          item = nlohmann::json::object();
          parent->push_back(item);
          // Push the new object so subsequent indented lines go into it
          stack.push_back({indent, &parent->back()});
          if (!key.empty() && key != "-") {
            // The "- key:" form — we pushed the object, now we need
            // to process this as a nested key with empty value
            // But the object was already pushed. We need to set up the
            // nesting correctly. For "- key:\n  sub: val" pattern,
            // the key is the outer list item's key to the nested object.
            // Simplified: just push the object frame.
          }
        } else {
          item[key] = parse_value(val);
          parent->push_back(item);
          // Push the item so subsequent keys at deeper indent go into it
          stack.push_back({indent, &parent->back()});
        }
      } else {
        // Simple scalar list item: "- value"
        parent->push_back(parse_value(rest));
      }
      continue;
    }

    // Key: value or Key:
    auto colon = content.find(':');
    if (colon == std::string::npos)
      continue;

    std::string key = trim(content.substr(0, colon));
    key = unquote(key);
    std::string val = trim(content.substr(colon + 1));

    if (val.empty()) {
      // Nested: check if next line starts with "- "
      bool is_list = false;
      if (i + 1 < lines.size())
        is_list = trim(lines[i + 1]).starts_with("- ");

      if (is_list) {
        (*parent)[key] = nlohmann::json::array();
        stack.push_back({indent, &(*parent)[key]});
      } else {
        (*parent)[key] = nlohmann::json::object();
        stack.push_back({indent, &(*parent)[key]});
      }
    } else {
      (*parent)[key] = parse_value(val);
    }
  }

  return root;
}

nlohmann::json load_config_file(std::string_view path) {
  std::ifstream f{std::string(path)};
  if (!f)
    throw std::runtime_error("cannot open config: " + std::string(path));
  std::stringstream ss;
  ss << f.rdbuf();
  return parse_yaml(ss.str());
}

}  // namespace progressive::config
