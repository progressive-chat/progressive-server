#include "ruma_wrapper.hpp"

#include <cctype>
#include <stdexcept>

namespace ruma {

namespace {

void skip_ws(const std::string& s, size_t& i) {
  while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
}

bool consume(const std::string& s, size_t& i, char c) {
  skip_ws(s, i);
  if (i < s.size() && s[i] == c) {
    ++i;
    return true;
  }
  return false;
}

std::string parse_string(const std::string& s, size_t& i) {
  // Assumes s[i] == '"'. Handles the common escapes; \uXXXX passes through raw
  // (good enough for a stub, wrong for production — see canonical JSON later).
  std::string out;
  ++i;  // opening quote
  while (i < s.size()) {
    const char c = s[i++];
    if (c == '"') return out;
    if (c == '\\' && i < s.size()) {
      const char esc = s[i++];
      switch (esc) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          if (i + 4 <= s.size()) {
            out.append(s.substr(i - 2, 6));
            i += 4;
          }
          break;
        }
        default: out.push_back(esc); break;
      }
    } else {
      out.push_back(c);
    }
  }
  throw std::runtime_error("unterminated JSON string");
}

}  // namespace

JsonObject JsonObject::parse(const std::string& body) {
  JsonObject obj;
  size_t i = 0;
  if (!consume(body, i, '{')) return obj;  // empty/invalid body -> empty object

  if (consume(body, i, '}')) return obj;

  while (true) {
    skip_ws(body, i);
    if (i >= body.size() || body[i] != '"') break;
    const std::string key = parse_string(body, i);
    if (!consume(body, i, ':')) break;

    skip_ws(body, i);
    if (i < body.size() && body[i] == '"') {
      obj.fields_[key] = parse_string(body, i);
    } else {
      // Non-string value (numbers, booleans, nested objects like `auth`).
      // Skip it — step 1 only reads string fields.
      size_t depth = 0;
      while (i < body.size()) {
        const char c = body[i];
        if (c == '{' || c == '[') ++depth;
        if (c == '}' || c == ']') {
          if (depth == 0) break;
          --depth;
        }
        if (depth == 0 && (c == ',')) break;
        ++i;
      }
    }

    if (consume(body, i, ',')) continue;
    consume(body, i, '}');
    break;
  }
  return obj;
}

std::optional<std::string> JsonObject::string(const std::string& key) const {
  const auto it = fields_.find(key);
  if (it == fields_.end()) return std::nullopt;
  return it->second;
}

template <>
Ruma<RegisterRequest> Ruma<RegisterRequest>::from_body(const std::string& body) {
  const JsonObject json = JsonObject::parse(body);
  RegisterRequest req;
  req.username = json.string("username");
  req.password = json.string("password");
  req.device_id = json.string("device_id");
  Ruma<RegisterRequest> wrapper;
  wrapper.value = std::move(req);
  return wrapper;
}

}  // namespace ruma
