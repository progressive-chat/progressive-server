#include "json_value.hpp"

#include <cctype>
#include <cstdio>
#include <stdexcept>

namespace json {

namespace {

void skip_ws(const std::string& s, size_t& i) {
  while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
}

std::string parse_string(const std::string& s, size_t& i) {
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
        case 'u':
          if (i + 4 <= s.size()) {
            unsigned code = 0;
            for (int k = 0; k < 4; ++k) {
              const char h = s[i + static_cast<size_t>(k)];
              code <<= 4;
              if (h >= '0' && h <= '9') code |= static_cast<unsigned>(h - '0');
              else if (h >= 'a' && h <= 'f') code |= static_cast<unsigned>(h - 'a' + 10);
              else if (h >= 'A' && h <= 'F') code |= static_cast<unsigned>(h - 'A' + 10);
            }
            i += 4;
            // Encode as UTF-8 (BMP only — surrogate pairs left raw like step 1).
            if (code < 0x80) {
              out.push_back(static_cast<char>(code));
            } else if (code < 0x800) {
              out.push_back(static_cast<char>(0xC0 | (code >> 6)));
              out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            } else {
              out.push_back(static_cast<char>(0xE0 | (code >> 12)));
              out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
              out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            }
          }
          break;
        default: out.push_back(esc); break;
      }
    } else {
      out.push_back(c);
    }
  }
  throw std::runtime_error("unterminated JSON string");
}

}  // namespace

Value Value::parse_value(const std::string& s, size_t& i) {
  skip_ws(s, i);
  if (i >= s.size()) throw std::runtime_error("unexpected end of JSON");

  const char c = s[i];
  if (c == '{') {
    Object obj;
    ++i;
    skip_ws(s, i);
    if (i < s.size() && s[i] == '}') {
      ++i;
      return Value(std::move(obj));
    }
    while (true) {
      skip_ws(s, i);
      if (i >= s.size() || s[i] != '"') throw std::runtime_error("expected object key");
      const std::string key = parse_string(s, i);
      skip_ws(s, i);
      if (i >= s.size() || s[i] != ':') throw std::runtime_error("expected ':'");
      ++i;
      obj[key] = parse_value(s, i);
      skip_ws(s, i);
      if (i < s.size() && s[i] == ',') {
        ++i;
        continue;
      }
      if (i < s.size() && s[i] == '}') {
        ++i;
        break;
      }
      throw std::runtime_error("expected ',' or '}'");
    }
    return Value(std::move(obj));
  }

  if (c == '[') {
    Array arr;
    ++i;
    skip_ws(s, i);
    if (i < s.size() && s[i] == ']') {
      ++i;
      return Value(std::move(arr));
    }
    while (true) {
      arr.push_back(parse_value(s, i));
      skip_ws(s, i);
      if (i < s.size() && s[i] == ',') {
        ++i;
        continue;
      }
      if (i < s.size() && s[i] == ']') {
        ++i;
        break;
      }
      throw std::runtime_error("expected ',' or ']'");
    }
    return Value(std::move(arr));
  }

  if (c == '"') return Value(parse_string(s, i));

  if (s.compare(i, 4, "true") == 0) {
    i += 4;
    return Value(true);
  }
  if (s.compare(i, 5, "false") == 0) {
    i += 5;
    return Value(false);
  }
  if (s.compare(i, 4, "null") == 0) {
    i += 4;
    return Value(nullptr);
  }

  // Number
  char* end = nullptr;
  const double number = std::strtod(s.c_str() + i, &end);
  if (end == s.c_str() + i) throw std::runtime_error("invalid JSON value");
  i = static_cast<size_t>(end - s.c_str());
  return Value(number);
}

Value Value::parse(const std::string& text) {
  size_t i = 0;
  Value v = parse_value(text, i);
  return v;
}

void Value::dump(const Value& v, std::string& out) {
  struct NumberFormat {
    static void apply(double d, std::string& out) {
      char buf[32];
      if (d == static_cast<double>(static_cast<long long>(d)) &&
          d >= -9.0e15 && d <= 9.0e15) {
        std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(d));
      } else {
        std::snprintf(buf, sizeof(buf), "%.17g", d);
      }
      out += buf;
    }
  };

  if (std::holds_alternative<std::nullptr_t>(v.storage_)) {
    out += "null";
  } else if (const auto* b = std::get_if<bool>(&v.storage_)) {
    out += *b ? "true" : "false";
  } else if (const auto* d = std::get_if<double>(&v.storage_)) {
    NumberFormat::apply(*d, out);
  } else if (const auto* str = std::get_if<std::string>(&v.storage_)) {
    out.push_back('"');
    for (const char ch : *str) {
      switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
          if (static_cast<unsigned char>(ch) < 0x20) {
            char buf[7];
            std::snprintf(buf, sizeof(buf), "\\u%04x", ch);
            out += buf;
          } else {
            out.push_back(ch);
          }
      }
    }
    out.push_back('"');
  } else if (const auto* arr = std::get_if<Array>(&v.storage_)) {
    out.push_back('[');
    bool first = true;
    for (const auto& item : *arr) {
      if (!first) out.push_back(',');
      first = false;
      dump(item, out);
    }
    out.push_back(']');
  } else if (const auto* obj = std::get_if<Object>(&v.storage_)) {
    out.push_back('{');
    bool first = true;
    for (const auto& [key, value] : *obj) {  // sorted: canonical order
      if (!first) out.push_back(',');
      first = false;
      Value key_value(key);
      dump(key_value, out);
      out.push_back(':');
      dump(value, out);
    }
    out.push_back('}');
  }
}

std::string Value::canonical() const {
  std::string out;
  dump(*this, out);
  return out;
}

}  // namespace json
