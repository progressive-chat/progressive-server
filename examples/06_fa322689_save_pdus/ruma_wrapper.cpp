#include "ruma_wrapper.hpp"

#include <cctype>
#include <stdexcept>

namespace ruma {

const char* errcode(ErrorKind kind) {
  switch (kind) {
    case ErrorKind::InvalidUsername: return "M_INVALID_USERNAME";
    case ErrorKind::UserInUse: return "M_USER_IN_USE";
    case ErrorKind::Forbidden: return "M_FORBIDDEN";
    case ErrorKind::Unknown: return "M_UNKNOWN";
    case ErrorKind::NotFound: return "M_NOT_FOUND";
    case ErrorKind::MissingToken: return "M_MISSING_TOKEN";
    case ErrorKind::UnknownToken: return "M_UNKNOWN_TOKEN";
  }
  return "M_UNKNOWN";
}

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
  std::string out;
  ++i;
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

// NEW in c2c18b46: capture the raw text of a non-string value so callers can
// descend into nested objects (login's identifier).
std::string parse_raw_value(const std::string& s, size_t& i) {
  const size_t start = i;
  size_t depth = 0;
  bool in_string = false;
  while (i < s.size()) {
    const char c = s[i];
    if (in_string) {
      if (c == '\\') {
        ++i;
      } else if (c == '"') {
        in_string = false;
      }
    } else if (c == '"') {
      in_string = true;
    } else if (c == '{' || c == '[') {
      ++depth;
    } else if (c == '}' || c == ']') {
      if (depth-- == 0) break;  // closing brace of the enclosing object
    } else if (c == ',' && depth == 0) {
      break;
    }
    ++i;
  }
  return s.substr(start, i - start);
}

}  // namespace

JsonObject JsonObject::parse(const std::string& body) {
  JsonObject obj;
  size_t i = 0;
  if (!consume(body, i, '{')) return obj;

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
      obj.raw_values_[key] = parse_raw_value(body, i);
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

JsonObject JsonObject::object(const std::string& key) const {
  const auto it = raw_values_.find(key);
  if (it == raw_values_.end()) return JsonObject{};
  return JsonObject::parse(it->second);
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

// NEW: login deserialization. Old ruma flattened UserInfo into the request
// ("type":"m.id.user","user":"neo"); modern clients send it under
// "identifier". Both are accepted, preferring the legacy flat form like the
// original did.
template <>
Ruma<LoginRequest> Ruma<LoginRequest>::from_body(const std::string& body) {
  const JsonObject json = JsonObject::parse(body);
  LoginRequest req;

  const auto flat_type = json.string("type");
  const auto flat_user = json.string("user");
  if (flat_user && flat_type && *flat_type == "m.id.user") {
    req.user_is_matrix_id = true;
    req.user_localpart = flat_user;
  } else {
    const JsonObject ident = json.object("identifier");
    const auto id_type = ident.string("type");
    const auto id_user = ident.string("user");
    if (id_type && *id_type == "m.id.user" && id_user) {
      req.user_is_matrix_id = true;
      req.user_localpart = id_user;
    } else {
      // A non-MatrixId variant — falls through to "Bad login type."
      req.user_is_matrix_id = false;
    }
  }

  req.password = json.string("password");
  req.device_id = json.string("device_id");

  Ruma<LoginRequest> wrapper;
  wrapper.value = std::move(req);
  return wrapper;
}

template <>
Ruma<JoinRoomByIdRequest> Ruma<JoinRoomByIdRequest>::from_body(const std::string&) {
  Ruma<JoinRoomByIdRequest> wrapper;
  return wrapper;
}

template <>
Ruma<CreateMessageEventRequest> Ruma<CreateMessageEventRequest>::from_body(
    const std::string& body) {
  Ruma<CreateMessageEventRequest> wrapper;
  wrapper.value.content_json = body;
  return wrapper;
}

}  // namespace ruma

// NEW in fa322689: /sync has no body to parse (query params ignored upstream).
template <>
ruma::Ruma<ruma::SyncRequest> ruma::Ruma<ruma::SyncRequest>::from_body(const std::string&) {
  Ruma<SyncRequest> wrapper;
  return wrapper;
}
