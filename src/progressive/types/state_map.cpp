#include "state_map.hpp"

#include <sstream>

namespace progressive {

StreamToken StreamToken::from_string(std::string_view s) {
  StreamToken tok;
  // format: s{rk}_{pk}_{tk}_{rek}
  size_t pos = 0;
  auto next = [&]() -> std::string {
    auto u = s.find('_', pos);
    if (u == std::string_view::npos)
      u = s.size();
    auto v = std::string(s.substr(pos, u - pos));
    pos = u + 1;
    return v;
  };
  if (pos < s.size() && s[pos] == 's') {
    pos++;
    tok.room_key = next();
  } else
    tok.room_key = next();
  tok.presence_key = std::stoull(next());
  tok.typing_key = std::stoull(next());
  tok.receipt_key = std::stoull(next());
  return tok;
}

std::string StreamToken::to_string() const {
  std::stringstream ss;
  ss << 's' << room_key << '_' << presence_key << '_' << typing_key << '_' << receipt_key;
  return ss.str();
}

}  // namespace progressive
