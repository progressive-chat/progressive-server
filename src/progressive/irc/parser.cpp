#include "parser.hpp"

#include <sstream>

namespace progressive::irc {

IrcMessage IrcMessage::parse(std::string_view line) {
  IrcMessage msg;
  size_t pos = 0;

  // Strip \r\n
  while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
    line.remove_suffix(1);

  // Parse prefix
  if (!line.empty() && line[0] == ':') {
    auto space = line.find(' ');
    if (space != std::string_view::npos) {
      msg.prefix = std::string(line.substr(1, space - 1));
      line.remove_prefix(space + 1);
    }
  }

  // Parse command
  auto space = line.find(' ');
  if (space == std::string_view::npos) {
    msg.command = std::string(line);
    return msg;
  }
  msg.command = std::string(line.substr(0, space));
  line.remove_prefix(space + 1);

  // Parse params
  while (!line.empty()) {
    if (line[0] == ':') {
      msg.trailing = std::string(line.substr(1));
      break;
    }
    auto sp = line.find(' ');
    if (sp == std::string_view::npos) {
      msg.params.push_back(std::string(line));
      break;
    }
    msg.params.push_back(std::string(line.substr(0, sp)));
    line.remove_prefix(sp + 1);
  }

  return msg;
}

std::string IrcMessage::to_string() const {
  std::stringstream ss;
  if (!prefix.empty())
    ss << ':' << prefix << ' ';
  ss << command;
  for (auto& p : params)
    ss << ' ' << p;
  if (!trailing.empty())
    ss << " :" << trailing;
  ss << "\r\n";
  return ss.str();
}

}  // namespace progressive::irc
