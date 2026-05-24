#pragma once
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace progressive::irc {

struct IrcMessage {
  std::string prefix;   // :server.name or :nick!user@host
  std::string command;  // NICK, USER, JOIN, PRIVMSG, etc.
  std::vector<std::string> params;
  std::string trailing;  // last param after :

  static IrcMessage parse(std::string_view line);
  std::string to_string() const;
};

class IrcSession {
public:
  IrcSession() = default;

  std::string nick;
  std::string user;
  std::string realname;
  std::string host;
  bool registered = false;
  bool password_ok = false;

  std::string id() const { return nick.empty() ? "(unknown)" : nick; }
};

class IrcChannel {
public:
  std::string name;
  std::string topic;
  std::map<std::string, bool, std::less<>> members;  // nick -> operator
};

}  // namespace progressive::irc
