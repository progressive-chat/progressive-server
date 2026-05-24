#pragma once
#include <map>
#include <set>
#include <string>
#include <string_view>

namespace progressive::irc {

struct IrcFloodState {
  int messages = 0;
  int64_t window_start = 0;
  bool muted = false;
  int64_t mute_until = 0;
};

class IrcServices {
public:
  bool register_nick(std::string_view nick, std::string_view password);
  bool identify_nick(std::string_view nick, std::string_view password);
  bool register_channel(std::string_view channel, std::string_view founder);
  bool is_registered_nick(std::string_view nick);
  std::string get_founder(std::string_view channel);

  bool check_flood(std::string_view nick, int max_messages = 5, int window_ms = 3000);

private:
  std::map<std::string, std::string, std::less<>> nick_passwords_;
  std::map<std::string, std::string, std::less<>> channel_founders_;
  std::map<std::string, IrcFloodState, std::less<>> flood_states_;
};

struct IrcCap {
  std::set<std::string> requested;
  std::set<std::string> enabled;
  bool negotiation = false;
  bool done = false;

  static constexpr const char* supported[] = {"server-time", "message-tags", "echo-message",
                                              "sasl",        "multi-prefix", "away-notify",
                                              "account-tag"};
};

}  // namespace progressive::irc
