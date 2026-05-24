#include "services.hpp"

#include "../util/time.hpp"

namespace progressive::irc {

bool IrcServices::register_nick(std::string_view nick, std::string_view password) {
  if (nick_passwords_.find(std::string(nick)) != nick_passwords_.end())
    return false;
  nick_passwords_[std::string(nick)] = std::string(password);
  return true;
}

bool IrcServices::identify_nick(std::string_view nick, std::string_view password) {
  auto it = nick_passwords_.find(std::string(nick));
  if (it == nick_passwords_.end())
    return false;
  return it->second == password;
}

bool IrcServices::register_channel(std::string_view channel, std::string_view founder) {
  if (channel_founders_.find(std::string(channel)) != channel_founders_.end())
    return false;
  channel_founders_[std::string(channel)] = std::string(founder);
  return true;
}

bool IrcServices::is_registered_nick(std::string_view nick) {
  return nick_passwords_.find(std::string(nick)) != nick_passwords_.end();
}

std::string IrcServices::get_founder(std::string_view channel) {
  auto it = channel_founders_.find(std::string(channel));
  return it != channel_founders_.end() ? it->second : "";
}

bool IrcServices::check_flood(std::string_view nick, int max_messages, int window_ms) {
  auto& fs = flood_states_[std::string(nick)];
  int64_t now = util::now_ms();

  if (fs.muted && now < fs.mute_until)
    return false;
  if (fs.muted && now >= fs.mute_until) {
    fs.muted = false;
    fs.messages = 0;
  }

  if (now - fs.window_start > window_ms) {
    fs.window_start = now;
    fs.messages = 0;
  }
  fs.messages++;
  if (fs.messages > max_messages) {
    fs.muted = true;
    fs.mute_until = now + 5000;
    return false;
  }
  return true;
}

}  // namespace progressive::irc
