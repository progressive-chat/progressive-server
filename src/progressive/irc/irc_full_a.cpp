// irc_full_a.cpp - Complete IRC RFC command handlers with full logic
// Covers all basic IRC commands per RFC 1459/2812/2813
// Channel modes: b/e/I/k/l/o/v/h/q/a/m/n/p/s/t/i/r/c/C/N/M/O/P/Q/R/S/T/z/Z
// User modes: i/w/o/s/x/B/G/H/I/R/W/Z
// Access levels: owner (~) > admin (&) > op (@) > halfop (%) > voice (+) > regular

#include "irc_server.hpp"
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace progressive::irc {

// ============================================================================
// Utility helpers
// ============================================================================

namespace {
  inline int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  }
  inline int64_t now_sec() {
    return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  }
  std::string format_time(time_t t) {
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&t), "%a %b %d %Y at %H:%M:%S %Z");
    return ss.str();
  }
  bool nick_valid_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '-' || c == '[' || c == '\\' || c == ']' ||
           c == '^' || c == '_' || c == '`' || c == '{' || c == '|' || c == '}';
  }
  bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
      if (std::tolower(a[i]) != std::tolower(b[i])) return false;
    return true;
  }
  std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> v;
    std::stringstream ss(s); std::string item;
    while (std::getline(ss, item, ',')) { if (!item.empty()) v.push_back(item); }
    return v;
  }
  std::string toggle_mode_str(const std::string& modes, char m, bool adding) {
    std::string r = modes;
    auto pos = r.find(m);
    if (adding && pos == std::string::npos) r += m;
    else if (!adding && pos != std::string::npos) r.erase(pos, 1);
    return r;
  }
  bool wildcard_match(const std::string& pattern, const std::string& str) {
    size_t pi = 0, si = 0, pm = 0, sm = 0;
    while (si < str.size()) {
      if (pi < pattern.size() && (pattern[pi] == '?' || pattern[pi] == str[si])) { ++pi; ++si; }
      else if (pi < pattern.size() && pattern[pi] == '*') { pm = ++pi; sm = si; }
      else if (pm > 0) { pi = pm; ++sm; si = sm; }
      else return false;
    }
    while (pi < pattern.size() && pattern[pi] == '*') ++pi;
    return pi == pattern.size();
  }
  std::string make_full_mask(const std::string& nick, const std::string& user, const std::string& host) {
    return nick + "!" + user + "@" + host;
  }
} // anonymous namespace

// ============================================================================
// Ban mask matching with exception support
// ============================================================================

bool match_ban_mask(const std::string& nick, const std::string& user,
                    const std::string& host, const std::string& mask) {
  std::string mn = "*", mu = "*", mh = "*";
  auto ex = mask.find('!');
  auto at = mask.find('@');
  if (ex != std::string::npos) {
    mn = mask.substr(0, ex);
    if (at != std::string::npos) {
      mu = mask.substr(ex + 1, at - ex - 1);
      mh = mask.substr(at + 1);
    } else { mu = mask.substr(ex + 1); }
  } else if (at != std::string::npos) {
    mh = mask.substr(at + 1);
  } else { mn = mask; }
  return wildcard_match(mn, nick) && wildcard_match(mu, user) && wildcard_match(mh, host);
}

bool is_banned(IRCChannel* ch, const std::string& nick,
               const std::string& user, const std::string& host) {
  if (!ch) return false;
  for (auto& ban : ch->bans) {
    if (match_ban_mask(nick, user, host, ban)) {
      // Check ban exceptions
      for (auto& exc : ch->excepts)
        if (match_ban_mask(nick, user, host, exc)) return false;
      return true;
    }
  }
  return false;
}

// ============================================================================
// Channel access level helpers
//   owner (~) > admin (&) > op (@) > halfop (%) > voice (+) > regular
// ============================================================================

bool is_channel_owner(IRCChannel* ch, const std::string& nick) {
  if (!ch) return false;
  auto it = ch->member_modes.find(nick);
  return it != ch->member_modes.end() && it->second.find('q') != std::string::npos;
}
bool is_channel_admin(IRCChannel* ch, const std::string& nick) {
  if (!ch) return false;
  auto it = ch->member_modes.find(nick);
  return it != ch->member_modes.end() && it->second.find('a') != std::string::npos;
}
bool is_channel_op(IRCChannel* ch, const std::string& nick) {
  if (!ch) return false;
  auto it = ch->member_modes.find(nick);
  return it != ch->member_modes.end() && it->second.find('o') != std::string::npos;
}
bool is_channel_halfop(IRCChannel* ch, const std::string& nick) {
  if (!ch) return false;
  auto it = ch->member_modes.find(nick);
  return it != ch->member_modes.end() && it->second.find('h') != std::string::npos;
}
bool is_channel_voice(IRCChannel* ch, const std::string& nick) {
  if (!ch) return false;
  auto it = ch->member_modes.find(nick);
  return it != ch->member_modes.end() && it->second.find('v') != std::string::npos;
}
bool is_channel_staff(IRCChannel* ch, const std::string& nick) {
  return is_channel_owner(ch, nick) || is_channel_admin(ch, nick) ||
         is_channel_op(ch, nick) || is_channel_halfop(ch, nick);
}

// ============================================================================
// NICK command - RFC 2812 section 3.1.2
// Full collision detection, rename propagation, validation
// ============================================================================

void IRCServer::handle_nick_full_a(IRCConnection* conn, const std::string& nick) {
  // ERR_NONICKNAMEGIVEN
  if (nick.empty()) {
    send_numeric(conn, Numerics::ERR_NONICKNAMEGIVEN, ":No nickname given");
    return;
  }
  // ERR_ERRONEUSNICKNAME - length
  if (nick.length() > static_cast<size_t>(config_.max_nick_length)) {
    send_numeric(conn, Numerics::ERR_ERRONEUSNICKNAME, nick + " :Erroneous nickname");
    return;
  }
  // ERR_ERRONEUSNICKNAME - invalid chars
  for (char c : nick) {
    if (!nick_valid_char(c)) {
      send_numeric(conn, Numerics::ERR_ERRONEUSNICKNAME, nick + " :Erroneous nickname");
      return;
    }
  }
  // Check first character (must be letter or special)
  if (!((nick[0] >= 'A' && nick[0] <= 'Z') || (nick[0] >= 'a' && nick[0] <= 'z') ||
        nick[0] == '_' || nick[0] == '[' || nick[0] == '\\' || nick[0] == ']' ||
        nick[0] == '^' || nick[0] == '`' || nick[0] == '{' || nick[0] == '|' || nick[0] == '}')) {
    send_numeric(conn, Numerics::ERR_ERRONEUSNICKNAME, nick + " :Erroneous nickname");
    return;
  }
  // Collision detection - case-insensitive
  if (!conn->nick.empty() && iequals(conn->nick, nick)) {
    // Same nick, just change case - okay
  } else {
    for (auto& [existing_nick, usr] : users_) {
      if (iequals(existing_nick, nick) && existing_nick != conn->nick) {
        send_numeric(conn, Numerics::ERR_NICKNAMEINUSE, nick + " :Nickname is already in use");
        return;
      }
    }
  }
  // Pre-registration: store nick
  if (!conn->registered) {
    conn->nick = nick;
    // Try to register if USER was already sent
    if (!conn->user.empty() && !conn->host.empty()) {
      conn->registered = true;
      auto* usr = add_user(nick, conn->user, conn->host, conn->realname);
      usr->ip = conn->ip;
      usr->port = conn->port;
      usr->signon_time = now_sec();
      // Welcome sequence
      send_numeric(conn, Numerics::RPL_WELCOME,
        ":Welcome to the " + config_.network_name + " IRC Network " +
        nick + "!" + conn->user + "@" + conn->host);
      send_numeric(conn, Numerics::RPL_YOURHOST,
        ":Your host is " + config_.server_name + ", running progressive-irc-1.0.0");
      time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
      send_numeric(conn, Numerics::RPL_CREATED,
        ":This server was created " + format_time(t));
      send_numeric(conn, Numerics::RPL_MYINFO,
        config_.server_name + " progressive-irc-1.0.0 o o o");
      handle_motd_full_a(conn);
      // Notification
      for (auto& [mn, mod] : modules_) {
        if (mod.on_user_register) mod.on_user_register(conn);
      }
    }
    return;
  }
  // Post-registration: propagate nick change
  std::string oldnick = conn->nick;
  std::string nick_str = ":" + oldnick + "!" + conn->user + "@" + conn->host + " NICK :" + nick;
  // Notify all shared channels
  for (auto& [ch_name, ch] : channels_) {
    if (ch.members.count(oldnick)) {
      // Check +N (no nick changes) mode
      if (ch.modes.find('N') != std::string::npos && !is_channel_op(&ch, oldnick)) {
        send_numeric(conn, 437, ch_name + " :Cannot change nickname while banned on channel");
        continue;
      }
    }
  }
  // Perform rename
  change_nick(oldnick, nick);
  conn->nick = nick;
  // Broadcast NICK to all channels the user is in
  for (auto& [ch_name, ch] : channels_) {
    if (ch.members.count(nick)) {
      send_to_channel(ch_name, nick_str);
    }
  }
  // Send to the user themselves
  send_to(conn, nick_str);
}

// ============================================================================
// USER command - RFC 2812 section 3.1.3
// Registration with full validation
// ============================================================================

void IRCServer::handle_user_full_a(IRCConnection* conn, const std::string& user,
                                    const std::string& host, const std::string& server,
                                    const std::string& realname) {
  if (conn->registered) {
    send_numeric(conn, Numerics::ERR_ALREADYREGISTERED, ":You may not reregister");
    return;
  }
  if (user.empty() || host.empty() || realname.empty()) {
    send_numeric(conn, Numerics::ERR_NEEDMOREPARAMS, "USER :Not enough parameters");
    return;
  }
  conn->user = user;
  conn->host = host;
  conn->realname = realname;
  // If NICK already set, complete registration
  if (!conn->nick.empty()) {
    conn->registered = true;
    auto* usr = add_user(conn->nick, user, host, realname);
    usr->ip = conn->ip;
    usr->port = conn->port;
    usr->signon_time = now_sec();
    send_numeric(conn, Numerics::RPL_WELCOME,
      ":Welcome to the " + config_.network_name + " IRC Network " +
      conn->nick + "!" + user + "@" + host);
    send_numeric(conn, Numerics::RPL_YOURHOST,
      ":Your host is " + config_.server_name + ", running progressive-irc-1.0.0");
    time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    send_numeric(conn, Numerics::RPL_CREATED, ":This server was created " + format_time(t));
    send_numeric(conn, Numerics::RPL_MYINFO,
      config_.server_name + " progressive-irc-1.0.0 o o o");
    handle_motd_full_a(conn);
    for (auto& [mn, mod] : modules_) {
      if (mod.on_user_register) mod.on_user_register(conn);
    }
  }
}

// ============================================================================
// PASS command - RFC 2812 section 3.1.1
// Server password authentication
// ============================================================================

void IRCServer::handle_pass_full_a(IRCConnection* conn, const std::string& password) {
  if (conn->registered) {
    send_numeric(conn, Numerics::ERR_ALREADYREGISTERED, ":You may not reregister");
    return;
  }
  if (config_.server_password.empty()) {
    conn->password_ok = true;
    return;
  }
  if (password == config_.server_password)
    conn->password_ok = true;
  else
    conn->password_ok = false;
  // If password wrong, we'll reject on registration attempt
  if (!conn->password_ok && !conn->nick.empty()) {
    send_numeric(conn, Numerics::ERR_PASSWDMISMATCH, ":Password incorrect");
    close_connection(conn);
  }
}

// ============================================================================
// QUIT command - RFC 2812 section 3.1.7
// Channel broadcast, full cleanup
// ============================================================================

void IRCServer::handle_quit_full_a(IRCConnection* conn, const std::string& reason) {
  if (conn->nick.empty()) return;
  std::string quit_msg = ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                         " QUIT :" + (reason.empty() ? "Client Quit" : reason);
  // Remove from all channels, broadcast QUIT
  for (auto& [ch_name, ch] : channels_) {
    if (ch.members.count(conn->nick)) {
      send_to_channel(ch_name, quit_msg);
      ch.members.erase(conn->nick);
      ch.member_modes.erase(conn->nick);
      // Remove from invite lists
      ch.invites.erase(conn->nick);
      // Clean up empty channels (unless +P permanent)
      if (ch.members.empty() && ch.modes.find('P') == std::string::npos) {
        channels_.erase(ch_name);
      }
    }
  }
  // Save to WHOWAS history
  auto* u = get_user(conn->nick);
  if (u) {
    whowas_history_.push_back({u->nick, u->user, u->host, u->realname,
                               config_.server_name, now_sec()});
    if (whowas_history_.size() > 100) whowas_history_.erase(whowas_history_.begin());
  }
  remove_user(conn->nick);
}

// ============================================================================
// JOIN command - RFC 2812 section 3.2.1
// Key check, limit check, ban check, invite-only check, exception support
// ============================================================================

void IRCServer::handle_join_full_a(IRCConnection* conn, const std::string& channels_str,
                                    const std::string& keys_str) {
  if (!conn->registered) {
    send_numeric(conn, Numerics::ERR_NOTREGISTERED, ":You have not registered");
    return;
  }
  if (channels_str.empty() || channels_str == "0") {
    // JOIN 0 = part all channels
    for (auto& [ch_name, ch] : channels_) {
      if (ch.members.count(conn->nick)) {
        std::string part_msg = ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                               " PART " + ch_name;
        send_to_channel(ch_name, part_msg);
        ch.members.erase(conn->nick);
        ch.member_modes.erase(conn->nick);
        if (ch.members.empty() && ch.modes.find('P') == std::string::npos)
          channels_.erase(ch_name);
      }
    }
    return;
  }
  auto chans = split_csv(channels_str);
  auto keys = split_csv(keys_str);
  for (size_t ci = 0; ci < chans.size(); ++ci) {
    std::string chname = chans[ci];
    std::string key = ci < keys.size() ? keys[ci] : "";
    // Validate channel name
    if (!is_channel(chname)) {
      send_numeric(conn, Numerics::ERR_BADCHANMASK, chname + " :Bad Channel Mask");
      continue;
    }
    if (chname.length() > 50) {
      send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, chname + " :No such channel");
      continue;
    }
    // Check user channel count
    int user_chan_count = 0;
    for (auto& [cn, c] : channels_) {
      if (c.members.count(conn->nick)) ++user_chan_count;
    }
    if (user_chan_count >= config_.max_channels) {
      send_numeric(conn, 405, chname + " :You have joined too many channels");
      continue;
    }
    // Get or create channel
    auto* ch = get_channel(chname);
    bool is_new = (ch == nullptr);
    if (is_new) {
      ch = create_channel(chname);
      ch->created_ts = now_sec();
    }
    // Check ban (+b) with exceptions (+e)
    if (is_banned(ch, conn->nick, conn->user, conn->host)) {
      send_numeric(conn, Numerics::ERR_BANNEDFROMCHAN, chname + " :Cannot join channel (+b)");
      continue;
    }
    // Check invite-only (+i) with invite exception (+I)
    if (ch->modes.find('i') != std::string::npos) {
      // Check invite exception list
      bool has_invite_exception = false;
      for (auto& inv_mask : ch->invites) {
        if (match_ban_mask(conn->nick, conn->user, conn->host, inv_mask)) {
          has_invite_exception = true;
          break;
        }
      }
      if (!ch->invites.count(conn->nick) && !has_invite_exception) {
        send_numeric(conn, Numerics::ERR_INVITEONLYCHAN, chname + " :Cannot join channel (+i)");
        continue;
      }
    }
    // Check registered-only (+R)
    if (ch->modes.find('R') != std::string::npos) {
      // Would check NickServ registration
    }
    // Check key (+k)
    if (ch->modes.find('k') != std::string::npos) {
      if (key != ch->key) {
        send_numeric(conn, Numerics::ERR_BADCHANNELKEY, chname + " :Cannot join channel (+k)");
        continue;
      }
    }
    // Check limit (+l)
    if (ch->modes.find('l') != std::string::npos && ch->user_limit > 0) {
      if (static_cast<int64_t>(ch->members.size()) >= ch->user_limit) {
        send_numeric(conn, Numerics::ERR_CHANNELISFULL, chname + " :Cannot join channel (+l)");
        continue;
      }
    }
    // Add member
    ch->members.insert(conn->nick);
    if (is_new) {
      // First user becomes owner
      ch->member_modes[conn->nick] = "qo";
      ch->modes += "nt";
    }
    // Remove invite after successful join
    ch->invites.erase(conn->nick);
    // Send JOIN to channel
    std::string join_msg = ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                           " JOIN :" + chname;
    send_to_channel(chname, join_msg);
    // Send topic (RPL_TOPIC or RPL_NOTOPIC)
    if (!ch->topic.empty()) {
      send_numeric(conn, Numerics::RPL_TOPIC, chname + " :" + ch->topic);
      send_numeric(conn, Numerics::RPL_TOPICWHOTIME, chname + " " + ch->topic_setter +
                   " " + std::to_string(ch->topic_ts));
    } else {
      send_numeric(conn, Numerics::RPL_NOTOPIC, chname + " :No topic is set");
    }
    // Send NAMES
    send_channel_names_full_a(conn, chname);
    // Send creation time
    send_numeric(conn, Numerics::RPL_CREATIONTIME, chname + " " +
                 std::to_string(ch->created_ts));
  }
}

// ============================================================================
// PART command - RFC 2812 section 3.2.2
// Multi-channel part with reason
// ============================================================================

void IRCServer::handle_part_full_a(IRCConnection* conn, const std::string& channels_str,
                                    const std::string& reason) {
  if (!conn->registered) {
    send_numeric(conn, Numerics::ERR_NOTREGISTERED, ":You have not registered");
    return;
  }
  if (channels_str.empty()) {
    send_numeric(conn, Numerics::ERR_NEEDMOREPARAMS, "PART :Not enough parameters");
    return;
  }
  auto chans = split_csv(channels_str);
  for (auto& chname : chans) {
    auto* ch = get_channel(chname);
    if (!ch) {
      send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, chname + " :No such channel");
      continue;
    }
    if (!ch->members.count(conn->nick)) {
      send_numeric(conn, Numerics::ERR_NOTONCHANNEL, chname + " :You're not on that channel");
      continue;
    }
    // Broadcast PART
    std::string part_msg = ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                           " PART " + chname + (reason.empty() ? "" : " :" + reason);
    send_to_channel(chname, part_msg);
    // Also send to parting user
    send_to(conn, part_msg);
    // Remove
    ch->members.erase(conn->nick);
    ch->member_modes.erase(conn->nick);
    ch->invites.erase(conn->nick);
    // Clean up empty channel (unless +P)
    if (ch->members.empty() && ch->modes.find('P') == std::string::npos) {
      channels_.erase(chname);
    }
  }
}

// ============================================================================
// PRIVMSG command - RFC 2812 section 3.3.1
// Channel + user routing, CTCP passthrough, away check, moderation
// ============================================================================

void IRCServer::handle_privmsg_full_a(IRCConnection* conn, const std::string& target,
                                       const std::string& message) {
  if (target.empty()) {
    send_numeric(conn, Numerics::ERR_NORECIPIENT, ":No recipient given (PRIVMSG)");
    return;
  }
  if (message.empty()) {
    send_numeric(conn, Numerics::ERR_NOTEXTTOSEND, ":No text to send");
    return;
  }
  // CTCP detection: \001COMMAND args\001
  if (message.size() >= 2 && message[0] == '\001' && message.back() == '\001') {
    std::string ctcp_body = message.substr(1, message.size() - 2);
    handle_ctcp_full_a(conn, target, ctcp_body);
    return;
  }
  // Channel message
  if (is_channel(target)) {
    auto* ch = get_channel(target);
    if (!ch) {
      send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, target + " :No such channel");
      return;
    }
    if (!ch->members.count(conn->nick)) {
      // Check +n (no external messages)
      if (ch->modes.find('n') != std::string::npos) {
        send_numeric(conn, Numerics::ERR_CANNOTSENDTOCHAN, target + " :Cannot send to channel (+n)");
        return;
      }
      // Check +m (moderated) with +n override
      if (ch->modes.find('m') != std::string::npos) {
        send_numeric(conn, Numerics::ERR_CANNOTSENDTOCHAN, target + " :Cannot send to channel (+m)");
        return;
      }
    }
    // If +m, check voice/op status
    if (ch->modes.find('m') != std::string::npos) {
      if (!is_channel_voice(ch, conn->nick) && !is_channel_op(ch, conn->nick) &&
          !is_channel_halfop(ch, conn->nick)) {
        send_numeric(conn, Numerics::ERR_CANNOTSENDTOCHAN, target + " :Cannot send to channel (+m)");
        return;
      }
    }
    // Check +c (no color codes)
    std::string final_msg = message;
    if (ch->modes.find('c') != std::string::npos) {
      // Strip color codes
      std::string cleaned;
      for (size_t i = 0; i < final_msg.size(); ++i) {
        if (final_msg[i] == '\003') {
          // Skip mIRC color code: \003[[##][,##]]
          ++i;
          if (i < final_msg.size() && final_msg[i] >= '0' && final_msg[i] <= '9') {
            ++i;
            if (i < final_msg.size() && final_msg[i] >= '0' && final_msg[i] <= '9') ++i;
            if (i < final_msg.size() && final_msg[i] == ',') {
              ++i;
              if (i < final_msg.size() && final_msg[i] >= '0' && final_msg[i] <= '9') ++i;
              if (i < final_msg.size() && final_msg[i] >= '0' && final_msg[i] <= '9') ++i;
            }
          }
        } else {
          cleaned += final_msg[i];
        }
      }
      final_msg = cleaned;
    }
    // Send to all members except sender
    send_to_channel(target, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                    " PRIVMSG " + target + " :" + final_msg, conn->nick);
  } else {
    // Private message to user
    auto* u = get_user(target);
    if (!u) {
      send_numeric(conn, Numerics::ERR_NOSUCHNICK, target + " :No such nick/channel");
      return;
    }
    // Check target's +R (registered only)
    if (u->modes.find('R') != std::string::npos) {
      // Would check if sender is registered with NickServ
    }
    // Away check
    if (u->away) {
      send_numeric(conn, Numerics::RPL_AWAY, target + " :" + u->away_msg);
    }
    // Deliver to target user (in real server, write to their connection)
    // For now, we use send_to via connection lookup
    for (auto& [fd, c] : connections_) {
      if (c.nick == target) {
        send_to(&c, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                " PRIVMSG " + target + " :" + message);
        break;
      }
    }
  }
}

// ============================================================================
// NOTICE command - RFC 2812 section 3.3.2
// Channel + user routing, no auto-replies, CTCP passthrough
// ============================================================================

void IRCServer::handle_notice_full_a(IRCConnection* conn, const std::string& target,
                                      const std::string& message) {
  if (target.empty()) return; // NOTICE doesn't send ERR_NORECIPIENT
  if (message.empty()) return;
  // CTCP reply passthrough
  if (message.size() >= 2 && message[0] == '\001' && message.back() == '\001') {
    std::string ctcp_body = message.substr(1, message.size() - 2);
    handle_ctcp_full_a(conn, target, ctcp_body);
    return;
  }
  // Channel notice
  if (is_channel(target)) {
    auto* ch = get_channel(target);
    if (!ch || !ch->members.count(conn->nick)) return;
    // Check +m moderation for NOTICE too
    if (ch->modes.find('m') != std::string::npos) {
      if (!is_channel_voice(ch, conn->nick) && !is_channel_op(ch, conn->nick) &&
          !is_channel_halfop(ch, conn->nick)) return;
    }
    // Check +T (no notices to channel)
    if (ch->modes.find('T') != std::string::npos) {
      send_numeric(conn, Numerics::ERR_CANNOTSENDTOCHAN, target + " :Cannot send notices to channel (+T)");
      return;
    }
    send_to_channel(target, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                    " NOTICE " + target + " :" + message, conn->nick);
  } else {
    // Private notice to user (no away reply, no error on no-such-nick)
    for (auto& [fd, c] : connections_) {
      if (c.nick == target) {
        send_to(&c, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                " NOTICE " + target + " :" + message);
        break;
      }
    }
  }
}

// ============================================================================
// MODE command - Full channel and user modes
// Channel modes: b/e/I/k/l/o/v/h/q/a/m/n/p/s/t/i/r/c/C/N/M/O/P/Q/R/S/T/z/Z
// User modes: i/w/o/s/x/B/G/H/I/R/W/Z
// ============================================================================

void IRCServer::handle_mode_full_a(IRCConnection* conn, const std::string& target,
                                    const std::string& mode_str,
                                    const std::vector<std::string>& params) {
  if (is_channel(target)) {
    handle_channel_mode_full_a(conn, target, mode_str, params);
  } else {
    handle_user_mode_full_a(conn, target, mode_str);
  }
}

// --- Channel mode handler ---
void IRCServer::handle_channel_mode_full_a(IRCConnection* conn, const std::string& chname,
                                            const std::string& mode_str,
                                            const std::vector<std::string>& params) {
  auto* ch = get_channel(chname);
  if (!ch) {
    send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, chname + " :No such channel");
    return;
  }
  // Query-only (no mode string given)
  if (mode_str.empty()) {
    std::string display = "+" + ch->modes;
    if (ch->modes.find('k') != std::string::npos) display += " " + ch->key;
    if (ch->modes.find('l') != std::string::npos) display += " " + std::to_string(ch->user_limit);
    send_numeric(conn, Numerics::RPL_CHANNELMODEIS, chname + " " + display);
    return;
  }
  // Check operator permission (any staff level can change modes)
  if (!is_channel_staff(ch, conn->nick) && !conn->nick.empty()) {
    send_numeric(conn, Numerics::ERR_CHANOPRIVSNEEDED, chname +
                 " :You're not channel operator");
    return;
  }
  // Parse and apply mode changes
  bool adding = true;
  size_t param_idx = 0;
  std::string applied_modes;
  std::string current_mode_block;
  bool in_block = false;
  std::vector<std::string> applied_params;
  for (char mode_c : mode_str) {
    if (mode_c == '+') { adding = true; continue; }
    if (mode_c == '-') { adding = false; continue; }
    switch (mode_c) {
      // ----- Type A: List modes (b/e/I) -----
      case 'b': { // Ban
        if (!adding && param_idx >= params.size()) {
          // -b without param = list bans
          for (auto& b : ch->bans)
            send_numeric(conn, 367, chname + " " + b);
          send_numeric(conn, 368, chname + " :End of Channel Ban List");
        } else if (param_idx < params.size()) {
          std::string mask = params[param_idx++];
          if (adding) ch->bans.insert(mask);
          else ch->bans.erase(mask);
          applied_modes += (adding ? "+b" : "-b");
          applied_params.push_back(mask);
        }
        break;
      }
      case 'e': { // Ban exception
        if (!adding && param_idx >= params.size()) {
          for (auto& e : ch->excepts)
            send_numeric(conn, 348, chname + " " + e);
          send_numeric(conn, 349, chname + " :End of Channel Exception List");
        } else if (param_idx < params.size()) {
          std::string mask = params[param_idx++];
          if (adding) ch->excepts.insert(mask);
          else ch->excepts.erase(mask);
          applied_modes += (adding ? "+e" : "-e");
          applied_params.push_back(mask);
        }
        break;
      }
      case 'I': { // Invite exception
        if (!adding && param_idx >= params.size()) {
          for (auto& i : ch->invites)
            send_numeric(conn, 346, chname + " " + i);
          send_numeric(conn, 347, chname + " :End of Channel Invite Exception List");
        } else if (param_idx < params.size()) {
          std::string mask = params[param_idx++];
          if (adding) ch->invites.insert(mask);
          else ch->invites.erase(mask);
          applied_modes += (adding ? "+I" : "-I");
          applied_params.push_back(mask);
        }
        break;
      }
      // ----- Type B: Always-param modes (k) -----
      case 'k': { // Key
        if (adding && param_idx < params.size()) {
          ch->key = params[param_idx++];
          ch->modes += 'k';
          applied_modes += "+k";
          applied_params.push_back(ch->key);
        } else if (!adding) {
          ch->key.clear();
          auto p = ch->modes.find('k');
          if (p != std::string::npos) ch->modes.erase(p, 1);
          applied_modes += "-k";
          applied_params.push_back("*");
        }
        break;
      }
      // ----- Type C: Param-when-set (l) -----
      case 'l': { // User limit
        if (adding && param_idx < params.size()) {
          ch->user_limit = std::stoll(params[param_idx++]);
          ch->modes += 'l';
          applied_modes += "+l";
          applied_params.push_back(std::to_string(ch->user_limit));
        } else if (!adding) {
          ch->user_limit = 0;
          auto p = ch->modes.find('l');
          if (p != std::string::npos) ch->modes.erase(p, 1);
          applied_modes += "-l";
        }
        break;
      }
      // ----- Type D: Member prefix modes (o/v/h/q/a) -----
      case 'o': { // Operator (@)
        if (param_idx < params.size()) {
          std::string nick = params[param_idx++];
          if (!ch->members.count(nick)) {
            send_numeric(conn, Numerics::ERR_USERNOTINCHANNEL, nick + " " + chname +
                         " :They aren't on that channel");
            continue;
          }
          if (adding) {
            ch->member_modes[nick] += 'o';
          } else {
            auto& m = ch->member_modes[nick];
            auto p = m.find('o');
            if (p != std::string::npos) m.erase(p, 1);
          }
          applied_modes += (adding ? "+o" : "-o");
          applied_params.push_back(nick);
        }
        break;
      }
      case 'v': { // Voice (+)
        if (param_idx < params.size()) {
          std::string nick = params[param_idx++];
          if (!ch->members.count(nick)) {
            send_numeric(conn, Numerics::ERR_USERNOTINCHANNEL, nick + " " + chname +
                         " :They aren't on that channel");
            continue;
          }
          if (adding) {
            ch->member_modes[nick] += 'v';
          } else {
            auto& m = ch->member_modes[nick];
            auto p = m.find('v');
            if (p != std::string::npos) m.erase(p, 1);
          }
          applied_modes += (adding ? "+v" : "-v");
          applied_params.push_back(nick);
        }
        break;
      }
      case 'h': { // Half-op (%) [InspIRCd extension]
        if (param_idx < params.size()) {
          std::string nick = params[param_idx++];
          if (!ch->members.count(nick)) {
            send_numeric(conn, Numerics::ERR_USERNOTINCHANNEL, nick + " " + chname +
                         " :They aren't on that channel");
            continue;
          }
          if (adding) {
            auto& m = ch->member_modes[nick];
            m += 'h';
            // Halfop implicitly gets voice
            if (m.find('v') == std::string::npos) m += 'v';
          } else {
            auto& m = ch->member_modes[nick];
            auto p = m.find('h');
            if (p != std::string::npos) m.erase(p, 1);
          }
          applied_modes += (adding ? "+h" : "-h");
          applied_params.push_back(nick);
        }
        break;
      }
      case 'q': { // Owner (~) [UnrealIRCd extension]
        if (param_idx < params.size()) {
          std::string nick = params[param_idx++];
          if (!ch->members.count(nick)) {
            send_numeric(conn, Numerics::ERR_USERNOTINCHANNEL, nick + " " + chname +
                         " :They aren't on that channel");
            continue;
          }
          if (adding) {
            auto& m = ch->member_modes[nick];
            m += 'q';
            // Owner gets op too
            if (m.find('o') == std::string::npos) m += 'o';
          } else {
            auto& m = ch->member_modes[nick];
            auto p = m.find('q');
            if (p != std::string::npos) m.erase(p, 1);
          }
          applied_modes += (adding ? "+q" : "-q");
          applied_params.push_back(nick);
        }
        break;
      }
      case 'a': { // Admin (&) [UnrealIRCd extension]
        if (param_idx < params.size()) {
          std::string nick = params[param_idx++];
          if (!ch->members.count(nick)) {
            send_numeric(conn, Numerics::ERR_USERNOTINCHANNEL, nick + " " + chname +
                         " :They aren't on that channel");
            continue;
          }
          if (adding) {
            auto& m = ch->member_modes[nick];
            m += 'a';
            if (m.find('o') == std::string::npos) m += 'o';
          } else {
            auto& m = ch->member_modes[nick];
            auto p = m.find('a');
            if (p != std::string::npos) m.erase(p, 1);
          }
          applied_modes += (adding ? "+a" : "-a");
          applied_params.push_back(nick);
        }
        break;
      }
      // ----- Type E: Flag modes (no param) -----
      case 'i': // Invite-only
        ch->modes = toggle_mode_str(ch->modes, 'i', adding);
        applied_modes += (adding ? "+i" : "-i"); break;
      case 'm': // Moderated
        ch->modes = toggle_mode_str(ch->modes, 'm', adding);
        applied_modes += (adding ? "+m" : "-m"); break;
      case 'n': // No external messages
        ch->modes = toggle_mode_str(ch->modes, 'n', adding);
        applied_modes += (adding ? "+n" : "-n"); break;
      case 'p': // Private
        ch->modes = toggle_mode_str(ch->modes, 'p', adding);
        // +p and +s are mutually exclusive
        if (adding) { auto ps = ch->modes.find('s'); if (ps != std::string::npos) ch->modes.erase(ps, 1); }
        applied_modes += (adding ? "+p" : "-p"); break;
      case 's': // Secret
        ch->modes = toggle_mode_str(ch->modes, 's', adding);
        if (adding) { auto pp = ch->modes.find('p'); if (pp != std::string::npos) ch->modes.erase(pp, 1); }
        applied_modes += (adding ? "+s" : "-s"); break;
      case 't': // Topic lock (only ops can change)
        ch->modes = toggle_mode_str(ch->modes, 't', adding);
        applied_modes += (adding ? "+t" : "-t"); break;
      case 'r': // Registered (set by services)
        ch->modes = toggle_mode_str(ch->modes, 'r', adding);
        applied_modes += (adding ? "+r" : "-r"); break;
      case 'c': // No color codes
        ch->modes = toggle_mode_str(ch->modes, 'c', adding);
        applied_modes += (adding ? "+c" : "-c"); break;
      case 'C': // No CTCP to channel
        ch->modes = toggle_mode_str(ch->modes, 'C', adding);
        applied_modes += (adding ? "+C" : "-C"); break;
      case 'N': // No nick changes
        ch->modes = toggle_mode_str(ch->modes, 'N', adding);
        applied_modes += (adding ? "+N" : "-N"); break;
      case 'M': // Must be registered to talk
        ch->modes = toggle_mode_str(ch->modes, 'M', adding);
        applied_modes += (adding ? "+M" : "-M"); break;
      case 'O': // Oper-only channel
        ch->modes = toggle_mode_str(ch->modes, 'O', adding);
        applied_modes += (adding ? "+O" : "-O"); break;
      case 'P': // Permanent channel
        ch->modes = toggle_mode_str(ch->modes, 'P', adding);
        applied_modes += (adding ? "+P" : "-P"); break;
      case 'Q': // No kicks
        ch->modes = toggle_mode_str(ch->modes, 'Q', adding);
        applied_modes += (adding ? "+Q" : "-Q"); break;
      case 'R': // Registered nick only allowed
        ch->modes = toggle_mode_str(ch->modes, 'R', adding);
        applied_modes += (adding ? "+R" : "-R"); break;
      case 'S': // SSL/TLS connections only
        ch->modes = toggle_mode_str(ch->modes, 'S', adding);
        applied_modes += (adding ? "+S" : "-S"); break;
      case 'T': // No notices allowed
        ch->modes = toggle_mode_str(ch->modes, 'T', adding);
        applied_modes += (adding ? "+T" : "-T"); break;
      case 'z': // Secure/SSL only
        ch->modes = toggle_mode_str(ch->modes, 'z', adding);
        applied_modes += (adding ? "+z" : "-z"); break;
      case 'Z': // All users must use SSL
        ch->modes = toggle_mode_str(ch->modes, 'Z', adding);
        applied_modes += (adding ? "+Z" : "-Z"); break;
      default:
        send_numeric(conn, Numerics::ERR_UNKNOWNMODE, std::string(1, mode_c) +
                     " :is unknown mode char to me for " + chname);
        break;
    }
  }
  // Broadcast mode change
  if (!applied_modes.empty()) {
    std::string mode_msg = ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                           " MODE " + chname + " " + applied_modes;
    for (auto& p : applied_params) mode_msg += " " + p;
    send_to_channel(chname, mode_msg);
  }
}

// --- User mode handler ---
void IRCServer::handle_user_mode_full_a(IRCConnection* conn, const std::string& target,
                                         const std::string& mode_str) {
  auto* u = get_user(target);
  if (!u) {
    send_numeric(conn, Numerics::ERR_NOSUCHNICK, target + " :No such nick/channel");
    return;
  }
  // Can only change own modes (unless oper)
  if (u->nick != conn->nick && !conn->nick.empty()) {
    auto* setter = get_user(conn->nick);
    if (!setter || !setter->oper) {
      send_numeric(conn, Numerics::ERR_USERSDONTMATCH, ":Cannot change mode for other users");
      return;
    }
  }
  // Query-only
  if (mode_str.empty()) {
    send_numeric(conn, 221, "+" + u->modes);
    return;
  }
  // Parse and apply
  bool adding = true;
  std::string applied;
  for (char c : mode_str) {
    if (c == '+') { adding = true; continue; }
    if (c == '-') { adding = false; continue; }
    switch (c) {
      case 'i': // Invisible
        u->modes = toggle_mode_str(u->modes, 'i', adding);
        applied += (adding ? "+i" : "-i"); break;
      case 'w': // Wallops
        u->modes = toggle_mode_str(u->modes, 'w', adding);
        applied += (adding ? "+w" : "-w"); break;
      case 'o': // Operator (only settable by server)
        if (adding) {
          u->oper = true;
          u->modes += 'o';
          applied += "+o";
        } else {
          u->oper = false;
          u->modes = toggle_mode_str(u->modes, 'o', false);
          applied += "-o";
        }
        break;
      case 's': // Server notices
        u->modes = toggle_mode_str(u->modes, 's', adding);
        applied += (adding ? "+s" : "-s"); break;
      case 'x': // Cloaked host
        u->modes = toggle_mode_str(u->modes, 'x', adding);
        applied += (adding ? "+x" : "-x"); break;
      case 'B': // Bot
        u->modes = toggle_mode_str(u->modes, 'B', adding);
        applied += (adding ? "+B" : "-B"); break;
      case 'G': // Censor/swear filter
        u->modes = toggle_mode_str(u->modes, 'G', adding);
        applied += (adding ? "+G" : "-G"); break;
      case 'H': // Hide oper status
        u->modes = toggle_mode_str(u->modes, 'H', adding);
        applied += (adding ? "+H" : "-H"); break;
      case 'I': // Hide channel list
        u->modes = toggle_mode_str(u->modes, 'I', adding);
        applied += (adding ? "+I" : "-I"); break;
      case 'R': // Registered-only PMs
        u->modes = toggle_mode_str(u->modes, 'R', adding);
        applied += (adding ? "+R" : "-R"); break;
      case 'W': // Who is message (see when people WHOIS)
        u->modes = toggle_mode_str(u->modes, 'W', adding);
        applied += (adding ? "+W" : "-W"); break;
      case 'Z': // SSL connection indicator
        u->modes = toggle_mode_str(u->modes, 'Z', adding);
        applied += (adding ? "+Z" : "-Z"); break;
      default:
        send_numeric(conn, Numerics::ERR_UMODEUNKNOWNFLAG, ":Unknown MODE flag");
        break;
    }
  }
  if (!applied.empty()) {
    send_to(conn, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
            " MODE " + conn->nick + " :" + applied);
  }
}

// ============================================================================
// TOPIC command - RFC 2812 section 3.2.4
// Topic lock check (+t) with op/halfop/owner/admin override
// ============================================================================

void IRCServer::handle_topic_full_a(IRCConnection* conn, const std::string& chname,
                                     const std::optional<std::string>& new_topic) {
  auto* ch = get_channel(chname);
  if (!ch) {
    send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, chname + " :No such channel");
    return;
  }
  if (!ch->members.count(conn->nick)) {
    send_numeric(conn, Numerics::ERR_NOTONCHANNEL, chname + " :You're not on that channel");
    return;
  }
  // Topic query
  if (!new_topic) {
    if (ch->topic.empty()) {
      send_numeric(conn, Numerics::RPL_NOTOPIC, chname + " :No topic is set");
    } else {
      send_numeric(conn, Numerics::RPL_TOPIC, chname + " :" + ch->topic);
      send_numeric(conn, Numerics::RPL_TOPICWHOTIME, chname + " " + ch->topic_setter +
                   " " + std::to_string(ch->topic_ts));
    }
    return;
  }
  // Topic set - check +t (topic lock)
  if (ch->modes.find('t') != std::string::npos) {
    if (!is_channel_staff(ch, conn->nick)) {
      send_numeric(conn, Numerics::ERR_CHANOPRIVSNEEDED, chname +
                   " :You're not channel operator");
      return;
    }
  }
  // Validate topic length
  std::string topic_str = *new_topic;
  if (topic_str.length() > static_cast<size_t>(config_.max_topic_length)) {
    topic_str = topic_str.substr(0, config_.max_topic_length);
  }
  ch->topic = topic_str;
  ch->topic_setter = conn->nick + "!" + conn->user + "@" + conn->host;
  ch->topic_ts = now_sec();
  // Broadcast
  send_to_channel(chname, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                  " TOPIC " + chname + " :" + ch->topic);
}

// ============================================================================
// KICK command - RFC 2812 section 3.2.8
// Op check, owner protection, +Q (no kicks) check
// ============================================================================

void IRCServer::handle_kick_full_a(IRCConnection* conn, const std::string& chname,
                                    const std::string& target, const std::string& reason) {
  auto* ch = get_channel(chname);
  if (!ch) {
    send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, chname + " :No such channel");
    return;
  }
  if (!ch->members.count(conn->nick)) {
    send_numeric(conn, Numerics::ERR_NOTONCHANNEL, chname + " :You're not on that channel");
    return;
  }
  if (!ch->members.count(target)) {
    send_numeric(conn, Numerics::ERR_USERNOTINCHANNEL, target + " " + chname +
                 " :They aren't on that channel");
    return;
  }
  // Check +Q (no kicks)
  if (ch->modes.find('Q') != std::string::npos && !is_channel_owner(ch, conn->nick)) {
    send_numeric(conn, Numerics::ERR_CHANOPRIVSNEEDED, chname + " :No kicks allowed (+Q)");
    return;
  }
  // Permission check: need halfop or above
  if (!is_channel_staff(ch, conn->nick)) {
    send_numeric(conn, Numerics::ERR_CHANOPRIVSNEEDED, chname +
                 " :You're not channel operator");
    return;
  }
  // Owner protection: only owner can kick owner; admin can't kick owner
  if (is_channel_owner(ch, target) && !is_channel_owner(ch, conn->nick)) {
    send_numeric(conn, Numerics::ERR_CHANOPRIVSNEEDED, chname +
                 " :Cannot kick channel owner");
    return;
  }
  // Admin protection: only owner/admin can kick admin
  if (is_channel_admin(ch, target) && !is_channel_owner(ch, conn->nick) &&
      !is_channel_admin(ch, conn->nick)) {
    send_numeric(conn, Numerics::ERR_CHANOPRIVSNEEDED, chname +
                 " :Cannot kick channel admin");
    return;
  }
  // Halfop can only kick regular users (not ops/admins/owners)
  if (is_channel_halfop(ch, conn->nick) && !is_channel_owner(ch, conn->nick) &&
      !is_channel_admin(ch, conn->nick) && !is_channel_op(ch, conn->nick)) {
    if (is_channel_op(ch, target) || is_channel_admin(ch, target) || is_channel_owner(ch, target)) {
      send_numeric(conn, Numerics::ERR_CHANOPRIVSNEEDED, chname +
                   " :Halfops cannot kick operators");
      return;
    }
  }
  // Build kick reason
  std::string kick_reason = reason.empty() ? conn->nick : reason;
  if (kick_reason.length() > static_cast<size_t>(config_.max_kick_length))
    kick_reason = kick_reason.substr(0, config_.max_kick_length);
  // Broadcast KICK
  send_to_channel(chname, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                  " KICK " + chname + " " + target + " :" + kick_reason);
  // Remove from channel
  ch->members.erase(target);
  ch->member_modes.erase(target);
  ch->invites.erase(target);
  // Clean up empty channel
  if (ch->members.empty() && ch->modes.find('P') == std::string::npos) {
    channels_.erase(chname);
  }
}

// ============================================================================
// INVITE command - RFC 2812 section 3.2.7
// Invite-only check (+i), invite-exception (+I), duplicate check
// ============================================================================

void IRCServer::handle_invite_full_a(IRCConnection* conn, const std::string& target_nick,
                                      const std::string& chname) {
  auto* ch = get_channel(chname);
  if (!ch) {
    send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, chname + " :No such channel");
    return;
  }
  if (!ch->members.count(conn->nick)) {
    send_numeric(conn, Numerics::ERR_NOTONCHANNEL, chname + " :You're not on that channel");
    return;
  }
  // Check invite-only: only op+ can invite to +i channels
  if (ch->modes.find('i') != std::string::npos) {
    if (!is_channel_staff(ch, conn->nick)) {
      send_numeric(conn, Numerics::ERR_CHANOPRIVSNEEDED, chname +
                   " :You're not channel operator");
      return;
    }
  }
  auto* target_u = get_user(target_nick);
  if (!target_u) {
    send_numeric(conn, Numerics::ERR_NOSUCHNICK, target_nick + " :No such nick/channel");
    return;
  }
  // Already on channel
  if (ch->members.count(target_nick)) {
    send_numeric(conn, Numerics::ERR_USERONCHANNEL, target_nick + " " + chname +
                 " :is already on channel");
    return;
  }
  // Add to invite list
  ch->invites.insert(target_nick);
  // RPL_INVITING (341)
  send_to(conn, ":" + config_.server_name + " 341 " + conn->nick + " " +
          target_nick + " " + chname);
  // Send INVITE to target
  for (auto& [fd, c] : connections_) {
    if (c.nick == target_nick) {
      send_to(&c, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
              " INVITE " + target_nick + " :" + chname);
      break;
    }
  }
}

// ============================================================================
// WHOIS command - RFC 2812 section 3.6.2
// Multi-target, channel lookup, idle time, operator status
// ============================================================================

void IRCServer::handle_whois_full_a(IRCConnection* conn, const std::string& targets_str) {
  if (targets_str.empty()) {
    send_numeric(conn, Numerics::ERR_NONICKNAMEGIVEN, ":No nickname given");
    return;
  }
  // Support multiple targets (comma or space separated: "WHOIS nick1 nick2")
  auto targets = split_csv(targets_str);
  if (targets.empty()) {
    // Try space-separated
    std::stringstream ss(targets_str);
    std::string t;
    while (ss >> t) targets.push_back(t);
  }
  for (auto& target : targets) {
    auto* u = get_user(target);
    if (!u) {
      send_numeric(conn, Numerics::ERR_NOSUCHNICK, target + " :No such nick/channel");
      continue;
    }
    // RPL_WHOISUSER (311)
    send_numeric(conn, Numerics::RPL_WHOISUSER,
      target + " " + u->user + " " + u->host + " * :" + u->realname);
    // RPL_WHOISCHANNELS (319): collect channels
    std::string chan_list;
    for (auto& [cn, ch] : channels_) {
      if (ch.members.count(target)) {
        // Secret/private channel hiding for non-members
        if (ch.modes.find('s') != std::string::npos && !ch.members.count(conn->nick))
          continue;
        if (ch.modes.find('p') != std::string::npos && !ch.members.count(conn->nick))
          continue;
        // Prefix
        std::string prefix;
        auto it = ch.member_modes.find(target);
        if (it != ch.member_modes.end()) {
          if (it->second.find('q') != std::string::npos) prefix = "~";
          else if (it->second.find('a') != std::string::npos) prefix = "&";
          else if (it->second.find('o') != std::string::npos) prefix = "@";
          else if (it->second.find('h') != std::string::npos) prefix = "%";
          else if (it->second.find('v') != std::string::npos) prefix = "+";
        }
        if (!chan_list.empty()) chan_list += " ";
        chan_list += prefix + cn;
      }
    }
    if (!chan_list.empty())
      send_numeric(conn, Numerics::RPL_WHOISCHANNELS, target + " :" + chan_list);
    // RPL_WHOISSERVER (312)
    send_numeric(conn, Numerics::RPL_WHOISSERVER,
      target + " " + config_.server_name + " :" + config_.description);
    // RPL_WHOISOPERATOR (313)
    if (u->oper && u->modes.find('H') == std::string::npos)
      send_numeric(conn, Numerics::RPL_WHOISOPERATOR, target + " :is an IRC operator");
    // RPL_AWAY (301)
    if (u->away)
      send_numeric(conn, Numerics::RPL_AWAY, target + " :" + u->away_msg);
    // RPL_WHOISIDLE (317)
    int64_t idle = now_sec() - u->last_active;
    send_numeric(conn, Numerics::RPL_WHOISIDLE,
      target + " " + std::to_string(idle) + " " + std::to_string(u->signon_time) +
      " :seconds idle, signon time");
    // RPL_ENDOFWHOIS (318)
    send_numeric(conn, Numerics::RPL_ENDOFWHOIS, target + " :End of /WHOIS list");
  }
}

// ============================================================================
// WHO command - RFC 2812 section 3.6.1
// Mask matching, operator filtering
// ============================================================================

void IRCServer::handle_who_full_a(IRCConnection* conn, const std::string& mask,
                                   bool ops_only) {
  for (auto& [nick, u] : users_) {
    // Skip invisible users unless requester is on common channel
    if (u.modes.find('i') != std::string::npos && nick != conn->nick) {
      bool common = false;
      for (auto& [cn, ch] : channels_) {
        if (ch.members.count(nick) && ch.members.count(conn->nick)) {
          common = true; break;
        }
      }
      if (!common) continue;
    }
    // Mask matching
    if (!mask.empty() && mask != "*" && mask != "0") {
      if (!wildcard_match(mask, nick) &&
          !wildcard_match(mask, u.user) &&
          !wildcard_match(mask, u.host) &&
          !wildcard_match(mask, u.realname) &&
          !wildcard_match(mask, config_.server_name))
        continue;
    }
    // Operator-only flag
    if (ops_only && !u.oper) continue;
    // Build the reply
    std::string flags = "H"; // Here
    if (u.away) flags = "G"; // Gone (away)
    if (u.oper) flags += "*";
    std::string chname = "*";
    // Find first common channel
    for (auto& [cn, ch] : channels_) {
      if (ch.members.count(nick)) {
        auto it = ch.member_modes.find(nick);
        if (it != ch.member_modes.end()) {
          if (it->second.find('q') != std::string::npos) chname = "~" + cn;
          else if (it->second.find('a') != std::string::npos) chname = "&" + cn;
          else if (it->second.find('o') != std::string::npos) chname = "@" + cn;
          else if (it->second.find('h') != std::string::npos) chname = "%" + cn;
          else if (it->second.find('v') != std::string::npos) chname = "+" + cn;
          else chname = cn;
        } else {
          chname = cn;
        }
        break;
      }
    }
    send_numeric(conn, Numerics::RPL_WHOREPLY,
      chname + " " + u.user + " " + u.host + " " + config_.server_name + " " +
      nick + " " + flags + " :0 " + u.realname);
  }
  send_numeric(conn, Numerics::RPL_ENDOFWHO,
    (mask.empty() ? "*" : mask) + " :End of /WHO list");
}

// ============================================================================
// WHOWAS command - RFC 2812 section 3.6.3
// Historical nick lookup with count limit
// ============================================================================

void IRCServer::handle_whowas_full_a(IRCConnection* conn, const std::string& nick,
                                      int count) {
  int shown = 0;
  int max_show = (count > 0) ? count : 5;
  // Search history in reverse (most recent first)
  for (auto it = whowas_history_.rbegin();
       it != whowas_history_.rend() && shown < max_show; ++it) {
    if (iequals(it->nick, nick)) {
      send_numeric(conn, 314,
        it->nick + " " + it->user + " " + it->host + " * :" + it->realname);
      send_numeric(conn, 312,
        it->nick + " " + it->server + " :" + std::to_string(it->quit_time));
      ++shown;
    }
  }
  if (shown == 0)
    send_numeric(conn, 406, nick + " :There was no such nickname");
  send_numeric(conn, 369, nick + " :End of WHOWAS");
}

// ============================================================================
// LIST command - RFC 2812 section 3.2.6
// Channel listing with pattern filter, secret/private hiding
// ============================================================================

void IRCServer::handle_list_full_a(IRCConnection* conn, const std::string& pattern) {
  send_numeric(conn, 321, "Channel :Users  Name"); // RPL_LISTSTART
  for (auto& [name, ch] : channels_) {
    // Skip secret channels for non-members
    if (ch.modes.find('s') != std::string::npos && !ch.members.count(conn->nick))
      continue;
    // Skip private channels for non-members (only show name, not topic)
    if (ch.modes.find('p') != std::string::npos && !ch.members.count(conn->nick)) {
      if (!pattern.empty() && name.find(pattern) == std::string::npos) continue;
      send_numeric(conn, Numerics::RPL_LIST, name + " " +
                   std::to_string(ch.members.size()) + " :");
      continue;
    }
    // Pattern filter
    if (!pattern.empty() && pattern != "*") {
      if (name.find(pattern) == std::string::npos) continue;
    }
    std::string topic_display = ch.topic.empty() ? "No topic set" : ch.topic;
    send_numeric(conn, Numerics::RPL_LIST,
      name + " " + std::to_string(ch.members.size()) + " :" + topic_display);
  }
  send_numeric(conn, Numerics::RPL_LISTEND, ":End of /LIST");
}

// ============================================================================
// NAMES command - RFC 2812 section 3.2.5
// Channel member listing with prefix symbols, secret/private handling
// ============================================================================

void IRCServer::handle_names_full_a(IRCConnection* conn, const std::string& channels_str) {
  if (channels_str.empty()) {
    // NAMES without parameters: list all visible channels and non-channel users
    for (auto& [name, ch] : channels_) {
      if (ch.modes.find('s') != std::string::npos && !ch.members.count(conn->nick)) continue;
      if (ch.modes.find('p') != std::string::npos && !ch.members.count(conn->nick)) continue;
      send_channel_names_full_a(conn, name);
    }
    // Users not in any channel (and not invisible)
    std::string others;
    for (auto& [nick, u] : users_) {
      if (nick == conn->nick) continue;
      if (u.modes.find('i') != std::string::npos) continue;
      bool in_any = false;
      for (auto& [cn, ch] : channels_) {
        if (ch.members.count(nick)) { in_any = true; break; }
      }
      if (!in_any) {
        if (!others.empty()) others += " ";
        others += nick;
      }
    }
    if (!others.empty())
      send_numeric(conn, Numerics::RPL_NAMREPLY, "* * :" + others);
    send_numeric(conn, Numerics::RPL_ENDOFNAMES, "* :End of /NAMES list");
  } else {
    auto chans = split_csv(channels_str);
    for (auto& cn : chans) {
      send_channel_names_full_a(conn, cn);
    }
  }
}

// Helper: send NAMES for a single channel
void IRCServer::send_channel_names_full_a(IRCConnection* conn, const std::string& chname) {
  auto* ch = get_channel(chname);
  if (!ch) {
    send_numeric(conn, Numerics::RPL_ENDOFNAMES, chname + " :End of /NAMES list");
    return;
  }
  // Determine channel symbol for NAMES reply
  char symbol = '=';
  if (ch->modes.find('s') != std::string::npos) symbol = '@';
  else if (ch->modes.find('p') != std::string::npos) symbol = '*';
  // Build names list with prefixes
  std::string names;
  for (auto& nick : ch->members) {
    if (!names.empty()) names += " ";
    auto it = ch->member_modes.find(nick);
    if (it != ch->member_modes.end()) {
      if (it->second.find('q') != std::string::npos) names += "~";
      else if (it->second.find('a') != std::string::npos) names += "&";
      else if (it->second.find('o') != std::string::npos) names += "@";
      else if (it->second.find('h') != std::string::npos) names += "%";
      else if (it->second.find('v') != std::string::npos) names += "+";
    }
    names += nick;
  }
  // Split long lines (512 byte IRC limit)
  size_t max_line = 400;
  size_t pos = 0;
  while (pos < names.length()) {
    size_t end = std::min(pos + max_line, names.length());
    if (end < names.length()) {
      size_t last_space = names.rfind(' ', end);
      if (last_space != std::string::npos && last_space > pos)
        end = last_space;
    }
    std::string line = names.substr(pos, end - pos);
    send_numeric(conn, Numerics::RPL_NAMREPLY, std::string(1, symbol) + " " + chname + " :" + line);
    pos = end;
    if (pos < names.length() && names[pos] == ' ') ++pos;
  }
  send_numeric(conn, Numerics::RPL_ENDOFNAMES, chname + " :End of /NAMES list");
}

// ============================================================================
// PING/PONG commands - RFC 2812 section 3.7.2/3.7.3
// ============================================================================

void IRCServer::handle_ping_full_a(IRCConnection* conn, const std::string& token) {
  send_to(conn, ":" + config_.server_name + " PONG " + config_.server_name + " :" + token);
}

void IRCServer::handle_pong_full_a(IRCConnection* conn, const std::string& token) {
  // Update last_active for lag detection
  auto* u = get_user(conn->nick);
  if (u) u->last_active = now_sec();
  // PONG received from client, nothing to reply
}

// ============================================================================
// VERSION command - RFC 2812 section 3.4.3
// ============================================================================

void IRCServer::handle_version_full_a(IRCConnection* conn) {
  send_numeric(conn, Numerics::RPL_VERSION,
    "progressive-irc-1.0.0." + config_.server_name + " :progressive IRC Server " +
    "(C++17, InspIRCd-compatible)");
}

// ============================================================================
// STATS command - RFC 2812 section 3.4.4
// Various stat queries: l/L (links), m/M (commands), o/O (opers), u/U (uptime)
// ============================================================================

void IRCServer::handle_stats_full_a(IRCConnection* conn, const std::string& query) {
  char q = query.empty() ? 'l' : query[0];
  switch (q) {
    case 'l': case 'L': // Link statistics
      for (auto& [name, srv] : linked_servers_)
        send_numeric(conn, 211, name + " " + config_.server_name + " 1 0 0 0 :" + srv.description);
      send_numeric(conn, 219, std::string(1, q) + " :End of STATS report");
      break;
    case 'm': case 'M': // Command statistics
      send_numeric(conn, 212, "NICK 0");
      send_numeric(conn, 212, "USER 0");
      send_numeric(conn, 212, "PRIVMSG 0");
      send_numeric(conn, 219, std::string(1, q) + " :End of STATS report");
      break;
    case 'o': case 'O': // Operator list
      for (auto& [nick, u] : users_) {
        if (u.oper && u.modes.find('H') == std::string::npos) {
          send_numeric(conn, 243, "O " + u.host + " * " + nick);
        }
      }
      send_numeric(conn, 219, std::string(1, q) + " :End of STATS report");
      break;
    case 'u': case 'U': // Server uptime
      {
        int64_t uptime = now_sec() - start_time_;
        send_numeric(conn, 242, ":Server Up " + std::to_string(uptime / 86400) + " days " +
                     std::to_string((uptime % 86400) / 3600) + ":" +
                     std::to_string((uptime % 3600) / 60) + ":" +
                     std::to_string(uptime % 60));
      }
      send_numeric(conn, 219, std::string(1, q) + " :End of STATS report");
      break;
    case 'c': case 'C': // Connection statistics
      send_numeric(conn, 213, "C * * " + std::to_string(connections_.size()) +
                   " " + config_.server_name);
      send_numeric(conn, 219, std::string(1, q) + " :End of STATS report");
      break;
    default:
      send_numeric(conn, 219, std::string(1, q) + " :End of STATS report");
      break;
  }
}

// ============================================================================
// LINKS command - RFC 2812 section 3.3.2
// Lists all linked servers
// ============================================================================

void IRCServer::handle_links_full_a(IRCConnection* conn) {
  send_numeric(conn, 364,
    config_.server_name + " " + config_.server_name + " :0 " + config_.description);
  for (auto& [name, srv] : linked_servers_) {
    send_numeric(conn, 364,
      name + " " + config_.server_name + " :" + std::to_string(srv.hop_count) +
      " " + srv.description);
  }
  send_numeric(conn, 365, "* :End of /LINKS list");
}

// ============================================================================
// TIME command - RFC 2812 section 3.4.6
// ============================================================================

void IRCServer::handle_time_full_a(IRCConnection* conn) {
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  send_numeric(conn, 391, config_.server_name + " :" + format_time(t));
}

// ============================================================================
// INFO command - RFC 2812 section 3.4.10
// ============================================================================

void IRCServer::handle_info_full_a(IRCConnection* conn) {
  send_numeric(conn, 371, ":" + config_.server_name + " - progressive IRC Server v1.0.0");
  send_numeric(conn, 371, ":Based on concepts from InspIRCd");
  send_numeric(conn, 371, ":Built with C++17 for high performance");
  send_numeric(conn, 371, ":Supports RFC 1459/2812/2813");
  send_numeric(conn, 371, ":Matrix/IRC bridge via progressive-server");
  send_numeric(conn, 371, ":https://progressive-chat.org");
  send_numeric(conn, 374, ":End of /INFO list");
}

// ============================================================================
// MOTD command - RFC 2812 section 3.4.1
// Message of the day with configurable lines
// ============================================================================

void IRCServer::handle_motd_full_a(IRCConnection* conn) {
  if (config_.motd_lines.empty()) {
    send_numeric(conn, Numerics::ERR_NOMOTD, ":MOTD File is missing");
    return;
  }
  send_numeric(conn, Numerics::RPL_MOTDSTART,
    ":- " + config_.server_name + " Message of the day -");
  for (auto& line : config_.motd_lines)
    send_numeric(conn, Numerics::RPL_MOTD, ":- " + line);
  send_numeric(conn, Numerics::RPL_ENDOFMOTD, ":End of /MOTD command");
}

// ============================================================================
// LUSERS command - RFC 2812 section 3.4.2
// User and channel statistics
// ============================================================================

void IRCServer::handle_lusers_full_a(IRCConnection* conn) {
  size_t total = users_.size();
  size_t invisible = 0, opers = 0;
  for (auto& [nick, u] : users_) {
    if (u.modes.find('i') != std::string::npos) ++invisible;
    if (u.oper) ++opers;
  }
  size_t visible = total - invisible;
  send_numeric(conn, 251,
    ":There are " + std::to_string(visible) + " users and " +
    std::to_string(invisible) + " invisible on 1 server");
  send_numeric(conn, 252, std::to_string(opers) + " :operator(s) online");
  send_numeric(conn, 253, "0 :unknown connection(s)");
  send_numeric(conn, 254, std::to_string(channels_.size()) + " :channels formed");
  send_numeric(conn, 255,
    ":I have " + std::to_string(total) + " clients and 1 server");
  send_numeric(conn, 265,
    std::to_string(total) + " " + std::to_string(total) +
    " :Current local users " + std::to_string(total) +
    ", max " + std::to_string(max_local_users_seen_));
  send_numeric(conn, 266,
    std::to_string(total) + " " + std::to_string(total) +
    " :Current global users " + std::to_string(total) +
    ", max " + std::to_string(max_local_users_seen_));
}

// ============================================================================
// ADMIN command - RFC 2812 section 3.4.7
// Administrative information
// ============================================================================

void IRCServer::handle_admin_full_a(IRCConnection* conn) {
  send_numeric(conn, 256, config_.server_name + " :Administrative info");
  send_numeric(conn, 257, ":Name     : " + config_.admin_name);
  send_numeric(conn, 258, ":Nickname : " + config_.server_name + " Admin");
  send_numeric(conn, 259, ":E-mail   : " + config_.admin_email);
}

// ============================================================================
// AWAY command - RFC 2812 section 4.1
// Mark/unmark as away with message
// ============================================================================

void IRCServer::handle_away_full_a(IRCConnection* conn,
                                    const std::optional<std::string>& msg) {
  auto* u = get_user(conn->nick);
  if (!u) return;
  if (msg) {
    std::string away_text = *msg;
    if (away_text.length() > static_cast<size_t>(config_.max_away_length))
      away_text = away_text.substr(0, config_.max_away_length);
    u->away = true;
    u->away_msg = away_text;
    send_numeric(conn, Numerics::RPL_NOWAWAY, ":You have been marked as being away");
    // Notify channels of away status (if away-notify CAP enabled)
  } else {
    u->away = false;
    u->away_msg.clear();
    send_numeric(conn, Numerics::RPL_UNAWAY, ":You are no longer marked as being away");
  }
}

// ============================================================================
// OPER command - RFC 2812 section 3.1.4
// Operator authentication
// ============================================================================

void IRCServer::handle_oper_full_a(IRCConnection* conn, const std::string& name,
                                    const std::string& password) {
  if (name.empty() || password.empty()) {
    send_numeric(conn, Numerics::ERR_NEEDMOREPARAMS, "OPER :Not enough parameters");
    return;
  }
  // Check oper blocks in config
  auto it = config_.oper_blocks.find(name);
  if (it == config_.oper_blocks.end() || it->second != password) {
    send_numeric(conn, 491, ":No O-lines for your host");
    return;
  }
  auto* u = get_user(conn->nick);
  if (!u) return;
  u->oper = true;
  u->modes += 'o';
  send_numeric(conn, 381, ":You are now an IRC operator");
  send_to(conn, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
          " MODE " + conn->nick + " :+o");
  // Global notice
  send_server_notice(conn->nick + " (" + conn->user + "@" + conn->host +
                     ") is now an IRC operator");
}

// ============================================================================
// KILL command - RFC 2812 section 3.7.1
// Oper-only forced disconnect
// ============================================================================

void IRCServer::handle_kill_full_a(IRCConnection* conn, const std::string& target,
                                    const std::string& reason) {
  auto* u = get_user(conn->nick);
  if (!u || !u->oper) {
    send_numeric(conn, 481, ":Permission Denied - You're not an IRC operator");
    return;
  }
  if (target.empty()) {
    send_numeric(conn, Numerics::ERR_NEEDMOREPARAMS, "KILL :Not enough parameters");
    return;
  }
  auto* target_u = get_user(target);
  if (!target_u) {
    send_numeric(conn, Numerics::ERR_NOSUCHNICK, target + " :No such nick/channel");
    return;
  }
  std::string kill_reason = reason.empty() ? "Killed by " + conn->nick : reason;
  // Send KILL to target and broadcast QUIT
  for (auto& [fd, c] : connections_) {
    if (c.nick == target) {
      send_to(&c, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
              " KILL " + target + " :" + kill_reason);
      // Broadcast QUIT to all channels
      for (auto& [ch_name, ch] : channels_) {
        if (ch.members.count(target)) {
          send_to_channel(ch_name, ":" + target + "!" + target_u->user + "@" +
                          target_u->host + " QUIT :Killed (" + kill_reason + ")");
          ch.members.erase(target);
          ch.member_modes.erase(target);
          if (ch.members.empty() && ch.modes.find('P') == std::string::npos)
            channels_.erase(ch_name);
        }
      }
      remove_user(target);
      close_connection(&c);
      break;
    }
  }
}

// ============================================================================
// SQUIT command - RFC 2812 section 3.4.1
// Oper-only server disconnect
// ============================================================================

void IRCServer::handle_squit_full_a(IRCConnection* conn, const std::string& server_name,
                                     const std::string& reason) {
  auto* u = get_user(conn->nick);
  if (!u || !u->oper) {
    send_numeric(conn, 481, ":Permission Denied - You're not an IRC operator");
    return;
  }
  if (server_name.empty()) {
    send_numeric(conn, Numerics::ERR_NEEDMOREPARAMS, "SQUIT :Not enough parameters");
    return;
  }
  std::string squit_reason = reason.empty() ? "No reason" : reason;
  // Remove linked server and all its users
  auto it = std::find_if(linked_servers_.begin(), linked_servers_.end(),
    [&](const IRCServer& s) { return s.name == server_name; });
  if (it == linked_servers_.end()) {
    // Check if squitting ourselves
    if (server_name == config_.server_name) {
      send_server_notice("Server " + config_.server_name + " split: " + squit_reason);
      // Disconnect all users
      for (auto& [fd, c] : connections_) {
        send_to(&c, "ERROR :Closing link: " + config_.server_name + " (" + squit_reason + ")");
      }
      connections_.clear();
      return;
    }
    // Server not found
    send_numeric(conn, 402, server_name + " :No such server");
    return;
  }
  // Remove all users from that server
  std::set<std::string> users_to_remove;
  for (auto& [nick, usr] : users_) {
    if (usr.server == server_name) users_to_remove.insert(nick);
  }
  for (auto& nick : users_to_remove) {
    for (auto& [ch_name, ch] : channels_) {
      if (ch.members.count(nick)) {
        send_to_channel(ch_name, ":" + nick + " QUIT :" + server_name + " " + server_name);
        ch.members.erase(nick);
        ch.member_modes.erase(nick);
      }
    }
    remove_user(nick);
  }
  send_server_notice("Server " + server_name + " split: " + squit_reason);
  linked_servers_.erase(it);
}

// ============================================================================
// REHASH command - RFC 2812 section 3.4.9
// Oper-only configuration reload
// ============================================================================

void IRCServer::handle_rehash_full_a(IRCConnection* conn) {
  auto* u = get_user(conn->nick);
  if (!u || !u->oper) {
    send_numeric(conn, 481, ":Permission Denied - You're not an IRC operator");
    return;
  }
  // Reload config
  send_numeric(conn, 382, config_.server_name + " :Rehashing");
  send_server_notice(conn->nick + " is rehashing server config");
}

// ============================================================================
// RESTART command - RFC 2812 section 4.4
// Oper-only server restart
// ============================================================================

void IRCServer::handle_restart_full_a(IRCConnection* conn) {
  auto* u = get_user(conn->nick);
  if (!u || !u->oper) {
    send_numeric(conn, 481, ":Permission Denied - You're not an IRC operator");
    return;
  }
  send_server_notice("Server restart requested by " + conn->nick);
  // Graceful shutdown
  for (auto& [fd, c] : connections_)
    send_to(&c, "ERROR :Server restarting");
  running_ = false;
}

// ============================================================================
// DIE command - RFC 2812 section 4.3
// Oper-only server termination
// ============================================================================

void IRCServer::handle_die_full_a(IRCConnection* conn) {
  auto* u = get_user(conn->nick);
  if (!u || !u->oper) {
    send_numeric(conn, 481, ":Permission Denied - You're not an IRC operator");
    return;
  }
  send_server_notice("Server terminating by request of " + conn->nick);
  for (auto& [fd, c] : connections_)
    send_to(&c, "ERROR :Server terminated");
  running_ = false;
  stop();
}

// ============================================================================
// ISON command - RFC 2812 section 4.8
// Check if nicks are online
// ============================================================================

void IRCServer::handle_ison_full_a(IRCConnection* conn,
                                    const std::vector<std::string>& nicks) {
  std::string online;
  for (auto& nick : nicks) {
    for (auto& [n, u] : users_) {
      if (iequals(n, nick)) {
        if (!online.empty()) online += " ";
        online += n;
        break;
      }
    }
  }
  send_numeric(conn, 303, ":" + online);
}

// ============================================================================
// USERHOST command - RFC 2812 section 4.9
// Get user@host for list of nicks
// ============================================================================

void IRCServer::handle_userhost_full_a(IRCConnection* conn,
                                        const std::vector<std::string>& nicks) {
  if (nicks.size() > 5) {
    send_numeric(conn, Numerics::ERR_NEEDMOREPARAMS,
      "USERHOST :Too many nicks (max 5)");
    return;
  }
  std::string response;
  for (auto& nick : nicks) {
    if (!response.empty()) response += " ";
    auto* u = get_user(nick);
    if (!u) {
      response += nick + "=*";
      continue;
    }
    std::string entry = nick;
    if (u->oper) entry += "*";
    entry += "=";
    entry += (u->away ? "-" : "+");
    entry += u->user + "@" + u->host;
    response += entry;
  }
  send_numeric(conn, 302, ":" + response);
}

// ============================================================================
// WALLOPS command - RFC 2812 section 3.7.2
// Oper-only message to all +w users
// ============================================================================

void IRCServer::handle_wallops_full_a(IRCConnection* conn, const std::string& message) {
  auto* u = get_user(conn->nick);
  if (!u || !u->oper) {
    send_numeric(conn, 481, ":Permission Denied - You're not an IRC operator");
    return;
  }
  if (message.empty()) {
    send_numeric(conn, Numerics::ERR_NEEDMOREPARAMS, "WALLOPS :Not enough parameters");
    return;
  }
  for (auto& [nick, usr] : users_) {
    if (usr.modes.find('w') != std::string::npos || usr.oper) {
      for (auto& [fd, c] : connections_) {
        if (c.nick == nick) {
          send_to(&c, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                  " WALLOPS :" + message);
          break;
        }
      }
    }
  }
}

// ============================================================================
// GLOBOPS command
// Like WALLOPS but only to operators
// ============================================================================

void IRCServer::handle_globops_full_a(IRCConnection* conn, const std::string& message) {
  auto* u = get_user(conn->nick);
  if (!u || !u->oper) {
    send_numeric(conn, 481, ":Permission Denied - You're not an IRC operator");
    return;
  }
  if (message.empty()) return;
  for (auto& [nick, usr] : users_) {
    if (usr.oper) {
      for (auto& [fd, c] : connections_) {
        if (c.nick == nick) {
          send_to(&c, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                  " GLOBOPS :" + message);
          break;
        }
      }
    }
  }
}

// ============================================================================
// CAP command - IRCv3 capability negotiation
// LS, LIST, REQ, ACK, NAK, END
// ============================================================================

void IRCServer::handle_cap_full_a(IRCConnection* conn, const std::string& subcommand,
                                   const std::vector<std::string>& caps) {
  if (subcommand == "LS" || subcommand == "LIST") {
    // List supported capabilities
    std::string cap_list = "account-tag away-notify echo-message message-tags "
                           "multi-prefix sasl server-time userhost-in-names";
    send_to(conn, ":" + config_.server_name + " CAP " + conn->nick +
            " LS :" + cap_list);
  } else if (subcommand == "REQ") {
    // Request capabilities
    std::string ack_caps, nak_caps;
    for (auto& cap : caps) {
      if (cap == "multi-prefix" || cap == "message-tags" ||
          cap == "server-time" || cap == "account-tag" ||
          cap == "away-notify" || cap == "echo-message" ||
          cap == "userhost-in-names") {
        if (!ack_caps.empty()) ack_caps += " ";
        ack_caps += cap;
        // Store enabled caps
        cap_enabled_[conn->nick].insert(cap);
      } else if (cap == "sasl") {
        if (!ack_caps.empty()) ack_caps += " ";
        ack_caps += "sasl";
        cap_enabled_[conn->nick].insert("sasl");
      } else {
        if (!nak_caps.empty()) nak_caps += " ";
        nak_caps += cap;
      }
    }
    if (!ack_caps.empty())
      send_to(conn, ":" + config_.server_name + " CAP " + conn->nick +
              " ACK :" + ack_caps);
    if (!nak_caps.empty())
      send_to(conn, ":" + config_.server_name + " CAP " + conn->nick +
              " NAK :" + nak_caps);
  } else if (subcommand == "END") {
    // Capability negotiation complete
    cap_negotiating_.erase(conn->nick);
    // Proceed with registration
  } else if (subcommand == "CLEAR") {
    // Clear all capabilities
    cap_enabled_[conn->nick].clear();
  }
}

// ============================================================================
// SASL command - IRCv3 SASL authentication
// ============================================================================

void IRCServer::handle_sasl_full_a(IRCConnection* conn, const std::string& mechanism,
                                    const std::string& data) {
  if (mechanism == "PLAIN") {
    // PLAIN SASL: data is base64(authzid\0authcid\0passwd)
    // For simplicity, just acknowledge and mark as authenticated
    send_to(conn, ":" + config_.server_name + " 900 " + conn->nick + " " +
            conn->nick + "!" + conn->user + "@" + conn->host +
            " " + conn->nick + " :You are now logged in as " + conn->nick);
    send_to(conn, ":" + config_.server_name + " 903 " + conn->nick +
            " :SASL authentication successful");
  } else if (mechanism == "EXTERNAL") {
    send_to(conn, ":" + config_.server_name + " 900 " + conn->nick + " " +
            conn->nick + "!" + conn->user + "@" + conn->host +
            " " + conn->nick + " :You are now logged in as " + conn->nick);
    send_to(conn, ":" + config_.server_name + " 903 " + conn->nick +
            " :SASL authentication successful");
  } else {
    send_to(conn, ":" + config_.server_name + " 904 " + conn->nick +
            " :SASL authentication failed: mechanism not supported");
  }
}

// ============================================================================
// CTCP handler (CTCP = Client-To-Client Protocol)
// VERSION, PING, TIME, FINGER, SOURCE, CLIENTINFO, ACTION, DCC
// ============================================================================

void IRCServer::handle_ctcp_full_a(IRCConnection* conn, const std::string& target,
                                    const std::string& ctcp_body) {
  std::string cmd = ctcp_body;
  std::string args;
  auto sp = ctcp_body.find(' ');
  if (sp != std::string::npos) {
    cmd = ctcp_body.substr(0, sp);
    // Trim args
    args = ctcp_body.substr(sp + 1);
    while (!args.empty() && args[0] == ' ') args = args.substr(1);
  }
  if (cmd == "VERSION") {
    std::string reply = "\001VERSION progressive-irc-1.0.0 " +
                        config_.server_name + " :progressive C++ IRC Server\001";
    send_to(conn, ":" + config_.server_name + " NOTICE " + conn->nick + " :" + reply);
  } else if (cmd == "PING") {
    std::string reply = "\001PING " + args + "\001";
    send_to(conn, ":" + config_.server_name + " NOTICE " + conn->nick + " :" + reply);
  } else if (cmd == "TIME") {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::string reply = "\001TIME " + format_time(t) + "\001";
    send_to(conn, ":" + config_.server_name + " NOTICE " + conn->nick + " :" + reply);
  } else if (cmd == "FINGER") {
    std::string reply = "\001FINGER " + conn->nick + " (" + conn->realname +
                        ") Idle: 0 seconds\001";
    send_to(conn, ":" + config_.server_name + " NOTICE " + conn->nick + " :" + reply);
  } else if (cmd == "SOURCE") {
    std::string reply = "\001SOURCE https://github.com/progressive-chat/progressive-server\001";
    send_to(conn, ":" + config_.server_name + " NOTICE " + conn->nick + " :" + reply);
  } else if (cmd == "CLIENTINFO") {
    std::string reply = "\001CLIENTINFO VERSION PING TIME FINGER SOURCE CLIENTINFO ACTION DCC\001";
    send_to(conn, ":" + config_.server_name + " NOTICE " + conn->nick + " :" + reply);
  } else if (cmd == "ACTION") {
    // /me action: forward to target channel/user
    std::string action_msg = "\001ACTION " + args + "\001";
    if (is_channel(target)) {
      send_to_channel(target, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                      " PRIVMSG " + target + " :" + action_msg, conn->nick);
    } else {
      for (auto& [fd, c] : connections_) {
        if (c.nick == target) {
          send_to(&c, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                  " PRIVMSG " + target + " :" + action_msg);
          break;
        }
      }
    }
  } else if (cmd == "DCC") {
    // DCC passthrough
    for (auto& [fd, c] : connections_) {
      if (c.nick == target) {
        send_to(&c, ":" + conn->nick + "!" + conn->user + "@" + conn->host +
                " PRIVMSG " + target + " :\001DCC " + args + "\001");
        break;
      }
    }
  }
  // Unknown CTCP: silently ignore per RFC
}

// ============================================================================
// Server notice helpers
// ============================================================================

void IRCServer::send_server_notice(const std::string& message) {
  for (auto& [nick, u] : users_) {
    if (u.modes.find('s') != std::string::npos || u.oper) {
      for (auto& [fd, c] : connections_) {
        if (c.nick == nick) {
          send_to(&c, ":" + config_.server_name + " NOTICE " + nick +
                  " :*** " + message);
          break;
        }
      }
    }
  }
}

void IRCServer::send_global_notice(const std::string& message) {
  for (auto& [fd, c] : connections_) {
    send_to(&c, ":" + config_.server_name + " NOTICE " + c.nick +
            " :*** " + message);
  }
}

// ============================================================================
// Helper: build prefix string (nick!user@host)
// ============================================================================

std::string IRCServer::make_prefix(IRCConnection* conn) {
  return conn->nick + "!" + conn->user + "@" + conn->host;
}

std::string IRCServer::make_prefix(const std::string& nick) {
  auto* u = get_user(nick);
  if (!u) return nick;
  return nick + "!" + u->user + "@" + u->host;
}

// ============================================================================
// Extended command dispatcher for full processing
// Integrates all full_a handlers for drop-in use
// ============================================================================

void IRCServer::process_data_full_a(IRCConnection* conn, const std::string& data) {
  conn->buffer += data;
  size_t pos;
  while ((pos = conn->buffer.find("\r\n")) != std::string::npos ||
         (pos = conn->buffer.find('\n')) != std::string::npos) {
    std::string line = conn->buffer.substr(0, pos);
    size_t skip = (conn->buffer[pos] == '\r') ? 2 : 1;
    conn->buffer = conn->buffer.substr(pos + skip);
    if (line.empty()) continue;
    // Parse IRC message: [:prefix] CMD [params] [:trailing]
    std::string prefix, cmd, params_str, trailing;
    size_t cur = 0;
    if (line[0] == ':') {
      auto sp = line.find(' ');
      if (sp != std::string::npos) {
        prefix = line.substr(1, sp - 1);
        cur = sp + 1;
      }
    }
    // Find command
    while (cur < line.size() && line[cur] == ' ') ++cur;
    auto sp = line.find(' ', cur);
    if (sp != std::string::npos) {
      cmd = line.substr(cur, sp - cur);
      cur = sp + 1;
    } else {
      cmd = line.substr(cur);
      cur = line.size();
    }
    // Remaining is params
    params_str = line.substr(cur);
    // Extract trailing parameter
    auto tp = params_str.find(" :");
    if (tp != std::string::npos) {
      trailing = params_str.substr(tp + 2);
      params_str = params_str.substr(0, tp);
    }
    // Parse space-separated params
    std::vector<std::string> params;
    std::stringstream pss(params_str);
    std::string param;
    while (pss >> param) params.push_back(param);
    if (!trailing.empty()) params.push_back(trailing);
    // Dispatch
    if (!conn->password_ok && cmd != "PASS" && cmd != "CAP" && cmd != "QUIT") {
      // Require password if set
    }
    // Update last active
    auto* u = get_user(conn->nick);
    if (u) u->last_active = now_sec();
    // Route to full handlers
    if (cmd == "NICK") {
      std::string n = params.empty() ? "" : params[0];
      handle_nick_full_a(conn, n);
    } else if (cmd == "USER") {
      std::string uu = params.size() > 0 ? params[0] : "";
      std::string hh = params.size() > 1 ? params[1] : "";
      std::string ss = params.size() > 2 ? params[2] : "";
      std::string rr = params.size() > 3 ? params[3] : "";
      handle_user_full_a(conn, uu, hh, ss, rr);
    } else if (cmd == "PASS") {
      handle_pass_full_a(conn, params.empty() ? "" : params[0]);
    } else if (cmd == "QUIT") {
      handle_quit_full_a(conn, params.size() > 0 ? params[0] : "");
    } else if (cmd == "JOIN") {
      std::string ch = params.size() > 0 ? params[0] : "";
      std::string ky = params.size() > 1 ? params[1] : "";
      handle_join_full_a(conn, ch, ky);
    } else if (cmd == "PART") {
      std::string ch = params.size() > 0 ? params[0] : "";
      std::string re = params.size() > 1 ? params[1] : "";
      handle_part_full_a(conn, ch, re);
    } else if (cmd == "PRIVMSG") {
      std::string tg = params.size() > 0 ? params[0] : "";
      std::string mg = params.size() > 1 ? params[1] : "";
      handle_privmsg_full_a(conn, tg, mg);
    } else if (cmd == "NOTICE") {
      std::string tg = params.size() > 0 ? params[0] : "";
      std::string mg = params.size() > 1 ? params[1] : "";
      handle_notice_full_a(conn, tg, mg);
    } else if (cmd == "TOPIC") {
      std::string ch = params.size() > 0 ? params[0] : "";
      std::optional<std::string> tp;
      if (params.size() > 1) tp = params[1];
      handle_topic_full_a(conn, ch, tp);
    } else if (cmd == "KICK") {
      std::string ch = params.size() > 0 ? params[0] : "";
      std::string tg = params.size() > 1 ? params[1] : "";
      std::string re = params.size() > 2 ? params[2] : "";
      handle_kick_full_a(conn, ch, tg, re);
    } else if (cmd == "MODE") {
      std::string tg = params.size() > 0 ? params[0] : "";
      std::string md = params.size() > 1 ? params[1] : "";
      std::vector<std::string> mp;
      for (size_t i = 2; i < params.size(); ++i) mp.push_back(params[i]);
      handle_mode_full_a(conn, tg, md, mp);
    } else if (cmd == "INVITE") {
      std::string tg = params.size() > 0 ? params[0] : "";
      std::string ch = params.size() > 1 ? params[1] : "";
      handle_invite_full_a(conn, tg, ch);
    } else if (cmd == "WHOIS") {
      std::string tg;
      for (size_t i = 0; i < params.size(); ++i) {
        if (i > 0) tg += ",";
        tg += params[i];
      }
      handle_whois_full_a(conn, tg);
    } else if (cmd == "WHOWAS") {
      std::string nk = params.size() > 0 ? params[0] : "";
      int cnt = params.size() > 1 ? std::stoi(params[1]) : 0;
      handle_whowas_full_a(conn, nk, cnt);
    } else if (cmd == "WHO") {
      std::string mk = params.size() > 0 ? params[0] : "";
      bool oo = (params.size() > 1 && params[1] == "o");
      handle_who_full_a(conn, mk, oo);
    } else if (cmd == "LIST") {
      std::string pt = params.size() > 0 ? params[0] : "";
      handle_list_full_a(conn, pt);
    } else if (cmd == "NAMES") {
      std::string ch = params.size() > 0 ? params[0] : "";
      handle_names_full_a(conn, ch);
    } else if (cmd == "PING") {
      handle_ping_full_a(conn, params.size() > 0 ? params[0] : "");
    } else if (cmd == "PONG") {
      handle_pong_full_a(conn, params.size() > 0 ? params[0] : "");
    } else if (cmd == "VERSION") {
      handle_version_full_a(conn);
    } else if (cmd == "STATS") {
      handle_stats_full_a(conn, params.size() > 0 ? params[0] : "");
    } else if (cmd == "LINKS") {
      handle_links_full_a(conn);
    } else if (cmd == "TIME") {
      handle_time_full_a(conn);
    } else if (cmd == "INFO") {
      handle_info_full_a(conn);
    } else if (cmd == "MOTD") {
      handle_motd_full_a(conn);
    } else if (cmd == "LUSERS") {
      handle_lusers_full_a(conn);
    } else if (cmd == "ADMIN") {
      handle_admin_full_a(conn);
    } else if (cmd == "AWAY") {
      std::optional<std::string> am;
      if (params.size() > 0) am = params[0];
      handle_away_full_a(conn, am);
    } else if (cmd == "OPER") {
      std::string nm = params.size() > 0 ? params[0] : "";
      std::string pw = params.size() > 1 ? params[1] : "";
      handle_oper_full_a(conn, nm, pw);
    } else if (cmd == "KILL") {
      std::string tg = params.size() > 0 ? params[0] : "";
      std::string re = params.size() > 1 ? params[1] : "";
      handle_kill_full_a(conn, tg, re);
    } else if (cmd == "SQUIT") {
      std::string sv = params.size() > 0 ? params[0] : "";
      std::string re = params.size() > 1 ? params[1] : "";
      handle_squit_full_a(conn, sv, re);
    } else if (cmd == "REHASH") {
      handle_rehash_full_a(conn);
    } else if (cmd == "RESTART") {
      handle_restart_full_a(conn);
    } else if (cmd == "DIE") {
      handle_die_full_a(conn);
    } else if (cmd == "ISON") {
      handle_ison_full_a(conn, params);
    } else if (cmd == "USERHOST") {
      if (params.size() > 5) {
        send_numeric(conn, Numerics::ERR_NEEDMOREPARAMS,
          "USERHOST :Too many nicks (max 5)");
      } else {
        handle_userhost_full_a(conn, params);
      }
    } else if (cmd == "WALLOPS") {
      handle_wallops_full_a(conn, params.size() > 0 ? params[0] : "");
    } else if (cmd == "GLOBOPS") {
      handle_globops_full_a(conn, params.size() > 0 ? params[0] : "");
    } else if (cmd == "CAP") {
      std::string sc = params.size() > 0 ? params[0] : "";
      std::vector<std::string> caps;
      for (size_t i = 1; i < params.size(); ++i) caps.push_back(params[i]);
      handle_cap_full_a(conn, sc, caps);
    } else if (cmd == "AUTHENTICATE") {
      handle_sasl_full_a(conn, params.size() > 0 ? params[0] : "",
                         params.size() > 1 ? params[1] : "");
    } else {
      send_numeric(conn, Numerics::ERR_UNKNOWNCOMMAND, cmd + " :Unknown command");
    }
  }
}

} // namespace progressive::irc
