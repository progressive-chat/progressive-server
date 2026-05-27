// irc_commands.cpp - IRC command handlers with full logic
// Expanding the IRC server to match InspIRCd's feature set

#include "irc_server.hpp"
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <random>
#include <sstream>

namespace progressive::irc {

// ============================================================================
// Full IRC Command Implementations
// ============================================================================

// --- NICK command with full RFC 2812 compliance ---
void IRCServer::handle_nick_full(IRCConnection* conn, const std::string& nick) {
  if (nick.empty()) {
    send_numeric(conn, Numerics::ERR_NONICKNAMEGIVEN, ":No nickname given");
    return;
  }
  if (nick.length() > static_cast<size_t>(config_.max_nick_length)) {
    send_numeric(conn, Numerics::ERR_ERRONEUSNICKNAME, nick + " :Erroneous nickname");
    return;
  }
  // Validate characters (RFC 2812: letter, digit, - [ \ ] ^ _ ` { | } )
  if (nick.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-[]\\^_`{|}") != std::string::npos) {
    send_numeric(conn, Numerics::ERR_ERRONEUSNICKNAME, nick + " :Erroneous nickname");
    return;
  }
  // Check if nick already in use
  auto* existing = get_user(nick);
  if (existing && existing->nick != conn->nick) {
    send_numeric(conn, Numerics::ERR_NICKNAMEINUSE, nick + " :Nickname is already in use");
    return;
  }
  // Process nick change
  if (!conn->registered) {
    conn->nick = nick;
    if (!conn->user.empty() && !conn->host.empty()) {
      conn->registered = true;
      auto* usr = add_user(nick, conn->user, conn->host, conn->realname);
      usr->ip = conn->ip;
      usr->port = conn->port;
      usr->signon_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
      // Send welcome sequence
      send_numeric(conn, Numerics::RPL_WELCOME, ":Welcome to the " + config_.network_name + " IRC Network " + nick + "!" + conn->user + "@" + conn->host);
      send_numeric(conn, Numerics::RPL_YOURHOST, ":Your host is " + config_.server_name + ", running progressive-irc-1.0.0");
      auto now = std::chrono::system_clock::now();
      auto time_t = std::chrono::system_clock::to_time_t(now);
      std::stringstream ss; ss << std::put_time(std::gmtime(&time_t), "%a %b %d %Y at %H:%M:%S %Z");
      send_numeric(conn, Numerics::RPL_CREATED, ":This server was created " + ss.str());
      send_numeric(conn, Numerics::RPL_MYINFO, config_.server_name + " progressive-irc-1.0.0 o o o");
      // Send MOTD
      handle_motd(conn);
      // Notify modules
      for (auto& [name, mod] : modules_) {
        if (mod.on_user_register) mod.on_user_register(conn);
      }
    }
  } else {
    std::string oldnick = conn->nick;
    change_nick(oldnick, nick);
    conn->nick = nick;
    // Notify all channels
    for (auto& [ch_name, ch] : channels_) {
      if (ch.members.count(oldnick)) {
        send_to_channel(ch_name, ":" + oldnick + "!" + conn->user + "@" + conn->host + " NICK :" + nick);
      }
    }
  }
}

// --- JOIN command with full channel management ---
void IRCServer::handle_join_full(IRCConnection* conn, const std::string& channels_str, const std::string& keys_str) {
  if (!conn->registered) {
    send_numeric(conn, Numerics::ERR_NOTREGISTERED, ":You have not registered");
    return;
  }
  // Split channels and keys
  std::vector<std::string> chans, keys;
  std::stringstream css(channels_str), kss(keys_str);
  std::string item;
  while (std::getline(css, item, ',')) { if (!item.empty()) chans.push_back(item); }
  while (std::getline(kss, item, ',')) { keys.push_back(item); }
  
  for (size_t i = 0; i < chans.size(); i++) {
    std::string chname = chans[i];
    std::string key = i < keys.size() ? keys[i] : "";
    
    // Validate channel name
    if (!is_channel(chname)) {
      send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, chname + " :No such channel");
      continue;
    }
    if (chname.length() > 50) {
      send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, chname + " :Channel name too long");
      continue;
    }
    
    // Check channel limit
    if (conn->nick.empty()) continue;
    int user_chan_count = 0;
    for (auto& [cn, ch] : channels_) {
      if (ch.members.count(conn->nick)) user_chan_count++;
    }
    if (user_chan_count >= config_.max_channels) {
      send_numeric(conn, Numerics::ERR_TOOMANYCHANNELS, chname + " :You have joined too many channels");
      continue;
    }
    
    // Get or create channel
    auto* ch = get_channel(chname);
    bool is_new = (ch == nullptr);
    if (is_new) {
      ch = create_channel(chname);
      ch->created_ts = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    }
    
    // Check bans
    for (auto& ban_mask : ch->bans) {
      if (match_ban_mask(conn->nick, conn->user, conn->host, ban_mask)) {
        send_numeric(conn, Numerics::ERR_BANNEDFROMCHAN, chname + " :Cannot join channel (+b)");
        // Run module on_ban check
        bool blocked = false;
        for (auto& [mn, mod] : modules_) {
          if (mod.on_join && !mod.on_join(conn, chname, key)) { blocked = true; break; }
        }
        if (blocked) continue;
        send_numeric(conn, Numerics::ERR_BANNEDFROMCHAN, chname + " :Cannot join channel (+b)");
        continue;
      }
    }
    
    // Check invite-only
    if (ch->modes.find('i') != std::string::npos) {
      if (!ch->invites.count(conn->nick)) {
        send_numeric(conn, Numerics::ERR_INVITEONLYCHAN, chname + " :Cannot join channel (+i)");
        continue;
      }
    }
    
    // Check key
    if (ch->modes.find('k') != std::string::npos) {
      if (key != ch->key) {
        send_numeric(conn, Numerics::ERR_BADCHANNELKEY, chname + " :Cannot join channel (+k)");
        continue;
      }
    }
    
    // Check limit
    if (ch->modes.find('l') != std::string::npos && ch->user_limit > 0) {
      if (static_cast<int64_t>(ch->members.size()) >= ch->user_limit) {
        send_numeric(conn, Numerics::ERR_CHANNELISFULL, chname + " :Cannot join channel (+l)");
        continue;
      }
    }
    
    // Add member
    ch->members.insert(conn->nick);
    if (is_new) {
      ch->member_modes[conn->nick] = "o";  // First user is op
      ch->modes += "nt";  // Default modes: no external messages, topic lock
    }
    
    // Remove from invite list
    ch->invites.erase(conn->nick);
    
    // Send JOIN to channel
    std::string join_msg = ":" + conn->nick + "!" + conn->user + "@" + conn->host + " JOIN :" + chname;
    send_to_channel(chname, join_msg);
    
    // Send topic
    if (!ch->topic.empty()) {
      send_numeric(conn, Numerics::RPL_TOPIC, chname + " :" + ch->topic);
      send_numeric(conn, Numerics::RPL_TOPICWHOTIME, chname + " " + ch->topic_setter + " " + std::to_string(ch->topic_ts));
    } else {
      send_numeric(conn, Numerics::RPL_NOTOPIC, chname + " :No topic is set");
    }
    
    // Send NAMES list
    send_channel_names(conn, chname);
    
    // Send creation time
    send_numeric(conn, Numerics::RPL_CREATIONTIME, chname + " " + std::to_string(ch->created_ts));
  }
}

// --- PRIVMSG with CTCP handling ---
void IRCServer::handle_privmsg_full(IRCConnection* conn, const std::string& target, const std::string& msg) {
  if (target.empty()) { send_numeric(conn, Numerics::ERR_NORECIPIENT, ":No recipient given"); return; }
  if (msg.empty()) { send_numeric(conn, Numerics::ERR_NOTEXTTOSEND, ":No text to send"); return; }
  
  // CTCP detection
  if (msg.size() >= 2 && msg[0] == '\001' && msg.back() == '\001') {
    std::string ctcp = msg.substr(1, msg.size() - 2);
    handle_ctcp(conn, target, ctcp);
    return;
  }
  
  // Channel message
  if (is_channel(target)) {
    auto* ch = get_channel(target);
    if (!ch) { send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, target + " :No such channel"); return; }
    if (!ch->members.count(conn->nick)) {
      // Check if can send external messages
      if (ch->modes.find('n') != std::string::npos) {
        send_numeric(conn, Numerics::ERR_CANNOTSENDTOCHAN, target + " :Cannot send to channel");
        return;
      }
    }
    // Check for moderation
    if (ch->modes.find('m') != std::string::npos) {
      auto it = ch->member_modes.find(conn->nick);
      if (it == ch->member_modes.end() || (it->second.find('o') == std::string::npos && it->second.find('v') == std::string::npos)) {
        send_numeric(conn, Numerics::ERR_CANNOTSENDTOCHAN, target + " :Cannot send to channel (+m)");
        return;
      }
    }
    // Send to all except sender
    send_to_channel(target, ":" + conn->nick + "!" + conn->user + "@" + conn->host + " PRIVMSG " + target + " :" + msg, conn->nick);
  } else {
    // Private message to user
    auto* u = get_user(target);
    if (!u) { send_numeric(conn, Numerics::ERR_NOSUCHNICK, target + " :No such nick/channel"); return; }
    // Check away status
    if (u->away) {
      send_numeric(conn, Numerics::RPL_AWAY, target + " :" + u->away_msg);
    }
    // Deliver to target
    // (in a real server, would write to the user's connection)
  }
}

// --- MODE command - full channel and user modes ---
void IRCServer::handle_mode_full(IRCConnection* conn, const std::string& target, 
    const std::string& mode_str, const std::vector<std::string>& params) {
  if (is_channel(target)) {
    auto* ch = get_channel(target);
    if (!ch) { send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, target + " :No such channel"); return; }
    
    if (mode_str.empty()) {
      // Just query modes
      std::string mode_display = "+" + ch->modes;
      if (ch->modes.find('k') != std::string::npos) mode_display += " " + ch->key;
      if (ch->modes.find('l') != std::string::npos) mode_display += " " + std::to_string(ch->user_limit);
      send_numeric(conn, Numerics::RPL_CHANNELMODEIS, target + " " + mode_display);
      return;
    }
    
    // Parse mode changes
    bool adding = true;
    size_t param_idx = 0;
    std::string applied_modes;
    std::vector<std::string> applied_params;
    
    for (char c : mode_str) {
      if (c == '+') { adding = true; continue; }
      if (c == '-') { adding = false; continue; }
      
      switch (c) {
        case 'o': { // Op/Deop
          if (param_idx < params.size()) {
            std::string target_nick = params[param_idx++];
            if (ch->members.count(target_nick)) {
              if (adding) ch->member_modes[target_nick] += 'o';
              else {
                auto pos = ch->member_modes[target_nick].find('o');
                if (pos != std::string::npos) ch->member_modes[target_nick].erase(pos, 1);
              }
              applied_modes += (adding ? "+" : "-") + std::string(1, c);
              applied_params.push_back(target_nick);
            }
          }
          break;
        }
        case 'v': { // Voice/Devoice
          if (param_idx < params.size()) {
            std::string target_nick = params[param_idx++];
            if (ch->members.count(target_nick)) {
              if (adding) ch->member_modes[target_nick] += 'v';
              else {
                auto pos = ch->member_modes[target_nick].find('v');
                if (pos != std::string::npos) ch->member_modes[target_nick].erase(pos, 1);
              }
              applied_modes += (adding ? "+" : "-") + std::string(1, c);
              applied_params.push_back(target_nick);
            }
          }
          break;
        }
        case 'b': { // Ban
          if (param_idx < params.size()) {
            std::string mask = params[param_idx++];
            if (adding) ch->bans.insert(mask);
            else ch->bans.erase(mask);
            applied_modes += (adding ? "+" : "-") + std::string(1, c);
            applied_params.push_back(mask);
          } else if (!adding) {
            // List bans
            for (auto& b : ch->bans) {
              send_numeric(conn, 367, target + " " + b);
            }
            send_numeric(conn, 368, target + " :End of Channel Ban List");
          }
          break;
        }
        case 'k': { // Key
          if (adding && param_idx < params.size()) {
            ch->key = params[param_idx++];
            ch->modes += 'k';
            applied_modes += "+k";
            applied_params.push_back(ch->key);
          } else if (!adding) {
            ch->key.clear();
            auto pos = ch->modes.find('k');
            if (pos != std::string::npos) ch->modes.erase(pos, 1);
            applied_modes += "-k";
            applied_params.push_back("*");
          }
          break;
        }
        case 'l': { // Limit
          if (adding && param_idx < params.size()) {
            ch->user_limit = std::stoll(params[param_idx++]);
            ch->modes += 'l';
            applied_modes += "+l";
            applied_params.push_back(std::to_string(ch->user_limit));
          } else if (!adding) {
            ch->user_limit = 0;
            auto pos = ch->modes.find('l');
            if (pos != std::string::npos) ch->modes.erase(pos, 1);
            applied_modes += "-l";
          }
          break;
        }
        case 'i': ch->modes += (adding ? "i" : ""); if (!adding) { auto p = ch->modes.find('i'); if (p != std::string::npos) ch->modes.erase(p, 1); } applied_modes += (adding ? "+i" : "-i"); break;
        case 'm': ch->modes += (adding ? "m" : ""); if (!adding) { auto p = ch->modes.find('m'); if (p != std::string::npos) ch->modes.erase(p, 1); } applied_modes += (adding ? "+m" : "-m"); break;
        case 'n': ch->modes += (adding ? "n" : ""); if (!adding) { auto p = ch->modes.find('n'); if (p != std::string::npos) ch->modes.erase(p, 1); } applied_modes += (adding ? "+n" : "-n"); break;
        case 't': ch->modes += (adding ? "t" : ""); if (!adding) { auto p = ch->modes.find('t'); if (p != std::string::npos) ch->modes.erase(p, 1); } applied_modes += (adding ? "+t" : "-t"); break;
        case 's': ch->modes += (adding ? "s" : ""); if (!adding) { auto p = ch->modes.find('s'); if (p != std::string::npos) ch->modes.erase(p, 1); } applied_modes += (adding ? "+s" : "-s"); break;
        case 'p': ch->modes += (adding ? "p" : ""); if (!adding) { auto p = ch->modes.find('p'); if (p != std::string::npos) ch->modes.erase(p, 1); } applied_modes += (adding ? "+p" : "-p"); break;
      }
    }
    
    if (!applied_modes.empty()) {
      std::string mode_msg = ":" + conn->nick + "!" + conn->user + "@" + conn->host + " MODE " + target + " " + applied_modes;
      for (auto& p : applied_params) mode_msg += " " + p;
      send_to_channel(target, mode_msg);
    }
  } else {
    // User modes
    auto* u = get_user(target);
    if (!u || u->nick != conn->nick) { send_numeric(conn, Numerics::ERR_USERSDONTMATCH, ":Cannot change mode for other users"); return; }
    if (mode_str.empty()) {
      send_numeric(conn, 221, "+" + u->modes);
      return;
    }
    // Process user mode changes (i, w, s, o)
    bool adding = true;
    for (char c : mode_str) {
      if (c == '+') { adding = true; continue; }
      if (c == '-') { adding = false; continue; }
      switch (c) {
        case 'i': if (adding) u->modes += 'i'; else { auto p = u->modes.find('i'); if (p != std::string::npos) u->modes.erase(p, 1); } break;
        case 'w': if (adding) u->modes += 'w'; else { auto p = u->modes.find('w'); if (p != std::string::npos) u->modes.erase(p, 1); } break;
        case 's': if (adding) u->modes += 's'; else { auto p = u->modes.find('s'); if (p != std::string::npos) u->modes.erase(p, 1); } break;
      }
    }
    send_to(conn, ":" + conn->nick + " MODE " + conn->nick + " :" + mode_str);
  }
}

// --- WHOIS with multi-server support ---
void IRCServer::handle_whois_full(IRCConnection* conn, const std::string& targets) {
  std::stringstream ss(targets);
  std::string target;
  while (std::getline(ss, target, ',')) {
    auto* u = get_user(target);
    if (!u) {
      send_numeric(conn, Numerics::ERR_NOSUCHNICK, target + " :No such nick/channel");
      continue;
    }
    send_numeric(conn, Numerics::RPL_WHOISUSER, target + " " + u->user + " " + u->host + " * :" + u->realname);
    
    // Channels
    std::string chans;
    for (auto& [cn, ch] : channels_) {
      if (ch.members.count(target)) {
        std::string prefix;
        auto it = ch.member_modes.find(target);
        if (it != ch.member_modes.end()) {
          if (it->second.find('o') != std::string::npos) prefix = "@";
          else if (it->second.find('v') != std::string::npos) prefix = "+";
        }
        if (!chans.empty()) chans += " ";
        chans += prefix + cn;
      }
    }
    if (!chans.empty()) send_numeric(conn, Numerics::RPL_WHOISCHANNELS, target + " :" + chans);
    
    send_numeric(conn, Numerics::RPL_WHOISSERVER, target + " " + config_.server_name + " :" + config_.description);
    
    if (u->oper) send_numeric(conn, Numerics::RPL_WHOISOPERATOR, target + " :is an IRC operator");
    if (u->away) send_numeric(conn, Numerics::RPL_AWAY, target + " :" + u->away_msg);
    
    // Idle time
    int64_t idle = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count() - u->last_active;
    send_numeric(conn, Numerics::RPL_WHOISIDLE, target + " " + std::to_string(idle) + " " + std::to_string(u->signon_time) + " :seconds idle, signon time");
    
    send_numeric(conn, Numerics::RPL_ENDOFWHOIS, target + " :End of /WHOIS list");
  }
}

// --- TOPIC with full timestamp support ---
void IRCServer::handle_topic_full(IRCConnection* conn, const std::string& chname, const std::optional<std::string>& new_topic) {
  auto* ch = get_channel(chname);
  if (!ch) { send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, chname + " :No such channel"); return; }
  if (!ch->members.count(conn->nick)) { send_numeric(conn, Numerics::ERR_NOTONCHANNEL, chname + " :You're not on that channel"); return; }
  
  if (!new_topic) {
    if (ch->topic.empty()) {
      send_numeric(conn, Numerics::RPL_NOTOPIC, chname + " :No topic is set");
    } else {
      send_numeric(conn, Numerics::RPL_TOPIC, chname + " :" + ch->topic);
      send_numeric(conn, Numerics::RPL_TOPICWHOTIME, chname + " " + ch->topic_setter + " " + std::to_string(ch->topic_ts));
    }
    return;
  }
  
  // Check topic lock
  if (ch->modes.find('t') != std::string::npos) {
    auto it = ch->member_modes.find(conn->nick);
    if (it == ch->member_modes.end() || it->second.find('o') == std::string::npos) {
      send_numeric(conn, Numerics::ERR_CHANOPRIVSNEEDED, chname + " :You're not channel operator");
      return;
    }
  }
  
  ch->topic = *new_topic;
  ch->topic_setter = conn->nick + "!" + conn->user + "@" + conn->host;
  ch->topic_ts = std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
  
  send_to_channel(chname, ":" + conn->nick + "!" + conn->user + "@" + conn->host + " TOPIC " + chname + " :" + *new_topic);
}

// --- KICK with reason ---
void IRCServer::handle_kick_full(IRCConnection* conn, const std::string& chname, const std::string& target, const std::string& reason) {
  auto* ch = get_channel(chname);
  if (!ch) { send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, chname + " :No such channel"); return; }
  if (!ch->members.count(conn->nick)) { send_numeric(conn, Numerics::ERR_NOTONCHANNEL, chname + " :You're not on that channel"); return; }
  if (!ch->members.count(target)) { send_numeric(conn, Numerics::ERR_USERNOTINCHANNEL, target + " " + chname + " :They aren't on that channel"); return; }
  
  // Check op status
  auto it = ch->member_modes.find(conn->nick);
  if (it == ch->member_modes.end() || it->second.find('o') == std::string::npos) {
    send_numeric(conn, Numerics::ERR_CHANOPRIVSNEEDED, chname + " :You're not channel operator");
    return;
  }
  
  std::string kick_reason = reason.empty() ? conn->nick : reason;
  if (kick_reason.length() > static_cast<size_t>(config_.max_kick_length)) {
    kick_reason = kick_reason.substr(0, config_.max_kick_length);
  }
  
  send_to_channel(chname, ":" + conn->nick + "!" + conn->user + "@" + conn->host + " KICK " + chname + " " + target + " :" + kick_reason);
  ch->members.erase(target);
  ch->member_modes.erase(target);
}

// --- INVITE command ---
void IRCServer::handle_invite_full(IRCConnection* conn, const std::string& target, const std::string& chname) {
  auto* ch = get_channel(chname);
  if (!ch) { send_numeric(conn, Numerics::ERR_NOSUCHCHANNEL, chname + " :No such channel"); return; }
  if (!ch->members.count(conn->nick)) { send_numeric(conn, Numerics::ERR_NOTONCHANNEL, chname + " :You're not on that channel"); return; }
  
  // Check invite-only
  if (ch->modes.find('i') != std::string::npos) {
    auto it = ch->member_modes.find(conn->nick);
    if (it == ch->member_modes.end() || it->second.find('o') == std::string::npos) {
      send_numeric(conn, Numerics::ERR_CHANOPRIVSNEEDED, chname + " :You're not channel operator");
      return;
    }
  }
  
  auto* u = get_user(target);
  if (!u) { send_numeric(conn, Numerics::ERR_NOSUCHNICK, target + " :No such nick/channel"); return; }
  if (ch->members.count(target)) { send_numeric(conn, Numerics::ERR_USERONCHANNEL, target + " " + chname + " :is already on channel"); return; }
  
  ch->invites.insert(target);
  send_to(conn, ":" + config_.server_name + " 341 " + conn->nick + " " + target + " " + chname);
  // Send INVITE to target
  // (in a real server, deliver to target's connection)
}

// --- Helper: channel NAMES ---
void IRCServer::send_channel_names(IRCConnection* conn, const std::string& chname) {
  auto* ch = get_channel(chname);
  if (!ch) return;
  
  std::string names;
  char symbol = '=';
  if (ch->modes.find('s') != std::string::npos) symbol = '@';
  else if (ch->modes.find('p') != std::string::npos) symbol = '*';
  
  for (auto& nick : ch->members) {
    if (!names.empty()) names += " ";
    auto it = ch->member_modes.find(nick);
    if (it != ch->member_modes.end()) {
      if (it->second.find('o') != std::string::npos) names += "@";
      else if (it->second.find('v') != std::string::npos) names += "+";
    }
    names += nick;
  }
  
  // Split long names into multiple lines if needed (RFC 2812 limit)
  size_t max_line = 400;
  size_t pos = 0;
  while (pos < names.length()) {
    size_t end = std::min(pos + max_line, names.length());
    if (end < names.length()) {
      // Find last space before limit
      size_t last_space = names.rfind(' ', end);
      if (last_space != std::string::npos && last_space > pos) end = last_space;
    }
    std::string line = names.substr(pos, end - pos);
    send_numeric(conn, Numerics::RPL_NAMREPLY, std::string(1, symbol) + " " + chname + " :" + line);
    pos = end;
    if (pos < names.length() && names[pos] == ' ') pos++;
  }
  send_numeric(conn, Numerics::RPL_ENDOFNAMES, chname + " :End of /NAMES list");
}

// --- Helper: CTCP handler ---
void IRCServer::handle_ctcp(IRCConnection* conn, const std::string& target, const std::string& ctcp) {
  std::string cmd = ctcp;
  std::string args;
  auto sp = ctcp.find(' ');
  if (sp != std::string::npos) {
    cmd = ctcp.substr(0, sp);
    args = ctcp.substr(sp + 1);
  }
  
  if (cmd == "VERSION") {
    // Reply to VERSION
    std::string reply = "\001VERSION progressive-irc-1.0.0 " + config_.server_name + " :C++ IRC Server\001";
    send_to(conn, ":" + config_.server_name + " NOTICE " + conn->nick + " :" + reply);
  } else if (cmd == "PING") {
    // Reply to PING
    std::string reply = "\001PING " + args + "\001";
    send_to(conn, ":" + config_.server_name + " NOTICE " + conn->nick + " :" + reply);
  } else if (cmd == "TIME") {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss; ss << std::put_time(std::gmtime(&t), "%a %b %d %H:%M:%S %Y");
    std::string reply = "\001TIME " + ss.str() + "\001";
    send_to(conn, ":" + config_.server_name + " NOTICE " + conn->nick + " :" + reply);
  } else if (cmd == "ACTION") {
    // /me action - just forward as regular message
    std::string action_msg = "\001ACTION " + args + "\001";
    if (is_channel(target)) {
      send_to_channel(target, ":" + conn->nick + "!" + conn->user + "@" + conn->host + " PRIVMSG " + target + " :" + action_msg, conn->nick);
    }
  }
  // Unknown CTCP: silently ignore per RFC
}

// --- Helper: Ban mask matching ---
bool IRCServer::match_ban_mask(const std::string& nick, const std::string& user, const std::string& host, const std::string& mask) {
  // Parse mask: nick!user@host
  std::string full = nick + "!" + user + "@" + host;
  std::string mask_nick = "*", mask_user = "*", mask_host = "*";
  auto ex = mask.find('!');
  auto at = mask.find('@');
  if (ex != std::string::npos) {
    mask_nick = mask.substr(0, ex);
    if (at != std::string::npos) {
      mask_user = mask.substr(ex + 1, at - ex - 1);
      mask_host = mask.substr(at + 1);
    } else {
      mask_user = mask.substr(ex + 1);
    }
  } else if (at != std::string::npos) {
    mask_host = mask.substr(at + 1);
  } else {
    mask_nick = mask;
  }
  
  auto match_part = [](const std::string& str, const std::string& pattern) -> bool {
    if (pattern == "*") return true;
    std::string regex_pattern;
    for (char c : pattern) {
      if (c == '*') regex_pattern += ".*";
      else if (c == '?') regex_pattern += ".";
      else if (c == '.' || c == '+' || c == '^' || c == '$' || c == '\\' || c == '[' || c == ']' || c == '(' || c == ')' || c == '{' || c == '}')
        regex_pattern += '\\' + std::string(1, c);
      else regex_pattern += c;
    }
    return std::regex_match(str, std::regex(regex_pattern, std::regex::icase));
  };
  
  return match_part(nick, mask_nick) && match_part(user, mask_user) && match_part(host, mask_host);
}

} // namespace progressive::irc


// ============================================================
// EXTENDED IRC COMMANDS - Full RFC 2812/2813 implementation
// ============================================================

// ADMIN command - RFC 2812 section 3.4.7
void irc_admin(const std::string& prefix, const std::string& target, IRCServer& server) {
    server.send_numeric(256, prefix, server.servername(), " :Administrative info");
    server.send_numeric(257, prefix, " :Name     : " + server.servername());
    server.send_numeric(258, prefix, " :Nickname : " + server.servername());
    server.send_numeric(259, prefix, " :E-Mail   : admin@" + server.servername());
}

// AWAY command - RFC 2812 section 4.1
void irc_away(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    auto* user = server.get_user(prefix);
    if (!user) return;
    if (params.empty()) {
        user->away_message.clear();
        server.send_numeric(305, prefix, " :You are no longer marked as being away");
    } else {
        user->away_message = params[0];
        server.send_numeric(306, prefix, " :You have been marked as being away");
    }
}

// CONNECT command - RFC 2812 section 3.4.2 (server linking)
void irc_connect(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    if (params.empty()) {
        server.send_numeric(461, prefix, "CONNECT", ":Not enough parameters");
        return;
    }
    std::string target_server = params[0];
    int port = params.size() > 1 ? std::stoi(params[1]) : 6667;
    server.send_notice(prefix, "*** Connecting to " + target_server + ":" + std::to_string(port));
    server.send_numeric(382, prefix, target_server + " :Connecting to server");
}

// DIE command - RFC 2812 section 4.3
void irc_die(const std::string& prefix, IRCServer& server) {
    auto* user = server.get_user(prefix);
    if (!user || !user->is_oper) {
        server.send_numeric(481, prefix, ":Permission Denied- You're not an IRC operator");
        return;
    }
    server.send_notice(prefix, "*** Server shutting down");
    server.shutdown();
}

// ERROR command - RFC 2812 section 3.7.1
void irc_error(const std::string& prefix, const std::string& message, IRCServer& server) {
    server.broadcast(":" + server.servername() + " ERROR :" + message);
}

// HELP command
void irc_help(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    if (params.empty()) {
        server.send_numeric(704, prefix, "index", ":Help topics available:");
        server.send_numeric(705, prefix, "index", ":NICK PRIVMSG JOIN PART QUIT MODE KICK");
        server.send_numeric(705, prefix, "index", ":TOPIC INVITE WHOIS WHOWAS LIST NAMES");
        server.send_numeric(705, prefix, "index", ":PING PONG VERSION TIME USERHOST ISON");
        server.send_numeric(706, prefix, "index", ":End of /HELP");
    } else {
        std::string topic = params[0];
        std::transform(topic.begin(), topic.end(), topic.begin(), ::toupper);
        if (topic == "NICK") server.send_numeric(704, prefix, "NICK", ":Change your nickname - /NICK <newnick>");
        else if (topic == "JOIN") server.send_numeric(704, prefix, "JOIN", ":Join a channel - /JOIN <#channel> [key]");
        else if (topic == "PRIVMSG") server.send_numeric(704, prefix, "PRIVMSG", ":Send a message - /PRIVMSG <target> :<message>");
        else if (topic == "MODE") server.send_numeric(704, prefix, "MODE", ":Change modes - /MODE <target> <modes> [params]");
        else server.send_numeric(704, prefix, topic, ":No help available for that topic");
        server.send_numeric(706, prefix, topic, ":End of /HELP");
    }
}

// INFO command - RFC 2812 section 3.4.10
void irc_info(const std::string& prefix, IRCServer& server) {
    server.send_numeric(371, prefix, ":" + server.servername() + " - Progressive IRC Server");
    server.send_numeric(371, prefix, ":Based on InspIRCd C++ IRC daemon");
    server.send_numeric(371, prefix, ":Supporting Matrix/IRC bridge via progressive-server");
    server.send_numeric(371, prefix, ":For more info: https://progressive-chat.org");
    server.send_numeric(374, prefix, ":End of /INFO list");
}

// ISON command - RFC 2812 section 4.8
void irc_ison(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    std::vector<std::string> online;
    for (const auto& nick : params) {
        for (const auto& [_, user] : server.users()) {
            if (user->nick == nick) {
                online.push_back(nick);
                break;
            }
        }
    }
    std::string resp;
    for (size_t i = 0; i < online.size(); i++) {
        if (i > 0) resp += " ";
        resp += online[i];
    }
    server.send_numeric(303, prefix, ":" + resp);
}

// LINKS command - RFC 2812 section 3.3.2
void irc_links(const std::string& prefix, IRCServer& server) {
    server.send_numeric(364, prefix, server.servername() + " " + server.servername() + " :0 Progressive IRC Server");
    server.send_numeric(365, prefix, "*", ":End of /LINKS list");
}

// LIST command - RFC 2812 section 3.2.6
void irc_list(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    std::string filter;
    if (!params.empty()) filter = params[0];
    
    server.send_numeric(321, prefix, "Channel", ":Users  Name");
    for (const auto& [name, channel] : server.channels()) {
        if (!filter.empty() && name.find(filter) == std::string::npos) continue;
        if (channel->modes.find('s') != std::string::npos && !channel->has_user(prefix)) continue;
        if (channel->modes.find('p') != std::string::npos && !channel->has_user(prefix)) continue;
        std::string topic = channel->topic.empty() ? "No topic set" : channel->topic;
        server.send_numeric(322, prefix, name + " " + std::to_string(channel->users.size()) + " :" + topic);
    }
    server.send_numeric(323, prefix, ":End of /LIST");
}

// LUSERS command - RFC 2812 section 3.4.2
void irc_lusers(const std::string& prefix, IRCServer& server) {
    size_t user_count = server.users().size();
    size_t invisible = 0;
    size_t opers = 0;
    for (const auto& [_, user] : server.users()) {
        if (user->modes.find('i') != std::string::npos) invisible++;
        if (user->is_oper) opers++;
    }
    size_t visible = user_count - invisible;
    
    server.send_numeric(251, prefix, " :There are " + std::to_string(visible) + " users and " + std::to_string(invisible) + " invisible on " + std::to_string(user_count) + " servers");
    server.send_numeric(252, prefix, std::to_string(opers), " :operator(s) online");
    server.send_numeric(253, prefix, "0", " :unknown connection(s)");
    server.send_numeric(254, prefix, std::to_string(server.channels().size()), " :channels formed");
    server.send_numeric(255, prefix, " :I have " + std::to_string(user_count) + " clients and 1 servers");
    server.send_numeric(265, prefix, std::to_string(user_count) + " " + std::to_string(invisible + 1), " :Current local users " + std::to_string(user_count) + ", max " + std::to_string(user_count));
    server.send_numeric(266, prefix, std::to_string(user_count) + " " + std::to_string(invisible + 1), " :Current global users " + std::to_string(user_count) + ", max " + std::to_string(user_count));
}

// MAP command
void irc_map(const std::string& prefix, IRCServer& server) {
    server.send_numeric(15, prefix, server.servername() + " :" + server.servername());
    server.send_numeric(7, prefix, ":End of /MAP");
}

// MOTD command - RFC 2812 section 3.4.1
void irc_motd(const std::string& prefix, IRCServer& server) {
    auto motd_lines = server.get_motd();
    if (motd_lines.empty()) {
        server.send_numeric(422, prefix, ":MOTD File is missing");
        return;
    }
    server.send_numeric(375, prefix, ":- " + server.servername() + " Message of the day -");
    for (const auto& line : motd_lines) {
        server.send_numeric(372, prefix, ":- " + line);
    }
    server.send_numeric(376, prefix, ":End of /MOTD command");
}

// NAMES command - RFC 2812 section 3.2.5
void irc_names(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    if (params.empty()) {
        // List all visible channels
        for (const auto& [name, channel] : server.channels()) {
            if (channel->modes.find('s') != std::string::npos && !channel->has_user(prefix)) continue;
            if (channel->modes.find('p') != std::string::npos && !channel->has_user(prefix)) continue;
            irc_names_single_channel(prefix, name, channel, server);
        }
        
        // Also send users not in any channel
        std::string users_none;
        for (const auto& [_, user] : server.users()) {
            if (user->channels.empty() && user->modes.find('i') == std::string::npos) {
                if (!users_none.empty()) users_none += " ";
                users_none += user->nick;
            }
        }
        if (!users_none.empty()) {
            server.send_numeric(353, prefix, "* *", ":" + users_none);
        }
    } else {
        for (const auto& ch_name : params) {
            auto* ch = server.get_channel(ch_name);
            if (!ch) continue;
            irc_names_single_channel(prefix, ch_name, ch, server);
        }
    }
    server.send_numeric(366, prefix, params.empty() ? "*" : params[0], ":End of /NAMES list");
}

void irc_names_single_channel(const std::string& prefix, const std::string& name, 
                               IRCChannel* ch, IRCServer& server) {
    std::vector<std::string> named_users;
    for (const auto& nick : ch->users) {
        std::string prefix_char;
        if (ch->is_op(nick)) prefix_char = "@";
        else if (ch->is_halfop(nick)) prefix_char = "%";
        else if (ch->is_voice(nick)) prefix_char = "+";
        else if (ch->is_owner(nick)) prefix_char = "~";
        else if (ch->is_admin(nick)) prefix_char = "&";
        named_users.push_back(prefix_char + nick);
    }
    
    // Split into chunks of max NICKLEN
    std::string current_chunk;
    for (const auto& nu : named_users) {
        if (current_chunk.size() + nu.size() + 1 > 400) {
            server.send_numeric(353, prefix, "= " + name, ":" + current_chunk);
            current_chunk.clear();
        }
        if (!current_chunk.empty()) current_chunk += " ";
        current_chunk += nu;
    }
    if (!current_chunk.empty()) {
        server.send_numeric(353, prefix, "= " + name, ":" + current_chunk);
    }
}

// OPER command - RFC 2812 section 3.1.4
void irc_oper(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    if (params.size() < 2) {
        server.send_numeric(461, prefix, "OPER", ":Not enough parameters");
        return;
    }
    std::string name = params[0];
    std::string password = params[1];
    
    if (server.verify_oper(name, password)) {
        auto* user = server.get_user(prefix);
        if (user) {
            user->is_oper = true;
            user->modes += "o";
        }
        server.send_numeric(381, prefix, ":You are now an IRC operator");
        server.send_mode(prefix, prefix, "+o", "");
    } else {
        server.send_numeric(464, prefix, ":Password incorrect");
    }
}

// PART command - RFC 2812 section 3.2.2
void irc_part(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    if (params.empty()) {
        server.send_numeric(461, prefix, "PART", ":Not enough parameters");
        return;
    }
    
    std::string reason = params.size() > 1 ? params[1] : prefix;
    auto channels = split_channels(params[0]);
    
    for (const auto& ch_name : channels) {
        auto* ch = server.get_channel(ch_name);
        if (!ch) {
            server.send_numeric(403, prefix, ch_name, ":No such channel");
            continue;
        }
        if (!ch->has_user(prefix)) {
            server.send_numeric(442, prefix, ch_name, ":You're not on that channel");
            continue;
        }
        
        // Notify channel
        server.broadcast_to_channel(ch_name, ":" + prefix + " PART " + ch_name + " :" + reason, "");
        
        // Remove user from channel
        ch->remove_user(prefix);
        
        // Notify user
        server.send_numeric(0, prefix, "PART", ch_name + " :" + reason);
        
        // Clean up empty channels
        if (ch->users.empty() && ch->modes.find('P') == std::string::npos) {
            server.remove_channel(ch_name);
        }
    }
}

// REHASH command - RFC 2812 section 3.4.9
void irc_rehash(const std::string& prefix, IRCServer& server) {
    auto* user = server.get_user(prefix);
    if (!user || !user->is_oper) {
        server.send_numeric(481, prefix, ":Permission Denied");
        return;
    }
    server.reload_config();
    server.send_numeric(382, prefix, server.config_file + " :Rehashing");
}

// RESTART command - RFC 2812 section 4.4
void irc_restart(const std::string& prefix, IRCServer& server) {
    auto* user = server.get_user(prefix);
    if (!user || !user->is_oper) {
        server.send_numeric(481, prefix, ":Permission Denied");
        return;
    }
    server.send_notice(prefix, "*** Restarting server...");
    server.restart();
}

// SERVER command - RFC 2813 section 2.3 (server-to-server)
void irc_server_link(const std::string& servername, int hopcount, const std::string& info, IRCServer& server) {
    server.add_linked_server(servername, hopcount, info);
    
    // Propagate to other servers
    for (const auto& [name, linked] : server.linked_servers()) {
        if (name != servername) {
            server.send_to_server(name, ":" + server.servername() + " SERVER " + servername + " " + std::to_string(hopcount + 1) + " :" + info);
        }
    }
    
    // Send NETINFO
    server.send_to_server(servername, ":" + server.servername() + " NETINFO " + 
        std::to_string(std::time(nullptr)) + " " +
        std::to_string(server.users().size()) + " " +
        std::to_string(server.channels().size()) + " 0 0 230000 0");
}

// SQUIT command - RFC 2812 section 3.4.1
void irc_squit(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    auto* user = server.get_user(prefix);
    if (!user || !user->is_oper) {
        server.send_numeric(481, prefix, ":Permission Denied");
        return;
    }
    if (params.empty()) {
        server.send_numeric(461, prefix, "SQUIT", ":Not enough parameters");
        return;
    }
    std::string target = params[0];
    std::string reason = params.size() > 1 ? params[1] : "No reason";
    
    server.remove_linked_server(target);
    server.send_to_server(target, ":" + prefix + " SQUIT " + target + " :" + reason);
}

// STATS command - RFC 2812 section 3.4.4
void irc_stats(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    char query = params.empty() ? 'l' : params[0][0];
    
    switch (query) {
        case 'l': case 'L':
            // Link statistics
            for (const auto& [name, linked] : server.linked_servers()) {
                server.send_numeric(211, prefix, name + " " + server.servername() + " 1 0 0 0 :" + linked.info);
            }
            server.send_numeric(219, prefix, std::string(1, query), ":End of STATS report");
            break;
        case 'm': case 'M':
            // Command statistics
            for (const auto& [cmd, count] : server.command_stats()) {
                server.send_numeric(212, prefix, cmd + " " + std::to_string(count));
            }
            server.send_numeric(219, prefix, std::string(1, query), ":End of STATS report");
            break;
        case 'o': case 'O':
            // Operator list
            for (const auto& [_, user] : server.users()) {
                if (user->is_oper) {
                    server.send_numeric(243, prefix, "O " + user->nick + " * " + server.servername());
                }
            }
            server.send_numeric(219, prefix, std::string(1, query), ":End of STATS report");
            break;
        case 'u': case 'U':
            // Server uptime
            server.send_numeric(242, prefix, ":Server Up " + std::to_string(server.uptime_seconds()) + " seconds");
            server.send_numeric(219, prefix, std::string(1, query), ":End of STATS report");
            break;
        default:
            server.send_numeric(219, prefix, std::string(1, query), ":End of STATS report");
    }
}

// SUMMON command - RFC 2812 section 4.5 (deprecated)
void irc_summon(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    server.send_numeric(445, prefix, ":SUMMON has been removed");
}

// TIME command - RFC 2812 section 3.4.6
void irc_time_cmd(const std::string& prefix, IRCServer& server) {
    std::time_t now = std::time(nullptr);
    server.send_numeric(391, prefix, server.servername() + " :" + std::ctime(&now));
}

// TRACE command - RFC 2812 section 3.4.8
void irc_trace(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    std::string target = params.empty() ? server.servername() : params[0];
    
    if (target == server.servername()) {
        for (const auto& [_, user] : server.users()) {
            server.send_numeric(204, prefix, "User " + user->nick + "[" + user->ident + "@" + user->host + "] class 0 " + server.servername());
        }
        server.send_numeric(206, prefix, ":" + server.servername() + " " + server.version_string());
    } else {
        server.send_numeric(402, prefix, target, ":No such server");
    }
}

// USERHOST command - RFC 2812 section 4.9
void irc_userhost(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    std::vector<std::string> responses;
    for (const auto& nick : params) {
        bool found = false;
        for (const auto& [_, user] : server.users()) {
            if (user->nick == nick) {
                std::string resp = nick;
                if (user->is_oper) resp += "*";
                resp += "=" + (user->modes.find('+') != std::string::npos ? "+" : "-") + user->ident + "@" + user->host;
                responses.push_back(resp);
                found = true;
                break;
            }
        }
        if (!found) responses.push_back(nick + "=*");
    }
    
    std::string resp;
    for (size_t i = 0; i < responses.size(); i++) {
        if (i > 0) resp += " ";
        resp += responses[i];
    }
    server.send_numeric(302, prefix, ":" + resp);
}

// USERS command - RFC 2812 section 4.6 (deprecated)
void irc_users(const std::string& prefix, IRCServer& server) {
    server.send_numeric(446, prefix, ":USERS has been removed");
}

// VERSION command - RFC 2812 section 3.4.3
void irc_version_cmd(const std::string& prefix, IRCServer& server) {
    server.send_numeric(351, prefix, server.version_string() + " " + server.servername() + " :" + server.version_description());
}

// WALLOPS command - RFC 2812 section 3.7.2
void irc_wallops(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    auto* user = server.get_user(prefix);
    if (!user || !user->is_oper) {
        server.send_numeric(481, prefix, ":Permission Denied");
        return;
    }
    if (params.empty()) {
        server.send_numeric(461, prefix, "WALLOPS", ":Not enough parameters");
        return;
    }
    std::string msg = params[0];
    for (const auto& [_, u] : server.users()) {
        if (u->modes.find('w') != std::string::npos || u->is_oper) {
            server.send_to_user(u->nick, ":" + prefix + " WALLOPS :" + msg);
        }
    }
}

// WHOWAS command - RFC 2812 section 3.6.3
void irc_whowas(const std::string& prefix, const std::vector<std::string>& params, IRCServer& server) {
    if (params.empty()) {
        server.send_numeric(431, prefix, ":No nickname given");
        return;
    }
    std::string nick = params[0];
    int count = params.size() > 1 ? std::stoi(params[1]) : 0;
    
    auto history = server.get_whowas(nick, count);
    if (history.empty()) {
        server.send_numeric(406, prefix, nick, ":There was no such nickname");
    } else {
        for (const auto& entry : history) {
            server.send_numeric(314, prefix, entry.nick + " " + entry.ident + " " + entry.host + " * :" + entry.realname);
        }
    }
    server.send_numeric(369, prefix, nick, ":End of WHOWAS");
}

// Channel Modes - Full implementation
void apply_channel_mode(const std::string& setter, const std::string& ch_name,
                         char mode, bool adding, const std::string& param,
                         IRCChannel* ch, IRCServer& server) {
    switch (mode) {
        case 'b': { // Ban
            if (adding) {
                ch->bans.push_back(param);
                server.broadcast_to_channel(ch_name, ":" + setter + " MODE " + ch_name + " +b " + param, "");
            } else {
                auto it = std::find(ch->bans.begin(), ch->bans.end(), param);
                if (it != ch->bans.end()) ch->bans.erase(it);
                server.broadcast_to_channel(ch_name, ":" + setter + " MODE " + ch_name + " -b " + param, "");
            }
            break;
        }
        case 'e': { // Ban exception
            if (adding) ch->excepts.push_back(param);
            else {
                auto it = std::find(ch->excepts.begin(), ch->excepts.end(), param);
                if (it != ch->excepts.end()) ch->excepts.erase(it);
            }
            break;
        }
        case 'I': { // Invite exception
            if (adding) ch->invex.push_back(param);
            else {
                auto it = std::find(ch->invex.begin(), ch->invex.end(), param);
                if (it != ch->invex.end()) ch->invex.erase(it);
            }
            break;
        }
        case 'k': { // Key (password)
            if (adding) ch->key = param;
            else ch->key.clear();
            break;
        }
        case 'l': { // User limit
            if (adding) ch->user_limit = std::stoi(param);
            else ch->user_limit = 0;
            break;
        }
        case 'o': { // Channel operator
            if (adding) {
                ch->ops.insert(param);
                ch->halfops.erase(param);
                ch->voices.erase(param);
            } else {
                ch->ops.erase(param);
            }
            break;
        }
        case 'h': { // Half operator
            if (adding) {
                ch->halfops.insert(param);
                ch->voices.insert(param);
            } else {
                ch->halfops.erase(param);
            }
            break;
        }
        case 'v': { // Voice
            if (adding) ch->voices.insert(param);
            else ch->voices.erase(param);
            break;
        }
        case 'q': { // Owner (~)
            if (adding) {
                ch->owners.insert(param);
                ch->ops.insert(param);
            } else ch->owners.erase(param);
            break;
        }
        case 'a': { // Protected/Admin (&)
            if (adding) {
                ch->admins.insert(param);
                ch->ops.insert(param);
            } else ch->admins.erase(param);
            break;
        }
        case 'i': ch->modes = toggle_mode(ch->modes, 'i', adding); break; // Invite-only
        case 'm': ch->modes = toggle_mode(ch->modes, 'm', adding); break; // Moderated
        case 'n': ch->modes = toggle_mode(ch->modes, 'n', adding); break; // No external messages
        case 'p': ch->modes = toggle_mode(ch->modes, 'p', adding); break; // Private
        case 's': ch->modes = toggle_mode(ch->modes, 's', adding); break; // Secret
        case 't': ch->modes = toggle_mode(ch->modes, 't', adding); break; // Topic locked
        case 'r': ch->modes = toggle_mode(ch->modes, 'r', adding); break; // Registered
        case 'c': ch->modes = toggle_mode(ch->modes, 'c', adding); break; // No color
        case 'C': ch->modes = toggle_mode(ch->modes, 'C', adding); break; // No CTCP
        case 'N': ch->modes = toggle_mode(ch->modes, 'N', adding); break; // No nick changes
        case 'M': ch->modes = toggle_mode(ch->modes, 'M', adding); break; // Must be registered
        case 'O': ch->modes = toggle_mode(ch->modes, 'O', adding); break; // Oper only
        case 'P': ch->modes = toggle_mode(ch->modes, 'P', adding); break; // Permanent
        case 'Q': ch->modes = toggle_mode(ch->modes, 'Q', adding); break; // No kicks
        case 'R': ch->modes = toggle_mode(ch->modes, 'R', adding); break; // Registered only
        case 'S': ch->modes = toggle_mode(ch->modes, 'S', adding); break; // SSL only
        case 'T': ch->modes = toggle_mode(ch->modes, 'T', adding); break; // No notices
        case 'z': ch->modes = toggle_mode(ch->modes, 'z', adding); break; // Secure/SSL
        case 'Z': ch->modes = toggle_mode(ch->modes, 'Z', adding); break; // All users SSL
    }
}

std::string toggle_mode(const std::string& modes, char mode, bool adding) {
    std::string result = modes;
    auto pos = result.find(mode);
    if (adding && pos == std::string::npos) {
        result += mode;
    } else if (!adding && pos != std::string::npos) {
        result.erase(pos, 1);
    }
    return result;
}

// User Mode implementation
void apply_user_mode(const std::string& setter, const std::string& target_nick,
                      char mode, bool adding, IRCUser* user, IRCServer& server) {
    switch (mode) {
        case 'i': // Invisible
            user->modes = toggle_mode(user->modes, 'i', adding);
            break;
        case 'w': // Wallops
            user->modes = toggle_mode(user->modes, 'w', adding);
            break;
        case 'o': // Operator
            if (adding) {
                user->is_oper = true;
                user->modes += "o";
                server.send_to_user(target_nick, ":" + setter + " MODE " + target_nick + " :+o");
            } else {
                user->is_oper = false;
                user->modes = toggle_mode(user->modes, 'o', false);
                server.send_to_user(target_nick, ":" + setter + " MODE " + target_nick + " :-o");
            }
            break;
        case 's': // Server notices
            user->modes = toggle_mode(user->modes, 's', adding);
            break;
        case 'x': // Cloaked host
            user->modes = toggle_mode(user->modes, 'x', adding);
            break;
        case 'B': // Bot
            user->modes = toggle_mode(user->modes, 'B', adding);
            break;
        case 'G': // Censor
            user->modes = toggle_mode(user->modes, 'G', adding);
            break;
        case 'H': // Hide oper
            user->modes = toggle_mode(user->modes, 'H', adding);
            break;
        case 'I': // Hide channels
            user->modes = toggle_mode(user->modes, 'I', adding);
            break;
        case 'R': // Registered only PM
            user->modes = toggle_mode(user->modes, 'R', adding);
            break;
        case 'W': // Who is message
            user->modes = toggle_mode(user->modes, 'W', adding);
            break;
        case 'Z': // SSL
            user->modes = toggle_mode(user->modes, 'Z', adding);
            break;
    }
}

// Full KICK implementation with reason
void irc_kick_full(IRCServer& server, const std::string& prefix,
                    const std::string& channel, const std::string& target,
                    const std::string& reason) {
    auto* ch = server.get_channel(channel);
    if (!ch) {
        server.send_numeric(403, prefix, channel, ":No such channel");
        return;
    }
    if (!ch->has_user(prefix)) {
        server.send_numeric(442, prefix, channel, ":You're not on that channel");
        return;
    }
    if (!ch->is_op(prefix) && !ch->is_halfop(prefix) && !ch->is_owner(prefix)) {
        server.send_numeric(482, prefix, channel, ":You're not channel operator");
        return;
    }
    if (!ch->has_user(target)) {
        server.send_numeric(441, prefix, target + " " + channel, ":They aren't on that channel");
        return;
    }
    if (ch->is_owner(target) && !ch->is_owner(prefix)) {
        server.send_numeric(482, prefix, channel, ":Cannot kick channel owner");
        return;
    }
    
    std::string kick_reason = reason.empty() ? prefix : reason;
    server.broadcast_to_channel(channel, ":" + prefix + " KICK " + channel + " " + target + " :" + kick_reason, "");
    ch->remove_user(target);
    ch->ops.erase(target);
    ch->halfops.erase(target);
    ch->voices.erase(target);
}

// Split comma-separated channels
std::vector<std::string> split_channels(const std::string& input) {
    std::vector<std::string> result;
    std::stringstream ss(input);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (!item.empty()) result.push_back(item);
    }
    return result;
}

// NICK collision detection
bool is_nick_collision(const std::string& nick, IRCServer& server) {
    for (const auto& [_, user] : server.users()) {
        if (iequals(user->nick, nick)) return true;
    }
    return false;
}

bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (std::tolower(a[i]) != std::tolower(b[i])) return false;
    }
    return true;
}

// Server-side NOTICE routing
void irc_server_notice(IRCServer& server, const std::string& from, 
                        const std::string& target, const std::string& message) {
    // Try user first
    auto* user = server.get_user(target);
    if (user) {
        server.send_to_user(target, ":" + from + " NOTICE " + target + " :" + message);
        return;
    }
    // Try channel
    auto* ch = server.get_channel(target);
    if (ch) {
        for (const auto& nick : ch->users) {
            if (nick != from) {
                server.send_to_user(nick, ":" + from + " NOTICE " + target + " :" + message);
            }
        }
        return;
    }
    // Try server
    server.send_to_server(target, ":" + from + " NOTICE " + target + " :" + message);
}

// CTCP handling
void handle_ctcp(IRCServer& server, const std::string& prefix,
                  const std::string& target, const std::string& ctcp_command,
                  const std::string& ctcp_params) {
    if (ctcp_command == "VERSION") {
        server.send_notice(prefix, "VERSION " + server.version_string() + "");
    } else if (ctcp_command == "PING") {
        server.send_notice(prefix, "PING " + ctcp_params + "");
    } else if (ctcp_command == "TIME") {
        std::time_t now = std::time(nullptr);
        server.send_notice(prefix, "TIME " + std::string(std::ctime(&now)) + "");
    } else if (ctcp_command == "FINGER") {
        server.send_notice(prefix, "FINGER " + server.servername() + " IRC Server");
    } else if (ctcp_command == "SOURCE") {
        server.send_notice(prefix, "SOURCE https://progressive-chat.org");
    } else if (ctcp_command == "CLIENTINFO") {
        server.send_notice(prefix, "CLIENTINFO VERSION PING TIME FINGER SOURCE ACTION DCC");
    } else if (ctcp_command == "ACTION") {
        // /me actions just get forwarded normally
        auto* ch = server.get_channel(target);
        if (ch) {
            server.broadcast_to_channel(target, ":" + prefix + " PRIVMSG " + target + " :ACTION " + ctcp_params + "", prefix);
        }
    } else if (ctcp_command == "DCC") {
        // DCC chat/file transfer - just forward
        auto* user = server.get_user(target);
        if (user) {
            server.send_to_user(target, ":" + prefix + " PRIVMSG " + target + " :DCC " + ctcp_params + "");
        }
    }
}

// Ban mask parsing and matching
bool match_ban_mask(const std::string& mask, const std::string& nick,
                     const std::string& ident, const std::string& host) {
    std::string user_mask = nick + "!" + ident + "@" + host;
    return wildcard_match(mask, user_mask);
}

bool wildcard_match(const std::string& pattern, const std::string& str) {
    size_t pi = 0, si = 0;
    size_t pmatch = 0, smatch = 0;
    
    while (si < str.size()) {
        if (pi < pattern.size() && (pattern[pi] == '?' || pattern[pi] == str[si])) {
            pi++; si++;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
            pmatch = ++pi;
            smatch = si;
        } else if (pmatch > 0) {
            pi = pmatch;
            smatch++;
            si = smatch;
        } else {
            return false;
        }
    }
    
    while (pi < pattern.size() && pattern[pi] == '*') pi++;
    return pi == pattern.size();
}

// Channel ban checking
bool is_banned(IRCChannel* ch, const std::string& nick,
                const std::string& ident, const std::string& host) {
    for (const auto& ban : ch->bans) {
        if (match_ban_mask(ban, nick, ident, host)) {
            // Check if excepted from ban
            bool excepted = false;
            for (const auto& exc : ch->excepts) {
                if (match_ban_mask(exc, nick, ident, host)) {
                    excepted = true;
                    break;
                }
            }
            if (!excepted) return true;
        }
    }
    return false;
}

// Server link data management
void irc_burst(IRCServer& server, const std::string& target_server) {
    // Send all local users to the new server
    for (const auto& [_, user] : server.users()) {
        server.send_to_server(target_server, 
            ":" + server.servername() + " UID " + user->nick + " 1 " + 
            std::to_string(std::time(nullptr)) + " +" + user->modes + " " +
            user->ident + " " + user->host + " 0 " + user->uid + " :" + user->realname);
    }
    
    // Send all channels
    for (const auto& [name, ch] : server.channels()) {
        server.send_to_server(target_server,
            ":" + server.servername() + " SJOIN " + std::to_string(std::time(nullptr)) +
            " " + name + " +" + ch->modes + " :" + channel_members_string(ch));
    }
    
    server.send_to_server(target_server,
        ":" + server.servername() + " BURST " + std::to_string(std::time(nullptr)));
}

std::string channel_members_string(IRCChannel* ch) {
    std::string result;
    for (const auto& nick : ch->users) {
        if (!result.empty()) result += " ";
        if (ch->is_owner(nick)) result += "~";
        else if (ch->is_admin(nick)) result += "&";
        else if (ch->is_op(nick)) result += "@";
        else if (ch->is_halfop(nick)) result += "%";
        else if (ch->is_voice(nick)) result += "+";
        result += nick;
    }
    return result;
}

// UID generation (TS6-style)
std::string generate_uid(IRCServer& server) {
    static int uid_counter = 0;
    std::string sid = server.sid().empty() ? "000" : server.sid();
    char buf[10];
    snprintf(buf, sizeof(buf), "%s%06d", sid.c_str(), uid_counter++);
    return buf;
}

// SID management
void set_server_sid(IRCServer& server, const std::string& sid) {
    server.set_sid(sid);
}

// NOTICE to all opers (snotices)
void snotice(IRCServer& server, const std::string& message) {
    for (const auto& [_, user] : server.users()) {
        if (user->is_oper && user->modes.find('s') != std::string::npos) {
            server.send_to_user(user->nick, ":" + server.servername() + " NOTICE " + user->nick + " :*** " + message);
        }
    }
}

// Global notice
void global_notice(IRCServer& server, const std::string& message) {
    for (const auto& [_, user] : server.users()) {
        server.send_to_user(user->nick, ":" + server.servername() + " NOTICE " + user->nick + " :*** " + message);
    }
}

// Server quit (removes a user from all channels)
void server_quit(IRCServer& server, const std::string& nick, const std::string& reason) {
    auto* user = server.get_user(nick);
    if (!user) return;
    
    std::string quit_reason = reason.empty() ? "Quit: " + nick : reason;
    
    // Notify all channels
    for (const auto& ch_name : user->channels) {
        server.broadcast_to_channel(ch_name, ":" + nick + " QUIT :" + quit_reason, "");
        auto* ch = server.get_channel(ch_name);
        if (ch) {
            ch->remove_user(nick);
            ch->ops.erase(nick);
            ch->halfops.erase(nick);
            ch->voices.erase(nick);
            ch->owners.erase(nick);
            ch->admins.erase(nick);
            
            if (ch->users.empty() && ch->modes.find('P') == std::string::npos) {
                server.remove_channel(ch_name);
            }
        }
    }
    
    server.remove_user(nick);
}

// ============================================================
// End of extended IRC commands
// ============================================================
