// irc_full_c.cpp — Services (NickServ/ChanServ/HostServ/OperServ), extended modes,
// WHOX, metadata, watch/monitor, message tags, STARTTLS/STS, WebSocket gateway
// References: RFC 1459, 2812, 2813, IRCv3.x specs, Atheme/Anope services, InspIRCd
#include "irc_server.hpp"
#include "parser.hpp"
#include "services.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace progressive::irc {

using json = nlohmann::json;

// ============================================================================
// Utility helpers
// ============================================================================
static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}
static int64_t now_sec() { return now_ms() / 1000; }

static std::string to_upper(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return s;
}
static std::string to_lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

static std::string sha256(const std::string&) {
  // Stub — real implementation would use openssl
  return "sha256-stub";
}

// ============================================================================
// SECTION 1: HostServ — vHost Management
// ============================================================================

class HostServManager {
public:
  struct VHostEntry {
    std::string account;
    std::string vhost;         // virtual host to display
    std::string real_host;     // actual host for logging
    std::string real_ip;       // actual IP for logging
    bool active = true;
    int64_t set_at = 0;
    std::string set_by;        // who set it (user or oper)
  };

  // Request a vHost
  bool request_vhost(const std::string& account, const std::string& desired_vhost) {
    auto key = to_lower(account);
    if (pending_requests_.count(key)) return false;
    pending_requests_[key] = {account, desired_vhost, "", "", false, now_sec(), account};
    return true;
  }

  // Oper approves a vHost request
  bool approve_vhost(const std::string& account) {
    auto key = to_lower(account);
    auto it = pending_requests_.find(key);
    if (it == pending_requests_.end()) return false;
    VHostEntry entry = it->second;
    entry.active = true;
    host_map_[key] = entry;
    pending_requests_.erase(it);
    return true;
  }

  // Oper rejects a vHost request
  bool reject_vhost(const std::string& account, const std::string& reason) {
    auto key = to_lower(account);
    rejected_[key] = reason;
    return pending_requests_.erase(key) > 0;
  }

  // Oper directly assigns a vHost
  bool set_vhost(const std::string& account, const std::string& vhost,
                 const std::string& set_by) {
    auto key = to_lower(account);
    VHostEntry entry;
    entry.account = account;
    entry.vhost = vhost;
    entry.active = true;
    entry.set_at = now_sec();
    entry.set_by = set_by;
    host_map_[key] = entry;
    return true;
  }

  // Remove vHost assignment
  bool del_vhost(const std::string& account) {
    auto key = to_lower(account);
    return host_map_.erase(key) > 0;
  }

  // Activate/deactivate a vHost
  bool set_active(const std::string& account, bool active) {
    auto key = to_lower(account);
    auto it = host_map_.find(key);
    if (it == host_map_.end()) return false;
    it->second.active = active;
    return true;
  }

  // Get vHost for an account
  std::string get_vhost(const std::string& account) {
    auto it = host_map_.find(to_lower(account));
    if (it != host_map_.end() && it->second.active)
      return it->second.vhost;
    return "";
  }

  // Get pending requests list
  std::vector<VHostEntry> list_pending() {
    std::vector<VHostEntry> result;
    for (auto& [k, v] : pending_requests_) result.push_back(v);
    return result;
  }

  // Get all active vHosts
  std::vector<VHostEntry> list_all() {
    std::vector<VHostEntry> result;
    for (auto& [k, v] : host_map_) if (v.active) result.push_back(v);
    return result;
  }

  // Log real host/IP for a connection
  void log_connection(const std::string& account, const std::string& real_host,
                      const std::string& real_ip) {
    auto key = to_lower(account);
    auto it = host_map_.find(key);
    if (it != host_map_.end()) {
      it->second.real_host = real_host;
      it->second.real_ip = real_ip;
    }
    connection_log_[key].push_back({
      real_host, real_ip, now_sec(), account
    });
    // Keep last 100 entries
    while (connection_log_[key].size() > 100)
      connection_log_[key].pop_front();
  }

  // Get last connection info
  struct ConnectionRecord {
    std::string host;
    std::string ip;
    int64_t timestamp;
    std::string account;
  };
  std::vector<ConnectionRecord> get_connection_log(const std::string& account) {
    auto key = to_lower(account);
    auto it = connection_log_.find(key);
    if (it == connection_log_.end()) return {};
    return {it->second.begin(), it->second.end()};
  }

private:
  std::map<std::string, VHostEntry, std::less<>> host_map_;
  std::map<std::string, VHostEntry, std::less<>> pending_requests_;
  std::map<std::string, std::string, std::less<>> rejected_;
  std::map<std::string, std::deque<ConnectionRecord>, std::less<>> connection_log_;
};

// ============================================================================
// SECTION 2: Extended Account Manager (NickServ backend)
// ============================================================================

class AccountManagerFull {
public:
  struct UserAccount {
    std::string name;
    std::string email;
    std::string password_hash;
    std::string certfp;
    int64_t registered_at = 0;
    int64_t last_seen = 0;
    int64_t last_identified = 0;
    bool suspended = false;
    bool frozen = false;         // NickServ FREEZE
    bool no_expire = false;      // NickServ SET NOEXPIRE
    bool private_info = false;   // NickServ SET PRIVATE
    bool kill_on_identify = false;
    bool enforce = false;        // NickServ SET ENFORCE
    std::string enroll_to;       // For grouped nicks
    std::string language;        // NickServ SET LANGUAGE
    std::set<std::string> access_list;
    std::vector<std::string> memos;
    std::string autojoin_channels;
    int64_t holiday_start = 0;   // NickServ HOLIDAY
    int64_t holiday_end = 0;
    std::string holiday_msg;
    bool identified = false;
  };

  bool register_account(const std::string& name, const std::string& email,
                        const std::string& password) {
    auto key = to_lower(name);
    if (accounts_.count(key)) return false;
    UserAccount acct;
    acct.name = name;
    acct.email = email;
    acct.password_hash = "hash:" + password; // TODO: bcrypt
    acct.registered_at = now_sec();
    acct.last_seen = now_sec();
    accounts_[key] = acct;
    return true;
  }

  bool identify(const std::string& name, const std::string& password) {
    auto key = to_lower(name);
    auto it = accounts_.find(key);
    if (it == accounts_.end() || it->second.suspended || it->second.frozen)
      return false;
    if (it->second.password_hash != "hash:" + password)
      return false;
    it->second.last_identified = now_sec();
    it->second.last_seen = now_sec();
    it->second.identified = true;
    return true;
  }

  bool logout(const std::string& name) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return false;
    it->second.identified = false;
    return true;
  }

  // NickServ SET commands
  bool set_email(const std::string& name, const std::string& email) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return false;
    it->second.email = email;
    return true;
  }

  bool set_password(const std::string& name, const std::string& newpass) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return false;
    it->second.password_hash = "hash:" + newpass;
    return true;
  }

  bool set_no_expire(const std::string& name, bool val) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return false;
    it->second.no_expire = val;
    return true;
  }

  bool set_private(const std::string& name, bool val) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return false;
    it->second.private_info = val;
    return true;
  }

  bool set_enforce(const std::string& name, bool val) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return false;
    it->second.enforce = val;
    return true;
  }

  bool set_language(const std::string& name, const std::string& lang) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return false;
    it->second.language = lang;
    return true;
  }

  // NickServ HOLIDAY
  bool set_holiday(const std::string& name, int64_t start_ts, int64_t end_ts,
                   const std::string& msg) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return false;
    it->second.holiday_start = start_ts;
    it->second.holiday_end = end_ts;
    it->second.holiday_msg = msg;
    return true;
  }

  bool is_on_holiday(const std::string& name) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return false;
    int64_t now = now_sec();
    return now >= it->second.holiday_start && now <= it->second.holiday_end;
  }

  std::string get_holiday_msg(const std::string& name) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return "";
    return it->second.holiday_msg;
  }

  // NickServ DROP
  bool drop_account(const std::string& name) {
    return accounts_.erase(to_lower(name)) > 0;
  }

  // NickServ INFO (detailed)
  std::string get_info(const std::string& name) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return "";
    std::stringstream ss;
    ss << "Nickname: " << it->second.name << " | ";
    ss << "Registered: " << it->second.registered_at << " | ";
    ss << "Last seen: " << it->second.last_seen << " | ";
    if (it->second.holiday_start > 0)
      ss << "Holiday: " << it->second.holiday_msg << " | ";
    if (!it->second.email.empty())
      ss << "Email: " << it->second.email << " | ";
    ss << "Flags:";
    if (it->second.identified) ss << " identified";
    if (it->second.no_expire) ss << " no-expire";
    if (it->second.private_info) ss << " private";
    if (it->second.enforce) ss << " enforce";
    if (it->second.suspended) ss << " suspended";
    return ss.str();
  }

  // Send memo
  bool send_memo(const std::string& from, const std::string& to,
                 const std::string& message) {
    auto it = accounts_.find(to_lower(to));
    if (it == accounts_.end()) return false;
    std::stringstream ss;
    ss << "[" << now_sec() << "] " << from << ": " << message;
    it->second.memos.push_back(ss.str());
    return true;
  }

  // Read memos
  std::vector<std::string> read_memos(const std::string& name, bool clear = false) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return {};
    auto ms = it->second.memos;
    if (clear) it->second.memos.clear();
    return ms;
  }

  bool is_registered(const std::string& name) {
    auto it = accounts_.find(to_lower(name));
    return it != accounts_.end() && !it->second.suspended;
  }

  bool is_identified(const std::string& name) {
    auto it = accounts_.find(to_lower(name));
    return it != accounts_.end() && it->second.identified;
  }

  UserAccount* get_account(const std::string& name) {
    auto it = accounts_.find(to_lower(name));
    return it != accounts_.end() ? &it->second : nullptr;
  }

  // OperServ only
  bool suspend(const std::string& name) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return false;
    it->second.suspended = true;
    return true;
  }
  bool unsuspend(const std::string& name) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return false;
    it->second.suspended = false;
    return true;
  }
  bool freeze(const std::string& name) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return false;
    it->second.frozen = true;
    return true;
  }
  bool unfreeze(const std::string& name) {
    auto it = accounts_.find(to_lower(name));
    if (it == accounts_.end()) return false;
    it->second.frozen = false;
    return true;
  }

private:
  std::map<std::string, UserAccount, std::less<>> accounts_;
};

// ============================================================================
// SECTION 3: Channel Registration with Extended Access
// ============================================================================

class ChannelRegistrationFull {
public:
  // Channel access levels
  static constexpr int ACCESS_FOUNDER = 100;   // FOUNDER ~
  static constexpr int ACCESS_SOP     = 50;    // SOP (SuperOP) &
  static constexpr int ACCESS_AOP     = 40;    // AOP (AutoOP) @ -> o
  static constexpr int ACCESS_HOP     = 30;    // HOP (HalfOP) %
  static constexpr int ACCESS_VOP     = 20;    // VOP (Voice) +
  static constexpr int ACCESS_NONE    = 0;

  struct ChannelInfo {
    std::string name;
    std::string founder;
    int64_t registered_at = 0;
    int64_t last_used = 0;
    std::string entry_message;
    std::map<std::string, int, std::less<>> access_list; // nick -> level
    std::map<int, std::string> level_names = {
      {ACCESS_FOUNDER, "FOUNDER"},
      {ACCESS_SOP, "SOP"},
      {ACCESS_AOP, "AOP"},
      {ACCESS_HOP, "HOP"},
      {ACCESS_VOP, "VOP"}
    };
    bool secure = false;        // +s mode enforced
    bool verbose = false;       // verbose ops
    bool keep_topic = false;    // KEEPTOPIC
    bool topic_lock = false;    // TOPICLOCK
    bool no_expire = false;
    bool no_autoop = false;
    std::string successor;
    int64_t expire_at = 0;
    std::vector<std::string> akick_list; // Auto-kick
    std::string url;
    std::string email;
  };

  bool register_channel(const std::string& name, const std::string& founder) {
    auto key = to_lower(name);
    if (channels_.count(key)) return false;
    ChannelInfo info;
    info.name = name;
    info.founder = founder;
    info.registered_at = now_sec();
    info.access_list[founder] = ACCESS_FOUNDER;
    channels_[key] = info;
    return true;
  }

  bool drop_channel(const std::string& name) {
    return channels_.erase(to_lower(name)) > 0;
  }

  bool is_registered(const std::string& name) {
    return channels_.count(to_lower(name));
  }

  std::string get_founder(const std::string& name) {
    auto it = channels_.find(to_lower(name));
    return it != channels_.end() ? it->second.founder : "";
  }

  // Access management
  bool set_access(const std::string& channel, const std::string& nick, int level) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return false;
    if (level == 0) {
      it->second.access_list.erase(nick);
    } else {
      it->second.access_list[nick] = level;
    }
    return true;
  }

  int get_access(const std::string& channel, const std::string& nick) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return 0;
    auto ait = it->second.access_list.find(nick);
    return ait != it->second.access_list.end() ? ait->second : 0;
  }

  static const char* access_level_name(int level) {
    if (level >= ACCESS_FOUNDER) return "FOUNDER";
    if (level >= ACCESS_SOP) return "SOP";
    if (level >= ACCESS_AOP) return "AOP";
    if (level >= ACCESS_HOP) return "HOP";
    if (level >= ACCESS_VOP) return "VOP";
    return "";
  }

  static char access_level_prefix(int level) {
    if (level >= ACCESS_FOUNDER) return '~';
    if (level >= ACCESS_SOP) return '&';
    if (level >= ACCESS_AOP) return '@';
    if (level >= ACCESS_HOP) return '%';
    if (level >= ACCESS_VOP) return '+';
    return 0;
  }

  // AKick (auto-kick) management
  bool add_akick(const std::string& channel, const std::string& mask) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return false;
    it->second.akick_list.push_back(mask);
    return true;
  }
  bool del_akick(const std::string& channel, const std::string& mask) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return false;
    auto& list = it->second.akick_list;
    auto pos = std::find(list.begin(), list.end(), mask);
    if (pos == list.end()) return false;
    list.erase(pos);
    return true;
  }
  std::vector<std::string> get_akicks(const std::string& channel) {
    auto it = channels_.find(to_lower(channel));
    return it != channels_.end() ? it->second.akick_list : std::vector<std::string>{};
  }

  // ChanServ SET
  bool set_entrymsg(const std::string& channel, const std::string& msg) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return false;
    it->second.entry_message = msg;
    return true;
  }
  bool set_secure(const std::string& channel, bool val) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return false;
    it->second.secure = val;
    return true;
  }
  bool set_verbose(const std::string& channel, bool val) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return false;
    it->second.verbose = val;
    return true;
  }
  bool set_keeptopic(const std::string& channel, bool val) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return false;
    it->second.keep_topic = val;
    return true;
  }
  bool set_topiclock(const std::string& channel, bool val) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return false;
    it->second.topic_lock = val;
    return true;
  }
  bool set_successor(const std::string& channel, const std::string& nick) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return false;
    it->second.successor = nick;
    return true;
  }
  bool set_no_expire(const std::string& channel, bool val) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return false;
    it->second.no_expire = val;
    return true;
  }
  bool set_url(const std::string& channel, const std::string& url) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return false;
    it->second.url = url;
    return true;
  }
  bool set_email(const std::string& channel, const std::string& email) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return false;
    it->second.email = email;
    return true;
  }

  // ChanServ INFO
  std::string get_info(const std::string& channel) {
    auto it = channels_.find(to_lower(channel));
    if (it == channels_.end()) return "";
    auto& ci = it->second;
    std::stringstream ss;
    ss << "Channel: " << ci.name << " | Founder: " << ci.founder;
    ss << " | Registered: " << ci.registered_at;
    ss << " | Last used: " << ci.last_used;
    if (!ci.url.empty()) ss << " | URL: " << ci.url;
    if (!ci.email.empty()) ss << " | Email: " << ci.email;
    if (ci.secure) ss << " | Secure";
    if (ci.verbose) ss << " | Verbose";
    if (ci.no_expire) ss << " | NoExpire";
    if (ci.keep_topic) ss << " | KeepTopic";
    if (!ci.entry_message.empty()) ss << " | Entry: " << ci.entry_message;
    ss << " | Access entries: " << ci.access_list.size();
    return ss.str();
  }

  // Get all registrations for a user
  std::vector<std::string> get_channels_for(const std::string& nick) {
    std::vector<std::string> result;
    for (auto& [k, v] : channels_) {
      if (to_lower(v.founder) == to_lower(nick)) result.push_back(v.name);
      // Also check if they have access
      if (v.access_list.count(nick)) result.push_back(v.name);
    }
    return result;
  }

  void touch_channel(const std::string& name) {
    auto it = channels_.find(to_lower(name));
    if (it != channels_.end()) it->second.last_used = now_sec();
  }

private:
  std::map<std::string, ChannelInfo, std::less<>> channels_;
};

// ============================================================================
// SECTION 4: OperServ — Operator Services
// ============================================================================

class OperServManager {
public:
  // == KLINE: Kill line (IP/hostname based ban) ==
  struct KLine {
    std::string mask;
    std::string reason;
    int64_t set_at;
    int64_t expires_at; // 0 = permanent
    std::string set_by;
  };

  bool add_kline(const std::string& mask, const std::string& reason,
                 const std::string& set_by, int64_t duration_secs = 0) {
    auto key = to_lower(mask);
    if (klines_.count(key)) return false;
    klines_[key] = {mask, reason, now_sec(),
                    duration_secs > 0 ? now_sec() + duration_secs : 0, set_by};
    return true;
  }
  bool del_kline(const std::string& mask) {
    return klines_.erase(to_lower(mask)) > 0;
  }
  bool check_kline(const std::string& match) {
    int64_t now = now_sec();
    for (auto& [k, v] : klines_) {
      if (v.expires_at > 0 && now > v.expires_at) continue; // expired
      if (wildcard_match(v.mask, match)) return true;
    }
    return false;
  }

  // == ZLINE: IP-based ban ==
  struct ZLine {
    std::string ip_mask;
    std::string reason;
    int64_t set_at;
    int64_t expires_at;
    std::string set_by;
  };

  bool add_zline(const std::string& ip, const std::string& reason,
                 const std::string& set_by, int64_t duration = 0) {
    zlines_[ip] = {ip, reason, now_sec(),
                   duration > 0 ? now_sec() + duration : 0, set_by};
    return true;
  }
  bool del_zline(const std::string& ip) { return zlines_.erase(ip) > 0; }
  bool check_zline(const std::string& ip) {
    int64_t now = now_sec();
    auto it = zlines_.find(ip);
    if (it != zlines_.end()) {
      if (it->second.expires_at > 0 && now > it->second.expires_at) {
        zlines_.erase(it);
        return false;
      }
      return true;
    }
    // CIDR matching
    for (auto& [mask, zl] : zlines_) {
      if (zl.expires_at > 0 && now > zl.expires_at) continue;
      if (cidr_match(mask, ip)) return true;
    }
    return false;
  }

  // == GLINE: Global kill line (network-wide) ==
  struct GLine {
    std::string mask;
    std::string reason;
    int64_t set_at;
    int64_t expires_at;
    std::string set_by;
  };

  bool add_gline(const std::string& mask, const std::string& reason,
                 const std::string& set_by, int64_t duration = 86400) {
    glines_[to_lower(mask)] = {mask, reason, now_sec(),
                               now_sec() + duration, set_by};
    return true;
  }
  bool del_gline(const std::string& mask) { return glines_.erase(to_lower(mask)) > 0; }
  bool check_gline(const std::string& match) {
    int64_t now = now_sec();
    for (auto& [k, v] : glines_) {
      if (now > v.expires_at) continue;
      if (wildcard_match(v.mask, match)) return true;
    }
    return false;
  }

  // == SHUN: Silently block a user (no disconnect, just drop messages) ==
  struct Shun {
    std::string mask;
    std::string reason;
    int64_t set_at;
    int64_t expires_at;
    std::string set_by;
  };

  bool add_shun(const std::string& mask, const std::string& reason,
                const std::string& set_by, int64_t duration = 3600) {
    shuns_[to_lower(mask)] = {mask, reason, now_sec(),
                              now_sec() + duration, set_by};
    return true;
  }
  bool del_shun(const std::string& mask) { return shuns_.erase(to_lower(mask)) > 0; }
  bool is_shunned(const std::string& match) {
    int64_t now = now_sec();
    for (auto& [k, v] : shuns_) {
      if (now > v.expires_at) continue;
      if (wildcard_match(to_lower(v.mask), to_lower(match))) return true;
    }
    return false;
  }

  // == DNSBL (DNS Blacklist checking) ==
  struct DNSBLZone {
    std::string zone;          // e.g. "dnsbl.dronebl.org"
    std::string name;          // Display name
    std::string reply_type;    // "A" or "TXT"
    bool active = true;
  };

  struct DNSBLResult {
    bool blacklisted = false;
    std::string dnsbl_name;
    std::string reply;
  };

  void add_zone(const std::string& name, const std::string& zone) {
    dnsbl_zones_[name] = {zone, name, "A", true};
  }
  void remove_zone(const std::string& name) { dnsbl_zones_.erase(name); }

  DNSBLResult check_ip(const std::string& ip) {
    DNSBLResult result;
    // Reverse IP for DNS lookup: 1.2.3.4 -> 4.3.2.1.zone
    auto parts = split(ip, '.');
    if (parts.size() != 4) return result;
    std::string reversed = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0];
    for (auto& [name, zone] : dnsbl_zones_) {
      if (!zone.active) continue;
      // TODO: actual DNS lookup
      // Here we return a stub — no blacklist
      (void)reversed; (void)zone.zone;
    }
    return result;
  }

  // == JUPE: Fake server (jupiter) to prevent server name collision ==
  struct Jupe {
    std::string server_name;
    std::string reason;
    int64_t set_at;
    int64_t expires_at;
    std::string set_by;
  };

  bool add_jupe(const std::string& server, const std::string& reason,
                const std::string& set_by, int64_t duration = 3600) {
    jupes_[to_lower(server)] = {server, reason, now_sec(),
                                duration > 0 ? now_sec() + duration : 0, set_by};
    return true;
  }
  bool del_jupe(const std::string& server) { return jupes_.erase(to_lower(server)) > 0; }
  bool is_juped(const std::string& server) {
    int64_t now = now_sec();
    auto it = jupes_.find(to_lower(server));
    if (it == jupes_.end()) return false;
    if (it->second.expires_at > 0 && now > it->second.expires_at) {
      jupes_.erase(it);
      return false;
    }
    return true;
  }

  // == RESV: Reserve a nick or channel ==
  struct Resv {
    std::string mask;   // nick or channel mask
    std::string reason;
    int64_t set_at;
    std::string set_by;
  };

  bool add_resv(const std::string& mask, const std::string& reason,
                const std::string& set_by) {
    reservs_[to_lower(mask)] = {mask, reason, now_sec(), set_by};
    return true;
  }
  bool del_resv(const std::string& mask) { return reservs_.erase(to_lower(mask)) > 0; }
  bool is_reserved(const std::string& target) {
    for (auto& [k, v] : reservs_) {
      if (wildcard_match(v.mask, target)) return true;
    }
    return false;
  }
  std::vector<Resv> list_resv() {
    std::vector<Resv> result;
    for (auto& [k, v] : reservs_) result.push_back(v);
    return result;
  }

  // == XLINE: Extended line (regex-based ban) ==
  struct XLine {
    std::string pattern;
    std::string reason;
    int64_t set_at;
    int64_t expires_at;
    std::string set_by;
    bool nick_xline = false; // applies to nicks
    bool gecos_xline = false; // applies to realnames
  };

  bool add_xline(const std::string& pattern, const std::string& reason,
                 const std::string& set_by, bool nick = true, bool gecos = true,
                 int64_t duration = 3600) {
    auto key = to_lower(pattern);
    xlines_[key] = {pattern, reason, now_sec(),
                    duration > 0 ? now_sec() + duration : 0, set_by, nick, gecos};
    return true;
  }
  bool del_xline(const std::string& pattern) {
    return xlines_.erase(to_lower(pattern)) > 0;
  }
  // Check if nick matches any XLine
  bool check_nick_xline(const std::string& nick, std::string& out_reason) {
    int64_t now = now_sec();
    for (auto& [k, v] : xlines_) {
      if (!v.nick_xline) continue;
      if (v.expires_at > 0 && now > v.expires_at) continue;
      try {
        std::regex re(v.pattern, std::regex::icase);
        if (std::regex_search(nick, re)) {
          out_reason = v.reason;
          return true;
        }
      } catch (...) { continue; }
    }
    return false;
  }

  // == List operations ==
  std::vector<KLine> list_klines() {
    std::vector<KLine> r; for (auto& [k, v] : klines_) r.push_back(v); return r;
  }
  std::vector<ZLine> list_zlines() {
    std::vector<ZLine> r; for (auto& [k, v] : zlines_) r.push_back(v); return r;
  }
  std::vector<GLine> list_glines() {
    std::vector<GLine> r; for (auto& [k, v] : glines_) r.push_back(v); return r;
  }
  std::vector<Shun> list_shuns() {
    std::vector<Shun> r; for (auto& [k, v] : shuns_) r.push_back(v); return r;
  }
  std::vector<Jupe> list_jupes() {
    std::vector<Jupe> r; for (auto& [k, v] : jupes_) r.push_back(v); return r;
  }

private:
  static std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> tokens;
    std::stringstream ss(s);
    std::string token;
    while (std::getline(ss, token, delim)) tokens.push_back(token);
    return tokens;
  }
  static bool wildcard_match(const std::string& pattern, const std::string& str) {
    size_t pi = 0, si = 0, star = std::string::npos, ss = 0;
    while (si < str.size()) {
      if (pi < pattern.size() && (pattern[pi] == '?' ||
          to_lower(std::string(1, pattern[pi])) == to_lower(std::string(1, str[si])))) {
        ++pi; ++si;
      } else if (pi < pattern.size() && pattern[pi] == '*') {
        star = pi++; ss = si;
      } else if (star != std::string::npos) {
        pi = star + 1; si = ++ss;
      } else { return false; }
    }
    while (pi < pattern.size() && pattern[pi] == '*') ++pi;
    return pi == pattern.size();
  }
  static bool cidr_match(const std::string& cidr, const std::string& ip) {
    auto slash = cidr.find('/');
    if (slash == std::string::npos) return cidr == ip;
    std::string net = cidr.substr(0, slash);
    int bits = std::stoi(cidr.substr(slash + 1));
    struct in_addr net_a, ip_a;
    if (inet_pton(AF_INET, net.c_str(), &net_a) != 1) return false;
    if (inet_pton(AF_INET, ip.c_str(), &ip_a) != 1) return false;
    uint32_t mask = (bits == 0) ? 0 : htonl(0xFFFFFFFF << (32 - bits));
    return (net_a.s_addr & mask) == (ip_a.s_addr & mask);
  }

  std::map<std::string, KLine, std::less<>> klines_;
  std::map<std::string, ZLine, std::less<>> zlines_;
  std::map<std::string, GLine, std::less<>> glines_;
  std::map<std::string, Shun, std::less<>> shuns_;
  std::map<std::string, Jupe, std::less<>> jupes_;
  std::map<std::string, Resv, std::less<>> reservs_;
  std::map<std::string, XLine, std::less<>> xlines_;
  std::map<std::string, DNSBLZone, std::less<>> dnsbl_zones_;
};

// ============================================================================
// SECTION 5: Extended WHO (WHOX) Implementation
// ============================================================================

class WHOXHandler {
public:
  // WHOX field flags
  static constexpr char WHOX_FLAG_REALNAME    = 'r';
  static constexpr char WHOX_FLAG_NICK        = 'n';
  static constexpr char WHOX_FLAG_USER        = 'u';
  static constexpr char WHOX_FLAG_HOST        = 'h';
  static constexpr char WHOX_FLAG_IP          = 'i';
  static constexpr char WHOX_FLAG_SERVER      = 's';
  static constexpr char WHOX_FLAG_INFO        = 'f';
  static constexpr char WHOX_FLAG_IDLE        = 'd';
  static constexpr char WHOX_FLAG_CHANNELS    = 'c';
  static constexpr char WHOX_FLAG_HOPCOUNT    = 'l';
  static constexpr char WHOX_FLAG_MODES       = 'm';
  static constexpr char WHOX_FLAG_ACCOUNT     = 'a';
  static constexpr char WHOX_FLAG_OPLEVEL     = 'o';
  static constexpr char WHOX_FLAG_CERTFP      = 'e';
  static constexpr char WHOX_FLAG_REGMASK     = 'R';
  static constexpr char WHOX_FLAG_CONNECTION  = 't';

  struct WHOXQuery {
    std::string mask;
    std::string flags;       // requested field flags
    std::string match;       // extended WHO mask match string
    bool ops_only = false;
    bool is_whox = false;    // true if %flags present
  };

  // Parse WHO parameters: WHO <mask> [o] [%<fields>[,<querytype>]] [<mask2>]
  static WHOXQuery parse_who(const std::string& params, bool ops_only) {
    WHOXQuery q;
    q.ops_only = ops_only;
    q.flags = "nuhfdarcia"; // default flags

    std::stringstream ss(params);
    std::vector<std::string> args;
    std::string tok;
    while (ss >> tok) args.push_back(tok);

    if (args.empty()) return q;
    q.mask = args[0];

    for (size_t i = 0; i < args.size(); i++) {
      if (args[i] == "o") {
        q.ops_only = true;
      } else if (!args[i].empty() && args[i][0] == '%') {
        q.is_whox = true;
        std::string field_str = args[i].substr(1);
        auto comma = field_str.find(',');
        if (comma != std::string::npos) {
          q.flags = field_str.substr(0, comma);
          q.match = field_str.substr(comma + 1);
        } else {
          q.flags = field_str;
        }
      } else if (i > 0 && !q.is_whox) {
        q.match = args[i];
      }
    }
    return q;
  }

  // Build WHOX reply line
  // Format: :server 354 <target> <fields...> :<trailing>
  // Fields are returned in the order specified by flags
  std::string build_whox_reply(const std::string& target_nick,
                                const IRCUser& user,
                                const std::string& flags,
                                AccountManagerFull* accounts = nullptr,
                                const std::string& certfp = "",
                                const std::string& real_ip = "",
                                const std::string& channel = "",
                                int access_level = 0) {
    std::vector<std::string> fields;

    for (char f : flags) {
      switch (f) {
        case 'n': // nick
          fields.push_back(user.nick);
          break;
        case 'u': // username
          fields.push_back(user.user);
          break;
        case 'h': // hostname
          fields.push_back(user.host);
          break;
        case 'i': // IP address
          fields.push_back(real_ip.empty() ? user.ip : real_ip);
          break;
        case 's': // server
          fields.push_back(user.server);
          break;
        case 'f': // info (realname)
          fields.push_back("0 " + user.realname); // hopcount + realname
          break;
        case 'd': // idle time
          fields.push_back(std::to_string(now_sec() - user.last_active));
          break;
        case 'a': // account name
          if (accounts) {
            auto* acct = accounts->get_account(user.nick);
            fields.push_back(acct ? user.nick : "0");
          } else {
            fields.push_back("0");
          }
          break;
        case 'o': // oplevel
          fields.push_back(std::to_string(access_level));
          break;
        case 'e': // certfp
          fields.push_back(certfp.empty() ? "0" : certfp);
          break;
        case 'l': // hopcount
          fields.push_back("0");
          break;
        case 'c': // channel name
          fields.push_back(channel);
          break;
        case 'm': // user modes
          fields.push_back("+" + user.modes);
          break;
        case 'r': // realname (trailing)
          break;
        case 't': // connection type
          fields.push_back(certfp.empty() ? "plain" : "ssl");
          break;
        case 'R': // registered mask
          if (accounts && accounts->is_registered(user.nick))
            fields.push_back(user.nick);
          else
            fields.push_back("0");
          break;
        default:
          fields.push_back("0");
          break;
      }
    }

    // Trailing: realname if 'r' flag
    std::string trailing = "";
    if (flags.find('r') != std::string::npos) {
      trailing = " :" + user.realname;
    }

    // Build reply
    std::stringstream ss;
    ss << "354 " << target_nick << " ";
    for (size_t i = 0; i < fields.size(); i++) {
      if (i > 0) ss << " ";
      ss << fields[i];
    }
    ss << trailing;
    return ss.str();
  }

  // Check WHOX match string against user
  bool whox_matches(const IRCUser& user, const std::string& match,
                    AccountManagerFull* accounts = nullptr) {
    if (match.empty()) return true;

    // Format: <match_type>=<match_value>
    auto eq = match.find('=');
    if (eq == std::string::npos) return true;

    std::string mtype = match.substr(0, eq);
    std::string mval = match.substr(eq + 1);

    if (mtype == "a" && accounts) {
      // Account name match
      auto* acct = accounts->get_account(user.nick);
      return acct && to_lower(acct->name) == to_lower(mval);
    }
    if (mtype == "h") {
      return to_lower(user.host) == to_lower(mval);
    }
    if (mtype == "n") {
      return to_lower(user.nick) == to_lower(mval);
    }
    if (mtype == "u") {
      return to_lower(user.user) == to_lower(mval);
    }
    if (mtype == "i") {
      return user.ip == mval;
    }
    if (mtype == "r") {
      return to_lower(user.realname).find(to_lower(mval)) != std::string::npos;
    }
    if (mtype == "s") {
      return to_lower(user.server) == to_lower(mval);
    }
    if (mtype == "o") {
      return (mval == "0" && !user.oper) || (mval == "1" && user.oper);
    }
    return true;
  }
};

// ============================================================================
// SECTION 6: Server-side Watch & Monitor with Notifications
// ============================================================================

class WatchMonitorManager {
public:
  struct WatchEntry {
    std::string target_nick;
    bool notified_online = false;
    int64_t last_notify_time = 0;
  };

  struct MonitorEntry {
    std::string target_nick;
    int64_t added_at = 0;
  };

  // === WATCH (client-side notified) ===
  bool add_watch(const std::string& nick, const std::string& target) {
    auto& list = watches_[to_lower(nick)];
    if (list.count(target)) return false;
    list.insert(target);
    // Notify current status
    return true;
  }

  bool remove_watch(const std::string& nick, const std::string& target) {
    auto it = watches_.find(to_lower(nick));
    if (it == watches_.end()) return false;
    return it->second.erase(target) > 0;
  }

  std::set<std::string> get_watches(const std::string& nick) {
    auto it = watches_.find(to_lower(nick));
    return it != watches_.end() ? it->second : std::set<std::string>{};
  }

  bool is_watching(const std::string& nick, const std::string& target) {
    auto it = watches_.find(to_lower(nick));
    return it != watches_.end() && it->second.count(target);
  }

  // Notify all watchers when a nick changes status
  std::vector<std::string> get_watchers_for(const std::string& nick) {
    std::vector<std::string> watchers;
    for (auto& [watcher, targets] : watches_) {
      if (targets.count(nick))
        watchers.push_back(watcher);
    }
    return watchers;
  }

  // === MONITOR (server-initiated, IRCv3) ===
  bool add_monitor(const std::string& requester_nick, const std::string& target) {
    monitor_list_[to_lower(requester_nick)].push_back({target, now_sec()});
    return true;
  }

  bool remove_monitor(const std::string& requester_nick, const std::string& target) {
    auto it = monitor_list_.find(to_lower(requester_nick));
    if (it == monitor_list_.end()) return false;
    auto& vec = it->second;
    auto pos = std::find_if(vec.begin(), vec.end(), [&](const MonitorEntry& e) {
      return to_lower(e.target_nick) == to_lower(target);
    });
    if (pos == vec.end()) return false;
    vec.erase(pos);
    return true;
  }

  void clear_monitor(const std::string& nick) {
    monitor_list_.erase(to_lower(nick));
  }

  std::vector<MonitorEntry> get_monitor_list(const std::string& nick) {
    auto it = monitor_list_.find(to_lower(nick));
    return it != monitor_list_.end() ? it->second : std::vector<MonitorEntry>{};
  }

  // Get all nicks monitoring this target
  std::vector<std::string> get_monitors_for(const std::string& target) {
    std::vector<std::string> monitors;
    for (auto& [nick, entries] : monitor_list_) {
      for (auto& e : entries) {
        if (to_lower(e.target_nick) == to_lower(target)) {
          monitors.push_back(nick);
          break;
        }
      }
    }
    return monitors;
  }

  // Build monitor status reply for all monitored targets
  std::string build_monitor_status(const std::string& nick,
                                    std::function<bool(const std::string&)> is_online_fn) {
    auto it = monitor_list_.find(to_lower(nick));
    if (it == monitor_list_.end()) return "";

    std::stringstream online_ss, offline_ss;
    int online_count = 0, offline_count = 0;

    for (auto& e : it->second) {
      if (is_online_fn(e.target_nick)) {
        if (online_count++ > 0) online_ss << ",";
        online_ss << e.target_nick;
      } else {
        if (offline_count++ > 0) offline_ss << ",";
        offline_ss << e.target_nick;
      }
    }

    std::string result;
    // RPL_MONONLINE (730)
    if (online_count > 0)
      result += "730 " + nick + " :" + online_ss.str() + "\r\n";
    // RPL_MONOFFLINE (731)
    if (offline_count > 0)
      result += "731 " + nick + " :" + offline_ss.str() + "\r\n";
    return result;
  }

private:
  // nick -> set of watched nicks (WATCH command, client-side)
  std::map<std::string, std::set<std::string>, std::less<>> watches_;
  // nick -> list of monitored nicks (MONITOR command, IRCv3)
  std::map<std::string, std::vector<MonitorEntry>, std::less<>> monitor_list_;
};

// ============================================================================
// SECTION 7: Message Tag Manager — msgid, time, account, batch, labeled-response
// ============================================================================

class MessageTagManagerFull {
public:
  struct TagSpec {
    std::string name;
    bool client_bound;  // client -> server
    bool server_bound;  // server -> client
    std::string description;
  };

  MessageTagManagerFull() { register_default_tags(); }

  void register_default_tags() {
    tags_["account"]  = {"account",  false, true,  "Services account name"};
    tags_["batch"]    = {"batch",    false, true,  "Batch reference"};
    tags_["label"]    = {"label",    true,  true,  "Label for labeled-response"};
    tags_["msgid"]    = {"msgid",    false, true,  "Unique message ID"};
    tags_["time"]     = {"time",     false, true,  "ISO8601 server time"};
    tags_["+typing"]  = {"typing",   true,  false, "Client typing indicator"};
    tags_["+react"]   = {"react",    true,  false, "Message reaction"};
    tags_["+reply"]   = {"reply",    true,  false, "In-reply-to message ID"};
    tags_["draft/channel-context"] = {"chcontext", false, true, "Channel context"};
    tags_["draft/display-name"]    = {"displayname", false, true, "Display name"};
  }

  bool is_valid_tag(const std::string& name) const {
    std::string clean = name;
    if (!clean.empty() && clean[0] == '+') clean = clean.substr(1);
    return tags_.find(clean) != tags_.end();
  }

  // Serialize map of tags to @-prefixed string
  std::string serialize(const std::map<std::string, std::string>& tags_map) {
    if (tags_map.empty()) return "";
    std::stringstream ss;
    ss << "@";
    bool first = true;
    for (auto& [key, val] : tags_map) {
      if (!first) ss << ";";
      first = false;
      ss << key;
      if (!val.empty()) ss << "=" << val;
    }
    return ss.str();
  }

  // Parse @tags from raw IRC message line
  std::map<std::string, std::string> parse(const std::string& raw,
                                            std::string& remaining) {
    std::map<std::string, std::string> result;
    if (raw.empty() || raw[0] != '@') {
      remaining = raw;
      return result;
    }
    size_t sp = raw.find(' ');
    std::string tag_str;
    if (sp == std::string::npos) {
      tag_str = raw.substr(1);
      remaining.clear();
    } else {
      tag_str = raw.substr(1, sp - 1);
      remaining = raw.substr(sp + 1);
    }
    std::stringstream ss(tag_str);
    std::string segment;
    while (std::getline(ss, segment, ';')) {
      if (segment.empty()) continue;
      auto eq = segment.find('=');
      if (eq != std::string::npos) {
        result[segment.substr(0, eq)] = segment.substr(eq + 1);
      } else {
        result[segment] = "";
      }
    }
    return result;
  }

  // Attach standard tags to an outgoing IRC message
  std::string attach_tags(const std::string& msg, const std::string& account = "",
                           const std::string& batch_ref = "",
                           const std::string& label = "") {
    std::map<std::string, std::string> tags;

    // Always add msgid and time
    tags["msgid"] = generate_msgid();
    tags["time"] = format_time_iso8601(now_ms());

    if (!account.empty())
      tags["account"] = account;
    if (!batch_ref.empty())
      tags["batch"] = batch_ref;
    if (!label.empty())
      tags["label"] = label;

    // Check if message already has tags
    if (!msg.empty() && msg[0] == '@') {
      // Merge: strip existing @tags prefix
      size_t sp = msg.find(' ');
      if (sp != std::string::npos) {
        std::string existing_tags = msg.substr(1, sp - 1);
        std::string rest = msg.substr(sp + 1);
        // Parse existing tags and merge
        std::stringstream ss(existing_tags);
        std::string seg;
        while (std::getline(ss, seg, ';')) {
          auto eq = seg.find('=');
          if (eq != std::string::npos)
            tags[seg.substr(0, eq)] = seg.substr(eq + 1);
          else if (!seg.empty())
            tags[seg] = "";
        }
        return serialize(tags) + " " + rest;
      }
    }

    return serialize(tags) + " " + msg;
  }

  // Generate unique message ID
  static std::string generate_msgid() {
    static std::atomic<uint64_t> counter{0};
    std::stringstream ss;
    ss << std::hex << now_ms() << "-" << ++counter;
    return ss.str();
  }

  // Format time as ISO8601 for time tag
  static std::string format_time_iso8601(int64_t ts_ms) {
    std::time_t sec = ts_ms / 1000;
    int ms = ts_ms % 1000;
    struct tm tm_gmt;
    gmtime_r(&sec, &tm_gmt);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_gmt);
    std::stringstream ss;
    ss << buf << "." << std::setfill('0') << std::setw(3) << ms << "Z";
    return ss.str();
  }

  // === Batch support ===
  struct BatchState {
    std::string ref_tag;
    std::string batch_type;     // "netsplit", "chathistory", etc.
    std::string initiator_nick;
    int64_t started_at = 0;
    bool open = true;
  };

  std::string start_batch(const std::string& initiator_nick,
                          const std::string& batch_type) {
    std::string ref = generate_msgid();
    batches_[ref] = {ref, batch_type, initiator_nick, now_sec(), true};
    return ref;
  }

  bool end_batch(const std::string& ref) {
    auto it = batches_.find(ref);
    if (it == batches_.end()) return false;
    it->second.open = false;
    return true;
  }

  BatchState* get_batch(const std::string& ref) {
    auto it = batches_.find(ref);
    return it != batches_.end() ? &it->second : nullptr;
  }

  // === Labeled response ===
  // Track pending labeled requests
  struct LabeledRequest {
    std::string label;
    std::string command;
    int64_t sent_at;
    std::string target_nick;
  };

  void register_labeled_request(const std::string& label, const std::string& cmd,
                                 const std::string& target) {
    labeled_[label] = {label, cmd, now_ms(), target};
  }

  LabeledRequest* get_labeled_request(const std::string& label) {
    auto it = labeled_.find(label);
    return it != labeled_.end() ? &it->second : nullptr;
  }

  void clear_labeled_request(const std::string& label) {
    labeled_.erase(label);
  }

  // Build a labeled response (ACK)
  std::string build_ack(const std::string& target_nick, const std::string& label,
                         const std::string& full_response) {
    std::map<std::string, std::string> tags;
    tags["label"] = label;
    return serialize(tags) + " :server ACK " + target_nick + " :" + full_response;
  }

private:
  std::map<std::string, TagSpec> tags_;
  std::map<std::string, BatchState> batches_;
  std::map<std::string, LabeledRequest> labeled_;
};

// ============================================================================
// SECTION 8: STS (Strict Transport Security) & STARTTLS
// ============================================================================

class TransportSecurityManager {
public:
  struct STSPolicy {
    int duration_seconds = 0;
    int tls_port = 6697;
    bool preload = false;
  };

  struct TLSContext {
    bool active = false;
    std::string certfp;
    std::string cipher;
    std::string protocol_version;
    int64_t handshake_completed_at = 0;
  };

  // === STS (Strict Transport Security) ===
  void configure_sts(int duration, int port = 6697, bool preload = false) {
    sts_policy_.duration_seconds = duration;
    sts_policy_.tls_port = port;
    sts_policy_.preload = preload;
  }

  std::string get_sts_cap_string() {
    if (sts_policy_.duration_seconds <= 0) return "";
    std::stringstream ss;
    ss << "sts=duration=" << sts_policy_.duration_seconds;
    if (sts_policy_.tls_port != 6697)
      ss << ",port=" << sts_policy_.tls_port;
    if (sts_policy_.preload)
      ss << ",preload";
    return ss.str();
  }

  STSPolicy get_policy() const { return sts_policy_; }
  bool sts_enabled() const { return sts_policy_.duration_seconds > 0; }

  // STS tracking — per-user whether they should be forced to SSL
  struct STSState {
    std::string nick;
    bool sts_seen = false;
    int64_t first_seen = 0;
    int64_t sts_expiry = 0;
  };

  void record_sts_seen(const std::string& nick) {
    auto key = to_lower(nick);
    auto& state = sts_states_[key];
    state.nick = nick;
    state.sts_seen = true;
    state.first_seen = now_sec();
    state.sts_expiry = now_sec() + sts_policy_.duration_seconds;
  }

  bool must_use_tls(const std::string& nick) {
    if (!sts_enabled()) return false;
    auto it = sts_states_.find(to_lower(nick));
    if (it == sts_states_.end()) return false;
    return it->second.sts_seen && now_sec() < it->second.sts_expiry;
  }

  // === STARTTLS ===
  struct StartTLSState {
    bool requested = false;
    bool completed = false;
    std::string certfp;
    int64_t request_time = 0;
  };

  bool request_starttls(const std::string& nick) {
    auto key = to_lower(nick);
    auto& state = starttls_states_[key];
    if (state.requested) return false; // already requested
    state.requested = true;
    state.request_time = now_sec();
    return true;
  }

  bool complete_starttls(const std::string& nick, const std::string& certfp) {
    auto key = to_lower(nick);
    auto it = starttls_states_.find(key);
    if (it == starttls_states_.end()) return false;
    it->second.completed = true;
    it->second.certfp = certfp;
    return true;
  }

  StartTLSState* get_starttls_state(const std::string& nick) {
    auto it = starttls_states_.find(to_lower(nick));
    return it != starttls_states_.end() ? &it->second : nullptr;
  }

  // Per-connection TLS state
  TLSContext* get_tls_context(const std::string& nick) {
    return &tls_contexts_[to_lower(nick)];
  }

  void set_tls_active(const std::string& nick, const std::string& certfp,
                      const std::string& cipher, const std::string& proto) {
    auto& ctx = tls_contexts_[to_lower(nick)];
    ctx.active = true;
    ctx.certfp = certfp;
    ctx.cipher = cipher;
    ctx.protocol_version = proto;
    ctx.handshake_completed_at = now_sec();
  }

  bool is_tls_active(const std::string& nick) {
    auto it = tls_contexts_.find(to_lower(nick));
    return it != tls_contexts_.end() && it->second.active;
  }

private:
  STSPolicy sts_policy_;
  std::map<std::string, STSState, std::less<>> sts_states_;
  std::map<std::string, StartTLSState, std::less<>> starttls_states_;
  std::map<std::string, TLSContext, std::less<>> tls_contexts_;
};

// ============================================================================
// SECTION 9: WebSocket IRC Gateway
// ============================================================================

class WebSocketIRC {
public:
  // WebSocket opcodes (RFC 6455)
  static constexpr uint8_t WS_CONTINUATION = 0x0;
  static constexpr uint8_t WS_TEXT         = 0x1;
  static constexpr uint8_t WS_BINARY       = 0x2;
  static constexpr uint8_t WS_CLOSE        = 0x8;
  static constexpr uint8_t WS_PING         = 0x9;
  static constexpr uint8_t WS_PONG         = 0xA;

  static constexpr uint8_t WS_FIN_BIT      = 0x80;
  static constexpr uint8_t WS_MASK_BIT     = 0x80;

  // Frame representation
  struct Frame {
    bool fin = true;
    uint8_t opcode = WS_TEXT;
    bool masked = false;
    uint32_t mask_key = 0;
    std::string payload;
  };

  // Connection state
  struct WSConnection {
    bool upgraded = false;
    bool client_closed = false;
    std::string ws_key;    // Sec-WebSocket-Key
    std::string protocol;  // Sec-WebSocket-Protocol
    std::string partial_frame; // buffered incomplete data
    int64_t last_ping = 0;
    int64_t last_pong = 0;
    int ping_interval = 30; // seconds
    std::string irc_session_nick;
  };

  // === Parsing ===

  // Parse incoming bytes into frames. Returns completed frames.
  std::vector<Frame> parse(const std::string& raw, WSConnection& conn) {
    std::vector<Frame> frames;
    conn.partial_frame += raw;
    size_t offset = 0;

    while (offset < conn.partial_frame.size()) {
      Frame frame;
      if (!parse_single_frame(conn.partial_frame, offset, frame))
        break;
      frames.push_back(frame);
    }

    // Discard consumed bytes
    if (offset > 0)
      conn.partial_frame = conn.partial_frame.substr(offset);
    else if (offset == 0 && conn.partial_frame.size() > 64 * 1024)
      conn.partial_frame.clear(); // prevent memory issues from malformed data

    return frames;
  }

  // Build a frame for sending
  std::string build_frame(const std::string& payload, uint8_t opcode = WS_TEXT,
                           bool mask = false, uint32_t mask_key = 0) {
    std::string frame;
    frame += static_cast<char>(WS_FIN_BIT | opcode);

    size_t len = payload.size();
    if (mask) {
      // Client frames are masked
      if (len <= 125) {
        frame += static_cast<char>(WS_MASK_BIT | len);
      } else if (len <= 65535) {
        frame += static_cast<char>(WS_MASK_BIT | 126);
        frame += static_cast<char>((len >> 8) & 0xFF);
        frame += static_cast<char>(len & 0xFF);
      } else {
        frame += static_cast<char>(WS_MASK_BIT | 127);
        for (int i = 7; i >= 0; i--)
          frame += static_cast<char>((len >> (i * 8)) & 0xFF);
      }
      // Write mask key
      frame += static_cast<char>((mask_key >> 24) & 0xFF);
      frame += static_cast<char>((mask_key >> 16) & 0xFF);
      frame += static_cast<char>((mask_key >> 8) & 0xFF);
      frame += static_cast<char>(mask_key & 0xFF);
      // Mask payload
      for (size_t i = 0; i < len; i++) {
        uint8_t key_byte = (mask_key >> (24 - (i % 4) * 8)) & 0xFF;
        frame += static_cast<char>(payload[i] ^ key_byte);
      }
    } else {
      // Server frames must NOT be masked
      if (len <= 125) {
        frame += static_cast<char>(len);
      } else if (len <= 65535) {
        frame += static_cast<char>(126);
        frame += static_cast<char>((len >> 8) & 0xFF);
        frame += static_cast<char>(len & 0xFF);
      } else {
        frame += static_cast<char>(127);
        for (int i = 7; i >= 0; i--)
          frame += static_cast<char>((len >> (i * 8)) & 0xFF);
      }
      frame += payload;
    }
    return frame;
  }

  // Build a close frame
  std::string build_close(uint16_t code = 1000, const std::string& reason = "") {
    std::string payload;
    payload += static_cast<char>((code >> 8) & 0xFF);
    payload += static_cast<char>(code & 0xFF);
    payload += reason;
    return build_frame(payload, WS_CLOSE, false);
  }

  // Build a ping frame
  std::string build_ping(const std::string& data = "") {
    return build_frame(data, WS_PING, false);
  }

  // Build a pong frame
  std::string build_pong(const std::string& data = "") {
    return build_frame(data, WS_PONG, false);
  }

  // === HTTP Upgrade ===

  struct UpgradeRequest {
    std::string ws_key;
    std::string ws_protocol;
    std::string ws_version;
    std::string origin;
    std::string host;
    bool valid = false;
  };

  UpgradeRequest parse_upgrade_request(const std::string& http_data) {
    UpgradeRequest req;
    std::stringstream ss(http_data);
    std::string line;
    int line_num = 0;

    while (std::getline(ss, line)) {
      if (!line.empty() && line.back() == '\r')
        line.pop_back();

      if (line_num == 0) {
        // GET /path HTTP/1.1
        if (line.find("GET ") != 0) return req;
      } else {
        auto colon = line.find(':');
        if (colon == std::string::npos) { line_num++; continue; }

        std::string header = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        if (!value.empty() && value[0] == ' ')
          value = value.substr(1);

        if (header == "Sec-WebSocket-Key")
          req.ws_key = value;
        else if (header == "Sec-WebSocket-Protocol")
          req.ws_protocol = value;
        else if (header == "Sec-WebSocket-Version")
          req.ws_version = value;
        else if (header == "Origin")
          req.origin = value;
        else if (header == "Host")
          req.host = value;
      }
      line_num++;
    }
    req.valid = !req.ws_key.empty();
    return req;
  }

  std::string build_upgrade_response(const UpgradeRequest& req) {
    // Compute accept key: base64(sha1(ws_key + magic))
    std::string magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string combined = req.ws_key + magic;
    // TODO: real SHA1; using sha256 stub for illustration
    std::string accept = base64_encode(sha256(combined));

    std::stringstream ss;
    ss << "HTTP/1.1 101 Switching Protocols\r\n"
       << "Upgrade: websocket\r\n"
       << "Connection: Upgrade\r\n"
       << "Sec-WebSocket-Accept: " << accept << "\r\n"
       << "Sec-WebSocket-Extensions: permessage-deflate\r\n";
    if (!req.ws_protocol.empty()) {
      ss << "Sec-WebSocket-Protocol: " << req.ws_protocol << "\r\n";
    }
    // CORS headers
    if (!req.origin.empty()) {
      ss << "Access-Control-Allow-Origin: " << req.origin << "\r\n";
    }
    ss << "\r\n";
    return ss.str();
  }

  // Convert IRC message to WebSocket frame
  std::string irc_to_ws(const std::string& irc_line) {
    return build_frame(irc_line);
  }

  // Check if a connection needs a ping
  bool should_ping(WSConnection& conn) {
    int64_t now = now_sec();
    if (conn.last_ping > 0 && (now - conn.last_ping) > conn.ping_interval) {
      // Check if we received a pong recently
      if (conn.last_pong < conn.last_ping) {
        return true; // missed pong, still ping again
      }
    }
    if (conn.last_ping == 0 || (now - conn.last_ping) > conn.ping_interval)
      return true;
    return false;
  }

  void record_ping(WSConnection& conn) { conn.last_ping = now_sec(); }
  void record_pong(WSConnection& conn) { conn.last_pong = now_sec(); }

private:
  bool parse_single_frame(const std::string& buf, size_t& offset, Frame& frame) {
    if (buf.size() - offset < 2) return false;

    uint8_t b0 = static_cast<uint8_t>(buf[offset]);
    uint8_t b1 = static_cast<uint8_t>(buf[offset + 1]);

    frame.fin    = (b0 & 0x80) != 0;
    frame.opcode = b0 & 0x0F;
    frame.masked = (b1 & 0x80) != 0;

    size_t payload_len = b1 & 0x7F;
    size_t header_len = 2;

    if (payload_len == 126) {
      if (buf.size() - offset < 4) return false;
      payload_len = (static_cast<uint16_t>(static_cast<uint8_t>(buf[offset + 2])) << 8)
                  | static_cast<uint16_t>(static_cast<uint8_t>(buf[offset + 3]));
      header_len = 4;
    } else if (payload_len == 127) {
      if (buf.size() - offset < 10) return false;
      payload_len = 0;
      for (int i = 0; i < 8; i++)
        payload_len = (payload_len << 8) | static_cast<uint8_t>(buf[offset + 2 + i]);
      header_len = 10;
    }

    size_t mask_offset = header_len;
    if (frame.masked) {
      if (buf.size() - offset < mask_offset + 4) return false;
      frame.mask_key =
        (static_cast<uint32_t>(static_cast<uint8_t>(buf[offset + mask_offset])) << 24) |
        (static_cast<uint32_t>(static_cast<uint8_t>(buf[offset + mask_offset + 1])) << 16) |
        (static_cast<uint32_t>(static_cast<uint8_t>(buf[offset + mask_offset + 2])) << 8)  |
        static_cast<uint32_t>(static_cast<uint8_t>(buf[offset + mask_offset + 3]));
      header_len += 4;
      mask_offset += 4;
    }

    if (buf.size() - offset < header_len + payload_len) return false;

    frame.payload = buf.substr(offset + header_len, payload_len);

    // Unmask
    if (frame.masked && payload_len > 0) {
      for (size_t i = 0; i < payload_len; i++) {
        uint8_t key_byte = (frame.mask_key >> (24 - (i % 4) * 8)) & 0xFF;
        frame.payload[i] ^= key_byte;
      }
    }

    offset += header_len + payload_len;
    return true;
  }

  static std::string base64_encode(const std::string& in) {
    static const char* tbl =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
      val = (val << 8) + c; valb += 8;
      while (valb >= 0) { out += tbl[(val >> valb) & 0x3F]; valb -= 6; }
    }
    if (valb > -6) out += tbl[((val << 8) >> (valb + 8)) & 0x3F];
    while (out.size() % 4) out += '=';
    return out;
  }
};

// ============================================================================
// SECTION 10: Server-side Ignore
// ============================================================================

class ServerIgnore {
public:
  struct IgnoreEntry {
    std::string mask;         // nick!user@host pattern
    std::string set_by;
    int64_t set_at;
    // What to ignore
    bool ignore_privmsg = true;
    bool ignore_notice = true;
    bool ignore_invite = false;
    bool ignore_ctcp  = true;
  };

  // Add ignore entry for a user
  bool add_ignore(const std::string& nick, const std::string& mask,
                  bool privmsg = true, bool notice = true,
                  bool invite = false, bool ctcp = true) {
    auto key = to_lower(nick);
    IgnoreEntry entry{mask, nick, now_sec(), privmsg, notice, invite, ctcp};
    ignores_[key].push_back(entry);
    return true;
  }

  // Remove ignore entry by mask
  bool del_ignore(const std::string& nick, const std::string& mask) {
    auto key = to_lower(nick);
    auto it = ignores_.find(key);
    if (it == ignores_.end()) return false;
    auto& list = it->second;
    auto pos = std::find_if(list.begin(), list.end(), [&](const IgnoreEntry& e) {
      return to_lower(e.mask) == to_lower(mask);
    });
    if (pos == list.end()) return false;
    list.erase(pos);
    if (list.empty()) ignores_.erase(it);
    return true;
  }

  // Clear all ignores for a user
  void clear_ignores(const std::string& nick) {
    ignores_.erase(to_lower(nick));
  }

  // List all ignores for a user
  std::vector<IgnoreEntry> list_ignores(const std::string& nick) {
    auto it = ignores_.find(to_lower(nick));
    return it != ignores_.end() ? it->second : std::vector<IgnoreEntry>{};
  }

  // Check if a message FROM `sender_mask` (nick!user@host) should be
  // blocked for the target nick, for the given message type
  bool is_ignored(const std::string& target_nick, const std::string& sender_mask,
                  const std::string& msg_type) {
    auto it = ignores_.find(to_lower(target_nick));
    if (it == ignores_.end()) return false;

    for (auto& entry : it->second) {
      if (!wildcard_match(entry.mask, sender_mask)) continue;

      if (msg_type == "PRIVMSG" && entry.ignore_privmsg) return true;
      if (msg_type == "NOTICE" && entry.ignore_notice) return true;
      if (msg_type == "INVITE" && entry.ignore_invite) return true;
      if (msg_type == "CTCP" && entry.ignore_ctcp) return true;
    }
    return false;
  }

  // Server-side global ignore (oper-set, SILENCE-like)
  struct GlobalIgnore {
    std::string mask;
    std::string reason;
    std::string set_by;
    int64_t set_at;
    int64_t expires_at;
  };

  bool add_global_ignore(const std::string& mask, const std::string& reason,
                         const std::string& set_by, int64_t duration = 0) {
    global_ignores_[to_lower(mask)] = {mask, reason, set_by, now_sec(),
                                       duration > 0 ? now_sec() + duration : 0};
    return true;
  }
  bool del_global_ignore(const std::string& mask) {
    return global_ignores_.erase(to_lower(mask)) > 0;
  }
  bool is_globally_ignored(const std::string& sender_mask) {
    int64_t now = now_sec();
    for (auto& [k, v] : global_ignores_) {
      if (v.expires_at > 0 && now > v.expires_at) continue;
      if (wildcard_match(v.mask, sender_mask)) return true;
    }
    return false;
  }

private:
  static bool wildcard_match(const std::string& pattern, const std::string& str) {
    size_t pi = 0, si = 0, star = std::string::npos, ss = 0;
    while (si < str.size()) {
      if (pi < pattern.size() && (pattern[pi] == '?' ||
          to_lower(std::string(1, pattern[pi])) == to_lower(std::string(1, str[si])))) {
        ++pi; ++si;
      } else if (pi < pattern.size() && pattern[pi] == '*') {
        star = pi++; ss = si;
      } else if (star != std::string::npos) {
        pi = star + 1; si = ++ss;
      } else { return false; }
    }
    while (pi < pattern.size() && pattern[pi] == '*') ++pi;
    return pi == pattern.size();
  }

  std::map<std::string, std::vector<IgnoreEntry>, std::less<>> ignores_;
  std::map<std::string, GlobalIgnore, std::less<>> global_ignores_;
};

// ============================================================================
// SECTION 11: Ident Lookup & Real Host/IP Logging
// ============================================================================

class IdentLookup {
public:
  struct IdentResult {
    std::string username;      // ident username
    std::string os_type;       // e.g. "UNIX", "WIN32"
    bool success = false;
    int64_t lookup_time = 0;
  };

  // Initiate ident lookup for a connection
  // RFC 1413: connect to port 113 on client's IP, send "localport,remoteport"
  void start_lookup(const std::string& client_ip, int client_port,
                    int server_port, const std::string& nick) {
    PendingLookup pl;
    pl.client_ip = client_ip;
    pl.client_port = client_port;
    pl.server_port = server_port;
    pl.nick = nick;
    pl.started_at = now_sec();

    std::string key = client_ip + ":" + std::to_string(client_port);
    pending_[key] = pl;

    // In a real implementation, this would:
    // 1. Make a TCP connection to client_ip:113
    // 2. Send: "server_port,client_port\r\n"
    // 3. Read response: "server_port,client_port : USERID : os_type : username\r\n"
    // 4. Parse and store result

    // Stub: simulate async completion
    IdentResult result;
    result.success = false; // No ident available by default
    results_[key] = result;
  }

  // Complete a lookup with the actual result
  void complete_lookup(const std::string& client_ip, int client_port,
                       const std::string& username, const std::string& os_type) {
    std::string key = client_ip + ":" + std::to_string(client_port);
    results_[key] = {username, os_type, true, now_sec()};
    pending_.erase(key);
  }

  // Get ident result for a connection
  IdentResult get_result(const std::string& client_ip, int client_port) {
    std::string key = client_ip + ":" + std::to_string(client_port);
    auto it = results_.find(key);
    if (it != results_.end()) return it->second;
    return {"", "", false, 0};
  }

  // Check if a lookup is pending
  bool is_pending(const std::string& client_ip, int client_port) {
    std::string key = client_ip + ":" + std::to_string(client_port);
    return pending_.count(key) > 0;
  }

  // Timeout old lookups
  void cleanup_timed_out(int timeout_secs = 30) {
    int64_t now = now_sec();
    std::vector<std::string> to_remove;
    for (auto& [key, pl] : pending_) {
      if (now - pl.started_at > timeout_secs) {
        to_remove.push_back(key);
        results_[key] = {"", "", false, now}; // timed out
      }
    }
    for (auto& key : to_remove) pending_.erase(key);
  }

private:
  struct PendingLookup {
    std::string client_ip;
    int client_port;
    int server_port;
    std::string nick;
    int64_t started_at = 0;
  };
  std::map<std::string, PendingLookup, std::less<>> pending_;
  std::map<std::string, IdentResult, std::less<>> results_;
};

// ============================================================================
// SECTION 12: Connection/User Logging with Real Host & IP
// ============================================================================

class ConnectionLogger {
public:
  struct ConnectionLog {
    std::string nick;
    std::string ident_user;     // from ident lookup
    std::string real_host;      // DNS PTR result
    std::string real_ip;
    std::string vhost;          // display host (may differ from real)
    std::string server_host;    // our server hostname
    int port = 0;
    int64_t connected_at = 0;
    int64_t disconnected_at = 0;
    std::string disconnect_reason;
    bool tls = false;
    std::string certfp;
    int64_t bytes_sent = 0;
    int64_t bytes_recv = 0;
    std::string geoip_country;
    std::string geoip_city;
    std::string banned_by;      // which K/G/Z line matched, if any
  };

  void log_connect(const std::string& nick, const std::string& real_ip,
                   const std::string& real_host, int port, bool tls = false) {
    std::string key = to_lower(nick);
    ConnectionLog entry;
    entry.nick = nick;
    entry.real_ip = real_ip;
    entry.real_host = real_host;
    entry.vhost = real_host; // default vhost = real host
    entry.port = port;
    entry.connected_at = now_sec();
    entry.tls = tls;
    connect_log_[key] = entry;
    // Also track by IP for duplicate connection checks
    ip_log_[real_ip].push_back({nick, now_sec(), "connect"});
  }

  void log_disconnect(const std::string& nick, const std::string& reason) {
    auto key = to_lower(nick);
    auto it = connect_log_.find(key);
    if (it == connect_log_.end()) return;
    it->second.disconnected_at = now_sec();
    it->second.disconnect_reason = reason;

    // Archive old entries
    if (connect_log_.size() > 10000) {
      std::vector<std::string> old;
      for (auto& [k, v] : connect_log_) {
        if (v.disconnected_at > 0 && (now_sec() - v.disconnected_at) > 86400)
          old.push_back(k);
      }
      for (auto& k : old) connect_log_.erase(k);
    }
  }

  void set_banned_by(const std::string& nick, const std::string& ban_type) {
    auto it = connect_log_.find(to_lower(nick));
    if (it != connect_log_.end()) it->second.banned_by = ban_type;
  }

  ConnectionLog* get_log(const std::string& nick) {
    auto it = connect_log_.find(to_lower(nick));
    return it != connect_log_.end() ? &it->second : nullptr;
  }

  // Check for duplicate connections from same IP
  int count_connections_from_ip(const std::string& ip) {
    int count = 0;
    int64_t now = now_sec();
    for (auto& [nick, entry] : connect_log_) {
      if (entry.real_ip == ip && entry.disconnected_at == 0)
        count++;
    }
    // Count recent entries from ip_log too
    auto& entries = ip_log_[ip];
    for (auto& e : entries) {
      if (now - e.timestamp < 60 && e.action == "connect")
        count++;
    }
    return count;
  }

  struct IPLogEntry {
    std::string nick;
    int64_t timestamp;
    std::string action; // "connect", "disconnect", "ban", "kline"
  };

  std::vector<IPLogEntry> get_ip_history(const std::string& ip) {
    auto it = ip_log_.find(ip);
    return it != ip_log_.end() ? it->second : std::vector<IPLogEntry>{};
  }

private:
  std::map<std::string, ConnectionLog, std::less<>> connect_log_;
  std::map<std::string, std::vector<IPLogEntry>, std::less<>> ip_log_;
};

// ============================================================================
// SECTION 13: Server Notice Masking (SNOMASK)
// ============================================================================

class ServerNoticeMask {
public:
  // Server notice mask characters
  // +k = KILL notices, +c = connect/disconnect, +o = oper-up,
  // +s = server notices, +j = jupe notices, +d = debug,
  // +x = XLine notices, +g = GLine notices, +n = nick changes,
  // +q = quit notices, +r = remote connect/disconnect
  static constexpr char SNOMASK_KILLS     = 'k';
  static constexpr char SNOMASK_CONNECTS  = 'c';
  static constexpr char SNOMASK_OPERS     = 'o';
  static constexpr char SNOMASK_SERVERS   = 's';
  static constexpr char SNOMASK_JUPES     = 'j';
  static constexpr char SNOMASK_DEBUG     = 'd';
  static constexpr char SNOMASK_XLINES    = 'x';
  static constexpr char SNOMASK_GLINES    = 'g';
  static constexpr char SNOMASK_NICKS     = 'n';
  static constexpr char SNOMASK_QUITS     = 'q';
  static constexpr char SNOMASK_REMOTE    = 'r';
  static constexpr char SNOMASK_BANS      = 'b';

  struct SnoState {
    std::string oper_nick;
    std::string snomask;
    bool receives_all = false; // oper with full privileges
  };

  // Set snomask for an oper
  void set_snomask(const std::string& oper_nick, const std::string& snomask) {
    auto key = to_lower(oper_nick);
    auto& state = sno_states_[key];
    state.oper_nick = oper_nick;
    // Parse +/- flags
    for (char c : snomask) {
      if (c == '+') continue;
      if (c == '-') {
        // Clear specific mask
        // (simplified: just set the whole mask)
        continue;
      }
      if (state.snomask.find(c) == std::string::npos)
        state.snomask += c;
    }
  }

  // Get oper nicks that should receive notice of type
  std::vector<std::string> get_recipients(char notice_type) {
    std::vector<std::string> recipients;
    for (auto& [k, state] : sno_states_) {
      if (state.receives_all || state.snomask.find(notice_type) != std::string::npos) {
        recipients.push_back(state.oper_nick);
      }
    }
    return recipients;
  }

  // Send server notice to all matching opers
  std::string format_sno_notice(char sno_type, const std::string& message) {
    std::stringstream ss;
    ss << "NOTICE $" << sno_type << " :" << message;
    return ss.str();
  }

  void clear_snomask(const std::string& oper_nick) {
    sno_states_.erase(to_lower(oper_nick));
  }

private:
  std::map<std::string, SnoState, std::less<>> sno_states_;
};

// ============================================================================
// SECTION 14: NickServ Command Handler
// ============================================================================

class NickServHandler {
public:
  NickServHandler(AccountManagerFull* accounts, HostServManager* hostserv)
    : accounts_(accounts), hostserv_(hostserv) {}

  std::string handle(const std::string& nick, const std::string& msg) {
    std::stringstream ss(msg);
    std::string cmd;
    ss >> cmd;
    cmd = to_upper(cmd);

    if (cmd == "REGISTER") {
      std::string password, email;
      ss >> password >> email;
      if (password.empty())
        return "Usage: REGISTER <password> <email>";
      if (accounts_->register_account(nick, email, password))
        return "Nickname " + nick + " registered successfully.";
      return "Nickname " + nick + " is already registered.";
    }

    if (cmd == "IDENTIFY") {
      std::string password;
      ss >> password;
      if (password.empty())
        return "Usage: IDENTIFY <password>";
      if (accounts_->identify(nick, password))
        return "You are now identified for " + nick + ".";
      return "Invalid password. Check your credentials and try again.";
    }

    if (cmd == "LOGOUT") {
      if (accounts_->logout(nick))
        return "You are no longer identified.";
      return "You were not identified.";
    }

    if (cmd == "INFO") {
      std::string target;
      ss >> target;
      if (target.empty()) target = nick;
      std::string info = accounts_->get_info(target);
      if (info.empty())
        return target + " is not registered.";
      return info;
    }

    if (cmd == "DROP") {
      std::string to_drop;
      ss >> to_drop;
      if (to_drop.empty()) to_drop = nick;
      if (!accounts_->is_identified(nick))
        return "You must identify before using DROP.";
      if (accounts_->drop_account(to_drop))
        return "Nickname " + to_drop + " has been dropped.";
      return "Nickname " + to_drop + " is not registered.";
    }

    if (cmd == "SET") {
      return handle_set(nick, ss);
    }

    if (cmd == "HOLIDAY") {
      std::string subcmd;
      ss >> subcmd;
      subcmd = to_upper(subcmd);
      if (subcmd == "ON" || subcmd == "START") {
        int64_t days;
        std::string msg;
        ss >> days;
        std::getline(ss, msg);
        if (!msg.empty() && msg[0] == ' ') msg = msg.substr(1);
        if (days <= 0) return "Usage: HOLIDAY ON <days> <message>";
        int64_t start = now_sec();
        int64_t end = start + days * 86400;
        accounts_->set_holiday(nick, start, end, msg);
        return "Holiday mode enabled for " + std::to_string(days) + " days.";
      } else if (subcmd == "OFF" || subcmd == "END") {
        accounts_->set_holiday(nick, 0, 0, "");
        return "Holiday mode disabled.";
      }
      return "Usage: HOLIDAY ON|OFF";
    }

    if (cmd == "SEND") {
      // Memo: SEND <target> <message>
      std::string target;
      ss >> target;
      std::string memo_msg;
      std::getline(ss, memo_msg);
      if (!memo_msg.empty() && memo_msg[0] == ' ') memo_msg = memo_msg.substr(1);
      if (target.empty() || memo_msg.empty())
        return "Usage: SEND <nick> <message>";
      if (accounts_->send_memo(nick, target, memo_msg))
        return "Memo sent to " + target + ".";
      return target + " is not registered.";
    }

    if (cmd == "READ") {
      return handle_read_memos(nick);
    }

    if (cmd == "GHOST") {
      std::string target;
      ss >> target;
      // Would disconnect the target user (require identification)
      (void)target;
      return "GHOST: This command allows you to disconnect a user using your nickname.";
    }

    if (cmd == "RECOVER") {
      std::string target;
      ss >> target;
      // RECOVER forces nick change on target and reclaims the nick
      (void)target;
      return "RECOVER: This releases your nickname from another user.";
    }

    if (cmd == "ALIST") {
      // List channels you have access in
      return "ALIST: Lists channels where you have access.";
    }

    return "Unknown NickServ command. Try: REGISTER, IDENTIFY, INFO, LOGOUT, "
           "SET, DROP, HOLIDAY, SEND, READ, GHOST, RECOVER";
  }

private:
  std::string handle_set(const std::string& nick, std::stringstream& ss) {
    std::string setting;
    ss >> setting;
    setting = to_upper(setting);

    if (setting == "EMAIL") {
      std::string email;
      ss >> email;
      if (email.empty()) return "Usage: SET EMAIL <address>";
      accounts_->set_email(nick, email);
      return "Email set to " + email;
    }

    if (setting == "PASSWORD") {
      std::string pass;
      ss >> pass;
      if (pass.empty()) return "Usage: SET PASSWORD <new_password>";
      accounts_->set_password(nick, pass);
      return "Password updated.";
    }

    if (setting == "NOEXPIRE") {
      std::string val;
      ss >> val;
      val = to_upper(val);
      bool on = (val == "ON" || val == "1" || val == "TRUE");
      accounts_->set_no_expire(nick, on);
      return "NOEXPIRE " + std::string(on ? "enabled" : "disabled") + ".";
    }

    if (setting == "PRIVATE") {
      std::string val;
      ss >> val;
      bool on = (to_upper(val) == "ON" || val == "1" || val == "TRUE");
      accounts_->set_private(nick, on);
      return "PRIVATE " + std::string(on ? "enabled" : "disabled") + ".";
    }

    if (setting == "ENFORCE") {
      std::string val;
      ss >> val;
      bool on = (to_upper(val) == "ON" || val == "1" || val == "TRUE");
      accounts_->set_enforce(nick, on);
      return "ENFORCE " + std::string(on ? "enabled" : "disabled") + ".";
    }

    if (setting == "LANGUAGE") {
      std::string lang;
      ss >> lang;
      if (lang.empty()) return "Usage: SET LANGUAGE <code>";
      accounts_->set_language(nick, lang);
      return "Language set to " + lang + ".";
    }

    return "Unknown SET option. Try: EMAIL, PASSWORD, NOEXPIRE, PRIVATE, "
           "ENFORCE, LANGUAGE";
  }

  std::string handle_read_memos(const std::string& nick) {
    auto memos = accounts_->read_memos(nick, true);
    if (memos.empty()) return "You have no memos.";
    std::stringstream ss;
    ss << "You have " << memos.size() << " memo(s):\r\n";
    for (size_t i = 0; i < memos.size(); i++) {
      ss << "  " << (i + 1) << ". " << memos[i] << "\r\n";
    }
    return ss.str();
  }

  AccountManagerFull* accounts_;
  HostServManager* hostserv_;
};

// ============================================================================
// SECTION 15: ChanServ Command Handler
// ============================================================================

class ChanServHandler {
public:
  ChanServHandler(ChannelRegistrationFull* channels, AccountManagerFull* accounts)
    : channels_(channels), accounts_(accounts) {}

  std::string handle(const std::string& sender, const std::string& msg) {
    std::stringstream ss(msg);
    std::string cmd;
    ss >> cmd;
    cmd = to_upper(cmd);

    if (cmd == "REGISTER") {
      std::string channel, key;
      ss >> channel >> key;
      if (channel.empty())
        return "Usage: REGISTER <#channel> [key]";
      if (!accounts_->is_identified(sender))
        return "You must identify with NickServ before registering a channel.";
      if (channels_->register_channel(channel, sender))
        return "Channel " + channel + " registered to " + sender + ".";
      return "Channel " + channel + " is already registered.";
    }

    if (cmd == "DROP") {
      std::string channel;
      ss >> channel;
      if (channel.empty())
        return "Usage: DROP <#channel>";
      if (!accounts_->is_identified(sender))
        return "You must identify with NickServ first.";
      if (channels_->get_founder(channel) != sender)
        return "Only the founder can drop the channel.";
      channels_->drop_channel(channel);
      return "Channel " + channel + " has been dropped.";
    }

    if (cmd == "INFO") {
      std::string channel;
      ss >> channel;
      if (channel.empty())
        return "Usage: INFO <#channel>";
      std::string info = channels_->get_info(channel);
      if (info.empty())
        return "Channel " + channel + " is not registered.";
      return info;
    }

    if (cmd == "ACCESS") {
      return handle_access(sender, ss);
    }

    if (cmd == "SET") {
      return handle_set(sender, ss);
    }

    if (cmd == "AKICK") {
      return handle_akick(sender, ss);
    }

    if (cmd == "FLAGS") {
      // Display access flags for a user in a channel
      std::string channel, target;
      ss >> channel >> target;
      if (target.empty()) target = sender;
      if (channel.empty())
        return "Usage: FLAGS <#channel> [nick]";
      int level = channels_->get_access(channel, target);
      if (level == 0)
        return target + " has no access in " + channel + ".";
      std::stringstream resp;
      resp << target << " has " << ChannelRegistrationFull::access_level_name(level)
           << " access (" << level << ") in " << channel << ".";
      return resp.str();
    }

    if (cmd == "COUNT") {
      // Count how many channel registrations exist
      return "Channel count: (stats stub)";
    }

    return "Unknown ChanServ command. Try: REGISTER, DROP, ACCESS, SET, "
           "INFO, AKICK, FLAGS";
  }

private:
  std::string handle_access(const std::string& sender, std::stringstream& ss) {
    std::string channel, subcmd, target;
    ss >> channel >> subcmd;
    subcmd = to_upper(subcmd);

    if (channel.empty())
      return "Usage: ACCESS <#channel> ADD|DEL|LIST [nick] [level]";

    // Check permission: only founder or SOP can manage access
    int sender_level = channels_->get_access(channel, sender);
    if (sender_level < ChannelRegistrationFull::ACCESS_SOP &&
        channels_->get_founder(channel) != sender)
      return "Permission denied. You need at least SOP access.";

    if (subcmd == "ADD") {
      int level = 0;
      ss >> target >> level;
      if (target.empty() || level < 1)
        return "Usage: ACCESS <#channel> ADD <nick> <level>";
      channels_->set_access(channel, target, level);
      std::stringstream resp;
      resp << target << " added to " << channel
           << " with level " << level
           << " (" << ChannelRegistrationFull::access_level_name(level) << ").";
      return resp.str();
    }

    if (subcmd == "DEL") {
      ss >> target;
      if (target.empty())
        return "Usage: ACCESS <#channel> DEL <nick>";
      channels_->set_access(channel, target, 0);
      return target + " removed from " + channel + " access list.";
    }

    if (subcmd == "LIST") {
      // Would iterate access entries and display them
      return "Access list for " + channel + ": (list stub)";
    }

    return "Usage: ACCESS <#channel> ADD|DEL|LIST";
  }

  std::string handle_set(const std::string& sender, std::stringstream& ss) {
    std::string channel, setting, value;
    ss >> channel >> setting;
    std::getline(ss, value);
    if (!value.empty() && value[0] == ' ') value = value.substr(1);

    if (channel.empty())
      return "Usage: SET <#channel> <option> [value]";

    // Check permission
    int sender_level = channels_->get_access(channel, sender);
    if (sender_level < ChannelRegistrationFull::ACCESS_FOUNDER &&
        channels_->get_founder(channel) != sender)
      return "Permission denied. Only the founder can change channel settings.";

    setting = to_upper(setting);

    if (setting == "ENTRYMSG") {
      channels_->set_entrymsg(channel, value);
      return "Entry message for " + channel + " set.";
    }
    if (setting == "SECURE") {
      bool on = (to_upper(value) == "ON" || value == "1");
      channels_->set_secure(channel, on);
      return "SECURE " + std::string(on ? "enabled" : "disabled") + ".";
    }
    if (setting == "VERBOSE") {
      bool on = (to_upper(value) == "ON" || value == "1");
      channels_->set_verbose(channel, on);
      return "VERBOSE " + std::string(on ? "enabled" : "disabled") + ".";
    }
    if (setting == "KEEPTOPIC") {
      bool on = (to_upper(value) == "ON" || value == "1");
      channels_->set_keeptopic(channel, on);
      return "KEEPTOPIC " + std::string(on ? "enabled" : "disabled") + ".";
    }
    if (setting == "TOPICLOCK") {
      bool on = (to_upper(value) == "ON" || value == "1");
      channels_->set_topiclock(channel, on);
      return "TOPICLOCK " + std::string(on ? "enabled" : "disabled") + ".";
    }
    if (setting == "SUCCESSOR") {
      if (value.empty())
        return "Usage: SET <#channel> SUCCESSOR <nick>";
      channels_->set_successor(channel, value);
      return "Successor for " + channel + " set to " + value + ".";
    }
    if (setting == "NOEXPIRE") {
      bool on = (to_upper(value) == "ON" || value == "1");
      channels_->set_no_expire(channel, on);
      return "NOEXPIRE " + std::string(on ? "enabled" : "disabled") + ".";
    }
    if (setting == "URL") {
      channels_->set_url(channel, value);
      return "URL for " + channel + " updated.";
    }
    if (setting == "EMAIL") {
      channels_->set_email(channel, value);
      return "Email for " + channel + " updated.";
    }

    return "Unknown SET option. Try: ENTRYMSG, SECURE, VERBOSE, KEEPTOPIC, "
           "TOPICLOCK, SUCCESSOR, NOEXPIRE, URL, EMAIL";
  }

  std::string handle_akick(const std::string& sender, std::stringstream& ss) {
    std::string channel, subcmd, mask, reason;
    ss >> channel >> subcmd;
    subcmd = to_upper(subcmd);

    if (channel.empty())
      return "Usage: AKICK <#channel> ADD|DEL|LIST [mask] [reason]";

    int sender_level = channels_->get_access(channel, sender);
    if (sender_level < ChannelRegistrationFull::ACCESS_SOP &&
        channels_->get_founder(channel) != sender)
      return "Permission denied.";

    if (subcmd == "ADD") {
      ss >> mask;
      std::getline(ss, reason);
      if (!reason.empty() && reason[0] == ' ') reason = reason.substr(1);
      if (mask.empty())
        return "Usage: AKICK <#channel> ADD <mask> [reason]";
      channels_->add_akick(channel, mask);
      return "AKICK for " + mask + " added to " + channel + ".";
    }

    if (subcmd == "DEL") {
      ss >> mask;
      if (mask.empty())
        return "Usage: AKICK <#channel> DEL <mask>";
      channels_->del_akick(channel, mask);
      return "AKICK for " + mask + " removed from " + channel + ".";
    }

    if (subcmd == "LIST") {
      auto akicks = channels_->get_akicks(channel);
      if (akicks.empty())
        return "No AKICK entries for " + channel + ".";
      std::stringstream resp;
      resp << "AKICK entries for " + channel + ": ";
      for (size_t i = 0; i < akicks.size(); i++) {
        if (i > 0) resp << ", ";
        resp << akicks[i];
      }
      return resp.str();
    }

    return "Usage: AKICK <#channel> ADD|DEL|LIST";
  }

  ChannelRegistrationFull* channels_;
  AccountManagerFull* accounts_;
};

// ============================================================================
// SECTION 16: HostServ Command Handler
// ============================================================================

class HostServCLIHandler {
public:
  HostServCLIHandler(HostServManager* hostserv, AccountManagerFull* accounts)
    : hostserv_(hostserv), accounts_(accounts) {}

  std::string handle(const std::string& nick, const std::string& msg,
                     bool is_oper = false) {
    std::stringstream ss(msg);
    std::string cmd;
    ss >> cmd;
    cmd = to_upper(cmd);

    if (cmd == "REQUEST") {
      std::string vhost;
      ss >> vhost;
      if (vhost.empty())
        return "Usage: REQUEST <vhost>";
      if (!accounts_->is_identified(nick))
        return "You must identify with NickServ before requesting a vhost.";
      if (hostserv_->request_vhost(nick, vhost))
        return "vhost request for " + vhost + " submitted and awaiting approval.";
      return "You already have a pending vhost request.";
    }

    if (cmd == "ON") {
      if (hostserv_->set_active(nick, true))
        return "Your vhost is now active.";
      return "You do not have a vhost assigned.";
    }

    if (cmd == "OFF") {
      if (hostserv_->set_active(nick, false))
        return "Your vhost is now inactive (real host will be shown).";
      return "You do not have a vhost assigned.";
    }

    // Oper-only commands
    if (is_oper) {
      if (cmd == "APPROVE") {
        std::string account;
        ss >> account;
        if (account.empty()) return "Usage: APPROVE <account>";
        if (hostserv_->approve_vhost(account))
          return "vhost for " + account + " approved.";
        return "No pending vhost request for " + account + ".";
      }

      if (cmd == "REJECT") {
        std::string account, reason;
        ss >> account;
        std::getline(ss, reason);
        if (!reason.empty() && reason[0] == ' ') reason = reason.substr(1);
        if (account.empty()) return "Usage: REJECT <account> <reason>";
        hostserv_->reject_vhost(account, reason);
        return "vhost for " + account + " rejected.";
      }

      if (cmd == "SET") {
        std::string account, vhost;
        ss >> account >> vhost;
        if (account.empty() || vhost.empty())
          return "Usage: SET <account> <vhost>";
        hostserv_->set_vhost(account, vhost, nick);
        return "vhost " + vhost + " assigned to " + account + ".";
      }

      if (cmd == "DEL") {
        std::string account;
        ss >> account;
        if (account.empty()) return "Usage: DEL <account>";
        hostserv_->del_vhost(account);
        return "vhost for " + account + " removed.";
      }

      if (cmd == "LIST") {
        auto pending = hostserv_->list_pending();
        if (pending.empty()) return "No pending vhost requests.";
        std::stringstream resp;
        resp << "Pending vhost requests: ";
        for (size_t i = 0; i < pending.size(); i++) {
          if (i > 0) resp << ", ";
          resp << pending[i].account << " -> " << pending[i].vhost;
        }
        return resp.str();
      }
    }

    return "Unknown HostServ command. Try: REQUEST, ON, OFF" +
           std::string(is_oper ? ", APPROVE, REJECT, SET, DEL, LIST" : "");
  }

private:
  HostServManager* hostserv_;
  AccountManagerFull* accounts_;
};

// ============================================================================
// SECTION 17: OperServ Command Handler
// ============================================================================

class OperServCLIHandler {
public:
  OperServCLIHandler(OperServManager* operserv, AccountManagerFull* accounts,
                     HostServManager* hostserv, ServerNoticeMask* snomask)
    : operserv_(operserv), accounts_(accounts), hostserv_(hostserv),
      snomask_(snomask) {}

  std::string handle(const std::string& oper_nick, const std::string& msg) {
    std::stringstream ss(msg);
    std::string cmd;
    ss >> cmd;
    cmd = to_upper(cmd);

    if (cmd == "KLINE") {
      std::string mask, reason;
      ss >> mask;
      std::getline(ss, reason);
      if (!reason.empty() && reason[0] == ' ') reason = reason.substr(1);
      if (mask.empty()) return "Usage: KLINE <mask> [duration] :reason";
      // Parse optional duration
      int64_t dur = 3600; // default 1 hour
      if (reason.empty()) reason = "Banned by " + oper_nick;
      operserv_->add_kline(mask, reason, oper_nick, dur);
      // Send SNOMASK notice
      snomask_->format_sno_notice(ServerNoticeMask::SNOMASK_BANS,
                                   "KLINE added for " + mask + " by " + oper_nick);
      return "K:line added for " + mask + ".";
    }

    if (cmd == "UNKLINE") {
      std::string mask;
      ss >> mask;
      if (mask.empty()) return "Usage: UNKLINE <mask>";
      operserv_->del_kline(mask);
      return "K:line removed for " + mask + ".";
    }

    if (cmd == "ZLINE") {
      std::string ip, reason;
      ss >> ip;
      std::getline(ss, reason);
      if (!reason.empty() && reason[0] == ' ') reason = reason.substr(1);
      if (ip.empty()) return "Usage: ZLINE <ip/cidr> [duration] :reason";
      if (reason.empty()) reason = "Z:lined by " + oper_nick;
      operserv_->add_zline(ip, reason, oper_nick, 3600);
      snomask_->format_sno_notice(ServerNoticeMask::SNOMASK_BANS,
                                   "ZLINE added for " + ip + " by " + oper_nick);
      return "Z:line added for " + ip + ".";
    }

    if (cmd == "UNZLINE") {
      std::string ip;
      ss >> ip;
      if (ip.empty()) return "Usage: UNZLINE <ip>";
      operserv_->del_zline(ip);
      return "Z:line removed for " + ip + ".";
    }

    if (cmd == "GLINE") {
      std::string mask, reason;
      ss >> mask;
      std::getline(ss, reason);
      if (!reason.empty() && reason[0] == ' ') reason = reason.substr(1);
      if (mask.empty()) return "Usage: GLINE <mask> [duration] :reason";
      if (reason.empty()) reason = "G:lined by " + oper_nick;
      operserv_->add_gline(mask, reason, oper_nick, 86400);
      snomask_->format_sno_notice(ServerNoticeMask::SNOMASK_GLINES,
                                   "GLINE added for " + mask + " by " + oper_nick);
      return "G:line added for " + mask + ".";
    }

    if (cmd == "UNGLINE") {
      std::string mask;
      ss >> mask;
      if (mask.empty()) return "Usage: UNGLINE <mask>";
      operserv_->del_gline(mask);
      return "G:line removed for " + mask + ".";
    }

    if (cmd == "SHUN") {
      std::string mask, reason;
      ss >> mask;
      std::getline(ss, reason);
      if (!reason.empty() && reason[0] == ' ') reason = reason.substr(1);
      if (mask.empty()) return "Usage: SHUN <nick!user@host> [duration] :reason";
      if (reason.empty()) reason = "Shun by " + oper_nick;
      operserv_->add_shun(mask, reason, oper_nick, 3600);
      return "Shun added for " + mask + ".";
    }

    if (cmd == "UNSHUN") {
      std::string mask;
      ss >> mask;
      if (mask.empty()) return "Usage: UNSHUN <mask>";
      operserv_->del_shun(mask);
      return "Shun removed for " + mask + ".";
    }

    if (cmd == "JUPE") {
      std::string server, reason;
      ss >> server;
      std::getline(ss, reason);
      if (!reason.empty() && reason[0] == ' ') reason = reason.substr(1);
      if (server.empty()) return "Usage: JUPE <server> :reason";
      if (reason.empty()) reason = "Juped by " + oper_nick;
      operserv_->add_jupe(server, reason, oper_nick);
      snomask_->format_sno_notice(ServerNoticeMask::SNOMASK_JUPES,
                                   "JUPE added for " + server + " by " + oper_nick);
      return "Server " + server + " has been juped.";
    }

    if (cmd == "UNJUPE") {
      std::string server;
      ss >> server;
      if (server.empty()) return "Usage: UNJUPE <server>";
      operserv_->del_jupe(server);
      return "Jupe removed for " + server + ".";
    }

    if (cmd == "DNSBL") {
      std::string subcmd, param;
      ss >> subcmd >> param;
      subcmd = to_upper(subcmd);
      if (subcmd == "ADD") {
        std::string name, zone;
        ss >> name >> zone;
        operserv_->add_zone(param, zone);
        return "DNSBL zone " + param + " added.";
      }
      if (subcmd == "CHECK") {
        auto result = operserv_->check_ip(param);
        if (result.blacklisted)
          return param + " is blacklisted: " + result.dnsbl_name;
        return param + " is not blacklisted.";
      }
      return "Usage: DNSBL ADD|DEL|CHECK";
    }

    if (cmd == "SUSPEND") {
      std::string target, reason;
      ss >> target;
      std::getline(ss, reason);
      if (!reason.empty() && reason[0] == ' ') reason = reason.substr(1);
      if (target.empty()) return "Usage: SUSPEND <nick> :reason";
      if (accounts_->suspend(target))
        return "Account " + target + " suspended.";
      return "Account " + target + " not found.";
    }

    if (cmd == "UNSUSPEND") {
      std::string target;
      ss >> target;
      if (target.empty()) return "Usage: UNSUSPEND <nick>";
      if (accounts_->unsuspend(target))
        return "Account " + target + " unsuspended.";
      return "Account " + target + " not found.";
    }

    if (cmd == "FREEZE") {
      std::string target, reason;
      ss >> target;
      std::getline(ss, reason);
      if (target.empty()) return "Usage: FREEZE <nick> :reason";
      if (accounts_->freeze(target))
        return "Account " + target + " frozen.";
      return "Account " + target + " not found.";
    }

    if (cmd == "UNFREEZE") {
      std::string target;
      ss >> target;
      if (target.empty()) return "Usage: UNFREEZE <nick>";
      if (accounts_->unfreeze(target))
        return "Account " + target + " unfrozen.";
      return "Account " + target + " not found.";
    }

    if (cmd == "RESV") {
      std::string mask, reason;
      ss >> mask;
      std::getline(ss, reason);
      if (!reason.empty() && reason[0] == ' ') reason = reason.substr(1);
      if (mask.empty()) return "Usage: RESV <mask> :reason";
      operserv_->add_resv(mask, reason, oper_nick);
      return "RESV added for " + mask + ".";
    }

    if (cmd == "UNRESV") {
      std::string mask;
      ss >> mask;
      if (mask.empty()) return "Usage: UNRESV <mask>";
      operserv_->del_resv(mask);
      return "RESV removed for " + mask + ".";
    }

    if (cmd == "XLINE") {
      std::string pattern, reason;
      ss >> pattern;
      std::getline(ss, reason);
      if (!reason.empty() && reason[0] == ' ') reason = reason.substr(1);
      if (pattern.empty()) return "Usage: XLINE <regex> :reason";
      operserv_->add_xline(pattern, reason, oper_nick);
      snomask_->format_sno_notice(ServerNoticeMask::SNOMASK_XLINES,
                                   "XLINE added: " + pattern + " by " + oper_nick);
      return "XLine added: " + pattern;
    }

    if (cmd == "UNXLINE") {
      std::string pattern;
      ss >> pattern;
      if (pattern.empty()) return "Usage: UNXLINE <pattern>";
      operserv_->del_xline(pattern);
      return "XLine removed: " + pattern;
    }

    if (cmd == "STATS") {
      return handle_stats();
    }

    if (cmd == "SNOMASK") {
      std::string mask;
      ss >> mask;
      if (mask.empty()) return "Usage: SNOMASK <+flags>";
      snomask_->set_snomask(oper_nick, mask);
      return "SNOMASK set to " + mask;
    }

    return "Unknown OperServ command. Try: KLINE, ZLINE, GLINE, SHUN, JUPE, "
           "DNSBL, SUSPEND, FREEZE, RESV, XLINE, STATS, SNOMASK";
  }

private:
  std::string handle_stats() {
    auto klines  = operserv_->list_klines();
    auto zlines  = operserv_->list_zlines();
    auto glines  = operserv_->list_glines();
    auto shuns   = operserv_->list_shuns();
    auto jupes   = operserv_->list_jupes();
    auto reservs = operserv_->list_resv();

    std::stringstream ss;
    ss << "OperServ stats: "
       << klines.size() << " K:lines, "
       << zlines.size() << " Z:lines, "
       << glines.size() << " G:lines, "
       << shuns.size() << " shuns, "
       << jupes.size() << " jupes, "
       << reservs.size() << " RESVs.";
    return ss.str();
  }

  OperServManager* operserv_;
  AccountManagerFull* accounts_;
  HostServManager* hostserv_;
  ServerNoticeMask* snomask_;
};

// ============================================================================
// SECTION 18: Unified IRC Server Extension (Integration Hub)
// ============================================================================

// This class brings together all the extended IRC subsystems from this file.
// It acts as the integration point that the main IRCServer can delegate to.
class IRCFullServerC {
public:
  IRCFullServerC() :
    nickserv_(&accounts_, &hostserv_),
    chanserv_(&channels_, &accounts_),
    hostserv_cli_(&hostserv_, &accounts_),
    operserv_cli_(&operserv_, &accounts_, &hostserv_, &snomask_) {}

  // ======= Accessors for all subsystems =======

  AccountManagerFull& accounts()       { return accounts_; }
  ChannelRegistrationFull& channels()  { return channels_; }
  HostServManager& hostserv()          { return hostserv_; }
  OperServManager& operserv()          { return operserv_; }
  WHOXHandler& whox()                  { return whox_; }
  WatchMonitorManager& watchmonitor()  { return watchmon_; }
  MessageTagManagerFull& msg_tags()    { return msg_tags_; }
  TransportSecurityManager& tls()      { return transport_; }
  WebSocketIRC& websocket()            { return ws_irc_; }
  ServerIgnore& server_ignore()        { return ignore_; }
  IdentLookup& ident()                 { return ident_; }
  ConnectionLogger& conn_logger()      { return conn_logger_; }
  ServerNoticeMask& snomask()          { return snomask_; }
  NickServHandler& nickserv_handler()  { return nickserv_; }
  ChanServHandler& chanserv_handler()  { return chanserv_; }
  HostServCLIHandler& hostserv_cli()   { return hostserv_cli_; }
  OperServCLIHandler& operserv_cli()   { return operserv_cli_; }

  // ======= Services command routing =======

  // Route a PRIVMSG to the appropriate service bot
  std::string route_service(const std::string& target, const std::string& sender,
                            const std::string& message, bool sender_is_oper = false) {
    std::string svc = to_upper(target);

    if (svc == "NICKSERV") {
      return nickserv_.handle(sender, message);
    }
    if (svc == "CHANSERV") {
      return chanserv_.handle(sender, message);
    }
    if (svc == "HOSTSERV") {
      return hostserv_cli_.handle(sender, message, sender_is_oper);
    }
    if (svc == "OPERSERV") {
      if (!sender_is_oper)
        return "Permission denied. You must be an IRC operator to use OperServ.";
      return operserv_cli_.handle(sender, message);
    }
    return "";
  }

  // ======= Connection lifecycle =======

  void on_connect(const std::string& nick, const std::string& real_ip,
                  const std::string& real_host, int port, bool tls) {
    conn_logger_.log_connect(nick, real_ip, real_host, port, tls);
    // Start ident lookup
    ident_.start_lookup(real_ip, port, port > 0 ? port : 6667, nick);
    // Log to HostServ
    hostserv_.log_connection(nick, real_host, real_ip);
  }

  void on_disconnect(const std::string& nick, const std::string& reason) {
    conn_logger_.log_disconnect(nick, reason);
    accounts_.logout(nick);
  }

  // ======= Pre-connection checks =======

  struct PreConnectCheck {
    bool allowed = true;
    std::string deny_reason;
    std::string ban_type; // "KLINE", "ZLINE", "GLINE", "XLINE", "RESV"
  };

  PreConnectCheck check_can_connect(const std::string& ip, const std::string& nick,
                                     const std::string& realname = "") {
    PreConnectCheck result;

    // Check ZLINE (IP ban)
    if (operserv_.check_zline(ip)) {
      result.allowed = false;
      result.deny_reason = "You are Z:lined from this server.";
      result.ban_type = "ZLINE";
      return result;
    }

    // Check KLINE
    if (operserv_.check_kline(nick + "!" + nick + "@" + ip)) {
      result.allowed = false;
      result.deny_reason = "You are K:lined from this server.";
      result.ban_type = "KLINE";
      return result;
    }

    // Check GLINE
    if (operserv_.check_gline(nick + "@" + ip)) {
      result.allowed = false;
      result.deny_reason = "You are G:lined from this server.";
      result.ban_type = "GLINE";
      return result;
    }

    // Check RESV (nick/channel reservation)
    if (operserv_.is_reserved(nick)) {
      result.allowed = false;
      result.deny_reason = "That nickname is reserved.";
      result.ban_type = "RESV";
      return result;
    }

    // Check XLINE (regex match against nick/realname)
    std::string xline_reason;
    if (operserv_.check_nick_xline(nick, xline_reason)) {
      result.allowed = false;
      result.deny_reason = "Nick matches XLine: " + xline_reason;
      result.ban_type = "XLINE";
      return result;
    }

    // JUPE check (for server connections)
    if (operserv_.is_juped(nick)) {
      result.allowed = false;
      result.deny_reason = "Server is juped.";
      result.ban_type = "JUPE";
      return result;
    }

    return result;
  }

  // ======= WHOX integration =======

  std::string build_whox(const std::string& target, const IRCUser& user,
                          const std::string& flags,
                          const std::string& certfp = "",
                          const std::string& real_ip = "",
                          const std::string& channel = "",
                          int access_level = 0) {
    return whox_.build_whox_reply(target, user, flags, &accounts_,
                                   certfp, real_ip, channel, access_level);
  }

  // ======= Watch/Monitor broadcasts =======

  void notify_online(const std::string& nick) {
    // Update monitor lists
    watchmon_.notify_online(nick);
    // (broadcasting would be handled by caller)
  }

  void notify_offline(const std::string& nick) {
    watchmon_.notify_offline(nick);
  }

  // ======= Connection stats =======

  struct ServerStats {
    int64_t total_connections;
    int64_t active_connections;
    int64_t registered_nicks;
    int64_t registered_channels;
    int64_t klines_active;
    int64_t zlines_active;
    int64_t glines_active;
    int64_t shuns_active;
  };

  ServerStats get_stats() {
    ServerStats s;
    s.total_connections = 0; // From parent server
    s.active_connections = 0;
    s.registered_nicks = 0;  // Account count
    s.registered_channels = 0;
    s.klines_active = operserv_.list_klines().size();
    s.zlines_active = operserv_.list_zlines().size();
    s.glines_active = operserv_.list_glines().size();
    s.shuns_active = operserv_.list_shuns().size();
    return s;
  }

private:
  AccountManagerFull accounts_;
  ChannelRegistrationFull channels_;
  HostServManager hostserv_;
  OperServManager operserv_;
  WHOXHandler whox_;
  WatchMonitorManager watchmon_;
  MessageTagManagerFull msg_tags_;
  TransportSecurityManager transport_;
  WebSocketIRC ws_irc_;
  ServerIgnore ignore_;
  IdentLookup ident_;
  ConnectionLogger conn_logger_;
  ServerNoticeMask snomask_;

  // CLI command handlers (depend on the managers above)
  NickServHandler nickserv_;
  ChanServHandler chanserv_;
  HostServCLIHandler hostserv_cli_;
  OperServCLIHandler operserv_cli_;
};

// ============================================================================
// SECTION 19: End-of-file markers and static assertions
// ============================================================================

static_assert(sizeof(HostServManager) > 0, "HostServManager must be complete");
static_assert(sizeof(AccountManagerFull) > 0, "AccountManagerFull must be complete");
static_assert(sizeof(ChannelRegistrationFull) > 0, "ChannelRegistrationFull must be complete");
static_assert(sizeof(OperServManager) > 0, "OperServManager must be complete");
static_assert(sizeof(WHOXHandler) > 0, "WHOXHandler must be complete");
static_assert(sizeof(WatchMonitorManager) > 0, "WatchMonitorManager must be complete");
static_assert(sizeof(MessageTagManagerFull) > 0, "MessageTagManagerFull must be complete");
static_assert(sizeof(TransportSecurityManager) > 0, "TransportSecurityManager must be complete");
static_assert(sizeof(WebSocketIRC) > 0, "WebSocketIRC must be complete");
static_assert(sizeof(ServerIgnore) > 0, "ServerIgnore must be complete");
static_assert(sizeof(IdentLookup) > 0, "IdentLookup must be complete");
static_assert(sizeof(ConnectionLogger) > 0, "ConnectionLogger must be complete");
static_assert(sizeof(ServerNoticeMask) > 0, "ServerNoticeMask must be complete");
static_assert(sizeof(NickServHandler) > 0, "NickServHandler must be complete");
static_assert(sizeof(ChanServHandler) > 0, "ChanServHandler must be complete");
static_assert(sizeof(HostServCLIHandler) > 0, "HostServCLIHandler must be complete");
static_assert(sizeof(OperServCLIHandler) > 0, "OperServCLIHandler must be complete");
static_assert(sizeof(IRCFullServerC) > 0, "IRCFullServerC must be complete");

} // namespace progressive::irc
