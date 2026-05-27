// irc_config_oper.cpp — Complete IRC server configuration, operator blocks,
// connection class system, ban/exception/deny/allow blocks, logging config,
// vHost blocks, include directives, SIGHUP reload, and validation.
//
// References: IRC RFC 1459/2812/2813, InspIRCd config_reader.cpp,
// UnrealIRCd config parser, ngIRCd conf.c, Bahamut config parser,
// ircd-hybrid conf_parser.c, Charybdis newconf.c
//
// Config format: key=value pairs and named blocks { ... }
// Blocks: listen, oper, connect, class, admin, motd, except, deny,
//          allow, vhost, log, include
// Oper privileges: granular flags system (can_restart, can_die, can_rehash,
//   can_globops, can_wallops, can_kill, can_gline, can_unkline,
//   can_local_kill, can_kline, can_unkline, can_zline, can_unkzline,
//   can_gzline, can_unkgzline, can_rehash, can_jupe, can_restart_server,
//   can_die_server, can_admin, can_override, can_opermotd, can_operwall,
//   can_globalroute, can_localkill, can_set, can_squit, can_sajoin,
//   can_sapart, can_samode, can_sakick, can_satopic, can_swhois,
//   can_chghost, can_chgident, can_chgname, can_hideoper, etc.)

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <optional>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace progressive {
namespace irc {

// ============================================================================
// Constants
// ============================================================================

static constexpr size_t CONFIG_LINE_MAX = 4096;
static constexpr size_t CONFIG_INCLUDE_DEPTH_MAX = 16;
static constexpr size_t CONFIG_BLOCK_NEST_MAX = 8;
static constexpr int CONFIG_RELOAD_SIGNAL = SIGHUP;
static constexpr const char* CONFIG_DEFAULT_PATH = "ircd.conf";
static constexpr int DEFAULT_SENDQ = 262144;        // 256 KB
static constexpr int DEFAULT_RECVQ = 65536;         // 64 KB
static constexpr int DEFAULT_PING_FREQ = 120;       // seconds
static constexpr int DEFAULT_CONN_FREQ = 0;         // no limit
static constexpr int DEFAULT_MAX_CHANNELS = 20;
static constexpr int DEFAULT_MAX_CLIENTS = 1024;
static constexpr int DEFAULT_MAX_LINKS = 64;
static constexpr int DEFAULT_MAX_AWAY_LEN = 200;
static constexpr int DEFAULT_MAX_KICK_LEN = 255;
static constexpr int DEFAULT_MAX_TOPIC_LEN = 390;
static constexpr int DEFAULT_MAX_NICK_LEN = 30;
static constexpr int DEFAULT_MAX_SILENCE = 15;
static constexpr int DEFAULT_MAX_WATCH = 30;
static constexpr int DEFAULT_THROTTLE_COUNT = 4;
static constexpr int DEFAULT_THROTTLE_TIME = 60;
static constexpr int DEFAULT_OPER_HOST_ATTEMPTS = 3;
static constexpr int DEFAULT_SSLIN_HANDSHAKE_TIMEOUT = 30;
static constexpr int DEFAULT_MIN_NICK_LEN = 1;
static constexpr const char* DEFAULT_SERVER_NAME = "progressive.irc";
static constexpr const char* DEFAULT_NETWORK_NAME = "ProgressiveNet";
static constexpr const char* DEFAULT_SERVER_DESC = "Progressive IRC Server";
static constexpr const char* DEFAULT_ADMIN_NAME = "Admin";
static constexpr const char* DEFAULT_ADMIN_EMAIL = "admin@example.com";
static constexpr const char* DEFAULT_ADMIN_LOC = "Unknown";

// ============================================================================
// Forward declarations
// ============================================================================

class ConfigParser;

// ============================================================================
// Oper privilege flags — bitmask system for granular operator permissions
// ============================================================================

enum class OperFlag : uint64_t {
  // Core oper flags
  CAN_RESTART          = 1ULL << 0,
  CAN_DIE              = 1ULL << 1,
  CAN_REHASH           = 1ULL << 2,
  CAN_GLOBOPS          = 1ULL << 3,
  CAN_WALLOPS          = 1ULL << 4,
  CAN_KILL             = 1ULL << 5,
  CAN_KLINE            = 1ULL << 6,
  CAN_UNKLINE          = 1ULL << 7,
  CAN_GLINE            = 1ULL << 8,
  CAN_UNGLINE          = 1ULL << 9,
  CAN_ZLINE            = 1ULL << 10,
  CAN_UNZLINE          = 1ULL << 11,
  CAN_GZLINE           = 1ULL << 12,
  CAN_UNGZLINE         = 1ULL << 13,
  CAN_LOCAL_KILL       = 1ULL << 14,
  CAN_REMOTE_KILL      = 1ULL << 15,
  CAN_JUPE             = 1ULL << 16,
  CAN_LOCAL_JUPE       = 1ULL << 17,
  CAN_SQUIT            = 1ULL << 18,
  CAN_LOCAL_SQUIT      = 1ULL << 19,
  CAN_CONNECT          = 1ULL << 20,
  CAN_LOCAL_CONNECT    = 1ULL << 21,
  CAN_DCCDENY          = 1ULL << 22,
  CAN_UNDCCDENY        = 1ULL << 23,
  CAN_ADMIN            = 1ULL << 24,
  CAN_OVERRIDE         = 1ULL << 25,
  CAN_OPERMOTD         = 1ULL << 26,
  CAN_OPERWALL         = 1ULL << 27,
  CAN_GLOBALROUTE      = 1ULL << 28,
  CAN_SET              = 1ULL << 29,   // SET command
  CAN_SAJOIN           = 1ULL << 30,
  CAN_SAPART           = 1ULL << 31,
  CAN_SAMODE           = 1ULL << 32,
  CAN_SAKICK           = 1ULL << 33,
  CAN_SATOPIC          = 1ULL << 34,
  CAN_SWHOIS           = 1ULL << 35,
  CAN_CHGHOST          = 1ULL << 36,
  CAN_CHGIDENT         = 1ULL << 37,
  CAN_CHGNAME          = 1ULL << 38,
  CAN_HIDEOPER         = 1ULL << 39,
  CAN_SEE_HIDDEN       = 1ULL << 40,
  CAN_SEE_CHANS        = 1ULL << 41,
  CAN_SEE_OPS          = 1ULL << 42,
  CAN_SEE_INVIS        = 1ULL << 43,
  CAN_SEE_SECRET_CHANS = 1ULL << 44,
  CAN_SEE_ALL_CHANS    = 1ULL << 45,
  CAN_JOIN_OPERSONLY   = 1ULL << 46,
  CAN_FLOOD_EXEMPT     = 1ULL << 47,
  CAN_NO_CTCP          = 1ULL << 48,
  CAN_UNLIMITED_SENDQ  = 1ULL << 49,
  CAN_ALWAYS_OP        = 1ULL << 50,  // Always gets +o in channels (services)
  CAN_DEOP_PROTECT     = 1ULL << 51,
  CAN_SVSJOIN          = 1ULL << 52,
  CAN_SVSNICK          = 1ULL << 53,
  CAN_SVSNOOP          = 1ULL << 54,
  CAN_SVSKILL          = 1ULL << 55,
  CAN_SVSMODE          = 1ULL << 56,
  CAN_SVSSNO           = 1ULL << 57,
  CAN_SVSSQUIT         = 1ULL << 58,
  CAN_SVSADMIN         = 1ULL << 59,
};

// Pre-defined privilege sets
namespace OperPrivilegeSets {
  // Full netadmin — all flags
  static constexpr uint64_t NETADMIN = ~0ULL;

  // Standard global IRC operator
  static constexpr uint64_t GLOBAL_OPER =
      static_cast<uint64_t>(OperFlag::CAN_KILL) |
      static_cast<uint64_t>(OperFlag::CAN_GLOBOPS) |
      static_cast<uint64_t>(OperFlag::CAN_WALLOPS) |
      static_cast<uint64_t>(OperFlag::CAN_KLINE) |
      static_cast<uint64_t>(OperFlag::CAN_UNKLINE) |
      static_cast<uint64_t>(OperFlag::CAN_GLINE) |
      static_cast<uint64_t>(OperFlag::CAN_UNGLINE) |
      static_cast<uint64_t>(OperFlag::CAN_ZLINE) |
      static_cast<uint64_t>(OperFlag::CAN_UNZLINE) |
      static_cast<uint64_t>(OperFlag::CAN_LOCAL_KILL) |
      static_cast<uint64_t>(OperFlag::CAN_REHASH) |
      static_cast<uint64_t>(OperFlag::CAN_OVERRIDE) |
      static_cast<uint64_t>(OperFlag::CAN_OPERMOTD) |
      static_cast<uint64_t>(OperFlag::CAN_SEE_HIDDEN) |
      static_cast<uint64_t>(OperFlag::CAN_SEE_CHANS) |
      static_cast<uint64_t>(OperFlag::CAN_SQUIT) |
      static_cast<uint64_t>(OperFlag::CAN_CONNECT);

  // Local operator — can only act on the local server
  static constexpr uint64_t LOCAL_OPER =
      static_cast<uint64_t>(OperFlag::CAN_LOCAL_KILL) |
      static_cast<uint64_t>(OperFlag::CAN_REHASH) |
      static_cast<uint64_t>(OperFlag::CAN_GLOBOPS) |
      static_cast<uint64_t>(OperFlag::CAN_WALLOPS) |
      static_cast<uint64_t>(OperFlag::CAN_KLINE) |
      static_cast<uint64_t>(OperFlag::CAN_UNKLINE) |
      static_cast<uint64_t>(OperFlag::CAN_OPERMOTD) |
      static_cast<uint64_t>(OperFlag::CAN_SEE_HIDDEN) |
      static_cast<uint64_t>(OperFlag::CAN_SEE_CHANS);

  // Services bot — special permissions
  static constexpr uint64_t SERVICES =
      static_cast<uint64_t>(OperFlag::CAN_ALWAYS_OP) |
      static_cast<uint64_t>(OperFlag::CAN_OVERRIDE) |
      static_cast<uint64_t>(OperFlag::CAN_SEE_ALL_CHANS) |
      static_cast<uint64_t>(OperFlag::CAN_SEE_HIDDEN) |
      static_cast<uint64_t>(OperFlag::CAN_UNLIMITED_SENDQ) |
      static_cast<uint64_t>(OperFlag::CAN_FLOOD_EXEMPT) |
      static_cast<uint64_t>(OperFlag::CAN_KILL) |
      static_cast<uint64_t>(OperFlag::CAN_SWHOIS) |
      static_cast<uint64_t>(OperFlag::CAN_SVSJOIN) |
      static_cast<uint64_t>(OperFlag::CAN_SVSNICK) |
      static_cast<uint64_t>(OperFlag::CAN_SVSMODE) |
      static_cast<uint64_t>(OperFlag::CAN_SVSADMIN);

  // Helper: does flags contain a specific flag?
  inline bool has_flag(uint64_t flags, OperFlag f) {
    return (flags & static_cast<uint64_t>(f)) != 0;
  }
}

// ============================================================================
// Utility helpers
// ============================================================================

namespace {

int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string to_upper(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return s;
}

std::string to_lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::string trim(const std::string& s) {
  size_t start = 0;
  while (start < s.size() && (s[start] == ' ' || s[start] == '\t' ||
                               s[start] == '\r' || s[start] == '\n'))
    ++start;
  size_t end = s.size();
  while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' ||
                          s[end - 1] == '\r' || s[end - 1] == '\n'))
    --end;
  return s.substr(start, end - start);
}

std::string strip_comments(const std::string& line) {
  // Strip C-style (//) and shell-style (#) comments
  // But respect quoted strings
  bool in_quote_single = false;
  bool in_quote_double = false;
  for (size_t i = 0; i < line.size(); ++i) {
    if (line[i] == '\'' && !in_quote_double) {
      in_quote_single = !in_quote_single;
    } else if (line[i] == '"' && !in_quote_single) {
      in_quote_double = !in_quote_double;
    } else if (!in_quote_single && !in_quote_double) {
      if (line[i] == '#' || (line[i] == '/' && i + 1 < line.size() && line[i + 1] == '/')) {
        return line.substr(0, i);
      }
    }
  }
  return line;
}

bool wildcard_match(const std::string& pattern, const std::string& str) {
  size_t pi = 0, si = 0, star = std::string::npos, ss = 0;
  while (si < str.size()) {
    if (pi < pattern.size() &&
        (pattern[pi] == '?' ||
         std::tolower(pattern[pi]) == std::tolower(str[si]))) {
      ++pi; ++si;
    } else if (pi < pattern.size() && pattern[pi] == '*') {
      star = pi++; ss = si;
    } else if (star != std::string::npos) {
      pi = star + 1; si = ++ss;
    } else return false;
  }
  while (pi < pattern.size() && pattern[pi] == '*') ++pi;
  return pi == pattern.size();
}

bool cidr_match(const std::string& cidr, const std::string& ip) {
  auto slash = cidr.find('/');
  if (slash == std::string::npos) return cidr == ip;
  std::string net = cidr.substr(0, slash);
  int bits = std::stoi(cidr.substr(slash + 1));
  // Check for IPv6
  if (ip.find(':') != std::string::npos || net.find(':') != std::string::npos) {
    struct in6_addr net_addr, ip_addr;
    if (inet_pton(AF_INET6, net.c_str(), &net_addr) != 1) return false;
    if (inet_pton(AF_INET6, ip.c_str(), &ip_addr) != 1) return false;
    int byte = 0;
    for (; byte < bits / 8; ++byte) {
      if (net_addr.s6_addr[byte] != ip_addr.s6_addr[byte]) return false;
    }
    int remaining = bits % 8;
    if (remaining > 0) {
      uint8_t mask = 0xFF << (8 - remaining);
      if ((net_addr.s6_addr[byte] & mask) != (ip_addr.s6_addr[byte] & mask)) return false;
    }
    return true;
  }
  // IPv4
  struct in_addr net_addr, ip_addr;
  if (inet_pton(AF_INET, net.c_str(), &net_addr) != 1) return false;
  if (inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1) return false;
  uint32_t mask = (bits == 0) ? 0 : htonl(0xFFFFFFFF << (32 - bits));
  return (net_addr.s_addr & mask) == (ip_addr.s_addr & mask);
}

// Simple SHA256 stub (real implementation would use OpenSSL)
std::string sha256(const std::string& input) {
  // Production code will use EVP_Digest or similar
  // Stub returning deterministic placeholder for now
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (unsigned char c : input) ss << std::setw(2) << (int)c;
  return "sha256:" + ss.str();
}

// Simple random string generator
std::string random_string(size_t len) {
  static const char chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  static std::mt19937 rng(std::random_device{}());
  std::uniform_int_distribution<> dist(0, sizeof(chars) - 2);
  std::string s(len, '\0');
  for (size_t i = 0; i < len; ++i) s[i] = chars[dist(rng)];
  return s;
}

// Split string by delimiter
std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> v;
  std::stringstream ss(s); std::string item;
  while (std::getline(ss, item, delim)) {
    item = trim(item);
    if (!item.empty()) v.push_back(item);
  }
  return v;
}

bool file_exists(const std::string& path) {
  struct stat st;
  return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

std::string dirname_of(const std::string& path) {
  auto pos = path.rfind('/');
  if (pos == std::string::npos) return ".";
  return path.substr(0, pos);
}

std::string resolve_include_path(const std::string& include_path,
                                  const std::string& relative_to) {
  if (include_path.empty()) return include_path;
  // Absolute paths
  if (include_path[0] == '/') return include_path;
  // Relative to config file directory
  std::string base = dirname_of(relative_to);
  return base + "/" + include_path;
}

} // anonymous namespace

// ============================================================================
// Data structures for configuration
// ============================================================================

// ---- Listen block ----
struct ListenBlock {
  std::string address = "*";          // bind address, "*" = all
  int port = 6667;                    // port number
  bool ssl = false;                   // SSL/TLS enabled?
  std::string ssl_cert;               // PEM certificate path
  std::string ssl_key;                // PEM key path
  std::string ssl_dh_params;          // DH params file
  std::string ssl_cipher_list;        // OpenSSL cipher list
  std::string type = "clients";       // "clients", "servers", "services"
  bool ipv4 = true;
  bool ipv6 = false;
  int defer_accept = 0;              // TCP_DEFER_ACCEPT timeout
  int tcp_backlog = 128;
  bool tcp_nodelay = true;
  bool tcp_keepalive = true;
  int tcp_keepalive_idle = 60;
  int tcp_keepalive_intvl = 10;
  int tcp_keepalive_cnt = 5;
  bool so_reuseaddr = true;
  int max_clients_per_ip = 5;
  int max_total_clients = 0;         // 0 = no limit
  bool hidden = false;               // Don't show in /stats P
  bool cloaking = false;             // Enable hostname cloaking
  bool websocket = false;            // WebSocket gateway
  std::string websocket_origin;      // Allowed origin for WS
  bool verified_only = false;        // Only accept verified users

  bool is_valid() const {
    return port > 0 && port <= 65535;
  }

  std::string to_string() const {
    std::stringstream ss;
    ss << "ListenBlock{address=" << address << ", port=" << port
       << ", ssl=" << (ssl ? "yes" : "no") << ", type=" << type
       << ", ipv4=" << (ipv4 ? "yes" : "no") << ", ipv6=" << (ipv6 ? "yes" : "no")
       << "}";
    return ss.str();
  }
};

// ---- Connect block (server linking) ----
struct ConnectBlock {
  std::string name;                    // Server name
  std::string host;                    // Host or IP to connect to
  int port = 6667;                     // Port
  std::string password;                // Link password (plain or hash)
  std::string password_hash;           // Hashed password (SHA256/BCrypt)
  std::string send_password;           // Outgoing password
  std::string accept_password;         // Incoming password
  std::string fingerprint;             // SSL certificate fingerprint
  std::string bind_address;            // Local address to bind
  std::string class_name = "servers";  // Connection class
  bool ssl = false;                    // Use SSL for this link
  bool autoconnect = false;            // Auto-connect on startup
  int auto_connect_delay = 30;         // Seconds between reconnect attempts
  int max_retry = 3;                   // Max retry attempts before giving up
  bool hub = false;                    // This server is a hub
  bool leaf = false;                   // This server is a leaf
  bool topic_burst = true;             // Burst topics on connect
  bool zip_links = false;              // Compress link traffic
  int timeout = 60;                    // Connection timeout (seconds)
  int max_sendq = DEFAULT_SENDQ;       // Max send queue
  int max_recvq = DEFAULT_RECVQ;       // Max recv queue
  std::string flags = "";             // Additional flags string
  bool verified = false;              // Requires verified SSL

  bool is_valid() const {
    return !name.empty() && !host.empty() && port > 0 && port <= 65535;
  }

  std::string to_string() const {
    std::stringstream ss;
    ss << "ConnectBlock{name=" << name << ", host=" << host << ":" << port
       << ", ssl=" << (ssl ? "yes" : "no") << ", autoconnect=" << (autoconnect ? "yes" : "no")
       << ", class=" << class_name << "}";
    return ss.str();
  }
};

// ---- Class block (connection class) ----
struct ClassBlock {
  std::string name;                    // Class name
  int ping_freq = DEFAULT_PING_FREQ;   // Ping interval (seconds)
  int ping_warning = 15;              // Warning before timeout
  int conn_freq = DEFAULT_CONN_FREQ;   // Max connections per interval (0 = unlimited)
  int max_clients = DEFAULT_MAX_CLIENTS;
  int max_channels = DEFAULT_MAX_CHANNELS;
  int max_sendq = DEFAULT_SENDQ;       // Max send queue (bytes)
  int max_recvq = DEFAULT_RECVQ;       // Max recv queue (bytes)
  int max_away_len = DEFAULT_MAX_AWAY_LEN;
  int max_kick_len = DEFAULT_MAX_KICK_LEN;
  int max_topic_len = DEFAULT_MAX_TOPIC_LEN;
  int max_nick_len = DEFAULT_MAX_NICK_LEN;
  int max_silence = DEFAULT_MAX_SILENCE;
  int max_watch = DEFAULT_MAX_WATCH;
  int throttle_count = DEFAULT_THROTTLE_COUNT;
  int throttle_time = DEFAULT_THROTTLE_TIME;
  int oper_host_attempts = DEFAULT_OPER_HOST_ATTEMPTS;
  int timeout = 300;                   // Idle timeout (seconds)
  int registration_timeout = 30;       // Time to complete registration
  bool no_tilde = true;               // Strip ~ from username if ident fails
  bool ident_check = true;            // Check ident on connect
  int ident_timeout = 10;             // Ident lookup timeout
  std::string modes_on_connect = "+i"; // Default user modes
  std::string restrict_to = "";       // Restrict class to specific IP ranges
  std::string reserved_nick_prefix = ""; // Users in this class get prefix

  bool is_valid() const {
    return !name.empty() && ping_freq > 0;
  }

  std::string to_string() const {
    std::stringstream ss;
    ss << "ClassBlock{name=" << name << ", ping_freq=" << ping_freq
       << ", max_clients=" << max_clients << ", max_channels=" << max_channels
       << ", sendq=" << max_sendq << ", recvq=" << max_recvq
       << ", connfreq=" << conn_freq << "}";
    return ss.str();
  }
};

// ---- Operator block ----
struct OperBlock {
  std::string name;                    // Operator login name
  std::string password;                // Plaintext password
  std::string password_hash;           // Hashed password
  std::string hash_method = "sha256";  // "sha256", "bcrypt", "md5", "plaintext"
  std::string hostmask = "*@*";        // Allowed hostmask(s)
  std::vector<std::string> hostmasks;  // Multiple hostmasks
  std::string class_name = "opers";    // Connection class after oper-up
  std::string oper_class;              // Alias for class_name
  uint64_t flags = 0;                  // Privilege bitmask
  bool auto_login = false;            // Auto-oper from matching hostmasks
  bool ssl_only = false;              // Require SSL connection
  bool certfp_required = false;       // Require SSL cert fingerprint match
  std::string certfp;                  // SSL cert fingerprint (SHA256)
  std::string vhost;                   // vHost after oper-up
  std::string modes_on_oper = "+oW";   // Modes set on oper-up
  std::string snomask = "+s";         // Server notice mask
  int max_logins = 0;                // Max concurrent logins (0=unlimited)
  int failed_attempts = 0;            // Count of failed /oper attempts
  int64_t last_failed = 0;
  bool immune_to_klines = false;
  bool immune_to_gline = false;
  bool immune_to_restrictions = false;
  bool immune_to_shun = false;
  bool override_block = false;
  int oper_watch = 0;                 // Notify on oper connect/disconnect

  bool is_valid() const {
    return !name.empty() && (!password.empty() || !password_hash.empty()) && !hostmasks.empty();
  }

  bool match_host(const std::string& user_host_mask) const {
    if (hostmasks.empty()) return false;
    for (const auto& hm : hostmasks) {
      if (wildcard_match(hm, user_host_mask)) return true;
    }
    return false;
  }

  bool check_password(const std::string& provided) const {
    if (hash_method == "plaintext") {
      return password == provided;
    }
    // Hash the provided password and compare
    std::string hashed;
    if (hash_method == "sha256") {
      hashed = sha256(provided);
    } else if (hash_method == "md5") {
      // MD5 stub — real code uses EVP_md5
      hashed = "md5:" + provided;
    } else {
      // Unknown method, fallback to plaintext
      return password == provided;
    }
    return hashed == password_hash;
  }

  std::string to_string() const {
    std::stringstream ss;
    ss << "OperBlock{name=" << name << ", hash=" << hash_method
       << ", hostmasks=" << hostmasks.size() << ", flags=0x"
       << std::hex << flags << std::dec << ", class=" << class_name << "}";
    return ss.str();
  }
};

// ---- Exception block (klines/glines/zlines exempt) ----
struct ExceptionBlock {
  std::string mask;                    // n!u@h mask or CIDR
  std::string reason;                  // Why this exception exists
  std::string set_by;                  // Who set it
  int64_t set_at = 0;                  // When set
  int64_t expires_at = 0;              // Expiry time (0 = permanent)
  bool active = true;
  std::string types;                  // "k"=kline, "g"=gline, "z"=zline, "*"=all

  bool matches(const std::string& user_mask) const {
    if (!active) return false;
    if (types.find('*') != std::string::npos) return wildcard_match(mask, user_mask);
    return wildcard_match(mask, user_mask);
  }

  bool is_expired() const {
    if (expires_at == 0) return false;
    return now_sec() > expires_at;
  }

  std::string to_string() const {
    std::stringstream ss;
    ss << "ExceptionBlock{mask=" << mask << ", types=" << types
       << ", reason=" << reason << ", by=" << set_by
       << ", expires=" << expires_at << "}";
    return ss.str();
  }
};

// ---- Deny block ----
struct DenyBlock {
  std::string mask;                    // IP, hostmask, or CIDR
  std::string type = "all";           // "all", "connect", "chat"
  std::string reason = "You are banned from this server";
  std::string redirect_ip;            // Redirect to another server
  int redirect_port = 6667;
  bool active = true;
  int64_t set_at = 0;
  int64_t expires_at = 0;             // 0 = permanent
  std::string set_by;

  bool is_expired() const {
    if (expires_at == 0) return false;
    return now_sec() > expires_at;
  }

  bool matches(const std::string& ip_or_mask) const {
    if (!active || is_expired()) return false;
    // Check direct IP match
    if (ip_or_mask == mask) return true;
    // Check CIDR match
    if (mask.find('/') != std::string::npos) {
      return cidr_match(mask, ip_or_mask);
    }
    // Check wildcard match
    return wildcard_match(mask, ip_or_mask);
  }

  std::string to_string() const {
    std::stringstream ss;
    ss << "DenyBlock{mask=" << mask << ", type=" << type
       << ", reason=" << reason << "}";
    return ss.str();
  }
};

// ---- Allow block (whitelist, overrides deny) ----
struct AllowBlock {
  std::string mask;                    // IP, hostmask, or CIDR
  int max_clients_per_ip = 0;          // Override default limit
  std::string class_name = "";
  bool password_required = false;
  std::string password;
  bool active = true;
  std::string redirect_ip;
  int redirect_port = 0;
  bool can_bypass_clones = false;
  bool can_bypass_throttle = false;

  bool matches(const std::string& ip_or_mask) const {
    if (!active) return false;
    if (mask.find('/') != std::string::npos) {
      return cidr_match(mask, ip_or_mask);
    }
    return wildcard_match(mask, ip_or_mask);
  }

  std::string to_string() const {
    std::stringstream ss;
    ss << "AllowBlock{mask=" << mask
       << ", max_per_ip=" << max_clients_per_ip
       << ", pass=" << (password_required ? "yes" : "no") << "}";
    return ss.str();
  }
};

// ---- VHost block ----
struct VHostBlock {
  std::string login;                   // Account/login name
  std::string password;                // Password to activate
  std::string vhost;                   // Virtual host
  std::string set_by;
  int64_t set_at = 0;
  int64_t expires_at = 0;
  bool active = true;

  bool is_valid() const {
    return !login.empty() && !vhost.empty();
  }

  bool is_expired() const {
    if (expires_at == 0) return false;
    return now_sec() > expires_at;
  }

  std::string to_string() const {
    std::stringstream ss;
    ss << "VHostBlock{login=" << login << ", vhost=" << vhost
       << ", active=" << (active ? "yes" : "no") << "}";
    return ss.str();
  }
};

// ---- Admin info block ----
struct AdminInfo {
  std::string name = DEFAULT_ADMIN_NAME;
  std::string email = DEFAULT_ADMIN_EMAIL;
  std::string location = DEFAULT_ADMIN_LOC;
  std::string description;
  std::vector<std::string> extra_lines;

  std::string to_string() const {
    std::stringstream ss;
    ss << "AdminInfo{name=" << name << ", email=" << email
       << ", location=" << location << "}";
    return ss.str();
  }
};

// ---- Log block ----
struct LogBlock {
  std::string target;                  // "file", "syslog", "stdout", "stderr", "channel", "snomatic"
  std::string path;                    // File path (for file target)
  std::string channel;                 // Channel name (for channel target)
  std::string snomask;                 // Server notice mask (for snomatic target)
  std::string level = "info";          // "debug", "info", "notice", "warn", "error", "fatal"
  std::string subsystem = "*";        // "*" or specific subsystem name
  bool active = true;
  int max_file_size = 10485760;       // 10 MB default
  int max_backups = 5;                // Rotate backups
  bool timestamp = true;              // Include timestamp?
  bool color = false;                 // ANSI colors?

  bool is_valid() const {
    return !target.empty();
  }

  std::string to_string() const {
    std::stringstream ss;
    ss << "LogBlock{target=" << target << ", level=" << level
       << ", subsystem=" << subsystem << "}";
    return ss.str();
  }
};

// ---- MOTD ----
struct MotdInfo {
  std::string file_path;
  std::vector<std::string> lines;
  bool loaded = false;
  int64_t last_loaded = 0;
  std::string rules_file_path;
  std::vector<std::string> rules_lines;
  bool rules_loaded = false;
  std::string opermotd_path;
  std::vector<std::string> opermotd_lines;
  bool opermotd_loaded = false;

  void clear() {
    lines.clear();
    rules_lines.clear();
    opermotd_lines.clear();
    loaded = false;
    rules_loaded = false;
    opermotd_loaded = false;
  }

  std::string to_string() const {
    std::stringstream ss;
    ss << "MotdInfo{file=" << file_path << ", lines=" << lines.size()
       << ", loaded=" << (loaded ? "yes" : "no") << "}";
    return ss.str();
  }
};

// ---- Server configuration (master struct) ----
struct ServerConfiguration {
  // Server identity
  std::string server_name = DEFAULT_SERVER_NAME;
  std::string server_description = DEFAULT_SERVER_DESC;
  std::string network_name = DEFAULT_NETWORK_NAME;
  std::string server_sid;             // Server ID (auto-generated)
  std::string server_uid;             // Unique Server ID
  int numeric = 0;                    // Server numeric (TS6)

  // Network settings
  int default_max_clients = DEFAULT_MAX_CLIENTS;
  int default_ping_freq = DEFAULT_PING_FREQ;
  int default_max_channels = DEFAULT_MAX_CHANNELS;
  int default_max_nick_len = DEFAULT_MAX_NICK_LEN;
  int default_max_topic_len = DEFAULT_MAX_TOPIC_LEN;
  int default_max_kick_len = DEFAULT_MAX_KICK_LEN;
  int default_max_away_len = DEFAULT_MAX_AWAY_LEN;
  int default_sendq = DEFAULT_SENDQ;
  int default_recvq = DEFAULT_RECVQ;
  int max_connections = 1024;
  int max_local = 0;                  // 0 = same as max_connections
  int max_global = 0;
  int clients_per_ip = 5;
  int throttle_count = 4;
  int throttle_time = 60;

  // Listen blocks
  std::vector<ListenBlock> listen_blocks;

  // Operator blocks
  std::vector<OperBlock> oper_blocks;

  // Connect blocks (server linking)
  std::vector<ConnectBlock> connect_blocks;

  // Class blocks (connection class)
  std::vector<ClassBlock> class_blocks;

  // Exception blocks (kline/eline exempt)
  std::vector<ExceptionBlock> exception_blocks;

  // Deny blocks (bans)
  std::vector<DenyBlock> deny_blocks;

  // Allow blocks (whitelist)
  std::vector<AllowBlock> allow_blocks;

  // VHost blocks
  std::vector<VHostBlock> vhost_blocks;

  // Log blocks
  std::vector<LogBlock> log_blocks;

  // Admin info
  AdminInfo admin_info;

  // MOTD
  MotdInfo motd_info;

  // Security
  std::string ssl_cert_file;
  std::string ssl_key_file;
  std::string ssl_dh_params_file;
  std::string ssl_cipher_list;
  bool ssl_prefer_server_ciphers = true;
  int ssl_handshake_timeout = 30;
  bool require_ssl = false;
  bool require_auth = false;

  // Features
  bool allow_remote_oper = false;
  bool allow_insane_banmasks = false;
  bool disable_fake_channels = false;
  bool hide_servers = false;
  bool hide_ulined = false;
  bool hide_oper_server_notices = false;
  bool disable_remote_commands = false;
  bool disable_auth = false;
  bool allow_user_stats = true;
  bool allow_channel_links = false;
  bool allow_halfops = true;
  bool allow_admin_ops = true;
  bool allow_owner_ops = true;
  bool services_enabled = true;
  bool anope_compatibility = false;
  bool atheme_compatibility = true;
  bool inspircd_compatibility = true;
  bool unrealircd_compatibility = false;
  std::set<std::string> uline_servers;  // U-lined servers (services)
  std::string services_server = "services.local";

  // Misc
  std::string server_info;
  std::string custom_version;
  std::string cloak_key_1 = "aoAr1HnR6s";
  std::string cloak_key_2 = "q3QsE4vM2b";
  std::string cloak_key_3 = "x9ZtY8kL5p";
  std::string cloak_prefix = "progressive";
  std::string default_chanmodes = "+nt";
  std::string modes_on_connect = "+i";
  std::string modes_on_oper = "+oW";
  std::string snomask_on_oper = "+s";
  std::vector<std::string> include_history; // Track includes to prevent cycles
  std::string config_file_path;
  int64_t last_config_load = 0;
  bool config_valid = false;
  std::vector<std::string> config_errors;
  std::vector<std::string> config_warnings;

  // Default oper flags for /oper command when no block matches
  uint64_t default_oper_flags = OperPrivilegeSets::GLOBAL_OPER;
};

// ============================================================================
// Config Parser — state machine for parsing IRC config files
// ============================================================================

class ConfigParser {
public:
  explicit ConfigParser(ServerConfiguration& config) : config_(config) {}

  bool parse(const std::string& file_path, int depth = 0) {
    if (depth > static_cast<int>(CONFIG_INCLUDE_DEPTH_MAX)) {
      add_error("Maximum include depth (" +
                std::to_string(CONFIG_INCLUDE_DEPTH_MAX) + ") exceeded at: " + file_path);
      return false;
    }

    // Prevent include loops
    std::string canonical = file_path;
    auto it = std::find(config_.include_history.begin(),
                        config_.include_history.end(), canonical);
    if (it != config_.include_history.end()) {
      add_error("Include loop detected: " + file_path);
      return false;
    }
    config_.include_history.push_back(canonical);

    std::ifstream file(file_path);
    if (!file.is_open()) {
      add_error("Cannot open config file: " + file_path +
                " (" + std::string(strerror(errno)) + ")");
      config_.include_history.pop_back();
      return false;
    }

    config_.config_file_path = file_path;
    std::string current_block;
    std::vector<std::string> block_lines;
    int block_depth = 0;
    int line_number = 0;
    bool parsing_block = false;

    std::string line;
    while (std::getline(file, line)) {
      line_number++;
      // Strip comments and trim
      std::string stripped = trim(strip_comments(line));
      if (stripped.empty()) continue;
      if (stripped[0] == '#') continue;

      // Handle block open/close
      if (!parsing_block) {
        auto brace_open = stripped.find('{');
        auto eq_sign = stripped.find('=');
        auto brace_close = stripped.find('}');

        if (brace_open != std::string::npos) {
          // Start of a block definition
          current_block = trim(stripped.substr(0, brace_open));
          std::string block_params = trim(stripped.substr(brace_open + 1));
          // Remove trailing { if any
          if (!block_params.empty() && block_params.back() == '{') {
            block_params.pop_back();
          }
          block_lines.clear();
          block_depth = 1;
          parsing_block = true;

          // If the block opens and closes on same line
          auto close_brace = stripped.rfind('}');
          if (close_brace != std::string::npos && close_brace > brace_open) {
            std::string inner = stripped.substr(brace_open + 1,
                                                 close_brace - brace_open - 1);
            block_lines.push_back(trim(inner));
            parse_block(current_block, block_lines, file_path, line_number);
            parsing_block = false;
            block_lines.clear();
            current_block.clear();
            block_depth = 0;
          }
        } else if (eq_sign != std::string::npos) {
          // Key = Value line
          std::string key = trim(stripped.substr(0, eq_sign));
          std::string value = trim(stripped.substr(eq_sign + 1));
          // Strip quotes from value
          if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.size() - 2);
          }
          parse_key_value(key, value, file_path, line_number);
        } else if (stripped[0] == '}') {
          add_warning("Unexpected closing brace at line " +
                      std::to_string(line_number), file_path);
        } else {
          // Unrecognized
          add_warning("Unrecognized config line " + std::to_string(line_number) +
                      ": " + stripped, file_path);
        }
      } else {
        // Inside a block
        size_t pos = 0;
        while (pos < stripped.size()) {
          if (stripped[pos] == '{') {
            block_depth++;
          } else if (stripped[pos] == '}') {
            block_depth--;
            if (block_depth <= 0) {
              if (!block_lines.empty() && pos < stripped.size() - 1) {
                // Text before close brace
                std::string before_brace = trim(stripped.substr(0, pos));
                if (!before_brace.empty()) block_lines.push_back(before_brace);
              }
              // Parse the block
              parse_block(current_block, block_lines, file_path, line_number);
              parsing_block = false;
              block_lines.clear();
              current_block.clear();
              block_depth = 0;
              break;
            }
          }
          pos++;
        }
        if (parsing_block) {
          // Still inside block — accumulate line
          // Remove any trailing brace
          std::string clean = stripped;
          while (!clean.empty() && clean.back() == '}')
            clean.pop_back();
          clean = trim(clean);
          if (!clean.empty()) block_lines.push_back(clean);
        }
      }
    }

    // Check for unclosed block
    if (parsing_block) {
      add_error("Unclosed block '" + current_block + "' at end of file " + file_path);
      config_.include_history.pop_back();
      return false;
    }

    config_.include_history.pop_back();
    return true;
  }

private:
  ServerConfiguration& config_;
  int current_line_ = 0;

  void add_error(const std::string& msg, const std::string& file = "") {
    std::string entry = msg;
    if (!file.empty()) entry = file + ": " + entry;
    config_.config_errors.push_back(entry);
  }

  void add_warning(const std::string& msg, const std::string& file = "") {
    std::string entry = msg;
    if (!file.empty()) entry = file + ": " + entry;
    config_.config_warnings.push_back(entry);
  }

  void parse_key_value(const std::string& key, const std::string& value,
                        const std::string& file, int line) {
    std::string k = to_lower(key);

    // ---- Server Identity ----
    if (k == "server_name" || k == "name") {
      config_.server_name = value;
    } else if (k == "server_description" || k == "description" || k == "info") {
      config_.server_description = value;
    } else if (k == "network_name" || k == "network") {
      config_.network_name = value;
    } else if (k == "server_sid" || k == "sid") {
      config_.server_sid = value;
    } else if (k == "server_uid" || k == "uid") {
      config_.server_uid = value;
    } else if (k == "numeric") {
      config_.numeric = std::stoi(value);
    } else if (k == "server_info" || k == "custom_info") {
      config_.server_info = value;
    } else if (k == "custom_version") {
      config_.custom_version = value;

    // ---- Network Settings ----
    } else if (k == "max_clients" || k == "default_max_clients") {
      config_.default_max_clients = std::stoi(value);
    } else if (k == "max_connections") {
      config_.max_connections = std::stoi(value);
    } else if (k == "max_local") {
      config_.max_local = std::stoi(value);
    } else if (k == "max_global") {
      config_.max_global = std::stoi(value);
    } else if (k == "ping_frequency" || k == "ping_freq" || k == "default_ping_frequency") {
      config_.default_ping_freq = std::stoi(value);
    } else if (k == "max_channels" || k == "default_max_channels") {
      config_.default_max_channels = std::stoi(value);
    } else if (k == "max_nick_length" || k == "default_max_nick_length") {
      config_.default_max_nick_len = std::stoi(value);
    } else if (k == "max_topic_length" || k == "default_max_topic_length") {
      config_.default_max_topic_len = std::stoi(value);
    } else if (k == "max_kick_length" || k == "default_max_kick_length") {
      config_.default_max_kick_len = std::stoi(value);
    } else if (k == "max_away_length" || k == "default_max_away_length") {
      config_.default_max_away_len = std::stoi(value);
    } else if (k == "sendq" || k == "default_sendq") {
      config_.default_sendq = std::stoi(value);
    } else if (k == "recvq" || k == "default_recvq") {
      config_.default_recvq = std::stoi(value);
    } else if (k == "clients_per_ip") {
      config_.clients_per_ip = std::stoi(value);
    } else if (k == "throttle_count") {
      config_.throttle_count = std::stoi(value);
    } else if (k == "throttle_time") {
      config_.throttle_time = std::stoi(value);

    // ---- SSL/TLS ----
    } else if (k == "ssl_cert_file" || k == "ssl_cert") {
      config_.ssl_cert_file = value;
    } else if (k == "ssl_key_file" || k == "ssl_key") {
      config_.ssl_key_file = value;
    } else if (k == "ssl_dh_params_file" || k == "ssl_dh_params") {
      config_.ssl_dh_params_file = value;
    } else if (k == "ssl_cipher_list" || k == "ssl_ciphers") {
      config_.ssl_cipher_list = value;
    } else if (k == "ssl_prefer_server_ciphers") {
      config_.ssl_prefer_server_ciphers = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "ssl_handshake_timeout") {
      config_.ssl_handshake_timeout = std::stoi(value);
    } else if (k == "require_ssl") {
      config_.require_ssl = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "require_auth") {
      config_.require_auth = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");

    // ---- Features ----
    } else if (k == "allow_remote_oper") {
      config_.allow_remote_oper = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "allow_insane_banmasks") {
      config_.allow_insane_banmasks = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "disable_fake_channels") {
      config_.disable_fake_channels = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "hide_servers") {
      config_.hide_servers = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "hide_ulined") {
      config_.hide_ulined = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "hide_oper_server_notices") {
      config_.hide_oper_server_notices = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "disable_remote_commands") {
      config_.disable_remote_commands = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "disable_auth") {
      config_.disable_auth = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "allow_user_stats") {
      config_.allow_user_stats = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "allow_channel_links") {
      config_.allow_channel_links = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "allow_halfops") {
      config_.allow_halfops = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "allow_admin_ops") {
      config_.allow_admin_ops = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "allow_owner_ops") {
      config_.allow_owner_ops = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "services_enabled") {
      config_.services_enabled = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "anope_compatibility") {
      config_.anope_compatibility = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "atheme_compatibility") {
      config_.atheme_compatibility = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "inspircd_compatibility") {
      config_.inspircd_compatibility = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "unrealircd_compatibility") {
      config_.unrealircd_compatibility = (to_lower(value) == "yes" || value == "1" || to_lower(value) == "true");
    } else if (k == "services_server") {
      config_.services_server = value;
    } else if (k == "uline" || k == "uline_server") {
      config_.uline_servers.insert(value);

    // ---- Cloaking ----
    } else if (k == "cloak_key_1") {
      config_.cloak_key_1 = value;
    } else if (k == "cloak_key_2") {
      config_.cloak_key_2 = value;
    } else if (k == "cloak_key_3") {
      config_.cloak_key_3 = value;
    } else if (k == "cloak_prefix") {
      config_.cloak_prefix = value;

    // ---- Default modes / user modes ----
    } else if (k == "default_chanmodes") {
      config_.default_chanmodes = value;
    } else if (k == "modes_on_connect") {
      config_.modes_on_connect = value;
    } else if (k == "modes_on_oper") {
      config_.modes_on_oper = value;
    } else if (k == "snomask_on_oper") {
      config_.snomask_on_oper = value;

    // ---- Include directive ----
    } else if (k == "include") {
      handle_include(value, file);

    // ---- Unknown ----
    } else {
      add_warning("Unknown config key '" + key + "' at line " +
                  std::to_string(line), file);
    }
  }

  void parse_block(const std::string& block_type,
                   const std::vector<std::string>& lines,
                   const std::string& file, int line) {
    std::string bt = to_lower(trim(block_type));

    if (bt == "listen" || bt == "port") {
      parse_listen_block(lines, file, line);
    } else if (bt == "oper" || bt == "operator") {
      parse_oper_block(lines, file, line);
    } else if (bt == "connect" || bt == "link") {
      parse_connect_block(lines, file, line);
    } else if (bt == "class" || bt == "clientclass" || bt == "serverclass") {
      parse_class_block(lines, file, line);
    } else if (bt == "admin" || bt == "admininfo") {
      parse_admin_block(lines, file, line);
    } else if (bt == "motd") {
      parse_motd_block(lines, file, line);
    } else if (bt == "except" || bt == "exception" || bt == "eline") {
      parse_exception_block(lines, file, line);
    } else if (bt == "deny" || bt == "reject") {
      parse_deny_block(lines, file, line);
    } else if (bt == "allow" || bt == "accept") {
      parse_allow_block(lines, file, line);
    } else if (bt == "vhost" || bt == "virtualhost") {
      parse_vhost_block(lines, file, line);
    } else if (bt == "log" || bt == "logging") {
      parse_log_block(lines, file, line);
    } else if (bt == "include") {
      // Include as block with path directive inside
      for (const auto& l : lines) {
        auto eq = l.find('=');
        if (eq != std::string::npos) {
          std::string key = trim(l.substr(0, eq));
          std::string val = trim(l.substr(eq + 1));
          if (to_lower(key) == "path" || to_lower(key) == "file") {
            handle_include(val, file);
          }
        } else {
          // Raw path
          std::string val = trim(l);
          if (!val.empty()) handle_include(val, file);
        }
      }
    } else if (bt == "cloak" || bt == "cloaking") {
      parse_cloak_block(lines, file, line);
    } else if (bt == "settings" || bt == "options" || bt == "general") {
      // General settings block - key=value inside
      for (const auto& l : lines) {
        auto eq = l.find('=');
        if (eq != std::string::npos) {
          parse_key_value(trim(l.substr(0, eq)), trim(l.substr(eq + 1)), file, line);
        }
      }
    } else {
      add_warning("Unknown block type '" + block_type + "'", file);
    }
  }

  // ---- Listen block parser ----
  void parse_listen_block(const std::vector<std::string>& lines,
                           const std::string& file, int line) {
    ListenBlock lb;
    for (const auto& l : lines) {
      auto eq = l.find('=');
      if (eq == std::string::npos) {
        // Maybe raw port number
        std::string val = trim(l);
        try { lb.port = std::stoi(val); } catch (...) {}
        continue;
      }
      std::string k = to_lower(trim(l.substr(0, eq)));
      std::string v = trim(l.substr(eq + 1));
      if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
        v = v.substr(1, v.size() - 2);

      if (k == "address" || k == "ip" || k == "bind") {
        lb.address = v;
      } else if (k == "port") {
        try { lb.port = std::stoi(v); } catch (...) {}
      } else if (k == "ssl" || k == "tls") {
        lb.ssl = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "ssl_cert" || k == "ssl_cert_file" || k == "cert_file") {
        lb.ssl_cert = v;
      } else if (k == "ssl_key" || k == "ssl_key_file" || k == "key_file") {
        lb.ssl_key = v;
      } else if (k == "ssl_dh_params" || k == "dh_params" || k == "dh_file") {
        lb.ssl_dh_params = v;
      } else if (k == "ssl_cipher_list" || k == "ssl_ciphers" || k == "ciphers") {
        lb.ssl_cipher_list = v;
      } else if (k == "type") {
        lb.type = to_lower(v);
      } else if (k == "ipv4") {
        lb.ipv4 = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "ipv6") {
        lb.ipv6 = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "defer_accept") {
        try { lb.defer_accept = std::stoi(v); } catch (...) {}
      } else if (k == "tcp_backlog" || k == "backlog") {
        try { lb.tcp_backlog = std::stoi(v); } catch (...) {}
      } else if (k == "tcp_nodelay" || k == "nodelay") {
        lb.tcp_nodelay = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "tcp_keepalive" || k == "keepalive") {
        lb.tcp_keepalive = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "tcp_keepalive_idle" || k == "keepalive_idle") {
        try { lb.tcp_keepalive_idle = std::stoi(v); } catch (...) {}
      } else if (k == "tcp_keepalive_intvl" || k == "keepalive_intvl") {
        try { lb.tcp_keepalive_intvl = std::stoi(v); } catch (...) {}
      } else if (k == "tcp_keepalive_cnt" || k == "keepalive_cnt") {
        try { lb.tcp_keepalive_cnt = std::stoi(v); } catch (...) {}
      } else if (k == "so_reuseaddr" || k == "reuseaddr") {
        lb.so_reuseaddr = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "max_clients_per_ip" || k == "per_ip_max") {
        try { lb.max_clients_per_ip = std::stoi(v); } catch (...) {}
      } else if (k == "max_total_clients" || k == "max_clients") {
        try { lb.max_total_clients = std::stoi(v); } catch (...) {}
      } else if (k == "hidden") {
        lb.hidden = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "cloaking" || k == "cloak") {
        lb.cloaking = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "websocket" || k == "ws") {
        lb.websocket = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "websocket_origin" || k == "ws_origin") {
        lb.websocket_origin = v;
      } else if (k == "verified_only") {
        lb.verified_only = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      }
    }
    if (lb.is_valid()) {
      config_.listen_blocks.push_back(lb);
    } else {
      add_error("Invalid listen block (missing port?) at line " +
                std::to_string(line), file);
    }
  }

  // ---- Operator block parser ----
  void parse_oper_block(const std::vector<std::string>& lines,
                         const std::string& file, int line) {
    OperBlock ob;
    for (const auto& l : lines) {
      auto eq = l.find('=');
      if (eq == std::string::npos) {
        // Possibly bare operator name
        std::string val = trim(l);
        if (!val.empty() && ob.name.empty()) ob.name = val;
        continue;
      }
      std::string k = to_lower(trim(l.substr(0, eq)));
      std::string v = trim(l.substr(eq + 1));
      if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
        v = v.substr(1, v.size() - 2);

      if (k == "name" || k == "login" || k == "username") {
        ob.name = v;
      } else if (k == "password" || k == "pass") {
        ob.password = v;
      } else if (k == "password_hash" || k == "hash") {
        ob.password_hash = v;
      } else if (k == "hash_method" || k == "hashmethod" || k == "hash_type") {
        ob.hash_method = to_lower(v);
      } else if (k == "host" || k == "hostmask" || k == "from") {
        ob.hostmasks.push_back(v);
      } else if (k == "hostmasks") {
        auto hm = split(v, ',');
        for (auto& h : hm) ob.hostmasks.push_back(h);
      } else if (k == "class" || k == "class_name" || k == "oper_class") {
        ob.class_name = v;
      } else if (k == "flags" || k == "privileges" || k == "privs") {
        parse_oper_flags(ob, v, file, line);
      } else if (k == "auto" || k == "auto_login" || k == "autologin") {
        ob.auto_login = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "ssl_only" || k == "sslonly") {
        ob.ssl_only = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "certfp" || k == "ssl_certfp" || k == "fingerprint") {
        ob.certfp = v;
      } else if (k == "certfp_required") {
        ob.certfp_required = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "vhost") {
        ob.vhost = v;
      } else if (k == "modes" || k == "modes_on_oper" || k == "oper_modes") {
        ob.modes_on_oper = v;
      } else if (k == "snomask" || k == "snomask_on_oper") {
        ob.snomask = v;
      } else if (k == "max_logins" || k == "maxlogins") {
        try { ob.max_logins = std::stoi(v); } catch (...) {}
      } else if (k == "immune_to_klines" || k == "kline_immune") {
        ob.immune_to_klines = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "immune_to_gline" || k == "gline_immune") {
        ob.immune_to_gline = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "immune_to_restrictions") {
        ob.immune_to_restrictions = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "immune_to_shun") {
        ob.immune_to_shun = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "override" || k == "can_override") {
        ob.override_block = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "watch" || k == "oper_watch") {
        try { ob.oper_watch = std::stoi(v); } catch (...) {}
      }
    }
    if (ob.is_valid()) {
      config_.oper_blocks.push_back(ob);
    } else {
      add_error("Invalid oper block (need name, password, and hostmask) at line " +
                std::to_string(line), file);
    }
  }

  // ---- Connect block parser (server linking) ----
  void parse_connect_block(const std::vector<std::string>& lines,
                            const std::string& file, int line) {
    ConnectBlock cb;
    for (const auto& l : lines) {
      auto eq = l.find('=');
      if (eq == std::string::npos) {
        std::string val = trim(l);
        if (!val.empty() && cb.name.empty()) cb.name = val;
        continue;
      }
      std::string k = to_lower(trim(l.substr(0, eq)));
      std::string v = trim(l.substr(eq + 1));
      if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
        v = v.substr(1, v.size() - 2);

      if (k == "name" || k == "server") {
        cb.name = v;
      } else if (k == "host" || k == "address" || k == "ip") {
        cb.host = v;
      } else if (k == "port") {
        try { cb.port = std::stoi(v); } catch (...) {}
      } else if (k == "password" || k == "pass" || k == "link_password") {
        cb.password = v;
      } else if (k == "password_hash" || k == "pass_hash") {
        cb.password_hash = v;
      } else if (k == "send_password" || k == "send_pass") {
        cb.send_password = v;
      } else if (k == "accept_password" || k == "accept_pass" || k == "receive_password") {
        cb.accept_password = v;
      } else if (k == "ssl_cert_fingerprint" || k == "ssl_fingerprint" || k == "fingerprint") {
        cb.fingerprint = v;
      } else if (k == "bind" || k == "bind_address" || k == "source_ip") {
        cb.bind_address = v;
      } else if (k == "class" || k == "class_name") {
        cb.class_name = v;
      } else if (k == "ssl" || k == "tls") {
        cb.ssl = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "autoconnect" || k == "auto_connect" || k == "auto") {
        cb.autoconnect = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "autoconnect_delay" || k == "auto_connect_delay" || k == "reconnect_delay") {
        try { cb.auto_connect_delay = std::stoi(v); } catch (...) {}
      } else if (k == "max_retry" || k == "retry") {
        try { cb.max_retry = std::stoi(v); } catch (...) {}
      } else if (k == "hub") {
        cb.hub = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "leaf") {
        cb.leaf = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "topic_burst" || k == "topicburst") {
        cb.topic_burst = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "zip" || k == "zip_links" || k == "compression") {
        cb.zip_links = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "timeout") {
        try { cb.timeout = std::stoi(v); } catch (...) {}
      } else if (k == "max_sendq" || k == "sendq") {
        try { cb.max_sendq = std::stoi(v); } catch (...) {}
      } else if (k == "max_recvq" || k == "recvq") {
        try { cb.max_recvq = std::stoi(v); } catch (...) {}
      } else if (k == "flags") {
        cb.flags = v;
      } else if (k == "verified") {
        cb.verified = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      }
    }
    if (cb.is_valid()) {
      config_.connect_blocks.push_back(cb);
    } else {
      add_error("Invalid connect block (need name and host) at line " +
                std::to_string(line), file);
    }
  }

  // ---- Class block parser ----
  void parse_class_block(const std::vector<std::string>& lines,
                          const std::string& file, int line) {
    ClassBlock cblock;
    for (const auto& l : lines) {
      auto eq = l.find('=');
      if (eq == std::string::npos) {
        std::string val = trim(l);
        if (!val.empty() && cblock.name.empty()) cblock.name = val;
        continue;
      }
      std::string k = to_lower(trim(l.substr(0, eq)));
      std::string v = trim(l.substr(eq + 1));
      if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
        v = v.substr(1, v.size() - 2);

      if (k == "name" || k == "class_name") {
        cblock.name = v;
      } else if (k == "ping_freq" || k == "pingfreq" || k == "ping_frequency") {
        try { cblock.ping_freq = std::stoi(v); } catch (...) {}
      } else if (k == "ping_warning" || k == "pingwarning") {
        try { cblock.ping_warning = std::stoi(v); } catch (...) {}
      } else if (k == "conn_freq" || k == "connfreq" || k == "connect_frequency") {
        try { cblock.conn_freq = std::stoi(v); } catch (...) {}
      } else if (k == "max_clients" || k == "maxclients") {
        try { cblock.max_clients = std::stoi(v); } catch (...) {}
      } else if (k == "max_channels" || k == "maxchannels") {
        try { cblock.max_channels = std::stoi(v); } catch (...) {}
      } else if (k == "max_sendq" || k == "sendq" || k == "maxsendq") {
        try { cblock.max_sendq = std::stoi(v); } catch (...) {}
      } else if (k == "max_recvq" || k == "recvq" || k == "maxrecvq") {
        try { cblock.max_recvq = std::stoi(v); } catch (...) {}
      } else if (k == "max_away_length" || k == "max_away_len") {
        try { cblock.max_away_len = std::stoi(v); } catch (...) {}
      } else if (k == "max_kick_length" || k == "max_kick_len") {
        try { cblock.max_kick_len = std::stoi(v); } catch (...) {}
      } else if (k == "max_topic_length" || k == "max_topic_len") {
        try { cblock.max_topic_len = std::stoi(v); } catch (...) {}
      } else if (k == "max_nick_length" || k == "max_nick_len") {
        try { cblock.max_nick_len = std::stoi(v); } catch (...) {}
      } else if (k == "max_silence" || k == "maxsilence") {
        try { cblock.max_silence = std::stoi(v); } catch (...) {}
      } else if (k == "max_watch" || k == "maxwatch") {
        try { cblock.max_watch = std::stoi(v); } catch (...) {}
      } else if (k == "throttle_count") {
        try { cblock.throttle_count = std::stoi(v); } catch (...) {}
      } else if (k == "throttle_time") {
        try { cblock.throttle_time = std::stoi(v); } catch (...) {}
      } else if (k == "oper_host_attempts") {
        try { cblock.oper_host_attempts = std::stoi(v); } catch (...) {}
      } else if (k == "timeout" || k == "idle_timeout") {
        try { cblock.timeout = std::stoi(v); } catch (...) {}
      } else if (k == "registration_timeout" || k == "reg_timeout") {
        try { cblock.registration_timeout = std::stoi(v); } catch (...) {}
      } else if (k == "no_tilde" || k == "notilde") {
        cblock.no_tilde = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "ident_check" || k == "check_ident" || k == "ident") {
        cblock.ident_check = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "ident_timeout") {
        try { cblock.ident_timeout = std::stoi(v); } catch (...) {}
      } else if (k == "modes_on_connect" || k == "modes") {
        cblock.modes_on_connect = v;
      } else if (k == "restrict_to" || k == "restrict" || k == "ip_restrict") {
        cblock.restrict_to = v;
      } else if (k == "reserved_nick_prefix" || k == "nick_prefix" || k == "prefix") {
        cblock.reserved_nick_prefix = v;
      }
    }
    if (cblock.is_valid()) {
      // Check for duplicate class names
      for (const auto& existing : config_.class_blocks) {
        if (to_lower(existing.name) == to_lower(cblock.name)) {
          add_warning("Duplicate class block '" + cblock.name + "' — overwriting", file);
          break;
        }
      }
      config_.class_blocks.push_back(cblock);
    } else {
      add_error("Invalid class block (need name and valid ping_freq) at line " +
                std::to_string(line), file);
    }
  }

  // ---- Admin block parser ----
  void parse_admin_block(const std::vector<std::string>& lines,
                          const std::string& file, int line) {
    if (lines.empty()) return;
    // Admin block can be name/email/location or just raw text lines
    for (const auto& l : lines) {
      auto eq = l.find('=');
      if (eq != std::string::npos) {
        std::string k = to_lower(trim(l.substr(0, eq)));
        std::string v = trim(l.substr(eq + 1));
        if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
          v = v.substr(1, v.size() - 2);
        if (k == "name" || k == "admin_name") {
          config_.admin_info.name = v;
        } else if (k == "email" || k == "admin_email") {
          config_.admin_info.email = v;
        } else if (k == "location" || k == "admin_location" || k == "loc") {
          config_.admin_info.location = v;
        } else if (k == "description" || k == "desc") {
          config_.admin_info.description = v;
        } else {
          config_.admin_info.extra_lines.push_back(v);
        }
      } else {
        // Raw line — treated as extra info for /admin reply
        std::string v = trim(l);
        if (!v.empty()) config_.admin_info.extra_lines.push_back(v);
      }
    }
  }

  // ---- MOTD block parser ----
  void parse_motd_block(const std::vector<std::string>& lines,
                         const std::string& file, int line) {
    for (const auto& l : lines) {
      auto eq = l.find('=');
      if (eq == std::string::npos) continue;
      std::string k = to_lower(trim(l.substr(0, eq)));
      std::string v = trim(l.substr(eq + 1));
      if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
        v = v.substr(1, v.size() - 2);

      if (k == "file" || k == "motd_file" || k == "path") {
        config_.motd_info.file_path = v;
      } else if (k == "rules" || k == "rules_file") {
        config_.motd_info.rules_file_path = v;
      } else if (k == "opermotd" || k == "oper_motd_file" || k == "oper_file") {
        config_.motd_info.opermotd_path = v;
      }
    }
  }

  // ---- Exception block parser (eline) ----
  void parse_exception_block(const std::vector<std::string>& lines,
                              const std::string& file, int line) {
    ExceptionBlock eb;
    bool has_mask = false;
    for (const auto& l : lines) {
      auto eq = l.find('=');
      if (eq == std::string::npos) {
        // Raw mask
        std::string val = trim(l);
        if (!val.empty() && !has_mask) {
          eb.mask = val;
          has_mask = true;
        }
        continue;
      }
      std::string k = to_lower(trim(l.substr(0, eq)));
      std::string v = trim(l.substr(eq + 1));
      if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
        v = v.substr(1, v.size() - 2);

      if (k == "mask" || k == "hostmask" || k == "ip") {
        eb.mask = v;
        has_mask = true;
      } else if (k == "reason" || k == "comment") {
        eb.reason = v;
      } else if (k == "set_by" || k == "by" || k == "who") {
        eb.set_by = v;
      } else if (k == "expires" || k == "expires_at" || k == "expire") {
        try { eb.expires_at = std::stoll(v); } catch (...) {
          // Could be a human-readable duration
          eb.expires_at = parse_duration(v);
        }
      } else if (k == "types" || k == "type") {
        eb.types = v;
      } else if (k == "active") {
        eb.active = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      }
    }
    if (has_mask && !eb.mask.empty()) {
      eb.set_at = now_sec();
      config_.exception_blocks.push_back(eb);
    } else {
      add_warning("Exception block missing mask at line " +
                  std::to_string(line), file);
    }
  }

  // ---- Deny block parser ----
  void parse_deny_block(const std::vector<std::string>& lines,
                         const std::string& file, int line) {
    DenyBlock db;
    bool has_mask = false;
    for (const auto& l : lines) {
      auto eq = l.find('=');
      if (eq == std::string::npos) {
        std::string val = trim(l);
        if (!val.empty() && !has_mask) {
          db.mask = val;
          has_mask = true;
        }
        continue;
      }
      std::string k = to_lower(trim(l.substr(0, eq)));
      std::string v = trim(l.substr(eq + 1));
      if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
        v = v.substr(1, v.size() - 2);

      if (k == "mask" || k == "ip" || k == "hostmask") {
        db.mask = v;
        has_mask = true;
      } else if (k == "type" || k == "deny_type") {
        db.type = to_lower(v);
      } else if (k == "reason" || k == "message") {
        db.reason = v;
      } else if (k == "redirect_ip" || k == "redirect") {
        db.redirect_ip = v;
      } else if (k == "redirect_port" || k == "redirect_to_port") {
        try { db.redirect_port = std::stoi(v); } catch (...) {}
      } else if (k == "active") {
        db.active = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "expires" || k == "expires_at") {
        try { db.expires_at = std::stoll(v); } catch (...) {
          db.expires_at = parse_duration(v);
        }
      } else if (k == "set_by" || k == "by") {
        db.set_by = v;
      }
    }
    if (has_mask && !db.mask.empty()) {
      db.set_at = now_sec();
      config_.deny_blocks.push_back(db);
    } else {
      add_warning("Deny block missing mask at line " +
                  std::to_string(line), file);
    }
  }

  // ---- Allow block parser ----
  void parse_allow_block(const std::vector<std::string>& lines,
                          const std::string& file, int line) {
    AllowBlock ab;
    bool has_mask = false;
    for (const auto& l : lines) {
      auto eq = l.find('=');
      if (eq == std::string::npos) {
        std::string val = trim(l);
        if (!val.empty() && !has_mask) {
          ab.mask = val;
          has_mask = true;
        }
        continue;
      }
      std::string k = to_lower(trim(l.substr(0, eq)));
      std::string v = trim(l.substr(eq + 1));
      if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
        v = v.substr(1, v.size() - 2);

      if (k == "mask" || k == "ip" || k == "hostmask") {
        ab.mask = v;
        has_mask = true;
      } else if (k == "max_clients_per_ip" || k == "max_per_ip" || k == "clients_per_ip") {
        try { ab.max_clients_per_ip = std::stoi(v); } catch (...) {}
      } else if (k == "class" || k == "class_name") {
        ab.class_name = v;
      } else if (k == "password" || k == "pass") {
        ab.password = v;
        ab.password_required = !v.empty();
      } else if (k == "active") {
        ab.active = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "redirect_ip" || k == "redirect") {
        ab.redirect_ip = v;
      } else if (k == "redirect_port") {
        try { ab.redirect_port = std::stoi(v); } catch (...) {}
      } else if (k == "can_bypass_clones" || k == "bypass_clones") {
        ab.can_bypass_clones = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "can_bypass_throttle" || k == "bypass_throttle") {
        ab.can_bypass_throttle = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      }
    }
    if (has_mask && !ab.mask.empty()) {
      config_.allow_blocks.push_back(ab);
    } else {
      add_warning("Allow block missing mask at line " +
                  std::to_string(line), file);
    }
  }

  // ---- VHost block parser ----
  void parse_vhost_block(const std::vector<std::string>& lines,
                          const std::string& file, int line) {
    VHostBlock vb;
    for (const auto& l : lines) {
      auto eq = l.find('=');
      if (eq == std::string::npos) continue;
      std::string k = to_lower(trim(l.substr(0, eq)));
      std::string v = trim(l.substr(eq + 1));
      if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
        v = v.substr(1, v.size() - 2);

      if (k == "login" || k == "account" || k == "name") {
        vb.login = v;
      } else if (k == "password" || k == "pass") {
        vb.password = v;
      } else if (k == "vhost" || k == "host" || k == "virtual_host") {
        vb.vhost = v;
      } else if (k == "set_by" || k == "by") {
        vb.set_by = v;
      } else if (k == "expires" || k == "expires_at") {
        try { vb.expires_at = std::stoll(v); } catch (...) {
          vb.expires_at = parse_duration(v);
        }
      } else if (k == "active") {
        vb.active = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      }
    }
    if (vb.is_valid()) {
      vb.set_at = now_sec();
      config_.vhost_blocks.push_back(vb);
    }
  }

  // ---- Log block parser ----
  void parse_log_block(const std::vector<std::string>& lines,
                        const std::string& file, int line) {
    LogBlock logb;
    for (const auto& l : lines) {
      auto eq = l.find('=');
      if (eq == std::string::npos) {
        std::string val = trim(l);
        if (!val.empty() && logb.target.empty()) logb.target = val;
        continue;
      }
      std::string k = to_lower(trim(l.substr(0, eq)));
      std::string v = trim(l.substr(eq + 1));
      if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
        v = v.substr(1, v.size() - 2);

      if (k == "target" || k == "destination" || k == "dest") {
        logb.target = to_lower(v);
      } else if (k == "path" || k == "file" || k == "filename") {
        logb.path = v;
      } else if (k == "channel") {
        logb.channel = v;
      } else if (k == "snomask" || k == "snomatic_mask") {
        logb.snomask = v;
      } else if (k == "level" || k == "log_level" || k == "severity") {
        logb.level = to_lower(v);
      } else if (k == "subsystem" || k == "module" || k == "type") {
        logb.subsystem = to_lower(v);
      } else if (k == "active") {
        logb.active = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "max_file_size" || k == "maxsize" || k == "max_size") {
        try { logb.max_file_size = std::stoi(v); } catch (...) {}
      } else if (k == "max_backups" || k == "backups" || k == "rotate") {
        try { logb.max_backups = std::stoi(v); } catch (...) {}
      } else if (k == "timestamp" || k == "timestamps") {
        logb.timestamp = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      } else if (k == "color" || k == "ansi") {
        logb.color = (to_lower(v) == "yes" || v == "1" || to_lower(v) == "true");
      }
    }
    if (logb.is_valid()) {
      config_.log_blocks.push_back(logb);
    } else {
      add_warning("Invalid log block (need target) at line " +
                  std::to_string(line), file);
    }
  }

  // ---- Cloak block parser ----
  void parse_cloak_block(const std::vector<std::string>& lines,
                          const std::string& file, int line) {
    for (const auto& l : lines) {
      auto eq = l.find('=');
      if (eq == std::string::npos) continue;
      std::string k = to_lower(trim(l.substr(0, eq)));
      std::string v = trim(l.substr(eq + 1));
      if (v.size() >= 2 && v.front() == '"' && v.back() == '"')
        v = v.substr(1, v.size() - 2);

      if (k == "key1" || k == "cloak_key_1" || k == "key_1") {
        config_.cloak_key_1 = v;
      } else if (k == "key2" || k == "cloak_key_2" || k == "key_2") {
        config_.cloak_key_2 = v;
      } else if (k == "key3" || k == "cloak_key_3" || k == "key_3") {
        config_.cloak_key_3 = v;
      } else if (k == "prefix" || k == "cloak_prefix") {
        config_.cloak_prefix = v;
      }
    }
  }

  // ---- Include directive handler ----
  void handle_include(const std::string& path, const std::string& relative_to) {
    std::string resolved = resolve_include_path(path, relative_to);
    if (!file_exists(resolved)) {
      add_warning("Included file not found: " + resolved);
      return;
    }
    // Recursive parse
    ConfigParser sub_parser(config_);
    sub_parser.parse(resolved, 1 + std::count_if(
        config_.include_history.begin(), config_.include_history.end(),
        [](const std::string&) { return true; }));
  }

  // ---- Oper flags parser ----
  void parse_oper_flags(OperBlock& ob, const std::string& flags_str,
                         const std::string& file, int line) {
    std::string f = to_lower(trim(flags_str));

    // Predefined privilege sets
    if (f == "netadmin" || f == "all" || f == "*") {
      ob.flags = OperPrivilegeSets::NETADMIN;
      return;
    }
    if (f == "global" || f == "global_oper" || f == "ircop") {
      ob.flags = OperPrivilegeSets::GLOBAL_OPER;
      return;
    }
    if (f == "local" || f == "local_oper" || f == "locop") {
      ob.flags = OperPrivilegeSets::LOCAL_OPER;
      return;
    }
    if (f == "services" || f == "service") {
      ob.flags = OperPrivilegeSets::SERVICES;
      return;
    }

    // Try parsing as numeric value
    if (!f.empty() && (f[0] == '0' && f.size() > 1 && (f[1] == 'x' || f[1] == 'X'))) {
      // Hex
      try {
        ob.flags = std::stoull(f.substr(2), nullptr, 16);
        return;
      } catch (...) {}
    }

    // Parse comma/space separated flag names
    auto tokens = split(f, ',');
    for (const auto& token : tokens) {
      std::string tf = trim(token);
      if (tf.empty()) continue;

      // Map flag names to OperFlag values
      if (tf == "can_restart" || tf == "restart" || tf == "die_restart")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_RESTART);
      else if (tf == "can_die" || tf == "die")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_DIE);
      else if (tf == "can_rehash" || tf == "rehash")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_REHASH);
      else if (tf == "can_globops" || tf == "globops")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_GLOBOPS);
      else if (tf == "can_wallops" || tf == "wallops")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_WALLOPS);
      else if (tf == "can_kill" || tf == "kill")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_KILL);
      else if (tf == "can_kline" || tf == "kline")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_KLINE);
      else if (tf == "can_unkline" || tf == "unkline")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_UNKLINE);
      else if (tf == "can_gline" || tf == "gline")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_GLINE);
      else if (tf == "can_ungline" || tf == "ungline")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_UNGLINE);
      else if (tf == "can_zline" || tf == "zline")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_ZLINE);
      else if (tf == "can_unzline" || tf == "unzline")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_UNZLINE);
      else if (tf == "can_gzline" || tf == "gzline")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_GZLINE);
      else if (tf == "can_ungzline" || tf == "ungzline")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_UNGZLINE);
      else if (tf == "can_local_kill" || tf == "local_kill" || tf == "localkill")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_LOCAL_KILL);
      else if (tf == "can_kline" || tf == "remote_kill" || tf == "remotekill")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_REMOTE_KILL);
      else if (tf == "can_jupe" || tf == "jupe")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_JUPE);
      else if (tf == "can_local_jupe" || tf == "local_jupe" || tf == "localjupe")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_LOCAL_JUPE);
      else if (tf == "can_squit" || tf == "squit")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SQUIT);
      else if (tf == "can_local_squit" || tf == "local_squit" || tf == "localsquit")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_LOCAL_SQUIT);
      else if (tf == "can_connect" || tf == "connect")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_CONNECT);
      else if (tf == "can_local_connect" || tf == "local_connect")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_LOCAL_CONNECT);
      else if (tf == "can_dccdeny" || tf == "dccdeny")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_DCCDENY);
      else if (tf == "can_undccdeny" || tf == "undccdeny")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_UNDCCDENY);
      else if (tf == "can_admin" || tf == "admin")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_ADMIN);
      else if (tf == "can_override" || tf == "override")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_OVERRIDE);
      else if (tf == "can_opermotd" || tf == "opermotd")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_OPERMOTD);
      else if (tf == "can_operwall" || tf == "operwall")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_OPERWALL);
      else if (tf == "can_globalroute" || tf == "globalroute" || tf == "global_route")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_GLOBALROUTE);
      else if (tf == "can_set" || tf == "set")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SET);
      else if (tf == "can_sajoin" || tf == "sajoin")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SAJOIN);
      else if (tf == "can_sapart" || tf == "sapart")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SAPART);
      else if (tf == "can_samode" || tf == "samode")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SAMODE);
      else if (tf == "can_sakick" || tf == "sakick")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SAKICK);
      else if (tf == "can_satopic" || tf == "satopic")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SATOPIC);
      else if (tf == "can_swhois" || tf == "swhois")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SWHOIS);
      else if (tf == "can_chghost" || tf == "chghost")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_CHGHOST);
      else if (tf == "can_chgident" || tf == "chgident")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_CHGIDENT);
      else if (tf == "can_chgname" || tf == "chgname")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_CHGNAME);
      else if (tf == "can_hideoper" || tf == "hideoper" || tf == "hide_oper")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_HIDEOPER);
      else if (tf == "can_see_hidden" || tf == "see_hidden" || tf == "seehidden")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SEE_HIDDEN);
      else if (tf == "can_see_chans" || tf == "see_chans" || tf == "seechans")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SEE_CHANS);
      else if (tf == "can_see_ops" || tf == "see_ops" || tf == "seeops")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SEE_OPS);
      else if (tf == "can_see_invis" || tf == "see_invis" || tf == "seeinvis")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SEE_INVIS);
      else if (tf == "can_see_secret_chans" || tf == "see_secret" || tf == "seesecret")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SEE_SECRET_CHANS);
      else if (tf == "can_see_all_chans" || tf == "see_all" || tf == "seeall")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SEE_ALL_CHANS);
      else if (tf == "can_join_opersonly" || tf == "join_opersonly")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_JOIN_OPERSONLY);
      else if (tf == "can_flood_exempt" || tf == "flood_exempt" || tf == "floodexempt")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_FLOOD_EXEMPT);
      else if (tf == "can_no_ctcp" || tf == "no_ctcp" || tf == "noctcp")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_NO_CTCP);
      else if (tf == "can_unlimited_sendq" || tf == "unlimited_sendq" || tf == "unlimitedsendq")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_UNLIMITED_SENDQ);
      else if (tf == "can_always_op" || tf == "always_op" || tf == "alwaysop")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_ALWAYS_OP);
      else if (tf == "can_deop_protect" || tf == "deop_protect" || tf == "deopprotect")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_DEOP_PROTECT);
      else if (tf == "can_svsjoin" || tf == "svsjoin")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SVSJOIN);
      else if (tf == "can_svsnick" || tf == "svsnick")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SVSNICK);
      else if (tf == "can_svsnoop" || tf == "svsnoop")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SVSNOOP);
      else if (tf == "can_svskill" || tf == "svskill")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SVSKILL);
      else if (tf == "can_svsmode" || tf == "svsmode")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SVSMODE);
      else if (tf == "can_svssno" || tf == "svssno")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SVSSNO);
      else if (tf == "can_svssquit" || tf == "svssquit")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SVSSQUIT);
      else if (tf == "can_svsadmin" || tf == "svsadmin")
        ob.flags |= static_cast<uint64_t>(OperFlag::CAN_SVSADMIN);
      else {
        add_warning("Unknown oper flag '" + tf + "'", file);
      }
    }
  }

  // Parse human-readable duration strings: "1d2h30m", "3600", etc.
  int64_t parse_duration(const std::string& s) {
    if (s.empty()) return 0;
    // Try direct numeric parse first
    try {
      size_t pos;
      int64_t val = std::stoll(s, &pos);
      if (pos == s.size()) return now_sec() + val;
    } catch (...) {}

    int64_t total = 0;
    std::string num_str;
    for (char c : s) {
      if (c >= '0' && c <= '9') {
        num_str += c;
      } else {
        int64_t num = num_str.empty() ? 0 : std::stoll(num_str);
        switch (c | 0x20) {  // lowercase
          case 'y': total += num * 86400 * 365; break;
          case 'w': total += num * 86400 * 7; break;
          case 'd': total += num * 86400; break;
          case 'h': total += num * 3600; break;
          case 'm': total += num * 60; break;
          case 's': total += num; break;
        }
        num_str.clear();
      }
    }
    // Remaining number
    if (!num_str.empty()) total += std::stoll(num_str);
    return now_sec() + total;
  }
};

// ============================================================================
// Configuration manager — loading, validating, saving, reloading
// ============================================================================

class ConfigurationManager {
public:
  ConfigurationManager() {
    // Initialize with defaults
    config_.server_sid = random_string(3);
    config_.server_uid = random_string(10);
  }

  ~ConfigurationManager() {
    cleanup_signal_handler();
  }

  // ---- Load configuration from file ----
  bool load(const std::string& path = CONFIG_DEFAULT_PATH) {
    std::lock_guard lock(mutex_);

    // Reset errors/warnings
    config_.config_errors.clear();
    config_.config_warnings.clear();
    config_.include_history.clear();

    ConfigParser parser(config_);
    bool result = parser.parse(path);

    if (result) {
      // Apply defaults for any empty lists
      apply_defaults();
      // Validate the config
      validate();
      // Load external files (MOTD, rules, etc.)
      load_external_files();
      config_.last_config_load = now_sec();
      config_.config_valid = config_.config_errors.empty();
    } else {
      config_.config_valid = false;
    }

    return config_.config_valid;
  }

  // ---- Reload on SIGHUP ----
  bool reload() {
    if (config_.config_file_path.empty()) {
      return false;
    }
    // Save a copy of current config for rollback
    ServerConfiguration old_config = config_;
    bool result = load(config_.config_file_path);
    if (!result) {
      // Rollback
      config_ = old_config;
      return false;
    }
    return true;
  }

  // ---- Signal handler setup ----
  void setup_signal_handler() {
    struct sigaction sa{};
    sa.sa_handler = &ConfigurationManager::signal_handler_dispatcher;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaction(CONFIG_RELOAD_SIGNAL, &sa, nullptr);

    // Store this instance for the static handler
    instance_ = this;
  }

  // ---- Validate configuration ----
  bool validate() {
    bool valid = true;

    // Check server name
    if (config_.server_name.empty()) {
      config_.config_errors.push_back("server_name must be set");
      valid = false;
    }

    // Check at least one listen block (or we create a default)
    if (config_.listen_blocks.empty()) {
      config_.config_warnings.push_back(
          "No listen blocks defined; using default port 6667");
      ListenBlock default_listen;
      default_listen.port = 6667;
      config_.listen_blocks.push_back(default_listen);
    }

    // Validate listen blocks
    for (size_t i = 0; i < config_.listen_blocks.size(); ++i) {
      const auto& lb = config_.listen_blocks[i];
      if (!lb.is_valid()) {
        config_.config_errors.push_back(
            "Invalid listen block #" + std::to_string(i) +
            ": port must be 1-65535");
        valid = false;
      }
      if (lb.ssl && (lb.ssl_cert.empty() || lb.ssl_key.empty())) {
        config_.config_errors.push_back(
            "Listen block #" + std::to_string(i) +
            " has SSL enabled but missing cert/key");
        valid = false;
      }
      // Check for duplicate port+address combinations
      for (size_t j = i + 1; j < config_.listen_blocks.size(); ++j) {
        const auto& lb2 = config_.listen_blocks[j];
        if (lb.address == lb2.address && lb.port == lb2.port) {
          config_.config_warnings.push_back(
              "Duplicate listen: " + lb.address + ":" + std::to_string(lb.port));
        }
      }
    }

    // Validate oper blocks
    for (size_t i = 0; i < config_.oper_blocks.size(); ++i) {
      const auto& ob = config_.oper_blocks[i];
      if (!ob.is_valid()) {
        config_.config_errors.push_back(
            "Invalid oper block '" + ob.name +
            "': must have name, password, and hostmask");
        valid = false;
      }
      if (ob.password.empty() && ob.password_hash.empty()) {
        config_.config_errors.push_back(
            "Oper block '" + ob.name +
            "' has no password or password_hash");
        valid = false;
      }
      if (ob.hostmasks.empty()) {
        config_.config_errors.push_back(
            "Oper block '" + ob.name +
            "' has no hostmasks");
        valid = false;
      }
    }

    // Validate connect blocks
    for (size_t i = 0; i < config_.connect_blocks.size(); ++i) {
      const auto& cb = config_.connect_blocks[i];
      if (!cb.is_valid()) {
        config_.config_errors.push_back(
            "Invalid connect block '" + cb.name +
            "': must have name and host");
        valid = false;
      }
      // Check for duplicate connect names
      for (size_t j = i + 1; j < config_.connect_blocks.size(); ++j) {
        if (to_lower(cb.name) == to_lower(config_.connect_blocks[j].name)) {
          config_.config_warnings.push_back(
              "Duplicate connect block name: " + cb.name);
        }
      }
    }

    // Validate class blocks
    if (config_.class_blocks.empty()) {
      config_.config_warnings.push_back(
          "No class blocks defined; creating default 'clients' class");
      ClassBlock default_clients;
      default_clients.name = "clients";
      default_clients.ping_freq = DEFAULT_PING_FREQ;
      default_clients.max_clients = DEFAULT_MAX_CLIENTS;
      default_clients.max_channels = DEFAULT_MAX_CHANNELS;
      default_clients.max_sendq = DEFAULT_SENDQ;
      config_.class_blocks.push_back(default_clients);

      ClassBlock default_servers;
      default_servers.name = "servers";
      default_servers.ping_freq = 60;
      default_servers.max_clients = 0;  // unlimited
      default_servers.max_sendq = DEFAULT_SENDQ * 4;
      config_.class_blocks.push_back(default_servers);

      ClassBlock default_opers;
      default_opers.name = "opers";
      default_opers.ping_freq = 60;
      default_opers.max_clients = 0;
      default_opers.max_channels = 100;
      default_opers.max_sendq = DEFAULT_SENDQ * 2;
      config_.class_blocks.push_back(default_opers);
    }

    for (const auto& cblock : config_.class_blocks) {
      if (cblock.name.empty() || cblock.ping_freq <= 0) {
        config_.config_errors.push_back(
            "Invalid class block '" + cblock.name +
            "': must have name and valid ping_freq > 0");
        valid = false;
      }
    }

    // SSL/TLS validation
    if (config_.require_ssl && config_.ssl_cert_file.empty()) {
      config_.config_errors.push_back(
          "require_ssl is enabled but no ssl_cert_file is configured");
      valid = false;
    }

    // Validate ranges
    if (config_.default_max_nick_len < 1 || config_.default_max_nick_len > 50) {
      config_.config_errors.push_back(
          "max_nick_length must be between 1 and 50");
      valid = false;
    }

    if (config_.default_ping_freq < 30 || config_.default_ping_freq > 600) {
      config_.config_warnings.push_back(
          "ping_frequency outside recommended range (30-600)");
    }

    return valid;
  }

  // ---- Accessors ----
  const ServerConfiguration& config() const { return config_; }
  ServerConfiguration& mutable_config() { return config_; }

  // ---- Find operators by hostmask ----
  const OperBlock* find_oper_by_name(const std::string& name) const {
    for (const auto& ob : config_.oper_blocks) {
      if (to_lower(ob.name) == to_lower(name)) return &ob;
    }
    return nullptr;
  }

  const OperBlock* find_oper_by_host(const std::string& user_host_mask) const {
    for (const auto& ob : config_.oper_blocks) {
      if (ob.match_host(user_host_mask)) return &ob;
    }
    return nullptr;
  }

  std::vector<const OperBlock*> find_opers_for_user(
      const std::string& nick, const std::string& ident,
      const std::string& host, const std::string& ip) const {
    std::vector<const OperBlock*> matches;
    std::string full_mask = nick + "!" + ident + "@" + host;
    std::string ip_mask = nick + "!" + ident + "@" + ip;
    for (const auto& ob : config_.oper_blocks) {
      if (ob.match_host(full_mask) || ob.match_host(ip_mask)) {
        matches.push_back(&ob);
      }
    }
    return matches;
  }

  // ---- Find class by name ----
  const ClassBlock* find_class(const std::string& name) const {
    for (const auto& cb : config_.class_blocks) {
      if (to_lower(cb.name) == to_lower(name)) return &cb;
    }
    return nullptr;
  }

  const ClassBlock* find_default_class() const {
    auto* cb = find_class("clients");
    if (!cb && !config_.class_blocks.empty()) {
      return &config_.class_blocks[0];
    }
    return cb;
  }

  // ---- Find connect block by name ----
  const ConnectBlock* find_connect(const std::string& name) const {
    for (const auto& cb : config_.connect_blocks) {
      if (to_lower(cb.name) == to_lower(name)) return &cb;
    }
    return nullptr;
  }

  // ---- Allow/Deny checks ----
  bool is_allowed(const std::string& ip_or_mask) const {
    // Check allow blocks first
    for (const auto& ab : config_.allow_blocks) {
      if (ab.matches(ip_or_mask)) return true;
    }
    return false;
  }

  bool is_denied(const std::string& ip_or_mask) const {
    for (const auto& db : config_.deny_blocks) {
      if (db.matches(ip_or_mask)) return true;
    }
    return false;
  }

  const DenyBlock* find_deny(const std::string& ip_or_mask) const {
    for (const auto& db : config_.deny_blocks) {
      if (db.matches(ip_or_mask)) return &db;
    }
    return nullptr;
  }

  // ---- Exception checks ----
  bool is_excepted(const std::string& user_mask, const std::string& types = "k") const {
    for (const auto& eb : config_.exception_blocks) {
      if (!eb.is_expired() && eb.active && eb.matches(user_mask)) {
        // Check if exception covers the requested types
        if (eb.types.find('*') != std::string::npos) return true;
        for (char c : types) {
          if (eb.types.find(c) != std::string::npos) return true;
        }
      }
    }
    return false;
  }

  // ---- VHost lookup ----
  const VHostBlock* find_vhost(const std::string& login) const {
    for (const auto& vb : config_.vhost_blocks) {
      if (!vb.is_expired() && vb.active &&
          to_lower(vb.login) == to_lower(login)) {
        return &vb;
      }
    }
    return nullptr;
  }

  // ---- MOTD access ----
  const MotdInfo& motd() const { return config_.motd_info; }

  // ---- Admin info access ----
  const AdminInfo& admin_info() const { return config_.admin_info; }

  // ---- Statistics ----
  int listen_count() const { return static_cast<int>(config_.listen_blocks.size()); }
  int oper_count() const { return static_cast<int>(config_.oper_blocks.size()); }
  int connect_count() const { return static_cast<int>(config_.connect_blocks.size()); }
  int class_count() const { return static_cast<int>(config_.class_blocks.size()); }
  int exception_count() const { return static_cast<int>(config_.exception_blocks.size()); }
  int deny_count() const { return static_cast<int>(config_.deny_blocks.size()); }
  int allow_count() const { return static_cast<int>(config_.allow_blocks.size()); }
  int vhost_count() const { return static_cast<int>(config_.vhost_blocks.size()); }
  int log_count() const { return static_cast<int>(config_.log_blocks.size()); }

  const std::vector<std::string>& errors() const { return config_.config_errors; }
  const std::vector<std::string>& warnings() const { return config_.config_warnings; }
  bool is_valid() const { return config_.config_valid; }
  std::string config_file() const { return config_.config_file_path; }

  // ---- Add/Remove dynamic blocks at runtime (for /stats, /rehash, etc.) ----
  bool add_oper(const OperBlock& ob) {
    std::lock_guard lock(mutex_);
    config_.oper_blocks.push_back(ob);
    return true;
  }

  bool remove_oper(const std::string& name) {
    std::lock_guard lock(mutex_);
    auto& ops = config_.oper_blocks;
    auto it = std::find_if(ops.begin(), ops.end(), [&](const OperBlock& ob) {
      return to_lower(ob.name) == to_lower(name);
    });
    if (it != ops.end()) {
      ops.erase(it);
      return true;
    }
    return false;
  }

  bool add_deny(const DenyBlock& db) {
    std::lock_guard lock(mutex_);
    config_.deny_blocks.push_back(db);
    return true;
  }

  bool remove_deny(const std::string& mask) {
    std::lock_guard lock(mutex_);
    auto& denies = config_.deny_blocks;
    auto it = std::find_if(denies.begin(), denies.end(), [&](const DenyBlock& db) {
      return db.mask == mask;
    });
    if (it != denies.end()) {
      denies.erase(it);
      return true;
    }
    return false;
  }

  bool add_exception(const ExceptionBlock& eb) {
    std::lock_guard lock(mutex_);
    config_.exception_blocks.push_back(eb);
    return true;
  }

  bool remove_exception(const std::string& mask) {
    std::lock_guard lock(mutex_);
    auto& excs = config_.exception_blocks;
    auto it = std::find_if(excs.begin(), excs.end(), [&](const ExceptionBlock& eb) {
      return eb.mask == mask;
    });
    if (it != excs.end()) {
      excs.erase(it);
      return true;
    }
    return false;
  }

  bool add_vhost(const VHostBlock& vb) {
    std::lock_guard lock(mutex_);
    config_.vhost_blocks.push_back(vb);
    return true;
  }

  bool remove_vhost(const std::string& login) {
    std::lock_guard lock(mutex_);
    auto& vhs = config_.vhost_blocks;
    auto it = std::find_if(vhs.begin(), vhs.end(), [&](const VHostBlock& vb) {
      return to_lower(vb.login) == to_lower(login);
    });
    if (it != vhs.end()) {
      vhs.erase(it);
      return true;
    }
    return false;
  }

  // ---- Save current config back to file ----
  bool save_to_file(const std::string& path = "") {
    std::string file_path = path.empty() ? config_.config_file_path : path;
    if (file_path.empty()) return false;

    std::lock_guard lock(mutex_);
    std::ofstream file(file_path);
    if (!file.is_open()) return false;

    file << "# Progressive IRC Server Configuration\n";
    file << "# Generated: " << std::time(nullptr) << "\n";
    file << "# Server: " << config_.server_name << "\n\n";

    // ---- Server Identity ----
    file << "server_name = \"" << config_.server_name << "\"\n";
    file << "server_description = \"" << config_.server_description << "\"\n";
    file << "network_name = \"" << config_.network_name << "\"\n";

    // ---- Network Settings ----
    file << "\n# Network Settings\n";
    file << "max_clients = " << config_.default_max_clients << "\n";
    file << "ping_frequency = " << config_.default_ping_freq << "\n";
    file << "max_channels = " << config_.default_max_channels << "\n";
    file << "max_nick_length = " << config_.default_max_nick_len << "\n";
    file << "sendq = " << config_.default_sendq << "\n";
    file << "recvq = " << config_.default_recvq << "\n";

    // ---- Listen Blocks ----
    for (const auto& lb : config_.listen_blocks) {
      file << "\nlisten {\n";
      file << "  address = \"" << lb.address << "\"\n";
      file << "  port = " << lb.port << "\n";
      if (lb.ssl) {
        file << "  ssl = yes\n";
        if (!lb.ssl_cert.empty()) file << "  ssl_cert = \"" << lb.ssl_cert << "\"\n";
        if (!lb.ssl_key.empty()) file << "  ssl_key = \"" << lb.ssl_key << "\"\n";
      }
      file << "  type = \"" << lb.type << "\"\n";
      file << "  max_clients_per_ip = " << lb.max_clients_per_ip << "\n";
      file << "}\n";
    }

    // ---- Operator Blocks ----
    for (const auto& ob : config_.oper_blocks) {
      file << "\noper {\n";
      file << "  name = \"" << ob.name << "\"\n";
      if (!ob.password_hash.empty()) {
        file << "  password_hash = \"" << ob.password_hash << "\"\n";
        file << "  hash_method = \"" << ob.hash_method << "\"\n";
      } else {
        file << "  password = \"" << ob.password << "\"\n";
      }
      for (const auto& hm : ob.hostmasks) {
        file << "  host = \"" << hm << "\"\n";
      }
      file << "  class = \"" << ob.class_name << "\"\n";
      if (ob.flags != 0) {
        file << "  flags = \"global\"\n";
      }
      if (!ob.vhost.empty()) file << "  vhost = \"" << ob.vhost << "\"\n";
      if (ob.ssl_only) file << "  ssl_only = yes\n";
      file << "}\n";
    }

    // ---- Class Blocks ----
    for (const auto& cblock : config_.class_blocks) {
      file << "\nclass {\n";
      file << "  name = \"" << cblock.name << "\"\n";
      file << "  ping_freq = " << cblock.ping_freq << "\n";
      file << "  conn_freq = " << cblock.conn_freq << "\n";
      file << "  max_clients = " << cblock.max_clients << "\n";
      file << "  max_channels = " << cblock.max_channels << "\n";
      file << "  max_sendq = " << cblock.max_sendq << "\n";
      file << "  max_recvq = " << cblock.max_recvq << "\n";
      file << "}\n";
    }

    // ---- Connect Blocks ----
    for (const auto& cb : config_.connect_blocks) {
      file << "\nconnect {\n";
      file << "  name = \"" << cb.name << "\"\n";
      file << "  host = \"" << cb.host << "\"\n";
      file << "  port = " << cb.port << "\n";
      if (!cb.password.empty()) file << "  password = \"" << cb.password << "\"\n";
      if (cb.ssl) file << "  ssl = yes\n";
      file << "  autoconnect = " << (cb.autoconnect ? "yes" : "no") << "\n";
      file << "  class = \"" << cb.class_name << "\"\n";
      file << "}\n";
    }

    // ---- Deny Blocks ----
    for (const auto& db : config_.deny_blocks) {
      file << "\ndeny {\n";
      file << "  mask = \"" << db.mask << "\"\n";
      file << "  type = \"" << db.type << "\"\n";
      file << "  reason = \"" << db.reason << "\"\n";
      file << "}\n";
    }

    // ---- Exception Blocks ----
    for (const auto& eb : config_.exception_blocks) {
      file << "\nexcept {\n";
      file << "  mask = \"" << eb.mask << "\"\n";
      file << "  types = \"" << eb.types << "\"\n";
      file << "  reason = \"" << eb.reason << "\"\n";
      file << "}\n";
    }

    // ---- Admin Block ----
    file << "\nadmin {\n";
    file << "  name = \"" << config_.admin_info.name << "\"\n";
    file << "  email = \"" << config_.admin_info.email << "\"\n";
    file << "  location = \"" << config_.admin_info.location << "\"\n";
    file << "}\n";

    return true;
  }

  // ---- Generate a summary report ----
  std::string summary_report() const {
    std::stringstream ss;
    ss << "=== IRC Server Configuration Summary ===\n";
    ss << "  Config file: " << config_.config_file_path << "\n";
    ss << "  Server name: " << config_.server_name << "\n";
    ss << "  Network:     " << config_.network_name << "\n";
    ss << "  Description: " << config_.server_description << "\n";
    ss << "  SID:         " << config_.server_sid << "\n";
    ss << "  Loaded:      " << (config_.config_valid ? "OK" : "FAILED") << "\n";
    ss << "\n";
    ss << "  Listen blocks:    " << config_.listen_blocks.size() << "\n";
    for (const auto& lb : config_.listen_blocks) {
      ss << "    " << lb.address << ":" << lb.port
         << " (type=" << lb.type
         << ", ssl=" << (lb.ssl ? "yes" : "no") << ")\n";
    }
    ss << "\n";
    ss << "  Operator blocks:  " << config_.oper_blocks.size() << "\n";
    for (const auto& ob : config_.oper_blocks) {
      ss << "    " << ob.name << " (hostmasks=" << ob.hostmasks.size()
         << ", class=" << ob.class_name
         << ", flags=0x" << std::hex << ob.flags << std::dec << ")\n";
    }
    ss << "\n";
    ss << "  Connect blocks:   " << config_.connect_blocks.size() << "\n";
    for (const auto& cb : config_.connect_blocks) {
      ss << "    " << cb.name << " -> " << cb.host << ":" << cb.port
         << " (ssl=" << (cb.ssl ? "yes" : "no")
         << ", auto=" << (cb.autoconnect ? "yes" : "no") << ")\n";
    }
    ss << "\n";
    ss << "  Class blocks:     " << config_.class_blocks.size() << "\n";
    for (const auto& cblock : config_.class_blocks) {
      ss << "    " << cblock.name << " (ping=" << cblock.ping_freq
         << "s, sendq=" << cblock.max_sendq
         << ", maxchans=" << cblock.max_channels << ")\n";
    }
    ss << "\n";
    ss << "  Deny blocks:      " << config_.deny_blocks.size() << "\n";
    ss << "  Allow blocks:     " << config_.allow_blocks.size() << "\n";
    ss << "  Exception blocks: " << config_.exception_blocks.size() << "\n";
    ss << "  VHost blocks:     " << config_.vhost_blocks.size() << "\n";
    ss << "  Log blocks:       " << config_.log_blocks.size() << "\n";
    ss << "\n";
    if (!config_.config_errors.empty()) {
      ss << "  Errors (" << config_.config_errors.size() << "):\n";
      for (const auto& e : config_.config_errors) {
        ss << "    ERROR: " << e << "\n";
      }
    }
    if (!config_.config_warnings.empty()) {
      ss << "  Warnings (" << config_.config_warnings.size() << "):\n";
      for (const auto& w : config_.config_warnings) {
        ss << "    WARN: " << w << "\n";
      }
    }
    ss << "=========================================\n";
    return ss.str();
  }

private:
  ServerConfiguration config_;
  mutable std::mutex mutex_;

  static ConfigurationManager* instance_;

  static void signal_handler_dispatcher(int sig) {
    if (sig == CONFIG_RELOAD_SIGNAL && instance_) {
      instance_->on_sighup();
    }
  }

  void on_sighup() {
    reload();
    // Log the reload result
    if (config_.config_valid) {
      // reload successful — syslog or internal logging
    } else {
      // reload failed — log errors
    }
  }

  void cleanup_signal_handler() {
    if (instance_ == this) {
      instance_ = nullptr;
    }
  }

  void apply_defaults() {
    if (config_.server_sid.empty()) {
      config_.server_sid = random_string(3);
    }
    if (config_.server_uid.empty()) {
      config_.server_uid = random_string(10);
    }
    if (config_.max_local == 0) {
      config_.max_local = config_.max_connections;
    }
    if (config_.max_global == 0) {
      config_.max_global = config_.max_connections * 10;
    }
    // Ensure at least one default listen block exists
    if (config_.listen_blocks.empty()) {
      ListenBlock lb;
      lb.port = 6667;
      config_.listen_blocks.push_back(lb);
    }
  }

  void load_external_files() {
    // Load MOTD file
    if (!config_.motd_info.file_path.empty()) {
      load_text_file(config_.motd_info.file_path, config_.motd_info.lines);
      config_.motd_info.loaded = true;
      config_.motd_info.last_loaded = now_sec();
    }

    // Load rules file
    if (!config_.motd_info.rules_file_path.empty()) {
      load_text_file(config_.motd_info.rules_file_path, config_.motd_info.rules_lines);
      config_.motd_info.rules_loaded = true;
    }

    // Load opermotd file
    if (!config_.motd_info.opermotd_path.empty()) {
      load_text_file(config_.motd_info.opermotd_path, config_.motd_info.opermotd_lines);
      config_.motd_info.opermotd_loaded = true;
    }
  }

  bool load_text_file(const std::string& path, std::vector<std::string>& out) {
    std::ifstream file(path);
    if (!file.is_open()) return false;
    std::string line;
    while (std::getline(file, line)) {
      // Strip trailing CR
      if (!line.empty() && line.back() == '\r') line.pop_back();
      out.push_back(line);
    }
    return true;
  }
};

ConfigurationManager* ConfigurationManager::instance_ = nullptr;

// ============================================================================
// Global configuration singleton access
// ============================================================================

namespace {

std::unique_ptr<ConfigurationManager> g_config_manager;
std::once_flag g_config_init_flag;

void initialize_config_manager() {
  g_config_manager = std::make_unique<ConfigurationManager>();
}

} // namespace

ConfigurationManager& get_config_manager() {
  std::call_once(g_config_init_flag, initialize_config_manager);
  return *g_config_manager;
}

// ============================================================================
// Public API — configuration loading
// ============================================================================

bool load_config(const std::string& path) {
  auto& mgr = get_config_manager();
  return mgr.load(path);
}

bool reload_config() {
  auto& mgr = get_config_manager();
  return mgr.reload();
}

const ServerConfiguration& get_config() {
  return get_config_manager().config();
}

ServerConfiguration& get_mutable_config() {
  return get_config_manager().mutable_config();
}

// ============================================================================
// Public API — operator lookup helpers
// ============================================================================

const OperBlock* find_oper_by_name(const std::string& name) {
  return get_config_manager().find_oper_by_name(name);
}

const OperBlock* find_oper_by_host(const std::string& user_host_mask) {
  return get_config_manager().find_oper_by_host(user_host_mask);
}

std::vector<const OperBlock*> find_opers_for_user(
    const std::string& nick, const std::string& ident,
    const std::string& host, const std::string& ip) {
  return get_config_manager().find_opers_for_user(nick, ident, host, ip);
}

bool is_oper_name(const std::string& name) {
  return get_config_manager().find_oper_by_name(name) != nullptr;
}

// ============================================================================
// Public API — connection class lookup
// ============================================================================

const ClassBlock* find_class(const std::string& name) {
  return get_config_manager().find_class(name);
}

const ClassBlock* get_default_class() {
  return get_config_manager().find_default_class();
}

// ============================================================================
// Public API — connect/link lookup
// ============================================================================

const ConnectBlock* find_connect_block(const std::string& server_name) {
  return get_config_manager().find_connect(server_name);
}

// ============================================================================
// Public API — allow/deny checks
// ============================================================================

bool is_allowed_ip(const std::string& ip) {
  return get_config_manager().is_allowed(ip);
}

bool is_denied_ip(const std::string& ip) {
  return get_config_manager().is_denied(ip);
}

const DenyBlock* find_deny_block(const std::string& ip) {
  return get_config_manager().find_deny(ip);
}

// ============================================================================
// Public API — exception checks
// ============================================================================

bool is_excepted_from(const std::string& user_mask, const std::string& types) {
  return get_config_manager().is_excepted(user_mask, types);
}

// ============================================================================
// Public API — vHost
// ============================================================================

const VHostBlock* find_vhost_by_login(const std::string& login) {
  return get_config_manager().find_vhost(login);
}

// ============================================================================
// Public API — admin info
// ============================================================================

const AdminInfo& get_admin_info() {
  return get_config_manager().admin_info();
}

// ============================================================================
// Public API — MOTD
// ============================================================================

const MotdInfo& get_motd_info() {
  return get_config_manager().motd();
}

// ============================================================================
// Public API — configuration statistics
// ============================================================================

int config_listen_count() { return get_config_manager().listen_count(); }
int config_oper_count() { return get_config_manager().oper_count(); }
int config_connect_count() { return get_config_manager().connect_count(); }
int config_class_count() { return get_config_manager().class_count(); }
int config_exception_count() { return get_config_manager().exception_count(); }
int config_deny_count() { return get_config_manager().deny_count(); }
int config_allow_count() { return get_config_manager().allow_count(); }
int config_vhost_count() { return get_config_manager().vhost_count(); }
int config_log_count() { return get_config_manager().log_count(); }

const std::vector<std::string>& config_errors() {
  return get_config_manager().errors();
}

const std::vector<std::string>& config_warnings() {
  return get_config_manager().warnings();
}

bool config_is_valid() {
  return get_config_manager().is_valid();
}

std::string config_file_path() {
  return get_config_manager().config_file();
}

// ============================================================================
// Public API — runtime block manipulation
// ============================================================================

bool add_oper_block(const OperBlock& ob) {
  return get_config_manager().add_oper(ob);
}

bool remove_oper_block(const std::string& name) {
  return get_config_manager().remove_oper(name);
}

bool add_deny_block(const DenyBlock& db) {
  return get_config_manager().add_deny(db);
}

bool remove_deny_block(const std::string& mask) {
  return get_config_manager().remove_deny(mask);
}

bool add_exception_block(const ExceptionBlock& eb) {
  return get_config_manager().add_exception(eb);
}

bool remove_exception_block(const std::string& mask) {
  return get_config_manager().remove_exception(mask);
}

bool add_vhost_block(const VHostBlock& vb) {
  return get_config_manager().add_vhost(vb);
}

bool remove_vhost_block(const std::string& login) {
  return get_config_manager().remove_vhost(login);
}

// ============================================================================
// Public API — oper privilege checks
// ============================================================================

bool oper_has_flag(const OperBlock* ob, OperFlag flag) {
  if (!ob) return false;
  return OperPrivilegeSets::has_flag(ob->flags, flag);
}

bool oper_has_flag_by_name(const std::string& name, OperFlag flag) {
  auto* ob = find_oper_by_name(name);
  return oper_has_flag(ob, flag);
}

bool oper_can_kill(const OperBlock* ob) {
  return oper_has_flag(ob, OperFlag::CAN_KILL) ||
         oper_has_flag(ob, OperFlag::CAN_LOCAL_KILL);
}

bool oper_can_remote_kill(const OperBlock* ob) {
  return oper_has_flag(ob, OperFlag::CAN_KILL) ||
         oper_has_flag(ob, OperFlag::CAN_REMOTE_KILL);
}

bool oper_can_rehash(const OperBlock* ob) {
  return oper_has_flag(ob, OperFlag::CAN_REHASH);
}

bool oper_can_restart(const OperBlock* ob) {
  return oper_has_flag(ob, OperFlag::CAN_RESTART);
}

bool oper_can_die(const OperBlock* ob) {
  return oper_has_flag(ob, OperFlag::CAN_DIE);
}

bool oper_can_globops(const OperBlock* ob) {
  return oper_has_flag(ob, OperFlag::CAN_GLOBOPS);
}

bool oper_can_wallops(const OperBlock* ob) {
  return oper_has_flag(ob, OperFlag::CAN_WALLOPS);
}

bool oper_can_kline(const OperBlock* ob) {
  return oper_has_flag(ob, OperFlag::CAN_KLINE);
}

bool oper_can_unkline(const OperBlock* ob) {
  return oper_has_flag(ob, OperFlag::CAN_UNKLINE);
}

bool oper_can_gline(const OperBlock* ob) {
  return oper_has_flag(ob, OperFlag::CAN_GLINE);
}

bool oper_can_ungline(const OperBlock* ob) {
  return oper_has_flag(ob, OperFlag::CAN_UNGLINE);
}

bool oper_can_override(const OperBlock* ob) {
  return oper_has_flag(ob, OperFlag::CAN_OVERRIDE);
}

bool oper_can_squit(const OperBlock* ob) {
  return oper_has_flag(ob, OperFlag::CAN_SQUIT);
}

bool oper_is_immune_to_klines(const OperBlock* ob) {
  return ob ? ob->immune_to_klines : false;
}

bool oper_is_immune_to_gline(const OperBlock* ob) {
  return ob ? ob->immune_to_gline : false;
}

// ============================================================================
// Public API — config file save
// ============================================================================

bool save_config_to_file(const std::string& path) {
  return get_config_manager().save_to_file(path);
}

// ============================================================================
// Public API — summary / diagnostics
// ============================================================================

std::string config_summary() {
  return get_config_manager().summary_report();
}

// ============================================================================
// Public API — signal handler initialization
// ============================================================================

void init_config_signal_handler() {
  get_config_manager().setup_signal_handler();
}

// ============================================================================
// Oper flag name lookup helpers (for /stats o, /whois, etc.)
// ============================================================================

std::string oper_flag_name(OperFlag flag) {
  switch (flag) {
    case OperFlag::CAN_RESTART: return "can_restart";
    case OperFlag::CAN_DIE: return "can_die";
    case OperFlag::CAN_REHASH: return "can_rehash";
    case OperFlag::CAN_GLOBOPS: return "can_globops";
    case OperFlag::CAN_WALLOPS: return "can_wallops";
    case OperFlag::CAN_KILL: return "can_kill";
    case OperFlag::CAN_KLINE: return "can_kline";
    case OperFlag::CAN_UNKLINE: return "can_unkline";
    case OperFlag::CAN_GLINE: return "can_gline";
    case OperFlag::CAN_UNGLINE: return "can_ungline";
    case OperFlag::CAN_ZLINE: return "can_zline";
    case OperFlag::CAN_UNZLINE: return "can_unzline";
    case OperFlag::CAN_GZLINE: return "can_gzline";
    case OperFlag::CAN_UNGZLINE: return "can_ungzline";
    case OperFlag::CAN_LOCAL_KILL: return "can_local_kill";
    case OperFlag::CAN_REMOTE_KILL: return "can_remote_kill";
    case OperFlag::CAN_JUPE: return "can_jupe";
    case OperFlag::CAN_LOCAL_JUPE: return "can_local_jupe";
    case OperFlag::CAN_SQUIT: return "can_squit";
    case OperFlag::CAN_LOCAL_SQUIT: return "can_local_squit";
    case OperFlag::CAN_CONNECT: return "can_connect";
    case OperFlag::CAN_LOCAL_CONNECT: return "can_local_connect";
    case OperFlag::CAN_DCCDENY: return "can_dccdeny";
    case OperFlag::CAN_UNDCCDENY: return "can_undccdeny";
    case OperFlag::CAN_ADMIN: return "can_admin";
    case OperFlag::CAN_OVERRIDE: return "can_override";
    case OperFlag::CAN_OPERMOTD: return "can_opermotd";
    case OperFlag::CAN_OPERWALL: return "can_operwall";
    case OperFlag::CAN_GLOBALROUTE: return "can_globalroute";
    case OperFlag::CAN_SET: return "can_set";
    case OperFlag::CAN_SAJOIN: return "can_sajoin";
    case OperFlag::CAN_SAPART: return "can_sapart";
    case OperFlag::CAN_SAMODE: return "can_samode";
    case OperFlag::CAN_SAKICK: return "can_sakick";
    case OperFlag::CAN_SATOPIC: return "can_satopic";
    case OperFlag::CAN_SWHOIS: return "can_swhois";
    case OperFlag::CAN_CHGHOST: return "can_chghost";
    case OperFlag::CAN_CHGIDENT: return "can_chgident";
    case OperFlag::CAN_CHGNAME: return "can_chgname";
    case OperFlag::CAN_HIDEOPER: return "can_hideoper";
    case OperFlag::CAN_SEE_HIDDEN: return "can_see_hidden";
    case OperFlag::CAN_SEE_CHANS: return "can_see_chans";
    case OperFlag::CAN_SEE_OPS: return "can_see_ops";
    case OperFlag::CAN_SEE_INVIS: return "can_see_invis";
    case OperFlag::CAN_SEE_SECRET_CHANS: return "can_see_secret_chans";
    case OperFlag::CAN_SEE_ALL_CHANS: return "can_see_all_chans";
    case OperFlag::CAN_JOIN_OPERSONLY: return "can_join_opersonly";
    case OperFlag::CAN_FLOOD_EXEMPT: return "can_flood_exempt";
    case OperFlag::CAN_NO_CTCP: return "can_no_ctcp";
    case OperFlag::CAN_UNLIMITED_SENDQ: return "can_unlimited_sendq";
    case OperFlag::CAN_ALWAYS_OP: return "can_always_op";
    case OperFlag::CAN_DEOP_PROTECT: return "can_deop_protect";
    case OperFlag::CAN_SVSJOIN: return "can_svsjoin";
    case OperFlag::CAN_SVSNICK: return "can_svsnick";
    case OperFlag::CAN_SVSNOOP: return "can_svsnoop";
    case OperFlag::CAN_SVSKILL: return "can_svskill";
    case OperFlag::CAN_SVSMODE: return "can_svsmode";
    case OperFlag::CAN_SVSSNO: return "can_svssno";
    case OperFlag::CAN_SVSSQUIT: return "can_svssquit";
    case OperFlag::CAN_SVSADMIN: return "can_svsadmin";
    default: return "unknown";
  }
}

std::vector<std::string> oper_flag_list(uint64_t flags) {
  std::vector<std::string> result;
  for (uint64_t bit = 0; bit < 64; ++bit) {
    uint64_t mask = 1ULL << bit;
    if (flags & mask) {
      result.push_back(oper_flag_name(static_cast<OperFlag>(mask)));
    }
  }
  return result;
}

// ============================================================================
// Config diff utility — compare two configs and report changes
// ============================================================================

struct ConfigDiff {
  int listen_added = 0;
  int listen_removed = 0;
  int oper_added = 0;
  int oper_removed = 0;
  int connect_added = 0;
  int connect_removed = 0;
  int class_added = 0;
  int class_removed = 0;
  int deny_added = 0;
  int deny_removed = 0;
  int except_added = 0;
  int except_removed = 0;
  int allow_added = 0;
  int allow_removed = 0;
  int vhost_added = 0;
  int vhost_removed = 0;
  int log_added = 0;
  int log_removed = 0;
  bool server_name_changed = false;
  bool network_name_changed = false;
  bool any_change = false;

  std::string to_string() const {
    if (!any_change) return "No configuration changes detected.";
    std::stringstream ss;
    ss << "Configuration changes:\n";
    if (server_name_changed) ss << "  - server_name changed\n";
    if (network_name_changed) ss << "  - network_name changed\n";
    if (listen_added > 0) ss << "  + " << listen_added << " listen block(s) added\n";
    if (listen_removed > 0) ss << "  - " << listen_removed << " listen block(s) removed\n";
    if (oper_added > 0) ss << "  + " << oper_added << " oper block(s) added\n";
    if (oper_removed > 0) ss << "  - " << oper_removed << " oper block(s) removed\n";
    if (connect_added > 0) ss << "  + " << connect_added << " connect block(s) added\n";
    if (connect_removed > 0) ss << "  - " << connect_removed << " connect block(s) removed\n";
    if (class_added > 0) ss << "  + " << class_added << " class block(s) added\n";
    if (class_removed > 0) ss << "  - " << class_removed << " class block(s) removed\n";
    if (deny_added > 0) ss << "  + " << deny_added << " deny block(s) added\n";
    if (deny_removed > 0) ss << "  - " << deny_removed << " deny block(s) removed\n";
    if (except_added > 0) ss << "  + " << except_added << " exception block(s) added\n";
    if (except_removed > 0) ss << "  - " << except_removed << " exception block(s) removed\n";
    if (allow_added > 0) ss << "  + " << allow_added << " allow block(s) added\n";
    if (allow_removed > 0) ss << "  - " << allow_removed << " allow block(s) removed\n";
    if (vhost_added > 0) ss << "  + " << vhost_added << " vhost block(s) added\n";
    if (vhost_removed > 0) ss << "  - " << vhost_removed << " vhost block(s) removed\n";
    if (log_added > 0) ss << "  + " << log_added << " log block(s) added\n";
    if (log_removed > 0) ss << "  - " << log_removed << " log block(s) removed\n";
    return ss.str();
  }
};

ConfigDiff diff_configs(const ServerConfiguration& old_conf,
                         const ServerConfiguration& new_conf) {
  ConfigDiff diff;

  diff.server_name_changed = (old_conf.server_name != new_conf.server_name);
  diff.network_name_changed = (old_conf.network_name != new_conf.network_name);

  diff.listen_added = static_cast<int>(new_conf.listen_blocks.size()) -
                      static_cast<int>(old_conf.listen_blocks.size());
  if (diff.listen_added < 0) {
    diff.listen_removed = -diff.listen_added;
    diff.listen_added = 0;
  } else if (diff.listen_added == 0) {
    diff.listen_removed = 0;
  }

  diff.oper_added = static_cast<int>(new_conf.oper_blocks.size()) -
                    static_cast<int>(old_conf.oper_blocks.size());
  if (diff.oper_added < 0) {
    diff.oper_removed = -diff.oper_added;
    diff.oper_added = 0;
  }

  diff.connect_added = static_cast<int>(new_conf.connect_blocks.size()) -
                       static_cast<int>(old_conf.connect_blocks.size());
  if (diff.connect_added < 0) {
    diff.connect_removed = -diff.connect_added;
    diff.connect_added = 0;
  }

  diff.class_added = static_cast<int>(new_conf.class_blocks.size()) -
                     static_cast<int>(old_conf.class_blocks.size());
  if (diff.class_added < 0) {
    diff.class_removed = -diff.class_added;
    diff.class_added = 0;
  }

  diff.deny_added = static_cast<int>(new_conf.deny_blocks.size()) -
                    static_cast<int>(old_conf.deny_blocks.size());
  if (diff.deny_added < 0) {
    diff.deny_removed = -diff.deny_added;
    diff.deny_added = 0;
  }

  diff.except_added = static_cast<int>(new_conf.exception_blocks.size()) -
                      static_cast<int>(old_conf.exception_blocks.size());
  if (diff.except_added < 0) {
    diff.except_removed = -diff.except_added;
    diff.except_added = 0;
  }

  diff.allow_added = static_cast<int>(new_conf.allow_blocks.size()) -
                     static_cast<int>(old_conf.allow_blocks.size());
  if (diff.allow_added < 0) {
    diff.allow_removed = -diff.allow_added;
    diff.allow_added = 0;
  }

  diff.vhost_added = static_cast<int>(new_conf.vhost_blocks.size()) -
                     static_cast<int>(old_conf.vhost_blocks.size());
  if (diff.vhost_added < 0) {
    diff.vhost_removed = -diff.vhost_added;
    diff.vhost_added = 0;
  }

  diff.log_added = static_cast<int>(new_conf.log_blocks.size()) -
                   static_cast<int>(old_conf.log_blocks.size());
  if (diff.log_added < 0) {
    diff.log_removed = -diff.log_added;
    diff.log_added = 0;
  }

  diff.any_change = diff.server_name_changed || diff.network_name_changed ||
                    diff.listen_added > 0 || diff.listen_removed > 0 ||
                    diff.oper_added > 0 || diff.oper_removed > 0 ||
                    diff.connect_added > 0 || diff.connect_removed > 0 ||
                    diff.class_added > 0 || diff.class_removed > 0 ||
                    diff.deny_added > 0 || diff.deny_removed > 0 ||
                    diff.except_added > 0 || diff.except_removed > 0 ||
                    diff.allow_added > 0 || diff.allow_removed > 0 ||
                    diff.vhost_added > 0 || diff.vhost_removed > 0 ||
                    diff.log_added > 0 || diff.log_removed > 0;

  return diff;
}

// ============================================================================
// Cleanup expired entries (call periodically)
// ============================================================================

void cleanup_expired_entries() {
  auto& mgr = get_config_manager();
  auto& config = mgr.mutable_config();

  // Cleanup expired exceptions
  config.exception_blocks.erase(
      std::remove_if(config.exception_blocks.begin(), config.exception_blocks.end(),
                     [](const ExceptionBlock& eb) { return eb.is_expired(); }),
      config.exception_blocks.end());

  // Cleanup expired deny blocks
  config.deny_blocks.erase(
      std::remove_if(config.deny_blocks.begin(), config.deny_blocks.end(),
                     [](const DenyBlock& db) { return db.is_expired(); }),
      config.deny_blocks.end());

  // Cleanup expired vhosts
  config.vhost_blocks.erase(
      std::remove_if(config.vhost_blocks.begin(), config.vhost_blocks.end(),
                     [](const VHostBlock& vb) { return vb.is_expired(); }),
      config.vhost_blocks.end());
}

} // namespace irc
} // namespace progressive
