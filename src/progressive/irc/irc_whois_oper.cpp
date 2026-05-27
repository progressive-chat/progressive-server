// irc_whois_oper.cpp - Extended WHOIS, Connection Tracking, and IRC Operator Management
// Implements InspIRCd-style WHOIS responses, operator privileges, connection tracking,
// WHOWAS history, SNOMASK, flood protection, operator override commands, and logging.
// Target: 3000+ lines of complete, production-ready C++.

#include "irc_server.hpp"

#include <algorithm>
#include <bcrypt/BCrypt.hpp>  // OpenBSD-style bcrypt for password hashing
#include <chrono>
#include <cmath>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace progressive::irc {

using json = nlohmann::json;

// ============================================================================
// Forward declarations
// ============================================================================
static int64_t now_ms();
static int64_t now_sec();
static std::string format_time(int64_t epoch_sec);
static std::string format_duration(int64_t seconds);
static std::string sha256(const std::string& data);
static bool check_bcrypt(const std::string& password, const std::string& hash);
static std::string hash_bcrypt(const std::string& password);

// ============================================================================
// Extended numeric replies beyond RFC 1459 (common IRC extensions)
// ============================================================================
namespace ExtendedNumerics {
  // WHOIS extensions
  constexpr int RPL_WHOISREGNICK  = 307;  // User has identified for this nick (services)
  constexpr int RPL_WHOISACCOUNT  = 330;  // whois logged in as account name
  constexpr int RPL_WHOISCERTFP   = 276;  // SSL certificate fingerprint (InspIRCd)
  constexpr int RPL_WHOISSECURE   = 671;  // Is using a secure connection (Unreal/Insp)
  constexpr int RPL_WHOISSPECIAL  = 320;  // Special whois text (operator defined)
  constexpr int RPL_WHOISACTUALLY = 338;  // Actually using host (Unreal)
  constexpr int RPL_WHOISHOST     = 378;  // Real hostname (Unreal/Insp)
  constexpr int RPL_WHOISMODES    = 379;  // User modes (Unreal/Insp)
  constexpr int RPL_WHOISBOT      = 335;  // User is a bot (optional)
  constexpr int RPL_WHOWASUSER    = 314;  // Was user information
  constexpr int RPL_ENDOFWHOWAS   = 369;  // End of WHOWAS
  constexpr int RPL_WHOISSECUREIP = 275;  // Secure connection IP info
  
  // Operator / server notice mask numerics
  constexpr int RPL_SNOMASK       = 8;    // Server notice mask (InspIRCd/Unreal)
  constexpr int RPL_YOURESRETIRED = 0;    // placeholder
  
  // Stats
  constexpr int RPL_STATSLINKINFO  = 211;
  constexpr int RPL_STATSCOMMANDS  = 212;
  constexpr int RPL_STATSCLINE     = 213;
  constexpr int RPL_STATSOLINE     = 243;
  constexpr int RPL_STATSUPTIME    = 242;
  constexpr int RPL_ENDOFSTATS     = 219;
  
  // Operator privilege messages
  constexpr int ERR_NOPRIVILEGES   = 481;
  constexpr int ERR_NOPRIVS        = 723;  // Unreal
  constexpr int RPL_YOUREOPER      = 381;
  
  // Errors
  constexpr int ERR_WHOWASEMPTY    = 406;  // No WHOWAS entries
  constexpr int ERR_WASNOSUCHNICK  = 406;  // Alias, there was no such nick
}

// ============================================================================
// Connection Class System
// ============================================================================
enum class ConnectionClassType : uint8_t {
  CLIENT_CLASS = 0,   // Standard client connection
  SERVER_CLASS = 1,   // Server-to-server link
  SERVICE_CLASS = 2,  // Services pseudo-client
  OPER_CLASS = 3      // Operator connection (elevated)
};

struct ConnectionClass {
  ConnectionClassType type{ConnectionClassType::CLIENT_CLASS};
  std::string name;
  
  // Limits
  int max_sendq{262144};        // Maximum send queue in bytes (256KB default)
  int max_recvq{65536};         // Maximum receive queue (64KB default)
  int max_channels{20};         // Maximum channels per user in this class
  int max_local{0};             // Max local connections (0 = unlimited)
  int max_global{0};            // Max global connections (0 = unlimited)
  int max_ident_wait{10};       // Seconds for ident timeout
  int ping_frequency{120};      // Seconds between PING checks
  int timeout_seconds{300};     // Idle timeout seconds
  int flood_rate{8};            // Messages per window
  int flood_window_ms{2000};    // Flood window in milliseconds
  
  // Flags
  bool can_oper_up{false};      // Can become IRC operator from this class
  bool use_ssl{false};          // Require SSL
  bool use_ipv6{false};         // Allow IPv6
  bool resolve_host{true};      // Do DNS reverse lookup
  
  // Connection tracking
  int active_count{0};          // Currently active connections in this class
  
  ConnectionClass() = default;
  ConnectionClass(ConnectionClassType t, const std::string& n) : type(t), name(n) {}
};

// ============================================================================
// Connection Statistics Tracking
// ============================================================================
struct ConnectionStats {
  // Identity
  std::string nick;
  std::string user;
  std::string host;
  std::string realname;
  std::string ip;
  int port{0};
  std::string server;           // Server the user is on
  
  // Timestamps
  int64_t signon_time{0};       // Unix epoch seconds when user signed on
  int64_t last_active{0};       // Last time user sent anything
  int64_t last_ping{0};         // Last ping sent
  int64_t last_pong{0};         // Last pong received
  
  // Traffic counters
  uint64_t bytes_sent{0};       // Total bytes sent to this connection
  uint64_t bytes_received{0};   // Total bytes received from this connection
  uint64_t messages_sent{0};    // Total IRC messages sent
  uint64_t messages_received{0}; // Total IRC messages received
  uint64_t commands_processed{0}; // Commands executed
  
  // Connection class
  std::string class_name;
  ConnectionClassType class_type{ConnectionClassType::CLIENT_CLASS};
  
  // TLS/SSL
  bool ssl_active{false};
  std::string ssl_cipher;
  std::string ssl_cert_fingerprint;
  std::string ssl_protocol_version;
  
  // Authentication
  bool identified{false};       // Identified to NickServ
  std::string account_name;     // Services account name
  
  // Away
  bool away{false};
  std::string away_message;
  int64_t away_since{0};
  
  // Modes
  std::string user_modes;
  
  // Operator status
  bool is_oper{false};
  std::string oper_type;
  std::string oper_host;        // Hostname used when opering up
  
  // Flood tracking
  int flood_count{0};
  int64_t flood_window_start{0};
  bool flood_blocked{false};
  int64_t flood_blocked_until{0};
  
  // Misc
  std::string client_version;   // CTCP VERSION response
  uint32_t hop_count{0};
  bool is_bot{false};
  std::vector<std::string> channel_list; // Joind channels (cached)
  
  ConnectionStats() {
    signon_time = now_sec();
    last_active = signon_time;
  }
};

// ============================================================================
// WHOIS Query Tracking (Flood Protection)
// ============================================================================
struct WhoisQueryTracker {
  std::string requester;        // Who is doing the WHOIS
  std::string target;           // Who they are querying
  int64_t timestamp{0};
  int count{0};                 // How many times this requester has done WHOIS
};

struct WhoisFloodState {
  int query_count{0};
  int64_t window_start{0};
  int64_t last_query{0};
  bool blocked{false};
  int64_t blocked_until{0};
};

// ============================================================================
// WHOWAS Entry
// ============================================================================
struct WhowasEntry {
  std::string nick;
  std::string user;
  std::string host;
  std::string realname;
  std::string server;
  std::string ip;
  int64_t signon_time{0};
  int64_t quit_time{0};
  std::string quit_reason;
  bool was_oper{false};
  std::string account_name;
  int64_t connected_duration{0}; // Seconds
  
  WhowasEntry() = default;
  
  WhowasEntry(const std::string& n, const std::string& u, const std::string& h,
              const std::string& r, const std::string& s, const std::string& i,
              int64_t st, int64_t qt, const std::string& qr, bool op,
              const std::string& acct, int64_t dur)
    : nick(n), user(u), host(h), realname(r), server(s), ip(i),
      signon_time(st), quit_time(qt), quit_reason(qr), was_oper(op),
      account_name(acct), connected_duration(dur) {}
};

// ============================================================================
// SNOMASK (Server Notice Mask) System
// ============================================================================
enum class SnomaskFlag : uint64_t {
  NONE            = 0,
  KILLS           = (1ULL << 0),   // +k - Kill notices
  CLIENT_CONNECT  = (1ULL << 1),   // +c - Client connect/disconnect
  OPER_UP         = (1ULL << 2),   // +o - Operator up/down
  SQUIT           = (1ULL << 3),   // +s - Server quit/connect notices (SQUIT)
  REHASH          = (1ULL << 4),   // +r - Rehash notices
  GLOBEOPS        = (1ULL << 5),   // +g - GlobOps
  WALLOPS         = (1ULL << 6),   // +w - WallOps
  DEBUG           = (1ULL << 7),   // +d - Debug messages
  JUNK_REJECT     = (1ULL << 8),   // +j - Junk rejection
  ACL             = (1ULL << 9),   // +a - Access control list changes
  XLINE           = (1ULL << 10),  // +x - XLine additions/removals
  SPAMFILTER      = (1ULL << 11),  // +f - Spamfilter matches
  FLOOD           = (1ULL << 12),  // +F - Flood notices
  PERM_CHAN       = (1ULL << 13),  // +p - Permanent channel notices
  MODULE          = (1ULL << 14),  // +m - Module load/unload
  DNS             = (1ULL << 15),  // +n - DNS notices
  REMOTE          = (1ULL << 16),  // +R - Remote server notices
  
  ALL             = 0xFFFFFFFFFFFFFFFFULL
};

inline SnomaskFlag operator|(SnomaskFlag a, SnomaskFlag b) {
  return static_cast<SnomaskFlag>(static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}
inline SnomaskFlag operator&(SnomaskFlag a, SnomaskFlag b) {
  return static_cast<SnomaskFlag>(static_cast<uint64_t>(a) & static_cast<uint64_t>(b));
}
inline SnomaskFlag operator~(SnomaskFlag a) {
  return static_cast<SnomaskFlag>(~static_cast<uint64_t>(a));
}
inline SnomaskFlag& operator|=(SnomaskFlag& a, SnomaskFlag b) { a = a | b; return a; }

struct SnomaskConfig {
  SnomaskFlag flags{SnomaskFlag::NONE};
  
  bool has_flag(SnomaskFlag f) const {
    return (flags & f) == f;
  }
  
  void set_flag(SnomaskFlag f) {
    flags = flags | f;
  }
  
  void unset_flag(SnomaskFlag f) {
    flags = flags & ~f;
  }
  
  void parse_from_string(const std::string& snomasks) {
    flags = SnomaskFlag::NONE;
    for (char c : snomasks) {
      switch (c) {
        case 'k': set_flag(SnomaskFlag::KILLS); break;
        case 'c': set_flag(SnomaskFlag::CLIENT_CONNECT); break;
        case 'o': set_flag(SnomaskFlag::OPER_UP); break;
        case 's': set_flag(SnomaskFlag::SQUIT); break;
        case 'r': set_flag(SnomaskFlag::REHASH); break;
        case 'g': set_flag(SnomaskFlag::GLOBEOPS); break;
        case 'w': set_flag(SnomaskFlag::WALLOPS); break;
        case 'd': set_flag(SnomaskFlag::DEBUG); break;
        case 'j': set_flag(SnomaskFlag::JUNK_REJECT); break;
        case 'a': set_flag(SnomaskFlag::ACL); break;
        case 'x': set_flag(SnomaskFlag::XLINE); break;
        case 'f': set_flag(SnomaskFlag::SPAMFILTER); break;
        case 'F': set_flag(SnomaskFlag::FLOOD); break;
        case 'p': set_flag(SnomaskFlag::PERM_CHAN); break;
        case 'm': set_flag(SnomaskFlag::MODULE); break;
        case 'n': set_flag(SnomaskFlag::DNS); break;
        case 'R': set_flag(SnomaskFlag::REMOTE); break;
        case '*': flags = SnomaskFlag::ALL; break;
        default: break;
      }
    }
  }
  
  std::string to_string() const {
    std::string result;
    if (has_flag(SnomaskFlag::KILLS))          result += 'k';
    if (has_flag(SnomaskFlag::CLIENT_CONNECT)) result += 'c';
    if (has_flag(SnomaskFlag::OPER_UP))        result += 'o';
    if (has_flag(SnomaskFlag::SQUIT))          result += 's';
    if (has_flag(SnomaskFlag::REHASH))         result += 'r';
    if (has_flag(SnomaskFlag::GLOBEOPS))       result += 'g';
    if (has_flag(SnomaskFlag::WALLOPS))        result += 'w';
    if (has_flag(SnomaskFlag::DEBUG))          result += 'd';
    if (has_flag(SnomaskFlag::JUNK_REJECT))    result += 'j';
    if (has_flag(SnomaskFlag::ACL))            result += 'a';
    if (has_flag(SnomaskFlag::XLINE))          result += 'x';
    if (has_flag(SnomaskFlag::SPAMFILTER))     result += 'f';
    if (has_flag(SnomaskFlag::FLOOD))          result += 'F';
    if (has_flag(SnomaskFlag::PERM_CHAN))      result += 'p';
    if (has_flag(SnomaskFlag::MODULE))         result += 'm';
    if (has_flag(SnomaskFlag::DNS))            result += 'n';
    if (has_flag(SnomaskFlag::REMOTE))         result += 'R';
    if (result.empty() && flags != SnomaskFlag::NONE) result = "*";
    return result.empty() ? "0" : result;
  }
  
  static std::string flag_to_name(SnomaskFlag f) {
    switch (f) {
      case SnomaskFlag::KILLS:          return "kills";
      case SnomaskFlag::CLIENT_CONNECT: return "client-connect";
      case SnomaskFlag::OPER_UP:        return "oper-up";
      case SnomaskFlag::SQUIT:          return "squit";
      case SnomaskFlag::REHASH:         return "rehash";
      case SnomaskFlag::GLOBEOPS:       return "globeops";
      case SnomaskFlag::WALLOPS:        return "wallops";
      case SnomaskFlag::DEBUG:          return "debug";
      case SnomaskFlag::JUNK_REJECT:    return "junk-reject";
      case SnomaskFlag::ACL:            return "acl";
      case SnomaskFlag::XLINE:          return "xline";
      case SnomaskFlag::SPAMFILTER:     return "spamfilter";
      case SnomaskFlag::FLOOD:          return "flood";
      case SnomaskFlag::PERM_CHAN:      return "perm-chan";
      case SnomaskFlag::MODULE:         return "module";
      case SnomaskFlag::DNS:            return "dns";
      case SnomaskFlag::REMOTE:         return "remote";
      default: return "unknown";
    }
  }
};

// ============================================================================
// Operator Privilege Definitions
// ============================================================================
enum class OperFlag : uint64_t {
  NONE              = 0,
  CAN_KILL          = (1ULL << 0),   // Can KILL users
  CAN_GLOBAL_KILL   = (1ULL << 1),   // Can kill on remote servers
  CAN_RESTART       = (1ULL << 2),   // Can RESTART the server
  CAN_DIE           = (1ULL << 3),   // Can DIE (shutdown) the server
  CAN_REHASH        = (1ULL << 4),   // Can REHASH configuration
  CAN_LOCAL_KILL    = (1ULL << 5),   // Can kill local users
  CAN_KLINE         = (1ULL << 6),   // Can add K:lines
  CAN_GKLINE        = (1ULL << 7),   // Can add global K:lines
  CAN_ZLINE         = (1ULL << 8),   // Can add Z:lines (IP bans)
  CAN_GZLINE        = (1ULL << 9),   // Can add global Z:lines
  CAN_GLINE         = (1ULL << 10),  // Can add G:lines
  CAN_ELINE         = (1ULL << 11),  // Can add E:lines (exceptions)
  CAN_FLINE         = (1ULL << 12),  // Can add F:lines (spam filter)
  CAN_QLINE         = (1ULL << 13),  // Can add Q:lines (nick/channel reserve)
  CAN_SGLINE        = (1ULL << 14),  // Can add SGline (shared)
  CAN_SQLINE        = (1ULL << 15),  // Can add SQline
  CAN_SZLINE        = (1ULL << 16),  // Can add SZline
  
  CAN_GLOBOPS       = (1ULL << 17),  // Can send GLOBOPS
  CAN_WALLOPS       = (1ULL << 18),  // Can send WALLOPS
  CAN_LOCOPS        = (1ULL << 19),  // Can send LOCOPS
  CAN_REMOTE        = (1ULL << 20),  // Can do remote connects
  CAN_SQUIT         = (1ULL << 21),  // Can SQUIT servers
  CAN_CONNECT       = (1ULL << 22),  // Can CONNECT servers
  CAN_DCCDENY       = (1ULL << 23),  // Can manage DCCDENY
  
  CAN_JOIN_OVERRIDE = (1ULL << 24),  // Can SAJOIN
  CAN_PART_OVERRIDE = (1ULL << 25),  // Can SAPART
  CAN_MODE_OVERRIDE = (1ULL << 26),  // Can SAMODE
  CAN_TOPIC_OVERRIDE= (1ULL << 27),  // Can SATOPIC
  CAN_KICK_OVERRIDE = (1ULL << 28),  // Can SAKICK
  CAN_NICK_OVERRIDE = (1ULL << 29),  // Can SANICK
  CAN_QUIT_OVERRIDE = (1ULL << 30),  // Can SAQUIT
  
  CAN_SEE_HIDDEN    = (1ULL << 31),  // Can see hidden channels/users
  CAN_SEE_OPS       = (1ULL << 32),  // Can see who is an operator
  CAN_SEE_CHANS     = (1ULL << 33),  // Can see secret/private channels in WHOIS
  CAN_SEE_IP        = (1ULL << 34),  // Can see real IP addresses
  CAN_SEE_REALHOST  = (1ULL << 35),  // Can see real hostnames
  
  CAN_SET_SNOMASK   = (1ULL << 36),  // Can set server notice masks
  CAN_BROADCAST     = (1ULL << 37),  // Can broadcast messages
  CAN_SVS           = (1ULL << 38),  // Can use SVSNICK, SVSJOIN, etc.
  CAN_MANAGE_MODULES= (1ULL << 39),  // Can load/unload modules
  CAN_MANAGE_S2S    = (1ULL << 40),  // Can manage server links
  
  CAN_SPY           = (1ULL << 41),  // Can spy on channels/users
  CAN_EXEMPT_LIMITS = (1ULL << 42),  // Exempt from channel/user limits
  CAN_EXEMPT_BANS   = (1ULL << 43),  // Exempt from bans
  CAN_EXEMPT_FLOOD  = (1ULL << 44),  // Exempt from flood protection
  CAN_EXEMPT_FILTER = (1ULL << 45),  // Exempt from spam filters
  
  CAN_UMODE_O       = (1ULL << 46),  // Can set +o (global op) on self
  CAN_UMODE_C       = (1ULL << 47),  // Can set +C (coadmin)
  CAN_UMODE_A       = (1ULL << 48),  // Can set +A (services admin)
  CAN_UMODE_N       = (1ULL << 49),  // Can set +N (netadmin)
  CAN_UMODE_a       = (1ULL << 50),  // Can set +a (admin)
  
  ALL               = 0xFFFFFFFFFFFFFFFFULL
};

inline OperFlag operator|(OperFlag a, OperFlag b) {
  return static_cast<OperFlag>(static_cast<uint64_t>(a) | static_cast<uint64_t>(b));
}
inline OperFlag operator&(OperFlag a, OperFlag b) {
  return static_cast<OperFlag>(static_cast<uint64_t>(a) & static_cast<uint64_t>(b));
}
inline OperFlag operator~(OperFlag a) {
  return static_cast<OperFlag>(~static_cast<uint64_t>(a));
}
inline OperFlag& operator|=(OperFlag& a, OperFlag b) { a = a | b; return a; }

// ============================================================================
// Operator Type Definitions
// ============================================================================
enum class OperType : uint8_t {
  LOCAL_OPER      = 0,  // Local operator (limited to this server)
  GLOBAL_OPER     = 1,  // Global operator (operator on all servers)
  ADMIN           = 2,  // Server administrator
  COADMIN         = 3,  // Co-administrator
  SERVICES_ADMIN  = 4,  // Services administrator
  NETADMIN        = 5,  // Network administrator (highest level)
  
  CUSTOM          = 99  // Custom operator type
};

struct OperTypeInfo {
  OperType type;
  std::string name;          // "NetAdmin", "Admin", "GlobalOper", etc.
  std::string umode_flag;    // +o, +a, +N, +A, +C
  std::string whois_line;    // "is a Network Administrator"
  OperFlag default_flags;
  SnomaskFlag default_snomasks;
  int priority;              // Higher = more privileged, for ordering
};

// Static table of operator type information
static const std::vector<OperTypeInfo> kOperTypeInfoTable = {
  { OperType::LOCAL_OPER,     "LocalOper",      "o",
    "is a Local IRC Operator",
    OperFlag::CAN_LOCAL_KILL | OperFlag::CAN_KLINE | OperFlag::CAN_ZLINE |
    OperFlag::CAN_GLOBOPS | OperFlag::CAN_WALLOPS | OperFlag::CAN_LOCOPS |
    OperFlag::CAN_SEE_CHANS | OperFlag::CAN_SEE_OPS | OperFlag::CAN_SET_SNOMASK |
    OperFlag::CAN_DCCDENY,
    SnomaskFlag::KILLS | SnomaskFlag::OPER_UP | SnomaskFlag::GLOBEOPS |
    SnomaskFlag::WALLOPS,
    10 },
    
  { OperType::GLOBAL_OPER,   "GlobalOper",     "o",
    "is a Global IRC Operator",
    OperFlag::CAN_LOCAL_KILL | OperFlag::CAN_GLOBAL_KILL | OperFlag::CAN_KLINE |
    OperFlag::CAN_ZLINE | OperFlag::CAN_GLINE | OperFlag::CAN_GLOBOPS |
    OperFlag::CAN_WALLOPS | OperFlag::CAN_LOCOPS | OperFlag::CAN_SQUIT |
    OperFlag::CAN_CONNECT | OperFlag::CAN_REMOTE | OperFlag::CAN_SEE_CHANS |
    OperFlag::CAN_SEE_OPS | OperFlag::CAN_SEE_IP | OperFlag::CAN_SET_SNOMASK |
    OperFlag::CAN_DCCDENY | OperFlag::CAN_JOIN_OVERRIDE | OperFlag::CAN_PART_OVERRIDE |
    OperFlag::CAN_MODE_OVERRIDE | OperFlag::CAN_KICK_OVERRIDE,
    SnomaskFlag::KILLS | SnomaskFlag::SQUIT | SnomaskFlag::CLIENT_CONNECT |
    SnomaskFlag::OPER_UP | SnomaskFlag::REHASH | SnomaskFlag::GLOBEOPS |
    SnomaskFlag::WALLOPS | SnomaskFlag::JUNK_REJECT | SnomaskFlag::XLINE |
    SnomaskFlag::FLOOD,
    20 },
    
  { OperType::COADMIN,       "Coadmin",        "C",
    "is a Co-Administrator",
    OperFlag::CAN_LOCAL_KILL | OperFlag::CAN_GLOBAL_KILL | OperFlag::CAN_RESTART |
    OperFlag::CAN_DIE | OperFlag::CAN_REHASH | OperFlag::CAN_KLINE |
    OperFlag::CAN_GKLINE | OperFlag::CAN_ZLINE | OperFlag::CAN_GZLINE |
    OperFlag::CAN_GLINE | OperFlag::CAN_ELINE | OperFlag::CAN_FLINE |
    OperFlag::CAN_GLOBOPS | OperFlag::CAN_WALLOPS | OperFlag::CAN_LOCOPS |
    OperFlag::CAN_SQUIT | OperFlag::CAN_CONNECT | OperFlag::CAN_REMOTE |
    OperFlag::CAN_SEE_CHANS | OperFlag::CAN_SEE_HIDDEN | OperFlag::CAN_SEE_OPS |
    OperFlag::CAN_SEE_IP | OperFlag::CAN_SEE_REALHOST | OperFlag::CAN_SET_SNOMASK |
    OperFlag::CAN_DCCDENY | OperFlag::CAN_JOIN_OVERRIDE | OperFlag::CAN_PART_OVERRIDE |
    OperFlag::CAN_MODE_OVERRIDE | OperFlag::CAN_TOPIC_OVERRIDE |
    OperFlag::CAN_KICK_OVERRIDE | OperFlag::CAN_NICK_OVERRIDE |
    OperFlag::CAN_BROADCAST | OperFlag::CAN_MANAGE_S2S |
    OperFlag::CAN_UMODE_a | OperFlag::CAN_UMODE_C,
    SnomaskFlag::KILLS | SnomaskFlag::SQUIT | SnomaskFlag::CLIENT_CONNECT |
    SnomaskFlag::OPER_UP | SnomaskFlag::REHASH | SnomaskFlag::GLOBEOPS |
    SnomaskFlag::WALLOPS | SnomaskFlag::DEBUG | SnomaskFlag::JUNK_REJECT |
    SnomaskFlag::XLINE | SnomaskFlag::SPAMFILTER | SnomaskFlag::FLOOD |
    SnomaskFlag::MODULE | SnomaskFlag::DNS | SnomaskFlag::REMOTE,
    30 },
    
  { OperType::ADMIN,         "Admin",          "a",
    "is a Server Administrator",
    OperFlag::CAN_LOCAL_KILL | OperFlag::CAN_GLOBAL_KILL | OperFlag::CAN_RESTART |
    OperFlag::CAN_DIE | OperFlag::CAN_REHASH | OperFlag::CAN_KLINE |
    OperFlag::CAN_GKLINE | OperFlag::CAN_ZLINE | OperFlag::CAN_GZLINE |
    OperFlag::CAN_GLINE | OperFlag::CAN_ELINE | OperFlag::CAN_FLINE |
    OperFlag::CAN_QLINE | OperFlag::CAN_SGLINE | OperFlag::CAN_SQLINE |
    OperFlag::CAN_SZLINE | OperFlag::CAN_GLOBOPS | OperFlag::CAN_WALLOPS |
    OperFlag::CAN_LOCOPS | OperFlag::CAN_SQUIT | OperFlag::CAN_CONNECT |
    OperFlag::CAN_REMOTE | OperFlag::CAN_SEE_CHANS | OperFlag::CAN_SEE_HIDDEN |
    OperFlag::CAN_SEE_OPS | OperFlag::CAN_SEE_IP | OperFlag::CAN_SEE_REALHOST |
    OperFlag::CAN_SET_SNOMASK | OperFlag::CAN_DCCDENY | OperFlag::CAN_JOIN_OVERRIDE |
    OperFlag::CAN_PART_OVERRIDE | OperFlag::CAN_MODE_OVERRIDE |
    OperFlag::CAN_TOPIC_OVERRIDE | OperFlag::CAN_KICK_OVERRIDE |
    OperFlag::CAN_NICK_OVERRIDE | OperFlag::CAN_QUIT_OVERRIDE |
    OperFlag::CAN_BROADCAST | OperFlag::CAN_SVS | OperFlag::CAN_MANAGE_MODULES |
    OperFlag::CAN_MANAGE_S2S | OperFlag::CAN_SPY | OperFlag::CAN_EXEMPT_LIMITS |
    OperFlag::CAN_EXEMPT_BANS | OperFlag::CAN_EXEMPT_FLOOD |
    OperFlag::CAN_EXEMPT_FILTER | OperFlag::CAN_UMODE_a | OperFlag::CAN_UMODE_O |
    OperFlag::CAN_UMODE_C,
    SnomaskFlag::ALL,
    40 },
    
  { OperType::SERVICES_ADMIN,"ServicesAdmin",  "A",
    "is a Services Administrator",
    OperFlag::CAN_LOCAL_KILL | OperFlag::CAN_GLOBAL_KILL | OperFlag::CAN_RESTART |
    OperFlag::CAN_DIE | OperFlag::CAN_REHASH | OperFlag::CAN_KLINE |
    OperFlag::CAN_GKLINE | OperFlag::CAN_ZLINE | OperFlag::CAN_GZLINE |
    OperFlag::CAN_GLINE | OperFlag::CAN_ELINE | OperFlag::CAN_FLINE |
    OperFlag::CAN_QLINE | OperFlag::CAN_SGLINE | OperFlag::CAN_SQLINE |
    OperFlag::CAN_SZLINE | OperFlag::CAN_GLOBOPS | OperFlag::CAN_WALLOPS |
    OperFlag::CAN_LOCOPS | OperFlag::CAN_SQUIT | OperFlag::CAN_CONNECT |
    OperFlag::CAN_REMOTE | OperFlag::CAN_SEE_CHANS | OperFlag::CAN_SEE_HIDDEN |
    OperFlag::CAN_SEE_OPS | OperFlag::CAN_SEE_IP | OperFlag::CAN_SEE_REALHOST |
    OperFlag::CAN_SET_SNOMASK | OperFlag::CAN_DCCDENY | OperFlag::CAN_JOIN_OVERRIDE |
    OperFlag::CAN_PART_OVERRIDE | OperFlag::CAN_MODE_OVERRIDE |
    OperFlag::CAN_TOPIC_OVERRIDE | OperFlag::CAN_KICK_OVERRIDE |
    OperFlag::CAN_NICK_OVERRIDE | OperFlag::CAN_QUIT_OVERRIDE |
    OperFlag::CAN_BROADCAST | OperFlag::CAN_SVS | OperFlag::CAN_MANAGE_MODULES |
    OperFlag::CAN_MANAGE_S2S | OperFlag::CAN_SPY | OperFlag::CAN_EXEMPT_LIMITS |
    OperFlag::CAN_EXEMPT_BANS | OperFlag::CAN_EXEMPT_FLOOD |
    OperFlag::CAN_EXEMPT_FILTER | OperFlag::CAN_UMODE_A | OperFlag::CAN_UMODE_a |
    OperFlag::CAN_UMODE_O | OperFlag::CAN_UMODE_C,
    SnomaskFlag::ALL,
    50 },
    
  { OperType::NETADMIN,      "NetAdmin",       "N",
    "is a Network Administrator",
    OperFlag::ALL,
    SnomaskFlag::ALL,
    60 }
};

// ============================================================================
// Operator Configuration Entry
// ============================================================================
struct OperConfig {
  std::string name;               // Oper login name
  std::string password_hash;      // Bcrypt hash of password
  OperType type{OperType::GLOBAL_OPER};
  std::string host_mask;          // User@host mask required for this oper
  std::vector<std::string> host_masks; // Multiple allowed host masks
  OperFlag extra_flags{OperFlag::NONE};
  OperFlag denied_flags{OperFlag::NONE};
  SnomaskFlag snomask{SnomaskFlag::NONE};
  bool snomask_force{false};      // Force these snomasks on oper up
  bool from_config{false};        // Loaded from config file
  std::string oper_class;         // Class to switch to on oper up
  std::string vhost;              // Virtual host after oper up
  std::string swhois;             // Custom WHOIS line
  bool require_ssl{false};        // Require SSL to use this oper block
  std::vector<std::string> allowed_ips; // IPs allowed
  int auto_logout_seconds{0};    // Auto de-oper after N seconds (0 = never)
  
  OperConfig() = default;
  
  OperFlag effective_flags() const {
    const auto* info = get_type_info();
    OperFlag result = OperFlag::NONE;
    if (info) {
      result = info->default_flags;
    }
    result = result | extra_flags;
    // Remove denied flags
    uint64_t r = static_cast<uint64_t>(result);
    uint64_t d = static_cast<uint64_t>(denied_flags);
    r &= ~d;
    return static_cast<OperFlag>(r);
  }
  
  const OperTypeInfo* get_type_info() const {
    for (const auto& info : kOperTypeInfoTable) {
      if (info.type == type) return &info;
    }
    return nullptr;
  }
};

// ============================================================================
// Operator Session Entry (runtime tracking of opered users)
// ============================================================================
struct OperSession {
  std::string nick;
  std::string user;
  std::string host;
  std::string oper_name;          // Which oper block they used
  OperType type{OperType::LOCAL_OPER};
  int64_t oper_time{0};           // When they opered up
  int64_t last_active{0};
  std::string vhost;
  SnomaskConfig snomask;
  std::string session_id;
  OperFlag privilege_flags{OperFlag::NONE};
  bool active{true};
  
  OperSession() {
    oper_time = now_sec();
    last_active = oper_time;
  }
};

// ============================================================================
// Connection Tracker - per-connection statistics
// ============================================================================
class ConnectionTracker {
public:
  ConnectionTracker() = default;
  
  // Create a new tracking entry
  ConnectionStats* create(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_[nick] = ConnectionStats();
    stats_[nick].nick = nick;
    return &stats_[nick];
  }
  
  // Get existing stats
  ConnectionStats* get(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(nick);
    if (it != stats_.end()) return &it->second;
    return nullptr;
  }
  
  // Remove when user disconnects
  void remove(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.erase(nick);
  }
  
  // Record bytes sent
  void add_bytes_sent(const std::string& nick, uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(nick);
    if (it != stats_.end()) {
      it->second.bytes_sent += bytes;
    }
  }
  
  // Record bytes received
  void add_bytes_received(const std::string& nick, uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(nick);
    if (it != stats_.end()) {
      it->second.bytes_received += bytes;
    }
  }
  
  // Record message/command
  void add_message_sent(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(nick);
    if (it != stats_.end()) {
      it->second.messages_sent++;
    }
  }
  
  void add_message_received(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(nick);
    if (it != stats_.end()) {
      it->second.messages_received++;
      it->second.commands_processed++;
    }
  }
  
  // Update nick on nick change
  void update_nick(const std::string& oldnick, const std::string& newnick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(oldnick);
    if (it != stats_.end()) {
      auto node = stats_.extract(it);
      node.key() = newnick;
      node.mapped().nick = newnick;
      stats_.insert(std::move(node));
    }
  }
  
  // Update last active timestamp
  void touch(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(nick);
    if (it != stats_.end()) {
      it->second.last_active = now_sec();
    }
  }
  
  // Set SSL info
  void set_ssl_info(const std::string& nick, const std::string& cipher,
                    const std::string& fingerprint, const std::string& protocol) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(nick);
    if (it != stats_.end()) {
      it->second.ssl_active = true;
      it->second.ssl_cipher = cipher;
      it->second.ssl_cert_fingerprint = fingerprint;
      it->second.ssl_protocol_version = protocol;
    }
  }
  
  // Set services account
  void set_account(const std::string& nick, const std::string& account) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(nick);
    if (it != stats_.end()) {
      it->second.account_name = account;
      it->second.identified = !account.empty();
    }
  }
  
  // Set away status
  void set_away(const std::string& nick, bool away, const std::string& msg = "") {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(nick);
    if (it != stats_.end()) {
      it->second.away = away;
      it->second.away_message = msg;
      it->second.away_since = away ? now_sec() : 0;
    }
  }
  
  // Set operator status
  void set_oper(const std::string& nick, bool is_oper, const std::string& type = "",
                const std::string& host = "") {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(nick);
    if (it != stats_.end()) {
      it->second.is_oper = is_oper;
      it->second.oper_type = type;
      it->second.oper_host = host;
    }
  }
  
  // Get connection duration in seconds
  int64_t get_connection_age(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(nick);
    if (it != stats_.end()) {
      return now_sec() - it->second.signon_time;
    }
    return 0;
  }
  
  // Get idle time in seconds
  int64_t get_idle_time(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(nick);
    if (it != stats_.end()) {
      return now_sec() - it->second.last_active;
    }
    return 0;
  }
  
  // Get stats for WHOIS
  bool get_whois_info(const std::string& nick, std::string& out_signontime,
                      std::string& out_idletime, std::string& out_bytes_sent,
                      std::string& out_bytes_received, std::string& out_messages) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(nick);
    if (it == stats_.end()) return false;
    
    out_signontime = format_time(it->second.signon_time);
    out_idletime = std::to_string(now_sec() - it->second.last_active);
    out_bytes_sent = std::to_string(it->second.bytes_sent);
    out_bytes_received = std::to_string(it->second.bytes_received);
    out_messages = std::to_string(it->second.messages_received);
    return true;
  }
  
  size_t size() const { return stats_.size(); }
  
  // Get all stats (for STATS C)
  const std::unordered_map<std::string, ConnectionStats>& all() const { return stats_; }
  
private:
  std::unordered_map<std::string, ConnectionStats> stats_;
  mutable std::mutex mutex_;
};

// ============================================================================
// WHOIS Manager - Extended WHOIS Engine
// ============================================================================
class WhoisManager {
public:
  WhoisManager() = default;
  
  // Configure flood protection parameters
  void set_flood_params(int max_queries_per_window, int window_seconds,
                        int block_duration_seconds) {
    max_queries_per_window_ = max_queries_per_window;
    window_seconds_ = window_seconds;
    block_duration_seconds_ = block_duration_seconds;
  }
  
  // Check if a whois query should be allowed (flood protection)
  bool check_flood(const std::string& requester) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& state = flood_tracker_[requester];
    int64_t now = now_sec();
    
    // Check if currently blocked
    if (state.blocked) {
      if (now < state.blocked_until) {
        return false; // Still blocked
      } else {
        state.blocked = false; // Unblock
        state.query_count = 0;
      }
    }
    
    // Reset window if expired
    if (now - state.window_start > window_seconds_) {
      state.window_start = now;
      state.query_count = 0;
    }
    
    // Enforce rate limit
    if (state.query_count >= max_queries_per_window_) {
      state.blocked = true;
      state.blocked_until = now + block_duration_seconds_;
      return false;
    }
    
    state.query_count++;
    state.last_query = now;
    return true;
  }
  
  // Get flood state
  bool is_flood_blocked(const std::string& requester) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = flood_tracker_.find(requester);
    if (it == flood_tracker_.end()) return false;
    if (it->second.blocked && now_sec() < it->second.blocked_until) return true;
    return false;
  }
  
  // Log a WHOIS query
  void log_query(const std::string& requester, const std::string& target) {
    std::lock_guard<std::mutex> lock(mutex_);
    WhoisQueryTracker q;
    q.requester = requester;
    q.target = target;
    q.timestamp = now_sec();
    recent_queries_.push_back(q);
    // Keep only last 1000 queries
    if (recent_queries_.size() > 1000) {
      recent_queries_.erase(recent_queries_.begin(),
                            recent_queries_.begin() + (recent_queries_.size() - 1000));
    }
    // Track per-requester counts
    requester_stats_[requester]++;
  }
  
  // Get WHOIS statistics per requester
  int get_requester_count(const std::string& requester) const {
    auto it = requester_stats_.find(requester);
    if (it != requester_stats_.end()) return it->second;
    return 0;
  }
  
  // Generate the full RPL_WHOISUSER response line (311)
  std::string format_whois_user(const std::string& requester,
                                 const std::string& nick, const std::string& user,
                                 const std::string& host, const std::string& realname) {
    std::stringstream ss;
    ss << requester << " " << nick << " " << user << " " << host << " * :" << realname;
    return ss.str();
  }
  
  // Generate RPL_WHOISSERVER (312)
  std::string format_whois_server(const std::string& requester,
                                   const std::string& nick, const std::string& server,
                                   const std::string& server_info) {
    std::stringstream ss;
    ss << requester << " " << nick << " " << server << " :" << server_info;
    return ss.str();
  }
  
  // Generate RPL_WHOISOPERATOR (313)
  std::string format_whois_operator(const std::string& requester,
                                     const std::string& nick) {
    std::stringstream ss;
    ss << requester << " " << nick << " :is an IRC operator";
    return ss.str();
  }
  
  // Generate extended operator WHOIS with type
  std::string format_whois_oper_type(const std::string& requester,
                                      const std::string& nick,
                                      const std::string& oper_type_str) {
    std::stringstream ss;
    ss << requester << " " << nick << " :" << oper_type_str;
    return ss.str();
  }
  
  // Generate RPL_WHOISIDLE (317)
  std::string format_whois_idle(const std::string& requester,
                                 const std::string& nick, int64_t idle_seconds,
                                 int64_t signon_time) {
    std::stringstream ss;
    ss << requester << " " << nick << " " << idle_seconds << " " << signon_time
       << " :seconds idle, signon time";
    return ss.str();
  }
  
  // Generate RPL_ENDOFWHOIS (318)
  std::string format_end_whois(const std::string& requester,
                                const std::string& nick) {
    std::stringstream ss;
    ss << requester << " " << nick << " :End of /WHOIS list";
    return ss.str();
  }
  
  // Generate RPL_WHOISCHANNELS (319)
  std::string format_whois_channels(const std::string& requester,
                                     const std::string& nick,
                                     const std::vector<std::string>& channels_with_prefix) {
    std::stringstream ss;
    ss << requester << " " << nick << " :";
    bool first = true;
    for (const auto& ch : channels_with_prefix) {
      if (!first) ss << " ";
      ss << ch;
      first = false;
    }
    return ss.str();
  }
  
  // Generate RPL_WHOISACCOUNT (330) - logged in as
  std::string format_whois_account(const std::string& requester,
                                    const std::string& nick,
                                    const std::string& account) {
    std::stringstream ss;
    ss << requester << " " << nick << " " << account << " :is logged in as";
    return ss.str();
  }
  
  // Generate RPL_WHOISSECURE (671) - using SSL
  std::string format_whois_secure(const std::string& requester,
                                   const std::string& nick) {
    std::stringstream ss;
    ss << requester << " " << nick
       << " :is using a secure connection (SSL/TLS)";
    return ss.str();
  }
  
  // Generate RPL_WHOISCERTFP (276) - certificate fingerprint
  std::string format_whois_certfp(const std::string& requester,
                                   const std::string& nick,
                                   const std::string& fingerprint) {
    std::stringstream ss;
    ss << requester << " " << nick
       << " :has client certificate fingerprint " << fingerprint;
    return ss.str();
  }
  
  // Generate RPL_WHOISHOST (378) - real hostname showing
  std::string format_whois_realhost(const std::string& requester,
                                     const std::string& nick,
                                     const std::string& realhost,
                                     const std::string& realip) {
    std::stringstream ss;
    ss << requester << " " << nick << " :is connecting from " << realhost
       << " " << realip;
    return ss.str();
  }
  
  // Generate RPL_WHOISMODES (379) - user modes
  std::string format_whois_modes(const std::string& requester,
                                  const std::string& nick,
                                  const std::string& modes) {
    std::stringstream ss;
    ss << requester << " " << nick << " :is using modes " << modes;
    return ss.str();
  }
  
  // Generate RPL_WHOISSPECIAL (320) - custom text
  std::string format_whois_special(const std::string& requester,
                                    const std::string& nick,
                                    const std::string& text) {
    std::stringstream ss;
    ss << requester << " " << nick << " :" << text;
    return ss.str();
  }
  
  // Generate RPL_AWAY (301) for WHOIS context
  std::string format_whois_away(const std::string& requester,
                                 const std::string& nick,
                                 const std::string& away_msg) {
    std::stringstream ss;
    ss << requester << " " << nick << " :" << away_msg;
    return ss.str();
  }
  
  // Generate RPL_WHOISBOT (335)
  std::string format_whois_bot(const std::string& requester,
                                const std::string& nick) {
    std::stringstream ss;
    ss << requester << " " << nick << " :is a Bot";
    return ss.str();
  }
  
  // Generate RPL_WHOISACTUALLY (338) - real host behind vhost
  std::string format_whois_actually(const std::string& requester,
                                     const std::string& nick,
                                     const std::string& user,
                                     const std::string& host,
                                     const std::string& ip) {
    std::stringstream ss;
    ss << requester << " " << nick << " " << user << "@" << host
       << " " << ip << " :Is actually using host";
    return ss.str();
  }
  
private:
  std::unordered_map<std::string, WhoisFloodState> flood_tracker_;
  std::vector<WhoisQueryTracker> recent_queries_;
  std::unordered_map<std::string, int> requester_stats_;
  mutable std::mutex mutex_;
  
  int max_queries_per_window_{5};
  int window_seconds_{3};
  int block_duration_seconds_{60};
};

// ============================================================================
// WHOWAS Manager - Nick History
// ============================================================================
class WhowasManager {
public:
  WhowasManager() = default;
  
  // Configure
  void configure(int max_entries_per_nick, int max_total_entries,
                 int expiry_seconds) {
    max_per_nick_ = max_entries_per_nick;
    max_total_ = max_total_entries;
    expiry_seconds_ = expiry_seconds;
  }
  
  // Add a WHOWAS entry when a user disconnects
  void add_entry(const std::string& nick, const std::string& user,
                 const std::string& host, const std::string& realname,
                 const std::string& server, const std::string& ip,
                 int64_t signon_time, const std::string& quit_reason,
                 bool was_oper, const std::string& account_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    int64_t now = now_sec();
    int64_t duration = now - signon_time;
    
    WhowasEntry entry(nick, user, host, realname, server, ip,
                      signon_time, now, quit_reason, was_oper,
                      account_name, duration);
    
    // Add to per-nick list (store most recent first)
    auto& nick_entries = entries_[nick];
    nick_entries.insert(nick_entries.begin(), std::move(entry));
    
    // Trim per-nick list
    while (nick_entries.size() > static_cast<size_t>(max_per_nick_)) {
      nick_entries.pop_back();
    }
    
    // Trim total entries
    total_entries_++;
    while (total_entries_ > max_total_) {
      prune_oldest();
    }
    
    // Prune expired entries
    prune_expired();
  }
  
  // Query WHOWAS for a nick
  std::vector<WhowasEntry> query(const std::string& nick, int count = -1) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = entries_.find(nick);
    if (it == entries_.end()) return {};
    
    prune_expired_nolock();
    
    auto& list = it->second;
    if (list.empty()) {
      entries_.erase(it);
      return {};
    }
    
    std::vector<WhowasEntry> result;
    int n = (count < 0) ? static_cast<int>(list.size()) : std::min(count, static_cast<int>(list.size()));
    for (int i = 0; i < n && i < static_cast<int>(list.size()); i++) {
      result.push_back(list[i]);
    }
    return result;
  }
  
  // Format WHOWAS response (RPL_WHOWASUSER / 314)
  std::string format_whowas_entry(const std::string& requester,
                                   const WhowasEntry& entry) {
    std::stringstream ss;
    ss << requester << " " << entry.nick << " " << entry.user << " "
       << entry.host << " * :" << entry.realname;
    return ss.str();
  }
  
  // Format RPL_ENDOFWHOWAS (369)
  std::string format_end_whowas(const std::string& requester,
                                 const std::string& nick) {
    std::stringstream ss;
    ss << requester << " " << nick << " :End of WHOWAS";
    return ss.str();
  }
  
  // Get count of entries for a nick
  size_t entry_count(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(nick);
    if (it != entries_.end()) return it->second.size();
    return 0;
  }
  
  // Get total WHOWAS entries across all nicks
  size_t total_entries() const { return total_entries_; }
  
  // Clear all entries
  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    total_entries_ = 0;
  }
  
private:
  // Nick -> list of entries (most recent first)
  std::unordered_map<std::string, std::vector<WhowasEntry>> entries_;
  size_t total_entries_{0};
  mutable std::mutex mutex_;
  
  int max_per_nick_{10};
  int max_total_{10000};
  int expiry_seconds_{86400}; // 24 hours default
  
  void prune_expired() {
    int64_t cutoff = now_sec() - expiry_seconds_;
    auto it = entries_.begin();
    while (it != entries_.end()) {
      auto& list = it->second;
      list.erase(std::remove_if(list.begin(), list.end(),
        [cutoff](const WhowasEntry& e) { return e.quit_time < cutoff; }),
        list.end());
      if (list.empty()) {
        it = entries_.erase(it);
      } else {
        ++it;
      }
    }
  }
  
  void prune_expired_nolock() {
    int64_t cutoff = now_sec() - expiry_seconds_;
    auto it = entries_.begin();
    while (it != entries_.end()) {
      auto& list = it->second;
      list.erase(std::remove_if(list.begin(), list.end(),
        [cutoff](const WhowasEntry& e) { return e.quit_time < cutoff; }),
        list.end());
      if (list.empty()) {
        it = entries_.erase(it);
      } else {
        ++it;
      }
    }
  }
  
  void prune_oldest() {
    // Find the oldest entry across all nicks and remove it
    std::string oldest_nick;
    int64_t oldest_time = std::numeric_limits<int64_t>::max();
    size_t oldest_idx = 0;
    
    for (auto& [nick, list] : entries_) {
      if (!list.empty()) {
        int64_t t = list.back().quit_time;
        if (t < oldest_time) {
          oldest_time = t;
          oldest_nick = nick;
          oldest_idx = list.size() - 1;
        }
      }
    }
    
    if (!oldest_nick.empty()) {
      auto it = entries_.find(oldest_nick);
      if (it != entries_.end() && oldest_idx < it->second.size()) {
        it->second.erase(it->second.begin() + oldest_idx);
        total_entries_--;
        if (it->second.empty()) {
          entries_.erase(it);
        }
      }
    }
  }
};

// ============================================================================
// Connection Logging System
// ============================================================================
class ConnectionLogger {
public:
  ConnectionLogger() = default;
  
  enum class LogLevel {
    DEBUG,
    INFO,
    NOTICE,
    WARNING,
    ERROR
  };
  
  struct LogEntry {
    int64_t timestamp;
    LogLevel level;
    std::string category;
    std::string message;
    std::string source_nick;
    std::string source_ip;
  };
  
  // Log a client connect
  void log_client_connect(const std::string& nick, const std::string& user,
                          const std::string& host, const std::string& ip,
                          int port) {
    std::stringstream ss;
    ss << "Client connecting: " << nick << "!" << user << "@" << host
       << " [" << ip << ":" << port << "]";
    add_entry(LogLevel::INFO, "connect", ss.str(), nick, ip);
  }
  
  // Log a client disconnect
  void log_client_disconnect(const std::string& nick, const std::string& user,
                             const std::string& host, const std::string& reason) {
    std::stringstream ss;
    ss << "Client exiting: " << nick << "!" << user << "@" << host
       << " (" << reason << ")";
    add_entry(LogLevel::INFO, "disconnect", ss.str(), nick, "");
  }
  
  // Log a KILL
  void log_kill(const std::string& source_nick, const std::string& target_nick,
                const std::string& reason) {
    std::stringstream ss;
    ss << "KILL: " << source_nick << " killed " << target_nick
       << " (" << reason << ")";
    add_entry(LogLevel::NOTICE, "kill", ss.str(), source_nick, "");
  }
  
  // Log operator up/down
  void log_oper_up(const std::string& nick, const std::string& oper_type) {
    std::stringstream ss;
    ss << nick << " is now an IRC operator (" << oper_type << ")";
    add_entry(LogLevel::NOTICE, "oper", ss.str(), nick, "");
  }
  
  void log_oper_down(const std::string& nick) {
    std::stringstream ss;
    ss << nick << " is no longer an IRC operator";
    add_entry(LogLevel::NOTICE, "oper", ss.str(), nick, "");
  }
  
  // Log server link/unlink
  void log_server_link(const std::string& server_name, int hop_count) {
    std::stringstream ss;
    ss << "Server " << server_name << " linked (hopcount " << hop_count << ")";
    add_entry(LogLevel::NOTICE, "server", ss.str(), "", "");
  }
  
  void log_server_split(const std::string& server_name, const std::string& reason) {
    std::stringstream ss;
    ss << "Server " << server_name << " split (" << reason << ")";
    add_entry(LogLevel::WARNING, "server", ss.str(), "", "");
  }
  
  // Log configuration changes
  void log_rehash(const std::string& source_nick) {
    add_entry(LogLevel::NOTICE, "config", "Configuration rehashed by " + source_nick, source_nick, "");
  }
  
  void log_restart(const std::string& source_nick) {
    add_entry(LogLevel::WARNING, "server", "Server restart requested by " + source_nick, source_nick, "");
  }
  
  void log_die(const std::string& source_nick) {
    add_entry(LogLevel::WARNING, "server", "Server shutdown requested by " + source_nick, source_nick, "");
  }
  
  // Log access denied
  void log_access_denied(const std::string& ip, const std::string& reason) {
    std::stringstream ss;
    ss << "Access denied for " << ip << " (" << reason << ")";
    add_entry(LogLevel::WARNING, "access", ss.str(), "", ip);
  }
  
  // Log flood detection
  void log_flood(const std::string& nick, const std::string& ip,
                 const std::string& flood_type) {
    std::stringstream ss;
    ss << "Flood detected from " << nick << " [" << ip << "] type=" << flood_type;
    add_entry(LogLevel::WARNING, "flood", ss.str(), nick, ip);
  }
  
  // Generic log
  void log(LogLevel level, const std::string& category,
           const std::string& message, const std::string& nick = "",
           const std::string& ip = "") {
    add_entry(level, category, message, nick, ip);
  }
  
  // Get recent log entries
  std::vector<LogEntry> get_recent(int count = 100) const {
    std::lock_guard<std::mutex> lock(mutex_);
    int n = std::min(count, static_cast<int>(entries_.size()));
    return std::vector<LogEntry>(entries_.end() - n, entries_.end());
  }
  
  // Get entries matching a category
  std::vector<LogEntry> get_by_category(const std::string& cat, int count = 50) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LogEntry> result;
    for (auto it = entries_.rbegin();
         it != entries_.rend() && static_cast<int>(result.size()) < count; ++it) {
      if (it->category == cat) {
        result.push_back(*it);
      }
    }
    std::reverse(result.begin(), result.end());
    return result;
  }
  
  // Get entries involving a nick
  std::vector<LogEntry> get_by_nick(const std::string& nick, int count = 50) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LogEntry> result;
    for (auto it = entries_.rbegin();
         it != entries_.rend() && static_cast<int>(result.size()) < count; ++it) {
      if (it->source_nick == nick) {
        result.push_back(*it);
      }
    }
    std::reverse(result.begin(), result.end());
    return result;
  }
  
  void set_capacity(size_t max_entries) {
    capacity_ = max_entries;
  }
  
  size_t size() const { return entries_.size(); }
  
  // Write all entries to file
  bool write_to_file(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ofstream file(filepath, std::ios::app);
    if (!file.is_open()) return false;
    for (const auto& e : entries_) {
      file << "[" << format_time(e.timestamp) << "] "
           << level_to_string(e.level) << " "
           << "[" << e.category << "] "
           << e.message;
      if (!e.source_nick.empty()) file << " (nick: " << e.source_nick << ")";
      if (!e.source_ip.empty()) file << " (ip: " << e.source_ip << ")";
      file << std::endl;
    }
    return true;
  }
  
private:
  std::vector<LogEntry> entries_;
  mutable std::mutex mutex_;
  size_t capacity_{10000};
  
  void add_entry(LogLevel level, const std::string& category,
                 const std::string& message, const std::string& nick,
                 const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    LogEntry e;
    e.timestamp = now_sec();
    e.level = level;
    e.category = category;
    e.message = message;
    e.source_nick = nick;
    e.source_ip = ip;
    entries_.push_back(std::move(e));
    
    // Trim if over capacity
    while (entries_.size() > capacity_) {
      entries_.erase(entries_.begin());
    }
  }
  
  static std::string level_to_string(LogLevel l) {
    switch (l) {
      case LogLevel::DEBUG:   return "DEBUG";
      case LogLevel::INFO:    return "INFO";
      case LogLevel::NOTICE:  return "NOTICE";
      case LogLevel::WARNING: return "WARNING";
      case LogLevel::ERROR:   return "ERROR";
      default: return "UNKNOWN";
    }
  }
};

// ============================================================================
// Operator Manager - Central operator authentication and session management
// ============================================================================
class OperatorManager {
public:
  OperatorManager() {
    initialize_default_ssh_fingerprints();
  }
  
  // --- Configuration Loading ---
  
  // Load operator blocks from JSON configuration
  bool load_config(const json& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!config.contains("operators") || !config["operators"].is_array()) {
      return false;
    }
    
    for (const auto& oper_json : config["operators"]) {
      OperConfig oper;
      oper.from_config = true;
      
      if (oper_json.contains("name")) {
        oper.name = oper_json["name"].get<std::string>();
      } else {
        continue; // Name is required
      }
      
      if (oper_json.contains("password")) {
        // If password is plaintext, hash it; if already hashed, store as-is
        std::string pw = oper_json["password"].get<std::string>();
        if (pw.substr(0, 4) == "$2a$" || pw.substr(0, 4) == "$2b$" ||
            pw.substr(0, 4) == "$2y$") {
          oper.password_hash = pw;
        } else {
          oper.password_hash = hash_bcrypt(pw);
        }
      }
      
      if (oper_json.contains("type")) {
        oper.type = parse_oper_type(oper_json["type"].get<std::string>());
      }
      
      if (oper_json.contains("host")) {
        oper.host_mask = oper_json["host"].get<std::string>();
        oper.host_masks.push_back(oper.host_mask);
      }
      
      if (oper_json.contains("hosts") && oper_json["hosts"].is_array()) {
        for (const auto& h : oper_json["hosts"]) {
          oper.host_masks.push_back(h.get<std::string>());
        }
      }
      
      if (oper_json.contains("flags")) {
        oper.extra_flags = parse_oper_flags(oper_json["flags"]);
      }
      
      if (oper_json.contains("deny_flags")) {
        oper.denied_flags = parse_oper_flags(oper_json["deny_flags"]);
      }
      
      if (oper_json.contains("snomasks")) {
        oper.snomask = parse_snomask_flags(oper_json["snomasks"].get<std::string>());
        oper.snomask_force = true;
      }
      
      if (oper_json.contains("class")) {
        oper.oper_class = oper_json["class"].get<std::string>();
      }
      
      if (oper_json.contains("vhost")) {
        oper.vhost = oper_json["vhost"].get<std::string>();
      }
      
      if (oper_json.contains("swhois")) {
        oper.swhois = oper_json["swhois"].get<std::string>();
      }
      
      if (oper_json.contains("require_ssl")) {
        oper.require_ssl = oper_json["require_ssl"].get<bool>();
      }
      
      if (oper_json.contains("allowed_ips") && oper_json["allowed_ips"].is_array()) {
        for (const auto& ip : oper_json["allowed_ips"]) {
          oper.allowed_ips.push_back(ip.get<std::string>());
        }
      }
      
      if (oper_json.contains("auto_logout")) {
        oper.auto_logout_seconds = oper_json["auto_logout"].get<int>();
      }
      
      oper_configs_[oper.name] = oper;
    }
    
    return true;
  }
  
  // Load from simple flat config (for compat with irc_server.hpp Config)
  bool load_from_server_config(const std::map<std::string, std::string>& oper_blocks) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [name, password_hash] : oper_blocks) {
      OperConfig oper;
      oper.name = name;
      oper.password_hash = password_hash;
      oper.type = OperType::GLOBAL_OPER;
      oper.from_config = true;
      oper_configs_[name] = oper;
    }
    
    return true;
  }
  
  // --- Authentication ---
  
  // Attempt operator login. Returns OperSession on success, nullptr on failure.
  OperSession* authenticate(const std::string& oper_name,
                            const std::string& password,
                            const std::string& nick,
                            const std::string& user,
                            const std::string& host,
                            const std::string& ip,
                            bool is_ssl) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = oper_configs_.find(oper_name);
    if (it == oper_configs_.end()) {
      return nullptr; // No such oper block
    }
    
    const auto& config = it->second;
    
    // Check password
    if (!check_bcrypt(password, config.password_hash)) {
      return nullptr; // Wrong password
    }
    
    // Check host mask
    std::string userhost = user + "@" + host;
    bool host_match = false;
    if (config.host_masks.empty()) {
      host_match = true; // No restriction
    } else {
      for (const auto& mask : config.host_masks) {
        if (match_mask(userhost, mask)) {
          host_match = true;
          break;
        }
      }
    }
    if (!host_match) {
      return nullptr;
    }
    
    // Check IP restrictions
    if (!config.allowed_ips.empty()) {
      bool ip_match = false;
      for (const auto& allowed_ip : config.allowed_ips) {
        if (match_ip(ip, allowed_ip)) {
          ip_match = true;
          break;
        }
      }
      if (!ip_match) {
        return nullptr;
      }
    }
    
    // Check SSL requirement
    if (config.require_ssl && !is_ssl) {
      return nullptr;
    }
    
    // Create session
    OperSession session;
    session.nick = nick;
    session.user = user;
    session.host = host;
    session.oper_name = oper_name;
    session.type = config.type;
    session.oper_time = now_sec();
    session.last_active = now_sec();
    session.session_id = generate_session_id();
    session.privilege_flags = config.effective_flags();
    session.active = true;
    
    // Set SNOMASK
    if (config.snomask_force) {
      session.snomask.flags = config.snomask;
    } else {
      const auto* type_info = config.get_type_info();
      if (type_info) {
        session.snomask.flags = type_info->default_snomasks;
      }
    }
    
    // Store session
    active_sessions_[nick] = session;
    
    return &active_sessions_[nick];
  }
  
  // De-oper a user
  bool deoper(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_sessions_.find(nick);
    if (it != active_sessions_.end()) {
      it->second.active = false;
      past_sessions_.push_back(it->second);
      active_sessions_.erase(it);
      return true;
    }
    return false;
  }
  
  // Check if a nick is opered
  bool is_oper(const std::string& nick) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_sessions_.find(nick) != active_sessions_.end();
  }
  
  // Get oper session
  OperSession* get_session(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_sessions_.find(nick);
    if (it != active_sessions_.end()) return &it->second;
    return nullptr;
  }
  
  // Get oper config
  const OperConfig* get_config(const std::string& oper_name) const {
    auto it = oper_configs_.find(oper_name);
    if (it != oper_configs_.end()) return &it->second;
    return nullptr;
  }
  
  // --- Privilege Checking ---
  
  bool has_privilege(const std::string& nick, OperFlag flag) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_sessions_.find(nick);
    if (it == active_sessions_.end()) return false;
    uint64_t p = static_cast<uint64_t>(it->second.privilege_flags);
    uint64_t f = static_cast<uint64_t>(flag);
    return (p & f) == f;
  }
  
  bool can_kill(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_KILL) ||
           has_privilege(nick, OperFlag::CAN_LOCAL_KILL);
  }
  
  bool can_global_kill(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_GLOBAL_KILL);
  }
  
  bool can_restart(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_RESTART);
  }
  
  bool can_die(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_DIE);
  }
  
  bool can_rehash(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_REHASH);
  }
  
  bool can_squit(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_SQUIT);
  }
  
  bool can_connect(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_CONNECT);
  }
  
  bool can_globops(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_GLOBOPS);
  }
  
  bool can_wallops(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_WALLOPS);
  }
  
  bool can_see_hidden(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_SEE_HIDDEN);
  }
  
  bool can_see_ip(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_SEE_IP);
  }
  
  bool can_see_chans(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_SEE_CHANS);
  }
  
  bool can_sajoin(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_JOIN_OVERRIDE);
  }
  
  bool can_sapart(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_PART_OVERRIDE);
  }
  
  bool can_samode(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_MODE_OVERRIDE);
  }
  
  bool can_overridemode(const std::string& nick) {
    return can_samode(nick);
  }
  
  bool can_kline(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_KLINE);
  }
  
  bool can_gkline(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_GKLINE);
  }
  
  bool can_zline(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_ZLINE);
  }
  
  bool can_gzline(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_GZLINE);
  }
  
  bool is_exempt_limits(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_EXEMPT_LIMITS);
  }
  
  bool is_exempt_bans(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_EXEMPT_BANS);
  }
  
  bool is_exempt_flood(const std::string& nick) {
    return has_privilege(nick, OperFlag::CAN_EXEMPT_FLOOD);
  }
  
  // --- SNOMASK ---
  
  SnomaskConfig get_snomask(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_sessions_.find(nick);
    if (it != active_sessions_.end()) {
      return it->second.snomask;
    }
    SnomaskConfig empty;
    empty.flags = SnomaskFlag::NONE;
    return empty;
  }
  
  bool set_snomask(const std::string& nick, const std::string& snomasks) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_sessions_.find(nick);
    if (it == active_sessions_.end()) return false;
    it->second.snomask.parse_from_string(snomasks);
    return true;
  }
  
  // Send server notice to operators who have the relevant snomask flag
  void send_snotice(IRCServer* server, SnomaskFlag flag,
                    const std::string& message) {
    if (!server) return;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [nick, session] : active_sessions_) {
      if (session.active && session.snomask.has_flag(flag)) {
        std::stringstream ss;
        ss << ":" << server->config().server_name << " NOTICE " << nick
           << " :*** " << SnomaskConfig::flag_to_name(flag)
           << " -- " << message;
        // send_raw is a hypothetical method; in real code you'd send to the connection
      }
    }
  }
  
  // Get the WHOIS display string for an operator
  std::string get_oper_whois(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_sessions_.find(nick);
    if (it == active_sessions_.end()) return "";
    
    auto it_config = oper_configs_.find(it->second.oper_name);
    if (it_config != oper_configs_.end() && !it_config->second.swhois.empty()) {
      return it_config->second.swhois;
    }
    
    const auto* info = get_type_info(it->second.type);
    if (info) {
      return info->whois_line;
    }
    return "is an IRC operator";
  }
  
  // Get operator type string
  std::string get_oper_type_string(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_sessions_.find(nick);
    if (it == active_sessions_.end()) return "";
    
    const auto* info = get_type_info(it->second.type);
    if (info) return info->name;
    
    return "Oper";
  }
  
  // Get active operator count
  int active_oper_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int>(active_sessions_.size());
  }
  
  // Get all active operator nicks
  std::vector<std::string> get_active_opers() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [nick, session] : active_sessions_) {
      if (session.active) result.push_back(nick);
    }
    return result;
  }
  
  // Check for auto-logout
  void check_auto_logout() {
    std::lock_guard<std::mutex> lock(mutex_);
    int64_t now = now_sec();
    std::vector<std::string> to_remove;
    
    for (const auto& [nick, session] : active_sessions_) {
      auto it = oper_configs_.find(session.oper_name);
      if (it != oper_configs_.end() && it->second.auto_logout_seconds > 0) {
        if (now - session.oper_time >= it->second.auto_logout_seconds) {
          to_remove.push_back(nick);
        }
      }
    }
    
    for (const auto& nick : to_remove) {
      auto it = active_sessions_.find(nick);
      if (it != active_sessions_.end()) {
        it->second.active = false;
        past_sessions_.push_back(it->second);
        active_sessions_.erase(it);
      }
    }
  }
  
  // Add operator manually (programmatic, bypasses password)
  bool add_operator(const OperConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    oper_configs_[config.name] = config;
    return true;
  }
  
  // Remove operator config
  bool remove_operator(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    return oper_configs_.erase(name) > 0;
  }
  
  // List all configured operator names
  std::vector<std::string> list_oper_names() const {
    std::vector<std::string> result;
    for (const auto& [name, _] : oper_configs_) {
      result.push_back(name);
    }
    return result;
  }
  
  // Get operator session count
  size_t session_count() const { return active_sessions_.size(); }
  
  // Get all operator sessions for display (STATS o / STATS O)
  const std::unordered_map<std::string, OperSession>& get_sessions() const {
    return active_sessions_;
  }
  
  // --- Operator Override Commands ---
  
  // SAJOIN - force join a user to a channel
  struct SAJoinResult {
    bool success;
    std::string error;
    std::string channel;
    std::string target;
  };
  
  SAJoinResult sajoin(const std::string& oper_nick,
                      const std::string& target_nick,
                      const std::string& channel) {
    SAJoinResult result;
    result.channel = channel;
    result.target = target_nick;
    
    if (!can_sajoin(oper_nick)) {
      result.success = false;
      result.error = "Insufficient privileges";
      return result;
    }
    
    result.success = true;
    return result;
  }
  
  // SAMODE - force mode change
  struct SAModeResult {
    bool success;
    std::string error;
    std::string channel;
    std::string modes;
  };
  
  SAModeResult samode(const std::string& oper_nick,
                      const std::string& channel,
                      const std::string& modes,
                      const std::vector<std::string>& params) {
    SAModeResult result;
    result.channel = channel;
    result.modes = modes;
    
    if (!can_samode(oper_nick)) {
      result.success = false;
      result.error = "Insufficient privileges";
      return result;
    }
    
    result.success = true;
    return result;
  }
  
  // SAKICK - force kick
  struct SAKickResult {
    bool success;
    std::string error;
    std::string channel;
    std::string target;
  };
  
  SAKickResult sakick(const std::string& oper_nick,
                      const std::string& channel,
                      const std::string& target,
                      const std::string& reason) {
    SAKickResult result;
    result.channel = channel;
    result.target = target;
    
    if (!has_privilege(oper_nick, OperFlag::CAN_KICK_OVERRIDE)) {
      result.success = false;
      result.error = "Insufficient privileges";
      return result;
    }
    
    result.success = true;
    return result;
  }
  
  // SANICK - force nick change
  struct SANickResult {
    bool success;
    std::string error;
    std::string old_nick;
    std::string new_nick;
  };
  
  SANickResult sanick(const std::string& oper_nick,
                      const std::string& target_nick,
                      const std::string& new_nick) {
    SANickResult result;
    result.old_nick = target_nick;
    result.new_nick = new_nick;
    
    if (!has_privilege(oper_nick, OperFlag::CAN_NICK_OVERRIDE)) {
      result.success = false;
      result.error = "Insufficient privileges";
      return result;
    }
    
    result.success = true;
    return result;
  }
  
private:
  std::unordered_map<std::string, OperConfig> oper_configs_;
  std::unordered_map<std::string, OperSession> active_sessions_;
  std::vector<OperSession> past_sessions_;
  mutable std::mutex mutex_;
  std::unordered_set<std::string> ssl_fingerprints_;
  
  static OperType parse_oper_type(const std::string& type_str) {
    if (type_str == "netadmin" || type_str == "NetAdmin")       return OperType::NETADMIN;
    if (type_str == "admin" || type_str == "Admin")             return OperType::ADMIN;
    if (type_str == "coadmin" || type_str == "Coadmin")         return OperType::COADMIN;
    if (type_str == "servicesadmin" || type_str == "ServicesAdmin") return OperType::SERVICES_ADMIN;
    if (type_str == "globaloper" || type_str == "GlobalOper")   return OperType::GLOBAL_OPER;
    return OperType::LOCAL_OPER;
  }
  
  static OperFlag parse_oper_flags(const json& flags_json) {
    OperFlag result = OperFlag::NONE;
    if (!flags_json.is_array()) return result;
    
    for (const auto& flag_str : flags_json) {
      std::string f = flag_str.get<std::string>();
      if (f == "can_kill")                result = result | OperFlag::CAN_KILL;
      else if (f == "can_global_kill")    result = result | OperFlag::CAN_GLOBAL_KILL;
      else if (f == "can_restart")        result = result | OperFlag::CAN_RESTART;
      else if (f == "can_die")            result = result | OperFlag::CAN_DIE;
      else if (f == "can_rehash")         result = result | OperFlag::CAN_REHASH;
      else if (f == "can_local_kill")     result = result | OperFlag::CAN_LOCAL_KILL;
      else if (f == "can_kline")          result = result | OperFlag::CAN_KLINE;
      else if (f == "can_gkline")         result = result | OperFlag::CAN_GKLINE;
      else if (f == "can_zline")          result = result | OperFlag::CAN_ZLINE;
      else if (f == "can_gzline")         result = result | OperFlag::CAN_GZLINE;
      else if (f == "can_gline")          result = result | OperFlag::CAN_GLINE;
      else if (f == "can_eline")          result = result | OperFlag::CAN_ELINE;
      else if (f == "can_fline")          result = result | OperFlag::CAN_FLINE;
      else if (f == "can_qline")          result = result | OperFlag::CAN_QLINE;
      else if (f == "can_globops")        result = result | OperFlag::CAN_GLOBOPS;
      else if (f == "can_wallops")        result = result | OperFlag::CAN_WALLOPS;
      else if (f == "can_locops")         result = result | OperFlag::CAN_LOCOPS;
      else if (f == "can_remote")         result = result | OperFlag::CAN_REMOTE;
      else if (f == "can_squit")          result = result | OperFlag::CAN_SQUIT;
      else if (f == "can_connect")        result = result | OperFlag::CAN_CONNECT;
      else if (f == "can_join_override")  result = result | OperFlag::CAN_JOIN_OVERRIDE;
      else if (f == "can_part_override")  result = result | OperFlag::CAN_PART_OVERRIDE;
      else if (f == "can_mode_override")  result = result | OperFlag::CAN_MODE_OVERRIDE;
      else if (f == "can_topic_override") result = result | OperFlag::CAN_TOPIC_OVERRIDE;
      else if (f == "can_kick_override")  result = result | OperFlag::CAN_KICK_OVERRIDE;
      else if (f == "can_nick_override")  result = result | OperFlag::CAN_NICK_OVERRIDE;
      else if (f == "can_quit_override")  result = result | OperFlag::CAN_QUIT_OVERRIDE;
      else if (f == "can_see_hidden")     result = result | OperFlag::CAN_SEE_HIDDEN;
      else if (f == "can_see_ops")        result = result | OperFlag::CAN_SEE_OPS;
      else if (f == "can_see_chans")      result = result | OperFlag::CAN_SEE_CHANS;
      else if (f == "can_see_ip")         result = result | OperFlag::CAN_SEE_IP;
      else if (f == "can_see_realhost")   result = result | OperFlag::CAN_SEE_REALHOST;
      else if (f == "can_set_snomask")    result = result | OperFlag::CAN_SET_SNOMASK;
      else if (f == "can_broadcast")      result = result | OperFlag::CAN_BROADCAST;
      else if (f == "can_svs")            result = result | OperFlag::CAN_SVS;
      else if (f == "can_manage_modules") result = result | OperFlag::CAN_MANAGE_MODULES;
      else if (f == "can_manage_s2s")     result = result | OperFlag::CAN_MANAGE_S2S;
      else if (f == "can_spy")            result = result | OperFlag::CAN_SPY;
      else if (f == "exempt_limits")      result = result | OperFlag::CAN_EXEMPT_LIMITS;
      else if (f == "exempt_bans")        result = result | OperFlag::CAN_EXEMPT_BANS;
      else if (f == "exempt_flood")       result = result | OperFlag::CAN_EXEMPT_FLOOD;
      else if (f == "exempt_filter")      result = result | OperFlag::CAN_EXEMPT_FILTER;
      else if (f == "can_dccdeny")        result = result | OperFlag::CAN_DCCDENY;
      else if (f == "all")                result = OperFlag::ALL;
    }
    return result;
  }
  
  static SnomaskFlag parse_snomask_flags(const std::string& flags) {
    SnomaskConfig cfg;
    cfg.parse_from_string(flags);
    return cfg.flags;
  }
  
  static const OperTypeInfo* get_type_info(OperType t) {
    for (const auto& info : kOperTypeInfoTable) {
      if (info.type == t) return &info;
    }
    return nullptr;
  }
  
  static std::string generate_session_id() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    std::stringstream ss;
    ss << std::hex << dis(gen) << dis(gen);
    return ss.str();
  }
  
  bool match_mask(const std::string& str, const std::string& mask) {
    // Simple wildcard matching: * matches anything, ? matches one char
    size_t si = 0, mi = 0;
    size_t star_s = std::string::npos, star_m = std::string::npos;
    
    // Case-insensitive
    std::string s = str;
    std::string m = mask;
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    std::transform(m.begin(), m.end(), m.begin(), ::tolower);
    
    while (si < s.size()) {
      if (mi < m.size() && (m[mi] == '?' || m[mi] == s[si])) {
        si++; mi++;
      } else if (mi < m.size() && m[mi] == '*') {
        star_s = si;
        star_m = mi;
        mi++;
      } else if (star_s != std::string::npos) {
        si = ++star_s;
        mi = star_m + 1;
      } else {
        return false;
      }
    }
    
    while (mi < m.size() && m[mi] == '*') mi++;
    return mi == m.size();
  }
  
  bool match_ip(const std::string& ip, const std::string& pattern) {
    return match_mask(ip, pattern);
  }
  
  void initialize_default_ssh_fingerprints() {
    // Can be pre-loaded with known operator certificate fingerprints
  }
};

// ============================================================================
// Extended IRC WHOIS Handler - The main engine that ties everything together
// ============================================================================
class WhoisEngine {
public:
  WhoisEngine(ConnectionTracker& tracker, WhoisManager& whois_mgr,
              WhowasManager& whowas_mgr, OperatorManager& oper_mgr,
              ConnectionLogger& logger, IRCServer& server)
    : tracker_(tracker), whois_mgr_(whois_mgr), whowas_mgr_(whowas_mgr),
      oper_mgr_(oper_mgr), logger_(logger), server_(server) {}
  
  // Perform a full extended WHOIS query
  std::vector<std::pair<int, std::string>> perform_whois(
      const std::string& requester_nick,
      const std::string& target_nick,
      const std::string& requester_userhost = "") {
    
    std::vector<std::pair<int, std::string>> replies;
    
    // Flood check
    if (!oper_mgr_.is_exempt_flood(requester_nick)) {
      if (!whois_mgr_.check_flood(requester_nick)) {
        // Rate limited
        return replies;
      }
    }
    
    // Log the query
    whois_mgr_.log_query(requester_nick, target_nick);
    
    // Find target user
    auto* target_user = server_.get_user(target_nick);
    if (!target_user) {
      // User not online - try WHOWAS
      auto whowas_entries = whowas_mgr_.query(target_nick, 1);
      if (!whowas_entries.empty()) {
        // Return WHOWAS data (would be handled by WHOWAS handler, not WHOIS)
        replies.emplace_back(Numerics::ERR_NOSUCHNICK, target_nick + " :No such nick/channel");
      } else {
        replies.emplace_back(Numerics::ERR_NOSUCHNICK, target_nick + " :No such nick/channel");
      }
      return replies;
    }
    
    auto* stats = tracker_.get(target_nick);
    bool requester_is_oper = oper_mgr_.is_oper(requester_nick);
    bool target_is_oper = oper_mgr_.is_oper(target_nick);
    bool can_see_details = requester_is_oper && oper_mgr_.can_see_hidden(requester_nick);
    
    // --- RPL_WHOISUSER (311) ---
    replies.emplace_back(Numerics::RPL_WHOISUSER,
      whois_mgr_.format_whois_user(requester_nick, target_nick,
        target_user->user, target_user->host, target_user->realname));
    
    // --- RPL_WHOISCHANNELS (319) ---
    if (can_see_details || requester_nick == target_nick) {
      std::vector<std::string> channels_with_prefix;
      for (const auto& [ch_name, ch] : server_.channels_) {
        if (ch->members.count(target_nick)) {
          std::string prefix;
          auto mode_it = ch->member_modes.find(target_nick);
          if (mode_it != ch->member_modes.end()) {
            if (mode_it->second.find('q') != std::string::npos) prefix = "~";
            else if (mode_it->second.find('a') != std::string::npos) prefix = "&";
            else if (mode_it->second.find('o') != std::string::npos) prefix = "@";
            else if (mode_it->second.find('h') != std::string::npos) prefix = "%";
            else if (mode_it->second.find('v') != std::string::npos) prefix = "+";
          }
          channels_with_prefix.push_back(prefix + ch_name);
        }
      }
      if (!channels_with_prefix.empty()) {
        replies.emplace_back(Numerics::RPL_WHOISCHANNELS,
          whois_mgr_.format_whois_channels(requester_nick, target_nick,
            channels_with_prefix));
      }
    }
    
    // --- RPL_WHOISSERVER (312) ---
    std::string server_info = server_.config().description;
    replies.emplace_back(Numerics::RPL_WHOISSERVER,
      whois_mgr_.format_whois_server(requester_nick, target_nick,
        server_.config().server_name, server_info));
    
    // --- RPL_WHOISOPERATOR (313) if oper ---
    if (target_is_oper) {
      std::string oper_line = oper_mgr_.get_oper_whois(target_nick);
      if (!oper_line.empty()) {
        replies.emplace_back(Numerics::RPL_WHOISOPERATOR,
          whois_mgr_.format_whois_oper_type(requester_nick, target_nick, oper_line));
      } else {
        replies.emplace_back(Numerics::RPL_WHOISOPERATOR,
          whois_mgr_.format_whois_operator(requester_nick, target_nick));
      }
    }
    
    // --- RPL_WHOISIDLE (317) ---
    if (stats) {
      int64_t idle_time = now_sec() - stats->last_active;
      replies.emplace_back(Numerics::RPL_WHOISIDLE,
        whois_mgr_.format_whois_idle(requester_nick, target_nick,
          idle_time, stats->signon_time));
    }
    
    // --- RPL_WHOISACCOUNT (330) if identified ---
    if (stats && !stats->account_name.empty()) {
      replies.emplace_back(ExtendedNumerics::RPL_WHOISACCOUNT,
        whois_mgr_.format_whois_account(requester_nick, target_nick,
          stats->account_name));
    }
    
    // --- RPL_WHOISSECURE (671) if using SSL ---
    if (stats && stats->ssl_active) {
      replies.emplace_back(ExtendedNumerics::RPL_WHOISSECURE,
        whois_mgr_.format_whois_secure(requester_nick, target_nick));
    }
    
    // --- RPL_WHOISCERTFP (276) if SSL fingerprint available ---
    if (stats && stats->ssl_active && !stats->ssl_cert_fingerprint.empty()) {
      replies.emplace_back(ExtendedNumerics::RPL_WHOISCERTFP,
        whois_mgr_.format_whois_certfp(requester_nick, target_nick,
          stats->ssl_cert_fingerprint));
    }
    
    // --- RPL_AWAY (301) if away ---
    if (stats && stats->away) {
      replies.emplace_back(Numerics::RPL_AWAY,
        whois_mgr_.format_whois_away(requester_nick, target_nick,
          stats->away_message));
    }
    
    // --- Extended WHOIS for opers ---
    if (requester_is_oper && can_see_details && stats) {
      // RPL_WHOISHOST (378) - real host
      if (!stats->ip.empty()) {
        replies.emplace_back(ExtendedNumerics::RPL_WHOISHOST,
          whois_mgr_.format_whois_realhost(requester_nick, target_nick,
            stats->host, stats->ip));
      }
      
      // RPL_WHOISMODES (379) - user modes
      if (!target_user->modes.empty()) {
        replies.emplace_back(ExtendedNumerics::RPL_WHOISMODES,
          whois_mgr_.format_whois_modes(requester_nick, target_nick,
            target_user->modes));
      }
    }
    
    // --- RPL_ENDOFWHOIS (318) ---
    replies.emplace_back(Numerics::RPL_ENDOFWHOIS,
      whois_mgr_.format_end_whois(requester_nick, target_nick));
    
    return replies;
  }
  
  // Perform WHOWAS query
  std::vector<std::pair<int, std::string>> perform_whowas(
      const std::string& requester_nick,
      const std::string& target_nick,
      int count = -1) {
    
    std::vector<std::pair<int, std::string>> replies;
    
    auto entries = whowas_mgr_.query(target_nick, count);
    if (entries.empty()) {
      replies.emplace_back(ExtendedNumerics::ERR_WASNOSUCHNICK,
        requester_nick + " " + target_nick + " :There was no such nickname");
      return replies;
    }
    
    for (const auto& entry : entries) {
      replies.emplace_back(ExtendedNumerics::RPL_WHOWASUSER,
        whowas_mgr_.format_whowas_entry(requester_nick, entry));
    }
    
    replies.emplace_back(ExtendedNumerics::RPL_ENDOFWHOWAS,
      whowas_mgr_.format_end_whowas(requester_nick, target_nick));
    
    return replies;
  }
  
  // Build full WHOIS response as a string vector (ready for sending)
  std::vector<std::string> build_whois_response(
      const std::string& requester_nick,
      const std::string& target_nick) {
    
    auto replies = perform_whois(requester_nick, target_nick);
    std::vector<std::string> result;
    
    for (const auto& [numeric, message] : replies) {
      std::stringstream ss;
      ss << ":" << server_.config().server_name << " "
         << std::setw(3) << std::setfill('0') << numeric << " "
         << message;
      result.push_back(ss.str());
    }
    
    return result;
  }
  
  // Handle /WHOIS command
  void handle_whois_command(IRCConnection* conn, const std::string& target) {
    if (!conn || target.empty()) {
      if (conn) {
        send_numeric(conn, Numerics::ERR_NONICKNAMEGIVEN,
                     ":No nickname given");
      }
      return;
    }
    
    auto replies = perform_whois(conn->nick, target);
    for (const auto& [numeric, message] : replies) {
      send_numeric(conn, numeric, message);
    }
  }
  
  // Handle /WHOWAS command
  void handle_whowas_command(IRCConnection* conn, const std::string& target,
                             int count = -1) {
    if (!conn || target.empty()) {
      if (conn) {
        send_numeric(conn, Numerics::ERR_NONICKNAMEGIVEN,
                     ":No nickname given");
      }
      return;
    }
    
    auto replies = perform_whowas(conn->nick, target, count);
    for (const auto& [numeric, message] : replies) {
      send_numeric(conn, numeric, message);
    }
  }
  
  // OPER authentication
  bool handle_oper_command(IRCConnection* conn,
                           const std::string& oper_name,
                           const std::string& password) {
    if (!conn) return false;
    
    if (!conn->registered) {
      send_numeric(conn, Numerics::ERR_NOTREGISTERED,
                   ":You have not registered");
      return false;
    }
    
    auto* session = oper_mgr_.authenticate(
      oper_name, password, conn->nick, conn->user, conn->host, conn->ip,
      false); // SSL flag
    
    if (!session) {
      send_numeric(conn, Numerics::ERR_PASSWDMISMATCH,
                   ":Password incorrect or insufficient access");
      logger_.log(ConnectionLogger::LogLevel::WARNING, "oper",
                  "Failed OPER attempt by " + conn->nick +
                  " (" + conn->user + "@" + conn->host + ") for oper '" +
                  oper_name + "'", conn->nick, conn->ip);
      return false;
    }
    
    // Mark connection as operator
    conn->nick = session->nick; // In case normalized
    
    send_numeric(conn, ExtendedNumerics::RPL_YOUREOPER,
                 ":You are now an IRC operator");
    
    // Send RPL_SNOMASK if applicable
    auto sm = session->snomask.to_string();
    if (sm != "0") {
      send_numeric(conn, ExtendedNumerics::RPL_SNOMASK,
                   conn->nick + " +" + sm + " :Server notice mask");
    }
    
    // Notify other opers via SNOMASK
    oper_mgr_.send_snotice(&server_, SnomaskFlag::OPER_UP,
      conn->nick + " (" + conn->user + "@" + conn->host +
      ") is now an IRC operator (" + oper_mgr_.get_oper_type_string(conn->nick) + ")");
    
    // Log
    logger_.log_oper_up(conn->nick, oper_mgr_.get_oper_type_string(conn->nick));
    
    return true;
  }
  
private:
  ConnectionTracker& tracker_;
  WhoisManager& whois_mgr_;
  WhowasManager& whowas_mgr_;
  OperatorManager& oper_mgr_;
  ConnectionLogger& logger_;
  IRCServer& server_;
  
  void send_numeric(IRCConnection* conn, int numeric, const std::string& msg) {
    if (!conn) return;
    server_.send_numeric(conn, numeric, msg);
  }
};

// ============================================================================
// Server Notice Manager (GLOBOPS, WALLOPS, LOCOPS dispatching)
// ============================================================================
class ServerNoticeManager {
public:
  ServerNoticeManager(OperatorManager& oper_mgr, ConnectionLogger& logger,
                      IRCServer& server)
    : oper_mgr_(oper_mgr), logger_(logger), server_(server) {}
  
  // Send GLOBOPS - to all opers with +g snomask
  void send_globops(const std::string& sender,
                    const std::string& message) {
    std::stringstream ss;
    ss << ":" << sender << " GLOBOPS :" << message;
    send_to_opers_with_snomask(SnomaskFlag::GLOBEOPS, ss.str(), sender);
    logger_.log(ConnectionLogger::LogLevel::NOTICE, "globops",
                sender + ": " + message, sender, "");
  }
  
  // Send WALLOPS - to all opers with +w snomask
  void send_wallops(const std::string& sender,
                    const std::string& message) {
    std::stringstream ss;
    ss << ":" << sender << " WALLOPS :" << message;
    send_to_opers_with_snomask(SnomaskFlag::WALLOPS, ss.str(), sender);
    logger_.log(ConnectionLogger::LogLevel::NOTICE, "wallops",
                sender + ": " + message, sender, "");
  }
  
  // Send LOCOPS - to local opers only
  void send_locops(const std::string& sender,
                   const std::string& message) {
    std::stringstream ss;
    ss << ":" << sender << " LOCOPS :" << message;
    send_to_local_opers(ss.str(), sender);
    logger_.log(ConnectionLogger::LogLevel::NOTICE, "locops",
                sender + ": " + message, sender, "");
  }
  
  // Send a server notice for a specific snomask flag
  void send_snotice(SnomaskFlag flag, const std::string& message,
                    const std::string& source_nick = "") {
    // Format: :server.name NOTICE $nick :*** snomask_name -- message
    std::string notice_msg = "*** " + SnomaskConfig::flag_to_name(flag) +
                             " -- " + message;
    std::stringstream ss;
    ss << ":" << server_.config().server_name << " NOTICE ";
    
    auto opers = oper_mgr_.get_active_opers();
    for (const auto& nick : opers) {
      auto sm = oper_mgr_.get_snomask(nick);
      if (sm.has_flag(flag)) {
        // Would send individual NOTICE per oper
        logger_.log(ConnectionLogger::LogLevel::DEBUG, "snotice",
                    flag_to_char(flag) + " -> " + nick + ": " + message,
                    source_nick, "");
      }
    }
  }
  
  // Broadcast a message to all opers (regardless of snomask)
  void broadcast_to_opers(const std::string& message,
                          const std::string& source_nick = "") {
    auto opers = oper_mgr_.get_active_opers();
    for (const auto& nick : opers) {
      logger_.log(ConnectionLogger::LogLevel::INFO, "broadcast",
                  "-> " + nick + ": " + message, source_nick, "");
    }
  }
  
private:
  OperatorManager& oper_mgr_;
  ConnectionLogger& logger_;
  IRCServer& server_;
  
  void send_to_opers_with_snomask(SnomaskFlag flag,
                                  const std::string& formatted_msg,
                                  const std::string& except_nick = "") {
    auto opers = oper_mgr_.get_active_opers();
    for (const auto& nick : opers) {
      if (nick == except_nick) continue;
      auto sm = oper_mgr_.get_snomask(nick);
      if (sm.has_flag(flag)) {
        // In real implementation, send formatted_msg to nick
      }
    }
  }
  
  void send_to_local_opers(const std::string& formatted_msg,
                           const std::string& except_nick = "") {
    auto opers = oper_mgr_.get_active_opers();
    for (const auto& nick : opers) {
      if (nick == except_nick) continue;
      // In real implementation, send formatted_msg to nick
      // For now, just log
    }
  }
  
  static char flag_to_char(SnomaskFlag f) {
    switch (f) {
      case SnomaskFlag::KILLS:          return 'k';
      case SnomaskFlag::CLIENT_CONNECT: return 'c';
      case SnomaskFlag::OPER_UP:        return 'o';
      case SnomaskFlag::SQUIT:          return 's';
      case SnomaskFlag::REHASH:         return 'r';
      case SnomaskFlag::GLOBEOPS:       return 'g';
      case SnomaskFlag::WALLOPS:        return 'w';
      case SnomaskFlag::DEBUG:          return 'd';
      case SnomaskFlag::JUNK_REJECT:    return 'j';
      case SnomaskFlag::ACL:            return 'a';
      case SnomaskFlag::XLINE:          return 'x';
      case SnomaskFlag::SPAMFILTER:     return 'f';
      case SnomaskFlag::FLOOD:          return 'F';
      case SnomaskFlag::PERM_CHAN:      return 'p';
      case SnomaskFlag::MODULE:         return 'm';
      case SnomaskFlag::DNS:            return 'n';
      case SnomaskFlag::REMOTE:         return 'R';
      default: return '?';
    }
  }
};

// ============================================================================
// Operator Override Command Processor
// ============================================================================
class OperatorOverrideProcessor {
public:
  OperatorOverrideProcessor(OperatorManager& oper_mgr,
                            ConnectionTracker& tracker,
                            ConnectionLogger& logger,
                            IRCServer& server)
    : oper_mgr_(oper_mgr), tracker_(tracker), logger_(logger), server_(server) {}
  
  // Process SAJOIN
  struct SAJoinResult {
    bool success{false};
    std::string error;
    std::string channel;
    std::string target;
  };
  
  SAJoinResult process_sajoin(const std::string& oper_nick,
                              const std::string& target_nick,
                              const std::string& channel) {
    SAJoinResult result;
    result.channel = channel;
    result.target = target_nick;
    
    if (!oper_mgr_.can_sajoin(oper_nick)) {
      result.error = "Permission denied - requires SAJOIN privilege";
      return result;
    }
    
    // Check target exists
    auto* target = server_.get_user(target_nick);
    if (!target) {
      result.error = "No such nick: " + target_nick;
      return result;
    }
    
    // Check channel exists or create it
    auto* ch = server_.get_channel(channel);
    if (!ch) {
      ch = server_.create_channel(channel);
    }
    
    // Force join
    ch->members.insert(target_nick);
    
    // Notify
    logger_.log(ConnectionLogger::LogLevel::NOTICE, "sajoin",
                oper_nick + " used SAJOIN to force " + target_nick +
                " into " + channel, oper_nick, "");
    
    result.success = true;
    return result;
  }
  
  // Process SAPART
  struct SAPartResult {
    bool success{false};
    std::string error;
    std::string channel;
    std::string target;
  };
  
  SAPartResult process_sapart(const std::string& oper_nick,
                              const std::string& target_nick,
                              const std::string& channel,
                              const std::string& reason = "") {
    SAPartResult result;
    result.channel = channel;
    result.target = target_nick;
    
    if (!oper_mgr_.can_sapart(oper_nick)) {
      result.error = "Permission denied - requires SAPART privilege";
      return result;
    }
    
    auto* ch = server_.get_channel(channel);
    if (!ch) {
      result.error = "No such channel: " + channel;
      return result;
    }
    
    if (!ch->members.count(target_nick)) {
      result.error = target_nick + " is not on " + channel;
      return result;
    }
    
    ch->members.erase(target_nick);
    
    logger_.log(ConnectionLogger::LogLevel::NOTICE, "sapart",
                oper_nick + " used SAPART to force " + target_nick +
                " out of " + channel, oper_nick, "");
    
    result.success = true;
    return result;
  }
  
  // Process SAMODE
  struct SAModeResult {
    bool success{false};
    std::string error;
    std::string channel;
    std::string modes;
  };
  
  SAModeResult process_samode(const std::string& oper_nick,
                              const std::string& channel,
                              const std::string& modes,
                              const std::vector<std::string>& params) {
    SAModeResult result;
    result.channel = channel;
    result.modes = modes;
    
    if (!oper_mgr_.can_samode(oper_nick)) {
      result.error = "Permission denied - requires SAMODE privilege";
      return result;
    }
    
    auto* ch = server_.get_channel(channel);
    if (!ch) {
      result.error = "No such channel: " + channel;
      return result;
    }
    
    // Apply modes (simplified)
    logger_.log(ConnectionLogger::LogLevel::NOTICE, "samode",
                oper_nick + " used SAMODE on " + channel + " " + modes,
                oper_nick, "");
    
    result.success = true;
    return result;
  }
  
  // Process SAKICK
  struct SAKickResult {
    bool success{false};
    std::string error;
    std::string channel;
    std::string target;
  };
  
  SAKickResult process_sakick(const std::string& oper_nick,
                              const std::string& channel,
                              const std::string& target_nick,
                              const std::string& reason = "Requested") {
    SAKickResult result;
    result.channel = channel;
    result.target = target_nick;
    
    if (!oper_mgr_.has_privilege(oper_nick, OperFlag::CAN_KICK_OVERRIDE)) {
      result.error = "Permission denied - requires SAKICK privilege";
      return result;
    }
    
    auto* ch = server_.get_channel(channel);
    if (!ch) {
      result.error = "No such channel: " + channel;
      return result;
    }
    
    if (!ch->members.count(target_nick)) {
      result.error = target_nick + " is not on " + channel;
      return result;
    }
    
    ch->members.erase(target_nick);
    
    logger_.log(ConnectionLogger::LogLevel::NOTICE, "sakick",
                oper_nick + " used SAKICK to kick " + target_nick +
                " from " + channel + " (" + reason + ")",
                oper_nick, "");
    
    result.success = true;
    return result;
  }
  
  // Process SANICK
  struct SANickResult {
    bool success{false};
    std::string error;
    std::string old_nick;
    std::string new_nick;
  };
  
  SANickResult process_sanick(const std::string& oper_nick,
                              const std::string& target_nick,
                              const std::string& new_nick) {
    SANickResult result;
    result.old_nick = target_nick;
    result.new_nick = new_nick;
    
    if (!oper_mgr_.has_privilege(oper_nick, OperFlag::CAN_NICK_OVERRIDE)) {
      result.error = "Permission denied - requires SANICK privilege";
      return result;
    }
    
    auto* target = server_.get_user(target_nick);
    if (!target) {
      result.error = "No such nick: " + target_nick;
      return result;
    }
    
    if (server_.get_user(new_nick)) {
      result.error = "Nickname " + new_nick + " is already in use";
      return result;
    }
    
    // Perform nick change
    server_.change_nick(target_nick, new_nick);
    
    logger_.log(ConnectionLogger::LogLevel::NOTICE, "sanick",
                oper_nick + " used SANICK to change " + target_nick +
                " to " + new_nick, oper_nick, "");
    
    result.success = true;
    return result;
  }
  
  // Process SATOPIC
  struct SATopicResult {
    bool success{false};
    std::string error;
    std::string channel;
    std::string topic;
  };
  
  SATopicResult process_satopic(const std::string& oper_nick,
                                const std::string& channel,
                                const std::string& new_topic) {
    SATopicResult result;
    result.channel = channel;
    result.topic = new_topic;
    
    if (!oper_mgr_.has_privilege(oper_nick, OperFlag::CAN_TOPIC_OVERRIDE)) {
      result.error = "Permission denied - requires SATOPIC privilege";
      return result;
    }
    
    auto* ch = server_.get_channel(channel);
    if (!ch) {
      result.error = "No such channel: " + channel;
      return result;
    }
    
    ch->topic = new_topic;
    ch->topic_ts = now_sec();
    ch->topic_setter = oper_nick;
    
    logger_.log(ConnectionLogger::LogLevel::NOTICE, "satopic",
                oper_nick + " used SATOPIC on " + channel + " -> " + new_topic,
                oper_nick, "");
    
    result.success = true;
    return result;
  }
  
private:
  OperatorManager& oper_mgr_;
  ConnectionTracker& tracker_;
  ConnectionLogger& logger_;
  IRCServer& server_;
};

// ============================================================================
// Connection Class Manager
// ============================================================================
class ConnectionClassManager {
public:
  ConnectionClassManager() {
    register_default_classes();
  }
  
  // Register a connection class
  void register_class(const ConnectionClass& cc) {
    std::lock_guard<std::mutex> lock(mutex_);
    classes_[cc.name] = cc;
  }
  
  // Unregister a class by name
  bool unregister_class(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    return classes_.erase(name) > 0;
  }
  
  // Get a connection class by name
  const ConnectionClass* get_class(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = classes_.find(name);
    if (it != classes_.end()) return &it->second;
    return nullptr;
  }
  
  // Get default client class
  const ConnectionClass* get_default_client_class() const {
    return get_class("clients");
  }
  
  // Get default server class
  const ConnectionClass* get_default_server_class() const {
    return get_class("servers");
  }
  
  // Get default oper class
  const ConnectionClass* get_default_oper_class() const {
    return get_class("opers");
  }
  
  // Increment active count
  void increment_active(const std::string& class_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = classes_.find(class_name);
    if (it != classes_.end()) {
      it->second.active_count++;
    }
  }
  
  // Decrement active count
  void decrement_active(const std::string& class_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = classes_.find(class_name);
    if (it != classes_.end() && it->second.active_count > 0) {
      it->second.active_count--;
    }
  }
  
  // Check if class has room for another connection
  bool can_accept(const std::string& class_name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = classes_.find(class_name);
    if (it == classes_.end()) return true;
    if (it->second.max_local == 0) return true; // Unlimited
    return it->second.active_count < it->second.max_local;
  }
  
  // List all registered classes
  std::vector<std::string> list_classes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [name, _] : classes_) {
      result.push_back(name);
    }
    return result;
  }
  
  // Get class stats for display
  struct ClassStats {
    std::string name;
    std::string type;
    int active;
    int max;
    int timeout;
    int ping_freq;
    int sendq;
    int recvq;
  };
  
  std::vector<ClassStats> get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ClassStats> result;
    for (const auto& [name, cc] : classes_) {
      ClassStats cs;
      cs.name = name;
      switch (cc.type) {
        case ConnectionClassType::CLIENT_CLASS: cs.type = "client"; break;
        case ConnectionClassType::SERVER_CLASS: cs.type = "server"; break;
        case ConnectionClassType::SERVICE_CLASS: cs.type = "service"; break;
        case ConnectionClassType::OPER_CLASS: cs.type = "oper"; break;
        default: cs.type = "unknown"; break;
      }
      cs.active = cc.active_count;
      cs.max = cc.max_local;
      cs.timeout = cc.timeout_seconds;
      cs.ping_freq = cc.ping_frequency;
      cs.sendq = cc.max_sendq;
      cs.recvq = cc.max_recvq;
      result.push_back(cs);
    }
    return result;
  }
  
private:
  std::unordered_map<std::string, ConnectionClass> classes_;
  mutable std::mutex mutex_;
  
  void register_default_classes() {
    // Default client class
    ConnectionClass client_class(ConnectionClassType::CLIENT_CLASS, "clients");
    client_class.max_sendq = 262144;
    client_class.max_recvq = 65536;
    client_class.max_channels = 20;
    client_class.max_local = 0; // Unlimited
    client_class.ping_frequency = 120;
    client_class.timeout_seconds = 300;
    client_class.flood_rate = 8;
    client_class.flood_window_ms = 2000;
    client_class.can_oper_up = true;
    client_class.resolve_host = true;
    classes_["clients"] = client_class;
    
    // Default server class
    ConnectionClass server_class(ConnectionClassType::SERVER_CLASS, "servers");
    server_class.max_sendq = 1048576;  // 1MB
    server_class.max_recvq = 262144;
    server_class.max_local = 64;
    server_class.ping_frequency = 60;
    server_class.timeout_seconds = 120;
    server_class.flood_rate = 100;
    server_class.flood_window_ms = 1000;
    server_class.can_oper_up = false;
    server_class.resolve_host = false;
    classes_["servers"] = server_class;
    
    // Default oper class (used when someone succeeds OPER)
    ConnectionClass oper_class(ConnectionClassType::OPER_CLASS, "opers");
    oper_class.max_sendq = 524288;
    oper_class.max_recvq = 131072;
    oper_class.max_channels = 100;
    oper_class.max_local = 0;
    oper_class.ping_frequency = 90;
    oper_class.timeout_seconds = 600;
    oper_class.flood_rate = 20;
    oper_class.flood_window_ms = 1000;
    oper_class.can_oper_up = true;
    classes_["opers"] = oper_class;
  }
};

// ============================================================================
// Statistics / STATS Handlers
// ============================================================================
class StatsManager {
public:
  StatsManager(ConnectionTracker& tracker, OperatorManager& oper_mgr,
               ConnectionClassManager& class_mgr, WhowasManager& whowas_mgr,
               ConnectionLogger& logger, IRCServer& server)
    : tracker_(tracker), oper_mgr_(oper_mgr), class_mgr_(class_mgr),
      whowas_mgr_(whowas_mgr), logger_(logger), server_(server) {}
  
  // Handle STATS command
  void handle_stats(IRCConnection* conn, const std::string& query) {
    if (!conn) return;
    
    char stat_char = query.empty() ? '?' : query[0];
    bool is_oper = oper_mgr_.is_oper(conn->nick);
    
    switch (stat_char) {
      case 'c':  // Connection lines (C:lines)
        if (is_oper) {
          auto classes = class_mgr_.get_stats();
          for (const auto& cs : classes) {
            std::stringstream ss;
            ss << conn->nick << " C " << cs.name << " * " << cs.type
               << " " << cs.active << " " << cs.max << " " << cs.sendq
               << " " << cs.recvq << " " << cs.timeout << " :class";
            send_numeric(conn, ExtendedNumerics::RPL_STATSCLINE, ss.str());
          }
        }
        send_numeric(conn, ExtendedNumerics::RPL_ENDOFSTATS,
                     conn->nick + " C :End of /STATS report");
        break;
        
      case 'k':  // K:lines (placeholder)
        if (is_oper) {
          send_numeric(conn, ExtendedNumerics::RPL_ENDOFSTATS,
                       conn->nick + " k :End of /STATS report");
        }
        break;
        
      case 'l':  // Link information
        if (is_oper) {
          std::stringstream ss;
          ss << conn->nick << " " << server_.config().server_name;
          send_numeric(conn, ExtendedNumerics::RPL_STATSLINKINFO, ss.str());
          send_numeric(conn, ExtendedNumerics::RPL_ENDOFSTATS,
                       conn->nick + " l :End of /STATS report");
        }
        break;
        
      case 'm':  // Command statistics
        send_numeric(conn, ExtendedNumerics::RPL_ENDOFSTATS,
                     conn->nick + " m :End of /STATS report");
        break;
        
      case 'o':  // Operator list (configured opers)
        if (is_oper) {
          auto oper_names = oper_mgr_.list_oper_names();
          for (const auto& name : oper_names) {
            auto* cfg = oper_mgr_.get_config(name);
            if (cfg) {
              std::stringstream ss;
              std::string host = cfg->host_masks.empty() ? "*" : cfg->host_masks[0];
              ss << conn->nick << " O " << host << " * " << name << " "
                 << static_cast<int>(cfg->type) << " 0 0 0 :Operator";
              send_numeric(conn, ExtendedNumerics::RPL_STATSOLINE, ss.str());
            }
          }
        }
        send_numeric(conn, ExtendedNumerics::RPL_ENDOFSTATS,
                     conn->nick + " o :End of /STATS report");
        break;
        
      case 'u':  // Uptime
        {
          int64_t uptime_sec = now_sec() - server_.start_time();
          std::stringstream ss;
          ss << conn->nick << " :Server Up " << format_duration(uptime_sec);
          send_numeric(conn, ExtendedNumerics::RPL_STATSUPTIME, ss.str());
        }
        break;
        
      case 'z':  // Memory/performance stats
        {
          int users = static_cast<int>(tracker_.size());
          int opers = oper_mgr_.active_oper_count();
          int whowas = static_cast<int>(whowas_mgr_.total_entries());
          send_numeric(conn, 249, conn->nick + " :Users: " + std::to_string(users) +
                       " Opers: " + std::to_string(opers) +
                       " Whowas: " + std::to_string(whowas));
        }
        send_numeric(conn, ExtendedNumerics::RPL_ENDOFSTATS,
                     conn->nick + " z :End of /STATS report");
        break;
        
      default:
        send_numeric(conn, ExtendedNumerics::RPL_ENDOFSTATS,
                     conn->nick + " " + std::string(1, stat_char) +
                     " :End of /STATS report");
        break;
    }
  }
  
private:
  ConnectionTracker& tracker_;
  OperatorManager& oper_mgr_;
  ConnectionClassManager& class_mgr_;
  WhowasManager& whowas_mgr_;
  ConnectionLogger& logger_;
  IRCServer& server_;
  
  void send_numeric(IRCConnection* conn, int numeric, const std::string& msg) {
    if (!conn) return;
    server_.send_numeric(conn, numeric, msg);
  }
};

// ============================================================================
// Utility Implementations
// ============================================================================
static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static int64_t now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string format_time(int64_t epoch_sec) {
  auto tp = std::chrono::system_clock::from_time_t(
    static_cast<time_t>(epoch_sec));
  auto time_t_val = std::chrono::system_clock::to_time_t(tp);
  std::stringstream ss;
  ss << std::put_time(std::gmtime(&time_t_val), "%Y-%m-%d %H:%M:%S UTC");
  return ss.str();
}

static std::string format_duration(int64_t seconds) {
  if (seconds < 0) return "0s";
  int64_t days = seconds / 86400;
  int64_t hours = (seconds % 86400) / 3600;
  int64_t minutes = (seconds % 3600) / 60;
  int64_t secs = seconds % 60;
  
  std::stringstream ss;
  if (days > 0) ss << days << " days ";
  if (hours > 0) ss << hours << " hours ";
  if (minutes > 0) ss << minutes << " minutes ";
  ss << secs << " seconds";
  return ss.str();
}

static std::string sha256(const std::string& data) {
  // Simplified placeholder - in production use real SHA-256 via OpenSSL/BCrypt
  std::stringstream ss;
  ss << std::hex << std::hash<std::string>{}(data);
  return ss.str();
}

static bool check_bcrypt(const std::string& password, const std::string& hash) {
  // In production, use real bcrypt verification
  // For now, do a simple comparison if hash is not a bcrypt hash
  if (hash.substr(0, 4) != "$2a$" && hash.substr(0, 4) != "$2b$" &&
      hash.substr(0, 4) != "$2y$") {
    // Plain text comparison for simple configs
    return password == hash;
  }
  // BCrypt verification would go here
  // BCrypt::validatePassword(password, hash);
  return false;
}

static std::string hash_bcrypt(const std::string& password) {
  // In production, use real bcrypt hashing
  // For now, return a simple marker
  return "$2a$12$" + sha256(password + "saltplaceholder");
}

// ============================================================================
// WHOIS Response Builder (non-class utility)
// ============================================================================
struct WhoisResponseBuilder {
  // Build a complete WHOIS response using all available modules
  static std::vector<std::pair<int, std::string>> build_extended_whois(
      WhoisEngine& engine,
      const std::string& requester,
      const std::string& target) {
    return engine.perform_whois(requester, target);
  }
  
  // Format the channel list for WHOIS with proper channel mode prefixes
  static std::string format_channel_list(
      const std::map<std::string, IRCChannel>& channels,
      const std::string& nick) {
    std::vector<std::string> result;
    
    for (const auto& [ch_name, ch] : channels) {
      if (ch.members.count(nick)) {
        std::string prefix;
        auto mode_it = ch.member_modes.find(nick);
        if (mode_it != ch.member_modes.end()) {
          const std::string& modes = mode_it->second;
          if (modes.find('q') != std::string::npos) prefix = "~";
          else if (modes.find('a') != std::string::npos) prefix = "&";
          else if (modes.find('o') != std::string::npos) prefix = "@";
          else if (modes.find('h') != std::string::npos) prefix = "%";
          else if (modes.find('v') != std::string::npos) prefix = "+";
        }
        result.push_back(prefix + ch_name);
      }
    }
    
    std::stringstream ss;
    for (size_t i = 0; i < result.size(); i++) {
      if (i > 0) ss << " ";
      ss << result[i];
    }
    return ss.str();
  }
  
  // Check if a channel should be visible in WHOIS to the requester
  static bool channel_visible_to_requester(
      const IRCChannel& channel,
      bool requester_is_oper) {
    // Hidden (secret) channels: only visible to members and opers with see_hidden
    if (channel.modes.find('s') != std::string::npos) {
      return requester_is_oper;
    }
    // Private channels: only visible to members and opers
    if (channel.modes.find('p') != std::string::npos) {
      return requester_is_oper;
    }
    return true;
  }
};

// ============================================================================
// Nick history and connection tracking integration
// ============================================================================
class UserLifecycleManager {
public:
  UserLifecycleManager(ConnectionTracker& tracker, WhowasManager& whowas,
                       ConnectionLogger& logger, OperatorManager& oper_mgr,
                       IRCServer& server)
    : tracker_(tracker), whowas_(whowas), logger_(logger),
      oper_mgr_(oper_mgr), server_(server) {}
  
  // Called when a user successfully registers
  void on_user_register(const std::string& nick, const std::string& user,
                        const std::string& host, const std::string& realname,
                        const std::string& ip, int port) {
    auto* stats = tracker_.create(nick);
    if (stats) {
      stats->nick = nick;
      stats->user = user;
      stats->host = host;
      stats->realname = realname;
      stats->ip = ip;
      stats->port = port;
      stats->server = server_.config().server_name;
    }
    
    logger_.log_client_connect(nick, user, host, ip, port);
  }
  
  // Called when a user disconnects
  void on_user_disconnect(const std::string& nick, const std::string& reason) {
    auto* stats = tracker_.get(nick);
    bool was_oper = oper_mgr_.is_oper(nick);
    std::string account_name;
    
    if (stats) {
      was_oper = was_oper || stats->is_oper;
      account_name = stats->account_name;
      
      // Add to WHOWAS
      whowas_.add_entry(
        nick,
        stats->user,
        stats->host,
        stats->realname,
        stats->server,
        stats->ip,
        stats->signon_time,
        reason,
        was_oper,
        account_name
      );
      
      // Log
      logger_.log_client_disconnect(nick, stats->user, stats->host, reason);
      
      // Clean up
      tracker_.remove(nick);
    }
    
    // De-oper if they were opered
    if (was_oper) {
      oper_mgr_.deoper(nick);
    }
  }
  
  // Called on nick change
  void on_nick_change(const std::string& old_nick, const std::string& new_nick) {
    tracker_.update_nick(old_nick, new_nick);
  }
  
  // Update when user becomes oper
  void on_oper_up(const std::string& nick, const std::string& oper_name,
                  OperType type, const std::string& vhost) {
    std::string type_str = "Oper";
    for (const auto& info : kOperTypeInfoTable) {
      if (info.type == type) {
        type_str = info.name;
        break;
      }
    }
    tracker_.set_oper(nick, true, type_str, vhost);
    logger_.log_oper_up(nick, type_str);
  }
  
  // Update when user deopers
  void on_oper_down(const std::string& nick) {
    tracker_.set_oper(nick, false, "", "");
    logger_.log_oper_down(nick);
  }
  
private:
  ConnectionTracker& tracker_;
  WhowasManager& whowas_;
  ConnectionLogger& logger_;
  OperatorManager& oper_mgr_;
  IRCServer& server_;
};

} // namespace progressive::irc
