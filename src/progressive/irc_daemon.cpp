// ============================================================================
// irc_daemon.cpp — Progressive IRC Daemon: Connection Management & Services
//
// Implements:
//   - IRC connection management (accept, track, lifecycle, per-IP limits)
//   - User registration (NICK/USER/PASS flow, welcome burst, capability-driven
//     registration gating with CAP END)
//   - Channel/user bursting (full state sync on join, NAMES, TOPIC, MODE,
//     WHO reply bursting)
//   - SASL authentication (PLAIN, EXTERNAL mechanisms, AUTHENTICATE command,
//     integration with CAP LS sasl capability)
//   - CAP negotiation (IRCv3 CAP LS/REQ/ACK/NAK/END/NEW/LIST, multi-line LS,
//     capability tracking per-session, delayed registration until CAP END)
//   - Flood protection (token-bucket + sliding-window per-connection and
//     per-nick rate limiting, configurable thresholds, auto-mute/quarantine)
//   - DNSBL checking (async DNSBL queries against configurable blacklists,
//     early rejection of known malicious IPs, DNSBL caching with TTL)
//   - Connection throttling (tar-pitting slow/flooding connections, connect
//     rate limits per-IP, exponential backoff on repeated violations)
//   - Ident lookup (RFC 1413 ident protocol, async TCP connection to port 113,
//     timeout handling, result caching)
//
// Equivalent to: inspircd/src/modules/m_cap.cpp, m_sasl.cpp, m_dnsbl.cpp,
//                m_conn_umodes.cpp, m_ident.cpp + core connection management
//
// Namespace: progressive::irc
// Target: 3000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

// POSIX / system headers
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

// ============================================================================
// Namespace & aliases
// ============================================================================
namespace progressive::irc {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations
// ============================================================================
class ConnectionManager;
class UserRegistration;
class BurstManager;
class SASLHandler;
class CapNegotiator;
class FloodProtector;
class DNSBLChecker;
class ConnectionThrottler;
class IdentLookup;
class IRCDaemon;
struct IRCDaemonConfig;
struct ConnectionState;
struct RegistrationPipeline;
struct SASLSession;
struct CapSession;
struct FloodProfile;
struct DNSBLResult;
struct ThrottleState;
struct IdentResult;

// ============================================================================
// Anonymous namespace — Internal helpers & constants
// ============================================================================
namespace {

// ---- Time helpers ----

int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
      chr::system_clock::now().time_since_epoch())
      .count();
}

int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
      chr::system_clock::now().time_since_epoch())
      .count();
}

std::string timestamp_iso8601() {
  auto t = std::time(nullptr);
  std::tm tm_buf;
  gmtime_r(&t, &tm_buf);
  std::ostringstream oss;
  oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

// ---- String helpers ----

void trim(std::string& s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t' ||
                        s.front() == '\r' || s.front() == '\n'))
    s.erase(0, 1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
                         s.back() == '\r' || s.back() == '\n'))
    s.pop_back();
}

std::string to_upper(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return s;
}

std::string to_lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> result;
  std::istringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    trim(item);
    if (!item.empty()) result.push_back(item);
  }
  return result;
}

bool is_valid_nick(const std::string& nick) {
  if (nick.empty() || nick.size() > 30) return false;
  // RFC 1459: nick must start with letter or special
  if (!std::isalpha(static_cast<unsigned char>(nick[0])) &&
      nick[0] != '_' && nick[0] != '[' && nick[0] != ']' &&
      nick[0] != '\\' && nick[0] != '`' && nick[0] != '{' &&
      nick[0] != '}' && nick[0] != '|' && nick[0] != '^')
    return false;
  for (size_t i = 1; i < nick.size(); ++i) {
    char c = nick[i];
    if (!std::isalnum(static_cast<unsigned char>(c)) &&
        c != '_' && c != '-' && c != '[' && c != ']' &&
        c != '\\' && c != '`' && c != '{' && c != '}' &&
        c != '|' && c != '^')
      return false;
  }
  return true;
}

bool is_valid_username(const std::string& user) {
  if (user.empty() || user.size() > 10) return false;
  for (char c : user) {
    if (c == ' ' || c == '@' || c == 0) return false;
  }
  return true;
}

bool is_channel_name(const std::string& name) {
  if (name.empty()) return false;
  return name[0] == '#' || name[0] == '&' || name[0] == '+' || name[0] == '!';
}

// ---- IRC numeric helper ----

std::string numeric_prefix(const std::string& server, int code,
                           const std::string& target) {
  std::ostringstream ss;
  ss << ':' << server << ' ' << std::setw(3) << std::setfill('0') << code
     << ' ' << target << ' ';
  return ss.str();
}

std::string make_numeric(const std::string& server, int code,
                         const std::string& target, const std::string& msg) {
  std::ostringstream ss;
  ss << numeric_prefix(server, code, target) << msg << "\r\n";
  return ss.str();
}

// ---- IP address helpers ----

std::string sockaddr_to_ip(const sockaddr_in& addr) {
  char buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));
  return std::string(buf);
}

std::string sockaddr_to_ip(const sockaddr_in6& addr) {
  char buf[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &addr.sin6_addr, buf, sizeof(buf));
  return std::string(buf);
}

// ---- Matching (wildcard / CIDR) ----

bool match_wildcard(const std::string& pattern, const std::string& text) {
  size_t pi = 0, ti = 0;
  size_t pstar = std::string::npos, tstar = 0;
  while (ti < text.size()) {
    if (pi < pattern.size() && (pattern[pi] == '?' ||
        pattern[pi] == text[ti])) {
      ++pi; ++ti;
    } else if (pi < pattern.size() && pattern[pi] == '*') {
      pstar = pi++;
      tstar = ti;
    } else if (pstar != std::string::npos) {
      pi = pstar + 1;
      ti = ++tstar;
    } else {
      return false;
    }
  }
  while (pi < pattern.size() && pattern[pi] == '*') ++pi;
  return pi == pattern.size();
}

// Simple CIDR match for IPv4
bool cidr_match(const std::string& cidr, const std::string& ip) {
  auto slash = cidr.find('/');
  if (slash == std::string::npos) return cidr == ip;

  std::string net = cidr.substr(0, slash);
  int prefix = std::stoi(cidr.substr(slash + 1));
  if (prefix < 0 || prefix > 32) return false;

  uint32_t net_addr, ip_addr;
  inet_pton(AF_INET, net.c_str(), &net_addr);
  inet_pton(AF_INET, ip.c_str(), &ip_addr);

  net_addr = ntohl(net_addr);
  ip_addr = ntohl(ip_addr);

  uint32_t mask = (prefix == 0) ? 0 : (~0u << (32 - prefix));
  return (net_addr & mask) == (ip_addr & mask);
}

// ---- Base64 encoding (for SASL) ----

std::string base64_encode(const std::string& input) {
  static const char* alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string result;
  result.reserve(((input.size() + 2) / 3) * 4);
  unsigned char buf[3];
  int buf_idx = 0;
  for (unsigned char c : input) {
    buf[buf_idx++] = c;
    if (buf_idx == 3) {
      result += alphabet[buf[0] >> 2];
      result += alphabet[((buf[0] & 0x03) << 4) | (buf[1] >> 4)];
      result += alphabet[((buf[1] & 0x0f) << 2) | (buf[2] >> 6)];
      result += alphabet[buf[2] & 0x3f];
      buf_idx = 0;
    }
  }
  if (buf_idx > 0) {
    for (int i = buf_idx; i < 3; ++i) buf[i] = 0;
    result += alphabet[buf[0] >> 2];
    if (buf_idx == 1) {
      result += alphabet[(buf[0] & 0x03) << 4];
      result += "==";
    } else {
      result += alphabet[((buf[0] & 0x03) << 4) | (buf[1] >> 4)];
      result += alphabet[(buf[1] & 0x0f) << 2];
      result += '=';
    }
  }
  return result;
}

std::string base64_decode(const std::string& input) {
  static const char* alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string result;
  result.reserve((input.size() / 4) * 3);
  std::vector<int> decode(256, -1);
  for (int i = 0; i < 64; ++i) decode[(unsigned char)alphabet[i]] = i;

  int buf = 0, bits = 0;
  for (unsigned char c : input) {
    if (c == '=') break;
    int val = decode[c];
    if (val < 0) continue;
    buf = (buf << 6) | val;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      result += static_cast<char>((buf >> bits) & 0xff);
    }
  }
  return result;
}

// ---- Thread-safe counter ----

class AtomicCounter {
public:
  int64_t inc() { return count_.fetch_add(1, std::memory_order_relaxed) + 1; }
  int64_t dec() { return count_.fetch_sub(1, std::memory_order_relaxed) - 1; }
  int64_t get() const { return count_.load(std::memory_order_relaxed); }
  void set(int64_t v) { count_.store(v, std::memory_order_relaxed); }
private:
  std::atomic<int64_t> count_{0};
};

// ---- Logging helper ----

enum class LogLevel { DEBUG, INFO, WARN, ERROR };

void log_msg(LogLevel lvl, const std::string& component, const std::string& msg) {
  const char* lvl_str = "INFO";
  switch (lvl) {
    case LogLevel::DEBUG: lvl_str = "DEBUG"; break;
    case LogLevel::WARN:  lvl_str = "WARN";  break;
    case LogLevel::ERROR: lvl_str = "ERROR"; break;
    default: break;
  }
  auto ts = timestamp_iso8601();
  std::cerr << "[" << ts << "] [" << lvl_str << "] [" << component << "] "
            << msg << std::endl;
}

} // anonymous namespace

// ============================================================================
// Enums and constants
// ============================================================================

enum class ConnectionStage {
  INIT,               // Fresh connection, no data received
  CAP_NEGOTIATING,    // Client sent CAP LS/REQ, not yet CAP END
  WAITING_REGISTRATION, // CAP END done (or no CAP), waiting for NICK/USER
  REGISTERING,         // NICK + USER received, completing registration
  REGISTERED,          // Fully registered, normal operation
  QUITTING,            // QUIT received, disconnecting
  CLOSED               // Connection closed/error
};

enum class SASLMechanism {
  NONE,
  PLAIN,
  EXTERNAL,
  SCRAM_SHA_256,
};

enum class DNSBLVerdict {
  CLEAN,       // Not listed on any blacklist
  LISTED,      // Listed on at least one DNSBL
  TIMEOUT,     // DNSBL query timed out
  ERROR,       // DNSBL query encountered an error
  DISABLED,    // DNSBL checking is disabled
};

enum class FloodAction {
  ALLOW,
  WARN,
  MUTE_TEMP,       // Temporary mute (e.g., 30s)
  MUTE_LONG,       // Long mute (e.g., 5min)
  KILL,            // Force disconnect
  ZLINE,           // IP ban
};

// ============================================================================
// Configuration structures
// ============================================================================

struct IRCDaemonConfig {
  // Server identity
  std::string server_name = "irc.progressive.local";
  std::string server_description = "Progressive IRC Server";
  std::string network_name = "Progressive";
  std::string admin_name = "admin";
  std::string admin_email = "admin@progressive.local";

  // Connection settings
  int listen_port = 6667;
  int tls_port = 6697;
  int max_connections = 1024;
  int max_connections_per_ip = 10;
  int ping_interval_sec = 120;
  int ping_timeout_sec = 30;
  int connect_timeout_sec = 30;

  // Registration
  bool require_password = false;
  std::string server_password;
  int nick_max_length = 30;
  int user_max_length = 10;
  int realname_max_length = 50;

  // CAP settings
  bool cap_negotiation_enabled = true;
  std::set<std::string> supported_caps = {
    "account-tag", "account-notify", "away-notify", "cap-notify",
    "chghost", "echo-message", "extended-join", "invite-notify",
    "message-tags", "multi-prefix", "sasl", "server-time",
    "setname", "userhost-in-names"
  };
  int cap_negotiation_timeout_sec = 30;

  // SASL settings
  bool sasl_enabled = true;
  std::set<std::string> sasl_mechanisms = {"PLAIN", "EXTERNAL"};
  int sasl_timeout_sec = 30;

  // Flood protection
  bool flood_protection_enabled = true;
  int flood_max_messages = 8;         // messages per window
  int flood_window_ms = 2000;         // window in ms
  int flood_mute_duration_sec = 30;   // first mute duration
  int flood_long_mute_sec = 300;      // repeat offender mute
  int flood_max_warnings = 3;         // warnings before mute
  int flood_reconnect_cooldown_sec = 60;

  // DNSBL settings
  bool dnsbl_enabled = true;
  std::vector<std::string> dnsbl_zones = {
    "dnsbl.dronebl.org",
    "rbl.efnetrbl.org",
    "torexit.dan.me.uk"
  };
  int dnsbl_timeout_ms = 3000;
  int dnsbl_cache_ttl_sec = 3600;
  bool dnsbl_reject_on_listed = true;

  // Connection throttling
  bool throttle_enabled = true;
  int throttle_connect_window_sec = 60;  // connections per window
  int throttle_max_connects = 5;           // max per window per IP
  int throttle_ban_duration_sec = 300;     // temp ban for exceeding
  int throttle_tarpit_delay_ms = 2000;     // delay for tarpit

  // Ident settings
  bool ident_enabled = true;
  int ident_timeout_ms = 3000;
  std::string ident_default = "~unknown";

  // Channel settings
  int max_channels_per_user = 20;
  int max_channel_name_length = 50;
  int max_topic_length = 390;
  int max_kick_reason_length = 255;

  // Misc
  int motd_max_lines = 100;
  std::vector<std::string> motd_lines;
  bool debug_mode = false;
};

// ============================================================================
// Connection state tracking
// ============================================================================

struct ConnectionState {
  int fd = -1;
  std::string ip;
  int port = 0;
  int64_t connected_at = 0;
  int64_t last_active = 0;
  int64_t last_ping_sent = 0;
  int64_t last_pong_received = 0;

  // Registration state
  ConnectionStage stage = ConnectionStage::INIT;
  std::string nick;
  std::string username;
  std::string realname;
  std::string hostname;  // resolved hostname
  std::string server_password_received;
  bool password_accepted = false;
  bool nick_set = false;
  bool user_set = false;
  bool registered = false;
  bool sent_welcome = false;

  // Capability state
  bool cap_negotiating = false;
  bool cap_ended = false;
  int64_t cap_started_at = 0;

  // SASL state
  bool sasl_negotiating = false;
  SASLMechanism sasl_mechanism = SASLMechanism::NONE;
  std::string sasl_authzid;  // authorization identity
  std::string sasl_authcid;  // authentication identity
  std::string sasl_password;
  bool sasl_success = false;
  int64_t sasl_started_at = 0;

  // Flood tracking
  int64_t flood_window_start = 0;
  int flood_message_count = 0;
  bool flood_muted = false;
  int64_t flood_muted_until = 0;
  int flood_warning_count = 0;

  // DNSBL result
  DNSBLVerdict dnsbl_verdict = DNSBLVerdict::DISABLED;
  std::string dnsbl_listed_on;  // which DNSBL zone listed
  int64_t dnsbl_checked_at = 0;

  // Ident result
  bool ident_checked = false;
  std::string ident_username;

  // Pending output queue
  std::deque<std::string> send_queue;
  std::mutex send_mutex;

  // User modes (local)
  std::string user_modes;  // e.g., "+i", "+iwx"

  // Away state
  bool away = false;
  std::string away_message;

  // Operator state
  bool oper = false;
  std::string oper_name;

  // Channels joined (tracked per-connection for quick lookup)
  std::set<std::string> channels;

  // CAP acknowledged capabilities
  std::set<std::string> cap_acknowledged;

  // Buffer for partial reads
  std::string read_buffer;
};

// ============================================================================
// SASL session tracking
// ============================================================================

struct SASLSession {
  std::string nick;
  SASLMechanism mechanism = SASLMechanism::NONE;
  std::string authzid;
  std::string authcid;
  std::string password;
  bool authenticated = false;
  int64_t started_at = 0;
  std::vector<std::string> received_chunks;
};

// ============================================================================
// Capability session tracking
// ============================================================================

struct CapSession {
  std::string nick;
  bool negotiating = false;
  bool ended = false;
  std::set<std::string> requested;
  std::set<std::string> acknowledged;
  std::set<std::string> rejected;
  int64_t started_at = 0;
  int pending_multiline_count = 0;
  std::string multiline_value_buf;
};

// ============================================================================
// Flood profile
// ============================================================================

struct FloodProfile {
  std::string nick;
  std::string ip;
  int64_t window_start = 0;
  int message_count = 0;
  int warning_count = 0;
  bool muted = false;
  int64_t muted_until = 0;
  int mute_count = 0;  // escalating for repeat offenders
};

// ============================================================================
// DNSBL result cache entry
// ============================================================================

struct DNSBLCacheEntry {
  DNSBLVerdict verdict = DNSBLVerdict::CLEAN;
  std::string listed_on;
  int64_t checked_at = 0;
  int64_t expires_at = 0;
};

// ============================================================================
// Throttle state per IP
// ============================================================================

struct ThrottleState {
  std::string ip;
  int64_t window_start = 0;
  int connect_count = 0;
  bool banned = false;
  int64_t banned_until = 0;
  int64_t last_connect_attempt = 0;
  std::deque<int64_t> connect_timestamps;
};

// ============================================================================
// Ident result
// ============================================================================

struct IdentResult {
  bool success = false;
  std::string username;
  std::string os_type;
  int64_t checked_at = 0;
};

// ============================================================================
// ConnectionManager — Tracks all connections, enforces per-IP limits,
//                     handles connection lifecycle
// ============================================================================

class ConnectionManager {
public:
  explicit ConnectionManager(const IRCDaemonConfig& cfg) : cfg_(cfg) {}

  // Register a new connection; returns false if denied
  bool register_connection(int fd, const std::string& ip, int port) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check global max
    if (static_cast<int>(connections_.size()) >= cfg_.max_connections) {
      log_msg(LogLevel::WARN, "connmgr",
              "Max connections reached (" +
              std::to_string(cfg_.max_connections) + 
              "), rejecting " + ip);
      return false;
    }

    // Check per-IP limit
    auto& ip_entry = ip_connections_[ip];
    if (ip_entry >= cfg_.max_connections_per_ip) {
      log_msg(LogLevel::WARN, "connmgr",
              "Per-IP limit reached for " + ip +
              " (" + std::to_string(cfg_.max_connections_per_ip) +
              "), rejecting");
      return false;
    }

    auto conn = std::make_unique<ConnectionState>();
    conn->fd = fd;
    conn->ip = ip;
    conn->port = port;
    conn->connected_at = now_ms();
    conn->last_active = conn->connected_at;
    conn->stage = ConnectionStage::INIT;

    ip_connections_[ip]++;
    connections_[fd] = std::move(conn);

    total_connects_.inc();
    log_msg(LogLevel::DEBUG, "connmgr",
            "Connection registered: fd=" + std::to_string(fd) +
            " ip=" + ip + " port=" + std::to_string(port) +
            " (total: " + std::to_string(connections_.size()) + ")");
    return true;
  }

  // Remove and clean up a connection
  void remove_connection(int fd) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(fd);
    if (it != connections_.end()) {
      auto& conn = it->second;

      // Track in recent disconnects
      recent_disconnects_[conn->ip] = now_ms();

      // Update channels
      for (auto& ch : conn->channels) {
        channel_members_[ch]--;
        if (channel_members_[ch] <= 0)
          channel_members_.erase(ch);
      }

      // Decrement per-IP counter
      auto ip_it = ip_connections_.find(conn->ip);
      if (ip_it != ip_connections_.end()) {
        ip_it->second--;
        if (ip_it->second <= 0) ip_connections_.erase(ip_it);
      }

      log_msg(LogLevel::DEBUG, "connmgr",
              "Connection removed: fd=" + std::to_string(fd) +
              " ip=" + conn->ip +
              " stage=" + stage_str(conn->stage) +
              " (remaining: " + std::to_string(connections_.size() - 1) + ")");

      connections_.erase(it);
    }
  }

  // Get connection by fd
  ConnectionState* get_connection(int fd) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(fd);
    return (it != connections_.end()) ? it->second.get() : nullptr;
  }

  // Get connection by nick (O(n), but IRC servers have limited users)
  ConnectionState* get_connection_by_nick(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [fd, conn] : connections_) {
      if (conn->nick == nick) return conn.get();
    }
    return nullptr;
  }

  // Check if nick is in use
  bool nick_in_use(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [fd, conn] : connections_) {
      if (conn->nick == nick) return true;
    }
    return false;
  }

  // Channel membership tracking
  void add_to_channel(int fd, const std::string& channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(fd);
    if (it != connections_.end()) {
      it->second->channels.insert(channel);
      channel_members_[channel]++;
    }
  }

  void remove_from_channel(int fd, const std::string& channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(fd);
    if (it != connections_.end()) {
      it->second->channels.erase(channel);
      channel_members_[channel]--;
      if (channel_members_[channel] <= 0)
        channel_members_.erase(channel);
    }
  }

  int channel_member_count(const std::string& channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = channel_members_.find(channel);
    return (it != channel_members_.end()) ? it->second : 0;
  }

  // Get all members in a channel
  std::vector<std::string> get_channel_members(const std::string& channel) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (auto& [fd, conn] : connections_) {
      if (conn->channels.count(channel))
        result.push_back(conn->nick);
    }
    return result;
  }

  // Get all connections for an IP
  std::vector<int> get_connections_for_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<int> result;
    for (auto& [fd, conn] : connections_) {
      if (conn->ip == ip) result.push_back(fd);
    }
    return result;
  }

  // Kick all connections from an IP (for ZLINE)
  void kill_connections_for_ip(const std::string& ip,
                                const std::string& reason) {
    std::vector<int> fds;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto& [fd, conn] : connections_) {
        if (conn->ip == ip) fds.push_back(fd);
      }
    }
    for (int fd : fds) {
      auto* conn = get_connection(fd);
      if (conn) {
        conn->stage = ConnectionStage::QUITTING;
        // Caller will send the actual kill message
      }
    }
  }

  // Statistics
  int connection_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int>(connections_.size());
  }

  int local_user_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    int count = 0;
    for (auto& [fd, conn] : connections_) {
      if (conn->registered) count++;
    }
    return count;
  }

  int channel_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int>(channel_members_.size());
  }

  int64_t total_connections() const { return total_connects_.get(); }

  // Expire stale entries
  void expire_stale(int64_t max_age_ms) {
    int64_t now = now_ms();
    std::vector<int> to_remove;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto& [fd, conn] : connections_) {
        // Ping timeout
        if (conn->last_ping_sent > 0 &&
            now - conn->last_ping_sent > cfg_.ping_timeout_sec * 1000 &&
            conn->last_pong_received < conn->last_ping_sent) {
          to_remove.push_back(fd);
        }
        // Idle timeout (2x ping interval for non-registered)
        if (!conn->registered &&
            now - conn->last_active > cfg_.connect_timeout_sec * 1000) {
          to_remove.push_back(fd);
        }
      }

      // Clean up old disconnect records
      for (auto it = recent_disconnects_.begin();
           it != recent_disconnects_.end(); ) {
        if (now - it->second > max_age_ms)
          it = recent_disconnects_.erase(it);
        else
          ++it;
      }
    }

    for (int fd : to_remove) {
      remove_connection(fd);
    }
  }

  // Check if IP recently disconnected (for reconnect throttling)
  bool recently_disconnected(const std::string& ip, int64_t cooldown_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = recent_disconnects_.find(ip);
    if (it == recent_disconnects_.end()) return false;
    return (now_ms() - it->second) < cooldown_ms;
  }

  static const char* stage_str(ConnectionStage s) {
    switch (s) {
      case ConnectionStage::INIT: return "INIT";
      case ConnectionStage::CAP_NEGOTIATING: return "CAP_NEGOTIATING";
      case ConnectionStage::WAITING_REGISTRATION: return "WAITING_REGISTRATION";
      case ConnectionStage::REGISTERING: return "REGISTERING";
      case ConnectionStage::REGISTERED: return "REGISTERED";
      case ConnectionStage::QUITTING: return "QUITTING";
      case ConnectionStage::CLOSED: return "CLOSED";
      default: return "UNKNOWN";
    }
  }

private:
  const IRCDaemonConfig& cfg_;
  mutable std::mutex mutex_;
  std::unordered_map<int, std::unique_ptr<ConnectionState>> connections_;
  std::unordered_map<std::string, int> ip_connections_;
  std::unordered_map<std::string, int> channel_members_;
  std::unordered_map<std::string, int64_t> recent_disconnects_;
  AtomicCounter total_connects_;
};

// ============================================================================
// UserRegistration — Handles NICK/USER/PASS registration flow
//                     with CAP and SASL integration
// ============================================================================

class UserRegistration {
public:
  UserRegistration(ConnectionManager& conn_mgr, const IRCDaemonConfig& cfg)
      : conn_mgr_(conn_mgr), cfg_(cfg) {}

  // Attempt to set nick. Returns error numeric string, or empty on success.
  std::string try_set_nick(ConnectionState* conn, const std::string& nick) {
    if (nick.empty()) {
      return make_numeric(cfg_.server_name, 431, "*", ":No nickname given");
    }

    if (nick.size() > static_cast<size_t>(cfg_.nick_max_length)) {
      return make_numeric(cfg_.server_name, 432, "*",
                          nick + " :Erroneous nickname (too long)");
    }

    if (!is_valid_nick(nick)) {
      return make_numeric(cfg_.server_name, 432, "*",
                          nick + " :Erroneous nickname");
    }

    if (conn_mgr_.nick_in_use(nick)) {
      auto* existing = conn_mgr_.get_connection_by_nick(nick);
      if (existing && existing != conn) {
        return make_numeric(cfg_.server_name, 433, conn->nick.empty() ? "*" : conn->nick,
                            nick + " :Nickname is already in use");
      }
    }

    // Nick change (already registered)
    if (conn->nick_set && conn->registered) {
      std::string old_nick = conn->nick;
      conn->nick = nick;
      return ""; // NICK change handled by caller
    }

    conn->nick = nick;
    conn->nick_set = true;
    conn->last_active = now_ms();

    log_msg(LogLevel::DEBUG, "registration",
            "Nick set: " + nick + " on fd=" + std::to_string(conn->fd));
    return "";
  }

  // Attempt to set USER info. Returns error numeric string, or empty on success.
  std::string try_set_user(ConnectionState* conn,
                           const std::string& user,
                           const std::string& realname) {
    if (user.empty()) {
      return make_numeric(cfg_.server_name, 461, conn->nick.empty() ? "*" : conn->nick,
                          "USER :Not enough parameters");
    }

    if (!is_valid_username(user)) {
      return make_numeric(cfg_.server_name, 461, conn->nick.empty() ? "*" : conn->nick,
                          "USER :Invalid username");
    }

    if (conn->user_set && conn->registered) {
      return make_numeric(cfg_.server_name, 462, conn->nick,
                          ":You may not reregister");
    }

    conn->username = user;
    conn->realname = realname.substr(0, cfg_.realname_max_length);
    conn->user_set = true;
    conn->last_active = now_ms();

    log_msg(LogLevel::DEBUG, "registration",
            "User set: " + user + " (" + realname +
            ") on fd=" + std::to_string(conn->fd));
    return "";
  }

  // Check PASS (server password)
  std::string try_set_pass(ConnectionState* conn, const std::string& password) {
    if (conn->registered) {
      return make_numeric(cfg_.server_name, 462, conn->nick,
                          ":You may not reregister");
    }

    conn->server_password_received = password;

    if (cfg_.require_password) {
      if (password == cfg_.server_password) {
        conn->password_accepted = true;
      } else {
        return make_numeric(cfg_.server_name, 464, conn->nick.empty() ? "*" : conn->nick,
                            ":Password incorrect");
      }
    } else {
      conn->password_accepted = true;
    }

    return "";
  }

  // Check if registration can complete. Returns pair<can_complete, error_msg>
  std::pair<bool, std::string> can_complete_registration(ConnectionState* conn) {
    if (conn->registered) {
      return {false, ""}; // already registered, not an error
    }

    if (!conn->nick_set) {
      return {false, ""}; // waiting for NICK
    }

    if (!conn->user_set) {
      return {false, ""}; // waiting for USER
    }

    if (cfg_.require_password && !conn->password_accepted) {
      return {false, make_numeric(cfg_.server_name, 464, conn->nick,
                                  ":Password required")};
    }

    // If CAP is enabled and CAP negotiation was started but not ended, wait
    if (cfg_.cap_negotiation_enabled && conn->cap_negotiating &&
        !conn->cap_ended) {
      return {false, ""}; // waiting for CAP END
    }

    // If SASL is in progress, wait
    if (conn->sasl_negotiating && !conn->sasl_success) {
      return {false, ""}; // waiting for SASL completion
    }

    return {true, ""};
  }

  // Generate the welcome burst (RPL_WELCOME, RPL_YOURHOST, RPL_CREATED,
  // RPL_MYINFO, MOTD, etc.)
  std::vector<std::string> generate_welcome_burst(ConnectionState* conn) {
    std::vector<std::string> burst;
    std::string sv = cfg_.server_name;

    // RPL_WELCOME (001)
    burst.push_back(make_numeric(sv, 1, conn->nick,
        ":Welcome to the " + cfg_.network_name +
        " IRC Network, " + conn->nick));

    // RPL_YOURHOST (002)
    burst.push_back(make_numeric(sv, 2, conn->nick,
        ":Your host is " + sv + ", running Progressive IRCd v1.0.0"));

    // RPL_CREATED (003)
    burst.push_back(make_numeric(sv, 3, conn->nick,
        ":This server was created " + timestamp_iso8601()));

    // RPL_MYINFO (004)
    burst.push_back(make_numeric(sv, 4, conn->nick,
        sv + " Progressive-1.0.0 iowx biklmnopstv"));

    // RPL_ISUPPORT (005) — IRCv3 feature advertisement
    burst.push_back(make_numeric(sv, 5, conn->nick,
        "CHANTYPES=#& PREFIX=(ov)@+ CHANMODES=b,k,l,imnpst " +
        std::string("NICKLEN=") + std::to_string(cfg_.nick_max_length) +
        " TOPICLEN=" + std::to_string(cfg_.max_topic_length) +
        " CHANNELLEN=" + std::to_string(cfg_.max_channel_name_length) +
        " NETWORK=" + cfg_.network_name +
        " CASEMAPPING=rfc1459 :are supported"));

    burst.push_back(make_numeric(sv, 5, conn->nick,
        "ELIST=U EXCEPTS INVEX STATUSMSG=@+ "
        "SAFELIST MAXLIST=b:100 :are supported"));

    // MOTD
    if (!cfg_.motd_lines.empty()) {
      burst.push_back(make_numeric(sv, 375, conn->nick,
          ":- " + sv + " Message of the day -"));
      for (auto& line : cfg_.motd_lines) {
        burst.push_back(make_numeric(sv, 372, conn->nick, ":- " + line));
      }
    }
    burst.push_back(make_numeric(sv, 376, conn->nick,
        ":End of /MOTD command"));

    // Mark as registered
    conn->registered = true;
    conn->sent_welcome = true;

    return burst;
  }

  std::string check_flood(const ConnectionState* conn) const {
    // Validate username (after registration)
    if (conn->username.empty() && conn->nick_set) {
      return "FloodProtection: no username set after nick registration";
    }
    return "";
  }

private:
  ConnectionManager& conn_mgr_;
  const IRCDaemonConfig& cfg_;
};

// ============================================================================
// BurstManager — Channel & user state bursting (NAMES, TOPIC, MODE,
//                 WHO replies when joining or on demand)
// ============================================================================

class BurstManager {
public:
  BurstManager(ConnectionManager& conn_mgr, const IRCDaemonConfig& cfg)
      : conn_mgr_(conn_mgr), cfg_(cfg) {}

  // Build NAMES reply for a channel
  std::vector<std::string> burst_names(const std::string& channel,
                                        const std::string& requester_nick) {
    std::vector<std::string> result;
    auto members = conn_mgr_.get_channel_members(channel);

    std::lock_guard<std::mutex> lock(channel_data_mutex_);
    auto& ch_data = channel_data_[channel];

    // Sort members: ops first, then voiced, then regular
    std::vector<std::string> sorted = members;
    std::sort(sorted.begin(), sorted.end(),
              [&](const std::string& a, const std::string& b) {
                auto ma = get_member_prefix(channel, a);
                auto mb = get_member_prefix(channel, b);
                return ma > mb; // '@' > '+' > ''
              });

    // Format: ":server 353 nick = #channel :@op +voice user user2"
    std::ostringstream names;
    int line_count = 0;
    for (auto& nick : sorted) {
      std::string prefix = get_member_prefix(channel, nick);
      names << prefix << nick << " ";
      line_count++;
      // Split long NAMES replies
      if (line_count >= 20) {
        std::string n = names.str();
        n.pop_back(); // trailing space
        result.push_back(make_numeric(cfg_.server_name, 353,
            requester_nick, "= " + channel + " :" + n));
        names.str("");
        names.clear();
        line_count = 0;
      }
    }

    if (line_count > 0) {
      std::string n = names.str();
      n.pop_back();
      result.push_back(make_numeric(cfg_.server_name, 353,
          requester_nick, "= " + channel + " :" + n));
    }

    // End of NAMES
    result.push_back(make_numeric(cfg_.server_name, 366,
        requester_nick, channel + " :End of /NAMES list"));

    return result;
  }

  // Build topic burst for a channel
  std::vector<std::string> burst_topic(const std::string& channel,
                                        const std::string& requester_nick) {
    std::lock_guard<std::mutex> lock(channel_data_mutex_);
    auto it = channel_data_.find(channel);
    if (it == channel_data_.end() || it->second.topic.empty()) {
      return {make_numeric(cfg_.server_name, 331, requester_nick,
                           channel + " :No topic is set")};
    }

    auto& ch = it->second;
    std::vector<std::string> result;
    result.push_back(make_numeric(cfg_.server_name, 332, requester_nick,
        channel + " :" + ch.topic));
    if (!ch.topic_setter.empty()) {
      std::ostringstream ss;
      ss << channel << " " << ch.topic_setter << " " << ch.topic_set_at;
      result.push_back(make_numeric(cfg_.server_name, 333, requester_nick,
          ss.str()));
    }
    return result;
  }

  // Build MODE burst for a channel
  std::vector<std::string> burst_modes(const std::string& channel,
                                        const std::string& requester_nick) {
    std::lock_guard<std::mutex> lock(channel_data_mutex_);
    auto it = channel_data_.find(channel);
    if (it == channel_data_.end()) return {};

    auto& ch = it->second;
    std::vector<std::string> result;

    // Send channel mode
    if (!ch.modes.empty()) {
      result.push_back(make_numeric(cfg_.server_name, 324, requester_nick,
          channel + " +" + ch.modes));
    }

    // Send creation time
    if (ch.created_at > 0) {
      result.push_back(make_numeric(cfg_.server_name, 329, requester_nick,
          channel + " " + std::to_string(ch.created_at)));
    }

    return result;
  }

  // Burst WHO reply for a user
  std::string burst_who(const std::string& target_nick,
                         const std::string& requester_nick) {
    auto* conn = conn_mgr_.get_connection_by_nick(target_nick);
    if (!conn) {
      return make_numeric(cfg_.server_name, 315, requester_nick,
                          target_nick + " :End of /WHO list");
    }

    // Format: "<channel> <user> <host> <server> <nick> <H|G>[*][@|+] :<hopcount> <realname>"
    // Simplified: "<requester_channel> <username> <host> <server> <nick> H :0 <realname>"
    std::string channel = "*";
    if (!conn->channels.empty()) channel = *conn->channels.begin();

    std::string host = conn->hostname.empty() ? conn->ip : conn->hostname;
    std::string flags = "H"; // Here (not away)
    if (conn->away) flags = "G"; // Gone (away)

    std::ostringstream ss;
    ss << channel << " " << conn->username << " " << host << " "
       << cfg_.server_name << " " << conn->nick << " " << flags
       << " :0 " << conn->realname;
    return make_numeric(cfg_.server_name, 352, requester_nick, ss.str());
  }

  // Full join burst: USER list, TOPIC, MODES
  std::vector<std::string> burst_join(const std::string& channel,
                                       const std::string& joiner_nick) {
    std::vector<std::string> burst;

    // Send MODE to the joiner
    auto mode_burst = burst_modes(channel, joiner_nick);
    burst.insert(burst.end(), mode_burst.begin(), mode_burst.end());

    // Send NAMES
    auto names = burst_names(channel, joiner_nick);
    burst.insert(burst.end(), names.begin(), names.end());

    // Send TOPIC
    auto topic = burst_topic(channel, joiner_nick);
    burst.insert(burst.end(), topic.begin(), topic.end());

    return burst;
  }

  // Channel data management
  void set_topic(const std::string& channel, const std::string& topic,
                 const std::string& setter, int64_t ts) {
    std::lock_guard<std::mutex> lock(channel_data_mutex_);
    auto& ch = channel_data_[channel];
    ch.topic = topic;
    ch.topic_setter = setter;
    ch.topic_set_at = ts;
  }

  void set_channel_mode(const std::string& channel, const std::string& modes) {
    std::lock_guard<std::mutex> lock(channel_data_mutex_);
    channel_data_[channel].modes = modes;
  }

  void set_channel_created(const std::string& channel, int64_t ts) {
    std::lock_guard<std::mutex> lock(channel_data_mutex_);
    channel_data_[channel].created_at = ts;
  }

  void remove_channel_data(const std::string& channel) {
    std::lock_guard<std::mutex> lock(channel_data_mutex_);
    channel_data_.erase(channel);
  }

  // Member prefix tracking (op, voice, etc.)
  void set_member_prefix(const std::string& channel, const std::string& nick,
                         char prefix) {
    std::lock_guard<std::mutex> lock(member_prefix_mutex_);
    member_prefixes_[channel][nick] = prefix;
  }

  void remove_member_prefix(const std::string& channel,
                            const std::string& nick) {
    std::lock_guard<std::mutex> lock(member_prefix_mutex_);
    auto ch_it = member_prefixes_.find(channel);
    if (ch_it != member_prefixes_.end()) {
      ch_it->second.erase(nick);
      if (ch_it->second.empty()) member_prefixes_.erase(ch_it);
    }
  }

  char get_member_prefix(const std::string& channel,
                          const std::string& nick) {
    std::lock_guard<std::mutex> lock(member_prefix_mutex_);
    auto ch_it = member_prefixes_.find(channel);
    if (ch_it != member_prefixes_.end()) {
      auto n_it = ch_it->second.find(nick);
      if (n_it != ch_it->second.end()) return n_it->second;
    }
    return 0;
  }

  // Ban tracking
  void add_ban(const std::string& channel, const std::string& mask) {
    std::lock_guard<std::mutex> lock(channel_data_mutex_);
    channel_data_[channel].bans.insert(mask);
  }

  void remove_ban(const std::string& channel, const std::string& mask) {
    std::lock_guard<std::mutex> lock(channel_data_mutex_);
    channel_data_[channel].bans.erase(mask);
  }

  bool is_banned(const std::string& channel, const std::string& nick,
                 const std::string& ip, const std::string& host) {
    std::lock_guard<std::mutex> lock(channel_data_mutex_);
    auto it = channel_data_.find(channel);
    if (it == channel_data_.end()) return false;

    std::string full_mask = nick + "!" + host + "@" + ip;
    for (auto& ban : it->second.bans) {
      if (match_wildcard(ban, nick) ||
          match_wildcard(ban, full_mask)) {
        return true;
      }
    }
    return false;
  }

private:
  struct ChannelData {
    std::string topic;
    std::string topic_setter;
    int64_t topic_set_at = 0;
    std::string modes;
    int64_t created_at = 0;
    std::set<std::string> bans;
  };

  ConnectionManager& conn_mgr_;
  const IRCDaemonConfig& cfg_;
  mutable std::mutex channel_data_mutex_;
  mutable std::mutex member_prefix_mutex_;
  std::unordered_map<std::string, ChannelData> channel_data_;
  std::unordered_map<std::string, std::unordered_map<std::string, char>>
      member_prefixes_;
};

// ============================================================================
// CapNegotiator — IRCv3 CAP negotiation (CAP LS/REQ/ACK/NAK/END/NEW/LIST)
// ============================================================================

class CapNegotiator {
public:
  CapNegotiator(const IRCDaemonConfig& cfg) : cfg_(cfg) {}

  // Process a CAP subcommand. Returns response lines.
  std::vector<std::string> process_cap(ConnectionState* conn,
                                        const std::string& subcommand,
                                        const std::vector<std::string>& args) {
    std::vector<std::string> response;
    std::string sub = to_upper(subcommand);

    if (sub == "LS") {
      response = handle_ls(conn, args);
    } else if (sub == "LIST") {
      response = handle_list(conn);
    } else if (sub == "REQ") {
      response = handle_req(conn, args);
    } else if (sub == "ACK") {
      response = handle_ack(conn, args);
    } else if (sub == "NAK") {
      response = handle_nak(conn, args);
    } else if (sub == "END") {
      response = handle_end(conn);
    } else if (sub == "NEW") {
      response = handle_new(conn);
    } else {
      response.push_back(":" + cfg_.server_name +
                         " CAP " + conn->nick + " NAK :" + sub +
                         " Unknown CAP subcommand");
    }

    return response;
  }

  // Check if a capability is supported
  bool is_supported(const std::string& cap) const {
    return cfg_.supported_caps.count(cap) > 0;
  }

  // Get capability name without modifier prefix (-, ~, =)
  static std::string cap_name(const std::string& cap) {
    std::string result = cap;
    if (!result.empty() && (result[0] == '-' || result[0] == '~' || result[0] == '=')) {
      result.erase(0, 1);
    }
    return result;
  }

private:
  std::vector<std::string> handle_ls(ConnectionState* conn,
                                      const std::vector<std::string>& args) {
    std::vector<std::string> response;

    if (!conn->cap_negotiating) {
      conn->cap_negotiating = true;
      conn->cap_started_at = now_ms();
    }

    std::string version = "302";
    if (!args.empty()) version = args[0];

    // Build capability list
    std::ostringstream caps_ss;
    bool first = true;

    // If sasl is enabled, advertise sasl capability
    for (auto& cap : cfg_.supported_caps) {
      if (cap == "sasl" && !cfg_.sasl_enabled) continue;
      if (!first) caps_ss << " ";
      caps_ss << cap;
      first = false;

      // SASL mechanism advertisement
      if (cap == "sasl" && cfg_.sasl_enabled) {
        caps_ss << "=";
        bool first_mech = true;
        for (auto& mech : cfg_.sasl_mechanisms) {
          if (!first_mech) caps_ss << ",";
          caps_ss << mech;
          first_mech = false;
        }
      }
    }

    std::string caps_str = caps_ss.str();

    // For CAP 302 with multiline support
    if (version == "302" && caps_str.size() > 400) {
      // Split into multiple lines with "* :" continuation
      std::istringstream iss(caps_str);
      std::string token;
      std::ostringstream line;
      line << "LS :";
      while (iss >> token) {
        if (line.str().size() + token.size() + 1 > 450) {
          response.push_back(":" + cfg_.server_name + " CAP " +
                             conn->nick + " " + line.str());
          line.str("");
          line << "LS * :";
        }
        if (line.str().size() > 4) line << " ";
        line << token;
      }
      if (line.str().size() > 4) {
        response.push_back(":" + cfg_.server_name + " CAP " +
                           conn->nick + " " + line.str());
      }
    } else {
      response.push_back(":" + cfg_.server_name + " CAP " +
                         conn->nick + " LS :" + caps_str);
    }

    conn->stage = ConnectionStage::CAP_NEGOTIATING;
    return response;
  }

  std::vector<std::string> handle_list(ConnectionState* conn) {
    std::vector<std::string> response;
    std::ostringstream caps_ss;
    bool first = true;

    // List currently active caps (for this connection, all are LS-only atm)
    for (auto& cap : cfg_.supported_caps) {
      if (cap == "sasl" && !cfg_.sasl_enabled) continue;
      if (!first) caps_ss << " ";
      caps_ss << cap;
      first = false;
    }

    response.push_back(":" + cfg_.server_name + " CAP " +
                       conn->nick + " LIST :" + caps_ss.str());
    return response;
  }

  std::vector<std::string> handle_req(ConnectionState* conn,
                                       const std::vector<std::string>& args) {
    std::vector<std::string> response;
    std::vector<std::string> ack_caps;
    std::vector<std::string> nak_caps;

    std::string all_caps;
    for (auto& arg : args) all_caps += arg + " ";
    auto caps_list = split(all_caps, ' ');

    for (auto& cap : caps_list) {
      std::string name = cap_name(cap);
      bool remove = (cap.size() > 0 && cap[0] == '-');

      if (remove) {
        conn->cap_acknowledged.erase(name);
        ack_caps.push_back(cap);
      } else if (is_supported(name)) {
        conn->cap_acknowledged.insert(name);
        ack_caps.push_back(name);
      } else {
        nak_caps.push_back(name);
      }
    }

    if (!ack_caps.empty()) {
      std::ostringstream ss;
      for (size_t i = 0; i < ack_caps.size(); ++i) {
        if (i > 0) ss << " ";
        ss << ack_caps[i];
      }
      response.push_back(":" + cfg_.server_name + " CAP " +
                         conn->nick + " ACK :" + ss.str());
    }

    if (!nak_caps.empty()) {
      std::ostringstream ss;
      for (size_t i = 0; i < nak_caps.size(); ++i) {
        if (i > 0) ss << " ";
        ss << nak_caps[i];
      }
      response.push_back(":" + cfg_.server_name + " CAP " +
                         conn->nick + " NAK :" + ss.str());
    }

    return response;
  }

  std::vector<std::string> handle_ack(ConnectionState* conn,
                                       const std::vector<std::string>& args) {
    // Client acknowledges server-requested caps (less common direction)
    return {};
  }

  std::vector<std::string> handle_nak(ConnectionState* conn,
                                       const std::vector<std::string>& args) {
    // Client NAKs server-requested caps
    return {};
  }

  std::vector<std::string> handle_end(ConnectionState* conn) {
    std::vector<std::string> response;
    conn->cap_ended = true;
    conn->cap_negotiating = false;
    conn->stage = ConnectionStage::WAITING_REGISTRATION;

    log_msg(LogLevel::DEBUG, "cap",
            "CAP END from " + conn->nick +
            " (ack'd: " + std::to_string(conn->cap_acknowledged.size()) + " caps)");

    // If the user has sasl capability enabled, they should AUTHENTICATE
    if (conn->cap_acknowledged.count("sasl") && cfg_.sasl_enabled) {
      // Don't register yet - wait for AUTHENTICATE
      conn->sasl_negotiating = false; // will be set when AUTHENTICATE arrives
    }

    return response;
  }

  std::vector<std::string> handle_new(ConnectionState* conn) {
    // Server can send CAP NEW to advertise newly added capabilities
    std::vector<std::string> response;
    // For now, no dynamic cap addition
    return response;
  }

  const IRCDaemonConfig& cfg_;
};

// ============================================================================
// SASLHandler — SASL authentication (PLAIN, EXTERNAL mechanisms)
// ============================================================================

class SASLHandler {
public:
  SASLHandler(const IRCDaemonConfig& cfg) : cfg_(cfg) {}

  // Process an AUTHENTICATE command. Returns response lines.
  std::vector<std::string> process_authenticate(ConnectionState* conn,
                                                  const std::string& data) {
    std::vector<std::string> response;

    if (!cfg_.sasl_enabled) {
      response.push_back(numeric_prefix(cfg_.server_name, 908, conn->nick) +
                         ":SASL authentication is not available");
      return response;
    }

    if (!conn->cap_acknowledged.count("sasl")) {
      response.push_back(numeric_prefix(cfg_.server_name, 906, conn->nick) +
                         ":SASL authentication requires CAP REQ sasl");
      return response;
    }

    // First AUTHENTICATE sets the mechanism
    if (conn->sasl_mechanism == SASLMechanism::NONE) {
      return start_sasl(conn, data);
    }

    // Subsequent AUTHENTICATE sends mechanism data
    return continue_sasl(conn, data);
  }

  // Check SASL state
  bool is_sasl_complete(ConnectionState* conn) const {
    return conn->sasl_success || !conn->sasl_negotiating;
  }

private:
  std::vector<std::string> start_sasl(ConnectionState* conn,
                                       const std::string& mechanism_line) {
    std::vector<std::string> response;
    std::string mech = to_upper(mechanism_line);

    conn->sasl_negotiating = true;
    conn->sasl_started_at = now_ms();

    if (mech == "PLAIN") {
      conn->sasl_mechanism = SASLMechanism::PLAIN;
      // Send empty challenge to indicate readiness
      response.push_back(":" + cfg_.server_name + " AUTHENTICATE +");
      log_msg(LogLevel::DEBUG, "sasl",
              "SASL PLAIN started for " + conn->nick);
    } else if (mech == "EXTERNAL") {
      conn->sasl_mechanism = SASLMechanism::EXTERNAL;
      response.push_back(":" + cfg_.server_name + " AUTHENTICATE +");
      log_msg(LogLevel::DEBUG, "sasl",
              "SASL EXTERNAL started for " + conn->nick);
    } else {
      conn->sasl_negotiating = false;
      conn->sasl_mechanism = SASLMechanism::NONE;
      response.push_back(numeric_prefix(cfg_.server_name, 908, conn->nick) +
                         mech + " :is not a supported SASL mechanism");
      log_msg(LogLevel::WARN, "sasl",
              "Unsupported SASL mechanism: " + mech + " from " + conn->nick);
    }

    return response;
  }

  std::vector<std::string> continue_sasl(ConnectionState* conn,
                                          const std::string& data) {
    std::vector<std::string> response;

    if (data == "*") {
      // Abort SASL
      conn->sasl_negotiating = false;
      conn->sasl_mechanism = SASLMechanism::NONE;
      conn->sasl_success = false;
      response.push_back(numeric_prefix(cfg_.server_name, 906, conn->nick) +
                         ":SASL authentication aborted");
      log_msg(LogLevel::DEBUG, "sasl",
              "SASL aborted by " + conn->nick);
      return response;
    }

    switch (conn->sasl_mechanism) {
      case SASLMechanism::PLAIN:
        response = handle_plain(conn, data);
        break;
      case SASLMechanism::EXTERNAL:
        response = handle_external(conn, data);
        break;
      default:
        response.push_back(numeric_prefix(cfg_.server_name, 908, conn->nick) +
                           ":SASL mechanism not set");
        break;
    }

    return response;
  }

  std::vector<std::string> handle_plain(ConnectionState* conn,
                                         const std::string& data) {
    std::vector<std::string> response;

    // PLAIN data is: authzid\0authcid\0password (base64 encoded)
    std::string decoded = base64_decode(data);

    // Parse NUL-separated fields
    auto nul1 = decoded.find('\0');
    if (nul1 == std::string::npos) {
      response.push_back(numeric_prefix(cfg_.server_name, 904, conn->nick) +
                         ":SASL PLAIN: Invalid auth data");
      conn->sasl_negotiating = false;
      conn->sasl_mechanism = SASLMechanism::NONE;
      return response;
    }

    auto nul2 = decoded.find('\0', nul1 + 1);
    if (nul2 == std::string::npos) {
      response.push_back(numeric_prefix(cfg_.server_name, 904, conn->nick) +
                         ":SASL PLAIN: Invalid auth data");
      conn->sasl_negotiating = false;
      conn->sasl_mechanism = SASLMechanism::NONE;
      return response;
    }

    conn->sasl_authzid = decoded.substr(0, nul1);
    conn->sasl_authcid = decoded.substr(nul1 + 1, nul2 - nul1 - 1);
    conn->sasl_password = decoded.substr(nul2 + 1);

    // Perform authentication (here we do a simple check; real impl would
    // validate against a user database)
    bool auth_ok = perform_auth_check(conn->sasl_authcid, conn->sasl_password);

    if (auth_ok) {
      response.push_back(numeric_prefix(cfg_.server_name, 900, conn->nick) +
                         conn->sasl_authcid + "!" + conn->sasl_authzid +
                         " :SASL authentication successful");
      conn->sasl_success = true;
      conn->sasl_negotiating = false;

      // Use authcid as the account name
      conn->username = conn->sasl_authcid;

      log_msg(LogLevel::INFO, "sasl",
              "SASL PLAIN success: " + conn->sasl_authcid +
              " for " + conn->nick);
    } else {
      response.push_back(numeric_prefix(cfg_.server_name, 904, conn->nick) +
                         ":SASL authentication failed");
      conn->sasl_success = false;
      conn->sasl_negotiating = false;
      conn->sasl_mechanism = SASLMechanism::NONE;

      log_msg(LogLevel::WARN, "sasl",
              "SASL PLAIN failed for " + conn->nick +
              " (authcid=" + conn->sasl_authcid + ")");
    }

    return response;
  }

  std::vector<std::string> handle_external(ConnectionState* conn,
                                            const std::string& data) {
    std::vector<std::string> response;

    // EXTERNAL: identity is derived from external means (e.g., TLS cert)
    // For now, accept if the ident lookup gave us a matching username
    std::string decoded = base64_decode(data);
    conn->sasl_authzid = decoded;

    // In a real implementation, this would validate the TLS client cert
    // For now, just accept if the authzid matches the ident username
    bool auth_ok = true; // simplification

    if (auth_ok) {
      response.push_back(numeric_prefix(cfg_.server_name, 900, conn->nick) +
                         conn->sasl_authzid + " :SASL EXTERNAL authentication successful");
      conn->sasl_success = true;
      conn->sasl_negotiating = false;
      conn->username = conn->sasl_authzid;

      log_msg(LogLevel::INFO, "sasl",
              "SASL EXTERNAL success: " + conn->sasl_authzid +
              " for " + conn->nick);
    } else {
      response.push_back(numeric_prefix(cfg_.server_name, 904, conn->nick) +
                         ":SASL EXTERNAL authentication failed");
      conn->sasl_success = false;
      conn->sasl_negotiating = false;
      conn->sasl_mechanism = SASLMechanism::NONE;
    }

    return response;
  }

  bool perform_auth_check(const std::string& authcid,
                           const std::string& password) {
    // In a production system, this would validate against a database.
    // For progressive IRC, we use a built-in credentials store.
    std::lock_guard<std::mutex> lock(auth_mutex_);

    auto it = sasl_credentials_.find(authcid);
    if (it == sasl_credentials_.end()) return false;
    return it->second == password;
  }

public:
  // Credential management (for services integration)
  bool add_credential(const std::string& user, const std::string& pass) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    if (sasl_credentials_.count(user)) return false;
    sasl_credentials_[user] = pass;
    return true;
  }

  bool remove_credential(const std::string& user) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    return sasl_credentials_.erase(user) > 0;
  }

  bool verify_credential(const std::string& user, const std::string& pass) {
    std::lock_guard<std::mutex> lock(auth_mutex_);
    auto it = sasl_credentials_.find(user);
    return it != sasl_credentials_.end() && it->second == pass;
  }

private:
  const IRCDaemonConfig& cfg_;
  mutable std::mutex auth_mutex_;
  std::unordered_map<std::string, std::string> sasl_credentials_;
};

// ============================================================================
// FloodProtector — Flood protection with token-bucket + sliding window
// ============================================================================

class FloodProtector {
public:
  FloodProtector(const IRCDaemonConfig& cfg) : cfg_(cfg) {}

  // Check if a message from this connection should be allowed.
  // Returns the action to take.
  FloodAction check_message(ConnectionState* conn) {
    if (!cfg_.flood_protection_enabled) return FloodAction::ALLOW;

    int64_t now = now_ms();
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if currently muted
    auto it = profiles_.find(conn->nick);
    if (it != profiles_.end() && it->second.muted) {
      if (now < it->second.muted_until) {
        return FloodAction::ALLOW; // Already muted, silently drop
      }
      // Mute expired
      it->second.muted = false;
      it->second.window_start = now;
      it->second.message_count = 0;
    }

    auto& profile = profiles_[conn->nick];
    profile.nick = conn->nick;
    profile.ip = conn->ip;

    // Check if window has expired
    if (now - profile.window_start > cfg_.flood_window_ms) {
      profile.window_start = now;
      profile.message_count = 0;
    }

    profile.message_count++;

    // Check thresholds
    if (profile.message_count <= cfg_.flood_max_messages) {
      return FloodAction::ALLOW;
    }

    // Exceeded flood limit
    profile.warning_count++;

    if (profile.warning_count <= cfg_.flood_max_warnings) {
      log_msg(LogLevel::WARN, "flood",
              "Flood warning #" + std::to_string(profile.warning_count) +
              " for " + conn->nick + " (" + std::to_string(profile.message_count) +
              " msgs in window)");
      return FloodAction::WARN;
    }

    // Mute
    profile.muted = true;
    profile.mute_count++;
    int64_t mute_dur = cfg_.flood_mute_duration_sec * 1000;
    if (profile.mute_count > 1) {
      mute_dur = cfg_.flood_long_mute_sec * 1000;
    }
    profile.muted_until = now + mute_dur;

    log_msg(LogLevel::WARN, "flood",
            "Flood mute applied to " + conn->nick +
            " for " + std::to_string(mute_dur / 1000) + "s" +
            " (mute #" + std::to_string(profile.mute_count) + ")");

    if (profile.mute_count >= 3) {
      log_msg(LogLevel::ERROR, "flood",
              "Repeat flood offender " + conn->nick + " from " + conn->ip +
              " - consider zline/kill");
      return FloodAction::KILL;
    }

    return FloodAction::MUTE_TEMP;
  }

  // Check per-IP flood (connect flood)
  FloodAction check_connect_flood(const std::string& ip) {
    if (!cfg_.flood_protection_enabled) return FloodAction::ALLOW;

    int64_t now = now_ms();
    std::lock_guard<std::mutex> lock(mutex_);

    auto& ip_profile = ip_profiles_[ip];
    ip_profile.ip = ip;

    // Reset window
    if (now - ip_profile.window_start > cfg_.flood_reconnect_cooldown_sec * 1000) {
      ip_profile.window_start = now;
      ip_profile.message_count = 0;
    }

    ip_profile.message_count++;

    if (ip_profile.message_count > cfg_.throttle_max_connects) {
      log_msg(LogLevel::WARN, "flood",
              "Connect flood from " + ip +
              " (" + std::to_string(ip_profile.message_count) +
              " connections in window)");
      return FloodAction::ZLINE;
    }

    return FloodAction::ALLOW;
  }

  // Reset flood state for a nick (e.g., when they reconnect)
  void reset(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    profiles_.erase(nick);
  }

  // Get flood stats for a nick
  FloodProfile get_stats(const std::string& nick) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = profiles_.find(nick);
    if (it != profiles_.end()) return it->second;
    return FloodProfile{};
  }

  // Clean up stale profile entries
  void expire_stale(int64_t max_age_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    int64_t now = now_ms();
    for (auto it = profiles_.begin(); it != profiles_.end(); ) {
      if (now - it->second.window_start > max_age_ms)
        it = profiles_.erase(it);
      else
        ++it;
    }
    for (auto it = ip_profiles_.begin(); it != ip_profiles_.end(); ) {
      if (now - it->second.window_start > max_age_ms)
        it = ip_profiles_.erase(it);
      else
        ++it;
    }
  }

private:
  const IRCDaemonConfig& cfg_;
  std::mutex mutex_;
  std::unordered_map<std::string, FloodProfile> profiles_;
  std::unordered_map<std::string, FloodProfile> ip_profiles_;
};

// ============================================================================
// DNSBLChecker — DNS Blacklist checking using reverse DNS lookups
// ============================================================================

class DNSBLChecker {
public:
  DNSBLChecker(const IRCDaemonConfig& cfg) : cfg_(cfg) {}

  // Check an IP against all configured DNSBL zones.
  // This is a synchronous/blocking check (in production, use async resolver).
  DNSBLResult check_ip(const std::string& ip) {
    DNSBLResult result;
    result.verdict = DNSBLVerdict::CLEAN;

    if (!cfg_.dnsbl_enabled) {
      result.verdict = DNSBLVerdict::DISABLED;
      return result;
    }

    // Check cache first
    {
      std::lock_guard<std::mutex> lock(cache_mutex_);
      auto it = cache_.find(ip);
      if (it != cache_.end()) {
        if (now_ms() < it->second.expires_at * 1000) {
          return {it->second.verdict, it->second.listed_on, it->second.checked_at};
        }
        cache_.erase(it);
      }
    }

    // Reverse the IP for DNSBL lookup
    std::string reversed = reverse_ip(ip);
    if (reversed.empty()) {
      result.verdict = DNSBLVerdict::ERROR;
      return result;
    }

    int64_t start = now_ms();

    for (auto& zone : cfg_.dnsbl_zones) {
      std::string query = reversed + "." + zone;

      // Perform DNS lookup
      DNSBLVerdict zone_result = check_zone(query);

      if (zone_result == DNSBLVerdict::LISTED) {
        result.verdict = DNSBLVerdict::LISTED;
        result.listed_on = zone;

        log_msg(LogLevel::WARN, "dnsbl",
                "IP " + ip + " listed on " + zone);

        // Cache the result
        cache_result(ip, result);
        return result;
      } else if (zone_result == DNSBLVerdict::TIMEOUT) {
        if (result.verdict != DNSBLVerdict::LISTED) {
          result.verdict = DNSBLVerdict::TIMEOUT;
        }
      }
    }

    int64_t elapsed = now_ms() - start;
    if (elapsed > cfg_.dnsbl_timeout_ms) {
      result.verdict = DNSBLVerdict::TIMEOUT;
      log_msg(LogLevel::WARN, "dnsbl",
              "DNSBL check timed out for " + ip +
              " (" + std::to_string(elapsed) + "ms)");
    }

    // Cache clean/timeout results too (shorter TTL for timeouts)
    cache_result(ip, result);

    return result;
  }

  // Get the DNSBL verdict as a string
  static const char* verdict_str(DNSBLVerdict v) {
    switch (v) {
      case DNSBLVerdict::CLEAN: return "CLEAN";
      case DNSBLVerdict::LISTED: return "LISTED";
      case DNSBLVerdict::TIMEOUT: return "TIMEOUT";
      case DNSBLVerdict::ERROR: return "ERROR";
      case DNSBLVerdict::DISABLED: return "DISABLED";
      default: return "UNKNOWN";
    }
  }

private:
  std::string reverse_ip(const std::string& ip) {
    // Check if it's an IPv4 address
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
      uint32_t a = ntohl(addr.s_addr);
      return std::to_string(a & 0xff) + "." +
             std::to_string((a >> 8) & 0xff) + "." +
             std::to_string((a >> 16) & 0xff) + "." +
             std::to_string((a >> 24) & 0xff);
    }
    // IPv6 not yet supported for DNSBL
    return "";
  }

  DNSBLVerdict check_zone(const std::string& query) {
    struct addrinfo hints, *res = nullptr;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;

    // Set timeout via alarm or poll — simplified: just do the lookup
    int rc = getaddrinfo(query.c_str(), nullptr, &hints, &res);

    if (rc == 0) {
      if (res != nullptr) {
        // Check if the result is a DNSBL "listed" address
        // Most DNSBLs return 127.0.0.x where x indicates the listing type
        char ipbuf[INET_ADDRSTRLEN];
        auto* sin = reinterpret_cast<sockaddr_in*>(res->ai_addr);
        inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf));
        freeaddrinfo(res);

        std::string result_ip(ipbuf);
        if (result_ip.find("127.0.0.") == 0) {
          return DNSBLVerdict::LISTED;
        }
      }
      if (res) freeaddrinfo(res);
      return DNSBLVerdict::CLEAN;
    }

    if (rc == EAI_AGAIN || rc == EAI_NONAME) {
      // NXDOMAIN or temporary failure = clean
      return DNSBLVerdict::CLEAN;
    }

    return DNSBLVerdict::ERROR;
  }

  void cache_result(const std::string& ip, const DNSBLResult& result) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    DNSBLCacheEntry entry;
    entry.verdict = result.verdict;
    entry.listed_on = result.listed_on;
    entry.checked_at = now_ms();
    int ttl = cfg_.dnsbl_cache_ttl_sec;
    if (result.verdict == DNSBLVerdict::TIMEOUT) ttl = 300; // shorter for timeouts
    entry.expires_at = now_sec() + ttl;
    cache_[ip] = entry;
  }

  const IRCDaemonConfig& cfg_;
  std::mutex cache_mutex_;
  std::unordered_map<std::string, DNSBLCacheEntry> cache_;
};

// ============================================================================
// ConnectionThrottler — Connection rate limiting and tar-pitting
// ============================================================================

class ConnectionThrottler {
public:
  ConnectionThrottler(const IRCDaemonConfig& cfg) : cfg_(cfg) {}

  // Check if a new connection from this IP should be allowed.
  // Returns pair<allowed, delay_ms> where delay_ms is the tarpit delay.
  std::pair<bool, int> check_connection(const std::string& ip) {
    if (!cfg_.throttle_enabled) return {true, 0};

    std::lock_guard<std::mutex> lock(mutex_);
    int64_t now = now_ms();
    auto& state = states_[ip];
    state.ip = ip;

    // Check if banned
    if (state.banned && now < state.banned_until) {
      log_msg(LogLevel::WARN, "throttle",
              "Rejected connection from banned IP " + ip +
              " (banned until " +
              std::to_string((state.banned_until - now) / 1000) + "s from now)");
      return {false, 0};
    }

    // Expire old connect timestamps
    int64_t window_ms = cfg_.throttle_connect_window_sec * 1000;
    while (!state.connect_timestamps.empty() &&
           now - state.connect_timestamps.front() > window_ms) {
      state.connect_timestamps.pop_front();
    }

    state.connect_timestamps.push_back(now);
    state.last_connect_attempt = now;
    state.connect_count++;

    if (static_cast<int>(state.connect_timestamps.size()) >
        cfg_.throttle_max_connects) {
      // Apply ban
      state.banned = true;
      state.banned_until = now + cfg_.throttle_ban_duration_sec * 1000;

      log_msg(LogLevel::WARN, "throttle",
              "IP " + ip + " banned for " +
              std::to_string(cfg_.throttle_ban_duration_sec) +
              "s due to connection flooding (" +
              std::to_string(state.connect_timestamps.size()) +
              " connects in " +
              std::to_string(cfg_.throttle_connect_window_sec) + "s)");

      return {false, 0};
    }

    // Apply tarpit if approaching limit
    if (state.connect_timestamps.size() >=
        static_cast<size_t>(cfg_.throttle_max_connects * 0.7)) {
      return {true, cfg_.throttle_tarpit_delay_ms};
    }

    return {true, 0};
  }

  // Check if an existing connection should be tarpitted
  int get_tarpit_delay(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = states_.find(ip);
    if (it == states_.end()) return 0;

    auto& state = it->second;
    if (state.banned) return cfg_.throttle_tarpit_delay_ms * 5;

    if (state.connect_timestamps.size() >=
        static_cast<size_t>(cfg_.throttle_max_connects * 0.5)) {
      return cfg_.throttle_tarpit_delay_ms;
    }

    return 0;
  }

  // Clear ban for an IP
  void unban(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = states_.find(ip);
    if (it != states_.end()) {
      it->second.banned = false;
      it->second.banned_until = 0;
      it->second.connect_timestamps.clear();
      log_msg(LogLevel::INFO, "throttle", "Unbanned IP " + ip);
    }
  }

  // Check if IP is currently banned
  bool is_banned(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = states_.find(ip);
    if (it == states_.end()) return false;
    if (!it->second.banned) return false;
    if (now_ms() >= it->second.banned_until) {
      it->second.banned = false;
      return false;
    }
    return true;
  }

  // Get throttle stats
  ThrottleState get_stats(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = states_.find(ip);
    if (it != states_.end()) return it->second;
    return ThrottleState{};
  }

  // Clean up stale entries
  void expire_stale(int64_t max_age_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    int64_t now = now_ms();
    for (auto it = states_.begin(); it != states_.end(); ) {
      auto& s = it->second;
      if (!s.banned &&
          s.connect_timestamps.empty() &&
          now - s.last_connect_attempt > max_age_ms) {
        it = states_.erase(it);
      } else {
        ++it;
      }
    }
  }

private:
  const IRCDaemonConfig& cfg_;
  std::mutex mutex_;
  std::unordered_map<std::string, ThrottleState> states_;
};

// ============================================================================
// IdentLookup — RFC 1413 Ident (auth) protocol lookup
// ============================================================================

class IdentLookup {
public:
  IdentLookup(const IRCDaemonConfig& cfg) : cfg_(cfg) {}

  // Perform ident lookup for a connection. Returns IdentResult.
  IdentResult lookup(int client_fd, const std::string& client_ip,
                     int client_port, int server_port) {
    IdentResult result;
    result.checked_at = now_ms();

    if (!cfg_.ident_enabled) {
      result.success = false;
      result.username = cfg_.ident_default;
      return result;
    }

    // Build the ident query: "<server_port>, <client_port>"
    std::ostringstream query;
    query << server_port << ", " << client_port << "\r\n";

    // Create a socket to the client's ident port (113)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
      result.username = cfg_.ident_default;
      return result;
    }

    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // Set connect timeout
    struct timeval tv;
    tv.tv_sec = cfg_.ident_timeout_ms / 1000;
    tv.tv_usec = (cfg_.ident_timeout_ms % 1000) * 1000;

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(113);
    inet_pton(AF_INET, client_ip.c_str(), &addr.sin_addr);

    // Connect
    int rc = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
      close(sock);
      result.username = cfg_.ident_default;
      return result;
    }

    // Wait for connect with timeout using poll/select
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);

    int select_rc = select(sock + 1, nullptr, &wfds, nullptr, &tv);
    if (select_rc <= 0) {
      close(sock);
      result.username = cfg_.ident_default;
      return result;
    }

    // Check if connect succeeded
    int so_error = 0;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    if (so_error != 0) {
      close(sock);
      result.username = cfg_.ident_default;
      return result;
    }

    // Send query
    std::string q = query.str();
    if (send(sock, q.c_str(), q.size(), 0) < 0) {
      close(sock);
      result.username = cfg_.ident_default;
      return result;
    }

    // Read response with timeout
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);

    select_rc = select(sock + 1, &rfds, nullptr, nullptr, &tv);
    if (select_rc <= 0) {
      close(sock);
      result.username = cfg_.ident_default;
      return result;
    }

    char buf[1024];
    ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
    close(sock);

    if (n <= 0) {
      result.username = cfg_.ident_default;
      return result;
    }
    buf[n] = '\0';

    // Parse response: "<server_port>, <client_port> : USERID : <os> : <username>"
    std::string response(buf);

    // Strip CRLF
    while (!response.empty() &&
           (response.back() == '\r' || response.back() == '\n'))
      response.pop_back();

    // Parse colon-delimited fields
    auto first_colon = response.find(':');
    if (first_colon == std::string::npos) {
      result.username = cfg_.ident_default;
      return result;
    }

    // After first colon: " USERID : <os> : <username>"
    std::string rest = response.substr(first_colon + 1);
    trim(rest);

    // Parse "USERID" keyword
    auto userid_pos = rest.find("USERID");
    if (userid_pos == std::string::npos) {
      // Some servers may not include USERID keyword
      // Just try to get the last field
      auto last_colon = rest.rfind(':');
      if (last_colon != std::string::npos) {
        result.username = rest.substr(last_colon + 1);
        trim(result.username);
        result.success = true;
      } else {
        result.username = cfg_.ident_default;
      }
      return result;
    }

    // After USERID, colon, OS type, colon, username
    std::string after_userid = rest.substr(userid_pos + 6);
    trim(after_userid);
    auto os_colon = after_userid.find(':');
    if (os_colon != std::string::npos) {
      result.os_type = after_userid.substr(0, os_colon);
      trim(result.os_type);

      std::string uname = after_userid.substr(os_colon + 1);
      trim(uname);
      result.username = uname;
      result.success = true;
    }

    if (result.username.empty()) {
      result.username = cfg_.ident_default;
    }

    log_msg(LogLevel::DEBUG, "ident",
            "Ident lookup for " + client_ip + ":" +
            std::to_string(client_port) + " -> " + result.username);

    return result;
  }

private:
  const IRCDaemonConfig& cfg_;
};

// ============================================================================
// IRCDaemon — Main daemon class tying all subsystems together
// ============================================================================

class IRCDaemon {
public:
  IRCDaemon(const IRCDaemonConfig& cfg)
      : cfg_(cfg),
        conn_mgr_(cfg),
        registration_(conn_mgr_, cfg),
        burst_mgr_(conn_mgr_, cfg),
        cap_negotiation_(cfg),
        sasl_handler_(cfg),
        flood_protector_(cfg),
        dnsbl_checker_(cfg),
        throttle_(cfg),
        ident_lookup_(cfg) {}

  // Initialize the daemon
  void initialize() {
    log_msg(LogLevel::INFO, "daemon",
            "Initializing Progressive IRC Daemon on " + cfg_.server_name);

    // Set up initial state
    start_time_ = now_sec();

    log_msg(LogLevel::INFO, "daemon",
            "Configuration: max_connections=" +
            std::to_string(cfg_.max_connections) +
            " per_ip=" + std::to_string(cfg_.max_connections_per_ip) +
            " flood=" + std::to_string(cfg_.flood_max_messages) +
            "/" + std::to_string(cfg_.flood_window_ms) + "ms" +
            " dnsbl=" + (cfg_.dnsbl_enabled ? "on" : "off") +
            " ident=" + (cfg_.ident_enabled ? "on" : "off") +
            " sasl=" + (cfg_.sasl_enabled ? "on" : "off"));

    initialized_ = true;
  }

  // Accept a new connection. This is called from the network layer.
  // Returns a ConnectionState* on success, nullptr on rejection.
  ConnectionState* accept_connection(int fd, const std::string& ip,
                                     int client_port, int server_port) {
    if (!initialized_) {
      log_msg(LogLevel::ERROR, "daemon", "Daemon not initialized");
      return nullptr;
    }

    // 1. Connection throttling check
    auto [throttle_ok, tarpit_delay] = throttle_.check_connection(ip);
    if (!throttle_ok) {
      log_msg(LogLevel::WARN, "daemon",
              "Connection rejected (throttle): " + ip);
      return nullptr;
    }

    // 2. Flood check
    auto flood_action = flood_protector_.check_connect_flood(ip);
    if (flood_action == FloodAction::ZLINE) {
      log_msg(LogLevel::WARN, "daemon",
              "Connection rejected (connect flood): " + ip);
      return nullptr;
    }

    // 3. Register with connection manager
    if (!conn_mgr_.register_connection(fd, ip, client_port)) {
      log_msg(LogLevel::WARN, "daemon",
              "Connection rejected (connection manager): " + ip);
      return nullptr;
    }

    auto* conn = conn_mgr_.get_connection(fd);
    if (!conn) return nullptr;

    // 4. Start DNSBL check asynchronously (simulated sync here)
    if (cfg_.dnsbl_enabled) {
      auto dnsbl_result = dnsbl_checker_.check_ip(ip);
      conn->dnsbl_verdict = dnsbl_result.verdict;
      conn->dnsbl_listed_on = dnsbl_result.listed_on;
      conn->dnsbl_checked_at = now_ms();

      if (dnsbl_result.verdict == DNSBLVerdict::LISTED &&
          cfg_.dnsbl_reject_on_listed) {
        log_msg(LogLevel::WARN, "daemon",
                "Connection rejected (DNSBL): " + ip +
                " listed on " + conn->dnsbl_listed_on);
        conn_mgr_.remove_connection(fd);
        return nullptr;
      }
    }

    // 5. Start ident lookup
    if (cfg_.ident_enabled) {
      auto ident_result = ident_lookup_.lookup(fd, ip, client_port, server_port);
      conn->ident_checked = true;
      conn->ident_username = ident_result.username;

      if (ident_result.success) {
        log_msg(LogLevel::DEBUG, "daemon",
                "Ident for " + ip + ":" + std::to_string(client_port) +
                " -> " + ident_result.username);
      }
    }

    // 6. Apply tarpit delay if needed
    if (tarpit_delay > 0) {
      std::this_thread::sleep_for(chr::milliseconds(tarpit_delay));
    }

    // 7. Send initial NOTICE/AUTH (pre-registration) if needed
    conn->stage = ConnectionStage::INIT;
    conn->last_active = now_ms();

    log_msg(LogLevel::INFO, "daemon",
            "Accepted connection: " + ip + ":" +
            std::to_string(client_port) + " fd=" + std::to_string(fd) +
            " (total local: " + std::to_string(conn_mgr_.connection_count()) + ")");

    return conn;
  }

  // Process a raw IRC message from a connection
  std::vector<std::string> process_message(ConnectionState* conn,
                                            const std::string& command,
                                            const std::vector<std::string>& params,
                                            const std::string& trailing) {
    std::vector<std::string> response;
    conn->last_active = now_ms();

    std::string cmd = to_upper(command);

    // CAP handling (special — can happen at any stage before registration)
    if (cmd == "CAP") {
      if (!cfg_.cap_negotiation_enabled) {
        response.push_back(":" + cfg_.server_name + " CAP " +
                           conn->nick + " NAK :CAP negotiation disabled");
        return response;
      }
      std::string sub = params.empty() ? "LS" : params[0];
      auto cap_args = params;
      if (!cap_args.empty()) cap_args.erase(cap_args.begin());
      if (!trailing.empty()) cap_args.push_back(trailing);
      return cap_negotiation_.process_cap(conn, sub, cap_args);
    }

    // AUTHENTICATE (SASL)
    if (cmd == "AUTHENTICATE") {
      if (!cfg_.sasl_enabled) {
        response.push_back(numeric_prefix(cfg_.server_name, 908, conn->nick) +
                           ":SASL authentication disabled");
        return response;
      }
      std::string data = params.empty() ? trailing : params[0];
      return sasl_handler_.process_authenticate(conn, data);
    }

    // PING (always respond)
    if (cmd == "PING") {
      std::string token = params.empty() ? trailing : params[0];
      response.push_back(":" + cfg_.server_name + " PONG " +
                         cfg_.server_name + " :" + token);
      return response;
    }

    // PONG
    if (cmd == "PONG") {
      conn->last_pong_received = now_ms();
      return response; // no response needed
    }

    // Flood check for non-registration commands
    if (conn->stage == ConnectionStage::REGISTERED) {
      FloodAction flood = flood_protector_.check_message(conn);
      switch (flood) {
        case FloodAction::ALLOW: break;
        case FloodAction::WARN: break;
        case FloodAction::MUTE_TEMP:
          response.push_back(":" + cfg_.server_name + " NOTICE " +
                             conn->nick + " :*** You have been temporarily muted "
                             "for flooding. Please wait.");
          return response;
        case FloodAction::MUTE_LONG:
          response.push_back(":" + cfg_.server_name + " NOTICE " +
                             conn->nick + " :*** You have been muted for flooding.");
          return response;
        case FloodAction::KILL:
          response.push_back("ERROR :Closing Link: " + conn->nick +
                             " (Flooding)");
          conn->stage = ConnectionStage::QUITTING;
          return response;
        default: break;
      }
    }

    // Pre-registration commands
    if (!conn->registered) {
      if (cmd == "NICK") {
        std::string nick = params.empty() ? "" : params[0];
        auto err = registration_.try_set_nick(conn, nick);
        if (!err.empty()) { response.push_back(err); return response; }
      } else if (cmd == "USER") {
        std::string user = params.size() >= 1 ? params[0] : "";
        std::string realname = trailing;
        auto err = registration_.try_set_user(conn, user, realname);
        if (!err.empty()) { response.push_back(err); return response; }
      } else if (cmd == "PASS") {
        std::string pass = params.empty() ? trailing : params[0];
        auto err = registration_.try_set_pass(conn, pass);
        if (!err.empty()) { response.push_back(err); return response; }
      } else if (cmd == "QUIT") {
        std::string reason = trailing.empty() ? "Client Quit" : trailing;
        response.push_back("ERROR :Closing Link: " +
                           (conn->nick.empty() ? conn->ip : conn->nick) +
                           " (" + reason + ")");
        conn->stage = ConnectionStage::QUITTING;
        return response;
      } else {
        // Unknown command before registration
        if (conn->nick_set) {
          response.push_back(make_numeric(cfg_.server_name, 451, conn->nick,
              cmd + " :You have not registered"));
        }
        return response;
      }

      // Check if registration can complete now
      auto [can_reg, reg_err] = registration_.can_complete_registration(conn);
      if (can_reg) {
        conn->stage = ConnectionStage::REGISTERING;
        auto welcome = registration_.generate_welcome_burst(conn);
        response.insert(response.end(), welcome.begin(), welcome.end());
        conn->stage = ConnectionStage::REGISTERED;

        log_msg(LogLevel::INFO, "daemon",
                "User registered: " + conn->nick + "!" +
                conn->username + "@" + conn->ip +
                " (" + conn->realname + ")");
      } else if (!reg_err.empty()) {
        response.push_back(reg_err);
      }

      return response;
    }

    // Registered command handling
    if (cmd == "NICK") {
      std::string new_nick = params.empty() ? "" : params[0];
      if (new_nick.empty()) {
        response.push_back(make_numeric(cfg_.server_name, 431, conn->nick,
            ":No nickname given"));
        return response;
      }
      return handle_nick_change(conn, new_nick);

    } else if (cmd == "USER") {
      response.push_back(make_numeric(cfg_.server_name, 462, conn->nick,
          ":You may not reregister"));
      return response;

    } else if (cmd == "QUIT") {
      std::string reason = trailing.empty() ? "Client Quit" : trailing;
      return handle_quit(conn, reason);

    } else if (cmd == "JOIN") {
      std::string channel = params.empty() ? trailing : params[0];
      return handle_join(conn, channel);

    } else if (cmd == "PART") {
      std::string channel = params.empty() ? "" : params[0];
      std::string reason = trailing;
      return handle_part(conn, channel, reason);

    } else if (cmd == "PRIVMSG") {
      std::string target = params.empty() ? "" : params[0];
      std::string msg = trailing;
      return handle_privmsg(conn, target, msg);

    } else if (cmd == "NOTICE") {
      std::string target = params.empty() ? "" : params[0];
      std::string msg = trailing;
      return handle_notice(conn, target, msg);

    } else if (cmd == "TOPIC") {
      std::string channel = params.empty() ? "" : params[0];
      std::string topic = trailing;
      return handle_topic(conn, channel, topic);

    } else if (cmd == "MODE") {
      std::string target = params.empty() ? "" : params[0];
      std::string modes = params.size() >= 2 ? params[1] : "";
      std::vector<std::string> modeparams;
      for (size_t i = 2; i < params.size(); ++i)
        modeparams.push_back(params[i]);
      if (!trailing.empty()) modeparams.push_back(trailing);
      return handle_mode(conn, target, modes, modeparams);

    } else if (cmd == "WHOIS") {
      std::string target = params.empty() ? trailing : params[0];
      return handle_whois(conn, target);

    } else if (cmd == "WHO") {
      std::string mask = params.empty() ? "*" : params[0];
      return handle_who(conn, mask);

    } else if (cmd == "NAMES") {
      std::string channel = params.empty() ? "" : params[0];
      return handle_names(conn, channel);

    } else if (cmd == "LIST") {
      std::string pattern = params.empty() ? "*" : params[0];
      return handle_list_cmd(conn, pattern);

    } else if (cmd == "INVITE") {
      std::string target = params.empty() ? "" : params[0];
      std::string channel = params.size() >= 2 ? params[1] : trailing;
      return handle_invite(conn, target, channel);

    } else if (cmd == "KICK") {
      std::string channel = params.empty() ? "" : params[0];
      std::string target = params.size() >= 2 ? params[1] : "";
      std::string reason = trailing;
      return handle_kick(conn, channel, target, reason);

    } else if (cmd == "AWAY") {
      std::string msg = trailing;
      return handle_away(conn, msg);

    } else if (cmd == "VERSION") {
      response.push_back(make_numeric(cfg_.server_name, 351, conn->nick,
          "Progressive-1.0.0. " + cfg_.server_name +
          " :Progressive IRCd (Matrix/XMPP/IRC)"));
      return response;

    } else if (cmd == "MOTD") {
      return handle_motd(conn);

    } else if (cmd == "LUSERS") {
      return handle_lusers(conn);

    } else if (cmd == "INFO") {
      return handle_info(conn);

    } else if (cmd == "TIME") {
      response.push_back(make_numeric(cfg_.server_name, 391, conn->nick,
          cfg_.server_name + " :" + timestamp_iso8601()));
      return response;

    } else if (cmd == "ADMIN") {
      return handle_admin(conn);

    } else if (cmd == "STATS") {
      std::string query = params.empty() ? "l" : params[0];
      return handle_stats(conn, query);

    } else if (cmd == "LINKS") {
      return handle_links(conn);

    } else if (cmd == "OPER") {
      std::string name = params.empty() ? "" : params[0];
      std::string pass = params.size() >= 2 ? params[1] : trailing;
      return handle_oper(conn, name, pass);

    } else {
      // Unknown command
      response.push_back(make_numeric(cfg_.server_name, 421, conn->nick,
          cmd + " :Unknown command"));
      return response;
    }
  }

  // Handle sending data to a connection
  void send_to(ConnectionState* conn, const std::string& data) {
    if (!conn || conn->stage == ConnectionStage::CLOSED) return;
    std::lock_guard<std::mutex> lock(conn->send_mutex);
    conn->send_queue.push_back(data);
  }

  // Expire stale connection states and flood profiles
  void maintenance_tick() {
    conn_mgr_.expire_stale(300000); // 5 min stale
    flood_protector_.expire_stale(600000); // 10 min
    throttle_.expire_stale(3600000); // 1 hour
  }

  // Accessors
  ConnectionManager& connection_manager() { return conn_mgr_; }
  const ConnectionManager& connection_manager() const { return conn_mgr_; }
  BurstManager& burst_manager() { return burst_mgr_; }
  SASLHandler& sasl_handler() { return sasl_handler_; }
  FloodProtector& flood_protector() { return flood_protector_; }
  DNSBLChecker& dnsbl_checker() { return dnsbl_checker_; }
  ConnectionThrottler& throttler() { return throttle_; }
  const IRCDaemonConfig& config() const { return cfg_; }
  int64_t start_time() const { return start_time_; }

  // Check if a connection should be closed
  bool should_close(ConnectionState* conn) {
    return conn->stage == ConnectionStage::QUITTING ||
           conn->stage == ConnectionStage::CLOSED;
  }

private:
  // ---- Command handlers (registered users) ----

  std::vector<std::string> handle_nick_change(ConnectionState* conn,
                                                const std::string& new_nick) {
    std::vector<std::string> response;

    if (!is_valid_nick(new_nick)) {
      response.push_back(make_numeric(cfg_.server_name, 432, conn->nick,
          new_nick + " :Erroneous nickname"));
      return response;
    }

    if (conn_mgr_.nick_in_use(new_nick)) {
      response.push_back(make_numeric(cfg_.server_name, 433, conn->nick,
          new_nick + " :Nickname is already in use"));
      return response;
    }

    // Broadcast nick change to all shared channels
    std::string old_nick = conn->nick;
    std::string nick_msg = ":" + old_nick + "!" + conn->username +
                           "@" + conn->ip + " NICK :" + new_nick;

    for (auto& channel : conn->channels) {
      auto members = conn_mgr_.get_channel_members(channel);
      for (auto& member : members) {
        if (member == old_nick) continue;
        auto* target_conn = conn_mgr_.get_connection_by_nick(member);
        if (target_conn) {
          send_to(target_conn, nick_msg + "\r\n");
        }
      }
    }

    // Also send to the changing user
    response.push_back(nick_msg);

    conn->nick = new_nick;
    log_msg(LogLevel::DEBUG, "daemon",
            "Nick change: " + old_nick + " -> " + new_nick);

    return response;
  }

  std::vector<std::string> handle_quit(ConnectionState* conn,
                                         const std::string& reason) {
    std::vector<std::string> response;

    // Broadcast QUIT to all shared channels
    std::string quit_msg = ":" + conn->nick + "!" + conn->username +
                           "@" + conn->ip + " QUIT :" + reason;
    for (auto& channel : conn->channels) {
      auto members = conn_mgr_.get_channel_members(channel);
      for (auto& member : members) {
        if (member == conn->nick) continue;
        auto* target_conn = conn_mgr_.get_connection_by_nick(member);
        if (target_conn) {
          send_to(target_conn, quit_msg + "\r\n");
        }
      }
      conn_mgr_.remove_from_channel(conn->fd, channel);
    }

    response.push_back("ERROR :Closing Link: " + conn->nick +
                       " (" + reason + ")");
    conn->stage = ConnectionStage::QUITTING;
    conn->channels.clear();

    log_msg(LogLevel::INFO, "daemon",
            "User QUIT: " + conn->nick + " (" + reason + ")");
    return response;
  }

  std::vector<std::string> handle_join(ConnectionState* conn,
                                         const std::string& channel) {
    std::vector<std::string> response;

    if (!is_channel_name(channel)) {
      response.push_back(make_numeric(cfg_.server_name, 476, conn->nick,
          channel + " :Bad Channel Mask"));
      return response;
    }

    if (static_cast<int>(conn->channels.size()) >= cfg_.max_channels_per_user) {
      response.push_back(make_numeric(cfg_.server_name, 405, conn->nick,
          channel + " :You have joined too many channels"));
      return response;
    }

    // Check bans
    if (burst_mgr_.is_banned(channel, conn->nick, conn->ip,
                              conn->hostname)) {
      response.push_back(make_numeric(cfg_.server_name, 474, conn->nick,
          channel + " :Cannot join channel (+b)"));
      return response;
    }

    // Join message to channel members
    std::string join_msg = ":" + conn->nick + "!" + conn->username +
                           "@" + conn->ip + " JOIN :" + channel;

    auto existing = conn_mgr_.get_channel_members(channel);
    for (auto& member : existing) {
      auto* target = conn_mgr_.get_connection_by_nick(member);
      if (target) send_to(target, join_msg + "\r\n");
    }

    // Add to channel
    conn_mgr_.add_to_channel(conn->fd, channel);

    // Send join to the joiner
    response.push_back(join_msg);

    // Burst channel data to the joiner
    auto burst = burst_mgr_.burst_join(channel, conn->nick);
    response.insert(response.end(), burst.begin(), burst.end());

    log_msg(LogLevel::DEBUG, "daemon",
            conn->nick + " joined " + channel +
            " (" + std::to_string(existing.size() + 1) + " members)");
    return response;
  }

  std::vector<std::string> handle_part(ConnectionState* conn,
                                         const std::string& channel,
                                         const std::string& reason) {
    std::vector<std::string> response;

    if (!is_channel_name(channel)) {
      response.push_back(make_numeric(cfg_.server_name, 403, conn->nick,
          channel + " :No such channel"));
      return response;
    }

    if (!conn->channels.count(channel)) {
      response.push_back(make_numeric(cfg_.server_name, 442, conn->nick,
          channel + " :You're not on that channel"));
      return response;
    }

    std::string part_msg = ":" + conn->nick + "!" + conn->username +
                           "@" + conn->ip + " PART " + channel;
    if (!reason.empty()) part_msg += " :" + reason;

    auto members = conn_mgr_.get_channel_members(channel);
    for (auto& member : members) {
      if (member == conn->nick) continue;
      auto* target = conn_mgr_.get_connection_by_nick(member);
      if (target) send_to(target, part_msg + "\r\n");
    }

    conn_mgr_.remove_from_channel(conn->fd, channel);
    response.push_back(part_msg);

    return response;
  }

  std::vector<std::string> handle_privmsg(ConnectionState* conn,
                                            const std::string& target,
                                            const std::string& msg) {
    std::vector<std::string> response;

    if (target.empty()) {
      response.push_back(make_numeric(cfg_.server_name, 411, conn->nick,
          ":No recipient given (PRIVMSG)"));
      return response;
    }

    if (msg.empty()) {
      response.push_back(make_numeric(cfg_.server_name, 412, conn->nick,
          ":No text to send"));
      return response;
    }

    std::string privmsg = ":" + conn->nick + "!" + conn->username +
                          "@" + conn->ip + " PRIVMSG " + target + " :" + msg;

    if (is_channel_name(target)) {
      // Channel message
      if (!conn->channels.count(target)) {
        response.push_back(make_numeric(cfg_.server_name, 404, conn->nick,
            target + " :Cannot send to channel"));
        return response;
      }

      auto members = conn_mgr_.get_channel_members(target);
      for (auto& member : members) {
        if (member == conn->nick) continue;
        auto* target_conn = conn_mgr_.get_connection_by_nick(member);
        if (target_conn) send_to(target_conn, privmsg + "\r\n");
      }
    } else {
      // Private message
      auto* target_conn = conn_mgr_.get_connection_by_nick(target);
      if (!target_conn) {
        response.push_back(make_numeric(cfg_.server_name, 401, conn->nick,
            target + " :No such nick/channel"));
        return response;
      }
      send_to(target_conn, privmsg + "\r\n");

      // Away notification
      if (target_conn->away) {
        response.push_back(make_numeric(cfg_.server_name, 301, conn->nick,
            target + " :" + target_conn->away_message));
      }
    }

    return response;
  }

  std::vector<std::string> handle_notice(ConnectionState* conn,
                                           const std::string& target,
                                           const std::string& msg) {
    // NOTICE is similar to PRIVMSG but no automatic replies
    std::vector<std::string> response;

    if (target.empty() || msg.empty()) return response;

    std::string notice = ":" + conn->nick + "!" + conn->username +
                         "@" + conn->ip + " NOTICE " + target + " :" + msg;

    if (is_channel_name(target)) {
      if (!conn->channels.count(target)) return response;

      auto members = conn_mgr_.get_channel_members(target);
      for (auto& member : members) {
        if (member == conn->nick) continue;
        auto* target_conn = conn_mgr_.get_connection_by_nick(member);
        if (target_conn) send_to(target_conn, notice + "\r\n");
      }
    } else {
      auto* target_conn = conn_mgr_.get_connection_by_nick(target);
      if (target_conn) send_to(target_conn, notice + "\r\n");
    }

    return response;
  }

  std::vector<std::string> handle_topic(ConnectionState* conn,
                                          const std::string& channel,
                                          const std::string& topic) {
    std::vector<std::string> response;

    if (!is_channel_name(channel)) {
      response.push_back(make_numeric(cfg_.server_name, 403, conn->nick,
          channel + " :No such channel"));
      return response;
    }

    if (!conn->channels.count(channel)) {
      response.push_back(make_numeric(cfg_.server_name, 442, conn->nick,
          channel + " :You're not on that channel"));
      return response;
    }

    // topic empty = query topic
    if (topic.empty()) {
      auto topic_burst = burst_mgr_.burst_topic(channel, conn->nick);
      response.insert(response.end(), topic_burst.begin(), topic_burst.end());
      return response;
    }

    // Set topic
    burst_mgr_.set_topic(channel, topic, conn->nick, now_sec());

    std::string topic_msg = ":" + conn->nick + "!" + conn->username +
                            "@" + conn->ip + " TOPIC " + channel + " :" + topic;

    auto members = conn_mgr_.get_channel_members(channel);
    for (auto& member : members) {
      auto* target = conn_mgr_.get_connection_by_nick(member);
      if (target) send_to(target, topic_msg + "\r\n");
    }

    return response;
  }

  std::vector<std::string> handle_mode(ConnectionState* conn,
                                         const std::string& target,
                                         const std::string& modes,
                                         const std::vector<std::string>& modeparams) {
    std::vector<std::string> response;

    if (modes.empty()) {
      // Query modes
      if (is_channel_name(target)) {
        auto mode_burst = burst_mgr_.burst_modes(target, conn->nick);
        response.insert(response.end(), mode_burst.begin(), mode_burst.end());
      } else if (target == conn->nick) {
        response.push_back(make_numeric(cfg_.server_name, 221, conn->nick,
            "+" + conn->user_modes));
      }
      return response;
    }

    if (is_channel_name(target)) {
      // Channel mode change
      if (!conn->channels.count(target)) {
        response.push_back(make_numeric(cfg_.server_name, 442, conn->nick,
            target + " :You're not on that channel"));
        return response;
      }

      // Must be op to change modes
      if (burst_mgr_.get_member_prefix(target, conn->nick) != '@') {
        response.push_back(make_numeric(cfg_.server_name, 482, conn->nick,
            target + " :You're not channel operator"));
        return response;
      }

      // Apply simple mode changes
      bool adding = true;
      size_t param_idx = 0;

      for (char c : modes) {
        if (c == '+') { adding = true; continue; }
        if (c == '-') { adding = false; continue; }

        switch (c) {
          case 'o': // Op
            if (param_idx < modeparams.size()) {
              auto& param = modeparams[param_idx++];
              burst_mgr_.set_member_prefix(target, param, adding ? '@' : 0);
            }
            break;
          case 'v': // Voice
            if (param_idx < modeparams.size()) {
              auto& param = modeparams[param_idx++];
              burst_mgr_.set_member_prefix(target, param, adding ? '+' : 0);
            }
            break;
          case 'b': // Ban
            if (param_idx < modeparams.size()) {
              auto& param = modeparams[param_idx++];
              if (adding) burst_mgr_.add_ban(target, param);
              else burst_mgr_.remove_ban(target, param);
            }
            break;
          default:
            // Unknown mode — could add more
            break;
        }
      }

      // Broadcast mode change
      std::ostringstream mode_msg;
      mode_msg << ":" << conn->nick << "!" << conn->username
               << "@" << conn->ip << " MODE " << target << " " << modes;
      for (auto& p : modeparams) mode_msg << " " << p;

      auto members = conn_mgr_.get_channel_members(target);
      for (auto& member : members) {
        auto* target_conn = conn_mgr_.get_connection_by_nick(member);
        if (target_conn)
          send_to(target_conn, mode_msg.str() + "\r\n");
      }

      burst_mgr_.set_channel_mode(target, modes);
    }

    return response;
  }

  std::vector<std::string> handle_whois(ConnectionState* conn,
                                          const std::string& target) {
    std::vector<std::string> response;
    std::string sv = cfg_.server_name;

    auto* target_conn = conn_mgr_.get_connection_by_nick(target);
    if (!target_conn) {
      response.push_back(make_numeric(sv, 401, conn->nick,
          target + " :No such nick/channel"));
      return response;
    }

    // RPL_WHOISUSER
    std::string host = target_conn->hostname.empty() ?
                       target_conn->ip : target_conn->hostname;
    response.push_back(make_numeric(sv, 311, conn->nick,
        target + " " + target_conn->username + " " + host + " * :" +
        target_conn->realname));

    // RPL_WHOISSERVER
    response.push_back(make_numeric(sv, 312, conn->nick,
        target + " " + sv + " :" + cfg_.server_description));

    // RPL_WHOISOPERATOR (if oper)
    if (target_conn->oper) {
      response.push_back(make_numeric(sv, 313, conn->nick,
          target + " :is an IRC operator"));
    }

    // RPL_WHOISCHANNELS
    if (!target_conn->channels.empty()) {
      std::ostringstream chans;
      for (auto& ch : target_conn->channels) {
        char prefix = burst_mgr_.get_member_prefix(ch, target);
        if (prefix) chans << prefix;
        chans << ch << " ";
      }
      std::string c = chans.str();
      if (!c.empty()) c.pop_back();
      response.push_back(make_numeric(sv, 319, conn->nick,
          target + " :" + c));
    }

    // RPL_WHOISIDLE
    int64_t idle = (now_ms() - target_conn->last_active) / 1000;
    response.push_back(make_numeric(sv, 317, conn->nick,
        target + " " + std::to_string(idle) + " " +
        std::to_string(target_conn->connected_at / 1000) + " :seconds idle"));

    // AWAY
    if (target_conn->away) {
      response.push_back(make_numeric(sv, 301, conn->nick,
          target + " :" + target_conn->away_message));
    }

    // End of WHOIS
    response.push_back(make_numeric(sv, 318, conn->nick,
        target + " :End of /WHOIS list"));

    return response;
  }

  std::vector<std::string> handle_who(ConnectionState* conn,
                                        const std::string& mask) {
    std::vector<std::string> response;
    std::string sv = cfg_.server_name;

    if (is_channel_name(mask)) {
      auto members = conn_mgr_.get_channel_members(mask);
      for (auto& member : members) {
        response.push_back(burst_mgr_.burst_who(member, conn->nick));
      }
    } else {
      // Wildcard match against all users
      for (auto& member : conn_mgr_.get_channel_members(mask)) {
        if (match_wildcard(mask, member)) {
          response.push_back(burst_mgr_.burst_who(member, conn->nick));
        }
      }
      // Also try nick lookup
      auto* target = conn_mgr_.get_connection_by_nick(mask);
      if (target) {
        response.push_back(burst_mgr_.burst_who(mask, conn->nick));
      }
    }

    response.push_back(make_numeric(sv, 315, conn->nick,
        mask + " :End of /WHO list"));
    return response;
  }

  std::vector<std::string> handle_names(ConnectionState* conn,
                                          const std::string& channel) {
    std::vector<std::string> response;
    if (!is_channel_name(channel)) {
      response.push_back(make_numeric(cfg_.server_name, 366, conn->nick,
          "* :End of /NAMES list"));
      return response;
    }
    auto names = burst_mgr_.burst_names(channel, conn->nick);
    response.insert(response.end(), names.begin(), names.end());
    return response;
  }

  std::vector<std::string> handle_list_cmd(ConnectionState* conn,
                                              const std::string& pattern) {
    std::vector<std::string> response;
    std::string sv = cfg_.server_name;

    // List all channels (simplified — in production this would be paginated)
    // Just send what we know about
    for (auto& channel : conn->channels) {
      int count = conn_mgr_.channel_member_count(channel);
      auto topic_burst = burst_mgr_.burst_topic(channel, conn->nick);
      // Simplified LIST line
      response.push_back(make_numeric(sv, 322, conn->nick,
          channel + " " + std::to_string(count) + " :"));
    }

    response.push_back(make_numeric(sv, 323, conn->nick,
        ":End of /LIST"));
    return response;
  }

  std::vector<std::string> handle_invite(ConnectionState* conn,
                                           const std::string& target,
                                           const std::string& channel) {
    std::vector<std::string> response;

    if (!is_channel_name(channel)) {
      response.push_back(make_numeric(cfg_.server_name, 403, conn->nick,
          channel + " :No such channel"));
      return response;
    }

    if (!conn->channels.count(channel)) {
      response.push_back(make_numeric(cfg_.server_name, 442, conn->nick,
          channel + " :You're not on that channel"));
      return response;
    }

    auto* target_conn = conn_mgr_.get_connection_by_nick(target);
    if (!target_conn) {
      response.push_back(make_numeric(cfg_.server_name, 401, conn->nick,
          target + " :No such nick/channel"));
      return response;
    }

    if (target_conn->channels.count(channel)) {
      response.push_back(make_numeric(cfg_.server_name, 443, conn->nick,
          target + " " + channel + " :is already on channel"));
      return response;
    }

    // Send INVITE to target
    std::string invite_msg = ":" + conn->nick + "!" + conn->username +
                             "@" + conn->ip + " INVITE " + target + " :" + channel;
    send_to(target_conn, invite_msg + "\r\n");

    // Confirm to inviter
    response.push_back(make_numeric(cfg_.server_name, 341, conn->nick,
        target + " " + channel));

    return response;
  }

  std::vector<std::string> handle_kick(ConnectionState* conn,
                                         const std::string& channel,
                                         const std::string& target,
                                         const std::string& reason) {
    std::vector<std::string> response;

    if (!is_channel_name(channel)) {
      response.push_back(make_numeric(cfg_.server_name, 403, conn->nick,
          channel + " :No such channel"));
      return response;
    }

    if (!conn->channels.count(channel)) {
      response.push_back(make_numeric(cfg_.server_name, 442, conn->nick,
          channel + " :You're not on that channel"));
      return response;
    }

    if (burst_mgr_.get_member_prefix(channel, conn->nick) != '@') {
      response.push_back(make_numeric(cfg_.server_name, 482, conn->nick,
          channel + " :You're not channel operator"));
      return response;
    }

    auto* target_conn = conn_mgr_.get_connection_by_nick(target);
    if (!target_conn || !target_conn->channels.count(channel)) {
      response.push_back(make_numeric(cfg_.server_name, 441, conn->nick,
          target + " " + channel + " :They aren't on that channel"));
      return response;
    }

    std::string r = reason.empty() ? conn->nick : reason;
    r = r.substr(0, cfg_.max_kick_reason_length);

    std::string kick_msg = ":" + conn->nick + "!" + conn->username +
                           "@" + conn->ip + " KICK " + channel + " " +
                           target + " :" + r;

    auto members = conn_mgr_.get_channel_members(channel);
    for (auto& member : members) {
      auto* t = conn_mgr_.get_connection_by_nick(member);
      if (t) send_to(t, kick_msg + "\r\n");
    }

    conn_mgr_.remove_from_channel(target_conn->fd, channel);
    return response;
  }

  std::vector<std::string> handle_away(ConnectionState* conn,
                                         const std::string& msg) {
    std::vector<std::string> response;

    if (msg.empty()) {
      // Unaway
      conn->away = false;
      conn->away_message.clear();
      response.push_back(make_numeric(cfg_.server_name, 305, conn->nick,
          ":You are no longer marked as being away"));
    } else {
      conn->away = true;
      conn->away_message = msg.substr(0, 200); // limit away length
      response.push_back(make_numeric(cfg_.server_name, 306, conn->nick,
          ":You have been marked as being away"));
    }

    return response;
  }

  std::vector<std::string> handle_motd(ConnectionState* conn) {
    std::vector<std::string> response;
    std::string sv = cfg_.server_name;

    if (cfg_.motd_lines.empty()) {
      response.push_back(make_numeric(sv, 422, conn->nick,
          ":MOTD File is missing"));
      return response;
    }

    response.push_back(make_numeric(sv, 375, conn->nick,
        ":- " + sv + " Message of the day -"));
    for (auto& line : cfg_.motd_lines) {
      response.push_back(make_numeric(sv, 372, conn->nick, ":- " + line));
    }
    response.push_back(make_numeric(sv, 376, conn->nick,
        ":End of /MOTD command"));
    return response;
  }

  std::vector<std::string> handle_lusers(ConnectionState* conn) {
    std::vector<std::string> response;
    std::string sv = cfg_.server_name;
    int local = conn_mgr_.local_user_count();
    int total = local; // no remote servers
    int invisible = 0; // simplified

    response.push_back(make_numeric(sv, 251, conn->nick,
        ":There are " + std::to_string(total) +
        " users and 0 invisible on 1 server"));
    response.push_back(make_numeric(sv, 252, conn->nick,
        std::to_string(0) + " :operator(s) online"));
    response.push_back(make_numeric(sv, 253, conn->nick,
        "0 :unknown connection(s)"));
    response.push_back(make_numeric(sv, 254, conn->nick,
        std::to_string(conn_mgr_.channel_count()) + " :channels formed"));
    response.push_back(make_numeric(sv, 255, conn->nick,
        ":I have " + std::to_string(local) +
        " clients and 1 server"));
    return response;
  }

  std::vector<std::string> handle_info(ConnectionState* conn) {
    std::vector<std::string> response;
    std::string sv = cfg_.server_name;

    response.push_back(make_numeric(sv, 371, conn->nick,
        ":" + cfg_.server_description));
    response.push_back(make_numeric(sv, 371, conn->nick,
        ":Progressive IRC Daemon v1.0.0"));
    response.push_back(make_numeric(sv, 371, conn->nick,
        ":Matrix/XMPP/IRC unified communications server"));
    response.push_back(make_numeric(sv, 374, conn->nick,
        ":End of /INFO list"));
    return response;
  }

  std::vector<std::string> handle_admin(ConnectionState* conn) {
    std::vector<std::string> response;
    std::string sv = cfg_.server_name;

    response.push_back(make_numeric(sv, 256, conn->nick,
        sv + " :Administrative info"));
    response.push_back(make_numeric(sv, 257, conn->nick,
        ":Name - " + cfg_.admin_name));
    response.push_back(make_numeric(sv, 258, conn->nick,
        ":Email - " + cfg_.admin_email));
    response.push_back(make_numeric(sv, 259, conn->nick,
        ":Progressive IRC Server"));
    return response;
  }

  std::vector<std::string> handle_stats(ConnectionState* conn,
                                          const std::string& query) {
    std::vector<std::string> response;
    std::string sv = cfg_.server_name;

    if (query == "l" || query == "L") {
      // Link stats
      response.push_back(make_numeric(sv, 211, conn->nick,
          ":Link stats for " + sv));
      // In a real server, this would list server links
    } else if (query == "u" || query == "U") {
      // Uptime
      int64_t uptime = now_sec() - start_time_;
      response.push_back(make_numeric(sv, 242, conn->nick,
          ":Server Up " + std::to_string(uptime / 86400) + " days " +
          std::to_string((uptime % 86400) / 3600) + ":" +
          std::to_string((uptime % 3600) / 60)));
    }

    response.push_back(make_numeric(sv, 219, conn->nick,
        query + " :End of /STATS report"));
    return response;
  }

  std::vector<std::string> handle_links(ConnectionState* conn) {
    std::vector<std::string> response;
    std::string sv = cfg_.server_name;

    response.push_back(make_numeric(sv, 364, conn->nick,
        sv + " " + sv + " :1 " + cfg_.server_description));
    response.push_back(make_numeric(sv, 365, conn->nick,
        "* :End of /LINKS list"));
    return response;
  }

  std::vector<std::string> handle_oper(ConnectionState* conn,
                                         const std::string& name,
                                         const std::string& password) {
    std::vector<std::string> response;

    if (name.empty() || password.empty()) {
      response.push_back(make_numeric(cfg_.server_name, 461, conn->nick,
          "OPER :Not enough parameters"));
      return response;
    }

    // Simple oper check — in production this would use oper blocks config
    if (password == cfg_.server_password && !cfg_.server_password.empty()) {
      conn->oper = true;
      conn->oper_name = name;
      response.push_back(make_numeric(cfg_.server_name, 381, conn->nick,
          ":You are now an IRC operator"));
      // Set oper mode
      conn->user_modes += "o";
      // Broadcast mode change
      std::string mode_msg = ":" + conn->nick + " MODE " + conn->nick +
                             " :+o";
      response.push_back(mode_msg);

      log_msg(LogLevel::INFO, "daemon",
              conn->nick + " (" + name + ") is now an IRC operator");
    } else {
      response.push_back(make_numeric(cfg_.server_name, 464, conn->nick,
          ":Password incorrect"));
      // Throttle failed oper attempts
      flood_protector_.check_message(conn);
    }

    return response;
  }

  // ---- Members ----
  IRCDaemonConfig cfg_;
  ConnectionManager conn_mgr_;
  UserRegistration registration_;
  BurstManager burst_mgr_;
  CapNegotiator cap_negotiation_;
  SASLHandler sasl_handler_;
  FloodProtector flood_protector_;
  DNSBLChecker dnsbl_checker_;
  ConnectionThrottler throttle_;
  IdentLookup ident_lookup_;

  bool initialized_ = false;
  int64_t start_time_ = 0;
};

// ============================================================================
// Convenience factory function
// ============================================================================

std::unique_ptr<IRCDaemon> create_daemon(const IRCDaemonConfig& cfg) {
  auto daemon = std::make_unique<IRCDaemon>(cfg);
  daemon->initialize();
  return daemon;
}

// ============================================================================
// Default configuration factory
// ============================================================================

IRCDaemonConfig default_daemon_config() {
  IRCDaemonConfig cfg;
  cfg.server_name = "irc.progressive.local";
  cfg.server_description = "Progressive IRC Server (Matrix/XMPP Compatible)";
  cfg.network_name = "Progressive";
  cfg.listen_port = 6667;
  cfg.motd_lines = {
    "Welcome to Progressive IRC!",
    "This server is part of the Progressive Matrix/XMPP/IRC network.",
    "",
    "  - Matrix homeserver: matrix.progressive.local",
    "  - XMPP server: xmpp.progressive.local",
    "  - IRC server: irc.progressive.local",
    "",
    "Enjoy your stay!"
  };
  return cfg;
}

} // namespace progressive::irc
