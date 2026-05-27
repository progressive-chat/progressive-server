// bridge_admin.cpp - Bridge Administration & Integration Manager
// Implements IRC bridge admin, email bridge admin, webhook bridge admin,
// bot/SDK admin, integration manager, and third-party identifier lookup.
//
// Equivalent to:
//   synapse/handlers/bridge.py (conceptual)
//   synapse/appservice/api.py (bridge portions)
//   synapse/third_party_id/ (third-party identifier resolution)
//   synapse/rest/admin/bridges.py
//
// Target: 2000+ lines of production-grade C++.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
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
#include <vector>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations
// ============================================================================
class IRCBridgeAdmin;
class IRCConnection;
class IRCChannelMapping;
class IRCNicknameRegistry;
class IRCConnectionPool;

class EmailBridgeAdmin;
class EmailToMatrixGateway;
class EmailInviteManager;
class EmailNotificationTemplates;

class WebhookBridgeAdmin;
class WebhookRegistration;
class WebhookRouter;
class WebhookEventFilter;

class BotSDKAdmin;
class BotUserManager;
class BotAccessTokenManager;
class AppServiceBotRegistry;

class IntegrationManager;
class IntegrationRegistry;
class WidgetIntegration;
class BridgeIntegration;
class BotIntegration;

class ThirdPartyLookup;
class ThirdPartyIdentifierResolver;
class EmailLookupProvider;
class PhoneLookupProvider;
class IRCLookupProvider;

// ============================================================================
// Utility helpers (anonymous namespace)
// ============================================================================
namespace {

  bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
  }

  bool ends_with(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() &&
           s.substr(s.size() - suffix.size()) == suffix;
  }

  std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
  }

  std::string to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
  }

  std::string trim(std::string s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
  }

  std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> tokens;
    std::stringstream ss(s);
    std::string token;
    while (std::getline(ss, token, delim)) {
      if (!token.empty()) tokens.push_back(token);
    }
    return tokens;
  }

  std::string generate_token(size_t length = 64) {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);
    std::string token;
    token.reserve(length);
    for (size_t i = 0; i < length; ++i)
      token += charset[dist(rng)];
    return token;
  }

  std::string generate_uuid() {
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<int> dist(0, 15);
    const char* hex = "0123456789abcdef";
    std::string uuid;
    uuid.reserve(36);
    for (int i = 0; i < 36; ++i) {
      if (i == 8 || i == 13 || i == 18 || i == 23) {
        uuid += '-';
      } else if (i == 14) {
        uuid += '4';
      } else if (i == 19) {
        uuid += hex[(dist(rng) & 0x3) | 0x8];
      } else {
        uuid += hex[dist(rng)];
      }
    }
    return uuid;
  }

  std::string current_iso8601() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) %
              1000;
    std::tm tm_buf;
    gmtime_r(&t, &tm_buf);
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S") << '.' << std::setw(3)
        << std::setfill('0') << ms.count() << "Z";
    return oss.str();
  }

  int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
  }

  int64_t now_sec() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
  }

  bool is_valid_email(const std::string& email) {
    static const std::regex email_regex(
        R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)",
        std::regex::ECMAScript | std::regex::optimize);
    return std::regex_match(email, email_regex);
  }

  bool is_valid_phone(const std::string& phone) {
    static const std::regex phone_regex(
        R"(^\+[1-9]\d{6,14}$)",
        std::regex::ECMAScript | std::regex::optimize);
    return std::regex_match(phone, phone_regex);
  }

  bool is_valid_matrix_id(const std::string& id) {
    static const std::regex mxid_regex(
        R"(^@[a-zA-Z0-9._=\-/]+:[a-zA-Z0-9.-]+$)",
        std::regex::ECMAScript | std::regex::optimize);
    return std::regex_match(id, mxid_regex);
  }

  std::string sanitize_nickname(const std::string& nick) {
    std::string result;
    result.reserve(nick.size());
    for (char c : nick) {
      if (std::isalnum(static_cast<unsigned char>(c)) ||
          c == '-' || c == '_' || c == '[' || c == ']' ||
          c == '\\' || c == '`' || c == '^' || c == '{' ||
          c == '|' || c == '}') {
        result += c;
      }
    }
    if (result.empty()) return "user";
    if (std::isdigit(static_cast<unsigned char>(result[0])))
      result = "u" + result;
    if (result.size() > 30) result.resize(30);
    return result;
  }

}  // anonymous namespace

// ============================================================================
// STATUS ENUMS
// ============================================================================

enum class BridgeConnectionStatus {
  DISCONNECTED = 0,
  CONNECTING = 1,
  CONNECTED = 2,
  RECONNECTING = 3,
  ERROR = 4,
  AUTH_FAILED = 5,
  RATE_LIMITED = 6,
  SHUTTING_DOWN = 7
};

std::string bridge_status_str(BridgeConnectionStatus s) {
  switch (s) {
    case BridgeConnectionStatus::DISCONNECTED:  return "disconnected";
    case BridgeConnectionStatus::CONNECTING:    return "connecting";
    case BridgeConnectionStatus::CONNECTED:     return "connected";
    case BridgeConnectionStatus::RECONNECTING:  return "reconnecting";
    case BridgeConnectionStatus::ERROR:         return "error";
    case BridgeConnectionStatus::AUTH_FAILED:   return "auth_failed";
    case BridgeConnectionStatus::RATE_LIMITED:   return "rate_limited";
    case BridgeConnectionStatus::SHUTTING_DOWN:  return "shutting_down";
    default: return "unknown";
  }
}

BridgeConnectionStatus bridge_status_from_str(const std::string& s) {
  if (s == "disconnected")  return BridgeConnectionStatus::DISCONNECTED;
  if (s == "connecting")    return BridgeConnectionStatus::CONNECTING;
  if (s == "connected")     return BridgeConnectionStatus::CONNECTED;
  if (s == "reconnecting")  return BridgeConnectionStatus::RECONNECTING;
  if (s == "error")        return BridgeConnectionStatus::ERROR;
  if (s == "auth_failed")   return BridgeConnectionStatus::AUTH_FAILED;
  if (s == "rate_limited")  return BridgeConnectionStatus::RATE_LIMITED;
  if (s == "shutting_down") return BridgeConnectionStatus::SHUTTING_DOWN;
  return BridgeConnectionStatus::DISCONNECTED;
}

enum class IntegrationType {
  WIDGET = 0,
  BOT = 1,
  BRIDGE = 2,
  WEBHOOK = 3,
  GENERIC = 4
};

std::string integration_type_str(IntegrationType t) {
  switch (t) {
    case IntegrationType::WIDGET:  return "widget";
    case IntegrationType::BOT:     return "bot";
    case IntegrationType::BRIDGE:  return "bridge";
    case IntegrationType::WEBHOOK: return "webhook";
    case IntegrationType::GENERIC: return "generic";
    default: return "unknown";
  }
}

IntegrationType integration_type_from_str(const std::string& s) {
  if (s == "widget")  return IntegrationType::WIDGET;
  if (s == "bot")     return IntegrationType::BOT;
  if (s == "bridge")  return IntegrationType::BRIDGE;
  if (s == "webhook") return IntegrationType::WEBHOOK;
  return IntegrationType::GENERIC;
}

enum class ThirdPartyMedium {
  EMAIL = 0,
  MSISDN = 1,
  IRC_NICK = 2,
  TELEGRAM = 3,
  DISCORD = 4,
  CUSTOM = 5
};

std::string third_party_medium_str(ThirdPartyMedium m) {
  switch (m) {
    case ThirdPartyMedium::EMAIL:     return "email";
    case ThirdPartyMedium::MSISDN:    return "msisdn";
    case ThirdPartyMedium::IRC_NICK:  return "irc_nick";
    case ThirdPartyMedium::TELEGRAM:  return "telegram";
    case ThirdPartyMedium::DISCORD:   return "discord";
    case ThirdPartyMedium::CUSTOM:    return "custom";
    default: return "unknown";
  }
}

ThirdPartyMedium third_party_medium_from_str(const std::string& s) {
  if (s == "email")     return ThirdPartyMedium::EMAIL;
  if (s == "msisdn")    return ThirdPartyMedium::MSISDN;
  if (s == "irc_nick")  return ThirdPartyMedium::IRC_NICK;
  if (s == "telegram")  return ThirdPartyMedium::TELEGRAM;
  if (s == "discord")   return ThirdPartyMedium::DISCORD;
  return ThirdPartyMedium::CUSTOM;
}

// ============================================================================
// PART 1: IRC BRIDGE ADMIN
// Manages IRC connections, channel mappings (Matrix room <-> IRC channel),
// nickname management, and IRC connection status monitoring.
// ============================================================================

// --------------------------------------------------------------------------
// IRCNicknameRegistry - tracks IRC nickname ownership and conflicts
// --------------------------------------------------------------------------
class IRCNicknameRegistry {
public:
  struct NickEntry {
    std::string nickname;
    std::string mxid;          // owning Matrix user
    std::string irc_server;    // which IRC server
    int64_t registered_at;
    int64_t last_seen;
    bool online{false};
    std::string virtual_user;  // ghost MXID for this nick
  };

  // Register a nickname for a user on a server
  bool register_nickname(const std::string& nickname,
                         const std::string& mxid,
                         const std::string& irc_server) {
    std::unique_lock lock(mutex_);
    std::string key = make_key(nickname, irc_server);

    if (auto it = nicks_.find(key); it != nicks_.end()) {
      // Nickname already registered - check ownership
      if (it->second.mxid == mxid) {
        // Same user, update last_seen
        it->second.last_seen = now_sec();
        return true;
      }
      // Conflict - different user
      return false;
    }

    NickEntry entry;
    entry.nickname = nickname;
    entry.mxid = mxid;
    entry.irc_server = irc_server;
    entry.registered_at = now_sec();
    entry.last_seen = now_sec();
    entry.online = true;
    entry.virtual_user = make_virtual_user(nickname, irc_server);

    nicks_[key] = std::move(entry);
    return true;
  }

  // Release a nickname
  bool release_nickname(const std::string& nickname,
                        const std::string& irc_server,
                        const std::string& mxid) {
    std::unique_lock lock(mutex_);
    std::string key = make_key(nickname, irc_server);

    auto it = nicks_.find(key);
    if (it != nicks_.end() && it->second.mxid == mxid) {
      it->second.online = false;
      nicks_.erase(it);
      return true;
    }
    return false;
  }

  // Set online/offline status
  bool set_online_status(const std::string& nickname,
                         const std::string& irc_server, bool online) {
    std::unique_lock lock(mutex_);
    std::string key = make_key(nickname, irc_server);
    auto it = nicks_.find(key);
    if (it != nicks_.end()) {
      it->second.online = online;
      if (online) it->second.last_seen = now_sec();
      return true;
    }
    return false;
  }

  // Look up the Matrix user owning a nickname
  std::optional<std::string> lookup_owner(const std::string& nickname,
                                          const std::string& irc_server) {
    std::shared_lock lock(mutex_);
    std::string key = make_key(nickname, irc_server);
    auto it = nicks_.find(key);
    if (it != nicks_.end()) return it->second.mxid;
    return std::nullopt;
  }

  // Look up virtual/ghost user for a nickname
  std::optional<std::string> lookup_virtual_user(const std::string& nickname,
                                                  const std::string& irc_server) {
    std::shared_lock lock(mutex_);
    std::string key = make_key(nickname, irc_server);
    auto it = nicks_.find(key);
    if (it != nicks_.end()) return it->second.virtual_user;
    return std::nullopt;
  }

  // List all nicknames for a Matrix user
  std::vector<NickEntry> list_nicks_for_user(const std::string& mxid) {
    std::shared_lock lock(mutex_);
    std::vector<NickEntry> result;
    for (const auto& [key, entry] : nicks_) {
      if (entry.mxid == mxid) result.push_back(entry);
    }
    return result;
  }

  // List all nicknames on a server
  std::vector<NickEntry> list_nicks_for_server(const std::string& irc_server) {
    std::shared_lock lock(mutex_);
    std::vector<NickEntry> result;
    for (const auto& [key, entry] : nicks_) {
      if (entry.irc_server == irc_server) result.push_back(entry);
    }
    return result;
  }

  json to_json() {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& [key, entry] : nicks_) {
      arr.push_back({
          {"nickname", entry.nickname},
          {"mxid", entry.mxid},
          {"irc_server", entry.irc_server},
          {"online", entry.online},
          {"virtual_user", entry.virtual_user},
          {"registered_at", entry.registered_at},
          {"last_seen", entry.last_seen}
      });
    }
    return arr;
  }

  size_t count() const {
    std::shared_lock lock(mutex_);
    return nicks_.size();
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, NickEntry> nicks_;

  static std::string make_key(const std::string& nickname,
                              const std::string& server) {
    return to_lower(nickname) + "@" + server;
  }

  static std::string make_virtual_user(const std::string& nickname,
                                       const std::string& server) {
    return "@irc_" + sanitize_nickname(nickname) + ":" + server;
  }
};

// --------------------------------------------------------------------------
// IRCChannelMapping - maps Matrix room to IRC channel
// --------------------------------------------------------------------------
class IRCChannelMapping {
public:
  struct Mapping {
    std::string id;            // unique mapping ID
    std::string matrix_room_id;
    std::string irc_channel;   // e.g. "#matrix"
    std::string irc_server;
    bool bidirectional{true};  // messages flow both ways
    bool enabled{true};
    bool autojoin{true};
    std::string bridge_user;   // bot user that bridges messages
    int64_t created_at;
    int64_t updated_at;
    json extra_config;         // per-channel overrides

    Mapping() : created_at(now_sec()), updated_at(now_sec()) {}
  };

  // Create a new channel mapping
  Mapping create_mapping(const std::string& matrix_room,
                         const std::string& irc_channel,
                         const std::string& irc_server,
                         const std::string& bridge_user,
                         bool bidirectional = true,
                         const json& extra = json::object()) {
    std::unique_lock lock(mutex_);
    Mapping m;
    m.id = "irc_map_" + generate_uuid();
    m.matrix_room_id = matrix_room;
    m.irc_channel = irc_channel;
    m.irc_server = irc_server;
    m.bidirectional = bidirectional;
    m.bridge_user = bridge_user;
    m.extra_config = extra;
    m.created_at = now_sec();
    m.updated_at = now_sec();

    // Index
    mappings_[m.id] = m;
    mx_to_irc_[matrix_room][irc_server].push_back(m.id);
    irc_to_mx_[make_irc_key(irc_channel, irc_server)] = m.id;

    return m;
  }

  // Update a mapping
  bool update_mapping(const std::string& mapping_id, const json& updates) {
    std::unique_lock lock(mutex_);
    auto it = mappings_.find(mapping_id);
    if (it == mappings_.end()) return false;

    if (updates.contains("enabled"))
      it->second.enabled = updates["enabled"].get<bool>();
    if (updates.contains("bidirectional"))
      it->second.bidirectional = updates["bidirectional"].get<bool>();
    if (updates.contains("autojoin"))
      it->second.autojoin = updates["autojoin"].get<bool>();
    if (updates.contains("bridge_user"))
      it->second.bridge_user = updates["bridge_user"].get<std::string>();
    if (updates.contains("extra_config"))
      it->second.extra_config = updates["extra_config"];

    it->second.updated_at = now_sec();
    return true;
  }

  // Delete a mapping
  bool delete_mapping(const std::string& mapping_id) {
    std::unique_lock lock(mutex_);
    auto it = mappings_.find(mapping_id);
    if (it == mappings_.end()) return false;

    // Clean indices
    auto& server_map = mx_to_irc_[it->second.matrix_room_id][it->second.irc_server];
    server_map.erase(
        std::remove(server_map.begin(), server_map.end(), mapping_id),
        server_map.end());

    std::string ik = make_irc_key(it->second.irc_channel, it->second.irc_server);
    irc_to_mx_.erase(ik);

    mappings_.erase(it);
    return true;
  }

  // Get mapping by ID
  std::optional<Mapping> get_mapping(const std::string& mapping_id) {
    std::shared_lock lock(mutex_);
    auto it = mappings_.find(mapping_id);
    if (it != mappings_.end()) return it->second;
    return std::nullopt;
  }

  // Get Matrix room for IRC channel
  std::optional<std::string> get_matrix_room(const std::string& irc_channel,
                                              const std::string& irc_server) {
    std::shared_lock lock(mutex_);
    std::string key = make_irc_key(irc_channel, irc_server);
    auto it = irc_to_mx_.find(key);
    if (it != irc_to_mx_.end()) {
      auto mit = mappings_.find(it->second);
      if (mit != mappings_.end() && mit->second.enabled)
        return mit->second.matrix_room_id;
    }
    return std::nullopt;
  }

  // Get IRC channels for a Matrix room
  std::vector<Mapping> get_irc_channels(const std::string& matrix_room) {
    std::shared_lock lock(mutex_);
    std::vector<Mapping> result;
    auto it = mx_to_irc_.find(matrix_room);
    if (it != mx_to_irc_.end()) {
      for (const auto& [server, ids] : it->second) {
        for (const auto& id : ids) {
          auto mit = mappings_.find(id);
          if (mit != mappings_.end()) result.push_back(mit->second);
        }
      }
    }
    return result;
  }

  // List all mappings for a server
  std::vector<Mapping> list_mappings_for_server(const std::string& irc_server) {
    std::shared_lock lock(mutex_);
    std::vector<Mapping> result;
    for (const auto& [id, m] : mappings_) {
      if (m.irc_server == irc_server) result.push_back(m);
    }
    return result;
  }

  // Check if mapping exists
  bool mapping_exists(const std::string& irc_channel,
                      const std::string& irc_server) {
    std::shared_lock lock(mutex_);
    return irc_to_mx_.count(make_irc_key(irc_channel, irc_server)) > 0;
  }

  // Toggle mapping
  bool set_enabled(const std::string& mapping_id, bool enabled) {
    std::unique_lock lock(mutex_);
    auto it = mappings_.find(mapping_id);
    if (it != mappings_.end()) {
      it->second.enabled = enabled;
      it->second.updated_at = now_sec();
      return true;
    }
    return false;
  }

  json to_json() {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& [id, m] : mappings_) {
      arr.push_back({
          {"id", m.id},
          {"matrix_room_id", m.matrix_room_id},
          {"irc_channel", m.irc_channel},
          {"irc_server", m.irc_server},
          {"bidirectional", m.bidirectional},
          {"enabled", m.enabled},
          {"autojoin", m.autojoin},
          {"bridge_user", m.bridge_user},
          {"created_at", m.created_at},
          {"updated_at", m.updated_at},
          {"extra_config", m.extra_config}
      });
    }
    return arr;
  }

  size_t count() const {
    std::shared_lock lock(mutex_);
    return mappings_.size();
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, Mapping> mappings_;
  // mx_to_irc_[room_id][server] = vector of mapping IDs
  std::unordered_map<std::string,
      std::unordered_map<std::string, std::vector<std::string>>> mx_to_irc_;
  // irc_to_mx_[channel@server] = mapping ID
  std::unordered_map<std::string, std::string> irc_to_mx_;

  static std::string make_irc_key(const std::string& channel,
                                  const std::string& server) {
    return to_lower(channel) + "@" + server;
  }
};

// --------------------------------------------------------------------------
// IRCConnection - a single IRC server connection
// --------------------------------------------------------------------------
class IRCConnection {
public:
  struct Config {
    std::string server_host;
    int server_port{6667};
    bool use_ssl{false};
    std::string nickname;
    std::string username;
    std::string realname;
    std::string nickserv_password;  // NickServ auth
    std::string password;           // server password
    std::vector<std::string> autojoin_channels;
    int reconnect_delay_ms{5000};
    int max_reconnect_attempts{10};
    int ping_interval_sec{60};
    int connection_timeout_sec{30};
  };

  struct ConnectionStats {
    BridgeConnectionStatus status{BridgeConnectionStatus::DISCONNECTED};
    int64_t connected_since{0};
    int64_t last_message_at{0};
    int64_t messages_sent{0};
    int64_t messages_received{0};
    int64_t reconnect_attempts{0};
    int64_t pings_sent{0};
    int64_t pongs_received{0};
    double avg_latency_ms{0};
    std::string last_error;
    std::string version_string;
    int channel_count{0};
  };

  explicit IRCConnection(const Config& cfg)
      : config_(cfg), stats_() {
    stats_.status = BridgeConnectionStatus::DISCONNECTED;
  }

  // Connection lifecycle
  bool connect(const std::string& identity) {
    connection_id_ = identity;
    stats_.status = BridgeConnectionStatus::CONNECTING;
    stats_.reconnect_attempts = 0;

    // Simulated TCP connect (real impl would use sockets)
    bool ok = simulate_connect();
    if (!ok) {
      stats_.status = BridgeConnectionStatus::ERROR;
      stats_.last_error = "Connection refused";
      return false;
    }

    // Simulated IRC handshake
    ok = simulate_handshake();
    if (!ok) {
      stats_.status = BridgeConnectionStatus::AUTH_FAILED;
      stats_.last_error = "NickServ authentication failed";
      return false;
    }

    stats_.status = BridgeConnectionStatus::CONNECTED;
    stats_.connected_since = now_ms();
    stats_.version_string = "progressive-irc-bridge-1.0";

    // Auto-join channels
    for (const auto& ch : config_.autojoin_channels) {
      join_channel(ch);
    }

    return true;
  }

  void disconnect() {
    stats_.status = BridgeConnectionStatus::SHUTTING_DOWN;
    stats_.connected_since = 0;
    stats_.status = BridgeConnectionStatus::DISCONNECTED;
  }

  bool reconnect() {
    if (stats_.reconnect_attempts >= config_.max_reconnect_attempts) {
      stats_.status = BridgeConnectionStatus::ERROR;
      stats_.last_error = "Max reconnect attempts exceeded";
      return false;
    }
    stats_.status = BridgeConnectionStatus::RECONNECTING;
    stats_.reconnect_attempts++;

    return connect(connection_id_);
  }

  // Channel operations
  bool join_channel(const std::string& channel) {
    if (std::find(joined_channels_.begin(), joined_channels_.end(), channel)
        != joined_channels_.end()) {
      return true; // already joined
    }
    joined_channels_.push_back(channel);
    stats_.channel_count = static_cast<int>(joined_channels_.size());
    return true;
  }

  bool part_channel(const std::string& channel) {
    auto it = std::find(joined_channels_.begin(), joined_channels_.end(), channel);
    if (it != joined_channels_.end()) {
      joined_channels_.erase(it);
      stats_.channel_count = static_cast<int>(joined_channels_.size());
      return true;
    }
    return false;
  }

  std::vector<std::string> list_channels() const {
    return joined_channels_;
  }

  bool is_in_channel(const std::string& channel) const {
    return std::find(joined_channels_.begin(), joined_channels_.end(), channel)
           != joined_channels_.end();
  }

  // Nickname operations
  bool change_nickname(const std::string& new_nick) {
    config_.nickname = new_nick;
    return true; // simulated
  }

  // Status
  BridgeConnectionStatus status() const { return stats_.status; }
  const ConnectionStats& stats() const { return stats_; }
  const Config& config() const { return config_; }
  const std::string& connection_id() const { return connection_id_; }

  json status_json() const {
    return {
      {"connection_id", connection_id_},
      {"server", config_.server_host + ":" + std::to_string(config_.server_port)},
      {"nickname", config_.nickname},
      {"status", bridge_status_str(stats_.status)},
      {"ssl", config_.use_ssl},
      {"connected_since", stats_.connected_since},
      {"messages_sent", stats_.messages_sent},
      {"messages_received", stats_.messages_received},
      {"reconnect_attempts", stats_.reconnect_attempts},
      {"channels", joined_channels_},
      {"channel_count", stats_.channel_count},
      {"avg_latency_ms", stats_.avg_latency_ms},
      {"version", stats_.version_string},
      {"last_error", stats_.last_error}
    };
  }

  // Increment message counters
  void record_message_sent() { stats_.messages_sent++; stats_.last_message_at = now_ms(); }
  void record_message_rcvd() { stats_.messages_received++; stats_.last_message_at = now_ms(); }
  void record_ping() { stats_.pings_sent++; }
  void record_pong(int64_t latency_ms) {
    stats_.pongs_received++;
    // Exponential moving average for latency
    stats_.avg_latency_ms = stats_.avg_latency_ms * 0.9 + latency_ms * 0.1;
  }

private:
  Config config_;
  ConnectionStats stats_;
  std::string connection_id_;
  std::vector<std::string> joined_channels_;

  bool simulate_connect() {
    // In real impl: socket() -> connect() -> SSL handshake if needed
    return true;
  }

  bool simulate_handshake() {
    // In real impl: send NICK, USER, handle NickServ, wait for 001
    return !config_.nickserv_password.empty() || true;
  }
};

// --------------------------------------------------------------------------
// IRCConnectionPool - manages multiple IRC server connections
// --------------------------------------------------------------------------
class IRCConnectionPool {
public:
  // Add a connection
  std::string add_connection(const IRCConnection::Config& cfg) {
    std::unique_lock lock(mutex_);
    std::string conn_id = "irc_conn_" + generate_uuid();
    auto conn = std::make_shared<IRCConnection>(cfg);
    connections_[conn_id] = conn;
    return conn_id;
  }

  // Remove a connection
  bool remove_connection(const std::string& conn_id) {
    std::unique_lock lock(mutex_);
    auto it = connections_.find(conn_id);
    if (it != connections_.end()) {
      it->second->disconnect();
      connections_.erase(it);
      return true;
    }
    return false;
  }

  // Get connection
  std::shared_ptr<IRCConnection> get_connection(const std::string& conn_id) {
    std::shared_lock lock(mutex_);
    auto it = connections_.find(conn_id);
    if (it != connections_.end()) return it->second;
    return nullptr;
  }

  // Connect all connections
  bool connect_all() {
    std::shared_lock lock(mutex_);
    bool all_ok = true;
    for (auto& [id, conn] : connections_) {
      if (!conn->connect(id)) all_ok = false;
    }
    return all_ok;
  }

  // Connect a specific connection
  bool connect_one(const std::string& conn_id) {
    auto conn = get_connection(conn_id);
    if (!conn) return false;
    return conn->connect(conn_id);
  }

  // Disconnect all
  void disconnect_all() {
    std::shared_lock lock(mutex_);
    for (auto& [id, conn] : connections_) {
      conn->disconnect();
    }
  }

  // Reconnect all disconnected
  int reconnect_all() {
    std::shared_lock lock(mutex_);
    int count = 0;
    for (auto& [id, conn] : connections_) {
      if (conn->status() == BridgeConnectionStatus::DISCONNECTED ||
          conn->status() == BridgeConnectionStatus::ERROR) {
        if (conn->reconnect()) count++;
      }
    }
    return count;
  }

  // Status for all connections
  json all_status() {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& [id, conn] : connections_) {
      arr.push_back(conn->status_json());
    }
    return arr;
  }

  // Status for one connection
  json connection_status(const std::string& conn_id) {
    auto conn = get_connection(conn_id);
    if (!conn) return {{"error", "not_found"}};
    return conn->status_json();
  }

  // Summary
  json summary() {
    std::shared_lock lock(mutex_);
    int connected = 0, disconnected = 0, error = 0;
    for (const auto& [id, conn] : connections_) {
      switch (conn->status()) {
        case BridgeConnectionStatus::CONNECTED:    connected++; break;
        case BridgeConnectionStatus::DISCONNECTED: disconnected++; break;
        case BridgeConnectionStatus::ERROR:
        case BridgeConnectionStatus::AUTH_FAILED:  error++; break;
        default: break;
      }
    }
    return {
      {"total_connections", connections_.size()},
      {"connected", connected},
      {"disconnected", disconnected},
      {"error", error}
    };
  }

  size_t count() const {
    std::shared_lock lock(mutex_);
    return connections_.size();
  }

  // Find connections by server
  std::vector<std::string> find_by_server(const std::string& host) {
    std::shared_lock lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [id, conn] : connections_) {
      if (conn->config().server_host == host) result.push_back(id);
    }
    return result;
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, std::shared_ptr<IRCConnection>> connections_;
};

// ============================================================================
// IRCBridgeAdmin - top-level IRC bridge administration
// ============================================================================
class IRCBridgeAdmin {
public:
  IRCBridgeAdmin()
      : connections_(std::make_unique<IRCConnectionPool>()),
        mappings_(std::make_unique<IRCChannelMapping>()),
        nicks_(std::make_unique<IRCNicknameRegistry>()) {}

  // ---- Connection Management ----

  std::string add_irc_server(const std::string& host, int port,
                             const std::string& nickname,
                             const std::string& nickserv_pass = "",
                             bool ssl = false,
                             const std::vector<std::string>& autojoin = {}) {
    IRCConnection::Config cfg;
    cfg.server_host = host;
    cfg.server_port = port;
    cfg.use_ssl = ssl;
    cfg.nickname = nickname;
    cfg.username = nickname;
    cfg.realname = "Progressive Matrix Bridge";
    cfg.nickserv_password = nickserv_pass;
    cfg.autojoin_channels = autojoin;
    return connections_->add_connection(cfg);
  }

  bool remove_irc_server(const std::string& conn_id) {
    return connections_->remove_connection(conn_id);
  }

  bool connect_server(const std::string& conn_id) {
    return connections_->connect_one(conn_id);
  }

  bool disconnect_server(const std::string& conn_id) {
    auto conn = connections_->get_connection(conn_id);
    if (!conn) return false;
    conn->disconnect();
    return true;
  }

  int reconnect_all_servers() {
    return connections_->reconnect_all();
  }

  json get_all_connections_status() {
    return connections_->all_status();
  }

  json get_connection_status(const std::string& conn_id) {
    return connections_->connection_status(conn_id);
  }

  json get_connection_summary() {
    return connections_->summary();
  }

  // ---- Channel Mapping Management ----

  std::string map_channel(const std::string& matrix_room,
                          const std::string& irc_channel,
                          const std::string& irc_server,
                          const std::string& bridge_user) {
    auto m = mappings_->create_mapping(matrix_room, irc_channel,
                                        irc_server, bridge_user);
    return m.id;
  }

  bool unmap_channel(const std::string& mapping_id) {
    return mappings_->delete_mapping(mapping_id);
  }

  bool update_channel_mapping(const std::string& mapping_id,
                               const json& updates) {
    return mappings_->update_mapping(mapping_id, updates);
  }

  std::optional<std::string> get_matrix_room_for_irc(
      const std::string& irc_channel, const std::string& irc_server) {
    return mappings_->get_matrix_room(irc_channel, irc_server);
  }

  std::vector<IRCChannelMapping::Mapping> get_irc_channels_for_room(
      const std::string& matrix_room) {
    return mappings_->get_irc_channels(matrix_room);
  }

  json get_all_mappings() {
    return mappings_->to_json();
  }

  // ---- Nickname Management ----

  bool register_nick(const std::string& nickname, const std::string& mxid,
                     const std::string& irc_server) {
    return nicks_->register_nickname(nickname, mxid, irc_server);
  }

  bool release_nick(const std::string& nickname, const std::string& irc_server,
                    const std::string& mxid) {
    return nicks_->release_nickname(nickname, irc_server, mxid);
  }

  json get_all_nicks() {
    return nicks_->to_json();
  }

  // Access internals
  IRCConnectionPool& connection_pool() { return *connections_; }
  IRCChannelMapping& channel_mappings() { return *mappings_; }
  IRCNicknameRegistry& nicknames() { return *nicks_; }

private:
  std::unique_ptr<IRCConnectionPool> connections_;
  std::unique_ptr<IRCChannelMapping> mappings_;
  std::unique_ptr<IRCNicknameRegistry> nicks_;
};

// ============================================================================
// PART 2: EMAIL BRIDGE ADMIN
// Email-to-Matrix gateway, invite by email, email notification templates.
// ============================================================================

// --------------------------------------------------------------------------
// EmailToMatrixGateway - receives emails and posts them to Matrix rooms
// --------------------------------------------------------------------------
class EmailToMatrixGateway {
public:
  struct EmailRoute {
    std::string id;
    std::string email_address;   // inbound email address
    std::string matrix_room_id;  // target room
    bool strip_signatures{true};
    bool convert_html{true};
    size_t max_attachment_mb{10};
    std::vector<std::string> allowed_senders;  // empty = all allowed
    int64_t created_at;
    bool enabled{true};
    int64_t messages_processed{0};
  };

  struct InboundEmail {
    std::string message_id;
    std::string from;
    std::string to;
    std::string subject;
    std::string body_text;
    std::string body_html;
    int64_t received_at;
    std::vector<std::string> attachment_paths;
  };

  // Create an email route
  EmailRoute create_route(const std::string& email,
                          const std::string& room_id) {
    std::unique_lock lock(mutex_);
    EmailRoute route;
    route.id = "email_route_" + generate_uuid();
    route.email_address = email;
    route.matrix_room_id = room_id;
    route.created_at = now_sec();
    routes_[route.id] = route;
    routes_by_email_[to_lower(email)] = route.id;
    return route;
  }

  bool delete_route(const std::string& route_id) {
    std::unique_lock lock(mutex_);
    auto it = routes_.find(route_id);
    if (it != routes_.end()) {
      routes_by_email_.erase(to_lower(it->second.email_address));
      routes_.erase(it);
      return true;
    }
    return false;
  }

  bool update_route(const std::string& route_id, const json& updates) {
    std::unique_lock lock(mutex_);
    auto it = routes_.find(route_id);
    if (it == routes_.end()) return false;

    if (updates.contains("enabled"))
      it->second.enabled = updates["enabled"].get<bool>();
    if (updates.contains("strip_signatures"))
      it->second.strip_signatures = updates["strip_signatures"].get<bool>();
    if (updates.contains("convert_html"))
      it->second.convert_html = updates["convert_html"].get<bool>();
    if (updates.contains("max_attachment_mb"))
      it->second.max_attachment_mb = updates["max_attachment_mb"].get<size_t>();
    if (updates.contains("allowed_senders"))
      it->second.allowed_senders = updates["allowed_senders"].get<std::vector<std::string>>();

    // Re-index if email changed
    if (updates.contains("email_address")) {
      routes_by_email_.erase(to_lower(it->second.email_address));
      it->second.email_address = updates["email_address"].get<std::string>();
      routes_by_email_[to_lower(it->second.email_address)] = route_id;
    }
    return true;
  }

  // Process an inbound email
  json process_inbound(const InboundEmail& email) {
    std::shared_lock lock(mutex_);
    std::string lookup = to_lower(email.to);
    auto it = routes_by_email_.find(lookup);
    if (it == routes_by_email_.end()) {
      return {{"error", "no_route"}, {"email", email.to}};
    }

    auto rit = routes_.find(it->second);
    if (rit == routes_.end() || !rit->second.enabled) {
      return {{"error", "route_disabled"}};
    }

    auto& route = rit->second;

    // Check allowed senders
    if (!route.allowed_senders.empty()) {
      bool allowed = false;
      for (const auto& sender : route.allowed_senders) {
        if (sender == email.from || ends_with(email.from, "@" + sender)) {
          allowed = true;
          break;
        }
      }
      if (!allowed) {
        return {{"error", "sender_not_allowed"}, {"from", email.from}};
      }
    }

    // Build Matrix message
    json matrix_event;
    matrix_event["msgtype"] = "m.text";
    matrix_event["room_id"] = route.matrix_room_id;

    std::string body = "**From:** " + email.from + "\n";
    if (!email.subject.empty())
      body += "**Subject:** " + email.subject + "\n\n";
    body += email.body_text;

    if (route.strip_signatures) {
      body = strip_email_signature(body);
    }

    matrix_event["body"] = body;

    if (route.convert_html && !email.body_html.empty()) {
      matrix_event["format"] = "org.matrix.custom.html";
      matrix_event["formatted_body"] = email.body_html;
    }

    // Increment counter (const cast for shared_lock stats)
    const_cast<EmailRoute&>(route).messages_processed++;

    matrix_event["route_id"] = route.id;
    matrix_event["email_message_id"] = email.message_id;
    return matrix_event;
  }

  // Lookup route for an email address
  std::optional<EmailRoute> find_route(const std::string& email) {
    std::shared_lock lock(mutex_);
    auto it = routes_by_email_.find(to_lower(email));
    if (it != routes_by_email_.end()) {
      auto rit = routes_.find(it->second);
      if (rit != routes_.end()) return rit->second;
    }
    return std::nullopt;
  }

  json list_routes() {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& [id, route] : routes_) {
      arr.push_back({
          {"id", route.id},
          {"email_address", route.email_address},
          {"matrix_room_id", route.matrix_room_id},
          {"enabled", route.enabled},
          {"messages_processed", route.messages_processed}
      });
    }
    return arr;
  }

  size_t count() const {
    std::shared_lock lock(mutex_);
    return routes_.size();
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, EmailRoute> routes_;
  std::unordered_map<std::string, std::string> routes_by_email_;

  static std::string strip_email_signature(const std::string& body) {
    // Remove common signature markers
    std::string result = body;
    size_t sig_pos = std::string::npos;

    // Look for signature delimiter "-- "
    sig_pos = result.rfind("\n-- \n");
    if (sig_pos != std::string::npos) {
      result = result.substr(0, sig_pos);
      return result;
    }

    // Look for common signature blocks
    static const std::vector<std::string> sig_markers = {
      "\n--\n", "\nSent from my", "\nBest regards,\n",
      "\nCheers,\n", "\nThanks,\n"
    };
    for (const auto& marker : sig_markers) {
      sig_pos = result.rfind(marker);
      if (sig_pos != std::string::npos && sig_pos > result.size() / 2) {
        result = result.substr(0, sig_pos);
        break;
      }
    }
    return result;
  }
};

// --------------------------------------------------------------------------
// EmailInviteManager - manages inviting users via email
// --------------------------------------------------------------------------
class EmailInviteManager {
public:
  struct EmailInvite {
    std::string id;
    std::string email;
    std::string room_id;
    std::string invited_by;
    std::string invite_token;
    int64_t created_at;
    int64_t expires_at; // 0 = never
    bool accepted{false};
    bool sent{false};
    int send_attempts{0};
  };

  // Create an email invite
  EmailInvite create_invite(const std::string& email,
                            const std::string& room_id,
                            const std::string& invited_by,
                            int64_t ttl_sec = 86400 * 7) { // 7 days default
    std::unique_lock lock(mutex_);
    EmailInvite inv;
    inv.id = "email_inv_" + generate_uuid();
    inv.email = email;
    inv.room_id = room_id;
    inv.invited_by = invited_by;
    inv.invite_token = generate_token(32);
    inv.created_at = now_sec();
    inv.expires_at = (ttl_sec > 0) ? now_sec() + ttl_sec : 0;
    invites_[inv.id] = inv;
    return inv;
  }

  // Lookup invite by token
  std::optional<EmailInvite> find_by_token(const std::string& token) {
    std::shared_lock lock(mutex_);
    for (const auto& [id, inv] : invites_) {
      if (inv.invite_token == token && !inv.accepted) {
        if (inv.expires_at == 0 || inv.expires_at > now_sec()) {
          return inv;
        }
      }
    }
    return std::nullopt;
  }

  // Accept an invite
  bool accept_invite(const std::string& token, const std::string& mxid) {
    std::unique_lock lock(mutex_);
    for (auto& [id, inv] : invites_) {
      if (inv.invite_token == token && !inv.accepted) {
        if (inv.expires_at == 0 || inv.expires_at > now_sec()) {
          inv.accepted = true;
          inv.accepted_by_ = mxid;
          inv.accepted_at_ = now_sec();
          return true;
        }
      }
    }
    return false;
  }

  // Mark invite as sent
  bool mark_sent(const std::string& invite_id) {
    std::unique_lock lock(mutex_);
    auto it = invites_.find(invite_id);
    if (it != invites_.end()) {
      it->second.sent = true;
      it->second.send_attempts++;
      return true;
    }
    return false;
  }

  // List pending invites for a room
  std::vector<EmailInvite> list_pending_for_room(const std::string& room_id) {
    std::shared_lock lock(mutex_);
    std::vector<EmailInvite> result;
    for (const auto& [id, inv] : invites_) {
      if (inv.room_id == room_id && !inv.accepted) {
        if (inv.expires_at == 0 || inv.expires_at > now_sec()) {
          result.push_back(inv);
        }
      }
    }
    return result;
  }

  // List all invites sent by a user
  std::vector<EmailInvite> list_by_sender(const std::string& mxid) {
    std::shared_lock lock(mutex_);
    std::vector<EmailInvite> result;
    for (const auto& [id, inv] : invites_) {
      if (inv.invited_by == mxid) result.push_back(inv);
    }
    return result;
  }

  // Purge expired invites
  size_t purge_expired() {
    std::unique_lock lock(mutex_);
    size_t count = 0;
    auto it = invites_.begin();
    while (it != invites_.end()) {
      if (it->second.expires_at > 0 && it->second.expires_at < now_sec()) {
        it = invites_.erase(it);
        count++;
      } else {
        ++it;
      }
    }
    return count;
  }

  json stats() {
    std::shared_lock lock(mutex_);
    size_t total = invites_.size();
    size_t pending = 0, accepted = 0;
    for (const auto& [id, inv] : invites_) {
      if (inv.accepted) accepted++;
      else pending++;
    }
    return {
      {"total", total},
      {"pending", pending},
      {"accepted", accepted}
    };
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, EmailInvite> invites_;
};

// Extend EmailInvite with accepted fields (inline)
// See EmailInvite struct: these fields are added via the accept flow
namespace {
  struct EmailInviteExtended : public EmailInviteManager::EmailInvite {
    std::string accepted_by_;
    int64_t accepted_at_{0};
  };
}

// --------------------------------------------------------------------------
// EmailNotificationTemplates - templated email notifications
// --------------------------------------------------------------------------
class EmailNotificationTemplates {
public:
  struct Template {
    std::string id;
    std::string name;
    std::string subject;
    std::string body_html;
    std::string body_text;
    std::string lang{"en"};
    std::map<std::string, std::string> variables; // var -> description
    int64_t updated_at;
  };

  // Define a notification template
  std::string add_template(const std::string& name,
                           const std::string& subject,
                           const std::string& body_html,
                           const std::string& body_text,
                           const std::string& lang = "en") {
    std::unique_lock lock(mutex_);
    Template tmpl;
    tmpl.id = "email_tmpl_" + generate_uuid();
    tmpl.name = name;
    tmpl.subject = subject;
    tmpl.body_html = body_html;
    tmpl.body_text = body_text;
    tmpl.lang = lang;
    tmpl.updated_at = now_sec();

    // Extract variable names from template
    tmpl.variables = extract_variables(subject + body_html + body_text);

    templates_[tmpl.id] = tmpl;
    templates_by_name_[to_lower(name)][lang] = tmpl.id;
    return tmpl.id;
  }

  // Get template by name and optional language
  std::optional<Template> get_template(const std::string& name,
                                       const std::string& lang = "en") {
    std::shared_lock lock(mutex_);
    auto nit = templates_by_name_.find(to_lower(name));
    if (nit != templates_by_name_.end()) {
      auto lit = nit->second.find(lang);
      if (lit == nit->second.end()) {
        // Fallback to English
        lit = nit->second.find("en");
      }
      if (lit != nit->second.end()) {
        auto tit = templates_.find(lit->second);
        if (tit != templates_.end()) return tit->second;
      }
    }
    return std::nullopt;
  }

  // Render a template with variables
  std::string render_subject(const std::string& name,
                             const std::map<std::string, std::string>& vars,
                             const std::string& lang = "en") {
    auto tmpl = get_template(name, lang);
    if (!tmpl) return "";
    return substitute(tmpl->subject, vars);
  }

  std::string render_body_html(const std::string& name,
                               const std::map<std::string, std::string>& vars,
                               const std::string& lang = "en") {
    auto tmpl = get_template(name, lang);
    if (!tmpl) return "";
    return substitute(tmpl->body_html, vars);
  }

  std::string render_body_text(const std::string& name,
                               const std::map<std::string, std::string>& vars,
                               const std::string& lang = "en") {
    auto tmpl = get_template(name, lang);
    if (!tmpl) return "";
    return substitute(tmpl->body_text, vars);
  }

  // Delete template
  bool delete_template(const std::string& template_id) {
    std::unique_lock lock(mutex_);
    auto it = templates_.find(template_id);
    if (it != templates_.end()) {
      auto& name_map = templates_by_name_[to_lower(it->second.name)];
      for (auto lit = name_map.begin(); lit != name_map.end(); ) {
        if (lit->second == template_id)
          lit = name_map.erase(lit);
        else
          ++lit;
      }
      templates_.erase(it);
      return true;
    }
    return false;
  }

  // List all templates
  json list_templates() {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& [id, tmpl] : templates_) {
      arr.push_back({
          {"id", tmpl.id},
          {"name", tmpl.name},
          {"subject", tmpl.subject},
          {"lang", tmpl.lang},
          {"variables", tmpl.variables}
      });
    }
    return arr;
  }

  // Prebuilt common templates
  void initialize_defaults() {
    add_template("invite",
                 "You're invited to ${room_name} on ${server_name}",
                 "<p>Hello ${display_name},</p><p>${inviter_name} has invited you to <strong>${room_name}</strong> on ${server_name}.</p><p>Click <a href='${invite_link}'>here</a> to accept.</p>",
                 "Hello ${display_name},\n\n${inviter_name} has invited you to ${room_name} on ${server_name}.\n\nAccept: ${invite_link}");

    add_template("message_notification",
                 "New message in ${room_name}",
                 "<p><strong>${sender_name}</strong> sent a message in ${room_name}:</p><blockquote>${message_preview}</blockquote>",
                 "${sender_name} sent a message in ${room_name}:\n${message_preview}");

    add_template("password_reset",
                 "Password reset for ${server_name}",
                 "<p>Click <a href='${reset_link}'>here</a> to reset your password. This link expires in ${expiry_minutes} minutes.</p>",
                 "Reset your password: ${reset_link}\nThis link expires in ${expiry_minutes} minutes.");

    add_template("email_verification",
                 "Verify your email for ${server_name}",
                 "<p>Your verification code is: <strong>${code}</strong></p>",
                 "Your verification code is: ${code}");

    add_template("welcome",
                 "Welcome to ${server_name}!",
                 "<p>Welcome ${display_name}! Your account has been created.</p><p>Get started: ${homeserver_url}</p>",
                 "Welcome ${display_name}! Your account has been created.\nGet started: ${homeserver_url}");
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, Template> templates_;
  // name -> (lang -> template_id)
  std::unordered_map<std::string, std::unordered_map<std::string, std::string>>
      templates_by_name_;

  std::map<std::string, std::string> extract_variables(const std::string& text) {
    std::map<std::string, std::string> vars;
    std::regex var_regex(R"(\$\{([a-zA-Z_][a-zA-Z0-9_]*)\})");
    auto begin = std::sregex_iterator(text.begin(), text.end(), var_regex);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
      std::string var_name = (*it)[1].str();
      if (!vars.count(var_name)) vars[var_name] = "";
    }
    return vars;
  }

  std::string substitute(const std::string& tmpl,
                         const std::map<std::string, std::string>& vars) {
    std::string result;
    result.reserve(tmpl.size());
    size_t i = 0;
    while (i < tmpl.size()) {
      if (tmpl[i] == '$' && i + 1 < tmpl.size() && tmpl[i + 1] == '{') {
        size_t end = tmpl.find('}', i + 2);
        if (end != std::string::npos) {
          std::string var = tmpl.substr(i + 2, end - i - 2);
          auto vit = vars.find(var);
          result += (vit != vars.end()) ? vit->second : ("${" + var + "}");
          i = end + 1;
          continue;
        }
      }
      result += tmpl[i];
      ++i;
    }
    return result;
  }
};

// ============================================================================
// EmailBridgeAdmin - top-level email bridge admin
// ============================================================================
class EmailBridgeAdmin {
public:
  EmailBridgeAdmin()
      : gateway_(std::make_unique<EmailToMatrixGateway>()),
        invites_(std::make_unique<EmailInviteManager>()),
        templates_(std::make_unique<EmailNotificationTemplates>()) {
    templates_->initialize_defaults();
  }

  // Gateway
  EmailToMatrixGateway& gateway() { return *gateway_; }
  EmailInviteManager& invites() { return *invites_; }
  EmailNotificationTemplates& templates() { return *templates_; }

  // Convenience wrappers
  std::string add_email_route(const std::string& email, const std::string& room) {
    auto route = gateway_->create_route(email, room);
    return route.id;
  }

  json create_email_invite(const std::string& email,
                           const std::string& room_id,
                           const std::string& invited_by) {
    auto inv = invites_->create_invite(email, room_id, invited_by);
    return {
      {"invite_id", inv.id},
      {"email", inv.email},
      {"room_id", inv.room_id},
      {"token", inv.invite_token},
      {"expires_at", inv.expires_at}
    };
  }

  json send_invite_email(const std::string& invite_id,
                         const std::string& server_name,
                         const std::string& room_name,
                         const std::string& inviter_name) {
    // Find the invite, render the template, simulate sending
    // (Real impl would use SMTP)
    json result;
    result["sent"] = invites_->mark_sent(invite_id);
    result["template_used"] = "invite";
    result["invite_id"] = invite_id;
    return result;
  }

  // Comprehensive status dump
  json get_status() {
    return {
      {"email_routes", gateway_->list_routes()},
      {"route_count", gateway_->count()},
      {"pending_invites", invites_->stats()},
      {"templates", templates_->list_templates()}
    };
  }

private:
  std::unique_ptr<EmailToMatrixGateway> gateway_;
  std::unique_ptr<EmailInviteManager> invites_;
  std::unique_ptr<EmailNotificationTemplates> templates_;
};

// ============================================================================
// PART 3: WEBHOOK BRIDGE ADMIN
// Register webhook URLs, map to rooms, event filtering for webhooks.
// ============================================================================

// --------------------------------------------------------------------------
// WebhookEventFilter - filter rules for webhook events
// --------------------------------------------------------------------------
class WebhookEventFilter {
public:
  struct FilterRule {
    std::string field;         // JSON path, e.g. "event_type" or "content.body"
    std::string op;            // "eq", "neq", "contains", "regex", "gt", "lt"
    std::string value;
    bool negate{false};
  };

  struct FilterSet {
    std::string id;
    std::vector<FilterRule> rules;
    std::string logic;  // "and" or "or"
  };

  FilterSet create_filter(const std::vector<FilterRule>& rules,
                          const std::string& logic = "and") {
    FilterSet fs;
    fs.id = "filter_" + generate_uuid();
    fs.rules = rules;
    fs.logic = (logic == "or") ? "or" : "and";
    filters_[fs.id] = fs;
    return fs;
  }

  bool delete_filter(const std::string& filter_id) {
    return filters_.erase(filter_id) > 0;
  }

  // Evaluate a JSON payload against a filter set
  bool evaluate(const std::string& filter_id, const json& payload) {
    auto it = filters_.find(filter_id);
    if (it == filters_.end()) return true; // no filter = pass

    const auto& fs = it->second;
    if (fs.rules.empty()) return true;

    bool result = (fs.logic == "and");
    for (const auto& rule : fs.rules) {
      bool match = evaluate_rule(rule, payload);
      if (rule.negate) match = !match;

      if (fs.logic == "and") {
        if (!match) { result = false; break; }
      } else { // or
        if (match) { result = true; break; }
      }
    }
    return result;
  }

  // Test a single payload against a set of rules
  bool test_rules(const std::vector<FilterRule>& rules,
                  const json& payload,
                  const std::string& logic = "and") {
    FilterSet tmp;
    tmp.rules = rules;
    tmp.logic = logic;
    auto tmp_id = "tmp_test";
    filters_[tmp_id] = tmp;
    bool result = evaluate(tmp_id, payload);
    filters_.erase(tmp_id);
    return result;
  }

  json list_filters() {
    json arr = json::array();
    for (const auto& [id, fs] : filters_) {
      json rarr = json::array();
      for (const auto& r : fs.rules) {
        rarr.push_back({
            {"field", r.field},
            {"op", r.op},
            {"value", r.value},
            {"negate", r.negate}
        });
      }
      arr.push_back({
          {"id", fs.id},
          {"logic", fs.logic},
          {"rules", rarr}
      });
    }
    return arr;
  }

private:
  std::unordered_map<std::string, FilterSet> filters_;

  // Navigate JSON payload using dot-notation path
  static json get_json_value(const json& payload, const std::string& path) {
    auto parts = split(path, '.');
    const json* current = &payload;
    for (const auto& part : parts) {
      if (current->is_object()) {
        if (current->contains(part)) {
          current = &(*current)[part];
        } else {
          return json(); // not found
        }
      } else if (current->is_array()) {
        try {
          size_t idx = std::stoull(part);
          if (idx < current->size()) {
            current = &(*current)[idx];
          } else {
            return json();
          }
        } catch (...) {
          return json();
        }
      } else {
        return json();
      }
    }
    return *current;
  }

  static bool evaluate_rule(const FilterRule& rule, const json& payload) {
    json val = get_json_value(payload, rule.field);
    if (val.is_null()) return false;

    std::string val_str = val.is_string() ? val.get<std::string>()
                          : val.dump();

    if (rule.op == "eq") {
      return val_str == rule.value;
    } else if (rule.op == "neq") {
      return val_str != rule.value;
    } else if (rule.op == "contains") {
      return val_str.find(rule.value) != std::string::npos;
    } else if (rule.op == "regex") {
      try {
        std::regex re(rule.value, std::regex::ECMAScript);
        return std::regex_search(val_str, re);
      } catch (...) {
        return false;
      }
    } else if (rule.op == "gt" || rule.op == "lt") {
      try {
        double num_val = std::stod(val_str);
        double cmp_val = std::stod(rule.value);
        if (rule.op == "gt") return num_val > cmp_val;
        if (rule.op == "lt") return num_val < cmp_val;
      } catch (...) {
        return false;
      }
    } else if (rule.op == "exists") {
      return !val.is_null();
    } else if (rule.op == "is_array") {
      return val.is_array();
    } else if (rule.op == "is_object") {
      return val.is_object();
    }

    return false;
  }
};

// --------------------------------------------------------------------------
// WebhookRegistration - a single webhook endpoint
// --------------------------------------------------------------------------
class WebhookRegistration {
public:
  struct Webhook {
    std::string id;
    std::string name;
    std::string url_path;       // unique path, e.g. "/webhooks/github"
    std::string secret_token;   // for HMAC verification
    std::string matrix_room_id;
    std::string filter_id;      // optional event filter
    std::string bridge_user;    // bot that posts to room
    bool enabled{true};
    bool verify_hmac{true};
    std::map<std::string, std::string> headers; // custom headers
    int64_t created_at;
    int64_t last_triggered_at{0};
    int64_t trigger_count{0};
    int64_t error_count{0};

    Webhook() : created_at(now_sec()) {}
  };

  // Create a webhook
  Webhook create_webhook(const std::string& name,
                         const std::string& matrix_room,
                         const std::string& bridge_user,
                         const std::string& custom_path = "") {
    std::unique_lock lock(mutex_);
    Webhook wh;
    wh.id = "wh_" + generate_uuid();
    wh.name = name;
    wh.url_path = custom_path.empty()
        ? "/webhooks/" + generate_token(16)
        : custom_path;
    wh.secret_token = generate_token(48);
    wh.matrix_room_id = matrix_room;
    wh.bridge_user = bridge_user;

    webhooks_[wh.id] = wh;
    path_index_[wh.url_path] = wh.id;
    return wh;
  }

  // Update webhook config
  bool update_webhook(const std::string& webhook_id, const json& updates) {
    std::unique_lock lock(mutex_);
    auto it = webhooks_.find(webhook_id);
    if (it == webhooks_.end()) return false;

    if (updates.contains("enabled"))
      it->second.enabled = updates["enabled"].get<bool>();
    if (updates.contains("name"))
      it->second.name = updates["name"].get<std::string>();
    if (updates.contains("matrix_room_id"))
      it->second.matrix_room_id = updates["matrix_room_id"].get<std::string>();
    if (updates.contains("filter_id"))
      it->second.filter_id = updates["filter_id"].get<std::string>();
    if (updates.contains("verify_hmac"))
      it->second.verify_hmac = updates["verify_hmac"].get<bool>();
    if (updates.contains("headers"))
      it->second.headers = updates["headers"].get<std::map<std::string, std::string>>();

    // Handle path change
    if (updates.contains("url_path")) {
      path_index_.erase(it->second.url_path);
      it->second.url_path = updates["url_path"].get<std::string>();
      path_index_[it->second.url_path] = webhook_id;
    }

    return true;
  }

  // Delete webhook
  bool delete_webhook(const std::string& webhook_id) {
    std::unique_lock lock(mutex_);
    auto it = webhooks_.find(webhook_id);
    if (it != webhooks_.end()) {
      path_index_.erase(it->second.url_path);
      webhooks_.erase(it);
      return true;
    }
    return false;
  }

  // Lookup webhook by URL path
  std::optional<Webhook> find_by_path(const std::string& path) {
    std::shared_lock lock(mutex_);
    auto it = path_index_.find(path);
    if (it != path_index_.end()) {
      auto wit = webhooks_.find(it->second);
      if (wit != webhooks_.end()) return wit->second;
    }
    return std::nullopt;
  }

  // Lookup webhook by ID
  std::optional<Webhook> find_by_id(const std::string& id) {
    std::shared_lock lock(mutex_);
    auto it = webhooks_.find(id);
    if (it != webhooks_.end()) return it->second;
    return std::nullopt;
  }

  // Verify HMAC signature
  bool verify_signature(const std::string& webhook_id,
                        const std::string& body,
                        const std::string& signature) {
    auto wh = find_by_id(webhook_id);
    if (!wh) return false;
    if (!wh->verify_hmac) return true; // verification disabled

    // Simulated HMAC-SHA256 verification
    // Real impl: compute HMAC(secret_token, body) and compare
    std::string expected = "sha256=" + wh->secret_token.substr(0, 16);
    return signature == expected;
  }

  // Record a webhook trigger
  void record_trigger(const std::string& webhook_id, bool success) {
    std::unique_lock lock(mutex_);
    auto it = webhooks_.find(webhook_id);
    if (it != webhooks_.end()) {
      it->second.last_triggered_at = now_sec();
      if (success)
        it->second.trigger_count++;
      else
        it->second.error_count++;
    }
  }

  // List webhooks for a room
  std::vector<Webhook> list_for_room(const std::string& room_id) {
    std::shared_lock lock(mutex_);
    std::vector<Webhook> result;
    for (const auto& [id, wh] : webhooks_) {
      if (wh.matrix_room_id == room_id) result.push_back(wh);
    }
    return result;
  }

  json list_all() {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& [id, wh] : webhooks_) {
      arr.push_back({
          {"id", wh.id},
          {"name", wh.name},
          {"url_path", wh.url_path},
          {"matrix_room_id", wh.matrix_room_id},
          {"enabled", wh.enabled},
          {"filter_id", wh.filter_id},
          {"trigger_count", wh.trigger_count},
          {"error_count", wh.error_count},
          {"last_triggered_at", wh.last_triggered_at}
      });
    }
    return arr;
  }

  // Regenerate secret for a webhook
  std::optional<std::string> regenerate_secret(const std::string& webhook_id) {
    std::unique_lock lock(mutex_);
    auto it = webhooks_.find(webhook_id);
    if (it != webhooks_.end()) {
      it->second.secret_token = generate_token(48);
      return it->second.secret_token;
    }
    return std::nullopt;
  }

  size_t count() const {
    std::shared_lock lock(mutex_);
    return webhooks_.size();
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, Webhook> webhooks_;
  std::unordered_map<std::string, std::string> path_index_;
};

// --------------------------------------------------------------------------
// WebhookRouter - handles incoming webhook requests
// --------------------------------------------------------------------------
class WebhookRouter {
public:
  struct RoutedRequest {
    std::string webhook_id;
    std::string matrix_room_id;
    std::string bridge_user;
    json payload;
    bool passed_filter{true};
    bool signature_valid{true};
  };

  WebhookRouter(WebhookRegistration& registry, WebhookEventFilter& filters)
      : registry_(registry), filters_(filters) {}

  // Route an incoming webhook request
  RoutedRequest route(const std::string& path,
                      const json& payload,
                      const std::string& signature = "") {
    RoutedRequest result;

    auto wh = registry_.find_by_path(path);
    if (!wh) {
      result.passed_filter = false;
      result.webhook_id = "unknown";
      return result;
    }

    if (!wh->enabled) {
      result.passed_filter = false;
      result.webhook_id = wh->id;
      return result;
    }

    result.webhook_id = wh->id;
    result.matrix_room_id = wh->matrix_room_id;
    result.bridge_user = wh->bridge_user;
    result.payload = payload;

    // Verify HMAC if required
    if (!signature.empty()) {
      result.signature_valid = registry_.verify_signature(
          wh->id, payload.dump(), signature);
      if (!result.signature_valid && wh->verify_hmac) {
        result.passed_filter = false;
        registry_.record_trigger(wh->id, false);
        return result;
      }
    }

    // Apply filter if configured
    if (!wh->filter_id.empty()) {
      result.passed_filter = filters_.evaluate(wh->filter_id, payload);
    }

    registry_.record_trigger(wh->id, result.passed_filter);
    return result;
  }

  // Build a Matrix message from a webhook payload
  json build_matrix_message(const RoutedRequest& req,
                            const std::string& template_name = "") {
    json msg;
    msg["msgtype"] = "m.text";
    msg["body"] = req.payload.dump(2);
    msg["room_id"] = req.matrix_room_id;

    // Add webhook metadata
    msg["webhook_id"] = req.webhook_id;
    msg["webhook_timestamp"] = current_iso8601();

    return msg;
  }

private:
  WebhookRegistration& registry_;
  WebhookEventFilter& filters_;
};

// ============================================================================
// WebhookBridgeAdmin - top-level webhook bridge administration
// ============================================================================
class WebhookBridgeAdmin {
public:
  WebhookBridgeAdmin()
      : registry_(std::make_unique<WebhookRegistration>()),
        filters_(std::make_unique<WebhookEventFilter>()),
        router_(std::make_unique<WebhookRouter>(*registry_, *filters_)) {}

  // Registration
  json create_webhook(const std::string& name,
                      const std::string& room_id,
                      const std::string& bridge_user) {
    auto wh = registry_->create_webhook(name, room_id, bridge_user);
    return {
      {"id", wh.id},
      {"name", wh.name},
      {"url_path", wh.url_path},
      {"secret_token", wh.secret_token}, // Only returned on creation
      {"room_id", wh.matrix_room_id}
    };
  }

  bool delete_webhook(const std::string& webhook_id) {
    return registry_->delete_webhook(webhook_id);
  }

  bool update_webhook(const std::string& webhook_id, const json& updates) {
    return registry_->update_webhook(webhook_id, updates);
  }

  json list_webhooks() { return registry_->list_all(); }

  json list_webhooks_for_room(const std::string& room_id) {
    auto webhooks = registry_->list_for_room(room_id);
    json arr = json::array();
    for (const auto& wh : webhooks) {
      arr.push_back({
          {"id", wh.id},
          {"name", wh.name},
          {"url_path", wh.url_path},
          {"enabled", wh.enabled},
          {"trigger_count", wh.trigger_count}
      });
    }
    return arr;
  }

  // Filter management
  std::string create_filter(const std::vector<WebhookEventFilter::FilterRule>& rules,
                            const std::string& logic = "and") {
    auto fs = filters_->create_filter(rules, logic);
    return fs.id;
  }

  bool delete_filter(const std::string& filter_id) {
    return filters_->delete_filter(filter_id);
  }

  // Incoming webhook handling
  json handle_incoming(const std::string& path,
                       const json& payload,
                       const std::string& signature = "") {
    auto routed = router_->route(path, payload, signature);
    if (!routed.passed_filter) {
      return {
        {"accepted", false},
        {"reason", routed.signature_valid ? "filter_rejected" : "invalid_signature"}
      };
    }
    auto msg = router_->build_matrix_message(routed);
    return {
      {"accepted", true},
      {"webhook_id", routed.webhook_id},
      {"room_id", routed.matrix_room_id},
      {"matrix_message", msg}
    };
  }

  // Status
  json get_status() {
    return {
      {"total_webhooks", registry_->count()},
      {"filters", filters_->list_filters()},
      {"webhooks", registry_->list_all()}
    };
  }

  // Access internals
  WebhookRegistration& registry() { return *registry_; }
  WebhookEventFilter& filters() { return *filters_; }
  WebhookRouter& router() { return *router_; }

private:
  std::unique_ptr<WebhookRegistration> registry_;
  std::unique_ptr<WebhookEventFilter> filters_;
  std::unique_ptr<WebhookRouter> router_;
};

// ============================================================================
// PART 4: BOT / SDK ADMIN
// Bot user management, bot access tokens, appservice bot accounts.
// ============================================================================

// --------------------------------------------------------------------------
// BotAccessTokenManager - manage token issuance for bots
// --------------------------------------------------------------------------
class BotAccessTokenManager {
public:
  struct BotToken {
    std::string token_id;
    std::string token_value;
    std::string bot_user_id;
    int64_t issued_at;
    int64_t expires_at;       // 0 = never expires
    int64_t last_used_at;
    std::string description;
    std::vector<std::string> scopes;
    bool revoked{false};
  };

  // Issue a new access token
  BotToken issue_token(const std::string& bot_user_id,
                       const std::vector<std::string>& scopes = {"read", "write"},
                       int64_t ttl_sec = 0,
                       const std::string& description = "") {
    std::unique_lock lock(mutex_);
    BotToken bt;
    bt.token_id = "bot_tok_" + generate_uuid();
    bt.token_value = "syt_" + generate_token(60);
    bt.bot_user_id = bot_user_id;
    bt.issued_at = now_sec();
    bt.expires_at = ttl_sec > 0 ? now_sec() + ttl_sec : 0;
    bt.description = description;
    bt.scopes = scopes;

    tokens_[bt.token_id] = bt;
    tokens_by_value_[bt.token_value] = bt.token_id;
    return bt;
  }

  // Validate a token and return bot user info
  std::optional<BotToken> validate_token(const std::string& token_value) {
    std::shared_lock lock(mutex_);
    auto it = tokens_by_value_.find(token_value);
    if (it == tokens_by_value_.end()) return std::nullopt;

    auto tit = tokens_.find(it->second);
    if (tit == tokens_.end() || tit->second.revoked) return std::nullopt;

    // Check expiry
    if (tit->second.expires_at > 0 && tit->second.expires_at < now_sec()) {
      return std::nullopt;
    }

    // Update last_used (const_cast for stats)
    const_cast<BotToken&>(tit->second).last_used_at = now_sec();
    return tit->second;
  }

  // Revoke a token
  bool revoke_token(const std::string& token_id) {
    std::unique_lock lock(mutex_);
    auto it = tokens_.find(token_id);
    if (it != tokens_.end()) {
      it->second.revoked = true;
      tokens_by_value_.erase(it->second.token_value);
      return true;
    }
    return false;
  }

  // Revoke all tokens for a bot
  size_t revoke_all_for_bot(const std::string& bot_user_id) {
    std::unique_lock lock(mutex_);
    size_t count = 0;
    for (auto& [id, tok] : tokens_) {
      if (tok.bot_user_id == bot_user_id && !tok.revoked) {
        tok.revoked = true;
        tokens_by_value_.erase(tok.token_value);
        count++;
      }
    }
    return count;
  }

  // List tokens for a bot (masked values)
  json list_tokens_for_bot(const std::string& bot_user_id) {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& [id, tok] : tokens_) {
      if (tok.bot_user_id == bot_user_id) {
        arr.push_back({
            {"token_id", tok.token_id},
            {"token_value_masked", tok.token_value.substr(0, 8) + "..."},
            {"issued_at", tok.issued_at},
            {"expires_at", tok.expires_at},
            {"revoked", tok.revoked},
            {"description", tok.description},
            {"scopes", tok.scopes},
            {"last_used_at", tok.last_used_at}
        });
      }
    }
    return arr;
  }

  // Purge expired tokens
  size_t purge_expired() {
    std::unique_lock lock(mutex_);
    size_t count = 0;
    auto it = tokens_.begin();
    while (it != tokens_.end()) {
      if (it->second.expires_at > 0 && it->second.expires_at < now_sec()) {
        tokens_by_value_.erase(it->second.token_value);
        it = tokens_.erase(it);
        count++;
      } else {
        ++it;
      }
    }
    return count;
  }

  json stats() {
    std::shared_lock lock(mutex_);
    size_t active = 0, revoked = 0;
    for (const auto& [id, tok] : tokens_) {
      if (tok.revoked) revoked++;
      else active++;
    }
    return {
      {"total", tokens_.size()},
      {"active", active},
      {"revoked", revoked}
    };
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, BotToken> tokens_;
  std::unordered_map<std::string, std::string> tokens_by_value_;
};

// --------------------------------------------------------------------------
// BotUserManager - manage bot user accounts
// --------------------------------------------------------------------------
class BotUserManager {
public:
  struct BotUser {
    std::string user_id;       // @bot_xxx:server
    std::string display_name;
    std::string description;
    std::string avatar_url;
    std::string owner_user_id; // who created this bot
    int64_t created_at;
    bool enabled{true};
    bool is_appservice_bot{false};
    std::string appservice_id; // if is_appservice_bot
    std::vector<std::string> autojoin_rooms;
    json extra_data;
  };

  // Register a new bot user
  BotUser register_bot(const std::string& localpart,
                       const std::string& server_name,
                       const std::string& owner_mxid,
                       const std::string& display_name = "",
                       bool appservice_bot = false) {
    std::unique_lock lock(mutex_);
    BotUser bot;
    bot.user_id = "@" + localpart + ":" + server_name;
    bot.display_name = display_name.empty() ? localpart : display_name;
    bot.owner_user_id = owner_mxid;
    bot.created_at = now_sec();
    bot.is_appservice_bot = appservice_bot;

    bots_[bot.user_id] = bot;
    return bot;
  }

  // Get bot by user ID
  std::optional<BotUser> get_bot(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    auto it = bots_.find(user_id);
    if (it != bots_.end()) return it->second;
    return std::nullopt;
  }

  // Update bot details
  bool update_bot(const std::string& user_id, const json& updates) {
    std::unique_lock lock(mutex_);
    auto it = bots_.find(user_id);
    if (it == bots_.end()) return false;

    if (updates.contains("display_name"))
      it->second.display_name = updates["display_name"].get<std::string>();
    if (updates.contains("description"))
      it->second.description = updates["description"].get<std::string>();
    if (updates.contains("avatar_url"))
      it->second.avatar_url = updates["avatar_url"].get<std::string>();
    if (updates.contains("enabled"))
      it->second.enabled = updates["enabled"].get<bool>();
    if (updates.contains("autojoin_rooms"))
      it->second.autojoin_rooms = updates["autojoin_rooms"].get<std::vector<std::string>>();
    return true;
  }

  // Enable/disable bot
  bool set_enabled(const std::string& user_id, bool enabled) {
    std::unique_lock lock(mutex_);
    auto it = bots_.find(user_id);
    if (it != bots_.end()) {
      it->second.enabled = enabled;
      return true;
    }
    return false;
  }

  // Delete bot
  bool delete_bot(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    return bots_.erase(user_id) > 0;
  }

  // List bots owned by a user
  std::vector<BotUser> list_by_owner(const std::string& owner_mxid) {
    std::shared_lock lock(mutex_);
    std::vector<BotUser> result;
    for (const auto& [id, bot] : bots_) {
      if (bot.owner_user_id == owner_mxid) result.push_back(bot);
    }
    return result;
  }

  // List all bots
  json list_all() {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& [id, bot] : bots_) {
      arr.push_back({
          {"user_id", bot.user_id},
          {"display_name", bot.display_name},
          {"owner", bot.owner_user_id},
          {"enabled", bot.enabled},
          {"is_appservice_bot", bot.is_appservice_bot},
          {"created_at", bot.created_at}
      });
    }
    return arr;
  }

  // Count bots
  size_t count() const {
    std::shared_lock lock(mutex_);
    return bots_.size();
  }

  // Check if a user is a bot
  bool is_bot(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    return bots_.count(user_id) > 0;
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, BotUser> bots_;
};

// --------------------------------------------------------------------------
// AppServiceBotRegistry - register bots as appservice users
// --------------------------------------------------------------------------
class AppServiceBotRegistry {
public:
  struct AppServiceBot {
    std::string bot_user_id;
    std::string appservice_id;
    std::string as_token;
    std::string sender_localpart;
    bool rate_limited{true};
    std::vector<std::string> protocols;
    int64_t registered_at;
  };

  // Register an appservice bot
  AppServiceBot register_appservice_bot(const std::string& bot_user_id,
                                         const std::string& as_id,
                                         const std::string& as_token) {
    std::unique_lock lock(mutex_);
    AppServiceBot bot;
    bot.bot_user_id = bot_user_id;
    bot.appservice_id = as_id;
    bot.as_token = as_token;
    bot.sender_localpart = bot_user_id.substr(1, bot_user_id.find(':') - 1);
    bot.registered_at = now_sec();

    bots_[bot_user_id] = bot;
    return bot;
  }

  // Lookup bot by user ID
  std::optional<AppServiceBot> lookup(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    auto it = bots_.find(user_id);
    if (it != bots_.end()) return it->second;
    return std::nullopt;
  }

  // Check if a user is an appservice bot
  bool is_appservice_bot(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    return bots_.count(user_id) > 0;
  }

  // List all appservice bots
  json list_all() {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& [id, bot] : bots_) {
      arr.push_back({
          {"bot_user_id", bot.bot_user_id},
          {"appservice_id", bot.appservice_id},
          {"protocols", bot.protocols},
          {"registered_at", bot.registered_at}
      });
    }
    return arr;
  }

  // Get bots by appservice ID
  std::vector<AppServiceBot> list_by_appservice(const std::string& as_id) {
    std::shared_lock lock(mutex_);
    std::vector<AppServiceBot> result;
    for (const auto& [id, bot] : bots_) {
      if (bot.appservice_id == as_id) result.push_back(bot);
    }
    return result;
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, AppServiceBot> bots_;
};

// ============================================================================
// BotSDKAdmin - top-level bot/SDK administration
// ============================================================================
class BotSDKAdmin {
public:
  BotSDKAdmin()
      : users_(std::make_unique<BotUserManager>()),
        tokens_(std::make_unique<BotAccessTokenManager>()),
        appservice_bots_(std::make_unique<AppServiceBotRegistry>()) {}

  // User management
  json create_bot(const std::string& localpart,
                  const std::string& server_name,
                  const std::string& owner_mxid,
                  const std::string& display_name = "",
                  bool appservice_bot = false) {
    auto bot = users_->register_bot(localpart, server_name, owner_mxid,
                                     display_name, appservice_bot);
    return {
      {"user_id", bot.user_id},
      {"display_name", bot.display_name},
      {"owner", bot.owner_user_id},
      {"is_appservice_bot", bot.is_appservice_bot},
      {"created_at", bot.created_at}
    };
  }

  bool update_bot(const std::string& user_id, const json& updates) {
    return users_->update_bot(user_id, updates);
  }

  bool delete_bot(const std::string& user_id) {
    // Revoke all tokens first
    tokens_->revoke_all_for_bot(user_id);
    return users_->delete_bot(user_id);
  }

  bool enable_bot(const std::string& user_id, bool enabled) {
    return users_->set_enabled(user_id, enabled);
  }

  json list_bots() { return users_->list_all(); }

  json list_bots_by_owner(const std::string& owner_mxid) {
    auto bots = users_->list_by_owner(owner_mxid);
    json arr = json::array();
    for (const auto& bot : bots) {
      arr.push_back({
          {"user_id", bot.user_id},
          {"display_name", bot.display_name},
          {"enabled", bot.enabled},
          {"is_appservice_bot", bot.is_appservice_bot}
      });
    }
    return arr;
  }

  // Token management
  json issue_token(const std::string& bot_user_id,
                   const std::vector<std::string>& scopes = {"read", "write"},
                   int64_t ttl_sec = 0,
                   const std::string& description = "") {
    auto tok = tokens_->issue_token(bot_user_id, scopes, ttl_sec, description);
    return {
      {"token_id", tok.token_id},
      {"token_value", tok.token_value},
      {"bot_user_id", tok.bot_user_id},
      {"expires_at", tok.expires_at},
      {"scopes", tok.scopes}
    };
  }

  json validate_token(const std::string& token_value) {
    auto tok = tokens_->validate_token(token_value);
    if (!tok) return {{"valid", false}};
    return {
      {"valid", true},
      {"bot_user_id", tok->bot_user_id},
      {"scopes", tok->scopes},
      {"expires_at", tok->expires_at}
    };
  }

  bool revoke_token(const std::string& token_id) {
    return tokens_->revoke_token(token_id);
  }

  json list_tokens(const std::string& bot_user_id) {
    return tokens_->list_tokens_for_bot(bot_user_id);
  }

  // Appservice bot management
  json register_appservice_bot(const std::string& bot_user_id,
                               const std::string& as_id,
                               const std::string& as_token) {
    auto bot = appservice_bots_->register_appservice_bot(
        bot_user_id, as_id, as_token);
    return {
      {"bot_user_id", bot.bot_user_id},
      {"appservice_id", bot.appservice_id},
      {"registered_at", bot.registered_at}
    };
  }

  json list_appservice_bots() {
    return appservice_bots_->list_all();
  }

  // Status
  json get_status() {
    return {
      {"bot_count", users_->count()},
      {"token_stats", tokens_->stats()},
      {"appservice_bots", appservice_bots_->list_all()}
    };
  }

  // Access internals
  BotUserManager& users() { return *users_; }
  BotAccessTokenManager& tokens() { return *tokens_; }
  AppServiceBotRegistry& appservice_bots() { return *appservice_bots_; }

private:
  std::unique_ptr<BotUserManager> users_;
  std::unique_ptr<BotAccessTokenManager> tokens_;
  std::unique_ptr<AppServiceBotRegistry> appservice_bots_;
};

// ============================================================================
// PART 5: INTEGRATION MANAGER
// Manage integrations (widgets, bots, bridges), integration configuration,
// list supported integrations.
// ============================================================================

// --------------------------------------------------------------------------
// WidgetIntegration - manage Matrix widgets in rooms
// --------------------------------------------------------------------------
class WidgetIntegration {
public:
  struct Widget {
    std::string id;
    std::string name;
    std::string room_id;
    std::string widget_url;
    std::string widget_type;   // e.g. "m.custom", "m.jitsi"
    std::string creator;
    bool wait_for_iframe_load{true};
    json data;                 // widget content data
    int64_t created_at;
    int64_t updated_at;
    Widget() : created_at(now_sec()), updated_at(now_sec()) {}
  };

  // Create a widget in a room
  Widget create_widget(const std::string& room_id,
                       const std::string& name,
                       const std::string& widget_url,
                       const std::string& widget_type,
                       const std::string& creator,
                       const json& data = json::object()) {
    std::unique_lock lock(mutex_);
    Widget w;
    w.id = "widget_" + generate_uuid();
    w.name = name;
    w.room_id = room_id;
    w.widget_url = widget_url;
    w.widget_type = widget_type;
    w.creator = creator;
    w.data = data;
    widgets_[w.id] = w;
    return w;
  }

  // Delete widget
  bool delete_widget(const std::string& widget_id) {
    std::unique_lock lock(mutex_);
    return widgets_.erase(widget_id) > 0;
  }

  // Update widget
  bool update_widget(const std::string& widget_id, const json& updates) {
    std::unique_lock lock(mutex_);
    auto it = widgets_.find(widget_id);
    if (it == widgets_.end()) return false;
    if (updates.contains("name")) it->second.name = updates["name"];
    if (updates.contains("widget_url")) it->second.widget_url = updates["widget_url"];
    if (updates.contains("data")) it->second.data = updates["data"];
    it->second.updated_at = now_sec();
    return true;
  }

  // List widgets in a room
  std::vector<Widget> list_for_room(const std::string& room_id) {
    std::shared_lock lock(mutex_);
    std::vector<Widget> result;
    for (const auto& [id, w] : widgets_) {
      if (w.room_id == room_id) result.push_back(w);
    }
    return result;
  }

  // Build Matrix widget state event
  json build_widget_event(const Widget& w) {
    return {
      {"type", "im.vector.modular.widgets"},
      {"state_key", w.id},
      {"content", {
        {"id", w.id},
        {"name", w.name},
        {"type", w.widget_type},
        {"url", w.widget_url},
        {"creatorUserId", w.creator},
        {"waitForIframeLoad", w.wait_for_iframe_load},
        {"data", w.data}
      }}
    };
  }

  json list_all() {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& [id, w] : widgets_) {
      arr.push_back({
          {"id", w.id},
          {"name", w.name},
          {"room_id", w.room_id},
          {"widget_type", w.widget_type},
          {"creator", w.creator},
          {"created_at", w.created_at}
      });
    }
    return arr;
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, Widget> widgets_;
};

// --------------------------------------------------------------------------
// IntegrationRegistry - central registry of all supported integrations
// --------------------------------------------------------------------------
class IntegrationRegistry {
public:
  struct IntegrationDescriptor {
    std::string id;
    std::string name;
    IntegrationType type;
    std::string description;
    std::string homepage_url;
    std::string configuration_schema; // JSON Schema
    bool enabled_by_default{true};
    std::vector<std::string> protocols;
    std::map<std::string, std::string> metadata;
    int64_t instances_count{0};
  };

  // Register a supported integration type
  std::string register_type(const std::string& name,
                            IntegrationType type,
                            const std::string& description,
                            const std::string& homepage_url = "",
                            const std::string& schema = "{}") {
    std::unique_lock lock(mutex_);
    IntegrationDescriptor desc;
    desc.id = "integration_" + generate_uuid();
    desc.name = name;
    desc.type = type;
    desc.description = description;
    desc.homepage_url = homepage_url;
    desc.configuration_schema = schema;

    descriptors_[desc.id] = desc;
    descriptors_by_name_[to_lower(name)] = desc.id;
    return desc.id;
  }

  // Get integration descriptor
  std::optional<IntegrationDescriptor> get_descriptor(const std::string& id) {
    std::shared_lock lock(mutex_);
    auto it = descriptors_.find(id);
    if (it != descriptors_.end()) return it->second;
    return std::nullopt;
  }

  // Find by name
  std::optional<IntegrationDescriptor> find_by_name(const std::string& name) {
    std::shared_lock lock(mutex_);
    auto nit = descriptors_by_name_.find(to_lower(name));
    if (nit != descriptors_by_name_.end()) {
      auto it = descriptors_.find(nit->second);
      if (it != descriptors_.end()) return it->second;
    }
    return std::nullopt;
  }

  // List all supported types
  json list_all() {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& [id, desc] : descriptors_) {
      arr.push_back({
          {"id", desc.id},
          {"name", desc.name},
          {"type", integration_type_str(desc.type)},
          {"description", desc.description},
          {"homepage_url", desc.homepage_url},
          {"protocols", desc.protocols},
          {"instances_count", desc.instances_count},
          {"enabled_by_default", desc.enabled_by_default}
      });
    }
    return arr;
  }

  // List by type
  json list_by_type(IntegrationType type) {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& [id, desc] : descriptors_) {
      if (desc.type == type) {
        arr.push_back({
            {"id", desc.id},
            {"name", desc.name},
            {"description", desc.description}
        });
      }
    }
    return arr;
  }

  // Increment instance count for an integration
  void increment_instance_count(const std::string& id) {
    std::unique_lock lock(mutex_);
    auto it = descriptors_.find(id);
    if (it != descriptors_.end()) it->second.instances_count++;
  }

  // Initialize default known integrations
  void initialize_defaults() {
    register_type("Jitsi Meet", IntegrationType::WIDGET,
                  "Video conferencing via Jitsi",
                  "https://jitsi.org/",
                  R"({"type":"object","properties":{"jitsiDomain":{"type":"string"}}})");

    register_type("Etherpad", IntegrationType::WIDGET,
                  "Collaborative document editing",
                  "https://etherpad.org/");

    register_type("BigBlueButton", IntegrationType::WIDGET,
                  "Virtual classroom and meetings",
                  "https://bigbluebutton.org/");

    register_type("IRC Bridge", IntegrationType::BRIDGE,
                  "Bridge Matrix rooms to IRC channels",
                  "https://github.com/matrix-org/matrix-appservice-irc");

    register_type("Telegram Bridge", IntegrationType::BRIDGE,
                  "Bridge Matrix to Telegram",
                  "https://github.com/tulir/mautrix-telegram");

    register_type("WhatsApp Bridge", IntegrationType::BRIDGE,
                  "Bridge Matrix to WhatsApp",
                  "https://github.com/tulir/mautrix-whatsapp");

    register_type("Signal Bridge", IntegrationType::BRIDGE,
                  "Bridge Matrix to Signal",
                  "https://github.com/tulir/mautrix-signal");

    register_type("Discord Bridge", IntegrationType::BRIDGE,
                  "Bridge Matrix to Discord",
                  "https://github.com/half-shot/matrix-appservice-discord");

    register_type("Email Bridge", IntegrationType::BRIDGE,
                  "Bridge Matrix to email (SMTP/IMAP)",
                  "");

    register_type("Hookshot", IntegrationType::WEBHOOK,
                  "Generic webhook bridge for Matrix",
                  "https://github.com/matrix-org/matrix-hookshot");

    register_type("Giphy Bot", IntegrationType::BOT,
                  "Search and share GIFs in rooms",
                  "https://giphy.com/");

    register_type("Reminder Bot", IntegrationType::BOT,
                  "Set reminders and get notified in Matrix",
                  "");

    register_type("GitLab Bot", IntegrationType::BOT,
                  "Get GitLab notifications in Matrix rooms",
                  "https://gitlab.com/");

    register_type("GitHub Bot", IntegrationType::BOT,
                  "Get GitHub notifications in Matrix rooms",
                  "https://github.com/");

    register_type("RSS Bot", IntegrationType::BOT,
                  "Post RSS feed updates to Matrix rooms",
                  "");

    register_type("Custom Widget", IntegrationType::WIDGET,
                  "Custom iframe widget for rooms",
                  "");

    register_type("Generic Webhook", IntegrationType::WEBHOOK,
                  "Generic incoming webhook endpoint",
                  "");
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, IntegrationDescriptor> descriptors_;
  std::unordered_map<std::string, std::string> descriptors_by_name_;
};

// --------------------------------------------------------------------------
// IntegrationInstance - active instance of an integration
// --------------------------------------------------------------------------
class IntegrationInstance {
public:
  struct Instance {
    std::string id;
    std::string integration_type_id;  // references IntegrationRegistry
    std::string room_id;              // room this integration is in
    std::string user_id;              // who installed it
    json configuration;
    bool enabled{true};
    int64_t installed_at;
    int64_t last_active_at;
    std::string status{"active"};     // active, error, paused
    std::string status_message;
  };

  // Install an integration
  Instance install(const std::string& integration_type_id,
                   const std::string& room_id,
                   const std::string& user_id,
                   const json& config = json::object()) {
    std::unique_lock lock(mutex_);
    Instance inst;
    inst.id = "inst_" + generate_uuid();
    inst.integration_type_id = integration_type_id;
    inst.room_id = room_id;
    inst.user_id = user_id;
    inst.configuration = config;
    inst.installed_at = now_sec();
    inst.last_active_at = now_sec();

    instances_[inst.id] = inst;
    return inst;
  }

  // Uninstall
  bool uninstall(const std::string& instance_id) {
    std::unique_lock lock(mutex_);
    return instances_.erase(instance_id) > 0;
  }

  // Update configuration
  bool update_config(const std::string& instance_id,
                     const json& new_config) {
    std::unique_lock lock(mutex_);
    auto it = instances_.find(instance_id);
    if (it != instances_.end()) {
      it->second.configuration = new_config;
      it->second.last_active_at = now_sec();
      return true;
    }
    return false;
  }

  // Enable/disable
  bool set_enabled(const std::string& instance_id, bool enabled) {
    std::unique_lock lock(mutex_);
    auto it = instances_.find(instance_id);
    if (it != instances_.end()) {
      it->second.enabled = enabled;
      return true;
    }
    return false;
  }

  // Set status
  bool set_status(const std::string& instance_id,
                  const std::string& status,
                  const std::string& message = "") {
    std::unique_lock lock(mutex_);
    auto it = instances_.find(instance_id);
    if (it != instances_.end()) {
      it->second.status = status;
      it->second.status_message = message;
      return true;
    }
    return false;
  }

  // Get instance
  std::optional<Instance> get_instance(const std::string& instance_id) {
    std::shared_lock lock(mutex_);
    auto it = instances_.find(instance_id);
    if (it != instances_.end()) return it->second;
    return std::nullopt;
  }

  // List instances in a room
  std::vector<Instance> list_for_room(const std::string& room_id) {
    std::shared_lock lock(mutex_);
    std::vector<Instance> result;
    for (const auto& [id, inst] : instances_) {
      if (inst.room_id == room_id) result.push_back(inst);
    }
    return result;
  }

  // List instances by type
  std::vector<Instance> list_by_type(const std::string& type_id) {
    std::shared_lock lock(mutex_);
    std::vector<Instance> result;
    for (const auto& [id, inst] : instances_) {
      if (inst.integration_type_id == type_id) result.push_back(inst);
    }
    return result;
  }

  json list_all() {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& [id, inst] : instances_) {
      arr.push_back({
          {"id", inst.id},
          {"integration_type_id", inst.integration_type_id},
          {"room_id", inst.room_id},
          {"user_id", inst.user_id},
          {"enabled", inst.enabled},
          {"installed_at", inst.installed_at},
          {"status", inst.status},
          {"status_message", inst.status_message}
      });
    }
    return arr;
  }

  size_t count() const {
    std::shared_lock lock(mutex_);
    return instances_.size();
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, Instance> instances_;
};

// ============================================================================
// IntegrationManager - top-level integration management
// ============================================================================
class IntegrationManager {
public:
  IntegrationManager()
      : registry_(std::make_unique<IntegrationRegistry>()),
        widgets_(std::make_unique<WidgetIntegration>()),
        instances_(std::make_unique<IntegrationInstance>()) {
    registry_->initialize_defaults();
  }

  // ---- Integration type registry ----
  json list_supported_integrations() { return registry_->list_all(); }
  json list_supported_by_type(IntegrationType type) {
    return registry_->list_by_type(type);
  }

  // ---- Widget management ----
  json create_widget(const std::string& room_id,
                     const std::string& name,
                     const std::string& url,
                     const std::string& type,
                     const std::string& creator,
                     const json& data = json::object()) {
    auto w = widgets_->create_widget(room_id, name, url, type, creator, data);
    return {
      {"widget_id", w.id},
      {"name", w.name},
      {"room_id", w.room_id},
      {"widget_url", w.widget_url},
      {"widget_type", w.widget_type}
    };
  }

  bool delete_widget(const std::string& widget_id) {
    return widgets_->delete_widget(widget_id);
  }

  json list_widgets_for_room(const std::string& room_id) {
    auto widgets = widgets_->list_for_room(room_id);
    json arr = json::array();
    for (const auto& w : widgets) {
      arr.push_back({
          {"id", w.id},
          {"name", w.name},
          {"widget_type", w.widget_type},
          {"widget_url", w.widget_url}
      });
    }
    return arr;
  }

  // ---- Instance lifecycle ----
  json install_integration(const std::string& type_id,
                           const std::string& room_id,
                           const std::string& user_id,
                           const json& config = json::object()) {
    auto inst = instances_->install(type_id, room_id, user_id, config);
    registry_->increment_instance_count(type_id);
    return {
      {"instance_id", inst.id},
      {"type_id", inst.integration_type_id},
      {"room_id", inst.room_id},
      {"installed_at", inst.installed_at}
    };
  }

  bool uninstall_integration(const std::string& instance_id) {
    return instances_->uninstall(instance_id);
  }

  bool update_integration_config(const std::string& instance_id,
                                  const json& config) {
    return instances_->update_config(instance_id, config);
  }

  json list_instances_for_room(const std::string& room_id) {
    auto insts = instances_->list_for_room(room_id);
    json arr = json::array();
    for (const auto& inst : insts) {
      arr.push_back({
          {"id", inst.id},
          {"integration_type_id", inst.integration_type_id},
          {"enabled", inst.enabled},
          {"status", inst.status},
          {"installed_at", inst.installed_at}
      });
    }
    return arr;
  }

  json list_all_instances() { return instances_->list_all(); }

  // Status overview
  json get_status() {
    return {
      {"supported_integrations", registry_->list_all()},
      {"active_instances", instances_->count()},
      {"widgets", widgets_->list_all()},
      {"instances", instances_->list_all()}
    };
  }

  // Access internals
  IntegrationRegistry& registry() { return *registry_; }
  WidgetIntegration& widgets() { return *widgets_; }
  IntegrationInstance& instances() { return *instances_; }

private:
  std::unique_ptr<IntegrationRegistry> registry_;
  std::unique_ptr<WidgetIntegration> widgets_;
  std::unique_ptr<IntegrationInstance> instances_;
};

// ============================================================================
// PART 6: THIRD-PARTY LOOKUP
// Resolve third-party identifiers (email, phone, IRC nick) to Matrix user IDs.
// ============================================================================

// --------------------------------------------------------------------------
// ThirdPartyIdentifierResolver - resolve 3PID to MXID
// --------------------------------------------------------------------------
class ThirdPartyIdentifierResolver {
public:
  struct IdentifierRecord {
    std::string id;
    std::string medium;        // email, msisdn, irc_nick, etc.
    std::string address;       // the actual identifier value
    std::string mxid;          // resolved Matrix user ID
    int64_t valid_at;          // timestamp this mapping is valid
    int64_t added_at;
    bool verified{false};
    json extra_data;
  };

  // Add/update an identifier mapping
  IdentifierRecord add_mapping(const std::string& medium,
                                const std::string& address,
                                const std::string& mxid,
                                bool verified = false,
                                const json& extra = json::object()) {
    std::unique_lock lock(mutex_);
    std::string key = make_key(medium, address);

    IdentifierRecord rec;
    rec.id = "3pid_" + generate_uuid();
    rec.medium = medium;
    rec.address = address;
    rec.mxid = mxid;
    rec.valid_at = now_sec() + (86400 * 365); // valid for 1 year
    rec.added_at = now_sec();
    rec.verified = verified;
    rec.extra_data = extra;

    // Replace existing if present
    records_[key] = rec;
    mxid_index_[mxid][medium].push_back(address);

    return rec;
  }

  // Remove a mapping
  bool remove_mapping(const std::string& medium, const std::string& address) {
    std::unique_lock lock(mutex_);
    std::string key = make_key(medium, address);
    auto it = records_.find(key);
    if (it != records_.end()) {
      std::string mxid = it->second.mxid;
      // Clean index
      auto& medium_map = mxid_index_[mxid];
      auto& addr_vec = medium_map[medium];
      addr_vec.erase(std::remove(addr_vec.begin(), addr_vec.end(), address),
                     addr_vec.end());
      if (addr_vec.empty()) medium_map.erase(medium);
      if (medium_map.empty()) mxid_index_.erase(mxid);

      records_.erase(it);
      return true;
    }
    return false;
  }

  // Lookup MXID by medium + address
  std::optional<std::string> lookup(const std::string& medium,
                                     const std::string& address) {
    std::shared_lock lock(mutex_);
    std::string key = make_key(medium, address);
    auto it = records_.find(key);
    if (it != records_.end() && it->second.valid_at > now_sec()) {
      return it->second.mxid;
    }
    return std::nullopt;
  }

  // Get full record
  std::optional<IdentifierRecord> get_record(const std::string& medium,
                                              const std::string& address) {
    std::shared_lock lock(mutex_);
    std::string key = make_key(medium, address);
    auto it = records_.find(key);
    if (it != records_.end()) return it->second;
    return std::nullopt;
  }

  // List all third-party IDs for a MXID
  std::vector<IdentifierRecord> list_for_user(const std::string& mxid) {
    std::shared_lock lock(mutex_);
    std::vector<IdentifierRecord> result;
    auto mit = mxid_index_.find(mxid);
    if (mit != mxid_index_.end()) {
      for (const auto& [medium, addresses] : mit->second) {
        for (const auto& addr : addresses) {
          auto rit = records_.find(make_key(medium, addr));
          if (rit != records_.end()) result.push_back(rit->second);
        }
      }
    }
    return result;
  }

  // Bulk lookup (for identity server /lookup API)
  json bulk_lookup(const std::vector<std::pair<std::string, std::string>>& queries) {
    json results = json::array();
    for (const auto& [medium, address] : queries) {
      auto mxid = lookup(medium, address);
      json entry;
      entry["medium"] = medium;
      entry["address"] = address;
      if (mxid) {
        entry["mxid"] = *mxid;
        entry["found"] = true;
      } else {
        entry["found"] = false;
      }
      results.push_back(entry);
    }
    return results;
  }

  // Search by partial address (for discovery)
  std::vector<IdentifierRecord> search(const std::string& medium,
                                        const std::string& partial) {
    std::shared_lock lock(mutex_);
    std::vector<IdentifierRecord> result;
    std::string lower_partial = to_lower(partial);
    for (const auto& [key, rec] : records_) {
      if (rec.medium == medium &&
          to_lower(rec.address).find(lower_partial) != std::string::npos) {
        if (rec.valid_at > now_sec()) {
          result.push_back(rec);
        }
      }
    }
    return result;
  }

  // Verify an identifier
  bool verify(const std::string& medium, const std::string& address) {
    std::unique_lock lock(mutex_);
    std::string key = make_key(medium, address);
    auto it = records_.find(key);
    if (it != records_.end()) {
      it->second.verified = true;
      return true;
    }
    return false;
  }

  json stats() {
    std::shared_lock lock(mutex_);
    std::map<std::string, size_t> by_medium;
    for (const auto& [key, rec] : records_) {
      by_medium[rec.medium]++;
    }
    return {
      {"total_mappings", records_.size()},
      {"unique_users", mxid_index_.size()},
      {"by_medium", by_medium}
    };
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, IdentifierRecord> records_;
  // mxid -> medium -> [addresses]
  std::unordered_map<std::string,
      std::unordered_map<std::string, std::vector<std::string>>> mxid_index_;

  static std::string make_key(const std::string& medium,
                              const std::string& address) {
    return to_lower(medium) + ":" + to_lower(address);
  }
};

// --------------------------------------------------------------------------
// Specialized lookup providers for specific mediums
// --------------------------------------------------------------------------

// EmailLookupProvider - resolves email -> MXID
class EmailLookupProvider {
public:
  explicit EmailLookupProvider(ThirdPartyIdentifierResolver& resolver)
      : resolver_(resolver) {}

  std::optional<std::string> lookup_email(const std::string& email) {
    if (!is_valid_email(email)) return std::nullopt;
    return resolver_.lookup("email", email);
  }

  // Bind email to MXID
  json bind_email(const std::string& email, const std::string& mxid,
                  bool verified = false) {
    auto rec = resolver_.add_mapping("email", email, mxid, verified);
    return {
      {"id", rec.id},
      {"medium", "email"},
      {"address", rec.address},
      {"mxid", rec.mxid},
      {"verified", rec.verified}
    };
  }

  // Unbind
  bool unbind_email(const std::string& email) {
    return resolver_.remove_mapping("email", email);
  }

  // List emails for user
  json list_for_user(const std::string& mxid) {
    auto records = resolver_.list_for_user(mxid);
    json arr = json::array();
    for (const auto& r : records) {
      if (r.medium == "email") {
        arr.push_back({
            {"email", r.address},
            {"verified", r.verified},
            {"added_at", r.added_at}
        });
      }
    }
    return arr;
  }

private:
  ThirdPartyIdentifierResolver& resolver_;
};

// PhoneLookupProvider - resolves phone -> MXID
class PhoneLookupProvider {
public:
  explicit PhoneLookupProvider(ThirdPartyIdentifierResolver& resolver)
      : resolver_(resolver) {}

  std::optional<std::string> lookup_phone(const std::string& phone) {
    if (!is_valid_phone(phone)) return std::nullopt;
    return resolver_.lookup("msisdn", phone);
  }

  json bind_phone(const std::string& phone, const std::string& mxid,
                  bool verified = false) {
    auto rec = resolver_.add_mapping("msisdn", phone, mxid, verified);
    return {
      {"id", rec.id},
      {"medium", "msisdn"},
      {"address", rec.address},
      {"mxid", rec.mxid},
      {"verified", rec.verified}
    };
  }

  bool unbind_phone(const std::string& phone) {
    return resolver_.remove_mapping("msisdn", phone);
  }

  json list_for_user(const std::string& mxid) {
    auto records = resolver_.list_for_user(mxid);
    json arr = json::array();
    for (const auto& r : records) {
      if (r.medium == "msisdn") {
        arr.push_back({
            {"phone", r.address},
            {"verified", r.verified},
            {"added_at", r.added_at}
        });
      }
    }
    return arr;
  }

private:
  ThirdPartyIdentifierResolver& resolver_;
};

// IRCLookupProvider - resolves IRC nick -> MXID
class IRCLookupProvider {
public:
  explicit IRCLookupProvider(ThirdPartyIdentifierResolver& resolver,
                              IRCNicknameRegistry* nick_registry = nullptr)
      : resolver_(resolver), nick_registry_(nick_registry) {}

  // Lookup by IRC nick on a specific server
  std::optional<std::string> lookup_irc(const std::string& nickname,
                                         const std::string& irc_server) {
    // First try the nickname registry (real-time)
    if (nick_registry_) {
      auto owner = nick_registry_->lookup_owner(nickname, irc_server);
      if (owner) return owner;
    }

    // Then try the 3PID resolver (persisted)
    std::string addr = nickname + "@" + irc_server;
    return resolver_.lookup("irc_nick", addr);
  }

  // Bind IRC nick to MXID
  json bind_irc(const std::string& nickname,
                const std::string& irc_server,
                const std::string& mxid) {
    std::string addr = nickname + "@" + irc_server;
    auto rec = resolver_.add_mapping("irc_nick", addr, mxid);
    return {
      {"id", rec.id},
      {"nickname", nickname},
      {"irc_server", irc_server},
      {"mxid", rec.mxid}
    };
  }

  // Unbind
  bool unbind_irc(const std::string& nickname, const std::string& irc_server) {
    std::string addr = nickname + "@" + irc_server;
    return resolver_.remove_mapping("irc_nick", addr);
  }

  // List IRC nicks for user
  json list_for_user(const std::string& mxid) {
    auto records = resolver_.list_for_user(mxid);
    json arr = json::array();
    for (const auto& r : records) {
      if (r.medium == "irc_nick") {
        arr.push_back({
            {"address", r.address},
            {"verified", r.verified},
            {"added_at", r.added_at}
        });
      }
    }
    return arr;
  }

private:
  ThirdPartyIdentifierResolver& resolver_;
  IRCNicknameRegistry* nick_registry_{nullptr};
};

// ============================================================================
// ThirdPartyLookup - top-level third-party identifier lookup service
// ============================================================================
class ThirdPartyLookup {
public:
  ThirdPartyLookup(IRCNicknameRegistry* nick_registry = nullptr)
      : resolver_(std::make_unique<ThirdPartyIdentifierResolver>()),
        email_provider_(std::make_unique<EmailLookupProvider>(*resolver_)),
        phone_provider_(std::make_unique<PhoneLookupProvider>(*resolver_)),
        irc_provider_(std::make_unique<IRCLookupProvider>(*resolver_, nick_registry)) {}

  // ---- Generic lookup ----
  std::optional<std::string> lookup(ThirdPartyMedium medium,
                                     const std::string& address,
                                     const std::string& extra = "") {
    switch (medium) {
      case ThirdPartyMedium::EMAIL:
        return email_provider_->lookup_email(address);
      case ThirdPartyMedium::MSISDN:
        return phone_provider_->lookup_phone(address);
      case ThirdPartyMedium::IRC_NICK:
        return irc_provider_->lookup_irc(address, extra);
      default:
        return resolver_->lookup(third_party_medium_str(medium), address);
    }
  }

  // ---- Generic binding ----
  json bind(ThirdPartyMedium medium,
            const std::string& address,
            const std::string& mxid,
            bool verified = false,
            const std::string& extra = "") {
    switch (medium) {
      case ThirdPartyMedium::EMAIL:
        return email_provider_->bind_email(address, mxid, verified);
      case ThirdPartyMedium::MSISDN:
        return phone_provider_->bind_phone(address, mxid, verified);
      case ThirdPartyMedium::IRC_NICK:
        return irc_provider_->bind_irc(address, extra, mxid);
      default:
        {
          auto rec = resolver_->add_mapping(
              third_party_medium_str(medium), address, mxid, verified);
          return json{{"id", rec.id}, {"medium", rec.medium},
                      {"address", rec.address}, {"mxid", rec.mxid}};
        }
    }
  }

  // ---- Generic unbind ----
  bool unbind(ThirdPartyMedium medium,
              const std::string& address,
              const std::string& extra = "") {
    switch (medium) {
      case ThirdPartyMedium::EMAIL:
        return email_provider_->unbind_email(address);
      case ThirdPartyMedium::MSISDN:
        return phone_provider_->unbind_phone(address);
      case ThirdPartyMedium::IRC_NICK:
        return irc_provider_->unbind_irc(address, extra);
      default:
        return resolver_->remove_mapping(
            third_party_medium_str(medium), address);
    }
  }

  // ---- List all 3PIDs for a user ----
  json list_for_user(const std::string& mxid) {
    json result;
    result["emails"] = email_provider_->list_for_user(mxid);
    result["phones"] = phone_provider_->list_for_user(mxid);
    result["irc_nicks"] = irc_provider_->list_for_user(mxid);

    auto all_records = resolver_->list_for_user(mxid);
    json custom = json::array();
    for (const auto& r : all_records) {
      if (r.medium != "email" && r.medium != "msisdn" && r.medium != "irc_nick") {
        custom.push_back({
            {"medium", r.medium},
            {"address", r.address},
            {"verified", r.verified}
        });
      }
    }
    result["custom"] = custom;
    return result;
  }

  // ---- Bulk lookup ----
  json bulk_lookup(const std::vector<std::pair<ThirdPartyMedium, std::string>>& queries) {
    json results = json::array();
    for (const auto& [medium, addr] : queries) {
      auto mxid = lookup(medium, addr);
      json entry;
      entry["medium"] = third_party_medium_str(medium);
      entry["address"] = addr;
      entry["found"] = mxid.has_value();
      if (mxid) entry["mxid"] = *mxid;
      results.push_back(entry);
    }
    return results;
  }

  // ---- Identity server lookup API ----
  json identity_lookup(const std::string& medium,
                       const std::string& address) {
    ThirdPartyMedium m = third_party_medium_from_str(medium);
    auto mxid = lookup(m, address);
    if (!mxid) return {{"found", false}};
    return {
      {"found", true},
      {"medium", medium},
      {"address", address},
      {"mxid", *mxid}
    };
  }

  // ---- Stats ----
  json stats() { return resolver_->stats(); }

  // ---- Access internals ----
  ThirdPartyIdentifierResolver& resolver() { return *resolver_; }
  EmailLookupProvider& email() { return *email_provider_; }
  PhoneLookupProvider& phone() { return *phone_provider_; }
  IRCLookupProvider& irc() { return *irc_provider_; }

private:
  std::unique_ptr<ThirdPartyIdentifierResolver> resolver_;
  std::unique_ptr<EmailLookupProvider> email_provider_;
  std::unique_ptr<PhoneLookupProvider> phone_provider_;
  std::unique_ptr<IRCLookupProvider> irc_provider_;
};

// ============================================================================
// PART 7: BRIDGE ADMIN FACADE
// Unifies all bridge subsystems under a single admin interface.
// ============================================================================
class BridgeAdmin {
public:
  BridgeAdmin()
      : irc_(std::make_unique<IRCBridgeAdmin>()),
        email_(std::make_unique<EmailBridgeAdmin>()),
        webhook_(std::make_unique<WebhookBridgeAdmin>()),
        bots_(std::make_unique<BotSDKAdmin>()),
        integrations_(std::make_unique<IntegrationManager>()),
        third_party_(std::make_unique<ThirdPartyLookup>(&irc_->nicknames())) {}

  // ---- Subsystem access ----
  IRCBridgeAdmin& irc() { return *irc_; }
  EmailBridgeAdmin& email() { return *email_; }
  WebhookBridgeAdmin& webhook() { return *webhook_; }
  BotSDKAdmin& bots() { return *bots_; }
  IntegrationManager& integrations() { return *integrations_; }
  ThirdPartyLookup& third_party() { return *third_party_; }

  // ---- Comprehensive status ----
  json get_full_status() {
    json status;
    status["irc"] = {
      {"connections", irc_->get_connection_summary()},
      {"mappings_count", irc_->channel_mappings().count()},
      {"nicks_count", irc_->nicknames().count()}
    };
    status["email"] = {
      {"routes_count", email_->gateway().count()},
      {"invite_stats", email_->invites().stats()}
    };
    status["webhooks"] = webhook_->get_status();
    status["bots"] = bots_->get_status();
    status["integrations"] = integrations_->get_status();
    status["third_party"] = third_party_->stats();
    status["timestamp"] = current_iso8601();

    return status;
  }

  // ---- Generate admin report ----
  std::string generate_report() {
    std::stringstream ss;
    ss << "=== Bridge Admin Report ===\n"
       << "Generated: " << current_iso8601() << "\n\n";

    auto s = get_full_status();
    ss << "IRC Connections: " << s["irc"]["connections"]["total_connections"] << " total, "
       << s["irc"]["connections"]["connected"] << " connected\n";
    ss << "IRC Mappings: " << s["irc"]["mappings_count"] << "\n";
    ss << "Email Routes: " << s["email"]["routes_count"] << "\n";
    ss << "Webhooks: " << s["webhooks"]["total_webhooks"] << "\n";
    ss << "Bots: " << s["bots"]["bot_count"] << "\n";
    ss << "Active Integrations: " << s["integrations"]["active_instances"] << "\n";
    ss << "3PID Mappings: " << s["third_party"]["total_mappings"] << "\n";

    return ss.str();
  }

  // ---- Shutdown all bridges ----
  void shutdown() {
    irc_->connection_pool().disconnect_all();
  }

private:
  std::unique_ptr<IRCBridgeAdmin> irc_;
  std::unique_ptr<EmailBridgeAdmin> email_;
  std::unique_ptr<WebhookBridgeAdmin> webhook_;
  std::unique_ptr<BotSDKAdmin> bots_;
  std::unique_ptr<IntegrationManager> integrations_;
  std::unique_ptr<ThirdPartyLookup> third_party_;
};

// ============================================================================
// PART 8: REST API HANDLERS (Bridge Admin HTTP endpoints)
// ============================================================================

// Bridge REST API handler - serves the /_progressive/bridge/ endpoints
class BridgeAdminRestAPI {
public:
  explicit BridgeAdminRestAPI(BridgeAdmin& bridge) : bridge_(bridge) {}

  // Handle GET /_progressive/bridge/status
  json handle_get_status() {
    return bridge_.get_full_status();
  }

  // Handle GET /_progressive/bridge/report
  std::string handle_get_report() {
    return bridge_.generate_report();
  }

  // ---- IRC Endpoints ----

  json handle_get_irc_connections() {
    return bridge_.irc().get_all_connections_status();
  }

  json handle_get_irc_connection(const std::string& conn_id) {
    return bridge_.irc().get_connection_status(conn_id);
  }

  json handle_post_irc_connect(const std::string& conn_id) {
    bool ok = bridge_.irc().connect_server(conn_id);
    return {{"success", ok}, {"connection_id", conn_id}};
  }

  json handle_post_irc_disconnect(const std::string& conn_id) {
    bool ok = bridge_.irc().disconnect_server(conn_id);
    return {{"success", ok}, {"connection_id", conn_id}};
  }

  json handle_post_irc_register_server(const json& body) {
    std::string host = body.value("host", "");
    int port = body.value("port", 6667);
    std::string nick = body.value("nickname", "matrixbot");
    std::string nspass = body.value("nickserv_password", "");
    bool ssl = body.value("ssl", false);
    std::vector<std::string> autojoin;
    if (body.contains("autojoin_channels"))
      autojoin = body["autojoin_channels"].get<std::vector<std::string>>();

    std::string conn_id = bridge_.irc().add_irc_server(
        host, port, nick, nspass, ssl, autojoin);
    return {{"success", true}, {"connection_id", conn_id}};
  }

  json handle_get_irc_mappings() {
    return bridge_.irc().get_all_mappings();
  }

  json handle_post_irc_map(const json& body) {
    std::string room = body.value("matrix_room_id", "");
    std::string channel = body.value("irc_channel", "");
    std::string server = body.value("irc_server", "");
    std::string bridge_user = body.value("bridge_user", "@ircbot:localhost");

    std::string map_id = bridge_.irc().map_channel(
        room, channel, server, bridge_user);
    return {{"success", true}, {"mapping_id", map_id}};
  }

  json handle_delete_irc_map(const std::string& map_id) {
    bool ok = bridge_.irc().unmap_channel(map_id);
    return {{"success", ok}};
  }

  json handle_get_irc_nicks() {
    return bridge_.irc().get_all_nicks();
  }

  // ---- Email Endpoints ----

  json handle_get_email_routes() {
    return bridge_.email().gateway().list_routes();
  }

  json handle_post_email_route(const json& body) {
    std::string email = body.value("email", "");
    std::string room = body.value("room_id", "");
    auto route = bridge_.email().gateway().create_route(email, room);
    return {{"success", true}, {"route_id", route.id}};
  }

  json handle_delete_email_route(const std::string& route_id) {
    bool ok = bridge_.email().gateway().delete_route(route_id);
    return {{"success", ok}};
  }

  json handle_post_email_invite(const json& body) {
    return bridge_.email().create_email_invite(
        body.value("email", ""),
        body.value("room_id", ""),
        body.value("invited_by", ""));
  }

  json handle_get_email_stats() {
    return bridge_.email().invites().stats();
  }

  // ---- Webhook Endpoints ----

  json handle_get_webhooks() {
    return bridge_.webhook().list_webhooks();
  }

  json handle_post_webhook(const json& body) {
    return bridge_.webhook().create_webhook(
        body.value("name", ""),
        body.value("room_id", ""),
        body.value("bridge_user", "@webhookbot:localhost"));
  }

  json handle_delete_webhook(const std::string& wh_id) {
    bool ok = bridge_.webhook().delete_webhook(wh_id);
    return {{"success", ok}};
  }

  json handle_post_webhook_receive(const std::string& path,
                                   const json& body) {
    return bridge_.webhook().handle_incoming(path, body);
  }

  // ---- Bot Endpoints ----

  json handle_get_bots() {
    return bridge_.bots().list_bots();
  }

  json handle_post_bot_create(const json& body) {
    return bridge_.bots().create_bot(
        body.value("localpart", ""),
        body.value("server_name", "localhost"),
        body.value("owner", ""),
        body.value("display_name", ""));
  }

  json handle_delete_bot(const std::string& bot_id) {
    bool ok = bridge_.bots().delete_bot(bot_id);
    return {{"success", ok}};
  }

  json handle_post_bot_token(const json& body) {
    return bridge_.bots().issue_token(
        body.value("bot_user_id", ""),
        body.value("scopes", std::vector<std::string>{"read", "write"}),
        body.value("ttl_sec", 0));
  }

  // ---- Integration Endpoints ----

  json handle_get_integrations() {
    return bridge_.integrations().list_supported_integrations();
  }

  json handle_post_integration_install(const json& body) {
    return bridge_.integrations().install_integration(
        body.value("type_id", ""),
        body.value("room_id", ""),
        body.value("user_id", ""));
  }

  json handle_delete_integration(const std::string& inst_id) {
    bool ok = bridge_.integrations().uninstall_integration(inst_id);
    return {{"success", ok}};
  }

  json handle_get_widgets_for_room(const std::string& room_id) {
    return bridge_.integrations().list_widgets_for_room(room_id);
  }

  json handle_post_widget(const json& body) {
    return bridge_.integrations().create_widget(
        body.value("room_id", ""),
        body.value("name", ""),
        body.value("widget_url", ""),
        body.value("widget_type", "m.custom"),
        body.value("creator", ""));
  }

  // ---- Third-Party Lookup Endpoints ----

  json handle_get_3pid_lookup(const std::string& medium,
                              const std::string& address) {
    return bridge_.third_party().identity_lookup(medium, address);
  }

  json handle_post_3pid_bind(const json& body) {
    ThirdPartyMedium m = third_party_medium_from_str(
        body.value("medium", "email"));
    return bridge_.third_party().bind(
        m,
        body.value("address", ""),
        body.value("mxid", ""),
        body.value("verified", false));
  }

  json handle_delete_3pid(const std::string& medium,
                          const std::string& address) {
    ThirdPartyMedium m = third_party_medium_from_str(medium);
    bool ok = bridge_.third_party().unbind(m, address);
    return {{"success", ok}};
  }

  json handle_get_user_3pids(const std::string& mxid) {
    return bridge_.third_party().list_for_user(mxid);
  }

  // ---- Shutdown ----
  json handle_post_shutdown() {
    bridge_.shutdown();
    return {{"success", true}, {"message", "Bridges shutting down"}};
  }

private:
  BridgeAdmin& bridge_;
};

// ============================================================================
// PART 9: YAML CONFIGURATION LOADER
// ============================================================================
class BridgeConfigLoader {
public:
  struct BridgeConfig {
    // IRC
    std::vector<IRCConnection::Config> irc_connections;

    // Email
    struct EmailConfig {
      std::string smtp_host;
      int smtp_port{587};
      std::string smtp_username;
      std::string smtp_password;
      bool smtp_tls{true};
      std::string from_address;
      std::string from_name{"Progressive Matrix"};
    } email;

    // Webhook
    struct WebhookConfig {
      std::string base_url;       // e.g. "https://matrix.example.com/webhooks"
      bool require_hmac{true};
      size_t max_payload_size{1048576}; // 1 MB
    } webhook;

    // Bots
    struct BotConfig {
      std::string default_server;
      bool allow_user_bots{true};
      int max_bots_per_user{10};
    } bots;

    // General
    bool auto_start_bridges{false};
    std::string data_directory{"/var/lib/progressive/bridges"};
  };

  static BridgeConfig load_from_yaml(const std::string& path) {
    BridgeConfig config;
    try {
      YAML::Node root = YAML::LoadFile(path);
      if (!root.IsMap()) return config;

      // IRC connections
      if (root["irc"] && root["irc"]["connections"]) {
        for (const auto& conn : root["irc"]["connections"]) {
          IRCConnection::Config irc_cfg;
          irc_cfg.server_host = conn["host"].as<std::string>("");
          irc_cfg.server_port = conn["port"].as<int>(6667);
          irc_cfg.use_ssl = conn["ssl"].as<bool>(false);
          irc_cfg.nickname = conn["nickname"].as<std::string>("matrixbot");
          irc_cfg.username = conn["username"].as<std::string>(irc_cfg.nickname);
          irc_cfg.realname = conn["realname"].as<std::string>("Progressive Matrix Bridge");
          irc_cfg.nickserv_password = conn["nickserv_password"].as<std::string>("");
          irc_cfg.password = conn["password"].as<std::string>("");

          if (conn["autojoin_channels"]) {
            for (const auto& ch : conn["autojoin_channels"]) {
              irc_cfg.autojoin_channels.push_back(ch.as<std::string>());
            }
          }

          irc_cfg.reconnect_delay_ms = conn["reconnect_delay_ms"].as<int>(5000);
          irc_cfg.max_reconnect_attempts = conn["max_reconnect_attempts"].as<int>(10);

          config.irc_connections.push_back(std::move(irc_cfg));
        }
      }

      // Email config
      if (root["email"]) {
        auto& em = root["email"];
        config.email.smtp_host = em["smtp_host"].as<std::string>("");
        config.email.smtp_port = em["smtp_port"].as<int>(587);
        config.email.smtp_username = em["smtp_username"].as<std::string>("");
        config.email.smtp_password = em["smtp_password"].as<std::string>("");
        config.email.smtp_tls = em["smtp_tls"].as<bool>(true);
        config.email.from_address = em["from_address"].as<std::string>("");
        config.email.from_name = em["from_name"].as<std::string>("Progressive Matrix");
      }

      // Webhook config
      if (root["webhook"]) {
        auto& wh = root["webhook"];
        config.webhook.base_url = wh["base_url"].as<std::string>("");
        config.webhook.require_hmac = wh["require_hmac"].as<bool>(true);
        config.webhook.max_payload_size =
            wh["max_payload_size"].as<size_t>(1048576);
      }

      // Bot config
      if (root["bots"]) {
        auto& bt = root["bots"];
        config.bots.default_server =
            bt["default_server"].as<std::string>("localhost");
        config.bots.allow_user_bots = bt["allow_user_bots"].as<bool>(true);
        config.bots.max_bots_per_user = bt["max_bots_per_user"].as<int>(10);
      }

      // General
      config.auto_start_bridges =
          root["auto_start_bridges"].as<bool>(false);
      config.data_directory =
          root["data_directory"].as<std::string>("/var/lib/progressive/bridges");

    } catch (const YAML::Exception& e) {
      std::cerr << "[BridgeConfigLoader] YAML parse error: " << e.what()
                << std::endl;
    }
    return config;
  }

  // Apply loaded config to BridgeAdmin
  static void apply_to_bridge(BridgeAdmin& bridge, const BridgeConfig& config) {
    // Register IRC connections
    for (auto& irc_cfg : config.irc_connections) {
      bridge.irc().connection_pool().add_connection(irc_cfg);
    }

    // Auto-start if configured
    if (config.auto_start_bridges) {
      bridge.irc().connection_pool().connect_all();
    }
  }
};

// ============================================================================
// PART 10: METRICS AND MONITORING
// ============================================================================
class BridgeAdminMetrics {
public:
  BridgeAdminMetrics() { reset(); }

  void record_irc_message_bridged() { irc_msgs_bridged_++; }
  void record_irc_connection_attempt(bool success) {
    if (success) irc_connections_ok_++;
    else irc_connections_failed_++;
  }
  void record_email_processed() { email_processed_++; }
  void record_webhook_triggered(bool passed) {
    if (passed) webhooks_accepted_++;
    else webhooks_rejected_++;
  }
  void record_bot_token_issued() { bot_tokens_issued_++; }
  void record_3pid_lookup(ThirdPartyMedium medium) {
    std::string m = third_party_medium_str(medium);
    lookup_by_medium_[m]++;
  }

  json snapshot() {
    return {
      {"irc", {
        {"messages_bridged", irc_msgs_bridged_.load()},
        {"connections_ok", irc_connections_ok_.load()},
        {"connections_failed", irc_connections_failed_.load()}
      }},
      {"email", {
        {"emails_processed", email_processed_.load()}
      }},
      {"webhooks", {
        {"accepted", webhooks_accepted_.load()},
        {"rejected", webhooks_rejected_.load()}
      }},
      {"bots", {
        {"tokens_issued", bot_tokens_issued_.load()}
      }},
      {"third_party_lookups", lookup_by_medium_}
    };
  }

  void reset() {
    irc_msgs_bridged_ = 0;
    irc_connections_ok_ = 0;
    irc_connections_failed_ = 0;
    email_processed_ = 0;
    webhooks_accepted_ = 0;
    webhooks_rejected_ = 0;
    bot_tokens_issued_ = 0;
    lookup_by_medium_.clear();
  }

private:
  std::atomic<int64_t> irc_msgs_bridged_{0};
  std::atomic<int64_t> irc_connections_ok_{0};
  std::atomic<int64_t> irc_connections_failed_{0};
  std::atomic<int64_t> email_processed_{0};
  std::atomic<int64_t> webhooks_accepted_{0};
  std::atomic<int64_t> webhooks_rejected_{0};
  std::atomic<int64_t> bot_tokens_issued_{0};
  std::map<std::string, int64_t> lookup_by_medium_;
};

}  // namespace progressive
