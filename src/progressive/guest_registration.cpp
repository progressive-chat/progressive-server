// ============================================================================
// guest_registration.cpp — Matrix Guest Access, Registration Tokens,
//   Account Data, OpenID, Login Tokens, and User-Interactive Authentication
//
// Implements:
//   - GuestAccess: guest registration, guest user IDs (@guest_XXXX:domain),
//     restrict guest capabilities (no room creation, max rooms joined,
//     auto-cleanup), guest account expiration
//   - RegistrationTokens: create token with uses_allowed/pending/completed/
//     expiry_time, validate token, consume token on registration, list all
//     tokens, update token, delete token, get token usage stats
//   - AccountData: global account data (m.direct, m.push_rules,
//     m.ignored_user_list, org.matrix.preview_urls, m.widgets),
//     room-specific account data, sync account data stream
//   - OpenID: generate OpenID token (access_token + expires_in +
//     matrix_server_name), exchange token for user info, validate token,
//     revoke token
//   - LoginToken: create short-lived login tokens, validate login token,
//     exchange for access token (POST /login with token auth type)
//   - UserInteractiveAuth: session management for UI auth (create session,
//     validate stage, mark stage complete, get completed stages,
//     session expiry)
//
// Equivalent to synapse/handlers/guest.py +
//              synapse/handlers/register.py (registration token parts) +
//              synapse/handlers/account_data.py +
//              synapse/rest/client/v1/openid.py +
//              synapse/handlers/auth.py (login token parts) +
//              synapse/handlers/ui_auth/
// Target: 2500+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
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

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/registration.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class GuestAccess;
class RegistrationTokenManager;
class AccountDataManager;
class OpenIDManager;
class LoginTokenManager;
class UserInteractiveAuthSessionManager;
class GuestRegistry;
class TokenStore;
class AccountDataStore;
class OpenIDTokenStore;
class LoginTokenStore;
class UIASessionStore;

// ============================================================================
// Anonymous namespace — Internal helper utilities
// ============================================================================
namespace {

// ---- Timestamp helpers ----

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

std::string now_iso8601() {
  auto now = chr::system_clock::now();
  auto tt = chr::system_clock::to_time_t(now);
  std::ostringstream oss;
  oss << std::put_time(std::gmtime(&tt), "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

// ---- String helpers ----

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

std::string trim(const std::string& s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> tokens;
  std::istringstream iss(s);
  std::string token;
  while (std::getline(iss, token, delim)) {
    if (!token.empty()) tokens.push_back(token);
  }
  return tokens;
}

std::string join(const std::vector<std::string>& parts,
                  const std::string& sep) {
  std::ostringstream oss;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i > 0) oss << sep;
    oss << parts[i];
  }
  return oss.str();
}

// ---- Random generation ----

std::string generate_hex(size_t len) {
  static const char hex_chars[] = "0123456789abcdef";
  static thread_local std::mt19937 rng(
      static_cast<unsigned>(
          chr::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<int> dist(0, 15);
  std::string out(len, '\0');
  for (size_t i = 0; i < len; ++i) out[i] = hex_chars[dist(rng)];
  return out;
}

std::string generate_token(int len = 64) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(
      static_cast<unsigned>(
          chr::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<int> dist(0, 61);
  std::string out(len, '\0');
  for (int i = 0; i < len; ++i) out[i] = alphabet[dist(rng)];
  return out;
}

std::string generate_numeric_token(int digits = 6) {
  static thread_local std::mt19937 rng(
      static_cast<unsigned>(
          chr::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<int> dist(0, 9);
  std::string out(digits, '0');
  for (int i = 0; i < digits; ++i) out[i] = static_cast<char>('0' + dist(rng));
  return out;
}

std::string generate_guest_suffix(int length = 8) {
  static const char alphanum_lower[] =
      "abcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(
      static_cast<unsigned>(
          chr::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<int> dist(0, 35);
  std::string out(length, '\0');
  for (int i = 0; i < length; ++i) out[i] = alphanum_lower[dist(rng)];
  return out;
}

std::string generate_openid_token() {
  // OpenID tokens: "oid_" prefix + 32 hex chars
  return "oid_" + generate_hex(32);
}

std::string generate_login_token_str() {
  // Login tokens: "mlt_" prefix + 32 hex chars
  return "mlt_" + generate_hex(32);
}

std::string generate_ui_session_id() {
  // UI auth session IDs: "uias_" prefix + 16 hex chars
  return "uias_" + generate_hex(16);
}

std::string generate_registration_token_str() {
  // Registration tokens: "mrt_" prefix + 24 hex chars
  return "mrt_" + generate_hex(24);
}

// ---- SHA-256 placeholder ----
std::array<unsigned char, 32> sha256_raw(const std::string& input) {
  std::array<unsigned char, 32> hash{};
  for (size_t i = 0; i < input.size(); ++i) {
    hash[i % 32] ^= static_cast<unsigned char>(input[i]);
    hash[(i * 7 + 13) % 32] ^= static_cast<unsigned char>(input[i]);
    hash[(i * 3 + 29) % 32] ^= static_cast<unsigned char>(input[i] >> 1);
    hash[(i * 11 + 5) % 32] ^= static_cast<unsigned char>(
        (input[i] * 173) & 0xFF);
  }
  for (size_t i = 0; i < 32; ++i) {
    hash[i] = static_cast<unsigned char>((hash[i] * 2654435761ULL) & 0xFF);
  }
  for (int pass = 0; pass < 3; ++pass) {
    for (size_t i = 0; i < 32; ++i) {
      hash[(i + pass) % 32] ^=
          static_cast<unsigned char>((hash[i] * 97 + pass * 31) & 0xFF);
    }
  }
  return hash;
}

std::string sha256_hex(const std::string& input) {
  auto hash = sha256_raw(input);
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (auto b : hash) oss << std::setw(2) << static_cast<int>(b);
  return oss.str();
}

// ---- Base64 helpers ----
static const char kBase64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& input) {
  std::string output;
  output.reserve(((input.size() + 2) / 3) * 4);
  int val = 0, valb = -6;
  for (unsigned char c : input) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      output.push_back(kBase64Chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) {
    output.push_back(kBase64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
  }
  while (output.size() % 4) output.push_back('=');
  return output;
}

std::string base64url_encode(const std::string& input) {
  std::string b64 = base64_encode(input);
  while (!b64.empty() && b64.back() == '=') b64.pop_back();
  for (char& c : b64) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  return b64;
}

// ---- URL encoding ----
std::string url_encode(const std::string& s) {
  std::ostringstream escaped;
  escaped << std::hex << std::uppercase;
  for (unsigned char c : s) {
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      escaped << c;
    } else {
      escaped << '%' << std::setw(2) << std::setfill('0')
              << static_cast<int>(c);
    }
  }
  return escaped.str();
}

// ---- JSON helpers ----
json error_response(const std::string& errcode, const std::string& error_msg,
                    int status = 400) {
  return json({
      {"errcode", errcode},
      {"error", error_msg},
      {"status", status}
  });
}

json success_response(const json& data = {}) {
  return data;
}

// ---- Time formatting ----
std::string format_timestamp_iso(int64_t epoch_ms) {
  auto tt = static_cast<std::time_t>(epoch_ms / 1000);
  std::ostringstream oss;
  oss << std::put_time(std::gmtime(&tt), "%Y-%m-%dT%H:%M:%S.");
  oss << std::setfill('0') << std::setw(3) << (epoch_ms % 1000) << "Z";
  return oss.str();
}

} // anonymous namespace

// ============================================================================
// Configuration constants
// ============================================================================
namespace config {

// Guest configuration
constexpr int64_t kGuestAccessTokenTTLMs = 3'600'000;       // 1 hour
constexpr int64_t kGuestAccountMaxAgeMs = 86'400'000;       // 24 hours
constexpr int     kGuestMaxRoomsJoined = 10;
constexpr int     kGuestCleanupIntervalSec = 300;            // 5 minutes
constexpr size_t  kGuestSuffixLength = 8;
constexpr bool    kGuestCanSendEvents = true;
constexpr bool    kGuestCanJoinRooms = true;
constexpr bool    kGuestCanReadMessages = true;
constexpr bool    kGuestCanCreateRooms = false;
constexpr bool    kGuestCanInvite = false;
constexpr bool    kGuestCanKick = false;
constexpr bool    kGuestCanBan = false;
constexpr bool    kGuestCanSetPowerLevels = false;

// Registration token configuration
constexpr int64_t kRegTokenDefaultTTLMs = 2'592'000'000;    // 30 days
constexpr int     kRegTokenMaxUsesAllowed = 10000;
constexpr int     kRegTokenCleanupIntervalSec = 600;         // 10 minutes

// OpenID configuration
constexpr int64_t kOpenIDTokenTTLMs = 300'000;               // 5 minutes
constexpr int     kOpenIDCleanupIntervalSec = 120;            // 2 minutes

// Login token configuration
constexpr int64_t kLoginTokenTTLMs = 300'000;                // 5 minutes
constexpr int     kLoginTokenCleanupIntervalSec = 60;         // 1 minute
constexpr size_t  kLoginTokenMaxPerUser = 5;

// UI Auth configuration
constexpr int64_t kUIASessionTTLMs = 1'800'000;              // 30 minutes
constexpr int     kUIASessionCleanupIntervalSec = 300;        // 5 minutes
constexpr size_t  kUIASessionMaxStages = 10;

// Account data configuration
constexpr int64_t kAccountDataMaxValueSize = 65536;           // 64 KB
constexpr size_t  kAccountDataMaxKeysPerType = 100;

} // namespace config

// ============================================================================
// GuestAccess
//
// Manages guest user registration, access tokens, capability restrictions,
// room join limits, auto-cleanup of expired guests, and guest lifecycle.
//
// Guest user IDs follow the format: @guest_XXXXXXXX:domain
// Guest access tokens are scoped and short-lived (default 1 hour).
// ============================================================================
class GuestAccess {
public:
  // Guest user info
  struct GuestInfo {
    std::string user_id;
    std::string display_name;
    std::string access_token;
    std::string device_id;
    int64_t created_at_ms{0};
    int64_t expires_at_ms{0};
    int64_t last_active_ms{0};
    int rooms_joined{0};
    bool active{true};
    std::string ip_address;
    std::set<std::string> joined_room_ids;
  };

  // Guest capability flags
  struct GuestCapabilities {
    bool can_send_events{true};
    bool can_join_rooms{true};
    bool can_read_messages{true};
    bool can_create_rooms{false};
    bool can_invite{false};
    bool can_kick{false};
    bool can_ban{false};
    bool can_set_power_levels{false};
    int max_rooms_joined{10};
  };

  explicit GuestAccess(const std::string& server_name)
      : server_name_(server_name),
        guest_counter_(0) {
    cleaner_running_ = true;
    cleaner_thread_ = std::thread([this]() { this->cleaner_loop(); });
  }

  ~GuestAccess() {
    cleaner_running_ = false;
    if (cleaner_thread_.joinable()) cleaner_thread_.join();
  }

  // ---- Guest Registration ----

  /// Register a new guest user.
  /// Returns a GuestInfo with access_token, user_id, device_id, etc.
  /// If registration is disabled via server config, returns empty optional.
  std::optional<GuestInfo> register_guest(
      const std::string& ip_address = "127.0.0.1",
      const std::string& display_name_hint = "",
      bool read_only = false) {

    // Check if guest registration is enabled
    if (!guest_registration_enabled_) {
      return std::nullopt;
    }

    // Generate unique guest suffix
    std::string suffix;
    {
      std::lock_guard<std::shared_mutex> lock(mutex_);
      int attempts = 0;
      do {
        suffix = generate_guest_suffix(config::kGuestSuffixLength);
        if (++attempts > 100) return std::nullopt;  // collision safety valve
      } while (guest_by_suffix_.find(suffix) != guest_by_suffix_.end());
    }

    GuestInfo info;
    info.user_id = "@guest_" + suffix + ":" + server_name_;
    info.access_token = generate_token(64);
    info.device_id = "guest_" + suffix;
    info.created_at_ms = now_ms();
    info.expires_at_ms = now_ms() + config::kGuestAccountMaxAgeMs;
    info.last_active_ms = now_ms();
    info.ip_address = ip_address;
    info.active = true;

    // Set display name
    if (!display_name_hint.empty()) {
      info.display_name = display_name_hint;
    } else {
      info.display_name = "Guest " + suffix;
    }

    // Apply capability restrictions
    if (read_only) {
      info.display_name += " (read-only)";
    }

    // Register the guest
    {
      std::lock_guard<std::shared_mutex> lock(mutex_);
      guests_by_token_[info.access_token] = info;
      guests_by_user_id_[info.user_id] = info;
      guest_by_suffix_[suffix] = info.user_id;
      guest_counter_++;
    }

    return info;
  }

  /// Get a guest by access token
  std::optional<GuestInfo> get_guest_by_token(const std::string& access_token) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it != guests_by_token_.end()) {
      auto& guest = it->second;

      // Check expiration
      if (now_ms() > guest.expires_at_ms) {
        return std::nullopt;
      }

      // Check deactivated
      if (!guest.active) {
        return std::nullopt;
      }

      // Update last_active
      return guest;
    }
    return std::nullopt;
  }

  /// Get a guest by user ID
  std::optional<GuestInfo> get_guest_by_user_id(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = guests_by_user_id_.find(user_id);
    if (it != guests_by_user_id_.end()) {
      if (now_ms() > it->second.expires_at_ms || !it->second.active) {
        return std::nullopt;
      }
      return it->second;
    }
    return std::nullopt;
  }

  /// Check if a user ID belongs to a guest
  bool is_guest(const std::string& user_id) {
    return starts_with(user_id, "@guest_");
  }

  /// Update guest's last active timestamp
  bool touch_guest(const std::string& access_token) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it != guests_by_token_.end() && it->second.active) {
      it->second.last_active_ms = now_ms();
      return true;
    }
    return false;
  }

  /// Revoke guest access token (logout)
  bool revoke_guest(const std::string& access_token) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it != guests_by_token_.end()) {
      auto user_id = it->second.user_id;
      guests_by_token_.erase(it);
      guests_by_user_id_.erase(user_id);
      return true;
    }
    return false;
  }

  /// Deactivate a guest (permanently)
  bool deactivate_guest(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_user_id_.find(user_id);
    if (it != guests_by_user_id_.end()) {
      it->second.active = false;
      // Also remove token mapping
      guests_by_token_.erase(it->second.access_token);
      return true;
    }
    return false;
  }

  // ---- Room Limits ----

  /// Check if guest can join another room
  bool can_join_room(const std::string& access_token) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it == guests_by_token_.end() || !it->second.active) return false;

    const auto& caps = guest_capabilities_;
    return caps.can_join_rooms &&
           it->second.joined_room_ids.size() <
               static_cast<size_t>(caps.max_rooms_joined);
  }

  /// Record that a guest joined a room
  bool record_room_join(const std::string& access_token,
                         const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it == guests_by_token_.end() || !it->second.active) return false;

    if (it->second.joined_room_ids.size() >=
        static_cast<size_t>(guest_capabilities_.max_rooms_joined)) {
      return false;
    }

    it->second.joined_room_ids.insert(room_id);
    it->second.rooms_joined = static_cast<int>(
        it->second.joined_room_ids.size());
    return true;
  }

  /// Record that a guest left a room
  bool record_room_leave(const std::string& access_token,
                          const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it == guests_by_token_.end()) return false;

    it->second.joined_room_ids.erase(room_id);
    it->second.rooms_joined = static_cast<int>(
        it->second.joined_room_ids.size());
    return true;
  }

  /// Get rooms a guest has joined
  std::set<std::string> get_guest_rooms(const std::string& access_token) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it != guests_by_token_.end() && it->second.active) {
      return it->second.joined_room_ids;
    }
    return {};
  }

  // ---- Capability Management ----

  /// Get current guest capabilities
  GuestCapabilities get_capabilities() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return guest_capabilities_;
  }

  /// Update guest capabilities
  void set_capabilities(const GuestCapabilities& caps) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    guest_capabilities_ = caps;
  }

  /// Check specific capability for a guest
  bool check_capability(const std::string& access_token,
                         const std::string& capability) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it == guests_by_token_.end() || !it->second.active) return false;

    const auto& caps = guest_capabilities_;
    if (capability == "create_room") return caps.can_create_rooms;
    if (capability == "invite") return caps.can_invite;
    if (capability == "kick") return caps.can_kick;
    if (capability == "ban") return caps.can_ban;
    if (capability == "set_power_levels") return caps.can_set_power_levels;
    if (capability == "send_events") return caps.can_send_events;
    if (capability == "join_rooms") return caps.can_join_rooms;
    if (capability == "read_messages") return caps.can_read_messages;

    return false;
  }

  // ---- Access Token Refresh ----

  /// Refresh guest access token (extend TTL)
  std::optional<std::string> refresh_access_token(
      const std::string& old_token) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(old_token);
    if (it == guests_by_token_.end() || !it->second.active) {
      return std::nullopt;
    }

    if (now_ms() > it->second.expires_at_ms) {
      return std::nullopt;
    }

    // Generate new token
    std::string new_token = generate_token(64);
    auto info = it->second;
    info.access_token = new_token;
    info.last_active_ms = now_ms();
    // Don't extend account expiry, only token rotation

    // Remove old mapping, add new
    guests_by_token_.erase(it);
    guests_by_token_[new_token] = info;
    guests_by_user_id_[info.user_id] = info;

    return new_token;
  }

  // ---- Status and Statistics ----

  /// Get guest count
  size_t guest_count() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return guests_by_user_id_.size();
  }

  /// Get total number of guests ever registered
  uint64_t total_guests_registered() {
    return guest_counter_.load();
  }

  /// Enable/disable guest registration
  void set_guest_registration_enabled(bool enabled) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    guest_registration_enabled_ = enabled;
  }

  bool is_guest_registration_enabled() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return guest_registration_enabled_;
  }

  /// Set the maximum age for guest accounts
  void set_max_account_age_ms(int64_t age_ms) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    max_account_age_ms_ = age_ms;
  }

  /// Set server name for guest ID construction
  void set_server_name(const std::string& server_name) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    server_name_ = server_name;
  }

  /// Get guest status as JSON for admin
  json get_guest_status_json() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json j;
    j["enabled"] = guest_registration_enabled_;
    j["active_guests"] = guests_by_user_id_.size();
    j["total_registered"] = guest_counter_.load();
    j["config"] = {
        {"max_rooms_joined", guest_capabilities_.max_rooms_joined},
        {"can_create_rooms", guest_capabilities_.can_create_rooms},
        {"can_invite", guest_capabilities_.can_invite},
        {"can_kick", guest_capabilities_.can_kick},
        {"can_ban", guest_capabilities_.can_ban},
        {"can_send_events", guest_capabilities_.can_send_events},
        {"can_join_rooms", guest_capabilities_.can_join_rooms},
        {"max_account_age_ms", max_account_age_ms_}
    };

    // List active guests
    json active;
    for (const auto& [uid, info] : guests_by_user_id_) {
      if (info.active && now_ms() <= info.expires_at_ms) {
        json g;
        g["user_id"] = info.user_id;
        g["display_name"] = info.display_name;
        g["rooms_joined"] = info.rooms_joined;
        g["created_at"] = format_timestamp_iso(info.created_at_ms);
        g["expires_at"] = format_timestamp_iso(info.expires_at_ms);
        g["last_active"] = format_timestamp_iso(info.last_active_ms);
        g["ip_address"] = info.ip_address;
        active.push_back(g);
      }
    }
    j["active_guest_list"] = active;

    return j;
  }

  /// List all expired guest users (for cleanup)
  std::vector<std::string> get_expired_guest_ids() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<std::string> expired;
    auto now = now_ms();
    for (const auto& [uid, info] : guests_by_user_id_) {
      if (!info.active || now > info.expires_at_ms) {
        expired.push_back(uid);
      }
    }
    return expired;
  }

private:
  void cleaner_loop() {
    while (cleaner_running_) {
      std::this_thread::sleep_for(
          chr::seconds(config::kGuestCleanupIntervalSec));

      std::lock_guard<std::shared_mutex> lock(mutex_);
      auto now = now_ms();

      // Clean up expired guests
      for (auto it = guests_by_user_id_.begin();
           it != guests_by_user_id_.end();) {
        if (now > it->second.expires_at_ms || !it->second.active) {
          // Remove from token map too
          guests_by_token_.erase(it->second.access_token);
          // Remove from suffix map
          std::string suffix = it->first;
          size_t guest_pos = suffix.find("guest_");
          if (guest_pos != std::string::npos) {
            suffix = suffix.substr(guest_pos + 6);
            size_t colon_pos = suffix.find(':');
            if (colon_pos != std::string::npos) {
              suffix = suffix.substr(0, colon_pos);
            }
            guest_by_suffix_.erase(suffix);
          }
          it = guests_by_user_id_.erase(it);
        } else {
          ++it;
        }
      }

      // Clean up stale tokens (tokens for non-existent guests)
      for (auto it = guests_by_token_.begin();
           it != guests_by_token_.end();) {
        auto uid_it = guests_by_user_id_.find(it->second.user_id);
        if (uid_it == guests_by_user_id_.end()) {
          it = guests_by_token_.erase(it);
        } else {
          ++it;
        }
      }

      // Clean up orphaned suffix entries
      for (auto it = guest_by_suffix_.begin();
           it != guest_by_suffix_.end();) {
        if (guests_by_user_id_.find(it->second) == guests_by_user_id_.end()) {
          it = guest_by_suffix_.erase(it);
        } else {
          ++it;
        }
      }
    }
  }

  mutable std::shared_mutex mutex_;
  std::string server_name_;
  std::atomic<uint64_t> guest_counter_{0};
  bool guest_registration_enabled_{true};
  int64_t max_account_age_ms_{config::kGuestAccountMaxAgeMs};

  // Guest mappings
  std::unordered_map<std::string, GuestInfo> guests_by_token_;
  std::unordered_map<std::string, GuestInfo> guests_by_user_id_;
  std::unordered_map<std::string, std::string> guest_by_suffix_;

  GuestCapabilities guest_capabilities_;

  // Cleaner
  std::atomic<bool> cleaner_running_{false};
  std::thread cleaner_thread_;
};

// ============================================================================
// RegistrationTokenManager
//
// Manages registration tokens for controlling who can register.
// Tokens can have: uses_allowed, pending count, completed count,
// expiry_time. Tokens are validated and consumed during registration.
// ============================================================================
class RegistrationTokenManager {
public:
  // Registration token record
  struct RegToken {
    std::string token;
    std::string owner;           // User or admin who created it
    int uses_allowed{1};         // How many times it can be used (-1 = unlimited)
    int pending{0};              // Registrations in progress
    int completed{0};            // Successfully used count
    int64_t created_at_ms{0};
    int64_t expires_at_ms{0};
    bool active{true};
    std::string comment;         // Optional description
    json metadata;               // Arbitrary metadata
  };

  explicit RegistrationTokenManager() {
    cleaner_running_ = true;
    cleaner_thread_ = std::thread([this]() { this->cleaner_loop(); });
  }

  ~RegistrationTokenManager() {
    cleaner_running_ = false;
    if (cleaner_thread_.joinable()) cleaner_thread_.join();
  }

  // ---- Token Creation ----

  /// Create a new registration token.
  /// Returns the created token on success.
  std::optional<RegToken> create_token(
      const std::string& owner,
      int uses_allowed = 1,
      int64_t ttl_ms = config::kRegTokenDefaultTTLMs,
      const std::string& comment = "",
      const json& metadata = {}) {

    if (uses_allowed < -1 || uses_allowed > config::kRegTokenMaxUsesAllowed) {
      return std::nullopt;
    }

    RegToken rt;
    rt.token = generate_registration_token_str();
    rt.owner = owner;
    rt.uses_allowed = uses_allowed;
    rt.pending = 0;
    rt.completed = 0;
    rt.created_at_ms = now_ms();
    rt.expires_at_ms = now_ms() + ttl_ms;
    rt.active = true;
    rt.comment = comment;
    rt.metadata = metadata;

    // Ensure token uniqueness
    {
      std::lock_guard<std::shared_mutex> lock(mutex_);
      int attempts = 0;
      while (tokens_.find(rt.token) != tokens_.end()) {
        rt.token = generate_registration_token_str();
        if (++attempts > 10) return std::nullopt;
      }
      tokens_[rt.token] = rt;
    }

    return rt;
  }

  // ---- Token Validation ----

  /// Validate a registration token.
  /// Returns the token info if valid, std::nullopt if invalid/expired.
  std::optional<RegToken> validate_token(const std::string& token_str) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = tokens_.find(token_str);
    if (it == tokens_.end()) return std::nullopt;

    const auto& rt = it->second;

    // Check active
    if (!rt.active) return std::nullopt;

    // Check expiry
    if (now_ms() > rt.expires_at_ms) return std::nullopt;

    // Check uses remaining
    if (rt.uses_allowed != -1 &&
        (rt.completed + rt.pending) >= rt.uses_allowed) {
      return std::nullopt;
    }

    return rt;
  }

  /// Mark a token as "in progress" (pending registration)
  bool mark_pending(const std::string& token_str) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = tokens_.find(token_str);
    if (it == tokens_.end()) return false;

    auto& rt = it->second;

    if (!rt.active) return false;
    if (now_ms() > rt.expires_at_ms) return false;

    // Check uses remaining
    if (rt.uses_allowed != -1 &&
        (rt.completed + rt.pending) >= rt.uses_allowed) {
      return false;
    }

    rt.pending++;
    return true;
  }

  /// Mark a token as "completed" (registration successful)
  bool mark_completed(const std::string& token_str) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = tokens_.find(token_str);
    if (it == tokens_.end()) return false;

    auto& rt = it->second;

    if (!rt.active) return false;
    if (rt.pending <= 0) {
      // No pending to complete, but still count it
      rt.completed++;
    } else {
      rt.pending--;
      rt.completed++;
    }

    // If token is fully used, deactivate
    if (rt.uses_allowed != -1 && rt.completed >= rt.uses_allowed) {
      rt.active = false;
    }

    return true;
  }

  /// Release a pending registration (e.g., if registration failed)
  bool release_pending(const std::string& token_str) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = tokens_.find(token_str);
    if (it == tokens_.end()) return false;

    auto& rt = it->second;
    if (rt.pending > 0) {
      rt.pending--;
      return true;
    }
    return false;
  }

  // ---- Token Management ----

  /// Get all tokens (filtered)
  std::vector<RegToken> list_tokens(
      const std::string& owner_filter = "",
      bool include_inactive = false) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<RegToken> result;
    for (const auto& [_, rt] : tokens_) {
      if (!include_inactive && !rt.active) continue;
      if (!owner_filter.empty() && rt.owner != owner_filter) continue;
      result.push_back(rt);
    }
    return result;
  }

  /// Get a specific token
  std::optional<RegToken> get_token(const std::string& token_str) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = tokens_.find(token_str);
    if (it != tokens_.end()) return it->second;
    return std::nullopt;
  }

  /// Update a token's properties
  bool update_token(
      const std::string& token_str,
      std::optional<int> uses_allowed = std::nullopt,
      std::optional<int64_t> new_expiry_ms = std::nullopt,
      std::optional<std::string> comment = std::nullopt,
      std::optional<json> metadata = std::nullopt,
      std::optional<bool> active = std::nullopt) {

    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = tokens_.find(token_str);
    if (it == tokens_.end()) return false;

    auto& rt = it->second;

    if (uses_allowed.has_value()) {
      int val = uses_allowed.value();
      if (val < -1 || val > config::kRegTokenMaxUsesAllowed) return false;
      rt.uses_allowed = val;
    }
    if (new_expiry_ms.has_value()) {
      rt.expires_at_ms = new_expiry_ms.value();
    }
    if (comment.has_value()) {
      rt.comment = comment.value();
    }
    if (metadata.has_value()) {
      rt.metadata = metadata.value();
    }
    if (active.has_value()) {
      rt.active = active.value();
    }

    return true;
  }

  /// Delete a registration token
  bool delete_token(const std::string& token_str) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    return tokens_.erase(token_str) > 0;
  }

  /// Deactivate a token (soft-delete)
  bool deactivate_token(const std::string& token_str) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = tokens_.find(token_str);
    if (it == tokens_.end()) return false;
    it->second.active = false;
    return true;
  }

  /// Reactivate a token
  bool reactivate_token(const std::string& token_str) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = tokens_.find(token_str);
    if (it == tokens_.end()) return false;
    it->second.active = true;
    return true;
  }

  // ---- Statistics ----

  /// Get token usage statistics
  json get_token_stats() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json stats;

    int total_active = 0;
    int total_completed = 0;
    int total_pending = 0;
    int total_unused = 0;
    int total_expired = 0;
    int unlimited_tokens = 0;

    auto now = now_ms();

    for (const auto& [_, rt] : tokens_) {
      if (!rt.active) continue;
      total_active++;

      if (now > rt.expires_at_ms) {
        total_expired++;
        continue;
      }

      total_completed += rt.completed;
      total_pending += rt.pending;

      if (rt.uses_allowed == -1) {
        unlimited_tokens++;
      }

      if (rt.completed == 0 && rt.pending == 0) {
        total_unused++;
      }
    }

    stats["total_tokens"] = tokens_.size();
    stats["active_tokens"] = total_active;
    stats["total_completed_registrations"] = total_completed;
    stats["total_pending_registrations"] = total_pending;
    stats["unused_tokens"] = total_unused;
    stats["expired_tokens"] = total_expired;
    stats["unlimited_use_tokens"] = unlimited_tokens;
    stats["timestamp"] = now_iso8601();

    return stats;
  }

  /// Get detailed stats for a specific token
  json get_token_detail_json(const std::string& token_str) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = tokens_.find(token_str);
    if (it == tokens_.end()) {
      return {{"error", "Token not found"}};
    }

    const auto& rt = it->second;
    json j;
    j["token"] = rt.token;
    j["owner"] = rt.owner;
    j["uses_allowed"] = rt.uses_allowed;
    j["pending"] = rt.pending;
    j["completed"] = rt.completed;
    j["active"] = rt.active;
    j["created_at"] = format_timestamp_iso(rt.created_at_ms);
    j["expires_at"] = format_timestamp_iso(rt.expires_at_ms);
    j["expired"] = (now_ms() > rt.expires_at_ms);
    j["comment"] = rt.comment;
    j["metadata"] = rt.metadata;

    if (rt.uses_allowed == -1) {
      j["remaining_uses"] = -1; // unlimited
    } else {
      int remaining = rt.uses_allowed - rt.completed - rt.pending;
      if (remaining < 0) remaining = 0;
      j["remaining_uses"] = remaining;
    }

    return j;
  }

  /// Clean up expired/inactive tokens
  size_t cleanup_expired() {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    size_t cleaned = 0;
    auto now = now_ms();

    for (auto it = tokens_.begin(); it != tokens_.end();) {
      if (!it->second.active || now > it->second.expires_at_ms) {
        it = tokens_.erase(it);
        cleaned++;
      } else {
        ++it;
      }
    }

    return cleaned;
  }

private:
  void cleaner_loop() {
    while (cleaner_running_) {
      std::this_thread::sleep_for(
          chr::seconds(config::kRegTokenCleanupIntervalSec));
      cleanup_expired();
    }
  }

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, RegToken> tokens_;

  std::atomic<bool> cleaner_running_{false};
  std::thread cleaner_thread_;
};

// ============================================================================
// AccountDataManager
//
// Manages user account data — both global (no room_id) and room-specific.
// Implements the Matrix account_data API: GET/PUT per type, and the account_data
// section in the /sync response.
//
// Supported global types: m.direct, m.push_rules, m.ignored_user_list,
// org.matrix.preview_urls, m.widgets, and any custom type.
// ============================================================================
class AccountDataManager {
public:
  // Account data entry
  struct AccountDataEntry {
    std::string user_id;
    std::string type;          // Event type, e.g. "m.direct"
    std::string room_id;       // Empty for global account data
    std::string content_json;  // The JSON content as a string
    int64_t updated_at_ms{0};
  };

  // Accretion: diff since a given stream token
  struct AccountDataAccretion {
    std::vector<AccountDataEntry> entries;
    int64_t stream_position{0};
    bool limited{false};
  };

  explicit AccountDataManager() {
    stream_position_.store(0);
  }

  // ---- Global Account Data ----

  /// Set global account data for a user + type.
  /// Returns the new stream position.
  int64_t set_global_account_data(
      const std::string& user_id,
      const std::string& type,
      const json& content) {

    // Validate content size
    std::string content_str = content.dump();
    if (content_str.size() > config::kAccountDataMaxValueSize) {
      throw std::runtime_error(
          "Account data value exceeds maximum size of " +
          std::to_string(config::kAccountDataMaxValueSize) + " bytes");
    }

    std::lock_guard<std::shared_mutex> lock(mutex_);

    AccountDataEntry entry;
    entry.user_id = user_id;
    entry.type = type;
    entry.room_id = "";  // Global
    entry.content_json = content_str;
    entry.updated_at_ms = now_ms();

    auto key = make_key(user_id, type, "");
    int64_t stream_pos = next_stream_position();

    // Store the entry
    global_account_data_[key] = entry;

    // Track per-user stream positions
    user_stream_positions_[user_id] = stream_pos;

    return stream_pos;
  }

  /// Get global account data for a user + type
  std::optional<json> get_global_account_data(
      const std::string& user_id,
      const std::string& type) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto key = make_key(user_id, type, "");
    auto it = global_account_data_.find(key);
    if (it != global_account_data_.end()) {
      try {
        return json::parse(it->second.content_json);
      } catch (...) {
        return std::nullopt;
      }
    }
    return std::nullopt;
  }

  /// Delete global account data by type
  bool delete_global_account_data(
      const std::string& user_id,
      const std::string& type) {

    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto key = make_key(user_id, type, "");
    return global_account_data_.erase(key) > 0;
  }

  /// Get all global account data for a user
  json get_all_global_account_data(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json result = json::object();

    for (const auto& [key, entry] : global_account_data_) {
      if (entry.user_id != user_id) continue;
      try {
        result[entry.type] = json::parse(entry.content_json);
      } catch (...) {
        result[entry.type] = json::object();
      }
    }
    return result;
  }

  // ---- Room-Specific Account Data ----

  /// Set room account data for a user + room + type
  int64_t set_room_account_data(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& type,
      const json& content) {

    std::string content_str = content.dump();
    if (content_str.size() > config::kAccountDataMaxValueSize) {
      throw std::runtime_error(
          "Room account data value exceeds maximum size of " +
          std::to_string(config::kAccountDataMaxValueSize) + " bytes");
    }

    std::lock_guard<std::shared_mutex> lock(mutex_);

    AccountDataEntry entry;
    entry.user_id = user_id;
    entry.type = type;
    entry.room_id = room_id;
    entry.content_json = content_str;
    entry.updated_at_ms = now_ms();

    auto key = make_key(user_id, type, room_id);
    int64_t stream_pos = next_stream_position();

    room_account_data_[key] = entry;
    user_stream_positions_[user_id] = stream_pos;

    return stream_pos;
  }

  /// Get room account data for a user + room + type
  std::optional<json> get_room_account_data(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& type) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto key = make_key(user_id, type, room_id);
    auto it = room_account_data_.find(key);
    if (it != room_account_data_.end()) {
      try {
        return json::parse(it->second.content_json);
      } catch (...) {
        return std::nullopt;
      }
    }
    return std::nullopt;
  }

  /// Delete room account data
  bool delete_room_account_data(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& type) {

    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto key = make_key(user_id, type, room_id);
    return room_account_data_.erase(key) > 0;
  }

  /// Get all room account data for a user + room
  json get_all_room_account_data(
      const std::string& user_id,
      const std::string& room_id) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    json result = json::object();

    for (const auto& [key, entry] : room_account_data_) {
      if (entry.user_id != user_id || entry.room_id != room_id) continue;
      try {
        result[entry.type] = json::parse(entry.content_json);
      } catch (...) {
        result[entry.type] = json::object();
      }
    }
    return result;
  }

  // ---- m.direct Special Handling ----

  /// Set m.direct (user ID -> room IDs mapping)
  int64_t set_direct_rooms(
      const std::string& user_id,
      const json& direct_map) {

    // Validate: m.direct is a map of user_id -> [room_id, ...]
    if (!direct_map.is_object()) {
      throw std::runtime_error("m.direct must be an object mapping user IDs to room ID arrays");
    }

    for (const auto& [target_user, room_ids] : direct_map.items()) {
      if (!room_ids.is_array()) {
        throw std::runtime_error("m.direct values must be arrays of room IDs");
      }
    }

    return set_global_account_data(user_id, "m.direct", direct_map);
  }

  /// Get m.direct for a user
  json get_direct_rooms(const std::string& user_id) {
    auto result = get_global_account_data(user_id, "m.direct");
    return result.value_or(json::object());
  }

  /// Add a direct room entry
  int64_t add_direct_room(
      const std::string& user_id,
      const std::string& target_user_id,
      const std::string& room_id) {

    std::lock_guard<std::shared_mutex> lock(mutex_);

    json direct_map;
    auto key = make_key(user_id, "m.direct", "");
    auto it = global_account_data_.find(key);
    if (it != global_account_data_.end()) {
      try {
        direct_map = json::parse(it->second.content_json);
      } catch (...) {
        direct_map = json::object();
      }
    }

    if (!direct_map.contains(target_user_id)) {
      direct_map[target_user_id] = json::array();
    }
    // Don't add duplicate
    auto& rooms = direct_map[target_user_id];
    bool exists = false;
    for (const auto& rid : rooms) {
      if (rid.get<std::string>() == room_id) { exists = true; break; }
    }
    if (!exists) {
      rooms.push_back(room_id);
    }

    return set_global_account_data(user_id, "m.direct", direct_map);
  }

  /// Remove a direct room entry
  int64_t remove_direct_room(
      const std::string& user_id,
      const std::string& target_user_id,
      const std::string& room_id) {

    std::lock_guard<std::shared_mutex> lock(mutex_);

    json direct_map;
    auto key = make_key(user_id, "m.direct", "");
    auto it = global_account_data_.find(key);
    if (it != global_account_data_.end()) {
      try {
        direct_map = json::parse(it->second.content_json);
      } catch (...) {
        direct_map = json::object();
      }
    }

    if (direct_map.contains(target_user_id)) {
      auto& rooms = direct_map[target_user_id];
      json new_rooms = json::array();
      for (const auto& rid : rooms) {
        if (rid.get<std::string>() != room_id) {
          new_rooms.push_back(rid);
        }
      }
      if (new_rooms.empty()) {
        direct_map.erase(target_user_id);
      } else {
        direct_map[target_user_id] = new_rooms;
      }
    }

    return set_global_account_data(user_id, "m.direct", direct_map);
  }

  // ---- m.push_rules Special Handling ----

  /// Set push rules
  int64_t set_push_rules(
      const std::string& user_id,
      const json& push_rules) {
    return set_global_account_data(user_id, "m.push_rules", push_rules);
  }

  /// Get push rules
  json get_push_rules(const std::string& user_id) {
    auto result = get_global_account_data(user_id, "m.push_rules");
    return result.value_or(json::object());
  }

  // ---- m.ignored_user_list Special Handling ----

  /// Set ignored user list
  int64_t set_ignored_users(
      const std::string& user_id,
      const json& ignored_users) {
    return set_global_account_data(user_id, "m.ignored_user_list", ignored_users);
  }

  /// Get ignored user list
  json get_ignored_users(const std::string& user_id) {
    auto result = get_global_account_data(user_id, "m.ignored_user_list");
    return result.value_or(json::object());
  }

  /// Check if a user is ignored
  bool is_user_ignored(
      const std::string& user_id,
      const std::string& target_user_id) {

    auto ignored = get_ignored_users(user_id);
    if (ignored.contains("ignored_users") &&
        ignored["ignored_users"].is_object()) {
      return ignored["ignored_users"].contains(target_user_id);
    }
    return false;
  }

  /// Add user to ignore list
  int64_t add_to_ignore_list(
      const std::string& user_id,
      const std::string& target_user_id) {

    auto ignored = get_ignored_users(user_id);
    if (!ignored.contains("ignored_users") || !ignored["ignored_users"].is_object()) {
      ignored["ignored_users"] = json::object();
    }
    ignored["ignored_users"][target_user_id] = json::object();
    return set_global_account_data(user_id, "m.ignored_user_list", ignored);
  }

  /// Remove user from ignore list
  int64_t remove_from_ignore_list(
      const std::string& user_id,
      const std::string& target_user_id) {

    auto ignored = get_ignored_users(user_id);
    if (ignored.contains("ignored_users") && ignored["ignored_users"].is_object()) {
      ignored["ignored_users"].erase(target_user_id);
      set_global_account_data(user_id, "m.ignored_user_list", ignored);
    }
    return next_stream_position();
  }

  // ---- org.matrix.preview_urls Special Handling ----

  /// Set URL preview enabled flag
  int64_t set_url_previews_enabled(
      const std::string& user_id,
      bool enabled) {
    json content;
    content["disable"] = !enabled;
    return set_global_account_data(user_id, "org.matrix.preview_urls", content);
  }

  /// Check if URL previews are enabled for a user
  bool are_url_previews_enabled(const std::string& user_id) {
    auto result = get_global_account_data(user_id, "org.matrix.preview_urls");
    if (result.has_value() && result->contains("disable")) {
      return !result->at("disable").get<bool>();
    }
    return true; // enabled by default
  }

  // ---- m.widgets Special Handling ----

  /// Set widgets for a user (global or room-specific)
  int64_t set_widgets(
      const std::string& user_id,
      const json& widgets,
      const std::string& room_id = "") {

    if (room_id.empty()) {
      return set_global_account_data(user_id, "m.widgets", widgets);
    } else {
      return set_room_account_data(user_id, room_id, "m.widgets", widgets);
    }
  }

  /// Get widgets for a user
  json get_widgets(
      const std::string& user_id,
      const std::string& room_id = "") {

    std::optional<json> result;
    if (room_id.empty()) {
      result = get_global_account_data(user_id, "m.widgets");
    } else {
      result = get_room_account_data(user_id, room_id, "m.widgets");
    }
    return result.value_or(json::object());
  }

  /// Add a widget
  int64_t add_widget(
      const std::string& user_id,
      const std::string& widget_id,
      const json& widget_data,
      const std::string& room_id = "") {

    auto widgets = get_widgets(user_id, room_id);
    if (!widgets.is_object()) widgets = json::object();
    widgets[widget_id] = widget_data;
    return set_widgets(user_id, widgets, room_id);
  }

  /// Remove a widget
  int64_t remove_widget(
      const std::string& user_id,
      const std::string& widget_id,
      const std::string& room_id = "") {

    auto widgets = get_widgets(user_id, room_id);
    if (widgets.contains(widget_id)) {
      widgets.erase(widget_id);
      return set_widgets(user_id, widgets, room_id);
    }
    return 0;
  }

  // ---- Sync Account Data Stream ----

  /// Get account data changes since a given stream position.
  /// Used for populating the account_data section of /sync responses.
  AccountDataAccretion get_account_data_stream(
      const std::string& user_id,
      int64_t since_position = 0) {

    std::shared_lock<std::shared_mutex> lock(mutex_);

    AccountDataAccretion acc;
    acc.stream_position = stream_position_.load();

    auto pos_it = user_stream_positions_.find(user_id);
    if (pos_it != user_stream_positions_.end()) {
      acc.stream_position = pos_it->second;
    }

    if (since_position == 0) {
      // Initial sync: return all account data
      for (const auto& [key, entry] : global_account_data_) {
        if (entry.user_id == user_id) {
          acc.entries.push_back(entry);
        }
      }
      for (const auto& [key, entry] : room_account_data_) {
        if (entry.user_id == user_id) {
          acc.entries.push_back(entry);
        }
      }
    } else {
      // Incremental sync: only entries updated after since_position
      // For simplicity, check update timestamp
      for (const auto& [key, entry] : global_account_data_) {
        if (entry.user_id == user_id && entry.updated_at_ms > since_position) {
          acc.entries.push_back(entry);
        }
      }
      for (const auto& [key, entry] : room_account_data_) {
        if (entry.user_id == user_id && entry.updated_at_ms > since_position) {
          acc.entries.push_back(entry);
        }
      }
    }

    return acc;
  }

  /// Build the account_data section for a /sync response
  json build_sync_account_data(
      const std::string& user_id,
      int64_t since_position = 0) {

    auto acc = get_account_data_stream(user_id, since_position);
    json result = json::object();

    json global_events = json::array();
    json room_events = json::object();

    for (const auto& entry : acc.entries) {
      json event;
      event["type"] = entry.type;
      try {
        event["content"] = json::parse(entry.content_json);
      } catch (...) {
        event["content"] = json::object();
      }

      if (entry.room_id.empty()) {
        global_events.push_back(event);
      } else {
        if (!room_events.contains(entry.room_id)) {
          room_events[entry.room_id] = json::array();
        }
        room_events[entry.room_id].push_back(event);
      }
    }

    result["events"] = global_events;
    result["rooms"] = room_events;
    result["stream_position"] = acc.stream_position;

    return result;
  }

  /// Get the current stream position
  int64_t get_stream_position() {
    return stream_position_.load();
  }

  // ---- Bulk Operations ----

  /// Clear all account data for a user (e.g., on account deactivation)
  size_t clear_user_account_data(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    size_t count = 0;

    for (auto it = global_account_data_.begin();
         it != global_account_data_.end();) {
      if (it->second.user_id == user_id) {
        it = global_account_data_.erase(it);
        count++;
      } else {
        ++it;
      }
    }

    for (auto it = room_account_data_.begin();
         it != room_account_data_.end();) {
      if (it->second.user_id == user_id) {
        it = room_account_data_.erase(it);
        count++;
      } else {
        ++it;
      }
    }

    user_stream_positions_.erase(user_id);
    return count;
  }

  /// Export all account data for a user (for data portability)
  json export_user_account_data(const std::string& user_id) {
    json export_data;

    export_data["global"] = get_all_global_account_data(user_id);

    // Collect all distinct room IDs this user has data for
    std::set<std::string> room_ids;
    {
      std::shared_lock<std::shared_mutex> lock(mutex_);
      for (const auto& [key, entry] : room_account_data_) {
        if (entry.user_id == user_id && !entry.room_id.empty()) {
          room_ids.insert(entry.room_id);
        }
      }
    }

    json room_data = json::object();
    for (const auto& room_id : room_ids) {
      room_data[room_id] = get_all_room_account_data(user_id, room_id);
    }
    export_data["rooms"] = room_data;

    return export_data;
  }

  /// Import account data for a user (for data portability)
  size_t import_user_account_data(
      const std::string& user_id,
      const json& import_data) {

    size_t count = 0;

    if (import_data.contains("global") && import_data["global"].is_object()) {
      for (const auto& [type, content] : import_data["global"].items()) {
        set_global_account_data(user_id, type, content);
        count++;
      }
    }

    if (import_data.contains("rooms") && import_data["rooms"].is_object()) {
      for (const auto& [room_id, room_data] : import_data["rooms"].items()) {
        if (room_data.is_object()) {
          for (const auto& [type, content] : room_data.items()) {
            set_room_account_data(user_id, room_id, type, content);
            count++;
          }
        }
      }
    }

    return count;
  }

private:
  std::string make_key(const std::string& user_id,
                        const std::string& type,
                        const std::string& room_id) {
    return user_id + "\x00" + type + "\x00" + room_id;
  }

  int64_t next_stream_position() {
    return stream_position_.fetch_add(1) + 1;
  }

  mutable std::shared_mutex mutex_;
  std::atomic<int64_t> stream_position_{0};

  std::unordered_map<std::string, AccountDataEntry> global_account_data_;
  std::unordered_map<std::string, AccountDataEntry> room_account_data_;
  std::unordered_map<std::string, int64_t> user_stream_positions_;
};

// ============================================================================
// OpenIDManager
//
// Implements the Matrix OpenID API for clients.
// Matrix clients can request an OpenID token from the homeserver, which they
// can then present to a third-party service (e.g., an integration manager)
// to verify their identity.
//
// Endpoints:
//   POST /_matrix/client/v3/user/{userId}/openid/request_token
//     -> returns {access_token, token_type, matrix_server_name, expires_in}
//
// The third party then validates by calling:
//   GET /_matrix/federation/v1/openid/userinfo?access_token=...
//     -> returns {sub: @user:domain}
// ============================================================================
class OpenIDManager {
public:
  // OpenID token record
  struct OpenIDToken {
    std::string access_token;
    std::string user_id;
    std::string matrix_server_name;
    int64_t created_at_ms{0};
    int64_t expires_at_ms{0};
    bool revoked{false};
    std::string client_info;  // Informational: requesting client
  };

  // OpenID sub (subject) info returned to third parties
  struct OpenIDSubInfo {
    std::string sub;  // The Matrix user ID (@user:domain)
  };

  explicit OpenIDManager(const std::string& server_name)
      : matrix_server_name_(server_name) {
    cleaner_running_ = true;
    cleaner_thread_ = std::thread([this]() { this->cleaner_loop(); });
  }

  ~OpenIDManager() {
    cleaner_running_ = false;
    if (cleaner_thread_.joinable()) cleaner_thread_.join();
  }

  // ---- Token Generation ----

  /// Generate an OpenID access token for a user.
  /// Returns the token info in the format expected by the client API.
  /// Returns empty optional if user is not valid.
  std::optional<json> generate_openid_token(
      const std::string& user_id,
      const std::string& client_info = "") {

    if (user_id.empty()) return std::nullopt;

    OpenIDToken token;
    token.access_token = generate_openid_token();
    token.user_id = user_id;
    token.matrix_server_name = matrix_server_name_;
    token.created_at_ms = now_ms();
    token.expires_at_ms = now_ms() + config::kOpenIDTokenTTLMs;
    token.revoked = false;
    token.client_info = client_info;

    {
      std::lock_guard<std::shared_mutex> lock(mutex_);

      // Ensure token uniqueness
      int attempts = 0;
      while (tokens_by_access_.find(token.access_token) != tokens_by_access_.end()) {
        token.access_token = generate_openid_token();
        if (++attempts > 10) return std::nullopt;
      }

      tokens_by_access_[token.access_token] = token;

      // Track tokens per user
      user_tokens_[user_id].push_back(token.access_token);

      // Limit per-user tokens
      auto& user_token_list = user_tokens_[user_id];
      if (user_token_list.size() > kMaxOpenIDTokensPerUser) {
        // Revoke oldest tokens
        while (user_token_list.size() > kMaxOpenIDTokensPerUser) {
          auto old_token = user_token_list.front();
          user_token_list.pop_front();
          auto it = tokens_by_access_.find(old_token);
          if (it != tokens_by_access_.end()) {
            it->second.revoked = true;
          }
        }
      }
    }

    // Build response
    json response;
    response["access_token"] = token.access_token;
    response["token_type"] = "Bearer";
    response["matrix_server_name"] = matrix_server_name_;
    response["expires_in"] =
        static_cast<int64_t>(config::kOpenIDTokenTTLMs / 1000);

    return response;
  }

  // ---- Token Exchange (User Info) ----

  /// Exchange an OpenID access token for user info.
  /// This is the server-side validation endpoint called by third parties.
  /// Returns the "sub" (user ID) if the token is valid.
  std::optional<OpenIDSubInfo> get_user_info(
      const std::string& access_token) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = tokens_by_access_.find(access_token);
    if (it == tokens_by_access_.end()) return std::nullopt;

    const auto& token = it->second;

    if (token.revoked) return std::nullopt;
    if (now_ms() > token.expires_at_ms) return std::nullopt;

    OpenIDSubInfo info;
    info.sub = token.user_id;
    return info;
  }

  // ---- Token Validation ----

  /// Validate an OpenID token.
  /// Returns the user_id if the token is valid.
  std::optional<std::string> validate_token(
      const std::string& access_token) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = tokens_by_access_.find(access_token);
    if (it == tokens_by_access_.end()) return std::nullopt;

    const auto& token = it->second;
    if (token.revoked) return std::nullopt;
    if (now_ms() > token.expires_at_ms) return std::nullopt;

    return token.user_id;
  }

  /// Check if a token is still valid (without returning user_id)
  bool is_token_valid(const std::string& access_token) {
    return validate_token(access_token).has_value();
  }

  /// Get the full token info (for debugging/admin)
  std::optional<json> get_token_info(
      const std::string& access_token) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = tokens_by_access_.find(access_token);
    if (it == tokens_by_access_.end()) return std::nullopt;

    const auto& token = it->second;
    json info;
    info["user_id"] = token.user_id;
    info["matrix_server_name"] = token.matrix_server_name;
    info["created_at"] = format_timestamp_iso(token.created_at_ms);
    info["expires_at"] = format_timestamp_iso(token.expires_at_ms);
    info["expires_in_ms"] = token.expires_at_ms - now_ms();
    info["revoked"] = token.revoked;
    info["client_info"] = token.client_info;

    return info;
  }

  // ---- Token Revocation ----

  /// Revoke an OpenID token
  bool revoke_token(const std::string& access_token) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = tokens_by_access_.find(access_token);
    if (it == tokens_by_access_.end()) return false;
    it->second.revoked = true;
    return true;
  }

  /// Revoke all OpenID tokens for a specific user
  size_t revoke_user_tokens(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    size_t count = 0;

    auto it = user_tokens_.find(user_id);
    if (it != user_tokens_.end()) {
      for (const auto& token_str : it->second) {
        auto token_it = tokens_by_access_.find(token_str);
        if (token_it != tokens_by_access_.end()) {
          token_it->second.revoked = true;
          count++;
        }
      }
      user_tokens_.erase(it);
    }

    return count;
  }

  // ---- Token Management ----

  /// Get count of active OpenID tokens for a user
  size_t get_user_token_count(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = user_tokens_.find(user_id);
    if (it == user_tokens_.end()) return 0;

    size_t count = 0;
    for (const auto& token_str : it->second) {
      auto token_it = tokens_by_access_.find(token_str);
      if (token_it != tokens_by_access_.end() &&
          !token_it->second.revoked &&
          now_ms() <= token_it->second.expires_at_ms) {
        count++;
      }
    }
    return count;
  }

  /// Get statistics
  json get_stats() {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    size_t total_tokens = tokens_by_access_.size();
    size_t active_tokens = 0;
    size_t revoked_count = 0;
    size_t expired_count = 0;

    auto now = now_ms();

    for (const auto& [_, token] : tokens_by_access_) {
      if (token.revoked) {
        revoked_count++;
      } else if (now > token.expires_at_ms) {
        expired_count++;
      } else {
        active_tokens++;
      }
    }

    json stats;
    stats["total_tokens_ever"] = total_tokens;
    stats["active_tokens"] = active_tokens;
    stats["revoked_tokens"] = revoked_count;
    stats["expired_tokens"] = expired_count;
    stats["unique_users"] = user_tokens_.size();
    stats["server_name"] = matrix_server_name_;
    stats["token_ttl_ms"] = config::kOpenIDTokenTTLMs;

    return stats;
  }

private:
  void cleaner_loop() {
    while (cleaner_running_) {
      std::this_thread::sleep_for(
          chr::seconds(config::kOpenIDCleanupIntervalSec));

      std::lock_guard<std::shared_mutex> lock(mutex_);
      auto now = now_ms();

      // Clean up expired and revoked tokens
      for (auto it = tokens_by_access_.begin();
           it != tokens_by_access_.end();) {
        if (it->second.revoked || now > it->second.expires_at_ms) {
          // Remove from user list
          auto user_it = user_tokens_.find(it->second.user_id);
          if (user_it != user_tokens_.end()) {
            auto& list = user_it->second;
            list.erase(
                std::remove(list.begin(), list.end(), it->first),
                list.end());
            if (list.empty()) {
              user_tokens_.erase(user_it);
            }
          }
          it = tokens_by_access_.erase(it);
        } else {
          ++it;
        }
      }
    }
  }

  static constexpr size_t kMaxOpenIDTokensPerUser = 25;

  mutable std::shared_mutex mutex_;
  std::string matrix_server_name_;

  // Primary token storage: access_token -> OpenIDToken
  std::unordered_map<std::string, OpenIDToken> tokens_by_access_;

  // User -> list of their tokens
  std::unordered_map<std::string, std::deque<std::string>> user_tokens_;

  std::atomic<bool> cleaner_running_{false};
  std::thread cleaner_thread_;
};

// ============================================================================
// LoginTokenManager
//
// Manages short-lived login tokens that allow passwordless login.
// A user can request a login token (e.g., via email), then exchange it
// for a full access token via POST /login with "type": "m.login.token".
//
// Equivalent to synapse/handlers/auth.py login token handling.
// ============================================================================
class LoginTokenManager {
public:
  // Login token record
  struct LoginToken {
    std::string token;
    std::string user_id;
    std::string device_id;
    int64_t created_at_ms{0};
    int64_t expires_at_ms{0};
    bool used{false};
    bool revoked{false};
    std::string auth_provider;     // How the token was requested (e.g., "email")
    std::string auth_provider_session;
    std::string redirect_url;      // Where to redirect after successful login
  };

  explicit LoginTokenManager() {
    cleaner_running_ = true;
    cleaner_thread_ = std::thread([this]() { this->cleaner_loop(); });
  }

  ~LoginTokenManager() {
    cleaner_running_ = false;
    if (cleaner_thread_.joinable()) cleaner_thread_.join();
  }

  // ---- Token Creation ----

  /// Create a login token for a user.
  /// Returns the token string on success.
  std::optional<std::string> create_login_token(
      const std::string& user_id,
      const std::string& auth_provider = "",
      const std::string& device_id = "",
      const std::string& redirect_url = "",
      int64_t custom_ttl_ms = 0) {

    if (user_id.empty()) return std::nullopt;

    // Check per-user token limit
    {
      std::shared_lock<std::shared_mutex> lock(mutex_);
      auto it = user_active_tokens_.find(user_id);
      if (it != user_active_tokens_.end() &&
          it->second >= config::kLoginTokenMaxPerUser) {
        return std::nullopt;
      }
    }

    LoginToken lt;
    lt.token = generate_login_token_str();
    lt.user_id = user_id;
    lt.device_id = device_id;
    lt.created_at_ms = now_ms();
    lt.expires_at_ms = now_ms() + (
        custom_ttl_ms > 0 ? custom_ttl_ms : config::kLoginTokenTTLMs);
    lt.auth_provider = auth_provider;
    lt.redirect_url = redirect_url;

    {
      std::lock_guard<std::shared_mutex> lock(mutex_);

      // Ensure uniqueness
      int attempts = 0;
      while (tokens_.find(lt.token) != tokens_.end()) {
        lt.token = generate_login_token_str();
        if (++attempts > 10) return std::nullopt;
      }

      tokens_[lt.token] = lt;
      user_active_tokens_[user_id]++;
    }

    return lt.token;
  }

  // ---- Token Validation ----

  /// Validate a login token.
  /// Returns the token info if valid and not yet used/expired.
  std::optional<LoginToken> validate_login_token(
      const std::string& token_str) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = tokens_.find(token_str);
    if (it == tokens_.end()) return std::nullopt;

    const auto& lt = it->second;

    if (lt.used) return std::nullopt;
    if (lt.revoked) return std::nullopt;
    if (now_ms() > lt.expires_at_ms) return std::nullopt;

    return lt;
  }

  // ---- Token Exchange (POST /login) ----

  /// Exchange a login token for a full access token.
  /// This is called by POST /login with auth type "m.login.token".
  /// Returns the user_id + device_id; the caller generates the access token.
  std::optional<std::pair<std::string, std::string>> exchange_login_token(
      const std::string& token_str) {

    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = tokens_.find(token_str);
    if (it == tokens_.end()) return std::nullopt;

    auto& lt = it->second;

    if (lt.used) return std::nullopt;
    if (lt.revoked) return std::nullopt;
    if (now_ms() > lt.expires_at_ms) return std::nullopt;

    // Mark as used
    lt.used = true;

    // Decrement user active token count
    auto cnt_it = user_active_tokens_.find(lt.user_id);
    if (cnt_it != user_active_tokens_.end() && cnt_it->second > 0) {
      cnt_it->second--;
    }

    return std::make_pair(lt.user_id, lt.device_id);
  }

  /// Build the login response for token-based auth
  json build_login_response(
      const std::string& token_str,
      const std::string& access_token,
      const std::string& home_server = "",
      int64_t access_token_ttl_ms = 0) {

    auto exchange_result = exchange_login_token(token_str);
    if (!exchange_result.has_value()) {
      return error_response("M_UNKNOWN_TOKEN", "Invalid or expired login token");
    }

    auto& [user_id, device_id] = exchange_result.value();

    json response;
    response["user_id"] = user_id;
    response["access_token"] = access_token;
    if (!device_id.empty()) {
      response["device_id"] = device_id;
    }
    if (!home_server.empty()) {
      response["home_server"] = home_server;
    }

    if (access_token_ttl_ms > 0) {
      response["expires_in_ms"] = access_token_ttl_ms;
    }

    // Get the stored redirect_url if any
    {
      std::shared_lock<std::shared_mutex> lock(mutex_);
      auto it = tokens_.find(token_str);
      if (it != tokens_.end() && !it->second.redirect_url.empty()) {
        response["well_known"] = {
            {"m.homeserver", {{"base_url", it->second.redirect_url}}}
        };
      }
    }

    return response;
  }

  // ---- Token Management ----

  /// Revoke a login token before use
  bool revoke_token(const std::string& token_str) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = tokens_.find(token_str);
    if (it == tokens_.end()) return false;

    if (!it->second.used) {
      auto cnt_it = user_active_tokens_.find(it->second.user_id);
      if (cnt_it != user_active_tokens_.end() && cnt_it->second > 0) {
        cnt_it->second--;
      }
    }

    it->second.revoked = true;
    return true;
  }

  /// Revoke all login tokens for a user
  size_t revoke_user_tokens(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    size_t count = 0;

    for (auto& [_, lt] : tokens_) {
      if (lt.user_id == user_id && !lt.revoked && !lt.used) {
        lt.revoked = true;
        count++;
      }
    }

    user_active_tokens_.erase(user_id);
    return count;
  }

  /// Get all active login tokens for a user
  std::vector<LoginToken> get_user_tokens(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<LoginToken> result;

    for (const auto& [_, lt] : tokens_) {
      if (lt.user_id == user_id && !lt.used && !lt.revoked &&
          now_ms() <= lt.expires_at_ms) {
        result.push_back(lt);
      }
    }

    return result;
  }

  /// Check if a user has any active login tokens
  bool has_active_tokens(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = user_active_tokens_.find(user_id);
    return it != user_active_tokens_.end() && it->second > 0;
  }

  /// Get count of active tokens for a user
  size_t get_active_token_count(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = user_active_tokens_.find(user_id);
    return it != user_active_tokens_.end() ? it->second : 0;
  }

  /// Get token statistics
  json get_stats() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json stats;

    size_t total = tokens_.size();
    size_t active = 0;
    size_t used = 0;
    size_t revoked = 0;
    size_t expired = 0;

    auto now = now_ms();

    for (const auto& [_, lt] : tokens_) {
      if (lt.used) {
        used++;
      } else if (lt.revoked) {
        revoked++;
      } else if (now > lt.expires_at_ms) {
        expired++;
      } else {
        active++;
      }
    }

    stats["total_tokens_ever"] = total;
    stats["active_tokens"] = active;
    stats["used_tokens"] = used;
    stats["revoked_tokens"] = revoked;
    stats["expired_tokens"] = expired;
    stats["unique_users_with_active"] = user_active_tokens_.size();
    stats["token_ttl_ms"] = config::kLoginTokenTTLMs;

    return stats;
  }

  /// Get admin-view of all tokens
  json get_admin_token_list(int limit = 50, int offset = 0) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json result = json::array();

    int skipped = 0;
    int included = 0;

    for (const auto& [_, lt] : tokens_) {
      if (skipped < offset) { skipped++; continue; }
      if (included >= limit) break;

      json t;
      t["token_prefix"] = lt.token.substr(0, 8) + "...";
      t["user_id"] = lt.user_id;
      t["device_id"] = lt.device_id;
      t["created_at"] = format_timestamp_iso(lt.created_at_ms);
      t["expires_at"] = format_timestamp_iso(lt.expires_at_ms);
      t["used"] = lt.used;
      t["revoked"] = lt.revoked;
      t["expired"] = (now_ms() > lt.expires_at_ms);
      t["auth_provider"] = lt.auth_provider;

      result.push_back(t);
      included++;
    }

    return result;
  }

private:
  void cleaner_loop() {
    while (cleaner_running_) {
      std::this_thread::sleep_for(
          chr::seconds(config::kLoginTokenCleanupIntervalSec));

      std::lock_guard<std::shared_mutex> lock(mutex_);
      auto now = now_ms();

      for (auto it = tokens_.begin(); it != tokens_.end();) {
        if (it->second.used || it->second.revoked || now > it->second.expires_at_ms) {
          // Update user count if this was an active token
          if (!it->second.used && !it->second.revoked && now > it->second.expires_at_ms) {
            auto cnt_it = user_active_tokens_.find(it->second.user_id);
            if (cnt_it != user_active_tokens_.end() && cnt_it->second > 0) {
              cnt_it->second--;
              if (cnt_it->second == 0) {
                user_active_tokens_.erase(cnt_it);
              }
            }
          }
          it = tokens_.erase(it);
        } else {
          ++it;
        }
      }
    }
  }

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, LoginToken> tokens_;
  std::unordered_map<std::string, size_t> user_active_tokens_;

  std::atomic<bool> cleaner_running_{false};
  std::thread cleaner_thread_;
};

// ============================================================================
// UserInteractiveAuthSessionManager
//
// Manages User-Interactive Authentication (UI Auth) sessions.
// UI Auth is used whenever an action requires the user to re-authenticate
// or complete specific stages (e.g., password, email verification, m.login.recaptcha,
// m.login.terms, m.login.dummy, m.login.sso, etc.).
//
// Sessions track which stages are required, which have been completed, and
// expire after a configurable timeout.
//
// Equivalent to synapse/handlers/ui_auth/ and synapse/api/auth.py (UI auth parts).
// ============================================================================
class UserInteractiveAuthSessionManager {
public:
  // UI Auth stage definition
  struct UIAStage {
    std::string type;       // e.g., "m.login.password", "m.login.recaptcha"
    int order{0};           // Order in the flow
    bool required{true};
    json params;            // Stage-specific parameters
  };

  // UI Auth flow: a set of stages
  struct UIAFlow {
    std::vector<UIAStage> stages;
    std::string description;
  };

  // UI Auth parameters returned to the client
  struct UIAParams {
    std::vector<UIAFlow> flows;
    json params;            // Session-level params
    std::string session_id;
  };

  // UI Auth session
  struct UIASession {
    std::string session_id;
    std::string user_id;
    std::string action;         // What action required auth (e.g., "DELETE_DEVICE")
    int64_t created_at_ms{0};
    int64_t expires_at_ms{0};
    bool completed{false};
    bool cancelled{false};

    // The chosen flow
    int chosen_flow_index{-1};
    std::vector<UIAStage> chosen_stages;

    // Completed stages (by type)
    std::set<std::string> completed_stages;

    // Stage-specific state
    std::unordered_map<std::string, json> stage_state;

    // Session data (opaque to auth, passed through to the handler)
    json session_data;

    // Access token for the session initiator
    std::string initiating_token;

    // Client information
    std::string ip_address;
    std::string user_agent;
  };

  // Result of processing a stage
  struct UIAStageResult {
    bool success{false};
    bool session_complete{false};
    json completion_params;      // Additional params to return to client
    std::string error_code;
    std::string error_message;
  };

  explicit UserInteractiveAuthSessionManager() {
    cleaner_running_ = true;
    cleaner_thread_ = std::thread([this]() { this->cleaner_loop(); });
  }

  ~UserInteractiveAuthSessionManager() {
    cleaner_running_ = false;
    if (cleaner_thread_.joinable()) cleaner_thread_.join();
  }

  // ---- Session Creation ----

  /// Create a new UI Auth session.
  /// Returns the session and the UI auth params to send to the client.
  std::optional<UIAParams> create_session(
      const std::string& user_id,
      const std::string& action,
      const std::vector<UIAFlow>& flows,
      const json& session_data = {},
      const std::string& ip_address = "127.0.0.1",
      const std::string& user_agent = "") {

    if (user_id.empty()) return std::nullopt;
    if (flows.empty()) return std::nullopt;

    UIASession session;
    session.session_id = generate_ui_session_id();
    session.user_id = user_id;
    session.action = action;
    session.created_at_ms = now_ms();
    session.expires_at_ms = now_ms() + config::kUIASessionTTLMs;
    session.completed = false;
    session.cancelled = false;
    session.chosen_flow_index = -1;
    session.session_data = session_data;
    session.ip_address = ip_address;
    session.user_agent = user_agent;

    {
      std::lock_guard<std::shared_mutex> lock(mutex_);

      // Ensure session ID uniqueness
      int attempts = 0;
      while (sessions_.find(session.session_id) != sessions_.end()) {
        session.session_id = generate_ui_session_id();
        if (++attempts > 10) return std::nullopt;
      }

      sessions_[session.session_id] = session;
    }

    // Build the UI auth params response
    UIAParams params;
    params.flows = flows;
    params.session_id = session.session_id;

    // Add session-level params
    params.params["session"] = session.session_id;

    return params;
  }

  /// Create a session with auto-generated flows based on required stages
  std::optional<UIAParams> create_session_simple(
      const std::string& user_id,
      const std::string& action,
      const std::vector<std::string>& required_stage_types,
      const json& session_data = {},
      const std::string& ip_address = "127.0.0.1") {

    std::vector<UIAFlow> flows;

    // Create a flow with all stages
    UIAFlow flow;
    int order = 0;
    for (const auto& stage_type : required_stage_types) {
      UIAStage stage;
      stage.type = stage_type;
      stage.order = order++;
      stage.required = true;
      flow.stages.push_back(stage);
    }
    flows.push_back(flow);

    return create_session(user_id, action, flows, session_data, ip_address);
  }

  // ---- Session Lookup ----

  /// Get a session by ID
  std::optional<UIASession> get_session(const std::string& session_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
      auto session = it->second;

      // Check expiry
      if (now_ms() > session.expires_at_ms || session.cancelled) {
        return std::nullopt;
      }

      return session;
    }
    return std::nullopt;
  }

  /// Check if a session exists and is active
  bool session_exists(const std::string& session_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return false;
    if (now_ms() > it->second.expires_at_ms || it->second.cancelled) return false;
    return true;
  }

  // ---- Stage Validation ----

  /// Validate a stage submission.
  /// Checks if the stage type is valid for this session, hasn't been completed
  /// already, and the provided auth data is correct.
  /// The caller provides a validation function for the specific stage type.
  UIAStageResult validate_stage(
      const std::string& session_id,
      const std::string& stage_type,
      const json& auth_data,
      std::function<bool(const UIASession&, const std::string&, const json&)> validator) {

    UIAStageResult result;

    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
      result.error_code = "M_UNKNOWN_SESSION";
      result.error_message = "Unknown UI auth session";
      return result;
    }

    auto& session = it->second;

    // Check expiry
    if (now_ms() > session.expires_at_ms) {
      result.error_code = "M_SESSION_EXPIRED";
      result.error_message = "UI auth session has expired";
      sessions_.erase(it);
      return result;
    }

    // Check cancelled
    if (session.cancelled) {
      result.error_code = "M_SESSION_CANCELLED";
      result.error_message = "UI auth session was cancelled";
      return result;
    }

    // Check already completed
    if (session.completed) {
      result.error_code = "M_SESSION_COMPLETED";
      result.error_message = "UI auth session already completed";
      return result;
    }

    // Check if the flow has been chosen
    if (session.chosen_flow_index < 0) {
      // Find a flow that contains this stage
      int flow_idx = -1;
      for (size_t i = 0; i < session.chosen_stages.empty() ? 0 : 0; ++i) {
        // This is handled by the caller providing the flows
      }

      // Default: stage type validation passes if it's not yet completed
      if (session.completed_stages.find(stage_type) !=
          session.completed_stages.end()) {
        result.error_code = "M_STAGE_ALREADY_COMPLETED";
        result.error_message = "Stage '" + stage_type + "' already completed";
        return result;
      }
    }

    // Check if already completed
    if (session.completed_stages.find(stage_type) !=
        session.completed_stages.end()) {
      result.error_code = "M_STAGE_ALREADY_COMPLETED";
      result.error_message = "Stage '" + stage_type + "' already completed";
      return result;
    }

    // Validate using the caller's validator
    bool validated = validator(session, stage_type, auth_data);
    if (!validated) {
      result.error_code = "M_UNAUTHORIZED";
      result.error_message = "Authentication failed for stage '" + stage_type + "'";
      return result;
    }

    // Mark stage as completed
    session.completed_stages.insert(stage_type);

    // Store stage state if provided in auth_data
    if (auth_data.contains("session")) {
      session.stage_state[stage_type] = auth_data;
    }

    result.success = true;

    // Check if all required stages are complete
    // If chosen_flow_index is set, check all stages in that flow
    if (session.chosen_flow_index >= 0 &&
        static_cast<size_t>(session.chosen_flow_index) <
            session.chosen_stages.size()) {
      bool all_complete = true;
      for (const auto& stage : session.chosen_stages) {
        if (stage.required &&
            session.completed_stages.find(stage.type) ==
                session.completed_stages.end()) {
          all_complete = false;
          break;
        }
      }
      if (all_complete) {
        session.completed = true;
        result.session_complete = true;
      }
    }

    // Build completion params
    result.completion_params["completed"] = session.completed_stages;

    return result;
  }

  // ---- Stage Completion ----

  /// Mark a stage as complete without validation (e.g., for m.login.dummy)
  bool mark_stage_complete(
      const std::string& session_id,
      const std::string& stage_type,
      const json& stage_data = {}) {

    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return false;

    auto& session = it->second;

    if (session.completed || session.cancelled) return false;
    if (now_ms() > session.expires_at_ms) return false;

    session.completed_stages.insert(stage_type);
    if (!stage_data.empty()) {
      session.stage_state[stage_type] = stage_data;
    }

    return true;
  }

  /// Check if all stages in a flow are complete
  bool check_session_complete(const std::string& session_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return false;

    auto& session = it->second;

    if (session.chosen_flow_index < 0) return false;

    for (const auto& stage : session.chosen_stages) {
      if (stage.required &&
          session.completed_stages.find(stage.type) ==
              session.completed_stages.end()) {
        return false;
      }
    }

    session.completed = true;
    return true;
  }

  /// Mark session as fully complete
  bool mark_session_complete(const std::string& session_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return false;

    it->second.completed = true;
    return true;
  }

  // ---- Stage Status ----

  /// Get completed stages for a session
  std::optional<std::set<std::string>> get_completed_stages(
      const std::string& session_id) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return std::nullopt;

    const auto& session = it->second;
    if (now_ms() > session.expires_at_ms || session.cancelled) {
      return std::nullopt;
    }

    return session.completed_stages;
  }

  /// Get remaining stages (stages not yet completed)
  std::optional<std::vector<std::string>> get_remaining_stages(
      const std::string& session_id) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return std::nullopt;

    const auto& session = it->second;
    if (session.chosen_flow_index < 0) return std::nullopt;
    if (now_ms() > session.expires_at_ms || session.cancelled) {
      return std::nullopt;
    }

    std::vector<std::string> remaining;
    for (const auto& stage : session.chosen_stages) {
      if (stage.required &&
          session.completed_stages.find(stage.type) ==
              session.completed_stages.end()) {
        remaining.push_back(stage.type);
      }
    }

    return remaining;
  }

  // ---- Session Lifecycle ----

  /// Cancel a session
  bool cancel_session(const std::string& session_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return false;
    it->second.cancelled = true;
    return true;
  }

  /// Extend session expiry
  bool extend_session(const std::string& session_id, int64_t additional_ms = 0) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return false;

    if (additional_ms <= 0) {
      additional_ms = config::kUIASessionTTLMs;
    }

    it->second.expires_at_ms = now_ms() + additional_ms;
    return true;
  }

  /// Remove a session (clean up)
  bool remove_session(const std::string& session_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    return sessions_.erase(session_id) > 0;
  }

  /// Get session data (opaque data passed through)
  std::optional<json> get_session_data(const std::string& session_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return std::nullopt;

    if (now_ms() > it->second.expires_at_ms || it->second.cancelled) {
      return std::nullopt;
    }

    return it->second.session_data;
  }

  /// Update session data
  bool update_session_data(
      const std::string& session_id,
      const json& data) {

    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return false;
    it->second.session_data = data;
    return true;
  }

  // ---- Chosen Flow ----

  /// Set the chosen flow for a session (called when client picks a flow)
  bool set_chosen_flow(
      const std::string& session_id,
      int flow_index,
      const std::vector<UIAStage>& stages) {

    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return false;

    auto& session = it->second;
    if (session.session_id.empty()) return false;

    session.chosen_flow_index = flow_index;
    session.chosen_stages = stages;

    return true;
  }

  // ---- Stage State ----

  /// Get state for a specific stage
  std::optional<json> get_stage_state(
      const std::string& session_id,
      const std::string& stage_type) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return std::nullopt;

    const auto& session = it->second;
    auto state_it = session.stage_state.find(stage_type);
    if (state_it != session.stage_state.end()) {
      return state_it->second;
    }
    return std::nullopt;
  }

  /// Set state for a specific stage
  bool set_stage_state(
      const std::string& session_id,
      const std::string& stage_type,
      const json& state) {

    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return false;

    it->second.stage_state[stage_type] = state;
    return true;
  }

  // ---- Statistics and Management ----

  /// Get session count
  size_t session_count() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return sessions_.size();
  }

  /// Get active session count (not expired, not cancelled, not completed)
  size_t active_session_count() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    size_t count = 0;
    auto now = now_ms();
    for (const auto& [_, session] : sessions_) {
      if (!session.completed && !session.cancelled &&
          now <= session.expires_at_ms) {
        count++;
      }
    }
    return count;
  }

  /// Get statistics as JSON
  json get_stats() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json stats;

    size_t total = sessions_.size();
    size_t active = 0;
    size_t completed = 0;
    size_t cancelled = 0;
    size_t expired = 0;

    auto now = now_ms();

    for (const auto& [_, session] : sessions_) {
      if (session.cancelled) {
        cancelled++;
      } else if (session.completed) {
        completed++;
      } else if (now > session.expires_at_ms) {
        expired++;
      } else {
        active++;
      }
    }

    stats["total_sessions"] = total;
    stats["active_sessions"] = active;
    stats["completed_sessions"] = completed;
    stats["cancelled_sessions"] = cancelled;
    stats["expired_sessions"] = expired;
    stats["session_ttl_ms"] = config::kUIASessionTTLMs;

    // Aggregate by action type
    std::map<std::string, size_t> by_action;
    for (const auto& [_, session] : sessions_) {
      by_action[session.action]++;
    }
    json actions_json = json::object();
    for (const auto& [action, count] : by_action) {
      actions_json[action] = count;
    }
    stats["sessions_by_action"] = actions_json;

    return stats;
  }

  /// Get admin-view list of sessions
  json get_admin_session_list(int limit = 50) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json result = json::array();
    auto now = now_ms();
    int count = 0;

    for (const auto& [_, session] : sessions_) {
      if (count >= limit) break;

      json s;
      s["session_id"] = session.session_id;
      s["user_id"] = session.user_id;
      s["action"] = session.action;
      s["created_at"] = format_timestamp_iso(session.created_at_ms);
      s["expires_at"] = format_timestamp_iso(session.expires_at_ms);
      s["completed"] = session.completed;
      s["cancelled"] = session.cancelled;
      s["expired"] = (now > session.expires_at_ms);

      json stages = json::array();
      for (const auto& stage : session.completed_stages) {
        stages.push_back(stage);
      }
      s["completed_stages"] = stages;

      if (session.chosen_flow_index >= 0) {
        s["chosen_flow_index"] = session.chosen_flow_index;
      }

      s["ip_address"] = session.ip_address;
      s["user_agent"] = session.user_agent;

      result.push_back(s);
      count++;
    }

    return result;
  }

  /// Cancel all sessions for a user
  size_t cancel_user_sessions(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    size_t count = 0;

    for (auto& [_, session] : sessions_) {
      if (session.user_id == user_id && !session.cancelled && !session.completed) {
        session.cancelled = true;
        count++;
      }
    }

    return count;
  }

  /// Clear all sessions for a user
  size_t clear_user_sessions(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    size_t count = 0;

    for (auto it = sessions_.begin(); it != sessions_.end();) {
      if (it->second.user_id == user_id) {
        it = sessions_.erase(it);
        count++;
      } else {
        ++it;
      }
    }

    return count;
  }

private:
  void cleaner_loop() {
    while (cleaner_running_) {
      std::this_thread::sleep_for(
          chr::seconds(config::kUIASessionCleanupIntervalSec));

      std::lock_guard<std::shared_mutex> lock(mutex_);
      auto now = now_ms();

      for (auto it = sessions_.begin(); it != sessions_.end();) {
        const auto& session = it->second;
        bool should_remove = session.cancelled ||
                             (session.completed && now > session.expires_at_ms) ||
                             (!session.completed && now > session.expires_at_ms);

        if (should_remove) {
          it = sessions_.erase(it);
        } else {
          ++it;
        }
      }
    }
  }

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, UIASession> sessions_;

  std::atomic<bool> cleaner_running_{false};
  std::thread cleaner_thread_;
};

// ============================================================================
// GuestRegistrationAPI — Unified facade for guest access, registration tokens,
// account data, OpenID, login tokens, and UI auth sessions.
//
// Composes all managers into a single entry point, providing a clean API
// for the Matrix server to manage these subsystems.
// ============================================================================
class GuestRegistrationAPI {
public:
  explicit GuestRegistrationAPI(
      const std::string& server_name,
      storage::RegistrationStore* reg_store = nullptr)
      : server_name_(server_name),
        reg_store_(reg_store),
        guest_access_(std::make_unique<GuestAccess>(server_name)),
        reg_tokens_(std::make_unique<RegistrationTokenManager>()),
        account_data_(std::make_unique<AccountDataManager>()),
        openid_(std::make_unique<OpenIDManager>(server_name)),
        login_tokens_(std::make_unique<LoginTokenManager>()),
        ui_auth_sessions_(std::make_unique<UserInteractiveAuthSessionManager>()) {
  }

  // ---- Component Accessors ----

  GuestAccess& guest_access() { return *guest_access_; }
  RegistrationTokenManager& reg_tokens() { return *reg_tokens_; }
  AccountDataManager& account_data() { return *account_data_; }
  OpenIDManager& openid() { return *openid_; }
  LoginTokenManager& login_tokens() { return *login_tokens_; }
  UserInteractiveAuthSessionManager& ui_auth_sessions() {
    return *ui_auth_sessions_;
  }

  // ---- Server Name ----

  void set_server_name(const std::string& name) {
    server_name_ = name;
    guest_access_->set_server_name(name);
  }

  std::string get_server_name() const { return server_name_; }

  // ---- Registration Store Access ----

  storage::RegistrationStore* registration_store() { return reg_store_; }
  void set_registration_store(storage::RegistrationStore* store) {
    reg_store_ = store;
  }

  // ---- High-Level Workflows ----

  /// Complete guest registration flow.
  /// 1. Registers guest
  /// 2. Sets up initial account data
  /// 3. Returns access token and user info
  json complete_guest_registration(
      const std::string& ip_address = "127.0.0.1",
      bool read_only = false) {

    json response;

    auto guest = guest_access_->register_guest(ip_address, "", read_only);
    if (!guest.has_value()) {
      response["errcode"] = "M_GUEST_ACCESS_FORBIDDEN";
      response["error"] = "Guest registration is disabled";
      return response;
    }

    response["user_id"] = guest->user_id;
    response["access_token"] = guest->access_token;
    response["device_id"] = guest->device_id;
    response["home_server"] = server_name_;
    response["is_guest"] = true;

    return response;
  }

  /// Complete user registration with optional registration token.
  /// 1. Validate registration token if provided
  /// 2. Mark token as completed
  /// 3. Return success
  json complete_user_registration_with_token(
      const std::string& user_id,
      const std::string& access_token,
      const std::string& device_id = "",
      const std::string& reg_token_str = "") {

    json response;

    // Validate registration token if provided
    if (!reg_token_str.empty()) {
      auto token_info = reg_tokens_->validate_token(reg_token_str);
      if (!token_info.has_value()) {
        response["errcode"] = "M_INVALID_REGISTRATION_TOKEN";
        response["error"] = "Invalid or expired registration token";
        return response;
      }

      // Mark as completed
      reg_tokens_->mark_completed(reg_token_str);
    }

    response["user_id"] = user_id;
    response["access_token"] = access_token;
    response["home_server"] = server_name_;
    if (!device_id.empty()) {
      response["device_id"] = device_id;
    }

    return response;
  }

  /// Handle login via token (m.login.token)
  json handle_login_token(
      const std::string& login_token_str,
      const std::string& access_token = "") {

    // If no access token is provided, we generate one
    std::string effective_token = access_token.empty()
        ? generate_token(64)
        : access_token;

    return login_tokens_->build_login_response(
        login_token_str, effective_token, server_name_);
  }

  /// Handle OpenID token request
  json handle_openid_request(
      const std::string& user_id,
      const std::string& client_info = "") {

    auto result = openid_->generate_openid_token(user_id, client_info);
    if (!result.has_value()) {
      return error_response("M_UNKNOWN", "Failed to generate OpenID token");
    }
    return result.value();
  }

  /// Check if a user requires UI auth for an action.
  /// Returns the UI auth params if required, or an empty object if not.
  json require_ui_auth_if_needed(
      const std::string& user_id,
      const std::string& action,
      bool force_auth = false) {

    if (!force_auth) {
      return json::object();  // No auth required
    }

    // Create a simple session with m.login.password
    auto params = ui_auth_sessions_->create_session_simple(
        user_id, action, {"m.login.password"});

    if (!params.has_value()) {
      return error_response("M_UNKNOWN", "Failed to create UI auth session");
    }

    json response;
    response["flows"] = json::array();

    for (const auto& flow : params->flows) {
      json f;
      json stages_array = json::array();
      for (const auto& stage : flow.stages) {
        stages_array.push_back(stage.type);
      }
      f["stages"] = stages_array;
      response["flows"].push_back(f);
    }

    response["params"] = params->params;
    response["session"] = params->session_id;

    response["errcode"] = "M_USER_INTERACTIVE_AUTH";
    response["error"] = "User interactive authentication required";

    return response;
  }

  /// Get comprehensive status overview
  json get_dashboard() {
    json dashboard;

    dashboard["server_name"] = server_name_;
    dashboard["timestamp"] = now_iso8601();

    // Guest stats
    dashboard["guest_access"] = guest_access_->get_guest_status_json();

    // Registration token stats
    dashboard["registration_tokens"] = reg_tokens_->get_token_stats();

    // OpenID stats
    dashboard["openid"] = openid_->get_stats();

    // Login token stats
    dashboard["login_tokens"] = login_tokens_->get_stats();

    // UI Auth session stats
    dashboard["ui_auth_sessions"] = ui_auth_sessions_->get_stats();

    // Account data summary
    json acct_summary;
    acct_summary["stream_position"] = account_data_->get_stream_position();
    dashboard["account_data"] = acct_summary;

    return dashboard;
  }

  /// Shutdown all background tasks
  void shutdown() {
    // Currently no explicit shutdown needed;
    // destructors handle cleanup thread joining.
  }

private:
  std::string server_name_;
  storage::RegistrationStore* reg_store_{nullptr};

  std::unique_ptr<GuestAccess> guest_access_;
  std::unique_ptr<RegistrationTokenManager> reg_tokens_;
  std::unique_ptr<AccountDataManager> account_data_;
  std::unique_ptr<OpenIDManager> openid_;
  std::unique_ptr<LoginTokenManager> login_tokens_;
  std::unique_ptr<UserInteractiveAuthSessionManager> ui_auth_sessions_;
};

// ============================================================================
// REST handler integration helpers
//
// These helpers bridge between the GuestRegistrationAPI and the HTTP layer,
// providing request/response handling for the guest and registration endpoints.
// ============================================================================
namespace rest {

/// Guest registration request handler result
struct GuestRegistrationResult {
  bool success{false};
  json response_body;
  int http_status{200};
};

/// Handle GET /_matrix/client/v3/account/whoami for a guest
GuestRegistrationResult handle_guest_whoami(
    GuestAccess& guest_access,
    const std::string& access_token) {

  GuestRegistrationResult result;

  auto guest = guest_access.get_guest_by_token(access_token);
  if (!guest.has_value()) {
    result.http_status = 401;
    result.response_body = error_response(
        "M_UNKNOWN_TOKEN", "Unknown or expired guest token");
    return result;
  }

  result.success = true;
  result.response_body = {
      {"user_id", guest->user_id},
      {"is_guest", true},
      {"device_id", guest->device_id}
  };

  return result;
}

/// Handle GET /_matrix/client/v3/capabilities for a guest
GuestRegistrationResult handle_guest_capabilities(
    GuestAccess& guest_access,
    const std::string& access_token) {

  GuestRegistrationResult result;

  auto guest = guest_access.get_guest_by_token(access_token);
  if (!guest.has_value()) {
    result.http_status = 401;
    result.response_body = error_response(
        "M_UNKNOWN_TOKEN", "Unknown or expired guest token");
    return result;
  }

  auto caps = guest_access.get_capabilities();

  json response;
  response["capabilities"] = {
      {"m.room_versions", {
          {"default", "10"},
          {"available", json::object()}
      }},
      {"m.change_password", {{"enabled", false}}},
      {"m.set_displayname", {{"enabled", caps.can_send_events}}},
      {"m.set_avatar_url", {{"enabled", caps.can_send_events}}},
      {"m.3pid_changes", {{"enabled", false}}}
  };

  result.success = true;
  result.response_body = response;

  return result;
}

/// Handle GET /_matrix/client/v3/register/available (username check)
GuestRegistrationResult handle_username_available(
    GuestAccess& guest_access,
    const std::string& username) {

  GuestRegistrationResult result;

  // Basic validation
  if (username.empty()) {
    result.http_status = 400;
    result.response_body = error_response(
        "M_INVALID_PARAM", "Username is required");
    return result;
  }

  if (username.size() < 3 || username.size() > 255) {
    result.success = true;
    result.response_body = {{"available", false}};
    return result;
  }

  // Check for invalid characters
  static const std::regex valid_username("^[a-z0-9._\\-=/]+$");
  if (!std::regex_match(username, valid_username)) {
    result.success = true;
    result.response_body = {{"available", false}};
    return result;
  }

  // Check if guest with this username exists
  std::string guest_user_id = "@guest_" + username + ":";
  // Guest IDs are randomized, so this check is mostly for reserved words
  if (username.find("guest_") == 0) {
    result.success = true;
    result.response_body = {{"available", false}};
    return result;
  }

  result.success = true;
  result.response_body = {{"available", true}};

  return result;
}

/// Handle POST /_matrix/client/v3/register (guest registration)
GuestRegistrationResult handle_guest_register(
    GuestAccess& guest_access,
    const json& request_body,
    const std::string& ip_address = "127.0.0.1") {

  GuestRegistrationResult result;

  // Check if registration is enabled
  if (!guest_access.is_guest_registration_enabled()) {
    result.http_status = 403;
    result.response_body = error_response(
        "M_FORBIDDEN", "Guest registration is disabled on this server");
    return result;
  }

  bool read_only = false;
  std::string display_name;

  if (request_body.contains("initial_device_display_name")) {
    display_name = request_body["initial_device_display_name"].get<std::string>();
  }

  // Check if guest kind is specified
  if (request_body.contains("kind") &&
      request_body["kind"].get<std::string>() == "guest") {

    // Good — this is an explicit guest registration
    auto guest = guest_access.register_guest(ip_address, display_name, read_only);
    if (!guest.has_value()) {
      result.http_status = 429;
      result.response_body = error_response(
          "M_LIMIT_EXCEEDED", "Too many guests. Try again later.");
      return result;
    }

    result.success = true;
    result.response_body = {
        {"user_id", guest->user_id},
        {"access_token", guest->access_token},
        {"device_id", guest->device_id},
        {"home_server", guest_access.get_guest_status_json()["server_name"]},
        {"is_guest", true}
    };
    result.http_status = 200;
    return result;
  }

  // Not a guest registration request
  result.http_status = 400;
  result.response_body = error_response(
      "M_UNRECOGNIZED", "kind must be 'guest' for guest registration");
  return result;
}

/// Handle POST /_matrix/client/v3/login (guest login / token login)
GuestRegistrationResult handle_guest_login(
    GuestAccess& guest_access,
    LoginTokenManager& login_tokens,
    const json& request_body) {

  GuestRegistrationResult result;

  std::string login_type;
  if (request_body.contains("type")) {
    login_type = request_body["type"].get<std::string>();
  }

  // Handle token-based login (m.login.token)
  if (login_type == "m.login.token") {
    if (!request_body.contains("token")) {
      result.http_status = 400;
      result.response_body = error_response(
          "M_MISSING_PARAM", "token is required for m.login.token");
      return result;
    }

    std::string token_str = request_body["token"].get<std::string>();
    auto login_result = login_tokens.exchange_login_token(token_str);

    if (!login_result.has_value()) {
      result.http_status = 403;
      result.response_body = error_response(
          "M_UNKNOWN_TOKEN", "Invalid or expired login token");
      return result;
    }

    auto& [user_id, device_id] = login_result.value();

    result.success = true;
    result.response_body = {
        {"user_id", user_id},
        {"access_token", generate_token(64)},
        {"home_server", ""}
    };
    if (!device_id.empty()) {
      result.response_body["device_id"] = device_id;
    }
    result.http_status = 200;
    return result;
  }

  // Handle guest login (m.login.guest)
  if (login_type == "m.login.guest" || login_type.empty()) {
    std::string ip = "127.0.0.1";
    auto guest = guest_access.register_guest(ip);

    if (!guest.has_value()) {
      result.http_status = 403;
      result.response_body = error_response(
          "M_FORBIDDEN", "Guest access is disabled");
      return result;
    }

    result.success = true;
    result.response_body = {
        {"user_id", guest->user_id},
        {"access_token", guest->access_token},
        {"device_id", guest->device_id},
        {"home_server", ""},
        {"is_guest", true}
    };
    result.http_status = 200;
    return result;
  }

  result.http_status = 400;
  result.response_body = error_response(
      "M_UNRECOGNIZED", "Unsupported login type: " + login_type);
  return result;
}

} // namespace rest

// ============================================================================
// Global factory functions
// ============================================================================

std::unique_ptr<GuestAccess> create_guest_access(
    const std::string& server_name) {
  return std::make_unique<GuestAccess>(server_name);
}

std::unique_ptr<RegistrationTokenManager> create_registration_token_manager() {
  return std::make_unique<RegistrationTokenManager>();
}

std::unique_ptr<AccountDataManager> create_account_data_manager() {
  return std::make_unique<AccountDataManager>();
}

std::unique_ptr<OpenIDManager> create_openid_manager(
    const std::string& server_name) {
  return std::make_unique<OpenIDManager>(server_name);
}

std::unique_ptr<LoginTokenManager> create_login_token_manager() {
  return std::make_unique<LoginTokenManager>();
}

std::unique_ptr<UserInteractiveAuthSessionManager>
create_ui_auth_session_manager() {
  return std::make_unique<UserInteractiveAuthSessionManager>();
}

std::unique_ptr<GuestRegistrationAPI> create_guest_registration_api(
    const std::string& server_name,
    storage::RegistrationStore* reg_store = nullptr) {
  return std::make_unique<GuestRegistrationAPI>(server_name, reg_store);
}

} // namespace progressive
