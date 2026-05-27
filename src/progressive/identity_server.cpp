// identity_server.cpp - Matrix Identity Server API
// Implements IS API: 3PID session management, bindings, store-invite,
// terms of service, email/SMS verification, session keys, public keys.
// Equivalent to synapse/handlers/identity.py + synapse/rest/client/v2_alpha/account.py
// Target: 2500+ lines

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
class IdentitySessionManager;
class IdentityThreepidBinder;
class IdentityStoreInviteManager;
class IdentityTermsManager;
class IdentityEmailSender;
class IdentitySmsSender;
class IdentitySessionKeyManager;
class IdentityPublicKeyManager;
class IdentityServer;

// ============================================================================
// Utility: string and time helpers
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

std::string url_decode(const std::string& s) {
  std::ostringstream decoded;
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '%' && i + 2 < s.size() && isxdigit(s[i+1]) && isxdigit(s[i+2])) {
      int val;
      std::istringstream hex_ss(s.substr(i + 1, 2));
      hex_ss >> std::hex >> val;
      decoded << static_cast<char>(val);
      i += 2;
    } else if (s[i] == '+') {
      decoded << ' ';
    } else {
      decoded << s[i];
    }
  }
  return decoded.str();
}

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

std::string generate_token(size_t length = 64) {
  static const char charset[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
  static thread_local std::mt19937 rng(
      static_cast<unsigned>(chr::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);
  std::string token(length, '\0');
  for (size_t i = 0; i < length; ++i) token[i] = charset[dist(rng)];
  return token;
}

std::string generate_numeric_token(int digits = 6) {
  static thread_local std::mt19937 rng(
      static_cast<unsigned>(chr::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<int> dist(0, 9);
  std::string out(digits, '0');
  for (int i = 0; i < digits; ++i)
    out[i] = static_cast<char>('0' + dist(rng));
  return out;
}

std::string generate_sid() {
  return generate_token(32);
}

bool valid_email(const std::string& email) {
  static const std::regex email_re(
      R"(^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$)",
      std::regex::ECMAScript);
  return std::regex_match(email, email_re);
}

bool valid_msisdn(const std::string& msisdn) {
  static const std::regex phone_re(R"(^\+[1-9]\d{6,15}$)",
                                    std::regex::ECMAScript);
  return std::regex_match(msisdn, phone_re);
}

bool valid_matrix_id(const std::string& mxid) {
  static const std::regex mxid_re(R"(^@[a-zA-Z0-9._=\-/]+:\S+$)");
  return std::regex_match(mxid, mxid_re);
}

std::string sha256_hex(const std::string& input) {
  // Simple 256-bit hash placeholder using combination of character folding.
  // In production this would use OpenSSL EVP_sha256() or similar.
  // We use a deterministic algorithm that produces a 64-char hex digest.
  std::array<unsigned char, 32> hash{};
  for (size_t i = 0; i < input.size(); ++i) {
    hash[i % 32] ^= static_cast<unsigned char>(input[i]);
    hash[(i * 7 + 13) % 32] ^= static_cast<unsigned char>(input[i]);
    hash[(i * 3 + 29) % 32] ^= static_cast<unsigned char>(input[i] >> 1);
  }
  for (size_t i = 0; i < 32; ++i) {
    hash[i] = static_cast<unsigned char>((hash[i] * 2654435761ULL) & 0xFF);
  }
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (auto b : hash) oss << std::setw(2) << static_cast<int>(b);
  return oss.str();
}

std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
  return sha256_hex(key + "::hmac::" + data);
}

std::string sign_json(const json& payload, const std::string& signing_key) {
  std::string canonical = payload.dump();
  return hmac_sha256_hex(signing_key, canonical);
}

json error_json(const std::string& errcode, const std::string& error) {
  return json{{"errcode", errcode}, {"error", error}};
}

} // anonymous namespace

// ============================================================================
// IdentitySessionManager - manages 3PID validation sessions
// Handles: requestToken, submitToken, session lifecycle
// Equivalent to synapse.handlers.identity.IdentityHandler session methods
// ============================================================================
class IdentitySessionManager {
public:
  struct SessionData {
    std::string sid;
    std::string medium;        // "email" or "msisdn"
    std::string address;       // the email or phone number
    std::string client_secret;
    int send_attempt{0};
    std::string token;         // the numeric code
    int64_t created_at_ms{0};
    int64_t validated_at_ms{0};
    int64_t expires_at_ms{0};
    std::string next_link;     // optional redirect after validation
    std::string ip_address;
    int attempt_count{0};
    bool validated{false};
    std::string validated_user_id;
    std::optional<std::string> id_server;
    std::optional<std::string> id_access_token;
  };

  IdentitySessionManager() {
    session_cleaner_running_ = true;
    cleaner_thread_ = std::thread([this]() { this->cleaner_loop(); });
  }

  ~IdentitySessionManager() {
    session_cleaner_running_ = false;
    if (cleaner_thread_.joinable()) cleaner_thread_.join();
  }

  // Create a new validation session
  SessionData create_session(
      const std::string& medium,
      const std::string& address,
      const std::string& client_secret,
      int send_attempt,
      const std::optional<std::string>& next_link = std::nullopt,
      const std::string& ip_address = "127.0.0.1",
      const std::optional<std::string>& id_server = std::nullopt,
      const std::optional<std::string>& id_access_token = std::nullopt) {

    SessionData session;
    session.sid = generate_sid();
    session.medium = medium;
    session.address = address;
    session.client_secret = client_secret;
    session.send_attempt = send_attempt;
    session.token = generate_numeric_token(6);
    session.created_at_ms = now_ms();
    session.validated_at_ms = 0;
    session.expires_at_ms = now_ms() + kSessionTTLMs;
    session.next_link = next_link.value_or("");
    session.ip_address = ip_address;
    session.attempt_count = 0;
    session.validated = false;
    session.id_server = id_server;
    session.id_access_token = id_access_token;

    std::lock_guard<std::shared_mutex> lock(sessions_mutex_);
    sessions_[session.sid] = session;
    return session;
  }

  // Get session by SID
  std::optional<SessionData> get_session(const std::string& sid) {
    std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
    auto it = sessions_.find(sid);
    if (it != sessions_.end()) return it->second;
    return std::nullopt;
  }

  // Validate token for a session
  struct ValidateResult {
    bool success{false};
    std::string error;
    SessionData session;
  };

  ValidateResult validate_token(
      const std::string& sid,
      const std::string& client_secret,
      const std::string& token) {

    ValidateResult result;
    std::lock_guard<std::shared_mutex> lock(sessions_mutex_);
    auto it = sessions_.find(sid);
    if (it == sessions_.end()) {
      result.error = "Session not found";
      return result;
    }

    auto& session = it->second;

    // Check expiry
    if (now_ms() > session.expires_at_ms) {
      result.error = "Session expired";
      sessions_.erase(it);
      return result;
    }

    // Check client_secret
    if (session.client_secret != client_secret) {
      result.error = "Client secret mismatch";
      session.attempt_count++;
      return result;
    }

    // Validate token
    if (session.token != token) {
      result.error = "Token mismatch";
      session.attempt_count++;
      if (session.attempt_count >= kMaxAttempts) {
        sessions_.erase(it);
        result.error = "Too many attempts, session invalidated";
      }
      return result;
    }

    // Mark validated
    session.validated = true;
    session.validated_at_ms = now_ms();
    result.success = true;
    result.session = session;
    return result;
  }

  // Resend the token with a new code
  std::optional<SessionData> resend_token(const std::string& sid) {
    std::lock_guard<std::shared_mutex> lock(sessions_mutex_);
    auto it = sessions_.find(sid);
    if (it == sessions_.end()) return std::nullopt;

    auto& session = it->second;
    if (now_ms() > session.expires_at_ms) {
      sessions_.erase(it);
      return std::nullopt;
    }

    session.send_attempt++;
    // Generate a fresh token on resend
    session.token = generate_numeric_token(6);
    session.expires_at_ms = now_ms() + kSessionTTLMs;
    session.attempt_count = 0;
    return session;
  }

  // Remove a session
  bool remove_session(const std::string& sid) {
    std::lock_guard<std::shared_mutex> lock(sessions_mutex_);
    return sessions_.erase(sid) > 0;
  }

  // Mark session as having sent to the given address
  void mark_sent(const std::string& sid) {
    std::lock_guard<std::shared_mutex> lock(sessions_mutex_);
    auto it = sessions_.find(sid);
    if (it != sessions_.end()) {
      it->second.send_attempt++;
    }
  }

  // Get session count (for metrics)
  size_t session_count() {
    std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
    return sessions_.size();
  }

  // Rate limit check: max sessions per address within a window
  bool check_rate_limit(const std::string& medium, const std::string& address) {
    std::lock_guard<std::mutex> lock(ratelimit_mutex_);
    std::string key = medium + ":" + to_lower(address);
    int64_t now = now_ms();

    // Clean old entries for this key
    auto& entries = rate_limit_map_[key];
    entries.erase(
        std::remove_if(entries.begin(), entries.end(),
                       [now](int64_t ts) { return now - ts > kRateLimitWindowMs; }),
        entries.end());

    if (entries.size() >= kMaxRequestsPerWindow) return false;
    entries.push_back(now);
    return true;
  }

private:
  static constexpr int64_t kSessionTTLMs = 30 * 60 * 1000;        // 30 minutes
  static constexpr int kMaxAttempts = 5;
  static constexpr int64_t kRateLimitWindowMs = 15 * 60 * 1000;   // 15 minutes
  static constexpr size_t kMaxRequestsPerWindow = 10;

  std::shared_mutex sessions_mutex_;
  std::unordered_map<std::string, SessionData> sessions_;

  std::mutex ratelimit_mutex_;
  std::unordered_map<std::string, std::vector<int64_t>> rate_limit_map_;

  // Background cleaner thread
  std::atomic<bool> session_cleaner_running_{false};
  std::thread cleaner_thread_;

  void cleaner_loop() {
    while (session_cleaner_running_) {
      std::this_thread::sleep_for(chr::seconds(60));
      std::lock_guard<std::shared_mutex> lock(sessions_mutex_);
      int64_t now = now_ms();
      for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        if (now > it->second.expires_at_ms) {
          it = sessions_.erase(it);
        } else {
          ++it;
        }
      }
    }
  }
};

// ============================================================================
// IdentityThreepidBinder - handles 3PID to Matrix ID bindings
// Handles: bind, unbind, lookup operations
// Equivalent to synapse.handlers.identity.IdentityHandler threepid methods
// ============================================================================
class IdentityThreepidBinder {
public:
  struct ThreepidBinding {
    std::string medium;
    std::string address;
    std::string mxid;
    int64_t bound_at_ms{0};
    bool not_before_ms{0};
    bool not_after_ms{0};
    std::string id_server;
    std::string signature;
    std::string bind_token;
  };

  struct HashLookupEntry {
    std::string medium;
    std::string address_hash;      // hashed address (pepper + address)
    std::string mxid;
    std::string pepper_id;
  };

  IdentityThreepidBinder(const std::string& pepper = "")
      : pepper_(pepper.empty() ? generate_token(32) : pepper) {}

  // Set pepper
  void set_pepper(const std::string& pepper) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    pepper_ = pepper;
  }

  // Get pepper
  std::string get_pepper() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return pepper_;
  }

  // Hash an address with pepper for privacy-preserving lookups
  std::string hash_address(const std::string& medium, const std::string& address) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::string input = pepper_ + "|" + to_lower(medium) + "|" + to_lower(address);
    return sha256_hex(input);
  }

  // Create a hash lookup entry
  HashLookupEntry create_hash_entry(const std::string& medium,
                                     const std::string& address,
                                     const std::string& mxid) {
    HashLookupEntry entry;
    entry.medium = medium;
    entry.address_hash = hash_address(medium, address);
    entry.mxid = mxid;
    entry.pepper_id = pepper_.substr(0, 8); // partial pepper ID for rotation

    std::lock_guard<std::shared_mutex> lock(mutex_);
    hash_lookups_[entry.address_hash] = entry;
    return entry;
  }

  // Bind a 3PID to a Matrix ID
  ThreepidBinding bind_threepid(
      const std::string& medium,
      const std::string& address,
      const std::string& mxid,
      const std::string& id_server) {

    ThreepidBinding binding;
    binding.medium = medium;
    binding.address = to_lower(address);
    binding.mxid = mxid;
    binding.bound_at_ms = now_ms();
    binding.id_server = id_server;
    binding.bind_token = generate_token(32);
    binding.signature = hmac_sha256_hex(
        pepper_, medium + ":" + to_lower(address) + ":" + mxid);

    std::lock_guard<std::shared_mutex> lock(mutex_);
    std::string key = binding.medium + ":" + binding.address;
    bindings_[key] = binding;

    // Also update hash lookup
    auto hash_entry = create_hash_entry(medium, address, mxid);

    // Index by mxid for reverse lookups
    mxid_bindings_[mxid].push_back(binding);

    return binding;
  }

  // Unbind a 3PID from a Matrix ID
  bool unbind_threepid(
      const std::string& medium,
      const std::string& address,
      const std::string& mxid) {

    std::lock_guard<std::shared_mutex> lock(mutex_);
    std::string key = to_lower(medium) + ":" + to_lower(address);
    auto it = bindings_.find(key);
    if (it != bindings_.end() && it->second.mxid == mxid) {
      bindings_.erase(it);

      // Remove from mxid index
      auto& vec = mxid_bindings_[mxid];
      vec.erase(std::remove_if(vec.begin(), vec.end(),
                               [&](const ThreepidBinding& b) {
                                 return b.medium == medium &&
                                        b.address == to_lower(address);
                               }),
                vec.end());
      if (vec.empty()) mxid_bindings_.erase(mxid);

      // Remove from hash lookups
      std::string hash = hash_address(medium, address);
      hash_lookups_.erase(hash);
      return true;
    }
    return false;
  }

  // Lookup Matrix IDs by 3PID hashes (privacy-preserving)
  std::vector<json> lookup_by_hash(
      const std::vector<std::pair<std::string, std::string>>& hashes) {
    // hashes: vector of (medium, hashed_address) pairs
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<json> results;
    for (const auto& [medium, addr_hash] : hashes) {
      auto it = hash_lookups_.find(addr_hash);
      if (it != hash_lookups_.end() && it->second.medium == medium) {
        results.push_back(json{
            {"medium", medium},
            {"address", it->second.address_hash},
            {"mxid", it->second.mxid}
        });
      }
    }
    return results;
  }

  // Direct lookup by address (non-hashed, legacy)
  std::optional<std::string> lookup_by_address(
      const std::string& medium, const std::string& address) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::string key = to_lower(medium) + ":" + to_lower(address);
    auto it = bindings_.find(key);
    if (it != bindings_.end()) return it->second.mxid;
    return std::nullopt;
  }

  // Get all bindings for a Matrix ID
  std::vector<ThreepidBinding> get_bindings_for_mxid(const std::string& mxid) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = mxid_bindings_.find(mxid);
    if (it != mxid_bindings_.end()) return it->second;
    return {};
  }

  // Check if a binding exists
  bool is_bound(const std::string& medium, const std::string& address) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::string key = to_lower(medium) + ":" + to_lower(address);
    return bindings_.find(key) != bindings_.end();
  }

  // Get binding count
  size_t binding_count() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return bindings_.size();
  }

  // Export all bindings (for migration/backup)
  json export_bindings() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json result = json::array();
    for (const auto& [key, binding] : bindings_) {
      result.push_back(json{
          {"medium", binding.medium},
          {"address", binding.address},
          {"mxid", binding.mxid},
          {"bound_at_ms", binding.bound_at_ms},
          {"id_server", binding.id_server},
          {"signature", binding.signature}
      });
    }
    return result;
  }

  // Import bindings (for migration)
  void import_bindings(const json& data) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    for (const auto& item : data) {
      ThreepidBinding binding;
      binding.medium = item.value("medium", "");
      binding.address = item.value("address", "");
      binding.mxid = item.value("mxid", "");
      binding.bound_at_ms = item.value("bound_at_ms", 0LL);
      binding.id_server = item.value("id_server", "");
      binding.signature = item.value("signature", "");

      std::string key = binding.medium + ":" + binding.address;
      bindings_[key] = binding;
      mxid_bindings_[binding.mxid].push_back(binding);
      create_hash_entry(binding.medium, binding.address, binding.mxid);
    }
  }

  // Rotate pepper - rehashes all addresses with new pepper
  void rotate_pepper(const std::string& new_pepper) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    std::string old_pepper = pepper_;
    pepper_ = new_pepper;

    // Rehash all entries
    std::unordered_map<std::string, HashLookupEntry> new_hashes;
    for (auto& [old_hash, entry] : hash_lookups_) {
      std::string input = pepper_ + "|" + entry.medium + "|" + entry.address_hash;
      std::string new_hash = sha256_hex(
          pepper_ + "|" + entry.medium + "|" + entry.address_hash);
      // We can't recover the original address from the old hash,
      // so this is a partial rotation. In production, we'd need the original
      // addresses. Store the old pepper for a transition period.
      old_peppers_.push_back(old_pepper);
      entry.pepper_id = pepper_.substr(0, 8);
      new_hashes[new_hash] = entry;
    }
    hash_lookups_ = std::move(new_hashes);
  }

private:
  mutable std::shared_mutex mutex_;
  std::string pepper_;
  std::vector<std::string> old_peppers_; // for pepper rotation transition
  std::unordered_map<std::string, ThreepidBinding> bindings_;
  std::unordered_map<std::string, std::vector<ThreepidBinding>> mxid_bindings_;
  std::unordered_map<std::string, HashLookupEntry> hash_lookups_;
};

// ============================================================================
// IdentityStoreInviteManager - stores 3PID room invitations
// Handles: POST /store-invite
// Equivalent to synapse.handlers.identity.IdentityHandler.store_invite
// ============================================================================
class IdentityStoreInviteManager {
public:
  struct StoredInvite {
    std::string invite_id;
    std::string medium;
    std::string address;
    std::string room_id;
    std::string room_name;
    std::string sender;
    std::string room_type;      // "m.room" or "m.direct"
    std::string token;
    std::string state;          // "pending", "accepted", "rejected", "expired"
    std::string mxid;           // resolved mxid after acceptance
    int64_t created_at_ms{0};
    int64_t accepted_at_ms{0};
    int64_t expires_at_ms{0};
    int display_name_ok{0};     // whether sender's display name OK to share
    json stored_public_keys;    // public keys of the room
  };

  IdentityStoreInviteManager() {
    cleaner_running_ = true;
    cleaner_thread_ = std::thread([this]() { this->cleaner_loop(); });
  }

  ~IdentityStoreInviteManager() {
    cleaner_running_ = false;
    if (cleaner_thread_.joinable()) cleaner_thread_.join();
  }

  // Store a new invite
  StoredInvite store_invite(
      const std::string& medium,
      const std::string& address,
      const std::string& room_id,
      const std::string& sender,
      const std::string& token,
      const std::optional<std::string>& room_name = std::nullopt,
      const std::optional<std::string>& room_type = std::nullopt,
      const json& public_keys = json::object()) {

    StoredInvite invite;
    invite.invite_id = generate_token(24);
    invite.medium = medium;
    invite.address = to_lower(address);
    invite.room_id = room_id;
    invite.room_name = room_name.value_or("");
    invite.sender = sender;
    invite.room_type = room_type.value_or("m.room");
    invite.token = token;
    invite.state = "pending";
    invite.created_at_ms = now_ms();
    invite.accepted_at_ms = 0;
    invite.expires_at_ms = now_ms() + kInviteTTLMs;
    invite.stored_public_keys = public_keys;

    std::lock_guard<std::shared_mutex> lock(mutex_);
    invites_[invite.invite_id] = invite;

    // Index by address for querying
    std::string addr_key = medium + ":" + invite.address;
    address_invites_[addr_key].push_back(invite.invite_id);

    // Index by room_id
    room_invites_[room_id].push_back(invite.invite_id);

    return invite;
  }

  // Get an invite by ID
  std::optional<StoredInvite> get_invite(const std::string& invite_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = invites_.find(invite_id);
    if (it != invites_.end()) return it->second;
    return std::nullopt;
  }

  // Get invites for a 3PID address
  std::vector<StoredInvite> get_invites_for_address(
      const std::string& medium, const std::string& address) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::string addr_key = medium + ":" + to_lower(address);
    std::vector<StoredInvite> result;
    auto it = address_invites_.find(addr_key);
    if (it != address_invites_.end()) {
      for (const auto& invite_id : it->second) {
        auto inv_it = invites_.find(invite_id);
        if (inv_it != invites_.end()) {
          result.push_back(inv_it->second);
        }
      }
    }
    return result;
  }

  // Get invites for a room
  std::vector<StoredInvite> get_invites_for_room(const std::string& room_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<StoredInvite> result;
    auto it = room_invites_.find(room_id);
    if (it != room_invites_.end()) {
      for (const auto& invite_id : it->second) {
        auto inv_it = invites_.find(invite_id);
        if (inv_it != invites_.end()) {
          result.push_back(inv_it->second);
        }
      }
    }
    return result;
  }

  // Accept an invite (mark as accepted and bind mxid)
  bool accept_invite(const std::string& invite_id, const std::string& mxid) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = invites_.find(invite_id);
    if (it == invites_.end()) return false;
    if (it->second.state != "pending") return false;
    if (now_ms() > it->second.expires_at_ms) {
      it->second.state = "expired";
      return false;
    }
    it->second.state = "accepted";
    it->second.mxid = mxid;
    it->second.accepted_at_ms = now_ms();
    return true;
  }

  // Reject an invite
  bool reject_invite(const std::string& invite_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = invites_.find(invite_id);
    if (it == invites_.end()) return false;
    if (it->second.state != "pending") return false;
    it->second.state = "rejected";
    return true;
  }

  // Check if an invite is valid
  bool is_invite_valid(const std::string& invite_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = invites_.find(invite_id);
    if (it == invites_.end()) return false;
    return it->second.state == "pending" && now_ms() <= it->second.expires_at_ms;
  }

  // Get invite count
  size_t invite_count() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return invites_.size();
  }

  // Get pending invite count
  size_t pending_invite_count() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, inv] : invites_) {
      if (inv.state == "pending" && now_ms() <= inv.expires_at_ms) count++;
    }
    return count;
  }

  // Get invite statistics
  json get_stats() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    size_t total = invites_.size();
    size_t pending = 0, accepted = 0, rejected = 0, expired = 0;
    int64_t now = now_ms();
    for (const auto& [id, inv] : invites_) {
      if (inv.state == "pending" && now <= inv.expires_at_ms) pending++;
      else if (inv.state == "accepted") accepted++;
      else if (inv.state == "rejected") rejected++;
      else expired++;
    }
    return json{
        {"total", total},
        {"pending", pending},
        {"accepted", accepted},
        {"rejected", rejected},
        {"expired", expired}
    };
  }

  // Delete an invite
  bool delete_invite(const std::string& invite_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    return invites_.erase(invite_id) > 0;
  }

private:
  static constexpr int64_t kInviteTTLMs = 7 * 24 * 60 * 60 * 1000LL; // 7 days

  std::shared_mutex mutex_;
  std::unordered_map<std::string, StoredInvite> invites_;
  std::unordered_map<std::string, std::vector<std::string>> address_invites_;
  std::unordered_map<std::string, std::vector<std::string>> room_invites_;

  std::atomic<bool> cleaner_running_{false};
  std::thread cleaner_thread_;

  void cleaner_loop() {
    while (cleaner_running_) {
      std::this_thread::sleep_for(chr::seconds(300)); // every 5 min
      std::lock_guard<std::shared_mutex> lock(mutex_);
      int64_t now = now_ms();
      for (auto& [id, inv] : invites_) {
        if (inv.state == "pending" && now > inv.expires_at_ms) {
          inv.state = "expired";
        }
      }
    }
  }
};

// ============================================================================
// IdentityTermsManager - manages terms of service policies
// Handles: GET /terms (list policies), POST /terms (accept)
// Equivalent to synapse.handlers.terms.TermsHandler
// ============================================================================
class IdentityTermsManager {
public:
  struct Policy {
    std::string id;
    std::string version;
    std::string language;       // e.g. "en", "fr"
    std::string name;
    std::string url;            // URL to the policy document
    int64_t created_at_ms{0};
    bool active{true};
  };

  struct AcceptanceRecord {
    std::string user_id;
    std::string policy_id;
    std::string policy_version;
    std::string accepted_by_ip;
    int64_t accepted_at_ms{0};
    std::string acceptance_token;
  };

  IdentityTermsManager() {
    // Initialize with default policies
    add_policy("privacy_policy", "1.0", "en",
               "Privacy Policy",
               "https://matrix.org/legal/privacy-notice/");
    add_policy("terms_of_service", "1.0", "en",
               "Terms of Service",
               "https://matrix.org/legal/terms-and-conditions/");
  }

  // Add a policy
  Policy add_policy(const std::string& id,
                     const std::string& version,
                     const std::string& language,
                     const std::string& name,
                     const std::string& url) {
    Policy policy;
    policy.id = id;
    policy.version = version;
    policy.language = language;
    policy.name = name;
    policy.url = url;
    policy.created_at_ms = now_ms();
    policy.active = true;

    std::lock_guard<std::shared_mutex> lock(mutex_);
    std::string key = id + "/" + version + "/" + language;
    policies_[key] = policy;
    return policy;
  }

  // Get all active policies
  json get_policies(const std::string& language = "") {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json result = json::object();

    // Group by policy ID
    std::map<std::string, json> grouped;
    for (const auto& [key, policy] : policies_) {
      if (!policy.active) continue;
      // Filter by language if specified
      if (!language.empty() && policy.language != language) continue;

      json policy_json;
      policy_json["version"] = policy.version;
      // If a language was specified, include it; otherwise use the policy's language
      if (!language.empty()) {
        policy_json[policy.language] = json{
            {"name", policy.name},
            {"url", policy.url}
        };
      } else {
        policy_json[policy.language] = json{
            {"name", policy.name},
            {"url", policy.url}
        };
      }
      // Merge into grouped
      if (!grouped.contains(policy.id)) {
        grouped[policy.id] = json::object();
      }
      grouped[policy.id][policy.version] = policy_json;
    }
    for (const auto& [id, versions] : grouped) {
      result[id] = versions;
    }
    return result;
  }

  // Record a user's acceptance of a policy
  AcceptanceRecord accept_policy(
      const std::string& user_id,
      const std::string& policy_id,
      const std::string& policy_version,
      const std::string& ip_address = "127.0.0.1") {

    AcceptanceRecord record;
    record.user_id = user_id;
    record.policy_id = policy_id;
    record.policy_version = policy_version;
    record.accepted_by_ip = ip_address;
    record.accepted_at_ms = now_ms();
    record.acceptance_token = generate_token(32);

    std::lock_guard<std::shared_mutex> lock(mutex_);
    acceptances_[user_id][policy_id] = record;
    return record;
  }

  // Check if a user has accepted a policy
  bool has_accepted(const std::string& user_id,
                     const std::string& policy_id,
                     const std::string& min_version = "") {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto user_it = acceptances_.find(user_id);
    if (user_it == acceptances_.end()) return false;

    auto policy_it = user_it->second.find(policy_id);
    if (policy_it == user_it->second.end()) return false;

    if (!min_version.empty()) {
      // Simple version comparison (assumes format like "1.0")
      return policy_it->second.policy_version >= min_version;
    }
    return true;
  }

  // Get all acceptances for a user
  std::map<std::string, AcceptanceRecord> get_user_acceptances(
      const std::string& user_id) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = acceptances_.find(user_id);
    if (it != acceptances_.end()) return it->second;
    return {};
  }

  // Get all users who have not accepted a required policy
  std::vector<std::string> get_users_pending_policy(
      const std::string& policy_id,
      const std::vector<std::string>& all_users) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<std::string> pending;
    for (const auto& user_id : all_users) {
      auto it = acceptances_.find(user_id);
      if (it == acceptances_.end() || !it->second.contains(policy_id)) {
        pending.push_back(user_id);
      }
    }
    return pending;
  }

  // Set a policy as inactive (deprecated)
  void deactivate_policy(const std::string& id,
                          const std::string& version,
                          const std::string& language) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    std::string key = id + "/" + version + "/" + language;
    auto it = policies_.find(key);
    if (it != policies_.end()) {
      it->second.active = false;
    }
  }

  // Get policy by ID and version
  std::optional<Policy> get_policy(const std::string& id,
                                    const std::string& version,
                                    const std::string& language) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::string key = id + "/" + version + "/" + language;
    auto it = policies_.find(key);
    if (it != policies_.end()) return it->second;
    return std::nullopt;
  }

private:
  std::shared_mutex mutex_;
  std::unordered_map<std::string, Policy> policies_;
  std::unordered_map<std::string,
    std::unordered_map<std::string, AcceptanceRecord>> acceptances_;
};

// ============================================================================
// IdentityEmailSender - sends verification and notification emails
// Handles: email templates, SMTP integration, email validation
// Equivalent to synapse.push.emailpusher + synapse.handlers.identity email
// ============================================================================
class IdentityEmailSender {
public:
  struct EmailTemplate {
    std::string subject_template;
    std::string body_text_template;
    std::string body_html_template;
  };

  struct EmailSendResult {
    bool success{false};
    std::string message_id;
    std::string error;
    int smtp_code{0};
  };

  struct EmailConfig {
    std::string smtp_host{"localhost"};
    int smtp_port{587};
    std::string smtp_username;
    std::string smtp_password;
    std::string from_address{"noreply@matrix.local"};
    std::string from_name{"Matrix Identity Server"};
    bool use_tls{true};
    bool use_starttls{true};
    int connect_timeout_sec{10};
    int send_timeout_sec{30};
  };

  IdentityEmailSender() {
    init_templates();
  }

  explicit IdentityEmailSender(const EmailConfig& config) : config_(config) {
    init_templates();
  }

  void set_config(const EmailConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
  }

  EmailConfig get_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
  }

  // Send a verification email
  EmailSendResult send_verification_email(
      const std::string& to_address,
      const std::string& token,
      const std::string& client_secret,
      const std::string& sid,
      const std::optional<std::string>& next_link = std::nullopt) {

    std::string subject = "Your Matrix verification code is: " + token;
    std::string body_text = "Hello,\n\n"
        "You have requested to verify your email address for Matrix.\n\n"
        "Your verification code is: " + token + "\n\n"
        "If you did not request this, please ignore this email.\n\n"
        "This code will expire in 30 minutes.\n\n"
        "Session ID: " + sid + "\n"
        "Client Secret: " + client_secret + "\n";

    if (next_link.has_value() && !next_link->empty()) {
      body_text += "\nAfter verification, you will be redirected to: " +
                   next_link.value() + "\n";
    }

    body_text += "\n-- Matrix Identity Server\n";

    std::string body_html =
        "<html><body style=\"font-family: Arial, sans-serif;\">"
        "<h2>Matrix Email Verification</h2>"
        "<p>Hello,</p>"
        "<p>You have requested to verify your email address for Matrix.</p>"
        "<div style=\"background: #f0f0f0; padding: 20px; border-radius: 8px; "
        "margin: 20px 0; text-align: center;\">"
        "<p style=\"font-size: 14px; color: #666;\">Your verification code:</p>"
        "<p style=\"font-size: 32px; font-weight: bold; letter-spacing: 4px; "
        "color: #333;\">" + token + "</p>"
        "</div>"
        "<p style=\"color: #888; font-size: 12px;\">"
        "If you did not request this, please ignore this email.<br>"
        "This code will expire in 30 minutes.</p>"
        "<hr style=\"border: none; border-top: 1px solid #eee;\">"
        "<p style=\"color: #aaa; font-size: 11px;\">"
        "Session: " + sid + "</p>";

    if (next_link.has_value() && !next_link->empty()) {
      body_html += "<p style=\"color: #aaa; font-size: 11px;\">"
                   "Next: " + next_link.value() + "</p>";
    }

    body_html += "</body></html>";

    return send_email(to_address, subject, body_text, body_html);
  }

  // Send a password reset email
  EmailSendResult send_password_reset_email(
      const std::string& to_address,
      const std::string& reset_link,
      const std::string& ip_address = "") {

    std::string subject = "Matrix Password Reset Request";
    std::string body_text = "Hello,\n\n"
        "A password reset was requested for your Matrix account.\n\n"
        "To reset your password, please click the link below:\n"
        + reset_link + "\n\n"
        "This link will expire in 1 hour.\n\n";

    if (!ip_address.empty()) {
      body_text += "Request originated from IP: " + ip_address + "\n\n";
    }
    body_text += "If you did not request this, please ignore this email.\n\n"
                 "-- Matrix Identity Server\n";

    std::string body_html =
        "<html><body style=\"font-family: Arial, sans-serif;\">"
        "<h2>Matrix Password Reset</h2>"
        "<p>Hello,</p>"
        "<p>A password reset was requested for your Matrix account.</p>"
        "<div style=\"text-align: center; margin: 30px 0;\">"
        "<a href=\"" + reset_link + "\" "
        "style=\"background: #03b381; color: white; padding: 14px 32px; "
        "text-decoration: none; border-radius: 6px; font-size: 16px;\">"
        "Reset Password</a>"
        "</div>"
        "<p style=\"color: #888; font-size: 12px;\">"
        "This link will expire in 1 hour.<br>";

    if (!ip_address.empty()) {
      body_html += "Request from IP: " + ip_address + "<br>";
    }

    body_html += "If you did not request this, please ignore this email.</p>"
                 "</body></html>";

    return send_email(to_address, subject, body_text, body_html);
  }

  // Send a notification email
  EmailSendResult send_notification_email(
      const std::string& to_address,
      const std::string& subject,
      const std::string& notification_text) {

    std::string body_html =
        "<html><body style=\"font-family: Arial, sans-serif;\">"
        "<h3>Matrix Notification</h3>"
        "<p>" + notification_text + "</p>"
        "<hr style=\"border: none; border-top: 1px solid #eee;\">"
        "<p style=\"color: #aaa; font-size: 11px;\">"
        "This is an automated message from Matrix Identity Server.</p>"
        "</body></html>";

    return send_email(to_address, subject, notification_text, body_html);
  }

  // Send a welcome email
  EmailSendResult send_welcome_email(
      const std::string& to_address,
      const std::string& mxid,
      const std::string& display_name) {

    std::string greeting = display_name.empty() ? "there" : display_name;
    std::string subject = "Welcome to Matrix, " + greeting + "!";

    std::string body_text = "Hello " + greeting + ",\n\n"
        "Welcome to Matrix! Your Matrix ID is: " + mxid + "\n\n"
        "You can use this ID to connect with others on the Matrix network.\n\n"
        "Here are some resources to get started:\n"
        "- Web client: https://app.element.io\n"
        "- Mobile apps: Search for \"Element\" in your app store\n"
        "- Documentation: https://matrix.org/docs/\n\n"
        "Enjoy!\n"
        "-- The Matrix Team\n";

    std::string body_html =
        "<html><body style=\"font-family: Arial, sans-serif;\">"
        "<h1 style=\"color: #03b381;\">Welcome to Matrix!</h1>"
        "<p>Hello <strong>" + greeting + "</strong>,</p>"
        "<p>Your Matrix ID is: <code>" + mxid + "</code></p>"
        "<p>Connect with others using this ID on the Matrix network.</p>"
        "<h3>Get Started</h3>"
        "<ul>"
        "<li><a href=\"https://app.element.io\">Web Client (Element)</a></li>"
        "<li>Search for \"Element\" in your app store for mobile</li>"
        "<li><a href=\"https://matrix.org/docs/\">Documentation</a></li>"
        "</ul>"
        "<p>Enjoy!</p>"
        "<p>-- The Matrix Team</p>"
        "</body></html>";

    return send_email(to_address, subject, body_text, body_html);
  }

  // Send an email with custom content
  EmailSendResult send_custom_email(
      const std::string& to_address,
      const std::string& subject,
      const std::string& body_text,
      const std::string& body_html = "") {

    return send_email(to_address, subject, body_text,
                      body_html.empty() ? body_text : body_html);
  }

  // Validate an email by syntax
  static bool validate_syntax(const std::string& email) {
    return valid_email(email);
  }

  // Check email send rate limiting
  bool check_rate_limit(const std::string& email) {
    std::lock_guard<std::mutex> lock(ratelimit_mutex_);
    std::string key = to_lower(email);
    int64_t now = now_ms();

    auto& entries = rate_limit_map_[key];
    entries.erase(
        std::remove_if(entries.begin(), entries.end(),
                       [now](int64_t ts) { return now - ts > kEmailRateWindowMs; }),
        entries.end());

    if (entries.size() >= kMaxEmailsPerWindow) return false;
    return true;
  }

  void record_send(const std::string& email) {
    std::lock_guard<std::mutex> lock(ratelimit_mutex_);
    rate_limit_map_[to_lower(email)].push_back(now_ms());
  }

  // Get send count statistics
  json get_stats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return json{
        {"total_sent", total_sent_.load()},
        {"total_failed", total_failed_.load()},
        {"last_send_at_ms", last_send_at_ms_.load()}
    };
  }

private:
  mutable std::mutex config_mutex_;
  EmailConfig config_;
  std::unordered_map<std::string, EmailTemplate> templates_;
  std::atomic<int64_t> total_sent_{0};
  std::atomic<int64_t> total_failed_{0};
  std::atomic<int64_t> last_send_at_ms_{0};
  std::mutex stats_mutex_;
  std::mutex ratelimit_mutex_;
  std::unordered_map<std::string, std::vector<int64_t>> rate_limit_map_;

  static constexpr int64_t kEmailRateWindowMs = 60 * 60 * 1000; // 1 hour
  static constexpr size_t kMaxEmailsPerWindow = 20;

  void init_templates() {
    templates_["verification"] = {
        "Your Matrix verification code is: {{token}}",
        "Hello,\n\nYour verification code is: {{token}}\n\n-- Matrix",
        "<html><body><p>Code: <strong>{{token}}</strong></p></body></html>"
    };
    templates_["password_reset"] = {
        "Matrix Password Reset",
        "Hello,\n\nReset your password: {{reset_link}}\n\n-- Matrix",
        "<html><body><p>Reset: <a href=\"{{reset_link}}\">Click here</a></p></body></html>"
    };
    templates_["welcome"] = {
        "Welcome to Matrix, {{display_name}}!",
        "Welcome {{display_name}}!\nYour Matrix ID: {{mxid}}\n\n-- Matrix",
        "<html><body><h1>Welcome {{display_name}}!</h1><p>ID: {{mxid}}</p></body></html>"
    };
    templates_["notification"] = {
        "Matrix Notification",
        "{{notification_text}}\n\n-- Matrix",
        "<html><body><p>{{notification_text}}</p></body></html>"
    };
    templates_["invite"] = {
        "You've been invited to a Matrix room",
        "Hello,\n\n{{sender}} has invited you to \"{{room_name}}\".\n\n"
        "Join: {{join_link}}\n\n-- Matrix",
        "<html><body><h2>Room Invitation</h2>"
        "<p>{{sender}} invited you to <strong>{{room_name}}</strong>.</p>"
        "<p><a href=\"{{join_link}}\">Join Room</a></p></body></html>"
    };
  }

  EmailSendResult send_email(
      const std::string& to_address,
      const std::string& subject,
      const std::string& body_text,
      const std::string& body_html) {

    EmailSendResult result;

    // Rate limit check
    if (!check_rate_limit(to_address)) {
      result.error = "Rate limit exceeded for email: " + to_address;
      total_failed_++;
      return result;
    }

    // In production this would connect to SMTP, send the email, and handle
    // retries with exponential backoff. For the massive handler pattern,
    // we simulate the SMTP flow but log what we would do.

    std::string message_id = generate_token(16) + "@matrix.local";
    record_send(to_address);

    // Build MIME message headers (in production this would be sent via SMTP)
    std::ostringstream mime;
    mime << "From: " << config_.from_name << " <" << config_.from_address << ">\r\n";
    mime << "To: " << to_address << "\r\n";
    mime << "Subject: " << subject << "\r\n";
    mime << "Message-ID: <" << message_id << ">\r\n";
    mime << "Date: " << chr::system_clock::to_time_t(chr::system_clock::now()) << "\r\n";
    mime << "MIME-Version: 1.0\r\n";
    mime << "Content-Type: multipart/alternative; "
         << "boundary=\"boundary-" << generate_token(8) << "\"\r\n\r\n";

    // Plain text part
    mime << "--boundary\r\n";
    mime << "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
    mime << body_text << "\r\n\r\n";

    // HTML part
    mime << "--boundary\r\n";
    mime << "Content-Type: text/html; charset=UTF-8\r\n\r\n";
    mime << body_html << "\r\n\r\n";
    mime << "--boundary--\r\n";

    // In a real server, this would call SMTP send here.
    // We simulate success with logging the MIME body size.
    result.success = true;
    result.message_id = message_id;
    result.smtp_code = 250;

    total_sent_++;
    last_send_at_ms_ = now_ms();

    return result;
  }

  // Template rendering helper
  std::string render_template(const std::string& tmpl,
                               const std::map<std::string, std::string>& vars) {
    std::string result = tmpl;
    for (const auto& [key, value] : vars) {
      std::string placeholder = "{{" + key + "}}";
      size_t pos = 0;
      while ((pos = result.find(placeholder, pos)) != std::string::npos) {
        result.replace(pos, placeholder.size(), value);
        pos += value.size();
      }
    }
    return result;
  }
};

// ============================================================================
// IdentitySmsSender - sends SMS verification codes
// Handles: phone number verification via SMS (Twilio/Vonage integration)
// Equivalent to synapse.handlers.identity.IdentityHandler SMS methods
// ============================================================================
class IdentitySmsSender {
public:
  struct SmsConfig {
    std::string provider;          // "twilio", "vonage", "mock"
    std::string account_sid;
    std::string auth_token;
    std::string from_number;       // sender phone number / alphanumeric ID
    int max_length{160};
    bool enabled{true};
    std::string api_endpoint;
  };

  struct SmsSendResult {
    bool success{false};
    std::string message_sid;
    std::string error;
    int status_code{0};
    double cost{0.0};
  };

  IdentitySmsSender() {
    // Default to mock provider for development
    config_.provider = "mock";
    config_.from_number = "Matrix";
    config_.enabled = true;
  }

  explicit IdentitySmsSender(const SmsConfig& config) : config_(config) {}

  void set_config(const SmsConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
  }

  SmsConfig get_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
  }

  // Send verification code via SMS
  SmsSendResult send_verification_sms(
      const std::string& phone_number,
      const std::string& token,
      const std::string& client_secret,
      const std::string& sid) {

    std::string message = "Your Matrix verification code is: " + token +
                          "\n\nSession: " + sid.substr(0, 8);

    if (message.size() > static_cast<size_t>(config_.max_length)) {
      // Truncate with care
      message = "Matrix code: " + token + ". SID: " + sid.substr(0, 6);
    }

    return send_sms(phone_number, message);
  }

  // Send a custom SMS notification
  SmsSendResult send_notification_sms(
      const std::string& phone_number,
      const std::string& message) {

    if (message.size() > static_cast<size_t>(config_.max_length)) {
      return {false, "", "Message exceeds max length", 400, 0.0};
    }
    return send_sms(phone_number, message);
  }

  // Check SMS rate limiting
  bool check_rate_limit(const std::string& phone_number) {
    std::lock_guard<std::mutex> lock(ratelimit_mutex_);
    std::string key = phone_number;
    int64_t now = now_ms();

    auto& entries = rate_limit_map_[key];
    entries.erase(
        std::remove_if(entries.begin(), entries.end(),
                       [now](int64_t ts) { return now - ts > kSmsRateWindowMs; }),
        entries.end());

    if (entries.size() >= kMaxSmsPerWindow) return false;
    return true;
  }

  void record_send(const std::string& phone_number) {
    std::lock_guard<std::mutex> lock(ratelimit_mutex_);
    rate_limit_map_[phone_number].push_back(now_ms());
  }

  // Validate phone number format
  static bool validate_phone(const std::string& phone) {
    return valid_msisdn(phone);
  }

  // Get send statistics
  json get_stats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return json{
        {"total_sent", total_sent_.load()},
        {"total_failed", total_failed_.load()},
        {"last_send_at_ms", last_send_at_ms_.load()},
        {"total_cost", total_cost_.load()}
    };
  }

private:
  mutable std::mutex config_mutex_;
  SmsConfig config_;
  std::atomic<int64_t> total_sent_{0};
  std::atomic<int64_t> total_failed_{0};
  std::atomic<int64_t> last_send_at_ms_{0};
  std::atomic<double> total_cost_{0.0};
  std::mutex stats_mutex_;
  std::mutex ratelimit_mutex_;
  std::unordered_map<std::string, std::vector<int64_t>> rate_limit_map_;

  static constexpr int64_t kSmsRateWindowMs = 60 * 60 * 1000; // 1 hour
  static constexpr size_t kMaxSmsPerWindow = 5;

  SmsSendResult send_sms(const std::string& phone_number,
                          const std::string& message) {

    SmsSendResult result;

    if (!config_.enabled) {
      result.error = "SMS sending is disabled";
      total_failed_++;
      return result;
    }

    if (!check_rate_limit(phone_number)) {
      result.error = "Rate limit exceeded for phone: " + phone_number;
      total_failed_++;
      return result;
    }

    record_send(phone_number);

    if (config_.provider == "mock") {
      // Mock provider: simulate successful send
      result.success = true;
      result.message_sid = "MOCK_" + generate_token(16);
      result.status_code = 200;
      result.cost = 0.0075; // Typical SMS cost

      total_sent_++;
      total_cost_.fetch_add(result.cost);
      last_send_at_ms_ = now_ms();
      return result;
    }

    if (config_.provider == "twilio") {
      // In production, this would use libcurl to call the Twilio API.
      // POST https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json
      // For the massive handler, we simulate the API call flow.

      // Validate required config
      if (config_.account_sid.empty() || config_.auth_token.empty()) {
        result.error = "Twilio credentials not configured";
        total_failed_++;
        return result;
      }

      // Simulate API call
      result.success = true;
      result.message_sid = "SM" + generate_token(32);
      result.status_code = 201;
      result.cost = 0.0075;

      total_sent_++;
      total_cost_.fetch_add(result.cost);
      last_send_at_ms_ = now_ms();
      return result;
    }

    if (config_.provider == "vonage") {
      // In production, this would use libcurl to call the Vonage API.
      // POST https://rest.nexmo.com/sms/json

      if (config_.account_sid.empty() || config_.auth_token.empty()) {
        result.error = "Vonage credentials not configured";
        total_failed_++;
        return result;
      }

      result.success = true;
      result.message_sid = "VN" + generate_token(32);
      result.status_code = 200;
      result.cost = 0.0062;

      total_sent_++;
      total_cost_.fetch_add(result.cost);
      last_send_at_ms_ = now_ms();
      return result;
    }

    result.error = "Unknown SMS provider: " + config_.provider;
    total_failed_++;
    return result;
  }
};

// ============================================================================
// IdentitySessionKeyManager - session key creation, validation, resend, expiry
// Handles: creating session keys for API access, validating, rotating
// Equivalent to identity server session key management
// ============================================================================
class IdentitySessionKeyManager {
public:
  struct SessionKey {
    std::string key_id;
    std::string key_value;       // the private key (Ed25519 seed)
    std::string public_key;      // base64-encoded public key
    int64_t created_at_ms{0};
    int64_t expires_at_ms{0};
    int64_t rotated_at_ms{0};
    bool active{true};
    bool is_ephemeral{false};
    std::string algorithm{"ed25519"};
    json signatures;             // signatures from other keys
  };

  struct SignedKeyResponse {
    std::string public_key;
    std::string key_id;
    int64_t valid_until_ts{0};
    json signatures;
  };

  IdentitySessionKeyManager() {
    // Generate initial server key
    generate_key_pair("ed25519", false);
  }

  ~IdentitySessionKeyManager() {
    cleaner_running_ = false;
    if (cleaner_thread_.joinable()) cleaner_thread_.join();
  }

  // Generate a new key pair
  SessionKey generate_key_pair(const std::string& algorithm = "ed25519",
                                bool ephemeral = false) {
    SessionKey key;
    key.key_id = "ed25519:" + generate_token(8);
    key.key_value = generate_token(64);       // seed for key derivation
    key.public_key = generate_token(43);      // base64-like public key
    key.created_at_ms = now_ms();
    key.expires_at_ms = now_ms() + kDefaultKeyTTLMs;
    key.rotated_at_ms = 0;
    key.active = true;
    key.is_ephemeral = ephemeral;
    key.algorithm = algorithm;

    // Self-sign the key
    json self_sig;
    self_sig[key.key_id] = sign_json(
        json{{"key_id", key.key_id}, {"public_key", key.public_key}},
        key.key_value);
    key.signatures = self_sig;

    std::lock_guard<std::shared_mutex> lock(mutex_);
    keys_[key.key_id] = key;

    // Add to active keys list
    active_key_ids_.push_back(key.key_id);
    if (active_key_ids_.size() > kMaxActiveKeys) {
      // Rotate out oldest key
      std::string oldest = active_key_ids_.front();
      active_key_ids_.erase(active_key_ids_.begin());
      auto it = keys_.find(oldest);
      if (it != keys_.end()) {
        it->second.active = false;
        it->second.rotated_at_ms = now_ms();
      }
    }

    return key;
  }

  // Get a specific key by ID
  std::optional<SessionKey> get_key(const std::string& key_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = keys_.find(key_id);
    if (it != keys_.end()) return it->second;
    return std::nullopt;
  }

  // Get all active public keys
  json get_public_keys() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json result = json::object();
    for (const auto& [key_id, key] : keys_) {
      if (!key.active) continue;
      if (key.expires_at_ms < now_ms()) continue;

      json key_json;
      key_json["key"] = key.public_key;
      key_json["expires_ts"] = key.expires_at_ms;
      if (!key.signatures.empty()) {
        key_json["signatures"] = key.signatures;
      }
      result[key_id] = key_json;
    }
    return result;
  }

  // Get a specific public key response for /pubkey/{keyId}
  std::optional<SignedKeyResponse> get_public_key_response(
      const std::string& key_id) {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = keys_.find(key_id);
    if (it == keys_.end()) return std::nullopt;

    const auto& key = it->second;
    if (key.expires_at_ms < now_ms() && !key.is_ephemeral) return std::nullopt;

    SignedKeyResponse resp;
    resp.public_key = key.public_key;
    resp.key_id = key.key_id;
    resp.valid_until_ts = key.expires_at_ms / 1000;
    resp.signatures = key.signatures;
    return resp;
  }

  // Get the public key for the /_matrix/identity/v2 response
  json get_v2_public_key() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json result = json::object();
    for (const auto& [key_id, key] : keys_) {
      if (!key.active) continue;
      if (key.is_ephemeral) continue;
      if (key.expires_at_ms < now_ms()) continue;
      if (result.empty()) {
        // Return the first (most recent) valid non-ephemeral key
        result["public_key"] = key.public_key;
        result["key_validity_url"] =
            "/_matrix/identity/v2/pubkey/" + key.key_id;
        result["key_validity_url_sha256"] =
            sha256_hex(key.public_key);
        break;
      }
    }
    return result;
  }

  // Sign data with a key
  std::optional<std::string> sign_data(const std::string& key_id,
                                        const std::string& data) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = keys_.find(key_id);
    if (it == keys_.end() || !it->second.active) return std::nullopt;
    return hmac_sha256_hex(it->second.key_value, data);
  }

  // Verify a signature
  bool verify_signature(const std::string& key_id,
                         const std::string& data,
                         const std::string& signature) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = keys_.find(key_id);
    if (it == keys_.end()) return false;
    std::string expected = hmac_sha256_hex(it->second.key_value, data);
    return expected == signature;
  }

  // Rotate keys - deactivate old, create new
  SessionKey rotate_keys() {
    auto new_key = generate_key_pair("ed25519", false);

    // Cross-sign: sign the new key with old active keys
    std::lock_guard<std::shared_mutex> lock(mutex_);
    for (const auto& kid : active_key_ids_) {
      if (kid == new_key.key_id) continue;
      auto old_it = keys_.find(kid);
      if (old_it != keys_.end() && old_it->second.active) {
        json sig_data;
        sig_data["new_key_id"] = new_key.key_id;
        sig_data["new_public_key"] = new_key.public_key;
        new_key.signatures[kid] =
            hmac_sha256_hex(old_it->second.key_value, sig_data.dump());
      }
    }
    keys_[new_key.key_id] = new_key;
    return new_key;
  }

  // Check if a key is valid
  bool is_key_valid(const std::string& key_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = keys_.find(key_id);
    if (it == keys_.end()) return false;
    return it->second.active && it->second.expires_at_ms > now_ms();
  }

  // Get key stats
  json get_key_stats() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    int64_t now = now_ms();
    size_t total = keys_.size();
    size_t active = 0, expired = 0, ephemeral = 0;
    for (const auto& [id, key] : keys_) {
      if (key.active && key.expires_at_ms > now) active++;
      if (key.expires_at_ms <= now) expired++;
      if (key.is_ephemeral) ephemeral++;
    }
    return json{
        {"total_keys", total},
        {"active_keys", active},
        {"expired_keys", expired},
        {"ephemeral_keys", ephemeral},
        {"max_active_keys", kMaxActiveKeys},
        {"default_ttl_ms", kDefaultKeyTTLMs}
    };
  }

  // Delete a key
  bool delete_key(const std::string& key_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = keys_.find(key_id);
    if (it != keys_.end()) {
      it->second.active = false;
      it->second.expires_at_ms = 0; // expire immediately
      return true;
    }
    return false;
  }

private:
  static constexpr int64_t kDefaultKeyTTLMs = 7 * 24 * 60 * 60 * 1000LL; // 7 days
  static constexpr size_t kMaxActiveKeys = 10;

  std::shared_mutex mutex_;
  std::unordered_map<std::string, SessionKey> keys_;
  std::vector<std::string> active_key_ids_;

  std::atomic<bool> cleaner_running_{true};
  std::thread cleaner_thread_{[this]() {
    while (cleaner_running_) {
      std::this_thread::sleep_for(chr::seconds(3600)); // hourly
      std::lock_guard<std::shared_mutex> lock(mutex_);
      int64_t now = now_ms();
      for (auto& [id, key] : keys_) {
        if (key.active && now > key.expires_at_ms && !key.is_ephemeral) {
          key.active = false;
          key.rotated_at_ms = now;
        }
      }
      // Clean up old inactive keys (keep last 100)
      std::vector<std::string> to_remove;
      int inactive_count = 0;
      for (const auto& [id, key] : keys_) {
        if (!key.active) inactive_count++;
      }
      if (inactive_count > 100) {
        size_t to_remove_count = inactive_count - 100;
        for (auto it = keys_.begin();
             it != keys_.end() && to_remove.size() < to_remove_count; ++it) {
          if (!it->second.active) to_remove.push_back(it->first);
        }
        for (const auto& id : to_remove) keys_.erase(id);
      }
    }
  }};
};

// ============================================================================
// IdentityPublicKeyManager - public key publishing for identity server
// Handles: GET /_matrix/identity/v2/pubkey/{keyId}
// Equivalent to synapse.crypto.keyring + identity server pubkey endpoint
// ============================================================================
class IdentityPublicKeyManager {
public:
  struct PublishedKey {
    std::string key_id;
    std::string algorithm;       // "ed25519", "curve25519"
    std::string public_key_b64;  // base64-encoded public key
    std::string server_name;     // origin server name
    int64_t valid_until_ts{0};
    int64_t published_at_ms{0};
    bool is_self_signed{true};
    std::string signing_key_id;
    std::string signature;
    json metadata;               // any additional metadata
  };

  struct KeyQueryResponse {
    std::string server_name;
    std::map<std::string, json> verify_keys;
    int64_t valid_until_ts{0};
    json old_verify_keys;
    json signatures;
  };

  IdentityPublicKeyManager(const std::string& server_name)
      : server_name_(server_name) {}

  // Publish a new public key
  PublishedKey publish_key(
      const std::string& key_id,
      const std::string& algorithm,
      const std::string& public_key_b64,
      int64_t valid_until_ts = 0,
      const json& metadata = json::object()) {

    PublishedKey key;
    key.key_id = key_id;
    key.algorithm = algorithm;
    key.public_key_b64 = public_key_b64;
    key.server_name = server_name_;
    key.valid_until_ts = valid_until_ts > 0 ? valid_until_ts
                         : (now_ms() / 1000) + kDefaultValiditySec;
    key.published_at_ms = now_ms();
    key.metadata = metadata;

    std::lock_guard<std::shared_mutex> lock(mutex_);
    published_keys_[key_id] = key;
    return key;
  }

  // Get a specific published key by ID
  std::optional<PublishedKey> get_key(const std::string& key_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = published_keys_.find(key_id);
    if (it != published_keys_.end()) return it->second;
    return std::nullopt;
  }

  // Get the public key response for the IS pubkey endpoint
  json get_pubkey_response(const std::string& key_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = published_keys_.find(key_id);
    if (it == published_keys_.end()) {
      return json::object();
    }

    const auto& key = it->second;
    int64_t now_ts = now_ms() / 1000;
    if (now_ts > key.valid_until_ts) {
      return json{{"error", "Key expired"}};
    }

    return json{
        {"key", key.public_key_b64},
        {"algorithm", key.algorithm},
        {"valid_until_ts", key.valid_until_ts},
        {"server_name", key.server_name},
        {"signatures", key.signature.empty() ?
            json::object() :
            json{{key.signing_key_id, key.signature}}
        },
        {"metadata", key.metadata}
    };
  }

  // Get all published keys for this server
  json get_all_published_keys() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    int64_t now_ts = now_ms() / 1000;
    json result = json::object();
    for (const auto& [key_id, key] : published_keys_) {
      if (now_ts <= key.valid_until_ts) {
        result[key_id] = json{
            {"key", key.public_key_b64},
            {"algorithm", key.algorithm},
            {"valid_until_ts", key.valid_until_ts},
            {"signatures", key.signature.empty() ?
                json::object() :
                json{{key.signing_key_id, key.signature}}
            }
        };
      }
    }
    return result;
  }

  // Build a full key query response (for server key queries)
  KeyQueryResponse build_server_key_response() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    int64_t now_ts = now_ms() / 1000;
    KeyQueryResponse resp;
    resp.server_name = server_name_;
    resp.valid_until_ts = now_ts + kDefaultValiditySec;

    int64_t max_valid = 0;
    for (const auto& [key_id, key] : published_keys_) {
      if (now_ts <= key.valid_until_ts) {
        resp.verify_keys[key_id] = json{
            {"key", key.public_key_b64}
        };
        if (key.valid_until_ts > max_valid) {
          max_valid = key.valid_until_ts;
        }
      }
    }
    if (max_valid > 0) resp.valid_until_ts = max_valid;

    // Collect old (expired) keys
    json old_keys = json::object();
    for (const auto& [key_id, key] : published_keys_) {
      if (now_ts > key.valid_until_ts && key.valid_until_ts >
          now_ts - kKeepOldKeysForSec) {
        old_keys[key_id] = json{
            {"key", key.public_key_b64},
            {"expired_ts", key.valid_until_ts}
        };
      }
    }
    resp.old_verify_keys = old_keys;

    return resp;
  }

  // Sign a key with another key (cross-signing)
  void sign_key(const std::string& key_id,
                const std::string& signing_key_id,
                const std::string& signature) {

    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = published_keys_.find(key_id);
    if (it != published_keys_.end()) {
      it->second.signing_key_id = signing_key_id;
      it->second.signature = signature;
      it->second.is_self_signed = (key_id == signing_key_id);
    }
  }

  // Revoke a key
  bool revoke_key(const std::string& key_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = published_keys_.find(key_id);
    if (it != published_keys_.end()) {
      it->second.valid_until_ts = 0; // expired immediately
      return true;
    }
    return false;
  }

  // Check if a key is valid
  bool is_key_valid(const std::string& key_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = published_keys_.find(key_id);
    if (it == published_keys_.end()) return false;
    return (now_ms() / 1000) <= it->second.valid_until_ts;
  }

  // Verify that we have a key from a specific server
  bool has_server_key(const std::string& server_name,
                       const std::string& key_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = published_keys_.find(key_id);
    if (it == published_keys_.end()) return false;
    return it->second.server_name == server_name;
  }

  // Get the server name
  std::string get_server_name() const { return server_name_; }

  // Set server name (for dynamic configuration)
  void set_server_name(const std::string& name) { server_name_ = name; }

  // Get key stats
  json get_stats() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    int64_t now_ts = now_ms() / 1000;
    size_t total = published_keys_.size();
    size_t valid = 0, expired = 0, self_signed = 0;
    for (const auto& [id, key] : published_keys_) {
      if (now_ts <= key.valid_until_ts) valid++;
      else expired++;
      if (key.is_self_signed) self_signed++;
    }
    return json{
        {"total_keys", total},
        {"valid_keys", valid},
        {"expired_keys", expired},
        {"self_signed_keys", self_signed},
        {"server_name", server_name_},
        {"default_validity_sec", kDefaultValiditySec}
    };
  }

private:
  static constexpr int64_t kDefaultValiditySec = 86400;         // 24 hours
  static constexpr int64_t kKeepOldKeysForSec = 7 * 86400;      // 7 days

  std::string server_name_;
  std::shared_mutex mutex_;
  std::unordered_map<std::string, PublishedKey> published_keys_;
};

// ============================================================================
// IdentityServer - top-level identity server coordinating all subsystems
// ============================================================================
class IdentityServer {
public:
  struct IdentityConfig {
    std::string server_name{"localhost:8090"};
    std::string pepper;                     // pepper for hash lookups
    bool enable_v1_api{true};
    bool enable_v2_api{true};
    bool enable_email{true};
    bool enable_sms{false};
    int session_ttl_minutes{30};
    int invite_ttl_days{7};
    int rate_limit_per_15min{10};
    std::string trusted_id_servers;         // comma-separated
  };

  IdentityServer() : pubkey_manager_("localhost") {}

  explicit IdentityServer(const IdentityConfig& config)
      : config_(config),
        binder_(config.pepper),
        pubkey_manager_(config.server_name) {}

  void set_config(const IdentityConfig& config) {
    config_ = config;
    binder_.set_pepper(config.pepper);
    pubkey_manager_.set_server_name(config.server_name);
    email_sender_.set_config(IdentityEmailSender::EmailConfig{});
  }

  IdentityConfig get_config() const { return config_; }

  // Access subsystems
  IdentitySessionManager& sessions() { return session_manager_; }
  IdentityThreepidBinder& binder() { return binder_; }
  IdentityStoreInviteManager& invites() { return invite_manager_; }
  IdentityTermsManager& terms() { return terms_manager_; }
  IdentityEmailSender& email() { return email_sender_; }
  IdentitySmsSender& sms() { return sms_sender_; }
  IdentitySessionKeyManager& session_keys() { return session_key_manager_; }
  IdentityPublicKeyManager& pubkeys() { return pubkey_manager_; }

  // Centralized request handling

  // POST /validate/email/requestToken
  json handle_email_request_token(const json& body, const std::string& ip) {
    std::string email = body.value("email", "");
    std::string client_secret = body.value("client_secret", "");
    int send_attempt = body.value("send_attempt", 0);
    std::string next_link = body.value("next_link", "");
    std::string id_server = body.value("id_server", "");
    std::string id_access_token = body.value("id_access_token", "");

    if (!valid_email(email)) {
      return json{{"errcode", "M_INVALID_PARAM"}, {"error", "Invalid email"}};
    }
    if (client_secret.empty()) {
      return json{{"errcode", "M_MISSING_PARAM"}, {"error", "Missing client_secret"}};
    }

    if (!session_manager_.check_rate_limit("email", email)) {
      return json{{"errcode", "M_LIMIT_EXCEEDED"},
                  {"error", "Rate limit exceeded"}};
    }

    auto session = session_manager_.create_session(
        "email", email, client_secret, send_attempt,
        next_link.empty() ? std::nullopt : std::optional<std::string>(next_link),
        ip,
        id_server.empty() ? std::nullopt : std::optional<std::string>(id_server),
        id_access_token.empty() ? std::nullopt
                                : std::optional<std::string>(id_access_token));

    // Send email if enabled
    if (config_.enable_email) {
      std::optional<std::string> nl =
          next_link.empty() ? std::nullopt : std::optional<std::string>(next_link);
      auto result = email_sender_.send_verification_email(
          email, session.token, client_secret, session.sid, nl);
      if (result.success) {
        session_manager_.mark_sent(session.sid);
      }
    }

    json response;
    response["sid"] = session.sid;
    response["submit_url"] = "";
    return response;
  }

  // POST /validate/msisdn/requestToken
  json handle_msisdn_request_token(const json& body, const std::string& ip) {
    std::string phone = body.value("phone_number", "");
    if (phone.empty()) phone = body.value("msisdn", "");
    std::string country = body.value("country", "");
    std::string client_secret = body.value("client_secret", "");
    int send_attempt = body.value("send_attempt", 0);
    std::string next_link = body.value("next_link", "");
    std::string id_server = body.value("id_server", "");

    // Normalize phone number
    std::string normalized = phone;
    if (!country.empty() && !starts_with(phone, "+")) {
      normalized = country + phone;
    }

    if (!valid_msisdn(normalized)) {
      return json{{"errcode", "M_INVALID_PARAM"},
                  {"error", "Invalid phone number"}};
    }
    if (client_secret.empty()) {
      return json{{"errcode", "M_MISSING_PARAM"}, {"error", "Missing client_secret"}};
    }

    if (!session_manager_.check_rate_limit("msisdn", normalized)) {
      return json{{"errcode", "M_LIMIT_EXCEEDED"},
                  {"error", "Rate limit exceeded"}};
    }

    auto session = session_manager_.create_session(
        "msisdn", normalized, client_secret, send_attempt,
        next_link.empty() ? std::nullopt : std::optional<std::string>(next_link),
        ip,
        id_server.empty() ? std::nullopt : std::optional<std::string>(id_server));

    // Send SMS if enabled
    if (config_.enable_sms) {
      auto result = sms_sender_.send_verification_sms(
          normalized, session.token, client_secret, session.sid);
      if (result.success) {
        session_manager_.mark_sent(session.sid);
      }
    }

    json response;
    response["sid"] = session.sid;
    if (config_.enable_sms) {
      response["msisdn"] = normalized;
    }
    return response;
  }

  // GET /validate/email/submitToken
  json handle_email_submit_token(const std::string& sid,
                                  const std::string& client_secret,
                                  const std::string& token) {
    if (sid.empty() || client_secret.empty() || token.empty()) {
      return json{{"errcode", "M_MISSING_PARAM"},
                  {"error", "Missing required parameters"}};
    }

    auto result = session_manager_.validate_token(sid, client_secret, token);
    if (!result.success) {
      if (result.error == "Session expired") {
        return json{{"errcode", "M_SESSION_EXPIRED"}, {"error", result.error}};
      }
      if (result.error == "Token mismatch" || result.error == "Client secret mismatch") {
        return json{{"errcode", "M_INVALID_TOKEN"}, {"error", result.error}};
      }
      return json{{"errcode", "M_UNKNOWN"}, {"error", result.error}};
    }

    json response;
    response["success"] = true;
    response["medium"] = "email";
    response["address"] = result.session.address;
    response["validated_at"] = result.session.validated_at_ms / 1000;
    if (!result.session.next_link.empty()) {
      response["next_link"] = result.session.next_link;
    }
    return response;
  }

  // GET /validate/msisdn/submitToken
  json handle_msisdn_submit_token(const std::string& sid,
                                   const std::string& client_secret,
                                   const std::string& token) {
    if (sid.empty() || client_secret.empty() || token.empty()) {
      return json{{"errcode", "M_MISSING_PARAM"},
                  {"error", "Missing required parameters"}};
    }

    auto result = session_manager_.validate_token(sid, client_secret, token);
    if (!result.success) {
      if (result.error == "Session expired") {
        return json{{"errcode", "M_SESSION_EXPIRED"}, {"error", result.error}};
      }
      if (result.error == "Token mismatch" || result.error == "Client secret mismatch") {
        return json{{"errcode", "M_INVALID_TOKEN"}, {"error", result.error}};
      }
      return json{{"errcode", "M_UNKNOWN"}, {"error", result.error}};
    }

    json response;
    response["success"] = true;
    response["medium"] = "msisdn";
    response["address"] = result.session.address;
    response["validated_at"] = result.session.validated_at_ms / 1000;
    if (!result.session.next_link.empty()) {
      response["next_link"] = result.session.next_link;
    }
    return response;
  }

  // POST /bind
  json handle_bind(const json& body) {
    std::string medium = body.value("medium", "");
    std::string address = body.value("address", "");
    std::string mxid = body.value("mxid", "");

    if (medium.empty() || address.empty() || mxid.empty()) {
      return json{{"errcode", "M_MISSING_PARAM"},
                  {"error", "Missing medium, address, or mxid"}};
    }

    if (!valid_matrix_id(mxid)) {
      return json{{"errcode", "M_INVALID_PARAM"}, {"error", "Invalid Matrix ID"}};
    }

    if (medium != "email" && medium != "msisdn") {
      return json{{"errcode", "M_INVALID_PARAM"},
                  {"error", "Medium must be 'email' or 'msisdn'"}};
    }

    // Optionally verify the session
    if (body.contains("sid") && body.contains("client_secret")) {
      std::string sid = body.value("sid", "");
      std::string client_secret = body.value("client_secret", "");
      auto session = session_manager_.get_session(sid);
      if (!session.has_value()) {
        return json{{"errcode", "M_SESSION_NOT_FOUND"},
                    {"error", "Session not found"}};
      }
      if (!session->validated) {
        return json{{"errcode", "M_SESSION_NOT_VALIDATED"},
                    {"error", "Session not yet validated"}};
      }
      if (session->client_secret != client_secret) {
        return json{{"errcode", "M_INVALID_PARAM"},
                    {"error", "Client secret mismatch"}};
      }
    }

    auto binding = binder_.bind_threepid(medium, address, mxid,
                                          config_.server_name);

    json response;
    response["medium"] = binding.medium;
    response["address"] = binding.address;
    response["mxid"] = binding.mxid;
    response["bound_at"] = binding.bound_at_ms / 1000;
    return response;
  }

  // GET /lookup - privacy-preserving lookup
  json handle_lookup_hash(const json& body) {
    // Expects: {"hashes": {"medium": ["hash1", "hash2", ...], ...}}
    // Or legacy: {"addresses": ["email@example.com", ...], "medium": "email"}

    std::vector<std::pair<std::string, std::string>> queries;

    if (body.contains("hashes")) {
      const auto& hashes = body["hashes"];
      for (auto it = hashes.begin(); it != hashes.end(); ++it) {
        std::string medium = it.key();
        const auto& addr_hashes = it.value();
        if (addr_hashes.is_array()) {
          for (const auto& h : addr_hashes) {
            queries.emplace_back(medium, h.get<std::string>());
          }
        }
      }
    } else if (body.contains("addresses") && body.contains("medium")) {
      // Legacy single-medium lookup: hash each address
      std::string medium = body.value("medium", "");
      const auto& addresses = body["addresses"];
      if (addresses.is_array()) {
        for (const auto& addr : addresses) {
          std::string hashed = binder_.hash_address(medium, addr.get<std::string>());
          queries.emplace_back(medium, hashed);
        }
      }
    } else {
      return json{{"errcode", "M_MISSING_PARAM"},
                  {"error", "Missing hashes or addresses"}};
    }

    auto results = binder_.lookup_by_hash(queries);

    json response;
    response["mappings"] = json::array();
    for (const auto& r : results) {
      response["mappings"].push_back(r);
    }
    return response;
  }

  // POST /unbind
  json handle_unbind(const json& body) {
    std::string medium = body.value("medium", "");
    std::string address = body.value("address", "");
    std::string mxid = body.value("mxid", "");

    if (medium.empty() || address.empty() || mxid.empty()) {
      return json{{"errcode", "M_MISSING_PARAM"},
                  {"error", "Missing medium, address, or mxid"}};
    }

    bool success = binder_.unbind_threepid(medium, address, mxid);
    if (!success) {
      return json{{"errcode", "M_NOT_FOUND"},
                  {"error", "Binding not found"}};
    }

    return json{{"success", true}};
  }

  // POST /store-invite
  json handle_store_invite(const json& body) {
    std::string medium = body.value("medium", "");
    std::string address = body.value("address", "");
    std::string room_id = body.value("room_id", "");
    std::string sender = body.value("sender", "");
    std::string token = body.value("token", generate_token(32));
    std::string room_name = body.value("room_name", "");
    std::string room_type = body.value("room_type", "m.room");
    json public_keys = body.value("public_keys", json::object());

    if (medium.empty() || address.empty() || room_id.empty() || sender.empty()) {
      return json{{"errcode", "M_MISSING_PARAM"},
                  {"error", "Missing required parameters"}};
    }

    if (medium != "email" && medium != "msisdn") {
      return json{{"errcode", "M_INVALID_PARAM"},
                  {"error", "Medium must be 'email' or 'msisdn'"}};
    }

    auto invite = invite_manager_.store_invite(
        medium, address, room_id, sender, token,
        room_name.empty() ? std::nullopt : std::optional<std::string>(room_name),
        room_type.empty() ? std::nullopt : std::optional<std::string>(room_type),
        public_keys);

    // Send invitation notification
    if (config_.enable_email && medium == "email") {
      std::string join_url = "https://matrix.to/#/" + room_id + "?via=" +
                             config_.server_name;
      std::string subject = sender + " has invited you to \"" +
                            (room_name.empty() ? room_id : room_name) + "\"";
      std::string body = "Hello,\n\n" + sender + " has invited you to join "
                         "\"" + (room_name.empty() ? room_id : room_name) + "\" "
                         "on Matrix.\n\nTo accept, click: " + join_url +
                         "\n\nRoom ID: " + room_id +
                         "\nInvite Token: " + token + "\n";

      email_sender_.send_custom_email(address, subject, body, body);
    }

    if (config_.enable_sms && medium == "msisdn") {
      std::string msg = sender + " invited you to \"" +
                        (room_name.empty() ? room_id : room_name) + "\". "
                        "Room: " + room_id;
      sms_sender_.send_notification_sms(address, msg);
    }

    json response;
    response["invite_id"] = invite.invite_id;
    response["token"] = invite.token;
    response["public_keys"] = json::array();
    for (auto& [pubkey_id, pubkey_val] : invite.stored_public_keys.items()) {
      response["public_keys"].push_back(
          json{{"public_key", pubkey_val}, {"key_id", pubkey_id}});
    }
    response["display_name"] = sender;
    return response;
  }

  // GET /terms - list policies
  json handle_get_terms(const std::string& language = "") {
    return terms_.get_policies(language);
  }

  // POST /terms - accept policies
  json handle_accept_terms(const json& body, const std::string& ip) {
    // Body: {"user_accepts": ["policy_id_version_hash", ...]}
    // Or: {"accepted": ["policy_id", ...]}
    std::string user_id = body.value("user_id", body.value("mxid", ""));
    std::vector<std::string> accepted;

    if (body.contains("user_accepts") && body["user_accepts"].is_array()) {
      for (const auto& item : body["user_accepts"]) {
        accepted.push_back(item.get<std::string>());
      }
    } else if (body.contains("accepted") && body["accepted"].is_array()) {
      for (const auto& item : body["accepted"]) {
        accepted.push_back(item.get<std::string>());
      }
    }

    if (user_id.empty() || accepted.empty()) {
      return json{{"errcode", "M_MISSING_PARAM"},
                  {"error", "Missing user_id or accepted policies"}};
    }

    json results = json::array();
    for (const auto& policy_ref : accepted) {
      // policy_ref format: "policy_id/version/language" or just "policy_id"
      std::string policy_id = policy_ref;
      std::string version = "1.0";
      std::string language = "en";

      // Try to parse the format
      size_t slash1 = policy_ref.find('/');
      if (slash1 != std::string::npos) {
        policy_id = policy_ref.substr(0, slash1);
        size_t slash2 = policy_ref.find('/', slash1 + 1);
        if (slash2 != std::string::npos) {
          version = policy_ref.substr(slash1 + 1, slash2 - slash1 - 1);
          language = policy_ref.substr(slash2 + 1);
        } else {
          version = policy_ref.substr(slash1 + 1);
        }
      }

      auto record = terms_.accept_policy(user_id, policy_id, version, ip);
      results.push_back(json{
          {"policy_id", record.policy_id},
          {"version", record.policy_version},
          {"accepted_at", record.accepted_at_ms / 1000}
      });
    }

    return json{{"accepted", results}};
  }

  // GET /_matrix/identity/api/v1
  json handle_v1_api() {
    json response;
    response["version"] = "1.0";
    response["endpoints"] = json::array({
        "/_matrix/identity/api/v1",
        "/_matrix/identity/v2",
        "/_matrix/identity/v2/pubkey",
        "/validate/email/requestToken",
        "/validate/email/submitToken",
        "/validate/msisdn/requestToken",
        "/validate/msisdn/submitToken",
        "/bind",
        "/lookup",
        "/unbind",
        "/store-invite",
        "/terms"
    });
    response["server"] = config_.server_name;
    return response;
  }

  // GET /_matrix/identity/v2
  json handle_v2_api() {
    json response;
    response["version"] = "2.0";
    // Include the server's public key
    auto pubkey = session_key_manager_.get_v2_public_key();
    for (auto it = pubkey.begin(); it != pubkey.end(); ++it) {
      response[it.key()] = it.value();
    }
    return response;
  }

  // GET /_matrix/identity/v2/pubkey/{keyId}
  json handle_pubkey(const std::string& key_id) {
    // First check the session key manager
    auto key_resp = session_key_manager_.get_public_key_response(key_id);
    if (key_resp.has_value()) {
      json response;
      response["public_key"] = key_resp->public_key;
      response["key_id"] = key_resp->key_id;
      response["valid_until_ts"] = key_resp->valid_until_ts;
      if (!key_resp->signatures.empty()) {
        response["signatures"] = key_resp->signatures;
      }
      return response;
    }

    // Also check the public key manager
    auto pubkey = pubkey_manager_.get_pubkey_response(key_id);
    if (!pubkey.empty()) return pubkey;

    return json{{"errcode", "M_NOT_FOUND"}, {"error", "Key not found"}};
  }

  // GET /_matrix/identity/v2/pubkey (list all keys)
  json handle_pubkey_list() {
    return session_key_manager_.get_public_keys();
  }

  // Get overall server stats
  json get_server_stats() {
    return json{
        {"sessions", session_manager_.session_count()},
        {"bindings", binder_.binding_count()},
        {"invites", invite_manager_.invite_count()},
        {"pending_invites", invite_manager_.pending_invite_count()},
        {"email_stats", email_sender_.get_stats()},
        {"sms_stats", sms_sender_.get_stats()},
        {"key_stats", session_key_manager_.get_key_stats()},
        {"pubkey_stats", pubkey_manager_.get_stats()},
        {"invite_stats", invite_manager_.get_stats()}
    };
  }

  // Resend a validation token
  json handle_resend_token(const std::string& sid) {
    auto session = session_manager_.resend_token(sid);
    if (!session.has_value()) {
      return json{{"errcode", "M_SESSION_NOT_FOUND"},
                  {"error", "Session not found or expired"}};
    }

    // Resend via appropriate medium
    if (session->medium == "email" && config_.enable_email) {
      email_sender_.send_verification_email(
          session->address, session->token, session->client_secret, session->sid);
    } else if (session->medium == "msisdn" && config_.enable_sms) {
      sms_sender_.send_verification_sms(
          session->address, session->token, session->client_secret, session->sid);
    }

    json response;
    response["sid"] = session->sid;
    response["success"] = true;
    return response;
  }

private:
  IdentityConfig config_;
  IdentitySessionManager session_manager_;
  IdentityThreepidBinder binder_;
  IdentityStoreInviteManager invite_manager_;
  IdentityTermsManager terms_manager_;
  IdentityEmailSender email_sender_;
  IdentitySmsSender sms_sender_;
  IdentitySessionKeyManager session_key_manager_;
  IdentityPublicKeyManager pubkey_manager_;
};

// ============================================================================
// Identity REST Servlets - pluggable into the existing REST framework
// ============================================================================

// --- ValidateEmailRequestTokenServlet ---
class ValidateEmailRequestTokenServlet : public rest::BaseRestServlet {
public:
  explicit ValidateEmailRequestTokenServlet(IdentityServer& server)
      : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {
      R"(^/validate/email/requestToken$)",
      R"(^/validate/email/request_token$)"
    };
  }

  std::vector<std::string> methods() const override {
    return {"POST", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      rest::HttpResponse resp;
      resp.code = 200;
      resp.body = json::object();
      return resp;
    }

    try {
      json body = json::parse(req.body.empty() ? "{}" : req.body);
      json result = server_.handle_email_request_token(body, req.client_ip);
      if (result.contains("errcode")) {
        return rest::BaseRestServlet::error_response(
            400, result["errcode"], result["error"]);
      }
      return rest::BaseRestServlet::success_response(result);
    } catch (const json::parse_error&) {
      return rest::BaseRestServlet::error_response(
          400, "M_BAD_JSON", "Invalid JSON body");
    } catch (const std::exception& e) {
      return rest::BaseRestServlet::error_response(
          500, "M_UNKNOWN", e.what());
    }
  }

private:
  IdentityServer& server_;
};

// --- ValidateMsisdnRequestTokenServlet ---
class ValidateMsisdnRequestTokenServlet : public rest::BaseRestServlet {
public:
  explicit ValidateMsisdnRequestTokenServlet(IdentityServer& server)
      : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {
      R"(^/validate/msisdn/requestToken$)",
      R"(^/validate/msisdn/request_token$)"
    };
  }

  std::vector<std::string> methods() const override {
    return {"POST", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      rest::HttpResponse resp;
      resp.code = 200;
      resp.body = json::object();
      return resp;
    }

    try {
      json body = json::parse(req.body.empty() ? "{}" : req.body);
      json result = server_.handle_msisdn_request_token(body, req.client_ip);
      if (result.contains("errcode")) {
        return rest::BaseRestServlet::error_response(
            400, result["errcode"], result["error"]);
      }
      return rest::BaseRestServlet::success_response(result);
    } catch (const json::parse_error&) {
      return rest::BaseRestServlet::error_response(
          400, "M_BAD_JSON", "Invalid JSON body");
    } catch (const std::exception& e) {
      return rest::BaseRestServlet::error_response(
          500, "M_UNKNOWN", e.what());
    }
  }

private:
  IdentityServer& server_;
};

// --- ValidateEmailSubmitTokenServlet ---
class ValidateEmailSubmitTokenServlet : public rest::BaseRestServlet {
public:
  explicit ValidateEmailSubmitTokenServlet(IdentityServer& server)
      : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {
      R"(^/validate/email/submitToken$)",
      R"(^/validate/email/submit_token$)"
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }

    std::string sid = req.query_params.count("sid") ?
        req.query_params.at("sid") : "";
    std::string client_secret = req.query_params.count("client_secret") ?
        req.query_params.at("client_secret") : "";
    std::string token = req.query_params.count("token") ?
        req.query_params.at("token") : "";

    // Also support matrix-style query params
    if (sid.empty()) {
      auto it = req.query_params.find("sid");
      if (it != req.query_params.end()) sid = it->second;
    }
    if (client_secret.empty()) {
      auto it = req.query_params.find("client_secret");
      if (it != req.query_params.end()) client_secret = it->second;
    }
    if (token.empty()) {
      auto it = req.query_params.find("token");
      if (it != req.query_params.end()) token = it->second;
    }

    json result = server_.handle_email_submit_token(sid, client_secret, token);
    if (result.contains("errcode")) {
      return rest::BaseRestServlet::error_response(
          400, result["errcode"], result["error"]);
    }
    return rest::BaseRestServlet::success_response(result);
  }

private:
  IdentityServer& server_;
};

// --- ValidateMsisdnSubmitTokenServlet ---
class ValidateMsisdnSubmitTokenServlet : public rest::BaseRestServlet {
public:
  explicit ValidateMsisdnSubmitTokenServlet(IdentityServer& server)
      : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {
      R"(^/validate/msisdn/submitToken$)",
      R"(^/validate/msisdn/submit_token$)"
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }

    std::string sid, client_secret, token;
    auto sid_it = req.query_params.find("sid");
    auto cs_it = req.query_params.find("client_secret");
    auto tk_it = req.query_params.find("token");
    if (sid_it != req.query_params.end()) sid = sid_it->second;
    if (cs_it != req.query_params.end()) client_secret = cs_it->second;
    if (tk_it != req.query_params.end()) token = tk_it->second;

    json result = server_.handle_msisdn_submit_token(sid, client_secret, token);
    if (result.contains("errcode")) {
      return rest::BaseRestServlet::error_response(
          400, result["errcode"], result["error"]);
    }
    return rest::BaseRestServlet::success_response(result);
  }

private:
  IdentityServer& server_;
};

// --- BindServlet ---
class BindServlet : public rest::BaseRestServlet {
public:
  explicit BindServlet(IdentityServer& server) : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {R"(^/bind$)"};
  }

  std::vector<std::string> methods() const override {
    return {"POST", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }
    try {
      json body = json::parse(req.body.empty() ? "{}" : req.body);
      json result = server_.handle_bind(body);
      if (result.contains("errcode")) {
        return rest::BaseRestServlet::error_response(
            400, result["errcode"], result["error"]);
      }
      return rest::BaseRestServlet::success_response(result);
    } catch (const json::parse_error&) {
      return rest::BaseRestServlet::error_response(
          400, "M_BAD_JSON", "Invalid JSON body");
    } catch (const std::exception& e) {
      return rest::BaseRestServlet::error_response(
          500, "M_UNKNOWN", e.what());
    }
  }

private:
  IdentityServer& server_;
};

// --- LookupServlet ---
class LookupServlet : public rest::BaseRestServlet {
public:
  explicit LookupServlet(IdentityServer& server) : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {R"(^/lookup$)"};
  }

  std::vector<std::string> methods() const override {
    return {"POST", "GET", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }

    try {
      json body;
      if (req.method == "GET") {
        // GET lookup with query params for legacy single-address lookup
        body = json::object();
        std::string medium = req.query_params.count("medium") ?
            req.query_params.at("medium") : "email";
        std::string address;
        auto addr_it = req.query_params.find("address");
        if (addr_it != req.query_params.end()) address = addr_it->second;

        if (!address.empty()) {
          body["medium"] = medium;
          body["addresses"] = json::array({address});
        }
      } else {
        body = json::parse(req.body.empty() ? "{}" : req.body);
      }

      json result = server_.handle_lookup_hash(body);
      if (result.contains("errcode")) {
        return rest::BaseRestServlet::error_response(
            400, result["errcode"], result["error"]);
      }
      return rest::BaseRestServlet::success_response(result);
    } catch (const json::parse_error&) {
      return rest::BaseRestServlet::error_response(
          400, "M_BAD_JSON", "Invalid JSON body");
    } catch (const std::exception& e) {
      return rest::BaseRestServlet::error_response(
          500, "M_UNKNOWN", e.what());
    }
  }

private:
  IdentityServer& server_;
};

// --- UnbindServlet ---
class UnbindServlet : public rest::BaseRestServlet {
public:
  explicit UnbindServlet(IdentityServer& server) : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {R"(^/unbind$)"};
  }

  std::vector<std::string> methods() const override {
    return {"POST", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }
    try {
      json body = json::parse(req.body.empty() ? "{}" : req.body);
      json result = server_.handle_unbind(body);
      if (result.contains("errcode")) {
        return rest::BaseRestServlet::error_response(
            400, result["errcode"], result["error"]);
      }
      return rest::BaseRestServlet::success_response(result);
    } catch (const json::parse_error&) {
      return rest::BaseRestServlet::error_response(
          400, "M_BAD_JSON", "Invalid JSON body");
    } catch (const std::exception& e) {
      return rest::BaseRestServlet::error_response(
          500, "M_UNKNOWN", e.what());
    }
  }

private:
  IdentityServer& server_;
};

// --- StoreInviteServlet ---
class StoreInviteServlet : public rest::BaseRestServlet {
public:
  explicit StoreInviteServlet(IdentityServer& server) : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {R"(^/store-invite$)", R"(^/store_invite$)"};
  }

  std::vector<std::string> methods() const override {
    return {"POST", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }
    try {
      json body = json::parse(req.body.empty() ? "{}" : req.body);
      json result = server_.handle_store_invite(body);
      if (result.contains("errcode")) {
        return rest::BaseRestServlet::error_response(
            400, result["errcode"], result["error"]);
      }
      return rest::BaseRestServlet::success_response(result);
    } catch (const json::parse_error&) {
      return rest::BaseRestServlet::error_response(
          400, "M_BAD_JSON", "Invalid JSON body");
    } catch (const std::exception& e) {
      return rest::BaseRestServlet::error_response(
          500, "M_UNKNOWN", e.what());
    }
  }

private:
  IdentityServer& server_;
};

// --- TermsGetServlet ---
class TermsGetServlet : public rest::BaseRestServlet {
public:
  explicit TermsGetServlet(IdentityServer& server) : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {R"(^/terms$)"};
  }

  std::vector<std::string> methods() const override {
    return {"GET", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }

    std::string language = "";
    auto lang_it = req.query_params.find("language");
    if (lang_it != req.query_params.end()) {
      language = lang_it->second;
    }

    json result = server_.handle_get_terms(language);
    return rest::BaseRestServlet::success_response(result);
  }

private:
  IdentityServer& server_;
};

// --- TermsAcceptServlet ---
class TermsAcceptServlet : public rest::BaseRestServlet {
public:
  explicit TermsAcceptServlet(IdentityServer& server) : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {R"(^/terms$)"};
  }

  std::vector<std::string> methods() const override {
    return {"POST", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }
    try {
      json body = json::parse(req.body.empty() ? "{}" : req.body);
      json result = server_.handle_accept_terms(body, req.client_ip);
      if (result.contains("errcode")) {
        return rest::BaseRestServlet::error_response(
            400, result["errcode"], result["error"]);
      }
      return rest::BaseRestServlet::success_response(result);
    } catch (const json::parse_error&) {
      return rest::BaseRestServlet::error_response(
          400, "M_BAD_JSON", "Invalid JSON body");
    } catch (const std::exception& e) {
      return rest::BaseRestServlet::error_response(
          500, "M_UNKNOWN", e.what());
    }
  }

private:
  IdentityServer& server_;
};

// --- V1ApiServlet ---
class V1ApiServlet : public rest::BaseRestServlet {
public:
  explicit V1ApiServlet(IdentityServer& server) : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {R"(^/_matrix/identity/api/v1$)"};
  }

  std::vector<std::string> methods() const override {
    return {"GET", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }
    json result = server_.handle_v1_api();
    return rest::BaseRestServlet::success_response(result);
  }

private:
  IdentityServer& server_;
};

// --- V2ApiServlet ---
class V2ApiServlet : public rest::BaseRestServlet {
public:
  explicit V2ApiServlet(IdentityServer& server) : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {R"(^/_matrix/identity/v2$)"};
  }

  std::vector<std::string> methods() const override {
    return {"GET", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }
    json result = server_.handle_v2_api();
    return rest::BaseRestServlet::success_response(result);
  }

private:
  IdentityServer& server_;
};

// --- PubkeyServlet ---
class PubkeyServlet : public rest::BaseRestServlet {
public:
  explicit PubkeyServlet(IdentityServer& server) : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {
      R"(^/_matrix/identity/v2/pubkey/([a-zA-Z0-9_:.\-]+)$)",
      R"(^/_matrix/identity/v2/pubkey$)"
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }

    // Check if we have a key_id in path params
    auto key_id_it = req.path_params.find("1");
    bool has_key_id = false;
    std::string key_id;

    if (key_id_it != req.path_params.end()) {
      key_id = key_id_it->second;
      has_key_id = true;
    } else {
      // Try to extract from path directly
      std::string path = req.path;
      std::string prefix = "/_matrix/identity/v2/pubkey/";
      if (path.size() > prefix.size() &&
          path.substr(0, prefix.size()) == prefix) {
        key_id = path.substr(prefix.size());
        has_key_id = true;
      }
    }

    json result;
    if (has_key_id) {
      result = server_.handle_pubkey(key_id);
    } else {
      result = server_.handle_pubkey_list();
    }

    if (result.contains("errcode")) {
      return rest::BaseRestServlet::error_response(
          404, result["errcode"], result["error"]);
    }
    return rest::BaseRestServlet::success_response(result);
  }

private:
  IdentityServer& server_;
};

// --- ResendTokenServlet ---
class ResendTokenServlet : public rest::BaseRestServlet {
public:
  explicit ResendTokenServlet(IdentityServer& server) : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {R"(^/validate/.+/resendToken$)", R"(^/validate/.+/resend_token$)"};
  }

  std::vector<std::string> methods() const override {
    return {"POST", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }
    try {
      json body = json::parse(req.body.empty() ? "{}" : req.body);
      std::string sid = body.value("sid", "");
      if (sid.empty()) {
        return rest::BaseRestServlet::error_response(
            400, "M_MISSING_PARAM", "Missing sid");
      }
      json result = server_.handle_resend_token(sid);
      if (result.contains("errcode")) {
        return rest::BaseRestServlet::error_response(
            400, result["errcode"], result["error"]);
      }
      return rest::BaseRestServlet::success_response(result);
    } catch (const json::parse_error&) {
      return rest::BaseRestServlet::error_response(
          400, "M_BAD_JSON", "Invalid JSON body");
    } catch (const std::exception& e) {
      return rest::BaseRestServlet::error_response(
          500, "M_UNKNOWN", e.what());
    }
  }

private:
  IdentityServer& server_;
};

// --- IdentityServerStatsServlet ---
class IdentityServerStatsServlet : public rest::BaseRestServlet {
public:
  explicit IdentityServerStatsServlet(IdentityServer& server) : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {R"(^/_matrix/identity/admin/stats$)"};
  }

  std::vector<std::string> methods() const override {
    return {"GET", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }
    json result = server_.get_server_stats();
    return rest::BaseRestServlet::success_response(result);
  }

private:
  IdentityServer& server_;
};

// --- IdentityBindingsListServlet ---
class IdentityBindingsListServlet : public rest::BaseRestServlet {
public:
  explicit IdentityBindingsListServlet(IdentityServer& server) : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {R"(^/_matrix/identity/admin/bindings$)"};
  }

  std::vector<std::string> methods() const override {
    return {"GET", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }

    std::string mxid;
    auto mxid_it = req.query_params.find("mxid");
    if (mxid_it != req.query_params.end()) mxid = mxid_it->second;

    if (!mxid.empty()) {
      auto bindings = server_.binder().get_bindings_for_mxid(mxid);
      json result = json::array();
      for (const auto& b : bindings) {
        result.push_back(json{
            {"medium", b.medium},
            {"address", b.address},
            {"mxid", b.mxid},
            {"bound_at_ms", b.bound_at_ms}
        });
      }
      return rest::BaseRestServlet::success_response(result);
    }

    json result = server_.binder().export_bindings();
    return rest::BaseRestServlet::success_response(result);
  }

private:
  IdentityServer& server_;
};

// --- IdentityInvitesListServlet ---
class IdentityInvitesListServlet : public rest::BaseRestServlet {
public:
  explicit IdentityInvitesListServlet(IdentityServer& server) : server_(server) {}

  std::vector<std::string> patterns() const override {
    return {R"(^/_matrix/identity/admin/invites$)"};
  }

  std::vector<std::string> methods() const override {
    return {"GET", "OPTIONS"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    if (req.method == "OPTIONS") {
      return rest::HttpResponse{200, json::object()};
    }

    std::string medium, address, room_id;
    auto medium_it = req.query_params.find("medium");
    auto addr_it = req.query_params.find("address");
    auto room_it = req.query_params.find("room_id");
    if (medium_it != req.query_params.end()) medium = medium_it->second;
    if (addr_it != req.query_params.end()) address = addr_it->second;
    if (room_it != req.query_params.end()) room_id = room_it->second;

    std::vector<IdentityStoreInviteManager::StoredInvite> invites;
    if (!room_id.empty()) {
      invites = server_.invites().get_invites_for_room(room_id);
    } else if (!medium.empty() && !address.empty()) {
      invites = server_.invites().get_invites_for_address(medium, address);
    }

    json result = json::array();
    for (const auto& inv : invites) {
      result.push_back(json{
          {"invite_id", inv.invite_id},
          {"medium", inv.medium},
          {"address", inv.address},
          {"room_id", inv.room_id},
          {"sender", inv.sender},
          {"state", inv.state},
          {"created_at_ms", inv.created_at_ms}
      });
    }
    return rest::BaseRestServlet::success_response(result);
  }

private:
  IdentityServer& server_;
};

// ============================================================================
// IdentityServer factory / registry helpers
// ============================================================================

// Singleton accessor for default identity server
IdentityServer& get_identity_server() {
  static IdentityServer instance;
  return instance;
}

// Create and register all identity servlets into a registry
void register_identity_servlets(rest::ServletRegistry& registry,
                                 IdentityServer& server) {
  registry.register_servlet(
      std::make_unique<ValidateEmailRequestTokenServlet>(server));
  registry.register_servlet(
      std::make_unique<ValidateMsisdnRequestTokenServlet>(server));
  registry.register_servlet(
      std::make_unique<ValidateEmailSubmitTokenServlet>(server));
  registry.register_servlet(
      std::make_unique<ValidateMsisdnSubmitTokenServlet>(server));
  registry.register_servlet(
      std::make_unique<BindServlet>(server));
  registry.register_servlet(
      std::make_unique<LookupServlet>(server));
  registry.register_servlet(
      std::make_unique<UnbindServlet>(server));
  registry.register_servlet(
      std::make_unique<StoreInviteServlet>(server));
  registry.register_servlet(
      std::make_unique<TermsGetServlet>(server));
  registry.register_servlet(
      std::make_unique<TermsAcceptServlet>(server));
  registry.register_servlet(
      std::make_unique<V1ApiServlet>(server));
  registry.register_servlet(
      std::make_unique<V2ApiServlet>(server));
  registry.register_servlet(
      std::make_unique<PubkeyServlet>(server));
  registry.register_servlet(
      std::make_unique<ResendTokenServlet>(server));
  registry.register_servlet(
      std::make_unique<IdentityServerStatsServlet>(server));
  registry.register_servlet(
      std::make_unique<IdentityBindingsListServlet>(server));
  registry.register_servlet(
      std::make_unique<IdentityInvitesListServlet>(server));
}

} // namespace progressive
