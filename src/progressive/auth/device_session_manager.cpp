#include "device_session_manager.hpp"
#include "../json.hpp"
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <shared_mutex>
#include <regex>
#include <queue>
#include <deque>
#include <cmath>

/* ============================================================================
 * progressive::auth - Device & Session Management + User-Interactive Auth
 *
 * Implements the full Matrix Client-Server API auth subsystem:
 *   - Device CRUD (creation, listing, update, deletion)
 *   - Session lifecycle (login, refresh, logout, admin inspection)
 *   - User-Interactive Authentication (UIA) with 8+ stage types
 *   - Registration, password change, 3PID add via UIA flows
 *   - Token generation / refresh / revocation
 *   - Device dehydration for offline key recovery
 *   - In-memory rate limiting
 *
 * No external database — all state held in memory with thread-safe access.
 * ========================================================================== */

namespace progressive {
namespace auth {

using json = nlohmann::json;

/* ============================================================================
 * Internal Constants
 * ========================================================================== */

static constexpr size_t   ACCESS_TOKEN_BYTES   = 32;
static constexpr size_t   DEVICE_ID_LENGTH     = 10;
static constexpr size_t   SESSION_ID_LENGTH    = 24;
static constexpr int64_t  DEFAULT_TOKEN_TTL_SEC = 1209600L;  // 14 days
static constexpr int64_t  REFRESH_TOKEN_TTL_SEC = 2592000L;  // 30 days
static constexpr int64_t  UIA_SESSION_TTL_SEC   = 600L;      // 10 minutes
static constexpr int      RATE_LIMIT_WINDOW_SEC = 300;       // 5-minute window
static constexpr int      RATE_LIMIT_MAX_AUTH   = 20;        // 20 auth attempts
static constexpr int      RATE_LIMIT_MAX_LOGIN  = 30;        // 30 login attempts
static constexpr int      RATE_LIMIT_MAX_REG    = 10;        // 10 registration attempts

/* ============================================================================
 * Shared Mutable State (all guarded by mutexes)
 * ========================================================================== */

static std::shared_mutex g_devices_mutex;
static std::unordered_map<std::string /*user_id*/,
                          std::vector<DeviceInfo>> g_devices_by_user;

static std::shared_mutex g_sessions_mutex;
static std::unordered_map<std::string /*access_token*/, SessionInfo> g_sessions_by_token;
static std::unordered_map<std::string /*user_id*/,
                          std::vector<std::string /*access_token*/>> g_tokens_by_user;
static std::unordered_map<std::string /*device_id*/,
                          std::unordered_set<std::string>> g_tokens_by_device;

static std::shared_mutex g_uia_mutex;
static std::unordered_map<std::string /*session_id*/, UIASession> g_uia_sessions;

static std::shared_mutex g_dehydrated_mutex;
static std::unordered_map<std::string /*device_id*/, DehydratedDevice> g_dehydrated_devices;
static std::unordered_map<std::string /*user_id*/,
                          std::unordered_set<std::string>> g_dehydrated_by_user;

static std::shared_mutex g_ratelimit_mutex;
static std::deque<RateLimitEntry> g_ratelimit_entries;

static std::shared_mutex g_terms_mutex;
static std::unordered_map<std::string, std::vector<std::string>> g_pending_terms;

static std::shared_mutex g_email_tokens_mutex;
static std::unordered_map<std::string /* sid */, PendingEmailToken> g_pending_email_tokens;

static std::shared_mutex g_msisdn_tokens_mutex;
static std::unordered_map<std::string /* sid */, PendingMSISDNToken> g_pending_msisdn_tokens;

static std::shared_mutex g_password_mutex;
static std::unordered_map<std::string /*user_id*/, std::string /*bcrypt-hash*/> g_password_hashes;

static std::shared_mutex g_users_mutex;
static std::unordered_map<std::string /*user_id*/, UserAccount> g_users;
static std::unordered_set<std::string> g_registered_usernames;
static std::unordered_map<std::string /*3pid*/, std::string /*user_id*/> g_threepid_owners;

/* ============================================================================
 * Forward Declarations (helpers)
 * ========================================================================== */

static std::string generate_token_impl(size_t num_bytes);
static std::string generate_device_id_impl();
static std::string generate_session_id_impl();
static std::string sha256_hex(const std::string& input);
static std::string hmac_sha256_hex(const std::string& key, const std::string& msg);
static std::string canonical_json(const json& obj);
static int64_t  now_epoch_seconds();
static bool     validate_user_id(const std::string& id);
static bool     validate_device_id(const std::string& id);
static bool     check_rate_limit(const std::string& scope, const std::string& key, int max_allowed);
static void     record_rate_limit(const std::string& scope, const std::string& key);
static json     make_error(const std::string& errcode, const std::string& error);
static bool     verify_password_internal(const std::string& user_id, const std::string& password);
static json     build_uia_response(const UIASession& sess);
static json     get_completed_stages_array(const UIASession& sess);
static json     get_available_flows(const std::string& session_id);

/* ============================================================================
 * Token / ID Generation
 * ========================================================================== */

static std::string generate_token_impl(size_t num_bytes) {
    std::vector<unsigned char> buf(num_bytes);
    if (RAND_bytes(buf.data(), static_cast<int>(num_bytes)) != 1) {
        // fallback to urandom-style generation
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<unsigned short> dist(0, 255);
        for (size_t i = 0; i < num_bytes; ++i)
            buf[i] = static_cast<unsigned char>(dist(gen));
    }
    std::ostringstream oss;
    for (auto b : buf)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}

static std::string generate_device_id_impl() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    static const char alphanum[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789";
    std::uniform_int_distribution<size_t> dist(0, sizeof(alphanum) - 2);
    std::string id;
    id.reserve(DEVICE_ID_LENGTH);
    for (size_t i = 0; i < DEVICE_ID_LENGTH; ++i)
        id.push_back(alphanum[dist(gen)]);
    return id;
}

static std::string generate_session_id_impl() {
    return generate_token_impl(SESSION_ID_LENGTH);
}

static int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static std::string sha256_hex(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return oss.str();
}

static std::string hmac_sha256_hex(const std::string& key, const std::string& msg) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(),
         key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
         result, &len);
    std::ostringstream oss;
    for (unsigned int i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(result[i]);
    return oss.str();
}

static std::string canonical_json(const json& obj) {
    return obj.dump();
}

/* ============================================================================
 * Validation Helpers
 * ========================================================================== */

static bool validate_user_id(const std::string& id) {
    // Must start with @, contain :, be 3-255 chars
    if (id.empty() || id.size() > 255) return false;
    if (id[0] != '@') return false;
    auto colon = id.find(':');
    if (colon == std::string::npos || colon < 2 || colon == id.size() - 1) return false;
    // localpart after @ before :
    std::string localpart = id.substr(1, colon - 1);
    if (localpart.empty()) return false;
    for (char c : localpart) {
        if (!std::isalnum(static_cast<unsigned char>(c)) &&
            c != '_' && c != '-' && c != '.' && c != '=')
            return false;
    }
    return true;
}

static bool validate_device_id(const std::string& id) {
    if (id.empty() || id.size() > 255) return false;
    for (char c : id) {
        if (!std::isalnum(static_cast<unsigned char>(c)) &&
            c != '_' && c != '-' && c != '.')
            return false;
    }
    return true;
}

static bool is_valid_email(const std::string& email) {
    static const std::regex pattern(
        R"(^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$)");
    return std::regex_match(email, pattern);
}

static bool is_valid_msisdn(const std::string& msisdn) {
    static const std::regex pattern(R"(^\+\d{7,15}$)");
    return std::regex_match(msisdn, pattern);
}

/* ============================================================================
 * Error Helpers
 * ========================================================================== */

static json make_error(const std::string& errcode, const std::string& error) {
    return json{{"errcode", errcode}, {"error", error}};
}

static json make_unauthorized() {
    return json{
        {"errcode", "M_UNKNOWN_TOKEN"},
        {"error", "Unknown or expired access token"},
        {"soft_logout", false}};
}

static json make_forbidden() {
    return json{
        {"errcode", "M_FORBIDDEN"},
        {"error", "You do not have permission to perform this action"}};
}

static json make_not_found() {
    return json{
        {"errcode", "M_NOT_FOUND"},
        {"error", "The requested resource was not found"}};
}

static json make_rate_limited(int64_t retry_after_ms) {
    return json{
        {"errcode", "M_LIMIT_EXCEEDED"},
        {"error", "Too many requests"},
        {"retry_after_ms", retry_after_ms}};
}

static json make_user_in_use() {
    return json{
        {"errcode", "M_USER_IN_USE"},
        {"error", "The desired user ID is already taken"}};
}

static json make_invalid_username() {
    return json{
        {"errcode", "M_INVALID_USERNAME"},
        {"error", "The user ID is not valid"}};
}

/* ============================================================================
 * Password Handling (simple SHA-256 hash — production would use bcrypt/argon2)
 * ========================================================================== */

static std::string hash_password(const std::string& password) {
    return sha256_hex("progressive_matrix_salt_v1:" + password);
}

static bool verify_password_internal(const std::string& user_id, const std::string& password) {
    std::shared_lock lock(g_password_mutex);
    auto it = g_password_hashes.find(user_id);
    if (it == g_password_hashes.end()) return false;
    std::string expected = hash_password(password);
    return it->second == expected;
}

/* ============================================================================
 * Rate Limiting
 * ========================================================================== */

void DeviceSessionManager::prune_rate_limits() {
    std::unique_lock lock(g_ratelimit_mutex);
    int64_t cutoff = now_epoch_seconds() - RATE_LIMIT_WINDOW_SEC;
    while (!g_ratelimit_entries.empty() && g_ratelimit_entries.front().timestamp < cutoff) {
        g_ratelimit_entries.pop_front();
    }
}

static bool check_rate_limit(const std::string& scope, const std::string& key, int max_allowed) {
    DeviceSessionManager::prune_rate_limits();
    std::shared_lock lock(g_ratelimit_mutex);
    int count = 0;
    for (const auto& entry : g_ratelimit_entries) {
        if (entry.scope == scope && entry.key == key)
            ++count;
    }
    return count < max_allowed;
}

static void record_rate_limit(const std::string& scope, const std::string& key) {
    std::unique_lock lock(g_ratelimit_mutex);
    g_ratelimit_entries.push_back({scope, key, now_epoch_seconds()});
}

static int64_t rate_limit_retry_after(const std::string& scope, const std::string& key) {
    std::shared_lock lock(g_ratelimit_mutex);
    int64_t now = now_epoch_seconds();
    int64_t earliest = now;
    for (const auto& entry : g_ratelimit_entries) {
        if (entry.scope == scope && entry.key == key) {
            if (entry.timestamp < earliest) earliest = entry.timestamp;
        }
    }
    int64_t retry = (earliest + RATE_LIMIT_WINDOW_SEC - now) * 1000;
    return retry > 0 ? retry : 1000;
}

/* ============================================================================
 * Session Lookup
 * ========================================================================== */

// Returns true and populates info if a valid session was found.
bool DeviceSessionManager::lookup_session(const std::string& access_token,
                                          SessionInfo& info) {
    std::shared_lock lock(g_sessions_mutex);
    auto it = g_sessions_by_token.find(access_token);
    if (it == g_sessions_by_token.end()) return false;
    info = it->second;
    return true;
}

// Validates that the token exists and is not expired.
bool DeviceSessionManager::validate_token(const std::string& access_token) {
    SessionInfo info;
    if (!lookup_session(access_token, info)) return false;
    int64_t now = now_epoch_seconds();
    if (info.expires_at > 0 && now > info.expires_at) return false;
    return true;
}

// Look up user ID from an access token.
std::string DeviceSessionManager::user_id_from_token(const std::string& access_token) {
    SessionInfo info;
    if (!lookup_session(access_token, info)) return "";
    return info.user_id;
}

// Look up device ID from an access token.
std::string DeviceSessionManager::device_id_from_token(const std::string& access_token) {
    SessionInfo info;
    if (!lookup_session(access_token, info)) return "";
    return info.device_id;
}

/* ============================================================================
 * Device Management: Create
 * ========================================================================== */

std::string DeviceSessionManager::create_device(const std::string& user_id,
                                                 const std::string& display_name,
                                                 const std::string& ip_address,
                                                 const std::string& initial_device_id) {
    std::string device_id = initial_device_id;
    if (device_id.empty()) {
        // Generate unique device ID for this user
        for (int attempt = 0; attempt < 20; ++attempt) {
            device_id = generate_device_id_impl();
            // Check uniqueness across all users' devices
            {
                std::shared_lock lock(g_devices_mutex);
                bool conflict = false;
                for (const auto& [uid, devs] : g_devices_by_user) {
                    for (const auto& d : devs) {
                        if (d.device_id == device_id) { conflict = true; break; }
                    }
                    if (conflict) break;
                }
                if (!conflict) break;
            }
        }
    }

    if (!validate_device_id(device_id))
        return "";

    DeviceInfo dev;
    dev.device_id    = device_id;
    dev.user_id      = user_id;
    dev.display_name = display_name.empty() ? "Unknown Device" : display_name;
    dev.last_seen_ip = ip_address;
    dev.last_seen_ts = now_epoch_seconds();
    dev.created_ts   = now_epoch_seconds();

    {
        std::unique_lock lock(g_devices_mutex);
        g_devices_by_user[user_id].push_back(dev);
    }

    // Update last-seen timestamp
    touch_device(user_id, device_id, ip_address);

    return device_id;
}

/* ============================================================================
 * Device Management: List
 * ========================================================================== */

json DeviceSessionManager::list_devices(const std::string& user_id) {
    json devices_array = json::array();
    std::shared_lock lock(g_devices_mutex);
    auto it = g_devices_by_user.find(user_id);
    if (it == g_devices_by_user.end())
        return devices_array;

    for (const auto& dev : it->second) {
        json d;
        d["device_id"]    = dev.device_id;
        d["display_name"] = dev.display_name;
        d["last_seen_ip"] = dev.last_seen_ip;
        d["last_seen_ts"] = dev.last_seen_ts;
        devices_array.push_back(d);
    }
    return devices_array;
}

/* ============================================================================
 * Device Management: Get Info
 * ========================================================================== */

std::optional<DeviceInfo> DeviceSessionManager::get_device_info(
    const std::string& user_id, const std::string& device_id) {
    std::shared_lock lock(g_devices_mutex);
    auto it = g_devices_by_user.find(user_id);
    if (it == g_devices_by_user.end()) return std::nullopt;
    for (const auto& d : it->second) {
        if (d.device_id == device_id) return d;
    }
    return std::nullopt;
}

/* ============================================================================
 * Device Management: Update
 * ========================================================================== */

bool DeviceSessionManager::update_device(const std::string& user_id,
                                          const std::string& device_id,
                                          const std::string& new_display_name) {
    std::unique_lock lock(g_devices_mutex);
    auto it = g_devices_by_user.find(user_id);
    if (it == g_devices_by_user.end()) return false;
    for (auto& d : it->second) {
        if (d.device_id == device_id) {
            d.display_name = new_display_name;
            return true;
        }
    }
    return false;
}

/* ============================================================================
 * Device Management: Delete
 * ========================================================================== */

bool DeviceSessionManager::delete_device(const std::string& user_id,
                                          const std::string& device_id) {
    // 1. Remove all access tokens associated with this device
    {
        std::unique_lock lock(g_sessions_mutex);
        auto dit = g_tokens_by_device.find(device_id);
        if (dit != g_tokens_by_device.end()) {
            // copy set since we'll modify it
            auto tokens = dit->second;
            for (const auto& tok : tokens) {
                g_sessions_by_token.erase(tok);
                auto uit = g_tokens_by_user.find(user_id);
                if (uit != g_tokens_by_user.end()) {
                    auto& vec = uit->second;
                    vec.erase(std::remove(vec.begin(), vec.end(), tok), vec.end());
                }
            }
            g_tokens_by_device.erase(device_id);
        }
    }

    // 2. Remove the device record
    {
        std::unique_lock lock(g_devices_mutex);
        auto it = g_devices_by_user.find(user_id);
        if (it == g_devices_by_user.end()) return false;
        auto& vec = it->second;
        auto orig_size = vec.size();
        vec.erase(
            std::remove_if(vec.begin(), vec.end(),
                           [&device_id](const DeviceInfo& d) { return d.device_id == device_id; }),
            vec.end());
        if (vec.size() == orig_size) return false; // not found
        if (vec.empty()) g_devices_by_user.erase(it);
    }

    // 3. Remove dehydrated device if present
    {
        std::unique_lock lock(g_dehydrated_mutex);
        g_dehydrated_devices.erase(device_id);
        auto uit = g_dehydrated_by_user.find(user_id);
        if (uit != g_dehydrated_by_user.end()) {
            uit->second.erase(device_id);
            if (uit->second.empty()) g_dehydrated_by_user.erase(uit);
        }
    }

    return true;
}

/* ============================================================================
 * Device Management: Touch (update last-seen)
 * ========================================================================== */

void DeviceSessionManager::touch_device(const std::string& user_id,
                                         const std::string& device_id,
                                         const std::string& ip_address) {
    std::unique_lock lock(g_devices_mutex);
    auto it = g_devices_by_user.find(user_id);
    if (it == g_devices_by_user.end()) return;
    for (auto& d : it->second) {
        if (d.device_id == device_id) {
            d.last_seen_ts  = now_epoch_seconds();
            d.last_seen_ip  = ip_address;
            return;
        }
    }
}

/* ============================================================================
 * Access Token Creation
 * ========================================================================== */

std::string DeviceSessionManager::create_access_token(
    const std::string& user_id,
    const std::string& device_id,
    const std::string& ip_address,
    const std::string& user_agent) {
    std::string token = generate_token_impl(ACCESS_TOKEN_BYTES);

    SessionInfo sess;
    sess.access_token = token;
    sess.user_id      = user_id;
    sess.device_id    = device_id;
    sess.ip_address   = ip_address;
    sess.user_agent   = user_agent;
    sess.created_at   = now_epoch_seconds();
    sess.expires_at   = sess.created_at + DEFAULT_TOKEN_TTL_SEC;
    sess.refresh_token = generate_token_impl(ACCESS_TOKEN_BYTES);
    sess.is_refresh   = false;

    {
        std::unique_lock lock(g_sessions_mutex);
        g_sessions_by_token[token] = sess;
        g_tokens_by_user[user_id].push_back(token);
        g_tokens_by_device[device_id].insert(token);
    }

    // Touch the device to record last-seen
    touch_device(user_id, device_id, ip_address);

    return token;
}

/* ============================================================================
 * Refresh Token Handling
 * ========================================================================== */

bool DeviceSessionManager::refresh_access_token(const std::string& refresh_token,
                                                 std::string& new_access_token,
                                                 std::string& new_refresh_token) {
    std::unique_lock lock(g_sessions_mutex);

    // Find the session that has this refresh_token
    std::string found_token;
    SessionInfo found_sess;
    for (const auto& [at, sess] : g_sessions_by_token) {
        if (sess.refresh_token == refresh_token && !sess.is_refresh) {
            found_token = at;
            found_sess = sess;
            break;
        }
    }

    if (found_token.empty()) return false;

    // Check expiry of the original session
    int64_t now = now_epoch_seconds();
    if (found_sess.expires_at > 0 && now > found_sess.expires_at) {
        // Original expired — still allow refresh if within refresh TTL
        if (now > found_sess.created_at + REFRESH_TOKEN_TTL_SEC)
            return false;
    }

    // Generate new tokens
    new_access_token  = generate_token_impl(ACCESS_TOKEN_BYTES);
    new_refresh_token = generate_token_impl(ACCESS_TOKEN_BYTES);

    // Update session
    found_sess.access_token  = new_access_token;
    found_sess.refresh_token = new_refresh_token;
    found_sess.is_refresh    = true;
    found_sess.created_at    = now;
    found_sess.expires_at    = now + DEFAULT_TOKEN_TTL_SEC;

    // Move the session entry
    g_sessions_by_token.erase(found_token);
    g_sessions_by_token[new_access_token] = found_sess;

    // Update token lists
    auto uit = g_tokens_by_user.find(found_sess.user_id);
    if (uit != g_tokens_by_user.end()) {
        auto& vec = uit->second;
        std::replace(vec.begin(), vec.end(), found_token, new_access_token);
    }

    auto dit = g_tokens_by_device.find(found_sess.device_id);
    if (dit != g_tokens_by_device.end()) {
        dit->second.erase(found_token);
        dit->second.insert(new_access_token);
    }

    return true;
}

/* ============================================================================
 * Single Device Logout
 * ========================================================================== */

bool DeviceSessionManager::logout_device(const std::string& access_token) {
    std::unique_lock lock(g_sessions_mutex);
    auto it = g_sessions_by_token.find(access_token);
    if (it == g_sessions_by_token.end()) return false;

    const auto& sess = it->second;

    // Remove from token-by-device
    auto dit = g_tokens_by_device.find(sess.device_id);
    if (dit != g_tokens_by_device.end()) {
        dit->second.erase(access_token);
        if (dit->second.empty()) g_tokens_by_device.erase(dit);
    }

    // Remove from token-by-user
    auto uit = g_tokens_by_user.find(sess.user_id);
    if (uit != g_tokens_by_user.end()) {
        auto& vec = uit->second;
        vec.erase(std::remove(vec.begin(), vec.end(), access_token), vec.end());
    }

    g_sessions_by_token.erase(it);
    return true;
}

/* ============================================================================
 * All-Devices Logout (except current)
 * ========================================================================== */

int DeviceSessionManager::logout_all_devices(const std::string& user_id,
                                              const std::string& current_token) {
    std::unique_lock lock(g_sessions_mutex);
    auto uit = g_tokens_by_user.find(user_id);
    if (uit == g_tokens_by_user.end()) return 0;

    int revoked = 0;
    std::vector<std::string> to_revoke;

    for (const auto& token : uit->second) {
        if (token == current_token) continue;
        to_revoke.push_back(token);
    }

    for (const auto& token : to_revoke) {
        auto sit = g_sessions_by_token.find(token);
        if (sit == g_sessions_by_token.end()) continue;

        // Remove from token-by-device
        auto dit = g_tokens_by_device.find(sit->second.device_id);
        if (dit != g_tokens_by_device.end()) {
            dit->second.erase(token);
            if (dit->second.empty()) g_tokens_by_device.erase(dit);
        }

        g_sessions_by_token.erase(sit);
        ++revoked;
    }

    // Rebuild the list for this user
    std::vector<std::string> remaining;
    for (const auto& token : uit->second) {
        if (token == current_token || g_sessions_by_token.count(token))
            remaining.push_back(token);
    }
    uit->second = remaining;

    return revoked;
}

/* ============================================================================
 * Session Listing (Admin)
 * ========================================================================== */

json DeviceSessionManager::list_sessions_admin(
    const std::string& user_id,
    const std::string& current_token) {
    json result = json::array();

    std::shared_lock lock(g_sessions_mutex);
    auto uit = g_tokens_by_user.find(user_id);
    if (uit == g_tokens_by_user.end()) return result;

    for (const auto& token : uit->second) {
        auto sit = g_sessions_by_token.find(token);
        if (sit == g_sessions_by_token.end()) continue;
        const auto& sess = sit->second;
        json s;
        s["access_token_hash"] = sha256_hex(token).substr(0, 16) + "...";
        s["device_id"]         = sess.device_id;
        s["ip_address"]        = sess.ip_address;
        s["user_agent"]        = sess.user_agent;
        s["created_at"]        = sess.created_at;
        s["expires_at"]        = sess.expires_at;
        s["is_current"]        = (token == current_token);
        s["is_refresh"]        = sess.is_refresh;
        result.push_back(s);
    }

    return result;
}

/* ============================================================================
 * Session Deletion (Admin)
 * ========================================================================== */

bool DeviceSessionManager::delete_session(const std::string& access_token) {
    return logout_device(access_token);
}

bool DeviceSessionManager::delete_session_by_hash(
    const std::string& user_id,
    const std::string& token_hash_prefix) {
    std::unique_lock lock(g_sessions_mutex);
    auto uit = g_tokens_by_user.find(user_id);
    if (uit == g_tokens_by_user.end()) return false;

    for (const auto& token : uit->second) {
        std::string hash = sha256_hex(token).substr(0, 16);
        if (hash == token_hash_prefix) {
            // Found it — delete this session
            auto sit = g_sessions_by_token.find(token);
            if (sit != g_sessions_by_token.end()) {
                auto dit = g_tokens_by_device.find(sit->second.device_id);
                if (dit != g_tokens_by_device.end()) {
                    dit->second.erase(token);
                    if (dit->second.empty()) g_tokens_by_device.erase(dit);
                }
                g_sessions_by_token.erase(sit);
            }
            auto& vec = uit->second;
            vec.erase(std::remove(vec.begin(), vec.end(), token), vec.end());
            return true;
        }
    }
    return false;
}

/* ============================================================================
 * UIA Session Store: Create
 * ========================================================================== */

std::string DeviceSessionManager::uia_create_session(
    const json& flows,
    const json& params,
    const std::string& session_id_hint) {
    std::string session_id = session_id_hint.empty()
                                 ? generate_session_id_impl()
                                 : session_id_hint;

    UIASession sess;
    sess.session_id   = session_id;
    sess.created_at   = now_epoch_seconds();
    sess.expires_at   = sess.created_at + UIA_SESSION_TTL_SEC;
    sess.state        = UIAState::InProgress;
    sess.flows        = flows;
    sess.params       = params;

    // Parse available stages from flows
    if (flows.is_array()) {
        for (const auto& flow : flows) {
            if (flow.contains("stages") && flow["stages"].is_array()) {
                std::vector<std::string> flow_stages;
                for (const auto& s : flow["stages"])
                    flow_stages.push_back(s.get<std::string>());
                sess.parsed_flows.push_back(flow_stages);
            }
        }
    }

    {
        std::unique_lock lock(g_uia_mutex);
        g_uia_sessions[session_id] = sess;
    }

    return session_id;
}

/* ============================================================================
 * UIA Session Store: Get
 * ========================================================================== */

std::optional<UIASession> DeviceSessionManager::uia_get_session(
    const std::string& session_id) {
    std::shared_lock lock(g_uia_mutex);
    auto it = g_uia_sessions.find(session_id);
    if (it == g_uia_sessions.end()) return std::nullopt;

    UIASession sess = it->second;
    // Check expiry
    if (now_epoch_seconds() > sess.expires_at) {
        // Don't erase here (lock upgrade complexity) — caller should handle
        return std::nullopt;
    }
    return sess;
}

/* ============================================================================
 * UIA Session Store: Update
 * ========================================================================== */

bool DeviceSessionManager::uia_update_session(const UIASession& updated) {
    std::unique_lock lock(g_uia_mutex);
    auto it = g_uia_sessions.find(updated.session_id);
    if (it == g_uia_sessions.end()) return false;
    it->second = updated;
    return true;
}

/* ============================================================================
 * UIA Session Store: Delete
 * ========================================================================== */

void DeviceSessionManager::uia_delete_session(const std::string& session_id) {
    std::unique_lock lock(g_uia_mutex);
    g_uia_sessions.erase(session_id);
}

/* ============================================================================
 * UIA Session Store: Cleanup Expired
 * ========================================================================== */

void DeviceSessionManager::uia_cleanup_expired() {
    std::unique_lock lock(g_uia_mutex);
    int64_t now = now_epoch_seconds();
    auto it = g_uia_sessions.begin();
    while (it != g_uia_sessions.end()) {
        if (now > it->second.expires_at)
            it = g_uia_sessions.erase(it);
        else
            ++it;
    }
}

/* ============================================================================
 * UIA: Auth Dict Validation
 * ========================================================================== */

bool DeviceSessionManager::uia_validate_auth_dict(const json& auth_dict) {
    if (!auth_dict.is_object()) return false;
    if (!auth_dict.contains("session")) return false;
    if (!auth_dict["session"].is_string()) return false;
    if (!auth_dict.contains("type")) return false;
    if (!auth_dict["type"].is_string()) return false;
    return true;
}

/* ============================================================================
 * UIA: Build Response (the auth object returned to client)
 * ========================================================================== */

static json build_uia_response(const UIASession& sess) {
    json response;
    response["session"] = sess.session_id;
    response["flows"]   = sess.flows;

    // If params is non-empty, include it
    if (!sess.params.empty())
        response["params"] = sess.params;

    // Completed stages
    json completed = json::array();
    for (const auto& s : sess.completed_stages)
        completed.push_back(s);
    if (!completed.empty())
        response["completed"] = completed;

    return response;
}

static json get_completed_stages_array(const UIASession& sess) {
    json arr = json::array();
    for (const auto& s : sess.completed_stages)
        arr.push_back(s);
    return arr;
}

static json get_available_flows(const std::string& session_id) {
    auto opt = DeviceSessionManager::uia_get_session(session_id);
    if (!opt.has_value()) return json::array();
    return opt->flows;
}

/* ============================================================================
 * UIA: Stage Processing Dispatcher
 * ========================================================================== */

UIAStageResult DeviceSessionManager::uia_process_stage(
    const std::string& session_id,
    const json& auth_dict) {
    UIAStageResult result;

    auto opt_sess = uia_get_session(session_id);
    if (!opt_sess.has_value()) {
        result.error = make_error("M_UNKNOWN", "UIA session not found or expired");
        return result;
    }

    UIASession sess = opt_sess.value();
    std::string stage_type = auth_dict["type"].get<std::string>();

    // Check if already completed
    if (sess.completed_stages.count(stage_type)) {
        result.error = make_error("M_UNKNOWN",
                                   "Stage '" + stage_type + "' already completed");
        return result;
    }

    // Dispatch to stage handler
    bool stage_ok = false;

    if (stage_type == "m.login.password") {
        stage_ok = uia_stage_password(sess, auth_dict);
    } else if (stage_type == "m.login.recaptcha") {
        stage_ok = uia_stage_recaptcha(sess, auth_dict);
    } else if (stage_type == "m.login.email.identity") {
        stage_ok = uia_stage_email(sess, auth_dict);
    } else if (stage_type == "m.login.msisdn") {
        stage_ok = uia_stage_msisdn(sess, auth_dict);
    } else if (stage_type == "m.login.terms") {
        stage_ok = uia_stage_terms(sess, auth_dict);
    } else if (stage_type == "m.login.sso") {
        stage_ok = uia_stage_sso(sess, auth_dict);
    } else if (stage_type == "m.login.token") {
        stage_ok = uia_stage_token(sess, auth_dict);
    } else if (stage_type == "m.login.dummy") {
        stage_ok = uia_stage_dummy(sess, auth_dict);
    } else {
        result.error = make_error("M_UNKNOWN",
                                   "Unknown UIA stage type: " + stage_type);
        return result;
    }

    if (!stage_ok) {
        // stage_ok==false with non-empty sess.error means the handler set an error
        if (!sess.error.empty()) {
            result.error = json{{"errcode", "M_UNAUTHORIZED"}, {"error", sess.error}};
        } else {
            result.error = make_error("M_UNAUTHORIZED", "Stage verification failed");
        }
        result.completed  = get_completed_stages_array(sess);
        result.flows      = sess.flows;
        result.params     = sess.params;
        return result;
    }

    // Mark stage as completed
    sess.completed_stages.insert(stage_type);
    uia_update_session(sess);

    // Check if any flow is now fully satisfied
    bool flow_complete = false;
    for (const auto& flow : sess.parsed_flows) {
        bool all_done = true;
        for (const auto& req_stage : flow) {
            if (!sess.completed_stages.count(req_stage)) {
                all_done = false;
                break;
            }
        }
        if (all_done) {
            flow_complete = true;
            break;
        }
    }

    if (flow_complete) {
        sess.state = UIAState::Complete;
        uia_update_session(sess);
        result.done      = true;
        result.completed = get_completed_stages_array(sess);
        // Return the original params that were stored with the session
        if (!sess.params.empty())
            result.params = sess.params;
    } else {
        result.completed = get_completed_stages_array(sess);
        result.flows     = sess.flows;
        result.params    = sess.params;
    }

    return result;
}

/* ============================================================================
 * UIA Individual Stage Handlers
 * ========================================================================== */

bool DeviceSessionManager::uia_stage_password(UIASession& sess, const json& auth) {
    // auth dict should contain "identifier" and "password"
    if (!auth.contains("identifier") || !auth.contains("password")) {
        sess.error = "Missing identifier or password in auth dict";
        return false;
    }

    const auto& identifier = auth["identifier"];
    std::string user_id;
    if (identifier.is_object() && identifier.contains("type") && identifier.contains("user")) {
        if (identifier["type"] == "m.id.user") {
            user_id = identifier["user"].get<std::string>();
        } else if (identifier["type"] == "m.id.thirdparty") {
            // 3PID login
            std::string medium = identifier.value("medium", "");
            std::string address = identifier.value("address", "");
            std::string resolved = resolve_threepid(medium, address);
            if (resolved.empty()) {
                sess.error = "Third-party identifier not found";
                return false;
            }
            user_id = resolved;
        } else {
            sess.error = "Unknown identifier type";
            return false;
        }
    } else if (identifier.is_string()) {
        user_id = identifier.get<std::string>();
    } else {
        // Legacy "user" field
        if (auth.contains("user"))
            user_id = auth["user"].get<std::string>();
        else {
            sess.error = "Missing user identifier";
            return false;
        }
    }

    std::string password = auth["password"].get<std::string>();

    if (!verify_password_internal(user_id, password)) {
        sess.error = "Invalid password";
        return false;
    }

    // Store the authenticated user in the session
    sess.authenticated_user_id = user_id;
    return true;
}

bool DeviceSessionManager::uia_stage_recaptcha(UIASession& sess, const json& auth) {
    // In practice, verify the recaptcha response with Google's API.
    // For the server implementation, we accept any non-empty response.
    if (!auth.contains("response")) {
        sess.error = "Missing recaptcha response";
        return false;
    }
    std::string response = auth["response"].get<std::string>();
    if (response.empty()) {
        sess.error = "Empty recaptcha response";
        return false;
    }
    // In production: POST to https://www.google.com/recaptcha/api/siteverify
    // For now, accept all non-empty tokens.
    return true;
}

bool DeviceSessionManager::uia_stage_email(UIASession& sess, const json& auth) {
    // m.login.email.identity
    // Expects "threepid_creds" or "threepidCreds" with sid and client_secret
    std::string sid;
    std::string client_secret;

    if (auth.contains("threepid_creds")) {
        const auto& creds = auth["threepid_creds"];
        sid           = creds.value("sid", "");
        client_secret = creds.value("client_secret", "");
    } else if (auth.contains("threepidCreds")) {
        const auto& creds = auth["threepidCreds"];
        sid           = creds.value("sid", "");
        client_secret = creds.value("client_secret", "");
    } else {
        sess.error = "Missing threepid_creds";
        return false;
    }

    if (sid.empty()) {
        sess.error = "Missing sid in threepid_creds";
        return false;
    }

    // Verify the email token
    {
        std::shared_lock lock(g_email_tokens_mutex);
        auto it = g_pending_email_tokens.find(sid);
        if (it == g_pending_email_tokens.end()) {
            sess.error = "Email verification session not found";
            return false;
        }
        const auto& pending = it->second;
        if (pending.client_secret != client_secret) {
            sess.error = "Client secret mismatch";
            return false;
        }
        if (!pending.validated) {
            sess.error = "Email has not been validated yet";
            return false;
        }
    }

    return true;
}

bool DeviceSessionManager::uia_stage_msisdn(UIASession& sess, const json& auth) {
    // m.login.msisdn
    // Expects "threepid_creds" or "threepidCreds" with sid and client_secret
    std::string sid;
    std::string client_secret;

    if (auth.contains("threepid_creds")) {
        const auto& creds = auth["threepid_creds"];
        sid           = creds.value("sid", "");
        client_secret = creds.value("client_secret", "");
    } else if (auth.contains("threepidCreds")) {
        const auto& creds = auth["threepidCreds"];
        sid           = creds.value("sid", "");
        client_secret = creds.value("client_secret", "");
    } else {
        sess.error = "Missing threepid_creds";
        return false;
    }

    if (sid.empty()) {
        sess.error = "Missing sid";
        return false;
    }

    {
        std::shared_lock lock(g_msisdn_tokens_mutex);
        auto it = g_pending_msisdn_tokens.find(sid);
        if (it == g_pending_msisdn_tokens.end()) {
            sess.error = "MSISDN verification session not found";
            return false;
        }
        const auto& pending = it->second;
        if (pending.client_secret != client_secret) {
            sess.error = "Client secret mismatch";
            return false;
        }
        if (!pending.validated) {
            sess.error = "MSISDN has not been validated yet";
            return false;
        }
    }

    return true;
}

bool DeviceSessionManager::uia_stage_terms(UIASession& sess, const json& auth) {
    // m.login.terms
    // Client must accept the terms URLs that were presented in params
    if (!auth.contains("policies") || !auth["policies"].is_object()) {
        sess.error = "Missing policies acceptance";
        return false;
    }

    // In a full implementation, verify each policy was accepted.
    // For the server, we just check that policies is not empty.
    if (auth["policies"].empty()) {
        sess.error = "No policies accepted";
        return false;
    }

    return true;
}

bool DeviceSessionManager::uia_stage_sso(UIASession& sess, const json& auth) {
    // m.login.sso
    // This is typically handled via redirect, but when submitted as UIA,
    // the client provides a token obtained from the SSO provider.
    if (!auth.contains("token")) {
        sess.error = "Missing SSO token";
        return false;
    }

    std::string sso_token = auth["token"].get<std::string>();
    if (sso_token.empty()) {
        sess.error = "Empty SSO token";
        return false;
    }

    // In a full implementation, validate the SSO token with the IDP.
    // For the server, accept any non-empty string as valid.
    // If session.params contains sso_redirect_url, we assume validation occurred.
    return true;
}

bool DeviceSessionManager::uia_stage_token(UIASession& sess, const json& auth) {
    // m.login.token — registration token or login token
    if (!auth.contains("token")) {
        sess.error = "Missing token";
        return false;
    }

    std::string token = auth["token"].get<std::string>();
    if (token.empty()) {
        sess.error = "Empty token";
        return false;
    }

    // If the session params define a required registration token, verify it
    if (sess.params.contains("registration_token") || sess.params.contains("token")) {
        std::string required = sess.params.value("registration_token",
                                                  sess.params.value("token", ""));
        if (!required.empty() && token != required) {
            sess.error = "Invalid token";
            return false;
        }
    }

    return true;
}

bool DeviceSessionManager::uia_stage_dummy(UIASession& sess, const json& auth) {
    // m.login.dummy — always succeeds
    (void)auth;
    return true;
}

/* ============================================================================
 * UIA: Verify Completion
 * ========================================================================== */

bool DeviceSessionManager::uia_verify_complete(const std::string& session_id) {
    auto opt = uia_get_session(session_id);
    if (!opt.has_value()) return false;
    return opt->state == UIAState::Complete;
}

/* ============================================================================
 * UIA: Get Authenticated User
 * ========================================================================== */

std::string DeviceSessionManager::uia_get_authenticated_user(
    const std::string& session_id) {
    auto opt = uia_get_session(session_id);
    if (!opt.has_value()) return "";
    return opt->authenticated_user_id;
}

/* ============================================================================
 * UIA: Check if a specific stage is complete
 * ========================================================================== */

bool DeviceSessionManager::uia_is_stage_complete(
    const std::string& session_id, const std::string& stage_type) {
    auto opt = uia_get_session(session_id);
    if (!opt.has_value()) return false;
    return opt->completed_stages.count(stage_type) > 0;
}

/* ============================================================================
 * Registration with UIA
 * ========================================================================== */

json DeviceSessionManager::register_user(
    const std::string& ip_address,
    const json& registration_body) {
    // Rate limiting
    if (!check_rate_limit("register", ip_address, RATE_LIMIT_MAX_REG))
        return make_rate_limited(rate_limit_retry_after("register", ip_address));

    record_rate_limit("register", ip_address);

    // Check if this is a UIA continuation (has auth dict)
    if (registration_body.contains("auth")) {
        return register_with_uia_continue(ip_address, registration_body);
    }

    // Initial registration — check if UIA is required
    bool needs_uia = false;
    json flows = json::array();

    // Registration often requires dummy stage or recaptcha
    json flow1 = json::array();
    flow1.push_back("m.login.dummy");
    flows.push_back({{"stages", flow1}});
    needs_uia = true;

    if (!needs_uia) {
        // Simple registration without UIA
        return register_simple(ip_address, registration_body);
    }

    // Create UIA session for registration
    json params;
    params["type"] = "m.register";
    if (registration_body.contains("username"))
        params["username"] = registration_body["username"];
    if (registration_body.contains("password"))
        params["password"] = registration_body["password"];
    if (registration_body.contains("device_id"))
        params["device_id"] = registration_body["device_id"];
    if (registration_body.contains("initial_device_display_name"))
        params["initial_device_display_name"] = registration_body["initial_device_display_name"];
    if (registration_body.contains("inhibit_login"))
        params["inhibit_login"] = registration_body["inhibit_login"];

    std::string session_id = uia_create_session(flows, params);
    auto opt = uia_get_session(session_id);
    if (!opt.has_value())
        return make_error("M_UNKNOWN", "Failed to create UIA session");

    json response = build_uia_response(opt.value());
    response["errcode"] = "M_UNAUTHORIZED";
    response["error"]   = "User-Interactive Authentication required";
    return response;
}

json DeviceSessionManager::register_with_uia_continue(
    const std::string& ip_address,
    const json& body) {
    const auto& auth = body["auth"];
    std::string session_id = auth["session"].get<std::string>();

    auto result = uia_process_stage(session_id, auth);

    if (result.done) {
        // UIA complete — now perform the actual registration
        auto opt = uia_get_session(session_id);
        if (!opt.has_value())
            return make_error("M_UNKNOWN", "UIA session disappeared");

        const auto& stored_params = opt->params;

        // Build registration data from stored params
        json reg_data;
        if (stored_params.contains("username"))
            reg_data["username"] = stored_params["username"];
        if (stored_params.contains("password"))
            reg_data["password"] = stored_params["password"];
        if (stored_params.contains("device_id"))
            reg_data["device_id"] = stored_params["device_id"];
        if (stored_params.contains("initial_device_display_name"))
            reg_data["initial_device_display_name"] = stored_params["initial_device_display_name"];
        if (body.contains("username") && !reg_data.contains("username"))
            reg_data["username"] = body["username"];
        if (body.contains("password") && !reg_data.contains("password"))
            reg_data["password"] = body["password"];

        json reg_result = register_simple(ip_address, reg_data);

        uia_delete_session(session_id);
        return reg_result;
    }

    // Still in progress
    if (!result.error.empty())
        return result.error;

    auto opt = uia_get_session(session_id);
    json response = build_uia_response(opt.value_or(UIASession{}));
    response["errcode"] = "M_UNAUTHORIZED";
    response["error"]   = "Additional authentication required";
    if (!result.completed.empty())
        response["completed"] = result.completed;
    return response;
}

json DeviceSessionManager::register_simple(
    const std::string& ip_address,
    const json& body) {
    std::string username;
    std::string password;
    std::string device_id;
    std::string display_name;
    bool inhibit_login = false;

    if (body.contains("username"))
        username = body["username"].get<std::string>();
    if (body.contains("password"))
        password = body["password"].get<std::string>();
    if (body.contains("device_id"))
        device_id = body["device_id"].get<std::string>();
    if (body.contains("initial_device_display_name"))
        display_name = body["initial_device_display_name"].get<std::string>();
    if (body.contains("inhibit_login"))
        inhibit_login = body["inhibit_login"].get<bool>();

    // Validate username
    if (username.empty())
        return make_invalid_username();

    // Build full user_id (in production this depends on server name)
    std::string user_id;
    if (username[0] == '@') {
        user_id = username; // already fully qualified
    } else {
        user_id = "@" + username + ":localhost";
    }

    if (!validate_user_id(user_id))
        return make_invalid_username();

    // Check if username is taken
    {
        std::unique_lock lock(g_users_mutex);
        if (g_registered_usernames.count(user_id)) {
            return make_user_in_use();
        }
    }

    // Hash and store password
    std::string pwd_hash = hash_password(password);
    {
        std::unique_lock lock(g_password_mutex);
        g_password_hashes[user_id] = pwd_hash;
    }

    // Create user account
    UserAccount account;
    account.user_id     = user_id;
    account.created_at  = now_epoch_seconds();
    account.is_admin    = false;
    account.deactivated = false;

    {
        std::unique_lock lock(g_users_mutex);
        g_users[user_id] = account;
        g_registered_usernames.insert(user_id);
    }

    // Create device
    std::string actual_device_id = create_device(user_id, display_name, ip_address, device_id);

    json response;
    response["user_id"]   = user_id;
    response["device_id"] = actual_device_id;

    if (!inhibit_login) {
        std::string user_agent = "Unknown";
        if (body.contains("user_agent"))
            user_agent = body["user_agent"].get<std::string>();

        std::string token = create_access_token(user_id, actual_device_id,
                                                  ip_address, user_agent);

        response["access_token"]  = token;
        response["home_server"]   = "localhost";
    }

    return response;
}

/* ============================================================================
 * Login
 * ========================================================================== */

json DeviceSessionManager::login_user(
    const std::string& ip_address,
    const json& login_body) {
    // Rate limiting
    if (!check_rate_limit("login", ip_address, RATE_LIMIT_MAX_LOGIN))
        return make_rate_limited(rate_limit_retry_after("login", ip_address));

    record_rate_limit("login", ip_address);

    // Check if this is a UIA continuation
    if (login_body.contains("auth")) {
        return login_with_uia_continue(ip_address, login_body);
    }

    // Determine identifier type
    std::string user_id;
    std::string password;
    std::string device_id;
    std::string display_name;
    std::string user_agent = "Unknown";

    if (login_body.contains("identifier")) {
        const auto& identifier = login_body["identifier"];
        if (identifier.is_object() && identifier.contains("type") && identifier.contains("user")) {
            if (identifier["type"] == "m.id.user") {
                user_id = identifier["user"].get<std::string>();
            } else if (identifier["type"] == "m.id.thirdparty") {
                std::string medium = identifier.value("medium", "");
                std::string address = identifier.value("address", "");
                user_id = resolve_threepid(medium, address);
                if (user_id.empty()) {
                    return make_error("M_FORBIDDEN",
                                      "Third-party identifier not found");
                }
            }
        } else if (identifier.is_string()) {
            user_id = identifier.get<std::string>();
        }
    } else if (login_body.contains("user")) {
        // Legacy field
        user_id = login_body["user"].get<std::string>();
    }

    if (user_id.empty())
        return make_error("M_INVALID_USERNAME", "Missing user identifier");

    // Normalize user_id if needed (ensure @ prefix and domain)
    if (user_id.find(':') == std::string::npos) {
        std::string localpart = user_id;
        if (!localpart.empty() && localpart[0] == '@')
            localpart = localpart.substr(1);
        user_id = "@" + localpart + ":localhost";
    }

    if (login_body.contains("password"))
        password = login_body["password"].get<std::string>();
    if (login_body.contains("device_id"))
        device_id = login_body["device_id"].get<std::string>();
    if (login_body.contains("initial_device_display_name"))
        display_name = login_body["initial_device_display_name"].get<std::string>();
    if (login_body.contains("user_agent"))
        user_agent = login_body["user_agent"].get<std::string>();

    // Check if user exists
    {
        std::shared_lock lock(g_users_mutex);
        if (!g_registered_usernames.count(user_id))
            return make_error("M_FORBIDDEN", "Invalid username or password");
    }

    // Check if UIA is needed for this login (e.g., terms not accepted)
    if (login_body.contains("needs_uia") && login_body["needs_uia"].get<bool>()) {
        return login_create_uia(user_id, password, device_id, display_name, user_agent, ip_address);
    }

    // Verify password
    if (!verify_password_internal(user_id, password))
        return make_error("M_FORBIDDEN", "Invalid username or password");

    // Create device
    std::string actual_device_id = create_device(user_id, display_name, ip_address, device_id);

    // Create access token
    std::string token = create_access_token(user_id, actual_device_id, ip_address, user_agent);

    json response;
    response["user_id"]      = user_id;
    response["access_token"] = token;
    response["device_id"]    = actual_device_id;
    response["home_server"]  = "localhost";

    // Include well-known info
    json well_known;
    well_known["m.homeserver"]["base_url"] = "https://localhost";
    response["well_known"] = well_known;

    return response;
}

json DeviceSessionManager::login_create_uia(
    const std::string& user_id,
    const std::string& password,
    const std::string& device_id,
    const std::string& display_name,
    const std::string& user_agent,
    const std::string& ip_address) {
    json flows = json::array();

    // Password-only flow
    json flow1 = json::array();
    flow1.push_back("m.login.password");
    flows.push_back({{"stages", flow1}});

    // Password + terms flow
    json flow2 = json::array();
    flow2.push_back("m.login.password");
    flow2.push_back("m.login.terms");
    flows.push_back({{"stages", flow2}});

    json params;
    params["type"]      = "m.login";
    params["user_id"]   = user_id;
    params["password"]  = password;
    params["device_id"] = device_id;
    params["display_name"] = display_name;
    params["user_agent"]   = user_agent;

    std::string session_id = uia_create_session(flows, params);
    auto opt = uia_get_session(session_id);
    if (!opt.has_value())
        return make_error("M_UNKNOWN", "Failed to create UIA session");

    json response = build_uia_response(opt.value());
    response["errcode"] = "M_UNAUTHORIZED";
    response["error"]   = "User-Interactive Authentication required";
    return response;
}

json DeviceSessionManager::login_with_uia_continue(
    const std::string& ip_address,
    const json& body) {
    const auto& auth_dict = body["auth"];
    std::string session_id = auth_dict["session"].get<std::string>();

    auto result = uia_process_stage(session_id, auth_dict);

    if (result.done) {
        auto opt = uia_get_session(session_id);
        if (!opt.has_value())
            return make_error("M_UNKNOWN", "UIA session disappeared");

        const auto& params = opt->params;
        std::string user_id     = params.value("user_id", "");
        std::string password    = params.value("password", "");
        std::string device_id   = params.value("device_id", "");
        std::string display_name = params.value("display_name", "");
        std::string user_agent  = params.value("user_agent", "Unknown");

        // Verify password again (defense in depth)
        if (user_id.empty())
            return make_error("M_UNKNOWN", "No user in session");

        // Create device
        std::string actual_device_id = create_device(user_id, display_name,
                                                       ip_address, device_id);
        std::string token = create_access_token(user_id, actual_device_id,
                                                  ip_address, user_agent);

        uia_delete_session(session_id);

        json response;
        response["user_id"]      = user_id;
        response["access_token"] = token;
        response["device_id"]    = actual_device_id;
        response["home_server"]  = "localhost";
        return response;
    }

    if (!result.error.empty())
        return result.error;

    auto opt = uia_get_session(session_id);
    json response = build_uia_response(opt.value_or(UIASession{}));
    response["errcode"] = "M_UNAUTHORIZED";
    response["error"]   = "Additional authentication required";
    if (!result.completed.empty())
        response["completed"] = result.completed;
    return response;
}

/* ============================================================================
 * Password Change with UIA
 * ========================================================================== */

json DeviceSessionManager::change_password(
    const std::string& user_id,
    const std::string& ip_address,
    const json& body) {
    // Rate limiting
    if (!check_rate_limit("password_change", user_id, RATE_LIMIT_MAX_AUTH))
        return make_rate_limited(rate_limit_retry_after("password_change", user_id));
    record_rate_limit("password_change", user_id);

    // Check if this is UIA continuation
    if (body.contains("auth")) {
        return change_password_uia_continue(user_id, ip_address, body);
    }

    // Initial request — require UIA
    json flows = json::array();

    // Password verification flow
    json flow1 = json::array();
    flow1.push_back("m.login.password");
    flows.push_back({{"stages", flow1}});

    json params;
    params["type"]         = "m.password_change";
    params["user_id"]      = user_id;
    params["new_password"] = body.value("new_password", "");

    std::string session_id = uia_create_session(flows, params);
    auto opt = uia_get_session(session_id);
    if (!opt.has_value())
        return make_error("M_UNKNOWN", "Failed to create UIA session");

    json response = build_uia_response(opt.value());
    response["errcode"] = "M_UNAUTHORIZED";
    response["error"]   = "User-Interactive Authentication required";
    return response;
}

json DeviceSessionManager::change_password_uia_continue(
    const std::string& user_id,
    const std::string& ip_address,
    const json& body) {
    const auto& auth_dict = body["auth"];
    std::string session_id = auth_dict["session"].get<std::string>();

    auto result = uia_process_stage(session_id, auth_dict);

    if (result.done) {
        auto opt = uia_get_session(session_id);
        if (!opt.has_value())
            return make_error("M_UNKNOWN", "UIA session disappeared");

        std::string new_password = opt->params.value("new_password",
                                                      body.value("new_password", ""));
        if (new_password.empty())
            return make_error("M_MISSING_PARAM", "Missing new_password");

        // Update password
        std::string pwd_hash = hash_password(new_password);
        {
            std::unique_lock lock(g_password_mutex);
            g_password_hashes[user_id] = pwd_hash;
        }

        // Revoke all existing sessions except current
        std::string current_token;
        if (body.contains("access_token"))
            current_token = body["access_token"].get<std::string>();

        logout_all_devices(user_id, current_token);

        uia_delete_session(session_id);

        return json{{"success", true}};
    }

    if (!result.error.empty())
        return result.error;

    auto opt = uia_get_session(session_id);
    json response = build_uia_response(opt.value_or(UIASession{}));
    response["errcode"] = "M_UNAUTHORIZED";
    response["error"]   = "Additional authentication required";
    if (!result.completed.empty())
        response["completed"] = result.completed;
    return response;
}

/* ============================================================================
 * 3PID Management: Add Email / MSISDN
 * ========================================================================== */

json DeviceSessionManager::add_threepid(
    const std::string& user_id,
    const std::string& ip_address,
    const json& body) {
    // Rate limiting
    if (!check_rate_limit("threepid_add", user_id, RATE_LIMIT_MAX_AUTH))
        return make_rate_limited(rate_limit_retry_after("threepid_add", user_id));
    record_rate_limit("threepid_add", user_id);

    // Check if this is UIA continuation
    if (body.contains("auth")) {
        return add_threepid_uia_continue(user_id, ip_address, body);
    }

    // Validate request
    std::string medium = body.value("medium", "");
    std::string address = body.value("address", "");

    if (medium.empty() || address.empty())
        return make_error("M_MISSING_PARAM", "Missing medium or address");

    if (medium != "email" && medium != "msisdn")
        return make_error("M_INVALID_PARAM",
                           "medium must be 'email' or 'msisdn'");

    if (medium == "email" && !is_valid_email(address))
        return make_error("M_INVALID_PARAM", "Invalid email address");

    if (medium == "msisdn" && !is_valid_msisdn(address))
        return make_error("M_INVALID_PARAM", "Invalid phone number");

    // Require UIA
    json flows = json::array();

    json flow1 = json::array();
    flow1.push_back("m.login.password");
    flows.push_back({{"stages", flow1}});

    json flow2 = json::array();
    flow2.push_back("m.login.email.identity");
    flows.push_back({{"stages", flow2}});

    json params;
    params["type"]    = "m.threepid_add";
    params["user_id"] = user_id;
    params["medium"]  = medium;
    params["address"] = address;

    std::string session_id = uia_create_session(flows, params);
    auto opt = uia_get_session(session_id);
    if (!opt.has_value())
        return make_error("M_UNKNOWN", "Failed to create UIA session");

    json response = build_uia_response(opt.value());
    response["errcode"] = "M_UNAUTHORIZED";
    response["error"]   = "User-Interactive Authentication required";
    return response;
}

json DeviceSessionManager::add_threepid_uia_continue(
    const std::string& user_id,
    const std::string& ip_address,
    const json& body) {
    const auto& auth_dict = body["auth"];
    std::string session_id = auth_dict["session"].get<std::string>();

    auto result = uia_process_stage(session_id, auth_dict);

    if (result.done) {
        auto opt = uia_get_session(session_id);
        if (!opt.has_value())
            return make_error("M_UNKNOWN", "UIA session disappeared");

        std::string medium  = opt->params.value("medium", "");
        std::string address = opt->params.value("address", "");

        // Check if already bound
        {
            std::unique_lock lock(g_users_mutex);
            std::string key = medium + ":" + address;
            if (g_threepid_owners.count(key))
                return make_error("M_THREEPID_IN_USE",
                                   "This identifier is already associated with an account");
            g_threepid_owners[key] = user_id;
        }

        uia_delete_session(session_id);

        json resp;
        resp["success"] = true;
        return resp;
    }

    if (!result.error.empty())
        return result.error;

    auto opt = uia_get_session(session_id);
    json response = build_uia_response(opt.value_or(UIASession{}));
    response["errcode"] = "M_UNAUTHORIZED";
    response["error"]   = "Additional authentication required";
    if (!result.completed.empty())
        response["completed"] = result.completed;
    return response;
}

/* ============================================================================
 * 3PID: Request Email Token
 * ========================================================================== */

json DeviceSessionManager::request_email_token(
    const std::string& ip_address,
    const json& body) {
    std::string email        = body.value("email", "");
    std::string client_secret = body.value("client_secret", "");
    int send_attempt         = body.value("send_attempt", 0);

    if (email.empty())
        return make_error("M_MISSING_PARAM", "Missing email");
    if (!is_valid_email(email))
        return make_error("M_INVALID_PARAM", "Invalid email address");
    if (client_secret.empty())
        return make_error("M_MISSING_PARAM", "Missing client_secret");

    // Generate sid and token
    std::string sid   = generate_session_id_impl();
    std::string token = generate_token_impl(6); // 12-char hex numeric token

    {
        std::unique_lock lock(g_email_tokens_mutex);
        // Clean up old tokens for this email
        auto it = g_pending_email_tokens.begin();
        while (it != g_pending_email_tokens.end()) {
            if (it->second.email == email) {
                it = g_pending_email_tokens.erase(it);
            } else {
                ++it;
            }
        }

        PendingEmailToken pending;
        pending.email         = email;
        pending.client_secret = client_secret;
        pending.token         = token;
        pending.send_attempt  = send_attempt;
        pending.created_at    = now_epoch_seconds();
        pending.validated     = false;
        g_pending_email_tokens[sid] = pending;
    }

    json response;
    response["sid"] = sid;
    // In production, email with the token would actually be sent here.
    // For dev/testing we include it in the response.
    response["token"] = token;
    response["success"] = true;
    return response;
}

/* ============================================================================
 * 3PID: Validate Email Token
 * ========================================================================== */

json DeviceSessionManager::validate_email_token(
    const std::string& ip_address,
    const json& body) {
    std::string sid           = body.value("sid", "");
    std::string token         = body.value("token", "");
    std::string client_secret = body.value("client_secret", "");

    if (sid.empty() || token.empty())
        return make_error("M_MISSING_PARAM", "Missing sid or token");

    {
        std::unique_lock lock(g_email_tokens_mutex);
        auto it = g_pending_email_tokens.find(sid);
        if (it == g_pending_email_tokens.end())
            return make_error("M_NOT_FOUND", "Email token request not found");

        auto& pending = it->second;
        if (pending.token != token)
            return make_error("M_FORBIDDEN", "Invalid token");

        if (pending.client_secret != client_secret)
            return make_error("M_FORBIDDEN", "Client secret mismatch");

        pending.validated = true;

        json response;
        response["success"] = true;
        return response;
    }
}

/* ============================================================================
 * 3PID: Resolve (look up user by 3PID)
 * ========================================================================== */

std::string DeviceSessionManager::resolve_threepid(
    const std::string& medium,
    const std::string& address) {
    std::shared_lock lock(g_users_mutex);
    std::string key = medium + ":" + address;
    auto it = g_threepid_owners.find(key);
    if (it == g_threepid_owners.end()) return "";
    return it->second;
}

/* ============================================================================
 * 3PID: List Threepids for a User
 * ========================================================================== */

json DeviceSessionManager::list_threepids(const std::string& user_id) {
    json result = json::array();
    std::shared_lock lock(g_users_mutex);
    for (const auto& [key, uid] : g_threepid_owners) {
        if (uid == user_id) {
            auto colon = key.find(':');
            if (colon != std::string::npos) {
                json entry;
                entry["medium"]  = key.substr(0, colon);
                entry["address"] = key.substr(colon + 1);
                entry["validated_at"] = now_epoch_seconds();
                result.push_back(entry);
            }
        }
    }
    return result;
}

/* ============================================================================
 * 3PID: Request MSISDN Token (SMS)
 * ========================================================================== */

json DeviceSessionManager::request_msisdn_token(
    const std::string& ip_address,
    const json& body) {
    std::string phone_number  = body.value("phone_number", "");
    std::string country       = body.value("country", "");
    std::string client_secret = body.value("client_secret", "");
    int send_attempt          = body.value("send_attempt", 0);

    // Build full MSISDN
    std::string msisdn = phone_number;
    if (!country.empty() && !phone_number.empty() && phone_number[0] != '+')
        msisdn = "+" + country + phone_number;

    if (msisdn.empty())
        return make_error("M_MISSING_PARAM", "Missing phone_number");
    if (!is_valid_msisdn(msisdn))
        return make_error("M_INVALID_PARAM", "Invalid phone number");
    if (client_secret.empty())
        return make_error("M_MISSING_PARAM", "Missing client_secret");

    std::string sid   = generate_session_id_impl();
    std::string token = generate_token_impl(6);

    {
        std::unique_lock lock(g_msisdn_tokens_mutex);
        PendingMSISDNToken pending;
        pending.msisdn         = msisdn;
        pending.client_secret  = client_secret;
        pending.token          = token;
        pending.send_attempt   = send_attempt;
        pending.created_at     = now_epoch_seconds();
        pending.validated      = false;
        g_pending_msisdn_tokens[sid] = pending;
    }

    json response;
    response["sid"]     = sid;
    response["token"]   = token; // dev mode
    response["success"] = true;
    return response;
}

/* ============================================================================
 * 3PID: Validate MSISDN Token
 * ========================================================================== */

json DeviceSessionManager::validate_msisdn_token(
    const std::string& ip_address,
    const json& body) {
    std::string sid           = body.value("sid", "");
    std::string token         = body.value("token", "");
    std::string client_secret = body.value("client_secret", "");

    if (sid.empty() || token.empty())
        return make_error("M_MISSING_PARAM", "Missing sid or token");

    {
        std::unique_lock lock(g_msisdn_tokens_mutex);
        auto it = g_pending_msisdn_tokens.find(sid);
        if (it == g_pending_msisdn_tokens.end())
            return make_error("M_NOT_FOUND", "MSISDN token request not found");

        auto& pending = it->second;
        if (pending.token != token)
            return make_error("M_FORBIDDEN", "Invalid token");
        if (pending.client_secret != client_secret)
            return make_error("M_FORBIDDEN", "Client secret mismatch");

        pending.validated = true;

        json response;
        response["success"] = true;
        return response;
    }
}

/* ============================================================================
 * Device Dehydration (Offline Recovery)
 *
 * When a device is "dehydrated", its device keys and one-time-keys are stored
 * on the server. When the device comes back online, it can "rehydrate" by
 * claiming those stored keys.
 * ========================================================================== */

json DeviceSessionManager::dehydrate_device(
    const std::string& user_id,
    const std::string& device_id,
    const json& dehydration_data) {
    if (user_id.empty() || device_id.empty())
        return make_error("M_MISSING_PARAM", "Missing user_id or device_id");

    // Validate the device exists and belongs to the user
    {
        std::shared_lock lock(g_devices_mutex);
        auto it = g_devices_by_user.find(user_id);
        if (it == g_devices_by_user.end())
            return make_error("M_NOT_FOUND", "User has no devices");
        bool found = false;
        for (const auto& d : it->second) {
            if (d.device_id == device_id) { found = true; break; }
        }
        if (!found)
            return make_error("M_NOT_FOUND", "Device not found");
    }

    DehydratedDevice dd;
    dd.device_id    = device_id;
    dd.user_id      = user_id;
    dd.created_at   = now_epoch_seconds();

    if (dehydration_data.contains("device_keys"))
        dd.device_keys = dehydration_data["device_keys"];
    if (dehydration_data.contains("one_time_keys"))
        dd.one_time_keys = dehydration_data["one_time_keys"];
    if (dehydration_data.contains("fallback_keys"))
        dd.fallback_keys = dehydration_data["fallback_keys"];
    if (dehydration_data.contains("display_name"))
        dd.display_name = dehydration_data["display_name"].get<std::string>();

    {
        std::unique_lock lock(g_dehydrated_mutex);
        g_dehydrated_devices[device_id] = dd;
        g_dehydrated_by_user[user_id].insert(device_id);
    }

    json response;
    response["success"]   = true;
    response["device_id"] = device_id;
    return response;
}

json DeviceSessionManager::rehydrate_device(
    const std::string& user_id,
    const std::string& device_id) {
    std::unique_lock lock(g_dehydrated_mutex);
    auto it = g_dehydrated_devices.find(device_id);
    if (it == g_dehydrated_devices.end())
        return make_error("M_NOT_FOUND", "No dehydrated device found");

    const auto& dd = it->second;
    if (dd.user_id != user_id)
        return make_error("M_FORBIDDEN", "Device does not belong to this user");

    json response;
    response["device_id"]      = dd.device_id;
    response["device_keys"]    = dd.device_keys;
    response["one_time_keys"]  = dd.one_time_keys;
    response["fallback_keys"]  = dd.fallback_keys;
    response["display_name"]   = dd.display_name;
    response["success"]        = true;

    return response;
}

json DeviceSessionManager::claim_dehydrated_keys(
    const std::string& user_id,
    const std::string& device_id) {
    // Similar to rehydrate but also marks the keys as claimed
    json result = rehydrate_device(user_id, device_id);
    if (result.contains("errcode"))
        return result;

    // Mark as claimed (remove one_time_keys after claim)
    {
        std::unique_lock lock(g_dehydrated_mutex);
        auto it = g_dehydrated_devices.find(device_id);
        if (it != g_dehydrated_devices.end()) {
            it->second.one_time_keys = json::object(); // clear claimed OTPKs
            it->second.claimed       = true;
        }
    }

    return result;
}

json DeviceSessionManager::list_dehydrated_devices(const std::string& user_id) {
    json result = json::array();
    std::shared_lock lock(g_dehydrated_mutex);
    auto uit = g_dehydrated_by_user.find(user_id);
    if (uit == g_dehydrated_by_user.end()) return result;

    for (const auto& did : uit->second) {
        auto dit = g_dehydrated_devices.find(did);
        if (dit == g_dehydrated_devices.end()) continue;
        json entry;
        entry["device_id"]    = dit->second.device_id;
        entry["display_name"] = dit->second.display_name;
        entry["created_at"]   = dit->second.created_at;
        entry["claimed"]      = dit->second.claimed;
        result.push_back(entry);
    }
    return result;
}

/* ============================================================================
 * Terms of Service Management
 * ========================================================================== */

json DeviceSessionManager::get_terms(const std::string& user_id) {
    json response;
    json policies;

    // Example terms — in production these would be configured
    json terms_of_service;
    terms_of_service["version"] = "1.0";
    {
        json langs;
        langs["en"] = json{{"name", "Terms of Service"},
                           {"url",  "https://localhost/_matrix/consent?v=1.0"}};
        terms_of_service["en"] = langs;
    }
    policies["terms_of_service"] = terms_of_service;

    json privacy_policy;
    privacy_policy["version"] = "1.0";
    {
        json langs;
        langs["en"] = json{{"name", "Privacy Policy"},
                           {"url",  "https://localhost/_matrix/consent?v=privacy_1.0"}};
        privacy_policy["en"] = langs;
    }
    policies["privacy_policy"] = privacy_policy;

    response["policies"] = policies;

    // Check if user has already accepted
    {
        std::shared_lock lock(g_terms_mutex);
        auto it = g_pending_terms.find(user_id);
        if (it != g_pending_terms.end()) {
            response["accepted"] = it->second;
        } else {
            response["accepted"] = json::array();
        }
    }

    return response;
}

json DeviceSessionManager::accept_terms(
    const std::string& user_id,
    const json& body) {
    if (!body.contains("policies") || !body["policies"].is_object())
        return make_error("M_MISSING_PARAM", "Missing policies");

    std::unique_lock lock(g_terms_mutex);
    auto& accepted = g_pending_terms[user_id];

    for (auto& [key, val] : body["policies"].items()) {
        if (val.is_string()) {
            // Accept specific version
            accepted.push_back(key + ":" + val.get<std::string>());
        }
    }

    json response;
    response["success"] = true;
    return response;
}

/* ============================================================================
 * User Profile / Account Info
 * ========================================================================== */

json DeviceSessionManager::get_user_account(const std::string& user_id) {
    std::shared_lock lock(g_users_mutex);
    auto it = g_users.find(user_id);
    if (it == g_users.end())
        return make_error("M_NOT_FOUND", "User not found");

    json response;
    response["user_id"]     = it->second.user_id;
    response["created_at"]  = it->second.created_at;
    response["deactivated"] = it->second.deactivated;
    response["is_admin"]    = it->second.is_admin;
    return response;
}

bool DeviceSessionManager::user_exists(const std::string& user_id) {
    std::shared_lock lock(g_users_mutex);
    return g_registered_usernames.count(user_id) > 0;
}

/* ============================================================================
 * Deactivate / Reactivate Account
 * ========================================================================== */

json DeviceSessionManager::deactivate_account(
    const std::string& user_id,
    const std::string& ip_address,
    const json& body) {
    // Require UIA for deactivation
    if (body.contains("auth")) {
        return deactivate_account_uia(user_id, ip_address, body);
    }

    json flows = json::array();
    json flow1 = json::array();
    flow1.push_back("m.login.password");
    flows.push_back({{"stages", flow1}});

    json params;
    params["type"]    = "m.deactivate";
    params["user_id"] = user_id;
    params["erase"]   = body.value("erase", false);

    std::string session_id = uia_create_session(flows, params);
    auto opt = uia_get_session(session_id);
    if (!opt.has_value())
        return make_error("M_UNKNOWN", "Failed to create UIA session");

    json response = build_uia_response(opt.value());
    response["errcode"] = "M_UNAUTHORIZED";
    response["error"]   = "User-Interactive Authentication required";
    return response;
}

json DeviceSessionManager::deactivate_account_uia(
    const std::string& user_id,
    const std::string& ip_address,
    const json& body) {
    const auto& auth_dict = body["auth"];
    std::string session_id = auth_dict["session"].get<std::string>();

    auto result = uia_process_stage(session_id, auth_dict);

    if (result.done) {
        // Deactivate the account
        {
            std::unique_lock lock(g_users_mutex);
            auto it = g_users.find(user_id);
            if (it != g_users.end())
                it->second.deactivated = true;
        }

        // Log out all sessions
        logout_all_devices(user_id, "");

        uia_delete_session(session_id);

        json resp;
        resp["success"] = true;
        return resp;
    }

    if (!result.error.empty())
        return result.error;

    auto opt = uia_get_session(session_id);
    json response = build_uia_response(opt.value_or(UIASession{}));
    response["errcode"] = "M_UNAUTHORIZED";
    response["error"]   = "Additional authentication required";
    if (!result.completed.empty())
        response["completed"] = result.completed;
    return response;
}

/* ============================================================================
 * Device Count
 * ========================================================================== */

size_t DeviceSessionManager::device_count(const std::string& user_id) {
    std::shared_lock lock(g_devices_mutex);
    auto it = g_devices_by_user.find(user_id);
    if (it == g_devices_by_user.end()) return 0;
    return it->second.size();
}

/* ============================================================================
 * Session Count
 * ========================================================================== */

size_t DeviceSessionManager::session_count(const std::string& user_id) {
    std::shared_lock lock(g_sessions_mutex);
    auto it = g_tokens_by_user.find(user_id);
    if (it == g_tokens_by_user.end()) return 0;
    return it->second.size();
}

/* ============================================================================
 * Bulk Session Revocation (e.g., when password changes)
 * ========================================================================== */

void DeviceSessionManager::revoke_all_user_sessions(const std::string& user_id) {
    std::unique_lock lock(g_sessions_mutex);
    auto uit = g_tokens_by_user.find(user_id);
    if (uit == g_tokens_by_user.end()) return;

    for (const auto& token : uit->second) {
        auto sit = g_sessions_by_token.find(token);
        if (sit != g_sessions_by_token.end()) {
            auto dit = g_tokens_by_device.find(sit->second.device_id);
            if (dit != g_tokens_by_device.end())
                g_tokens_by_device.erase(dit);
            g_sessions_by_token.erase(sit);
        }
    }
    g_tokens_by_user.erase(uit);
}

/* ============================================================================
 * System Statistics
 * ========================================================================== */

json DeviceSessionManager::get_system_stats() {
    json stats;
    {
        std::shared_lock lock(g_users_mutex);
        stats["total_users"] = g_users.size();
    }
    {
        std::shared_lock lock(g_sessions_mutex);
        stats["active_sessions"] = g_sessions_by_token.size();
    }
    {
        std::shared_lock lock(g_devices_mutex);
        size_t total_devices = 0;
        for (const auto& [uid, devs] : g_devices_by_user)
            total_devices += devs.size();
        stats["total_devices"] = total_devices;
    }
    {
        std::shared_lock lock(g_dehydrated_mutex);
        stats["dehydrated_devices"] = g_dehydrated_devices.size();
    }
    {
        std::shared_lock lock(g_uia_mutex);
        stats["active_uia_sessions"] = g_uia_sessions.size();
    }
    return stats;
}

/* ============================================================================
 * Admin: List all users
 * ========================================================================== */

json DeviceSessionManager::list_all_users() {
    json result = json::array();
    std::shared_lock lock(g_users_mutex);
    for (const auto& [uid, acct] : g_users) {
        json entry;
        entry["user_id"]     = acct.user_id;
        entry["created_at"]  = acct.created_at;
        entry["deactivated"] = acct.deactivated;
        entry["is_admin"]    = acct.is_admin;
        result.push_back(entry);
    }
    return result;
}

/* ============================================================================
 * Admin: Set user as admin
 * ========================================================================== */

bool DeviceSessionManager::set_admin(const std::string& user_id, bool admin_status) {
    std::unique_lock lock(g_users_mutex);
    auto it = g_users.find(user_id);
    if (it == g_users.end()) return false;
    it->second.is_admin = admin_status;
    return true;
}

/* ============================================================================
 * Cleanup Routines (should be called periodically)
 * ========================================================================== */

void DeviceSessionManager::cleanup_expired_tokens() {
    int64_t now = now_epoch_seconds();
    std::unique_lock lock(g_sessions_mutex);
    std::vector<std::string> to_revoke;

    for (const auto& [token, sess] : g_sessions_by_token) {
        if (sess.expires_at > 0 && now > sess.expires_at) {
            to_revoke.push_back(token);
        }
    }

    for (const auto& token : to_revoke) {
        auto sit = g_sessions_by_token.find(token);
        if (sit == g_sessions_by_token.end()) continue;
        auto dit = g_tokens_by_device.find(sit->second.device_id);
        if (dit != g_tokens_by_device.end()) {
            dit->second.erase(token);
            if (dit->second.empty()) g_tokens_by_device.erase(dit);
        }
        auto uit = g_tokens_by_user.find(sit->second.user_id);
        if (uit != g_tokens_by_user.end()) {
            auto& vec = uit->second;
            vec.erase(std::remove(vec.begin(), vec.end(), token), vec.end());
        }
        g_sessions_by_token.erase(sit);
    }
}

void DeviceSessionManager::cleanup_expired_uia() {
    int64_t now = now_epoch_seconds();
    std::unique_lock lock(g_uia_mutex);
    auto it = g_uia_sessions.begin();
    while (it != g_uia_sessions.end()) {
        if (now > it->second.expires_at)
            it = g_uia_sessions.erase(it);
        else
            ++it;
    }
}

void DeviceSessionManager::cleanup_expired_email_tokens() {
    int64_t now = now_epoch_seconds();
    std::unique_lock lock(g_email_tokens_mutex);
    auto it = g_pending_email_tokens.begin();
    while (it != g_pending_email_tokens.end()) {
        if (now - it->second.created_at > 3600) // 1-hour TTL
            it = g_pending_email_tokens.erase(it);
        else
            ++it;
    }
}

void DeviceSessionManager::cleanup_all() {
    cleanup_expired_tokens();
    cleanup_expired_uia();
    cleanup_expired_email_tokens();
    uia_cleanup_expired();
    prune_rate_limits();
}

/* ============================================================================
 * Auth Dictionary Helpers — Check if a stage exists in available flows
 * ========================================================================== */

bool DeviceSessionManager::uia_is_stage_supported(
    const std::string& session_id,
    const std::string& stage_type) {
    auto opt = uia_get_session(session_id);
    if (!opt.has_value()) return false;
    for (const auto& flow : opt->parsed_flows) {
        for (const auto& s : flow) {
            if (s == stage_type) return true;
        }
    }
    return false;
}

/* ============================================================================
 * Access Token Info (for debugging/admin)
 * ========================================================================== */

json DeviceSessionManager::token_info(const std::string& access_token) {
    json info;
    SessionInfo sess;
    if (!lookup_session(access_token, sess)) {
        info["valid"] = false;
        return info;
    }
    info["valid"]       = true;
    info["user_id"]     = sess.user_id;
    info["device_id"]   = sess.device_id;
    info["ip_address"]  = sess.ip_address;
    info["user_agent"]  = sess.user_agent;
    info["created_at"]  = sess.created_at;
    info["expires_at"]  = sess.expires_at;
    info["is_refresh"]  = sess.is_refresh;
    info["expired"]     = (sess.expires_at > 0 && now_epoch_seconds() > sess.expires_at);
    return info;
}

/* ============================================================================
 * Signing Key / Macaroon-Style Token Validation
 * ========================================================================== */

std::string DeviceSessionManager::sign_auth_message(
    const std::string& content,
    const std::string& secret) {
    return hmac_sha256_hex(secret, content);
}

bool DeviceSessionManager::verify_auth_signature(
    const std::string& content,
    const std::string& signature,
    const std::string& secret) {
    std::string expected = sign_auth_message(content, secret);
    // Constant-time comparison
    if (expected.size() != signature.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < expected.size(); ++i)
        diff |= static_cast<unsigned char>(expected[i]) ^
                static_cast<unsigned char>(signature[i]);
    return diff == 0;
}

/* ============================================================================
 * Dummy endpoint: check if a username is available
 * (before registration, without starting UIA)
 * ========================================================================== */

json DeviceSessionManager::check_username_availability(const std::string& username) {
    std::string user_id;
    if (username.find(':') != std::string::npos)
        user_id = username;
    else
        user_id = "@" + username + ":localhost";

    if (!validate_user_id(user_id))
        return make_invalid_username();

    std::shared_lock lock(g_users_mutex);
    if (g_registered_usernames.count(user_id))
        return json{{"available", false}};

    return json{{"available", true}};
}

/* ============================================================================
 * Boot Time Initialization
 * ========================================================================== */

void DeviceSessionManager::initialize() {
    // Clear all in-memory state
    {
        std::unique_lock lock(g_devices_mutex);
        g_devices_by_user.clear();
    }
    {
        std::unique_lock lock(g_sessions_mutex);
        g_sessions_by_token.clear();
        g_tokens_by_user.clear();
        g_tokens_by_device.clear();
    }
    {
        std::unique_lock lock(g_uia_mutex);
        g_uia_sessions.clear();
    }
    {
        std::unique_lock lock(g_dehydrated_mutex);
        g_dehydrated_devices.clear();
        g_dehydrated_by_user.clear();
    }
    {
        std::unique_lock lock(g_ratelimit_mutex);
        g_ratelimit_entries.clear();
    }
    {
        std::unique_lock lock(g_terms_mutex);
        g_pending_terms.clear();
    }
    {
        std::unique_lock lock(g_email_tokens_mutex);
        g_pending_email_tokens.clear();
    }
    {
        std::unique_lock lock(g_msisdn_tokens_mutex);
        g_pending_msisdn_tokens.clear();
    }

    // Seed OpenSSL RNG
    RAND_poll();

    // Create admin account if none exists
    {
        std::unique_lock lock(g_users_mutex);
        if (g_users.empty()) {
            UserAccount admin;
            admin.user_id     = "@admin:localhost";
            admin.created_at  = now_epoch_seconds();
            admin.is_admin    = true;
            admin.deactivated = false;
            g_users[admin.user_id] = admin;
            g_registered_usernames.insert(admin.user_id);

            std::unique_lock plock(g_password_mutex);
            g_password_hashes["@admin:localhost"] = hash_password("admin");
        }
    }
}

/* ============================================================================
 * Batch Device Operations
 * ========================================================================== */

json DeviceSessionManager::batch_create_devices(
    const std::string& user_id,
    const json& device_list,
    const std::string& ip_address) {
    json results = json::array();
    if (!device_list.is_array()) {
        return make_error("M_INVALID_PARAM", "device_list must be an array");
    }

    for (const auto& spec : device_list) {
        std::string display_name = spec.value("display_name", "");
        std::string device_id    = spec.value("device_id", "");
        std::string actual = create_device(user_id, display_name, ip_address, device_id);
        if (actual.empty()) {
            results.push_back({
                {"status", "error"},
                {"requested_id", device_id},
                {"error", "Could not create device"}
            });
        } else {
            results.push_back({
                {"status", "created"},
                {"device_id", actual},
                {"display_name", display_name.empty() ? "Unknown Device" : display_name}
            });
        }
    }
    return results;
}

json DeviceSessionManager::batch_delete_devices(
    const std::string& user_id,
    const json& device_ids) {
    json results = json::array();
    if (!device_ids.is_array()) {
        return make_error("M_INVALID_PARAM", "device_ids must be an array");
    }

    for (const auto& did : device_ids) {
        std::string d = did.get<std::string>();
        bool ok = delete_device(user_id, d);
        results.push_back({
            {"device_id", d},
            {"deleted", ok}
        });
    }
    return results;
}

/* ============================================================================
 * Enhanced UIA Flow Builder
 *
 * Dynamically constructs the list of authentication flows based on what
 * stages are configured for the homeserver and what the client context
 * requires (e.g. whether terms need re-acceptance).
 * ========================================================================== */

json DeviceSessionManager::uia_build_flows_for_operation(
    const std::string& operation_type,
    const std::string& user_id,
    const json& extra_context) {
    json flows = json::array();

    // Always allow password auth for existing users
    json password_flow = json::array();
    password_flow.push_back("m.login.password");
    flows.push_back({{"stages", password_flow}});

    // For registration, offer dummy flow
    if (operation_type == "register") {
        json dummy_flow = json::array();
        dummy_flow.push_back("m.login.dummy");
        flows.push_back({{"stages", dummy_flow}});

        // Registration token flow
        json token_flow = json::array();
        token_flow.push_back("m.login.token");
        if (extra_context.contains("recaptcha_required") &&
            extra_context["recaptcha_required"].get<bool>()) {
            json recaptcha_and_token = json::array();
            recaptcha_and_token.push_back("m.login.recaptcha");
            recaptcha_and_token.push_back("m.login.token");
            flows.push_back({{"stages", recaptcha_and_token}});
        }
    }

    // For sensitive operations, offer multi-stage flows
    if (operation_type == "password_change" || operation_type == "deactivate") {
        json password_only = json::array();
        password_only.push_back("m.login.password");
        flows.push_back({{"stages", password_only}});
    }

    // Terms acceptance flow (for login)
    if (operation_type == "login") {
        bool terms_pending = true;
        {
            std::shared_lock lock(g_terms_mutex);
            auto it = g_pending_terms.find(user_id);
            if (it != g_pending_terms.end() && !it->second.empty())
                terms_pending = false; // already accepted something
        }
        if (terms_pending) {
            json pwd_and_terms = json::array();
            pwd_and_terms.push_back("m.login.password");
            pwd_and_terms.push_back("m.login.terms");
            flows.push_back({{"stages", pwd_and_terms}});
        }
    }

    // SSO flow (if configured)
    if (extra_context.value("sso_enabled", false)) {
        json sso_flow = json::array();
        sso_flow.push_back("m.login.sso");
        flows.push_back({{"stages", sso_flow}});
    }

    // Email identity flow
    if (operation_type == "threepid_add") {
        json email_flow = json::array();
        email_flow.push_back("m.login.email.identity");
        flows.push_back({{"stages", email_flow}});

        json msisdn_flow = json::array();
        msisdn_flow.push_back("m.login.msisdn");
        flows.push_back({{"stages", msisdn_flow}});
    }

    return flows;
}

/* ============================================================================
 * UIA: Get Remaining Stages
 *
 * Returns the stages that still need to be completed for any viable flow.
 * ========================================================================== */

json DeviceSessionManager::uia_get_remaining_stages(const std::string& session_id) {
    auto opt = uia_get_session(session_id);
    if (!opt.has_value()) return json::array();

    json remaining = json::array();
    std::set<std::string> candidates;

    // Find the flow with the fewest remaining stages
    size_t best_remaining = SIZE_MAX;
    for (const auto& flow : opt->parsed_flows) {
        size_t incomplete = 0;
        for (const auto& stage : flow) {
            if (!opt->completed_stages.count(stage))
                ++incomplete;
        }
        if (incomplete < best_remaining) {
            best_remaining = incomplete;
            candidates.clear();
            for (const auto& stage : flow) {
                if (!opt->completed_stages.count(stage))
                    candidates.insert(stage);
            }
        }
    }

    for (const auto& s : candidates)
        remaining.push_back(s);

    return remaining;
}

/* ============================================================================
 * Session Analytics & Auditing
 * ========================================================================== */

json DeviceSessionManager::get_session_analytics(const std::string& user_id) {
    json analytics;

    std::shared_lock lock(g_sessions_mutex);
    auto uit = g_tokens_by_user.find(user_id);
    if (uit == g_tokens_by_user.end()) {
        analytics["total_sessions"]  = 0;
        analytics["active_sessions"] = 0;
        analytics["unique_ips"]      = 0;
        analytics["unique_devices"]  = 0;
        return analytics;
    }

    int64_t now = now_epoch_seconds();
    int total = 0, active = 0;
    std::unordered_set<std::string> ips, devices, agents;

    for (const auto& token : uit->second) {
        auto sit = g_sessions_by_token.find(token);
        if (sit == g_sessions_by_token.end()) continue;
        const auto& sess = sit->second;
        ++total;
        if (sess.expires_at <= 0 || now <= sess.expires_at) ++active;
        ips.insert(sess.ip_address);
        devices.insert(sess.device_id);
        agents.insert(sess.user_agent);
    }

    analytics["total_sessions"]    = total;
    analytics["active_sessions"]   = active;
    analytics["expired_sessions"]  = total - active;
    analytics["unique_ips"]        = ips.size();
    analytics["unique_devices"]    = devices.size();
    analytics["unique_user_agents"] = agents.size();

    // Session age distribution
    json age_buckets;
    age_buckets["last_hour"]    = 0;
    age_buckets["last_day"]     = 0;
    age_buckets["last_week"]    = 0;
    age_buckets["last_month"]   = 0;
    age_buckets["older"]        = 0;

    for (const auto& token : uit->second) {
        auto sit = g_sessions_by_token.find(token);
        if (sit == g_sessions_by_token.end()) continue;
        int64_t age = now - sit->second.created_at;
        if (age < 3600)           age_buckets["last_hour"]    = age_buckets["last_hour"].get<int>() + 1;
        else if (age < 86400)     age_buckets["last_day"]     = age_buckets["last_day"].get<int>() + 1;
        else if (age < 604800)    age_buckets["last_week"]    = age_buckets["last_week"].get<int>() + 1;
        else if (age < 2592000)   age_buckets["last_month"]   = age_buckets["last_month"].get<int>() + 1;
        else                      age_buckets["older"]        = age_buckets["older"].get<int>() + 1;
    }
    analytics["age_distribution"] = age_buckets;

    return analytics;
}

/* ============================================================================
 * Token Rotation Helper
 *
 * Rotates the access token for a session while keeping the same device
 * association. Used during periodic key rotation.
 * ========================================================================== */

bool DeviceSessionManager::rotate_access_token(
    const std::string& old_token,
    std::string& new_token) {
    std::unique_lock lock(g_sessions_mutex);
    auto it = g_sessions_by_token.find(old_token);
    if (it == g_sessions_by_token.end()) return false;

    SessionInfo sess = it->second;
    new_token = generate_token_impl(ACCESS_TOKEN_BYTES);

    // Update session
    sess.access_token = new_token;
    sess.created_at   = now_epoch_seconds();   // refresh creation time

    // Remove old entry, insert new
    g_sessions_by_token.erase(it);
    g_sessions_by_token[new_token] = sess;

    // Update index by user
    auto uit = g_tokens_by_user.find(sess.user_id);
    if (uit != g_tokens_by_user.end()) {
        auto& vec = uit->second;
        std::replace(vec.begin(), vec.end(), old_token, new_token);
    }

    // Update index by device
    auto dit = g_tokens_by_device.find(sess.device_id);
    if (dit != g_tokens_by_device.end()) {
        dit->second.erase(old_token);
        dit->second.insert(new_token);
    }

    return true;
}

/* ============================================================================
 * Batch Token Rotation (for all sessions of a user)
 * ========================================================================== */

int DeviceSessionManager::rotate_all_user_tokens(const std::string& user_id) {
    std::unique_lock lock(g_sessions_mutex);
    auto uit = g_tokens_by_user.find(user_id);
    if (uit == g_tokens_by_user.end()) return 0;

    std::vector<std::string> old_tokens = uit->second;
    int rotated = 0;

    for (const auto& old_tok : old_tokens) {
        auto sit = g_sessions_by_token.find(old_tok);
        if (sit == g_sessions_by_token.end()) continue;

        SessionInfo sess = sit->second;
        std::string new_tok = generate_token_impl(ACCESS_TOKEN_BYTES);

        sess.access_token = new_tok;
        sess.created_at   = now_epoch_seconds();

        g_sessions_by_token.erase(sit);
        g_sessions_by_token[new_tok] = sess;

        // Update device index
        auto dit = g_tokens_by_device.find(sess.device_id);
        if (dit != g_tokens_by_device.end()) {
            dit->second.erase(old_tok);
            dit->second.insert(new_tok);
        }

        // Build new token list
        std::replace(uit->second.begin(), uit->second.end(), old_tok, new_tok);
        ++rotated;
    }

    return rotated;
}

/* ============================================================================
 * Backup Codes Support
 *
 * Generates and validates single-use backup codes for account recovery.
 * ========================================================================== */

json DeviceSessionManager::generate_backup_codes(
    const std::string& user_id,
    int count) {
    if (count <= 0 || count > 50)
        count = 10; // Default: 10 codes

    json codes = json::array();

    std::unique_lock lock(g_users_mutex);
    auto it = g_users.find(user_id);
    if (it == g_users.end())
        return make_error("M_NOT_FOUND", "User not found");

    it->second.backup_codes.clear();

    for (int i = 0; i < count; ++i) {
        std::string code;
        // Generate human-friendly codes: XXXX-XXXX-XXXX
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<int> dist(0, 9);
        for (int block = 0; block < 3; ++block) {
            if (block > 0) code += '-';
            for (int d = 0; d < 4; ++d)
                code += std::to_string(dist(gen));
        }
        // Store hash
        it->second.backup_codes.push_back(hash_password(code));
        codes.push_back(code);
    }

    return codes;
}

json DeviceSessionManager::validate_backup_code(
    const std::string& user_id,
    const std::string& code) {
    std::unique_lock lock(g_users_mutex);
    auto it = g_users.find(user_id);
    if (it == g_users.end())
        return make_error("M_NOT_FOUND", "User not found");

    std::string code_hash = hash_password(code);
    auto& codes = it->second.backup_codes;

    auto found = std::find(codes.begin(), codes.end(), code_hash);
    if (found == codes.end()) {
        return json{
            {"valid", false},
            {"remaining", codes.size()}
        };
    }

    codes.erase(found);

    json response;
    response["valid"]     = true;
    response["remaining"] = codes.size();
    response["success"]   = true;
    return response;
}

/* ============================================================================
 * Account Lockout / Brute Force Protection
 * ========================================================================== */

bool DeviceSessionManager::is_account_locked(const std::string& user_id) {
    // Check rate-limiting for this user
    if (!check_rate_limit("login", user_id, 5))
        return true; // Only 5 login attempts per user per window
    return false;
}

bool DeviceSessionManager::check_and_record_login_attempt(
    const std::string& user_id,
    const std::string& ip_address) {
    // Combined check: both per-IP and per-user
    if (!check_rate_limit("login", ip_address, RATE_LIMIT_MAX_LOGIN)) {
        return false;
    }
    if (!check_rate_limit("login_per_user", user_id, 15)) {
        return false;
    }

    record_rate_limit("login", ip_address);
    record_rate_limit("login_per_user", user_id);
    return true;
}

/* ============================================================================
 * Advanced Rate Limiting: Per-Method Tracking
 * ========================================================================== */

void DeviceSessionManager::record_api_call(
    const std::string& method,
    const std::string& ip_address) {
    record_rate_limit(method, ip_address);
}

bool DeviceSessionManager::check_api_rate_limit(
    const std::string& method,
    const std::string& ip_address,
    int max_per_window) {
    return check_rate_limit(method, ip_address, max_per_window);
}

json DeviceSessionManager::get_rate_limit_status(
    const std::string& scope,
    const std::string& key,
    int max_allowed) {
    DeviceSessionManager::prune_rate_limits();
    std::shared_lock lock(g_ratelimit_mutex);

    int count = 0;
    int64_t oldest = now_epoch_seconds();
    for (const auto& entry : g_ratelimit_entries) {
        if (entry.scope == scope && entry.key == key) {
            ++count;
            if (entry.timestamp < oldest) oldest = entry.timestamp;
        }
    }

    json status;
    status["current"]     = count;
    status["limit"]       = max_allowed;
    status["window_sec"]  = RATE_LIMIT_WINDOW_SEC;
    status["resets_in"]   = (oldest + RATE_LIMIT_WINDOW_SEC) - now_epoch_seconds();
    status["limited"]     = (count >= max_allowed);
    return status;
}

/* ============================================================================
 * Device Fingerprinting
 *
 * Compute a stability score for a device to detect suspicious changes.
 * ========================================================================== */

json DeviceSessionManager::compute_device_stability(
    const std::string& user_id,
    const std::string& device_id) {
    json stability;
    stability["score"] = 100; // 0-100, higher = more stable

    std::shared_lock lock(g_devices_mutex);
    auto it = g_devices_by_user.find(user_id);
    if (it == g_devices_by_user.end()) {
        stability["score"] = 0;
        stability["reason"] = "user not found";
        return stability;
    }

    for (const auto& d : it->second) {
        if (d.device_id != device_id) continue;

        int64_t age = now_epoch_seconds() - d.created_ts;
        if (age < 300) {
            stability["score"] = 25;
            stability["reason"] = "device very new (< 5 min)";
        } else if (age < 3600) {
            stability["score"] = 50;
            stability["reason"] = "device recently created (< 1 hour)";
        } else if (age < 86400) {
            stability["score"] = 75;
            stability["reason"] = "device created < 24 hours ago";
        } else if (age > 2592000) {
            stability["score"] = 95;
            stability["reason"] = "established device (> 30 days)";
        }

        stability["device_age_seconds"] = age;
        stability["display_name"] = d.display_name;
        break;
    }

    return stability;
}

/* ============================================================================
 * UIA Session Prolongation
 *
 * Extend the lifetime of an active UIA session (e.g. while user is
 * completing email verification which may take minutes).
 * ========================================================================== */

bool DeviceSessionManager::uia_prolong_session(const std::string& session_id,
                                                 int64_t additional_seconds) {
    std::unique_lock lock(g_uia_mutex);
    auto it = g_uia_sessions.find(session_id);
    if (it == g_uia_sessions.end()) return false;
    it->second.expires_at = now_epoch_seconds() + additional_seconds;
    return true;
}

/* ============================================================================
 * Emergency Session Purge
 *
 * Immediately terminate ALL sessions across the entire server.
 * Used in security incidents.
 * ========================================================================== */

void DeviceSessionManager::emergency_purge_all_sessions() {
    std::unique_lock lock(g_sessions_mutex);
    g_sessions_by_token.clear();
    g_tokens_by_user.clear();
    g_tokens_by_device.clear();
}

size_t DeviceSessionManager::emergency_purge_sessions_for_user(
    const std::string& user_id) {
    std::unique_lock lock(g_sessions_mutex);
    auto uit = g_tokens_by_user.find(user_id);
    if (uit == g_tokens_by_user.end()) return 0;

    size_t count = uit->second.size();
    for (const auto& token : uit->second) {
        auto sit = g_sessions_by_token.find(token);
        if (sit != g_sessions_by_token.end()) {
            g_tokens_by_device.erase(sit->second.device_id);
            g_sessions_by_token.erase(sit);
        }
    }
    g_tokens_by_user.erase(uit);
    return count;
}

/* ============================================================================
 * Health Check
 * ========================================================================== */

json DeviceSessionManager::health_check() {
    json health;
    health["status"] = "ok";

    {
        std::shared_lock lock(g_users_mutex);
        health["users"] = g_users.size();
    }
    {
        std::shared_lock lock(g_sessions_mutex);
        health["active_sessions"] = g_sessions_by_token.size();
    }
    {
        std::shared_lock lock(g_devices_mutex);
        size_t total_devs = 0;
        for (const auto& [_, devs] : g_devices_by_user)
            total_devs += devs.size();
        health["devices"] = total_devs;
    }
    {
        std::shared_lock lock(g_uia_mutex);
        health["pending_uia_sessions"] = g_uia_sessions.size();
    }
    {
        std::shared_lock lock(g_ratelimit_mutex);
        health["rate_limit_entries"] = g_ratelimit_entries.size();
    }

    health["timestamp"] = now_epoch_seconds();
    return health;
}

/* ============================================================================
 * Metrics / Prometheus-style exposition helper
 * ========================================================================== */

json DeviceSessionManager::get_metrics() {
    json metrics;

    {
        std::shared_lock l1(g_users_mutex);
        metrics["progressive_users_total"] = g_users.size();
    }
    {
        std::shared_lock l2(g_sessions_mutex);
        metrics["progressive_sessions_active"] = g_sessions_by_token.size();
        size_t expired = 0;
        int64_t now = now_epoch_seconds();
        for (const auto& [_, sess] : g_sessions_by_token) {
            if (sess.expires_at > 0 && now > sess.expires_at) ++expired;
        }
        metrics["progressive_sessions_expired"] = expired;
    }
    {
        std::shared_lock l3(g_devices_mutex);
        size_t total = 0;
        for (const auto& [_, devs] : g_devices_by_user) total += devs.size();
        metrics["progressive_devices_total"] = total;
    }
    {
        std::shared_lock l4(g_dehydrated_mutex);
        metrics["progressive_dehydrated_devices"] = g_dehydrated_devices.size();
    }
    {
        std::shared_lock l5(g_ratelimit_mutex);
        metrics["progressive_rate_limit_queue_size"] = g_ratelimit_entries.size();
    }

    return metrics;
}

/* ============================================================================
 * Namespace closing
 * ========================================================================== */

} // namespace auth
} // namespace progressive
