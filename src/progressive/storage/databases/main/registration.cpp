#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/database.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace progressive::storage {

// ============ Registration SQL DDL ============
namespace reg_sql {

static const char* USERS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS users (
    name TEXT NOT NULL,
    password_hash TEXT,
    is_guest BOOLEAN NOT NULL DEFAULT FALSE,
    admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_deactivated BOOLEAN NOT NULL DEFAULT FALSE,
    is_support BOOLEAN NOT NULL DEFAULT FALSE,
    user_type TEXT,
    shadow_banned BOOLEAN NOT NULL DEFAULT FALSE,
    approved BOOLEAN NOT NULL DEFAULT TRUE,
    locked BOOLEAN NOT NULL DEFAULT FALSE,
    suspended BOOLEAN NOT NULL DEFAULT FALSE,
    creation_ts BIGINT NOT NULL DEFAULT 0,
    consent_version TEXT,
    consent_server_notice_sent TEXT,
    appservice_id TEXT,
    display_name TEXT,
    avatar_url TEXT,
    deactivated BOOLEAN NOT NULL DEFAULT FALSE,
    external_ids TEXT DEFAULT '{}',
    CONSTRAINT users_pkey PRIMARY KEY (name)
);
)SQL";

static const char* ACCESS_TOKENS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS access_tokens (
    id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    device_id TEXT,
    token TEXT NOT NULL UNIQUE,
    valid_until_ms BIGINT,
    puppets_user_id TEXT,
    last_validated BIGINT NOT NULL DEFAULT 0,
    refresh_token_id BIGINT,
    used BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT access_tokens_fkey FOREIGN KEY (user_id) REFERENCES users (name)
);
CREATE INDEX IF NOT EXISTS access_tokens_user_idx ON access_tokens (user_id);
CREATE INDEX IF NOT EXISTS access_tokens_token_idx ON access_tokens (token);
)SQL";

static const char* REFRESH_TOKENS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    device_id TEXT,
    token TEXT NOT NULL UNIQUE,
    next_token_id BIGINT,
    expiry_ts BIGINT,
    ultimate_session_expiry_ts BIGINT,
    CONSTRAINT refresh_tokens_fkey FOREIGN KEY (user_id) REFERENCES users (name)
);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_idx ON refresh_tokens (user_id);
)SQL";

static const char* REGISTRATIONS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS registrations (
    token TEXT NOT NULL PRIMARY KEY,
    uses_allowed INTEGER,
    pending INTEGER NOT NULL DEFAULT 0,
    completed INTEGER NOT NULL DEFAULT 0,
    expiry_time BIGINT,
    user_id TEXT
);
)SQL";

static const char* RATELIMIT_OVERRIDES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS ratelimit_override (
    user_id TEXT NOT NULL PRIMARY KEY,
    messages_per_second BIGINT,
    burst_count BIGINT,
    CONSTRAINT ratelimit_fkey FOREIGN KEY (user_id) REFERENCES users (name)
);
)SQL";

static const char* THREEPID_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS user_threepids (
    user_id TEXT NOT NULL,
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    validated_at BIGINT NOT NULL DEFAULT 0,
    added_at BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT threepid_pkey PRIMARY KEY (user_id, medium, address)
);
CREATE INDEX IF NOT EXISTS threepid_address_idx ON user_threepids (medium, address);
)SQL";

static const char* THREEPID_VALIDATION_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS threepid_validation_session (
    session_id TEXT NOT NULL PRIMARY KEY,
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    validated_at BIGINT,
    last_send_attempt BIGINT NOT NULL DEFAULT 0,
    validated BOOLEAN NOT NULL DEFAULT FALSE,
    next_link TEXT,
    msisdn TEXT
);
)SQL";

static const char* THREEPID_INVITES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS threepid_guest_access_tokens (
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    guest_access_token TEXT NOT NULL,
    CONSTRAINT threepid_invites_pkey PRIMARY KEY (medium, address)
);
)SQL";

static const char* LOGIN_TOKENS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS login_tokens (
    token TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    expiry_ts BIGINT NOT NULL
);
)SQL";

static const char* USER_CONSENT_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS user_consent (
    user_id TEXT NOT NULL PRIMARY KEY,
    consent_version TEXT NOT NULL,
    consent_ts BIGINT NOT NULL,
    CONSTRAINT consent_fkey FOREIGN KEY (user_id) REFERENCES users (name)
);
)SQL";

static const char* EXPIRATION_URL_CACHE_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS expiration_url_cache (
    url_hash TEXT NOT NULL PRIMARY KEY,
    expiry_ts BIGINT NOT NULL,
    expiry_url TEXT NOT NULL
);
)SQL";

static const char* ACCOUNT_VALIDITY_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS account_validity (
    user_id TEXT NOT NULL PRIMARY KEY,
    expiration_ts_ms BIGINT NOT NULL,
    email_sent BOOLEAN NOT NULL DEFAULT FALSE,
    renewal_token TEXT
);
)SQL";

static const char* WHITELISTED_THREEPID_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS whitelisted_threepid (
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    CONSTRAINT whitelisted_threepid_pkey PRIMARY KEY (medium, address)
);
)SQL";

static const char* USER_IPS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS user_ips (
    user_id TEXT NOT NULL,
    access_token TEXT NOT NULL,
    device_id TEXT,
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    last_seen BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS user_ips_user_idx ON user_ips (user_id);
CREATE INDEX IF NOT EXISTS user_ips_ip_idx ON user_ips (ip);
)SQL";

static const char* USER_DAILY_VISITS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS user_daily_visits (
    user_id TEXT NOT NULL,
    device_id TEXT,
    timestamp BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS user_daily_visits_uts_idx ON user_daily_visits (user_id, timestamp);
)SQL";

static const char* DEVICES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS devices (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    display_name TEXT,
    last_seen BIGINT,
    ip TEXT,
    user_agent TEXT,
    hidden BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT devices_pkey PRIMARY KEY (user_id, device_id)
);
CREATE INDEX IF NOT EXISTS devices_user_idx ON devices (user_id);
)SQL";

static const char* USER_EXTERNAL_IDS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS user_external_ids (
    auth_provider TEXT NOT NULL,
    external_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    CONSTRAINT external_ids_pkey PRIMARY KEY (auth_provider, external_id)
);
CREATE INDEX IF NOT EXISTS external_ids_user_idx ON user_external_ids (user_id);
)SQL";

} // namespace reg_sql

// ============ Helpers ============

namespace {

std::string generate_token(int length = 32) {
  static const char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dist(0, 63);
  std::string token(length, 'A');
  for (auto& c : token) c = cs[dist(gen)];
  return token;
}

std::string hash_password(const std::string& password) {
  // In production: use bcrypt/scrypt/argon2
  // Simple SHA-256 for testing
  return "hashed:" + password;
}

bool verify_password(const std::string& password, const std::string& hash) {
  if (hash.rfind("hashed:", 0) == 0) {
    return hash.substr(7) == password;
  }
  return hash == password;
}

int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}

bool valid_user_id(const std::string& user_id) {
  // Must start with @, end with :domain, no spaces
  if (user_id.empty() || user_id[0] != '@') return false;
  auto colon = user_id.find(':');
  if (colon == std::string::npos || colon == 1 || colon == user_id.size() - 1) return false;
  for (char c : user_id) {
    if (std::isspace(c)) return false;
  }
  return true;
}

std::string canonicalize_user_id(const std::string& user_id) {
  // Lowercase the localpart
  auto colon = user_id.find(':');
  if (colon == std::string::npos) return user_id;
  std::string localpart = user_id.substr(0, colon);
  std::transform(localpart.begin(), localpart.end(), localpart.begin(), ::tolower);
  return localpart + user_id.substr(colon);
}

} // anonymous namespace

// ============ RegistrationStore Implementation ============

RegistrationStore::RegistrationStore(DatabasePool& db_pool)
    : db_pool_(db_pool) {}

// ---------- User CRUD ----------

std::string RegistrationStore::register_user_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& password_hash,
    const std::string& display_name,
    bool admin,
    bool is_guest,
    bool is_support,
    const std::string& user_type,
    const std::string& avatar_url) {
  
  std::string canonical = canonicalize_user_id(user_id);
  
  // Check if user already exists
  if (user_exists_txn(txn, canonical)) {
    return ""; // User already exists
  }
  
  int64_t ts = now_ms();
  
  txn.execute(
      "INSERT INTO users (name, password_hash, is_guest, admin, is_support, "
      "user_type, creation_ts, display_name, avatar_url, deactivated) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      {canonical, password_hash, is_guest ? 1 : 0, admin ? 1 : 0,
       is_support ? 1 : 0, user_type, ts, display_name, avatar_url, 0});
  
  return canonical;
}

bool RegistrationStore::user_exists_txn(LoggingTransaction& txn,
                                         const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT 1 FROM users WHERE name = ?", {user_id});
  return row && !row->is_null();
}

json RegistrationStore::get_user_by_id_txn(LoggingTransaction& txn,
                                            const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT name, password_hash, is_guest, admin, deactivated, user_type, "
      "creation_ts, display_name, avatar_url, shadow_banned, approved, locked, "
      "suspended, consent_version, appservice_id "
      "FROM users WHERE name = ?", {user_id});
  
  json user;
  if (row && !row->is_null()) {
    user["name"] = row->get<std::string>(0);
    if (!row->is_null(1)) user["password_hash"] = row->get<std::string>(1);
    user["is_guest"] = row->get<int64_t>(2) != 0;
    user["admin"] = row->get<int64_t>(3) != 0;
    user["deactivated"] = row->get<int64_t>(4) != 0;
    if (!row->is_null(5)) user["user_type"] = row->get<std::string>(5);
    user["creation_ts"] = row->get<int64_t>(6);
    if (!row->is_null(7)) user["display_name"] = row->get<std::string>(7);
    if (!row->is_null(8)) user["avatar_url"] = row->get<std::string>(8);
    user["shadow_banned"] = row->get<int64_t>(9) != 0;
    user["approved"] = row->get<int64_t>(10) != 0;
    user["locked"] = row->get<int64_t>(11) != 0;
    user["suspended"] = row->get<int64_t>(12) != 0;
    if (!row->is_null(13)) user["consent_version"] = row->get<std::string>(13);
    if (!row->is_null(14)) user["appservice_id"] = row->get<std::string>(14);
  }
  return user;
}

void RegistrationStore::set_password_txn(LoggingTransaction& txn,
                                          const std::string& user_id,
                                          const std::string& password_hash) {
  txn.execute(
      "UPDATE users SET password_hash = ? WHERE name = ?",
      {password_hash, user_id});
}

bool RegistrationStore::check_password_txn(LoggingTransaction& txn,
                                            const std::string& user_id,
                                            const std::string& password) {
  auto row = txn.select_one(
      "SELECT password_hash FROM users WHERE name = ? AND deactivated = 0",
      {user_id});
  if (!row || row->is_null()) return false;
  std::string hash = row->get<std::string>(0);
  return verify_password(password, hash);
}

// ---------- Account Deactivation ----------

void RegistrationStore::deactivate_account_txn(LoggingTransaction& txn,
                                                const std::string& user_id,
                                                bool erase) {
  txn.execute(
      "UPDATE users SET deactivated = 1, password_hash = NULL WHERE name = ?",
      {user_id});
  
  if (erase) {
    // Remove all access tokens
    txn.execute("DELETE FROM access_tokens WHERE user_id = ?", {user_id});
    txn.execute("DELETE FROM refresh_tokens WHERE user_id = ?", {user_id});
    // Remove threepids
    txn.execute("DELETE FROM user_threepids WHERE user_id = ?", {user_id});
    // Remove devices
    txn.execute("DELETE FROM devices WHERE user_id = ?", {user_id});
    // Leave all rooms
    txn.execute("DELETE FROM local_current_membership WHERE user_id = ?", {user_id});
  }
}

void RegistrationStore::set_shadow_banned_txn(LoggingTransaction& txn,
                                               const std::string& user_id,
                                               bool shadow_banned) {
  txn.execute(
      "UPDATE users SET shadow_banned = ? WHERE name = ?",
      {shadow_banned ? 1 : 0, user_id});
}

// ---------- Access Tokens ----------

std::string RegistrationStore::add_access_token_to_user_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& device_id,
    int64_t valid_until_ms,
    const std::string& puppets_user_id) {
  
  std::string token = generate_token(64);
  int64_t ts = now_ms();
  
  // Create refresh token
  std::string refresh_token = generate_token(48);
  int64_t expiry = valid_until_ms > 0 ? valid_until_ms : ts + 30 * 86400000LL; // 30 days
  
  txn.execute(
      "INSERT INTO refresh_tokens (user_id, device_id, token, expiry_ts) "
      "VALUES (?, ?, ?, ?)",
      {user_id, device_id, refresh_token, expiry});
  
  auto rid = txn.select_one("SELECT last_insert_rowid()");
  int64_t refresh_token_id = rid ? rid->get<int64_t>(0) : 0;
  
  txn.execute(
      "INSERT INTO access_tokens (user_id, device_id, token, valid_until_ms, "
      "puppets_user_id, last_validated, refresh_token_id) "
      "VALUES (?, ?, ?, ?, ?, ?, ?)",
      {user_id, device_id, token, valid_until_ms, puppets_user_id, ts,
       refresh_token_id});
  
  // Record device
  int64_t now_ts = now_ms();
  txn.execute(
      "INSERT INTO devices (user_id, device_id, last_seen) VALUES (?, ?, ?) "
      "ON CONFLICT (user_id, device_id) DO UPDATE SET last_seen = excluded.last_seen",
      {user_id, device_id, now_ts});
  
  return token;
}

std::optional<std::string> RegistrationStore::get_user_by_access_token_txn(
    LoggingTransaction& txn, const std::string& token) {
  auto row = txn.select_one(
      "SELECT user_id FROM access_tokens WHERE token = ? AND used = 1 "
      "AND (valid_until_ms IS NULL OR valid_until_ms > ?)",
      {token, now_ms()});
  if (row && !row->is_null()) {
    return row->get<std::string>(0);
  }
  return std::nullopt;
}

json RegistrationStore::get_user_by_token_txn(LoggingTransaction& txn,
                                               const std::string& token) {
  json result;
  auto row = txn.select_one(
      "SELECT a.user_id, a.device_id, a.valid_until_ms, a.puppets_user_id, "
      "u.admin, u.deactivated "
      "FROM access_tokens a JOIN users u ON a.user_id = u.name "
      "WHERE a.token = ? AND a.used = 1", {token});
  
  if (row && !row->is_null()) {
    result["user_id"] = row->get<std::string>(0);
    if (!row->is_null(1)) result["device_id"] = row->get<std::string>(1);
    if (!row->is_null(2)) result["valid_until_ms"] = row->get<int64_t>(2);
    if (!row->is_null(3)) result["puppets_user_id"] = row->get<std::string>(3);
    result["is_admin"] = row->get<int64_t>(4) != 0;
    result["is_deactivated"] = row->get<int64_t>(5) != 0;
  }
  return result;
}

void RegistrationStore::remove_access_token_txn(LoggingTransaction& txn,
                                                  const std::string& token) {
  txn.execute(
      "DELETE FROM access_tokens WHERE token = ?", {token});
}

void RegistrationStore::remove_all_access_tokens_for_user_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  txn.execute("DELETE FROM access_tokens WHERE user_id = ?", {user_id});
  txn.execute("DELETE FROM refresh_tokens WHERE user_id = ?", {user_id});
}

std::vector<std::string> RegistrationStore::get_user_devices_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  std::vector<std::string> result;
  auto rows = txn.select(
      "SELECT DISTINCT device_id FROM access_tokens WHERE user_id = ? AND used = 1",
      {user_id});
  for (auto& row : rows) {
    if (!row.is_null() && !row.get<std::string>(0).empty()) {
      result.push_back(row.get<std::string>(0));
    }
  }
  return result;
}

// ---------- Guest Access ----------

std::string RegistrationStore::register_guest_txn(LoggingTransaction& txn) {
  std::string guest_id = "@guest_" + generate_token(8) + ":localhost";
  return register_user_txn(txn, guest_id, "", "Guest User", false, true);
}

// ---------- Registration Tokens ----------

std::string RegistrationStore::create_registration_token_txn(
    LoggingTransaction& txn,
    int uses_allowed,
    int64_t expiry_time,
    const std::string& user_id) {
  std::string token = generate_token(32);
  
  txn.execute(
      "INSERT INTO registrations (token, uses_allowed, pending, completed, expiry_time, user_id) "
      "VALUES (?, ?, 0, 0, ?, ?)",
      {token, uses_allowed, expiry_time, user_id});
  
  return token;
}

bool RegistrationStore::validate_registration_token_txn(
    LoggingTransaction& txn, const std::string& token) {
  auto row = txn.select_one(
      "SELECT uses_allowed, pending, completed, expiry_time "
      "FROM registrations WHERE token = ?", {token});
  
  if (!row || row->is_null()) return false;
  
  int uses_allowed = row->is_null(0) ? -1 : row->get<int>(0);
  int pending = row->get<int>(1);
  int completed = row->is_null(2) ? 0 : row->get<int>(2);
  int64_t expiry = row->is_null(3) ? 0 : row->get<int64_t>(3);
  
  if (expiry > 0 && expiry < now_ms()) return false;
  if (uses_allowed > 0 && (pending + completed) >= uses_allowed) return false;
  
  txn.execute(
      "UPDATE registrations SET pending = pending + 1 WHERE token = ?", {token});
  return true;
}

void RegistrationStore::complete_registration_token_txn(
    LoggingTransaction& txn, const std::string& token) {
  txn.execute(
      "UPDATE registrations SET pending = MAX(pending - 1, 0), "
      "completed = completed + 1 WHERE token = ?", {token});
}

// ---------- Threepid (Email/Phone) Association ----------

void RegistrationStore::add_user_threepid_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& medium,
    const std::string& address,
    int64_t validated_at,
    int64_t added_at) {
  txn.execute(
      "INSERT INTO user_threepids (user_id, medium, address, validated_at, added_at) "
      "VALUES (?, ?, ?, ?, ?)",
      {user_id, medium, address, validated_at, added_at > 0 ? added_at : now_ms()});
}

void RegistrationStore::remove_user_threepid_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& medium,
    const std::string& address) {
  txn.execute(
      "DELETE FROM user_threepids WHERE user_id = ? AND medium = ? AND address = ?",
      {user_id, medium, address});
}

std::vector<json> RegistrationStore::get_user_threepids_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  std::vector<json> result;
  auto rows = txn.select(
      "SELECT medium, address, validated_at, added_at "
      "FROM user_threepids WHERE user_id = ?", {user_id});
  for (auto& row : rows) {
    json tp;
    tp["medium"] = row.get<std::string>(0);
    tp["address"] = row.get<std::string>(1);
    tp["validated_at"] = row.get<int64_t>(2);
    tp["added_at"] = row.get<int64_t>(3);
    result.push_back(tp);
  }
  return result;
}

std::optional<std::string> RegistrationStore::get_user_by_threepid_txn(
    LoggingTransaction& txn,
    const std::string& medium,
    const std::string& address) {
  auto row = txn.select_one(
      "SELECT user_id FROM user_threepids WHERE medium = ? AND address = ?",
      {medium, address});
  if (row && !row->is_null()) {
    return row->get<std::string>(0);
  }
  return std::nullopt;
}

bool RegistrationStore::is_threepid_associated_txn(
    LoggingTransaction& txn,
    const std::string& medium,
    const std::string& address) {
  auto row = txn.select_one(
      "SELECT 1 FROM user_threepids WHERE medium = ? AND address = ?",
      {medium, address});
  return row && !row->is_null();
}

// ---------- ThreePID Validation ----------

std::string RegistrationStore::create_threepid_validation_session_txn(
    LoggingTransaction& txn,
    const std::string& medium,
    const std::string& address,
    const std::string& client_secret,
    const std::string& next_link) {
  std::string session_id = generate_token(32);
  int64_t ts = now_ms();
  
  txn.execute(
      "INSERT INTO threepid_validation_session "
      "(session_id, medium, address, client_secret, last_send_attempt) "
      "VALUES (?, ?, ?, ?, ?)",
      {session_id, medium, address, client_secret, ts});
  
  return session_id;
}

std::optional<json> RegistrationStore::get_threepid_validation_session_txn(
    LoggingTransaction& txn, const std::string& session_id) {
  auto row = txn.select_one(
      "SELECT session_id, medium, address, client_secret, validated_at, "
      "last_send_attempt, validated, next_link "
      "FROM threepid_validation_session WHERE session_id = ?", {session_id});
  
  if (row && !row->is_null()) {
    json sess;
    sess["session_id"] = row->get<std::string>(0);
    sess["medium"] = row->get<std::string>(1);
    sess["address"] = row->get<std::string>(2);
    sess["client_secret"] = row->get<std::string>(3);
    if (!row->is_null(4)) sess["validated_at"] = row->get<int64_t>(4);
    sess["last_send_attempt"] = row->get<int64_t>(5);
    sess["validated"] = row->get<int64_t>(6) != 0;
    if (!row->is_null(7)) sess["next_link"] = row->get<std::string>(7);
    return sess;
  }
  return std::nullopt;
}

void RegistrationStore::validate_threepid_session_txn(
    LoggingTransaction& txn,
    const std::string& session_id) {
  txn.execute(
      "UPDATE threepid_validation_session SET validated = 1, validated_at = ? "
      "WHERE session_id = ?", {now_ms(), session_id});
}

// ---------- Threepid invites ----------

std::string RegistrationStore::make_threepid_invite_token_txn(
    LoggingTransaction& txn,
    const std::string& medium,
    const std::string& address) {
  std::string token = generate_token(32);
  txn.execute(
      "INSERT OR REPLACE INTO threepid_guest_access_tokens "
      "(medium, address, guest_access_token) VALUES (?, ?, ?)",
      {medium, address, token});
  return token;
}

std::optional<std::string> RegistrationStore::get_threepid_invite_txn(
    LoggingTransaction& txn,
    const std::string& medium,
    const std::string& address) {
  auto row = txn.select_one(
      "SELECT guest_access_token FROM threepid_guest_access_tokens "
      "WHERE medium = ? AND address = ?", {medium, address});
  if (row && !row->is_null()) {
    return row->get<std::string>(0);
  }
  return std::nullopt;
}

// ---------- Account Validity ----------

void RegistrationStore::set_account_validity_for_user_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    int64_t expiration_ts_ms,
    bool email_sent) {
  txn.execute(
      "INSERT INTO account_validity (user_id, expiration_ts_ms, email_sent) "
      "VALUES (?, ?, ?) "
      "ON CONFLICT (user_id) DO UPDATE SET "
      "expiration_ts_ms = excluded.expiration_ts_ms, email_sent = excluded.email_sent",
      {user_id, expiration_ts_ms, email_sent ? 1 : 0});
}

std::optional<int64_t> RegistrationStore::get_account_validity_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT expiration_ts_ms FROM account_validity WHERE user_id = ?", {user_id});
  if (row && !row->is_null()) {
    return row->get<int64_t>(0);
  }
  return std::nullopt;
}

// ---------- Rate Limit Overrides ----------

void RegistrationStore::set_ratelimit_override_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    int64_t messages_per_second,
    int64_t burst_count) {
  txn.execute(
      "INSERT INTO ratelimit_override (user_id, messages_per_second, burst_count) "
      "VALUES (?, ?, ?) ON CONFLICT (user_id) DO UPDATE SET "
      "messages_per_second = excluded.messages_per_second, "
      "burst_count = excluded.burst_count",
      {user_id, messages_per_second, burst_count});
}

std::optional<json> RegistrationStore::get_ratelimit_override_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT messages_per_second, burst_count FROM ratelimit_override WHERE user_id = ?",
      {user_id});
  if (row && !row->is_null()) {
    json override;
    override["messages_per_second"] = row->get<int64_t>(0);
    override["burst_count"] = row->get<int64_t>(1);
    return override;
  }
  return std::nullopt;
}

// ---------- Admin Queries ----------

std::vector<json> RegistrationStore::get_users_paginate_txn(
    LoggingTransaction& txn, int64_t start, int64_t limit,
    const std::string& name_filter, bool guests, bool deactivated) {
  std::vector<json> result;
  
  std::vector<std::string> conditions;
  std::vector<DatabaseType> params;
  
  if (!guests) conditions.push_back("is_guest = 0");
  if (!deactivated) conditions.push_back("deactivated = 0");
  if (!name_filter.empty()) {
    conditions.push_back("name LIKE ?");
    params.push_back("%" + name_filter + "%");
  }
  
  std::string where = conditions.empty() ? "" : 
      "WHERE " + [&]() { 
        std::string s;
        for (size_t i = 0; i < conditions.size(); ++i) {
          if (i > 0) s += " AND ";
          s += conditions[i];
        }
        return s;
      }();
  
  std::string query = "SELECT name, is_guest, admin, deactivated, user_type, "
      "creation_ts, display_name, avatar_url FROM users " + where + 
      " ORDER BY name LIMIT ? OFFSET ?";
  params.push_back(limit);
  params.push_back(start);
  
  auto rows = txn.select(query, params);
  for (auto& row : rows) {
    json u;
    u["name"] = row.get<std::string>(0);
    u["is_guest"] = row.get<int64_t>(1) != 0;
    u["admin"] = row.get<int64_t>(2) != 0;
    u["deactivated"] = row.get<int64_t>(3) != 0;
    if (!row.is_null(4)) u["user_type"] = row.get<std::string>(4);
    u["creation_ts"] = row.get<int64_t>(5);
    if (!row.is_null(6)) u["display_name"] = row.get<std::string>(6);
    if (!row.is_null(7)) u["avatar_url"] = row.get<std::string>(7);
    result.push_back(u);
  }
  return result;
}

int64_t RegistrationStore::count_users_txn(LoggingTransaction& txn) {
  auto row = txn.select_one("SELECT COUNT(*) FROM users");
  return row ? row->get<int64_t>(0) : 0;
}

int64_t RegistrationStore::count_daily_active_users_txn(
    LoggingTransaction& txn, int64_t since_ts) {
  auto row = txn.select_one(
      "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits WHERE timestamp > ?",
      {since_ts});
  return row ? row->get<int64_t>(0) : 0;
}

int64_t RegistrationStore::count_monthly_active_users_txn(
    LoggingTransaction& txn, int64_t since_ts) {
  auto row = txn.select_one(
      "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits WHERE timestamp > ?",
      {since_ts});
  return row ? row->get<int64_t>(0) : 0;
}

// ---------- Login Tokens ----------

std::string RegistrationStore::create_login_token_txn(
    LoggingTransaction& txn, const std::string& user_id, int64_t duration_ms) {
  std::string token = generate_token(32);
  int64_t expiry = now_ms() + duration_ms;
  
  txn.execute(
      "INSERT INTO login_tokens (token, user_id, expiry_ts) VALUES (?, ?, ?)",
      {token, user_id, expiry});
  
  return token;
}

std::optional<std::string> RegistrationStore::get_user_by_login_token_txn(
    LoggingTransaction& txn, const std::string& token) {
  auto row = txn.select_one(
      "SELECT user_id, expiry_ts FROM login_tokens WHERE token = ? AND expiry_ts > ?",
      {token, now_ms()});
  if (row && !row->is_null()) {
    return row->get<std::string>(0);
  }
  return std::nullopt;
}

void RegistrationStore::invalidate_login_token_txn(
    LoggingTransaction& txn, const std::string& token) {
  txn.execute("DELETE FROM login_tokens WHERE token = ?", {token});
}

// ---------- User Consent ----------

void RegistrationStore::save_user_consent_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& consent_version,
    int64_t consent_ts) {
  txn.execute(
      "INSERT INTO user_consent (user_id, consent_version, consent_ts) "
      "VALUES (?, ?, ?) ON CONFLICT (user_id) DO UPDATE SET "
      "consent_version = excluded.consent_version, consent_ts = excluded.consent_ts",
      {user_id, consent_version, consent_ts});
  
  // Also update users table
  txn.execute(
      "UPDATE users SET consent_version = ?, consent_server_notice_sent = ? WHERE name = ?",
      {consent_version, consent_version, user_id});
}

std::optional<std::string> RegistrationStore::get_user_consent_version_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT consent_version FROM user_consent WHERE user_id = ?", {user_id});
  if (row && !row->is_null()) {
    return row->get<std::string>(0);
  }
  // Fallback to users table
  auto row2 = txn.select_one(
      "SELECT consent_version FROM users WHERE name = ?", {user_id});
  if (row2 && !row2->is_null() && !row2->get<std::string>(0).empty()) {
    return row2->get<std::string>(0);
  }
  return std::nullopt;
}

// ---------- IP Tracking ----------

void RegistrationStore::record_user_ip_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& access_token,
    const std::string& device_id,
    const std::string& ip,
    const std::string& user_agent) {
  int64_t ts = now_ms();
  
  txn.execute(
      "INSERT INTO user_ips (user_id, access_token, device_id, ip, user_agent, last_seen) "
      "VALUES (?, ?, ?, ?, ?, ?)",
      {user_id, access_token, device_id, ip, user_agent, ts});
}

std::vector<json> RegistrationStore::get_user_ips_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  std::vector<json> result;
  auto rows = txn.select(
      "SELECT access_token, device_id, ip, user_agent, last_seen "
      "FROM user_ips WHERE user_id = ? ORDER BY last_seen DESC",
      {user_id});
  for (auto& row : rows) {
    json entry;
    entry["access_token"] = row.get<std::string>(0);
    if (!row.is_null(1)) entry["device_id"] = row.get<std::string>(1);
    entry["ip"] = row.get<std::string>(2);
    entry["user_agent"] = row.get<std::string>(3);
    entry["last_seen"] = row.get<int64_t>(4);
    result.push_back(entry);
  }
  return result;
}

std::string RegistrationStore::get_last_seen_ip_for_user_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT ip FROM user_ips WHERE user_id = ? ORDER BY last_seen DESC LIMIT 1",
      {user_id});
  if (row && !row->is_null()) return row->get<std::string>(0);
  return "";
}

// ---------- External IDs (OIDC/SAML) ----------

void RegistrationStore::record_user_external_id_txn(
    LoggingTransaction& txn,
    const std::string& auth_provider,
    const std::string& external_id,
    const std::string& user_id) {
  txn.execute(
      "INSERT INTO user_external_ids (auth_provider, external_id, user_id) "
      "VALUES (?, ?, ?) ON CONFLICT (auth_provider, external_id) DO NOTHING",
      {auth_provider, external_id, user_id});
  
  // Update users.external_ids JSON
  auto existing = txn.select_one(
      "SELECT external_ids FROM users WHERE name = ?", {user_id});
  json external;
  if (existing && !existing->is_null()) {
    external = json::parse(existing->get<std::string>(0));
  }
  external[auth_provider] = external_id;
  txn.execute(
      "UPDATE users SET external_ids = ? WHERE name = ?",
      {external.dump(), user_id});
}

std::optional<std::string> RegistrationStore::get_user_by_external_id_txn(
    LoggingTransaction& txn,
    const std::string& auth_provider,
    const std::string& external_id) {
  auto row = txn.select_one(
      "SELECT user_id FROM user_external_ids "
      "WHERE auth_provider = ? AND external_id = ?",
      {auth_provider, external_id});
  if (row && !row->is_null()) {
    return row->get<std::string>(0);
  }
  return std::nullopt;
}

// ---------- Profile (display name / avatar) ----------

void RegistrationStore::set_display_name_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& display_name) {
  txn.execute(
      "UPDATE users SET display_name = ? WHERE name = ?",
      {display_name, user_id});
}

std::optional<std::string> RegistrationStore::get_display_name_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT display_name FROM users WHERE name = ?", {user_id});
  if (row && !row->is_null() && !row->get<std::string>(0).empty()) {
    return row->get<std::string>(0);
  }
  return std::nullopt;
}

void RegistrationStore::set_avatar_url_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& avatar_url) {
  txn.execute(
      "UPDATE users SET avatar_url = ? WHERE name = ?",
      {avatar_url, user_id});
}

std::optional<std::string> RegistrationStore::get_avatar_url_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT avatar_url FROM users WHERE name = ?", {user_id});
  if (row && !row->is_null() && !row->get<std::string>(0).empty()) {
    return row->get<std::string>(0);
  }
  return std::nullopt;
}

// ---------- Server Notices ----------

void RegistrationStore::set_server_notice_sent_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& consent_version) {
  txn.execute(
      "UPDATE users SET consent_server_notice_sent = ? WHERE name = ?",
      {consent_version, user_id});
}

bool RegistrationStore::was_server_notice_sent_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& consent_version) {
  auto row = txn.select_one(
      "SELECT consent_server_notice_sent FROM users WHERE name = ?", {user_id});
  if (row && !row->is_null() && row->get<std::string>(0) == consent_version) {
    return true;
  }
  return false;
}

// ---------- Appservice users ----------

void RegistrationStore::set_appservice_id_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& appservice_id) {
  txn.execute(
      "UPDATE users SET appservice_id = ? WHERE name = ?",
      {appservice_id, user_id});
}

std::optional<std::string> RegistrationStore::get_appservice_id_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT appservice_id FROM users WHERE name = ?", {user_id});
  if (row && !row->is_null() && !row->get<std::string>(0).empty()) {
    return row->get<std::string>(0);
  }
  return std::nullopt;
}

} // namespace progressive::storage
