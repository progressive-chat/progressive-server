#pragma once
// ============================================================================
// registration.hpp - C++ translation of synapse/storage/databases/main/registration.py
// Original: 3,022 lines of Python
// ============================================================================

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/engine.hpp"
#include "progressive/storage/types.hpp"

namespace progressive::storage {

using json = nlohmann::json;

// ============================================================================
// Exceptions (registration.py lines 61-72)
// ============================================================================
class ExternalIDReuseException : public std::runtime_error {
public:
  explicit ExternalIDReuseException(const std::string& msg = "")
      : std::runtime_error(msg) {}
};

class LoginTokenExpired : public std::runtime_error {
public:
  explicit LoginTokenExpired(const std::string& msg = "")
      : std::runtime_error(msg) {}
};

class LoginTokenReused : public std::runtime_error {
public:
  explicit LoginTokenReused(const std::string& msg = "")
      : std::runtime_error(msg) {}
};

// ============================================================================
// TokenLookupResult - Result of looking up an access token
// Equivalent to Python attr.s class at line 74
// ============================================================================
struct TokenLookupResult {
  std::string user_id;
  bool is_guest{false};
  std::optional<std::string> device_id;
  bool token_used{false};
  std::optional<int64_t> token_owner;
  // Shadow-banned flag
  bool shadow_banned{false};
};

// ============================================================================
// UserInfo - Information about a user
// Equivalent to synapse.types.UserInfo
// ============================================================================
struct UserInfo {
  std::string user_id;
  bool is_guest{false};
  bool is_admin{false};
  bool is_deactivated{false};
  bool is_locked{false};
  bool is_shadow_banned{false};
  std::string user_type;
  std::string display_name;
  std::optional<std::string> avatar_url;
  int64_t creation_ts{0};
  std::optional<std::string> consent_version;
};

// ============================================================================
// Threepid - Third-party identifier (email, phone, etc.)
// ============================================================================
struct Threepid {
  std::string medium;  // "email" or "msisdn"
  std::string address;
  int64_t validated_at{0};
  int64_t added_at{0};
};

// ============================================================================
// ExternalIDResult
// ============================================================================
struct ExternalIDResult {
  std::string auth_provider;
  std::string external_id;
  std::string user_id;
};

// ============================================================================
// RegistrationWorkerStore
// Equivalent to Python class RegistrationWorkerStore at line ~100
// ============================================================================
class RegistrationWorkerStore : public virtual DatabasePool {
public:
  explicit RegistrationWorkerStore(DatabasePool& db);

  // ---- User lookup ----
  // get_user_by_id (line ~120)
  std::optional<UserInfo> get_user_by_id(const std::string& user_id);

  // get_user_by_access_token (line ~180)
  std::optional<TokenLookupResult> get_user_by_access_token(
      const std::string& token);

  // get_user_by_login_token (line ~280)
  std::optional<std::string> get_user_by_login_token(
      const std::string& login_token);

  // ---- Guest management ----
  // count_guest_users (line ~340)
  int64_t count_guest_users();

  // get_guest_user_ids (line ~380)
  std::vector<std::string> get_guest_user_ids();

  // ---- External IDs ----
  // get_user_by_external_id (line ~400)
  std::optional<std::string> get_user_by_external_id(
      const std::string& auth_provider, const std::string& external_id);

  // get_external_ids_for_user (line ~430)
  std::vector<ExternalIDResult> get_external_ids_for_user(
      const std::string& user_id);

  // ---- Account validity ----
  // get_account_validity_for_user (line ~480)
  std::optional<int64_t> get_account_validity_for_user(
      const std::string& user_id);

  // is_account_expired (line ~520)
  bool is_account_expired(const std::string& user_id, int64_t current_time);

  // ---- Password management ----
  // get_password_hash (line ~560)
  std::optional<std::string> get_password_hash(const std::string& user_id);

  // ---- Expiration ----
  // set_account_validity_for_user (line ~600)
  void set_account_validity_for_user(const std::string& user_id,
                                       int64_t expiration_ts_ms);

  // set_renewal_token_for_user (line ~650)
  void set_renewal_token_for_user(const std::string& user_id,
                                    const std::string& renewal_token);

  // validate_renewal_token (line ~680)
  std::optional<std::string> validate_renewal_token(
      const std::string& renewal_token);

  // ---- User discovery ----
  // get_users_paginate (line ~730)
  struct PaginatedUsers {
    std::vector<UserInfo> users;
    int64_t total{0};
  };
  PaginatedUsers get_users_paginate(int64_t start, int64_t limit,
                                      const std::string& name_filter = "",
                                      bool guests = true, bool deactivated = false,
                                      const std::string& user_id_filter = "");

  // search_users (line ~820) - simple prefix search
  std::vector<std::string> search_users(const std::string& term, int limit = 10);

  // get_users_by_id (line ~870)
  std::map<std::string, UserInfo> get_users_by_id(
      const std::set<std::string>& user_ids);

  // get_threepids_for_user (line ~920)
  std::vector<Threepid> get_threepids_for_user(const std::string& user_id);

  // is_server_admin (line ~980)
  bool is_server_admin(const std::string& user_id);

  // is_guest (line ~1000)
  bool is_guest(const std::string& user_id);

  // is_deactivated (line ~1030)
  bool is_deactivated(const std::string& user_id);

  // is_shadow_banned (line ~1060)
  bool is_shadow_banned(const std::string& user_id);

  // get_display_name_for_user (line ~1090)
  std::optional<std::string> get_display_name_for_user(
      const std::string& user_id);

  // ---- User consent ----
  // get_consent_version (line ~1120)
  std::optional<std::string> get_consent_version(const std::string& user_id);

  // set_consent_version (line ~1160)
  void set_consent_version(const std::string& user_id,
                            const std::string& consent_version);

  // get_user_last_seen (line ~1190)
  std::optional<int64_t> get_user_last_seen(const std::string& user_id);

  // + 10 more methods from registration.py lines 1200-3022

protected:
  DatabasePool& db_;
};

// ============================================================================
// RegistrationBackgroundUpdateStore
// Equivalent to Python class RegistrationBackgroundUpdateStore at line ~1300
// ============================================================================
class RegistrationBackgroundUpdateStore : public RegistrationWorkerStore {
public:
  explicit RegistrationBackgroundUpdateStore(DatabasePool& db);

  // Background update: populate user_daily_visits
  void run_background_update_populate_user_daily_visits();

  // Background update: add full_user_id to profiles
  void run_background_update_full_user_id_profiles();
};

// ============================================================================
// RegistrationStore - Full registration storage
// Equivalent to Python class RegistrationStore at line ~1500
// ============================================================================
class RegistrationStore : public RegistrationBackgroundUpdateStore {
public:
  explicit RegistrationStore(DatabasePool& db);

  // ---- User registration ----
  // register_user (line ~1550)
  std::string register_user(
      const std::string& user_id,
      const std::optional<std::string>& password_hash = std::nullopt,
      const std::optional<std::string>& display_name = std::nullopt,
      bool is_admin = false,
      bool is_guest = false,
      const std::string& user_type = "",
      const std::optional<int64_t>& consent_version = std::nullopt);

  // create_account (line ~1650)
  std::string create_account(
      const std::string& user_id,
      const std::optional<std::string>& password_hash = std::nullopt,
      bool is_admin = false, bool is_guest = false,
      const std::string& user_type = "");

  // ---- Access token management ----
  // add_access_token_to_user (line ~1720)
  std::string add_access_token_to_user(
      const std::string& user_id,
      const std::optional<std::string>& device_id = std::nullopt,
      const std::optional<int64_t>& valid_until_ms = std::nullopt,
      const std::optional<int64_t>& token_owner = std::nullopt);

  // delete_access_token (line ~1790)
  void delete_access_token(const std::string& token);

  // delete_all_access_tokens_for_user (line ~1830)
  void delete_all_access_tokens_for_user(const std::string& user_id,
                                            const std::optional<std::string>&
                                                except_device_id = std::nullopt);

  // user_delete_access_tokens (line ~1880)
  void user_delete_access_tokens(const std::string& user_id,
                                    const std::optional<std::string>&
                                        except_token_id = std::nullopt);

  // remove_user_access_token (line ~1940)
  void remove_user_access_token(const std::string& user_id);

  // update_refresh_token (line ~1970)
  void update_refresh_token(const std::string& token,
                              int64_t next_token_id);

  // replace_refresh_token (line ~2010)
  void replace_refresh_token(const std::string& token);

  // ---- Login token management ----
  // add_login_token_to_user (line ~2060)
  std::string add_login_token_to_user(const std::string& user_id,
                                        const std::string& auth_provider_id,
                                        int64_t duration_ms);

  // mark_login_token_as_used (line ~2130)
  void mark_login_token_as_used(const std::string& login_token);

  // ---- External ID management ----
  // record_user_external_id (line ~2180)
  void record_user_external_id(const std::string& auth_provider,
                                 const std::string& external_id,
                                 const std::string& user_id);

  // ---- Password management ----
  // set_password (line ~2230)
  void set_password(const std::string& user_id,
                      const std::string& password_hash);

  // set_password_reset_token (line ~2280)
  void set_password_reset_token(const std::string& user_id,
                                  const std::string& reset_token,
                                  int64_t expiration_ts_ms);

  // get_password_reset_token (line ~2330)
  std::optional<std::pair<std::string, int64_t>> get_password_reset_token(
      const std::string& reset_token);

  // delete_password_reset_token (line ~2380)
  void delete_password_reset_token(const std::string& reset_token);

  // get_password_reset_tokens_for_user (line ~2420)
  std::vector<std::pair<std::string, int64_t>>
  get_password_reset_tokens_for_user(const std::string& user_id);

  // ---- Threepid management ----
  // user_add_threepid (line ~2480)
  void user_add_threepid(const std::string& user_id,
                          const std::string& medium,
                          const std::string& address,
                          int64_t validated_at, int64_t added_at);

  // user_delete_threepid (line ~2530)
  void user_delete_threepid(const std::string& user_id,
                               const std::string& medium,
                               const std::string& address);

  // user_delete_threepids (line ~2570)
  void user_delete_threepids(const std::string& user_id);

  // get_user_by_threepid (line ~2600)
  std::optional<std::string> get_user_by_threepid(
      const std::string& medium, const std::string& address);

  // count_all_users (line ~2640)
  int64_t count_all_users();

  // count_daily_user_type (line ~2680)
  int64_t count_daily_user_type();

  // ---- User deactivation ----
  // deactivate_account (line ~2730)
  bool deactivate_account(const std::string& user_id, bool erase_data);

  // set_shadow_banned (line ~2800)
  void set_shadow_banned(const std::string& user_id, bool banned);

  // set_user_deactivated_status (line ~2840)
  void set_user_deactivated_status(const std::string& user_id,
                                    bool deactivated);

  // set_admin (line ~2870)
  void set_admin(const std::string& user_id, bool admin);

  // set_locked (line ~2900)
  void set_locked(const std::string& user_id, bool locked);

  // ---- Session management ----
  // add_user_session (line ~2940)
  void add_user_session(const std::string& user_id,
                         const std::string& session_id);

  // get_user_sessions (line ~2980)
  std::vector<std::string> get_user_sessions(const std::string& user_id);

  // delete_user_session (line ~3000)
  void delete_user_session(const std::string& user_id,
                            const std::string& session_id);

private:
  // Helper: generate access token
  static std::string generate_token(int length = 64);

  // Helper: hach password
  static std::string hash_password(const std::string& password);

  // Helper: check admin
  void ensure_admin_not_deactivated(const std::string& user_id);
};

}  // namespace progressive::storage
