#pragma once
// ============================================================================
// end_to_end_keys.hpp - C++ translation of end_to_end_keys.py (1,894 lines)
// ============================================================================

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"

namespace progressive::storage {

using json = nlohmann::json;

// ============================================================================
// DeviceKeyLookupResult - Result of E2E device key lookup
// Equivalent to Python attr.s class at line 68
// ============================================================================
struct DeviceKeyLookupResult {
  std::optional<std::string> display_name;
  json keys;  // The key data from e2e_device_keys_json
};

// ============================================================================
// CrossSigningKeyInfo - Cross-signing key data
// ============================================================================
struct CrossSigningKeyInfo {
  std::string user_id;
  std::string key_type;  // "master", "self_signing", "user_signing"
  std::string key_data;  // JSON string
};

// ============================================================================
// SignatureListItem - Item in signature list
// ============================================================================
struct SignatureListItem {
  std::string user_id;
  std::string device_id;
  std::string signature;
};

// ============================================================================
// EndToEndKeyWorkerStore
// Equivalent to Python class EndToEndKeyWorkerStore at line ~100
// ============================================================================
class EndToEndKeyWorkerStore {
public:
  explicit EndToEndKeyWorkerStore(DatabasePool& db);

  // get_e2e_device_keys_for_federation (line ~150)
  std::map<std::string, std::map<std::string, json>>
  get_e2e_device_keys_for_federation(const std::string& user_id);

  // get_e2e_device_keys_and_signatures (line ~250)
  struct DeviceKeyResult {
    std::map<std::string, std::map<std::string, DeviceKeyLookupResult>>
        device_keys;
    std::map<std::string, std::map<std::string, json>> signatures;
    std::map<std::string, std::map<std::string, json>>
        one_time_key_counts;
  };
  DeviceKeyResult get_e2e_device_keys_and_signatures(
      const std::string& query_user_id,
      const std::vector<std::string>& device_ids);

  // get_e2e_one_time_keys (line ~400)
  std::map<std::string, std::map<std::string, json>>
  get_e2e_one_time_keys(const std::string& user_id,
                          const std::string& device_id,
                          const std::vector<std::string>& algorithm,
                          int64_t limit = 10);

  // count_e2e_one_time_keys (line ~500)
  std::map<std::string, int64_t> count_e2e_one_time_keys(
      const std::string& user_id, const std::string& device_id);

  // get_e2e_unused_fallback_key_types (line ~560)
  std::vector<std::string> get_e2e_unused_fallback_key_types(
      const std::string& user_id, const std::string& device_id);

  // get_e2e_cross_signing_keys_bulk (line ~620)
  std::map<std::string, std::map<std::string, json>>
  get_e2e_cross_signing_keys_bulk(
      const std::set<std::string>& user_ids);

  // get_e2e_cross_signing_key (line ~700)
  std::optional<json> get_e2e_cross_signing_key(
      const std::string& user_id, const std::string& key_type);

  // get_all_user_signature_changes_for_remotes (line ~760)
  std::vector<SignatureListItem>
  get_all_user_signature_changes_for_remotes(int64_t from_token,
                                               int64_t to_token);

  // count_bulk_e2e_one_time_keys (line ~830)
  std::map<std::string, std::map<std::string, std::map<std::string, int64_t>>>
  count_bulk_e2e_one_time_keys(const std::set<std::string>& user_ids);

  // is_master_cross_signing_key_known (line ~890)
  bool is_master_cross_signing_key_known(const std::string& user_id);

protected:
  DatabasePool& db_;
};

// ============================================================================
// EndToEndBackgroundUpdateStore
// Equivalent to Python class at line ~950
// ============================================================================
class EndToEndBackgroundUpdateStore : public EndToEndKeyWorkerStore {
public:
  explicit EndToEndBackgroundUpdateStore(DatabasePool& db);

  // Background: e2e_one_time_keys_idx
  void run_background_e2e_one_time_keys_idx();

  // Background: e2e_fallback_keys_idx
  void run_background_e2e_fallback_keys_idx();
};

// ============================================================================
// EndToEndKeyStore - Full E2E key storage
// Equivalent to Python class EndToEndKeyStore at line ~1050
// ============================================================================
class EndToEndKeyStore : public EndToEndBackgroundUpdateStore {
public:
  explicit EndToEndKeyStore(DatabasePool& db);

  // ---- Device keys ----
  // set_e2e_device_keys (line ~1100)
  void set_e2e_device_keys(const std::string& user_id,
                              const std::string& device_id,
                              int64_t time_now,
                              const json& device_keys);

  // delete_e2e_device_keys_for_device (line ~1180)
  void delete_e2e_device_keys_for_device(const std::string& user_id,
                                            const std::string& device_id);

  // claim_e2e_one_time_keys (line ~1240)
  std::map<std::string, std::map<std::string, std::map<std::string, json>>>
  claim_e2e_one_time_keys(
      const std::map<std::string,
                     std::map<std::string, std::map<std::string, int>>>&
          query_list,
      int64_t timeout_ms = 60000);

  // add_e2e_one_time_keys (line ~1360)
  void add_e2e_one_time_keys(
      const std::string& user_id, const std::string& device_id,
      int64_t time_now,
      const std::map<std::string, std::map<std::string, json>>& keys);

  // set_e2e_fallback_keys (line ~1440)
  void set_e2e_fallback_keys(
      const std::string& user_id, const std::string& device_id,
      const std::map<std::string, json>& fallback_keys);

  // set_e2e_cross_signing_key (line ~1510)
  void set_e2e_cross_signing_key(const std::string& user_id,
                                    const std::string& key_type,
                                    const json& key,
                                    int64_t stream_id);

  // store_e2e_cross_signing_signatures (line ~1580)
  void store_e2e_cross_signing_signatures(
      const std::string& user_id,
      const std::map<std::string, std::map<std::string, std::string>>&
          signatures);

  // delete_e2e_keys_for_user (line ~1650)
  void delete_e2e_keys_for_user(const std::string& user_id);

  // count_one_time_keys_for_device (line ~1700)
  std::map<std::string, int64_t> count_one_time_keys_for_device(
      const std::string& user_id, const std::string& device_id);

  // get_e2e_device_keys_txn (line ~1760)
  std::map<std::string, json> get_e2e_device_keys_txn(
      LoggingTransaction& txn, const std::string& user_id,
      const std::string& device_id);

  // claim_e2e_fallback_keys (line ~1830)
  std::map<std::string, std::map<std::string, json>>
  claim_e2e_fallback_keys(
      const std::string& user_id, const std::string& device_id,
      const std::vector<std::string>& algorithms);

private:
  // Helper: parse key JSON
  static json parse_key_json(const std::string& json_str);

  // Helper: determine if a key is expired
  static bool is_key_expired(int64_t ts, int64_t now,
                               int64_t timeout_ms);
};

}  // namespace progressive::storage
