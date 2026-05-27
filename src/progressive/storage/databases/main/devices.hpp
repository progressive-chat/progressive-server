#pragma once
// ============================================================================
// devices.hpp - C++ translation of synapse/storage/databases/main/devices.py
// Original: 2,806 lines of Python
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
// DeviceInfo - Information about a user's device
// Equivalent to Python data class
// ============================================================================
struct DeviceInfo {
  std::string device_id;
  std::string user_id;
  std::optional<std::string> display_name;
  std::optional<std::string> last_seen_ip;
  std::optional<std::string> last_seen_user_agent;
  int64_t last_seen_ts{0};
  std::optional<std::string> device_type;
  bool hidden{false};
};

// ============================================================================
// DeviceListEntry - Entry in device_lists_stream
// Equivalent to Python class at line ~150
// ============================================================================
struct DeviceListEntry {
  std::string user_id;
  std::string device_id;
  int64_t stream_id{0};
};

// ============================================================================
// DeviceMaxStreamID
// ============================================================================
struct DeviceMaxStreamID {
  int64_t stream_id{0};
};

// ============================================================================
// DeviceWorkerStore - Worker-level device operations
// Equivalent to Python class DeviceWorkerStore at line ~200
// ============================================================================
class DeviceWorkerStore {
public:
  explicit DeviceWorkerStore(DatabasePool& db);

  // get_device (line ~250)
  std::optional<DeviceInfo> get_device(const std::string& user_id,
                                         const std::string& device_id);

  // get_devices_by_user (line ~320)
  std::vector<DeviceInfo> get_devices_by_user(const std::string& user_id);

  // get_devices_by_auth_id (line ~380)
  std::vector<DeviceInfo> get_devices_by_auth_id(
      const std::string& user_id);

  // get_device_update_token_for_user (line ~440)
  std::optional<std::string> get_device_update_token_for_user(
      const std::string& user_id);

  // get_number_of_devices_by_user (line ~490)
  int64_t get_number_of_devices_by_user(const std::string& user_id);

  // get_device_stream_token (line ~540)
  int64_t get_device_stream_token();

  // get_all_device_list_changes_for_remotes (line ~600)
  std::vector<DeviceListEntry> get_all_device_list_changes_for_remotes(
      int64_t from_stream_id, int64_t to_stream_id);

  // get_user_devices_from_cache (line ~680)
  std::map<std::string, std::vector<json>> get_user_devices_from_cache(
      const std::set<std::string>& user_ids);

  // get_device_list_last_stream_id_for_remote (line ~750)
  int64_t get_device_list_last_stream_id_for_remote(
      const std::string& user_id);

  // mark_remote_user_device_list_as_received (line ~800)
  void mark_remote_user_device_list_as_received(
      const std::string& user_id);

  // is_device_list_outdated (line ~850)
  bool is_device_list_outdated(const std::string& user_id,
                                 int64_t current_stream_id);

  // get_cached_devices_for_user (line ~920)
  std::optional<std::vector<DeviceInfo>> get_cached_devices_for_user(
      const std::string& user_id);

  // store_device_list_update (internal, line ~1000)
  void store_device_list_update_txn(LoggingTransaction& txn,
                                      const std::string& user_id,
                                      const std::string& device_id,
                                      int64_t stream_id);

protected:
  DatabasePool& db_;
};

// ============================================================================
// DeviceBackgroundUpdateStore
// Equivalent to Python class DeviceBackgroundUpdateStore at line ~1100
// ============================================================================
class DeviceBackgroundUpdateStore : public DeviceWorkerStore {
public:
  explicit DeviceBackgroundUpdateStore(DatabasePool& db);

  // Background update: last_seen index
  void run_background_device_last_seen_idx();

  // Background update: device_list_stream_idx (line ~1170)
  void run_background_device_list_stream_idx();

  // Background update: hidden devices index
  void run_background_device_hidden_idx();
};

// ============================================================================
// DeviceStore - Full device operations
// Equivalent to Python class DeviceStore at line ~1300
// ============================================================================
class DeviceStore : public DeviceBackgroundUpdateStore {
public:
  explicit DeviceStore(DatabasePool& db);

  // ---- Device CRUD ----
  // store_device (line ~1350)
  std::string store_device(
      const std::string& user_id, const std::string& device_id,
      const std::optional<std::string>& initial_device_display_name =
          std::nullopt);

  // delete_device (line ~1430)
  void delete_device(const std::string& user_id,
                       const std::string& device_id);

  // delete_all_devices_for_user (line ~1490)
  void delete_all_devices_for_user(const std::string& user_id,
                                      const std::optional<std::string>&
                                          except_device_id = std::nullopt);

  // update_device (line ~1560)
  void update_device(const std::string& user_id,
                       const std::string& device_id,
                       const std::optional<std::string>& display_name =
                           std::nullopt,
                       const std::optional<std::string>& device_type =
                           std::nullopt,
                       bool hidden = false);

  // update_device_last_seen (line ~1640)
  void update_device_last_seen(const std::string& user_id,
                                  const std::string& device_id,
                                  const std::string& ip_address,
                                  const std::string& user_agent);

  // ---- Device lists (federation) ----
  // mark_device_list_as_streamed (line ~1730)
  void mark_device_list_as_streamed(const std::string& user_id,
                                       const std::string& device_id,
                                       int64_t stream_id);

  // add_device_change_to_stream (line ~1790)
  int64_t add_device_change_to_stream(const std::string& user_id,
                                        const std::vector<std::string>&
                                            device_ids,
                                        const std::string& host);

  // add_device_list_outlier (line ~1860)
  void add_device_list_outlier(const std::string& user_id);

  // ---- Device inbox ----
  // add_messages_to_device_inbox (line ~1930)
  void add_messages_to_device_inbox(
      const std::string& local_user_id,
      const std::string& message_id,
      const std::map<std::string, std::map<std::string, json>>&
          messages_by_device);

  // get_to_device_messages (line ~2030)
  std::vector<json> get_to_device_messages(const std::string& user_id);

  // delete_messages_for_device (line ~2110)
  void delete_messages_for_device(const std::string& user_id,
                                     const std::string& device_id,
                                     int64_t up_to_stream_id);

  // delete_all_messages_for_device (line ~2180)
  void delete_all_messages_for_device(const std::string& user_id,
                                         const std::string& device_id);

  // ---- Device list federation ----
  // get_users_whose_devices_changed (line ~2250)
  std::map<std::string, std::vector<std::string>>
  get_users_whose_devices_changed(int64_t from_stream_id,
                                    int64_t to_stream_id);

  // get_unpartnered_devices (line ~2330)
  std::vector<std::string> get_unpartnered_devices(
      const std::string& user_id,
      const std::set<std::string>& partner_device_ids);

  // count_devices_by_users (line ~2400)
  std::map<std::string, int64_t> count_devices_by_users(
      const std::set<std::string>& user_ids);

  // get_device_update_edus_by_remote (line ~2480)
  std::vector<DeviceListEntry> get_device_update_edus_by_remote(
      const std::string& destination, int64_t from_stream_id,
      int64_t limit);

  // mark_destinations_as_up_to_date (line ~2570)
  void mark_destinations_as_up_to_date(
      const std::string& destination,
      const std::set<std::string>& user_ids);

  // delete_device_edus_for_remote (line ~2620)
  void delete_device_edus_for_remote(const std::string& destination,
                                       const std::string& user_id,
                                       int64_t stream_id);

  // cache_device_list (line ~2690)
  void cache_device_list(const std::string& user_id,
                           const std::vector<DeviceInfo>& devices);

  // get_cached_device_list_changes (line ~2760)
  std::vector<DeviceListEntry> get_cached_device_list_changes(
      int64_t from_stream_id, int64_t to_stream_id);

private:
  // Device ID sequence generator
  int64_t device_id_gen_{0};

  // Helpers
  int64_t next_device_stream_id();
  std::string make_device_id();

  // Cache management
  void invalidate_device_caches(const std::string& user_id);
};

}  // namespace progressive::storage
