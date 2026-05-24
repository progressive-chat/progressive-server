#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "../storage/database.hpp"

namespace progressive::handlers {

class DeviceHandler {
public:
  explicit DeviceHandler(storage::DatabasePool& db);

  // synapse/handlers/device.py line-by-line ports
  nlohmann::json get_devices_by_user(std::string_view user_id);
  void delete_devices(std::string_view user_id, const std::vector<std::string>& device_ids);
  bool check_device_registered(std::string_view user_id, std::string_view device_id);
  void upsert_device(std::string_view user_id, std::string_view device_id,
                     std::string_view display_name = "");
  void update_device(std::string_view user_id, std::string_view device_id,
                     std::string_view display_name);
  void delete_all_devices_for_user(std::string_view user_id, std::string_view except_device = "");
  void delete_dehydrated_device(std::string_view user_id);
  nlohmann::json get_dehydrated_device(std::string_view user_id);
  void store_dehydrated_device(std::string_view user_id, std::string_view device_data);

private:
  storage::DatabasePool& db_;
};

}  // namespace progressive::handlers
