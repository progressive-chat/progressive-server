#include "device_handler.hpp"

#include "../util/random.hpp"
#include "../util/time.hpp"

namespace progressive::handlers {

DeviceHandler::DeviceHandler(storage::DatabasePool& db) : db_(db) {}

nlohmann::json DeviceHandler::get_devices_by_user(std::string_view user_id) {
  auto rows = db_.query("SELECT token,device_id,created_at FROM access_tokens WHERE user_id='" +
                        std::string(user_id) + "'");
  nlohmann::json result;
  result["devices"] = nlohmann::json::array();
  for (auto& r : rows) {
    nlohmann::json dev;
    dev["device_id"] = r.value("device_id", "unknown");
    dev["last_seen_ts"] = 0;
    dev["display_name"] = r.value("device_id", "");
    result["devices"].push_back(dev);
  }
  return result;
}

void DeviceHandler::delete_devices(std::string_view user_id,
                                   const std::vector<std::string>& device_ids) {
  for (auto& did : device_ids) {
    db_.execute("DELETE FROM access_tokens WHERE user_id='" + std::string(user_id) +
                "' AND device_id='" + did + "'");
    db_.execute("DELETE FROM device_inbox WHERE user_id='" + std::string(user_id) +
                "' AND device_id='" + did + "'");
  }
}

bool DeviceHandler::check_device_registered(std::string_view user_id, std::string_view device_id) {
  auto rows = db_.query("SELECT token FROM access_tokens WHERE user_id='" + std::string(user_id) +
                        "' AND device_id='" + std::string(device_id) + "'");
  return !rows.empty();
}

void DeviceHandler::upsert_device(std::string_view user_id, std::string_view device_id,
                                  std::string_view display_name) {
  std::string tok = "syt_" + util::random_token(64);
  db_.execute("INSERT OR REPLACE INTO access_tokens (token,user_id,device_id) VALUES ('" + tok +
              "','" + std::string(user_id) + "','" + std::string(device_id) + "')");
  (void)display_name;  // display_name stored in separate metadata in full impl
}

void DeviceHandler::update_device(std::string_view user_id, std::string_view device_id,
                                  std::string_view display_name) {
  db_.execute("UPDATE access_tokens SET device_id='" + std::string(device_id) +
              "' WHERE user_id='" + std::string(user_id) + "' AND device_id='" +
              std::string(device_id) + "'");
  (void)display_name;
}

void DeviceHandler::delete_all_devices_for_user(std::string_view user_id,
                                                std::string_view except_device) {
  std::string uid(user_id);
  std::string ed(except_device);
  db_.execute("DELETE FROM access_tokens WHERE user_id='" + uid + "' AND device_id!='" + ed + "'");
}

void DeviceHandler::delete_dehydrated_device(std::string_view user_id) {
  db_.execute("DELETE FROM access_tokens WHERE user_id='" + std::string(user_id) +
              "' AND device_id='dehydrated'");
}

nlohmann::json DeviceHandler::get_dehydrated_device(std::string_view user_id) {
  auto rows = db_.query("SELECT token FROM access_tokens WHERE user_id='" + std::string(user_id) +
                        "' AND device_id='dehydrated'");
  nlohmann::json result;
  result["device_id"] = rows.empty() ? "" : "dehydrated";
  result["device_data"] = nlohmann::json::object();
  return result;
}

void DeviceHandler::store_dehydrated_device(std::string_view user_id,
                                            std::string_view device_data) {
  db_.execute("INSERT OR REPLACE INTO access_tokens (token,user_id,device_id) VALUES ('" +
              std::string(device_data) + "','" + std::string(user_id) + "','dehydrated')");
}

}  // namespace progressive::handlers
