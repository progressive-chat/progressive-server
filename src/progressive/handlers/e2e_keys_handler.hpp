#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

#include "../storage/database.hpp"

namespace progressive::handlers {

class E2eKeysHandler {
public:
  explicit E2eKeysHandler(storage::DatabasePool& db);

  // synapse/handlers/e2e_keys.py line-by-line ports
  nlohmann::json upload_keys_for_user(std::string_view user_id, std::string_view device_id,
                                      const nlohmann::json& keys);
  nlohmann::json upload_device_keys(std::string_view user_id, std::string_view device_id,
                                    const nlohmann::json& device_keys);
  nlohmann::json claim_one_time_keys(std::string_view user_id, const nlohmann::json& query);
  nlohmann::json query_devices(const nlohmann::json& query);
  nlohmann::json upload_signing_keys(std::string_view user_id, const nlohmann::json& keys);
  nlohmann::json upload_signatures(std::string_view user_id, const nlohmann::json& signatures);
  nlohmann::json check_cross_signing_setup(std::string_view user_id);
  int count_one_time_keys(std::string_view user_id, std::string_view device_id);
  void delete_old_one_time_keys();

private:
  storage::DatabasePool& db_;
};

}  // namespace progressive::handlers
