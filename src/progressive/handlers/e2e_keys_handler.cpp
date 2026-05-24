#include "e2e_keys_handler.hpp"

#include "../util/random.hpp"
#include "../util/time.hpp"

namespace progressive::handlers {

E2eKeysHandler::E2eKeysHandler(storage::DatabasePool& db) : db_(db) {}

nlohmann::json E2eKeysHandler::upload_keys_for_user(std::string_view user_id,
                                                    std::string_view device_id,
                                                    const nlohmann::json& keys) {
  auto result =
      upload_device_keys(user_id, device_id, keys.value("device_keys", nlohmann::json::object()));

  // Upload one-time keys
  int otk_count = 0;
  if (keys.contains("one_time_keys") && keys["one_time_keys"].is_object()) {
    for (auto& [kid, key_data] : keys["one_time_keys"].items()) {
      db_.execute(
          "INSERT OR IGNORE INTO device_inbox (user_id,device_id,type,sender,"
          "content,stream_id) VALUES ('" +
          std::string(user_id) + "','otk','" + kid + "','" + std::string(user_id) + "','" +
          key_data.dump() + "',0)");
      otk_count++;
    }
  }

  // Count remaining OTKs
  result["one_time_key_counts"] = nlohmann::json::object();
  result["one_time_key_counts"]["signed_curve25519"] = count_one_time_keys(user_id, device_id);
  return result;
}

nlohmann::json E2eKeysHandler::upload_device_keys(std::string_view user_id,
                                                  std::string_view device_id,
                                                  const nlohmann::json& device_keys) {
  if (!device_keys.is_null() && !device_keys.empty()) {
    db_.execute(
        "INSERT OR REPLACE INTO device_inbox (user_id,device_id,type,sender,"
        "content,stream_id) VALUES ('" +
        std::string(user_id) + "','" + std::string(device_id) + "','device_keys','" +
        std::string(user_id) + "','" + device_keys.dump() + "',0)");
  }
  return {};
}

nlohmann::json E2eKeysHandler::claim_one_time_keys(std::string_view user_id,
                                                   const nlohmann::json& query) {
  nlohmann::json result;
  result["one_time_keys"] = nlohmann::json::object();
  result["failures"] = nlohmann::json::object();

  if (!query.contains("one_time_keys") || !query["one_time_keys"].is_object())
    return result;

  for (auto& [target_user, devices] : query["one_time_keys"].items()) {
    if (!devices.is_object())
      continue;
    nlohmann::json user_keys;
    for (auto& [device_id, algorithms] : devices.items()) {
      // Claim one OTK per device
      auto rows = db_.query("SELECT type,content FROM device_inbox WHERE user_id='" +
                            std::string(user_id) + "' AND device_id='otk' LIMIT 1");
      if (!rows.empty()) {
        std::string key_type = rows[0]["type"].get<std::string>();
        user_keys[device_id] = nlohmann::json::object();
        user_keys[device_id][key_type] =
            nlohmann::json::parse(rows[0]["content"].get<std::string>());
        // Delete claimed key
        db_.execute("DELETE FROM device_inbox WHERE user_id='" + std::string(user_id) +
                    "' AND device_id='otk' AND type='" + key_type + "' LIMIT 1");
      }
    }
    if (!user_keys.empty())
      result["one_time_keys"][target_user] = user_keys;
  }
  return result;
}

nlohmann::json E2eKeysHandler::query_devices(const nlohmann::json& query) {
  nlohmann::json result;
  result["device_keys"] = nlohmann::json::object();
  result["failures"] = nlohmann::json::object();

  if (!query.contains("device_keys") || !query["device_keys"].is_object())
    return result;

  for (auto& [target_user, devices] : query["device_keys"].items()) {
    nlohmann::json user_devices;
    for (auto& [device_id, _] : devices.items()) {
      auto rows = db_.query("SELECT type,content FROM device_inbox WHERE user_id='" +
                            std::string(target_user) + "' AND device_id='" +
                            std::string(device_id) + "' AND type='device_keys' LIMIT 1");
      if (!rows.empty()) {
        user_devices[device_id] = nlohmann::json::parse(rows[0]["content"].get<std::string>());
      }
    }
    if (!user_devices.empty())
      result["device_keys"][target_user] = user_devices;
  }
  return result;
}

nlohmann::json E2eKeysHandler::upload_signing_keys(std::string_view user_id,
                                                   const nlohmann::json& keys) {
  if (keys.contains("master_key"))
    db_.execute(
        "INSERT OR REPLACE INTO device_inbox (user_id,device_id,type,sender,"
        "content,stream_id) VALUES ('" +
        std::string(user_id) + "','cs_master','master_key','" + std::string(user_id) + "','" +
        keys["master_key"].dump() + "',0)");
  if (keys.contains("self_signing_key"))
    db_.execute(
        "INSERT OR REPLACE INTO device_inbox (user_id,device_id,type,sender,"
        "content,stream_id) VALUES ('" +
        std::string(user_id) + "','cs_self','self_signing','" + std::string(user_id) + "','" +
        keys["self_signing_key"].dump() + "',0)");
  return {};
}

nlohmann::json E2eKeysHandler::upload_signatures(std::string_view user_id,
                                                 const nlohmann::json& signatures) {
  for (auto& [target_user, user_sigs] : signatures.items()) {
    db_.execute(
        "INSERT OR REPLACE INTO device_inbox (user_id,device_id,type,sender,"
        "content,stream_id) VALUES ('" +
        std::string(target_user) + "','signatures','sig','" + std::string(user_id) + "','" +
        user_sigs.dump() + "',0)");
  }
  return {};
}

nlohmann::json E2eKeysHandler::check_cross_signing_setup(std::string_view user_id) {
  auto rows = db_.query("SELECT content FROM device_inbox WHERE user_id='" + std::string(user_id) +
                        "' AND type='master_key'");
  nlohmann::json result;
  result["ok"] = !rows.empty();
  return result;
}

int E2eKeysHandler::count_one_time_keys(std::string_view user_id, std::string_view device_id) {
  auto rows = db_.query("SELECT COUNT(*) as cnt FROM device_inbox WHERE user_id='" +
                        std::string(user_id) + "' AND device_id='otk'");
  if (rows.empty())
    return 0;
  return rows[0]["cnt"].is_number() ? rows[0]["cnt"].template get<int>() : 0;
}

void E2eKeysHandler::delete_old_one_time_keys() {
  // Background task: delete OTKs older than 30 days
  int64_t cutoff = util::now_ms() - 2592000000LL;
  db_.execute("DELETE FROM device_inbox WHERE device_id='otk' AND stream_id < " +
              std::to_string(cutoff));
}

}  // namespace progressive::handlers
