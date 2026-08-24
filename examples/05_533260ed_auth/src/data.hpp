// data.hpp — translation of Conduit commit 533260ed's src/data.rs
//
// The FOUR-TREE auth model:
//   USERID_PASSWORD   user_id -> password        (plaintext still!)
//   USERID_DEVICEIDS  user_id -> device list     (NUL-joined via utils)
//   DEVICEID_TOKEN    device_id -> access_token
//   TOKEN_USERID      token -> user_id
#pragma once

#include "sled.hpp"

#include <filesystem>
#include <optional>
#include <string>

class Data {
 public:
  static Data load_or_create(const std::filesystem::path& dir);

  void set_hostname(const std::string& hostname);
  std::string hostname() const;

  bool user_exists(const std::string& user_id) const;
  void user_add(const std::string& user_id, const std::optional<std::string>& password);
  std::optional<std::string> user_from_token(const std::string& token) const;
  std::optional<std::string> password_get(const std::string& user_id) const;
  void device_add(const std::string& user_id, const std::string& device_id);
  void token_replace(const std::string& user_id, const std::string& device_id,
                     const std::string& token);

 private:
  explicit Data(sled::Db db);
  sled::Db db_;
};
