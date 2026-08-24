// data.hpp — translation of Conduit commit 34a53ce2's src/data.rs
//
//   pub struct Data(sled::Db);
//   impl Data {
//       pub fn load_or_create() -> Self
//       pub fn set_hostname(&self, hostname: &str)  // sled root tree
//       pub fn hostname(&self) -> String
//       pub fn user_exists(&self, user_id) -> bool          // tree username_password
//       pub fn user_add(&self, user_id, password)
//   }
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

 private:
  explicit Data(sled::Db db);
  sled::Db db_;
};
