// data.hpp — translation of Conduit commit 34a53ce2's src/data.rs
//
// This is the commit that invented Conduit's Data layer: handlers stop
// touching the database directly and call named domain methods instead. The
// pattern survives in every descendant (conduwuit's Database, tuwunel's
// Data/Store, progressive-server's storage::).
//
// Rust original:
//
//   pub struct Data(sled::Db);
//
//   impl Data {
//       pub fn load_or_create() -> Self { Data(sled::open(...data_dir()).unwrap()) }
//       pub fn set_hostname(&self, hostname: &str) {
//           self.0.insert("hostname", hostname).unwrap();
//       }
//       pub fn hostname(&self) -> String { ... self.0.get("hostname") ... }
//       pub fn user_exists(&self, user_id: &UserId) -> bool {
//           self.0.open_tree("username_password").unwrap().contains_key(...).unwrap()
//       }
//       pub fn user_add(&self, user_id: UserId, password: Option<String>) {
//           self.0.open_tree("username_password").unwrap()
//               .insert(user_id.to_string(), &*password.unwrap_or_default()).unwrap();
//       }
//   }

#pragma once

#include "database.hpp"

#include <filesystem>
#include <optional>
#include <string>

class Data {
 public:
  // Data::load_or_create() — directory chosen here instead of inside the
  // ProjectDirs crate.
  static Data load_or_create(const std::filesystem::path& dir);

  void set_hostname(const std::string& hostname);
  std::string hostname() const;

  bool user_exists(const std::string& user_id) const;
  void user_add(const std::string& user_id,
                const std::optional<std::string>& password);

 private:
  explicit Data(stubdb::Db db) : db_(std::move(db)) {}
  stubdb::Db db_;
};
