// data.hpp — translation of Conduit commit 533260ed's src/data.rs
//
// This commit introduced the FOUR-TREE auth model, which persisted (with more
// trees added) through the whole lineage:
//
//   const USERID_PASSWORD:  user_id    -> password        (plaintext still!)
//   const USERID_DEVICEIDS: user_id    -> device list     (NUL-joined via utils)
//   const DEVICEID_TOKEN:   device_id  -> access_token
//   const TOKEN_USERID:     token      -> user_id
//
// New methods:
//
//   pub fn user_from_token(&self, token: &str) -> Option<UserId>
//   pub fn password_get(&self, user_id: &UserId) -> Option<String>
//   pub fn device_add(&self, user_id: &UserId, device_id: &str)
//   pub fn token_replace(&self, user_id: &UserId, device_id: &String,
//                        token: String)
//   pub fn room_event_add(&self, _room_event: &RoomEvent) { todo!(); }

#pragma once

#include "database.hpp"

#include <filesystem>
#include <optional>
#include <string>

class Data {
 public:
  /// Load an existing database or create a new one.
  static Data load_or_create(const std::filesystem::path& dir);

  /// Set the hostname of the server.
  void set_hostname(const std::string& hostname);
  /// Get the hostname of the server.
  std::string hostname() const;

  /// Check if a user has an account by looking for an assigned password.
  bool user_exists(const std::string& user_id) const;

  /// Create a new user account by assigning them a password.
  void user_add(const std::string& user_id, const std::optional<std::string>& password);

  /// NEW: find out which user an access token belongs to.
  std::optional<std::string> user_from_token(const std::string& token) const;

  /// NEW: get the stored password of a user (nullopt if no account).
  std::optional<std::string> password_get(const std::string& user_id) const;

  /// NEW: add a new device to a user.
  void device_add(const std::string& user_id, const std::string& device_id);

  /// NEW: replace the access token of one device.
  void token_replace(const std::string& user_id, const std::string& device_id,
                     const std::string& token);

 private:
  explicit Data(stubdb::Db db) : db_(std::move(db)) {}
  stubdb::Db db_;
};
