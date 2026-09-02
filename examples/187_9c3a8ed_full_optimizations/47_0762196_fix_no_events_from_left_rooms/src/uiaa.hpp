// uiaa.hpp — translation of Conduit commit c85d363d's src/database/uiaa.rs
//
// User-Interactive Authentication: the server stores a UiaaInfo session per
// (user, device); clients complete stages (m.login.dummy / m.login.password)
// and resubmit with auth.session until a flow succeeds.
//
//   pub struct Uiaa { userdeviceid_uiaainfo: sled::Tree }
//   create(user_id, device_id, uiaainfo)          — start a session
//   try_auth(...) -> (bool worked, UiaaInfo)      — attempt a stage
//   update_uiaa_session / get_uiaa_session

#pragma once

#include "sled.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <vector>

namespace database {

class Uiaa {
 public:
  explicit Uiaa(sled::Tree tree) : tree_(std::move(tree)) {}

  /// Creates a new Uiaa session. Make sure the session token is unique.
  void create(const std::string& user_id, const std::string& device_id,
              const nlohmann::json& uiaainfo);

  /// Attempt `auth` ({"type":..., "session":..., ...}) against the flows.
  /// Returns {worked, uiaainfo-to-return-to-client}.
  struct Attempt {
    bool worked;
    nlohmann::json info;
  };
  Attempt try_auth(const std::string& user_id, const std::string& device_id,
                   const nlohmann::json& auth, const nlohmann::json& uiaainfo,
                   const std::string& hostname);

 private:
  void update_session(const std::string& key, const nlohmann::json* uiaainfo);
  std::optional<nlohmann::json> get_session(const std::string& key,
                                            const std::string& session) const;
  sled::Tree tree_;
};

}  // namespace database
