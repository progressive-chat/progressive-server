// uiaa.hpp — translation of Conduit commit cf94b8e7's src/database/uiaa.rs
//
// User-Interactive Authentication: the server stores a UiaaInfo session per
// (user, device, session). Clients complete stages (m.login.dummy / m.login.password)
// and resubmit with auth.session until a flow succeeds.
//
//   pub struct Uiaa {
//       userdevicesessionid_uiaainfo: sled::Tree,
//       userdevicesessionid_uiaarequest: sled::Tree,
//   }
//   create(user_id, device_id, session, uiaainfo)      — start a session
//   try_auth(...) -> (bool worked, UiaaInfo)           — attempt a stage
//   set_uiaa_request / get_uiaa_request  — store/retrieve original JSON request
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
  explicit Uiaa(sled::Tree tree, sled::Tree request_tree)
      : tree_(std::move(tree)), request_tree_(std::move(request_tree)) {}

  /// Creates a new Uiaa session with given session token.
  void create(const std::string& user_id, const std::string& device_id,
              const std::string& session, const nlohmann::json& uiaainfo);

  /// Attempt `auth` ({"type":..., "session":..., ...}) against the flows.
  /// Returns {worked, uiaainfo-to-return-to-client}.
  struct Attempt {
    bool worked;
    nlohmann::json info;
  };
  Attempt try_auth(const std::string& user_id, const std::string& device_id,
                   const nlohmann::json& auth, const nlohmann::json& uiaainfo,
                   const std::string& hostname);

  /// Store the original JSON request body for the given session.
  void set_uiaa_request(const std::string& user_id, const std::string& device_id,
                        const std::string& session,
                        const nlohmann::json& request);

  /// Retrieve the original JSON request for the given session.
  std::optional<nlohmann::json> get_uiaa_request(
      const std::string& user_id, const std::string& device_id,
      const std::string& session) const;

 private:
  void update_session(const std::string& key, const nlohmann::json* uiaainfo);
  std::optional<nlohmann::json> get_session(const std::string& key,
                                            const std::string& session) const;
  std::string make_key(const std::string& user_id,
                       const std::string& device_id,
                       const std::string& session) const;

  sled::Tree tree_;
  sled::Tree request_tree_;
};

}  // namespace database
