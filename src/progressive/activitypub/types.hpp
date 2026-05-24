#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "../storage/database.hpp"

namespace progressive::activitypub {

struct Activity {
  std::string id;
  std::string type;  // Create, Announce, Like, Follow, Accept, Delete
  std::string actor;
  std::string object;
  std::string target;
  std::string content;
  nlohmann::json to;

  static Activity from_json(const nlohmann::json& j);
  nlohmann::json to_json() const;
};

struct Actor {
  std::string id;
  std::string type = "Person";
  std::string preferred_username;
  std::string name;
  std::string summary;
  std::string inbox;
  std::string outbox;
  std::string followers;
  std::string following;
  std::string public_key_pem;
  std::string shared_inbox;

  nlohmann::json to_json() const;
};

nlohmann::json webfinger_response(std::string_view resource, std::string_view server_name);

void process_inbox_activity(const Activity& activity, storage::DatabasePool& db,
                            std::string_view server_name);

}  // namespace progressive::activitypub
