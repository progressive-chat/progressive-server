#include "types.hpp"

#include "../util/random.hpp"
#include "../util/time.hpp"

namespace progressive::activitypub {

Activity Activity::from_json(const nlohmann::json& j) {
  Activity a;
  a.id = j.value("id", "");
  a.type = j.value("type", "");
  a.actor = j.value("actor", "");
  a.object = j.value("object", "");
  a.target = j.value("target", "");
  a.content = j.value("content", "");
  a.to = j.value("to", nlohmann::json::array());
  return a;
}

nlohmann::json Activity::to_json() const {
  nlohmann::json j;
  j["@context"] = "https://www.w3.org/ns/activitystreams";
  j["id"] = id;
  j["type"] = type;
  if (!actor.empty())
    j["actor"] = actor;
  if (!object.empty())
    j["object"] = object;
  if (!target.empty())
    j["target"] = target;
  if (!content.empty())
    j["content"] = content;
  j["to"] =
      to.is_null() ? nlohmann::json::array({"https://www.w3.org/ns/activitystreams#Public"}) : to;
  return j;
}

nlohmann::json Actor::to_json() const {
  nlohmann::json j;
  j["@context"] = "https://www.w3.org/ns/activitystreams";
  j["id"] = id;
  j["type"] = type;
  if (!preferred_username.empty())
    j["preferredUsername"] = preferred_username;
  if (!name.empty())
    j["name"] = name;
  if (!summary.empty())
    j["summary"] = summary;
  if (!inbox.empty())
    j["inbox"] = inbox;
  if (!outbox.empty())
    j["outbox"] = outbox;
  if (!followers.empty())
    j["followers"] = followers;
  if (!following.empty())
    j["following"] = following;
  if (!shared_inbox.empty())
    j["endpoints"] = {{"sharedInbox", shared_inbox}};
  j["publicKey"] = {{"id", id + "#main-key"}, {"owner", id}, {"publicKeyPem", public_key_pem}};
  return j;
}

nlohmann::json webfinger_response(std::string_view resource, std::string_view server_name) {
  std::string user = std::string(resource);
  auto acct = user.find("acct:");
  if (acct != std::string::npos)
    user = user.substr(acct + 5);
  nlohmann::json j;
  j["subject"] = std::string(resource);
  j["aliases"] =
      nlohmann::json::array({"https://" + std::string(server_name) + "/api/v3/user/" + user});
  j["links"] = nlohmann::json::array(
      {{{"rel", "self"},
        {"type", "application/activity+json"},
        {"href", "https://" + std::string(server_name) + "/api/v3/user/" + user}},
       {{"rel", "http://webfinger.net/rel/profile-page"},
        {"type", "text/html"},
        {"href", "https://" + std::string(server_name) + "/api/v3/user/" + user}}});
  return j;
}

void process_inbox_activity(const Activity& activity, storage::DatabasePool& db,
                            std::string_view server_name) {
  if (activity.type == "Create") {
    // A new post/comment was created on a remote instance
    // Extract user and create local copy if needed
    std::string uname = activity.actor;
    auto slash = uname.rfind('/');
    if (slash != std::string::npos)
      uname = uname.substr(slash + 1);
    db.execute("INSERT OR IGNORE INTO users (id,creation_ts) VALUES ('@" + uname + ":" +
               std::string(server_name) + "'," + std::to_string(util::now_ms()) + ")");
  } else if (activity.type == "Like" || activity.type == "Announce") {
    // Record the interaction
  } else if (activity.type == "Follow") {
    // Auto-accept: send Accept activity back
    // In real impl, this would federate the Accept to remote inbox
  }
}

}  // namespace progressive::activitypub
