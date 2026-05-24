#include "types.hpp"

#include <nlohmann/json.hpp>

namespace progressive::lemmy {

nlohmann::json Community::to_json() const {
  return {{"id", id},
          {"name", name},
          {"title", title},
          {"description", description},
          {"creator_id", creator_id},
          {"subscriber_count", subscriber_count},
          {"post_count", post_count}};
}

Community Community::from_json(const nlohmann::json& j) {
  Community c;
  c.name = j.value("name", "");
  c.title = j.value("title", "");
  c.description = j.value("description", "");
  c.creator_id = j.value("creator_id", "");
  return c;
}

nlohmann::json Post::to_json() const {
  return {{"id", id},
          {"name", name},
          {"url", url},
          {"body", body},
          {"creator_id", creator_id},
          {"community_id", community_id},
          {"score", score},
          {"upvotes", upvotes},
          {"downvotes", downvotes},
          {"comment_count", comment_count}};
}

Post Post::from_json(const nlohmann::json& j) {
  Post p;
  p.name = j.value("name", "");
  p.url = j.value("url", "");
  p.body = j.value("body", "");
  p.creator_id = j.value("creator_id", "");
  p.community_id = j.value("community_id", 0);
  return p;
}

nlohmann::json Comment::to_json() const {
  return {{"id", id},           {"content", content},     {"creator_id", creator_id},
          {"post_id", post_id}, {"parent_id", parent_id}, {"score", score}};
}

Comment Comment::from_json(const nlohmann::json& j) {
  Comment c;
  c.content = j.value("content", "");
  c.creator_id = j.value("creator_id", "");
  c.post_id = j.value("post_id", 0);
  c.parent_id = j.value("parent_id", 0);
  return c;
}

}  // namespace progressive::lemmy
