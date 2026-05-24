#pragma once
#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace progressive::lemmy {

struct Community {
  int64_t id = 0;
  std::string name;
  std::string title;
  std::string description;
  std::string creator_id;
  int64_t created_ts = 0;
  int subscriber_count = 0;
  int post_count = 0;

  nlohmann::json to_json() const;
  static Community from_json(const nlohmann::json& j);
};

struct Post {
  int64_t id = 0;
  std::string name;
  std::string url;
  std::string body;
  std::string creator_id;
  int64_t community_id = 0;
  int64_t created_ts = 0;
  int score = 0;
  int upvotes = 0;
  int downvotes = 0;
  int comment_count = 0;

  nlohmann::json to_json() const;
  static Post from_json(const nlohmann::json& j);
};

struct Comment {
  int64_t id = 0;
  std::string content;
  std::string creator_id;
  int64_t post_id = 0;
  int64_t parent_id = 0;
  int64_t created_ts = 0;
  int score = 0;

  nlohmann::json to_json() const;
  static Comment from_json(const nlohmann::json& j);
};

struct Vote {
  int64_t post_id = 0;
  int64_t comment_id = 0;
  int score = 0;  // 1 = upvote, -1 = downvote, 0 = remove
  std::string creator_id;
};

struct SiteInfo {
  std::string name;
  std::string description;
  std::string version = "Progressive Lemmy 0.1.0";
  int user_count = 0;
  int community_count = 0;
  int post_count = 0;
};

}  // namespace progressive::lemmy
