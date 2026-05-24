#include "server.hpp"

#include <nlohmann/json.hpp>

#include "../util/random.hpp"
#include "../util/time.hpp"
#include "types.hpp"

namespace progressive::lemmy {

static std::string sql_esc(std::string_view s) {
  std::string o;
  for (char c : s) {
    if (c == '\'')
      o += "''";
    else
      o += c;
  }
  return o;
}

void register_lemmy_routes(progressive::http::Router& router, storage::DatabasePool& db,
                           std::string_view server_name) {
  namespace bh = boost::beast::http;
  namespace ph = progressive::http;
  using Req = bh::request<bh::string_body>;
  using Res = bh::response<bh::string_body>;
  using Params = std::map<std::string, std::string>;

  // Ensure Lemmy tables exist
  db.execute(R"(
    CREATE TABLE IF NOT EXISTS lemmy_communities (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, title TEXT,
      description TEXT, creator_id TEXT, created_ts BIGINT, subscriber_count INTEGER DEFAULT 0,
      post_count INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS lemmy_posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, url TEXT, body TEXT,
      creator_id TEXT, community_id INTEGER, created_ts BIGINT,
      score INTEGER DEFAULT 0, upvotes INTEGER DEFAULT 0, downvotes INTEGER DEFAULT 0,
      comment_count INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS lemmy_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT, creator_id TEXT,
      post_id INTEGER, parent_id INTEGER DEFAULT 0, created_ts BIGINT, score INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS lemmy_votes (
      user_id TEXT, post_id INTEGER DEFAULT 0, comment_id INTEGER DEFAULT 0,
      score INTEGER, PRIMARY KEY (user_id, post_id, comment_id)
    );
    CREATE TABLE IF NOT EXISTS lemmy_community_subscribers (
      community_id INTEGER, user_id TEXT, PRIMARY KEY (community_id, user_id)
    );
  )");

  // GET /api/v3/site
  router.add_route(
      bh::verb::get, "/api/v3/site",
      [&db, server_name](Req&&, Params) -> Res {
        auto cc = db.query("SELECT COUNT(*) as c FROM lemmy_communities");
        auto pc = db.query("SELECT COUNT(*) as c FROM lemmy_posts");
        auto uc = db.query("SELECT COUNT(*) as c FROM users");
        SiteInfo si;
        si.name = std::string(server_name);
        si.description = "Progressive Lemmy Instance";
        si.community_count =
            (!cc.empty() && cc[0]["c"].is_number()) ? cc[0]["c"].template get<int>() : 0;
        si.post_count =
            (!pc.empty() && pc[0]["c"].is_number()) ? pc[0]["c"].template get<int>() : 0;
        si.user_count =
            (!uc.empty() && uc[0]["c"].is_number()) ? uc[0]["c"].template get<int>() : 0;
        nlohmann::json j;
        j["site_view"] = {{"site", {{"name", si.name}, {"description", si.description}}}};
        j["site_view"]["counts"] = {{"users", si.user_count},
                                    {"communities", si.community_count},
                                    {"posts", si.post_count}};
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_site");

  // POST /api/v3/community
  router.add_route(
      bh::verb::post, "/api/v3/community",
      [&db](Req&& req, Params) -> Res {
        auto body = nlohmann::json::parse(req.body());
        auto c = Community::from_json(body);
        uint64_t now = util::now_ms();
        db.execute(
            "INSERT INTO lemmy_communities (name,title,description,creator_id,created_ts) VALUES "
            "('" +
            sql_esc(c.name) + "','" + sql_esc(c.title) + "','" + sql_esc(c.description) + "','" +
            sql_esc(c.creator_id) + "'," + std::to_string(now) + ")");
        auto rows = db.query("SELECT last_insert_rowid() as id");
        c.id = (!rows.empty()) ? rows[0]["id"].template get<int>() : 1;
        nlohmann::json j;
        j["community_view"] = {{"community", c.to_json()}, {"subscribed", "NotSubscribed"}};
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_create_community");

  // GET /api/v3/community?id=...
  router.add_route(
      bh::verb::get, "/api/v3/community",
      [&db](Req&& req, Params) -> Res {
        auto t = std::string(req.target());
        auto p = t.find("id=");
        std::string id = (p != std::string::npos) ? t.substr(p + 3) : "1";
        auto rows = db.query("SELECT * FROM lemmy_communities WHERE id=" + id);
        nlohmann::json j;
        if (!rows.empty()) {
          Community c;
          c.id = rows[0]["id"].template get<int>();
          c.name = rows[0]["name"];
          c.title = rows[0].value("title", "");
          c.description = rows[0].value("description", "");
          c.creator_id = rows[0]["creator_id"];
          c.subscriber_count = rows[0].value("subscriber_count", 0);
          c.post_count = rows[0].value("post_count", 0);
          j["community_view"] = {{"community", c.to_json()}, {"subscribed", "NotSubscribed"}};
        }
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_get_community");

  // GET /api/v3/community/list
  router.add_route(
      bh::verb::get, "/api/v3/community/list",
      [&db](Req&&, Params) -> Res {
        auto rows =
            db.query("SELECT * FROM lemmy_communities ORDER BY subscriber_count DESC LIMIT 20");
        nlohmann::json j;
        j["communities"] = nlohmann::json::array();
        for (auto& r : rows) {
          Community c;
          c.id = r["id"].template get<int>();
          c.name = r["name"];
          c.title = r.value("title", "");
          c.subscriber_count = r.value("subscriber_count", 0);
          c.post_count = r.value("post_count", 0);
          j["communities"].push_back({{"community", c.to_json()}, {"subscribed", "NotSubscribed"}});
        }
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_list_communities");

  // POST /api/v3/post
  router.add_route(
      bh::verb::post, "/api/v3/post",
      [&db](Req&& req, Params) -> Res {
        auto body = nlohmann::json::parse(req.body());
        auto p = Post::from_json(body);
        uint64_t now = util::now_ms();
        db.execute(
            "INSERT INTO lemmy_posts (name,url,body,creator_id,community_id,created_ts) VALUES ('" +
            sql_esc(p.name) + "','" + sql_esc(p.url) + "','" + sql_esc(p.body) + "','" +
            sql_esc(p.creator_id) + "'," + std::to_string(p.community_id) + "," +
            std::to_string(now) + ")");
        db.execute("UPDATE lemmy_communities SET post_count=post_count+1 WHERE id=" +
                   std::to_string(p.community_id));
        auto rows = db.query("SELECT last_insert_rowid() as id");
        p.id = (!rows.empty()) ? rows[0]["id"].template get<int>() : 1;
        nlohmann::json j;
        j["post_view"] = {{"post", p.to_json()}, {"community", {{"id", p.community_id}}}};
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_create_post");

  // GET /api/v3/post?id=...
  router.add_route(
      bh::verb::get, "/api/v3/post",
      [&db](Req&& req, Params) -> Res {
        auto t = std::string(req.target());
        auto p = t.find("id=");
        std::string id = (p != std::string::npos) ? t.substr(p + 3) : "1";
        auto rows = db.query("SELECT * FROM lemmy_posts WHERE id=" + id);
        nlohmann::json j;
        if (!rows.empty()) {
          Post pt;
          pt.id = rows[0]["id"].template get<int>();
          pt.name = rows[0]["name"];
          pt.body = rows[0].value("body", "");
          pt.creator_id = rows[0]["creator_id"];
          pt.community_id = rows[0]["community_id"].template get<int>();
          pt.score = rows[0].value("score", 0);
          pt.upvotes = rows[0].value("upvotes", 0);
          pt.downvotes = rows[0].value("downvotes", 0);
          pt.comment_count = rows[0].value("comment_count", 0);
          j["post_view"] = {{"post", pt.to_json()}, {"community", {{"id", pt.community_id}}}};
        }
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_get_post");

  // GET /api/v3/post/list?community_id=...
  router.add_route(
      bh::verb::get, "/api/v3/post/list",
      [&db](Req&& req, Params) -> Res {
        auto t = std::string(req.target());
        auto p = t.find("community_id=");
        std::string cid = (p != std::string::npos) ? t.substr(p + 14) : "1";
        auto rows = db.query("SELECT * FROM lemmy_posts WHERE community_id=" + cid +
                             " ORDER BY score DESC LIMIT 20");
        nlohmann::json j;
        j["posts"] = nlohmann::json::array();
        for (auto& r : rows) {
          Post pt;
          pt.id = r["id"].template get<int>();
          pt.name = r["name"];
          pt.body = r.value("body", "");
          pt.creator_id = r["creator_id"];
          pt.score = r.value("score", 0);
          pt.upvotes = r.value("upvotes", 0);
          pt.downvotes = r.value("downvotes", 0);
          pt.comment_count = r.value("comment_count", 0);
          j["posts"].push_back({{"post", pt.to_json()}, {"community", {{"id", cid}}}});
        }
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_list_posts");

  // POST /api/v3/comment
  router.add_route(
      bh::verb::post, "/api/v3/comment",
      [&db](Req&& req, Params) -> Res {
        auto body = nlohmann::json::parse(req.body());
        auto c = Comment::from_json(body);
        uint64_t now = util::now_ms();
        db.execute(
            "INSERT INTO lemmy_comments (content,creator_id,post_id,parent_id,created_ts) VALUES "
            "('" +
            sql_esc(c.content) + "','" + sql_esc(c.creator_id) + "'," + std::to_string(c.post_id) +
            "," + std::to_string(c.parent_id) + "," + std::to_string(now) + ")");
        db.execute("UPDATE lemmy_posts SET comment_count=comment_count+1 WHERE id=" +
                   std::to_string(c.post_id));
        auto rows = db.query("SELECT last_insert_rowid() as id");
        c.id = (!rows.empty()) ? rows[0]["id"].template get<int>() : 1;
        nlohmann::json j;
        j["comment_view"] = {{"comment", c.to_json()}, {"post", {{"id", c.post_id}}}};
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_create_comment");

  // POST /api/v3/post/like
  router.add_route(
      bh::verb::post, "/api/v3/post/like",
      [&db](Req&& req, Params) -> Res {
        auto body = nlohmann::json::parse(req.body());
        int64_t post_id = body.value("post_id", int64_t(0));
        int score = body.value("score", 0);  // 1, -1, or 0
        std::string uid = body.value("creator_id", body.value("auth", std::string{""}));
        auto existing = db.query("SELECT score FROM lemmy_votes WHERE user_id='" + sql_esc(uid) +
                                 "' AND post_id=" + std::to_string(post_id));
        int old_score = (!existing.empty() && existing[0]["score"].is_number())
                            ? existing[0]["score"].template get<int>()
                            : 0;

        if (score == 0) {
          db.execute("DELETE FROM lemmy_votes WHERE user_id='" + sql_esc(uid) +
                     "' AND post_id=" + std::to_string(post_id));
        } else {
          db.execute("INSERT OR REPLACE INTO lemmy_votes (user_id,post_id,score) VALUES ('" +
                     sql_esc(uid) + "'," + std::to_string(post_id) + "," + std::to_string(score) +
                     ")");
        }

        // Update post counts
        if (old_score != score) {
          if (old_score == 1)
            db.execute("UPDATE lemmy_posts SET upvotes=upvotes-1,score=score-1 WHERE id=" +
                       std::to_string(post_id));
          else if (old_score == -1)
            db.execute("UPDATE lemmy_posts SET downvotes=downvotes-1,score=score+1 WHERE id=" +
                       std::to_string(post_id));
          if (score == 1)
            db.execute("UPDATE lemmy_posts SET upvotes=upvotes+1,score=score+1 WHERE id=" +
                       std::to_string(post_id));
          else if (score == -1)
            db.execute("UPDATE lemmy_posts SET downvotes=downvotes+1,score=score-1 WHERE id=" +
                       std::to_string(post_id));
        }

        auto rows = db.query("SELECT score,upvotes,downvotes FROM lemmy_posts WHERE id=" +
                             std::to_string(post_id));
        nlohmann::json j;
        j["post_view"] = {{"post", {{"id", post_id}, {"score", rows[0].value("score", 0)}}}};
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_vote");

  // GET /api/v3/user?username=...
  router.add_route(
      bh::verb::get, "/api/v3/user",
      [&db](Req&& req, Params) -> Res {
        auto t = std::string(req.target());
        auto p = t.find("username=");
        std::string uname = (p != std::string::npos) ? t.substr(p + 9) : "";
        auto rows = db.query("SELECT * FROM users WHERE id LIKE '@" + sql_esc(uname) + ":%'");
        nlohmann::json j;
        if (!rows.empty()) {
          j["person_view"] = {{"person", {{"id", rows[0]["id"]}, {"name", uname}}}};
        }
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_user");
}

}  // namespace progressive::lemmy
