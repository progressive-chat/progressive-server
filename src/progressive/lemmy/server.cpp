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

  // POST /api/v3/comment/like
  router.add_route(
      bh::verb::post, "/api/v3/comment/like",
      [&db](Req&& req, Params) -> Res {
        auto body = nlohmann::json::parse(req.body());
        int64_t comment_id = body.value("comment_id", int64_t(0));
        int score = body.value("score", 0);
        std::string uid = body.value("creator_id", body.value("auth", std::string{""}));
        if (score == 0)
          db.execute("DELETE FROM lemmy_votes WHERE user_id='" + sql_esc(uid) +
                     "' AND comment_id=" + std::to_string(comment_id));
        else
          db.execute("INSERT OR REPLACE INTO lemmy_votes (user_id,comment_id,score) VALUES ('" +
                     sql_esc(uid) + "'," + std::to_string(comment_id) + "," +
                     std::to_string(score) + ")");
        db.execute("UPDATE lemmy_comments SET score=score+" + std::to_string(score) +
                   " WHERE id=" + std::to_string(comment_id));
        auto rows =
            db.query("SELECT score FROM lemmy_comments WHERE id=" + std::to_string(comment_id));
        nlohmann::json j;
        j["comment_view"] = {
            {"comment", {{"id", comment_id}, {"score", rows[0].value("score", 0)}}}};
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_comment_like");

  // POST /api/v3/community/follow
  router.add_route(
      bh::verb::post, "/api/v3/community/follow",
      [&db](Req&& req, Params) -> Res {
        auto body = nlohmann::json::parse(req.body());
        int64_t cid = body.value("community_id", int64_t(0));
        std::string uid = body.value("creator_id", body.value("auth", std::string{""}));
        bool follow = body.value("follow", true);
        if (follow) {
          db.execute(
              "INSERT OR IGNORE INTO lemmy_community_subscribers (community_id,user_id) VALUES (" +
              std::to_string(cid) + ",'" + sql_esc(uid) + "')");
          db.execute("UPDATE lemmy_communities SET subscriber_count=subscriber_count+1 WHERE id=" +
                     std::to_string(cid));
        } else {
          db.execute("DELETE FROM lemmy_community_subscribers WHERE community_id=" +
                     std::to_string(cid) + " AND user_id='" + sql_esc(uid) + "'");
          db.execute(
              "UPDATE lemmy_communities SET subscriber_count=MAX(0,subscriber_count-1) WHERE id=" +
              std::to_string(cid));
        }
        nlohmann::json j;
        j["community_view"] = {{"community", {{"id", cid}}},
                               {"subscribed", follow ? "Subscribed" : "NotSubscribed"}};
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_follow");

  // GET /api/v3/post/list (front page — all posts by hot)
  router.add_route(
      bh::verb::get, "/api/v3/post/list",
      [&db](Req&& req, Params) -> Res {
        auto t = std::string(req.target());
        auto p = t.find("type_=");
        std::string stype = (p != std::string::npos) ? t.substr(p + 6) : "Hot";
        // Also check for community_id filter
        auto cp = t.find("community_id=");
        std::string where =
            (cp != std::string::npos) ? " WHERE community_id=" + t.substr(cp + 14) : "";
        std::string order = stype == "New" ? " ORDER BY created_ts DESC" : " ORDER BY score DESC";
        auto rows = db.query("SELECT * FROM lemmy_posts" + where + order + " LIMIT 20");
        nlohmann::json j;
        j["posts"] = nlohmann::json::array();
        for (auto& r : rows) {
          Post pt;
          pt.id = r["id"].template get<int>();
          pt.name = r["name"];
          pt.body = r.value("body", "");
          pt.creator_id = r["creator_id"];
          pt.community_id = r["community_id"].template get<int>();
          pt.score = r.value("score", 0);
          pt.comment_count = r.value("comment_count", 0);
          j["posts"].push_back({{"post", pt.to_json()}});
        }
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_front_page");

  // PUT /api/v3/post (edit)
  router.add_route(
      bh::verb::put, "/api/v3/post",
      [&db](Req&& req, Params) -> Res {
        auto body = nlohmann::json::parse(req.body());
        int64_t pid = body.value("post_id", int64_t(0));
        std::string name = body.value("name", "");
        std::string bd = body.value("body", "");
        db.execute("UPDATE lemmy_posts SET name='" + sql_esc(name) + "',body='" + sql_esc(bd) +
                   "' WHERE id=" + std::to_string(pid));
        nlohmann::json j;
        j["post_view"] = {{"post", {{"id", pid}, {"name", name}, {"body", bd}}}};
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_edit_post");

  // DELETE /api/v3/post
  router.add_route(
      bh::verb::delete_, "/api/v3/post",
      [&db](Req&& req, Params) -> Res {
        auto t = std::string(req.target());
        auto p = t.find("id=");
        int64_t pid = (p != std::string::npos) ? std::stoll(t.substr(p + 3)) : 0;
        db.execute("DELETE FROM lemmy_posts WHERE id=" + std::to_string(pid));
        db.execute("DELETE FROM lemmy_comments WHERE post_id=" + std::to_string(pid));
        nlohmann::json j;
        j["success"] = true;
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_delete_post");

  // POST /api/v3/user/login (Lemmy login via Matrix token)
  router.add_route(
      bh::verb::post, "/api/v3/user/login",
      [&db](Req&& req, Params) -> Res {
        auto body = nlohmann::json::parse(req.body());
        std::string uname = body.value("username_or_email", "");
        std::string pw = body.value("password", "");
        auto rows = db.query("SELECT id,password_hash FROM users WHERE id LIKE '@" +
                             sql_esc(uname) + ":%'");
        nlohmann::json j;
        if (!rows.empty() && !rows[0]["password_hash"].is_null()) {
          j["jwt"] = "lemmy_" + util::random_token(32);
          auto ur =
              db.query("SELECT id,admin FROM users WHERE id LIKE '@" + sql_esc(uname) + ":%'");
          j["person"] = {{"local_user_view", {{"person", {{"id", ur[0]["id"]}, {"name", uname}}}}}};
        } else {
          j["error"] = "invalid_login";
        }
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_login");

  // POST /api/v3/user/register
  router.add_route(
      bh::verb::post, "/api/v3/user/register",
      [&db](Req&& req, Params) -> Res {
        auto body = nlohmann::json::parse(req.body());
        std::string uname = body.value("username", "");
        std::string pw = body.value("password", "");
        std::string mx_user = "@" + uname + ":localhost";
        db.execute("INSERT OR IGNORE INTO users (id,password_hash,creation_ts) VALUES ('" +
                   sql_esc(mx_user) + "','" + sql_esc(pw) + "'," + std::to_string(util::now_ms()) +
                   ")");
        nlohmann::json j;
        j["jwt"] = "lemmy_" + util::random_token(32);
        j["person"] = {{"local_user_view", {{"person", {{"name", uname}}}}}};
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_register");

  // PUT /api/v3/comment (edit)
  router.add_route(
      bh::verb::put, "/api/v3/comment",
      [&db](Req&& req, Params) -> Res {
        auto body = nlohmann::json::parse(req.body());
        int64_t cid = body.value("comment_id", int64_t(0));
        std::string content = body.value("content", "");
        db.execute("UPDATE lemmy_comments SET content='" + sql_esc(content) +
                   "' WHERE id=" + std::to_string(cid));
        nlohmann::json j;
        j["comment_view"] = {{"comment", {{"id", cid}, {"content", content}}}};
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_edit_comment");

  // DELETE /api/v3/comment
  router.add_route(
      bh::verb::delete_, "/api/v3/comment",
      [&db](Req&& req, Params) -> Res {
        auto t = std::string(req.target());
        auto p = t.find("id=");
        int64_t cid = (p != std::string::npos) ? std::stoll(t.substr(p + 3)) : 0;
        db.execute("UPDATE lemmy_comments SET content='[deleted]' WHERE id=" + std::to_string(cid));
        nlohmann::json j;
        j["success"] = true;
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_delete_comment");

  // ActivityPub outbox (federation stub)
  router.add_route(
      bh::verb::get, "/api/v3/user/{username}/outbox",
      [&db](Req&&, Params p) -> Res {
        nlohmann::json j;
        j["@context"] = "https://www.w3.org/ns/activitystreams";
        j["type"] = "OrderedCollection";
        j["totalItems"] = 0;
        j["orderedItems"] = nlohmann::json::array();
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_activitypub_outbox");

  // ActivityPub inbox (federation stub)
  router.add_route(
      bh::verb::post, "/api/v3/user/{username}/inbox",
      [&db](Req&& req, Params) -> Res {
        nlohmann::json j;
        j["status"] = "ok";
        Res r{bh::status::ok, 11};
        ph::set_json(r, j.dump());
        return r;
      },
      "lemmy_activitypub_inbox");
}

}  // namespace progressive::lemmy
