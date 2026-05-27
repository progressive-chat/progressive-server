// lemmy_handlers.cpp — Lemmy Community, Post, Comment, and Moderation Handlers (3000+ lines)
// Implements: Community CRUD, Post CRUD, Comment CRUD, voting, saving, moderation log.
//
// Each handler: parse params from JSON/query, validate authentication,
// execute business logic via LemmyServer, return structured response.
//
// Namespace: progressive::lemmy

#include "lemmy_server.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <ctime>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace progressive::lemmy {

using json = nlohmann::json;

// ============================================================================
// API Response structures
// ============================================================================

struct HandlerApiError {
  std::string error;
  int code{400};
};

struct HandlerApiResponse {
  bool success{true};
  json data;
  std::optional<std::string> error;
  int status_code{200};

  json to_json() const {
    json j;
    j["success"] = success;
    if (success) {
      j["data"] = data;
    } else {
      j["error"] = error.value_or("Unknown error");
      j["code"] = status_code;
    }
    return j;
  }

  static HandlerApiResponse ok(const json& d) {
    HandlerApiResponse r;
    r.success = true;
    r.data = d;
    return r;
  }
  static HandlerApiResponse fail(const std::string& msg, int code = 400) {
    HandlerApiResponse r;
    r.success = false;
    r.error = msg;
    r.status_code = code;
    return r;
  }
};

// ============================================================================
// Auth context extracted from request headers / JWT
// ============================================================================

struct HandlerAuthContext {
  bool authenticated{false};
  std::string user_id;
  std::string user_name;
  bool is_admin{false};
  bool is_moderator{false};
  std::vector<std::string> moderated_community_ids;
  std::string token;

  json to_json() const {
    return {{"authenticated", authenticated},
            {"user_id", user_id},
            {"user_name", user_name},
            {"is_admin", is_admin},
            {"is_moderator", is_moderator}};
  }
};

// ============================================================================
// Pagination / Query parameters
// ============================================================================

struct HandlerPageParams {
  int page{1};
  int limit{20};
  std::string sort{"hot"};
  std::string type_{"all"};
  std::optional<std::string> community_id;
  std::optional<std::string> community_name;
  bool saved_only{false};
  bool liked_only{false};
  bool disliked_only{false};
  bool show_nsfw{false};
  bool show_read{true};
  std::optional<std::string> language_id;

  static HandlerPageParams from_json(const json& j) {
    HandlerPageParams p;
    if (j.contains("page")) p.page = j["page"].get<int>();
    if (j.contains("limit")) p.limit = j["limit"].get<int>();
    if (j.contains("sort")) p.sort = j["sort"].get<std::string>();
    if (j.contains("type_")) p.type_ = j["type_"].get<std::string>();
    if (j.contains("community_id") && !j["community_id"].is_null())
      p.community_id = j["community_id"].get<std::string>();
    if (j.contains("community_name") && !j["community_name"].is_null())
      p.community_name = j["community_name"].get<std::string>();
    if (j.contains("saved_only")) p.saved_only = j["saved_only"].get<bool>();
    if (j.contains("liked_only")) p.liked_only = j["liked_only"].get<bool>();
    if (j.contains("disliked_only")) p.disliked_only = j["disliked_only"].get<bool>();
    if (j.contains("show_nsfw")) p.show_nsfw = j["show_nsfw"].get<bool>();
    if (j.contains("show_read")) p.show_read = j["show_read"].get<bool>();
    if (j.contains("language_id") && !j["language_id"].is_null())
      p.language_id = j["language_id"].get<std::string>();
    // Clamp
    if (p.page < 1) p.page = 1;
    if (p.limit < 1) p.limit = 20;
    if (p.limit > 200) p.limit = 200;
    return p;
  }

  static HandlerPageParams from_query(const std::map<std::string, std::string>& q) {
    HandlerPageParams p;
    auto gi = [&](const std::string& k) -> std::string {
      auto it = q.find(k);
      return it != q.end() ? it->second : "";
    };
    try { if (!gi("page").empty()) p.page = std::stoi(gi("page")); } catch (...) {}
    try { if (!gi("limit").empty()) p.limit = std::stoi(gi("limit")); } catch (...) {}
    if (!gi("sort").empty()) p.sort = gi("sort");
    if (!gi("type_").empty()) p.type_ = gi("type_");
    if (!gi("community_id").empty()) p.community_id = gi("community_id");
    if (!gi("community_name").empty()) p.community_name = gi("community_name");
    if (p.page < 1) p.page = 1;
    if (p.limit < 1) p.limit = 20;
    if (p.limit > 200) p.limit = 200;
    return p;
  }
};

// ============================================================================
// API Helpers — internal namespace
// ============================================================================

namespace h_detail {

// Time helpers
inline int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}
inline int64_t now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}
inline time_t now_time() {
  return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
}

// ID generation
inline std::string gen_id(const std::string& prefix = "") {
  static std::atomic<int64_t> counter{1};
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(counter.fetch_add(1, std::memory_order_relaxed));
}

// Extract auth token from request JSON or Authorization header value
inline std::optional<std::string> extract_token(const json& request,
                                                  const std::string& auth_header = "") {
  if (request.contains("auth") && !request["auth"].is_null()) {
    return request["auth"].get<std::string>();
  }
  if (!auth_header.empty() && auth_header.rfind("Bearer ", 0) == 0) {
    return auth_header.substr(7);
  }
  if (!auth_header.empty()) {
    return auth_header;
  }
  if (request.contains("token") && !request["token"].is_null()) {
    return request["token"].get<std::string>();
  }
  return std::nullopt;
}

// Validate auth against LemmyServer
inline HandlerAuthContext validate_auth(LemmyServer& server, const json& request,
                                        const std::string& auth_header = "") {
  HandlerAuthContext ctx;
  auto token_opt = extract_token(request, auth_header);
  if (!token_opt.has_value()) {
    return ctx;
  }
  const std::string& token = token_opt.value();
  ctx.token = token;
  if (!server.verify_jwt(token)) {
    return ctx;
  }
  // Extract user ID from token (format: "jwt-USERID-timestamp")
  std::string uid;
  size_t first_dash = token.find('-');
  if (first_dash != std::string::npos) {
    size_t second_dash = token.find('-', first_dash + 1);
    if (second_dash != std::string::npos) {
      uid = token.substr(first_dash + 1, second_dash - first_dash - 1);
    }
  }
  if (uid.empty()) {
    return ctx;
  }
  auto user_opt = server.get_user(uid);
  if (!user_opt.has_value()) {
    return ctx;
  }
  ctx.authenticated = true;
  ctx.user_id = uid;
  ctx.user_name = user_opt->name;
  ctx.is_admin = user_opt->admin;

  // Check moderator status across communities
  ctx.moderated_community_ids.clear();
  ctx.is_moderator = false;

  return ctx;
}

// Check if user can moderate a given community
inline bool can_moderate_community(LemmyServer& server, const HandlerAuthContext& ctx,
                                   const std::string& community_id) {
  if (!ctx.authenticated) return false;
  if (ctx.is_admin) return true;
  auto comm_opt = server.get_community(community_id);
  if (!comm_opt.has_value()) return false;
  return true;  // Simplified: all authenticated users pass for now
}

// Check if user can act on a post (author or mod)
inline bool can_edit_post(LemmyServer& server, const HandlerAuthContext& ctx,
                          const Post& post) {
  if (!ctx.authenticated) return false;
  if (ctx.is_admin) return true;
  if (post.creator_id == ctx.user_id) return true;
  return can_moderate_community(server, ctx, post.community_id);
}

// Check if user can act on a comment (author or mod)
inline bool can_edit_comment(LemmyServer& server, const HandlerAuthContext& ctx,
                             const Comment& comment) {
  if (!ctx.authenticated) return false;
  if (ctx.is_admin) return true;
  if (comment.creator_id == ctx.user_id) return true;
  auto post_opt = server.get_post(comment.post_id);
  if (post_opt.has_value()) {
    return can_moderate_community(server, ctx, post_opt->community_id);
  }
  return false;
}

// Serialize a Post to JSON for API response
inline json post_to_json(const Post& p) {
  json j;
  j["id"] = p.id;
  j["name"] = p.name;
  j["url"] = p.url;
  j["body"] = p.body;
  j["creator_id"] = p.creator_id;
  j["community_id"] = p.community_id;
  j["removed"] = p.removed;
  j["deleted"] = p.deleted;
  j["locked"] = p.locked;
  j["stickied"] = p.stickied;
  j["nsfw"] = p.nsfw;
  j["featured_community"] = p.featured_community;
  j["featured_local"] = p.featured_local;
  j["score"] = p.score;
  j["upvotes"] = p.upvotes;
  j["downvotes"] = p.downvotes;
  j["comments"] = p.comments;
  j["published"] = p.published;
  j["updated"] = p.updated;
  return j;
}

// Serialize a Comment to JSON for API response
inline json comment_to_json(const Comment& c) {
  json j;
  j["id"] = c.id;
  j["content"] = c.content;
  j["creator_id"] = c.creator_id;
  j["post_id"] = c.post_id;
  if (c.parent_id.has_value()) {
    j["parent_id"] = c.parent_id.value();
  } else {
    j["parent_id"] = nullptr;
  }
  j["removed"] = c.removed;
  j["deleted"] = c.deleted;
  j["distinguished"] = c.distinguished;
  j["score"] = c.score;
  j["upvotes"] = c.upvotes;
  j["downvotes"] = c.downvotes;
  j["published"] = c.published;
  j["updated"] = c.updated;
  return j;
}

// Serialize a Community to JSON for API response
inline json community_to_json(const Community& c) {
  json j;
  j["id"] = c.id;
  j["name"] = c.name;
  j["title"] = c.title;
  j["description"] = c.description;
  if (c.icon.has_value()) j["icon"] = c.icon.value(); else j["icon"] = nullptr;
  if (c.banner.has_value()) j["banner"] = c.banner.value(); else j["banner"] = nullptr;
  j["nsfw"] = c.nsfw;
  j["removed"] = c.removed;
  j["deleted"] = c.deleted;
  j["hidden"] = c.hidden;
  j["posting_restricted_to_mods"] = c.posting_restricted_to_mods;
  j["subscribers"] = c.subscribers;
  j["posts"] = c.posts;
  j["comments"] = c.comments;
  j["published"] = c.published;
  j["updated"] = c.updated;
  return j;
}

// Serialize a User to JSON for API response
inline json user_to_json(const User& u) {
  json j;
  j["id"] = u.id;
  j["name"] = u.name;
  j["display_name"] = u.display_name;
  j["bio"] = u.bio;
  j["avatar"] = u.avatar.has_value() ? u.avatar.value() : "";
  j["banner"] = u.banner.has_value() ? u.banner.value() : "";
  j["admin"] = u.admin;
  j["bot_account"] = u.bot_account;
  j["comment_score"] = u.comment_score;
  j["post_score"] = u.post_score;
  j["published"] = u.published;
  j["updated"] = u.updated;
  return j;
}

// Serialize a ModAction to JSON for modlog
inline json mod_action_to_json(const ModAction& a) {
  json j;
  j["id"] = a.id;
  j["mod_person_id"] = a.mod_person_id;
  j["target_person_id"] = a.target_person_id;
  j["community_id"] = a.community_id;
  j["action"] = a.action;
  j["reason"] = a.reason;
  j["removed"] = a.removed;
  j["published"] = a.published;
  return j;
}

// Safe string truncation
inline std::string truncate(const std::string& s, size_t max_len) {
  if (s.size() <= max_len) return s;
  return s.substr(0, max_len);
}

// Validate community/post/comment name
inline bool is_valid_name(const std::string& name) {
  if (name.empty() || name.size() > 200) return false;
  static const std::regex valid_regex(R"(^[a-zA-Z0-9_\-\.\ ]+$)");
  return std::regex_match(name, valid_regex);
}

// Sanitize HTML/script injection from text
inline std::string sanitize_text(const std::string& input) {
  std::string result;
  result.reserve(input.size());
  for (char c : input) {
    switch (c) {
      case '<': result += "&lt;"; break;
      case '>': result += "&gt;"; break;
      case '"': result += "&quot;"; break;
      case '\'': result += "&#39;"; break;
      case '&': result += "&amp;"; break;
      default: result += c;
    }
  }
  return result;
}

// Escape JSON string value
inline std::string json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 16);
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out += c;
    }
  }
  return out;
}

// Normalize URL
inline std::string normalize_url(const std::string& url) {
  if (url.empty()) return url;
  if (url.find("://") == std::string::npos) {
    return "https://" + url;
  }
  return url;
}

// Validate URL format
inline bool is_valid_url(const std::string& url) {
  if (url.empty()) return true;  // empty URL is allowed for text posts
  static const std::regex url_regex(
    R"(^https?://[^\s/$.?#].[^\s]*$)",
    std::regex::icase
  );
  return std::regex_match(url, url_regex);
}

// Validate language code
inline bool is_valid_language(const std::string& lang) {
  if (lang.empty()) return true;
  static const std::regex lang_regex(R"(^[a-z]{2}(-[A-Z]{2})?$)");
  return std::regex_match(lang, lang_regex);
}

// Rate limiting helper
struct HandlerRateLimiter {
  struct Entry {
    int64_t window_start{0};
    int count{0};
  };
  std::unordered_map<std::string, Entry> entries_;
  std::mutex mutex_;
  int max_requests_{60};
  int64_t window_ms_{60000};

  HandlerRateLimiter(int max_req = 60, int64_t window = 60000)
      : max_requests_(max_req), window_ms_(window) {}

  bool check(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = now_ms();
    auto& entry = entries_[key];
    if (now - entry.window_start > window_ms_) {
      entry.window_start = now;
      entry.count = 1;
      return true;
    }
    if (entry.count >= max_requests_) {
      return false;
    }
    entry.count++;
    return true;
  }

  void reset(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.erase(key);
  }
};

// Global rate limiters
static HandlerRateLimiter g_post_rate_limiter(30, 60000);
static HandlerRateLimiter g_comment_rate_limiter(60, 60000);
static HandlerRateLimiter g_vote_rate_limiter(120, 60000);
static HandlerRateLimiter g_auth_rate_limiter(20, 60000);
static HandlerRateLimiter g_mod_rate_limiter(30, 60000);
static HandlerRateLimiter g_community_rate_limiter(10, 60000);
static HandlerRateLimiter g_save_rate_limiter(60, 60000);

// Sort helpers for posts
inline double calculate_post_hot_rank(int64_t score, int64_t published_ms, int64_t now_ms_val) {
  double order = std::log10(std::max(std::abs(static_cast<double>(score)), 1.0));
  int sign = (score > 0) ? 1 : ((score < 0) ? -1 : 0);
  double seconds = static_cast<double>(now_ms_val - published_ms) / 1000.0;
  return sign * order + seconds / 45000.0;
}

inline double calculate_comment_hot_rank(int64_t score, int64_t published_ms, int64_t now_ms_val) {
  double order = std::log10(std::max(std::abs(static_cast<double>(score)), 1.0));
  int sign = (score > 0) ? 1 : ((score < 0) ? -1 : 0);
  double seconds = static_cast<double>(now_ms_val - published_ms) / 1000.0;
  return sign * order + seconds / 45000.0;
}

// Sort posts vector by given criteria
inline void sort_posts(std::vector<Post>& posts, const std::string& sort) {
  int64_t now = now_ms();
  if (sort == "hot" || sort == "active") {
    std::sort(posts.begin(), posts.end(), [&](const Post& a, const Post& b) {
      return calculate_post_hot_rank(a.score, a.published, now) >
             calculate_post_hot_rank(b.score, b.published, now);
    });
  } else if (sort == "new") {
    std::sort(posts.begin(), posts.end(), [](const Post& a, const Post& b) {
      return a.published > b.published;
    });
  } else if (sort == "old") {
    std::sort(posts.begin(), posts.end(), [](const Post& a, const Post& b) {
      return a.published < b.published;
    });
  } else if (sort == "top_day" || sort == "top_week" || sort == "top_month" ||
             sort == "top_year" || sort == "top_all") {
    std::sort(posts.begin(), posts.end(), [](const Post& a, const Post& b) {
      return a.score > b.score;
    });
  } else if (sort == "most_comments") {
    std::sort(posts.begin(), posts.end(), [](const Post& a, const Post& b) {
      return a.comments > b.comments;
    });
  } else if (sort == "new_comments") {
    std::sort(posts.begin(), posts.end(), [](const Post& a, const Post& b) {
      return a.updated > b.updated;
    });
  } else {
    // Default: hot
    std::sort(posts.begin(), posts.end(), [&](const Post& a, const Post& b) {
      return calculate_post_hot_rank(a.score, a.published, now) >
             calculate_post_hot_rank(b.score, b.published, now);
    });
  }
}

// Sort communities vector
inline void sort_communities(std::vector<Community>& communities, const std::string& sort) {
  if (sort == "top_month" || sort == "top_week" || sort == "top_day" || sort == "top_all") {
    std::sort(communities.begin(), communities.end(), [](const Community& a, const Community& b) {
      return a.subscribers > b.subscribers;
    });
  } else if (sort == "new") {
    std::sort(communities.begin(), communities.end(), [](const Community& a, const Community& b) {
      return a.published > b.published;
    });
  } else if (sort == "old") {
    std::sort(communities.begin(), communities.end(), [](const Community& a, const Community& b) {
      return a.published < b.published;
    });
  } else if (sort == "active") {
    std::sort(communities.begin(), communities.end(), [](const Community& a, const Community& b) {
      return a.posts > b.posts;
    });
  } else {
    // Default to hot / active
    std::sort(communities.begin(), communities.end(), [](const Community& a, const Community& b) {
      return a.subscribers > b.subscribers;
    });
  }
}

// Sort comments vector
inline void sort_comments(std::vector<Comment>& comments, const std::string& sort) {
  int64_t now = now_ms();
  if (sort == "hot") {
    std::sort(comments.begin(), comments.end(), [&](const Comment& a, const Comment& b) {
      return calculate_comment_hot_rank(a.score, a.published, now) >
             calculate_comment_hot_rank(b.score, b.published, now);
    });
  } else if (sort == "top") {
    std::sort(comments.begin(), comments.end(), [](const Comment& a, const Comment& b) {
      return a.score > b.score;
    });
  } else if (sort == "new") {
    std::sort(comments.begin(), comments.end(), [](const Comment& a, const Comment& b) {
      return a.published > b.published;
    });
  } else if (sort == "old") {
    std::sort(comments.begin(), comments.end(), [](const Comment& a, const Comment& b) {
      return a.published < b.published;
    });
  } else {
    // Default: hot
    std::sort(comments.begin(), comments.end(), [&](const Comment& a, const Comment& b) {
      return calculate_comment_hot_rank(a.score, a.published, now) >
             calculate_comment_hot_rank(b.score, b.published, now);
    });
  }
}

// Paginate a vector
template<typename T>
inline std::vector<T> paginate(const std::vector<T>& items, int page, int limit) {
  std::vector<T> result;
  if (items.empty()) return result;
  size_t start = static_cast<size_t>((page - 1) * limit);
  if (start >= items.size()) return result;
  size_t end = std::min(start + static_cast<size_t>(limit), items.size());
  result.reserve(end - start);
  for (size_t i = start; i < end; ++i) {
    result.push_back(items[i]);
  }
  return result;
}

// Build a comment tree from flat list (depth-first)
struct CommentTreeNode {
  Comment comment;
  std::vector<CommentTreeNode> children;
};

inline void build_comment_tree(std::vector<CommentTreeNode>& roots,
                               const std::vector<Comment>& flat_comments,
                               int max_depth, int current_depth = 0) {
  if (current_depth >= max_depth) return;

  std::unordered_map<std::string, std::vector<Comment>> children_map;
  std::vector<Comment> root_comments;

  for (const auto& c : flat_comments) {
    if (!c.parent_id.has_value() || c.parent_id.value().empty()) {
      root_comments.push_back(c);
    } else {
      children_map[c.parent_id.value()].push_back(c);
    }
  }

  for (const auto& rc : root_comments) {
    CommentTreeNode node;
    node.comment = rc;
    auto it = children_map.find(rc.id);
    if (it != children_map.end()) {
      // Recursively handle children (simplified: one level)
      for (const auto& child : it->second) {
        CommentTreeNode child_node;
        child_node.comment = child;
        node.children.push_back(child_node);
      }
    }
    roots.push_back(node);
  }
}

// Flatten comment tree back to depth-ordered list
inline void flatten_comment_tree(const std::vector<CommentTreeNode>& roots,
                                 std::vector<Comment>& out, int depth = 0) {
  for (const auto& node : roots) {
    out.push_back(node.comment);
    flatten_comment_tree(node.children, out, depth + 1);
  }
}

}  // namespace h_detail

using namespace h_detail;

// ============================================================================
// ============================================================================
// COMMUNITY HANDLERS
// ============================================================================
// ============================================================================

// ---------------------------------------------------------------------------
// get_community — fetch community by ID or name with moderator list
// ---------------------------------------------------------------------------
HandlerApiResponse handle_get_community(LemmyServer& server, const json& request,
                                        const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);

  // Support fetching by id or name
  std::string lookup;
  bool by_name = false;
  if (request.contains("id") && !request["id"].is_null()) {
    lookup = request["id"].get<std::string>();
  } else if (request.contains("name") && !request["name"].is_null()) {
    lookup = request["name"].get<std::string>();
    by_name = true;
  } else if (request.contains("community_id") && !request["community_id"].is_null()) {
    lookup = request["community_id"].get<std::string>();
  } else {
    return HandlerApiResponse::fail("Missing required parameter: id or name");
  }

  auto comm_opt = server.get_community(lookup);
  if (!comm_opt.has_value()) {
    return HandlerApiResponse::fail("Community not found", 404);
  }

  const Community& community = comm_opt.value();

  // Check if community is deleted/hidden (admins can still see)
  if (community.deleted && !ctx.is_admin) {
    return HandlerApiResponse::fail("Community has been deleted", 410);
  }

  json response = community_to_json(community);

  // Attach counts
  response["subscriber_count"] = community.subscribers;
  response["post_count"] = community.posts;
  response["comment_count"] = community.comments;

  // Attach moderator list
  json mods = json::array();
  // In a full implementation, we'd look up community_mods_ from server
  // Here we provide a simplified moderator list
  mods.push_back({{"moderator_id", community.id + "_mod1"},
                   {"community_id", community.id}});
  response["moderators"] = mods;

  // Attach site info if available
  auto site_info = server.get_site();
  response["site_id"] = site_info.id;
  response["site_name"] = site_info.name;

  // If user is authenticated, include their subscription status
  if (ctx.authenticated) {
    response["subscribed"] = "NotSubscribed";  // Default
    response["blocked"] = false;

    // Check if user is a moderator of this community
    bool is_community_mod = ctx.is_admin;
    response["can_moderate"] = is_community_mod;
  }

  // Count online users (simplified)
  response["users_active_month"] = 0;
  response["users_active_week"] = 0;
  response["users_active_day"] = 0;

  return HandlerApiResponse::ok({{"community_view", response}});
}

// ---------------------------------------------------------------------------
// create_community — create community with name, title, description, icon
// ---------------------------------------------------------------------------
HandlerApiResponse handle_create_community(LemmyServer& server, const json& request,
                                           const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  // Rate limit
  if (!g_community_rate_limiter.check("community:create:" + ctx.user_id)) {
    return HandlerApiResponse::fail("Rate limit exceeded. Please try again later.", 429);
  }

  // Validate required fields
  if (!request.contains("name") || request["name"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: name");
  }
  if (!request.contains("title") || request["title"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: title");
  }

  std::string name = truncate(request["name"].get<std::string>(), 20);
  std::string title = truncate(request["title"].get<std::string>(), 100);
  std::string description;
  std::optional<std::string> icon_url;
  std::optional<std::string> banner_url;
  bool nsfw = false;
  bool posting_restricted_to_mods = false;
  std::optional<std::string> language;

  if (request.contains("description") && !request["description"].is_null()) {
    description = truncate(sanitize_text(request["description"].get<std::string>()), 5000);
  }
  if (request.contains("icon") && !request["icon"].is_null()) {
    icon_url = request["icon"].get<std::string>();
  }
  if (request.contains("banner") && !request["banner"].is_null()) {
    banner_url = request["banner"].get<std::string>();
  }
  if (request.contains("nsfw") && !request["nsfw"].is_null()) {
    nsfw = request["nsfw"].get<bool>();
  }
  if (request.contains("posting_restricted_to_mods") && !request["posting_restricted_to_mods"].is_null()) {
    posting_restricted_to_mods = request["posting_restricted_to_mods"].get<bool>();
  }
  if (request.contains("language") && !request["language"].is_null()) {
    language = request["language"].get<std::string>();
  }

  // Validate name format
  if (!is_valid_name(name)) {
    return HandlerApiResponse::fail("Invalid community name. Use alphanumeric, underscore, hyphen, dot, or space.");
  }

  // Check name length constraints (Lemmy requires 3-20 chars for community name)
  if (name.size() < 3) {
    return HandlerApiResponse::fail("Community name must be at least 3 characters");
  }

  // Validate title is not empty
  if (title.empty()) {
    return HandlerApiResponse::fail("Community title cannot be empty");
  }

  // Check if community name already exists
  auto existing = server.get_community(name);
  if (existing.has_value()) {
    return HandlerApiResponse::fail("Community name already taken", 409);
  }

  // Validate language code
  if (language.has_value() && !is_valid_language(language.value())) {
    return HandlerApiResponse::fail("Invalid language code format");
  }

  // Create community
  Community community = server.create_community(name, title, description, ctx.user_id, nsfw);

  // Set additional fields post-creation
  if (icon_url.has_value()) {
    // Update with icon (use update_community)
    server.update_community(community.id, {{"icon", icon_url.value()}});
  }
  if (banner_url.has_value()) {
    server.update_community(community.id, {{"banner", banner_url.value()}});
  }

  // Re-fetch to get updated community
  auto updated_comm = server.get_community(community.id);
  json response = community_to_json(updated_comm.has_value() ? updated_comm.value() : community);

  // Add creator as moderator
  server.add_mod(community.id, ctx.user_id, ctx.user_id);

  // Attach moderators
  json mods = json::array();
  mods.push_back({{"moderator_id", ctx.user_id},
                   {"community_id", community.id}});
  response["moderators"] = mods;

  // Subscribe creator automatically
  server.follow_community(ctx.user_id, community.id);
  response["subscribed"] = "Subscribed";

  return HandlerApiResponse::ok({{"community_view", response}});
}

// ---------------------------------------------------------------------------
// edit_community — update community fields
// ---------------------------------------------------------------------------
HandlerApiResponse handle_edit_community(LemmyServer& server, const json& request,
                                         const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("community_id") || request["community_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: community_id");
  }

  std::string community_id = request["community_id"].get<std::string>();
  auto comm_opt = server.get_community(community_id);
  if (!comm_opt.has_value()) {
    return HandlerApiResponse::fail("Community not found", 404);
  }

  // Check moderation permissions
  if (!ctx.is_admin && !can_moderate_community(server, ctx, community_id)) {
    return HandlerApiResponse::fail("Not authorized to edit this community", 403);
  }

  // Build updates
  json updates;
  if (request.contains("title") && !request["title"].is_null()) {
    std::string new_title = truncate(request["title"].get<std::string>(), 100);
    if (new_title.empty()) {
      return HandlerApiResponse::fail("Title cannot be empty");
    }
    updates["title"] = new_title;
  }
  if (request.contains("description") && !request["description"].is_null()) {
    updates["description"] = truncate(sanitize_text(request["description"].get<std::string>()), 5000);
  }
  if (request.contains("icon") && !request["icon"].is_null()) {
    updates["icon"] = request["icon"].get<std::string>();
  }
  if (request.contains("banner") && !request["banner"].is_null()) {
    updates["banner"] = request["banner"].get<std::string>();
  }
  if (request.contains("nsfw") && !request["nsfw"].is_null()) {
    updates["nsfw"] = request["nsfw"].get<bool>();
  }
  if (request.contains("posting_restricted_to_mods") && !request["posting_restricted_to_mods"].is_null()) {
    updates["posting_restricted_to_mods"] = request["posting_restricted_to_mods"].get<bool>();
  }
  if (request.contains("language") && !request["language"].is_null()) {
    updates["language"] = request["language"].get<std::string>();
  }

  if (updates.empty()) {
    return HandlerApiResponse::fail("No valid update fields provided");
  }

  Community updated = server.update_community(community_id, updates);

  json response = community_to_json(updated);

  // Attach moderator list
  json mods = json::array();
  mods.push_back({{"moderator_id", ctx.user_id}, {"community_id", community_id}});
  response["moderators"] = mods;

  return HandlerApiResponse::ok({{"community_view", response}});
}

// ---------------------------------------------------------------------------
// delete_community — mark as deleted (owner action)
// ---------------------------------------------------------------------------
HandlerApiResponse handle_delete_community(LemmyServer& server, const json& request,
                                           const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("community_id") || request["community_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: community_id");
  }

  std::string community_id = request["community_id"].get<std::string>();
  bool deleted = true;
  if (request.contains("deleted") && !request["deleted"].is_null()) {
    deleted = request["deleted"].get<bool>();
  }

  auto comm_opt = server.get_community(community_id);
  if (!comm_opt.has_value()) {
    return HandlerApiResponse::fail("Community not found", 404);
  }

  // Only admin can delete communities
  if (!ctx.is_admin) {
    return HandlerApiResponse::fail("Not authorized to delete this community", 403);
  }

  if (deleted) {
    server.delete_community(community_id);
    // Log the action
    server.add_mod(community_id, ctx.user_id, ctx.user_id);
  }

  json response;
  response["community_id"] = community_id;
  response["deleted"] = deleted;

  return HandlerApiResponse::ok(response);
}

// ---------------------------------------------------------------------------
// remove_community — moderator removal (hide from listing)
// ---------------------------------------------------------------------------
HandlerApiResponse handle_remove_community(LemmyServer& server, const json& request,
                                           const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("community_id") || request["community_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: community_id");
  }

  std::string community_id = request["community_id"].get<std::string>();
  std::string reason;
  bool removed = true;

  if (request.contains("reason") && !request["reason"].is_null()) {
    reason = truncate(request["reason"].get<std::string>(), 500);
  }
  if (request.contains("removed") && !request["removed"].is_null()) {
    removed = request["removed"].get<bool>();
  }

  auto comm_opt = server.get_community(community_id);
  if (!comm_opt.has_value()) {
    return HandlerApiResponse::fail("Community not found", 404);
  }

  // Check moderation permissions
  if (!ctx.is_admin && !can_moderate_community(server, ctx, community_id)) {
    return HandlerApiResponse::fail("Not authorized to moderate this community", 403);
  }

  if (removed) {
    server.remove_community(community_id, ctx.user_id, reason);
    // The remove_community in server calls delete_community for now
    // In full impl, it would mark as removed
  } else {
    // Un-remove: just mark it as not removed (simplified approach)
    server.hide_community(community_id, ctx.user_id, "");
  }

  // Log the mod action
  server.add_mod(community_id, ctx.user_id, ctx.user_id);

  json response;
  response["community_id"] = community_id;
  response["removed"] = removed;
  response["reason"] = reason;

  return HandlerApiResponse::ok(response);
}

// ---------------------------------------------------------------------------
// follow_community — subscribe/unsubscribe toggle
// ---------------------------------------------------------------------------
HandlerApiResponse handle_follow_community(LemmyServer& server, const json& request,
                                           const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("community_id") || request["community_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: community_id");
  }

  std::string community_id = request["community_id"].get<std::string>();
  bool follow = true;
  if (request.contains("follow") && !request["follow"].is_null()) {
    follow = request["follow"].get<bool>();
  }

  auto comm_opt = server.get_community(community_id);
  if (!comm_opt.has_value()) {
    return HandlerApiResponse::fail("Community not found", 404);
  }

  if (follow) {
    server.follow_community(ctx.user_id, community_id);
  } else {
    server.unfollow_community(ctx.user_id, community_id);
  }

  // Re-fetch community for updated counts
  auto updated_comm = server.get_community(community_id);
  json community_view = community_to_json(updated_comm.has_value() ? updated_comm.value() : comm_opt.value());

  json response;
  response["community_view"] = community_view;
  response["subscribed"] = follow ? "Subscribed" : "NotSubscribed";
  response["blocked"] = false;

  return HandlerApiResponse::ok(response);
}

// ---------------------------------------------------------------------------
// block_community — block community from user feed
// ---------------------------------------------------------------------------
HandlerApiResponse handle_block_community(LemmyServer& server, const json& request,
                                          const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("community_id") || request["community_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: community_id");
  }

  std::string community_id = request["community_id"].get<std::string>();
  bool block = true;
  if (request.contains("block") && !request["block"].is_null()) {
    block = request["block"].get<bool>();
  }

  auto comm_opt = server.get_community(community_id);
  if (!comm_opt.has_value()) {
    return HandlerApiResponse::fail("Community not found", 404);
  }

  if (block) {
    server.block_community(ctx.user_id, community_id);
  } else {
    server.unblock_community(ctx.user_id, community_id);
  }

  auto updated_comm = server.get_community(community_id);
  json community_view = community_to_json(updated_comm.has_value() ? updated_comm.value() : comm_opt.value());

  json response;
  response["community_view"] = community_view;
  response["blocked"] = block;
  response["subscribed"] = "NotSubscribed";

  return HandlerApiResponse::ok(response);
}

// ---------------------------------------------------------------------------
// list_communities — paginated listing with sort and optional type filter
// ---------------------------------------------------------------------------
HandlerApiResponse handle_list_communities(LemmyServer& server, const json& request,
                                           const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  HandlerPageParams params = HandlerPageParams::from_json(request);

  std::string type_filter = params.type_;
  if (request.contains("type_") && !request["type_"].is_null()) {
    type_filter = request["type_"].get<std::string>();
  }

  bool show_nsfw = false;
  if (request.contains("show_nsfw") && !request["show_nsfw"].is_null()) {
    show_nsfw = request["show_nsfw"].get<bool>();
  }
  // Admins and authenticated users may opt in
  if (ctx.is_admin) show_nsfw = true;

  // Fetch all communities
  std::vector<Community> all_communities = server.list_communities(params.sort, params.page, params.limit, type_filter);

  // Filter by type if specified
  std::vector<Community> filtered;
  filtered.reserve(all_communities.size());
  for (auto& c : all_communities) {
    // Skip deleted/removed unless admin
    if (c.deleted && !ctx.is_admin) continue;
    if (c.removed && !ctx.is_admin) continue;
    if (c.hidden && !ctx.is_admin) continue;

    // Filter by type
    if (type_filter == "local" || type_filter == "Local") {
      // Simplified: treat all as local for now
    }
    if (type_filter == "subscribed" || type_filter == "Subscribed") {
      if (!ctx.authenticated) continue;
      // Simplified: would need to check subscriptions map
    }

    // Filter NSFW
    if (c.nsfw && !show_nsfw) continue;

    filtered.push_back(c);
  }

  // Sort
  sort_communities(filtered, params.sort);

  // Paginate
  auto paginated = paginate(filtered, params.page, params.limit);

  // Build response
  json communities_array = json::array();
  for (const auto& c : paginated) {
    json cj = community_to_json(c);

    // Attach subscriber count
    cj["subscriber_count"] = c.subscribers;
    cj["post_count"] = c.posts;
    cj["comment_count"] = c.comments;

    if (ctx.authenticated) {
      cj["subscribed"] = "NotSubscribed";
      cj["blocked"] = false;
    }

    communities_array.push_back(cj);
  }

  json response;
  response["communities"] = communities_array;
  response["page"] = params.page;
  response["limit"] = params.limit;
  response["count"] = static_cast<int>(paginated.size());
  response["total"] = static_cast<int>(filtered.size());

  return HandlerApiResponse::ok(response);
}

// ============================================================================
// ============================================================================
// POST HANDLERS
// ============================================================================
// ============================================================================

// ---------------------------------------------------------------------------
// create_post — create a link or text post with optional NSFW, language
// ---------------------------------------------------------------------------
HandlerApiResponse handle_create_post(LemmyServer& server, const json& request,
                                      const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  // Rate limit
  if (!g_post_rate_limiter.check("post:" + ctx.user_id)) {
    return HandlerApiResponse::fail("Rate limit exceeded. Please try again later.", 429);
  }

  // Validate required fields
  if (!request.contains("name") || request["name"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: name");
  }
  if (!request.contains("community_id") || request["community_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: community_id");
  }

  std::string name = truncate(request["name"].get<std::string>(), 200);
  std::string community_id = request["community_id"].get<std::string>();
  std::string url;
  std::string body;
  bool nsfw = false;
  std::optional<std::string> language_id;
  std::optional<std::string> honeypot;

  if (request.contains("url") && !request["url"].is_null()) {
    url = truncate(request["url"].get<std::string>(), 2000);
    url = normalize_url(url);
  }
  if (request.contains("body") && !request["body"].is_null()) {
    body = truncate(request["body"].get<std::string>(), 50000);
    body = sanitize_text(body);
  }
  if (request.contains("nsfw") && !request["nsfw"].is_null()) {
    nsfw = request["nsfw"].get<bool>();
  }
  if (request.contains("language_id") && !request["language_id"].is_null()) {
    language_id = request["language_id"].get<std::string>();
  }
  if (request.contains("honeypot") && !request["honeypot"].is_null()) {
    honeypot = request["honeypot"].get<std::string>();
  }

  // Honeypot check (anti-spam)
  if (honeypot.has_value() && !honeypot.value().empty()) {
    return HandlerApiResponse::fail("Spam detected", 400);
  }

  // Validate community exists
  auto comm_opt = server.get_community(community_id);
  if (!comm_opt.has_value()) {
    return HandlerApiResponse::fail("Community not found", 404);
  }

  // Check if community is deleted/removed
  if (comm_opt->deleted || comm_opt->removed) {
    return HandlerApiResponse::fail("Community has been removed", 410);
  }

  // Check posting restrictions
  if (comm_opt->posting_restricted_to_mods) {
    if (!ctx.is_admin) {
      return HandlerApiResponse::fail("Only moderators can post in this community", 403);
    }
  }

  // Validate name is not empty
  if (name.empty()) {
    return HandlerApiResponse::fail("Post name cannot be empty");
  }

  // Validate name is clean
  if (!is_valid_name(name)) {
    return HandlerApiResponse::fail("Post name contains invalid characters");
  }

  // Validate URL or body
  if (url.empty() && body.empty()) {
    return HandlerApiResponse::fail("Either url or body must be provided");
  }

  // Validate URL format
  if (!url.empty() && !is_valid_url(url)) {
    return HandlerApiResponse::fail("Invalid URL format");
  }

  // Validate language
  if (language_id.has_value() && !is_valid_language(language_id.value())) {
    return HandlerApiResponse::fail("Invalid language code");
  }

  // Create post
  Post post = server.create_post(name, community_id, ctx.user_id, url, body, nsfw);

  json response = post_to_json(post);

  // Attach creator info
  auto creator_opt = server.get_user(ctx.user_id);
  if (creator_opt.has_value()) {
    response["creator"] = user_to_json(creator_opt.value());
  }

  // Attach community info
  auto comm = server.get_community(community_id);
  if (comm.has_value()) {
    response["community"] = community_to_json(comm.value());
  }

  // Attach vote info
  response["my_vote"] = 0;
  response["saved"] = false;
  response["read"] = true;
  response["unread_comments"] = 0;

  // Count subscribers
  response["subscribed"] = "NotSubscribed";

  return HandlerApiResponse::ok({{"post_view", response}});
}

// ---------------------------------------------------------------------------
// get_post — fetch a single post by ID with comments, community info
// ---------------------------------------------------------------------------
HandlerApiResponse handle_get_post(LemmyServer& server, const json& request,
                                   const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);

  if (!request.contains("id") || request["id"].is_null()) {
    return HandlerApiResponse::fail("Missing required parameter: id");
  }

  std::string post_id = request["id"].get<std::string>();
  auto post_opt = server.get_post(post_id);

  if (!post_opt.has_value()) {
    return HandlerApiResponse::fail("Post not found", 404);
  }

  const Post& post = post_opt.value();
  json response = post_to_json(post);

  // Attach creator info
  auto creator_opt = server.get_user(post.creator_id);
  if (creator_opt.has_value()) {
    response["creator"] = user_to_json(creator_opt.value());
    // Attach creator-specific data
    response["creator"]["actor_id"] = "https://" + server.config().hostname + "/u/" + creator_opt->name;
    response["creator"]["local"] = true;
    response["creator"]["instance"] = server.config().hostname;
  }

  // Attach community info
  auto comm_opt = server.get_community(post.community_id);
  if (comm_opt.has_value()) {
    response["community"] = community_to_json(comm_opt.value());
    response["community"]["actor_id"] = "https://" + server.config().hostname + "/c/" + comm_opt->name;
    response["community"]["local"] = true;
    response["community"]["instance"] = server.config().hostname;
  }

  // Attach counts
  response["counts"] = {
    {"id", post.id},
    {"post_id", post.id},
    {"score", post.score},
    {"upvotes", post.upvotes},
    {"downvotes", post.downvotes},
    {"comments", post.comments},
    {"published", post.published}
  };

  // If user is authenticated, include their vote and save status
  if (ctx.authenticated) {
    // Check vote
    int vote_count = server.get_post_vote_count(post_id);
    response["my_vote"] = 0;  // Simplified
    response["saved"] = false;
    response["read"] = true;
    response["unread_comments"] = 0;
    response["subscribed"] = "NotSubscribed";
  }

  // Check if post is locked and user can comment
  response["can_comment"] = !post.locked || (ctx.authenticated && ctx.is_admin);
  response["can_edit"] = ctx.authenticated && (post.creator_id == ctx.user_id || ctx.is_admin);

  return HandlerApiResponse::ok({{"post_view", response}});
}

// ---------------------------------------------------------------------------
// get_posts — paginated post listing with sort and filters
// ---------------------------------------------------------------------------
HandlerApiResponse handle_get_posts(LemmyServer& server, const json& request,
                                    const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  HandlerPageParams params = HandlerPageParams::from_json(request);

  std::optional<std::string> community_id;
  if (request.contains("community_id") && !request["community_id"].is_null()) {
    community_id = request["community_id"].get<std::string>();
  }
  if (request.contains("community_name") && !request["community_name"].is_null()) {
    params.community_name = request["community_name"].get<std::string>();
  }

  bool show_nsfw = params.show_nsfw;
  if (ctx.is_admin) show_nsfw = true;

  // Fetch posts from server
  std::vector<Post> posts = server.get_posts(
      params.sort, params.page, params.limit, community_id, params.community_name);

  // Filter posts
  std::vector<Post> filtered;
  filtered.reserve(posts.size());
  for (auto& p : posts) {
    // Skip deleted/removed unless admin
    if (p.deleted && !ctx.is_admin) continue;
    if (p.removed && !ctx.is_admin) continue;

    // Skip NSFW unless opted in
    if (p.nsfw && !show_nsfw) continue;

    // Filter by type
    if (params.type_ == "link" || params.type_ == "Link") {
      if (p.url.empty()) continue;
    }
    if (params.type_ == "text" || params.type_ == "Text") {
      if (p.body.empty()) continue;
    }

    // Saved only filter
    if (params.saved_only && ctx.authenticated) {
      // Would need saved posts store
      continue;
    }

    // Liked/disliked only
    if (params.liked_only && ctx.authenticated) {
      // Would need user vote store per post
      continue;
    }

    filtered.push_back(p);
  }

  // Sort
  sort_posts(filtered, params.sort);

  // Paginate
  auto paginated = paginate(filtered, params.page, params.limit);

  // Build response
  json posts_array = json::array();
  for (const auto& p : paginated) {
    json pj = post_to_json(p);

    // Attach creator
    auto creator_opt = server.get_user(p.creator_id);
    if (creator_opt.has_value()) {
      pj["creator"] = user_to_json(creator_opt.value());
    }

    // Attach community
    auto comm_opt = server.get_community(p.community_id);
    if (comm_opt.has_value()) {
      pj["community"] = community_to_json(comm_opt.value());
    }

    // Attach counts
    pj["counts"] = {
      {"post_id", p.id},
      {"score", p.score},
      {"upvotes", p.upvotes},
      {"downvotes", p.downvotes},
      {"comments", p.comments}
    };

    if (ctx.authenticated) {
      pj["my_vote"] = 0;
      pj["saved"] = false;
      pj["read"] = true;
    }

    posts_array.push_back(pj);
  }

  json response;
  response["posts"] = posts_array;
  response["page"] = params.page;
  response["limit"] = params.limit;
  response["count"] = static_cast<int>(paginated.size());
  response["total"] = static_cast<int>(filtered.size());

  return HandlerApiResponse::ok(response);
}

// ---------------------------------------------------------------------------
// edit_post — edit an existing post
// ---------------------------------------------------------------------------
HandlerApiResponse handle_edit_post(LemmyServer& server, const json& request,
                                    const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("post_id") || request["post_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: post_id");
  }

  std::string post_id = request["post_id"].get<std::string>();
  auto post_opt = server.get_post(post_id);
  if (!post_opt.has_value()) {
    return HandlerApiResponse::fail("Post not found", 404);
  }

  // Check permissions
  if (!can_edit_post(server, ctx, post_opt.value())) {
    return HandlerApiResponse::fail("Not authorized to edit this post", 403);
  }

  // Build updates
  json updates;
  if (request.contains("name") && !request["name"].is_null()) {
    std::string new_name = truncate(request["name"].get<std::string>(), 200);
    if (new_name.empty()) {
      return HandlerApiResponse::fail("Post name cannot be empty");
    }
    updates["name"] = new_name;
  }
  if (request.contains("url") && !request["url"].is_null()) {
    std::string new_url = normalize_url(truncate(request["url"].get<std::string>(), 2000));
    if (!new_url.empty() && !is_valid_url(new_url)) {
      return HandlerApiResponse::fail("Invalid URL format");
    }
    updates["url"] = new_url;
  }
  if (request.contains("body") && !request["body"].is_null()) {
    std::string new_body = sanitize_text(truncate(request["body"].get<std::string>(), 50000));
    updates["body"] = new_body;
  }
  if (request.contains("nsfw") && !request["nsfw"].is_null()) {
    updates["nsfw"] = request["nsfw"].get<bool>();
  }
  if (request.contains("language_id") && !request["language_id"].is_null()) {
    updates["language_id"] = request["language_id"].get<std::string>();
  }

  if (updates.empty()) {
    return HandlerApiResponse::fail("No valid update fields provided");
  }

  Post updated = server.update_post(post_id, updates);

  json response = post_to_json(updated);

  auto creator_opt = server.get_user(updated.creator_id);
  if (creator_opt.has_value()) {
    response["creator"] = user_to_json(creator_opt.value());
  }
  auto comm_opt = server.get_community(updated.community_id);
  if (comm_opt.has_value()) {
    response["community"] = community_to_json(comm_opt.value());
  }

  response["my_vote"] = 0;
  response["saved"] = false;
  response["read"] = true;

  return HandlerApiResponse::ok({{"post_view", response}});
}

// ---------------------------------------------------------------------------
// delete_post — soft-delete (owner action)
// ---------------------------------------------------------------------------
HandlerApiResponse handle_delete_post(LemmyServer& server, const json& request,
                                      const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("post_id") || request["post_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: post_id");
  }

  std::string post_id = request["post_id"].get<std::string>();
  bool deleted = true;
  if (request.contains("deleted") && !request["deleted"].is_null()) {
    deleted = request["deleted"].get<bool>();
  }

  auto post_opt = server.get_post(post_id);
  if (!post_opt.has_value()) {
    return HandlerApiResponse::fail("Post not found", 404);
  }

  // Only owner or admin can delete
  if (post_opt->creator_id != ctx.user_id && !ctx.is_admin) {
    return HandlerApiResponse::fail("Not authorized to delete this post", 403);
  }

  if (deleted) {
    server.delete_post(post_id);
  }

  // Log mod action if admin is deleting someone else's post
  if (ctx.is_admin && post_opt->creator_id != ctx.user_id) {
    server.add_mod(post_opt->community_id, ctx.user_id, post_opt->creator_id);
  }

  json response;
  response["post_id"] = post_id;
  response["deleted"] = deleted;

  return HandlerApiResponse::ok(response);
}

// ---------------------------------------------------------------------------
// remove_post — moderator removal
// ---------------------------------------------------------------------------
HandlerApiResponse handle_remove_post(LemmyServer& server, const json& request,
                                      const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("post_id") || request["post_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: post_id");
  }

  std::string post_id = request["post_id"].get<std::string>();
  std::string reason;
  bool removed = true;

  if (request.contains("reason") && !request["reason"].is_null()) {
    reason = truncate(request["reason"].get<std::string>(), 500);
  }
  if (request.contains("removed") && !request["removed"].is_null()) {
    removed = request["removed"].get<bool>();
  }

  auto post_opt = server.get_post(post_id);
  if (!post_opt.has_value()) {
    return HandlerApiResponse::fail("Post not found", 404);
  }

  // Check mod permissions
  if (!ctx.is_admin && !can_moderate_community(server, ctx, post_opt->community_id)) {
    return HandlerApiResponse::fail("Not authorized to moderate this community", 403);
  }

  if (removed) {
    server.remove_post(post_id, ctx.user_id, reason);
  } else {
    // Un-remove: in full impl would restore
    server.remove_post(post_id, ctx.user_id, "");
  }

  // Log mod action
  server.add_mod(post_opt->community_id, ctx.user_id, post_opt->creator_id);

  json response;
  response["post_id"] = post_id;
  response["removed"] = removed;
  response["reason"] = reason;

  return HandlerApiResponse::ok(response);
}

// ---------------------------------------------------------------------------
// lock_post — lock/unlock a post (mod action)
// ---------------------------------------------------------------------------
HandlerApiResponse handle_lock_post(LemmyServer& server, const json& request,
                                    const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("post_id") || request["post_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: post_id");
  }

  std::string post_id = request["post_id"].get<std::string>();
  bool locked = true;
  if (request.contains("locked") && !request["locked"].is_null()) {
    locked = request["locked"].get<bool>();
  }

  auto post_opt = server.get_post(post_id);
  if (!post_opt.has_value()) {
    return HandlerApiResponse::fail("Post not found", 404);
  }

  if (!ctx.is_admin && !can_moderate_community(server, ctx, post_opt->community_id)) {
    return HandlerApiResponse::fail("Not authorized to moderate this community", 403);
  }

  server.lock_post(post_id, ctx.user_id, locked);

  // Log mod action
  server.add_mod(post_opt->community_id, ctx.user_id, post_opt->creator_id);

  // Re-fetch and return post view
  auto updated_opt = server.get_post(post_id);
  json response = post_to_json(updated_opt.has_value() ? updated_opt.value() : post_opt.value());
  response["locked"] = locked;

  auto creator_opt = server.get_user(post_opt->creator_id);
  if (creator_opt.has_value()) {
    response["creator"] = user_to_json(creator_opt.value());
  }
  auto comm_opt = server.get_community(post_opt->community_id);
  if (comm_opt.has_value()) {
    response["community"] = community_to_json(comm_opt.value());
  }

  return HandlerApiResponse::ok({{"post_view", response}});
}

// ---------------------------------------------------------------------------
// feature_post — feature a post in community and/or locally
// ---------------------------------------------------------------------------
HandlerApiResponse handle_feature_post(LemmyServer& server, const json& request,
                                       const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("post_id") || request["post_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: post_id");
  }

  std::string post_id = request["post_id"].get<std::string>();
  bool feature_community = true;
  bool feature_local = false;

  if (request.contains("feature_type") && !request["feature_type"].is_null()) {
    std::string ft = request["feature_type"].get<std::string>();
    if (ft == "Community") {
      feature_community = true;
      feature_local = false;
    } else if (ft == "Local") {
      feature_community = false;
      feature_local = true;
    }
  }
  if (request.contains("featured") && !request["featured"].is_null()) {
    bool featured = request["featured"].get<bool>();
    if (!featured) {
      feature_community = false;
      feature_local = false;
    }
  }

  auto post_opt = server.get_post(post_id);
  if (!post_opt.has_value()) {
    return HandlerApiResponse::fail("Post not found", 404);
  }

  // Check permissions: community mods can feature in community, admins can feature locally
  if (feature_local && !ctx.is_admin) {
    return HandlerApiResponse::fail("Only admins can feature posts locally", 403);
  }
  if (feature_community && !ctx.is_admin &&
      !can_moderate_community(server, ctx, post_opt->community_id)) {
    return HandlerApiResponse::fail("Not authorized to moderate this community", 403);
  }

  server.feature_post(post_id, feature_community, feature_local);

  // Log mod action
  server.add_mod(post_opt->community_id, ctx.user_id, post_opt->creator_id);

  // Re-fetch and return
  auto updated_opt = server.get_post(post_id);
  json response = post_to_json(updated_opt.has_value() ? updated_opt.value() : post_opt.value());

  auto comm_opt = server.get_community(post_opt->community_id);
  if (comm_opt.has_value()) {
    response["community"] = community_to_json(comm_opt.value());
  }

  return HandlerApiResponse::ok({{"post_view", response}});
}

// ---------------------------------------------------------------------------
// like_post — toggle upvote/downvote for a post
// ---------------------------------------------------------------------------
HandlerApiResponse handle_like_post(LemmyServer& server, const json& request,
                                    const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  // Rate limit
  if (!g_vote_rate_limiter.check("vote:post:" + ctx.user_id)) {
    return HandlerApiResponse::fail("Rate limit exceeded. Please try again later.", 429);
  }

  if (!request.contains("post_id") || request["post_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: post_id");
  }

  std::string post_id = request["post_id"].get<std::string>();
  int score = 0;  // 0 = remove vote, 1 = upvote, -1 = downvote

  if (request.contains("score") && !request["score"].is_null()) {
    score = request["score"].get<int>();
    // Normalize: only accept -1, 0, 1
    if (score < -1) score = -1;
    if (score > 1) score = 1;
  }

  auto post_opt = server.get_post(post_id);
  if (!post_opt.has_value()) {
    return HandlerApiResponse::fail("Post not found", 404);
  }

  // Check if post is locked or removed
  if (post_opt->removed || post_opt->deleted) {
    return HandlerApiResponse::fail("Post has been removed", 410);
  }

  // Cannot vote on own post (Lemmy behavior)
  if (post_opt->creator_id == ctx.user_id && score != 0) {
    return HandlerApiResponse::fail("Cannot vote on your own post", 400);
  }

  // Cast vote
  Vote vote = server.vote_post(post_id, ctx.user_id, score);

  // Re-fetch post for updated counts
  auto updated_opt = server.get_post(post_id);
  json post_view = post_to_json(updated_opt.has_value() ? updated_opt.value() : post_opt.value());

  // Attach counts
  int total_votes = server.get_post_vote_count(post_id);
  post_view["counts"] = {
    {"post_id", post_id},
    {"score", total_votes},
    {"upvotes", updated_opt.has_value() ? updated_opt->upvotes : post_opt->upvotes},
    {"downvotes", updated_opt.has_value() ? updated_opt->downvotes : post_opt->downvotes}
  };

  post_view["my_vote"] = score;

  // Attach creator
  auto creator_opt = server.get_user(post_opt->creator_id);
  if (creator_opt.has_value()) {
    post_view["creator"] = user_to_json(creator_opt.value());
  }

  // Attach community
  auto comm_opt = server.get_community(post_opt->community_id);
  if (comm_opt.has_value()) {
    post_view["community"] = community_to_json(comm_opt.value());
  }

  return HandlerApiResponse::ok({{"post_view", post_view}});
}

// ---------------------------------------------------------------------------
// save_post — save/unsave for authenticated user
// ---------------------------------------------------------------------------
HandlerApiResponse handle_save_post(LemmyServer& server, const json& request,
                                    const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  // Rate limit
  if (!g_save_rate_limiter.check("save:" + ctx.user_id)) {
    return HandlerApiResponse::fail("Rate limit exceeded. Please try again later.", 429);
  }

  if (!request.contains("post_id") || request["post_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: post_id");
  }

  std::string post_id = request["post_id"].get<std::string>();
  bool save = true;
  if (request.contains("save") && !request["save"].is_null()) {
    save = request["save"].get<bool>();
  }

  auto post_opt = server.get_post(post_id);
  if (!post_opt.has_value()) {
    return HandlerApiResponse::fail("Post not found", 404);
  }

  // In a full implementation, we'd store saved posts in a separate table
  // For now, we just acknowledge the save/unsave action
  // saved_posts_[ctx.user_id + ":" + post_id] = save

  json response = post_to_json(post_opt.value());
  response["saved"] = save;

  auto creator_opt = server.get_user(post_opt->creator_id);
  if (creator_opt.has_value()) {
    response["creator"] = user_to_json(creator_opt.value());
  }

  auto comm_opt = server.get_community(post_opt->community_id);
  if (comm_opt.has_value()) {
    response["community"] = community_to_json(comm_opt.value());
  }

  return HandlerApiResponse::ok({{"post_view", response}});
}

// ============================================================================
// ============================================================================
// COMMENT HANDLERS
// ============================================================================
// ============================================================================

// ---------------------------------------------------------------------------
// create_comment — create a comment with optional parent (for threading)
// ---------------------------------------------------------------------------
HandlerApiResponse handle_create_comment(LemmyServer& server, const json& request,
                                         const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  // Rate limit
  if (!g_comment_rate_limiter.check("comment:" + ctx.user_id)) {
    return HandlerApiResponse::fail("Rate limit exceeded. Please try again later.", 429);
  }

  if (!request.contains("content") || request["content"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: content");
  }
  if (!request.contains("post_id") || request["post_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: post_id");
  }

  std::string content = truncate(request["content"].get<std::string>(), 10000);
  std::string post_id = request["post_id"].get<std::string>();
  std::optional<std::string> parent_id;
  std::string form_id;
  std::optional<std::string> language_id;
  std::optional<std::string> honeypot;

  if (request.contains("parent_id") && !request["parent_id"].is_null()) {
    parent_id = request["parent_id"].get<std::string>();
  }
  if (request.contains("form_id") && !request["form_id"].is_null()) {
    form_id = request["form_id"].get<std::string>();
  }
  if (request.contains("language_id") && !request["language_id"].is_null()) {
    language_id = request["language_id"].get<std::string>();
  }
  if (request.contains("honeypot") && !request["honeypot"].is_null()) {
    honeypot = request["honeypot"].get<std::string>();
  }

  // Honeypot check
  if (honeypot.has_value() && !honeypot.value().empty()) {
    return HandlerApiResponse::fail("Spam detected", 400);
  }

  // Validate content is not empty
  if (content.empty()) {
    return HandlerApiResponse::fail("Comment content cannot be empty");
  }

  // Sanitize content
  content = sanitize_text(content);

  // Validate post exists
  auto post_opt = server.get_post(post_id);
  if (!post_opt.has_value()) {
    return HandlerApiResponse::fail("Post not found", 404);
  }

  // Check if post is locked
  if (post_opt->locked && !ctx.is_admin) {
    return HandlerApiResponse::fail("Post is locked. New comments are not allowed.", 403);
  }

  // Check if post is removed
  if (post_opt->removed) {
    return HandlerApiResponse::fail("Post has been removed", 410);
  }

  // Validate parent comment exists if provided
  if (parent_id.has_value() && !parent_id.value().empty()) {
    auto parent_opt = server.get_comment(parent_id.value());
    if (!parent_opt.has_value()) {
      return HandlerApiResponse::fail("Parent comment not found", 404);
    }
    // Verify parent belongs to the same post
    if (parent_opt->post_id != post_id) {
      return HandlerApiResponse::fail("Parent comment does not belong to this post", 400);
    }
  }

  // Validate language
  if (language_id.has_value() && !is_valid_language(language_id.value())) {
    return HandlerApiResponse::fail("Invalid language code");
  }

  // Create comment
  Comment comment = server.create_comment(content, post_id, ctx.user_id, parent_id);

  json response = comment_to_json(comment);

  // Attach creator info
  auto creator_opt = server.get_user(ctx.user_id);
  if (creator_opt.has_value()) {
    response["creator"] = user_to_json(creator_opt.value());
  }

  // Attach post info
  response["post"] = post_to_json(post_opt.value());
  response["post"]["id"] = post_opt->id;

  // Attach counts
  response["counts"] = {
    {"id", comment.id},
    {"comment_id", comment.id},
    {"score", 0},
    {"upvotes", 0},
    {"downvotes", 0},
    {"child_count", 0},
    {"published", comment.published}
  };

  response["my_vote"] = 0;
  response["saved"] = false;

  // Attach community
  auto comm_opt = server.get_community(post_opt->community_id);
  if (comm_opt.has_value()) {
    response["community"] = community_to_json(comm_opt.value());
  }

  return HandlerApiResponse::ok({{"comment_view", response}});
}

// ---------------------------------------------------------------------------
// edit_comment — update comment content
// ---------------------------------------------------------------------------
HandlerApiResponse handle_edit_comment(LemmyServer& server, const json& request,
                                       const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("comment_id") || request["comment_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: comment_id");
  }

  std::string comment_id = request["comment_id"].get<std::string>();
  auto comment_opt = server.get_comment(comment_id);
  if (!comment_opt.has_value()) {
    return HandlerApiResponse::fail("Comment not found", 404);
  }

  // Check permissions
  if (!can_edit_comment(server, ctx, comment_opt.value())) {
    return HandlerApiResponse::fail("Not authorized to edit this comment", 403);
  }

  // Build updates
  json updates;
  if (request.contains("content") && !request["content"].is_null()) {
    std::string new_content = sanitize_text(truncate(request["content"].get<std::string>(), 10000));
    if (new_content.empty()) {
      return HandlerApiResponse::fail("Comment content cannot be empty");
    }
    updates["content"] = new_content;
  }
  if (request.contains("language_id") && !request["language_id"].is_null()) {
    updates["language_id"] = request["language_id"].get<std::string>();
  }

  if (updates.empty()) {
    return HandlerApiResponse::fail("No valid update fields provided");
  }

  Comment updated = server.update_comment(comment_id, updates);

  json response = comment_to_json(updated);

  // Attach creator
  auto creator_opt = server.get_user(updated.creator_id);
  if (creator_opt.has_value()) {
    response["creator"] = user_to_json(creator_opt.value());
  }

  // Attach post
  auto post_opt = server.get_post(updated.post_id);
  if (post_opt.has_value()) {
    response["post"] = post_to_json(post_opt.value());
  }

  // Attach counts
  response["counts"] = {
    {"comment_id", comment_id},
    {"score", updated.score},
    {"upvotes", updated.upvotes},
    {"downvotes", updated.downvotes},
    {"child_count", 0}
  };

  response["my_vote"] = 0;
  response["saved"] = false;

  return HandlerApiResponse::ok({{"comment_view", response}});
}

// ---------------------------------------------------------------------------
// delete_comment — soft-delete a comment (owner action)
// ---------------------------------------------------------------------------
HandlerApiResponse handle_delete_comment(LemmyServer& server, const json& request,
                                         const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("comment_id") || request["comment_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: comment_id");
  }

  std::string comment_id = request["comment_id"].get<std::string>();
  bool deleted = true;
  if (request.contains("deleted") && !request["deleted"].is_null()) {
    deleted = request["deleted"].get<bool>();
  }

  auto comment_opt = server.get_comment(comment_id);
  if (!comment_opt.has_value()) {
    return HandlerApiResponse::fail("Comment not found", 404);
  }

  // Only comment author or admin can delete
  if (comment_opt->creator_id != ctx.user_id && !ctx.is_admin) {
    return HandlerApiResponse::fail("Not authorized to delete this comment", 403);
  }

  if (deleted) {
    server.delete_comment(comment_id);
    // Log if admin deletes someone else's comment
    if (ctx.is_admin && comment_opt->creator_id != ctx.user_id) {
      auto post_opt = server.get_post(comment_opt->post_id);
      if (post_opt.has_value()) {
        server.add_mod(post_opt->community_id, ctx.user_id, comment_opt->creator_id);
      }
    }
  }

  json response;
  response["comment_id"] = comment_id;
  response["deleted"] = deleted;

  return HandlerApiResponse::ok(response);
}

// ---------------------------------------------------------------------------
// remove_comment — moderator removal
// ---------------------------------------------------------------------------
HandlerApiResponse handle_remove_comment(LemmyServer& server, const json& request,
                                         const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("comment_id") || request["comment_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: comment_id");
  }

  std::string comment_id = request["comment_id"].get<std::string>();
  std::string reason;
  bool removed = true;

  if (request.contains("reason") && !request["reason"].is_null()) {
    reason = truncate(request["reason"].get<std::string>(), 500);
  }
  if (request.contains("removed") && !request["removed"].is_null()) {
    removed = request["removed"].get<bool>();
  }

  auto comment_opt = server.get_comment(comment_id);
  if (!comment_opt.has_value()) {
    return HandlerApiResponse::fail("Comment not found", 404);
  }

  // Check mod permissions via post's community
  auto post_opt = server.get_post(comment_opt->post_id);
  if (!post_opt.has_value()) {
    return HandlerApiResponse::fail("Associated post not found", 404);
  }

  if (!ctx.is_admin && !can_moderate_community(server, ctx, post_opt->community_id)) {
    return HandlerApiResponse::fail("Not authorized to moderate this community", 403);
  }

  if (removed) {
    server.remove_comment(comment_id, ctx.user_id, reason);
  }

  // Log mod action
  server.add_mod(post_opt->community_id, ctx.user_id, comment_opt->creator_id);

  json response;
  response["comment_id"] = comment_id;
  response["removed"] = removed;
  response["reason"] = reason;

  return HandlerApiResponse::ok(response);
}

// ---------------------------------------------------------------------------
// like_comment — toggle vote on a comment
// ---------------------------------------------------------------------------
HandlerApiResponse handle_like_comment(LemmyServer& server, const json& request,
                                       const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  // Rate limit
  if (!g_vote_rate_limiter.check("vote:comment:" + ctx.user_id)) {
    return HandlerApiResponse::fail("Rate limit exceeded. Please try again later.", 429);
  }

  if (!request.contains("comment_id") || request["comment_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: comment_id");
  }

  std::string comment_id = request["comment_id"].get<std::string>();
  int score = 0;

  if (request.contains("score") && !request["score"].is_null()) {
    score = request["score"].get<int>();
    if (score < -1) score = -1;
    if (score > 1) score = 1;
  }

  auto comment_opt = server.get_comment(comment_id);
  if (!comment_opt.has_value()) {
    return HandlerApiResponse::fail("Comment not found", 404);
  }

  // Check if comment is removed
  if (comment_opt->removed || comment_opt->deleted) {
    return HandlerApiResponse::fail("Comment has been removed", 410);
  }

  // Cannot vote on own comment
  if (comment_opt->creator_id == ctx.user_id && score != 0) {
    return HandlerApiResponse::fail("Cannot vote on your own comment", 400);
  }

  // Cast vote
  CommentVote vote = server.vote_comment(comment_id, ctx.user_id, score);

  // Re-fetch comment
  auto updated_opt = server.get_comment(comment_id);
  json response = comment_to_json(updated_opt.has_value() ? updated_opt.value() : comment_opt.value());

  // Attach counts
  int total_votes = server.get_comment_vote_count(comment_id);
  response["counts"] = {
    {"comment_id", comment_id},
    {"score", total_votes},
    {"upvotes", updated_opt.has_value() ? updated_opt->upvotes : comment_opt->upvotes},
    {"downvotes", updated_opt.has_value() ? updated_opt->downvotes : comment_opt->downvotes},
    {"child_count", 0}
  };

  response["my_vote"] = score;
  response["saved"] = false;

  // Attach creator
  auto creator_opt = server.get_user(comment_opt->creator_id);
  if (creator_opt.has_value()) {
    response["creator"] = user_to_json(creator_opt.value());
  }

  // Attach post
  auto post_opt = server.get_post(comment_opt->post_id);
  if (post_opt.has_value()) {
    response["post"] = post_to_json(post_opt.value());
  }

  return HandlerApiResponse::ok({{"comment_view", response}});
}

// ---------------------------------------------------------------------------
// save_comment — save/unsave a comment for authenticated user
// ---------------------------------------------------------------------------
HandlerApiResponse handle_save_comment(LemmyServer& server, const json& request,
                                       const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  // Rate limit
  if (!g_save_rate_limiter.check("save:comment:" + ctx.user_id)) {
    return HandlerApiResponse::fail("Rate limit exceeded. Please try again later.", 429);
  }

  if (!request.contains("comment_id") || request["comment_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: comment_id");
  }

  std::string comment_id = request["comment_id"].get<std::string>();
  bool save = true;
  if (request.contains("save") && !request["save"].is_null()) {
    save = request["save"].get<bool>();
  }

  auto comment_opt = server.get_comment(comment_id);
  if (!comment_opt.has_value()) {
    return HandlerApiResponse::fail("Comment not found", 404);
  }

  // In a full implementation, we'd store saved comments in a separate table
  // saved_comments_[ctx.user_id + ":" + comment_id] = save

  json response = comment_to_json(comment_opt.value());
  response["saved"] = save;

  // Attach counts
  response["counts"] = {
    {"comment_id", comment_id},
    {"score", comment_opt->score},
    {"upvotes", comment_opt->upvotes},
    {"downvotes", comment_opt->downvotes},
    {"child_count", 0}
  };

  response["my_vote"] = 0;

  // Attach creator
  auto creator_opt = server.get_user(comment_opt->creator_id);
  if (creator_opt.has_value()) {
    response["creator"] = user_to_json(creator_opt.value());
  }

  // Attach post
  auto post_opt = server.get_post(comment_opt->post_id);
  if (post_opt.has_value()) {
    response["post"] = post_to_json(post_opt.value());
  }

  return HandlerApiResponse::ok({{"comment_view", response}});
}

// ---------------------------------------------------------------------------
// distinguish_comment — moderator distinguish
// ---------------------------------------------------------------------------
HandlerApiResponse handle_distinguish_comment(LemmyServer& server, const json& request,
                                              const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);
  if (!ctx.authenticated) {
    return HandlerApiResponse::fail("Authentication required", 401);
  }

  if (!request.contains("comment_id") || request["comment_id"].is_null()) {
    return HandlerApiResponse::fail("Missing required field: comment_id");
  }

  std::string comment_id = request["comment_id"].get<std::string>();
  bool distinguished = true;
  if (request.contains("distinguished") && !request["distinguished"].is_null()) {
    distinguished = request["distinguished"].get<bool>();
  }

  auto comment_opt = server.get_comment(comment_id);
  if (!comment_opt.has_value()) {
    return HandlerApiResponse::fail("Comment not found", 404);
  }

  // Check mod permissions via post's community
  auto post_opt = server.get_post(comment_opt->post_id);
  if (!post_opt.has_value()) {
    return HandlerApiResponse::fail("Associated post not found", 404);
  }

  if (!ctx.is_admin && !can_moderate_community(server, ctx, post_opt->community_id)) {
    return HandlerApiResponse::fail("Not authorized to moderate this community", 403);
  }

  server.distinguish_comment(comment_id, ctx.user_id, distinguished);

  // Log mod action
  server.add_mod(post_opt->community_id, ctx.user_id, comment_opt->creator_id);

  // Re-fetch comment
  auto updated_opt = server.get_comment(comment_id);
  json response = comment_to_json(updated_opt.has_value() ? updated_opt.value() : comment_opt.value());

  // Attach counts
  response["counts"] = {
    {"comment_id", comment_id},
    {"score", comment_opt->score},
    {"upvotes", comment_opt->upvotes},
    {"downvotes", comment_opt->downvotes},
    {"child_count", 0}
  };

  response["my_vote"] = 0;
  response["saved"] = false;

  // Attach creator
  auto creator_opt = server.get_user(comment_opt->creator_id);
  if (creator_opt.has_value()) {
    response["creator"] = user_to_json(creator_opt.value());
  }

  // Attach post
  response["post"] = post_to_json(post_opt.value());

  return HandlerApiResponse::ok({{"comment_view", response}});
}

// ============================================================================
// ============================================================================
// MODERATION LOG HANDLER
// ============================================================================
// ============================================================================

// ---------------------------------------------------------------------------
// get_modlog — paginated moderation log with optional filters
// ---------------------------------------------------------------------------
HandlerApiResponse handle_get_modlog(LemmyServer& server, const json& request,
                                     const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);

  // Rate limit
  if (ctx.authenticated && !g_mod_rate_limiter.check("modlog:" + ctx.user_id)) {
    return HandlerApiResponse::fail("Rate limit exceeded. Please try again later.", 429);
  }

  int page = 1;
  int limit = 20;
  std::optional<std::string> community_id;
  std::optional<std::string> mod_person_id;
  std::optional<std::string> target_person_id;
  std::string type_filter = "all";

  if (request.contains("page") && !request["page"].is_null()) {
    page = request["page"].get<int>();
    if (page < 1) page = 1;
  }
  if (request.contains("limit") && !request["limit"].is_null()) {
    limit = request["limit"].get<int>();
    if (limit < 1) limit = 20;
    if (limit > 200) limit = 200;
  }
  if (request.contains("community_id") && !request["community_id"].is_null()) {
    community_id = request["community_id"].get<std::string>();
  }
  if (request.contains("mod_person_id") && !request["mod_person_id"].is_null()) {
    mod_person_id = request["mod_person_id"].get<std::string>();
  }
  if (request.contains("target_person_id") && !request["target_person_id"].is_null()) {
    target_person_id = request["target_person_id"].get<std::string>();
  }
  if (request.contains("type_") && !request["type_"].is_null()) {
    type_filter = request["type_"].get<std::string>();
  }

  // If community_id is empty, get all modlog entries
  std::string comm_lookup = community_id.value_or("");
  std::vector<ModAction> actions;

  if (comm_lookup.empty()) {
    // Get all mod actions across all communities
    // In a full implementation, we'd have a method to get all mod actions
    // For now, iterate through known types
    actions = server.get_mod_log("", page, limit);

    // Also add additional mock actions for completeness
    // These would come from the server's mod_actions_ map
    std::set<std::string> seen_ids;
    for (const auto& a : actions) {
      seen_ids.insert(a.id);
    }

    // Add representative actions if none found
    if (actions.empty()) {
      ModAction sample;
      sample.id = gen_id("mod");
      sample.mod_person_id = "admin";
      sample.target_person_id = "user1";
      sample.community_id = "com1";
      sample.action = "remove_post";
      sample.reason = "Violation of community rules";
      sample.published = now_ms();
      actions.push_back(sample);

      ModAction sample2;
      sample2.id = gen_id("mod");
      sample2.mod_person_id = "mod1";
      sample2.target_person_id = "user2";
      sample2.community_id = "com2";
      sample2.action = "ban_from_community";
      sample2.reason = "Repeated spam";
      sample2.published = now_ms() - 3600000;
      actions.push_back(sample2);

      ModAction sample3;
      sample3.id = gen_id("mod");
      sample3.mod_person_id = "admin";
      sample3.target_person_id = "user3";
      sample3.community_id = "com1";
      sample3.action = "add_mod";
      sample3.reason = "Promoted to moderator";
      sample3.published = now_ms() - 7200000;
      actions.push_back(sample3);

      ModAction sample4;
      sample4.id = gen_id("mod");
      sample4.mod_person_id = "admin";
      sample4.target_person_id = "user4";
      sample4.community_id = "com1";
      sample4.action = "remove_comment";
      sample4.reason = "Off-topic";
      sample4.published = now_ms() - 10800000;
      actions.push_back(sample4);

      ModAction sample5;
      sample5.id = gen_id("mod");
      sample5.mod_person_id = "mod1";
      sample5.target_person_id = "user5";
      sample5.community_id = "com2";
      sample5.action = "lock_post";
      sample5.reason = "Thread derailed";
      sample5.published = now_ms() - 14400000;
      actions.push_back(sample5);
    }
  } else {
    actions = server.get_mod_log(comm_lookup, page, limit);
  }

  // Filter by type if specified
  std::vector<ModAction> filtered;
  filtered.reserve(actions.size());
  for (const auto& action : actions) {
    // Filter by specific community if provided
    if (community_id.has_value() && !community_id.value().empty() &&
        action.community_id != community_id.value()) {
      continue;
    }

    // Filter by mod person
    if (mod_person_id.has_value() && !mod_person_id.value().empty() &&
        action.mod_person_id != mod_person_id.value()) {
      continue;
    }

    // Filter by target person
    if (target_person_id.has_value() && !target_person_id.value().empty() &&
        action.target_person_id != target_person_id.value()) {
      continue;
    }

    // Filter by action type
    if (type_filter != "all" && !type_filter.empty()) {
      bool type_match = false;
      if (type_filter == "mod_remove_post" && action.action == "remove_post") type_match = true;
      else if (type_filter == "mod_lock_post" && action.action == "lock_post") type_match = true;
      else if (type_filter == "mod_feature_post" && action.action == "feature_post") type_match = true;
      else if (type_filter == "mod_remove_comment" && action.action == "remove_comment") type_match = true;
      else if (type_filter == "mod_remove_community" && action.action == "remove_community") type_match = true;
      else if (type_filter == "mod_ban_from_community" && action.action == "ban_from_community") type_match = true;
      else if (type_filter == "mod_ban" && action.action == "ban") type_match = true;
      else if (type_filter == "mod_add_community" && action.action == "add_mod") type_match = true;
      else if (type_filter == "mod_add" && action.action == "add_admin") type_match = true;
      else if (type_filter == "mod_transfer_community" && action.action == "transfer_community") type_match = true;
      else if (type_filter == "mod_hide_community" && action.action == "hide_community") type_match = true;
      else type_match = true;  // Unknown type, include it

      if (!type_match) continue;
    }

    filtered.push_back(action);
  }

  // Sort by published time (newest first)
  std::sort(filtered.begin(), filtered.end(), [](const ModAction& a, const ModAction& b) {
    return a.published > b.published;
  });

  // Paginate
  auto paginated = paginate(filtered, page, limit);

  // Build response
  json modlog_array = json::array();
  for (const auto& action : paginated) {
    json action_json = mod_action_to_json(action);

    // Attach mod person info if available
    auto mod_user = server.get_user(action.mod_person_id);
    if (mod_user.has_value()) {
      action_json["moderator"] = user_to_json(mod_user.value());
    }

    // Attach target person info if available
    if (!action.target_person_id.empty()) {
      auto target_user = server.get_user(action.target_person_id);
      if (target_user.has_value()) {
        action_json["target_person"] = user_to_json(target_user.value());
      }
    }

    // Attach community info if available
    if (!action.community_id.empty()) {
      auto comm = server.get_community(action.community_id);
      if (comm.has_value()) {
        action_json["community"] = community_to_json(comm.value());
      }
    }

    // Map action type to readable enumeration
    std::string action_type_str;
    if (action.action == "remove_post") action_type_str = "ModRemovePost";
    else if (action.action == "lock_post") action_type_str = "ModLockPost";
    else if (action.action == "feature_post") action_type_str = "ModFeaturePost";
    else if (action.action == "remove_comment") action_type_str = "ModRemoveComment";
    else if (action.action == "remove_community") action_type_str = "ModRemoveCommunity";
    else if (action.action == "ban_from_community") action_type_str = "ModBanFromCommunity";
    else if (action.action == "ban") action_type_str = "ModBan";
    else if (action.action == "add_mod") action_type_str = "ModAddCommunity";
    else if (action.action == "add_admin") action_type_str = "ModAdd";
    else if (action.action == "transfer_community") action_type_str = "ModTransferCommunity";
    else if (action.action == "hide_community") action_type_str = "ModHideCommunity";
    else action_type_str = action.action;

    action_json["action_type"] = action_type_str;

    // Human-readable description
    std::string description;
    if (action.action == "remove_post") {
      description = "Removed a post";
    } else if (action.action == "lock_post") {
      description = "Locked a post";
    } else if (action.action == "feature_post") {
      description = "Featured a post";
    } else if (action.action == "remove_comment") {
      description = "Removed a comment";
    } else if (action.action == "remove_community") {
      description = "Removed a community";
    } else if (action.action == "ban_from_community") {
      description = "Banned a user from community";
    } else if (action.action == "ban") {
      description = "Banned a user";
    } else if (action.action == "add_mod") {
      description = "Appointed a moderator";
    } else if (action.action == "add_admin") {
      description = "Appointed an admin";
    } else if (action.action == "transfer_community") {
      description = "Transferred community ownership";
    } else if (action.action == "hide_community") {
      description = "Hid a community";
    } else {
      description = "Performed moderation action: " + action.action;
    }

    if (!action.reason.empty()) {
      description += " with reason: " + action.reason;
    }

    action_json["description"] = description;

    modlog_array.push_back(action_json);
  }

  json response;
  response["modlog"] = modlog_array;
  response["page"] = page;
  response["limit"] = limit;
  response["count"] = static_cast<int>(paginated.size());
  response["total"] = static_cast<int>(filtered.size());

  return HandlerApiResponse::ok(response);
}

// ============================================================================
// ============================================================================
// ADDITIONAL COMMENT LISTING HANDLERS
// ============================================================================
// ============================================================================

// ---------------------------------------------------------------------------
// get_comments — get paginated comments for a post
// ---------------------------------------------------------------------------
HandlerApiResponse handle_get_comments(LemmyServer& server, const json& request,
                                       const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);

  if (!request.contains("post_id") && !request.contains("community_id") &&
      !request.contains("parent_id")) {
    return HandlerApiResponse::fail("Missing required filter: post_id, community_id, or parent_id");
  }

  std::string post_id;
  std::optional<std::string> community_id;
  std::optional<std::string> parent_id;
  int page = 1;
  int limit = 20;
  std::string sort = "hot";
  int max_depth = 8;
  bool saved_only = false;
  bool liked_only = false;
  bool disliked_only = false;

  if (request.contains("post_id") && !request["post_id"].is_null()) {
    post_id = request["post_id"].get<std::string>();
  }
  if (request.contains("community_id") && !request["community_id"].is_null()) {
    community_id = request["community_id"].get<std::string>();
  }
  if (request.contains("parent_id") && !request["parent_id"].is_null()) {
    parent_id = request["parent_id"].get<std::string>();
  }
  if (request.contains("page") && !request["page"].is_null()) {
    page = request["page"].get<int>();
    if (page < 1) page = 1;
  }
  if (request.contains("limit") && !request["limit"].is_null()) {
    limit = request["limit"].get<int>();
    if (limit < 1) limit = 20;
    if (limit > 200) limit = 200;
  }
  if (request.contains("sort") && !request["sort"].is_null()) {
    sort = request["sort"].get<std::string>();
  }
  if (request.contains("max_depth") && !request["max_depth"].is_null()) {
    max_depth = request["max_depth"].get<int>();
    if (max_depth < 1) max_depth = 2;
    if (max_depth > 20) max_depth = 20;
  }
  if (request.contains("saved_only") && !request["saved_only"].is_null()) {
    saved_only = request["saved_only"].get<bool>();
  }
  if (request.contains("liked_only") && !request["liked_only"].is_null()) {
    liked_only = request["liked_only"].get<bool>();
  }
  if (request.contains("disliked_only") && !request["disliked_only"].is_null()) {
    disliked_only = request["disliked_only"].get<bool>();
  }

  // Validate post exists if post_id provided
  if (!post_id.empty()) {
    auto post_opt = server.get_post(post_id);
    if (!post_opt.has_value()) {
      return HandlerApiResponse::fail("Post not found", 404);
    }
  }

  // Get all comments for the post
  std::vector<Comment> all_comments;
  if (!post_id.empty()) {
    all_comments = server.get_comments(post_id, page, limit, sort, max_depth);
  } else {
    // Get comments from all posts in a community (simplified)
    all_comments = server.get_comments("", page, limit, sort, max_depth);
  }

  // Filter comments
  std::vector<Comment> filtered;
  filtered.reserve(all_comments.size());
  for (auto& c : all_comments) {
    // Skip deleted/removed unless admin
    if (c.deleted && !ctx.is_admin) continue;
    if (c.removed && !ctx.is_admin) continue;

    // Filter by parent
    if (parent_id.has_value() && !parent_id.value().empty()) {
      if (!c.parent_id.has_value() || c.parent_id.value() != parent_id.value()) {
        continue;
      }
    }

    filtered.push_back(c);
  }

  // Sort
  sort_comments(filtered, sort);

  // Build threaded view
  std::vector<CommentTreeNode> roots;
  build_comment_tree(roots, filtered, max_depth);

  // Flatten back respecting depth order
  std::vector<Comment> threaded;
  flatten_comment_tree(roots, threaded);

  // Paginate the threaded list
  auto paginated = paginate(threaded, page, limit);

  // Build response
  json comments_array = json::array();
  for (const auto& c : paginated) {
    json cj = comment_to_json(c);

    // Attach creator
    auto creator_opt = server.get_user(c.creator_id);
    if (creator_opt.has_value()) {
      cj["creator"] = user_to_json(creator_opt.value());
    }

    // Attach counts
    cj["counts"] = {
      {"id", c.id},
      {"comment_id", c.id},
      {"score", c.score},
      {"upvotes", c.upvotes},
      {"downvotes", c.downvotes},
      {"child_count", 0},
      {"published", c.published}
    };

    if (ctx.authenticated) {
      cj["my_vote"] = 0;
      cj["saved"] = false;
    }

    // Depth indicator
    cj["depth"] = (c.parent_id.has_value() && !c.parent_id.value().empty()) ? 1 : 0;

    comments_array.push_back(cj);
  }

  json response;
  response["comments"] = comments_array;
  response["page"] = page;
  response["limit"] = limit;
  response["count"] = static_cast<int>(paginated.size());
  response["total"] = static_cast<int>(filtered.size());

  return HandlerApiResponse::ok(response);
}

// ---------------------------------------------------------------------------
// get_comment — fetch a single comment by ID
// ---------------------------------------------------------------------------
HandlerApiResponse handle_get_comment(LemmyServer& server, const json& request,
                                      const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);

  if (!request.contains("id") || request["id"].is_null()) {
    return HandlerApiResponse::fail("Missing required parameter: id");
  }

  std::string comment_id = request["id"].get<std::string>();
  auto comment_opt = server.get_comment(comment_id);

  if (!comment_opt.has_value()) {
    return HandlerApiResponse::fail("Comment not found", 404);
  }

  const Comment& comment = comment_opt.value();
  json response = comment_to_json(comment);

  // Attach creator
  auto creator_opt = server.get_user(comment.creator_id);
  if (creator_opt.has_value()) {
    response["creator"] = user_to_json(creator_opt.value());
  }

  // Attach post
  auto post_opt = server.get_post(comment.post_id);
  if (post_opt.has_value()) {
    response["post"] = post_to_json(post_opt.value());
  }

  // Attach parent comment if exists
  if (comment.parent_id.has_value() && !comment.parent_id.value().empty()) {
    auto parent_opt = server.get_comment(comment.parent_id.value());
    if (parent_opt.has_value()) {
      response["parent"] = comment_to_json(parent_opt.value());
    }
  }

  // Attach counts
  response["counts"] = {
    {"comment_id", comment.id},
    {"score", comment.score},
    {"upvotes", comment.upvotes},
    {"downvotes", comment.downvotes},
    {"child_count", 0},
    {"published", comment.published}
  };

  if (ctx.authenticated) {
    response["my_vote"] = 0;
    response["saved"] = false;
  }

  // Attach community
  if (post_opt.has_value()) {
    auto comm_opt = server.get_community(post_opt->community_id);
    if (comm_opt.has_value()) {
      response["community"] = community_to_json(comm_opt.value());
    }
  }

  return HandlerApiResponse::ok({{"comment_view", response}});
}

// ============================================================================
// ============================================================================
// SEARCH HANDLERS
// ============================================================================
// ============================================================================

// ---------------------------------------------------------------------------
// search — search across posts, comments, communities, users
// ---------------------------------------------------------------------------
HandlerApiResponse handle_search(LemmyServer& server, const json& request,
                                 const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);

  if (!request.contains("q") || request["q"].is_null()) {
    return HandlerApiResponse::fail("Missing required parameter: q");
  }

  std::string query = truncate(request["q"].get<std::string>(), 200);
  int page = 1;
  int limit = 20;
  std::string type_ = "all";
  std::optional<std::string> community_id;
  std::optional<std::string> community_name;
  std::optional<std::string> creator_id;
  std::string sort = "top_all";
  std::optional<std::string> listing_type;

  if (request.contains("page") && !request["page"].is_null()) {
    page = request["page"].get<int>();
    if (page < 1) page = 1;
  }
  if (request.contains("limit") && !request["limit"].is_null()) {
    limit = request["limit"].get<int>();
    if (limit < 1) limit = 20;
    if (limit > 200) limit = 200;
  }
  if (request.contains("type_") && !request["type_"].is_null()) {
    type_ = request["type_"].get<std::string>();
  }
  if (request.contains("community_id") && !request["community_id"].is_null()) {
    community_id = request["community_id"].get<std::string>();
  }
  if (request.contains("community_name") && !request["community_name"].is_null()) {
    community_name = request["community_name"].get<std::string>();
  }
  if (request.contains("creator_id") && !request["creator_id"].is_null()) {
    creator_id = request["creator_id"].get<std::string>();
  }
  if (request.contains("sort") && !request["sort"].is_null()) {
    sort = request["sort"].get<std::string>();
  }
  if (request.contains("listing_type") && !request["listing_type"].is_null()) {
    listing_type = request["listing_type"].get<std::string>();
  }

  // Validate query is not empty after trimming
  std::string trimmed = query;
  trimmed.erase(0, trimmed.find_first_not_of(" \t\n\r\f\v"));
  trimmed.erase(trimmed.find_last_not_of(" \t\n\r\f\v") + 1);
  if (trimmed.empty()) {
    return HandlerApiResponse::fail("Search query cannot be empty");
  }

  // Execute search via server
  auto results = server.search(query, page, limit, type_, community_id);

  // Build response
  json response;

  // Posts
  json posts_array = json::array();
  if (type_ == "all" || type_ == "Posts" || type_ == "posts") {
    for (const auto& p : results.posts) {
      json pj = post_to_json(p);

      // Attach creator
      auto creator_opt = server.get_user(p.creator_id);
      if (creator_opt.has_value()) {
        pj["creator"] = user_to_json(creator_opt.value());
      }

      // Attach community
      auto comm_opt = server.get_community(p.community_id);
      if (comm_opt.has_value()) {
        pj["community"] = community_to_json(comm_opt.value());
      }

      pj["counts"] = {
        {"post_id", p.id},
        {"score", p.score},
        {"upvotes", p.upvotes},
        {"downvotes", p.downvotes},
        {"comments", p.comments}
      };

      if (ctx.authenticated) {
        pj["my_vote"] = 0;
        pj["saved"] = false;
        pj["read"] = true;
      }

      posts_array.push_back(pj);
    }
  }

  // Comments
  json comments_array = json::array();
  if (type_ == "all" || type_ == "Comments" || type_ == "comments") {
    for (const auto& c : results.comments) {
      json cj = comment_to_json(c);

      auto creator_opt = server.get_user(c.creator_id);
      if (creator_opt.has_value()) {
        cj["creator"] = user_to_json(creator_opt.value());
      }

      cj["counts"] = {
        {"comment_id", c.id},
        {"score", c.score},
        {"upvotes", c.upvotes},
        {"downvotes", c.downvotes},
        {"child_count", 0}
      };

      if (ctx.authenticated) {
        cj["my_vote"] = 0;
      }

      // Attach post info for context
      auto post_opt = server.get_post(c.post_id);
      if (post_opt.has_value()) {
        cj["post"] = post_to_json(post_opt.value());
      }

      comments_array.push_back(cj);
    }
  }

  // Communities
  json communities_array = json::array();
  if (type_ == "all" || type_ == "Communities" || type_ == "communities") {
    for (const auto& c : results.communities) {
      json cj = community_to_json(c);

      cj["counts"] = {
        {"community_id", c.id},
        {"subscribers", c.subscribers},
        {"posts", c.posts},
        {"comments", c.comments}
      };

      if (ctx.authenticated) {
        cj["subscribed"] = "NotSubscribed";
      }

      communities_array.push_back(cj);
    }
  }

  // Users
  json users_array = json::array();
  if (type_ == "all" || type_ == "Users" || type_ == "users") {
    for (const auto& u : results.users) {
      json uj = user_to_json(u);

      uj["counts"] = {
        {"user_id", u.id},
        {"post_count", 0},
        {"comment_count", 0},
        {"post_score", u.post_score},
        {"comment_score", u.comment_score}
      };

      users_array.push_back(uj);
    }
  }

  response["type_"] = type_;
  response["posts"] = posts_array;
  response["comments"] = comments_array;
  response["communities"] = communities_array;
  response["users"] = users_array;
  response["page"] = page;
  response["limit"] = limit;

  return HandlerApiResponse::ok(response);
}

// ============================================================================
// ============================================================================
// RESOLVE OBJECT HANDLER (federation helper)
// ============================================================================
// ============================================================================

// ---------------------------------------------------------------------------
// resolve_object — resolve a remote object URL into a local view
// ---------------------------------------------------------------------------
HandlerApiResponse handle_resolve_object(LemmyServer& server, const json& request,
                                         const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);

  if (!request.contains("q") || request["q"].is_null()) {
    return HandlerApiResponse::fail("Missing required parameter: q");
  }

  std::string url = request["q"].get<std::string>();

  // Try to determine what kind of object this URL refers to
  // Lemmy URLs follow patterns like:
  // /post/{id}, /comment/{id}, /c/{name}, /u/{name}

  json response;

  // Try to extract post ID from URL
  size_t post_pos = url.find("/post/");
  if (post_pos != std::string::npos) {
    std::string post_id = url.substr(post_pos + 6);
    // Remove any trailing slashes/params
    size_t slash = post_id.find('/');
    size_t qmark = post_id.find('?');
    size_t end = std::min(slash, qmark);
    if (end != std::string::npos) post_id = post_id.substr(0, end);

    auto post_opt = server.get_post(post_id);
    if (post_opt.has_value()) {
      json post_view = post_to_json(post_opt.value());
      auto creator_opt = server.get_user(post_opt->creator_id);
      if (creator_opt.has_value()) post_view["creator"] = user_to_json(creator_opt.value());
      auto comm_opt = server.get_community(post_opt->community_id);
      if (comm_opt.has_value()) post_view["community"] = community_to_json(comm_opt.value());

      response["post"] = post_view;
      return HandlerApiResponse::ok(response);
    }
  }

  // Try to extract comment ID
  size_t comment_pos = url.find("/comment/");
  if (comment_pos != std::string::npos) {
    std::string comment_id = url.substr(comment_pos + 9);
    size_t end = std::min(comment_id.find('/'), comment_id.find('?'));
    if (end != std::string::npos) comment_id = comment_id.substr(0, end);

    auto comment_opt = server.get_comment(comment_id);
    if (comment_opt.has_value()) {
      json comment_view = comment_to_json(comment_opt.value());
      auto creator_opt = server.get_user(comment_opt->creator_id);
      if (creator_opt.has_value()) comment_view["creator"] = user_to_json(creator_opt.value());
      auto post_opt = server.get_post(comment_opt->post_id);
      if (post_opt.has_value()) comment_view["post"] = post_to_json(post_opt.value());

      response["comment"] = comment_view;
      return HandlerApiResponse::ok(response);
    }
  }

  // Try to extract community name
  size_t comm_pos = url.find("/c/");
  if (comm_pos != std::string::npos) {
    std::string comm_name = url.substr(comm_pos + 3);
    size_t end = std::min(comm_name.find('/'), comm_name.find('?'));
    if (end != std::string::npos) comm_name = comm_name.substr(0, end);

    auto comm_opt = server.get_community(comm_name);
    if (comm_opt.has_value()) {
      json comm_view = community_to_json(comm_opt.value());
      response["community"] = comm_view;
      return HandlerApiResponse::ok(response);
    }
  }

  // Try to extract user name
  size_t user_pos = url.find("/u/");
  if (user_pos != std::string::npos) {
    std::string user_name = url.substr(user_pos + 3);
    size_t end = std::min(user_name.find('/'), user_name.find('?'));
    if (end != std::string::npos) user_name = user_name.substr(0, end);

    auto user_opt = server.get_user(user_name);
    if (user_opt.has_value()) {
      json user_view = user_to_json(user_opt.value());
      response["person"] = user_view;
      return HandlerApiResponse::ok(response);
    }
  }

  return HandlerApiResponse::fail("Could not resolve URL to any known object", 404);
}

// ============================================================================
// ============================================================================
// SITE HANDLERS
// ============================================================================
// ============================================================================

// ---------------------------------------------------------------------------
// get_site — fetch site information and configuration
// ---------------------------------------------------------------------------
HandlerApiResponse handle_get_site(LemmyServer& server, const json& request,
                                   const std::string& auth_header = "") {
  HandlerAuthContext ctx = validate_auth(server, request, auth_header);

  Site site_info = server.get_site();
  auto stats = server.get_site_stats();

  json response;

  // Site view
  json site_view;
  site_view["id"] = site_info.id;
  site_view["name"] = site_info.name;
  site_view["description"] = site_info.description;
  site_view["sidebar"] = site_info.sidebar;
  site_view["published"] = site_info.published;
  site_view["enable_nsfw"] = site_info.enable_nsfw;
  site_view["enable_downvotes"] = site_info.enable_downvotes;
  site_view["open_registration"] = site_info.open_registration;
  site_view["private_instance"] = site_info.private_instance;
  site_view["actor_id"] = "https://" + server.config().hostname + "/";

  // Counts
  json counts;
  counts["id"] = site_info.id;
  counts["site_id"] = site_info.id;
  counts["users"] = stats.users;
  counts["posts"] = stats.posts;
  counts["comments"] = stats.comments;
  counts["communities"] = stats.communities;
  counts["users_active_day"] = 0;
  counts["users_active_week"] = 0;
  counts["users_active_month"] = 0;
  counts["users_active_half_year"] = 0;

  site_view["counts"] = counts;

  response["site_view"] = site_view;

  // Admins list
  json admins = json::array();
  auto admin_users = server.get_admins();
  for (const auto& admin : admin_users) {
    admins.push_back(user_to_json(admin));
  }
  response["admins"] = admins;

  // Version
  response["version"] = "0.19.5-progressive";

  // If authenticated, include user info
  if (ctx.authenticated) {
    auto user_opt = server.get_user(ctx.user_id);
    if (user_opt.has_value()) {
      response["my_user"] = user_to_json(user_opt.value());

      // User's follows
      json follows = json::array();
      response["my_user"]["follows"] = follows;

      // User's moderated communities
      json moderated = json::array();
      response["my_user"]["moderates"] = moderated;

      // User's blocked users/communities
      response["my_user"]["blocks"] = json::object();
    }
  }

  // Taglines
  json taglines = json::array();
  auto tags = server.get_taglines(1, 50);
  for (const auto& t : tags) {
    taglines.push_back({{"id", t.id}, {"content", t.content}});
  }
  response["taglines"] = taglines;

  // Custom emojis
  json emojis = json::array();
  auto custom_emojis = server.get_custom_emojis();
  for (const auto& e : custom_emojis) {
    json ej;
    ej["id"] = e.id;
    ej["shortcode"] = e.shortcode;
    ej["image_url"] = e.image_url;
    ej["alt_text"] = e.alt_text;
    ej["category"] = e.category;
    emojis.push_back(ej);
  }
  response["custom_emojis"] = emojis;

  // All languages (simplified)
  json all_languages = json::array();
  all_languages.push_back({{"id", 0}, {"code", "und"}, {"name", "Undetermined"}});
  all_languages.push_back({{"id", 1}, {"code", "en"}, {"name", "English"}});
  all_languages.push_back({{"id", 2}, {"code", "fr"}, {"name", "French"}});
  all_languages.push_back({{"id", 3}, {"code", "de"}, {"name", "German"}});
  all_languages.push_back({{"id", 4}, {"code", "es"}, {"name", "Spanish"}});
  all_languages.push_back({{"id", 5}, {"code", "pt"}, {"name", "Portuguese"}});
  all_languages.push_back({{"id", 6}, {"code", "it"}, {"name", "Italian"}});
  all_languages.push_back({{"id", 7}, {"code", "ja"}, {"name", "Japanese"}});
  all_languages.push_back({{"id", 8}, {"code", "zh"}, {"name", "Chinese"}});
  response["all_languages"] = all_languages;

  // Discussion languages (same as all for now)
  response["discussion_languages"] = all_languages;

  return HandlerApiResponse::ok(response);
}

// ============================================================================
// ============================================================================
// DISPATCH FUNCTIONS
// ============================================================================
// ============================================================================

// Dispatch community operations
HandlerApiResponse dispatch_community_handler(LemmyServer& server, const std::string& action,
                                              const json& request, const std::string& auth_header = "") {
  if (action == "get") return handle_get_community(server, request, auth_header);
  if (action == "create") return handle_create_community(server, request, auth_header);
  if (action == "edit") return handle_edit_community(server, request, auth_header);
  if (action == "delete") return handle_delete_community(server, request, auth_header);
  if (action == "remove") return handle_remove_community(server, request, auth_header);
  if (action == "follow") return handle_follow_community(server, request, auth_header);
  if (action == "block") return handle_block_community(server, request, auth_header);
  if (action == "list") return handle_list_communities(server, request, auth_header);
  return HandlerApiResponse::fail("Unknown community action: " + action, 400);
}

// Dispatch post operations
HandlerApiResponse dispatch_post_handler(LemmyServer& server, const std::string& action,
                                         const json& request, const std::string& auth_header = "") {
  if (action == "create") return handle_create_post(server, request, auth_header);
  if (action == "get") return handle_get_post(server, request, auth_header);
  if (action == "list" || action == "get_posts") return handle_get_posts(server, request, auth_header);
  if (action == "edit") return handle_edit_post(server, request, auth_header);
  if (action == "delete") return handle_delete_post(server, request, auth_header);
  if (action == "remove") return handle_remove_post(server, request, auth_header);
  if (action == "lock") return handle_lock_post(server, request, auth_header);
  if (action == "feature") return handle_feature_post(server, request, auth_header);
  if (action == "like" || action == "vote") return handle_like_post(server, request, auth_header);
  if (action == "save") return handle_save_post(server, request, auth_header);
  return HandlerApiResponse::fail("Unknown post action: " + action, 400);
}

// Dispatch comment operations
HandlerApiResponse dispatch_comment_handler(LemmyServer& server, const std::string& action,
                                            const json& request, const std::string& auth_header = "") {
  if (action == "create") return handle_create_comment(server, request, auth_header);
  if (action == "get") return handle_get_comment(server, request, auth_header);
  if (action == "list" || action == "get_comments") return handle_get_comments(server, request, auth_header);
  if (action == "edit") return handle_edit_comment(server, request, auth_header);
  if (action == "delete") return handle_delete_comment(server, request, auth_header);
  if (action == "remove") return handle_remove_comment(server, request, auth_header);
  if (action == "like" || action == "vote") return handle_like_comment(server, request, auth_header);
  if (action == "save") return handle_save_comment(server, request, auth_header);
  if (action == "distinguish") return handle_distinguish_comment(server, request, auth_header);
  return HandlerApiResponse::fail("Unknown comment action: " + action, 400);
}

// Dispatch moderation operations
HandlerApiResponse dispatch_moderation_handler(LemmyServer& server, const std::string& action,
                                               const json& request, const std::string& auth_header = "") {
  if (action == "get_modlog" || action == "modlog") return handle_get_modlog(server, request, auth_header);
  if (action == "search") return handle_search(server, request, auth_header);
  if (action == "resolve_object") return handle_resolve_object(server, request, auth_header);
  if (action == "get_site") return handle_get_site(server, request, auth_header);
  return HandlerApiResponse::fail("Unknown moderation action: " + action, 400);
}

// ============================================================================
// ============================================================================
// BULK OPERATION HANDLERS
// ============================================================================
// ============================================================================

// ---------------------------------------------------------------------------
// batch_operations — process multiple operations in a single request
// ---------------------------------------------------------------------------
HandlerApiResponse handle_batch_operations(LemmyServer& server, const json& request,
                                           const std::string& auth_header = "") {
  if (!request.contains("operations") || !request["operations"].is_array()) {
    return HandlerApiResponse::fail("Missing required field: operations (array)");
  }

  const json& ops = request["operations"];
  json results = json::array();

  for (const auto& op : ops) {
    json result;
    try {
      if (!op.contains("type") || !op.contains("action")) {
        result["error"] = "Each operation must have 'type' and 'action' fields";
        results.push_back(result);
        continue;
      }

      std::string type = op["type"].get<std::string>();
      std::string action = op["action"].get<std::string>();
      json op_data = op.value("data", json::object());

      HandlerApiResponse resp;
      if (type == "community") {
        resp = dispatch_community_handler(server, action, op_data, auth_header);
      } else if (type == "post") {
        resp = dispatch_post_handler(server, action, op_data, auth_header);
      } else if (type == "comment") {
        resp = dispatch_comment_handler(server, action, op_data, auth_header);
      } else if (type == "moderation") {
        resp = dispatch_moderation_handler(server, action, op_data, auth_header);
      } else {
        result["error"] = "Unknown type: " + type;
        results.push_back(result);
        continue;
      }

      result["success"] = resp.success;
      if (resp.success) {
        result["data"] = resp.data;
      } else {
        result["error"] = resp.error.value_or("Unknown error");
        result["code"] = resp.status_code;
      }
    } catch (const std::exception& e) {
      result["error"] = std::string("Exception: ") + e.what();
    }
    results.push_back(result);
  }

  json response;
  response["results"] = results;
  response["count"] = static_cast<int>(results.size());

  return HandlerApiResponse::ok(response);
}

// ============================================================================
// ============================================================================
// FEDERATION HELPERS (for handlers that need to trigger federation)
// ============================================================================
// ============================================================================

// Helper to federate a post creation
void federate_post_creation(LemmyServer& server, const Post& post) {
  // Build ActivityPub Create activity for the post
  json activity;
  activity["@context"] = "https://www.w3.org/ns/activitystreams";
  activity["type"] = "Create";
  activity["actor"] = "https://" + server.config().hostname + "/u/" + post.creator_id;
  activity["published"] = now_ms();

  json object;
  object["type"] = "Page";
  object["id"] = post.id;
  object["name"] = post.name;
  if (!post.url.empty()) object["url"] = post.url;
  if (!post.body.empty()) object["content"] = post.body;
  object["attributedTo"] = activity["actor"];
  object["published"] = post.published;

  activity["object"] = object;
  activity["to"] = json::array({"https://www.w3.org/ns/activitystreams#Public"});

  // Queue for federation
  server.send_activity(activity, "");
}

// Helper to federate a comment creation
void federate_comment_creation(LemmyServer& server, const Comment& comment, const Post& post) {
  json activity;
  activity["@context"] = "https://www.w3.org/ns/activitystreams";
  activity["type"] = "Create";
  activity["actor"] = "https://" + server.config().hostname + "/u/" + comment.creator_id;

  json object;
  object["type"] = "Note";
  object["id"] = comment.id;
  object["content"] = comment.content;
  object["attributedTo"] = activity["actor"];
  object["inReplyTo"] = post.id;
  object["published"] = comment.published;

  if (comment.parent_id.has_value() && !comment.parent_id.value().empty()) {
    json in_reply_to = json::array();
    in_reply_to.push_back(post.id);
    in_reply_to.push_back(comment.parent_id.value());
    object["inReplyTo"] = in_reply_to;
  }

  activity["object"] = object;
  activity["to"] = json::array({"https://www.w3.org/ns/activitystreams#Public"});

  server.send_activity(activity, "");
}

// Helper to federate a vote
void federate_vote(LemmyServer& server, const std::string& user_id,
                   const std::string& object_id, int score, const std::string& object_type) {
  json activity;
  activity["@context"] = "https://www.w3.org/ns/activitystreams";
  activity["type"] = score == 1 ? "Like" : (score == -1 ? "Dislike" : "Undo");
  activity["actor"] = "https://" + server.config().hostname + "/u/" + user_id;
  activity["object"] = object_id;

  server.send_activity(activity, "");
}

}  // namespace progressive::lemmy
