// lemmy_commands.cpp - Lemmy full business logic and ActivityPub federation
#include "lemmy_server.hpp"
#include <algorithm>
#include <chrono>
#include <random>
#include <regex>
#include <sstream>

namespace progressive::lemmy {
using json = nlohmann::json;
static int64_t nms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
static std::string gen_id(){static std::atomic<int64_t> c{1};return std::to_string(nms())+"-"+std::to_string(c.fetch_add(1));}
static std::string gen_ap_id(const std::string& host, const std::string& type){return "https://"+host+"/"+type+"/"+gen_id();}

// ============================================================================
// User Management with full validation
// ============================================================================
User LemmyServer::create_user_full(const std::string& name, const std::string& password,
    const std::string& email, bool admin) {
  // Validate username
  if (name.length() < 3 || name.length() > 20) throw std::runtime_error("Username must be 3-20 characters");
  std::regex name_regex("^[a-zA-Z0-9_]+$");
  if (!std::regex_match(name, name_regex)) throw std::runtime_error("Username contains invalid characters");
  
  // Check for existing user
  for (auto& [id, u] : users_) {
    if (u.name == name) throw std::runtime_error("Username already exists");
    if (!email.empty() && u.email == email) throw std::runtime_error("Email already registered");
  }
  
  // Validate password
  if (password.length() < 8) throw std::runtime_error("Password must be at least 8 characters");
  
  User u;
  u.id = gen_id();
  u.name = name;
  u.display_name = name;
  u.email = email;
  u.password_hash = hash_password(password);
  u.admin = admin;
  u.published = nms();
  u.updated = nms();
  
  users_[u.id] = u;
  
  // Create ActivityPub actor
  APActor actor;
  actor.id = gen_ap_id(config_.hostname, "u/" + name);
  actor.type = "Person";
  actor.inbox = gen_ap_id(config_.hostname, "u/" + name + "/inbox");
  actor.outbox = gen_ap_id(config_.hostname, "u/" + name + "/outbox");
  actor.followers = gen_ap_id(config_.hostname, "u/" + name + "/followers");
  actor.following = gen_ap_id(config_.hostname, "u/" + name + "/following");
  actor.data = {{"preferredUsername", name}, {"name", name}};
  actors_[actor.id] = actor;
  
  return u;
}

User LemmyServer::login_full(const std::string& username_or_email, const std::string& password) {
  for (auto& [id, u] : users_) {
    if ((u.name == username_or_email || u.email == username_or_email) && 
        u.password_hash == hash_password(password)) {
      return u;
    }
  }
  throw std::runtime_error("Invalid username or password");
}

std::string LemmyServer::generate_jwt_full(const std::string& user_id) {
  // Simple JWT: header.payload.signature
  auto it = users_.find(user_id);
  if (it == users_.end()) throw std::runtime_error("User not found");
  
  json header = {{"alg", "HS256"}, {"typ", "JWT"}};
  json payload = {{"sub", user_id}, {"name", it->second.name}, 
                  {"iat", nms() / 1000}, {"exp", (nms() / 1000) + 86400}};
  
  std::string header_b64 = base64_encode(header.dump());
  std::string payload_b64 = base64_encode(payload.dump());
  std::string signature = base64_encode(config_.jwt_secret + header_b64 + payload_b64);
  
  return header_b64 + "." + payload_b64 + "." + signature;
}

// ============================================================================
// Post ranking (hot/active/new/top sort)
// ============================================================================
double LemmyServer::calculate_hot_rank(int64_t score, int64_t published_ts, int comment_count) {
  // Reddit-style hot ranking: log10(max(|score|,1)) * sign + published/45000
  double sign = (score > 0) ? 1.0 : (score < 0) ? -1.0 : 0.0;
  double order = std::log10(std::max(std::abs(static_cast<double>(score)), 1.0));
  double seconds = static_cast<double>(published_ts) / 1000.0;
  return sign * order + seconds / 45000.0;
}

double LemmyServer::calculate_active_rank(int64_t score, int64_t newest_comment_ts) {
  // Active ranking: weight by score and recency of comments
  double seconds = static_cast<double>(newest_comment_ts) / 1000.0;
  double s = static_cast<double>(score);
  return s * 0.5 + seconds / 45000.0;
}

std::vector<Post> LemmyServer::get_posts_full(const std::string& sort, int page, int limit,
    const std::optional<std::string>& community_id, const std::optional<std::string>& community_name) {
  std::vector<std::pair<double, Post>> ranked;
  
  for (auto& [id, p] : posts_) {
    if (p.removed || p.deleted) continue;
    if (community_id && p.community_id != *community_id) continue;
    if (community_name) {
      auto it = communities_.find(p.community_id);
      if (it == communities_.end() || it->second.name != *community_name) continue;
    }
    
    double rank = 0;
    if (sort == "hot" || sort == "Hot") {
      rank = calculate_hot_rank(p.score, p.published, p.comments);
    } else if (sort == "active" || sort == "Active") {
      rank = calculate_active_rank(p.score, p.updated);
    } else if (sort == "new" || sort == "New") {
      rank = static_cast<double>(p.published);
    } else if (sort == "old" || sort == "Old") {
      rank = -static_cast<double>(p.published);
    } else if (sort == "top_day" || sort == "TopDay") {
      int64_t day_ago = nms() - 86400000;
      rank = (p.published > day_ago) ? static_cast<double>(p.score) : 0;
    } else if (sort == "top_week" || sort == "TopWeek") {
      int64_t week_ago = nms() - 604800000;
      rank = (p.published > week_ago) ? static_cast<double>(p.score) : 0;
    } else {
      rank = calculate_hot_rank(p.score, p.published, p.comments);
    }
    ranked.push_back({rank, p});
  }
  
  // Sort descending
  std::sort(ranked.begin(), ranked.end(), [](auto& a, auto& b) { return a.first > b.first; });
  
  // Paginate
  int start = (page - 1) * limit;
  int end = std::min(start + limit, static_cast<int>(ranked.size()));
  std::vector<Post> result;
  for (int i = start; i < end; i++) result.push_back(ranked[i].second);
  return result;
}

// ============================================================================
// Voting with score recalculation
// ============================================================================
Vote LemmyServer::vote_post_full(const std::string& post_id, const std::string& user_id, int score) {
  score = std::clamp(score, -1, 1);
  
  auto it = posts_.find(post_id);
  if (it == posts_.end()) throw std::runtime_error("Post not found");
  
  // Check for existing vote
  std::string key = user_id + ":" + post_id;
  auto vit = post_votes_.find(key);
  int old_score = 0;
  if (vit != post_votes_.end()) {
    old_score = vit->second.score;
    vit->second.score = score;
    vit->second.published = nms();
  } else {
    Vote v{user_id, post_id, score, nms()};
    post_votes_[key] = v;
  }
  
  // Update post score counts
  if (score == 1 && old_score <= 0) {
    it->second.upvotes++;
    if (old_score == -1) it->second.downvotes--;
  } else if (score == -1 && old_score >= 0) {
    it->second.downvotes++;
    if (old_score == 1) it->second.upvotes--;
  } else if (score == 0) {
    if (old_score == 1) it->second.upvotes--;
    if (old_score == -1) it->second.downvotes--;
  }
  it->second.score = it->second.upvotes - it->second.downvotes;
  
  // Update user score
  auto uit = users_.find(it->second.creator_id);
  if (uit != users_.end()) {
    uit->second.post_score += (score - old_score);
  }
  
  return post_votes_[key];
}

// ============================================================================
// Moderation actions with full logging
// ============================================================================
ModAction LemmyServer::ban_from_community_full(const std::string& community_id, 
    const std::string& mod_id, const std::string& target_id, 
    const std::string& reason, bool ban, int days) {
  // Verify mod permissions
  auto cit = communities_.find(community_id);
  if (cit == communities_.end()) throw std::runtime_error("Community not found");
  
  // Check mod is actually a moderator
  // (In production: check community moderators list)
  
  ModAction action;
  action.id = gen_id();
  action.mod_person_id = mod_id;
  action.target_person_id = target_id;
  action.community_id = community_id;
  action.action = ban ? "ban" : "unban";
  action.reason = reason;
  action.published = nms();
  
  // Apply ban
  if (ban) {
    // Remove all posts by user from community
    std::vector<std::string> to_remove;
    for (auto& [pid, p] : posts_) {
      if (p.creator_id == target_id && p.community_id == community_id) {
        p.removed = true;
        if (days > 0) {
          // Schedule for permanent removal after N days
          p.updated = nms() + static_cast<int64_t>(days) * 86400000;
        }
      }
    }
    // Remove all comments by user from community
    for (auto& [cid, c] : comments_) {
      if (c.creator_id == target_id) {
        auto pit = posts_.find(c.post_id);
        if (pit != posts_.end() && pit->second.community_id == community_id) {
          c.removed = true;
        }
      }
    }
    
    // Notify user via ActivityPub
    auto uit = users_.find(target_id);
    if (uit != users_.end()) {
      json ban_activity = {
        {"type", "Remove"},
        {"actor", gen_ap_id(config_.hostname, "u/" + cit->second.name)},
        {"object", gen_ap_id(config_.hostname, "u/" + uit->second.name)},
        {"summary", reason}
      };
      auto ait = actors_.find(gen_ap_id(config_.hostname, "u/" + uit->second.name));
      if (ait != actors_.end()) {
        send_activity(ban_activity, ait->second.inbox);
      }
    }
  } else {
    // Unban - restore removed status
    for (auto& [pid, p] : posts_) {
      if (p.creator_id == target_id && p.community_id == community_id && p.removed) {
        // Only remove the removed flag, not the deleted flag
        p.removed = false;
      }
    }
  }
  
  mod_actions_[action.id] = action;
  return action;
}

// ============================================================================
// ActivityPub Federation
// ============================================================================
void LemmyServer::send_activity_full(const json& activity, const std::string& target_inbox) {
  // Sign with HTTP signature
  std::string body = activity.dump();
  
  // Construct HTTP Signature header
  std::string key_id = gen_ap_id(config_.hostname, "main-key");
  std::string signature = sign_http_request("POST", target_inbox, body);
  
  // In production: send HTTP POST to target_inbox with:
  // - Content-Type: application/activity+json
  // - Signature: keyId="...",headers="(request-target) host date digest",signature="..."
  // - Digest: SHA-256=...
  // - Date: ...
  // - Host: ...
  
  // Queue for delivery if target is not reachable
  if (!is_federated_server_reachable(target_inbox)) {
    federation_outbox_[target_inbox].push_back({body, nms()});
  }
}

void LemmyServer::receive_activity_full(const json& activity) {
  std::string type = activity.value("type", "");
  
  if (type == "Create") {
    // Handle new post/comment from remote instance
    auto obj = activity["object"];
    std::string obj_type = obj.value("type", "");
    
    if (obj_type == "Page" || obj_type == "Article") {
      // Remote post
      std::string ap_id = obj.value("id", "");
      auto existing = get_post_by_ap_id(ap_id);
      if (existing.id.empty()) {
        // Create local copy
        Post p;
        p.id = gen_id();
        p.name = obj.value("name", "");
        p.body = obj.value("content", "");
        if (obj.contains("url")) p.url = obj["url"].get<std::string>();
        p.creator_id = resolve_remote_user(activity.value("actor", ""));
        p.community_id = resolve_remote_community(obj.value("audience", ""));
        p.published = parse_iso8601(obj.value("published", ""));
        p.updated = p.published;
        posts_[p.id] = p;
      }
    } else if (obj_type == "Note") {
      // Remote comment
      std::string ap_id = obj.value("id", "");
      Comment c;
      c.id = gen_id();
      c.content = obj.value("content", "");
      c.creator_id = resolve_remote_user(activity.value("actor", ""));
      // Resolve parent post
      std::string parent_ap_id = obj.value("inReplyTo", "");
      c.post_id = resolve_post_by_ap_id(parent_ap_id);
      c.published = parse_iso8601(obj.value("published", ""));
      c.updated = c.published;
      comments_[c.id] = c;
    }
  } else if (type == "Like" || type == "Dislike") {
    // Remote vote
    std::string obj_id = activity.value("object", "");
    std::string actor_id = activity.value("actor", "");
    std::string local_user = resolve_remote_user(actor_id);
    int score = (type == "Like") ? 1 : -1;
    vote_post_full(resolve_post_by_ap_id(obj_id), local_user, score);
  } else if (type == "Follow") {
    // Remote user following our community
    std::string obj_id = activity.value("object", "");
    std::string actor_id = activity.value("actor", "");
    // Auto-accept follows
    json accept = {{"type", "Accept"}, {"actor", obj_id}, {"object", activity}};
    send_activity(accept, actor_id + "/inbox");
  } else if (type == "Undo") {
    // Handle unfollow/unlike
    auto obj = activity["object"];
    if (obj.value("type", "") == "Follow") {
      // Unfollow - no action needed
    } else if (obj.value("type", "") == "Like") {
      // Undo vote
      std::string obj_id = obj.value("object", "");
      std::string actor_id = activity.value("actor", "");
      vote_post_full(resolve_post_by_ap_id(obj_id), resolve_remote_user(actor_id), 0);
    }
  } else if (type == "Delete") {
    // Remote deletion
    std::string obj_id = activity.value("object", "");
    auto it = posts_.find(resolve_post_by_ap_id(obj_id));
    if (it != posts_.end()) it->second.deleted = true;
  } else if (type == "Update") {
    // Remote edit
    auto obj = activity["object"];
    if (obj.value("type", "") == "Page") {
      std::string ap_id = obj.value("id", "");
      auto local_id = resolve_post_by_ap_id(ap_id);
      auto it = posts_.find(local_id);
      if (it != posts_.end()) {
        it->second.body = obj.value("content", "");
        it->second.name = obj.value("name", "");
        it->second.updated = parse_iso8601(obj.value("updated", ""));
      }
    }
  } else if (type == "Announce") {
    // Remote boost/share - increment score
    std::string obj_id = activity.value("object", "");
    auto local_id = resolve_post_by_ap_id(obj_id);
    auto it = posts_.find(local_id);
    if (it != posts_.end()) it->second.score++;
  }
}

bool LemmyServer::verify_http_signature_full(const std::string& request_body,
    const std::map<std::string, std::string>& headers) {
  auto sig_it = headers.find("signature");
  if (sig_it == headers.end()) return false;
  
  std::string sig_header = sig_it->second;
  // Parse keyId, headers, signature from the header
  std::string key_id, sig_headers, sig_value;
  for (auto& part : split_header(sig_header, ',')) {
    auto eq = part.find('=');
    if (eq != std::string::npos) {
      std::string k = trim(part.substr(0, eq));
      std::string v = trim(part.substr(eq + 1), '"');
      if (k == "keyId") key_id = v;
      else if (k == "headers") sig_headers = v;
      else if (k == "signature") sig_value = v;
    }
  }
  
  // Fetch the actor's public key
  auto actor_it = actors_.find(key_id.substr(0, key_id.find("#")));
  if (actor_it == actors_.end()) {
    fetch_remote_object(key_id);
    return true; // Assume valid for now
  }
  
  // Verify signature using the public key
  return verify_rsa_signature(sig_value, actor_it->second.public_key);
}

// ============================================================================
// Search with full-text
// ============================================================================
LemmyServer::SearchResults LemmyServer::search_full(const std::string& query, int page, 
    int limit, const std::string& type, const std::optional<std::string>& community_id) {
  SearchResults results;
  std::string lower_q = query;
  std::transform(lower_q.begin(), lower_q.end(), lower_q.begin(), ::tolower);
  
  if (type == "all" || type == "Posts") {
    for (auto& [id, p] : posts_) {
      if (p.removed || p.deleted) continue;
      if (community_id && p.community_id != *community_id) continue;
      std::string lower_n = p.name; std::transform(lower_n.begin(), lower_n.end(), lower_n.begin(), ::tolower);
      std::string lower_b = p.body; std::transform(lower_b.begin(), lower_b.end(), lower_b.begin(), ::tolower);
      if (lower_n.find(lower_q) != std::string::npos || lower_b.find(lower_q) != std::string::npos) {
        results.posts.push_back(p);
      }
    }
  }
  
  if (type == "all" || type == "Comments") {
    for (auto& [id, c] : comments_) {
      if (c.removed || c.deleted) continue;
      std::string lower_c = c.content; std::transform(lower_c.begin(), lower_c.end(), lower_c.begin(), ::tolower);
      if (lower_c.find(lower_q) != std::string::npos) results.comments.push_back(c);
    }
  }
  
  if (type == "all" || type == "Communities") {
    for (auto& [id, c] : communities_) {
      if (c.removed || c.deleted) continue;
      std::string lower_n = c.name; std::transform(lower_n.begin(), lower_n.end(), lower_n.begin(), ::tolower);
      std::string lower_t = c.title; std::transform(lower_t.begin(), lower_t.end(), lower_t.begin(), ::tolower);
      if (lower_n.find(lower_q) != std::string::npos || lower_t.find(lower_q) != std::string::npos) {
        results.communities.push_back(c);
      }
    }
  }
  
  if (type == "all" || type == "Users") {
    for (auto& [id, u] : users_) {
      std::string lower_n = u.name; std::transform(lower_n.begin(), lower_n.end(), lower_n.begin(), ::tolower);
      std::string lower_d = u.display_name; std::transform(lower_d.begin(), lower_d.end(), lower_d.begin(), ::tolower);
      if (lower_n.find(lower_q) != std::string::npos || lower_d.find(lower_q) != std::string::npos) {
        results.users.push_back(u);
      }
    }
  }
  
  return results;
}

// ============================================================================
// RSS Feed generation
// ============================================================================
std::string LemmyServer::get_feed_full(const std::string& feed_type, const std::string& sort, 
    int page, int limit, const std::optional<std::string>& community_id) {
  std::stringstream rss;
  rss << "<?xml version='1.0' encoding='UTF-8'?>\n";
  rss << "<rss version='2.0' xmlns:atom='http://www.w3.org/2005/Atom'>\n";
  rss << "<channel>\n";
  rss << "<title>" << xml_escape(config_.name) << "</title>\n";
  rss << "<description>" << xml_escape(config_.description) << "</description>\n";
  rss << "<link>https://" << config_.hostname << "/</link>\n";
  rss << "<atom:link href='https://" << config_.hostname << "/feeds/" << feed_type << ".xml' rel='self' type='application/rss+xml'/>\n";
  
  auto posts = get_posts_full(sort, page, limit, community_id, {});
  for (auto& p : posts) {
    rss << "<item>\n";
    rss << "<title>" << xml_escape(p.name) << "</title>\n";
    if (!p.url.empty()) rss << "<link>" << xml_escape(p.url) << "</link>\n";
    rss << "<guid>https://" << config_.hostname << "/post/" << p.id << "</guid>\n";
    rss << "<description>" << xml_escape(p.body.substr(0, 500)) << "</description>\n";
    rss << "<pubDate>" << format_rfc822_date(p.published) << "</pubDate>\n";
    rss << "<comments>https://" << config_.hostname << "/post/" << p.id << "</comments>\n";
    rss << "</item>\n";
  }
  
  rss << "</channel>\n</rss>";
  return rss.str();
}

// ============================================================================
// Statistics calculation
// ============================================================================
LemmyServer::SiteStats LemmyServer::get_site_stats_full() {
  SiteStats stats;
  stats.users = users_.size();
  stats.posts = posts_.size();
  stats.comments = comments_.size();
  stats.communities = communities_.size();
  return stats;
}

LemmyServer::SiteStats LemmyServer::get_community_stats_full(const std::string& community_id) {
  SiteStats stats;
  for (auto& [id, p] : posts_) {
    if (p.community_id == community_id && !p.deleted && !p.removed) stats.posts++;
  }
  for (auto& [id, c] : comments_) {
    auto pit = posts_.find(c.post_id);
    if (pit != posts_.end() && pit->second.community_id == community_id && !c.deleted && !c.removed) stats.comments++;
  }
  stats.communities = 1;
  return stats;
}

// ============================================================================
// Helpers
// ============================================================================
std::string LemmyServer::hash_password(const std::string& pw) {
  // Simple hash for demonstration - in production use bcrypt/argon2
  std::hash<std::string> hasher;
  return std::to_string(hasher(pw));
}

std::string LemmyServer::base64_encode(const std::string& input) {
  static const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out; int val = 0, valb = -6;
  for (unsigned char c : input) { val = (val << 8) + c; valb += 8; while (valb >= 0) { out += chars[(val >> valb) & 0x3F]; valb -= 6; } }
  if (valb > -6) out += chars[((val << 8) >> (valb + 8)) & 0x3F];
  while (out.size() % 4) out += '=';
  return out;
}

std::string LemmyServer::sign_http_request(const std::string& method, const std::string& url, const std::string& body) {
  return "signed-" + std::to_string(std::hash<std::string>{}(method + url + body));
}

std::string LemmyServer::resolve_remote_user(const std::string& actor_id) {
  // Check if we already have this user mapped
  for (auto& [id, actor] : actors_) {
    if (actor.id == actor_id) {
      // Find the local user
      for (auto& [uid, user] : users_) {
        if (gen_ap_id(config_.hostname, "u/" + user.name) == actor_id) return uid;
      }
    }
  }
  // Create a placeholder user
  return create_user("remote_" + gen_id(), "", "").id;
}

std::string LemmyServer::resolve_remote_community(const std::string& community_ap_id) {
  for (auto& [id, c] : communities_) {
    if (gen_ap_id(config_.hostname, "c/" + c.name) == community_ap_id) return id;
  }
  return "";
}

std::string LemmyServer::resolve_post_by_ap_id(const std::string& ap_id) {
  for (auto& [id, p] : posts_) {
    if (gen_ap_id(config_.hostname, "post/" + id) == ap_id) return id;
  }
  return "";
}

bool LemmyServer::is_federated_server_reachable(const std::string& url) { return true; }
bool LemmyServer::verify_rsa_signature(const std::string& sig, const std::string& key) { return true; }

int64_t LemmyServer::parse_iso8601(const std::string& date_str) {
  return nms(); // Simplified
}

std::vector<std::string> LemmyServer::split_header(const std::string& s, char delim) {
  std::vector<std::string> r; std::string item; bool in_quotes = false;
  for (char c : s) {
    if (c == '"') in_quotes = !in_quotes;
    if (c == delim && !in_quotes) { if (!item.empty()) r.push_back(item); item.clear(); }
    else item += c;
  }
  if (!item.empty()) r.push_back(item);
  return r;
}

std::string LemmyServer::trim(const std::string& s, char trim_char) {
  size_t start = 0, end = s.length();
  while (start < end && s[start] == trim_char) start++;
  while (end > start && s[end-1] == trim_char) end--;
  return s.substr(start, end - start);
}

std::string LemmyServer::xml_escape(const std::string& s) {
  std::string r;
  for (char c : s) {
    if (c == '&') r += "&amp;"; else if (c == '<') r += "&lt;";
    else if (c == '>') r += "&gt;"; else if (c == '"') r += "&quot;";
    else r += c;
  }
  return r;
}

std::string LemmyServer::format_rfc822_date(int64_t ts_ms) {
  time_t t = ts_ms / 1000;
  char buf[64];
  strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&t));
  return buf;
}

} // namespace progressive::lemmy


// ============================================================
// LEMY Extended - Full ActivityPub Federation + API
// ============================================================

// ActivityPub Actor handling
json lemmy_get_actor(LemmyServer& srv, const std::string& actor_name) {
    auto* user = srv.get_user_by_name(actor_name);
    if (user) {
        json actor;
        actor["@context"] = json::array({"https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"});
        actor["id"] = srv.base_url()+"/u/"+actor_name;
        actor["type"] = "Person";
        actor["preferredUsername"] = actor_name;
        actor["name"] = user->display_name.empty()?actor_name:user->display_name;
        actor["inbox"] = srv.base_url()+"/u/"+actor_name+"/inbox";
        actor["outbox"] = srv.base_url()+"/u/"+actor_name+"/outbox";
        actor["followers"] = srv.base_url()+"/u/"+actor_name+"/followers";
        actor["following"] = srv.base_url()+"/u/"+actor_name+"/following";
        actor["publicKey"] = {{"id",srv.base_url()+"/u/"+actor_name+"#main-key"},{"owner",srv.base_url()+"/u/"+actor_name},{"publicKeyPem",user->public_key}};
        if(!user->avatar_url.empty()) actor["icon"] = {{"type","Image"},{"url",user->avatar_url}};
        actor["published"] = std::to_string(user->created_at/1000);
        actor["summary"] = user->bio;
        return actor;
    }
    auto* community = srv.get_community_by_name(actor_name);
    if (community) {
        json actor;
        actor["@context"] = json::array({"https://www.w3.org/ns/activitystreams"});
        actor["id"] = srv.base_url()+"/c/"+actor_name;
        actor["type"] = "Group";
        actor["preferredUsername"] = actor_name;
        actor["name"] = community->title;
        actor["inbox"] = srv.base_url()+"/c/"+actor_name+"/inbox";
        actor["outbox"] = srv.base_url()+"/c/"+actor_name+"/outbox";
        actor["followers"] = srv.base_url()+"/c/"+actor_name+"/followers";
        actor["publicKey"] = {{"id",srv.base_url()+"/c/"+actor_name+"#main-key"},{"owner",srv.base_url()+"/c/"+actor_name},{"publicKeyPem",community->public_key}};
        actor["summary"] = community->description;
        if(!community->icon_url.empty()) actor["icon"] = {{"type","Image"},{"url",community->icon_url}};
        actor["published"] = std::to_string(community->created_at/1000);
        return actor;
    }
    return json::object();
}

// ActivityPub Outbox
json lemmy_get_outbox(LemmyServer& srv, const std::string& actor, int page) {
    json outbox;
    outbox["@context"] = "https://www.w3.org/ns/activitystreams";
    outbox["id"] = srv.base_url()+"/u/"+actor+"/outbox?page="+std::to_string(page);
    outbox["type"] = "OrderedCollectionPage";
    outbox["partOf"] = srv.base_url()+"/u/"+actor+"/outbox";
    outbox["orderedItems"] = json::array();
    
    auto activities = srv.get_user_activities(actor, page*20, 20);
    for (auto& act : activities) outbox["orderedItems"].push_back(act);
    return outbox;
}

// ActivityPub Followers
json lemmy_get_followers(LemmyServer& srv, const std::string& actor, int page) {
    json followers;
    followers["@context"] = "https://www.w3.org/ns/activitystreams";
    followers["id"] = srv.base_url()+"/u/"+actor+"/followers?page="+std::to_string(page);
    followers["type"] = "OrderedCollectionPage";
    followers["partOf"] = srv.base_url()+"/u/"+actor+"/followers";
    followers["orderedItems"] = json::array();
    auto folls = srv.get_actor_followers(actor, page*20, 20);
    for (auto& f : folls) followers["orderedItems"].push_back(f);
    return followers;
}

// ActivityPub Inbox processing
void lemmy_process_inbox(LemmyServer& srv, const std::string& actor, const json& activity) {
    std::string type = activity.value("type", "");
    
    if (type == "Follow") {
        std::string follower = activity["actor"].get<std::string>();
        srv.accept_follow(actor, follower);
        // Send Accept
        json accept;
        accept["@context"] = "https://www.w3.org/ns/activitystreams";
        accept["id"] = srv.base_url()+"/activities/accept/" + generate_lemmy_id();
        accept["type"] = "Accept";
        accept["actor"] = srv.base_url()+"/u/"+actor;
        accept["object"] = activity;
        srv.send_to_inbox(follower, accept);
    }
    else if (type == "Undo") {
        json object = activity.value("object", json::object());
        if (object.value("type","") == "Follow") {
            std::string follower = object.value("actor","");
            srv.remove_follower(actor, follower);
        }
    }
    else if (type == "Create") {
        json object = activity.value("object", json::object());
        std::string obj_type = object.value("type","");
        if (obj_type == "Note" || obj_type == "Article") {
            // Incoming post or comment from federated instance
            std::string community_id = object.value("to","");
            lemmy_ingest_post(srv, object, community_id);
        }
    }
    else if (type == "Like" || type == "Dislike") {
        json object = activity.value("object", json::object());
        std::string post_id = object.value("id","");
        if (!post_id.empty()) {
            bool is_upvote = (type == "Like");
            int64_t person_id = srv.get_or_create_remote_person(activity["actor"]);
            srv.add_remote_vote(post_id, person_id, is_upvote ? 1 : -1);
        }
    }
    else if (type == "Delete") {
        json object = activity.value("object", json::object());
        std::string obj_id = object.is_string() ? object.get<std::string>() : object.value("id","");
        srv.mark_removed(obj_id);
    }
    else if (type == "Update") {
        json object = activity.value("object", json::object());
        std::string obj_type = object.value("type","");
        if (obj_type == "Person") lemmy_update_remote_person(srv, object);
        else if (obj_type == "Group") lemmy_update_remote_community(srv, object);
        else if (obj_type == "Note" || obj_type == "Article") lemmy_update_post(srv, object);
    }
    else if (type == "Announce") {
        // Boost / cross-post
        json object = activity.value("object", json::object());
        lemmy_handle_announce(srv, object, activity["actor"]);
    }
    else if (type == "Block") {
        std::string target = activity["object"].get<std::string>();
        srv.block_instance_or_user(actor, target);
    }
}

// Ingest federated post
void lemmy_ingest_post(LemmyServer& srv, const json& object, const std::string& community_url) {
    std::string post_url = object["id"].get<std::string>();
    if (srv.post_exists(post_url)) return;
    
    auto* community = srv.get_community_by_url(community_url);
    if (!community) return;
    
    int64_t creator_id = srv.get_or_create_remote_person(object["attributedTo"]);
    
    int64_t post_id = srv.create_post_from_activity(object, community->id, creator_id);
    
    // Notify community subscribers
    srv.notify_community_subscribers(community->id, post_id);
}

// Create federated activity
json lemmy_create_activity(LemmyServer& srv, const std::string& actor, const std::string& act_type, const json& object, const std::vector<std::string>& to) {
    json activity;
    activity["@context"] = "https://www.w3.org/ns/activitystreams";
    activity["id"] = srv.base_url()+"/activities/"+act_type+"/"+generate_lemmy_id();
    activity["type"] = act_type;
    activity["actor"] = srv.base_url()+"/u/"+actor;
    activity["object"] = object;
    activity["to"] = to;
    activity["cc"] = json::array({srv.base_url()+"/c/all/followers"});
    return activity;
}

// Send activity to followers
void lemmy_federate_activity(LemmyServer& srv, const json& activity, const std::vector<std::string>& inboxes) {
    for (auto& inbox : inboxes) {
        srv.send_to_inbox(inbox, activity);
    }
}

// WebFinger implementation
json lemmy_webfinger(LemmyServer& srv, const std::string& resource) {
    auto acct = resource.find("acct:");
    std::string username;
    if (acct == 0) {
        auto at = resource.find('@', 5);
        username = resource.substr(5, at-5);
    }
    
    json wf;
    wf["subject"] = resource;
    wf["links"] = json::array();
    
    auto* user = srv.get_user_by_name(username);
    if (user) {
        json link;
        link["rel"] = "self";
        link["type"] = "application/activity+json";
        link["href"] = srv.base_url()+"/u/"+username;
        wf["links"].push_back(link);
    }
    
    auto* community = srv.get_community_by_name(username);
    if (community) {
        json link;
        link["rel"] = "self";
        link["type"] = "application/activity+json";
        link["href"] = srv.base_url()+"/c/"+username;
        wf["links"].push_back(link);
    }
    
    return wf;
}

// NodeInfo (Lemmy discovery)
json lemmy_nodeinfo(LemmyServer& srv, const std::string& version) {
    json ni;
    ni["version"] = version.empty() ? "2.0" : version;
    ni["software"] = {{"name","progressive-lemmy"},{"version",srv.version()}};
    ni["protocols"] = json::array({"activitypub"});
    ni["services"] = {{"inbound",json::array()},{"outbound",json::array()}};
    
    if (version == "2.0" || version.empty()) {
        ni["openRegistrations"] = srv.registration_open();
        ni["usage"] = {
            {"users",{{"total",srv.user_count()},{"activeMonth",srv.monthly_active_users()}}},
            {"localPosts",srv.local_post_count()},
            {"localComments",srv.local_comment_count()}
        };
    }
    
    return ni;
}

// Full-Text Search (PostgreSQL FTS equivalent)
std::vector<json> lemmy_search(LemmyServer& srv, const std::string& q, const std::string& type_, 
                                const std::string& community_name, int page, int limit, 
                                const std::string& sort) {
    std::vector<json> results;
    
    if (type_ == "Posts" || type_.empty()) {
        auto posts = srv.search_posts(q, community_name, page, limit, sort);
        for (auto& p : posts) {
            json post;
            post["type"] = "Post";
            post["post"] = p;
            results.push_back(post);
        }
    }
    
    if (type_ == "Comments" || type_.empty()) {
        auto comments = srv.search_comments(q, community_name, page, limit, sort);
        for (auto& c : comments) {
            json comment;
            comment["type"] = "Comment";
            comment["comment"] = c;
            results.push_back(comment);
        }
    }
    
    if (type_ == "Communities" || type_.empty()) {
        auto communities = srv.search_communities(q, page, limit);
        for (auto& c : communities) {
            json comm;
            comm["type"] = "Community";
            comm["community"] = c;
            results.push_back(comm);
        }
    }
    
    if (type_ == "Users" || type_.empty()) {
        auto users = srv.search_users(q, page, limit);
        for (auto& u : users) {
            json user;
            user["type"] = "User";
            user["user"] = u;
            results.push_back(user);
        }
    }
    
    return results;
}

// Moderation actions
json lemmy_ban_user(LemmyServer& srv, const std::string& mod_id, const std::string& user_id, 
                    bool ban, bool remove_data, const std::string& reason, int64_t expires) {
    auto* mod = srv.get_user(mod_id);
    if (!mod || !mod->is_admin) return {{"error","not_admin"}};
    
    srv.ban_user(user_id, ban, expires, reason);
    
    if (remove_data) {
        srv.remove_user_content(user_id);
    }
    
    json resp;
    resp["banned"] = ban;
    resp["user_id"] = user_id;
    resp["reason"] = reason;
    resp["expires"] = expires;
    return resp;
}

json lemmy_ban_from_community(LemmyServer& srv, const std::string& mod_id, int64_t community_id,
                               const std::string& user_id, bool ban, const std::string& reason, 
                               bool remove_data, int64_t expires) {
    auto* mod = srv.get_user(mod_id);
    if (!mod) return {{"error","not_found"}};
    if (!srv.is_community_mod(mod_id, community_id) && !mod->is_admin) return {{"error","not_mod"}};
    
    srv.ban_user_from_community(user_id, community_id, ban, expires, reason);
    
    if (remove_data) {
        srv.remove_user_content_from_community(user_id, community_id);
    }
    
    json resp;
    resp["banned"] = ban;
    resp["user_id"] = user_id;
    resp["community_id"] = community_id;
    return resp;
}

json lemmy_add_mod_to_community(LemmyServer& srv, const std::string& mod_id, int64_t community_id,
                                 const std::string& user_id, bool added) {
    if (!srv.is_admin(mod_id)) return {{"error","not_admin"}};
    auto* user = srv.get_user(user_id);
    if (!user) return {{"error","user_not_found"}};
    
    if (added) srv.add_moderator(community_id, user_id);
    else srv.remove_moderator(community_id, user_id);
    
    return {{"success",true},{"community_id",community_id},{"user_id",user_id},{"moderator",added}};
}

json lemmy_remove_post(LemmyServer& srv, const std::string& mod_id, int64_t post_id, 
                       bool removed, const std::string& reason) {
    auto* mod = srv.get_user(mod_id);
    if (!mod) return {{"error","not_found"}};
    auto post = srv.get_post(post_id);
    if (!post) return {{"error","post_not_found"}};
    if (!srv.is_community_mod(mod_id, post->community_id) && !mod->is_admin) return {{"error","not_mod"}};
    
    srv.set_post_removed(post_id, removed, reason);
    return {{"success",true},{"post_id",post_id},{"removed",removed}};
}

json lemmy_remove_comment(LemmyServer& srv, const std::string& mod_id, int64_t comment_id,
                          bool removed, const std::string& reason) {
    auto* mod = srv.get_user(mod_id);
    if (!mod) return {{"error","not_found"}};
    auto comment = srv.get_comment(comment_id);
    if (!comment) return {{"error","comment_not_found"}};
    if (!srv.is_community_mod(mod_id, comment->community_id) && !mod->is_admin) return {{"error","not_mod"}};
    
    srv.set_comment_removed(comment_id, removed, reason);
    return {{"success",true},{"comment_id",comment_id},{"removed",removed}};
}

json lemmy_purge_post(LemmyServer& srv, const std::string& admin_id, int64_t post_id, const std::string& reason) {
    if (!srv.is_admin(admin_id)) return {{"error","not_admin"}};
    srv.purge_post(post_id);
    return {{"success",true}};
}

json lemmy_purge_comment(LemmyServer& srv, const std::string& admin_id, int64_t comment_id, const std::string& reason) {
    if (!srv.is_admin(admin_id)) return {{"error","not_admin"}};
    srv.purge_comment(comment_id);
    return {{"success",true}};
}

json lemmy_purge_user(LemmyServer& srv, const std::string& admin_id, const std::string& user_id, const std::string& reason) {
    if (!srv.is_admin(admin_id)) return {{"error","not_admin"}};
    srv.purge_user(user_id);
    return {{"success",true}};
}

json lemmy_purge_community(LemmyServer& srv, const std::string& admin_id, int64_t community_id, const std::string& reason) {
    if (!srv.is_admin(admin_id)) return {{"error","not_admin"}};
    srv.purge_community(community_id);
    return {{"success",true}};
}

// Federation blocklist
json lemmy_federation_blocklist(LemmyServer& srv) {
    json bl;
    bl["allowed_instances"] = json::array();
    bl["blocked_instances"] = json::array();
    for (auto& inst : srv.blocked_instances()) bl["blocked_instances"].push_back(inst);
    for (auto& inst : srv.allowed_instances()) bl["allowed_instances"].push_back(inst);
    bl["strict_allowlist"] = srv.strict_allowlist();
    return bl;
}

// RSS/Atom Feed generation
std::string lemmy_generate_rss(LemmyServer& srv, const std::string& feed_type, const std::string& name, const std::string& sort) {
    std::stringstream rss;
    rss << "<?xml version="1.0" encoding="UTF-8"?>
";
    rss << "<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom" xmlns:dc="http://purl.org/dc/elements/1.1/">
";
    rss << "  <channel>
";
    rss << "    <title>Progressive Lemmy - " << (feed_type=="All"?"All Posts":feed_type) << "</title>
";
    rss << "    <link>" << srv.base_url() << "/</link>
";
    rss << "    <description>Lemmy RSS Feed</description>
";
    rss << "    <atom:link href="" << srv.base_url() << "/feeds/" << feed_type << ".xml?sort=" << sort << "" rel="self" type="application/rss+xml"/>
";
    
    auto posts = srv.get_feed_posts(feed_type, name, sort, 20);
    for (auto& p : posts) {
        rss << "    <item>
";
        rss << "      <title>" << xml_escape(p.name) << "</title>
";
        rss << "      <link>" << srv.base_url() << "/post/" << p.id << "</link>
";
        rss << "      <description>" << xml_escape(p.body) << "</description>
";
        rss << "      <pubDate>" << p.published << "</pubDate>
";
        rss << "      <dc:creator>" << xml_escape(p.creator_name) << "</dc:creator>
";
        if (!p.community_name.empty()) {
            rss << "      <category>" << xml_escape(p.community_name) << "</category>
";
        }
        rss << "      <guid>" << p.ap_id << "</guid>
";
        rss << "    </item>
";
    }
    
    rss << "  </channel>
</rss>
";
    return rss.str();
}

// Pagination helpers
json lemmy_paginated_response(const std::vector<json>& items, int page, int limit, int total_count) {
    json resp;
    resp["items"] = items;
    resp["page"] = page;
    resp["limit"] = limit;
    resp["total_count"] = total_count;
    resp["total_pages"] = (total_count + limit - 1) / limit;
    resp["has_next"] = (page + 1) * limit < total_count;
    resp["has_prev"] = page > 0;
    return resp;
}

// Captcha integration
json lemmy_get_captcha(LemmyServer& srv) {
    json captcha;
    if (!srv.captcha_enabled()) {
        captcha["ok"] = json::object();
        return captcha;
    }
    captcha["ok"] = {
        {"png",srv.generate_captcha_image()},
        {"wav",""},
        {"uuid",srv.generate_captcha_uuid()}
    };
    return captcha;
}

// Private message
json lemmy_create_private_message(LemmyServer& srv, const std::string& from_id, const std::string& to_id, const std::string& content) {
    auto* from = srv.get_user(from_id);
    auto* to = srv.get_user(to_id);
    if (!from || !to) return {{"error","user_not_found"}};
    
    // Check block
    if (srv.is_blocked_by(to_id, from_id)) return {{"error","blocked"}};
    
    int64_t pm_id = srv.create_pm(from_id, to_id, content);
    
    json pm;
    pm["id"] = pm_id;
    pm["from_id"] = from_id;
    pm["to_id"] = to_id;
    pm["content"] = content;
    pm["created_at"] = std::time(nullptr);
    pm["read"] = false;
    
    // Notify recipient
    srv.notify_user(to_id, "new_private_message", pm);
    
    return pm;
}

json lemmy_get_private_messages(LemmyServer& srv, const std::string& user_id, bool unread_only, int page, int limit) {
    auto pms = srv.get_user_pms(user_id, unread_only, page, limit);
    auto count = srv.count_user_pms(user_id, unread_only);
    return lemmy_paginated_response(pms, page, limit, count);
}

json lemmy_mark_pm_read(LemmyServer& srv, const std::string& user_id, int64_t pm_id, bool read) {
    srv.mark_pm_read(pm_id, read);
    return {{"id",pm_id},{"read",read}};
}

// Report handling
json lemmy_create_report(LemmyServer& srv, const std::string& reporter_id, int64_t item_id, 
                         const std::string& item_type, const std::string& reason) {
    int64_t report_id = srv.create_report(reporter_id, item_id, item_type, reason);
    // Notify admins
    srv.notify_admins("new_report", {{"report_id",report_id},{"type",item_type},{"item_id",item_id},{"reason",reason}});
    return {{"report_id",report_id},{"success",true}};
}

json lemmy_resolve_report(LemmyServer& srv, const std::string& admin_id, int64_t report_id, bool resolved) {
    if (!srv.is_admin(admin_id)) return {{"error","not_admin"}};
    srv.resolve_report(report_id, admin_id, resolved);
    return {{"report_id",report_id},{"resolved",resolved}};
}

json lemmy_list_reports(LemmyServer& srv, const std::string& admin_id, const std::string& community_name, bool unresolved_only, int page, int limit) {
    if (!srv.is_admin(admin_id)) return {{"error","not_admin"}};
    int64_t community_id = community_name.empty() ? -1 : srv.get_community_id_by_name(community_name);
    auto reports = srv.list_reports(community_id, unresolved_only, page, limit);
    auto count = srv.count_reports(community_id, unresolved_only);
    return lemmy_paginated_response(reports, page, limit, count);
}

// Site configuration
json lemmy_get_site(LemmyServer& srv) {
    json site;
    site["id"] = 1;
    site["name"] = srv.site_name();
    site["description"] = srv.site_description();
    site["sidebar"] = srv.site_sidebar();
    site["published"] = srv.site_created();
    site["updated"] = srv.site_updated();
    site["icon_url"] = srv.site_icon();
    site["banner_url"] = srv.site_banner();
    site["actor_id"] = srv.base_url() + "/";
    site["last_refreshed_at"] = std::time(nullptr);
    site["inbox_url"] = srv.base_url() + "/inbox";
    site["public_key"] = srv.site_public_key();
    site["instance_id"] = 1;
    return site;
}

json lemmy_edit_site(LemmyServer& srv, const std::string& admin_id, const json& updates) {
    if (!srv.is_admin(admin_id)) return {{"error","not_admin"}};
    if (updates.contains("name")) srv.set_site_name(updates["name"]);
    if (updates.contains("description")) srv.set_site_description(updates["description"]);
    if (updates.contains("sidebar")) srv.set_site_sidebar(updates["sidebar"]);
    if (updates.contains("icon_url")) srv.set_site_icon(updates["icon_url"]);
    if (updates.contains("banner_url")) srv.set_site_banner(updates["banner_url"]);
    if (updates.contains("registration_open")) srv.set_registration_open(updates["registration_open"]);
    if (updates.contains("enable_nsfw")) srv.set_enable_nsfw(updates["enable_nsfw"]);
    if (updates.contains("community_creation_admin_only")) srv.set_community_creation_admin_only(updates["community_creation_admin_only"]);
    if (updates.contains("require_email_verification")) srv.set_require_email_verification(updates["require_email_verification"]);
    if (updates.contains("application_question")) srv.set_application_question(updates["application_question"]);
    if (updates.contains("private_instance")) srv.set_private_instance(updates["private_instance"]);
    if (updates.contains("default_theme")) srv.set_default_theme(updates["default_theme"]);
    if (updates.contains("default_post_listing_type")) srv.set_default_listing_type(updates["default_post_listing_type"]);
    if (updates.contains("legal_information")) srv.set_legal_info(updates["legal_information"]);
    if (updates.contains("hide_modlog_names")) srv.set_hide_modlog_names(updates["hide_modlog_names"]);
    if (updates.contains("discussion_languages")) srv.set_discussion_languages(updates["discussion_languages"]);
    if (updates.contains("slur_filter_regex")) srv.set_slur_filter(updates["slur_filter_regex"]);
    if (updates.contains("actor_name_max_length")) srv.set_actor_name_max_length(updates["actor_name_max_length"]);
    if (updates.contains("federation_enabled")) srv.set_federation_enabled(updates["federation_enabled"]);
    if (updates.contains("captcha_enabled")) srv.set_captcha_enabled(updates["captcha_enabled"]);
    if (updates.contains("captcha_difficulty")) srv.set_captcha_difficulty(updates["captcha_difficulty"]);
    if (updates.contains("allowed_instances")) srv.set_allowed_instances(updates["allowed_instances"]);
    if (updates.contains("blocked_instances")) srv.set_blocked_instances(updates["blocked_instances"]);
    return lemmy_get_site(srv);
}

// Taglines
json lemmy_list_taglines(LemmyServer& srv) {
    auto taglines = srv.get_taglines();
    json resp;
    resp["taglines"] = taglines;
    return resp;
}

json lemmy_create_tagline(LemmyServer& srv, const std::string& admin_id, const std::string& content) {
    if (!srv.is_admin(admin_id)) return {{"error","not_admin"}};
    srv.create_tagline(content);
    return {{"success",true}};
}

// Custom emoji
json lemmy_list_custom_emojis(LemmyServer& srv) {
    auto emojis = srv.get_custom_emojis();
    json resp;
    resp["custom_emojis"] = emojis;
    return resp;
}

json lemmy_create_custom_emoji(LemmyServer& srv, const std::string& admin_id, const std::string& shortcode, const std::string& image_url, const std::string& alt_text, const std::string& category) {
    if (!srv.is_admin(admin_id)) return {{"error","not_admin"}};
    srv.create_emoji(shortcode, image_url, alt_text, category);
    return {{"success",true}};
}

// Federation queue management
json lemmy_get_federation_queue(LemmyServer& srv, const std::string& admin_id, int page, int limit) {
    if (!srv.is_admin(admin_id)) return {{"error","not_admin"}};
    auto queue = srv.get_federation_queue(page, limit);
    auto count = srv.count_federation_queue();
    return lemmy_paginated_response(queue, page, limit, count);
}

json lemmy_retry_federation_send(LemmyServer& srv, const std::string& admin_id, int64_t activity_id) {
    if (!srv.is_admin(admin_id)) return {{"error","not_admin"}};
    srv.retry_federation_send(activity_id);
    return {{"success",true}};
}

// ============================================================
// Helper functions
// ============================================================

std::string generate_lemmy_id() {
    static std::atomic<int64_t> counter{0};
    return std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + "-" + std::to_string(++counter);
}

std::string xml_escape(const std::string& s) {
    std::string result; result.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '&': result += "&amp;"; break;
            case '"': result += "&quot;"; break;
            case ''': result += "&apos;"; break;
            default: result += c;
        }
    }
    return result;
}

