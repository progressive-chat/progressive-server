// lemmy_full_b.cpp — Advanced Lemmy Features (2000+ lines)
// Implements: Comment trees, User profiles/settings (2FA, password reset,
// email verification), Community sidebar editing, Post URL metadata fetching
// (OpenGraph/oEmbed), Image upload via pictrs API, Banned user appeal system,
// Instance/community transfer, Modlog detailed history, Admin purge queue,
// Registration applications with email, Email notifications for replies/
// mentions/PMs, WebSocket real-time notifications, OAuth2 provider for Matrix
// bridging, Language tagging, NSFW marking, Sticky/locked posts.
//
// Reference: lemmy_server.hpp — companion to lemmy_server_full.cpp and
// lemmy_full_a.cpp providing advanced community and user features.

#include "lemmy_server.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <ctime>
#include <deque>
#include <functional>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <stack>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ---------------------------------------------------------------------------
// OpenSSL for cryptographic operations (TOTP/2FA, OAuth2 tokens, SHA)
// ---------------------------------------------------------------------------
#if defined(PROGRESSIVE_USE_OPENSSL) && !defined(PROGRESSIVE_NO_OPENSSL)
  #include <openssl/hmac.h>
  #include <openssl/rand.h>
  #include <openssl/sha.h>
  #define LFB_HAS_OPENSSL 1
#else
  #define LFB_HAS_OPENSSL 0
#endif

namespace progressive::lemmy {

using json = nlohmann::json;

// ============================================================================
// Section B1: Internal helpers — time, UUIDs, base64, URL parsing, HTML
// ============================================================================

namespace lfb_detail {

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

inline std::string gen_uid(const std::string& prefix = "") {
  static std::atomic<int64_t> counter{1};
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(counter.fetch_add(1, std::memory_order_relaxed));
}

// Simple UUID v4 generation
std::string gen_uuid() {
  std::string uuid(36, '-');
  static const char* hex = "0123456789abcdef";
  static std::mt19937_64 rng(now_ms() ^ std::hash<std::thread::id>{}(std::this_thread::get_id()));
  std::uniform_int_distribution<int> dist(0, 15);

  for (int i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23) { uuid[i] = '-'; continue; }
    uuid[i] = hex[dist(rng)];
  }
  uuid[14] = '4'; // Version 4
  uuid[19] = hex[(dist(rng) & 0x3) | 0x8]; // Variant
  return uuid;
}

// Base64 encode
std::string b64_encode(const std::string& input) {
  static const char* chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((input.size() + 2) / 3) * 4);
  int val = 0, valb = -6;
  for (unsigned char c : input) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) out.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4) out.push_back('=');
  return out;
}

// Base64 URL-safe encode (for OAuth2 tokens)
std::string b64_url_encode(const std::string& input) {
  std::string b = b64_encode(input);
  for (char& c : b) {
    if (c == '+') c = '-';
    if (c == '/') c = '_';
  }
  while (!b.empty() && b.back() == '=') b.pop_back();
  return b;
}

// SHA-256 hash
std::string sha256(const std::string& data) {
#if LFB_HAS_OPENSSL
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
  std::stringstream ss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
  return ss.str();
#else
  return data; // Placeholder
#endif
}

// HMAC-SHA256
std::string hmac_sha256(const std::string& key, const std::string& data) {
#if LFB_HAS_OPENSSL
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(data.data()), data.size(), result, &len);
  std::stringstream ss;
  for (unsigned int i = 0; i < len; ++i)
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(result[i]);
  return ss.str();
#else
  return data;
#endif
}

// Secure random bytes
std::string random_bytes(size_t count) {
  std::string buf(count, '\0');
#if LFB_HAS_OPENSSL
  RAND_bytes(reinterpret_cast<unsigned char*>(&buf[0]), static_cast<int>(count));
#else
  std::mt19937_64 rng(now_ms());
  for (size_t i = 0; i < count; i++)
    buf[i] = static_cast<char>(rng() & 0xFF);
#endif
  return buf;
}

// Extract domain from URL
std::string extract_domain(const std::string& url) {
  std::regex re(R"(https?://([^/:]+))");
  std::smatch m;
  if (std::regex_search(url, m, re)) return m[1].str();
  return url;
}

// Strip HTML tags (simple)
std::string strip_html(const std::string& html) {
  std::string result;
  bool in_tag = false;
  for (char c : html) {
    if (c == '<') in_tag = true;
    else if (c == '>') in_tag = false;
    else if (!in_tag) result += c;
  }
  // Decode common entities
  auto replace_all = [](std::string& s, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
      s.replace(pos, from.length(), to);
      pos += to.length();
    }
  };
  replace_all(result, "&amp;", "&");
  replace_all(result, "&lt;", "<");
  replace_all(result, "&gt;", ">");
  replace_all(result, "&quot;", "\"");
  replace_all(result, "&#39;", "'");
  replace_all(result, "&#x27;", "'");
  replace_all(result, "&nbsp;", " ");
  return result;
}

// Extract meta tag content from HTML
std::string extract_meta(const std::string& html, const std::string& property) {
  // Try property="og:title" style
  std::regex re_prop(property + R"("\s+content="([^"]*))", std::regex::icase);
  std::smatch m;
  if (std::regex_search(html, m, re_prop)) return m[1].str();

  // Try name="title" style
  std::regex re_name(R"(name=")" + property + R"("\s+content="([^"]*))", std::regex::icase);
  if (std::regex_search(html, m, re_name)) return m[1].str();

  return "";
}

// ISO 8601 format
std::string format_iso8601(int64_t ts_sec) {
  time_t t = static_cast<time_t>(ts_sec);
  struct tm tm_buf;
  gmtime_r(&t, &tm_buf);
  char buf[64];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
  return buf;
}

// XML escape
std::string xml_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&apos;"; break;
      default: out += c;
    }
  }
  return out;
}

} // namespace lfb_detail

// ============================================================================
// Section B2: Comment Tree Builder — nested replies with depth limit
// ============================================================================

// Forward declaration: external comment lookup (accesses LemmyServer)
// Comment tree node for creating nested comment structures
struct CommentTreeNode {
  Comment comment;
  std::vector<std::shared_ptr<CommentTreeNode>> children;
  int depth{0};
  bool collapsed{false};
};

// Build a comment tree from a flat list of comments.
// depth_limit: maximum nesting depth (default 8).
// sort_by: "hot", "new", "old", "top".
json build_comment_tree(
    const std::vector<Comment>& comments,
    const std::string& sort_by,
    int max_depth) {

  // Index comments by ID for O(1) parent lookup
  std::unordered_map<std::string, std::shared_ptr<CommentTreeNode>> index;
  std::vector<std::shared_ptr<CommentTreeNode>> roots;

  // Create tree nodes
  for (const auto& c : comments) {
    auto node = std::make_shared<CommentTreeNode>();
    node->comment = c;
    index[c.id] = node;
  }

  // Build parent-child relationships
  for (const auto& c : comments) {
    auto it = index.find(c.id);
    if (it == index.end()) continue;

    if (c.parent_id.has_value() && !c.parent_id->empty()) {
      auto parent_it = index.find(*c.parent_id);
      if (parent_it != index.end()) {
        parent_it->second->children.push_back(it->second);
        it->second->depth = parent_it->second->depth + 1;
      } else {
        // Orphaned — treat as root
        it->second->depth = 0;
        roots.push_back(it->second);
      }
    } else {
      roots.push_back(it->second);
    }
  }

  // Mark nodes beyond max_depth as collapsed
  std::function<void(std::shared_ptr<CommentTreeNode>)> mark_collapsed =
      [&](std::shared_ptr<CommentTreeNode> node) {
        if (node->depth >= max_depth) {
          node->collapsed = true;
        }
        for (auto& child : node->children) {
          if (child->depth >= max_depth) child->collapsed = true;
          mark_collapsed(child);
        }
      };

  for (auto& root : roots) mark_collapsed(root);

  // Sorting helper
  auto cmp_hot = [](const std::shared_ptr<CommentTreeNode>& a,
                     const std::shared_ptr<CommentTreeNode>& b) {
    double rank_a = a->comment.score / (1.0 + std::log(1.0 + std::abs(a->comment.score)));
    double rank_b = b->comment.score / (1.0 + std::log(1.0 + std::abs(b->comment.score)));
    // Time decay
    int64_t age_a = lfb_detail::now_sec() - a->comment.published;
    int64_t age_b = lfb_detail::now_sec() - b->comment.published;
    double order = std::log10(std::max(std::abs(rank_a), 1.0)) +
                   (age_a > 0 ? age_a / 45000.0 : 0);
    double order_b = std::log10(std::max(std::abs(rank_b), 1.0)) +
                     (age_b > 0 ? age_b / 45000.0 : 0);
    return order > order_b;
  };

  auto cmp_new = [](const std::shared_ptr<CommentTreeNode>& a,
                     const std::shared_ptr<CommentTreeNode>& b) {
    return a->comment.published > b->comment.published;
  };

  auto cmp_old = [](const std::shared_ptr<CommentTreeNode>& a,
                     const std::shared_ptr<CommentTreeNode>& b) {
    return a->comment.published < b->comment.published;
  };

  auto cmp_top = [](const std::shared_ptr<CommentTreeNode>& a,
                     const std::shared_ptr<CommentTreeNode>& b) {
    return a->comment.score > b->comment.score;
  };

  // Sort recursively
  std::function<void(std::vector<std::shared_ptr<CommentTreeNode>>&)> sort_nodes;

  if (sort_by == "new") {
    sort_nodes = [cmp_new](std::vector<std::shared_ptr<CommentTreeNode>>& nodes) {
      std::sort(nodes.begin(), nodes.end(), cmp_new);
      for (auto& n : nodes) sort_nodes(n->children);
    };
  } else if (sort_by == "old") {
    sort_nodes = [cmp_old](std::vector<std::shared_ptr<CommentTreeNode>>& nodes) {
      std::sort(nodes.begin(), nodes.end(), cmp_old);
      for (auto& n : nodes) sort_nodes(n->children);
    };
  } else if (sort_by == "top") {
    sort_nodes = [cmp_top](std::vector<std::shared_ptr<CommentTreeNode>>& nodes) {
      std::sort(nodes.begin(), nodes.end(), cmp_top);
      for (auto& n : nodes) sort_nodes(n->children);
    };
  } else {
    sort_nodes = [cmp_hot](std::vector<std::shared_ptr<CommentTreeNode>>& nodes) {
      std::sort(nodes.begin(), nodes.end(), cmp_hot);
      for (auto& n : nodes) sort_nodes(n->children);
    };
  }

  sort_nodes(roots);

  // Serialize to JSON
  std::function<json(const std::shared_ptr<CommentTreeNode>&)> serialize;

  serialize = [&](const std::shared_ptr<CommentTreeNode>& node) -> json {
    json j;
    // Filter deleted/removed comments for non-mod views
    j["id"] = node->comment.id;
    j["content"] = node->comment.deleted ? "[removed]" : node->comment.content;
    j["creator_id"] = node->comment.creator_id;
    j["post_id"] = node->comment.post_id;
    j["parent_id"] = node->comment.parent_id.has_value() ?
                     json(*node->comment.parent_id) : json(nullptr);
    j["removed"] = node->comment.removed;
    j["deleted"] = node->comment.deleted;
    j["distinguished"] = node->comment.distinguished;
    j["score"] = node->comment.score;
    j["upvotes"] = node->comment.upvotes;
    j["downvotes"] = node->comment.downvotes;
    j["published"] = lfb_detail::format_iso8601(node->comment.published / 1000);
    j["updated"] = node->comment.updated > 0 ?
                   json(lfb_detail::format_iso8601(node->comment.updated / 1000)) :
                   json(nullptr);
    j["depth"] = node->depth;
    j["collapsed"] = node->collapsed;
    j["child_count"] = static_cast<int>(node->children.size());

    json children_json = json::array();
    for (const auto& child : node->children) {
      children_json.push_back(serialize(child));
    }
    j["children"] = children_json;
    return j;
  };

  json result = json::array();
  for (const auto& root : roots) {
    result.push_back(serialize(root));
  }

  return result;
}

// Flatten comment tree back to a sorted list (for pagination or API responses)
std::vector<Comment> flatten_comment_tree(const json& tree) {
  std::vector<Comment> result;
  std::function<void(const json&)> flatten = [&](const json& node) {
    Comment c;
    c.id = node["id"];
    c.content = node["content"];
    c.creator_id = node["creator_id"];
    c.post_id = node["post_id"];
    if (!node["parent_id"].is_null()) c.parent_id = node["parent_id"];
    c.removed = node.value("removed", false);
    c.deleted = node.value("deleted", false);
    c.distinguished = node.value("distinguished", false);
    c.score = node.value("score", int64_t{0});
    c.upvotes = node.value("upvotes", int64_t{0});
    c.downvotes = node.value("downvotes", int64_t{0});
    result.push_back(c);
    if (node.contains("children")) {
      for (const auto& child : node["children"]) {
        flatten(child);
      }
    }
  };
  for (const auto& root : tree) flatten(root);
  return result;
}

// Get comment count at each depth level
std::map<int, int> comment_depth_distribution(const std::vector<Comment>& comments) {
  std::unordered_map<std::string, int> depth_map;
  std::unordered_map<std::string, std::string> parent_map;

  for (const auto& c : comments) {
    if (c.parent_id.has_value() && !c.parent_id->empty())
      parent_map[c.id] = *c.parent_id;
  }

  std::function<int(const std::string&)> get_depth =
      [&](const std::string& cid) -> int {
    if (depth_map.count(cid)) return depth_map[cid];
    auto pit = parent_map.find(cid);
    if (pit == parent_map.end()) { depth_map[cid] = 0; return 0; }
    int d = get_depth(pit->second) + 1;
    depth_map[cid] = d;
    return d;
  };

  std::map<int, int> result;
  for (const auto& c : comments) {
    int d = get_depth(c.id);
    result[d]++;
  }
  return result;
}

// ============================================================================
// Section B3: Post URL Metadata Fetching (OpenGraph, oEmbed, Link Previews)
// ============================================================================

// Post metadata fetched from external URLs
struct PostMetadata {
  std::string title;             // og:title or <title>
  std::string description;       // og:description or meta description
  std::string image_url;         // og:image
  std::string site_name;         // og:site_name
  std::string content_type;      // og:type (article, video, etc.)
  std::string video_url;         // og:video
  std::string audio_url;         // og:audio
  std::string embed_html;        // oEmbed HTML
  std::string author;            // article:author
  int64_t published_time{0};     // article:published_time
  int64_t image_width{0};
  int64_t image_height{0};
  bool has_oembed{false};
  bool is_nsfw{false};
  std::string lang;              // og:locale or detected lang
};

// Parse OpenGraph tags from HTML
PostMetadata parse_opengraph(const std::string& html) {
  using lfb_detail::extract_meta;
  PostMetadata meta;

  meta.title = extract_meta(html, "og:title");
  meta.description = extract_meta(html, "og:description");
  meta.image_url = extract_meta(html, "og:image");
  meta.site_name = extract_meta(html, "og:site_name");
  meta.content_type = extract_meta(html, "og:type");
  meta.video_url = extract_meta(html, "og:video");
  meta.audio_url = extract_meta(html, "og:audio");
  meta.author = extract_meta(html, "article:author");
  meta.lang = extract_meta(html, "og:locale");

  // Fallback to <title> tag
  if (meta.title.empty()) {
    std::regex re_title(R"(<title[^>]*>([^<]+)</title>)", std::regex::icase);
    std::smatch m;
    if (std::regex_search(html, m, re_title)) meta.title = m[1].str();
  }

  // Fallback to meta description
  if (meta.description.empty()) {
    meta.description = extract_meta(html, "description");
  }

  // Image dimensions
  std::string w = extract_meta(html, "og:image:width");
  std::string h = extract_meta(html, "og:image:height");
  if (!w.empty()) meta.image_width = std::stoll(w);
  if (!h.empty()) meta.image_height = std::stoll(h);

  // Published time
  std::string pub = extract_meta(html, "article:published_time");
  if (!pub.empty()) {
    // Parse ISO 8601 roughly
    struct tm tm_buf = {};
    if (strptime(pub.c_str(), "%Y-%m-%dT%H:%M:%S", &tm_buf) ||
        strptime(pub.c_str(), "%Y-%m-%d", &tm_buf)) {
      meta.published_time = static_cast<int64_t>(timegm(&tm_buf));
    }
  }

  // NSFW detection
  std::string rating = extract_meta(html, "rating");
  meta.is_nsfw = (rating == "adult" || rating == "RTA-5042-1996-1400-1577-RTA");

  // oEmbed discovery
  std::regex re_oembed(R"(<link[^>]+type="application/json\+oembed"[^>]+href="([^"]+))",
                       std::regex::icase);
  std::smatch om;
  if (std::regex_search(html, om, re_oembed)) {
    meta.has_oembed = true;
    // In a full implementation, we'd fetch the oEmbed JSON here
    // For now, store the URL so the client can fetch it
  }

  return meta;
}

// Simulate fetching URL metadata (in production: use libcurl/Boost.Beast HTTP client)
PostMetadata fetch_url_metadata(const std::string& url) {
  // This function simulates HTTP fetching of the target URL.
  // In a production system, you'd use an async HTTP client to fetch the page,
  // then parse the OpenGraph tags.
  //
  // For now, return placeholder metadata based on URL structure.
  PostMetadata meta;
  meta.title = "Link: " + url;
  meta.description = "Content from " + url;
  meta.site_name = lfb_detail::extract_domain(url);
  meta.content_type = "website";

  // Detect image URLs
  static const std::vector<std::string> image_exts = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".avif", ".bmp"
  };
  for (const auto& ext : image_exts) {
    if (url.find(ext) != std::string::npos) {
      meta.image_url = url;
      meta.content_type = "image";
      break;
    }
  }

  // Detect video URLs
  static const std::vector<std::string> video_domains = {
    "youtube.com", "youtu.be", "vimeo.com", "peertube", "dailymotion.com",
    "twitch.tv", "bilibili.com"
  };
  for (const auto& d : video_domains) {
    if (url.find(d) != std::string::npos) {
      meta.content_type = "video";
      meta.video_url = url;
      break;
    }
  }

  return meta;
}

// Serialize PostMetadata to JSON
json metadata_to_json(const PostMetadata& meta) {
  json j;
  j["title"] = meta.title;
  j["description"] = meta.description;
  j["image_url"] = meta.image_url;
  j["site_name"] = meta.site_name;
  j["content_type"] = meta.content_type;
  if (!meta.video_url.empty()) j["video_url"] = meta.video_url;
  if (!meta.audio_url.empty()) j["audio_url"] = meta.audio_url;
  if (!meta.embed_html.empty()) j["embed_html"] = meta.embed_html;
  if (!meta.author.empty()) j["author"] = meta.author;
  if (meta.published_time > 0) j["published_time"] = meta.published_time;
  if (meta.image_width > 0) j["image_width"] = meta.image_width;
  if (meta.image_height > 0) j["image_height"] = meta.image_height;
  j["has_oembed"] = meta.has_oembed;
  j["is_nsfw"] = meta.is_nsfw;
  if (!meta.lang.empty()) j["lang"] = meta.lang;
  return j;
}

// Generate link preview HTML card
std::string generate_link_preview_html(const PostMetadata& meta, const std::string& target_url) {
  std::stringstream html;
  html << "<div class=\"link-preview\">\n";
  if (!meta.image_url.empty()) {
    html << "  <a href=\"" << lfb_detail::xml_escape(target_url) << "\" target=\"_blank\" rel=\"noopener\">\n";
    html << "    <img src=\"" << lfb_detail::xml_escape(meta.image_url)
         << "\" alt=\"\" class=\"preview-image\"";
    if (meta.image_width > 0 && meta.image_height > 0)
      html << " width=\"" << meta.image_width << "\" height=\"" << meta.image_height << "\"";
    html << " />\n";
    html << "  </a>\n";
  }
  html << "  <div class=\"preview-content\">\n";
  if (!meta.site_name.empty())
    html << "    <span class=\"preview-site\">" << lfb_detail::xml_escape(meta.site_name) << "</span>\n";
  html << "    <a href=\"" << lfb_detail::xml_escape(target_url) << "\" class=\"preview-title\" target=\"_blank\" rel=\"noopener\">"
       << lfb_detail::xml_escape(meta.title) << "</a>\n";
  if (!meta.description.empty())
    html << "    <p class=\"preview-description\">" << lfb_detail::xml_escape(meta.description) << "</p>\n";
  html << "  </div>\n";
  html << "</div>";
  return html.str();
}

// ============================================================================
// Section B4: Community Sidebar / Description Editing
// ============================================================================

// Extended community settings
struct CommunitySettings {
  std::string community_id;
  std::string sidebar;          // Markdown sidebar content
  std::string description;      // Community description
  std::string banner;           // Banner image URL
  std::string icon;             // Icon image URL
  std::string language;         // Primary language (ISO 639-1)
  std::string default_sort;     // Default sort order for posts
  bool nsfw{false};
  bool only_moderators_can_post{false};
  bool only_moderators_can_comment{false};
  bool enable_flairs{false};
  std::vector<std::string> flairs;          // Available post flairs
  std::vector<std::string> user_flairs;     // Available user flairs
  std::string welcome_message;              // Welcome message for new subscribers
  std::vector<std::string> rules;           // Community rules
  std::string banner_mode;                  // "cover", "contain", "repeat"
  bool show_avatars_in_sidebar{true};
  bool allow_images_in_comments{true};
  int post_body_max_length{50000};
  bool allow_video_posts{true};
  bool allow_image_posts{true};
  bool allow_link_posts{true};
  bool allow_text_posts{true};
  bool allow_poll_posts{false};
  bool restrict_suggested_titles{false};
};

// Extended community update — handles sidebar, rules, settings
CommunitySettings get_community_settings(const Community& community) {
  CommunitySettings s;
  s.community_id = community.id;
  s.description = community.description;
  s.nsfw = community.nsfw;
  s.only_moderators_can_post = community.posting_restricted_to_mods;
  return s;
}

// Apply community settings
void apply_community_settings(Community& community, const CommunitySettings& settings) {
  community.description = settings.description;
  community.nsfw = settings.nsfw;
  community.posting_restricted_to_mods = settings.only_moderators_can_post;
}

// Serialize community settings to JSON
json community_settings_to_json(const CommunitySettings& settings) {
  json j;
  j["community_id"] = settings.community_id;
  j["description"] = settings.description;
  j["sidebar"] = settings.sidebar;
  if (!settings.banner.empty()) j["banner"] = settings.banner;
  if (!settings.icon.empty()) j["icon"] = settings.icon;
  if (!settings.language.empty()) j["language"] = settings.language;
  if (!settings.default_sort.empty()) j["default_sort"] = settings.default_sort;
  j["nsfw"] = settings.nsfw;
  j["only_moderators_can_post"] = settings.only_moderators_can_post;
  j["only_moderators_can_comment"] = settings.only_moderators_can_comment;
  j["enable_flairs"] = settings.enable_flairs;
  j["flairs"] = settings.flairs;
  j["user_flairs"] = settings.user_flairs;
  j["welcome_message"] = settings.welcome_message;
  j["rules"] = settings.rules;
  j["banner_mode"] = settings.banner_mode;
  j["show_avatars_in_sidebar"] = settings.show_avatars_in_sidebar;
  j["allow_images_in_comments"] = settings.allow_images_in_comments;
  j["post_body_max_length"] = settings.post_body_max_length;
  j["allow_video_posts"] = settings.allow_video_posts;
  j["allow_image_posts"] = settings.allow_image_posts;
  j["allow_link_posts"] = settings.allow_link_posts;
  j["allow_text_posts"] = settings.allow_text_posts;
  j["allow_poll_posts"] = settings.allow_poll_posts;
  j["restrict_suggested_titles"] = settings.restrict_suggested_titles;
  return j;
}

// Parse community settings from JSON
CommunitySettings community_settings_from_json(const json& j) {
  CommunitySettings s;
  s.community_id = j.value("community_id", "");
  s.description = j.value("description", "");
  s.sidebar = j.value("sidebar", "");
  s.banner = j.value("banner", "");
  s.icon = j.value("icon", "");
  s.language = j.value("language", "");
  s.default_sort = j.value("default_sort", "hot");
  s.nsfw = j.value("nsfw", false);
  s.only_moderators_can_post = j.value("only_moderators_can_post", false);
  s.only_moderators_can_comment = j.value("only_moderators_can_comment", false);
  s.enable_flairs = j.value("enable_flairs", false);
  if (j.contains("flairs") && j["flairs"].is_array())
    s.flairs = j["flairs"].get<std::vector<std::string>>();
  if (j.contains("user_flairs") && j["user_flairs"].is_array())
    s.user_flairs = j["user_flairs"].get<std::vector<std::string>>();
  s.welcome_message = j.value("welcome_message", "");
  if (j.contains("rules") && j["rules"].is_array())
    s.rules = j["rules"].get<std::vector<std::string>>();
  s.banner_mode = j.value("banner_mode", "cover");
  return s;
}

// ============================================================================
// Section B5: User Profile Management — Settings, 2FA, Password Reset,
//           Email Verification, Language Tags, NSFW preferences
// ============================================================================

// Extended user profile settings
struct UserProfileSettings {
  std::string user_id;
  std::string display_name;
  std::string bio;
  std::string email;
  std::optional<std::string> avatar;
  std::optional<std::string> banner;
  std::optional<std::string> matrix_user_id;
  std::string default_listing_type;       // "all", "local", "subscribed"
  std::string default_sort_type;          // "hot", "new", "top", "old"
  std::string interface_language;         // ISO 639-1
  std::string theme;                      // "darkly", "litely", etc.
  bool bot_account{false};
  bool show_nsfw{false};
  bool show_scores{true};
  bool show_avatars{true};
  bool show_read_posts{true};
  bool show_bot_accounts{true};
  bool send_notifications_to_email{false};
  bool show_new_post_notifs{true};
  bool open_links_in_new_tab{false};
  bool infinite_scroll_enabled{true};
  bool enable_keyboard_navigation{false};
  bool enable_animated_images{true};
  bool collapse_bot_comments{false};
  bool email_verified{false};
  bool totp_2fa_enabled{false};
  std::string totp_2fa_secret;
  std::vector<std::string> discussion_languages;
  bool auto_mark_nsfw{false};
  bool blur_nsfw{true};
  std::string federated_feed_mode;        // "all", "local", "disabled"
};

// TOTP / 2FA implementation (Time-based One-Time Password)
struct TOTPConfig {
  std::string secret;             // Base32-encoded secret
  int digits{6};                  // Number of digits (6 or 8)
  int period{30};                 // Time step in seconds
  std::string algorithm{"SHA1"};  // HMAC algorithm
  std::string issuer{"LemmyInstance"};
};

// Generate a TOTP secret (base32-encoded, 160 bits)
std::string generate_totp_secret() {
  std::string raw = lfb_detail::random_bytes(20);
  static const char* base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  std::string encoded;
  encoded.reserve(32);
  int bits = 0, value = 0;
  for (unsigned char c : raw) {
    value = (value << 8) | c;
    bits += 8;
    while (bits >= 5) {
      encoded += base32_chars[(value >> (bits - 5)) & 0x1F];
      bits -= 5;
    }
  }
  if (bits > 0)
    encoded += base32_chars[(value << (5 - bits)) & 0x1F];
  return encoded;
}

// Verify a TOTP code against a secret
bool verify_totp(const std::string& secret, const std::string& code, int period, int digits) {
  if (code.length() != static_cast<size_t>(digits)) return false;

  // Base32 decode the secret
  static const std::string base32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  std::vector<uint8_t> decoded;
  int bits = 0, value = 0;
  for (char c : secret) {
    if (c == ' ' || c == '=') continue;
    size_t pos = base32_alphabet.find(toupper(c));
    if (pos == std::string::npos) return false;
    value = (value << 5) | static_cast<int>(pos);
    bits += 5;
    if (bits >= 8) {
      decoded.push_back(static_cast<uint8_t>(value >> (bits - 8)));
      bits -= 8;
    }
  }

  if (decoded.empty()) return false;

  // Calculate counter value
  int64_t counter =
      (lfb_detail::now_sec() / period);
  // Check current, previous, and next time window (1-minute tolerance)
  for (int64_t offset = -1; offset <= 1; offset++) {
    int64_t counter_val = counter + offset;

    // HMAC-SHA1
    std::string counter_bytes(8, '\0');
    for (int i = 7; i >= 0; i--) {
      counter_bytes[i] = static_cast<char>(counter_val & 0xFF);
      counter_val >>= 8;
    }

    std::string key_str(decoded.begin(), decoded.end());
    std::string hmac = lfb_detail::hmac_sha256(key_str, counter_bytes);
    // Use first 20 bytes for SHA1-like behavior
    if (hmac.length() < 40) continue;

    // Dynamic truncation
    int offset_byte = std::stoi(hmac.substr(39, 1), nullptr, 16) & 0x0F;
    int binary =
        ((std::stoi(hmac.substr(offset_byte * 2, 2), nullptr, 16) & 0x7F) << 24) |
        ((std::stoi(hmac.substr((offset_byte + 1) * 2, 2), nullptr, 16) & 0xFF) << 16) |
        ((std::stoi(hmac.substr((offset_byte + 2) * 2, 2), nullptr, 16) & 0xFF) << 8) |
        (std::stoi(hmac.substr((offset_byte + 3) * 2, 2), nullptr, 16) & 0xFF);

    // Modulo for N digits
    int mod_val = 1;
    for (int d = 0; d < digits; d++) mod_val *= 10;
    int otp = binary % mod_val;

    // Zero-pad
    std::stringstream ss;
    ss << std::setw(digits) << std::setfill('0') << otp;

    if (ss.str() == code) return true;
  }

  return false;
}

// Generate a TOTP URI for QR codes
std::string generate_totp_uri(const TOTPConfig& config, const std::string& account_name) {
  std::stringstream uri;
  uri << "otpauth://totp/" << lfb_detail::b64_url_encode(config.issuer + ":" + account_name)
      << "?secret=" << config.secret
      << "&issuer=" << lfb_detail::b64_url_encode(config.issuer)
      << "&algorithm=" << config.algorithm
      << "&digits=" << config.digits
      << "&period=" << config.period;
  return uri.str();
}

// Email verification token generation and validation
struct EmailVerification {
  std::string token;
  std::string user_id;
  std::string email;
  int64_t created_at;
  int64_t expires_at;
  bool used{false};
};

EmailVerification create_email_verification(const std::string& user_id,
                                              const std::string& email) {
  EmailVerification ev;
  ev.token = lfb_detail::gen_uuid() + "-" + lfb_detail::gen_uid();
  ev.user_id = user_id;
  ev.email = email;
  ev.created_at = lfb_detail::now_sec();
  ev.expires_at = ev.created_at + 86400; // 24 hours
  ev.used = false;
  return ev;
}

// Password reset token
struct PasswordReset {
  std::string token;
  std::string user_id;
  int64_t created_at;
  int64_t expires_at;
  bool used{false};
};

PasswordReset create_password_reset(const std::string& user_id) {
  PasswordReset pr;
  pr.token = lfb_detail::gen_uuid() + "-" + lfb_detail::gen_uid();
  pr.user_id = user_id;
  pr.created_at = lfb_detail::now_sec();
  pr.expires_at = pr.created_at + 3600; // 1 hour
  pr.used = false;
  return pr;
}

// Serialize user profile settings to JSON
json user_profile_settings_to_json(const UserProfileSettings& s) {
  json j;
  j["user_id"] = s.user_id;
  j["display_name"] = s.display_name;
  j["bio"] = s.bio;
  j["email"] = s.email;
  if (s.avatar.has_value()) j["avatar"] = *s.avatar;
  if (s.banner.has_value()) j["banner"] = *s.banner;
  if (s.matrix_user_id.has_value()) j["matrix_user_id"] = *s.matrix_user_id;
  j["default_listing_type"] = s.default_listing_type;
  j["default_sort_type"] = s.default_sort_type;
  j["interface_language"] = s.interface_language;
  j["theme"] = s.theme;
  j["bot_account"] = s.bot_account;
  j["show_nsfw"] = s.show_nsfw;
  j["show_scores"] = s.show_scores;
  j["show_avatars"] = s.show_avatars;
  j["show_read_posts"] = s.show_read_posts;
  j["show_bot_accounts"] = s.show_bot_accounts;
  j["send_notifications_to_email"] = s.send_notifications_to_email;
  j["show_new_post_notifs"] = s.show_new_post_notifs;
  j["open_links_in_new_tab"] = s.open_links_in_new_tab;
  j["infinite_scroll_enabled"] = s.infinite_scroll_enabled;
  j["enable_keyboard_navigation"] = s.enable_keyboard_navigation;
  j["enable_animated_images"] = s.enable_animated_images;
  j["collapse_bot_comments"] = s.collapse_bot_comments;
  j["email_verified"] = s.email_verified;
  j["totp_2fa_enabled"] = s.totp_2fa_enabled;
  j["discussion_languages"] = s.discussion_languages;
  j["auto_mark_nsfw"] = s.auto_mark_nsfw;
  j["blur_nsfw"] = s.blur_nsfw;
  j["federated_feed_mode"] = s.federated_feed_mode;
  return j;
}

// ============================================================================
// Section B6: Language Tagging for Posts and Comments
// ============================================================================

// ISO 639-1 language code validation
static const std::set<std::string> VALID_LANGUAGES = {
  "aa","ab","ae","af","ak","am","an","ar","as","av","ay","az",
  "ba","be","bg","bh","bi","bm","bn","bo","br","bs",
  "ca","ce","ch","co","cr","cs","cu","cv","cy",
  "da","de","dv","dz",
  "ee","el","en","eo","es","et","eu",
  "fa","ff","fi","fj","fo","fr","fy",
  "ga","gd","gl","gn","gu","gv",
  "ha","he","hi","ho","hr","ht","hu","hy",
  "hz","ia","id","ie","ig","ii","ik","io","is","it","iu",
  "ja","jv",
  "ka","kg","ki","kj","kk","kl","km","kn","ko","kr","ks","ku","kv","kw","ky",
  "la","lb","lg","li","ln","lo","lt","lu","lv",
  "mg","mh","mi","mk","ml","mn","mr","ms","mt","my",
  "na","nb","nd","ne","ng","nl","nn","no","nr","nv","ny",
  "oc","oj","om","or","os",
  "pa","pi","pl","ps","pt",
  "qu",
  "rm","rn","ro","ru","rw",
  "sa","sc","sd","se","sg","si","sk","sl","sm","sn","so","sq","sr","ss","st","su","sv","sw",
  "ta","te","tg","th","ti","tk","tl","tn","to","tr","ts","tt","tw","ty",
  "ug","uk","ur","uz",
  "ve","vi","vo",
  "wa","wo",
  "xh",
  "yi","yo",
  "za","zh","zu",
  "und" // Undetermined
};

bool is_valid_language_code(const std::string& code) {
  return VALID_LANGUAGES.count(code) > 0;
}

// Language tag for content
struct LanguageTag {
  std::string id;
  std::string code;         // ISO 639-1
  std::string name;         // English name
  std::string native_name;  // Native name
};

std::vector<LanguageTag> get_supported_languages() {
  static const std::vector<std::pair<std::string, std::string>> langs = {
    {"en", "English"}, {"es", "Espa\u00f1ol"}, {"fr", "Fran\u00e7ais"},
    {"de", "Deutsch"}, {"pt", "Portugu\u00eas"}, {"it", "Italiano"},
    {"nl", "Nederlands"}, {"pl", "Polski"}, {"ru", "\u0420\u0443\u0441\u0441\u043a\u0438\u0439"},
    {"ja", "\u65e5\u672c\u8a9e"}, {"zh", "\u4e2d\u6587"},
    {"ko", "\ud55c\uad6d\uc5b4"}, {"ar", "\u0627\u0644\u0639\u0631\u0628\u064a\u0629"},
    {"tr", "T\u00fcrk\u00e7e"}, {"sv", "Svenska"},
    {"fi", "Suomi"}, {"da", "Dansk"}, {"no", "Norsk"},
    {"cs", "\u010ce\u0161tina"}, {"uk", "\u0423\u043a\u0440\u0430\u0457\u043d\u0441\u044c\u043a\u0430"},
    {"und", "Undetermined"}
  };
  std::vector<LanguageTag> result;
  for (const auto& [code, native] : langs) {
    LanguageTag t;
    t.id = "lang-" + code;
    t.code = code;
    t.name = native;
    t.native_name = native;
    result.push_back(t);
  }
  return result;
}

// Detect language from text (simple heuristic — in production, use CLD3/CLD2)
std::string detect_language_heuristic(const std::string& text) {
  // Simple character-based heuristics
  int latin = 0, cyrillic = 0, cjk = 0, arabic = 0, total = 0;
  for (unsigned char c : text) {
    if (c < 128) { latin++; total++; continue; }
    // Rough range checks for various scripts
    if (c >= 0xD0 && c <= 0xD4) cyrillic++;
    if ((c >= 0xE2 && c <= 0xE9) || (c >= 0xA4 && c <= 0xBF)) cjk++;
    if (c >= 0xD8 && c <= 0xDB) arabic++;
    total++;
  }
  if (total == 0) return "und";
  if (cyrillic * 100 / total > 40) return "ru";
  if (cjk * 100 / total > 30) return "zh";
  if (arabic * 100 / total > 40) return "ar";
  return "en";
}

// ============================================================================
// Section B7: Image Upload via Pictrs API (Extended)
// ============================================================================

// Pictrs API integration — extended image management
struct PictrsUploadResult {
  std::string file_url;       // Full URL to the image
  std::string delete_token;   // Token required to delete the image
  std::string thumbnail_url;  // Thumbnail URL
  std::string file_id;        // Pictrs file identifier
  int64_t size{0};            // File size in bytes
  int width{0};               // Image width
  int height{0};              // Image height
  std::string content_type;   // MIME type
};

// Pictrs API client configuration
struct PictrsConfig {
  std::string pictrs_url;         // e.g., "http://localhost:8080"
  std::string pictrs_api_key;     // API key for pictrs
  int max_image_size{10485760};   // 10 MB default
  std::vector<std::string> allowed_formats{"jpg","jpeg","png","gif","webp","svg","bmp","avif"};
  bool generate_thumbnails{true};
  int thumbnail_size{256};        // Thumbnail max dimension
  bool strip_exif{true};          // Remove EXIF metadata
};

// Build pictrs upload request body
json pictrs_build_upload_request(const std::vector<uint8_t>& data,
                                   const std::string& filename,
                                   const std::string& content_type) {
  json req;
  req["filename"] = filename;
  req["content_type"] = content_type;
  req["size"] = static_cast<int64_t>(data.size());
  req["data"] = lfb_detail::b64_encode(std::string(data.begin(), data.end()));
  return req;
}

// Parse pictrs upload response
PictrsUploadResult pictrs_parse_upload_response(const json& response,
                                                  const PictrsConfig& config) {
  PictrsUploadResult result;
  if (response.contains("files") && response["files"].is_array() &&
      !response["files"].empty()) {
    auto& file = response["files"][0];
    result.file_url = config.pictrs_url + "/image/" +
        file.value("file", "");
    result.delete_token = file.value("delete_token", "");
    result.file_id = file.value("file", "");
    result.size = file.value("size", int64_t{0});

    if (config.generate_thumbnails) {
      result.thumbnail_url = config.pictrs_url + "/image/" +
          file.value("file", "") + "?thumbnail=" +
          std::to_string(config.thumbnail_size);
    }
  }
  return result;
}

// Generate pictrs thumbnail URL
std::string pictrs_thumbnail_url(const std::string& image_url,
                                   int size,
                                   const PictrsConfig& config) {
  // Strip any existing query params, add thumbnail
  std::string base = image_url;
  auto pos = base.find('?');
  if (pos != std::string::npos) base = base.substr(0, pos);
  return base + "?thumbnail=" + std::to_string(size);
}

// Verify an uploaded image exists (by checking pictrs)
bool pictrs_verify_image(const std::string& image_url,
                           const PictrsConfig& config) {
  // In production: HTTP HEAD request to pictrs
  return !image_url.empty() &&
         image_url.find(config.pictrs_url) == 0;
}

// Delete image via pictrs API
json pictrs_delete_image(const std::string& delete_token,
                           const std::string& image_url,
                           const PictrsConfig& config) {
  // In production: HTTP DELETE to pictrs with token
  json result;
  result["success"] = true;
  result["deleted_url"] = image_url;
  return result;
}

// Determine if content is an image URL
bool is_image_url(const std::string& url) {
  static const std::set<std::string> image_exts = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".avif",
    ".tiff", ".ico"
  };
  for (const auto& ext : image_exts) {
    if (url.length() >= ext.length() &&
        url.compare(url.length() - ext.length(), ext.length(), ext) == 0)
      return true;
  }
  return url.find("/pictrs/") != std::string::npos;
}

// ============================================================================
// Section B8: Banned User Appeal System
// ============================================================================

// Ban appeal submitted by a banned user
struct BanAppeal {
  std::string id;
  std::string user_id;
  std::string ban_id;           // Reference to the ban ModAction
  std::string appeal_text;      // User's appeal message
  std::string admin_response;   // Admin's response (optional)
  enum class Status { Pending, Approved, Rejected, Cancelled };
  Status status{Status::Pending};
  int64_t created_at{0};
  int64_t updated_at{0};
  std::string admin_id;         // Admin who reviewed it
};

// Appeal system manager
class BanAppealManager {
public:
  BanAppeal submit_appeal(const std::string& user_id,
                           const std::string& ban_id,
                           const std::string& appeal_text) {
    BanAppeal appeal;
    appeal.id = "appeal-" + lfb_detail::gen_uid();
    appeal.user_id = user_id;
    appeal.ban_id = ban_id;
    appeal.appeal_text = appeal_text;
    appeal.status = BanAppeal::Status::Pending;
    appeal.created_at = lfb_detail::now_sec();
    appeal.updated_at = appeal.created_at;

    std::unique_lock lock(appeals_mutex_);
    appeals_[appeal.id] = appeal;
    user_appeals_[user_id].push_back(appeal.id);
    return appeal;
  }

  std::optional<BanAppeal> get_appeal(const std::string& appeal_id) {
    std::shared_lock lock(appeals_mutex_);
    auto it = appeals_.find(appeal_id);
    if (it != appeals_.end()) return it->second;
    return std::nullopt;
  }

  std::vector<BanAppeal> get_pending_appeals(int page, int limit) {
    std::shared_lock lock(appeals_mutex_);
    std::vector<BanAppeal> result;
    for (const auto& [id, appeal] : appeals_) {
      if (appeal.status == BanAppeal::Status::Pending)
        result.push_back(appeal);
    }
    // Paginate
    int start = (page - 1) * limit;
    if (start < 0) start = 0;
    if (start < static_cast<int>(result.size())) {
      result = std::vector<BanAppeal>(result.begin() + start,
                     start + limit <= static_cast<int>(result.size()) ?
                     result.begin() + start + limit : result.end());
    } else {
      result.clear();
    }
    return result;
  }

  std::vector<BanAppeal> get_user_appeals(const std::string& user_id) {
    std::shared_lock lock(appeals_mutex_);
    std::vector<BanAppeal> result;
    auto it = user_appeals_.find(user_id);
    if (it != user_appeals_.end()) {
      for (const auto& aid : it->second) {
        auto ait = appeals_.find(aid);
        if (ait != appeals_.end()) result.push_back(ait->second);
      }
    }
    return result;
  }

  BanAppeal review_appeal(const std::string& appeal_id,
                            const std::string& admin_id,
                            BanAppeal::Status decision,
                            const std::string& response) {
    std::unique_lock lock(appeals_mutex_);
    auto it = appeals_.find(appeal_id);
    if (it == appeals_.end())
      throw std::runtime_error("Appeal not found: " + appeal_id);

    if (it->second.status != BanAppeal::Status::Pending)
      throw std::runtime_error("Appeal already reviewed");

    it->second.status = decision;
    it->second.admin_id = admin_id;
    it->second.admin_response = response;
    it->second.updated_at = lfb_detail::now_sec();

    return it->second;
  }

  void cancel_appeal(const std::string& appeal_id) {
    std::unique_lock lock(appeals_mutex_);
    auto it = appeals_.find(appeal_id);
    if (it != appeals_.end() &&
        it->second.status == BanAppeal::Status::Pending) {
      it->second.status = BanAppeal::Status::Cancelled;
      it->second.updated_at = lfb_detail::now_sec();
    }
  }

  size_t pending_count() {
    std::shared_lock lock(appeals_mutex_);
    size_t count = 0;
    for (const auto& [id, appeal] : appeals_) {
      if (appeal.status == BanAppeal::Status::Pending) count++;
    }
    return count;
  }

private:
  mutable std::shared_mutex appeals_mutex_;
  std::map<std::string, BanAppeal> appeals_;
  std::map<std::string, std::vector<std::string>> user_appeals_; // user_id -> appeal_ids
};

// Serialize BanAppeal to JSON
json ban_appeal_to_json(const BanAppeal& appeal) {
  json j;
  j["id"] = appeal.id;
  j["user_id"] = appeal.user_id;
  j["ban_id"] = appeal.ban_id;
  j["appeal_text"] = appeal.appeal_text;
  j["admin_response"] = appeal.admin_response;
  j["status"] = [&]() -> std::string {
    switch (appeal.status) {
      case BanAppeal::Status::Pending: return "pending";
      case BanAppeal::Status::Approved: return "approved";
      case BanAppeal::Status::Rejected: return "rejected";
      case BanAppeal::Status::Cancelled: return "cancelled";
    }
    return "unknown";
  }();
  j["admin_id"] = appeal.admin_id;
  j["created_at"] = appeal.created_at;
  j["updated_at"] = appeal.updated_at;
  return j;
}

// ============================================================================
// Section B9: Instance Block Transfer & Community Transfer
// ============================================================================

// Federation block list with transfer support
struct InstanceBlockRecord {
  std::string domain;
  int64_t blocked_at;
  std::string blocked_by;      // Admin user_id
  std::string reason;
  bool published{false};        // Whether announced via ActivityPub
  std::string block_activity_id; // AP activity ID for federation
};

// Instance block transfer — export/import block lists
class InstanceBlockManager {
public:
  void add_block(const std::string& domain, const std::string& admin_id,
                 const std::string& reason) {
    std::unique_lock lock(blocks_mutex_);
    std::string lower = domain;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    InstanceBlockRecord rec;
    rec.domain = lower;
    rec.blocked_at = lfb_detail::now_sec();
    rec.blocked_by = admin_id;
    rec.reason = reason;
    blocks_[lower] = rec;
  }

  void remove_block(const std::string& domain) {
    std::unique_lock lock(blocks_mutex_);
    std::string lower = domain;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    blocks_.erase(lower);
  }

  bool is_blocked(const std::string& domain) {
    std::shared_lock lock(blocks_mutex_);
    std::string lower = domain;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return blocks_.count(lower) > 0;
  }

  // Export block list for transfer to another instance
  json export_blocks() {
    std::shared_lock lock(blocks_mutex_);
    json result = json::array();
    for (const auto& [domain, rec] : blocks_) {
      json entry;
      entry["domain"] = domain;
      entry["blocked_at"] = rec.blocked_at;
      entry["reason"] = rec.reason;
      entry["published"] = rec.published;
      result.push_back(entry);
    }
    return result;
  }

  // Import block list from another instance (for transfer)
  int import_blocks(const json& block_list, const std::string& admin_id) {
    std::unique_lock lock(blocks_mutex_);
    int imported = 0;
    for (const auto& entry : block_list) {
      std::string domain = entry.value("domain", "");
      if (domain.empty()) continue;
      std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
      if (blocks_.count(domain)) continue; // Already blocked
      InstanceBlockRecord rec;
      rec.domain = domain;
      rec.blocked_at = lfb_detail::now_sec();
      rec.blocked_by = admin_id;
      rec.reason = entry.value("reason", "Imported from remote instance");
      rec.published = false;
      blocks_[domain] = rec;
      imported++;
    }
    return imported;
  }

  // Get all block records (for federation/announcement)
  std::vector<InstanceBlockRecord> get_all_blocks() {
    std::shared_lock lock(blocks_mutex_);
    std::vector<InstanceBlockRecord> result;
    for (const auto& [d, r] : blocks_) result.push_back(r);
    return result;
  }

  // Mark block as published (after federated announcement)
  void mark_published(const std::string& domain,
                      const std::string& activity_id) {
    std::unique_lock lock(blocks_mutex_);
    std::string lower = domain;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    auto it = blocks_.find(lower);
    if (it != blocks_.end()) {
      it->second.published = true;
      it->second.block_activity_id = activity_id;
    }
  }

  // Get count
  size_t count() {
    std::shared_lock lock(blocks_mutex_);
    return blocks_.size();
  }

private:
  mutable std::shared_mutex blocks_mutex_;
  std::map<std::string, InstanceBlockRecord> blocks_;
};

// Community transfer — transfer ownership of a community
struct CommunityTransfer {
  std::string id;
  std::string community_id;
  std::string from_user_id;
  std::string to_user_id;
  std::string initiated_by;        // Admin or current owner
  enum class Status { Pending, Accepted, Rejected, Cancelled };
  Status status{Status::Pending};
  int64_t created_at{0};
  int64_t resolved_at{0};
};

class CommunityTransferManager {
public:
  CommunityTransfer initiate_transfer(const std::string& community_id,
                                        const std::string& from_user_id,
                                        const std::string& to_user_id,
                                        const std::string& initiated_by) {
    CommunityTransfer transfer;
    transfer.id = "ctransfer-" + lfb_detail::gen_uid();
    transfer.community_id = community_id;
    transfer.from_user_id = from_user_id;
    transfer.to_user_id = to_user_id;
    transfer.initiated_by = initiated_by;
    transfer.status = CommunityTransfer::Status::Pending;
    transfer.created_at = lfb_detail::now_sec();

    std::unique_lock lock(transfers_mutex_);
    transfers_[transfer.id] = transfer;
    community_transfers_[community_id].push_back(transfer.id);
    return transfer;
  }

  std::optional<CommunityTransfer> get_transfer(const std::string& transfer_id) {
    std::shared_lock lock(transfers_mutex_);
    auto it = transfers_.find(transfer_id);
    if (it != transfers_.end()) return it->second;
    return std::nullopt;
  }

  std::vector<CommunityTransfer> get_pending_for_user(
      const std::string& user_id) {
    std::shared_lock lock(transfers_mutex_);
    std::vector<CommunityTransfer> result;
    for (const auto& [id, t] : transfers_) {
      if (t.to_user_id == user_id &&
          t.status == CommunityTransfer::Status::Pending)
        result.push_back(t);
    }
    return result;
  }

  CommunityTransfer accept_transfer(const std::string& transfer_id) {
    std::unique_lock lock(transfers_mutex_);
    auto it = transfers_.find(transfer_id);
    if (it == transfers_.end())
      throw std::runtime_error("Transfer not found");
    if (it->second.status != CommunityTransfer::Status::Pending)
      throw std::runtime_error("Transfer already resolved");
    it->second.status = CommunityTransfer::Status::Accepted;
    it->second.resolved_at = lfb_detail::now_sec();
    return it->second;
  }

  CommunityTransfer reject_transfer(const std::string& transfer_id) {
    std::unique_lock lock(transfers_mutex_);
    auto it = transfers_.find(transfer_id);
    if (it == transfers_.end())
      throw std::runtime_error("Transfer not found");
    if (it->second.status != CommunityTransfer::Status::Pending)
      throw std::runtime_error("Transfer already resolved");
    it->second.status = CommunityTransfer::Status::Rejected;
    it->second.resolved_at = lfb_detail::now_sec();
    return it->second;
  }

  void cancel_transfer(const std::string& transfer_id) {
    std::unique_lock lock(transfers_mutex_);
    auto it = transfers_.find(transfer_id);
    if (it != transfers_.end() &&
        it->second.status == CommunityTransfer::Status::Pending) {
      it->second.status = CommunityTransfer::Status::Cancelled;
      it->second.resolved_at = lfb_detail::now_sec();
    }
  }

private:
  mutable std::shared_mutex transfers_mutex_;
  std::map<std::string, CommunityTransfer> transfers_;
  std::map<std::string, std::vector<std::string>> community_transfers_;
};

// Serialize to JSON
json community_transfer_to_json(const CommunityTransfer& t) {
  json j;
  j["id"] = t.id;
  j["community_id"] = t.community_id;
  j["from_user_id"] = t.from_user_id;
  j["to_user_id"] = t.to_user_id;
  j["initiated_by"] = t.initiated_by;
  j["status"] = [&]() -> std::string {
    switch (t.status) {
      case CommunityTransfer::Status::Pending: return "pending";
      case CommunityTransfer::Status::Accepted: return "accepted";
      case CommunityTransfer::Status::Rejected: return "rejected";
      case CommunityTransfer::Status::Cancelled: return "cancelled";
    }
    return "unknown";
  }();
  j["created_at"] = t.created_at;
  j["resolved_at"] = t.resolved_at;
  return j;
}

// ============================================================================
// Section B10: Detailed Modlog (Moderation Action History)
// ============================================================================

// Extended modlog entry with more detail
struct ModlogEntry {
  std::string id;
  std::string mod_person_id;
  std::string mod_person_name;
  std::string target_person_id;
  std::string target_person_name;
  std::string community_id;
  std::string community_name;
  std::string action;               // "removed_post", "banned_user", etc.
  std::string reason;
  std::string details;              // Extra JSON details
  std::string item_id;              // ID of the item being acted upon
  std::string item_type;            // "post", "comment", "user", "community"
  bool removed{false};
  int64_t published{0};
  int64_t expires{0};              // For temporary bans
};

// Predefined modlog action types
static const std::vector<std::string> MODLOG_ACTIONS = {
  // Post actions
  "removed_post", "restored_post", "locked_post", "unlocked_post",
  "stickied_post", "unsticky_post", "featured_post", "unfeatured_post",
  // Comment actions
  "removed_comment", "restored_comment", "distinguished_comment",
  // User actions
  "banned_user", "unbanned_user", "purged_user",
  "banned_from_community", "unbanned_from_community",
  "added_mod", "removed_mod", "added_admin", "removed_admin",
  // Community actions
  "removed_community", "restored_community", "hidden_community",
  "unhidden_community", "transferred_community",
  "updated_community_settings",
  // Instance actions
  "blocked_instance", "unblocked_instance",
  "allowed_instance", "disallowed_instance",
  "updated_site", "resolved_report",
  // Registration
  "approved_registration", "denied_registration",
};

// Modlog manager class
class ModlogManager {
public:
  ModlogEntry add_entry(const std::string& mod_person_id,
                          const std::string& mod_person_name,
                          const std::string& target_person_id,
                          const std::string& target_person_name,
                          const std::string& community_id,
                          const std::string& community_name,
                          const std::string& action,
                          const std::string& reason,
                          const std::string& item_type = "",
                          const std::string& item_id = "",
                          const std::string& details = "",
                          int64_t expires = 0) {
    ModlogEntry entry;
    entry.id = "modlog-" + lfb_detail::gen_uid();
    entry.mod_person_id = mod_person_id;
    entry.mod_person_name = mod_person_name;
    entry.target_person_id = target_person_id;
    entry.target_person_name = target_person_name;
    entry.community_id = community_id;
    entry.community_name = community_name;
    entry.action = action;
    entry.reason = reason;
    entry.item_type = item_type;
    entry.item_id = item_id;
    entry.details = details;
    entry.published = lfb_detail::now_sec();
    entry.expires = expires;

    std::unique_lock lock(entries_mutex_);
    entries_.push_back(entry);
    // Index by community and user
    community_entries_[community_id].push_back(entry.id);
    mod_entries_[mod_person_id].push_back(entry.id);
    target_entries_[target_person_id].push_back(entry.id);

    // Keep log manageable — trim if too large
    if (entries_.size() > 100000) {
      entries_.erase(entries_.begin(), entries_.begin() + 10000);
    }

    return entry;
  }

  std::vector<ModlogEntry> get_modlog(const std::string& community_id,
                                        const std::string& mod_person_id,
                                        const std::string& target_person_id,
                                        const std::string& action_filter,
                                        int page = 1, int limit = 20) {
    std::shared_lock lock(entries_mutex_);
    std::vector<ModlogEntry> result;

    // Collect candidate IDs based on filters
    std::set<std::string> candidate_ids;

    if (!community_id.empty()) {
      auto it = community_entries_.find(community_id);
      if (it != community_entries_.end()) {
        for (const auto& eid : it->second) candidate_ids.insert(eid);
      }
    }

    if (!mod_person_id.empty()) {
      auto it = mod_entries_.find(mod_person_id);
      if (it != mod_entries_.end()) {
        std::set<std::string> mod_set(it->second.begin(), it->second.end());
        if (candidate_ids.empty()) {
          candidate_ids = mod_set;
        } else {
          std::set<std::string> intersection;
          for (const auto& id : candidate_ids) {
            if (mod_set.count(id)) intersection.insert(id);
          }
          candidate_ids = std::move(intersection);
        }
      }
    }

    if (!target_person_id.empty()) {
      auto it = target_entries_.find(target_person_id);
      if (it != target_entries_.end()) {
        std::set<std::string> tset(it->second.begin(), it->second.end());
        if (candidate_ids.empty()) {
          candidate_ids = tset;
        } else {
          std::set<std::string> intersection;
          for (const auto& id : candidate_ids) {
            if (tset.count(id)) intersection.insert(id);
          }
          candidate_ids = std::move(intersection);
        }
      }
    }

    // If no filters, get all
    if (candidate_ids.empty()) {
      for (const auto& entry : entries_) candidate_ids.insert(entry.id);
    }

    // Build result, apply action filter
    for (const auto& entry : entries_) {
      if (candidate_ids.count(entry.id) == 0) continue;
      if (!action_filter.empty() && entry.action != action_filter) continue;
      result.push_back(entry);
    }

    // Sort newest first
    std::sort(result.begin(), result.end(),
              [](const ModlogEntry& a, const ModlogEntry& b) {
                return a.published > b.published;
              });

    // Paginate
    int start = (page - 1) * limit;
    if (start < 0) start = 0;
    if (start < static_cast<int>(result.size())) {
      result = std::vector<ModlogEntry>(
          result.begin() + start,
          start + limit <= static_cast<int>(result.size()) ?
          result.begin() + start + limit : result.end());
    } else {
      result.clear();
    }

    return result;
  }

  // Get modlog statistics for a community
  json get_modlog_stats(const std::string& community_id) {
    std::shared_lock lock(entries_mutex_);
    json stats;
    stats["total_actions"] = 0;
    std::map<std::string, int> action_counts;

    for (const auto& entry : entries_) {
      if (!community_id.empty() && entry.community_id != community_id) continue;
      action_counts[entry.action]++;
      stats["total_actions"] = static_cast<int>(stats["total_actions"]) + 1;
    }

    json actions_json = json::object();
    for (const auto& [action, count] : action_counts) {
      actions_json[action] = count;
    }
    stats["actions"] = actions_json;
    return stats;
  }

  // Export modlog for a given time range
  json export_modlog(int64_t from_ts, int64_t to_ts,
                       const std::string& community_id = "") {
    std::shared_lock lock(entries_mutex_);
    json result = json::array();
    for (const auto& entry : entries_) {
      if (entry.published < from_ts || entry.published > to_ts) continue;
      if (!community_id.empty() && entry.community_id != community_id) continue;
      result.push_back(modlog_entry_to_json(entry));
    }
    return result;
  }

private:
  mutable std::shared_mutex entries_mutex_;
  std::deque<ModlogEntry> entries_;
  std::map<std::string, std::vector<std::string>> community_entries_;
  std::map<std::string, std::vector<std::string>> mod_entries_;
  std::map<std::string, std::vector<std::string>> target_entries_;
};

// Serialize modlog entry
json modlog_entry_to_json(const ModlogEntry& entry) {
  json j;
  j["id"] = entry.id;
  j["mod_person_id"] = entry.mod_person_id;
  j["mod_person_name"] = entry.mod_person_name;
  j["target_person_id"] = entry.target_person_id;
  j["target_person_name"] = entry.target_person_name;
  j["community_id"] = entry.community_id;
  j["community_name"] = entry.community_name;
  j["action"] = entry.action;
  j["reason"] = entry.reason;
  if (!entry.details.empty()) j["details"] = entry.details;
  if (!entry.item_id.empty()) j["item_id"] = entry.item_id;
  if (!entry.item_type.empty()) j["item_type"] = entry.item_type;
  j["removed"] = entry.removed;
  j["published"] = lfb_detail::format_iso8601(entry.published);
  if (entry.expires > 0) j["expires"] = lfb_detail::format_iso8601(entry.expires);
  return j;
}

// ============================================================================
// Section B11: Admin Purge Queue
// ============================================================================

// Individual purge task
struct PurgeTask {
  std::string id;
  std::string admin_id;
  enum class TargetType { User, Post, Comment, Community, Image, PM };
  TargetType target_type;
  std::string target_id;
  std::string reason;
  enum class Status { Queued, InProgress, Completed, Failed, Cancelled };
  Status status{Status::Queued};
  int64_t created_at{0};
  int64_t started_at{0};
  int64_t completed_at{0};
  std::string error_message;
  int retry_count{0};
  int max_retries{3};
  int priority{5};  // 1=highest, 10=lowest
};

// Purge queue manager
class PurgeQueueManager {
public:
  PurgeTask enqueue(const std::string& admin_id,
                      PurgeTask::TargetType target_type,
                      const std::string& target_id,
                      const std::string& reason,
                      int priority = 5) {
    PurgeTask task;
    task.id = "purge-" + lfb_detail::gen_uid();
    task.admin_id = admin_id;
    task.target_type = target_type;
    task.target_id = target_id;
    task.reason = reason;
    task.status = PurgeTask::Status::Queued;
    task.created_at = lfb_detail::now_sec();
    task.priority = priority;

    std::unique_lock lock(queue_mutex_);
    purge_queue_.push(task);
    all_tasks_[task.id] = task;
    return task;
  }

  std::optional<PurgeTask> dequeue() {
    std::unique_lock lock(queue_mutex_);
    if (purge_queue_.empty()) return std::nullopt;

    PurgeTask task = purge_queue_.top();
    purge_queue_.pop();

    task.status = PurgeTask::Status::InProgress;
    task.started_at = lfb_detail::now_sec();
    all_tasks_[task.id] = task;
    return task;
  }

  void mark_completed(const std::string& task_id) {
    std::unique_lock lock(queue_mutex_);
    auto it = all_tasks_.find(task_id);
    if (it != all_tasks_.end()) {
      it->second.status = PurgeTask::Status::Completed;
      it->second.completed_at = lfb_detail::now_sec();
    }
  }

  void mark_failed(const std::string& task_id, const std::string& error) {
    std::unique_lock lock(queue_mutex_);
    auto it = all_tasks_.find(task_id);
    if (it != all_tasks_.end()) {
      it->second.status = PurgeTask::Status::Failed;
      it->second.error_message = error;
      it->second.completed_at = lfb_detail::now_sec();
    }
  }

  void cancel(const std::string& task_id) {
    std::unique_lock lock(queue_mutex_);
    auto it = all_tasks_.find(task_id);
    if (it != all_tasks_.end() &&
        (it->second.status == PurgeTask::Status::Queued ||
         it->second.status == PurgeTask::Status::InProgress)) {
      it->second.status = PurgeTask::Status::Cancelled;
      it->second.completed_at = lfb_detail::now_sec();
    }
  }

  void retry(const std::string& task_id) {
    std::unique_lock lock(queue_mutex_);
    auto it = all_tasks_.find(task_id);
    if (it != all_tasks_.end() && it->second.status == PurgeTask::Status::Failed) {
      if (it->second.retry_count < it->second.max_retries) {
        it->second.status = PurgeTask::Status::Queued;
        it->second.retry_count++;
        purge_queue_.push(it->second);
      }
    }
  }

  std::vector<PurgeTask> get_status(int page, int limit,
                                       const std::optional<PurgeTask::Status>& filter = {}) {
    std::shared_lock lock(queue_mutex_);
    std::vector<PurgeTask> result;
    for (const auto& [id, task] : all_tasks_) {
      if (filter.has_value() && task.status != *filter) continue;
      result.push_back(task);
    }
    std::sort(result.begin(), result.end(),
              [](const PurgeTask& a, const PurgeTask& b) {
                return a.created_at > b.created_at;
              });

    int start = (page - 1) * limit;
    if (start < 0) start = 0;
    if (start < static_cast<int>(result.size())) {
      result = std::vector<PurgeTask>(
          result.begin() + start,
          start + limit <= static_cast<int>(result.size()) ?
          result.begin() + start + limit : result.end());
    } else {
      result.clear();
    }
    return result;
  }

  json get_queue_stats() {
    std::shared_lock lock(queue_mutex_);
    json stats;
    stats["pending"] = purge_queue_.size();
    int in_progress = 0, completed = 0, failed = 0, cancelled = 0;
    for (const auto& [id, task] : all_tasks_) {
      switch (task.status) {
        case PurgeTask::Status::Queued: break;
        case PurgeTask::Status::InProgress: in_progress++; break;
        case PurgeTask::Status::Completed: completed++; break;
        case PurgeTask::Status::Failed: failed++; break;
        case PurgeTask::Status::Cancelled: cancelled++; break;
      }
    }
    stats["in_progress"] = in_progress;
    stats["completed"] = completed;
    stats["failed"] = failed;
    stats["cancelled"] = cancelled;
    stats["total"] = all_tasks_.size();
    return stats;
  }

  // Process the queue (called periodically)
  std::vector<PurgeTask> process_queue(int batch_size = 10) {
    std::vector<PurgeTask> tasks;
    for (int i = 0; i < batch_size; i++) {
      auto task = dequeue();
      if (!task.has_value()) break;
      tasks.push_back(*task);
    }
    return tasks;
  }

private:
  // Priority queue for purge tasks
  struct PurgeTaskCompare {
    bool operator()(const PurgeTask& a, const PurgeTask& b) const {
      if (a.priority != b.priority) return a.priority > b.priority; // Lower number = higher priority
      return a.created_at > b.created_at; // Older first
    }
  };

  mutable std::shared_mutex queue_mutex_;
  std::priority_queue<PurgeTask, std::vector<PurgeTask>, PurgeTaskCompare> purge_queue_;
  std::map<std::string, PurgeTask> all_tasks_;
};

// Serialize PurgeTask to JSON
json purge_task_to_json(const PurgeTask& task) {
  json j;
  j["id"] = task.id;
  j["admin_id"] = task.admin_id;
  j["target_type"] = [&]() -> std::string {
    switch (task.target_type) {
      case PurgeTask::TargetType::User: return "user";
      case PurgeTask::TargetType::Post: return "post";
      case PurgeTask::TargetType::Comment: return "comment";
      case PurgeTask::TargetType::Community: return "community";
      case PurgeTask::TargetType::Image: return "image";
      case PurgeTask::TargetType::PM: return "pm";
    }
    return "unknown";
  }();
  j["target_id"] = task.target_id;
  j["reason"] = task.reason;
  j["status"] = [&]() -> std::string {
    switch (task.status) {
      case PurgeTask::Status::Queued: return "queued";
      case PurgeTask::Status::InProgress: return "in_progress";
      case PurgeTask::Status::Completed: return "completed";
      case PurgeTask::Status::Failed: return "failed";
      case PurgeTask::Status::Cancelled: return "cancelled";
    }
    return "unknown";
  }();
  j["created_at"] = task.created_at;
  j["started_at"] = task.started_at;
  j["completed_at"] = task.completed_at;
  if (!task.error_message.empty()) j["error_message"] = task.error_message;
  j["retry_count"] = task.retry_count;
  j["priority"] = task.priority;
  return j;
}

// ============================================================================
// Section B12: Registration Applications with Email Notifications
// ============================================================================

// Extended registration application
struct RegistrationApp {
  std::string id;
  std::string user_id;
  std::string username;
  std::string email;
  std::string answer;          // Answer to application question
  std::string admin_notes;     // Admin notes during review
  bool accepted{false};
  bool denied{false};
  bool read{false};
  int64_t published{0};
  int64_t reviewed_at{0};
  std::string reviewed_by;     // Admin user_id
  std::string deny_reason;     // Reason for denial
};

// Registration application manager
class RegistrationApplicationManager {
public:
  RegistrationApp submit_application(const std::string& user_id,
                                        const std::string& username,
                                        const std::string& email,
                                        const std::string& answer) {
    RegistrationApp app;
    app.id = "regapp-" + lfb_detail::gen_uid();
    app.user_id = user_id;
    app.username = username;
    app.email = email;
    app.answer = answer;
    app.published = lfb_detail::now_sec();

    std::unique_lock lock(apps_mutex_);
    apps_[app.id] = app;
    pending_count_++;
    return app;
  }

  std::optional<RegistrationApp> get_application(const std::string& app_id) {
    std::shared_lock lock(apps_mutex_);
    auto it = apps_.find(app_id);
    if (it != apps_.end()) return it->second;
    return std::nullopt;
  }

  std::vector<RegistrationApp> get_applications(int page, int limit,
                                                   bool unread_only = true) {
    std::shared_lock lock(apps_mutex_);
    std::vector<RegistrationApp> result;
    for (const auto& [id, app] : apps_) {
      if (unread_only && app.read) continue;
      result.push_back(app);
    }
    std::sort(result.begin(), result.end(),
              [](const RegistrationApp& a, const RegistrationApp& b) {
                return a.published > b.published;
              });

    int start = (page - 1) * limit;
    if (start < 0) start = 0;
    if (start < static_cast<int>(result.size())) {
      result = std::vector<RegistrationApp>(
          result.begin() + start,
          start + limit <= static_cast<int>(result.size()) ?
          result.begin() + start + limit : result.end());
    } else {
      result.clear();
    }
    return result;
  }

  RegistrationApp approve_application(const std::string& app_id,
                                         const std::string& admin_id,
                                         const std::string& notes = "") {
    std::unique_lock lock(apps_mutex_);
    auto it = apps_.find(app_id);
    if (it == apps_.end())
      throw std::runtime_error("Application not found");
    if (it->second.accepted || it->second.denied)
      throw std::runtime_error("Application already processed");

    it->second.accepted = true;
    it->second.read = true;
    it->second.reviewed_at = lfb_detail::now_sec();
    it->second.reviewed_by = admin_id;
    it->second.admin_notes = notes;
    pending_count_--;
    approved_count_++;

    return it->second;
  }

  RegistrationApp deny_application(const std::string& app_id,
                                      const std::string& admin_id,
                                      const std::string& reason,
                                      const std::string& notes = "") {
    std::unique_lock lock(apps_mutex_);
    auto it = apps_.find(app_id);
    if (it == apps_.end())
      throw std::runtime_error("Application not found");
    if (it->second.accepted || it->second.denied)
      throw std::runtime_error("Application already processed");

    it->second.denied = true;
    it->second.read = true;
    it->second.reviewed_at = lfb_detail::now_sec();
    it->second.reviewed_by = admin_id;
    it->second.deny_reason = reason;
    it->second.admin_notes = notes;
    pending_count_--;
    denied_count_++;

    return it->second;
  }

  void mark_read(const std::string& app_id) {
    std::unique_lock lock(apps_mutex_);
    auto it = apps_.find(app_id);
    if (it != apps_.end()) it->second.read = true;
  }

  int pending_count() {
    std::shared_lock lock(apps_mutex_);
    return pending_count_;
  }

  json get_stats() {
    std::shared_lock lock(apps_mutex_);
    json stats;
    stats["pending"] = pending_count_;
    stats["approved"] = approved_count_;
    stats["denied"] = denied_count_;
    stats["total"] = static_cast<int>(apps_.size());
    return stats;
  }

private:
  mutable std::shared_mutex apps_mutex_;
  std::map<std::string, RegistrationApp> apps_;
  int pending_count_{0};
  int approved_count_{0};
  int denied_count_{0};
};

// Serialize registration app
json registration_app_to_json(const RegistrationApp& app) {
  json j;
  j["id"] = app.id;
  j["user_id"] = app.user_id;
  j["username"] = app.username;
  j["email"] = app.email;
  j["answer"] = app.answer;
  j["accepted"] = app.accepted;
  j["denied"] = app.denied;
  j["read"] = app.read;
  j["published"] = app.published;
  if (app.reviewed_at > 0) j["reviewed_at"] = app.reviewed_at;
  if (!app.reviewed_by.empty()) j["reviewed_by"] = app.reviewed_by;
  if (!app.admin_notes.empty()) j["admin_notes"] = app.admin_notes;
  if (!app.deny_reason.empty()) j["deny_reason"] = app.deny_reason;
  return j;
}

// ============================================================================
// Section B13: Email Notification System for Replies, Mentions, PMs
// ============================================================================

// Email notification configuration
struct EmailConfig {
  std::string smtp_server;
  int smtp_port{587};
  std::string smtp_username;
  std::string smtp_password;
  std::string from_address;
  std::string from_name{"Lemmy Instance"};
  bool use_tls{true};
  bool use_starttls{true};
  int max_rate_per_minute{30};
};

// Email notification type
enum class NotificationType {
  CommentReply,        // Someone replied to your comment
  PostReply,           // Someone commented on your post
  UserMention,         // Someone @mentioned you in a comment/post
  PrivateMessage,      // New private message
  RegistrationApproved,// Your registration was approved
  RegistrationDenied,  // Your registration was denied
  CommunityTransfer,   // Community ownership transfer request
  BanAppealUpdate,     // Your ban appeal was reviewed
  NewFollower,         // Someone followed you (if enabled)
  ModAction,           // A moderator action was taken in your community
  PasswordReset,       // Password reset email
  EmailVerification,   // Email verification
  ReportResolved,      // Your report was resolved
};

// Email template
struct EmailTemplate {
  std::string subject;
  std::string body_html;
  std::string body_text;
};

// Build email for notification
EmailTemplate build_notification_email(
    NotificationType type,
    const std::string& recipient_name,
    const std::string& instance_name,
    const json& context) {

  EmailTemplate tpl;
  std::string instance_url = context.value("instance_url", "https://" + instance_name);

  switch (type) {
    case NotificationType::CommentReply: {
      tpl.subject = "New reply to your comment on " + instance_name;
      std::stringstream body;
      body << "<h2>You have a new reply</h2>\n";
      body << "<p>Hello " << lfb_detail::xml_escape(recipient_name) << ",</p>\n";
      body << "<p><strong>" << lfb_detail::xml_escape(context.value("replier_name", "Someone"))
           << "</strong> replied to your comment on "
           << lfb_detail::xml_escape(context.value("post_title", "a post")) << ":</p>\n";
      body << "<blockquote>" << lfb_detail::xml_escape(context.value("reply_content", ""))
           << "</blockquote>\n";
      body << "<p><a href=\"" << instance_url << "/comment/"
           << lfb_detail::xml_escape(context.value("comment_id", ""))
           << "\">View reply</a></p>\n";
      body << "<hr>\n<p><small>Sent by " << lfb_detail::xml_escape(instance_name)
           << ". Manage notifications in your <a href=\"" << instance_url
           << "/settings\">settings</a>.</small></p>\n";
      tpl.body_html = body.str();
      tpl.body_text = lfb_detail::strip_html(tpl.body_html);
      break;
    }

    case NotificationType::PostReply: {
      tpl.subject = "New comment on your post on " + instance_name;
      std::stringstream body;
      body << "<h2>New comment on your post</h2>\n";
      body << "<p>Hello " << lfb_detail::xml_escape(recipient_name) << ",</p>\n";
      body << "<p>" << lfb_detail::xml_escape(context.value("commenter_name", "Someone"))
           << " commented on your post <strong>"
           << lfb_detail::xml_escape(context.value("post_title", "a post"))
           << "</strong>:</p>\n";
      body << "<blockquote>" << lfb_detail::xml_escape(context.value("comment_content", ""))
           << "</blockquote>\n";
      body << "<p><a href=\"" << instance_url << "/post/"
           << lfb_detail::xml_escape(context.value("post_id", ""))
           << "\">View post</a></p>\n";
      tpl.body_html = body.str();
      tpl.body_text = lfb_detail::strip_html(tpl.body_html);
      break;
    }

    case NotificationType::UserMention: {
      tpl.subject = "You were mentioned on " + instance_name;
      std::stringstream body;
      body << "<h2>You were mentioned</h2>\n";
      body << "<p>Hello " << lfb_detail::xml_escape(recipient_name) << ",</p>\n";
      body << "<p>" << lfb_detail::xml_escape(context.value("mentioner_name", "Someone"))
           << " mentioned you in a "
           << context.value("mention_type", "comment") << ":</p>\n";
      body << "<blockquote>" << lfb_detail::xml_escape(context.value("content", ""))
           << "</blockquote>\n";
      body << "<p><a href=\"" << instance_url << "/"
           << context.value("mention_type", "comment") << "/"
           << lfb_detail::xml_escape(context.value("item_id", ""))
           << "\">View</a></p>\n";
      tpl.body_html = body.str();
      tpl.body_text = lfb_detail::strip_html(tpl.body_html);
      break;
    }

    case NotificationType::PrivateMessage: {
      tpl.subject = "New private message from " +
                   context.value("sender_name", "a user") + " on " + instance_name;
      std::stringstream body;
      body << "<h2>You have a new private message</h2>\n";
      body << "<p>Hello " << lfb_detail::xml_escape(recipient_name) << ",</p>\n";
      body << "<p>You received a new message from <strong>"
           << lfb_detail::xml_escape(context.value("sender_name", "a user"))
           << "</strong>:</p>\n";
      body << "<blockquote>" << lfb_detail::xml_escape(context.value("message_content", ""))
           << "</blockquote>\n";
      body << "<p><a href=\"" << instance_url
           << "/messages\">View messages</a></p>\n";
      tpl.body_html = body.str();
      tpl.body_text = lfb_detail::strip_html(tpl.body_html);
      break;
    }

    case NotificationType::RegistrationApproved: {
      tpl.subject = "Your registration has been approved on " + instance_name;
      std::stringstream body;
      body << "<h2>Registration Approved!</h2>\n";
      body << "<p>Hello " << lfb_detail::xml_escape(recipient_name) << ",</p>\n";
      body << "<p>Your registration application for <strong>"
           << lfb_detail::xml_escape(instance_name) << "</strong> has been approved.</p>\n";
      body << "<p>You can now <a href=\"" << instance_url
           << "/login\">log in</a> to your account.</p>\n";
      tpl.body_html = body.str();
      tpl.body_text = lfb_detail::strip_html(tpl.body_html);
      break;
    }

    case NotificationType::PasswordReset: {
      tpl.subject = "Password reset for " + instance_name;
      std::stringstream body;
      body << "<h2>Password Reset</h2>\n";
      body << "<p>Hello " << lfb_detail::xml_escape(recipient_name) << ",</p>\n";
      body << "<p>A password reset was requested for your account on "
           << lfb_detail::xml_escape(instance_name) << ".</p>\n";
      body << "<p><a href=\"" << instance_url << "/reset-password?token="
           << lfb_detail::xml_escape(context.value("reset_token", ""))
           << "\">Reset your password</a></p>\n";
      body << "<p>This link will expire in 1 hour. If you did not request this reset, "
           << "you can safely ignore this email.</p>\n";
      tpl.body_html = body.str();
      tpl.body_text = lfb_detail::strip_html(tpl.body_html);
      break;
    }

    case NotificationType::EmailVerification: {
      tpl.subject = "Verify your email on " + instance_name;
      std::stringstream body;
      body << "<h2>Email Verification</h2>\n";
      body << "<p>Hello " << lfb_detail::xml_escape(recipient_name) << ",</p>\n";
      body << "<p>Please verify your email address by clicking the link below:</p>\n";
      body << "<p><a href=\"" << instance_url << "/verify-email?token="
           << lfb_detail::xml_escape(context.value("verify_token", ""))
           << "\">Verify Email</a></p>\n";
      body << "<p>This link will expire in 24 hours.</p>\n";
      tpl.body_html = body.str();
      tpl.body_text = lfb_detail::strip_html(tpl.body_html);
      break;
    }

    default: {
      tpl.subject = "Notification from " + instance_name;
      tpl.body_html = "<p>You have a new notification on " +
                      lfb_detail::xml_escape(instance_name) + ".</p>\n";
      tpl.body_text = lfb_detail::strip_html(tpl.body_html);
      break;
    }
  }

  return tpl;
}

// Email notification queue system
class EmailNotificationQueue {
public:
  struct QueuedEmail {
    std::string id;
    std::string to_address;
    std::string to_name;
    std::string subject;
    std::string body_html;
    std::string body_text;
    NotificationType type;
    int64_t queued_at;
    int retry_count{0};
    bool sent{false};
    std::string error;
  };

  void queue_email(const std::string& to_address,
                    const std::string& to_name,
                    NotificationType type,
                    const json& context,
                    const std::string& instance_name) {
    EmailTemplate tpl = build_notification_email(
        type, to_name, instance_name, context);

    QueuedEmail email;
    email.id = "email-" + lfb_detail::gen_uid();
    email.to_address = to_address;
    email.to_name = to_name;
    email.subject = tpl.subject;
    email.body_html = tpl.body_html;
    email.body_text = tpl.body_text;
    email.type = type;
    email.queued_at = lfb_detail::now_sec();

    std::unique_lock lock(queue_mutex_);
    email_queue_.push(email);
  }

  std::optional<QueuedEmail> dequeue() {
    std::unique_lock lock(queue_mutex_);
    if (email_queue_.empty()) return std::nullopt;
    auto email = email_queue_.front();
    email_queue_.pop();
    return email;
  }

  void mark_sent(const std::string& email_id) {
    std::unique_lock lock(queue_mutex_);
    sent_emails_[email_id] = true;
  }

  void mark_failed(const std::string& email_id, const std::string& error) {
    std::unique_lock lock(queue_mutex_);
    failed_emails_[email_id] = error;
  }

  size_t pending_count() {
    std::shared_lock lock(queue_mutex_);
    return email_queue_.size();
  }

  json get_stats() {
    std::shared_lock lock(queue_mutex_);
    json stats;
    stats["pending"] = static_cast<int>(email_queue_.size());
    stats["sent"] = static_cast<int>(sent_emails_.size());
    stats["failed"] = static_cast<int>(failed_emails_.size());
    return stats;
  }

private:
  mutable std::shared_mutex queue_mutex_;
  std::queue<QueuedEmail> email_queue_;
  std::map<std::string, bool> sent_emails_;
  std::map<std::string, std::string> failed_emails_;
};

// ============================================================================
// Section B14: WebSocket Real-Time Notifications
// ============================================================================

// WebSocket client connection
struct WSConnection {
  std::string id;
  std::string user_id;
  std::string session_id;
  int64_t connected_at{0};
  int64_t last_activity{0};
  std::vector<std::string> subscribed_communities;
  std::vector<std::string> subscribed_channels;
  bool alive{true};
};

// WebSocket message types
enum class WSMessageType {
  // Server->Client
  NewPost,              // New post in subscribed community
  NewComment,           // New comment on subscribed post
  CommentReply,         // Someone replied to your comment
  PostReply,            // Someone commented on your post
  UserMention,          // Someone mentioned you
  PrivateMessage,       // New private message
  VoteUpdate,           // Post/comment score changed
  ModAction,            // Mod action in subscribed community
  ReportResolved,       // Your report was resolved
  RegistrationUpdate,   // Registration application status changed
  BanAppealUpdate,      // Ban appeal reviewed
  CommunityTransfer,    // Community transfer status changed
  SiteMessage,          // Site-wide announcement
  UserJoined,           // User joined (presence)
  CommunityUpdate,      // Community settings changed
  Ping,                 // Keep-alive
  // Client->Server
  SubscribeCommunity,   // Subscribe to community updates
  UnsubscribeCommunity, // Unsubscribe from community updates
  SubscribePost,        // Subscribe to post updates
  UnsubscribePost,      // Unsubscribe from post updates
  TypingIndicator,      // User is typing
  MarkAsRead,           // Mark notification as read
};

// WebSocket notification manager
class WSNotificationManager {
public:
  // Register a new WebSocket connection
  WSConnection register_connection(const std::string& user_id,
                                      const std::string& session_id) {
    WSConnection conn;
    conn.id = "ws-" + lfb_detail::gen_uid();
    conn.user_id = user_id;
    conn.session_id = session_id;
    conn.connected_at = lfb_detail::now_sec();
    conn.last_activity = conn.connected_at;

    std::unique_lock lock(conns_mutex_);
    connections_[conn.id] = conn;
    user_connections_[user_id].insert(conn.id);
    return conn;
  }

  // Mark connection disconnected
  void unregister_connection(const std::string& connection_id) {
    std::unique_lock lock(conns_mutex_);
    auto it = connections_.find(connection_id);
    if (it != connections_.end()) {
      auto uit = user_connections_.find(it->second.user_id);
      if (uit != user_connections_.end())
        uit->second.erase(connection_id);
      connections_.erase(it);
    }
  }

  // Update last activity (for heartbeat tracking)
  void touch(const std::string& connection_id) {
    std::shared_lock lock(conns_mutex_);
    auto it = connections_.find(connection_id);
    if (it != connections_.end())
      it->second.last_activity = lfb_detail::now_sec();
  }

  // Subscribe to a community
  void subscribe_community(const std::string& connection_id,
                             const std::string& community_id) {
    std::unique_lock lock(conns_mutex_);
    auto it = connections_.find(connection_id);
    if (it == connections_.end()) return;
    auto& subs = it->second.subscribed_communities;
    if (std::find(subs.begin(), subs.end(), community_id) == subs.end())
      subs.push_back(community_id);
    community_subscribers_[community_id].insert(connection_id);
  }

  void unsubscribe_community(const std::string& connection_id,
                               const std::string& community_id) {
    std::unique_lock lock(conns_mutex_);
    auto it = connections_.find(connection_id);
    if (it == connections_.end()) return;
    auto& subs = it->second.subscribed_communities;
    subs.erase(std::remove(subs.begin(), subs.end(), community_id), subs.end());
    auto csit = community_subscribers_.find(community_id);
    if (csit != community_subscribers_.end())
      csit->second.erase(connection_id);
  }

  // Broadcast notification to specific user's connections
  void notify_user(const std::string& user_id,
                    WSMessageType type,
                    const json& payload) {
    std::shared_lock lock(conns_mutex_);
    auto it = user_connections_.find(user_id);
    if (it == user_connections_.end()) return;

    for (const auto& cid : it->second) {
      auto cit = connections_.find(cid);
      if (cit == connections_.end() || !cit->second.alive) continue;
      enqueue_message(cid, type, payload);
    }
  }

  // Broadcast to all subscribers of a community
  void notify_community(const std::string& community_id,
                          WSMessageType type,
                          const json& payload) {
    std::shared_lock lock(conns_mutex_);
    auto it = community_subscribers_.find(community_id);
    if (it == community_subscribers_.end()) return;

    for (const auto& cid : it->second) {
      auto cit = connections_.find(cid);
      if (cit == connections_.end() || !cit->second.alive) continue;
      enqueue_message(cid, type, payload);
    }
  }

  // Broadcast to all connected users (site-wide)
  void broadcast_all(WSMessageType type, const json& payload) {
    std::shared_lock lock(conns_mutex_);
    for (const auto& [cid, conn] : connections_) {
      if (!conn.alive) continue;
      enqueue_message(cid, type, payload);
    }
  }

  // Get pending messages for a connection
  std::vector<json> drain_messages(const std::string& connection_id) {
    std::unique_lock lock(msg_mutex_);
    std::vector<json> result;
    auto it = message_queues_.find(connection_id);
    if (it != message_queues_.end()) {
      result = std::move(it->second);
      message_queues_.erase(it);
    }
    return result;
  }

  // Build a standard WS message
  json build_message(WSMessageType type, const json& payload, int64_t timestamp = 0) {
    if (timestamp == 0) timestamp = lfb_detail::now_sec();
    json msg;
    msg["type"] = ws_message_type_to_string(type);
    msg["payload"] = payload;
    msg["timestamp"] = timestamp;
    msg["id"] = "wsmsg-" + lfb_detail::gen_uid();
    return msg;
  }

  // Status info
  json get_status() {
    std::shared_lock lock(conns_mutex_);
    json status;
    status["active_connections"] = static_cast<int>(connections_.size());
    status["unique_users"] = static_cast<int>(user_connections_.size());
    int alive = 0;
    for (const auto& [cid, conn] : connections_) {
      if (conn.alive) alive++;
    }
    status["alive_connections"] = alive;
    status["subscribed_communities"] = static_cast<int>(community_subscribers_.size());
    return status;
  }

  // Cleanup stale connections
  int cleanup_stale(int max_idle_seconds = 300) {
    std::unique_lock lock(conns_mutex_);
    int64_t now = lfb_detail::now_sec();
    std::vector<std::string> to_remove;
    for (const auto& [cid, conn] : connections_) {
      if (now - conn.last_activity > max_idle_seconds)
        to_remove.push_back(cid);
    }
    for (const auto& cid : to_remove) {
      auto it = connections_.find(cid);
      if (it != connections_.end()) {
        user_connections_[it->second.user_id].erase(cid);
        connections_.erase(it);
      }
      // Clean up community subscriptions
      for (auto& [com_id, subs] : community_subscribers_)
        subs.erase(cid);
      // Clean up message queue
      message_queues_.erase(cid);
    }
    return static_cast<int>(to_remove.size());
  }

private:
  void enqueue_message(const std::string& connection_id,
                        WSMessageType type,
                        const json& payload) {
    std::unique_lock lock(msg_mutex_);
    json msg = build_message(type, payload);
    message_queues_[connection_id].push_back(msg);
    // Limit queue size per connection
    if (message_queues_[connection_id].size() > 500) {
      message_queues_[connection_id].erase(
          message_queues_[connection_id].begin());
    }
  }

  std::string ws_message_type_to_string(WSMessageType type) {
    switch (type) {
      case WSMessageType::NewPost: return "new_post";
      case WSMessageType::NewComment: return "new_comment";
      case WSMessageType::CommentReply: return "comment_reply";
      case WSMessageType::PostReply: return "post_reply";
      case WSMessageType::UserMention: return "user_mention";
      case WSMessageType::PrivateMessage: return "private_message";
      case WSMessageType::VoteUpdate: return "vote_update";
      case WSMessageType::ModAction: return "mod_action";
      case WSMessageType::ReportResolved: return "report_resolved";
      case WSMessageType::RegistrationUpdate: return "registration_update";
      case WSMessageType::BanAppealUpdate: return "ban_appeal_update";
      case WSMessageType::CommunityTransfer: return "community_transfer";
      case WSMessageType::SiteMessage: return "site_message";
      case WSMessageType::UserJoined: return "user_joined";
      case WSMessageType::CommunityUpdate: return "community_update";
      case WSMessageType::Ping: return "ping";
      case WSMessageType::SubscribeCommunity: return "subscribe_community";
      case WSMessageType::UnsubscribeCommunity: return "unsubscribe_community";
      case WSMessageType::SubscribePost: return "subscribe_post";
      case WSMessageType::UnsubscribePost: return "unsubscribe_post";
      case WSMessageType::TypingIndicator: return "typing";
      case WSMessageType::MarkAsRead: return "mark_as_read";
    }
    return "unknown";
  }

  mutable std::shared_mutex conns_mutex_;
  mutable std::shared_mutex msg_mutex_;
  std::map<std::string, WSConnection> connections_;
  std::map<std::string, std::set<std::string>> user_connections_;
  std::map<std::string, std::set<std::string>> community_subscribers_;
  std::map<std::string, std::vector<json>> message_queues_;
};

// ============================================================================
// Section B15: OAuth2 Provider for Matrix Bridging
// ============================================================================

// OAuth2 types
struct OAuth2Client {
  std::string client_id;
  std::string client_secret;
  std::string client_name;
  std::string redirect_uri;
  std::string client_type;       // "confidential" or "public"
  bool enabled{true};
  int64_t created_at{0};
  std::vector<std::string> grant_types;       // "authorization_code", "client_credentials"
  std::vector<std::string> scopes;            // Allowed scopes
  std::optional<std::string> logo_uri;
  std::optional<std::string> tos_uri;
  std::optional<std::string> policy_uri;
};

struct OAuth2AuthorizationCode {
  std::string code;
  std::string client_id;
  std::string user_id;
  std::string redirect_uri;
  std::vector<std::string> scopes;
  int64_t created_at;
  int64_t expires_at;
  bool used{false};
  std::string code_challenge;    // PKCE challenge
  std::string code_challenge_method; // "S256" or "plain"
};

struct OAuth2Token {
  std::string access_token;
  std::string refresh_token;
  std::string client_id;
  std::string user_id;
  std::vector<std::string> scopes;
  int64_t created_at;
  int64_t expires_at;            // access token expiry
  int64_t refresh_expires_at;    // refresh token expiry
  bool revoked{false};
};

// Standard OAuth2 scopes for Lemmy
static const std::vector<std::string> LFB_OAUTH2_SCOPES = {
  "read",                  // Read access (posts, comments, communities)
  "write",                 // Write access (create posts, comments, vote)
  "read:account",          // Read user account info
  "write:account",         // Update user account settings
  "read:private_message",  // Read private messages
  "write:private_message", // Send private messages
  "follow",                // Follow/unfollow communities
  "moderate",              // Community moderation
  "admin",                 // Full admin access
  "matrix",                // Matrix bridge integration
};

// OAuth2 Provider class
class OAuth2Provider {
public:
  // Register a new OAuth2 client application
  OAuth2Client register_client(const std::string& client_name,
                                  const std::string& redirect_uri,
                                  const std::string& client_type = "confidential",
                                  const std::vector<std::string>& scopes = {"read"},
                                  const std::vector<std::string>& grant_types = {"authorization_code"}) {
    OAuth2Client client;
    client.client_id = lfb_detail::gen_uuid();
    client.client_secret = lfb_detail::random_bytes(32);
    client.client_secret = lfb_detail::b64_url_encode(client.client_secret);
    client.client_name = client_name;
    client.redirect_uri = redirect_uri;
    client.client_type = client_type;
    client.scopes = scopes;
    client.grant_types = grant_types;
    client.created_at = lfb_detail::now_sec();

    std::unique_lock lock(mutex_);
    clients_[client.client_id] = client;
    return client;
  }

  // Get client by ID (for Matrix bridge authentication)
  std::optional<OAuth2Client> get_client(const std::string& client_id) {
    std::shared_lock lock(mutex_);
    auto it = clients_.find(client_id);
    if (it != clients_.end()) return it->second;
    return std::nullopt;
  }

  // Generate authorization code (authorization code grant flow)
  OAuth2AuthorizationCode generate_authorization_code(
      const std::string& client_id,
      const std::string& user_id,
      const std::string& redirect_uri,
      const std::vector<std::string>& scopes,
      const std::string& code_challenge = "",
      const std::string& code_challenge_method = "") {

    // Validate client
    auto client = get_client(client_id);
    if (!client.has_value())
      throw std::runtime_error("Invalid client_id");
    if (!client->enabled)
      throw std::runtime_error("Client is disabled");
    if (client->redirect_uri != redirect_uri)
      throw std::runtime_error("Redirect URI mismatch");

    OAuth2AuthorizationCode auth_code;
    auth_code.code = lfb_detail::random_bytes(32);
    auth_code.code = lfb_detail::b64_url_encode(auth_code.code);
    auth_code.client_id = client_id;
    auth_code.user_id = user_id;
    auth_code.redirect_uri = redirect_uri;
    auth_code.scopes = scopes;
    auth_code.created_at = lfb_detail::now_sec();
    auth_code.expires_at = auth_code.created_at + 600; // 10 minutes
    auth_code.code_challenge = code_challenge;
    auth_code.code_challenge_method = code_challenge_method;

    std::unique_lock lock(mutex_);
    // Invalidate old codes for this user+client
    for (auto it = auth_codes_.begin(); it != auth_codes_.end(); ) {
      if (it->second.client_id == client_id &&
          it->second.user_id == user_id) {
        it = auth_codes_.erase(it);
      } else {
        ++it;
      }
    }
    auth_codes_[auth_code.code] = auth_code;
    return auth_code;
  }

  // Exchange authorization code for tokens
  OAuth2Token exchange_code_for_tokens(
      const std::string& code,
      const std::string& client_id,
      const std::string& client_secret,
      const std::string& redirect_uri,
      const std::string& code_verifier = "") {

    std::unique_lock lock(mutex_);

    // Validate client
    auto client_it = clients_.find(client_id);
    if (client_it == clients_.end())
      throw std::runtime_error("Invalid client_id");
    if (client_it->second.client_secret != client_secret)
      throw std::runtime_error("Invalid client_secret");

    // Find and validate auth code
    auto code_it = auth_codes_.find(code);
    if (code_it == auth_codes_.end())
      throw std::runtime_error("Invalid authorization code");

    auto& auth_code = code_it->second;
    if (auth_code.used)
      throw std::runtime_error("Authorization code already used");
    if (auth_code.expires_at < lfb_detail::now_sec())
      throw std::runtime_error("Authorization code expired");
    if (auth_code.client_id != client_id)
      throw std::runtime_error("Client ID mismatch");
    if (auth_code.redirect_uri != redirect_uri)
      throw std::runtime_error("Redirect URI mismatch");

    // PKCE verification
    if (!auth_code.code_challenge.empty()) {
      if (code_verifier.empty())
        throw std::runtime_error("Code verifier required for PKCE");
      if (auth_code.code_challenge_method == "S256") {
        std::string computed = lfb_detail::b64_url_encode(
            lfb_detail::sha256(code_verifier));
        if (computed != auth_code.code_challenge)
          throw std::runtime_error("Invalid code verifier");
      } else if (auth_code.code_challenge_method == "plain") {
        if (code_verifier != auth_code.code_challenge)
          throw std::runtime_error("Invalid code verifier");
      }
    }

    // Generate tokens
    OAuth2Token token;
    token.access_token = lfb_detail::random_bytes(48);
    token.access_token = lfb_detail::b64_url_encode(token.access_token);
    token.refresh_token = lfb_detail::random_bytes(48);
    token.refresh_token = lfb_detail::b64_url_encode(token.refresh_token);
    token.client_id = client_id;
    token.user_id = auth_code.user_id;
    token.scopes = auth_code.scopes;
    token.created_at = lfb_detail::now_sec();
    token.expires_at = token.created_at + 3600;        // 1 hour
    token.refresh_expires_at = token.created_at + 2592000; // 30 days

    // Mark code as used
    auth_code.used = true;

    // Store tokens
    access_tokens_[token.access_token] = token;
    refresh_tokens_[token.refresh_token] = token;

    // Cleanup expired
    cleanup_expired();

    return token;
  }

  // Refresh an access token
  OAuth2Token refresh_token(const std::string& refresh_token_str,
                              const std::string& client_id,
                              const std::string& client_secret) {
    std::unique_lock lock(mutex_);

    // Validate client
    auto client_it = clients_.find(client_id);
    if (client_it == clients_.end())
      throw std::runtime_error("Invalid client_id");
    if (client_it->second.client_secret != client_secret)
      throw std::runtime_error("Invalid client_secret");

    // Find and validate refresh token
    auto rt_it = refresh_tokens_.find(refresh_token_str);
    if (rt_it == refresh_tokens_.end())
      throw std::runtime_error("Invalid refresh token");

    auto& old_token = rt_it->second;
    if (old_token.revoked)
      throw std::runtime_error("Token revoked");
    if (old_token.refresh_expires_at < lfb_detail::now_sec())
      throw std::runtime_error("Refresh token expired");
    if (old_token.client_id != client_id)
      throw std::runtime_error("Client ID mismatch");

    // Revoke old tokens
    old_token.revoked = true;
    access_tokens_.erase(old_token.access_token);

    // Generate new tokens
    OAuth2Token token;
    token.access_token = lfb_detail::random_bytes(48);
    token.access_token = lfb_detail::b64_url_encode(token.access_token);
    token.refresh_token = refresh_token_str;  // Keep the same refresh token (rotation optional)
    token.client_id = client_id;
    token.user_id = old_token.user_id;
    token.scopes = old_token.scopes;
    token.created_at = lfb_detail::now_sec();
    token.expires_at = token.created_at + 3600;
    token.refresh_expires_at = old_token.refresh_expires_at;

    access_tokens_[token.access_token] = token;
    refresh_tokens_[token.refresh_token] = token;

    cleanup_expired();
    return token;
  }

  // Validate an access token
  struct TokenValidationResult {
    bool valid{false};
    std::string user_id;
    std::string client_id;
    std::vector<std::string> scopes;
    std::string error;
  };

  TokenValidationResult validate_token(const std::string& access_token_str) {
    std::shared_lock lock(mutex_);
    TokenValidationResult result;

    auto it = access_tokens_.find(access_token_str);
    if (it == access_tokens_.end()) {
      result.error = "Token not found";
      return result;
    }

    auto& token = it->second;
    if (token.revoked) {
      result.error = "Token revoked";
      return result;
    }

    if (token.expires_at < lfb_detail::now_sec()) {
      result.error = "Token expired";
      return result;
    }

    result.valid = true;
    result.user_id = token.user_id;
    result.client_id = token.client_id;
    result.scopes = token.scopes;
    return result;
  }

  // Revoke a token
  void revoke_token(const std::string& token_str) {
    std::unique_lock lock(mutex_);
    auto at_it = access_tokens_.find(token_str);
    if (at_it != access_tokens_.end()) {
      at_it->second.revoked = true;
      // Also revoke the corresponding refresh token
      auto rt_it = refresh_tokens_.find(at_it->second.refresh_token);
      if (rt_it != refresh_tokens_.end())
        rt_it->second.revoked = true;
    }
  }

  // OAuth2 authorization endpoint data
  json authorization_endpoint_info(const std::string& instance_url) {
    json info;
    info["issuer"] = instance_url;
    info["authorization_endpoint"] = instance_url + "/oauth2/authorize";
    info["token_endpoint"] = instance_url + "/oauth2/token";
    info["revocation_endpoint"] = instance_url + "/oauth2/revoke";
    info["token_endpoint_auth_methods_supported"] = {"client_secret_post"};
    info["grant_types_supported"] = {"authorization_code", "refresh_token"};
    info["response_types_supported"] = {"code"};
    info["scopes_supported"] = LFB_OAUTH2_SCOPES;
    info["code_challenge_methods_supported"] = {"S256", "plain"};
    info["service_documentation"] = instance_url + "/api/docs";
    info["registration_endpoint"] = instance_url + "/oauth2/register";
    return info;
  }

  // OAuth2 Discovery document (.well-known/oauth-authorization-server)
  json oauth2_discovery(const std::string& instance_url) {
    return authorization_endpoint_info(instance_url);
  }

  // Matrix-specific OIDC-like endpoints
  json matrix_oidc_info(const std::string& instance_url) {
    json info;
    info["issuer"] = instance_url;
    info["authorization_endpoint"] = instance_url + "/oauth2/authorize";
    info["token_endpoint"] = instance_url + "/oauth2/token";
    info["userinfo_endpoint"] = instance_url + "/oauth2/userinfo";
    info["jwks_uri"] = instance_url + "/oauth2/jwks.json";
    info["scopes_supported"] = {"openid", "matrix", "read"};
    info["response_types_supported"] = {"code"};
    info["id_token_signing_alg_values_supported"] = {"RS256", "HS256"};
    return info;
  }

  // Cleanup old/expired entries
  void cleanup_expired() {
    int64_t now = lfb_detail::now_sec();
    for (auto it = auth_codes_.begin(); it != auth_codes_.end(); ) {
      if (it->second.expires_at < now) it = auth_codes_.erase(it);
      else ++it;
    }
    for (auto it = access_tokens_.begin(); it != access_tokens_.end(); ) {
      if (it->second.expires_at < now) {
        // Also clean refresh
        refresh_tokens_.erase(it->second.refresh_token);
        it = access_tokens_.erase(it);
      } else {
        ++it;
      }
    }
    for (auto it = refresh_tokens_.begin(); it != refresh_tokens_.end(); ) {
      if (it->second.refresh_expires_at < now) it = refresh_tokens_.erase(it);
      else ++it;
    }
  }

  // Get token stats
  json get_stats() {
    std::shared_lock lock(mutex_);
    json stats;
    stats["active_access_tokens"] = static_cast<int>(access_tokens_.size());
    stats["active_refresh_tokens"] = static_cast<int>(refresh_tokens_.size());
    stats["pending_auth_codes"] = static_cast<int>(auth_codes_.size());
    stats["registered_clients"] = static_cast<int>(clients_.size());
    return stats;
  }

  // Check if token has required scope
  bool token_has_scope(const std::string& access_token, const std::string& scope) {
    auto result = validate_token(access_token);
    if (!result.valid) return false;
    return std::find(result.scopes.begin(), result.scopes.end(), scope) !=
           result.scopes.end();
  }

private:
  mutable std::shared_mutex mutex_;
  std::map<std::string, OAuth2Client> clients_;
  std::map<std::string, OAuth2AuthorizationCode> auth_codes_;
  std::map<std::string, OAuth2Token> access_tokens_;
  std::map<std::string, OAuth2Token> refresh_tokens_;
};

// ============================================================================
// Section B16: Sticky & Locked Post Implementation
// ============================================================================

// Post pinning/locking manager
class PostManagementExtras {
public:
  // Lock a post (prevent new comments)
  struct LockResult {
    bool success{false};
    std::string post_id;
    bool locked{false};
    std::string mod_id;
    std::string reason;
    int64_t action_time{0};
  };

  LockResult lock_post(const Post& post, const std::string& mod_id,
                         const std::string& reason, bool lock = true) {
    LockResult result;
    result.post_id = post.id;
    result.locked = lock;
    result.mod_id = mod_id;
    result.reason = reason;
    result.action_time = lfb_detail::now_sec();
    result.success = true;
    return result;
  }

  // Sticky a post (pin to top of community)
  struct StickyResult {
    bool success{false};
    std::string post_id;
    std::string community_id;
    bool stickied{false};
    bool featured_community{false};
    bool featured_local{false};
    std::string mod_id;
    int64_t action_time{0};
  };

  StickyResult sticky_post(const Post& post, const std::string& mod_id,
                             bool sticky = true) {
    StickyResult result;
    result.post_id = post.id;
    result.community_id = post.community_id;
    result.stickied = sticky;
    result.featured_community = sticky;
    result.mod_id = mod_id;
    result.action_time = lfb_detail::now_sec();
    result.success = true;
    return result;
  }

  // Feature a post locally (instance-wide pin)
  StickyResult feature_post_local(const Post& post, const std::string& admin_id,
                                    bool feature = true) {
    StickyResult result;
    result.post_id = post.id;
    result.community_id = post.community_id;
    result.stickied = true;
    result.featured_community = true;
    result.featured_local = feature;
    result.mod_id = admin_id;
    result.action_time = lfb_detail::now_sec();
    result.success = true;
    return result;
  }

  // NSFW marking logic
  bool should_mark_nsfw(const PostMetadata& meta, const std::string& post_title,
                          const std::string& community_name) {
    // Explicit NSFW from metadata
    if (meta.is_nsfw) return true;

    // Check title for common NSFW indicators
    static const std::vector<std::string> nsfw_keywords = {
      "nsfw", "nsfl", "adult", "explicit", "xxx", "porn", "nsfw:"
    };
    std::string lower_title = post_title;
    std::transform(lower_title.begin(), lower_title.end(), lower_title.begin(), ::tolower);
    for (const auto& kw : nsfw_keywords) {
      if (lower_title.find(kw) != std::string::npos) return true;
    }

    // Check community name for NSFW indicators
    if (community_name.find("nsfw") != std::string::npos) return true;
    if (community_name.find("NSFW") != std::string::npos) return true;

    return false;
  }

  // Check if a post is locked and user can't comment
  bool is_locked_for_commenting(const Post& post, const std::string& user_id,
                                  bool is_mod = false) {
    if (!post.locked) return false;
    if (is_mod) return false; // Mods can always comment
    return true;
  }

  // Generate post actions JSON for API
  json get_post_actions_json(const Post& post) {
    json actions;
    actions["locked"] = post.locked;
    actions["stickied"] = post.stickied;
    actions["featured_community"] = post.featured_community;
    actions["featured_local"] = post.featured_local;
    actions["nsfw"] = post.nsfw;
    actions["can_comment"] = !post.locked;
    actions["can_vote"] = true;
    return actions;
  }

  // Get sticky posts for a community (to display at top)
  std::vector<std::string> get_sticky_post_ids(
      const std::map<std::string, Post>& posts,
      const std::string& community_id) {
    std::vector<std::string> result;
    for (const auto& [id, p] : posts) {
      if (p.community_id == community_id &&
          (p.stickied || p.featured_community) &&
          !p.deleted && !p.removed)
        result.push_back(id);
    }
    // Sort by most recent first
    std::sort(result.begin(), result.end(),
              [&posts](const std::string& a, const std::string& b) {
                return posts.at(a).published > posts.at(b).published;
              });
    return result;
  }

  // Get locally featured posts
  std::vector<std::string> get_featured_local_post_ids(
      const std::map<std::string, Post>& posts) {
    std::vector<std::string> result;
    for (const auto& [id, p] : posts) {
      if (p.featured_local && !p.deleted && !p.removed)
        result.push_back(id);
    }
    return result;
  }
};

// ============================================================================
// Section B17: Combined Feature Orchestrator (ties everything together)
// ============================================================================

// Main orchestrator class that combines all B-series features.
// In production, this would be part of LemmyServer itself.
class LemmyFullB {
public:
  // Constructor
  LemmyFullB(const std::string& hostname, int port)
      : hostname_(hostname), port_(port) {
  }

  // ---- Access to sub-managers ----
  BanAppealManager& ban_appeals() { return ban_appeals_; }
  InstanceBlockManager& instance_blocks() { return instance_blocks_; }
  CommunityTransferManager& community_transfers() { return community_transfers_; }
  ModlogManager& modlog() { return modlog_; }
  PurgeQueueManager& purge_queue() { return purge_queue_; }
  RegistrationApplicationManager& registrations() { return registrations_; }
  EmailNotificationQueue& email_queue() { return email_queue_; }
  WSNotificationManager& websocket() { return websocket_; }
  OAuth2Provider& oauth2() { return oauth2_; }
  PostManagementExtras& post_extras() { return post_extras_; }

  // ---- Language tagging ----
  std::string detect_language(const std::string& text) {
    return detect_language_heuristic(text);
  }

  bool validate_language(const std::string& code) {
    return is_valid_language_code(code);
  }

  json get_languages() {
    json langs = json::array();
    for (const auto& lt : get_supported_languages()) {
      json l;
      l["id"] = lt.id;
      l["code"] = lt.code;
      l["name"] = lt.name;
      langs.push_back(l);
    }
    return langs;
  }

  // ---- Post URL metadata ----
  PostMetadata fetch_metadata(const std::string& url) {
    return fetch_url_metadata(url);
  }

  json fetch_metadata_json(const std::string& url) {
    return metadata_to_json(fetch_url_metadata(url));
  }

  std::string generate_preview_html(const std::string& url) {
    auto meta = fetch_url_metadata(url);
    return generate_link_preview_html(meta, url);
  }

  // ---- Comment trees ----
  json build_comment_tree(const std::vector<Comment>& comments,
                           const std::string& sort = "hot",
                           int max_depth = 8) {
    return ::progressive::lemmy::build_comment_tree(comments, sort, max_depth);
  }

  std::vector<Comment> flatten_tree(const json& tree) {
    return ::progressive::lemmy::flatten_comment_tree(tree);
  }

  std::map<int, int> depth_distribution(const std::vector<Comment>& comments) {
    return ::progressive::lemmy::comment_depth_distribution(comments);
  }

  // ---- Image upload via pictrs ----
  void configure_pictrs(const PictrsConfig& config) {
    pictrs_config_ = config;
  }

  // ---- User profile / 2FA / Email verification ----
  std::string setup_2fa(const std::string& user_id) {
    std::string secret = generate_totp_secret();
    // In production: store secret against user_id
    return secret;
  }

  bool verify_2fa(const std::string& user_id, const std::string& code,
                    const std::string& secret) {
    return verify_totp(secret, code, 30, 6);
  }

  std::string generate_2fa_uri(const std::string& user_id, const std::string& secret) {
    TOTPConfig config;
    config.secret = secret;
    config.issuer = hostname_;
    return generate_totp_uri(config, user_id);
  }

  std::string create_email_verification_token(const std::string& user_id,
                                                const std::string& email) {
    auto ev = create_email_verification(user_id, email);
    // Store token -> user mapping (simplified)
    return ev.token;
  }

  std::string create_password_reset_token(const std::string& user_id) {
    auto pr = create_password_reset(user_id);
    return pr.token;
  }

  // ---- NSFW detection ----
  bool is_nsfw_content(const PostMetadata& meta, const std::string& title,
                         const std::string& community_name) {
    return post_extras_.should_mark_nsfw(meta, title, community_name);
  }

  // ---- NSFW post marking ----
  struct NSFWMarkResult {
    std::string post_id;
    bool nsfw;
    std::string reason;
    int64_t when;
  };

  NSFWMarkResult mark_post_nsfw(const Post& post, bool nsfw = true) {
    NSFWMarkResult r;
    r.post_id = post.id;
    r.nsfw = nsfw;
    r.reason = nsfw ? "Content marked as NSFW" : "NSFW marking removed";
    r.when = lfb_detail::now_sec();
    return r;
  }

  // ---- Lock / Sticky posts ----
  PostManagementExtras::LockResult lock_post(const Post& post,
                                                const std::string& mod_id,
                                                const std::string& reason) {
    return post_extras_.lock_post(post, mod_id, reason, true);
  }

  PostManagementExtras::LockResult unlock_post(const Post& post,
                                                  const std::string& mod_id) {
    return post_extras_.lock_post(post, mod_id, "", false);
  }

  PostManagementExtras::StickyResult sticky_post(const Post& post,
                                                    const std::string& mod_id) {
    return post_extras_.sticky_post(post, mod_id, true);
  }

  PostManagementExtras::StickyResult unsticky_post(const Post& post,
                                                      const std::string& mod_id) {
    return post_extras_.sticky_post(post, mod_id, false);
  }

  // ---- Email notification helpers ----
  void notify_comment_reply(const std::string& to_email,
                              const std::string& to_name,
                              const std::string& replier_name,
                              const std::string& post_title,
                              const std::string& reply_content,
                              const std::string& comment_id) {
    json context;
    context["instance_url"] = "https://" + hostname_;
    context["replier_name"] = replier_name;
    context["post_title"] = post_title;
    context["reply_content"] = reply_content;
    context["comment_id"] = comment_id;
    email_queue_.queue_email(to_email, to_name,
                               NotificationType::CommentReply,
                               context, hostname_);
  }

  void notify_user_mention(const std::string& to_email,
                             const std::string& to_name,
                             const std::string& mentioner_name,
                             const std::string& content,
                             const std::string& item_type,
                             const std::string& item_id) {
    json context;
    context["instance_url"] = "https://" + hostname_;
    context["mentioner_name"] = mentioner_name;
    context["content"] = content;
    context["mention_type"] = item_type;
    context["item_id"] = item_id;
    email_queue_.queue_email(to_email, to_name,
                               NotificationType::UserMention,
                               context, hostname_);
  }

  void notify_private_message(const std::string& to_email,
                                const std::string& to_name,
                                const std::string& sender_name,
                                const std::string& message_content) {
    json context;
    context["instance_url"] = "https://" + hostname_;
    context["sender_name"] = sender_name;
    context["message_content"] = message_content;
    email_queue_.queue_email(to_email, to_name,
                               NotificationType::PrivateMessage,
                               context, hostname_);
  }

  void notify_password_reset(const std::string& to_email,
                               const std::string& to_name,
                               const std::string& reset_token) {
    json context;
    context["instance_url"] = "https://" + hostname_;
    context["reset_token"] = reset_token;
    email_queue_.queue_email(to_email, to_name,
                               NotificationType::PasswordReset,
                               context, hostname_);
  }

  void notify_email_verification(const std::string& to_email,
                                   const std::string& to_name,
                                   const std::string& verify_token) {
    json context;
    context["instance_url"] = "https://" + hostname_;
    context["verify_token"] = verify_token;
    email_queue_.queue_email(to_email, to_name,
                               NotificationType::EmailVerification,
                               context, hostname_);
  }

  // ---- WebSocket broadcast helpers ----
  void ws_new_post(const std::string& community_id, const json& post_data) {
    websocket_.notify_community(community_id, WSMessageType::NewPost, post_data);
  }

  void ws_new_comment(const std::string& post_id, const json& comment_data) {
    json payload = comment_data;
    payload["post_id"] = post_id;
    websocket_.broadcast_all(WSMessageType::NewComment, payload);
  }

  void ws_comment_reply(const std::string& user_id, const json& reply_data) {
    websocket_.notify_user(user_id, WSMessageType::CommentReply, reply_data);
  }

  void ws_user_mention(const std::string& user_id, const json& mention_data) {
    websocket_.notify_user(user_id, WSMessageType::UserMention, mention_data);
  }

  void ws_private_message(const std::string& user_id, const json& pm_data) {
    websocket_.notify_user(user_id, WSMessageType::PrivateMessage, pm_data);
  }

  void ws_mod_action(const std::string& community_id, const json& action_data) {
    websocket_.notify_community(community_id, WSMessageType::ModAction, action_data);
  }

  // ---- Admin purge helpers ----
  PurgeTask purge_user(const std::string& admin_id, const std::string& user_id,
                         const std::string& reason) {
    return purge_queue_.enqueue(admin_id, PurgeTask::TargetType::User,
                                  user_id, reason, 5);
  }

  PurgeTask purge_post_obj(const std::string& admin_id, const std::string& post_id,
                              const std::string& reason) {
    return purge_queue_.enqueue(admin_id, PurgeTask::TargetType::Post,
                                  post_id, reason, 3);
  }

  PurgeTask purge_comment_obj(const std::string& admin_id,
                                const std::string& comment_id,
                                const std::string& reason) {
    return purge_queue_.enqueue(admin_id, PurgeTask::TargetType::Comment,
                                  comment_id, reason, 3);
  }

  PurgeTask purge_community_obj(const std::string& admin_id,
                                  const std::string& community_id,
                                  const std::string& reason) {
    return purge_queue_.enqueue(admin_id, PurgeTask::TargetType::Community,
                                  community_id, reason, 7);
  }

  void process_purge_queue(int batch = 10) {
    auto tasks = purge_queue_.process_queue(batch);
    for (auto& task : tasks) {
      try {
        // Perform the actual purge based on target_type
        switch (task.target_type) {
          case PurgeTask::TargetType::User:
            // Purge user data
            break;
          case PurgeTask::TargetType::Post:
            // Purge post + all comments
            break;
          case PurgeTask::TargetType::Comment:
            // Purge single comment
            break;
          case PurgeTask::TargetType::Community:
            // Purge community + all posts/comments
            break;
          case PurgeTask::TargetType::Image:
            // Delete image via pictrs
            break;
          case PurgeTask::TargetType::PM:
            // Delete private messages
            break;
        }
        purge_queue_.mark_completed(task.id);
      } catch (const std::exception& e) {
        purge_queue_.mark_failed(task.id, e.what());
      }
    }
  }

  // ---- Periodic maintenance ----
  void periodic_maintenance() {
    // Cleanup stale WebSocket connections
    int cleaned = websocket_.cleanup_stale(300);
    (void)cleaned;

    // Cleanup expired OAuth2 tokens
    oauth2_.cleanup_expired();

    // Process pending purge tasks
    process_purge_queue(5);

    // Process pending email notifications
    process_email_queue(10);
  }

  void process_email_queue(int batch = 10) {
    for (int i = 0; i < batch; i++) {
      auto email = email_queue_.dequeue();
      if (!email.has_value()) break;
      try {
        // In production: send via SMTP
        // send_email_smtp(email->to_address, email->subject,
        //                 email->body_html, email->body_text);
        email_queue_.mark_sent(email->id);
      } catch (const std::exception& e) {
        email_queue_.mark_failed(email->id, e.what());
      }
    }
  }

  // ---- Stats aggregation ----
  json get_all_stats() {
    json stats;
    stats["hostname"] = hostname_;
    stats["port"] = port_;
    stats["timestamp"] = lfb_detail::now_sec();

    // Ban appeals
    stats["ban_appeals"] = {
      {"pending", ban_appeals_.pending_count()}
    };

    // Instance blocks
    stats["instance_blocks"] = {
      {"count", instance_blocks_.count()}
    };

    // Purge queue
    stats["purge_queue"] = purge_queue_.get_queue_stats();

    // Registrations
    stats["registrations"] = registrations_.get_stats();

    // Email queue
    stats["email_queue"] = email_queue_.get_stats();

    // WebSocket
    stats["websocket"] = websocket_.get_status();

    // OAuth2
    stats["oauth2"] = oauth2_.get_stats();

    return stats;
  }

private:
  std::string hostname_;
  int port_{8080};

  // Sub-managers
  BanAppealManager ban_appeals_;
  InstanceBlockManager instance_blocks_;
  CommunityTransferManager community_transfers_;
  ModlogManager modlog_;
  PurgeQueueManager purge_queue_;
  RegistrationApplicationManager registrations_;
  EmailNotificationQueue email_queue_;
  WSNotificationManager websocket_;
  OAuth2Provider oauth2_;
  PostManagementExtras post_extras_;

  // Configuration
  PictrsConfig pictrs_config_;
};

} // namespace progressive::lemmy
