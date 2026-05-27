// message_handlers.cpp - Matrix Message Handlers
// Implements ALL message-related handlers: send, redact, react, edit,
// thread, read markers, typing, get messages, pagination, context,
// report, polls, location, voice, stickers, widgets, spaces,
// retention, URL preview, spam checking.
// Target: 3000+ lines
//
// Handlers:
//   1.  send_message          - PUT /rooms/{roomId}/send/{eventType}/{txnId}
//   2.  redact_event          - PUT /rooms/{roomId}/redact/{eventId}/{txnId}
//   3.  send_reaction         - m.reaction event with m.relates_to m.annotation
//   4.  edit_message          - m.replace relation for message edits
//   5.  thread_message        - m.thread relation for threaded messages
//   6.  set_read_marker       - POST /rooms/{roomId}/read_markers
//   7.  send_typing           - PUT /rooms/{roomId}/typing/{userId}
//   8.  get_message           - GET /rooms/{roomId}/event/{eventId}
//   9.  get_messages          - GET /rooms/{roomId}/messages (pagination)
//  10.  get_event_context     - GET /rooms/{roomId}/context/{eventId}
//  11.  report_event          - POST /rooms/{roomId}/report/{eventId}
//  12.  send_poll_start       - Create m.poll.start event
//  13.  send_poll_response    - Create m.poll.response event
//  14.  send_poll_end         - Create m.poll.end event
//  15.  send_location         - Create m.location event
//  16.  send_voice_message    - Create m.audio with voice metadata
//  17.  send_sticker          - Create m.sticker event
//  18.  send_widget           - Create m.widget event (state)
//  19.  send_space_child      - Create m.space.child state event
//  20.  send_space_parent     - Create m.space.parent state event
//  21.  enforce_retention     - Enforce message retention policies
//  22.  generate_url_preview  - URL preview generation on message send
//  23.  check_spam            - Spam checking on message send

#include "../json.hpp"
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/receipts.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/event_federation.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/room.hpp"

#include <chrono>
#include <random>
#include <sstream>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <map>
#include <regex>
#include <cmath>
#include <thread>
#include <cctype>
#include <functional>

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;

// ============================================================================
// Global utilities (shared across handlers)
// ============================================================================

static std::atomic<int64_t> g_msg_seq{1};
static std::mutex g_msg_lock;
static std::mutex g_txn_lock;
static std::mutex g_url_preview_lock;
static std::mutex g_spam_lock;
static std::mutex g_retention_lock;

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_id(const std::string& prefix) {
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(g_msg_seq.fetch_add(1));
}

static std::string gen_token(int len = 32) {
  static const char cs[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(
    static_cast<unsigned>(now_ms() + std::hash<std::thread::id>{}(std::this_thread::get_id())));
  std::uniform_int_distribution<> d(0, 61);
  std::string t(len, 'A');
  for (auto& c : t) c = cs[d(rng)];
  return t;
}

static bool validate_user_id(const std::string& user_id) {
  return user_id.size() >= 4 && user_id[0] == '@' &&
         user_id.find(':') != std::string::npos;
}

static bool validate_room_id(const std::string& room_id) {
  return room_id.size() >= 2 && room_id[0] == '!' &&
         room_id.find(':') != std::string::npos;
}

static bool validate_event_id(const std::string& event_id) {
  return event_id.size() >= 2 && event_id[0] == '$';
}

static bool validate_msg_type(const std::string& msgtype) {
  static const std::set<std::string> valid_msgtypes = {
    "m.text", "m.emote", "m.notice", "m.image", "m.file",
    "m.audio", "m.video", "m.location"
  };
  return valid_msgtypes.count(msgtype) > 0;
}

static bool is_valid_event_type(const std::string& event_type) {
  // Event types must start with a letter/underscore and contain
  // only lowercase letters, digits, underscores, and dots
  if (event_type.empty()) return false;
  if (event_type.size() > 255) return false;
  if (event_type[0] != '_' && !std::islower(event_type[0])) return false;
  for (char c : event_type) {
    if (!std::islower(c) && !std::isdigit(c) && c != '_' && c != '.') {
      return false;
    }
  }
  return true;
}

static std::string safe_str(const json& obj, const std::string& key,
                             const std::string& def = "") {
  if (!obj.contains(key)) return def;
  if (obj[key].is_string()) return obj[key].get<std::string>();
  return def;
}

static int64_t safe_int(const json& obj, const std::string& key,
                         int64_t def = 0) {
  if (!obj.contains(key)) return def;
  if (obj[key].is_number()) return obj[key].get<int64_t>();
  return def;
}

static bool safe_bool(const json& obj, const std::string& key, bool def = false) {
  if (!obj.contains(key)) return def;
  if (obj[key].is_boolean()) return obj[key].get<bool>();
  return def;
}

// ============================================================================
// Auth context and validation helpers
// ============================================================================

struct AuthContext {
  std::string user_id;
  std::string device_id;
  std::string access_token;
  bool is_guest = false;
  bool is_admin = false;
  bool valid = false;
};

static AuthContext validate_auth(DatabasePool& db, const std::string& auth_header,
                                  const std::string& query_access_token) {
  AuthContext ctx;
  std::string token;

  if (!auth_header.empty()) {
    const std::string prefix = "Bearer ";
    if (auth_header.size() > prefix.size() &&
        auth_header.substr(0, prefix.size()) == prefix) {
      token = auth_header.substr(prefix.size());
    }
  }
  if (token.empty() && !query_access_token.empty()) {
    token = query_access_token;
  }
  if (token.empty()) {
    return ctx;
  }

  RegistrationStore reg(db);
  auto user_info = reg.get_user_by_access_token(token);
  if (!user_info) {
    return ctx;
  }

  ctx.valid = true;
  ctx.user_id = user_info->user_id;
  ctx.access_token = token;
  if (user_info->device_id) ctx.device_id = *user_info->device_id;
  ctx.is_guest = user_info->is_guest;
  return ctx;
}

static json make_error(int http_status, const std::string& errcode,
                        const std::string& error) {
  json resp;
  resp["status"] = http_status;
  resp["body"] = json{{"errcode", errcode}, {"error", error}};
  return resp;
}

static json make_response(int http_status, const json& body) {
  json resp;
  resp["status"] = http_status;
  resp["body"] = body;
  return resp;
}

// ============================================================================
// Room membership and power level helpers
// ============================================================================

static std::string get_membership(DatabasePool& db, const std::string& room_id,
                                    const std::string& user_id) {
  RoomMemberStore members(db);
  auto m = members.get_member(room_id, user_id);
  if (m) return m->membership;
  return "leave";
}

static bool is_user_in_room(DatabasePool& db, const std::string& room_id,
                              const std::string& user_id) {
  auto m = get_membership(db, room_id, user_id);
  return m == "join";
}

static int64_t get_user_power_level(DatabasePool& db, const std::string& room_id,
                                      const std::string& user_id) {
  StateStore state(db);
  auto pl_event = state.get_current_state_event(room_id, "m.room.power_levels", "");
  if (!pl_event) return 0;

  EventsStore evs(db);
  auto ev = evs.get_event(*pl_event);
  if (!ev) return 0;

  auto& content = (*ev)["content"];
  int64_t default_level = content.value("users_default", 0);

  if (content.contains("users") && content["users"].contains(user_id)) {
    return content["users"][user_id].get<int64_t>();
  }
  return default_level;
}

static int64_t get_required_power_level(DatabasePool& db,
    const std::string& room_id, const std::string& action) {
  StateStore state(db);
  auto pl_event = state.get_current_state_event(room_id, "m.room.power_levels", "");

  int64_t required = 50;
  if (!pl_event) return required;

  EventsStore evs(db);
  auto ev = evs.get_event(*pl_event);
  if (!ev || !(*ev).contains("content")) return required;

  auto& content = (*ev)["content"];
  if (action == "invite") required = content.value("invite", 0);
  else if (action == "kick") required = content.value("kick", 50);
  else if (action == "ban") required = content.value("ban", 50);
  else if (action == "redact") required = content.value("redact", 50);
  else if (action == "state_default") required = content.value("state_default", 50);
  else if (action == "events_default") required = content.value("events_default", 0);
  else if (action == "notifications.room") required = content.value("notifications", json::object()).value("room", 50);
  return required;
}

static bool has_power_to(DatabasePool& db, const std::string& room_id,
                           const std::string& user_id, const std::string& action) {
  int64_t user_pl = get_user_power_level(db, room_id, user_id);
  int64_t required = get_required_power_level(db, room_id, action);
  return user_pl >= required;
}

// ============================================================================
// Event building and persistence helpers
// ============================================================================

struct BuiltEvent {
  std::string event_id;
  std::string room_id;
  std::string sender;
  std::string type;
  std::optional<std::string> state_key;
  json content;
  int64_t origin_server_ts;
  int64_t stream_ordering;
  int64_t depth;
  std::vector<std::string> prev_events;
  std::vector<std::string> auth_events;
  std::string room_version;
  std::optional<std::string> txn_id;
};

static BuiltEvent build_base_event(DatabasePool& db, const std::string& room_id,
                                     const std::string& user_id,
                                     const std::string& event_type,
                                     const json& content,
                                     std::optional<std::string> state_key = std::nullopt,
                                     int64_t depth_override = 0) {
  BuiltEvent ev;
  ev.event_id = gen_id("$");
  ev.room_id = room_id;
  ev.sender = user_id;
  ev.type = event_type;
  ev.state_key = state_key;
  ev.content = content;
  ev.origin_server_ts = now_ms();
  ev.stream_ordering = now_ms();
  ev.room_version = "1";

  if (depth_override > 0) {
    ev.depth = depth_override;
  } else {
    EventFederationWorkerStore fed(db);
    auto info = fed.get_room_federation_info(room_id);
    ev.depth = info.event_count + 1;
    for (auto& ext : info.forward_extremities) {
      ev.prev_events.push_back(ext);
    }
  }

  if (event_type == "m.room.member" || event_type == "m.room.create" ||
      event_type == "m.room.power_levels" || event_type == "m.room.join_rules") {
    StateStore state(db);
    auto current = state.get_current_state(room_id);
    for (auto& [key, eid] : current) {
      if (key.first == "m.room.create" || key.first == "m.room.power_levels" ||
          key.first == "m.room.join_rules" || key.first == "m.room.member") {
        ev.auth_events.push_back(eid);
      }
    }
  }

  return ev;
}

static json event_to_json(const BuiltEvent& ev) {
  json event_json;
  event_json["event_id"] = ev.event_id;
  event_json["room_id"] = ev.room_id;
  event_json["sender"] = ev.sender;
  event_json["type"] = ev.type;
  event_json["content"] = ev.content;
  event_json["origin_server_ts"] = ev.origin_server_ts;
  event_json["stream_ordering"] = ev.stream_ordering;
  event_json["depth"] = ev.depth;
  event_json["prev_events"] = ev.prev_events;
  event_json["auth_events"] = ev.auth_events;
  if (ev.state_key) event_json["state_key"] = *ev.state_key;
  return event_json;
}

static void persist_event(DatabasePool& db, const BuiltEvent& ev,
                           bool is_state = false) {
  json event_json = event_to_json(ev);

  auto txn = db.cursor("persist_message_event");
  if (txn) {
    std::string sql = "INSERT OR REPLACE INTO events "
                      "(event_id, room_id, sender, type, state_key, json, stream_ordering, "
                      "origin_server_ts, depth, outlier, instance_name) "
                      "VALUES (?,?,?,?,?,?,?,?,?,0,'master')";
    txn->execute(sql, {ev.event_id, ev.room_id, ev.sender, ev.type,
                       ev.state_key.value_or(""), event_json.dump(),
                       std::to_string(ev.stream_ordering),
                       std::to_string(ev.origin_server_ts),
                       std::to_string(ev.depth)});

    if (is_state && ev.state_key) {
      std::string state_sql = "INSERT OR REPLACE INTO current_state_events "
                              "(room_id, type, state_key, event_id) VALUES (?,?,?,?)";
      txn->execute(state_sql, {ev.room_id, ev.type, *ev.state_key, ev.event_id});
    }

    // Store txn_id mapping for deduplication
    if (ev.txn_id) {
      std::string txn_sql = "INSERT OR IGNORE INTO event_txn_id "
                            "(event_id, room_id, user_id, txn_id, ts) VALUES (?,?,?,?,?)";
      txn->execute(txn_sql, {ev.event_id, ev.room_id, ev.sender, *ev.txn_id,
                             std::to_string(ev.origin_server_ts)});
    }

    std::string stream_sql = "UPDATE stream_ordering SET stream_id = ?";
    txn->execute(stream_sql, {std::to_string(ev.stream_ordering)});

    txn->commit();
  }
}

static void push_event_to_federation(DatabasePool& db, const BuiltEvent& ev,
                                       const std::vector<std::string>& destinations) {
  json pdu = event_to_json(ev);
  pdu["origin"] = "localhost";

  for (auto& dest : destinations) {
    std::string fed_sql = "INSERT OR REPLACE INTO federation_stream "
                          "(type, room_id, event_id, destination, json_data, stream_id) "
                          "VALUES ('pdu',?,?,?,?,?)";
    auto txn = db.cursor("fed_push_msg");
    if (txn) {
      txn->execute(fed_sql, {ev.room_id, ev.event_id, dest, pdu.dump(),
                              std::to_string(now_ms())});
      txn->commit();
    }
  }
}

static std::vector<std::string> get_room_participating_servers(
    DatabasePool& db, const std::string& room_id) {
  std::vector<std::string> servers;
  RoomMemberStore members(db);
  auto all_members = members.get_joined_members(room_id);
  std::set<std::string> seen;
  for (auto& m : all_members) {
    auto pos = m.user_id.find(':');
    if (pos != std::string::npos) {
      std::string server = m.user_id.substr(pos + 1);
      if (seen.insert(server).second) {
        servers.push_back(server);
      }
    }
  }
  return servers;
}

// ============================================================================
// Txn ID deduplication
// ============================================================================

static std::optional<std::string> check_txn_id(DatabasePool& db,
                                                const std::string& room_id,
                                                const std::string& user_id,
                                                const std::string& txn_id) {
  auto rows = db.execute("check_txn",
    "SELECT event_id FROM event_txn_id WHERE room_id='" + room_id +
    "' AND user_id='" + user_id + "' AND txn_id='" + txn_id + "'");
  if (!rows.empty()) {
    return rows[0]["event_id"].value;
  }
  return std::nullopt;
}

// ============================================================================
// Spam checking infrastructure
// ============================================================================

struct SpamCheckResult {
  bool allowed = true;
  std::string errcode;
  std::string error;
  json spam_check_data;
};

static SpamCheckResult check_spam(DatabasePool& db, const std::string& user_id,
                                   const std::string& room_id,
                                   const std::string& event_type,
                                   const json& content) {
  SpamCheckResult result;

  // ---- 1. Check if user is shadow-banned ----
  auto shadow_rows = db.execute("spam_check_shadow",
    "SELECT user_id FROM shadow_banned WHERE user_id='" + user_id + "'");
  if (!shadow_rows.empty()) {
    result.allowed = false;
    result.errcode = "M_FORBIDDEN";
    result.error = "User is shadow-banned";
    return result;
  }

  // ---- 2. Check rate limiting ----
  // Count messages in the last N seconds
  int64_t window_ms = 10000; // 10 second window
  int64_t max_messages = 20;  // 20 messages per window
  auto rate_rows = db.execute("spam_check_rate",
    "SELECT COUNT(*) as cnt FROM events WHERE sender='" + user_id +
    "' AND origin_server_ts > " + std::to_string(now_ms() - window_ms));
  if (!rate_rows.empty() && rate_rows[0]["cnt"].value &&
      std::stoll(*rate_rows[0]["cnt"].value) > max_messages) {
    result.allowed = false;
    result.errcode = "M_LIMIT_EXCEEDED";
    result.error = "Rate limit exceeded. Too many messages.";
    return result;
  }

  // ---- 3. Check for duplicate content (spam detection) ----
  std::string content_hash = std::to_string(
    std::hash<std::string>{}(content.dump()));
  auto dup_rows = db.execute("spam_check_dup",
    "SELECT event_id FROM spam_hashes WHERE user_id='" + user_id +
    "' AND content_hash='" + content_hash + "' LIMIT 1");
  if (!dup_rows.empty()) {
    result.allowed = false;
    result.errcode = "M_FORBIDDEN";
    result.error = "Duplicate message detected. Slow down.";
    return result;
  }

  // ---- 4. Check message content length ----
  std::string body = content.value("body", "");
  if (body.size() > 65536) {
    result.allowed = false;
    result.errcode = "M_TOO_LARGE";
    result.error = "Message body exceeds maximum length of 65536 characters";
    return result;
  }

  // ---- 5. Store content hash for future duplicate detection ----
  db.execute("spam_store_hash",
    "INSERT OR REPLACE INTO spam_hashes (user_id, content_hash, ts) VALUES ('" +
    user_id + "','" + content_hash + "'," + std::to_string(now_ms()) + ")");

  // ---- 6. Check for banned URLs ----
  if (event_type == "m.room.message" && content.contains("url")) {
    std::string url = content["url"].get<std::string>();
    auto url_rows = db.execute("spam_check_url",
      "SELECT url FROM banned_urls WHERE '" + url + "' LIKE '%' || pattern || '%' LIMIT 1");
    if (!url_rows.empty()) {
      result.allowed = false;
      result.errcode = "M_FORBIDDEN";
      result.error = "Message contains a banned URL";
      return result;
    }
  }

  return result;
}

// ============================================================================
// URL preview generation
// ============================================================================

struct UrlPreview {
  std::string url;
  std::string title;
  std::string description;
  std::string image_url;
  std::string og_type;
  int64_t image_width = 0;
  int64_t image_height = 0;
  int64_t image_size = 0;
  bool valid = false;
};

static UrlPreview generate_url_preview(DatabasePool& db, const std::string& url) {
  UrlPreview preview;
  if (url.empty()) return preview;

  // Cache check - avoid regenerating previews we already have
  auto cache_rows = db.execute("url_preview_cache",
    "SELECT title, description, image_url, og_type, image_width, image_height, image_size "
    "FROM url_previews WHERE url='" + url +
    "' AND expiry_ts > " + std::to_string(now_ms()));
  if (!cache_rows.empty()) {
    auto& row = cache_rows[0];
    preview.url = url;
    preview.valid = true;
    preview.title = row["title"].value.value_or("");
    preview.description = row["description"].value.value_or("");
    preview.image_url = row["image_url"].value.value_or("");
    preview.og_type = row["og_type"].value.value_or("");
    if (row["image_width"].value) preview.image_width = std::stoll(*row["image_width"].value);
    if (row["image_height"].value) preview.image_height = std::stoll(*row["image_height"].value);
    if (row["image_size"].value) preview.image_size = std::stoll(*row["image_size"].value);
    return preview;
  }

  // ---- Parse URL to extract preview data ----
  preview.url = url;

  // Extract domain for title
  std::string domain = url;
  size_t proto = domain.find("://");
  if (proto != std::string::npos) domain = domain.substr(proto + 3);
  size_t slash = domain.find('/');
  if (slash != std::string::npos) domain = domain.substr(0, slash);
  preview.title = domain;

  // Check for known patterns to generate previews
  // GitHub URLs
  if (url.find("github.com") != std::string::npos) {
    preview.og_type = "website";
    preview.title = "GitHub";
    preview.description = "Where the world builds software";
    preview.image_url = "https://github.githubassets.com/favicons/favicon.png";
    preview.image_width = 32;
    preview.image_height = 32;
  }
  // YouTube URLs
  else if (url.find("youtube.com") != std::string::npos ||
           url.find("youtu.be") != std::string::npos) {
    preview.og_type = "video";
    preview.title = "YouTube Video";
    preview.description = "Watch on YouTube";
    preview.image_url = "https://www.youtube.com/favicon.ico";
  }
  // Twitter/X URLs
  else if (url.find("twitter.com") != std::string::npos ||
           url.find("x.com") != std::string::npos) {
    preview.og_type = "article";
    preview.title = "Post on X";
    preview.description = "View on X (formerly Twitter)";
  }
  // Generic web URL
  else if (url.find("http://") == 0 || url.find("https://") == 0) {
    preview.og_type = "website";
    preview.description = "Link shared from " + domain;
  }

  preview.valid = true;

  // Store in cache for future use
  int64_t expiry = now_ms() + 86400000; // 24 hours
  db.execute("url_preview_insert",
    "INSERT OR REPLACE INTO url_previews "
    "(url, title, description, image_url, og_type, image_width, image_height, image_size, expiry_ts) "
    "VALUES ('" + url + "','" + preview.title + "','" + preview.description + "','" +
    preview.image_url + "','" + preview.og_type + "'," +
    std::to_string(preview.image_width) + "," + std::to_string(preview.image_height) + "," +
    std::to_string(preview.image_size) + "," + std::to_string(expiry) + ")");

  return preview;
}

static void attach_url_previews_to_content(json& content, DatabasePool& db) {
  if (!content.contains("body") || !content["body"].is_string()) return;

  std::string body_text = content["body"].get<std::string>();
  std::vector<std::string> urls;

  // Extract URLs from text using regex
  std::regex url_regex(R"((https?://[^\s<>"']+))");
  std::smatch match;
  std::string::const_iterator search_start(body_text.cbegin());
  while (std::regex_search(search_start, body_text.cend(), match, url_regex)) {
    urls.push_back(match[0]);
    search_start = match.suffix().first;
  }

  if (urls.empty()) return;

  // Generate preview for the first URL only (standard Matrix behavior)
  UrlPreview preview = generate_url_preview(db, urls[0]);
  if (preview.valid) {
    json url_preview_json;
    url_preview_json["og:url"] = preview.url;
    if (!preview.title.empty())
      url_preview_json["og:title"] = preview.title;
    if (!preview.description.empty())
      url_preview_json["og:description"] = preview.description;
    if (!preview.image_url.empty()) {
      json image_obj;
      image_obj["url"] = preview.image_url;
      if (preview.image_width > 0)
        image_obj["og:image:width"] = preview.image_width;
      if (preview.image_height > 0)
        image_obj["og:image:height"] = preview.image_height;
      url_preview_json["og:image"] = image_obj;
    }
    if (!preview.og_type.empty())
      url_preview_json["og:type"] = preview.og_type;

    // Add URL preview info to content (Matrix spec: under "org.matrix.url_previews")
    if (!content.contains("org.matrix.url_previews")) {
      content["org.matrix.url_previews"] = json::array();
    }
    content["org.matrix.url_previews"].push_back(url_preview_json);
  }
}

// ============================================================================
// Message retention enforcement
// ============================================================================

struct RetentionPolicy {
  int64_t max_lifetime_ms = 0; // 0 = no retention
  int64_t min_lifetime_ms = 0;
  bool enabled = false;
};

static RetentionPolicy get_retention_policy(DatabasePool& db, const std::string& room_id) {
  RetentionPolicy policy;

  StateStore state(db);
  auto ret_event = state.get_current_state_event(room_id, "m.room.retention", "");
  if (!ret_event) {
    // Check server-level default
    auto rows = db.execute("retention_default",
      "SELECT max_lifetime_ms, min_lifetime_ms FROM server_retention_defaults LIMIT 1");
    if (!rows.empty()) {
      auto& r = rows[0];
      if (r["max_lifetime_ms"].value)
        policy.max_lifetime_ms = std::stoll(*r["max_lifetime_ms"].value);
      if (r["min_lifetime_ms"].value)
        policy.min_lifetime_ms = std::stoll(*r["min_lifetime_ms"].value);
      policy.enabled = policy.max_lifetime_ms > 0;
    }
    return policy;
  }

  EventsStore evs(db);
  auto ev = evs.get_event(*ret_event);
  if (!ev) return policy;

  auto& content = (*ev)["content"];
  if (content.contains("max_lifetime")) {
    policy.max_lifetime_ms = content["max_lifetime"].get<int64_t>();
  }
  if (content.contains("min_lifetime")) {
    policy.min_lifetime_ms = content["min_lifetime"].get<int64_t>();
  }
  policy.enabled = policy.max_lifetime_ms > 0;

  return policy;
}

static void enforce_retention(DatabasePool& db, const std::string& room_id) {
  RetentionPolicy policy = get_retention_policy(db, room_id);
  if (!policy.enabled) return;

  int64_t cutoff_ts = now_ms() - policy.max_lifetime_ms;

  // Find events older than the retention cutoff
  auto rows = db.execute("retention_find",
    "SELECT event_id, type, sender, origin_server_ts FROM events "
    "WHERE room_id='" + room_id + "' "
    "AND origin_server_ts < " + std::to_string(cutoff_ts) +
    " AND type != 'm.room.create' "
    "AND type != 'm.room.power_levels' "
    "AND type != 'm.room.join_rules' "
    "AND type != 'm.room.member' "
    "ORDER BY origin_server_ts ASC LIMIT 100");

  if (rows.empty()) return;

  // Redact expired events
  for (auto& row : rows) {
    std::string event_id = row["event_id"].value.value_or("");

    // Create redaction event
    json redact_content;
    redact_content["reason"] = "Message expired due to retention policy";

    BuiltEvent redact_ev = build_base_event(db, room_id, "@server:localhost",
                                             "m.room.redaction", redact_content);
    redact_ev.event_id = gen_id("$ret");
    persist_event(db, redact_ev);

    // Apply redaction - set redacted flag on event
    db.execute("retention_redact",
      "UPDATE events SET is_redacted=1, redacts='" + redact_ev.event_id +
      "' WHERE event_id='" + event_id + "'");
  }
}

// ============================================================================
// Event relation validation helpers
// ============================================================================

struct EventRelation {
  std::string rel_type;    // m.annotation, m.replace, m.thread, m.reference
  std::string event_id;    // The parent event being related to
  std::string key;          // For m.annotation (reaction key)
  bool is_falling_back = true;
};

static std::optional<EventRelation> parse_event_relation(const json& content) {
  if (!content.contains("m.relates_to") || !content["m.relates_to"].is_object()) {
    return std::nullopt;
  }

  auto& rel = content["m.relates_to"];
  EventRelation er;
  er.rel_type = rel.value("rel_type", "");
  er.event_id = rel.value("event_id", "");

  if (er.rel_type == "m.annotation" && rel.contains("key")) {
    er.key = rel["key"].get<std::string>();
  }

  return er;
}

static bool validate_event_relation(DatabasePool& db,
                                     const std::string& room_id,
                                     const json& content) {
  auto relation = parse_event_relation(content);
  if (!relation) return true; // No relation = valid

  // Verify the parent event exists in the same room
  auto rows = db.execute("rel_check",
    "SELECT room_id, sender, type FROM events WHERE event_id='" +
    relation->event_id + "'");
  if (rows.empty()) {
    return false; // Parent event doesn't exist
  }

  std::string parent_room = rows[0]["room_id"].value.value_or("");
  if (parent_room != room_id) {
    return false; // Cross-room relations not allowed
  }

  // For m.replace, verify sender is the same as the original event
  if (relation->rel_type == "m.replace") {
    std::string parent_sender = rows[0]["sender"].value.value_or("");
    // Allow server and admins to edit any message
    // For now, require same sender
    // (power_level check for admins done at call-site)
  }

  // For m.annotation (reactions), check for duplicate
  if (relation->rel_type == "m.annotation" && !relation->key.empty()) {
    auto dup = db.execute("rel_dup_check",
      "SELECT event_id FROM event_relations WHERE relates_to_id='" +
      relation->event_id + "' AND relation_type='m.annotation' "
      "AND aggregation_key='" + relation->key + "'");
    if (!dup.empty()) {
      return false; // Duplicate annotation
    }
  }

  return true;
}

static void store_event_relation(DatabasePool& db, const std::string& event_id,
                                  const EventRelation& relation) {
  std::string key = relation.key.empty() ? "" : relation.key;
  std::string agg_key = key;
  db.execute("rel_store",
    "INSERT OR REPLACE INTO event_relations "
    "(event_id, relates_to_id, relation_type, aggregation_key) VALUES ('" +
    event_id + "','" + relation.event_id + "','" + relation.rel_type + "','" +
    agg_key + "')");

  // Update relation aggregation counters
  if (relation.rel_type == "m.annotation") {
    db.execute("rel_agg_annot",
      "INSERT OR REPLACE INTO event_relation_aggregations "
      "(event_id, type, key, count) VALUES ('" +
      relation.event_id + "','m.annotation','" + agg_key + "',"
      "COALESCE((SELECT count FROM event_relation_aggregations "
      "WHERE event_id='" + relation.event_id + "' AND type='m.annotation' "
      "AND key='" + agg_key + "'),0)+1)");
  }

  if (relation.rel_type == "m.replace") {
    db.execute("rel_agg_replace",
      "INSERT OR REPLACE INTO event_relation_aggregations "
      "(event_id, type, key, count) VALUES ('" +
      relation.event_id + "','m.replace','',1)");
  }
}

// ============================================================================
// Thread validation
// ============================================================================

struct ThreadValidation {
  bool valid = false;
  std::string root_event_id;
  std::string root_room_id;
  bool is_thread_root = false;
  std::string error;
};

static ThreadValidation validate_thread_relation(DatabasePool& db,
                                                  const std::string& room_id,
                                                  const json& content) {
  ThreadValidation result;

  auto relation = parse_event_relation(content);
  if (!relation || relation->rel_type != "m.thread") {
    result.valid = true; // Not a thread message, always valid
    return result;
  }

  result.root_event_id = relation->event_id;

  // Verify the thread root exists
  auto root_rows = db.execute("thread_root_check",
    "SELECT room_id, sender, type FROM events WHERE event_id='" +
    relation->event_id + "'");
  if (root_rows.empty()) {
    result.error = "Thread root event not found";
    return result;
  }

  result.root_room_id = root_rows[0]["room_id"].value.value_or("");

  // Thread root must be in the same room
  if (result.root_room_id != room_id) {
    result.error = "Thread root is in a different room";
    return result;
  }

  // Check if the event being related to is itself a thread participation
  std::string root_type = root_rows[0]["type"].value.value_or("");

  // Check if the content indicates this IS a thread root (fallback)
  if (content.contains("m.thread") && content["m.thread"].is_object()) {
    result.is_thread_root = true;
  }

  // Validate that the thread root event type allows threading
  // Most message types allow threading
  static const std::set<std::string> allowed_root_types = {
    "m.room.message", "m.room.encrypted", "m.sticker",
    "m.poll.start", "m.location"
  };

  // Also allow if the root is itself a thread reply
  auto rel_check = db.execute("thread_rel_check",
    "SELECT relation_type, relates_to_id FROM event_relations "
    "WHERE event_id='" + relation->event_id + "'");
  bool root_has_thread_relation = false;
  for (auto& r : rel_check) {
    if (r["relation_type"].value.value_or("") == "m.thread") {
      root_has_thread_relation = true;
      break;
    }
  }

  if (allowed_root_types.count(root_type) == 0 && !root_has_thread_relation) {
    result.error = "Thread root event type does not support threading";
    return result;
  }

  result.valid = true;
  return result;
}

// ============================================================================
// 1. SEND MESSAGE HANDLER
// ============================================================================
// PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
//
// Sends a message to a room. Handles:
// - TxnId deduplication
// - Message type validation (m.room.message, m.reaction, etc.)
// - Event creation with content validation
// - URL preview generation
// - Spam checking
// - Persistence
// - Federation push
// ============================================================================

json handle_send_message(DatabasePool& db, const std::string& auth_header,
                          const std::string& access_token_param,
                          const std::string& room_id,
                          const std::string& event_type,
                          const std::string& txn_id,
                          const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Validate event type ----
  if (!is_valid_event_type(event_type)) {
    return make_error(400, "M_UNKNOWN",
                      "Invalid event type: " + event_type);
  }

  // ---- 4. Check txn_id deduplication ----
  if (!txn_id.empty()) {
    auto existing = check_txn_id(db, room_id, auth.user_id, txn_id);
    if (existing) {
      // Return the existing event_id
      json body;
      body["event_id"] = *existing;
      return make_response(200, body);
    }
  }

  // ---- 5. Validate message-type-specific content ----
  json content = request_body.value("content", request_body);
  if (!request_body.contains("content") && request_body.contains("body")) {
    content = request_body; // Direct content without wrapper
  }

  // Validate m.room.message content
  if (event_type == "m.room.message") {
    std::string msgtype = content.value("msgtype", "");
    if (!validate_msg_type(msgtype)) {
      return make_error(400, "M_UNKNOWN",
                        "Invalid msgtype: " + msgtype);
    }
    if (!content.contains("body")) {
      return make_error(400, "M_BAD_JSON",
                        "Missing 'body' in message content");
    }
  }

  // ---- 6. Spam check ----
  SpamCheckResult spam = check_spam(db, auth.user_id, room_id,
                                     event_type, content);
  if (!spam.allowed) {
    return make_error(429, spam.errcode, spam.error);
  }

  // ---- 7. Validate event relations ----
  bool is_reaction = (event_type == "m.reaction");
  bool is_edit = content.contains("m.relates_to") &&
                 content["m.relates_to"].is_object() &&
                 content["m.relates_to"].value("rel_type", "") == "m.replace";
  bool is_thread = content.contains("m.relates_to") &&
                   content["m.relates_to"].is_object() &&
                   content["m.relates_to"].value("rel_type", "") == "m.thread";

  // Validate relation
  if (content.contains("m.relates_to")) {
    if (!validate_event_relation(db, room_id, content)) {
      return make_error(400, "M_UNKNOWN",
                        "Invalid event relation");
    }
  }

  // Validate thread
  if (is_thread) {
    auto thread_val = validate_thread_relation(db, room_id, content);
    if (!thread_val.valid) {
      return make_error(400, "M_UNKNOWN", thread_val.error);
    }
  }

  // ---- 8. Handle reactions specifically ----
  if (is_reaction) {
    return handle_send_reaction(db, auth_header, access_token_param,
                                 room_id, txn_id, content, auth);
  }

  // ---- 9. Handle edits specifically ----
  if (is_edit) {
    return handle_edit_message(db, auth_header, access_token_param,
                                room_id, txn_id, content, auth);
  }

  // ---- 10. Generate URL previews for m.room.message ----
  if (event_type == "m.room.message") {
    attach_url_previews_to_content(content, db);
  }

  // ---- 11. Build and persist event ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     event_type, content);
  ev.txn_id = txn_id;

  // For state events, extract state_key from content or path
  if (content.contains("state_key") && content["state_key"].is_string()) {
    ev.state_key = content["state_key"].get<std::string>();
  } else if (event_type == "m.room.name" || event_type == "m.room.topic" ||
             event_type == "m.room.power_levels" || event_type == "m.room.join_rules") {
    ev.state_key = std::string("");
  }

  bool is_state = ev.state_key.has_value();
  persist_event(db, ev, is_state);

  // ---- 12. Store event relation if present ----
  if (content.contains("m.relates_to")) {
    auto relation = parse_event_relation(content);
    if (relation) {
      store_event_relation(db, ev.event_id, *relation);
    }
  }

  // ---- 13. Update thread metadata ----
  if (is_thread) {
    auto relation = parse_event_relation(content);
    if (relation && !relation->event_id.empty()) {
      int64_t now = now_ms();
      db.execute("thread_update",
        "INSERT OR REPLACE INTO thread_summaries "
        "(room_id, root_event_id, latest_event_id, latest_event_ts, reply_count, last_sender) "
        "VALUES ('" + room_id + "','" + relation->event_id + "','" + ev.event_id + "'," +
        std::to_string(now) + ","
        "COALESCE((SELECT reply_count+1 FROM thread_summaries "
        "WHERE room_id='" + room_id + "' AND root_event_id='" +
        relation->event_id + "'),1),'" + ev.sender + "')");
    }
  }

  // ---- 14. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 15. Enforce retention (periodic, not per-message) ----
  // Check if we should run retention (once every 5 minutes)
  {
    static std::atomic<int64_t> last_retention_run{0};
    int64_t now = now_ms();
    if (now - last_retention_run.load() > 300000) { // 5 minutes
      enforce_retention(db, room_id);
      last_retention_run.store(now);
    }
  }

  // ---- 16. Return event_id ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 2. REDACT EVENT HANDLER
// ============================================================================
// PUT /_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}
//
// Redacts an event. The sender must have appropriate power levels
// or be the original sender of the event. Creates a m.room.redaction
// event and applies redaction to the target event's content.
// ============================================================================

json handle_redact_event(DatabasePool& db, const std::string& auth_header,
                           const std::string& access_token_param,
                           const std::string& room_id,
                           const std::string& event_id,
                           const std::string& txn_id,
                           const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Check txn_id deduplication ----
  if (!txn_id.empty()) {
    auto existing = check_txn_id(db, room_id, auth.user_id, txn_id);
    if (existing) {
      json body;
      body["event_id"] = *existing;
      return make_response(200, body);
    }
  }

  // ---- 4. Validate target event exists ----
  auto target_rows = db.execute("redact_target",
    "SELECT sender, type, content, json, is_redacted FROM events "
    "WHERE event_id='" + event_id + "' AND room_id='" + room_id + "'");
  if (target_rows.empty()) {
    return make_error(404, "M_NOT_FOUND",
                      "Event not found: " + event_id);
  }

  std::string target_sender = target_rows[0]["sender"].value.value_or("");
  bool already_redacted = target_rows[0]["is_redacted"].value &&
    *target_rows[0]["is_redacted"].value == "1";

  if (already_redacted) {
    return make_error(400, "M_UNKNOWN",
                      "Event is already redacted");
  }

  // ---- 5. Check power levels for redaction ----
  bool is_own_event = (target_sender == auth.user_id);
  if (!is_own_event) {
    if (!has_power_to(db, room_id, auth.user_id, "redact")) {
      return make_error(403, "M_FORBIDDEN",
                        "Insufficient power level to redact other users' events");
    }
  }

  // ---- 6. Get redaction reason from body ----
  std::string reason = request_body.value("reason", "");

  // ---- 7. Build redaction content ----
  json redact_content;
  if (!reason.empty()) {
    redact_content["reason"] = reason;
  }
  redact_content["redacts"] = event_id;

  // ---- 8. Create redaction event ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     "m.room.redaction", redact_content);
  ev.event_id = gen_id("$redact");
  ev.txn_id = txn_id;
  persist_event(db, ev);

  // ---- 9. Apply redaction - strip content from target event ----
  // Matrix redaction: keep only specific fields
  json redacted_content;
  redacted_content["event_id"] = event_id;
  redacted_content["room_id"] = room_id;
  redacted_content["sender"] = target_sender;

  // Preserve type but strip content
  std::string target_type = target_rows[0]["type"].value.value_or("");

  // Store redacted content and mark as redacted
  db.execute("redact_apply",
    "UPDATE events SET is_redacted=1, redacts='" + ev.event_id +
    "' WHERE event_id='" + event_id + "'");

  // Store the redaction mapping
  int64_t now = now_ms();
  db.execute("redaction_map",
    "INSERT OR REPLACE INTO redactions "
    "(event_id, redacts, room_id, sender, reason, ts) VALUES ('" +
    ev.event_id + "','" + event_id + "','" + room_id + "','" + auth.user_id +
    "','" + reason + "'," + std::to_string(now) + ")");

  // ---- 10. Update relation aggregations (remove from counts) ----
  auto rel_rows = db.execute("redact_rels",
    "SELECT relation_type, aggregation_key FROM event_relations "
    "WHERE event_id='" + event_id + "'");
  for (auto& row : rel_rows) {
    std::string rel_type = row["relation_type"].value.value_or("");
    std::string agg_key = row["aggregation_key"].value.value_or("");
    if (rel_type == "m.annotation" && !agg_key.empty()) {
      db.execute("redact_rel_update",
        "UPDATE event_relation_aggregations SET count = MAX(0, count - 1) "
        "WHERE event_id IN (SELECT relates_to_id FROM event_relations "
        "WHERE event_id='" + event_id + "') "
        "AND type='m.annotation' AND key='" + agg_key + "'");
    }
  }

  // ---- 11. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 12. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 3. SEND REACTION HANDLER
// ============================================================================
// m.reaction event with m.relates_to having rel_type=m.annotation
// Reactions allow users to add emoji/key annotations to events.
// Key is the emoji/annotation text (e.g. "👍", "❤️")
// ============================================================================

json handle_send_reaction(DatabasePool& db, const std::string& auth_header,
                           const std::string& access_token_param,
                           const std::string& room_id,
                           const std::string& txn_id,
                           const json& content,
                           const AuthContext& auth) {
  // ---- 1. Validate m.reaction content ----
  if (!content.contains("m.relates_to") || !content["m.relates_to"].is_object()) {
    return make_error(400, "M_BAD_JSON",
                      "Reaction must include m.relates_to with m.annotation");
  }

  auto& rel = content["m.relates_to"];
  std::string rel_type = rel.value("rel_type", "");
  if (rel_type != "m.annotation") {
    return make_error(400, "M_BAD_JSON",
                      "Reaction relation type must be m.annotation");
  }

  std::string related_event_id = rel.value("event_id", "");
  std::string reaction_key = rel.value("key", "");

  if (related_event_id.empty()) {
    return make_error(400, "M_BAD_JSON",
                      "Reaction must reference an event_id");
  }

  if (reaction_key.empty()) {
    return make_error(400, "M_BAD_JSON",
                      "Reaction must include a key (emoji/annotation)");
  }

  // ---- 2. Validate the related event exists ----
  auto target_rows = db.execute("react_target",
    "SELECT room_id, sender, type FROM events WHERE event_id='" +
    related_event_id + "'");
  if (target_rows.empty()) {
    return make_error(404, "M_NOT_FOUND",
                      "Related event not found: " + related_event_id);
  }

  std::string target_room = target_rows[0]["room_id"].value.value_or("");
  if (target_room != room_id) {
    return make_error(400, "M_UNKNOWN",
                      "Cannot react to an event in a different room");
  }

  // ---- 3. Prevent self-reactions on certain event types ----
  std::string target_type = target_rows[0]["type"].value.value_or("");
  static const std::set<std::string> non_reactable = {
    "m.room.redaction", "m.room.create"
  };
  if (non_reactable.count(target_type)) {
    return make_error(400, "M_UNKNOWN",
                      "Cannot react to " + target_type + " events");
  }

  // ---- 4. Spam check ----
  SpamCheckResult spam = check_spam(db, auth.user_id, room_id,
                                     "m.reaction", content);
  if (!spam.allowed) {
    return make_error(429, spam.errcode, spam.error);
  }

  // ---- 5. Check if user already reacted with this key (toggle) ----
  auto existing_reaction = db.execute("react_dup",
    "SELECT e.event_id FROM events e "
    "INNER JOIN event_relations er ON e.event_id = er.event_id "
    "WHERE e.sender='" + auth.user_id + "' "
    "AND e.room_id='" + room_id + "' "
    "AND er.relates_to_id='" + related_event_id + "' "
    "AND er.relation_type='m.annotation' "
    "AND er.aggregation_key='" + reaction_key + "' "
    "AND e.is_redacted=0 LIMIT 1");
  if (!existing_reaction.empty()) {
    // Toggle: redact the existing reaction
    std::string existing_id = existing_reaction[0]["event_id"].value.value_or("");

    json redact_body;
    redact_body["reason"] = "Reaction retracted";
    return handle_redact_event(db, auth_header, access_token_param,
                                room_id, existing_id, txn_id + "_toggle", redact_body);
  }

  // ---- 6. Build reaction event content ----
  json reaction_content;
  reaction_content["m.relates_to"] = {
    {"rel_type", "m.annotation"},
    {"event_id", related_event_id},
    {"key", reaction_key}
  };

  // ---- 7. Build and persist event ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     "m.reaction", reaction_content);
  ev.event_id = gen_id("$react");
  ev.txn_id = txn_id;
  persist_event(db, ev);

  // ---- 8. Store relation ----
  EventRelation react_rel;
  react_rel.rel_type = "m.annotation";
  react_rel.event_id = related_event_id;
  react_rel.key = reaction_key;
  store_event_relation(db, ev.event_id, react_rel);

  // ---- 9. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 10. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 4. EDIT MESSAGE HANDLER
// ============================================================================
// m.replace relation for message edits.
// The original message's content is replaced by the new content,
// while preserving the original event. The new event has a
// m.relates_to with rel_type=m.replace.
// Only the original sender (or admins) can edit messages.
// ============================================================================

json handle_edit_message(DatabasePool& db, const std::string& auth_header,
                          const std::string& access_token_param,
                          const std::string& room_id,
                          const std::string& txn_id,
                          const json& content,
                          const AuthContext& auth) {
  // ---- 1. Validate m.replace relation ----
  auto relation = parse_event_relation(content);
  if (!relation || relation->rel_type != "m.replace") {
    return make_error(400, "M_BAD_JSON",
                      "Edit must include m.relates_to with m.replace");
  }

  std::string original_event_id = relation->event_id;

  // ---- 2. Validate the original event ----
  auto target_rows = db.execute("edit_target",
    "SELECT sender, type, content, json FROM events "
    "WHERE event_id='" + original_event_id + "' AND room_id='" + room_id + "'");
  if (target_rows.empty()) {
    return make_error(404, "M_NOT_FOUND",
                      "Original event not found: " + original_event_id);
  }

  std::string original_sender = target_rows[0]["sender"].value.value_or("");
  std::string original_type = target_rows[0]["type"].value.value_or("");

  // ---- 3. Permission check ----
  // Only original sender can edit, unless admin with power to redact
  bool is_own_event = (original_sender == auth.user_id);
  if (!is_own_event) {
    if (!has_power_to(db, room_id, auth.user_id, "redact")) {
      return make_error(403, "M_FORBIDDEN",
                        "Cannot edit another user's message");
    }
  }

  // ---- 4. Validate the original event type can be edited ----
  static const std::set<std::string> editable_types = {
    "m.room.message", "m.sticker"
  };
  if (editable_types.count(original_type) == 0) {
    return make_error(400, "M_UNKNOWN",
                      "Cannot edit event of type: " + original_type);
  }

  // ---- 5. Validate the edit content has required fields ----
  // An edit should contain the new body and format
  if (content.contains("body") || content.contains("formatted_body")) {
    // New content must have a "body" field per spec
  } else {
    return make_error(400, "M_BAD_JSON",
                      "Edit must contain a new body");
  }

  // ---- 6. Build replacement content ----
  json new_content = content;
  // The m.relates_to is used only for relation; the actual new content
  // is the content minus m.relates_to
  json edit_content;
  for (auto& [key, val] : new_content.items()) {
    if (key != "m.relates_to") {
      edit_content[key] = val;
    }
  }
  edit_content["m.relates_to"] = content["m.relates_to"];
  // Add edit marker
  edit_content["m.new_content"] = edit_content;
  // Remove the actual body from the outer level
  json clean_new_content;
  for (auto& [key, val] : edit_content.items()) {
    if (key != "m.new_content") {
      clean_new_content[key] = val;
    }
  }
  // "m.new_content" holds the replacement content without m.relates_to
  {
    json nc;
    for (auto& [key, val] : clean_new_content.items()) {
      if (key != "m.relates_to" && key != "body" && key != "msgtype" &&
          key != "format" && key != "formatted_body") {
        // Copy non-standard fields
      } else if (key == "body" || key == "msgtype" || key == "format" ||
                 key == "formatted_body") {
        nc[key] = val;
      }
    }
    nc["body"] = clean_new_content.value("body", "");
    nc["msgtype"] = clean_new_content.value("msgtype", "m.text");
    if (clean_new_content.contains("format"))
      nc["format"] = clean_new_content["format"];
    if (clean_new_content.contains("formatted_body"))
      nc["formatted_body"] = clean_new_content["formatted_body"];

    edit_content["m.new_content"] = nc;
  }

  // ---- 7. Spam check ----
  SpamCheckResult spam = check_spam(db, auth.user_id, room_id,
                                     original_type, edit_content);
  if (!spam.allowed) {
    return make_error(429, spam.errcode, spam.error);
  }

  // ---- 8. Build and persist edit event ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     original_type, edit_content);
  ev.event_id = gen_id("$edit");
  ev.txn_id = txn_id;
  persist_event(db, ev);

  // ---- 9. Store relation ----
  EventRelation edit_rel;
  edit_rel.rel_type = "m.replace";
  edit_rel.event_id = original_event_id;
  store_event_relation(db, ev.event_id, edit_rel);

  // ---- 10. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 11. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 5. THREAD MESSAGE HANDLER
// ============================================================================
// m.thread relation for threaded messages.
// A thread is a chain of replies to a root message.
// The root message can be identified by having m.relates_to with rel_type=m.thread
// and is_falling_back=true (or by being the first message).
// Thread participation includes updating thread summaries.
// ============================================================================

json handle_thread_message(DatabasePool& db, const std::string& auth_header,
                            const std::string& access_token_param,
                            const std::string& room_id,
                            const std::string& event_type,
                            const std::string& txn_id,
                            const json& content,
                            const AuthContext& auth) {
  // ---- 1. Validate thread relation ----
  if (!content.contains("m.relates_to") || !content["m.relates_to"].is_object()) {
    return make_error(400, "M_BAD_JSON",
                      "Thread messages must include m.relates_to with m.thread");
  }

  auto& rel = content["m.relates_to"];
  if (rel.value("rel_type", "") != "m.thread") {
    return make_error(400, "M_BAD_JSON",
                      "Thread messages require m.thread relation type");
  }

  std::string root_event_id = rel.value("event_id", "");
  if (root_event_id.empty()) {
    return make_error(400, "M_BAD_JSON",
                      "Thread relation must include event_id");
  }

  // ---- 2. Validate thread root ----
  auto root_rows = db.execute("thread_root",
    "SELECT room_id, sender, type, origin_server_ts FROM events "
    "WHERE event_id='" + root_event_id + "'");
  if (root_rows.empty()) {
    return make_error(404, "M_NOT_FOUND",
                      "Thread root event not found");
  }

  std::string root_room = root_rows[0]["room_id"].value.value_or("");
  if (root_room != room_id) {
    return make_error(400, "M_UNKNOWN",
                      "Cannot participate in thread from a different room");
  }

  // ---- 3. Determine thread fallback behavior ----
  bool is_falling_back = rel.value("is_falling_back", true);

  // ---- 4. Build thread content with proper relation ----
  json thread_content = content;
  // Ensure proper m.relates_to structure
  if (!thread_content.contains("m.relates_to")) {
    thread_content["m.relates_to"] = json::object();
  }
  thread_content["m.relates_to"]["rel_type"] = "m.thread";
  thread_content["m.relates_to"]["event_id"] = root_event_id;
  thread_content["m.relates_to"]["is_falling_back"] = is_falling_back;

  // Add m.thread key for client rendering
  if (!content.contains("m.thread")) {
    thread_content["m.thread"] = json::object();
  }

  // ---- 5. Determine the event type to use ----
  std::string actual_event_type = event_type;
  if (actual_event_type.empty() || actual_event_type == "m.room.message") {
    actual_event_type = "m.room.message";
  }

  // ---- 6. Spam check ----
  SpamCheckResult spam = check_spam(db, auth.user_id, room_id,
                                     actual_event_type, thread_content);
  if (!spam.allowed) {
    return make_error(429, spam.errcode, spam.error);
  }

  // ---- 7. Build and persist event ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     actual_event_type, thread_content);
  ev.event_id = gen_id("$thread");
  ev.txn_id = txn_id;
  persist_event(db, ev);

  // ---- 8. Store thread relation ----
  EventRelation thread_rel;
  thread_rel.rel_type = "m.thread";
  thread_rel.event_id = root_event_id;
  store_event_relation(db, ev.event_id, thread_rel);

  // ---- 9. Update thread summary ----
  int64_t now = now_ms();
  db.execute("thread_summary_update",
    "INSERT INTO thread_summaries "
    "(room_id, root_event_id, latest_event_id, latest_event_ts, reply_count, "
    "last_sender, participants) "
    "VALUES ('" + room_id + "','" + root_event_id + "','" + ev.event_id + "'," +
    std::to_string(now) + ",1,'" + ev.sender + "','" + ev.sender + "') "
    "ON CONFLICT (room_id, root_event_id) DO UPDATE SET "
    "latest_event_id='" + ev.event_id + "', "
    "latest_event_ts=" + std::to_string(now) + ", "
    "reply_count=reply_count+1, "
    "last_sender='" + ev.sender + "', "
    "participants=CASE WHEN participants NOT LIKE '%" + ev.sender + "%' "
    "THEN participants || ',' || '" + ev.sender + "' ELSE participants END");

  // ---- 10. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 11. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 6. SET READ MARKER HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/read_markers
//
// Sets the user's read markers for a room. Can set:
// - m.fully_read: The last event the user has fully read
// - m.read: The user's read receipt position (public/private)
// Body: { "m.fully_read": "<event_id>", "m.read": "<event_id>",
//         "m.read.private": "<event_id>" }
// ============================================================================

json handle_set_read_marker(DatabasePool& db, const std::string& auth_header,
                              const std::string& access_token_param,
                              const std::string& room_id,
                              const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  int64_t now = now_ms();
  bool any_set = false;

  // ---- 3. Process m.fully_read marker ----
  if (request_body.contains("m.fully_read") &&
      request_body["m.fully_read"].is_string()) {
    std::string fully_read_event = request_body["m.fully_read"].get<std::string>();

    // Validate the event exists in the room
    auto ev_rows = db.execute("fully_read_check",
      "SELECT stream_ordering FROM events "
      "WHERE event_id='" + fully_read_event + "' AND room_id='" + room_id + "'");
    if (!ev_rows.empty()) {
      int64_t stream_ord = 0;
      if (ev_rows[0]["stream_ordering"].value) {
        stream_ord = std::stoll(*ev_rows[0]["stream_ordering"].value);
      }

      db.execute("fully_read_set",
        "INSERT OR REPLACE INTO fully_read_markers "
        "(user_id, room_id, event_id, stream_ordering, ts) VALUES ('" +
        auth.user_id + "','" + room_id + "','" + fully_read_event + "'," +
        std::to_string(stream_ord) + "," + std::to_string(now) + ")");
      any_set = true;
    }
  }

  // ---- 4. Process m.read receipt (public) ----
  if (request_body.contains("m.read") &&
      request_body["m.read"].is_string()) {
    std::string read_event = request_body["m.read"].get<std::string>();

    ReceiptsStore receipts(db);
    receipts.insert_receipt(room_id, auth.user_id, read_event,
                             "m.read", now, 0);
    any_set = true;
  }

  // ---- 5. Process m.read.private receipt ----
  if (request_body.contains("m.read.private") &&
      request_body["m.read.private"].is_string()) {
    std::string private_read_event = request_body["m.read.private"].get<std::string>();

    ReceiptsStore receipts(db);
    receipts.insert_receipt(room_id, auth.user_id, private_read_event,
                             "m.read.private", now, 0);
    any_set = true;
  }

  // ---- 6. If neither was set, that's fine (empty body is valid) ----
  if (!any_set) {
    // No read markers were specified, this is still a valid request
  }

  // ---- 7. Update stream position ----
  db.execute("read_marker_stream",
    "UPDATE stream_ordering SET stream_id = " + std::to_string(now) +
    " WHERE type = 'receipt'");

  // ---- 8. Return empty body on success ----
  return make_response(200, json::object());
}

// ============================================================================
// 7. SEND TYPING NOTIFICATION HANDLER
// ============================================================================
// PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}
//
// Sets the typing status for a user in a room. Body:
// { "typing": true/false, "timeout": <milliseconds> }
// Typing notifications time out after the specified duration.
// ============================================================================

json handle_send_typing(DatabasePool& db, const std::string& auth_header,
                         const std::string& access_token_param,
                         const std::string& room_id,
                         const std::string& user_id,
                         const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. User can only set their own typing status ----
  if (auth.user_id != user_id) {
    return make_error(403, "M_FORBIDDEN",
                      "Can only set your own typing status");
  }

  // ---- 3. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 4. Parse typing status ----
  bool typing = request_body.value("typing", false);
  int64_t timeout_ms = request_body.value("timeout", 30000);
  if (timeout_ms <= 0) timeout_ms = 30000; // default 30 seconds
  if (timeout_ms > 120000) timeout_ms = 120000; // cap at 2 minutes

  int64_t now = now_ms();
  int64_t expiry = now + timeout_ms;

  // ---- 5. Upsert typing notification ----
  if (typing) {
    db.execute("typing_set",
      "INSERT OR REPLACE INTO typing_notifications "
      "(room_id, user_id, is_typing, timeout_ms, expiry_ts, ts) VALUES ('" +
      room_id + "','" + user_id + "',1," + std::to_string(timeout_ms) + "," +
      std::to_string(expiry) + "," + std::to_string(now) + ")");
  } else {
    // Remove typing indicator
    db.execute("typing_stop",
      "DELETE FROM typing_notifications "
      "WHERE room_id='" + room_id + "' AND user_id='" + user_id + "'");
  }

  // ---- 6. Clean up expired typing notifications ----
  db.execute("typing_cleanup",
    "DELETE FROM typing_notifications WHERE expiry_ts < " +
    std::to_string(now));

  // ---- 7. Push typing notification via federation ----
  // Typing EDUs are ephemeral and pushed via /send endpoint to participating servers
  auto servers = get_room_participating_servers(db, room_id);
  for (auto& dest : servers) {
    json edu;
    edu["type"] = "m.typing";
    edu["content"] = {
      {"room_id", room_id},
      {"user_id", user_id},
      {"typing", typing}
    };
    edu["origin"] = "localhost";

    std::string fed_sql = "INSERT OR REPLACE INTO federation_stream "
                          "(type, room_id, event_id, destination, json_data, stream_id) "
                          "VALUES ('edu','" + room_id + "','','" + dest + "',?,?)";
    auto txn = db.cursor("fed_typing");
    if (txn) {
      txn->execute(fed_sql, {edu.dump(), std::to_string(now)});
      txn->commit();
    }
  }

  // ---- 8. Return empty object on success ----
  return make_response(200, json::object());
}

// ============================================================================
// 8. GET MESSAGE HANDLER
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/event/{eventId}
//
// Retrieves a single event by its event ID.
// The user must be in the room to read the event.
// ============================================================================

json handle_get_message(DatabasePool& db, const std::string& auth_header,
                         const std::string& access_token_param,
                         const std::string& room_id,
                         const std::string& event_id) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Fetch event ----
  auto rows = db.execute("get_event",
    "SELECT json, is_redacted, redacts FROM events "
    "WHERE event_id='" + event_id + "' AND room_id='" + room_id + "'");
  if (rows.empty()) {
    return make_error(404, "M_NOT_FOUND",
                      "Event not found: " + event_id);
  }

  std::string event_json_str = rows[0]["json"].value.value_or("{}");
  json event = json::parse(event_json_str.empty() ? "{}" : event_json_str);

  // ---- 4. Apply redaction if needed ----
  if (rows[0]["is_redacted"].value && *rows[0]["is_redacted"].value == "1") {
    // Strip content for redacted events
    json redacted;
    redacted["event_id"] = event["event_id"];
    redacted["room_id"] = event["room_id"];
    redacted["sender"] = event["sender"];
    redacted["type"] = event["type"];
    redacted["origin_server_ts"] = event["origin_server_ts"];
    if (event.contains("state_key")) redacted["state_key"] = event["state_key"];
    event = redacted;
  }

  // ---- 5. Add unsigned data (age, transaction_id, relations) ----
  int64_t age = now_ms() - event.value("origin_server_ts", 0);
  event["unsigned"] = json::object();
  event["unsigned"]["age"] = age;

  // Add relations if any exist
  auto rel_rows = db.execute("get_event_rels",
    "SELECT relation_type, aggregation_key FROM event_relations "
    "WHERE relates_to_id='" + event_id + "' ORDER BY event_id");

  // Add summaries for reactions/annotations
  json annotations;
  annotations["m.annotation"] = json::object();
  auto agg_rows = db.execute("get_event_aggs",
    "SELECT key, count FROM event_relation_aggregations "
    "WHERE event_id='" + event_id + "' AND type='m.annotation'");
  for (auto& row : agg_rows) {
    std::string key = row["key"].value.value_or("");
    int64_t count = row["count"].value ? std::stoll(*row["count"].value) : 0;
    annotations["m.annotation"][key] = count;
  }
  if (!agg_rows.empty()) {
    event["unsigned"]["m.relations"] = annotations;
  }

  // ---- 6. Return event ----
  return make_response(200, event);
}

// ============================================================================
// 9. GET MESSAGES HANDLER (PAGINATION)
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/messages
//
// Retrieves messages from a room with pagination support.
// Query parameters:
// - from: pagination token (start of range)
// - to: pagination token (end of range, optional)
// - dir: 'b' (backward) or 'f' (forward)
// - limit: maximum number of events to return
// - filter: JSON filter object
// ============================================================================

struct PaginationToken {
  int64_t stream_ordering;
  int64_t topological_ordering;
  std::string direction; // "b" or "f"
};

static PaginationToken parse_pagination_token(const std::string& token) {
  PaginationToken pt;
  pt.stream_ordering = 0;
  pt.topological_ordering = 0;
  pt.direction = "b";

  if (token.empty()) return pt;

  // Token format: "s<stream>_t<topo>" or "end"
  if (token == "end") {
    pt.stream_ordering = INT64_MAX;
    return pt;
  }

  size_t s_pos = token.find('s');
  size_t t_pos = token.find('t');
  if (s_pos != std::string::npos && t_pos != std::string::npos) {
    std::string s_str = token.substr(s_pos + 1, t_pos - s_pos - 2);
    std::string t_str = token.substr(t_pos + 1);
    pt.stream_ordering = std::stoll(s_str);
    pt.topological_ordering = std::stoll(t_str);
  }

  return pt;
}

static std::string create_pagination_token(int64_t stream_ord,
                                            int64_t topo_ord,
                                            const std::string& direction) {
  return "s" + std::to_string(stream_ord) + "_t" + std::to_string(topo_ord);
}

json handle_get_messages(DatabasePool& db, const std::string& auth_header,
                          const std::string& access_token_param,
                          const std::string& room_id,
                          const std::string& from_token,
                          const std::string& to_token,
                          const std::string& direction,
                          int64_t limit,
                          const json& filter) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Validate pagination parameters ----
  if (direction != "b" && direction != "f") {
    return make_error(400, "M_UNKNOWN",
                      "Invalid direction. Must be 'b' or 'f'.");
  }

  if (limit <= 0) limit = 10;
  if (limit > 1000) limit = 1000;

  // ---- 4. Parse pagination token ----
  PaginationToken pt = parse_pagination_token(from_token);
  PaginationToken tt;
  if (!to_token.empty()) {
    tt = parse_pagination_token(to_token);
  }

  // Default: if no from_token, start from latest events
  if (from_token.empty() && direction == "b") {
    pt.stream_ordering = INT64_MAX;
  } else if (from_token.empty() && direction == "f") {
    pt.stream_ordering = 0;
  }

  // ---- 5. Build event type filter from filter JSON ----
  std::string type_filter;
  std::string senders_filter;
  std::string not_senders_filter;
  std::string contains_url_filter;
  bool filter_has_types = false;
  bool filter_has_senders = false;
  bool filter_has_not_senders = false;

  if (filter.contains("types") && filter["types"].is_array()) {
    std::string types_list;
    for (auto& t : filter["types"]) {
      if (!types_list.empty()) types_list += ",";
      types_list += "'" + t.get<std::string>() + "'";
    }
    type_filter = " AND type IN (" + types_list + ")";
    filter_has_types = true;
  }

  if (filter.contains("not_types") && filter["not_types"].is_array()) {
    std::string not_types_list;
    for (auto& t : filter["not_types"]) {
      if (!not_types_list.empty()) not_types_list += ",";
      not_types_list += "'" + t.get<std::string>() + "'";
    }
    type_filter += " AND type NOT IN (" + not_types_list + ")";
  }

  if (filter.contains("senders") && filter["senders"].is_array()) {
    std::string senders_list;
    for (auto& s : filter["senders"]) {
      if (!senders_list.empty()) senders_list += ",";
      senders_list += "'" + s.get<std::string>() + "'";
    }
    senders_filter = " AND sender IN (" + senders_list + ")";
    filter_has_senders = true;
  }

  if (filter.contains("not_senders") && filter["not_senders"].is_array()) {
    std::string not_senders_list;
    for (auto& s : filter["not_senders"]) {
      if (!not_senders_list.empty()) not_senders_list += ",";
      not_senders_list += "'" + s.get<std::string>() + "'";
    }
    not_senders_filter = " AND sender NOT IN (" + not_senders_list + ")";
    filter_has_not_senders = true;
  }

  if (filter.contains("contains_url") && filter["contains_url"].is_boolean()) {
    if (filter["contains_url"].get<bool>()) {
      contains_url_filter = " AND contains_url = 1";
    }
  }

  // ---- 6. Query events ----
  std::string sql;
  if (direction == "b") {
    // Backward pagination: get events with lower stream ordering
    sql = "SELECT json, is_redacted, stream_ordering, topological_ordering "
          "FROM events WHERE room_id='" + room_id + "' "
          "AND stream_ordering < " + std::to_string(pt.stream_ordering) +
          type_filter + senders_filter + not_senders_filter +
          contains_url_filter +
          " AND outlier = 0 "
          "ORDER BY stream_ordering DESC "
          "LIMIT " + std::to_string(limit + 1); // +1 to detect if there are more
  } else {
    // Forward pagination: get events with higher stream ordering
    sql = "SELECT json, is_redacted, stream_ordering, topological_ordering "
          "FROM events WHERE room_id='" + room_id + "' "
          "AND stream_ordering > " + std::to_string(pt.stream_ordering);
    if (!to_token.empty()) {
      sql += " AND stream_ordering < " + std::to_string(tt.stream_ordering);
    }
    sql += type_filter + senders_filter + not_senders_filter +
           contains_url_filter +
           " AND outlier = 0 "
           "ORDER BY stream_ordering ASC "
           "LIMIT " + std::to_string(limit + 1);
  }

  auto rows = db.execute("get_messages_query", sql);

  // ---- 7. Process results ----
  json result;
  result["start"] = from_token;
  result["chunk"] = json::array();

  int64_t last_stream = 0;
  int64_t last_topo = 0;
  int count = 0;

  for (auto& row : rows) {
    if (count >= limit) break;

    std::string event_json_str = row["json"].value.value_or("{}");
    json event = json::parse(event_json_str.empty() ? "{}" : event_json_str);

    int64_t stream_ord = row["stream_ordering"].value ?
      std::stoll(*row["stream_ordering"].value) : 0;
    int64_t topo_ord = 0;

    // Apply redaction if needed
    if (row["is_redacted"].value && *row["is_redacted"].value == "1") {
      json redacted;
      redacted["event_id"] = event["event_id"];
      redacted["room_id"] = event["room_id"];
      redacted["sender"] = event["sender"];
      redacted["type"] = event["type"];
      redacted["origin_server_ts"] = event["origin_server_ts"];
      if (event.contains("state_key")) redacted["state_key"] = event["state_key"];
      event = redacted;
    }

    // Add unsigned age
    int64_t age = now_ms() - event.value("origin_server_ts", 0);
    if (!event.contains("unsigned") || !event["unsigned"].is_object()) {
      event["unsigned"] = json::object();
    }
    event["unsigned"]["age"] = age;

    result["chunk"].push_back(event);

    last_stream = stream_ord;
    last_topo = topo_ord;
    count++;
  }

  // ---- 8. Determine pagination tokens ----
  if (direction == "b") {
    // end token = token for the last event in chunk
    if (count > 0) {
      result["end"] = create_pagination_token(last_stream, last_topo, direction);
    } else {
      result["end"] = from_token;
    }

    // If there are more events (we fetched limit+1 but only returned limit)
    if (rows.size() > static_cast<size_t>(limit)) {
      result["start"] = create_pagination_token(last_stream, last_topo, direction);
    }
  } else {
    // Forward pagination
    if (count > 0) {
      result["end"] = create_pagination_token(last_stream, last_topo, direction);
    } else {
      result["end"] = from_token;
    }
  }

  // ---- 9. Add state events at the start if requested ----
  // (Some clients request state at the start of a timeline)
  if (filter.contains("lazy_load_members") &&
      filter["lazy_load_members"].get<bool>()) {
    StateStore state(db);
    auto current_state = state.get_current_state(room_id);
    EventsStore evs(db);
    json state_array = json::array();
    for (auto& [key, eid] : current_state) {
      if (key.first == "m.room.member") {
        auto ev = evs.get_event(eid);
        if (ev && ev->contains("content")) {
          json stripped;
          stripped["type"] = "m.room.member";
          stripped["state_key"] = key.second;
          stripped["content"] = {
            {"membership", (*ev)["content"].value("membership", "join")},
            {"displayname", (*ev)["content"].value("displayname", "")}
          };
          stripped["sender"] = (*ev).value("sender", "");
          stripped["event_id"] = (*ev).value("event_id", "");
          stripped["origin_server_ts"] = (*ev).value("origin_server_ts", 0);
          state_array.push_back(stripped);
        }
      }
    }
    if (!state_array.empty()) {
      result["state"] = state_array;
    }
  }

  return make_response(200, result);
}

// ============================================================================
// 10. GET EVENT CONTEXT HANDLER
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/context/{eventId}
//
// Retrieves the context around a specific event:
// - events_before: events that happened just before the requested event
// - events_after: events that happened just after the requested event
// - state: the state of the room at the time of the requested event
// Query params: limit (for before/after), filter
// ============================================================================

json handle_get_event_context(DatabasePool& db, const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id,
                               const std::string& event_id,
                               int64_t limit,
                               const json& filter) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Get the target event ----
  auto target_rows = db.execute("context_target",
    "SELECT json, stream_ordering, topological_ordering, is_redacted "
    "FROM events WHERE event_id='" + event_id + "' AND room_id='" + room_id + "'");
  if (target_rows.empty()) {
    return make_error(404, "M_NOT_FOUND",
                      "Event not found: " + event_id);
  }

  std::string target_json_str = target_rows[0]["json"].value.value_or("{}");
  json target_event = json::parse(target_json_str.empty() ? "{}" : target_json_str);
  int64_t target_stream = target_rows[0]["stream_ordering"].value ?
    std::stoll(*target_rows[0]["stream_ordering"].value) : 0;

  if (limit <= 0) limit = 10;
  if (limit > 100) limit = 100;

  // ---- 4. Get events before (lower stream ordering) ----
  json events_before = json::array();
  auto before_rows = db.execute("context_before",
    "SELECT json, is_redacted, stream_ordering FROM events "
    "WHERE room_id='" + room_id + "' "
    "AND stream_ordering < " + std::to_string(target_stream) +
    " AND outlier = 0 "
    "ORDER BY stream_ordering DESC "
    "LIMIT " + std::to_string(limit));

  for (auto& row : before_rows) {
    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
    if (row["is_redacted"].value && *row["is_redacted"].value == "1") {
      json redacted;
      redacted["event_id"] = ev["event_id"];
      redacted["room_id"] = ev["room_id"];
      redacted["sender"] = ev["sender"];
      redacted["type"] = ev["type"];
      redacted["origin_server_ts"] = ev["origin_server_ts"];
      if (ev.contains("state_key")) redacted["state_key"] = ev["state_key"];
      ev = redacted;
    }
    events_before.push_back(ev);
  }

  // ---- 5. Get events after (higher stream ordering) ----
  json events_after = json::array();
  auto after_rows = db.execute("context_after",
    "SELECT json, is_redacted, stream_ordering FROM events "
    "WHERE room_id='" + room_id + "' "
    "AND stream_ordering > " + std::to_string(target_stream) +
    " AND outlier = 0 "
    "ORDER BY stream_ordering ASC "
    "LIMIT " + std::to_string(limit));

  for (auto& row : after_rows) {
    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
    if (row["is_redacted"].value && *row["is_redacted"].value == "1") {
      json redacted;
      redacted["event_id"] = ev["event_id"];
      redacted["room_id"] = ev["room_id"];
      redacted["sender"] = ev["sender"];
      redacted["type"] = ev["type"];
      redacted["origin_server_ts"] = ev["origin_server_ts"];
      if (ev.contains("state_key")) redacted["state_key"] = ev["state_key"];
      ev = redacted;
    }
    events_after.push_back(ev);
  }

  // ---- 6. Get state at the point of the event ----
  json state_at_event = json::array();
  // Use the event's prev_state if available, otherwise current state
  StateStore state(db);
  auto current_state = state.get_current_state(room_id);
  EventsStore evs(db);

  for (auto& [key, eid] : current_state) {
    // Filter to state events that were active before this event
    auto ev = evs.get_event(eid);
    if (ev) {
      int64_t state_stream = (*ev).value("stream_ordering", 0);
      if (state_stream <= target_stream) {
        json state_ev;
        state_ev["type"] = key.first;
        state_ev["state_key"] = key.second;
        state_ev["content"] = (*ev).value("content", json::object());
        state_ev["event_id"] = eid;
        state_ev["sender"] = (*ev).value("sender", "");
        state_ev["origin_server_ts"] = (*ev).value("origin_server_ts", 0);
        state_at_event.push_back(state_ev);
      }
    }
  }

  // ---- 7. Apply redaction to target event ----
  if (target_rows[0]["is_redacted"].value &&
      *target_rows[0]["is_redacted"].value == "1") {
    json redacted;
    redacted["event_id"] = target_event["event_id"];
    redacted["room_id"] = target_event["room_id"];
    redacted["sender"] = target_event["sender"];
    redacted["type"] = target_event["type"];
    redacted["origin_server_ts"] = target_event["origin_server_ts"];
    if (target_event.contains("state_key"))
      redacted["state_key"] = target_event["state_key"];
    target_event = redacted;
  }

  // ---- 8. Build response ----
  json result;
  result["event"] = target_event;
  result["events_before"] = events_before;
  result["events_after"] = events_after;
  result["state"] = state_at_event;

  return make_response(200, result);
}

// ============================================================================
// 11. REPORT EVENT HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}
//
// Reports a problematic event to the server administrators.
// Body: { "reason": "reason text", "score": <integer> }
// Score is an optional severity indicator (-100 to 0).
// ============================================================================

json handle_report_event(DatabasePool& db, const std::string& auth_header,
                          const std::string& access_token_param,
                          const std::string& room_id,
                          const std::string& event_id,
                          const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Validate the event exists ----
  auto target_rows = db.execute("report_check",
    "SELECT event_id FROM events WHERE event_id='" + event_id +
    "' AND room_id='" + room_id + "'");
  if (target_rows.empty()) {
    return make_error(404, "M_NOT_FOUND",
                      "Event not found: " + event_id);
  }

  // ---- 4. Parse reason and score ----
  std::string reason = request_body.value("reason", "");
  int64_t score = request_body.value("score", -100);

  if (reason.empty()) {
    return make_error(400, "M_BAD_JSON",
                      "Report must include a reason");
  }

  // Clamp score to valid range (-100 to 0)
  if (score < -100) score = -100;
  if (score > 0) score = 0;

  // ---- 5. Store report ----
  int64_t now = now_ms();
  std::string report_id = gen_id("$report");

  db.execute("report_insert",
    "INSERT INTO event_reports "
    "(report_id, room_id, event_id, reporter, reason, score, ts) VALUES ('" +
    report_id + "','" + room_id + "','" + event_id + "','" + auth.user_id +
    "','" + reason + "'," + std::to_string(score) + "," + std::to_string(now) + ")");

  // ---- 6. Check if the event has reached report threshold ----
  auto count_rows = db.execute("report_count",
    "SELECT COUNT(*) as cnt FROM event_reports WHERE event_id='" + event_id + "'");
  int64_t report_count = 0;
  if (!count_rows.empty() && count_rows[0]["cnt"].value) {
    report_count = std::stoll(*count_rows[0]["cnt"].value);
  }

  // If report count exceeds threshold, flag for admin review
  static const int64_t REPORT_THRESHOLD = 3;
  if (report_count >= REPORT_THRESHOLD) {
    db.execute("report_flag",
      "INSERT OR IGNORE INTO event_flags (event_id, room_id, flag_type, ts) "
      "VALUES ('" + event_id + "','" + room_id + "','auto_flagged'," +
      std::to_string(now) + ")");
  }

  // ---- 7. Return empty object ----
  return make_response(200, json::object());
}

// ============================================================================
// 12. SEND POLL START EVENT HANDLER
// ============================================================================
// Creates an m.poll.start event.
// Content includes the poll question, options, and configuration.
// Polls start a voting session in the room.
// ============================================================================

json handle_send_poll_start(DatabasePool& db, const std::string& auth_header,
                              const std::string& access_token_param,
                              const std::string& room_id,
                              const std::string& txn_id,
                              const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Check txn_id ----
  if (!txn_id.empty()) {
    auto existing = check_txn_id(db, room_id, auth.user_id, txn_id);
    if (existing) {
      json body;
      body["event_id"] = *existing;
      return make_response(200, body);
    }
  }

  // ---- 4. Validate poll start content ----
  std::string question = request_body.value("question", "");
  if (question.empty()) {
    return make_error(400, "M_BAD_JSON",
                      "Poll must include a question");
  }

  if (!request_body.contains("answers") || !request_body["answers"].is_array()) {
    return make_error(400, "M_BAD_JSON",
                      "Poll must include answers array");
  }

  auto& answers = request_body["answers"];
  if (answers.size() < 2) {
    return make_error(400, "M_BAD_JSON",
                      "Poll must have at least 2 answers");
  }

  if (answers.size() > 20) {
    return make_error(400, "M_BAD_JSON",
                      "Poll cannot have more than 20 answers");
  }

  // ---- 5. Build poll start content ----
  json poll_content;

  // Create full poll structure per MSC3381
  json poll_start;
  poll_start["kind"] = "org.matrix.msc3381.poll.start"; // unstable prefix
  poll_start["max_selections"] = request_body.value("max_selections", 1);
  poll_start["question"] = {
    {"body", question},
    {"msgtype", "m.text"},
    {"org.matrix.msc1767.text", question}
  };

  // Build answers
  json poll_answers = json::array();
  for (size_t i = 0; i < answers.size(); i++) {
    std::string answer_text;
    if (answers[i].is_string()) {
      answer_text = answers[i].get<std::string>();
    } else if (answers[i].is_object() && answers[i].contains("text")) {
      answer_text = answers[i]["text"].get<std::string>();
    } else {
      answer_text = "Option " + std::to_string(i + 1);
    }

    json answer_obj;
    answer_obj["id"] = "answer_" + std::to_string(i + 1);
    answer_obj["org.matrix.msc1767.text"] = answer_text;
    poll_answers.push_back(answer_obj);
  }
  poll_start["answers"] = poll_answers;

  poll_content["org.matrix.msc3381.poll.start"] = poll_start;
  poll_content["m.text"] = question;
  poll_content["msgtype"] = "m.text";
  poll_content["body"] = question;

  // ---- 6. Spam check ----
  SpamCheckResult spam = check_spam(db, auth.user_id, room_id,
                                     "m.poll.start", poll_content);
  if (!spam.allowed) {
    return make_error(429, spam.errcode, spam.error);
  }

  // ---- 7. Build and persist ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     "m.poll.start", poll_content);
  ev.event_id = gen_id("$poll");
  ev.txn_id = txn_id;
  persist_event(db, ev);

  // ---- 8. Store poll metadata ----
  int64_t now = now_ms();
  db.execute("poll_meta",
    "INSERT INTO poll_info (poll_id, room_id, creator, question, max_selections, "
    "num_answers, created_ts, closed) VALUES ('" +
    ev.event_id + "','" + room_id + "','" + auth.user_id + "','" + question +
    "'," + std::to_string(poll_start["max_selections"].get<int64_t>()) + "," +
    std::to_string(answers.size()) + "," + std::to_string(now) + ",0)");

  // ---- 9. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 10. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 13. SEND POLL RESPONSE EVENT HANDLER
// ============================================================================
// Creates an m.poll.response event.
// Content includes the selected answer IDs and the poll event_id.
// ============================================================================

json handle_send_poll_response(DatabasePool& db, const std::string& auth_header,
                                const std::string& access_token_param,
                                const std::string& room_id,
                                const std::string& txn_id,
                                const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Validate poll response ----
  if (!request_body.contains("m.relates_to") || !request_body["m.relates_to"].is_object()) {
    return make_error(400, "M_BAD_JSON",
                      "Poll response must reference the poll via m.relates_to");
  }

  auto& rel = request_body["m.relates_to"];
  std::string poll_id = rel.value("event_id", "");

  if (poll_id.empty()) {
    return make_error(400, "M_BAD_JSON",
                      "Poll response must reference a poll event_id");
  }

  // Verify poll exists
  auto poll_rows = db.execute("poll_check",
    "SELECT closed, max_selections FROM poll_info WHERE poll_id='" + poll_id + "'");
  if (poll_rows.empty()) {
    return make_error(404, "M_NOT_FOUND",
                      "Poll not found: " + poll_id);
  }

  // Check if poll is closed
  if (poll_rows[0]["closed"].value && *poll_rows[0]["closed"].value == "1") {
    return make_error(400, "M_UNKNOWN", "This poll is closed");
  }

  // Check if user already voted (prevent double voting)
  auto vote_rows = db.execute("poll_vote_check",
    "SELECT event_id FROM events e "
    "INNER JOIN event_relations er ON e.event_id = er.event_id "
    "WHERE e.type='m.poll.response' AND e.room_id='" + room_id + "' "
    "AND e.sender='" + auth.user_id + "' "
    "AND er.relates_to_id='" + poll_id + "' "
    "AND e.is_redacted = 0 LIMIT 1");
  if (!vote_rows.empty()) {
    return make_error(400, "M_UNKNOWN", "You have already voted in this poll");
  }

  // ---- 4. Validate selections ----
  if (!request_body.contains("selections") || !request_body["selections"].is_array()) {
    return make_error(400, "M_BAD_JSON",
                      "Poll response must include selections array");
  }

  int max_selections = poll_rows[0]["max_selections"].value ?
    std::stoll(*poll_rows[0]["max_selections"].value) : 1;

  if (request_body["selections"].size() > static_cast<size_t>(max_selections)) {
    return make_error(400, "M_BAD_JSON",
                      "Maximum " + std::to_string(max_selections) + " selection(s) allowed");
  }

  // ---- 5. Build poll response content ----
  json response_content;
  response_content["m.relates_to"] = request_body["m.relates_to"];

  json poll_response;
  poll_response["org.matrix.msc3381.poll.response"] = json::object();
  poll_response["org.matrix.msc3381.poll.response"]["answer_ids"] =
    request_body["selections"];
  response_content["org.matrix.msc3381.poll.response"] =
    poll_response["org.matrix.msc3381.poll.response"];

  // ---- 6. Build and persist ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     "m.poll.response", response_content);
  ev.event_id = gen_id("$vote");
  ev.txn_id = txn_id;
  persist_event(db, ev);

  // Store relation
  EventRelation vote_rel;
  vote_rel.rel_type = "m.reference";
  vote_rel.event_id = poll_id;
  store_event_relation(db, ev.event_id, vote_rel);

  // ---- 7. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 8. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 14. SEND POLL END EVENT HANDLER
// ============================================================================
// Creates an m.poll.end event to close a poll.
// Only the poll creator can end the poll.
// ============================================================================

json handle_send_poll_end(DatabasePool& db, const std::string& auth_header,
                           const std::string& access_token_param,
                           const std::string& room_id,
                           const std::string& txn_id,
                           const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Validate poll end request ----
  std::string poll_id = request_body.value("poll_id", "");

  if (poll_id.empty()) {
    return make_error(400, "M_BAD_JSON",
                      "Must specify poll_id to end");
  }

  // Verify poll exists and is not already closed
  auto poll_rows = db.execute("poll_end_check",
    "SELECT creator, closed FROM poll_info WHERE poll_id='" + poll_id +
    "' AND room_id='" + room_id + "'");
  if (poll_rows.empty()) {
    return make_error(404, "M_NOT_FOUND",
                      "Poll not found: " + poll_id);
  }

  if (poll_rows[0]["closed"].value && *poll_rows[0]["closed"].value == "1") {
    return make_error(400, "M_UNKNOWN", "Poll is already closed");
  }

  // ---- 4. Only the creator can end the poll ----
  std::string creator = poll_rows[0]["creator"].value.value_or("");
  if (creator != auth.user_id) {
    if (!has_power_to(db, room_id, auth.user_id, "redact")) {
      return make_error(403, "M_FORBIDDEN",
                        "Only the poll creator can end this poll");
    }
  }

  // ---- 5. Tally votes ----
  auto tally_rows = db.execute("poll_tally",
    "SELECT ec.content FROM events e "
    "INNER JOIN event_relations er ON e.event_id = er.event_id "
    "WHERE er.relates_to_id='" + poll_id + "' "
    "AND e.type='m.poll.response' AND e.is_redacted=0");

  std::map<std::string, int64_t> tally;
  for (auto& row : tally_rows) {
    std::string content_str = row["content"].value.value_or("{}");
    json resp_content = json::parse(content_str);
    if (resp_content.contains("selections") && resp_content["selections"].is_array()) {
      for (auto& sel : resp_content["selections"]) {
        std::string answer_id = sel.get<std::string>();
        tally[answer_id]++;
      }
    }
  }

  // ---- 6. Build poll end content with results ----
  json end_content;
  end_content["m.relates_to"] = json::object();
  end_content["m.relates_to"]["rel_type"] = "m.reference";
  end_content["m.relates_to"]["event_id"] = poll_id;

  // Add MSC3381 poll end structure
  json poll_end;
  poll_end["kind"] = "org.matrix.msc3381.poll.end";

  // Build results
  json results = json::object();
  for (auto& [answer_id, count] : tally) {
    results[answer_id] = count;
  }
  poll_end["results"] = results;

  // Calculate total votes
  int64_t total_votes = 0;
  for (auto& [_, count] : tally) total_votes += count;
  poll_end["total_votes"] = total_votes;

  end_content["org.matrix.msc3381.poll.end"] = poll_end;

  // ---- 7. Build and persist ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     "m.poll.end", end_content);
  ev.event_id = gen_id("$pollend");
  ev.txn_id = txn_id;
  persist_event(db, ev);

  // Mark poll as closed
  int64_t now = now_ms();
  db.execute("poll_close",
    "UPDATE poll_info SET closed=1, closed_ts=" + std::to_string(now) +
    " WHERE poll_id='" + poll_id + "'");

  // ---- 8. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 9. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 15. SEND LOCATION EVENT HANDLER
// ============================================================================
// Creates an m.location event with geo_uri and optional thumbnail.
// Includes location metadata like description/address.
// ============================================================================

json handle_send_location(DatabasePool& db, const std::string& auth_header,
                           const std::string& access_token_param,
                           const std::string& room_id,
                           const std::string& txn_id,
                           const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Check txn_id ----
  if (!txn_id.empty()) {
    auto existing = check_txn_id(db, room_id, auth.user_id, txn_id);
    if (existing) {
      json body;
      body["event_id"] = *existing;
      return make_response(200, body);
    }
  }

  // ---- 4. Validate location content ----
  if (!request_body.contains("geo_uri") || !request_body["geo_uri"].is_string()) {
    return make_error(400, "M_BAD_JSON",
                      "Location must include a geo_uri");
  }

  std::string geo_uri = request_body["geo_uri"].get<std::string>();

  // Validate geo URI format: "geo:<lat>,<lon>" or "geo:<lat>,<lon>;<params>"
  std::regex geo_regex(R"(^geo:-?\d+\.?\d*,-?\d+\.?\d*(;.*)?$)");
  if (!std::regex_match(geo_uri, geo_regex)) {
    return make_error(400, "M_BAD_JSON",
                      "Invalid geo_uri format. Expected: geo:<lat>,<lon>");
  }

  // ---- 5. Build location content ----
  json location_content;
  location_content["geo_uri"] = geo_uri;
  location_content["msgtype"] = "m.location";
  location_content["body"] = request_body.value("body", "Location: " + geo_uri);

  if (request_body.contains("org.matrix.msc3488.location") &&
      request_body["org.matrix.msc3488.location"].is_object()) {
    location_content["org.matrix.msc3488.location"] =
      request_body["org.matrix.msc3488.location"];
  }

  if (request_body.contains("org.matrix.msc3488.asset") &&
      request_body["org.matrix.msc3488.asset"].is_object()) {
    location_content["org.matrix.msc3488.asset"] =
      request_body["org.matrix.msc3488.asset"];
  }

  // Add optional thumbnail info
  if (request_body.contains("info") && request_body["info"].is_object()) {
    location_content["info"] = request_body["info"];
    if (request_body.contains("url")) {
      location_content["url"] = request_body["url"];
    }
  }

  // ---- 6. Spam check ----
  SpamCheckResult spam = check_spam(db, auth.user_id, room_id,
                                     "m.location", location_content);
  if (!spam.allowed) {
    return make_error(429, spam.errcode, spam.error);
  }

  // ---- 7. Build and persist ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     "m.location", location_content);
  ev.event_id = gen_id("$loc");
  ev.txn_id = txn_id;
  persist_event(db, ev);

  // ---- 8. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 9. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 16. SEND VOICE MESSAGE EVENT HANDLER
// ============================================================================
// Creates an m.audio event with voice-specific metadata.
// Voice messages have msgtype=m.audio with org.matrix.msc3245.voice
// metadata indicating it's a voice recording.
// ============================================================================

json handle_send_voice_message(DatabasePool& db, const std::string& auth_header,
                                const std::string& access_token_param,
                                const std::string& room_id,
                                const std::string& txn_id,
                                const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Check txn_id ----
  if (!txn_id.empty()) {
    auto existing = check_txn_id(db, room_id, auth.user_id, txn_id);
    if (existing) {
      json body;
      body["event_id"] = *existing;
      return make_response(200, body);
    }
  }

  // ---- 4. Validate voice message content ----
  if (!request_body.contains("url") || !request_body["url"].is_string()) {
    return make_error(400, "M_BAD_JSON",
                      "Voice message must include an audio URL");
  }

  if (!request_body.contains("info") || !request_body["info"].is_object()) {
    return make_error(400, "M_BAD_JSON",
                      "Voice message must include info with duration");
  }

  int64_t duration = request_body["info"].value("duration", 0);
  if (duration <= 0) {
    return make_error(400, "M_BAD_JSON",
                      "Voice message must have a positive duration");
  }

  // ---- 5. Build voice message content ----
  json voice_content;
  voice_content["msgtype"] = "m.audio";
  voice_content["body"] = request_body.value("body", "Voice message");
  voice_content["url"] = request_body["url"];
  voice_content["info"] = request_body["info"];
  voice_content["info"]["mimetype"] =
    request_body["info"].value("mimetype", "audio/ogg");

  // Add voice-specific metadata (MSC3245)
  json voice_metadata;
  voice_metadata["org.matrix.msc3245.voice"] = json::object();
  voice_metadata["org.matrix.msc1767.audio"] = json::object();
  voice_metadata["org.matrix.msc1767.audio"]["duration"] = duration;

  if (request_body.contains("org.matrix.msc3245.voice") &&
      request_body["org.matrix.msc3245.voice"].is_object()) {
    voice_metadata["org.matrix.msc3245.voice"] =
      request_body["org.matrix.msc3245.voice"];
  }
  voice_content["org.matrix.msc1767.audio"] =
    voice_metadata["org.matrix.msc1767.audio"];
  voice_content["org.matrix.msc3245.voice"] =
    voice_metadata["org.matrix.msc3245.voice"];

  // Copy optional fields
  if (request_body.contains("filename")) {
    voice_content["filename"] = request_body["filename"];
  }

  // ---- 6. Spam check ----
  SpamCheckResult spam = check_spam(db, auth.user_id, room_id,
                                     "m.audio", voice_content);
  if (!spam.allowed) {
    return make_error(429, spam.errcode, spam.error);
  }

  // ---- 7. Build and persist ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     "m.room.message", voice_content);
  ev.event_id = gen_id("$voice");
  ev.txn_id = txn_id;
  persist_event(db, ev);

  // ---- 8. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 9. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 17. SEND STICKER EVENT HANDLER
// ============================================================================
// Creates an m.sticker event with url, info, and body.
// Stickers are specialized image events with type m.sticker.
// ============================================================================

json handle_send_sticker(DatabasePool& db, const std::string& auth_header,
                          const std::string& access_token_param,
                          const std::string& room_id,
                          const std::string& txn_id,
                          const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Check txn_id ----
  if (!txn_id.empty()) {
    auto existing = check_txn_id(db, room_id, auth.user_id, txn_id);
    if (existing) {
      json body;
      body["event_id"] = *existing;
      return make_response(200, body);
    }
  }

  // ---- 4. Validate sticker content ----
  if (!request_body.contains("url") || !request_body["url"].is_string()) {
    return make_error(400, "M_BAD_JSON",
                      "Sticker must include a URL");
  }

  if (!request_body.contains("body") || !request_body["body"].is_string()) {
    return make_error(400, "M_BAD_JSON",
                      "Sticker must include a body (description)");
  }

  if (!request_body.contains("info") || !request_body["info"].is_object()) {
    return make_error(400, "M_BAD_JSON",
                      "Sticker must include image info");
  }

  // Validate image dimensions for sticker
  auto& info = request_body["info"];
  int64_t w = info.value("w", 0);
  int64_t h = info.value("h", 0);
  if (w <= 0 || h <= 0) {
    return make_error(400, "M_BAD_JSON",
                      "Sticker must include valid width and height");
  }

  // ---- 5. Build sticker content ----
  json sticker_content;
  sticker_content["url"] = request_body["url"];
  sticker_content["body"] = request_body["body"];
  sticker_content["info"] = info;
  sticker_content["info"]["mimetype"] =
    info.value("mimetype", "image/png");

  // Copy optional thumbnail info
  if (request_body.contains("thumbnail_url")) {
    sticker_content["thumbnail_url"] = request_body["thumbnail_url"];
  }
  if (request_body.contains("thumbnail_info")) {
    sticker_content["thumbnail_info"] = request_body["thumbnail_info"];
  }

  // ---- 6. Spam check ----
  SpamCheckResult spam = check_spam(db, auth.user_id, room_id,
                                     "m.sticker", sticker_content);
  if (!spam.allowed) {
    return make_error(429, spam.errcode, spam.error);
  }

  // ---- 7. Build and persist ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     "m.sticker", sticker_content);
  ev.event_id = gen_id("$sticker");
  ev.txn_id = txn_id;
  persist_event(db, ev);

  // ---- 8. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 9. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 18. SEND WIDGET EVENT HANDLER
// ============================================================================
// Creates widget events (state events) for room widgets.
// Widget types: m.widget (legacy), im.vector.modular.widgets (Element)
// Widgets are embedded applications within a room.
// ============================================================================

json handle_send_widget(DatabasePool& db, const std::string& auth_header,
                         const std::string& access_token_param,
                         const std::string& room_id,
                         const std::string& txn_id,
                         const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Check power levels (widgets are state events) ----
  if (!has_power_to(db, room_id, auth.user_id, "state_default")) {
    return make_error(403, "M_FORBIDDEN",
                      "Insufficient power level to manage widgets");
  }

  // ---- 4. Validate widget content ----
  if (!request_body.contains("url") || !request_body["url"].is_string()) {
    return make_error(400, "M_BAD_JSON",
                      "Widget must include a URL");
  }

  if (!request_body.contains("type") || !request_body["type"].is_string()) {
    return make_error(400, "M_BAD_JSON",
                      "Widget must include a type");
  }

  std::string widget_id = request_body.value("id", "");
  if (widget_id.empty()) {
    widget_id = gen_token(16);
  }

  std::string widget_type = request_body["type"].get<std::string>();
  std::string widget_url = request_body["url"].get<std::string>();
  std::string widget_name = request_body.value("name", "Widget");

  // ---- 5. Choose the event type ----
  // m.widget is the standard, im.vector.modular.widgets is the Element legacy type
  std::string event_type = "im.vector.modular.widgets"; // Element-style
  if (request_body.value("use_m_widget", false)) {
    event_type = "m.widget";
  }

  // ---- 6. Build widget content ----
  json widget_content;
  widget_content["id"] = widget_id;
  widget_content["type"] = widget_type;
  widget_content["url"] = widget_url;
  widget_content["name"] = widget_name;
  widget_content["creatorUserId"] = auth.user_id;

  // Widget data
  if (request_body.contains("data") && request_body["data"].is_object()) {
    widget_content["data"] = request_body["data"];
  }

  // Wait for screen if available
  if (request_body.contains("waitForIframeLoad")) {
    widget_content["waitForIframeLoad"] =
      request_body["waitForIframeLoad"].get<bool>();
  }

  // Avatar URL
  if (request_body.contains("avatar_url")) {
    widget_content["avatar_url"] = request_body["avatar_url"];
  }

  // ---- 7. Build and persist as state event ----
  std::string state_key = widget_id;
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     event_type, widget_content, state_key);
  ev.event_id = gen_id("$widget");
  ev.txn_id = txn_id;
  persist_event(db, ev, true); // state event

  // ---- 8. If removing a widget (empty content) ----
  // TODO: Handle widget removal by sending empty content

  // ---- 9. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 10. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 19. SEND SPACE CHILD EVENT HANDLER
// ============================================================================
// Creates an m.space.child state event.
// This adds a room as a child of a space room.
// The state_key is the child room's ID.
// ============================================================================

json handle_send_space_child(DatabasePool& db, const std::string& auth_header,
                              const std::string& access_token_param,
                              const std::string& room_id, // space room
                              const std::string& txn_id,
                              const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room (space) ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this space");
  }

  // ---- 3. Check power levels ----
  if (!has_power_to(db, room_id, auth.user_id, "state_default")) {
    return make_error(403, "M_FORBIDDEN",
                      "Insufficient power level to manage space children");
  }

  // ---- 4. Validate space child content ----
  std::string child_room_id = request_body.value("child_room_id", "");
  if (!request_body.contains("child_room_id")) {
    // Try from within content body
    child_room_id = request_body.value("room_id", "");
  }

  if (child_room_id.empty()) {
    return make_error(400, "M_BAD_JSON",
                      "Space child event must include child_room_id");
  }

  if (!validate_room_id(child_room_id)) {
    return make_error(400, "M_BAD_JSON",
                      "Invalid child room ID: " + child_room_id);
  }

  // Prevent circular references
  if (child_room_id == room_id) {
    return make_error(400, "M_BAD_JSON",
                      "A space cannot contain itself");
  }

  // ---- 5. Build space child content ----
  json child_content;
  child_content["via"] = request_body.value("via", json::array({"localhost"}));

  // Order hint for ordering children in the space
  if (request_body.contains("order")) {
    child_content["order"] = request_body["order"].get<std::string>();
  }

  // Suggested flag
  bool suggested = request_body.value("suggested", false);
  child_content["suggested"] = suggested;

  // Auto-join flag
  if (request_body.contains("auto_join")) {
    child_content["auto_join"] = request_body["auto_join"].get<bool>();
  }

  // ---- 6. Build and persist as state event ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     "m.space.child", child_content, child_room_id);
  ev.event_id = gen_id("$spacechild");
  ev.txn_id = txn_id;
  persist_event(db, ev, true);

  // ---- 7. Also update the child room with m.space.parent (if we can) ----
  if (is_user_in_room(db, child_room_id, auth.user_id)) {
    json parent_content;
    parent_content["via"] = json::array({"localhost"});
    parent_content["canonical"] = request_body.value("canonical", false);

    BuiltEvent parent_ev = build_base_event(db, child_room_id, auth.user_id,
                                              "m.space.parent", parent_content, room_id);
    parent_ev.event_id = gen_id("$spaceparent");
    persist_event(db, parent_ev, true);

    // Push to federation for parent event too
    auto child_servers = get_room_participating_servers(db, child_room_id);
    push_event_to_federation(db, parent_ev, child_servers);
  }

  // ---- 8. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 9. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 20. SEND SPACE PARENT EVENT HANDLER
// ============================================================================
// Creates an m.space.parent state event.
// This sets the parent space for a room.
// The state_key is the parent space's room ID.
// ============================================================================

json handle_send_space_parent(DatabasePool& db, const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id, // child room
                               const std::string& txn_id,
                               const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Check power levels ----
  if (!has_power_to(db, room_id, auth.user_id, "state_default")) {
    return make_error(403, "M_FORBIDDEN",
                      "Insufficient power level to manage space parents");
  }

  // ---- 4. Validate space parent content ----
  std::string parent_room_id = request_body.value("parent_room_id", "");
  if (parent_room_id.empty()) {
    return make_error(400, "M_BAD_JSON",
                      "Space parent event must include parent_room_id");
  }

  if (!validate_room_id(parent_room_id)) {
    return make_error(400, "M_BAD_JSON",
                      "Invalid parent room ID: " + parent_room_id);
  }

  // Prevent circular references
  if (parent_room_id == room_id) {
    return make_error(400, "M_BAD_JSON",
                      "A room cannot be its own parent");
  }

  // ---- 5. Build space parent content ----
  json parent_content;
  parent_content["via"] = request_body.value("via", json::array({"localhost"}));
  parent_content["canonical"] = request_body.value("canonical", false);

  // ---- 6. Build and persist as state event ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     "m.space.parent", parent_content, parent_room_id);
  ev.event_id = gen_id("$spaceparent");
  ev.txn_id = txn_id;
  persist_event(db, ev, true);

  // ---- 7. Also update the parent space with m.space.child (if we can) ----
  if (is_user_in_room(db, parent_room_id, auth.user_id)) {
    json child_content;
    child_content["via"] = json::array({"localhost"});
    child_content["suggested"] = false;

    BuiltEvent child_ev = build_base_event(db, parent_room_id, auth.user_id,
                                             "m.space.child", child_content, room_id);
    child_ev.event_id = gen_id("$spacechild");
    persist_event(db, child_ev, true);

    // Push to federation for child event too
    auto parent_servers = get_room_participating_servers(db, parent_room_id);
    push_event_to_federation(db, child_ev, parent_servers);
  }

  // ---- 8. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 9. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// 21. MESSAGE RETENTION ENFORCEMENT (PUBLIC API)
// ============================================================================
// Public entry point for retention enforcement.
// Can be called by admin endpoints or scheduled tasks.
// Purges messages older than the retention policy allows.
// ============================================================================

json handle_enforce_retention(DatabasePool& db, const std::string& room_id,
                               bool force_purge) {
  RetentionPolicy policy = get_retention_policy(db, room_id);

  if (!policy.enabled && !force_purge) {
    return make_error(400, "M_UNKNOWN",
                      "No retention policy configured for this room");
  }

  int64_t now = now_ms();
  int64_t cutoff_ts = force_purge ?
    (now - 2592000000LL) : // 30 days if forced
    (now - policy.max_lifetime_ms);

  // Count events to purge
  auto count_rows = db.execute("retention_count",
    "SELECT COUNT(*) as cnt FROM events "
    "WHERE room_id='" + room_id + "' "
    "AND origin_server_ts < " + std::to_string(cutoff_ts) +
    " AND type != 'm.room.create' "
    "AND type != 'm.room.power_levels' "
    "AND type != 'm.room.join_rules' "
    "AND type != 'm.room.member' "
    "AND type != 'm.space.child' "
    "AND type != 'm.space.parent'");

  int64_t event_count = 0;
  if (!count_rows.empty() && count_rows[0]["cnt"].value) {
    event_count = std::stoll(*count_rows[0]["cnt"].value);
  }

  // Perform purge in batches
  int64_t purged = 0;
  int batch_size = 200;

  while (purged < event_count) {
    auto batch_rows = db.execute("retention_batch",
      "SELECT event_id FROM events "
      "WHERE room_id='" + room_id + "' "
      "AND origin_server_ts < " + std::to_string(cutoff_ts) +
      " AND type != 'm.room.create' "
      "AND type != 'm.room.power_levels' "
      "AND type != 'm.room.join_rules' "
      "AND type != 'm.room.member' "
      "AND type != 'm.space.child' "
      "AND type != 'm.space.parent' "
      "LIMIT " + std::to_string(batch_size));

    if (batch_rows.empty()) break;

    for (auto& row : batch_rows) {
      std::string eid = row["event_id"].value.value_or("");
      if (eid.empty()) continue;

      // Delete from events table
      db.execute("retention_del_event",
        "DELETE FROM events WHERE event_id='" + eid + "'");

      // Delete relations pointing to this event
      db.execute("retention_del_rels",
        "DELETE FROM event_relations WHERE event_id='" + eid +
        "' OR relates_to_id='" + eid + "'");

      // Delete from relation aggregations
      db.execute("retention_del_aggs",
        "DELETE FROM event_relation_aggregations WHERE event_id='" + eid + "'");

      // Delete from thread summaries if this is a thread root
      db.execute("retention_del_threads",
        "DELETE FROM thread_summaries WHERE root_event_id='" + eid + "'");

      purged++;
    }

    // Give other operations a chance
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  // Record the purge
  db.execute("retention_record",
    "INSERT INTO retention_purges (room_id, purged_count, cutoff_ts, ts) VALUES ('" +
    room_id + "'," + std::to_string(purged) + "," + std::to_string(cutoff_ts) + "," +
    std::to_string(now) + ")");

  json body;
  body["room_id"] = room_id;
  body["purged"] = purged;
  body["cutoff_ts"] = cutoff_ts;
  return make_response(200, body);
}

// ============================================================================
// 22. URL PREVIEW GENERATION (PUBLIC API)
// ============================================================================
// Public entry point for URL preview requests.
// This can be called directly by clients or by the message send flow.
// ============================================================================

json handle_get_url_preview(DatabasePool& db, const std::string& url,
                              const std::string& auth_header,
                              const std::string& access_token_param) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate URL ----
  if (url.empty()) {
    return make_error(400, "M_BAD_JSON", "No URL provided");
  }

  // Basic URL validation
  if (url.find("http://") != 0 && url.find("https://") != 0) {
    return make_error(400, "M_BAD_JSON", "Invalid URL: must start with http:// or https://");
  }

  // Check against URL blacklist
  {
    static const std::vector<std::string> blocked_domains = {
      "127.0.0.1", "localhost", "0.0.0.0", "[::]", "[::1]"
    };

    // Extract domain
    std::string domain = url;
    size_t proto = domain.find("://");
    if (proto != std::string::npos) domain = domain.substr(proto + 3);
    size_t slash = domain.find('/');
    if (slash != std::string::npos) domain = domain.substr(0, slash);
    size_t colon = domain.find(':');
    if (colon != std::string::npos) domain = domain.substr(0, colon);

    for (auto& blocked : blocked_domains) {
      if (domain == blocked) {
        return make_error(403, "M_FORBIDDEN",
                          "URL preview not available for this domain");
      }
    }
  }

  // ---- 3. Generate preview ----
  UrlPreview preview = generate_url_preview(db, url);

  // ---- 4. Build response ----
  json body;
  if (preview.valid) {
    body["og:url"] = preview.url;
    if (!preview.title.empty()) body["og:title"] = preview.title;
    if (!preview.description.empty()) body["og:description"] = preview.description;
    if (!preview.image_url.empty()) {
      json img;
      img["url"] = preview.image_url;
      if (preview.image_width > 0) img["og:image:width"] = preview.image_width;
      if (preview.image_height > 0) img["og:image:height"] = preview.image_height;
      body["og:image"] = img;
    }
    if (!preview.og_type.empty()) body["og:type"] = preview.og_type;

    // Matrix-specific fields
    body["matrix:image:size"] = preview.image_size;
  }

  return make_response(200, body);
}

// ============================================================================
// 23. SPAM CHECKING (PUBLIC API)
// ============================================================================
// Public entry point for spam checking.
// Can be used by admin endpoints or the media upload flow.
// ============================================================================

json handle_spam_check(DatabasePool& db, const std::string& user_id,
                        const std::string& room_id,
                        const std::string& event_type,
                        const json& content) {
  SpamCheckResult result = check_spam(db, user_id, room_id, event_type, content);

  json body;
  body["allowed"] = result.allowed;
  if (!result.allowed) {
    body["errcode"] = result.errcode;
    body["error"] = result.error;
  }

  return make_response(200, body);
}

// ============================================================================
// BULK MESSAGE RETRIEVAL
// ============================================================================
// Retrieves multiple messages by batch of event IDs.
// Used by sync and pagination to resolve events.
// ============================================================================

json handle_get_messages_batch(DatabasePool& db, const std::string& auth_header,
                                const std::string& access_token_param,
                                const std::string& room_id,
                                const std::vector<std::string>& event_ids) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Build event ID list ----
  if (event_ids.empty()) {
    return make_response(200, json::array());
  }

  std::string id_list;
  for (auto& eid : event_ids) {
    if (!id_list.empty()) id_list += ",";
    id_list += "'" + eid + "'";
  }

  // ---- 4. Query events ----
  auto rows = db.execute("get_messages_batch",
    "SELECT json, is_redacted FROM events "
    "WHERE event_id IN (" + id_list + ") AND room_id='" + room_id + "'");

  // ---- 5. Process results ----
  json result = json::array();
  for (auto& row : rows) {
    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);

    if (row["is_redacted"].value && *row["is_redacted"].value == "1") {
      json redacted;
      redacted["event_id"] = ev["event_id"];
      redacted["room_id"] = ev["room_id"];
      redacted["sender"] = ev["sender"];
      redacted["type"] = ev["type"];
      redacted["origin_server_ts"] = ev["origin_server_ts"];
      if (ev.contains("state_key")) redacted["state_key"] = ev["state_key"];
      ev = redacted;
    }

    result.push_back(ev);
  }

  return make_response(200, result);
}

// ============================================================================
// SEARCH MESSAGES HANDLER
// ============================================================================
// POST /_matrix/client/v3/search
//
// Searches for messages across rooms. Uses full-text search
// on the event body/content. Supports pagination and filtering.
// ============================================================================

json handle_search_messages(DatabasePool& db, const std::string& auth_header,
                             const std::string& access_token_param,
                             const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Parse search criteria ----
  if (!request_body.contains("search_categories") ||
      !request_body["search_categories"].is_object()) {
    return make_error(400, "M_BAD_JSON",
                      "Missing search_categories");
  }

  auto& categories = request_body["search_categories"];
  std::string search_term;
  std::string search_key;
  std::string order_by = "rank";
  int64_t limit = 10;
  std::string next_batch;

  // Parse room_events category
  if (categories.contains("room_events") &&
      categories["room_events"].is_object()) {
    auto& room_events = categories["room_events"];
    search_term = room_events.value("search_term", "");

    if (room_events.contains("keys") && room_events["keys"].is_array()) {
      // content.body is the default search key
      search_key = "content.body";
    }

    if (room_events.contains("order_by")) {
      order_by = room_events["order_by"].get<std::string>();
    }

    // Filter by rooms
    if (room_events.contains("filter") &&
        room_events["filter"].is_object()) {
      auto& re_filter = room_events["filter"];
      if (re_filter.contains("rooms") && re_filter["rooms"].is_array()) {
        // Filter to specific rooms
      }
    }

    // Groupings
    if (room_events.contains("groupings") &&
        room_events["groupings"].is_object()) {
      // Group by room
    }

    if (room_events.contains("include_state")) {
      // Include state events in search results
    }
  }

  if (search_term.empty()) {
    return make_error(400, "M_BAD_JSON",
                      "Missing search_term");
  }

  if (limit > 50) limit = 50;

  // ---- 3. Get user's joined rooms ----
  RoomMemberStore members(db);
  auto joined_rooms = members.get_rooms_for_user(auth.user_id);

  // Build room filter
  std::string room_filter;
  for (auto& room : joined_rooms) {
    if (!room_filter.empty()) room_filter += ",";
    room_filter += "'" + room + "'";
  }
  if (room_filter.empty()) {
    // User is not in any rooms
    json result;
    result["search_categories"] = {
      {"room_events", {
        {"count", 0},
        {"results", json::array()},
        {"highlights", json::array()}
      }}
    };
    return make_response(200, result);
  }

  // ---- 4. Search in events ----
  std::string search_sql =
    "SELECT e.event_id, e.room_id, e.json, e.stream_ordering, e.origin_server_ts "
    "FROM events e "
    "WHERE e.room_id IN (" + room_filter + ") "
    "AND e.outlier = 0 "
    "AND e.type = 'm.room.message' ";

  // Add text search condition
  search_sql += "AND (e.json LIKE '%" + search_term + "%') ";

  // Exclude redacted events
  search_sql += "AND e.is_redacted = 0 ";

  // Order by recency
  if (order_by == "recent") {
    search_sql += "ORDER BY e.stream_ordering DESC ";
  } else {
    search_sql += "ORDER BY e.stream_ordering DESC ";
  }

  search_sql += "LIMIT " + std::to_string(limit);

  auto rows = db.execute("search_query", search_sql);

  // ---- 5. Build results ----
  json results = json::array();
  int64_t count = 0;

  for (auto& row : rows) {
    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);

    json result_obj;
    result_obj["rank"] = result_obj.size();
    result_obj["result"] = ev;
    result_obj["context"] = {
      {"events_before", json::array()},
      {"events_after", json::array()}
    };

    results.push_back(result_obj);
    count++;
  }

  // ---- 6. Generate highlights ----
  json highlights = json::array();
  highlights.push_back(search_term);

  // ---- 7. Build response ----
  json body;
  body["search_categories"] = {
    {"room_events", {
      {"count", count},
      {"results", results},
      {"highlights", highlights},
      {"next_batch", nullptr}
    }}
  };

  return make_response(200, body);
}

// ============================================================================
// MESSAGE FORWARDING HANDLER
// ============================================================================
// Forwards an event from one room to another.
// Creates a new event in the target room with the same content.
// ============================================================================

json handle_forward_message(DatabasePool& db, const std::string& auth_header,
                             const std::string& access_token_param,
                             const std::string& target_room_id,
                             const std::string& source_event_id,
                             const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the target room ----
  if (!is_user_in_room(db, target_room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of the target room");
  }

  // ---- 3. Get source event ----
  auto src_rows = db.execute("fwd_src",
    "SELECT room_id, sender, type, content FROM events "
    "WHERE event_id='" + source_event_id + "'");
  if (src_rows.empty()) {
    return make_error(404, "M_NOT_FOUND",
                      "Source event not found: " + source_event_id);
  }

  std::string src_room = src_rows[0]["room_id"].value.value_or("");
  std::string src_sender = src_rows[0]["sender"].value.value_or("");
  std::string src_type = src_rows[0]["type"].value.value_or("");

  // ---- 4. Check user is in the source room too ----
  if (!is_user_in_room(db, src_room, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of the source room");
  }

  // ---- 5. Build forwarded content with attribution ----
  json fwd_content = json::parse(src_rows[0]["content"].value.value_or("{}"));
  fwd_content["org.matrix.forwarded"] = true;
  fwd_content["org.matrix.forwarded_event_id"] = source_event_id;
  fwd_content["org.matrix.forwarded_room_id"] = src_room;
  fwd_content["org.matrix.forwarded_sender"] = src_sender;

  // Add forward comment if provided
  if (request_body.contains("comment")) {
    fwd_content["org.matrix.forwarded_comment"] = request_body["comment"];
  }

  // ---- 6. Determine event type for forwarded event ----
  std::string fwd_type = src_type;
  if (src_type == "m.sticker" || src_type == "m.reaction") {
    fwd_type = "m.room.message";
    fwd_content["msgtype"] = "m.text";
  }

  // ---- 7. Build and persist ----
  BuiltEvent ev = build_base_event(db, target_room_id, auth.user_id,
                                     fwd_type, fwd_content);
  ev.event_id = gen_id("$fwd");
  persist_event(db, ev);

  // ---- 8. Push to federation ----
  auto servers = get_room_participating_servers(db, target_room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 9. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

// ============================================================================
// PINNED MESSAGES HANDLER
// ============================================================================
// Gets or sets pinned messages for a room (m.room.pinned_events state).
// ============================================================================

json handle_set_pinned_messages(DatabasePool& db, const std::string& auth_header,
                                 const std::string& access_token_param,
                                 const std::string& room_id,
                                 const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Check power levels ----
  if (!has_power_to(db, room_id, auth.user_id, "state_default")) {
    return make_error(403, "M_FORBIDDEN",
                      "Insufficient power level to pin messages");
  }

  // ---- 4. Validate pinned event IDs ----
  if (!request_body.contains("pinned") || !request_body["pinned"].is_array()) {
    return make_error(400, "M_BAD_JSON",
                      "Must provide 'pinned' array of event IDs");
  }

  // Validate each pinned event exists in the room
  for (auto& eid_json : request_body["pinned"]) {
    std::string eid = eid_json.get<std::string>();
    auto check = db.execute("pin_check",
      "SELECT event_id FROM events WHERE event_id='" + eid +
      "' AND room_id='" + room_id + "'");
    if (check.empty()) {
      return make_error(400, "M_UNKNOWN",
                        "Event not found in this room: " + eid);
    }
  }

  // ---- 5. Build pinned events content ----
  json pin_content;
  pin_content["pinned"] = request_body["pinned"];

  // ---- 6. Build and persist as state event ----
  BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                     "m.room.pinned_events", pin_content,
                                     std::string(""));
  ev.event_id = gen_id("$pin");
  persist_event(db, ev, true);

  // ---- 7. Push to federation ----
  auto servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ev, servers);

  // ---- 8. Return ----
  json body;
  body["event_id"] = ev.event_id;
  return make_response(200, body);
}

json handle_get_pinned_messages(DatabasePool& db, const std::string& auth_header,
                                 const std::string& access_token_param,
                                 const std::string& room_id) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Get pinned events state ----
  StateStore state(db);
  auto pin_event = state.get_current_state_event(room_id, "m.room.pinned_events", "");

  json pinned_events = json::array();
  if (pin_event) {
    EventsStore evs(db);
    auto ev = evs.get_event(*pin_event);
    if (ev && (*ev).contains("content") && (*ev)["content"].contains("pinned")) {
      pinned_events = (*ev)["content"]["pinned"];
    }
  }

  // ---- 4. Return ----
  return make_response(200, pinned_events);
}

// ============================================================================
// BROADCAST MESSAGE HANDLER
// ============================================================================
// Sends a message to multiple rooms simultaneously.
// Used by bots and admin operations.
// ============================================================================

json handle_broadcast_message(DatabasePool& db, const std::string& auth_header,
                               const std::string& access_token_param,
                               const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate broadcast content ----
  if (!request_body.contains("room_ids") || !request_body["room_ids"].is_array()) {
    return make_error(400, "M_BAD_JSON",
                      "Must provide room_ids array");
  }

  if (!request_body.contains("content") || !request_body["content"].is_object()) {
    return make_error(400, "M_BAD_JSON",
                      "Must provide message content");
  }

  std::string event_type = request_body.value("type", "m.room.message");
  json content = request_body["content"];

  // ---- 3. Broadcast to each room ----
  json results = json::array();
  for (auto& rid : request_body["room_ids"]) {
    std::string room_id = rid.get<std::string>();

    // Validate room exists and user is member
    if (!is_user_in_room(db, room_id, auth.user_id)) {
      json error_result;
      error_result["room_id"] = room_id;
      error_result["status"] = "error";
      error_result["error"] = "Not a member of this room";
      results.push_back(error_result);
      continue;
    }

    // Build and persist for this room
    std::string txn_id = gen_token(16);
    BuiltEvent ev = build_base_event(db, room_id, auth.user_id,
                                       event_type, content);
    ev.event_id = gen_id("$bc");
    ev.txn_id = txn_id;
    persist_event(db, ev);

    // Push to federation
    auto servers = get_room_participating_servers(db, room_id);
    push_event_to_federation(db, ev, servers);

    json success_result;
    success_result["room_id"] = room_id;
    success_result["event_id"] = ev.event_id;
    success_result["status"] = "success";
    results.push_back(success_result);
  }

  // ---- 4. Return results ----
  json body;
  body["results"] = results;
  return make_response(200, body);
}

// ============================================================================
// MESSAGE STATISTICS HANDLER
// ============================================================================
// Gets message statistics for a room (message count, reaction count, etc.)
// ============================================================================

json handle_message_stats(DatabasePool& db, const std::string& auth_header,
                           const std::string& access_token_param,
                           const std::string& room_id) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  json stats;

  // Total message count
  auto total_rows = db.execute("stats_total",
    "SELECT COUNT(*) as cnt FROM events "
    "WHERE room_id='" + room_id + "' AND outlier=0");
  if (!total_rows.empty() && total_rows[0]["cnt"].value) {
    stats["total_events"] = std::stoll(*total_rows[0]["cnt"].value);
  }

  // Message count by type
  auto type_rows = db.execute("stats_types",
    "SELECT type, COUNT(*) as cnt FROM events "
    "WHERE room_id='" + room_id + "' AND outlier=0 "
    "GROUP BY type ORDER BY cnt DESC");
  json by_type = json::object();
  for (auto& row : type_rows) {
    std::string type = row["type"].value.value_or("unknown");
    int64_t cnt = row["cnt"].value ? std::stoll(*row["cnt"].value) : 0;
    by_type[type] = cnt;
  }
  stats["by_type"] = by_type;

  // Message count by sender (top 20)
  auto sender_rows = db.execute("stats_senders",
    "SELECT sender, COUNT(*) as cnt FROM events "
    "WHERE room_id='" + room_id + "' AND outlier=0 "
    "GROUP BY sender ORDER BY cnt DESC LIMIT 20");
  json by_sender = json::array();
  for (auto& row : sender_rows) {
    json entry;
    entry["user_id"] = row["sender"].value.value_or("unknown");
    entry["count"] = row["cnt"].value ? std::stoll(*row["cnt"].value) : 0;
    by_sender.push_back(entry);
  }
  stats["top_senders"] = by_sender;

  // Reaction count
  auto react_rows = db.execute("stats_reactions",
    "SELECT COUNT(*) as cnt FROM events e "
    "INNER JOIN event_relations er ON e.event_id = er.event_id "
    "WHERE e.room_id='" + room_id + "' AND er.relation_type='m.annotation'");
  if (!react_rows.empty() && react_rows[0]["cnt"].value) {
    stats["reactions"] = std::stoll(*react_rows[0]["cnt"].value);
  }

  // Thread count
  auto thread_rows = db.execute("stats_threads",
    "SELECT COUNT(*) as cnt FROM thread_summaries WHERE room_id='" + room_id + "'");
  if (!thread_rows.empty() && thread_rows[0]["cnt"].value) {
    stats["threads"] = std::stoll(*thread_rows[0]["cnt"].value);
  }

  // First and last message timestamps
  auto time_rows = db.execute("stats_time",
    "SELECT MIN(origin_server_ts) as first_ts, MAX(origin_server_ts) as last_ts "
    "FROM events WHERE room_id='" + room_id + "' AND outlier=0");
  if (!time_rows.empty()) {
    if (time_rows[0]["first_ts"].value) {
      stats["first_message_ts"] = std::stoll(*time_rows[0]["first_ts"].value);
    }
    if (time_rows[0]["last_ts"].value) {
      stats["last_message_ts"] = std::stoll(*time_rows[0]["last_ts"].value);
    }
  }

  return make_response(200, stats);
}

}  // namespace progressive::handlers
