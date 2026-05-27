// search_context_stats.cpp - Matrix Server-Side Search, Event Context, and Room Statistics
// Implements ALL search, context, and statistics handlers with full database logic.
// Target: 3000+ lines
//
// Handlers:
//   1.  full_text_search          - POST /search with search_categories
//   2.  message_search            - Search room events by body content
//   3.  room_event_search         - Room event search with highlights
//   4.  search_ordering           - Order by rank, by recency
//   5.  search_grouping           - Group results by room
//   6.  search_result_context     - Events before/after match
//   7.  event_context_api         - GET /rooms/{roomId}/context/{eventId}
//   8.  context_before            - Events before the target event
//   9.  context_after             - Events after the target event
//  10.  context_state             - State at the target event
//  11.  room_statistics_api       - Total events, members, messages
//  12.  room_event_counts         - Per-type event counts
//  13.  room_timeline_analytics   - Timeline analytics
//  14.  user_room_statistics      - User room statistics
//  15.  server_side_search_index  - Search indexing
//  16.  search_result_pagination  - Search result pagination
//  17.  search_filters            - By room, by sender, by date range
//  18.  search_result_deduplication - Search result dedup
//  19.  search_rate_limiting       - Search rate limiting
//  20.  search_admin_api           - Search admin API

#include "../json.hpp"
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/event_federation.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/receipts.hpp"

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
#include <deque>
#include <queue>

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;

// ============================================================================
// Global utilities (shared across handlers)
// ============================================================================

static std::atomic<int64_t> g_search_seq{1};
static std::atomic<int64_t> g_index_seq{1};
static std::mutex g_search_lock;
static std::mutex g_index_lock;
static std::mutex g_stats_lock;
static std::mutex g_rate_limit_lock;
static std::mutex g_search_cache_lock;
static std::mutex g_context_lock;

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static int64_t now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_id(const std::string& prefix) {
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(g_search_seq.fetch_add(1));
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
  return room_id.size() >= 4 && room_id[0] == '!' &&
         room_id.find(':') != std::string::npos;
}

static json make_error_obj(const std::string& errcode, const std::string& error) {
  json j;
  j["errcode"] = errcode;
  j["error"] = error;
  return j;
}

// Simple SQL-safe string escaping
static std::string sql_escape(const std::string& str) {
  std::string result;
  result.reserve(str.size() + 8);
  for (char c : str) {
    if (c == '\'') result += "''";
    else if (c == '\\') result += "\\\\";
    else if (c == '%') result += "\\%";
    else if (c == '_') result += "\\_";
    else result += c;
  }
  return result;
}

// Parse JSON content from DB row into event JSON
static json parse_event_content(const std::string& content_str) {
  if (content_str.empty() || content_str == "{}") return json::object();
  try { return json::parse(content_str); }
  catch (...) { return json::object(); }
}

// Compute Levenshtein-based relevance score (0.0-1.0)
static double compute_relevance(const std::string& haystack, const std::string& needle) {
  if (needle.empty()) return 0.0;
  std::string hl = haystack;
  std::string nl = needle;
  std::transform(hl.begin(), hl.end(), hl.begin(), ::tolower);
  std::transform(nl.begin(), nl.end(), nl.begin(), ::tolower);

  // Exact match boost
  if (hl == nl) return 1.0;
  if (hl.find(nl) != std::string::npos) return 0.8;

  // Word-level match
  std::istringstream iss(hl);
  std::string word;
  double best = 0.0;
  while (iss >> word) {
    if (word.find(nl) != std::string::npos) {
      best = std::max(best, 0.6);
    }
    if (word.size() >= nl.size() / 2) {
      // Partial word match scoring
      size_t match_chars = 0;
      for (size_t i = 0; i < nl.size() && i < word.size(); ++i) {
        if (word[i] == nl[i]) ++match_chars;
      }
      double partial = static_cast<double>(match_chars) / nl.size();
      best = std::max(best, partial * 0.5);
    }
  }
  return best;
}

// Extract text body from event content for searching
static std::string extract_searchable_text(const json& content) {
  std::string text;
  if (content.contains("body") && content["body"].is_string()) {
    text += content["body"].get<std::string>() + " ";
  }
  if (content.contains("formatted_body") && content["formatted_body"].is_string()) {
    text += content["formatted_body"].get<std::string>() + " ";
  }
  if (content.contains("name") && content["name"].is_string()) {
    text += content["name"].get<std::string>() + " ";
  }
  if (content.contains("topic") && content["topic"].is_string()) {
    text += content["topic"].get<std::string>() + " ";
  }
  if (content.contains("url") && content["url"].is_string()) {
    text += content["url"].get<std::string>() + " ";
  }
  // Strip HTML tags from formatted_body
  if (content.contains("formatted_body") && content["formatted_body"].is_string()) {
    std::string fmt = content["formatted_body"].get<std::string>();
    std::regex html_tag("<[^>]*>");
    text += std::regex_replace(fmt, html_tag, " ") + " ";
  }
  return text;
}

// Generate highlights from text matching search terms
static json generate_highlights(const std::string& text, const std::string& search_term, int max_length = 200) {
  json highlights = json::array();
  if (search_term.empty() || text.empty()) return highlights;

  std::string ltext = text;
  std::string lterm = search_term;
  std::transform(ltext.begin(), ltext.end(), ltext.begin(), ::tolower);
  std::transform(lterm.begin(), lterm.end(), lterm.begin(), ::tolower);

  size_t pos = 0;
  int found = 0;
  while ((pos = ltext.find(lterm, pos)) != std::string::npos && found < 5) {
    int64_t start = static_cast<int64_t>(pos) - max_length / 4;
    if (start < 0) start = 0;
    int64_t end = static_cast<int64_t>(pos) + lterm.size() + max_length / 4;
    if (end > static_cast<int64_t>(text.size())) end = text.size();

    std::string snippet = text.substr(start, end - start);
    if (start > 0) snippet = "..." + snippet;
    if (end < static_cast<int64_t>(text.size())) snippet = snippet + "...";

    highlights.push_back(snippet);
    pos += lterm.size();
    ++found;
  }
  return highlights;
}

// ============================================================================
// Rate Limiter for search operations
// ============================================================================
class SearchRateLimiter {
public:
  SearchRateLimiter() = default;

  bool check(const std::string& user_id, int max_per_window = 30, int64_t window_sec = 60) {
    std::lock_guard<std::mutex> lock(g_rate_limit_lock);
    int64_t now = now_sec();
    auto& entry = buckets_[user_id];
    // Clean expired entries
    entry.requests.erase(
      std::remove_if(entry.requests.begin(), entry.requests.end(),
        [&](int64_t ts) { return now - ts > window_sec; }),
      entry.requests.end());
    if (static_cast<int>(entry.requests.size()) >= max_per_window) {
      entry.rate_limited_count++;
      return false;
    }
    entry.requests.push_back(now);
    entry.total_requests++;
    return true;
  }

  json get_stats(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(g_rate_limit_lock);
    json stats;
    auto it = buckets_.find(user_id);
    if (it != buckets_.end()) {
      stats["total_requests"] = it->second.total_requests;
      stats["rate_limited_count"] = it->second.rate_limited_count;
      stats["current_window_count"] = static_cast<int>(it->second.requests.size());
    } else {
      stats["total_requests"] = 0;
      stats["rate_limited_count"] = 0;
      stats["current_window_count"] = 0;
    }
    return stats;
  }

  json global_stats() {
    std::lock_guard<std::mutex> lock(g_rate_limit_lock);
    json stats;
    stats["total_users"] = static_cast<int>(buckets_.size());
    int64_t total_req = 0;
    int64_t total_limited = 0;
    for (auto& [uid, b] : buckets_) {
      total_req += b.total_requests;
      total_limited += b.rate_limited_count;
    }
    stats["total_requests"] = total_req;
    stats["total_rate_limited"] = total_limited;
    return stats;
  }

  void reset_user(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(g_rate_limit_lock);
    buckets_.erase(user_id);
  }

private:
  struct RateBucket {
    std::vector<int64_t> requests;
    int64_t total_requests{0};
    int64_t rate_limited_count{0};
  };
  std::unordered_map<std::string, RateBucket> buckets_;
};

// Global rate limiter instance
static SearchRateLimiter g_search_rate_limiter;

// ============================================================================
// Search Index (in-memory inverted index with DB persistence)
// ============================================================================
class SearchIndex {
public:
  SearchIndex() = default;

  // Index an event
  void index_event(const std::string& event_id, const std::string& room_id,
                   const std::string& sender, const std::string& event_type,
                   const std::string& text_content, int64_t origin_server_ts,
                   int64_t stream_ordering) {
    std::lock_guard<std::mutex> lock(g_index_lock);

    // Remove existing entry
    auto it = event_index_.find(event_id);
    if (it != event_index_.end()) {
      remove_event_from_index(event_id);
    }

    // Tokenize text
    auto tokens = tokenize(text_content);

    IndexedEvent entry;
    entry.event_id = event_id;
    entry.room_id = room_id;
    entry.sender = sender;
    entry.event_type = event_type;
    entry.text_content = text_content;
    entry.origin_server_ts = origin_server_ts;
    entry.stream_ordering = stream_ordering;

    event_index_[event_id] = entry;

    for (const auto& token : tokens) {
      inverted_index_[token].push_back(event_id);
      room_inverted_index_[room_id][token].push_back(event_id);
      sender_inverted_index_[sender][token].push_back(event_id);
    }

    // Track by room
    room_events_[room_id].push_back(event_id);

    // Track by sender
    sender_events_[sender].push_back(event_id);

    ++total_indexed_;
  }

  // De-index an event
  void deindex_event(const std::string& event_id) {
    std::lock_guard<std::mutex> lock(g_index_lock);
    remove_event_from_index(event_id);
  }

  // Search across all rooms (global search)
  struct SearchHit {
    std::string event_id;
    std::string room_id;
    std::string sender;
    std::string event_type;
    std::string text_content;
    int64_t origin_server_ts{0};
    int64_t stream_ordering{0};
    double relevance{0.0};
  };

  std::vector<SearchHit> search(const std::string& query, int limit = 50,
                                 const std::string& room_filter = "",
                                 const std::string& sender_filter = "",
                                 int64_t from_ts = 0, int64_t to_ts = 0) {
    std::lock_guard<std::mutex> lock(g_index_lock);

    std::vector<SearchHit> results;
    std::unordered_set<std::string> seen;

    auto query_tokens = tokenize(query);
    if (query_tokens.empty()) return results;

    // Find events matching all tokens
    std::vector<std::string> candidate_ids;
    bool first = true;
    for (const auto& token : query_tokens) {
      std::vector<std::string> matching;
      // Check global inverted index
      auto glob_it = inverted_index_.find(token);
      if (glob_it != inverted_index_.end()) {
        matching.insert(matching.end(), glob_it->second.begin(), glob_it->second.end());
      }
      // Also check partial prefix matches
      for (auto& [idx_token, events] : inverted_index_) {
        if (idx_token.find(token) != std::string::npos && idx_token != token) {
          matching.insert(matching.end(), events.begin(), events.end());
        }
      }

      if (first) {
        candidate_ids = std::move(matching);
        first = false;
      } else {
        std::sort(candidate_ids.begin(), candidate_ids.end());
        std::sort(matching.begin(), matching.end());
        std::vector<std::string> intersection;
        std::set_intersection(
          candidate_ids.begin(), candidate_ids.end(),
          matching.begin(), matching.end(),
          std::back_inserter(intersection));
        candidate_ids = std::move(intersection);
      }
    }

    for (const auto& eid : candidate_ids) {
      auto ev_it = event_index_.find(eid);
      if (ev_it == event_index_.end()) continue;
      if (seen.count(eid)) continue;

      const auto& ev = ev_it->second;

      // Apply filters
      if (!room_filter.empty() && ev.room_id != room_filter) continue;
      if (!sender_filter.empty() && ev.sender != sender_filter) continue;
      if (from_ts > 0 && ev.origin_server_ts < from_ts) continue;
      if (to_ts > 0 && ev.origin_server_ts > to_ts) continue;

      SearchHit hit;
      hit.event_id = ev.event_id;
      hit.room_id = ev.room_id;
      hit.sender = ev.sender;
      hit.event_type = ev.event_type;
      hit.text_content = ev.text_content;
      hit.origin_server_ts = ev.origin_server_ts;
      hit.stream_ordering = ev.stream_ordering;
      hit.relevance = compute_relevance(ev.text_content, query);

      results.push_back(hit);
      seen.insert(eid);
    }

    // Sort by relevance (descending)
    std::sort(results.begin(), results.end(), [](const SearchHit& a, const SearchHit& b) {
      if (std::abs(a.relevance - b.relevance) > 0.001)
        return a.relevance > b.relevance;
      return a.stream_ordering > b.stream_ordering;
    });

    if (static_cast<int>(results.size()) > limit) {
      results.resize(limit);
    }

    return results;
  }

  // Search within a specific room
  std::vector<SearchHit> search_room(const std::string& room_id,
                                      const std::string& query, int limit = 50) {
    return search(query, limit, room_id, "", 0, 0);
  }

  // Search by sender
  std::vector<SearchHit> search_by_sender(const std::string& sender,
                                           const std::string& query, int limit = 50) {
    return search(query, limit, "", sender, 0, 0);
  }

  // Get index statistics
  json get_index_stats() {
    std::lock_guard<std::mutex> lock(g_index_lock);
    json stats;
    stats["total_indexed"] = total_indexed_;
    stats["unique_tokens"] = static_cast<int>(inverted_index_.size());
    stats["rooms_indexed"] = static_cast<int>(room_events_.size());
    stats["senders_indexed"] = static_cast<int>(sender_events_.size());
    return stats;
  }

  // Rebuild index from database
  void rebuild_from_db(DatabasePool& db) {
    std::lock_guard<std::mutex> lock(g_index_lock);
    clear();

    auto rows = db.execute("rebuild_index",
      "SELECT event_id, room_id, sender, type, content, origin_server_ts, stream_ordering "
      "FROM events WHERE is_state=0 OR is_state IS NULL "
      "ORDER BY stream_ordering ASC");

    for (auto& row : rows) {
      std::string event_id = row[0].value.value_or("");
      std::string room_id = row[1].value.value_or("");
      std::string sender = row[2].value.value_or("");
      std::string event_type = row[3].value.value_or("");
      std::string content_str = row[4].value.value_or("{}");
      int64_t ots = row[5].value ? std::stoll(*row[5].value) : 0;
      int64_t so = row[6].value ? std::stoll(*row[6].value) : 0;

      json content = parse_event_content(content_str);
      std::string text = extract_searchable_text(content);

      if (!text.empty()) {
        IndexedEvent entry;
        entry.event_id = event_id;
        entry.room_id = room_id;
        entry.sender = sender;
        entry.event_type = event_type;
        entry.text_content = text;
        entry.origin_server_ts = ots;
        entry.stream_ordering = so;

        event_index_[event_id] = entry;

        auto tokens = tokenize(text);
        for (const auto& token : tokens) {
          inverted_index_[token].push_back(event_id);
          room_inverted_index_[room_id][token].push_back(event_id);
          sender_inverted_index_[sender][token].push_back(event_id);
        }

        room_events_[room_id].push_back(event_id);
        sender_events_[sender].push_back(event_id);
        ++total_indexed_;
      }
    }
  }

  void clear() {
    event_index_.clear();
    inverted_index_.clear();
    room_inverted_index_.clear();
    sender_inverted_index_.clear();
    room_events_.clear();
    sender_events_.clear();
    total_indexed_ = 0;
  }

private:
  struct IndexedEvent {
    std::string event_id;
    std::string room_id;
    std::string sender;
    std::string event_type;
    std::string text_content;
    int64_t origin_server_ts{0};
    int64_t stream_ordering{0};
  };

  // Tokenize text into lowercase words (min 2 chars)
  std::vector<std::string> tokenize(const std::string& text) {
    std::vector<std::string> tokens;
    std::unordered_set<std::string> seen;
    std::string current;
    for (char c : text) {
      if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '\'') {
        current += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      } else {
        if (current.size() >= 2 && !seen.count(current)) {
          tokens.push_back(current);
          seen.insert(current);
        }
        current.clear();
      }
    }
    if (current.size() >= 2 && !seen.count(current)) {
      tokens.push_back(current);
    }
    return tokens;
  }

  void remove_event_from_index(const std::string& event_id) {
    auto ev_it = event_index_.find(event_id);
    if (ev_it == event_index_.end()) return;

    const auto& ev = ev_it->second;
    auto tokens = tokenize(ev.text_content);

    // Remove from global inverted index
    for (const auto& token : tokens) {
      auto& vec = inverted_index_[token];
      vec.erase(std::remove(vec.begin(), vec.end(), event_id), vec.end());
      if (vec.empty()) inverted_index_.erase(token);
    }

    // Remove from room inverted index
    auto ri_it = room_inverted_index_.find(ev.room_id);
    if (ri_it != room_inverted_index_.end()) {
      for (const auto& token : tokens) {
        auto& vec = ri_it->second[token];
        vec.erase(std::remove(vec.begin(), vec.end(), event_id), vec.end());
      }
    }

    // Remove from sender inverted index
    auto si_it = sender_inverted_index_.find(ev.sender);
    if (si_it != sender_inverted_index_.end()) {
      for (const auto& token : tokens) {
        auto& vec = si_it->second[token];
        vec.erase(std::remove(vec.begin(), vec.end(), event_id), vec.end());
      }
    }

    // Remove from room list
    auto rl_it = room_events_.find(ev.room_id);
    if (rl_it != room_events_.end()) {
      auto& vec = rl_it->second;
      vec.erase(std::remove(vec.begin(), vec.end(), event_id), vec.end());
    }

    // Remove from sender list
    auto sl_it = sender_events_.find(ev.sender);
    if (sl_it != sender_events_.end()) {
      auto& vec = sl_it->second;
      vec.erase(std::remove(vec.begin(), vec.end(), event_id), vec.end());
    }

    event_index_.erase(event_id);
    --total_indexed_;
  }

  // Primary storage
  std::unordered_map<std::string, IndexedEvent> event_index_;

  // Global inverted index: token -> list of event_ids
  std::unordered_map<std::string, std::vector<std::string>> inverted_index_;

  // Per-room inverted index
  std::unordered_map<std::string, std::unordered_map<std::string, std::vector<std::string>>> room_inverted_index_;

  // Per-sender inverted index
  std::unordered_map<std::string, std::unordered_map<std::string, std::vector<std::string>>> sender_inverted_index_;

  // Room -> event list
  std::unordered_map<std::string, std::vector<std::string>> room_events_;

  // Sender -> event list
  std::unordered_map<std::string, std::vector<std::string>> sender_events_;

  int64_t total_indexed_{0};
};

// Global search index instance
static SearchIndex g_search_index;

// ============================================================================
// SearchHandler - Full-text search with all features
// ============================================================================
class SearchHandler {
public:
  explicit SearchHandler(DatabasePool& db) : db_(db) {}

  // ── 1. Full-text search (POST /search with search_categories) ──────────
  json full_text_search(const std::string& user_id, const json& body) {
    std::lock_guard<std::mutex> lock(g_search_lock);

    // Rate limit check
    if (!g_search_rate_limiter.check(user_id)) {
      json err;
      err["errcode"] = "M_LIMIT_EXCEEDED";
      err["error"] = "Search rate limit exceeded. Try again later.";
      err["retry_after_ms"] = 60000;
      return err;
    }

    json result;
    result["search_categories"] = json::object();

    auto search_categories = body.value("search_categories", json::object());
    std::string order_by = body.value("order_by", "rank");
    std::string group_by = body.value("group_by", "");
    bool include_profile = body.value("include_profile", false);

    // Process each search category
    if (search_categories.contains("room_events")) {
      auto& cat = search_categories["room_events"];
      std::string search_term = cat.value("search_term", "");
      std::string keys = cat.value("keys", "content.body");
      int limit = cat.value("limit", 10);
      limit = std::min(std::max(limit, 1), 100);

      json room_events_result;
      room_events_result["count"] = 0;
      room_events_result["results"] = json::array();
      room_events_result["highlights"] = json::array();
      room_events_result["groups"] = json::object();

      if (!search_term.empty()) {
        auto hits = perform_search(user_id, search_term, keys, cat, limit, order_by);

        for (size_t i = 0; i < hits.size(); ++i) {
          auto& hit = hits[i];
          json sr;
          sr["rank"] = hit.relevance;

          json ev;
          ev["event_id"] = hit.event_id;
          ev["room_id"] = hit.room_id;
          ev["type"] = hit.event_type;
          ev["sender"] = hit.sender;
          ev["content"] = hit.content;
          ev["origin_server_ts"] = hit.origin_server_ts;
          ev["stream_ordering"] = hit.stream_ordering;

          sr["result"] = ev;

          // Generate highlights
          std::string searchable = extract_searchable_text(hit.content);
          json highlights = generate_highlights(searchable, search_term);
          if (!highlights.empty()) {
            sr["highlights"] = highlights;
          }

          room_events_result["results"].push_back(sr);
          room_events_result["count"] = static_cast<int64_t>(room_events_result["count"]) + 1;

          // Group by room
          if (group_by == "room_id") {
            std::string rid = hit.room_id;
            if (!room_events_result["groups"].contains(rid)) {
              room_events_result["groups"][rid] = json::object();
              room_events_result["groups"][rid]["results"] = json::array();
              room_events_result["groups"][rid]["next_batch"] = "";
            }
            room_events_result["groups"][rid]["results"].push_back(sr);
          }
        }
      }

      // Pagination: next_batch token
      if (room_events_result["results"].size() >= static_cast<size_t>(limit)) {
        room_events_result["next_batch"] = gen_token(16);
      }

      result["search_categories"]["room_events"] = room_events_result;
    }

    // Process room search category
    if (search_categories.contains("room")) {
      result["search_categories"]["room"] = search_rooms_by_term(
        user_id, search_categories["room"]);
    }

    return result;
  }

  // ── 2. Message search (search room events by body content) ─────────────
  json message_search(const std::string& user_id, const std::string& search_term,
                      int limit, const std::string& order_by) {
    std::lock_guard<std::mutex> lock(g_search_lock);

    if (!g_search_rate_limiter.check(user_id)) {
      json err;
      err["errcode"] = "M_LIMIT_EXCEEDED";
      err["error"] = "Search rate limit exceeded";
      return err;
    }

    json result;
    result["results"] = json::array();
    result["count"] = 0;

    if (search_term.empty()) return result;

    int actual_limit = std::min(std::max(limit, 1), 100);

    // Get rooms the user is in
    auto user_rooms = get_user_rooms(user_id);

    for (auto& room_id : user_rooms) {
      auto hits = g_search_index.search_room(room_id, search_term, actual_limit);

      for (auto& hit : hits) {
        json sr;
        sr["rank"] = hit.relevance;
        json ev;
        ev["event_id"] = hit.event_id;
        ev["room_id"] = hit.room_id;
        ev["type"] = hit.event_type;
        ev["sender"] = hit.sender;
        ev["origin_server_ts"] = hit.origin_server_ts;

        // Fetch content from DB for full event data
        auto event_data = fetch_event(hit.event_id);
        if (event_data.contains("content")) {
          ev["content"] = event_data["content"];
        }

        sr["result"] = ev;
        result["results"].push_back(sr);
        result["count"] = static_cast<int64_t>(result["count"]) + 1;

        if (result["count"] >= actual_limit) break;
      }
      if (result["count"] >= actual_limit) break;
    }

    return result;
  }

  // ── 3. Room event search with highlights ────────────────────────────────
  json room_event_search(const std::string& room_id, const std::string& user_id,
                          const std::string& search_term, const json& filter_json,
                          int limit, bool include_profile) {
    std::lock_guard<std::mutex> lock(g_search_lock);

    json result;
    result["results"] = json::array();
    result["count"] = 0;
    result["highlights"] = json::array();

    if (search_term.empty()) return result;

    int actual_limit = std::min(std::max(limit, 1), 100);

    // Extract filters
    std::string sender_filter;
    if (filter_json.contains("senders")) {
      if (filter_json["senders"].is_array() && !filter_json["senders"].empty()) {
        sender_filter = filter_json["senders"][0].get<std::string>();
      }
    }

    std::string type_filter;
    if (filter_json.contains("types")) {
      if (filter_json["types"].is_array() && !filter_json["types"].empty()) {
        type_filter = filter_json["types"][0].get<std::string>();
      }
    }

    bool contains_url = filter_json.value("contains_url", false);

    std::string order_by = filter_json.value("order_by", "rank");

    auto hits = g_search_index.search_room(room_id, search_term, actual_limit);

    for (auto& hit : hits) {
      // Apply filters
      if (!sender_filter.empty() && hit.sender != sender_filter) continue;
      if (!type_filter.empty() && hit.event_type != type_filter) continue;

      json sr;
      sr["rank"] = hit.relevance;

      // Fetch full event from DB
      json full_event = fetch_event(hit.event_id);

      if (contains_url) {
        std::string text = extract_searchable_text(
          full_event.value("content", json::object()));
        if (text.find("http") == std::string::npos) continue;
      }

      // Generate highlights
      std::string search_text = extract_searchable_text(
        full_event.value("content", json::object()));
      json event_highlights = generate_highlights(search_text, search_term);

      if (!event_highlights.empty()) {
        sr["highlights"] = event_highlights;
        result["highlights"].push_back(hit.event_id);
      }

      json ev;
      ev["event_id"] = hit.event_id;
      ev["room_id"] = hit.room_id;
      ev["type"] = hit.event_type;
      ev["sender"] = hit.sender;
      ev["content"] = full_event.value("content", json::object());
      ev["origin_server_ts"] = hit.origin_server_ts;

      if (include_profile) {
        auto profile = fetch_user_profile(hit.sender);
        if (!profile.empty()) {
          ev["sender_profile"] = profile;
        }
      }

      sr["result"] = ev;
      result["results"].push_back(sr);
      result["count"] = static_cast<int64_t>(result["count"]) + 1;
    }

    // Sort if requested
    if (order_by == "recent" || order_by == "recency") {
      std::sort(result["results"].begin(), result["results"].end(),
        [](const json& a, const json& b) {
          json ev_a = a["result"];
          json ev_b = b["result"];
          int64_t ts_a = ev_a.value("origin_server_ts", 0);
          int64_t ts_b = ev_b.value("origin_server_ts", 0);
          return ts_a > ts_b;
        });
    }

    return result;
  }

  // ── 4. Search ordering (by rank, by recency) ────────────────────────────
  void apply_search_ordering(json& results_array, const std::string& order_by) {
    if (order_by == "rank") {
      std::sort(results_array.begin(), results_array.end(),
        [](const json& a, const json& b) {
          return a.value("rank", 0.0) > b.value("rank", 0.0);
        });
    } else if (order_by == "recent" || order_by == "recency") {
      std::sort(results_array.begin(), results_array.end(),
        [](const json& a, const json& b) {
          int64_t ts_a = a["result"].value("origin_server_ts", 0);
          int64_t ts_b = b["result"].value("origin_server_ts", 0);
          return ts_a > ts_b;
        });
    } else if (order_by == "oldest") {
      std::sort(results_array.begin(), results_array.end(),
        [](const json& a, const json& b) {
          int64_t ts_a = a["result"].value("origin_server_ts", 0);
          int64_t ts_b = b["result"].value("origin_server_ts", 0);
          return ts_a < ts_b;
        });
    }
  }

  // ── 5. Search grouping (group results by room) ──────────────────────────
  json group_search_by_room(const json& results_array) {
    json grouped;
    std::map<std::string, json> room_groups;

    for (auto& result : results_array) {
      std::string room_id = result["result"].value("room_id", "");
      if (!room_groups.count(room_id)) {
        room_groups[room_id] = json::object();
        room_groups[room_id]["room_id"] = room_id;
        room_groups[room_id]["results"] = json::array();
        room_groups[room_id]["count"] = 0;
      }
      room_groups[room_id]["results"].push_back(result);
      room_groups[room_id]["count"] = static_cast<int64_t>(
        room_groups[room_id]["count"]) + 1;
    }

    json groups_array = json::array();
    for (auto& [rid, group] : room_groups) {
      groups_array.push_back(group);
    }
    return groups_array;
  }

  // ── 6. Search result context (events before/after match) ────────────────
  json get_search_result_context(const std::string& event_id,
                                  const std::string& room_id,
                                  int before_limit, int after_limit) {
    std::lock_guard<std::mutex> lock(g_search_lock);

    json context;
    context["event_id"] = event_id;
    context["events_before"] = json::array();
    context["events_after"] = json::array();

    int actual_before = std::min(std::max(before_limit, 0), 20);
    int actual_after = std::min(std::max(after_limit, 0), 20);

    if (actual_before == 0 && actual_after == 0) return context;

    // Get target event stream ordering
    auto target = fetch_event(event_id);
    if (target.empty()) return context;

    int64_t target_stream = target.value("stream_ordering", 0);

    // Events before
    if (actual_before > 0) {
      auto before_rows = db_.execute("search_context_before",
        "SELECT event_id, type, sender, content, stream_ordering, origin_server_ts "
        "FROM events WHERE room_id='" + sql_escape(room_id) + "' "
        "AND stream_ordering < " + std::to_string(target_stream) + " "
        "AND (is_state=0 OR is_state IS NULL) "
        "ORDER BY stream_ordering DESC LIMIT " + std::to_string(actual_before));

      for (auto& row : before_rows) {
        json ev;
        ev["event_id"] = row[0].value.value_or("");
        ev["type"] = row[1].value.value_or("");
        ev["sender"] = row[2].value.value_or("");
        ev["content"] = parse_event_content(row[3].value.value_or("{}"));
        ev["origin_server_ts"] = row[5].value ? std::stoll(*row[5].value) : 0;
        context["events_before"].push_back(ev);
      }
    }

    // Events after
    if (actual_after > 0) {
      auto after_rows = db_.execute("search_context_after",
        "SELECT event_id, type, sender, content, stream_ordering, origin_server_ts "
        "FROM events WHERE room_id='" + sql_escape(room_id) + "' "
        "AND stream_ordering > " + std::to_string(target_stream) + " "
        "AND (is_state=0 OR is_state IS NULL) "
        "ORDER BY stream_ordering ASC LIMIT " + std::to_string(actual_after));

      for (auto& row : after_rows) {
        json ev;
        ev["event_id"] = row[0].value.value_or("");
        ev["type"] = row[1].value.value_or("");
        ev["sender"] = row[2].value.value_or("");
        ev["content"] = parse_event_content(row[3].value.value_or("{}"));
        ev["origin_server_ts"] = row[5].value ? std::stoll(*row[5].value) : 0;
        context["events_after"].push_back(ev);
      }
    }

    return context;
  }

  // ── 16. Search result pagination ────────────────────────────────────────
  json paginate_search_results(const std::string& search_token,
                                const std::string& search_term,
                                const std::string& user_id,
                                int limit, const std::string& direction) {
    std::lock_guard<std::mutex> lock(g_search_lock);

    json result;
    result["results"] = json::array();
    result["count"] = 0;

    // Decode token: format "stream_order:search_hash"
    int64_t cursor = 0;
    try {
      auto colon_pos = search_token.find(':');
      if (colon_pos != std::string::npos) {
        cursor = std::stoll(search_token.substr(0, colon_pos));
      }
    } catch (...) {
      return result;
    }

    int actual_limit = std::min(std::max(limit, 1), 50);

    std::string comp_op = (direction == "b" || direction == "backwards") ? "<" : ">";
    std::string order_by_dir = (direction == "b" || direction == "backwards") ? "DESC" : "ASC";

    auto rows = db_.execute("paginate_search",
      "SELECT event_id, room_id, type, sender, content, stream_ordering, origin_server_ts "
      "FROM events "
      "WHERE content LIKE '%" + sql_escape(search_term) + "%' "
      "AND stream_ordering " + comp_op + " " + std::to_string(cursor) + " "
      "AND (is_state=0 OR is_state IS NULL) "
      "ORDER BY stream_ordering " + order_by_dir + " "
      "LIMIT " + std::to_string(actual_limit));

    for (auto& row : rows) {
      json ev;
      ev["event_id"] = row[0].value.value_or("");
      ev["room_id"] = row[1].value.value_or("");
      ev["type"] = row[2].value.value_or("");
      ev["sender"] = row[3].value.value_or("");
      ev["content"] = parse_event_content(row[4].value.value_or("{}"));
      ev["stream_ordering"] = row[5].value ? std::stoll(*row[5].value) : 0;
      ev["origin_server_ts"] = row[6].value ? std::stoll(*row[6].value) : 0;

      json sr;
      sr["rank"] = 0.5;
      sr["result"] = ev;
      result["results"].push_back(sr);
      result["count"] = static_cast<int64_t>(result["count"]) + 1;

      // Set next batch token
      if (result["count"] == actual_limit) {
        int64_t last_stream = ev["stream_ordering"].is_number()
          ? ev["stream_ordering"].get<int64_t>() : cursor;
        result["next_batch"] = std::to_string(last_stream) + ":search_" + gen_token(8);
      }
    }

    return result;
  }

  // ── 17. Search filters (by room, by sender, by date range) ──────────────
  json search_with_filters(const std::string& user_id,
                            const std::string& search_term,
                            const json& filters) {
    std::lock_guard<std::mutex> lock(g_search_lock);

    json result;
    result["results"] = json::array();
    result["count"] = 0;

    if (search_term.empty()) return result;

    std::string room_filter = filters.value("room_id", "");
    std::string sender_filter = filters.value("sender", "");
    int64_t from_ts = filters.value("from_ts", 0);
    int64_t to_ts = filters.value("to_ts", 0);
    int limit = filters.value("limit", 20);
    limit = std::min(std::max(limit, 1), 100);

    // If room filter specified, verify user is in that room
    if (!room_filter.empty()) {
      auto user_rooms = get_user_rooms(user_id);
      bool in_room = false;
      for (auto& r : user_rooms) {
        if (r == room_filter) { in_room = true; break; }
      }
      if (!in_room) {
        result["error"] = "User is not a member of the specified room";
        return result;
      }
    }

    auto hits = g_search_index.search(search_term, limit,
                                       room_filter, sender_filter,
                                       from_ts, to_ts);

    for (auto& hit : hits) {
      json sr;
      sr["rank"] = hit.relevance;

      json ev;
      ev["event_id"] = hit.event_id;
      ev["room_id"] = hit.room_id;
      ev["type"] = hit.event_type;
      ev["sender"] = hit.sender;
      ev["origin_server_ts"] = hit.origin_server_ts;

      // Fetch full content
      auto full_event = fetch_event(hit.event_id);
      if (full_event.contains("content")) {
        ev["content"] = full_event["content"];
      }

      sr["result"] = ev;
      result["results"].push_back(sr);
      result["count"] = static_cast<int64_t>(result["count"]) + 1;
    }

    return result;
  }

  // ── 18. Search result deduplication ─────────────────────────────────────
  json deduplicate_search_results(const json& results) {
    json deduped;
    deduped["count"] = 0;
    deduped["results"] = json::array();

    std::unordered_set<std::string> seen_ids;

    for (auto& res : results) {
      if (res.contains("result") && res["result"].contains("event_id")) {
        std::string eid = res["result"]["event_id"].get<std::string>();
        if (!seen_ids.count(eid)) {
          seen_ids.insert(eid);
          deduped["results"].push_back(res);
          deduped["count"] = static_cast<int64_t>(deduped["count"]) + 1;
        }
      }
    }

    deduped["duplicates_removed"] = static_cast<int64_t>(
      results.size() - seen_ids.size());
    return deduped;
  }

  // Database fetch helpers
  json fetch_event(const std::string& event_id) {
    auto rows = db_.execute("fetch_event_by_id",
      "SELECT event_id, room_id, type, sender, content, state_key, "
      "stream_ordering, origin_server_ts, depth, is_redacted, redacts, "
      "prev_events, auth_events "
      "FROM events WHERE event_id='" + sql_escape(event_id) + "'");

    if (rows.empty()) return json::object();

    auto& row = rows[0];
    json ev;
    ev["event_id"] = row[0].value.value_or("");
    ev["room_id"] = row[1].value.value_or("");
    ev["type"] = row[2].value.value_or("");
    ev["sender"] = row[3].value.value_or("");
    ev["content"] = parse_event_content(row[4].value.value_or("{}"));
    ev["origin_server_ts"] = row[7].value ? std::stoll(*row[7].value) : 0;
    ev["stream_ordering"] = row[6].value ? std::stoll(*row[6].value) : 0;

    std::string state_key = row[5].value.value_or("");
    if (!state_key.empty()) ev["state_key"] = state_key;

    if (row[9].value && *row[9].value == "1") {
      // Return redacted skeleton
      json redacted;
      redacted["event_id"] = ev["event_id"];
      redacted["room_id"] = ev["room_id"];
      redacted["sender"] = ev["sender"];
      redacted["type"] = ev["type"];
      redacted["origin_server_ts"] = ev["origin_server_ts"];
      if (!state_key.empty()) redacted["state_key"] = state_key;
      return redacted;
    }

    return ev;
  }

private:
  struct SearchResult {
    std::string event_id;
    std::string room_id;
    std::string event_type;
    std::string sender;
    json content;
    int64_t origin_server_ts{0};
    int64_t stream_ordering{0};
    double relevance{0.0};
  };

  std::vector<SearchResult> perform_search(const std::string& user_id,
                                            const std::string& search_term,
                                            const std::string& keys,
                                            const json& cat,
                                            int limit,
                                            const std::string& order_by) {
    std::vector<SearchResult> results;

    // Get filter params
    std::string room_filter;
    if (cat.contains("filter") && cat["filter"].contains("rooms")) {
      auto& rooms_arr = cat["filter"]["rooms"];
      if (rooms_arr.is_array() && !rooms_arr.empty()) {
        room_filter = rooms_arr[0].get<std::string>();
      }
    }

    std::string sender_filter;
    if (cat.contains("filter") && cat["filter"].contains("senders")) {
      auto& senders_arr = cat["filter"]["senders"];
      if (senders_arr.is_array() && !senders_arr.empty()) {
        sender_filter = senders_arr[0].get<std::string>();
      }
    }

    // Use the search index
    auto hits = g_search_index.search(search_term, limit,
                                       room_filter, sender_filter, 0, 0);

    // DB fallback for richer results
    if (hits.empty()) {
      auto user_rooms = get_user_rooms(user_id);
      std::string room_where;
      if (!room_filter.empty()) {
        room_where = "AND e.room_id='" + sql_escape(room_filter) + "'";
      } else if (!user_rooms.empty()) {
        std::string rooms_list;
        for (auto& r : user_rooms) {
          if (!rooms_list.empty()) rooms_list += ",";
          rooms_list += "'" + sql_escape(r) + "'";
        }
        room_where = "AND e.room_id IN (" + rooms_list + ")";
      }

      std::string sql = "SELECT e.event_id, e.room_id, e.type, e.sender, "
        "e.content, e.stream_ordering, e.origin_server_ts "
        "FROM events e "
        "WHERE e.content LIKE '%" + sql_escape(search_term) + "%' "
        "AND (e.is_state=0 OR e.is_state IS NULL) " +
        room_where +
        " ORDER BY e.stream_ordering DESC LIMIT " + std::to_string(limit);

      auto rows = db_.execute("search_events_fallback", sql);

      for (auto& row : rows) {
        SearchResult sr;
        sr.event_id = row[0].value.value_or("");
        sr.room_id = row[1].value.value_or("");
        sr.event_type = row[2].value.value_or("");
        sr.sender = row[3].value.value_or("");
        sr.content = parse_event_content(row[4].value.value_or("{}"));
        sr.stream_ordering = row[5].value ? std::stoll(*row[5].value) : 0;
        sr.origin_server_ts = row[6].value ? std::stoll(*row[6].value) : 0;

        std::string text = extract_searchable_text(sr.content);
        sr.relevance = compute_relevance(text, search_term);

        results.push_back(sr);
      }
    } else {
      for (auto& hit : hits) {
        SearchResult sr;
        sr.event_id = hit.event_id;
        sr.room_id = hit.room_id;
        sr.event_type = hit.event_type;
        sr.sender = hit.sender;
        sr.content = json::object();
        sr.origin_server_ts = hit.origin_server_ts;
        sr.stream_ordering = hit.stream_ordering;
        sr.relevance = hit.relevance;

        // Try to get content from DB
        auto full_event = fetch_event(hit.event_id);
        if (full_event.contains("content")) {
          sr.content = full_event["content"];
        }

        results.push_back(sr);
      }
    }

    // Apply ordering
    if (order_by == "rank") {
      std::sort(results.begin(), results.end(), [](const SearchResult& a, const SearchResult& b) {
        if (std::abs(a.relevance - b.relevance) > 0.001)
          return a.relevance > b.relevance;
        return a.stream_ordering > b.stream_ordering;
      });
    } else if (order_by == "recent" || order_by == "recency") {
      std::sort(results.begin(), results.end(), [](const SearchResult& a, const SearchResult& b) {
        return a.origin_server_ts > b.origin_server_ts;
      });
    }

    return results;
  }

  std::vector<std::string> get_user_rooms(const std::string& user_id) {
    std::vector<std::string> rooms;
    auto rows = db_.execute("get_user_rooms",
      "SELECT room_id FROM room_memberships "
      "WHERE user_id='" + sql_escape(user_id) + "' AND membership='join'");

    for (auto& row : rows) {
      rooms.push_back(row[0].value.value_or(""));
    }
    return rooms;
  }

  json search_rooms_by_term(const std::string& user_id, const json& cat) {
    json result;
    result["results"] = json::array();
    result["count"] = 0;

    std::string search_term = cat.value("search_term", "");
    if (search_term.empty()) return result;

    int limit = cat.value("limit", 10);
    limit = std::min(std::max(limit, 1), 50);

    auto rows = db_.execute("search_rooms",
      "SELECT room_id, name, topic, canonical_alias, num_joined_members, "
      "encryption, join_rules, history_visibility, guest_access "
      "FROM rooms WHERE (name LIKE '%" + sql_escape(search_term) + "%' "
      "OR room_id LIKE '%" + sql_escape(search_term) + "%' "
      "OR topic LIKE '%" + sql_escape(search_term) + "%') "
      "LIMIT " + std::to_string(limit));

    for (auto& row : rows) {
      json room;
      room["room_id"] = row[0].value.value_or("");
      room["name"] = row[1].value.value_or("");
      room["topic"] = row[2].value.value_or("");
      room["canonical_alias"] = row[3].value.value_or("");
      room["num_joined_members"] = row[4].value ? std::stoi(*row[4].value) : 0;
      result["results"].push_back(room);
      result["count"] = static_cast<int64_t>(result["count"]) + 1;
    }

    return result;
  }

  json fetch_user_profile(const std::string& user_id) {
    json profile;
    auto rows = db_.execute("fetch_profile",
      "SELECT display_name, avatar_url FROM profiles WHERE user_id='" +
      sql_escape(user_id) + "'");

    if (!rows.empty()) {
      profile["display_name"] = rows[0][0].value.value_or("");
      profile["avatar_url"] = rows[0][1].value.value_or("");
    }
    return profile;
  }

  DatabasePool& db_;
};

// ============================================================================
// EventContextHandler - Event context API
// ============================================================================
class EventContextHandler {
public:
  explicit EventContextHandler(DatabasePool& db) : db_(db) {}

  // ── 7. Event context API (GET /rooms/{roomId}/context/{eventId}) ────────
  json get_event_context(const std::string& room_id, const std::string& event_id,
                          int64_t before_limit, int64_t after_limit,
                          bool include_state) {
    std::lock_guard<std::mutex> lock(g_context_lock);

    json result;
    result["event"] = json::object();
    result["events_before"] = json::array();
    result["events_after"] = json::array();
    result["state"] = json::array();

    if (before_limit <= 0) before_limit = 5;
    if (before_limit > 100) before_limit = 100;
    if (after_limit <= 0) after_limit = 5;
    if (after_limit > 100) after_limit = 100;

    // Get target event
    auto target = fetch_full_event(room_id, event_id);
    if (target.empty()) {
      return make_error_obj("M_NOT_FOUND",
        "Event '" + event_id + "' not found in room '" + room_id + "'");
    }

    result["event"] = target;

    int64_t target_stream = target.value("stream_ordering", 0);

    // ── 8. Context before ─────────────────────────────────────────────────
    json events_before = get_events_before(room_id, target_stream, before_limit);
    result["events_before"] = events_before;

    // ── 9. Context after ─────────────────────────────────────────────────
    json events_after = get_events_after(room_id, target_stream, after_limit);
    result["events_after"] = events_after;

    // ── 10. Context state ─────────────────────────────────────────────────
    if (include_state) {
      json state = get_state_at_event(room_id, target_stream, target);
      result["state"] = state;
    }

    // Pagination tokens
    result["start"] = "";
    result["end"] = "";

    if (events_before.size() > 0) {
      auto& first_before = events_before[0];
      if (first_before.contains("stream_ordering")) {
        result["start"] = "s" + std::to_string(
          first_before["stream_ordering"].get<int64_t>());
      }
    }
    if (events_after.size() > 0) {
      auto& last_after = events_after[events_after.size() - 1];
      if (last_after.contains("stream_ordering")) {
        result["end"] = "s" + std::to_string(
          last_after["stream_ordering"].get<int64_t>());
      }
    }

    return result;
  }

  // ── 8. Context before (events before the target event) ─────────────────
  json get_events_before(const std::string& room_id, int64_t target_stream,
                          int64_t limit) {
    json events = json::array();

    auto rows = db_.execute("context_before_events",
      "SELECT event_id, type, sender, content, state_key, "
      "stream_ordering, origin_server_ts, depth, is_redacted, redacts "
      "FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND stream_ordering < " + std::to_string(target_stream) + " "
      "AND (is_outlier=0 OR is_outlier IS NULL) "
      "ORDER BY stream_ordering DESC "
      "LIMIT " + std::to_string(limit));

    // Reverse to chronological order
    std::vector<json> temp;
    for (auto& row : rows) {
      json ev = build_event_json(row);
      temp.push_back(ev);
    }
    std::reverse(temp.begin(), temp.end());
    for (auto& ev : temp) {
      events.push_back(ev);
    }
    return events;
  }

  // ── 9. Context after (events after the target event) ───────────────────
  json get_events_after(const std::string& room_id, int64_t target_stream,
                         int64_t limit) {
    json events = json::array();

    auto rows = db_.execute("context_after_events",
      "SELECT event_id, type, sender, content, state_key, "
      "stream_ordering, origin_server_ts, depth, is_redacted, redacts "
      "FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND stream_ordering > " + std::to_string(target_stream) + " "
      "AND (is_outlier=0 OR is_outlier IS NULL) "
      "ORDER BY stream_ordering ASC "
      "LIMIT " + std::to_string(limit));

    for (auto& row : rows) {
      json ev = build_event_json(row);
      events.push_back(ev);
    }
    return events;
  }

  // ── 10. Context state (state at the target event) ──────────────────────
  json get_state_at_event(const std::string& room_id, int64_t target_stream,
                           const json& target_event) {
    json state = json::array();

    // Get state events that were active at the time of this event
    // This means state events with stream_ordering <= target_stream
    std::string state_sql =
      "SELECT event_id, type, state_key, sender, content, "
      "stream_ordering, origin_server_ts "
      "FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND is_state=1 "
      "AND stream_ordering <= " + std::to_string(target_stream) + " "
      "ORDER BY stream_ordering ASC";

    auto rows = db_.execute("context_state", state_sql);

    // Keep only the latest state for each (type, state_key) pair
    std::map<std::pair<std::string, std::string>, json> latest_state;

    for (auto& row : rows) {
      std::string event_type = row[1].value.value_or("");
      std::string state_key = row[2].value.value_or("");

      json st;
      st["event_id"] = row[0].value.value_or("");
      st["type"] = event_type;
      st["state_key"] = state_key;
      st["sender"] = row[3].value.value_or("");
      st["content"] = parse_event_content(row[4].value.value_or("{}"));
      st["origin_server_ts"] = row[6].value ? std::stoll(*row[6].value) : 0;

      auto key = std::make_pair(event_type, state_key);
      latest_state[key] = st;
    }

    for (auto& [key, st] : latest_state) {
      state.push_back(st);
    }

    return state;
  }

  // Get detailed timeline context (expanded context with metadata)
  json get_timeline_context(const std::string& room_id,
                             const std::string& event_id,
                             int64_t before_limit, int64_t after_limit) {
    std::lock_guard<std::mutex> lock(g_context_lock);

    json result;
    result["event"] = json::object();
    result["events_before"] = json::array();
    result["events_after"] = json::array();
    result["timeline_metadata"] = json::object();

    if (before_limit <= 0) before_limit = 10;
    if (before_limit > 200) before_limit = 200;
    if (after_limit <= 0) after_limit = 10;
    if (after_limit > 200) after_limit = 200;

    auto target = fetch_full_event(room_id, event_id);
    if (target.empty()) {
      return make_error_obj("M_NOT_FOUND", "Event not found");
    }

    result["event"] = target;
    int64_t target_stream = target.value("stream_ordering", 0);

    // Get before events
    json before = json::array();
    auto before_rows = db_.execute("timeline_before",
      "SELECT event_id, type, sender, content, state_key, "
      "stream_ordering, origin_server_ts, depth, is_redacted, redacts, "
      "membership, is_state "
      "FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND stream_ordering < " + std::to_string(target_stream) + " "
      "AND (is_outlier=0 OR is_outlier IS NULL) "
      "ORDER BY stream_ordering DESC "
      "LIMIT " + std::to_string(before_limit));

    std::vector<json> temp_before;
    for (auto& row : before_rows) {
      json ev = build_event_json(row);
      ev["contextual"] = true;
      temp_before.push_back(ev);
    }
    std::reverse(temp_before.begin(), temp_before.end());
    for (auto& ev : temp_before) {
      before.push_back(ev);
    }
    result["events_before"] = before;

    // Get after events
    json after = json::array();
    auto after_rows = db_.execute("timeline_after",
      "SELECT event_id, type, sender, content, state_key, "
      "stream_ordering, origin_server_ts, depth, is_redacted, redacts, "
      "membership, is_state "
      "FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND stream_ordering > " + std::to_string(target_stream) + " "
      "AND (is_outlier=0 OR is_outlier IS NULL) "
      "ORDER BY stream_ordering ASC "
      "LIMIT " + std::to_string(after_limit));

    for (auto& row : after_rows) {
      json ev = build_event_json(row);
      ev["contextual"] = true;
      after.push_back(ev);
    }
    result["events_after"] = after;

    // Timeline metadata
    result["timeline_metadata"]["total_before_available"] = count_events_before(
      room_id, target_stream);
    result["timeline_metadata"]["total_after_available"] = count_events_after(
      room_id, target_stream);

    return result;
  }

private:
  json fetch_full_event(const std::string& room_id, const std::string& event_id) {
    auto rows = db_.execute("fetch_full_event",
      "SELECT event_id, type, sender, content, state_key, "
      "stream_ordering, origin_server_ts, depth, is_redacted, redacts, "
      "membership, is_state, prev_events, auth_events "
      "FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND event_id='" + sql_escape(event_id) + "'");

    if (rows.empty()) return json::object();

    auto& row = rows[0];
    json ev = build_event_json(row);

    // Add prev_events if available
    std::string prev_str = row[12].value.value_or("[]");
    if (!prev_str.empty() && prev_str != "[]") {
      try {
        ev["prev_events"] = json::parse(prev_str);
      } catch (...) {}
    }

    return ev;
  }

  json build_event_json(const storage::Row& row) {
    json ev;
    ev["event_id"] = row[0].value.value_or("");
    ev["type"] = row[1].value.value_or("");
    ev["sender"] = row[2].value.value_or("");
    ev["content"] = parse_event_content(row[3].value.value_or("{}"));
    ev["origin_server_ts"] = row[6].value ? std::stoll(*row[6].value) : 0;
    ev["stream_ordering"] = row[5].value ? std::stoll(*row[5].value) : 0;

    std::string state_key = row[4].value.value_or("");
    if (!state_key.empty()) ev["state_key"] = state_key;

    if (row.count() > 7) {
      ev["depth"] = row[7].value ? std::stoll(*row[7].value) : 0;
    }

    // Handle redaction
    if (row.count() > 8 && row[8].value && *row[8].value == "1") {
      json redacted;
      redacted["event_id"] = ev["event_id"];
      redacted["room_id"] = ev.value("room_id", "");
      redacted["sender"] = ev["sender"];
      redacted["type"] = ev["type"];
      redacted["origin_server_ts"] = ev["origin_server_ts"];
      if (!state_key.empty()) redacted["state_key"] = state_key;
      return redacted;
    }

    if (row.count() > 10) {
      std::string membership = row[10].value.value_or("");
      if (!membership.empty()) ev["membership"] = membership;
    }

    return ev;
  }

  int64_t count_events_before(const std::string& room_id, int64_t target_stream) {
    auto rows = db_.execute("count_before",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND stream_ordering < " + std::to_string(target_stream));

    if (!rows.empty() && rows[0][0].value) {
      return std::stoll(*rows[0][0].value);
    }
    return 0;
  }

  int64_t count_events_after(const std::string& room_id, int64_t target_stream) {
    auto rows = db_.execute("count_after",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND stream_ordering > " + std::to_string(target_stream));

    if (!rows.empty() && rows[0][0].value) {
      return std::stoll(*rows[0][0].value);
    }
    return 0;
  }

  DatabasePool& db_;
};

// ============================================================================
// RoomStatsHandler - Room and user statistics
// ============================================================================
class RoomStatsHandler {
public:
  explicit RoomStatsHandler(DatabasePool& db) : db_(db) {}

  // ── 11. Room statistics API (total events, members, messages) ───────────
  json get_room_statistics(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(g_stats_lock);

    json stats;
    stats["room_id"] = room_id;

    // Total events
    auto ev_rows = db_.execute("room_total_events",
      "SELECT COUNT(*) as cnt FROM events WHERE room_id='" +
      sql_escape(room_id) + "'");
    stats["total_events"] = (!ev_rows.empty() && ev_rows[0][0].value)
      ? std::stoll(*ev_rows[0][0].value) : 0;

    // Total members
    auto mem_rows = db_.execute("room_total_members",
      "SELECT COUNT(*) as cnt FROM room_memberships "
      "WHERE room_id='" + sql_escape(room_id) + "' AND membership='join'");
    stats["total_members"] = (!mem_rows.empty() && mem_rows[0][0].value)
      ? std::stoll(*mem_rows[0][0].value) : 0;

    // Total messages (non-state events)
    auto msg_rows = db_.execute("room_total_messages",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND (is_state=0 OR is_state IS NULL)");
    stats["total_messages"] = (!msg_rows.empty() && msg_rows[0][0].value)
      ? std::stoll(*msg_rows[0][0].value) : 0;

    // Total state events
    auto state_rows = db_.execute("room_total_state",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' AND is_state=1");
    stats["total_state_events"] = (!state_rows.empty() && state_rows[0][0].value)
      ? std::stoll(*state_rows[0][0].value) : 0;

    // Banned users count
    auto banned_rows = db_.execute("room_banned",
      "SELECT COUNT(*) as cnt FROM room_memberships "
      "WHERE room_id='" + sql_escape(room_id) + "' AND membership='ban'");
    stats["banned_users"] = (!banned_rows.empty() && banned_rows[0][0].value)
      ? std::stoll(*banned_rows[0][0].value) : 0;

    // Invited users count
    auto invited_rows = db_.execute("room_invited",
      "SELECT COUNT(*) as cnt FROM room_memberships "
      "WHERE room_id='" + sql_escape(room_id) + "' AND membership='invite'");
    stats["invited_users"] = (!invited_rows.empty() && invited_rows[0][0].value)
      ? std::stoll(*invited_rows[0][0].value) : 0;

    // Knocked users
    auto knocked_rows = db_.execute("room_knocked",
      "SELECT COUNT(*) as cnt FROM room_memberships "
      "WHERE room_id='" + sql_escape(room_id) + "' AND membership='knock'");
    stats["knocked_users"] = (!knocked_rows.empty() && knocked_rows[0][0].value)
      ? std::stoll(*knocked_rows[0][0].value) : 0;

    // Left users
    auto left_rows = db_.execute("room_left",
      "SELECT COUNT(*) as cnt FROM room_memberships "
      "WHERE room_id='" + sql_escape(room_id) + "' AND membership='leave'");
    stats["left_users"] = (!left_rows.empty() && left_rows[0][0].value)
      ? std::stoll(*left_rows[0][0].value) : 0;

    // Room name and topic
    auto info_rows = db_.execute("room_info",
      "SELECT name, topic, canonical_alias, room_version, "
      "is_encrypted, history_visibility, join_rules, guest_access "
      "FROM rooms WHERE room_id='" + sql_escape(room_id) + "'");

    if (!info_rows.empty()) {
      stats["name"] = info_rows[0][0].value.value_or("");
      stats["topic"] = info_rows[0][1].value.value_or("");
      stats["canonical_alias"] = info_rows[0][2].value.value_or("");
      stats["room_version"] = info_rows[0][3].value.value_or("1");
      stats["is_encrypted"] = info_rows[0][4].value.value_or("0") == "1";
      stats["history_visibility"] = info_rows[0][5].value.value_or("shared");
      stats["join_rules"] = info_rows[0][6].value.value_or("invite");
      stats["guest_access"] = info_rows[0][7].value.value_or("forbidden");
    }

    return stats;
  }

  // ── 12. Room event counts (per-type event counts) ───────────────────────
  json get_room_event_counts(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(g_stats_lock);

    json counts;
    counts["room_id"] = room_id;
    counts["event_types"] = json::object();

    auto rows = db_.execute("event_type_counts",
      "SELECT type, COUNT(*) as cnt FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "GROUP BY type ORDER BY cnt DESC");

    for (auto& row : rows) {
      std::string event_type = row[0].value.value_or("");
      int64_t cnt = row[1].value ? std::stoll(*row[1].value) : 0;
      counts["event_types"][event_type] = cnt;
    }

    // Add total
    int64_t total = 0;
    for (auto& [key, val] : counts["event_types"].items()) {
      total += val.get<int64_t>();
    }
    counts["total"] = total;

    return counts;
  }

  // Per-type state event counts
  json get_room_state_event_counts(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(g_stats_lock);

    json counts;
    counts["room_id"] = room_id;
    counts["state_event_types"] = json::object();

    auto rows = db_.execute("state_type_counts",
      "SELECT type, COUNT(*) as cnt FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' AND is_state=1 "
      "GROUP BY type ORDER BY cnt DESC");

    int64_t total = 0;
    for (auto& row : rows) {
      std::string event_type = row[0].value.value_or("");
      int64_t cnt = row[1].value ? std::stoll(*row[1].value) : 0;
      counts["state_event_types"][event_type] = cnt;
      total += cnt;
    }
    counts["total_state_events"] = total;

    return counts;
  }

  // ── 13. Room timeline analytics ─────────────────────────────────────────
  json get_room_timeline_analytics(const std::string& room_id,
                                     int64_t window_sec) {
    std::lock_guard<std::mutex> lock(g_stats_lock);

    json analytics;
    analytics["room_id"] = room_id;
    analytics["window_seconds"] = window_sec;

    int64_t now = now_ms();
    int64_t cutoff = now - (window_sec * 1000);

    // Events in time window
    auto ev_rows = db_.execute("timeline_window_events",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND origin_server_ts >= " + std::to_string(cutoff));
    analytics["events_in_window"] = (!ev_rows.empty() && ev_rows[0][0].value)
      ? std::stoll(*ev_rows[0][0].value) : 0;

    // Messages per hour (8 windows of window_sec/8 duration)
    int64_t sub_window = window_sec / 8;
    if (sub_window < 60) sub_window = 60;

    json messages_per_hour = json::array();
    for (int i = 0; i < 8; ++i) {
      int64_t sub_start = cutoff + (i * sub_window * 1000);
      int64_t sub_end = sub_start + (sub_window * 1000);

      auto sub_rows = db_.execute("timeline_subwindow",
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "AND origin_server_ts >= " + std::to_string(sub_start) +
        " AND origin_server_ts < " + std::to_string(sub_end) +
        " AND (is_state=0 OR is_state IS NULL)");

      json slot;
      slot["start_ts"] = sub_start;
      slot["end_ts"] = sub_end;
      slot["count"] = (!sub_rows.empty() && sub_rows[0][0].value)
        ? std::stoll(*sub_rows[0][0].value) : 0;
      messages_per_hour.push_back(slot);
    }
    analytics["messages_per_window"] = messages_per_hour;

    // Top senders
    auto senders_rows = db_.execute("top_senders",
      "SELECT sender, COUNT(*) as cnt FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND (is_state=0 OR is_state IS NULL) "
      "GROUP BY sender ORDER BY cnt DESC LIMIT 10");

    json top_senders = json::array();
    for (auto& row : senders_rows) {
      json sender;
      sender["user_id"] = row[0].value.value_or("");
      sender["message_count"] = row[1].value ? std::stoll(*row[1].value) : 0;
      top_senders.push_back(sender);
    }
    analytics["top_senders"] = top_senders;

    // First event time
    auto first_ev = db_.execute("first_event",
      "SELECT MIN(origin_server_ts) as ts FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "'");
    analytics["first_event_ts"] = (!first_ev.empty() && first_ev[0][0].value)
      ? std::stoll(*first_ev[0][0].value) : 0;

    // Last event time
    auto last_ev = db_.execute("last_event",
      "SELECT MAX(origin_server_ts) as ts FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "'");
    analytics["last_event_ts"] = (!last_ev.empty() && last_ev[0][0].value)
      ? std::stoll(*last_ev[0][0].value) : 0;

    // Activity heatmap (hourly distribution)
    json hourly_activity = json::object();
    for (int h = 0; h < 24; ++h) {
      int64_t hour_start = h * 3600000;
      int64_t hour_end = (h + 1) * 3600000;

      auto hour_rows = db_.execute("hourly_activity",
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "AND (origin_server_ts % 86400000) >= " + std::to_string(hour_start) +
        " AND (origin_server_ts % 86400000) < " + std::to_string(hour_end));

      hourly_activity["hour_" + std::to_string(h)] = (!hour_rows.empty() && hour_rows[0][0].value)
        ? std::stoll(*hour_rows[0][0].value) : 0;
    }
    analytics["hourly_activity_distribution"] = hourly_activity;

    return analytics;
  }

  // ── 14. User room statistics ────────────────────────────────────────────
  json get_user_room_statistics(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(g_stats_lock);

    json stats;
    stats["user_id"] = user_id;

    // Total rooms user is in
    auto rooms_rows = db_.execute("user_room_count",
      "SELECT COUNT(*) as cnt FROM room_memberships "
      "WHERE user_id='" + sql_escape(user_id) + "' AND membership='join'");
    stats["joined_rooms"] = (!rooms_rows.empty() && rooms_rows[0][0].value)
      ? std::stoll(*rooms_rows[0][0].value) : 0;

    // Total invites
    auto invite_rows = db_.execute("user_invite_count",
      "SELECT COUNT(*) as cnt FROM room_memberships "
      "WHERE user_id='" + sql_escape(user_id) + "' AND membership='invite'");
    stats["pending_invites"] = (!invite_rows.empty() && invite_rows[0][0].value)
      ? std::stoll(*invite_rows[0][0].value) : 0;

    // Total events sent
    auto ev_rows = db_.execute("user_event_count",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE sender='" + sql_escape(user_id) + "'");
    stats["total_events_sent"] = (!ev_rows.empty() && ev_rows[0][0].value)
      ? std::stoll(*ev_rows[0][0].value) : 0;

    // Total messages sent
    auto msg_rows = db_.execute("user_message_count",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE sender='" + sql_escape(user_id) + "' "
      "AND type='m.room.message' OR type='m.room.encrypted'");
    stats["total_messages_sent"] = (!msg_rows.empty() && msg_rows[0][0].value)
      ? std::stoll(*msg_rows[0][0].value) : 0;

    // Total rooms created
    auto created_rows = db_.execute("user_created_count",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE sender='" + sql_escape(user_id) + "' AND type='m.room.create'");
    stats["rooms_created"] = (!created_rows.empty() && created_rows[0][0].value)
      ? std::stoll(*created_rows[0][0].value) : 0;

    // Event type breakdown
    auto type_rows = db_.execute("user_type_breakdown",
      "SELECT type, COUNT(*) as cnt FROM events "
      "WHERE sender='" + sql_escape(user_id) + "' "
      "GROUP BY type ORDER BY cnt DESC LIMIT 20");

    json event_types = json::object();
    for (auto& row : type_rows) {
      event_types[row[0].value.value_or("")] = row[1].value
        ? std::stoll(*row[1].value) : 0;
    }
    stats["event_type_breakdown"] = event_types;

    // Per-room stats for user
    auto per_room_rows = db_.execute("user_per_room_stats",
      "SELECT e.room_id, r.name, COUNT(*) as cnt "
      "FROM events e "
      "LEFT JOIN rooms r ON e.room_id = r.room_id "
      "WHERE e.sender='" + sql_escape(user_id) + "' "
      "GROUP BY e.room_id ORDER BY cnt DESC LIMIT 20");

    json per_room = json::array();
    for (auto& row : per_room_rows) {
      json room_stat;
      room_stat["room_id"] = row[0].value.value_or("");
      room_stat["room_name"] = row[1].value.value_or("");
      room_stat["events_count"] = row[2].value ? std::stoll(*row[2].value) : 0;
      per_room.push_back(room_stat);
    }
    stats["per_room_stats"] = per_room;

    return stats;
  }

  // Get user stats in a specific room
  json get_user_stats_in_room(const std::string& user_id,
                               const std::string& room_id) {
    std::lock_guard<std::mutex> lock(g_stats_lock);

    json stats;
    stats["user_id"] = user_id;
    stats["room_id"] = room_id;

    // Membership info
    auto mem_rows = db_.execute("user_room_membership",
      "SELECT membership, display_name FROM room_memberships "
      "WHERE user_id='" + sql_escape(user_id) + "' "
      "AND room_id='" + sql_escape(room_id) + "'");

    if (!mem_rows.empty()) {
      stats["membership"] = mem_rows[0][0].value.value_or("leave");
      stats["display_name"] = mem_rows[0][1].value.value_or("");
    } else {
      stats["membership"] = "leave";
    }

    // Events sent in room
    auto ev_rows = db_.execute("user_room_events",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE sender='" + sql_escape(user_id) + "' "
      "AND room_id='" + sql_escape(room_id) + "'");
    stats["events_in_room"] = (!ev_rows.empty() && ev_rows[0][0].value)
      ? std::stoll(*ev_rows[0][0].value) : 0;

    // Messages sent in room
    auto msg_rows = db_.execute("user_room_messages",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE sender='" + sql_escape(user_id) + "' "
      "AND room_id='" + sql_escape(room_id) + "' "
      "AND (is_state=0 OR is_state IS NULL)");
    stats["messages_in_room"] = (!msg_rows.empty() && msg_rows[0][0].value)
      ? std::stoll(*msg_rows[0][0].value) : 0;

    // First event timestamp in room
    auto first_rows = db_.execute("user_room_first",
      "SELECT MIN(origin_server_ts) as ts FROM events "
      "WHERE sender='" + sql_escape(user_id) + "' "
      "AND room_id='" + sql_escape(room_id) + "'");
    stats["first_event_ts"] = (!first_rows.empty() && first_rows[0][0].value)
      ? std::stoll(*first_rows[0][0].value) : 0;

    // Last event timestamp in room
    auto last_rows = db_.execute("user_room_last",
      "SELECT MAX(origin_server_ts) as ts FROM events "
      "WHERE sender='" + sql_escape(user_id) + "' "
      "AND room_id='" + sql_escape(room_id) + "'");
    stats["last_event_ts"] = (!last_rows.empty() && last_rows[0][0].value)
      ? std::stoll(*last_rows[0][0].value) : 0;

    return stats;
  }

  // ── 15. Server-side search indexing ─────────────────────────────────────
  json get_index_statistics() {
    std::lock_guard<std::mutex> lock(g_stats_lock);
    return g_search_index.get_index_stats();
  }

  // Server-wide statistics
  json get_server_statistics() {
    std::lock_guard<std::mutex> lock(g_stats_lock);

    json stats;
    stats["generated_at"] = now_ms();

    // Total users
    auto user_rows = db_.execute("server_user_count",
      "SELECT COUNT(*) as cnt FROM users");
    stats["total_users"] = (!user_rows.empty() && user_rows[0][0].value)
      ? std::stoll(*user_rows[0][0].value) : 0;

    // Total active users (30 days)
    int64_t thirty_days_ago = now_ms() - (30LL * 24 * 3600 * 1000);
    auto active_rows = db_.execute("server_active_users",
      "SELECT COUNT(DISTINCT sender) as cnt FROM events "
      "WHERE origin_server_ts >= " + std::to_string(thirty_days_ago));
    stats["active_users_30d"] = (!active_rows.empty() && active_rows[0][0].value)
      ? std::stoll(*active_rows[0][0].value) : 0;

    // Total rooms
    auto room_rows = db_.execute("server_room_count",
      "SELECT COUNT(*) as cnt FROM rooms");
    stats["total_rooms"] = (!room_rows.empty() && room_rows[0][0].value)
      ? std::stoll(*room_rows[0][0].value) : 0;

    // Total events
    auto ev_rows = db_.execute("server_event_count",
      "SELECT COUNT(*) as cnt FROM events");
    stats["total_events"] = (!ev_rows.empty() && ev_rows[0][0].value)
      ? std::stoll(*ev_rows[0][0].value) : 0;

    // Total messages
    auto msg_rows = db_.execute("server_message_count",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE (is_state=0 OR is_state IS NULL)");
    stats["total_messages"] = (!msg_rows.empty() && msg_rows[0][0].value)
      ? std::stoll(*msg_rows[0][0].value) : 0;

    // Search index stats
    stats["search_index"] = g_search_index.get_index_stats();

    // Rate limiter stats
    stats["search_rate_limiter"] = g_search_rate_limiter.global_stats();

    // Top rooms by event count
    auto top_rooms_rows = db_.execute("server_top_rooms",
      "SELECT room_id, COUNT(*) as cnt FROM events "
      "GROUP BY room_id ORDER BY cnt DESC LIMIT 10");

    json top_rooms = json::array();
    for (auto& row : top_rooms_rows) {
      json r;
      r["room_id"] = row[0].value.value_or("");
      r["event_count"] = row[1].value ? std::stoll(*row[1].value) : 0;
      top_rooms.push_back(r);
    }
    stats["top_rooms_by_activity"] = top_rooms;

    // Top users by event count
    auto top_users_rows = db_.execute("server_top_users",
      "SELECT sender, COUNT(*) as cnt FROM events "
      "GROUP BY sender ORDER BY cnt DESC LIMIT 10");

    json top_users = json::array();
    for (auto& row : top_users_rows) {
      json u;
      u["user_id"] = row[0].value.value_or("");
      u["event_count"] = row[1].value ? std::stoll(*row[1].value) : 0;
      top_users.push_back(u);
    }
    stats["top_users_by_activity"] = top_users;

    // Events per type globally
    auto type_rows = db_.execute("server_type_breakdown",
      "SELECT type, COUNT(*) as cnt FROM events "
      "GROUP BY type ORDER BY cnt DESC LIMIT 30");

    json type_breakdown = json::object();
    for (auto& row : type_rows) {
      type_breakdown[row[0].value.value_or("")] = row[1].value
        ? std::stoll(*row[1].value) : 0;
    }
    stats["event_type_breakdown"] = type_breakdown;

    return stats;
  }

  // Daily room stats snapshot
  json get_room_daily_stats(const std::string& room_id, int days) {
    std::lock_guard<std::mutex> lock(g_stats_lock);

    json daily_stats;
    daily_stats["room_id"] = room_id;
    daily_stats["daily"] = json::array();

    if (days <= 0) days = 7;
    if (days > 90) days = 90;

    int64_t now = now_ms();
    int64_t day_ms = 24LL * 3600 * 1000;

    for (int d = 0; d < days; ++d) {
      int64_t day_start = now - ((d + 1) * day_ms);
      int64_t day_end = now - (d * day_ms);

      json day;
      day["date"] = day_start;
      day["date_end"] = day_end;

      auto ev_rows = db_.execute("daily_events",
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "AND origin_server_ts >= " + std::to_string(day_start) +
        " AND origin_server_ts < " + std::to_string(day_end));
      day["events"] = (!ev_rows.empty() && ev_rows[0][0].value)
        ? std::stoll(*ev_rows[0][0].value) : 0;

      auto msg_rows = db_.execute("daily_messages",
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "AND (is_state=0 OR is_state IS NULL) "
        "AND origin_server_ts >= " + std::to_string(day_start) +
        " AND origin_server_ts < " + std::to_string(day_end));
      day["messages"] = (!msg_rows.empty() && msg_rows[0][0].value)
        ? std::stoll(*msg_rows[0][0].value) : 0;

      auto join_rows = db_.execute("daily_joins",
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "AND type='m.room.member' "
        "AND origin_server_ts >= " + std::to_string(day_start) +
        " AND origin_server_ts < " + std::to_string(day_end));
      day["joins"] = (!join_rows.empty() && join_rows[0][0].value)
        ? std::stoll(*join_rows[0][0].value) : 0;

      daily_stats["daily"].push_back(day);
    }

    return daily_stats;
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// SearchAdminHandler - Administrative search operations
// ============================================================================
class SearchAdminHandler {
public:
  explicit SearchAdminHandler(DatabasePool& db) : db_(db) {}

  // ── 19. Search rate limiting admin ──────────────────────────────────────
  json get_rate_limit_stats(const std::string& user_id) {
    return g_search_rate_limiter.get_stats(user_id);
  }

  json get_global_rate_limit_stats() {
    return g_search_rate_limiter.global_stats();
  }

  json reset_user_rate_limit(const std::string& user_id) {
    g_search_rate_limiter.reset_user(user_id);
    json resp;
    resp["success"] = true;
    resp["user_id"] = user_id;
    resp["message"] = "Rate limit reset for user";
    return resp;
  }

  // ── 15. Admin: rebuild search index ─────────────────────────────────────
  json rebuild_search_index() {
    std::lock_guard<std::mutex> lock(g_index_lock);

    json result;
    result["action"] = "rebuild_search_index";
    int64_t start = now_ms();

    g_search_index.rebuild_from_db(db_);

    int64_t elapsed = now_ms() - start;
    result["elapsed_ms"] = elapsed;
    result["stats"] = g_search_index.get_index_stats();
    result["success"] = true;

    return result;
  }

  json rebuild_search_index_for_room(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(g_index_lock);

    json result;
    result["action"] = "rebuild_search_index_for_room";
    result["room_id"] = room_id;
    int64_t start = now_ms();

    // Re-index events for this room
    auto rows = db_.execute("rebuild_room_index",
      "SELECT event_id, room_id, sender, type, content, origin_server_ts, stream_ordering "
      "FROM events WHERE room_id='" + sql_escape(room_id) + "' "
      "AND (is_state=0 OR is_state IS NULL) "
      "ORDER BY stream_ordering ASC");

    int64_t count = 0;
    for (auto& row : rows) {
      std::string event_id = row[0].value.value_or("");
      std::string rid = row[1].value.value_or("");
      std::string sender = row[2].value.value_or("");
      std::string event_type = row[3].value.value_or("");
      std::string content_str = row[4].value.value_or("{}");
      int64_t ots = row[5].value ? std::stoll(*row[5].value) : 0;
      int64_t so = row[6].value ? std::stoll(*row[6].value) : 0;

      json content = parse_event_content(content_str);
      std::string text = extract_searchable_text(content);

      if (!text.empty()) {
        g_search_index.index_event(event_id, rid, sender, event_type,
                                    text, ots, so);
        ++count;
      }
    }

    int64_t elapsed = now_ms() - start;
    result["events_indexed"] = count;
    result["elapsed_ms"] = elapsed;
    result["success"] = true;

    return result;
  }

  // ── 20. Search admin API ────────────────────────────────────────────────
  json get_search_admin_stats() {
    json stats;
    stats["search_index"] = g_search_index.get_index_stats();
    stats["rate_limiter"] = g_search_rate_limiter.global_stats();

    // DB stats
    auto idx_rows = db_.execute("admin_index_stats",
      "SELECT COUNT(*) as cnt FROM events");
    stats["total_events_in_db"] = (!idx_rows.empty() && idx_rows[0][0].value)
      ? std::stoll(*idx_rows[0][0].value) : 0;

    auto room_rows = db_.execute("admin_room_count",
      "SELECT COUNT(*) as cnt FROM rooms");
    stats["total_rooms_in_db"] = (!room_rows.empty() && room_rows[0][0].value)
      ? std::stoll(*room_rows[0][0].value) : 0;

    auto user_rows = db_.execute("admin_user_count",
      "SELECT COUNT(*) as cnt FROM users");
    stats["total_users_in_db"] = (!user_rows.empty() && user_rows[0][0].value)
      ? std::stoll(*user_rows[0][0].value) : 0;

    return stats;
  }

  // Clear search index
  json clear_search_index() {
    std::lock_guard<std::mutex> lock(g_index_lock);
    g_search_index.clear();
    json result;
    result["success"] = true;
    result["message"] = "Search index cleared";
    return result;
  }

  // Index a single event manually
  json index_single_event(const std::string& event_id) {
    auto rows = db_.execute("admin_fetch_event",
      "SELECT event_id, room_id, sender, type, content, origin_server_ts, stream_ordering "
      "FROM events WHERE event_id='" + sql_escape(event_id) + "'");

    json result;
    if (rows.empty()) {
      result["error"] = "Event not found";
      return result;
    }

    auto& row = rows[0];
    std::string eid = row[0].value.value_or("");
    std::string rid = row[1].value.value_or("");
    std::string sender = row[2].value.value_or("");
    std::string event_type = row[3].value.value_or("");
    std::string content_str = row[4].value.value_or("{}");
    int64_t ots = row[5].value ? std::stoll(*row[5].value) : 0;
    int64_t so = row[6].value ? std::stoll(*row[6].value) : 0;

    json content = parse_event_content(content_str);
    std::string text = extract_searchable_text(content);

    if (!text.empty()) {
      g_search_index.index_event(eid, rid, sender, event_type, text, ots, so);
      result["success"] = true;
      result["message"] = "Event indexed";
    } else {
      result["success"] = false;
      result["message"] = "No searchable text found";
    }

    return result;
  }

  // De-index a single event
  json deindex_single_event(const std::string& event_id) {
    g_search_index.deindex_event(event_id);
    json result;
    result["success"] = true;
    result["message"] = "Event deindexed";
    return result;
  }

  // Perform a raw index search (admin debug)
  json admin_search(const std::string& query, int limit) {
    json result;
    result["query"] = query;
    result["results"] = json::array();
    result["count"] = 0;

    auto hits = g_search_index.search(query, std::min(std::max(limit, 1), 200));

    for (auto& hit : hits) {
      json h;
      h["event_id"] = hit.event_id;
      h["room_id"] = hit.room_id;
      h["sender"] = hit.sender;
      h["type"] = hit.event_type;
      h["relevance"] = hit.relevance;
      h["text_preview"] = hit.text_content.size() > 200
        ? hit.text_content.substr(0, 200) + "..."
        : hit.text_content;
      result["results"].push_back(h);
    }
    result["count"] = static_cast<int64_t>(hits.size());

    return result;
  }

  // ── 19. Search rate limiting configuration ──────────────────────────────
  struct RateLimitConfig {
    int max_requests_per_window{30};
    int64_t window_seconds{60};
    bool enabled{true};
  };

  json set_rate_limit(const RateLimitConfig& config) {
    rate_limit_config_ = config;
    json resp;
    resp["success"] = true;
    resp["max_requests_per_window"] = config.max_requests_per_window;
    resp["window_seconds"] = config.window_seconds;
    resp["enabled"] = config.enabled;
    return resp;
  }

  json get_rate_limit_config() {
    json config;
    config["max_requests_per_window"] = rate_limit_config_.max_requests_per_window;
    config["window_seconds"] = rate_limit_config_.window_seconds;
    config["enabled"] = rate_limit_config_.enabled;
    return config;
  }

  // Purge old events from index
  json purge_old_events(int64_t older_than_ms) {
    std::lock_guard<std::mutex> lock(g_index_lock);

    auto rows = db_.execute("admin_old_events",
      "SELECT event_id FROM events "
      "WHERE origin_server_ts < " + std::to_string(older_than_ms) +
      " AND (is_state=0 OR is_state IS NULL) "
      "ORDER BY origin_server_ts ASC LIMIT 10000");

    int64_t purged = 0;
    for (auto& row : rows) {
      std::string eid = row[0].value.value_or("");
      g_search_index.deindex_event(eid);
      ++purged;
    }

    json result;
    result["success"] = true;
    result["purged"] = purged;
    result["older_than_ms"] = older_than_ms;
    return result;
  }

private:
  DatabasePool& db_;
  RateLimitConfig rate_limit_config_;
};

// ============================================================================
// Top-level handler API functions
// These are the entry points called from the REST layer.
// ============================================================================

// Search handler instance (lazy initialized)
static std::unique_ptr<SearchHandler> g_search_handler;
static std::unique_ptr<EventContextHandler> g_event_context_handler;
static std::unique_ptr<RoomStatsHandler> g_room_stats_handler;
static std::unique_ptr<SearchAdminHandler> g_search_admin_handler;
static std::mutex g_handler_init_mutex;

static void ensure_handlers_initialized(DatabasePool& db) {
  std::lock_guard<std::mutex> lock(g_handler_init_mutex);
  if (!g_search_handler) {
    g_search_handler = std::make_unique<SearchHandler>(db);
    g_event_context_handler = std::make_unique<EventContextHandler>(db);
    g_room_stats_handler = std::make_unique<RoomStatsHandler>(db);
    g_search_admin_handler = std::make_unique<SearchAdminHandler>(db);
  }
}

// ============================================================================
// Public API: Full-text search
// POST /_matrix/client/v3/search
// ============================================================================
json handle_full_text_search(DatabasePool& db, const std::string& user_id,
                               const json& body) {
  ensure_handlers_initialized(db);
  return g_search_handler->full_text_search(user_id, body);
}

// ============================================================================
// Public API: Message search (simplified)
// POST /_matrix/client/v3/search/messages
// ============================================================================
json handle_message_search(DatabasePool& db, const std::string& user_id,
                            const std::string& search_term, int limit,
                            const std::string& order_by) {
  ensure_handlers_initialized(db);
  return g_search_handler->message_search(user_id, search_term, limit, order_by);
}

// ============================================================================
// Public API: Room event search
// POST /_matrix/client/v3/rooms/{roomId}/search
// ============================================================================
json handle_room_event_search(DatabasePool& db, const std::string& room_id,
                                const std::string& user_id,
                                const std::string& search_term,
                                const json& filter_json, int limit,
                                bool include_profile) {
  ensure_handlers_initialized(db);
  return g_search_handler->room_event_search(room_id, user_id,
    search_term, filter_json, limit, include_profile);
}

// ============================================================================
// Public API: Group search results by room
// ============================================================================
json handle_group_search_by_room(DatabasePool& db, const json& results_array) {
  ensure_handlers_initialized(db);
  return g_search_handler->group_search_by_room(results_array);
}

// ============================================================================
// Public API: Apply search ordering
// ============================================================================
json handle_apply_search_ordering(DatabasePool& db, json& results_array,
                                    const std::string& order_by) {
  ensure_handlers_initialized(db);
  g_search_handler->apply_search_ordering(results_array, order_by);
  return results_array;
}

// ============================================================================
// Public API: Get search result context (events before/after)
// ============================================================================
json handle_search_result_context(DatabasePool& db, const std::string& event_id,
                                    const std::string& room_id,
                                    int before_limit, int after_limit) {
  ensure_handlers_initialized(db);
  return g_search_handler->get_search_result_context(event_id, room_id,
    before_limit, after_limit);
}

// ============================================================================
// Public API: Event context
// GET /_matrix/client/v3/rooms/{roomId}/context/{eventId}
// ============================================================================
json handle_event_context(DatabasePool& db, const std::string& room_id,
                           const std::string& event_id,
                           int64_t before_limit, int64_t after_limit,
                           bool include_state) {
  ensure_handlers_initialized(db);
  return g_event_context_handler->get_event_context(room_id, event_id,
    before_limit, after_limit, include_state);
}

// ============================================================================
// Public API: Timeline context (expanded)
// ============================================================================
json handle_timeline_context(DatabasePool& db, const std::string& room_id,
                               const std::string& event_id,
                               int64_t before_limit, int64_t after_limit) {
  ensure_handlers_initialized(db);
  return g_event_context_handler->get_timeline_context(room_id, event_id,
    before_limit, after_limit);
}

// ============================================================================
// Public API: Events before a target event
// ============================================================================
json handle_events_before(DatabasePool& db, const std::string& room_id,
                           int64_t target_stream, int64_t limit) {
  ensure_handlers_initialized(db);
  return g_event_context_handler->get_events_before(room_id, target_stream, limit);
}

// ============================================================================
// Public API: Events after a target event
// ============================================================================
json handle_events_after(DatabasePool& db, const std::string& room_id,
                          int64_t target_stream, int64_t limit) {
  ensure_handlers_initialized(db);
  return g_event_context_handler->get_events_after(room_id, target_stream, limit);
}

// ============================================================================
// Public API: Room statistics
// ============================================================================
json handle_room_statistics(DatabasePool& db, const std::string& room_id) {
  ensure_handlers_initialized(db);
  return g_room_stats_handler->get_room_statistics(room_id);
}

// ============================================================================
// Public API: Room event counts (per-type)
// ============================================================================
json handle_room_event_counts(DatabasePool& db, const std::string& room_id) {
  ensure_handlers_initialized(db);
  return g_room_stats_handler->get_room_event_counts(room_id);
}

// ============================================================================
// Public API: Room state event counts
// ============================================================================
json handle_room_state_event_counts(DatabasePool& db, const std::string& room_id) {
  ensure_handlers_initialized(db);
  return g_room_stats_handler->get_room_state_event_counts(room_id);
}

// ============================================================================
// Public API: Room timeline analytics
// ============================================================================
json handle_room_timeline_analytics(DatabasePool& db, const std::string& room_id,
                                      int64_t window_sec) {
  ensure_handlers_initialized(db);
  return g_room_stats_handler->get_room_timeline_analytics(room_id, window_sec);
}

// ============================================================================
// Public API: User room statistics
// ============================================================================
json handle_user_room_statistics(DatabasePool& db, const std::string& user_id) {
  ensure_handlers_initialized(db);
  return g_room_stats_handler->get_user_room_statistics(user_id);
}

// ============================================================================
// Public API: User stats in specific room
// ============================================================================
json handle_user_stats_in_room(DatabasePool& db, const std::string& user_id,
                                 const std::string& room_id) {
  ensure_handlers_initialized(db);
  return g_room_stats_handler->get_user_stats_in_room(user_id, room_id);
}

// ============================================================================
// Public API: Search index statistics
// ============================================================================
json handle_index_statistics(DatabasePool& db) {
  ensure_handlers_initialized(db);
  return g_room_stats_handler->get_index_statistics();
}

// ============================================================================
// Public API: Server-wide statistics
// ============================================================================
json handle_server_statistics(DatabasePool& db) {
  ensure_handlers_initialized(db);
  return g_room_stats_handler->get_server_statistics();
}

// ============================================================================
// Public API: Room daily stats
// ============================================================================
json handle_room_daily_stats(DatabasePool& db, const std::string& room_id,
                               int days) {
  ensure_handlers_initialized(db);
  return g_room_stats_handler->get_room_daily_stats(room_id, days);
}

// ============================================================================
// Public API: Search result pagination
// ============================================================================
json handle_search_pagination(DatabasePool& db, const std::string& search_token,
                                const std::string& search_term,
                                const std::string& user_id, int limit,
                                const std::string& direction) {
  ensure_handlers_initialized(db);
  return g_search_handler->paginate_search_results(search_token, search_term,
    user_id, limit, direction);
}

// ============================================================================
// Public API: Search with filters
// ============================================================================
json handle_search_with_filters(DatabasePool& db, const std::string& user_id,
                                  const std::string& search_term,
                                  const json& filters) {
  ensure_handlers_initialized(db);
  return g_search_handler->search_with_filters(user_id, search_term, filters);
}

// ============================================================================
// Public API: Deduplicate search results
// ============================================================================
json handle_deduplicate_search(DatabasePool& db, const json& results) {
  ensure_handlers_initialized(db);
  return g_search_handler->deduplicate_search_results(results);
}

// ============================================================================
// Public API: Search rate limiter admin
// ============================================================================
json handle_search_rate_limit_stats(DatabasePool& db, const std::string& user_id) {
  ensure_handlers_initialized(db);
  return g_search_admin_handler->get_rate_limit_stats(user_id);
}

json handle_search_rate_limit_reset(DatabasePool& db, const std::string& user_id) {
  ensure_handlers_initialized(db);
  return g_search_admin_handler->reset_user_rate_limit(user_id);
}

// ============================================================================
// Public API: Admin - rebuild search index
// ============================================================================
json handle_admin_rebuild_index(DatabasePool& db) {
  ensure_handlers_initialized(db);
  return g_search_admin_handler->rebuild_search_index();
}

json handle_admin_rebuild_room_index(DatabasePool& db, const std::string& room_id) {
  ensure_handlers_initialized(db);
  return g_search_admin_handler->rebuild_search_index_for_room(room_id);
}

// ============================================================================
// Public API: Admin - search admin stats
// ============================================================================
json handle_search_admin_stats(DatabasePool& db) {
  ensure_handlers_initialized(db);
  return g_search_admin_handler->get_search_admin_stats();
}

// ============================================================================
// Public API: Admin - clear search index
// ============================================================================
json handle_admin_clear_index(DatabasePool& db) {
  ensure_handlers_initialized(db);
  return g_search_admin_handler->clear_search_index();
}

// ============================================================================
// Public API: Admin - index/deindex single event
// ============================================================================
json handle_admin_index_event(DatabasePool& db, const std::string& event_id) {
  ensure_handlers_initialized(db);
  return g_search_admin_handler->index_single_event(event_id);
}

json handle_admin_deindex_event(DatabasePool& db, const std::string& event_id) {
  ensure_handlers_initialized(db);
  return g_search_admin_handler->deindex_single_event(event_id);
}

// ============================================================================
// Public API: Admin - raw search for debugging
// ============================================================================
json handle_admin_search(DatabasePool& db, const std::string& query, int limit) {
  ensure_handlers_initialized(db);
  return g_search_admin_handler->admin_search(query, limit);
}

// ============================================================================
// Initialization: called on server startup to prepare search infrastructure
// ============================================================================
void init_search_context_stats(DatabasePool& db, bool rebuild_index) {
  ensure_handlers_initialized(db);

  // Optionally rebuild the search index from the database
  if (rebuild_index) {
    g_search_admin_handler->rebuild_search_index();
  }

  // Ensure search-related DB tables exist
  db.execute("ensure_search_tables", R"(
    CREATE TABLE IF NOT EXISTS search_index_meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  )");

  // Record index version
  db.execute("set_index_version",
    "INSERT OR REPLACE INTO search_index_meta (key, value) "
    "VALUES ('version', '1')");
}

// ============================================================================
// Shutdown: clean up resources
// ============================================================================
void shutdown_search_context_stats() {
  std::lock_guard<std::mutex> lock(g_handler_init_mutex);
  g_search_handler.reset();
  g_event_context_handler.reset();
  g_room_stats_handler.reset();
  g_search_admin_handler.reset();
}

// ============================================================================
// Event indexing hook - called when new events are persisted
// ============================================================================
void index_new_event(const std::string& event_id, const std::string& room_id,
                     const std::string& sender, const std::string& event_type,
                     const json& content, int64_t origin_server_ts,
                     int64_t stream_ordering) {
  std::string text = extract_searchable_text(content);
  if (!text.empty()) {
    g_search_index.index_event(event_id, room_id, sender, event_type,
                                text, origin_server_ts, stream_ordering);
  }
}

// ============================================================================
// Event de-index hook - called when events are redacted or deleted
// ============================================================================
void deindex_event(const std::string& event_id) {
  g_search_index.deindex_event(event_id);
}

// ============================================================================
// Bulk index - for batch operations
// ============================================================================
void bulk_index_events(DatabasePool& db, const std::vector<std::string>& event_ids) {
  for (auto& eid : event_ids) {
    auto rows = db.execute("bulk_fetch",
      "SELECT event_id, room_id, sender, type, content, origin_server_ts, stream_ordering "
      "FROM events WHERE event_id='" + sql_escape(eid) + "'");

    if (!rows.empty()) {
      auto& row = rows[0];
      std::string rid = row[1].value.value_or("");
      std::string sender = row[2].value.value_or("");
      std::string event_type = row[3].value.value_or("");
      json content = parse_event_content(row[4].value.value_or("{}"));
      int64_t ots = row[5].value ? std::stoll(*row[5].value) : 0;
      int64_t so = row[6].value ? std::stoll(*row[6].value) : 0;

      std::string text = extract_searchable_text(content);
      if (!text.empty()) {
        g_search_index.index_event(eid, rid, sender, event_type,
                                    text, ots, so);
      }
    }
  }
}

// ============================================================================
// Search health check
// ============================================================================
json search_health_check(DatabasePool& db) {
  json health;
  health["status"] = "ok";
  health["search_index"] = g_search_index.get_index_stats();
  health["rate_limiter"] = g_search_rate_limiter.global_stats();
  health["timestamp"] = now_ms();

  // Check DB connectivity
  try {
    auto rows = db.execute("search_health_ping",
      "SELECT 1 as ok");
    health["database"] = "connected";
  } catch (...) {
    health["database"] = "error";
    health["status"] = "degraded";
  }

  return health;
}

// ============================================================================
// Search Suggestions / Autocomplete
// Builds a suggestion index from frequently searched terms and room content
// ============================================================================
class SearchAutoComplete {
public:
  SearchAutoComplete() = default;

  // Record a search query to build suggestion frequency
  void record_search(const std::string& query) {
    std::lock_guard<std::mutex> lock(suggest_lock_);
    auto it = search_frequency_.find(query);
    if (it != search_frequency_.end()) {
      it->second++;
    } else {
      search_frequency_[query] = 1;
    }
    // Keep only top 10000 entries
    if (search_frequency_.size() > 10000) {
      prune_frequencies();
    }
  }

  // Get autocomplete suggestions for a prefix
  json suggest(const std::string& prefix, int limit = 10) {
    std::lock_guard<std::mutex> lock(suggest_lock_);
    json suggestions = json::array();

    // Exact prefix matches first
    for (auto& [term, freq] : search_frequency_) {
      if (term.size() >= prefix.size() &&
          term.compare(0, prefix.size(), prefix) == 0) {
        json s;
        s["term"] = term;
        s["frequency"] = freq;
        suggestions.push_back(s);
      }
    }

    // Sort by frequency
    std::sort(suggestions.begin(), suggestions.end(),
      [](const json& a, const json& b) {
        return a["frequency"].get<int64_t>() > b["frequency"].get<int64_t>();
      });

    if (static_cast<int>(suggestions.size()) > limit) {
      suggestions.erase(limit, suggestions.size() - limit);
    }

    return suggestions;
  }

  // Build suggestions from room names and topics in the DB
  void build_from_rooms(DatabasePool& db) {
    std::lock_guard<std::mutex> lock(suggest_lock_);
    auto rows = db.execute("suggest_rooms",
      "SELECT name, topic FROM rooms WHERE name IS NOT NULL AND name != '' "
      "LIMIT 5000");

    for (auto& row : rows) {
      std::string name = row[0].value.value_or("");
      std::string topic = row[1].value.value_or("");
      if (!name.empty()) add_term(name, 1);
      if (!topic.empty()) {
        // Tokenize topic and add individual words
        std::istringstream iss(topic);
        std::string word;
        while (iss >> word) {
          if (word.size() >= 3) add_term(word, 1);
        }
      }
    }
  }

  // Build suggestions from event content (most common terms)
  void build_from_events(DatabasePool& db, int sample_size = 10000) {
    std::lock_guard<std::mutex> lock(suggest_lock_);
    auto rows = db.execute("suggest_events",
      "SELECT content FROM events WHERE (is_state=0 OR is_state IS NULL) "
      "ORDER BY stream_ordering DESC LIMIT " + std::to_string(sample_size));

    for (auto& row : rows) {
      json content = parse_event_content(row[0].value.value_or("{}"));
      std::string text = extract_searchable_text(content);
      std::istringstream iss(text);
      std::string word;
      while (iss >> word) {
        if (word.size() >= 3) add_term(word, 1);
      }
    }
  }

  json get_stats() {
    std::lock_guard<std::mutex> lock(suggest_lock_);
    json stats;
    stats["total_terms"] = static_cast<int64_t>(search_frequency_.size());
    return stats;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(suggest_lock_);
    search_frequency_.clear();
  }

private:
  void add_term(const std::string& term, int64_t increment) {
    auto it = search_frequency_.find(term);
    if (it != search_frequency_.end()) {
      it->second += increment;
    } else {
      search_frequency_[term] = increment;
    }
  }

  void prune_frequencies() {
    // Keep top 5000 by frequency
    std::vector<std::pair<std::string, int64_t>> sorted;
    for (auto& [term, freq] : search_frequency_) {
      sorted.emplace_back(term, freq);
    }
    std::sort(sorted.begin(), sorted.end(),
      [](const auto& a, const auto& b) { return a.second > b.second; });
    if (sorted.size() > 5000) sorted.resize(5000);

    search_frequency_.clear();
    for (auto& [term, freq] : sorted) {
      search_frequency_[term] = freq;
    }
  }

  std::unordered_map<std::string, int64_t> search_frequency_;
  std::mutex suggest_lock_;
};

static SearchAutoComplete g_search_autocomplete;
static std::mutex g_autocomplete_lock;

// Public autocomplete API
json handle_search_suggest(DatabasePool& db, const std::string& prefix,
                            int limit) {
  return g_search_autocomplete.suggest(prefix, std::min(std::max(limit, 1), 50));
}

void record_search_query(const std::string& query) {
  if (!query.empty()) {
    g_search_autocomplete.record_search(query);
  }
}

void build_autocomplete_index(DatabasePool& db) {
  g_search_autocomplete.build_from_rooms(db);
  g_search_autocomplete.build_from_events(db);
}

json handle_autocomplete_stats(DatabasePool& db) {
  return g_search_autocomplete.get_stats();
}

void clear_autocomplete_index() {
  g_search_autocomplete.clear();
}

// ============================================================================
// Search Result Cache
// Caches recent search results to reduce DB load for repeated queries
// ============================================================================
class SearchResultCache {
public:
  struct CachedResult {
    json results;
    int64_t timestamp;
    int hit_count;
  };

  // Try to get cached results
  std::optional<json> get(const std::string& query_hash, int64_t max_age_ms = 30000) {
    std::lock_guard<std::mutex> lock(cache_lock_);
    auto it = cache_.find(query_hash);
    if (it == cache_.end()) return std::nullopt;

    int64_t age = now_ms() - it->second.timestamp;
    if (age > max_age_ms) {
      cache_.erase(it);
      return std::nullopt;
    }

    it->second.hit_count++;
    return it->second.results;
  }

  // Store results in cache
  void put(const std::string& query_hash, const json& results) {
    std::lock_guard<std::mutex> lock(cache_lock_);
    CachedResult entry;
    entry.results = results;
    entry.timestamp = now_ms();
    entry.hit_count = 0;

    cache_[query_hash] = entry;

    // Evict oldest entries if cache is too large
    if (cache_.size() > max_entries_) {
      evict_oldest();
    }
  }

  // Generate a hash for a search query
  static std::string hash_query(const std::string& query,
                                 const std::string& room_filter,
                                 const std::string& sender_filter) {
    std::string combined = query + "|" + room_filter + "|" + sender_filter;
    // Simple hash
    uint64_t h = 0;
    for (char c : combined) {
      h = h * 31 + static_cast<uint64_t>(static_cast<unsigned char>(c));
    }
    return std::to_string(h);
  }

  json get_stats() {
    std::lock_guard<std::mutex> lock(cache_lock_);
    json stats;
    stats["cache_size"] = static_cast<int64_t>(cache_.size());
    stats["max_entries"] = static_cast<int64_t>(max_entries_);

    int64_t total_hits = 0;
    for (auto& [key, entry] : cache_) {
      total_hits += entry.hit_count;
    }
    stats["total_hits"] = total_hits;

    return stats;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(cache_lock_);
    cache_.clear();
  }

  void set_max_entries(size_t max) {
    std::lock_guard<std::mutex> lock(cache_lock_);
    max_entries_ = max;
  }

private:
  void evict_oldest() {
    auto oldest = cache_.begin();
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
      if (it->second.timestamp < oldest->second.timestamp) {
        oldest = it;
      }
    }
    cache_.erase(oldest);
  }

  std::unordered_map<std::string, CachedResult> cache_;
  std::mutex cache_lock_;
  size_t max_entries_{1000};
};

static SearchResultCache g_search_cache;

// Cache API
json search_with_cache(DatabasePool& db, const std::string& user_id,
                        const std::string& search_term,
                        const json& filters) {
  std::string room_filter = filters.value("room_id", "");
  std::string sender_filter = filters.value("sender", "");
  std::string query_hash = SearchResultCache::hash_query(
    search_term, room_filter, sender_filter);

  // Try cache first
  int64_t cache_ttl = filters.value("cache_ttl_ms", 30000);
  auto cached = g_search_cache.get(query_hash, cache_ttl);
  if (cached) {
    json result = *cached;
    result["from_cache"] = true;
    return result;
  }

  // Perform actual search
  ensure_handlers_initialized(db);
  json result = g_search_handler->search_with_filters(
    user_id, search_term, filters);
  result["from_cache"] = false;

  // Cache the result
  g_search_cache.put(query_hash, result);

  return result;
}

json handle_cache_stats() {
  return g_search_cache.get_stats();
}

void handle_cache_clear() {
  g_search_cache.clear();
}

// ============================================================================
// Room Analytics - Trends, growth patterns, activity correlations
// ============================================================================
class RoomAnalytics {
public:
  explicit RoomAnalytics(DatabasePool& db) : db_(db) {}

  // Growth rate: members added over time windows
  json room_growth_analysis(const std::string& room_id, int days) {
    json analysis;
    analysis["room_id"] = room_id;
    analysis["daily_growth"] = json::array();

    if (days <= 0) days = 30;
    if (days > 365) days = 365;

    int64_t day_ms = 24LL * 3600 * 1000;
    int64_t now = now_ms();

    for (int d = days; d >= 0; --d) {
      int64_t day_start = now - (d * day_ms);
      int64_t day_end = day_start + day_ms;

      json day_stats;
      day_stats["day_offset"] = d;
      day_stats["date_ts"] = day_start;

      auto join_rows = db_.execute("growth_joins",
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "AND type='m.room.member' "
        "AND origin_server_ts >= " + std::to_string(day_start) +
        " AND origin_server_ts < " + std::to_string(day_end));
      day_stats["new_joins"] = (!join_rows.empty() && join_rows[0][0].value)
        ? std::stoll(*join_rows[0][0].value) : 0;

      auto leave_rows = db_.execute("growth_leaves",
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "AND type='m.room.member' "
        "AND origin_server_ts >= " + std::to_string(day_start) +
        " AND origin_server_ts < " + std::to_string(day_end));
      day_stats["leaves"] = (!leave_rows.empty() && leave_rows[0][0].value)
        ? std::stoll(*leave_rows[0][0].value) : 0;

      day_stats["net_change"] = day_stats["new_joins"].get<int64_t>() -
        day_stats["leaves"].get<int64_t>();

      analysis["daily_growth"].push_back(day_stats);
    }

    return analysis;
  }

  // Activity correlation: which rooms are active at the same time
  json room_activity_correlation(const std::string& room_id, int limit) {
    json correlation;
    correlation["room_id"] = room_id;
    correlation["correlated_rooms"] = json::array();

    if (limit <= 0) limit = 10;

    // Find users who are active in this room
    auto active_rows = db_.execute("corr_active_users",
      "SELECT DISTINCT sender FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND origin_server_ts >= " + std::to_string(now_ms() - (30LL * 24 * 3600 * 1000)) +
      " LIMIT 200");

    if (active_rows.empty()) return correlation;

    std::string user_list;
    for (auto& row : active_rows) {
      if (!user_list.empty()) user_list += ",";
      user_list += "'" + sql_escape(row[0].value.value_or("")) + "'";
    }

    // Find other rooms these users are in
    auto corr_rows = db_.execute("corr_related_rooms",
      "SELECT e2.room_id, COUNT(DISTINCT e2.sender) as shared_users, "
      "COUNT(*) as total_events "
      "FROM events e2 "
      "WHERE e2.sender IN (" + user_list + ") "
      "AND e2.room_id != '" + sql_escape(room_id) + "' "
      "AND e2.origin_server_ts >= " + std::to_string(now_ms() - (30LL * 24 * 3600 * 1000)) +
      " GROUP BY e2.room_id "
      "ORDER BY shared_users DESC LIMIT " + std::to_string(limit));

    for (auto& row : corr_rows) {
      json corr_room;
      corr_room["room_id"] = row[0].value.value_or("");
      corr_room["shared_users"] = row[1].value ? std::stoll(*row[1].value) : 0;
      corr_room["recent_events"] = row[2].value ? std::stoll(*row[2].value) : 0;
      correlation["correlated_rooms"].push_back(corr_room);
    }

    return correlation;
  }

  // Message type distribution analysis
  json message_type_distribution(const std::string& room_id) {
    json dist;
    dist["room_id"] = room_id;
    dist["message_types"] = json::object();

    auto rows = db_.execute("msg_type_dist",
      "SELECT type, COUNT(*) as cnt FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND (type LIKE 'm.room.message%' OR type LIKE 'm.%') "
      "AND (is_state=0 OR is_state IS NULL) "
      "GROUP BY type ORDER BY cnt DESC");

    for (auto& row : rows) {
      dist["message_types"][row[0].value.value_or("")] =
        row[1].value ? std::stoll(*row[1].value) : 0;
    }

    // Compute percentages
    int64_t total = 0;
    for (auto& [key, val] : dist["message_types"].items()) {
      total += val.get<int64_t>();
    }
    dist["total_messages"] = total;

    if (total > 0) {
      json percentages = json::object();
      for (auto& [key, val] : dist["message_types"].items()) {
        double pct = (val.get<int64_t>() * 100.0) / total;
        percentages[key] = std::round(pct * 100.0) / 100.0;
      }
      dist["percentages"] = percentages;
    }

    return dist;
  }

  // Content length statistics
  json content_length_stats(const std::string& room_id) {
    json stats;
    stats["room_id"] = room_id;

    auto rows = db_.execute("content_stats",
      "SELECT content FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND (is_state=0 OR is_state IS NULL) "
      "AND type='m.room.message' "
      "ORDER BY stream_ordering DESC LIMIT 5000");

    if (rows.empty()) return stats;

    std::vector<int64_t> lengths;
    for (auto& row : rows) {
      json content = parse_event_content(row[0].value.value_or("{}"));
      std::string body = content.value("body", "");
      lengths.push_back(static_cast<int64_t>(body.size()));
    }

    if (lengths.empty()) return stats;

    std::sort(lengths.begin(), lengths.end());
    stats["sample_size"] = static_cast<int64_t>(lengths.size());
    stats["min_length"] = lengths.front();
    stats["max_length"] = lengths.back();
    stats["median_length"] = lengths[lengths.size() / 2];

    int64_t sum = 0;
    for (auto l : lengths) sum += l;
    stats["average_length"] = sum / static_cast<int64_t>(lengths.size());

    // Length distribution buckets
    json buckets = json::object();
    int b50 = 0, b100 = 0, b250 = 0, b500 = 0, b1000 = 0, bplus = 0;
    for (auto l : lengths) {
      if (l <= 50) ++b50;
      else if (l <= 100) ++b100;
      else if (l <= 250) ++b250;
      else if (l <= 500) ++b500;
      else if (l <= 1000) ++b1000;
      else ++bplus;
    }
    buckets["0_50"] = b50;
    buckets["51_100"] = b100;
    buckets["101_250"] = b250;
    buckets["251_500"] = b500;
    buckets["501_1000"] = b1000;
    buckets["1001_plus"] = bplus;
    stats["length_distribution"] = buckets;

    return stats;
  }

  // Active hours analysis
  json active_hours_analysis(const std::string& room_id, int days) {
    json analysis;
    analysis["room_id"] = room_id;
    analysis["hourly_activity"] = json::object();

    if (days <= 0) days = 7;
    if (days > 90) days = 90;

    int64_t cutoff = now_ms() - (days * 24LL * 3600 * 1000);

    auto rows = db_.execute("active_hours",
      "SELECT origin_server_ts FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND origin_server_ts >= " + std::to_string(cutoff) +
      " AND (is_state=0 OR is_state IS NULL)");

    std::vector<int> hour_counts(24, 0);
    int64_t total = 0;

    for (auto& row : rows) {
      int64_t ts = row[0].value ? std::stoll(*row[0].value) : 0;
      if (ts > 0) {
        // Extract hour of day in UTC
        int64_t hour = (ts / 3600000) % 24;
        if (hour >= 0 && hour < 24) {
          hour_counts[static_cast<size_t>(hour)]++;
          total++;
        }
      }
    }

    json hour_json = json::object();
    for (int h = 0; h < 24; ++h) {
      std::string key = std::to_string(h);
      json hour_data;
      hour_data["count"] = hour_counts[h];
      hour_data["percentage"] = total > 0
        ? std::round((hour_counts[h] * 10000.0) / total) / 100.0 : 0.0;
      hour_json[key] = hour_data;
    }
    analysis["hourly_activity"] = hour_json;
    analysis["total_analyzed"] = total;
    analysis["period_days"] = days;

    // Find peak hour
    int peak_hour = 0;
    int peak_count = 0;
    for (int h = 0; h < 24; ++h) {
      if (hour_counts[h] > peak_count) {
        peak_count = hour_counts[h];
        peak_hour = h;
      }
    }
    analysis["peak_hour_utc"] = peak_hour;
    analysis["peak_hour_count"] = peak_count;

    return analysis;
  }

  // User churn analysis
  json user_churn_analysis(const std::string& room_id, int days) {
    json analysis;
    analysis["room_id"] = room_id;

    if (days <= 0) days = 30;
    int64_t cutoff = now_ms() - (days * 24LL * 3600 * 1000);

    // Users who joined in the period
    auto joined_rows = db_.execute("churn_joined",
      "SELECT COUNT(DISTINCT state_key) as cnt FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND type='m.room.member' "
      "AND origin_server_ts >= " + std::to_string(cutoff));
    analysis["new_members"] = (!joined_rows.empty() && joined_rows[0][0].value)
      ? std::stoll(*joined_rows[0][0].value) : 0;

    // Users who left in the period
    auto left_rows = db_.execute("churn_left",
      "SELECT COUNT(DISTINCT state_key) as cnt FROM events "
      "WHERE room_id='" + sql_escape(room_id) + "' "
      "AND type='m.room.member' "
      "AND origin_server_ts >= " + std::to_string(cutoff));
    analysis["departed_members"] = (!left_rows.empty() && left_rows[0][0].value)
      ? std::stoll(*left_rows[0][0].value) : 0;

    // Current members
    auto current_rows = db_.execute("churn_current",
      "SELECT COUNT(*) as cnt FROM room_memberships "
      "WHERE room_id='" + sql_escape(room_id) + "' AND membership='join'");
    analysis["current_members"] = (!current_rows.empty() && current_rows[0][0].value)
      ? std::stoll(*current_rows[0][0].value) : 0;

    // Churn rate: departed / (current + departed)
    int64_t departed = analysis["departed_members"].get<int64_t>();
    int64_t current = analysis["current_members"].get<int64_t>();
    int64_t total_eval = current + departed;
    analysis["churn_rate"] = total_eval > 0
      ? std::round((departed * 10000.0) / total_eval) / 100.0 : 0.0;

    analysis["period_days"] = days;

    return analysis;
  }

private:
  DatabasePool& db_;
};

static std::unique_ptr<RoomAnalytics> g_room_analytics;
static std::mutex g_analytics_mutex;

static void ensure_analytics_initialized(DatabasePool& db) {
  if (!g_room_analytics) {
    g_room_analytics = std::make_unique<RoomAnalytics>(db);
  }
}

json handle_room_growth_analysis(DatabasePool& db, const std::string& room_id,
                                   int days) {
  ensure_analytics_initialized(db);
  return g_room_analytics->room_growth_analysis(room_id, days);
}

json handle_room_activity_correlation(DatabasePool& db,
                                        const std::string& room_id, int limit) {
  ensure_analytics_initialized(db);
  return g_room_analytics->room_activity_correlation(room_id, limit);
}

json handle_message_type_distribution(DatabasePool& db,
                                        const std::string& room_id) {
  ensure_analytics_initialized(db);
  return g_room_analytics->message_type_distribution(room_id);
}

json handle_content_length_stats(DatabasePool& db,
                                   const std::string& room_id) {
  ensure_analytics_initialized(db);
  return g_room_analytics->content_length_stats(room_id);
}

json handle_active_hours_analysis(DatabasePool& db,
                                    const std::string& room_id, int days) {
  ensure_analytics_initialized(db);
  return g_room_analytics->active_hours_analysis(room_id, days);
}

json handle_user_churn_analysis(DatabasePool& db,
                                  const std::string& room_id, int days) {
  ensure_analytics_initialized(db);
  return g_room_analytics->user_churn_analysis(room_id, days);
}

} // namespace progressive::handlers
