// timeline_pagination.cpp - Matrix Timeline Pagination Engine
// Implements: GET /rooms/{}/messages, GET /rooms/{}/context/{},
// event filtering, lazy loading, state at event, pagination tokens,
// deduplication, timeline gap detection, federation backfill,
// timeline caching, room initial sync, limited timeline flag,
// prev_batch tokens, topological ordering, gappy sync handling.
// Target: 3500+ lines
//
// Handlers:
//   1. handle_get_room_messages      - GET /rooms/{roomId}/messages
//   2. handle_get_event_context      - GET /rooms/{roomId}/context/{eventId}
//   3. handle_get_room_timeline      - GET /rooms/{roomId}/timeline (initial sync)
//   4. handle_backfill_timeline      - POST /rooms/{roomId}/backfill (federation)
//   5. handle_resolve_room_state     - GET /rooms/{roomId}/state_at/{eventId}
//   6. handle_get_timeline_batch     - Bulk event resolution
//   7. handle_stream_paginate        - Stream-based pagination
//   8. get_timeline_for_sync         - Sync timeline generation
//   9. handle_detect_timeline_gaps   - Gap detection
//  10. handle_get_prev_batch_token   - Prev batch token generation

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
#include "progressive/storage/databases/main/small_stores.hpp"
#include "progressive/storage/databases/main/filtering.hpp"

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
#include <optional>
#include <tuple>
#include <memory>

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;

// ============================================================================
// Global utilities (shared across timeline/pagination handlers)
// ============================================================================

static std::atomic<int64_t> g_timeline_seq{1};
static std::mutex g_timeline_cache_mutex;
static std::mutex g_gap_detect_mutex;
static std::mutex g_backfill_mutex;
static std::mutex g_pagination_mutex;
static std::mutex g_prev_batch_mutex;
static std::mutex g_sync_timeline_mutex;
static std::mutex g_dedup_mutex;
static std::mutex g_member_lazy_load_mutex;

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_id(const std::string& prefix) {
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(g_timeline_seq.fetch_add(1));
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

static bool user_has_access_to_room(DatabasePool& db, const std::string& room_id,
                                     const std::string& user_id) {
  auto m = get_membership(db, room_id, user_id);
  return m == "join" || m == "invite" || m == "knock";
}

static bool can_view_history(DatabasePool& db, const std::string& room_id,
                              const std::string& user_id) {
  // Check history visibility rules
  auto m = get_membership(db, room_id, user_id);
  if (m == "join") return true;

  StateStore state(db);
  auto hv_event = state.get_current_state_event(room_id, "m.room.history_visibility", "");
  if (!hv_event) return (m == "join");

  EventsStore evs(db);
  auto ev = evs.get_event(*hv_event);
  if (!ev) return (m == "join");

  std::string history_vis = (*ev)["content"].value("history_visibility", "shared");

  if (history_vis == "world_readable") return true;
  if (history_vis == "shared" && m == "join") return true;
  if (history_vis == "invited" && (m == "join" || m == "invite")) return true;
  if (history_vis == "joined" && m == "join") return true;

  return false;
}

// ============================================================================
// Pagination Token Structures
// ============================================================================

struct PaginationToken {
  int64_t stream_ordering;
  int64_t topological_ordering;
  std::string direction; // "b" or "f"
  std::string instance_name;

  PaginationToken() : stream_ordering(0), topological_ordering(0),
                      direction("b"), instance_name("master") {}

  bool is_valid() const { return stream_ordering >= 0; }
  bool is_end() const { return stream_ordering == INT64_MAX; }
  bool is_start() const { return stream_ordering == 0; }

  std::string encode() const {
    // Format: "s{stream}_t{topo}_d{dir}_i{instance}"
    std::string s = "s" + std::to_string(stream_ordering) +
                    "_t" + std::to_string(topological_ordering) +
                    "_d" + direction +
                    "_i" + instance_name;
    return s;
  }

  static PaginationToken decode(const std::string& token) {
    PaginationToken pt;
    if (token.empty()) return pt;

    if (token == "end") {
      pt.stream_ordering = INT64_MAX;
      pt.direction = "b";
      return pt;
    }
    if (token == "start" || token == "begin") {
      pt.stream_ordering = 0;
      pt.direction = "f";
      return pt;
    }

    size_t s_pos = token.find('s');
    size_t t_pos = token.find('_t');
    size_t d_pos = token.find('_d');
    size_t i_pos = token.find('_i');

    if (s_pos != std::string::npos && t_pos != std::string::npos) {
      std::string s_str = token.substr(s_pos + 1, t_pos - s_pos - 1);
      try { pt.stream_ordering = std::stoll(s_str); } catch (...) { pt.stream_ordering = 0; }
    }

    if (t_pos != std::string::npos) {
      size_t t_end = d_pos != std::string::npos ? d_pos : (i_pos != std::string::npos ? i_pos : token.size());
      std::string t_str = token.substr(t_pos + 2, t_end - t_pos - 2);
      try { pt.topological_ordering = std::stoll(t_str); } catch (...) { pt.topological_ordering = 0; }
    }

    if (d_pos != std::string::npos) {
      size_t d_end = i_pos != std::string::npos ? i_pos : token.size();
      if (d_pos + 2 < d_end) {
        pt.direction = token.substr(d_pos + 2, 1);
      }
    }

    if (i_pos != std::string::npos && i_pos + 2 < token.size()) {
      pt.instance_name = token.substr(i_pos + 2);
    }

    return pt;
  }
};

// ============================================================================
// Timeline Filter Configuration
// ============================================================================

struct TimelineFilter {
  std::vector<std::string> types;
  std::vector<std::string> not_types;
  std::vector<std::string> senders;
  std::vector<std::string> not_senders;
  std::vector<std::string> rooms;
  std::vector<std::string> not_rooms;
  std::optional<bool> contains_url;
  bool lazy_load_members = false;
  bool include_redundant_members = false;
  bool not_rooms_filter = false;
  int64_t limit = 10;
  std::string direction = "b";

  TimelineFilter() = default;

  static TimelineFilter from_json(const json& filter_json) {
    TimelineFilter filter;

    if (filter_json.contains("types") && filter_json["types"].is_array()) {
      for (auto& t : filter_json["types"]) {
        if (t.is_string()) filter.types.push_back(t.get<std::string>());
      }
    }

    if (filter_json.contains("not_types") && filter_json["not_types"].is_array()) {
      for (auto& t : filter_json["not_types"]) {
        if (t.is_string()) filter.not_types.push_back(t.get<std::string>());
      }
    }

    if (filter_json.contains("senders") && filter_json["senders"].is_array()) {
      for (auto& s : filter_json["senders"]) {
        if (s.is_string()) filter.senders.push_back(s.get<std::string>());
      }
    }

    if (filter_json.contains("not_senders") && filter_json["not_senders"].is_array()) {
      for (auto& s : filter_json["not_senders"]) {
        if (s.is_string()) filter.not_senders.push_back(s.get<std::string>());
      }
    }

    if (filter_json.contains("rooms") && filter_json["rooms"].is_array()) {
      for (auto& r : filter_json["rooms"]) {
        if (r.is_string()) filter.rooms.push_back(r.get<std::string>());
      }
    }

    if (filter_json.contains("not_rooms") && filter_json["not_rooms"].is_array()) {
      for (auto& r : filter_json["not_rooms"]) {
        if (r.is_string()) filter.not_rooms.push_back(r.get<std::string>());
      }
    }

    if (filter_json.contains("contains_url") && filter_json["contains_url"].is_boolean()) {
      filter.contains_url = filter_json["contains_url"].get<bool>();
    }

    filter.lazy_load_members = safe_bool(filter_json, "lazy_load_members", false);
    filter.include_redundant_members = safe_bool(filter_json, "include_redundant_members", false);
    filter.limit = safe_int(filter_json, "limit", 10);

    return filter;
  }

  std::string to_sql_clause() const {
    std::string clause;

    if (!types.empty()) {
      std::string types_list;
      for (auto& t : types) {
        if (!types_list.empty()) types_list += ",";
        types_list += "'" + t + "'";
      }
      clause += " AND type IN (" + types_list + ")";
    }

    if (!not_types.empty()) {
      std::string not_types_list;
      for (auto& t : not_types) {
        if (!not_types_list.empty()) not_types_list += ",";
        not_types_list += "'" + t + "'";
      }
      clause += " AND type NOT IN (" + not_types_list + ")";
    }

    if (!senders.empty()) {
      std::string senders_list;
      for (auto& s : senders) {
        if (!senders_list.empty()) senders_list += ",";
        senders_list += "'" + s + "'";
      }
      clause += " AND sender IN (" + senders_list + ")";
    }

    if (!not_senders.empty()) {
      std::string not_senders_list;
      for (auto& s : not_senders) {
        if (!not_senders_list.empty()) not_senders_list += ",";
        not_senders_list += "'" + s + "'";
      }
      clause += " AND sender NOT IN (" + not_senders_list + ")";
    }

    if (contains_url.has_value() && contains_url.value()) {
      clause += " AND contains_url = 1";
    }

    return clause;
  }
};

// ============================================================================
// Timeline Gap Detection Structures
// ============================================================================

struct TimelineGap {
  std::string room_id;
  int64_t start_stream_ordering;  // inclusive
  int64_t end_stream_ordering;    // exclusive
  int64_t start_topological;
  int64_t end_topological;
  std::string gap_type;  // "forward", "backward", "sync"
  int64_t gap_size_estimate;
  bool is_limited;
  int64_t detected_at;

  PaginationToken prev_batch_token;
  PaginationToken next_batch_token;

  TimelineGap() : start_stream_ordering(0), end_stream_ordering(0),
                  start_topological(0), end_topological(0),
                  gap_type("backward"), gap_size_estimate(0),
                  is_limited(true), detected_at(0) {}

  json to_json() const {
    json j;
    j["room_id"] = room_id;
    j["start_stream"] = start_stream_ordering;
    j["end_stream"] = end_stream_ordering;
    j["start_topo"] = start_topological;
    j["end_topo"] = end_topological;
    j["gap_type"] = gap_type;
    j["gap_size"] = gap_size_estimate;
    j["is_limited"] = is_limited;
    j["detected_at"] = detected_at;
    j["prev_batch"] = prev_batch_token.encode();
    j["next_batch"] = next_batch_token.encode();
    return j;
  }
};

// ============================================================================
// Timeline Cache Entry
// ============================================================================

struct TimelineCacheEntry {
  std::string room_id;
  std::string key;  // cache key: token + direction + limit
  std::vector<json> events;
  PaginationToken start_token;
  PaginationToken end_token;
  bool limited;
  int64_t cached_at;
  int64_t ttl_ms;

  TimelineCacheEntry() : limited(false), cached_at(0), ttl_ms(30000) {}

  bool is_expired() const {
    return (now_ms() - cached_at) > ttl_ms;
  }
};

// ============================================================================
// Timeline Cache Manager
// ============================================================================

class TimelineCache {
public:
  TimelineCache(size_t max_size = 512) : max_entries_(max_size) {}

  std::optional<TimelineCacheEntry> get(const std::string& key) {
    std::lock_guard<std::mutex> lock(g_timeline_cache_mutex);
    auto it = cache_.find(key);
    if (it != cache_.end() && !it->second.is_expired()) {
      // Move to front (LRU)
      touch_lru(key);
      return it->second;
    }
    return std::nullopt;
  }

  void put(const std::string& key, const TimelineCacheEntry& entry) {
    std::lock_guard<std::mutex> lock(g_timeline_cache_mutex);
    if (cache_.size() >= max_entries_) {
      evict_lru();
    }
    cache_[key] = entry;
    lru_order_.push_back(key);
  }

  void invalidate_room(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(g_timeline_cache_mutex);
    auto it = cache_.begin();
    while (it != cache_.end()) {
      if (it->second.room_id == room_id) {
        auto lru_it = std::find(lru_order_.begin(), lru_order_.end(), it->first);
        if (lru_it != lru_order_.end()) lru_order_.erase(lru_it);
        it = cache_.erase(it);
      } else {
        ++it;
      }
    }
  }

  void clear() {
    std::lock_guard<std::mutex> lock(g_timeline_cache_mutex);
    cache_.clear();
    lru_order_.clear();
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(g_timeline_cache_mutex);
    return cache_.size();
  }

private:
  void touch_lru(const std::string& key) {
    auto it = std::find(lru_order_.begin(), lru_order_.end(), key);
    if (it != lru_order_.end()) {
      lru_order_.erase(it);
    }
    lru_order_.push_back(key);
  }

  void evict_lru() {
    if (!lru_order_.empty()) {
      std::string oldest = lru_order_.front();
      lru_order_.pop_front();
      cache_.erase(oldest);
    }
  }

  size_t max_entries_;
  std::unordered_map<std::string, TimelineCacheEntry> cache_;
  std::deque<std::string> lru_order_;
};

// Global timeline cache
static TimelineCache g_timeline_cache(1024);

// ============================================================================
// Timeline Gap Detector
// ============================================================================

class TimelineGapDetector {
public:
  TimelineGapDetector() = default;

  // Detect gaps between two batches of events
  static std::optional<TimelineGap> detect_gap(
      DatabasePool& db,
      const std::string& room_id,
      const std::vector<json>& chunk,
      const PaginationToken& from_token,
      const PaginationToken& end_token,
      const std::string& direction) {

    if (chunk.empty()) return std::nullopt;

    // Get the stream ordering of the first and last events in the chunk
    int64_t first_stream = INT64_MAX;
    int64_t last_stream = 0;
    int64_t first_topo = 0;
    int64_t last_topo = 0;

    for (auto& ev : chunk) {
      int64_t s = ev.value("stream_ordering", 0);
      int64_t t = ev.value("depth", 0);
      if (s < first_stream) {
        first_stream = s;
        first_topo = t;
      }
      if (s > last_stream) {
        last_stream = s;
        last_topo = t;
      }
    }

    // Check if there's a gap: count events between from_token and first/last event
    TimelineGap gap;
    gap.room_id = room_id;
    gap.detected_at = now_ms();

    if (direction == "b") {
      // Backward: check between last_stream and from_token
      gap.gap_type = "backward";
      gap.start_stream_ordering = last_stream;
      gap.end_stream_ordering = from_token.stream_ordering;
      gap.start_topological = last_topo;
      gap.end_topological = from_token.topological_ordering;

      // Count events that would be in the gap
      auto gap_rows = db.execute("gap_detect_backward",
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + room_id + "' "
        "AND stream_ordering > " + std::to_string(last_stream) +
        " AND stream_ordering < " + std::to_string(from_token.stream_ordering) +
        " AND outlier = 0");

      if (!gap_rows.empty() && gap_rows[0]["cnt"].value) {
        gap.gap_size_estimate = std::stoll(*gap_rows[0]["cnt"].value);
      }

      if (gap.gap_size_estimate > 0) {
        gap.is_limited = true;
        gap.prev_batch_token = end_token;
        gap.next_batch_token = PaginationToken();
        gap.next_batch_token.stream_ordering = last_stream;
        gap.next_batch_token.topological_ordering = last_topo;
        gap.next_batch_token.direction = "b";

        // Store gap info
        store_gap(db, gap);
        return gap;
      }
    } else {
      // Forward: check between end_token and next possible event
      gap.gap_type = "forward";
      gap.start_stream_ordering = end_token.stream_ordering;
      gap.end_stream_ordering = first_stream;
      gap.start_topological = end_token.topological_ordering;
      gap.end_topological = first_topo;

      auto gap_rows = db.execute("gap_detect_forward",
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + room_id + "' "
        "AND stream_ordering > " + std::to_string(end_token.stream_ordering) +
        " AND stream_ordering < " + std::to_string(first_stream) +
        " AND outlier = 0");

      if (!gap_rows.empty() && gap_rows[0]["cnt"].value) {
        gap.gap_size_estimate = std::stoll(*gap_rows[0]["cnt"].value);
      }

      if (gap.gap_size_estimate > 0) {
        gap.is_limited = true;
        gap.prev_batch_token = end_token;
        gap.next_batch_token = PaginationToken();
        gap.next_batch_token.stream_ordering = first_stream;
        gap.next_batch_token.topological_ordering = first_topo;
        gap.next_batch_token.direction = "f";

        store_gap(db, gap);
        return gap;
      }
    }

    return std::nullopt;
  }

  // Detect gaps from sync token
  static std::optional<TimelineGap> detect_sync_gap(
      DatabasePool& db,
      const std::string& room_id,
      int64_t sync_token,
      int64_t current_stream) {

    TimelineGap gap;
    gap.room_id = room_id;
    gap.gap_type = "sync";
    gap.start_stream_ordering = sync_token;
    gap.end_stream_ordering = current_stream;
    gap.detected_at = now_ms();

    auto gap_rows = db.execute("sync_gap_detect",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE room_id='" + room_id + "' "
      "AND stream_ordering > " + std::to_string(sync_token) +
      " AND stream_ordering <= " + std::to_string(current_stream) +
      " AND outlier = 0");

    if (!gap_rows.empty() && gap_rows[0]["cnt"].value) {
      gap.gap_size_estimate = std::stoll(*gap_rows[0]["cnt"].value);
    }

    // If gap exceeds threshold, it's a sync gap
    static const int64_t SYNC_GAP_THRESHOLD = 100;
    if (gap.gap_size_estimate > SYNC_GAP_THRESHOLD) {
      gap.is_limited = true;
      return gap;
    }

    return std::nullopt;
  }

  // Check if event is next to a backward extremity
  static bool is_next_to_backward_gap(DatabasePool& db, const std::string& room_id,
                                       int64_t stream_ordering) {
    auto rows = db.execute("check_backward_gap",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE room_id='" + room_id + "' "
      "AND stream_ordering = " + std::to_string(stream_ordering - 1) +
      " AND outlier = 0");
    if (rows.empty() || !rows[0]["cnt"].value) return true;
    return std::stoll(*rows[0]["cnt"].value) == 0;
  }

  // Check if event is next to a forward extremity
  static bool is_next_to_forward_gap(DatabasePool& db, const std::string& room_id,
                                      int64_t stream_ordering) {
    auto rows = db.execute("check_forward_gap",
      "SELECT COUNT(*) as cnt FROM events "
      "WHERE room_id='" + room_id + "' "
      "AND stream_ordering = " + std::to_string(stream_ordering + 1) +
      " AND outlier = 0");
    if (rows.empty() || !rows[0]["cnt"].value) return true;
    return std::stoll(*rows[0]["cnt"].value) == 0;
  }

  // Get all gaps for a room
  static std::vector<TimelineGap> get_gaps(DatabasePool& db, const std::string& room_id) {
    std::vector<TimelineGap> gaps;
    auto rows = db.execute("get_timeline_gaps",
      "SELECT * FROM timeline_gaps WHERE room_id='" + room_id +
      "' ORDER BY detected_at DESC LIMIT 50");

    for (auto& row : rows) {
      TimelineGap gap;
      gap.room_id = room_id;
      gap.start_stream_ordering = row["start_stream"].value ?
        std::stoll(*row["start_stream"].value) : 0;
      gap.end_stream_ordering = row["end_stream"].value ?
        std::stoll(*row["end_stream"].value) : 0;
      gap.start_topological = row["start_topo"].value ?
        std::stoll(*row["start_topo"].value) : 0;
      gap.end_topological = row["end_topo"].value ?
        std::stoll(*row["end_topo"].value) : 0;
      gap.gap_type = row["gap_type"].value.value_or("backward");
      gap.gap_size_estimate = row["gap_size"].value ?
        std::stoll(*row["gap_size"].value) : 0;
      gap.is_limited = row["is_limited"].value &&
                       *row["is_limited"].value == "1";
      gap.detected_at = row["detected_at"].value ?
        std::stoll(*row["detected_at"].value) : 0;
      gaps.push_back(gap);
    }

    return gaps;
  }

private:
  static void store_gap(DatabasePool& db, const TimelineGap& gap) {
    // Store gap in database for tracking
    try {
      auto txn = db.cursor("store_timeline_gap");
      if (txn) {
        std::string sql = "INSERT OR REPLACE INTO timeline_gaps "
          "(room_id, start_stream, end_stream, start_topo, end_topo, "
          "gap_type, gap_size, is_limited, detected_at) "
          "VALUES (?,?,?,?,?,?,?,?,?)";
        txn->execute(sql, {
          gap.room_id,
          std::to_string(gap.start_stream_ordering),
          std::to_string(gap.end_stream_ordering),
          std::to_string(gap.start_topological),
          std::to_string(gap.end_topological),
          gap.gap_type,
          std::to_string(gap.gap_size_estimate),
          gap.is_limited ? "1" : "0",
          std::to_string(gap.detected_at)
        });
        txn->commit();
      }
    } catch (...) {
      // Non-critical: silently ignore storage failures for gap tracking
    }
  }
};

// ============================================================================
// Federation Backfill Engine
// ============================================================================

class FederationBackfillEngine {
public:
  struct BackfillRequest {
    std::string room_id;
    std::vector<std::string> event_ids;  // extremity events to backfill from
    int64_t limit;
    std::string target_server;
    int attempt;
  };

  struct BackfillResult {
    std::vector<json> events;
    std::string prev_batch;
    std::string next_batch;
    bool limited;
    bool success;
    std::string error;
  };

  // Request backfill from federation for events before a given point
  static BackfillResult backfill(
      DatabasePool& db,
      const std::string& room_id,
      const std::vector<std::string>& extremity_ids,
      int64_t limit,
      const std::string& target_server = "") {

    BackfillResult result;
    result.limited = true;
    result.success = false;

    // ---- 1. Get backward extremities if not provided ----
    std::vector<std::string> ext_ids = extremity_ids;
    if (ext_ids.empty()) {
      EventFederationWorkerStore fed_worker(db);
      ext_ids = fed_worker.get_backward_extremeties(room_id);
    }

    if (ext_ids.empty()) {
      result.error = "No backward extremities to backfill from";
      return result;
    }

    // ---- 2. Determine target server(s) ----
    std::vector<std::string> target_servers;
    if (!target_server.empty()) {
      target_servers.push_back(target_server);
    } else {
      // Find servers that have events in this room
      auto servers = get_room_participating_servers(db, room_id);
      target_servers = servers;
    }

    if (target_servers.empty()) {
      result.error = "No target servers available for backfill";
      return result;
    }

    // ---- 3. Build backfill request ----
    json backfill_body;
    backfill_body["limit"] = limit;
    backfill_body["v"] = get_room_version(db, room_id);

    json ext_ids_json = json::array();
    for (auto& eid : ext_ids) {
      ext_ids_json.push_back(eid);
    }
    backfill_body["event_ids"] = ext_ids_json;

    // ---- 4. Attempt federation backfill from each server ----
    for (auto& server : target_servers) {
      // Simulate federation backfill (in production, would make HTTP request)
      json backfill_response = simulate_federation_backfill(db, room_id, server, backfill_body);

      if (backfill_response.contains("pdus") && backfill_response["pdus"].is_array()) {
        // ---- 5. Process and persist backfilled events ----
        std::vector<json> pdus = backfill_response["pdus"];
        std::vector<json> sorted_pdus;

        for (auto& pdu : pdus) {
          // Validate each PDU
          if (!validate_backfill_pdu(db, room_id, pdu)) continue;
          sorted_pdus.push_back(pdu);
        }

        // Sort by topological ordering (depth) for proper insertion
        std::sort(sorted_pdus.begin(), sorted_pdus.end(),
          [](const json& a, const json& b) {
            return a.value("depth", 0) < b.value("depth", 0);
          });

        // Persist backfilled events
        for (auto& pdu : sorted_pdus) {
          persist_backfilled_event(db, room_id, pdu);
        }

        result.events = sorted_pdus;
        result.success = true;
        result.limited = backfill_response.value("limited", true);

        // Generate pagination tokens
        if (!sorted_pdus.empty()) {
          int64_t min_stream = sorted_pdus[0].value("stream_ordering", 0);
          int64_t max_stream = sorted_pdus.back().value("stream_ordering", 0);
          int64_t min_topo = sorted_pdus[0].value("depth", 0);
          int64_t max_topo = sorted_pdus.back().value("depth", 0);

          PaginationToken prev;
          prev.stream_ordering = min_stream;
          prev.topological_ordering = min_topo;
          prev.direction = "b";

          PaginationToken next;
          next.stream_ordering = max_stream;
          next.topological_ordering = max_topo;
          next.direction = "b";

          result.prev_batch = prev.encode();
          result.next_batch = next.encode();
        }

        break;  // Success, don't try other servers
      }
    }

    return result;
  }

  // Check if room needs backfill
  static bool needs_backfill(DatabasePool& db, const std::string& room_id) {
    EventFederationWorkerStore fed(db);
    auto extremities = fed.get_backward_extremeties(room_id);

    // Room needs backfill if there are backward extremities
    if (extremities.size() > 1) return true;

    // Or if room has limited timeline
    auto rows = db.execute("check_limited",
      "SELECT is_limited FROM room_timeline_status WHERE room_id='" + room_id + "'");
    if (!rows.empty() && rows[0]["is_limited"].value &&
        *rows[0]["is_limited"].value == "1") {
      return true;
    }

    return false;
  }

  // Mark room as needing backfill
  static void mark_for_backfill(DatabasePool& db, const std::string& room_id) {
    int64_t now = now_ms();
    db.execute("mark_backfill",
      "INSERT OR REPLACE INTO room_timeline_status "
      "(room_id, is_limited, limited_ts, needs_backfill) "
      "VALUES ('" + room_id + "', 1, " + std::to_string(now) + ", 1)");
  }

private:
  static std::string get_room_version(DatabasePool& db, const std::string& room_id) {
    StateStore state(db);
    return state.get_room_version_from_state(room_id);
  }

  static bool validate_backfill_pdu(DatabasePool& db, const std::string& room_id,
                                     const json& pdu) {
    // Validate PDU has required fields
    if (!pdu.contains("event_id") || !pdu.contains("type") ||
        !pdu.contains("sender") || !pdu.contains("room_id")) {
      return false;
    }

    // Validate room_id matches
    if (pdu["room_id"].get<std::string>() != room_id) {
      return false;
    }

    // Check for duplicate events
    auto existing = db.execute("backfill_dup_check",
      "SELECT event_id FROM events WHERE event_id='" +
      pdu["event_id"].get<std::string>() + "'");
    if (!existing.empty()) return false;

    return true;
  }

  static void persist_backfilled_event(DatabasePool& db, const std::string& room_id,
                                        const json& pdu) {
    auto txn = db.cursor("persist_backfilled");
    if (!txn) return;

    std::string event_id = pdu["event_id"].get<std::string>();
    std::string sender = pdu["sender"].get<std::string>();
    std::string type = pdu["type"].get<std::string>();
    std::string state_key = pdu.value("state_key", "");
    int64_t depth = pdu.value("depth", 0);
    int64_t origin_ts = pdu.value("origin_server_ts", now_ms());
    int64_t stream_ord = now_ms();  // Assign new stream ordering

    // Mark as outlier=0 (not outlier) since it's now part of our DAG
    std::string sql = "INSERT OR IGNORE INTO events "
      "(event_id, room_id, sender, type, state_key, json, "
      "stream_ordering, origin_server_ts, depth, outlier, instance_name) "
      "VALUES (?,?,?,?,?,?,?,?,?,0,'master')";
    txn->execute(sql, {
      event_id, room_id, sender, type, state_key,
      pdu.dump(), std::to_string(stream_ord),
      std::to_string(origin_ts), std::to_string(depth)
    });

    // Update stream ordering
    txn->execute("UPDATE stream_ordering SET stream_id = ?",
      {std::to_string(stream_ord)});

    txn->commit();
  }

  static json simulate_federation_backfill(DatabasePool& db,
      const std::string& room_id, const std::string& server,
      const json& request) {
    // In production, this would make an actual HTTP request to the federation endpoint
    // GET /_matrix/federation/v1/backfill/{roomId}
    // For now, we return a simulated response (empty PDUs for safety)
    json response;
    response["origin"] = server;
    response["origin_server_ts"] = now_ms();
    response["pdus"] = json::array();
    response["limited"] = false;
    return response;
  }

  static std::vector<std::string> get_room_participating_servers(
      DatabasePool& db, const std::string& room_id) {
    std::vector<std::string> servers;
    RoomMemberStore members(db);
    auto joined = members.get_joined_members(room_id);
    std::set<std::string> seen;
    for (auto& m : joined) {
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
};

// ============================================================================
// Lazy Loading Member Resolution
// ============================================================================

class LazyMemberLoader {
public:
  // Resolve members for lazy loading in timeline
  static json resolve_lazy_loaded_members(
      DatabasePool& db,
      const std::string& room_id,
      const std::vector<json>& events,
      bool include_redundant = false) {

    json state_events = json::array();
    std::unordered_set<std::string> resolved_state_keys;

    // Collect all state_keys referenced in the timeline
    std::set<std::string> referenced_users;

    for (auto& ev : events) {
      std::string sender = ev.value("sender", "");
      if (!sender.empty() && sender[0] == '@') {
        referenced_users.insert(sender);
      }

      if (ev.contains("state_key") && ev["state_key"].is_string()) {
        std::string sk = ev["state_key"].get<std::string>();
        if (sk.size() > 0 && sk[0] == '@') {
          referenced_users.insert(sk);
        }
      }
    }

    // Get member events for referenced users
    StateStore state(db);
    auto current_state = state.get_current_state(room_id);
    EventsStore evs(db);

    for (auto& [key, eid] : current_state) {
      if (key.first != "m.room.member") continue;
      std::string state_key = key.second;

      if (!include_redundant &&
          referenced_users.find(state_key) == referenced_users.end()) {
        continue;  // Skip non-referenced members for lazy loading
      }

      auto ev = evs.get_event(eid);
      if (!ev) continue;

      json stripped;
      stripped["type"] = "m.room.member";
      stripped["state_key"] = state_key;
      stripped["sender"] = (*ev).value("sender", "");
      stripped["event_id"] = eid;
      stripped["origin_server_ts"] = (*ev).value("origin_server_ts", 0);

      // Strip to just membership and displayname for lazy loading
      json content;
      content["membership"] = (*ev)["content"].value("membership", "leave");
      content["displayname"] = (*ev)["content"].value("displayname", "");
      if (include_redundant) {
        content["avatar_url"] = (*ev)["content"].value("avatar_url", "");
      }
      stripped["content"] = content;

      stripped["unsigned"] = json::object();

      state_events.push_back(stripped);
      resolved_state_keys.insert(state_key);
    }

    return state_events;
  }

  // Generate lazy-loaded member summaries for sync
  static json generate_member_summaries(
      DatabasePool& db,
      const std::string& room_id,
      const std::vector<std::string>& hero_user_ids = {}) {

    json summaries = json::object();

    RoomMemberStore members(db);
    auto joined = members.get_joined_members(room_id);

    for (auto& m : joined) {
      if (!hero_user_ids.empty() &&
          std::find(hero_user_ids.begin(), hero_user_ids.end(), m.user_id) ==
          hero_user_ids.end()) {
        continue;  // Only include heroes unless empty list
      }

      json member_json;
      member_json["membership"] = m.membership;
      if (m.display_name) member_json["displayname"] = *m.display_name;
      if (m.avatar_url) member_json["avatar_url"] = *m.avatar_url;

      summaries[m.user_id] = member_json;
    }

    return summaries;
  }
};

// ============================================================================
// Event Deduplication
// ============================================================================

class EventDeduplicator {
public:
  // Deduplicate a list of events by event_id
  static std::vector<json> deduplicate(const std::vector<json>& events) {
    std::vector<json> result;
    std::unordered_set<std::string> seen;

    for (auto& ev : events) {
      std::string event_id = ev.value("event_id", "");
      if (event_id.empty()) {
        // Generate synthetic ID for dedup
        event_id = ev.value("type", "") + ":" +
                   ev.value("sender", "") + ":" +
                   std::to_string(ev.value("origin_server_ts", 0));
      }

      if (seen.insert(event_id).second) {
        result.push_back(ev);
      }
    }

    return result;
  }

  // Merge two event lists, deduplicating and sorting
  static std::vector<json> merge_and_deduplicate(
      const std::vector<json>& list_a,
      const std::vector<json>& list_b,
      bool sort_by_stream = true) {

    std::unordered_map<std::string, json> merged;
    std::vector<json> result;

    for (auto& ev : list_a) {
      std::string eid = ev.value("event_id", "");
      if (!eid.empty()) merged[eid] = ev;
    }

    for (auto& ev : list_b) {
      std::string eid = ev.value("event_id", "");
      if (!eid.empty() && merged.find(eid) == merged.end()) {
        merged[eid] = ev;
      }
    }

    for (auto& [eid, ev] : merged) {
      result.push_back(ev);
    }

    if (sort_by_stream) {
      std::sort(result.begin(), result.end(),
        [](const json& a, const json& b) {
          return a.value("stream_ordering", 0) > b.value("stream_ordering", 0);
        });
    }

    return result;
  }

  // Remove events that have been superseded (state events with same type/state_key)
  static std::vector<json> deduplicate_state_events(const std::vector<json>& events) {
    std::vector<json> result;
    std::map<std::pair<std::string, std::string>, std::pair<int64_t, json>> latest_state;

    for (auto& ev : events) {
      if (!ev.contains("state_key")) {
        result.push_back(ev);
        continue;
      }

      std::string type = ev.value("type", "");
      std::string state_key = ev["state_key"].get<std::string>();
      int64_t stream = ev.value("stream_ordering", 0);

      auto key = std::make_pair(type, state_key);
      auto it = latest_state.find(key);
      if (it == latest_state.end() || stream > it->second.first) {
        latest_state[key] = {stream, ev};
      }
    }

    for (auto& [key, pair] : latest_state) {
      result.push_back(pair.second);
    }

    return result;
  }
};

// ============================================================================
// Topological Ordering
// ============================================================================

class TopologicalOrderer {
public:
  // Sort events by topological ordering (depth first, then stream)
  static void sort_topologically(std::vector<json>& events) {
    std::sort(events.begin(), events.end(),
      [](const json& a, const json& b) {
        int64_t a_depth = a.value("depth", 0);
        int64_t b_depth = b.value("depth", 0);
        if (a_depth != b_depth) return a_depth > b_depth;

        int64_t a_stream = a.value("stream_ordering", 0);
        int64_t b_stream = b.value("stream_ordering", 0);
        if (a_stream != b_stream) return a_stream > b_stream;

        return a.value("origin_server_ts", 0) > b.value("origin_server_ts", 0);
      });
  }

  // Sort events by topological ordering ascending
  static void sort_topologically_asc(std::vector<json>& events) {
    std::sort(events.begin(), events.end(),
      [](const json& a, const json& b) {
        int64_t a_depth = a.value("depth", 0);
        int64_t b_depth = b.value("depth", 0);
        if (a_depth != b_depth) return a_depth < b_depth;

        int64_t a_stream = a.value("stream_ordering", 0);
        int64_t b_stream = b.value("stream_ordering", 0);
        return a_stream < b_stream;
      });
  }

  // Check if events are in topological order
  static bool is_topologically_ordered(const std::vector<json>& events) {
    for (size_t i = 1; i < events.size(); i++) {
      int64_t prev_depth = events[i-1].value("depth", 0);
      int64_t curr_depth = events[i].value("depth", 0);

      if (prev_depth < curr_depth) return false;

      if (prev_depth == curr_depth) {
        int64_t prev_stream = events[i-1].value("stream_ordering", 0);
        int64_t curr_stream = events[i].value("stream_ordering", 0);
        if (prev_stream < curr_stream) return false;
      }
    }
    return true;
  }

  // Build a topological order map from event references
  static std::map<std::string, int> compute_topological_ranks(
      const std::vector<json>& events) {

    std::map<std::string, std::vector<std::string>> dag;
    std::map<std::string, int> indegree;
    std::map<std::string, int> ranks;

    // Build graph from prev_events references
    for (auto& ev : events) {
      std::string eid = ev.value("event_id", "");
      if (eid.empty()) continue;

      if (indegree.find(eid) == indegree.end()) {
        indegree[eid] = 0;
      }

      if (ev.contains("prev_events") && ev["prev_events"].is_array()) {
        for (auto& prev : ev["prev_events"]) {
          std::string prev_id = prev.is_string() ? prev.get<std::string>() :
                                (prev.is_array() && !prev.empty() && prev[0].is_string() ?
                                 prev[0].get<std::string>() : "");
          if (!prev_id.empty()) {
            dag[prev_id].push_back(eid);
            indegree[eid]++;
          }
        }
      }
    }

    // Kahn's algorithm for topological sort
    std::deque<std::string> queue;
    for (auto& [eid, deg] : indegree) {
      if (deg == 0) queue.push_back(eid);
    }

    int rank = 0;
    while (!queue.empty()) {
      size_t level_size = queue.size();
      for (size_t i = 0; i < level_size; i++) {
        std::string node = queue.front();
        queue.pop_front();
        ranks[node] = rank;

        for (auto& next : dag[node]) {
          indegree[next]--;
          if (indegree[next] == 0) {
            queue.push_back(next);
          }
        }
      }
      rank++;
    }

    return ranks;
  }
};

// ============================================================================
// State at Event Resolution
// ============================================================================

class StateAtEventResolver {
public:
  // Resolve the state of the room at the point of a given event
  static json resolve_state_at_event(
      DatabasePool& db,
      const std::string& room_id,
      const std::string& event_id) {

    json result;
    result["events"] = json::array();

    // ---- 1. Get the target event's stream and topological ordering ----
    auto event_rows = db.execute("state_at_event_target",
      "SELECT stream_ordering, topological_ordering, depth, sender, type, "
      "state_key, json FROM events "
      "WHERE event_id='" + event_id + "' AND room_id='" + room_id + "'");

    if (event_rows.empty()) {
      result["error"] = "Event not found";
      return result;
    }

    int64_t target_stream = event_rows[0]["stream_ordering"].value ?
      std::stoll(*event_rows[0]["stream_ordering"].value) : 0;
    int64_t target_depth = event_rows[0]["depth"].value ?
      std::stoll(*event_rows[0]["depth"].value) : 0;

    result["event_id"] = event_id;
    result["stream_ordering"] = target_stream;
    result["depth"] = target_depth;

    // ---- 2. Get the state group for this event ----
    StateStore state(db);
    auto state_group = state.get_state_group_for_event(event_id);

    if (state_group) {
      // Fast path: resolve state from state group
      auto state_map = state.get_state_for_group(*state_group, room_id);

      EventsStore evs(db);
      for (auto& [key, eid] : state_map) {
        auto ev = evs.get_event(eid);
        if (!ev) continue;

        json state_ev;
        state_ev["type"] = key.first;
        state_ev["state_key"] = key.second;
        state_ev["content"] = (*ev).value("content", json::object());
        state_ev["event_id"] = eid;
        state_ev["sender"] = (*ev).value("sender", "");
        state_ev["origin_server_ts"] = (*ev).value("origin_server_ts", 0);
        state_ev["stream_ordering"] = (*ev).value("stream_ordering", 0);
        result["events"].push_back(state_ev);
      }
    } else {
      // Slow path: resolve state by walking back from the event
      resolve_state_by_walkback(db, room_id, event_id, target_stream, target_depth, result);
    }

    // ---- 3. Add metadata about the resolution ----
    result["state_group"] = state_group.value_or(-1);

    return result;
  }

  // Resolve state at a specific stream ordering position
  static json resolve_state_at_stream(
      DatabasePool& db,
      const std::string& room_id,
      int64_t stream_ordering) {

    json result;
    result["events"] = json::array();
    result["stream_ordering"] = stream_ordering;

    // Get all state events that were active at this stream position
    auto rows = db.execute("state_at_stream",
      "SELECT e.type, e.state_key, e.event_id, e.json FROM events e "
      "INNER JOIN current_state_events cs ON e.event_id = cs.event_id "
      "WHERE e.room_id='" + room_id + "' "
      "AND e.stream_ordering <= " + std::to_string(stream_ordering) +
      " AND e.state_key != '' "
      "ORDER BY e.stream_ordering DESC");

    std::map<std::pair<std::string, std::string>, json> resolved;
    for (auto& row : rows) {
      std::string type = row["type"].value.value_or("");
      std::string state_key = row["state_key"].value.value_or("");
      auto key = std::make_pair(type, state_key);

      if (resolved.find(key) != resolved.end()) continue;  // Already resolved

      std::string ev_str = row["json"].value.value_or("{}");
      json ev = json::parse(ev_str.empty() ? "{}" : ev_str);

      json state_ev;
      state_ev["type"] = type;
      state_ev["state_key"] = state_key;
      state_ev["content"] = ev.value("content", json::object());
      state_ev["event_id"] = row["event_id"].value.value_or("");
      state_ev["sender"] = ev.value("sender", "");
      state_ev["origin_server_ts"] = ev.value("origin_server_ts", 0);
      state_ev["stream_ordering"] = ev.value("stream_ordering", 0);

      resolved[key] = state_ev;
    }

    for (auto& [key, ev] : resolved) {
      result["events"].push_back(ev);
    }

    return result;
  }

private:
  static void resolve_state_by_walkback(
      DatabasePool& db,
      const std::string& room_id,
      const std::string& event_id,
      int64_t target_stream,
      int64_t target_depth,
      json& result) {

    // Walk back through prev_events to find state events
    std::set<std::string> visited;
    std::deque<std::string> queue;
    queue.push_back(event_id);

    std::map<std::pair<std::string, std::string>, std::string> resolved_state;
    int max_iterations = 100;  // Safety limit

    while (!queue.empty() && max_iterations-- > 0) {
      std::string current_id = queue.front();
      queue.pop_front();

      if (!visited.insert(current_id).second) continue;

      auto rows = db.execute("walkback_event",
        "SELECT json, stream_ordering, depth FROM events "
        "WHERE event_id='" + current_id + "' AND room_id='" + room_id + "'");

      if (rows.empty()) continue;

      std::string ev_str = rows[0]["json"].value.value_or("{}");
      json ev = json::parse(ev_str.empty() ? "{}" : ev_str);

      int64_t ev_stream = rows[0]["stream_ordering"].value ?
        std::stoll(*rows[0]["stream_ordering"].value) : 0;

      // If this is a state event before the target, record it
      if (ev.contains("state_key") && ev["state_key"].is_string() &&
          !ev["state_key"].get<std::string>().empty() &&
          ev_stream <= target_stream) {
        std::string type = ev["type"].get<std::string>();
        std::string state_key = ev["state_key"].get<std::string>();
        auto key = std::make_pair(type, state_key);

        if (resolved_state.find(key) == resolved_state.end()) {
          resolved_state[key] = current_id;
        }
      }

      // Add prev_events to queue
      if (ev.contains("prev_events") && ev["prev_events"].is_array()) {
        for (auto& prev : ev["prev_events"]) {
          std::string prev_id = prev.is_string() ? prev.get<std::string>() : "";
          if (!prev_id.empty() && visited.find(prev_id) == visited.end()) {
            queue.push_back(prev_id);
          }
        }
      }
    }

    // Convert resolved state to output format
    EventsStore evs(db);
    for (auto& [key, eid] : resolved_state) {
      auto ev = evs.get_event(eid);
      if (!ev) continue;

      json state_ev;
      state_ev["type"] = key.first;
      state_ev["state_key"] = key.second;
      state_ev["content"] = (*ev).value("content", json::object());
      state_ev["event_id"] = eid;
      state_ev["sender"] = (*ev).value("sender", "");
      state_ev["origin_server_ts"] = (*ev).value("origin_server_ts", 0);
      state_ev["stream_ordering"] = (*ev).value("stream_ordering", 0);
      result["events"].push_back(state_ev);
    }
  }
};

// ============================================================================
// Room Initial Sync Timeline Builder
// ============================================================================

class InitialSyncTimelineBuilder {
public:
  struct InitialSyncResult {
    std::vector<json> timeline_events;
    std::vector<json> state_events;
    std::string prev_batch;
    bool limited;
    int64_t num_joined_members;
    json room_account_data;
  };

  // Build the initial timeline for a room when a user first joins
  static InitialSyncResult build_initial_timeline(
      DatabasePool& db,
      const std::string& room_id,
      const std::string& user_id,
      int64_t limit = 20) {

    InitialSyncResult result;
    result.limited = true;

    // ---- 1. Get current state for the room ----
    StateStore state(db);
    auto current_state = state.get_current_state(room_id);
    EventsStore evs(db);

    for (auto& [key, eid] : current_state) {
      auto ev = evs.get_event(eid);
      if (!ev) continue;

      json state_ev = *ev;
      result.state_events.push_back(state_ev);
    }

    // ---- 2. Get recent timeline events ----
    auto timeline_rows = db.execute("init_sync_timeline",
      "SELECT json, is_redacted, stream_ordering, topological_ordering, depth "
      "FROM events WHERE room_id='" + room_id + "' "
      "AND outlier = 0 "
      "ORDER BY stream_ordering DESC "
      "LIMIT " + std::to_string(limit));

    int64_t min_stream = INT64_MAX;
    int64_t max_stream = 0;
    int64_t min_topo = 0;
    int64_t max_topo = 0;

    for (auto& row : timeline_rows) {
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

      int64_t stream = row["stream_ordering"].value ?
        std::stoll(*row["stream_ordering"].value) : 0;
      int64_t topo = row["depth"].value ?
        std::stoll(*row["depth"].value) : 0;

      if (stream < min_stream) { min_stream = stream; min_topo = topo; }
      if (stream > max_stream) { max_stream = stream; max_topo = topo; }

      // Add unsigned age
      int64_t age = now_ms() - ev.value("origin_server_ts", 0);
      ev["unsigned"] = json::object();
      ev["unsigned"]["age"] = age;

      result.timeline_events.push_back(ev);
    }

    // ---- 3. Generate prev_batch token ----
    if (min_stream < INT64_MAX) {
      PaginationToken pt;
      pt.stream_ordering = min_stream - 1;
      pt.topological_ordering = min_topo;
      pt.direction = "b";
      result.prev_batch = pt.encode();

      // Check if timeline is limited
      auto count_rows = db.execute("init_sync_count",
        "SELECT COUNT(*) as cnt FROM events WHERE room_id='" + room_id +
        "' AND stream_ordering < " + std::to_string(min_stream) +
        " AND outlier = 0");
      if (!count_rows.empty() && count_rows[0]["cnt"].value) {
        int64_t older_count = std::stoll(*count_rows[0]["cnt"].value);
        result.limited = (older_count > 0);
      }
    }

    // ---- 4. Get member count ----
    RoomMemberStore members(db);
    auto joined = members.get_joined_members(room_id);
    result.num_joined_members = joined.size();

    // ---- 5. Get room account data ----
    // (user-specific room tags, etc.)
    result.room_account_data = json::object();

    return result;
  }

  // Build a limited initial sync (for rooms with too much history)
  static InitialSyncResult build_limited_initial_sync(
      DatabasePool& db,
      const std::string& room_id,
      const std::string& user_id,
      int64_t limit = 10) {

    InitialSyncResult result = build_initial_timeline(db, room_id, user_id, limit);
    result.limited = true;
    return result;
  }
};

// ============================================================================
// Prev Batch Token Generator
// ============================================================================

class PrevBatchTokenGenerator {
public:
  // Generate prev_batch token for a position in the timeline
  static std::string generate_prev_batch(
      int64_t stream_ordering,
      int64_t topological_ordering,
      const std::string& direction = "b") {

    PaginationToken pt;
    pt.stream_ordering = stream_ordering;
    pt.topological_ordering = topological_ordering;
    pt.direction = direction;
    return pt.encode();
  }

  // Generate prev_batch from the last event in a chunk
  static std::string generate_from_chunk(
      const std::vector<json>& chunk,
      const std::string& direction = "b") {

    if (chunk.empty()) {
      PaginationToken pt;
      pt.stream_ordering = 0;
      pt.direction = direction;
      return pt.encode();
    }

    // For backward pagination, prev_batch points to before the first event
    // For forward pagination, prev_batch points to after the last event
    int64_t stream, topo;

    if (direction == "b") {
      const json& first = chunk.front();
      stream = first.value("stream_ordering", 0);
      topo = first.value("depth", 0);
    } else {
      const json& last = chunk.back();
      stream = last.value("stream_ordering", 0);
      topo = last.value("depth", 0);
    }

    return generate_prev_batch(stream, topo, direction);
  }

  // Generate prev_batch token with gap indication
  static std::string generate_with_gap(
      int64_t stream_ordering,
      int64_t topological_ordering,
      bool has_gap,
      const std::string& direction = "b") {

    PaginationToken pt;
    pt.stream_ordering = stream_ordering;
    pt.topological_ordering = topological_ordering;
    pt.direction = direction;

    std::string token = pt.encode();
    if (has_gap) {
      token += "_g";  // Append gap indicator
    }
    return token;
  }

  // Check if a prev_batch token indicates a gap
  static bool token_has_gap(const std::string& prev_batch) {
    return prev_batch.size() >= 2 &&
           prev_batch.substr(prev_batch.size() - 2) == "_g";
  }

  // Generate end token (next_batch equivalent)
  static std::string generate_end_token(
      int64_t stream_ordering,
      int64_t topological_ordering,
      const std::string& direction = "b") {

    PaginationToken pt;
    pt.stream_ordering = stream_ordering;
    pt.topological_ordering = topological_ordering;
    pt.direction = direction;
    return pt.encode();
  }
};

// ============================================================================
// Event Redaction Helper
// ============================================================================

static json apply_redaction(const json& event) {
  json redacted;
  redacted["event_id"] = event["event_id"];
  redacted["room_id"] = event["room_id"];
  redacted["sender"] = event["sender"];
  redacted["type"] = event["type"];
  redacted["origin_server_ts"] = event["origin_server_ts"];
  if (event.contains("state_key")) redacted["state_key"] = event["state_key"];
  if (event.contains("unsigned")) redacted["unsigned"] = event["unsigned"];
  return redacted;
}

static json process_event_for_response(const json& event, bool is_redacted = false) {
  json result = event;

  if (is_redacted) {
    result = apply_redaction(event);
  }

  // Add unsigned age
  int64_t age = now_ms() - result.value("origin_server_ts", 0);
  if (!result.contains("unsigned") || !result["unsigned"].is_object()) {
    result["unsigned"] = json::object();
  }
  result["unsigned"]["age"] = age;

  return result;
}

// ============================================================================
// 1. GET ROOM MESSAGES HANDLER (PAGINATION)
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/messages
//
// Full-featured message pagination with:
// - from/to/dir/limit/filter query parameters
// - Pagination tokens (stream ordering + topological ordering)
// - Event type/sender filtering
// - Lazy loaded members
// - Redaction support
// - Timeline gap detection
// - Timeline caching
// - prev_batch/next_batch tokens
// - Deduplication
// - Topological ordering

json handle_get_room_messages(DatabasePool& db,
                               const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id,
                               const std::string& from_token_str,
                               const std::string& to_token_str,
                               const std::string& direction,
                               int64_t limit,
                               const json& filter_json) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room access ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  if (!can_view_history(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User cannot view history in this room");
  }

  // ---- 3. Validate pagination parameters ----
  if (direction != "b" && direction != "f") {
    return make_error(400, "M_UNKNOWN",
                      "Invalid direction. Must be 'b' (backward) or 'f' (forward).");
  }

  if (limit <= 0) limit = 10;
  if (limit > 1000) limit = 1000;

  // ---- 4. Parse pagination tokens ----
  PaginationToken from_token = PaginationToken::decode(from_token_str);
  PaginationToken to_token;

  if (!to_token_str.empty()) {
    to_token = PaginationToken::decode(to_token_str);
  }

  // Set defaults for empty tokens
  if (from_token_str.empty()) {
    if (direction == "b") {
      from_token.stream_ordering = INT64_MAX;
      from_token.direction = "b";
    } else {
      from_token.stream_ordering = 0;
      from_token.direction = "f";
    }
  }

  // ---- 5. Parse filter ----
  TimelineFilter filter = TimelineFilter::from_json(filter_json);

  // ---- 6. Check timeline cache ----
  std::string cache_key = room_id + ":" + from_token_str + ":" +
                          to_token_str + ":" + direction + ":" +
                          std::to_string(limit);

  auto cached = g_timeline_cache.get(cache_key);
  if (cached && !cached->limited) {
    // Return cached result if not limited
    json result;
    result["start"] = from_token_str;
    result["end"] = cached->end_token.encode();
    result["chunk"] = cached->events;
    result["limited"] = false;
    return make_response(200, result);
  }

  // ---- 7. Build SQL filter clause ----
  std::string filter_clause = filter.to_sql_clause();

  // ---- 8. Query events ----
  std::string sql;
  if (direction == "b") {
    sql = "SELECT event_id, json, is_redacted, stream_ordering, "
          "topological_ordering, depth, sender, type, state_key, "
          "contains_url, outlier "
          "FROM events WHERE room_id='" + room_id + "' "
          "AND stream_ordering < " + std::to_string(from_token.stream_ordering) +
          filter_clause +
          " AND outlier = 0 "
          "ORDER BY stream_ordering DESC, topological_ordering DESC "
          "LIMIT " + std::to_string(limit + 1); // +1 to detect has_more
  } else {
    sql = "SELECT event_id, json, is_redacted, stream_ordering, "
          "topological_ordering, depth, sender, type, state_key, "
          "contains_url, outlier "
          "FROM events WHERE room_id='" + room_id + "' "
          "AND stream_ordering > " + std::to_string(from_token.stream_ordering);
    if (!to_token_str.empty()) {
      sql += " AND stream_ordering < " + std::to_string(to_token.stream_ordering);
    }
    sql += filter_clause +
           " AND outlier = 0 "
           "ORDER BY stream_ordering ASC, topological_ordering ASC "
           "LIMIT " + std::to_string(limit + 1);
  }

  auto rows = db.execute("get_room_messages", sql);

  // ---- 9. Process results with deduplication ----
  json result;
  result["start"] = from_token_str;
  result["chunk"] = json::array();

  std::vector<json> events;
  std::unordered_set<std::string> seen_event_ids;

  int64_t min_stream = INT64_MAX;
  int64_t max_stream = 0;
  int64_t min_topo = 0;
  int64_t max_topo = 0;
  int count = 0;

  for (auto& row : rows) {
    if (count >= limit) break;

    std::string event_id = row["event_id"].value.value_or("");
    if (event_id.empty()) continue;

    // Deduplicate
    if (!seen_event_ids.insert(event_id).second) continue;

    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);

    int64_t stream_ord = row["stream_ordering"].value ?
      std::stoll(*row["stream_ordering"].value) : 0;
    int64_t depth = row["depth"].value ?
      std::stoll(*row["depth"].value) : 0;

    bool is_redacted = row["is_redacted"].value &&
                       *row["is_redacted"].value == "1";

    ev = process_event_for_response(ev, is_redacted);

    events.push_back(ev);
    result["chunk"].push_back(ev);

    if (stream_ord < min_stream) {
      min_stream = stream_ord;
      min_topo = depth;
    }
    if (stream_ord > max_stream) {
      max_stream = stream_ord;
      max_topo = depth;
    }

    count++;
  }

  // ---- 10. Determine limited flag and pagination tokens ----
  bool has_more = (rows.size() > static_cast<size_t>(limit));

  if (direction == "b") {
    // end token = token for the event at the end of the chunk
    if (count > 0) {
      PaginationToken end_token;
      end_token.stream_ordering = max_stream;
      end_token.topological_ordering = max_topo;
      end_token.direction = "b";
      result["end"] = end_token.encode();
    } else {
      result["end"] = from_token_str;
    }

    // If has_more, update start token
    result["start"] = has_more ?
      PrevBatchTokenGenerator::generate_prev_batch(min_stream, min_topo, "b") :
      from_token_str;
  } else {
    // Forward pagination: end token is for the last event
    if (count > 0) {
      PaginationToken end_token;
      end_token.stream_ordering = max_stream;
      end_token.topological_ordering = max_topo;
      end_token.direction = "f";
      result["end"] = end_token.encode();
    } else {
      result["end"] = from_token_str;
    }

    result["start"] = from_token_str;
  }

  result["limited"] = has_more;

  // ---- 11. Detect timeline gaps ----
  if (has_more && !events.empty()) {
    auto gap = TimelineGapDetector::detect_gap(
      db, room_id, events, from_token,
      PaginationToken::decode(result["end"].get<std::string>()),
      direction);

    if (gap) {
      result["gap"] = gap->to_json();
    }
  }

  // ---- 12. Add lazy loaded members if requested ----
  if (filter.lazy_load_members) {
    auto state_events = LazyMemberLoader::resolve_lazy_loaded_members(
      db, room_id, events, filter.include_redundant_members);
    if (!state_events.empty()) {
      result["state"] = state_events;
    }
  }

  // ---- 13. Cache the result ----
  if (!has_more) {
    TimelineCacheEntry entry;
    entry.room_id = room_id;
    entry.key = cache_key;
    entry.events = events;
    entry.start_token = from_token;
    entry.end_token = PaginationToken::decode(result["end"].get<std::string>());
    entry.limited = false;
    entry.cached_at = now_ms();
    entry.ttl_ms = 60000;  // 1 minute TTL
    g_timeline_cache.put(cache_key, entry);
  }

  // ---- 14. Check if room needs backfill ----
  if (has_more && FederationBackfillEngine::needs_backfill(db, room_id)) {
    result["needs_backfill"] = true;
  }

  return make_response(200, result);
}

// ============================================================================
// 2. GET EVENT CONTEXT HANDLER
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/context/{eventId}
//
// Retrieves events before and after a given event, plus state at that event.
// Parameters:
// - limit: max number of events before/after (default 10)
// - filter: JSON event filter

json handle_get_event_context(DatabasePool& db,
                               const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id,
                               const std::string& event_id,
                               int64_t limit,
                               const json& filter_json) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room access ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  if (!can_view_history(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User cannot view history in this room");
  }

  // ---- 3. Get the target event ----
  auto target_rows = db.execute("context_target_event",
    "SELECT json, is_redacted, stream_ordering, topological_ordering, "
    "depth, sender, type FROM events "
    "WHERE event_id='" + event_id + "' AND room_id='" + room_id + "'");

  if (target_rows.empty()) {
    return make_error(404, "M_NOT_FOUND",
                      "Event not found: " + event_id);
  }

  std::string target_json = target_rows[0]["json"].value.value_or("{}");
  json target_event = json::parse(target_json.empty() ? "{}" : target_json);
  int64_t target_stream = target_rows[0]["stream_ordering"].value ?
    std::stoll(*target_rows[0]["stream_ordering"].value) : 0;
  int64_t target_topo = target_rows[0]["depth"].value ?
    std::stoll(*target_rows[0]["depth"].value) : 0;

  // ---- 4. Validate and normalize limit ----
  if (limit <= 0) limit = 10;
  if (limit > 100) limit = 100;

  // Parse filter
  TimelineFilter filter = TimelineFilter::from_json(filter_json);

  // ---- 5. Get events before (lower stream_ordering) ----
  json events_before = json::array();
  std::string before_sql =
    "SELECT json, is_redacted, stream_ordering, topological_ordering, "
    "depth FROM events "
    "WHERE room_id='" + room_id + "' "
    "AND stream_ordering < " + std::to_string(target_stream) +
    filter.to_sql_clause() +
    " AND outlier = 0 "
    "ORDER BY stream_ordering DESC, topological_ordering DESC "
    "LIMIT " + std::to_string(limit);

  auto before_rows = db.execute("context_before", before_sql);

  for (auto& row : before_rows) {
    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
    bool is_redacted = row["is_redacted"].value &&
                       *row["is_redacted"].value == "1";
    ev = process_event_for_response(ev, is_redacted);
    events_before.push_back(ev);
  }

  // ---- 6. Get events after (higher stream_ordering) ----
  json events_after = json::array();
  std::string after_sql =
    "SELECT json, is_redacted, stream_ordering, topological_ordering, "
    "depth FROM events "
    "WHERE room_id='" + room_id + "' "
    "AND stream_ordering > " + std::to_string(target_stream) +
    filter.to_sql_clause() +
    " AND outlier = 0 "
    "ORDER BY stream_ordering ASC, topological_ordering ASC "
    "LIMIT " + std::to_string(limit);

  auto after_rows = db.execute("context_after", after_sql);

  for (auto& row : after_rows) {
    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
    bool is_redacted = row["is_redacted"].value &&
                       *row["is_redacted"].value == "1";
    ev = process_event_for_response(ev, is_redacted);
    events_after.push_back(ev);
  }

  // ---- 7. Get state at the event ----
  json state_at_event = json::array();
  StateStore state(db);
  auto current_state = state.get_current_state(room_id);
  EventsStore evs(db);

  for (auto& [key, eid] : current_state) {
    auto ev = evs.get_event(eid);
    if (!ev) continue;

    int64_t state_stream = (*ev).value("stream_ordering", 0);
    if (state_stream <= target_stream) {
      json state_ev;
      state_ev["type"] = key.first;
      state_ev["state_key"] = key.second;
      state_ev["content"] = (*ev).value("content", json::object());
      state_ev["event_id"] = eid;
      state_ev["sender"] = (*ev).value("sender", "");
      state_ev["origin_server_ts"] = (*ev).value("origin_server_ts", 0);
      state_ev["stream_ordering"] = state_stream;
      state_at_event.push_back(state_ev);
    }
  }

  // ---- 8. Process target event ----
  bool target_is_redacted = target_rows[0]["is_redacted"].value &&
                            *target_rows[0]["is_redacted"].value == "1";
  target_event = process_event_for_response(target_event, target_is_redacted);

  // ---- 9. Generate prev/next batch tokens ----
  std::string prev_batch, next_batch;
  if (!events_before.empty()) {
    int64_t first_before_stream = events_before[0].value("stream_ordering", 0);
    int64_t first_before_topo = events_before[0].value("depth", 0);
    prev_batch = PrevBatchTokenGenerator::generate_prev_batch(
      first_before_stream - 1, first_before_topo, "b");
  }
  if (!events_after.empty()) {
    int64_t last_after_stream = events_after.back().value("stream_ordering", 0);
    int64_t last_after_topo = events_after.back().value("depth", 0);
    next_batch = PrevBatchTokenGenerator::generate_end_token(
      last_after_stream + 1, last_after_topo, "f");
  }

  // ---- 10. Build response ----
  json result;
  result["event"] = target_event;
  result["events_before"] = events_before;
  result["events_after"] = events_after;
  result["state"] = state_at_event;

  if (!prev_batch.empty()) result["start"] = prev_batch;
  if (!next_batch.empty()) result["end"] = next_batch;

  return make_response(200, result);
}

// ============================================================================
// 3. GET ROOM TIMELINE HANDLER (INITIAL SYNC)
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/timeline
//
// Retrieves the initial timeline for a room. Used when a client first
// loads a room or after reconnection.

json handle_get_room_timeline(DatabasePool& db,
                               const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id,
                               int64_t limit,
                               bool include_state = true) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room access ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Validate parameters ----
  if (limit <= 0) limit = 20;
  if (limit > 500) limit = 500;

  // ---- 4. Build initial timeline ----
  auto initial = InitialSyncTimelineBuilder::build_initial_timeline(
    db, room_id, auth.user_id, limit);

  // ---- 5. Build response ----
  json result;
  result["chunk"] = initial.timeline_events;
  result["start"] = "";
  result["end"] = initial.prev_batch;
  result["limited"] = initial.limited;
  result["num_joined_members"] = initial.num_joined_members;

  if (include_state && !initial.state_events.empty()) {
    result["state"] = initial.state_events;
  }

  // ---- 6. Add lazy loaded member data ----
  auto lazy_members = LazyMemberLoader::resolve_lazy_loaded_members(
    db, room_id, initial.timeline_events, false);
  if (!lazy_members.empty()) {
    result["lazy_loaded_members"] = lazy_members;
  }

  // ---- 7. Check for gaps ----
  if (initial.limited) {
    auto gap = TimelineGapDetector::detect_sync_gap(
      db, room_id, 0, now_ms());
    if (gap) {
      result["gap"] = gap->to_json();
    }
  }

  return make_response(200, result);
}

// ============================================================================
// 4. BACKFILL TIMELINE HANDLER (FEDERATION)
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/backfill
//
// Triggers backfill from federation for a room with gaps in the timeline.

json handle_backfill_timeline(DatabasePool& db,
                               const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id,
                               const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room access ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Parse backfill parameters ----
  int64_t limit = request_body.value("limit", 50);
  if (limit <= 0) limit = 50;
  if (limit > 500) limit = 500;

  std::vector<std::string> extremity_ids;
  if (request_body.contains("event_ids") && request_body["event_ids"].is_array()) {
    for (auto& eid : request_body["event_ids"]) {
      if (eid.is_string()) {
        extremity_ids.push_back(eid.get<std::string>());
      }
    }
  }

  std::string target_server = request_body.value("server", "");

  // ---- 4. Perform backfill ----
  auto backfill_result = FederationBackfillEngine::backfill(
    db, room_id, extremity_ids, limit, target_server);

  // ---- 5. Build response ----
  json result;
  result["events"] = backfill_result.events;
  result["event_count"] = backfill_result.events.size();
  result["limited"] = backfill_result.limited;
  result["success"] = backfill_result.success;

  if (!backfill_result.prev_batch.empty()) {
    result["prev_batch"] = backfill_result.prev_batch;
  }
  if (!backfill_result.next_batch.empty()) {
    result["next_batch"] = backfill_result.next_batch;
  }
  if (!backfill_result.error.empty()) {
    result["error"] = backfill_result.error;
  }

  // ---- 6. Update room timeline status ----
  if (backfill_result.success && !backfill_result.limited) {
    db.execute("clear_limited",
      "UPDATE room_timeline_status SET is_limited=0, needs_backfill=0 "
      "WHERE room_id='" + room_id + "'");
  }

  return make_response(200, result);
}

// ============================================================================
// 5. RESOLVE ROOM STATE HANDLER
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/state_at/{eventId}
//
// Resolves the state of a room at the time of a specific event.

json handle_resolve_room_state(DatabasePool& db,
                                const std::string& auth_header,
                                const std::string& access_token_param,
                                const std::string& room_id,
                                const std::string& event_id) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room access ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Resolve state ----
  auto state_result = StateAtEventResolver::resolve_state_at_event(
    db, room_id, event_id);

  if (state_result.contains("error")) {
    return make_error(404, "M_NOT_FOUND",
                      state_result["error"].get<std::string>());
  }

  // ---- 4. Return state ----
  return make_response(200, state_result);
}

// ============================================================================
// 6. GET TIMELINE BATCH HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/timeline/batch
//
// Retrieves multiple events by their IDs. Used to resolve events
// that may have been referenced but not yet fetched by the client.

json handle_get_timeline_batch(DatabasePool& db,
                                const std::string& auth_header,
                                const std::string& access_token_param,
                                const std::string& room_id,
                                const std::vector<std::string>& event_ids,
                                bool deduplicate = true) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room access ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  if (event_ids.empty()) {
    return make_response(200, json::array());
  }

  // ---- 3. Build event ID list ----
  std::string id_list;
  for (auto& eid : event_ids) {
    if (!id_list.empty()) id_list += ",";
    id_list += "'" + eid + "'";
  }

  // ---- 4. Query events ----
  auto rows = db.execute("get_timeline_batch",
    "SELECT event_id, json, is_redacted, stream_ordering, "
    "topological_ordering, depth, sender, type "
    "FROM events "
    "WHERE event_id IN (" + id_list + ") AND room_id='" + room_id + "' "
    "ORDER BY stream_ordering DESC");

  // ---- 5. Process results ----
  std::vector<json> events;
  std::unordered_set<std::string> seen;

  for (auto& row : rows) {
    std::string eid = row["event_id"].value.value_or("");
    if (eid.empty() || (deduplicate && !seen.insert(eid).second)) continue;

    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
    bool is_redacted = row["is_redacted"].value &&
                       *row["is_redacted"].value == "1";
    ev = process_event_for_response(ev, is_redacted);
    events.push_back(ev);
  }

  // ---- 6. Add lazy loaded members for the batch ----
  json result;
  result["events"] = events;
  result["count"] = events.size();

  auto lazy_members = LazyMemberLoader::resolve_lazy_loaded_members(
    db, room_id, events, false);
  if (!lazy_members.empty()) {
    result["state"] = lazy_members;
  }

  return make_response(200, result);
}

// ============================================================================
// 7. STREAM PAGINATE HANDLER
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/stream/{streamToken}
//
// Paginates events using raw stream ordering for efficient sync.

json handle_stream_paginate(DatabasePool& db,
                             const std::string& auth_header,
                             const std::string& access_token_param,
                             const std::string& room_id,
                             int64_t from_stream,
                             int64_t to_stream,
                             const std::string& direction,
                             int64_t limit) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room access ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  if (limit <= 0) limit = 100;
  if (limit > 5000) limit = 5000;

  // ---- 3. Query events by stream range ----
  std::string sql;
  if (direction == "f") {
    sql = "SELECT event_id, json, is_redacted, stream_ordering, "
          "topological_ordering, depth, type, sender "
          "FROM events WHERE room_id='" + room_id + "' "
          "AND stream_ordering > " + std::to_string(from_stream) +
          " AND stream_ordering <= " + std::to_string(to_stream) +
          " AND outlier = 0 "
          "ORDER BY stream_ordering ASC "
          "LIMIT " + std::to_string(limit);
  } else {
    sql = "SELECT event_id, json, is_redacted, stream_ordering, "
          "topological_ordering, depth, type, sender "
          "FROM events WHERE room_id='" + room_id + "' "
          "AND stream_ordering < " + std::to_string(from_stream) +
          " AND stream_ordering >= " + std::to_string(to_stream) +
          " AND outlier = 0 "
          "ORDER BY stream_ordering DESC "
          "LIMIT " + std::to_string(limit);
  }

  auto rows = db.execute("stream_paginate", sql);

  // ---- 4. Process results ----
  json result;
  result["chunk"] = json::array();
  result["start"] = std::to_string(from_stream);
  int64_t last_stream = from_stream;

  for (auto& row : rows) {
    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
    bool is_redacted = row["is_redacted"].value &&
                       *row["is_redacted"].value == "1";
    ev = process_event_for_response(ev, is_redacted);
    result["chunk"].push_back(ev);

    int64_t stream = row["stream_ordering"].value ?
      std::stoll(*row["stream_ordering"].value) : 0;
    last_stream = stream;
  }

  result["end"] = std::to_string(last_stream);
  result["limited"] = (rows.size() >= static_cast<size_t>(limit));

  return make_response(200, result);
}

// ============================================================================
// 8. GET TIMELINE FOR SYNC
// ============================================================================
// Internal function to generate timeline data for sync responses.
// Used by the sync handler to produce timeline chunks with limited flags.

struct SyncTimelineResult {
  std::vector<json> events;
  std::string prev_batch;
  bool limited;
  int64_t num_joined_members;
  std::vector<json> state;
};

SyncTimelineResult get_timeline_for_sync(DatabasePool& db,
                                          const std::string& room_id,
                                          const std::string& user_id,
                                          int64_t since_token,
                                          int64_t limit = 50) {
  SyncTimelineResult result;
  result.limited = false;

  std::lock_guard<std::mutex> lock(g_sync_timeline_mutex);

  // ---- 1. Get events since the last sync ----
  std::string sql =
    "SELECT event_id, json, is_redacted, stream_ordering, "
    "topological_ordering, depth, sender, type, state_key "
    "FROM events WHERE room_id='" + room_id + "' "
    "AND stream_ordering > " + std::to_string(since_token) +
    " AND outlier = 0 "
    "ORDER BY stream_ordering ASC "
    "LIMIT " + std::to_string(limit);

  auto rows = db.execute("sync_timeline", sql);

  // ---- 2. Process events ----
  std::unordered_set<std::string> seen;
  int64_t last_stream = since_token;
  int64_t first_topological = 0;

  for (auto& row : rows) {
    std::string eid = row["event_id"].value.value_or("");
    if (eid.empty() || !seen.insert(eid).second) continue;

    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
    bool is_redacted = row["is_redacted"].value &&
                       *row["is_redacted"].value == "1";
    ev = process_event_for_response(ev, is_redacted);
    result.events.push_back(ev);

    int64_t stream = row["stream_ordering"].value ?
      std::stoll(*row["stream_ordering"].value) : 0;
    last_stream = stream;

    if (first_topological == 0) {
      first_topological = row["depth"].value ?
        std::stoll(*row["depth"].value) : 0;
    }
  }

  // ---- 3. Check for gap (limited timeline) ----
  auto count_rows = db.execute("sync_gap_count",
    "SELECT COUNT(*) as cnt FROM events WHERE room_id='" + room_id +
    "' AND stream_ordering > " + std::to_string(since_token) +
    " AND stream_ordering <= " + std::to_string(last_stream) +
    " AND outlier = 0");

  int64_t total_events = 0;
  if (!count_rows.empty() && count_rows[0]["cnt"].value) {
    total_events = std::stoll(*count_rows[0]["cnt"].value);
  }

  // Limited if we couldn't return all events
  result.limited = (total_events > static_cast<int64_t>(result.events.size()));

  // ---- 4. Check for gap using GapDetector ----
  auto sync_gap = TimelineGapDetector::detect_sync_gap(
    db, room_id, since_token, last_stream);
  if (sync_gap) {
    result.limited = true;
  }

  // ---- 5. Generate prev_batch token ----
  if (!result.events.empty()) {
    PaginationToken pt;
    pt.stream_ordering = result.events[0].value("stream_ordering", 0);
    pt.topological_ordering = result.events[0].value("depth", 0);
    pt.direction = "b";
    result.prev_batch = pt.encode();
  } else {
    result.prev_batch = std::to_string(since_token);
  }

  // ---- 6. Get room state (limited set for sync) ----
  StateStore state(db);
  auto current_state = state.get_current_state(room_id);
  EventsStore evs(db);

  // Only include essential state for sync
  for (auto& [key, eid] : current_state) {
    if (key.first == "m.room.name" ||
        key.first == "m.room.canonical_alias" ||
        key.first == "m.room.topic" ||
        key.first == "m.room.avatar" ||
        key.first == "m.room.join_rules" ||
        key.first == "m.room.create" ||
        key.first == "m.room.encryption" ||
        key.first == "m.room.tombstone") {
      auto ev = evs.get_event(eid);
      if (ev) {
        json state_ev;
        state_ev["type"] = key.first;
        state_ev["state_key"] = key.second;
        state_ev["content"] = (*ev).value("content", json::object());
        state_ev["event_id"] = eid;
        result.state.push_back(state_ev);
      }
    }
  }

  // ---- 7. Get member count ----
  RoomMemberStore members(db);
  auto joined = members.get_joined_members(room_id);
  result.num_joined_members = joined.size();

  return result;
}

// ============================================================================
// 9. DETECT TIMELINE GAPS HANDLER
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/timeline/gaps
//
// Detects and returns gaps in a room's timeline.

json handle_detect_timeline_gaps(DatabasePool& db,
                                  const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& room_id,
                                  int64_t from_stream,
                                  int64_t to_stream) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room access ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Get all gaps for the room ----
  auto gaps = TimelineGapDetector::get_gaps(db, room_id);

  // ---- 4. Also check live gap detection in the given range ----
  if (to_stream > from_stream) {
    auto sync_gap = TimelineGapDetector::detect_sync_gap(
      db, room_id, from_stream, to_stream);
    if (sync_gap) {
      gaps.push_back(*sync_gap);
    }
  }

  // ---- 5. Check for backward/forward gaps near the range boundaries ----
  bool backward_gap = TimelineGapDetector::is_next_to_backward_gap(
    db, room_id, from_stream);
  bool forward_gap = TimelineGapDetector::is_next_to_forward_gap(
    db, room_id, to_stream);

  // ---- 6. Build response ----
  json result;
  result["gaps"] = json::array();
  for (auto& gap : gaps) {
    result["gaps"].push_back(gap.to_json());
  }
  result["backward_gap"] = backward_gap;
  result["forward_gap"] = forward_gap;
  result["needs_backfill"] = FederationBackfillEngine::needs_backfill(db, room_id);
  result["gap_count"] = gaps.size();

  return make_response(200, result);
}

// ============================================================================
// 10. GET PREV BATCH TOKEN HANDLER
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/prev_batch
//
// Generates a prev_batch token for a given position.

json handle_get_prev_batch_token(DatabasePool& db,
                                  const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& room_id,
                                  int64_t stream_ordering,
                                  int64_t topological_ordering) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room access ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 3. Check if there's a gap at this position ----
  json result;

  // Generate prev_batch token
  std::string prev_batch = PrevBatchTokenGenerator::generate_prev_batch(
    stream_ordering, topological_ordering);

  // Check if this position has a gap
  bool has_gap = TimelineGapDetector::is_next_to_backward_gap(
    db, room_id, stream_ordering);

  // Generate end token
  std::string end_token = PrevBatchTokenGenerator::generate_end_token(
    stream_ordering, topological_ordering);

  // ---- 4. Build response ----
  result["prev_batch"] = prev_batch;
  result["has_gap"] = has_gap;
  result["limited"] = has_gap;

  return make_response(200, result);
}

// ============================================================================
// 11. GAPPY SYNC HANDLER
// ============================================================================
// Handles the case where a sync has gaps (limited timeline).
// Called internally when sync detects a limited timeline.

json handle_gappy_sync_timeline(DatabasePool& db,
                                 const std::string& room_id,
                                 const std::string& user_id,
                                 int64_t since_token,
                                 int64_t limit) {
  std::lock_guard<std::mutex> lock(g_sync_timeline_mutex);

  // ---- 1. Detect the sync gap ----
  int64_t current_max_stream = 0;
  auto max_rows = db.execute("max_stream_room",
    "SELECT MAX(stream_ordering) as m FROM events "
    "WHERE room_id='" + room_id + "'");
  if (!max_rows.empty() && max_rows[0]["m"].value) {
    current_max_stream = std::stoll(*max_rows[0]["m"].value);
  }

  auto gap = TimelineGapDetector::detect_sync_gap(
    db, room_id, since_token, current_max_stream);

  // ---- 2. Get what events we can (most recent ones) ----
  std::string sql =
    "SELECT event_id, json, is_redacted, stream_ordering, "
    "topological_ordering, depth, sender, type, state_key "
    "FROM events WHERE room_id='" + room_id + "' "
    "AND stream_ordering <= " + std::to_string(current_max_stream) +
    " AND outlier = 0 "
    "ORDER BY stream_ordering DESC "
    "LIMIT " + std::to_string(limit);

  auto rows = db.execute("gappy_sync_timeline", sql);

  // ---- 3. Process events (newest first) ----
  std::vector<json> events;
  std::unordered_set<std::string> seen;
  int64_t oldest_returned_stream = INT64_MAX;

  for (auto& row : rows) {
    std::string eid = row["event_id"].value.value_or("");
    if (eid.empty() || !seen.insert(eid).second) continue;

    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
    bool is_redacted = row["is_redacted"].value &&
                       *row["is_redacted"].value == "1";
    ev = process_event_for_response(ev, is_redacted);
    events.push_back(ev);

    int64_t stream = row["stream_ordering"].value ?
      std::stoll(*row["stream_ordering"].value) : 0;
    if (stream < oldest_returned_stream) {
      oldest_returned_stream = stream;
    }
  }

  // Reverse to get chronological order (oldest first)
  std::reverse(events.begin(), events.end());

  // ---- 4. Generate prev_batch pointing to before oldest returned event ----
  std::string prev_batch;
  if (oldest_returned_stream < INT64_MAX) {
    PaginationToken pt;
    pt.stream_ordering = oldest_returned_stream;
    pt.topological_ordering = events.empty() ? 0 :
      events[0].value("depth", 0);
    pt.direction = "b";

    // Mark as gap token
    prev_batch = PrevBatchTokenGenerator::generate_with_gap(
      oldest_returned_stream,
      events.empty() ? 0 : events[0].value("depth", 0),
      true, "b");
  }

  // ---- 5. Build response ----
  json result;
  result["chunk"] = events;
  result["start"] = std::to_string(since_token);
  result["end"] = prev_batch;
  result["limited"] = true;
  result["num_events_skipped"] = gap ? gap->gap_size_estimate : 0;

  if (gap) {
    result["gap_info"] = gap->to_json();
    result["needs_backfill"] = true;
  }

  // ---- 6. Mark room as needing backfill ----
  FederationBackfillEngine::mark_for_backfill(db, room_id);

  return result;
}

// ============================================================================
// 12. TIMELINE ENRICHMENT
// ============================================================================
// Enriches timeline events with additional context data.

json enrich_timeline_events(DatabasePool& db,
                             const std::string& room_id,
                             const std::vector<json>& events,
                             bool include_relations = true,
                             bool include_read_receipts = false) {
  json result;
  result["events"] = events;

  // ---- 1. Add event relations (aggregations) ----
  if (include_relations) {
    json relations = json::object();

    for (auto& ev : events) {
      std::string eid = ev.value("event_id", "");
      if (eid.empty()) continue;

      auto agg_rows = db.execute("timeline_aggs",
        "SELECT key, count FROM event_relation_aggregations "
        "WHERE event_id='" + eid + "' AND type='m.annotation'");

      if (!agg_rows.empty()) {
        json annotations = json::object();
        for (auto& row : agg_rows) {
          std::string key = row["key"].value.value_or("");
          int64_t count = row["count"].value ?
            std::stoll(*row["count"].value) : 0;
          annotations[key] = count;
        }
        relations[eid] = {{"m.annotation", annotations}};
      }
    }

    result["relations"] = relations;
  }

  // ---- 2. Add read receipts ----
  if (include_read_receipts) {
    json read_receipts = json::object();

    for (auto& ev : events) {
      std::string eid = ev.value("event_id", "");
      if (eid.empty()) continue;

      auto rr_rows = db.execute("timeline_read_receipts",
        "SELECT user_id, ts FROM receipts_linearized "
        "WHERE event_id='" + eid + "' AND room_id='" + room_id + "'");

      if (!rr_rows.empty()) {
        json eid_receipts = json::object();
        for (auto& row : rr_rows) {
          std::string uid = row["user_id"].value.value_or("");
          int64_t ts = row["ts"].value ? std::stoll(*row["ts"].value) : 0;
          eid_receipts[uid] = {{"ts", ts}};
        }
        read_receipts[eid] = eid_receipts;
      }
    }

    result["read_receipts"] = read_receipts;
  }

  return result;
}

// ============================================================================
// 13. TIMELINE LIST BUILDERS (FOR ROOM LIST)
// ============================================================================

json build_room_timeline_summary(DatabasePool& db,
                                  const std::string& room_id,
                                  const std::string& user_id) {
  json summary;

  // ---- 1. Get last event info ----
  auto last_rows = db.execute("timeline_summary_last",
    "SELECT json, type, sender, origin_server_ts, stream_ordering "
    "FROM events WHERE room_id='" + room_id + "' "
    "AND outlier = 0 "
    "ORDER BY stream_ordering DESC LIMIT 1");

  if (!last_rows.empty()) {
    std::string ev_str = last_rows[0]["json"].value.value_or("{}");
    json last_ev = json::parse(ev_str.empty() ? "{}" : ev_str);

    summary["last_event"] = json::object();
    summary["last_event"]["event_id"] = last_ev.value("event_id", "");
    summary["last_event"]["type"] = last_rows[0]["type"].value.value_or("");
    summary["last_event"]["sender"] = last_rows[0]["sender"].value.value_or("");
    summary["last_event"]["origin_server_ts"] = last_rows[0]["origin_server_ts"].value ?
      std::stoll(*last_rows[0]["origin_server_ts"].value) : 0;

    // Get sender display name
    std::string sender = last_rows[0]["sender"].value.value_or("");
    if (!sender.empty()) {
      ProfileStore profiles(db);
      auto profile = profiles.get_profile(sender);
      if (profile) {
        summary["last_event"]["sender_display_name"] = profile->display_name.value_or("");
        summary["last_event"]["sender_avatar_url"] = profile->avatar_url.value_or("");
      }
    }

    // Get content body preview
    if (last_ev.contains("content") && last_ev["content"].is_object()) {
      std::string body = last_ev["content"].value("body", "");
      std::string msgtype = last_ev["content"].value("msgtype", "");

      if (msgtype == "m.image") {
        summary["last_event"]["preview"] = "sent an image";
      } else if (msgtype == "m.file") {
        summary["last_event"]["preview"] = "sent a file";
      } else if (msgtype == "m.video") {
        summary["last_event"]["preview"] = "sent a video";
      } else if (msgtype == "m.audio") {
        summary["last_event"]["preview"] = "sent an audio message";
      } else if (!body.empty()) {
        if (body.size() > 100) {
          summary["last_event"]["preview"] = body.substr(0, 100) + "...";
        } else {
          summary["last_event"]["preview"] = body;
        }
      }
    }
  }

  // ---- 2. Get event counts ----
  auto count_rows = db.execute("timeline_summary_counts",
    "SELECT COUNT(*) as cnt FROM events WHERE room_id='" + room_id +
    "' AND outlier = 0");
  int64_t total_events = 0;
  if (!count_rows.empty() && count_rows[0]["cnt"].value) {
    total_events = std::stoll(*count_rows[0]["cnt"].value);
  }
  summary["total_events"] = total_events;

  // ---- 3. Check if timeline is limited ----
  summary["limited"] = FederationBackfillEngine::needs_backfill(db, room_id);

  // ---- 4. Get member count ----
  RoomMemberStore members(db);
  auto joined = members.get_joined_members(room_id);
  summary["num_joined_members"] = joined.size();

  return summary;
}

// ============================================================================
// 14. BULK TIMELINE OPERATIONS
// ============================================================================

json handle_bulk_get_timelines(DatabasePool& db,
                                const std::string& auth_header,
                                const std::string& access_token_param,
                                const std::vector<std::string>& room_ids,
                                int64_t limit) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (limit <= 0) limit = 10;
  if (limit > 50) limit = 50;

  // ---- 2. Build response for each room ----
  json result;

  for (auto& room_id : room_ids) {
    if (!is_user_in_room(db, room_id, auth.user_id)) {
      result[room_id] = {{"error", "Not a member"}};
      continue;
    }

    auto summary = build_room_timeline_summary(db, room_id, auth.user_id);
    result[room_id] = summary;
  }

  return make_response(200, result);
}

// ============================================================================
// 15. TIMELINE INVALIDATION
// ============================================================================

void invalidate_room_timeline_cache(const std::string& room_id) {
  g_timeline_cache.invalidate_room(room_id);
}

void clear_all_timeline_caches() {
  g_timeline_cache.clear();
}

// ============================================================================
// 16. GET TIMELINE AROUND TOKEN
// ============================================================================
// Retrieves events before and after a given pagination token.

json handle_get_timeline_around_token(DatabasePool& db,
                                       const std::string& auth_header,
                                       const std::string& access_token_param,
                                       const std::string& room_id,
                                       const std::string& token_str,
                                       int64_t before_limit,
                                       int64_t after_limit) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room access ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  PaginationToken token = PaginationToken::decode(token_str);

  if (before_limit <= 0) before_limit = 5;
  if (after_limit <= 0) after_limit = 5;
  if (before_limit > 50) before_limit = 50;
  if (after_limit > 50) after_limit = 50;

  // ---- 3. Get events before ----
  json events_before = json::array();
  auto before_rows = db.execute("around_before",
    "SELECT json, is_redacted, stream_ordering, topological_ordering, depth "
    "FROM events WHERE room_id='" + room_id + "' "
    "AND stream_ordering < " + std::to_string(token.stream_ordering) +
    " AND outlier = 0 "
    "ORDER BY stream_ordering DESC "
    "LIMIT " + std::to_string(before_limit));

  for (auto& row : before_rows) {
    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
    bool is_redacted = row["is_redacted"].value &&
                       *row["is_redacted"].value == "1";
    ev = process_event_for_response(ev, is_redacted);
    events_before.push_back(ev);
  }

  // ---- 4. Get events after ----
  json events_after = json::array();
  auto after_rows = db.execute("around_after",
    "SELECT json, is_redacted, stream_ordering, topological_ordering, depth "
    "FROM events WHERE room_id='" + room_id + "' "
    "AND stream_ordering >= " + std::to_string(token.stream_ordering) +
    " AND outlier = 0 "
    "ORDER BY stream_ordering ASC "
    "LIMIT " + std::to_string(after_limit));

  for (auto& row : after_rows) {
    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
    bool is_redacted = row["is_redacted"].value &&
                       *row["is_redacted"].value == "1";
    ev = process_event_for_response(ev, is_redacted);
    events_after.push_back(ev);
  }

  // ---- 5. Build response ----
  json result;
  result["events_before"] = events_before;
  result["events_after"] = events_after;
  result["start"] = token_str;
  result["end"] = token_str;

  return make_response(200, result);
}

// ============================================================================
// 17. GET ROOM EVENT COUNT
// ============================================================================

json handle_get_room_event_count(DatabasePool& db,
                                  const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& room_id) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  auto rows = db.execute("event_count",
    "SELECT COUNT(*) as cnt FROM events WHERE room_id='" + room_id +
    "' AND outlier = 0");

  int64_t count = 0;
  if (!rows.empty() && rows[0]["cnt"].value) {
    count = std::stoll(*rows[0]["cnt"].value);
  }

  json result;
  result["total_events"] = count;

  // Also get stream range
  auto range_rows = db.execute("stream_range",
    "SELECT MIN(stream_ordering) as min_s, MAX(stream_ordering) as max_s "
    "FROM events WHERE room_id='" + room_id + "' AND outlier = 0");

  if (!range_rows.empty()) {
    if (range_rows[0]["min_s"].value) {
      result["min_stream"] = std::stoll(*range_rows[0]["min_s"].value);
    }
    if (range_rows[0]["max_s"].value) {
      result["max_stream"] = std::stoll(*range_rows[0]["max_s"].value);
    }
  }

  return make_response(200, result);
}

// ============================================================================
// 18. GET TIMELINE VISIBILITY
// ============================================================================
// Returns timeline visibility settings for a room.

json handle_get_timeline_visibility(DatabasePool& db,
                                     const std::string& auth_header,
                                     const std::string& access_token_param,
                                     const std::string& room_id) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  json result;

  // Get history visibility
  StateStore state(db);
  auto hv_event = state.get_current_state_event(room_id, "m.room.history_visibility", "");
  if (hv_event) {
    EventsStore evs(db);
    auto ev = evs.get_event(*hv_event);
    if (ev) {
      result["history_visibility"] = (*ev)["content"].value("history_visibility", "shared");
    }
  } else {
    result["history_visibility"] = "shared";
  }

  // Check if user can view history
  result["can_view_history"] = can_view_history(db, room_id, auth.user_id);

  // Check if room needs backfill
  result["needs_backfill"] = FederationBackfillEngine::needs_backfill(db, room_id);

  // Check for gaps
  auto gaps = TimelineGapDetector::get_gaps(db, room_id);
  result["gap_count"] = gaps.size();
  result["has_gaps"] = !gaps.empty();

  return make_response(200, result);
}

// ============================================================================
// 19. TOPOLOGICAL PAGINATION HANDLER
// ============================================================================
// Paginates events using topological ordering primarily, stream ordering secondarily.

json handle_topological_paginate(DatabasePool& db,
                                  const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& room_id,
                                  const std::string& from_token_str,
                                  int64_t limit) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  PaginationToken from_token = PaginationToken::decode(from_token_str);
  if (from_token_str.empty()) {
    from_token.stream_ordering = INT64_MAX;
  }

  if (limit <= 0) limit = 10;
  if (limit > 500) limit = 500;

  // ---- 2. Query with topological ordering ----
  std::string sql =
    "SELECT json, is_redacted, stream_ordering, topological_ordering, depth "
    "FROM events WHERE room_id='" + room_id + "' "
    "AND (topological_ordering < " + std::to_string(from_token.topological_ordering) +
    " OR (topological_ordering = " + std::to_string(from_token.topological_ordering) +
    " AND stream_ordering < " + std::to_string(from_token.stream_ordering) + ")) "
    "AND outlier = 0 "
    "ORDER BY topological_ordering DESC, stream_ordering DESC "
    "LIMIT " + std::to_string(limit + 1);

  auto rows = db.execute("topo_paginate", sql);

  // ---- 3. Process ----
  json result;
  result["chunk"] = json::array();
  result["start"] = from_token_str;

  int64_t last_stream = 0;
  int64_t last_topo = 0;
  int count = 0;

  for (auto& row : rows) {
    if (count >= limit) break;

    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
    bool is_redacted = row["is_redacted"].value &&
                       *row["is_redacted"].value == "1";
    ev = process_event_for_response(ev, is_redacted);

    result["chunk"].push_back(ev);

    last_stream = row["stream_ordering"].value ?
      std::stoll(*row["stream_ordering"].value) : 0;
    last_topo = row["depth"].value ?
      std::stoll(*row["depth"].value) : 0;
    count++;
  }

  result["end"] = PrevBatchTokenGenerator::generate_prev_batch(
    last_stream, last_topo, "b");
  result["limited"] = rows.size() > static_cast<size_t>(limit);

  // After topological pagination, sort results topologically
  std::vector<json> chunk;
  for (auto& ev : result["chunk"]) chunk.push_back(ev);
  TopologicalOrderer::sort_topologically(chunk);
  result["chunk"] = chunk;

  return make_response(200, result);
}

// ============================================================================
// 20. TIMELINE EXPORT HANDLER
// ============================================================================
// Exports timeline events in a streamable format.

json handle_timeline_export(DatabasePool& db,
                             const std::string& auth_header,
                             const std::string& access_token_param,
                             const std::string& room_id,
                             int64_t from_ts,
                             int64_t to_ts,
                             int64_t limit) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  if (limit <= 0) limit = 100;
  if (limit > 1000) limit = 1000;

  std::string sql =
    "SELECT json, is_redacted, stream_ordering, depth, type, sender, "
    "origin_server_ts FROM events "
    "WHERE room_id='" + room_id + "' "
    "AND origin_server_ts >= " + std::to_string(from_ts) +
    " AND origin_server_ts <= " + std::to_string(to_ts) +
    " AND outlier = 0 "
    "ORDER BY origin_server_ts ASC "
    "LIMIT " + std::to_string(limit);

  auto rows = db.execute("timeline_export", sql);

  json result;
  result["events"] = json::array();
  result["from"] = from_ts;
  result["to"] = to_ts;

  for (auto& row : rows) {
    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
    bool is_redacted = row["is_redacted"].value &&
                       *row["is_redacted"].value == "1";
    ev = process_event_for_response(ev, is_redacted);
    result["events"].push_back(ev);
  }

  result["count"] = result["events"].size();

  return make_response(200, result);
}

// ============================================================================
// 21. GET ROOM TIMELINE FILTERS
// ============================================================================
// Returns available filters for a room's timeline.

json handle_get_timeline_filters(DatabasePool& db,
                                  const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& room_id) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // Get distinct event types in the room
  auto type_rows = db.execute("timeline_types",
    "SELECT DISTINCT type FROM events WHERE room_id='" + room_id +
    "' AND outlier = 0 ORDER BY type");

  json types = json::array();
  for (auto& row : type_rows) {
    types.push_back(row["type"].value.value_or(""));
  }

  // Get distinct senders
  auto sender_rows = db.execute("timeline_senders",
    "SELECT DISTINCT sender FROM events WHERE room_id='" + room_id +
    "' AND outlier = 0 ORDER BY sender");

  json senders = json::array();
  for (auto& row : sender_rows) {
    senders.push_back(row["sender"].value.value_or(""));
  }

  json result;
  result["event_types"] = types;
  result["senders"] = senders;
  result["has_url_events"] = false;  // Would check contains_url column

  return make_response(200, result);
}

// ============================================================================
// 22. TIMELINE PERIODIC CLEANUP
// ============================================================================

void timeline_periodic_cleanup(DatabasePool& db) {
  // Clean up expired cache entries
  g_timeline_cache.clear();

  // Clean up old gap records (older than 7 days)
  int64_t cutoff = now_ms() - (7 * 24 * 60 * 60 * 1000);
  db.execute("cleanup_gaps",
    "DELETE FROM timeline_gaps WHERE detected_at < " + std::to_string(cutoff));

  // Clean up old timeline status records
  db.execute("cleanup_timeline_status",
    "DELETE FROM room_timeline_status WHERE limited_ts < " +
    std::to_string(cutoff));
}

// ============================================================================
// 23. TIMELINE STATISTICS
// ============================================================================

json handle_get_timeline_stats(DatabasePool& db,
                                const std::string& auth_header,
                                const std::string& access_token_param) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  json stats;

  // Count events
  auto event_rows = db.execute("stats_events",
    "SELECT COUNT(*) as cnt FROM events WHERE outlier = 0");
  if (!event_rows.empty() && event_rows[0]["cnt"].value) {
    stats["total_events"] = std::stoll(*event_rows[0]["cnt"].value);
  }

  // Count rooms with timelines
  auto room_rows = db.execute("stats_rooms",
    "SELECT COUNT(DISTINCT room_id) as cnt FROM events WHERE outlier = 0");
  if (!room_rows.empty() && room_rows[0]["cnt"].value) {
    stats["rooms_with_events"] = std::stoll(*room_rows[0]["cnt"].value);
  }

  // Cache statistics
  stats["cache_size"] = g_timeline_cache.size();

  // Gap statistics
  auto gap_rows = db.execute("stats_gaps",
    "SELECT COUNT(*) as cnt FROM timeline_gaps");
  if (!gap_rows.empty() && gap_rows[0]["cnt"].value) {
    stats["total_gaps"] = std::stoll(*gap_rows[0]["cnt"].value);
  }

  // Backfill statistics
  auto backfill_rows = db.execute("stats_backfill",
    "SELECT COUNT(*) as cnt FROM room_timeline_status WHERE needs_backfill=1");
  if (!backfill_rows.empty() && backfill_rows[0]["cnt"].value) {
    stats["rooms_needing_backfill"] = std::stoll(*backfill_rows[0]["cnt"].value);
  }

  // Stream ordering range
  auto stream_rows = db.execute("stats_stream",
    "SELECT MIN(stream_ordering) as min_s, MAX(stream_ordering) as max_s FROM events");
  if (!stream_rows.empty()) {
    if (stream_rows[0]["min_s"].value) {
      stats["min_stream"] = std::stoll(*stream_rows[0]["min_s"].value);
    }
    if (stream_rows[0]["max_s"].value) {
      stats["max_stream"] = std::stoll(*stream_rows[0]["max_s"].value);
    }
  }

  return make_response(200, stats);
}

// ============================================================================
// 24. PAGINATION TOKEN UTILITIES
// ============================================================================

// Decode a pagination token and return its components
json decode_pagination_token_json(const std::string& token) {
  PaginationToken pt = PaginationToken::decode(token);

  json result;
  result["stream_ordering"] = pt.stream_ordering;
  result["topological_ordering"] = pt.topological_ordering;
  result["direction"] = pt.direction;
  result["instance_name"] = pt.instance_name;
  result["is_end"] = pt.is_end();
  result["is_start"] = pt.is_start();
  result["has_gap"] = PrevBatchTokenGenerator::token_has_gap(token);

  return result;
}

// Encode a pagination token from its components
std::string encode_pagination_token_json(int64_t stream, int64_t topo,
                                          const std::string& dir,
                                          const std::string& instance) {
  PaginationToken pt;
  pt.stream_ordering = stream;
  pt.topological_ordering = topo;
  pt.direction = dir.empty() ? "b" : dir;
  pt.instance_name = instance.empty() ? "master" : instance;
  return pt.encode();
}

// Compare two pagination tokens
int compare_pagination_tokens(const std::string& token_a,
                               const std::string& token_b) {
  PaginationToken a = PaginationToken::decode(token_a);
  PaginationToken b = PaginationToken::decode(token_b);

  if (a.topological_ordering != b.topological_ordering) {
    return a.topological_ordering < b.topological_ordering ? -1 : 1;
  }

  if (a.stream_ordering != b.stream_ordering) {
    return a.stream_ordering < b.stream_ordering ? -1 : 1;
  }

  return 0;
}

// ============================================================================
// 25. EVENT LOOKUP BY POSITION
// ============================================================================

json get_event_at_position(DatabasePool& db,
                            const std::string& room_id,
                            int64_t position) {
  auto rows = db.execute("event_at_position",
    "SELECT json, is_redacted FROM events "
    "WHERE room_id='" + room_id + "' "
    "AND stream_ordering = " + std::to_string(position) +
    " AND outlier = 0 LIMIT 1");

  if (rows.empty()) {
    return json();
  }

  std::string ev_str = rows[0]["json"].value.value_or("{}");
  json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
  bool is_redacted = rows[0]["is_redacted"].value &&
                     *rows[0]["is_redacted"].value == "1";

  return process_event_for_response(ev, is_redacted);
}

// ============================================================================
// 26. TIMELINE BUILDER FOR NOTIFICATIONS
// ============================================================================

json build_notification_timeline_context(DatabasePool& db,
                                          const std::string& room_id,
                                          const std::string& event_id) {
  json context;

  // Get the event
  auto rows = db.execute("notif_event",
    "SELECT json, is_redacted, stream_ordering FROM events "
    "WHERE event_id='" + event_id + "' AND room_id='" + room_id + "'");

  if (rows.empty()) return context;

  std::string ev_str = rows[0]["json"].value.value_or("{}");
  json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
  bool is_redacted = rows[0]["is_redacted"].value &&
                     *rows[0]["is_redacted"].value == "1";
  int64_t stream = rows[0]["stream_ordering"].value ?
    std::stoll(*rows[0]["stream_ordering"].value) : 0;

  ev = process_event_for_response(ev, is_redacted);
  context["event"] = ev;

  // Get a few events before for context
  auto before_rows = db.execute("notif_before",
    "SELECT json, is_redacted, stream_ordering FROM events "
    "WHERE room_id='" + room_id + "' "
    "AND stream_ordering < " + std::to_string(stream) +
    " AND outlier = 0 "
    "ORDER BY stream_ordering DESC LIMIT 3");

  context["events_before"] = json::array();
  for (auto& row : before_rows) {
    std::string bev_str = row["json"].value.value_or("{}");
    json bev = json::parse(bev_str.empty() ? "{}" : bev_str);
    bool bre = row["is_redacted"].value && *row["is_redacted"].value == "1";
    context["events_before"].push_back(
      process_event_for_response(bev, bre));
  }

  // Get room name
  StateStore state(db);
  auto name_event = state.get_current_state_event(room_id, "m.room.name", "");
  if (name_event) {
    EventsStore evs(db);
    auto name_ev = evs.get_event(*name_event);
    if (name_ev) {
      context["room_name"] = (*name_ev)["content"].value("name", "");
    }
  }

  // Get sender display name
  std::string sender = ev.value("sender", "");
  if (!sender.empty()) {
    ProfileStore profiles(db);
    auto profile = profiles.get_profile(sender);
    if (profile && profile->display_name) {
      context["sender_display_name"] = *profile->display_name;
    }
  }

  return context;
}

// ============================================================================
// 27. BATCH EVENT RESOLUTION WITH RELATIONS
// ============================================================================

json resolve_events_with_relations(DatabasePool& db,
                                    const std::string& room_id,
                                    const std::vector<std::string>& event_ids,
                                    bool include_relations = true) {
  if (event_ids.empty()) {
    return json::array();
  }

  // Build event ID list
  std::string id_list;
  for (auto& eid : event_ids) {
    if (!id_list.empty()) id_list += ",";
    id_list += "'" + eid + "'";
  }

  auto rows = db.execute("resolve_events_with_rels",
    "SELECT e.json, e.is_redacted, e.stream_ordering, e.type, e.sender, "
    "e.event_id FROM events e "
    "WHERE e.event_id IN (" + id_list + ") AND e.room_id='" + room_id + "' "
    "ORDER BY e.stream_ordering DESC");

  json result = json::array();

  for (auto& row : rows) {
    std::string ev_str = row["json"].value.value_or("{}");
    json ev = json::parse(ev_str.empty() ? "{}" : ev_str);
    bool is_redacted = row["is_redacted"].value &&
                       *row["is_redacted"].value == "1";
    std::string eid = row["event_id"].value.value_or("");

    ev = process_event_for_response(ev, is_redacted);

    if (include_relations && !eid.empty()) {
      // Add relation aggregations
      auto agg_rows = db.execute("event_rels_resolve",
        "SELECT key, count FROM event_relation_aggregations "
        "WHERE event_id='" + eid + "' AND type='m.annotation'");

      if (!agg_rows.empty()) {
        json annotations = json::object();
        for (auto& ar : agg_rows) {
          std::string key = ar["key"].value.value_or("");
          int64_t count = ar["count"].value ?
            std::stoll(*ar["count"].value) : 0;
          annotations[key] = count;
        }
        ev["unsigned"]["m.relations"] = json::object();
        ev["unsigned"]["m.relations"]["m.annotation"] = annotations;
      }
    }

    result.push_back(ev);
  }

  return result;
}

// ============================================================================
// 28. EDITED MESSAGE TIMELINE RESOLVER
// ============================================================================

json resolve_edited_messages_in_timeline(DatabasePool& db,
                                          const std::string& room_id,
                                          const std::vector<json>& timeline) {
  json result = json::array();

  for (auto& ev : timeline) {
    std::string eid = ev.value("event_id", "");
    if (eid.empty()) {
      result.push_back(ev);
      continue;
    }

    // Check for m.replace relations (edits)
    auto edit_rows = db.execute("check_edits",
      "SELECT er.event_id, e.json FROM event_relations er "
      "JOIN events e ON er.event_id = e.event_id "
      "WHERE er.relates_to_id='" + eid + "' "
      "AND er.relation_type='m.replace' "
      "AND e.is_redacted=0 "
      "ORDER BY e.stream_ordering DESC LIMIT 1");

    if (!edit_rows.empty()) {
      std::string edit_json_str = edit_rows[0]["json"].value.value_or("{}");
      json edit_ev = json::parse(edit_json_str.empty() ? "{}" : edit_json_str);

      // Apply edit - replace content with m.new_content
      if (edit_ev.contains("content") &&
          edit_ev["content"].contains("m.new_content")) {
        json new_content = edit_ev["content"]["m.new_content"];

        // Merge new content into original event
        json edited_ev = ev;
        edited_ev["content"]["body"] = new_content.value("body", ev["content"].value("body", ""));
        if (new_content.contains("msgtype")) {
          edited_ev["content"]["msgtype"] = new_content["msgtype"];
        }
        if (new_content.contains("formatted_body")) {
          edited_ev["content"]["formatted_body"] = new_content["formatted_body"];
        }
        if (new_content.contains("format")) {
          edited_ev["content"]["format"] = new_content["format"];
        }

        // Add edit metadata
        edited_ev["unsigned"]["m.relations"] = json::object();
        edited_ev["unsigned"]["m.relations"]["m.replace"] = json::object();
        edited_ev["unsigned"]["m.relations"]["m.replace"]["event_id"] =
          edit_rows[0]["event_id"].value.value_or("");
        edited_ev["unsigned"]["m.relations"]["m.replace"]["origin_server_ts"] =
          edit_ev.value("origin_server_ts", 0);
        edited_ev["unsigned"]["m.relations"]["m.replace"]["sender"] =
          edit_ev.value("sender", "");

        result.push_back(edited_ev);
        continue;
      }
    }

    result.push_back(ev);
  }

  return result;
}

// ============================================================================
// END OF TIMELINE PAGINATION ENGINE
// ============================================================================

}  // namespace progressive::handlers
