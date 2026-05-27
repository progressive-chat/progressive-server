// initial_sync_visibility.cpp - Matrix Room Initial Sync, Event Visibility,
// and Limited Timeline Computation
//
// Implements: initial sync (full state), incremental sync (since token),
// timeline computation per room, state computation per room, ephemeral events
// (typing, receipts), account_data computation, presence computation,
// to_device messages, device_lists tracking, device_one_time_keys_count,
// lazy loading members in sync, room summary (heroes, joined_count,
// invited_count), unread notification counts, limited timeline flag,
// sync token generation/parsing, sync response size budgeting,
// sync timeout with long-poll.
//
// Based on Synapse: synapse/handlers/sync.py, synapse/handlers/initial_sync.py,
// synapse/visibility.py, synapse/handlers/presence.py,
// synapse/handlers/receipts.py, synapse/handlers/typing.py,
// synapse/handlers/device.py, synapse/handlers/e2e_keys.py,
// synapse/handlers/account_data.py, synapse/push/bulk_push_rule_evaluator.py,
// synapse/streams/config.py
//
// Target: 3500+ lines

#include "../json.hpp"
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/small_stores.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/receipts.hpp"
#include "progressive/storage/databases/main/filtering.hpp"
#include "progressive/storage/databases/main/event_federation.hpp"
#include "progressive/util/cache.hpp"
#include "progressive/util/time.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstring>
#include <ctime>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;

// ============================================================================
// Global utilities (shared across initial sync / visibility handlers)
// ============================================================================

static std::atomic<int64_t> g_sync_seq{1};
static std::atomic<int64_t> g_sync_stream_id{1};
static std::atomic<int64_t> g_sync_global_id{1};
static std::mutex g_sync_lock;
static std::mutex g_token_lock;
static std::mutex g_presence_lock;
static std::mutex g_ephemeral_lock;
static std::mutex g_account_data_lock;
static std::mutex g_to_device_lock;
static std::mutex g_device_list_lock;
static std::mutex g_lazy_load_lock;
static std::mutex g_notification_lock;
static std::mutex g_summary_lock;
static std::mutex g_budget_lock;
static std::mutex g_long_poll_lock;
static std::mutex g_state_comp_lock;
static std::mutex g_timeline_comp_lock;
static std::mutex g_visibility_lock;
static std::mutex g_filter_lock;

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static int64_t now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static int64_t now_us() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_id(const std::string& prefix) {
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(g_sync_seq.fetch_add(1));
}

static std::string gen_token(int len = 48) {
  static const char cs[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  static thread_local std::mt19937 rng(
    static_cast<unsigned>(now_us() + std::hash<std::thread::id>{}(std::this_thread::get_id())));
  std::uniform_int_distribution<> d(0, 63);
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

static void safe_set_if(json& obj, const std::string& key, const json& val) {
  if (!val.is_null()) obj[key] = val;
}

static std::string sql_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 4);
  for (char c : s) {
    if (c == '\'') out += "''"; else out += c;
  }
  return out;
}

static std::string extract_localpart(const std::string& user_id) {
  if (user_id.empty() || user_id[0] != '@') return user_id;
  auto pos = user_id.find(':');
  if (pos == std::string::npos) return user_id.substr(1);
  return user_id.substr(1, pos - 1);
}

static std::string extract_domain(const std::string& mxid) {
  auto pos = mxid.find(':');
  if (pos == std::string::npos) return "";
  return mxid.substr(pos + 1);
}

// ============================================================================
// StreamToken - Represents a sync stream position for pagination
// Equivalent to Synapse StreamToken (synapse/streams/config.py)
// ============================================================================

struct StreamToken {
  int64_t room_key{0};
  int64_t presence_key{0};
  int64_t account_data_key{0};
  int64_t to_device_key{0};
  int64_t device_list_key{0};
  int64_t device_one_time_key_count_key{0};
  int64_t groups_key{0};
  int64_t unread_notification_key{0};

  bool is_null() const {
    return room_key == 0 && presence_key == 0 &&
           account_data_key == 0 && to_device_key == 0 &&
           device_list_key == 0 && device_one_time_key_count_key == 0 &&
           groups_key == 0 && unread_notification_key == 0;
  }

  std::string serialize() const {
    std::ostringstream oss;
    oss << "s" << room_key << "_"
        << presence_key << "_"
        << account_data_key << "_"
        << to_device_key << "_"
        << device_list_key << "_"
        << device_one_time_key_count_key << "_"
        << groups_key << "_"
        << unread_notification_key;
    return oss.str();
  }

  static StreamToken deserialize(const std::string& token) {
    StreamToken st;
    if (token.empty() || token[0] != 's') return st;
    std::stringstream ss(token.substr(1));
    std::string part;
    int idx = 0;
    while (std::getline(ss, part, '_')) {
      int64_t val = 0;
      try { val = std::stoll(part); } catch (...) { val = 0; }
      switch (idx++) {
        case 0: st.room_key = val; break;
        case 1: st.presence_key = val; break;
        case 2: st.account_data_key = val; break;
        case 3: st.to_device_key = val; break;
        case 4: st.device_list_key = val; break;
        case 5: st.device_one_time_key_count_key = val; break;
        case 6: st.groups_key = val; break;
        case 7: st.unread_notification_key = val; break;
        default: break;
      }
    }
    return st;
  }

  json to_json() const {
    json j;
    j["room_key"] = room_key;
    j["presence_key"] = presence_key;
    j["account_data_key"] = account_data_key;
    j["to_device_key"] = to_device_key;
    j["device_list_key"] = device_list_key;
    j["device_one_time_key_count_key"] = device_one_time_key_count_key;
    j["groups_key"] = groups_key;
    j["unread_notification_key"] = unread_notification_key;
    return j;
  }
};

// ============================================================================
// SyncFilter - Parsed representation of a Matrix sync filter
// Equivalent to Synapse synapse/api/filtering.py Filter
// ============================================================================

struct SyncFilter {
  // Timeline limits
  int64_t timeline_limit{20};
  int64_t presence_limit{0};
  int64_t state_limit{0};
  int64_t account_data_limit{0};

  // Room filter
  std::optional<std::vector<std::string>> rooms;
  std::optional<std::vector<std::string>> not_rooms;

  // Event filter
  std::optional<std::vector<std::string>> types;
  std::optional<std::vector<std::string>> not_types;
  std::optional<std::vector<std::string>> senders;
  std::optional<std::vector<std::string>> not_senders;

  // Content filters
  bool contains_url{false};
  std::optional<std::string> search_term;
  std::optional<int64_t> min_depth;
  std::optional<int64_t> max_depth;

  // Lazy loading
  bool lazy_load_members{false};
  bool include_redundant_members{false};

  // Ephemeral
  bool include_ephemeral{true};
  bool include_typing{true};
  bool include_read_receipts{true};

  // State filtering
  bool include_state{true};
  std::optional<std::vector<std::string>> state_types;
  std::optional<std::vector<std::string>> state_not_types;

  // Unread counts
  bool unread_thread_notifications{false};

  // Unread notification filters
  bool include_unread_notifications{true};

  static SyncFilter from_json(const json& filter_def) {
    SyncFilter f;
    if (!filter_def.is_object()) return f;

    // Room filter
    if (filter_def.contains("room") && filter_def["room"].is_object()) {
      auto& rf = filter_def["room"];
      if (rf.contains("rooms") && rf["rooms"].is_array()) {
        f.rooms = std::vector<std::string>();
        for (const auto& r : rf["rooms"])
          if (r.is_string()) f.rooms->push_back(r.get<std::string>());
      }
      if (rf.contains("not_rooms") && rf["not_rooms"].is_array()) {
        f.not_rooms = std::vector<std::string>();
        for (const auto& r : rf["not_rooms"])
          if (r.is_string()) f.not_rooms->push_back(r.get<std::string>());
      }
      if (rf.contains("timeline") && rf["timeline"].is_object()) {
        auto& tl = rf["timeline"];
        if (tl.contains("limit")) f.timeline_limit = safe_int(tl, "limit", 20);
        if (tl.contains("lazy_load_members"))
          f.lazy_load_members = safe_bool(tl, "lazy_load_members", false);
        if (tl.contains("include_redundant_members"))
          f.include_redundant_members = safe_bool(tl, "include_redundant_members", false);
      }
      if (rf.contains("state") && rf["state"].is_object()) {
        auto& st = rf["state"];
        if (st.contains("limit")) f.state_limit = safe_int(st, "limit", 0);
        if (st.contains("lazy_load_members"))
          f.lazy_load_members = safe_bool(st, "lazy_load_members", false);
        if (st.contains("types") && st["types"].is_array()) {
          f.state_types = std::vector<std::string>();
          for (const auto& t : st["types"])
            if (t.is_string()) f.state_types->push_back(t.get<std::string>());
        }
        if (st.contains("not_types") && st["not_types"].is_array()) {
          f.state_not_types = std::vector<std::string>();
          for (const auto& t : st["not_types"])
            if (t.is_string()) f.state_not_types->push_back(t.get<std::string>());
        }
      }
      if (rf.contains("ephemeral") && rf["ephemeral"].is_object()) {
        auto& ep = rf["ephemeral"];
        if (ep.contains("include_typing"))
          f.include_typing = safe_bool(ep, "include_typing", true);
        if (ep.contains("include_read_receipts"))
          f.include_read_receipts = safe_bool(ep, "include_read_receipts", true);
      }
      if (rf.contains("unread_notifications") && rf["unread_notifications"].is_object()) {
        auto& un = rf["unread_notifications"];
        f.unread_thread_notifications = safe_bool(un, "unread_thread_notifications", false);
      }
    }

    // Global filters
    if (filter_def.contains("presence") && filter_def["presence"].is_object()) {
      f.presence_limit = safe_int(filter_def["presence"], "limit", 0);
      if (filter_def["presence"].contains("senders") && filter_def["presence"]["senders"].is_array()) {
        f.senders = std::vector<std::string>();
        for (const auto& s : filter_def["presence"]["senders"])
          if (s.is_string()) f.senders->push_back(s.get<std::string>());
      }
    }
    if (filter_def.contains("account_data") && filter_def["account_data"].is_object()) {
      f.account_data_limit = safe_int(filter_def["account_data"], "limit", 0);
      if (filter_def["account_data"].contains("types") && filter_def["account_data"]["types"].is_array()) {
        f.types = std::vector<std::string>();
        for (const auto& t : filter_def["account_data"]["types"])
          if (t.is_string()) f.types->push_back(t.get<std::string>());
      }
    }
    if (filter_def.contains("event_format")) {
      // Not implemented fully for v1; accept but ignore
    }
    if (filter_def.contains("event_fields") && filter_def["event_fields"].is_array()) {
      // Event field filtering not implemented in this version
    }

    return f;
  }

  bool should_include_room(const std::string& room_id) const {
    if (rooms) {
      return std::find(rooms->begin(), rooms->end(), room_id) != rooms->end();
    }
    if (not_rooms) {
      return std::find(not_rooms->begin(), not_rooms->end(), room_id) == not_rooms->end();
    }
    return true;
  }

  bool should_include_event_type(const std::string& event_type) const {
    if (types) {
      return std::find(types->begin(), types->end(), event_type) != types->end();
    }
    if (not_types) {
      return std::find(not_types->begin(), not_types->end(), event_type) == not_types->end();
    }
    return true;
  }

  bool should_include_sender(const std::string& sender) const {
    if (senders) {
      return std::find(senders->begin(), senders->end(), sender) != senders->end();
    }
    if (not_senders) {
      return std::find(not_senders->begin(), not_senders->end(), sender) == not_senders->end();
    }
    return true;
  }

  bool should_include_state_type(const std::string& state_type) const {
    if (state_types) {
      return std::find(state_types->begin(), state_types->end(), state_type) != state_types->end();
    }
    if (state_not_types) {
      return std::find(state_not_types->begin(), state_not_types->end(), state_type) == state_not_types->end();
    }
    return true;
  }
};

// ============================================================================
// VisibilityPolicy - Handles history visibility and event filtering
// Based on Synapse synapse/visibility.py
// ============================================================================

enum class HistoryVisibility {
  SHARED,
  INVITED,
  JOINED,
  WORLD_READABLE
};

static HistoryVisibility parse_history_visibility(const std::string& s) {
  if (s == "invited") return HistoryVisibility::INVITED;
  if (s == "joined") return HistoryVisibility::JOINED;
  if (s == "world_readable") return HistoryVisibility::WORLD_READABLE;
  return HistoryVisibility::SHARED; // default
}

static std::string history_visibility_to_string(HistoryVisibility hv) {
  switch (hv) {
    case HistoryVisibility::SHARED: return "shared";
    case HistoryVisibility::INVITED: return "invited";
    case HistoryVisibility::JOINED: return "joined";
    case HistoryVisibility::WORLD_READABLE: return "world_readable";
    default: return "shared";
  }
}

class VisibilityPolicy {
public:
  explicit VisibilityPolicy(DatabasePool& db) : db_(db) {}

  // Check if a user can see an event based on history visibility rules
  bool is_event_visible(const std::string& room_id,
                         const std::string& user_id,
                         const json& event,
                         const std::string& sender_membership,
                         const std::string& event_membership) {
    HistoryVisibility vis = get_history_visibility(room_id);

    // If world_readable, everyone can see
    if (vis == HistoryVisibility::WORLD_READABLE) return true;

    // Check sender's membership at time of event
    bool sender_was_joined = (sender_membership == "join");
    bool sender_was_invited = (sender_membership == "invite");

    // The viewer's membership at the time
    bool viewer_was_joined = (event_membership == "join");
    bool viewer_was_invited = (event_membership == "invite");

    switch (vis) {
      case HistoryVisibility::SHARED:
        // Everyone who has ever been in the room can see
        return sender_was_joined || sender_was_invited ||
               viewer_was_joined || viewer_was_invited;

      case HistoryVisibility::INVITED:
        // Events from join/invite members visible to anyone who was invited/joined
        if (sender_was_joined && (viewer_was_joined || viewer_was_invited))
          return true;
        // Members can see their own events
        {
          std::string event_sender = safe_str(event, "sender", "");
          if (event_sender == user_id) return true;
        }
        return false;

      case HistoryVisibility::JOINED:
        // Only those who were joined can see, and only from joined senders
        if (sender_was_joined && viewer_was_joined) return true;
        {
          std::string event_sender = safe_str(event, "sender", "");
          if (event_sender == user_id) return true;
        }
        return false;

      default:
        return true;
    }
  }

  // Check visibility of state events specifically
  bool filter_event_for_client(const std::string& room_id,
                                 const std::string& user_id,
                                 const json& event) {
    // State events are always visible if the user can see the room
    std::string ev_type = safe_str(event, "type", "");
    if (ev_type.empty()) return true;

    // Membership events are visible if the user is involved
    if (ev_type == "m.room.member") {
      std::string state_key = safe_str(event, "state_key", "");
      if (state_key == user_id) return true;
    }

    // For other events, apply history visibility
    HistoryVisibility vis = get_history_visibility(room_id);
    if (vis == HistoryVisibility::WORLD_READABLE) return true;

    return true; // default for now, further filtering in caller
  }

  HistoryVisibility get_history_visibility(const std::string& room_id) {
    {
      std::lock_guard<std::mutex> lock(vis_cache_mutex_);
      auto cached = vis_cache_.get(room_id);
      if (cached) return *cached;
    }

    HistoryVisibility vis = HistoryVisibility::SHARED;

    RowList rows = db_.execute(
        "get_history_visibility",
        "SELECT event_json FROM current_state_events "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND type='m.room.history_visibility' AND state_key=''");

    if (!rows.empty() && !rows[0].empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "event_json" && col.value && !col.value->empty()) {
          try {
            json ev = json::parse(*col.value);
            if (ev.contains("content") && ev["content"].contains("history_visibility")) {
              vis = parse_history_visibility(
                  ev["content"]["history_visibility"].get<std::string>());
            }
          } catch (...) {}
          break;
        }
      }
    }

    {
      std::lock_guard<std::mutex> lock(vis_cache_mutex_);
      vis_cache_.put(room_id, vis);
    }

    return vis;
  }

  // Determine if user was a member of the room at a given event
  std::string get_membership_at_event(const std::string& room_id,
                                        const std::string& user_id,
                                        const json& event) {
    std::string event_id = safe_str(event, "event_id", "");
    if (event_id.empty()) return "leave";

    // Check room_memberships table for membership at event stream ordering
    int64_t stream_ord = safe_int(event, "stream_ordering", 0);
    RowList rows = db_.execute(
        "get_membership_at_stream",
        "SELECT membership FROM room_memberships "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND user_id='" + sql_escape(user_id) +
        "' AND event_stream_ordering <= " + std::to_string(stream_ord) +
        " ORDER BY event_stream_ordering DESC LIMIT 1");

    if (!rows.empty() && !rows[0].empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "membership" && col.value) return *col.value;
      }
    }

    return "leave";
  }

  // Check if member events should be redacted (stripped of content)
  bool should_redact_member_event(const json& event, bool lazy_load) {
    if (!lazy_load) return false;
    // In lazy loading mode, membership events for non-hero members
    // are redacted to just have membership + displayname
    std::string ev_type = safe_str(event, "type", "");
    if (ev_type != "m.room.member") return false;
    return true;
  }

private:
  DatabasePool& db_;
  mutable std::mutex vis_cache_mutex_;
  util::LruCache<HistoryVisibility> vis_cache_{5000, 300};
};

// ============================================================================
// SyncRequest - Parsed sync request parameters
// ============================================================================

struct SyncRequest {
  std::string user_id;
  std::string device_id;
  std::string since;
  int timeout_ms{0};
  std::string filter;
  bool full_state{false};
  std::string set_presence;
  bool is_guest{false};
  std::string access_token;

  // Parsed filter
  SyncFilter parsed_filter;

  bool is_initial() const { return since.empty() || full_state; }
};

// ============================================================================
// RoomSyncResult - Per-room sync data container
// ============================================================================

struct RoomSyncResult {
  // Timeline section
  struct TimelineSection {
    json events;
    bool limited{false};
    std::string prev_batch;
  };

  TimelineSection timeline;
  json state;
  json ephemeral;
  json account_data;
  json unread_notifications;
  json summary;

  // Metadata flags
  bool has_new_events{false};
  bool has_state_changes{false};
  int64_t last_stream_ordering{0};
};

// ============================================================================
// EventVisibilityResult - Result of event visibility check
// ============================================================================

struct EventVisibilityResult {
  bool visible{true};
  bool should_redact{false};
  std::string reason;
};

// ============================================================================
// SyncBudget - Manages sync response size limits
// Equivalent to Synapse's response size budgeting in sync.py
// ============================================================================

class SyncBudget {
public:
  static constexpr int64_t DEFAULT_MAX_SYNC_SIZE = 10 * 1024 * 1024;   // 10 MB
  static constexpr int64_t DEFAULT_MAX_ROOM_SIZE = 2 * 1024 * 1024;    // 2 MB per room
  static constexpr int64_t DEFAULT_MAX_TIMELINE_EVENTS = 100;
  static constexpr int64_t DEFAULT_MAX_STATE_EVENTS = 500;

  SyncBudget(int64_t max_size = DEFAULT_MAX_SYNC_SIZE)
      : max_response_size_(max_size),
        current_size_(0),
        room_count_(0),
        timeline_event_count_(0),
        state_event_count_(0),
        budget_exceeded_(false) {}

  // Check if adding an event would exceed budget
  bool can_add_event(int64_t estimated_bytes = 1024) {
    if (budget_exceeded_) return false;
    return (current_size_ + estimated_bytes) <= max_response_size_;
  }

  bool can_add_timeline_event() {
    return timeline_event_count_ < DEFAULT_MAX_TIMELINE_EVENTS && !budget_exceeded_;
  }

  bool can_add_state_event() {
    return state_event_count_ < DEFAULT_MAX_STATE_EVENTS && !budget_exceeded_;
  }

  // Record an added event
  void record_event(int64_t actual_bytes) {
    current_size_ += actual_bytes;
    timeline_event_count_++;
    if (current_size_ >= max_response_size_) {
      budget_exceeded_ = true;
    }
  }

  void record_state_event(int64_t actual_bytes) {
    current_size_ += actual_bytes;
    state_event_count_++;
    if (current_size_ >= max_response_size_) {
      budget_exceeded_ = true;
    }
  }

  void record_room() { room_count_++; }

  // Estimate size of a JSON object in bytes
  static int64_t estimate_json_size(const json& j) {
    try {
      return static_cast<int64_t>(j.dump().size());
    } catch (...) {
      return 512;
    }
  }

  bool is_budget_exceeded() const { return budget_exceeded_; }
  int64_t current_size() const { return current_size_; }
  int64_t room_count() const { return room_count_; }
  int64_t timeline_event_count() const { return timeline_event_count_; }
  int64_t state_event_count() const { return state_event_count_; }
  int64_t max_response_size() const { return max_response_size_; }

  void reset() {
    current_size_ = 0;
    room_count_ = 0;
    timeline_event_count_ = 0;
    state_event_count_ = 0;
    budget_exceeded_ = false;
  }

private:
  int64_t max_response_size_;
  int64_t current_size_;
  int64_t room_count_;
  int64_t timeline_event_count_;
  int64_t state_event_count_;
  bool budget_exceeded_;
};

// ============================================================================
// SyncLongPollManager - Long poll wait for new sync data
// Equivalent to Synapse's long poll / timeout mechanism in sync.py
// ============================================================================

class SyncLongPollManager {
public:
  SyncLongPollManager() : next_notify_id_(0) {}

  // Wait for new data or timeout
  bool wait_for_updates(const std::string& user_id,
                          int64_t timeout_ms,
                          int64_t since_stream_id) {
    if (timeout_ms <= 0) return false;

    int64_t notify_id;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      notify_id = next_notify_id_++;
      waiters_[user_id] = {notify_id, since_stream_id, false};
    }

    std::unique_lock<std::mutex> lock(mutex_);
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);

    bool got_update = cv_.wait_until(lock, deadline, [&]() {
      auto it = waiters_.find(user_id);
      if (it == waiters_.end()) return true;
      return it->second.notified;
    });

    // Clean up waiter
    waiters_.erase(user_id);

    return got_update;
  }

  // Notify a user that new data is available
  void notify_user(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = waiters_.find(user_id);
    if (it != waiters_.end()) {
      it->second.notified = true;
    }
    cv_.notify_all();
  }

  // Wake all waiters
  void notify_all() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& w : waiters_) {
      w.second.notified = true;
    }
    cv_.notify_all();
  }

private:
  struct Waiter {
    int64_t notify_id;
    int64_t since_stream_id;
    bool notified;
  };

  std::mutex mutex_;
  std::condition_variable cv_;
  int64_t next_notify_id_;
  std::unordered_map<std::string, Waiter> waiters_;
};

// ============================================================================
// SyncTokenManager - Sync token generation and parsing
// Equivalent to Synapse synapse/handlers/sync.py token management
// ============================================================================

class SyncTokenManager {
public:
  explicit SyncTokenManager(DatabasePool& db) : db_(db) {}

  // Generate a next_batch token for the current stream position
  std::string generate_next_batch_token() {
    std::lock_guard<std::mutex> lock(token_mutex_);

    StreamToken token;
    token.room_key = get_max_stream_id("events");
    token.presence_key = get_max_stream_id("presence_stream");
    token.account_data_key = get_max_stream_id("account_data");
    token.to_device_key = get_max_stream_id("device_inbox");
    token.device_list_key = get_max_stream_id("device_lists_stream");
    token.device_one_time_key_count_key = get_max_stream_id("e2e_one_time_keys_json");
    token.groups_key = 0; // groups not implemented yet
    token.unread_notification_key = get_max_stream_id("event_push_summary");

    return token.serialize();
  }

  // Parse a since token
  StreamToken parse_since_token(const std::string& since) {
    return StreamToken::deserialize(since);
  }

  // Get current token
  StreamToken get_current_token() {
    StreamToken token;
    token.room_key = get_max_stream_id("events");
    token.presence_key = get_max_stream_id("presence_stream");
    token.account_data_key = get_max_stream_id("account_data");
    token.to_device_key = get_max_stream_id("device_inbox");
    token.device_list_key = get_max_stream_id("device_lists_stream");
    token.device_one_time_key_count_key = get_max_stream_id("e2e_one_time_keys_json");
    token.groups_key = 0;
    token.unread_notification_key = get_max_stream_id("event_push_summary");
    return token;
  }

  // Get events since a given room stream position
  RowList get_events_since(int64_t since_room_key, int limit = 50) {
    return db_.execute(
        "get_events_since",
        "SELECT event_id, room_id, type, state_key, content, "
        "stream_ordering, topological_ordering, sender, origin_server_ts "
        "FROM events WHERE stream_ordering > " + std::to_string(since_room_key) +
        " ORDER BY stream_ordering ASC LIMIT " + std::to_string(limit));
  }

  // Get state events changed since a given room stream position
  RowList get_state_events_since(const std::string& room_id, int64_t since_room_key) {
    return db_.execute(
        "get_state_events_since",
        "SELECT event_id, type, state_key, content, stream_ordering, sender "
        "FROM current_state_events "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND stream_ordering > " + std::to_string(since_room_key) +
        " ORDER BY stream_ordering ASC");
  }

  // Get all current state for a room (initial sync)
  RowList get_current_state(const std::string& room_id) {
    return db_.execute(
        "get_current_state",
        "SELECT event_id, type, state_key, content, stream_ordering, sender "
        "FROM current_state_events "
        "WHERE room_id='" + sql_escape(room_id) +
        "' ORDER BY type, state_key");
  }

  // Get all states for rooms the user is in (initial sync)
  RowList get_current_state_for_user_rooms(const std::string& user_id) {
    return db_.execute(
        "get_current_state_for_user_rooms",
        "SELECT cse.room_id, cse.event_id, cse.type, cse.state_key, "
        "cse.content, cse.stream_ordering, cse.sender "
        "FROM current_state_events cse "
        "INNER JOIN room_memberships rm "
        "ON cse.room_id = rm.room_id AND rm.user_id='" + sql_escape(user_id) +
        "' AND rm.membership = 'join' "
        "ORDER BY cse.room_id, cse.type, cse.state_key");
  }

private:
  int64_t get_max_stream_id(const std::string& table) {
    RowList rows = db_.execute(
        "get_max_stream_id",
        "SELECT COALESCE(MAX(stream_ordering), 0) as max_id FROM " + table);
    if (!rows.empty() && !rows[0].empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "max_id" && col.value) {
          try { return std::stoll(*col.value); } catch (...) { return 0; }
        }
      }
    }
    return 0;
  }

  DatabasePool& db_;
  std::mutex token_mutex_;
};

// ============================================================================
// TimelineComputer - Computes room timeline for sync responses
// ============================================================================

class TimelineComputer {
public:
  TimelineComputer(DatabasePool& db) : db_(db) {}

  // Compute timeline for a room since a given stream position
  RoomSyncResult::TimelineSection compute_timeline(
      const std::string& room_id,
      const std::string& user_id,
      int64_t since_room_key,
      bool full_state,
      const SyncFilter& filter,
      SyncBudget& budget) {

    RoomSyncResult::TimelineSection result;
    result.limited = false;
    result.events = json::array();

    int64_t limit = filter.timeline_limit > 0 ? filter.timeline_limit : 20;

    if (full_state) {
      // Initial sync: get most recent events up to limit
      result = load_recent_timeline(room_id, user_id, limit, filter, budget);
      // For initial sync, timeline is always limited
      result.limited = true;
    } else {
      // Incremental sync: get events since token
      result = load_incremental_timeline(room_id, user_id, since_room_key,
                                          limit, filter, budget);
      // limited flag set if we had to truncate or if there are gaps
    }

    // Generate prev_batch token
    if (!result.events.empty()) {
      json first_ev = result.events[0];
      int64_t first_stream = safe_int(first_ev, "stream_ordering", 0);
      result.prev_batch = "t" + std::to_string(first_stream - 1) + "_0";
    } else {
      result.prev_batch = "t0_0";
    }

    return result;
  }

  // Load incremental timeline (events since token)
  RoomSyncResult::TimelineSection load_incremental_timeline(
      const std::string& room_id,
      const std::string& user_id,
      int64_t since_room_key,
      int64_t limit,
      const SyncFilter& filter,
      SyncBudget& budget) {

    RoomSyncResult::TimelineSection result;
    result.events = json::array();

    RowList rows = db_.execute(
        "load_incremental_timeline",
        "SELECT event_id, type, state_key, content, sender, "
        "origin_server_ts, stream_ordering, topological_ordering, "
        "outlier, rejected_reason "
        "FROM events "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND stream_ordering > " + std::to_string(since_room_key) +
        " AND outlier = 0 "
        "ORDER BY topological_ordering ASC, stream_ordering ASC "
        "LIMIT " + std::to_string(limit + 10));

    int64_t count = 0;
    bool need_limit_flag = false;

    for (const auto& row : rows) {
      if (count >= limit || !budget.can_add_timeline_event()) {
        need_limit_flag = true;
        break;
      }

      json event = row_to_event(row);
      if (event.is_null()) continue;

      // Apply event type/sender filtering
      std::string ev_type = safe_str(event, "type", "");
      std::string sender = safe_str(event, "sender", "");
      if (!filter.should_include_event_type(ev_type)) continue;
      if (!filter.should_include_sender(sender)) continue;

      if (!filter_event(event, filter)) continue;

      int64_t ev_size = SyncBudget::estimate_json_size(event);
      budget.record_event(ev_size);
      result.events.push_back(event);
      count++;
    }

    result.limited = need_limit_flag;
    return result;
  }

  // Load recent timeline (initial sync or limited=true)
  RoomSyncResult::TimelineSection load_recent_timeline(
      const std::string& room_id,
      const std::string& user_id,
      int64_t limit,
      const SyncFilter& filter,
      SyncBudget& budget) {

    RoomSyncResult::TimelineSection result;
    result.events = json::array();

    RowList rows = db_.execute(
        "load_recent_timeline",
        "SELECT event_id, type, state_key, content, sender, "
        "origin_server_ts, stream_ordering, topological_ordering, "
        "outlier, rejected_reason "
        "FROM events "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND outlier = 0 "
        "ORDER BY topological_ordering DESC, stream_ordering DESC "
        "LIMIT " + std::to_string(limit + 10));

    // Reverse to get chronological order
    std::vector<json> events_vec;
    for (auto it = rows.rbegin(); it != rows.rend(); ++it) {
      json event = row_to_event(*it);
      if (event.is_null()) continue;

      std::string ev_type = safe_str(event, "type", "");
      std::string sender = safe_str(event, "sender", "");
      if (!filter.should_include_event_type(ev_type)) continue;
      if (!filter.should_include_sender(sender)) continue;

      if (!filter_event(event, filter)) continue;
      events_vec.push_back(event);
    }

    int64_t count = 0;
    bool need_limit_flag = false;
    for (const auto& ev : events_vec) {
      if (count >= limit || !budget.can_add_timeline_event()) {
        need_limit_flag = true;
        break;
      }
      int64_t ev_size = SyncBudget::estimate_json_size(ev);
      budget.record_event(ev_size);
      result.events.push_back(ev);
      count++;
    }

    result.limited = need_limit_flag;
    return result;
  }

  // Apply filter to individual events
  bool filter_event(const json& event, const SyncFilter& filter) {
    if (filter.contains_url) {
      std::string content_str = safe_str(event, "content", "");
      if (content_str.find("http://") == std::string::npos &&
          content_str.find("https://") == std::string::npos)
        return false;
    }
    if (filter.search_term) {
      std::string body = safe_str(event, "content", "");
      // Check content.body if present
      try {
        if (event.contains("content") && event["content"].contains("body")) {
          body = event["content"]["body"].get<std::string>();
        }
      } catch (...) {}
      if (body.find(*filter.search_term) == std::string::npos)
        return false;
    }
    return true;
  }

  // Convert a database row to a JSON event
  json row_to_event(const Row& row) {
    json event;
    std::string event_id, ev_type, state_key, content_str, sender;
    int64_t origin_server_ts = 0, stream_ord = 0, topo_ord = 0;
    int64_t outlier = 0;

    for (const auto& col : row) {
      if (col.name == "event_id" && col.value) event_id = *col.value;
      else if (col.name == "type" && col.value) ev_type = *col.value;
      else if (col.name == "state_key" && col.value) state_key = *col.value;
      else if (col.name == "content" && col.value) content_str = *col.value;
      else if (col.name == "sender" && col.value) sender = *col.value;
      else if (col.name == "origin_server_ts" && col.value) {
        try { origin_server_ts = std::stoll(*col.value); } catch (...) {}
      }
      else if (col.name == "stream_ordering" && col.value) {
        try { stream_ord = std::stoll(*col.value); } catch (...) {}
      }
      else if (col.name == "topological_ordering" && col.value) {
        try { topo_ord = std::stoll(*col.value); } catch (...) {}
      }
      else if (col.name == "outlier" && col.value) {
        try { outlier = std::stoll(*col.value); } catch (...) {}
      }
    }

    if (event_id.empty()) return json();

    event["event_id"] = event_id;
    event["type"] = ev_type;
    if (!state_key.empty()) event["state_key"] = state_key;
    event["sender"] = sender;
    event["origin_server_ts"] = origin_server_ts;
    event["stream_ordering"] = stream_ord;
    event["topological_ordering"] = topo_ord;
    event["outlier"] = (outlier != 0);

    // Parse content JSON
    try {
      if (!content_str.empty()) {
        event["content"] = json::parse(content_str);
      } else {
        event["content"] = json::object();
      }
    } catch (...) {
      event["content"] = json::object();
    }

    // Add unsigned
    event["unsigned"] = json::object();

    return event;
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// StateComputer - Computes room state for sync responses
// ============================================================================

class StateComputer {
public:
  StateComputer(DatabasePool& db) : db_(db) {}

  // Compute state for a room in sync response
  json compute_state(const std::string& room_id,
                      const std::string& user_id,
                      int64_t since_room_key,
                      bool full_state,
                      const SyncFilter& filter,
                      SyncBudget& budget) {

    json state_events = json::array();

    if (full_state) {
      // Initial sync: return entire current state
      RowList rows = db_.execute(
          "get_current_state_full",
          "SELECT event_id, type, state_key, content, sender, "
          "origin_server_ts, stream_ordering "
          "FROM current_state_events "
          "WHERE room_id='" + sql_escape(room_id) +
          "' ORDER BY type, state_key");

      for (const auto& row : rows) {
        if (!budget.can_add_state_event()) break;

        json event = row_to_state_event(row);
        if (event.is_null()) continue;

        std::string ev_type = safe_str(event, "type", "");
        if (!filter.should_include_state_type(ev_type)) continue;

        // Apply lazy loading to member events
        if (ev_type == "m.room.member" && filter.lazy_load_members) {
          event = redact_member_event_for_lazy_load(event, user_id);
        }

        int64_t ev_size = SyncBudget::estimate_json_size(event);
        budget.record_state_event(ev_size);
        state_events.push_back(event);
      }
    } else {
      // Incremental sync: return only state that has changed
      RowList rows = db_.execute(
          "get_state_delta",
          "SELECT cse.event_id, cse.type, cse.state_key, cse.content, "
          "cse.sender, cse.origin_server_ts, cse.stream_ordering "
          "FROM current_state_events cse "
          "WHERE cse.room_id='" + sql_escape(room_id) +
          "' AND cse.stream_ordering > " + std::to_string(since_room_key) +
          " ORDER BY cse.type, cse.state_key");

      for (const auto& row : rows) {
        if (!budget.can_add_state_event()) break;

        json event = row_to_state_event(row);
        if (event.is_null()) continue;

        std::string ev_type = safe_str(event, "type", "");
        if (!filter.should_include_state_type(ev_type)) continue;

        if (ev_type == "m.room.member" && filter.lazy_load_members) {
          event = redact_member_event_for_lazy_load(event, user_id);
        }

        int64_t ev_size = SyncBudget::estimate_json_size(event);
        budget.record_state_event(ev_size);
        state_events.push_back(event);
      }

      // Also check for state that comes from timeline events
      // (state events in the gap between since_token and now)
      RowList timeline_state = db_.execute(
          "get_timeline_state_delta",
          "SELECT event_id, type, state_key, content, sender, "
          "origin_server_ts, stream_ordering "
          "FROM events "
          "WHERE room_id='" + sql_escape(room_id) +
          "' AND stream_ordering > " + std::to_string(since_room_key) +
          " AND state_key IS NOT NULL AND state_key != '' "
          "ORDER BY stream_ordering ASC");

      for (const auto& row : timeline_state) {
        if (!budget.can_add_state_event()) break;

        json event = row_to_state_event(row);
        if (event.is_null()) continue;

        std::string ev_type = safe_str(event, "type", "");
        if (!filter.should_include_state_type(ev_type)) continue;

        // Skip if already in state_events (dedup by type+state_key)
        bool dup = false;
        for (const auto& existing : state_events) {
          if (safe_str(existing, "type", "") == ev_type &&
              safe_str(existing, "state_key", "") == safe_str(event, "state_key", "")) {
            dup = true;
            break;
          }
        }
        if (dup) continue;

        if (ev_type == "m.room.member" && filter.lazy_load_members) {
          event = redact_member_event_for_lazy_load(event, user_id);
        }

        int64_t ev_size = SyncBudget::estimate_json_size(event);
        budget.record_state_event(ev_size);
        state_events.push_back(event);
      }
    }

    return state_events;
  }

  // Redact member events for lazy loading (only keep membership and displayname)
  json redact_member_event_for_lazy_load(const json& event,
                                            const std::string& user_id) {
    json redacted = event;
    json new_content = json::object();

    if (event.contains("content")) {
      if (event["content"].contains("membership"))
        new_content["membership"] = event["content"]["membership"];
      if (event["content"].contains("displayname"))
        new_content["displayname"] = event["content"]["displayname"];
      if (event["content"].contains("avatar_url"))
        new_content["avatar_url"] = event["content"]["avatar_url"];
    }

    redacted["content"] = new_content;
    return redacted;
  }

  // Convert a database row to a state event JSON
  json row_to_state_event(const Row& row) {
    json event;
    std::string event_id, ev_type, state_key, content_str, sender;
    int64_t origin_server_ts = 0, stream_ord = 0;

    for (const auto& col : row) {
      if (col.name == "event_id" && col.value) event_id = *col.value;
      else if (col.name == "type" && col.value) ev_type = *col.value;
      else if (col.name == "state_key" && col.value) state_key = *col.value;
      else if (col.name == "content" && col.value) content_str = *col.value;
      else if (col.name == "sender" && col.value) sender = *col.value;
      else if (col.name == "origin_server_ts" && col.value) {
        try { origin_server_ts = std::stoll(*col.value); } catch (...) {}
      }
      else if (col.name == "stream_ordering" && col.value) {
        try { stream_ord = std::stoll(*col.value); } catch (...) {}
      }
    }

    if (event_id.empty()) return json();

    event["event_id"] = event_id;
    event["type"] = ev_type;
    if (!state_key.empty()) event["state_key"] = state_key;
    event["sender"] = sender;
    event["origin_server_ts"] = origin_server_ts;
    event["stream_ordering"] = stream_ord;

    try {
      if (!content_str.empty()) {
        event["content"] = json::parse(content_str);
      } else {
        event["content"] = json::object();
      }
    } catch (...) {
      event["content"] = json::object();
    }

    event["unsigned"] = json::object();
    return event;
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// EphemeralComputer - Computes ephemeral events (typing, receipts)
// ============================================================================

class EphemeralComputer {
public:
  EphemeralComputer(DatabasePool& db) : db_(db) {}

  // Compute ephemeral events for a room
  json compute_ephemeral(const std::string& room_id,
                           const std::string& user_id,
                           const SyncFilter& filter) {

    json ephemeral = json::array();

    if (!filter.include_ephemeral) return ephemeral;

    // Typing notifications
    if (filter.include_typing) {
      json typing = get_typing_notification(room_id);
      if (!typing.is_null()) ephemeral.push_back(typing);
    }

    // Read receipts
    if (filter.include_read_receipts) {
      json receipts = get_read_receipts(room_id);
      if (!receipts.is_null()) ephemeral.push_back(receipts);
    }

    return ephemeral;
  }

  // Get current typing notification for room
  json get_typing_notification(const std::string& room_id) {
    RowList rows = db_.execute(
        "get_typing",
        "SELECT user_id, timeout_ms FROM typing "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND (last_typed_ts + timeout_ms) > " + std::to_string(now_ms()));

    if (rows.empty()) return json();

    json typing;
    typing["type"] = "m.typing";
    json content;
    json user_ids = json::array();

    for (const auto& row : rows) {
      for (const auto& col : row) {
        if (col.name == "user_id" && col.value) {
          user_ids.push_back(*col.value);
        }
      }
    }

    content["user_ids"] = user_ids;
    typing["content"] = content;

    return typing;
  }

  // Get read receipts for room
  json get_read_receipts(const std::string& room_id) {
    RowList rows = db_.execute(
        "get_receipts",
        "SELECT user_id, event_id, receipt_type, data, "
        "thread_id, stream_ordering "
        "FROM receipts_linearized "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND receipt_type = 'm.read' "
        "ORDER BY stream_ordering DESC");

    if (rows.empty()) return json();

    json receipt;
    receipt["type"] = "m.receipt";
    json content;

    for (const auto& row : rows) {
      std::string ev_id, uid, data_str, thread_id;

      for (const auto& col : row) {
        if (col.name == "event_id" && col.value) ev_id = *col.value;
        else if (col.name == "user_id" && col.value) uid = *col.value;
        else if (col.name == "data" && col.value) data_str = *col.value;
        else if (col.name == "thread_id" && col.value) thread_id = *col.value;
      }

      if (ev_id.empty() || uid.empty()) continue;

      try {
        json data_json = json::parse(data_str);
        int64_t ts = safe_int(data_json, "ts", 0);

        if (!content.contains(ev_id)) {
          content[ev_id] = json::object();
          content[ev_id]["m.read"] = json::object();
        }

        content[ev_id]["m.read"][uid] = json::object();
        content[ev_id]["m.read"][uid]["ts"] = ts;

        if (!thread_id.empty()) {
          content[ev_id]["m.read"][uid]["thread_id"] = thread_id;
        }
      } catch (...) {}
    }

    receipt["content"] = content;
    return receipt;
  }

  // Compute typing for multiple rooms
  std::map<std::string, json> compute_typing_for_rooms(
      const std::vector<std::string>& room_ids,
      const std::string& user_id,
      const SyncFilter& filter) {

    std::map<std::string, json> result;
    if (!filter.include_typing) return result;

    for (const auto& room_id : room_ids) {
      json typing = get_typing_notification(room_id);
      if (!typing.is_null()) {
        result[room_id] = typing;
      }
    }

    return result;
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// AccountDataComputer - Computes account data for sync responses
// ============================================================================

class AccountDataComputer {
public:
  AccountDataComputer(DatabasePool& db) : db_(db) {}

  // Compute global account data
  json compute_global_account_data(const std::string& user_id,
                                     int64_t since_account_data_key,
                                     const SyncFilter& filter) {
    json result = json::array();

    RowList rows;
    if (since_account_data_key > 0) {
      rows = db_.execute(
          "get_global_account_data_since",
          "SELECT type, content, stream_ordering "
          "FROM account_data "
          "WHERE user_id='" + sql_escape(user_id) +
          "' AND room_id IS NULL "
          "AND stream_ordering > " + std::to_string(since_account_data_key) +
          " ORDER BY stream_ordering ASC");
    } else {
      rows = db_.execute(
          "get_global_account_data_all",
          "SELECT type, content, stream_ordering "
          "FROM account_data "
          "WHERE user_id='" + sql_escape(user_id) +
          "' AND room_id IS NULL "
          "ORDER BY stream_ordering ASC");
    }

    for (const auto& row : rows) {
      std::string ev_type, content_str;
      int64_t stream_ord = 0;

      for (const auto& col : row) {
        if (col.name == "type" && col.value) ev_type = *col.value;
        else if (col.name == "content" && col.value) content_str = *col.value;
        else if (col.name == "stream_ordering" && col.value) {
          try { stream_ord = std::stoll(*col.value); } catch (...) {}
        }
      }

      if (filter.types) {
        bool found = false;
        for (const auto& t : *filter.types) {
          if (t == ev_type) { found = true; break; }
        }
        if (!found) continue;
      }

      json item;
      item["type"] = ev_type;
      try {
        if (!content_str.empty()) {
          item["content"] = json::parse(content_str);
        } else {
          item["content"] = json::object();
        }
      } catch (...) {
        item["content"] = json::object();
      }

      result.push_back(item);
    }

    return result;
  }

  // Compute room-specific account data
  json compute_room_account_data(const std::string& room_id,
                                   const std::string& user_id,
                                   int64_t since_account_data_key) {
    json result = json::array();

    RowList rows;
    if (since_account_data_key > 0) {
      rows = db_.execute(
          "get_room_account_data_since",
          "SELECT type, content "
          "FROM account_data "
          "WHERE user_id='" + sql_escape(user_id) +
          "' AND room_id='" + sql_escape(room_id) +
          "' AND stream_ordering > " + std::to_string(since_account_data_key) +
          " ORDER BY stream_ordering ASC");
    } else {
      rows = db_.execute(
          "get_room_account_data_all",
          "SELECT type, content "
          "FROM account_data "
          "WHERE user_id='" + sql_escape(user_id) +
          "' AND room_id='" + sql_escape(room_id) +
          "' ORDER BY stream_ordering ASC");
    }

    for (const auto& row : rows) {
      std::string ev_type, content_str;

      for (const auto& col : row) {
        if (col.name == "type" && col.value) ev_type = *col.value;
        else if (col.name == "content" && col.value) content_str = *col.value;
      }

      json item;
      item["type"] = ev_type;
      try {
        if (!content_str.empty()) {
          item["content"] = json::parse(content_str);
        } else {
          item["content"] = json::object();
        }
      } catch (...) {
        item["content"] = json::object();
      }

      result.push_back(item);
    }

    return result;
  }

  // Bulk compute room account data for joined rooms
  std::map<std::string, json> compute_room_account_data_bulk(
      const std::vector<std::string>& room_ids,
      const std::string& user_id,
      int64_t since_account_data_key) {

    std::map<std::string, json> result;

    for (const auto& room_id : room_ids) {
      json data = compute_room_account_data(room_id, user_id, since_account_data_key);
      if (!data.empty()) {
        result[room_id] = data;
      }
    }

    return result;
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// PresenceComputer - Computes presence events for sync responses
// ============================================================================

class PresenceComputer {
public:
  PresenceComputer(DatabasePool& db) : db_(db) {}

  // Get presence events since a given stream position
  json get_presence_events(const std::string& user_id,
                             int64_t since_presence_key,
                             const SyncFilter& filter,
                             int64_t& next_presence_key) {

    json events = json::array();

    RowList rows;
    if (since_presence_key > 0) {
      rows = db_.execute(
          "get_presence_since",
          "SELECT user_id, state, status_msg, last_active_ts, "
          "last_federation_update_ts, last_user_sync_ts, stream_ordering "
          "FROM presence_stream "
          "WHERE stream_ordering > " + std::to_string(since_presence_key) +
          " ORDER BY stream_ordering ASC");
    } else {
      rows = db_.execute(
          "get_presence_all",
          "SELECT user_id, state, status_msg, last_active_ts, "
          "last_federation_update_ts, last_user_sync_ts, stream_ordering "
          "FROM presence_stream "
          "ORDER BY stream_ordering ASC");
    }

    next_presence_key = since_presence_key;

    for (const auto& row : rows) {
      std::string uid, state, status_msg;
      int64_t last_active_ts = 0;
      int64_t last_user_sync_ts = 0;
      int64_t stream_ord = 0;

      for (const auto& col : row) {
        if (col.name == "user_id" && col.value) uid = *col.value;
        else if (col.name == "state" && col.value) state = *col.value;
        else if (col.name == "status_msg" && col.value) status_msg = *col.value;
        else if (col.name == "last_active_ts" && col.value) {
          try { last_active_ts = std::stoll(*col.value); } catch (...) {}
        }
        else if (col.name == "last_user_sync_ts" && col.value) {
          try { last_user_sync_ts = std::stoll(*col.value); } catch (...) {}
        }
        else if (col.name == "stream_ordering" && col.value) {
          try { stream_ord = std::stoll(*col.value); } catch (...) {}
        }
      }

      if (!filter.should_include_sender(uid)) continue;

      if (filter.presence_limit > 0 &&
          static_cast<int64_t>(events.size()) >= filter.presence_limit)
        break;

      json presence;
      presence["type"] = "m.presence";
      presence["sender"] = uid;
      json content;
      content["presence"] = state;
      if (!status_msg.empty()) content["status_msg"] = status_msg;
      content["last_active_ago"] = (now_ms() / 1000) - (last_active_ts / 1000);
      content["currently_active"] =
        ((now_ms() - last_user_sync_ts) < 120000);

      presence["content"] = content;

      events.push_back(presence);

      if (stream_ord > next_presence_key) {
        next_presence_key = stream_ord;
      }
    }

    return events;
  }

  // Get single user's presence (for direct lookups)
  json get_user_presence(const std::string& user_id) {
    RowList rows = db_.execute(
        "get_user_presence",
        "SELECT state, status_msg, last_active_ts, last_user_sync_ts "
        "FROM presence_stream "
        "WHERE user_id='" + sql_escape(user_id) +
        "' ORDER BY stream_ordering DESC LIMIT 1");

    if (rows.empty()) return json();

    std::string state, status_msg;
    int64_t last_active_ts = 0;
    int64_t last_user_sync_ts = 0;

    for (const auto& col : rows[0]) {
      if (col.name == "state" && col.value) state = *col.value;
      else if (col.name == "status_msg" && col.value) status_msg = *col.value;
      else if (col.name == "last_active_ts" && col.value) {
        try { last_active_ts = std::stoll(*col.value); } catch (...) {}
      }
      else if (col.name == "last_user_sync_ts" && col.value) {
        try { last_user_sync_ts = std::stoll(*col.value); } catch (...) {}
      }
    }

    json presence;
    presence["presence"] = state;
    if (!status_msg.empty()) presence["status_msg"] = status_msg;
    presence["last_active_ago"] = (now_ms() / 1000) - (last_active_ts / 1000);
    presence["currently_active"] = ((now_ms() - last_user_sync_ts) < 120000);

    return presence;
  }

  // Get presence for a list of users
  json get_presence_for_users(const std::vector<std::string>& user_ids) {
    json result = json::array();

    for (const auto& uid : user_ids) {
      json p = get_user_presence(uid);
      if (!p.is_null()) {
        json entry;
        entry["type"] = "m.presence";
        entry["sender"] = uid;
        entry["content"] = p;
        result.push_back(entry);
      }
    }

    return result;
  }

  // Update user presence
  void update_presence(const std::string& user_id,
                         const std::string& state,
                         const std::string& status_msg = "") {
    std::lock_guard<std::mutex> lock(g_presence_lock);

    int64_t now = now_ms();
    int64_t stream_id = g_sync_stream_id.fetch_add(1);

    db_.execute(
        "update_presence",
        "INSERT INTO presence_stream "
        "(user_id, state, status_msg, last_active_ts, "
        "last_federation_update_ts, last_user_sync_ts, stream_ordering) "
        "VALUES ('" + sql_escape(user_id) + "', '" + sql_escape(state) +
        "', '" + sql_escape(status_msg) + "', " + std::to_string(now) +
        ", " + std::to_string(now) + ", " + std::to_string(now) +
        ", " + std::to_string(stream_id) + ")");
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// ToDeviceComputer - Computes to-device messages for sync responses
// ============================================================================

class ToDeviceComputer {
public:
  ToDeviceComputer(DatabasePool& db) : db_(db) {}

  // Get to-device messages for a user/device since a token
  json get_to_device_messages(const std::string& user_id,
                                const std::string& device_id,
                                int64_t since_to_device_key) {

    json messages = json::array();

    RowList rows;
    if (since_to_device_key > 0) {
      rows = db_.execute(
          "get_to_device_since",
          "SELECT message_id, sender, type, content, stream_ordering "
          "FROM device_inbox "
          "WHERE user_id='" + sql_escape(user_id) +
          "' AND device_id='" + sql_escape(device_id) +
          "' AND stream_ordering > " + std::to_string(since_to_device_key) +
          " ORDER BY stream_ordering ASC");
    } else {
      rows = db_.execute(
          "get_to_device_all",
          "SELECT message_id, sender, type, content, stream_ordering "
          "FROM device_inbox "
          "WHERE user_id='" + sql_escape(user_id) +
          "' AND device_id='" + sql_escape(device_id) +
          "' ORDER BY stream_ordering ASC");
    }

    for (const auto& row : rows) {
      std::string sender, ev_type, content_str;
      int64_t stream_ord = 0;

      for (const auto& col : row) {
        if (col.name == "sender" && col.value) sender = *col.value;
        else if (col.name == "type" && col.value) ev_type = *col.value;
        else if (col.name == "content" && col.value) content_str = *col.value;
        else if (col.name == "stream_ordering" && col.value) {
          try { stream_ord = std::stoll(*col.value); } catch (...) {}
        }
      }

      json msg;
      msg["sender"] = sender;
      msg["type"] = ev_type;
      try {
        if (!content_str.empty()) {
          msg["content"] = json::parse(content_str);
        } else {
          msg["content"] = json::object();
        }
      } catch (...) {
        msg["content"] = json::object();
      }

      messages.push_back(msg);
    }

    return messages;
  }

  // Store a to-device message for delivery
  void store_to_device_message(const std::string& user_id,
                                 const std::string& device_id,
                                 const std::string& sender,
                                 const std::string& msg_type,
                                 const json& content) {
    std::lock_guard<std::mutex> lock(g_to_device_lock);

    int64_t stream_id = g_sync_stream_id.fetch_add(1);
    std::string message_id = gen_id("tdm");

    std::string content_str;
    try { content_str = content.dump(); } catch (...) { content_str = "{}"; }

    db_.execute(
        "store_to_device",
        "INSERT INTO device_inbox "
        "(user_id, device_id, message_id, sender, type, content, stream_ordering) "
        "VALUES ('" + sql_escape(user_id) + "', '" + sql_escape(device_id) +
        "', '" + sql_escape(message_id) + "', '" + sql_escape(sender) +
        "', '" + sql_escape(msg_type) + "', '" + sql_escape(content_str) +
        "', " + std::to_string(stream_id) + ")");
  }

  // Delete delivered to-device messages
  void delete_delivered_messages(const std::string& user_id,
                                   const std::string& device_id,
                                   int64_t up_to_stream_id) {
    std::lock_guard<std::mutex> lock(g_to_device_lock);

    db_.execute(
        "delete_to_device",
        "DELETE FROM device_inbox "
        "WHERE user_id='" + sql_escape(user_id) +
        "' AND device_id='" + sql_escape(device_id) +
        "' AND stream_ordering <= " + std::to_string(up_to_stream_id));
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// DeviceListComputer - Tracks device list changes for sync
// ============================================================================

class DeviceListComputer {
public:
  DeviceListComputer(DatabasePool& db) : db_(db) {}

  // Get users whose device lists have changed
  std::vector<std::string> get_changed_device_list_users(
      const std::string& user_id,
      int64_t since_device_list_key) {

    std::vector<std::string> changed;

    RowList rows;
    if (since_device_list_key > 0) {
      rows = db_.execute(
          "get_changed_device_lists",
          "SELECT DISTINCT user_id "
          "FROM device_lists_stream "
          "WHERE stream_id > " + std::to_string(since_device_list_key) +
          " ORDER BY stream_id ASC");
    } else {
      rows = db_.execute(
          "get_all_changed_device_lists",
          "SELECT DISTINCT user_id "
          "FROM device_lists_stream "
          "ORDER BY stream_id ASC");
    }

    for (const auto& row : rows) {
      for (const auto& col : row) {
        if (col.name == "user_id" && col.value) {
          changed.push_back(*col.value);
        }
      }
    }

    return changed;
  }

  // Get users who have left (all devices deleted)
  std::vector<std::string> get_left_device_list_users(
      const std::string& user_id,
      int64_t since_device_list_key) {

    std::vector<std::string> left;

    RowList rows;
    if (since_device_list_key > 0) {
      rows = db_.execute(
          "get_left_device_lists",
          "SELECT DISTINCT user_id "
          "FROM device_lists_outbound_pokes "
          "WHERE stream_id > " + std::to_string(since_device_list_key) +
          " AND left = 1 "
          "ORDER BY stream_id ASC");
    } else {
      rows = db_.execute(
          "get_all_left_device_lists",
          "SELECT DISTINCT user_id "
          "FROM device_lists_outbound_pokes "
          "WHERE left = 1 "
          "ORDER BY stream_id ASC");
    }

    for (const auto& row : rows) {
      for (const auto& col : row) {
        if (col.name == "user_id" && col.value) {
          left.push_back(*col.value);
        }
      }
    }

    return left;
  }

  // Mark a user's device list as changed
  void mark_device_list_changed(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(g_device_list_lock);

    int64_t stream_id = g_sync_stream_id.fetch_add(1);

    db_.execute(
        "mark_device_list_changed",
        "INSERT INTO device_lists_stream (user_id, stream_id) "
        "VALUES ('" + sql_escape(user_id) + "', " +
        std::to_string(stream_id) + ")");
  }

  // Get device one-time key counts for a user
  json get_device_one_time_keys_count(const std::string& user_id,
                                        const std::string& device_id) {
    json result = json::object();

    RowList rows = db_.execute(
        "get_one_time_key_counts",
        "SELECT key_type, key_count "
        "FROM e2e_one_time_keys_json "
        "WHERE user_id='" + sql_escape(user_id) +
        "' AND device_id='" + sql_escape(device_id) + "'");

    for (const auto& row : rows) {
      std::string key_type;
      int64_t key_count = 0;

      for (const auto& col : row) {
        if (col.name == "key_type" && col.value) key_type = *col.value;
        else if (col.name == "key_count" && col.value) {
          try { key_count = std::stoll(*col.value); } catch (...) {}
        }
      }

      if (!key_type.empty()) {
        result[key_type] = key_count;
      }
    }

    // If no device_id specified, aggregate across all devices
    if (device_id.empty()) {
      result = get_aggregate_one_time_key_counts(user_id);
    }

    return result;
  }

  // Aggregate one-time key counts across all user's devices
  json get_aggregate_one_time_key_counts(const std::string& user_id) {
    json result = json::object();

    RowList rows = db_.execute(
        "get_aggregate_one_time_keys",
        "SELECT key_type, SUM(COALESCE(key_count, 0)) as total "
        "FROM e2e_one_time_keys_json "
        "WHERE user_id='" + sql_escape(user_id) +
        "' GROUP BY key_type");

    for (const auto& row : rows) {
      std::string key_type;
      int64_t total = 0;

      for (const auto& col : row) {
        if (col.name == "key_type" && col.value) key_type = *col.value;
        else if (col.name == "total" && col.value) {
          try { total = std::stoll(*col.value); } catch (...) {}
        }
      }

      if (!key_type.empty()) {
        result[key_type] = total;
      }
    }

    return result;
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// LazyLoadingManager - Manages lazy loading of room members in sync
// ============================================================================

class LazyLoadingManager {
public:
  LazyLoadingManager(DatabasePool& db) : db_(db), max_heroes_(5) {}

  // Determine if lazy loading should be applied for a room
  bool should_lazy_load(const std::string& room_id,
                           const SyncFilter& filter) {
    if (!filter.lazy_load_members) return false;

    // Check number of joined members
    int64_t member_count = get_joined_member_count(room_id);
    if (member_count <= max_heroes_ + 5) return false; // small rooms: full sync

    return true;
  }

  // Compute lazy load summary (heroes) for a room
  json compute_lazy_load_summary(const std::string& room_id,
                                   const std::string& viewer_user_id,
                                   std::set<std::string>& included_user_ids) {

    json summary = json::object();

    // Get heroes
    std::vector<HeroInfo> heroes = get_heroes(room_id, viewer_user_id, 5);

    json hero_array = json::array();
    for (const auto& hero : heroes) {
      json hj;
      hj["user_id"] = hero.user_id;
      if (!hero.display_name.empty()) hj["display_name"] = hero.display_name;
      if (!hero.avatar_url.empty()) hj["avatar_url"] = hero.avatar_url;
      hero_array.push_back(hj);
      included_user_ids.insert(hero.user_id);
    }

    summary["heroes"] = hero_array;
    summary["summary_sent"] = true;

    return summary;
  }

  // Check if a member has been sent in the sync response
  bool has_sent_member(const std::string& user_id,
                         const std::string& member) {
    std::lock_guard<std::mutex> lock(g_lazy_load_lock);
    auto it = sent_members_.find(std::string(user_id));
    if (it == sent_members_.end()) return false;
    return it->second.find(std::string(member)) != it->second.end();
  }

  // Mark a member as sent in the sync response
  void mark_member_sent(const std::string& user_id,
                          const std::string& member) {
    std::lock_guard<std::mutex> lock(g_lazy_load_lock);
    sent_members_[std::string(user_id)].insert(std::string(member));
  }

  // Clear sent members for a user (e.g., on new session)
  void clear_sent_members(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(g_lazy_load_lock);
    sent_members_.erase(std::string(user_id));
  }

  // Filter member events for lazy loading
  json filter_member_events_for_lazy_load(const json& state_events,
                                            const std::string& user_id,
                                            const std::set<std::string>& included_users) {
    json filtered = json::array();

    for (const auto& ev : state_events) {
      std::string ev_type = safe_str(ev, "type", "");
      if (ev_type != "m.room.member") {
        filtered.push_back(ev);
        continue;
      }

      std::string state_key = safe_str(ev, "state_key", "");
      // Always include the requester's own membership
      if (state_key == user_id) {
        filtered.push_back(ev);
        continue;
      }

      // Include hero members
      if (included_users.count(state_key)) {
        filtered.push_back(ev);
        continue;
      }

      // For other members, redact to just membership
      json redacted = ev;
      json new_content = json::object();
      if (ev.contains("content")) {
        if (ev["content"].contains("membership"))
          new_content["membership"] = ev["content"]["membership"];
        if (ev["content"].contains("displayname"))
          new_content["displayname"] = ev["content"]["displayname"];
        if (ev["content"].contains("avatar_url"))
          new_content["avatar_url"] = ev["content"]["avatar_url"];
      }
      redacted["content"] = new_content;
      filtered.push_back(redacted);
    }

    return filtered;
  }

private:
  struct HeroInfo {
    std::string user_id;
    std::string display_name;
    std::string avatar_url;
    int64_t join_order{0};
    int64_t last_active_ts{0};
  };

  int64_t get_joined_member_count(const std::string& room_id) {
    RowList rows = db_.execute(
        "get_joined_count",
        "SELECT COUNT(*) as cnt FROM room_memberships "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND membership='join'");

    if (!rows.empty() && !rows[0].empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "cnt" && col.value) {
          try { return std::stoll(*col.value); } catch (...) { return 0; }
        }
      }
    }
    return 0;
  }

  std::vector<HeroInfo> get_heroes(const std::string& room_id,
                                      const std::string& viewer_user_id,
                                      int limit) {
    std::vector<HeroInfo> heroes;

    // Get joined members, ordered by event stream ordering (join order)
    RowList rows = db_.execute(
        "get_heroes_from_members",
        "SELECT rm.user_id, rm.display_name, rm.avatar_url, "
        "rm.event_stream_ordering "
        "FROM room_memberships rm "
        "WHERE rm.room_id='" + sql_escape(room_id) +
        "' AND rm.membership='join' "
        "ORDER BY rm.event_stream_ordering ASC "
        "LIMIT " + std::to_string(limit + 10));

    for (const auto& row : rows) {
      HeroInfo hero;

      for (const auto& col : row) {
        if (col.name == "user_id" && col.value) hero.user_id = *col.value;
        else if (col.name == "display_name" && col.value) hero.display_name = *col.value;
        else if (col.name == "avatar_url" && col.value) hero.avatar_url = *col.value;
        else if (col.name == "event_stream_ordering" && col.value) {
          try { hero.join_order = std::stoll(*col.value); } catch (...) {}
        }
      }

      // Skip the viewer
      if (hero.user_id == viewer_user_id) continue;

      // Check presence for last_active_ts
      RowList presence = db_.execute(
          "get_hero_presence",
          "SELECT last_active_ts FROM presence_stream "
          "WHERE user_id='" + sql_escape(hero.user_id) +
          "' ORDER BY stream_ordering DESC LIMIT 1");

      if (!presence.empty() && !presence[0].empty()) {
        for (const auto& col : presence[0]) {
          if (col.name == "last_active_ts" && col.value) {
            try { hero.last_active_ts = std::stoll(*col.value); } catch (...) {}
          }
        }
      }

      // If no display name, extract from user_id
      if (hero.display_name.empty()) {
        hero.display_name = extract_localpart(hero.user_id);
      }

      heroes.push_back(hero);

      if (static_cast<int>(heroes.size()) >= limit) break;
    }

    // Sort: active users first, then by join order
    std::sort(heroes.begin(), heroes.end(),
              [](const HeroInfo& a, const HeroInfo& b) {
                // Active users come first
                bool a_active = a.last_active_ts > 0;
                bool b_active = b.last_active_ts > 0;
                if (a_active != b_active) return a_active;
                if (a_active && b_active) return a.last_active_ts > b.last_active_ts;
                // Then join order
                return a.join_order < b.join_order;
              });

    if (static_cast<int>(heroes.size()) > limit) {
      heroes.resize(limit);
    }

    return heroes;
  }

  DatabasePool& db_;
  int max_heroes_;
  std::map<std::string, std::set<std::string>> sent_members_;
};

// ============================================================================
// RoomSummaryComputer - Computes room summaries for sync responses
// ============================================================================

class RoomSummaryComputer {
public:
  RoomSummaryComputer(DatabasePool& db) : db_(db) {}

  // Compute room summary for sync response (heroes, counts)
  json compute_summary(const std::string& room_id,
                         const std::string& viewer_user_id) {
    json summary = json::object();

    // Get joined member count
    int64_t joined_count = get_member_count(room_id, "join");
    summary["m.joined_member_count"] = joined_count;

    // Get invited member count
    int64_t invited_count = get_member_count(room_id, "invite");
    summary["m.invited_member_count"] = invited_count;

    // Get heroes (top 5 active members)
    std::vector<HeroEntry> heroes = get_heroes_for_room(room_id, viewer_user_id);

    if (!heroes.empty()) {
      json hero_arr = json::array();
      for (const auto& h : heroes) {
        json hj;
        hj["user_id"] = h.user_id;
        if (!h.display_name.empty()) hj["display_name"] = h.display_name;
        if (!h.avatar_url.empty()) hj["avatar_url"] = h.avatar_url;
        hero_arr.push_back(hj);
      }
      summary["m.heroes"] = hero_arr;
    }

    return summary;
  }

  // Compute summaries for multiple rooms
  std::map<std::string, json> compute_summaries_bulk(
      const std::vector<std::string>& room_ids,
      const std::string& viewer_user_id) {

    std::map<std::string, json> results;

    for (const auto& room_id : room_ids) {
      results[room_id] = compute_summary(room_id, viewer_user_id);
    }

    return results;
  }

  // Get room name from state
  std::string get_room_name(const std::string& room_id) {
    RowList rows = db_.execute(
        "get_room_name",
        "SELECT event_json FROM current_state_events "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND type='m.room.name' AND state_key='' "
        "LIMIT 1");

    if (!rows.empty() && !rows[0].empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "event_json" && col.value && !col.value->empty()) {
          try {
            json ev = json::parse(*col.value);
            if (ev.contains("content") && ev["content"].contains("name")) {
              return ev["content"]["name"].get<std::string>();
            }
          } catch (...) {}
        }
      }
    }
    return "";
  }

  // Generate a display name for a room (from state or from heroes)
  std::string generate_room_display_name(const std::string& room_id,
                                            const std::string& viewer_user_id) {
    std::string name = get_room_name(room_id);
    if (!name.empty()) return name;

    // Fall back to canonical alias
    RowList alias_rows = db_.execute(
        "get_canonical_alias",
        "SELECT event_json FROM current_state_events "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND type='m.room.canonical_alias' AND state_key='' "
        "LIMIT 1");

    if (!alias_rows.empty() && !alias_rows[0].empty()) {
      for (const auto& col : alias_rows[0]) {
        if (col.name == "event_json" && col.value && !col.value->empty()) {
          try {
            json ev = json::parse(*col.value);
            if (ev.contains("content") && ev["content"].contains("alias")) {
              return ev["content"]["alias"].get<std::string>();
            }
          } catch (...) {}
        }
      }
    }

    // Fall back to heroes/other members
    std::vector<HeroEntry> heroes = get_heroes_for_room(room_id, viewer_user_id);
    if (heroes.size() == 1) {
      return heroes[0].display_name.empty() ?
             extract_localpart(heroes[0].user_id) : heroes[0].display_name;
    } else if (heroes.size() == 2) {
      std::string n1 = heroes[0].display_name.empty() ?
                       extract_localpart(heroes[0].user_id) : heroes[0].display_name;
      std::string n2 = heroes[1].display_name.empty() ?
                       extract_localpart(heroes[1].user_id) : heroes[1].display_name;
      return n1 + " and " + n2;
    } else if (heroes.size() >= 3) {
      std::string n1 = heroes[0].display_name.empty() ?
                       extract_localpart(heroes[0].user_id) : heroes[0].display_name;
      return n1 + " and " + std::to_string(heroes.size() - 1) + " others";
    }

    return "Empty Room";
  }

private:
  struct HeroEntry {
    std::string user_id;
    std::string display_name;
    std::string avatar_url;
    int64_t join_order{0};
    int64_t last_active_ts{0};
  };

  int64_t get_member_count(const std::string& room_id,
                            const std::string& membership) {
    RowList rows = db_.execute(
        "get_member_count_" + membership,
        "SELECT COUNT(*) as cnt FROM room_memberships "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND membership='" + sql_escape(membership) + "'");

    if (!rows.empty() && !rows[0].empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "cnt" && col.value) {
          try { return std::stoll(*col.value); } catch (...) { return 0; }
        }
      }
    }
    return 0;
  }

  std::vector<HeroEntry> get_heroes_for_room(const std::string& room_id,
                                                const std::string& viewer_user_id) {
    std::vector<HeroEntry> heroes;

    RowList rows = db_.execute(
        "get_heroes_for_summary",
        "SELECT rm.user_id, p.display_name, p.avatar_url, "
        "rm.event_stream_ordering "
        "FROM room_memberships rm "
        "LEFT JOIN profiles p ON rm.user_id = p.user_id "
        "WHERE rm.room_id='" + sql_escape(room_id) +
        "' AND rm.membership='join' "
        "ORDER BY rm.event_stream_ordering ASC "
        "LIMIT 20");

    for (const auto& row : rows) {
      HeroEntry hero;

      for (const auto& col : row) {
        if (col.name == "user_id" && col.value) hero.user_id = *col.value;
        else if (col.name == "display_name" && col.value) hero.display_name = *col.value;
        else if (col.name == "avatar_url" && col.value) hero.avatar_url = *col.value;
        else if (col.name == "event_stream_ordering" && col.value) {
          try { hero.join_order = std::stoll(*col.value); } catch (...) {}
        }
      }

      // Skip viewer
      if (hero.user_id == viewer_user_id) continue;

      if (hero.display_name.empty()) {
        hero.display_name = extract_localpart(hero.user_id);
      }

      heroes.push_back(hero);
    }

    // Limit to 5 heroes
    if (heroes.size() > 5) {
      heroes.resize(5);
    }

    return heroes;
  }

  DatabasePool& db_;
};

// ============================================================================
// UnreadNotificationComputer - Computes unread notification counts
// ============================================================================

class UnreadNotificationComputer {
public:
  UnreadNotificationComputer(DatabasePool& db) : db_(db) {}

  // Compute unread notifications for a room
  json compute_unread_notifications(const std::string& room_id,
                                      const std::string& user_id) {
    json unread;
    unread["highlight_count"] = get_highlight_count(room_id, user_id);
    unread["notification_count"] = get_notification_count(room_id, user_id);
    return unread;
  }

  // Compute unread notifications for all joined rooms
  std::map<std::string, json> compute_unread_for_rooms(
      const std::vector<std::string>& room_ids,
      const std::string& user_id) {

    std::map<std::string, json> results;

    for (const auto& room_id : room_ids) {
      json unread = compute_unread_notifications(room_id, user_id);
      if (unread["highlight_count"].get<int>() > 0 ||
          unread["notification_count"].get<int>() > 0) {
        results[room_id] = unread;
      }
    }

    return results;
  }

  // Get unread notification count for a room
  int get_notification_count(const std::string& room_id,
                                const std::string& user_id) {
    // Based on event_push_summary table
    RowList rows = db_.execute(
        "get_notification_count",
        "SELECT notif_count FROM event_push_summary "
        "WHERE user_id='" + sql_escape(user_id) +
        "' AND room_id='" + sql_escape(room_id) +
        "' LIMIT 1");

    if (!rows.empty() && !rows[0].empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "notif_count" && col.value) {
          try { return std::stoi(*col.value); } catch (...) { return 0; }
        }
      }
    }

    return 0;
  }

  // Get highlight count for a room
  int get_highlight_count(const std::string& room_id,
                             const std::string& user_id) {
    RowList rows = db_.execute(
        "get_highlight_count",
        "SELECT highlight_count FROM event_push_summary "
        "WHERE user_id='" + sql_escape(user_id) +
        "' AND room_id='" + sql_escape(room_id) +
        "' LIMIT 1");

    if (!rows.empty() && !rows[0].empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "highlight_count" && col.value) {
          try { return std::stoi(*col.value); } catch (...) { return 0; }
        }
      }
    }

    // Fallback: count from event_push_actions
    return get_highlight_count_from_actions(room_id, user_id);
  }

  // Get highlight count from push actions table
  int get_highlight_count_from_actions(const std::string& room_id,
                                          const std::string& user_id) {
    RowList rows = db_.execute(
        "get_highlight_from_actions",
        "SELECT COUNT(*) as cnt FROM event_push_actions "
        "WHERE user_id='" + sql_escape(user_id) +
        "' AND room_id='" + sql_escape(room_id) +
        "' AND highlight = 1");

    if (!rows.empty() && !rows[0].empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "cnt" && col.value) {
          try { return std::stoi(*col.value); } catch (...) { return 0; }
        }
      }
    }

    return 0;
  }

  // Clear notifications for a room (marking as read)
  void clear_notifications(const std::string& room_id,
                             const std::string& user_id) {
    std::lock_guard<std::mutex> lock(g_notification_lock);

    db_.execute(
        "clear_notifications",
        "UPDATE event_push_summary "
        "SET notif_count = 0, highlight_count = 0 "
        "WHERE user_id='" + sql_escape(user_id) +
        "' AND room_id='" + sql_escape(room_id) + "'");
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// SyncResponseBuilder - Builds the complete sync response JSON
// ============================================================================

class SyncResponseBuilder {
public:
  SyncResponseBuilder(DatabasePool& db)
      : db_(db),
        token_manager_(db),
        timeline_computer_(db),
        state_computer_(db),
        ephemeral_computer_(db),
        account_data_computer_(db),
        presence_computer_(db),
        to_device_computer_(db),
        device_list_computer_(db),
        lazy_loading_(db),
        summary_computer_(db),
        unread_computer_(db) {}

  // Build a complete sync response
  json build_sync_response(const SyncRequest& request) {
    json response;

    // Determine if initial sync
    bool is_initial = request.is_initial();
    StreamToken since_token;
    if (!request.since.empty()) {
      since_token = token_manager_.parse_since_token(request.since);
    }

    // Build next_batch token
    response["next_batch"] = token_manager_.generate_next_batch_token();

    // Initialize response structure
    json rooms;
    rooms["join"] = json::object();
    rooms["invite"] = json::object();
    rooms["leave"] = json::object();
    response["rooms"] = rooms;

    response["presence"] = json::object();
    response["presence"]["events"] = json::array();

    response["account_data"] = json::object();
    response["account_data"]["events"] = json::array();

    response["to_device"] = json::object();
    response["to_device"]["events"] = json::array();

    response["device_lists"] = json::object();
    response["device_lists"]["changed"] = json::array();
    response["device_lists"]["left"] = json::array();

    response["device_one_time_keys_count"] = json::object();

    // Initialize sync budget
    SyncBudget budget;
    int64_t sync_start = now_ms();

    // =====================================================================
    // Get rooms for user
    // =====================================================================
    RowList user_rooms;
    if (request.full_state) {
      user_rooms = db_.execute(
          "get_user_rooms_full",
          "SELECT room_id, membership, event_stream_ordering, forgotten "
          "FROM room_memberships "
          "WHERE user_id='" + sql_escape(request.user_id) +
          "' ORDER BY event_stream_ordering DESC");
    } else if (!request.since.empty()) {
      user_rooms = db_.execute(
          "get_user_rooms_since",
          "SELECT room_id, membership, event_stream_ordering, forgotten "
          "FROM room_memberships "
          "WHERE user_id='" + sql_escape(request.user_id) +
          "' AND event_stream_ordering > " + std::to_string(since_token.room_key) +
          " ORDER BY event_stream_ordering DESC");
    } else {
      user_rooms = db_.execute(
          "get_user_rooms_all",
          "SELECT room_id, membership, event_stream_ordering, forgotten "
          "FROM room_memberships "
          "WHERE user_id='" + sql_escape(request.user_id) +
          "' ORDER BY event_stream_ordering DESC");
    }

    // Process each room
    std::vector<std::string> joined_rooms;
    std::vector<std::string> invited_rooms;
    std::vector<std::string> left_rooms;

    for (const auto& row : user_rooms) {
      std::string room_id, membership;
      bool forgotten = false;

      for (const auto& col : row) {
        if (col.name == "room_id" && col.value) room_id = *col.value;
        else if (col.name == "membership" && col.value) membership = *col.value;
        else if (col.name == "forgotten" && col.value) {
          try { forgotten = (std::stoi(*col.value) != 0); } catch (...) {}
        }
      }

      if (room_id.empty()) continue;

      // Apply room filter
      if (!request.parsed_filter.should_include_room(room_id)) continue;

      // Skip forgotten rooms
      if (forgotten && membership == "leave") continue;

      if (membership == "join") {
        joined_rooms.push_back(room_id);
      } else if (membership == "invite") {
        invited_rooms.push_back(room_id);
      } else if (membership == "leave" || membership == "ban") {
        left_rooms.push_back(room_id);
      }
    }

    // =====================================================================
    // Compute joined rooms sync data
    // =====================================================================
    for (const auto& room_id : joined_rooms) {
      if (!budget.can_add_event()) continue;
      budget.record_room();

      json room_data;

      // Timeline
      RoomSyncResult::TimelineSection timeline =
          timeline_computer_.compute_timeline(
              room_id, request.user_id, since_token.room_key,
              request.full_state, request.parsed_filter, budget);

      json timeline_json;
      timeline_json["events"] = timeline.events;
      timeline_json["limited"] = timeline.limited;
      if (!timeline.prev_batch.empty()) {
        timeline_json["prev_batch"] = timeline.prev_batch;
      }
      room_data["timeline"] = timeline_json;

      // State
      json state = state_computer_.compute_state(
          room_id, request.user_id, since_token.room_key,
          request.full_state, request.parsed_filter, budget);

      // Apply lazy loading to state if needed
      if (request.parsed_filter.lazy_load_members &&
          lazy_loading_.should_lazy_load(room_id, request.parsed_filter)) {
        std::set<std::string> included_users;
        json ll_summary = lazy_loading_.compute_lazy_load_summary(
            room_id, request.user_id, included_users);
        room_data["summary"] = ll_summary;
        state = lazy_loading_.filter_member_events_for_lazy_load(
            state, request.user_id, included_users);
      }

      room_data["state"] = json::object();
      room_data["state"]["events"] = state;

      // Ephemeral
      json ephemeral = ephemeral_computer_.compute_ephemeral(
          room_id, request.user_id, request.parsed_filter);
      room_data["ephemeral"] = json::object();
      room_data["ephemeral"]["events"] = ephemeral;

      // Account data
      json acct_data = account_data_computer_.compute_room_account_data(
          room_id, request.user_id, since_token.account_data_key);
      room_data["account_data"] = json::object();
      room_data["account_data"]["events"] = acct_data;

      // Unread notifications
      json unread = unread_computer_.compute_unread_notifications(
          room_id, request.user_id);
      room_data["unread_notifications"] = unread;

      // Summary
      json summary = summary_computer_.compute_summary(
          room_id, request.user_id);
      room_data["summary"] = summary;

      response["rooms"]["join"][room_id] = room_data;
    }

    // =====================================================================
    // Compute invited rooms sync data
    // =====================================================================
    for (const auto& room_id : invited_rooms) {
      if (!budget.can_add_event()) continue;
      budget.record_room();

      json room_data;

      // For invites, include the invite state (stripped)
      json invite_state;
      json invite_events = json::array();

      RowList invite_rows = db_.execute(
          "get_invite_state",
          "SELECT event_id, type, state_key, content, sender "
          "FROM current_state_events "
          "WHERE room_id='" + sql_escape(room_id) +
          "' AND type='m.room.member' AND state_key='" +
          sql_escape(request.user_id) + "' "
          "LIMIT 1");

      for (const auto& row : invite_rows) {
        json event;
        std::string content_str;

        for (const auto& col : row) {
          if (col.name == "event_id" && col.value) event["event_id"] = *col.value;
          else if (col.name == "type" && col.value) event["type"] = *col.value;
          else if (col.name == "state_key" && col.value) event["state_key"] = *col.value;
          else if (col.name == "content" && col.value) content_str = *col.value;
          else if (col.name == "sender" && col.value) event["sender"] = *col.value;
        }

        try {
          if (!content_str.empty()) {
            event["content"] = json::parse(content_str);
          } else {
            event["content"] = json::object();
          }
        } catch (...) {
          event["content"] = json::object();
        }

        invite_events.push_back(event);
      }

      invite_state["events"] = invite_events;
      room_data["invite_state"] = invite_state;

      response["rooms"]["invite"][room_id] = room_data;
    }

    // =====================================================================
    // Compute left rooms sync data
    // =====================================================================
    for (const auto& room_id : left_rooms) {
      if (!budget.can_add_event()) continue;
      budget.record_room();

      json room_data;

      // For left rooms, include limited timeline and state
      json timeline_json;
      timeline_json["events"] = json::array();
      timeline_json["limited"] = false;

      // Include the last few events for context
      RowList leave_timeline = db_.execute(
          "get_leave_timeline",
          "SELECT event_id, type, state_key, content, sender, "
          "stream_ordering, origin_server_ts "
          "FROM events "
          "WHERE room_id='" + sql_escape(room_id) +
          "' AND outlier = 0 "
          "ORDER BY topological_ordering DESC, stream_ordering DESC "
          "LIMIT 5");

      for (auto it = leave_timeline.rbegin(); it != leave_timeline.rend(); ++it) {
        json event;
        std::string content_str;
        int64_t stream_ord = 0, origin_ts = 0;

        for (const auto& col : *it) {
          if (col.name == "event_id" && col.value) event["event_id"] = *col.value;
          else if (col.name == "type" && col.value) event["type"] = *col.value;
          else if (col.name == "content" && col.value) content_str = *col.value;
          else if (col.name == "sender" && col.value) event["sender"] = *col.value;
          else if (col.name == "stream_ordering" && col.value) {
            try { stream_ord = std::stoll(*col.value); } catch (...) {}
          }
          else if (col.name == "origin_server_ts" && col.value) {
            try { origin_ts = std::stoll(*col.value); } catch (...) {}
          }
        }

        event["stream_ordering"] = stream_ord;
        event["origin_server_ts"] = origin_ts;
        try {
          if (!content_str.empty()) {
            event["content"] = json::parse(content_str);
          } else {
            event["content"] = json::object();
          }
        } catch (...) { event["content"] = json::object(); }

        timeline_json["events"].push_back(event);
      }

      room_data["timeline"] = timeline_json;

      // State (empty for left rooms, client already has last state)
      json state_json;
      state_json["events"] = json::array();
      room_data["state"] = state_json;

      response["rooms"]["leave"][room_id] = room_data;
    }

    // =====================================================================
    // Presence
    // =====================================================================
    {
      int64_t next_presence_key = 0;
      json presence_events = presence_computer_.get_presence_events(
          request.user_id, since_token.presence_key,
          request.parsed_filter, next_presence_key);
      response["presence"]["events"] = presence_events;
    }

    // =====================================================================
    // Account Data (global)
    // =====================================================================
    {
      json global_acct = account_data_computer_.compute_global_account_data(
          request.user_id, since_token.account_data_key,
          request.parsed_filter);
      response["account_data"]["events"] = global_acct;
    }

    // =====================================================================
    // To-Device Messages
    // =====================================================================
    {
      json to_device = to_device_computer_.get_to_device_messages(
          request.user_id, request.device_id, since_token.to_device_key);
      response["to_device"]["events"] = to_device;
    }

    // =====================================================================
    // Device Lists
    // =====================================================================
    {
      std::vector<std::string> changed =
          device_list_computer_.get_changed_device_list_users(
              request.user_id, since_token.device_list_key);
      std::vector<std::string> left =
          device_list_computer_.get_left_device_list_users(
              request.user_id, since_token.device_list_key);

      for (const auto& uid : changed) {
        response["device_lists"]["changed"].push_back(uid);
      }
      for (const auto& uid : left) {
        response["device_lists"]["left"].push_back(uid);
      }
    }

    // =====================================================================
    // Device One-Time Keys Count
    // =====================================================================
    {
      json key_counts = device_list_computer_.get_device_one_time_keys_count(
          request.user_id, request.device_id);
      response["device_one_time_keys_count"] = key_counts;
    }

    return response;
  }

  // Handle a full sync request (initial or with timeout/long-poll)
  json handle_sync_request(const std::string& user_id,
                             const std::string& device_id,
                             const std::string& since,
                             int timeout_ms,
                             const std::string& filter_json_str,
                             bool full_state,
                             const std::string& set_presence) {

    SyncRequest request;
    request.user_id = user_id;
    request.device_id = device_id;
    request.since = since;
    request.timeout_ms = timeout_ms;
    request.filter = filter_json_str;
    request.full_state = full_state;
    request.set_presence = set_presence;

    // Parse filter if provided
    if (!filter_json_str.empty()) {
      try {
        json filter_def = json::parse(filter_json_str);
        request.parsed_filter = SyncFilter::from_json(filter_def);
      } catch (...) {
        // Use default filter on parse error
      }
    }

    // If set_presence is provided, update user presence
    if (!set_presence.empty()) {
      presence_computer_.update_presence(user_id, set_presence);
    }

    // For incremental sync with timeout, use long poll
    if (!request.is_initial() && timeout_ms > 0) {
      return handle_sync_with_long_poll(request);
    }

    // Build response
    return build_sync_response(request);
  }

  // Handle sync with long-poll timeout
  json handle_sync_with_long_poll(const SyncRequest& request) {
    StreamToken since_token = token_manager_.parse_since_token(request.since);

    // Check if there's new data available
    int64_t current_room_key = token_manager_.get_current_token().room_key;

    if (current_room_key > since_token.room_key) {
      // Data is available, return immediately
      return build_sync_response(request);
    }

    // No new data yet, wait for new events via long poll
    bool got_update = long_poll_manager_.wait_for_updates(
        request.user_id, request.timeout_ms, since_token.room_key);

    // Re-check after wake
    if (got_update) {
      return build_sync_response(request);
    }

    // Timeout reached with no new data - return minimal sync response
    return build_empty_sync_response(request);
  }

  // Build empty sync response (timeout with no new data)
  json build_empty_sync_response(const SyncRequest& request) {
    json response;
    response["next_batch"] = token_manager_.generate_next_batch_token();
    response["rooms"] = json::object();
    response["rooms"]["join"] = json::object();
    response["rooms"]["invite"] = json::object();
    response["rooms"]["leave"] = json::object();
    response["presence"] = json::object();
    response["presence"]["events"] = json::array();
    response["account_data"] = json::object();
    response["account_data"]["events"] = json::array();
    response["to_device"] = json::object();
    response["to_device"]["events"] = json::array();
    response["device_lists"] = json::object();
    response["device_lists"]["changed"] = json::array();
    response["device_lists"]["left"] = json::array();
    response["device_one_time_keys_count"] = json::object();
    return response;
  }

  // Update user's last sync timestamp
  void record_user_sync(const std::string& user_id) {
    db_.execute(
        "record_user_sync",
        "UPDATE users SET last_sync_ts = " +
        std::to_string(now_ms()) +
        " WHERE name = '" + sql_escape(user_id) + "'");
  }

  // Get the long poll manager for external notification use
  SyncLongPollManager& long_poll() { return long_poll_manager_; }
  SyncTokenManager& tokens() { return token_manager_; }
  TimelineComputer& timeline() { return timeline_computer_; }
  StateComputer& state() { return state_computer_; }
  EphemeralComputer& ephemeral() { return ephemeral_computer_; }
  AccountDataComputer& account_data() { return account_data_computer_; }
  PresenceComputer& presence() { return presence_computer_; }
  ToDeviceComputer& to_device() { return to_device_computer_; }
  DeviceListComputer& device_lists() { return device_list_computer_; }
  LazyLoadingManager& lazy_loading() { return lazy_loading_; }
  RoomSummaryComputer& summary() { return summary_computer_; }
  UnreadNotificationComputer& unread() { return unread_computer_; }

private:
  DatabasePool& db_;
  SyncTokenManager token_manager_;
  TimelineComputer timeline_computer_;
  StateComputer state_computer_;
  EphemeralComputer ephemeral_computer_;
  AccountDataComputer account_data_computer_;
  PresenceComputer presence_computer_;
  ToDeviceComputer to_device_computer_;
  DeviceListComputer device_list_computer_;
  LazyLoadingManager lazy_loading_;
  RoomSummaryComputer summary_computer_;
  UnreadNotificationComputer unread_computer_;
  SyncLongPollManager long_poll_manager_;
};

// ============================================================================
// SyncRateLimiter - Rate limiting for sync requests
// ============================================================================

class SyncRateLimiter {
public:
  static constexpr int64_t MIN_SYNC_INTERVAL_MS = 500;   // Minimum 500ms between syncs
  static constexpr int64_t MAX_SYNCS_PER_MINUTE = 30;    // Max 30 syncs per minute
  static constexpr int64_t RATE_LIMIT_WINDOW_MS = 60000; // 1 minute window

  bool check_rate_limit(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(rate_mutex_);

    int64_t now = now_ms();

    // Clean up old entries
    auto& history = rate_history_[user_id];
    history.erase(
        std::remove_if(history.begin(), history.end(),
                       [&](int64_t ts) {
                         return (now - ts) > RATE_LIMIT_WINDOW_MS;
                       }),
        history.end());

    // Check minimum interval
    if (!history.empty()) {
      int64_t last = history.back();
      if ((now - last) < MIN_SYNC_INTERVAL_MS) {
        return false; // Rate limited
      }
    }

    // Check max per window
    if (static_cast<int64_t>(history.size()) >= MAX_SYNCS_PER_MINUTE) {
      return false; // Rate limited
    }

    // Record this sync
    history.push_back(now);
    return true;
  }

  // Estimate time until next allowed sync
  int64_t time_until_allowed(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(rate_mutex_);

    int64_t now = now_ms();
    auto it = rate_history_.find(user_id);
    if (it == rate_history_.end() || it->second.empty()) return 0;

    auto& history = it->second;
    int64_t last = history.back();
    int64_t wait = MIN_SYNC_INTERVAL_MS - (now - last);

    if (wait < 0) wait = 0;

    if (static_cast<int64_t>(history.size()) >= MAX_SYNCS_PER_MINUTE) {
      int64_t oldest = history.front();
      int64_t window_wait = RATE_LIMIT_WINDOW_MS - (now - oldest);
      if (window_wait > wait) wait = window_wait;
    }

    return wait;
  }

private:
  std::mutex rate_mutex_;
  std::unordered_map<std::string, std::vector<int64_t>> rate_history_;
};

// ============================================================================
// InitialSyncVisibilityHandler - Main handler class
// ============================================================================

class InitialSyncVisibilityHandler {
public:
  InitialSyncVisibilityHandler(DatabasePool& db)
      : db_(db),
        sync_builder_(db),
        visibility_(db),
        rate_limiter_() {}

  // Handle initial sync request (full state)
  json handle_initial_sync(const std::string& user_id,
                             const std::string& device_id,
                             const std::string& filter_json,
                             int limit) {

    SyncRequest request;
    request.user_id = user_id;
    request.device_id = device_id;
    request.since = "";
    request.full_state = true;
    request.filter = filter_json;
    request.timeout_ms = 0;

    if (!filter_json.empty()) {
      try {
        json filter_def = json::parse(filter_json);
        request.parsed_filter = SyncFilter::from_json(filter_def);
      } catch (...) {}
    }

    // Override timeline limit if provided
    if (limit > 0) {
      request.parsed_filter.timeline_limit = limit;
    }

    // Check rate limit
    if (!rate_limiter_.check_rate_limit(user_id)) {
      json error;
      error["errcode"] = "M_LIMIT_EXCEEDED";
      error["error"] = "Too many sync requests";
      int64_t retry_after = rate_limiter_.time_until_allowed(user_id);
      error["retry_after_ms"] = retry_after;
      return error;
    }

    return sync_builder_.build_sync_response(request);
  }

  // Handle incremental sync request
  json handle_incremental_sync(const std::string& user_id,
                                  const std::string& device_id,
                                  const std::string& since,
                                  int timeout_ms,
                                  const std::string& filter_json,
                                  bool full_state,
                                  const std::string& set_presence) {

    // Check rate limit
    if (!rate_limiter_.check_rate_limit(user_id)) {
      json error;
      error["errcode"] = "M_LIMIT_EXCEEDED";
      error["error"] = "Too many sync requests";
      int64_t retry_after = rate_limiter_.time_until_allowed(user_id);
      error["retry_after_ms"] = retry_after;
      return error;
    }

    return sync_builder_.handle_sync_request(
        user_id, device_id, since, timeout_ms,
        filter_json, full_state, set_presence);
  }

  // Check if a specific event is visible to a user
  EventVisibilityResult check_event_visibility(
      const std::string& room_id,
      const std::string& user_id,
      const json& event) {

    EventVisibilityResult result;

    std::string sender = safe_str(event, "sender", "");
    std::string ev_type = safe_str(event, "type", "");

    // Get current membership of user in room
    std::string user_membership = get_current_membership(room_id, user_id);

    // Get sender's membership at event time
    std::string sender_membership = visibility_.get_membership_at_event(
        room_id, sender, event);

    result.visible = visibility_.is_event_visible(
        room_id, user_id, event, sender_membership, user_membership);

    if (!result.visible) {
      result.reason = "Event not visible due to history visibility rules";
    }

    return result;
  }

  // Compute limited timeline for a room
  json compute_limited_timeline(const std::string& room_id,
                                  const std::string& user_id,
                                  int64_t limit,
                                  const SyncFilter& filter) {

    SyncBudget budget(10 * 1024 * 1024); // Large budget for single room

    RoomSyncResult::TimelineSection timeline =
        sync_builder_.timeline().compute_timeline(
            room_id, user_id, 0, true, filter, budget);

    json result;
    result["events"] = timeline.events;
    result["limited"] = timeline.limited;
    if (!timeline.prev_batch.empty()) {
      result["prev_batch"] = timeline.prev_batch;
    }

    return result;
  }

  // Compute full state for a room
  json compute_full_state(const std::string& room_id,
                            const std::string& user_id,
                            const SyncFilter& filter) {

    SyncBudget budget(10 * 1024 * 1024);

    json state = sync_builder_.state().compute_state(
        room_id, user_id, 0, true, filter, budget);

    return state;
  }

  // Get rooms for user with visibility checks
  std::vector<std::string> get_visible_rooms_for_user(
      const std::string& user_id) {

    RowList rows = db_.execute(
        "get_visible_rooms",
        "SELECT DISTINCT room_id FROM room_memberships "
        "WHERE user_id='" + sql_escape(user_id) +
        "' AND membership IN ('join','invite','leave','ban')");

    std::vector<std::string> rooms;
    for (const auto& row : rows) {
      for (const auto& col : row) {
        if (col.name == "room_id" && col.value) {
          rooms.push_back(*col.value);
        }
      }
    }

    return rooms;
  }

  // Public accessors for sub-components
  SyncResponseBuilder& sync_builder() { return sync_builder_; }
  VisibilityPolicy& visibility() { return visibility_; }

  // Sync response size estimation
  json estimate_sync_size(const json& sync_response) {
    json estimate;

    int64_t total_bytes = SyncBudget::estimate_json_size(sync_response);
    estimate["total_bytes"] = total_bytes;
    estimate["total_kb"] = total_bytes / 1024;
    estimate["total_mb"] = static_cast<double>(total_bytes) / (1024.0 * 1024.0);

    int64_t room_count = 0;
    int64_t event_count = 0;

    if (sync_response.contains("rooms")) {
      auto& rooms = sync_response["rooms"];
      for (const auto& section : {"join", "invite", "leave"}) {
        if (rooms.contains(section) && rooms[section].is_object()) {
          for (const auto& el : rooms[section].items()) {
            room_count++;
            if (el.value().contains("timeline") &&
                el.value()["timeline"].contains("events")) {
              event_count += el.value()["timeline"]["events"].size();
            }
            if (el.value().contains("state") &&
                el.value()["state"].contains("events")) {
              event_count += el.value()["state"]["events"].size();
            }
          }
        }
      }
    }

    estimate["room_count"] = room_count;
    estimate["event_count"] = event_count;

    return estimate;
  }

private:
  std::string get_current_membership(const std::string& room_id,
                                       const std::string& user_id) {
    RowList rows = db_.execute(
        "get_current_membership",
        "SELECT membership FROM room_memberships "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND user_id='" + sql_escape(user_id) +
        "' ORDER BY event_stream_ordering DESC LIMIT 1");

    if (!rows.empty() && !rows[0].empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "membership" && col.value) {
          return *col.value;
        }
      }
    }

    return "leave";
  }

  DatabasePool& db_;
  SyncResponseBuilder sync_builder_;
  VisibilityPolicy visibility_;
  SyncRateLimiter rate_limiter_;
};

// ============================================================================
// SyncCache - Caches sync responses for identical requests
// ============================================================================

class SyncCache {
public:
  SyncCache() : cache_(100, 10) {} // 100 entries, 10 second TTL

  std::optional<json> get(const std::string& user_id,
                            const std::string& since) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    std::string key = user_id + ":" + since;
    return cache_.get(key);
  }

  void put(const std::string& user_id,
            const std::string& since,
            const json& response) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    std::string key = user_id + ":" + since;
    cache_.put(key, response);
  }

  void invalidate(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    // Clear all entries for this user
    // Since LruCache doesn't support prefix invalidation, we just clear
    cache_.clear();
  }

  void invalidate_room(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    // Clear entire cache on room update since we can't do prefix matches
    cache_.clear();
  }

private:
  std::mutex cache_mutex_;
  util::LruCache<json> cache_;
};

// ============================================================================
// SyncMetrics - Tracks sync performance metrics
// ============================================================================

class SyncMetrics {
public:
  void record_sync(int64_t duration_ms, int64_t room_count,
                    int64_t event_count, int64_t response_size,
                    bool is_initial) {
    std::lock_guard<std::mutex> lock(metrics_mutex_);

    if (is_initial) {
      initial_sync_count_++;
      total_initial_duration_ms_ += duration_ms;
    } else {
      incremental_sync_count_++;
      total_incremental_duration_ms_ += duration_ms;
    }

    total_syncs_++;
    total_rooms_ += room_count;
    total_events_ += event_count;
    total_response_bytes_ += response_size;

    if (duration_ms > max_duration_ms_) max_duration_ms_ = duration_ms;
    if (duration_ms < min_duration_ms_ || min_duration_ms_ == 0)
      min_duration_ms_ = duration_ms;
  }

  json get_metrics() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);

    json m;
    m["total_syncs"] = total_syncs_;
    m["initial_sync_count"] = initial_sync_count_;
    m["incremental_sync_count"] = incremental_sync_count_;
    m["total_rooms_processed"] = total_rooms_;
    m["total_events_processed"] = total_events_;
    m["total_response_bytes"] = total_response_bytes_;

    if (initial_sync_count_ > 0) {
      m["avg_initial_duration_ms"] = total_initial_duration_ms_ / initial_sync_count_;
    }
    if (incremental_sync_count_ > 0) {
      m["avg_incremental_duration_ms"] = total_incremental_duration_ms_ / incremental_sync_count_;
    }

    m["min_duration_ms"] = min_duration_ms_;
    m["max_duration_ms"] = max_duration_ms_;
    m["avg_response_size_kb"] = total_syncs_ > 0 ?
        (total_response_bytes_ / total_syncs_ / 1024) : 0;

    return m;
  }

  void reset() {
    std::lock_guard<std::mutex> lock(metrics_mutex_);
    total_syncs_ = 0;
    initial_sync_count_ = 0;
    incremental_sync_count_ = 0;
    total_rooms_ = 0;
    total_events_ = 0;
    total_response_bytes_ = 0;
    total_initial_duration_ms_ = 0;
    total_incremental_duration_ms_ = 0;
    min_duration_ms_ = 0;
    max_duration_ms_ = 0;
  }

private:
  std::mutex metrics_mutex_;
  int64_t total_syncs_{0};
  int64_t initial_sync_count_{0};
  int64_t incremental_sync_count_{0};
  int64_t total_rooms_{0};
  int64_t total_events_{0};
  int64_t total_response_bytes_{0};
  int64_t total_initial_duration_ms_{0};
  int64_t total_incremental_duration_ms_{0};
  int64_t min_duration_ms_{0};
  int64_t max_duration_ms_{0};
};

// ============================================================================
// RoomEventFilter - Filters events for specific room output
// ============================================================================

class RoomEventFilter {
public:
  // Strip unwanted fields from events before sending to client
  static json clean_event_for_client(const json& event) {
    json cleaned = event;

    // Ensure essential fields
    if (!cleaned.contains("event_id")) cleaned["event_id"] = "";
    if (!cleaned.contains("type")) cleaned["type"] = "";
    if (!cleaned.contains("sender")) cleaned["sender"] = "";
    if (!cleaned.contains("origin_server_ts")) cleaned["origin_server_ts"] = 0;
    if (!cleaned.contains("content")) cleaned["content"] = json::object();

    // Remove internal fields that shouldn't go to clients
    std::vector<std::string> internal_fields = {
        "internal_metadata", "outlier", "rejected_reason",
        "processed", "event_reference_hash"
    };

    for (const auto& field : internal_fields) {
      cleaned.erase(field);
    }

    return cleaned;
  }

  // Apply event filter to a list of events
  static json filter_event_list(const json& events, const SyncFilter& filter) {
    json filtered = json::array();

    for (const auto& ev : events) {
      std::string ev_type = safe_str(ev, "type", "");
      std::string sender = safe_str(ev, "sender", "");

      if (!filter.should_include_event_type(ev_type)) continue;
      if (!filter.should_include_sender(sender)) continue;

      json cleaned = clean_event_for_client(ev);
      filtered.push_back(cleaned);
    }

    return filtered;
  }

  // Determine if a timeline is limited
  static bool is_timeline_limited(const json& events,
                                    int64_t requested_limit,
                                    int64_t available_events) {
    if (requested_limit <= 0) return false;
    return static_cast<int64_t>(events.size()) < available_events ||
           static_cast<int64_t>(events.size()) >= requested_limit;
  }
};

// ============================================================================
// TimelineGapDetector - Detects gaps in sync timelines
// ============================================================================

class TimelineGapDetector {
public:
  explicit TimelineGapDetector(DatabasePool& db) : db_(db) {}

  // Check if there's a gap between the since token and current events
  bool has_gap(const std::string& room_id,
                int64_t since_stream_ordering,
                int64_t limit) {

    int64_t total_events = get_event_count_since(room_id, since_stream_ordering);
    return total_events > limit;
  }

  // Get total number of events since a stream position
  int64_t get_event_count_since(const std::string& room_id,
                                  int64_t since_stream_ordering) {
    RowList rows = db_.execute(
        "get_event_count_since",
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND stream_ordering > " + std::to_string(since_stream_ordering) +
        " AND outlier = 0");

    if (!rows.empty() && !rows[0].empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "cnt" && col.value) {
          try { return std::stoll(*col.value); } catch (...) { return 0; }
        }
      }
    }

    return 0;
  }

  // Determine if limited flag should be set
  bool should_set_limited(const std::string& room_id,
                            int64_t since_stream_ordering,
                            int64_t events_returned,
                            int64_t limit) {
    if (since_stream_ordering == 0) {
      // Initial sync: always limited unless all events fit
      int64_t total = get_total_event_count(room_id);
      return total > limit;
    } else {
      // Incremental sync: limited if there are more events than returned
      int64_t total = get_event_count_since(room_id, since_stream_ordering);
      return total > events_returned;
    }
  }

private:
  int64_t get_total_event_count(const std::string& room_id) {
    RowList rows = db_.execute(
        "get_total_event_count",
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND outlier = 0");

    if (!rows.empty() && !rows[0].empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "cnt" && col.value) {
          try { return std::stoll(*col.value); } catch (...) { return 0; }
        }
      }
    }

    return 0;
  }

  DatabasePool& db_;
};

// ============================================================================
// NotificationDispatcher - Notifies long-poll waiters of new events
// ============================================================================

class NotificationDispatcher {
public:
  explicit NotificationDispatcher(SyncLongPollManager& long_poll)
      : long_poll_(long_poll) {}

  // Notify all devices of a user
  void notify_new_event(const std::string& room_id,
                           const json& event) {
    // Get all users in the room
    RowList rows; // Note: this requires db_ which we don't have here
    // In practice, this would use the database to find all room members
    // and notify them. For now, notify all waiters.

    long_poll_.notify_all();
  }

  // Notify specific user of new data
  void notify_user(const std::string& user_id) {
    long_poll_.notify_user(user_id);
  }

  // Notify about typing changes
  void notify_typing_change(const std::string& room_id) {
    long_poll_.notify_all();
  }

  // Notify about new to-device message
  void notify_to_device(const std::string& user_id) {
    long_poll_.notify_user(user_id);
  }

  // Notify about presence change
  void notify_presence_change(const std::string& user_id) {
    long_poll_.notify_all();
  }

  // Notify about device list changes
  void notify_device_list_change(const std::string& user_id) {
    long_poll_.notify_all();
  }

private:
  SyncLongPollManager& long_poll_;
};

// ============================================================================
// SyncResponseCompressor - Compresses sync responses for large payloads
// ============================================================================

class SyncResponseCompressor {
public:
  // Check if response should be compressed
  static bool should_compress(const json& response) {
    return SyncBudget::estimate_json_size(response) > 5 * 1024; // > 5KB
  }

  // Minify JSON (compact format)
  static std::string minify(const json& response) {
    try {
      return response.dump();
    } catch (...) {
      return "{}";
    }
  }

  // Pretty-print JSON for debugging
  static std::string pretty_print(const json& response) {
    try {
      return response.dump(2);
    } catch (...) {
      return "{}";
    }
  }

  // Deduplicate repeated content in sync response
  static json deduplicate_room_events(json& response) {
    // This is a placeholder for more sophisticated dedup if needed
    return response;
  }
};

// ============================================================================
// Global sync handler facade (public API)
// ============================================================================

class SyncHandlerFacade {
public:
  SyncHandlerFacade(DatabasePool& db)
      : handler_(db),
        cache_(),
        metrics_() {}

  // Main sync entry point
  json handle_sync(const std::string& user_id,
                    const std::string& device_id,
                    const std::string& since,
                    int timeout_ms,
                    const std::string& filter_json,
                    bool full_state,
                    const std::string& set_presence) {

    auto start = std::chrono::steady_clock::now();

    // Check cache for identical request
    if (!full_state && timeout_ms == 0 && !since.empty()) {
      auto cached = cache_.get(user_id, since);
      if (cached) return *cached;
    }

    json response = handler_.handle_incremental_sync(
        user_id, device_id, since, timeout_ms, filter_json,
        full_state, set_presence);

    // Cache the response
    if (!full_state && !since.empty()) {
      cache_.put(user_id, since, response);
    }

    // Record metrics
    auto end = std::chrono::steady_clock::now();
    int64_t duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end - start).count();

    int64_t room_count = 0;
    int64_t event_count = 0;
    if (response.contains("rooms")) {
      for (const auto& section : {"join", "invite", "leave"}) {
        if (response["rooms"].contains(section)) {
          room_count += response["rooms"][section].size();
          for (const auto& el : response["rooms"][section].items()) {
            if (el.value().contains("timeline") &&
                el.value()["timeline"].contains("events")) {
              event_count += el.value()["timeline"]["events"].size();
            }
          }
        }
      }
    }

    int64_t response_size = SyncBudget::estimate_json_size(response);
    metrics_.record_sync(duration_ms, room_count, event_count,
                          response_size, full_state || since.empty());

    return response;
  }

  // Initial sync entry point
  json handle_initial_sync(const std::string& user_id,
                             const std::string& device_id,
                             const std::string& filter_json,
                             int limit) {

    auto start = std::chrono::steady_clock::now();

    json response = handler_.handle_initial_sync(
        user_id, device_id, filter_json, limit);

    auto end = std::chrono::steady_clock::now();
    int64_t duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end - start).count();

    int64_t room_count = 0;
    int64_t event_count = 0;
    if (response.contains("rooms") && response["rooms"].contains("join")) {
      room_count = response["rooms"]["join"].size();
      for (const auto& el : response["rooms"]["join"].items()) {
        if (el.value().contains("timeline") &&
            el.value()["timeline"].contains("events")) {
          event_count += el.value()["timeline"]["events"].size();
        }
        if (el.value().contains("state") &&
            el.value()["state"].contains("events")) {
          event_count += el.value()["state"]["events"].size();
        }
      }
    }

    int64_t response_size = SyncBudget::estimate_json_size(response);
    metrics_.record_sync(duration_ms, room_count, event_count,
                          response_size, true);

    return response;
  }

  // Check event visibility
  bool is_event_visible(const std::string& room_id,
                          const std::string& user_id,
                          const json& event) {
    EventVisibilityResult result = handler_.check_event_visibility(
        room_id, user_id, event);
    return result.visible;
  }

  // Get sync metrics
  json get_metrics() {
    return metrics_.get_metrics();
  }

  // Invalidate cache
  void invalidate_cache(const std::string& user_id) {
    cache_.invalidate(user_id);
  }

  // Get handler references for direct access
  InitialSyncVisibilityHandler& handler() { return handler_; }

private:
  InitialSyncVisibilityHandler handler_;
  SyncCache cache_;
  SyncMetrics metrics_;
};

// ============================================================================
// TypingNotificationManager - Additional typing handling
// ============================================================================

class TypingNotificationManager {
public:
  TypingNotificationManager(DatabasePool& db) : db_(db) {}

  // Set a user as typing in a room
  void set_typing(const std::string& room_id,
                   const std::string& user_id,
                   int64_t timeout_ms) {

    std::lock_guard<std::mutex> lock(g_ephemeral_lock);

    int64_t now = now_ms();

    // Upsert typing record
    db_.execute(
        "set_typing",
        "INSERT OR REPLACE INTO typing "
        "(room_id, user_id, last_typed_ts, timeout_ms) "
        "VALUES ('" + sql_escape(room_id) + "', '" +
        sql_escape(user_id) + "', " + std::to_string(now) +
        ", " + std::to_string(timeout_ms) + ")");

    // Clean up expired typing notifications
    db_.execute(
        "clean_typing",
        "DELETE FROM typing WHERE (last_typed_ts + timeout_ms) < " +
        std::to_string(now));
  }

  // Get current typing users in a room
  std::vector<std::string> get_typing_users(const std::string& room_id) {
    RowList rows = db_.execute(
        "get_typing_users",
        "SELECT user_id FROM typing "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND (last_typed_ts + timeout_ms) > " +
        std::to_string(now_ms()));

    std::vector<std::string> users;
    for (const auto& row : rows) {
      for (const auto& col : row) {
        if (col.name == "user_id" && col.value) {
          users.push_back(*col.value);
        }
      }
    }
    return users;
  }

  // Clear typing for a user
  void clear_typing(const std::string& room_id,
                      const std::string& user_id) {
    db_.execute(
        "clear_typing",
        "DELETE FROM typing "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND user_id='" + sql_escape(user_id) + "'");
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// ReceiptManager - Additional receipt handling
// ============================================================================

class ReceiptManager {
public:
  ReceiptManager(DatabasePool& db) : db_(db) {}

  // Store a receipt
  void store_receipt(const std::string& room_id,
                      const std::string& user_id,
                      const std::string& event_id,
                      const std::string& receipt_type,
                      const std::string& thread_id) {

    std::lock_guard<std::mutex> lock(g_ephemeral_lock);

    int64_t stream_id = g_sync_stream_id.fetch_add(1);

    json data;
    data["ts"] = now_ms();

    std::string data_str;
    try { data_str = data.dump(); } catch (...) { data_str = "{}"; }

    db_.execute(
        "store_receipt",
        "INSERT INTO receipts_linearized "
        "(room_id, user_id, event_id, receipt_type, data, thread_id, "
        "stream_ordering) "
        "VALUES ('" + sql_escape(room_id) + "', '" + sql_escape(user_id) +
        "', '" + sql_escape(event_id) + "', '" + sql_escape(receipt_type) +
        "', '" + sql_escape(data_str) + "', '" + sql_escape(thread_id) +
        "', " + std::to_string(stream_id) + ")");
  }

  // Get the last read receipt for a user in a room
  std::optional<std::string> get_last_read_event_id(
      const std::string& room_id,
      const std::string& user_id) {

    RowList rows = db_.execute(
        "get_last_read",
        "SELECT event_id FROM receipts_linearized "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND user_id='" + sql_escape(user_id) +
        "' AND receipt_type='m.read' "
        "ORDER BY stream_ordering DESC LIMIT 1");

    if (!rows.empty() && !rows[0].empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "event_id" && col.value) {
          return *col.value;
        }
      }
    }

    return std::nullopt;
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// Global factory function for external use
// ============================================================================

std::unique_ptr<SyncHandlerFacade> create_sync_handler(DatabasePool& db) {
  return std::make_unique<SyncHandlerFacade>(db);
}

// ============================================================================
// End of initial_sync_visibility.cpp
// ============================================================================

}  // namespace progressive::handlers
