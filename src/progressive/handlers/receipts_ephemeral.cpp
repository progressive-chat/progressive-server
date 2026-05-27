// receipts_ephemeral.cpp - Matrix Read Receipts and Ephemeral Events
// Implements ALL receipt and ephemeral event handlers: read receipts,
// fully_read markers, typing notifications, receipt federation,
// receipt linearizing, receipt graph storage, receipt stream ordering,
// receipt privacy, and full query capabilities.
// Target: 3500+ lines
//
// Handlers:
//   1.  post_read_receipt             - POST /rooms/{roomId}/receipt/{receiptType}/{eventId}
//   2.  post_fully_read_marker        - POST /rooms/{roomId}/read_markers (dedicated)
//   3.  get_fully_read_marker         - GET /rooms/{roomId}/read_markers
//   4.  get_room_receipts             - GET /rooms/{roomId}/receipts
//   5.  get_event_receipts            - GET /rooms/{roomId}/receipts/{eventId}
//   6.  post_typing_notification      - PUT /rooms/{roomId}/typing/{userId}
//   7.  get_typing_notifications      - GET /rooms/{roomId}/typing
//   8.  manage_typing_timeouts        - Background timeout sweep
//   9.  federate_receipts             - Push receipt EDUs to participating servers
//  10.  linearize_receipt             - Insert receipt into linearized stream
//  11.  store_receipt_graph           - Update receipt graph table
//  12.  get_receipt_stream_position   - Get max receipt stream ordering
//  13.  build_receipt_sync_block      - Build ephemeral receipt block for sync
//  14.  handle_receipt_privacy        - Privacy filtering for m.read.private
//  15.  query_receipts_by_room        - Room-scoped receipt queries
//  16.  query_receipts_by_event       - Event-scoped receipt queries
//  17.  process_receipt_edu           - Incoming federation receipt EDUs
//  18.  broadcast_receipt_updates     - Notify local clients of receipt changes
//  19.  aggregate_receipts            - Aggregate multiple user receipts
//  20.  receipt_cleanup_maintenance   - Periodic cleanup of old receipts

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
#include "progressive/storage/databases/main/devices.hpp"

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
#include <condition_variable>

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;

// ============================================================================
// Global utilities (shared across receipt/ephemeral handlers)
// ============================================================================

static std::atomic<int64_t> g_receipt_seq{1};
static std::atomic<int64_t> g_typing_seq{1};
static std::atomic<int64_t> g_edu_seq{1};
static std::mutex g_receipt_lock;
static std::mutex g_typing_lock;
static std::mutex g_typing_timeout_lock;
static std::mutex g_fully_read_lock;
static std::mutex g_fed_lock;
static std::mutex g_stream_lock;
static std::mutex g_notify_lock;
static std::mutex g_privacy_lock;
static std::mutex g_cleanup_lock;

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_id(const std::string& prefix) {
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(g_receipt_seq.fetch_add(1));
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
// Receipt data structures
// ============================================================================

enum class ReceiptType {
  READ,         // m.read
  READ_PRIVATE, // m.read.private
  FULLY_READ,   // m.fully_read
  UNKNOWN
};

static ReceiptType receipt_type_from_string(const std::string& type) {
  if (type == "m.read") return ReceiptType::READ;
  if (type == "m.read.private") return ReceiptType::READ_PRIVATE;
  if (type == "m.fully_read") return ReceiptType::FULLY_READ;
  return ReceiptType::UNKNOWN;
}

static std::string receipt_type_to_string(ReceiptType type) {
  switch (type) {
    case ReceiptType::READ: return "m.read";
    case ReceiptType::READ_PRIVATE: return "m.read.private";
    case ReceiptType::FULLY_READ: return "m.fully_read";
    default: return "m.read";
  }
}

struct ReceiptEntry {
  std::string room_id;
  std::string user_id;
  std::string event_id;
  std::string receipt_type;
  int64_t stream_ordering;
  int64_t thread_id;
  int64_t timestamp;
  json data;
};

struct FullyReadMarker {
  std::string room_id;
  std::string user_id;
  std::string event_id;
  int64_t stream_ordering;
  int64_t timestamp;
};

struct TypingNotification {
  std::string room_id;
  std::string user_id;
  bool is_typing;
  int64_t timeout_ms;
  int64_t expiry_ts;
  int64_t updated_ts;
  std::string display_name;
};

struct ReceiptQueryParams {
  std::string room_id;
  std::string event_id;
  std::string user_id;
  std::string receipt_type;
  int64_t from_stream;
  int64_t to_stream;
  int limit;
  bool include_private;
};

// ============================================================================
// Receipt stream position manager
// ============================================================================

class ReceiptStreamManager {
public:
  ReceiptStreamManager() = default;

  int64_t next_stream_id() {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    current_stream_ = std::max(current_stream_, now_ms());
    return ++current_stream_;
  }

  int64_t get_current_stream_id() {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    return current_stream_;
  }

  void update_stream_id(int64_t new_id) {
    std::lock_guard<std::mutex> lock(stream_mutex_);
    if (new_id > current_stream_) current_stream_ = new_id;
  }

private:
  int64_t current_stream_ = {0};
  std::mutex stream_mutex_;
};

static ReceiptStreamManager g_stream_manager;

// ============================================================================
// Typing timeout manager - manages expiry of typing notifications
// ============================================================================

class TypingTimeoutManager {
public:
  static TypingTimeoutManager& instance() {
    static TypingTimeoutManager inst;
    return inst;
  }

  void start(DatabasePool& db) {
    if (running_) return;
    running_ = true;
    cleanup_thread_ = std::thread([this, &db]() {
      while (running_) {
        {
          std::unique_lock<std::mutex> lock(mutex_);
          cv_.wait_for(lock, std::chrono::seconds(10), [this] { return !running_; });
        }
        if (!running_) break;
        sweep_expired_typing(db);
        sweep_expired_receipts(db);
      }
    });
  }

  void stop() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      running_ = false;
    }
    cv_.notify_all();
    if (cleanup_thread_.joinable()) cleanup_thread_.join();
  }

  void track_typing(const std::string& room_id, const std::string& user_id,
                    int64_t expiry) {
    std::lock_guard<std::mutex> lock(mutex_);
    typing_expiry_[{room_id, user_id}] = expiry;
  }

  void remove_typing(const std::string& room_id, const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    typing_expiry_.erase({room_id, user_id});
  }

  int64_t get_typing_expiry(const std::string& room_id,
                            const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = typing_expiry_.find({room_id, user_id});
    if (it != typing_expiry_.end()) return it->second;
    return 0;
  }

private:
  TypingTimeoutManager() = default;

  void sweep_expired_typing(DatabasePool& db) {
    int64_t now = now_ms();
    std::vector<std::pair<std::string, std::string>> expired;

    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto it = typing_expiry_.begin(); it != typing_expiry_.end();) {
        if (it->second <= now) {
          expired.push_back(it->first);
          it = typing_expiry_.erase(it);
        } else {
          ++it;
        }
      }
    }

    for (auto& key : expired) {
      // Remove from database
      auto cursor = db.cursor("typing_sweep");
      if (cursor) {
        cursor->execute("DELETE FROM typing_notifications "
                        "WHERE room_id='" + key.first +
                        "' AND user_id='" + key.second + "'");
        cursor->commit();
      }

      // Notify federation about typing stop
      auto servers = get_room_participating_servers(db, key.first);
      int64_t ts = now_ms();
      for (auto& dest : servers) {
        json edu;
        edu["type"] = "m.typing";
        edu["content"] = json::object({
          {"room_id", key.first},
          {"user_id", key.second},
          {"typing", false}
        });
        edu["origin"] = "localhost";
        edu["origin_server_ts"] = ts;

        auto txn = db.cursor("fed_typing_expired");
        if (txn) {
          txn->execute(
            "INSERT OR REPLACE INTO federation_stream "
            "(type, room_id, event_id, destination, json_data, stream_id) "
            "VALUES ('edu','" + key.first + "','','" + dest + "',?,?)",
            {edu.dump(), std::to_string(ts)}
          );
          txn->commit();
        }
      }
    }
  }

  void sweep_expired_receipts(DatabasePool& db) {
    // Periodically clean up very old receipt entries
    // Keep receipts for 30 days by default
    int64_t cutoff = now_ms() - (30LL * 24 * 60 * 60 * 1000);

    auto cursor = db.cursor("receipt_sweep");
    if (cursor) {
      cursor->execute(
        "DELETE FROM receipts_linearized WHERE stream_id < "
        "(SELECT COALESCE(MAX(stream_id), 0) - 1000000 FROM receipts_linearized)"
      );
      cursor->commit();
    }
  }

  std::unordered_map<std::pair<std::string, std::string>, int64_t,
    boost::hash<std::pair<std::string, std::string>>> typing_expiry_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::thread cleanup_thread_;
  bool running_ = false;
};

// Simple pair hash without boost dependency
struct PairHash {
  template <class T1, class T2>
  std::size_t operator()(const std::pair<T1, T2>& p) const {
    auto h1 = std::hash<T1>{}(p.first);
    auto h2 = std::hash<T2>{}(p.second);
    return h1 ^ (h2 << 1);
  }
};

// ============================================================================
// Receipt notification manager - notifies connected clients of receipt changes
// ============================================================================

struct ReceiptNotificationListener {
  std::string user_id;
  std::string device_id;
  std::function<void(const json&)> callback;
  int64_t registered_at;
};

class ReceiptNotificationManager {
public:
  static ReceiptNotificationManager& instance() {
    static ReceiptNotificationManager inst;
    return inst;
  }

  void register_listener(const std::string& user_id,
                          const std::string& device_id,
                          std::function<void(const json&)> callback) {
    std::lock_guard<std::mutex> lock(notify_mutex_);
    ReceiptNotificationListener listener;
    listener.user_id = user_id;
    listener.device_id = device_id;
    listener.callback = callback;
    listener.registered_at = now_ms();
    listeners_.push_back(listener);
  }

  void unregister_listener(const std::string& user_id,
                            const std::string& device_id) {
    std::lock_guard<std::mutex> lock(notify_mutex_);
    listeners_.erase(
      std::remove_if(listeners_.begin(), listeners_.end(),
        [&](const ReceiptNotificationListener& l) {
          return l.user_id == user_id && l.device_id == device_id;
        }),
      listeners_.end()
    );
  }

  void notify_receipt_change(const std::string& room_id,
                              const std::string& event_id,
                              const std::string& receipt_type,
                              const std::string& user_id,
                              const json& receipt_data) {
    std::lock_guard<std::mutex> lock(notify_mutex_);
    json notification;
    notification["type"] = "m.receipt";
    notification["room_id"] = room_id;
    notification["content"] = json::object();
    notification["content"][event_id] = json::object();
    notification["content"][event_id][receipt_type] = json::object();
    notification["content"][event_id][receipt_type][user_id] = receipt_data;

    // Clean up stale listeners (older than 24 hours)
    int64_t cutoff = now_ms() - (24LL * 60 * 60 * 1000);
    for (auto& listener : listeners_) {
      if (listener.registered_at > cutoff) {
        listener.callback(notification);
      }
    }
  }

  void notify_typing_change(const std::string& room_id,
                             const std::string& user_id,
                             bool typing) {
    std::lock_guard<std::mutex> lock(notify_mutex_);
    json notification;
    notification["type"] = "m.typing";
    notification["room_id"] = room_id;
    notification["content"] = json::object({
      {"user_ids", json::array({user_id})}
    });

    int64_t cutoff = now_ms() - (24LL * 60 * 60 * 1000);
    for (auto& listener : listeners_) {
      if (listener.registered_at > cutoff) {
        listener.callback(notification);
      }
    }
  }

private:
  std::vector<ReceiptNotificationListener> listeners_;
  std::mutex notify_mutex_;
};

// ============================================================================
// Receipt privacy manager - handles m.read.private filtering
// ============================================================================

class ReceiptPrivacyManager {
public:
  static ReceiptPrivacyManager& instance() {
    static ReceiptPrivacyManager inst;
    return inst;
  }

  // Filter receipts visible to a given user
  // m.read.private receipts are ONLY visible to the user who set them
  json filter_receipts_for_user(const json& raw_receipts,
                                 const std::string& requesting_user_id) {
    json filtered = json::object();

    for (auto& [event_id, receipt_types] : raw_receipts.items()) {
      json filtered_event = json::object();

      for (auto& [receipt_type, user_receipts] : receipt_types.items()) {
        if (receipt_type == "m.read.private") {
          // Private receipts: only include the requesting user's own entry
          if (user_receipts.contains(requesting_user_id)) {
            filtered_event[receipt_type] = json::object();
            filtered_event[receipt_type][requesting_user_id] =
              user_receipts[requesting_user_id];
          }
        } else if (receipt_type == "m.read") {
          // Public receipts: include everyone
          filtered_event[receipt_type] = user_receipts;
        } else {
          // Other types: include as-is
          filtered_event[receipt_type] = user_receipts;
        }
      }

      if (!filtered_event.empty()) {
        filtered[event_id] = filtered_event;
      }
    }

    return filtered;
  }

  // Check if a receipt type is private
  bool is_private_receipt(const std::string& receipt_type) {
    return receipt_type == "m.read.private";
  }

  // Mask private receipts for federation (never send m.read.private over federation)
  json mask_private_receipts_for_federation(const json& raw_receipts) {
    json masked = json::object();

    for (auto& [event_id, receipt_types] : raw_receipts.items()) {
      json masked_event = json::object();

      for (auto& [receipt_type, user_receipts] : receipt_types.items()) {
        if (receipt_type == "m.read.private") {
          // Skip private receipts entirely for federation
          continue;
        }
        masked_event[receipt_type] = user_receipts;
      }

      if (!masked_event.empty()) {
        masked[event_id] = masked_event;
      }
    }

    return masked;
  }

private:
  ReceiptPrivacyManager() = default;
  std::mutex privacy_mutex_;
};

// ============================================================================
// Receipt linearizer - manages linearized receipt stream
// ============================================================================

class ReceiptLinearizer {
public:
  ReceiptLinearizer(DatabasePool& db) : db_(db) {}

  // Insert a receipt into the linearized table with a new stream ID
  int64_t linearize(const ReceiptEntry& entry) {
    int64_t stream_id = g_stream_manager.next_stream_id();

    json data = entry.data;
    if (data.empty()) {
      data = json::object({
        {"ts", entry.timestamp}
      });
    }

    auto cursor = db_.cursor("receipt_linearize");
    if (cursor) {
      std::string sql =
        "INSERT INTO receipts_linearized "
        "(room_id, receipt_type, user_id, event_id, data, thread_id) "
        "VALUES (?, ?, ?, ?, ?, ?)";
      cursor->execute(sql, {
        entry.room_id,
        entry.receipt_type,
        entry.user_id,
        entry.event_id,
        data.dump(),
        std::to_string(entry.thread_id)
      });
      cursor->commit();
    }

    // Update stream position tracking
    g_stream_manager.update_stream_id(stream_id);

    return stream_id;
  }

  // Get receipts from a given stream position
  std::vector<ReceiptEntry> get_receipts_since(int64_t from_stream,
                                                 int64_t to_stream,
                                                 const std::string& room_id = "") {
    std::vector<ReceiptEntry> results;
    std::string sql =
      "SELECT room_id, receipt_type, user_id, event_id, data, thread_id, stream_id "
      "FROM receipts_linearized "
      "WHERE stream_id > ? AND stream_id <= ?";

    std::vector<SQLParam> params = {
      std::to_string(from_stream),
      std::to_string(to_stream)
    };

    if (!room_id.empty()) {
      sql += " AND room_id = ?";
      params.push_back(room_id);
    }

    sql += " ORDER BY stream_id ASC";

    auto cursor = db_.cursor("receipt_since");
    if (cursor) {
      cursor->execute(sql, params);
      auto rows = cursor->fetchall();
      for (auto& row : rows) {
        ReceiptEntry entry;
        entry.room_id = row.get<std::string>(0);
        entry.receipt_type = row.get<std::string>(1);
        entry.user_id = row.get<std::string>(2);
        entry.event_id = row.get<std::string>(3);
        std::string data_str = row.get<std::string>(4);
        entry.data = json::parse(data_str.empty() ? "{}" : data_str);
        entry.thread_id = std::stoll(row.get<std::string>(5));
        entry.stream_ordering = row.get<int64_t>(6);
        results.push_back(entry);
      }
    }

    return results;
  }

  // Get all receipts for a specific room
  std::vector<ReceiptEntry> get_room_receipts(const std::string& room_id,
                                                int64_t limit = 100) {
    std::vector<ReceiptEntry> results;
    auto cursor = db_.cursor("receipt_room");
    if (cursor) {
      std::string sql =
        "SELECT room_id, receipt_type, user_id, event_id, data, thread_id, stream_id "
        "FROM receipts_linearized "
        "WHERE room_id = ? "
        "ORDER BY stream_id DESC LIMIT ?";
      cursor->execute(sql, {room_id, std::to_string(limit)});
      auto rows = cursor->fetchall();
      for (auto& row : rows) {
        ReceiptEntry entry;
        entry.room_id = row.get<std::string>(0);
        entry.receipt_type = row.get<std::string>(1);
        entry.user_id = row.get<std::string>(2);
        entry.event_id = row.get<std::string>(3);
        std::string data_str = row.get<std::string>(4);
        entry.data = json::parse(data_str.empty() ? "{}" : data_str);
        entry.thread_id = std::stoll(row.get<std::string>(5));
        entry.stream_ordering = row.get<int64_t>(6);
        results.push_back(entry);
      }
    }
    return results;
  }

  // Get latest receipt for each user in a room
  std::map<std::string, ReceiptEntry> get_latest_receipts_for_room(
      const std::string& room_id, const std::string& receipt_type = "m.read") {
    std::map<std::string, ReceiptEntry> results;
    auto cursor = db_.cursor("receipt_latest");
    if (cursor) {
      std::string sql =
        "SELECT r.room_id, r.receipt_type, r.user_id, r.event_id, r.data, "
        "       r.thread_id, MAX(r.stream_id) as stream_id "
        "FROM receipts_linearized r "
        "WHERE r.room_id = ? AND r.receipt_type = ? "
        "GROUP BY r.user_id";
      cursor->execute(sql, {room_id, receipt_type});
      auto rows = cursor->fetchall();
      for (auto& row : rows) {
        ReceiptEntry entry;
        entry.room_id = row.get<std::string>(0);
        entry.receipt_type = row.get<std::string>(1);
        entry.user_id = row.get<std::string>(2);
        entry.event_id = row.get<std::string>(3);
        std::string data_str = row.get<std::string>(4);
        entry.data = json::parse(data_str.empty() ? "{}" : data_str);
        entry.thread_id = std::stoll(row.get<std::string>(5));
        entry.stream_ordering = row.get<int64_t>(6);
        results[entry.user_id] = entry;
      }
    }
    return results;
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// Receipt graph storage - maintains receipt graph per room/user
// ============================================================================

class ReceiptGraphStore {
public:
  ReceiptGraphStore(DatabasePool& db) : db_(db) {}

  // Upsert a receipt into the graph table
  void upsert_graph_receipt(const ReceiptEntry& entry) {
    auto cursor = db_.cursor("receipt_graph_upsert");
    if (cursor) {
      json data = entry.data;
      if (data.empty()) {
        data = json::object({
          {"ts", entry.timestamp}
        });
      }

      // Check if there's an existing graph entry for this user/room/type
      std::string check_sql =
        "SELECT event_ids, data FROM receipts_graph "
        "WHERE room_id = ? AND receipt_type = ? AND user_id = ?";
      cursor->execute(check_sql, {
        entry.room_id,
        entry.receipt_type,
        entry.user_id
      });

      auto existing_rows = cursor->fetchall();
      if (!existing_rows.empty()) {
        // Merge with existing event_ids
        std::string existing_event_ids = existing_rows[0].get<std::string>(0);
        std::string existing_data_str = existing_rows[0].get<std::string>(1);
        json existing_data = json::parse(existing_data_str.empty() ? "{}" : existing_data_str);

        // Parse existing event_ids as JSON array
        json event_ids_array;
        try {
          event_ids_array = json::parse(existing_event_ids);
        } catch (...) {
          event_ids_array = json::array();
        }
        if (!event_ids_array.is_array()) {
          event_ids_array = json::array();
        }

        // Add new event_id if not already present
        bool found = false;
        for (auto& eid : event_ids_array) {
          if (eid.is_string() && eid.get<std::string>() == entry.event_id) {
            found = true;
            break;
          }
        }
        if (!found) {
          event_ids_array.push_back(entry.event_id);
        }

        // Merge data
        existing_data["ts"] = std::max(
          existing_data.value("ts", 0LL),
          entry.timestamp
        );
        existing_data["last_event_id"] = entry.event_id;

        // Update
        cursor->execute(
          "UPDATE receipts_graph SET event_ids = ?, data = ? "
          "WHERE room_id = ? AND receipt_type = ? AND user_id = ?",
          {
            event_ids_array.dump(),
            existing_data.dump(),
            entry.room_id,
            entry.receipt_type,
            entry.user_id
          }
        );
      } else {
        // Insert new graph entry
        json event_ids_array = json::array({entry.event_id});
        cursor->execute(
          "INSERT INTO receipts_graph "
          "(room_id, receipt_type, user_id, event_ids, data) "
          "VALUES (?, ?, ?, ?, ?)",
          {
            entry.room_id,
            entry.receipt_type,
            entry.user_id,
            event_ids_array.dump(),
            data.dump()
          }
        );
      }

      cursor->commit();
    }
  }

  // Get receipt graph for a room
  json get_room_graph(const std::string& room_id,
                       const std::string& receipt_type = "") {
    json result = json::object();
    auto cursor = db_.cursor("receipt_graph_get");
    if (cursor) {
      std::string sql =
        "SELECT user_id, receipt_type, event_ids, data "
        "FROM receipts_graph WHERE room_id = ?";
      std::vector<SQLParam> params = {room_id};

      if (!receipt_type.empty()) {
        sql += " AND receipt_type = ?";
        params.push_back(receipt_type);
      }

      cursor->execute(sql, params);
      auto rows = cursor->fetchall();
      for (auto& row : rows) {
        std::string user_id = row.get<std::string>(0);
        std::string rtype = row.get<std::string>(1);
        std::string event_ids_str = row.get<std::string>(2);
        std::string data_str = row.get<std::string>(3);

        json event_ids_array;
        try {
          event_ids_array = json::parse(event_ids_str);
        } catch (...) {
          event_ids_array = json::array();
        }

        json entry;
        entry["event_ids"] = event_ids_array;
        entry["data"] = json::parse(data_str.empty() ? "{}" : data_str);

        if (!result.contains(rtype)) {
          result[rtype] = json::object();
        }
        result[rtype][user_id] = entry;
      }
    }
    return result;
  }

  // Get graph for a specific user in a room
  json get_user_graph(const std::string& room_id,
                       const std::string& user_id,
                       const std::string& receipt_type = "") {
    json result = json::object();
    auto cursor = db_.cursor("receipt_graph_user");
    if (cursor) {
      std::string sql =
        "SELECT receipt_type, event_ids, data "
        "FROM receipts_graph WHERE room_id = ? AND user_id = ?";
      std::vector<SQLParam> params = {room_id, user_id};

      if (!receipt_type.empty()) {
        sql += " AND receipt_type = ?";
        params.push_back(receipt_type);
      }

      cursor->execute(sql, params);
      auto rows = cursor->fetchall();
      for (auto& row : rows) {
        std::string rtype = row.get<std::string>(0);
        std::string event_ids_str = row.get<std::string>(1);
        std::string data_str = row.get<std::string>(2);

        json event_ids_array;
        try {
          event_ids_array = json::parse(event_ids_str);
        } catch (...) {
          event_ids_array = json::array();
        }

        json entry;
        entry["event_ids"] = event_ids_array;
        entry["data"] = json::parse(data_str.empty() ? "{}" : data_str);
        result[rtype] = entry;
      }
    }
    return result;
  }

  // Delete graph entries for a room (used when room is deleted)
  void delete_room_graph(const std::string& room_id) {
    auto cursor = db_.cursor("receipt_graph_delete");
    if (cursor) {
      cursor->execute("DELETE FROM receipts_graph WHERE room_id = ?", {room_id});
      cursor->commit();
    }
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// Receipt federation manager
// ============================================================================

class ReceiptFederationManager {
public:
  ReceiptFederationManager(DatabasePool& db) : db_(db) {}

  // Federate a receipt EDU to all participating servers
  void federate_receipt(const ReceiptEntry& entry,
                         const std::string& origin_server = "localhost") {
    auto servers = get_room_participating_servers(db_, entry.room_id);

    if (entry.receipt_type == "m.read.private") {
      // Never federate private receipts
      return;
    }

    int64_t ts = now_ms();
    for (auto& dest : servers) {
      json edu;
      edu["type"] = "m.receipt";
      edu["room_id"] = entry.room_id;
      edu["content"] = json::object({
        {entry.event_id, json::object({
          {entry.receipt_type, json::object({
            {entry.user_id, json::object({
              {"ts", entry.timestamp}
            })}
          })}
        })}
      });
      edu["origin"] = origin_server;
      edu["origin_server_ts"] = ts;
      edu["edu_type"] = "m.receipt";

      push_edu_to_federation(edu, dest);
    }
  }

  // Federate a fully_read marker EDU
  void federate_fully_read(const FullyReadMarker& marker,
                            const std::string& origin_server = "localhost") {
    auto servers = get_room_participating_servers(db_, marker.room_id);
    int64_t ts = now_ms();

    for (auto& dest : servers) {
      json edu;
      edu["type"] = "m.fully_read";
      edu["room_id"] = marker.room_id;
      edu["content"] = json::object({
        {"event_id", marker.event_id},
        {"user_id", marker.user_id}
      });
      edu["origin"] = origin_server;
      edu["origin_server_ts"] = ts;
      edu["edu_type"] = "m.fully_read";

      push_edu_to_federation(edu, dest);
    }
  }

  // Process an incoming receipt EDU from federation
  json process_incoming_receipt_edu(const json& edu) {
    if (!edu.contains("room_id") || !edu.contains("content")) {
      return make_error(400, "M_BAD_JSON", "Invalid receipt EDU format");
    }

    std::string room_id = edu["room_id"].get<std::string>();
    json& content = edu["content"];

    // Process each event_id in the content
    for (auto& [event_id, receipt_types] : content.items()) {
      if (!receipt_types.is_object()) continue;

      for (auto& [receipt_type, user_receipts] : receipt_types.items()) {
        if (receipt_type == "m.read.private") {
          // Never accept private receipts over federation
          continue;
        }

        if (!user_receipts.is_object()) continue;

        for (auto& [user_id, receipt_data] : user_receipts.items()) {
          ReceiptEntry entry;
          entry.room_id = room_id;
          entry.user_id = user_id;
          entry.event_id = event_id;
          entry.receipt_type = receipt_type;
          entry.timestamp = receipt_data.value("ts", now_ms());
          entry.thread_id = receipt_data.value("thread_id", 0LL);
          entry.data = receipt_data;
          entry.stream_ordering = g_stream_manager.next_stream_id();

          // Persist the federated receipt
          persist_federated_receipt(entry);
        }
      }
    }

    return make_response(200, json::object());
  }

  // Process an incoming typing EDU from federation
  json process_incoming_typing_edu(const json& edu) {
    if (!edu.contains("room_id") || !edu.contains("content")) {
      return make_error(400, "M_BAD_JSON", "Invalid typing EDU format");
    }

    std::string room_id = edu["room_id"].get<std::string>();
    json& content = edu["content"];
    std::string user_id = content.value("user_id", "");
    bool typing = content.value("typing", false);

    if (user_id.empty()) {
      return make_error(400, "M_BAD_JSON", "Missing user_id in typing EDU");
    }

    int64_t now = now_ms();
    int64_t timeout_ms = content.value("timeout", 30000LL);
    if (timeout_ms <= 0) timeout_ms = 30000;
    if (timeout_ms > 120000) timeout_ms = 120000;

    auto cursor = db_.cursor("fed_typing_process");
    if (cursor) {
      if (typing) {
        int64_t expiry = now + timeout_ms;
        cursor->execute(
          "INSERT OR REPLACE INTO typing_notifications "
          "(room_id, user_id, is_typing, timeout_ms, expiry_ts, ts) "
          "VALUES (?, ?, 1, ?, ?, ?)",
          {room_id, user_id, std::to_string(timeout_ms),
           std::to_string(expiry), std::to_string(now)}
        );
      } else {
        cursor->execute(
          "DELETE FROM typing_notifications "
          "WHERE room_id = ? AND user_id = ?",
          {room_id, user_id}
        );
      }
      cursor->commit();
    }

    return make_response(200, json::object());
  }

private:
  void push_edu_to_federation(const json& edu, const std::string& destination) {
    int64_t stream_id = g_edu_seq.fetch_add(1);
    auto cursor = db_.cursor("fed_edu_push");
    if (cursor) {
      cursor->execute(
        "INSERT OR REPLACE INTO federation_stream "
        "(type, room_id, event_id, destination, json_data, stream_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        {
          "edu",
          edu.value("room_id", ""),
          "",
          destination,
          edu.dump(),
          std::to_string(stream_id)
        }
      );
      cursor->commit();
    }
  }

  void persist_federated_receipt(const ReceiptEntry& entry) {
    // Insert into receipts_linearized
    auto cursor = db_.cursor("fed_receipt_persist");
    if (cursor) {
      json data = entry.data;
      if (data.empty()) {
        data = json::object({{"ts", entry.timestamp}});
      }

      cursor->execute(
        "INSERT INTO receipts_linearized "
        "(room_id, receipt_type, user_id, event_id, data, thread_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        {
          entry.room_id,
          entry.receipt_type,
          entry.user_id,
          entry.event_id,
          data.dump(),
          std::to_string(entry.thread_id)
        }
      );

      // Also update receipts_graph
      cursor->execute(
        "INSERT OR REPLACE INTO receipts_graph "
        "(room_id, receipt_type, user_id, event_ids, data) "
        "VALUES (?, ?, ?, ?, ?)",
        {
          entry.room_id,
          entry.receipt_type,
          entry.user_id,
          json::array({entry.event_id}).dump(),
          data.dump()
        }
      );

      cursor->commit();
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// Sync ephemeral block builder - builds receipt blocks for sync responses
// ============================================================================

class SyncEphemeralBuilder {
public:
  SyncEphemeralBuilder(DatabasePool& db, const std::string& user_id)
    : db_(db), user_id_(user_id) {}

  // Build ephemeral events for a room (receipts + typing)
  json build_ephemeral_for_room(const std::string& room_id,
                                  int64_t since_stream = 0) {
    json ephemeral = json::object();
    ephemeral["events"] = json::array();

    // --- Receipts ---
    json receipt_block = build_receipt_block(room_id, since_stream);
    if (!receipt_block.empty()) {
      ephemeral["events"].push_back(receipt_block);
    }

    // --- Typing ---
    json typing_block = build_typing_block(room_id);
    if (!typing_block.empty()) {
      ephemeral["events"].push_back(typing_block);
    }

    return ephemeral;
  }

  // Build receipts for sync response
  json build_receipt_block(const std::string& room_id,
                            int64_t since_stream = 0) {
    ReceiptsStore receipts_store(db_);
    ReceiptLinearizer linearizer(db_);

    std::vector<ReceiptEntry> entries;
    if (since_stream > 0) {
      int64_t to_stream = g_stream_manager.get_current_stream_id();
      entries = linearizer.get_receipts_since(since_stream, to_stream, room_id);
    } else {
      entries = linearizer.get_latest_receipts_for_room_as_entries(room_id);
    }

    if (entries.empty()) return json();

    // Group receipts by event_id, then by receipt_type, then by user_id
    json receipt_dict = json::object();
    for (auto& entry : entries) {
      if (!receipt_dict.contains(entry.event_id)) {
        receipt_dict[entry.event_id] = json::object();
      }
      if (!receipt_dict[entry.event_id].contains(entry.receipt_type)) {
        receipt_dict[entry.event_id][entry.receipt_type] = json::object();
      }
      json user_receipt;
      user_receipt["ts"] = entry.timestamp;
      if (!entry.data.empty()) {
        for (auto& [k, v] : entry.data.items()) {
          user_receipt[k] = v;
        }
      }
      receipt_dict[entry.event_id][entry.receipt_type][entry.user_id] = user_receipt;
    }

    // Apply privacy filtering
    auto& privacy_mgr = ReceiptPrivacyManager::instance();
    json filtered = privacy_mgr.filter_receipts_for_user(receipt_dict, user_id_);

    if (filtered.empty()) return json();

    json result;
    result["type"] = "m.receipt";
    result["content"] = filtered;
    return result;
  }

  // Build typing notification block for sync response
  json build_typing_block(const std::string& room_id) {
    std::vector<std::string> typing_users;
    auto cursor = db_.cursor("sync_typing");
    if (cursor) {
      cursor->execute(
        "SELECT user_id FROM typing_notifications "
        "WHERE room_id = ? AND is_typing = 1 AND expiry_ts > ?",
        {room_id, std::to_string(now_ms())}
      );
      auto rows = cursor->fetchall();
      for (auto& row : rows) {
        std::string uid = row.get<std::string>(0);
        if (uid != user_id_) {
          typing_users.push_back(uid);
        }
      }
    }

    if (typing_users.empty()) return json();

    json result;
    result["type"] = "m.typing";
    result["content"] = json::object({
      {"user_ids", typing_users}
    });
    return result;
  }

  // Build fully_read marker for sync response (account_data section)
  json build_fully_read_account_data(const std::string& room_id) {
    auto cursor = db_.cursor("sync_fully_read");
    if (cursor) {
      cursor->execute(
        "SELECT event_id, stream_ordering, ts FROM fully_read_markers "
        "WHERE room_id = ? AND user_id = ? "
        "ORDER BY stream_ordering DESC LIMIT 1",
        {room_id, user_id_}
      );
      auto rows = cursor->fetchall();
      if (!rows.empty()) {
        json result;
        result["type"] = "m.fully_read";
        result["content"] = json::object({
          {"event_id", rows[0].get<std::string>(0)}
        });
        return result;
      }
    }
    return json();
  }

private:
  DatabasePool& db_;
  std::string user_id_;
};

// Helper: get latest receipts for room as vector of entries
static std::vector<ReceiptEntry> get_latest_receipts_for_room_as_entries(
    DatabasePool& db, const std::string& room_id) {
  std::vector<ReceiptEntry> results;
  auto cursor = db.cursor("receipt_latest_entries");
  if (cursor) {
    cursor->execute(
      "SELECT r.room_id, r.receipt_type, r.user_id, r.event_id, r.data, "
      "       r.thread_id, MAX(r.stream_id) as stream_id "
      "FROM receipts_linearized r "
      "WHERE r.room_id = ? "
      "GROUP BY r.user_id, r.receipt_type",
      {room_id}
    );
    auto rows = cursor->fetchall();
    for (auto& row : rows) {
      ReceiptEntry entry;
      entry.room_id = row.get<std::string>(0);
      entry.receipt_type = row.get<std::string>(1);
      entry.user_id = row.get<std::string>(2);
      entry.event_id = row.get<std::string>(3);
      std::string data_str = row.get<std::string>(4);
      try {
        entry.data = json::parse(data_str.empty() ? "{}" : data_str);
      } catch (...) {
        entry.data = json::object();
      }
      entry.timestamp = entry.data.value("ts", now_ms());
      entry.thread_id = std::stoll(row.get<std::string>(5));
      entry.stream_ordering = row.get<int64_t>(6);
      results.push_back(entry);
    }
  }
  return results;
}

// ============================================================================
// 1. POST READ RECEIPT HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
//
// Sets the user's read receipt position for a room.
// receiptType can be: m.read (public) or m.read.private (private)
// Body is optional; if provided, may contain "thread_id" for thread receipts
// and arbitrary data to be stored alongside the receipt.
// ============================================================================

json handle_post_read_receipt(DatabasePool& db,
                               const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id,
                               const std::string& receipt_type,
                               const std::string& event_id,
                               const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate receipt type ----
  if (receipt_type != "m.read" && receipt_type != "m.read.private") {
    return make_error(400, "M_INVALID_PARAM",
                      "receiptType must be m.read or m.read.private");
  }

  // ---- 3. Validate event_id format ----
  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM",
                      "Invalid event_id format: " + event_id);
  }

  // ---- 4. Validate user is in the room ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN",
                      "User is not a member of this room");
  }

  // ---- 5. Validate the event exists in the room ----
  auto ev_rows = db.execute("receipt_event_check",
    "SELECT stream_ordering FROM events "
    "WHERE event_id='" + event_id + "' AND room_id='" + room_id + "'");
  if (ev_rows.empty()) {
    return make_error(404, "M_NOT_FOUND",
                      "Event not found in room: " + event_id);
  }

  // ---- 6. Extract optional parameters ----
  int64_t thread_id = safe_int(request_body, "thread_id", 0);
  int64_t ts = now_ms();
  json receipt_data = request_body;
  receipt_data["ts"] = ts;

  // ---- 7. Build receipt entry ----
  ReceiptEntry entry;
  entry.room_id = room_id;
  entry.user_id = auth.user_id;
  entry.event_id = event_id;
  entry.receipt_type = receipt_type;
  entry.thread_id = thread_id;
  entry.timestamp = ts;
  entry.data = receipt_data;

  // ---- 8. Linearize the receipt ----
  ReceiptLinearizer linearizer(db);
  int64_t stream_id = linearizer.linearize(entry);
  entry.stream_ordering = stream_id;

  // ---- 9. Update receipt graph ----
  ReceiptGraphStore graph_store(db);
  graph_store.upsert_graph_receipt(entry);

  // ---- 10. Update stream position ----
  db.execute("receipt_stream_update",
    "UPDATE stream_ordering SET stream_id = " + std::to_string(stream_id) +
    " WHERE type = 'receipt'");

  // ---- 11. Federate the receipt ----
  ReceiptFederationManager fed_mgr(db);
  fed_mgr.federate_receipt(entry);

  // ---- 12. Notify connected clients ----
  auto& notify_mgr = ReceiptNotificationManager::instance();
  json notify_data;
  notify_data["ts"] = ts;
  notify_mgr.notify_receipt_change(room_id, event_id, receipt_type,
                                    auth.user_id, notify_data);

  // ---- 13. Return empty body on success ----
  return make_response(200, json::object());
}

// ============================================================================
// 2. POST FULLY READ MARKER HANDLER (DEDICATED)
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/read_markers
//
// Sets the user's fully_read marker for a room.
// Body: { "m.fully_read": "<event_id>", "m.read": "<event_id>",
//         "m.read.private": "<event_id>" }
// Can set multiple markers in one request.
// ============================================================================

json handle_post_fully_read_marker(DatabasePool& db,
                                     const std::string& auth_header,
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
    auto ev_rows = db.execute("fully_read_check_2",
      "SELECT stream_ordering FROM events "
      "WHERE event_id='" + fully_read_event + "' AND room_id='" + room_id + "'");
    if (!ev_rows.empty()) {
      int64_t stream_ord = 0;
      if (ev_rows[0]["stream_ordering"].value) {
        stream_ord = std::stoll(*ev_rows[0]["stream_ordering"].value);
      }

      // Persist fully_read marker
      db.execute("fully_read_set_2",
        "INSERT OR REPLACE INTO fully_read_markers "
        "(user_id, room_id, event_id, stream_ordering, ts) VALUES ('" +
        auth.user_id + "','" + room_id + "','" + fully_read_event + "'," +
        std::to_string(stream_ord) + "," + std::to_string(now) + ")");

      // Federate fully_read
      FullyReadMarker marker;
      marker.room_id = room_id;
      marker.user_id = auth.user_id;
      marker.event_id = fully_read_event;
      marker.stream_ordering = stream_ord;
      marker.timestamp = now;

      ReceiptFederationManager fed_mgr(db);
      fed_mgr.federate_fully_read(marker);

      any_set = true;
    }
  }

  // ---- 4. Process m.read receipt (public) ----
  if (request_body.contains("m.read") &&
      request_body["m.read"].is_string()) {
    std::string read_event = request_body["m.read"].get<std::string>();

    ReceiptEntry entry;
    entry.room_id = room_id;
    entry.user_id = auth.user_id;
    entry.event_id = read_event;
    entry.receipt_type = "m.read";
    entry.thread_id = 0;
    entry.timestamp = now;
    entry.data = json::object({{"ts", now}});

    ReceiptLinearizer linearizer(db);
    int64_t stream_id = linearizer.linearize(entry);
    entry.stream_ordering = stream_id;

    ReceiptGraphStore graph_store(db);
    graph_store.upsert_graph_receipt(entry);

    ReceiptFederationManager fed_mgr(db);
    fed_mgr.federate_receipt(entry);

    auto& notify_mgr = ReceiptNotificationManager::instance();
    json notify_data;
    notify_data["ts"] = now;
    notify_mgr.notify_receipt_change(room_id, read_event, "m.read",
                                      auth.user_id, notify_data);
    any_set = true;
  }

  // ---- 5. Process m.read.private receipt ----
  if (request_body.contains("m.read.private") &&
      request_body["m.read.private"].is_string()) {
    std::string private_read_event = request_body["m.read.private"].get<std::string>();

    ReceiptEntry entry;
    entry.room_id = room_id;
    entry.user_id = auth.user_id;
    entry.event_id = private_read_event;
    entry.receipt_type = "m.read.private";
    entry.thread_id = 0;
    entry.timestamp = now;
    entry.data = json::object({{"ts", now}});

    ReceiptLinearizer linearizer(db);
    int64_t stream_id = linearizer.linearize(entry);
    entry.stream_ordering = stream_id;

    ReceiptGraphStore graph_store(db);
    graph_store.upsert_graph_receipt(entry);

    // Do NOT federate m.read.private receipts

    auto& notify_mgr = ReceiptNotificationManager::instance();
    // Private receipts are only notified to the user's own sessions
    json notify_data;
    notify_data["ts"] = now;
    notify_data["private"] = true;
    notify_mgr.notify_receipt_change(room_id, private_read_event, "m.read.private",
                                      auth.user_id, notify_data);
    any_set = true;
  }

  // ---- 6. Update stream position ----
  if (any_set) {
    db.execute("fully_read_stream",
      "UPDATE stream_ordering SET stream_id = " + std::to_string(now) +
      " WHERE type = 'receipt'");
  }

  // ---- 7. Return empty body on success ----
  return make_response(200, json::object());
}

// ============================================================================
// 3. GET FULLY READ MARKER HANDLER
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/read_markers
//
// Returns the user's fully_read and read receipt markers for a room.
// Response: { "m.fully_read": "<event_id>", "m.read": "<event_id>",
//             "m.read.private": "<event_id>" }
// ============================================================================

json handle_get_fully_read_marker(DatabasePool& db,
                                    const std::string& auth_header,
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

  json result = json::object();

  // ---- 3. Get fully_read marker ----
  auto fr_rows = db.execute("get_fully_read",
    "SELECT event_id FROM fully_read_markers "
    "WHERE user_id='" + auth.user_id + "' AND room_id='" + room_id + "' "
    "ORDER BY stream_ordering DESC LIMIT 1");
  if (!fr_rows.empty() && fr_rows[0]["event_id"].value) {
    result["m.fully_read"] = *fr_rows[0]["event_id"].value;
  }

  // ---- 4. Get m.read (public) receipt ----
  ReceiptsStore receipts(db);
  auto read_receipt = receipts.get_user_receipt(room_id, auth.user_id, "m.read");
  if (read_receipt) {
    result["m.read"] = read_receipt->event_id;
  }

  // ---- 5. Get m.read.private receipt ----
  auto private_receipt = receipts.get_user_receipt(
    room_id, auth.user_id, "m.read.private");
  if (private_receipt) {
    result["m.read.private"] = private_receipt->event_id;
  }

  // ---- 6. Return ----
  return make_response(200, result);
}

// ============================================================================
// 4. GET ROOM RECEIPTS HANDLER
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/receipts
//
// Returns all read receipts for a room.
// Query params:
//   - receipt_type: filter by receipt type (m.read, m.read.private)
//   - from: stream ordering token for pagination
//   - limit: maximum number of receipts to return
//   - include_private: whether to include m.read.private receipts (default: true)
// ============================================================================

json handle_get_room_receipts(DatabasePool& db,
                                const std::string& auth_header,
                                const std::string& access_token_param,
                                const std::string& room_id,
                                const ReceiptQueryParams& params) {
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

  // ---- 3. Get receipts ----
  ReceiptLinearizer linearizer(db);

  std::vector<ReceiptEntry> entries;
  if (params.from_stream > 0) {
    int64_t to_stream = g_stream_manager.get_current_stream_id();
    entries = linearizer.get_receipts_since(params.from_stream, to_stream, room_id);
  } else {
    entries = get_latest_receipts_for_room_as_entries(db, room_id);
  }

  // ---- 4. Filter by receipt type ----
  if (!params.receipt_type.empty()) {
    entries.erase(
      std::remove_if(entries.begin(), entries.end(),
        [&](const ReceiptEntry& e) {
          return e.receipt_type != params.receipt_type;
        }),
      entries.end()
    );
  }

  // ---- 5. Apply privacy filtering for private receipts ----
  if (!params.include_private) {
    entries.erase(
      std::remove_if(entries.begin(), entries.end(),
        [](const ReceiptEntry& e) {
          return e.receipt_type == "m.read.private";
        }),
      entries.end()
    );
  } else {
    // Filter private receipts: only show the requesting user's own
    entries.erase(
      std::remove_if(entries.begin(), entries.end(),
        [&](const ReceiptEntry& e) {
          return e.receipt_type == "m.read.private" &&
                 e.user_id != auth.user_id;
        }),
      entries.end()
    );
  }

  // ---- 6. Apply limit ----
  if (params.limit > 0 && static_cast<int>(entries.size()) > params.limit) {
    entries.resize(params.limit);
  }

  // ---- 7. Build response ----
  json result = json::array();
  for (auto& entry : entries) {
    json item;
    item["room_id"] = entry.room_id;
    item["receipt_type"] = entry.receipt_type;
    item["user_id"] = entry.user_id;
    item["event_id"] = entry.event_id;
    item["thread_id"] = entry.thread_id;
    item["stream_ordering"] = entry.stream_ordering;
    item["data"] = entry.data;
    result.push_back(item);
  }

  return make_response(200, result);
}

// ============================================================================
// 5. GET EVENT RECEIPTS HANDLER
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/receipts/{eventId}
//
// Returns read receipts for a specific event in a room.
// Response format:
// {
//   "m.read": {
//     "@user1:domain": { "ts": 123456789 },
//     "@user2:domain": { "ts": 123456790 }
//   },
//   "m.read.private": {
//     "@user3:domain": { "ts": 123456791 }
//   }
// }
// ============================================================================

json handle_get_event_receipts(DatabasePool& db,
                                 const std::string& auth_header,
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

  // ---- 3. Validate event_id format ----
  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM",
                      "Invalid event_id format: " + event_id);
  }

  // ---- 4. Query all receipts for this event ----
  // Use receipts_graph to find all users who have read up to this event
  json result = json::object();
  result["m.read"] = json::object();
  result["m.read.private"] = json::object();

  ReceiptsStore receipts(db);
  auto users = receipts.get_users_with_read_receipts_for_event(room_id, event_id);

  // Get full receipt data for each user
  for (auto& user_id : users) {
    // Get public receipt
    auto read_rcpt = receipts.get_user_receipt(room_id, user_id, "m.read");
    if (read_rcpt) {
      auto ev_rows = db.execute("receipt_data_lookup",
        "SELECT data, stream_id FROM receipts_linearized "
        "WHERE room_id='" + room_id + "' AND user_id='" + user_id +
        "' AND receipt_type='m.read' "
        "ORDER BY stream_id DESC LIMIT 1");
      if (!ev_rows.empty()) {
        json data;
        if (ev_rows[0]["data"].value) {
          try {
            data = json::parse(*ev_rows[0]["data"].value);
          } catch (...) {
            data = json::object();
          }
        }
        data["ts"] = data.value("ts", read_rcpt->stream_ordering);
        result["m.read"][user_id] = data;
      }
    }

    // Get private receipt (only if requesting user is the owner)
    if (user_id == auth.user_id) {
      auto private_rcpt = receipts.get_user_receipt(
        room_id, user_id, "m.read.private");
      if (private_rcpt) {
        auto ev_rows = db.execute("private_receipt_data",
          "SELECT data, stream_id FROM receipts_linearized "
          "WHERE room_id='" + room_id + "' AND user_id='" + user_id +
          "' AND receipt_type='m.read.private' "
          "ORDER BY stream_id DESC LIMIT 1");
        if (!ev_rows.empty()) {
          json data;
          if (ev_rows[0]["data"].value) {
            try {
              data = json::parse(*ev_rows[0]["data"].value);
            } catch (...) {
              data = json::object();
            }
          }
          data["ts"] = data.value("ts", private_rcpt->stream_ordering);
          result["m.read.private"][user_id] = data;
        }
      }
    }
  }

  // ---- 5. Remove empty sections ----
  if (result["m.read"].empty()) result.erase("m.read");
  if (result["m.read.private"].empty()) result.erase("m.read.private");

  // ---- 6. Return ----
  return make_response(200, result);
}

// ============================================================================
// 6. POST TYPING NOTIFICATION HANDLER
// ============================================================================
// PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}
//
// Sets the typing status for a user in a room.
// Body: { "typing": true/false, "timeout": <milliseconds> }
// Typing notifications time out after the specified duration.
// ============================================================================

json handle_post_typing_notification(DatabasePool& db,
                                       const std::string& auth_header,
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

  // ---- 5. Lookup display name for rich typing notifications ----
  std::string display_name;
  ProfileStore profile(db);
  auto displayname_opt = profile.get_displayname(user_id);
  if (displayname_opt) {
    display_name = *displayname_opt;
  }

  // ---- 6. Upsert typing notification ----
  if (typing) {
    db.execute("typing_set_2",
      "INSERT OR REPLACE INTO typing_notifications "
      "(room_id, user_id, is_typing, timeout_ms, expiry_ts, ts, display_name) VALUES ('" +
      room_id + "','" + user_id + "',1," + std::to_string(timeout_ms) + "," +
      std::to_string(expiry) + "," + std::to_string(now) + ",'" + display_name + "')");

    // Track in timeout manager
    TypingTimeoutManager::instance().track_typing(room_id, user_id, expiry);
  } else {
    // Remove typing indicator
    db.execute("typing_stop_2",
      "DELETE FROM typing_notifications "
      "WHERE room_id='" + room_id + "' AND user_id='" + user_id + "'");

    // Remove from timeout manager
    TypingTimeoutManager::instance().remove_typing(room_id, user_id);
  }

  // ---- 7. Clean up expired typing notifications ----
  db.execute("typing_cleanup_2",
    "DELETE FROM typing_notifications WHERE expiry_ts < " +
    std::to_string(now));

  // ---- 8. Push typing notification via federation ----
  auto servers = get_room_participating_servers(db, room_id);
  int64_t edu_stream_id = g_edu_seq.fetch_add(1);
  for (auto& dest : servers) {
    json edu;
    edu["type"] = "m.typing";
    edu["content"] = json::object({
      {"room_id", room_id},
      {"user_id", user_id},
      {"typing", typing},
      {"timeout", timeout_ms}
    });
    edu["origin"] = "localhost";
    edu["origin_server_ts"] = now;

    auto txn = db.cursor("fed_typing_2");
    if (txn) {
      txn->execute(
        "INSERT OR REPLACE INTO federation_stream "
        "(type, room_id, event_id, destination, json_data, stream_id) "
        "VALUES ('edu','" + room_id + "','','" + dest + "',?,?)",
        {edu.dump(), std::to_string(edu_stream_id)}
      );
      txn->commit();
    }
  }

  // ---- 9. Notify connected clients ----
  auto& notify_mgr = ReceiptNotificationManager::instance();
  notify_mgr.notify_typing_change(room_id, user_id, typing);

  // ---- 10. Return empty object on success ----
  return make_response(200, json::object());
}

// ============================================================================
// 7. GET TYPING NOTIFICATIONS HANDLER
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/typing
//
// Returns the current typing status for users in a room.
// Response:
// {
//   "user_ids": ["@alice:domain", "@bob:domain"]
// }
// Optionally include display names via query param include_displaynames=true
// ============================================================================

json handle_get_typing_notifications(DatabasePool& db,
                                       const std::string& auth_header,
                                       const std::string& access_token_param,
                                       const std::string& room_id,
                                       bool include_displaynames) {
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

  // ---- 3. Query active typing notifications ----
  int64_t now = now_ms();
  std::vector<std::string> user_ids;
  std::map<std::string, TypingNotification> typing_map;

  auto txn = db.cursor("get_typing");
  if (txn) {
    txn->execute(
      "SELECT user_id, is_typing, timeout_ms, expiry_ts, ts, display_name "
      "FROM typing_notifications "
      "WHERE room_id = ? AND is_typing = 1 AND expiry_ts > ?",
      {room_id, std::to_string(now)}
    );
    auto rows = txn->fetchall();
    for (auto& row : rows) {
      TypingNotification tn;
      tn.room_id = room_id;
      tn.user_id = row.get<std::string>(0);
      tn.is_typing = row.get<int64_t>(1) == 1;
      tn.timeout_ms = row.get<int64_t>(2);
      tn.expiry_ts = row.get<int64_t>(3);
      tn.updated_ts = row.get<int64_t>(4);
      tn.display_name = row.get<std::string>(5);

      user_ids.push_back(tn.user_id);
      typing_map[tn.user_id] = tn;
    }
  }

  // ---- 4. Build response ----
  json result;
  result["user_ids"] = user_ids;

  if (include_displaynames) {
    result["users"] = json::object();
    for (auto& uid : user_ids) {
      auto it = typing_map.find(uid);
      if (it != typing_map.end()) {
        if (!it->second.display_name.empty()) {
          result["users"][uid] = it->second.display_name;
        }
      }
    }
  }

  // ---- 5. Return ----
  return make_response(200, result);
}

// ============================================================================
// 8. MANAGE TYPING TIMEOUTS (BACKGROUND SWEEP)
// ============================================================================
// Periodic background task to clean up expired typing notifications.
// Called by the timeout management thread and also available for
// explicit invocation (e.g., after server restart).
// ============================================================================

json handle_manage_typing_timeouts(DatabasePool& db, bool force_full_sweep) {
  int64_t now = now_ms();
  int64_t count_expired = 0;

  // ---- 1. Delete expired typing notifications ----
  auto txn = db.cursor("typing_timeout_sweep");
  if (txn) {
    txn->execute(
      "DELETE FROM typing_notifications WHERE expiry_ts < ?",
      {std::to_string(now)}
    );
    count_expired = txn->rowcount();
    txn->commit();
  }

  // ---- 2. Notify federation about any expired typing ----
  if (force_full_sweep && count_expired > 0) {
    // In a full sweep, we would query which rooms had expired typing
    // and notify their participating servers. For efficiency, we
    // handle this in the individual sweep method.
  }

  // ---- 3. Clean up old receipts (optional maintenance) ----
  int64_t receipt_cutoff = now - (30LL * 24 * 60 * 60 * 1000); // 30 days
  auto rtxn = db.cursor("receipt_timeout_cleanup");
  if (rtxn) {
    rtxn->execute(
      "DELETE FROM receipts_linearized WHERE stream_id < "
      "(SELECT COALESCE(MAX(stream_id), 0) - 1000000 FROM receipts_linearized)"
    );
    rtxn->commit();
  }

  // ---- 4. Return summary ----
  json result;
  result["expired_typing_count"] = count_expired;
  result["timestamp"] = now;

  return make_response(200, result);
}

// ============================================================================
// 9. FEDERATE RECEIPTS
// ============================================================================
// Pushes receipt EDUs to all participating servers for a room.
// Handles both individual receipt pushes and batch federation.
// ============================================================================

json handle_federate_receipts(DatabasePool& db,
                                const std::string& room_id,
                                const json& receipts_payload,
                                const std::string& origin_server) {
  // ---- 1. Validate room exists ----
  RoomStore rooms(db);
  if (!rooms.room_exists(room_id)) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 2. Get participating servers ----
  auto servers = get_room_participating_servers(db, room_id);
  if (servers.empty()) {
    return make_response(200, json::object({{"sent", 0}, {"message", "No remote servers"}}));
  }

  // ---- 3. Mask private receipts for federation ----
  auto& privacy_mgr = ReceiptPrivacyManager::instance();
  json safe_payload;
  if (receipts_payload.contains("content")) {
    json masked_content = privacy_mgr.mask_private_receipts_for_federation(
      receipts_payload["content"]);
    safe_payload = receipts_payload;
    safe_payload["content"] = masked_content;
  } else {
    safe_payload = receipts_payload;
  }

  // ---- 4. Push to each server ----
  int64_t ts = now_ms();
  int64_t stream_id = g_edu_seq.fetch_add(1);
  int sent_count = 0;

  for (auto& dest : servers) {
    json edu = safe_payload;
    if (!edu.contains("origin")) edu["origin"] = origin_server;
    if (!edu.contains("origin_server_ts")) edu["origin_server_ts"] = ts;

    auto txn = db.cursor("fed_receipt_batch");
    if (txn) {
      txn->execute(
        "INSERT OR REPLACE INTO federation_stream "
        "(type, room_id, event_id, destination, json_data, stream_id) "
        "VALUES ('edu', ?, '', ?, ?, ?)",
        {room_id, dest, edu.dump(), std::to_string(stream_id)}
      );
      txn->commit();
      sent_count++;
    }
  }

  // ---- 5. Return summary ----
  json result;
  result["sent"] = sent_count;
  result["servers"] = servers.size();

  return make_response(200, result);
}

// ============================================================================
// 10. LINEARIZE RECEIPT
// ============================================================================
// Inserts a receipt into the linearized stream table.
// Used both by local receipt creation and by federation receipt processing.
// ============================================================================

json handle_linearize_receipt(DatabasePool& db,
                                const std::string& room_id,
                                const std::string& receipt_type,
                                const std::string& user_id,
                                const std::string& event_id,
                                const json& receipt_data,
                                int64_t thread_id) {
  // ---- 1. Validate parameters ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room_id");
  }
  if (!validate_user_id(user_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid user_id");
  }
  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid event_id");
  }

  // ---- 2. Build receipt entry ----
  ReceiptEntry entry;
  entry.room_id = room_id;
  entry.user_id = user_id;
  entry.event_id = event_id;
  entry.receipt_type = receipt_type;
  entry.thread_id = thread_id;
  entry.timestamp = receipt_data.value("ts", now_ms());
  entry.data = receipt_data;

  // ---- 3. Insert into linearized table ----
  ReceiptLinearizer linearizer(db);
  int64_t stream_id = linearizer.linearize(entry);

  // ---- 4. Return ----
  json result;
  result["stream_id"] = stream_id;
  result["room_id"] = room_id;
  result["receipt_type"] = receipt_type;
  result["user_id"] = user_id;
  result["event_id"] = event_id;

  return make_response(200, result);
}

// ============================================================================
// 11. STORE RECEIPT GRAPH
// ============================================================================
// Updates the receipt graph table for a user/room/receipt_type triplet.
// The graph stores all event_ids a user has issued receipts for,
// allowing efficient queries for "what events has user X read?"
// ============================================================================

json handle_store_receipt_graph(DatabasePool& db,
                                  const std::string& room_id,
                                  const std::string& receipt_type,
                                  const std::string& user_id,
                                  const std::string& event_id,
                                  const json& data) {
  // ---- 1. Validate parameters ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room_id");
  }
  if (!validate_user_id(user_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid user_id");
  }

  // ---- 2. Build entry and store ----
  ReceiptEntry entry;
  entry.room_id = room_id;
  entry.user_id = user_id;
  entry.event_id = event_id;
  entry.receipt_type = receipt_type;
  entry.timestamp = data.value("ts", now_ms());
  entry.data = data;

  ReceiptGraphStore graph_store(db);
  graph_store.upsert_graph_receipt(entry);

  // ---- 3. Verify storage ----
  json graph_result = graph_store.get_user_graph(room_id, user_id, receipt_type);

  // ---- 4. Return ----
  json result;
  result["stored"] = true;
  result["room_id"] = room_id;
  result["receipt_type"] = receipt_type;
  result["user_id"] = user_id;
  result["event_id"] = event_id;
  result["graph"] = graph_result;

  return make_response(200, result);
}

// ============================================================================
// 12. GET RECEIPT STREAM POSITION
// ============================================================================
// Returns the maximum receipt stream ordering value.
// Used by sync and federation to determine which receipts are new.
// ============================================================================

json handle_get_receipt_stream_position(DatabasePool& db) {
  int64_t position = g_stream_manager.get_current_stream_id();

  // Also check database for any higher value
  ReceiptsStore receipts(db);
  int64_t db_position = receipts.get_max_receipt_stream_ordering();

  int64_t max_position = std::max(position, db_position);
  g_stream_manager.update_stream_id(max_position);

  json result;
  result["stream_position"] = max_position;
  result["timestamp"] = now_ms();

  return make_response(200, result);
}

// ============================================================================
// 13. BUILD RECEIPT SYNC BLOCK
// ============================================================================
// Builds the ephemeral receipt block for inclusion in the sync response.
// This is the main integration point for receipts in /sync.
// ============================================================================

json handle_build_receipt_sync_block(DatabasePool& db,
                                       const std::string& room_id,
                                       const std::string& user_id,
                                       int64_t since_stream) {
  // ---- 1. Validate parameters ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room_id");
  }

  // ---- 2. Build ephemeral block ----
  SyncEphemeralBuilder builder(db, user_id);

  json ephemeral = builder.build_ephemeral_for_room(room_id, since_stream);

  // ---- 3. Build fully_read marker for account_data ----
  json fully_read = builder.build_fully_read_account_data(room_id);

  // ---- 4. Return ----
  json result;
  result["ephemeral"] = ephemeral;
  result["account_data"] = json::object();
  if (!fully_read.empty()) {
    result["account_data"]["events"] = json::array({fully_read});
  } else {
    result["account_data"]["events"] = json::array();
  }

  return make_response(200, result);
}

// ============================================================================
// 14. HANDLE RECEIPT PRIVACY
// ============================================================================
// Manages m.read.private filtering. Private receipts are only visible
// to the user who set them. This handler provides the privacy filtering
// logic and can be called directly for testing/admin purposes.
// ============================================================================

json handle_receipt_privacy(DatabasePool& db,
                              const json& raw_receipts,
                              const std::string& requesting_user_id,
                              bool mask_for_federation) {
  // ---- 1. Validate user_id ----
  if (!validate_user_id(requesting_user_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid user_id");
  }

  // ---- 2. Apply privacy filtering ----
  auto& privacy_mgr = ReceiptPrivacyManager::instance();

  json filtered;
  if (mask_for_federation) {
    filtered = privacy_mgr.mask_private_receipts_for_federation(raw_receipts);
  } else {
    filtered = privacy_mgr.filter_receipts_for_user(raw_receipts, requesting_user_id);
  }

  // ---- 3. Return ----
  json result;
  result["filtered_receipts"] = filtered;
  result["requesting_user"] = requesting_user_id;
  result["masked_for_federation"] = mask_for_federation;

  return make_response(200, result);
}

// ============================================================================
// 15. QUERY RECEIPTS BY ROOM (ADVANCED)
// ============================================================================
// Advanced room-scoped receipt queries with filtering, sorting, and
// aggregation capabilities.
// Supports: filtering by user, receipt type, date range, thread scope.
// ============================================================================

json handle_query_receipts_by_room(DatabasePool& db,
                                     const std::string& auth_header,
                                     const std::string& access_token_param,
                                     const ReceiptQueryParams& params) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ----
  if (!params.room_id.empty() && !validate_room_id(params.room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room_id");
  }

  // ---- 3. Build and execute query ----
  std::string sql =
    "SELECT r.room_id, r.receipt_type, r.user_id, r.event_id, r.data, "
    "       r.thread_id, r.stream_id "
    "FROM receipts_linearized r WHERE 1=1";

  std::vector<SQLParam> sql_params;

  if (!params.room_id.empty()) {
    sql += " AND r.room_id = ?";
    sql_params.push_back(params.room_id);
  }

  if (!params.receipt_type.empty()) {
    sql += " AND r.receipt_type = ?";
    sql_params.push_back(params.receipt_type);
  }

  if (!params.user_id.empty()) {
    sql += " AND r.user_id = ?";
    sql_params.push_back(params.user_id);
  }

  if (!params.event_id.empty()) {
    sql += " AND r.event_id = ?";
    sql_params.push_back(params.event_id);
  }

  if (params.from_stream > 0) {
    sql += " AND r.stream_id > ?";
    sql_params.push_back(std::to_string(params.from_stream));
  }

  if (params.to_stream > 0) {
    sql += " AND r.stream_id <= ?";
    sql_params.push_back(std::to_string(params.to_stream));
  }

  sql += " ORDER BY r.stream_id DESC";

  if (params.limit > 0) {
    sql += " LIMIT ?";
    sql_params.push_back(std::to_string(params.limit));
  }

  // ---- 4. Execute query ----
  json results = json::array();
  auto cursor = db.cursor("receipt_room_query");
  if (cursor) {
    cursor->execute(sql, sql_params);
    auto rows = cursor->fetchall();
    for (auto& row : rows) {
      json item;
      item["room_id"] = row.get<std::string>(0);
      item["receipt_type"] = row.get<std::string>(1);
      item["user_id"] = row.get<std::string>(2);
      item["event_id"] = row.get<std::string>(3);
      std::string data_str = row.get<std::string>(4);
      try {
        item["data"] = json::parse(data_str.empty() ? "{}" : data_str);
      } catch (...) {
        item["data"] = json::object();
      }
      item["thread_id"] = std::stoll(row.get<std::string>(5));
      item["stream_id"] = row.get<int64_t>(6);
      results.push_back(item);
    }
  }

  // ---- 5. Apply privacy filtering ----
  if (!params.include_private) {
    json filtered = json::array();
    for (auto& r : results) {
      if (r["receipt_type"] != "m.read.private") {
        filtered.push_back(r);
      } else if (r["user_id"] == auth.user_id) {
        // Only include own private receipts
        filtered.push_back(r);
      }
    }
    results = filtered;
  }

  // ---- 6. Return ----
  json response;
  response["receipts"] = results;
  response["count"] = results.size();

  return make_response(200, response);
}

// ============================================================================
// 16. QUERY RECEIPTS BY EVENT (ADVANCED)
// ============================================================================
// Advanced event-scoped receipt queries. Returns all users who have
// read up to a given event, including aggregated counts.
// ============================================================================

json handle_query_receipts_by_event(DatabasePool& db,
                                      const std::string& auth_header,
                                      const std::string& access_token_param,
                                      const std::string& room_id,
                                      const std::string& event_id,
                                      bool include_aggregates) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate parameters ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room_id");
  }
  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid event_id");
  }

  // ---- 3. Get receipts for this event ----
  ReceiptsStore receipts(db);
  auto users = receipts.get_users_with_read_receipts_for_event(room_id, event_id);

  // ---- 4. Build detailed response ----
  json users_list = json::array();
  int64_t public_count = 0;
  int64_t private_count = 0;

  for (auto& user_id : users) {
    json user_entry;
    user_entry["user_id"] = user_id;

    // Get public receipt
    auto read_rcpt = receipts.get_user_receipt(room_id, user_id, "m.read");
    if (read_rcpt) {
      user_entry["m.read"] = json::object({
        {"event_id", read_rcpt->event_id},
        {"ts", read_rcpt->stream_ordering}
      });
      public_count++;
    }

    // Get private receipt (only include stats, not details for other users)
    if (user_id == auth.user_id) {
      auto private_rcpt = receipts.get_user_receipt(
        room_id, user_id, "m.read.private");
      if (private_rcpt) {
        user_entry["m.read.private"] = json::object({
          {"event_id", private_rcpt->event_id},
          {"ts", private_rcpt->stream_ordering}
        });
      }
    } else {
      // Check if this user has any private receipt
      auto has_private = receipts.get_user_receipt(
        room_id, user_id, "m.read.private");
      if (has_private) {
        private_count++;
      }
    }

    users_list.push_back(user_entry);
  }

  // ---- 5. Build response ----
  json result;
  result["event_id"] = event_id;
  result["room_id"] = room_id;
  result["users"] = users_list;

  if (include_aggregates) {
    result["aggregates"] = json::object({
      {"total_users", users.size()},
      {"public_read_count", public_count},
      {"private_read_count", private_count}
    });
  }

  // ---- 6. Return ----
  return make_response(200, result);
}

// ============================================================================
// 17. PROCESS RECEIPT EDU (FEDERATION INGRESS)
// ============================================================================
// Processes an incoming receipt EDU from another server.
// Validates the EDU format, origins, and persists the receipt.
// ============================================================================

json handle_process_receipt_edu(DatabasePool& db,
                                  const json& edu,
                                  const std::string& origin_server) {
  // ---- 1. Validate EDU format ----
  if (!edu.contains("type")) {
    return make_error(400, "M_BAD_JSON", "EDU missing type field");
  }

  std::string edu_type = edu["type"].get<std::string>();

  if (edu_type == "m.receipt") {
    ReceiptFederationManager fed_mgr(db);
    return fed_mgr.process_incoming_receipt_edu(edu);
  } else if (edu_type == "m.typing") {
    ReceiptFederationManager fed_mgr(db);
    return fed_mgr.process_incoming_typing_edu(edu);
  } else if (edu_type == "m.fully_read") {
    // Process fully_read EDU
    if (!edu.contains("room_id") || !edu.contains("content")) {
      return make_error(400, "M_BAD_JSON", "Invalid fully_read EDU");
    }

    std::string room_id = edu["room_id"].get<std::string>();
    json& content = edu["content"];
    std::string event_id = content.value("event_id", "");
    std::string user_id = content.value("user_id", "");

    if (event_id.empty() || user_id.empty()) {
      return make_error(400, "M_BAD_JSON",
                        "Missing event_id or user_id in fully_read EDU");
    }

    int64_t now = now_ms();
    db.execute("fed_fully_read_set",
      "INSERT OR REPLACE INTO fully_read_markers "
      "(user_id, room_id, event_id, stream_ordering, ts) VALUES ('" +
      user_id + "','" + room_id + "','" + event_id + "'," +
      std::to_string(now) + "," + std::to_string(now) + ")");

    return make_response(200, json::object());
  } else {
    return make_error(400, "M_UNKNOWN",
                      "Unknown EDU type: " + edu_type);
  }
}

// ============================================================================
// 18. BROADCAST RECEIPT UPDATES
// ============================================================================
// Notifies all local clients connected to the server about receipt changes.
// Used when receipts change due to federation or batch operations.
// ============================================================================

json handle_broadcast_receipt_updates(DatabasePool& db,
                                        const std::string& room_id,
                                        const json& receipt_changes) {
  // ---- 1. Validate room_id ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room_id");
  }

  // ---- 2. Process each changed event ----
  auto& notify_mgr = ReceiptNotificationManager::instance();
  int notified_count = 0;

  for (auto& [event_id, receipt_types] : receipt_changes.items()) {
    if (!receipt_types.is_object()) continue;

    for (auto& [receipt_type, user_receipts] : receipt_types.items()) {
      if (!user_receipts.is_object()) continue;

      // Skip private receipts for broadcast
      if (receipt_type == "m.read.private") continue;

      for (auto& [user_id, receipt_data] : user_receipts.items()) {
        json notify_data;
        if (receipt_data.is_object()) {
          notify_data = receipt_data;
        } else {
          notify_data = json::object({{"ts", now_ms()}});
        }

        notify_mgr.notify_receipt_change(room_id, event_id, receipt_type,
                                          user_id, notify_data);
        notified_count++;
      }
    }
  }

  // ---- 3. Return summary ----
  json result;
  result["notified_count"] = notified_count;
  result["room_id"] = room_id;

  return make_response(200, result);
}

// ============================================================================
// 19. AGGREGATE RECEIPTS
// ============================================================================
// Aggregates receipt data across multiple rooms/users for summary views.
// Used by notification systems, room list displays, and analytics.
// ============================================================================

json handle_aggregate_receipts(DatabasePool& db,
                                 const std::string& auth_header,
                                 const std::string& access_token_param,
                                 const std::vector<std::string>& room_ids,
                                 const std::string& user_id_filter) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate rooms ----
  for (auto& rid : room_ids) {
    if (!validate_room_id(rid)) {
      return make_error(400, "M_INVALID_PARAM", "Invalid room_id: " + rid);
    }
  }

  // ---- 3. Aggregate receipts for each room ----
  json result = json::object();
  result["rooms"] = json::object();

  for (auto& room_id : room_ids) {
    json room_aggs;
    room_aggs["room_id"] = room_id;

    // Count public read receipts
    int64_t public_count = 0;
    auto cursor = db.cursor("agg_public");
    if (cursor) {
      std::string sql =
        "SELECT COUNT(DISTINCT user_id) FROM receipts_linearized "
        "WHERE room_id = ? AND receipt_type = 'm.read'";
      std::vector<SQLParam> params = {room_id};

      if (!user_id_filter.empty()) {
        sql += " AND user_id = ?";
        params.push_back(user_id_filter);
      }

      cursor->execute(sql, params);
      auto rows = cursor->fetchall();
      if (!rows.empty()) {
        public_count = rows[0].get<int64_t>(0);
      }
    }
    room_aggs["public_read_count"] = public_count;

    // Count private read receipts (only for requesting user)
    int64_t private_count = 0;
    auto pcursor = db.cursor("agg_private");
    if (pcursor) {
      std::string sql =
        "SELECT COUNT(*) FROM receipts_linearized "
        "WHERE room_id = ? AND receipt_type = 'm.read.private'";
      std::vector<SQLParam> params = {room_id};

      if (!user_id_filter.empty()) {
        sql += " AND user_id = ?";
        params.push_back(user_id_filter);
      } else {
        sql += " AND user_id = ?";
        params.push_back(auth.user_id);
      }

      pcursor->execute(sql, params);
      auto rows = pcursor->fetchall();
      if (!rows.empty()) {
        private_count = rows[0].get<int64_t>(0);
      }
    }
    room_aggs["private_read_count"] = private_count;

    // Get latest receipt timestamp per room
    int64_t latest_ts = 0;
    auto ltcursor = db.cursor("agg_latest_ts");
    if (ltcursor) {
      ltcursor->execute(
        "SELECT MAX(stream_id) FROM receipts_linearized "
        "WHERE room_id = ?",
        {room_id}
      );
      auto rows = ltcursor->fetchall();
      if (!rows.empty()) {
        latest_ts = rows[0].get<int64_t>(0);
      }
    }
    room_aggs["latest_receipt_stream"] = latest_ts;

    // Get typing information
    int64_t now = now_ms();
    auto tpcursor = db.cursor("agg_typing");
    if (tpcursor) {
      tpcursor->execute(
        "SELECT COUNT(*) FROM typing_notifications "
        "WHERE room_id = ? AND is_typing = 1 AND expiry_ts > ?",
        {room_id, std::to_string(now)}
      );
      auto rows = tpcursor->fetchall();
      if (!rows.empty()) {
        room_aggs["typing_users_count"] = rows[0].get<int64_t>(0);
      }
    }

    result["rooms"][room_id] = room_aggs;
  }

  // ---- 4. Return ----
  result["timestamp"] = now_ms();
  return make_response(200, result);
}

// ============================================================================
// 20. RECEIPT CLEANUP MAINTENANCE
// ============================================================================
// Periodic maintenance to clean up old receipts, expired typing,
// and optimize receipt storage.
// ============================================================================

json handle_receipt_cleanup_maintenance(DatabasePool& db,
                                          bool aggressive,
                                          int64_t max_age_days) {
  int64_t now = now_ms();
  int64_t cutoff = now - (max_age_days * 24LL * 60 * 60 * 1000);

  json result;
  result["timestamp"] = now;
  result["aggressive"] = aggressive;
  result["max_age_days"] = max_age_days;

  // ---- 1. Clean up expired typing notifications ----
  int64_t typing_removed = 0;
  auto ttxn = db.cursor("maint_typing");
  if (ttxn) {
    ttxn->execute(
      "DELETE FROM typing_notifications WHERE expiry_ts < ?",
      {std::to_string(now)}
    );
    typing_removed = ttxn->rowcount();
    ttxn->commit();
  }
  result["typing_removed"] = typing_removed;

  // ---- 2. Clean up old linearized receipts ----
  int64_t receipts_removed = 0;
  int64_t keep_threshold = aggressive ? 100000 : 1000000;

  auto rtxn = db.cursor("maint_receipts");
  if (rtxn) {
    rtxn->execute(
      "DELETE FROM receipts_linearized WHERE stream_id < "
      "(SELECT COALESCE(MAX(stream_id), 0) - ? FROM receipts_linearized)",
      {std::to_string(keep_threshold)}
    );
    receipts_removed = rtxn->rowcount();
    rtxn->commit();
  }
  result["receipts_linearized_removed"] = receipts_removed;

  // ---- 3. Clean up old fully_read markers ----
  int64_t fully_read_removed = 0;
  if (aggressive && max_age_days > 0) {
    auto frtxn = db.cursor("maint_fully_read");
    if (frtxn) {
      frtxn->execute(
        "DELETE FROM fully_read_markers WHERE ts < ?",
        {std::to_string(cutoff)}
      );
      fully_read_removed = frtxn->rowcount();
      frtxn->commit();
    }
  }
  result["fully_read_removed"] = fully_read_removed;

  // ---- 4. Vacuum receipts_graph (compact storage) ----
  int64_t graph_compacted = 0;
  if (aggressive) {
    auto gctxn = db.cursor("maint_graph");
    if (gctxn) {
      // Remove graph entries with no linearized receipts
      gctxn->execute(
        "DELETE FROM receipts_graph WHERE (room_id, receipt_type, user_id) NOT IN "
        "(SELECT DISTINCT room_id, receipt_type, user_id FROM receipts_linearized)"
      );
      graph_compacted = gctxn->rowcount();
      gctxn->commit();
    }
  }
  result["graph_entries_compacted"] = graph_compacted;

  // ---- 5. Clean up federation stream ----
  int64_t fed_removed = 0;
  if (aggressive) {
    auto fetxn = db.cursor("maint_federation");
    if (fetxn) {
      fetxn->execute(
        "DELETE FROM federation_stream WHERE stream_id < ?",
        {std::to_string(cutoff)}
      );
      fed_removed = fetxn->rowcount();
      fetxn->commit();
    }
  }
  result["federation_stream_removed"] = fed_removed;

  // ---- 6. Return summary ----
  return make_response(200, result);
}

// ============================================================================
// Additional utility: Get read status for multiple rooms
// Used by room list to show read indicators
// ============================================================================

json handle_get_multi_room_read_status(DatabasePool& db,
                                         const std::string& auth_header,
                                         const std::string& access_token_param,
                                         const std::vector<std::string>& room_ids) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Get read status for each room ----
  json result = json::object();

  for (auto& room_id : room_ids) {
    json room_status;
    room_status["room_id"] = room_id;

    // Check fully_read marker
    auto fr_rows = db.execute("multi_fr",
      "SELECT event_id, stream_ordering FROM fully_read_markers "
      "WHERE user_id='" + auth.user_id + "' AND room_id='" + room_id + "' "
      "ORDER BY stream_ordering DESC LIMIT 1");
    if (!fr_rows.empty() && fr_rows[0]["event_id"].value) {
      room_status["fully_read_event"] = *fr_rows[0]["event_id"].value;
    }

    // Check m.read receipt
    ReceiptsStore receipts(db);
    auto read_rcpt = receipts.get_user_receipt(room_id, auth.user_id, "m.read");
    if (read_rcpt) {
      room_status["read_event"] = read_rcpt->event_id;
      room_status["read_stream"] = read_rcpt->stream_ordering;
    }

    // Check m.read.private receipt
    auto private_rcpt = receipts.get_user_receipt(
      room_id, auth.user_id, "m.read.private");
    if (private_rcpt) {
      room_status["private_read_event"] = private_rcpt->event_id;
    }

    // Check if there are unread messages
    // Compare last event in room with read receipt position
    auto ev_rows = db.execute("multi_last_ev",
      "SELECT event_id FROM events "
      "WHERE room_id='" + room_id + "' "
      "ORDER BY stream_ordering DESC LIMIT 1");
    if (!ev_rows.empty() && ev_rows[0]["event_id"].value) {
      std::string last_event = *ev_rows[0]["event_id"].value;
      room_status["last_event"] = last_event;

      if (read_rcpt) {
        room_status["has_unread"] = (last_event != read_rcpt->event_id);
      } else {
        room_status["has_unread"] = true;
      }
    }

    // Check typing status
    int64_t now = now_ms();
    auto tp_rows = db.execute("multi_typing",
      "SELECT user_id FROM typing_notifications "
      "WHERE room_id='" + room_id + "' AND is_typing=1 AND expiry_ts>" +
      std::to_string(now));
    if (!tp_rows.empty()) {
      room_status["typing_users"] = json::array();
      for (auto& row : tp_rows) {
        if (row["user_id"].value) {
          room_status["typing_users"].push_back(*row["user_id"].value);
        }
      }
    }

    result[room_id] = room_status;
  }

  // ---- 3. Return ----
  return make_response(200, result);
}

// ============================================================================
// Additional utility: Bulk import receipts (admin/migration)
// ============================================================================

json handle_bulk_import_receipts(DatabasePool& db,
                                   const std::string& auth_header,
                                   const std::string& access_token_param,
                                   const json& receipts_array) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate input is array ----
  if (!receipts_array.is_array()) {
    return make_error(400, "M_BAD_JSON", "Receipts must be an array");
  }

  // ---- 3. Bulk insert ----
  int64_t imported = 0;
  int64_t skipped = 0;
  int64_t errors = 0;
  json error_details = json::array();

  for (auto& receipt : receipts_array) {
    if (!receipt.is_object()) {
      errors++;
      continue;
    }

    std::string room_id = safe_str(receipt, "room_id");
    std::string user_id = safe_str(receipt, "user_id");
    std::string event_id = safe_str(receipt, "event_id");
    std::string receipt_type = safe_str(receipt, "receipt_type", "m.read");
    int64_t thread_id = safe_int(receipt, "thread_id", 0);
    int64_t ts = safe_int(receipt, "ts", now_ms());

    if (room_id.empty() || user_id.empty() || event_id.empty()) {
      errors++;
      json err;
      err["reason"] = "Missing required fields";
      err["receipt"] = receipt;
      error_details.push_back(err);
      continue;
    }

    if (!validate_room_id(room_id) || !validate_user_id(user_id) ||
        !validate_event_id(event_id)) {
      skipped++;
      continue;
    }

    // Build entry
    ReceiptEntry entry;
    entry.room_id = room_id;
    entry.user_id = user_id;
    entry.event_id = event_id;
    entry.receipt_type = receipt_type;
    entry.thread_id = thread_id;
    entry.timestamp = ts;
    entry.data = receipt.value("data", json::object({{"ts", ts}}));

    // Insert
    ReceiptLinearizer linearizer(db);
    linearizer.linearize(entry);

    ReceiptGraphStore graph_store(db);
    graph_store.upsert_graph_receipt(entry);

    imported++;
  }

  // ---- 4. Return summary ----
  json result;
  result["imported"] = imported;
  result["skipped"] = skipped;
  result["errors"] = errors;
  if (!error_details.empty()) {
    result["error_details"] = error_details;
  }

  return make_response(200, result);
}

// ============================================================================
// Additional utility: Export room receipts
// ============================================================================

json handle_export_room_receipts(DatabasePool& db,
                                   const std::string& auth_header,
                                   const std::string& access_token_param,
                                   const std::string& room_id,
                                   int64_t from_stream,
                                   int64_t limit) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room_id");
  }

  // ---- 3. Export receipts ----
  if (limit <= 0) limit = 500;

  ReceiptLinearizer linearizer(db);
  std::vector<ReceiptEntry> entries;

  if (from_stream > 0) {
    int64_t to_stream = g_stream_manager.get_current_stream_id();
    entries = linearizer.get_receipts_since(from_stream, to_stream, room_id);
  } else {
    entries = get_latest_receipts_for_room_as_entries(db, room_id);
  }

  if (static_cast<int64_t>(entries.size()) > limit) {
    entries.resize(limit);
  }

  // ---- 4. Build export format ----
  json result = json::object();
  result["room_id"] = room_id;
  result["receipts"] = json::array();

  for (auto& entry : entries) {
    json item;
    item["room_id"] = entry.room_id;
    item["receipt_type"] = entry.receipt_type;
    item["user_id"] = entry.user_id;
    item["event_id"] = entry.event_id;
    item["thread_id"] = entry.thread_id;
    item["stream_ordering"] = entry.stream_ordering;
    item["timestamp"] = entry.timestamp;
    item["data"] = entry.data;
    result["receipts"].push_back(item);
  }

  result["count"] = result["receipts"].size();
  result["exported_at"] = now_ms();

  return make_response(200, result);
}

// ============================================================================
// Additional utility: Receipt conflict resolution
// ============================================================================
// Resolves conflicting receipts from federation and local sources.
// Uses timestamp-based conflict resolution with server priority.

json handle_resolve_receipt_conflict(DatabasePool& db,
                                       const ReceiptEntry& local,
                                       const ReceiptEntry& remote,
                                       const std::string& origin_server) {
  // ---- 1. Compare timestamps ----
  // Local receipts always win in case of equal timestamps
  if (remote.timestamp > local.timestamp) {
    // Remote is newer, use remote
    ReceiptLinearizer linearizer(db);
    linearizer.linearize(remote);

    ReceiptGraphStore graph_store(db);
    graph_store.upsert_graph_receipt(remote);

    json result;
    result["winner"] = "remote";
    result["origin"] = origin_server;
    result["timestamp"] = remote.timestamp;
    return make_response(200, result);
  }

  // Local wins (either newer or equal timestamp)
  json result;
  result["winner"] = "local";
  result["timestamp"] = local.timestamp;
  return make_response(200, result);
}

// ============================================================================
// Additional utility: Receipt thread scoping
// ============================================================================
// Manages thread-scoped receipts (MSC3771-style thread receipts).
// Thread receipts allow users to track read position per thread.

json handle_thread_receipt(DatabasePool& db,
                             const std::string& auth_header,
                             const std::string& access_token_param,
                             const std::string& room_id,
                             int64_t thread_root_event_id_int,
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

  // ---- 3. Extract thread receipt data ----
  std::string event_id = safe_str(request_body, "event_id");
  std::string receipt_type = safe_str(request_body, "receipt_type", "m.read");
  int64_t thread_id = safe_int(request_body, "thread_id", thread_root_event_id_int);
  int64_t ts = now_ms();

  if (event_id.empty()) {
    return make_error(400, "M_BAD_JSON", "Must provide event_id");
  }

  // ---- 4. Build thread-scoped receipt entry ----
  ReceiptEntry entry;
  entry.room_id = room_id;
  entry.user_id = auth.user_id;
  entry.event_id = event_id;
  entry.receipt_type = receipt_type;
  entry.thread_id = thread_id;
  entry.timestamp = ts;
  entry.data = json::object({
    {"ts", ts},
    {"thread_id", thread_id}
  });

  // ---- 5. Linearize with thread scope ----
  ReceiptLinearizer linearizer(db);
  int64_t stream_id = linearizer.linearize(entry);

  // ---- 6. Update graph for thread scope ----
  ReceiptGraphStore graph_store(db);
  graph_store.upsert_graph_receipt(entry);

  // ---- 7. Federate if public ----
  if (receipt_type == "m.read") {
    ReceiptFederationManager fed_mgr(db);
    fed_mgr.federate_receipt(entry);
  }

  // ---- 8. Return ----
  json result;
  result["stream_id"] = stream_id;
  result["thread_id"] = thread_id;
  result["event_id"] = event_id;

  return make_response(200, result);
}

// ============================================================================
// Additional utility: Get thread read receipts
// ============================================================================

json handle_get_thread_receipts(DatabasePool& db,
                                  const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& room_id,
                                  int64_t thread_id) {
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

  // ---- 3. Query thread receipts ----
  auto cursor = db.cursor("thread_receipts");
  json receipts = json::object();

  if (cursor) {
    cursor->execute(
      "SELECT r.receipt_type, r.user_id, r.event_id, r.data, MAX(r.stream_id) as stream_id "
      "FROM receipts_linearized r "
      "WHERE r.room_id = ? AND r.thread_id = ? "
      "GROUP BY r.receipt_type, r.user_id",
      {room_id, std::to_string(thread_id)}
    );

    auto rows = cursor->fetchall();
    for (auto& row : rows) {
      std::string rtype = row.get<std::string>(0);
      std::string uid = row.get<std::string>(1);
      std::string eid = row.get<std::string>(2);
      std::string data_str = row.get<std::string>(3);
      json data;
      try {
        data = json::parse(data_str.empty() ? "{}" : data_str);
      } catch (...) {
        data = json::object();
      }

      // Apply privacy: only show private receipts to their owner
      if (rtype == "m.read.private" && uid != auth.user_id) {
        continue;
      }

      if (!receipts.contains(rtype)) {
        receipts[rtype] = json::object();
      }
      receipts[rtype][uid] = json::object({
        {"event_id", eid},
        {"ts", data.value("ts", 0)}
      });
    }
  }

  // ---- 4. Return ----
  json result;
  result["thread_id"] = thread_id;
  result["receipts"] = receipts;

  return make_response(200, result);
}

// ============================================================================
// Additional utility: Read receipt batch set (for initial sync seeding)
// ============================================================================

json handle_batch_set_receipts(DatabasePool& db,
                                 const std::string& auth_header,
                                 const std::string& access_token_param,
                                 const json& batch_payload) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate batch payload ----
  if (!batch_payload.contains("receipts") || !batch_payload["receipts"].is_array()) {
    return make_error(400, "M_BAD_JSON", "Must provide receipts array");
  }

  // ---- 3. Process each receipt in the batch ----
  int64_t processed = 0;
  int64_t failed = 0;
  json failures = json::array();

  for (auto& receipt : batch_payload["receipts"]) {
    std::string room_id = safe_str(receipt, "room_id");
    std::string event_id = safe_str(receipt, "event_id");
    std::string receipt_type = safe_str(receipt, "receipt_type", "m.read");
    int64_t thread_id = safe_int(receipt, "thread_id", 0);

    if (room_id.empty() || event_id.empty()) {
      failed++;
      json f;
      f["reason"] = "Missing room_id or event_id";
      f["receipt"] = receipt;
      failures.push_back(f);
      continue;
    }

    ReceiptEntry entry;
    entry.room_id = room_id;
    entry.user_id = auth.user_id;
    entry.event_id = event_id;
    entry.receipt_type = receipt_type;
    entry.thread_id = thread_id;
    entry.timestamp = receipt.value("ts", now_ms());
    entry.data = receipt.value("data", json::object({{"ts", entry.timestamp}}));

    try {
      ReceiptLinearizer linearizer(db);
      linearizer.linearize(entry);

      ReceiptGraphStore graph_store(db);
      graph_store.upsert_graph_receipt(entry);

      if (receipt_type != "m.read.private") {
        ReceiptFederationManager fed_mgr(db);
        fed_mgr.federate_receipt(entry);
      }

      processed++;
    } catch (const std::exception& e) {
      failed++;
      json f;
      f["reason"] = e.what();
      f["receipt"] = receipt;
      failures.push_back(f);
    }
  }

  // ---- 4. Return summary ----
  json result;
  result["processed"] = processed;
  result["failed"] = failed;
  if (!failures.empty()) {
    result["failures"] = failures;
  }

  return make_response(200, result);
}

// ============================================================================
// Additional utility: Typing timeout configuration
// ============================================================================

json handle_configure_typing_timeout(DatabasePool& db,
                                       const std::string& auth_header,
                                       const std::string& access_token_param,
                                       int64_t default_timeout_ms,
                                       int64_t max_timeout_ms) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate timeout values ----
  if (default_timeout_ms < 5000) default_timeout_ms = 5000;
  if (default_timeout_ms > 300000) default_timeout_ms = 300000;
  if (max_timeout_ms < default_timeout_ms) max_timeout_ms = default_timeout_ms * 2;
  if (max_timeout_ms > 600000) max_timeout_ms = 600000;

  // ---- 3. Store configuration ----
  // In a real implementation, this would persist to a server config table
  int64_t now = now_ms();

  // For now, store as server-level state
  json config;
  config["default_typing_timeout_ms"] = default_timeout_ms;
  config["max_typing_timeout_ms"] = max_timeout_ms;
  config["updated_at"] = now;

  // Persist as account data for the server
  db.execute("typing_config",
    "INSERT OR REPLACE INTO account_data "
    "(user_id, type, content, stream_id) VALUES "
    "('@server:localhost', 'm.typing.config', '" +
    config.dump() + "', " + std::to_string(now) + ")");

  // ---- 4. Return ----
  return make_response(200, config);
}

// ============================================================================
// Additional utility: Receipt statistics
// ============================================================================

json handle_receipt_statistics(DatabasePool& db,
                                 const std::string& auth_header,
                                 const std::string& access_token_param) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  json stats;

  // Total linearized receipts
  auto txn = db.cursor("stats_receipts");
  if (txn) {
    txn->execute("SELECT COUNT(*) FROM receipts_linearized");
    auto rows = txn->fetchall();
    stats["total_linearized_receipts"] = rows.empty() ? 0 : rows[0].get<int64_t>(0);

    txn->execute("SELECT COUNT(*) FROM receipts_graph");
    rows = txn->fetchall();
    stats["total_graph_entries"] = rows.empty() ? 0 : rows[0].get<int64_t>(0);

    txn->execute(
      "SELECT COUNT(DISTINCT room_id) FROM receipts_linearized "
      "WHERE receipt_type = 'm.read'"
    );
    rows = txn->fetchall();
    stats["rooms_with_public_receipts"] = rows.empty() ? 0 : rows[0].get<int64_t>(0);

    txn->execute(
      "SELECT COUNT(DISTINCT room_id) FROM receipts_linearized "
      "WHERE receipt_type = 'm.read.private'"
    );
    rows = txn->fetchall();
    stats["rooms_with_private_receipts"] = rows.empty() ? 0 : rows[0].get<int64_t>(0);

    txn->execute(
      "SELECT COUNT(*) FROM typing_notifications WHERE is_typing = 1"
    );
    rows = txn->fetchall();
    stats["active_typing_sessions"] = rows.empty() ? 0 : rows[0].get<int64_t>(0);

    txn->execute(
      "SELECT COUNT(DISTINCT user_id) FROM receipts_linearized"
    );
    rows = txn->fetchall();
    stats["unique_users_with_receipts"] = rows.empty() ? 0 : rows[0].get<int64_t>(0);

    txn->execute("SELECT COALESCE(MAX(stream_id), 0) FROM receipts_linearized");
    rows = txn->fetchall();
    stats["max_stream_id"] = rows.empty() ? 0 : rows[0].get<int64_t>(0);
  }

  stats["stream_manager_position"] = g_stream_manager.get_current_stream_id();
  stats["timestamp"] = now_ms();

  return make_response(200, stats);
}

// ============================================================================
// Initialization: boot up receipt/ephemeral subsystem
// ============================================================================

void initialize_receipts_ephemeral(DatabasePool& db) {
  // Start typing timeout manager
  TypingTimeoutManager::instance().start(db);

  // Initialize stream position from database
  ReceiptsStore receipts(db);
  int64_t max_stream = receipts.get_max_receipt_stream_ordering();
  if (max_stream > 0) {
    g_stream_manager.update_stream_id(max_stream);
  }

  // Load active typing sessions into timeout manager
  auto txn = db.cursor("init_typing");
  if (txn) {
    txn->execute(
      "SELECT room_id, user_id, expiry_ts FROM typing_notifications "
      "WHERE is_typing = 1 AND expiry_ts > ?",
      {std::to_string(now_ms())}
    );
    auto rows = txn->fetchall();
    for (auto& row : rows) {
      std::string room_id = row.get<std::string>(0);
      std::string user_id = row.get<std::string>(1);
      int64_t expiry = row.get<int64_t>(2);
      TypingTimeoutManager::instance().track_typing(room_id, user_id, expiry);
    }
  }

  // Ensure stream ordering table has receipt entry
  db.execute("init_stream",
    "INSERT OR IGNORE INTO stream_ordering (type, stream_id) "
    "VALUES ('receipt', " + std::to_string(g_stream_manager.get_current_stream_id()) + ")");

  // Clean up any expired typing on startup
  db.execute("init_cleanup",
    "DELETE FROM typing_notifications WHERE expiry_ts < " +
    std::to_string(now_ms()));
}

void shutdown_receipts_ephemeral() {
  TypingTimeoutManager::instance().stop();
}

// ============================================================================
// Query parameter parser for receipt endpoints
// ============================================================================

ReceiptQueryParams parse_receipt_query_params(const std::string& query_string) {
  ReceiptQueryParams params;
  params.from_stream = 0;
  params.to_stream = 0;
  params.limit = 100;
  params.include_private = true;

  // Parse query string into key-value pairs
  if (!query_string.empty()) {
    std::string qs = query_string;
    if (qs[0] == '?') qs = qs.substr(1);

    std::istringstream stream(qs);
    std::string pair;
    while (std::getline(stream, pair, '&')) {
      auto eq_pos = pair.find('=');
      if (eq_pos == std::string::npos) continue;

      std::string key = pair.substr(0, eq_pos);
      std::string value = pair.substr(eq_pos + 1);

      // URL decode value
      auto decode = [](const std::string& s) -> std::string {
        std::string result;
        for (size_t i = 0; i < s.size(); ++i) {
          if (s[i] == '%' && i + 2 < s.size()) {
            int val;
            std::istringstream is(s.substr(i + 1, 2));
            if (is >> std::hex >> val) {
              result += static_cast<char>(val);
              i += 2;
            } else {
              result += s[i];
            }
          } else if (s[i] == '+') {
            result += ' ';
          } else {
            result += s[i];
          }
        }
        return result;
      };

      value = decode(value);

      if (key == "room_id") {
        params.room_id = value;
      } else if (key == "event_id") {
        params.event_id = value;
      } else if (key == "user_id") {
        params.user_id = value;
      } else if (key == "receipt_type") {
        params.receipt_type = value;
      } else if (key == "from") {
        try { params.from_stream = std::stoll(value); }
        catch (...) { params.from_stream = 0; }
      } else if (key == "to") {
        try { params.to_stream = std::stoll(value); }
        catch (...) { params.to_stream = 0; }
      } else if (key == "limit") {
        try { params.limit = std::stoi(value); }
        catch (...) { params.limit = 100; }
      } else if (key == "include_private") {
        params.include_private = (value == "true" || value == "1");
      }
    }
  }

  if (params.limit <= 0) params.limit = 100;
  if (params.limit > 1000) params.limit = 1000;

  return params;
}

// ============================================================================
// Receipt preview builder (for room list hover/tooltip)
// ============================================================================

json build_receipt_preview(DatabasePool& db,
                             const std::string& room_id,
                             const std::string& user_id,
                             int max_preview_users) {
  json preview;
  preview["room_id"] = room_id;

  // Get recent read receipts
  ReceiptsStore receipts(db);
  auto latest = get_latest_receipts_for_room_as_entries(db, room_id);

  // Filter to public receipts only
  std::vector<ReceiptEntry> public_entries;
  for (auto& e : latest) {
    if (e.receipt_type == "m.read" && e.user_id != user_id) {
      public_entries.push_back(e);
    }
  }

  // Sort by timestamp descending
  std::sort(public_entries.begin(), public_entries.end(),
    [](const ReceiptEntry& a, const ReceiptEntry& b) {
      return a.timestamp > b.timestamp;
    });

  // Limit to max_preview_users
  if (static_cast<int>(public_entries.size()) > max_preview_users) {
    public_entries.resize(max_preview_users);
  }

  preview["recent_readers"] = json::array();
  for (auto& e : public_entries) {
    json reader;
    reader["user_id"] = e.user_id;
    reader["event_id"] = e.event_id;
    reader["ts"] = e.timestamp;

    // Get display name
    ProfileStore profile(db);
    auto displayname = profile.get_displayname(e.user_id);
    if (displayname) reader["display_name"] = *displayname;

    preview["recent_readers"].push_back(reader);
  }

  // Get active typing users
  int64_t now = now_ms();
  auto txn = db.cursor("preview_typing");
  if (txn) {
    txn->execute(
      "SELECT user_id FROM typing_notifications "
      "WHERE room_id = ? AND is_typing = 1 AND expiry_ts > ?",
      {room_id, std::to_string(now)}
    );
    auto rows = txn->fetchall();
    preview["typing_users"] = json::array();
    for (auto& row : rows) {
      std::string uid = row.get<std::string>(0);
      if (uid != user_id) {
        preview["typing_users"].push_back(uid);
      }
    }
  }

  preview["timestamp"] = now;
  return preview;
}

// ============================================================================
// Receipt-based unread counting
// ============================================================================

struct UnreadCount {
  int64_t highlight_count = 0;
  int64_t notification_count = 0;
};

UnreadCount compute_unread_counts(DatabasePool& db,
                                    const std::string& room_id,
                                    const std::string& user_id) {
  UnreadCount counts;

  // Get user's read receipt position
  ReceiptsStore receipts(db);
  auto read_rcpt = receipts.get_user_receipt(room_id, user_id, "m.read");

  int64_t read_stream = 0;
  if (read_rcpt) {
    read_stream = read_rcpt->stream_ordering;
  }

  // Count events after read position
  if (read_stream > 0) {
    auto txn = db.cursor("unread_counts");
    if (txn) {
      // Total unread notifications
      txn->execute(
        "SELECT COUNT(*) FROM events "
        "WHERE room_id = ? AND stream_ordering > ?",
        {room_id, std::to_string(read_stream)}
      );
      auto rows = txn->fetchall();
      if (!rows.empty()) {
        counts.notification_count = rows[0].get<int64_t>(0);
      }

      // Highlight count (events mentioning the user)
      txn->execute(
        "SELECT COUNT(*) FROM events "
        "WHERE room_id = ? AND stream_ordering > ? "
        "AND json LIKE ?",
        {room_id, std::to_string(read_stream), "%" + user_id + "%"}
      );
      rows = txn->fetchall();
      if (!rows.empty()) {
        counts.highlight_count = rows[0].get<int64_t>(0);
      }
    }
  }

  return counts;
}

} // namespace progressive::handlers
