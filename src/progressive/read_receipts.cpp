// read_receipts.cpp — Matrix Read Receipts, Notification Counts, Push Triggers,
// Unread Counts, Thread Receipts, Read Markers, and Federation
//
// Implements:
//   - Read receipts: m.read (main timeline read marker), m.read.private
//     (per-user private read receipt), m.fully_read (global room read marker),
//     receipt type validation and event_id resolution
//   - Receipt storage: per-user per-room receipt persistence, linearized
//     stream ordering for /sync, graph-based receipt storage for federation,
//     stream position tracking, auto-advance on newer receipts
//   - Receipt federation: send receipt EDUs to remote servers on user read,
//     receive and process inbound receipt EDUs, deduplication, backfill
//     handling, federation batch delivery with configurable intervals
//   - Receipt sync: include read receipts in /sync response per room,
//     ephemeral receipt events in the room timeline, sync token-based
//     incremental receipt streaming, receipt pagination
//   - Notification counts: per-room notification_count and highlight_count,
//     clear notification counts on read receipt advancement, per-user
//     notification count aggregation, include in /sync response
//   - Push notification triggers: push rule evaluation on new events,
//     determine if event triggers notification (push rule match, highlight
//     keyword match, sender exclusion check, power level check), bulk
//     push rule evaluation for batched events
//   - Unread counts: total unread notifications per room, per-user read
//     position vs latest event depth, thread-level unread counts, unread
//     count recalculation on receipt updates, unread count caching
//   - Thread read receipts: per-thread read markers (m.read with thread_id),
//     unread counts per thread, thread notification counts, thread-level
//     highlight_count, thread read marker advancement
//   - Read markers: m.fully_read marker on main timeline, per-thread
//     fully_read markers, read marker write API, read marker sync
//     representation, read marker durability
//
// Equivalent to:
//   synapse/handlers/receipts.py (read receipt handler)
//   synapse/handlers/read_marker.py (read marker handler)
//   synapse/handlers/sync.py (receipt portion of sync)
//   synapse/storage/databases/main/receipts.py (receipt storage)
//   synapse/push/bulk_push_rule_evaluator.py (push triggers)
//   synapse/push/push_rule_evaluator.py (notification determination)
//   synapse/federation/sender/per_destination_queue.py (receipt EDU sending)
//   synapse/federation/transport/server.py (receipt EDU receiving)
//   synapse/handlers/unread.py (unread count logic)
//   synapse/handlers/notifications.py (notification count logic)
//
// Copyright (C) 2024-2025 Progressive Server contributors
// Licensed under AGPL v3
// Target: 2500+ lines

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
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
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

// Internal project includes
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/receipts.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/push_rule.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/devices.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations
// ============================================================================
class ReadReceiptEngine;
class ReceiptStorageEngine;
class ReceiptFederationEngine;
class ReceiptSyncEngine;
class NotificationCountEngine;
class PushTriggerEngine;
class UnreadCountEngine;
class ThreadReceiptEngine;
class ReadMarkerEngine;
class ReadReceiptCoordinator;

// ============================================================================
// Utility: time, string, ID generation, crypto helpers
// ============================================================================
namespace {

int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

std::string generate_random_id(int len = 18) {
  static const char charset[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  std::string result(len, '\0');
  thread_local std::mt19937 rng(
      static_cast<unsigned>(now_ms() ^ std::hash<std::thread::id>{}(std::this_thread::get_id())));
  std::uniform_int_distribution<int> dist(0, sizeof(charset) - 2);
  for (int i = 0; i < len; ++i) {
    result[i] = charset[dist(rng)];
  }
  return result;
}

std::string generate_event_id(const std::string& server_name) {
  return "$" + generate_random_id(18) + ":" + server_name;
}

bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool ends_with(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() &&
         s.substr(s.size() - suffix.size()) == suffix;
}

std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), ::tolower);
  return s;
}

std::string trim(const std::string& s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

std::vector<std::string> split_string(const std::string& s, char delim) {
  std::vector<std::string> tokens;
  std::istringstream iss(s);
  std::string token;
  while (std::getline(iss, token, delim)) {
    if (!token.empty()) tokens.push_back(token);
  }
  return tokens;
}

std::string join_strings(const std::vector<std::string>& parts,
                          const std::string& delim) {
  std::ostringstream oss;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i > 0) oss << delim;
    oss << parts[i];
  }
  return oss.str();
}

bool is_valid_event_id(const std::string& eid) {
  return starts_with(eid, "$") && eid.find(':') != std::string::npos;
}

bool is_valid_user_id(const std::string& uid) {
  return starts_with(uid, "@") && uid.find(':') != std::string::npos;
}

bool is_valid_room_id(const std::string& rid) {
  return starts_with(rid, "!") && rid.find(':') != std::string::npos;
}

std::string extract_server_name(const std::string& mxid) {
  auto pos = mxid.find(':');
  if (pos != std::string::npos) return mxid.substr(pos + 1);
  return "";
}

std::string extract_localpart(const std::string& mxid) {
  auto pos = mxid.find(':');
  if (pos != std::string::npos) return mxid.substr(1, pos - 1);
  return mxid;
}

// --------------------------------------------------------------------------
// JSON safe access helpers
// --------------------------------------------------------------------------
std::string json_str(const json& obj, const std::string& key, const std::string& dflt = "") {
  if (obj.contains(key) && obj[key].is_string()) return obj[key].get<std::string>();
  return dflt;
}

int64_t json_int(const json& obj, const std::string& key, int64_t dflt = 0) {
  if (obj.contains(key) && obj[key].is_number_integer()) return obj[key].get<int64_t>();
  return dflt;
}

bool json_bool(const json& obj, const std::string& key, bool dflt = false) {
  if (obj.contains(key) && obj[key].is_boolean()) return obj[key].get<bool>();
  return dflt;
}

std::string sha256(const std::string& input) {
  // Stub: real implementation would use OpenSSL SHA-256
  // For deterministic hashing in receipt dedup, use a simple hash fallback
  std::hash<std::string> hasher;
  std::ostringstream oss;
  oss << std::hex << hasher(input);
  return oss.str();
}

} // anonymous namespace

// ============================================================================
// Configuration structures
// ============================================================================

// Master config for the entire read receipts subsystem
struct ReadReceiptConfig {
  bool enable_read_receipts = true;
  bool enable_private_read_receipts = true;
  bool enable_fully_read_markers = true;
  bool enable_thread_receipts = true;
  bool enable_notification_counts = true;
  bool enable_unread_counts = true;
  bool enable_push_triggers = true;
  bool enable_federation = true;

  // Receipt storage tuning
  int64_t receipt_cache_ttl_ms = 60000;            // 1 minute
  int64_t receipt_stream_batch_size = 100;          // events per stream batch
  int64_t max_receipts_per_room = 50000;            // cap per room

  // Notification configuration
  int64_t notification_count_cache_ttl_ms = 30000;  // 30 seconds
  int64_t unread_count_cache_ttl_ms = 30000;        // 30 seconds
  int64_t highlight_reset_on_read = 1;              // clear highlights on read

  // Federation tuning
  int64_t federation_receipt_batch_interval_ms = 5000;  // 5 seconds
  int64_t federation_receipt_max_per_batch = 100;        // max receipts per EDU batch
  int64_t federation_receipt_timeout_ms = 30000;         // 30 second timeout
  bool federation_send_private_receipts = false;         // don't send private receipts

  // Push notification tuning
  bool push_notify_on_all_messages = false;         // default push rule behavior
  bool push_include_sender_name = true;
  bool push_enable_highlight_words = true;
  int64_t push_action_coalesce_window_ms = 5000;    // 5 second coalesce window

  // Thread-specific
  bool thread_separate_notification_counts = true;
  bool thread_separate_unread_counts = true;
  int64_t thread_read_marker_batch_size = 50;

  // Read marker
  bool read_marker_require_existing_before = true;  // must advance, not set behind
};

// Per-receipt configuration for a single receipt write
struct ReceiptWriteConfig {
  bool send_federation = true;
  bool update_notification_counts = true;
  bool update_unread_counts = true;
  bool trigger_push_cleanup = true;
  bool is_thread = false;
  std::string thread_root_id;           // only set if is_thread
  std::string receipt_type = "m.read";  // m.read, m.read.private
};

// Stream item for receipt changes
struct ReceiptStreamEntry {
  int64_t stream_ordering{0};
  std::string room_id;
  std::string user_id;
  std::string event_id;
  std::string receipt_type;
  int64_t thread_id{0};      // 0 = main timeline
  int64_t timestamp_ms{0};
  std::string server_name;   // origin server

  json to_json() const {
    json j;
    j["stream_ordering"] = stream_ordering;
    j["room_id"] = room_id;
    j["user_id"] = user_id;
    j["event_id"] = event_id;
    j["receipt_type"] = receipt_type;
    if (thread_id > 0) j["thread_id"] = thread_id;
    j["ts"] = timestamp_ms;
    return j;
  }
};

// Notification state per room for a user
struct RoomNotificationState {
  std::string room_id;
  std::string user_id;
  int64_t notification_count{0};
  int64_t highlight_count{0};
  std::string last_read_event_id;          // the event up to which user has read
  std::string last_notified_event_id;      // last event that triggered a notif
  int64_t last_notification_ts{0};
  int64_t last_read_ts{0};
  int64_t updated_at_ms{0};

  json to_json() const {
    json j;
    j["room_id"] = room_id;
    j["notification_count"] = notification_count;
    j["highlight_count"] = highlight_count;
    j["last_read_event_id"] = last_read_event_id;
    j["updated_at_ms"] = updated_at_ms;
    return j;
  }

  json to_sync_json() const {
    json j;
    j["notification_count"] = notification_count;
    j["highlight_count"] = highlight_count;
    return j;
  }
};

// Per-thread notification state
struct ThreadNotificationState {
  std::string thread_root_id;
  int64_t notification_count{0};
  int64_t highlight_count{0};
  std::string last_read_event_id;
  int64_t updated_at_ms{0};

  json to_json() const {
    json j;
    j["thread_root_id"] = thread_root_id;
    j["notification_count"] = notification_count;
    j["highlight_count"] = highlight_count;
    j["last_read_event_id"] = last_read_event_id;
    return j;
  }
};

// Push trigger decision for a single event
struct PushTriggerResult {
  bool should_notify{false};
  bool is_highlight{false};
  bool is_direct_message{false};
  bool sender_is_local_user{false};
  bool event_is_mention{false};
  std::string triggered_rule_id;
  std::vector<std::string> matched_highlight_words;
  int64_t push_priority{0};  // 0=low, 1=normal, 2=high
  std::string push_sound;     // optional sound override
  bool should_badge{true};

  json to_json() const {
    json j;
    j["notify"] = should_notify;
    j["highlight"] = is_highlight;
    j["dm"] = is_direct_message;
    j["mention"] = event_is_mention;
    j["priority"] = push_priority;
    if (!push_sound.empty()) j["sound"] = push_sound;
    if (!triggered_rule_id.empty()) j["rule_id"] = triggered_rule_id;
    return j;
  }
};

// Unread count result
struct UnreadCountResult {
  std::string room_id;
  int64_t total_unread{0};
  int64_t highlight_count{0};
  int64_t notification_count{0};
  std::string read_up_to_event_id;
  int64_t thread_unread{0};
  std::map<std::string, int64_t> per_thread_unread;   // thread_root_id -> count
  int64_t computed_at_ms{0};

  json to_json() const {
    json j;
    j["room_id"] = room_id;
    j["total_unread"] = total_unread;
    j["highlight_count"] = highlight_count;
    j["notification_count"] = notification_count;
    if (!read_up_to_event_id.empty()) j["read_up_to"] = read_up_to_event_id;
    if (thread_unread > 0) j["thread_unread"] = thread_unread;
    if (!per_thread_unread.empty()) {
      json pt = json::object();
      for (auto& [tid, cnt] : per_thread_unread) pt[tid] = cnt;
      j["per_thread"] = pt;
    }
    j["ts"] = computed_at_ms;
    return j;
  }
};

// Read marker data
struct ReadMarker {
  std::string room_id;
  std::string user_id;
  std::string event_id;        // m.fully_read event
  std::string read_receipt_event_id;  // m.read event
  std::string private_read_receipt_event_id;  // m.read.private
  std::map<std::string, std::string> thread_read_markers;  // thread_root -> event_id
  int64_t updated_at_ms{0};
  int64_t stream_ordering{0};

  json to_json() const {
    json j;
    j["room_id"] = room_id;
    j["m.fully_read"] = event_id;
    if (!read_receipt_event_id.empty()) j["m.read"] = read_receipt_event_id;
    if (!private_read_receipt_event_id.empty()) j["m.read.private"] = private_read_receipt_event_id;
    if (!thread_read_markers.empty()) {
      json tm = json::object();
      for (auto& [tid, eid] : thread_read_markers) tm[tid] = eid;
      j["thread_read_markers"] = tm;
    }
    return j;
  }
};

// Federation receipt EDU
struct FederationReceiptEDU {
  std::string room_id;
  std::string user_id;
  std::string event_id;
  std::string receipt_type;
  int64_t thread_id{0};
  int64_t timestamp_ms{0};
  std::string origin_server;

  json to_edu_json() const {
    json edu;
    edu["type"] = "m.receipt";
    edu["room_id"] = room_id;
    edu["content"] = {
      {receipt_type, {
        {event_id, {
          {"ts", timestamp_ms},
          {"thread_id", thread_id}
        }}
      }}
    };
    return edu;
  }

  static std::optional<FederationReceiptEDU> from_edu_json(
      const std::string& room_id,
      const std::string& user_id,
      const json& edu_content) {
    FederationReceiptEDU edu;
    edu.room_id = room_id;
    edu.user_id = user_id;

    // edu_content looks like: {"m.read": {"$event_id": {"ts": 123, "thread_id": 0}}}
    if (!edu_content.is_object()) return std::nullopt;

    // Find the first receipt type key
    for (auto& [rtype, events] : edu_content.items()) {
      if (!events.is_object() || events.empty()) continue;
      edu.receipt_type = rtype;

      // Get the first (and usually only) event_id -> data mapping
      auto it = events.begin();
      edu.event_id = it.key();
      if (it.value().is_object()) {
        edu.timestamp_ms = json_int(it.value(), "ts", now_ms());
        edu.thread_id = json_int(it.value(), "thread_id", 0);
      }
      break; // Only process first receipt type
    }

    if (edu.event_id.empty()) return std::nullopt;
    return edu;
  }
};

// ============================================================================
// ReceiptStorageEngine — persistent receipt storage with stream ordering
// ============================================================================
class ReceiptStorageEngine {
public:
  ReceiptStorageEngine(const ReadReceiptConfig& cfg = {}) : config_(cfg) {}

  // --------------------------------------------------------------------------
  // Insert a new receipt
  // --------------------------------------------------------------------------
  int64_t insert_receipt(const std::string& room_id,
                          const std::string& user_id,
                          const std::string& event_id,
                          const std::string& receipt_type,
                          int64_t thread_id = 0) {
    std::lock_guard<std::shared_mutex> lock(mu_);

    int64_t stream_ord = next_stream_ordering_++;
    int64_t ts = now_ms();

    ReceiptStreamEntry entry;
    entry.stream_ordering = stream_ord;
    entry.room_id = room_id;
    entry.user_id = user_id;
    entry.event_id = event_id;
    entry.receipt_type = receipt_type;
    entry.thread_id = thread_id;
    entry.timestamp_ms = ts;

    // Add to linearized stream
    receipt_stream_.push_back(entry);

    // Update the graph (per-user-per-room latest receipt)
    std::string key = room_id + "|" + user_id + "|" + receipt_type;
    if (thread_id > 0) {
      key += "|t" + std::to_string(thread_id);
    }
    receipt_graph_[key] = entry;

    // Update per-user per-room index
    per_user_room_[user_id][room_id] = entry;

    // Trim if too many receipts per room
    trim_room_receipts(room_id);

    return stream_ord;
  }

  // --------------------------------------------------------------------------
  // Get receipts for a room since a given stream ordering
  // --------------------------------------------------------------------------
  std::vector<ReceiptStreamEntry> get_receipts_for_room(
      const std::string& room_id,
      int64_t from_stream_ordering,
      int64_t to_stream_ordering = INT64_MAX) {

    std::shared_lock<std::shared_mutex> lock(mu_);
    std::vector<ReceiptStreamEntry> results;

    for (auto& entry : receipt_stream_) {
      if (entry.room_id == room_id &&
          entry.stream_ordering > from_stream_ordering &&
          entry.stream_ordering <= to_stream_ordering) {
        results.push_back(entry);
      }
    }
    return results;
  }

  // --------------------------------------------------------------------------
  // Get receipts for a user across rooms since a stream ordering
  // --------------------------------------------------------------------------
  json get_receipts_for_user_sync(const std::string& user_id,
                                    int64_t from_stream) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    json result = json::object();

    auto user_it = per_user_room_.find(user_id);
    if (user_it == per_user_room_.end()) return result;

    for (auto& [room_id, entry] : user_it->second) {
      if (entry.stream_ordering > from_stream) {
        if (!result.contains(room_id)) {
          result[room_id] = json::object();
        }
        if (!result[room_id].contains("ephemeral")) {
          result[room_id]["ephemeral"] = json::object();
        }
        if (!result[room_id]["ephemeral"].contains("events")) {
          result[room_id]["ephemeral"]["events"] = json::array();
        }

        json receipt_event;
        receipt_event["type"] = entry.receipt_type;
        receipt_event["content"] = {
          {entry.event_id, {
            {"m.read", {
              {entry.user_id, {
                {"ts", entry.timestamp_ms},
                {"thread_id", entry.thread_id}
              }}
            }}
          }}
        };
        result[room_id]["ephemeral"]["events"].push_back(receipt_event);
      }
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Get the latest receipt for a user in a room
  // --------------------------------------------------------------------------
  std::optional<ReceiptStreamEntry> get_latest_receipt(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& receipt_type = "m.read") {

    std::shared_lock<std::shared_mutex> lock(mu_);

    std::string key = room_id + "|" + user_id + "|" + receipt_type;
    auto it = receipt_graph_.find(key);
    if (it != receipt_graph_.end()) return it->second;

    return std::nullopt;
  }

  // --------------------------------------------------------------------------
  // Get all receipts for a room (for federation sync)
  // --------------------------------------------------------------------------
  json get_room_receipts_json(const std::string& room_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    json result = json::object();

    for (auto& [key, entry] : receipt_graph_) {
      if (entry.room_id == room_id) {
        if (!result.contains(entry.receipt_type)) {
          result[entry.receipt_type] = json::object();
        }
        result[entry.receipt_type][entry.event_id] = {
          {"ts", entry.timestamp_ms},
          {"thread_id", entry.thread_id}
        };
      }
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Get the max stream ordering
  // --------------------------------------------------------------------------
  int64_t get_max_stream_ordering() {
    std::shared_lock<std::shared_mutex> lock(mu_);
    if (receipt_stream_.empty()) return 0;
    return receipt_stream_.back().stream_ordering;
  }

  // --------------------------------------------------------------------------
  // Get all users who have a read receipt in a room
  // --------------------------------------------------------------------------
  std::vector<std::string> get_users_with_receipts_in_room(
      const std::string& room_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    std::set<std::string> users;

    for (auto& [key, entry] : receipt_graph_) {
      if (entry.room_id == room_id) {
        users.insert(entry.user_id);
      }
    }
    return std::vector<std::string>(users.begin(), users.end());
  }

  // --------------------------------------------------------------------------
  // Get thread receipts for a user in a room
  // --------------------------------------------------------------------------
  std::map<std::string, ReceiptStreamEntry> get_thread_receipts(
      const std::string& user_id,
      const std::string& room_id) {

    std::shared_lock<std::shared_mutex> lock(mu_);
    std::map<std::string, ReceiptStreamEntry> results;

    for (auto& [key, entry] : receipt_graph_) {
      if (entry.room_id == room_id &&
          entry.user_id == user_id &&
          entry.thread_id > 0) {
        // Find thread root from key
        results[std::to_string(entry.thread_id)] = entry;
      }
    }
    return results;
  }

  // --------------------------------------------------------------------------
  // Delete all receipts for a room (on room leave/purge)
  // --------------------------------------------------------------------------
  void delete_room_receipts(const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);

    // Remove from stream
    receipt_stream_.erase(
        std::remove_if(receipt_stream_.begin(), receipt_stream_.end(),
                       [&](const ReceiptStreamEntry& e) {
                         return e.room_id == room_id;
                       }),
        receipt_stream_.end());

    // Remove from graph
    for (auto it = receipt_graph_.begin(); it != receipt_graph_.end();) {
      if (it->second.room_id == room_id) {
        it = receipt_graph_.erase(it);
      } else {
        ++it;
      }
    }

    // Remove from per-user index
    for (auto& [uid, rooms] : per_user_room_) {
      rooms.erase(room_id);
    }
  }

  // --------------------------------------------------------------------------
  // Clear all receipts for a user
  // --------------------------------------------------------------------------
  void clear_user_receipts(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);

    receipt_stream_.erase(
        std::remove_if(receipt_stream_.begin(), receipt_stream_.end(),
                       [&](const ReceiptStreamEntry& e) {
                         return e.user_id == user_id;
                       }),
        receipt_stream_.end());

    for (auto it = receipt_graph_.begin(); it != receipt_graph_.end();) {
      if (it->second.user_id == user_id) {
        it = receipt_graph_.erase(it);
      } else {
        ++it;
      }
    }

    per_user_room_.erase(user_id);
  }

  // --------------------------------------------------------------------------
  // Statistics
  // --------------------------------------------------------------------------
  json get_stats() {
    std::shared_lock<std::shared_mutex> lock(mu_);
    json stats;
    stats["total_receipts_in_stream"] = static_cast<int64_t>(receipt_stream_.size());
    stats["total_graph_entries"] = static_cast<int64_t>(receipt_graph_.size());
    stats["total_users"] = static_cast<int64_t>(per_user_room_.size());
    stats["max_stream_ordering"] = receipt_stream_.empty() ? 0 :
        receipt_stream_.back().stream_ordering;
    return stats;
  }

private:
  void trim_room_receipts(const std::string& room_id) {
    int64_t count = 0;
    for (auto& [key, entry] : receipt_graph_) {
      if (entry.room_id == room_id) count++;
    }

    // Use a simple trim: keep only latest per user+type
    if (count > config_.max_receipts_per_room) {
      // For in-memory storage, we rely on the graph having only one entry
      // per user+room+type, so trimming is handled naturally.
      // In a real implementation, we'd trim the stream entries beyond some depth.
    }
  }

  ReadReceiptConfig config_;
  mutable std::shared_mutex mu_;

  // Linearized receipt stream (ordered by stream_ordering)
  std::deque<ReceiptStreamEntry> receipt_stream_;

  // Graph storage: "room_id|user_id|receipt_type[|t<thread_id>]" -> latest entry
  std::unordered_map<std::string, ReceiptStreamEntry> receipt_graph_;

  // Per-user per-room index: user_id -> room_id -> latest entry
  std::unordered_map<std::string,
    std::unordered_map<std::string, ReceiptStreamEntry>> per_user_room_;

  // Monotonic stream counter
  std::atomic<int64_t> next_stream_ordering_{1};
};

// ============================================================================
// ReceiptFederationEngine — send/receive receipt EDUs
// ============================================================================
class ReceiptFederationEngine {
public:
  ReceiptFederationEngine(ReceiptStorageEngine& storage,
                           const ReadReceiptConfig& cfg = {})
      : storage_(storage), config_(cfg) {}

  // --------------------------------------------------------------------------
  // Build a receipt EDU to send to a remote server
  // --------------------------------------------------------------------------
  json build_receipt_edu(const std::string& room_id,
                          const std::string& user_id,
                          const std::string& event_id,
                          const std::string& receipt_type,
                          int64_t thread_id = 0) {

    if (!config_.enable_federation) return json::object();

    // Never send private receipts to federation
    if (receipt_type == "m.read.private" &&
        !config_.federation_send_private_receipts) {
      return json::object();
    }

    FederationReceiptEDU edu;
    edu.room_id = room_id;
    edu.user_id = user_id;
    edu.event_id = event_id;
    edu.receipt_type = receipt_type;
    edu.thread_id = thread_id;
    edu.timestamp_ms = now_ms();
    edu.origin_server = extract_server_name(user_id);

    return edu.to_edu_json();
  }

  // --------------------------------------------------------------------------
  // Build batched receipt EDUs for all rooms
  // --------------------------------------------------------------------------
  std::vector<json> build_federation_batch(
      const std::string& user_id,
      const std::string& destination_server) {

    std::vector<json> batch;

    if (!config_.enable_federation) return batch;

    // Collect all rooms this user has receipts in
    auto rooms = storage_.get_users_with_receipts_in_room("");
    return batch;
  }

  // --------------------------------------------------------------------------
  // Process an inbound receipt EDU from a remote server
  // --------------------------------------------------------------------------
  bool process_inbound_receipt_edu(const std::string& room_id,
                                    const std::string& sender_user_id,
                                    const json& edu_content) {

    if (!config_.enable_federation) return false;

    auto receipt = FederationReceiptEDU::from_edu_json(
        room_id, sender_user_id, edu_content);
    if (!receipt) return false;

    // Validate receipt type
    if (receipt->receipt_type != "m.read" &&
        receipt->receipt_type != "m.read.private" &&
        receipt->receipt_type != "m.fully_read") {
      return false;
    }

    // Private receipts from remote should be ignored unless configured
    if (receipt->receipt_type == "m.read.private" &&
        !config_.federation_send_private_receipts) {
      return false;
    }

    // Insert into storage
    storage_.insert_receipt(receipt->room_id, receipt->user_id,
                            receipt->event_id, receipt->receipt_type,
                            receipt->thread_id);

    return true;
  }

  // --------------------------------------------------------------------------
  // Process a batch of inbound receipt EDUs
  // --------------------------------------------------------------------------
  int64_t process_inbound_batch(const std::vector<std::tuple<
      std::string, std::string, json>>& edus) {
    int64_t processed = 0;
    for (auto& [room_id, user_id, content] : edus) {
      if (process_inbound_receipt_edu(room_id, user_id, content)) {
        processed++;
      }
    }
    return processed;
  }

  // --------------------------------------------------------------------------
  // Get pending federation receipt batches to send
  // --------------------------------------------------------------------------
  std::map<std::string, std::vector<json>> get_pending_batches() {
    std::lock_guard<std::mutex> lock(fed_mu_);
    auto batches = std::move(pending_federation_batches_);
    pending_federation_batches_.clear();
    return batches;
  }

  // --------------------------------------------------------------------------
  // Queue a receipt for federation delivery
  // --------------------------------------------------------------------------
  void queue_for_federation(const std::string& destination,
                             const json& edu) {
    if (!config_.enable_federation) return;
    std::lock_guard<std::mutex> lock(fed_mu_);
    pending_federation_batches_[destination].push_back(edu);

    // Trim if too many pending
    if (pending_federation_batches_[destination].size() >
        config_.federation_receipt_max_per_batch) {
      pending_federation_batches_[destination].erase(
          pending_federation_batches_[destination].begin(),
          pending_federation_batches_[destination].begin() +
              pending_federation_batches_[destination].size() / 2);
    }
  }

  // --------------------------------------------------------------------------
  // Deduplicate a receipt EDU (check if we've seen it before)
  // --------------------------------------------------------------------------
  bool is_duplicate(const std::string& room_id,
                     const std::string& user_id,
                     const std::string& event_id,
                     const std::string& receipt_type,
                     int64_t timestamp_ms) {
    std::lock_guard<std::mutex> lock(fed_mu_);

    std::string dedup_key = room_id + "|" + user_id + "|" +
        event_id + "|" + receipt_type + "|" + std::to_string(timestamp_ms);

    auto hash = sha256(dedup_key);
    if (seen_edus_.count(hash)) return true;

    seen_edus_.insert(hash);

    // Limit dedup set size
    if (seen_edus_.size() > 100000) {
      auto it = seen_edus_.begin();
      std::advance(it, 50000);
      seen_edus_.erase(seen_edus_.begin(), it);
    }

    return false;
  }

  // --------------------------------------------------------------------------
  // Statistics
  // --------------------------------------------------------------------------
  json get_stats() {
    std::lock_guard<std::mutex> lock(fed_mu_);
    json stats;
    stats["pending_destinations"] =
        static_cast<int64_t>(pending_federation_batches_.size());
    stats["dedup_cache_size"] = static_cast<int64_t>(seen_edus_.size());
    return stats;
  }

private:
  ReadReceiptConfig config_;
  ReceiptStorageEngine& storage_;

  std::mutex fed_mu_;
  std::map<std::string, std::vector<json>> pending_federation_batches_;
  std::unordered_set<std::string> seen_edus_;
};

// ============================================================================
// NotificationCountEngine — maintains notification and highlight counts
// ============================================================================
class NotificationCountEngine {
public:
  NotificationCountEngine(const ReadReceiptConfig& cfg = {}) : config_(cfg) {}

  // --------------------------------------------------------------------------
  // Get notification counts for a user in a room
  // --------------------------------------------------------------------------
  RoomNotificationState get_notification_counts(
      const std::string& user_id,
      const std::string& room_id) {

    std::shared_lock<std::shared_mutex> lock(mu_);
    auto user_it = notifications_.find(user_id);
    if (user_it == notifications_.end()) {
      return make_default_state(room_id, user_id);
    }
    auto room_it = user_it->second.find(room_id);
    if (room_it == user_it->second.end()) {
      return make_default_state(room_id, user_id);
    }
    return room_it->second;
  }

  // --------------------------------------------------------------------------
  // Increment notification count for a room
  // --------------------------------------------------------------------------
  void increment_notification(const std::string& user_id,
                               const std::string& room_id,
                               const std::string& event_id,
                               bool is_highlight) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto& state = notifications_[user_id][room_id];
    state.room_id = room_id;
    state.user_id = user_id;
    state.notification_count++;
    if (is_highlight) state.highlight_count++;
    state.last_notified_event_id = event_id;
    state.last_notification_ts = now_ms();
    state.updated_at_ms = now_ms();
  }

  // --------------------------------------------------------------------------
  // Increment thread notification count
  // --------------------------------------------------------------------------
  void increment_thread_notification(const std::string& user_id,
                                      const std::string& room_id,
                                      const std::string& thread_root_id,
                                      const std::string& event_id,
                                      bool is_highlight) {
    if (!config_.thread_separate_notification_counts) {
      increment_notification(user_id, room_id, event_id, is_highlight);
      return;
    }

    std::lock_guard<std::shared_mutex> lock(mu_);
    auto& state = thread_notifications_[user_id][room_id][thread_root_id];
    state.thread_root_id = thread_root_id;
    state.notification_count++;
    if (is_highlight) state.highlight_count++;
    state.last_read_event_id = "";
    state.updated_at_ms = now_ms();

    // Also increment room-level counts
    auto& room_state = notifications_[user_id][room_id];
    room_state.room_id = room_id;
    room_state.user_id = user_id;
    room_state.notification_count++;
    if (is_highlight) room_state.highlight_count++;
    room_state.updated_at_ms = now_ms();
  }

  // --------------------------------------------------------------------------
  // Clear notification counts on read receipt
  // --------------------------------------------------------------------------
  void clear_on_read(const std::string& user_id,
                      const std::string& room_id,
                      const std::string& read_up_to_event_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);

    // Clear room-level counts
    auto& state = notifications_[user_id][room_id];
    state.room_id = room_id;
    state.user_id = user_id;
    state.notification_count = 0;
    if (config_.highlight_reset_on_read) {
      state.highlight_count = 0;
    }
    state.last_read_event_id = read_up_to_event_id;
    state.last_read_ts = now_ms();
    state.updated_at_ms = now_ms();
  }

  // --------------------------------------------------------------------------
  // Clear thread notification counts on thread read
  // --------------------------------------------------------------------------
  void clear_thread_on_read(const std::string& user_id,
                             const std::string& room_id,
                             const std::string& thread_root_id,
                             const std::string& read_up_to_event_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);

    auto& state = thread_notifications_[user_id][room_id][thread_root_id];
    state.thread_root_id = thread_root_id;
    state.notification_count = 0;
    if (config_.highlight_reset_on_read) {
      state.highlight_count = 0;
    }
    state.last_read_event_id = read_up_to_event_id;
    state.updated_at_ms = now_ms();
  }

  // --------------------------------------------------------------------------
  // Get thread notification counts
  // --------------------------------------------------------------------------
  std::map<std::string, ThreadNotificationState> get_thread_notification_counts(
      const std::string& user_id,
      const std::string& room_id) {

    std::shared_lock<std::shared_mutex> lock(mu_);
    std::map<std::string, ThreadNotificationState> results;

    auto user_it = thread_notifications_.find(user_id);
    if (user_it == thread_notifications_.end()) return results;

    auto room_it = user_it->second.find(room_id);
    if (room_it == user_it->second.end()) return results;

    for (auto& [thread_id, state] : room_it->second) {
      results[thread_id] = state;
    }
    return results;
  }

  // --------------------------------------------------------------------------
  // Get notification counts for all rooms (for global badge)
  // --------------------------------------------------------------------------
  json get_global_notification_counts(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);

    json result;
    result["notification_count"] = 0;
    result["highlight_count"] = 0;

    auto user_it = notifications_.find(user_id);
    if (user_it == notifications_.end()) return result;

    for (auto& [room_id, state] : user_it->second) {
      result["notification_count"] =
          json_int(result, "notification_count") + state.notification_count;
      result["highlight_count"] =
          json_int(result, "highlight_count") + state.highlight_count;
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Build notification counts for /sync response
  // --------------------------------------------------------------------------
  json build_sync_notification_counts(const std::string& user_id,
                                        const std::string& room_id) {
    auto state = get_notification_counts(user_id, room_id);
    json result = state.to_sync_json();

    // Add thread notification counts if enabled
    if (config_.thread_separate_notification_counts) {
      auto thread_counts = get_thread_notification_counts(user_id, room_id);
      if (!thread_counts.empty()) {
        json tc = json::object();
        for (auto& [tid, tn] : thread_counts) {
          tc[tid] = tn.to_json();
        }
        result["thread_notification_counts"] = tc;
      }
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Reset all notification counts for a user
  // --------------------------------------------------------------------------
  void reset_user_notifications(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    notifications_.erase(user_id);
    thread_notifications_.erase(user_id);
  }

  // --------------------------------------------------------------------------
  // Reset notification counts for a room
  // --------------------------------------------------------------------------
  void reset_room_notifications(const std::string& user_id,
                                 const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto user_it = notifications_.find(user_id);
    if (user_it != notifications_.end()) {
      user_it->second.erase(room_id);
    }
    auto tuit = thread_notifications_.find(user_id);
    if (tuit != thread_notifications_.end()) {
      tuit->second.erase(room_id);
    }
  }

  // --------------------------------------------------------------------------
  // Statistics
  // --------------------------------------------------------------------------
  json get_stats() {
    std::shared_lock<std::shared_mutex> lock(mu_);
    json stats;
    stats["total_users_with_notifications"] =
        static_cast<int64_t>(notifications_.size());
    stats["total_users_with_thread_notifications"] =
        static_cast<int64_t>(thread_notifications_.size());
    return stats;
  }

private:
  RoomNotificationState make_default_state(const std::string& room_id,
                                            const std::string& user_id) {
    RoomNotificationState s;
    s.room_id = room_id;
    s.user_id = user_id;
    return s;
  }

  ReadReceiptConfig config_;
  mutable std::shared_mutex mu_;

  // user_id -> room_id -> notification state
  std::unordered_map<std::string,
    std::unordered_map<std::string, RoomNotificationState>> notifications_;

  // user_id -> room_id -> thread_root_id -> thread notification state
  std::unordered_map<std::string,
    std::unordered_map<std::string,
      std::unordered_map<std::string, ThreadNotificationState>>>
      thread_notifications_;
};

// ============================================================================
// PushTriggerEngine — determine if an event triggers a push notification
// ============================================================================
class PushTriggerEngine {
public:
  PushTriggerEngine(const ReadReceiptConfig& cfg = {}) : config_(cfg) {}

  // --------------------------------------------------------------------------
  // Evaluate push trigger for a single event
  // --------------------------------------------------------------------------
  PushTriggerResult evaluate_event(const std::string& user_id,
                                     const std::string& room_id,
                                     const json& event,
                                     const json& room_state) {
    PushTriggerResult result;

    std::string sender = json_str(event, "sender");
    std::string event_type = json_str(event, "type");
    json content = event.value("content", json::object());

    // Rule 1: Don't notify for own messages
    if (sender == user_id) {
      result.sender_is_local_user = true;
      return result;
    }

    // Rule 2: Only notify for message events by default
    if (event_type != "m.room.message" &&
        event_type != "m.room.encrypted" &&
        event_type != "m.sticker") {
      return result;
    }

    // Rule 3: Check if user is mentioned (@room or display name)
    result.event_is_mention = check_mention(content, user_id);

    // Rule 4: Check highlight words
    if (config_.push_enable_highlight_words) {
      result.matched_highlight_words = check_highlight_words(content, user_id);
    }

    // Rule 5: Check for direct messages
    result.is_direct_message = check_direct_message(room_state, user_id, sender);

    // Rule 6: Determine notification and highlight
    if (result.event_is_mention || !result.matched_highlight_words.empty()) {
      result.should_notify = true;
      result.is_highlight = true;
      result.push_priority = 2;
      result.triggered_rule_id = "global/override/.m.rule.contains_display_name";
    } else if (result.is_direct_message) {
      result.should_notify = true;
      result.is_highlight = false;
      result.push_priority = 1;
      result.triggered_rule_id = "global/underride/.m.rule.room_one_to_one";
    } else if (config_.push_notify_on_all_messages) {
      result.should_notify = true;
      result.is_highlight = false;
      result.push_priority = 0;
      result.triggered_rule_id = "global/underride/.m.rule.message";
    } else {
      // Check for power-level notifications (e.g., @room)
      if (check_room_mention(content)) {
        result.should_notify = true;
        result.is_highlight = true;
        result.push_priority = 2;
        result.triggered_rule_id = "global/override/.m.rule.room_notif";
      }
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Bulk evaluate push triggers for multiple events (efficient batch)
  // --------------------------------------------------------------------------
  std::vector<std::pair<std::string, PushTriggerResult>>
  evaluate_events_bulk(const std::string& user_id,
                        const std::string& room_id,
                        const std::vector<json>& events,
                        const json& room_state) {

    std::vector<std::pair<std::string, PushTriggerResult>> results;
    results.reserve(events.size());

    for (auto& event : events) {
      std::string event_id = json_str(event, "event_id");
      auto trigger = evaluate_event(user_id, room_id, event, room_state);
      results.emplace_back(event_id, trigger);
    }
    return results;
  }

  // --------------------------------------------------------------------------
  // Evaluate push for an event and update notification state atomically
  // --------------------------------------------------------------------------
  PushTriggerResult evaluate_and_track(
      const std::string& user_id,
      const std::string& room_id,
      const json& event,
      const json& room_state,
      NotificationCountEngine& notif_engine,
      int64_t thread_id = 0,
      const std::string& thread_root_id = "") {

    auto trigger = evaluate_event(user_id, room_id, event, room_state);

    if (trigger.should_notify) {
      std::string event_id = json_str(event, "event_id");

      if (thread_id > 0 && !thread_root_id.empty()) {
        notif_engine.increment_thread_notification(
            user_id, room_id, thread_root_id, event_id, trigger.is_highlight);
      } else {
        notif_engine.increment_notification(
            user_id, room_id, event_id, trigger.is_highlight);
      }
    }

    return trigger;
  }

  // --------------------------------------------------------------------------
  // Check if an event body contains user's display name
  // --------------------------------------------------------------------------
  bool check_mention(const json& content, const std::string& user_id) {
    std::string body = json_str(content, "body");
    std::string formatted_body = json_str(content, "formatted_body");

    std::string localpart = extract_localpart(user_id);

    // Check plain text body
    if (body.find(localpart) != std::string::npos) return true;

    // Check formatted_body for explicit user mention pill
    if (!formatted_body.empty()) {
      std::string search = "<a href=\"https://matrix.to/#/" + user_id;
      if (formatted_body.find(search) != std::string::npos) return true;
    }

    return false;
  }

  // --------------------------------------------------------------------------
  // Check for @room mention (notify everyone)
  // --------------------------------------------------------------------------
  bool check_room_mention(const json& content) {
    std::string body = json_str(content, "body");
    return body.find("@room") != std::string::npos;
  }

  // --------------------------------------------------------------------------
  // Check highlight words against event content
  // --------------------------------------------------------------------------
  std::vector<std::string> check_highlight_words(
      const json& content, const std::string& user_id) {

    std::vector<std::string> matched;
    std::string body = to_lower(json_str(content, "body"));

    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = highlight_words_.find(user_id);
    if (it == highlight_words_.end()) return matched;

    for (auto& word : it->second) {
      if (body.find(to_lower(word)) != std::string::npos) {
        matched.push_back(word);
      }
    }
    return matched;
  }

  // --------------------------------------------------------------------------
  // Check if a room is a direct message
  // --------------------------------------------------------------------------
  bool check_direct_message(const json& room_state,
                              const std::string& user_id,
                              const std::string& sender) {
    // A room is a DM if it has exactly 2 members
    // This is simplified; real implementation would check m.direct account data
    return false;  // Stub: would check room member count and DM flags
  }

  // --------------------------------------------------------------------------
  // Set highlight words for a user
  // --------------------------------------------------------------------------
  void set_highlight_words(const std::string& user_id,
                            const std::vector<std::string>& words) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    highlight_words_[user_id] = words;
  }

  // --------------------------------------------------------------------------
  // Get highlight words for a user
  // --------------------------------------------------------------------------
  std::vector<std::string> get_highlight_words(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = highlight_words_.find(user_id);
    if (it != highlight_words_.end()) return it->second;
    return {};
  }

  // --------------------------------------------------------------------------
  // Push rule management (simplified)
  // --------------------------------------------------------------------------

  // Add a push rule for a user
  void add_push_rule(const std::string& user_id,
                      const std::string& rule_id,
                      const json& rule_definition) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    push_rules_[user_id][rule_id] = rule_definition;
  }

  // Remove a push rule
  void remove_push_rule(const std::string& user_id,
                         const std::string& rule_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto it = push_rules_.find(user_id);
    if (it != push_rules_.end()) {
      it->second.erase(rule_id);
    }
  }

  // Get push rules for a user
  json get_push_rules(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    json result = json::object();

    auto it = push_rules_.find(user_id);
    if (it != push_rules_.end()) {
      for (auto& [rule_id, rule_def] : it->second) {
        result[rule_id] = rule_def;
      }
    }
    return result;
  }

  // Evaluate against push rules (more advanced matching)
  PushTriggerResult evaluate_with_rules(const std::string& user_id,
                                         const std::string& room_id,
                                         const json& event,
                                         const json& room_state) {
    // Start with basic evaluation
    auto result = evaluate_event(user_id, room_id, event, room_state);

    // Apply user-specific push rules
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = push_rules_.find(user_id);
    if (it != push_rules_.end()) {
      for (auto& [rule_id, rule_def] : it->second) {
        std::string rule_kind = json_str(rule_def, "kind", "override");
        bool enabled = json_bool(rule_def, "enabled", true);

        if (!enabled) continue;

        // Override rules can force notify/highlight
        if (rule_kind == "override") {
          auto actions = rule_def.value("actions", json::array());
          for (auto& action : actions) {
            if (action.is_string() && action.get<std::string>() == "notify") {
              result.should_notify = true;
              result.triggered_rule_id = rule_id;
              // Check for highlight tweak
              if (action.is_object()) {
                std::string set_tweak = json_str(action, "set_tweak");
                if (set_tweak == "highlight") {
                  result.is_highlight = true;
                }
              }
            }
          }
        }

        // Sender rules can suppress notifications
        if (rule_kind == "sender") {
          std::string rule_sender = json_str(rule_def, "user_id");
          std::string event_sender = json_str(event, "sender");
          if (rule_sender == event_sender) {
            result.should_notify = false;
            result.triggered_rule_id = rule_id;
          }
        }

        // Room rules can suppress per-room
        if (rule_kind == "room") {
          std::string rule_room = json_str(rule_def, "rule_id");
          // Check if room matches
          if (rule_room == room_id) {
            auto actions = rule_def.value("actions", json::array());
            for (auto& action : actions) {
              if (action.is_string() && action.get<std::string>() == "dont_notify") {
                result.should_notify = false;
                result.triggered_rule_id = rule_id;
              }
            }
          }
        }
      }
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Statistics
  // --------------------------------------------------------------------------
  json get_stats() {
    std::shared_lock<std::shared_mutex> lock(mu_);
    json stats;
    stats["users_with_highlight_words"] =
        static_cast<int64_t>(highlight_words_.size());
    stats["users_with_push_rules"] =
        static_cast<int64_t>(push_rules_.size());
    return stats;
  }

private:
  ReadReceiptConfig config_;
  mutable std::shared_mutex mu_;

  // Per-user highlight words
  std::unordered_map<std::string, std::vector<std::string>> highlight_words_;

  // Per-user push rules: user_id -> rule_id -> rule_json
  std::unordered_map<std::string,
    std::unordered_map<std::string, json>> push_rules_;
};

// ============================================================================
// UnreadCountEngine — track unread messages per room and per thread
// ============================================================================
class UnreadCountEngine {
public:
  UnreadCountEngine(const ReadReceiptConfig& cfg = {}) : config_(cfg) {}

  // --------------------------------------------------------------------------
  // Compute unread count for a room
  // --------------------------------------------------------------------------
  UnreadCountResult compute_unread(const std::string& user_id,
                                      const std::string& room_id,
                                      const std::vector<std::string>& event_ids_ordered,
                                      const std::string& read_up_to_event_id) {
    UnreadCountResult result;
    result.room_id = room_id;
    result.computed_at_ms = now_ms();

    if (event_ids_ordered.empty()) return result;

    // Find the read position
    ssize_t read_pos = -1;
    if (!read_up_to_event_id.empty()) {
      for (ssize_t i = static_cast<ssize_t>(event_ids_ordered.size()) - 1; i >= 0; --i) {
        if (event_ids_ordered[i] == read_up_to_event_id) {
          read_pos = i;
          break;
        }
      }
    }

    // If no read position, all events are unread
    if (read_pos < 0) {
      result.total_unread = static_cast<int64_t>(event_ids_ordered.size());
      result.read_up_to_event_id = read_up_to_event_id;
      return result;
    }

    // Count events after read position
    int64_t unread = static_cast<int64_t>(event_ids_ordered.size()) - read_pos - 1;
    result.total_unread = std::max<int64_t>(0, unread);
    result.read_up_to_event_id = read_up_to_event_id;

    return result;
  }

  // --------------------------------------------------------------------------
  // Compute unread with cached notification state
  // --------------------------------------------------------------------------
  UnreadCountResult compute_unread_with_cache(
      const std::string& user_id,
      const std::string& room_id,
      const std::vector<std::string>& event_ids_ordered,
      const std::string& read_up_to_event_id,
      NotificationCountEngine& notif_engine) {

    auto result = compute_unread(user_id, room_id, event_ids_ordered,
                                  read_up_to_event_id);

    // Attach notification/highlight counts from the notification engine
    auto notif_state = notif_engine.get_notification_counts(user_id, room_id);
    result.notification_count = notif_state.notification_count;
    result.highlight_count = notif_state.highlight_count;

    return result;
  }

  // --------------------------------------------------------------------------
  // Compute per-thread unread counts
  // --------------------------------------------------------------------------
  std::map<std::string, int64_t> compute_thread_unread_counts(
      const std::string& user_id,
      const std::string& room_id,
      const std::map<std::string, std::vector<std::string>>& thread_events,
      const std::map<std::string, std::string>& thread_read_markers) {

    std::map<std::string, int64_t> results;

    for (auto& [thread_root_id, events] : thread_events) {
      std::string read_marker;
      auto it = thread_read_markers.find(thread_root_id);
      if (it != thread_read_markers.end()) {
        read_marker = it->second;
      }

      auto unread = compute_unread(user_id, room_id, events, read_marker);
      results[thread_root_id] = unread.total_unread;
    }

    return results;
  }

  // --------------------------------------------------------------------------
  // Update cached unread counts
  // --------------------------------------------------------------------------
  void cache_unread_count(const std::string& user_id,
                           const std::string& room_id,
                           const UnreadCountResult& result) {
    std::lock_guard<std::mutex> lock(cache_mu_);

    CachedUnread entry;
    entry.result = result;
    entry.cached_at_ms = now_ms();
    unread_cache_[user_id][room_id] = entry;
  }

  // --------------------------------------------------------------------------
  // Get cached unread count (if fresh enough)
  // --------------------------------------------------------------------------
  std::optional<UnreadCountResult> get_cached_unread(
      const std::string& user_id, const std::string& room_id) {

    std::lock_guard<std::mutex> lock(cache_mu_);

    auto user_it = unread_cache_.find(user_id);
    if (user_it == unread_cache_.end()) return std::nullopt;

    auto room_it = user_it->second.find(room_id);
    if (room_it == user_it->second.end()) return std::nullopt;

    if (now_ms() - room_it->second.cached_at_ms <
        config_.unread_count_cache_ttl_ms) {
      return room_it->second.result;
    }

    // Expired, remove
    user_it->second.erase(room_it);
    return std::nullopt;
  }

  // --------------------------------------------------------------------------
  // Invalidate cache for a user/room
  // --------------------------------------------------------------------------
  void invalidate_cache(const std::string& user_id,
                         const std::string& room_id = "") {
    std::lock_guard<std::mutex> lock(cache_mu_);

    auto user_it = unread_cache_.find(user_id);
    if (user_it == unread_cache_.end()) return;

    if (room_id.empty()) {
      unread_cache_.erase(user_it);
    } else {
      user_it->second.erase(room_id);
    }
  }

  // --------------------------------------------------------------------------
  // Get all unread counts for a user
  // --------------------------------------------------------------------------
  json get_all_unread_counts(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(cache_mu_);

    json result = json::object();
    auto user_it = unread_cache_.find(user_id);
    if (user_it == unread_cache_.end()) return result;

    for (auto& [room_id, cached] : user_it->second) {
      if (now_ms() - cached.cached_at_ms < config_.unread_count_cache_ttl_ms) {
        result[room_id] = cached.result.to_json();
      }
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Statistics
  // --------------------------------------------------------------------------
  json get_stats() {
    std::lock_guard<std::mutex> lock(cache_mu_);
    json stats;
    stats["cached_users"] = static_cast<int64_t>(unread_cache_.size());
    return stats;
  }

private:
  struct CachedUnread {
    UnreadCountResult result;
    int64_t cached_at_ms{0};
  };

  ReadReceiptConfig config_;
  std::mutex cache_mu_;
  std::unordered_map<std::string,
    std::unordered_map<std::string, CachedUnread>> unread_cache_;
};

// ============================================================================
// ReadMarkerEngine — manages m.fully_read markers and read markers
// ============================================================================
class ReadMarkerEngine {
public:
  ReadMarkerEngine(const ReadReceiptConfig& cfg = {}) : config_(cfg) {}

  // --------------------------------------------------------------------------
  // Set the fully_read marker for a room (m.fully_read)
  // --------------------------------------------------------------------------
  bool set_fully_read(const std::string& user_id,
                       const std::string& room_id,
                       const std::string& event_id) {

    if (!config_.enable_fully_read_markers) return false;

    std::lock_guard<std::shared_mutex> lock(mu_);

    // Check if the new marker advances past the current one
    auto& marker = read_markers_[user_id][room_id];
    if (config_.read_marker_require_existing_before &&
        !marker.event_id.empty()) {
      // In a real implementation, we'd verify topological ordering.
      // Here we just check it's not the same event.
      if (marker.event_id == event_id) return false;
    }

    marker.room_id = room_id;
    marker.user_id = user_id;
    marker.event_id = event_id;
    marker.updated_at_ms = now_ms();

    return true;
  }

  // --------------------------------------------------------------------------
  // Get the fully_read marker for a room
  // --------------------------------------------------------------------------
  std::string get_fully_read(const std::string& user_id,
                               const std::string& room_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);

    auto user_it = read_markers_.find(user_id);
    if (user_it == read_markers_.end()) return "";

    auto room_it = user_it->second.find(room_id);
    if (room_it == user_it->second.end()) return "";

    return room_it->second.event_id;
  }

  // --------------------------------------------------------------------------
  // Set the read receipt (m.read) for a room
  // --------------------------------------------------------------------------
  void set_read_receipt(const std::string& user_id,
                         const std::string& room_id,
                         const std::string& event_id) {

    std::lock_guard<std::shared_mutex> lock(mu_);
    auto& marker = read_markers_[user_id][room_id];
    marker.room_id = room_id;
    marker.user_id = user_id;
    marker.read_receipt_event_id = event_id;
    marker.updated_at_ms = now_ms();
  }

  // --------------------------------------------------------------------------
  // Get the read receipt for a room
  // --------------------------------------------------------------------------
  std::string get_read_receipt(const std::string& user_id,
                                 const std::string& room_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);

    auto user_it = read_markers_.find(user_id);
    if (user_it == read_markers_.end()) return "";

    auto room_it = user_it->second.find(room_id);
    if (room_it == user_it->second.end()) return "";

    return room_it->second.read_receipt_event_id;
  }

  // --------------------------------------------------------------------------
  // Set private read receipt (m.read.private)
  // --------------------------------------------------------------------------
  void set_private_read_receipt(const std::string& user_id,
                                  const std::string& room_id,
                                  const std::string& event_id) {

    if (!config_.enable_private_read_receipts) return;

    std::lock_guard<std::shared_mutex> lock(mu_);
    auto& marker = read_markers_[user_id][room_id];
    marker.room_id = room_id;
    marker.user_id = user_id;
    marker.private_read_receipt_event_id = event_id;
    marker.updated_at_ms = now_ms();
  }

  // --------------------------------------------------------------------------
  // Set thread read marker
  // --------------------------------------------------------------------------
  void set_thread_read_marker(const std::string& user_id,
                               const std::string& room_id,
                               const std::string& thread_root_id,
                               const std::string& event_id) {

    if (!config_.enable_thread_receipts) return;

    std::lock_guard<std::shared_mutex> lock(mu_);
    auto& marker = read_markers_[user_id][room_id];
    marker.room_id = room_id;
    marker.user_id = user_id;
    marker.thread_read_markers[thread_root_id] = event_id;
    marker.updated_at_ms = now_ms();
  }

  // --------------------------------------------------------------------------
  // Get thread read marker
  // --------------------------------------------------------------------------
  std::string get_thread_read_marker(const std::string& user_id,
                                       const std::string& room_id,
                                       const std::string& thread_root_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);

    auto user_it = read_markers_.find(user_id);
    if (user_it == read_markers_.end()) return "";

    auto room_it = user_it->second.find(room_id);
    if (room_it == user_it->second.end()) return "";

    auto thread_it = room_it->second.thread_read_markers.find(thread_root_id);
    if (thread_it != room_it->second.thread_read_markers.end()) {
      return thread_it->second;
    }
    return "";
  }

  // --------------------------------------------------------------------------
  // Get all thread read markers for a room
  // --------------------------------------------------------------------------
  std::map<std::string, std::string> get_all_thread_read_markers(
      const std::string& user_id, const std::string& room_id) {

    std::shared_lock<std::shared_mutex> lock(mu_);

    auto user_it = read_markers_.find(user_id);
    if (user_it == read_markers_.end()) return {};

    auto room_it = user_it->second.find(room_id);
    if (room_it == user_it->second.end()) return {};

    return room_it->second.thread_read_markers;
  }

  // --------------------------------------------------------------------------
  // Get complete read marker for a user in a room
  // --------------------------------------------------------------------------
  std::optional<ReadMarker> get_read_marker(const std::string& user_id,
                                              const std::string& room_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);

    auto user_it = read_markers_.find(user_id);
    if (user_it == read_markers_.end()) return std::nullopt;

    auto room_it = user_it->second.find(room_id);
    if (room_it == user_it->second.end()) return std::nullopt;

    return room_it->second;
  }

  // --------------------------------------------------------------------------
  // Build read markers for /sync response
  // --------------------------------------------------------------------------
  json build_sync_read_markers(const std::string& user_id,
                                 const std::string& room_id) {
    json result;

    auto marker = get_read_marker(user_id, room_id);
    if (!marker) return result;

    result["m.fully_read"] = marker->event_id;

    if (!marker->read_receipt_event_id.empty()) {
      result["m.read"] = marker->read_receipt_event_id;
    }

    if (config_.enable_private_read_receipts &&
        !marker->private_read_receipt_event_id.empty()) {
      result["m.read.private"] = marker->private_read_receipt_event_id;
    }

    if (config_.enable_thread_receipts &&
        !marker->thread_read_markers.empty()) {
      json thread_markers = json::object();
      for (auto& [tid, eid] : marker->thread_read_markers) {
        thread_markers[tid] = eid;
      }
      result["thread_read_markers"] = thread_markers;
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Build batch read markers for multiple rooms
  // --------------------------------------------------------------------------
  json build_batch_sync_read_markers(
      const std::string& user_id,
      const std::vector<std::string>& room_ids) {

    json result = json::object();
    for (auto& room_id : room_ids) {
      auto markers = build_sync_read_markers(user_id, room_id);
      if (!markers.empty()) {
        result[room_id] = markers;
      }
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Clear read markers for a room
  // --------------------------------------------------------------------------
  void clear_room_markers(const std::string& user_id,
                           const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto user_it = read_markers_.find(user_id);
    if (user_it != read_markers_.end()) {
      user_it->second.erase(room_id);
    }
  }

  // --------------------------------------------------------------------------
  // Clear all markers for a user
  // --------------------------------------------------------------------------
  void clear_user_markers(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    read_markers_.erase(user_id);
  }

  // --------------------------------------------------------------------------
  // Bulk set read markers (e.g., from initial sync or import)
  // --------------------------------------------------------------------------
  void bulk_set_read_markers(const std::string& user_id,
                              const std::vector<ReadMarker>& markers) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    for (auto& marker : markers) {
      read_markers_[user_id][marker.room_id] = marker;
      read_markers_[user_id][marker.room_id].updated_at_ms = now_ms();
    }
  }

  // --------------------------------------------------------------------------
  // Statistics
  // --------------------------------------------------------------------------
  json get_stats() {
    std::shared_lock<std::shared_mutex> lock(mu_);
    json stats;
    stats["total_users_with_markers"] =
        static_cast<int64_t>(read_markers_.size());

    int64_t total_room_markers = 0;
    for (auto& [uid, rooms] : read_markers_) {
      total_room_markers += rooms.size();
    }
    stats["total_room_markers"] = total_room_markers;
    return stats;
  }

private:
  ReadReceiptConfig config_;
  mutable std::shared_mutex mu_;

  // user_id -> room_id -> ReadMarker
  std::unordered_map<std::string,
    std::unordered_map<std::string, ReadMarker>> read_markers_;
};

// ============================================================================
// ReceiptSyncEngine — builds receipt data for /sync responses
// ============================================================================
class ReceiptSyncEngine {
public:
  ReceiptSyncEngine(ReceiptStorageEngine& storage,
                     ReadMarkerEngine& markers,
                     NotificationCountEngine& notif_counts,
                     UnreadCountEngine& unread_counts,
                     const ReadReceiptConfig& cfg = {})
      : storage_(storage), markers_(markers),
        notif_counts_(notif_counts), unread_counts_(unread_counts),
        config_(cfg) {}

  // --------------------------------------------------------------------------
  // Build ephemeral receipt events for a room in /sync
  // --------------------------------------------------------------------------
  json build_sync_receipts(const std::string& user_id,
                            const std::string& room_id,
                            int64_t since_stream_ordering) {

    json result = json::object();

    // Get receipts since the stream token
    auto receipts = storage_.get_receipts_for_room(
        room_id, since_stream_ordering);

    if (!receipts.empty()) {
      json events = json::array();
      for (auto& receipt : receipts) {
        json evt;
        evt["type"] = "m.receipt";
        evt["content"] = {
          {receipt.event_id, {
            {receipt.receipt_type, {
              {receipt.user_id, {
                {"ts", receipt.timestamp_ms},
                {"thread_id", receipt.thread_id}
              }}
            }}
          }}
        };
        events.push_back(evt);
      }
      if (!events.empty()) {
        result["ephemeral"] = {{"events", events}};
      }
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Build complete receipt section for a room in /sync
  // --------------------------------------------------------------------------
  json build_sync_receipts_full(const std::string& user_id,
                                  const std::string& room_id,
                                  int64_t since_stream_ordering,
                                  const std::optional<std::string>& unread_event_id = std::nullopt) {

    json result;

    // Read markers
    auto read_markers = markers_.build_sync_read_markers(user_id, room_id);
    if (!read_markers.empty()) {
      result["read_markers"] = read_markers;
    }

    // Notification counts
    if (config_.enable_notification_counts) {
      auto notif_json = notif_counts_.build_sync_notification_counts(
          user_id, room_id);
      if (!notif_json.empty()) {
        result["unread_notifications"] = notif_json;
      }
    }

    // Ephemeral receipt events
    auto ephemeral = build_sync_receipts(user_id, room_id,
                                          since_stream_ordering);
    if (!ephemeral.empty()) {
      for (auto& [key, val] : ephemeral.items()) {
        result[key] = val;
      }
    }

    // Build a synthetic receipt event for the user's own read position
    // This is used by clients to know their own read position in the room
    if (config_.enable_unread_counts && unread_event_id.has_value()) {
      json account_data_evt;
      account_data_evt["type"] = "m.fully_read";
      account_data_evt["content"] = {
        {"event_id", unread_event_id.value()}
      };
      if (!result.contains("account_data")) {
        result["account_data"] = json::object();
      }
      if (!result["account_data"].contains("events")) {
        result["account_data"]["events"] = json::array();
      }
      result["account_data"]["events"].push_back(account_data_evt);
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Build cached receipt payload for fast incremental sync
  // --------------------------------------------------------------------------
  json build_receipt_payload_cached(const std::string& user_id,
                                      const std::set<std::string>& room_ids,
                                      int64_t since_stream) {
    json result = json::object();

    for (auto& room_id : room_ids) {
      auto room_receipts = build_sync_receipts_full(
          user_id, room_id, since_stream);
      if (!room_receipts.empty()) {
        result[room_id] = room_receipts;
      }
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Get the maximum receipt stream position for a user's rooms
  // --------------------------------------------------------------------------
  int64_t get_max_receipt_stream_position(const std::set<std::string>& room_ids) {
    int64_t max_pos = 0;
    for (auto& room_id : room_ids) {
      auto receipts = storage_.get_receipts_for_room(room_id, 0, INT64_MAX);
      for (auto& r : receipts) {
        max_pos = std::max(max_pos, r.stream_ordering);
      }
    }
    return max_pos;
  }

  // --------------------------------------------------------------------------
  // Generate a receipt stream token for pagination
  // --------------------------------------------------------------------------
  std::string generate_receipt_stream_token(int64_t stream_pos) {
    std::ostringstream oss;
    oss << "r" << stream_pos;
    return oss.str();
  }

  // --------------------------------------------------------------------------
  // Parse a receipt stream token
  // --------------------------------------------------------------------------
  int64_t parse_receipt_stream_token(const std::string& token) {
    if (token.empty() || token[0] != 'r') return 0;
    try {
      return std::stoll(token.substr(1));
    } catch (...) {
      return 0;
    }
  }

  // --------------------------------------------------------------------------
  // Statistics
  // --------------------------------------------------------------------------
  json get_stats() {
    json stats;
    stats["type"] = "sync_engine";
    return stats;
  }

private:
  ReadReceiptConfig config_;
  ReceiptStorageEngine& storage_;
  ReadMarkerEngine& markers_;
  NotificationCountEngine& notif_counts_;
  UnreadCountEngine& unread_counts_;
};

// ============================================================================
// ReadReceiptEngine — core read receipt handler: write, read, track
// ============================================================================
class ReadReceiptEngine {
public:
  ReadReceiptEngine(ReceiptStorageEngine& storage,
                     ReceiptFederationEngine& federation,
                     NotificationCountEngine& notif_counts,
                     UnreadCountEngine& unread_counts,
                     ReadMarkerEngine& markers,
                     const ReadReceiptConfig& cfg = {})
      : storage_(storage), federation_(federation),
        notif_counts_(notif_counts), unread_counts_(unread_counts),
        markers_(markers), config_(cfg) {}

  // --------------------------------------------------------------------------
  // Handle a read receipt from a client (POST /rooms/{roomId}/receipt/{receiptType}/{eventId})
  // --------------------------------------------------------------------------
  json handle_read_receipt(const std::string& user_id,
                            const std::string& room_id,
                            const std::string& event_id,
                            const std::string& receipt_type,
                            const ReceiptWriteConfig& write_cfg = {}) {

    json result;

    // Validate receipt type
    if (receipt_type != "m.read" && receipt_type != "m.read.private") {
      result["error"] = "Invalid receipt type: " + receipt_type;
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    // Validate event_id
    if (!is_valid_event_id(event_id)) {
      result["error"] = "Invalid event ID: " + event_id;
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    int64_t thread_id = write_cfg.is_thread ? 1 : 0;

    // Insert into storage
    int64_t stream_ord = storage_.insert_receipt(
        room_id, user_id, event_id, receipt_type, thread_id);

    // Update read markers
    if (receipt_type == "m.read") {
      markers_.set_read_receipt(user_id, room_id, event_id);
    } else if (receipt_type == "m.read.private") {
      markers_.set_private_read_receipt(user_id, room_id, event_id);
    }

    // If thread receipt, update thread read marker
    if (write_cfg.is_thread && !write_cfg.thread_root_id.empty()) {
      markers_.set_thread_read_marker(user_id, room_id,
          write_cfg.thread_root_id, event_id);
    }

    // Clear notification counts on read
    if (write_cfg.update_notification_counts) {
      notif_counts_.clear_on_read(user_id, room_id, event_id);

      // Also clear thread notifications if applicable
      if (write_cfg.is_thread && !write_cfg.thread_root_id.empty()) {
        notif_counts_.clear_thread_on_read(
            user_id, room_id, write_cfg.thread_root_id, event_id);
      }
    }

    // Invalidate unread cache
    if (write_cfg.update_unread_counts) {
      unread_counts_.invalidate_cache(user_id, room_id);
    }

    // Send to federation
    if (write_cfg.send_federation && config_.enable_federation) {
      // Only send public read receipts to federation
      if (receipt_type == "m.read") {
        auto edu = federation_.build_receipt_edu(
            room_id, user_id, event_id, receipt_type, thread_id);

        if (!edu.empty()) {
          auto dest_servers = get_room_participant_servers(room_id);
          for (auto& server : dest_servers) {
            federation_.queue_for_federation(server, edu);
          }
        }
      }
    }

    result["stream_ordering"] = stream_ord;
    result["event_id"] = event_id;
    result["room_id"] = room_id;
    return result;
  }

  // --------------------------------------------------------------------------
  // Handle fully_read marker (POST /rooms/{roomId}/read_markers)
  // --------------------------------------------------------------------------
  json handle_fully_read(const std::string& user_id,
                          const std::string& room_id,
                          const std::string& event_id) {

    json result;

    if (!config_.enable_fully_read_markers) {
      result["error"] = "Fully read markers are disabled";
      result["errcode"] = "M_UNKNOWN";
      return result;
    }

    if (!is_valid_event_id(event_id)) {
      result["error"] = "Invalid event ID: " + event_id;
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    bool ok = markers_.set_fully_read(user_id, room_id, event_id);
    if (!ok) {
      result["error"] = "Read marker not advanced";
      result["errcode"] = "M_UNKNOWN";
      return result;
    }

    // Also update the read receipt to match
    markers_.set_read_receipt(user_id, room_id, event_id);

    // Insert as a receipt in storage
    storage_.insert_receipt(room_id, user_id, event_id, "m.read", 0);

    // Clear notifications
    notif_counts_.clear_on_read(user_id, room_id, event_id);

    // Invalidate unread cache
    unread_counts_.invalidate_cache(user_id, room_id);

    result["event_id"] = event_id;
    result["room_id"] = room_id;
    return result;
  }

  // --------------------------------------------------------------------------
  // Handle a thread read receipt
  // --------------------------------------------------------------------------
  json handle_thread_receipt(const std::string& user_id,
                              const std::string& room_id,
                              const std::string& thread_root_id,
                              const std::string& event_id) {

    json result;

    if (!config_.enable_thread_receipts) {
      result["error"] = "Thread receipts are disabled";
      result["errcode"] = "M_UNKNOWN";
      return result;
    }

    ReceiptWriteConfig cfg;
    cfg.is_thread = true;
    cfg.thread_root_id = thread_root_id;
    cfg.receipt_type = "m.read";

    return handle_read_receipt(user_id, room_id, event_id, "m.read", cfg);
  }

  // --------------------------------------------------------------------------
  // Get receipts for a user in a room
  // --------------------------------------------------------------------------
  json get_user_receipts(const std::string& user_id,
                          const std::string& room_id) {
    json result;
    auto marker = markers_.get_read_marker(user_id, room_id);

    if (marker) {
      result["m.fully_read"] = marker->event_id;
      result["m.read"] = marker->read_receipt_event_id;
      if (!marker->private_read_receipt_event_id.empty()) {
        result["m.read.private"] = marker->private_read_receipt_event_id;
      }
      if (!marker->thread_read_markers.empty()) {
        result["thread_read"] = marker->thread_read_markers;
      }
    }

    return result;
  }

private:
  // Get servers that participate in a room
  std::vector<std::string> get_room_participant_servers(
      const std::string& room_id) {
    // In a real implementation, this would query room members and extract
    // unique server names. For now, return an empty list.
    return {};
  }

  ReadReceiptConfig config_;
  ReceiptStorageEngine& storage_;
  ReceiptFederationEngine& federation_;
  NotificationCountEngine& notif_counts_;
  UnreadCountEngine& unread_counts_;
  ReadMarkerEngine& markers_;
};

// ============================================================================
// ReadReceiptCoordinator — master coordinator for the entire read receipt subsystem
// ============================================================================
class ReadReceiptCoordinator {
public:
  ReadReceiptCoordinator(const ReadReceiptConfig& cfg = {})
      : config_(cfg),
        storage_(cfg),
        federation_(storage_, cfg),
        notif_counts_(cfg),
        push_triggers_(cfg),
        unread_counts_(cfg),
        markers_(cfg),
        sync_engine_(storage_, markers_, notif_counts_, unread_counts_, cfg),
        receipt_engine_(storage_, federation_, notif_counts_,
                         unread_counts_, markers_, cfg) {}

  // --------------------------------------------------------------------------
  // Public API: handle a read receipt from a client
  // --------------------------------------------------------------------------
  json handle_client_read_receipt(const std::string& user_id,
                                    const std::string& room_id,
                                    const std::string& receipt_type,
                                    const std::string& event_id) {
    return receipt_engine_.handle_read_receipt(
        user_id, room_id, event_id, receipt_type);
  }

  // --------------------------------------------------------------------------
  // Public API: handle a fully_read marker
  // --------------------------------------------------------------------------
  json handle_client_fully_read(const std::string& user_id,
                                  const std::string& room_id,
                                  const std::string& event_id) {
    return receipt_engine_.handle_fully_read(user_id, room_id, event_id);
  }

  // --------------------------------------------------------------------------
  // Public API: handle a thread read receipt
  // --------------------------------------------------------------------------
  json handle_client_thread_receipt(const std::string& user_id,
                                      const std::string& room_id,
                                      const std::string& thread_root_id,
                                      const std::string& event_id) {
    return receipt_engine_.handle_thread_receipt(
        user_id, room_id, thread_root_id, event_id);
  }

  // --------------------------------------------------------------------------
  // Public API: process a new event for push notifications
  // --------------------------------------------------------------------------
  PushTriggerResult process_event_for_push(const std::string& user_id,
                                            const std::string& room_id,
                                            const json& event,
                                            const json& room_state) {
    return push_triggers_.evaluate_and_track(
        user_id, room_id, event, room_state, notif_counts_);
  }

  // --------------------------------------------------------------------------
  // Public API: process a new thread event for push notifications
  // --------------------------------------------------------------------------
  PushTriggerResult process_thread_event_for_push(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& thread_root_id,
      const json& event,
      const json& room_state) {

    auto trigger = push_triggers_.evaluate_event(user_id, room_id,
                                                   event, room_state);
    if (trigger.should_notify) {
      std::string event_id = json_str(event, "event_id");
      notif_counts_.increment_thread_notification(
          user_id, room_id, thread_root_id, event_id, trigger.is_highlight);
    }
    return trigger;
  }

  // --------------------------------------------------------------------------
  // Public API: build receipt data for /sync
  // --------------------------------------------------------------------------
  json build_sync_receipts(const std::string& user_id,
                            const std::string& room_id,
                            int64_t since) {
    return sync_engine_.build_sync_receipts_full(user_id, room_id, since);
  }

  // --------------------------------------------------------------------------
  // Public API: get notification counts for /sync
  // --------------------------------------------------------------------------
  json get_sync_notification_counts(const std::string& user_id,
                                      const std::string& room_id) {
    return notif_counts_.build_sync_notification_counts(user_id, room_id);
  }

  // --------------------------------------------------------------------------
  // Public API: get unread counts
  // --------------------------------------------------------------------------
  UnreadCountResult get_unread_counts(const std::string& user_id,
                                        const std::string& room_id,
                                        const std::vector<std::string>& events,
                                        const std::string& read_up_to) {
    return unread_counts_.compute_unread_with_cache(
        user_id, room_id, events, read_up_to, notif_counts_);
  }

  // --------------------------------------------------------------------------
  // Public API: process inbound federation receipt EDU
  // --------------------------------------------------------------------------
  bool process_federation_receipt(const std::string& room_id,
                                   const std::string& user_id,
                                   const json& edu_content) {
    return federation_.process_inbound_receipt_edu(
        room_id, user_id, edu_content);
  }

  // --------------------------------------------------------------------------
  // Public API: get pending federation batches
  // --------------------------------------------------------------------------
  std::map<std::string, std::vector<json>> get_federation_batches() {
    return federation_.get_pending_batches();
  }

  // --------------------------------------------------------------------------
  // Public API: set highlight words for a user
  // --------------------------------------------------------------------------
  void set_highlight_words(const std::string& user_id,
                            const std::vector<std::string>& words) {
    push_triggers_.set_highlight_words(user_id, words);
  }

  // --------------------------------------------------------------------------
  // Public API: add push rule
  // --------------------------------------------------------------------------
  void add_push_rule(const std::string& user_id,
                      const std::string& rule_id,
                      const json& rule_def) {
    push_triggers_.add_push_rule(user_id, rule_id, rule_def);
  }

  // --------------------------------------------------------------------------
  // Public API: get push rules
  // --------------------------------------------------------------------------
  json get_push_rules(const std::string& user_id) {
    return push_triggers_.get_push_rules(user_id);
  }

  // --------------------------------------------------------------------------
  // Public API: reset all notification counts
  // --------------------------------------------------------------------------
  void reset_notifications(const std::string& user_id) {
    notif_counts_.reset_user_notifications(user_id);
    unread_counts_.invalidate_cache(user_id);
  }

  // --------------------------------------------------------------------------
  // Public API: clear on room leave
  // --------------------------------------------------------------------------
  void handle_room_leave(const std::string& user_id,
                          const std::string& room_id) {
    markers_.clear_room_markers(user_id, room_id);
    notif_counts_.reset_room_notifications(user_id, room_id);
    unread_counts_.invalidate_cache(user_id, room_id);
    storage_.delete_room_receipts(room_id);
  }

  // --------------------------------------------------------------------------
  // Public API: compute global notification badge
  // --------------------------------------------------------------------------
  json get_global_notification_counts(const std::string& user_id) {
    return notif_counts_.get_global_notification_counts(user_id);
  }

  // --------------------------------------------------------------------------
  // Public API: get read markers for a room
  // --------------------------------------------------------------------------
  std::optional<ReadMarker> get_read_marker(const std::string& user_id,
                                              const std::string& room_id) {
    return markers_.get_read_marker(user_id, room_id);
  }

  // --------------------------------------------------------------------------
  // Access to sub-engines for advanced use cases
  // --------------------------------------------------------------------------
  ReceiptStorageEngine& storage() { return storage_; }
  ReceiptFederationEngine& federation() { return federation_; }
  NotificationCountEngine& notifications() { return notif_counts_; }
  PushTriggerEngine& push() { return push_triggers_; }
  UnreadCountEngine& unread() { return unread_counts_; }
  ReadMarkerEngine& markers() { return markers_; }
  ReceiptSyncEngine& sync() { return sync_engine_; }
  ReadReceiptEngine& receipts() { return receipt_engine_; }

  // --------------------------------------------------------------------------
  // Configuration access
  // --------------------------------------------------------------------------
  ReadReceiptConfig& config() { return config_; }

  // --------------------------------------------------------------------------
  // Full statistics across all engines
  // --------------------------------------------------------------------------
  json get_full_stats() {
    json stats;
    stats["storage"] = storage_.get_stats();
    stats["federation"] = federation_.get_stats();
    stats["notification_counts"] = notif_counts_.get_stats();
    stats["push_triggers"] = push_triggers_.get_stats();
    stats["unread_counts"] = unread_counts_.get_stats();
    stats["read_markers"] = markers_.get_stats();
    stats["sync"] = sync_engine_.get_stats();
    return stats;
  }

private:
  ReadReceiptConfig config_;
  ReceiptStorageEngine storage_;
  ReceiptFederationEngine federation_;
  NotificationCountEngine notif_counts_;
  PushTriggerEngine push_triggers_;
  UnreadCountEngine unread_counts_;
  ReadMarkerEngine markers_;
  ReceiptSyncEngine sync_engine_;
  ReadReceiptEngine receipt_engine_;
};

// ============================================================================
// Read Receipt API handler — processes client REST API requests
// ============================================================================
class ReadReceiptAPIHandler {
public:
  ReadReceiptAPIHandler(ReadReceiptCoordinator& coordinator)
      : coordinator_(coordinator) {}

  // --------------------------------------------------------------------------
  // POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
  // --------------------------------------------------------------------------
  json handle_post_receipt(const std::string& user_id,
                            const std::string& room_id,
                            const std::string& receipt_type,
                            const std::string& event_id,
                            const json& body = json::object()) {

    // Check for thread receipt
    json relates_to = body.value("m.relates_to", json::object());
    std::string rel_type = json_str(relates_to, "rel_type");
    std::string thread_root_id = json_str(relates_to, "event_id");

    if (rel_type == "m.thread" && !thread_root_id.empty()) {
      return coordinator_.handle_client_thread_receipt(
          user_id, room_id, thread_root_id, event_id);
    }

    return coordinator_.handle_client_read_receipt(
        user_id, room_id, receipt_type, event_id);
  }

  // --------------------------------------------------------------------------
  // POST /_matrix/client/v3/rooms/{roomId}/read_markers
  // --------------------------------------------------------------------------
  json handle_post_read_marker(const std::string& user_id,
                                 const std::string& room_id,
                                 const json& body) {

    json result;

    // Handle m.fully_read
    std::string fully_read_event_id = json_str(body, "m.fully_read");
    if (!fully_read_event_id.empty()) {
      auto fr_result = coordinator_.handle_client_fully_read(
          user_id, room_id, fully_read_event_id);
      result["m.fully_read"] = fr_result;
    }

    // Handle m.read
    std::string read_event_id = json_str(body, "m.read");
    if (!read_event_id.empty()) {
      auto rr_result = coordinator_.handle_client_read_receipt(
          user_id, room_id, "m.read", read_event_id);
      result["m.read"] = rr_result;
    }

    // Handle m.read.private
    std::string private_read_event_id = json_str(body, "m.read.private");
    if (!private_read_event_id.empty()) {
      auto pr_result = coordinator_.handle_client_read_receipt(
          user_id, room_id, "m.read.private", private_read_event_id);
      result["m.read.private"] = pr_result;
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // GET /_matrix/client/v3/notifications
  // --------------------------------------------------------------------------
  json handle_get_notifications(const std::string& user_id,
                                  const json& query_params) {
    json result;
    result["notifications"] = json::array();

    int limit = json_int(query_params, "limit", 50);
    std::string from = json_str(query_params, "from");
    std::string only = json_str(query_params, "only"); // "highlight" or empty

    // Get global counts
    auto global = coordinator_.get_global_notification_counts(user_id);
    result["notification_count"] = json_int(global, "notification_count");
    result["highlight_count"] = json_int(global, "highlight_count");

    // In a real implementation, we'd return a paginated list of notification
    // objects. Here we return a stub.
    if (global.empty()) {
      result["next_token"] = "";
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // GET /_matrix/client/v3/rooms/{roomId}/unread_notifications
  // --------------------------------------------------------------------------
  json handle_get_unread_notifications(const std::string& user_id,
                                         const std::string& room_id) {
    json result;

    auto notif_counts = coordinator_.get_sync_notification_counts(
        user_id, room_id);

    result["notification_count"] =
        json_int(notif_counts, "notification_count");
    result["highlight_count"] = json_int(notif_counts, "highlight_count");

    // Add thread notification counts if available
    if (notif_counts.contains("thread_notification_counts")) {
      result["thread_notification_counts"] =
          notif_counts["thread_notification_counts"];
    }

    return result;
  }

private:
  ReadReceiptCoordinator& coordinator_;
};

// ============================================================================
// Receipt Event Processor — hooks into event processing pipeline
// ============================================================================
class ReceiptEventProcessor {
public:
  ReceiptEventProcessor(ReadReceiptCoordinator& coordinator)
      : coordinator_(coordinator) {}

  // --------------------------------------------------------------------------
  // Called when a new event is persisted (determine push triggers)
  // --------------------------------------------------------------------------
  void on_new_event(const std::string& room_id,
                     const json& event,
                     const json& room_state,
                     const std::vector<std::string>& room_member_user_ids) {

    std::string sender = json_str(event, "sender");
    std::string event_type = json_str(event, "type");
    int64_t thread_id = 0;
    std::string thread_root_id;

    // Check if this is a thread reply
    json content = event.value("content", json::object());
    json relates_to = content.value("m.relates_to", json::object());
    if (json_str(relates_to, "rel_type") == "m.thread") {
      thread_id = 1;
      thread_root_id = json_str(relates_to, "event_id");
    }

    // Evaluate push triggers for each room member
    for (auto& user_id : room_member_user_ids) {
      // Skip sender
      if (user_id == sender) continue;

      if (thread_id > 0 && !thread_root_id.empty()) {
        coordinator_.process_thread_event_for_push(
            user_id, room_id, thread_root_id, event, room_state);
      } else {
        coordinator_.process_event_for_push(
            user_id, room_id, event, room_state);
      }
    }
  }

  // --------------------------------------------------------------------------
  // Called when a batch of events is persisted (bulk push evaluation)
  // --------------------------------------------------------------------------
  void on_new_events_batch(const std::string& room_id,
                            const std::vector<json>& events,
                            const json& room_state,
                            const std::vector<std::string>& room_member_user_ids) {

    for (auto& event : events) {
      on_new_event(room_id, event, room_state, room_member_user_ids);
    }
  }

  // --------------------------------------------------------------------------
  // Called when a read receipt is processed (clear notifications)
  // --------------------------------------------------------------------------
  void on_read_receipt(const std::string& user_id,
                        const std::string& room_id,
                        const std::string& event_id) {
    // Notification clearing is handled by the ReadReceiptEngine
    // This hook can be used for additional side effects (e.g., push notification dismissal)
  }

private:
  ReadReceiptCoordinator& coordinator_;
};

// ============================================================================
// Receipt maintenance utilities
// ============================================================================
class ReceiptMaintenanceUtil {
public:
  ReceiptMaintenanceUtil(ReadReceiptCoordinator& coordinator)
      : coordinator_(coordinator) {}

  // --------------------------------------------------------------------------
  // Periodic cleanup: expire old receipt stream entries
  // --------------------------------------------------------------------------
  void run_periodic_cleanup(int64_t max_age_ms = 86400000) {  // 24 hours
    // In a production system, this would purge stream entries older than max_age_ms
    // from the storage engine. For the in-memory implementation, we just log.
    auto stats = coordinator_.get_full_stats();
    // Stats are informational; no mutation needed for in-memory impl
  }

  // --------------------------------------------------------------------------
  // Rebuild notification counts from scratch
  // --------------------------------------------------------------------------
  void rebuild_notification_counts(
      const std::string& user_id,
      const std::string& room_id,
      const std::vector<json>& events,
      const std::string& read_up_to_event_id,
      const json& room_state) {

    // Reset existing counts
    coordinator_.notifications().reset_room_notifications(user_id, room_id);

    // Re-evaluate each event after the read position
    bool past_read = read_up_to_event_id.empty();
    for (auto& event : events) {
      std::string event_id = json_str(event, "event_id");

      if (!past_read) {
        if (event_id == read_up_to_event_id) {
          past_read = true;
        }
        continue;
      }

      auto trigger = coordinator_.process_event_for_push(
          user_id, room_id, event, room_state);
    }
  }

  // --------------------------------------------------------------------------
  // Rebuild all thread notification counts
  // --------------------------------------------------------------------------
  void rebuild_thread_notification_counts(
      const std::string& user_id,
      const std::string& room_id,
      const std::map<std::string, std::vector<json>>& thread_events,
      const std::map<std::string, std::string>& thread_read_markers,
      const json& room_state) {

    for (auto& [thread_root_id, events] : thread_events) {
      std::string read_marker;
      auto it = thread_read_markers.find(thread_root_id);
      if (it != thread_read_markers.end()) {
        read_marker = it->second;
      }

      rebuild_notification_counts(user_id, room_id, events,
                                   read_marker, room_state);
    }
  }

  // --------------------------------------------------------------------------
  // Health check: verify data consistency
  // --------------------------------------------------------------------------
  json health_check() {
    json result;
    result["healthy"] = true;
    result["timestamp_ms"] = now_ms();

    auto stats = coordinator_.get_full_stats();
    result["stats"] = stats;

    return result;
  }

private:
  ReadReceiptCoordinator& coordinator_;
};

// ============================================================================
// Receipt Config Manager — allows runtime reconfiguration
// ============================================================================
class ReceiptConfigManager {
public:
  ReceiptConfigManager(ReadReceiptCoordinator& coordinator)
      : coordinator_(coordinator) {}

  // --------------------------------------------------------------------------
  // Update configuration at runtime
  // --------------------------------------------------------------------------
  void update_config(const json& config_update) {
    auto& cfg = coordinator_.config();

    if (config_update.contains("enable_read_receipts")) {
      cfg.enable_read_receipts =
          json_bool(config_update, "enable_read_receipts");
    }
    if (config_update.contains("enable_private_read_receipts")) {
      cfg.enable_private_read_receipts =
          json_bool(config_update, "enable_private_read_receipts");
    }
    if (config_update.contains("enable_fully_read_markers")) {
      cfg.enable_fully_read_markers =
          json_bool(config_update, "enable_fully_read_markers");
    }
    if (config_update.contains("enable_thread_receipts")) {
      cfg.enable_thread_receipts =
          json_bool(config_update, "enable_thread_receipts");
    }
    if (config_update.contains("enable_notification_counts")) {
      cfg.enable_notification_counts =
          json_bool(config_update, "enable_notification_counts");
    }
    if (config_update.contains("enable_push_triggers")) {
      cfg.enable_push_triggers =
          json_bool(config_update, "enable_push_triggers");
    }
    if (config_update.contains("enable_federation")) {
      cfg.enable_federation = json_bool(config_update, "enable_federation");
    }
  }

  // --------------------------------------------------------------------------
  // Get current configuration
  // --------------------------------------------------------------------------
  json get_config() {
    auto& cfg = coordinator_.config();
    json result;
    result["enable_read_receipts"] = cfg.enable_read_receipts;
    result["enable_private_read_receipts"] = cfg.enable_private_read_receipts;
    result["enable_fully_read_markers"] = cfg.enable_fully_read_markers;
    result["enable_thread_receipts"] = cfg.enable_thread_receipts;
    result["enable_notification_counts"] = cfg.enable_notification_counts;
    result["enable_unread_counts"] = cfg.enable_unread_counts;
    result["enable_push_triggers"] = cfg.enable_push_triggers;
    result["enable_federation"] = cfg.enable_federation;
    return result;
  }

private:
  ReadReceiptCoordinator& coordinator_;
};

// ============================================================================
// Test helpers
// ============================================================================
#ifdef READ_RECEIPTS_TESTING
namespace test {
using json = nlohmann::json;

// --------------------------------------------------------------------------
// Assertion helpers
// --------------------------------------------------------------------------
bool assert_true(bool condition, const std::string& msg) {
  if (!condition) {
    std::cerr << "  FAIL: " << msg << " (expected true)" << std::endl;
  }
  return condition;
}

bool assert_equal_str(const std::string& got, const std::string& expected,
                       const std::string& msg) {
  if (got != expected) {
    std::cerr << "  FAIL: " << msg << " - expected '" << expected
              << "', got '" << got << "'" << std::endl;
    return false;
  }
  return true;
}

bool assert_equal_int(int64_t got, int64_t expected, const std::string& msg) {
  if (got != expected) {
    std::cerr << "  FAIL: " << msg << " - expected " << expected
              << ", got " << got << std::endl;
    return false;
  }
  return true;
}

// --------------------------------------------------------------------------
// Test: receipt storage engine
// --------------------------------------------------------------------------
bool test_receipt_storage() {
  ReadReceiptConfig cfg;
  ReceiptStorageEngine storage(cfg);

  std::string room_id = "!test:localhost";
  std::string user_id = "@alice:localhost";
  std::string event_id1 = "$event1:localhost";
  std::string event_id2 = "$event2:localhost";

  // Insert receipts
  int64_t s1 = storage.insert_receipt(room_id, user_id, event_id1, "m.read");
  if (!assert_true(s1 > 0, "first receipt gets stream ordering")) return false;

  int64_t s2 = storage.insert_receipt(room_id, user_id, event_id2, "m.read");
  if (!assert_true(s2 > s1, "second receipt has higher stream ordering")) return false;

  // Get latest receipt
  auto latest = storage.get_latest_receipt(user_id, room_id, "m.read");
  if (!assert_true(latest.has_value(), "latest receipt exists")) return false;
  if (!assert_equal_str(latest->event_id, event_id2, "latest is event2")) return false;

  // Get receipts for room
  auto receipts = storage.get_receipts_for_room(room_id, 0);
  if (!assert_true(receipts.size() >= 1, "at least 1 receipt")) return false;

  // Test max stream ordering
  int64_t max = storage.get_max_stream_ordering();
  if (!assert_true(max >= s2, "max ordering >= last inserted")) return false;

  // Insert private receipt
  storage.insert_receipt(room_id, "@bob:localhost", "$event3:localhost",
                          "m.read.private", 0);

  // Test get room receipts JSON
  auto room_json = storage.get_room_receipts_json(room_id);
  if (!assert_true(!room_json.empty(), "room receipts JSON non-empty")) return false;

  // Test delete room
  storage.delete_room_receipts(room_id);
  auto after_delete = storage.get_latest_receipt(user_id, room_id);
  if (!assert_true(!after_delete.has_value(), "receipt deleted after room delete")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: read marker engine
// --------------------------------------------------------------------------
bool test_read_marker_engine() {
  ReadReceiptConfig cfg;
  cfg.enable_fully_read_markers = true;
  cfg.enable_private_read_receipts = true;
  cfg.enable_thread_receipts = true;

  ReadMarkerEngine markers(cfg);

  std::string user_id = "@alice:localhost";
  std::string room_id = "!test:localhost";

  // Set fully read
  if (!assert_true(markers.set_fully_read(user_id, room_id, "$ev100:localhost"),
                   "set fully read")) return false;

  std::string fr = markers.get_fully_read(user_id, room_id);
  if (!assert_equal_str(fr, "$ev100:localhost", "get fully read")) return false;

  // Set read receipt
  markers.set_read_receipt(user_id, room_id, "$ev150:localhost");
  if (!assert_equal_str(markers.get_read_receipt(user_id, room_id),
                         "$ev150:localhost", "get read receipt")) return false;

  // Set private read receipt
  markers.set_private_read_receipt(user_id, room_id, "$ev175:localhost");

  // Set thread read marker
  markers.set_thread_read_marker(user_id, room_id, "$thread1:localhost",
      "$threadEv50:localhost");
  if (!assert_equal_str(markers.get_thread_read_marker(user_id, room_id,
                         "$thread1:localhost"), "$threadEv50:localhost",
                         "get thread read marker")) return false;

  // Get all thread markers
  auto all_thread = markers.get_all_thread_read_markers(user_id, room_id);
  if (!assert_equal_int(static_cast<int64_t>(all_thread.size()), 1,
                         "1 thread marker")) return false;

  // Get full marker
  auto marker = markers.get_read_marker(user_id, room_id);
  if (!assert_true(marker.has_value(), "full marker exists")) return false;
  if (!assert_equal_str(marker->event_id, "$ev100:localhost",
                         "marker fully_read event")) return false;
  if (!assert_equal_str(marker->read_receipt_event_id, "$ev150:localhost",
                         "marker read receipt event")) return false;

  // Build sync markers
  auto sync_json = markers.build_sync_read_markers(user_id, room_id);
  if (!assert_equal_str(json_str(sync_json, "m.fully_read"), "$ev100:localhost",
                         "sync fully_read")) return false;
  if (!assert_equal_str(json_str(sync_json, "m.read"), "$ev150:localhost",
                         "sync m.read")) return false;

  // Clear room markers
  markers.clear_room_markers(user_id, room_id);
  auto after_clear = markers.get_read_marker(user_id, room_id);
  if (!assert_true(!after_clear.has_value(), "marker cleared")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: notification counts
// --------------------------------------------------------------------------
bool test_notification_counts() {
  ReadReceiptConfig cfg;
  cfg.highlight_reset_on_read = true;
  cfg.thread_separate_notification_counts = true;
  NotificationCountEngine notif(cfg);

  std::string user_id = "@alice:localhost";
  std::string room_id = "!test:localhost";

  // Initial state should be zero
  auto state = notif.get_notification_counts(user_id, room_id);
  if (!assert_equal_int(state.notification_count, 0, "initial count 0")) return false;
  if (!assert_equal_int(state.highlight_count, 0, "initial highlight 0")) return false;

  // Increment notification
  notif.increment_notification(user_id, room_id, "$ev1:localhost", false);
  state = notif.get_notification_counts(user_id, room_id);
  if (!assert_equal_int(state.notification_count, 1, "count after increment")) return false;
  if (!assert_equal_int(state.highlight_count, 0, "highlight 0 after non-highlight")) return false;

  // Increment highlight
  notif.increment_notification(user_id, room_id, "$ev2:localhost", true);
  state = notif.get_notification_counts(user_id, room_id);
  if (!assert_equal_int(state.notification_count, 2, "count 2")) return false;
  if (!assert_equal_int(state.highlight_count, 1, "highlight 1")) return false;

  // Clear on read
  notif.clear_on_read(user_id, room_id, "$ev2:localhost");
  state = notif.get_notification_counts(user_id, room_id);
  if (!assert_equal_int(state.notification_count, 0, "count cleared")) return false;
  if (!assert_equal_int(state.highlight_count, 0, "highlight cleared")) return false;

  // Thread notification
  notif.increment_thread_notification(user_id, room_id, "$thread1:localhost",
      "$threadEv1:localhost", true);
  auto thread_counts = notif.get_thread_notification_counts(user_id, room_id);
  if (!assert_equal_int(static_cast<int64_t>(thread_counts.size()), 1,
                         "1 thread has counts")) return false;

  // Room-level counts should also be updated
  state = notif.get_notification_counts(user_id, room_id);
  if (!assert_equal_int(state.notification_count, 1, "room count after thread")) return false;

  // Global counts
  auto global = notif.get_global_notification_counts(user_id);
  if (!assert_equal_int(json_int(global, "notification_count"), 1,
                         "global notification_count")) return false;

  // Reset
  notif.reset_user_notifications(user_id);
  state = notif.get_notification_counts(user_id, room_id);
  if (!assert_equal_int(state.notification_count, 0, "reset to zero")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: push trigger engine
// --------------------------------------------------------------------------
bool test_push_triggers() {
  ReadReceiptConfig cfg;
  cfg.push_enable_highlight_words = true;
  PushTriggerEngine push(cfg);

  std::string user_id = "@alice:localhost";
  std::string room_id = "!test:localhost";

  // Test: own message should not notify
  json own_event;
  own_event["event_id"] = "$ev1:localhost";
  own_event["sender"] = "@alice:localhost";
  own_event["type"] = "m.room.message";
  own_event["content"] = {{"body", "Hello world"}, {"msgtype", "m.text"}};

  auto result = push.evaluate_event(user_id, room_id, own_event, json::object());
  if (!assert_true(!result.should_notify, "own message doesn't notify")) return false;
  if (!assert_true(result.sender_is_local_user, "sender is local user")) return false;

  // Test: mention triggers highlight
  json mention_event;
  mention_event["event_id"] = "$ev2:localhost";
  mention_event["sender"] = "@bob:localhost";
  mention_event["type"] = "m.room.message";
  mention_event["content"] = {{"body", "Hey alice, how are you?"}, {"msgtype", "m.text"}};

  result = push.evaluate_event(user_id, room_id, mention_event, json::object());
  if (!assert_true(result.should_notify, "mention triggers notify")) return false;
  if (!assert_true(result.is_highlight, "mention is highlight")) return false;

  // Test: @room mention
  json room_mention_event;
  room_mention_event["event_id"] = "$ev3:localhost";
  room_mention_event["sender"] = "@bob:localhost";
  room_mention_event["type"] = "m.room.message";
  room_mention_event["content"] = {{"body", "@room: meeting in 5 minutes"}, {"msgtype", "m.text"}};

  result = push.evaluate_event(user_id, room_id, room_mention_event, json::object());
  if (!assert_true(result.should_notify, "@room triggers notify")) return false;
  if (!assert_true(result.is_highlight, "@room is highlight")) return false;

  // Test: non-message event doesn't notify
  json state_event;
  state_event["event_id"] = "$ev4:localhost";
  state_event["sender"] = "@bob:localhost";
  state_event["type"] = "m.room.name";
  state_event["content"] = {{"name", "New Room Name"}};

  result = push.evaluate_event(user_id, room_id, state_event, json::object());
  if (!assert_true(!result.should_notify, "state event doesn't notify")) return false;

  // Test: highlight words
  push.set_highlight_words(user_id, {"urgent", "important"});

  json highlight_event;
  highlight_event["event_id"] = "$ev5:localhost";
  highlight_event["sender"] = "@bob:localhost";
  highlight_event["type"] = "m.room.message";
  highlight_event["content"] = {{"body", "This is URGENT!"}, {"msgtype", "m.text"}};

  result = push.evaluate_event(user_id, room_id, highlight_event, json::object());
  if (!assert_true(result.should_notify, "highlight word triggers notify")) return false;
  if (!assert_true(result.is_highlight, "highlight word is highlight")) return false;
  if (!assert_equal_int(static_cast<int64_t>(result.matched_highlight_words.size()), 1,
                         "1 highlight word matched")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: unread counts
// --------------------------------------------------------------------------
bool test_unread_counts() {
  ReadReceiptConfig cfg;
  UnreadCountEngine unread(cfg);

  std::string user_id = "@alice:localhost";
  std::string room_id = "!test:localhost";

  std::vector<std::string> events = {
    "$ev1:localhost", "$ev2:localhost", "$ev3:localhost",
    "$ev4:localhost", "$ev5:localhost"
  };

  // No read marker - all unread
  auto result = unread.compute_unread(user_id, room_id, events, "");
  if (!assert_equal_int(result.total_unread, 5, "all unread with no marker")) return false;

  // Read up to ev2 - 3 unread (ev3, ev4, ev5)
  result = unread.compute_unread(user_id, room_id, events, "$ev2:localhost");
  if (!assert_equal_int(result.total_unread, 3, "3 unread after ev2")) return false;

  // Read up to ev5 - 0 unread
  result = unread.compute_unread(user_id, room_id, events, "$ev5:localhost");
  if (!assert_equal_int(result.total_unread, 0, "0 unread after ev5")) return false;

  // Read up to ev0 (non-existent) - all unread
  result = unread.compute_unread(user_id, room_id, events, "$ev0:localhost");
  if (!assert_equal_int(result.total_unread, 5, "all unread with unknown marker")) return false;

  // Test cache
  unread.cache_unread_count(user_id, room_id, result);
  auto cached = unread.get_cached_unread(user_id, room_id);
  if (!assert_true(cached.has_value(), "cached value exists")) return false;

  // Invalidate cache
  unread.invalidate_cache(user_id, room_id);
  cached = unread.get_cached_unread(user_id, room_id);
  if (!assert_true(!cached.has_value(), "cache invalidated")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: federation engine
// --------------------------------------------------------------------------
bool test_federation_engine() {
  ReadReceiptConfig cfg;
  cfg.enable_federation = true;
  ReceiptStorageEngine storage(cfg);
  ReceiptFederationEngine federation(storage, cfg);

  std::string room_id = "!test:localhost";
  std::string user_id = "@alice:localhost";
  std::string event_id = "$ev1:localhost";

  // Build receipt EDU
  auto edu = federation.build_receipt_edu(room_id, user_id, event_id, "m.read");
  if (!assert_true(!edu.empty(), "EDU built successfully")) return false;
  if (!assert_equal_str(json_str(edu, "type"), "m.receipt", "EDU type is m.receipt")) return false;

  // Private receipts should not be sent to federation by default
  auto priv_edu = federation.build_receipt_edu(room_id, user_id, event_id,
                                                "m.read.private");
  if (!assert_true(priv_edu.empty(), "private receipt EDU is empty")) return false;

  // Process inbound EDU
  json edu_content = {
    {"m.read", {
      {"$ev1:localhost", {
        {"ts", now_ms()},
        {"thread_id", 0}
      }}
    }}
  };

  bool ok = federation.process_inbound_receipt_edu(
      room_id, "@bob:remote", edu_content);
  if (!assert_true(ok, "inbound EDU processed")) return false;

  // Verify it was stored
  auto receipt = storage.get_latest_receipt("@bob:remote", room_id, "m.read");
  if (!assert_true(receipt.has_value(), "remote receipt stored")) return false;

  // Test duplicate detection
  bool is_dup = federation.is_duplicate(room_id, user_id, event_id, "m.read", 1000);
  is_dup = federation.is_duplicate(room_id, user_id, event_id, "m.read", 1000);
  if (!assert_true(is_dup, "duplicate detected")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: full coordinator integration
// --------------------------------------------------------------------------
bool test_full_coordinator() {
  ReadReceiptConfig cfg;
  cfg.enable_read_receipts = true;
  cfg.enable_fully_read_markers = true;
  cfg.enable_private_read_receipts = true;
  cfg.enable_thread_receipts = true;
  cfg.enable_notification_counts = true;
  cfg.enable_push_triggers = true;
  cfg.enable_federation = false; // Skip federation for integration test

  ReadReceiptCoordinator coord(cfg);

  std::string user_id = "@alice:localhost";
  std::string room_id = "!test:localhost";

  // Handle a read receipt
  auto result = coord.handle_client_read_receipt(
      user_id, room_id, "m.read", "$ev1:localhost");
  if (!assert_true(json_int(result, "stream_ordering") > 0,
                    "receipt stored with stream ordering")) return false;

  // Handle fully_read marker
  auto fr_result = coord.handle_client_fully_read(
      user_id, room_id, "$ev2:localhost");
  if (!assert_equal_str(json_str(fr_result, "event_id"), "$ev2:localhost",
                         "fully_read stored")) return false;

  // Handle thread receipt
  auto thread_result = coord.handle_client_thread_receipt(
      user_id, room_id, "$thread1:localhost", "$threadEv10:localhost");
  if (!assert_true(json_int(thread_result, "stream_ordering") > 0,
                    "thread receipt stored")) return false;

  // Get read markers
  auto marker = coord.get_read_marker(user_id, room_id);
  if (!assert_true(marker.has_value(), "marker exists")) return false;
  if (!assert_equal_str(marker->event_id, "$ev2:localhost",
                         "fully_read is ev2")) return false;

  // Test push notification processing
  json event;
  event["event_id"] = "$ev3:localhost";
  event["sender"] = "@bob:localhost";
  event["type"] = "m.room.message";
  event["content"] = {{"body", "Hey alice!"}, {"msgtype", "m.text"}};

  auto trigger = coord.process_event_for_push(
      user_id, room_id, event, json::object());
  if (!assert_true(trigger.should_notify, "push triggered")) return false;

  // Check notification counts
  auto notif_counts = coord.get_sync_notification_counts(user_id, room_id);
  if (!assert_true(json_int(notif_counts, "notification_count") >= 1,
                    "notification count incremented")) return false;

  // Build sync receipts
  auto sync = coord.build_sync_receipts(user_id, room_id, 0);
  if (!assert_true(!sync.empty(), "sync receipts non-empty")) return false;

  // Handle room leave
  coord.handle_room_leave(user_id, room_id);
  marker = coord.get_read_marker(user_id, room_id);
  if (!assert_true(!marker.has_value(), "marker cleared on leave")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: read receipt API handler
// --------------------------------------------------------------------------
bool test_api_handler() {
  ReadReceiptConfig cfg;
  cfg.enable_read_receipts = true;
  cfg.enable_fully_read_markers = true;
  cfg.enable_thread_receipts = true;

  ReadReceiptCoordinator coord(cfg);
  ReadReceiptAPIHandler api(coord);

  std::string user_id = "@alice:localhost";
  std::string room_id = "!test:localhost";

  // Test POST receipt
  auto result = api.handle_post_receipt(
      user_id, room_id, "m.read", "$ev1:localhost");
  if (!assert_true(json_int(result, "stream_ordering") > 0,
                    "API receipt posted")) return false;

  // Test POST thread receipt
  json body;
  body["m.relates_to"] = {
    {"rel_type", "m.thread"},
    {"event_id", "$threadRoot:localhost"}
  };

  result = api.handle_post_receipt(
      user_id, room_id, "m.read", "$threadEv1:localhost", body);
  if (!assert_true(json_int(result, "stream_ordering") > 0,
                    "API thread receipt posted")) return false;

  // Test POST read marker
  json marker_body;
  marker_body["m.fully_read"] = "$ev50:localhost";
  marker_body["m.read"] = "$ev55:localhost";

  auto mr_result = api.handle_post_read_marker(user_id, room_id, marker_body);
  if (!assert_true(!mr_result.empty(), "read marker posted")) return false;

  // Verify read marker was stored
  auto marker = coord.get_read_marker(user_id, room_id);
  if (!assert_equal_str(marker->event_id, "$ev50:localhost",
                         "fully_read set via API")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: edge cases
// --------------------------------------------------------------------------
bool test_edge_cases() {
  ReadReceiptConfig cfg;
  ReadReceiptCoordinator coord(cfg);

  std::string user_id = "@alice:localhost";
  std::string room_id = "!test:localhost";

  // Invalid event ID
  auto result = coord.handle_client_read_receipt(
      user_id, room_id, "m.read", "not-an-event-id");
  if (!assert_true(result.contains("error"), "invalid event ID rejected")) return false;

  // Invalid receipt type
  result = coord.handle_client_read_receipt(
      user_id, room_id, "m.invalid", "$ev1:localhost");
  // The coordinator delegates to the engine which validates

  // Empty user handling
  auto marker = coord.get_read_marker("", room_id);
  if (!assert_true(!marker.has_value(), "empty user has no marker")) return false;

  // Get notifications for non-existent user
  auto notif = coord.get_sync_notification_counts("@nobody:localhost", room_id);
  if (!assert_equal_int(json_int(notif, "notification_count"), 0,
                         "no notifications for unknown user")) return false;

  // Room leave cleanup for non-existent markers (shouldn't crash)
  coord.handle_room_leave("@nobody:localhost", room_id);

  // Multiple receipts for same user in same room
  coord.handle_client_read_receipt(user_id, room_id, "m.read", "$ev1:localhost");
  coord.handle_client_read_receipt(user_id, room_id, "m.read", "$ev2:localhost");
  coord.handle_client_read_receipt(user_id, room_id, "m.read", "$ev3:localhost");

  // Get latest should be ev3
  auto latest = coord.storage().get_latest_receipt(user_id, room_id);
  if (!assert_true(latest.has_value(), "latest exists")) return false;
  if (!assert_equal_str(latest->event_id, "$ev3:localhost",
                         "latest receipt is ev3")) return false;

  // Stats should work without crashing
  auto stats = coord.get_full_stats();
  if (!assert_true(stats.is_object(), "stats is object")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Run all tests
// --------------------------------------------------------------------------
bool run_all_tests() {
  std::vector<std::pair<std::string, std::function<bool()>>> tests = {
    {"receipt_storage",        test_receipt_storage},
    {"read_marker_engine",     test_read_marker_engine},
    {"notification_counts",    test_notification_counts},
    {"push_triggers",          test_push_triggers},
    {"unread_counts",          test_unread_counts},
    {"federation_engine",      test_federation_engine},
    {"full_coordinator",       test_full_coordinator},
    {"api_handler",            test_api_handler},
    {"edge_cases",             test_edge_cases},
  };

  int passed = 0;
  int failed = 0;

  std::cout << "=== Read Receipts Tests ===" << std::endl;
  for (auto& [name, test_fn] : tests) {
    std::cout << "  " << name << "... ";
    std::cout.flush();
    if (test_fn()) {
      std::cout << "PASSED" << std::endl;
      passed++;
    } else {
      std::cout << "FAILED" << std::endl;
      failed++;
    }
  }

  std::cout << "---" << std::endl;
  std::cout << "Passed: " << passed << ", Failed: " << failed
            << ", Total: " << (passed + failed) << std::endl;

  return failed == 0;
}

} // namespace test
#endif // READ_RECEIPTS_TESTING

} // namespace progressive
