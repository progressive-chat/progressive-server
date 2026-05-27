// ============================================================================
// to_device.cpp — Matrix To-Device Message Store and Delivery
//
// Implements:
//   - To-device send: PUT /sendToDevice/{eventType}/{txnId} with messages map
//     {user_id: {device_id: content}}, idempotency by txn_id
//   - To-device delivery: store messages in device_inbox table per
//     (user_id, device_id), track per-device stream positions
//   - Wildcard device support: * device_id means deliver to ALL user devices
//   - To-device sync: return new to-device messages in /sync response
//     since last sync token
//   - Message deduplication: don't deliver duplicate message_ids
//   - To-device federation: forward to-device messages to remote users
//     via federation /send endpoint
//   - Deferred device handling: queue messages for devices that don't exist yet
//   - To-device message limits: max messages per request, max message size,
//     rate limiting
//   - Cleanup: delete old delivered messages, expire undelivered messages
//     after timeout
//
// Equivalent to:
//   synapse/handlers/device_message.py
//   synapse/storage/databases/main/devices.py (device inbox section)
//   synapse/handlers/e2e_keys.py (to_device portions)
//   synapse/federation/sender/per_destination_queue.py (to_device EDU queue)
//   synapse/replication/tcp/streams/_to_device.py
//
// Target: 2000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
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
#include <vector>

#include <nlohmann/json.hpp>

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations
// ============================================================================
class ToDeviceSender;
class ToDeviceDeliveryManager;
class ToDeviceWildcardResolver;
class ToDeviceSyncProvider;
class ToDeviceDeduplicator;
class ToDeviceFederationForwarder;
class DeferredDeviceQueue;
class ToDeviceLimitEnforcer;
class ToDeviceCleanupWorker;
class ToDeviceStreamTracker;
class ToDeviceRateLimiter;
class ToDeviceTransactionStore;
class ToDeviceCoordinator;

// ============================================================================
// Utility: time, string, crypto, and helpers
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

std::string generate_token(int length = 16) {
  static thread_local std::mt19937_64 rng(
      std::random_device{}() ^
      static_cast<uint64_t>(
          chr::system_clock::now().time_since_epoch().count()));
  static const char charset[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  std::string result;
  result.reserve(length);
  std::uniform_int_distribution<int> dist(0, sizeof(charset) - 2);
  for (int i = 0; i < length; ++i) {
    result += charset[dist(rng)];
  }
  return result;
}

std::string generate_event_id() {
  return "$" + generate_token(24);
}

std::string sha256(const std::string& input) {
  // Simple placeholder hash; real implementation would use OpenSSL/BoringSSL
  std::hash<std::string> hasher;
  std::stringstream ss;
  ss << std::hex << std::setfill('0') << std::setw(16) << hasher(input);
  return ss.str();
}

std::string make_message_id(const std::string& sender,
                             const std::string& device_id,
                             const std::string& msg_type,
                             int64_t ts) {
  std::string raw = sender + "|" + device_id + "|" + msg_type + "|" +
                    std::to_string(ts);
  return "m" + sha256(raw).substr(0, 16);
}

// Validate user ID format: @localpart:domain
bool is_valid_user_id(const std::string& uid) {
  if (uid.empty() || uid[0] != '@') return false;
  auto colon = uid.find(':');
  if (colon == std::string::npos || colon == uid.size() - 1) return false;
  return true;
}

// Validate device ID: non-empty, printable, max 255 chars
bool is_valid_device_id(const std::string& did) {
  if (did.empty() || did.size() > 255) return false;
  for (char c : did) {
    if (c < 0x20 || c > 0x7E) return false;
  }
  return true;
}

// Validate event type: starts with 'm.' or is a namespaced type
bool is_valid_event_type(const std::string& type) {
  if (type.empty()) return false;
  if (type.size() > 255) return false;
  // Must contain a dot
  if (type.find('.') == std::string::npos) return false;
  // Only allow alphanumeric, dot, underscore, hyphen
  for (char c : type) {
    if (!std::isalnum(static_cast<unsigned char>(c)) &&
        c != '.' && c != '_' && c != '-') {
      return false;
    }
  }
  return true;
}

// Parse server_name from user_id: @alice:matrix.org -> matrix.org
std::string server_name_from_user_id(const std::string& uid) {
  auto colon = uid.find(':');
  if (colon == std::string::npos) return "";
  return uid.substr(colon + 1);
}

// Check if user belongs to this server
bool is_local_user(const std::string& uid, const std::string& server_name) {
  return server_name_from_user_id(uid) == server_name;
}

// Truncate a string to max_len for logging/display
std::string truncate(const std::string& s, size_t max_len = 80) {
  if (s.size() <= max_len) return s;
  return s.substr(0, max_len - 3) + "...";
}

}  // anonymous namespace

// ============================================================================
// ToDeviceConfig — Global to-device configuration
// ============================================================================
struct ToDeviceConfig {
  // Limits
  int64_t max_messages_per_request = 100;
  int64_t max_message_content_size = 65536;       // 64 KiB
  int64_t max_messages_per_user_inbox = 500;
  int64_t max_concurrent_sends = 10;

  // Rate limiting
  double send_rate_burst = 10.0;
  double send_rate_per_second = 5.0;

  // Deduplication
  int64_t dedup_cache_size = 10000;
  int64_t dedup_cache_ttl_ms = 3600000;            // 1 hour

  // Federation
  int64_t federation_batch_size = 100;
  int64_t federation_retry_delay_ms = 30000;       // 30 seconds
  int     federation_max_retries = 3;

  // Deferred devices
  int64_t deferred_queue_max_age_ms = 86400000;    // 24 hours
  int64_t deferred_queue_check_interval_ms = 300000; // 5 minutes

  // Cleanup
  int64_t cleanup_interval_ms = 3600000;           // 1 hour
  int64_t delivered_message_keep_ms = 300000;      // 5 minutes
  int64_t undelivered_message_timeout_ms = 604800000; // 7 days
  int64_t stream_id_max_age_ms = 2592000000;       // 30 days

  // Stream tracking
  int64_t max_stream_id_gap = 1000000;

  // TLS / signing for federation
  std::string server_name = "localhost";
  std::string signing_key_path;
  std::string tls_cert_path;

  json to_json() const {
    return {
      {"max_messages_per_request", max_messages_per_request},
      {"max_message_content_size", max_message_content_size},
      {"max_messages_per_user_inbox", max_messages_per_user_inbox},
      {"dedup_cache_size", dedup_cache_size},
      {"dedup_cache_ttl_ms", dedup_cache_ttl_ms},
      {"federation_batch_size", federation_batch_size},
      {"federation_retry_delay_ms", federation_retry_delay_ms},
      {"federation_max_retries", federation_max_retries},
      {"deferred_queue_max_age_ms", deferred_queue_max_age_ms},
      {"cleanup_interval_ms", cleanup_interval_ms},
      {"delivered_message_keep_ms", delivered_message_keep_ms},
      {"undelivered_message_timeout_ms", undelivered_message_timeout_ms}
    };
  }

  static ToDeviceConfig from_json(const json& j) {
    ToDeviceConfig cfg;
    if (j.contains("max_messages_per_request"))
      cfg.max_messages_per_request = j["max_messages_per_request"];
    if (j.contains("max_message_content_size"))
      cfg.max_message_content_size = j["max_message_content_size"];
    if (j.contains("max_messages_per_user_inbox"))
      cfg.max_messages_per_user_inbox = j["max_messages_per_user_inbox"];
    if (j.contains("dedup_cache_size"))
      cfg.dedup_cache_size = j["dedup_cache_size"];
    if (j.contains("dedup_cache_ttl_ms"))
      cfg.dedup_cache_ttl_ms = j["dedup_cache_ttl_ms"];
    if (j.contains("federation_batch_size"))
      cfg.federation_batch_size = j["federation_batch_size"];
    if (j.contains("federation_retry_delay_ms"))
      cfg.federation_retry_delay_ms = j["federation_retry_delay_ms"];
    if (j.contains("federation_max_retries"))
      cfg.federation_max_retries = j["federation_max_retries"];
    if (j.contains("deferred_queue_max_age_ms"))
      cfg.deferred_queue_max_age_ms = j["deferred_queue_max_age_ms"];
    if (j.contains("cleanup_interval_ms"))
      cfg.cleanup_interval_ms = j["cleanup_interval_ms"];
    if (j.contains("delivered_message_keep_ms"))
      cfg.delivered_message_keep_ms = j["delivered_message_keep_ms"];
    if (j.contains("undelivered_message_timeout_ms"))
      cfg.undelivered_message_timeout_ms = j["undelivered_message_timeout_ms"];
    return cfg;
  }
};

// ============================================================================
// ToDeviceMessage — A single to-device message
// ============================================================================
struct ToDeviceMessage {
  std::string message_id;
  std::string sender;
  std::string sender_device;
  std::string target_user;
  std::string target_device;     // "*" for wildcard
  std::string message_type;
  json        content;
  int64_t     stream_id = 0;
  int64_t     received_ts = 0;
  int64_t     delivered_ts = 0;
  bool        delivered = false;
  bool        wildcard_expanded = false;
  int         retry_count = 0;

  bool is_wildcard() const { return target_device == "*"; }
  bool is_expired(int64_t now, int64_t timeout_ms) const {
    return now - received_ts > timeout_ms;
  }
  bool is_delivered() const { return delivered; }

  json to_sync_format() const {
    json ev;
    ev["sender"] = sender;
    ev["type"] = message_type;
    ev["content"] = content;
    return ev;
  }

  json to_edu_format() const {
    json edu;
    edu["sender"] = sender;
    edu["type"] = message_type;
    edu["message_id"] = message_id;
    edu["content"] = content;
    edu["target_user"] = target_user;
    edu["target_device"] = target_device;
    return edu;
  }

  json to_json() const {
    return {
      {"message_id", message_id},
      {"sender", sender},
      {"sender_device", sender_device},
      {"target_user", target_user},
      {"target_device", target_device},
      {"message_type", message_type},
      {"content", content},
      {"stream_id", stream_id},
      {"received_ts", received_ts},
      {"delivered_ts", delivered_ts},
      {"delivered", delivered},
      {"wildcard_expanded", wildcard_expanded}
    };
  }

  static ToDeviceMessage from_json(const json& j) {
    ToDeviceMessage m;
    m.message_id = j.value("message_id", "");
    m.sender = j.value("sender", "");
    m.sender_device = j.value("sender_device", "");
    m.target_user = j.value("target_user", "");
    m.target_device = j.value("target_device", "");
    m.message_type = j.value("message_type", "");
    m.content = j.value("content", json::object());
    m.stream_id = j.value("stream_id", 0);
    m.received_ts = j.value("received_ts", 0);
    m.delivered_ts = j.value("delivered_ts", 0);
    m.delivered = j.value("delivered", false);
    m.wildcard_expanded = j.value("wildcard_expanded", false);
    return m;
  }
};

// ============================================================================
// ToDeviceSendResult — Result of a send operation
// ============================================================================
struct ToDeviceSendResult {
  bool        success = false;
  std::string txn_id;
  int         messages_sent = 0;
  int         devices_delivered = 0;
  int         users_queued_federation = 0;
  int         wildcard_expansions = 0;
  std::vector<std::string> errors;
  std::vector<std::string> deferred_devices;
  int64_t     timestamp_ms = 0;

  json to_json() const {
    return {
      {"success", success},
      {"txn_id", txn_id},
      {"messages_sent", messages_sent},
      {"devices_delivered", devices_delivered},
      {"users_queued_federation", users_queued_federation},
      {"wildcard_expansions", wildcard_expansions},
      {"errors", errors},
      {"deferred_devices", deferred_devices},
      {"timestamp_ms", timestamp_ms}
    };
  }
};

// ============================================================================
// ToDeviceSyncResult — To-device portion of a sync response
// ============================================================================
struct ToDeviceSyncResult {
  std::vector<json> events;
  int64_t           next_batch_token = 0;
  bool              has_more = false;
  int               total_pending = 0;
};

// ============================================================================
// ToDeviceStats — Statistics for monitoring
// ============================================================================
struct ToDeviceStats {
  std::atomic<int64_t> total_sent{0};
  std::atomic<int64_t> total_delivered{0};
  std::atomic<int64_t> total_federated{0};
  std::atomic<int64_t> total_wildcard_expanded{0};
  std::atomic<int64_t> total_deduplicated{0};
  std::atomic<int64_t> total_deferred{0};
  std::atomic<int64_t> total_cleanup_deleted{0};
  std::atomic<int64_t> total_rejected_limits{0};
  std::atomic<int64_t> current_inbox_count{0};
  std::atomic<int64_t> current_deferred_count{0};
  int64_t              last_cleanup_ts = 0;

  json snapshot() const {
    return {
      {"total_sent", total_sent.load()},
      {"total_delivered", total_delivered.load()},
      {"total_federated", total_federated.load()},
      {"total_wildcard_expanded", total_wildcard_expanded.load()},
      {"total_deduplicated", total_deduplicated.load()},
      {"total_deferred", total_deferred.load()},
      {"total_cleanup_deleted", total_cleanup_deleted.load()},
      {"total_rejected_limits", total_rejected_limits.load()},
      {"current_inbox_count", current_inbox_count.load()},
      {"current_deferred_count", current_deferred_count.load()},
      {"last_cleanup_ts", last_cleanup_ts}
    };
  }
};

// ============================================================================
// SentTransaction — Record of a processed sendToDevice transaction
// ============================================================================
struct SentTransaction {
  std::string txn_id;
  std::string user_id;
  std::string event_type;
  int64_t     sent_ts = 0;
  int         delivered_count = 0;
  json        request_hash;
};

// ============================================================================
// DeviceInfo — Lightweight device info for inbox delivery
// ============================================================================
struct DeviceTarget {
  std::string user_id;
  std::string device_id;
  int64_t     last_seen_ts = 0;
  bool        exists = false;
};

// ============================================================================
// FederationDestination — Per-remote-server to-device queue
// ============================================================================
struct FederationToDeviceBatch {
  std::string     destination;
  std::string     origin;
  std::vector<ToDeviceMessage> messages;
  int64_t         created_ts = 0;
  int64_t         last_attempt_ts = 0;
  int             retry_count = 0;
  int64_t         next_attempt_ts = 0;
  bool            sent = false;
};

// ============================================================================
// StreamToken — Per-device stream position
// ============================================================================
struct DeviceStreamPosition {
  std::string user_id;
  std::string device_id;
  int64_t     stream_id = 0;
  int64_t     updated_ts = 0;
};

// ============================================================================
// ToDeviceTransactionStore — Idempotency store for sendToDevice transactions
// ============================================================================
class ToDeviceTransactionStore {
public:
  ToDeviceTransactionStore() = default;

  bool is_duplicate(const std::string& txn_id) {
    std::shared_lock lock(mutex_);
    auto it = transactions_.find(txn_id);
    if (it == transactions_.end()) return false;
    return true;
  }

  bool is_duplicate_for_user(const std::string& user_id,
                              const std::string& txn_id) {
    std::string key = user_id + ":" + txn_id;
    std::shared_lock lock(mutex_);
    return transactions_.count(key) > 0;
  }

  void record_transaction(const std::string& user_id,
                           const std::string& txn_id,
                           const std::string& event_type,
                           int delivered_count,
                           const json& request_hash) {
    std::unique_lock lock(mutex_);
    std::string key = user_id + ":" + txn_id;
    SentTransaction txn;
    txn.txn_id = txn_id;
    txn.user_id = user_id;
    txn.event_type = event_type;
    txn.sent_ts = now_ms();
    txn.delivered_count = delivered_count;
    txn.request_hash = request_hash;
    transactions_[key] = txn;

    // Also index by txn_id alone
    transactions_[txn_id] = txn;
  }

  std::optional<SentTransaction> get_transaction(
      const std::string& user_id, const std::string& txn_id) {
    std::shared_lock lock(mutex_);
    std::string key = user_id + ":" + txn_id;
    auto it = transactions_.find(key);
    if (it == transactions_.end()) return std::nullopt;
    return it->second;
  }

  void evict_old_transactions(int64_t older_than_ms) {
    std::unique_lock lock(mutex_);
    int64_t cutoff = now_ms() - older_than_ms;
    auto it = transactions_.begin();
    while (it != transactions_.end()) {
      if (it->second.sent_ts < cutoff) {
        it = transactions_.erase(it);
      } else {
        ++it;
      }
    }
  }

  size_t size() const {
    std::shared_lock lock(mutex_);
    return transactions_.size();
  }

  void clear() {
    std::unique_lock lock(mutex_);
    transactions_.clear();
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, SentTransaction> transactions_;
};

// ============================================================================
// ToDeviceDeduplicator — Prevents duplicate message delivery
// ============================================================================
class ToDeviceDeduplicator {
public:
  explicit ToDeviceDeduplicator(int64_t cache_size = 10000,
                                 int64_t cache_ttl_ms = 3600000)
      : max_cache_size_(cache_size), cache_ttl_ms_(cache_ttl_ms) {}

  bool is_duplicate(const std::string& message_id) {
    int64_t now = now_ms();
    std::unique_lock lock(mutex_);

    // Check cache
    auto it = dedup_cache_.find(message_id);
    if (it != dedup_cache_.end()) {
      if (now - it->second < cache_ttl_ms_) {
        stats_.total_deduplicated++;
        return true;  // Still valid, duplicate
      }
      // Expired, remove and treat as new
      dedup_cache_.erase(it);
    }
    return false;
  }

  void mark_seen(const std::string& message_id) {
    int64_t now = now_ms();
    std::unique_lock lock(mutex_);

    // Evict if cache is full
    if (dedup_cache_.size() >= static_cast<size_t>(max_cache_size_)) {
      evict_expired(now);
      // If still full, evict oldest
      if (dedup_cache_.size() >= static_cast<size_t>(max_cache_size_)) {
        evict_oldest_half();
      }
    }

    dedup_cache_[message_id] = now;
  }

  void mark_batch_seen(const std::vector<std::string>& message_ids) {
    for (const auto& mid : message_ids) {
      mark_seen(mid);
    }
  }

  bool check_and_mark(const std::string& message_id) {
    if (is_duplicate(message_id)) return true;
    mark_seen(message_id);
    return false;
  }

  size_t cache_size() const {
    std::unique_lock lock(mutex_);
    return dedup_cache_.size();
  }

  void evict_expired() {
    std::unique_lock lock(mutex_);
    evict_expired(now_ms());
  }

  void clear() {
    std::unique_lock lock(mutex_);
    dedup_cache_.clear();
  }

  ToDeviceStats& stats() { return stats_; }

private:
  void evict_expired(int64_t now) {
    auto it = dedup_cache_.begin();
    while (it != dedup_cache_.end()) {
      if (now - it->second >= cache_ttl_ms_) {
        it = dedup_cache_.erase(it);
      } else {
        ++it;
      }
    }
  }

  void evict_oldest_half() {
    // Collect all entries, sort by timestamp, remove oldest half
    std::vector<std::pair<std::string, int64_t>> entries(
        dedup_cache_.begin(), dedup_cache_.end());
    std::sort(entries.begin(), entries.end(),
              [](const auto& a, const auto& b) { return a.second < b.second; });
    size_t to_remove = entries.size() / 2;
    for (size_t i = 0; i < to_remove; ++i) {
      dedup_cache_.erase(entries[i].first);
    }
  }

  mutable std::mutex mutex_;
  std::unordered_map<std::string, int64_t> dedup_cache_;
  int64_t max_cache_size_;
  int64_t cache_ttl_ms_;
  ToDeviceStats stats_;
};

// ============================================================================
// ToDeviceStreamTracker — Per-device stream position tracking
// ============================================================================
class ToDeviceStreamTracker {
public:
  ToDeviceStreamTracker() {
    // Initialize global stream ID
    global_stream_id_.store(1);
  }

  int64_t next_stream_id() {
    return global_stream_id_.fetch_add(1);
  }

  int64_t current_stream_id() const {
    return global_stream_id_.load();
  }

  void update_device_position(const std::string& user_id,
                               const std::string& device_id,
                               int64_t stream_id) {
    std::string key = user_id + ":" + device_id;
    std::unique_lock lock(mutex_);
    auto it = positions_.find(key);
    if (it == positions_.end() || it->second.stream_id < stream_id) {
      DeviceStreamPosition pos;
      pos.user_id = user_id;
      pos.device_id = device_id;
      pos.stream_id = stream_id;
      pos.updated_ts = now_ms();
      positions_[key] = pos;
    }
  }

  std::optional<int64_t> get_device_position(const std::string& user_id,
                                               const std::string& device_id) {
    std::string key = user_id + ":" + device_id;
    std::shared_lock lock(mutex_);
    auto it = positions_.find(key);
    if (it == positions_.end()) return std::nullopt;
    return it->second.stream_id;
  }

  void remove_device(const std::string& user_id, const std::string& device_id) {
    std::string key = user_id + ":" + device_id;
    std::unique_lock lock(mutex_);
    positions_.erase(key);
  }

  void remove_user(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    std::string prefix = user_id + ":";
    auto it = positions_.begin();
    while (it != positions_.end()) {
      if (it->first.compare(0, prefix.size(), prefix) == 0) {
        it = positions_.erase(it);
      } else {
        ++it;
      }
    }
  }

  std::vector<DeviceStreamPosition> get_user_positions(
      const std::string& user_id) {
    std::vector<DeviceStreamPosition> result;
    std::string prefix = user_id + ":";
    std::shared_lock lock(mutex_);
    for (const auto& [key, pos] : positions_) {
      if (key.compare(0, prefix.size(), prefix) == 0) {
        result.push_back(pos);
      }
    }
    return result;
  }

  int64_t get_max_position_for_user(const std::string& user_id) {
    int64_t max_pos = 0;
    std::string prefix = user_id + ":";
    std::shared_lock lock(mutex_);
    for (const auto& [key, pos] : positions_) {
      if (key.compare(0, prefix.size(), prefix) == 0) {
        if (pos.stream_id > max_pos) max_pos = pos.stream_id;
      }
    }
    return max_pos;
  }

  void evict_stale_positions(int64_t max_age_ms) {
    int64_t cutoff = now_ms() - max_age_ms;
    std::unique_lock lock(mutex_);
    auto it = positions_.begin();
    while (it != positions_.end()) {
      if (it->second.updated_ts < cutoff) {
        it = positions_.erase(it);
      } else {
        ++it;
      }
    }
  }

  size_t position_count() const {
    std::shared_lock lock(mutex_);
    return positions_.size();
  }

  // Generate a sync token encoding stream positions
  std::string make_sync_token(const std::string& user_id) {
    int64_t pos = get_max_position_for_user(user_id);
    return "s" + std::to_string(pos) + "_" + generate_token(8);
  }

  // Parse stream position from sync token
  int64_t parse_sync_token(const std::string& token) {
    if (token.empty() || token[0] != 's') return 0;
    size_t underscore = token.find('_');
    if (underscore == std::string::npos) return 0;
    try {
      return std::stoll(token.substr(1, underscore - 1));
    } catch (...) {
      return 0;
    }
  }

private:
  std::atomic<int64_t> global_stream_id_{1};
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, DeviceStreamPosition> positions_;
};

// ============================================================================
// ToDeviceRateLimiter — Rate limits for to-device sending
// ============================================================================
class ToDeviceRateLimiter {
public:
  ToDeviceRateLimiter(double burst = 10.0, double rate_per_sec = 5.0)
      : burst_size_(burst), rate_per_second_(rate_per_sec) {
    tokens_.store(burst);
    last_refill_ts_.store(now_ms());
  }

  bool allow_request(double cost = 1.0) {
    refill_tokens();
    double current = tokens_.load();
    while (true) {
      if (current < cost) return false;
      if (tokens_.compare_exchange_weak(current, current - cost)) {
        return true;
      }
    }
  }

  double available_tokens() const {
    const_cast<ToDeviceRateLimiter*>(this)->refill_tokens();
    return tokens_.load();
  }

  void set_rate(double burst, double rate_per_sec) {
    burst_size_ = burst;
    rate_per_second_ = rate_per_sec;
    // Clamp tokens to new burst
    double current = tokens_.load();
    if (current > burst) tokens_.store(burst);
  }

  double burst_size() const { return burst_size_; }
  double rate_per_second() const { return rate_per_second_; }

  json status() const {
    return {
      {"burst_size", burst_size_},
      {"rate_per_second", rate_per_second_},
      {"available_tokens", available_tokens()}
    };
  }

private:
  void refill_tokens() {
    int64_t now = now_ms();
    int64_t last = last_refill_ts_.load();
    if (now <= last) return;

    double elapsed_sec = static_cast<double>(now - last) / 1000.0;
    double refill = elapsed_sec * rate_per_second_;

    double current = tokens_.load();
    double new_tokens = std::min(current + refill, burst_size_);

    if (tokens_.compare_exchange_strong(current, new_tokens)) {
      last_refill_ts_.store(now);
    }
  }

  double burst_size_;
  double rate_per_second_;
  std::atomic<double> tokens_{0.0};
  std::atomic<int64_t> last_refill_ts_{0};
};

// ============================================================================
// ToDeviceWildcardResolver — Resolves * device_id to all user devices
// ============================================================================
class ToDeviceWildcardResolver {
public:
  ToDeviceWildcardResolver() = default;

  // Set the device list for a user (caller provides known devices)
  void set_user_devices(const std::string& user_id,
                         const std::vector<std::string>& device_ids) {
    std::unique_lock lock(mutex_);
    user_devices_[user_id] = device_ids;
  }

  // Add a single device for a user
  void add_user_device(const std::string& user_id,
                        const std::string& device_id) {
    std::unique_lock lock(mutex_);
    auto& devices = user_devices_[user_id];
    if (std::find(devices.begin(), devices.end(), device_id) == devices.end()) {
      devices.push_back(device_id);
    }
  }

  // Remove a device for a user
  void remove_user_device(const std::string& user_id,
                           const std::string& device_id) {
    std::unique_lock lock(mutex_);
    auto& devices = user_devices_[user_id];
    devices.erase(std::remove(devices.begin(), devices.end(), device_id),
                  devices.end());
  }

  // Remove all devices for a user
  void remove_user(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    user_devices_.erase(user_id);
  }

  // Resolve wildcard: if device_id is "*", return all known devices
  // If device_id is specific, return that single device
  std::vector<std::string> resolve(const std::string& user_id,
                                     const std::string& device_id) {
    if (device_id != "*") {
      return {device_id};
    }
    std::shared_lock lock(mutex_);
    auto it = user_devices_.find(user_id);
    if (it == user_devices_.end()) return {};
    return it->second;
  }

  // Check if a user has a specific device
  bool has_device(const std::string& user_id, const std::string& device_id) {
    std::shared_lock lock(mutex_);
    auto it = user_devices_.find(user_id);
    if (it == user_devices_.end()) return false;
    const auto& devices = it->second;
    return std::find(devices.begin(), devices.end(), device_id) != devices.end();
  }

  // Get the count of devices for a user
  size_t device_count(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    auto it = user_devices_.find(user_id);
    if (it == user_devices_.end()) return 0;
    return it->second.size();
  }

  // List all device IDs for a user
  std::vector<std::string> list_devices(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    auto it = user_devices_.find(user_id);
    if (it == user_devices_.end()) return {};
    return it->second;
  }

  json dump_state() const {
    std::shared_lock lock(mutex_);
    json j;
    for (const auto& [uid, devs] : user_devices_) {
      j[uid] = devs;
    }
    return j;
  }

  size_t user_count() const {
    std::shared_lock lock(mutex_);
    return user_devices_.size();
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, std::vector<std::string>> user_devices_;
};

// ============================================================================
// ToDeviceInboxStore — In-memory device inbox for (user, device) pairs
// ============================================================================
class ToDeviceInboxStore {
public:
  ToDeviceInboxStore() = default;

  // Add a message to the device inbox
  // Returns false if the user's inbox is full
  bool add_message(const ToDeviceMessage& msg, int64_t max_per_user = 500) {
    std::string key = msg.target_user + ":" + msg.target_device;
    std::unique_lock lock(mutex_);

    auto& inbox = inboxes_[key];
    if (static_cast<int64_t>(inbox.size()) >= max_per_user) {
      return false;  // Inbox full
    }

    // Check dedup within this device's inbox
    for (const auto& existing : inbox) {
      if (existing.message_id == msg.message_id) {
        return true;  // Already in inbox, silently succeed
      }
    }

    inbox.push_back(msg);
    total_count_.fetch_add(1);
    return true;
  }

  // Add batch of messages for a target
  int add_batch(const std::string& user_id,
                 const std::string& device_id,
                 const std::vector<ToDeviceMessage>& messages,
                 int64_t max_per_user = 500) {
    std::string key = user_id + ":" + device_id;
    std::unique_lock lock(mutex_);

    auto& inbox = inboxes_[key];
    int added = 0;
    for (const auto& msg : messages) {
      if (static_cast<int64_t>(inbox.size()) >= max_per_user) break;

      // Check dedup
      bool dup = false;
      for (const auto& existing : inbox) {
        if (existing.message_id == msg.message_id) { dup = true; break; }
      }
      if (dup) continue;

      inbox.push_back(msg);
      added++;
      total_count_.fetch_add(1);
    }
    return added;
  }

  // Get messages for a device since a given stream position
  std::vector<ToDeviceMessage> get_messages(const std::string& user_id,
                                              const std::string& device_id,
                                              int64_t since_stream_id,
                                              int limit = 100) {
    std::string key = user_id + ":" + device_id;
    std::shared_lock lock(mutex_);

    auto it = inboxes_.find(key);
    if (it == inboxes_.end()) return {};

    std::vector<ToDeviceMessage> result;
    for (const auto& msg : it->second) {
      if (msg.stream_id > since_stream_id) {
        result.push_back(msg);
        if (static_cast<int>(result.size()) >= limit) break;
      }
    }
    return result;
  }

  // Get all messages for a user across all devices
  std::vector<ToDeviceMessage> get_all_for_user(const std::string& user_id,
                                                  int limit = 500) {
    std::vector<ToDeviceMessage> result;
    std::string prefix = user_id + ":";
    std::shared_lock lock(mutex_);

    for (const auto& [key, inbox] : inboxes_) {
      if (key.compare(0, prefix.size(), prefix) == 0) {
        for (const auto& msg : inbox) {
          result.push_back(msg);
          if (static_cast<int>(result.size()) >= limit) break;
        }
        if (static_cast<int>(result.size()) >= limit) break;
      }
    }
    return result;
  }

  // Delete delivered messages up to a given stream ID
  int delete_delivered(const std::string& user_id,
                        const std::string& device_id,
                        int64_t up_to_stream_id) {
    std::string key = user_id + ":" + device_id;
    std::unique_lock lock(mutex_);

    auto it = inboxes_.find(key);
    if (it == inboxes_.end()) return 0;

    int removed = 0;
    auto& inbox = it->second;
    inbox.erase(
        std::remove_if(inbox.begin(), inbox.end(),
                       [&](const ToDeviceMessage& msg) {
                         if (msg.stream_id <= up_to_stream_id && msg.delivered) {
                           removed++;
                           total_count_.fetch_sub(1);
                           return true;
                         }
                         return false;
                       }),
        inbox.end());

    if (inbox.empty()) {
      inboxes_.erase(it);
    }
    return removed;
  }

  // Delete all messages for a device
  int delete_all_for_device(const std::string& user_id,
                             const std::string& device_id) {
    std::string key = user_id + ":" + device_id;
    std::unique_lock lock(mutex_);

    auto it = inboxes_.find(key);
    if (it == inboxes_.end()) return 0;

    int removed = static_cast<int>(it->second.size());
    total_count_.fetch_sub(removed);
    inboxes_.erase(it);
    return removed;
  }

  // Delete all inboxes for a user
  int delete_all_for_user(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    std::string prefix = user_id + ":";
    int removed = 0;

    auto it = inboxes_.begin();
    while (it != inboxes_.end()) {
      if (it->first.compare(0, prefix.size(), prefix) == 0) {
        removed += static_cast<int>(it->second.size());
        total_count_.fetch_sub(it->second.size());
        it = inboxes_.erase(it);
      } else {
        ++it;
      }
    }
    return removed;
  }

  // Mark messages as delivered
  int mark_delivered(const std::string& user_id,
                      const std::string& device_id,
                      const std::vector<std::string>& message_ids) {
    std::string key = user_id + ":" + device_id;
    std::unique_lock lock(mutex_);

    auto it = inboxes_.find(key);
    if (it == inboxes_.end()) return 0;

    int marked = 0;
    int64_t now = now_ms();
    std::unordered_set<std::string> id_set(message_ids.begin(),
                                            message_ids.end());
    for (auto& msg : it->second) {
      if (!msg.delivered && id_set.count(msg.message_id)) {
        msg.delivered = true;
        msg.delivered_ts = now;
        marked++;
      }
    }
    return marked;
  }

  // Count messages for a device
  int64_t count_for_device(const std::string& user_id,
                            const std::string& device_id) {
    std::string key = user_id + ":" + device_id;
    std::shared_lock lock(mutex_);
    auto it = inboxes_.find(key);
    if (it == inboxes_.end()) return 0;
    return static_cast<int64_t>(it->second.size());
  }

  // Count pending (undelivered) messages for a user
  int64_t count_pending_for_user(const std::string& user_id) {
    int64_t count = 0;
    std::string prefix = user_id + ":";
    std::shared_lock lock(mutex_);
    for (const auto& [key, inbox] : inboxes_) {
      if (key.compare(0, prefix.size(), prefix) == 0) {
        for (const auto& msg : inbox) {
          if (!msg.delivered) count++;
        }
      }
    }
    return count;
  }

  // Expire undelivered messages older than timeout
  int expire_undelivered(int64_t timeout_ms) {
    int64_t cutoff = now_ms() - timeout_ms;
    std::unique_lock lock(mutex_);
    int expired = 0;

    auto it = inboxes_.begin();
    while (it != inboxes_.end()) {
      auto& inbox = it->second;
      auto before = inbox.size();
      inbox.erase(
          std::remove_if(inbox.begin(), inbox.end(),
                         [&](const ToDeviceMessage& msg) {
                           if (!msg.delivered &&
                               msg.received_ts < cutoff) {
                             return true;
                           }
                           return false;
                         }),
          inbox.end());
      expired += static_cast<int>(before - inbox.size());
      total_count_.fetch_sub(before - inbox.size());

      if (inbox.empty()) {
        it = inboxes_.erase(it);
      } else {
        ++it;
      }
    }
    return expired;
  }

  int64_t total_count() const { return total_count_.load(); }
  size_t device_count() const {
    std::shared_lock lock(mutex_);
    return inboxes_.size();
  }

  void clear() {
    std::unique_lock lock(mutex_);
    inboxes_.clear();
    total_count_.store(0);
  }

  json stats() const {
    std::shared_lock lock(mutex_);
    return {
      {"total_count", total_count_.load()},
      {"device_count", inboxes_.size()},
      {"timestamp_ms", now_ms()}
    };
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, std::vector<ToDeviceMessage>> inboxes_;
  std::atomic<int64_t> total_count_{0};
};

// ============================================================================
// DeferredDeviceQueue — Messages for devices that don't exist yet
// ============================================================================
class DeferredDeviceQueue {
public:
  DeferredDeviceQueue() = default;

  // Queue a message for a non-existent device
  void enqueue(const ToDeviceMessage& msg) {
    std::string key = msg.target_user + ":" + msg.target_device;
    std::unique_lock lock(mutex_);
    deferred_[key].push_back(msg);
    total_deferred_.fetch_add(1);
  }

  // Poll deferred messages when a device appears
  std::vector<ToDeviceMessage> poll_for_device(const std::string& user_id,
                                                  const std::string& device_id) {
    std::string key = user_id + ":" + device_id;
    std::unique_lock lock(mutex_);
    auto it = deferred_.find(key);
    if (it == deferred_.end()) return {};

    std::vector<ToDeviceMessage> result = std::move(it->second);
    total_deferred_.fetch_sub(result.size());
    deferred_.erase(it);
    return result;
  }

  // Poll wildcard-deferred messages for a user (match any device)
  std::vector<ToDeviceMessage> poll_wildcard_for_user(
      const std::string& user_id) {
    std::string wildcard_key = user_id + ":*";
    std::unique_lock lock(mutex_);
    auto it = deferred_.find(wildcard_key);
    if (it == deferred_.end()) return {};

    std::vector<ToDeviceMessage> result = std::move(it->second);
    total_deferred_.fetch_sub(result.size());
    deferred_.erase(it);

    // Also check for any deferred with target_device matching
    std::string prefix = user_id + ":";
    auto dit = deferred_.begin();
    while (dit != deferred_.end()) {
      if (dit->first.compare(0, prefix.size(), prefix) == 0) {
        total_deferred_.fetch_sub(dit->second.size());
        result.insert(result.end(),
                       std::make_move_iterator(dit->second.begin()),
                       std::make_move_iterator(dit->second.end()));
        dit = deferred_.erase(dit);
      } else {
        ++dit;
      }
    }
    return result;
  }

  // Re-queue when device goes away again
  void requeue_for_device(const std::string& user_id,
                           const std::string& device_id,
                           const std::vector<ToDeviceMessage>& messages) {
    if (messages.empty()) return;
    std::string key = user_id + ":" + device_id;
    std::unique_lock lock(mutex_);
    auto& q = deferred_[key];
    q.insert(q.end(), messages.begin(), messages.end());
    total_deferred_.fetch_add(messages.size());
  }

  // Get count of deferred messages for a device
  int64_t count_for_device(const std::string& user_id,
                            const std::string& device_id) {
    std::string key = user_id + ":" + device_id;
    std::shared_lock lock(mutex_);
    auto it = deferred_.find(key);
    if (it == deferred_.end()) return 0;
    return static_cast<int64_t>(it->second.size());
  }

  // Get total deferred count for a user
  int64_t count_for_user(const std::string& user_id) {
    int64_t total = 0;
    std::string prefix = user_id + ":";
    std::shared_lock lock(mutex_);
    for (const auto& [key, q] : deferred_) {
      if (key.compare(0, prefix.size(), prefix) == 0) {
        total += q.size();
      }
    }
    return total;
  }

  // Expire deferred messages older than max_age_ms
  int expire_old(int64_t max_age_ms) {
    int64_t cutoff = now_ms() - max_age_ms;
    std::unique_lock lock(mutex_);
    int expired = 0;

    auto it = deferred_.begin();
    while (it != deferred_.end()) {
      auto& q = it->second;
      auto before = q.size();
      q.erase(std::remove_if(q.begin(), q.end(),
                              [&](const ToDeviceMessage& msg) {
                                if (msg.received_ts < cutoff) {
                                  return true;
                                }
                                return false;
                              }),
              q.end());
      expired += static_cast<int>(before - q.size());
      total_deferred_.fetch_sub(before - q.size());

      if (q.empty()) {
        it = deferred_.erase(it);
      } else {
        ++it;
      }
    }
    return expired;
  }

  int64_t total_count() const { return total_deferred_.load(); }
  size_t key_count() const {
    std::shared_lock lock(mutex_);
    return deferred_.size();
  }

  void clear() {
    std::unique_lock lock(mutex_);
    deferred_.clear();
    total_deferred_.store(0);
  }

  json snapshot() const {
    std::shared_lock lock(mutex_);
    json result;
    for (const auto& [key, q] : deferred_) {
      json entry;
      entry["count"] = q.size();
      result[key] = entry;
    }
    return result;
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, std::vector<ToDeviceMessage>> deferred_;
  std::atomic<int64_t> total_deferred_{0};
};

// ============================================================================
// ToDeviceLimitEnforcer — Enforces limits on to-device messages
// ============================================================================
class ToDeviceLimitEnforcer {
public:
  explicit ToDeviceLimitEnforcer(const ToDeviceConfig& cfg) : config_(cfg) {}

  // Validate a single message against limits
  struct LimitCheck {
    bool allowed = true;
    std::string reason;
  };

  LimitCheck check_message_size(const json& content) {
    LimitCheck result;
    std::string serialized = content.dump();
    if (static_cast<int64_t>(serialized.size()) > config_.max_message_content_size) {
      result.allowed = false;
      result.reason = "Message content exceeds maximum size of " +
                      std::to_string(config_.max_message_content_size) +
                      " bytes";
      stats_.total_rejected_limits++;
    }
    return result;
  }

  LimitCheck check_request_size(const json& messages_map) {
    LimitCheck result;
    if (!messages_map.is_object()) {
      result.allowed = false;
      result.reason = "Messages must be an object";
      return result;
    }

    int total_messages = 0;
    for (const auto& [user_id, device_map] : messages_map.items()) {
      if (device_map.is_object()) {
        total_messages += device_map.size();
      }
    }

    if (total_messages > config_.max_messages_per_request) {
      result.allowed = false;
      result.reason = "Too many messages in request: " +
                      std::to_string(total_messages) +
                      " exceeds maximum of " +
                      std::to_string(config_.max_messages_per_request);
      stats_.total_rejected_limits++;
    }
    return result;
  }

  LimitCheck check_user_inbox_limit(const std::string& user_id,
                                      int64_t current_count) {
    LimitCheck result;
    if (current_count >= config_.max_messages_per_user_inbox) {
      result.allowed = false;
      result.reason = "User inbox is full (" +
                      std::to_string(current_count) +
                      " messages, max " +
                      std::to_string(config_.max_messages_per_user_inbox) +
                      ")";
      stats_.total_rejected_limits++;
    }
    return result;
  }

  // Check rate limit for a sender
  bool check_rate_limit(const std::string& sender,
                        ToDeviceRateLimiter& limiter) {
    if (!limiter.allow_request()) {
      stats_.total_rejected_limits++;
      return false;
    }
    return true;
  }

  ToDeviceStats& stats() { return stats_; }
  const ToDeviceConfig& config() const { return config_; }

  void update_config(const ToDeviceConfig& cfg) { config_ = cfg; }

private:
  ToDeviceConfig config_;
  ToDeviceStats stats_;
};

// ============================================================================
// ToDeviceFederationForwarder — Forwards to-device messages to remote servers
// ============================================================================
class ToDeviceFederationForwarder {
public:
  explicit ToDeviceFederationForwarder(const ToDeviceConfig& cfg,
                                         const std::string& server_name)
      : config_(cfg), server_name_(server_name) {}

  // Queue messages for federation to a remote destination
  void queue_for_destination(const std::string& destination,
                              const std::vector<ToDeviceMessage>& messages) {
    if (messages.empty()) return;

    std::unique_lock lock(mutex_);

    auto it = destination_queues_.find(destination);
    if (it == destination_queues_.end()) {
      FederationToDeviceBatch batch;
      batch.destination = destination;
      batch.origin = server_name_;
      batch.created_ts = now_ms();
      batch.messages = messages;
      destination_queues_[destination] = batch;
    } else {
      it->second.messages.insert(it->second.messages.end(),
                                  messages.begin(), messages.end());
    }
    stats_.total_federated.fetch_add(messages.size());
  }

  // Queue a single message for federation
  void queue_single(const std::string& destination,
                      const ToDeviceMessage& msg) {
    std::unique_lock lock(mutex_);
    destination_queues_[destination].messages.push_back(msg);
    if (destination_queues_[destination].destination.empty()) {
      destination_queues_[destination].destination = destination;
      destination_queues_[destination].origin = server_name_;
      destination_queues_[destination].created_ts = now_ms();
    }
    stats_.total_federated++;
  }

  // Get pending batches that are ready to send
  std::vector<FederationToDeviceBatch> get_ready_batches(int64_t now_ts) {
    std::vector<FederationToDeviceBatch> result;
    std::shared_lock lock(mutex_);
    for (auto& [dest, batch] : destination_queues_) {
      if (batch.sent) continue;
      if (batch.next_attempt_ts > 0 && now_ts < batch.next_attempt_ts) continue;
      if (batch.messages.empty()) continue;

      // Cap batch size
      if (static_cast<int64_t>(batch.messages.size()) >
          config_.federation_batch_size) {
        FederationToDeviceBatch split_batch;
        split_batch.destination = batch.destination;
        split_batch.origin = batch.origin;
        split_batch.created_ts = batch.created_ts;

        auto split_point = batch.messages.begin() +
                           config_.federation_batch_size;
        split_batch.messages.assign(batch.messages.begin(), split_point);
        batch.messages.erase(batch.messages.begin(), split_point);
        result.push_back(split_batch);
      } else {
        result.push_back(batch);
      }
    }
    return result;
  }

  // Mark a batch as sent successfully
  void mark_batch_sent(const std::string& destination) {
    std::unique_lock lock(mutex_);
    auto it = destination_queues_.find(destination);
    if (it != destination_queues_.end() && !it->second.messages.empty()) {
      it->second.sent = true;
      it->second.messages.clear();
    }
  }

  // Mark a batch as failed and schedule retry
  void mark_batch_failed(const std::string& destination) {
    std::unique_lock lock(mutex_);
    auto it = destination_queues_.find(destination);
    if (it != destination_queues_.end()) {
      it->second.retry_count++;
      it->second.last_attempt_ts = now_ms();
      if (it->second.retry_count >= config_.federation_max_retries) {
        // Give up, clear messages
        it->second.messages.clear();
        it->second.sent = true;
      } else {
        // Exponential backoff
        int64_t delay = config_.federation_retry_delay_ms *
                        (1 << (it->second.retry_count - 1));
        it->second.next_attempt_ts = now_ms() + delay;
      }
    }
  }

  // Build an EDU JSON array from a batch for federation /send
  json build_edu_batch(const FederationToDeviceBatch& batch) {
    json edu;
    edu["edu_type"] = "m.direct_to_device";
    edu["origin"] = batch.origin;

    json content;
    content["sender"] = batch.messages[0].sender;
    content["type"] = batch.messages[0].message_type;

    json messages_map = json::object();
    for (const auto& msg : batch.messages) {
      if (!messages_map.contains(msg.target_user)) {
        messages_map[msg.target_user] = json::object();
      }
      messages_map[msg.target_user][msg.target_device] = msg.content;
    }
    content["messages"] = messages_map;
    edu["content"] = content;

    return edu;
  }

  // Build full federation transaction
  json build_transaction(const std::string& destination,
                          const std::vector<FederationToDeviceBatch>& batches) {
    std::string txn_id = generate_token(24);
    json txn;
    txn["origin"] = server_name_;
    txn["origin_server_ts"] = now_ms();
    txn["transaction_id"] = txn_id;
    txn["destination"] = destination;
    txn["pdus"] = json::array();

    json edus = json::array();
    for (const auto& batch : batches) {
      edus.push_back(build_edu_batch(batch));
    }
    txn["edus"] = edus;

    return txn;
  }

  // Clean up fully sent destinations
  int cleanup_completed() {
    std::unique_lock lock(mutex_);
    int cleaned = 0;
    auto it = destination_queues_.begin();
    while (it != destination_queues_.end()) {
      if (it->second.sent && it->second.messages.empty()) {
        it = destination_queues_.erase(it);
        cleaned++;
      } else {
        ++it;
      }
    }
    return cleaned;
  }

  // Get all pending destination counts
  json pending_summary() const {
    std::shared_lock lock(mutex_);
    json summary = json::array();
    for (const auto& [dest, batch] : destination_queues_) {
      json entry;
      entry["destination"] = dest;
      entry["pending_count"] = batch.messages.size();
      entry["retry_count"] = batch.retry_count;
      entry["next_attempt_ts"] = batch.next_attempt_ts;
      entry["sent"] = batch.sent;
      summary.push_back(entry);
    }
    return summary;
  }

  size_t queue_count() const {
    std::shared_lock lock(mutex_);
    return destination_queues_.size();
  }

  int64_t total_pending() const {
    int64_t total = 0;
    std::shared_lock lock(mutex_);
    for (const auto& [dest, batch] : destination_queues_) {
      total += batch.messages.size();
    }
    return total;
  }

  ToDeviceStats& stats() { return stats_; }

private:
  ToDeviceConfig config_;
  std::string server_name_;
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, FederationToDeviceBatch> destination_queues_;
  ToDeviceStats stats_;
};

// ============================================================================
// ToDeviceCleanupWorker — Background cleanup of old/expired messages
// ============================================================================
class ToDeviceCleanupWorker {
public:
  explicit ToDeviceCleanupWorker(const ToDeviceConfig& cfg,
                                   ToDeviceInboxStore& inbox,
                                   DeferredDeviceQueue& deferred,
                                   ToDeviceStreamTracker& tracker)
      : config_(cfg), inbox_(inbox), deferred_(deferred), tracker_(tracker) {}

  // Run a single cleanup pass
  struct CleanupResult {
    int delivered_deleted = 0;
    int undelivered_expired = 0;
    int deferred_expired = 0;
    int stream_positions_expired = 0;
    int64_t elapsed_ms = 0;
  };

  CleanupResult run() {
    int64_t start = now_ms();
    CleanupResult result;
    int64_t now = now_ms();

    // 1. Expire undelivered messages
    result.undelivered_expired =
        inbox_.expire_undelivered(config_.undelivered_message_timeout_ms);

    // 2. Expire deferred messages
    result.deferred_expired =
        deferred_.expire_old(config_.deferred_queue_max_age_ms);

    // 3. Evict stale stream positions
    tracker_.evict_stale_positions(config_.stream_id_max_age_ms);

    stats_.total_cleanup_deleted.fetch_add(
        result.delivered_deleted + result.undelivered_expired +
        result.deferred_expired);
    stats_.last_cleanup_ts = now;

    result.elapsed_ms = now_ms() - start;
    return result;
  }

  ToDeviceStats& stats() { return stats_; }

private:
  ToDeviceConfig config_;
  ToDeviceInboxStore& inbox_;
  DeferredDeviceQueue& deferred_;
  ToDeviceStreamTracker& tracker_;
  ToDeviceStats stats_;
};

// ============================================================================
// ToDeviceSender — Core send logic for to-device messages
// ============================================================================
class ToDeviceSender {
public:
  ToDeviceSender(ToDeviceConfig cfg,
                  ToDeviceTransactionStore& txn_store,
                  ToDeviceDeduplicator& dedup,
                  ToDeviceWildcardResolver& wildcard_resolver,
                  ToDeviceInboxStore& inbox,
                  ToDeviceStreamTracker& stream_tracker,
                  ToDeviceRateLimiter& rate_limiter,
                  DeferredDeviceQueue& deferred,
                  ToDeviceFederationForwarder& federation,
                  ToDeviceLimitEnforcer& limits,
                  const std::string& server_name)
      : config_(cfg), txn_store_(txn_store), dedup_(dedup),
        wildcard_resolver_(wildcard_resolver), inbox_(inbox),
        stream_tracker_(stream_tracker), rate_limiter_(rate_limiter),
        deferred_(deferred), federation_(federation), limits_(limits),
        server_name_(server_name) {}

  // ========================================================================
  // send_to_device — Main entry point: process a sendToDevice request
  //
  // Parameters:
  //   sender       — the user ID sending the messages
  //   sender_device — the device ID of the sender
  //   event_type   — the event type (e.g. "m.room_key")
  //   txn_id       — transaction ID for idempotency
  //   messages_map — { user_id: { device_id: content } }
  //
  // Returns: ToDeviceSendResult with details about what was delivered
  // ========================================================================
  ToDeviceSendResult send_to_device(const std::string& sender,
                                      const std::string& sender_device,
                                      const std::string& event_type,
                                      const std::string& txn_id,
                                      const json& messages_map) {
    ToDeviceSendResult result;
    result.txn_id = txn_id;
    result.timestamp_ms = now_ms();

    // ---- Step 1: Idempotency check ----
    if (txn_store_.is_duplicate_for_user(sender, txn_id)) {
      result.success = true;
      result.messages_sent = 0;
      return result;  // Already processed
    }

    // ---- Step 2: Rate limit check ----
    if (!rate_limiter_.allow_request()) {
      result.success = false;
      result.errors.push_back("Rate limit exceeded");
      return result;
    }

    // ---- Step 3: Validate input ----
    if (!is_valid_event_type(event_type)) {
      result.success = false;
      result.errors.push_back("Invalid event type: " + event_type);
      return result;
    }

    // ---- Step 4: Check request size limits ----
    auto size_check = limits_.check_request_size(messages_map);
    if (!size_check.allowed) {
      result.success = false;
      result.errors.push_back(size_check.reason);
      return result;
    }

    // ---- Step 5: Process each user/device pair ----
    int64_t ts = now_ms();
    int delivered_total = 0;
    int federated_total = 0;
    int wildcard_total = 0;

    for (const auto& [target_user, device_map] : messages_map.items()) {
      if (!device_map.is_object()) continue;
      if (!is_valid_user_id(target_user)) {
        result.errors.push_back("Invalid target user ID: " +
                                truncate(target_user));
        continue;
      }

      bool is_local = is_local_user(target_user, server_name_);

      for (const auto& [target_device, msg_content] : device_map.items()) {
        // Check message content size
        auto content_check = limits_.check_message_size(msg_content);
        if (!content_check.allowed) {
          result.errors.push_back("For " + target_user + "/" + target_device +
                                  ": " + content_check.reason);
          continue;
        }

        // Generate message ID
        std::string msg_id = make_message_id(sender, sender_device,
                                               event_type, ts);
        // Dedup check
        if (dedup_.check_and_mark(msg_id)) {
          continue;  // Duplicate, skip
        }
        stats_.total_deduplicated++;

        // Build the message
        ToDeviceMessage msg;
        msg.message_id = msg_id;
        msg.sender = sender;
        msg.sender_device = sender_device;
        msg.target_user = target_user;
        msg.target_device = target_device;
        msg.message_type = event_type;
        msg.content = msg_content;
        msg.received_ts = ts;

        if (is_local) {
          // ---- Local delivery ----
          if (target_device == "*") {
            // Wildcard expansion
            auto device_ids = wildcard_resolver_.resolve(target_user, "*");
            if (device_ids.empty()) {
              // No devices known yet — defer for later
              deferred_.enqueue(msg);
              result.deferred_devices.push_back(target_user + ":" +
                                                  target_device);
              stats_.total_deferred++;
              continue;
            }

            wildcard_total++;
            for (const auto& did : device_ids) {
              msg.stream_id = stream_tracker_.next_stream_id();
              msg.target_device = did;
              msg.wildcard_expanded = true;

              bool added = inbox_.add_message(
                  msg, config_.max_messages_per_user_inbox);
              if (added) {
                delivered_total++;
              } else {
                result.errors.push_back(
                    "Inbox full for " + target_user + "/" + did);
              }
            }
          } else {
            // Direct device delivery
            if (!wildcard_resolver_.has_device(target_user, target_device)) {
              // Device doesn't exist — defer
              deferred_.enqueue(msg);
              result.deferred_devices.push_back(target_user + ":" +
                                                  target_device);
              stats_.total_deferred++;
              continue;
            }

            msg.stream_id = stream_tracker_.next_stream_id();
            bool added = inbox_.add_message(
                msg, config_.max_messages_per_user_inbox);
            if (added) {
              delivered_total++;
            } else {
              result.errors.push_back(
                  "Inbox full for " + target_user + "/" + target_device);
            }
          }
        } else {
          // ---- Federation delivery ----
          std::string dest_server = server_name_from_user_id(target_user);
          if (!dest_server.empty()) {
            federation_.queue_single(dest_server, msg);
            federated_total++;
          }
        }
      }
    }

    // ---- Step 6: Record transaction for idempotency ----
    json request_hash = {
      {"event_type", event_type},
      {"user_count", messages_map.size()},
      {"timestamp", ts}
    };
    txn_store_.record_transaction(sender, txn_id, event_type,
                                    delivered_total + federated_total,
                                    request_hash);

    // Update stats
    stats_.total_sent.fetch_add(delivered_total + federated_total);
    stats_.total_delivered.fetch_add(delivered_total);
    stats_.total_federated.fetch_add(federated_total);
    stats_.total_wildcard_expanded.fetch_add(wildcard_total);
    stats_.total_deferred.fetch_add(
        static_cast<int64_t>(result.deferred_devices.size()));
    stats_.current_inbox_count.store(inbox_.total_count());
    stats_.current_deferred_count.store(deferred_.total_count());

    result.success = true;
    result.messages_sent = delivered_total + federated_total;
    result.devices_delivered = delivered_total;
    result.users_queued_federation = federated_total;
    result.wildcard_expansions = wildcard_total;

    return result;
  }

  // ========================================================================
  // notify_device_appeared — Call when a new device is created.
  // Deliver any deferred messages to it.
  // ========================================================================
  std::vector<ToDeviceMessage> notify_device_appeared(
      const std::string& user_id, const std::string& device_id) {
    // Register the device with the wildcard resolver
    wildcard_resolver_.add_user_device(user_id, device_id);

    // Poll deferred messages for this specific device
    auto deferred_msgs = deferred_.poll_for_device(user_id, device_id);
    if (deferred_msgs.empty()) return {};

    // Also poll wildcard-deferred messages
    auto wildcard_msgs = deferred_.poll_wildcard_for_user(user_id);

    // Merge and deliver
    std::vector<ToDeviceMessage> all_deferred;
    all_deferred.insert(all_deferred.end(),
                         deferred_msgs.begin(), deferred_msgs.end());
    all_deferred.insert(all_deferred.end(),
                         wildcard_msgs.begin(), wildcard_msgs.end());

    int64_t ts = now_ms();
    for (auto& msg : all_deferred) {
      msg.stream_id = stream_tracker_.next_stream_id();
      msg.received_ts = ts;
      inbox_.add_message(msg, config_.max_messages_per_user_inbox);
    }

    return all_deferred;
  }

  // ========================================================================
  // notify_device_removed — Call when a device is deleted.
  // Re-queue any pending messages and clean up.
  // ========================================================================
  void notify_device_removed(const std::string& user_id,
                              const std::string& device_id) {
    // Get undelivered messages and re-queue them
    auto pending = inbox_.get_messages(user_id, device_id, 0, 1000);
    std::vector<ToDeviceMessage> undelivered;
    for (auto& msg : pending) {
      if (!msg.delivered) {
        undelivered.push_back(msg);
      }
    }

    // Re-queue if there are other devices or defer
    if (!undelivered.empty()) {
      auto other_devices = wildcard_resolver_.list_devices(user_id);
      other_devices.erase(
          std::remove(other_devices.begin(), other_devices.end(), device_id),
          other_devices.end());

      if (!other_devices.empty()) {
        // Deliver to remaining devices
        for (const auto& msg : undelivered) {
          int64_t stream_id = stream_tracker_.next_stream_id();
          for (const auto& other_did : other_devices) {
            ToDeviceMessage copy = msg;
            copy.target_device = other_did;
            copy.stream_id = stream_id++;
            inbox_.add_message(copy, config_.max_messages_per_user_inbox);
          }
        }
      } else {
        // No devices left, re-queue as deferred
        for (auto& msg : undelivered) {
          deferred_.enqueue(msg);
        }
      }
    }

    // Clean up
    inbox_.delete_all_for_device(user_id, device_id);
    wildcard_resolver_.remove_user_device(user_id, device_id);
    stream_tracker_.remove_device(user_id, device_id);
    dedup_.evict_expired();
  }

  // ========================================================================
  // get_sync — Get to-device messages for a sync response
  // ========================================================================
  ToDeviceSyncResult get_sync(const std::string& user_id,
                               const std::string& device_id,
                               const std::string& since_token,
                               int limit = 100) {
    ToDeviceSyncResult result;
    int64_t since_pos = stream_tracker_.parse_sync_token(since_token);

    auto messages = inbox_.get_messages(user_id, device_id, since_pos, limit);

    for (const auto& msg : messages) {
      result.events.push_back(msg.to_sync_format());
    }

    // Mark as delivered
    std::vector<std::string> delivered_ids;
    for (const auto& msg : messages) {
      delivered_ids.push_back(msg.message_id);
    }
    inbox_.mark_delivered(user_id, device_id, delivered_ids);

    // Generate next batch token
    result.next_batch_token = stream_tracker_.current_stream_id();
    result.has_more = (static_cast<int>(messages.size()) >= limit);
    result.total_pending = static_cast<int>(
        inbox_.count_pending_for_user(user_id));

    return result;
  }

  // ========================================================================
  // get_sync_for_all_devices — Get to-device for all user devices in sync
  // ========================================================================
  json get_sync_all_devices(const std::string& user_id,
                              const std::string& since_token) {
    json result;
    result["events"] = json::array();

    int64_t since_pos = stream_tracker_.parse_sync_token(since_token);
    auto messages = inbox_.get_all_for_user(user_id, 500);

    std::unordered_map<std::string, std::vector<ToDeviceMessage>> by_device;
    for (const auto& msg : messages) {
      if (msg.stream_id > since_pos) {
        by_device[msg.target_device].push_back(msg);
      }
    }

    for (const auto& [did, msgs] : by_device) {
      for (const auto& msg : msgs) {
        result["events"].push_back(msg.to_sync_format());
      }
      // Mark delivered
      std::vector<std::string> ids;
      for (const auto& msg : msgs) {
        ids.push_back(msg.message_id);
      }
      inbox_.mark_delivered(user_id, did, ids);
    }

    return result;
  }

  // ========================================================================
  // process_federation_edu — Handle incoming m.direct_to_device EDU
  // ========================================================================
  ToDeviceSendResult process_federation_edu(const std::string& origin,
                                              const json& edu_content) {
    ToDeviceSendResult result;
    result.timestamp_ms = now_ms();

    std::string sender = edu_content.value("sender", "");
    std::string msg_type = edu_content.value("type", "");
    json messages = edu_content.value("messages", json::object());

    if (!is_valid_event_type(msg_type)) {
      result.errors.push_back("Invalid event type from federation: " +
                              msg_type);
      return result;
    }

    for (const auto& [target_user, device_msgs] : messages.items()) {
      if (!device_msgs.is_object()) continue;
      if (!is_valid_user_id(target_user)) continue;
      if (!is_local_user(target_user, server_name_)) {
        // Not for us — shouldn't happen
        continue;
      }

      for (const auto& [target_device, msg_content] : device_msgs.items()) {
        std::string msg_id = make_message_id(sender, "",
                                               msg_type, now_ms());

        if (dedup_.check_and_mark(msg_id)) continue;

        ToDeviceMessage msg;
        msg.message_id = msg_id;
        msg.sender = sender;
        msg.sender_device = "";
        msg.target_user = target_user;
        msg.target_device = target_device;
        msg.message_type = msg_type;
        msg.content = msg_content;
        msg.received_ts = now_ms();

        if (target_device == "*") {
          auto device_ids = wildcard_resolver_.resolve(target_user, "*");
          if (device_ids.empty()) {
            deferred_.enqueue(msg);
            result.deferred_devices.push_back(target_user + ":*");
            continue;
          }
          for (const auto& did : device_ids) {
            msg.stream_id = stream_tracker_.next_stream_id();
            msg.target_device = did;
            inbox_.add_message(msg, config_.max_messages_per_user_inbox);
            result.devices_delivered++;
          }
        } else {
          if (!wildcard_resolver_.has_device(target_user, target_device)) {
            deferred_.enqueue(msg);
            result.deferred_devices.push_back(target_user + ":" +
                                                target_device);
            continue;
          }
          msg.stream_id = stream_tracker_.next_stream_id();
          inbox_.add_message(msg, config_.max_messages_per_user_inbox);
          result.devices_delivered++;
        }
      }
    }

    result.success = true;
    result.messages_sent = result.devices_delivered;
    return result;
  }

  // ========================================================================
  // Accessors for internal components
  // ========================================================================
  ToDeviceStats& stats() { return stats_; }
  const ToDeviceConfig& config() const { return config_; }
  ToDeviceInboxStore& inbox() { return inbox_; }
  DeferredDeviceQueue& deferred() { return deferred_; }
  ToDeviceStreamTracker& stream_tracker() { return stream_tracker_; }
  ToDeviceWildcardResolver& wildcard_resolver() { return wildcard_resolver_; }

  // ========================================================================
  // Administrative operations
  // ========================================================================
  json get_state() {
    return {
      {"config", config_.to_json()},
      {"stats", stats_.snapshot()},
      {"stream_id", stream_tracker_.current_stream_id()},
      {"inbox_count", inbox_.total_count()},
      {"inbox_devices", inbox_.device_count()},
      {"deferred_count", deferred_.total_count()},
      {"deferred_keys", deferred_.key_count()},
      {"dedup_cache_size", dedup_.cache_size()},
      {"federation_queues", federation_.queue_count()},
      {"federation_pending", federation_.total_pending()},
      {"transaction_count", txn_store_.size()},
      {"rate_limiter", rate_limiter_.status()}
    };
  }

  void run_cleanup() {
    cleanup_worker_ = std::make_unique<ToDeviceCleanupWorker>(
        config_, inbox_, deferred_, stream_tracker_);
    auto clean_result = cleanup_worker_->run();

    // Also cleanup transactions and dedup cache
    txn_store_.evict_old_transactions(86400000); // 24 hours
    dedup_.evict_expired();
    federation_.cleanup_completed();
  }

private:
  ToDeviceConfig config_;
  ToDeviceTransactionStore& txn_store_;
  ToDeviceDeduplicator& dedup_;
  ToDeviceWildcardResolver& wildcard_resolver_;
  ToDeviceInboxStore& inbox_;
  ToDeviceStreamTracker& stream_tracker_;
  ToDeviceRateLimiter& rate_limiter_;
  DeferredDeviceQueue& deferred_;
  ToDeviceFederationForwarder& federation_;
  ToDeviceLimitEnforcer& limits_;
  std::string server_name_;
  ToDeviceStats stats_;
  std::unique_ptr<ToDeviceCleanupWorker> cleanup_worker_;
};

// ============================================================================
// ToDeviceCoordinator — Top-level coordinator managing all to-device components
// ============================================================================
class ToDeviceCoordinator {
public:
  explicit ToDeviceCoordinator(const ToDeviceConfig& cfg,
                                 const std::string& server_name = "localhost")
      : config_(cfg),
        server_name_(server_name),
        dedup_(cfg.dedup_cache_size, cfg.dedup_cache_ttl_ms),
        rate_limiter_(cfg.send_rate_burst, cfg.send_rate_per_second),
        limits_(cfg),
        federation_(cfg, server_name),
        sender_(cfg, txn_store_, dedup_, wildcard_resolver_, inbox_,
                stream_tracker_, rate_limiter_, deferred_, federation_,
                limits_, server_name) {}

  // ---- Main send API ----
  ToDeviceSendResult send_to_device(const std::string& sender,
                                      const std::string& sender_device,
                                      const std::string& event_type,
                                      const std::string& txn_id,
                                      const json& messages_map) {
    return sender_.send_to_device(sender, sender_device, event_type,
                                   txn_id, messages_map);
  }

  // ---- Sync API ----
  ToDeviceSyncResult get_sync(const std::string& user_id,
                               const std::string& device_id,
                               const std::string& since_token,
                               int limit = 100) {
    return sender_.get_sync(user_id, device_id, since_token, limit);
  }

  json get_sync_all_devices(const std::string& user_id,
                             const std::string& since_token) {
    return sender_.get_sync_all_devices(user_id, since_token);
  }

  // ---- Device lifecycle ----
  void register_device(const std::string& user_id,
                        const std::string& device_id) {
    wildcard_resolver_.add_user_device(user_id, device_id);
    auto deferred_msgs = sender_.notify_device_appeared(user_id, device_id);
    if (!deferred_msgs.empty()) {
      // Messages were delivered from deferred queue
    }
  }

  void unregister_device(const std::string& user_id,
                          const std::string& device_id) {
    sender_.notify_device_removed(user_id, device_id);
  }

  void register_user(const std::string& user_id) {
    wildcard_resolver_.add_user_device(user_id, "");  // placeholder
  }

  void unregister_user(const std::string& user_id) {
    wildcard_resolver_.remove_user(user_id);
    inbox_.delete_all_for_user(user_id);
    stream_tracker_.remove_user(user_id);
  }

  // ---- Federation ----
  ToDeviceSendResult process_federation_edu(const std::string& origin,
                                               const json& edu_content) {
    return sender_.process_federation_edu(origin, edu_content);
  }

  json get_federation_batch(const std::string& destination) {
    json result;
    result["edus"] = json::array();

    auto batches = federation_.get_ready_batches(now_ms());
    for (auto& batch : batches) {
      if (batch.destination == destination) {
        result["edus"].push_back(federation_.build_edu_batch(batch));
      }
    }
    return result;
  }

  void mark_federation_batch_sent(const std::string& destination) {
    federation_.mark_batch_sent(destination);
  }

  void mark_federation_batch_failed(const std::string& destination) {
    federation_.mark_batch_failed(destination);
  }

  json federation_pending() { return federation_.pending_summary(); }

  // ---- Cleanup ----
  void run_cleanup() { sender_.run_cleanup(); }

  // ---- Configuration ----
  void update_config(const ToDeviceConfig& cfg) {
    config_ = cfg;
    rate_limiter_.set_rate(cfg.send_rate_burst, cfg.send_rate_per_second);
    limits_.update_config(cfg);
  }

  // ---- Status and monitoring ----
  json get_state() { return sender_.get_state(); }
  ToDeviceStats& stats() { return sender_.stats(); }

  // ---- Direct access for internal use ----
  ToDeviceWildcardResolver& wildcard_resolver() { return wildcard_resolver_; }
  ToDeviceStreamTracker& stream_tracker() { return stream_tracker_; }
  ToDeviceInboxStore& inbox() { return inbox_; }
  DeferredDeviceQueue& deferred() { return deferred_; }
  ToDeviceDeduplicator& dedup() { return dedup_; }

private:
  ToDeviceConfig config_;
  std::string server_name_;

  // Core components (order matters for initialization)
  ToDeviceTransactionStore txn_store_;
  ToDeviceDeduplicator dedup_;
  ToDeviceWildcardResolver wildcard_resolver_;
  ToDeviceInboxStore inbox_;
  ToDeviceStreamTracker stream_tracker_;
  ToDeviceRateLimiter rate_limiter_;
  DeferredDeviceQueue deferred_;
  ToDeviceLimitEnforcer limits_;
  ToDeviceFederationForwarder federation_;
  ToDeviceSender sender_;
};

// ============================================================================
// Utility: Build a to-device sync section from coordinator
// ============================================================================
json build_to_device_sync_section(ToDeviceCoordinator& coordinator,
                                    const std::string& user_id,
                                    const std::string& device_id,
                                    const std::string& since_token) {
  auto sync_result = coordinator.get_sync(user_id, device_id, since_token, 100);
  json section;
  section["events"] = sync_result.events;
  return section;
}

// ============================================================================
// Backward-compatible standalone API:
//   These functions mirror the simpler DeviceMessageHandler API used in
//   handlers_misc_full.cpp so existing code can use the richer coordinator.
// ============================================================================

// Simple singleton-like instance for backward compatibility
static std::unique_ptr<ToDeviceCoordinator> g_to_device_coordinator;

void init_to_device_system(const std::string& server_name,
                             const ToDeviceConfig& cfg) {
  g_to_device_coordinator = std::make_unique<ToDeviceCoordinator>(
      cfg, server_name);
}

void init_to_device_system_default(const std::string& server_name) {
  ToDeviceConfig cfg;
  cfg.server_name = server_name;
  g_to_device_coordinator = std::make_unique<ToDeviceCoordinator>(
      cfg, server_name);
}

ToDeviceCoordinator* get_to_device_coordinator() {
  return g_to_device_coordinator.get();
}

// Simple send — for backward compatibility with DeviceMessageHandler
void send_device_message_simple(const std::string& sender,
                                  const std::string& sender_device,
                                  const std::string& target_user,
                                  const std::string& target_device,
                                  const std::string& message_type,
                                  const json& content) {
  if (!g_to_device_coordinator) return;

  json messages_map;
  messages_map[target_user][target_device] = content;

  std::string txn_id = generate_token(16);
  g_to_device_coordinator->send_to_device(sender, sender_device,
                                            message_type, txn_id,
                                            messages_map);
}

// Bulk send — for backward compatibility with DeviceMessageHandler
void send_device_messages_simple(
    const std::string& sender,
    const std::string& message_type,
    const std::map<std::string, std::map<std::string, json>>& messages) {
  if (!g_to_device_coordinator) return;

  json messages_map;
  for (const auto& [user_id, device_msgs] : messages) {
    json device_map;
    for (const auto& [device_id, content] : device_msgs) {
      device_map[device_id] = content;
    }
    messages_map[user_id] = device_map;
  }

  std::string txn_id = generate_token(16);
  g_to_device_coordinator->send_to_device(sender, "", message_type,
                                            txn_id, messages_map);
}

// Get to-device messages for sync
json get_to_device_messages_simple(const std::string& user_id,
                                     const std::string& device_id,
                                     const std::string& since_token) {
  if (!g_to_device_coordinator) {
    json result;
    result["events"] = json::array();
    return result;
  }
  return build_to_device_sync_section(*g_to_device_coordinator,
                                        user_id, device_id, since_token);
}

// Register device with to-device system
void register_device_for_to_device(const std::string& user_id,
                                     const std::string& device_id) {
  if (g_to_device_coordinator) {
    g_to_device_coordinator->register_device(user_id, device_id);
  }
}

// Unregister device from to-device system
void unregister_device_from_to_device(const std::string& user_id,
                                        const std::string& device_id) {
  if (g_to_device_coordinator) {
    g_to_device_coordinator->unregister_device(user_id, device_id);
  }
}

// Process incoming federation to-device EDU
json process_federation_to_device_edu(const std::string& origin,
                                        const json& edu_content) {
  if (!g_to_device_coordinator) {
    json result;
    result["success"] = false;
    result["error"] = "To-device system not initialized";
    return result;
  }
  auto send_result = g_to_device_coordinator->process_federation_edu(
      origin, edu_content);
  return send_result.to_json();
}

// Run periodic cleanup
void run_to_device_cleanup() {
  if (g_to_device_coordinator) {
    g_to_device_coordinator->run_cleanup();
  }
}

// Get monitoring stats
json get_to_device_stats() {
  if (!g_to_device_coordinator) {
    return json::object();
  }
  return g_to_device_coordinator->get_state();
}

// Shutdown
void shutdown_to_device_system() {
  g_to_device_coordinator.reset();
}

}  // namespace progressive
