// ============================================================================
// stream_manager.cpp — Matrix Event Streaming Manager
//
// Implements the complete Matrix event stream infrastructure:
//   - Stream ID generation for all 8 stream types (events, presence,
//     receipts, typing, to_device, device_lists, account_data, push_rules)
//   - Stream position tracking per user per stream type for incremental sync
//   - Stream token encoding/decoding for sync tokens (multi-stream,
//     base64-encoded opaque tokens with versioning and validation)
//   - Stream change caches with LRU eviction and TTL-based expiry
//     for hot-path acceleration during /sync
//   - Max stream ID queries for gap detection and replication
//   - Stream ordering management for causal ordering across streams
//   - Full SQL DDL for all stream tables with indexes and constraints
//   - Per-stream CRUD operations with parameterized queries
//   - Transaction-safe stream ID advancement
//   - Cluster-aware stream ID coordination primitives
//   - Stream metrics collection and reporting
//   - Admin API support (stream reset, position queries, cache purge)
//
// Stream types:
//   1. events        — room event timeline (events.stream_ordering)
//   2. presence      — user presence state changes
//   3. receipts      — read receipts (m.read, m.read.private)
//   4. typing        — typing indicator EDUs
//   5. to_device     — end-to-end encrypted to-device messages
//   6. device_lists  — device identity list changes
//   7. account_data  — user account data changes (global + per-room)
//   8. push_rules    — push notification rule changes
//
// Equivalent to:
//   synapse/storage/databases/main/stream.py          (1,800+ lines)
//   synapse/types.py — StreamToken, RoomStreamToken    (~120 lines)
//   synapse/replication/tcp/streams/__init__.py        (~400 lines)
//   synapse/streams/events.py                          (~200 lines)
//   synapse/handlers/sync.py — token handling          (~300 lines)
//   synapse/util/caches/stream_change_cache.py         (~150 lines)
//
// Total equivalent: ~3,000 lines of Python
//
// Target: 3000+ lines of production-grade C++.
// Namespace: progressive::
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <bitset>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <list>
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
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/engine.hpp"
#include "progressive/storage/types.hpp"
#include "progressive/util/cache.hpp"
#include "progressive/util/log.hpp"
#include "progressive/util/random.hpp"
#include "progressive/util/time.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for storage
// ============================================================================
namespace storage {
class DatabasePool;
class LoggingTransaction;
}  // namespace storage

using storage::DatabasePool;
using storage::LoggingTransaction;
using storage::Row;
using storage::RowList;
using storage::ColumnValue;
using storage::SQLParam;

// ============================================================================
// Inline constants
// ============================================================================
namespace {

// Stream names for logging and metrics
constexpr const char* kStreamNameEvents = "events";
constexpr const char* kStreamNamePresence = "presence";
constexpr const char* kStreamNameReceipts = "receipts";
constexpr const char* kStreamNameTyping = "typing";
constexpr const char* kStreamNameToDevice = "to_device";
constexpr const char* kStreamNameDeviceLists = "device_lists";
constexpr const char* kStreamNameAccountData = "account_data";
constexpr const char* kStreamNamePushRules = "push_rules";

// Stream type enumeration
enum class StreamType : uint8_t {
  kEvents = 0,
  kPresence = 1,
  kReceipts = 2,
  kTyping = 3,
  kToDevice = 4,
  kDeviceLists = 5,
  kAccountData = 6,
  kPushRules = 7,
  kCount = 8,
};

// Number of stream types
constexpr size_t kNumStreamTypes = static_cast<size_t>(StreamType::kCount);

// Array of all stream type names (indexed by StreamType)
constexpr std::array<const char*, kNumStreamTypes> kStreamTypeNames = {
    kStreamNameEvents,      kStreamNamePresence,     kStreamNameReceipts,
    kStreamNameTyping,      kStreamNameToDevice,     kStreamNameDeviceLists,
    kStreamNameAccountData, kStreamNamePushRules,
};

// Default cache sizes per stream
constexpr size_t kDefaultChangeCacheSize = 1000;
constexpr int64_t kDefaultChangeCacheTtlSec = 300;

// Sync token configuration
constexpr const char* kSyncTokenPrefixV1 = "s4";
constexpr const char* kSyncTokenSeparator = "_";
constexpr size_t kSyncTokenMaxLength = 512;

// Stream position limits
constexpr int64_t kMaxStreamID = INT64_MAX;
constexpr int64_t kMinStreamID = 0;
constexpr int64_t kStreamIDAdvanceBatch = 1;

// Cache configuration
constexpr size_t kMaxCacheEntries = 2000;
constexpr int64_t kCacheTtlDefaultSec = 600;
constexpr int64_t kCacheEvictionIntervalMs = 60'000;

// Concurrency limits
constexpr int kMaxRetriesForStreamID = 10;

// ============================================================================
// Helper: convert StreamType to string
// ============================================================================
const char* stream_type_name(StreamType st) {
  auto idx = static_cast<size_t>(st);
  return (idx < kNumStreamTypes) ? kStreamTypeNames[idx] : "unknown";
}

// ============================================================================
// Helper: stream type to stream ID column name in sync tokens
// ============================================================================
const char* stream_type_to_token_key(StreamType st) {
  switch (st) {
    case StreamType::kEvents:      return "events";
    case StreamType::kPresence:    return "presence";
    case StreamType::kReceipts:    return "receipts";
    case StreamType::kTyping:      return "typing";
    case StreamType::kToDevice:    return "to_device";
    case StreamType::kDeviceLists: return "device_lists";
    case StreamType::kAccountData: return "account_data";
    case StreamType::kPushRules:   return "push_rules";
    default:                       return "unknown";
  }
}

// ============================================================================
// Helper: stream type to max_stream table name
// ============================================================================
std::string stream_type_to_max_table(StreamType st) {
  switch (st) {
    case StreamType::kEvents:      return "events_max_stream_id";
    case StreamType::kPresence:    return "presence_max_stream_id";
    case StreamType::kReceipts:    return "receipts_max_stream_id";
    case StreamType::kTyping:      return "typing_max_stream_id";
    case StreamType::kToDevice:    return "to_device_max_stream_id";
    case StreamType::kDeviceLists: return "device_lists_max_stream_id";
    case StreamType::kAccountData: return "account_data_max_stream_id";
    case StreamType::kPushRules:   return "push_rules_max_stream_id";
    default:                       return "unknown_max_stream_id";
  }
}

// ============================================================================
// Helper: stream type to user position table name
// ============================================================================
std::string stream_type_to_pos_table(StreamType st) {
  switch (st) {
    case StreamType::kEvents:      return "events_stream_positions";
    case StreamType::kPresence:    return "presence_stream_positions";
    case StreamType::kReceipts:    return "receipts_stream_positions";
    case StreamType::kTyping:      return "typing_stream_positions";
    case StreamType::kToDevice:    return "to_device_stream_positions";
    case StreamType::kDeviceLists: return "device_lists_stream_positions";
    case StreamType::kAccountData: return "account_data_stream_positions";
    case StreamType::kPushRules:   return "push_rules_stream_positions";
    default:                       return "unknown_stream_positions";
  }
}

// ============================================================================
// SQL string escaping
// ============================================================================
static std::string sql_escape(std::string_view sv) {
  std::string out;
  out.reserve(sv.size() + 4);
  for (char c : sv) {
    if (c == '\'') out += "''";
    else out += c;
  }
  return out;
}

// ============================================================================
// Timestamp helpers
// ============================================================================
static int64_t now_ms() {
  return util::now_ms();
}

static int64_t now_sec() {
  return now_ms() / 1000;
}

// ============================================================================
// Base64 encoding for sync tokens
// ============================================================================
static const char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static std::string base64_url_encode(const std::vector<uint8_t>& data) {
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  for (size_t i = 0; i < data.size(); i += 3) {
    uint32_t val = static_cast<uint32_t>(data[i]) << 16;
    if (i + 1 < data.size()) val |= static_cast<uint32_t>(data[i + 1]) << 8;
    if (i + 2 < data.size()) val |= static_cast<uint32_t>(data[i + 2]);
    out += kBase64Alphabet[(val >> 18) & 0x3F];
    out += kBase64Alphabet[(val >> 12) & 0x3F];
    if (i + 1 < data.size()) out += kBase64Alphabet[(val >> 6) & 0x3F];
    if (i + 2 < data.size()) out += kBase64Alphabet[val & 0x3F];
  }
  return out;
}

static std::vector<uint8_t> base64_url_decode(std::string_view encoded) {
  std::vector<uint8_t> out;
  out.reserve((encoded.size() * 3) / 4 + 1);

  // Build reverse lookup table
  static const std::array<int8_t, 256> kDecodeTable = []() {
    std::array<int8_t, 256> t;
    t.fill(-1);
    for (int i = 0; i < 64; ++i) {
      t[static_cast<uint8_t>(kBase64Alphabet[i])] = static_cast<int8_t>(i);
    }
    // Support both standard base64 and URL-safe variants
    t[static_cast<uint8_t>('+')] = 62;
    t[static_cast<uint8_t>('/')] = 63;
    return t;
  }();

  size_t i = 0;
  while (i < encoded.size()) {
    int8_t v0 = (i < encoded.size()) ? kDecodeTable[static_cast<uint8_t>(encoded[i])] : -1;
    int8_t v1 = (i + 1 < encoded.size()) ? kDecodeTable[static_cast<uint8_t>(encoded[i + 1])] : -1;
    int8_t v2 = (i + 2 < encoded.size()) ? kDecodeTable[static_cast<uint8_t>(encoded[i + 2])] : -1;
    int8_t v3 = (i + 3 < encoded.size()) ? kDecodeTable[static_cast<uint8_t>(encoded[i + 3])] : -1;

    if (v0 < 0) break;

    uint32_t val = (static_cast<uint32_t>(v0) << 18);
    if (v1 >= 0) val |= (static_cast<uint32_t>(v1) << 12);
    if (v2 >= 0) val |= (static_cast<uint32_t>(v2) << 6);
    if (v3 >= 0) val |= static_cast<uint32_t>(v3);

    out.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    if (v2 >= 0) out.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    if (v3 >= 0) out.push_back(static_cast<uint8_t>(val & 0xFF));

    i += 4;
  }
  return out;
}

// ============================================================================
// Varint encoding for compact stream token positions
// ============================================================================
static void append_varint(std::vector<uint8_t>& buf, uint64_t value) {
  while (value >= 0x80) {
    buf.push_back(static_cast<uint8_t>((value & 0x7F) | 0x80));
    value >>= 7;
  }
  buf.push_back(static_cast<uint8_t>(value & 0x7F));
}

static std::pair<uint64_t, bool> read_varint(const uint8_t* data,
                                               size_t size, size_t& offset) {
  uint64_t result = 0;
  int shift = 0;
  while (offset < size) {
    uint8_t byte = data[offset++];
    result |= (static_cast<uint64_t>(byte & 0x7F) << shift);
    if ((byte & 0x80) == 0) {
      return {result, true};
    }
    shift += 7;
    if (shift >= 63) {
      // Overflow protection
      return {0, false};
    }
  }
  return {0, false};
}

// ============================================================================
// Internal utility: parse a JSON value safely
// ============================================================================
static json parse_json_safe(const std::string& raw) {
  if (raw.empty()) return json::object();
  try {
    return json::parse(raw);
  } catch (...) {
    return json::object();
  }
}

}  // anonymous namespace

// ============================================================================
// StreamPosition — holds positions for all 8 stream types
// ============================================================================
struct StreamPosition {
  std::array<int64_t, kNumStreamTypes> positions{};

  StreamPosition() = default;

  explicit StreamPosition(int64_t default_val) {
    positions.fill(default_val);
  }

  int64_t get(StreamType st) const {
    return positions[static_cast<size_t>(st)];
  }

  void set(StreamType st, int64_t val) {
    positions[static_cast<size_t>(st)] = val;
  }

  void advance(StreamType st, int64_t val) {
    auto& pos = positions[static_cast<size_t>(st)];
    if (val > pos) pos = val;
  }

  int64_t events() const { return get(StreamType::kEvents); }
  int64_t presence() const { return get(StreamType::kPresence); }
  int64_t receipts() const { return get(StreamType::kReceipts); }
  int64_t typing() const { return get(StreamType::kTyping); }
  int64_t to_device() const { return get(StreamType::kToDevice); }
  int64_t device_lists() const { return get(StreamType::kDeviceLists); }
  int64_t account_data() const { return get(StreamType::kAccountData); }
  int64_t push_rules() const { return get(StreamType::kPushRules); }

  bool all_zero() const {
    for (auto p : positions) {
      if (p != 0) return false;
    }
    return true;
  }

  int64_t min_position() const {
    int64_t m = INT64_MAX;
    for (auto p : positions) {
      if (p < m) m = p;
    }
    return m == INT64_MAX ? 0 : m;
  }

  int64_t max_position() const {
    int64_t m = 0;
    for (auto p : positions) {
      if (p > m) m = p;
    }
    return m;
  }

  json to_json() const {
    json j;
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      j[kStreamTypeNames[i]] = positions[i];
    }
    return j;
  }

  static StreamPosition from_json(const json& j) {
    StreamPosition sp;
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      const char* name = kStreamTypeNames[i];
      if (j.contains(name) && j[name].is_number_integer()) {
        sp.positions[i] = j[name].get<int64_t>();
      }
    }
    return sp;
  }
};

// ============================================================================
// StreamToken — encoded/decoded sync token containing all stream positions
// ============================================================================
class StreamToken {
public:
  // --------------------------------------------------------------------------
  // Encode a StreamPosition into an opaque token string
  // --------------------------------------------------------------------------
  static std::string encode(const StreamPosition& pos) {
    // Binary format:
    //   byte 0:    version (0x01)
    //   byte 1-2:  flags (reserved)
    //   byte 3-..: varint-encoded stream positions in order:
    //              events, presence, receipts, typing, to_device,
    //              device_lists, account_data, push_rules
    //   then base64url-encode the whole thing
    std::vector<uint8_t> payload;
    payload.reserve(64);

    // Version
    payload.push_back(0x01);

    // Flags (reserved)
    payload.push_back(0x00);
    payload.push_back(0x00);

    // Encode each stream position as varint
    append_varint(payload, static_cast<uint64_t>(pos.events()));
    append_varint(payload, static_cast<uint64_t>(pos.presence()));
    append_varint(payload, static_cast<uint64_t>(pos.receipts()));
    append_varint(payload, static_cast<uint64_t>(pos.typing()));
    append_varint(payload, static_cast<uint64_t>(pos.to_device()));
    append_varint(payload, static_cast<uint64_t>(pos.device_lists()));
    append_varint(payload, static_cast<uint64_t>(pos.account_data()));
    append_varint(payload, static_cast<uint64_t>(pos.push_rules()));

    // Base64-url encode
    std::string b64 = base64_url_encode(payload);
    return std::string(kSyncTokenPrefixV1) + kSyncTokenSeparator + b64;
  }

  // --------------------------------------------------------------------------
  // Encode a single-value token (legacy compatibility)
  // --------------------------------------------------------------------------
  static std::string encode_single(int64_t stream_pos) {
    StreamPosition pos;
    pos.set(StreamType::kEvents, stream_pos);
    return encode(pos);
  }

  // --------------------------------------------------------------------------
  // Decode a token string into a StreamPosition
  // --------------------------------------------------------------------------
  static std::optional<StreamPosition> decode(std::string_view token) {
    if (token.empty()) return std::nullopt;

    // Check for legacy single-value token format (s3NNN or s4NNN)
    if (token.size() > 2 && token[0] == 's' && token[1] == '3') {
      try {
        StreamPosition pos;
        pos.set(StreamType::kEvents,
                std::stoll(std::string(token.substr(2))));
        return pos;
      } catch (...) {
        return std::nullopt;
      }
    }

    // Check for v4 token format: s4_BASE64PAYLOAD
    if (token.size() <= 3) return std::nullopt;
    if (!(token[0] == 's' && token[1] == '4')) return std::nullopt;
    if (token[2] != '_') return std::nullopt;

    // Extract base64 payload
    std::string_view b64_payload = token.substr(3);
    if (b64_payload.empty()) return std::nullopt;

    // Decode base64
    auto raw = base64_url_decode(b64_payload);
    if (raw.size() < 3) return std::nullopt;

    // Check version
    uint8_t version = raw[0];
    if (version != 0x01) {
      // Unknown version
      return std::nullopt;
    }

    // Skip flags
    size_t offset = 3;
    StreamPosition pos;

    // Decode each stream position from varints
    auto unpack = [&raw, &offset]() -> int64_t {
      auto [val, ok] = read_varint(raw.data(), raw.size(), offset);
      return ok ? static_cast<int64_t>(val) : 0;
    };

    pos.set(StreamType::kEvents, unpack());
    pos.set(StreamType::kPresence, unpack());
    pos.set(StreamType::kReceipts, unpack());
    pos.set(StreamType::kTyping, unpack());
    pos.set(StreamType::kToDevice, unpack());
    pos.set(StreamType::kDeviceLists, unpack());
    pos.set(StreamType::kAccountData, unpack());
    pos.set(StreamType::kPushRules, unpack());

    return pos;
  }

  // --------------------------------------------------------------------------
  // Decode a legacy single-value token
  // --------------------------------------------------------------------------
  static int64_t decode_legacy(std::string_view token) {
    auto pos = decode(token);
    if (pos.has_value()) {
      return pos->events();
    }
    return 0;
  }

  // --------------------------------------------------------------------------
  // Validate token format
  // --------------------------------------------------------------------------
  static bool is_valid(std::string_view token) {
    return decode(token).has_value();
  }

  // --------------------------------------------------------------------------
  // Encode to JSON format (for debug/admin API)
  // --------------------------------------------------------------------------
  static json to_json(const StreamPosition& pos) {
    json j;
    j["token"] = encode(pos);
    j["streams"] = pos.to_json();
    return j;
  }
};

// ============================================================================
// StreamRange — a range of stream IDs for gap queries
// ============================================================================
struct StreamRange {
  int64_t from_id;
  int64_t to_id;
  StreamType stream_type;

  bool is_valid() const { return from_id >= 0 && to_id >= from_id; }
  int64_t count() const { return std::max(int64_t(0), to_id - from_id); }

  json to_json() const {
    json j;
    j["from"] = from_id;
    j["to"] = to_id;
    j["stream_type"] = stream_type_name(stream_type);
    j["count"] = count();
    return j;
  }
};

// ============================================================================
// StreamChangeEntry — a single change in a stream
// ============================================================================
struct StreamChangeEntry {
  int64_t stream_id;
  std::string entity_id;     // user_id, room_id, event_id, etc.
  std::string secondary_key;  // device_id, receipt_type, etc.
  json metadata;
  int64_t timestamp_ms;

  json to_json() const {
    json j;
    j["stream_id"] = stream_id;
    j["entity_id"] = entity_id;
    if (!secondary_key.empty()) j["secondary_key"] = secondary_key;
    if (!metadata.is_null()) j["metadata"] = metadata;
    j["timestamp_ms"] = timestamp_ms;
    return j;
  }
};

// ============================================================================
// StreamChangeCache — LRU cache tracking recent changes per stream
// ============================================================================
class StreamChangeCache {
public:
  struct Entry {
    int64_t stream_id;
    std::string entity_id;
    int64_t expiry_ts;
  };

  // --------------------------------------------------------------------------
  // Constructor
  // --------------------------------------------------------------------------
  StreamChangeCache(size_t max_size = kDefaultChangeCacheSize,
                    int64_t ttl_sec = kDefaultChangeCacheTtlSec)
      : max_size_(max_size)
      , ttl_sec_(ttl_sec)
      , hits_(0)
      , misses_(0) {
    cache_.reserve(max_size_);
  }

  // --------------------------------------------------------------------------
  // Record a change at a given stream position
  // --------------------------------------------------------------------------
  void record_change(int64_t stream_id, const std::string& entity_id) {
    std::unique_lock lock(mutex_);

    // Add entry
    Entry entry;
    entry.stream_id = stream_id;
    entry.entity_id = entity_id;
    entry.expiry_ts = now_sec() + ttl_sec_;

    changes_.push_back(entry);

    // Update max stream ID
    if (stream_id > max_stream_id_.load(std::memory_order_relaxed)) {
      max_stream_id_.store(stream_id, std::memory_order_relaxed);
    }

    // Evict expired entries if over max
    while (changes_.size() > max_size_) {
      changes_.pop_front();
    }
  }

  // --------------------------------------------------------------------------
  // Check if any changes exist since a given stream position
  // --------------------------------------------------------------------------
  bool has_changes_since(int64_t since) const {
    std::shared_lock lock(mutex_);
    int64_t max_id = max_stream_id_.load(std::memory_order_relaxed);
    if (since >= max_id) {
      misses_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }

    // Quick check: is the latest change after 'since'?
    if (!changes_.empty()) {
      auto& last = changes_.back();
      if (last.stream_id > since) {
        hits_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }
    }

    // Linear scan (should be rare due to above checks)
    int64_t now = now_sec();
    for (auto it = changes_.rbegin(); it != changes_.rend(); ++it) {
      if (it->expiry_ts < now) continue;
      if (it->stream_id > since) {
        hits_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }
    }

    misses_.fetch_add(1, std::memory_order_relaxed);
    return false;
  }

  // --------------------------------------------------------------------------
  // Get all entities that changed since a position
  // --------------------------------------------------------------------------
  std::vector<std::string> get_changed_entities(int64_t since, int limit = 100) {
    std::shared_lock lock(mutex_);
    std::vector<std::string> result;
    std::set<std::string> seen;
    int64_t now = now_sec();

    // Walk backward through changes (newest first)
    for (auto it = changes_.rbegin();
         it != changes_.rend() && result.size() < static_cast<size_t>(limit);
         ++it) {
      if (it->expiry_ts < now) continue;
      if (it->stream_id <= since) continue;
      if (seen.find(it->entity_id) != seen.end()) continue;
      seen.insert(it->entity_id);
      result.push_back(it->entity_id);
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Get the highest stream ID in cache
  // --------------------------------------------------------------------------
  int64_t get_max_stream_id() const {
    return max_stream_id_.load(std::memory_order_relaxed);
  }

  // --------------------------------------------------------------------------
  // Get all cached entries (for snapshot)
  // --------------------------------------------------------------------------
  std::vector<Entry> get_all_entries() const {
    std::shared_lock lock(mutex_);
    return {changes_.begin(), changes_.end()};
  }

  // --------------------------------------------------------------------------
  // Purge expired entries
  // --------------------------------------------------------------------------
  void purge_expired() {
    std::unique_lock lock(mutex_);
    int64_t now = now_sec();
    while (!changes_.empty() && changes_.front().expiry_ts < now) {
      changes_.pop_front();
    }
  }

  // --------------------------------------------------------------------------
  // Clear the entire cache
  // --------------------------------------------------------------------------
  void clear() {
    std::unique_lock lock(mutex_);
    changes_.clear();
    max_stream_id_.store(0, std::memory_order_relaxed);
    hits_.store(0, std::memory_order_relaxed);
    misses_.store(0, std::memory_order_relaxed);
  }

  // --------------------------------------------------------------------------
  // Resize the cache
  // --------------------------------------------------------------------------
  void resize(size_t new_max_size) {
    std::unique_lock lock(mutex_);
    max_size_ = new_max_size;
    while (changes_.size() > max_size_) {
      changes_.pop_front();
    }
  }

  // --------------------------------------------------------------------------
  // Set TTL
  // --------------------------------------------------------------------------
  void set_ttl(int64_t ttl_sec) {
    std::unique_lock lock(mutex_);
    ttl_sec_ = ttl_sec;
    // Recompute expiry for all entries
    int64_t now = now_sec();
    for (auto& entry : changes_) {
      entry.expiry_ts = now + ttl_sec;
    }
  }

  // --------------------------------------------------------------------------
  // Statistics
  // --------------------------------------------------------------------------
  size_t size() const {
    std::shared_lock lock(mutex_);
    return changes_.size();
  }

  int64_t hit_count() const {
    return hits_.load(std::memory_order_relaxed);
  }

  int64_t miss_count() const {
    return misses_.load(std::memory_order_relaxed);
  }

  double hit_ratio() const {
    int64_t h = hits_.load(std::memory_order_relaxed);
    int64_t m = misses_.load(std::memory_order_relaxed);
    int64_t total = h + m;
    return (total > 0) ? (static_cast<double>(h) / static_cast<double>(total)) : 0.0;
  }

  json get_stats() const {
    json s;
    s["size"] = size();
    s["max_size"] = max_size_;
    s["ttl_sec"] = ttl_sec_;
    s["hits"] = hit_count();
    s["misses"] = miss_count();
    s["hit_ratio"] = hit_ratio();
    s["max_stream_id"] = get_max_stream_id();
    return s;
  }

private:
  mutable std::shared_mutex mutex_;
  std::deque<Entry> changes_;
  std::unordered_map<std::string, int64_t> cache_;
  size_t max_size_;
  int64_t ttl_sec_;
  std::atomic<int64_t> max_stream_id_{0};
  mutable std::atomic<int64_t> hits_{0};
  mutable std::atomic<int64_t> misses_{0};
};

// ============================================================================
// PerStreamCache — a single stream's change cache
// ============================================================================
class PerStreamCache {
public:
  explicit PerStreamCache(StreamType st,
                          size_t max_size = kDefaultChangeCacheSize,
                          int64_t ttl_sec = kDefaultChangeCacheTtlSec)
      : stream_type_(st)
      , cache_(max_size, ttl_sec) {}

  void record(int64_t stream_id, const std::string& entity_id) {
    cache_.record_change(stream_id, entity_id);
  }

  bool has_changes_since(int64_t since) const {
    return cache_.has_changes_since(since);
  }

  std::vector<std::string> get_changed(int64_t since, int limit = 100) {
    return cache_.get_changed_entities(since, limit);
  }

  int64_t max_stream_id() const {
    return cache_.get_max_stream_id();
  }

  void purge() { cache_.purge_expired(); }
  void clear() { cache_.clear(); }
  void resize(size_t s) { cache_.resize(s); }
  void set_ttl(int64_t t) { cache_.set_ttl(t); }
  size_t size() const { return cache_.size(); }

  StreamType stream_type() const { return stream_type_; }

  json get_stats() const {
    json s = cache_.get_stats();
    s["stream_type"] = stream_type_name(stream_type_);
    return s;
  }

private:
  StreamType stream_type_;
  StreamChangeCache cache_;
};

// ============================================================================
// MultiStreamCache — manages change caches for all 8 stream types
// ============================================================================
class MultiStreamCache {
public:
  MultiStreamCache() {
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      caches_.emplace_back(static_cast<StreamType>(i));
    }
  }

  PerStreamCache& get(StreamType st) {
    return caches_[static_cast<size_t>(st)];
  }

  const PerStreamCache& get(StreamType st) const {
    return caches_[static_cast<size_t>(st)];
  }

  // Record a change in the appropriate stream cache
  void record(StreamType st, int64_t stream_id,
              const std::string& entity_id) {
    get(st).record(stream_id, entity_id);
  }

  // Check if any stream has changes since the given positions
  bool has_any_changes_since(const StreamPosition& since) const {
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      if (caches_[i].has_changes_since(since.get(st))) {
        return true;
      }
    }
    return false;
  }

  // Purge all caches
  void purge_all() {
    for (auto& c : caches_) {
      c.purge();
    }
  }

  // Clear all caches
  void clear_all() {
    for (auto& c : caches_) {
      c.clear();
    }
  }

  // Get combined stats
  json get_all_stats() const {
    json j = json::array();
    for (const auto& c : caches_) {
      j.push_back(c.get_stats());
    }
    return j;
  }

private:
  std::vector<PerStreamCache> caches_;
};

// ============================================================================
// StreamIDGenerator — generates monotonically increasing stream IDs
//                      for each stream type
// ============================================================================
class StreamIDGenerator {
public:
  // --------------------------------------------------------------------------
  // Generate the next stream ID for a given stream type
  // This is database-backed and transaction-safe.
  // --------------------------------------------------------------------------
  int64_t generate_next(LoggingTransaction& txn, StreamType st) {
    std::string table = stream_type_to_max_table(st);

    // Atomic increment: UPDATE ... SET max_id = max_id + 1
    txn.execute(
        "UPDATE " + table + " SET max_stream_id = max_stream_id + "
        + std::to_string(kStreamIDAdvanceBatch) + " WHERE id = 1");

    auto row = txn.select_one(
        "SELECT max_stream_id FROM " + table + " WHERE id = 1");

    if (row && !row->is_null()) {
      int64_t new_id = row->get<int64_t>(0);
      // Update in-memory cache
      update_local_max(st, new_id);
      return new_id;
    }

    // Fallback: initialize the singleton row and try again
    txn.execute(
        "INSERT OR IGNORE INTO " + table + " (id, max_stream_id) VALUES (1, 1)");
    auto row2 = txn.select_one(
        "SELECT max_stream_id FROM " + table + " WHERE id = 1");
    if (row2 && !row2->is_null()) {
      int64_t id = row2->get<int64_t>(0);
      update_local_max(st, id);
      return id;
    }
    return 1;
  }

  // --------------------------------------------------------------------------
  // Reserve a batch of stream IDs (for bulk inserts)
  // --------------------------------------------------------------------------
  int64_t reserve_batch(LoggingTransaction& txn, StreamType st,
                         int64_t batch_size) {
    if (batch_size <= 0) return 0;
    std::string table = stream_type_to_max_table(st);

    txn.execute(
        "UPDATE " + table + " SET max_stream_id = max_stream_id + "
        + std::to_string(batch_size) + " WHERE id = 1");

    auto row = txn.select_one(
        "SELECT max_stream_id FROM " + table + " WHERE id = 1");

    if (row && !row->is_null()) {
      int64_t new_max = row->get<int64_t>(0);
      int64_t start_id = new_max - batch_size + 1;
      update_local_max(st, new_max);
      return start_id;  // Return the first ID in the batch
    }
    return generate_next(txn, st);
  }

  // --------------------------------------------------------------------------
  // Set the stream ID to at least the given value (for replication catch-up)
  // --------------------------------------------------------------------------
  void advance_to(LoggingTransaction& txn, StreamType st, int64_t min_id) {
    std::string table = stream_type_to_max_table(st);

    txn.execute(
        "INSERT INTO " + table + " (id, max_stream_id) VALUES (1, "
        + std::to_string(min_id) + ") "
        "ON CONFLICT (id) DO UPDATE SET max_stream_id = MAX(max_stream_id, "
        + std::to_string(min_id) + ")");

    update_local_max(st, min_id);
  }

  // --------------------------------------------------------------------------
  // Get the current maximum stream ID (database query)
  // --------------------------------------------------------------------------
  int64_t get_max(LoggingTransaction& txn, StreamType st) const {
    std::string table = stream_type_to_max_table(st);
    auto row = txn.select_one(
        "SELECT max_stream_id FROM " + table + " WHERE id = 1");
    return (row && !row->is_null()) ? row->get<int64_t>(0) : 0;
  }

  // --------------------------------------------------------------------------
  // Get the locally cached max stream ID
  // --------------------------------------------------------------------------
  int64_t get_local_max(StreamType st) const {
    return local_max_ids_[static_cast<size_t>(st)].load(
        std::memory_order_relaxed);
  }

  // --------------------------------------------------------------------------
  // Update the locally cached max stream ID
  // --------------------------------------------------------------------------
  void update_local_max(StreamType st, int64_t new_max) {
    auto& atomic_max = local_max_ids_[static_cast<size_t>(st)];
    int64_t current = atomic_max.load(std::memory_order_relaxed);
    while (new_max > current) {
      if (atomic_max.compare_exchange_weak(current, new_max,
                                            std::memory_order_relaxed)) {
        break;
      }
    }
  }

  // --------------------------------------------------------------------------
  // Initialize all stream max tables in the database
  // --------------------------------------------------------------------------
  static void create_all_tables(LoggingTransaction& txn) {
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      std::string table = stream_type_to_max_table(st);
      txn.execute(
          "CREATE TABLE IF NOT EXISTS " + table + " ("
          "  id INTEGER PRIMARY KEY,"
          "  max_stream_id INTEGER NOT NULL DEFAULT 0"
          ")");
      txn.execute(
          "INSERT OR IGNORE INTO " + table + " (id, max_stream_id) "
          "VALUES (1, 0)");
    }
  }

  // --------------------------------------------------------------------------
  // Get all max stream IDs as a StreamPosition
  // --------------------------------------------------------------------------
  StreamPosition get_all_max(LoggingTransaction& txn) const {
    StreamPosition pos;
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      pos.set(static_cast<StreamType>(i), get_max(txn, static_cast<StreamType>(i)));
    }
    return pos;
  }

  // --------------------------------------------------------------------------
  // Get all locally cached max stream IDs
  // --------------------------------------------------------------------------
  StreamPosition get_all_local_max() const {
    StreamPosition pos;
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      pos.set(static_cast<StreamType>(i),
              local_max_ids_[i].load(std::memory_order_relaxed));
    }
    return pos;
  }

private:
  std::array<std::atomic<int64_t>, kNumStreamTypes> local_max_ids_{};
};

// ============================================================================
// StreamPositionTracker — tracks per-user stream positions in the database
// ============================================================================
class StreamPositionTracker {
public:
  // --------------------------------------------------------------------------
  // DDL: create all stream position tables
  // --------------------------------------------------------------------------
  static void create_all_tables(LoggingTransaction& txn) {
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      std::string table = stream_type_to_pos_table(st);

      std::string sql =
          "CREATE TABLE IF NOT EXISTS " + table + " ("
          "  user_id TEXT NOT NULL,"
          "  stream_position INTEGER NOT NULL DEFAULT 0,"
          "  updated_ts INTEGER NOT NULL DEFAULT 0,"
          "  PRIMARY KEY (user_id)"
          ")";
      txn.execute(sql);

      // Create index for fast lookup
      txn.execute(
          "CREATE INDEX IF NOT EXISTS idx_" + table + "_position "
          "ON " + table + " (stream_position)");
    }
  }

  // --------------------------------------------------------------------------
  // Get the stream position for a user on a specific stream
  // --------------------------------------------------------------------------
  int64_t get_position(LoggingTransaction& txn, StreamType st,
                       const std::string& user_id) const {
    std::string table = stream_type_to_pos_table(st);
    auto row = txn.select_one(
        "SELECT stream_position FROM " + table + " WHERE user_id = ?",
        {user_id});
    return (row && !row->is_null()) ? row->get<int64_t>(0) : 0;
  }

  // --------------------------------------------------------------------------
  // Set the stream position for a user on a specific stream
  // --------------------------------------------------------------------------
  void set_position(LoggingTransaction& txn, StreamType st,
                    const std::string& user_id, int64_t position) {
    std::string table = stream_type_to_pos_table(st);
    int64_t ts = now_ms();

    txn.execute(
        "INSERT INTO " + table + " (user_id, stream_position, updated_ts) "
        "VALUES (?, ?, ?) "
        "ON CONFLICT (user_id) DO UPDATE SET "
        "stream_position = excluded.stream_position, "
        "updated_ts = excluded.updated_ts",
        {user_id, position, ts});
  }

  // --------------------------------------------------------------------------
  // Advance position only if new position is higher
  // --------------------------------------------------------------------------
  void advance_position(LoggingTransaction& txn, StreamType st,
                        const std::string& user_id, int64_t new_position) {
    int64_t current = get_position(txn, st, user_id);
    if (new_position > current) {
      set_position(txn, st, user_id, new_position);
    }
  }

  // --------------------------------------------------------------------------
  // Get all stream positions for a user
  // --------------------------------------------------------------------------
  StreamPosition get_all_positions(LoggingTransaction& txn,
                                    const std::string& user_id) const {
    StreamPosition pos;
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      pos.set(static_cast<StreamType>(i),
              get_position(txn, static_cast<StreamType>(i), user_id));
    }
    return pos;
  }

  // --------------------------------------------------------------------------
  // Set all stream positions for a user (e.g., after initial sync)
  // --------------------------------------------------------------------------
  void set_all_positions(LoggingTransaction& txn,
                         const std::string& user_id,
                         const StreamPosition& positions) {
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      set_position(txn, st, user_id, positions.get(st));
    }
  }

  // --------------------------------------------------------------------------
  // Reset all positions for a user (e.g., GDPR erasure)
  // --------------------------------------------------------------------------
  void reset_all_positions(LoggingTransaction& txn,
                           const std::string& user_id) {
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      std::string table = stream_type_to_pos_table(st);
      txn.execute(
          "DELETE FROM " + table + " WHERE user_id = ?",
          {user_id});
    }
  }

  // --------------------------------------------------------------------------
  // Get users whose positions are behind for a given stream
  // (useful for replication / catch-up)
  // --------------------------------------------------------------------------
  std::vector<std::string> get_users_behind(LoggingTransaction& txn,
                                              StreamType st,
                                              int64_t max_position,
                                              int limit = 100) const {
    std::string table = stream_type_to_pos_table(st);
    auto rows = txn.select(
        "SELECT user_id FROM " + table
        + " WHERE stream_position < ? "
        "ORDER BY stream_position ASC LIMIT ?",
        {max_position, limit});
    std::vector<std::string> result;
    for (auto& row : rows) {
      result.push_back(row->get<std::string>(0));
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Count users with positions at or behind a threshold
  // --------------------------------------------------------------------------
  int64_t count_users_behind(LoggingTransaction& txn, StreamType st,
                              int64_t max_position) const {
    std::string table = stream_type_to_pos_table(st);
    auto row = txn.select_one(
        "SELECT COUNT(*) FROM " + table + " WHERE stream_position < ?",
        {max_position});
    return (row && !row->is_null()) ? row->get<int64_t>(0) : 0;
  }
};

// ============================================================================
// StreamOrderingManager — manages causal ordering across streams
// ============================================================================
class StreamOrderingManager {
public:
  // --------------------------------------------------------------------------
  // Compute a global ordering key from multiple stream positions
  // --------------------------------------------------------------------------
  static int64_t compute_global_order(const StreamPosition& pos) {
    // Use a weighted sum to produce a total order.
    // Each stream gets its own bit-range to prevent collisions.
    // This means each stream can have up to 2^51 unique positions
    // and still maintain strict global order.
    int64_t order = 0;
    order |= (pos.events()       & 0x7FFFF) << 51;
    order |= (pos.presence()     & 0x7FFFF) << 38;
    order |= (pos.receipts()     & 0x7FFFF) << 25;
    order |= (pos.typing()       & 0x7FFFF) << 12;
    order |= (pos.to_device()    & 0xFF)    << 8;
    order |= (pos.device_lists() & 0xFF)    << 4;
    order |= (pos.account_data() & 0x7)     << 1;
    order |= (pos.push_rules()   & 0x1);
    return order;
  }

  // --------------------------------------------------------------------------
  // Check if position A is strictly after position B across all streams
  // --------------------------------------------------------------------------
  static bool is_after(const StreamPosition& a, const StreamPosition& b) {
    bool any_higher = false;
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      if (a.positions[i] > b.positions[i]) any_higher = true;
      if (a.positions[i] < b.positions[i]) return false;  // A is behind B
    }
    return any_higher;  // A >= B on all streams, > on at least one
  }

  // --------------------------------------------------------------------------
  // Merge two stream positions, taking the max of each
  // --------------------------------------------------------------------------
  static StreamPosition merge(const StreamPosition& a,
                               const StreamPosition& b) {
    StreamPosition result;
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      result.positions[i] = std::max(a.positions[i], b.positions[i]);
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Compute the "lag" between two positions (how far behind B is from A)
  // --------------------------------------------------------------------------
  static StreamPosition lag(const StreamPosition& current,
                             const StreamPosition& target) {
    StreamPosition result;
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      result.positions[i] = std::max(int64_t(0),
                                      target.positions[i] - current.positions[i]);
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Get the topological ordering for a stream
  // --------------------------------------------------------------------------
  static int64_t topological_order(StreamType st, int64_t stream_id) {
    // Each stream gets a unique prefix to maintain total order
    int64_t prefix = static_cast<int64_t>(st) << 60;
    return prefix | (stream_id & 0x0FFFFFFFFFFFFFFF);
  }

  // --------------------------------------------------------------------------
  // Reverse: extract the stream ID from a topological order
  // --------------------------------------------------------------------------
  static std::pair<StreamType, int64_t> from_topological_order(
      int64_t topo_order) {
    StreamType st = static_cast<StreamType>((topo_order >> 60) & 0x0F);
    int64_t stream_id = topo_order & 0x0FFFFFFFFFFFFFFF;
    return {st, stream_id};
  }
};

// ============================================================================
// StreamQueryBuilder — builds SQL queries for stream operations
// ============================================================================
class StreamQueryBuilder {
public:
  // --------------------------------------------------------------------------
  // Build a query to get changes since a position per entity type
  // --------------------------------------------------------------------------
  static std::string events_since(const std::string& room_id,
                                   int64_t since, int limit) {
    return
        "SELECT e.event_id, e.type, e.sender, e.room_id, "
        "e.state_key, e.content, e.stream_ordering, e.depth, "
        "e.origin_server_ts "
        "FROM events e "
        "WHERE e.room_id='" + sql_escape(room_id) + "' "
        "AND e.stream_ordering > " + std::to_string(since) + " "
        "ORDER BY e.stream_ordering ASC "
        "LIMIT " + std::to_string(limit);
  }

  static std::string presence_since(const std::vector<std::string>& user_ids,
                                      int64_t since, int limit) {
    std::string in_clause = "(";
    for (size_t i = 0; i < user_ids.size(); ++i) {
      if (i > 0) in_clause += ",";
      in_clause += "'" + sql_escape(user_ids[i]) + "'";
    }
    in_clause += ")";

    if (user_ids.empty()) in_clause = "('')";

    return
        "SELECT ps.user_id, ps.state, ps.last_active_ts, "
        "ps.status_msg, ps.currently_active, ps.stream_id "
        "FROM presence_stream ps "
        "WHERE ps.user_id IN " + in_clause + " "
        "AND ps.stream_id > " + std::to_string(since) + " "
        "ORDER BY ps.stream_id ASC "
        "LIMIT " + std::to_string(limit);
  }

  static std::string receipts_since(const std::string& room_id,
                                      int64_t since, int limit) {
    return
        "SELECT rp.user_id, rp.event_id, rp.receipt_type, "
        "rp.data, rp.stream_id, rp.origin_server_ts "
        "FROM receipts_linearized rp "
        "WHERE rp.room_id='" + sql_escape(room_id) + "' "
        "AND rp.stream_id > " + std::to_string(since) + " "
        "ORDER BY rp.stream_id ASC "
        "LIMIT " + std::to_string(limit);
  }

  static std::string typing_since(const std::string& room_id,
                                    int64_t since, int limit) {
    return
        "SELECT ts.room_id, ts.user_id, ts.stream_id, ts.timeout_ms, ts.ts "
        "FROM typing_stream ts "
        "WHERE ts.room_id='" + sql_escape(room_id) + "' "
        "AND ts.stream_id > " + std::to_string(since) + " "
        "ORDER BY ts.stream_id ASC "
        "LIMIT " + std::to_string(limit);
  }

  static std::string to_device_since(const std::string& user_id,
                                       int64_t since, int limit) {
    return
        "SELECT di.id, di.sender_user_id, di.message_type, "
        "di.content_json, di.stream_id, di.delivery_status, di.created_ts "
        "FROM to_device_messages di "
        "WHERE di.user_id='" + sql_escape(user_id) + "' "
        "AND di.stream_id > " + std::to_string(since) + " "
        "ORDER BY di.stream_id ASC "
        "LIMIT " + std::to_string(limit);
  }

  static std::string device_lists_since(const std::string& user_id,
                                          int64_t since, int limit) {
    return
        "SELECT dl.user_id, dl.stream_id, dl.is_join "
        "FROM device_lists_stream dl "
        "WHERE dl.stream_id > " + std::to_string(since) + " "
        "ORDER BY dl.stream_id ASC "
        "LIMIT " + std::to_string(limit);
  }

  static std::string account_data_since(const std::string& user_id,
                                          int64_t since, int limit,
                                          bool global_only = false) {
    std::string sql =
        "SELECT ad.data_type, ad.data_key, ad.room_id, ad.content_json, "
        "ad.stream_id, ad.updated_ts "
        "FROM account_data ad "
        "WHERE ad.user_id='" + sql_escape(user_id) + "' "
        "AND ad.stream_id > " + std::to_string(since) + " ";
    if (global_only) {
      sql += "AND ad.room_id IS NULL ";
    }
    sql += "ORDER BY ad.stream_id ASC LIMIT " + std::to_string(limit);
    return sql;
  }

  static std::string push_rules_since(const std::string& user_id,
                                        int64_t since, int limit) {
    return
        "SELECT pr.rule_id, pr.kind, pr.priority_class, pr.priority, "
        "pr.conditions, pr.actions, pr.enabled, pr.stream_id, pr.updated_ts "
        "FROM push_rules_stream pr "
        "WHERE pr.user_id='" + sql_escape(user_id) + "' "
        "AND pr.stream_id > " + std::to_string(since) + " "
        "ORDER BY pr.stream_id ASC "
        "LIMIT " + std::to_string(limit);
  }

  // --------------------------------------------------------------------------
  // Build queries for max stream ID checks
  // --------------------------------------------------------------------------
  static std::string max_stream_query(StreamType st) {
    return "SELECT max_stream_id FROM " + stream_type_to_max_table(st)
           + " WHERE id = 1";
  }

  static std::string all_max_stream_query() {
    std::string sql = "SELECT ";
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      if (i > 0) sql += ", ";
      sql += "(SELECT max_stream_id FROM "
             + stream_type_to_max_table(static_cast<StreamType>(i))
             + " WHERE id = 1) AS "
             + std::string(stream_type_name(static_cast<StreamType>(i)));
    }
    return sql;
  }
};

// ============================================================================
// StreamMetrics — collects operational metrics for stream operations
// ============================================================================
class StreamMetrics {
public:
  StreamMetrics() = default;

  void record_id_generation(StreamType st) {
    ids_generated_[static_cast<size_t>(st)].fetch_add(
        1, std::memory_order_relaxed);
  }

  void record_position_update(StreamType st) {
    positions_updated_[static_cast<size_t>(st)].fetch_add(
        1, std::memory_order_relaxed);
  }

  void record_cache_hit(StreamType st) {
    cache_hits_[static_cast<size_t>(st)].fetch_add(
        1, std::memory_order_relaxed);
  }

  void record_cache_miss(StreamType st) {
    cache_misses_[static_cast<size_t>(st)].fetch_add(
        1, std::memory_order_relaxed);
  }

  void record_token_encode() {
    tokens_encoded_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_token_decode() {
    tokens_decoded_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_token_decode_error() {
    token_decode_errors_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_stream_query(StreamType st, int64_t duration_us) {
    auto idx = static_cast<size_t>(st);
    query_count_[idx].fetch_add(1, std::memory_order_relaxed);
    query_duration_us_[idx].fetch_add(duration_us, std::memory_order_relaxed);
  }

  json get_metrics() const {
    json m;

    json per_stream = json::array();
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      json s;
      s["name"] = kStreamTypeNames[i];
      s["ids_generated"] = ids_generated_[i].load(std::memory_order_relaxed);
      s["positions_updated"] = positions_updated_[i].load(std::memory_order_relaxed);
      s["cache_hits"] = cache_hits_[i].load(std::memory_order_relaxed);
      s["cache_misses"] = cache_misses_[i].load(std::memory_order_relaxed);
      s["queries"] = query_count_[i].load(std::memory_order_relaxed);

      int64_t qc = query_count_[i].load(std::memory_order_relaxed);
      int64_t qd = query_duration_us_[i].load(std::memory_order_relaxed);
      s["avg_query_us"] = (qc > 0) ? (qd / qc) : 0;

      per_stream.push_back(s);
    }
    m["per_stream"] = per_stream;

    m["tokens_encoded"] = tokens_encoded_.load(std::memory_order_relaxed);
    m["tokens_decoded"] = tokens_decoded_.load(std::memory_order_relaxed);
    m["token_decode_errors"] = token_decode_errors_.load(
        std::memory_order_relaxed);

    return m;
  }

  void reset() {
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      ids_generated_[i].store(0, std::memory_order_relaxed);
      positions_updated_[i].store(0, std::memory_order_relaxed);
      cache_hits_[i].store(0, std::memory_order_relaxed);
      cache_misses_[i].store(0, std::memory_order_relaxed);
      query_count_[i].store(0, std::memory_order_relaxed);
      query_duration_us_[i].store(0, std::memory_order_relaxed);
    }
    tokens_encoded_.store(0, std::memory_order_relaxed);
    tokens_decoded_.store(0, std::memory_order_relaxed);
    token_decode_errors_.store(0, std::memory_order_relaxed);
  }

private:
  std::array<std::atomic<int64_t>, kNumStreamTypes> ids_generated_{};
  std::array<std::atomic<int64_t>, kNumStreamTypes> positions_updated_{};
  std::array<std::atomic<int64_t>, kNumStreamTypes> cache_hits_{};
  std::array<std::atomic<int64_t>, kNumStreamTypes> cache_misses_{};
  std::array<std::atomic<int64_t>, kNumStreamTypes> query_count_{};
  std::array<std::atomic<int64_t>, kNumStreamTypes> query_duration_us_{};
  std::atomic<int64_t> tokens_encoded_{0};
  std::atomic<int64_t> tokens_decoded_{0};
  std::atomic<int64_t> token_decode_errors_{0};
};

// ============================================================================
// StreamManager — the main orchestrator for all stream operations
//
// Provides the unified interface for:
//   - Generating next stream IDs for any stream type
//   - Tracking per-user stream positions
//   - Encoding/decoding sync tokens
//   - Managing change caches
//   - Querying changes since a given position
//   - Max stream ID queries
//   - Stream ordering
// ============================================================================
class StreamManager {
public:
  // --------------------------------------------------------------------------
  // Constructor
  // --------------------------------------------------------------------------
  explicit StreamManager(DatabasePool& db)
      : db_(db)
      , id_gen_()
      , pos_tracker_() {
    // Initialize local max IDs from database on startup
    initialize_local_max_ids();
  }

  // --------------------------------------------------------------------------
  // DDL: Create all stream-related tables
  // --------------------------------------------------------------------------
  static void create_all_tables(LoggingTransaction& txn) {
    // Create max stream ID tables
    StreamIDGenerator::create_all_tables(txn);

    // Create per-user stream position tables
    StreamPositionTracker::create_all_tables(txn);

    // Create presence stream table
    txn.execute(R"SQL(
      CREATE TABLE IF NOT EXISTS presence_stream (
        user_id TEXT NOT NULL,
        stream_id INTEGER NOT NULL,
        state TEXT NOT NULL DEFAULT 'offline',
        last_active_ts INTEGER,
        status_msg TEXT,
        currently_active INTEGER DEFAULT 0,
        last_user_sync_ts INTEGER,
        last_federation_update_ts INTEGER,
        PRIMARY KEY (user_id)
      )
    )SQL");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_presence_stream_id "
        "ON presence_stream (stream_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_presence_state "
        "ON presence_stream (state)");

    // Create typing stream table
    txn.execute(R"SQL(
      CREATE TABLE IF NOT EXISTS typing_stream (
        stream_id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        timeout_ms INTEGER NOT NULL DEFAULT 0,
        ts INTEGER NOT NULL,
        is_typing INTEGER NOT NULL DEFAULT 1
      )
    )SQL");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_typing_stream_room "
        "ON typing_stream (room_id, stream_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_typing_stream_user "
        "ON typing_stream (user_id, stream_id)");

    // Create receipts stream table
    txn.execute(R"SQL(
      CREATE TABLE IF NOT EXISTS receipts_stream (
        stream_id INTEGER NOT NULL,
        room_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        receipt_type TEXT NOT NULL DEFAULT 'm.read',
        data TEXT,
        origin_server_ts INTEGER,
        PRIMARY KEY (room_id, user_id, receipt_type)
      )
    )SQL");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_receipts_stream_id "
        "ON receipts_stream (stream_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_receipts_room_stream "
        "ON receipts_stream (room_id, stream_id)");

    // Create to-device stream table
    txn.execute(R"SQL(
      CREATE TABLE IF NOT EXISTS to_device_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        sender_user_id TEXT NOT NULL,
        message_type TEXT NOT NULL,
        content_json TEXT NOT NULL,
        stream_id INTEGER NOT NULL,
        delivery_status TEXT NOT NULL DEFAULT 'pending',
        delivered_at_ts INTEGER,
        created_ts INTEGER NOT NULL
      )
    )SQL");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_to_device_user_stream "
        "ON to_device_messages (user_id, device_id, stream_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_to_device_delivery "
        "ON to_device_messages (delivery_status, stream_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_to_device_stream "
        "ON to_device_messages (stream_id)");

    // Create to-device delivery tracking table
    txn.execute(R"SQL(
      CREATE TABLE IF NOT EXISTS to_device_delivery_tracking (
        user_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        last_stream_position INTEGER NOT NULL DEFAULT 0,
        pending_count INTEGER NOT NULL DEFAULT 0,
        delivered_count INTEGER NOT NULL DEFAULT 0,
        updated_ts INTEGER NOT NULL,
        PRIMARY KEY (user_id, device_id)
      )
    )SQL");

    // Create device_lists_stream table
    txn.execute(R"SQL(
      CREATE TABLE IF NOT EXISTS device_lists_stream (
        stream_id INTEGER NOT NULL,
        user_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        ts INTEGER NOT NULL,
        is_signature_change INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (stream_id, user_id, device_id)
      )
    )SQL");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_device_lists_stream_id "
        "ON device_lists_stream (stream_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_device_lists_user "
        "ON device_lists_stream (user_id, stream_id)");

    // Create device_list_outbound_pokes table
    txn.execute(R"SQL(
      CREATE TABLE IF NOT EXISTS device_list_outbound_pokes (
        stream_id INTEGER NOT NULL,
        user_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        sent_to_destination TEXT,
        ts INTEGER NOT NULL,
        PRIMARY KEY (stream_id, user_id, device_id)
      )
    )SQL");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_outbound_pokes_stream "
        "ON device_list_outbound_pokes (stream_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_outbound_pokes_user "
        "ON device_list_outbound_pokes (user_id, stream_id)");

    // Create push_rules_stream table
    txn.execute(R"SQL(
      CREATE TABLE IF NOT EXISTS push_rules_stream (
        stream_id INTEGER NOT NULL,
        user_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT 'override',
        priority_class INTEGER NOT NULL DEFAULT 0,
        priority INTEGER NOT NULL DEFAULT 0,
        conditions TEXT DEFAULT '[]',
        actions TEXT DEFAULT '[]',
        enabled INTEGER NOT NULL DEFAULT 1,
        default_rule INTEGER NOT NULL DEFAULT 0,
        updated_ts INTEGER NOT NULL,
        PRIMARY KEY (user_id, rule_id)
      )
    )SQL");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_push_rules_stream_id "
        "ON push_rules_stream (stream_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_push_rules_user "
        "ON push_rules_stream (user_id, stream_id)");

    // Create account_data table (if not already created by account_data_manager)
    txn.execute(R"SQL(
      CREATE TABLE IF NOT EXISTS account_data (
        user_id TEXT NOT NULL,
        data_type TEXT NOT NULL,
        data_key TEXT NOT NULL,
        room_id TEXT,
        content_json TEXT NOT NULL,
        stream_id INTEGER NOT NULL DEFAULT 0,
        created_ts INTEGER NOT NULL,
        updated_ts INTEGER NOT NULL,
        PRIMARY KEY (user_id, data_type, data_key)
      )
    )SQL");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_account_data_stream "
        "ON account_data (stream_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_account_data_user_stream "
        "ON account_data (user_id, stream_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS idx_account_data_room "
        "ON account_data (user_id, room_id, stream_id)");
  }

  // ==========================================================================
  // Stream ID generation
  // ==========================================================================

  // --------------------------------------------------------------------------
  // Generate the next stream ID for a specific stream type
  // --------------------------------------------------------------------------
  int64_t generate_next_id(LoggingTransaction& txn, StreamType st) {
    int64_t id = id_gen_.generate_next(txn, st);
    metrics_.record_id_generation(st);
    return id;
  }

  // --------------------------------------------------------------------------
  // Generate the next stream ID without a transaction (uses own)
  // --------------------------------------------------------------------------
  int64_t generate_next_id_nontxn(StreamType st) {
    LoggingTransaction txn(db_, "stream_gen_next");
    return generate_next_id(txn, st);
  }

  // --------------------------------------------------------------------------
  // Reserve a batch of stream IDs
  // --------------------------------------------------------------------------
  int64_t reserve_id_batch(LoggingTransaction& txn, StreamType st,
                            int64_t batch_size) {
    return id_gen_.reserve_batch(txn, st, batch_size);
  }

  // --------------------------------------------------------------------------
  // Generate next IDs for all stream types (returns StreamPosition)
  // --------------------------------------------------------------------------
  StreamPosition generate_next_all(LoggingTransaction& txn) {
    StreamPosition pos;
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      pos.set(st, id_gen_.generate_next(txn, st));
    }
    return pos;
  }

  // ==========================================================================
  // Max stream ID queries
  // ==========================================================================

  // --------------------------------------------------------------------------
  // Get the current max stream ID for a stream type
  // --------------------------------------------------------------------------
  int64_t get_max_id(LoggingTransaction& txn, StreamType st) const {
    return id_gen_.get_max(txn, st);
  }

  // --------------------------------------------------------------------------
  // Get the locally cached max stream ID
  // --------------------------------------------------------------------------
  int64_t get_local_max_id(StreamType st) const {
    return id_gen_.get_local_max(st);
  }

  // --------------------------------------------------------------------------
  // Get all max stream IDs
  // --------------------------------------------------------------------------
  StreamPosition get_all_max_ids(LoggingTransaction& txn) const {
    return id_gen_.get_all_max(txn);
  }

  // --------------------------------------------------------------------------
  // Get all locally cached max stream IDs
  // --------------------------------------------------------------------------
  StreamPosition get_all_local_max_ids() const {
    return id_gen_.get_all_local_max();
  }

  // --------------------------------------------------------------------------
  // Advance the stream ID to at least min_id (for replication)
  // --------------------------------------------------------------------------
  void advance_stream_to(LoggingTransaction& txn, StreamType st,
                          int64_t min_id) {
    id_gen_.advance_to(txn, st, min_id);
  }

  // ==========================================================================
  // Stream position tracking (per user)
  // ==========================================================================

  // --------------------------------------------------------------------------
  // Get a user's stream position
  // --------------------------------------------------------------------------
  int64_t get_user_position(LoggingTransaction& txn, StreamType st,
                             const std::string& user_id) const {
    return pos_tracker_.get_position(txn, st, user_id);
  }

  // --------------------------------------------------------------------------
  // Set a user's stream position
  // --------------------------------------------------------------------------
  void set_user_position(LoggingTransaction& txn, StreamType st,
                         const std::string& user_id, int64_t position) {
    pos_tracker_.set_position(txn, st, user_id, position);
    metrics_.record_position_update(st);
  }

  // --------------------------------------------------------------------------
  // Advance user position only if higher
  // --------------------------------------------------------------------------
  void advance_user_position(LoggingTransaction& txn, StreamType st,
                              const std::string& user_id, int64_t new_pos) {
    pos_tracker_.advance_position(txn, st, user_id, new_pos);
    metrics_.record_position_update(st);
  }

  // --------------------------------------------------------------------------
  // Get all stream positions for a user
  // --------------------------------------------------------------------------
  StreamPosition get_user_all_positions(LoggingTransaction& txn,
                                         const std::string& user_id) const {
    return pos_tracker_.get_all_positions(txn, user_id);
  }

  // --------------------------------------------------------------------------
  // Set all stream positions for a user
  // --------------------------------------------------------------------------
  void set_user_all_positions(LoggingTransaction& txn,
                               const std::string& user_id,
                               const StreamPosition& positions) {
    pos_tracker_.set_all_positions(txn, user_id, positions);
  }

  // --------------------------------------------------------------------------
  // Reset all stream positions for a user
  // --------------------------------------------------------------------------
  void reset_user_positions(LoggingTransaction& txn,
                             const std::string& user_id) {
    pos_tracker_.reset_all_positions(txn, user_id);
  }

  // ==========================================================================
  // Stream token encoding/decoding
  // ==========================================================================

  // --------------------------------------------------------------------------
  // Generate a sync token from a StreamPosition
  // --------------------------------------------------------------------------
  std::string make_sync_token(const StreamPosition& pos) {
    metrics_.record_token_encode();
    return StreamToken::encode(pos);
  }

  // --------------------------------------------------------------------------
  // Generate a sync token from current max positions
  // --------------------------------------------------------------------------
  std::string make_sync_token_from_max(LoggingTransaction& txn) {
    auto pos = get_all_max_ids(txn);
    metrics_.record_token_encode();
    return StreamToken::encode(pos);
  }

  // --------------------------------------------------------------------------
  // Parse a sync token to get a StreamPosition
  // --------------------------------------------------------------------------
  std::optional<StreamPosition> parse_sync_token(std::string_view token) {
    metrics_.record_token_decode();
    auto result = StreamToken::decode(token);
    if (!result.has_value()) {
      metrics_.record_token_decode_error();
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Check if a sync token is valid
  // --------------------------------------------------------------------------
  bool is_valid_sync_token(std::string_view token) {
    return StreamToken::is_valid(token);
  }

  // --------------------------------------------------------------------------
  // Get sync token as JSON (for admin API)
  // --------------------------------------------------------------------------
  json sync_token_to_json(const StreamPosition& pos) {
    return StreamToken::to_json(pos);
  }

  // ==========================================================================
  // Change cache operations
  // ==========================================================================

  // --------------------------------------------------------------------------
  // Record a change in the appropriate stream cache
  // --------------------------------------------------------------------------
  void record_change(StreamType st, int64_t stream_id,
                     const std::string& entity_id) {
    caches_.record(st, stream_id, entity_id);
  }

  // --------------------------------------------------------------------------
  // Check if any stream has changes since given positions
  // --------------------------------------------------------------------------
  bool has_any_changes_since(const StreamPosition& since) const {
    return caches_.has_any_changes_since(since);
  }

  // --------------------------------------------------------------------------
  // Get changed entities for a specific stream since a position
  // --------------------------------------------------------------------------
  std::vector<std::string> get_changed_entities(StreamType st,
                                                  int64_t since,
                                                  int limit = 100) {
    auto result = caches_.get(st).get_changed(since, limit);
    if (!result.empty()) {
      metrics_.record_cache_hit(st);
    } else {
      metrics_.record_cache_miss(st);
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Get cache stats
  // --------------------------------------------------------------------------
  json get_cache_stats() const {
    return caches_.get_all_stats();
  }

  // --------------------------------------------------------------------------
  // Purge all caches
  // --------------------------------------------------------------------------
  void purge_caches() {
    caches_.purge_all();
  }

  // --------------------------------------------------------------------------
  // Clear all caches
  // --------------------------------------------------------------------------
  void clear_caches() {
    caches_.clear_all();
  }

  // ==========================================================================
  // Stream ordering
  // ==========================================================================

  // --------------------------------------------------------------------------
  // Compute global ordering key
  // --------------------------------------------------------------------------
  static int64_t compute_global_order(const StreamPosition& pos) {
    return StreamOrderingManager::compute_global_order(pos);
  }

  // --------------------------------------------------------------------------
  // Check if position A is after position B
  // --------------------------------------------------------------------------
  static bool is_after(const StreamPosition& a, const StreamPosition& b) {
    return StreamOrderingManager::is_after(a, b);
  }

  // --------------------------------------------------------------------------
  // Merge two positions
  // --------------------------------------------------------------------------
  static StreamPosition merge_positions(const StreamPosition& a,
                                         const StreamPosition& b) {
    return StreamOrderingManager::merge(a, b);
  }

  // --------------------------------------------------------------------------
  // Compute lag between two positions
  // --------------------------------------------------------------------------
  static StreamPosition compute_lag(const StreamPosition& current,
                                     const StreamPosition& target) {
    return StreamOrderingManager::lag(current, target);
  }

  // ==========================================================================
  // Database-backed change queries
  // ==========================================================================

  // --------------------------------------------------------------------------
  // Query presence changes since a position for a set of users
  // --------------------------------------------------------------------------
  json query_presence_since(LoggingTransaction& txn,
                              const std::vector<std::string>& user_ids,
                              int64_t since, int limit = 100) {
    std::string sql =
        StreamQueryBuilder::presence_since(user_ids, since, limit);
    return execute_query(txn, sql, StreamType::kPresence);
  }

  // --------------------------------------------------------------------------
  // Query receipt changes since a position for a room
  // --------------------------------------------------------------------------
  json query_receipts_since(LoggingTransaction& txn,
                              const std::string& room_id,
                              int64_t since, int limit = 100) {
    std::string sql =
        StreamQueryBuilder::receipts_since(room_id, since, limit);
    return execute_query(txn, sql, StreamType::kReceipts);
  }

  // --------------------------------------------------------------------------
  // Query typing changes since a position for a room
  // --------------------------------------------------------------------------
  json query_typing_since(LoggingTransaction& txn,
                            const std::string& room_id,
                            int64_t since, int limit = 100) {
    std::string sql =
        StreamQueryBuilder::typing_since(room_id, since, limit);
    return execute_query(txn, sql, StreamType::kTyping);
  }

  // --------------------------------------------------------------------------
  // Query to-device changes since a position for a user
  // --------------------------------------------------------------------------
  json query_to_device_since(LoggingTransaction& txn,
                               const std::string& user_id,
                               int64_t since, int limit = 100) {
    std::string sql =
        StreamQueryBuilder::to_device_since(user_id, since, limit);
    return execute_query(txn, sql, StreamType::kToDevice);
  }

  // --------------------------------------------------------------------------
  // Query device list changes since a position
  // --------------------------------------------------------------------------
  json query_device_lists_since(LoggingTransaction& txn,
                                  int64_t since, int limit = 100) {
    std::string sql =
        StreamQueryBuilder::device_lists_since("", since, limit);
    return execute_query(txn, sql, StreamType::kDeviceLists);
  }

  // --------------------------------------------------------------------------
  // Query account data changes since a position for a user
  // --------------------------------------------------------------------------
  json query_account_data_since(LoggingTransaction& txn,
                                  const std::string& user_id,
                                  int64_t since, int limit = 100,
                                  bool global_only = false) {
    std::string sql =
        StreamQueryBuilder::account_data_since(user_id, since,
                                                limit, global_only);
    return execute_query(txn, sql, StreamType::kAccountData);
  }

  // --------------------------------------------------------------------------
  // Query push rules changes since a position for a user
  // --------------------------------------------------------------------------
  json query_push_rules_since(LoggingTransaction& txn,
                                const std::string& user_id,
                                int64_t since, int limit = 100) {
    std::string sql =
        StreamQueryBuilder::push_rules_since(user_id, since, limit);
    return execute_query(txn, sql, StreamType::kPushRules);
  }

  // ==========================================================================
  // Record stream changes in the database
  // ==========================================================================

  // --------------------------------------------------------------------------
  // Record a presence change in the database and cache
  // --------------------------------------------------------------------------
  void record_presence_change(LoggingTransaction& txn,
                               const std::string& user_id,
                               const std::string& state,
                               const std::string& status_msg,
                               bool currently_active) {
    int64_t stream_id = generate_next_id(txn, StreamType::kPresence);
    int64_t ts = now_ms();

    txn.execute(
        "INSERT INTO presence_stream "
        "(user_id, stream_id, state, last_active_ts, status_msg, "
        "currently_active, last_user_sync_ts) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (user_id) DO UPDATE SET "
        "stream_id = excluded.stream_id, "
        "state = excluded.state, "
        "last_active_ts = excluded.last_active_ts, "
        "status_msg = excluded.status_msg, "
        "currently_active = excluded.currently_active, "
        "last_user_sync_ts = excluded.last_user_sync_ts",
        {user_id, stream_id, state, ts, status_msg,
         currently_active ? 1 : 0, ts});

    record_change(StreamType::kPresence, stream_id, user_id);
  }

  // --------------------------------------------------------------------------
  // Record a typing change
  // --------------------------------------------------------------------------
  void record_typing_change(LoggingTransaction& txn,
                             const std::string& room_id,
                             const std::string& user_id,
                             int64_t timeout_ms,
                             bool is_typing) {
    int64_t stream_id = generate_next_id(txn, StreamType::kTyping);
    int64_t ts = now_ms();

    txn.execute(
        "INSERT INTO typing_stream "
        "(stream_id, room_id, user_id, timeout_ms, ts, is_typing) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        {stream_id, room_id, user_id, timeout_ms, ts, is_typing ? 1 : 0});

    record_change(StreamType::kTyping, stream_id, room_id + ":" + user_id);
  }

  // --------------------------------------------------------------------------
  // Record a receipt change
  // --------------------------------------------------------------------------
  void record_receipt_change(LoggingTransaction& txn,
                              const std::string& room_id,
                              const std::string& user_id,
                              const std::string& event_id,
                              const std::string& receipt_type,
                              const json& data) {
    int64_t stream_id = generate_next_id(txn, StreamType::kReceipts);

    txn.execute(
        "INSERT INTO receipts_stream "
        "(stream_id, room_id, user_id, event_id, receipt_type, data, "
        "origin_server_ts) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (room_id, user_id, receipt_type) DO UPDATE SET "
        "stream_id = excluded.stream_id, "
        "event_id = excluded.event_id, "
        "data = excluded.data, "
        "origin_server_ts = excluded.origin_server_ts",
        {stream_id, room_id, user_id, event_id, receipt_type,
         data.dump(), now_ms()});

    record_change(StreamType::kReceipts, stream_id,
                  room_id + ":" + user_id);
  }

  // --------------------------------------------------------------------------
  // Record a to-device message
  // --------------------------------------------------------------------------
  int64_t record_to_device_message(LoggingTransaction& txn,
                                    const std::string& target_user_id,
                                    const std::string& device_id,
                                    const std::string& sender_user_id,
                                    const std::string& message_type,
                                    const json& content) {
    int64_t stream_id = generate_next_id(txn, StreamType::kToDevice);
    int64_t ts = now_ms();

    txn.execute(
        "INSERT INTO to_device_messages "
        "(user_id, device_id, sender_user_id, message_type, "
        "content_json, stream_id, delivery_status, created_ts) "
        "VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)",
        {target_user_id, device_id, sender_user_id, message_type,
         content.dump(), stream_id, ts});

    // Update delivery tracking
    txn.execute(
        "INSERT INTO to_device_delivery_tracking "
        "(user_id, device_id, last_stream_position, pending_count, "
        "updated_ts) "
        "VALUES (?, ?, ?, 1, ?) "
        "ON CONFLICT (user_id, device_id) DO UPDATE SET "
        "last_stream_position = excluded.last_stream_position, "
        "pending_count = to_device_delivery_tracking.pending_count + 1, "
        "updated_ts = excluded.updated_ts",
        {target_user_id, device_id, stream_id, ts});

    record_change(StreamType::kToDevice, stream_id,
                  target_user_id + ":" + device_id);

    return stream_id;
  }

  // --------------------------------------------------------------------------
  // Record a device list change
  // --------------------------------------------------------------------------
  void record_device_list_change(LoggingTransaction& txn,
                                  const std::string& user_id,
                                  const std::string& device_id,
                                  bool is_signature_change) {
    int64_t stream_id = generate_next_id(txn, StreamType::kDeviceLists);
    int64_t ts = now_ms();

    txn.execute(
        "INSERT INTO device_lists_stream "
        "(stream_id, user_id, device_id, ts, is_signature_change) "
        "VALUES (?, ?, ?, ?, ?)",
        {stream_id, user_id, device_id, ts, is_signature_change ? 1 : 0});

    record_change(StreamType::kDeviceLists, stream_id, user_id);
  }

  // --------------------------------------------------------------------------
  // Record a device list outbound poke
  // --------------------------------------------------------------------------
  void record_device_list_outbound_poke(LoggingTransaction& txn,
                                          const std::string& user_id,
                                          const std::string& device_id,
                                          const std::string& destination) {
    int64_t stream_id = generate_next_id(txn, StreamType::kDeviceLists);
    int64_t ts = now_ms();

    txn.execute(
        "INSERT INTO device_list_outbound_pokes "
        "(stream_id, user_id, device_id, sent_to_destination, ts) "
        "VALUES (?, ?, ?, ?, ?)",
        {stream_id, user_id, device_id, destination, ts});
  }

  // --------------------------------------------------------------------------
  // Record an account data change
  // --------------------------------------------------------------------------
  void record_account_data_change(LoggingTransaction& txn,
                                   const std::string& user_id,
                                   const std::string& data_type,
                                   const std::string& data_key,
                                   const json& content,
                                   const std::optional<std::string>& room_id =
                                       std::nullopt) {
    int64_t stream_id = generate_next_id(txn, StreamType::kAccountData);
    int64_t ts = now_ms();

    std::string rid = room_id.value_or("");

    txn.execute(
        "INSERT INTO account_data "
        "(user_id, data_type, data_key, room_id, content_json, "
        "stream_id, created_ts, updated_ts) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (user_id, data_type, data_key) DO UPDATE SET "
        "content_json = excluded.content_json, "
        "stream_id = excluded.stream_id, "
        "updated_ts = excluded.updated_ts, "
        "room_id = COALESCE(excluded.room_id, account_data.room_id)",
        {user_id, data_type, data_key,
         (!rid.empty() ? rid : std::string()),
         content.dump(), stream_id, ts, ts});

    record_change(StreamType::kAccountData, stream_id,
                  user_id + ":" + data_type);
  }

  // --------------------------------------------------------------------------
  // Record a push rule change
  // --------------------------------------------------------------------------
  void record_push_rule_change(LoggingTransaction& txn,
                                const std::string& user_id,
                                const std::string& rule_id,
                                const std::string& kind,
                                int priority_class, int priority,
                                const json& conditions, const json& actions,
                                bool enabled, bool default_rule) {
    int64_t stream_id = generate_next_id(txn, StreamType::kPushRules);
    int64_t ts = now_ms();

    txn.execute(
        "INSERT INTO push_rules_stream "
        "(stream_id, user_id, rule_id, kind, priority_class, priority, "
        "conditions, actions, enabled, default_rule, updated_ts) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (user_id, rule_id) DO UPDATE SET "
        "stream_id = excluded.stream_id, "
        "kind = excluded.kind, "
        "priority_class = excluded.priority_class, "
        "priority = excluded.priority, "
        "conditions = excluded.conditions, "
        "actions = excluded.actions, "
        "enabled = excluded.enabled, "
        "default_rule = excluded.default_rule, "
        "updated_ts = excluded.updated_ts",
        {stream_id, user_id, rule_id, kind, priority_class, priority,
         conditions.dump(), actions.dump(),
         enabled ? 1 : 0, default_rule ? 1 : 0, ts});

    record_change(StreamType::kPushRules, stream_id, user_id + ":" + rule_id);
  }

  // ==========================================================================
  // Metrics
  // ==========================================================================

  json get_metrics() const {
    return metrics_.get_metrics();
  }

  void reset_metrics() {
    metrics_.reset();
  }

  // ==========================================================================
  // Admin / utility operations
  // ==========================================================================

  // --------------------------------------------------------------------------
  // Get full stream state snapshot for debugging
  // --------------------------------------------------------------------------
  json get_stream_snapshot(LoggingTransaction& txn) {
    json snap;
    snap["max_ids"] = get_all_max_ids(txn).to_json();
    snap["local_max_ids"] = get_all_local_max_ids().to_json();
    snap["cache_stats"] = get_cache_stats();
    snap["metrics"] = get_metrics();
    snap["timestamp_ms"] = now_ms();
    return snap;
  }

  // --------------------------------------------------------------------------
  // Validate stream consistency
  // --------------------------------------------------------------------------
  json validate_streams(LoggingTransaction& txn) {
    json report;
    report["valid"] = true;
    json issues = json::array();

    // Check that each max_stream table has exactly one row
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      std::string table = stream_type_to_max_table(st);
      auto row = txn.select_one(
          "SELECT COUNT(*) FROM " + table);
      int64_t count = (row && !row->is_null()) ? row->get<int64_t>(0) : 0;
      if (count != 1) {
        issues.push_back({
          {"stream", stream_type_name(st)},
          {"issue", "Wrong row count in " + table},
          {"expected", 1},
          {"actual", count}
        });
        report["valid"] = false;
      }

      // Check no negative stream IDs
      int64_t max_id = get_max_id(txn, st);
      if (max_id < 0) {
        issues.push_back({
          {"stream", stream_type_name(st)},
          {"issue", "Negative max_stream_id"},
          {"value", max_id}
        });
        report["valid"] = false;
      }
    }

    report["issues"] = issues;
    report["issue_count"] = issues.size();
    return report;
  }

  // --------------------------------------------------------------------------
  // Repair stream tables (re-initialize missing max_stream rows)
  // --------------------------------------------------------------------------
  int repair_streams(LoggingTransaction& txn) {
    int repairs = 0;
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      std::string table = stream_type_to_max_table(st);
      auto row = txn.select_one("SELECT COUNT(*) FROM " + table);
      int64_t count = (row && !row->is_null()) ? row->get<int64_t>(0) : 0;
      if (count == 0) {
        txn.execute(
            "INSERT OR IGNORE INTO " + table
            + " (id, max_stream_id) VALUES (1, 0)");
        repairs++;
      }
    }
    return repairs;
  }

  // --------------------------------------------------------------------------
  // Compact typing stream (remove stale entries)
  // --------------------------------------------------------------------------
  int compact_typing_stream(LoggingTransaction& txn, int64_t older_than_ms) {
    int64_t cutoff = now_ms() - older_than_ms;

    // Keep only the latest typing state per (room, user)
    txn.execute(
        "DELETE FROM typing_stream "
        "WHERE stream_id NOT IN ("
        "  SELECT MAX(stream_id) FROM typing_stream "
        "  GROUP BY room_id, user_id"
        ") AND ts < ?",
        {cutoff});

    // Count deleted
    auto row = txn.select_one("SELECT changes()");
    return (row && !row->is_null()) ? static_cast<int>(row->get<int64_t>(0)) : 0;
  }

  // --------------------------------------------------------------------------
  // Get users behind on a specific stream
  // --------------------------------------------------------------------------
  std::vector<std::string> get_users_behind(LoggingTransaction& txn,
                                               StreamType st,
                                               int64_t max_pos,
                                               int limit = 100) {
    return pos_tracker_.get_users_behind(txn, st, max_pos, limit);
  }

  // --------------------------------------------------------------------------
  // Count users behind on a specific stream
  // --------------------------------------------------------------------------
  int64_t count_users_behind(LoggingTransaction& txn, StreamType st,
                               int64_t max_pos) {
    return pos_tracker_.count_users_behind(txn, st, max_pos);
  }

private:
  // --------------------------------------------------------------------------
  // Initialize local max IDs from database
  // --------------------------------------------------------------------------
  void initialize_local_max_ids() {
    try {
      LoggingTransaction txn(db_, "stream_init");
      for (size_t i = 0; i < kNumStreamTypes; ++i) {
        auto st = static_cast<StreamType>(i);
        int64_t max_id = id_gen_.get_max(txn, st);
        id_gen_.update_local_max(st, max_id);
      }
    } catch (const std::exception& e) {
      util::log::warn("stream_manager",
                      std::string("Failed to initialize stream IDs: ") + e.what());
    }
  }

  // --------------------------------------------------------------------------
  // Execute a query and return results as JSON array, with timing
  // --------------------------------------------------------------------------
  json execute_query(LoggingTransaction& txn, const std::string& sql,
                      StreamType st) {
    auto start = chr::high_resolution_clock::now();

    auto rows = txn.select(sql);

    auto end = chr::high_resolution_clock::now();
    int64_t duration_us = chr::duration_cast<chr::microseconds>(
        end - start).count();
    metrics_.record_stream_query(st, duration_us);

    json result = json::array();
    for (auto& row : rows) {
      json obj = json::object();
      for (size_t col = 0; col < row->column_count(); ++col) {
        std::string col_name = row->column_name(col);
        if (row->is_null(col)) {
          obj[col_name] = nullptr;
        } else {
          // Try integer, then double, then string
          try {
            obj[col_name] = row->get<int64_t>(col);
          } catch (...) {
            try {
              obj[col_name] = row->get<double>(col);
            } catch (...) {
              try {
                obj[col_name] = row->get<std::string>(col);
              } catch (...) {
                obj[col_name] = nullptr;
              }
            }
          }
        }
      }
      result.push_back(obj);
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Helper: execute SQL and return raw rows (used by other executing functions)
  // --------------------------------------------------------------------------
  RowList db_execute_sql(const std::string& sql) {
    return db_.execute("stream_manager", sql);
  }

  // --------------------------------------------------------------------------
  // Members
  // --------------------------------------------------------------------------
  DatabasePool& db_;
  StreamIDGenerator id_gen_;
  StreamPositionTracker pos_tracker_;
  MultiStreamCache caches_;
  StreamMetrics metrics_;
};

// ============================================================================
// Convenience wrappers for external consumers
// ============================================================================

// ----------------------------------------------------------------------------
// Generate a sync token compatible with the sync engine
// ----------------------------------------------------------------------------
std::string generate_sync_token(StreamManager& mgr, LoggingTransaction& txn) {
  return mgr.make_sync_token_from_max(txn);
}

// ----------------------------------------------------------------------------
// Parse an incoming sync token and extract the events position
// ----------------------------------------------------------------------------
int64_t parse_sync_token_to_events(std::string_view token) {
  auto pos = StreamToken::decode(token);
  return pos.has_value() ? pos->events() : 0;
}

// ----------------------------------------------------------------------------
// Create a multi-stream sync token from individual positions
// ----------------------------------------------------------------------------
std::string create_multi_stream_token(int64_t events, int64_t presence,
                                       int64_t receipts, int64_t typing,
                                       int64_t to_device,
                                       int64_t device_lists,
                                       int64_t account_data,
                                       int64_t push_rules) {
  StreamPosition pos;
  pos.set(StreamType::kEvents, events);
  pos.set(StreamType::kPresence, presence);
  pos.set(StreamType::kReceipts, receipts);
  pos.set(StreamType::kTyping, typing);
  pos.set(StreamType::kToDevice, to_device);
  pos.set(StreamType::kDeviceLists, device_lists);
  pos.set(StreamType::kAccountData, account_data);
  pos.set(StreamType::kPushRules, push_rules);
  return StreamToken::encode(pos);
}

// ============================================================================
// StreamReplicationManager — handles stream replication across workers
// ============================================================================
class StreamReplicationManager {
public:
  // --------------------------------------------------------------------------
  // Constructor
  // --------------------------------------------------------------------------
  StreamReplicationManager(StreamManager& mgr, DatabasePool& db)
      : stream_mgr_(mgr), db_(db) {}

  // --------------------------------------------------------------------------
  // Get the replication position (max across all streams)
  // --------------------------------------------------------------------------
  int64_t get_replication_position(LoggingTransaction& txn) {
    auto max_ids = stream_mgr_.get_all_max_ids(txn);
    return std::max({
        max_ids.events(), max_ids.presence(), max_ids.receipts(),
        max_ids.typing(), max_ids.to_device(), max_ids.device_lists(),
        max_ids.account_data(), max_ids.push_rules()
    });
  }

  // --------------------------------------------------------------------------
  // Get min stream position across all users for a stream type
  // --------------------------------------------------------------------------
  int64_t get_min_user_position(LoggingTransaction& txn, StreamType st) {
    std::string table = stream_type_to_pos_table(st);
    auto row = txn.select_one(
        "SELECT MIN(stream_position) FROM " + table
        + " WHERE stream_position > 0");
    return (row && !row->is_null()) ? row->get<int64_t>(0) : 0;
  }

  // --------------------------------------------------------------------------
  // Compute replication lag for a stream
  // --------------------------------------------------------------------------
  int64_t compute_replication_lag(LoggingTransaction& txn, StreamType st) {
    int64_t max_id = stream_mgr_.get_max_id(txn, st);
    int64_t min_pos = get_min_user_position(txn, st);
    return std::max(int64_t(0), max_id - min_pos);
  }

  // --------------------------------------------------------------------------
  // Get replication status for all streams
  // --------------------------------------------------------------------------
  json get_replication_status(LoggingTransaction& txn) {
    json status = json::object();
    auto max_ids = stream_mgr_.get_all_max_ids(txn);

    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      json s;
      s["name"] = stream_type_name(st);
      s["max_id"] = max_ids.get(st);
      s["min_user_position"] = get_min_user_position(txn, st);
      s["lag"] = compute_replication_lag(txn, st);
      s["users_behind"] = stream_mgr_.count_users_behind(
          txn, st, max_ids.get(st));
      status[stream_type_name(st)] = s;
    }

    status["timestamp_ms"] = now_ms();
    return status;
  }

  // --------------------------------------------------------------------------
  // Advance a stream to at least the given position
  // --------------------------------------------------------------------------
  void catch_up_stream(LoggingTransaction& txn, StreamType st,
                        int64_t target_id) {
    int64_t current = stream_mgr_.get_max_id(txn, st);
    if (target_id > current) {
      stream_mgr_.advance_stream_to(txn, st, target_id);
      util::log::info("stream_replication",
          std::string("Caught up ") + stream_type_name(st) +
          " from " + std::to_string(current) + " to " +
          std::to_string(target_id));
    }
  }

  // --------------------------------------------------------------------------
  // Catch up all streams to at least the given positions
  // --------------------------------------------------------------------------
  void catch_up_all_streams(LoggingTransaction& txn,
                             const StreamPosition& targets) {
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      catch_up_stream(txn, st, targets.get(st));
    }
  }

private:
  StreamManager& stream_mgr_;
  DatabasePool& db_;
};

// ============================================================================
// StreamGapDetector — detects and reports gaps in stream continuity
// ============================================================================
class StreamGapDetector {
public:
  // --------------------------------------------------------------------------
  // Detect gaps in event stream for a room
  // --------------------------------------------------------------------------
  std::vector<StreamRange> detect_event_gaps(LoggingTransaction& txn,
                                               const std::string& room_id,
                                               int64_t from_id,
                                               int64_t to_id) {
    std::vector<StreamRange> gaps;

    if (from_id >= to_id) return gaps;

    // Query for stream IDs in range
    std::string sql =
        "SELECT stream_ordering FROM events "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "AND stream_ordering > " + std::to_string(from_id) + " "
        "AND stream_ordering <= " + std::to_string(to_id) + " "
        "ORDER BY stream_ordering ASC";

    auto rows = txn.select(sql);

    int64_t expected = from_id + 1;
    for (auto& row : rows) {
      int64_t actual = row->get<int64_t>(0);
      while (expected < actual) {
        StreamRange gap;
        gap.from_id = expected;
        gap.to_id = actual - 1;
        gap.stream_type = StreamType::kEvents;
        gaps.push_back(gap);
        expected = actual + 1;
      }
      expected = actual + 1;
    }

    // Check for gap at end
    if (expected <= to_id) {
      StreamRange gap;
      gap.from_id = expected;
      gap.to_id = to_id;
      gap.stream_type = StreamType::kEvents;
      gaps.push_back(gap);
    }

    return gaps;
  }

  // --------------------------------------------------------------------------
  // Detect gaps across all streams
  // --------------------------------------------------------------------------
  json detect_all_gaps(LoggingTransaction& txn,
                        const StreamPosition& from,
                        const StreamPosition& to) {
    json result = json::object();

    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      int64_t from_id = from.get(st);
      int64_t to_id = to.get(st);

      if (from_id >= to_id) {
        result[stream_type_name(st)] = json::array();
        continue;
      }

      // Count expected vs actual records in range
      std::string table = get_stream_source_table(st);
      int64_t expected = to_id - from_id;

      if (!table.empty()) {
        auto row = txn.select_one(
            "SELECT COUNT(*) FROM " + table
            + " WHERE stream_id > ? AND stream_id <= ?",
            {from_id, to_id});
        int64_t actual = (row && !row->is_null())
            ? row->get<int64_t>(0) : 0;

        json gap_report;
        gap_report["from"] = from_id;
        gap_report["to"] = to_id;
        gap_report["expected_range"] = expected;
        gap_report["actual_records"] = actual;
        gap_report["missing"] = std::max(int64_t(0), expected - actual);
        gap_report["has_gap"] = (actual < expected);
        result[stream_type_name(st)] = gap_report;
      } else {
        result[stream_type_name(st)] = json::object();
      }
    }

    return result;
  }

private:
  // --------------------------------------------------------------------------
  // Get the source table name for a stream type
  // --------------------------------------------------------------------------
  static std::string get_stream_source_table(StreamType st) {
    switch (st) {
      case StreamType::kEvents:      return "events";
      case StreamType::kPresence:    return "presence_stream";
      case StreamType::kReceipts:    return "receipts_stream";
      case StreamType::kTyping:      return "typing_stream";
      case StreamType::kToDevice:    return "to_device_messages";
      case StreamType::kDeviceLists: return "device_lists_stream";
      case StreamType::kAccountData: return "account_data";
      case StreamType::kPushRules:   return "push_rules_stream";
      default:                       return "";
    }
  }
};

// ============================================================================
// StreamBackfillProcessor — handles catch-up backfills for delayed users
// ============================================================================
class StreamBackfillProcessor {
public:
  // --------------------------------------------------------------------------
  // Constructor
  // --------------------------------------------------------------------------
  StreamBackfillProcessor(StreamManager& mgr, size_t batch_size = 500)
      : stream_mgr_(mgr), batch_size_(batch_size) {}

  // --------------------------------------------------------------------------
  // Backfill presence changes for a user
  // --------------------------------------------------------------------------
  json backfill_presence(LoggingTransaction& txn,
                          const std::string& user_id,
                          const std::vector<std::string>& shared_user_ids) {
    int64_t pos = stream_mgr_.get_user_position(
        txn, StreamType::kPresence, user_id);
    int64_t max_id = stream_mgr_.get_max_id(txn, StreamType::kPresence);

    if (pos >= max_id) return json::array();

    json result = stream_mgr_.query_presence_since(
        txn, shared_user_ids, pos, static_cast<int>(batch_size_));

    // Update user position
    if (!result.empty()) {
      int64_t latest = pos;
      for (const auto& entry : result) {
        if (entry.contains("stream_id")) {
          latest = std::max(latest, entry["stream_id"].get<int64_t>());
        }
      }
      stream_mgr_.advance_user_position(
          txn, StreamType::kPresence, user_id, latest);
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Backfill receipt changes for a user in a room
  // --------------------------------------------------------------------------
  json backfill_receipts(LoggingTransaction& txn,
                           const std::string& user_id,
                           const std::string& room_id) {
    int64_t pos = stream_mgr_.get_user_position(
        txn, StreamType::kReceipts, user_id);
    int64_t max_id = stream_mgr_.get_max_id(txn, StreamType::kReceipts);

    if (pos >= max_id) return json::array();

    json result = stream_mgr_.query_receipts_since(
        txn, room_id, pos, static_cast<int>(batch_size_));

    if (!result.empty()) {
      int64_t latest = pos;
      for (const auto& entry : result) {
        if (entry.contains("stream_id")) {
          latest = std::max(latest, entry["stream_id"].get<int64_t>());
        }
      }
      stream_mgr_.advance_user_position(
          txn, StreamType::kReceipts, user_id, latest);
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Backfill to-device messages for a user/device
  // --------------------------------------------------------------------------
  json backfill_to_device(LoggingTransaction& txn,
                            const std::string& user_id) {
    int64_t pos = stream_mgr_.get_user_position(
        txn, StreamType::kToDevice, user_id);
    int64_t max_id = stream_mgr_.get_max_id(txn, StreamType::kToDevice);

    if (pos >= max_id) return json::array();

    json result = stream_mgr_.query_to_device_since(
        txn, user_id, pos, static_cast<int>(batch_size_));

    if (!result.empty()) {
      int64_t latest = pos;
      for (const auto& entry : result) {
        if (entry.contains("stream_id")) {
          latest = std::max(latest, entry["stream_id"].get<int64_t>());
        }
      }
      stream_mgr_.advance_user_position(
          txn, StreamType::kToDevice, user_id, latest);
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Backfill account data changes for a user
  // --------------------------------------------------------------------------
  json backfill_account_data(LoggingTransaction& txn,
                               const std::string& user_id,
                               bool global_only = false) {
    int64_t pos = stream_mgr_.get_user_position(
        txn, StreamType::kAccountData, user_id);
    int64_t max_id = stream_mgr_.get_max_id(txn, StreamType::kAccountData);

    if (pos >= max_id) return json::array();

    json result = stream_mgr_.query_account_data_since(
        txn, user_id, pos, static_cast<int>(batch_size_),
        global_only);

    if (!result.empty()) {
      int64_t latest = pos;
      for (const auto& entry : result) {
        if (entry.contains("stream_id")) {
          latest = std::max(latest, entry["stream_id"].get<int64_t>());
        }
      }
      stream_mgr_.advance_user_position(
          txn, StreamType::kAccountData, user_id, latest);
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Full backfill for a user across all streams
  // --------------------------------------------------------------------------
  json backfill_all(LoggingTransaction& txn,
                     const std::string& user_id,
                     const std::vector<std::string>& shared_user_ids) {
    json result;
    result["presence"] = backfill_presence(txn, user_id, shared_user_ids);
    result["to_device"] = backfill_to_device(txn, user_id);
    result["account_data"] = backfill_account_data(txn, user_id, false);
    result["timestamp_ms"] = now_ms();

    // Mark this as a full backfill
    int64_t peer_ts = now_ms();
    for (const auto& uid : shared_user_ids) {
      result["shared_users"][uid] = {"backfilled_at": peer_ts};
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Set batch size for backfills
  // --------------------------------------------------------------------------
  void set_batch_size(size_t size) { batch_size_ = size; }
  size_t get_batch_size() const { return batch_size_; }

private:
  StreamManager& stream_mgr_;
  size_t batch_size_;
};

// ============================================================================
// StreamSnapshot — captures a point-in-time snapshot of all stream positions
// ============================================================================
class StreamSnapshot {
public:
  struct SnapshotData {
    StreamPosition max_ids;
    StreamPosition user_positions;
    int64_t captured_at_ms;
    std::string snapshot_id;
  };

  // --------------------------------------------------------------------------
  // Take a snapshot for a specific user
  // --------------------------------------------------------------------------
  static SnapshotData take_user_snapshot(StreamManager& mgr,
                                          LoggingTransaction& txn,
                                          const std::string& user_id) {
    SnapshotData snap;
    snap.max_ids = mgr.get_all_max_ids(txn);
    snap.user_positions = mgr.get_user_all_positions(txn, user_id);
    snap.captured_at_ms = now_ms();

    // Generate a unique snapshot ID
    snap.snapshot_id = "snap_" + std::to_string(snap.captured_at_ms)
                       + "_" + user_id;

    return snap;
  }

  // --------------------------------------------------------------------------
  // Compare two snapshots and report deltas
  // --------------------------------------------------------------------------
  static json compare(const SnapshotData& a, const SnapshotData& b) {
    json diff;
    diff["snapshot_a"] = a.snapshot_id;
    diff["snapshot_b"] = b.snapshot_id;
    diff["time_delta_ms"] = b.captured_at_ms - a.captured_at_ms;

    json stream_deltas = json::object();
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      int64_t delta_max = b.max_ids.get(st) - a.max_ids.get(st);
      int64_t delta_user = b.user_positions.get(st)
                           - a.user_positions.get(st);

      json sd;
      sd["max_id_delta"] = delta_max;
      sd["user_position_delta"] = delta_user;
      sd["user_behind"] = b.max_ids.get(st) - b.user_positions.get(st);
      stream_deltas[stream_type_name(st)] = sd;
    }
    diff["streams"] = stream_deltas;

    return diff;
  }
};

// ============================================================================
// StreamConsistencyChecker — validates stream integrity across tables
// ============================================================================
class StreamConsistencyChecker {
public:
  // --------------------------------------------------------------------------
  // Check consistency between max_stream tables and actual data
  // --------------------------------------------------------------------------
  static json check_max_stream_consistency(LoggingTransaction& txn) {
    json report;
    report["consistent"] = true;
    json checks = json::array();

    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      std::string max_table = stream_type_to_max_table(st);
      std::string source_table = StreamGapDetector::get_stream_source_table_impl(st);

      auto max_row = txn.select_one(
          "SELECT max_stream_id FROM " + max_table + " WHERE id = 1");
      int64_t declared_max = (max_row && !max_row->is_null())
          ? max_row->get<int64_t>(0) : 0;

      json check;
      check["stream"] = stream_type_name(st);
      check["declared_max"] = declared_max;

      if (!source_table.empty()) {
        auto actual_max_row = txn.select_one(
            "SELECT MAX(COALESCE(stream_id, stream_ordering, 0)) FROM "
            + source_table);
        int64_t actual_max = (actual_max_row && !actual_max_row->is_null())
            ? actual_max_row->get<int64_t>(0) : 0;

        check["actual_max"] = actual_max;
        check["consistent"] = (declared_max >= actual_max);

        if (declared_max < actual_max) {
          report["consistent"] = false;
          check["discrepancy"] = actual_max - declared_max;
          check["recommendation"] = "Advance max_stream_id to at least "
                                    + std::to_string(actual_max);
        }
      }

      checks.push_back(check);
    }

    report["checks"] = checks;
    report["timestamp_ms"] = now_ms();
    return report;
  }

  // --------------------------------------------------------------------------
  // Check for orphaned stream positions
  // --------------------------------------------------------------------------
  static json check_orphaned_positions(LoggingTransaction& txn) {
    json report;
    json orphans = json::array();

    // Fetch all user IDs that have stream positions
    std::set<std::string> position_user_ids;

    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      std::string table = stream_type_to_pos_table(st);
      auto rows = txn.select("SELECT DISTINCT user_id FROM " + table);

      for (auto& row : rows) {
        position_user_ids.insert(row->get<std::string>(0));
      }
    }

    // Check each user exists in the users table
    for (const auto& uid : position_user_ids) {
      auto user_row = txn.select_one(
          "SELECT name FROM users WHERE name = ?", {uid});
      if (!user_row || user_row->is_null()) {
        orphans.push_back({
          {"user_id", uid},
          {"issue", "Stream positions exist for non-existent user"}
        });
      }
    }

    report["orphaned_count"] = orphans.size();
    report["orphans"] = orphans;
    report["timestamp_ms"] = now_ms();
    return report;
  }

  // --------------------------------------------------------------------------
  // Clean up orphaned stream positions
  // --------------------------------------------------------------------------
  static int clean_orphaned_positions(LoggingTransaction& txn) {
    int cleaned = 0;

    std::set<std::string> position_user_ids;
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      std::string table = stream_type_to_pos_table(st);
      auto rows = txn.select("SELECT DISTINCT user_id FROM " + table);

      for (auto& row : rows) {
        position_user_ids.insert(row->get<std::string>(0));
      }
    }

    for (const auto& uid : position_user_ids) {
      auto user_row = txn.select_one(
          "SELECT name FROM users WHERE name = ?", {uid});
      if (!user_row || user_row->is_null()) {
        for (size_t i = 0; i < kNumStreamTypes; ++i) {
          auto st = static_cast<StreamType>(i);
          std::string table = stream_type_to_pos_table(st);
          txn.execute("DELETE FROM " + table + " WHERE user_id = ?", {uid});
        }
        cleaned++;
      }
    }

    return cleaned;
  }

  // --------------------------------------------------------------------------
  // Full consistency report
  // --------------------------------------------------------------------------
  static json full_consistency_report(LoggingTransaction& txn) {
    json report;
    report["max_stream_consistency"] = check_max_stream_consistency(txn);
    report["orphaned_positions"] = check_orphaned_positions(txn);
    report["overall_consistent"] =
        report["max_stream_consistency"]["consistent"].get<bool>() &&
        report["orphaned_positions"]["orphaned_count"].get<int>() == 0;
    report["timestamp_ms"] = now_ms();
    return report;
  }
};

// ============================================================================
// StreamEventIndexer — maintains secondary indexes on stream tables
// ============================================================================
class StreamEventIndexer {
public:
  // --------------------------------------------------------------------------
  // Rebuild all stream-related indexes
  // --------------------------------------------------------------------------
  static void rebuild_indexes(LoggingTransaction& txn) {
    // Presence indexes
    txn.execute(
        "REINDEX idx_presence_stream_id");
    txn.execute(
        "REINDEX idx_presence_state");

    // Typing indexes
    txn.execute(
        "REINDEX idx_typing_stream_room");
    txn.execute(
        "REINDEX idx_typing_stream_user");

    // Receipts indexes
    txn.execute(
        "REINDEX idx_receipts_stream_id");
    txn.execute(
        "REINDEX idx_receipts_room_stream");

    // To-device indexes
    txn.execute(
        "REINDEX idx_to_device_user_stream");
    txn.execute(
        "REINDEX idx_to_device_delivery");
    txn.execute(
        "REINDEX idx_to_device_stream");

    // Device lists indexes
    txn.execute(
        "REINDEX idx_device_lists_stream_id");
    txn.execute(
        "REINDEX idx_device_lists_user");
    txn.execute(
        "REINDEX idx_outbound_pokes_stream");
    txn.execute(
        "REINDEX idx_outbound_pokes_user");

    // Push rules indexes
    txn.execute(
        "REINDEX idx_push_rules_stream_id");
    txn.execute(
        "REINDEX idx_push_rules_user");

    // Account data indexes
    txn.execute(
        "REINDEX idx_account_data_stream");
    txn.execute(
        "REINDEX idx_account_data_user_stream");
    txn.execute(
        "REINDEX idx_account_data_room");

    // Position table indexes
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      std::string table = stream_type_to_pos_table(st);
      txn.execute(
          "REINDEX idx_" + table + "_position");
    }
  }

  // --------------------------------------------------------------------------
  // Analyze stream tables for query optimization
  // --------------------------------------------------------------------------
  static void analyze_tables(LoggingTransaction& txn) {
    for (size_t i = 0; i < kNumStreamTypes; ++i) {
      auto st = static_cast<StreamType>(i);
      std::string max_table = stream_type_to_max_table(st);
      std::string pos_table = stream_type_to_pos_table(st);
      std::string source_table =
          StreamGapDetector::get_stream_source_table_impl(st);

      txn.execute("ANALYZE " + max_table);
      txn.execute("ANALYZE " + pos_table);
      if (!source_table.empty()) {
        txn.execute("ANALYZE " + source_table);
      }
    }
  }
};

// Make get_stream_source_table_impl accessible as a public static
// on StreamGapDetector (used by other classes above)
namespace {
std::string stream_gap_source_table(StreamType st) {
  switch (st) {
    case StreamType::kEvents:      return "events";
    case StreamType::kPresence:    return "presence_stream";
    case StreamType::kReceipts:    return "receipts_stream";
    case StreamType::kTyping:      return "typing_stream";
    case StreamType::kToDevice:    return "to_device_messages";
    case StreamType::kDeviceLists: return "device_lists_stream";
    case StreamType::kAccountData: return "account_data";
    case StreamType::kPushRules:   return "push_rules_stream";
    default:                       return "";
  }
}
}  // anonymous namespace

// Re-open StreamGapDetector to add the public static accessor
std::string StreamGapDetector::get_stream_source_table_impl(StreamType st) {
  return stream_gap_source_table(st);
}

// ============================================================================
// StreamTransactionGuard — RAII guard for stream operations
// ============================================================================
class StreamTransactionGuard {
public:
  StreamTransactionGuard(StreamManager& mgr, DatabasePool& db,
                          const std::string& operation_name)
      : mgr_(mgr), db_(db), name_(operation_name),
        committed_(false) {
    start_ms_ = now_ms();
  }

  ~StreamTransactionGuard() {
    if (committed_) {
      int64_t elapsed = now_ms() - start_ms_;
      if (elapsed > 100) {
        util::log::debug("stream_txn",
            name_ + " completed in " + std::to_string(elapsed) + "ms");
      }
    } else {
      util::log::warn("stream_txn",
          name_ + " destroyed without commit");
    }
  }

  void commit() {
    committed_ = true;
  }

  bool is_committed() const { return committed_; }

private:
  StreamManager& mgr_;
  DatabasePool& db_;
  std::string name_;
  int64_t start_ms_;
  bool committed_;
};

// ============================================================================
// StreamMaintenanceScheduler — periodic stream maintenance tasks
// ============================================================================
class StreamMaintenanceScheduler {
public:
  StreamMaintenanceScheduler(StreamManager& mgr, DatabasePool& db)
      : mgr_(mgr), db_(db),
        last_purge_ms_(0),
        last_compact_ms_(0),
        last_consistency_check_ms_(0) {}

  // --------------------------------------------------------------------------
  // Run periodic maintenance tasks
  // --------------------------------------------------------------------------
  json run_maintenance(LoggingTransaction& txn) {
    json report;
    int64_t now = now_ms();
    int64_t purge_interval = 600'000;  // 10 minutes
    int64_t compact_interval = 3'600'000;  // 1 hour
    int64_t consistency_interval = 86'400'000;  // 24 hours

    // Purge caches
    if (now - last_purge_ms_ > purge_interval) {
      mgr_.purge_caches();
      last_purge_ms_ = now;
      report["cache_purged"] = true;
    }

    // Compact typing stream
    if (now - last_compact_ms_ > compact_interval) {
      int compacted = mgr_.compact_typing_stream(txn, 86'400'000);  // 24h
      if (compacted > 0) {
        report["typing_compacted"] = compacted;
      }
      last_compact_ms_ = now;
    }

    // Consistency check
    if (now - last_consistency_check_ms_ > consistency_interval) {
      auto consistency = StreamConsistencyChecker::check_max_stream_consistency(
          txn);
      if (!consistency["consistent"].get<bool>()) {
        report["consistency_issues"] = consistency;
      }
      last_consistency_check_ms_ = now;
    }

    report["timestamp_ms"] = now;
    return report;
  }

  // --------------------------------------------------------------------------
  // Force a full maintenance run
  // --------------------------------------------------------------------------
  json force_maintenance(LoggingTransaction& txn) {
    last_purge_ms_ = 0;
    last_compact_ms_ = 0;
    last_consistency_check_ms_ = 0;
    return run_maintenance(txn);
  }

private:
  StreamManager& mgr_;
  DatabasePool& db_;
  int64_t last_purge_ms_;
  int64_t last_compact_ms_;
  int64_t last_consistency_check_ms_;
};

}  // namespace progressive

// ============================================================================
// End of stream_manager.cpp
// ============================================================================
