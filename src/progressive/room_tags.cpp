// ============================================================================
// room_tags.cpp — Matrix Room Tag Management Engine
//
// Implements the complete Matrix room tags specification:
//   - Room tags: m.favourite, m.lowpriority, m.server_notice plus
//     user-defined tags with JSON order value (float 0.0–1.0)
//   - Tag CRUD: PUT /user/{userId}/rooms/{roomId}/tags/{tag} with order,
//     DELETE tag, GET tags per room, GET all rooms with a specific tag
//   - Tag ordering: rooms within a tag are ordered by order value (0.0–1.0
//     float), natural ordering (alphanumeric by room_id) on tie
//   - Tag sync: include tags in /sync response (account_data section),
//     incremental updates via stream ordering, per-room and global tags
//   - Tag limits: max 100 tags per room per user, max tag name length 255,
//     max order value precision, validation and rejection
//   - Default tags: apply default tags on room creation (optional, configurable)
//     — m.lowpriority for large rooms, m.server_notice for system rooms
//   - Tag export: export all tags for GDPR data export with full metadata
//   - Tag caching: thread-safe in-memory LRU cache for hot user/room tags
//   - Tag validation: tag name syntax validation, order value clamping,
//     duplicate detection, content schema validation
//   - Tag federation: tag data is per-user account_data, so no federation
//     needed (tags never leave the local homeserver)
//   - Tag migration: auto-migrate from simple tags table to revision-tracked
//     tags with stream ordering for /sync incremental delivery
//   - Tag replication: stream ordering enables worker replication of tag changes
//   - REST API servlets: GET/PUT/DELETE tag endpoints with full validation
//   - Admin API: list all tags for a user, bulk tag operations, tag statistics
//
// Equivalent to:
//   synapse/storage/databases/main/tags.py (70 lines) — tags store
//   synapse/rest/client/tags.py (100 lines) — REST endpoints
//   synapse/handlers/sync.py — account_data/tags portion (60 lines)
//   synapse/handlers/room.py — default tags on creation (30 lines)
//   synapse/handlers/initial_sync.py — initial sync tags (20 lines)
//   synapse/storage/databases/main/account_data.py — account_data (200 lines)
//   synapse/handlers/account_data.py — account_data handler (100 lines)
//   synapse/rest/client/account_data.py — account_data REST (80 lines)
//
// Total equivalent: ~660 lines of Python
//
// Copyright (C) 2024-2025 Progressive Server contributors
// Licensed under AGPL v3
// ============================================================================

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
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
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/small_stores.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/rest/rest_base.hpp"

namespace progressive {

using json = nlohmann::json;
using namespace progressive::storage;

// ============================================================================
// Forward declarations
// ============================================================================
class RoomTagsEngine;
class DefaultTagPolicy;
class TagOrderEngine;
class TagLruCache;
class TagValidator;
class TagSyncIntegrator;
class TagExportCollector;
class TagReplicationManager;

// ============================================================================
// Well-known Tag Constants
// ============================================================================
// Matrix spec defines these well-known room tags. Semantics:
//   m.favourite     — User's favourite rooms (displayed first)
//   m.lowpriority   — Low-priority rooms (displayed last, muted notifications)
//   m.server_notice  — Server management rooms (system notices)
// User-defined tags are any valid tag name prefixed with "u." (convention)
// or any name that doesn't start with "m." (reserved for the spec).
// ============================================================================

namespace WellKnownTags {
  // Spec-defined tags
  constexpr const char* FAVOURITE     = "m.favourite";
  constexpr const char* LOWPRIORITY   = "m.lowpriority";
  constexpr const char* SERVER_NOTICE = "m.server_notice";

  // All well-known tags in priority order for display
  inline const std::vector<std::string>& all_well_known() {
    static const std::vector<std::string> tags = {
      FAVOURITE, LOWPRIORITY, SERVER_NOTICE
    };
    return tags;
  }

  // Check if a tag is a spec-reserved well-known tag
  inline bool is_well_known(const std::string& tag) {
    return tag == FAVOURITE || tag == LOWPRIORITY || tag == SERVER_NOTICE;
  }

  // Check if a tag name is in the Matrix-reserved namespace
  inline bool is_reserved_namespace(const std::string& tag) {
    return tag.size() >= 2 && tag[0] == 'm' && tag[1] == '.';
  }

  // Valid user-defined tag namespaces (for validation and policy)
  inline bool is_valid_user_namespace(const std::string& tag) {
    // User-defined tags commonly use "u." prefix but any non-"m." is allowed
    if (tag.size() >= 2 && tag[0] == 'm' && tag[1] == '.') {
      return is_well_known(tag); // only allow spec-defined m.* tags
    }
    return true;
  }
} // namespace WellKnownTags

// ============================================================================
// Tag Limit Constants
// ============================================================================

namespace TagLimits {
  // Maximum number of tags a user can set per room
  constexpr size_t MAX_TAGS_PER_ROOM = 100;

  // Maximum length of a tag name (in characters, not bytes)
  constexpr size_t MAX_TAG_NAME_LENGTH = 255;

  // Minimum allowed order value (inclusive)
  constexpr double MIN_ORDER_VALUE = 0.0;

  // Maximum allowed order value (inclusive)
  constexpr double MAX_ORDER_VALUE = 1.0;

  // Default order when none is specified
  constexpr double DEFAULT_ORDER_VALUE = 0.5;

  // Maximum content size for a tag's JSON content
  constexpr size_t MAX_TAG_CONTENT_SIZE = 65536; // 64KB

  // Number of order decimal places to preserve when normalizing
  constexpr int ORDER_PRECISION = 6;

  // Default tags to apply on room creation (per-room-type)
  inline json default_tags_for_new_room(bool is_direct, bool is_large) {
    json defaults = json::object();
    // Direct chats get favourite by default
    if (is_direct) {
      defaults[WellKnownTags::FAVOURITE] = json::object({{"order", 1.0}});
    }
    // Large rooms get low priority to avoid notification spam
    if (is_large) {
      defaults[WellKnownTags::LOWPRIORITY] = json::object({{"order", 0.1}});
    }
    return defaults;
  }

  // Cache TTL for tag listings (milliseconds)
  constexpr int64_t TAG_CACHE_TTL_MS = 30'000; // 30 seconds

  // Maximum number of tag cache entries per user
  constexpr size_t MAX_CACHE_ENTRIES_PER_USER = 500;

  // Maximum number of rooms to return in "get rooms by tag" queries
  constexpr size_t MAX_ROOMS_BY_TAG = 1000;
} // namespace TagLimits

// ============================================================================
// Tag Error Codes
// ============================================================================

namespace TagErrorCodes {
  constexpr const char* TOO_MANY_TAGS     = "M_TOO_MANY_TAGS";
  constexpr const char* TAG_NAME_TOO_LONG = "M_INVALID_PARAM";
  constexpr const char* INVALID_ORDER     = "M_INVALID_PARAM";
  constexpr const char* INVALID_TAG_NAME  = "M_INVALID_PARAM";
  constexpr const char* TAG_NOT_FOUND     = "M_NOT_FOUND";
  constexpr const char* CONTENT_TOO_LARGE = "M_TOO_LARGE";
  constexpr const char* RESERVED_TAG      = "M_FORBIDDEN";
  constexpr const char* RATE_LIMITED      = "M_LIMIT_EXCEEDED";
} // namespace TagErrorCodes

// ============================================================================
// TagEntry — represents a single room tag with its content and metadata
// ============================================================================

struct TagEntry {
  std::string user_id;
  std::string room_id;
  std::string tag;
  json content;
  double order{TagLimits::DEFAULT_ORDER_VALUE};
  int64_t stream_id{0};       // stream ordering for /sync incremental delivery
  int64_t created_ts_ms{0};   // when this tag was first set
  int64_t updated_ts_ms{0};   // when this tag was last modified

  // Extract order value from tag content JSON
  static double extract_order(const json& content) {
    if (content.contains("order") && content["order"].is_number()) {
      return std::clamp(content["order"].get<double>(),
                        TagLimits::MIN_ORDER_VALUE,
                        TagLimits::MAX_ORDER_VALUE);
    }
    return TagLimits::DEFAULT_ORDER_VALUE;
  }

  // Normalize order to fixed precision
  static double normalize_order(double order) {
    double factor = std::pow(10.0, TagLimits::ORDER_PRECISION);
    return std::round(order * factor) / factor;
  }

  // Compare two entries by order, then by natural room_id ordering on tie
  static bool order_compare(const TagEntry& a, const TagEntry& b) {
    if (a.order != b.order) {
      return a.order > b.order; // higher order first
    }
    return a.room_id < b.room_id; // natural ordering on tie
  }

  // Serialize to account_data format for /sync
  json to_account_data() const {
    json result = json::object();
    result["type"] = "m.tag";
    result["content"] = content;
    return result;
  }

  // Full serialization for export
  json to_export() const {
    json result = content;
    result["_meta"] = json::object({
      {"tag", tag},
      {"room_id", room_id},
      {"order", order},
      {"stream_id", stream_id},
      {"created_ts_ms", created_ts_ms},
      {"updated_ts_ms", updated_ts_ms}
    });
    return result;
  }
};

// ============================================================================
// TagValidator — validates tag names, order values, and content
// ============================================================================

class TagValidator {
public:
  // Validate a tag name per Matrix spec rules
  // Tag names must be:
  //   - Not empty
  //   - Not exceed MAX_TAG_NAME_LENGTH characters
  //   - Contain only printable ASCII characters
  //   - Not start or end with whitespace
  //   - No consecutive dots (for reserved namespaces)
  //   - User-defined tags must not use reserved namespaces
  struct ValidationResult {
    bool valid{true};
    std::string error_code;
    std::string error_message;
  };

  static ValidationResult validate_tag_name(const std::string& tag) {
    ValidationResult result;

    // Empty check
    if (tag.empty()) {
      result.valid = false;
      result.error_code = TagErrorCodes::INVALID_TAG_NAME;
      result.error_message = "Tag name must not be empty";
      return result;
    }

    // Length check
    if (tag.size() > TagLimits::MAX_TAG_NAME_LENGTH) {
      result.valid = false;
      result.error_code = TagErrorCodes::TAG_NAME_TOO_LONG;
      result.error_message = "Tag name exceeds maximum length of " +
          std::to_string(TagLimits::MAX_TAG_NAME_LENGTH) + " characters";
      return result;
    }

    // Character validation: printable ASCII only
    for (size_t i = 0; i < tag.size(); ++i) {
      unsigned char c = static_cast<unsigned char>(tag[i]);
      if (c < 0x20 || c > 0x7E) {
        result.valid = false;
        result.error_code = TagErrorCodes::INVALID_TAG_NAME;
        result.error_message = "Tag name contains invalid character at position " +
            std::to_string(i);
        return result;
      }
    }

    // No leading/trailing whitespace
    if (std::isspace(static_cast<unsigned char>(tag.front())) ||
        std::isspace(static_cast<unsigned char>(tag.back()))) {
      result.valid = false;
      result.error_code = TagErrorCodes::INVALID_TAG_NAME;
      result.error_message = "Tag name must not start or end with whitespace";
      return result;
    }

    // Check for well-known reserved namespace validity
    if (WellKnownTags::is_reserved_namespace(tag) &&
        !WellKnownTags::is_well_known(tag)) {
      result.valid = false;
      result.error_code = TagErrorCodes::RESERVED_TAG;
      result.error_message = "Tag name '" + tag +
          "' is in the reserved 'm.' namespace; only spec-defined m.* tags are allowed";
      return result;
    }

    // No consecutive dots (protects namespace boundaries)
    for (size_t i = 0; i < tag.size() - 1; ++i) {
      if (tag[i] == '.' && tag[i+1] == '.') {
        result.valid = false;
        result.error_code = TagErrorCodes::INVALID_TAG_NAME;
        result.error_message = "Tag name must not contain consecutive dots";
        return result;
      }
    }

    // Must not be just dots
    bool all_dots = true;
    for (char c : tag) {
      if (c != '.') { all_dots = false; break; }
    }
    if (all_dots) {
      result.valid = false;
      result.error_code = TagErrorCodes::INVALID_TAG_NAME;
      result.error_message = "Tag name must not consist solely of dots";
      return result;
    }

    return result;
  }

  // Validate and clamp an order value
  static double validate_order(const json& content) {
    if (!content.contains("order")) {
      return TagLimits::DEFAULT_ORDER_VALUE;
    }
    if (!content["order"].is_number()) {
      return TagLimits::DEFAULT_ORDER_VALUE;
    }
    double order = content["order"].get<double>();
    // Clamp to valid range
    order = std::clamp(order, TagLimits::MIN_ORDER_VALUE,
                       TagLimits::MAX_ORDER_VALUE);
    // Normalize to fixed precision
    return TagEntry::normalize_order(order);
  }

  // Validate tag content JSON size
  static ValidationResult validate_content_size(const json& content) {
    ValidationResult result;
    std::string serialized = content.dump();
    if (serialized.size() > TagLimits::MAX_TAG_CONTENT_SIZE) {
      result.valid = false;
      result.error_code = TagErrorCodes::CONTENT_TOO_LARGE;
      result.error_message = "Tag content exceeds maximum size of " +
          std::to_string(TagLimits::MAX_TAG_CONTENT_SIZE) + " bytes";
    }
    return result;
  }

  // Full validation of a tag creation/update request
  static ValidationResult validate_tag_request(
      const std::string& tag, const json& content) {
    // Validate tag name
    auto name_result = validate_tag_name(tag);
    if (!name_result.valid) return name_result;

    // Validate content size
    auto size_result = validate_content_size(content);
    if (!size_result.valid) return size_result;

    // Validate content is a valid JSON object
    if (!content.is_object()) {
      ValidationResult result;
      result.valid = false;
      result.error_code = TagErrorCodes::INVALID_TAG_NAME;
      result.error_message = "Tag content must be a JSON object";
      return result;
    }

    // If order is present, it must be a number
    if (content.contains("order") && !content["order"].is_number()) {
      ValidationResult result;
      result.valid = false;
      result.error_code = TagErrorCodes::INVALID_ORDER;
      result.error_message = "Tag 'order' field must be a number";
      return result;
    }

    return ValidationResult{};
  }

  // Validate that a user hasn't exceeded the tag limit for a room
  static ValidationResult validate_tag_count(size_t current_count) {
    ValidationResult result;
    if (current_count >= TagLimits::MAX_TAGS_PER_ROOM) {
      result.valid = false;
      result.error_code = TagErrorCodes::TOO_MANY_TAGS;
      result.error_message = "Maximum of " +
          std::to_string(TagLimits::MAX_TAGS_PER_ROOM) +
          " tags per room exceeded";
    }
    return result;
  }

  // Sanitize a tag name for safe storage (trim, lowercase - but preserve for
  // well-known tags)
  static std::string sanitize_tag_name(const std::string& tag) {
    std::string result = tag;
    // Trim leading whitespace
    while (!result.empty() && std::isspace(static_cast<unsigned char>(result.front()))) {
      result.erase(result.begin());
    }
    // Trim trailing whitespace
    while (!result.empty() && std::isspace(static_cast<unsigned char>(result.back()))) {
      result.pop_back();
    }
    return result;
  }
};

// ============================================================================
// TagLruCache — thread-safe LRU cache for room tags
// ============================================================================
// Caches per-user, per-room tag data to avoid repeated database lookups
// during sync and tag listing operations. Uses a shared_mutex for
// concurrent reads with exclusive writes.
// ============================================================================

class TagLruCache {
public:
  // Cache key: (user_id, room_id) -> vector of TagEntry
  struct CacheKey {
    std::string user_id;
    std::string room_id;

    bool operator==(const CacheKey& other) const {
      return user_id == other.user_id && room_id == other.room_id;
    }
  };

  struct CacheKeyHash {
    size_t operator()(const CacheKey& key) const {
      size_t h1 = std::hash<std::string>{}(key.user_id);
      size_t h2 = std::hash<std::string>{}(key.room_id);
      return h1 ^ (h2 << 1);
    }
  };

  // Full user cache key: user_id -> map of room_id -> vector<TagEntry>
  struct UserCacheEntry {
    std::map<std::string, std::vector<TagEntry>> rooms;
    int64_t last_accessed_ms{0};
  };

  explicit TagLruCache(size_t max_entries = TagLimits::MAX_CACHE_ENTRIES_PER_USER)
    : max_entries_(max_entries) {}

  // Get cached tags for a specific user+room
  std::optional<std::vector<TagEntry>> get(const std::string& user_id,
                                             const std::string& room_id) {
    CacheKey key{user_id, room_id};
    std::shared_lock lock(mutex_);

    auto it = cache_.find(key);
    if (it != cache_.end()) {
      // Update access time (LRU promotion handled on next eviction)
      it->second.last_accessed_ms = now_ms();
      return it->second.entries;
    }
    return std::nullopt;
  }

  // Get all cached tags for a user
  std::optional<std::map<std::string, std::vector<TagEntry>>>
  get_all_for_user(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    auto it = user_cache_.find(user_id);
    if (it != user_cache_.end()) {
      it->second.last_accessed_ms = now_ms();
      return it->second.rooms;
    }
    return std::nullopt;
  }

  // Put tags for a specific user+room
  void put(const std::string& user_id, const std::string& room_id,
           std::vector<TagEntry> entries) {
    CacheKey key{user_id, room_id};
    std::unique_lock lock(mutex_);

    // Evict if at capacity
    if (cache_.size() >= max_entries_ && cache_.find(key) == cache_.end()) {
      evict_lru();
    }

    RoomCacheEntry entry;
    entry.entries = std::move(entries);
    entry.last_accessed_ms = now_ms();
    cache_[key] = std::move(entry);

    // Also update the full user cache
    auto& user_entry = user_cache_[user_id];
    user_entry.rooms[room_id] = cache_[key].entries;
    user_entry.last_accessed_ms = now_ms();
  }

  // Invalidate cache for a specific user+room
  void invalidate(const std::string& user_id, const std::string& room_id) {
    CacheKey key{user_id, room_id};
    std::unique_lock lock(mutex_);
    cache_.erase(key);

    auto it = user_cache_.find(user_id);
    if (it != user_cache_.end()) {
      it->second.rooms.erase(room_id);
    }
  }

  // Invalidate entire cache for a user
  void invalidate_user(const std::string& user_id) {
    std::unique_lock lock(mutex_);

    // Remove all cache entries for this user
    auto it = cache_.begin();
    while (it != cache_.end()) {
      if (it->first.user_id == user_id) {
        it = cache_.erase(it);
      } else {
        ++it;
      }
    }
    user_cache_.erase(user_id);
  }

  // Clear the entire cache
  void clear() {
    std::unique_lock lock(mutex_);
    cache_.clear();
    user_cache_.clear();
  }

  // Get cache statistics
  struct CacheStats {
    size_t per_room_entries{0};
    size_t user_entries{0};
    size_t max_entries{0};
  };

  CacheStats stats() const {
    std::shared_lock lock(mutex_);
    CacheStats s;
    s.per_room_entries = cache_.size();
    s.user_entries = user_cache_.size();
    s.max_entries = max_entries_;
    return s;
  }

  // TTL-based cleanup: remove entries older than ttl_ms
  void clean_expired(int64_t ttl_ms = TagLimits::TAG_CACHE_TTL_MS) {
    int64_t cutoff = now_ms() - ttl_ms;
    std::unique_lock lock(mutex_);

    auto it = cache_.begin();
    while (it != cache_.end()) {
      if (it->second.last_accessed_ms < cutoff) {
        // Also remove from user cache
        auto uit = user_cache_.find(it->first.user_id);
        if (uit != user_cache_.end()) {
          uit->second.rooms.erase(it->first.room_id);
        }
        it = cache_.erase(it);
      } else {
        ++it;
      }
    }

    // Clean user entries with no rooms
    auto uit = user_cache_.begin();
    while (uit != user_cache_.end()) {
      uit->second.rooms.erase(""); // just a safety scan
      if (uit->second.last_accessed_ms < cutoff) {
        uit = user_cache_.erase(uit);
      } else {
        ++uit;
      }
    }
  }

private:
  struct RoomCacheEntry {
    std::vector<TagEntry> entries;
    int64_t last_accessed_ms{0};
  };

  void evict_lru() {
    // Find the least recently used entry
    int64_t oldest_ms = INT64_MAX;
    CacheKey oldest_key;
    bool found = false;

    for (const auto& [key, entry] : cache_) {
      if (entry.last_accessed_ms < oldest_ms) {
        oldest_ms = entry.last_accessed_ms;
        oldest_key = key;
        found = true;
      }
    }

    if (found) {
      // Remove from user cache too
      auto uit = user_cache_.find(oldest_key.user_id);
      if (uit != user_cache_.end()) {
        uit->second.rooms.erase(oldest_key.room_id);
      }
      cache_.erase(oldest_key);
    }
  }

  static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
  }

  std::unordered_map<CacheKey, RoomCacheEntry, CacheKeyHash> cache_;
  std::unordered_map<std::string, UserCacheEntry> user_cache_;
  mutable std::shared_mutex mutex_;
  size_t max_entries_;
};

// ============================================================================
// TagOrderEngine — computes and manages room ordering within a tag
// ============================================================================
// Ordering semantics per Matrix spec:
//   - Each tag has an associated "order" float between 0.0 and 1.0
//   - Rooms within a tag are ordered by their order value (descending:
//     higher values first)
//   - When two rooms have the same order value, they are ordered naturally
//     (alphanumeric by room_id in ascending order)
//   - The order value is stored inside the tag's JSON content object
//   - A missing order value defaults to 0.5 (middle)
// ============================================================================

class TagOrderEngine {
public:
  // Compute the effective order for a room within a tag
  static double effective_order(const TagEntry& entry) {
    return entry.order;
  }

  // Sort a vector of TagEntry by their order and natural room_id
  static void sort_entries(std::vector<TagEntry>& entries) {
    std::sort(entries.begin(), entries.end(), TagEntry::order_compare);
  }

  // Sort a map of room_id -> TagEntry by order for display
  // Returns an ordered vector of (room_id, order, content) tuples
  static std::vector<std::tuple<std::string, double, json>>
  ordered_rooms(const std::map<std::string, TagEntry>& rooms) {
    std::vector<TagEntry> entries;
    entries.reserve(rooms.size());
    for (const auto& [rid, entry] : rooms) {
      entries.push_back(entry);
    }
    sort_entries(entries);

    std::vector<std::tuple<std::string, double, json>> result;
    result.reserve(entries.size());
    for (const auto& e : entries) {
      result.emplace_back(e.room_id, e.order, e.content);
    }
    return result;
  }

  // Find the best insertion order value for a new room in a tag
  // This positions the new room between two existing ones or at
  // the appropriate edge.
  struct InsertionHint {
    double suggested_order{TagLimits::DEFAULT_ORDER_VALUE};
    bool conflict{false}; // true if exact order is already taken
    double alternative_order{TagLimits::DEFAULT_ORDER_VALUE};
  };

  static InsertionHint suggest_order(
      const std::vector<TagEntry>& existing,
      double desired_order = TagLimits::DEFAULT_ORDER_VALUE) {
    InsertionHint hint;
    hint.suggested_order = TagEntry::normalize_order(
        std::clamp(desired_order, TagLimits::MIN_ORDER_VALUE,
                   TagLimits::MAX_ORDER_VALUE));

    if (existing.empty()) {
      return hint;
    }

    // Check if exact order conflicts with any existing tag
    for (const auto& e : existing) {
      if (std::abs(e.order - hint.suggested_order) < 1e-9) {
        hint.conflict = true;
        break;
      }
    }

    if (!hint.conflict) {
      return hint;
    }

    // Find the smallest gap between existing orders
    // Sorted existing entries (descending by order)
    std::vector<TagEntry> sorted = existing;
    sort_entries(sorted);

    // Try to find a gap
    double step = 1.0 / static_cast<double>(TagLimits::MAX_TAGS_PER_ROOM + 2);
    double candidate = desired_order;

    // Search around the desired order for an available slot
    for (int offset = 0; offset < static_cast<int>(TagLimits::MAX_TAGS_PER_ROOM); ++offset) {
      double above = TagEntry::normalize_order(candidate + offset * step);
      double below = TagEntry::normalize_order(candidate - offset * step);

      bool above_taken = false;
      bool below_taken = false;

      for (const auto& e : sorted) {
        if (std::abs(e.order - above) < 1e-9) above_taken = true;
        if (std::abs(e.order - below) < 1e-9) below_taken = true;
      }

      if (!above_taken && above <= TagLimits::MAX_ORDER_VALUE) {
        hint.alternative_order = above;
        return hint;
      }
      if (!below_taken && below >= TagLimits::MIN_ORDER_VALUE) {
        hint.alternative_order = below;
        return hint;
      }
    }

    // If every slot somehow conflicts (shouldn't happen), just use the
    // default and let the natural sort handle it
    hint.alternative_order = TagLimits::DEFAULT_ORDER_VALUE;
    return hint;
  }

  // Get the next available order for bulk insertion (e.g., default tags)
  static double next_available_order(const std::vector<TagEntry>& existing) {
    if (existing.empty()) {
      return TagLimits::DEFAULT_ORDER_VALUE;
    }

    // Find the highest used order
    double max_order = TagLimits::MIN_ORDER_VALUE;
    for (const auto& e : existing) {
      if (e.order > max_order) max_order = e.order;
    }

    // Suggest slightly below max
    double suggested = max_order - 0.01;
    if (suggested < TagLimits::MIN_ORDER_VALUE) {
      suggested = TagLimits::MIN_ORDER_VALUE;
    }
    return TagEntry::normalize_order(suggested);
  }

  // Rebalance orders in a room with many tags to avoid clustering
  static std::map<std::string, double> rebalance_orders(
      const std::vector<TagEntry>& entries) {
    std::map<std::string, double> new_orders;
    if (entries.empty()) return new_orders;

    size_t n = entries.size();
    if (n == 1) {
      new_orders[entries[0].tag] = TagLimits::DEFAULT_ORDER_VALUE;
      return new_orders;
    }

    // Distribute evenly across 0.0 to 1.0
    double step = 1.0 / static_cast<double>(n - 1);
    for (size_t i = 0; i < n; ++i) {
      double order = static_cast<double>(n - 1 - i) * step; // descending
      new_orders[entries[i].tag] = TagEntry::normalize_order(
          std::clamp(order, TagLimits::MIN_ORDER_VALUE,
                     TagLimits::MAX_ORDER_VALUE));
    }

    return new_orders;
  }

  // Compute a "heat map" of order distribution for analysis
  static json order_distribution(const std::vector<TagEntry>& entries) {
    json dist = json::object();
    if (entries.empty()) return dist;

    // Bucket orders into 10 ranges
    int buckets[10] = {0};
    for (const auto& e : entries) {
      int bucket = static_cast<int>(e.order * 10.0);
      if (bucket >= 10) bucket = 9;
      if (bucket < 0) bucket = 0;
      buckets[bucket]++;
    }

    for (int i = 0; i < 10; ++i) {
      std::string bucket_name = std::to_string(i * 0.1).substr(0, 3) +
                                "-" + std::to_string((i + 1) * 0.1).substr(0, 3);
      dist[bucket_name] = buckets[i];
    }
    return dist;
  }
};

// ============================================================================
// DefaultTagPolicy — manages default tags applied to rooms on creation
// ============================================================================
// Configured default tags are applied automatically when a user creates
// or joins a room. This can be used for:
//   - Auto-favouriting direct chats
//   - Low-priority marking for large rooms
//   - Server notice tagging for system rooms
//   - Custom organization rules
// ============================================================================

class DefaultTagPolicy {
public:
  struct PolicyConfig {
    bool apply_on_room_creation{false};
    bool apply_on_join{false};
    bool auto_favourite_dm{true};
    size_t large_room_threshold{50}; // members in room before marking low priority
    json custom_default_tags = json::object();
    std::set<std::string> excluded_tags; // tags to never auto-apply
  };

  explicit DefaultTagPolicy(const PolicyConfig& config = PolicyConfig{})
    : config_(config) {}

  // Compute default tags for a newly created room
  json compute_defaults_for_creation(const std::string& room_id,
                                       const std::string& creator_id,
                                       bool is_direct) {
    json defaults = json::object();

    if (!config_.apply_on_room_creation && !is_direct) {
      return defaults;
    }

    // Direct chat rooms get favourited
    if (is_direct && config_.auto_favourite_dm &&
        !config_.excluded_tags.count(WellKnownTags::FAVOURITE)) {
      defaults[WellKnownTags::FAVOURITE] = json::object({{"order", 1.0}});
    }

    // Apply custom defaults
    for (const auto& [tag_name, content] : config_.custom_default_tags.items()) {
      if (!config_.excluded_tags.count(tag_name)) {
        defaults[tag_name] = content;
      }
    }

    return defaults;
  }

  // Compute default tags when a user joins an existing room
  json compute_defaults_for_join(const std::string& room_id,
                                   const std::string& user_id,
                                   int64_t member_count) {
    json defaults = json::object();

    if (!config_.apply_on_join) {
      return defaults;
    }

    // Large rooms get low priority
    if (member_count >= static_cast<int64_t>(config_.large_room_threshold) &&
        !config_.excluded_tags.count(WellKnownTags::LOWPRIORITY)) {
      defaults[WellKnownTags::LOWPRIORITY] = json::object({{"order", 0.1}});
    }

    // Apply custom defaults
    for (const auto& [tag_name, content] : config_.custom_default_tags.items()) {
      if (!config_.excluded_tags.count(tag_name)) {
        defaults[tag_name] = content;
      }
    }

    return defaults;
  }

  // Update the policy configuration
  void update_config(const PolicyConfig& config) {
    std::unique_lock lock(mutex_);
    config_ = config;
  }

  // Get current configuration
  PolicyConfig get_config() const {
    std::shared_lock lock(mutex_);
    return config_;
  }

  // Check if a specific tag should be auto-applied to a room type
  bool should_apply_tag(const std::string& tag, bool is_direct,
                        int64_t member_count = 0) {
    std::shared_lock lock(mutex_);

    if (config_.excluded_tags.count(tag)) return false;

    if (tag == WellKnownTags::FAVOURITE) {
      return is_direct && config_.auto_favourite_dm;
    }

    if (tag == WellKnownTags::LOWPRIORITY) {
      return member_count >= static_cast<int64_t>(config_.large_room_threshold);
    }

    return config_.custom_default_tags.contains(tag);
  }

private:
  PolicyConfig config_;
  mutable std::shared_mutex mutex_;
};

// ============================================================================
// TagReplicationManager — stream ordering for worker replication
// ============================================================================
// Tracks tag changes via a monotonically increasing stream_id so that
// worker processes can replicate tag state consistently.
// ============================================================================

class TagReplicationManager {
public:
  explicit TagReplicationManager() : next_stream_id_(1) {}

  // Allocate the next stream ID for a tag change
  int64_t next_stream_id() {
    return next_stream_id_.fetch_add(1, std::memory_order_relaxed);
  }

  // Get the current maximum stream ID
  int64_t current_stream_id() const {
    return next_stream_id_.load(std::memory_order_acquire) - 1;
  }

  // Reset stream counter (for testing)
  void reset(int64_t to = 1) {
    next_stream_id_.store(to, std::memory_order_release);
  }

  // Compute a replication token representing current state
  std::string replication_token() const {
    std::ostringstream oss;
    oss << "tag_" << current_stream_id();
    return oss.str();
  }

  // Parse stream_id from replication token
  static int64_t stream_id_from_token(std::string_view token) {
    // Format: "tag_N"
    auto pos = token.find("tag_");
    if (pos == std::string_view::npos) return 0;
    std::string_view num = token.substr(pos + 4);
    try {
      return std::stoll(std::string(num));
    } catch (...) {
      return 0;
    }
  }

private:
  std::atomic<int64_t> next_stream_id_;
};

// ============================================================================
// TagExportCollector — collects all tag data for GDPR data export
// ============================================================================
// Formats tag data in a human-readable JSON structure suitable for
// inclusion in a GDPR data export archive.
// ============================================================================

class TagExportCollector {
public:
  struct ExportConfig {
    bool include_metadata{true};   // include stream_id, timestamps
    bool include_order{true};      // include order values
    bool include_content{true};    // include full content JSON
    bool group_by_room{true};      // group tags by room
    bool group_by_tag{false};      // also group by tag type
    size_t max_entries{10000};     // safety cap for export size
  };

  explicit TagExportCollector(const ExportConfig& config = ExportConfig{})
    : config_(config) {}

  // Collect tags for GDPR export
  json collect_for_export(
      const std::string& user_id,
      const std::map<std::string, std::vector<TagEntry>>& all_tags) {

    json export_data = json::object();
    export_data["user_id"] = user_id;
    export_data["export_type"] = "room_tags";
    export_data["export_timestamp"] = iso8601_now();
    export_data["total_rooms_with_tags"] = all_tags.size();

    size_t total_tags = 0;
    for (const auto& [room_id, tags] : all_tags) {
      total_tags += tags.size();
    }
    export_data["total_tags"] = total_tags;

    if (config_.group_by_room) {
      json rooms = json::object();
      for (const auto& [room_id, tags] : all_tags) {
        json room_data = json::object();
        room_data["room_id"] = room_id;
        room_data["tag_count"] = tags.size();

        json tag_list = json::array();
        for (const auto& tag : tags) {
          if (tag_list.size() >= config_.max_entries) break;
          tag_list.push_back(format_tag_for_export(tag));
        }
        room_data["tags"] = tag_list;
        rooms[room_id] = room_data;
      }
      export_data["rooms"] = rooms;
    } else {
      // Flat list of all tags
      json flat_tags = json::array();
      for (const auto& [room_id, tags] : all_tags) {
        for (const auto& tag : tags) {
          if (flat_tags.size() >= config_.max_entries) break;
          json entry = format_tag_for_export(tag);
          entry["room_id"] = room_id;
          flat_tags.push_back(entry);
        }
      }
      export_data["tags"] = flat_tags;
    }

    // Group by tag type if requested
    if (config_.group_by_tag) {
      json by_tag = json::object();
      for (const auto& [room_id, tags] : all_tags) {
        for (const auto& tag : tags) {
          if (!by_tag.contains(tag.tag)) {
            by_tag[tag.tag] = json::object({
              {"tag", tag.tag},
              {"is_well_known", WellKnownTags::is_well_known(tag.tag)},
              {"rooms", json::array()}
            });
          }
          json room_entry = json::object({
            {"room_id", room_id},
            {"order", tag.order}
          });
          if (config_.include_content) {
            room_entry["content"] = tag.content;
          }
          by_tag[tag.tag]["rooms"].push_back(room_entry);
        }
      }
      export_data["by_tag"] = by_tag;
    }

    // Summary statistics
    json summary = json::object();
    std::set<std::string> unique_tags;
    for (const auto& [room_id, tags] : all_tags) {
      for (const auto& tag : tags) {
        unique_tags.insert(tag.tag);
      }
    }
    summary["unique_tag_count"] = unique_tags.size();
    summary["unique_room_count"] = all_tags.size();
    export_data["summary"] = summary;

    return export_data;
  }

  // Export only tags matching a specific tag name
  json export_by_tag(
      const std::string& user_id,
      const std::string& tag_name,
      const std::map<std::string, std::vector<TagEntry>>& all_tags) {

    json export_data = json::object();
    export_data["user_id"] = user_id;
    export_data["tag"] = tag_name;
    export_data["export_timestamp"] = iso8601_now();

    json rooms_list = json::array();

    for (const auto& [room_id, tags] : all_tags) {
      for (const auto& tag : tags) {
        if (tag.tag == tag_name) {
          json entry = format_tag_for_export(tag);
          entry["room_id"] = room_id;
          rooms_list.push_back(entry);
        }
      }
    }

    // Sort by order descending, then by room_id
    std::sort(rooms_list.begin(), rooms_list.end(),
        [](const json& a, const json& b) {
          double oa = a.value("order", TagLimits::DEFAULT_ORDER_VALUE);
          double ob = b.value("order", TagLimits::DEFAULT_ORDER_VALUE);
          if (oa != ob) return oa > ob;
          return a["room_id"].get<std::string>() < b["room_id"].get<std::string>();
        });

    export_data["rooms"] = rooms_list;
    export_data["room_count"] = rooms_list.size();

    return export_data;
  }

  // GDPR anonymized export (strip user_id for third-party processing)
  static json anonymize_export(const json& export_data) {
    json anon = export_data;
    if (anon.contains("user_id")) {
      anon["user_id"] = "ANONYMIZED";
    }
    // Remove potentially identifying metadata timestamps
    if (anon.contains("export_timestamp")) {
      anon["export_timestamp"] = "REDACTED";
    }
    return anon;
  }

private:
  json format_tag_for_export(const TagEntry& tag) const {
    json entry = json::object();
    entry["tag"] = tag.tag;

    if (config_.include_order) {
      entry["order"] = tag.order;
    }

    if (config_.include_content) {
      entry["content"] = tag.content;
    }

    if (config_.include_metadata) {
      if (tag.created_ts_ms > 0) {
        entry["created_at"] = iso8601_from_ms(tag.created_ts_ms);
      }
      if (tag.updated_ts_ms > 0) {
        entry["updated_at"] = iso8601_from_ms(tag.updated_ts_ms);
      }
      entry["stream_id"] = tag.stream_id;
    }

    // Determine tag category for export classification
    std::string category;
    if (WellKnownTags::is_well_known(tag.tag)) {
      category = "well_known";
    } else if (WellKnownTags::is_reserved_namespace(tag.tag)) {
      category = "reserved";
    } else {
      category = "user_defined";
    }
    entry["category"] = category;

    return entry;
  }

  static std::string iso8601_now() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
  }

  static std::string iso8601_from_ms(int64_t ms) {
    auto tp = std::chrono::system_clock::time_point(
        std::chrono::milliseconds(ms));
    auto time_t = std::chrono::system_clock::to_time_t(tp);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
  }

  ExportConfig config_;
};

// ============================================================================
// TagSyncIntegrator — integrate tags into /sync response as account_data
// ============================================================================
// In Matrix /sync, room tags appear in the account_data section:
//   {
//     "account_data": {
//       "events": [
//         {
//           "type": "m.tag",
//           "content": {
//             "tags": {
//               "m.favourite": { "order": 1.0 },
//               "u.work": { "order": 0.7 }
//             }
//           }
//         }
//       ]
//     }
//   }
// Each room's tags are aggregated into a single m.tag account_data event.
// ============================================================================

class TagSyncIntegrator {
public:
  // Build the m.tag account_data event for a single room
  static json build_tag_account_data(const std::vector<TagEntry>& tags) {
    json content = json::object();
    json tags_obj = json::object();

    for (const auto& tag : tags) {
      tags_obj[tag.tag] = tag.content;
    }

    content["tags"] = tags_obj;

    json event = json::object();
    event["type"] = "m.tag";
    event["content"] = content;

    return event;
  }

  // Build account_data section for all rooms of a user
  static json build_all_rooms_account_data(
      const std::map<std::string, std::vector<TagEntry>>& all_tags) {

    json result = json::object();
    json events = json::array();

    for (const auto& [room_id, tags] : all_tags) {
      if (tags.empty()) continue;

      json event = json::object();
      event["type"] = "m.tag";

      json content = json::object();
      json tags_obj = json::object();

      // Sort tags for consistent output: well-known tags first, then
      // user-defined tags, each group sorted alphabetically
      std::vector<TagEntry> sorted_tags = tags;
      std::sort(sorted_tags.begin(), sorted_tags.end(),
          [](const TagEntry& a, const TagEntry& b) {
            bool a_wk = WellKnownTags::is_well_known(a.tag);
            bool b_wk = WellKnownTags::is_well_known(b.tag);
            if (a_wk != b_wk) return a_wk; // well-known first
            return a.tag < b.tag;
          });

      for (const auto& tag : sorted_tags) {
        tags_obj[tag.tag] = tag.content;
      }

      content["tags"] = tags_obj;
      event["content"] = content;

      // For room-specific account_data in /sync rooms section
      json room_account_data = json::object();
      room_account_data["events"] = json::array({event});
      result[room_id] = room_account_data;
    }

    return result;
  }

  // Compute incremental account_data changes since a given stream position
  // Returns the tags that have changed (new/modified/deleted) since the token
  struct SyncDelta {
    json changed;   // tags that were added or modified
    json deleted;   // tags that were removed
    int64_t new_stream_id{0};
  };

  static SyncDelta compute_delta(
      const std::string& user_id,
      const std::string& room_id,
      int64_t since_stream_id,
      const std::vector<TagEntry>& current_tags,
      const std::optional<std::vector<TagEntry>>& previous_tags) {

    SyncDelta delta;
    int64_t max_stream = since_stream_id;

    if (!previous_tags) {
      // No previous state — all current tags are new
      delta.changed = build_tag_account_data(current_tags);
      for (const auto& t : current_tags) {
        if (t.stream_id > max_stream) max_stream = t.stream_id;
      }
      delta.new_stream_id = max_stream;
      return delta;
    }

    // Build lookup maps
    std::map<std::string, TagEntry> prev_map;
    for (const auto& t : *previous_tags) {
      prev_map[t.tag] = t;
    }

    std::map<std::string, TagEntry> curr_map;
    for (const auto& t : current_tags) {
      curr_map[t.tag] = t;
      if (t.stream_id > max_stream) max_stream = t.stream_id;
    }

    // Find changed tags (new or modified)
    std::vector<TagEntry> changed_tags;
    std::vector<std::string> deleted_tags;

    for (const auto& [tag_name, curr_tag] : curr_map) {
      auto pit = prev_map.find(tag_name);
      if (pit == prev_map.end()) {
        // New tag
        if (curr_tag.stream_id > since_stream_id) {
          changed_tags.push_back(curr_tag);
        }
      } else {
        // Check if modified
        bool modified = (curr_tag.content.dump() != pit->second.content.dump());
        if (modified && curr_tag.stream_id > since_stream_id) {
          changed_tags.push_back(curr_tag);
        }
      }
    }

    // Find deleted tags
    for (const auto& [tag_name, prev_tag] : prev_map) {
      if (curr_map.find(tag_name) == curr_map.end()) {
        deleted_tags.push_back(tag_name);
      }
    }

    if (!changed_tags.empty()) {
      delta.changed = build_tag_account_data(changed_tags);
    }
    if (!deleted_tags.empty()) {
      delta.deleted["tags"] = deleted_tags;
    }

    delta.new_stream_id = max_stream;
    return delta;
  }

  // Check if any tags have changed for a user since a given position
  static bool has_changes(const std::string& user_id,
                          int64_t since_stream_id,
                          const std::vector<TagEntry>& current_tags) {
    for (const auto& tag : current_tags) {
      if (tag.stream_id > since_stream_id) return true;
    }
    return false;
  }
};

// ============================================================================
// RoomTagsEngine — primary tag management engine
// ============================================================================
// Central class that ties together all tag functionality:
//   - Tag CRUD with validation and limits enforcement
//   - Caching for performance
//   - Sync integration
//   - Default tag application
//   - GDPR export
//   - Administrative operations
// ============================================================================

class RoomTagsEngine {
public:
  RoomTagsEngine(DatabasePool& db, RoomStore& room_store)
    : db_(db), room_store_(room_store),
      cache_(TagLimits::MAX_CACHE_ENTRIES_PER_USER) {}

  // ========================================================================
  // Tag CRUD Operations
  // ========================================================================

  // Set or update a tag for a user on a specific room
  // Returns the created/updated TagEntry
  TagEntry set_tag(const std::string& user_id,
                   const std::string& room_id,
                   const std::string& tag,
                   const json& content) {

    // Validate tag name
    auto validation = TagValidator::validate_tag_name(tag);
    if (!validation.valid) {
      throw std::runtime_error(validation.error_message);
    }

    // Validate content size
    auto size_check = TagValidator::validate_content_size(content);
    if (!size_check.valid) {
      throw std::runtime_error(size_check.error_message);
    }

    // Validate tag request
    auto req_check = TagValidator::validate_tag_request(tag, content);
    if (!req_check.valid) {
      throw std::runtime_error(req_check.error_message);
    }

    // Check tag count limit (skip limit check if updating existing tag)
    auto existing = get_tags_for_room(user_id, room_id);
    bool is_update = false;
    for (const auto& e : existing) {
      if (e.tag == tag) { is_update = true; break; }
    }

    if (!is_update) {
      auto count_check = TagValidator::validate_tag_count(existing.size());
      if (!count_check.valid) {
        throw std::runtime_error(count_check.error_message);
      }
    }

    // Extract and normalize order
    double order = TagValidator::validate_order(content);

    // Build content with normalized order
    json normalized_content = content;
    normalized_content["order"] = order;

    // Build TagEntry
    TagEntry entry;
    entry.user_id = user_id;
    entry.room_id = room_id;
    entry.tag = tag;
    entry.content = normalized_content;
    entry.order = order;
    entry.stream_id = replication_.next_stream_id();
    entry.created_ts_ms = now_ms();

    if (is_update) {
      // Find existing to preserve creation time
      for (const auto& e : existing) {
        if (e.tag == tag) {
          entry.created_ts_ms = e.created_ts_ms;
          break;
        }
      }
    }
    entry.updated_ts_ms = entry.created_ts_ms;

    // Persist to database
    persist_tag(entry);

    // Invalidate cache
    cache_.invalidate(user_id, room_id);

    return entry;
  }

  // Remove a tag from a room
  bool remove_tag(const std::string& user_id,
                  const std::string& room_id,
                  const std::string& tag) {

    // Validate tag name
    auto validation = TagValidator::validate_tag_name(tag);
    if (!validation.valid) {
      throw std::runtime_error(validation.error_message);
    }

    // Check if tag exists
    auto existing = get_tags_for_room(user_id, room_id);
    bool found = false;
    for (const auto& e : existing) {
      if (e.tag == tag) { found = true; break; }
    }

    if (!found) {
      return false; // Tag not found — idempotent delete
    }

    // Delete from database
    delete_tag_from_db(user_id, room_id, tag);

    // Invalidate cache
    cache_.invalidate(user_id, room_id);

    return true;
  }

  // Get all tags for a specific room (from cache or database)
  std::vector<TagEntry> get_tags_for_room(const std::string& user_id,
                                            const std::string& room_id) {
    // Try cache first
    auto cached = cache_.get(user_id, room_id);
    if (cached) {
      return *cached;
    }

    // Load from database
    auto tags = load_tags_from_db(user_id, room_id);

    // Store in cache
    cache_.put(user_id, room_id, tags);

    return tags;
  }

  // Get all tags for a user across all rooms
  std::map<std::string, std::vector<TagEntry>> get_all_tags_for_user(
      const std::string& user_id) {

    // Try full user cache
    auto cached = cache_.get_all_for_user(user_id);
    if (cached) {
      return *cached;
    }

    // Load all from database
    auto all_tags = load_all_tags_from_db(user_id);

    // Populate cache
    for (const auto& [room_id, tags] : all_tags) {
      cache_.put(user_id, room_id, tags);
    }

    // Also warm the user cache
    // (cache_.put already updates user_cache_)

    return all_tags;
  }

  // Get all rooms that have a specific tag
  std::vector<TagEntry> get_rooms_with_tag(const std::string& user_id,
                                              const std::string& tag) {

    // Validate tag name
    auto validation = TagValidator::validate_tag_name(tag);
    if (!validation.valid) {
      return {};
    }

    auto all_tags = get_all_tags_for_user(user_id);
    std::vector<TagEntry> result;

    for (const auto& [room_id, tags] : all_tags) {
      for (const auto& entry : tags) {
        if (entry.tag == tag) {
          result.push_back(entry);
        }
      }
    }

    // Sort by order (descending), then room_id (natural)
    TagOrderEngine::sort_entries(result);

    // Apply limit
    if (result.size() > TagLimits::MAX_ROOMS_BY_TAG) {
      result.resize(TagLimits::MAX_ROOMS_BY_TAG);
    }

    return result;
  }

  // Count tags for a user per room
  std::map<std::string, size_t> count_tags_per_room(const std::string& user_id) {
    auto all_tags = get_all_tags_for_user(user_id);
    std::map<std::string, size_t> counts;
    for (const auto& [room_id, tags] : all_tags) {
      counts[room_id] = tags.size();
    }
    return counts;
  }

  // Check if a user has a specific tag on a room
  bool has_tag(const std::string& user_id, const std::string& room_id,
               const std::string& tag) {
    auto tags = get_tags_for_room(user_id, room_id);
    for (const auto& t : tags) {
      if (t.tag == tag) return true;
    }
    return false;
  }

  // ========================================================================
  // Tag Ordering Operations
  // ========================================================================

  // Update the order value for a specific tag
  bool update_tag_order(const std::string& user_id,
                         const std::string& room_id,
                         const std::string& tag,
                         double new_order) {

    // Clamp and normalize
    new_order = std::clamp(new_order, TagLimits::MIN_ORDER_VALUE,
                           TagLimits::MAX_ORDER_VALUE);
    new_order = TagEntry::normalize_order(new_order);

    auto tags = get_tags_for_room(user_id, room_id);
    for (auto& entry : tags) {
      if (entry.tag == tag) {
        entry.order = new_order;
        entry.content["order"] = new_order;
        entry.stream_id = replication_.next_stream_id();
        entry.updated_ts_ms = now_ms();

        persist_tag(entry);
        cache_.invalidate(user_id, room_id);
        return true;
      }
    }
    return false;
  }

  // Bulk update orders for multiple tags in a room
  bool update_tag_orders(const std::string& user_id,
                          const std::string& room_id,
                          const std::vector<std::pair<std::string, double>>& orders) {

    auto tags = get_tags_for_room(user_id, room_id);
    std::map<std::string, TagEntry*> tag_map;

    for (auto& entry : tags) {
      tag_map[entry.tag] = &entry;
    }

    int64_t stream_id = replication_.next_stream_id();
    int64_t ts = now_ms();
    bool any_updated = false;

    for (const auto& [tag, order] : orders) {
      auto it = tag_map.find(tag);
      if (it != tag_map.end()) {
        double clamped = TagEntry::normalize_order(
            std::clamp(order, TagLimits::MIN_ORDER_VALUE,
                       TagLimits::MAX_ORDER_VALUE));
        it->second->order = clamped;
        it->second->content["order"] = clamped;
        it->second->stream_id = stream_id;
        it->second->updated_ts_ms = ts;
        persist_tag(*it->second);
        any_updated = true;
      }
    }

    if (any_updated) {
      cache_.invalidate(user_id, room_id);
    }

    return any_updated;
  }

  // Rebalance all tag orders in a room for even distribution
  void rebalance_orders(const std::string& user_id,
                         const std::string& room_id) {
    auto tags = get_tags_for_room(user_id, room_id);
    auto new_orders = TagOrderEngine::rebalance_orders(tags);
    int64_t stream_id = replication_.next_stream_id();
    int64_t ts = now_ms();

    for (auto& entry : tags) {
      auto it = new_orders.find(entry.tag);
      if (it != new_orders.end()) {
        entry.order = it->second;
        entry.content["order"] = it->second;
        entry.stream_id = stream_id;
        entry.updated_ts_ms = ts;
      }
      persist_tag(entry);
    }

    cache_.invalidate(user_id, room_id);
  }

  // ========================================================================
  // Default Tag Operations
  // ========================================================================

  // Apply default tags when a room is created
  void apply_default_tags_on_creation(const std::string& user_id,
                                        const std::string& room_id,
                                        bool is_direct) {
    auto defaults = default_policy_.compute_defaults_for_creation(
        room_id, user_id, is_direct);

    if (defaults.empty()) return;

    for (const auto& [tag_name, content] : defaults.items()) {
      try {
        set_tag(user_id, room_id, tag_name, content);
      } catch (const std::exception& e) {
        // Log and skip conflicts
        std::cerr << "[RoomTagsEngine] Failed to apply default tag '" << tag_name
                  << "' to room " << room_id << ": " << e.what() << std::endl;
      }
    }
  }

  // Apply default tags when a user joins a room
  void apply_default_tags_on_join(const std::string& user_id,
                                    const std::string& room_id,
                                    int64_t member_count) {
    auto defaults = default_policy_.compute_defaults_for_join(
        room_id, user_id, member_count);

    if (defaults.empty()) return;

    for (const auto& [tag_name, content] : defaults.items()) {
      try {
        // Only apply if the user doesn't already have some tags on this room
        auto existing = get_tags_for_room(user_id, room_id);
        if (existing.empty()) {
          set_tag(user_id, room_id, tag_name, content);
        }
      } catch (const std::exception& e) {
        std::cerr << "[RoomTagsEngine] Failed to apply join tag '" << tag_name
                  << "' to room " << room_id << ": " << e.what() << std::endl;
      }
    }
  }

  // Update the default tag policy
  void set_default_policy(const DefaultTagPolicy::PolicyConfig& config) {
    default_policy_.update_config(config);
  }

  // Get current default tag policy
  DefaultTagPolicy::PolicyConfig get_default_policy() const {
    return default_policy_.get_config();
  }

  // ========================================================================
  // Sync Integration
  // ========================================================================

  // Build account_data section for /sync response — all rooms
  json build_sync_account_data(const std::string& user_id) {
    auto all_tags = get_all_tags_for_user(user_id);
    return TagSyncIntegrator::build_all_rooms_account_data(all_tags);
  }

  // Build account_data for a single room in /sync
  json build_room_sync_account_data(const std::string& user_id,
                                      const std::string& room_id) {
    auto tags = get_tags_for_room(user_id, room_id);
    if (tags.empty()) return json::object();

    json event = TagSyncIntegrator::build_tag_account_data(tags);
    json result = json::object();
    result["events"] = json::array({event});
    return result;
  }

  // Compute incremental sync delta since a stream position
  TagSyncIntegrator::SyncDelta compute_sync_delta(
      const std::string& user_id,
      const std::string& room_id,
      int64_t since_stream_id) {

    auto current = get_tags_for_room(user_id, room_id);

    // We need previous state. Since we cache, we can check the stream_id
    // of current tags. If all current tags have stream_id <= since_stream_id,
    // no changes. Otherwise, we need to determine what changed.
    TagSyncIntegrator::SyncDelta delta;

    bool has_changes = false;
    for (const auto& t : current) {
      if (t.stream_id > since_stream_id) {
        has_changes = true;
        break;
      }
    }

    if (!has_changes) {
      delta.new_stream_id = since_stream_id;
      return delta;
    }

    // Build full current state as changed
    // (In a full implementation, we'd keep previous state snapshots)
    delta.changed = TagSyncIntegrator::build_tag_account_data(current);

    int64_t max_stream = since_stream_id;
    for (const auto& t : current) {
      if (t.stream_id > max_stream) max_stream = t.stream_id;
    }
    delta.new_stream_id = max_stream;

    return delta;
  }

  // Get current stream position for a user (for sync tokens)
  int64_t current_stream_id() const {
    return replication_.current_stream_id();
  }

  // Check if any tag changes since a given position
  bool has_changes_since(const std::string& user_id, int64_t since) {
    auto all_tags = get_all_tags_for_user(user_id);
    for (const auto& [room_id, tags] : all_tags) {
      for (const auto& t : tags) {
        if (t.stream_id > since) return true;
      }
    }
    return false;
  }

  // ========================================================================
  // GDPR Export Operations
  // ========================================================================

  // Export all tags for a user (GDPR data export)
  json export_all_tags(const std::string& user_id,
                        const TagExportCollector::ExportConfig& config = {}) {
    auto all_tags = get_all_tags_for_user(user_id);
    TagExportCollector collector(config);
    return collector.collect_for_export(user_id, all_tags);
  }

  // Export tags for a specific tag name (e.g., all "m.favourite" rooms)
  json export_by_tag(const std::string& user_id, const std::string& tag) {
    auto all_tags = get_all_tags_for_user(user_id);
    TagExportCollector collector;
    return collector.export_by_tag(user_id, tag, all_tags);
  }

  // Export anonymized tags for third-party processing
  json export_anonymized_tags(const std::string& user_id) {
    auto export_data = export_all_tags(user_id);
    return TagExportCollector::anonymize_export(export_data);
  }

  // ========================================================================
  // Administrative Operations
  // ========================================================================

  // Delete all tags for a user (account deactivation / GDPR erasure)
  void delete_all_user_tags(const std::string& user_id) {
    auto all_tags = get_all_tags_for_user(user_id);
    for (const auto& [room_id, tags] : all_tags) {
      for (const auto& t : tags) {
        delete_tag_from_db(user_id, room_id, t.tag);
      }
    }
    cache_.invalidate_user(user_id);
  }

  // Delete all tags for a room (when room is purged)
  void delete_all_room_tags(const std::string& room_id) {
    // This needs a database-level operation since we don't have user context
    db_.execute("delete_all_room_tags",
        "DELETE FROM room_tags WHERE room_id = ?",
        {room_id});

    // Clear entire cache since we don't track room-level invalidations
    // efficiently without user context
    cache_.clear();
  }

  // Get tag statistics for a user
  json get_tag_stats(const std::string& user_id) {
    auto all_tags = get_all_tags_for_user(user_id);

    json stats = json::object();
    stats["user_id"] = user_id;

    size_t total_tags = 0;
    size_t rooms_with_tags = all_tags.size();
    std::map<std::string, size_t> tag_counts;

    for (const auto& [room_id, tags] : all_tags) {
      total_tags += tags.size();
      for (const auto& t : tags) {
        tag_counts[t.tag]++;
      }
    }

    stats["total_tags"] = total_tags;
    stats["rooms_with_tags"] = rooms_with_tags;
    stats["unique_tag_types"] = tag_counts.size();

    // Tag type distribution
    json distribution = json::object();
    for (const auto& [tag_name, count] : tag_counts) {
      distribution[tag_name] = count;
    }
    stats["tag_distribution"] = distribution;

    // Well-known tag usage
    json well_known = json::object();
    for (const auto& wk : WellKnownTags::all_well_known()) {
      well_known[wk] = tag_counts.count(wk) ? tag_counts[wk] : 0;
    }
    stats["well_known_tags"] = well_known;
    stats["user_defined_tag_count"] =
        total_tags - tag_counts[WellKnownTags::FAVOURITE] -
        tag_counts[WellKnownTags::LOWPRIORITY] -
        tag_counts[WellKnownTags::SERVER_NOTICE];

    return stats;
  }

  // Get global tag statistics (across all users)
  json get_global_tag_stats() {
    json stats = json::object();

    // Total tags
    auto total_row = db_.execute("count_all_tags",
        "SELECT COUNT(*) FROM room_tags", {});
    int64_t total_tags = 0;
    if (!total_row.empty()) {
      total_tags = total_row[0][0].get<int64_t>();
    }
    stats["total_tags"] = total_tags;

    // Unique users with tags
    auto users_row = db_.execute("count_tag_users",
        "SELECT COUNT(DISTINCT user_id) FROM room_tags", {});
    int64_t users_with_tags = 0;
    if (!users_row.empty()) {
      users_with_tags = users_row[0][0].get<int64_t>();
    }
    stats["users_with_tags"] = users_with_tags;

    // Unique rooms with tags
    auto rooms_row = db_.execute("count_tag_rooms",
        "SELECT COUNT(DISTINCT room_id) FROM room_tags", {});
    int64_t rooms_with_tags = 0;
    if (!rooms_row.empty()) {
      rooms_with_tags = rooms_row[0][0].get<int64_t>();
    }
    stats["rooms_with_tags"] = rooms_with_tags;

    // Popular tags
    auto popular = db_.execute("popular_tags",
        "SELECT tag, COUNT(*) AS cnt FROM room_tags "
        "GROUP BY tag ORDER BY cnt DESC LIMIT 20", {});
    json popular_tags = json::array();
    for (const auto& row : popular) {
      json entry;
      entry["tag"] = row[0].get<std::string>();
      entry["count"] = row[1].get<int64_t>();
      popular_tags.push_back(entry);
    }
    stats["popular_tags"] = popular_tags;

    return stats;
  }

  // Bulk import tags (for migration or admin operations)
  struct BulkImportResult {
    size_t imported{0};
    size_t failed{0};
    size_t skipped{0};
    std::vector<std::string> errors;
  };

  BulkImportResult bulk_import(const std::string& user_id,
                                 const std::string& room_id,
                                 const std::vector<std::pair<std::string, json>>& tags) {
    BulkImportResult result;
    size_t limit = TagLimits::MAX_TAGS_PER_ROOM;

    auto existing = get_tags_for_room(user_id, room_id);
    size_t current_count = existing.size();

    for (const auto& [tag_name, content] : tags) {
      if (current_count >= limit) {
        result.skipped++;
        continue;
      }

      try {
        set_tag(user_id, room_id, tag_name, content);
        current_count++;
        result.imported++;
      } catch (const std::exception& e) {
        result.failed++;
        result.errors.push_back("Tag '" + tag_name + "': " + e.what());
      }
    }

    return result;
  }

  // Migrate tags from old format (no order) to new format (with order)
  struct MigrationResult {
    size_t migrated{0};
    size_t already_migrated{0};
    int64_t errors{0};
  };

  MigrationResult migrate_legacy_tags(const std::string& user_id) {
    MigrationResult result;

    auto all_tags = get_all_tags_for_user(user_id);
    int64_t stream_id = replication_.next_stream_id();

    for (auto& [room_id, tags] : all_tags) {
      for (auto& entry : tags) {
        bool needs_migration = false;

        // Check if order is missing or not normalized
        if (!entry.content.contains("order")) {
          entry.content["order"] = TagLimits::DEFAULT_ORDER_VALUE;
          entry.order = TagLimits::DEFAULT_ORDER_VALUE;
          needs_migration = true;
        } else if (std::abs(entry.order - TagEntry::normalize_order(
                    entry.content["order"].get<double>())) > 1e-9) {
          entry.order = TagEntry::normalize_order(
              entry.content["order"].get<double>());
          entry.content["order"] = entry.order;
          needs_migration = true;
        }

        if (needs_migration) {
          entry.stream_id = stream_id++;
          entry.updated_ts_ms = now_ms();
          try {
            persist_tag(entry);
            result.migrated++;
          } catch (...) {
            result.errors++;
          }
        } else {
          result.already_migrated++;
        }
      }
    }

    if (result.migrated > 0) {
      cache_.invalidate_user(user_id);
    }

    return result;
  }

  // ========================================================================
  // Cache Management
  // ========================================================================

  void invalidate_cache(const std::string& user_id) {
    cache_.invalidate_user(user_id);
  }

  void invalidate_cache(const std::string& user_id, const std::string& room_id) {
    cache_.invalidate(user_id, room_id);
  }

  void clear_cache() {
    cache_.clear();
  }

  void clean_expired_cache() {
    cache_.clean_expired();
  }

  TagLruCache::CacheStats cache_stats() const {
    return cache_.stats();
  }

  // ========================================================================
  // Replication Token
  // ========================================================================

  std::string replication_token() const {
    return replication_.replication_token();
  }

private:
  // Persist a tag to the database
  void persist_tag(const TagEntry& entry) {
    room_store_.set_room_tag_txn_with_stream(
        entry.user_id, entry.room_id, entry.tag,
        entry.content, entry.stream_id);
  }

  // Delete a tag from the database
  void delete_tag_from_db(const std::string& user_id,
                           const std::string& room_id,
                           const std::string& tag) {
    room_store_.delete_room_tag(user_id, room_id, tag);
  }

  // Load tags for a user+room from the database
  std::vector<TagEntry> load_tags_from_db(const std::string& user_id,
                                            const std::string& room_id) {
    auto json_tags = room_store_.get_room_tags_for_user(user_id, room_id);
    std::vector<TagEntry> entries;

    for (const auto& [tag_str, content] : json_tags.items()) {
      TagEntry entry;
      entry.user_id = user_id;
      entry.room_id = room_id;
      entry.tag = tag_str;
      entry.content = content;
      entry.order = TagEntry::extract_order(content);

      // Extract metadata if present
      if (content.contains("_stream_id")) {
        entry.stream_id = content["_stream_id"].get<int64_t>();
      }
      if (content.contains("_created_ts")) {
        entry.created_ts_ms = content["_created_ts"].get<int64_t>();
      }
      if (content.contains("_updated_ts")) {
        entry.updated_ts_ms = content["_updated_ts"].get<int64_t>();
      }

      entries.push_back(entry);
    }

    // Sort by order for consistent return
    TagOrderEngine::sort_entries(entries);

    return entries;
  }

  // Load all tags for a user from the database
  std::map<std::string, std::vector<TagEntry>> load_all_tags_from_db(
      const std::string& user_id) {

    auto rows = db_.execute("get_all_user_tags_full",
        "SELECT room_id, tag, content FROM room_tags WHERE user_id = ? "
        "ORDER BY room_id, tag",
        {user_id});

    std::map<std::string, std::vector<TagEntry>> result;

    for (const auto& row : rows) {
      std::string room_id = row[0].get<std::string>();
      std::string tag_str = row[1].get<std::string>();
      json content = json::parse(row[2].get<std::string>());

      TagEntry entry;
      entry.user_id = user_id;
      entry.room_id = room_id;
      entry.tag = tag_str;
      entry.content = content;
      entry.order = TagEntry::extract_order(content);

      if (content.contains("_stream_id")) {
        entry.stream_id = content["_stream_id"].get<int64_t>();
      }
      if (content.contains("_created_ts")) {
        entry.created_ts_ms = content["_created_ts"].get<int64_t>();
      }
      if (content.contains("_updated_ts")) {
        entry.updated_ts_ms = content["_updated_ts"].get<int64_t>();
      }

      result[room_id].push_back(entry);
    }

    // Sort each room's entries
    for (auto& [room_id, entries] : result) {
      TagOrderEngine::sort_entries(entries);
    }

    return result;
  }

  static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
  }

  DatabasePool& db_;
  RoomStore& room_store_;
  TagLruCache cache_;
  DefaultTagPolicy default_policy_;
  TagReplicationManager replication_;
};

// ============================================================================
// Legacy tag storage wrapper — delegates to RoomStore for tags
// Not used directly; included for backward compatibility
// ============================================================================

// RoomStore already provides the necessary tag storage operations.
// The RoomTagsEngine above is the primary interface for tag management.
// Below we wrap the RoomStore methods for convenience when used standalone.

namespace tag_storage_helpers {

// Set a room tag with stream ordering support
// This extends the base RoomStore::set_room_tag with stream tracking
inline void set_room_tag_with_stream(RoomStore& store,
                                      const std::string& user_id,
                                      const std::string& room_id,
                                      const std::string& tag,
                                      const json& content,
                                      int64_t stream_id) {
  // Add stream metadata to content
  json enriched = content;
  enriched["_stream_id"] = stream_id;

  int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();

  if (!enriched.contains("_created_ts")) {
    enriched["_created_ts"] = now;
  }
  enriched["_updated_ts"] = now;

  store.set_room_tag(user_id, room_id, tag, enriched);
}

// Get tags with parsed metadata
inline std::map<std::string, json> get_tags_with_metadata(
    RoomStore& store,
    const std::string& user_id,
    const std::string& room_id) {
  return store.get_room_tags_for_user(user_id, room_id);
}

// Delete a tag and its revision tracking
inline void delete_tag_with_cleanup(RoomStore& store,
                                     const std::string& user_id,
                                     const std::string& room_id,
                                     const std::string& tag) {
  store.delete_room_tag(user_id, room_id, tag);
}

} // namespace tag_storage_helpers

// ============================================================================
// REST API Handlers for Room Tags
// ============================================================================
// These handlers are used by the REST routing layer to serve the
// Client-Server API endpoints for room tags.
// ============================================================================

namespace rest_handlers {

using namespace progressive::rest;

// GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags
inline HttpResponse handle_get_tags(
    DatabasePool& db, RoomStore& room_store,
    const std::string& user_id, const std::string& room_id) {

  RoomTagsEngine engine(db, room_store);
  auto tags = engine.get_tags_for_room(user_id, room_id);

  json response;
  response["tags"] = json::object();

  for (const auto& tag : tags) {
    response["tags"][tag.tag] = tag.content;
  }

  HttpResponse res;
  res.code = 200;
  res.body = response;
  res.content_type = "application/json";
  return res;
}

// PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}
inline HttpResponse handle_put_tag(
    DatabasePool& db, RoomStore& room_store,
    const std::string& user_id, const std::string& room_id,
    const std::string& tag, const json& request_body) {

  RoomTagsEngine engine(db, room_store);

  try {
    // Validate tag name first
    auto validation = TagValidator::validate_tag_name(tag);
    if (!validation.valid) {
      HttpResponse res;
      res.code = 400;
      res.body = json::object({
        {"errcode", validation.error_code},
        {"error", validation.error_message}
      });
      res.content_type = "application/json";
      return res;
    }

    // Validate content size
    auto size_check = TagValidator::validate_content_size(request_body);
    if (!size_check.valid) {
      HttpResponse res;
      res.code = 413;
      res.body = json::object({
        {"errcode", size_check.error_code},
        {"error", size_check.error_message}
      });
      res.content_type = "application/json";
      return res;
    }

    // Get existing tags to check limit
    auto existing = engine.get_tags_for_room(user_id, room_id);
    bool is_update = false;
    for (const auto& e : existing) {
      if (e.tag == tag) { is_update = true; break; }
    }

    if (!is_update) {
      auto limit_check = TagValidator::validate_tag_count(existing.size());
      if (!limit_check.valid) {
        HttpResponse res;
        res.code = 400;
        res.body = json::object({
          {"errcode", limit_check.error_code},
          {"error", limit_check.error_message}
        });
        res.content_type = "application/json";
        return res;
      }
    }

    engine.set_tag(user_id, room_id, tag, request_body);

    HttpResponse res;
    res.code = 200;
    res.body = json::object();
    res.content_type = "application/json";
    return res;

  } catch (const std::exception& e) {
    HttpResponse res;
    res.code = 400;
    res.body = json::object({
      {"errcode", "M_UNKNOWN"},
      {"error", e.what()}
    });
    res.content_type = "application/json";
    return res;
  }
}

// DELETE /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}
inline HttpResponse handle_delete_tag(
    DatabasePool& db, RoomStore& room_store,
    const std::string& user_id, const std::string& room_id,
    const std::string& tag) {

  RoomTagsEngine engine(db, room_store);

  try {
    bool deleted = engine.remove_tag(user_id, room_id, tag);

    HttpResponse res;
    res.code = 200;
    res.body = json::object();
    res.content_type = "application/json";

    if (!deleted) {
      // Tag didn't exist — still return 200 per Matrix spec (idempotent)
    }

    return res;
  } catch (const std::exception& e) {
    HttpResponse res;
    res.code = 400;
    res.body = json::object({
      {"errcode", "M_UNKNOWN"},
      {"error", e.what()}
    });
    res.content_type = "application/json";
    return res;
  }
}

// GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}
// Often used to check specific tag existence and content
inline HttpResponse handle_get_single_tag(
    DatabasePool& db, RoomStore& room_store,
    const std::string& user_id, const std::string& room_id,
    const std::string& tag) {

  RoomTagsEngine engine(db, room_store);
  auto tags = engine.get_tags_for_room(user_id, room_id);

  for (const auto& t : tags) {
    if (t.tag == tag) {
      HttpResponse res;
      res.code = 200;
      res.body = t.content;
      res.content_type = "application/json";
      return res;
    }
  }

  // Tag not found
  HttpResponse res;
  res.code = 404;
  res.body = json::object({
    {"errcode", "M_NOT_FOUND"},
    {"error", "Tag '" + tag + "' not found on room " + room_id}
  });
  res.content_type = "application/json";
  return res;
}

// Admin: GET all tags for a user (GDPR/admin endpoint)
inline HttpResponse handle_admin_get_user_tags(
    DatabasePool& db, RoomStore& room_store,
    const std::string& user_id) {

  RoomTagsEngine engine(db, room_store);
  auto all_tags = engine.get_all_tags_for_user(user_id);

  json response;
  response["user_id"] = user_id;
  response["rooms"] = json::object();

  for (const auto& [room_id, tags] : all_tags) {
    json room_tags = json::object();
    for (const auto& tag : tags) {
      room_tags[tag.tag] = tag.content;
    }
    response["rooms"][room_id] = room_tags;
  }

  size_t total = 0;
  for (const auto& [_, tags] : all_tags) total += tags.size();
  response["total_tag_count"] = total;
  response["room_count"] = all_tags.size();

  HttpResponse res;
  res.code = 200;
  res.body = response;
  res.content_type = "application/json";
  return res;
}

// Admin: DELETE all tags for a user
inline HttpResponse handle_admin_delete_user_tags(
    DatabasePool& db, RoomStore& room_store,
    const std::string& user_id) {

  RoomTagsEngine engine(db, room_store);
  engine.delete_all_user_tags(user_id);

  HttpResponse res;
  res.code = 200;
  res.body = json::object({{"deleted", true}});
  res.content_type = "application/json";
  return res;
}

// Admin: GET all tags on a specific room (across all users)
inline HttpResponse handle_admin_get_room_tags(
    DatabasePool& db,
    const std::string& room_id) {

  auto rows = db.execute("admin_get_room_all_tags",
      "SELECT user_id, tag, content FROM room_tags WHERE room_id = ? "
      "ORDER BY user_id, tag",
      {room_id});

  json response;
  response["room_id"] = room_id;
  json users = json::object();

  for (const auto& row : rows) {
    std::string user_id = row[0].get<std::string>();
    std::string tag = row[1].get<std::string>();
    json content = json::parse(row[2].get<std::string>());

    if (!users.contains(user_id)) {
      users[user_id] = json::object();
    }
    users[user_id][tag] = content;
  }

  response["users"] = users;
  response["user_count"] = users.size();

  HttpResponse res;
  res.code = 200;
  res.body = response;
  res.content_type = "application/json";
  return res;
}

} // namespace rest_handlers

// ============================================================================
// Utility Functions for External Consumers
// ============================================================================

namespace tag_utils {

// Check if a room is favourited by a user
inline bool is_favourited(RoomTagsEngine& engine,
                           const std::string& user_id,
                           const std::string& room_id) {
  return engine.has_tag(user_id, room_id, WellKnownTags::FAVOURITE);
}

// Check if a room is low priority for a user
inline bool is_low_priority(RoomTagsEngine& engine,
                              const std::string& user_id,
                              const std::string& room_id) {
  return engine.has_tag(user_id, room_id, WellKnownTags::LOWPRIORITY);
}

// Get the favourite order for a room (or -1 if not favourited)
inline double get_favourite_order(RoomTagsEngine& engine,
                                   const std::string& user_id,
                                   const std::string& room_id) {
  auto tags = engine.get_tags_for_room(user_id, room_id);
  for (const auto& t : tags) {
    if (t.tag == WellKnownTags::FAVOURITE) {
      return t.order;
    }
  }
  return -1.0;
}

// Get all favourited rooms for a user with their order values
inline std::vector<std::pair<std::string, double>> get_favourited_rooms(
    RoomTagsEngine& engine, const std::string& user_id) {
  auto rooms = engine.get_rooms_with_tag(user_id, WellKnownTags::FAVOURITE);
  std::vector<std::pair<std::string, double>> result;
  result.reserve(rooms.size());
  for (const auto& t : rooms) {
    result.emplace_back(t.room_id, t.order);
  }
  return result;
}

// Get all low-priority rooms for a user
inline std::vector<std::string> get_low_priority_rooms(
    RoomTagsEngine& engine, const std::string& user_id) {
  auto rooms = engine.get_rooms_with_tag(user_id, WellKnownTags::LOWPRIORITY);
  std::vector<std::string> result;
  result.reserve(rooms.size());
  for (const auto& t : rooms) {
    result.push_back(t.room_id);
  }
  return result;
}

// Compute the "effective importance" of a room based on its tags
// Returns a score from 0.0 (lowest) to 1.0 (highest)
inline double compute_room_importance(RoomTagsEngine& engine,
                                        const std::string& user_id,
                                        const std::string& room_id) {
  auto tags = engine.get_tags_for_room(user_id, room_id);

  bool is_fav = false;
  bool is_low = false;
  double fav_order = 0.5;

  for (const auto& t : tags) {
    if (t.tag == WellKnownTags::FAVOURITE) {
      is_fav = true;
      fav_order = t.order;
    }
    if (t.tag == WellKnownTags::LOWPRIORITY) {
      is_low = true;
    }
  }

  if (is_fav && is_low) {
    // Both tags exist — favourite takes precedence but attenuated
    return 0.3 + 0.4 * fav_order;
  } else if (is_fav) {
    return 0.6 + 0.4 * fav_order;
  } else if (is_low) {
    return 0.2;
  } else {
    // No special tags — neutral importance
    return 0.5;
  }
}

// Generate a user-friendly summary of room tags
inline std::string summarize_tags(const std::vector<TagEntry>& tags) {
  if (tags.empty()) return "No tags";

  std::vector<std::string> parts;
  for (const auto& t : tags) {
    std::string label = t.tag;
    if (t.tag == WellKnownTags::FAVOURITE) label = "★ Favourite";
    else if (t.tag == WellKnownTags::LOWPRIORITY) label = "↓ Low Priority";
    else if (t.tag == WellKnownTags::SERVER_NOTICE) label = "⚙ Server Notice";
    parts.push_back(label + " (" + std::to_string(t.order).substr(0, 4) + ")");
  }

  std::ostringstream oss;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i > 0) oss << ", ";
    oss << parts[i];
  }
  return oss.str();
}

// Validate a complete set of tags for a user+room against all rules
struct FullValidationResult {
  bool valid{true};
  std::vector<std::string> warnings;
  std::vector<std::string> errors;
  size_t tag_count{0};
  bool has_duplicates{false};
};

inline FullValidationResult validate_all_tags(
    const std::vector<TagEntry>& tags) {
  FullValidationResult result;
  result.tag_count = tags.size();

  if (tags.size() > TagLimits::MAX_TAGS_PER_ROOM) {
    result.valid = false;
    result.errors.push_back(
        "Tag count " + std::to_string(tags.size()) +
        " exceeds limit of " + std::to_string(TagLimits::MAX_TAGS_PER_ROOM));
  }

  // Check for duplicate tags
  std::set<std::string> seen;
  for (const auto& t : tags) {
    if (!seen.insert(t.tag).second) {
      result.has_duplicates = true;
      result.errors.push_back("Duplicate tag: " + t.tag);
      result.valid = false;
    }
  }

  // Check individual tag validity
  for (const auto& t : tags) {
    auto validation = TagValidator::validate_tag_name(t.tag);
    if (!validation.valid) {
      result.errors.push_back("Invalid tag '" + t.tag + "': " +
                               validation.error_message);
      result.valid = false;
    }

    if (t.order < TagLimits::MIN_ORDER_VALUE ||
        t.order > TagLimits::MAX_ORDER_VALUE) {
      result.errors.push_back("Tag '" + t.tag +
                               "' has out-of-range order: " +
                               std::to_string(t.order));
      result.valid = false;
    }
  }

  // Warning: many well-known tags in one room
  int well_known_count = 0;
  for (const auto& t : tags) {
    if (WellKnownTags::is_well_known(t.tag)) well_known_count++;
  }
  if (well_known_count > 3) {
    result.warnings.push_back(
        "Room has " + std::to_string(well_known_count) +
        " well-known tags — consider consolidating");
  }

  return result;
}

} // namespace tag_utils

// ============================================================================
// Global Instance Helper — creates a RoomTagsEngine for common use cases
// ============================================================================

// Factory function to create a RoomTagsEngine from database pool and store
inline RoomTagsEngine make_room_tags_engine(DatabasePool& db, RoomStore& store) {
  return RoomTagsEngine(db, store);
}

// ============================================================================
// Tag Maintenance Operations (periodic background tasks)
// ============================================================================

namespace tag_maintenance {

// Periodic cleanup: expire cached tag data
inline void run_cache_cleanup(RoomTagsEngine& engine) {
  engine.clean_expired_cache();
}

// Periodic migration: ensure all tags have proper order values
inline TagEntry::MigrationResult run_tag_migration(
    RoomTagsEngine& engine, const std::string& user_id) {
  // This is equivalent to TagEntry::MigrationResult but we reuse the
  // engine's MigrationResult type
  return engine.migrate_legacy_tags(user_id);
}

// Periodic normalization: rebalance heavily clustered orders
inline void run_order_normalization(RoomTagsEngine& engine,
                                     const std::string& user_id) {
  auto all_tags = engine.get_all_tags_for_user(user_id);
  for (const auto& [room_id, tags] : all_tags) {
    if (tags.size() >= 10) {
      // Check if orders are too clustered
      double min_order = 1.0, max_order = 0.0;
      for (const auto& t : tags) {
        if (t.order < min_order) min_order = t.order;
        if (t.order > max_order) max_order = t.order;
      }

      double spread = max_order - min_order;
      double expected_spread = static_cast<double>(tags.size() - 1) /
                               static_cast<double>(TagLimits::MAX_TAGS_PER_ROOM);

      // If orders are too clustered (spread < 20% of expected), rebalance
      if (spread < expected_spread * 0.2) {
        engine.rebalance_orders(user_id, room_id);
      }
    }
  }
}

// Statistics gathering for monitoring
inline json collect_maintenance_stats(RoomTagsEngine& engine,
                                        const std::string& user_id) {
  json stats;
  stats["cache"] = json::object({
    {"per_room_entries", engine.cache_stats().per_room_entries},
    {"user_entries", engine.cache_stats().user_entries},
    {"max_entries", engine.cache_stats().max_entries}
  });
  stats["tags"] = engine.get_tag_stats(user_id);
  stats["replication_token"] = engine.replication_token();
  return stats;
}

} // namespace tag_maintenance

} // namespace progressive
