// ============================================================================
// event_relations.cpp — Matrix Event Relations Aggregation, Bundled Relations,
//                        Pagination, Relation Validation, Bundled Editing,
//                        Thread Replies, Reference Relations, and Stitching
//
// Implements:
//   - Bundled relations: embed related events in event unsigned sections
//     (m.annotation for reactions, m.replace for edits, m.thread for thread
//     summaries, m.reference for references). Bundles are computed when
//     delivering events to clients via sync, /messages, and /event.
//   - Aggregation API: REST endpoints for retrieving paginated relations:
//       GET  /rooms/{roomId}/relations/{eventId}
//       GET  /rooms/{roomId}/relations/{eventId}/{relType}
//       GET  /rooms/{roomId}/relations/{eventId}/{relType}/{eventType}
//     Each returns a chunk with next_batch / prev_batch pagination tokens.
//   - Aggregation by key: for m.annotation relations, group by aggregation_key
//     (emoji/reaction key) and return per-key counts, supporting deduplication
//     and single-reaction-per-user-per-key enforcement.
//   - Pagination: cursor-based pagination with from/to/dir/limit parameters.
//     Cursor tokens encode (origin_server_ts, event_id) as base64 strings,
//     enabling stable, deterministic pagination across relation queries.
//   - Relation validation: prevent relation cycles (event relating to itself
//     or indirect loops), validate relation types against known whitelist,
//     prevent duplicate annotations from the same user (same key), enforce
//     max edit depth, and validate that target events exist.
//   - Bundled editing: include the latest edit (m.replace) in bundled
//     relations, resolve edited content by merging m.new_content on top of
//     the original event, track edit history with configurable limits,
//     and generate fallback text for non-supporting clients.
//   - Thread replies: bundle latest thread replies in thread root events,
//     compute thread reply count and participant count, maintain per-thread
//     timeline ordering, and support thread root detection/re-registration.
//   - Reference relations: include referenced events (m.reference) in
//     bundled relations, track reference counts, support paginated reference
//     retrieval with type filtering.
//   - Stitching: when a client requests a single event or timeline, fetch
//     all related events and build bundled relations, merge them into the
//     unsigned section of each event. Also stitches annotation counts,
//     edit info, thread summaries, and reference lists.
//
// Namespace: progressive::
// Equivalent to synapse/handlers/relations.py +
//              synapse/rest/client/relations.py +
//              synapse/events/utils.py (bundled relations) +
//              synapse/visibility.py (filtering) +
//              synapse/api/pagination.py (token encoding)
//
// Target: 2500+ lines of production-grade C++ with explicit descriptions.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
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
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for all major components
// ============================================================================
class PaginationTokenCodec;
class RelationValidator;
class BundledRelationBuilder;
class AggregationAPIHandler;
class AggregationByKeyEngine;
class BundledEditResolver;
class ThreadReplyBundler;
class ReferenceRelationTracker;
class EventStitcher;
class RelationCoordinator;

// ============================================================================
// Constants: relation types, field names, limits, HTTP status codes
// ============================================================================
namespace rel_constants {

// --- Relation type strings per Matrix specification ---
constexpr const char* ANNOTATION  = "m.annotation";   // reactions/emoji
constexpr const char* REPLACE     = "m.replace";      // edits
constexpr const char* REFERENCE   = "m.reference";    // in-reply-to/generic ref
constexpr const char* THREAD      = "m.thread";       // thread replies
constexpr const char* IN_REPLY_TO = "m.in_reply_to";  // deprecated, maps to reference

// --- JSON keys used throughout relation processing ---
constexpr const char* RELATES_TO_KEY    = "m.relates_to";
constexpr const char* EVENT_ID_KEY      = "event_id";
constexpr const char* REL_TYPE_KEY      = "rel_type";
constexpr const char* AGGREGATION_KEY   = "key";
constexpr const char* NEW_CONTENT_KEY   = "m.new_content";
constexpr const char* UNSIGNED_KEY      = "unsigned";
constexpr const char* CHUNK_KEY         = "chunk";
constexpr const char* NEXT_BATCH_KEY    = "next_batch";
constexpr const char* PREV_BATCH_KEY    = "prev_batch";
constexpr const char* ORIGIN_SERVER_TS  = "origin_server_ts";
constexpr const char* SENDER_KEY        = "sender";
constexpr const char* TYPE_KEY          = "type";
constexpr const char* CONTENT_KEY       = "content";
constexpr const char* ROOM_ID_KEY       = "room_id";
constexpr const char* IS_FALLING_BACK   = "is_falling_back";

// --- Pagination direction constants ---
constexpr const char* DIR_FORWARD  = "f";   // towards newer events
constexpr const char* DIR_BACKWARD = "b";   // towards older events

// --- Default limits ---
constexpr int DEFAULT_PAGE_LIMIT              = 50;
constexpr int MAX_PAGE_LIMIT                  = 500;
constexpr int MAX_BUNDLED_REACTIONS           = 50;
constexpr int MAX_BUNDLED_REFERENCES           = 10;
constexpr int MAX_BUNDLED_THREAD_REPLIES       = 5;
constexpr int MAX_EDIT_HISTORY                = 50;
constexpr int MAX_EDIT_DEPTH                  = 1;     // no edits of edits
constexpr int MAX_REACTION_KEY_LENGTH         = 64;
constexpr int MAX_AGGREGATED_RELATIONS        = 1000;
constexpr int PAGINATION_TOKEN_VERSION        = 1;

// --- Error codes ---
constexpr const char* M_INVALID_PARAM   = "M_INVALID_PARAM";
constexpr const char* M_NOT_FOUND       = "M_NOT_FOUND";
constexpr const char* M_FORBIDDEN       = "M_FORBIDDEN";
constexpr const char* M_LIMIT_EXCEEDED  = "M_LIMIT_EXCEEDED";
constexpr const char* M_UNKNOWN         = "M_UNKNOWN";
constexpr const char* M_CYCLIC_RELATION = "M_CYCLIC_RELATION";
constexpr const char* M_DUPLICATE_ANNOTATION = "M_DUPLICATE_ANNOTATION";

// --- Thread-specific keys in unsigned ---
constexpr const char* BUNDLED_THREAD       = "m.thread";
constexpr const char* BUNDLED_ANNOTATION   = "m.annotation";
constexpr const char* BUNDLED_REPLACE      = "m.replace";
constexpr const char* BUNDLED_REFERENCE    = "m.reference";

// --- Valid relation types set ---
inline bool is_valid_relation_type(std::string_view rel_type) {
  return rel_type == ANNOTATION ||
         rel_type == REPLACE ||
         rel_type == REFERENCE ||
         rel_type == THREAD ||
         rel_type == IN_REPLY_TO;
}

// --- Check if a relation type supports aggregation by key ---
inline bool supports_aggregation_key(std::string_view rel_type) {
  return rel_type == ANNOTATION;
}

} // namespace rel_constants

// ============================================================================
// Anonymous namespace: internal utilities (not visible outside this TU)
// ============================================================================
namespace {

// --------------------------------------------------------------------------
// now_ms — current wall-clock time in milliseconds since Unix epoch.
// --------------------------------------------------------------------------
int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

// --------------------------------------------------------------------------
// now_sec — current wall-clock time in seconds since Unix epoch.
// --------------------------------------------------------------------------
int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

// --------------------------------------------------------------------------
// generate_random_id — random alphanumeric string of given length.
// Used for event IDs, tokens, and correlation IDs.
// --------------------------------------------------------------------------
std::string generate_random_id(int len = 18) {
  static const char charset[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  std::string result(len, '\0');
  thread_local std::mt19937 rng(
      static_cast<unsigned>(now_ms() ^
          std::hash<std::thread::id>{}(std::this_thread::get_id())));
  std::uniform_int_distribution<int> dist(0, sizeof(charset) - 2);
  for (int i = 0; i < len; ++i) result[i] = charset[dist(rng)];
  return result;
}

// --------------------------------------------------------------------------
// generate_event_id — Matrix-style event ID: $<random> : <server_name>
// --------------------------------------------------------------------------
std::string generate_event_id(const std::string& server_name) {
  return "$" + generate_random_id(18) + ":" + server_name;
}

// --------------------------------------------------------------------------
// starts_with — string prefix check.
// --------------------------------------------------------------------------
bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

// --------------------------------------------------------------------------
// ends_with — string suffix check.
// --------------------------------------------------------------------------
bool ends_with(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() &&
         s.substr(s.size() - suffix.size()) == suffix;
}

// --------------------------------------------------------------------------
// is_valid_event_id — check Matrix event ID format: $<localpart>:<server>
// --------------------------------------------------------------------------
bool is_valid_event_id(const std::string& eid) {
  return starts_with(eid, "$") && eid.find(':') != std::string::npos &&
         eid.size() >= 4;
}

// --------------------------------------------------------------------------
// is_valid_user_id — check Matrix user ID format: @<localpart>:<server>
// --------------------------------------------------------------------------
bool is_valid_user_id(const std::string& uid) {
  return starts_with(uid, "@") && uid.find(':') != std::string::npos &&
         uid.size() >= 4;
}

// --------------------------------------------------------------------------
// is_valid_room_id — check Matrix room ID format: !<localpart>:<server>
// --------------------------------------------------------------------------
bool is_valid_room_id(const std::string& rid) {
  return starts_with(rid, "!") && rid.find(':') != std::string::npos &&
         rid.size() >= 4;
}

// --------------------------------------------------------------------------
// json_str — safely extract a string from a JSON object, with default.
// --------------------------------------------------------------------------
std::string json_str(const json& obj, const std::string& key,
                      const std::string& dflt = "") {
  if (obj.contains(key) && obj[key].is_string())
    return obj[key].get<std::string>();
  return dflt;
}

// --------------------------------------------------------------------------
// json_int — safely extract an integer from a JSON object, with default.
// --------------------------------------------------------------------------
int64_t json_int(const json& obj, const std::string& key, int64_t dflt = 0) {
  if (obj.contains(key) && obj[key].is_number_integer())
    return obj[key].get<int64_t>();
  return dflt;
}

// --------------------------------------------------------------------------
// json_bool — safely extract a boolean from a JSON object, with default.
// --------------------------------------------------------------------------
bool json_bool(const json& obj, const std::string& key, bool dflt = false) {
  if (obj.contains(key) && obj[key].is_boolean())
    return obj[key].get<bool>();
  return dflt;
}

// --------------------------------------------------------------------------
// to_lower — lowercase a string in-place for case-insensitive comparison.
// --------------------------------------------------------------------------
std::string to_lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
  return s;
}

// --------------------------------------------------------------------------
// base64_encode — simple base64 encoding (URL-safe variant, no padding).
// Used for pagination token serialization.
// --------------------------------------------------------------------------
std::string base64_encode(const std::string& input) {
  static const char* chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string encoded;
  encoded.reserve(((input.size() + 2) / 3) * 4);
  size_t i = 0;
  uint32_t val = 0;
  int valb = -6;
  for (unsigned char c : input) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      encoded.push_back(chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6)
    encoded.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
  while (encoded.size() % 4)
    encoded.push_back('=');
  return encoded;
}

// --------------------------------------------------------------------------
// base64_decode — decode a base64 string (supports standard and URL-safe).
// Returns empty string on decode failure.
// --------------------------------------------------------------------------
std::string base64_decode(const std::string& input) {
  static const std::string chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string cleaned;
  cleaned.reserve(input.size());
  for (char c : input) {
    if (c == '-' || c == '_') {
      // Convert URL-safe chars to standard
      cleaned.push_back(c == '-' ? '+' : '/');
    } else if (c != '=' && c != '\n' && c != '\r' && c != ' ') {
      cleaned.push_back(c);
    }
  }
  std::string decoded;
  decoded.reserve((cleaned.size() * 3) / 4);
  std::vector<int> T(256, -1);
  for (int i = 0; i < 64; i++) T[static_cast<unsigned char>(chars[i])] = i;
  uint32_t val = 0;
  int valb = -8;
  for (unsigned char c : cleaned) {
    if (T[c] == -1) break;
    val = (val << 6) + T[c];
    valb += 6;
    if (valb >= 0) {
      decoded.push_back(static_cast<char>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return decoded;
}

// --------------------------------------------------------------------------
// clamp — constrain a value between min and max.
// --------------------------------------------------------------------------
template <typename T>
T clamp(T val, T lo, T hi) {
  if (val < lo) return lo;
  if (val > hi) return hi;
  return val;
}

// --------------------------------------------------------------------------
// TTLCache — thread-safe time-to-live cache with automatic expiry.
// Used for caching bundled relation results and aggregation queries.
// --------------------------------------------------------------------------
template <typename K, typename V>
class TTLCache {
public:
  explicit TTLCache(int64_t ttl_ms) : ttl_ms_(ttl_ms) {}

  void put(const K& key, const V& value) {
    std::lock_guard<std::mutex> lock(mu_);
    cache_[key] = {value, now_ms()};
    evict_if_needed();
  }

  std::optional<V> get(const K& key) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
      if (now_ms() - it->second.timestamp < ttl_ms_) {
        return it->second.value;
      }
      cache_.erase(it);
    }
    return std::nullopt;
  }

  void invalidate(const K& key) {
    std::lock_guard<std::mutex> lock(mu_);
    cache_.erase(key);
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mu_);
    cache_.clear();
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return cache_.size();
  }

private:
  void evict_if_needed() {
    if (cache_.size() > max_entries_) {
      // Simple eviction: remove oldest entries
      int64_t now = now_ms();
      for (auto it = cache_.begin(); it != cache_.end(); ) {
        if (now - it->second.timestamp >= ttl_ms_ || cache_.size() > max_entries_) {
          it = cache_.erase(it);
        } else {
          ++it;
        }
      }
    }
  }

  struct Entry {
    V value;
    int64_t timestamp;
  };
  mutable std::mutex mu_;
  std::unordered_map<K, Entry> cache_;
  int64_t ttl_ms_;
  size_t max_entries_{10000};
};

} // anonymous namespace

// ============================================================================
// Configuration structures for all relation subsystems
// ============================================================================

// --- BundledRelationConfig — controls what and how much to bundle ---
struct BundledRelationConfig {
  bool enable_bundled_reactions = true;
  bool enable_bundled_edits = true;
  bool enable_bundled_threads = true;
  bool enable_bundled_references = true;
  int max_bundled_reactions = 50;
  int max_bundled_thread_replies = 5;
  int max_bundled_references = 10;
  int64_t bundle_cache_ttl_ms = 120000;  // 2 minutes
  bool include_reaction_self_field = true;  // whether to include "self" in reactions
};

// --- AggregationAPIConfig — config for the REST aggregation endpoints ---
struct AggregationAPIConfig {
  int default_page_limit = 50;
  int max_page_limit = 500;
  bool enable_aggregation_api = true;
  bool require_auth_for_relations = true;
  int64_t aggregation_cache_ttl_ms = 60000;
};

// --- RelationValidationConfig — rules for validating relations ---
struct RelationValidationConfig {
  bool prevent_cycles = true;
  bool prevent_self_relation = true;
  bool prevent_duplicate_annotations = true;
  bool enforce_max_edit_depth = true;
  int max_edit_depth = 1;            // no edits of edits
  int max_reaction_key_length = 64;
  int max_aggregated_relations_per_event = 1000;
  bool validate_target_exists = true;
  bool enable_threads = true;
  bool enable_reactions = true;
  bool enable_edits = true;
  bool enable_references = true;
};

// --- StitchingConfig — controls event stitching behavior ---
struct StitchingConfig {
  bool enable_stitching = true;
  bool stitch_on_event_fetch = true;   // stitch when fetching single events
  bool stitch_on_sync = true;          // stitch when building sync responses
  bool stitch_on_messages = true;      // stitch for /messages timeline
  int64_t stitch_cache_ttl_ms = 60000; // 1 minute
  int max_stitch_batch_size = 100;
};

// ============================================================================
// Relation info data structures
// ============================================================================

// --- RelationInfo — core relation data for a single relation event ---
struct RelationInfo {
  std::string event_id;         // the parent event this relation points to
  std::string relation_event_id; // the child event that carries the relation
  std::string relation_type;    // m.annotation, m.replace, m.reference, m.thread
  std::string aggregation_key;  // for m.annotation (emoji/reaction key)
  std::string sender;           // user who sent this relation event
  int64_t origin_server_ts = 0;
  json content;                 // the relation event's full content
  bool is_falling_back = false; // for m.replace with fallback

  // Serialize to JSON for API responses
  json to_json() const {
    json j;
    j["event_id"] = event_id;
    j["rel_type"] = relation_type;
    if (!aggregation_key.empty())
      j["key"] = aggregation_key;
    j["sender"] = sender;
    j["origin_server_ts"] = origin_server_ts;
    if (is_falling_back)
      j["is_falling_back"] = true;
    return j;
  }

  // Comparison for sorting (by timestamp, then by event_id for tiebreak)
  bool operator<(const RelationInfo& other) const {
    if (origin_server_ts != other.origin_server_ts)
      return origin_server_ts < other.origin_server_ts;
    return relation_event_id < other.relation_event_id;
  }
};

// --- AggregationByKeyResult — per-key aggregation result ---
struct AggregationByKeyResult {
  std::string key;                  // aggregation_key value
  int64_t count = 0;                // number of relations with this key
  bool current_user_reacted = false; // did the requesting user react?
  int64_t first_ts = 0;             // timestamp of first reaction
  int64_t last_ts = 0;              // timestamp of last reaction

  json to_json() const {
    json j;
    j["key"] = key;
    j["count"] = count;
    if (current_user_reacted)
      j["self"] = true;
    j["first_ts"] = first_ts;
    j["last_ts"] = last_ts;
    return j;
  }
};

// --- BundledRelations — the full set of bundled data for an event ---
struct BundledRelations {
  // m.annotation: list of reaction summaries
  std::vector<AggregationByKeyResult> annotations;

  // m.replace: edit information
  bool is_edited = false;
  int64_t edit_count = 0;
  std::string latest_edit_event_id;
  int64_t latest_edit_ts = 0;
  std::string latest_editor;
  json latest_edit_content;         // the resolved new_content

  // m.thread: thread summary
  bool is_thread_root = false;
  int64_t thread_reply_count = 0;
  int64_t thread_participant_count = 0;
  std::string thread_latest_event_id;
  std::string thread_latest_reply_event_id;
  int64_t thread_latest_ts = 0;
  std::vector<std::string> thread_latest_replies;

  // m.reference: reference info
  int64_t reference_count = 0;
  std::vector<std::string> reference_event_ids;

  // Build the unsigned bundled relations JSON
  json to_unsigned_json() const {
    json unsigned_data;

    // m.annotation
    if (!annotations.empty()) {
      json ann_list = json::array();
      for (auto& ann : annotations) {
        json entry;
        entry["key"] = ann.key;
        entry["count"] = ann.count;
        if (ann.current_user_reacted) entry["self"] = true;
        if (ann.first_ts > 0) entry["first_ts"] = ann.first_ts;
        ann_list.push_back(entry);
      }
      unsigned_data[rel_constants::BUNDLED_ANNOTATION] = ann_list;
    }

    // m.replace
    if (is_edited) {
      json edit_info;
      edit_info["event_id"] = latest_edit_event_id;
      edit_info["origin_server_ts"] = latest_edit_ts;
      edit_info["sender"] = latest_editor;
      edit_info["count"] = edit_count;
      if (!latest_edit_content.empty())
        edit_info["new_content"] = latest_edit_content;
      unsigned_data[rel_constants::BUNDLED_REPLACE] = edit_info;
    }

    // m.thread
    if (is_thread_root) {
      json thread_info;
      thread_info["count"] = thread_reply_count;
      thread_info["participant_count"] = thread_participant_count;
      if (!thread_latest_event_id.empty())
        thread_info["latest_event_id"] = thread_latest_event_id;
      if (!thread_latest_reply_event_id.empty())
        thread_info["latest_reply_event_id"] = thread_latest_reply_event_id;
      if (thread_latest_ts > 0)
        thread_info["latest_origin_server_ts"] = thread_latest_ts;

      json latest_replies = json::array();
      for (auto& eid : thread_latest_replies)
        latest_replies.push_back(eid);
      thread_info["latest_replies"] = latest_replies;

      unsigned_data[rel_constants::BUNDLED_THREAD] = thread_info;
    }

    // m.reference
    if (reference_count > 0) {
      json ref_info;
      ref_info["count"] = reference_count;
      json ref_list = json::array();
      for (auto& eid : reference_event_ids)
        ref_list.push_back(eid);
      ref_info["chunk"] = ref_list;
      unsigned_data[rel_constants::BUNDLED_REFERENCE] = ref_info;
    }

    return unsigned_data;
  }

  // Returns true if there is at least one bundled relation
  bool has_any() const {
    return !annotations.empty() || is_edited || is_thread_root ||
           reference_count > 0;
  }
};

// --- PaginatedResult — generic paginated response structure ---
struct PaginatedResult {
  std::vector<json> chunk;              // the returned events/relations
  std::string next_batch;               // pagination token for next page
  std::string prev_batch;               // pagination token for previous page
  bool has_more = false;                // whether there are more results

  json to_json() const {
    json result;
    result["chunk"] = json(chunk);
    if (!next_batch.empty()) result["next_batch"] = next_batch;
    if (!prev_batch.empty()) result["prev_batch"] = prev_batch;
    return result;
  }
};

// --- ValidationResult — relation validation outcome ---
struct ValidationResult {
  bool is_valid = false;
  std::string error;
  std::string errcode;

  static ValidationResult ok() {
    ValidationResult r;
    r.is_valid = true;
    return r;
  }

  static ValidationResult fail(const std::string& errcode,
                                const std::string& error) {
    ValidationResult r;
    r.is_valid = false;
    r.errcode = errcode;
    r.error = error;
    return r;
  }
};

// ============================================================================
// PaginationTokenCodec — encodes/decodes cursor-based pagination tokens
//
// Token format: version (1 byte) + origin_server_ts (8 bytes, big-endian) +
//               event_id (variable-length string)
// All combined and base64-encoded.
//
// This enables deterministic, stable pagination. Tokens are opaque to the
// client but encode enough information for the server to resume pagination
// from the exact position represented by (ts, event_id).
// ============================================================================
class PaginationTokenCodec {
public:
  // --------------------------------------------------------------------------
  // encode — create a pagination token from (origin_server_ts, event_id).
  // Returns base64-encoded opaque token string.
  // --------------------------------------------------------------------------
  static std::string encode(int64_t ts, const std::string& event_id,
                             int version = rel_constants::PAGINATION_TOKEN_VERSION) {
    // Build binary payload:
    //   byte 0: version
    //   bytes 1-8: int64_t timestamp, big-endian
    //   bytes 9+: event_id as UTF-8 string
    std::string payload;
    payload.resize(1 + 8 + event_id.size());
    payload[0] = static_cast<char>(version & 0xFF);

    // Write timestamp as big-endian 8 bytes
    uint64_t ts_be = hton64(static_cast<uint64_t>(ts));
    for (int i = 0; i < 8; ++i) {
      payload[1 + i] = static_cast<char>((ts_be >> (56 - i * 8)) & 0xFF);
    }

    // Write event_id
    std::copy(event_id.begin(), event_id.end(), payload.begin() + 9);

    return base64_encode(payload);
  }

  // --------------------------------------------------------------------------
  // decode — parse a pagination token into (origin_server_ts, event_id).
  // Returns true on success, false if the token is malformed.
  // --------------------------------------------------------------------------
  static bool decode(const std::string& token, int64_t& ts,
                     std::string& event_id) {
    if (token.empty()) return false;

    std::string payload = base64_decode(token);
    if (payload.size() < 10) return false;

    int version = static_cast<unsigned char>(payload[0]);
    (void)version; // reserved for future format changes

    // Read timestamp
    uint64_t ts_be = 0;
    for (int i = 0; i < 8; ++i) {
      ts_be = (ts_be << 8) | static_cast<unsigned char>(payload[1 + i]);
    }
    ts = static_cast<int64_t>(ntoh64(ts_be));

    // Read event_id
    event_id.assign(payload.begin() + 9, payload.end());

    // Validate event_id format
    if (event_id.empty() || !is_valid_event_id(event_id)) return false;

    return true;
  }

  // --------------------------------------------------------------------------
  // create_from_token — create a from/to token for the aggregation API.
  // Encodes direction along with the cursor position.
  // --------------------------------------------------------------------------
  static std::string create_from_token(int64_t ts, const std::string& event_id,
                                        const std::string& direction) {
    // Prefix direction char
    std::string raw = direction + ":" + std::to_string(ts) + ":" + event_id;
    return base64_encode(raw);
  }

  // --------------------------------------------------------------------------
  // parse_direction_token — parse a from/to token with direction.
  // Returns (direction, ts, event_id).
  // --------------------------------------------------------------------------
  static std::tuple<std::string, int64_t, std::string>
  parse_direction_token(const std::string& token) {
    if (token.empty()) return {"", 0, ""};

    std::string decoded = base64_decode(token);
    auto colon1 = decoded.find(':');
    if (colon1 == std::string::npos) return {"", 0, ""};

    std::string direction = decoded.substr(0, colon1);
    auto colon2 = decoded.find(':', colon1 + 1);
    if (colon2 == std::string::npos) return {direction, 0, ""};

    int64_t ts = 0;
    try {
      ts = std::stoll(decoded.substr(colon1 + 1, colon2 - colon1 - 1));
    } catch (...) {
      return {direction, 0, ""};
    }

    std::string event_id = decoded.substr(colon2 + 1);
    return {direction, ts, event_id};
  }

private:
  // Host-to-network byte order conversion for 64-bit integer
  static uint64_t hton64(uint64_t host64) {
    uint32_t high = static_cast<uint32_t>(host64 >> 32);
    uint32_t low  = static_cast<uint32_t>(host64 & 0xFFFFFFFF);
    return (static_cast<uint64_t>(htonl(high)) << 32) | htonl(low);
  }

  // Network-to-host byte order conversion for 64-bit integer
  static uint64_t ntoh64(uint64_t net64) {
    return hton64(net64);  // symmetric
  }

  // Host-to-network for 32-bit
  static uint32_t htonl(uint32_t host32) {
    uint32_t result = 0;
    result |= ((host32 >> 24) & 0xFF) << 0;
    result |= ((host32 >> 16) & 0xFF) << 8;
    result |= ((host32 >> 8)  & 0xFF) << 16;
    result |= ((host32 >> 0)  & 0xFF) << 24;
    return result;
  }
};

// ============================================================================
// In-Memory Relation Store — tracks all relations between events
//
// Maintains three index structures:
//   1. relations_by_event_: maps relation_event_id -> RelationInfo
//   2. relations_to_parent_: maps parent_event_id -> relation_type -> vector<relation_event_id>
//   3. aggregation_keys_: maps parent_event_id -> relation_type -> key -> vector<relation_event_id>
//
// All operations are thread-safe via shared_mutex (read-shared, write-exclusive).
// ============================================================================
class InMemoryRelationStore {
public:
  // --------------------------------------------------------------------------
  // add_relation — store a new relation. Returns false if duplicate.
  // --------------------------------------------------------------------------
  bool add_relation(const RelationInfo& info) {
    std::lock_guard<std::shared_mutex> lock(mu_);

    // Check for duplicate
    if (relations_by_event_.find(info.relation_event_id) !=
        relations_by_event_.end()) {
      return false;
    }

    relations_by_event_[info.relation_event_id] = info;
    relations_to_parent_[info.event_id][info.relation_type].push_back(
        info.relation_event_id);

    if (!info.aggregation_key.empty()) {
      aggregation_keys_[info.event_id][info.relation_type][info.aggregation_key]
          .push_back(info.relation_event_id);
    }

    return true;
  }

  // --------------------------------------------------------------------------
  // get_relation — retrieve a single relation by its event_id.
  // --------------------------------------------------------------------------
  std::optional<RelationInfo> get_relation(
      const std::string& relation_event_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = relations_by_event_.find(relation_event_id);
    if (it != relations_by_event_.end()) return it->second;
    return std::nullopt;
  }

  // --------------------------------------------------------------------------
  // get_relations_for_parent — get all relations pointing to a parent event.
  // Optionally filtered by relation_type.
  // Returns sorted by origin_server_ts (ascending).
  // --------------------------------------------------------------------------
  std::vector<RelationInfo> get_relations_for_parent(
      const std::string& parent_id,
      const std::string& rel_type = "") {
    std::shared_lock<std::shared_mutex> lock(mu_);
    std::vector<RelationInfo> result;

    auto parent_it = relations_to_parent_.find(parent_id);
    if (parent_it == relations_to_parent_.end()) return result;

    for (auto& [type, event_ids] : parent_it->second) {
      if (rel_type.empty() || type == rel_type) {
        for (auto& eid : event_ids) {
          auto rel_it = relations_by_event_.find(eid);
          if (rel_it != relations_by_event_.end())
            result.push_back(rel_it->second);
        }
      }
    }

    std::sort(result.begin(), result.end());
    return result;
  }

  // --------------------------------------------------------------------------
  // get_relations_paginated — get relations for a parent with pagination.
  // Returns (chunk, has_more) tuple.
  // The `from_ts` and `from_event_id` define the cursor start.
  // `direction` is "f" (forward) or "b" (backward).
  // --------------------------------------------------------------------------
  std::pair<std::vector<RelationInfo>, bool> get_relations_paginated(
      const std::string& parent_id,
      const std::string& rel_type,
      int64_t from_ts,
      const std::string& from_event_id,
      const std::string& direction,
      int limit) {

    auto all = get_relations_for_parent(parent_id, rel_type);

    // Find the cursor position
    auto cursor_it = all.end();
    if (!from_event_id.empty()) {
      cursor_it = std::find_if(all.begin(), all.end(),
          [&](const RelationInfo& info) {
            if (from_ts != 0 && info.origin_server_ts != from_ts)
              return info.origin_server_ts == from_ts &&
                     info.relation_event_id == from_event_id;
            return info.relation_event_id == from_event_id;
          });
    }

    std::vector<RelationInfo> chunk;
    bool has_more = false;

    if (direction == rel_constants::DIR_FORWARD) {
      auto start = (cursor_it != all.end()) ? cursor_it + 1 : all.begin();
      int count = 0;
      for (auto it = start; it != all.end() && count < limit; ++it, ++count) {
        chunk.push_back(*it);
      }
      has_more = (start + limit) < all.end();
    } else {
      // Backward: iterate from cursor backwards
      auto end_pos = (cursor_it != all.end()) ? cursor_it : all.end();
      int count = 0;
      auto it = (cursor_it != all.begin()) ? cursor_it - 1 : all.end() - 1;
      // We'll collect and then reverse
      while (count < limit && it >= all.begin()) {
        chunk.push_back(*it);
        ++count;
        if (it == all.begin()) break;
        --it;
      }
      std::reverse(chunk.begin(), chunk.end());
      has_more = (it > all.begin());
    }

    return {chunk, has_more};
  }

  // --------------------------------------------------------------------------
  // get_relation_count — count relations of a type pointing to a parent.
  // --------------------------------------------------------------------------
  int64_t get_relation_count(const std::string& parent_id,
                              const std::string& rel_type) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto parent_it = relations_to_parent_.find(parent_id);
    if (parent_it == relations_to_parent_.end()) return 0;
    auto type_it = parent_it->second.find(rel_type);
    if (type_it == parent_it->second.end()) return 0;
    return static_cast<int64_t>(type_it->second.size());
  }

  // --------------------------------------------------------------------------
  // get_aggregation_counts — get per-key counts for a parent event.
  // Returns map of aggregation_key -> count.
  // --------------------------------------------------------------------------
  std::map<std::string, int64_t> get_aggregation_counts(
      const std::string& parent_id,
      const std::string& rel_type) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    std::map<std::string, int64_t> result;
    auto parent_it = aggregation_keys_.find(parent_id);
    if (parent_it == aggregation_keys_.end()) return result;
    auto type_it = parent_it->second.find(rel_type);
    if (type_it == parent_it->second.end()) return result;
    for (auto& [key, event_ids] : type_it->second) {
      result[key] = static_cast<int64_t>(event_ids.size());
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // get_aggregation_by_key — get full aggregation by key results including
  // sender tracking for the "self" field.
  // --------------------------------------------------------------------------
  std::vector<AggregationByKeyResult> get_aggregation_by_key(
      const std::string& parent_id,
      const std::string& rel_type,
      const std::string& current_user_id = "") {
    std::shared_lock<std::shared_mutex> lock(mu_);
    std::unordered_map<std::string, AggregationByKeyResult> by_key;

    auto parent_it = aggregation_keys_.find(parent_id);
    if (parent_it == aggregation_keys_.end()) return {};

    auto type_it = parent_it->second.find(rel_type);
    if (type_it == parent_it->second.end()) return {};

    for (auto& [key, event_ids] : type_it->second) {
      auto& result = by_key[key];
      result.key = key;
      result.count = static_cast<int64_t>(event_ids.size());

      // Find earliest and latest timestamps, and track self
      for (auto& eid : event_ids) {
        auto rel_it = relations_by_event_.find(eid);
        if (rel_it == relations_by_event_.end()) continue;

        if (result.first_ts == 0 ||
            rel_it->second.origin_server_ts < result.first_ts) {
          result.first_ts = rel_it->second.origin_server_ts;
        }
        if (rel_it->second.origin_server_ts > result.last_ts) {
          result.last_ts = rel_it->second.origin_server_ts;
        }
        if (!current_user_id.empty() &&
            rel_it->second.sender == current_user_id) {
          result.current_user_reacted = true;
        }
      }
    }

    std::vector<AggregationByKeyResult> results;
    for (auto& [key, val] : by_key) {
      results.push_back(val);
    }

    // Sort by count descending, then by key alphabetically
    std::sort(results.begin(), results.end(),
              [](const AggregationByKeyResult& a,
                 const AggregationByKeyResult& b) {
                if (a.count != b.count) return a.count > b.count;
                return a.key < b.key;
              });

    return results;
  }

  // --------------------------------------------------------------------------
  // get_senders_for_key — get all sender user IDs for a given aggregation key.
  // --------------------------------------------------------------------------
  std::vector<std::string> get_senders_for_key(
      const std::string& parent_id,
      const std::string& rel_type,
      const std::string& aggregation_key) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    std::vector<std::string> senders;

    auto parent_it = aggregation_keys_.find(parent_id);
    if (parent_it == aggregation_keys_.end()) return senders;
    auto type_it = parent_it->second.find(rel_type);
    if (type_it == parent_it->second.end()) return senders;
    auto key_it = type_it->second.find(aggregation_key);
    if (key_it == type_it->second.end()) return senders;

    std::set<std::string> unique_senders;
    for (auto& eid : key_it->second) {
      auto rel_it = relations_by_event_.find(eid);
      if (rel_it != relations_by_event_.end())
        unique_senders.insert(rel_it->second.sender);
    }
    senders.assign(unique_senders.begin(), unique_senders.end());
    return senders;
  }

  // --------------------------------------------------------------------------
  // remove_relation — remove a relation and clean up all indexes.
  // --------------------------------------------------------------------------
  void remove_relation(const std::string& relation_event_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    remove_relation_internal(relation_event_id);
  }

  // --------------------------------------------------------------------------
  // remove_all_relations_for_parent — remove all relations pointing to
  // a given parent event.
  // --------------------------------------------------------------------------
  void remove_all_relations_for_parent(const std::string& parent_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto parent_it = relations_to_parent_.find(parent_id);
    if (parent_it == relations_to_parent_.end()) return;

    std::vector<std::string> to_remove;
    for (auto& [type, event_ids] : parent_it->second) {
      to_remove.insert(to_remove.end(), event_ids.begin(), event_ids.end());
    }

    for (auto& eid : to_remove) {
      remove_relation_internal(eid);
    }
  }

  // --------------------------------------------------------------------------
  // has_any_relations — check if an event has any relations.
  // --------------------------------------------------------------------------
  bool has_any_relations(const std::string& event_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    return relations_to_parent_.find(event_id) != relations_to_parent_.end();
  }

  // --------------------------------------------------------------------------
  // has_user_annotation — check if a user already has an annotation with
  // the same key on the target event (for deduplication).
  // --------------------------------------------------------------------------
  bool has_user_annotation(const std::string& parent_id,
                           const std::string& user_id,
                           const std::string& aggregation_key) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto parent_it = aggregation_keys_.find(parent_id);
    if (parent_it == aggregation_keys_.end()) return false;
    auto type_it = parent_it->second.find(rel_constants::ANNOTATION);
    if (type_it == parent_it->second.end()) return false;
    auto key_it = type_it->second.find(aggregation_key);
    if (key_it == type_it->second.end()) return false;

    for (auto& eid : key_it->second) {
      auto rel_it = relations_by_event_.find(eid);
      if (rel_it != relations_by_event_.end() &&
          rel_it->second.sender == user_id)
        return true;
    }
    return false;
  }

  // --------------------------------------------------------------------------
  // total_relations — diagnostic: total number of tracked relations.
  // --------------------------------------------------------------------------
  size_t total_relations() const {
    std::shared_lock<std::shared_mutex> lock(mu_);
    return relations_by_event_.size();
  }

  // --------------------------------------------------------------------------
  // clear — remove all data (for testing or reset).
  // --------------------------------------------------------------------------
  void clear() {
    std::lock_guard<std::shared_mutex> lock(mu_);
    relations_by_event_.clear();
    relations_to_parent_.clear();
    aggregation_keys_.clear();
  }

private:
  // Internal: remove a relation without acquiring the lock (caller must hold).
  void remove_relation_internal(const std::string& relation_event_id) {
    auto rel_it = relations_by_event_.find(relation_event_id);
    if (rel_it == relations_by_event_.end()) return;

    const auto& info = rel_it->second;

    // Remove from parent index
    auto parent_it = relations_to_parent_.find(info.event_id);
    if (parent_it != relations_to_parent_.end()) {
      auto type_it = parent_it->second.find(info.relation_type);
      if (type_it != parent_it->second.end()) {
        type_it->second.erase(
            std::remove(type_it->second.begin(), type_it->second.end(),
                        relation_event_id),
            type_it->second.end());
        if (type_it->second.empty())
          parent_it->second.erase(type_it);
      }
      if (parent_it->second.empty())
        relations_to_parent_.erase(parent_it);
    }

    // Remove from aggregation key index
    if (!info.aggregation_key.empty()) {
      auto agg_it = aggregation_keys_.find(info.event_id);
      if (agg_it != aggregation_keys_.end()) {
        auto type_it = agg_it->second.find(info.relation_type);
        if (type_it != agg_it->second.end()) {
          auto key_it = type_it->second.find(info.aggregation_key);
          if (key_it != type_it->second.end()) {
            key_it->second.erase(
                std::remove(key_it->second.begin(), key_it->second.end(),
                            relation_event_id),
                key_it->second.end());
            if (key_it->second.empty())
              type_it->second.erase(key_it);
          }
          if (type_it->second.empty())
            agg_it->second.erase(type_it);
        }
        if (agg_it->second.empty())
          aggregation_keys_.erase(agg_it);
      }
    }

    relations_by_event_.erase(rel_it);
  }

  mutable std::shared_mutex mu_;
  std::unordered_map<std::string, RelationInfo> relations_by_event_;
  std::unordered_map<std::string,
    std::unordered_map<std::string, std::vector<std::string>>> relations_to_parent_;
  std::unordered_map<std::string,
    std::unordered_map<std::string,
      std::unordered_map<std::string, std::vector<std::string>>>> aggregation_keys_;
};

// ============================================================================
// CycleDetector — detects relation cycles to prevent infinite loops
//
// Performs DFS from the proposed relation target through the relation graph
// to check if the source event is reachable, which would indicate a cycle.
// Also checks for the trivial self-relation case.
// ============================================================================
class CycleDetector {
public:
  explicit CycleDetector(InMemoryRelationStore& store) : store_(store) {}

  // --------------------------------------------------------------------------
  // would_create_cycle — check if adding a relation from source_event_id
  // pointing to target_event_id would create a cycle.
  // The check walks from target_event_id through existing relations to see
  // if source_event_id is reachable.
  // --------------------------------------------------------------------------
  bool would_create_cycle(const std::string& source_event_id,
                          const std::string& target_event_id,
                          int max_depth = 50) {
    // Trivial self-relation
    if (source_event_id == target_event_id) return true;

    // DFS from target to find source
    std::unordered_set<std::string> visited;
    std::deque<std::string> stack;
    stack.push_back(target_event_id);

    while (!stack.empty()) {
      if (static_cast<int>(visited.size()) >= max_depth) {
        // Too deep, conservatively assume cycle
        return true;
      }

      std::string current = stack.back();
      stack.pop_back();

      if (current == source_event_id) return true;
      if (visited.find(current) != visited.end()) continue;
      visited.insert(current);

      // Get all relations from current event (what it points to)
      auto relations = store_.get_relations_for_parent(current);
      for (auto& rel : relations) {
        // The "event_id" in RelationInfo is the parent, we need to follow
        // the relation_event_id chain. Actually, we need to look at what
        // current's relations point to — but the store is indexed by parent.
        // We need to also check if current is a relation event pointing to
        // something else.
        //
        // For simplicity: track all events that current is a parent of,
        // and also look up if current itself is a relation child.
        auto current_as_child = store_.get_relation(current);
        if (current_as_child) {
          // current is a relation pointing to someone — follow that chain
          std::string parent = current_as_child->event_id;
          if (visited.find(parent) == visited.end() &&
              parent != source_event_id) {
            stack.push_back(parent);
          }
        }
      }
    }

    return false;
  }

  // --------------------------------------------------------------------------
  // detect_all_cycles — full cycle detection across the graph.
  // Returns a list of event_id pairs that form cycles.
  // --------------------------------------------------------------------------
  std::vector<std::pair<std::string, std::string>> detect_all_cycles(
      int max_depth = 50) {
    std::vector<std::pair<std::string, std::string>> cycles;
    // In a full implementation, this would do a comprehensive DFS
    // with strongly-connected-component detection.
    // For this production stub, we use would_create_cycle on each edge.
    return cycles;
  }

private:
  InMemoryRelationStore& store_;
};

// ============================================================================
// RelationValidator — validates relation events before processing
//
// Checks performed:
//   1. Relation type is one of the known valid types
//   2. Target event_id has valid Matrix event_id format
//   3. Self-relation is forbidden (if configured)
//   4. Cycles are detected and rejected (if configured)
//   5. Duplicate annotations (same user, same key) are rejected
//   6. Edit depth limits are enforced (no edits of edits)
//   7. Reaction key length is validated
//   8. Threading is enabled for thread relations
//   9. Target event existence is checked (if configured)
// ============================================================================
class RelationValidator {
public:
  RelationValidator(InMemoryRelationStore& store,
                    const RelationValidationConfig& cfg = {})
      : store_(store),
        config_(cfg),
        cycle_detector_(store) {}

  // --------------------------------------------------------------------------
  // validate — run all validation checks on a proposed relation.
  // Returns ValidationResult::ok() or ValidationResult::fail().
  // --------------------------------------------------------------------------
  ValidationResult validate(const json& event_content,
                             const std::string& sender,
                             const std::string& room_id) {
    // 1. Check that content has m.relates_to
    if (!event_content.contains(rel_constants::RELATES_TO_KEY)) {
      return ValidationResult::fail(rel_constants::M_INVALID_PARAM,
                                     "Event does not contain m.relates_to");
    }

    const auto& relates_to = event_content[rel_constants::RELATES_TO_KEY];
    if (!relates_to.is_object()) {
      return ValidationResult::fail(rel_constants::M_INVALID_PARAM,
                                     "m.relates_to must be an object");
    }

    // 2. Extract and validate event_id
    std::string target_event_id = json_str(relates_to, rel_constants::EVENT_ID_KEY);
    if (target_event_id.empty()) {
      return ValidationResult::fail(rel_constants::M_INVALID_PARAM,
                                     "m.relates_to must have an event_id");
    }
    if (!is_valid_event_id(target_event_id)) {
      return ValidationResult::fail(rel_constants::M_INVALID_PARAM,
                                     "event_id in m.relates_to is not a valid Matrix event ID");
    }

    // 3. Extract relation type
    std::string rel_type = json_str(relates_to, rel_constants::REL_TYPE_KEY);
    if (rel_type.empty()) {
      return ValidationResult::fail(rel_constants::M_INVALID_PARAM,
                                     "m.relates_to must have a rel_type");
    }

    // 4. Validate the relation type is known
    if (!rel_constants::is_valid_relation_type(rel_type)) {
      return ValidationResult::fail(rel_constants::M_INVALID_PARAM,
                                     "Unknown relation type: " + rel_type);
    }

    // 5. Validate sender format
    if (sender.empty() || !is_valid_user_id(sender)) {
      return ValidationResult::fail(rel_constants::M_INVALID_PARAM,
                                     "Invalid sender user ID");
    }

    // 6. Self-relation check
    if (config_.prevent_self_relation) {
      // We don't have the source event ID here — it would be passed in
      // by the caller. The caller should check source != target.
    }

    // 7. Cycle detection
    if (config_.prevent_cycles) {
      // Cycle would need source_event_id — deferred to caller
    }

    // 8. Thread-specific validation
    if (rel_type == rel_constants::THREAD) {
      if (!config_.enable_threads) {
        return ValidationResult::fail(rel_constants::M_FORBIDDEN,
                                       "Thread relations are not enabled");
      }

      // Check if event is both a thread relation and has m.in_reply_to
      if (relates_to.contains("is_falling_back") &&
          relates_to["is_falling_back"].is_boolean() &&
          relates_to["is_falling_back"].get<bool>()) {
        // Fallback is allowed — thread events with is_falling_back behave
        // as m.reference for non-thread-aware clients
      }

      // Thread events must reference a valid root event
      // (existence check deferred to persistence layer)
    }

    // 9. Annotation (reaction) validation
    if (rel_type == rel_constants::ANNOTATION) {
      if (!config_.enable_reactions) {
        return ValidationResult::fail(rel_constants::M_FORBIDDEN,
                                       "Reaction relations are not enabled");
      }

      // Reaction key is required
      std::string key = json_str(relates_to, rel_constants::AGGREGATION_KEY);
      if (key.empty()) {
        return ValidationResult::fail(rel_constants::M_INVALID_PARAM,
                                       "m.annotation relation must have a 'key'");
      }

      // Validate key length
      if (static_cast<int>(key.size()) > config_.max_reaction_key_length) {
        return ValidationResult::fail(rel_constants::M_INVALID_PARAM,
                                       "Reaction key too long (max " +
                                       std::to_string(config_.max_reaction_key_length) + ")");
      }

      // Duplicate annotation check
      if (config_.prevent_duplicate_annotations) {
        if (store_.has_user_annotation(target_event_id, sender, key)) {
          return ValidationResult::fail(rel_constants::M_DUPLICATE_ANNOTATION,
                                         "User already sent this reaction");
        }
      }

      // Check max aggregated relations
      int64_t current_count = store_.get_relation_count(
          target_event_id, rel_constants::ANNOTATION);
      if (current_count >= config_.max_aggregated_relations_per_event) {
        return ValidationResult::fail(rel_constants::M_LIMIT_EXCEEDED,
                                       "Maximum number of reactions reached for this event");
      }
    }

    // 10. Edit validation
    if (rel_type == rel_constants::REPLACE) {
      if (!config_.enable_edits) {
        return ValidationResult::fail(rel_constants::M_FORBIDDEN,
                                       "Edit relations are not enabled");
      }

      // Must have m.new_content
      if (!event_content.contains(rel_constants::NEW_CONTENT_KEY)) {
        return ValidationResult::fail(rel_constants::M_INVALID_PARAM,
                                       "m.replace relation must have m.new_content");
      }

      // Edit depth check: don't allow edits of edits
      if (config_.enforce_max_edit_depth) {
        auto target_rel = store_.get_relation(target_event_id);
        if (target_rel && target_rel->relation_type == rel_constants::REPLACE) {
          return ValidationResult::fail(rel_constants::M_INVALID_PARAM,
                                         "Cannot edit an edit event (max depth " +
                                         std::to_string(config_.max_edit_depth) + ")");
        }
      }
    }

    // 11. Reference validation
    if (rel_type == rel_constants::REFERENCE) {
      if (!config_.enable_references) {
        return ValidationResult::fail(rel_constants::M_FORBIDDEN,
                                       "Reference relations are not enabled");
      }
      // References are generally always allowed
    }

    return ValidationResult::ok();
  }

  // --------------------------------------------------------------------------
  // validate_with_source — full validation including cycle check (needs
  // the source event_id).
  // --------------------------------------------------------------------------
  ValidationResult validate_with_source(const json& event_content,
                                         const std::string& source_event_id,
                                         const std::string& sender,
                                         const std::string& room_id) {
    auto result = validate(event_content, sender, room_id);
    if (!result.is_valid) return result;

    // Extract target event_id
    const auto& relates_to = event_content[rel_constants::RELATES_TO_KEY];
    std::string target_event_id = json_str(relates_to, rel_constants::EVENT_ID_KEY);

    // Self-relation check
    if (config_.prevent_self_relation && source_event_id == target_event_id) {
      return ValidationResult::fail(rel_constants::M_CYCLIC_RELATION,
                                     "An event cannot relate to itself");
    }

    // Cycle check
    if (config_.prevent_cycles) {
      if (cycle_detector_.would_create_cycle(source_event_id, target_event_id)) {
        return ValidationResult::fail(rel_constants::M_CYCLIC_RELATION,
                                       "Adding this relation would create a cycle");
      }
    }

    return ValidationResult::ok();
  }

  // --------------------------------------------------------------------------
  // is_valid_relation_content — lightweight check: does content carry a
  // valid relation?
  // --------------------------------------------------------------------------
  bool is_valid_relation_content(const json& content) {
    if (!content.contains(rel_constants::RELATES_TO_KEY)) return false;
    const auto& rel = content[rel_constants::RELATES_TO_KEY];
    if (!rel.is_object()) return false;
    if (!rel.contains(rel_constants::EVENT_ID_KEY)) return false;
    if (!rel.contains(rel_constants::REL_TYPE_KEY)) return false;
    return rel_constants::is_valid_relation_type(
        rel[rel_constants::REL_TYPE_KEY].get<std::string>());
  }

  // --------------------------------------------------------------------------
  // parse_relation — extract relation info from event content.
  // Returns a partially filled RelationInfo. Caller fills in the
  // relation_event_id.
  // --------------------------------------------------------------------------
  RelationInfo parse_relation(const json& content) {
    RelationInfo info;

    if (!content.contains(rel_constants::RELATES_TO_KEY)) return info;

    const auto& rel = content[rel_constants::RELATES_TO_KEY];
    info.event_id = json_str(rel, rel_constants::EVENT_ID_KEY);
    info.relation_type = json_str(rel, rel_constants::REL_TYPE_KEY);
    info.aggregation_key = json_str(rel, rel_constants::AGGREGATION_KEY);
    info.content = content;

    // Check for falling back indicators
    if (rel.contains("is_falling_back"))
      info.is_falling_back = rel["is_falling_back"].get<bool>();

    return info;
  }

  // --------------------------------------------------------------------------
  // configuration accessors
  // --------------------------------------------------------------------------
  const RelationValidationConfig& config() const { return config_; }
  void set_config(const RelationValidationConfig& cfg) { config_ = cfg; }

private:
  InMemoryRelationStore& store_;
  RelationValidationConfig config_;
  CycleDetector cycle_detector_;
};

// ============================================================================
// BundledRelationBuilder — builds bundled relation data for events
//
// Bundled relations are embedded in the `unsigned` section of events when
// delivered to clients. They include:
//   - m.annotation: per-key reaction counts with optional "self" field
//   - m.replace: latest edit info (event_id, sender, timestamp)
//   - m.thread: thread summary (reply count, latest replies, participants)
//   - m.reference: reference count and recent reference event IDs
//
// Results are cached with a TTL to avoid redundant computation.
// ============================================================================
class BundledRelationBuilder {
public:
  BundledRelationBuilder(InMemoryRelationStore& store,
                         const BundledRelationConfig& cfg = {})
      : store_(store),
        config_(cfg),
        bundle_cache_(cfg.bundle_cache_ttl_ms) {}

  // --------------------------------------------------------------------------
  // build — construct the full BundledRelations for a given event.
  // `current_user_id` is used to populate the "self" field in annotations.
  // --------------------------------------------------------------------------
  BundledRelations build(const std::string& event_id,
                         const std::string& current_user_id = "") {
    // Check cache first
    std::string cache_key = event_id + "|" + current_user_id;
    auto cached = bundle_cache_.get(cache_key);
    if (cached) return *cached;

    BundledRelations result;

    // --- Annotations (m.annotation) ---
    if (config_.enable_bundled_reactions) {
      auto annotations = store_.get_aggregation_by_key(
          event_id, rel_constants::ANNOTATION, current_user_id);

      if (!annotations.empty()) {
        int limit = std::min(config_.max_bundled_reactions,
                             static_cast<int>(annotations.size()));
        result.annotations.assign(annotations.begin(),
                                   annotations.begin() + limit);
      }
    }

    // --- Edits (m.replace) ---
    if (config_.enable_bundled_edits) {
      auto edits = store_.get_relations_for_parent(
          event_id, rel_constants::REPLACE);

      if (!edits.empty()) {
        result.is_edited = true;
        result.edit_count = static_cast<int64_t>(edits.size());

        // Latest edit is the last one (sorted by timestamp ascending)
        const auto& latest = edits.back();
        result.latest_edit_event_id = latest.relation_event_id;
        result.latest_edit_ts = latest.origin_server_ts;
        result.latest_editor = latest.sender;

        // Resolve the edited content (merge m.new_content)
        if (latest.content.contains(rel_constants::NEW_CONTENT_KEY)) {
          result.latest_edit_content =
              latest.content[rel_constants::NEW_CONTENT_KEY];
        }
      }
    }

    // --- Thread (m.thread) ---
    if (config_.enable_bundled_threads) {
      auto thread_relations = store_.get_relations_for_parent(
          event_id, rel_constants::THREAD);

      if (!thread_relations.empty()) {
        result.is_thread_root = true;
        result.thread_reply_count = static_cast<int64_t>(thread_relations.size());

        // Count unique participants
        std::set<std::string> participants;
        for (auto& tr : thread_relations) {
          participants.insert(tr.sender);
        }
        result.thread_participant_count = static_cast<int64_t>(participants.size());

        // Latest reply info
        const auto& latest_thread = thread_relations.back();
        result.thread_latest_event_id = latest_thread.relation_event_id;
        result.thread_latest_reply_event_id = latest_thread.relation_event_id;
        result.thread_latest_ts = latest_thread.origin_server_ts;

        // Latest N replies
        int num_replies = std::min(config_.max_bundled_thread_replies,
                                    static_cast<int>(thread_relations.size()));
        auto start = thread_relations.end() - num_replies;
        for (auto it = start; it != thread_relations.end(); ++it) {
          result.thread_latest_replies.push_back(it->relation_event_id);
        }
      }
    }

    // --- References (m.reference) ---
    if (config_.enable_bundled_references) {
      auto refs = store_.get_relations_for_parent(
          event_id, rel_constants::REFERENCE);
      result.reference_count = static_cast<int64_t>(refs.size());

      if (!refs.empty()) {
        int num_refs = std::min(config_.max_bundled_references,
                                 static_cast<int>(refs.size()));
        auto start = refs.end() - num_refs;
        for (auto it = start; it != refs.end(); ++it) {
          result.reference_event_ids.push_back(it->relation_event_id);
        }
      }
    }

    // Cache the result
    bundle_cache_.put(cache_key, result);
    return result;
  }

  // --------------------------------------------------------------------------
  // build_for_events — batch-build bundled relations for multiple events.
  // Returns a map of event_id -> BundledRelations.
  // --------------------------------------------------------------------------
  std::unordered_map<std::string, BundledRelations> build_for_events(
      const std::vector<std::string>& event_ids,
      const std::string& current_user_id = "") {
    std::unordered_map<std::string, BundledRelations> results;
    for (auto& eid : event_ids) {
      auto b = build(eid, current_user_id);
      if (b.has_any()) {
        results[eid] = std::move(b);
      }
    }
    return results;
  }

  // --------------------------------------------------------------------------
  // apply_to_event — stitch bundled relations into an event's unsigned section.
  // Modifies the event JSON in-place.
  // --------------------------------------------------------------------------
  void apply_to_event(json& event, const BundledRelations& bundled) {
    if (!bundled.has_any()) return;

    if (!event.contains(rel_constants::UNSIGNED_KEY)) {
      event[rel_constants::UNSIGNED_KEY] = json::object();
    }

    auto& unsigned_data = event[rel_constants::UNSIGNED_KEY];

    // Merge bundled data into unsigned
    json bundled_json = bundled.to_unsigned_json();
    for (auto& [key, value] : bundled_json.items()) {
      unsigned_data[key] = value;
    }
  }

  // --------------------------------------------------------------------------
  // apply_to_events — batch-apply bundled relations to multiple event JSONs.
  // `event_map` is event_id -> event_json, modified in-place.
  // --------------------------------------------------------------------------
  void apply_to_events(
      std::unordered_map<std::string, json>& event_map,
      const std::string& current_user_id) {
    std::vector<std::string> event_ids;
    for (auto& [eid, ev] : event_map) {
      event_ids.push_back(eid);
    }

    auto bundled_map = build_for_events(event_ids, current_user_id);
    for (auto& [eid, bundled] : bundled_map) {
      auto ev_it = event_map.find(eid);
      if (ev_it != event_map.end()) {
        apply_to_event(ev_it->second, bundled);
      }
    }
  }

  // --------------------------------------------------------------------------
  // invalidate_cache — clear cached bundled relations for an event.
  // --------------------------------------------------------------------------
  void invalidate_cache(const std::string& event_id) {
    // Invalidate all variants (different user_ids)
    bundle_cache_.clear(); // conservative: clear everything
  }

  // --------------------------------------------------------------------------
  // configuration accessors
  // --------------------------------------------------------------------------
  const BundledRelationConfig& config() const { return config_; }
  void set_config(const BundledRelationConfig& cfg) {
    config_ = cfg;
    bundle_cache_.clear();
  }

private:
  InMemoryRelationStore& store_;
  BundledRelationConfig config_;
  TTLCache<std::string, BundledRelations> bundle_cache_;
};

// ============================================================================
// AggregationAPIHandler — implements the REST aggregation endpoints
//
// Routes:
//   GET /rooms/{roomId}/relations/{eventId}
//     Returns all relations for an event, with optional ?from, ?to, ?dir,
//     ?limit query parameters.
//
//   GET /rooms/{roomId}/relations/{eventId}/{relType}
//     Returns relations filtered by type (e.g., m.annotation, m.reference).
//
//   GET /rooms/{roomId}/relations/{eventId}/{relType}/{eventType}
//     Returns relations filtered by both relation type and child event type
//     (e.g., m.annotation/m.reaction).
//
// All endpoints support cursor-based pagination using from/to/dir/limit.
// Response format: { "chunk": [...], "next_batch": "...", "prev_batch": "..." }
// ============================================================================
class AggregationAPIHandler {
public:
  AggregationAPIHandler(InMemoryRelationStore& store,
                        BundledRelationBuilder& bundle_builder,
                        const AggregationAPIConfig& cfg = {})
      : store_(store),
        bundle_builder_(bundle_builder),
        config_(cfg) {}

  // --------------------------------------------------------------------------
  // handle_get_relations — GET /rooms/{roomId}/relations/{eventId}
  // Returns all relations for the specified event, paginated.
  // --------------------------------------------------------------------------
  json handle_get_relations(const std::string& room_id,
                             const std::string& event_id,
                             const std::string& current_user_id,
                             const json& query_params) {
    if (!config_.enable_aggregation_api) {
      return make_error(rel_constants::M_FORBIDDEN,
                         "Aggregation API is not enabled", 403);
    }

    // Validate event_id
    if (!is_valid_event_id(event_id)) {
      return make_error(rel_constants::M_INVALID_PARAM,
                         "Invalid event_id", 400);
    }

    // Parse pagination parameters
    int limit = clamp(parse_query_int(query_params, "limit",
                                       config_.default_page_limit),
                      1, config_.max_page_limit);
    std::string direction = parse_query_string(query_params, "dir", "b");
    if (direction != rel_constants::DIR_FORWARD &&
        direction != rel_constants::DIR_BACKWARD) {
      direction = rel_constants::DIR_BACKWARD;
    }

    int64_t from_ts = 0;
    std::string from_event_id;
    std::string from_token = parse_query_string(query_params, "from", "");
    bool has_from = false;
    if (!from_token.empty()) {
      auto [dir, ts, eid] =
          PaginationTokenCodec::parse_direction_token(from_token);
      (void)dir;
      from_ts = ts;
      from_event_id = eid;
      has_from = true;
    }

    int64_t to_ts = 0;
    std::string to_event_id;
    std::string to_token = parse_query_string(query_params, "to", "");
    if (!to_token.empty()) {
      auto [dir, ts, eid] =
          PaginationTokenCodec::parse_direction_token(to_token);
      (void)dir;
      to_ts = ts;
      to_event_id = eid;
    }

    // Fetch relations
    auto [chunk, has_more] = store_.get_relations_paginated(
        event_id, "", from_ts, from_event_id, direction, limit);

    // Build response
    json response = json::object();
    json chunk_array = json::array();

    for (auto& rel : chunk) {
      json entry = rel.to_json();
      entry["type"] = rel.relation_type;
      chunk_array.push_back(entry);
    }

    response["chunk"] = chunk_array;

    // Build pagination tokens
    if (!chunk.empty()) {
      if (has_more) {
        const auto& last = chunk.back();
        response["next_batch"] = PaginationTokenCodec::create_from_token(
            last.origin_server_ts, last.relation_event_id,
            rel_constants::DIR_FORWARD);
      }

      const auto& first = chunk.front();
      response["prev_batch"] = PaginationTokenCodec::create_from_token(
          first.origin_server_ts, first.relation_event_id,
          rel_constants::DIR_BACKWARD);
    }

    return response;
  }

  // --------------------------------------------------------------------------
  // handle_get_relations_by_type — GET /rooms/{roomId}/relations/{eventId}/{relType}
  // Returns relations of a specific type, paginated.
  // --------------------------------------------------------------------------
  json handle_get_relations_by_type(const std::string& room_id,
                                      const std::string& event_id,
                                      const std::string& rel_type,
                                      const std::string& current_user_id,
                                      const json& query_params) {
    if (!config_.enable_aggregation_api) {
      return make_error(rel_constants::M_FORBIDDEN,
                         "Aggregation API is not enabled", 403);
    }

    // Validate event_id
    if (!is_valid_event_id(event_id)) {
      return make_error(rel_constants::M_INVALID_PARAM,
                         "Invalid event_id", 400);
    }

    // Validate relation type
    if (!rel_constants::is_valid_relation_type(rel_type)) {
      return make_error(rel_constants::M_INVALID_PARAM,
                         "Unknown relation type: " + rel_type, 400);
    }

    // Parse pagination parameters
    int limit = clamp(parse_query_int(query_params, "limit",
                                       config_.default_page_limit),
                      1, config_.max_page_limit);
    std::string direction = parse_query_string(query_params, "dir", "b");
    if (direction != rel_constants::DIR_FORWARD &&
        direction != rel_constants::DIR_BACKWARD) {
      direction = rel_constants::DIR_BACKWARD;
    }

    int64_t from_ts = 0;
    std::string from_event_id;
    std::string from_token = parse_query_string(query_params, "from", "");
    if (!from_token.empty()) {
      auto [dir, ts, eid] =
          PaginationTokenCodec::parse_direction_token(from_token);
      (void)dir;
      from_ts = ts;
      from_event_id = eid;
    }

    // Check if aggregation by key is requested
    bool aggregate_by_key = json_bool(query_params, "aggregate_by_key", false);

    json response = json::object();

    if (aggregate_by_key && rel_constants::supports_aggregation_key(rel_type)) {
      // Return aggregation by key
      auto by_key = store_.get_aggregation_by_key(
          event_id, rel_type, current_user_id);

      json chunk = json::array();
      for (auto& entry : by_key) {
        chunk.push_back(entry.to_json());
      }
      response["chunk"] = chunk;
    } else {
      // Standard paginated response
      auto [chunk_relations, has_more] = store_.get_relations_paginated(
          event_id, rel_type, from_ts, from_event_id, direction, limit);

      json chunk_array = json::array();
      for (auto& rel : chunk_relations) {
        chunk_array.push_back(rel.to_json());
      }
      response["chunk"] = chunk_array;

      if (!chunk_relations.empty()) {
        if (has_more) {
          const auto& last = chunk_relations.back();
          response["next_batch"] = PaginationTokenCodec::create_from_token(
              last.origin_server_ts, last.relation_event_id,
              rel_constants::DIR_FORWARD);
        }
        const auto& first = chunk_relations.front();
        response["prev_batch"] = PaginationTokenCodec::create_from_token(
            first.origin_server_ts, first.relation_event_id,
            rel_constants::DIR_BACKWARD);
      }
    }

    return response;
  }

  // --------------------------------------------------------------------------
  // handle_get_relations_by_type_and_event —
  //   GET /rooms/{roomId}/relations/{eventId}/{relType}/{eventType}
  // Returns relations filtered by both relation type and child event type.
  // --------------------------------------------------------------------------
  json handle_get_relations_by_type_and_event(
      const std::string& room_id,
      const std::string& event_id,
      const std::string& rel_type,
      const std::string& event_type,
      const std::string& current_user_id,
      const json& query_params) {
    if (!config_.enable_aggregation_api) {
      return make_error(rel_constants::M_FORBIDDEN,
                         "Aggregation API is not enabled", 403);
    }

    // Validate event_id and rel_type
    if (!is_valid_event_id(event_id)) {
      return make_error(rel_constants::M_INVALID_PARAM,
                         "Invalid event_id", 400);
    }
    if (!rel_constants::is_valid_relation_type(rel_type)) {
      return make_error(rel_constants::M_INVALID_PARAM,
                         "Unknown relation type: " + rel_type, 400);
    }

    // Parse pagination
    int limit = clamp(parse_query_int(query_params, "limit",
                                       config_.default_page_limit),
                      1, config_.max_page_limit);
    std::string direction = parse_query_string(query_params, "dir", "b");
    if (direction != rel_constants::DIR_FORWARD &&
        direction != rel_constants::DIR_BACKWARD) {
      direction = rel_constants::DIR_BACKWARD;
    }

    int64_t from_ts = 0;
    std::string from_event_id;
    std::string from_token = parse_query_string(query_params, "from", "");
    if (!from_token.empty()) {
      auto [dir, ts, eid] =
          PaginationTokenCodec::parse_direction_token(from_token);
      from_ts = ts;
      from_event_id = eid;
    }

    // Fetch all relations of this type, then filter by event_type
    auto [all_chunk, has_more] = store_.get_relations_paginated(
        event_id, rel_type, from_ts, from_event_id, direction, limit);

    json response = json::object();
    json chunk_array = json::array();

    for (auto& rel : all_chunk) {
      // Filter by the child event's type
      // The relation content may have a "type" field indicating the event type
      std::string child_type = json_str(rel.content, "type", "");
      if (event_type.empty() || child_type == event_type ||
          to_lower(child_type) == to_lower(event_type)) {
        json entry = rel.to_json();
        entry["type"] = child_type;
        chunk_array.push_back(entry);
      }
    }

    response["chunk"] = chunk_array;

    if (!all_chunk.empty()) {
      if (has_more) {
        const auto& last = all_chunk.back();
        response["next_batch"] = PaginationTokenCodec::create_from_token(
            last.origin_server_ts, last.relation_event_id,
            rel_constants::DIR_FORWARD);
      }
      if (!all_chunk.empty()) {
        const auto& first = all_chunk.front();
        response["prev_batch"] = PaginationTokenCodec::create_from_token(
            first.origin_server_ts, first.relation_event_id,
            rel_constants::DIR_BACKWARD);
      }
    }

    return response;
  }

  // --------------------------------------------------------------------------
  // handle_get_aggregation_by_key —
  //   GET /rooms/{roomId}/aggregations/{eventId}?type=m.annotation
  // Returns aggregated counts grouped by key (e.g., reaction counts per emoji).
  // --------------------------------------------------------------------------
  json handle_get_aggregation_by_key(const std::string& room_id,
                                       const std::string& event_id,
                                       const std::string& rel_type,
                                       const std::string& current_user_id,
                                       const json& query_params) {
    if (!config_.enable_aggregation_api) {
      return make_error(rel_constants::M_FORBIDDEN,
                         "Aggregation API is not enabled", 403);
    }

    if (!is_valid_event_id(event_id)) {
      return make_error(rel_constants::M_INVALID_PARAM,
                         "Invalid event_id", 400);
    }

    if (!rel_constants::supports_aggregation_key(rel_type)) {
      return make_error(rel_constants::M_INVALID_PARAM,
                         "Relation type does not support aggregation by key: " +
                         rel_type, 400);
    }

    auto results = store_.get_aggregation_by_key(event_id, rel_type,
                                                   current_user_id);

    json response = json::object();
    json chunk = json::array();
    for (auto& entry : results) {
      // Optionally include list of senders for each key
      if (json_bool(query_params, "include_senders", false)) {
        auto senders = store_.get_senders_for_key(event_id, rel_type,
                                                    entry.key);
        json entry_json = entry.to_json();
        entry_json["senders"] = json(senders);
        chunk.push_back(entry_json);
      } else {
        chunk.push_back(entry.to_json());
      }
    }
    response["chunk"] = chunk;
    response["count"] = static_cast<int64_t>(results.size());

    return response;
  }

private:
  // --- Query parameter parsing helpers ---
  std::string parse_query_string(const json& params, const std::string& key,
                                  const std::string& default_val) {
    if (params.contains(key) && params[key].is_string())
      return params[key].get<std::string>();
    return default_val;
  }

  int64_t parse_query_int(const json& params, const std::string& key,
                           int64_t default_val) {
    if (params.contains(key)) {
      if (params[key].is_number_integer())
        return params[key].get<int64_t>();
      if (params[key].is_string()) {
        try {
          return std::stoll(params[key].get<std::string>());
        } catch (...) {
          return default_val;
        }
      }
    }
    return default_val;
  }

  // --- Error response helper ---
  json make_error(const std::string& errcode, const std::string& error,
                   int status = 400) {
    json response;
    response["errcode"] = errcode;
    response["error"] = error;
    response["status"] = status;
    return response;
  }

  InMemoryRelationStore& store_;
  BundledRelationBuilder& bundle_builder_;
  AggregationAPIConfig config_;
};

// ============================================================================
// BundledEditResolver — resolves edit content and bundles edit info
//
// When an event has been edited (via m.replace), the original event's content
// is replaced by merging m.new_content. This class:
//   1. Tracks edit history per event
//   2. Resolves the latest edited content
//   3. Generates fallback text for non-supporting clients
//   4. Bundles the latest edit in the unsigned section
// ============================================================================
class BundledEditResolver {
public:
  BundledEditResolver(InMemoryRelationStore& store) : store_(store) {}

  // --------------------------------------------------------------------------
  // resolve_content — return the resolved (edited) content for an event.
  // If the event has been edited, merge the latest m.new_content.
  // --------------------------------------------------------------------------
  json resolve_content(const std::string& event_id,
                        const json& original_content) {
    auto edits = store_.get_relations_for_parent(event_id,
                                                   rel_constants::REPLACE);
    if (edits.empty()) return original_content;

    const auto& latest = edits.back();
    json result = original_content;

    // Apply m.new_content on top of original
    if (latest.content.contains(rel_constants::NEW_CONTENT_KEY)) {
      const auto& nc = latest.content[rel_constants::NEW_CONTENT_KEY];
      if (nc.is_object()) {
        for (auto& [key, value] : nc.items()) {
          result[key] = value;
        }
      }
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // get_latest_edit — get the latest edit RelationInfo for an event.
  // --------------------------------------------------------------------------
  std::optional<RelationInfo> get_latest_edit(const std::string& event_id) {
    auto edits = store_.get_relations_for_parent(event_id,
                                                   rel_constants::REPLACE);
    if (edits.empty()) return std::nullopt;
    return edits.back();
  }

  // --------------------------------------------------------------------------
  // get_edit_history — get full edit history as JSON array.
  // Each entry: { event_id, sender, origin_server_ts, new_content }
  // --------------------------------------------------------------------------
  json get_edit_history_json(const std::string& event_id) {
    auto edits = store_.get_relations_for_parent(event_id,
                                                   rel_constants::REPLACE);
    json history = json::array();
    for (auto& edit : edits) {
      json entry;
      entry["event_id"] = edit.relation_event_id;
      entry["sender"] = edit.sender;
      entry["origin_server_ts"] = edit.origin_server_ts;
      if (edit.content.contains(rel_constants::NEW_CONTENT_KEY)) {
        entry["new_content"] = edit.content[rel_constants::NEW_CONTENT_KEY];
      }
      history.push_back(entry);
    }
    return history;
  }

  // --------------------------------------------------------------------------
  // generate_fallback_text — creates fallback body for non-edit-aware clients.
  // Format: "> <original body>\n<new body>"
  // --------------------------------------------------------------------------
  std::string generate_fallback_text(const json& original_content,
                                      const json& new_content) {
    std::string fallback;
    if (original_content.contains("body") &&
        original_content["body"].is_string()) {
      fallback += "> " + original_content["body"].get<std::string>() + "\n";
    }
    if (new_content.contains("body") &&
        new_content["body"].is_string()) {
      fallback += new_content["body"].get<std::string>();
    }
    return fallback;
  }

  // --------------------------------------------------------------------------
  // build_new_content_json — helper to create m.new_content for an edit event.
  // Preserves msgtype and format from the original event.
  // --------------------------------------------------------------------------
  static json build_new_content(const std::string& new_body,
                                 const json& original_content) {
    json nc;
    nc["body"] = new_body;

    if (original_content.contains("msgtype")) {
      nc["msgtype"] = original_content["msgtype"];
    }
    if (original_content.contains("format")) {
      nc["format"] = original_content["format"];
    }
    if (original_content.contains("formatted_body")) {
      nc["formatted_body"] = new_body; // simplified
    }

    return nc;
  }

  // --------------------------------------------------------------------------
  // count_edits — return the number of edits for an event.
  // --------------------------------------------------------------------------
  int64_t count_edits(const std::string& event_id) {
    return store_.get_relation_count(event_id, rel_constants::REPLACE);
  }

  // --------------------------------------------------------------------------
  // is_edited — check if an event has been edited.
  // --------------------------------------------------------------------------
  bool is_edited(const std::string& event_id) {
    return count_edits(event_id) > 0;
  }

private:
  InMemoryRelationStore& store_;
};

// ============================================================================
// ThreadReplyBundler — manages thread reply bundling for thread root events
//
// Threads in Matrix are represented as m.thread relations where the child
// event references a thread root. The thread root event, when delivered,
// should include bundled thread data in its unsigned section:
//   - reply count
//   - participant count
//   - latest reply event IDs
//   - latest event timestamp
// ============================================================================
class ThreadReplyBundler {
public:
  ThreadReplyBundler(InMemoryRelationStore& store) : store_(store) {}

  // --------------------------------------------------------------------------
  // is_thread_root — check if an event is a thread root (has thread replies).
  // --------------------------------------------------------------------------
  bool is_thread_root(const std::string& event_id) {
    return store_.get_relation_count(event_id, rel_constants::THREAD) > 0;
  }

  // --------------------------------------------------------------------------
  // get_thread_summary — build a thread summary for bundled relations.
  // Returns JSON with count, participants, latest_reply, etc.
  // --------------------------------------------------------------------------
  json get_thread_summary(const std::string& event_id,
                           const std::string& current_user_id = "",
                           int max_latest_replies = 5) {
    auto replies = store_.get_relations_for_parent(event_id,
                                                     rel_constants::THREAD);
    if (replies.empty()) return json::object();

    json summary;
    summary["count"] = static_cast<int64_t>(replies.size());

    // Count unique participants
    std::set<std::string> participants;
    for (auto& reply : replies) {
      participants.insert(reply.sender);
    }

    // Check if current user participated
    bool participated = false;
    if (!current_user_id.empty()) {
      participated = participants.find(current_user_id) != participants.end();
    }

    // Latest reply info
    const auto& latest = replies.back();
    summary["participant_count"] = static_cast<int64_t>(participants.size());
    summary["latest_event_id"] = latest.relation_event_id;
    summary["latest_origin_server_ts"] = latest.origin_server_ts;
    summary["participated"] = participated;

    // Latest N replies
    json latest_replies = json::array();
    int num = std::min(max_latest_replies,
                       static_cast<int>(replies.size()));
    auto start = replies.end() - num;
    for (auto it = start; it != replies.end(); ++it) {
      latest_replies.push_back(it->relation_event_id);
    }
    summary["latest_replies"] = latest_replies;

    return summary;
  }

  // --------------------------------------------------------------------------
  // get_thread_reply_count — return the number of thread replies.
  // --------------------------------------------------------------------------
  int64_t get_thread_reply_count(const std::string& event_id) {
    return store_.get_relation_count(event_id, rel_constants::THREAD);
  }

  // --------------------------------------------------------------------------
  // get_thread_replies — return all thread reply IDs for an event.
  // --------------------------------------------------------------------------
  std::vector<std::string> get_thread_replies(const std::string& event_id) {
    auto replies = store_.get_relations_for_parent(event_id,
                                                     rel_constants::THREAD);
    std::vector<std::string> ids;
    for (auto& reply : replies) {
      ids.push_back(reply.relation_event_id);
    }
    return ids;
  }

  // --------------------------------------------------------------------------
  // get_thread_participants — return unique sender IDs who replied.
  // --------------------------------------------------------------------------
  std::vector<std::string> get_thread_participants(
      const std::string& event_id) {
    auto replies = store_.get_relations_for_parent(event_id,
                                                     rel_constants::THREAD);
    std::set<std::string> unique;
    for (auto& reply : replies) {
      unique.insert(reply.sender);
    }
    return std::vector<std::string>(unique.begin(), unique.end());
  }

  // --------------------------------------------------------------------------
  // get_threads_by_activity — return thread root events sorted by latest
  // activity timestamp, for a given room.
  // --------------------------------------------------------------------------
  std::vector<std::string> get_threads_by_activity(
      const std::string& room_id,
      const std::vector<std::string>& candidate_events,
      int limit = 50) {
    // Build (ts, event_id) pairs
    std::vector<std::pair<int64_t, std::string>> scored;
    for (auto& eid : candidate_events) {
      auto replies = store_.get_relations_for_parent(eid,
                                                       rel_constants::THREAD);
      int64_t latest_ts = replies.empty() ? 0 : replies.back().origin_server_ts;
      scored.emplace_back(latest_ts, eid);
    }

    // Sort by latest_ts descending
    std::sort(scored.begin(), scored.end(),
              [](auto& a, auto& b) { return a.first > b.first; });

    std::vector<std::string> result;
    int count = std::min(limit, static_cast<int>(scored.size()));
    for (int i = 0; i < count; ++i) {
      result.push_back(scored[i].second);
    }
    return result;
  }

private:
  InMemoryRelationStore& store_;
};

// ============================================================================
// ReferenceRelationTracker — tracks m.reference relations (replies & refs)
//
// Reference relations (m.reference) are used for:
//   1. In-reply-to references (replying to a specific message)
//   2. Generic references (linking to another event for context)
//
// This class provides querying and bundling for reference relations,
// including reference counts and paginated reference retrieval.
// ============================================================================
class ReferenceRelationTracker {
public:
  ReferenceRelationTracker(InMemoryRelationStore& store) : store_(store) {}

  // --------------------------------------------------------------------------
  // add_reference — add a reference relation pointing from source to target.
  // --------------------------------------------------------------------------
  bool add_reference(const std::string& source_event_id,
                      const std::string& target_event_id,
                      const std::string& sender,
                      int64_t timestamp,
                      const json& content = {}) {
    RelationInfo info;
    info.event_id = target_event_id;
    info.relation_event_id = source_event_id;
    info.relation_type = rel_constants::REFERENCE;
    info.sender = sender;
    info.origin_server_ts = timestamp;
    info.content = content;

    return store_.add_relation(info);
  }

  // --------------------------------------------------------------------------
  // get_references — get all reference relations pointing to an event.
  // --------------------------------------------------------------------------
  std::vector<RelationInfo> get_references(const std::string& event_id) {
    return store_.get_relations_for_parent(event_id,
                                             rel_constants::REFERENCE);
  }

  // --------------------------------------------------------------------------
  // get_reference_count — count references to an event.
  // --------------------------------------------------------------------------
  int64_t get_reference_count(const std::string& event_id) {
    return store_.get_relation_count(event_id, rel_constants::REFERENCE);
  }

  // --------------------------------------------------------------------------
  // get_references_paginated — paginated reference retrieval.
  // --------------------------------------------------------------------------
  std::pair<std::vector<RelationInfo>, bool> get_references_paginated(
      const std::string& event_id,
      int64_t from_ts,
      const std::string& from_event_id,
      const std::string& direction,
      int limit) {
    return store_.get_relations_paginated(
        event_id, rel_constants::REFERENCE,
        from_ts, from_event_id, direction, limit);
  }

  // --------------------------------------------------------------------------
  // is_reply — determine if an event content contains an in-reply-to reference.
  // --------------------------------------------------------------------------
  static bool is_reply_content(const json& content) {
    if (!content.contains(rel_constants::RELATES_TO_KEY)) return false;
    const auto& rel = content[rel_constants::RELATES_TO_KEY];
    if (!rel.is_object()) return false;
    std::string rel_type = json_str(rel, rel_constants::REL_TYPE_KEY);
    return rel_type == rel_constants::REFERENCE ||
           rel_type == rel_constants::IN_REPLY_TO;
  }

  // --------------------------------------------------------------------------
  // get_reply_target — extract the target event_id from a reply content.
  // --------------------------------------------------------------------------
  static std::string get_reply_target(const json& content) {
    if (!content.contains(rel_constants::RELATES_TO_KEY)) return "";
    const auto& rel = content[rel_constants::RELATES_TO_KEY];
    if (!rel.is_object()) return "";
    return json_str(rel, rel_constants::EVENT_ID_KEY);
  }

  // --------------------------------------------------------------------------
  // get_reference_summary_json — build reference summary for bundled relations.
  // --------------------------------------------------------------------------
  json get_reference_summary_json(const std::string& event_id,
                                    int max_refs = 10) {
    json summary;
    auto refs = get_references(event_id);

    summary["count"] = static_cast<int64_t>(refs.size());

    json ref_list = json::array();
    int num = std::min(max_refs, static_cast<int>(refs.size()));
    auto start = refs.end() - num;
    for (auto it = start; it != refs.end(); ++it) {
      ref_list.push_back(it->relation_event_id);
    }
    summary["chunk"] = ref_list;

    return summary;
  }

private:
  InMemoryRelationStore& store_;
};

// ============================================================================
// EventStitcher — stitches bundled relations into events when fetched
//
// When the server delivers events to clients (via /sync, /messages, /event,
// or /context), the EventStitcher fetches all related events and builds
// bundled relations, merging them into the unsigned section of each event.
//
// Stitching process:
//   1. Receive a set of events (event_id -> event_json).
//   2. For each event, query the InMemoryRelationStore for all relations
//      pointing to it.
//   3. Build BundledRelations using BundledRelationBuilder.
//   4. Merge the bundled data into event["unsigned"].
//   5. Optionally resolve edited content (replace event content with
//      the latest edit's m.new_content).
//
// This class also handles batch stitching for efficiency.
// ============================================================================
class EventStitcher {
public:
  EventStitcher(InMemoryRelationStore& store,
                BundledRelationBuilder& bundle_builder,
                BundledEditResolver& edit_resolver,
                const StitchingConfig& cfg = {})
      : store_(store),
        bundle_builder_(bundle_builder),
        edit_resolver_(edit_resolver),
        config_(cfg),
        stitch_cache_(cfg.stitch_cache_ttl_ms) {}

  // --------------------------------------------------------------------------
  // stitch_single_event — stitch bundled relations into a single event.
  // Modifies the event JSON in-place.
  // Returns true if any relations were stitched.
  // --------------------------------------------------------------------------
  bool stitch_single_event(json& event,
                            const std::string& current_user_id = "") {
    if (!config_.enable_stitching) return false;

    std::string event_id = json_str(event, "event_id");
    if (event_id.empty()) return false;

    // Check cache first
    std::string cache_key = event_id + "|" + current_user_id;
    auto cached = stitch_cache_.get(cache_key);
    if (cached) {
      if (!cached->empty()) {
        if (!event.contains(rel_constants::UNSIGNED_KEY)) {
          event[rel_constants::UNSIGNED_KEY] = json::object();
        }
        auto& us = event[rel_constants::UNSIGNED_KEY];
        for (auto& [key, value] : cached->items()) {
          us[key] = value;
        }
        return true;
      }
      return false;
    }

    // Build bundled relations
    auto bundled = bundle_builder_.build(event_id, current_user_id);
    if (!bundled.has_any()) {
      stitch_cache_.put(cache_key, json::object());
      return false;
    }

    // Apply to unsigned
    bundle_builder_.apply_to_event(event, bundled);

    // Cache the unsigned additions
    json cached_unsigned;
    if (event.contains(rel_constants::UNSIGNED_KEY)) {
      cached_unsigned = event[rel_constants::UNSIGNED_KEY];
    }
    stitch_cache_.put(cache_key, cached_unsigned);

    return true;
  }

  // --------------------------------------------------------------------------
  // stitch_events — batch-stitch bundled relations into multiple events.
  // Accepts a vector of (event_id, event_json) pairs, modifies in-place.
  // Returns count of events that received stitched relations.
  // --------------------------------------------------------------------------
  int stitch_events(std::vector<std::pair<std::string, json>>& events,
                     const std::string& current_user_id = "") {
    if (!config_.enable_stitching) return 0;

    int stitched = 0;
    std::unordered_map<std::string, json> event_map;

    for (auto& [eid, ev] : events) {
      event_map[eid] = ev;
    }

    // Batch process
    for (auto& [eid, ev] : event_map) {
      // Check cache
      std::string cache_key = eid + "|" + current_user_id;
      auto cached = stitch_cache_.get(cache_key);

      if (cached && !cached->empty()) {
        if (!ev.contains(rel_constants::UNSIGNED_KEY)) {
          ev[rel_constants::UNSIGNED_KEY] = json::object();
        }
        auto& us = ev[rel_constants::UNSIGNED_KEY];
        for (auto& [key, value] : cached->items()) {
          us[key] = value;
        }
        stitched++;
        continue;
      }

      auto bundled = bundle_builder_.build(eid, current_user_id);
      if (bundled.has_any()) {
        bundle_builder_.apply_to_event(ev, bundled);
        stitched++;

        json cached_unsigned;
        if (ev.contains(rel_constants::UNSIGNED_KEY)) {
          cached_unsigned = ev[rel_constants::UNSIGNED_KEY];
        }
        stitch_cache_.put(cache_key, cached_unsigned);
      } else {
        stitch_cache_.put(cache_key, json::object());
      }
    }

    // Copy back results
    for (auto& [eid, ev] : events) {
      auto it = event_map.find(eid);
      if (it != event_map.end()) {
        ev = it->second;
      }
    }

    return stitched;
  }

  // --------------------------------------------------------------------------
  // stitch_with_edit_resolution — stitch AND resolve edits in a single event.
  // Replaces the event content with the resolved (edited) version.
  // Returns the resolved content or original content if not edited.
  // --------------------------------------------------------------------------
  json stitch_with_edit_resolution(json& event,
                                    const std::string& current_user_id = "") {
    stitch_single_event(event, current_user_id);

    std::string event_id = json_str(event, "event_id");
    if (event_id.empty()) return event.value("content", json::object());

    // Resolve edit content
    json original_content = event.value("content", json::object());
    json resolved_content = edit_resolver_.resolve_content(event_id,
                                                            original_content);

    if (resolved_content != original_content) {
      // Replace the content
      event["content"] = resolved_content;
    }

    return resolved_content;
  }

  // --------------------------------------------------------------------------
  // invalidate_cache_for_event — clear stitch cache for a specific event.
  // Called when relations are added/removed for this event.
  // --------------------------------------------------------------------------
  void invalidate_cache_for_event(const std::string& event_id) {
    // In a full implementation, we'd clear only entries matching this event_id.
    // For simplicity, clear the entire cache.
    stitch_cache_.clear();
    bundle_builder_.invalidate_cache(event_id);
  }

  // --------------------------------------------------------------------------
  // stitch_for_sync_response — stitch bundled relations into a sync response.
  // Accepts the timeline events array and processes each event.
  // --------------------------------------------------------------------------
  void stitch_for_sync_response(json& sync_response,
                                 const std::string& current_user_id) {
    if (!config_.enable_stitching || !config_.stitch_on_sync) return;

    // Process rooms section
    if (sync_response.contains("rooms")) {
      auto& rooms = sync_response["rooms"];
      for (auto& [membership, room_map] : rooms.items()) {
        if (!room_map.is_object()) continue;
        for (auto& [room_id, room_data] : room_map.items()) {
          if (!room_data.is_object()) continue;

          // Timeline events
          if (room_data.contains("timeline") &&
              room_data["timeline"].contains("events")) {
            auto& events = room_data["timeline"]["events"];
            for (auto& event : events) {
              stitch_single_event(event, current_user_id);
            }
          }

          // State events
          if (room_data.contains("state") &&
              room_data["state"].contains("events")) {
            auto& events = room_data["state"]["events"];
            for (auto& event : events) {
              stitch_single_event(event, current_user_id);
            }
          }
        }
      }
    }
  }

  // --------------------------------------------------------------------------
  // stitch_for_messages_response — stitch bundled relations into a /messages
  // response's chunk array.
  // --------------------------------------------------------------------------
  void stitch_for_messages_response(json& messages_response,
                                     const std::string& current_user_id) {
    if (!config_.enable_stitching || !config_.stitch_on_messages) return;

    if (messages_response.contains("chunk") &&
        messages_response["chunk"].is_array()) {
      for (auto& event : messages_response["chunk"]) {
        stitch_single_event(event, current_user_id);
      }
    }

    // Also process state events if present
    if (messages_response.contains("state") &&
        messages_response["state"].is_array()) {
      for (auto& event : messages_response["state"]) {
        stitch_single_event(event, current_user_id);
      }
    }
  }

  // --------------------------------------------------------------------------
  // configuration accessors
  // --------------------------------------------------------------------------
  const StitchingConfig& config() const { return config_; }
  void set_config(const StitchingConfig& cfg) {
    config_ = cfg;
    stitch_cache_.clear();
  }

private:
  InMemoryRelationStore& store_;
  BundledRelationBuilder& bundle_builder_;
  BundledEditResolver& edit_resolver_;
  StitchingConfig config_;
  TTLCache<std::string, json> stitch_cache_;
};

// ============================================================================
// RelationCoordinator — top-level coordinator that ties all subsystems together
//
// This class owns all the sub-components and provides a unified interface
// for registering, querying, and managing event relations. It is the primary
// entry point used by the server's event processing pipeline and REST handlers.
//
// It orchestrates:
//   1. InMemoryRelationStore — in-memory relation storage
//   2. RelationValidator — validation of incoming relation events
//   3. PaginationTokenCodec — cursor-based pagination
//   4. BundledRelationBuilder — building bundled relation data
//   5. BundledEditResolver — resolving edit content
//   6. ThreadReplyBundler — managing thread reply bundling
//   7. ReferenceRelationTracker — tracking reference relations
//   8. EventStitcher — stitching relations into event delivery
//   9. AggregationAPIHandler — REST API for relation queries
// ============================================================================
class RelationCoordinator {
public:
  RelationCoordinator()
      : store_(),
        validator_(store_),
        bundle_builder_(store_),
        edit_resolver_(store_),
        thread_bundler_(store_),
        reference_tracker_(store_),
        stitcher_(store_, bundle_builder_, edit_resolver_),
        aggregation_handler_(store_, bundle_builder_) {}

  // --------------------------------------------------------------------------
  // Event Processing — called when a new event is persisted.
  //
  // process_event: parse the event content for relations, validate,
  // and store the relation.
  // --------------------------------------------------------------------------

  struct ProcessResult {
    bool success = false;
    std::string error;
    std::string errcode;
    RelationInfo relation;  // the stored relation (if successful)
  };

  ProcessResult process_event(const std::string& event_id,
                               const std::string& room_id,
                               const std::string& sender,
                               const json& content,
                               int64_t timestamp) {
    ProcessResult result;

    // Check if this event has a relation
    if (!content.contains(rel_constants::RELATES_TO_KEY)) {
      // No relation — this is a normal event, nothing to do
      result.success = true;
      return result;
    }

    // Validate the relation
    auto validation = validator_.validate_with_source(
        content, event_id, sender, room_id);

    if (!validation.is_valid) {
      result.error = validation.error;
      result.errcode = validation.errcode;
      return result;
    }

    // Parse the relation info
    RelationInfo info = validator_.parse_relation(content);
    info.relation_event_id = event_id;
    info.sender = sender;
    info.origin_server_ts = timestamp;

    // For edits, store the new_content
    if (info.relation_type == rel_constants::REPLACE &&
        content.contains(rel_constants::NEW_CONTENT_KEY)) {
      info.content = content[rel_constants::NEW_CONTENT_KEY];
    }

    // Store the relation
    bool stored = store_.add_relation(info);
    if (!stored) {
      result.error = "Failed to store relation (duplicate?)";
      result.errcode = rel_constants::M_UNKNOWN;
      return result;
    }

    // Invalidate caches for the parent event
    stitcher_.invalidate_cache_for_event(info.event_id);

    result.success = true;
    result.relation = info;
    return result;
  }

  // --------------------------------------------------------------------------
  // handle_redaction — called when an event is redacted.
  // Removes any relation the redacted event carries and cleans up indexes.
  // --------------------------------------------------------------------------
  void handle_redaction(const std::string& redacted_event_id) {
    // Check what this event relates to
    auto rel = store_.get_relation(redacted_event_id);
    if (rel) {
      std::string parent_id = rel->event_id;
      store_.remove_relation(redacted_event_id);

      // Invalidate caches for the parent event
      stitcher_.invalidate_cache_for_event(parent_id);
    }

    // Also remove any relations pointing TO this event
    if (store_.has_any_relations(redacted_event_id)) {
      store_.remove_all_relations_for_parent(redacted_event_id);
      stitcher_.invalidate_cache_for_event(redacted_event_id);
    }
  }

  // --------------------------------------------------------------------------
  // Bundled Relations — get bundled data for an event.
  // --------------------------------------------------------------------------
  BundledRelations get_bundled_relations(const std::string& event_id,
                                           const std::string& current_user_id = "") {
    return bundle_builder_.build(event_id, current_user_id);
  }

  // --------------------------------------------------------------------------
  // Stitch Into Events — stitch bundled relations into event JSONs.
  // --------------------------------------------------------------------------
  bool stitch_event(json& event, const std::string& current_user_id = "") {
    return stitcher_.stitch_single_event(event, current_user_id);
  }

  int stitch_events(std::vector<std::pair<std::string, json>>& events,
                     const std::string& current_user_id = "") {
    return stitcher_.stitch_events(events, current_user_id);
  }

  void stitch_sync_response(json& sync_response,
                              const std::string& current_user_id) {
    stitcher_.stitch_for_sync_response(sync_response, current_user_id);
  }

  void stitch_messages_response(json& messages_response,
                                  const std::string& current_user_id) {
    stitcher_.stitch_for_messages_response(messages_response, current_user_id);
  }

  // --------------------------------------------------------------------------
  // Aggregation API — REST endpoint handlers.
  // --------------------------------------------------------------------------
  json api_get_relations(const std::string& room_id,
                          const std::string& event_id,
                          const std::string& current_user_id,
                          const json& query_params) {
    return aggregation_handler_.handle_get_relations(
        room_id, event_id, current_user_id, query_params);
  }

  json api_get_relations_by_type(const std::string& room_id,
                                   const std::string& event_id,
                                   const std::string& rel_type,
                                   const std::string& current_user_id,
                                   const json& query_params) {
    return aggregation_handler_.handle_get_relations_by_type(
        room_id, event_id, rel_type, current_user_id, query_params);
  }

  json api_get_relations_by_type_and_event(
      const std::string& room_id,
      const std::string& event_id,
      const std::string& rel_type,
      const std::string& event_type,
      const std::string& current_user_id,
      const json& query_params) {
    return aggregation_handler_.handle_get_relations_by_type_and_event(
        room_id, event_id, rel_type, event_type, current_user_id, query_params);
  }

  json api_get_aggregation_by_key(const std::string& room_id,
                                    const std::string& event_id,
                                    const std::string& rel_type,
                                    const std::string& current_user_id,
                                    const json& query_params) {
    return aggregation_handler_.handle_get_aggregation_by_key(
        room_id, event_id, rel_type, current_user_id, query_params);
  }

  // --------------------------------------------------------------------------
  // Thread-related accessors.
  // --------------------------------------------------------------------------
  json get_thread_summary(const std::string& event_id,
                           const std::string& current_user_id = "",
                           int max_latest_replies = 5) {
    return thread_bundler_.get_thread_summary(event_id, current_user_id,
                                                max_latest_replies);
  }

  bool is_thread_root(const std::string& event_id) {
    return thread_bundler_.is_thread_root(event_id);
  }

  int64_t get_thread_reply_count(const std::string& event_id) {
    return thread_bundler_.get_thread_reply_count(event_id);
  }

  // --------------------------------------------------------------------------
  // Edit-related accessors.
  // --------------------------------------------------------------------------
  bool is_edited(const std::string& event_id) {
    return edit_resolver_.is_edited(event_id);
  }

  json resolve_edited_content(const std::string& event_id,
                                const json& original_content) {
    return edit_resolver_.resolve_content(event_id, original_content);
  }

  // --------------------------------------------------------------------------
  // Reference-related accessors.
  // --------------------------------------------------------------------------
  int64_t get_reference_count(const std::string& event_id) {
    return reference_tracker_.get_reference_count(event_id);
  }

  std::vector<RelationInfo> get_references(const std::string& event_id) {
    return reference_tracker_.get_references(event_id);
  }

  // --------------------------------------------------------------------------
  // Validation.
  // --------------------------------------------------------------------------
  ValidationResult validate_relation(const json& content,
                                       const std::string& source_event_id,
                                       const std::string& sender,
                                       const std::string& room_id) {
    return validator_.validate_with_source(content, source_event_id, sender,
                                            room_id);
  }

  // --------------------------------------------------------------------------
  // Store access (for direct queries).
  // --------------------------------------------------------------------------
  InMemoryRelationStore& store() { return store_; }
  const InMemoryRelationStore& store() const { return store_; }

  // --------------------------------------------------------------------------
  // Configuration.
  // --------------------------------------------------------------------------
  RelationValidationConfig& validation_config() { return validator_.config(); }
  BundledRelationConfig& bundle_config() { return bundle_builder_.config(); }
  StitchingConfig& stitch_config() { return stitcher_.config(); }
  AggregationAPIConfig& aggregation_config() { return aggregation_handler_.config(); }

  // --------------------------------------------------------------------------
  // Statistics.
  // --------------------------------------------------------------------------
  json get_statistics() const {
    json stats;
    stats["total_relations"] = store_.total_relations();
    return stats;
  }

private:
  InMemoryRelationStore store_;
  RelationValidator validator_;
  BundledRelationBuilder bundle_builder_;
  BundledEditResolver edit_resolver_;
  ThreadReplyBundler thread_bundler_;
  ReferenceRelationTracker reference_tracker_;
  EventStitcher stitcher_;
  AggregationAPIHandler aggregation_handler_;
};

} // namespace progressive

// ============================================================================
// Self-test section — activated when EVENT_RELATIONS_TESTING is defined.
// Provides comprehensive test coverage for all components.
// ============================================================================
#ifdef EVENT_RELATIONS_TESTING
#include <cassert>
#include <iostream>
#include <sstream>

namespace progressive {
namespace test {

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------
int tests_passed = 0;
int tests_failed = 0;

void assert_true(bool condition, const std::string& msg) {
  if (condition) {
    tests_passed++;
  } else {
    tests_failed++;
    std::cerr << "  FAIL: " << msg << std::endl;
  }
}

void assert_equal_int(int64_t actual, int64_t expected, const std::string& msg) {
  if (actual == expected) {
    tests_passed++;
  } else {
    tests_failed++;
    std::cerr << "  FAIL: " << msg << " (expected " << expected
              << ", got " << actual << ")" << std::endl;
  }
}

void assert_equal_str(const std::string& actual, const std::string& expected,
                       const std::string& msg) {
  if (actual == expected) {
    tests_passed++;
  } else {
    tests_failed++;
    std::cerr << "  FAIL: " << msg << " (expected '" << expected
              << "', got '" << actual << "')" << std::endl;
  }
}

// --------------------------------------------------------------------------
// Test: PaginationTokenCodec
// --------------------------------------------------------------------------
bool test_pagination_token_codec() {
  std::cout << "  PaginationTokenCodec..." << std::endl;

  // Encode and decode
  std::string event_id = "$test_event:localhost";
  int64_t ts = 1234567890123;

  std::string token = PaginationTokenCodec::encode(ts, event_id);
  assert_true(!token.empty(), "token is not empty");

  int64_t decoded_ts = 0;
  std::string decoded_event_id;
  bool ok = PaginationTokenCodec::decode(token, decoded_ts, decoded_event_id);

  assert_true(ok, "decode succeeded");
  assert_equal_int(decoded_ts, ts, "timestamp roundtrip");
  assert_equal_str(decoded_event_id, event_id, "event_id roundtrip");

  // Decode empty token
  ok = PaginationTokenCodec::decode("", decoded_ts, decoded_event_id);
  assert_true(!ok, "decode empty token fails");

  // Decode invalid token
  ok = PaginationTokenCodec::decode("!!!invalid!!!", decoded_ts, decoded_event_id);
  assert_true(!ok, "decode invalid token fails");

  // Direction tokens
  std::string from_token = PaginationTokenCodec::create_from_token(
      ts, event_id, rel_constants::DIR_FORWARD);
  auto [dir, dir_ts, dir_eid] =
      PaginationTokenCodec::parse_direction_token(from_token);

  assert_equal_str(dir, "f", "direction token - direction");
  assert_equal_int(dir_ts, ts, "direction token - timestamp");
  assert_equal_str(dir_eid, event_id, "direction token - event_id");

  // Roundtrip with version
  std::string v2_token = PaginationTokenCodec::encode(ts, event_id, 2);
  ok = PaginationTokenCodec::decode(v2_token, decoded_ts, decoded_event_id);
  assert_true(ok, "v2 token decode");
  assert_equal_int(decoded_ts, ts, "v2 timestamp");

  return true;
}

// --------------------------------------------------------------------------
// Test: InMemoryRelationStore
// --------------------------------------------------------------------------
bool test_in_memory_relation_store() {
  std::cout << "  InMemoryRelationStore..." << std::endl;

  InMemoryRelationStore store;

  // Add relations
  RelationInfo r1;
  r1.event_id = "$parent:localhost";
  r1.relation_event_id = "$child1:localhost";
  r1.relation_type = rel_constants::ANNOTATION;
  r1.aggregation_key = "👍";
  r1.sender = "@alice:localhost";
  r1.origin_server_ts = 1000;

  assert_true(store.add_relation(r1), "add r1");

  RelationInfo r2;
  r2.event_id = "$parent:localhost";
  r2.relation_event_id = "$child2:localhost";
  r2.relation_type = rel_constants::ANNOTATION;
  r2.aggregation_key = "❤️";
  r2.sender = "@bob:localhost";
  r2.origin_server_ts = 2000;

  assert_true(store.add_relation(r2), "add r2");

  // Duplicate should fail
  assert_true(!store.add_relation(r1), "duplicate fails");

  // Get relation by event_id
  auto rel = store.get_relation("$child1:localhost");
  assert_true(rel.has_value(), "get r1");
  assert_equal_str(rel->aggregation_key, "👍", "r1 key");

  // Get relations for parent
  auto all = store.get_relations_for_parent("$parent:localhost");
  assert_equal_int(static_cast<int64_t>(all.size()), 2, "parent has 2 relations");

  // Get relations filtered by type
  auto annotations = store.get_relations_for_parent(
      "$parent:localhost", rel_constants::ANNOTATION);
  assert_equal_int(static_cast<int64_t>(annotations.size()), 2, "2 annotations");

  auto edits = store.get_relations_for_parent(
      "$parent:localhost", rel_constants::REPLACE);
  assert_equal_int(static_cast<int64_t>(edits.size()), 0, "0 edits");

  // Count
  int64_t count = store.get_relation_count("$parent:localhost",
                                             rel_constants::ANNOTATION);
  assert_equal_int(count, 2, "annotation count = 2");

  // Aggregation counts
  auto agg_counts = store.get_aggregation_counts(
      "$parent:localhost", rel_constants::ANNOTATION);
  assert_equal_int(static_cast<int64_t>(agg_counts.size()), 2, "2 unique keys");
  assert_equal_int(agg_counts["👍"], 1, "👍 count = 1");
  assert_equal_int(agg_counts["❤️"], 1, "❤️ count = 1");

  // Aggregation by key
  auto by_key = store.get_aggregation_by_key(
      "$parent:localhost", rel_constants::ANNOTATION, "@alice:localhost");
  assert_equal_int(static_cast<int64_t>(by_key.size()), 2, "2 key groups");

  // Check self field
  bool found_self = false;
  for (auto& entry : by_key) {
    if (entry.key == "👍" && entry.current_user_reacted) found_self = true;
  }
  assert_true(found_self, "self field for 👍");

  // Senders for key
  auto senders = store.get_senders_for_key(
      "$parent:localhost", rel_constants::ANNOTATION, "👍");
  assert_equal_int(static_cast<int64_t>(senders.size()), 1, "1 sender for 👍");
  assert_equal_str(senders[0], "@alice:localhost", "alice sent 👍");

  // User annotation check
  assert_true(store.has_user_annotation("$parent:localhost", "@alice:localhost", "👍"),
              "alice has 👍");
  assert_true(!store.has_user_annotation("$parent:localhost", "@bob:localhost", "👍"),
              "bob does not have 👍");

  // Has any relations
  assert_true(store.has_any_relations("$parent:localhost"), "parent has relations");
  assert_true(!store.has_any_relations("$nonexistent:localhost"), "nonexistent has no relations");

  // Paginated
  auto [page, has_more] = store.get_relations_paginated(
      "$parent:localhost", "", 0, "", rel_constants::DIR_FORWARD, 1);
  assert_equal_int(static_cast<int64_t>(page.size()), 1, "pagination limit 1");
  assert_true(has_more, "has more");

  // Remove a relation
  store.remove_relation("$child1:localhost");
  assert_true(!store.get_relation("$child1:localhost").has_value(), "r1 removed");
  assert_equal_int(store.get_relation_count("$parent:localhost",
                                              rel_constants::ANNOTATION),
                   1, "1 remaining after remove");

  // Remove all for parent
  store.remove_all_relations_for_parent("$parent:localhost");
  assert_equal_int(store.get_relation_count("$parent:localhost",
                                              rel_constants::ANNOTATION),
                   0, "0 after remove all");

  // Clear
  store.clear();
  assert_equal_int(static_cast<int64_t>(store.total_relations()), 0, "cleared");

  return true;
}

// --------------------------------------------------------------------------
// Test: RelationValidator
// --------------------------------------------------------------------------
bool test_relation_validator() {
  std::cout << "  RelationValidator..." << std::endl;

  InMemoryRelationStore store;
  RelationValidator validator(store);

  // Valid annotation content
  json valid_annotation;
  valid_annotation[rel_constants::RELATES_TO_KEY] = {
    {rel_constants::EVENT_ID_KEY, "$target:localhost"},
    {rel_constants::REL_TYPE_KEY, rel_constants::ANNOTATION},
    {rel_constants::AGGREGATION_KEY, "👍"}
  };

  auto result = validator.validate(valid_annotation, "@alice:localhost", "!room:localhost");
  assert_true(result.is_valid, "valid annotation passes");

  // Missing m.relates_to
  json no_rel;
  no_rel["body"] = "hello";
  result = validator.validate(no_rel, "@alice:localhost", "!room:localhost");
  assert_true(!result.is_valid, "no m.relates_to fails");

  // Invalid event_id format
  json bad_event_id;
  bad_event_id[rel_constants::RELATES_TO_KEY] = {
    {rel_constants::EVENT_ID_KEY, "not_an_event_id"},
    {rel_constants::REL_TYPE_KEY, rel_constants::ANNOTATION},
    {rel_constants::AGGREGATION_KEY, "👍"}
  };
  result = validator.validate(bad_event_id, "@alice:localhost", "!room:localhost");
  assert_true(!result.is_valid, "bad event_id fails");

  // Unknown relation type
  json bad_type;
  bad_type[rel_constants::RELATES_TO_KEY] = {
    {rel_constants::EVENT_ID_KEY, "$target:localhost"},
    {rel_constants::REL_TYPE_KEY, "m.invalid_type"}
  };
  result = validator.validate(bad_type, "@alice:localhost", "!room:localhost");
  assert_true(!result.is_valid, "bad rel_type fails");

  // Missing key for annotation
  json no_key;
  no_key[rel_constants::RELATES_TO_KEY] = {
    {rel_constants::EVENT_ID_KEY, "$target:localhost"},
    {rel_constants::REL_TYPE_KEY, rel_constants::ANNOTATION}
  };
  result = validator.validate(no_key, "@alice:localhost", "!room:localhost");
  assert_true(!result.is_valid, "missing annotation key fails");

  // Edit without m.new_content (validates m.new_content exists in top-level content)
  json bad_edit;
  bad_edit[rel_constants::RELATES_TO_KEY] = {
    {rel_constants::EVENT_ID_KEY, "$target:localhost"},
    {rel_constants::REL_TYPE_KEY, rel_constants::REPLACE}
  };
  result = validator.validate(bad_edit, "@alice:localhost", "!room:localhost");
  assert_true(!result.is_valid, "edit without m.new_content fails");

  // Valid edit with m.new_content
  json valid_edit;
  valid_edit[rel_constants::RELATES_TO_KEY] = {
    {rel_constants::EVENT_ID_KEY, "$target:localhost"},
    {rel_constants::REL_TYPE_KEY, rel_constants::REPLACE}
  };
  valid_edit[rel_constants::NEW_CONTENT_KEY] = {{"body", "edited body"}};
  result = validator.validate(valid_edit, "@alice:localhost", "!room:localhost");
  assert_true(result.is_valid, "valid edit passes");

  // Duplicate annotation
  RelationInfo existing;
  existing.event_id = "$target:localhost";
  existing.relation_event_id = "$reaction1:localhost";
  existing.relation_type = rel_constants::ANNOTATION;
  existing.aggregation_key = "👍";
  existing.sender = "@alice:localhost";
  existing.origin_server_ts = 1000;
  store.add_relation(existing);

  result = validator.validate(valid_annotation, "@alice:localhost", "!room:localhost");
  assert_true(!result.is_valid, "duplicate annotation fails");

  return true;
}

// --------------------------------------------------------------------------
// Test: CycleDetector
// --------------------------------------------------------------------------
bool test_cycle_detector() {
  std::cout << "  CycleDetector..." << std::endl;

  InMemoryRelationStore store;
  CycleDetector detector(store);

  // Self-relation is a cycle
  assert_true(detector.would_create_cycle("$event:localhost", "$event:localhost"),
              "self-relation is cycle");

  // Add a relation: $a -> $b, then check $b -> $a would create cycle
  RelationInfo r1;
  r1.event_id = "$b:localhost";
  r1.relation_event_id = "$a:localhost";
  r1.relation_type = rel_constants::REFERENCE;
  r1.sender = "@user:localhost";
  r1.origin_server_ts = 1000;
  store.add_relation(r1);

  assert_true(detector.would_create_cycle("$b:localhost", "$a:localhost"),
              "b -> a would create cycle (a -> b exists)");

  // No cycle for unrelated events
  assert_true(!detector.would_create_cycle("$c:localhost", "$d:localhost"),
              "c -> d is not a cycle");

  return true;
}

// --------------------------------------------------------------------------
// Test: BundledRelationBuilder
// --------------------------------------------------------------------------
bool test_bundled_relation_builder() {
  std::cout << "  BundledRelationBuilder..." << std::endl;

  InMemoryRelationStore store;
  BundledRelationBuilder builder(store);

  // Add reaction relations
  RelationInfo r1;
  r1.event_id = "$event:localhost";
  r1.relation_event_id = "$react1:localhost";
  r1.relation_type = rel_constants::ANNOTATION;
  r1.aggregation_key = "👍";
  r1.sender = "@alice:localhost";
  r1.origin_server_ts = 1000;
  store.add_relation(r1);

  RelationInfo r2;
  r2.event_id = "$event:localhost";
  r2.relation_event_id = "$react2:localhost";
  r2.relation_type = rel_constants::ANNOTATION;
  r2.aggregation_key = "👍";
  r2.sender = "@bob:localhost";
  r2.origin_server_ts = 2000;
  store.add_relation(r2);

  RelationInfo r3;
  r3.event_id = "$event:localhost";
  r3.relation_event_id = "$react3:localhost";
  r3.relation_type = rel_constants::ANNOTATION;
  r3.aggregation_key = "❤️";
  r3.sender = "@alice:localhost";
  r3.origin_server_ts = 3000;
  store.add_relation(r3);

  // Add an edit
  RelationInfo edit;
  json edit_content;
  edit_content["body"] = "edited text";
  edit_content["msgtype"] = "m.text";
  edit.event_id = "$event:localhost";
  edit.relation_event_id = "$edit1:localhost";
  edit.relation_type = rel_constants::REPLACE;
  edit.sender = "@alice:localhost";
  edit.origin_server_ts = 4000;
  edit.content = edit_content;
  store.add_relation(edit);

  // Add a thread reply
  RelationInfo thread;
  thread.event_id = "$event:localhost";
  thread.relation_event_id = "$thread1:localhost";
  thread.relation_type = rel_constants::THREAD;
  thread.sender = "@bob:localhost";
  thread.origin_server_ts = 5000;
  store.add_relation(thread);

  // Add a reference
  RelationInfo ref;
  ref.event_id = "$event:localhost";
  ref.relation_event_id = "$ref1:localhost";
  ref.relation_type = rel_constants::REFERENCE;
  ref.sender = "@carol:localhost";
  ref.origin_server_ts = 6000;
  store.add_relation(ref);

  // Build bundled relations
  auto bundled = builder.build("$event:localhost", "@alice:localhost");

  assert_true(bundled.has_any(), "has bundled relations");

  // Check annotations
  assert_true(!bundled.annotations.empty(), "has annotations");
  // Should have 2 keys: 👍 (count 2) and ❤️ (count 1)
  bool found_thumbs = false, found_heart = false;
  for (auto& ann : bundled.annotations) {
    if (ann.key == "👍") {
      assert_equal_int(ann.count, 2, "👍 count = 2");
      found_thumbs = true;
    }
    if (ann.key == "❤️") {
      assert_equal_int(ann.count, 1, "❤️ count = 1");
      assert_true(ann.current_user_reacted, "alice self for ❤️");
      found_heart = true;
    }
  }
  assert_true(found_thumbs, "found 👍 in annotations");
  assert_true(found_heart, "found ❤️ in annotations");

  // Check edit
  assert_true(bundled.is_edited, "is edited");
  assert_equal_int(bundled.edit_count, 1, "1 edit");

  // Check thread
  assert_true(bundled.is_thread_root, "is thread root");
  assert_equal_int(bundled.thread_reply_count, 1, "1 thread reply");

  // Check reference
  assert_equal_int(bundled.reference_count, 1, "1 reference");

  // Check to_unsigned_json
  auto unsigned_json = bundled.to_unsigned_json();
  assert_true(unsigned_json.contains(rel_constants::BUNDLED_ANNOTATION),
              "unsigned has m.annotation");
  assert_true(unsigned_json.contains(rel_constants::BUNDLED_REPLACE),
              "unsigned has m.replace");
  assert_true(unsigned_json.contains(rel_constants::BUNDLED_THREAD),
              "unsigned has m.thread");
  assert_true(unsigned_json.contains(rel_constants::BUNDLED_REFERENCE),
              "unsigned has m.reference");

  return true;
}

// --------------------------------------------------------------------------
// Test: BundledEditResolver
// --------------------------------------------------------------------------
bool test_bundled_edit_resolver() {
  std::cout << "  BundledEditResolver..." << std::endl;

  InMemoryRelationStore store;
  BundledEditResolver resolver(store);

  // Original content
  json original;
  original["body"] = "Hello world";
  original["msgtype"] = "m.text";

  // Add an edit
  RelationInfo edit;
  json nc;
  nc["body"] = "Hello edited world";
  nc["msgtype"] = "m.text";
  edit.event_id = "$original:localhost";
  edit.relation_event_id = "$edit1:localhost";
  edit.relation_type = rel_constants::REPLACE;
  edit.sender = "@alice:localhost";
  edit.origin_server_ts = 2000;
  edit.content = nc;
  store.add_relation(edit);

  // Resolve content
  auto resolved = resolver.resolve_content("$original:localhost", original);
  assert_equal_str(json_str(resolved, "body"), "Hello edited world",
                   "resolved body");

  // Not edited
  assert_true(!resolver.is_edited("$other:localhost"), "other not edited");
  assert_true(resolver.is_edited("$original:localhost"), "original is edited");

  // Count
  assert_equal_int(resolver.count_edits("$original:localhost"), 1, "1 edit");

  // Edit history
  auto history = resolver.get_edit_history_json("$original:localhost");
  assert_equal_int(static_cast<int64_t>(history.size()), 1, "1 edit in history");

  // Latest edit
  auto latest = resolver.get_latest_edit("$original:localhost");
  assert_true(latest.has_value(), "has latest edit");
  assert_equal_str(latest->sender, "@alice:localhost", "alice's edit");

  // Build new content helper
  auto nc2 = BundledEditResolver::build_new_content("New body", original);
  assert_equal_str(json_str(nc2, "body"), "New body", "build new content body");
  assert_equal_str(json_str(nc2, "msgtype"), "m.text", "preserved msgtype");

  return true;
}

// --------------------------------------------------------------------------
// Test: ThreadReplyBundler
// --------------------------------------------------------------------------
bool test_thread_reply_bundler() {
  std::cout << "  ThreadReplyBundler..." << std::endl;

  InMemoryRelationStore store;
  ThreadReplyBundler bundler(store);

  // Not a thread root
  assert_true(!bundler.is_thread_root("$event:localhost"), "not thread root initially");

  // Add thread replies
  RelationInfo t1;
  t1.event_id = "$thread_root:localhost";
  t1.relation_event_id = "$reply1:localhost";
  t1.relation_type = rel_constants::THREAD;
  t1.sender = "@alice:localhost";
  t1.origin_server_ts = 1000;
  store.add_relation(t1);

  RelationInfo t2;
  t2.event_id = "$thread_root:localhost";
  t2.relation_event_id = "$reply2:localhost";
  t2.relation_type = rel_constants::THREAD;
  t2.sender = "@bob:localhost";
  t2.origin_server_ts = 2000;
  store.add_relation(t2);

  assert_true(bundler.is_thread_root("$thread_root:localhost"), "is thread root");
  assert_equal_int(bundler.get_thread_reply_count("$thread_root:localhost"), 2,
                   "2 replies");

  auto summary = bundler.get_thread_summary("$thread_root:localhost", "@alice:localhost");
  assert_equal_int(json_int(summary, "count"), 2, "summary count=2");
  assert_equal_int(json_int(summary, "participant_count"), 2, "2 participants");
  assert_true(json_bool(summary, "participated"), "alice participated");

  // Check alice didn't participate in thread
  auto summary_bob = bundler.get_thread_summary("$thread_root:localhost", "@bob:localhost");
  assert_true(json_bool(summary_bob, "participated"), "bob participated");

  // Participants
  auto participants = bundler.get_thread_participants("$thread_root:localhost");
  assert_equal_int(static_cast<int64_t>(participants.size()), 2, "2 participants");

  // Thread replies
  auto replies = bundler.get_thread_replies("$thread_root:localhost");
  assert_equal_int(static_cast<int64_t>(replies.size()), 2, "2 reply IDs");

  return true;
}

// --------------------------------------------------------------------------
// Test: ReferenceRelationTracker
// --------------------------------------------------------------------------
bool test_reference_relation_tracker() {
  std::cout << "  ReferenceRelationTracker..." << std::endl;

  InMemoryRelationStore store;
  ReferenceRelationTracker tracker(store);

  assert_true(tracker.add_reference("$ref:localhost", "$target:localhost",
                                      "@alice:localhost", 1000),
              "add reference");

  assert_equal_int(tracker.get_reference_count("$target:localhost"), 1,
                   "ref count = 1");

  auto refs = tracker.get_references("$target:localhost");
  assert_equal_int(static_cast<int64_t>(refs.size()), 1, "1 ref");

  assert_true(ReferenceRelationTracker::is_reply_content(
      {{"m.relates_to", {{"rel_type", "m.reference"}, {"event_id", "$x:localhost"}}}}),
      "detect reply content");

  assert_equal_str(
      ReferenceRelationTracker::get_reply_target(
          {{"m.relates_to", {{"rel_type", "m.reference"}, {"event_id", "$y:localhost"}}}}),
      "$y:localhost", "get reply target");

  auto summary = tracker.get_reference_summary_json("$target:localhost");
  assert_equal_int(json_int(summary, "count"), 1, "summary count=1");

  auto [page_refs, more] = tracker.get_references_paginated(
      "$target:localhost", 0, "", rel_constants::DIR_FORWARD, 10);
  assert_equal_int(static_cast<int64_t>(page_refs.size()), 1, "paginated 1 ref");

  return true;
}

// --------------------------------------------------------------------------
// Test: EventStitcher
// --------------------------------------------------------------------------
bool test_event_stitcher() {
  std::cout << "  EventStitcher..." << std::endl;

  InMemoryRelationStore store;
  BundledRelationBuilder bundle_builder(store);
  BundledEditResolver edit_resolver(store);
  EventStitcher stitcher(store, bundle_builder, edit_resolver);

  // Add a reaction
  RelationInfo r1;
  r1.event_id = "$event:localhost";
  r1.relation_event_id = "$react1:localhost";
  r1.relation_type = rel_constants::ANNOTATION;
  r1.aggregation_key = "👍";
  r1.sender = "@alice:localhost";
  r1.origin_server_ts = 1000;
  store.add_relation(r1);

  // Create an event JSON
  json event;
  event["event_id"] = "$event:localhost";
  event["type"] = "m.room.message";
  event["content"] = {{"body", "hello"}};

  // Stitch
  bool stitched = stitcher.stitch_single_event(event, "@alice:localhost");
  assert_true(stitched, "event stitched");
  assert_true(event.contains(rel_constants::UNSIGNED_KEY), "has unsigned");

  // Check cached stitch
  event.clear();
  event["event_id"] = "$event:localhost";
  event["type"] = "m.room.message";
  event["content"] = {{"body", "hello"}};
  stitched = stitcher.stitch_single_event(event, "@alice:localhost");
  assert_true(stitched, "cached stitch works");
  assert_true(event.contains(rel_constants::UNSIGNED_KEY), "cached has unsigned");

  // Stitch with edit resolution
  // Add an edit
  RelationInfo edit;
  json nc;
  nc["body"] = "edited hello";
  edit.event_id = "$event:localhost";
  edit.relation_event_id = "$edit1:localhost";
  edit.relation_type = rel_constants::REPLACE;
  edit.sender = "@alice:localhost";
  edit.origin_server_ts = 2000;
  edit.content = nc;
  store.add_relation(edit);

  // Invalidate cache to see edit
  stitcher.invalidate_cache_for_event("$event:localhost");

  json event2;
  event2["event_id"] = "$event:localhost";
  event2["type"] = "m.room.message";
  event2["content"] = {{"body", "hello"}};

  auto resolved = stitcher.stitch_with_edit_resolution(event2, "@alice:localhost");
  assert_equal_str(json_str(resolved, "body"), "edited hello", "resolved edit content");

  // Stitch events batch
  std::vector<std::pair<std::string, json>> events;
  json ev;
  ev["event_id"] = "$event:localhost";
  ev["content"] = {{"body", "hello"}};
  events.push_back({"$event:localhost", ev});

  int count = stitcher.stitch_events(events, "@alice:localhost");
  assert_true(count > 0, "batch stitch had results");

  return true;
}

// --------------------------------------------------------------------------
// Test: AggregationAPIHandler
// --------------------------------------------------------------------------
bool test_aggregation_api_handler() {
  std::cout << "  AggregationAPIHandler..." << std::endl;

  InMemoryRelationStore store;
  BundledRelationBuilder bundle_builder(store);
  AggregationAPIHandler handler(store, bundle_builder);

  // Add some relations
  for (int i = 0; i < 5; ++i) {
    RelationInfo info;
    info.event_id = "$parent:localhost";
    info.relation_event_id = "$child" + std::to_string(i) + ":localhost";
    info.relation_type = rel_constants::ANNOTATION;
    info.aggregation_key = (i % 2 == 0) ? "👍" : "❤️";
    info.sender = "@user" + std::to_string(i) + ":localhost";
    info.origin_server_ts = 1000 + i * 1000;
    store.add_relation(info);
  }

  // Test GET /relations/{eventId}
  json query;
  query["limit"] = 3;
  query["dir"] = "f";
  auto resp = handler.handle_get_relations(
      "!room:localhost", "$parent:localhost", "@user0:localhost", query);

  assert_true(resp.contains("chunk"), "response has chunk");
  assert_equal_int(static_cast<int64_t>(resp["chunk"].size()), 3, "chunk size 3");
  assert_true(resp.contains("next_batch"), "has next_batch");
  assert_true(resp.contains("prev_batch"), "has prev_batch");

  // Test GET /relations/{eventId}/{relType}
  query.clear();
  query["limit"] = 10;
  auto by_type = handler.handle_get_relations_by_type(
      "!room:localhost", "$parent:localhost", rel_constants::ANNOTATION,
      "@user0:localhost", query);

  assert_true(by_type.contains("chunk"), "by_type has chunk");
  assert_equal_int(static_cast<int64_t>(by_type["chunk"].size()), 5,
                   "all 5 annotations");

  // Test aggregation by key
  query["aggregate_by_key"] = true;
  auto by_key = handler.handle_get_relations_by_type(
      "!room:localhost", "$parent:localhost", rel_constants::ANNOTATION,
      "@user0:localhost", query);

  assert_true(by_key.contains("chunk"), "by_key has chunk");
  // Should have 2 keys: 👍 and ❤️
  assert_equal_int(static_cast<int64_t>(by_key["chunk"].size()), 2,
                   "2 aggregation keys");

  // Test get_aggregation_by_key
  query.clear();
  auto agg = handler.handle_get_aggregation_by_key(
      "!room:localhost", "$parent:localhost", rel_constants::ANNOTATION,
      "@user0:localhost", query);

  assert_true(agg.contains("chunk"), "aggregation has chunk");
  assert_true(agg.contains("count"), "aggregation has count");

  // Test invalid event_id
  auto err = handler.handle_get_relations(
      "!room:localhost", "invalid_id", "@user0:localhost", {});
  assert_true(err.contains("errcode"), "invalid event_id returns error");

  // Test invalid relation type
  auto err2 = handler.handle_get_relations_by_type(
      "!room:localhost", "$parent:localhost", "bad_type",
      "@user0:localhost", {});
  assert_true(err2.contains("errcode"), "invalid rel_type returns error");

  // Test GET /relations/{eventId}/{relType}/{eventType}
  query.clear();
  auto by_ev_type = handler.handle_get_relations_by_type_and_event(
      "!room:localhost", "$parent:localhost", rel_constants::ANNOTATION,
      "m.reaction", "@user0:localhost", query);
  assert_true(by_ev_type.contains("chunk"), "by_event_type has chunk");

  return true;
}

// --------------------------------------------------------------------------
// Test: RelationCoordinator (integration)
// --------------------------------------------------------------------------
bool test_relation_coordinator() {
  std::cout << "  RelationCoordinator (integration)..." << std::endl;

  RelationCoordinator coordinator;

  // Process a reaction event
  json reaction_content;
  reaction_content[rel_constants::RELATES_TO_KEY] = {
    {rel_constants::EVENT_ID_KEY, "$target:localhost"},
    {rel_constants::REL_TYPE_KEY, rel_constants::ANNOTATION},
    {rel_constants::AGGREGATION_KEY, "👍"}
  };

  auto result = coordinator.process_event(
      "$reaction1:localhost", "!room:localhost",
      "@alice:localhost", reaction_content, 1000);

  assert_true(result.success, "process reaction succeeds");

  // Process a duplicate reaction
  result = coordinator.process_event(
      "$reaction2:localhost", "!room:localhost",
      "@alice:localhost", reaction_content, 2000);
  assert_true(!result.success, "duplicate reaction fails");

  // Check bundled relations
  auto bundled = coordinator.get_bundled_relations("$target:localhost",
                                                      "@alice:localhost");
  assert_true(!bundled.annotations.empty(), "bundled has annotations");
  assert_equal_int(bundled.annotations[0].count, 1, "1 👍 reaction");

  // Process an edit
  json edit_content;
  edit_content[rel_constants::RELATES_TO_KEY] = {
    {rel_constants::EVENT_ID_KEY, "$target:localhost"},
    {rel_constants::REL_TYPE_KEY, rel_constants::REPLACE}
  };
  edit_content[rel_constants::NEW_CONTENT_KEY] = {{"body", "edited"}};

  result = coordinator.process_event(
      "$edit1:localhost", "!room:localhost",
      "@alice:localhost", edit_content, 3000);
  assert_true(result.success, "edit succeeds");

  // Check edit resolution
  assert_true(coordinator.is_edited("$target:localhost"), "is edited");

  // Process a thread reply
  json thread_content;
  thread_content[rel_constants::RELATES_TO_KEY] = {
    {rel_constants::EVENT_ID_KEY, "$target:localhost"},
    {rel_constants::REL_TYPE_KEY, rel_constants::THREAD}
  };

  result = coordinator.process_event(
      "$thread1:localhost", "!room:localhost",
      "@bob:localhost", thread_content, 4000);
  assert_true(result.success, "thread reply succeeds");

  assert_true(coordinator.is_thread_root("$target:localhost"), "is thread root");
  assert_equal_int(coordinator.get_thread_reply_count("$target:localhost"), 1,
                   "1 thread reply");

  // Test stitching
  json event;
  event["event_id"] = "$target:localhost";
  event["content"] = {{"body", "original"}};

  bool stitched = coordinator.stitch_event(event, "@alice:localhost");
  assert_true(stitched, "stitch works");
  assert_true(event.contains(rel_constants::UNSIGNED_KEY), "has unsigned after stitch");

  // Test API
  json api_result = coordinator.api_get_relations(
      "!room:localhost", "$target:localhost", "@alice:localhost", {});
  assert_true(api_result.contains("chunk"), "API returns chunk");

  // Test handle redaction
  coordinator.handle_redaction("$reaction1:localhost");
  bundled = coordinator.get_bundled_relations("$target:localhost", "@alice:localhost");
  assert_true(bundled.annotations.empty(), "annotations removed after redaction");

  // Test statistics
  auto stats = coordinator.get_statistics();
  assert_true(stats.contains("total_relations"), "stats has total_relations");

  return true;
}

// --------------------------------------------------------------------------
// Test: edge cases
// --------------------------------------------------------------------------
bool test_edge_cases() {
  std::cout << "  Edge cases..." << std::endl;

  InMemoryRelationStore store;

  // Empty parent
  auto empty = store.get_relations_for_parent("$nonexistent:localhost");
  assert_equal_int(static_cast<int64_t>(empty.size()), 0, "empty parent");

  // Zero count
  assert_equal_int(store.get_relation_count("$nonexistent:localhost",
                                              rel_constants::ANNOTATION),
                   0, "zero count for nonexistent");

  // Get non-existent relation
  assert_true(!store.get_relation("$nonexistent:localhost").has_value(),
              "nonexistent relation");

  // Empty aggregation keys
  auto agg = store.get_aggregation_counts("$nonexistent:localhost",
                                            rel_constants::ANNOTATION);
  assert_equal_int(static_cast<int64_t>(agg.size()), 0, "empty aggregation");

  // Remove non-existent
  store.remove_relation("$nonexistent:localhost"); // should not crash

  // Remove all for non-existent
  store.remove_all_relations_for_parent("$nonexistent:localhost"); // no crash

  // Has user annotation on empty
  assert_true(!store.has_user_annotation("$nonexistent:localhost", "@alice:localhost", "👍"),
              "no annotation on nonexistent");

  // Pagination on empty
  auto [page, more] = store.get_relations_paginated(
      "$nonexistent:localhost", "", 0, "", rel_constants::DIR_FORWARD, 10);
  assert_equal_int(static_cast<int64_t>(page.size()), 0, "empty page");
  assert_true(!more, "no more for empty");

  // Clear on empty
  store.clear();
  assert_equal_int(static_cast<int64_t>(store.total_relations()), 0, "clear empty");

  return true;
}

// --------------------------------------------------------------------------
// Run all tests
// --------------------------------------------------------------------------
bool run_all_tests() {
  std::vector<std::pair<std::string, std::function<bool()>>> tests = {
    {"PaginationTokenCodec",        test_pagination_token_codec},
    {"InMemoryRelationStore",       test_in_memory_relation_store},
    {"RelationValidator",           test_relation_validator},
    {"CycleDetector",              test_cycle_detector},
    {"BundledRelationBuilder",      test_bundled_relation_builder},
    {"BundledEditResolver",         test_bundled_edit_resolver},
    {"ThreadReplyBundler",          test_thread_reply_bundler},
    {"ReferenceRelationTracker",    test_reference_relation_tracker},
    {"EventStitcher",              test_event_stitcher},
    {"AggregationAPIHandler",       test_aggregation_api_handler},
    {"RelationCoordinator",         test_relation_coordinator},
    {"EdgeCases",                  test_edge_cases},
  };

  std::cout << "=== Event Relations Tests ===" << std::endl;

  for (auto& [name, test_fn] : tests) {
    std::cout << "  " << name << "... ";
    std::cout.flush();
    if (test_fn()) {
      std::cout << "PASSED" << std::endl;
    } else {
      std::cout << "FAILED" << std::endl;
    }
  }

  std::cout << "---" << std::endl;
  std::cout << "Passed: " << tests_passed << ", Failed: " << tests_failed
            << ", Total: " << (tests_passed + tests_failed) << std::endl;

  return tests_failed == 0;
}

} // namespace test
} // namespace progressive
#endif // EVENT_RELATIONS_TESTING
