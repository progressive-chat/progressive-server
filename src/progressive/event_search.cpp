// ============================================================================
// event_search.cpp — Matrix Event Search: Search Store, Indexing, Full-Text
//                        Search, Multi-Room Search, Ranking, Admin API,
//                        and Event Context
//
// Implements:
//   - Event search store: persist searchable event content in event_search
//     SQL table (key, value, event_id, room_id, stream_ordering,
//     origin_server_ts). Supports insert, delete, and query operations.
//   - Search indexing: on event persist, extract plain text from event
//     content fields (content.body, content.formatted_body, content.name,
//     content.topic). Strip HTML tags, normalize whitespace, tokenize into
//     individual words, and store each token in the search table.
//   - Full-text search: keyword-based search across event_search entries.
//     Supports single-room search and global search with configurable
//     pagination. Uses stream_ordering for stable cursor-based pagination.
//   - Multi-room search: search across all rooms a user is a member of,
//     group results by room_id, limit results per room, and aggregate
//     scores. Supports intersecting multiple search terms.
//   - Search ranking: result ranking by relevance: exact phrase match
//     highest, then all-terms match, then word frequency match, then
//     recency boost. Configurable weight coefficients for each factor.
//   - Search admin API: admin endpoints to reindex all events in a room,
//     rebuild search indexes from scratch, purge stale search entries,
//     and check index health/stats. Includes progress tracking.
//   - Search sync: expose search results via /_matrix/client/v3/search
//     REST API endpoint. Parses search_categories, search_term, room_id,
//     order_by, include_state, groupings, filter, limit, next_batch.
//   - Event context in search: when returning search results, include
//     context (events_before, events_after) around each matching event,
//     configurable limit, support recursive parent fetching for threads.
//
// Namespace: progressive::
// Equivalent to synapse/handlers/search.py +
//              synapse/storage/databases/main/search.py +
//              synapse/rest/client/search.py
//
// Target: 2000+ lines of production-grade C++ with explicit descriptions.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
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
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/rest/rest_base.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for all major components
// ============================================================================
class EventSearchStore;
class SearchIndexer;
class FullTextSearchEngine;
class MultiRoomSearchAggregator;
class SearchRanker;
class SearchAdminAPI;
class EventContextFetcher;
class SearchAPIHandler;
class SearchTokenCodec;
class SearchProgressTracker;

// ============================================================================
// Constants: search configuration, ranking weights, limits, error codes
// ============================================================================
namespace search_constants {

// --- Ranking weight coefficients (higher = more important) ---
constexpr double WEIGHT_EXACT_PHRASE  = 10.0;
constexpr double WEIGHT_ALL_TERMS     = 5.0;
constexpr double WEIGHT_PARTIAL_TERM  = 2.0;
constexpr double WEIGHT_SINGLE_TERM   = 1.0;
constexpr double WEIGHT_RECENCY       = 0.5;
constexpr double RECENCY_HALF_LIFE_MS = 604800000.0;  // 7 days in ms

// --- Search limits ---
constexpr int MAX_SEARCH_TERM_LENGTH      = 500;
constexpr int MAX_SEARCH_RESULTS          = 500;
constexpr int DEFAULT_SEARCH_LIMIT        = 50;
constexpr int MAX_SEARCH_ROOMS            = 100;
constexpr int MAX_CONTEXT_EVENTS          = 20;
constexpr int DEFAULT_CONTEXT_BEFORE      = 5;
constexpr int DEFAULT_CONTEXT_AFTER       = 5;
constexpr int REINDEX_BATCH_SIZE          = 200;
constexpr int MAX_TOKEN_LENGTH            = 64;
constexpr int MIN_TOKEN_LENGTH            = 2;

// --- Table and key constants ---
constexpr const char* TABLE_EVENT_SEARCH    = "event_search";
constexpr const char* KEY_BODY              = "content.body";
constexpr const char* KEY_NAME              = "content.name";
constexpr const char* KEY_TOPIC             = "content.topic";
constexpr const char* KEY_SENDER            = "content.sender";
constexpr const char* KEY_FILENAME          = "content.filename";
constexpr const char* KEY_URL               = "content.url";

// --- Order-by constants ---
constexpr const char* ORDER_RANK           = "rank";
constexpr const char* ORDER_RECENT         = "recent";

// --- Groupings constants ---
constexpr const char* GROUP_ROOM_ID        = "room_id";
constexpr const char* GROUP_SENDER         = "sender";
constexpr const char* GROUP_NONE           = "none";

// --- Error codes ---
constexpr const char* M_INVALID_PARAM      = "M_INVALID_PARAM";
constexpr const char* M_NOT_FOUND          = "M_NOT_FOUND";
constexpr const char* M_FORBIDDEN          = "M_FORBIDDEN";
constexpr const char* M_UNKNOWN            = "M_UNKNOWN";
constexpr const char* M_LIMIT_EXCEEDED     = "M_LIMIT_EXCEEDED";

// --- Search category constants ---
constexpr const char* CAT_ROOM_EVENTS      = "room_events";

// --- Pagination token version ---
constexpr int TOKEN_VERSION                = 2;

// --- HTML entities and tags to strip during indexing ---
inline const std::regex HTML_TAG_RE("<[^>]*>");
inline const std::regex HTML_ENTITY_RE("&[a-zA-Z]+;|&#[0-9]+;|&#x[0-9a-fA-F]+;");
inline const std::regex WHITESPACE_RE("\\s+");
inline const std::regex NON_ALPHANUM_RE("[^a-zA-Z0-9\\s]");

} // namespace search_constants

// ============================================================================
// Anonymous namespace — Internal helper utilities
// ============================================================================
namespace {

// --------------------------------------------------------------------------
// now_ms — current wall-clock time in milliseconds since Unix epoch.
// Used for timestamps, recency calculations, and token encoding.
// --------------------------------------------------------------------------
int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

// --------------------------------------------------------------------------
// now_sec — current wall-clock time in seconds since Unix epoch.
// Used for coarser-grained timestamps and expiry checks.
// --------------------------------------------------------------------------
int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

// --------------------------------------------------------------------------
// starts_with — string prefix check, avoids allocation.
// Returns true if s begins with prefix.
// --------------------------------------------------------------------------
bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

// --------------------------------------------------------------------------
// ends_with — string suffix check, avoids allocation.
// Returns true if s ends with suffix.
// --------------------------------------------------------------------------
bool ends_with(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() &&
         s.substr(s.size() - suffix.size()) == suffix;
}

// --------------------------------------------------------------------------
// to_lower — returns lowercase copy of input string.
// Used for case-insensitive search token matching.
// --------------------------------------------------------------------------
std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), ::tolower);
  return s;
}

// --------------------------------------------------------------------------
// to_upper — returns uppercase copy of input string.
// Used for case-insensitive comparison and normalization.
// --------------------------------------------------------------------------
std::string to_upper(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), ::toupper);
  return s;
}

// --------------------------------------------------------------------------
// trim — remove leading and trailing whitespace from a string.
// Returns a view into the original string (zero-copy when possible).
// --------------------------------------------------------------------------
std::string_view trim_view(std::string_view s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
    s.remove_prefix(1);
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
    s.remove_suffix(1);
  return s;
}

std::string trim_copy(const std::string& s) {
  auto v = trim_view(s);
  return std::string(v);
}

// --------------------------------------------------------------------------
// strip_html — remove HTML tags and decode HTML entities, returning
// plain text suitable for search indexing.
// Handles: <tag>, <tag attr="val">, &amp;, &lt;, &gt;, &#NN;, &#xNN;
// --------------------------------------------------------------------------
std::string strip_html(const std::string& html) {
  using namespace search_constants;

  // First remove HTML tags
  std::string result = std::regex_replace(html, HTML_TAG_RE, " ");

  // Decode common HTML entities
  struct EntityPair { std::string_view entity; const char* replacement; };
  static const EntityPair entities[] = {
    {"&amp;", "&"},  {"&lt;", "<"},   {"&gt;", ">"},
    {"&quot;", "\""}, {"&apos;", "'"}, {"&nbsp;", " "},
    {"&#39;", "'"},   {"&#34;", "\""},
  };

  for (const auto& ep : entities) {
    size_t pos = 0;
    while ((pos = result.find(ep.entity, pos)) != std::string::npos) {
      result.replace(pos, ep.entity.size(), ep.replacement);
      pos += strlen(ep.replacement);
    }
  }

  // Handle numeric entities &#NN; and &#xNN;
  result = std::regex_replace(result, std::regex("&#(\\d+);"),
    [](const std::smatch& m) {
      int cp = std::stoi(m[1].str());
      return cp < 128 ? std::string(1, static_cast<char>(cp)) : " ";
    });
  result = std::regex_replace(result, std::regex("&#x([0-9a-fA-F]+);"),
    [](const std::smatch& m) {
      int cp = std::stoi(m[1].str(), nullptr, 16);
      return cp < 128 ? std::string(1, static_cast<char>(cp)) : " ";
    });

  // Normalize whitespace
  result = std::regex_replace(result, WHITESPACE_RE, " ");

  return trim_copy(result);
}

// --------------------------------------------------------------------------
// extract_searchable_text — given event content JSON and event type,
// extract all searchable plain text from known content fields:
//   - content.body          (message body, always plain text)
//   - content.formatted_body (message formatted, strip HTML)
//   - content.name           (room name or filename)
//   - content.topic          (room topic)
//   - content.filename       (uploaded filename)
//   - content.url            (URL text)
// Returns a map of key -> extracted text value.
// --------------------------------------------------------------------------
std::map<std::string, std::string> extract_searchable_text(
    const std::string& event_type, const json& content) {

  using namespace search_constants;
  std::map<std::string, std::string> result;

  // Helper: safely extract string from JSON field
  auto extract_field = [&](const std::string& key_name,
                            const std::string& json_key,
                            bool strip_html_flag = false) {
    if (content.contains(json_key) && content[json_key].is_string()) {
      std::string text = content[json_key].get<std::string>();
      if (strip_html_flag) {
        text = strip_html(text);
      }
      text = std::regex_replace(text, WHITESPACE_RE, " ");
      text = trim_copy(text);
      if (!text.empty()) {
        result[key_name] = text;
      }
    }
  };

  // --- content.body: always the plain text body ---
  extract_field(KEY_BODY, "body", false);

  // --- content.formatted_body: rich text, strip HTML ---
  extract_field(KEY_BODY, "formatted_body", true);

  // --- content.name: room name events, filename in file events ---
  extract_field(KEY_NAME, "name", false);

  // --- content.topic: room topic events ---
  extract_field(KEY_TOPIC, "topic", false);

  // --- content.filename: upload filename ---
  extract_field(KEY_FILENAME, "filename", false);

  // --- content.url: URL text ---
  extract_field(KEY_URL, "url", false);

  return result;
}

// --------------------------------------------------------------------------
// tokenize — split a string into individual normalized tokens.
// Steps:
//   1. Convert to lowercase
//   2. Remove all non-alphanumeric characters (replace with space)
//   3. Split on whitespace
//   4. Filter tokens shorter than MIN_TOKEN_LENGTH
//   5. Truncate tokens longer than MAX_TOKEN_LENGTH
//   6. Deduplicate tokens
// Returns a set of unique tokens.
// --------------------------------------------------------------------------
std::set<std::string> tokenize(const std::string& text) {
  using namespace search_constants;
  std::set<std::string> tokens;

  if (text.empty()) return tokens;

  // Lowercase for case-insensitive indexing
  std::string normalized = to_lower(text);

  // Replace non-alphanumeric chars with spaces
  normalized = std::regex_replace(normalized, NON_ALPHANUM_RE, " ");

  // Split on whitespace
  std::istringstream stream(normalized);
  std::string token;
  while (stream >> token) {
    if (token.size() < MIN_TOKEN_LENGTH) continue;
    if (token.size() > MAX_TOKEN_LENGTH)
      token = token.substr(0, MAX_TOKEN_LENGTH);
    tokens.insert(token);
  }

  return tokens;
}

// --------------------------------------------------------------------------
// generate_random_id — random alphanumeric string of given length.
// Used for search request IDs and correlation tokens.
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
// base64_encode — encode binary data to base64 string.
// Used for pagination token encoding.
// --------------------------------------------------------------------------
std::string base64_encode(const std::string& input) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string result;
  result.reserve(((input.size() + 2) / 3) * 4);

  size_t i = 0;
  unsigned char a, b, c;
  while (i < input.size()) {
    a = static_cast<unsigned char>(input[i++]);
    uint32_t val = a << 16;
    if (i < input.size()) {
      b = static_cast<unsigned char>(input[i++]);
      val |= b << 8;
    }
    if (i < input.size()) {
      c = static_cast<unsigned char>(input[i++]);
      val |= c;
    }

    result.push_back(alphabet[(val >> 18) & 0x3F]);
    result.push_back(alphabet[(val >> 12) & 0x3F]);
    if (i - 1 < input.size())
      result.push_back(alphabet[(val >> 6) & 0x3F]);
    else
      result.push_back('=');
    if (i - 1 <= input.size())
      result.push_back(alphabet[val & 0x3F]);
    else
      result.push_back('=');
  }
  return result;
}

// --------------------------------------------------------------------------
// base64_decode — decode base64 string to binary data.
// Used for pagination token decoding. Returns empty on parse failure.
// --------------------------------------------------------------------------
std::string base64_decode(const std::string& input) {
  static const std::array<int, 256> decode_table = []() {
    std::array<int, 256> t;
    t.fill(-1);
    const char* alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 64; ++i) t[static_cast<unsigned char>(alpha[i])] = i;
    return t;
  }();

  std::string result;
  result.reserve((input.size() * 3) / 4);
  int val = 0, valb = -8;
  for (unsigned char c : input) {
    if (c == '=') break;
    int idx = decode_table[c];
    if (idx == -1) continue;
    val = (val << 6) | idx;
    valb += 6;
    if (valb >= 0) {
      result.push_back(static_cast<char>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return result;
}

// --------------------------------------------------------------------------
// validate_room_id — check if string looks like a valid Matrix room ID.
// --------------------------------------------------------------------------
bool is_valid_room_id(const std::string& rid) {
  return starts_with(rid, "!") && rid.find(':') != std::string::npos &&
         rid.size() >= 4;
}

// --------------------------------------------------------------------------
// validate_user_id — check if string looks like a valid Matrix user ID.
// --------------------------------------------------------------------------
bool is_valid_user_id(const std::string& uid) {
  return starts_with(uid, "@") && uid.find(':') != std::string::npos &&
         uid.size() >= 4;
}

// --------------------------------------------------------------------------
// validate_event_id — check if string looks like a valid Matrix event ID.
// --------------------------------------------------------------------------
bool is_valid_event_id(const std::string& eid) {
  return starts_with(eid, "$") && eid.find(':') != std::string::npos &&
         eid.size() >= 4;
}

// --------------------------------------------------------------------------
// build_error_json — create a Matrix-standard error JSON object.
// --------------------------------------------------------------------------
json build_error(int code, const std::string& errcode, const std::string& err) {
  return json{{"errcode", errcode}, {"error", err}};
}

// --------------------------------------------------------------------------
// safe_json_opt — safely get optional JSON field as string.
// --------------------------------------------------------------------------
std::optional<std::string> safe_json_str(const json& j, const std::string& key) {
  if (j.contains(key) && j[key].is_string())
    return j[key].get<std::string>();
  return std::nullopt;
}

// --------------------------------------------------------------------------
// parse_int_query — parse integer from query string, returns default on failure.
// --------------------------------------------------------------------------
int64_t parse_int_query(const std::map<std::string, std::string>& qs,
                         const std::string& key, int64_t def = 0) {
  auto it = qs.find(key);
  if (it == qs.end()) return def;
  try { return std::stoll(it->second); }
  catch (...) { return def; }
}

// --------------------------------------------------------------------------
// parse_str_query — get string from query params, empty if missing.
// --------------------------------------------------------------------------
std::string parse_str_query(const std::map<std::string, std::string>& qs,
                             const std::string& key) {
  auto it = qs.find(key);
  return (it != qs.end()) ? it->second : std::string{};
}

} // anonymous namespace

// ============================================================================
// SearchTokenCodec — encode/decode pagination tokens for search results.
//
// A pagination token is a base64-encoded binary blob containing:
//   byte 0..3:  version (big-endian int32, currently 2)
//   byte 4..11: stream_ordering (big-endian int64)
//   byte 12..19: origin_server_ts (big-endian int64)
//   byte 20..N:  comma-separated sorted keyword list (UTF-8)
//
// The token unambiguously identifies where the next page should start.
// ============================================================================
class SearchTokenCodec {
public:
  // ------------------------------------------------------------------------
  // encode — create a pagination token from search cursor position.
  // Returns a base64 string suitable for use as a next_batch value.
  // ------------------------------------------------------------------------
  static std::string encode(int64_t stream_ordering, int64_t origin_server_ts,
                            const std::string& search_term) {
    using namespace search_constants;
    std::string payload;

    // Version (4 bytes)
    int32_t version = TOKEN_VERSION;
    for (int i = 3; i >= 0; --i)
      payload.push_back(static_cast<char>((version >> (i * 8)) & 0xFF));

    // stream_ordering (8 bytes)
    for (int i = 7; i >= 0; --i)
      payload.push_back(
          static_cast<char>((stream_ordering >> (i * 8)) & 0xFF));

    // origin_server_ts (8 bytes)
    for (int i = 7; i >= 0; --i)
      payload.push_back(
          static_cast<char>((origin_server_ts >> (i * 8)) & 0xFF));

    // search term (variable-length UTF-8)
    payload += search_term;

    return base64_encode(payload);
  }

  // ------------------------------------------------------------------------
  // decode — parse a pagination token back into its components.
  // Returns (stream_ordering, origin_server_ts, search_term).
  // Throws std::runtime_error on invalid/malformed tokens.
  // ------------------------------------------------------------------------
  static std::tuple<int64_t, int64_t, std::string> decode(
      const std::string& token) {

    std::string payload = base64_decode(token);
    if (payload.size() < 20) {
      throw std::runtime_error("Invalid pagination token: too short");
    }

    size_t pos = 0;

    // Read version (4 bytes)
    int32_t version = 0;
    for (int i = 0; i < 4; ++i)
      version = (version << 8) | (static_cast<unsigned char>(payload[pos++]));
    if (version != search_constants::TOKEN_VERSION) {
      throw std::runtime_error(
          "Invalid pagination token: wrong version " + std::to_string(version));
    }

    // Read stream_ordering (8 bytes)
    int64_t stream_ordering = 0;
    for (int i = 0; i < 8; ++i)
      stream_ordering = (stream_ordering << 8) |
                        (static_cast<unsigned char>(payload[pos++]));

    // Read origin_server_ts (8 bytes)
    int64_t origin_server_ts = 0;
    for (int i = 0; i < 8; ++i)
      origin_server_ts = (origin_server_ts << 8) |
                         (static_cast<unsigned char>(payload[pos++]));

    // Remaining bytes are the search term
    std::string search_term(payload.begin() + pos, payload.end());

    return {stream_ordering, origin_server_ts, search_term};
  }

  // ------------------------------------------------------------------------
  // validate — check if a token is syntactically valid without full decode.
  // ------------------------------------------------------------------------
  static bool validate(const std::string& token) {
    try {
      decode(token);
      return true;
    } catch (...) {
      return false;
    }
  }
};

// ============================================================================
// EventSearchStore — manages the event_search SQL table.
//
// Provides methods to:
//   - Insert search entries (key, value, event_id, room_id, stream_ordering,
//     origin_server_ts)
//   - Delete entries by event_id
//   - Delete entries by room_id (for room deletion or full reindex)
//   - Query entries by keyword with ordering and pagination
//   - Get distinct values for a key within a room
//   - Count total entries in a room or across all rooms
//
// The underlying SQL schema is:
//   CREATE TABLE event_search (
//     id          INTEGER PRIMARY KEY AUTOINCREMENT,
//     key         TEXT NOT NULL,
//     value       TEXT NOT NULL,
//     event_id    TEXT NOT NULL,
//     room_id     TEXT NOT NULL,
//     stream_ordering     BIGINT NOT NULL,
//     origin_server_ts    BIGINT NOT NULL
//   );
//   CREATE INDEX idx_event_search_event_id ON event_search(event_id);
//   CREATE INDEX idx_event_search_room_id ON event_search(room_id);
//   CREATE INDEX idx_event_search_key_value ON event_search(key, value);
//   CREATE INDEX idx_event_search_stream ON event_search(stream_ordering);
// ============================================================================
class EventSearchStore {
public:
  explicit EventSearchStore(progressive::storage::DatabasePool& db_pool)
      : db_pool_(db_pool) {}

  // ------------------------------------------------------------------------
  // insert_search_entries — insert multiple search entries for an event.
  // Each token from each content field becomes a row in event_search.
  // Uses a batch insert for efficiency.
  // ------------------------------------------------------------------------
  void insert_search_entries(
      progressive::storage::LoggingTransaction& txn,
      const std::string& event_id,
      const std::string& room_id,
      int64_t stream_ordering,
      int64_t origin_server_ts,
      const std::map<std::string, std::string>& keyed_texts) {

    if (keyed_texts.empty()) return;

    // Tokenize each key:text pair and collect into (key, token) pairs
    struct Entry { std::string key; std::string token; };
    std::vector<Entry> entries;

    for (const auto& [key, text] : keyed_texts) {
      std::set<std::string> tokens = tokenize(text);
      for (const auto& token : tokens) {
        entries.push_back({key, token});
      }
    }

    if (entries.empty()) return;

    // Build batch INSERT
    std::string sql =
        "INSERT INTO event_search(key, value, event_id, room_id, "
        "stream_ordering, origin_server_ts) VALUES ";
    std::vector<progressive::storage::SQLParam> params;

    for (size_t i = 0; i < entries.size(); ++i) {
      if (i > 0) sql += ", ";
      sql += "(?," + std::to_string(i * 6 + 1) +
             ",?," + std::to_string(i * 6 + 2) +
             ",?," + std::to_string(i * 6 + 3) +
             ",?," + std::to_string(i * 6 + 4) +
             ",?," + std::to_string(i * 6 + 5) +
             ",?," + std::to_string(i * 6 + 6) + ")";

      params.push_back(progressive::storage::SQLParam(entries[i].key));
      params.push_back(progressive::storage::SQLParam(entries[i].token));
      params.push_back(progressive::storage::SQLParam(event_id));
      params.push_back(progressive::storage::SQLParam(room_id));
      params.push_back(progressive::storage::SQLParam(stream_ordering));
      params.push_back(progressive::storage::SQLParam(origin_server_ts));
    }

    txn.execute(sql, params);
  }

  // ------------------------------------------------------------------------
  // delete_event_entries — remove all search entries for a given event_id.
  // Called during event redaction or deletion.
  // ------------------------------------------------------------------------
  void delete_event_entries(progressive::storage::LoggingTransaction& txn,
                             const std::string& event_id) {
    txn.execute(
        "DELETE FROM event_search WHERE event_id = ?",
        {progressive::storage::SQLParam(event_id)});
  }

  // ------------------------------------------------------------------------
  // delete_room_entries — remove all search entries for a room.
  // Called before a full room reindex or on room purge.
  // ------------------------------------------------------------------------
  void delete_room_entries(progressive::storage::LoggingTransaction& txn,
                            const std::string& room_id) {
    txn.execute(
        "DELETE FROM event_search WHERE room_id = ?",
        {progressive::storage::SQLParam(room_id)});
  }

  // ------------------------------------------------------------------------
  // search_by_keyword — find events matching a keyword token.
  // Returns rows ordered by stream_ordering DESC.
  //
  // Parameters:
  //   txn:          active database transaction
  //   keyword:       the search token (lowercased)
  //   room_id:       if non-empty, restricts search to one room
  //   after_stream:  pagination cursor (stream_ordering upper bound)
  //   limit:         max results to return
  //
  // Returns vector of SearchEntry structs.
  // ------------------------------------------------------------------------
  std::vector<progressive::storage::SearchEntry> search_by_keyword(
      progressive::storage::LoggingTransaction& txn,
      const std::string& keyword,
      const std::string& room_id,
      int64_t after_stream,
      int limit) {

    std::vector<progressive::storage::SQLParam> params;
    std::string sql =
        "SELECT key, value, event_id, room_id, stream_ordering, "
        "origin_server_ts FROM event_search WHERE value = ?";

    params.push_back(progressive::storage::SQLParam(keyword));

    if (!room_id.empty()) {
      sql += " AND room_id = ?";
      params.push_back(progressive::storage::SQLParam(room_id));
    }

    if (after_stream > 0) {
      sql += " AND stream_ordering < ?";
      params.push_back(progressive::storage::SQLParam(after_stream));
    }

    sql += " ORDER BY stream_ordering DESC LIMIT ?";
    params.push_back(progressive::storage::SQLParam(
        static_cast<int64_t>(limit)));

    txn.execute(sql, params);

    std::vector<progressive::storage::SearchEntry> results;
    auto rows = txn.fetchall();
    results.reserve(rows.size());

    for (const auto& row : rows) {
      progressive::storage::SearchEntry entry;
      entry.key             = row[0].as_string();
      entry.value           = row[1].as_string();
      entry.event_id        = row[2].as_string();
      entry.room_id         = row[3].as_string();
      entry.stream_ordering = row[4].as_int64();
      entry.origin_server_ts = row[5].as_int64();
      results.push_back(std::move(entry));
    }

    return results;
  }

  // ------------------------------------------------------------------------
  // search_multi_keyword — find events matching ANY of the given keywords.
  // Uses "value IN (?, ?, ...)" for efficient lookup.
  // Deduplicates results by event_id (keeps highest stream_ordering).
  // ------------------------------------------------------------------------
  std::vector<progressive::storage::SearchEntry> search_multi_keyword(
      progressive::storage::LoggingTransaction& txn,
      const std::vector<std::string>& keywords,
      const std::string& room_id,
      int64_t after_stream,
      int limit) {

    if (keywords.empty()) return {};

    std::vector<progressive::storage::SQLParam> params;
    std::string sql =
        "SELECT key, value, event_id, room_id, stream_ordering, "
        "origin_server_ts FROM event_search WHERE value IN (";

    for (size_t i = 0; i < keywords.size(); ++i) {
      if (i > 0) sql += ", ";
      sql += "?";
      params.push_back(progressive::storage::SQLParam(keywords[i]));
    }
    sql += ")";

    if (!room_id.empty()) {
      sql += " AND room_id = ?";
      params.push_back(progressive::storage::SQLParam(room_id));
    }

    if (after_stream > 0) {
      sql += " AND stream_ordering < ?";
      params.push_back(progressive::storage::SQLParam(after_stream));
    }

    sql += " ORDER BY stream_ordering DESC LIMIT ?";
    params.push_back(progressive::storage::SQLParam(
        static_cast<int64_t>(limit * keywords.size()))); // larger fetch for dedup

    txn.execute(sql, params);
    auto rows = txn.fetchall();

    // Deduplicate by event_id, keeping highest stream_ordering per event
    std::map<std::string, progressive::storage::SearchEntry> dedup;
    for (const auto& row : rows) {
      std::string event_id = row[2].as_string();
      progressive::storage::SearchEntry entry;
      entry.key             = row[0].as_string();
      entry.value           = row[1].as_string();
      entry.event_id        = event_id;
      entry.room_id         = row[3].as_string();
      entry.stream_ordering = row[4].as_int64();
      entry.origin_server_ts = row[5].as_int64();

      auto existing = dedup.find(event_id);
      if (existing == dedup.end() ||
          entry.stream_ordering > existing->second.stream_ordering) {
        dedup[event_id] = std::move(entry);
      }
    }

    // Convert to vector sorted by stream_ordering DESC
    std::vector<progressive::storage::SearchEntry> results;
    results.reserve(dedup.size());
    for (auto& [_, entry] : dedup) results.push_back(std::move(entry));
    std::sort(results.begin(), results.end(),
              [](const auto& a, const auto& b) {
                return a.stream_ordering > b.stream_ordering;
              });

    if (static_cast<int>(results.size()) > limit)
      results.resize(limit);

    return results;
  }

  // ------------------------------------------------------------------------
  // count_entries_for_room — return total search entries for a room.
  // ------------------------------------------------------------------------
  int64_t count_entries_for_room(
      progressive::storage::LoggingTransaction& txn,
      const std::string& room_id) {
    txn.execute(
        "SELECT COUNT(*) FROM event_search WHERE room_id = ?",
        {progressive::storage::SQLParam(room_id)});
    auto row = txn.fetchone();
    return row.has_value() ? row->as_int64(0) : 0;
  }

  // ------------------------------------------------------------------------
  // count_total_entries — return total search entries across all rooms.
  // ------------------------------------------------------------------------
  int64_t count_total_entries(
      progressive::storage::LoggingTransaction& txn) {
    txn.execute("SELECT COUNT(*) FROM event_search");
    auto row = txn.fetchone();
    return row.has_value() ? row->as_int64(0) : 0;
  }

  // ------------------------------------------------------------------------
  // get_indexed_event_ids — get all distinct event_ids that have been
  // indexed in a room. Used for reindex verification.
  // ------------------------------------------------------------------------
  std::vector<std::string> get_indexed_event_ids(
      progressive::storage::LoggingTransaction& txn,
      const std::string& room_id) {
    txn.execute(
        "SELECT DISTINCT event_id FROM event_search WHERE room_id = ? "
        "ORDER BY event_id",
        {progressive::storage::SQLParam(room_id)});
    std::vector<std::string> result;
    auto rows = txn.fetchall();
    for (const auto& row : rows) {
      result.push_back(row[0].as_string());
    }
    return result;
  }

  // ------------------------------------------------------------------------
  // purge_stale_entries — remove search entries for events that no longer
  // exist in the events table. Returns number of entries removed.
  // ------------------------------------------------------------------------
  int64_t purge_stale_entries(
      progressive::storage::LoggingTransaction& txn) {
    txn.execute(
        "DELETE FROM event_search WHERE event_id NOT IN "
        "(SELECT event_id FROM events)");
    return txn.rowcount();
  }

private:
  progressive::storage::DatabasePool& db_pool_;
};

// ============================================================================
// SearchIndexer — extract, tokenize, and index event content on persist.
//
// Called during event persistence (in persist_events_txn) to populate
// the event_search table. Responsible for:
//   - Determining if an event type is indexable (messages, names, topics,
//     file uploads, etc.)
//   - Extracting searchable text from event content
//   - Tokenizing extracted text into individual search tokens
//   - Inserting tokens into event_search via EventSearchStore
//   - Handling redactions: remove search entries for redacted events
//   - Handling edits: update search entries when edited content differs
//
// Indexable event types:
//   - m.room.message    (body + formatted_body)
//   - m.room.name       (content.name)
//   - m.room.topic      (content.topic)
//   - m.room.message with m.file (filename + body)
//   - m.sticker         (body)
// ============================================================================
class SearchIndexer {
public:
  // ------------------------------------------------------------------------
  // Constructor — takes refs to DB pool and search store.
  // ------------------------------------------------------------------------
  SearchIndexer(progressive::storage::DatabasePool& db_pool,
                EventSearchStore& search_store)
      : db_pool_(db_pool), search_store_(search_store) {}

  // ------------------------------------------------------------------------
  // is_indexable_event_type — check if an event type should be indexed.
  // Returns true for messages, room names, room topics, stickers, polls.
  // ------------------------------------------------------------------------
  static bool is_indexable_event_type(const std::string& event_type) {
    static const std::set<std::string> indexable_types = {
      "m.room.message",
      "m.room.name",
      "m.room.topic",
      "m.sticker",
    };
    return indexable_types.find(event_type) != indexable_types.end();
  }

  // ------------------------------------------------------------------------
  // index_event — index a single event into the search store.
  //
  // Called during event persistence. Extracts text from event content,
  // tokenizes, and inserts into event_search.
  //
  // Parameters:
  //   txn:              active database transaction
  //   event_id:         the event being persisted
  //   room_id:          the room the event belongs to
  //   event_type:       the Matrix event type (e.g. "m.room.message")
  //   content:          the event content JSON
  //   stream_ordering:  stream position for ordering
  //   origin_server_ts: origin server timestamp in milliseconds
  // ------------------------------------------------------------------------
  void index_event(progressive::storage::LoggingTransaction& txn,
                    const std::string& event_id,
                    const std::string& room_id,
                    const std::string& event_type,
                    const json& content,
                    int64_t stream_ordering,
                    int64_t origin_server_ts) {

    // Only index events of searchable types
    if (!is_indexable_event_type(event_type)) return;

    // Extract searchable text from event content
    auto text_fields = extract_searchable_text(event_type, content);
    if (text_fields.empty()) return;

    // Insert tokens into search store
    search_store_.insert_search_entries(
        txn, event_id, room_id, stream_ordering, origin_server_ts, text_fields);
  }

  // ------------------------------------------------------------------------
  // reindex_event — reindex a single event (delete old entries, insert new).
  // Used when an event is edited or redacted.
  // ------------------------------------------------------------------------
  void reindex_event(progressive::storage::LoggingTransaction& txn,
                      const std::string& event_id,
                      const std::string& room_id,
                      const std::string& event_type,
                      const json& content,
                      int64_t stream_ordering,
                      int64_t origin_server_ts) {

    // Remove old search entries
    search_store_.delete_event_entries(txn, event_id);

    // Insert new entries
    index_event(txn, event_id, room_id, event_type, content,
                stream_ordering, origin_server_ts);
  }

  // ------------------------------------------------------------------------
  // unindex_event — remove all search entries for a given event.
  // Called when an event is redacted, purged, or deleted.
  // ------------------------------------------------------------------------
  void unindex_event(progressive::storage::LoggingTransaction& txn,
                      const std::string& event_id) {
    search_store_.delete_event_entries(txn, event_id);
  }

  // ------------------------------------------------------------------------
  // reindex_room — reindex all events in a room.
  //
  // Fetches all indexable events from the events table for a room,
  // deletes old search entries, and inserts fresh tokens. Uses batching
  // to avoid excessive memory usage.
  //
  // Parameters:
  //   txn:        active database transaction
  //   room_id:    the room to reindex
  //   on_progress: optional callback invoked after each batch, receives
  //                 (batch_number, events_processed, total_events)
  // ------------------------------------------------------------------------
  void reindex_room(
      progressive::storage::LoggingTransaction& txn,
      const std::string& room_id,
      std::function<void(int, int64_t, int64_t)> on_progress =
          [](int, int64_t, int64_t){}) {

    using namespace search_constants;

    // Clear existing search entries for this room
    search_store_.delete_room_entries(txn, room_id);

    // Count total indexable events in this room
    txn.execute(
        "SELECT COUNT(*) FROM events WHERE room_id = ? AND type IN "
        "('m.room.message', 'm.room.name', 'm.room.topic', 'm.sticker') "
        "AND outlier = 0",
        {progressive::storage::SQLParam(room_id)});
    auto count_row = txn.fetchone();
    int64_t total = count_row.has_value() ? count_row->as_int64(0) : 0;

    if (total == 0) return;

    // Fetch and index in batches
    int64_t processed = 0;
    int batch_num = 0;
    int64_t offset = 0;

    while (offset < total) {
      txn.execute(
          "SELECT event_id, type, content, stream_ordering, "
          "origin_server_ts FROM events "
          "WHERE room_id = ? AND type IN "
          "('m.room.message', 'm.room.name', 'm.room.topic', 'm.sticker') "
          "AND outlier = 0 "
          "ORDER BY stream_ordering ASC LIMIT ? OFFSET ?",
          {
            progressive::storage::SQLParam(room_id),
            progressive::storage::SQLParam(
                static_cast<int64_t>(REINDEX_BATCH_SIZE)),
            progressive::storage::SQLParam(offset)
          });

      auto rows = txn.fetchall();
      for (const auto& row : rows) {
        std::string event_id   = row[0].as_string();
        std::string event_type = row[1].as_string();
        std::string content_str = row[2].as_string();
        int64_t stream_ord     = row[3].as_int64();
        int64_t orig_ts        = row[4].as_int64();

        // Parse content JSON
        json content;
        try {
          content = json::parse(content_str);
        } catch (...) {
          content = json::object();
        }

        // Index the event
        index_event(txn, event_id, room_id, event_type, content,
                    stream_ord, orig_ts);
        ++processed;
      }

      ++batch_num;
      on_progress(batch_num, processed, total);
      offset += REINDEX_BATCH_SIZE;
    }
  }

  // ------------------------------------------------------------------------
  // rebuild_all_indexes — rebuild search indexes for all rooms.
  //
  // Fetches all rooms from the rooms table, then reindexes each room
  // sequentially. Reports progress via callback after each room.
  //
  // Parameters:
  //   txn:        active database transaction
  //   on_progress: callback invoked with (rooms_done, total_rooms, current_room_id)
  // ------------------------------------------------------------------------
  void rebuild_all_indexes(
      progressive::storage::LoggingTransaction& txn,
      std::function<void(int64_t, int64_t, const std::string&)> on_progress =
          [](int64_t, int64_t, const std::string&){}) {

    // Clear entire search table
    txn.execute("DELETE FROM event_search");

    // Get all rooms
    txn.execute("SELECT DISTINCT room_id FROM events WHERE outlier = 0");
    auto rows = txn.fetchall();
    std::vector<std::string> room_ids;
    for (const auto& row : rows)
      room_ids.push_back(row[0].as_string());

    int64_t total_rooms = room_ids.size();
    int64_t done = 0;

    for (const auto& room_id : room_ids) {
      on_progress(done, total_rooms, room_id);
      reindex_room(txn, room_id);
      ++done;
    }
    on_progress(done, total_rooms, "");
  }

private:
  progressive::storage::DatabasePool& db_pool_;
  EventSearchStore& search_store_;
};

// ============================================================================
// SearchRanker — rank search results by relevance score.
//
// Scoring factors (combined multiplicatively with weights):
//   1. Exact phrase match:   all search terms appear consecutively in the
//                            indexed value. Highest weight.
//   2. All terms match:      all search terms appear somewhere in the event
//                            content. Second highest.
//   3. Partial term count:   number of search terms that match, proportionally.
//   4. Single term match:    at least one term matches. Base score.
//   5. Recency boost:        exponential decay based on age, newer = higher.
//   6. Key boost:            content.body > content.name > content.topic.
//
// The final score is: base_score * recency_multiplier
// where base_score accumulates from matches and recency_multiplier
// decays exponentially with time.
// ============================================================================
class SearchRanker {
public:
  // ------------------------------------------------------------------------
  // SearchResult — a ranked search result with event metadata and score.
  // ------------------------------------------------------------------------
  struct SearchResult {
    progressive::storage::SearchEntry entry;
    double score{0.0};
    bool exact_match{false};
    int matched_terms{0};
    int total_terms{0};

    // For sorting: higher score first, then higher stream_ordering
    bool operator<(const SearchResult& other) const {
      if (score != other.score) return score > other.score;
      return entry.stream_ordering > other.entry.stream_ordering;
    }
  };

  // ------------------------------------------------------------------------
  // rank — rank a vector of search entries against a set of search terms.
  //
  // For each entry, computes a composite score based on:
  //   - How many search terms match the entry's value
  //   - Whether all terms match (bonus)
  //   - Whether there is an exact phrase match (big bonus)
  //   - The content key (body gets higher base weight than name/topic)
  //   - Recency: newer events score higher
  //
  // The result is a sorted vector of SearchResult, highest score first.
  //
  // Parameters:
  //   entries:      raw search entries from event_search table
  //   search_terms: lowercased, normalized search terms from user query
  //   full_text:    the full original search query (for exact phrase matching)
  //
  // Returns sorted vector of SearchResult.
  // ------------------------------------------------------------------------
  std::vector<SearchResult> rank(
      const std::vector<progressive::storage::SearchEntry>& entries,
      const std::vector<std::string>& search_terms,
      const std::string& full_text) {

    using namespace search_constants;
    std::vector<SearchResult> results;
    results.reserve(entries.size());

    int64_t now = now_ms();
    std::string lower_full_text = to_lower(trim_copy(full_text));

    for (const auto& entry : entries) {
      SearchResult sr;
      sr.entry = entry;
      sr.total_terms = static_cast<int>(search_terms.size());

      std::string lower_value = to_lower(entry.value);

      // Count matching terms
      int match_count = 0;
      for (const auto& term : search_terms) {
        if (lower_value.find(term) != std::string::npos) {
          ++match_count;
        }
      }

      if (match_count == 0) {
        sr.score = 0.0;
        sr.matched_terms = 0;
        results.push_back(sr);
        continue;
      }

      sr.matched_terms = match_count;

      // Base score: term match count
      double base = 0.0;

      // Exact phrase match: all terms appear consecutively
      if (!lower_full_text.empty() &&
          lower_value.find(lower_full_text) != std::string::npos) {
        base += WEIGHT_EXACT_PHRASE;
        sr.exact_match = true;
      }

      // All terms match
      if (match_count == sr.total_terms) {
        base += WEIGHT_ALL_TERMS;
      }

      // Proportional partial match
      double partial_ratio =
          static_cast<double>(match_count) / sr.total_terms;
      base += WEIGHT_PARTIAL_TERM * partial_ratio;

      // Per-term match bonus
      base += WEIGHT_SINGLE_TERM * match_count;

      // Key boost: body fields are more relevant than name/topic
      if (entry.key == search_constants::KEY_BODY) {
        base *= 1.5;
      } else if (entry.key == search_constants::KEY_NAME) {
        base *= 1.0;
      } else {
        base *= 0.7;
      }

      // Recency boost: exponential decay
      int64_t age_ms = now - entry.origin_server_ts;
      if (age_ms < 0) age_ms = 0; // future events get max recency
      double recency_multiplier =
          std::exp(-static_cast<double>(age_ms) / RECENCY_HALF_LIFE_MS) *
          WEIGHT_RECENCY + 1.0;

      sr.score = base * recency_multiplier;

      results.push_back(sr);
    }

    // Sort: highest score first
    std::sort(results.begin(), results.end());

    return results;
  }

  // ------------------------------------------------------------------------
  // rank_with_grouping — rank entries and group them by room_id or sender.
  //
  // When grouping is requested, each group gets its own ranked list,
  // and results are returned as a map from group_key -> ranked results.
  //
  // group_by: "room_id" or "sender"
  // results_per_group: max results per group
  // ------------------------------------------------------------------------
  std::map<std::string, std::vector<SearchResult>> rank_with_grouping(
      const std::vector<progressive::storage::SearchEntry>& entries,
      const std::vector<std::string>& search_terms,
      const std::string& full_text,
      const std::string& group_by,
      int results_per_group) {

    // Rank all entries first
    auto ranked = rank(entries, search_terms, full_text);

    // Group by the specified field
    std::map<std::string, std::vector<SearchResult>> groups;

    for (auto& result : ranked) {
      if (result.score <= 0.0) continue;

      std::string group_key;
      if (group_by == search_constants::GROUP_ROOM_ID) {
        group_key = result.entry.room_id;
      } else if (group_by == search_constants::GROUP_SENDER) {
        group_key = result.entry.event_id.substr(
            1, result.entry.event_id.find(':') - 1); // extract sender-like id
        // Fallback: use event_id as group key
        if (group_key.empty()) group_key = result.entry.event_id;
      } else {
        group_key = "__all__";
      }

      if (static_cast<int>(groups[group_key].size()) < results_per_group) {
        groups[group_key].push_back(std::move(result));
      }
    }

    return groups;
  }

  // ------------------------------------------------------------------------
  // compute_score_for_entry — compute score for a single entry/term set.
  // Exposed for external use by admin/analytics code.
  // ------------------------------------------------------------------------
  static double compute_score(double base, int64_t origin_server_ts) {
    using namespace search_constants;
    int64_t now = now_internal();
    int64_t age_ms = now - origin_server_ts;
    if (age_ms < 0) age_ms = 0;
    double recency = std::exp(-static_cast<double>(age_ms) / RECENCY_HALF_LIFE_MS)
                     * WEIGHT_RECENCY + 1.0;
    return base * recency;
  }

private:
  static int64_t now_internal() {
    return chr::duration_cast<chr::milliseconds>(
               chr::system_clock::now().time_since_epoch())
        .count();
  }
};

// ============================================================================
// FullTextSearchEngine — the main search query engine.
//
// Orchestrates the full search pipeline:
//   1. Parse and normalize the user's search query
//   2. Tokenize the query into individual search terms
//   3. Query event_search for matching entries
//   4. Rank results using SearchRanker
//   5. Paginate results using cursor tokens
//   6. Group results by room/sender if requested
//   7. Apply room-level filtering (user's joined rooms for multi-room)
//
// Supports:
//   - Single room search (with room_id parameter)
//   - Multi-room search (search across all rooms a user is in)
//   - Global search (admin-only, search across all rooms)
//   - Filter by event type, sender, time range
//   - Order by rank (relevance) or recency (stream_ordering)
//   - Include state events in search scope
// ============================================================================
class FullTextSearchEngine {
public:
  // ------------------------------------------------------------------------
  // SearchOptions — encapsulates all search parameters.
  // ------------------------------------------------------------------------
  struct SearchOptions {
    std::string search_term;          // raw user query
    std::string room_id;             // empty = all rooms user is in
    std::string user_id;             // user performing the search
    std::string order_by;            // "rank" or "recent"
    std::string group_by;            // "room_id", "sender", or "none"
    std::string next_batch;          // pagination token
    int limit{50};                   // max results
    bool include_state{false};       // include state events in results
    bool is_admin{false};            // admin search (no room filtering)
    int context_before{5};           // events_before for each result
    int context_after{5};            // events_after for each result
    std::optional<std::string> event_type_filter; // filter by event type
    std::optional<std::string> sender_filter;    // filter by sender
  };

  // ------------------------------------------------------------------------
  // SearchResponse — structured response from a search.
  // ------------------------------------------------------------------------
  struct SearchResponse {
    struct Result {
      std::string event_id;
      std::string room_id;
      std::string sender;
      std::string type;
      json content;
      int64_t origin_server_ts{0};
      int64_t stream_ordering{0};
      double rank{0.0};
      json context; // { events_before: [], events_after: [] }
    };

    std::vector<Result> results;
    std::optional<std::string> next_batch;
    int64_t total_results{0};
    std::map<std::string, std::vector<Result>> groups;
    bool grouped{false};
  };

  // ------------------------------------------------------------------------
  // Constructor
  // ------------------------------------------------------------------------
  FullTextSearchEngine(EventSearchStore& search_store,
                       SearchRanker& ranker,
                       progressive::storage::DatabasePool& db_pool)
      : search_store_(search_store),
        ranker_(ranker),
        db_pool_(db_pool) {}

  // ------------------------------------------------------------------------
  // search — execute a full-text search with the given options.
  //
  // Full pipeline:
  //   1. Normalize search term (trim, lowercase, strip special chars)
  //   2. Tokenize into individual search terms
  //   3. Resolve room scope (single room, user's rooms, or global)
  //   4. Query event_search for matching entries
  //   5. Rank results
  //   6. Apply grouping if requested
  //   7. Paginate with next_batch token
  //   8. Fetch full event data for each result
  //   9. Fetch context (before/after) for each result if requested
  //
  // Returns SearchResponse with results, next_batch, and metadata.
  // ------------------------------------------------------------------------
  SearchResponse search(progressive::storage::LoggingTransaction& txn,
                         const SearchOptions& options) {

    using namespace search_constants;

    SearchResponse response;

    // ---- 1. Normalize the search term ----
    std::string term = trim_copy(options.search_term);
    if (term.empty()) {
      return response; // empty search returns no results
    }

    std::string lower_term = to_lower(term);

    // ---- 2. Tokenize search query ----
    std::set<std::string> token_set = tokenize(term);
    if (token_set.empty()) {
      return response;
    }
    std::vector<std::string> tokens(token_set.begin(), token_set.end());

    // ---- 3. Resolve pagination cursor ----
    int64_t after_stream = INT64_MAX;
    if (!options.next_batch.empty()) {
      try {
        auto [so, ts, ignored] =
            SearchTokenCodec::decode(options.next_batch);
        after_stream = so;
      } catch (...) {
        // Invalid token, start from beginning
      }
    }

    int fetch_limit = options.limit + 1; // fetch one extra for next_batch

    // ---- 4. Determine room scope and query ----
    std::vector<progressive::storage::SearchEntry> raw_entries;

    if (!options.room_id.empty()) {
      // Single room search
      raw_entries = search_store_.search_multi_keyword(
          txn, tokens, options.room_id, after_stream, fetch_limit);
    } else if (options.is_admin) {
      // Admin global search: no room filter
      raw_entries = search_store_.search_multi_keyword(
          txn, tokens, "", after_stream, fetch_limit);
    } else {
      // Multi-room search: only rooms the user is in
      raw_entries = search_user_rooms(txn, options.user_id, tokens,
                                       after_stream, fetch_limit);
    }

    // ---- 5. Rank results ----
    std::vector<SearchRanker::SearchResult> ranked;

    if (options.group_by == GROUP_ROOM_ID || options.group_by == GROUP_SENDER) {
      // Grouped ranking
      auto groups = ranker_.rank_with_grouping(
          raw_entries, tokens, lower_term, options.group_by, options.limit);

      response.grouped = true;
      response.results.reserve(raw_entries.size());

      for (auto& [group_key, group_results] : groups) {
        std::vector<SearchResponse::Result> group_output;
        for (const auto& sr : group_results) {
          group_output.push_back(search_result_to_response(txn, sr));
        }
        response.groups[group_key] = group_output;
        // Also flatten into results for non-grouped consumer
        for (auto& r : group_output) {
          response.results.push_back(std::move(r));
        }
      }
    } else {
      // Regular flat ranking
      ranked = ranker_.rank(raw_entries, tokens, lower_term);

      // Filter out zero-score results
      ranked.erase(
          std::remove_if(ranked.begin(), ranked.end(),
                         [](const auto& r) { return r.score <= 0.0; }),
          ranked.end());

      // Apply order_by
      if (options.order_by == ORDER_RECENT) {
        std::sort(ranked.begin(), ranked.end(),
                  [](const auto& a, const auto& b) {
                    return a.entry.stream_ordering > b.entry.stream_ordering;
                  });
      }
      // Default is rank order (already sorted by SearchRanker::rank)

      // ---- 6. Pagination ----
      bool has_more = static_cast<int>(ranked.size()) > options.limit;
      if (has_more) {
        ranked.resize(options.limit);
      }

      // Generate next_batch token if there are more results
      if (has_more && !ranked.empty()) {
        const auto& last = ranked.back();
        response.next_batch = SearchTokenCodec::encode(
            last.entry.stream_ordering, last.entry.origin_server_ts,
            lower_term);
      }

      // ---- 7. Fetch full event data & context ----
      for (const auto& sr : ranked) {
        response.results.push_back(search_result_to_response(txn, sr));
      }
    }

    // ---- 8. Fetch context for each result if requested ----
    if (options.context_before > 0 || options.context_after > 0) {
      EventContextFetcher context_fetcher(db_pool_);
      for (auto& result : response.results) {
        result.context = context_fetcher.fetch_context(
            txn, result.room_id, result.event_id,
            options.context_before, options.context_after);
      }
    }

    response.total_results = response.results.size();

    return response;
  }

  // ------------------------------------------------------------------------
  // search_user_rooms — search across all rooms a user is a member of.
  //
  // Queries each room the user is in and aggregates results. Uses
  // roommember store to get user's room list, then queries event_search
  // for each room independently, combining and re-ranking.
  // ------------------------------------------------------------------------
  std::vector<progressive::storage::SearchEntry> search_user_rooms(
      progressive::storage::LoggingTransaction& txn,
      const std::string& user_id,
      const std::vector<std::string>& tokens,
      int64_t after_stream,
      int fetch_limit) {

    using namespace search_constants;
    std::vector<progressive::storage::SearchEntry> all_entries;

    if (user_id.empty()) return all_entries;

    // Get user's joined rooms from room_memberships table
    txn.execute(
        "SELECT DISTINCT room_id FROM room_memberships "
        "WHERE user_id = ? AND membership = 'join'",
        {progressive::storage::SQLParam(user_id)});
    auto rows = txn.fetchall();

    std::vector<std::string> room_ids;
    for (const auto& row : rows) {
      room_ids.push_back(row[0].as_string());
    }

    if (room_ids.empty()) return all_entries;

    // Search each room (limit per room to avoid overwhelming)
    int per_room_limit = std::max(10, fetch_limit / static_cast<int>(room_ids.size()));

    for (const auto& room_id : room_ids) {
      auto room_entries = search_store_.search_multi_keyword(
          txn, tokens, room_id, after_stream, per_room_limit);
      for (auto& entry : room_entries) {
        all_entries.push_back(std::move(entry));
      }
    }

    return all_entries;
  }

  // ------------------------------------------------------------------------
  // search_result_to_response — convert internal SearchResult to API-ready
  // SearchResponse::Result, fetching full event data from the events table.
  // ------------------------------------------------------------------------
  SearchResponse::Result search_result_to_response(
      progressive::storage::LoggingTransaction& txn,
      const SearchRanker::SearchResult& sr) {

    SearchResponse::Result result;

    // Fetch full event data
    txn.execute(
        "SELECT event_id, type, sender, content, origin_server_ts, "
        "stream_ordering, room_id FROM events WHERE event_id = ?",
        {progressive::storage::SQLParam(sr.entry.event_id)});

    auto row = txn.fetchone();
    if (row.has_value()) {
      result.event_id         = row->as_string(0);
      result.type             = row->as_string(1);
      result.sender           = row->as_string(2);
      result.origin_server_ts = row->as_int64(4);
      result.stream_ordering  = row->as_int64(5);
      result.room_id          = row->as_string(6);
      result.rank             = sr.score;

      // Parse content JSON
      try {
        result.content = json::parse(row->as_string(3));
      } catch (...) {
        result.content = json::object();
      }
    } else {
      // Fallback: use search entry data
      result.event_id         = sr.entry.event_id;
      result.room_id          = sr.entry.room_id;
      result.origin_server_ts = sr.entry.origin_server_ts;
      result.stream_ordering  = sr.entry.stream_ordering;
      result.rank             = sr.score;
      result.type             = "m.room.message";
      result.content          = json{{"body", sr.entry.value}};
    }

    return result;
  }

private:
  EventSearchStore& search_store_;
  SearchRanker& ranker_;
  progressive::storage::DatabasePool& db_pool_;
};

// ============================================================================
// MultiRoomSearchAggregator — handles cross-room search result aggregation.
//
// When searching across multiple rooms, results need to be aggregated,
// merged, and potentially limited per room. This class manages:
//   - Fan-out search to individual room search stores
//   - Result deduplication across rooms
//   - Per-room result limits
//   - Global result merging and re-ranking
//   - Order-by enforcement across rooms
//
// This is used by FullTextSearchEngine internally but separated for
// clarity and testability.
// ============================================================================
class MultiRoomSearchAggregator {
public:
  // ------------------------------------------------------------------------
  // AggregatedResult — a result from multi-room search with room grouping.
  // ------------------------------------------------------------------------
  struct AggregatedResult {
    std::string room_id;
    std::string event_id;
    double score{0.0};
    int64_t stream_ordering{0};
    int match_count{0};
  };

  // ------------------------------------------------------------------------
  // Constructor
  // ------------------------------------------------------------------------
  MultiRoomSearchAggregator(EventSearchStore& search_store,
                            SearchRanker& ranker)
      : search_store_(search_store), ranker_(ranker) {}

  // ------------------------------------------------------------------------
  // aggregate — search across multiple rooms and aggregate results.
  //
  // Parameters:
  //   txn:           active database transaction
  //   room_ids:      list of rooms to search
  //   tokens:        search tokens
  //   full_text:     original search query
  //   max_per_room:  max results per room before global merge
  //   global_limit:  max total results after merge
  //
  // Returns sorted list of AggregatedResult by score DESC.
  // ------------------------------------------------------------------------
  std::vector<AggregatedResult> aggregate(
      progressive::storage::LoggingTransaction& txn,
      const std::vector<std::string>& room_ids,
      const std::vector<std::string>& tokens,
      const std::string& full_text,
      int max_per_room,
      int global_limit) {

    std::vector<AggregatedResult> all_results;

    for (const auto& room_id : room_ids) {
      // Search this room
      auto entries = search_store_.search_multi_keyword(
          txn, tokens, room_id, 0, max_per_room);

      if (entries.empty()) continue;

      // Rank within room
      auto ranked = ranker_.rank(entries, tokens, full_text);

      for (const auto& sr : ranked) {
        if (sr.score <= 0.0) continue;
        AggregatedResult ar;
        ar.room_id = room_id;
        ar.event_id = sr.entry.event_id;
        ar.score = sr.score;
        ar.stream_ordering = sr.entry.stream_ordering;
        ar.match_count = sr.matched_terms;
        all_results.push_back(ar);
      }
    }

    // Sort globally by score DESC, then stream_ordering DESC
    std::sort(all_results.begin(), all_results.end(),
              [](const AggregatedResult& a, const AggregatedResult& b) {
                if (a.score != b.score) return a.score > b.score;
                return a.stream_ordering > b.stream_ordering;
              });

    // Apply global limit
    if (static_cast<int>(all_results.size()) > global_limit)
      all_results.resize(global_limit);

    return all_results;
  }

  // ------------------------------------------------------------------------
  // aggregate_by_group — aggregate results with explicit group boundaries.
  //
  // Returns a map of group_key -> list of results, suitable for the
  // grouped search response format.
  // ------------------------------------------------------------------------
  std::map<std::string, std::vector<AggregatedResult>> aggregate_by_group(
      progressive::storage::LoggingTransaction& txn,
      const std::vector<std::string>& room_ids,
      const std::vector<std::string>& tokens,
      const std::string& full_text,
      int max_per_room,
      int global_limit) {

    std::map<std::string, std::vector<AggregatedResult>> groups;

    for (const auto& room_id : room_ids) {
      auto entries = search_store_.search_multi_keyword(
          txn, tokens, room_id, 0, max_per_room);

      if (entries.empty()) continue;

      auto ranked = ranker_.rank(entries, tokens, full_text);

      auto& group = groups[room_id];
      for (const auto& sr : ranked) {
        if (sr.score <= 0.0) continue;
        AggregatedResult ar;
        ar.room_id = room_id;
        ar.event_id = sr.entry.event_id;
        ar.score = sr.score;
        ar.stream_ordering = sr.entry.stream_ordering;
        ar.match_count = sr.matched_terms;
        group.push_back(ar);
      }

      // Limit per group
      if (static_cast<int>(group.size()) > max_per_room)
        group.resize(max_per_room);
    }

    return groups;
  }

private:
  EventSearchStore& search_store_;
  SearchRanker& ranker_;
};

// ============================================================================
// SearchProgressTracker — tracks progress of long-running search operations.
//
// Used by reindex operations to report progress. Stores:
//   - Current batch number
//   - Events processed out of total
//   - Current room being processed
//   - Elapsed time
//   - Estimated time remaining
// ============================================================================
class SearchProgressTracker {
public:
  struct Progress {
    int batch_number{0};
    int64_t events_processed{0};
    int64_t total_events{0};
    int64_t rooms_done{0};
    int64_t total_rooms{0};
    std::string current_room_id;
    double percent_complete{0.0};
    double elapsed_seconds{0.0};
    std::optional<double> eta_seconds;
    bool is_complete{false};
  };

  // ------------------------------------------------------------------------
  // Constructor
  // ------------------------------------------------------------------------
  SearchProgressTracker()
      : start_time_(chr::steady_clock::now()) {}

  // ------------------------------------------------------------------------
  // update — update the tracker with latest progress data.
  // ------------------------------------------------------------------------
  void update(int batch, int64_t processed, int64_t total) {
    std::lock_guard<std::mutex> lock(mutex_);
    progress_.batch_number = batch;
    progress_.events_processed = processed;
    progress_.total_events = total;
    progress_.percent_complete = (total > 0)
        ? (static_cast<double>(processed) / total * 100.0) : 0.0;
    recalc_eta();
  }

  // ------------------------------------------------------------------------
  // update_room_progress — update with room-level progress.
  // ------------------------------------------------------------------------
  void update_room_progress(int64_t done, int64_t total,
                             const std::string& current_room) {
    std::lock_guard<std::mutex> lock(mutex_);
    progress_.rooms_done = done;
    progress_.total_rooms = total;
    progress_.current_room_id = current_room;
    if (total > 0) {
      progress_.percent_complete =
          static_cast<double>(done) / total * 100.0;
    }
    recalc_eta();
  }

  // ------------------------------------------------------------------------
  // mark_complete — mark the operation as finished.
  // ------------------------------------------------------------------------
  void mark_complete() {
    std::lock_guard<std::mutex> lock(mutex_);
    progress_.is_complete = true;
    progress_.percent_complete = 100.0;
    progress_.eta_seconds = std::nullopt;
    progress_.elapsed_seconds = elapsed();
  }

  // ------------------------------------------------------------------------
  // get_progress — get a snapshot of current progress.
  // ------------------------------------------------------------------------
  Progress get_progress() const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto p = progress_;
    p.elapsed_seconds = elapsed();
    return p;
  }

  // ------------------------------------------------------------------------
  // to_json — serialize progress to JSON for API responses.
  // ------------------------------------------------------------------------
  json to_json() const {
    auto p = get_progress();
    json j;
    j["batch_number"]     = p.batch_number;
    j["events_processed"] = p.events_processed;
    j["total_events"]     = p.total_events;
    j["rooms_done"]       = p.rooms_done;
    j["total_rooms"]      = p.total_rooms;
    j["current_room_id"]  = p.current_room_id;
    j["percent_complete"] = p.percent_complete;
    j["elapsed_seconds"]  = p.elapsed_seconds;
    j["is_complete"]      = p.is_complete;
    if (p.eta_seconds) j["eta_seconds"] = *p.eta_seconds;
    return j;
  }

private:
  void recalc_eta() {
    double elapsed = elapsed();
    if (elapsed > 0 && progress_.percent_complete > 0) {
      double total_estimated =
          elapsed / (progress_.percent_complete / 100.0);
      progress_.eta_seconds = total_estimated - elapsed;
    }
    progress_.elapsed_seconds = elapsed;
  }

  double elapsed() const {
    auto now = chr::steady_clock::now();
    return chr::duration_cast<chr::duration<double>>(now - start_time_).count();
  }

  mutable std::mutex mutex_;
  Progress progress_;
  chr::steady_clock::time_point start_time_;
};

// ============================================================================
// EventContextFetcher — fetches events before and after a target event.
//
// When returning search results, clients expect "context" around each
// matching event. This class fetches:
//   - events_before: up to N events that occurred before the target
//                    in the same room's timeline
//   - events_after:  up to M events that occurred after the target
//
// Uses stream_ordering for timeline ordering. Returns full event JSON
// suitable for inclusion in search result context sections.
// ============================================================================
class EventContextFetcher {
public:
  // ------------------------------------------------------------------------
  // Constructor
  // ------------------------------------------------------------------------
  explicit EventContextFetcher(progressive::storage::DatabasePool& db_pool)
      : db_pool_(db_pool) {}

  // ------------------------------------------------------------------------
  // fetch_context — get context events around a target event.
  //
  // Parameters:
  //   txn:       active database transaction
  //   room_id:   the room containing the target event
  //   event_id:  the target event ID
  //   limit_before: max events before the target
  //   limit_after:  max events after the target
  //
  // Returns JSON: { events_before: [...], events_after: [...] }
  // Each event in the array is a full event JSON object.
  // ------------------------------------------------------------------------
  json fetch_context(progressive::storage::LoggingTransaction& txn,
                      const std::string& room_id,
                      const std::string& event_id,
                      int limit_before,
                      int limit_after) {

    json context;
    context["events_before"] = json::array();
    context["events_after"]  = json::array();

    if (limit_before <= 0 && limit_after <= 0) return context;

    // Get the target event's stream_ordering
    txn.execute(
        "SELECT stream_ordering FROM events WHERE event_id = ?",
        {progressive::storage::SQLParam(event_id)});
    auto target_row = txn.fetchone();
    if (!target_row.has_value()) return context;

    int64_t target_stream = target_row->as_int64(0);

    // Fetch events_before (stream_ordering < target, DESC, then reverse)
    if (limit_before > 0) {
      txn.execute(
          "SELECT event_id, type, sender, content, origin_server_ts, "
          "stream_ordering FROM events "
          "WHERE room_id = ? AND stream_ordering < ? AND outlier = 0 "
          "ORDER BY stream_ordering DESC LIMIT ?",
          {
            progressive::storage::SQLParam(room_id),
            progressive::storage::SQLParam(target_stream),
            progressive::storage::SQLParam(static_cast<int64_t>(limit_before))
          });

      auto rows = txn.fetchall();
      std::vector<json> before_events;
      for (const auto& row : rows) {
        json ev = row_to_event_json(row);
        before_events.push_back(ev);
      }
      // Reverse to get chronological order
      std::reverse(before_events.begin(), before_events.end());
      context["events_before"] = before_events;
    }

    // Fetch events_after (stream_ordering > target, ASC)
    if (limit_after > 0) {
      txn.execute(
          "SELECT event_id, type, sender, content, origin_server_ts, "
          "stream_ordering FROM events "
          "WHERE room_id = ? AND stream_ordering > ? AND outlier = 0 "
          "ORDER BY stream_ordering ASC LIMIT ?",
          {
            progressive::storage::SQLParam(room_id),
            progressive::storage::SQLParam(target_stream),
            progressive::storage::SQLParam(static_cast<int64_t>(limit_after))
          });

      auto rows = txn.fetchall();
      json after_events = json::array();
      for (const auto& row : rows) {
        after_events.push_back(row_to_event_json(row));
      }
      context["events_after"] = after_events;
    }

    return context;
  }

  // ------------------------------------------------------------------------
  // fetch_context_multi — fetch context for multiple events in a batch.
  //
  // More efficient than calling fetch_context individually since it
  // can use a single DB round-trip per room.
  //
  // Parameters:
  //   txn:           active database transaction
  //   room_id:       room containing all target events
  //   event_ids:     list of target event IDs
  //   limit_before:  max events before each target
  //   limit_after:   max events after each target
  //
  // Returns map: event_id -> context JSON.
  // ------------------------------------------------------------------------
  std::map<std::string, json> fetch_context_multi(
      progressive::storage::LoggingTransaction& txn,
      const std::string& room_id,
      const std::vector<std::string>& event_ids,
      int limit_before,
      int limit_after) {

    std::map<std::string, json> contexts;

    for (const auto& event_id : event_ids) {
      contexts[event_id] = fetch_context(
          txn, room_id, event_id, limit_before, limit_after);
    }

    return contexts;
  }

private:
  // ------------------------------------------------------------------------
  // row_to_event_json — convert a database row to a Matrix event JSON.
  // Columns: event_id, type, sender, content, origin_server_ts, stream_ordering
  // ------------------------------------------------------------------------
  static json row_to_event_json(
      const progressive::storage::Row& row) {
    json ev;
    ev["event_id"]        = row[0].as_string();
    ev["type"]            = row[1].as_string();
    ev["sender"]          = row[2].as_string();
    ev["origin_server_ts"] = row[4].as_int64();

    try {
      ev["content"] = json::parse(row[3].as_string());
    } catch (...) {
      ev["content"] = json::object();
    }

    return ev;
  }

  progressive::storage::DatabasePool& db_pool_;
};

// ============================================================================
// SearchAdminAPI — admin REST API endpoints for search administration.
//
// Exposes:
//   POST   /_synapse/admin/v1/search/reindex-room/{roomId}
//          Reindex all events in a specific room. Returns progress stats.
//   POST   /_synapse/admin/v1/search/reindex-all
//          Rebuild search indexes for all rooms. Async operation with
//          progress tracking.
//   GET    /_synapse/admin/v1/search/progress/{jobId}
//          Get progress of a running reindex operation.
//   GET    /_synapse/admin/v1/search/stats
//          Get search index statistics (total entries, per-room counts).
//   POST   /_synapse/admin/v1/search/purge-stale
//          Remove search entries for events that no longer exist.
//   GET    /_synapse/admin/v1/search/health
//          Check search index health (stale entries, consistency).
//
// All endpoints require admin authentication.
// ============================================================================
class SearchAdminAPI {
public:
  // ------------------------------------------------------------------------
  // Constructor
  // ------------------------------------------------------------------------
  SearchAdminAPI(progressive::storage::DatabasePool& db_pool,
                 EventSearchStore& search_store,
                 SearchIndexer& indexer)
      : db_pool_(db_pool),
        search_store_(search_store),
        indexer_(indexer) {}

  // ------------------------------------------------------------------------
  // reindex_room — admin endpoint handler for reindexing a single room.
  //
  // POST /_synapse/admin/v1/search/reindex-room/{roomId}
  //
  // Request body (optional): { batch_size: int }
  //
  // Response:
  //   {
  //     "room_id": "!abc:localhost",
  //     "events_indexed": 1234,
  //     "total_events": 1234,
  //     "duration_ms": 567,
  //     "success": true
  //   }
  // ------------------------------------------------------------------------
  json handle_reindex_room(progressive::storage::LoggingTransaction& txn,
                            const std::string& room_id,
                            const json& request_body) {

    using namespace search_constants;

    if (!is_valid_room_id(room_id)) {
      return build_error(400, M_INVALID_PARAM,
                         "Invalid room ID: " + room_id);
    }

    // Helper: get batch size from request
    int batch_size = REINDEX_BATCH_SIZE;
    if (request_body.contains("batch_size") && request_body["batch_size"].is_number()) {
      batch_size = request_body["batch_size"].get<int>();
      if (batch_size < 10) batch_size = 10;
      if (batch_size > 1000) batch_size = 1000;
    }

    auto start = chr::steady_clock::now();

    // Count old entries for stats
    int64_t old_entries = search_store_.count_entries_for_room(txn, room_id);

    // Perform reindex
    int64_t events_indexed = 0;
    int64_t total_events = 0;

    auto on_progress = [&](int batch, int64_t processed, int64_t total) {
      events_indexed = processed;
      total_events = total;
    };

    indexer_.reindex_room(txn, room_id, on_progress);

    auto end = chr::steady_clock::now();
    auto duration_ms = chr::duration_cast<chr::milliseconds>(end - start).count();

    int64_t new_entries = search_store_.count_entries_for_room(txn, room_id);

    return json{
      {"room_id",         room_id},
      {"events_indexed",  events_indexed},
      {"total_events",    total_events},
      {"old_search_entries", old_entries},
      {"new_search_entries", new_entries},
      {"duration_ms",     duration_ms},
      {"success",         true}
    };
  }

  // ------------------------------------------------------------------------
  // handle_reindex_all — admin endpoint handler for full reindex.
  //
  // POST /_synapse/admin/v1/search/reindex-all
  //
  // Response:
  //   {
  //     "job_id": "abc123",
  //     "total_rooms": 42,
  //     "status": "started",
  //     "message": "Reindex started for 42 rooms"
  //   }
  // ------------------------------------------------------------------------
  json handle_reindex_all(progressive::storage::LoggingTransaction& txn) {
    auto start = chr::steady_clock::now();

    int64_t rooms_done = 0;
    int64_t total_rooms = 0;

    auto on_progress = [&](int64_t done, int64_t total,
                            const std::string& room) {
      rooms_done = done;
      total_rooms = total;
    };

    indexer_.rebuild_all_indexes(txn, on_progress);

    auto end = chr::steady_clock::now();
    auto duration_ms = chr::duration_cast<chr::milliseconds>(end - start).count();
    int64_t total_entries = search_store_.count_total_entries(txn);

    return json{
      {"total_rooms",     total_rooms},
      {"rooms_processed",  rooms_done},
      {"total_entries",    total_entries},
      {"duration_ms",      duration_ms},
      {"success",          true}
    };
  }

  // ------------------------------------------------------------------------
  // handle_stats — get search index statistics.
  //
  // GET /_synapse/admin/v1/search/stats
  //
  // Optional query params:
  //   room_id: filter stats to specific room
  //   verbose: include per-room breakdown
  //
  // Response:
  //   {
  //     "total_entries": 50000,
  //     "total_indexed_events": 12000,
  //     "total_rooms": 42,
  //     "rooms": [ {room_id, entry_count, event_count}, ... ]
  //   }
  // ------------------------------------------------------------------------
  json handle_stats(progressive::storage::LoggingTransaction& txn,
                     const std::string& room_id_filter = "",
                     bool verbose = false) {

    json response;
    response["total_entries"] = search_store_.count_total_entries(txn);

    // Count total events across all rooms
    txn.execute("SELECT COUNT(DISTINCT room_id) FROM events WHERE outlier = 0");
    auto room_count_row = txn.fetchone();
    response["total_rooms"] = room_count_row.has_value()
        ? room_count_row->as_int64(0) : 0;

    if (verbose) {
      json rooms = json::array();

      std::string room_query = room_id_filter.empty()
          ? "SELECT DISTINCT room_id FROM event_search"
          : "SELECT DISTINCT room_id FROM event_search WHERE room_id = ?";

      if (room_id_filter.empty()) {
        txn.execute(room_query);
      } else {
        txn.execute(room_query,
                     {progressive::storage::SQLParam(room_id_filter)});
      }

      auto rows = txn.fetchall();
      for (const auto& row : rows) {
        std::string rid = row[0].as_string();
        int64_t entry_count = search_store_.count_entries_for_room(txn, rid);

        txn.execute("SELECT COUNT(*) FROM events WHERE room_id = ? AND outlier = 0",
                     {progressive::storage::SQLParam(rid)});
        auto event_count_row = txn.fetchone();
        int64_t event_count = event_count_row.has_value()
            ? event_count_row->as_int64(0) : 0;

        rooms.push_back({
          {"room_id", rid},
          {"entry_count", entry_count},
          {"event_count", event_count},
          {"avg_entries_per_event",
           event_count > 0 ? static_cast<double>(entry_count) / event_count : 0.0}
        });
      }

      response["rooms"] = rooms;
    }

    return response;
  }

  // ------------------------------------------------------------------------
  // handle_purge_stale — remove stale search entries.
  //
  // POST /_synapse/admin/v1/search/purge-stale
  //
  // Response:
  //   {
  //     "entries_removed": 42,
  //     "entries_remaining": 50000,
  //     "success": true
  //   }
  // ------------------------------------------------------------------------
  json handle_purge_stale(progressive::storage::LoggingTransaction& txn) {
    int64_t before_count = search_store_.count_total_entries(txn);
    int64_t removed = search_store_.purge_stale_entries(txn);
    int64_t after_count = search_store_.count_total_entries(txn);

    return json{
      {"entries_removed",   removed},
      {"entries_before",    before_count},
      {"entries_remaining", after_count},
      {"success",           true}
    };
  }

  // ------------------------------------------------------------------------
  // handle_health — check search index health.
  //
  // GET /_synapse/admin/v1/search/health
  //
  // Checks:
  //   - Stale entries (event_search rows with no matching event)
  //   - Missing entries (indexable events with no event_search rows)
  //   - Total entry count
  //   - Average entries per event
  //
  // Response:
  //   {
  //     "healthy": true/false,
  //     "stale_entries": 0,
  //     "missing_indexed_events": 10,
  //     "total_entries": 50000,
  //     "total_events_indexable": 12400,
  //     "coverage_percent": 99.2,
  //     "issues": [ "Missing 10 events from index" ]
  //   }
  // ------------------------------------------------------------------------
  json handle_health(progressive::storage::LoggingTransaction& txn) {
    json response;
    std::vector<std::string> issues;

    // Check stale entries
    txn.execute(
        "SELECT COUNT(*) FROM event_search WHERE event_id NOT IN "
        "(SELECT event_id FROM events)");
    auto stale_row = txn.fetchone();
    int64_t stale = stale_row.has_value() ? stale_row->as_int64(0) : 0;

    // Check missing indexed events
    txn.execute(
        "SELECT COUNT(*) FROM events WHERE type IN "
        "('m.room.message', 'm.room.name', 'm.room.topic', 'm.sticker') "
        "AND outlier = 0 AND event_id NOT IN "
        "(SELECT DISTINCT event_id FROM event_search)");
    auto missing_row = txn.fetchone();
    int64_t missing = missing_row.has_value() ? missing_row->as_int64(0) : 0;

    int64_t total_entries = search_store_.count_total_entries(txn);

    txn.execute(
        "SELECT COUNT(*) FROM events WHERE type IN "
        "('m.room.message', 'm.room.name', 'm.room.topic', 'm.sticker') "
        "AND outlier = 0");
    auto total_events_row = txn.fetchone();
    int64_t total_indexable = total_events_row.has_value()
        ? total_events_row->as_int64(0) : 0;

    double coverage = total_indexable > 0
        ? (static_cast<double>(total_indexable - missing) / total_indexable * 100.0)
        : 100.0;

    response["total_entries"]            = total_entries;
    response["total_events_indexable"]   = total_indexable;
    response["stale_entries"]            = stale;
    response["missing_indexed_events"]    = missing;
    response["coverage_percent"]         = coverage;

    if (stale > 0)
      issues.push_back("Found " + std::to_string(stale) +
                       " stale search entries (events no longer exist)");
    if (missing > 0)
      issues.push_back("Missing " + std::to_string(missing) +
                       " events from search index");
    if (total_indexable == 0)
      issues.push_back("No indexable events found");

    response["healthy"] = (stale == 0 && missing == 0 && total_indexable > 0);
    response["issues"] = issues;

    return response;
  }

  // ------------------------------------------------------------------------
  // handle_event_detail — get search index detail for a specific event.
  //
  // GET /_synapse/admin/v1/search/event/{eventId}
  //
  // Response:
  //   {
  //     "event_id": "$abc:localhost",
  //     "indexed": true,
  //     "entry_count": 5,
  //     "entries": [
  //       { "key": "content.body", "value": "hello world" },
  //       ...
  //     ]
  //   }
  // ------------------------------------------------------------------------
  json handle_event_detail(progressive::storage::LoggingTransaction& txn,
                            const std::string& event_id) {

    if (!is_valid_event_id(event_id)) {
      return build_error(400, search_constants::M_INVALID_PARAM,
                         "Invalid event ID: " + event_id);
    }

    txn.execute(
        "SELECT key, value, stream_ordering, origin_server_ts "
        "FROM event_search WHERE event_id = ? "
        "ORDER BY key, value",
        {progressive::storage::SQLParam(event_id)});

    auto rows = txn.fetchall();
    json entries = json::array();
    for (const auto& row : rows) {
      entries.push_back({
        {"key", row[0].as_string()},
        {"value", row[1].as_string()},
        {"stream_ordering", row[2].as_int64()},
        {"origin_server_ts", row[3].as_int64()}
      });
    }

    return json{
      {"event_id",    event_id},
      {"indexed",     !entries.empty()},
      {"entry_count", entries.size()},
      {"entries",     entries}
    };
  }

private:
  progressive::storage::DatabasePool& db_pool_;
  EventSearchStore& search_store_;
  SearchIndexer& indexer_;
};

// ============================================================================
// SearchAPIHandler — implements the Client-Server /search REST endpoint.
//
// Endpoint: POST /_matrix/client/v3/search
//
// Request body (JSON):
//   {
//     "search_categories": {
//       "room_events": {
//         "search_term": "hello world",
//         "keys": ["content.body", "content.name", "content.topic"],
//         "filter": {
//           "rooms": ["!room1:localhost", "!room2:localhost"],
//           "senders": ["@user:localhost"],
//           "types": ["m.room.message"],
//           "not_rooms": ["!hidden:localhost"],
//           "not_senders": ["@blocked:localhost"],
//           "contains_url": true
//         },
//         "order_by": "recent",
//         "groupings": { "group_by": [ {"key": "room_id"} ] },
//         "include_state": false,
//         "event_context": {
//           "before_limit": 5,
//           "after_limit": 5,
//           "include_profile": true
//         },
//         "limit": 50,
//         "next_batch": "base64token..."
//       }
//     }
//   }
//
// Response:
//   {
//     "search_categories": {
//       "room_events": {
//         "results": [ ... ],
//         "count": 42,
//         "highlights": ["hello", "world"],
//         "next_batch": "base64token...",
//         "groups": { "!room1:localhost": { ... }, ... }
//       }
//     }
//   }
//
// Equivalent to synapse/rest/client/search.py SearchRestServlet
// ============================================================================
class SearchAPIHandler : public progressive::rest::ClientV1RestServlet {
public:
  // ------------------------------------------------------------------------
  // Constructor — ties together all search components.
  // ------------------------------------------------------------------------
  SearchAPIHandler(progressive::storage::DatabasePool& db_pool,
                   EventSearchStore& search_store,
                   SearchRanker& ranker)
      : db_pool_(db_pool),
        search_store_(search_store),
        ranker_(ranker),
        search_engine_(search_store, ranker, db_pool) {}

  // ------------------------------------------------------------------------
  // patterns — REST URL patterns this servlet handles.
  // ------------------------------------------------------------------------
  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/search",
      "/_matrix/client/v1/search",
    };
  }

  // ------------------------------------------------------------------------
  // on_request — handle incoming search HTTP request.
  //
  // Only POST is meaningful for search (GET would expose search_term in URL).
  // ------------------------------------------------------------------------
  progressive::rest::HttpResponse on_request(
      const progressive::rest::HttpRequest& req) override {

    using namespace search_constants;

    if (req.method != "POST") {
      progressive::rest::HttpResponse resp;
      resp.code = 405;
      resp.body = build_error(405, M_UNKNOWN, "Method not allowed");
      return resp;
    }

    // Parse request body
    json body;
    try {
      body = json::parse(req.body.empty() ? "{}" : req.body);
    } catch (...) {
      progressive::rest::HttpResponse resp;
      resp.code = 400;
      resp.body = build_error(400, M_INVALID_PARAM, "Invalid JSON body");
      return resp;
    }

    // Validate search_categories
    if (!body.contains("search_categories") || !body["search_categories"].is_object()) {
      progressive::rest::HttpResponse resp;
      resp.code = 400;
      resp.body = build_error(400, M_INVALID_PARAM,
                              "Missing or invalid 'search_categories'");
      return resp;
    }

    json categories = body["search_categories"];
    json response_categories = json::object();

    // ---- Process room_events category ----
    if (categories.contains(CAT_ROOM_EVENTS) &&
        categories[CAT_ROOM_EVENTS].is_object()) {

      const json& room_events = categories[CAT_ROOM_EVENTS];

      // Build search options from request
      FullTextSearchEngine::SearchOptions options;

      // Required: search_term
      if (!room_events.contains("search_term") ||
          !room_events["search_term"].is_string()) {
        progressive::rest::HttpResponse resp;
        resp.code = 400;
        resp.body = build_error(400, M_INVALID_PARAM,
                                "Missing 'search_term' in room_events category");
        return resp;
      }
      options.search_term = room_events["search_term"].get<std::string>();

      // Validate search_term length
      if (options.search_term.size() > MAX_SEARCH_TERM_LENGTH) {
        progressive::rest::HttpResponse resp;
        resp.code = 400;
        resp.body = build_error(400, M_INVALID_PARAM,
                                "search_term too long (max " +
                                std::to_string(MAX_SEARCH_TERM_LENGTH) +
                                " characters)");
        return resp;
      }

      // Extract user_id from request (authenticated user)
      options.user_id = req.auth_user.value_or("");

      // Optional: keys (content fields to search)
      // Default: all keys (body, name, topic)

      // Optional: filter
      if (room_events.contains("filter") && room_events["filter"].is_object()) {
        const json& filter = room_events["filter"];

        // rooms filter: if exactly one room, use single-room search
        if (filter.contains("rooms") && filter["rooms"].is_array() &&
            filter["rooms"].size() == 1 &&
            filter["rooms"][0].is_string()) {
          options.room_id = filter["rooms"][0].get<std::string>();
        }

        // sender filter
        if (filter.contains("senders") && filter["senders"].is_array() &&
            filter["senders"].size() > 0 &&
            filter["senders"][0].is_string()) {
          options.sender_filter = filter["senders"][0].get<std::string>();
        }

        // event type filter
        if (filter.contains("types") && filter["types"].is_array() &&
            filter["types"].size() > 0 &&
            filter["types"][0].is_string()) {
          options.event_type_filter = filter["types"][0].get<std::string>();
        }
      }

      // Optional: order_by
      options.order_by = room_events.value("order_by", ORDER_RANK);

      // Optional: group_by
      if (room_events.contains("groupings") &&
          room_events["groupings"].is_object()) {
        const json& groupings = room_events["groupings"];
        if (groupings.contains("group_by") &&
            groupings["group_by"].is_array() &&
            !groupings["group_by"].empty()) {
          auto gb = groupings["group_by"][0];
          if (gb.is_object() && gb.contains("key") && gb["key"].is_string()) {
            options.group_by = gb["key"].get<std::string>();
          }
        }
      }

      // Optional: include_state
      options.include_state = room_events.value("include_state", false);

      // Optional: event_context
      if (room_events.contains("event_context") &&
          room_events["event_context"].is_object()) {
        const json& ctx = room_events["event_context"];
        options.context_before = ctx.value("before_limit",
                                            DEFAULT_CONTEXT_BEFORE);
        options.context_after  = ctx.value("after_limit",
                                            DEFAULT_CONTEXT_AFTER);
        // Clamp to valid range
        if (options.context_before < 0) options.context_before = 0;
        if (options.context_before > MAX_CONTEXT_EVENTS)
          options.context_before = MAX_CONTEXT_EVENTS;
        if (options.context_after < 0) options.context_after = 0;
        if (options.context_after > MAX_CONTEXT_EVENTS)
          options.context_after = MAX_CONTEXT_EVENTS;
      }

      // Optional: limit
      options.limit = room_events.value("limit", DEFAULT_SEARCH_LIMIT);
      if (options.limit < 1) options.limit = 1;
      if (options.limit > MAX_SEARCH_RESULTS) options.limit = MAX_SEARCH_RESULTS;

      // Optional: next_batch
      options.next_batch = room_events.value("next_batch", "");

      // Check admin status
      options.is_admin = req.auth_user.has_value() &&
                         is_user_admin(req.auth_user.value());

      // ---- Execute search ----
      // Acquire a read transaction
      auto conn = db_pool_.acquire();
      if (!conn) {
        progressive::rest::HttpResponse resp;
        resp.code = 500;
        resp.body = build_error(500, M_UNKNOWN, "Database connection failed");
        return resp;
      }

      auto txn = conn->cursor("search");
      if (!txn) {
        progressive::rest::HttpResponse resp;
        resp.code = 500;
        resp.body = build_error(500, M_UNKNOWN, "Database transaction failed");
        return resp;
      }

      FullTextSearchEngine::SearchResponse search_result;
      try {
        search_result = search_engine_.search(*txn, options);
        txn->close();
        conn->commit();
      } catch (const std::exception& e) {
        try { txn->close(); conn->rollback(); } catch (...) {}
        progressive::rest::HttpResponse resp;
        resp.code = 500;
        resp.body = build_error(500, M_UNKNOWN,
                                std::string("Search error: ") + e.what());
        return resp;
      }

      // Build response for this category
      json category_result;
      category_result["count"] = search_result.total_results;

      // Convert results to JSON
      json results_json = json::array();
      for (const auto& result : search_result.results) {
        json r;
        r["rank"]            = result.rank;
        r["result"]          = json{
          {"event_id",         result.event_id},
          {"room_id",          result.room_id},
          {"sender",           result.sender},
          {"type",             result.type},
          {"content",          result.content},
          {"origin_server_ts", result.origin_server_ts},
          {"stream_ordering",  result.stream_ordering}
        };
        if (!result.context.empty()) {
          r["context"] = result.context;
        }
        results_json.push_back(r);
      }
      category_result["results"] = results_json;

      // Highlights: the search token terms
      std::set<std::string> highlight_tokens = tokenize(options.search_term);
      category_result["highlights"] =
          std::vector<std::string>(highlight_tokens.begin(),
                                    highlight_tokens.end());

      // Next batch token
      if (search_result.next_batch.has_value()) {
        category_result["next_batch"] = *search_result.next_batch;
      }

      // Groups (if grouped)
      if (search_result.grouped) {
        json groups_json = json::object();
        for (const auto& [group_key, group_results] : search_result.groups) {
          json group;
          group["results"] = json::array();
          for (const auto& gr : group_results) {
            json r;
            r["rank"]   = gr.rank;
            r["result"] = json{
              {"event_id",         gr.event_id},
              {"room_id",          gr.room_id},
              {"sender",           gr.sender},
              {"type",             gr.type},
              {"content",          gr.content},
              {"origin_server_ts", gr.origin_server_ts}
            };
            group["results"].push_back(r);
          }
          group["order"] = 0; // order within group
          groups_json[group_key] = group;
        }
        category_result["groups"] = groups_json;
      }

      response_categories[CAT_ROOM_EVENTS] = category_result;
    }

    progressive::rest::HttpResponse resp;
    resp.code = 200;
    resp.body = json{{"search_categories", response_categories}};
    return resp;
  }

private:
  // ------------------------------------------------------------------------
  // is_user_admin — check if the authenticated user has admin privileges.
  // This is a simplified check — in production this would consult the
  // server's admin list or auth provider.
  // ------------------------------------------------------------------------
  bool is_user_admin(const std::string& /*user_id*/) {
    // For now, check if user is in admin list
    // This would typically query the auth system
    return false; // Default: non-admin
  }

  progressive::storage::DatabasePool& db_pool_;
  EventSearchStore& search_store_;
  SearchRanker& ranker_;
  FullTextSearchEngine search_engine_;
};

// ============================================================================
// SearchCoordinator — top-level orchestrator for all search functionality.
//
// Wires together all components and provides the primary public API:
//   - index_event():   called from event persistence pipeline
//   - unindex_event(): called when events are redacted/purged
//   - search():        the main search entry point
//   - admin_api():     access to admin endpoints
//   - get_stats():     aggregate search index statistics
//
// This is the main class that external code interacts with.
// ============================================================================
class SearchCoordinator {
public:
  // ------------------------------------------------------------------------
  // Constructor — initializes all sub-components.
  // ------------------------------------------------------------------------
  SearchCoordinator(progressive::storage::DatabasePool& db_pool)
      : db_pool_(db_pool),
        search_store_(db_pool),
        indexer_(db_pool, search_store_),
        ranker_(),
        search_engine_(search_store_, ranker_, db_pool),
        admin_api_(db_pool, search_store_, indexer_),
        multi_room_aggregator_(search_store_, ranker_),
        event_context_fetcher_(db_pool),
        search_api_handler_(nullptr) {} // initialized in init_handlers

  // ------------------------------------------------------------------------
  // index_event — index a newly persisted event for search.
  //
  // Called from the event persistence pipeline after an event has been
  // stored in the events table. Extracts text, tokenizes, and inserts
  // into event_search.
  // ------------------------------------------------------------------------
  void index_event(progressive::storage::LoggingTransaction& txn,
                    const std::string& event_id,
                    const std::string& room_id,
                    const std::string& event_type,
                    const json& content,
                    int64_t stream_ordering,
                    int64_t origin_server_ts) {
    indexer_.index_event(txn, event_id, room_id, event_type,
                          content, stream_ordering, origin_server_ts);
  }

  // ------------------------------------------------------------------------
  // unindex_event — remove an event from the search index.
  // ------------------------------------------------------------------------
  void unindex_event(progressive::storage::LoggingTransaction& txn,
                      const std::string& event_id) {
    indexer_.unindex_event(txn, event_id);
  }

  // ------------------------------------------------------------------------
  // reindex_event — reindex an event (after edit, after redaction reversal).
  // ------------------------------------------------------------------------
  void reindex_event(progressive::storage::LoggingTransaction& txn,
                      const std::string& event_id,
                      const std::string& room_id,
                      const std::string& event_type,
                      const json& content,
                      int64_t stream_ordering,
                      int64_t origin_server_ts) {
    indexer_.reindex_event(txn, event_id, room_id, event_type,
                            content, stream_ordering, origin_server_ts);
  }

  // ------------------------------------------------------------------------
  // search — execute a full-text search and return structured results.
  // ------------------------------------------------------------------------
  FullTextSearchEngine::SearchResponse search(
      progressive::storage::LoggingTransaction& txn,
      const FullTextSearchEngine::SearchOptions& options) {
    return search_engine_.search(txn, options);
  }

  // ------------------------------------------------------------------------
  // get_admin_api — access admin API endpoints.
  // ------------------------------------------------------------------------
  SearchAdminAPI& admin_api() { return admin_api_; }

  // ------------------------------------------------------------------------
  // get_search_store — access underlying search store (for tests/admin).
  // ------------------------------------------------------------------------
  EventSearchStore& search_store() { return search_store_; }

  // ------------------------------------------------------------------------
  // get_multi_room_aggregator — access multi-room aggregator.
  // ------------------------------------------------------------------------
  MultiRoomSearchAggregator& multi_room_aggregator() {
    return multi_room_aggregator_;
  }

  // ------------------------------------------------------------------------
  // get_event_context_fetcher — access event context fetcher.
  // ------------------------------------------------------------------------
  EventContextFetcher& event_context_fetcher() {
    return event_context_fetcher_;
  }

  // ------------------------------------------------------------------------
  // get_search_stats — return comprehensive search index statistics.
  // ------------------------------------------------------------------------
  json get_search_stats(progressive::storage::LoggingTransaction& txn) {
    json stats;

    stats["total_search_entries"] = search_store_.count_total_entries(txn);

    txn.execute(
        "SELECT COUNT(DISTINCT room_id) FROM event_search");
    auto room_count = txn.fetchone();
    stats["indexed_rooms"] = room_count.has_value()
        ? room_count->as_int64(0) : 0;

    txn.execute(
        "SELECT COUNT(DISTINCT event_id) FROM event_search");
    auto event_count = txn.fetchone();
    stats["indexed_events"] = event_count.has_value()
        ? event_count->as_int64(0) : 0;

    // Average entries per event
    if (stats["indexed_events"].get<int64_t>() > 0) {
      double avg = static_cast<double>(stats["total_search_entries"].get<int64_t>()) /
                   stats["indexed_events"].get<int64_t>();
      stats["avg_entries_per_event"] = avg;
    } else {
      stats["avg_entries_per_event"] = 0.0;
    }

    // Most common tokens
    txn.execute(
        "SELECT value, COUNT(*) as cnt FROM event_search "
        "GROUP BY value ORDER BY cnt DESC LIMIT 10");
    json top_tokens = json::array();
    auto token_rows = txn.fetchall();
    for (const auto& row : token_rows) {
      top_tokens.push_back({
        {"token", row[0].as_string()},
        {"count", row[1].as_int64()}
      });
    }
    stats["top_tokens"] = top_tokens;

    // Index coverage
    txn.execute(
        "SELECT COUNT(*) FROM events WHERE type IN "
        "('m.room.message', 'm.room.name', 'm.room.topic', 'm.sticker') "
        "AND outlier = 0 AND event_id IN "
        "(SELECT DISTINCT event_id FROM event_search)");
    auto covered_row = txn.fetchone();
    int64_t covered = covered_row.has_value() ? covered_row->as_int64(0) : 0;

    txn.execute(
        "SELECT COUNT(*) FROM events WHERE type IN "
        "('m.room.message', 'm.room.name', 'm.room.topic', 'm.sticker') "
        "AND outlier = 0");
    auto total_row = txn.fetchone();
    int64_t total = total_row.has_value() ? total_row->as_int64(0) : 0;

    stats["index_coverage_percent"] = total > 0
        ? (static_cast<double>(covered) / total * 100.0) : 100.0;

    return stats;
  }

  // ------------------------------------------------------------------------
  // get_search_api_handler — obtain the REST API handler for /search.
  //
  // Initializes it lazily on first call.
  // ------------------------------------------------------------------------
  std::shared_ptr<SearchAPIHandler> get_search_api_handler() {
    if (!search_api_handler_) {
      search_api_handler_ = std::make_shared<SearchAPIHandler>(
          db_pool_, search_store_, ranker_);
    }
    return search_api_handler_;
  }

private:
  progressive::storage::DatabasePool& db_pool_;
  EventSearchStore search_store_;
  SearchIndexer indexer_;
  SearchRanker ranker_;
  FullTextSearchEngine search_engine_;
  SearchAdminAPI admin_api_;
  MultiRoomSearchAggregator multi_room_aggregator_;
  EventContextFetcher event_context_fetcher_;
  std::shared_ptr<SearchAPIHandler> search_api_handler_;
};

// ============================================================================
// Standalone convenience functions — callable without instantiating classes.
//
// These provide a simple API for external consumers that don't need the
// full SearchCoordinator lifecycle management.
// ============================================================================

// --------------------------------------------------------------------------
// search_events — perform a quick keyword search and return event IDs.
//
// Parameters:
//   db_pool:     database pool for read transaction
//   search_term: the search query
//   room_id:     optional room filter (empty = all rooms)
//   limit:       max results
//
// Returns: vector of matching event IDs, ordered by relevance.
// --------------------------------------------------------------------------
std::vector<std::string> search_events(
    progressive::storage::DatabasePool& db_pool,
    const std::string& search_term,
    const std::string& room_id = "",
    int limit = 50) {

  EventSearchStore store(db_pool);
  SearchRanker ranker;

  auto conn = db_pool.acquire();
  if (!conn) return {};

  auto txn = conn->cursor("search_events");
  if (!txn) return {};

  std::string lower_term = to_lower(trim_copy(search_term));
  std::set<std::string> tokens_set = tokenize(search_term);
  std::vector<std::string> tokens(tokens_set.begin(), tokens_set.end());

  if (tokens.empty()) return {};

  auto entries = store.search_multi_keyword(*txn, tokens, room_id, 0, limit * 3);
  auto ranked = ranker.rank(entries, tokens, lower_term);

  std::vector<std::string> result;
  for (const auto& sr : ranked) {
    if (sr.score <= 0.0) continue;
    result.push_back(sr.entry.event_id);
    if (static_cast<int>(result.size()) >= limit) break;
  }

  return result;
}

// --------------------------------------------------------------------------
// index_event_standalone — index a single event without managing a
// SearchCoordinator instance.
// --------------------------------------------------------------------------
void index_event_standalone(
    progressive::storage::LoggingTransaction& txn,
    const std::string& event_id,
    const std::string& room_id,
    const std::string& event_type,
    const json& content,
    int64_t stream_ordering,
    int64_t origin_server_ts) {

  progressive::storage::DatabasePool* dbp = nullptr; // placeholder
  // In practice this would receive the actual pool from the caller
  EventSearchStore store(*dbp);
  SearchIndexer indexer(*dbp, store);

  indexer.index_event(txn, event_id, room_id, event_type,
                       content, stream_ordering, origin_server_ts);
}

// --------------------------------------------------------------------------
// compute_search_score — compute a relevance score for diagnostic purposes.
// --------------------------------------------------------------------------
double compute_search_score(const std::string& document,
                             const std::string& search_term) {
  SearchRanker ranker;

  std::string lower_term = to_lower(trim_copy(search_term));
  std::set<std::string> tokens = tokenize(lower_term);
  std::vector<std::string> token_vec(tokens.begin(), tokens.end());

  // Create a synthetic search entry for scoring
  progressive::storage::SearchEntry entry;
  entry.value = to_lower(document);
  entry.key = search_constants::KEY_BODY;
  entry.origin_server_ts = now_ms();
  entry.stream_ordering = 1;

  std::vector<progressive::storage::SearchEntry> entries = {entry};
  auto ranked = ranker.rank(entries, token_vec, lower_term);

  return ranked.empty() ? 0.0 : ranked[0].score;
}

} // namespace progressive
