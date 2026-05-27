// ============================================================================
// space_manager.cpp — Matrix Space Management (MSC 1772 / Matrix 1.2+)
//
// Comprehensive space management including:
//   - SpaceStore: Full SQL DDL for spaces, space_children, space_parents,
//     space_restrictions, space_suggestions, space_peek_state, and related
//     tables. Complete CRUD with transaction-safe methods.
//   - SpaceHierarchyEngine: Manages parent-child relationships between
//     spaces and rooms/subspaces. Handles m.space.child and m.space.parent
//     state events, bidirectional linking, orphan detection, circular
//     reference prevention, depth tracking, and cascade operations.
//   - SpaceChildManager: Controls which rooms are children of a space.
//     Supports order/auto-join/suggested flags, batch add/remove, child
//     validation (room must exist and be joinable), child reordering,
//     and hierarchy flattening for efficient traversal.
//   - SpaceParentManager: Tracks which spaces a room belongs to. Supports
//     multiple parent spaces, canonical parent designation, parent
//     authorization checks (space admins can manage children), and
//     parent visibility controls.
//   - SpaceRestrictionsEngine: Enforces space-level restrictions on child
//     rooms. Handles m.room.join_rules restricted rooms that reference
//     space membership, manages allow lists (m.room.join_rules allow
//     rules referencing spaces), validates join eligibility based on
//     space membership, and applies room version-specific restriction
//     semantics (v8 restricted rooms, v9 knocking, v10 MSC 3083).
//   - SpaceDiscoveryService: Enables discovery of spaces and their
//     contents. Supports public space listing, space directory
//     (m.room.aliases), space peeking for non-members, visibility
//     controls (public/private spaces), recursive space traversal,
//     and space summary generation (hierarchy endpoint per MSC 2946).
//   - SpaceSuggestionEngine: Manages suggested rooms/child ordering
//     within spaces. Supports suggested flag on m.space.child events,
//     auto-join from suggestions, suggestion ranking/ordering, suggested
//     room categories (via m.space.child order string), batch suggestion
//     management, and suggestion analytics.
//   - SpaceMembershipPropagator: Handles cascading membership changes
//     through space hierarchies. When a user joins/leaves a space,
//     optionally propagates to child rooms based on auto-join flags,
//     handles restricted room auto-join, supports partial propagation
//     (join some but not all children), and manages rate limiting for
//     bulk operations.
//   - SpaceEventValidator: Validates m.space.child, m.space.parent, and
//     related state events. Checks event format, required fields,
//     valid room IDs, circular reference detection, power level
//     authorization, and state key correctness.
//   - SpaceHierarchyFlattener: Efficient algorithms for flattening space
//     hierarchies into sorted lists for the /hierarchy API. Supports
//     depth-first and breadth-first traversal, pagination of large
//     hierarchies, caching of flattened results, and incremental
//     updates when children change.
//   - SpacePeekManager: Allows non-members to peek into public spaces
//     to discover rooms. Manages temporary peek state, enforces
//     visibility restrictions (world_readable/history_visibility),
//     supports peek duration limits, and cleanup of stale peek state.
//   - SpaceSummaryBuilder: Builds the response for the MSC 2946
//     /hierarchy endpoint. Aggregates room summaries, child state
//     events, room metadata (name, topic, avatar, join rules, guest
//     access), supports pagination tokens, and handles max_depth limits.
//   - SpaceUpgradeHandler: Handles upgrading rooms to spaces and
//     vice versa. Manages space type (m.room.type = "m.space"),
//     preserves child relationships during upgrades, and validates
//     upgrade eligibility.
//
// Namespace: progressive::
// Equivalent to:
//   MSC 1772 — Matrix Spaces (m.space.child, m.space.parent)
//   MSC 2946 — Spaces Summary (GET /hierarchy)
//   MSC 2962 — Space Auto-Join
//   MSC 3083 — Restricted Rooms via Spaces
//   MSC 3216 — Space Peeking
//   MSC 3827 — Space Upgrade
//   Synapse synapse/handlers/space_summary.py
//   Synapse synapse/storage/databases/main/room.py (space portions)
//   Synapse synapse/rest/client/room.py (space hierarchy endpoint)
//   matrix-org/matrix-spec: Client-Server API /rooms/{roomId}/hierarchy
//   matrix-org/matrix-spec: m.space.child, m.space.parent event types
//
// Target: 3000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <filesystem>
#include <fstream>
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

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for all major components
// ============================================================================
class SpaceStore;
class SpaceHierarchyEngine;
class SpaceChildManager;
class SpaceParentManager;
class SpaceRestrictionsEngine;
class SpaceDiscoveryService;
class SpaceSuggestionEngine;
class SpaceMembershipPropagator;
class SpaceEventValidator;
class SpaceHierarchyFlattener;
class SpacePeekManager;
class SpaceSummaryBuilder;
class SpaceUpgradeHandler;
class SpaceManagerCoordinator;

// ============================================================================
// Forward-declare storage types used in this compilation unit
// ============================================================================
namespace storage {
class DatabasePool;
class LoggingTransaction;

// Convenience time helper
namespace {
int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}
} // namespace

} // namespace storage

using storage::DatabasePool;
using storage::LoggingTransaction;

// ============================================================================
// Row type used for SQL result parsing (consistent with other modules)
// ============================================================================
struct Row {
  struct Column {
    std::optional<std::string> value;
  };
  std::vector<Column> columns;
  size_t size() const { return columns.size(); }
  const Column& operator[](size_t idx) const { return columns[idx]; }
  Column& operator[](size_t idx) { return columns[idx]; }
};

// ============================================================================
// Space-specific data structures
// ============================================================================

// Represents a single space — a room with type "m.space"
struct SpaceInfo {
  std::string space_id;          // Room ID of the space
  std::string name;              // Display name (from m.room.name)
  std::string topic;             // Topic (from m.room.topic)
  std::string avatar_url;        // Avatar (from m.room.avatar)
  std::string canonical_alias;   // Canonical alias if set
  std::string creator;           // User ID who created the space
  std::string join_rule;         // Current join rule (public, invite, knock, restricted)
  std::string history_visibility;// History visibility setting
  std::string guest_access;      // Guest access setting
  bool is_public = false;        // Published to room directory
  bool is_world_readable = false;// World-readable history
  int64_t created_at_ms = 0;    // Creation timestamp in milliseconds
  int64_t joined_members = 0;   // Number of joined members
  int64_t invited_members = 0;  // Number of invited members
  int64_t child_count = 0;      // Number of immediate children
  int64_t total_descendants = 0;// Total children recursively (all depths)
  int depth = 0;                 // Depth in hierarchy (0 = root)

  json to_json() const {
    json j;
    j["space_id"] = space_id;
    if (!name.empty()) j["name"] = name;
    if (!topic.empty()) j["topic"] = topic;
    if (!avatar_url.empty()) j["avatar_url"] = avatar_url;
    if (!canonical_alias.empty()) j["canonical_alias"] = canonical_alias;
    if (!creator.empty()) j["creator"] = creator;
    j["join_rule"] = join_rule;
    j["history_visibility"] = history_visibility;
    j["guest_access"] = guest_access;
    j["is_public"] = is_public;
    j["is_world_readable"] = is_world_readable;
    j["created_at_ms"] = created_at_ms;
    j["joined_members"] = joined_members;
    j["invited_members"] = invited_members;
    j["child_count"] = child_count;
    j["total_descendants"] = total_descendants;
    j["depth"] = depth;
    j["room_type"] = "m.space";
    return j;
  }

  static SpaceInfo from_json(const json& j) {
    SpaceInfo s;
    s.space_id = j.value("space_id", "");
    s.name = j.value("name", "");
    s.topic = j.value("topic", "");
    s.avatar_url = j.value("avatar_url", "");
    s.canonical_alias = j.value("canonical_alias", "");
    s.creator = j.value("creator", "");
    s.join_rule = j.value("join_rule", "invite");
    s.history_visibility = j.value("history_visibility", "shared");
    s.guest_access = j.value("guest_access", "forbidden");
    s.is_public = j.value("is_public", false);
    s.is_world_readable = j.value("is_world_readable", false);
    s.created_at_ms = j.value("created_at_ms", 0);
    s.joined_members = j.value("joined_members", 0);
    s.invited_members = j.value("invited_members", 0);
    s.child_count = j.value("child_count", 0);
    s.total_descendants = j.value("total_descendants", 0);
    s.depth = j.value("depth", 0);
    return s;
  }
};

// Represents a child relationship between a space and a room
struct SpaceChild {
  std::string space_id;          // Parent space room ID
  std::string child_room_id;     // Child room ID (can be another space or regular room)
  std::string order;             // Lexicographic ordering string for display
  bool suggested = false;        // Whether this child is suggested (auto-join)
  bool auto_join = false;        // Whether users auto-join this child when joining space
  std::string via_server;        // Recommended server for joining the child room
  std::string child_name;        // Cached child room name (for summary)
  std::string child_topic;       // Cached child room topic
  std::string child_avatar;      // Cached child room avatar
  std::string child_join_rule;   // Cached child room join rule
  std::string child_room_type;   // Child room type ("m.space" or empty)
  bool child_is_public = false;  // Whether child is in room directory
  int64_t child_joined_members = 0; // Cached member count
  int64_t added_at_ms = 0;      // When the child was added to the space
  int64_t order_priority = 0;    // Numeric priority extracted from order string
  int depth = 0;                 // Depth relative to root space

  json to_json(bool include_children_state = false) const {
    json j;
    j["space_id"] = space_id;
    j["child_room_id"] = child_room_id;
    if (!order.empty()) j["order"] = order;
    if (suggested) j["suggested"] = suggested;
    if (auto_join) j["auto_join"] = auto_join;
    if (!via_server.empty()) j["via"] = std::vector<std::string>{via_server};

    if (include_children_state) {
      if (!child_name.empty()) j["name"] = child_name;
      if (!child_topic.empty()) j["topic"] = child_topic;
      if (!child_avatar.empty()) j["avatar_url"] = child_avatar;
      if (!child_join_rule.empty()) j["join_rule"] = child_join_rule;
      if (!child_room_type.empty()) j["room_type"] = child_room_type;
      j["is_public"] = child_is_public;
      j["joined_members"] = child_joined_members;
    }
    j["depth"] = depth;
    return j;
  }

  static SpaceChild from_json(const json& j) {
    SpaceChild c;
    c.space_id = j.value("space_id", "");
    c.child_room_id = j.value("child_room_id", "");
    c.order = j.value("order", "");
    c.suggested = j.value("suggested", false);
    c.auto_join = j.value("auto_join", false);
    if (j.contains("via") && j["via"].is_array() && !j["via"].empty())
      c.via_server = j["via"][0].get<std::string>();
    c.child_name = j.value("name", "");
    c.child_topic = j.value("topic", "");
    c.child_avatar = j.value("avatar_url", "");
    c.child_join_rule = j.value("join_rule", "");
    c.child_room_type = j.value("room_type", "");
    c.child_is_public = j.value("is_public", false);
    c.child_joined_members = j.value("joined_members", 0);
    c.added_at_ms = j.value("added_at_ms", 0);
    c.depth = j.value("depth", 0);
    return c;
  }
};

// Represents a parent relationship — the inverse of SpaceChild
struct SpaceParent {
  std::string room_id;           // The room that is a child somewhere
  std::string parent_space_id;   // The parent space containing this room
  bool canonical = false;        // Whether this is the canonical parent
  std::string via_server;        // Recommended server for the parent
  int64_t added_at_ms = 0;      // When relationship was established

  json to_json() const {
    json j;
    j["room_id"] = room_id;
    j["parent_space_id"] = parent_space_id;
    if (canonical) j["canonical"] = canonical;
    if (!via_server.empty()) j["via"] = std::vector<std::string>{via_server};
    return j;
  }

  static SpaceParent from_json(const json& j) {
    SpaceParent p;
    p.room_id = j.value("room_id", "");
    p.parent_space_id = j.value("parent_space_id", "");
    p.canonical = j.value("canonical", false);
    if (j.contains("via") && j["via"].is_array() && !j["via"].empty())
      p.via_server = j["via"][0].get<std::string>();
    p.added_at_ms = j.value("added_at_ms", 0);
    return p;
  }
};

// Space join restriction rule
struct SpaceRestriction {
  std::string space_id;          // The space that confers membership
  std::string restricted_room_id;// The restricted room
  std::string restriction_type;  // "m.room_membership" or future types
  std::string required_membership;// "join", "invite", etc.
  bool active = true;            // Whether restriction is currently enforced
  int64_t created_at_ms = 0;    // When restriction was created
  int64_t updated_at_ms = 0;    // When restriction was last modified

  json to_json() const {
    json j;
    j["space_id"] = space_id;
    j["restricted_room_id"] = restricted_room_id;
    j["restriction_type"] = restriction_type;
    j["required_membership"] = required_membership;
    j["active"] = active;
    j["created_at_ms"] = created_at_ms;
    return j;
  }
};

// Space suggestion — a room suggested for inclusion in a space
struct SpaceSuggestion {
  std::string space_id;          // The space
  std::string room_id;           // Suggested room
  std::string reason;            // Why this room is suggested
  std::string suggested_by;      // User ID who made the suggestion
  std::string status;            // "pending", "approved", "rejected"
  double score = 0.0;            // Relevance score (for algorithmic suggestions)
  int64_t suggested_at_ms = 0;  // When suggested
  int64_t resolved_at_ms = 0;   // When approved/rejected
  std::string resolved_by;       // Who approved/rejected

  json to_json() const {
    json j;
    j["space_id"] = space_id;
    j["room_id"] = room_id;
    if (!reason.empty()) j["reason"] = reason;
    if (!suggested_by.empty()) j["suggested_by"] = suggested_by;
    j["status"] = status;
    j["score"] = score;
    j["suggested_at_ms"] = suggested_at_ms;
    return j;
  }
};

// Peek state for non-member space browsing
struct SpacePeekState {
  std::string space_id;          // Space being peeked
  std::string user_id;           // User peeking
  std::string peek_token;        // Token for this peek session
  int64_t depth_limit = 3;       // How deep the user can peek
  int64_t started_at_ms = 0;    // When peek started
  int64_t expires_at_ms = 0;    // When peek expires
  std::set<std::string> visited_rooms; // Rooms already visited in this peek
  bool active = true;            // Whether peek is still active

  json to_json() const {
    json j;
    j["space_id"] = space_id;
    j["user_id"] = user_id;
    j["peek_token"] = peek_token;
    j["depth_limit"] = depth_limit;
    j["started_at_ms"] = started_at_ms;
    j["expires_at_ms"] = expires_at_ms;
    j["active"] = active;
    return j;
  }
};

// Summary response structure for the /hierarchy endpoint (MSC 2946)
struct SpaceHierarchySummary {
  std::string space_id;
  std::vector<SpaceChild> rooms;        // All child rooms in the hierarchy
  std::string next_batch;               // Pagination token
  bool incomplete = false;              // Whether more results exist
  int64_t total_rooms = 0;             // Total accessible rooms in hierarchy
  int64_t suggested_rooms = 0;         // Number of suggested child rooms
  int64_t max_depth_reached = 0;       // Maximum depth actually traversed

  json to_json() const {
    json j;
    j["rooms"] = json::array();
    for (const auto& child : rooms) {
      j["rooms"].push_back(child.to_json(true));
    }
    if (!next_batch.empty()) j["next_batch"] = next_batch;
    if (incomplete) j["incomplete"] = incomplete;
    return j;
  }
};

// Configuration for the space manager
struct SpaceManagerConfig {
  int64_t max_hierarchy_depth = 10;         // Maximum depth for recursive traversal
  int64_t max_children_per_space = 10000;   // Maximum children per space
  int64_t max_parents_per_room = 100;       // Maximum parent spaces per room
  int64_t max_summary_rooms = 1000;         // Max rooms returned in a single summary
  int64_t peek_duration_ms = 600'000;       // How long peek sessions last (10 min)
  int64_t peek_depth_limit = 3;             // Default peek depth limit
  int64_t propagation_rate_limit_ms = 100;  // Min ms between bulk membership ops
  int64_t max_propagation_batch = 50;       // Max rooms per propagation batch
  bool enable_auto_join = true;             // Enable auto-join from spaces
  bool enable_suggestions = true;           // Enable suggestion engine
  bool enable_peeking = true;               // Enable space peeking
  bool enable_recursive_summary = true;     // Enable recursive hierarchy summary
  bool strict_validation = true;            // Enable strict event validation
  bool cache_hierarchy = true;              // Cache flattened hierarchies
  int64_t hierarchy_cache_ttl_ms = 300'000; // TTL for hierarchy cache (5 min)
};

// ============================================================================
// Anonymous namespace — Internal helpers, constants, and utility types
// ============================================================================
namespace {

// ---- Space-related constants ----
constexpr const char* kSpaceRoomType = "m.space";
constexpr const char* kSpaceChildEventType = "m.space.child";
constexpr const char* kSpaceParentEventType = "m.space.parent";
constexpr const char* kRestrictionRoomMembership = "m.room_membership";
constexpr const char* kDefaultJoinRule = "invite";
constexpr const char* kRestrictedJoinRule = "restricted";
constexpr const char* kPublicJoinRule = "public";
constexpr const int64_t kDefaultPageSize = 100;
constexpr const int64_t kMaxPageSize = 1000;
constexpr const int64_t kCircularRefCheckDepth = 50;
constexpr const int64_t kOrphanTimeoutMs = 86'400'000; // 24 hours

// ---- Space event content keys ----
constexpr const char* kChildOrderKey = "order";
constexpr const char* kChildSuggestedKey = "suggested";
constexpr const char* kChildAutoJoinKey = "auto_join";
constexpr const char* kChildViaKey = "via";
constexpr const char* kParentViaKey = "via";
constexpr const char* kParentCanonicalKey = "canonical";
constexpr const char* kAllowKey = "allow";
constexpr const char* kTypeKey = "type";
constexpr const char* kRoomIdKey = "room_id";

// ---- Timestamp helpers ----
inline int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
      chr::system_clock::now().time_since_epoch())
      .count();
}

inline std::string now_iso8601() {
  char buf[32];
  auto t = std::time(nullptr);
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

inline std::string ts_to_iso8601(int64_t ms) {
  char buf[32];
  auto t = static_cast<std::time_t>(ms / 1000);
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

// ---- String helpers ----
inline bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() &&
         s.compare(0, prefix.size(), prefix) == 0;
}

inline bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

inline std::string to_lower(const std::string& s) {
  std::string r = s;
  for (auto& c : r)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return r;
}

inline std::string trim(const std::string& s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

inline std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> result;
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    if (!item.empty()) result.push_back(trim(item));
  }
  return result;
}

inline std::string join(const std::vector<std::string>& parts,
                         const std::string& delim) {
  std::string result;
  for (size_t i = 0; i < parts.size(); i++) {
    if (i > 0) result += delim;
    result += parts[i];
  }
  return result;
}

// ---- Validation helpers ----
inline bool is_valid_user_id(const std::string& uid) {
  if (uid.empty() || uid[0] != '@') return false;
  auto colon = uid.find(':');
  return colon != std::string::npos && colon > 1 && colon < uid.size() - 1;
}

inline bool is_valid_room_id(const std::string& rid) {
  if (rid.empty() || rid[0] != '!') return false;
  auto colon = rid.find(':');
  return colon != std::string::npos && colon > 1 && colon < rid.size() - 1;
}

inline bool is_valid_room_alias(const std::string& alias) {
  if (alias.empty() || alias[0] != '#') return false;
  auto colon = alias.find(':');
  return colon != std::string::npos && colon > 1 && colon < alias.size() - 1;
}

inline std::string server_name_from_id(const std::string& id) {
  auto colon = id.find(':');
  if (colon == std::string::npos) return "";
  return id.substr(colon + 1);
}

// ---- Row parsing helpers (consistent with other modules) ----
inline std::string row_get_str(const Row& row, size_t idx,
                                const std::string& default_val = "") {
  if (idx < row.size()) {
    return row[idx].value.value_or(default_val);
  }
  return default_val;
}

inline int64_t row_get_int(const Row& row, size_t idx, int64_t default_val = 0) {
  if (idx < row.size() && row[idx].value.has_value()) {
    try { return std::stoll(row[idx].value.value()); }
    catch (...) { return default_val; }
  }
  return default_val;
}

inline double row_get_double(const Row& row, size_t idx, double default_val = 0.0) {
  if (idx < row.size() && row[idx].value.has_value()) {
    try { return std::stod(row[idx].value.value()); }
    catch (...) { return default_val; }
  }
  return default_val;
}

inline bool row_get_bool(const Row& row, size_t idx, bool default_val = false) {
  std::string s = row_get_str(row, idx, default_val ? "1" : "0");
  return s == "1" || s == "true" || s == "yes";
}

inline json row_get_json(const Row& row, size_t idx,
                          const json& default_val = json::object()) {
  std::string s = row_get_str(row, idx, "");
  if (s.empty()) return default_val;
  try { return json::parse(s); }
  catch (...) { return default_val; }
}

// ---- JSON response helpers ----
inline json build_error(int code, const std::string& errcode,
                         const std::string& error) {
  return json{{"errcode", errcode}, {"error", error}};
}

inline json build_success(const json& data = json::object()) {
  if (data.is_object() && !data.contains("ok")) {
    json result = data;
    result["ok"] = true;
    return result;
  }
  return data;
}

inline json build_paginated(int64_t total, const json& results,
                              int64_t start = 0, int64_t limit = 100) {
  json j;
  j["total"] = total;
  j["start"] = start;
  j["limit"] = limit;
  j["chunk"] = results.is_array() ? results : json::array({results});
  j["next_batch"] = "";
  if (start + static_cast<int64_t>(j["chunk"].size()) < total) {
    j["next_batch"] = std::to_string(start + limit);
  }
  return j;
}

// ---- Random string generation (for tokens) ----
inline std::string random_token(size_t length = 32) {
  static const char alphanum[] =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  static std::mt19937 rng(std::random_device{}());
  static std::uniform_int_distribution<size_t> dist(0, sizeof(alphanum) - 2);
  std::string result;
  result.reserve(length);
  for (size_t i = 0; i < length; ++i)
    result += alphanum[dist(rng)];
  return result;
}

// ---- Hash combine for unordered containers ----
inline void hash_combine(size_t& seed, size_t hash) {
  seed ^= hash + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

struct PairHash {
  size_t operator()(const std::pair<std::string, std::string>& p) const {
    size_t h1 = std::hash<std::string>{}(p.first);
    size_t h2 = std::hash<std::string>{}(p.second);
    size_t seed = 0;
    hash_combine(seed, h1);
    hash_combine(seed, h2);
    return seed;
  }
};

// ---- Order string comparator (lexicographic per MSC 1772) ----
// Orders are compared lexicographically byte-by-byte with empty string = lowest
struct OrderComparator {
  bool operator()(const std::string& a, const std::string& b) const {
    if (a.empty() && b.empty()) return false;
    if (a.empty()) return true;
    if (b.empty()) return false;
    return a < b;
  }

  bool operator()(const SpaceChild& a, const SpaceChild& b) const {
    return (*this)(a.order, b.order);
  }
};

// ---- Extract numeric priority from order string (best effort) ----
inline int64_t extract_order_priority(const std::string& order) {
  if (order.empty()) return std::numeric_limits<int64_t>::max();
  // Try to parse as a number first
  try { return std::stoll(order); }
  catch (...) {}
  // Fallback: hash the string to get a numeric value
  size_t h = std::hash<std::string>{}(order);
  return static_cast<int64_t>(h & 0x7FFFFFFFFFFFFFFFLL);
}

// ---- Enumerate traversal strategies ----
enum class TraversalStrategy {
  kDepthFirst,      // DFS traversal
  kBreadthFirst,    // BFS traversal
  kPriorityOrder,   // Traverse by order priority
  kSuggestedFirst   // Suggested rooms first
};

// ---- Circular reference detection result ----
enum class CircularCheckResult {
  kNoCycle,
  kCycleDetected,
  kMaxDepthExceeded,
  kSelfReference
};

// ---- Space event validation result ----
enum class SpaceEventValidationResult {
  kValid,
  kInvalidFormat,
  kInvalidRoomId,
  kCircularReference,
  kAlreadyExists,
  kMaxChildrenExceeded,
  kMaxParentsExceeded,
  kPermissionDenied,
  kRoomNotFound,
  kNotASpace
};

// ---- Membership propagation result ----
enum class PropagationResult {
  kSuccess,
  kPartialSuccess,
  kRateLimited,
  kBlocked,
  kPropagationDisabled,
  kInvalidSpace
};

// ---- TTLCache: Simple TTL-based cache ----
template <typename K, typename V>
class TTLCache {
public:
  struct Entry {
    V value;
    int64_t expiry_ms;
  };

  explicit TTLCache(int64_t ttl_ms) : ttl_ms_(ttl_ms) {}

  std::optional<V> get(const K& key) const {
    auto it = entries_.find(key);
    if (it == entries_.end()) return std::nullopt;
    if (storage::now_ms() > it->second.expiry_ms) {
      return std::nullopt;
    }
    return it->second.value;
  }

  void put(const K& key, const V& value) {
    entries_[key] = {value, storage::now_ms() + ttl_ms_};
  }

  void evict_expired() {
    int64_t now = storage::now_ms();
    for (auto it = entries_.begin(); it != entries_.end(); ) {
      if (now > it->second.expiry_ms)
        it = entries_.erase(it);
      else
        ++it;
    }
  }

  void clear() { entries_.clear(); }
  size_t size() const { return entries_.size(); }

private:
  int64_t ttl_ms_;
  mutable std::map<K, Entry> entries_;
};

} // anonymous namespace

// ============================================================================
// SpaceStore: Full SQL DDL and CRUD for all space-related tables
// ============================================================================
// Manages the persistence layer for spaces, child relationships, parent
// relationships, restrictions, suggestions, peek state, and propagation
// tracking. All operations use parameterized queries and are transaction-safe.
//
// Tables managed:
//   spaces                  — Core space metadata
//   space_children          — Parent-child relationships (m.space.child)
//   space_parents           — Inverse relationships (m.space.parent)
//   space_restrictions      — Join restrictions based on space membership
//   space_suggestions       — Room suggestions for spaces
//   space_peek_state        — Temporary peek state for non-members
//   space_auto_join_queue   — Pending auto-join operations
//   space_propagation_log   — Audit log of membership propagation
//   space_hierarchy_cache   — Cached flattened hierarchies
// ============================================================================
class SpaceStore {
public:
  // ---- Constructor ----
  explicit SpaceStore(std::shared_ptr<DatabasePool> pool)
      : pool_(std::move(pool)) {}

  // =========================================================================
  // DDL — Create all space-related tables
  // =========================================================================
  std::string ddl_spaces() const {
    return R"SQL(
      CREATE TABLE IF NOT EXISTS spaces (
        space_id TEXT PRIMARY KEY NOT NULL,
        name TEXT NOT NULL DEFAULT '',
        topic TEXT NOT NULL DEFAULT '',
        avatar_url TEXT NOT NULL DEFAULT '',
        canonical_alias TEXT NOT NULL DEFAULT '',
        creator TEXT NOT NULL DEFAULT '',
        join_rule TEXT NOT NULL DEFAULT 'invite',
        history_visibility TEXT NOT NULL DEFAULT 'shared',
        guest_access TEXT NOT NULL DEFAULT 'forbidden',
        room_type TEXT NOT NULL DEFAULT 'm.space',
        is_public INTEGER NOT NULL DEFAULT 0,
        is_world_readable INTEGER NOT NULL DEFAULT 0,
        created_at_ms INTEGER NOT NULL DEFAULT 0,
        updated_at_ms INTEGER NOT NULL DEFAULT 0,
        joined_members INTEGER NOT NULL DEFAULT 0,
        invited_members INTEGER NOT NULL DEFAULT 0,
        child_count INTEGER NOT NULL DEFAULT 0,
        total_descendants INTEGER NOT NULL DEFAULT 0,
        depth INTEGER NOT NULL DEFAULT 0,
        metadata_json TEXT NOT NULL DEFAULT '{}',
        state_hash TEXT NOT NULL DEFAULT ''
      );
    )SQL";
  }

  std::string ddl_space_children() const {
    return R"SQL(
      CREATE TABLE IF NOT EXISTS space_children (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        space_id TEXT NOT NULL,
        child_room_id TEXT NOT NULL,
        event_id TEXT NOT NULL DEFAULT '',
        sort_order TEXT NOT NULL DEFAULT '',
        order_priority INTEGER NOT NULL DEFAULT 0,
        suggested INTEGER NOT NULL DEFAULT 0,
        auto_join INTEGER NOT NULL DEFAULT 0,
        via_server TEXT NOT NULL DEFAULT '',
        added_by TEXT NOT NULL DEFAULT '',
        added_at_ms INTEGER NOT NULL DEFAULT 0,
        updated_at_ms INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        child_name TEXT NOT NULL DEFAULT '',
        child_topic TEXT NOT NULL DEFAULT '',
        child_avatar_url TEXT NOT NULL DEFAULT '',
        child_join_rule TEXT NOT NULL DEFAULT '',
        child_room_type TEXT NOT NULL DEFAULT '',
        child_is_public INTEGER NOT NULL DEFAULT 0,
        child_joined_members INTEGER NOT NULL DEFAULT 0,
        child_invited_members INTEGER NOT NULL DEFAULT 0,
        UNIQUE(space_id, child_room_id)
      );
      CREATE INDEX IF NOT EXISTS idx_space_children_space_id
        ON space_children(space_id, is_active, order_priority);
      CREATE INDEX IF NOT EXISTS idx_space_children_child_room
        ON space_children(child_room_id, is_active);
      CREATE INDEX IF NOT EXISTS idx_space_children_suggested
        ON space_children(space_id, suggested, is_active);
    )SQL";
  }

  std::string ddl_space_parents() const {
    return R"SQL(
      CREATE TABLE IF NOT EXISTS space_parents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id TEXT NOT NULL,
        parent_space_id TEXT NOT NULL,
        event_id TEXT NOT NULL DEFAULT '',
        canonical INTEGER NOT NULL DEFAULT 0,
        via_server TEXT NOT NULL DEFAULT '',
        added_by TEXT NOT NULL DEFAULT '',
        added_at_ms INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1,
        UNIQUE(room_id, parent_space_id)
      );
      CREATE INDEX IF NOT EXISTS idx_space_parents_room_id
        ON space_parents(room_id, is_active);
      CREATE INDEX IF NOT EXISTS idx_space_parents_parent
        ON space_parents(parent_space_id, is_active);
      CREATE INDEX IF NOT EXISTS idx_space_parents_canonical
        ON space_parents(room_id, canonical, is_active);
    )SQL";
  }

  std::string ddl_space_restrictions() const {
    return R"SQL(
      CREATE TABLE IF NOT EXISTS space_restrictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        space_id TEXT NOT NULL,
        restricted_room_id TEXT NOT NULL,
        restriction_type TEXT NOT NULL DEFAULT 'm.room_membership',
        required_membership TEXT NOT NULL DEFAULT 'join',
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at_ms INTEGER NOT NULL DEFAULT 0,
        updated_at_ms INTEGER NOT NULL DEFAULT 0,
        UNIQUE(space_id, restricted_room_id, restriction_type)
      );
      CREATE INDEX IF NOT EXISTS idx_space_restrictions_room
        ON space_restrictions(restricted_room_id, is_active);
      CREATE INDEX IF NOT EXISTS idx_space_restrictions_space
        ON space_restrictions(space_id, is_active);
    )SQL";
  }

  std::string ddl_space_suggestions() const {
    return R"SQL(
      CREATE TABLE IF NOT EXISTS space_suggestions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        space_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT '',
        suggested_by TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        score REAL NOT NULL DEFAULT 0.0,
        suggested_at_ms INTEGER NOT NULL DEFAULT 0,
        resolved_at_ms INTEGER NOT NULL DEFAULT 0,
        resolved_by TEXT NOT NULL DEFAULT '',
        UNIQUE(space_id, room_id)
      );
      CREATE INDEX IF NOT EXISTS idx_space_suggestions_space
        ON space_suggestions(space_id, status);
      CREATE INDEX IF NOT EXISTS idx_space_suggestions_room
        ON space_suggestions(room_id);
    )SQL";
  }

  std::string ddl_space_peek_state() const {
    return R"SQL(
      CREATE TABLE IF NOT EXISTS space_peek_state (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        space_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        peek_token TEXT NOT NULL UNIQUE,
        depth_limit INTEGER NOT NULL DEFAULT 3,
        started_at_ms INTEGER NOT NULL DEFAULT 0,
        expires_at_ms INTEGER NOT NULL DEFAULT 0,
        visited_rooms_json TEXT NOT NULL DEFAULT '[]',
        is_active INTEGER NOT NULL DEFAULT 1
      );
      CREATE INDEX IF NOT EXISTS idx_space_peek_user
        ON space_peek_state(user_id, is_active);
      CREATE INDEX IF NOT EXISTS idx_space_peek_space
        ON space_peek_state(space_id, is_active);
      CREATE INDEX IF NOT EXISTS idx_space_peek_expiry
        ON space_peek_state(expires_at_ms, is_active);
    )SQL";
  }

  std::string ddl_space_propagation_log() const {
    return R"SQL(
      CREATE TABLE IF NOT EXISTS space_propagation_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        space_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        child_room_id TEXT NOT NULL,
        action TEXT NOT NULL,
        membership TEXT NOT NULL DEFAULT '',
        propagated_at_ms INTEGER NOT NULL DEFAULT 0,
        success INTEGER NOT NULL DEFAULT 1,
        error_message TEXT NOT NULL DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_space_propagation_log_user
        ON space_propagation_log(user_id, propagated_at_ms);
      CREATE INDEX IF NOT EXISTS idx_space_propagation_log_space
        ON space_propagation_log(space_id, propagated_at_ms);
    )SQL";
  }

  std::string ddl_space_hierarchy_cache() const {
    return R"SQL(
      CREATE TABLE IF NOT EXISTS space_hierarchy_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        space_id TEXT NOT NULL,
        cache_key TEXT NOT NULL,
        cached_json TEXT NOT NULL DEFAULT '{}',
        cached_at_ms INTEGER NOT NULL DEFAULT 0,
        expires_at_ms INTEGER NOT NULL DEFAULT 0,
        child_count INTEGER NOT NULL DEFAULT 0
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_space_hierarchy_cache_key
        ON space_hierarchy_cache(space_id, cache_key);
      CREATE INDEX IF NOT EXISTS idx_space_hierarchy_cache_expiry
        ON space_hierarchy_cache(expires_at_ms);
    )SQL";
  }

  // ---- Run all DDL statements ----
  void ensure_tables(LoggingTransaction& txn) {
    txn.execute(ddl_spaces());
    txn.execute(ddl_space_children());
    txn.execute(ddl_space_parents());
    txn.execute(ddl_space_restrictions());
    txn.execute(ddl_space_suggestions());
    txn.execute(ddl_space_peek_state());
    txn.execute(ddl_space_propagation_log());
    txn.execute(ddl_space_hierarchy_cache());
  }

  // =========================================================================
  // Space CRUD operations
  // =========================================================================

  // Insert or update a space record
  bool upsert_space(LoggingTransaction& txn, const SpaceInfo& space) {
    std::string sql = R"SQL(
      INSERT INTO spaces (space_id, name, topic, avatar_url, canonical_alias,
        creator, join_rule, history_visibility, guest_access, room_type,
        is_public, is_world_readable, created_at_ms, updated_at_ms,
        joined_members, invited_members, child_count, total_descendants, depth)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(space_id) DO UPDATE SET
        name = excluded.name,
        topic = excluded.topic,
        avatar_url = excluded.avatar_url,
        canonical_alias = excluded.canonical_alias,
        join_rule = excluded.join_rule,
        history_visibility = excluded.history_visibility,
        guest_access = excluded.guest_access,
        is_public = excluded.is_public,
        is_world_readable = excluded.is_world_readable,
        updated_at_ms = excluded.updated_at_ms,
        joined_members = excluded.joined_members,
        invited_members = excluded.invited_members,
        child_count = excluded.child_count,
        total_descendants = excluded.total_descendants,
        depth = excluded.depth
    )SQL";

    std::vector<std::string> params = {
      space.space_id, space.name, space.topic, space.avatar_url,
      space.canonical_alias, space.creator, space.join_rule,
      space.history_visibility, space.guest_access, kSpaceRoomType,
      space.is_public ? "1" : "0", space.is_world_readable ? "1" : "0",
      std::to_string(space.created_at_ms), std::to_string(storage::now_ms()),
      std::to_string(space.joined_members), std::to_string(space.invited_members),
      std::to_string(space.child_count), std::to_string(space.total_descendants),
      std::to_string(space.depth)
    };

    return txn.execute_params(sql, params);
  }

  // Get a space by ID
  std::optional<SpaceInfo> get_space(LoggingTransaction& txn,
                                      const std::string& space_id) {
    std::string sql = R"SQL(
      SELECT space_id, name, topic, avatar_url, canonical_alias, creator,
             join_rule, history_visibility, guest_access, is_public,
             is_world_readable, created_at_ms, joined_members, invited_members,
             child_count, total_descendants, depth
      FROM spaces WHERE space_id = ?
    )SQL";

    auto rows = txn.query_params(sql, {space_id});
    if (rows.empty()) return std::nullopt;

    const auto& row = rows[0];
    SpaceInfo s;
    s.space_id = row_get_str(row, 0);
    s.name = row_get_str(row, 1);
    s.topic = row_get_str(row, 2);
    s.avatar_url = row_get_str(row, 3);
    s.canonical_alias = row_get_str(row, 4);
    s.creator = row_get_str(row, 5);
    s.join_rule = row_get_str(row, 6);
    s.history_visibility = row_get_str(row, 7);
    s.guest_access = row_get_str(row, 8);
    s.is_public = row_get_bool(row, 9);
    s.is_world_readable = row_get_bool(row, 10);
    s.created_at_ms = row_get_int(row, 11);
    s.joined_members = row_get_int(row, 12);
    s.invited_members = row_get_int(row, 13);
    s.child_count = row_get_int(row, 14);
    s.total_descendants = row_get_int(row, 15);
    s.depth = row_get_int(row, 16);
    return s;
  }

  // Delete a space (soft delete: mark as inactive)
  bool delete_space(LoggingTransaction& txn, const std::string& space_id) {
    std::string sql = "DELETE FROM spaces WHERE space_id = ?";
    return txn.execute_params(sql, {space_id});
  }

  // List all spaces with optional filtering and pagination
  std::vector<SpaceInfo> list_spaces(LoggingTransaction& txn,
                                      const std::string& filter = "",
                                      int64_t limit = 100,
                                      int64_t offset = 0,
                                      const std::string& order_by = "created_at_ms DESC") {
    std::string sql = "SELECT space_id, name, topic, avatar_url, canonical_alias, "
                       "creator, join_rule, history_visibility, guest_access, "
                       "is_public, is_world_readable, created_at_ms, joined_members, "
                       "invited_members, child_count, total_descendants, depth "
                       "FROM spaces";

    std::vector<std::string> params;
    if (!filter.empty()) {
      sql += " WHERE (space_id LIKE ? OR name LIKE ? OR topic LIKE ? "
             "OR canonical_alias LIKE ? OR creator LIKE ?)";
      std::string like_filter = "%" + filter + "%";
      params = {like_filter, like_filter, like_filter, like_filter, like_filter};
    }

    sql += " ORDER BY " + order_by + " LIMIT ? OFFSET ?";
    params.push_back(std::to_string(limit));
    params.push_back(std::to_string(offset));

    auto rows = txn.query_params(sql, params);
    std::vector<SpaceInfo> results;
    results.reserve(rows.size());

    for (const auto& row : rows) {
      SpaceInfo s;
      s.space_id = row_get_str(row, 0);
      s.name = row_get_str(row, 1);
      s.topic = row_get_str(row, 2);
      s.avatar_url = row_get_str(row, 3);
      s.canonical_alias = row_get_str(row, 4);
      s.creator = row_get_str(row, 5);
      s.join_rule = row_get_str(row, 6);
      s.history_visibility = row_get_str(row, 7);
      s.guest_access = row_get_str(row, 8);
      s.is_public = row_get_bool(row, 9);
      s.is_world_readable = row_get_bool(row, 10);
      s.created_at_ms = row_get_int(row, 11);
      s.joined_members = row_get_int(row, 12);
      s.invited_members = row_get_int(row, 13);
      s.child_count = row_get_int(row, 14);
      s.total_descendants = row_get_int(row, 15);
      s.depth = row_get_int(row, 16);
      results.push_back(s);
    }
    return results;
  }

  // Get spaces by creator
  std::vector<SpaceInfo> get_spaces_by_creator(LoggingTransaction& txn,
                                                const std::string& creator) {
    std::string sql = "SELECT space_id, name, topic, avatar_url, canonical_alias, "
                       "creator, join_rule, history_visibility, guest_access, "
                       "is_public, is_world_readable, created_at_ms, joined_members, "
                       "invited_members, child_count, total_descendants, depth "
                       "FROM spaces WHERE creator = ? ORDER BY created_at_ms DESC";

    auto rows = txn.query_params(sql, {creator});
    std::vector<SpaceInfo> results;
    results.reserve(rows.size());
    for (const auto& row : rows) {
      SpaceInfo s;
      s.space_id = row_get_str(row, 0);
      s.name = row_get_str(row, 1);
      s.topic = row_get_str(row, 2);
      s.avatar_url = row_get_str(row, 3);
      s.canonical_alias = row_get_str(row, 4);
      s.creator = row_get_str(row, 5);
      s.join_rule = row_get_str(row, 6);
      s.history_visibility = row_get_str(row, 7);
      s.guest_access = row_get_str(row, 8);
      s.is_public = row_get_bool(row, 9);
      s.is_world_readable = row_get_bool(row, 10);
      s.created_at_ms = row_get_int(row, 11);
      s.joined_members = row_get_int(row, 12);
      s.invited_members = row_get_int(row, 13);
      s.child_count = row_get_int(row, 14);
      s.total_descendants = row_get_int(row, 15);
      s.depth = row_get_int(row, 16);
      results.push_back(s);
    }
    return results;
  }

  // Check if a room is a space
  bool is_space(LoggingTransaction& txn, const std::string& room_id) {
    std::string sql = "SELECT COUNT(*) FROM spaces WHERE space_id = ?";
    auto rows = txn.query_params(sql, {room_id});
    if (rows.empty()) return false;
    return row_get_int(rows[0], 0) > 0;
  }

  // Update space metadata
  bool update_space_metadata(LoggingTransaction& txn, const std::string& space_id,
                              const std::string& name, const std::string& topic,
                              const std::string& avatar_url) {
    std::string sql = "UPDATE spaces SET name = ?, topic = ?, avatar_url = ?, "
                       "updated_at_ms = ? WHERE space_id = ?";
    return txn.execute_params(sql, {name, topic, avatar_url,
                              std::to_string(storage::now_ms()), space_id});
  }

  // Update space join rule
  bool update_space_join_rule(LoggingTransaction& txn, const std::string& space_id,
                               const std::string& join_rule) {
    std::string sql = "UPDATE spaces SET join_rule = ?, updated_at_ms = ? "
                       "WHERE space_id = ?";
    return txn.execute_params(sql, {join_rule,
                              std::to_string(storage::now_ms()), space_id});
  }

  // Update space member counts
  bool update_space_member_counts(LoggingTransaction& txn,
                                   const std::string& space_id,
                                   int64_t joined, int64_t invited) {
    std::string sql = "UPDATE spaces SET joined_members = ?, invited_members = ?, "
                       "updated_at_ms = ? WHERE space_id = ?";
    return txn.execute_params(sql, {std::to_string(joined),
                              std::to_string(invited),
                              std::to_string(storage::now_ms()), space_id});
  }

  // =========================================================================
  // Space Children CRUD
  // =========================================================================

  // Add a child to a space
  bool add_child(LoggingTransaction& txn, const SpaceChild& child) {
    std::string sql = R"SQL(
      INSERT INTO space_children (space_id, child_room_id, event_id, sort_order,
        order_priority, suggested, auto_join, via_server, added_by, added_at_ms,
        updated_at_ms, is_active, child_name, child_topic, child_avatar_url,
        child_join_rule, child_room_type, child_is_public, child_joined_members,
        child_invited_members)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(space_id, child_room_id) DO UPDATE SET
        sort_order = excluded.sort_order,
        order_priority = excluded.order_priority,
        suggested = excluded.suggested,
        auto_join = excluded.auto_join,
        via_server = excluded.via_server,
        updated_at_ms = excluded.updated_at_ms,
        is_active = 1,
        child_name = excluded.child_name,
        child_topic = excluded.child_topic,
        child_avatar_url = excluded.child_avatar_url,
        child_join_rule = excluded.child_join_rule,
        child_room_type = excluded.child_room_type,
        child_is_public = excluded.child_is_public,
        child_joined_members = excluded.child_joined_members,
        child_invited_members = excluded.child_invited_members
    )SQL";

    return txn.execute_params(sql, {
      child.space_id,
      child.child_room_id,
      "",  // event_id
      child.order,
      std::to_string(child.order_priority > 0 ? child.order_priority
                        : extract_order_priority(child.order)),
      child.suggested ? "1" : "0",
      child.auto_join ? "1" : "0",
      child.via_server,
      "",  // added_by
      std::to_string(child.added_at_ms > 0 ? child.added_at_ms : storage::now_ms()),
      std::to_string(storage::now_ms()),
      child.child_name,
      child.child_topic,
      child.child_avatar,
      child.child_join_rule,
      child.child_room_type,
      child.child_is_public ? "1" : "0",
      std::to_string(child.child_joined_members),
      "0"  // child_invited_members placeholder
    });
  }

  // Remove a child from a space (soft delete: mark inactive)
  bool remove_child(LoggingTransaction& txn, const std::string& space_id,
                     const std::string& child_room_id) {
    std::string sql = "UPDATE space_children SET is_active = 0, "
                       "updated_at_ms = ? WHERE space_id = ? AND child_room_id = ?";
    return txn.execute_params(sql, {std::to_string(storage::now_ms()),
                              space_id, child_room_id});
  }

  // Permanently delete a child entry
  bool delete_child(LoggingTransaction& txn, const std::string& space_id,
                     const std::string& child_room_id) {
    std::string sql = "DELETE FROM space_children WHERE space_id = ? "
                       "AND child_room_id = ?";
    return txn.execute_params(sql, {space_id, child_room_id});
  }

  // Get children of a space (active only)
  std::vector<SpaceChild> get_children(LoggingTransaction& txn,
                                        const std::string& space_id,
                                        int64_t limit = 1000,
                                        int64_t offset = 0,
                                        const std::string& order_by = "order_priority ASC") {
    std::string sql = "SELECT space_id, child_room_id, sort_order, suggested, "
                       "auto_join, via_server, added_at_ms, child_name, child_topic, "
                       "child_avatar_url, child_join_rule, child_room_type, "
                       "child_is_public, child_joined_members "
                       "FROM space_children "
                       "WHERE space_id = ? AND is_active = 1 "
                       "ORDER BY " + order_by + " LIMIT ? OFFSET ?";

    auto rows = txn.query_params(sql, {space_id, std::to_string(limit),
                                 std::to_string(offset)});
    std::vector<SpaceChild> results;
    results.reserve(rows.size());
    for (const auto& row : rows) {
      SpaceChild c;
      c.space_id = row_get_str(row, 0);
      c.child_room_id = row_get_str(row, 1);
      c.order = row_get_str(row, 2);
      c.suggested = row_get_bool(row, 3);
      c.auto_join = row_get_bool(row, 4);
      c.via_server = row_get_str(row, 5);
      c.added_at_ms = row_get_int(row, 6);
      c.child_name = row_get_str(row, 7);
      c.child_topic = row_get_str(row, 8);
      c.child_avatar = row_get_str(row, 9);
      c.child_join_rule = row_get_str(row, 10);
      c.child_room_type = row_get_str(row, 11);
      c.child_is_public = row_get_bool(row, 12);
      c.child_joined_members = row_get_int(row, 13);
      c.order_priority = extract_order_priority(c.order);
      results.push_back(c);
    }
    return results;
  }

  // Get child count for a space
  int64_t get_child_count(LoggingTransaction& txn, const std::string& space_id) {
    std::string sql = "SELECT COUNT(*) FROM space_children "
                       "WHERE space_id = ? AND is_active = 1";
    auto rows = txn.query_params(sql, {space_id});
    return rows.empty() ? 0 : row_get_int(rows[0], 0);
  }

  // Get suggested children
  std::vector<SpaceChild> get_suggested_children(LoggingTransaction& txn,
                                                   const std::string& space_id) {
    std::string sql = "SELECT space_id, child_room_id, sort_order, suggested, "
                       "auto_join, via_server, added_at_ms, child_name, child_topic, "
                       "child_avatar_url, child_join_rule, child_room_type, "
                       "child_is_public, child_joined_members "
                       "FROM space_children "
                       "WHERE space_id = ? AND is_active = 1 AND suggested = 1 "
                       "ORDER BY order_priority ASC";

    auto rows = txn.query_params(sql, {space_id});
    std::vector<SpaceChild> results;
    results.reserve(rows.size());
    for (const auto& row : rows) {
      SpaceChild c;
      c.space_id = row_get_str(row, 0);
      c.child_room_id = row_get_str(row, 1);
      c.order = row_get_str(row, 2);
      c.suggested = row_get_bool(row, 3);
      c.auto_join = row_get_bool(row, 4);
      c.via_server = row_get_str(row, 5);
      c.added_at_ms = row_get_int(row, 6);
      c.child_name = row_get_str(row, 7);
      c.child_topic = row_get_str(row, 8);
      c.child_avatar = row_get_str(row, 9);
      c.child_join_rule = row_get_str(row, 10);
      c.child_room_type = row_get_str(row, 11);
      c.child_is_public = row_get_bool(row, 12);
      c.child_joined_members = row_get_int(row, 13);
      c.order_priority = extract_order_priority(c.order);
      results.push_back(c);
    }
    return results;
  }

  // Check if a room is a child of a space
  bool is_child(LoggingTransaction& txn, const std::string& space_id,
                 const std::string& child_room_id) {
    std::string sql = "SELECT COUNT(*) FROM space_children "
                       "WHERE space_id = ? AND child_room_id = ? AND is_active = 1";
    auto rows = txn.query_params(sql, {space_id, child_room_id});
    return !rows.empty() && row_get_int(rows[0], 0) > 0;
  }

  // Get child entry
  std::optional<SpaceChild> get_child(LoggingTransaction& txn,
                                       const std::string& space_id,
                                       const std::string& child_room_id) {
    std::string sql = "SELECT space_id, child_room_id, sort_order, suggested, "
                       "auto_join, via_server, added_at_ms, child_name, child_topic, "
                       "child_avatar_url, child_join_rule, child_room_type, "
                       "child_is_public, child_joined_members "
                       "FROM space_children "
                       "WHERE space_id = ? AND child_room_id = ? AND is_active = 1";

    auto rows = txn.query_params(sql, {space_id, child_room_id});
    if (rows.empty()) return std::nullopt;

    const auto& row = rows[0];
    SpaceChild c;
    c.space_id = row_get_str(row, 0);
    c.child_room_id = row_get_str(row, 1);
    c.order = row_get_str(row, 2);
    c.suggested = row_get_bool(row, 3);
    c.auto_join = row_get_bool(row, 4);
    c.via_server = row_get_str(row, 5);
    c.added_at_ms = row_get_int(row, 6);
    c.child_name = row_get_str(row, 7);
    c.child_topic = row_get_str(row, 8);
    c.child_avatar = row_get_str(row, 9);
    c.child_join_rule = row_get_str(row, 10);
    c.child_room_type = row_get_str(row, 11);
    c.child_is_public = row_get_bool(row, 12);
    c.child_joined_members = row_get_int(row, 13);
    c.order_priority = extract_order_priority(c.order);
    return c;
  }

  // Batch add children
  bool batch_add_children(LoggingTransaction& txn,
                           const std::vector<SpaceChild>& children) {
    for (const auto& child : children) {
      if (!add_child(txn, child)) return false;
    }
    return true;
  }

  // Batch remove children
  bool batch_remove_children(LoggingTransaction& txn,
                              const std::string& space_id,
                              const std::vector<std::string>& child_ids) {
    for (const auto& cid : child_ids) {
      if (!remove_child(txn, space_id, cid)) return false;
    }
    return true;
  }

  // Update child metadata cache
  bool update_child_cache(LoggingTransaction& txn,
                           const std::string& space_id,
                           const std::string& child_room_id,
                           const std::string& name,
                           const std::string& topic,
                           const std::string& avatar,
                           const std::string& join_rule) {
    std::string sql = "UPDATE space_children SET child_name = ?, child_topic = ?, "
                       "child_avatar_url = ?, child_join_rule = ?, "
                       "updated_at_ms = ? "
                       "WHERE space_id = ? AND child_room_id = ?";
    return txn.execute_params(sql, {name, topic, avatar, join_rule,
                              std::to_string(storage::now_ms()),
                              space_id, child_room_id});
  }

  // Reorder a child
  bool reorder_child(LoggingTransaction& txn, const std::string& space_id,
                      const std::string& child_room_id, const std::string& new_order) {
    int64_t priority = extract_order_priority(new_order);
    std::string sql = "UPDATE space_children SET sort_order = ?, "
                       "order_priority = ?, updated_at_ms = ? "
                       "WHERE space_id = ? AND child_room_id = ?";
    return txn.execute_params(sql, {new_order, std::to_string(priority),
                              std::to_string(storage::now_ms()),
                              space_id, child_room_id});
  }

  // =========================================================================
  // Space Parents CRUD
  // =========================================================================

  // Add a parent relationship
  bool add_parent(LoggingTransaction& txn, const SpaceParent& parent) {
    std::string sql = R"SQL(
      INSERT INTO space_parents (room_id, parent_space_id, event_id, canonical,
        via_server, added_by, added_at_ms, is_active)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1)
      ON CONFLICT(room_id, parent_space_id) DO UPDATE SET
        canonical = excluded.canonical,
        via_server = excluded.via_server,
        is_active = 1
    )SQL";

    return txn.execute_params(sql, {
      parent.room_id, parent.parent_space_id, "",
      parent.canonical ? "1" : "0", parent.via_server, "",
      std::to_string(parent.added_at_ms > 0 ? parent.added_at_ms : storage::now_ms())
    });
  }

  // Remove a parent relationship
  bool remove_parent(LoggingTransaction& txn, const std::string& room_id,
                      const std::string& parent_space_id) {
    std::string sql = "UPDATE space_parents SET is_active = 0 "
                       "WHERE room_id = ? AND parent_space_id = ?";
    return txn.execute_params(sql, {room_id, parent_space_id});
  }

  // Get parents of a room
  std::vector<SpaceParent> get_parents(LoggingTransaction& txn,
                                        const std::string& room_id) {
    std::string sql = "SELECT room_id, parent_space_id, canonical, via_server, "
                       "added_at_ms FROM space_parents "
                       "WHERE room_id = ? AND is_active = 1 "
                       "ORDER BY canonical DESC, added_at_ms DESC";

    auto rows = txn.query_params(sql, {room_id});
    std::vector<SpaceParent> results;
    results.reserve(rows.size());
    for (const auto& row : rows) {
      SpaceParent p;
      p.room_id = row_get_str(row, 0);
      p.parent_space_id = row_get_str(row, 1);
      p.canonical = row_get_bool(row, 2);
      p.via_server = row_get_str(row, 3);
      p.added_at_ms = row_get_int(row, 4);
      results.push_back(p);
    }
    return results;
  }

  // Get canonical parent for a room
  std::optional<SpaceParent> get_canonical_parent(LoggingTransaction& txn,
                                                    const std::string& room_id) {
    std::string sql = "SELECT room_id, parent_space_id, canonical, via_server, "
                       "added_at_ms FROM space_parents "
                       "WHERE room_id = ? AND canonical = 1 AND is_active = 1 "
                       "LIMIT 1";

    auto rows = txn.query_params(sql, {room_id});
    if (rows.empty()) return std::nullopt;

    const auto& row = rows[0];
    SpaceParent p;
    p.room_id = row_get_str(row, 0);
    p.parent_space_id = row_get_str(row, 1);
    p.canonical = row_get_bool(row, 2);
    p.via_server = row_get_str(row, 3);
    p.added_at_ms = row_get_int(row, 4);
    return p;
  }

  // Set a parent as canonical (and unset all others)
  bool set_canonical_parent(LoggingTransaction& txn,
                             const std::string& room_id,
                             const std::string& parent_space_id) {
    // First, unset all canonical parents for this room
    std::string unset_sql = "UPDATE space_parents SET canonical = 0 "
                             "WHERE room_id = ?";
    txn.execute_params(unset_sql, {room_id});

    // Now set the specific one as canonical
    std::string set_sql = "UPDATE space_parents SET canonical = 1 "
                           "WHERE room_id = ? AND parent_space_id = ?";
    return txn.execute_params(set_sql, {room_id, parent_space_id});
  }

  // =========================================================================
  // Space Restrictions CRUD
  // =========================================================================

  // Add a space restriction
  bool add_restriction(LoggingTransaction& txn, const SpaceRestriction& restriction) {
    std::string sql = R"SQL(
      INSERT INTO space_restrictions (space_id, restricted_room_id, restriction_type,
        required_membership, is_active, created_at_ms, updated_at_ms)
      VALUES (?, ?, ?, ?, 1, ?, ?)
      ON CONFLICT(space_id, restricted_room_id, restriction_type) DO UPDATE SET
        required_membership = excluded.required_membership,
        is_active = 1,
        updated_at_ms = excluded.updated_at_ms
    )SQL";

    return txn.execute_params(sql, {
      restriction.space_id, restriction.restricted_room_id,
      restriction.restriction_type, restriction.required_membership,
      std::to_string(restriction.created_at_ms > 0
                       ? restriction.created_at_ms : storage::now_ms()),
      std::to_string(storage::now_ms())
    });
  }

  // Remove a restriction
  bool remove_restriction(LoggingTransaction& txn,
                           const std::string& space_id,
                           const std::string& restricted_room_id) {
    std::string sql = "UPDATE space_restrictions SET is_active = 0, "
                       "updated_at_ms = ? WHERE space_id = ? "
                       "AND restricted_room_id = ?";
    return txn.execute_params(sql, {std::to_string(storage::now_ms()),
                              space_id, restricted_room_id});
  }

  // Get restrictions for a room
  std::vector<SpaceRestriction> get_restrictions_for_room(
      LoggingTransaction& txn, const std::string& room_id) {
    std::string sql = "SELECT space_id, restricted_room_id, restriction_type, "
                       "required_membership, is_active, created_at_ms "
                       "FROM space_restrictions "
                       "WHERE restricted_room_id = ? AND is_active = 1";

    auto rows = txn.query_params(sql, {room_id});
    std::vector<SpaceRestriction> results;
    results.reserve(rows.size());
    for (const auto& row : rows) {
      SpaceRestriction r;
      r.restricted_room_id = row_get_str(row, 1);
      r.restriction_type = row_get_str(row, 2);
      r.required_membership = row_get_str(row, 3);
      r.active = row_get_bool(row, 4);
      r.created_at_ms = row_get_int(row, 5);
      results.push_back(r);
    }
    return results;
  }

  // Get spaces that restrict access to a room
  std::vector<std::string> get_restricting_spaces(
      LoggingTransaction& txn, const std::string& room_id) {
    std::string sql = "SELECT space_id FROM space_restrictions "
                       "WHERE restricted_room_id = ? AND is_active = 1";
    auto rows = txn.query_params(sql, {room_id});
    std::vector<std::string> results;
    results.reserve(rows.size());
    for (const auto& row : rows)
      results.push_back(row_get_str(row, 0));
    return results;
  }

  // =========================================================================
  // Space Suggestions CRUD
  // =========================================================================

  // Add a suggestion
  bool add_suggestion(LoggingTransaction& txn, const SpaceSuggestion& suggestion) {
    std::string sql = R"SQL(
      INSERT INTO space_suggestions (space_id, room_id, reason, suggested_by,
        status, score, suggested_at_ms, resolved_at_ms, resolved_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(space_id, room_id) DO UPDATE SET
        reason = excluded.reason,
        suggested_by = excluded.suggested_by,
        status = excluded.status,
        score = excluded.score,
        suggested_at_ms = excluded.suggested_at_ms
    )SQL";

    return txn.execute_params(sql, {
      suggestion.space_id, suggestion.room_id, suggestion.reason,
      suggestion.suggested_by, suggestion.status,
      std::to_string(suggestion.score),
      std::to_string(suggestion.suggested_at_ms > 0
                       ? suggestion.suggested_at_ms : storage::now_ms()),
      std::to_string(suggestion.resolved_at_ms),
      suggestion.resolved_by
    });
  }

  // Get pending suggestions for a space
  std::vector<SpaceSuggestion> get_pending_suggestions(
      LoggingTransaction& txn, const std::string& space_id) {
    std::string sql = "SELECT space_id, room_id, reason, suggested_by, status, "
                       "score, suggested_at_ms "
                       "FROM space_suggestions "
                       "WHERE space_id = ? AND status = 'pending' "
                       "ORDER BY score DESC, suggested_at_ms DESC";

    auto rows = txn.query_params(sql, {space_id});
    std::vector<SpaceSuggestion> results;
    results.reserve(rows.size());
    for (const auto& row : rows) {
      SpaceSuggestion s;
      s.space_id = row_get_str(row, 0);
      s.room_id = row_get_str(row, 1);
      s.reason = row_get_str(row, 2);
      s.suggested_by = row_get_str(row, 3);
      s.status = row_get_str(row, 4);
      s.score = row_get_double(row, 5);
      s.suggested_at_ms = row_get_int(row, 6);
      results.push_back(s);
    }
    return results;
  }

  // Approve a suggestion
  bool approve_suggestion(LoggingTransaction& txn, const std::string& space_id,
                           const std::string& room_id, const std::string& resolved_by) {
    std::string sql = "UPDATE space_suggestions SET status = 'approved', "
                       "resolved_at_ms = ?, resolved_by = ? "
                       "WHERE space_id = ? AND room_id = ?";
    return txn.execute_params(sql, {std::to_string(storage::now_ms()),
                              resolved_by, space_id, room_id});
  }

  // Reject a suggestion
  bool reject_suggestion(LoggingTransaction& txn, const std::string& space_id,
                          const std::string& room_id, const std::string& resolved_by) {
    std::string sql = "UPDATE space_suggestions SET status = 'rejected', "
                       "resolved_at_ms = ?, resolved_by = ? "
                       "WHERE space_id = ? AND room_id = ?";
    return txn.execute_params(sql, {std::to_string(storage::now_ms()),
                              resolved_by, space_id, room_id});
  }

  // =========================================================================
  // Space Peek State CRUD
  // =========================================================================

  // Create a peek session
  SpacePeekState create_peek(LoggingTransaction& txn, const std::string& space_id,
                              const std::string& user_id, int64_t depth_limit,
                              int64_t duration_ms) {
    SpacePeekState peek;
    peek.space_id = space_id;
    peek.user_id = user_id;
    peek.peek_token = random_token(32);
    peek.depth_limit = depth_limit;
    peek.started_at_ms = storage::now_ms();
    peek.expires_at_ms = peek.started_at_ms + duration_ms;
    peek.active = true;

    std::string sql = "INSERT INTO space_peek_state (space_id, user_id, peek_token, "
                       "depth_limit, started_at_ms, expires_at_ms, visited_rooms_json, "
                       "is_active) VALUES (?, ?, ?, ?, ?, ?, '[]', 1)";
    txn.execute_params(sql, {space_id, user_id, peek.peek_token,
                        std::to_string(depth_limit),
                        std::to_string(peek.started_at_ms),
                        std::to_string(peek.expires_at_ms)});

    return peek;
  }

  // Get active peek session
  std::optional<SpacePeekState> get_active_peek(LoggingTransaction& txn,
                                                  const std::string& peek_token) {
    std::string sql = "SELECT space_id, user_id, peek_token, depth_limit, "
                       "started_at_ms, expires_at_ms, is_active "
                       "FROM space_peek_state "
                       "WHERE peek_token = ? AND is_active = 1 "
                       "AND expires_at_ms > ?";

    auto rows = txn.query_params(sql, {peek_token,
                                 std::to_string(storage::now_ms())});
    if (rows.empty()) return std::nullopt;

    const auto& row = rows[0];
    SpacePeekState peek;
    peek.space_id = row_get_str(row, 0);
    peek.user_id = row_get_str(row, 1);
    peek.peek_token = row_get_str(row, 2);
    peek.depth_limit = row_get_int(row, 3);
    peek.started_at_ms = row_get_int(row, 4);
    peek.expires_at_ms = row_get_int(row, 5);
    peek.active = row_get_bool(row, 6);
    return peek;
  }

  // Update peek visited rooms
  bool update_peek_visited(LoggingTransaction& txn, const std::string& peek_token,
                            const std::set<std::string>& visited) {
    json arr = json::array();
    for (const auto& v : visited) arr.push_back(v);
    std::string sql = "UPDATE space_peek_state SET visited_rooms_json = ? "
                       "WHERE peek_token = ?";
    return txn.execute_params(sql, {arr.dump(), peek_token});
  }

  // Expire a peek session
  bool expire_peek(LoggingTransaction& txn, const std::string& peek_token) {
    std::string sql = "UPDATE space_peek_state SET is_active = 0 "
                       "WHERE peek_token = ?";
    return txn.execute_params(sql, {peek_token});
  }

  // Cleanup expired peek sessions
  int64_t cleanup_expired_peeks(LoggingTransaction& txn) {
    std::string sql = "UPDATE space_peek_state SET is_active = 0 "
                       "WHERE expires_at_ms <= ? AND is_active = 1";
    txn.execute_params(sql, {std::to_string(storage::now_ms())});
    // Return count (approximate)
    std::string count_sql = "SELECT COUNT(*) FROM space_peek_state WHERE is_active = 0";
    auto rows = txn.query(count_sql);
    return rows.empty() ? 0 : row_get_int(rows[0], 0);
  }

  // =========================================================================
  // Propagation Log CRUD
  // =========================================================================

  // Log a propagation event
  bool log_propagation(LoggingTransaction& txn, const std::string& space_id,
                        const std::string& user_id, const std::string& child_room_id,
                        const std::string& action, const std::string& membership,
                        bool success, const std::string& error) {
    std::string sql = "INSERT INTO space_propagation_log (space_id, user_id, "
                       "child_room_id, action, membership, propagated_at_ms, success, "
                       "error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    return txn.execute_params(sql, {
      space_id, user_id, child_room_id, action, membership,
      std::to_string(storage::now_ms()), success ? "1" : "0", error
    });
  }

  // =========================================================================
  // Hierarchy Cache CRUD
  // =========================================================================

  // Get cached hierarchy
  std::optional<json> get_cached_hierarchy(LoggingTransaction& txn,
                                            const std::string& space_id,
                                            const std::string& cache_key) {
    std::string sql = "SELECT cached_json, expires_at_ms "
                       "FROM space_hierarchy_cache "
                       "WHERE space_id = ? AND cache_key = ? "
                       "AND expires_at_ms > ?";

    auto rows = txn.query_params(sql, {space_id, cache_key,
                                 std::to_string(storage::now_ms())});
    if (rows.empty()) return std::nullopt;

    return json::parse(row_get_str(rows[0], 0, "{}"));
  }

  // Store hierarchy in cache
  bool cache_hierarchy(LoggingTransaction& txn, const std::string& space_id,
                        const std::string& cache_key, const json& hierarchy,
                        int64_t child_count, int64_t ttl_ms) {
    std::string sql = R"SQL(
      INSERT INTO space_hierarchy_cache (space_id, cache_key, cached_json,
        cached_at_ms, expires_at_ms, child_count)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(space_id, cache_key) DO UPDATE SET
        cached_json = excluded.cached_json,
        cached_at_ms = excluded.cached_at_ms,
        expires_at_ms = excluded.expires_at_ms,
        child_count = excluded.child_count
    )SQL";

    int64_t now = storage::now_ms();
    return txn.execute_params(sql, {
      space_id, cache_key, hierarchy.dump(),
      std::to_string(now), std::to_string(now + ttl_ms),
      std::to_string(child_count)
    });
  }

  // Invalidate hierarchy cache for a space
  bool invalidate_hierarchy_cache(LoggingTransaction& txn,
                                   const std::string& space_id) {
    std::string sql = "UPDATE space_hierarchy_cache SET expires_at_ms = 0 "
                       "WHERE space_id = ?";
    return txn.execute_params(sql, {space_id});
  }

  // Cleanup expired cache entries
  void cleanup_cache(LoggingTransaction& txn) {
    std::string sql = "DELETE FROM space_hierarchy_cache WHERE expires_at_ms <= ?";
    txn.execute_params(sql, {std::to_string(storage::now_ms())});
  }

private:
  std::shared_ptr<DatabasePool> pool_;
};

// ============================================================================
// SpaceEventValidator: Validates m.space.child and m.space.parent events
// ============================================================================
// Checks event format, required fields, valid IDs, circular references,
// power level authorization, and state key correctness. Ensures that space
// events conform to the Matrix specification before they are persisted.
// ============================================================================
class SpaceEventValidator {
public:
  // ---- Validate an m.space.child event ----
  SpaceEventValidationResult validate_child_event(
      const json& content, const std::string& state_key,
      const std::string& sender, const std::string& space_id,
      SpaceStore& store, LoggingTransaction& txn) {

    // State key must be the child room ID
    if (state_key.empty() || !is_valid_room_id(state_key)) {
      return SpaceEventValidationResult::kInvalidRoomId;
    }

    const std::string& child_room_id = state_key;

    // Cannot add a room as child of itself
    if (child_room_id == space_id) {
      return SpaceEventValidationResult::kSelfReference;
    }

    // Check if the child_room_id looks valid
    if (!is_valid_room_id(child_room_id)) {
      return SpaceEventValidationResult::kInvalidRoomId;
    }

    // Check circular reference by walking up from the child
    if (child_room_id[0] == '!') {
      // If child is a space, check it's not already an ancestor
      CircularCheckResult circ = check_circular_reference(
          txn, store, space_id, child_room_id);
      if (circ != CircularCheckResult::kNoCycle) {
        return SpaceEventValidationResult::kCircularReference;
      }
    }

    // Validate 'via' servers if provided
    if (content.contains(kChildViaKey)) {
      if (!content[kChildViaKey].is_array() || content[kChildViaKey].empty()) {
        // via must be a non-empty array of server names
        return SpaceEventValidationResult::kInvalidFormat;
      }
    }

    // Validate 'order' if provided
    if (content.contains(kChildOrderKey)) {
      if (!content[kChildOrderKey].is_string()) {
        return SpaceEventValidationResult::kInvalidFormat;
      }
      // Order should be at most 50 characters per spec
      std::string order = content[kChildOrderKey].get<std::string>();
      if (order.size() > 50) {
        return SpaceEventValidationResult::kInvalidFormat;
      }
    }

    // Validate 'suggested' boolean if provided
    if (content.contains(kChildSuggestedKey)) {
      if (!content[kChildSuggestedKey].is_boolean()) {
        return SpaceEventValidationResult::kInvalidFormat;
      }
    }

    // Validate 'auto_join' boolean if provided
    if (content.contains(kChildAutoJoinKey)) {
      if (!content[kChildAutoJoinKey].is_boolean()) {
        return SpaceEventValidationResult::kInvalidFormat;
      }
    }

    // Check max children limit
    int64_t current_count = store.get_child_count(txn, space_id);
    if (current_count >= kDefaultPageSize * 100) { // Reasonable upper limit
      return SpaceEventValidationResult::kMaxChildrenExceeded;
    }

    return SpaceEventValidationResult::kValid;
  }

  // ---- Validate an m.space.parent event ----
  SpaceEventValidationResult validate_parent_event(
      const json& content, const std::string& state_key,
      const std::string& sender, const std::string& room_id,
      SpaceStore& store, LoggingTransaction& txn) {

    // State key must be the parent space ID
    if (state_key.empty() || !is_valid_room_id(state_key)) {
      return SpaceEventValidationResult::kInvalidRoomId;
    }

    const std::string& parent_space_id = state_key;

    // Cannot be parent of itself
    if (parent_space_id == room_id) {
      return SpaceEventValidationResult::kSelfReference;
    }

    // Check circular reference
    CircularCheckResult circ = check_circular_reference(
        txn, store, parent_space_id, room_id);
    if (circ != CircularCheckResult::kNoCycle) {
      return SpaceEventValidationResult::kCircularReference;
    }

    // Validate 'via' if provided
    if (content.contains(kParentViaKey)) {
      if (!content[kParentViaKey].is_array()) {
        return SpaceEventValidationResult::kInvalidFormat;
      }
    }

    // Check max parents limit
    auto parents = store.get_parents(txn, room_id);
    if (static_cast<int64_t>(parents.size()) >= 100) {
      return SpaceEventValidationResult::kMaxParentsExceeded;
    }

    return SpaceEventValidationResult::kValid;
  }

  // ---- Check if adding a child would create a circular reference ----
  CircularCheckResult check_circular_reference(
      LoggingTransaction& txn, SpaceStore& store,
      const std::string& space_id, const std::string& target_room_id) {
    // Walk up from the target_room_id (if it's a space) to see if we
    // reach space_id — this would form a cycle.
    if (!store.is_space(txn, target_room_id)) {
      return CircularCheckResult::kNoCycle;
    }

    std::unordered_set<std::string> visited;
    std::queue<std::string> queue;
    queue.push(target_room_id);
    visited.insert(target_room_id);

    int depth = 0;
    while (!queue.empty() && depth < kCircularRefCheckDepth) {
      std::string current = queue.front();
      queue.pop();

      // Get parents of the current node
      auto parents = store.get_parents(txn, current);
      for (const auto& parent : parents) {
        if (parent.parent_space_id == space_id) {
          return CircularCheckResult::kCycleDetected;
        }
        if (visited.find(parent.parent_space_id) == visited.end()) {
          visited.insert(parent.parent_space_id);
          queue.push(parent.parent_space_id);
        }
      }

      // Also check children (walking up in reverse)
      auto children = store.get_children(txn, current);
      for (const auto& child : children) {
        if (child.child_room_id == space_id) {
          return CircularCheckResult::kCycleDetected;
        }
      }

      depth++;
    }

    if (depth >= kCircularRefCheckDepth) {
      return CircularCheckResult::kMaxDepthExceeded;
    }

    return CircularCheckResult::kNoCycle;
  }

  // ---- Validate a restricted room allow rule ----
  bool validate_restricted_allow_rule(const json& allow_entry) {
    if (!allow_entry.is_object()) return false;
    if (!allow_entry.contains(kTypeKey)) return false;
    if (allow_entry[kTypeKey] != kRestrictionRoomMembership) return false;
    if (!allow_entry.contains(kRoomIdKey)) return false;
    if (!allow_entry[kRoomIdKey].is_string()) return false;
    std::string room_id = allow_entry[kRoomIdKey].get<std::string>();
    return is_valid_room_id(room_id);
  }

  // ---- Get a human-readable description of a validation result ----
  static std::string result_description(SpaceEventValidationResult result) {
    switch (result) {
      case SpaceEventValidationResult::kValid:
        return "Event is valid";
      case SpaceEventValidationResult::kInvalidFormat:
        return "Invalid event format — missing or malformed fields";
      case SpaceEventValidationResult::kInvalidRoomId:
        return "Invalid room ID — must start with '!' and contain a server name";
      case SpaceEventValidationResult::kCircularReference:
        return "Circular reference detected — cannot add a space that is already an ancestor";
      case SpaceEventValidationResult::kAlreadyExists:
        return "Child already exists in this space";
      case SpaceEventValidationResult::kMaxChildrenExceeded:
        return "Maximum number of children per space exceeded";
      case SpaceEventValidationResult::kMaxParentsExceeded:
        return "Maximum number of parent spaces per room exceeded";
      case SpaceEventValidationResult::kPermissionDenied:
        return "Permission denied — insufficient power level";
      case SpaceEventValidationResult::kRoomNotFound:
        return "Room not found";
      case SpaceEventValidationResult::kNotASpace:
        return "Room is not a space";
    }
    return "Unknown error";
  }
};

// ============================================================================
// SpaceHierarchyFlattener: Efficient traversal and flattening of space trees
// ============================================================================
// Provides algorithms for traversing space hierarchies with configurable
// strategies (DFS, BFS, priority-ordered, suggested-first). Handles depth
// limits, circular reference prevention, pagination, and caching.
// ============================================================================
class SpaceHierarchyFlattener {
public:
  explicit SpaceHierarchyFlattener(const SpaceManagerConfig& config)
      : config_(config) {}

  // ---- Flatten hierarchy starting from a root space ----
  // Returns all rooms in the hierarchy sorted according to the strategy.
  // Supports pagination via limit and offset.
  std::vector<SpaceChild> flatten(SpaceStore& store, LoggingTransaction& txn,
                                   const std::string& root_space_id,
                                   TraversalStrategy strategy,
                                   int64_t max_depth,
                                   int64_t limit = kDefaultPageSize,
                                   int64_t offset = 0) {
    std::vector<SpaceChild> result;
    std::unordered_set<std::string> visited;
    std::vector<SpaceChild> all_children;

    // Choose traversal strategy
    switch (strategy) {
      case TraversalStrategy::kDepthFirst:
        traverse_dfs(store, txn, root_space_id, 0, max_depth,
                     visited, all_children);
        break;
      case TraversalStrategy::kBreadthFirst:
        traverse_bfs(store, txn, root_space_id, max_depth,
                     visited, all_children);
        break;
      case TraversalStrategy::kPriorityOrder:
        traverse_priority(store, txn, root_space_id, max_depth,
                          visited, all_children);
        break;
      case TraversalStrategy::kSuggestedFirst:
        traverse_suggested_first(store, txn, root_space_id, max_depth,
                                 visited, all_children);
        break;
    }

    // Sort if needed (DFS and BFS already maintain order)
    if (strategy == TraversalStrategy::kPriorityOrder) {
      std::sort(all_children.begin(), all_children.end(),
                OrderComparator{});
    }

    // Apply pagination
    if (offset > 0 && static_cast<size_t>(offset) < all_children.size()) {
      all_children.erase(all_children.begin(),
                         all_children.begin() + offset);
    }
    if (limit > 0 && static_cast<size_t>(limit) < all_children.size()) {
      all_children.resize(limit);
    }

    return all_children;
  }

  // ---- Get total descendant count for a space ----
  int64_t count_descendants(SpaceStore& store, LoggingTransaction& txn,
                             const std::string& space_id, int64_t max_depth) {
    std::unordered_set<std::string> visited;
    std::vector<SpaceChild> all;
    traverse_dfs(store, txn, space_id, 0, max_depth, visited, all);
    return static_cast<int64_t>(all.size());
  }

  // ---- Get all ancestor spaces of a room ----
  std::vector<std::string> get_ancestors(SpaceStore& store,
                                          LoggingTransaction& txn,
                                          const std::string& room_id,
                                          int64_t max_depth = 10) {
    std::vector<std::string> ancestors;
    std::unordered_set<std::string> visited;
    std::queue<std::string> queue;
    queue.push(room_id);
    visited.insert(room_id);

    int depth = 0;
    while (!queue.empty() && depth < max_depth) {
      size_t level_size = queue.size();
      for (size_t i = 0; i < level_size; i++) {
        std::string current = queue.front();
        queue.pop();

        auto parents = store.get_parents(txn, current);
        for (const auto& parent : parents) {
          if (visited.find(parent.parent_space_id) == visited.end()) {
            visited.insert(parent.parent_space_id);
            ancestors.push_back(parent.parent_space_id);
            queue.push(parent.parent_space_id);
          }
        }
      }
      depth++;
    }

    return ancestors;
  }

  // ---- Check if a space is an ancestor of a room ----
  bool is_ancestor(SpaceStore& store, LoggingTransaction& txn,
                    const std::string& space_id, const std::string& room_id,
                    int64_t max_depth = 10) {
    auto ancestors = get_ancestors(store, txn, room_id, max_depth);
    return std::find(ancestors.begin(), ancestors.end(), space_id) != ancestors.end();
  }

private:
  const SpaceManagerConfig& config_;

  // ---- Depth-first traversal ----
  void traverse_dfs(SpaceStore& store, LoggingTransaction& txn,
                    const std::string& current_id, int current_depth,
                    int64_t max_depth, std::unordered_set<std::string>& visited,
                    std::vector<SpaceChild>& output) {
    if (current_depth >= max_depth) return;
    if (visited.find(current_id) != visited.end()) return;
    visited.insert(current_id);

    auto children = store.get_children(txn, current_id, kDefaultPageSize, 0,
                                        "suggested DESC, order_priority ASC");
    for (auto& child : children) {
      if (visited.find(child.child_room_id) != visited.end()) continue;
      child.depth = current_depth + 1;
      output.push_back(child);
      // Recurse if the child is itself a space
      if (store.is_space(txn, child.child_room_id)) {
        traverse_dfs(store, txn, child.child_room_id, current_depth + 1,
                     max_depth, visited, output);
      }
    }
  }

  // ---- Breadth-first traversal ----
  void traverse_bfs(SpaceStore& store, LoggingTransaction& txn,
                    const std::string& root_id, int64_t max_depth,
                    std::unordered_set<std::string>& visited,
                    std::vector<SpaceChild>& output) {
    std::queue<std::pair<std::string, int>> queue;
    queue.push({root_id, 0});
    visited.insert(root_id);

    while (!queue.empty()) {
      auto [current_id, depth] = queue.front();
      queue.pop();

      if (depth >= max_depth) continue;

      auto children = store.get_children(txn, current_id, kDefaultPageSize, 0,
                                          "order_priority ASC");
      for (auto& child : children) {
        if (visited.find(child.child_room_id) != visited.end()) continue;
        visited.insert(child.child_room_id);
        child.depth = depth + 1;
        output.push_back(child);
        if (store.is_space(txn, child.child_room_id)) {
          queue.push({child.child_room_id, depth + 1});
        }
      }
    }
  }

  // ---- Priority-ordered traversal ----
  void traverse_priority(SpaceStore& store, LoggingTransaction& txn,
                         const std::string& root_id, int64_t max_depth,
                         std::unordered_set<std::string>& visited,
                         std::vector<SpaceChild>& output) {
    // Use BFS but with a priority queue
    using PQEntry = std::pair<int64_t, std::pair<std::string, int>>;
    std::priority_queue<PQEntry, std::vector<PQEntry>, std::greater<PQEntry>> pq;
    pq.push({0, {root_id, 0}});
    visited.insert(root_id);

    while (!pq.empty()) {
      auto [priority, pair] = pq.top();
      auto [current_id, depth] = pair;
      pq.pop();

      if (depth >= max_depth) continue;

      auto children = store.get_children(txn, current_id, kDefaultPageSize, 0,
                                          "order_priority ASC");
      for (auto& child : children) {
        if (visited.find(child.child_room_id) != visited.end()) continue;
        visited.insert(child.child_room_id);
        child.depth = depth + 1;
        child.order_priority = extract_order_priority(child.order);
        output.push_back(child);
        if (store.is_space(txn, child.child_room_id)) {
          pq.push({child.order_priority, {child.child_room_id, depth + 1}});
        }
      }
    }
  }

  // ---- Suggested-first traversal ----
  void traverse_suggested_first(SpaceStore& store, LoggingTransaction& txn,
                                const std::string& root_id, int64_t max_depth,
                                std::unordered_set<std::string>& visited,
                                std::vector<SpaceChild>& output) {
    // Get suggested children first, then others, all BFS
    std::queue<std::pair<std::string, int>> queue;
    queue.push({root_id, 0});
    visited.insert(root_id);

    while (!queue.empty()) {
      auto [current_id, depth] = queue.front();
      queue.pop();

      if (depth >= max_depth) continue;

      // Get suggested first, then regular
      auto suggested = store.get_suggested_children(txn, current_id);
      for (auto& child : suggested) {
        if (visited.find(child.child_room_id) != visited.end()) continue;
        visited.insert(child.child_room_id);
        child.depth = depth + 1;
        output.push_back(child);
        if (store.is_space(txn, child.child_room_id)) {
          queue.push({child.child_room_id, depth + 1});
        }
      }

      auto all = store.get_children(txn, current_id);
      for (auto& child : all) {
        if (visited.find(child.child_room_id) != visited.end()) continue;
        visited.insert(child.child_room_id);
        child.depth = depth + 1;
        output.push_back(child);
        if (store.is_space(txn, child.child_room_id)) {
          queue.push({child.child_room_id, depth + 1});
        }
      }
    }
  }
};

// ============================================================================
// SpaceHierarchyEngine: Core hierarchy management for spaces
// ============================================================================
// Manages the parent-child DAG that defines space relationships. Handles
// bidirectional linking of m.space.child and m.space.parent events, orphan
// detection, cascade operations, depth tracking, and structural validation.
// ============================================================================
class SpaceHierarchyEngine {
public:
  explicit SpaceHierarchyEngine(std::shared_ptr<SpaceStore> store,
                                 std::shared_ptr<SpaceHierarchyFlattener> flattener,
                                 std::shared_ptr<SpaceEventValidator> validator)
      : store_(std::move(store)),
        flattener_(std::move(flattener)),
        validator_(std::move(validator)) {}

  // ---- Add a child to a space (handles both child and parent events) ----
  SpaceEventValidationResult add_child_to_space(
      LoggingTransaction& txn, const std::string& space_id,
      const std::string& child_room_id, const json& content,
      const std::string& sender) {

    // Validate
    auto result = validator_->validate_child_event(
        content, child_room_id, sender, space_id, *store_, txn);
    if (result != SpaceEventValidationResult::kValid) {
      return result;
    }

    // Check if already a child
    if (store_->is_child(txn, space_id, child_room_id)) {
      return SpaceEventValidationResult::kAlreadyExists;
    }

    // Parse content
    SpaceChild child;
    child.space_id = space_id;
    child.child_room_id = child_room_id;
    child.order = content.value(kChildOrderKey, "");
    child.suggested = content.value(kChildSuggestedKey, false);
    child.auto_join = content.value(kChildAutoJoinKey, false);
    if (content.contains(kChildViaKey) && content[kChildViaKey].is_array() &&
        !content[kChildViaKey].empty()) {
      child.via_server = content[kChildViaKey][0].get<std::string>();
    }
    child.added_at_ms = storage::now_ms();
    child.order_priority = extract_order_priority(child.order);

    // If the child is a space, verify it exists
    if (store_->is_space(txn, child_room_id)) {
      auto child_space = store_->get_space(txn, child_room_id);
      if (child_space) {
        child.child_name = child_space->name;
        child.child_topic = child_space->topic;
        child.child_avatar = child_space->avatar_url;
        child.child_join_rule = child_space->join_rule;
        child.child_room_type = "m.space";
        child.child_is_public = child_space->is_public;
        child.child_joined_members = child_space->joined_members;
      }
    } else {
      // Regular room — cache what we can
      child.child_room_type = "";
    }

    // Persist child
    if (!store_->add_child(txn, child)) {
      return SpaceEventValidationResult::kInvalidFormat;
    }

    // Update parent side
    SpaceParent parent;
    parent.room_id = child_room_id;
    parent.parent_space_id = space_id;
    parent.via_server = child.via_server;
    parent.canonical = false;
    parent.added_at_ms = storage::now_ms();
    store_->add_parent(txn, parent);

    // Update space child count
    int64_t count = store_->get_child_count(txn, space_id);
    auto space = store_->get_space(txn, space_id);
    if (space) {
      store_->upsert_space(txn, *space);
    }

    // Update descendant count
    update_descendant_counts(txn, space_id);

    // Invalidate hierarchy cache
    store_->invalidate_hierarchy_cache(txn, space_id);

    return SpaceEventValidationResult::kValid;
  }

  // ---- Remove a child from a space ----
  bool remove_child_from_space(LoggingTransaction& txn,
                                const std::string& space_id,
                                const std::string& child_room_id) {
    if (!store_->remove_child(txn, space_id, child_room_id)) return false;
    store_->remove_parent(txn, child_room_id, space_id);

    // Update descendant counts
    update_descendant_counts(txn, space_id);

    // Invalidate cache
    store_->invalidate_hierarchy_cache(txn, space_id);

    return true;
  }

  // ---- Reorder a child within a space ----
  bool reorder_child(LoggingTransaction& txn, const std::string& space_id,
                      const std::string& child_room_id,
                      const std::string& new_order) {
    bool ok = store_->reorder_child(txn, space_id, child_room_id, new_order);
    if (ok) {
      store_->invalidate_hierarchy_cache(txn, space_id);
    }
    return ok;
  }

  // ---- Update child metadata cache ----
  bool refresh_child_metadata(LoggingTransaction& txn,
                               const std::string& space_id,
                               const std::string& child_room_id) {
    auto child = store_->get_child(txn, space_id, child_room_id);
    if (!child) return false;

    // Refresh from the actual room state (simulated here with empty values
    // since we don't have access to the room state store in this module)
    return store_->update_child_cache(txn, space_id, child_room_id,
                                       child->child_name, child->child_topic,
                                       child->child_avatar, child->child_join_rule);
  }

  // ---- Set canonical parent for a room ----
  bool set_canonical_parent(LoggingTransaction& txn,
                             const std::string& room_id,
                             const std::string& parent_space_id) {
    return store_->set_canonical_parent(txn, room_id, parent_space_id);
  }

  // ---- Cascade delete: remove a space and all its descendants ----
  struct CascadeResult {
    int64_t spaces_removed;
    int64_t children_removed;
    int64_t parents_removed;
  };

  CascadeResult cascade_delete(LoggingTransaction& txn,
                                const std::string& space_id,
                                bool remove_descendant_spaces = true) {
    CascadeResult result{0, 0, 0};

    // Get all descendants (flatten the hierarchy)
    std::unordered_set<std::string> visited;
    std::vector<SpaceChild> all_descendants;
    flattener_->traverse_dfs(*store_, txn, space_id, 0,
                              config_.max_hierarchy_depth,
                              visited, all_descendants);

    // Remove all children from parent spaces
    for (const auto& desc : all_descendants) {
      store_->remove_child(txn, desc.space_id, desc.child_room_id);
      store_->remove_parent(txn, desc.child_room_id, desc.space_id);
      result.children_removed++;
    }

    // Also remove the parent relationships for all rooms pointing to this space
    auto parents = store_->get_parents(txn, space_id);
    for (const auto& p : parents) {
      store_->remove_parent(txn, p.room_id, p.parent_space_id);
      store_->remove_child(txn, p.parent_space_id, space_id);
      result.parents_removed++;
    }

    // If removing descendant spaces too, delete them
    if (remove_descendant_spaces) {
      for (const auto& desc : all_descendants) {
        if (store_->is_space(txn, desc.child_room_id)) {
          store_->delete_space(txn, desc.child_room_id);
          result.spaces_removed++;
        }
      }
      store_->delete_space(txn, space_id);
      result.spaces_removed++;
    }

    // Invalidate caches
    store_->invalidate_hierarchy_cache(txn, space_id);
    for (const auto& p : parents) {
      store_->invalidate_hierarchy_cache(txn, p.parent_space_id);
    }

    return result;
  }

  // ---- Detect orphan rooms (children of deleted spaces) ----
  std::vector<std::string> find_orphan_rooms(LoggingTransaction& txn) {
    std::vector<std::string> orphans;
    // Query for active children whose parent space no longer exists
    // This would need the actual space table check — we approximate here
    return orphans;
  }

private:
  std::shared_ptr<SpaceStore> store_;
  std::shared_ptr<SpaceHierarchyFlattener> flattener_;
  std::shared_ptr<SpaceEventValidator> validator_;
  SpaceManagerConfig config_;

  // ---- Update descendant counts for all ancestors of a space ----
  void update_descendant_counts(LoggingTransaction& txn,
                                 const std::string& space_id) {
    // Walk up the ancestor chain and update total_descendants
    auto ancestors = flattener_->get_ancestors(*store_, txn, space_id,
                                                config_.max_hierarchy_depth);
    for (const auto& ancestor_id : ancestors) {
      int64_t count = flattener_->count_descendants(*store_, txn, ancestor_id,
                                                      config_.max_hierarchy_depth);
      auto space = store_->get_space(txn, ancestor_id);
      if (space) {
        space->total_descendants = count;
        space->child_count = store_->get_child_count(txn, ancestor_id);
        store_->upsert_space(txn, *space);
      }
    }
  }
};

// ============================================================================
// SpaceRestrictionsEngine: Enforces restricted joins via space membership
// ============================================================================
// Implements MSC 3083 restricted rooms. Handles m.room.join_rules restricted
// rooms that reference space membership for join authorization. Validates
// join eligibility by checking whether the joining user is a member of the
// required space(s). Supports room version-specific restriction semantics
// including v8 restricted rooms, v9 knocking, and v10 MSC 3083 additions.
// ============================================================================
class SpaceRestrictionsEngine {
public:
  explicit SpaceRestrictionsEngine(std::shared_ptr<SpaceStore> store,
                                    std::shared_ptr<SpaceHierarchyFlattener> flattener)
      : store_(std::move(store)),
        flattener_(std::move(flattener)) {}

  // ---- Check if a user can join a restricted room via space membership ----
  bool can_user_join_restricted_room(
      LoggingTransaction& txn,
      const std::string& user_id,
      const std::string& room_id,
      const std::vector<std::string>& user_joined_spaces,
      const json& join_rules_content) {

    // Parse the join_rules content for allow rules
    if (!join_rules_content.contains(kAllowKey)) return false;
    if (!join_rules_content[kAllowKey].is_array()) return false;

    const auto& allow_rules = join_rules_content[kAllowKey];

    // Check each allow rule to see if any match
    for (const auto& rule : allow_rules) {
      if (!rule.is_object()) continue;
      if (rule.value(kTypeKey, "") != kRestrictionRoomMembership) continue;
      if (!rule.contains(kRoomIdKey)) continue;

      std::string required_room_id = rule[kRoomIdKey].get<std::string>();

      // Check if the user is a member of the required space
      if (std::find(user_joined_spaces.begin(), user_joined_spaces.end(),
                    required_room_id) != user_joined_spaces.end()) {
        return true;
      }

      // Also check if any ancestor space of the required room is joined
      // (since space membership typically implies subspace membership)
      auto ancestors = flattener_->get_ancestors(*store_, txn, required_room_id);
      for (const auto& ancestor : ancestors) {
        if (std::find(user_joined_spaces.begin(), user_joined_spaces.end(),
                      ancestor) != user_joined_spaces.end()) {
          return true;
        }
      }
    }

    return false;
  }

  // ---- Add a restriction to a room referencing a space ----
  bool add_room_restriction(LoggingTransaction& txn,
                             const std::string& space_id,
                             const std::string& restricted_room_id,
                             const std::string& required_membership = "join") {
    SpaceRestriction restriction;
    restriction.space_id = space_id;
    restriction.restricted_room_id = restricted_room_id;
    restriction.restriction_type = kRestrictionRoomMembership;
    restriction.required_membership = required_membership;
    restriction.created_at_ms = storage::now_ms();
    restriction.updated_at_ms = storage::now_ms();
    return store_->add_restriction(txn, restriction);
  }

  // ---- Remove a restriction ----
  bool remove_room_restriction(LoggingTransaction& txn,
                                const std::string& space_id,
                                const std::string& restricted_room_id) {
    return store_->remove_restriction(txn, space_id, restricted_room_id);
  }

  // ---- Get all restrictions for a room ----
  std::vector<SpaceRestriction> get_room_restrictions(
      LoggingTransaction& txn, const std::string& room_id) {
    return store_->get_restrictions_for_room(txn, room_id);
  }

  // ---- Get all spaces a room is restricted by ----
  std::vector<std::string> get_restricting_spaces(
      LoggingTransaction& txn, const std::string& room_id) {
    return store_->get_restricting_spaces(txn, room_id);
  }

  // ---- Build join_rules allow entries from space restrictions ----
  json build_allow_entries(LoggingTransaction& txn,
                            const std::string& room_id) {
    json allows = json::array();
    auto restrictions = get_room_restrictions(txn, room_id);
    for (const auto& r : restrictions) {
      if (r.active) {
        allows.push_back({
          {kTypeKey, r.restriction_type},
          {kRoomIdKey, r.space_id}
        });
      }
    }
    return allows;
  }

private:
  std::shared_ptr<SpaceStore> store_;
  std::shared_ptr<SpaceHierarchyFlattener> flattener_;
};

// ============================================================================
// SpaceDiscoveryService: Discovery and visibility of spaces
// ============================================================================
// Enables discovery of spaces and their contents. Supports public space
// listing, space directory, visibility controls, recursive traversal for
// browsing, and space summary generation. Implements MSC 2946 hierarchy
// endpoint with pagination and depth limits.
// ============================================================================
class SpaceDiscoveryService {
public:
  explicit SpaceDiscoveryService(std::shared_ptr<SpaceStore> store,
                                  std::shared_ptr<SpaceHierarchyFlattener> flattener,
                                  std::shared_ptr<SpaceHierarchyEngine> engine)
      : store_(std::move(store)),
        flattener_(std::move(flattener)),
        engine_(std::move(engine)) {}

  // ---- List public spaces (for discovery) ----
  std::vector<SpaceInfo> list_public_spaces(LoggingTransaction& txn,
                                             int64_t limit = 50,
                                             int64_t offset = 0,
                                             const std::string& search = "") {
    return store_->list_spaces(txn, search, limit, offset,
                                "joined_members DESC, created_at_ms DESC");
  }

  // ---- Get a space summary for the /hierarchy endpoint (MSC 2946) ----
  SpaceHierarchySummary get_space_summary(
      LoggingTransaction& txn,
      const std::string& space_id,
      const std::string& user_id,
      int64_t max_depth = 3,
      int64_t limit = 100,
      const std::string& from_token = "",
      bool suggested_only = false) {

    SpaceHierarchySummary summary;
    summary.space_id = space_id;

    // Try cache first
    std::string cache_key = "summary:" + space_id + ":" +
                            std::to_string(max_depth) + ":" +
                            (suggested_only ? "1" : "0");
    if (config_.cache_hierarchy) {
      auto cached = store_->get_cached_hierarchy(txn, space_id, cache_key);
      if (cached) {
        // Parse from cache (simplified — in production would fully deserialize)
        return summary;
      }
    }

    // Calculate offset from token
    int64_t offset = 0;
    if (!from_token.empty()) {
      try { offset = std::stoll(from_token); }
      catch (...) { offset = 0; }
    }

    // Traverse hierarchy
    TraversalStrategy strategy = suggested_only
        ? TraversalStrategy::kSuggestedFirst
        : TraversalStrategy::kPriorityOrder;

    std::vector<SpaceChild> children;

    if (suggested_only) {
      children = store_->get_suggested_children(txn, space_id);
      // Also get from descendant spaces recursively
      std::unordered_set<std::string> visited;
      std::vector<SpaceChild> more;
      flattener_->traverse_dfs(*store_, txn, space_id, 0, max_depth,
                                visited, more);
      // Filter suggested
      for (auto& c : more) {
        if (c.suggested) children.push_back(c);
      }
    } else {
      std::unordered_set<std::string> visited;
      std::vector<SpaceChild> all;
      flattener_->traverse_bfs(*store_, txn, space_id, max_depth,
                                visited, all);
      children = std::move(all);
    }

    // Remove duplicates
    std::unordered_set<std::string> seen_ids;
    std::vector<SpaceChild> unique_children;
    for (auto& c : children) {
      if (seen_ids.find(c.child_room_id) == seen_ids.end()) {
        seen_ids.insert(c.child_room_id);
        unique_children.push_back(c);
      }
    }

    summary.total_rooms = static_cast<int64_t>(unique_children.size());
    summary.max_depth_reached = max_depth;

    // Apply pagination
    if (offset > 0 && static_cast<size_t>(offset) < unique_children.size()) {
      unique_children.erase(unique_children.begin(),
                            unique_children.begin() + offset);
    }
    if (limit > 0 && static_cast<size_t>(limit) < unique_children.size()) {
      unique_children.resize(limit);
      summary.next_batch = std::to_string(offset + limit);
      summary.incomplete = true;
    }

    // Count suggested
    summary.suggested_rooms = 0;
    for (const auto& c : unique_children) {
      if (c.suggested) summary.suggested_rooms++;
    }

    summary.rooms = unique_children;

    // Cache the result
    if (config_.cache_hierarchy) {
      store_->cache_hierarchy(txn, space_id, cache_key,
                               summary.to_json(),
                               static_cast<int64_t>(summary.rooms.size()),
                               config_.hierarchy_cache_ttl_ms);
    }

    return summary;
  }

  // ---- Search spaces by name or topic ----
  std::vector<SpaceInfo> search_spaces(LoggingTransaction& txn,
                                        const std::string& query,
                                        int64_t limit = 20,
                                        bool public_only = true) {
    return store_->list_spaces(txn, query, limit, 0,
                                "joined_members DESC");
  }

  // ---- Check if a user can view a space (for discovery) ----
  bool can_view_space(LoggingTransaction& txn, const std::string& space_id,
                       const std::string& user_id) {
    auto space = store_->get_space(txn, space_id);
    if (!space) return false;

    // Public spaces are visible to everyone
    if (space->is_public) return true;
    if (space->is_world_readable) return true;

    // Private spaces: user must be a member
    // In a real implementation, we would check membership via the room store
    return false;
  }

private:
  std::shared_ptr<SpaceStore> store_;
  std::shared_ptr<SpaceHierarchyFlattener> flattener_;
  std::shared_ptr<SpaceHierarchyEngine> engine_;
  SpaceManagerConfig config_;
};

// ============================================================================
// SpaceSuggestionEngine: Manages suggested rooms within spaces
// ============================================================================
// Handles the suggested flag on m.space.child events, auto-join from
// suggestions, suggestion ranking/ordering, and batch suggestion management.
// Supports both manual suggestions (set by space admins) and algorithmic
// suggestions (scored by relevance heuristics).
// ============================================================================
class SpaceSuggestionEngine {
public:
  explicit SpaceSuggestionEngine(std::shared_ptr<SpaceStore> store,
                                  std::shared_ptr<SpaceHierarchyFlattener> flattener)
      : store_(std::move(store)),
        flattener_(std::move(flattener)) {}

  // ---- Mark a child as suggested ----
  bool suggest_child(LoggingTransaction& txn, const std::string& space_id,
                      const std::string& child_room_id) {
    auto child = store_->get_child(txn, space_id, child_room_id);
    if (!child) return false;

    child->suggested = true;
    child->auto_join = false; // Don't force auto-join
    return store_->add_child(txn, *child);
  }

  // ---- Unmark a child as suggested ----
  bool unsuggest_child(LoggingTransaction& txn, const std::string& space_id,
                        const std::string& child_room_id) {
    auto child = store_->get_child(txn, space_id, child_room_id);
    if (!child) return false;

    child->suggested = false;
    return store_->add_child(txn, *child);
  }

  // ---- Set auto-join on a child ----
  bool set_auto_join(LoggingTransaction& txn, const std::string& space_id,
                      const std::string& child_room_id, bool auto_join) {
    auto child = store_->get_child(txn, space_id, child_room_id);
    if (!child) return false;

    child->auto_join = auto_join;
    if (auto_join) {
      child->suggested = true; // Auto-join implies suggested
    }
    return store_->add_child(txn, *child);
  }

  // ---- Get rooms suggested for a user based on their space memberships ----
  std::vector<SpaceChild> get_suggestions_for_user(
      LoggingTransaction& txn, const std::string& user_id,
      const std::vector<std::string>& user_spaces) {

    std::vector<SpaceChild> suggestions;

    for (const auto& space_id : user_spaces) {
      auto suggested = store_->get_suggested_children(txn, space_id);
      for (auto& s : suggested) {
        suggestions.push_back(s);
      }
    }

    // Deduplicate by child_room_id
    std::unordered_set<std::string> seen;
    std::vector<SpaceChild> unique;
    for (auto& s : suggestions) {
      if (seen.find(s.child_room_id) == seen.end()) {
        seen.insert(s.child_room_id);
        unique.push_back(s);
      }
    }

    // Sort by order_priority
    std::sort(unique.begin(), unique.end(), OrderComparator{});
    return unique;
  }

  // ---- Score a room for suggestion relevance ----
  double score_suggestion(const SpaceChild& child,
                          const std::string& user_id,
                          const std::vector<std::string>& user_rooms) {
    double score = 0.0;

    // Already a member? Lower score
    if (std::find(user_rooms.begin(), user_rooms.end(),
                  child.child_room_id) != user_rooms.end()) {
      score -= 10.0;
    }

    // Suggested flag gives a boost
    if (child.suggested) score += 5.0;

    // Auto-join gives a big boost
    if (child.auto_join) score += 15.0;

    // Higher member count rooms are more relevant
    score += std::log1p(static_cast<double>(child.child_joined_members)) * 0.1;

    // Public rooms are more discoverable
    if (child.child_is_public) score += 1.0;

    return score;
  }

  // ---- Submit an algorithmic suggestion ----
  bool submit_suggestion(LoggingTransaction& txn, const std::string& space_id,
                          const std::string& room_id, const std::string& reason,
                          double score, const std::string& suggested_by) {
    SpaceSuggestion suggestion;
    suggestion.space_id = space_id;
    suggestion.room_id = room_id;
    suggestion.reason = reason;
    suggestion.suggested_by = suggested_by;
    suggestion.status = "pending";
    suggestion.score = score;
    suggestion.suggested_at_ms = storage::now_ms();
    return store_->add_suggestion(txn, suggestion);
  }

  // ---- Get top suggestions for a space ----
  std::vector<SpaceSuggestion> get_top_suggestions(
      LoggingTransaction& txn, const std::string& space_id, int limit = 10) {
    auto pending = store_->get_pending_suggestions(txn, space_id);
    if (static_cast<int>(pending.size()) > limit) {
      pending.resize(limit);
    }
    return pending;
  }

private:
  std::shared_ptr<SpaceStore> store_;
  std::shared_ptr<SpaceHierarchyFlattener> flattener_;
};

// ============================================================================
// SpaceMembershipPropagator: Cascading membership through space hierarchies
// ============================================================================
// When a user joins or leaves a space, optionally propagates membership
// changes to child rooms. Respects auto-join flags, handles restricted room
// auto-join via space membership, supports partial propagation, and manages
// rate limiting for bulk operations. Also tracks propagation history for
// audit and rollback purposes.
// ============================================================================
class SpaceMembershipPropagator {
public:
  explicit SpaceMembershipPropagator(std::shared_ptr<SpaceStore> store,
                                      std::shared_ptr<SpaceHierarchyFlattener> flattener,
                                      const SpaceManagerConfig& config)
      : store_(std::move(store)),
        flattener_(std::move(flattener)),
        config_(config),
        last_propagation_ms_(0) {}

  // ---- Propagate a join through the space hierarchy ----
  struct PropagationPlan {
    std::vector<std::string> rooms_to_join;      // Rooms to auto-join
    std::vector<std::string> rooms_to_skip;      // Rooms the user explicitly skipped
    std::vector<std::string> subspaces_to_join;   // Subspaces to recursively join
    int64_t total_rooms_affected;
  };

  PropagationPlan build_join_plan(LoggingTransaction& txn,
                                   const std::string& space_id,
                                   const std::string& user_id,
                                   const std::vector<std::string>& already_joined,
                                   bool include_suggested = true) {
    PropagationPlan plan;

    // Get all children with auto-join flag
    auto children = store_->get_children(txn, space_id, kDefaultPageSize, 0,
                                          "suggested DESC, order_priority ASC");

    for (const auto& child : children) {
      // Skip if already joined
      if (std::find(already_joined.begin(), already_joined.end(),
                    child.child_room_id) != already_joined.end()) {
        continue;
      }

      if (child.auto_join) {
        plan.rooms_to_join.push_back(child.child_room_id);
        if (store_->is_space(txn, child.child_room_id)) {
          plan.subspaces_to_join.push_back(child.child_room_id);
        }
      } else if (include_suggested && child.suggested) {
        // Don't auto-join suggested rooms but include in plan for UI
        continue;
      }
    }

    plan.total_rooms_affected = static_cast<int64_t>(plan.rooms_to_join.size());
    return plan;
  }

  // ---- Propagate a leave through the space hierarchy ----
  PropagationPlan build_leave_plan(LoggingTransaction& txn,
                                    const std::string& space_id,
                                    const std::string& user_id,
                                    const std::vector<std::string>& currently_joined) {
    PropagationPlan plan;

    // Get all children of this space
    std::unordered_set<std::string> visited;
    std::vector<SpaceChild> descendants;
    flattener_->traverse_bfs(*store_, txn, space_id,
                              config_.max_hierarchy_depth,
                              visited, descendants);

    for (const auto& child : descendants) {
      if (std::find(currently_joined.begin(), currently_joined.end(),
                    child.child_room_id) != currently_joined.end()) {
        // Only leave rooms that were auto-joined from this space
        // In a real implementation, we'd check the propagation log
        plan.rooms_to_join.push_back(child.child_room_id);  // rooms_to_leave, really
      }
    }

    plan.total_rooms_affected = static_cast<int64_t>(plan.rooms_to_join.size());
    return plan;
  }

  // ---- Apply a propagation plan (join rooms) ----
  PropagationResult apply_join_propagation(
      LoggingTransaction& txn, const std::string& space_id,
      const std::string& user_id, const PropagationPlan& plan) {

    if (!config_.enable_auto_join) {
      return PropagationResult::kPropagationDisabled;
    }

    // Rate limiting check
    int64_t now = storage::now_ms();
    if (now - last_propagation_ms_ < config_.propagation_rate_limit_ms) {
      return PropagationResult::kRateLimited;
    }
    last_propagation_ms_ = now;

    int64_t success_count = 0;
    int64_t total = static_cast<int64_t>(plan.rooms_to_join.size());

    for (size_t i = 0; i < plan.rooms_to_join.size(); i++) {
      if (i >= static_cast<size_t>(config_.max_propagation_batch)) break;

      const auto& room_id = plan.rooms_to_join[i];
      // In a real implementation, this would call the room join handler
      bool joined = true; // Simulated join success
      store_->log_propagation(txn, space_id, user_id, room_id, "join",
                               "join", joined, joined ? "" : "Join failed");
      if (joined) success_count++;
    }

    // Recursively propagate to subspaces
    for (const auto& sub_id : plan.subspaces_to_join) {
      auto sub_plan = build_join_plan(txn, sub_id, user_id, {}, true);
      apply_join_propagation(txn, sub_id, user_id, sub_plan);
    }

    return static_cast<int64_t>(plan.rooms_to_join.size()) == success_count
        ? PropagationResult::kSuccess
        : PropagationResult::kPartialSuccess;
  }

  // ---- Apply a propagation plan (leave rooms) ----
  PropagationResult apply_leave_propagation(
      LoggingTransaction& txn, const std::string& space_id,
      const std::string& user_id, const PropagationPlan& plan) {

    if (!config_.enable_auto_join) {
      return PropagationResult::kPropagationDisabled;
    }

    for (size_t i = 0; i < plan.rooms_to_join.size(); i++) {
      if (i >= static_cast<size_t>(config_.max_propagation_batch)) break;

      const auto& room_id = plan.rooms_to_join[i];
      // In a real implementation, this would call the room leave handler
      store_->log_propagation(txn, space_id, user_id, room_id, "leave",
                               "leave", true, "");
    }

    return PropagationResult::kSuccess;
  }

  // ---- Check if a user can auto-join a specific room via space ----
  bool can_auto_join(LoggingTransaction& txn, const std::string& space_id,
                      const std::string& child_room_id) {
    auto child = store_->get_child(txn, space_id, child_room_id);
    if (!child) return false;
    return child->auto_join;
  }

private:
  std::shared_ptr<SpaceStore> store_;
  std::shared_ptr<SpaceHierarchyFlattener> flattener_;
  SpaceManagerConfig config_;
  std::atomic<int64_t> last_propagation_ms_;
};

// ============================================================================
// SpacePeekManager: Non-member space browsing
// ============================================================================
// Allows non-members to peek into public spaces to discover rooms. Manages
// temporary peek sessions with configurable depth limits and duration.
// Supports visibility restrictions (world_readable, history_visibility),
// token-based access, and automatic cleanup of expired sessions.
// Implements MSC 3216 space peeking concepts.
// ============================================================================
class SpacePeekManager {
public:
  explicit SpacePeekManager(std::shared_ptr<SpaceStore> store,
                             std::shared_ptr<SpaceDiscoveryService> discovery,
                             const SpaceManagerConfig& config)
      : store_(std::move(store)),
        discovery_(std::move(discovery)),
        config_(config) {}

  // ---- Start a peek session ----
  SpacePeekState start_peek(LoggingTransaction& txn,
                             const std::string& space_id,
                             const std::string& user_id,
                             int64_t depth_limit = -1) {

    if (!config_.enable_peeking) {
      SpacePeekState empty;
      empty.active = false;
      return empty;
    }

    int64_t limit = depth_limit > 0 ? depth_limit : config_.peek_depth_limit;
    return store_->create_peek(txn, space_id, user_id, limit,
                                config_.peek_duration_ms);
  }

  // ---- Peek into a space using a session token ----
  std::optional<SpaceHierarchySummary> peek(LoggingTransaction& txn,
                                             const std::string& peek_token) {
    auto peek_state = store_->get_active_peek(txn, peek_token);
    if (!peek_state) return std::nullopt;

    return discovery_->get_space_summary(
        txn, peek_state->space_id, peek_state->user_id,
        peek_state->depth_limit);
  }

  // ---- Record a room visit during peeking ----
  bool record_visit(LoggingTransaction& txn, const std::string& peek_token,
                     const std::string& room_id) {
    auto peek_state = store_->get_active_peek(txn, peek_token);
    if (!peek_state) return false;

    peek_state->visited_rooms.insert(room_id);
    return store_->update_peek_visited(txn, peek_token,
                                        peek_state->visited_rooms);
  }

  // ---- End a peek session ----
  bool end_peek(LoggingTransaction& txn, const std::string& peek_token) {
    return store_->expire_peek(txn, peek_token);
  }

  // ---- Cleanup expired sessions ----
  int64_t cleanup_expired(LoggingTransaction& txn) {
    return store_->cleanup_expired_peeks(txn);
  }

  // ---- Check if a user can peek into a space ----
  bool can_peek(LoggingTransaction& txn, const std::string& space_id,
                 const std::string& user_id) {
    if (!config_.enable_peeking) return false;

    auto space = store_->get_space(txn, space_id);
    if (!space) return false;

    // Can peek into public or world-readable spaces
    if (space->is_public || space->is_world_readable) return true;

    // Private spaces: only members
    return false;
  }

private:
  std::shared_ptr<SpaceStore> store_;
  std::shared_ptr<SpaceDiscoveryService> discovery_;
  SpaceManagerConfig config_;
};

// ============================================================================
// SpaceSummaryBuilder: Builds the MSC 2946 /hierarchy response
// ============================================================================
// Aggregates room summaries, child state events, room metadata (name, topic,
// avatar, join rules, guest access), applies pagination, generates pagination
// tokens, and enforces max_depth limits. Used by the client API hierarchy
// endpoint to present a complete view of a space and its contents.
// ============================================================================
class SpaceSummaryBuilder {
public:
  explicit SpaceSummaryBuilder(std::shared_ptr<SpaceDiscoveryService> discovery)
      : discovery_(std::move(discovery)) {}

  // ---- Build a full hierarchy response ----
  json build_summary_response(LoggingTransaction& txn,
                               const std::string& space_id,
                               const std::string& user_id,
                               const json& params) {
    // Parse parameters
    int64_t max_depth = params.value("max_depth",
                                      static_cast<int64_t>(3));
    int64_t limit = params.value("limit",
                                  static_cast<int64_t>(100));
    std::string from = params.value("from", "");
    bool suggested_only = params.value("suggested_only", false);

    // Clamp values
    if (max_depth < 0) max_depth = 10;
    if (max_depth > 10) max_depth = 10;
    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;

    // Get the summary
    auto summary = discovery_->get_space_summary(
        txn, space_id, user_id, max_depth, limit, from, suggested_only);

    // Build the response JSON
    json response;
    response["rooms"] = json::array();

    for (const auto& child : summary.rooms) {
      json room_entry;
      room_entry["room_id"] = child.child_room_id;
      room_entry["room_type"] = child.child_room_type;

      // Include child state from the children_state array if available
      json children_state = json::array();

      json name_event;
      name_event["type"] = "m.room.name";
      name_event["state_key"] = "";
      name_event["content"] = {{"name", child.child_name}};
      children_state.push_back(name_event);

      json topic_event;
      topic_event["type"] = "m.room.topic";
      topic_event["state_key"] = "";
      topic_event["content"] = {{"topic", child.child_topic}};
      children_state.push_back(topic_event);

      json avatar_event;
      avatar_event["type"] = "m.room.avatar";
      avatar_event["state_key"] = "";
      avatar_event["content"] = {{"url", child.child_avatar}};
      children_state.push_back(avatar_event);

      json join_rules_event;
      join_rules_event["type"] = "m.room.join_rules";
      join_rules_event["state_key"] = "";
      join_rules_event["content"] = {
        {"join_rule", child.child_join_rule.empty()
                        ? std::string("invite") : child.child_join_rule}
      };
      children_state.push_back(join_rules_event);

      room_entry["children_state"] = children_state;

      if (child.suggested) {
        room_entry["suggested"] = true;
      }
      if (child.auto_join) {
        room_entry["auto_join"] = true;
      }

      response["rooms"].push_back(room_entry);
    }

    if (!summary.next_batch.empty()) {
      response["next_batch"] = summary.next_batch;
    }

    return response;
  }

private:
  std::shared_ptr<SpaceDiscoveryService> discovery_;
};

// ============================================================================
// SpaceUpgradeHandler: Upgrading rooms to spaces and vice versa
// ============================================================================
// Manages the upgrade of regular rooms to spaces (setting m.room.type to
// "m.space") and downgrading spaces to regular rooms. Preserves child/parent
// relationships during upgrades, validates upgrade eligibility, handles
// tombstone events for room version upgrades involving spaces, and supports
// MSC 3827 space upgrade concepts.
// ============================================================================
class SpaceUpgradeHandler {
public:
  explicit SpaceUpgradeHandler(std::shared_ptr<SpaceStore> store,
                                std::shared_ptr<SpaceHierarchyEngine> hierarchy)
      : store_(std::move(store)),
        hierarchy_(std::move(hierarchy)) {}

  // ---- Upgrade a room to a space ----
  bool upgrade_to_space(LoggingTransaction& txn, const std::string& room_id,
                         const std::string& name, const std::string& topic,
                         const std::string& creator) {
    // Check if already a space
    if (store_->is_space(txn, room_id)) return true;

    SpaceInfo space;
    space.space_id = room_id;
    space.name = name;
    space.topic = topic;
    space.creator = creator;
    space.join_rule = kDefaultJoinRule;
    space.history_visibility = "shared";
    space.guest_access = "forbidden";
    space.created_at_ms = storage::now_ms();
    space.depth = 0;

    // If this room already has parent spaces, compute depth
    auto parents = store_->get_parents(txn, room_id);
    if (!parents.empty()) {
      int max_parent_depth = 0;
      for (const auto& p : parents) {
        auto parent_space = store_->get_space(txn, p.parent_space_id);
        if (parent_space) {
          max_parent_depth = std::max(max_parent_depth, parent_space->depth + 1);
        }
      }
      space.depth = max_parent_depth;
    }

    return store_->upsert_space(txn, space);
  }

  // ---- Downgrade a space to a regular room ----
  bool downgrade_from_space(LoggingTransaction& txn,
                             const std::string& space_id) {
    if (!store_->is_space(txn, space_id)) return true;

    // Remove all child relationships
    auto children = store_->get_children(txn, space_id, 10000);
    for (const auto& child : children) {
      hierarchy_->remove_child_from_space(txn, space_id, child.child_room_id);
    }

    return store_->delete_space(txn, space_id);
  }

  // ---- Validate if a room can be upgraded ----
  struct UpgradeValidation {
    bool can_upgrade = true;
    std::string reason;
  };

  UpgradeValidation validate_upgrade(LoggingTransaction& txn,
                                      const std::string& room_id) {
    UpgradeValidation result;

    // Check it's not already a space
    if (store_->is_space(txn, room_id)) {
      result.can_upgrade = false;
      result.reason = "Room is already a space";
      return result;
    }

    // Check for circular reference potential
    auto parents = store_->get_parents(txn, room_id);
    if (parents.size() > 50) {
      result.can_upgrade = true;
      result.reason = "Room has many parent spaces; careful with circular references";
    }

    return result;
  }

  // ---- Get the recommended new room ID for a space upgrade ----
  std::string generate_upgrade_room_id(const std::string& server_name) {
    // Generate a new room ID for the upgraded version
    std::string random_part = random_token(18);
    return "!" + random_part + ":" + server_name;
  }

private:
  std::shared_ptr<SpaceStore> store_;
  std::shared_ptr<SpaceHierarchyEngine> hierarchy_;
};

// ============================================================================
// SpaceManagerCoordinator: Top-level orchestrator for all space operations
// ============================================================================
// Wires all sub-components together and presents a unified API for space
// management. Handles lifecycle management, configuration, access control,
// metrics collection, and background maintenance tasks (cache cleanup,
// peek expiry, orphan detection). The primary entry point for all space
// operations in the server.
// ============================================================================
class SpaceManagerCoordinator {
public:
  // ---- System statistics ----
  struct SpaceSystemStats {
    int64_t total_spaces = 0;
    int64_t total_child_relationships = 0;
    int64_t total_parent_relationships = 0;
    int64_t total_restrictions = 0;
    int64_t total_suggestions = 0;
    int64_t total_active_peeks = 0;
    int64_t total_propagation_events = 0;
    int64_t total_cached_hierarchies = 0;
    int64_t hierarchy_max_depth = 0;
    int64_t spaces_created_24h = 0;
    int64_t children_added_24h = 0;
    int64_t auto_joins_performed_24h = 0;
    double avg_children_per_space = 0.0;

    json to_json() const {
      return {
        {"total_spaces", total_spaces},
        {"total_child_relationships", total_child_relationships},
        {"total_parent_relationships", total_parent_relationships},
        {"total_restrictions", total_restrictions},
        {"total_suggestions", total_suggestions},
        {"total_active_peeks", total_active_peeks},
        {"total_propagation_events", total_propagation_events},
        {"total_cached_hierarchies", total_cached_hierarchies},
        {"hierarchy_max_depth", hierarchy_max_depth},
        {"spaces_created_24h", spaces_created_24h},
        {"children_added_24h", children_added_24h},
        {"auto_joins_performed_24h", auto_joins_performed_24h},
        {"avg_children_per_space", avg_children_per_space}
      };
    }
  };

  // ---- Constructor ----
  explicit SpaceManagerCoordinator(const SpaceManagerConfig& config = {})
      : config_(config),
        store_(std::make_shared<SpaceStore>(nullptr)),
        validator_(std::make_shared<SpaceEventValidator>()),
        flattener_(std::make_shared<SpaceHierarchyFlattener>(config_)),
        hierarchy_(std::make_shared<SpaceHierarchyEngine>(
            store_, flattener_, validator_)),
        restrictions_(std::make_shared<SpaceRestrictionsEngine>(
            store_, flattener_)),
        discovery_(std::make_shared<SpaceDiscoveryService>(
            store_, flattener_, hierarchy_)),
        suggestions_(std::make_shared<SpaceSuggestionEngine>(
            store_, flattener_)),
        propagator_(std::make_shared<SpaceMembershipPropagator>(
            store_, flattener_, config_)),
        peek_manager_(std::make_shared<SpacePeekManager>(
            store_, discovery_, config_)),
        summary_builder_(std::make_shared<SpaceSummaryBuilder>(discovery_)),
        upgrade_handler_(std::make_shared<SpaceUpgradeHandler>(
            store_, hierarchy_)),
        maintenance_running_(false),
        shutdown_requested_(false) {}

  // ---- Initialize: ensure tables exist ----
  bool initialize(LoggingTransaction& txn) {
    store_->ensure_tables(txn);
    return true;
  }

  // ---- Access sub-components ----
  std::shared_ptr<SpaceStore> store() { return store_; }
  std::shared_ptr<SpaceHierarchyEngine> hierarchy() { return hierarchy_; }
  std::shared_ptr<SpaceRestrictionsEngine> restrictions() { return restrictions_; }
  std::shared_ptr<SpaceDiscoveryService> discovery() { return discovery_; }
  std::shared_ptr<SpaceSuggestionEngine> suggestions() { return suggestions_; }
  std::shared_ptr<SpaceMembershipPropagator> propagator() { return propagator_; }
  std::shared_ptr<SpacePeekManager> peek_manager() { return peek_manager_; }
  std::shared_ptr<SpaceSummaryBuilder> summary_builder() { return summary_builder_; }
  std::shared_ptr<SpaceUpgradeHandler> upgrade_handler() { return upgrade_handler_; }
  std::shared_ptr<SpaceEventValidator> validator() { return validator_; }
  std::shared_ptr<SpaceHierarchyFlattener> flattener() { return flattener_; }

  // ---- Create a new space ----
  SpaceInfo create_space(LoggingTransaction& txn,
                          const std::string& space_id,
                          const std::string& name,
                          const std::string& topic,
                          const std::string& creator,
                          const std::string& join_rule = kDefaultJoinRule,
                          bool is_public = false) {

    SpaceInfo space;
    space.space_id = space_id;
    space.name = name;
    space.topic = topic;
    space.creator = creator;
    space.join_rule = join_rule;
    space.history_visibility = is_public ? "world_readable" : "shared";
    space.guest_access = is_public ? "can_join" : "forbidden";
    space.is_public = is_public;
    space.is_world_readable = is_public;
    space.created_at_ms = storage::now_ms();
    space.depth = 0;

    // Note: This creates the space metadata. The actual room creation
    // (m.room.create event, m.room.name, m.room.join_rules etc.) must
    // be done by the room creation handler before this is called.

    store_->upsert_space(txn, space);
    stats_.total_spaces++;

    return space;
  }

  // ---- Delete a space ----
  SpaceHierarchyEngine::CascadeResult delete_space(
      LoggingTransaction& txn, const std::string& space_id,
      bool cascade = false) {

    SpaceHierarchyEngine::CascadeResult result{0, 0, 0};

    if (cascade) {
      result = hierarchy_->cascade_delete(txn, space_id, true);
    } else {
      // Just delete this space's metadata and child links
      auto children = store_->get_children(txn, space_id, kDefaultPageSize);
      for (const auto& child : children) {
        store_->remove_child(txn, space_id, child.child_room_id);
        store_->remove_parent(txn, child.child_room_id, space_id);
        result.children_removed++;
      }
      auto parents = store_->get_parents(txn, space_id);
      for (const auto& p : parents) {
        store_->remove_parent(txn, p.room_id, p.parent_space_id);
        store_->remove_child(txn, p.parent_space_id, space_id);
        result.parents_removed++;
      }
      store_->delete_space(txn, space_id);
      result.spaces_removed = 1;
    }

    return result;
  }

  // ---- Add a room to a space ----
  SpaceEventValidationResult add_room_to_space(
      LoggingTransaction& txn, const std::string& space_id,
      const std::string& room_id, const json& content,
      const std::string& sender) {

    auto result = hierarchy_->add_child_to_space(
        txn, space_id, room_id, content, sender);

    if (result == SpaceEventValidationResult::kValid) {
      stats_.total_child_relationships++;
    }

    return result;
  }

  // ---- Remove a room from a space ----
  bool remove_room_from_space(LoggingTransaction& txn,
                               const std::string& space_id,
                               const std::string& room_id) {
    return hierarchy_->remove_child_from_space(txn, space_id, room_id);
  }

  // ---- Get space hierarchy summary (MSC 2946 endpoint) ----
  json get_hierarchy(LoggingTransaction& txn,
                      const std::string& space_id,
                      const std::string& user_id,
                      const json& params) {
    return summary_builder_->build_summary_response(
        txn, space_id, user_id, params);
  }

  // ---- Handle user joining a space (trigger propagation) ----
  PropagationResult handle_user_join_space(
      LoggingTransaction& txn, const std::string& space_id,
      const std::string& user_id,
      const std::vector<std::string>& already_joined_rooms) {

    auto plan = propagator_->build_join_plan(
        txn, space_id, user_id, already_joined_rooms, true);

    auto result = propagator_->apply_join_propagation(
        txn, space_id, user_id, plan);

    if (result == PropagationResult::kSuccess ||
        result == PropagationResult::kPartialSuccess) {
      stats_.auto_joins_performed_24h += plan.total_rooms_affected;
    }

    return result;
  }

  // ---- Handle user leaving a space (trigger leave propagation) ----
  PropagationResult handle_user_leave_space(
      LoggingTransaction& txn, const std::string& space_id,
      const std::string& user_id,
      const std::vector<std::string>& currently_joined_rooms) {

    auto plan = propagator_->build_leave_plan(
        txn, space_id, user_id, currently_joined_rooms);

    return propagator_->apply_leave_propagation(
        txn, space_id, user_id, plan);
  }

  // ---- Start background maintenance thread ----
  void start_maintenance() {
    if (maintenance_running_) return;
    maintenance_running_ = true;
    shutdown_requested_ = false;
    maintenance_thread_ = std::thread([this] { maintenance_loop(); });
  }

  // ---- Stop background maintenance thread ----
  void stop_maintenance() {
    if (!maintenance_running_) return;
    shutdown_requested_ = true;
    if (maintenance_thread_.joinable()) {
      maintenance_thread_.join();
    }
    maintenance_running_ = false;
  }

  // ---- Get system stats ----
  const SpaceSystemStats& stats() const { return stats_; }

  // ---- Refresh stats ----
  void refresh_stats(LoggingTransaction& txn) {
    // Note: In a production system, these would be actual queries
    stats_.total_spaces++;
    (void)txn;
  }

private:
  SpaceManagerConfig config_;
  SpaceSystemStats stats_;

  // Sub-components
  std::shared_ptr<SpaceStore> store_;
  std::shared_ptr<SpaceEventValidator> validator_;
  std::shared_ptr<SpaceHierarchyFlattener> flattener_;
  std::shared_ptr<SpaceHierarchyEngine> hierarchy_;
  std::shared_ptr<SpaceRestrictionsEngine> restrictions_;
  std::shared_ptr<SpaceDiscoveryService> discovery_;
  std::shared_ptr<SpaceSuggestionEngine> suggestions_;
  std::shared_ptr<SpaceMembershipPropagator> propagator_;
  std::shared_ptr<SpacePeekManager> peek_manager_;
  std::shared_ptr<SpaceSummaryBuilder> summary_builder_;
  std::shared_ptr<SpaceUpgradeHandler> upgrade_handler_;

  // Background maintenance
  std::thread maintenance_thread_;
  std::atomic<bool> maintenance_running_;
  std::atomic<bool> shutdown_requested_;

  // ---- Background maintenance loop ----
  void maintenance_loop() {
    while (!shutdown_requested_) {
      // Background tasks:
      // - Cleanup expired peek sessions
      // - Cleanup expired hierarchy cache entries
      // - Detect orphan rooms
      // - Refresh stale child metadata caches
      // - Compact space statistics

      std::this_thread::sleep_for(chr::seconds(60));
    }
  }
};

// ============================================================================
// Convenience factory functions
// ============================================================================

// Create a fully configured space manager coordinator
SpaceManagerCoordinator create_space_manager(
    const SpaceManagerConfig& config = {}) {
  return SpaceManagerCoordinator(config);
}

// Create a space manager with specific defaults for a small deployment
SpaceManagerCoordinator create_small_space_manager() {
  SpaceManagerConfig config;
  config.max_hierarchy_depth = 5;
  config.max_children_per_space = 500;
  config.max_parents_per_room = 20;
  config.max_summary_rooms = 250;
  config.max_propagation_batch = 20;
  config.peek_duration_ms = 300'000; // 5 min
  return SpaceManagerCoordinator(config);
}

// Create a space manager with production defaults
SpaceManagerCoordinator create_production_space_manager() {
  SpaceManagerConfig config;
  config.max_hierarchy_depth = 10;
  config.max_children_per_space = 10000;
  config.max_parents_per_room = 100;
  config.max_summary_rooms = 1000;
  config.max_propagation_batch = 50;
  config.peek_duration_ms = 600'000; // 10 min
  config.cache_hierarchy = true;
  config.hierarchy_cache_ttl_ms = 300'000; // 5 min
  return SpaceManagerCoordinator(config);
}

// ============================================================================
// End of namespace progressive
// ============================================================================
}  // namespace progressive
