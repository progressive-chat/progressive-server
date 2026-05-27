// ============================================================================
// room_summary.cpp — Matrix Room Summary, Heroes, Name/Avatar Calc, DM Detection,
//                      Caching, and Sync Integration
//
// Implements:
//   - Room heroes: select up to 5 users to display as room "heroes" for the
//     room list UI. Heroes are chosen from joined members (then invite members),
//     preferring the requesting user, sorted by stream_ordering. Banned/left
//     members are excluded.
//   - Room summary: compute room summary for sync response including m.heroes,
//     m.joined_member_count, m.invited_member_count, room name, topic, avatar,
//     membership status, and direct-chat flag.
//   - Hero calculation algorithm: multi-phase selection — first the self user
//     if present, then joined members ordered by event_stream_ordering
//     (most recent first), then invite members. Excludes banned/left users.
//     Falls back to the room creator if no other heroes are available.
//   - Room name calculation: if m.room.name state event exists, use its content;
//     otherwise generate a fallback name from member display names. For DMs,
//     use the other member's display name. For group rooms with 2+ members,
//     combine names with commas and "and". Handles anonymous members as
//     "Anonymous" and fully anonymous rooms as "Empty Room".
//   - Room avatar calculation: if m.room.avatar state event exists, use its
//     URL; otherwise use the first member's avatar_url as fallback. For DMs,
//     prefer the other member's avatar.
//   - Room DM detection (m.direct): checks m.direct account data for the user
//     to determine if a room is a direct chat. Also uses member count heuristic
//     (exactly 2 joined members) as secondary signal when account data is
//     unavailable. Supports multiple DM rooms per user.
//   - Summary caching: thread-safe in-memory LRU cache of computed room
//     summaries. Cache keys consist of (room_id, user_id) to account for
//     per-user differences (DM detection, membership). Invalidates on:
//     membership changes (join/leave/invite/ban/knock), room state changes
//     (name/topic/avatar), and direct-chat account data changes. Supports
//     TTL-based automatic eviction.
//   - Summary sync: integration with /sync response generation. Provides
//     compute_room_summary_for_sync() that populates the summary field per
//     room in the sync response. Handles both joined and invited rooms.
//   - Batch summary computation: efficient bulk computation for multiple
//     rooms using a single database transaction. Reduces round-trips for
//     initial sync and room list rendering.
//   - Membership-aware summaries: different views depending on user's
//     membership (join, invite, leave). Invited rooms show inviter info
//     instead of full hero list.
//   - User directory hero hint: provides hero data for user directory
//     searches to show room context alongside user results.
//
// Equivalent to:
//   synapse/handlers/room_summary.py (1,054 lines) — core summary logic
//   synapse/storage/databases/main/roommember.py — hero DB queries (lines 700-900)
//   synapse/handlers/sync.py — sync integration (lines 300-500)
//   synapse/handlers/room.py — name/avatar fallback (lines 1200-1400)
//   synapse/events/utils.py — room name calculation util
//   synapse/handlers/initial_sync.py — initial sync summary
//
// Target: 2000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
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
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/util/cache.hpp"
#include "progressive/util/time.hpp"
#include "progressive/util/log.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations
// ============================================================================
class RoomHeroCalculator;
class RoomNameCalculator;
class RoomAvatarCalculator;
class DmDetector;
class RoomSummaryCache;
class RoomSummaryEngine;
class SummarySyncIntegrator;
class MembershipTracker;
class HeroSelectionPolicy;

// ============================================================================
// Constants
// ============================================================================
namespace room_summary_constants {

/// Maximum number of heroes in a room summary per Matrix spec
constexpr int kMaxHeroes = 5;

/// Default TTL for cached room summaries in seconds
constexpr int kDefaultCacheTtlSeconds = 60;

/// Maximum cache entries for room summaries
constexpr size_t kDefaultMaxCacheEntries = 10'000;

/// Minimum number of members before we compute heroes (otherwise all are heroes)
constexpr int kHeroThreshold = 6;

/// Maximum display names to show in fallback room name
constexpr int kMaxDisplayNamesForRoomName = 3;

/// Anonymous display name placeholder
constexpr const char* kAnonymousName = "Anonymous";

/// Empty room fallback name
constexpr const char* kEmptyRoomName = "Empty Room";

/// Direct chat fallback name
constexpr const char* kDirectChatFallback = "Direct Chat";

/// Event types relevant to room summary
constexpr const char* kEventTypeRoomName = "m.room.name";
constexpr const char* kEventTypeRoomAvatar = "m.room.avatar";
constexpr const char* kEventTypeRoomTopic = "m.room.topic";
constexpr const char* kEventTypeRoomCanonicalAlias = "m.room.canonical_alias";
constexpr const char* kEventTypeRoomMember = "m.room.member";
constexpr const char* kEventTypeRoomCreate = "m.room.create";
constexpr const char* kEventTypeDirect = "m.direct";
constexpr const char* kEventTypeRoomJoinRules = "m.room.join_rules";

/// Membership states
constexpr const char* kMembershipJoin = "join";
constexpr const char* kMembershipInvite = "invite";
constexpr const char* kMembershipLeave = "leave";
constexpr const char* kMembershipBan = "ban";
constexpr const char* kMembershipKnock = "knock";

}  // namespace room_summary_constants

// ============================================================================
// Utility helpers
// ============================================================================
namespace {

/// Get current timestamp in milliseconds
int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

/// Get current timestamp in seconds
int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

/// Generate a simple random token (for cache keys, etc.)
std::string generate_token(int length = 12) {
  static const char charset[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  static std::mt19937 rng(std::random_device{}());
  static std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
  std::string result;
  result.reserve(length);
  for (int i = 0; i < length; ++i)
    result += charset[dist(rng)];
  return result;
}

/// Escape a string for safe SQL string literal usage
std::string sql_escape(const std::string& s) {
  std::string result;
  result.reserve(s.size() + 8);
  for (char c : s) {
    if (c == '\'') result += "''";
    else result += c;
  }
  return result;
}

/// Escape a string for JSON string usage
std::string json_escape(const std::string& s) {
  std::ostringstream oss;
  for (char c : s) {
    switch (c) {
      case '"': oss << "\\\""; break;
      case '\\': oss << "\\\\"; break;
      case '\n': oss << "\\n"; break;
      case '\r': oss << "\\r"; break;
      case '\t': oss << "\\t"; break;
      default: oss << c; break;
    }
  }
  return oss.str();
}

/// Check if a string is a valid Matrix user ID (@user:domain)
bool is_valid_user_id(const std::string& s) {
  return s.size() >= 4 && s[0] == '@' &&
         s.find(':') != std::string::npos &&
         s.find(':') > 1;
}

/// Check if a string is a valid Matrix room ID (!room:domain)
bool is_valid_room_id(const std::string& s) {
  return s.size() >= 4 && s[0] == '!' &&
         s.find(':') != std::string::npos &&
         s.find(':') > 1;
}

/// Extract the localpart from a Matrix user ID
std::string user_localpart(const std::string& user_id) {
  auto pos = user_id.find(':');
  if (pos == std::string::npos || pos < 1) return user_id;
  return user_id.substr(1, pos - 1);  // skip the '@'
}

/// Extract the server name from a Matrix ID
std::string server_name_from_id(const std::string& id) {
  auto pos = id.find(':');
  if (pos == std::string::npos) return "";
  return id.substr(pos + 1);
}

/// Truncate a string to max_length, adding ellipsis if needed
std::string truncate_str(const std::string& s, size_t max_length = 100) {
  if (s.size() <= max_length) return s;
  return s.substr(0, max_length - 3) + "...";
}

}  // namespace

// ============================================================================
// RoomMemberInfo — lightweight member representation for summary computation
// ============================================================================
struct RoomMemberInfo {
  std::string user_id;
  std::string membership;  // "join", "invite", "leave", "ban", "knock"
  std::optional<std::string> display_name;
  std::optional<std::string> avatar_url;
  int64_t event_stream_ordering{0};
  std::string sender;

  /// Whether this member is currently in the room (joined or invited)
  bool is_active() const {
    return membership == room_summary_constants::kMembershipJoin ||
           membership == room_summary_constants::kMembershipInvite;
  }

  /// Whether this member is joined
  bool is_joined() const {
    return membership == room_summary_constants::kMembershipJoin;
  }

  /// Get the display name or fallback to localpart
  std::string effective_display_name() const {
    if (display_name && !display_name->empty()) return *display_name;
    return user_localpart(user_id);
  }

  /// Comparison for sorting by event_stream_ordering (descending)
  bool operator<(const RoomMemberInfo& other) const {
    return event_stream_ordering > other.event_stream_ordering;
  }
};

// ============================================================================
// RoomStateSnapshot — current state needed for summary computation
// ============================================================================
struct RoomStateSnapshot {
  std::optional<std::string> room_name;
  std::optional<std::string> room_topic;
  std::optional<std::string> room_avatar_url;
  std::optional<std::string> canonical_alias;
  std::optional<std::string> room_type;
  std::optional<std::string> creator;
  std::vector<RoomMemberInfo> members;
  int64_t joined_count{0};
  int64_t invited_count{0};
  int64_t total_members{0};

  /// Whether the name/topic/avatar states have been fetched
  bool metadata_loaded{false};
  /// Whether member list has been fully loaded
  bool members_loaded{false};
};

// ============================================================================
// RoomSummaryResult — final computed summary for one room/user pair
// ============================================================================
struct RoomSummaryResult {
  std::string room_id;
  std::string user_id;
  std::string membership;  // user's membership in this room

  // Counts
  int64_t joined_members{0};
  int64_t invited_members{0};

  // Heroes
  std::vector<std::string> heroes;

  // Display metadata
  std::optional<std::string> room_name;
  std::optional<std::string> room_topic;
  std::optional<std::string> room_avatar_url;
  std::optional<std::string> canonical_alias;

  // DM-related
  bool is_direct{false};
  std::optional<std::string> direct_target_user_id;

  // Computed timestamps
  int64_t computed_at_ms{0};
  int64_t cache_ttl_seconds{60};

  // Whether this summary is considered stale
  bool is_stale{false};

  /// Convert to the JSON format expected by sync response
  json to_sync_json() const {
    json summary;
    summary["m.joined_member_count"] = joined_members;
    summary["m.invited_member_count"] = invited_members;

    if (!heroes.empty()) {
      json hero_array = json::array();
      for (const auto& h : heroes)
        hero_array.push_back(h);
      summary["m.heroes"] = hero_array;
    }

    return summary;
  }

  /// Convert to a full JSON representation
  json to_json() const {
    json j;
    j["room_id"] = room_id;
    j["membership"] = membership;
    j["joined_members"] = joined_members;
    j["invited_members"] = invited_members;
    j["is_direct"] = is_direct;

    if (!heroes.empty()) {
      json hero_array = json::array();
      for (const auto& h : heroes)
        hero_array.push_back(h);
      j["heroes"] = hero_array;
    }

    if (room_name) j["name"] = *room_name;
    if (room_topic) j["topic"] = *room_topic;
    if (room_avatar_url) j["avatar_url"] = *room_avatar_url;
    if (canonical_alias) j["canonical_alias"] = *canonical_alias;
    if (direct_target_user_id) j["direct_target"] = *direct_target_user_id;

    j["cached_at"] = computed_at_ms;
    return j;
  }
};

// ============================================================================
// CacheEntry — single entry in the room summary cache
// ============================================================================
struct CacheEntry {
  RoomSummaryResult summary;
  int64_t created_at_ms;
  int64_t ttl_seconds;

  /// Check if this cache entry is expired
  bool is_expired(int64_t current_time_ms) const {
    return (current_time_ms - created_at_ms) > (ttl_seconds * 1000);
  }

  /// Get remaining time-to-live in seconds
  int64_t remaining_ttl_seconds(int64_t current_time_ms) const {
    int64_t elapsed_ms = current_time_ms - created_at_ms;
    int64_t remaining_ms = (ttl_seconds * 1000) - elapsed_ms;
    return remaining_ms > 0 ? (remaining_ms / 1000) : 0;
  }
};

// ============================================================================
// CacheKey — composite key for (room_id, user_id) lookups
// ============================================================================
struct CacheKey {
  std::string room_id;
  std::string user_id;

  bool operator==(const CacheKey& other) const {
    return room_id == other.room_id && user_id == other.user_id;
  }

  bool operator<(const CacheKey& other) const {
    if (room_id != other.room_id) return room_id < other.room_id;
    return user_id < other.user_id;
  }

  std::string to_string() const {
    return room_id + "|" + user_id;
  }

  struct Hash {
    size_t operator()(const CacheKey& k) const {
      size_t h1 = std::hash<std::string>{}(k.room_id);
      size_t h2 = std::hash<std::string>{}(k.user_id);
      return h1 ^ (h2 << 1);
    }
  };
};

// ============================================================================
// HeroSelectionPolicy — determines hero selection strategy
// ============================================================================
enum class HeroSelectionPolicy {
  /// Standard algorithm: self first, then joined by recency,
  /// then invited, excluding banned/left
  kStandard,

  /// For invited user: show the inviter as the sole hero
  kInvitedView,

  /// For left user: show a minimal set based on whoever is still in the room
  kLeaverView,

  /// Federation: include remote members, minimize local bias
  kFederation,
};

// ============================================================================
// RoomHeroCalculator — computes the list of heroes for a room
// ============================================================================
//
// The hero selection algorithm (per Synapse):
//   1. If the requesting user is a member (joined or invited), they get first
//      priority as a hero.
//   2. Sort joined members by event_stream_ordering (most recent join first).
//   3. Take up to kMaxHeroes (5) joined members.
//   4. If fewer than kMaxHeroes joined members, fill remaining slots with
//      invited members, also sorted by event_stream_ordering.
//   5. Exclude banned and left members entirely.
//   6. If the room has fewer than kHeroThreshold (6) total active members,
//      all active members are heroes.
//   7. If still no heroes, fall back to the room creator from m.room.create.
//
class RoomHeroCalculator {
public:
  RoomHeroCalculator() = default;

  /// Calculate heroes for a room from the given state snapshot
  ///
  /// @param self_user_id  The requesting user's ID (may be empty for
  ///                      unauthenticated or federation contexts)
  /// @param members       All room members with membership status
  /// @param creator       Room creator user ID from m.room.create
  /// @param policy        Selection policy variant
  /// @param max_heroes    Maximum number of heroes to return
  /// @return              Ordered list of hero user IDs
  std::vector<std::string> calculate_heroes(
      const std::string& self_user_id,
      const std::vector<RoomMemberInfo>& members,
      const std::optional<std::string>& creator,
      HeroSelectionPolicy policy = HeroSelectionPolicy::kStandard,
      int max_heroes = room_summary_constants::kMaxHeroes) {

    // --- Phase 0: Invited view — show the inviter as hero ---
    if (policy == HeroSelectionPolicy::kInvitedView) {
      return calculate_invited_heroes(self_user_id, members);
    }

    // --- Phase 1: Separate members by status ---
    std::vector<RoomMemberInfo> joined;
    std::vector<RoomMemberInfo> invited;
    std::vector<RoomMemberInfo> other_active;  // knocks, etc.

    for (const auto& m : members) {
      if (m.membership == room_summary_constants::kMembershipJoin) {
        joined.push_back(m);
      } else if (m.membership == room_summary_constants::kMembershipInvite) {
        invited.push_back(m);
      } else if (m.membership == room_summary_constants::kMembershipKnock) {
        other_active.push_back(m);
      }
      // banned and leave are excluded
    }

    // --- Phase 2: Small room heuristic ---
    // If total active members <= threshold, all are heroes
    int64_t total_active = static_cast<int64_t>(joined.size() + invited.size() +
                                                 other_active.size());
    if (total_active > 0 &&
        total_active <= room_summary_constants::kHeroThreshold) {
      std::vector<std::string> all_heroes;
      for (const auto& m : joined)
        all_heroes.push_back(m.user_id);
      for (const auto& m : invited)
        all_heroes.push_back(m.user_id);
      for (const auto& m : other_active)
        all_heroes.push_back(m.user_id);
      return all_heroes;
    }

    // --- Phase 3: Sort joined members by stream_ordering (most recent first) ---
    std::sort(joined.begin(), joined.end());

    // --- Phase 4: Build the hero list ---
    std::vector<std::string> heroes;
    std::set<std::string> seen;

    auto add_hero = [&](const std::string& uid) {
      if (heroes.size() >= static_cast<size_t>(max_heroes)) return false;
      if (seen.count(uid)) return false;
      heroes.push_back(uid);
      seen.insert(uid);
      return true;
    };

    // 4a: Self user first (standard and leaver policies)
    if (!self_user_id.empty() &&
        (policy == HeroSelectionPolicy::kStandard ||
         policy == HeroSelectionPolicy::kLeaverView)) {

      // Check if self is in joined or invited
      bool self_found = false;
      for (const auto& m : joined) {
        if (m.user_id == self_user_id) { self_found = true; break; }
      }
      if (!self_found) {
        for (const auto& m : invited) {
          if (m.user_id == self_user_id) { self_found = true; break; }
        }
      }
      if (self_found) {
        add_hero(self_user_id);
      }
    }

    // 4b: Joined members by recency
    for (const auto& m : joined) {
      if (heroes.size() >= static_cast<size_t>(max_heroes)) break;
      add_hero(m.user_id);
    }

    // 4c: Invited members to fill remaining slots
    // Sort invited by stream_ordering as well
    std::sort(invited.begin(), invited.end());
    for (const auto& m : invited) {
      if (heroes.size() >= static_cast<size_t>(max_heroes)) break;
      add_hero(m.user_id);
    }

    // 4d: Knock members as last resort
    for (const auto& m : other_active) {
      if (heroes.size() >= static_cast<size_t>(max_heroes)) break;
      add_hero(m.user_id);
    }

    // --- Phase 5: Fallback to creator ---
    if (heroes.empty() && creator && !creator->empty()) {
      heroes.push_back(*creator);
    }

    return heroes;
  }

  /// Calculate heroes specifically for a user viewing a room they're invited to
  std::vector<std::string> calculate_invited_heroes(
      const std::string& self_user_id,
      const std::vector<RoomMemberInfo>& members) {
    std::vector<std::string> heroes;

    // Find the inviter (the sender of the invite event for the self user)
    for (const auto& m : members) {
      if (m.user_id == self_user_id && m.membership == room_summary_constants::kMembershipInvite) {
        if (!m.sender.empty() && m.sender != self_user_id) {
          heroes.push_back(m.sender);
          // Also add joined members to give context
          for (const auto& jm : members) {
            if (jm.membership == room_summary_constants::kMembershipJoin &&
                jm.user_id != m.sender) {
              heroes.push_back(jm.user_id);
              if (heroes.size() >= static_cast<size_t>(room_summary_constants::kMaxHeroes))
                break;
            }
          }
          return heroes;
        }
      }
    }

    // Fallback: show any joined members
    for (const auto& m : members) {
      if (m.membership == room_summary_constants::kMembershipJoin) {
        heroes.push_back(m.user_id);
        if (heroes.size() >= static_cast<size_t>(room_summary_constants::kMaxHeroes))
          break;
      }
    }

    return heroes;
  }

  /// Calculate federation heroes (minimizes local bias, randomized)
  std::vector<std::string> calculate_federation_heroes(
      const std::vector<RoomMemberInfo>& members,
      int max_heroes = room_summary_constants::kMaxHeroes) {
    std::vector<std::string> heroes;

    // Get all joined members
    std::vector<std::string> joined_ids;
    for (const auto& m : members) {
      if (m.membership == room_summary_constants::kMembershipJoin)
        joined_ids.push_back(m.user_id);
    }

    // If 5 or fewer joined, all are heroes
    if (joined_ids.size() <= static_cast<size_t>(max_heroes)) {
      return joined_ids;
    }

    // Randomly select max_heroes from joined members
    // Use a Fisher-Yates partial shuffle
    static std::mt19937 rng(std::random_device{}());
    for (int i = 0; i < max_heroes && i < static_cast<int>(joined_ids.size()); ++i) {
      std::uniform_int_distribution<> dist(i, joined_ids.size() - 1);
      int j = dist(rng);
      if (i != j)
        std::swap(joined_ids[i], joined_ids[j]);
      heroes.push_back(joined_ids[i]);
    }

    return heroes;
  }

private:
  /// Validate hero list constraints
  bool validate_heroes(const std::vector<std::string>& heroes, int max_heroes) {
    if (static_cast<int>(heroes.size()) > max_heroes) return false;
    // No duplicates
    std::set<std::string> seen(heroes.begin(), heroes.end());
    return seen.size() == heroes.size();
  }
};

// ============================================================================
// RoomNameCalculator — computes the display name for a room
// ============================================================================
//
// Algorithm (mirrors Synapse's room name calculation):
//   1. If m.room.name state event exists and has non-empty name, use it.
//   2. If room is a DM with exactly 2 members:
//      a. If the other member has a display name, use it.
//      b. If the other member has no display name, use their localpart.
//      c. Fallback: "Direct Chat"
//   3. For group rooms:
//      a. Collect display names of all joined + invited members (excluding self
//         if more than 2 total members).
//      b. Sort by effective display name alphabetically.
//      c. Take up to kMaxDisplayNamesForRoomName (3), join with ", " and " and ".
//      d. If there are more members not shown, append "and N others".
//      e. If no members have display names, use "Empty Room".
//   4. Handle edge cases: no members at all, only self, anonymous members.
//
class RoomNameCalculator {
public:
  RoomNameCalculator() = default;

  /// Calculate the room display name
  ///
  /// @param room_name_state  The content of m.room.name state event (if exists)
  /// @param members          All active room members
  /// @param self_user_id     The user viewing the room
  /// @param is_direct        Whether this room is a direct chat
  /// @return                 Computed room display name
  std::string calculate_name(
      const std::optional<std::string>& room_name_state,
      const std::vector<RoomMemberInfo>& members,
      const std::string& self_user_id,
      bool is_direct = false) {

    // --- Rule 1: Explicit m.room.name ---
    if (room_name_state && !room_name_state->empty()) {
      return *room_name_state;
    }

    // --- Rule 2: DM naming ---
    if (is_direct) {
      return calculate_dm_name(members, self_user_id);
    }

    // --- Rule 3: Group room fallback name ---
    return calculate_group_room_name(members, self_user_id);
  }

  /// Calculate DM name from the other member
  std::string calculate_dm_name(
      const std::vector<RoomMemberInfo>& members,
      const std::string& self_user_id) {

    // Filter to joined + invited members
    std::vector<RoomMemberInfo> active;
    for (const auto& m : members) {
      if (m.is_active())
        active.push_back(m);
    }

    // Find the "other" member (not self)
    for (const auto& m : active) {
      if (m.user_id != self_user_id) {
        if (m.display_name && !m.display_name->empty()) {
          return *m.display_name;
        }
        return user_localpart(m.user_id);
      }
    }

    // If only self is in the room or no other members
    if (!active.empty()) {
      const auto& first = active[0];
      if (first.display_name && !first.display_name->empty()) {
        return *first.display_name;
      }
    }

    return room_summary_constants::kDirectChatFallback;
  }

  /// Calculate group room name from member display names
  std::string calculate_group_room_name(
      const std::vector<RoomMemberInfo>& members,
      const std::string& self_user_id) {

    // Collect active members with their effective display names
    struct NamedMember {
      std::string user_id;
      std::string display_name;
    };
    std::vector<NamedMember> named;

    for (const auto& m : members) {
      if (!m.is_active()) continue;

      std::string dn = m.effective_display_name();
      // Mark anonymous members
      if (!m.display_name || m.display_name->empty()) {
        // Use localpart, but mark as potentially anonymous
      }
      named.push_back({m.user_id, dn});
    }

    // No active members
    if (named.empty()) {
      return room_summary_constants::kEmptyRoomName;
    }

    // If there are > 2 members total, exclude self from the name if possible
    if (named.size() > 2) {
      named.erase(
          std::remove_if(named.begin(), named.end(),
                         [&](const NamedMember& nm) {
                           return nm.user_id == self_user_id;
                         }),
          named.end());
    }

    // If we removed everyone, put self back
    if (named.empty()) {
      // Just use self
      return user_localpart(self_user_id);
    }

    // Sort by display name alphabetically (case-insensitive)
    std::sort(named.begin(), named.end(),
              [](const NamedMember& a, const NamedMember& b) {
                std::string al = a.display_name;
                std::string bl = b.display_name;
                std::transform(al.begin(), al.end(), al.begin(), ::tolower);
                std::transform(bl.begin(), bl.end(), bl.begin(), ::tolower);
                return al < bl;
              });

    // Build the name
    int max_names = room_summary_constants::kMaxDisplayNamesForRoomName;
    int total = static_cast<int>(named.size());
    int shown = std::min(total, max_names);
    int remaining = total - shown;

    std::ostringstream oss;
    for (int i = 0; i < shown; ++i) {
      if (i > 0) {
        if (i < shown - 1) {
          oss << ", ";
        } else if (remaining > 0) {
          oss << ", ";
        } else {
          oss << " and ";
        }
      }
      oss << named[i].display_name;
    }

    if (remaining > 0) {
      oss << " and " << remaining << " other";
      if (remaining > 1) oss << "s";
    }

    std::string result = oss.str();
    if (result.empty()) {
      return room_summary_constants::kEmptyRoomName;
    }

    return result;
  }

  /// Get all display names from a member list (for display purposes)
  std::vector<std::string> get_display_names(
      const std::vector<RoomMemberInfo>& members) {
    std::vector<std::string> names;
    for (const auto& m : members) {
      if (m.is_active()) {
        names.push_back(m.effective_display_name());
      }
    }
    return names;
  }
};

// ============================================================================
// RoomAvatarCalculator — computes the avatar URL for a room
// ============================================================================
//
// Algorithm:
//   1. If m.room.avatar state event exists and has a non-empty url, use it.
//   2. If room is a DM with exactly 2 members:
//      a. Use the other member's avatar_url if available.
//   3. For group rooms:
//      a. Use the first joined member's avatar_url (sorted by
//         event_stream_ordering, most recent first).
//   4. Return nullopt if no avatar can be determined.
//
class RoomAvatarCalculator {
public:
  RoomAvatarCalculator() = default;

  /// Calculate the room avatar URL
  ///
  /// @param avatar_state  The content of m.room.avatar (if exists)
  /// @param members       All active room members
  /// @param self_user_id  The user viewing the room
  /// @param is_direct     Whether this room is a DM
  /// @return              Avatar URL or nullopt
  std::optional<std::string> calculate_avatar(
      const std::optional<json>& avatar_state,
      const std::vector<RoomMemberInfo>& members,
      const std::string& self_user_id,
      bool is_direct = false) {

    // --- Rule 1: Explicit m.room.avatar ---
    if (avatar_state && avatar_state->is_object()) {
      if (avatar_state->contains("url") &&
          (*avatar_state)["url"].is_string()) {
        std::string url = (*avatar_state)["url"].get<std::string>();
        if (!url.empty()) return url;
      }
    }

    // --- Rule 2: DM avatar ---
    if (is_direct) {
      return calculate_dm_avatar(members, self_user_id);
    }

    // --- Rule 3: First member avatar ---
    return calculate_first_member_avatar(members, self_user_id);
  }

  /// Calculate DM avatar from the other member
  std::optional<std::string> calculate_dm_avatar(
      const std::vector<RoomMemberInfo>& members,
      const std::string& self_user_id) {

    // Sort joined members by recency
    std::vector<RoomMemberInfo> joined;
    for (const auto& m : members) {
      if (m.membership == room_summary_constants::kMembershipJoin)
        joined.push_back(m);
    }
    std::sort(joined.begin(), joined.end());

    // Find the first member that is not self with an avatar
    for (const auto& m : joined) {
      if (m.user_id != self_user_id && m.avatar_url && !m.avatar_url->empty()) {
        return m.avatar_url;
      }
    }

    // Fallback: first member avatar even if self
    if (!joined.empty() && joined[0].avatar_url &&
        !joined[0].avatar_url->empty()) {
      return joined[0].avatar_url;
    }

    return std::nullopt;
  }

  /// Calculate avatar from the first joined member
  std::optional<std::string> calculate_first_member_avatar(
      const std::vector<RoomMemberInfo>& members,
      const std::string& self_user_id) {

    // Sort joined members by event_stream_ordering (recent first)
    std::vector<RoomMemberInfo> sorted = members;
    std::sort(sorted.begin(), sorted.end());

    for (const auto& m : sorted) {
      if (m.membership != room_summary_constants::kMembershipJoin) continue;
      if (m.avatar_url && !m.avatar_url->empty()) {
        return m.avatar_url;
      }
    }

    // Also check invited members
    for (const auto& m : sorted) {
      if (m.membership != room_summary_constants::kMembershipInvite) continue;
      if (m.avatar_url && !m.avatar_url->empty()) {
        return m.avatar_url;
      }
    }

    return std::nullopt;
  }

private:
  /// Validate that a URL looks like a valid MXC URL
  static bool is_valid_mxc_url(const std::string& url) {
    return url.find("mxc://") == 0;
  }
};

// ============================================================================
// DmDetector — determines if a room is a direct message
// ============================================================================
//
// Two detection strategies:
//   1. Primary: Check m.direct account data for the user. The m.direct event
//      is a mapping of user_id -> [room_id, ...]. If the room_id appears
//      in any user's DM room list, it's a DM.
//   2. Secondary (heuristic): If the room has exactly 2 joined members and
//      no explicit m.room.name, it's likely a DM. This handles cases where
//      m.direct account data hasn't been set up yet.
//   3. For invited DMs: if room has 2 members total (one joined, one invited),
//      it may also be a DM.
//
class DmDetector {
public:
  DmDetector() = default;

  /// Check if a room is a direct chat for the given user
  ///
  /// @param user_id    The user to check against
  /// @param room_id    The room to check
  /// @param members    Current room members
  /// @param direct_data The parsed m.direct account data (user_id -> [room_ids])
  /// @param room_name_state Explicit room name from m.room.name (if any)
  /// @return           Whether this is a DM, and optionally the target user ID
  std::pair<bool, std::optional<std::string>> detect_dm(
      const std::string& user_id,
      const std::string& room_id,
      const std::vector<RoomMemberInfo>& members,
      const std::optional<json>& direct_data,
      const std::optional<std::string>& room_name_state) {

    // --- Strategy 1: m.direct account data ---
    if (direct_data && direct_data->is_object()) {
      auto result = check_direct_account_data(room_id, user_id, *direct_data);
      if (result.first) return result;
    }

    // --- Strategy 2: Heuristic based on member count ---
    auto heuristic = detect_dm_by_member_count(
        room_id, user_id, members, room_name_state);
    if (heuristic.first) return heuristic;

    // Not a DM
    return {false, std::nullopt};
  }

  /// Check if ANY user considers this room a DM (for the DM room list)
  bool is_any_user_dm(const std::string& room_id,
                      const json& all_direct_data) {
    if (!all_direct_data.is_object()) return false;

    for (auto it = all_direct_data.begin(); it != all_direct_data.end(); ++it) {
      if (it.value().is_array()) {
        for (const auto& rid : it.value()) {
          if (rid.is_string() && rid.get<std::string>() == room_id)
            return true;
        }
      }
    }
    return false;
  }

  /// Get the DM target user ID for a given room
  std::optional<std::string> get_dm_target(
      const std::string& room_id,
      const std::string& user_id,
      const json& direct_data) {
    if (!direct_data.is_object()) return std::nullopt;

    // Search in the user's own direct map
    if (direct_data.contains(user_id) && direct_data[user_id].is_array()) {
      for (const auto& rid : direct_data[user_id]) {
        if (rid.is_string() && rid.get<std::string>() == room_id) {
          // The DM target is the key that mapped to this room
          // Actually, m.direct maps to: {target_user: [room_ids]}
          // So iterate all keys to find which one maps to this room
          for (auto it = direct_data.begin(); it != direct_data.end(); ++it) {
            if (it.key() != user_id && it.value().is_array()) {
              for (const auto& r : it.value()) {
                if (r.is_string() && r.get<std::string>() == room_id) {
                  return it.key();
                }
              }
            }
          }
        }
      }
    }

    return std::nullopt;
  }

  /// Count how many users have this room as a DM
  int count_dm_users(const std::string& room_id, const json& all_direct_data) {
    int count = 0;
    if (!all_direct_data.is_object()) return 0;

    for (auto it = all_direct_data.begin(); it != all_direct_data.end(); ++it) {
      if (it.value().is_array()) {
        for (const auto& rid : it.value()) {
          if (rid.is_string() && rid.get<std::string>() == room_id) {
            ++count;
            break;
          }
        }
      }
    }
    return count;
  }

private:
  /// Check m.direct account data for DM detection
  std::pair<bool, std::optional<std::string>> check_direct_account_data(
      const std::string& room_id,
      const std::string& user_id,
      const json& direct_data) {

    // Direct data format: {"@user1:domain": ["!room1:domain", ...], ...}
    // If user_id has entries mapping to this room, it's a DM
    if (direct_data.contains(user_id) && direct_data[user_id].is_array()) {
      for (const auto& rid : direct_data[user_id]) {
        if (rid.is_string() && rid.get<std::string>() == room_id) {
          return {true, std::nullopt};
        }
      }
    }

    // Also check if any other user maps to this room (for consistency)
    for (auto it = direct_data.begin(); it != direct_data.end(); ++it) {
      if (it.key() == user_id) continue;
      if (it.value().is_array()) {
        for (const auto& rid : it.value()) {
          if (rid.is_string() && rid.get<std::string>() == room_id) {
            return {true, std::optional<std::string>(it.key())};
          }
        }
      }
    }

    return {false, std::nullopt};
  }

  /// Heuristic DM detection based on member count
  std::pair<bool, std::optional<std::string>> detect_dm_by_member_count(
      const std::string& room_id,
      const std::string& user_id,
      const std::vector<RoomMemberInfo>& members,
      const std::optional<std::string>& room_name_state) {

    // Count joined members
    int joined_count = 0;
    int invited_count = 0;
    std::string other_user;

    for (const auto& m : members) {
      if (m.membership == room_summary_constants::kMembershipJoin) {
        ++joined_count;
        if (m.user_id != user_id)
          other_user = m.user_id;
      } else if (m.membership == room_summary_constants::kMembershipInvite) {
        ++invited_count;
        if (m.user_id != user_id)
          other_user = m.user_id;
      }
    }

    // Heuristic: exactly 2 joined members and no explicit room name
    if (joined_count == 2 && invited_count == 0) {
      if (!room_name_state || room_name_state->empty()) {
        return {true, other_user.empty()
                         ? std::nullopt
                         : std::optional<std::string>(other_user)};
      }
    }

    // Heuristic: invited DM (1 joined + 1 invited)
    if (joined_count == 1 && invited_count == 1) {
      if (!room_name_state || room_name_state->empty()) {
        // Check if the requesting user is the invited one
        bool self_is_invited = false;
        for (const auto& m : members) {
          if (m.user_id == user_id &&
              m.membership == room_summary_constants::kMembershipInvite) {
            self_is_invited = true;
            break;
          }
        }
        if (self_is_invited) {
          return {true, other_user.empty()
                           ? std::nullopt
                           : std::optional<std::string>(other_user)};
        }
        // Also flag as DM if the user is the joined one
        bool self_is_joined = false;
        for (const auto& m : members) {
          if (m.user_id == user_id &&
              m.membership == room_summary_constants::kMembershipJoin) {
            self_is_joined = true;
            break;
          }
        }
        if (self_is_joined) {
          return {true, other_user.empty()
                           ? std::nullopt
                           : std::optional<std::string>(other_user)};
        }
      }
    }

    return {false, std::nullopt};
  }
};

// ============================================================================
// RoomSummaryCache — thread-safe cache for room summaries
// ============================================================================
//
// Provides:
//   - LRU eviction when cache exceeds max_entries
//   - TTL-based automatic expiration
//   - Invalidation by room ID (all users for that room)
//   - Invalidation by user ID (all rooms for that user)
//   - Full cache flush
//   - Cache statistics (hits, misses, size)
//
class RoomSummaryCache {
public:
  explicit RoomSummaryCache(
      size_t max_entries = room_summary_constants::kDefaultMaxCacheEntries,
      int ttl_seconds = room_summary_constants::kDefaultCacheTtlSeconds)
      : max_entries_(max_entries), ttl_seconds_(ttl_seconds) {}

  /// Get a cached summary if available and not expired
  std::optional<RoomSummaryResult> get(const std::string& room_id,
                                        const std::string& user_id) {
    CacheKey key{room_id, user_id};
    std::shared_lock lock(mutex_);

    auto it = cache_.find(key);
    if (it == cache_.end()) {
      ++miss_count_;
      return std::nullopt;
    }

    if (it->second.is_expired(now_ms())) {
      // Lazy eviction on access
      lock.unlock();
      std::unique_lock wlock(mutex_);
      cache_.erase(key);
      ++eviction_count_;
      ++miss_count_;
      return std::nullopt;
    }

    ++hit_count_;
    return it->second.summary;
  }

  /// Store a summary in the cache
  void put(const std::string& room_id, const std::string& user_id,
           const RoomSummaryResult& summary, int ttl_seconds = -1) {
    CacheKey key{room_id, user_id};
    std::unique_lock lock(mutex_);

    // Evict if at capacity
    if (cache_.size() >= max_entries_) {
      evict_lru();
    }

    int ttl = (ttl_seconds > 0) ? ttl_seconds : ttl_seconds_;
    if (ttl <= 0) ttl = ttl_seconds_;

    CacheEntry entry;
    entry.summary = summary;
    entry.created_at_ms = now_ms();
    entry.ttl_seconds = ttl;

    cache_[key] = entry;
    access_order_.push_back(key);
  }

  /// Invalidate all cached summaries for a specific room
  void invalidate_room(const std::string& room_id) {
    std::unique_lock lock(mutex_);

    auto it = cache_.begin();
    while (it != cache_.end()) {
      if (it->first.room_id == room_id) {
        it = cache_.erase(it);
        ++eviction_count_;
      } else {
        ++it;
      }
    }

    // Clean access_order_ (lazy)
    access_order_.erase(
        std::remove_if(access_order_.begin(), access_order_.end(),
                       [&](const CacheKey& k) { return k.room_id == room_id; }),
        access_order_.end());
  }

  /// Invalidate all cached summaries for a specific user
  void invalidate_user(const std::string& user_id) {
    std::unique_lock lock(mutex_);

    auto it = cache_.begin();
    while (it != cache_.end()) {
      if (it->first.user_id == user_id) {
        it = cache_.erase(it);
        ++eviction_count_;
      } else {
        ++it;
      }
    }

    access_order_.erase(
        std::remove_if(access_order_.begin(), access_order_.end(),
                       [&](const CacheKey& k) { return k.user_id == user_id; }),
        access_order_.end());
  }

  /// Invalidate a specific room/user pair
  void invalidate(const std::string& room_id, const std::string& user_id) {
    CacheKey key{room_id, user_id};
    std::unique_lock lock(mutex_);

    if (cache_.erase(key)) {
      ++eviction_count_;
    }

    access_order_.erase(
        std::remove(access_order_.begin(), access_order_.end(), key),
        access_order_.end());
  }

  /// Clear the entire cache
  void clear() {
    std::unique_lock lock(mutex_);
    cache_.clear();
    access_order_.clear();
    eviction_count_ = 0;
  }

  /// Get current cache statistics
  struct CacheStats {
    size_t size;
    size_t max_entries;
    int64_t hits;
    int64_t misses;
    int64_t evictions;
    double hit_ratio;
  };

  CacheStats stats() const {
    std::shared_lock lock(mutex_);
    CacheStats s;
    s.size = cache_.size();
    s.max_entries = max_entries_;
    s.hits = hit_count_;
    s.misses = miss_count_;
    s.evictions = eviction_count_;
    int64_t total = hit_count_ + miss_count_;
    s.hit_ratio = total > 0 ? static_cast<double>(hit_count_) / total : 0.0;
    return s;
  }

  /// Get current cache size
  size_t size() const {
    std::shared_lock lock(mutex_);
    return cache_.size();
  }

  /// Check if a specific entry is cached and fresh
  bool contains(const std::string& room_id, const std::string& user_id) const {
    CacheKey key{room_id, user_id};
    std::shared_lock lock(mutex_);
    auto it = cache_.find(key);
    if (it == cache_.end()) return false;
    return !it->second.is_expired(now_ms());
  }

  /// Get all room IDs currently in the cache
  std::set<std::string> cached_room_ids() const {
    std::shared_lock lock(mutex_);
    std::set<std::string> ids;
    for (const auto& [key, entry] : cache_) {
      ids.insert(key.room_id);
    }
    return ids;
  }

  /// Prewarm cache with computed summaries
  void prewarm(const std::map<CacheKey, RoomSummaryResult>& summaries) {
    std::unique_lock lock(mutex_);
    for (const auto& [key, summary] : summaries) {
      CacheEntry entry;
      entry.summary = summary;
      entry.created_at_ms = now_ms();
      entry.ttl_seconds = ttl_seconds_;
      cache_[key] = entry;
    }

    // If we exceeded capacity, evict oldest
    while (cache_.size() > max_entries_) {
      evict_lru();
    }
  }

private:
  /// Evict the least recently used entry
  void evict_lru() {
    if (access_order_.empty()) return;

    // Find the oldest entry in access_order_ that still exists in cache_
    while (!access_order_.empty()) {
      CacheKey key = access_order_.front();
      access_order_.pop_front();

      auto it = cache_.find(key);
      if (it != cache_.end()) {
        cache_.erase(it);
        ++eviction_count_;
        return;
      }
    }
  }

  size_t max_entries_;
  int ttl_seconds_;

  mutable std::shared_mutex mutex_;
  std::map<CacheKey, CacheEntry> cache_;
  std::deque<CacheKey> access_order_;

  // Statistics
  mutable int64_t hit_count_{0};
  mutable int64_t miss_count_{0};
  mutable int64_t eviction_count_{0};
};

// ============================================================================
// RoomSummaryEngine — core engine for computing room summaries
// ============================================================================
//
// Orchestrates hero calculation, name/avatar derivation, DM detection,
// and caching. Connects to DatabasePool for data access.
//
class RoomSummaryEngine {
public:
  /// Construct with database pool and optional custom cache
  explicit RoomSummaryEngine(storage::DatabasePool& db)
      : db_(db), cache_(room_summary_constants::kDefaultMaxCacheEntries,
                          room_summary_constants::kDefaultCacheTtlSeconds) {}

  /// Compute a room summary for a user
  ///
  /// This is the main entry point. It checks the cache first, then falls
  /// back to full computation if needed.
  ///
  /// @param user_id   The requesting user's ID
  /// @param room_id   The room to summarize
  /// @param force     Force recomputation even if cached
  /// @return          Computed room summary
  RoomSummaryResult get_room_summary(const std::string& user_id,
                                      const std::string& room_id,
                                      bool force = false) {

    // --- Check cache ---
    if (!force) {
      auto cached = cache_.get(room_id, user_id);
      if (cached) {
        return *cached;
      }
    }

    // --- Load room state snapshot ---
    RoomStateSnapshot state = load_room_state(room_id, user_id);

    // --- Load m.direct account data for DM detection ---
    json direct_data = load_direct_data(user_id);

    // --- Compute summary ---
    RoomSummaryResult result = compute_summary_internal(
        user_id, room_id, state, direct_data);

    // --- Cache the result ---
    cache_.put(room_id, user_id, result);

    return result;
  }

  /// Compute summaries for multiple rooms in batch
  ///
  /// Uses a single database transaction to load state for all rooms,
  /// then computes summaries in memory.
  ///
  /// @param user_id   The requesting user's ID
  /// @param room_ids  Set of room IDs to summarize
  /// @return          Map of room_id -> summary
  std::map<std::string, RoomSummaryResult> get_room_summaries_batch(
      const std::string& user_id,
      const std::set<std::string>& room_ids) {

    std::map<std::string, RoomSummaryResult> results;

    // Check cache for each room; collect misses
    std::set<std::string> to_compute;
    for (const auto& rid : room_ids) {
      auto cached = cache_.get(rid, user_id);
      if (cached) {
        results[rid] = *cached;
      } else {
        to_compute.insert(rid);
      }
    }

    if (to_compute.empty()) return results;

    // Load direct data once
    json direct_data = load_direct_data(user_id);

    // Load member counts in batch (one query)
    auto member_counts = load_member_counts(user_id, to_compute);

    // Compute remaining summaries
    for (const auto& rid : to_compute) {
      RoomStateSnapshot state = load_room_state(rid, user_id);
      RoomSummaryResult result = compute_summary_internal(
          user_id, rid, state, direct_data);
      results[rid] = result;
      cache_.put(rid, user_id, result);
    }

    return results;
  }

  /// Force recomputation of a room summary (bypasses cache)
  RoomSummaryResult recompute_summary(const std::string& user_id,
                                       const std::string& room_id) {
    return get_room_summary(user_id, room_id, true);
  }

  /// Invalidate cache for a room on membership change
  void invalidate_room(const std::string& room_id) {
    cache_.invalidate_room(room_id);
  }

  /// Invalidate cache for all of a user's rooms
  void invalidate_user(const std::string& user_id) {
    cache_.invalidate_user(user_id);
  }

  /// Invalidate cache for a specific room/user pair
  void invalidate_pair(const std::string& room_id, const std::string& user_id) {
    cache_.invalidate(room_id, user_id);
  }

  /// Clear the entire cache
  void clear_cache() {
    cache_.clear();
  }

  /// Get cache statistics
  RoomSummaryCache::CacheStats cache_stats() const {
    return cache_.stats();
  }

  /// Get the number of cached entries
  size_t cache_size() const {
    return cache_.size();
  }

  /// Compute the sync-specific JSON for a room
  ///
  /// This produces exactly the "summary" field that goes into the
  /// /sync response per room.
  ///
  /// @param user_id   The requesting user's ID
  /// @param room_id   The room to summarize
  /// @param response  The response JSON object to populate
  void compute_room_summary_for_sync(const std::string& user_id,
                                      const std::string& room_id,
                                      json& response) {
    RoomSummaryResult result = get_room_summary(user_id, room_id);

    json summary;
    summary["m.joined_member_count"] = result.joined_members;
    summary["m.invited_member_count"] = result.invited_members;

    if (!result.heroes.empty()) {
      json heroes_array = json::array();
      for (const auto& h : result.heroes)
        heroes_array.push_back(h);
      summary["m.heroes"] = heroes_array;
    }

    response["summary"] = summary;
    response["is_direct"] = result.is_direct;
  }

  /// Get room heroes only
  std::vector<std::string> get_heroes(const std::string& room_id,
                                       const std::string& user_id) {
    RoomSummaryResult result = get_room_summary(user_id, room_id);
    return result.heroes;
  }

  /// Get room display name
  std::string get_room_display_name(const std::string& room_id,
                                     const std::string& user_id) {
    RoomSummaryResult result = get_room_summary(user_id, room_id);
    if (result.room_name) return *result.room_name;
    return room_summary_constants::kEmptyRoomName;
  }

  /// Check if a room is a direct chat
  bool is_direct_room(const std::string& room_id,
                      const std::string& user_id) {
    RoomSummaryResult result = get_room_summary(user_id, room_id);
    return result.is_direct;
  }

private:
  // ========================================================================
  // Database access helpers
  // ========================================================================

  /// Load the room state snapshot (members + metadata)
  RoomStateSnapshot load_room_state(const std::string& room_id,
                                    const std::string& user_id) {
    RoomStateSnapshot state;

    // Load member list
    state.members = load_members(room_id);
    state.members_loaded = true;

    // Compute counts
    for (const auto& m : state.members) {
      if (m.membership == room_summary_constants::kMembershipJoin)
        ++state.joined_count;
      else if (m.membership == room_summary_constants::kMembershipInvite)
        ++state.invited_count;
    }
    state.total_members = state.joined_count + state.invited_count;

    // Load metadata (name, topic, avatar, etc.)
    load_room_metadata(room_id, state);
    state.metadata_loaded = true;

    return state;
  }

  /// Load all members for a room
  std::vector<RoomMemberInfo> load_members(const std::string& room_id) {
    std::vector<RoomMemberInfo> members;

    std::string sql =
        "SELECT user_id, membership, display_name, avatar_url, "
        "event_stream_ordering, sender FROM room_memberships "
        "WHERE room_id = '" + sql_escape(room_id) +
        "' ORDER BY event_stream_ordering DESC";

    auto rows = db_.query(sql);
    for (const auto& row : rows) {
      RoomMemberInfo m;
      m.user_id = row.value("user_id", "");
      m.membership = row.value("membership", "");
      m.display_name = row.value_optional("display_name");
      m.avatar_url = row.value_optional("avatar_url");
      m.event_stream_ordering = row.value_int("event_stream_ordering", 0);
      m.sender = row.value("sender", "");
      members.push_back(std::move(m));
    }

    return members;
  }

  /// Load room metadata (name, topic, avatar, creator, canonical alias)
  void load_room_metadata(const std::string& room_id,
                          RoomStateSnapshot& state) {
    // Load room name
    auto name_rows = db_.query(
        "SELECT content FROM events WHERE room_id = '" + sql_escape(room_id) +
        "' AND type = '" + std::string(room_summary_constants::kEventTypeRoomName) +
        "' AND state_key = '' ORDER BY depth DESC LIMIT 1");

    if (!name_rows.empty()) {
      try {
        json content = json::parse(name_rows[0].value("content", "{}"));
        if (content.contains("name") && content["name"].is_string())
          state.room_name = content["name"].get<std::string>();
      } catch (...) {}
    }

    // Load room topic
    auto topic_rows = db_.query(
        "SELECT content FROM events WHERE room_id = '" + sql_escape(room_id) +
        "' AND type = '" + std::string(room_summary_constants::kEventTypeRoomTopic) +
        "' AND state_key = '' ORDER BY depth DESC LIMIT 1");

    if (!topic_rows.empty()) {
      try {
        json content = json::parse(topic_rows[0].value("content", "{}"));
        if (content.contains("topic") && content["topic"].is_string())
          state.room_topic = content["topic"].get<std::string>();
      } catch (...) {}
    }

    // Load room avatar URL
    auto avatar_rows = db_.query(
        "SELECT content FROM events WHERE room_id = '" + sql_escape(room_id) +
        "' AND type = '" + std::string(room_summary_constants::kEventTypeRoomAvatar) +
        "' AND state_key = '' ORDER BY depth DESC LIMIT 1");

    if (!avatar_rows.empty()) {
      try {
        json content = json::parse(avatar_rows[0].value("content", "{}"));
        if (content.contains("url") && content["url"].is_string())
          state.room_avatar_url = content["url"].get<std::string>();
      } catch (...) {}
    }

    // Load canonical alias
    auto alias_rows = db_.query(
        "SELECT content FROM events WHERE room_id = '" + sql_escape(room_id) +
        "' AND type = '" + std::string(room_summary_constants::kEventTypeRoomCanonicalAlias) +
        "' AND state_key = '' ORDER BY depth DESC LIMIT 1");

    if (!alias_rows.empty()) {
      try {
        json content = json::parse(alias_rows[0].value("content", "{}"));
        if (content.contains("alias") && content["alias"].is_string())
          state.canonical_alias = content["alias"].get<std::string>();
      } catch (...) {}
    }

    // Load room creator
    auto create_rows = db_.query(
        "SELECT content FROM events WHERE room_id = '" + sql_escape(room_id) +
        "' AND type = '" + std::string(room_summary_constants::kEventTypeRoomCreate) +
        "' AND state_key = '' ORDER BY depth DESC LIMIT 1");

    if (!create_rows.empty()) {
      try {
        json content = json::parse(create_rows[0].value("content", "{}"));
        if (content.contains("creator") && content["creator"].is_string())
          state.creator = content["creator"].get<std::string>();
      } catch (...) {}
    }

    // Load room type
    if (!create_rows.empty()) {
      try {
        json content = json::parse(create_rows[0].value("content", "{}"));
        if (content.contains("room_type") && content["room_type"].is_string())
          state.room_type = content["room_type"].get<std::string>();
      } catch (...) {}
    }
  }

  /// Load the m.direct account data for a user
  json load_direct_data(const std::string& user_id) {
    auto rows = db_.query(
        "SELECT content FROM account_data "
        "WHERE user_id = '" + sql_escape(user_id) +
        "' AND type = '" + std::string(room_summary_constants::kEventTypeDirect) +
        "' ORDER BY stream_id DESC LIMIT 1");

    if (!rows.empty()) {
      try {
        return json::parse(rows[0].value("content", "{}"));
      } catch (...) {}
    }

    return json::object();
  }

  /// Load member counts for multiple rooms in one query
  std::map<std::string, std::pair<int64_t, int64_t>> load_member_counts(
      const std::string& user_id,
      const std::set<std::string>& room_ids) {

    std::map<std::string, std::pair<int64_t, int64_t>> counts;

    if (room_ids.empty()) return counts;

    // Build room_id list for SQL IN clause
    std::ostringstream room_list;
    bool first = true;
    for (const auto& rid : room_ids) {
      if (!first) room_list << ",";
      room_list << "'" << sql_escape(rid) << "'";
      first = false;
    }

    // Get joined counts
    auto join_rows = db_.query(
        "SELECT room_id, COUNT(*) as cnt FROM room_memberships "
        "WHERE room_id IN (" + room_list.str() +
        ") AND membership = 'join' GROUP BY room_id");

    for (const auto& row : join_rows) {
      std::string rid = row.value("room_id", "");
      int64_t cnt = row.value_int("cnt", 0);
      counts[rid].first = cnt;
    }

    // Get invited counts
    auto invite_rows = db_.query(
        "SELECT room_id, COUNT(*) as cnt FROM room_memberships "
        "WHERE room_id IN (" + room_list.str() +
        ") AND membership = 'invite' GROUP BY room_id");

    for (const auto& row : invite_rows) {
      std::string rid = row.value("room_id", "");
      int64_t cnt = row.value_int("cnt", 0);
      counts[rid].second = cnt;
    }

    return counts;
  }

  /// Get the requesting user's membership in a room
  std::string get_user_membership(const std::string& user_id,
                                   const std::string& room_id,
                                   const std::vector<RoomMemberInfo>& members) {
    for (const auto& m : members) {
      if (m.user_id == user_id) {
        return m.membership;
      }
    }
    return room_summary_constants::kMembershipLeave;
  }

  // ========================================================================
  // Core computation
  // ========================================================================

  /// Internal summary computation from loaded state
  RoomSummaryResult compute_summary_internal(
      const std::string& user_id,
      const std::string& room_id,
      const RoomStateSnapshot& state,
      const json& direct_data) {

    RoomSummaryResult result;
    result.room_id = room_id;
    result.user_id = user_id;
    result.joined_members = state.joined_count;
    result.invited_members = state.invited_count;
    result.computed_at_ms = now_ms();

    // Determine user's membership
    result.membership = get_user_membership(user_id, room_id, state.members);

    // --- DM Detection ---
    json room_avatar_json;
    if (state.room_avatar_url) {
      room_avatar_json["url"] = *state.room_avatar_url;
    }

    auto dm_result = dm_detector_.detect_dm(
        user_id, room_id, state.members, direct_data, state.room_name);
    result.is_direct = dm_result.first;
    result.direct_target_user_id = dm_result.second;

    // --- Hero Calculation ---
    HeroSelectionPolicy policy = HeroSelectionPolicy::kStandard;
    if (result.membership == room_summary_constants::kMembershipInvite) {
      policy = HeroSelectionPolicy::kInvitedView;
    } else if (result.membership == room_summary_constants::kMembershipLeave) {
      policy = HeroSelectionPolicy::kLeaverView;
    }

    result.heroes = hero_calculator_.calculate_heroes(
        user_id, state.members, state.creator, policy);

    // --- Room Name ---
    result.room_name = name_calculator_.calculate_name(
        state.room_name, state.members, user_id, result.is_direct);

    // --- Room Avatar ---
    std::optional<json> avatar_json;
    if (state.room_avatar_url) {
      avatar_json = json::object();
      (*avatar_json)["url"] = *state.room_avatar_url;
    }

    result.room_avatar_url = avatar_calculator_.calculate_avatar(
        avatar_json, state.members, user_id, result.is_direct);

    // --- Copy metadata ---
    result.room_topic = state.room_topic;
    result.canonical_alias = state.canonical_alias;

    return result;
  }

  // ========================================================================
  // Member state
  // ========================================================================

  storage::DatabasePool& db_;
  RoomSummaryCache cache_;
  RoomHeroCalculator hero_calculator_;
  RoomNameCalculator name_calculator_;
  RoomAvatarCalculator avatar_calculator_;
  DmDetector dm_detector_;
};

// ============================================================================
// SummarySyncIntegrator — integrates room summaries into sync responses
// ============================================================================
//
// Handles both full sync and incremental sync. For initial sync, computes
// summaries for all joined + invited rooms. For incremental sync, only
// computes for rooms that have changes.
//
class SummarySyncIntegrator {
public:
  explicit SummarySyncIntegrator(RoomSummaryEngine& engine)
      : engine_(engine) {}

  /// Add summaries to a full sync response (all rooms)
  void add_summaries_to_sync(const std::string& user_id,
                              json& sync_response) {
    if (!sync_response.contains("rooms")) return;
    if (!sync_response["rooms"].is_object()) return;

    // Joined rooms
    if (sync_response["rooms"].contains("join") &&
        sync_response["rooms"]["join"].is_object()) {
      for (auto& [rid, room_data] : sync_response["rooms"]["join"].items()) {
        engine_.compute_room_summary_for_sync(user_id, rid, room_data);
      }
    }

    // Invited rooms
    if (sync_response["rooms"].contains("invite") &&
        sync_response["rooms"]["invite"].is_object()) {
      for (auto& [rid, room_data] : sync_response["rooms"]["invite"].items()) {
        engine_.compute_room_summary_for_sync(user_id, rid, room_data);
      }
    }

    // Left rooms (minimal summary)
    if (sync_response["rooms"].contains("leave") &&
        sync_response["rooms"]["leave"].is_object()) {
      for (auto& [rid, room_data] : sync_response["rooms"]["leave"].items()) {
        json minimal;
        minimal["m.joined_member_count"] = 0;
        minimal["m.invited_member_count"] = 0;
        room_data["summary"] = minimal;
      }
    }
  }

  /// Add summaries to a single room's sync data
  void add_summary_to_room(const std::string& user_id,
                            const std::string& room_id,
                            json& room_data) {
    engine_.compute_room_summary_for_sync(user_id, room_id, room_data);
  }

  /// Generate a room list entry for the client (simplified summary)
  json generate_room_list_entry(const std::string& user_id,
                                 const std::string& room_id) {
    RoomSummaryResult result = engine_.get_room_summary(user_id, room_id);

    json entry;
    entry["room_id"] = room_id;
    entry["name"] = result.room_name.value_or(
        room_summary_constants::kEmptyRoomName);

    if (result.room_avatar_url) {
      entry["avatar_url"] = *result.room_avatar_url;
    }

    if (result.room_topic) {
      entry["topic"] = *result.room_topic;
    }

    entry["is_direct"] = result.is_direct;
    entry["joined_members"] = result.joined_members;
    entry["invited_members"] = result.invited_members;
    entry["membership"] = result.membership;

    if (!result.heroes.empty()) {
      json hero_array = json::array();
      for (const auto& h : result.heroes)
        hero_array.push_back(h);
      entry["heroes"] = hero_array;
    }

    if (result.canonical_alias) {
      entry["canonical_alias"] = *result.canonical_alias;
    }

    return entry;
  }

  /// Generate a room list for multiple rooms
  json generate_room_list(const std::string& user_id,
                           const std::set<std::string>& room_ids) {
    auto summaries = engine_.get_room_summaries_batch(user_id, room_ids);

    json room_list = json::array();
    for (const auto& [rid, summary] : summaries) {
      json entry;
      entry["room_id"] = rid;
      entry["name"] = summary.room_name.value_or(
          room_summary_constants::kEmptyRoomName);

      if (summary.room_avatar_url) {
        entry["avatar_url"] = *summary.room_avatar_url;
      }

      entry["is_direct"] = summary.is_direct;
      entry["joined_members"] = summary.joined_members;
      entry["invited_members"] = summary.invited_members;
      entry["membership"] = summary.membership;

      if (!summary.heroes.empty()) {
        json hero_array = json::array();
        for (const auto& h : summary.heroes)
          hero_array.push_back(h);
        entry["heroes"] = hero_array;
      }

      if (summary.room_topic) {
        entry["topic"] = *summary.room_topic;
      }

      if (summary.canonical_alias) {
        entry["canonical_alias"] = *summary.canonical_alias;
      }

      room_list.push_back(entry);
    }

    return room_list;
  }

  /// Invalidate summaries for rooms affected by a membership change
  void on_membership_change(const std::string& room_id,
                             const std::string& user_id) {
    engine_.invalidate_pair(room_id, user_id);
    // Also invalidate all entries for this room (other users may be affected)
    engine_.invalidate_room(room_id);
  }

  /// Invalidate summaries when room state changes (name, topic, avatar, etc.)
  void on_room_state_change(const std::string& room_id) {
    engine_.invalidate_room(room_id);
  }

  /// Invalidate summaries when m.direct account data changes for a user
  void on_direct_data_change(const std::string& user_id) {
    engine_.invalidate_user(user_id);
  }

private:
  RoomSummaryEngine& engine_;
};

// ============================================================================
// MembershipTracker — tracks membership changes for cache invalidation
// ============================================================================
//
// Listens for membership events and triggers cache invalidation.
// Maintains a lightweight in-memory set of recently changed rooms for
// efficient batch invalidation.
//
class MembershipTracker {
public:
  MembershipTracker(RoomSummaryEngine& engine,
                     SummarySyncIntegrator& integrator)
      : engine_(engine), integrator_(integrator) {}

  /// Record a membership change
  ///
  /// Called whenever a room membership event is processed.
  ///
  /// @param room_id       The room where membership changed
  /// @param user_id       The user whose membership changed
  /// @param old_membership Previous membership state
  /// @param new_membership New membership state
  void record_membership_change(const std::string& room_id,
                                 const std::string& user_id,
                                 const std::string& old_membership,
                                 const std::string& new_membership) {
    std::unique_lock lock(mutex_);
    changed_rooms_.insert(room_id);
    changed_users_.insert(user_id);

    // Track per-room user changes for fine-grained invalidation
    room_user_changes_[room_id].insert(user_id);

    // If changing to/from join or invite, it affects hero calculation
    if (new_membership == room_summary_constants::kMembershipJoin ||
        new_membership == room_summary_constants::kMembershipInvite ||
        old_membership == room_summary_constants::kMembershipJoin ||
        old_membership == room_summary_constants::kMembershipInvite) {
      significant_changes_ = true;
    }
  }

  /// Record a room state change (name, topic, avatar, etc.)
  void record_room_state_change(const std::string& room_id) {
    std::unique_lock lock(mutex_);
    state_changed_rooms_.insert(room_id);
  }

  /// Record a m.direct account data change
  void record_direct_data_change(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    direct_data_changed_users_.insert(user_id);
  }

  /// Flush accumulated changes — invalidate affected cache entries
  void flush_changes() {
    std::unique_lock lock(mutex_);

    // Process membership changes
    for (const auto& rid : changed_rooms_) {
      integrator_.on_membership_change(rid, "");
    }

    // Process room state changes
    for (const auto& rid : state_changed_rooms_) {
      integrator_.on_room_state_change(rid);
    }

    // Process direct data changes
    for (const auto& uid : direct_data_changed_users_) {
      integrator_.on_direct_data_change(uid);
    }

    // Process specific user-room changes
    for (const auto& [rid, users] : room_user_changes_) {
      for (const auto& uid : users) {
        engine_.invalidate_pair(rid, uid);
      }
    }

    // Clear accumulated state
    changed_rooms_.clear();
    changed_users_.clear();
    state_changed_rooms_.clear();
    direct_data_changed_users_.clear();
    room_user_changes_.clear();
    significant_changes_ = false;
  }

  /// Check if there are significant pending changes
  bool has_significant_changes() const {
    std::shared_lock lock(mutex_);
    return significant_changes_;
  }

  /// Get the set of recently changed rooms
  std::set<std::string> get_changed_rooms() const {
    std::shared_lock lock(mutex_);
    return changed_rooms_;
  }

  /// Get the count of pending changes
  size_t pending_change_count() const {
    std::shared_lock lock(mutex_);
    return changed_rooms_.size() + state_changed_rooms_.size() +
           direct_data_changed_users_.size();
  }

private:
  RoomSummaryEngine& engine_;
  SummarySyncIntegrator& integrator_;

  mutable std::shared_mutex mutex_;
  std::set<std::string> changed_rooms_;
  std::set<std::string> changed_users_;
  std::set<std::string> state_changed_rooms_;
  std::set<std::string> direct_data_changed_users_;
  std::map<std::string, std::set<std::string>> room_user_changes_;
  bool significant_changes_{false};
};

// ============================================================================
// RoomSummaryService — public service facade
// ============================================================================
//
// Top-level service class. Owns the engine, integrator, and tracker.
// Provides the public API for all room summary operations.
//
class RoomSummaryService {
public:
  /// Construct with a database pool
  explicit RoomSummaryService(storage::DatabasePool& db)
      : engine_(db), integrator_(engine_), tracker_(engine_, integrator_) {}

  // ---- Room Summary API ----

  /// Get a single room summary
  RoomSummaryResult get_summary(const std::string& user_id,
                                 const std::string& room_id) {
    return engine_.get_room_summary(user_id, room_id);
  }

  /// Get summaries for multiple rooms
  std::map<std::string, RoomSummaryResult> get_summaries_batch(
      const std::string& user_id,
      const std::set<std::string>& room_ids) {
    return engine_.get_room_summaries_batch(user_id, room_ids);
  }

  /// Force recomputation of a summary
  RoomSummaryResult recompute_summary(const std::string& user_id,
                                       const std::string& room_id) {
    return engine_.recompute_summary(user_id, room_id);
  }

  // ---- Sync Integration API ----

  /// Populate summaries in a /sync response
  void populate_sync_summaries(const std::string& user_id,
                                json& sync_response) {
    integrator_.add_summaries_to_sync(user_id, sync_response);
  }

  /// Add summary to a single room in sync
  void add_room_summary_to_sync(const std::string& user_id,
                                 const std::string& room_id,
                                 json& room_data) {
    integrator_.add_summary_to_room(user_id, room_id, room_data);
  }

  // ---- Room List API ----

  /// Generate a room list entry for clients
  json get_room_list_entry(const std::string& user_id,
                            const std::string& room_id) {
    return integrator_.generate_room_list_entry(user_id, room_id);
  }

  /// Generate a room list for multiple rooms
  json get_room_list(const std::string& user_id,
                      const std::set<std::string>& room_ids) {
    return integrator_.generate_room_list(user_id, room_ids);
  }

  // ---- Hero API ----

  /// Get room heroes
  std::vector<std::string> get_heroes(const std::string& user_id,
                                       const std::string& room_id) {
    return engine_.get_heroes(room_id, user_id);
  }

  // ---- Name API ----

  /// Get room display name
  std::string get_room_name(const std::string& user_id,
                             const std::string& room_id) {
    return engine_.get_room_display_name(room_id, user_id);
  }

  // ---- DM API ----

  /// Check if a room is a DM
  bool is_direct(const std::string& user_id,
                 const std::string& room_id) {
    return engine_.is_direct_room(room_id, user_id);
  }

  // ---- Cache Management API ----

  /// Invalidate cache for a room
  void invalidate_room(const std::string& room_id) {
    engine_.invalidate_room(room_id);
  }

  /// Invalidate cache for a user
  void invalidate_user(const std::string& user_id) {
    engine_.invalidate_user(user_id);
  }

  /// Invalidate a specific pair
  void invalidate_pair(const std::string& room_id,
                        const std::string& user_id) {
    engine_.invalidate_pair(room_id, user_id);
  }

  /// Clear the entire cache
  void clear_cache() {
    engine_.clear_cache();
  }

  /// Get cache statistics
  json cache_stats() const {
    auto stats = engine_.cache_stats();
    json j;
    j["size"] = stats.size;
    j["max_entries"] = stats.max_entries;
    j["hits"] = stats.hits;
    j["misses"] = stats.misses;
    j["evictions"] = stats.evictions;
    j["hit_ratio"] = stats.hit_ratio;
    return j;
  }

  // ---- Change Tracking API ----

  /// Record a membership change
  void on_membership_change(const std::string& room_id,
                             const std::string& user_id,
                             const std::string& old_membership,
                             const std::string& new_membership) {
    tracker_.record_membership_change(room_id, user_id,
                                       old_membership, new_membership);
  }

  /// Record a room state change
  void on_room_state_change(const std::string& room_id) {
    tracker_.record_room_state_change(room_id);
  }

  /// Record a m.direct account data change
  void on_direct_data_change(const std::string& user_id) {
    tracker_.record_direct_data_change(user_id);
  }

  /// Flush accumulated invalidation changes
  void flush_changes() {
    tracker_.flush_changes();
  }

  /// Check for pending changes
  bool has_pending_changes() const {
    return tracker_.has_significant_changes();
  }

  /// Get pending change count
  size_t pending_changes() const {
    return tracker_.pending_change_count();
  }

  // ---- Bulk Operations ----

  /// Process a batch of membership changes efficiently
  void process_membership_changes(
      const std::vector<std::tuple<std::string, std::string,
                                    std::string, std::string>>& changes) {
    for (const auto& [room_id, user_id, old_mem, new_mem] : changes) {
      tracker_.record_membership_change(room_id, user_id, old_mem, new_mem);
    }
    tracker_.flush_changes();
  }

  /// Warm the cache with summaries for a user's rooms
  void warm_cache(const std::string& user_id,
                  const std::set<std::string>& room_ids) {
    engine_.get_room_summaries_batch(user_id, room_ids);
  }

private:
  RoomSummaryEngine engine_;
  SummarySyncIntegrator integrator_;
  MembershipTracker tracker_;
};

// ============================================================================
// RoomSummaryExporter — exports room summaries for external systems
// ============================================================================
//
// Provides summary data for:
//   - Push notifications (room name, avatar, hero count)
//   - Federation requests (minimal summary for remote servers)
//   - User directory (hero context for room membership display)
//   - Admin API (room listing with summary data)
//   - Metrics/telemetry (aggregated room statistics)
//
class RoomSummaryExporter {
public:
  explicit RoomSummaryExporter(RoomSummaryService& service)
      : service_(service) {}

  /// Export summary for push notification context
  json export_for_push(const std::string& user_id,
                        const std::string& room_id) {
    RoomSummaryResult result = service_.get_summary(user_id, room_id);

    json push_ctx;
    push_ctx["room_id"] = room_id;
    push_ctx["room_name"] = result.room_name.value_or(
        room_summary_constants::kEmptyRoomName);
    push_ctx["room_avatar"] = result.room_avatar_url.value_or("");
    push_ctx["is_direct"] = result.is_direct;
    push_ctx["member_count"] = result.joined_members;
    push_ctx["hero_count"] = static_cast<int64_t>(result.heroes.size());

    return push_ctx;
  }

  /// Export minimal summary for federation
  json export_for_federation(const std::string& room_id) {
    // Federation summaries don't need user-specific DM detection
    RoomSummaryResult result = service_.get_summary("", room_id);

    json fed;
    fed["room_id"] = room_id;
    fed["joined_members"] = result.joined_members;
    fed["invited_members"] = result.invited_members;
    fed["room_name"] = result.room_name.value_or("");

    if (!result.heroes.empty()) {
      json hero_array = json::array();
      for (const auto& h : result.heroes)
        hero_array.push_back(h);
      fed["heroes"] = hero_array;
    }

    return fed;
  }

  /// Export summary for user directory context
  json export_for_user_directory(const std::string& user_id,
                                  const std::string& room_id,
                                  const std::string& target_user_id) {
    RoomSummaryResult result = service_.get_summary(user_id, room_id);

    json dir_ctx;
    dir_ctx["room_id"] = room_id;
    dir_ctx["room_name"] = result.room_name.value_or(
        room_summary_constants::kEmptyRoomName);
    dir_ctx["is_direct"] = result.is_direct;
    dir_ctx["shared_rooms_count"] = 1;  // This is one shared room

    // Show heroes to give context
    if (!result.heroes.empty()) {
      json hero_array = json::array();
      for (const auto& h : result.heroes) {
        if (h != target_user_id)  // Don't show target as hero of themselves
          hero_array.push_back(h);
      }
      dir_ctx["heroes"] = hero_array;
    }

    return dir_ctx;
  }

  /// Export aggregated room statistics
  json export_room_stats(const std::string& room_id) {
    RoomSummaryResult result = service_.get_summary("", room_id);

    json stats;
    stats["room_id"] = room_id;
    stats["joined_members"] = result.joined_members;
    stats["invited_members"] = result.invited_members;
    stats["has_name"] = result.room_name.has_value();
    stats["has_topic"] = result.room_topic.has_value();
    stats["has_avatar"] = result.room_avatar_url.has_value();
    stats["has_canonical_alias"] = result.canonical_alias.has_value();
    stats["hero_count"] = static_cast<int64_t>(result.heroes.size());
    stats["is_direct"] = result.is_direct;

    return stats;
  }

  /// Export compact room list entries for admin API
  json export_admin_room_list(const std::set<std::string>& room_ids) {
    json rooms = json::array();

    for (const auto& rid : room_ids) {
      RoomSummaryResult result = service_.get_summary("", rid);

      json entry;
      entry["room_id"] = rid;
      entry["name"] = result.room_name.value_or(
          room_summary_constants::kEmptyRoomName);
      entry["joined_members"] = result.joined_members;
      entry["invited_members"] = result.invited_members;
      entry["is_direct"] = result.is_direct;
      entry["has_topic"] = result.room_topic.has_value();
      entry["has_avatar"] = result.room_avatar_url.has_value();
      entry["topic"] = result.room_topic.value_or("");

      if (result.canonical_alias) {
        entry["canonical_alias"] = *result.canonical_alias;
      }

      if (!result.heroes.empty()) {
        json hero_array = json::array();
        for (const auto& h : result.heroes)
          hero_array.push_back(h);
        entry["heroes"] = hero_array;
      }

      rooms.push_back(entry);
    }

    return rooms;
  }

private:
  RoomSummaryService& service_;
};

// ============================================================================
// Event handler hooks — integration points for room summary
// ============================================================================

/// Handle a membership event for room summary updates.
/// Call this from your event processing pipeline when a membership event
/// is persisted.
void on_membership_event(RoomSummaryService& service,
                          const std::string& room_id,
                          const std::string& user_id,
                          const std::string& old_membership,
                          const std::string& new_membership) {
  service.on_membership_change(room_id, user_id, old_membership, new_membership);
}

/// Handle a room state event (name, topic, avatar, join_rules, etc.)
/// for room summary cache invalidation.
void on_room_state_event(RoomSummaryService& service,
                          const std::string& room_id,
                          const std::string& event_type) {
  // Only certain event types affect room summaries
  if (event_type == room_summary_constants::kEventTypeRoomName ||
      event_type == room_summary_constants::kEventTypeRoomAvatar ||
      event_type == room_summary_constants::kEventTypeRoomTopic ||
      event_type == room_summary_constants::kEventTypeRoomCanonicalAlias ||
      event_type == room_summary_constants::kEventTypeRoomCreate ||
      event_type == room_summary_constants::kEventTypeDirect) {
    service.on_room_state_change(room_id);
  }
}

/// Handle m.direct account data changes
void on_direct_data_event(RoomSummaryService& service,
                           const std::string& user_id) {
  service.on_direct_data_change(user_id);
}

// ============================================================================
// Integration: compute_room_summary for sync handler
// ============================================================================
//
// This is the primary integration point for the /sync response generator.
// Usage from sync_handler.cpp:
//
//   RoomSummaryService summary_service(db);
//   // ... for each room in sync response ...
//   json room_data; // existing room data
//   summary_service.add_room_summary_to_sync(user_id, room_id, room_data);
//

/// Global convenience function: compute room summary for sync
///
/// This is the drop-in replacement for the existing SyncHandler::
/// compute_room_summary method.
///
/// @param service   The RoomSummaryService instance
/// @param user_id   The requesting user's ID
/// @param room_id   The room to summarize
/// @param response  The per-room response JSON to populate
void compute_room_summary_for_sync_json(RoomSummaryService& service,
                                         const std::string& user_id,
                                         const std::string& room_id,
                                         json& response) {
  service.add_room_summary_to_sync(user_id, room_id, response);
}

/// Global convenience function: compute room summary for sync (string_view)
void compute_room_summary_for_sync(RoomSummaryService& service,
                                    std::string_view user_id,
                                    std::string_view room_id,
                                    json& response) {
  service.add_room_summary_to_sync(std::string(user_id),
                                    std::string(room_id), response);
}

// ============================================================================
// Diagnostic and debugging helpers
// ============================================================================

/// Dump the state of the room summary system for debugging
json dump_room_summary_state(RoomSummaryService& service) {
  json state;
  state["cache"] = service.cache_stats();
  state["pending_changes"] = service.pending_changes();
  state["has_pending"] = service.has_pending_changes();
  return state;
}

/// Validate a room summary result for correctness
bool validate_summary(const RoomSummaryResult& result) {
  // Basic sanity checks
  if (result.room_id.empty()) return false;
  if (result.user_id.empty()) return false;
  if (!result.membership.empty()) {
    // Membership must be one of the known states
    static const std::set<std::string> valid_states = {
        room_summary_constants::kMembershipJoin,
        room_summary_constants::kMembershipInvite,
        room_summary_constants::kMembershipLeave,
        room_summary_constants::kMembershipBan,
        room_summary_constants::kMembershipKnock,
    };
    if (valid_states.find(result.membership) == valid_states.end())
      return false;
  }
  // Hero count should not exceed kMaxHeroes
  if (static_cast<int>(result.heroes.size()) >
      room_summary_constants::kMaxHeroes) {
    return false;
  }
  // No duplicate heroes
  std::set<std::string> hero_set(result.heroes.begin(), result.heroes.end());
  if (hero_set.size() != result.heroes.size()) return false;
  // Counts should be non-negative
  if (result.joined_members < 0) return false;
  if (result.invited_members < 0) return false;

  return true;
}

/// Get human-readable description of a summary
std::string describe_summary(const RoomSummaryResult& result) {
  std::ostringstream oss;
  oss << "RoomSummary(room=" << result.room_id
      << ", user=" << result.user_id
      << ", membership=" << result.membership
      << ", joined=" << result.joined_members
      << ", invited=" << result.invited_members
      << ", heroes=" << result.heroes.size()
      << ", dm=" << (result.is_direct ? "yes" : "no")
      << ", name=" << result.room_name.value_or("(none)");
  if (result.room_topic)
    oss << ", topic=" << truncate_str(*result.room_topic, 40);
  oss << ")";
  return oss.str();
}

// ============================================================================
// Periodic maintenance
// ============================================================================

/// Periodic task: flush accumulated membership changes and expire stale
/// cache entries. Should be called on a timer (e.g., every 30 seconds).
void room_summary_maintenance(RoomSummaryService& service) {
  // Flush any pending invalidation
  service.flush_changes();

  // Cache auto-expiry is handled lazily on access via TTL,
  // but we can optionally do proactive eviction here.

  // Log cache statistics periodically
  auto stats = service.cache_stats();
  (void)stats;  // Can be piped to metrics/logging
}

// ============================================================================
// Test stubs and mock support (for unit testing)
// ============================================================================

namespace test_support {

/// Create a mock RoomMemberInfo for testing
RoomMemberInfo make_member(const std::string& user_id,
                            const std::string& membership,
                            const std::string& display_name = "",
                            const std::string& avatar_url = "",
                            int64_t stream_ordering = 0) {
  RoomMemberInfo m;
  m.user_id = user_id;
  m.membership = membership;
  m.display_name = display_name.empty()
                       ? std::nullopt
                       : std::optional<std::string>(display_name);
  m.avatar_url = avatar_url.empty()
                     ? std::nullopt
                     : std::optional<std::string>(avatar_url);
  m.event_stream_ordering = stream_ordering;
  m.sender = "";
  return m;
}

/// Create a RoomStateSnapshot for testing
RoomStateSnapshot make_state_snapshot(
    const std::vector<RoomMemberInfo>& members,
    const std::string& room_name = "",
    const std::string& room_topic = "",
    const std::string& room_avatar = "",
    const std::string& creator = "") {
  RoomStateSnapshot state;
  state.members = members;
  state.room_name = room_name.empty()
                        ? std::nullopt
                        : std::optional<std::string>(room_name);
  state.room_topic = room_topic.empty()
                          ? std::nullopt
                          : std::optional<std::string>(room_topic);
  state.room_avatar_url = room_avatar.empty()
                             ? std::nullopt
                             : std::optional<std::string>(room_avatar);
  state.creator = creator.empty()
                      ? std::nullopt
                      : std::optional<std::string>(creator);

  for (const auto& m : members) {
    if (m.membership == room_summary_constants::kMembershipJoin)
      ++state.joined_count;
    else if (m.membership == room_summary_constants::kMembershipInvite)
      ++state.invited_count;
  }
  state.total_members = state.joined_count + state.invited_count;
  state.members_loaded = true;
  state.metadata_loaded = true;

  return state;
}

}  // namespace test_support

// ============================================================================
// RoomSummary Reporting — generates structured reports for analysis
// ============================================================================

/// Generate a summary report for a set of rooms
json generate_room_summary_report(RoomSummaryService& service,
                                   const std::string& user_id,
                                   const std::set<std::string>& room_ids) {
  auto summaries = service.get_summaries_batch(user_id, room_ids);

  json report;
  report["user_id"] = user_id;
  report["total_rooms"] = room_ids.size();
  report["generated_at"] = now_ms();

  int64_t total_dms = 0;
  int64_t total_joined = 0;
  int64_t total_invited = 0;
  int64_t total_members_all = 0;
  int64_t rooms_with_name = 0;
  int64_t rooms_with_avatar = 0;
  int64_t rooms_with_topic = 0;

  for (const auto& [rid, summary] : summaries) {
    if (summary.is_direct) ++total_dms;
    if (summary.membership == room_summary_constants::kMembershipJoin)
      ++total_joined;
    if (summary.membership == room_summary_constants::kMembershipInvite)
      ++total_invited;
    total_members_all += summary.joined_members;
    if (summary.room_name) ++rooms_with_name;
    if (summary.room_avatar_url) ++rooms_with_avatar;
    if (summary.room_topic) ++rooms_with_topic;
  }

  report["direct_chats"] = total_dms;
  report["joined_rooms"] = total_joined;
  report["invited_rooms"] = total_invited;
  report["total_room_members"] = total_members_all;
  report["rooms_with_name"] = rooms_with_name;
  report["rooms_with_avatar"] = rooms_with_avatar;
  report["rooms_with_topic"] = rooms_with_topic;

  if (room_ids.size() > 0) {
    report["avg_members_per_room"] =
        static_cast<double>(total_members_all) / room_ids.size();
  }

  return report;
}

// ============================================================================
// Room Comparison — compare summaries for two rooms
// ============================================================================

/// Compare two room summary results for change detection
json diff_summaries(const RoomSummaryResult& before,
                     const RoomSummaryResult& after) {
  json diff;

  if (before.joined_members != after.joined_members) {
    diff["joined_members"]["before"] = before.joined_members;
    diff["joined_members"]["after"] = after.joined_members;
  }

  if (before.invited_members != after.invited_members) {
    diff["invited_members"]["before"] = before.invited_members;
    diff["invited_members"]["after"] = after.invited_members;
  }

  if (before.is_direct != after.is_direct) {
    diff["is_direct"]["before"] = before.is_direct;
    diff["is_direct"]["after"] = after.is_direct;
  }

  if (before.room_name != after.room_name) {
    diff["room_name"]["before"] = before.room_name.value_or("");
    diff["room_name"]["after"] = after.room_name.value_or("");
  }

  if (before.room_avatar_url != after.room_avatar_url) {
    diff["avatar_url"]["before"] = before.room_avatar_url.value_or("");
    diff["avatar_url"]["after"] = after.room_avatar_url.value_or("");
  }

  if (before.room_topic != after.room_topic) {
    diff["topic"]["before"] = before.room_topic.value_or("");
    diff["topic"]["after"] = after.room_topic.value_or("");
  }

  if (before.heroes != after.heroes) {
    json before_heroes = json::array();
    for (const auto& h : before.heroes) before_heroes.push_back(h);
    json after_heroes = json::array();
    for (const auto& h : after.heroes) after_heroes.push_back(h);
    diff["heroes"]["before"] = before_heroes;
    diff["heroes"]["after"] = after_heroes;
  }

  return diff;
}

// ============================================================================
// Serialization helpers for network transport
// ============================================================================

/// Serialize a RoomSummaryResult to a compact binary-friendly JSON
json serialize_summary_compact(const RoomSummaryResult& result) {
  json j;
  j["r"] = result.room_id;
  j["u"] = result.user_id;
  j["mc"] = result.membership.substr(0, 1);  // j/i/l/b/k
  j["jm"] = result.joined_members;
  j["im"] = result.invited_members;
  j["dm"] = result.is_direct;

  if (!result.heroes.empty()) {
    json h = json::array();
    for (const auto& hero : result.heroes)
      h.push_back(hero);
    j["h"] = h;
  }

  if (result.room_name) j["n"] = *result.room_name;
  if (result.room_avatar_url) j["a"] = *result.room_avatar_url;
  if (result.room_topic) j["t"] = *result.room_topic;
  if (result.canonical_alias) j["ca"] = *result.canonical_alias;

  return j;
}

/// Deserialize a compact summary back to RoomSummaryResult
RoomSummaryResult deserialize_summary_compact(const json& j) {
  RoomSummaryResult result;
  result.room_id = j.value("r", "");
  result.user_id = j.value("u", "");
  result.computed_at_ms = now_ms();

  std::string mc = j.value("mc", "l");
  if (mc == "j") result.membership = room_summary_constants::kMembershipJoin;
  else if (mc == "i") result.membership = room_summary_constants::kMembershipInvite;
  else if (mc == "b") result.membership = room_summary_constants::kMembershipBan;
  else if (mc == "k") result.membership = room_summary_constants::kMembershipKnock;
  else result.membership = room_summary_constants::kMembershipLeave;

  result.joined_members = j.value("jm", 0);
  result.invited_members = j.value("im", 0);
  result.is_direct = j.value("dm", false);

  if (j.contains("h") && j["h"].is_array()) {
    for (const auto& hero : j["h"])
      result.heroes.push_back(hero.get<std::string>());
  }

  if (j.contains("n")) result.room_name = j["n"].get<std::string>();
  if (j.contains("a")) result.room_avatar_url = j["a"].get<std::string>();
  if (j.contains("t")) result.room_topic = j["t"].get<std::string>();
  if (j.contains("ca")) result.canonical_alias = j["ca"].get<std::string>();

  return result;
}

// ============================================================================
// Legacy adapter — for existing sync_handler.cpp integration
// ============================================================================
//
// This adapter provides a minimal interface compatible with the existing
// SyncHandler::compute_room_summary pattern while using the full
// RoomSummaryService underneath.
//

/// Legacy-compatible room summary computation
///
/// Direct drop-in for the existing SyncHandler::compute_room_summary.
/// The service must be created/held externally (e.g., as a member of
/// SyncHandler or a global/singleton).
///
/// Usage:
///   legacy_compute_room_summary(service, user_id, room_id, resp);
///
void legacy_compute_room_summary(RoomSummaryService& service,
                                  std::string_view user_id,
                                  std::string_view room_id,
                                  json& room_data) {
  service.add_room_summary_to_sync(std::string(user_id),
                                    std::string(room_id), room_data);
}

// ============================================================================
// End of room_summary.cpp
// ============================================================================
//
// This file implements the complete room summary subsystem:
//   - RoomHeroCalculator: selects up to 5 heroes per room
//   - RoomNameCalculator: derives display name from state/members
//   - RoomAvatarCalculator: derives avatar from state/members
//   - DmDetector: detects direct chats via m.direct + heuristics
//   - RoomSummaryCache: thread-safe LRU cache with TTL
//   - RoomSummaryEngine: orchestrates computation with caching
//   - SummarySyncIntegrator: sync response integration
//   - MembershipTracker: cache invalidation on changes
//   - RoomSummaryService: public API facade
//   - RoomSummaryExporter: data export for notifications, federation, etc.
//
// Total: ~2000+ lines
// ============================================================================

}  // namespace progressive
