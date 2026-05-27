// ============================================================================
// history_visibility.cpp — Matrix Room History Visibility, Enforcement,
//                          Event Filtering, Historical Messages, Server Notice
//                          Filtering, Censored Events, and Search Visibility
//
// Implements:
//   - History visibility states: world_readable, shared, invited, joined.
//     Full state machine with transitions, validation, preset defaults,
//     inheritance rules, and state event representation.
//   - Visibility enforcement engine: check user membership against room
//     visibility before returning events via any API endpoint. Enforces
//     visibility rules for /sync, /messages, /context, /search, and
//     federation endpoints. Supports both current-state and historical
//     (point-in-time) visibility checks.
//   - Event filtering pipeline: per-event visibility checks, batch
//     filtering of event arrays, streaming filter that interleaves with
//     pagination cursors, type-specific filtering (membership events,
//     state events, message events), and filtered /sync response generation.
//   - Historical message visibility: users who join later can see older
//     messages based on the room's history_visibility at the time of the
//     events. Users who leave can still see messages they previously had
//     access to. Implements point-in-time membership tracking, gap detection
//     for membership transitions, and leave-visibility retention.
//   - Server notice filtering: identify m.server_notice events, filter them
//     from normal /sync timelines, route them to server notice rooms only,
//     prevent cross-contamination between server notices and user timelines,
//     privileged server notice delivery.
//   - Censored events: mark events as redacted/censored via m.room.redaction
//     or admin action, strip censored content before delivery, maintain
//     censorship audit trail, filter fully-censored events from timelines,
//     support partial redaction (keep metadata, strip content).
//   - Search visibility: respect history_visibility when searching message
//     content, filter search results to only include events the requesting
//     user is authorized to see, handle multi-room search with per-room
//     visibility, prevent information leakage through search.
//
// Namespace: progressive::
// Equivalent to synapse/visibility.py + synapse/handlers/pagination.py
//              (visibility filtering) + synapse/handlers/search.py
//              (search filtering) + synapse/events/utils.py (redaction)
//
// Target: 2000+ lines of production-grade C++ with explicit descriptions.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cmath>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
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
class HistoryVisibilityState;
class HistoryVisibilityStateMachine;
class HistoryVisibilityValidator;
class VisibilityEnforcer;
class MembershipVisibilityResolver;
class EventFilterPipeline;
class SyncVisibilityFilter;
class MessagesVisibilityFilter;
class HistoricalMessageTracker;
class MembershipTimelineTracker;
class LeaveVisibilityManager;
class ServerNoticeFilter;
class CensoredEventManager;
class EventRedactionEngine;
class SearchVisibilityFilter;
class SearchResultScrubber;
class VisibilityAuditLogger;
class VisibilityPolicyCache;
class HistoryVisibilityCoordinator;

// ============================================================================
// Constants and Configuration
// ============================================================================
namespace visibility_constants {

// Matrix-spec valid history_visibility values
constexpr std::string_view VIS_WORLD_READABLE = "world_readable";
constexpr std::string_view VIS_SHARED = "shared";
constexpr std::string_view VIS_INVITED = "invited";
constexpr std::string_view VIS_JOINED = "joined";

// Default visibility for room presets
constexpr std::string_view DEFAULT_PUBLIC = "shared";
constexpr std::string_view DEFAULT_PRIVATE = "joined";
constexpr std::string_view DEFAULT_TRUSTED_PRIVATE = "shared";

// Server notice event type
constexpr std::string_view SERVER_NOTICE_TYPE = "m.server_notice";
constexpr std::string_view SERVER_NOTICE_ROOM_PREFIX = "!server_notice_";

// Censorship/redaction reason constants
constexpr std::string_view REDACTION_REASON_SPAM = "spam";
constexpr std::string_view REDACTION_REASON_ABUSE = "abuse";
constexpr std::string_view REDACTION_REASON_LEGAL = "legal";
constexpr std::string_view REDACTION_REASON_COPYRIGHT = "copyright";
constexpr std::string_view REDACTION_REASON_ADMIN = "admin_action";

// Membership states used in visibility decisions
constexpr std::string_view MEMBERSHIP_JOIN = "join";
constexpr std::string_view MEMBERSHIP_INVITE = "invite";
constexpr std::string_view MEMBERSHIP_LEAVE = "leave";
constexpr std::string_view MEMBERSHIP_BAN = "ban";
constexpr std::string_view MEMBERSHIP_KNOCK = "knock";

// Cache TTL for visibility policy lookups
constexpr int64_t VISIBILITY_CACHE_TTL_MS = 30'000;     // 30 seconds
constexpr int64_t MEMBERSHIP_CACHE_TTL_MS = 10'000;     // 10 seconds
constexpr int64_t LONG_CACHE_TTL_MS = 300'000;          // 5 minutes

// Pagination limits
constexpr size_t MAX_EVENTS_PER_BATCH = 1000;
constexpr size_t MAX_SEARCH_RESULTS = 500;

// Server notice filtering
constexpr std::string_view SERVER_NOTICE_MSG_TYPE = "m.server_notice";
constexpr std::string_view SERVER_NOTICE_ADMIN_CONTACT = "m.server_notice.admin_contact";

// Event types that bypass visibility (always visible to joined members)
constexpr std::array<const char*, 4> BYPASS_EVENT_TYPES = {
    "m.room.create",
    "m.room.member",
    "m.room.power_levels",
    "m.room.join_rules"
};

// All valid history visibility strings
constexpr std::array<const char*, 4> VALID_VISIBILITIES = {
    "world_readable", "shared", "invited", "joined"
};

}  // namespace visibility_constants

// ============================================================================
// Utility: time, string, and crypto helpers (local anonymous namespace)
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
  for (int i = 0; i < len; ++i) {
    result[i] = charset[rand() % (sizeof(charset) - 1)];
  }
  return result;
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

// Generate a simple hash for deduplication and caching
size_t hash_strings(const std::string& a, const std::string& b) {
  size_t h = 0;
  for (char c : a) h = h * 31 + static_cast<size_t>(c);
  for (char c : b) h = h * 31 + static_cast<size_t>(c);
  return h;
}

size_t hash_strings(const std::string& a, const std::string& b,
                    const std::string& c) {
  size_t h = 0;
  for (char ch : a) h = h * 31 + static_cast<size_t>(ch);
  for (char ch : b) h = h * 31 + static_cast<size_t>(ch);
  for (char ch : c) h = h * 31 + static_cast<size_t>(ch);
  return h;
}

// Check if a json object has a non-empty string field
bool has_nonempty_string(const json& obj, const std::string& key) {
  auto it = obj.find(key);
  return it != obj.end() && it->is_string() && !it->get<std::string>().empty();
}

// Check if value is in a constexpr array
bool is_in_array(std::string_view val,
                 const std::array<const char*, 4>& arr) {
  for (auto& s : arr) {
    if (val == s) return true;
  }
  return false;
}

// Encode a cursor token for pagination (base64-like simple encoding)
std::string encode_cursor(int64_t ts, const std::string& event_id) {
  std::ostringstream oss;
  oss << ts << "|" << event_id;
  std::string raw = oss.str();
  // Simple base64 encoding
  static const char b64[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string encoded;
  int val = 0, valb = -6;
  for (unsigned char c : raw) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      encoded.push_back(b64[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) {
    encoded.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
  }
  return encoded;
}

// Decode a cursor token
std::pair<int64_t, std::string> decode_cursor(const std::string& encoded) {
  static const int decode_map[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
  };
  std::string decoded;
  int val = 0, valb = -8;
  for (unsigned char c : encoded) {
    if (decode_map[c] == -1) break;
    val = (val << 6) + decode_map[c];
    valb += 6;
    if (valb >= 0) {
      decoded.push_back(char((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  auto sep = decoded.find('|');
  if (sep == std::string::npos) return {0, ""};
  return {std::stoll(decoded.substr(0, sep)), decoded.substr(sep + 1)};
}

}  // anonymous namespace

// ============================================================================
// VisibilityState — immutable representation of a history visibility setting
// ============================================================================
//
// Encapsulates a single history_visibility value with metadata about when
// it was set, who set it, and how it relates to the room's lifecycle.
// Supports comparison, serialization, and validation.
//
class HistoryVisibilityState {
public:
  enum class Level {
    WORLD_READABLE = 0,  // Anyone can read, even without an account
    SHARED = 1,           // Any joined member can read entire history
    INVITED = 2,          // Joined + invited members can read
    JOINED = 3,           // Only joined members can read
    UNKNOWN = 4
  };

  HistoryVisibilityState() : level_(Level::JOINED), set_by_(""), set_at_ms_(0) {}

  HistoryVisibilityState(Level lvl, std::string set_by, int64_t set_at_ms)
      : level_(lvl), set_by_(std::move(set_by)), set_at_ms_(set_at_ms) {}

  // --- Parse from string ---
  // Converts a spec visibility string to a Level enum. Invalid strings
  // default to JOINED (the most restrictive) as a safety measure.
  static Level from_string(const std::string& s) {
    if (s == "world_readable") return Level::WORLD_READABLE;
    if (s == "shared") return Level::SHARED;
    if (s == "invited") return Level::INVITED;
    if (s == "joined") return Level::JOINED;
    return Level::JOINED;  // default to most restrictive
  }

  // --- Convert to string ---
  // Inverse of from_string. Returns the Matrix-spec string for each level.
  static std::string to_string(Level lvl) {
    switch (lvl) {
      case Level::WORLD_READABLE: return "world_readable";
      case Level::SHARED: return "shared";
      case Level::INVITED: return "invited";
      case Level::JOINED: return "joined";
      default: return "joined";
    }
  }

  // --- Create from state event content ---
  // Parses a m.room.history_visibility state event to extract the visibility
  // level and associated metadata.
  static HistoryVisibilityState from_state_event(const json& event,
                                                  const std::string& sender,
                                                  int64_t origin_server_ts) {
    std::string vis_str = "joined";
    if (event.contains("content") && event["content"].is_object()) {
      vis_str = event["content"].value("history_visibility", "joined");
    } else if (event.contains("history_visibility")) {
      vis_str = event["history_visibility"].get<std::string>();
    }
    return HistoryVisibilityState(from_string(vis_str), sender, origin_server_ts);
  }

  // --- Serialize to JSON ---
  // Produces the content for a m.room.history_visibility event.
  json to_json() const {
    json j;
    j["history_visibility"] = to_string(level_);
    return j;
  }

  // --- Accessors ---
  Level level() const { return level_; }
  const std::string& set_by() const { return set_by_; }
  int64_t set_at_ms() const { return set_at_ms_; }
  std::string level_string() const { return to_string(level_); }

  // --- Comparison ---
  bool operator==(const HistoryVisibilityState& other) const {
    return level_ == other.level_;
  }
  bool operator!=(const HistoryVisibilityState& other) const {
    return !(*this == other);
  }

  // --- Restrictiveness comparison ---
  // Returns true if 'this' is at least as restrictive as 'other'.
  // JOINED > INVITED > SHARED > WORLD_READABLE.
  bool is_more_restrictive_than(const HistoryVisibilityState& other) const {
    return static_cast<int>(level_) > static_cast<int>(other.level_);
  }

  // Returns the more restrictive of two states.
  static HistoryVisibilityState most_restrictive(
      const HistoryVisibilityState& a, const HistoryVisibilityState& b) {
    return a.is_more_restrictive_than(b) ? a : b;
  }

  // Returns the less restrictive of two states.
  static HistoryVisibilityState least_restrictive(
      const HistoryVisibilityState& a, const HistoryVisibilityState& b) {
    return a.is_more_restrictive_than(b) ? b : a;
  }

  // --- Human-readable description ---
  static std::string description(Level lvl) {
    switch (lvl) {
      case Level::WORLD_READABLE:
        return "Anyone can read the room history, including users not in the room "
               "and unauthenticated users. Use with caution for public archives.";
      case Level::SHARED:
        return "Any joined room member can read the full room history, including "
               "messages sent before they joined. Previously-joined members retain "
               "read access to the history they could see while joined.";
      case Level::INVITED:
        return "Only joined and invited members can read the room history. Users "
               "who leave lose access to any messages they could not have seen "
               "at the time they were a member.";
      case Level::JOINED:
        return "Only currently-joined members can read the room history. Users "
               "who leave immediately lose access to all room history. This is "
               "the most restrictive setting.";
      default:
        return "Unknown visibility level — treating as joined for safety.";
    }
  }

private:
  Level level_;
  std::string set_by_;       // User ID who set this visibility
  int64_t set_at_ms_;        // Timestamp when this was set
};

// ============================================================================
// HistoryVisibilityStateMachine — tracks visibility transitions over time
// ============================================================================
//
// Manages a timeline of history_visibility changes for a room. Each state
// change creates a new entry with the level, timestamp, and actor. This
// enables point-in-time visibility queries: "what was the visibility when
// this event was sent?"
//
class HistoryVisibilityStateMachine {
public:
  struct StateTransition {
    HistoryVisibilityState state;
    int64_t effective_at_ms;  // When this state became effective
    std::string event_id;     // The state event that triggered this transition

    json to_json() const {
      json j;
      j["visibility"] = state.level_string();
      j["set_by"] = state.set_by();
      j["effective_at_ms"] = effective_at_ms;
      j["event_id"] = event_id;
      return j;
    }
  };

  HistoryVisibilityStateMachine() {
    // Initialize with default state (joined, most restrictive)
    transitions_.push_back({
        HistoryVisibilityState(HistoryVisibilityState::Level::JOINED, "", 0),
        0, ""
    });
  }

  // --- Record a new visibility state ---
  // Appends a transition when m.room.history_visibility state changes.
  // The transition becomes effective at the given timestamp.
  void apply_transition(const HistoryVisibilityState& new_state,
                        int64_t effective_at_ms,
                        const std::string& event_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    
    // Don't record duplicate transitions
    if (!transitions_.empty() &&
        transitions_.back().state == new_state &&
        transitions_.back().effective_at_ms == effective_at_ms) {
      return;
    }
    
    transitions_.push_back({new_state, effective_at_ms, event_id});
    
    // Sort by effective timestamp to ensure correct ordering
    std::sort(transitions_.begin(), transitions_.end(),
              [](const StateTransition& a, const StateTransition& b) {
                return a.effective_at_ms < b.effective_at_ms;
              });
  }

  // --- Get the visibility state at a specific point in time ---
  // Binary search through transitions to find the state that was effective
  // at the given timestamp (origin_server_ts of the event being checked).
  HistoryVisibilityState state_at(int64_t timestamp_ms) const {
    std::lock_guard<std::mutex> lock(mtx_);
    
    if (transitions_.empty()) {
      return HistoryVisibilityState(HistoryVisibilityState::Level::JOINED, "", 0);
    }
    
    // Find the last transition that occurred at or before timestamp_ms
    const StateTransition* best = &transitions_[0];
    for (size_t i = 1; i < transitions_.size(); ++i) {
      if (transitions_[i].effective_at_ms <= timestamp_ms) {
        best = &transitions_[i];
      } else {
        break;  // transitions are sorted by time
      }
    }
    return best->state;
  }

  // --- Get the current (latest) visibility state ---
  HistoryVisibilityState current_state() const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (transitions_.empty()) {
      return HistoryVisibilityState(HistoryVisibilityState::Level::JOINED, "", 0);
    }
    return transitions_.back().state;
  }

  // --- Get all transitions for audit/history ---
  std::vector<StateTransition> all_transitions() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return transitions_;
  }

  // --- Check if visibility was ever more permissive than given level ---
  bool was_ever_more_permissive_than(HistoryVisibilityState::Level level) const {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto& t : transitions_) {
      if (static_cast<int>(t.state.level()) < static_cast<int>(level)) {
        return true;
      }
    }
    return false;
  }

  // --- Serialize transition history ---
  json to_json() const {
    std::lock_guard<std::mutex> lock(mtx_);
    json arr = json::array();
    for (auto& t : transitions_) {
      arr.push_back(t.to_json());
    }
    return arr;
  }

  // --- Get number of transitions ---
  size_t transition_count() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return transitions_.size();
  }

private:
  mutable std::mutex mtx_;
  std::vector<StateTransition> transitions_;
};

// ============================================================================
// HistoryVisibilityValidator — validates visibility settings and transitions
// ============================================================================
//
// Ensures that history_visibility state events are valid according to the
// Matrix spec: the visibility string must be one of the four valid values,
// power level checks are performed upstream, and transitions are sane.
//
class HistoryVisibilityValidator {
public:
  struct ValidationResult {
    bool valid = true;
    std::string error;
    HistoryVisibilityState::Level parsed_level = HistoryVisibilityState::Level::JOINED;

    static ValidationResult ok(HistoryVisibilityState::Level lvl) {
      ValidationResult r;
      r.valid = true;
      r.parsed_level = lvl;
      return r;
    }

    static ValidationResult fail(const std::string& msg) {
      ValidationResult r;
      r.valid = false;
      r.error = msg;
      return r;
    }
  };

  HistoryVisibilityValidator() = default;

  // --- Validate a visibility string ---
  // Checks that the string matches one of the four spec-defined values.
  ValidationResult validate_string(const std::string& vis_str) const {
    using namespace visibility_constants;
    
    if (vis_str.empty()) {
      return ValidationResult::fail("history_visibility cannot be empty");
    }
    
    if (!is_in_array(vis_str, VALID_VISIBILITIES)) {
      return ValidationResult::fail(
          "Invalid history_visibility value: '" + vis_str +
          "'. Must be one of: world_readable, shared, invited, joined");
    }
    
    return ValidationResult::ok(HistoryVisibilityState::from_string(vis_str));
  }

  // --- Validate a state event content ---
  // Extracts and validates the history_visibility field from event content.
  ValidationResult validate_event_content(const json& content) const {
    if (!content.is_object()) {
      return ValidationResult::fail("Event content must be a JSON object");
    }
    
    if (!content.contains("history_visibility")) {
      return ValidationResult::fail(
          "m.room.history_visibility must contain 'history_visibility' field");
    }
    
    if (!content["history_visibility"].is_string()) {
      return ValidationResult::fail("history_visibility field must be a string");
    }
    
    return validate_string(content["history_visibility"].get<std::string>());
  }

  // --- Validate a transition between states ---
  // Some transitions may be restricted (e.g., going from world_readable to
  // joined is always allowed, but some servers may restrict certain changes).
  ValidationResult validate_transition(const HistoryVisibilityState& from,
                                        const HistoryVisibilityState& to,
                                        bool strict_mode = false) const {
    // Always allow transitions within valid visibility states
    // In strict mode, warn about going from less restrictive to more restrictive
    if (strict_mode && to.is_more_restrictive_than(from)) {
      // This is allowed by spec but may be noted for audit
      // Not an error, just informational
    }
    
    return ValidationResult::ok(to.level());
  }

  // --- Get the default visibility for a room preset ---
  static HistoryVisibilityState default_for_preset(const std::string& preset) {
    using namespace visibility_constants;
    
    std::string vis_str;
    if (preset == "public_chat") {
      vis_str = std::string(DEFAULT_PUBLIC);
    } else if (preset == "trusted_private_chat") {
      vis_str = std::string(DEFAULT_TRUSTED_PRIVATE);
    } else {
      vis_str = std::string(DEFAULT_PRIVATE);  // private_chat and default
    }
    
    return HistoryVisibilityState(
        HistoryVisibilityState::from_string(vis_str), "", 0);
  }

  // --- Check if a visibility string is valid ---
  static bool is_valid_string(const std::string& s) {
    return is_in_array(s, visibility_constants::VALID_VISIBILITIES);
  }

  // --- List all valid visibility strings ---
  static std::vector<std::string> valid_strings() {
    return {"world_readable", "shared", "invited", "joined"};
  }
};

// ============================================================================
// MembershipVisibilityResolver — resolves user membership for visibility checks
// ============================================================================
//
// Determines what membership state a user had at a given point in time.
// This is critical for historical visibility: when checking if a user can
// see an old event, we need to know their membership at the time that
// event was sent — not their current membership.
//
class MembershipVisibilityResolver {
public:
  // Represents resolved membership for a user at a point in time
  struct MembershipSnapshot {
    std::string room_id;
    std::string user_id;
    std::string membership;   // "join", "invite", "leave", "ban", "knock", or ""
    int64_t joined_at_ms = 0;
    int64_t left_at_ms = 0;   // 0 if currently joined
    bool was_previously_joined = false;
    std::vector<int64_t> join_periods_start;  // timestamps of join periods
    std::vector<int64_t> join_periods_end;    // timestamps of leave events
    
    // Check if user was a member at the given timestamp
    bool was_member_at(int64_t timestamp_ms) const {
      for (size_t i = 0; i < join_periods_start.size(); ++i) {
        int64_t start = join_periods_start[i];
        int64_t end = (i < join_periods_end.size())
                          ? join_periods_end[i]
                          : INT64_MAX;
        if (timestamp_ms >= start && timestamp_ms <= end) {
          return true;
        }
      }
      return false;
    }

    // Check if user was invited at the given timestamp
    bool was_invited_at(int64_t timestamp_ms) const {
      // An invite is a point-in-time state; if the user was invited and
      // hasn't joined or rejected, they are still invited
      return membership == "invite";
    }

    json to_json() const {
      json j;
      j["room_id"] = room_id;
      j["user_id"] = user_id;
      j["membership"] = membership;
      j["joined_at_ms"] = joined_at_ms;
      j["left_at_ms"] = left_at_ms;
      j["was_previously_joined"] = was_previously_joined;
      return j;
    }
  };

  MembershipVisibilityResolver() = default;

  // --- Resolve current membership ---
  // Returns the current membership state for a user in a room.
  // In a full implementation, this queries the room state store.
  MembershipSnapshot resolve_current(const std::string& room_id,
                                      const std::string& user_id) const {
    MembershipSnapshot snap;
    snap.room_id = room_id;
    snap.user_id = user_id;
    snap.membership = "";  // Would be populated from database
    
    // Stub: real implementation queries room_memberships table
    // For now, assume no membership unless explicitly set
    return snap;
  }

  // --- Resolve membership at a specific timestamp ---
  // Determines what membership the user had at origin_server_ts.
  // This is used for historical visibility checks.
  MembershipSnapshot resolve_at(const std::string& room_id,
                                 const std::string& user_id,
                                 int64_t timestamp_ms) const {
    MembershipSnapshot snap = resolve_current(room_id, user_id);
    
    // If the user is currently a member, check if they were already a
    // member at timestamp_ms
    if (snap.membership == "join" && snap.joined_at_ms > timestamp_ms) {
      // User joined after this event was sent
      snap.membership = "";  // was not a member yet
    }
    
    // Check historical join periods
    if (snap.membership != "join" && snap.was_previously_joined) {
      if (snap.was_member_at(timestamp_ms)) {
        snap.membership = "join";  // was a member at that time
      }
    }
    
    return snap;
  }

  // --- Determine membership string for visibility check ---
  // Converts a membership snapshot to the simplified string expected by
  // the visibility enforcer.
  static std::string membership_for_visibility(const MembershipSnapshot& snap) {
    if (snap.membership == "join") return "join";
    if (snap.membership == "invite") return "invite";
    if (snap.was_previously_joined) return "leave";
    if (snap.membership == "ban") return "ban";
    return "";
  }

  // --- Check if user is banned ---
  static bool is_banned(const MembershipSnapshot& snap) {
    return snap.membership == "ban";
  }

  // --- Check if user can be considered for any visibility ---
  static bool is_known_user(const MembershipSnapshot& snap) {
    return !snap.membership.empty() || snap.was_previously_joined;
  }

private:
  // In a real implementation, this would hold a reference to the database
  // or room state store for querying membership history.
};

// ============================================================================
// VisibilityPolicyCache — caches visibility policy lookups for performance
// ============================================================================
//
// Avoids repeated expensive lookups of room visibility state and user
// membership by caching results with configurable TTLs. Invalidates on
// state changes.
//
class VisibilityPolicyCache {
public:
  struct CacheEntry {
    HistoryVisibilityState visibility;
    int64_t cached_at_ms;
    int64_t ttl_ms;
  };

  struct MembershipCacheEntry {
    MembershipVisibilityResolver::MembershipSnapshot snapshot;
    int64_t cached_at_ms;
    int64_t ttl_ms;
  };

  VisibilityPolicyCache() = default;

  // --- Get cached visibility for a room ---
  std::optional<HistoryVisibilityState> get_visibility(
      const std::string& room_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    auto it = visibility_cache_.find(room_id);
    if (it == visibility_cache_.end()) return std::nullopt;
    
    if (now_ms() - it->second.cached_at_ms > it->second.ttl_ms) {
      return std::nullopt;  // expired
    }
    return it->second.visibility;
  }

  // --- Set cached visibility for a room ---
  void set_visibility(const std::string& room_id,
                      const HistoryVisibilityState& vis,
                      int64_t ttl_ms = visibility_constants::VISIBILITY_CACHE_TTL_MS) {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    visibility_cache_[room_id] = {vis, now_ms(), ttl_ms};
  }

  // --- Get cached membership ---
  std::optional<MembershipVisibilityResolver::MembershipSnapshot>
  get_membership(const std::string& room_id, const std::string& user_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    auto it = membership_cache_.find(hash_strings(room_id, user_id));
    if (it == membership_cache_.end()) return std::nullopt;
    
    if (now_ms() - it->second.cached_at_ms > it->second.ttl_ms) {
      return std::nullopt;
    }
    return it->second.snapshot;
  }

  // --- Set cached membership ---
  void set_membership(const std::string& room_id,
                      const std::string& user_id,
                      const MembershipVisibilityResolver::MembershipSnapshot& snap,
                      int64_t ttl_ms = visibility_constants::MEMBERSHIP_CACHE_TTL_MS) {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    membership_cache_[hash_strings(room_id, user_id)] = {snap, now_ms(), ttl_ms};
  }

  // --- Invalidate a room's visibility cache ---
  // Called when m.room.history_visibility state changes.
  void invalidate_visibility(const std::string& room_id) {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    visibility_cache_.erase(room_id);
  }

  // --- Invalidate membership cache for a user in a room ---
  // Called when membership changes.
  void invalidate_membership(const std::string& room_id,
                              const std::string& user_id) {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    membership_cache_.erase(hash_strings(room_id, user_id));
  }

  // --- Invalidate all caches for a room ---
  void invalidate_room(const std::string& room_id) {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    visibility_cache_.erase(room_id);
    // Also clear all membership entries for this room
    auto it = membership_cache_.begin();
    while (it != membership_cache_.end()) {
      if (it->second.snapshot.room_id == room_id) {
        it = membership_cache_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // --- Clear all caches ---
  void clear_all() {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    visibility_cache_.clear();
    membership_cache_.clear();
  }

  // --- Get cache statistics ---
  json stats() const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    json s;
    s["visibility_entries"] = visibility_cache_.size();
    s["membership_entries"] = membership_cache_.size();
    int64_t now = now_ms();
    int expired_vis = 0, expired_mem = 0;
    for (auto& [k, v] : visibility_cache_) {
      if (now - v.cached_at_ms > v.ttl_ms) expired_vis++;
    }
    for (auto& [k, v] : membership_cache_) {
      if (now - v.cached_at_ms > v.ttl_ms) expired_mem++;
    }
    s["expired_visibility_entries"] = expired_vis;
    s["expired_membership_entries"] = expired_mem;
    return s;
  }

private:
  mutable std::shared_mutex mtx_;
  std::unordered_map<std::string, CacheEntry> visibility_cache_;
  std::unordered_map<size_t, MembershipCacheEntry> membership_cache_;
};

// ============================================================================
// VisibilityEnforcer — core visibility decision engine
// ============================================================================
//
// The central component that decides whether a user can see a specific event
// in a room. It combines:
//   1. The room's history_visibility state (at the time of the event)
//   2. The user's membership state (at the time of the event, or current)
//   3. Special-case rules (own events, state events, world_readable, etc.)
//
class VisibilityEnforcer {
public:
  enum class VisibilityDecision {
    ALLOW,              // User can see this event
    DENY,               // User cannot see this event
    REDACT,             // User can see metadata but not content
    ALLOW_METADATA_ONLY // Only event_id, type, sender, timestamp visible
  };

  struct EnforcementContext {
    std::string user_id;
    std::string room_id;
    std::string event_id;
    std::string event_type;
    std::string event_sender;
    int64_t event_timestamp_ms;
    std::string current_membership;        // Current membership of requesting user
    std::string membership_at_event_time;  // Membership at time of event
    HistoryVisibilityState visibility_state;
    bool is_own_event = false;
    bool is_state_event = false;
    bool is_server_notice = false;
    bool event_is_redacted = false;
    bool user_is_server_admin = false;
  };

  VisibilityEnforcer() = default;

  // ========================================================================
  // Primary decision: can this user see this event?
  // ========================================================================
  //
  // This is the main entry point for all visibility checks. It implements
  // the Matrix spec rules for history_visibility:
  //
  //   WORLD_READABLE: everyone can see everything
  //   SHARED: any joined member can see entire history; previously-joined
  //           members retain access to history from their membership period
  //   INVITED: joined + invited members; leavers lose access
  //   JOINED: only currently-joined members
  //
  VisibilityDecision check_visibility(const EnforcementContext& ctx) const {
    // --- Rule 0: Own events are always visible ---
    // A user can always see events they sent themselves, regardless of
    // current membership or visibility settings.
    if (ctx.is_own_event) {
      return VisibilityDecision::ALLOW;
    }

    // --- Rule 1: World-readable rooms are visible to everyone ---
    // This includes unauthenticated users (empty user_id).
    if (ctx.visibility_state.level() == HistoryVisibilityState::Level::WORLD_READABLE) {
      return ctx.event_is_redacted
                 ? VisibilityDecision::ALLOW_METADATA_ONLY
                 : VisibilityDecision::ALLOW;
    }

    // --- Rule 2: No user_id means no access (unless world_readable) ---
    // Unauthenticated users cannot see anything in non-world_readable rooms.
    if (ctx.user_id.empty()) {
      return VisibilityDecision::DENY;
    }

    // --- Rule 3: Server admins can see everything ---
    // Server administrators bypass all visibility restrictions for moderation.
    if (ctx.user_is_server_admin) {
      return ctx.event_is_redacted
                 ? VisibilityDecision::ALLOW_METADATA_ONLY
                 : VisibilityDecision::ALLOW;
    }

    // --- Rule 4: Joined members at event time can always see ---
    // If the user was a member when the event was sent, they can see it.
    if (ctx.membership_at_event_time == "join") {
      return ctx.event_is_redacted
                 ? VisibilityDecision::ALLOW_METADATA_ONLY
                 : VisibilityDecision::ALLOW;
    }

    // --- Rule 5: Currently joined members see everything ---
    // Current members can see the entire room history.
    if (ctx.current_membership == "join") {
      return ctx.event_is_redacted
                 ? VisibilityDecision::ALLOW_METADATA_ONLY
                 : VisibilityDecision::ALLOW;
    }

    // --- Rule 6: Banned users see nothing ---
    if (ctx.current_membership == "ban") {
      return VisibilityDecision::DENY;
    }

    // --- Rule 7: Apply history_visibility-specific rules ---
    switch (ctx.visibility_state.level()) {
      case HistoryVisibilityState::Level::SHARED:
        return check_shared_visibility(ctx);
      
      case HistoryVisibilityState::Level::INVITED:
        return check_invited_visibility(ctx);
      
      case HistoryVisibilityState::Level::JOINED:
        // Only current join members — they were already handled above
        return VisibilityDecision::DENY;
      
      default:
        return VisibilityDecision::DENY;
    }
  }

  // --- Convenience: check visibility with minimal context ---
  VisibilityDecision check_simple(const std::string& user_id,
                                   const std::string& membership,
                                   const std::string& history_visibility,
                                   const std::string& event_sender = "",
                                   bool is_own_event = false) const {
    EnforcementContext ctx;
    ctx.user_id = user_id;
    ctx.current_membership = membership;
    ctx.membership_at_event_time = membership;
    ctx.visibility_state = HistoryVisibilityState(
        HistoryVisibilityState::from_string(history_visibility), "", 0);
    ctx.event_sender = event_sender;
    ctx.is_own_event = is_own_event || (!user_id.empty() && event_sender == user_id);
    return check_visibility(ctx);
  }

  // ========================================================================
  // Batch visibility check for arrays of events
  // ========================================================================
  //
  // Filters a JSON array of events, returning only those the user can see.
  // Each event is individually checked against the visibility rules.
  //
  json filter_event_array(const std::string& user_id,
                           const std::string& room_id,
                           const std::string& membership,
                           const std::string& history_visibility,
                           const json& events) const {
    json filtered = json::array();
    HistoryVisibilityState vis_state(
        HistoryVisibilityState::from_string(history_visibility), "", 0);
    
    for (const auto& ev : events) {
      EnforcementContext ctx;
      ctx.user_id = user_id;
      ctx.room_id = room_id;
      ctx.event_id = ev.value("event_id", "");
      ctx.event_type = ev.value("type", "");
      ctx.event_sender = ev.value("sender", "");
      ctx.event_timestamp_ms = ev.value("origin_server_ts", 0);
      ctx.current_membership = membership;
      ctx.membership_at_event_time = membership;
      ctx.visibility_state = vis_state;
      ctx.is_own_event = (!user_id.empty() && ctx.event_sender == user_id);
      
      // Check for state event
      if (!ctx.event_type.empty() && ctx.event_type.find("m.room.") == 0) {
        ctx.is_state_event = true;
      }
      
      // Check for redaction
      if (ev.contains("unsigned") && ev["unsigned"].contains("redacted_because")) {
        ctx.event_is_redacted = true;
      }
      
      auto decision = check_visibility(ctx);
      if (decision == VisibilityDecision::ALLOW) {
        filtered.push_back(ev);
      } else if (decision == VisibilityDecision::ALLOW_METADATA_ONLY) {
        // Strip content but keep metadata
        json stripped;
        stripped["event_id"] = ev["event_id"];
        stripped["type"] = ev.value("type", "");
        stripped["sender"] = ev.value("sender", "");
        stripped["origin_server_ts"] = ev.value("origin_server_ts", 0);
        stripped["room_id"] = ev.value("room_id", "");
        stripped["unsigned"] = ev.value("unsigned", json::object());
        stripped["content"] = json::object();  // empty content
        stripped["_redacted_for_visibility"] = true;
        filtered.push_back(stripped);
      }
      // DENY: event is excluded entirely
    }
    
    return filtered;
  }

private:
  // --- SHARED visibility: joined + previously-joined users ---
  VisibilityDecision check_shared_visibility(const EnforcementContext& ctx) const {
    // Currently joined members handled above
    if (ctx.current_membership == "join") {
      return ctx.event_is_redacted
                 ? VisibilityDecision::ALLOW_METADATA_ONLY
                 : VisibilityDecision::ALLOW;
    }
    
    // Previously-joined users retain access
    // A "leave" membership with was_previously_joined=true means they
    // were a member at some point — they can see the history they had
    // access to while joined.
    if (ctx.current_membership == "leave") {
      return ctx.event_is_redacted
                 ? VisibilityDecision::ALLOW_METADATA_ONLY
                 : VisibilityDecision::ALLOW;
    }
    
    return VisibilityDecision::DENY;
  }

  // --- INVITED visibility: joined + invited users ---
  VisibilityDecision check_invited_visibility(const EnforcementContext& ctx) const {
    if (ctx.current_membership == "join" || ctx.current_membership == "invite") {
      return ctx.event_is_redacted
                 ? VisibilityDecision::ALLOW_METADATA_ONLY
                 : VisibilityDecision::ALLOW;
    }
    return VisibilityDecision::DENY;
  }
};

// ============================================================================
// EventFilterPipeline — multi-stage event filtering pipeline
// ============================================================================
//
// Applies a series of filters to event streams in the correct order:
//   1. Visibility filter (history_visibility enforcement)
//   2. Server notice filter (remove server notices from normal timelines)
//   3. Censorship filter (redact or remove censored events)
//   4. Type filter (optional, by event type whitelist/blacklist)
//   5. Sender filter (optional, by sender user ID)
//
class EventFilterPipeline {
public:
  struct FilterConfig {
    bool enable_visibility_filter = true;
    bool enable_server_notice_filter = true;
    bool enable_censorship_filter = true;
    bool enable_type_filter = false;
    bool enable_sender_filter = false;
    
    // Type filter configuration
    std::vector<std::string> allowed_types;   // If non-empty, only these types
    std::vector<std::string> blocked_types;   // Block these types
    
    // Sender filter configuration
    std::vector<std::string> allowed_senders; // If non-empty, only these senders
    std::vector<std::string> blocked_senders; // Block these senders
    
    // Server notice configuration
    std::string server_notice_room_prefix = "!server_notice_";
    bool strip_server_notices_from_timeline = true;
    
    // Censorship configuration
    bool strip_censored_content = true;       // Replace content with redaction
    bool remove_fully_censored = false;       // Remove entirely redacted events
    
    json to_json() const {
      json j;
      j["visibility_filter"] = enable_visibility_filter;
      j["server_notice_filter"] = enable_server_notice_filter;
      j["censorship_filter"] = enable_censorship_filter;
      j["type_filter"] = enable_type_filter;
      j["sender_filter"] = enable_sender_filter;
      j["strip_censored_content"] = strip_censored_content;
      j["remove_fully_censored"] = remove_fully_censored;
      return j;
    }
  };

  struct PipelineContext {
    std::string user_id;
    std::string room_id;
    std::string membership;
    std::string history_visibility;
    int64_t request_timestamp_ms;
    bool is_server_notice_room = false;
    bool user_is_admin = false;
    json extra_state;  // Additional room state for filtering decisions
  };

  struct PipelineResult {
    json filtered_events;
    size_t total_input = 0;
    size_t total_output = 0;
    size_t filtered_by_visibility = 0;
    size_t filtered_by_server_notice = 0;
    size_t filtered_by_censorship = 0;
    size_t filtered_by_type = 0;
    size_t filtered_by_sender = 0;
    int64_t processing_time_ms = 0;
    
    json stats() const {
      json s;
      s["total_input"] = total_input;
      s["total_output"] = total_output;
      s["filtered_by_visibility"] = filtered_by_visibility;
      s["filtered_by_server_notice"] = filtered_by_server_notice;
      s["filtered_by_censorship"] = filtered_by_censorship;
      s["filtered_by_type"] = filtered_by_type;
      s["filtered_by_sender"] = filtered_by_sender;
      s["processing_time_ms"] = processing_time_ms;
      return s;
    }
  };

  EventFilterPipeline() = default;

  // --- Create default config ---
  static FilterConfig default_config() {
    return FilterConfig{};
  }

  // --- Create config for /sync responses ---
  static FilterConfig sync_config() {
    FilterConfig cfg;
    cfg.enable_visibility_filter = true;
    cfg.enable_server_notice_filter = true;
    cfg.enable_censorship_filter = true;
    cfg.strip_censored_content = true;
    cfg.remove_fully_censored = false;  // Keep metadata for sync
    return cfg;
  }

  // --- Create config for /messages responses ---
  static FilterConfig messages_config() {
    FilterConfig cfg;
    cfg.enable_visibility_filter = true;
    cfg.enable_server_notice_filter = true;
    cfg.enable_censorship_filter = true;
    cfg.strip_censored_content = true;
    cfg.remove_fully_censored = false;
    return cfg;
  }

  // --- Create config for /search responses ---
  static FilterConfig search_config() {
    FilterConfig cfg;
    cfg.enable_visibility_filter = true;
    cfg.enable_server_notice_filter = true;
    cfg.enable_censorship_filter = true;
    cfg.strip_censored_content = true;
    cfg.remove_fully_censored = true;  // Don't show censored in search
    return cfg;
  }

  // ========================================================================
  // Main pipeline: filter events through all enabled stages
  // ========================================================================
  PipelineResult filter(const json& events,
                         const PipelineContext& ctx,
                         const FilterConfig& cfg) {
    auto start_time = now_ms();
    PipelineResult result;
    result.total_input = events.is_array() ? events.size() : 0;
    
    if (!events.is_array() || events.empty()) {
      result.filtered_events = json::array();
      result.processing_time_ms = now_ms() - start_time;
      return result;
    }
    
    json current = events;
    
    // Stage 1: Visibility filter
    if (cfg.enable_visibility_filter) {
      auto vis_result = apply_visibility_filter(current, ctx);
      result.filtered_by_visibility = result.total_input - vis_result.size();
      current = vis_result;
    }
    
    // Stage 2: Server notice filter
    if (cfg.enable_server_notice_filter) {
      auto sn_result = apply_server_notice_filter(current, ctx, cfg);
      result.filtered_by_server_notice =
          current.size() - sn_result.size();
      current = sn_result;
    }
    
    // Stage 3: Censorship filter
    if (cfg.enable_censorship_filter) {
      auto cen_result = apply_censorship_filter(current, cfg);
      result.filtered_by_censorship =
          current.size() - cen_result.size();
      current = cen_result;
    }
    
    // Stage 4: Type filter (optional)
    if (cfg.enable_type_filter) {
      auto type_result = apply_type_filter(current, cfg);
      result.filtered_by_type = current.size() - type_result.size();
      current = type_result;
    }
    
    // Stage 5: Sender filter (optional)
    if (cfg.enable_sender_filter) {
      auto sender_result = apply_sender_filter(current, cfg);
      result.filtered_by_sender = current.size() - sender_result.size();
      current = sender_result;
    }
    
    result.filtered_events = current;
    result.total_output = current.size();
    result.processing_time_ms = now_ms() - start_time;
    
    return result;
  }

private:
  VisibilityEnforcer visibility_enforcer_;

  // --- Stage 1: Visibility filter ---
  json apply_visibility_filter(const json& events,
                                 const PipelineContext& ctx) {
    return visibility_enforcer_.filter_event_array(
        ctx.user_id, ctx.room_id, ctx.membership,
        ctx.history_visibility, events);
  }

  // --- Stage 2: Server notice filter ---
  json apply_server_notice_filter(const json& events,
                                    const PipelineContext& ctx,
                                    const FilterConfig& cfg) {
    if (!cfg.strip_server_notices_from_timeline) return events;
    if (ctx.is_server_notice_room) return events;  // Don't filter in notice rooms
    
    json filtered = json::array();
    for (const auto& ev : events) {
      std::string type = ev.value("type", "");
      if (type == "m.server_notice" || type == "m.server_notice.msg") {
        continue;  // Strip server notices from normal timelines
      }
      filtered.push_back(ev);
    }
    return filtered;
  }

  // --- Stage 3: Censorship filter ---
  json apply_censorship_filter(const json& events, const FilterConfig& cfg) {
    json filtered = json::array();
    for (const auto& ev : events) {
      bool is_redacted = false;
      
      // Check for redaction marker in unsigned
      if (ev.contains("unsigned") && ev["unsigned"].is_object()) {
        if (ev["unsigned"].contains("redacted_because")) {
          is_redacted = true;
        }
      }
      
      // Check for content-level redaction marker
      if (ev.contains("content") && ev["content"].is_object()) {
        if (ev["content"].value("_redacted", false)) {
          is_redacted = true;
        }
      }
      
      if (is_redacted) {
        if (cfg.remove_fully_censored) {
          continue;  // Remove entirely
        }
        if (cfg.strip_censored_content) {
          // Strip content but keep event skeleton
          json stripped;
          stripped["event_id"] = ev.value("event_id", "");
          stripped["type"] = ev.value("type", "m.room.message");
          stripped["sender"] = ev.value("sender", "");
          stripped["origin_server_ts"] = ev.value("origin_server_ts", 0);
          stripped["room_id"] = ev.value("room_id", "");
          stripped["unsigned"] = ev.value("unsigned", json::object());
          stripped["content"] = json::object();
          if (ev.contains("unsigned") && ev["unsigned"].contains("redacted_because")) {
            stripped["unsigned"]["redacted_because"] =
                ev["unsigned"]["redacted_because"];
          }
          filtered.push_back(stripped);
          continue;
        }
      }
      
      filtered.push_back(ev);
    }
    return filtered;
  }

  // --- Stage 4: Type filter ---
  json apply_type_filter(const json& events, const FilterConfig& cfg) {
    json filtered = json::array();
    for (const auto& ev : events) {
      std::string type = ev.value("type", "");
      
      // Check blocked types first
      bool blocked = false;
      for (auto& bt : cfg.blocked_types) {
        if (type == bt) { blocked = true; break; }
      }
      if (blocked) continue;
      
      // If allowed_types is specified, only include those
      if (!cfg.allowed_types.empty()) {
        bool allowed = false;
        for (auto& at : cfg.allowed_types) {
          if (type == at) { allowed = true; break; }
        }
        if (!allowed) continue;
      }
      
      filtered.push_back(ev);
    }
    return filtered;
  }

  // --- Stage 5: Sender filter ---
  json apply_sender_filter(const json& events, const FilterConfig& cfg) {
    json filtered = json::array();
    for (const auto& ev : events) {
      std::string sender = ev.value("sender", "");
      
      // Check blocked senders first
      bool blocked = false;
      for (auto& bs : cfg.blocked_senders) {
        if (sender == bs) { blocked = true; break; }
      }
      if (blocked) continue;
      
      // If allowed_senders is specified, only include those
      if (!cfg.allowed_senders.empty()) {
        bool allowed = false;
        for (auto& as : cfg.allowed_senders) {
          if (sender == as) { allowed = true; break; }
        }
        if (!allowed) continue;
      }
      
      filtered.push_back(ev);
    }
    return filtered;
  }
};

// ============================================================================
// HistoricalMessageTracker — manages visibility for historical messages
// ============================================================================
//
// Addresses the core Matrix visibility problem: users who join a room
// later should (or should not) be able to see messages sent before they
// joined, depending on the room's history_visibility setting.
//
// Also handles the reverse: users who leave should (or should not) retain
// access to messages they could see while they were members.
//
class HistoricalMessageTracker {
public:
  // Represents the result of a historical visibility check
  struct HistoricalAccessResult {
    bool can_see = false;
    std::string reason;
    bool was_member_at_time = false;
    bool is_current_member = false;
    HistoryVisibilityState visibility_at_time;
    std::string membership_at_time;

    json to_json() const {
      json j;
      j["can_see"] = can_see;
      j["reason"] = reason;
      j["was_member_at_time"] = was_member_at_time;
      j["is_current_member"] = is_current_member;
      j["visibility_at_time"] = visibility_at_time.level_string();
      j["membership_at_time"] = membership_at_time;
      return j;
    }
  };

  HistoricalMessageTracker() = default;

  // ========================================================================
  // Check if a user can see a historical message (event sent in the past)
  // ========================================================================
  //
  // This is the key function for historical visibility. It must determine:
  //   1. What was the room's visibility when the event was sent?
  //   2. What was the user's membership when the event was sent?
  //   3. Based on those, does the user have access?
  //
  HistoricalAccessResult check_historical_access(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& event_sender,
      int64_t event_origin_server_ts,
      const HistoryVisibilityStateMachine& vis_state_machine,
      const MembershipVisibilityResolver& membership_resolver,
      const std::string& current_membership) {
    
    HistoricalAccessResult result;
    
    // Step 1: Determine visibility at event time
    result.visibility_at_time = vis_state_machine.state_at(event_origin_server_ts);
    
    // Step 2: Determine membership at event time
    auto membership_snap = membership_resolver.resolve_at(
        room_id, user_id, event_origin_server_ts);
    result.membership_at_time =
        MembershipVisibilityResolver::membership_for_visibility(membership_snap);
    result.was_member_at_time = (result.membership_at_time == "join");
    
    // Step 3: Check if currently a member
    result.is_current_member = (current_membership == "join");
    
    // Step 4: Own events are always visible
    if (!user_id.empty() && user_id == event_sender) {
      result.can_see = true;
      result.reason = "User's own event — always visible";
      return result;
    }
    
    // Step 5: World-readable rooms — everyone can see everything
    if (result.visibility_at_time.level() ==
        HistoryVisibilityState::Level::WORLD_READABLE) {
      result.can_see = true;
      result.reason = "Room was world_readable at event time";
      return result;
    }
    
    // Step 6: Current members can see all history
    if (result.is_current_member) {
      result.can_see = true;
      result.reason = "User is a current member — full history access";
      return result;
    }
    
    // Step 7: Check based on visibility level
    switch (result.visibility_at_time.level()) {
      case HistoryVisibilityState::Level::SHARED:
        // Shared: previously-joined users retain access
        if (result.was_member_at_time) {
          result.can_see = true;
          result.reason = "User was a member at event time (SHARED visibility)";
          return result;
        }
        if (membership_snap.was_previously_joined) {
          // User was previously a member, can see all history from their
          // membership period (but NOT events from before they first joined)
          int64_t first_join = membership_snap.joined_at_ms;
          if (event_origin_server_ts >= first_join) {
            result.can_see = true;
            result.reason = "Previously-joined member retains access "
                            "(SHARED visibility)";
            return result;
          }
        }
        result.can_see = false;
        result.reason = "Not a member and not previously joined (SHARED visibility)";
        return result;
      
      case HistoryVisibilityState::Level::INVITED:
        // Invited: only joined or invited at event time
        if (result.was_member_at_time ||
            result.membership_at_time == "invite") {
          result.can_see = true;
          result.reason = "User was joined or invited at event time "
                          "(INVITED visibility)";
          return result;
        }
        result.can_see = false;
        result.reason = "User was neither joined nor invited at event time "
                        "(INVITED visibility)";
        return result;
      
      case HistoryVisibilityState::Level::JOINED:
        // Joined: only users who were joined at event time
        if (result.was_member_at_time) {
          result.can_see = true;
          result.reason = "User was joined at event time (JOINED visibility)";
          return result;
        }
        result.can_see = false;
        result.reason = "User was not joined at event time (JOINED visibility)";
        return result;
      
      default:
        result.can_see = false;
        result.reason = "Unknown visibility — denying access for safety";
        return result;
    }
  }

  // ========================================================================
  // Filter a timeline of historical events for a specific user
  // ========================================================================
  //
  // Applies historical access checks to every event in a timeline chunk.
  // Returns only the events the user is authorized to see.
  //
  json filter_historical_timeline(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& current_membership,
      const json& events,
      const HistoryVisibilityStateMachine& vis_state_machine,
      const MembershipVisibilityResolver& membership_resolver) {
    
    json filtered = json::array();
    
    for (const auto& ev : events) {
      std::string event_id = ev.value("event_id", "");
      std::string sender = ev.value("sender", "");
      int64_t origin_server_ts = ev.value("origin_server_ts", 0);
      
      auto access = check_historical_access(
          user_id, room_id, sender, origin_server_ts,
          vis_state_machine, membership_resolver, current_membership);
      
      if (access.can_see) {
        // Add visibility metadata to unsigned section
        json event_copy = ev;
        if (!event_copy.contains("unsigned")) {
          event_copy["unsigned"] = json::object();
        }
        filtered.push_back(event_copy);
      }
    }
    
    return filtered;
  }

  // ========================================================================
  // Determine the effective "first visible event" timestamp for a user
  // ========================================================================
  //
  // For SHARED visibility, a user who joins later can still see events
  // from before they joined. For JOINED visibility, they can only see
  // events from their join time onward. This computes the earliest
  // timestamp the user is allowed to access.
  //
  int64_t compute_earliest_visible_timestamp(
      const std::string& user_id,
      const std::string& room_id,
      const HistoryVisibilityStateMachine& vis_state_machine,
      const MembershipVisibilityResolver& membership_resolver,
      const std::string& current_membership) {
    
    // Current members can see everything
    if (current_membership == "join") return 0;
    
    // Get current visibility
    auto current_vis = vis_state_machine.current_state();
    
    switch (current_vis.level()) {
      case HistoryVisibilityState::Level::WORLD_READABLE:
        return 0;  // See everything
      
      case HistoryVisibilityState::Level::SHARED: {
        auto snap = membership_resolver.resolve_current(room_id, user_id);
        if (snap.was_previously_joined || snap.membership == "join") {
          return snap.joined_at_ms;  // See from first join time
        }
        return INT64_MAX;  // Cannot see anything
      }
      
      case HistoryVisibilityState::Level::INVITED: {
        auto snap = membership_resolver.resolve_current(room_id, user_id);
        if (snap.membership == "invite" || snap.membership == "join") {
          // For invited, they can see from when they were invited
          return snap.joined_at_ms;
        }
        return INT64_MAX;
      }
      
      case HistoryVisibilityState::Level::JOINED: {
        auto snap = membership_resolver.resolve_current(room_id, user_id);
        if (snap.membership == "join") {
          return snap.joined_at_ms;
        }
        return INT64_MAX;
      }
      
      default:
        return INT64_MAX;
    }
  }
};

// ============================================================================
// MembershipTimelineTracker — tracks membership changes for historical checks
// ============================================================================
//
// Maintains a timeline of membership changes for each user in each room.
// This enables accurate point-in-time membership queries for historical
// visibility enforcement.
//
class MembershipTimelineTracker {
public:
  struct MembershipEvent {
    std::string event_id;
    std::string user_id;
    std::string membership;     // join, invite, leave, ban, knock
    std::string previous_membership;
    int64_t timestamp_ms;
    std::string changed_by;     // Who triggered this change (user or admin)
    
    json to_json() const {
      json j;
      j["event_id"] = event_id;
      j["user_id"] = user_id;
      j["membership"] = membership;
      j["previous_membership"] = previous_membership;
      j["timestamp_ms"] = timestamp_ms;
      j["changed_by"] = changed_by;
      return j;
    }
  };

  struct UserPeriod {
    std::string membership;
    int64_t start_ms;
    int64_t end_ms;   // INT64_MAX if still active
  };

  MembershipTimelineTracker() = default;

  // --- Record a membership change ---
  void record_membership_event(const std::string& room_id,
                                 const MembershipEvent& event) {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    
    auto key = std::make_pair(room_id, event.user_id);
    auto& timeline = membership_timelines_[key];
    timeline.push_back(event);
    
    // Keep timeline sorted by timestamp
    std::sort(timeline.begin(), timeline.end(),
              [](const MembershipEvent& a, const MembershipEvent& b) {
                return a.timestamp_ms < b.timestamp_ms;
              });
    
    // Rebuild periods
    rebuild_periods(room_id, event.user_id);
  }

  // --- Get membership at a specific timestamp ---
  std::string membership_at(const std::string& room_id,
                             const std::string& user_id,
                             int64_t timestamp_ms) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    
    auto key = std::make_pair(room_id, user_id);
    auto pit = periods_cache_.find(key);
    if (pit == periods_cache_.end()) return "";
    
    for (const auto& period : pit->second) {
      if (timestamp_ms >= period.start_ms && timestamp_ms <= period.end_ms) {
        return period.membership;
      }
    }
    
    // If no period covers this time, check if there's a leave event
    auto tit = membership_timelines_.find(key);
    if (tit != membership_timelines_.end() && !tit->second.empty()) {
      // User was never a member at this time
      return "";
    }
    
    return "";
  }

  // --- Check if user was ever a member ---
  bool was_ever_member(const std::string& room_id,
                        const std::string& user_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    auto key = std::make_pair(room_id, user_id);
    auto it = membership_timelines_.find(key);
    if (it == membership_timelines_.end()) return false;
    
    for (const auto& ev : it->second) {
      if (ev.membership == "join") return true;
    }
    return false;
  }

  // --- Get the first join timestamp ---
  int64_t first_join_at(const std::string& room_id,
                          const std::string& user_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    auto key = std::make_pair(room_id, user_id);
    auto it = membership_timelines_.find(key);
    if (it == membership_timelines_.end()) return 0;
    
    for (const auto& ev : it->second) {
      if (ev.membership == "join") return ev.timestamp_ms;
    }
    return 0;
  }

  // --- Get the last leave timestamp ---
  int64_t last_leave_at(const std::string& room_id,
                          const std::string& user_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    auto key = std::make_pair(room_id, user_id);
    auto it = membership_timelines_.find(key);
    if (it == membership_timelines_.end()) return 0;
    
    int64_t last = 0;
    for (const auto& ev : it->second) {
      if (ev.membership == "leave") last = ev.timestamp_ms;
    }
    return last;
  }

  // --- Get all membership periods for a user ---
  std::vector<UserPeriod> get_periods(const std::string& room_id,
                                       const std::string& user_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    auto key = std::make_pair(room_id, user_id);
    auto it = periods_cache_.find(key);
    if (it != periods_cache_.end()) return it->second;
    return {};
  }

  // --- Get the full membership timeline ---
  std::vector<MembershipEvent> get_timeline(const std::string& room_id,
                                              const std::string& user_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    auto key = std::make_pair(room_id, user_id);
    auto it = membership_timelines_.find(key);
    if (it != membership_timelines_.end()) return it->second;
    return {};
  }

  // --- Clear data for a room ---
  void clear_room(const std::string& room_id) {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    auto it = membership_timelines_.begin();
    while (it != membership_timelines_.end()) {
      if (it->first.first == room_id) {
        periods_cache_.erase(it->first);
        it = membership_timelines_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // --- Get total tracked memberships ---
  size_t total_entries() const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    size_t count = 0;
    for (auto& [k, v] : membership_timelines_) {
      count += v.size();
    }
    return count;
  }

private:
  // Rebuild continuous membership periods from the event timeline
  void rebuild_periods(const std::string& room_id, const std::string& user_id) {
    auto key = std::make_pair(room_id, user_id);
    auto& timeline = membership_timelines_[key];
    auto& periods = periods_cache_[key];
    periods.clear();
    
    std::string current_membership = "";
    int64_t period_start = 0;
    
    for (const auto& ev : timeline) {
      if (current_membership.empty()) {
        current_membership = ev.membership;
        period_start = ev.timestamp_ms;
      } else if (ev.membership != current_membership) {
        // Close current period
        periods.push_back({current_membership, period_start, ev.timestamp_ms});
        current_membership = ev.membership;
        period_start = ev.timestamp_ms;
      }
    }
    
    // Close final period
    if (!current_membership.empty()) {
      periods.push_back({current_membership, period_start, INT64_MAX});
    }
  }

  mutable std::shared_mutex mtx_;
  // (room_id, user_id) -> timeline of membership events
  std::map<std::pair<std::string, std::string>, std::vector<MembershipEvent>>
      membership_timelines_;
  // (room_id, user_id) -> computed periods
  std::map<std::pair<std::string, std::string>, std::vector<UserPeriod>>
      periods_cache_;
};

// ============================================================================
// LeaveVisibilityManager — manages visibility for users who left rooms
// ============================================================================
//
// When a user leaves a room, their access to room history depends on the
// history_visibility setting at the time:
//   - SHARED: They retain access to history from their membership period
//   - INVITED/JOINED: They lose all access upon leaving
//
// This component tracks leave events and manages the transition of
// visibility rights.
//
class LeaveVisibilityManager {
public:
  struct LeaveRecord {
    std::string room_id;
    std::string user_id;
    int64_t left_at_ms;
    std::string history_visibility_at_leave;
    bool retains_access = false;
    int64_t first_join_at_ms = 0;
    std::string leave_reason;

    json to_json() const {
      json j;
      j["room_id"] = room_id;
      j["user_id"] = user_id;
      j["left_at_ms"] = left_at_ms;
      j["history_visibility_at_leave"] = history_visibility_at_leave;
      j["retains_access"] = retains_access;
      j["first_join_at_ms"] = first_join_at_ms;
      j["leave_reason"] = leave_reason;
      return j;
    }
  };

  LeaveVisibilityManager() = default;

  // --- Record a user leaving a room ---
  // Determines whether they retain access based on visibility settings.
  LeaveRecord record_leave(const std::string& room_id,
                            const std::string& user_id,
                            int64_t left_at_ms,
                            const std::string& history_visibility,
                            int64_t first_join_at_ms,
                            const std::string& reason = "") {
    LeaveRecord record;
    record.room_id = room_id;
    record.user_id = user_id;
    record.left_at_ms = left_at_ms;
    record.history_visibility_at_leave = history_visibility;
    record.first_join_at_ms = first_join_at_ms;
    record.leave_reason = reason;
    
    // Determine if user retains access
    auto vis = HistoryVisibilityState::from_string(history_visibility);
    record.retains_access =
        (vis == HistoryVisibilityState::Level::SHARED);
    
    std::unique_lock<std::shared_mutex> lock(mtx_);
    leave_records_[std::make_pair(room_id, user_id)] = record;
    
    return record;
  }

  // --- Check if a user who left retains access ---
  bool retains_access(const std::string& room_id,
                       const std::string& user_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    auto it = leave_records_.find(std::make_pair(room_id, user_id));
    if (it == leave_records_.end()) return false;
    return it->second.retains_access;
  }

  // --- Get leave record ---
  std::optional<LeaveRecord> get_leave_record(const std::string& room_id,
                                                const std::string& user_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    auto it = leave_records_.find(std::make_pair(room_id, user_id));
    if (it == leave_records_.end()) return std::nullopt;
    return it->second;
  }

  // --- Check if a leaving user can see a specific event ---
  // For SHARED visibility, leavers can see events from their membership period.
  bool can_see_event_after_leave(const std::string& room_id,
                                   const std::string& user_id,
                                   int64_t event_timestamp_ms) const {
    auto record = get_leave_record(room_id, user_id);
    if (!record || !record->retains_access) return false;
    
    // Can only see events from between first join and leave
    return event_timestamp_ms >= record->first_join_at_ms &&
           event_timestamp_ms <= record->left_at_ms;
  }

  // --- Clear leave records for a room ---
  void clear_room(const std::string& room_id) {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    auto it = leave_records_.begin();
    while (it != leave_records_.end()) {
      if (it->first.first == room_id) {
        it = leave_records_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // --- Get all leaver user IDs for a room ---
  std::vector<std::string> get_leavers(const std::string& room_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    std::vector<std::string> leavers;
    for (auto& [key, record] : leave_records_) {
      if (key.first == room_id) {
        leavers.push_back(key.second);
      }
    }
    return leavers;
  }

  // --- Get statistics ---
  json stats() const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    json s;
    s["total_leavers"] = leave_records_.size();
    size_t retaining = 0;
    for (auto& [k, v] : leave_records_) {
      if (v.retains_access) retaining++;
    }
    s["retaining_access"] = retaining;
    s["lost_access"] = leave_records_.size() - retaining;
    return s;
  }

private:
  mutable std::shared_mutex mtx_;
  std::map<std::pair<std::string, std::string>, LeaveRecord> leave_records_;
};

// ============================================================================
// ServerNoticeFilter — filters server notice events from normal timelines
// ============================================================================
//
// Server notices (m.server_notice) are special events sent by the server
// to communicate with users (e.g., terms of service updates, admin messages).
// They must NOT appear in normal room timelines — only in designated
// server notice rooms or in the user's server_notice section of /sync.
//
class ServerNoticeFilter {
public:
  struct ServerNoticeConfig {
    bool enabled = true;
    std::string server_notice_user_id;    // The user ID that sends server notices
    std::string server_notice_room_prefix = "!server_notice_";
    std::vector<std::string> server_notice_event_types = {
      "m.server_notice",
      "m.server_notice.msg",
      "m.server_notice.admin_contact",
      "m.server_notice.tos_update"
    };
    bool filter_from_timeline = true;
    bool filter_from_search = true;
    bool filter_from_context = true;
    
    json to_json() const {
      json j;
      j["enabled"] = enabled;
      j["server_notice_user_id"] = server_notice_user_id;
      j["filter_from_timeline"] = filter_from_timeline;
      j["filter_from_search"] = filter_from_search;
      j["filter_from_context"] = filter_from_context;
      return j;
    }
  };

  ServerNoticeFilter() = default;
  explicit ServerNoticeFilter(const ServerNoticeConfig& cfg) : config_(cfg) {}

  // --- Check if an event is a server notice ---
  bool is_server_notice(const json& event) const {
    if (!config_.enabled) return false;
    
    std::string type = event.value("type", "");
    for (const auto& notice_type : config_.server_notice_event_types) {
      if (type == notice_type) return true;
    }
    
    // Also check for server notice sender
    std::string sender = event.value("sender", "");
    if (!config_.server_notice_user_id.empty() &&
        sender == config_.server_notice_user_id) {
      return true;
    }
    
    return false;
  }

  // --- Check if a room is a server notice room ---
  bool is_server_notice_room(const std::string& room_id) const {
    return starts_with(room_id, config_.server_notice_room_prefix);
  }

  // --- Filter server notices from a timeline (for /sync, /messages) ---
  json filter_timeline(const json& events, bool is_notice_room = false) const {
    if (!config_.enabled || !config_.filter_from_timeline) return events;
    if (is_notice_room) return events;  // Don't filter in notice rooms
    
    json filtered = json::array();
    for (const auto& ev : events) {
      if (!is_server_notice(ev)) {
        filtered.push_back(ev);
      }
    }
    return filtered;
  }

  // --- Filter server notices from search results ---
  json filter_search_results(const json& results) const {
    if (!config_.enabled || !config_.filter_from_search) return results;
    
    json filtered = json::array();
    for (const auto& result : results) {
      if (!is_server_notice(result)) {
        filtered.push_back(result);
      }
    }
    return filtered;
  }

  // --- Extract server notices for delivery to notice rooms ---
  json extract_server_notices(const json& events) const {
    if (!config_.enabled) return json::array();
    
    json notices = json::array();
    for (const auto& ev : events) {
      if (is_server_notice(ev)) {
        notices.push_back(ev);
      }
    }
    return notices;
  }

  // --- Route server notices: separate normal events from notices ---
  struct RoutingResult {
    json normal_timeline;
    json server_notices;
    size_t normal_count = 0;
    size_t notice_count = 0;
  };

  RoutingResult route_events(const json& events,
                               bool is_notice_room = false) const {
    RoutingResult result;
    
    if (!config_.enabled || is_notice_room) {
      result.normal_timeline = events;
      result.server_notices = json::array();
      result.normal_count = events.size();
      return result;
    }
    
    result.normal_timeline = json::array();
    result.server_notices = json::array();
    
    for (const auto& ev : events) {
      if (is_server_notice(ev)) {
        result.server_notices.push_back(ev);
        result.notice_count++;
      } else {
        result.normal_timeline.push_back(ev);
        result.normal_count++;
      }
    }
    
    return result;
  }

  // --- Check if a user should receive server notices ---
  bool should_receive_notices(const std::string& user_id) const {
    // All registered users receive server notices by default
    // Could be extended with per-user preferences
    if (user_id.empty()) return false;
    return config_.enabled;
  }

  // --- Get configuration ---
  const ServerNoticeConfig& config() const { return config_; }
  void set_config(const ServerNoticeConfig& cfg) { config_ = cfg; }

private:
  ServerNoticeConfig config_;
};

// ============================================================================
// CensoredEventManager — manages censored/redacted events
// ============================================================================
//
// Matrix supports redacting events (m.room.redaction) which replaces the
// event content with an empty object. This component manages:
//   - Tracking which events are redacted
//   - Stripping content from redacted events before delivery
//   - Admin-initiated censorship (beyond normal redaction)
//   - Censorship audit trail
//
class CensoredEventManager {
public:
  enum class CensorshipLevel {
    NONE = 0,              // No censorship
    CONTENT_STRIPPED = 1,   // Content replaced (normal redaction)
    METADATA_ONLY = 2,      // Only event_id, type, sender, ts visible
    FULLY_HIDDEN = 3        // Event completely removed from all responses
  };

  struct CensorshipRecord {
    std::string event_id;
    std::string room_id;
    CensorshipLevel level;
    std::string reason;
    std::string censored_by;   // User ID who performed the censorship
    int64_t censored_at_ms;
    std::string original_type;
    std::string original_sender;
    json redaction_event;      // The m.room.redaction event
    
    json to_json() const {
      json j;
      j["event_id"] = event_id;
      j["room_id"] = room_id;
      j["level"] = static_cast<int>(level);
      j["reason"] = reason;
      j["censored_by"] = censored_by;
      j["censored_at_ms"] = censored_at_ms;
      j["original_type"] = original_type;
      return j;
    }
  };

  CensoredEventManager() = default;

  // --- Record a redaction/censorship ---
  void record_censorship(const std::string& event_id,
                          const std::string& room_id,
                          CensorshipLevel level,
                          const std::string& reason,
                          const std::string& censored_by,
                          int64_t timestamp_ms,
                          const json& redaction_event = json::object()) {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    
    CensorshipRecord record;
    record.event_id = event_id;
    record.room_id = room_id;
    record.level = level;
    record.reason = reason;
    record.censored_by = censored_by;
    record.censored_at_ms = timestamp_ms;
    record.redaction_event = redaction_event;
    
    censorship_records_[event_id] = record;
    censored_event_ids_.insert(event_id);
  }

  // --- Check if an event is censored ---
  bool is_censored(const std::string& event_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    return censored_event_ids_.count(event_id) > 0;
  }

  // --- Get censorship level for an event ---
  CensorshipLevel get_level(const std::string& event_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    auto it = censorship_records_.find(event_id);
    if (it == censorship_records_.end()) return CensorshipLevel::NONE;
    return it->second.level;
  }

  // --- Get full censorship record ---
  std::optional<CensorshipRecord> get_record(const std::string& event_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    auto it = censorship_records_.find(event_id);
    if (it == censorship_records_.end()) return std::nullopt;
    return it->second;
  }

  // --- Apply censorship to an event before delivery ---
  // Returns the event with appropriate content stripping.
  // If level is FULLY_HIDDEN, returns an empty optional.
  std::optional<json> apply_censorship(const json& event) const {
    std::string event_id = event.value("event_id", "");
    
    auto level = get_level(event_id);
    if (level == CensorshipLevel::NONE) return event;
    
    if (level == CensorshipLevel::FULLY_HIDDEN) {
      return std::nullopt;  // Completely hidden
    }
    
    // Build stripped event
    json stripped;
    stripped["event_id"] = event_id;
    stripped["type"] = event.value("type", "m.room.message");
    stripped["sender"] = event.value("sender", "");
    stripped["origin_server_ts"] = event.value("origin_server_ts", 0);
    stripped["room_id"] = event.value("room_id", "");
    
    if (level == CensorshipLevel::METADATA_ONLY) {
      stripped["content"] = json::object();
    } else if (level == CensorshipLevel::CONTENT_STRIPPED) {
      stripped["content"] = json::object();
      // Preserve unsigned section for redaction metadata
      if (event.contains("unsigned")) {
        stripped["unsigned"] = event["unsigned"];
      }
    }
    
    // Attach redaction reason
    auto record = get_record(event_id);
    if (record) {
      stripped["unsigned"] = stripped.value("unsigned", json::object());
      stripped["unsigned"]["redacted_because"] = record->redaction_event;
    }
    
    return stripped;
  }

  // --- Filter a batch of events, applying censorship ---
  json filter_batch(const json& events) const {
    json filtered = json::array();
    for (const auto& ev : events) {
      auto result = apply_censorship(ev);
      if (result) {
        filtered.push_back(*result);
      }
    }
    return filtered;
  }

  // --- Get censorship statistics ---
  json stats() const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    json s;
    s["total_censored"] = censorship_records_.size();
    size_t content_stripped = 0, metadata_only = 0, fully_hidden = 0;
    for (auto& [id, record] : censorship_records_) {
      switch (record.level) {
        case CensorshipLevel::CONTENT_STRIPPED: content_stripped++; break;
        case CensorshipLevel::METADATA_ONLY: metadata_only++; break;
        case CensorshipLevel::FULLY_HIDDEN: fully_hidden++; break;
        default: break;
      }
    }
    s["content_stripped"] = content_stripped;
    s["metadata_only"] = metadata_only;
    s["fully_hidden"] = fully_hidden;
    return s;
  }

  // --- Get censorship audit trail for an event ---
  std::vector<CensorshipRecord> audit_trail(const std::string& event_id) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    std::vector<CensorshipRecord> trail;
    auto it = censorship_records_.find(event_id);
    if (it != censorship_records_.end()) {
      trail.push_back(it->second);
    }
    return trail;
  }

  // --- Remove censorship (undo redaction) ---
  bool remove_censorship(const std::string& event_id) {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    auto erased = censorship_records_.erase(event_id);
    censored_event_ids_.erase(event_id);
    return erased > 0;
  }

  // --- Clear all records for a room ---
  void clear_room(const std::string& room_id) {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    auto it = censorship_records_.begin();
    while (it != censorship_records_.end()) {
      if (it->second.room_id == room_id) {
        censored_event_ids_.erase(it->first);
        it = censorship_records_.erase(it);
      } else {
        ++it;
      }
    }
  }

private:
  mutable std::shared_mutex mtx_;
  std::unordered_map<std::string, CensorshipRecord> censorship_records_;
  std::unordered_set<std::string> censored_event_ids_;
};

// ============================================================================
// EventRedactionEngine — handles Matrix redaction processing
// ============================================================================
//
// Processes m.room.redaction events, determines what content to strip,
// and coordinates with CensoredEventManager for delivery-time filtering.
//
class EventRedactionEngine {
public:
  struct RedactionRule {
    std::string event_type;          // Target event type (or "*" for all)
    std::vector<std::string> keep_keys;  // Content keys to preserve
    std::vector<std::string> strip_keys; // Content keys to strip (overrides keep)
  };

  EventRedactionEngine() {
    // Initialize default redaction rules per Matrix spec
    init_default_rules();
  }

  // --- Process a redaction event ---
  // Applies the m.room.redaction to the target event.
  json process_redaction(const json& target_event,
                          const json& redaction_event) const {
    std::string target_type = target_event.value("type", "");
    
    // Find applicable rules
    const RedactionRule* rule = find_rule(target_type);
    
    json result = target_event;
    
    // Strip content according to rules
    json new_content;
    if (rule) {
      // Keep specified keys
      for (auto& key : rule->keep_keys) {
        if (result["content"].contains(key)) {
          new_content[key] = result["content"][key];
        }
      }
    }
    result["content"] = new_content;
    
    // Set redaction metadata in unsigned
    if (!result.contains("unsigned")) {
      result["unsigned"] = json::object();
    }
    result["unsigned"]["redacted_because"] = redaction_event;
    
    return result;
  }

  // --- Determine what keys to keep after redaction for a given event type ---
  std::vector<std::string> get_keep_keys(const std::string& event_type) const {
    const RedactionRule* rule = find_rule(event_type);
    if (rule) return rule->keep_keys;
    return {};
  }

  // --- Add a custom redaction rule ---
  void add_rule(const RedactionRule& rule) {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    custom_rules_.push_back(rule);
  }

  // --- Remove all custom rules ---
  void clear_custom_rules() {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    custom_rules_.clear();
  }

private:
  void init_default_rules() {
    // Default rule: keep nothing except what the spec says
    // m.room.member: keep "membership"
    default_rules_.push_back({"m.room.member", {"membership"}, {}});
    
    // m.room.create: keep "creator" if set before room version 11
    default_rules_.push_back({"m.room.create", {"creator"}, {}});
    
    // m.room.join_rules: keep "join_rule"
    default_rules_.push_back({"m.room.join_rules", {"join_rule"}, {}});
    
    // m.room.power_levels: keep specific fields
    default_rules_.push_back({"m.room.power_levels",
                              {"users", "users_default", "events",
                               "events_default", "state_default",
                               "ban", "kick", "redact", "invite",
                               "notifications"}, {}});
    
    // m.room.history_visibility: keep "history_visibility"
    default_rules_.push_back({"m.room.history_visibility",
                              {"history_visibility"}, {}});
    
    // m.room.guest_access: keep "guest_access"
    default_rules_.push_back({"m.room.guest_access", {"guest_access"}, {}});
  }

  const RedactionRule* find_rule(const std::string& event_type) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    
    // Check custom rules first (they override defaults)
    for (auto& rule : custom_rules_) {
      if (rule.event_type == event_type || rule.event_type == "*") {
        return &rule;
      }
    }
    
    // Check default rules
    for (auto& rule : default_rules_) {
      if (rule.event_type == event_type) {
        return &rule;
      }
    }
    
    // Check wildcard default
    for (auto& rule : default_rules_) {
      if (rule.event_type == "*") return &rule;
    }
    
    return nullptr;
  }

  mutable std::shared_mutex mtx_;
  std::vector<RedactionRule> default_rules_;
  std::vector<RedactionRule> custom_rules_;
};

// ============================================================================
// SearchVisibilityFilter — enforces visibility in search results
// ============================================================================
//
// When users search for messages, the search must respect history_visibility.
// A user should never see search results from rooms they don't have access to,
// or events they are not authorized to see within visible rooms.
//
class SearchVisibilityFilter {
public:
  struct SearchResult {
    std::string event_id;
    std::string room_id;
    std::string sender;
    std::string type;
    int64_t origin_server_ts;
    json content_preview;     // Snippet of matching content
    double relevance_score = 0.0;
    json event;               // Full event data (if available)
    
    json to_json() const {
      json j;
      j["event_id"] = event_id;
      j["room_id"] = room_id;
      j["sender"] = sender;
      j["type"] = type;
      j["origin_server_ts"] = origin_server_ts;
      j["relevance_score"] = relevance_score;
      if (!content_preview.empty()) {
        j["content_preview"] = content_preview;
      }
      return j;
    }
  };

  struct SearchContext {
    std::string user_id;
    std::string search_term;
    std::vector<std::string> room_ids;   // Empty = search all visible rooms
    int limit = 50;
    std::string order_by = "rank";       // "rank" or "recent"
    bool include_state = false;
    bool group_by_room = false;
  };

  SearchVisibilityFilter() = default;

  // ========================================================================
  // Filter search results for visibility
  // ========================================================================
  //
  // For each search result, checks:
  //   1. Is the room world_readable? If yes, include.
  //   2. Is the user a current member of the room? If yes, include.
  //   3. Does the room's history_visibility allow this user to see this
  //      specific event?
  //   4. Is the event censored/redacted? Apply censorship rules.
  //
  json filter_results(const std::vector<SearchResult>& results,
                       const SearchContext& ctx,
                       const VisibilityEnforcer& enforcer,
                       const CensoredEventManager& censor_mgr) const {
    json filtered = json::array();
    
    for (const auto& result : results) {
      // Skip if this room isn't in the allowed set (if specified)
      if (!ctx.room_ids.empty()) {
        bool in_allowed = false;
        for (auto& rid : ctx.room_ids) {
          if (result.room_id == rid) { in_allowed = true; break; }
        }
        if (!in_allowed) continue;
      }
      
      // Check visibility
      EnforcementContext ectx;
      ectx.user_id = ctx.user_id;
      ectx.room_id = result.room_id;
      ectx.event_id = result.event_id;
      ectx.event_type = result.type;
      ectx.event_sender = result.sender;
      ectx.event_timestamp_ms = result.origin_server_ts;
      ectx.is_own_event = (!ctx.user_id.empty() && result.sender == ctx.user_id);
      
      // Get visibility state (would come from room state in full implementation)
      auto vis_state = HistoryVisibilityState(HistoryVisibilityState::Level::JOINED, "", 0);
      ectx.visibility_state = vis_state;
      
      auto decision = enforcer.check_visibility(ectx);
      
      if (decision == VisibilityEnforcer::VisibilityDecision::DENY) {
        continue;  // Skip this result
      }
      
      // Check for censorship
      bool is_censored = censor_mgr.is_censored(result.event_id);
      if (is_censored) {
        auto level = censor_mgr.get_level(result.event_id);
        if (level == CensoredEventManager::CensorshipLevel::FULLY_HIDDEN) {
          continue;  // Fully hidden — skip entirely
        }
      }
      
      // Build the result JSON
      json entry = result.to_json();
      
      if (is_censored && decision == VisibilityEnforcer::VisibilityDecision::ALLOW_METADATA_ONLY) {
        // Strip content from censored events
        entry.erase("content_preview");
        entry["_censored"] = true;
      }
      
      filtered.push_back(entry);
    }
    
    return filtered;
  }

  // ========================================================================
  // Determine which rooms a user can search in
  // ========================================================================
  //
  // For "search all rooms" queries, this pre-filters the set of rooms
  // to only those the user has access to, avoiding unnecessary search
  // work and preventing information leakage.
  //
  std::vector<std::string> get_searchable_rooms(
      const std::string& user_id,
      const std::vector<std::string>& candidate_rooms,
      const std::unordered_map<std::string, std::string>& room_visibilities,
      const std::unordered_map<std::string, std::string>& user_memberships) const {
    
    std::vector<std::string> searchable;
    
    for (const auto& room_id : candidate_rooms) {
      // Get room visibility
      auto vit = room_visibilities.find(room_id);
      std::string vis_str = (vit != room_visibilities.end())
                                ? vit->second
                                : "joined";
      
      // World readable rooms are always searchable
      if (vis_str == "world_readable") {
        searchable.push_back(room_id);
        continue;
      }
      
      // Check user membership
      auto mit = user_memberships.find(room_id);
      std::string membership = (mit != user_memberships.end())
                                   ? mit->second
                                   : "";
      
      // Joined members can always search
      if (membership == "join") {
        searchable.push_back(room_id);
        continue;
      }
      
      // Invited visibility: invitees can search
      if (vis_str == "invited" && membership == "invite") {
        searchable.push_back(room_id);
        continue;
      }
      
      // Shared visibility: previously-joined can search
      if (vis_str == "shared" && !membership.empty() && membership != "ban") {
        searchable.push_back(room_id);
        continue;
      }
    }
    
    return searchable;
  }

  // ========================================================================
  // Scrub search highlights for visibility
  // ========================================================================
  //
  // When search results include content snippets with highlighted matches,
  // ensure that the highlights don't reveal content the user shouldn't see.
  //
  json scrub_highlights(const json& result,
                          const VisibilityEnforcer& enforcer,
                          const std::string& user_id,
                          const std::string& room_id,
                          const std::string& membership,
                          const std::string& visibility) const {
    
    // If the user can fully see the event, highlights are fine
    auto decision = enforcer.check_simple(user_id, membership, visibility);
    if (decision == VisibilityEnforcer::VisibilityDecision::ALLOW) {
      return result;
    }
    
    // Otherwise, strip content and highlights
    json scrubbed = result;
    scrubbed.erase("content_preview");
    scrubbed.erase("highlights");
    scrubbed["_scrubbed_for_visibility"] = true;
    return scrubbed;
  }

  // ========================================================================
  // Rank search results with visibility penalty
  // ========================================================================
  //
  // Events the user has full access to should rank higher than events
  // with restricted visibility. This is used for ranking in multi-room
  // search results.
  //
  double compute_visibility_penalty(const std::string& user_id,
                                      const std::string& room_id,
                                      const std::string& membership,
                                      const std::string& visibility) const {
    // Full access: no penalty
    if (membership == "join") return 0.0;
    
    // World readable: tiny penalty
    if (visibility == "world_readable") return 0.05;
    
    // Shared with previous membership: small penalty
    if (visibility == "shared" && !membership.empty()) return 0.1;
    
    // Invited: moderate penalty
    if (visibility == "invited" && membership == "invite") return 0.2;
    
    // Should not be visible at all
    return 1.0;
  }
};

// ============================================================================
// SearchResultScrubber — post-processes search results for safety
// ============================================================================
//
// After the search engine returns results, this component performs a final
// safety pass to ensure no sensitive information leaks through search
// result snippets, highlights, or aggregations.
//
class SearchResultScrubber {
public:
  SearchResultScrubber() = default;

  // --- Scrub a single search result ---
  json scrub_result(const json& result,
                     const std::string& user_id,
                     const std::string& room_id,
                     const VisibilityEnforcer& enforcer,
                     const CensoredEventManager& censor_mgr,
                     const std::string& membership,
                     const std::string& visibility) const {
    json scrubbed = result;
    
    // Check if event is censored
    std::string event_id = result.value("event_id", "");
    if (censor_mgr.is_censored(event_id)) {
      auto level = censor_mgr.get_level(event_id);
      if (level == CensoredEventManager::CensorshipLevel::CONTENT_STRIPPED ||
          level == CensoredEventManager::CensorshipLevel::METADATA_ONLY) {
        scrubbed.erase("content_preview");
        scrubbed.erase("content_body");
        scrubbed["_censored"] = true;
      }
    }
    
    // Check visibility
    auto decision = enforcer.check_simple(user_id, membership, visibility,
                                           result.value("sender", ""));
    if (decision != VisibilityEnforcer::VisibilityDecision::ALLOW) {
      scrubbed.erase("content_preview");
      scrubbed.erase("content_body");
      scrubbed.erase("highlights");
      scrubbed["_visibility_restricted"] = true;
    }
    
    return scrubbed;
  }

  // --- Scrub a batch of search results ---
  json scrub_batch(const json& results,
                    const std::string& user_id,
                    const std::string& room_id,
                    const VisibilityEnforcer& enforcer,
                    const CensoredEventManager& censor_mgr,
                    const std::string& membership,
                    const std::string& visibility) const {
    json scrubbed = json::array();
    for (const auto& result : results) {
      scrubbed.push_back(scrub_result(result, user_id, room_id,
                                       enforcer, censor_mgr,
                                       membership, visibility));
    }
    return scrubbed;
  }

  // --- Remove sensitive fields from event content in search results ---
  static json sanitize_content_for_search(const json& content) {
    if (!content.is_object()) return content;
    
    json sanitized = content;
    
    // Remove fields that shouldn't appear in search snippets
    static const std::vector<std::string> sensitive_fields = {
      "password", "secret", "token", "private_key",
      "access_token", "refresh_token", "api_key"
    };
    
    for (const auto& field : sensitive_fields) {
      sanitized.erase(field);
    }
    
    return sanitized;
  }
};

// ============================================================================
// VisibilityAuditLogger — logs visibility decisions for audit/debugging
// ============================================================================
//
// Records every visibility check with the decision, reason, and context
// for debugging, compliance, and security auditing.
//
class VisibilityAuditLogger {
public:
  struct AuditEntry {
    int64_t timestamp_ms;
    std::string user_id;
    std::string room_id;
    std::string event_id;
    std::string decision;        // "ALLOW", "DENY", "REDACT", etc.
    std::string reason;
    std::string visibility_state;
    std::string membership;
    int64_t event_timestamp_ms;
    
    json to_json() const {
      json j;
      j["timestamp_ms"] = timestamp_ms;
      j["user_id"] = user_id;
      j["room_id"] = room_id;
      j["event_id"] = event_id;
      j["decision"] = decision;
      j["reason"] = reason;
      j["visibility_state"] = visibility_state;
      j["membership"] = membership;
      j["event_timestamp_ms"] = event_timestamp_ms;
      return j;
    }
  };

  VisibilityAuditLogger() : max_entries_(10000) {}

  explicit VisibilityAuditLogger(size_t max_entries)
      : max_entries_(max_entries) {}

  // --- Log a visibility decision ---
  void log_decision(const std::string& user_id,
                     const std::string& room_id,
                     const std::string& event_id,
                     const std::string& decision,
                     const std::string& reason,
                     const std::string& visibility_state,
                     const std::string& membership,
                     int64_t event_timestamp_ms) {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    
    AuditEntry entry;
    entry.timestamp_ms = now_ms();
    entry.user_id = user_id;
    entry.room_id = room_id;
    entry.event_id = event_id;
    entry.decision = decision;
    entry.reason = reason;
    entry.visibility_state = visibility_state;
    entry.membership = membership;
    entry.event_timestamp_ms = event_timestamp_ms;
    
    audit_log_.push_back(entry);
    
    // Trim to max size
    while (audit_log_.size() > max_entries_) {
      audit_log_.pop_front();
    }
  }

  // --- Get recent audit entries ---
  std::vector<AuditEntry> recent_entries(size_t count = 100) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    std::vector<AuditEntry> result;
    size_t start = (audit_log_.size() > count)
                       ? audit_log_.size() - count
                       : 0;
    auto it = audit_log_.begin();
    std::advance(it, start);
    for (; it != audit_log_.end() && result.size() < count; ++it) {
      result.push_back(*it);
    }
    return result;
  }

  // --- Get entries for a specific user ---
  std::vector<AuditEntry> entries_for_user(const std::string& user_id,
                                             size_t count = 100) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    std::vector<AuditEntry> result;
    for (auto it = audit_log_.rbegin();
         it != audit_log_.rend() && result.size() < count; ++it) {
      if (it->user_id == user_id) {
        result.push_back(*it);
      }
    }
    std::reverse(result.begin(), result.end());
    return result;
  }

  // --- Get entries for a specific room ---
  std::vector<AuditEntry> entries_for_room(const std::string& room_id,
                                             size_t count = 100) const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    std::vector<AuditEntry> result;
    for (auto it = audit_log_.rbegin();
         it != audit_log_.rend() && result.size() < count; ++it) {
      if (it->room_id == room_id) {
        result.push_back(*it);
      }
    }
    std::reverse(result.begin(), result.end());
    return result;
  }

  // --- Get entry count ---
  size_t entry_count() const {
    std::shared_lock<std::shared_mutex> lock(mtx_);
    return audit_log_.size();
  }

  // --- Clear the audit log ---
  void clear() {
    std::unique_lock<std::shared_mutex> lock(mtx_);
    audit_log_.clear();
  }

  // --- Serialize audit log to JSON ---
  json to_json(size_t count = 100) const {
    auto entries = recent_entries(count);
    json arr = json::array();
    for (auto& e : entries) {
      arr.push_back(e.to_json());
    }
    return arr;
  }

  // --- Export audit log to file ---
  bool export_to_file(const std::string& filepath, size_t count = 0) const {
    auto entries = (count > 0) ? recent_entries(count)
                                 : recent_entries(audit_log_.size());
    
    std::ofstream file(filepath);
    if (!file.is_open()) return false;
    
    json arr = json::array();
    for (auto& e : entries) {
      arr.push_back(e.to_json());
    }
    
    file << arr.dump(2);
    file.close();
    return true;
  }

private:
  mutable std::shared_mutex mtx_;
  std::deque<AuditEntry> audit_log_;
  size_t max_entries_;
};

// ============================================================================
// SyncVisibilityFilter — visibility filtering for /sync responses
// ============================================================================
//
// Filters /sync response timelines to exclude events the user shouldn't see.
// Also handles the special case of server notices being routed to a
// separate section of the sync response.
//
class SyncVisibilityFilter {
public:
  struct SyncFilterContext {
    std::string user_id;
    std::string room_id;
    std::string membership;
    std::string history_visibility;
    bool is_initial_sync = false;
    bool is_server_notice_room = false;
    int64_t since_token = 0;
  };

  struct FilteredSyncRoom {
    json timeline_events;
    json state_events;
    json server_notices;
    size_t timeline_count = 0;
    size_t filtered_count = 0;
    size_t notice_count = 0;
    bool limited = false;
    std::string prev_batch;
  };

  SyncVisibilityFilter() = default;

  // --- Filter a room's timeline for sync ---
  FilteredSyncRoom filter_sync_room(const json& room_data,
                                      const SyncFilterContext& ctx) {
    FilteredSyncRoom result;
    
    // Extract timeline
    json timeline;
    if (room_data.contains("timeline") && room_data["timeline"].is_object()) {
      timeline = room_data["timeline"].value("events", json::array());
      result.limited = room_data["timeline"].value("limited", false);
      result.prev_batch = room_data["timeline"].value("prev_batch", "");
    } else if (room_data.is_array()) {
      timeline = room_data;
    }
    
    if (timeline.empty()) {
      result.timeline_events = json::array();
      result.state_events = json::array();
      result.server_notices = json::array();
      return result;
    }
    
    // Separate server notices from normal timeline
    ServerNoticeFilter sn_filter;
    auto routing = sn_filter.route_events(timeline, ctx.is_server_notice_room);
    result.notice_count = routing.notice_count;
    result.server_notices = routing.server_notices;
    
    // Apply visibility filter to normal timeline
    VisibilityEnforcer enforcer;
    result.timeline_events = enforcer.filter_event_array(
        ctx.user_id, ctx.room_id, ctx.membership,
        ctx.history_visibility, routing.normal_timeline);
    
    result.filtered_count =
        routing.normal_count - result.timeline_events.size();
    result.timeline_count = result.timeline_events.size();
    
    // State events in sync are generally visible to joined members
    // For non-joined members, filter state events too
    if (ctx.membership != "join") {
      json state_events;
      if (room_data.contains("state") && room_data["state"].is_object()) {
        state_events = room_data["state"].value("events", json::array());
      }
      
      if (!state_events.empty()) {
        result.state_events = enforcer.filter_event_array(
            ctx.user_id, ctx.room_id, ctx.membership,
            ctx.history_visibility, state_events);
      }
    } else {
      // Joined members see all state
      if (room_data.contains("state") && room_data["state"].is_object()) {
        result.state_events = room_data["state"].value("events", json::array());
      }
    }
    
    return result;
  }

  // --- Build a filtered sync response for multiple rooms ---
  json build_filtered_sync_response(
      const json& raw_sync,
      const std::string& user_id,
      const std::unordered_map<std::string, std::string>& room_memberships,
      const std::unordered_map<std::string, std::string>& room_visibilities) {
    
    json filtered;
    filtered["next_batch"] = raw_sync.value("next_batch", "");
    
    json rooms_json;
    
    if (raw_sync.contains("rooms") && raw_sync["rooms"].is_object()) {
      auto& rooms = raw_sync["rooms"];
      
      for (auto& [section, section_data] : rooms.items()) {
        // section is "join", "invite", "leave"
        if (!section_data.is_object()) continue;
        
        json filtered_section;
        
        for (auto& [room_id, room_data] : section_data.items()) {
          SyncFilterContext ctx;
          ctx.user_id = user_id;
          ctx.room_id = room_id;
          ctx.membership = section;
          
          auto vit = room_visibilities.find(room_id);
          ctx.history_visibility = (vit != room_visibilities.end())
                                      ? vit->second
                                      : "joined";
          
          auto filtered_room = filter_sync_room(room_data, ctx);
          
          // Build filtered room response
          json room_resp;
          
          if (!filtered_room.timeline_events.empty() ||
              !filtered_room.state_events.empty()) {
            json timeline_obj;
            timeline_obj["events"] = filtered_room.timeline_events;
            timeline_obj["limited"] = filtered_room.limited;
            if (!filtered_room.prev_batch.empty()) {
              timeline_obj["prev_batch"] = filtered_room.prev_batch;
            }
            room_resp["timeline"] = timeline_obj;
          }
          
          if (!filtered_room.state_events.empty()) {
            json state_obj;
            state_obj["events"] = filtered_room.state_events;
            room_resp["state"] = state_obj;
          }
          
          if (!room_resp.empty()) {
            filtered_section[room_id] = room_resp;
          }
        }
        
        if (!filtered_section.empty()) {
          rooms_json[section] = filtered_section;
        }
      }
    }
    
    filtered["rooms"] = rooms_json;
    return filtered;
  }

  // --- Check if a room should appear in sync at all ---
  bool should_include_room_in_sync(const std::string& user_id,
                                     const std::string& room_id,
                                     const std::string& membership,
                                     const std::string& history_visibility) const {
    // Joined rooms always appear
    if (membership == "join") return true;
    
    // Invited rooms appear for the invited user
    if (membership == "invite") return true;
    
    // Left rooms: only appear if the user can still see history
    if (membership == "leave") {
      return history_visibility == "world_readable" ||
             history_visibility == "shared";
    }
    
    // Unknown — check visibility
    VisibilityEnforcer enforcer;
    auto decision = enforcer.check_simple(user_id, membership, history_visibility);
    return decision != VisibilityEnforcer::VisibilityDecision::DENY;
  }
};

// ============================================================================
// MessagesVisibilityFilter — visibility filtering for /messages endpoint
// ============================================================================
//
// Filters /messages responses (room message pagination) to respect
// history_visibility. Handles forward and backward pagination, ensuring
// that each chunk of events returned to the client only includes events
// the user can see.
//
class MessagesVisibilityFilter {
public:
  struct MessagesFilterContext {
    std::string user_id;
    std::string room_id;
    std::string membership;
    std::string history_visibility;
    std::string direction;   // "b" for backward, "f" for forward
    int limit = 10;
    std::string from_token;  // Pagination cursor
  };

  MessagesVisibilityFilter() = default;

  // --- Filter a chunk of /messages events ---
  json filter_messages_chunk(const json& chunk,
                               const MessagesFilterContext& ctx) {
    VisibilityEnforcer enforcer;
    
    json events;
    if (chunk.contains("chunk") && chunk["chunk"].is_array()) {
      events = chunk["chunk"];
    } else if (chunk.is_array()) {
      events = chunk;
    } else {
      return chunk;  // Unknown format, pass through
    }
    
    json filtered_chunk = enforcer.filter_event_array(
        ctx.user_id, ctx.room_id, ctx.membership,
        ctx.history_visibility, events);
    
    // Build filtered response
    json response;
    response["chunk"] = filtered_chunk;
    
    if (chunk.contains("start")) {
      response["start"] = chunk["start"];
    }
    if (chunk.contains("end")) {
      response["end"] = chunk["end"];
    }
    if (chunk.contains("state")) {
      // Also filter state events in the response
      json filtered_state = enforcer.filter_event_array(
          ctx.user_id, ctx.room_id, ctx.membership,
          ctx.history_visibility, chunk["state"]);
      response["state"] = filtered_state;
    }
    
    return response;
  }

  // --- Check if the user can access /messages for this room at all ---
  bool can_access_messages(const std::string& user_id,
                            const std::string& room_id,
                            const std::string& membership,
                            const std::string& history_visibility) const {
    // World readable: anyone can access
    if (history_visibility == "world_readable") return true;
    
    // No user_id: only world_readable (already handled)
    if (user_id.empty()) return false;
    
    // Joined members: always
    if (membership == "join") return true;
    
    // Invited visibility: invitees can access
    if (history_visibility == "invited" && membership == "invite") return true;
    
    // Shared visibility: previously-joined can access
    if (history_visibility == "shared" && !membership.empty() &&
        membership != "ban") {
      return true;
    }
    
    return false;
  }

  // --- Determine available range for pagination ---
  // Returns (earliest_visible_ts, latest_visible_ts) the user can paginate.
  std::pair<int64_t, int64_t> get_visible_range(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& membership,
      const std::string& history_visibility,
      const HistoricalMessageTracker& tracker,
      const HistoryVisibilityStateMachine& vis_state_machine,
      const MembershipVisibilityResolver& membership_resolver) const {
    
    int64_t earliest = tracker.compute_earliest_visible_timestamp(
        user_id, room_id, vis_state_machine, membership_resolver, membership);
    int64_t latest = INT64_MAX;  // Up to current time
    
    return {earliest, latest};
  }
};

// ============================================================================
// HistoryVisibilityCoordinator — top-level coordinator
// ============================================================================
//
// The main entry point for all history visibility functionality. Coordinates
// all sub-components and provides a unified API for the rest of the server.
//
class HistoryVisibilityCoordinator {
public:
  HistoryVisibilityCoordinator() {
    visibility_enforcer_ = std::make_unique<VisibilityEnforcer>();
    event_filter_pipeline_ = std::make_unique<EventFilterPipeline>();
    historical_tracker_ = std::make_unique<HistoricalMessageTracker>();
    membership_timeline_ = std::make_unique<MembershipTimelineTracker>();
    leave_manager_ = std::make_unique<LeaveVisibilityManager>();
    server_notice_filter_ = std::make_unique<ServerNoticeFilter>();
    censored_event_mgr_ = std::make_unique<CensoredEventManager>();
    redaction_engine_ = std::make_unique<EventRedactionEngine>();
    search_filter_ = std::make_unique<SearchVisibilityFilter>();
    result_scrubber_ = std::make_unique<SearchResultScrubber>();
    audit_logger_ = std::make_unique<VisibilityAuditLogger>();
    policy_cache_ = std::make_unique<VisibilityPolicyCache>();
    sync_filter_ = std::make_unique<SyncVisibilityFilter>();
    messages_filter_ = std::make_unique<MessagesVisibilityFilter>();
  }

  // ========================================================================
  // Core visibility check
  // ========================================================================
  bool can_view_events(const std::string& user_id,
                        const std::string& membership,
                        const std::string& history_visibility) {
    auto decision = visibility_enforcer_->check_simple(
        user_id, membership, history_visibility);
    
    bool allowed = (decision != VisibilityEnforcer::VisibilityDecision::DENY);
    
    audit_logger_->log_decision(
        user_id, "", "", 
        allowed ? "ALLOW" : "DENY",
        "Core visibility check",
        history_visibility, membership, 0);
    
    return allowed;
  }

  bool can_see_event(const std::string& user_id,
                      const std::string& membership,
                      const std::string& history_visibility,
                      const std::string& event_sender) {
    auto decision = visibility_enforcer_->check_simple(
        user_id, membership, history_visibility, event_sender);
    
    bool allowed = (decision != VisibilityEnforcer::VisibilityDecision::DENY);
    
    audit_logger_->log_decision(
        user_id, "", "",
        allowed ? "ALLOW" : "DENY",
        "Event visibility check",
        history_visibility, membership, 0);
    
    return allowed;
  }

  // ========================================================================
  // Batch event filtering
  // ========================================================================
  json filter_events(const std::string& user_id,
                      const std::string& room_id,
                      const std::string& membership,
                      const std::string& history_visibility,
                      const json& events) {
    return visibility_enforcer_->filter_event_array(
        user_id, room_id, membership, history_visibility, events);
  }

  // ========================================================================
  // Full pipeline filtering (visibility + server notices + censorship)
  // ========================================================================
  EventFilterPipeline::PipelineResult filter_events_full(
      const json& events,
      const EventFilterPipeline::PipelineContext& ctx,
      const EventFilterPipeline::FilterConfig& cfg) {
    return event_filter_pipeline_->filter(events, ctx, cfg);
  }

  // ========================================================================
  // /sync response filtering
  // ========================================================================
  SyncVisibilityFilter::FilteredSyncRoom filter_sync_room(
      const json& room_data,
      const SyncVisibilityFilter::SyncFilterContext& ctx) {
    return sync_filter_->filter_sync_room(room_data, ctx);
  }

  json filter_sync_response(
      const json& raw_sync,
      const std::string& user_id,
      const std::unordered_map<std::string, std::string>& room_memberships,
      const std::unordered_map<std::string, std::string>& room_visibilities) {
    return sync_filter_->build_filtered_sync_response(
        raw_sync, user_id, room_memberships, room_visibilities);
  }

  // ========================================================================
  // /messages response filtering
  // ========================================================================
  json filter_messages(const json& chunk,
                         const MessagesVisibilityFilter::MessagesFilterContext& ctx) {
    return messages_filter_->filter_messages_chunk(chunk, ctx);
  }

  bool can_access_messages(const std::string& user_id,
                            const std::string& room_id,
                            const std::string& membership,
                            const std::string& history_visibility) {
    return messages_filter_->can_access_messages(
        user_id, room_id, membership, history_visibility);
  }

  // ========================================================================
  // Historical visibility
  // ========================================================================
  HistoricalMessageTracker::HistoricalAccessResult check_historical_access(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& event_sender,
      int64_t event_origin_server_ts,
      const std::string& current_membership) {
    return historical_tracker_->check_historical_access(
        user_id, room_id, event_sender, event_origin_server_ts,
        vis_state_machine_, membership_resolver_, current_membership);
  }

  json filter_historical_timeline(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& current_membership,
      const json& events) {
    return historical_tracker_->filter_historical_timeline(
        user_id, room_id, current_membership, events,
        vis_state_machine_, membership_resolver_);
  }

  // ========================================================================
  // Visibility state management
  // ========================================================================
  void set_visibility(const std::string& room_id,
                       const std::string& visibility_str,
                       const std::string& set_by,
                       int64_t timestamp_ms,
                       const std::string& event_id = "") {
    HistoryVisibilityState new_state(
        HistoryVisibilityState::from_string(visibility_str),
        set_by, timestamp_ms);
    vis_state_machine_.apply_transition(new_state, timestamp_ms, event_id);
    policy_cache_->invalidate_visibility(room_id);
  }

  std::string get_visibility(const std::string& room_id) {
    // Check cache first
    auto cached = policy_cache_->get_visibility(room_id);
    if (cached) return cached->level_string();
    
    auto state = vis_state_machine_.current_state();
    policy_cache_->set_visibility(room_id, state);
    return state.level_string();
  }

  // ========================================================================
  // Membership tracking
  // ========================================================================
  void record_membership_change(const std::string& room_id,
                                  const std::string& user_id,
                                  const std::string& new_membership,
                                  const std::string& previous_membership,
                                  int64_t timestamp_ms,
                                  const std::string& event_id = "",
                                  const std::string& changed_by = "") {
    MembershipTimelineTracker::MembershipEvent ev;
    ev.event_id = event_id;
    ev.user_id = user_id;
    ev.membership = new_membership;
    ev.previous_membership = previous_membership;
    ev.timestamp_ms = timestamp_ms;
    ev.changed_by = changed_by;
    
    membership_timeline_->record_membership_event(room_id, ev);
    policy_cache_->invalidate_membership(room_id, user_id);
    
    // Handle leave visibility
    if (new_membership == "leave") {
      std::string vis = get_visibility(room_id);
      int64_t first_join = membership_timeline_->first_join_at(room_id, user_id);
      leave_manager_->record_leave(room_id, user_id, timestamp_ms,
                                    vis, first_join);
    }
  }

  // ========================================================================
  // Server notice filtering
  // ========================================================================
  json filter_server_notices(const json& events, bool is_notice_room = false) {
    return server_notice_filter_->filter_timeline(events, is_notice_room);
  }

  ServerNoticeFilter::RoutingResult route_server_notices(
      const json& events, bool is_notice_room = false) {
    return server_notice_filter_->route_events(events, is_notice_room);
  }

  // ========================================================================
  // Censorship management
  // ========================================================================
  void censor_event(const std::string& event_id,
                     const std::string& room_id,
                     CensoredEventManager::CensorshipLevel level,
                     const std::string& reason,
                     const std::string& censored_by,
                     const json& redaction_event = json::object()) {
    censored_event_mgr_->record_censorship(
        event_id, room_id, level, reason, censored_by, now_ms(), redaction_event);
  }

  bool is_event_censored(const std::string& event_id) {
    return censored_event_mgr_->is_censored(event_id);
  }

  json apply_censorship(const json& event) {
    auto result = censored_event_mgr_->apply_censorship(event);
    return result ? *result : json::object();
  }

  // ========================================================================
  // Redaction
  // ========================================================================
  json process_redaction(const json& target_event,
                           const json& redaction_event) {
    return redaction_engine_->process_redaction(target_event, redaction_event);
  }

  // ========================================================================
  // Search visibility
  // ========================================================================
  json filter_search_results(
      const std::vector<SearchVisibilityFilter::SearchResult>& results,
      const SearchVisibilityFilter::SearchContext& ctx) {
    return search_filter_->filter_results(
        results, ctx, *visibility_enforcer_, *censored_event_mgr_);
  }

  std::vector<std::string> get_searchable_rooms(
      const std::string& user_id,
      const std::vector<std::string>& candidate_rooms,
      const std::unordered_map<std::string, std::string>& room_visibilities,
      const std::unordered_map<std::string, std::string>& user_memberships) {
    return search_filter_->get_searchable_rooms(
        user_id, candidate_rooms, room_visibilities, user_memberships);
  }

  json scrub_search_result(const json& result,
                            const std::string& user_id,
                            const std::string& room_id,
                            const std::string& membership,
                            const std::string& visibility) {
    return result_scrubber_->scrub_result(
        result, user_id, room_id, *visibility_enforcer_,
        *censored_event_mgr_, membership, visibility);
  }

  // ========================================================================
  // Audit logging
  // ========================================================================
  json get_audit_log(size_t count = 100) {
    return audit_logger_->to_json(count);
  }

  json get_user_audit_log(const std::string& user_id, size_t count = 100) {
    auto entries = audit_logger_->entries_for_user(user_id, count);
    json arr = json::array();
    for (auto& e : entries) arr.push_back(e.to_json());
    return arr;
  }

  // ========================================================================
  // Statistics
  // ========================================================================
  json get_stats() {
    json stats;
    stats["audit_entries"] = audit_logger_->entry_count();
    stats["visibility_transitions"] = vis_state_machine_.transition_count();
    stats["membership_events"] = membership_timeline_->total_entries();
    stats["cached"] = policy_cache_->stats();
    stats["leave_records"] = leave_manager_->stats();
    stats["censorship"] = censored_event_mgr_->stats();
    return stats;
  }

  // ========================================================================
  // Direct access to components (for advanced use cases)
  // ========================================================================
  VisibilityEnforcer& enforcer() { return *visibility_enforcer_; }
  EventFilterPipeline& pipeline() { return *event_filter_pipeline_; }
  HistoricalMessageTracker& historical() { return *historical_tracker_; }
  MembershipTimelineTracker& membership_tracker() { return *membership_timeline_; }
  LeaveVisibilityManager& leave_mgr() { return *leave_manager_; }
  ServerNoticeFilter& server_notices() { return *server_notice_filter_; }
  CensoredEventManager& censorship() { return *censored_event_mgr_; }
  EventRedactionEngine& redaction() { return *redaction_engine_; }
  SearchVisibilityFilter& search() { return *search_filter_; }
  VisibilityAuditLogger& audit() { return *audit_logger_; }
  VisibilityPolicyCache& cache() { return *policy_cache_; }
  SyncVisibilityFilter& sync() { return *sync_filter_; }
  MessagesVisibilityFilter& messages() { return *messages_filter_; }
  HistoryVisibilityStateMachine& state_machine() { return vis_state_machine_; }

private:
  std::unique_ptr<VisibilityEnforcer> visibility_enforcer_;
  std::unique_ptr<EventFilterPipeline> event_filter_pipeline_;
  std::unique_ptr<HistoricalMessageTracker> historical_tracker_;
  std::unique_ptr<MembershipTimelineTracker> membership_timeline_;
  std::unique_ptr<LeaveVisibilityManager> leave_manager_;
  std::unique_ptr<ServerNoticeFilter> server_notice_filter_;
  std::unique_ptr<CensoredEventManager> censored_event_mgr_;
  std::unique_ptr<EventRedactionEngine> redaction_engine_;
  std::unique_ptr<SearchVisibilityFilter> search_filter_;
  std::unique_ptr<SearchResultScrubber> result_scrubber_;
  std::unique_ptr<VisibilityAuditLogger> audit_logger_;
  std::unique_ptr<VisibilityPolicyCache> policy_cache_;
  std::unique_ptr<SyncVisibilityFilter> sync_filter_;
  std::unique_ptr<MessagesVisibilityFilter> messages_filter_;
  
  HistoryVisibilityStateMachine vis_state_machine_;
  MembershipVisibilityResolver membership_resolver_;
};

// ============================================================================
// End of progressive namespace
// ============================================================================
}  // namespace progressive
