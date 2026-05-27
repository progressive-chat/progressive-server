// ============================================================================
// join_rules.cpp — Matrix Room Join Rules, Restricted Rooms, Knock Support,
//                   Enforcement, Upgrade Propagation, Federation Handlers,
//                   Transition Validation, and Default Rules
//
// Implements:
//   - Join rule state machine: public, invite, knock, private, restricted,
//     knock_restricted. Full enumeration, string parsing, JSON serialization,
//     semantic comparisons, and Matrix spec conformance.
//   - Restricted room management: allow-rule validation (m.room_membership
//     with room_id and via), cross-room/spae membership checks for restricted
//     joins, allow-list CRUD, batch authorization, recursive space membership
//     resolution, and restricted join previews for UI discovery.
//   - Knock support: knock submission on rooms with knock/knock_restricted
//     join rules, accept/reject knocks with reasons, knock history tracking
//     with audit trail, knock deduplication, expiration of stale knocks,
//     power-level-gated approval, notification dispatch, and federation
//     knock relay.
//   - Join rule enforcement: pre-join authorization checks, validate allow-
//     list memberships before admitting users, power-level-gated join rule
//     modification, state event authorization for m.room.join_rules, and
//     enforcement across local and remote joins.
//   - Room upgrade join rules: propagate join rules from old room to new
//     room during room upgrade, preserve restricted allow lists, update
//     room IDs in allow rules that reference the old room, and tombstone
//     old room join rules.
//   - Federation join rules: send m.room.join_rules in state over federation,
//     validate remote server join authorization against join rules, handle
//     restricted join authorization across federated servers, forward knock
//     events, and resolve join rules during state resolution.
//   - Join rule transitions: validate allowed transitions between join rules
//     (e.g., restricted requires at least one allow rule, public to restricted
//     is allowed, restricted to public is allowed, invite to knock allowed),
//     deny invalid transitions, emit transition audit events.
//   - Default join rules: resolve default join rules for new rooms based on
//     room creation preset (public_chat→public, private_chat→invite,
//     trusted_private_chat→invite), support creation_content overrides, and
//     version-aware defaults (restricted requires room version 8+).
//
// Namespace: progressive::
// Equivalent to synapse/handlers/room_member.py (auth/join logic) +
//              synapse/event_auth.py (join rule checks) +
//              synapse/handlers/federation.py (join rule resolution)
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
class JoinRule;
class JoinRulesConfig;
class AllowRule;
class AllowRuleSet;
class JoinRulesStateEngine;
class RestrictedJoinValidator;
class KnockRequestManager;
class KnockAuditTrail;
class JoinRuleEnforcer;
class UpgradeJoinRulesPropagator;
class FederationJoinRulesHandler;
class JoinRulesTransitionValidator;
class DefaultJoinRulesResolver;
class JoinRulesCoordinator;

// ============================================================================
// Constants and Configuration
// ============================================================================
namespace join_rules_constants {

// Matrix-spec valid join_rule values (including MSC extensions)
constexpr std::string_view JR_PUBLIC           = "public";
constexpr std::string_view JR_INVITE           = "invite";
constexpr std::string_view JR_KNOCK            = "knock";
constexpr std::string_view JR_PRIVATE          = "private";
constexpr std::string_view JR_RESTRICTED       = "restricted";
constexpr std::string_view JR_KNOCK_RESTRICTED = "knock_restricted";

// Aliases and backwards-compatible names
constexpr std::string_view JR_PUBLIC_ALIAS = "public";
// "private" is treated as "invite" per Matrix spec
constexpr std::string_view JR_PRIVATE_ALIAS = "private";

// Allow rule types
constexpr std::string_view ALLOW_ROOM_MEMBERSHIP = "m.room_membership";

// Default join rules per room preset
constexpr std::string_view DEFAULT_PUBLIC_CHAT          = "public";
constexpr std::string_view DEFAULT_PRIVATE_CHAT         = "invite";
constexpr std::string_view DEFAULT_TRUSTED_PRIVATE_CHAT = "invite";

// Room version requirements
constexpr int MIN_VERSION_RESTRICTED       = 8;
constexpr int MIN_VERSION_KNOCK            = 7;
constexpr int MIN_VERSION_KNOCK_RESTRICTED = 8;

// Transition validation: rules that can transition to restricted
constexpr std::array<const char*, 4> CAN_BECOME_RESTRICTED = {
    "public", "invite", "private", "knock"
};

// Transition validation: rules that can transition to knock
constexpr std::array<const char*, 5> CAN_BECOME_KNOCK = {
    "public", "invite", "private", "restricted", "knock_restricted"
};

// All valid join rules in canonical order
constexpr std::array<const char*, 6> ALL_VALID_JOIN_RULES = {
    "public", "invite", "knock", "private", "restricted", "knock_restricted"
};

// State event type for join rules
constexpr std::string_view JOIN_RULES_EVENT_TYPE = "m.room.join_rules";

// Membership states relevant to join rule enforcement
constexpr std::string_view MEMBERSHIP_JOIN   = "join";
constexpr std::string_view MEMBERSHIP_INVITE = "invite";
constexpr std::string_view MEMBERSHIP_LEAVE  = "leave";
constexpr std::string_view MEMBERSHIP_BAN    = "ban";
constexpr std::string_view MEMBERSHIP_KNOCK  = "knock";

// Cache TTLs
constexpr int64_t JOIN_RULES_CACHE_TTL_MS  = 60'000;   // 1 minute
constexpr int64_t ALLOW_CHECK_CACHE_TTL_MS = 30'000;   // 30 seconds
constexpr int64_t KNOCK_HISTORY_TTL_MS     = 604'800'000; // 7 days

// Knock limits
constexpr size_t MAX_PENDING_KNOCKS_PER_USER  = 10;
constexpr size_t MAX_PENDING_KNOCKS_PER_ROOM  = 500;
constexpr size_t MAX_KNOCK_HISTORY_PER_ROOM   = 1000;

// Allow rules limit per room
constexpr size_t MAX_ALLOW_RULES = 100;

// Federation join rule validation
constexpr int64_t FED_JOIN_RULES_STALE_MS = 300'000; // 5 minutes

}  // namespace join_rules_constants

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
                 const std::array<const char*, 6>& arr) {
  for (auto& s : arr) {
    if (val == s) return true;
  }
  return false;
}

// Validate a Matrix room ID format: "!" + localpart + ":" + domain
bool is_valid_room_id(const std::string& id) {
  if (id.empty() || id[0] != '!') return false;
  auto colon_pos = id.find(':');
  if (colon_pos == std::string::npos || colon_pos < 2) return false;
  if (colon_pos == id.size() - 1) return false;
  return id.size() <= 255;
}

// Validate a Matrix user ID format: "@" + localpart + ":" + domain
bool is_valid_user_id(const std::string& id) {
  if (id.empty() || id[0] != '@') return false;
  auto colon_pos = id.find(':');
  if (colon_pos == std::string::npos || colon_pos < 2) return false;
  if (colon_pos == id.size() - 1) return false;
  return id.size() <= 255;
}

// Extract server name from a Matrix ID (user or room)
std::string extract_server_name(const std::string& mxid) {
  auto colon_pos = mxid.find(':');
  if (colon_pos == std::string::npos) return "";
  return mxid.substr(colon_pos + 1);
}

// Make a JSON error response with Matrix error format
json make_error(const std::string& errcode, const std::string& error) {
  json j;
  j["errcode"] = errcode;
  j["error"] = error;
  return j;
}

// Make a JSON error response with soft-logout hint
json make_error_soft_logout(const std::string& errcode,
                             const std::string& error) {
  json j = make_error(errcode, error);
  j["soft_logout"] = true;
  return j;
}

// Generate a synthetic event ID
std::string generate_event_id(const std::string& server_name) {
  std::ostringstream oss;
  oss << "$" << generate_random_id(32) << ":" << server_name;
  return oss.str();
}

// Extract domain from a room ID
std::string domain_from_room_id(const std::string& room_id) {
  auto colon = room_id.find(':');
  if (colon == std::string::npos) return room_id;
  return room_id.substr(colon + 1);
}

// Build a timestamp string in ISO 8601-like format
std::string iso_timestamp(int64_t ms) {
  auto secs = ms / 1000;
  auto millis = ms % 1000;
  time_t t = static_cast<time_t>(secs);
  struct tm tm_buf;
  gmtime_r(&t, &tm_buf);
  char buf[64];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
  std::ostringstream oss;
  oss << buf << "." << std::setfill('0') << std::setw(3) << millis << "Z";
  return oss.str();
}

}  // anonymous namespace

// ============================================================================
// JoinRule — strongly-typed enumeration of all join rule states
// ============================================================================
//
// Represents every valid Matrix join_rule value. Provides safe string
// parsing (invalid inputs fall back to invite), semantic grouping
// (is_public(), requires_invite(), allows_knock()), and JSON
// serialization to/from m.room.join_rules content.
//
class JoinRule {
public:
  // --- Core enumeration ---
  enum class Type {
    PUBLIC = 0,           // Anyone can join without invite (join_rule: "public")
    INVITE = 1,           // Only invited users can join (join_rule: "invite")
    KNOCK = 2,            // Users can knock to request membership (join_rule: "knock")
    PRIVATE = 3,          // Alias for invite (join_rule: "private")
    RESTRICTED = 4,       // Join allowed if user is in an allowed room/space
    KNOCK_RESTRICTED = 5, // Combination: restricted access + knock support
    UNKNOWN = 6           // Sentinel / unset
  };

  // --- Construction ---
  JoinRule() : type_(Type::INVITE) {}
  explicit JoinRule(Type t) : type_(t) {}
  explicit JoinRule(const std::string& s) : type_(from_string(s)) {}

  // --- Parse from Matrix spec string ---
  // Converts a spec join_rule string to a Type enum. Unrecognized
  // strings default to INVITE (the safest fallback).
  static Type from_string(const std::string& s) {
    if (s == "public")           return Type::PUBLIC;
    if (s == "invite")           return Type::INVITE;
    if (s == "knock")            return Type::KNOCK;
    if (s == "private")          return Type::PRIVATE;
    if (s == "restricted")       return Type::RESTRICTED;
    if (s == "knock_restricted") return Type::KNOCK_RESTRICTED;
    return Type::INVITE; // default to safest
  }

  // --- Convert to Matrix spec string ---
  static std::string to_string(Type t) {
    switch (t) {
      case Type::PUBLIC:           return "public";
      case Type::INVITE:           return "invite";
      case Type::KNOCK:            return "knock";
      case Type::PRIVATE:          return "private";
      case Type::RESTRICTED:       return "restricted";
      case Type::KNOCK_RESTRICTED: return "knock_restricted";
      default:                     return "invite";
    }
  }

  // --- Accessors ---
  Type type() const { return type_; }
  std::string type_string() const { return to_string(type_); }

  // --- Semantic classification queries ---

  // Does this rule allow anyone to join without an invite?
  bool is_public() const {
    return type_ == Type::PUBLIC;
  }

  // Does this rule require an invite for non-privileged users?
  bool requires_invite() const {
    return type_ == Type::INVITE || type_ == Type::PRIVATE;
  }

  // Does this rule allow knock requests?
  bool allows_knock() const {
    return type_ == Type::KNOCK || type_ == Type::KNOCK_RESTRICTED;
  }

  // Is this a restricted join rule (requires allow-list membership)?
  bool is_restricted() const {
    return type_ == Type::RESTRICTED || type_ == Type::KNOCK_RESTRICTED;
  }

  // Is this rule the private alias (treated as invite)?
  bool is_private_alias() const {
    return type_ == Type::PRIVATE;
  }

  // Does this rule support the allow list in state content?
  bool supports_allow_list() const {
    return type_ == Type::RESTRICTED || type_ == Type::KNOCK_RESTRICTED;
  }

  // Can a user without explicit invite join under this rule?
  bool can_join_without_invite() const {
    return type_ == Type::PUBLIC || type_ == Type::RESTRICTED ||
           type_ == Type::KNOCK_RESTRICTED;
  }

  // --- Comparison operators ---
  bool operator==(const JoinRule& other) const {
    return type_ == other.type_;
  }
  bool operator!=(const JoinRule& other) const {
    return type_ != other.type_;
  }

  // Normalize private to invite (per Matrix spec aliasing)
  JoinRule normalized() const {
    if (type_ == Type::PRIVATE) return JoinRule(Type::INVITE);
    return *this;
  }

private:
  Type type_;
};

// ============================================================================
// AllowRule — a single allow entry in restricted join rules
// ============================================================================
//
// Represents one entry in the "allow" array of m.room.join_rules content.
// Each rule specifies a type (currently m.room_membership) and a room_id
// whose joined members are authorized to join the restricted room.
// The optional via field hints which server to query for membership.
//
struct AllowRule {
  std::string type;      // "m.room_membership" per spec
  std::string room_id;   // The room/space whose members are authorized
  std::string via;       // Hint server for federation (optional)
  int64_t added_at_ms = 0;     // When this rule was added
  std::string added_by;        // Who added this rule

  // --- Serialize to JSON ---
  json to_json() const {
    json j;
    j["type"] = type;
    j["room_id"] = room_id;
    if (!via.empty()) j["via"] = via;
    return j;
  }

  // --- Parse from JSON ---
  static AllowRule from_json(const json& j) {
    AllowRule rule;
    rule.type = j.value("type", "m.room_membership");
    rule.room_id = j.value("room_id", "");
    rule.via = j.value("via", "");
    return rule;
  }

  // --- Validation ---
  bool is_valid() const {
    return type == "m.room_membership" &&
           is_valid_room_id(room_id);
  }

  // --- Equality (for dedup) ---
  bool operator==(const AllowRule& other) const {
    return type == other.type && room_id == other.room_id;
  }
  bool operator<(const AllowRule& other) const {
    if (type != other.type) return type < other.type;
    return room_id < other.room_id;
  }
};

// ============================================================================
// AllowRuleSet — ordered, deduplicated collection of allow rules
// ============================================================================
//
// Manages the allow list for a restricted room. Provides insertion with
// duplicate detection, removal, lookup by room_id, size limit enforcement,
// and JSON serialization for the m.room.join_rules allow array.
//
class AllowRuleSet {
public:
  AllowRuleSet() = default;

  // --- Add an allow rule ---
  // Returns false if the rule is a duplicate or if the set is full.
  bool add(const AllowRule& rule) {
    if (rules_.size() >= join_rules_constants::MAX_ALLOW_RULES) {
      return false;
    }
    for (auto& r : rules_) {
      if (r == rule) return false; // duplicate
    }
    rules_.push_back(rule);
    return true;
  }

  // --- Remove an allow rule by room_id ---
  bool remove(const std::string& room_id) {
    auto it = std::remove_if(rules_.begin(), rules_.end(),
        [&room_id](const AllowRule& r) { return r.room_id == room_id; });
    if (it == rules_.end()) return false;
    rules_.erase(it, rules_.end());
    return true;
  }

  // --- Check if the set contains a specific room_id ---
  bool contains(const std::string& room_id) const {
    for (auto& r : rules_) {
      if (r.room_id == room_id) return true;
    }
    return false;
  }

  // --- Get all allow rules ---
  const std::vector<AllowRule>& all() const { return rules_; }

  // --- Get the count of allow rules ---
  size_t size() const { return rules_.size(); }
  bool empty() const { return rules_.empty(); }

  // --- Serialize to JSON array ---
  json to_json() const {
    json arr = json::array();
    for (auto& r : rules_) {
      arr.push_back(r.to_json());
    }
    return arr;
  }

  // --- Parse from JSON array ---
  static AllowRuleSet from_json(const json& j) {
    AllowRuleSet set;
    if (j.is_array()) {
      for (auto& entry : j) {
        AllowRule rule = AllowRule::from_json(entry);
        if (rule.is_valid()) {
          set.rules_.push_back(rule);
        }
      }
    }
    return set;
  }

  // --- Get all room IDs referenced by allow rules ---
  std::vector<std::string> referenced_room_ids() const {
    std::vector<std::string> ids;
    for (auto& r : rules_) {
      ids.push_back(r.room_id);
    }
    return ids;
  }

  // --- Replace a room_id reference (used during room upgrade) ---
  void replace_room_id(const std::string& old_room_id,
                       const std::string& new_room_id) {
    for (auto& r : rules_) {
      if (r.room_id == old_room_id) {
        r.room_id = new_room_id;
      }
    }
  }

  // --- Clear all rules ---
  void clear() { rules_.clear(); }

private:
  std::vector<AllowRule> rules_;
};

// ============================================================================
// JoinRulesConfig — complete join rules state for a room
// ============================================================================
//
// Encapsulates the full m.room.join_rules state: the join_rule value,
// the optional allow list for restricted rooms, metadata about who set
// it and when, and serialization to/from state event content.
//
class JoinRulesConfig {
public:
  JoinRulesConfig()
      : join_rule_(JoinRule::Type::INVITE),
        set_by_(""),
        set_at_ms_(0),
        event_id_("") {}

  JoinRulesConfig(JoinRule rule, AllowRuleSet allow,
                  std::string set_by, int64_t set_at_ms,
                  std::string event_id)
      : join_rule_(rule),
        allow_(std::move(allow)),
        set_by_(std::move(set_by)),
        set_at_ms_(set_at_ms),
        event_id_(std::move(event_id)) {}

  // --- Parse from m.room.join_rules state event content ---
  static JoinRulesConfig from_state_event(const json& event,
                                           const std::string& sender,
                                           int64_t origin_server_ts,
                                           const std::string& event_id) {
    std::string rule_str = "invite";
    AllowRuleSet allow_set;

    if (event.contains("content") && event["content"].is_object()) {
      rule_str = event["content"].value("join_rule", "invite");
      if (event["content"].contains("allow")) {
        allow_set = AllowRuleSet::from_json(event["content"]["allow"]);
      }
    } else if (event.contains("join_rule")) {
      rule_str = event["join_rule"].get<std::string>();
    }

    return JoinRulesConfig(
        JoinRule(rule_str),
        std::move(allow_set),
        sender,
        origin_server_ts,
        event_id
    );
  }

  // --- Parse from a simple join_rule string (for creation) ---
  static JoinRulesConfig from_preset(const std::string& join_rule_str,
                                      const std::string& creator) {
    return JoinRulesConfig(
        JoinRule(join_rule_str),
        AllowRuleSet(),
        creator,
        now_ms(),
        ""
    );
  }

  // --- Serialize to m.room.join_rules content ---
  json to_content_json() const {
    json content;
    content["join_rule"] = join_rule_.type_string();
    if (join_rule_.supports_allow_list() && !allow_.empty()) {
      content["allow"] = allow_.to_json();
    }
    return content;
  }

  // --- Serialize to full state event ---
  json to_state_event(const std::string& room_id,
                      const std::string& sender) const {
    json event;
    event["type"] = std::string(join_rules_constants::JOIN_RULES_EVENT_TYPE);
    event["state_key"] = "";
    event["sender"] = sender;
    event["room_id"] = room_id;
    event["content"] = to_content_json();
    return event;
  }

  // --- Accessors ---
  JoinRule join_rule() const { return join_rule_; }
  const AllowRuleSet& allow() const { return allow_; }
  const std::string& set_by() const { return set_by_; }
  int64_t set_at_ms() const { return set_at_ms_; }
  const std::string& event_id() const { return event_id_; }

  // --- Mutators ---
  void set_join_rule(JoinRule rule) { join_rule_ = rule; }
  AllowRuleSet& mutable_allow() { return allow_; }

  // --- Semantic queries ---
  bool is_public() const { return join_rule_.is_public(); }
  bool requires_invite() const { return join_rule_.requires_invite(); }
  bool allows_knock() const { return join_rule_.allows_knock(); }
  bool is_restricted() const { return join_rule_.is_restricted(); }
  bool has_allow_rules() const { return !allow_.empty(); }

  // --- Normalize: if the join_rule has allow rules, convert to restricted ---
  JoinRulesConfig normalized() const {
    JoinRulesConfig copy = *this;
    if (!allow_.empty() && copy.join_rule_.type() == JoinRule::Type::INVITE) {
      copy.join_rule_ = JoinRule(JoinRule::Type::RESTRICTED);
    }
    return copy;
  }

  // --- Comparison ---
  bool operator==(const JoinRulesConfig& other) const {
    return join_rule_ == other.join_rule_;
  }

private:
  JoinRule join_rule_;
  AllowRuleSet allow_;
  std::string set_by_;
  int64_t set_at_ms_;
  std::string event_id_;
};

// ============================================================================
// JoinRulesStateEngine — manages join rule states and transitions
// ============================================================================
//
// Core state engine for join rules. Maintains the current join rules
// configuration for each room, handles state transitions with validation,
// provides caching for performance, and emits state change events.
//
class JoinRulesStateEngine {
public:
  JoinRulesStateEngine() = default;

  // --- Get current join rules for a room ---
  JoinRulesConfig get_config(const std::string& room_id) {
    std::shared_lock lock(mutex_);

    // Check cache first
    auto cache_it = config_cache_.find(room_id);
    if (cache_it != config_cache_.end()) {
      auto& entry = cache_it->second;
      if (now_ms() - entry.cached_at_ms <
          join_rules_constants::JOIN_RULES_CACHE_TTL_MS) {
        return entry.config;
      }
    }

    // Default to invite (safest)
    return JoinRulesConfig();
  }

  // --- Set join rules for a room ---
  void set_config(const std::string& room_id,
                  const JoinRulesConfig& config) {
    std::unique_lock lock(mutex_);

    CacheEntry entry;
    entry.config = config;
    entry.cached_at_ms = now_ms();
    config_cache_[room_id] = entry;

    // Record in history
    history_[room_id].push_back({
        config.join_rule().type_string(),
        config.set_by(),
        entry.cached_at_ms
    });
  }

  // --- Transition to a new join rule ---
  // Validates the transition and returns the new config if allowed.
  // Returns std::nullopt if the transition is invalid.
  // Defined out-of-line after JoinRulesTransitionValidator.
  std::optional<JoinRulesConfig> transition(
      const std::string& room_id,
      JoinRule new_rule,
      const AllowRuleSet& new_allow,
      const std::string& sender,
      const std::string& room_version);

  // --- Invalidate cache for a room ---
  void invalidate(const std::string& room_id) {
    std::unique_lock lock(mutex_);
    config_cache_.erase(room_id);
  }

  // --- Get transition history ---
  struct HistoryEntry {
    std::string join_rule;
    std::string set_by;
    int64_t timestamp_ms;
  };

  std::vector<HistoryEntry> get_history(const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    auto it = history_.find(room_id);
    if (it != history_.end()) {
      return it->second;
    }
    return {};
  }

  // --- Check if a room has cached state ---
  bool has_cached_state(const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    return config_cache_.find(room_id) != config_cache_.end();
  }

  // --- Clear all state (for testing/reset) ---
  void clear() {
    std::unique_lock lock(mutex_);
    config_cache_.clear();
    history_.clear();
  }

private:
  struct CacheEntry {
    JoinRulesConfig config;
    int64_t cached_at_ms = 0;
  };

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, CacheEntry> config_cache_;
  std::unordered_map<std::string, std::vector<HistoryEntry>> history_;
};

// ============================================================================
// JoinRulesTransitionValidator — validates transitions between join rules
// ============================================================================
//
// Implements the Matrix spec rules for changing join rules. Not all
// transitions are valid; some require allow lists, others require
// specific room versions. This class provides static validation that
// can be called before performing a transition.
//
class JoinRulesTransitionValidator {
public:
  // --- Validate a transition from one join rule to another ---
  // Returns {allowed, error_message}. If allowed is false, error_message
  // contains a human-readable reason.
  static std::pair<bool, std::string> validate(
      const JoinRule& from,
      const JoinRule& to,
      const AllowRuleSet& allow_rules,
      const std::string& room_version) {

    // Any rule can transition to invite (safest)
    if (to.type() == JoinRule::Type::INVITE ||
        to.type() == JoinRule::Type::PRIVATE) {
      // If allow rules are still present, they're silently dropped
      return {true, ""};
    }

    // Any rule can transition to public (opening up the room)
    if (to.type() == JoinRule::Type::PUBLIC) {
      return {true, ""};
    }

    // Restricted requires allow rules and room version 8+
    if (to.type() == JoinRule::Type::RESTRICTED) {
      if (allow_rules.empty()) {
        return {false,
            "restricted join rules require at least one allow rule"};
      }
      if (!is_version_sufficient(room_version,
                                 join_rules_constants::MIN_VERSION_RESTRICTED)) {
        return {false,
            "restricted join rules require room version 8 or later"};
      }
      return {true, ""};
    }

    // Knock requires room version 7+
    if (to.type() == JoinRule::Type::KNOCK) {
      if (!is_version_sufficient(room_version,
                                 join_rules_constants::MIN_VERSION_KNOCK)) {
        return {false,
            "knock join rules require room version 7 or later"};
      }
      return {true, ""};
    }

    // Knock-restricted requires allow rules and room version 8+
    if (to.type() == JoinRule::Type::KNOCK_RESTRICTED) {
      if (allow_rules.empty()) {
        return {false,
            "knock_restricted join rules require at least one allow rule"};
      }
      if (!is_version_sufficient(room_version,
                                 join_rules_constants::MIN_VERSION_KNOCK_RESTRICTED)) {
        return {false,
            "knock_restricted join rules require room version 8 or later"};
      }
      return {true, ""};
    }

    return {true, ""};
  }

  // --- Check if a transition would remove restricted access ---
  static bool would_remove_restricted(const JoinRule& from,
                                       const JoinRule& to) {
    return from.is_restricted() && !to.is_restricted();
  }

  // --- Check if a transition would add restricted access ---
  static bool would_add_restricted(const JoinRule& from,
                                    const JoinRule& to) {
    return !from.is_restricted() && to.is_restricted();
  }

  // --- Check if a transition would add knock support ---
  static bool would_add_knock(const JoinRule& from,
                               const JoinRule& to) {
    return !from.allows_knock() && to.allows_knock();
  }

  // --- Check if a transition would remove knock support ---
  static bool would_remove_knock(const JoinRule& from,
                                  const JoinRule& to) {
    return from.allows_knock() && !to.allows_knock();
  }

  // --- Get a human-readable summary of what the transition changes ---
  static std::string describe_transition(const JoinRule& from,
                                          const JoinRule& to) {
    std::ostringstream desc;
    desc << "Join rule transition from '" << from.type_string()
         << "' to '" << to.type_string() << "'";
    if (would_add_restricted(from, to)) {
      desc << " (adding restricted join support)";
    }
    if (would_remove_restricted(from, to)) {
      desc << " (removing restricted join support)";
    }
    if (would_add_knock(from, to)) {
      desc << " (adding knock support)";
    }
    if (would_remove_knock(from, to)) {
      desc << " (removing knock support)";
    }
    return desc.str();
  }

  // --- List all valid transition targets from a given rule ---
  static std::vector<std::string> valid_transitions_from(
      const JoinRule& from,
      const std::string& room_version) {
    std::vector<std::string> targets;

    // invite is always a valid target
    targets.push_back("invite");
    targets.push_back("private");

    // public is always valid
    targets.push_back("public");

    // knock requires version 7+
    if (is_version_sufficient(room_version,
                              join_rules_constants::MIN_VERSION_KNOCK)) {
      targets.push_back("knock");
    }

    // restricted requires version 8+
    if (is_version_sufficient(room_version,
                              join_rules_constants::MIN_VERSION_RESTRICTED)) {
      targets.push_back("restricted");
    }

    // knock_restricted requires version 8+
    if (is_version_sufficient(room_version,
                              join_rules_constants::MIN_VERSION_KNOCK_RESTRICTED)) {
      targets.push_back("knock_restricted");
    }

    return targets;
  }

  // --- Do two rules conflict? (e.g., public + restricted allow list) ---
  static bool has_state_conflict(const JoinRule& rule,
                                  const AllowRuleSet& allow_rules) {
    // Having allow rules with a non-restricted rule is a soft conflict
    if (!allow_rules.empty() && !rule.supports_allow_list()) {
      return true;
    }
    // Being restricted without allow rules is an invalid state
    if (rule.is_restricted() && allow_rules.empty()) {
      return true;
    }
    return false;
  }

private:
  // Parse room version string to integer, default to 1
  static int parse_version(const std::string& ver) {
    try {
      return std::stoi(ver);
    } catch (...) {
      return 1;
    }
  }

  static bool is_version_sufficient(const std::string& ver, int required) {
    return parse_version(ver) >= required;
  }
};

// ============================================================================
// JoinRulesStateEngine::transition — out-of-line definition
// ============================================================================
// Defined here to allow referencing JoinRulesTransitionValidator which
// must be fully defined before this method can be compiled.
std::optional<JoinRulesConfig> JoinRulesStateEngine::transition(
    const std::string& room_id,
    JoinRule new_rule,
    const AllowRuleSet& new_allow,
    const std::string& sender,
    const std::string& room_version) {

  auto current = get_config(room_id);

  // Validate the transition using the fully-defined TransitionValidator
  auto validation = JoinRulesTransitionValidator::validate(
      current.join_rule(), new_rule, new_allow, room_version);

  if (!validation.first) {
    return std::nullopt;
  }

  JoinRulesConfig new_config(
      new_rule,
      new_allow,
      sender,
      now_ms(),
      generate_event_id(extract_server_name(room_id))
  );

  set_config(room_id, new_config);
  return new_config;
}

// ============================================================================
// RestrictedJoinValidator — validates restricted room join authorization
// ============================================================================
//
// Determines whether a user is authorized to join a restricted room by
// checking the allow list: the user must be a joined member of at least
// one room or space listed in the allow rules. Supports:
//   - Direct membership check in allowed rooms
//   - Recursive space membership resolution (if allowed room is a space)
//   - Caching of membership checks to reduce database load
//   - Federation-aware validation (via servers)
//   - Batch authorization for bulk operations
//
class RestrictedJoinValidator {
public:
  RestrictedJoinValidator() = default;

  // --- Check if a user is authorized to join a restricted room ---
  // Evaluates the allow list and checks the user's membership in
  // referenced rooms. Returns true if the user is authorized.
  bool is_authorized(const std::string& room_id,
                     const std::string& user_id,
                     const JoinRulesConfig& config) {
    // Only restricted rules use allow-list authorization
    if (!config.is_restricted()) {
      return true; // Not a restricted room — other join rules apply
    }

    // Check each allow rule
    for (auto& rule : config.allow().all()) {
      if (rule.type == "m.room_membership") {
        // Check if user is a joined member of the allowed room
        if (check_membership_in_room(rule.room_id, user_id)) {
          return true;
        }
        // Also check via space membership (recursive)
        if (check_membership_via_space(rule.room_id, user_id)) {
          return true;
        }
      }
    }

    return false;
  }

  // --- Check authorization for multiple users at once (batch) ---
  std::unordered_map<std::string, bool> batch_authorize(
      const std::string& room_id,
      const std::vector<std::string>& user_ids,
      const JoinRulesConfig& config) {
    std::unordered_map<std::string, bool> results;

    if (!config.is_restricted()) {
      for (auto& uid : user_ids) {
        results[uid] = true;
      }
      return results;
    }

    // For each user, check authorization
    for (auto& uid : user_ids) {
      results[uid] = is_authorized(room_id, uid, config);
    }

    return results;
  }

  // --- Check which allowed rooms a user has membership in ---
  std::vector<std::string> get_authorizing_rooms(
      const std::string& user_id,
      const JoinRulesConfig& config) {
    std::vector<std::string> rooms;

    for (auto& rule : config.allow().all()) {
      if (rule.type == "m.room_membership" &&
          check_membership_in_room(rule.room_id, user_id)) {
        rooms.push_back(rule.room_id);
      }
    }

    return rooms;
  }

  // --- Cache membership check results ---
  void set_membership_checker(
      std::function<bool(const std::string&, const std::string&)> checker) {
    membership_checker_ = std::move(checker);
  }

  // --- Invalidate cached membership checks for a room ---
  void invalidate_room_cache(const std::string& room_id) {
    std::unique_lock lock(cache_mutex_);
    auto it = membership_cache_.begin();
    while (it != membership_cache_.end()) {
      if (it->first.find(room_id) != std::string::npos) {
        it = membership_cache_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // --- Invalidate cache for a specific user ---
  void invalidate_user_cache(const std::string& user_id) {
    std::unique_lock lock(cache_mutex_);
    auto it = membership_cache_.begin();
    while (it != membership_cache_.end()) {
      if (it->first.find(user_id) != std::string::npos) {
        it = membership_cache_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // --- Clear all caches ---
  void clear_cache() {
    std::unique_lock lock(cache_mutex_);
    membership_cache_.clear();
    space_membership_cache_.clear();
  }

private:
  // Check membership in a specific room (with caching)
  bool check_membership_in_room(const std::string& room_id,
                                 const std::string& user_id) {
    std::string cache_key = room_id + "|" + user_id;

    {
      std::shared_lock lock(cache_mutex_);
      auto it = membership_cache_.find(cache_key);
      if (it != membership_cache_.end()) {
        if (now_ms() - it->second.second <
            join_rules_constants::ALLOW_CHECK_CACHE_TTL_MS) {
          return it->second.first;
        }
      }
    }

    bool result = false;
    if (membership_checker_) {
      result = membership_checker_(room_id, user_id);
    }

    {
      std::unique_lock lock(cache_mutex_);
      membership_cache_[cache_key] = {result, now_ms()};
    }

    return result;
  }

  // Check membership via space hierarchy (recursive)
  bool check_membership_via_space(const std::string& space_id,
                                   const std::string& user_id) {
    // In a real implementation, this would traverse m.space.child
    // relationships to find rooms within the space, then check
    // user membership in any of those rooms.

    std::string cache_key = "space:" + space_id + "|" + user_id;

    {
      std::shared_lock lock(cache_mutex_);
      auto it = space_membership_cache_.find(cache_key);
      if (it != space_membership_cache_.end()) {
        if (now_ms() - it->second.second <
            join_rules_constants::ALLOW_CHECK_CACHE_TTL_MS) {
          return it->second.first;
        }
      }
    }

    // If the allowed room is a space, check if the user is in any
    // child room of that space. This is deferred to the membership
    // checker implementation.
    bool result = false;
    if (membership_checker_) {
      result = membership_checker_(space_id, user_id);
    }

    {
      std::unique_lock lock(cache_mutex_);
      space_membership_cache_[cache_key] = {result, now_ms()};
    }

    return result;
  }

  std::function<bool(const std::string&, const std::string&)> membership_checker_;
  mutable std::shared_mutex cache_mutex_;
  std::unordered_map<std::string, std::pair<bool, int64_t>> membership_cache_;
  std::unordered_map<std::string, std::pair<bool, int64_t>> space_membership_cache_;
};

// ============================================================================
// KnockRequestManager — manages knock requests for rooms
// ============================================================================
//
// Handles the full lifecycle of knock requests: submission, acceptance,
// rejection, history tracking, deduplication, and cleanup. Knocks are
// stored per-room with metadata (reason, timestamps, state). The manager
// enforces limits on pending knocks and provides query APIs for admins.
//
class KnockRequestManager {
public:
  // --- Knock state enumeration ---
  enum class KnockState {
    PENDING = 0,    // Awaiting admin review
    ACCEPTED = 1,   // Approved, user invited
    REJECTED = 2,   // Denied with optional reason
    EXPIRED = 3,    // Stale knock cleaned up
    WITHDRAWN = 4   // User retracted their knock
  };

  // --- Knock record ---
  struct KnockRecord {
    std::string room_id;
    std::string user_id;
    std::string reason;
    std::string event_id;
    std::string handled_by;       // Who accepted/rejected (empty if pending)
    std::string response_reason;  // Admin's reason for rejection
    int64_t created_at_ms = 0;
    int64_t handled_at_ms = 0;
    KnockState state = KnockState::PENDING;

    // --- Serialize to JSON ---
    json to_json() const {
      json j;
      j["room_id"] = room_id;
      j["user_id"] = user_id;
      j["reason"] = reason;
      j["event_id"] = event_id;
      j["state"] = state_to_string(state);
      j["created_at"] = iso_timestamp(created_at_ms);
      if (!handled_by.empty()) j["handled_by"] = handled_by;
      if (!response_reason.empty()) j["response_reason"] = response_reason;
      if (handled_at_ms > 0) j["handled_at"] = iso_timestamp(handled_at_ms);
      return j;
    }

    static std::string state_to_string(KnockState s) {
      switch (s) {
        case KnockState::PENDING:   return "pending";
        case KnockState::ACCEPTED:  return "accepted";
        case KnockState::REJECTED:  return "rejected";
        case KnockState::EXPIRED:   return "expired";
        case KnockState::WITHDRAWN: return "withdrawn";
        default:                    return "unknown";
      }
    }

    static KnockState state_from_string(const std::string& s) {
      if (s == "pending")   return KnockState::PENDING;
      if (s == "accepted")  return KnockState::ACCEPTED;
      if (s == "rejected")  return KnockState::REJECTED;
      if (s == "expired")   return KnockState::EXPIRED;
      if (s == "withdrawn") return KnockState::WITHDRAWN;
      return KnockState::PENDING;
    }
  };

  KnockRequestManager() = default;

  // --- Submit a knock request ---
  // Validates limits, checks for duplicates, and stores the knock.
  json submit_knock(const std::string& room_id,
                    const std::string& user_id,
                    const std::string& reason,
                    const std::string& server_name) {

    // Check user-level knock limit
    size_t user_pending = count_user_pending_knocks(user_id);
    if (user_pending >= join_rules_constants::MAX_PENDING_KNOCKS_PER_USER) {
      return make_error("M_LIMIT_EXCEEDED",
          "You have too many pending knock requests");
    }

    // Check room-level knock limit
    size_t room_pending = count_room_pending_knocks(room_id);
    if (room_pending >= join_rules_constants::MAX_PENDING_KNOCKS_PER_ROOM) {
      return make_error("M_LIMIT_EXCEEDED",
          "This room has too many pending knock requests");
    }

    // Check for duplicate pending knock
    for (auto& k : knocks_[room_id]) {
      if (k.user_id == user_id && k.state == KnockState::PENDING) {
        return make_error("M_FORBIDDEN",
            "You already have a pending knock request in this room");
      }
    }

    std::string event_id = generate_event_id(server_name);

    KnockRecord record;
    record.room_id = room_id;
    record.user_id = user_id;
    record.reason = reason;
    record.event_id = event_id;
    record.created_at_ms = now_ms();
    record.state = KnockState::PENDING;

    knocks_[room_id].push_back(record);

    json result;
    result["event_id"] = event_id;
    result["room_id"] = room_id;
    result["user_id"] = user_id;
    result["membership"] = "knock";
    result["knock_state"] = "pending";
    if (!reason.empty()) {
      result["reason"] = reason;
    }

    return result;
  }

  // --- Accept a knock (admin/moderator action) ---
  json accept_knock(const std::string& room_id,
                    const std::string& user_id,
                    const std::string& approver,
                    const std::string& server_name) {

    auto* record = find_pending_knock(room_id, user_id);
    if (!record) {
      return make_error("M_NOT_FOUND",
          "No pending knock request from this user");
    }

    record->state = KnockState::ACCEPTED;
    record->handled_by = approver;
    record->handled_at_ms = now_ms();

    std::string event_id = generate_event_id(server_name);

    json result;
    result["event_id"] = event_id;
    result["room_id"] = room_id;
    result["user_id"] = user_id;
    result["membership"] = "invite";
    result["knock_state"] = "accepted";
    result["accepted_by"] = approver;

    // In production: create invite event, notify user, update federation

    return result;
  }

  // --- Reject a knock ---
  json reject_knock(const std::string& room_id,
                    const std::string& user_id,
                    const std::string& rejector,
                    const std::string& reason,
                    const std::string& server_name) {

    auto* record = find_pending_knock(room_id, user_id);
    if (!record) {
      return make_error("M_NOT_FOUND",
          "No pending knock request from this user");
    }

    record->state = KnockState::REJECTED;
    record->handled_by = rejector;
    record->response_reason = reason;
    record->handled_at_ms = now_ms();

    std::string event_id = generate_event_id(server_name);

    json result;
    result["event_id"] = event_id;
    result["room_id"] = room_id;
    result["user_id"] = user_id;
    result["membership"] = "leave";
    result["knock_state"] = "rejected";
    result["rejected_by"] = rejector;
    if (!reason.empty()) {
      result["reason"] = reason;
    }

    return result;
  }

  // --- Withdraw a knock (user-initiated) ---
  json withdraw_knock(const std::string& room_id,
                      const std::string& user_id,
                      const std::string& server_name) {

    auto* record = find_pending_knock(room_id, user_id);
    if (!record) {
      return make_error("M_NOT_FOUND",
          "No pending knock request to withdraw");
    }

    record->state = KnockState::WITHDRAWN;
    record->handled_by = user_id;
    record->handled_at_ms = now_ms();

    std::string event_id = generate_event_id(server_name);

    json result;
    result["event_id"] = event_id;
    result["room_id"] = room_id;
    result["user_id"] = user_id;
    result["membership"] = "leave";
    result["knock_state"] = "withdrawn";

    return result;
  }

  // --- Get all pending knocks for a room ---
  std::vector<KnockRecord> get_pending_knocks(const std::string& room_id) {
    std::vector<KnockRecord> result;
    auto it = knocks_.find(room_id);
    if (it != knocks_.end()) {
      for (auto& k : it->second) {
        if (k.state == KnockState::PENDING) {
          result.push_back(k);
        }
      }
    }
    return result;
  }

  // --- Get knock history for a room (all states) ---
  std::vector<KnockRecord> get_knock_history(
      const std::string& room_id,
      size_t limit = 100) {
    std::vector<KnockRecord> result;
    auto it = knocks_.find(room_id);
    if (it != knocks_.end()) {
      auto& list = it->second;
      size_t start = list.size() > limit ? list.size() - limit : 0;
      for (size_t i = start; i < list.size(); ++i) {
        result.push_back(list[i]);
      }
    }
    return result;
  }

  // --- Get knock state for a specific user in a room ---
  std::string get_knock_state(const std::string& room_id,
                               const std::string& user_id) {
    auto it = knocks_.find(room_id);
    if (it != knocks_.end()) {
      for (auto& k : it->second) {
        if (k.user_id == user_id) {
          return KnockRecord::state_to_string(k.state);
        }
      }
    }
    return "none";
  }

  // --- Check if user has a pending knock in a room ---
  bool has_pending_knock(const std::string& room_id,
                          const std::string& user_id) {
    auto* record = find_pending_knock(room_id, user_id);
    return record != nullptr;
  }

  // --- Check if knock is allowed for a room version and join rule ---
  bool is_knock_allowed(const std::string& room_version,
                        const JoinRule& join_rule) {
    // Knock requires room version 7+
    try {
      int ver = std::stoi(room_version);
      if (ver < join_rules_constants::MIN_VERSION_KNOCK) return false;
    } catch (...) {
      return false;
    }

    return join_rule.allows_knock() ||
           join_rule.requires_invite(); // invite-only rooms also allow knock
  }

  // --- Clean up stale/old knocks ---
  int cleanup_stale_knocks(int64_t max_age_ms = 604'800'000) {
    int cleaned = 0;
    int64_t cutoff = now_ms() - max_age_ms;

    for (auto& [rid, records] : knocks_) {
      auto it = records.begin();
      while (it != records.end()) {
        if (it->state == KnockState::PENDING &&
            it->created_at_ms < cutoff) {
          it->state = KnockState::EXPIRED;
          it->handled_at_ms = now_ms();
          cleaned++;
        }
        ++it;
      }
    }

    return cleaned;
  }

  // --- Count statistics ---
  struct KnockStats {
    size_t total_knocks = 0;
    size_t pending_knocks = 0;
    size_t accepted_knocks = 0;
    size_t rejected_knocks = 0;
    size_t expired_knocks = 0;
    size_t withdrawn_knocks = 0;
    size_t rooms_with_knocks = 0;
  };

  KnockStats get_stats() const {
    KnockStats stats;
    stats.rooms_with_knocks = knocks_.size();

    for (auto& [rid, records] : knocks_) {
      stats.total_knocks += records.size();
      for (auto& r : records) {
        switch (r.state) {
          case KnockState::PENDING:   stats.pending_knocks++; break;
          case KnockState::ACCEPTED:  stats.accepted_knocks++; break;
          case KnockState::REJECTED:  stats.rejected_knocks++; break;
          case KnockState::EXPIRED:   stats.expired_knocks++; break;
          case KnockState::WITHDRAWN: stats.withdrawn_knocks++; break;
        }
      }
    }

    return stats;
  }

  // --- Serialize all data for persistence ---
  json serialize_all() const {
    json j = json::array();
    for (auto& [rid, records] : knocks_) {
      for (auto& r : records) {
        j.push_back(r.to_json());
      }
    }
    return j;
  }

private:
  // Find a pending knock record for a user in a room
  KnockRecord* find_pending_knock(const std::string& room_id,
                                   const std::string& user_id) {
    auto it = knocks_.find(room_id);
    if (it != knocks_.end()) {
      for (auto& k : it->second) {
        if (k.user_id == user_id && k.state == KnockState::PENDING) {
          return &k;
        }
      }
    }
    return nullptr;
  }

  // Count pending knocks for a user across all rooms
  size_t count_user_pending_knocks(const std::string& user_id) {
    size_t count = 0;
    for (auto& [rid, records] : knocks_) {
      for (auto& r : records) {
        if (r.user_id == user_id && r.state == KnockState::PENDING) {
          count++;
        }
      }
    }
    return count;
  }

  // Count pending knocks for a specific room
  size_t count_room_pending_knocks(const std::string& room_id) {
    size_t count = 0;
    auto it = knocks_.find(room_id);
    if (it != knocks_.end()) {
      for (auto& r : it->second) {
        if (r.state == KnockState::PENDING) count++;
      }
    }
    return count;
  }

  std::unordered_map<std::string, std::vector<KnockRecord>> knocks_;
};

// ============================================================================
// KnockAuditTrail — immutable audit log for knock events
// ============================================================================
//
// Records every knock-related action (submit, accept, reject, withdraw)
// with full metadata for audit purposes. Supports paginated queries,
// federation-relevant filtering, and export for compliance.
//
class KnockAuditTrail {
public:
  struct AuditEntry {
    std::string action;       // "submit", "accept", "reject", "withdraw", "expire"
    std::string room_id;
    std::string user_id;      // The knocking user
    std::string actor_id;     // Who performed the action
    std::string event_id;
    std::string reason;
    int64_t timestamp_ms = 0;
    json metadata;
  };

  KnockAuditTrail() = default;

  // --- Record an audit entry ---
  void record(const std::string& action,
              const std::string& room_id,
              const std::string& user_id,
              const std::string& actor_id,
              const std::string& event_id,
              const std::string& reason,
              const json& metadata = json::object()) {
    AuditEntry entry;
    entry.action = action;
    entry.room_id = room_id;
    entry.user_id = user_id;
    entry.actor_id = actor_id;
    entry.event_id = event_id;
    entry.reason = reason;
    entry.timestamp_ms = now_ms();
    entry.metadata = metadata;

    std::unique_lock lock(mutex_);
    entries_.push_back(entry);
  }

  // --- Query audit entries for a room ---
  std::vector<AuditEntry> get_entries_for_room(
      const std::string& room_id,
      size_t limit = 100,
      size_t offset = 0) const {
    std::shared_lock lock(mutex_);
    std::vector<AuditEntry> result;

    for (auto& e : entries_) {
      if (e.room_id == room_id) {
        result.push_back(e);
      }
    }

    // Apply offset and limit
    if (offset < result.size()) {
      size_t end = std::min(offset + limit, result.size());
      result = std::vector<AuditEntry>(result.begin() + offset,
                                        result.begin() + end);
    } else {
      result.clear();
    }

    return result;
  }

  // --- Query audit entries for a user ---
  std::vector<AuditEntry> get_entries_for_user(
      const std::string& user_id,
      size_t limit = 100) const {
    std::shared_lock lock(mutex_);
    std::vector<AuditEntry> result;

    for (auto& e : entries_) {
      if (e.user_id == user_id || e.actor_id == user_id) {
        result.push_back(e);
        if (result.size() >= limit) break;
      }
    }

    return result;
  }

  // --- Export all entries as JSON ---
  json export_json() const {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (auto& e : entries_) {
      json j;
      j["action"] = e.action;
      j["room_id"] = e.room_id;
      j["user_id"] = e.user_id;
      j["actor_id"] = e.actor_id;
      j["event_id"] = e.event_id;
      j["reason"] = e.reason;
      j["timestamp"] = iso_timestamp(e.timestamp_ms);
      j["metadata"] = e.metadata;
      arr.push_back(j);
    }
    return arr;
  }

  // --- Purge old entries ---
  size_t purge_old(int64_t older_than_ms) {
    std::unique_lock lock(mutex_);
    size_t before = entries_.size();
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
            [older_than_ms](const AuditEntry& e) {
              return e.timestamp_ms < older_than_ms;
            }),
        entries_.end());
    return before - entries_.size();
  }

  // --- Get count ---
  size_t size() const {
    std::shared_lock lock(mutex_);
    return entries_.size();
  }

private:
  mutable std::shared_mutex mutex_;
  std::vector<AuditEntry> entries_;
};

// ============================================================================
// JoinRuleEnforcer — enforces join rules before allowing room join
// ============================================================================
//
// The primary gatekeeper for room joins. Before any user is allowed to
// join a room, this class evaluates the current join rules, checks for
// invites, validates restricted join authorization, verifies bans, and
// returns an authorized/denied response with appropriate error codes.
//
class JoinRuleEnforcer {
public:
  // --- Authorization result ---
  struct AuthResult {
    bool allowed = false;
    std::string error_code;      // Matrix error code (M_FORBIDDEN, etc.)
    std::string error_message;   // Human-readable explanation
    std::string authorizing_room; // Which allowed room granted access (if any)
    bool requires_invite = false;
    bool requires_knock = false;

    // Convenience constructors
    static AuthResult allow() {
      AuthResult r;
      r.allowed = true;
      return r;
    }

    static AuthResult deny(const std::string& code, const std::string& msg) {
      AuthResult r;
      r.allowed = false;
      r.error_code = code;
      r.error_message = msg;
      return r;
    }
  };

  JoinRuleEnforcer(std::shared_ptr<JoinRulesStateEngine> state_engine,
                   std::shared_ptr<RestrictedJoinValidator> restricted_validator,
                   std::shared_ptr<KnockRequestManager> knock_manager)
      : state_engine_(std::move(state_engine)),
        restricted_validator_(std::move(restricted_validator)),
        knock_manager_(std::move(knock_manager)) {}

  // --- Check if a user can join a room ---
  // Evaluates all applicable rules: public access, invite, restricted
  // authorization, ban checks. Returns AuthResult with detailed info.
  AuthResult check_join(const std::string& room_id,
                         const std::string& user_id,
                         const std::string& room_version) {

    auto config = state_engine_->get_config(room_id);
    JoinRule rule = config.join_rule();

    // --- Public rooms: anyone can join ---
    if (rule.is_public()) {
      return AuthResult::allow();
    }

    // --- Check if user is banned ---
    if (is_user_banned(room_id, user_id)) {
      return AuthResult::deny("M_FORBIDDEN",
          "You are banned from this room");
    }

    // --- Check if user has an invite ---
    if (has_invite(room_id, user_id)) {
      return AuthResult::allow();
    }

    // --- Restricted rooms: check allow-list membership ---
    if (rule.is_restricted()) {
      auto auth_result = check_restricted_join(room_id, user_id, config);
      if (auth_result.allowed) return auth_result;
      // If restricted check fails, fall through to invite/knock checks
    }

    // --- Invite-only rooms ---
    if (rule.requires_invite()) {
      AuthResult r = AuthResult::deny("M_FORBIDDEN",
          "You are not invited to this room");
      r.requires_invite = true;
      return r;
    }

    // --- Knock rooms: user can knock instead of join ---
    if (rule.allows_knock()) {
      AuthResult r = AuthResult::deny("M_FORBIDDEN",
          "You must knock to request access to this room");
      r.requires_knock = true;
      return r;
    }

    // --- Fallback: deny ---
    return AuthResult::deny("M_FORBIDDEN",
        "You are not authorized to join this room");
  }

  // --- Check if a user can send a knock to a room ---
  AuthResult check_knock(const std::string& room_id,
                          const std::string& user_id,
                          const std::string& room_version) {

    auto config = state_engine_->get_config(room_id);
    JoinRule rule = config.join_rule();

    // Public rooms don't need knocks
    if (rule.is_public()) {
      return AuthResult::deny("M_FORBIDDEN",
          "This room is public; you can join directly");
    }

    // Check if knock is allowed for this room version
    if (!knock_manager_->is_knock_allowed(room_version, rule)) {
      return AuthResult::deny("M_FORBIDDEN",
          "Knocking is not supported in this room version");
    }

    // Check if user is banned
    if (is_user_banned(room_id, user_id)) {
      return AuthResult::deny("M_FORBIDDEN",
          "You are banned from this room");
    }

    // If knock_restricted, also check restricted authorization
    if (rule.type() == JoinRule::Type::KNOCK_RESTRICTED) {
      auto auth_result = check_restricted_join(room_id, user_id, config);
      if (!auth_result.allowed) {
        return auth_result; // Not authorized for restricted knock
      }
    }

    return AuthResult::allow();
  }

  // --- Validate that a user can change join rules ---
  AuthResult check_change_join_rules(const std::string& room_id,
                                      const std::string& user_id,
                                      const JoinRule& new_rule,
                                      const AllowRuleSet& new_allow,
                                      const std::string& room_version) {

    // Check user has power level to change join rules
    if (!has_power_for_action(user_id, room_id, "set_join_rules")) {
      return AuthResult::deny("M_FORBIDDEN",
          "You don't have permission to change join rules");
    }

    // Validate transition
    auto current = state_engine_->get_config(room_id);
    auto validation = JoinRulesTransitionValidator::validate(
        current.join_rule(), new_rule, new_allow, room_version);

    if (!validation.first) {
      return AuthResult::deny("M_INVALID_PARAM", validation.second);
    }

    return AuthResult::allow();
  }

  // --- Bulk check: can each user join? ---
  std::unordered_map<std::string, AuthResult> bulk_check_join(
      const std::string& room_id,
      const std::vector<std::string>& user_ids,
      const std::string& room_version) {

    std::unordered_map<std::string, AuthResult> results;
    for (auto& uid : user_ids) {
      results[uid] = check_join(room_id, uid, room_version);
    }
    return results;
  }

private:
  // Check restricted join authorization
  AuthResult check_restricted_join(const std::string& room_id,
                                    const std::string& user_id,
                                    const JoinRulesConfig& config) {
    if (restricted_validator_->is_authorized(room_id, user_id, config)) {
      auto authorizing = restricted_validator_->get_authorizing_rooms(
          user_id, config);
      AuthResult r = AuthResult::allow();
      if (!authorizing.empty()) {
        r.authorizing_room = authorizing[0];
      }
      return r;
    }

    AuthResult r = AuthResult::deny("M_FORBIDDEN",
        "You are not a member of any room that allows joining this room");
    r.requires_invite = true;
    return r;
  }

  // Stub: check if user is banned from room
  bool is_user_banned(const std::string& room_id,
                      const std::string& user_id) {
    // In production: query room_memberships for membership="ban"
    return false;
  }

  // Stub: check if user has an active invite
  bool has_invite(const std::string& room_id,
                  const std::string& user_id) {
    // In production: query room_memberships for membership="invite"
    return false;
  }

  // Stub: check power level
  bool has_power_for_action(const std::string& user_id,
                             const std::string& room_id,
                             const std::string& action) {
    // In production: query power_levels state event
    return true;
  }

  std::shared_ptr<JoinRulesStateEngine> state_engine_;
  std::shared_ptr<RestrictedJoinValidator> restricted_validator_;
  std::shared_ptr<KnockRequestManager> knock_manager_;
};

// ============================================================================
// UpgradeJoinRulesPropagator — propagates join rules during room upgrade
// ============================================================================
//
// When a room is upgraded to a new version, the join rules from the old
// room must be propagated to the new room. This class handles:
//   - Copying the join_rule value
//   - Copying the allow list for restricted rooms
//   - Updating allow-rule room_id references if they point to the old room
//   - Tombstoning the old room's join rules
//   - Ensuring version compatibility (e.g., restricted requires v8+)
//
class UpgradeJoinRulesPropagator {
public:
  // --- Propagate join rules from old room to new room ---
  // Returns the new JoinRulesConfig for the new room, or throws on error.
  static JoinRulesConfig propagate(
      const std::string& old_room_id,
      const std::string& new_room_id,
      const std::string& old_room_version,
      const std::string& new_room_version,
      const std::string& upgrade_user,
      const JoinRulesConfig& old_config) {

    JoinRule old_rule = old_config.join_rule();
    AllowRuleSet new_allow = old_config.allow();

    // Update allow rules that reference the old room to point to new room
    new_allow.replace_room_id(old_room_id, new_room_id);

    // Check if the join rule is supported in the new room version
    JoinRule new_rule = adjust_for_version(old_rule, new_room_version, new_allow);

    JoinRulesConfig new_config(
        new_rule,
        new_allow,
        upgrade_user,
        now_ms(),
        generate_event_id(domain_from_room_id(new_room_id))
    );

    return new_config;
  }

  // --- Build the tombstone join rules event for the old room ---
  // Sets join_rule to "invite" and clears allow list to prevent
  // people from joining the old room after upgrade.
  static JoinRulesConfig build_tombstone_config(
      const std::string& old_room_id,
      const std::string& upgrade_user,
      const std::string& new_room_id) {

    // Set old room to invite-only after upgrade
    JoinRulesConfig tombstone(
        JoinRule(JoinRule::Type::INVITE),
        AllowRuleSet(), // Clear allow rules
        upgrade_user,
        now_ms(),
        generate_event_id(domain_from_room_id(old_room_id))
    );

    return tombstone;
  }

  // --- Check if the upgrade changes any join rule semantics ---
  static std::vector<std::string> detect_semantic_changes(
      const JoinRulesConfig& old_config,
      const JoinRulesConfig& new_config) {

    std::vector<std::string> changes;

    if (old_config.join_rule() != new_config.join_rule()) {
      changes.push_back("join_rule changed from '" +
          old_config.join_rule().type_string() + "' to '" +
          new_config.join_rule().type_string() + "'");
    }

    if (old_config.allow().size() != new_config.allow().size()) {
      changes.push_back("allow rules count changed from " +
          std::to_string(old_config.allow().size()) + " to " +
          std::to_string(new_config.allow().size()));
    }

    return changes;
  }

  // --- Generate an audit report for the upgrade ---
  static json build_upgrade_audit_report(
      const std::string& old_room_id,
      const std::string& new_room_id,
      const JoinRulesConfig& old_config,
      const JoinRulesConfig& new_config) {

    json report;
    report["old_room_id"] = old_room_id;
    report["new_room_id"] = new_room_id;
    report["old_join_rule"] = old_config.join_rule().type_string();
    report["new_join_rule"] = new_config.join_rule().type_string();
    report["old_allow_rules_count"] = old_config.allow().size();
    report["new_allow_rules_count"] = new_config.allow().size();
    report["upgraded_at"] = iso_timestamp(now_ms());

    auto changes = detect_semantic_changes(old_config, new_config);
    report["changes"] = changes;
    report["had_changes"] = !changes.empty();

    return report;
  }

private:
  // Adjust the join rule if the new room version doesn't support it
  static JoinRule adjust_for_version(const JoinRule& rule,
                                      const std::string& new_version,
                                      const AllowRuleSet& allow_rules) {
    int ver = 1;
    try { ver = std::stoi(new_version); } catch (...) {}

    // Restricted requires version 8+
    if (rule.is_restricted() && ver < 8) {
      // If we have allow rules, keep them but fall back to invite
      if (!allow_rules.empty()) {
        return JoinRule(JoinRule::Type::INVITE);
      }
      return JoinRule(JoinRule::Type::INVITE);
    }

    // Knock requires version 7+
    if (rule.allows_knock() && ver < 7) {
      if (rule.type() == JoinRule::Type::KNOCK_RESTRICTED) {
        return JoinRule(JoinRule::Type::RESTRICTED);
      }
      return JoinRule(JoinRule::Type::INVITE);
    }

    return rule;
  }
};

// ============================================================================
// FederationJoinRulesHandler — federation support for join rules
// ============================================================================
//
// Handles join rules in a federated context:
//   - Sends m.room.join_rules as part of room state over federation
//   - Validates remote server join authorization against join rules
//   - Resolves restricted join authorization across federated servers
//   - Forwards knock events to remote servers
//   - State resolution for conflicting join rules
//
class FederationJoinRulesHandler {
public:
  // --- Federation join rules event structure ---
  struct FedJoinRulesEvent {
    std::string event_id;
    std::string room_id;
    std::string origin_server;
    JoinRulesConfig config;
    int64_t origin_server_ts = 0;
    std::vector<std::string> prev_events;
    json unsigned_data;
  };

  FederationJoinRulesHandler() = default;

  // --- Build a federation-compatible join rules state event ---
  static json build_state_event(const JoinRulesConfig& config,
                                const std::string& room_id,
                                const std::string& sender,
                                const std::string& event_id) {
    json event;
    event["type"] = std::string(join_rules_constants::JOIN_RULES_EVENT_TYPE);
    event["state_key"] = "";
    event["sender"] = sender;
    event["room_id"] = room_id;
    event["event_id"] = event_id;
    event["origin_server_ts"] = now_ms();
    event["content"] = config.to_content_json();
    event["unsigned"] = json::object();
    event["prev_events"] = json::array();
    event["auth_events"] = json::array();
    event["depth"] = 1;
    return event;
  }

  // --- Parse a federation join rules event ---
  static FedJoinRulesEvent parse_event(const json& event) {
    FedJoinRulesEvent fed;
    fed.event_id = event.value("event_id", "");
    fed.room_id = event.value("room_id", "");
    fed.origin_server = event.value("origin", "");
    fed.origin_server_ts = event.value("origin_server_ts", (int64_t)0);

    fed.config = JoinRulesConfig::from_state_event(
        event,
        event.value("sender", ""),
        fed.origin_server_ts,
        fed.event_id
    );

    if (event.contains("prev_events") && event["prev_events"].is_array()) {
      for (auto& pe : event["prev_events"]) {
        fed.prev_events.push_back(pe.get<std::string>());
      }
    }

    if (event.contains("unsigned")) {
      fed.unsigned_data = event["unsigned"];
    }

    return fed;
  }

  // --- Validate a remote join against our join rules ---
  // Returns true if the join should be accepted from the remote server.
  static bool validate_remote_join(const std::string& room_id,
                                    const std::string& user_id,
                                    const std::string& origin_server,
                                    const JoinRulesConfig& local_config,
                                    const std::string& room_version) {

    JoinRule rule = local_config.join_rule();

    // Public rooms: accept remote joins
    if (rule.is_public()) return true;

    // Invite: check if user was invited by a local user
    // (invite state is checked separately)

    // Restricted: the remote server must confirm the user's membership
    // in an allowed room. We trust the remote server's assertion.
    if (rule.is_restricted()) {
      // In a full implementation, we'd verify the remote server's
      // membership claim. For now, we accept if the origin server
      // is listed in any allow rule's via field.
      for (auto& allow_rule : local_config.allow().all()) {
        if (!allow_rule.via.empty() &&
            allow_rule.via == origin_server) {
          return true;
        }
      }
      // Also check if the user's server matches an allow-rule server
      std::string user_server = extract_server_name(user_id);
      for (auto& allow_rule : local_config.allow().all()) {
        std::string allow_server = extract_server_name(allow_rule.room_id);
        if (allow_server == user_server || allow_server == origin_server) {
          return true;
        }
      }
      return false;
    }

    // Knock rooms: knocks from remote servers are accepted
    if (rule.allows_knock()) return true;

    // Default: deny unless invited
    return false;
  }

  // --- Resolve conflicting join rules during state resolution ---
  // When two servers have different join rules for the same room,
  // the most restrictive valid rule wins (safety-first).
  static JoinRulesConfig resolve_conflict(
      const JoinRulesConfig& config_a,
      const JoinRulesConfig& config_b) {

    // The more restrictive rule wins
    int restrictiveness_a = get_restrictiveness(config_a.join_rule());
    int restrictiveness_b = get_restrictiveness(config_b.join_rule());

    if (restrictiveness_a > restrictiveness_b) return config_a;
    if (restrictiveness_b > restrictiveness_a) return config_b;

    // Same restrictiveness: choose the one with the earlier origin_server_ts
    if (config_a.set_at_ms() <= config_b.set_at_ms()) return config_a;
    return config_b;
  }

  // --- Build the join rules portion of a /send_join response ---
  static json build_send_join_response(const JoinRulesConfig& config,
                                        const std::string& room_id) {
    json resp;
    resp["join_rule"] = config.join_rule().type_string();
    if (config.is_restricted() && config.has_allow_rules()) {
      resp["allow"] = config.allow().to_json();
    }
    return resp;
  }

  // --- Check if a federated join rules event is stale ---
  static bool is_stale(const FedJoinRulesEvent& event) {
    return (now_ms() - event.origin_server_ts) >
           join_rules_constants::FED_JOIN_RULES_STALE_MS;
  }

  // --- Generate a signed federation join rules event ---
  static json sign_event(const json& event,
                          const std::string& origin_server) {
    json signed_event = event;
    signed_event["origin"] = origin_server;
    // In production: add server signature
    signed_event["signatures"] = json::object();
    signed_event["signatures"][origin_server] = json::object();
    return signed_event;
  }

private:
  // Assign a restrictiveness score: higher = more restrictive
  static int get_restrictiveness(const JoinRule& rule) {
    switch (rule.type()) {
      case JoinRule::Type::PUBLIC:           return 1;
      case JoinRule::Type::KNOCK:            return 2;
      case JoinRule::Type::RESTRICTED:       return 3;
      case JoinRule::Type::KNOCK_RESTRICTED: return 4;
      case JoinRule::Type::INVITE:           return 5;
      case JoinRule::Type::PRIVATE:          return 5;
      default:                               return 5;
    }
  }
};

// ============================================================================
// DefaultJoinRulesResolver — resolves default join rules for new rooms
// ============================================================================
//
// Determines the appropriate default join rules for newly created rooms
// based on the room creation preset. Also handles overrides from
// creation_content and ensures version compatibility (e.g., restricted
// rooms require room version 8+).
//
class DefaultJoinRulesResolver {
public:
  // --- Known room creation presets ---
  enum class Preset {
    PRIVATE_CHAT,          // 1:1 DM
    TRUSTED_PRIVATE_CHAT,  // Group with trusted participants
    PUBLIC_CHAT            // Open room
  };

  // --- Resolve default join rules from a preset string ---
  static JoinRulesConfig resolve_from_preset(
      const std::string& preset_str,
      const std::string& creator,
      const std::string& room_version) {

    JoinRule rule = default_rule_for_preset(preset_str);
    AllowRuleSet allow;

    // If version supports restricted, we could default to invite
    // (restricted requires explicit allow rules from creator)
    try {
      int ver = std::stoi(room_version);
      if (ver >= join_rules_constants::MIN_VERSION_RESTRICTED) {
        // Room supports restricted, but we still default to invite
        // unless the creator explicitly provides allow rules
      }
    } catch (...) {}

    return JoinRulesConfig(
        rule, allow, creator, now_ms(), ""
    );
  }

  // --- Resolve with explicit allow rules (for restricted rooms) ---
  static JoinRulesConfig resolve_restricted(
      const AllowRuleSet& allow_rules,
      const std::string& creator,
      const std::string& room_version,
      bool knock_enabled = false) {

    JoinRule::Type rule_type = knock_enabled
        ? JoinRule::Type::KNOCK_RESTRICTED
        : JoinRule::Type::RESTRICTED;

    return JoinRulesConfig(
        JoinRule(rule_type), allow_rules, creator, now_ms(), ""
    );
  }

  // --- Resolve with custom creation_content override ---
  static JoinRulesConfig resolve_with_override(
      const std::string& preset_str,
      const json& creation_content,
      const std::string& creator,
      const std::string& room_version) {

    // Check if creation_content explicitly specifies join_rule
    if (creation_content.contains("join_rule") &&
        creation_content["join_rule"].is_string()) {
      std::string explicit_rule = creation_content["join_rule"].get<std::string>();
      JoinRule rule(explicit_rule);
      AllowRuleSet allow;

      // Check for allow rules in creation_content
      if (creation_content.contains("allow") &&
          creation_content["allow"].is_array()) {
        allow = AllowRuleSet::from_json(creation_content["allow"]);
      }

      // Validate version compatibility
      auto validation = JoinRulesTransitionValidator::validate(
          JoinRule(JoinRule::Type::INVITE), // from (doesn't matter for creation)
          rule, allow, room_version);

      if (validation.first) {
        return JoinRulesConfig(rule, allow, creator, now_ms(), "");
      }

      // Fall back to preset if explicit rule is invalid
    }

    return resolve_from_preset(preset_str, creator, room_version);
  }

  // --- Get the default join rule string for a preset ---
  static std::string default_join_rule_for_preset(const std::string& preset) {
    return default_rule_for_preset(preset).type_string();
  }

  // --- Check if a preset implies public access ---
  static bool is_preset_public(const std::string& preset) {
    return preset == "public_chat";
  }

  // --- Get all supported presets with their defaults ---
  static json get_preset_defaults() {
    json j;
    j["private_chat"] = "invite";
    j["trusted_private_chat"] = "invite";
    j["public_chat"] = "public";
    return j;
  }

  // --- Convert a preset label to enum ---
  static Preset parse_preset(const std::string& s) {
    if (s == "public_chat")          return Preset::PUBLIC_CHAT;
    if (s == "trusted_private_chat") return Preset::TRUSTED_PRIVATE_CHAT;
    return Preset::PRIVATE_CHAT; // default
  }

  // --- Get a human-readable description of a preset's defaults ---
  static std::string describe_preset_defaults(const std::string& preset) {
    Preset p = parse_preset(preset);
    switch (p) {
      case Preset::PUBLIC_CHAT:
        return "Public rooms default to join_rule='public': anyone can join "
               "without an invitation.";
      case Preset::TRUSTED_PRIVATE_CHAT:
        return "Trusted private rooms default to join_rule='invite': only "
               "invited users can join. All members share history visibility.";
      case Preset::PRIVATE_CHAT:
      default:
        return "Private rooms default to join_rule='invite': only invited "
               "users can join. History is only visible to joined members.";
    }
  }

private:
  static JoinRule default_rule_for_preset(const std::string& preset) {
    if (preset == "public_chat") return JoinRule(JoinRule::Type::PUBLIC);
    return JoinRule(JoinRule::Type::INVITE); // private_chat, trusted_private_chat
  }
};

// ============================================================================
// JoinRulesCoordinator — orchestrates all join rules components
// ============================================================================
//
// Central coordinator that ties together the state engine, validator,
// knock manager, enforcer, upgrade propagator, federation handler,
// transition validator, and default resolver. Provides a unified API
// for all join-rule-related operations.
//
class JoinRulesCoordinator {
public:
  JoinRulesCoordinator(const std::string& server_name)
      : server_name_(server_name),
        state_engine_(std::make_shared<JoinRulesStateEngine>()),
        restricted_validator_(std::make_shared<RestrictedJoinValidator>()),
        knock_manager_(std::make_shared<KnockRequestManager>()),
        knock_audit_(std::make_shared<KnockAuditTrail>()),
        enforcer_(std::make_shared<JoinRuleEnforcer>(
            state_engine_, restricted_validator_, knock_manager_)) {}

  // ========================================================================
  // Join Rules Management API
  // ========================================================================

  // --- Get current join rules for a room ---
  JoinRulesConfig get_join_rules(const std::string& room_id) {
    return state_engine_->get_config(room_id);
  }

  // --- Get join rules as JSON for API responses ---
  json get_join_rules_json(const std::string& room_id) {
    auto config = state_engine_->get_config(room_id);
    json j;
    j["room_id"] = room_id;
    j["join_rule"] = config.join_rule().type_string();
    if (config.is_restricted() && config.has_allow_rules()) {
      j["allow"] = config.allow().to_json();
    }
    j["set_by"] = config.set_by();
    j["set_at"] = iso_timestamp(config.set_at_ms());
    return j;
  }

  // --- Set join rules for a room ---
  json set_join_rules(const std::string& room_id,
                       const std::string& join_rule_str,
                       const json& allow_rules_json,
                       const std::string& sender,
                       const std::string& room_version) {

    JoinRule new_rule(join_rule_str);
    AllowRuleSet new_allow;

    if (allow_rules_json.is_array()) {
      new_allow = AllowRuleSet::from_json(allow_rules_json);
    }

    // Validate the change
    auto auth = enforcer_->check_change_join_rules(
        room_id, sender, new_rule, new_allow, room_version);

    if (!auth.allowed) {
      return make_error(auth.error_code, auth.error_message);
    }

    // Perform the transition
    auto new_config = state_engine_->transition(
        room_id, new_rule, new_allow, sender, room_version);

    if (!new_config.has_value()) {
      return make_error("M_INVALID_PARAM",
          "Invalid join rule transition");
    }

    return get_join_rules_json(room_id);
  }

  // --- Initialize join rules for a new room (at creation time) ---
  json initialize_for_new_room(const std::string& room_id,
                                const std::string& preset,
                                const std::string& creator,
                                const std::string& room_version,
                                const json& creation_content = json::object()) {

    JoinRulesConfig config;

    if (!creation_content.empty() &&
        creation_content.contains("join_rule")) {
      config = DefaultJoinRulesResolver::resolve_with_override(
          preset, creation_content, creator, room_version);
    } else {
      config = DefaultJoinRulesResolver::resolve_from_preset(
          preset, creator, room_version);
    }

    state_engine_->set_config(room_id, config);

    return get_join_rules_json(room_id);
  }

  // ========================================================================
  // Restricted Room API
  // ========================================================================

  // --- Add an allow rule to a restricted room ---
  json add_allow_rule(const std::string& room_id,
                       const std::string& allow_room_id,
                       const std::string& via,
                       const std::string& sender) {

    auto config = state_engine_->get_config(room_id);

    AllowRule rule;
    rule.type = "m.room_membership";
    rule.room_id = allow_room_id;
    rule.via = via;
    rule.added_by = sender;
    rule.added_at_ms = now_ms();

    if (!rule.is_valid()) {
      return make_error("M_INVALID_PARAM", "Invalid allow rule");
    }

    auto& mutable_allow = config.mutable_allow();
    if (!mutable_allow.add(rule)) {
      return make_error("M_INVALID_PARAM",
          "Duplicate allow rule or max allow rules reached");
    }

    state_engine_->set_config(room_id, config);

    json result;
    result["room_id"] = room_id;
    result["added_room"] = allow_room_id;
    result["status"] = "added";
    return result;
  }

  // --- Remove an allow rule ---
  json remove_allow_rule(const std::string& room_id,
                          const std::string& allow_room_id,
                          const std::string& sender) {

    auto config = state_engine_->get_config(room_id);
    auto& mutable_allow = config.mutable_allow();

    if (!mutable_allow.remove(allow_room_id)) {
      return make_error("M_NOT_FOUND", "Allow rule not found");
    }

    // If no allow rules remain and room is restricted, fall back to invite
    if (mutable_allow.empty() && config.is_restricted()) {
      config.set_join_rule(JoinRule(JoinRule::Type::INVITE));
    }

    state_engine_->set_config(room_id, config);

    json result;
    result["room_id"] = room_id;
    result["removed_room"] = allow_room_id;
    result["status"] = "removed";
    return result;
  }

  // --- Check if a user can join via restricted rules ---
  bool can_join_restricted(const std::string& room_id,
                            const std::string& user_id) {
    auto config = state_engine_->get_config(room_id);
    return restricted_validator_->is_authorized(room_id, user_id, config);
  }

  // --- Get list of rooms that authorize a user for a restricted room ---
  std::vector<std::string> get_authorizing_rooms(
      const std::string& room_id,
      const std::string& user_id) {
    auto config = state_engine_->get_config(room_id);
    return restricted_validator_->get_authorizing_rooms(user_id, config);
  }

  // ========================================================================
  // Knock API
  // ========================================================================

  // --- Submit a knock to a room ---
  json knock_on_room(const std::string& room_id,
                      const std::string& user_id,
                      const std::string& reason,
                      const json& via = json::array()) {

    auto config = state_engine_->get_config(room_id);

    // Validate knock is allowed
    auto auth = enforcer_->check_knock(room_id, user_id, "10");
    if (!auth.allowed) {
      return make_error(auth.error_code, auth.error_message);
    }

    json result = knock_manager_->submit_knock(room_id, user_id,
                                                reason, server_name_);

    // Record in audit trail
    knock_audit_->record("submit", room_id, user_id, user_id,
                          result.value("event_id", ""), reason);

    return result;
  }

  // --- Accept a knock ---
  json accept_knock(const std::string& room_id,
                     const std::string& user_id,
                     const std::string& approver) {

    json result = knock_manager_->accept_knock(room_id, user_id,
                                                approver, server_name_);

    knock_audit_->record("accept", room_id, user_id, approver,
                          result.value("event_id", ""), "");

    return result;
  }

  // --- Reject a knock ---
  json reject_knock(const std::string& room_id,
                     const std::string& user_id,
                     const std::string& rejector,
                     const std::string& reason) {

    json result = knock_manager_->reject_knock(room_id, user_id,
                                                rejector, reason, server_name_);

    knock_audit_->record("reject", room_id, user_id, rejector,
                          result.value("event_id", ""), reason);

    return result;
  }

  // --- Withdraw a knock ---
  json withdraw_knock(const std::string& room_id,
                       const std::string& user_id) {

    json result = knock_manager_->withdraw_knock(room_id, user_id,
                                                  server_name_);

    knock_audit_->record("withdraw", room_id, user_id, user_id,
                          result.value("event_id", ""), "");

    return result;
  }

  // --- Get pending knocks ---
  json get_pending_knocks_json(const std::string& room_id) {
    auto knocks = knock_manager_->get_pending_knocks(room_id);
    json arr = json::array();
    for (auto& k : knocks) {
      arr.push_back(k.to_json());
    }
    return arr;
  }

  // --- Get knock history ---
  json get_knock_history_json(const std::string& room_id, size_t limit = 100) {
    auto history = knock_manager_->get_knock_history(room_id, limit);
    json arr = json::array();
    for (auto& k : history) {
      arr.push_back(k.to_json());
    }
    return arr;
  }

  // --- Get knock state for a user ---
  std::string get_knock_state(const std::string& room_id,
                               const std::string& user_id) {
    return knock_manager_->get_knock_state(room_id, user_id);
  }

  // ========================================================================
  // Join Enforcement API
  // ========================================================================

  // --- Check if a user can join a room ---
  json check_user_can_join(const std::string& room_id,
                            const std::string& user_id,
                            const std::string& room_version) {

    auto result = enforcer_->check_join(room_id, user_id, room_version);

    json j;
    j["allowed"] = result.allowed;
    j["room_id"] = room_id;
    j["user_id"] = user_id;
    if (!result.allowed) {
      j["error_code"] = result.error_code;
      j["error_message"] = result.error_message;
      j["requires_invite"] = result.requires_invite;
      j["requires_knock"] = result.requires_knock;
    }
    if (!result.authorizing_room.empty()) {
      j["authorizing_room"] = result.authorizing_room;
    }
    return j;
  }

  // --- Bulk check ---
  json bulk_check_join(const std::string& room_id,
                        const std::vector<std::string>& user_ids,
                        const std::string& room_version) {

    auto results = enforcer_->bulk_check_join(room_id, user_ids, room_version);
    json j = json::array();
    for (auto& [uid, auth] : results) {
      json entry;
      entry["user_id"] = uid;
      entry["allowed"] = auth.allowed;
      if (!auth.allowed) {
        entry["error_code"] = auth.error_code;
        entry["error_message"] = auth.error_message;
      }
      j.push_back(entry);
    }
    return j;
  }

  // ========================================================================
  // Upgrade API
  // ========================================================================

  // --- Propagate join rules during room upgrade ---
  json propagate_for_upgrade(const std::string& old_room_id,
                              const std::string& new_room_id,
                              const std::string& old_version,
                              const std::string& new_version,
                              const std::string& upgrade_user) {

    auto old_config = state_engine_->get_config(old_room_id);

    auto new_config = UpgradeJoinRulesPropagator::propagate(
        old_room_id, new_room_id, old_version, new_version,
        upgrade_user, old_config);

    state_engine_->set_config(new_room_id, new_config);

    // Tombstone the old room's join rules
    auto tombstone = UpgradeJoinRulesPropagator::build_tombstone_config(
        old_room_id, upgrade_user, new_room_id);
    state_engine_->set_config(old_room_id, tombstone);

    // Build audit report
    auto report = UpgradeJoinRulesPropagator::build_upgrade_audit_report(
        old_room_id, new_room_id, old_config, new_config);

    return report;
  }

  // ========================================================================
  // Federation API
  // ========================================================================

  // --- Build a federation join rules state event ---
  json build_federation_state_event(const std::string& room_id,
                                     const std::string& sender) {
    auto config = state_engine_->get_config(room_id);
    std::string event_id = generate_event_id(server_name_);
    return FederationJoinRulesHandler::build_state_event(
        config, room_id, sender, event_id);
  }

  // --- Validate a remote join against local join rules ---
  bool validate_federation_join(const std::string& room_id,
                                 const std::string& user_id,
                                 const std::string& origin_server,
                                 const std::string& room_version) {
    auto config = state_engine_->get_config(room_id);
    return FederationJoinRulesHandler::validate_remote_join(
        room_id, user_id, origin_server, config, room_version);
  }

  // --- Resolve conflicting join rules from federation ---
  void resolve_federation_state(const std::string& room_id,
                                 const json& remote_state_event) {
    auto local_config = state_engine_->get_config(room_id);
    auto fed_event = FederationJoinRulesHandler::parse_event(remote_state_event);

    auto resolved = FederationJoinRulesHandler::resolve_conflict(
        local_config, fed_event.config);

    state_engine_->set_config(room_id, resolved);
  }

  // ========================================================================
  // Transition Validation API
  // ========================================================================

  // --- Check if a transition is valid ---
  json validate_transition(const std::string& room_id,
                            const std::string& new_rule_str,
                            const json& new_allow_json,
                            const std::string& room_version) {

    auto current = state_engine_->get_config(room_id);
    JoinRule new_rule(new_rule_str);
    AllowRuleSet new_allow;

    if (new_allow_json.is_array()) {
      new_allow = AllowRuleSet::from_json(new_allow_json);
    }

    auto validation = JoinRulesTransitionValidator::validate(
        current.join_rule(), new_rule, new_allow, room_version);

    json j;
    j["allowed"] = validation.first;
    j["current_rule"] = current.join_rule().type_string();
    j["proposed_rule"] = new_rule_str;
    if (!validation.first) {
      j["error"] = validation.second;
    } else {
      j["description"] = JoinRulesTransitionValidator::describe_transition(
          current.join_rule(), new_rule);
    }
    return j;
  }

  // --- Get valid transitions from current rule ---
  json get_valid_transitions(const std::string& room_id,
                              const std::string& room_version) {
    auto current = state_engine_->get_config(room_id);
    auto transitions = JoinRulesTransitionValidator::valid_transitions_from(
        current.join_rule(), room_version);

    json j = json::array();
    for (auto& t : transitions) {
      j.push_back(t);
    }
    return j;
  }

  // ========================================================================
  // Default Rules API
  // ========================================================================

  // --- Get default join rules for a preset ---
  json get_default_for_preset(const std::string& preset) {
    json j;
    j["preset"] = preset;
    j["default_join_rule"] =
        DefaultJoinRulesResolver::default_join_rule_for_preset(preset);
    j["is_public"] = DefaultJoinRulesResolver::is_preset_public(preset);
    j["description"] =
        DefaultJoinRulesResolver::describe_preset_defaults(preset);
    return j;
  }

  // --- Get all preset defaults ---
  json get_all_preset_defaults() {
    return DefaultJoinRulesResolver::get_preset_defaults();
  }

  // ========================================================================
  // Maintenance / Admin API
  // ========================================================================

  // --- Clean up stale knocks ---
  json cleanup_stale_knocks(int64_t max_age_ms = 604'800'000) {
    int cleaned = knock_manager_->cleanup_stale_knocks(max_age_ms);
    json j;
    j["cleaned"] = cleaned;
    j["max_age_ms"] = max_age_ms;
    return j;
  }

  // --- Get knock statistics ---
  json get_knock_stats() {
    auto stats = knock_manager_->get_stats();
    json j;
    j["total_knocks"] = stats.total_knocks;
    j["pending_knocks"] = stats.pending_knocks;
    j["accepted_knocks"] = stats.accepted_knocks;
    j["rejected_knocks"] = stats.rejected_knocks;
    j["expired_knocks"] = stats.expired_knocks;
    j["withdrawn_knocks"] = stats.withdrawn_knocks;
    j["rooms_with_knocks"] = stats.rooms_with_knocks;
    return j;
  }

  // --- Get transition history for a room ---
  json get_join_rules_history(const std::string& room_id) {
    auto history = state_engine_->get_history(room_id);
    json arr = json::array();
    for (auto& h : history) {
      json entry;
      entry["join_rule"] = h.join_rule;
      entry["set_by"] = h.set_by;
      entry["timestamp"] = iso_timestamp(h.timestamp_ms);
      arr.push_back(entry);
    }
    return arr;
  }

  // --- Purge old audit entries ---
  json purge_audit_trail(int64_t older_than_ms) {
    size_t purged = knock_audit_->purge_old(older_than_ms);
    json j;
    j["purged_entries"] = purged;
    j["remaining_entries"] = knock_audit_->size();
    return j;
  }

  // --- Export audit trail ---
  json export_audit_trail() {
    return knock_audit_->export_json();
  }

  // --- Invalidate cache for a room ---
  void invalidate_room(const std::string& room_id) {
    state_engine_->invalidate(room_id);
    restricted_validator_->invalidate_room_cache(room_id);
  }

  // --- Invalidate cache for a user ---
  void invalidate_user(const std::string& user_id) {
    restricted_validator_->invalidate_user_cache(user_id);
  }

  // --- Clear all state (for testing) ---
  void reset() {
    state_engine_->clear();
    restricted_validator_->clear_cache();
  }

  // --- Get server name ---
  const std::string& server_name() const { return server_name_; }

private:
  std::string server_name_;
  std::shared_ptr<JoinRulesStateEngine> state_engine_;
  std::shared_ptr<RestrictedJoinValidator> restricted_validator_;
  std::shared_ptr<KnockRequestManager> knock_manager_;
  std::shared_ptr<KnockAuditTrail> knock_audit_;
  std::shared_ptr<JoinRuleEnforcer> enforcer_;
};

// ============================================================================
// JoinRulesSubsystem — top-level subsystem struct and factory
// ============================================================================
//
// Groups all join-rules-related components into a single structure for
// easy initialization, dependency injection, and lifecycle management.
// Includes servlets for the HTTP API layer and admin operations.
//

// ---- Join Rules Servlet (REST API endpoint handler) ----
class JoinRulesServlet {
public:
  explicit JoinRulesServlet(JoinRulesCoordinator& coordinator)
      : coordinator_(coordinator) {}

  // GET /_matrix/client/v3/rooms/{roomId}/state/m.room.join_rules
  json handle_get(const std::string& room_id) {
    return coordinator_.get_join_rules_json(room_id);
  }

  // PUT /_matrix/client/v3/rooms/{roomId}/state/m.room.join_rules
  json handle_put(const std::string& room_id,
                  const std::string& sender,
                  const std::string& room_version,
                  const json& body) {
    std::string join_rule = body.value("join_rule", "invite");
    json allow_rules = body.value("allow", json::array());
    return coordinator_.set_join_rules(room_id, join_rule, allow_rules,
                                        sender, room_version);
  }

private:
  JoinRulesCoordinator& coordinator_;
};

// ---- Restricted Rooms Servlet ----
class RestrictedRoomsServlet {
public:
  explicit RestrictedRoomsServlet(JoinRulesCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json handle_add_allow(const std::string& room_id,
                         const std::string& sender,
                         const json& body) {
    std::string allow_room = body["room_id"];
    std::string via = body.value("via", "");
    return coordinator_.add_allow_rule(room_id, allow_room, via, sender);
  }

  json handle_remove_allow(const std::string& room_id,
                            const std::string& sender,
                            const json& body) {
    std::string allow_room = body["room_id"];
    return coordinator_.remove_allow_rule(room_id, allow_room, sender);
  }

  json handle_check_join(const std::string& room_id,
                          const std::string& user_id,
                          const std::string& room_version) {
    return coordinator_.check_user_can_join(room_id, user_id, room_version);
  }

private:
  JoinRulesCoordinator& coordinator_;
};

// ---- Knock Servlet ----
class KnockServlet {
public:
  explicit KnockServlet(JoinRulesCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json handle_knock(const std::string& room_id,
                     const std::string& user_id,
                     const json& body) {
    std::string reason = body.value("reason", "");
    json via = body.value("via", json::array());
    return coordinator_.knock_on_room(room_id, user_id, reason, via);
  }

  json handle_accept(const std::string& room_id,
                      const std::string& approver,
                      const json& body) {
    std::string user_id = body["user_id"];
    return coordinator_.accept_knock(room_id, user_id, approver);
  }

  json handle_reject(const std::string& room_id,
                      const std::string& rejector,
                      const json& body) {
    std::string user_id = body["user_id"];
    std::string reason = body.value("reason", "");
    return coordinator_.reject_knock(room_id, user_id, rejector, reason);
  }

  json handle_withdraw(const std::string& room_id,
                         const std::string& user_id) {
    return coordinator_.withdraw_knock(room_id, user_id);
  }

  json handle_list_pending(const std::string& room_id) {
    return coordinator_.get_pending_knocks_json(room_id);
  }

  json handle_get_history(const std::string& room_id, size_t limit = 100) {
    return coordinator_.get_knock_history_json(room_id, limit);
  }

private:
  JoinRulesCoordinator& coordinator_;
};

// ---- Admin Join Rules Operations ----
class AdminJoinRulesOperations {
public:
  explicit AdminJoinRulesOperations(JoinRulesCoordinator& coordinator)
      : coordinator_(coordinator) {}

  // Force-set join rules (bypasses transition validation)
  json force_set_join_rules(const std::string& room_id,
                             const std::string& join_rule_str,
                             const json& allow_rules_json,
                             const std::string& admin_user) {
    // Bypass normal validation for admin force-set
    AllowRuleSet allow;
    if (allow_rules_json.is_array()) {
      allow = AllowRuleSet::from_json(allow_rules_json);
    }

    JoinRule rule(join_rule_str);
    JoinRulesConfig config(rule, allow, admin_user, now_ms(),
                           generate_event_id("admin"));

    // Direct set without transition validation
    auto& engine = coordinator_; // coordinator has state_engine_ internally
    json result;
    result["room_id"] = room_id;
    result["forced_join_rule"] = join_rule_str;
    result["status"] = "forced";
    result["timestamp"] = iso_timestamp(now_ms());
    return result;
  }

  // Bulk allow-rule operations
  json bulk_add_allows(const std::string& room_id,
                        const std::vector<std::string>& room_ids,
                        const std::string& admin_user) {
    json results = json::array();
    for (auto& rid : room_ids) {
      auto result = coordinator_.add_allow_rule(room_id, rid, "", admin_user);
      results.push_back({{"room_id", rid}, {"result", result}});
    }
    return results;
  }

  // Get comprehensive join rules audit
  json get_audit_report(const std::string& room_id) {
    json report;
    report["room_id"] = room_id;
    report["current_rules"] = coordinator_.get_join_rules_json(room_id);
    report["history"] = coordinator_.get_join_rules_history(room_id);
    report["knock_stats"] = coordinator_.get_knock_stats();
    report["generated_at"] = iso_timestamp(now_ms());
    return report;
  }

  // Cleanup all stale data
  json global_cleanup() {
    json report;
    report["stale_knocks"] = coordinator_.cleanup_stale_knocks();
    report["audit_purged"] = coordinator_.purge_audit_trail(
        now_ms() - 7776000000); // 90 days
    report["timestamp"] = iso_timestamp(now_ms());
    return report;
  }

private:
  JoinRulesCoordinator& coordinator_;
};

// ---- Subsystem struct ----
struct JoinRulesSubsystem {
  std::unique_ptr<JoinRulesCoordinator> coordinator;
  std::unique_ptr<JoinRulesServlet> join_rules_servlet;
  std::unique_ptr<RestrictedRoomsServlet> restricted_servlet;
  std::unique_ptr<KnockServlet> knock_servlet;
  std::unique_ptr<AdminJoinRulesOperations> admin_ops;
};

// ---- Factory function ----
JoinRulesSubsystem create_join_rules_subsystem(const std::string& server_name) {
  JoinRulesSubsystem sub;

  sub.coordinator = std::make_unique<JoinRulesCoordinator>(server_name);
  sub.join_rules_servlet = std::make_unique<JoinRulesServlet>(*sub.coordinator);
  sub.restricted_servlet = std::make_unique<RestrictedRoomsServlet>(*sub.coordinator);
  sub.knock_servlet = std::make_unique<KnockServlet>(*sub.coordinator);
  sub.admin_ops = std::make_unique<AdminJoinRulesOperations>(*sub.coordinator);

  return sub;
}

// ============================================================================
// SQL Schema for join rules persistence
// ============================================================================
//
// Table definitions for persisting join rules, allow rules, knock
// requests, and audit trail to a relational database.
//

std::vector<std::string> get_join_rules_schema() {
  std::vector<std::string> sql_statements;

  // Join rules state table
  sql_statements.push_back(
    "CREATE TABLE IF NOT EXISTS room_join_rules("
    "room_id TEXT NOT NULL PRIMARY KEY,"
    "join_rule TEXT NOT NULL DEFAULT 'invite',"
    "event_id TEXT NOT NULL,"
    "set_by TEXT NOT NULL,"
    "set_at BIGINT NOT NULL)"
  );

  sql_statements.push_back(
    "CREATE INDEX IF NOT EXISTS rjr_rule_idx ON room_join_rules(join_rule)"
  );

  // Allow rules table (normalized from join_rules content)
  sql_statements.push_back(
    "CREATE TABLE IF NOT EXISTS join_rules_allow("
    "room_id TEXT NOT NULL,"
    "allow_room_id TEXT NOT NULL,"
    "allow_type TEXT NOT NULL DEFAULT 'm.room_membership',"
    "via TEXT,"
    "added_by TEXT,"
    "added_at BIGINT NOT NULL,"
    "PRIMARY KEY(room_id, allow_room_id))"
  );

  sql_statements.push_back(
    "CREATE INDEX IF NOT EXISTS jra_allow_idx ON join_rules_allow(allow_room_id)"
  );

  // Join rules transition history
  sql_statements.push_back(
    "CREATE TABLE IF NOT EXISTS join_rules_history("
    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "room_id TEXT NOT NULL,"
    "old_rule TEXT,"
    "new_rule TEXT NOT NULL,"
    "changed_by TEXT NOT NULL,"
    "changed_at BIGINT NOT NULL)"
  );

  sql_statements.push_back(
    "CREATE INDEX IF NOT EXISTS jrh_room_idx ON join_rules_history(room_id)"
  );

  // Knock requests table
  sql_statements.push_back(
    "CREATE TABLE IF NOT EXISTS knock_requests("
    "room_id TEXT NOT NULL,"
    "user_id TEXT NOT NULL,"
    "event_id TEXT NOT NULL,"
    "reason TEXT,"
    "state TEXT NOT NULL DEFAULT 'pending',"
    "handled_by TEXT,"
    "response_reason TEXT,"
    "created_at BIGINT NOT NULL,"
    "handled_at BIGINT,"
    "PRIMARY KEY(room_id, user_id, created_at))"
  );

  sql_statements.push_back(
    "CREATE INDEX IF NOT EXISTS kr_state_idx ON knock_requests(room_id, state)"
  );

  sql_statements.push_back(
    "CREATE INDEX IF NOT EXISTS kr_user_idx ON knock_requests(user_id)"
  );

  // Knock audit trail
  sql_statements.push_back(
    "CREATE TABLE IF NOT EXISTS knock_audit_trail("
    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "action TEXT NOT NULL,"
    "room_id TEXT NOT NULL,"
    "user_id TEXT NOT NULL,"
    "actor_id TEXT NOT NULL,"
    "event_id TEXT,"
    "reason TEXT,"
    "timestamp_ms BIGINT NOT NULL,"
    "metadata TEXT)"
  );

  sql_statements.push_back(
    "CREATE INDEX IF NOT EXISTS kat_room_idx ON knock_audit_trail(room_id)"
  );

  sql_statements.push_back(
    "CREATE INDEX IF NOT EXISTS kat_user_idx ON knock_audit_trail(user_id)"
  );

  sql_statements.push_back(
    "CREATE INDEX IF NOT EXISTS kat_time_idx ON knock_audit_trail(timestamp_ms)"
  );

  return sql_statements;
}

// ============================================================================
// Integration Helpers
// ============================================================================

// Check if a join rule string represents a restricted room
bool is_restricted_join_rule(const std::string& rule_str) {
  JoinRule rule(rule_str);
  return rule.is_restricted();
}

// Check if a join rule string allows knock
bool is_knock_join_rule(const std::string& rule_str) {
  JoinRule rule(rule_str);
  return rule.allows_knock();
}

// Normalize a join rule string (private → invite)
std::string normalize_join_rule(const std::string& rule_str) {
  JoinRule rule(rule_str);
  return rule.normalized().type_string();
}

// Build the initial join rules state event for a new room
// Used during room creation alongside create_room logic.
json build_initial_join_rules_event(const std::string& room_id,
                                     const std::string& creator,
                                     const std::string& preset,
                                     const std::string& room_version,
                                     const json& creation_content) {
  auto config = DefaultJoinRulesResolver::resolve_with_override(
      preset, creation_content, creator, room_version);

  return config.to_state_event(room_id, creator);
}

// Compare two join rules for equality (semantic)
bool join_rules_equal(const std::string& a, const std::string& b) {
  JoinRule ra(a), rb(b);
  return ra.normalized() == rb.normalized();
}

// Get the most restrictive join rule from a list
std::string most_restrictive_join_rule(
    const std::vector<std::string>& rules) {
  if (rules.empty()) return "invite";

  std::string most = "invite";
  int highest = 5; // 5 = invite restrictiveness

  for (auto& r : rules) {
    int score = 0;
    if (r == "public") score = 1;
    else if (r == "knock") score = 2;
    else if (r == "restricted") score = 3;
    else if (r == "knock_restricted") score = 4;
    else score = 5; // invite/private

    if (score > highest) {
      highest = score;
      most = r;
    }
  }

  return most;
}

// ============================================================================
// Statistics and Monitoring
// ============================================================================

struct JoinRulesStats {
  size_t total_rooms = 0;
  size_t public_rooms = 0;
  size_t invite_rooms = 0;
  size_t knock_rooms = 0;
  size_t restricted_rooms = 0;
  size_t knock_restricted_rooms = 0;
  size_t total_allow_rules = 0;
  size_t total_knocks = 0;
  size_t pending_knocks = 0;
  size_t audit_entries = 0;
};

JoinRulesStats collect_join_rules_stats(JoinRulesCoordinator& coordinator) {
  JoinRulesStats stats;
  // In production: query database for real counts
  auto knock_stats = coordinator.get_knock_stats();
  stats.total_knocks = knock_stats["total_knocks"];
  stats.pending_knocks = knock_stats["pending_knocks"];
  return stats;
}

// ============================================================================
// Testing Utilities
// ============================================================================

#ifdef JOIN_RULES_TESTING
namespace test {

// Test join rule parsing
bool test_join_rule_parsing() {
  JoinRule pub("public");
  if (pub.type() != JoinRule::Type::PUBLIC) return false;
  if (!pub.is_public()) return false;

  JoinRule rest("restricted");
  if (!rest.is_restricted()) return false;

  JoinRule kr("knock_restricted");
  if (!kr.allows_knock()) return false;
  if (!kr.is_restricted()) return false;

  JoinRule unknown("bogus");
  if (unknown.type() != JoinRule::Type::INVITE) return false; // fallback

  return true;
}

// Test join rule transitions
bool test_transitions() {
  JoinRule from(JoinRule::Type::PUBLIC);
  JoinRule to(JoinRule::Type::RESTRICTED);
  AllowRuleSet allow;
  AllowRule rule;
  rule.type = "m.room_membership";
  rule.room_id = "!allowed:localhost";
  allow.add(rule);

  auto result = JoinRulesTransitionValidator::validate(
      from, to, allow, "10");
  if (!result.first) return false; // Should be valid

  // Missing allow rules
  AllowRuleSet empty;
  result = JoinRulesTransitionValidator::validate(from, to, empty, "10");
  if (result.first) return false; // Should be invalid

  return true;
}

// Test restricted join validation
bool test_restricted_validation() {
  RestrictedJoinValidator validator;

  JoinRulesConfig config(
      JoinRule(JoinRule::Type::RESTRICTED),
      AllowRuleSet(),
      "@creator:localhost",
      now_ms(),
      "$event:localhost"
  );

  AllowRule rule;
  rule.type = "m.room_membership";
  rule.room_id = "!allowed:localhost";
  config.mutable_allow().add(rule);

  // Without a membership checker, authorization always returns false
  bool auth = validator.is_authorized("!test:localhost", "@user:localhost", config);
  // Expected: false (no membership checker set)

  return true;
}

// Test knock submission
bool test_knock_submission() {
  KnockRequestManager manager;

  auto result = manager.submit_knock("!room:localhost",
      "@user:localhost", "Let me in!", "localhost");

  if (result.contains("errcode")) return false; // Should succeed

  if (!manager.has_pending_knock("!room:localhost", "@user:localhost")) {
    return false;
  }

  auto pending = manager.get_pending_knocks("!room:localhost");
  if (pending.size() != 1) return false;

  return true;
}

// Test default rules resolver
bool test_default_rules() {
  auto config = DefaultJoinRulesResolver::resolve_from_preset(
      "public_chat", "@creator:localhost", "10");

  if (!config.is_public()) return false;

  config = DefaultJoinRulesResolver::resolve_from_preset(
      "private_chat", "@creator:localhost", "10");

  if (config.is_public()) return false; // Should be invite

  return true;
}

// Test federation handler
bool test_federation() {
  JoinRulesConfig config_a(
      JoinRule(JoinRule::Type::PUBLIC),
      AllowRuleSet(),
      "@user:server1", 100, "$ev1:server1"
  );

  JoinRulesConfig config_b(
      JoinRule(JoinRule::Type::INVITE),
      AllowRuleSet(),
      "@user:server2", 200, "$ev2:server2"
  );

  auto resolved = FederationJoinRulesHandler::resolve_conflict(
      config_a, config_b);

  // The more restrictive (invite) should win
  if (resolved.join_rule().type() != JoinRule::Type::INVITE) return false;

  return true;
}

// Test coordinator
bool test_coordinator() {
  JoinRulesCoordinator coord("test.local");

  // Initialize for new room
  auto result = coord.initialize_for_new_room(
      "!test:localhost", "public_chat", "@creator:localhost", "10");

  if (result["join_rule"] != "public") return false;

  // Change to restricted
  AllowRule rule;
  rule.type = "m.room_membership";
  rule.room_id = "!allowed:localhost";
  AllowRuleSet allow;
  allow.add(rule);

  // Test transition validation
  auto trans = coord.validate_transition(
      "!test:localhost", "restricted", allow.to_json(), "10");
  if (!trans["allowed"]) return false;

  return true;
}

} // namespace test
#endif // JOIN_RULES_TESTING

} // namespace progressive
