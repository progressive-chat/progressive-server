// membership_lazy_loading.cpp - Matrix Room Membership, Lazy Loading, and Hero Computation
// Implements complete room membership management (invite, join, leave, ban, kick, knock),
// membership state transitions, lazy loading member computation, hero selection algorithm,
// hero ordering, room name from heroes, room avatar from member avatars, join rule
// enforcement, guest access enforcement, server ACL enforcement, power level enforcement
// for membership changes, membership event federation, membership history,
// room summary computation, notification count for membership events,
// and membership rate limiting.
//
// Target: 3500+ lines
//
// Based on Synapse:
//   synapse/handlers/room_member.py
//   synapse/handlers/room_member_worker.py
//   synapse/api/lazyloading.py
//   synapse/visibility.py
//   synapse/events/utils.py
//
// Handlers:
//   1.  handle_membership_invite      - POST /rooms/{roomId}/invite (lazy-load aware)
//   2.  handle_membership_join        - POST /join/{roomIdOrAlias} (lazy-load aware)
//   3.  handle_membership_leave       - POST /rooms/{roomId}/leave
//   4.  handle_membership_ban         - POST /rooms/{roomId}/ban
//   5.  handle_membership_kick        - POST /rooms/{roomId}/kick
//   6.  handle_membership_knock       - POST /knock/{roomIdOrAlias}
//   7.  handle_membership_unban       - POST /rooms/{roomId}/unban
//   8.  compute_lazy_loaded_members   - Compute which members to include for a user
//   9.  select_room_heroes            - Hero selection for lazy loading
//  10.  order_heroes                  - Hero ordering (joined first, active, alpha)
//  11.  room_name_from_heroes         - Generate room name from hero list
//  12.  room_avatar_from_members      - Generate room avatar from member avatars
//  13.  enforce_join_rules            - Join rule validation for membership
//  14.  enforce_guest_access          - Guest access check for membership
//  15.  enforce_server_acl            - Server ACL check for membership
//  16.  enforce_power_level           - Power level check for membership change
//  17.  federate_membership_event     - Push membership events to federation
//  18.  get_membership_history        - Retrieve membership history for a room
//  19.  compute_membership_summary    - Room summary with member counts
//  20.  compute_notification_for_membership - Notification count for membership
//  21.  check_membership_rate_limit   - Rate limiting for membership operations
//  22.  validate_membership_transition - Validate state transition (leave->join, etc.)
//  23.  handle_membership_event_incoming - Process incoming membership from federation
//  24.  compute_room_summary_from_members - Full room summary from members
//  25.  lazy_load_member_filter       - Filter members for lazy-loaded sync

#include "../json.hpp"
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/event_federation.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/presence.hpp"

#include <chrono>
#include <random>
#include <sstream>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <map>
#include <regex>
#include <cmath>
#include <thread>
#include <cctype>
#include <functional>
#include <shared_mutex>
#include <optional>
#include <deque>
#include <numeric>
#include <string_view>
#include <tuple>

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;

// ============================================================================
// Global state for membership lazy loading
// ============================================================================

static std::mutex g_membership_lock;
static std::mutex g_rate_limit_lock;
static std::mutex g_hero_cache_lock;
static std::mutex g_federation_push_lock;
static std::mutex g_membership_history_lock;
static std::atomic<int64_t> g_membership_seq{1};
static std::atomic<int64_t> g_membership_event_count{0};
static std::atomic<int64_t> g_lazy_load_computations{0};
static std::atomic<int64_t> g_hero_selections{0};
static std::atomic<int64_t> g_rate_limit_hits{0};

// ============================================================================
// Utility helpers (local to this compilation unit)
// ============================================================================

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_id(const std::string& prefix) {
  static std::atomic<int64_t> local_seq{1};
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(local_seq.fetch_add(1));
}

static std::string gen_token(int len = 32) {
  static const char cs[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(
    static_cast<unsigned>(now_ms() + std::hash<std::thread::id>{}(std::this_thread::get_id())));
  std::uniform_int_distribution<> d(0, 61);
  std::string t(len, 'A');
  for (auto& c : t) c = cs[d(rng)];
  return t;
}

static std::string safe_str(const json& obj, const std::string& key,
                             const std::string& def = "") {
  if (!obj.contains(key)) return def;
  if (obj[key].is_string()) return obj[key].get<std::string>();
  return def;
}

static int64_t safe_int(const json& obj, const std::string& key,
                         int64_t def = 0) {
  if (!obj.contains(key)) return def;
  if (obj[key].is_number()) return obj[key].get<int64_t>();
  return def;
}

static bool safe_bool(const json& obj, const std::string& key, bool def = false) {
  if (!obj.contains(key)) return def;
  if (obj[key].is_boolean()) return obj[key].get<bool>();
  return def;
}

static bool validate_user_id(const std::string& user_id) {
  return user_id.size() >= 4 && user_id[0] == '@' &&
         user_id.find(':') != std::string::npos;
}

static bool validate_room_id(const std::string& room_id) {
  return room_id.size() >= 2 && room_id[0] == '!' &&
         room_id.find(':') != std::string::npos;
}

static bool validate_room_alias(const std::string& alias) {
  return alias.size() >= 2 && alias[0] == '#' &&
         alias.find(':') != std::string::npos;
}

static std::string sql_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 4);
  for (char c : s) {
    if (c == '\'')
      out += "''";
    else
      out += c;
  }
  return out;
}

static std::string extract_localpart(const std::string& user_id) {
  if (user_id.empty() || user_id[0] != '@') return user_id;
  auto pos = user_id.find(':');
  if (pos == std::string::npos) return user_id.substr(1);
  return user_id.substr(1, pos - 1);
}

static std::string extract_domain(const std::string& mxid) {
  auto pos = mxid.find(':');
  if (pos == std::string::npos) return "";
  return mxid.substr(pos + 1);
}

// ============================================================================
// Auth context validation (shared with other membership handlers)
// ============================================================================

struct AuthContext {
  std::string user_id;
  std::string device_id;
  std::string access_token;
  bool is_guest = false;
  bool is_admin = false;
  bool valid = false;
};

static AuthContext validate_auth(DatabasePool& db, const std::string& auth_header,
                                  const std::string& query_access_token) {
  AuthContext ctx;
  std::string token;

  if (!auth_header.empty()) {
    const std::string prefix = "Bearer ";
    if (auth_header.size() > prefix.size() &&
        auth_header.substr(0, prefix.size()) == prefix) {
      token = auth_header.substr(prefix.size());
    }
  }
  if (token.empty() && !query_access_token.empty()) {
    token = query_access_token;
  }
  if (token.empty()) {
    return ctx;
  }

  RegistrationStore reg(db);
  auto user_info = reg.get_user_by_access_token(token);
  if (!user_info) {
    return ctx;
  }

  ctx.valid = true;
  ctx.user_id = user_info->user_id;
  ctx.access_token = token;
  if (user_info->device_id) ctx.device_id = *user_info->device_id;
  ctx.is_guest = user_info->is_guest;
  ctx.is_admin = user_info->is_admin;
  return ctx;
}

static json make_error(int http_status, const std::string& errcode,
                        const std::string& error) {
  json resp;
  resp["status"] = http_status;
  resp["body"] = json{{"errcode", errcode}, {"error", error}};
  return resp;
}

static json make_response(int http_status, const json& body) {
  json resp;
  resp["status"] = http_status;
  resp["body"] = body;
  return resp;
}

// ============================================================================
// MembershipState - Represents a full membership state at a point in time
// ============================================================================

enum class MembershipState {
  UNKNOWN,
  LEAVE,
  INVITE,
  JOIN,
  KNOCK,
  BAN
};

static std::string membership_state_str(MembershipState s) {
  switch (s) {
    case MembershipState::UNKNOWN: return "unknown";
    case MembershipState::LEAVE:   return "leave";
    case MembershipState::INVITE:  return "invite";
    case MembershipState::JOIN:    return "join";
    case MembershipState::KNOCK:   return "knock";
    case MembershipState::BAN:     return "ban";
  }
  return "unknown";
}

static MembershipState membership_state_from_str(const std::string& s) {
  if (s == "join")   return MembershipState::JOIN;
  if (s == "leave")  return MembershipState::LEAVE;
  if (s == "invite") return MembershipState::INVITE;
  if (s == "ban")    return MembershipState::BAN;
  if (s == "knock")  return MembershipState::KNOCK;
  return MembershipState::UNKNOWN;
}

static std::string get_membership_cached(DatabasePool& db,
    const std::string& room_id, const std::string& user_id) {
  RoomMemberStore members(db);
  auto m = members.get_member(room_id, user_id);
  if (m) return m->membership;
  return "leave";
}

static bool is_user_in_room(DatabasePool& db, const std::string& room_id,
                              const std::string& user_id) {
  auto m = get_membership_cached(db, room_id, user_id);
  return m == "join";
}

// ============================================================================
// MembershipTransition - Validates and describes allowed state changes
// ============================================================================

struct MembershipTransition {
  MembershipState from_state;
  MembershipState to_state;
  bool is_allowed;
  std::string reason_if_blocked;

  // Canonical state transition matrix
  // Source: Synapse synapse/api/constants.py EventContentFields
  //         and synapse/handlers/room_member.py _local_membership_update
  static MembershipTransition validate(
      MembershipState current, MembershipState target,
      bool is_targeting_self, bool has_power_to_invite,
      bool has_power_to_kick, bool has_power_to_ban,
      bool is_server_admin) {

    MembershipTransition result;
    result.from_state = current;
    result.to_state = target;
    result.is_allowed = false;

    // --- BAN -> anything: only server admin or user with ban power can unban ---
    if (current == MembershipState::BAN) {
      if (target == MembershipState::LEAVE) {
        result.is_allowed = (has_power_to_ban || is_server_admin);
        if (!result.is_allowed) result.reason_if_blocked = "Cannot unban without ban power";
      } else {
        result.reason_if_blocked = "Cannot transition from ban state";
      }
      return result;
    }

    // --- JOIN -> anything ---
    if (current == MembershipState::JOIN) {
      if (target == MembershipState::LEAVE) {
        result.is_allowed = true; // Anyone can leave
      } else if (target == MembershipState::BAN) {
        result.is_allowed = (has_power_to_ban || is_server_admin);
        if (!result.is_allowed) result.reason_if_blocked = "No ban permission";
      } else if (target == MembershipState::JOIN) {
        result.is_allowed = true; // Idempotent
      } else if (target == MembershipState::INVITE) {
        result.reason_if_blocked = "Already joined, cannot invite again";
      } else if (target == MembershipState::KNOCK) {
        result.reason_if_blocked = "Already joined, cannot knock";
      }
      return result;
    }

    // --- LEAVE -> anything ---
    if (current == MembershipState::LEAVE) {
      if (target == MembershipState::JOIN) {
        result.is_allowed = true; // Anyone can join (subject to rules)
      } else if (target == MembershipState::INVITE) {
        result.is_allowed = (has_power_to_invite || is_server_admin);
        if (!result.is_allowed) result.reason_if_blocked = "No invite permission";
      } else if (target == MembershipState::KNOCK) {
        result.is_allowed = true; // Anyone can knock
      } else if (target == MembershipState::BAN) {
        result.is_allowed = (has_power_to_ban || is_server_admin);
        if (!result.is_allowed) result.reason_if_blocked = "No ban permission";
      } else if (target == MembershipState::LEAVE) {
        result.is_allowed = true; // Idempotent
      }
      return result;
    }

    // --- INVITE -> anything ---
    if (current == MembershipState::INVITE) {
      if (target == MembershipState::JOIN) {
        result.is_allowed = is_targeting_self; // Only invited user can accept
        if (!result.is_allowed) result.reason_if_blocked = "Only the invited user can accept";
      } else if (target == MembershipState::LEAVE) {
        result.is_allowed = is_targeting_self; // Only invited user can reject
        if (!result.is_allowed) result.reason_if_blocked = "Only the invited user can reject";
      } else if (target == MembershipState::BAN) {
        result.is_allowed = (has_power_to_ban || is_server_admin);
        if (!result.is_allowed) result.reason_if_blocked = "No ban permission";
      } else if (target == MembershipState::KNOCK) {
        result.reason_if_blocked = "Already invited, cannot knock";
      }
      return result;
    }

    // --- KNOCK -> anything ---
    if (current == MembershipState::KNOCK) {
      if (target == MembershipState::JOIN) {
        result.is_allowed = is_targeting_self;
        if (!result.is_allowed) result.reason_if_blocked = "Only the knocking user can join";
      } else if (target == MembershipState::LEAVE) {
        result.is_allowed = is_targeting_self;
        if (!result.is_allowed) result.reason_if_blocked = "Only the knocking user can withdraw";
      } else if (target == MembershipState::INVITE) {
        result.is_allowed = (has_power_to_invite || is_server_admin);
        if (!result.is_allowed) result.reason_if_blocked = "No invite permission";
      } else if (target == MembershipState::BAN) {
        result.is_allowed = (has_power_to_ban || is_server_admin);
        if (!result.is_allowed) result.reason_if_blocked = "No ban permission";
      }
      return result;
    }

    result.reason_if_blocked = "Unknown state transition";
    return result;
  }
};

// ============================================================================
// Power level helpers
// ============================================================================

static int64_t get_user_power_level(DatabasePool& db, const std::string& room_id,
                                      const std::string& user_id) {
  StateStore state(db);
  auto pl_event = state.get_current_state_event(room_id, "m.room.power_levels", "");
  if (!pl_event) return (user_id.empty() ? 0 : 0);

  EventsStore evs(db);
  auto ev = evs.get_event(*pl_event);
  if (!ev) return 0;

  auto& content = (*ev)["content"];
  int64_t default_level = content.value("users_default", 0);

  if (content.contains("users") && content["users"].contains(user_id)) {
    return content["users"][user_id].get<int64_t>();
  }
  return default_level;
}

static int64_t get_required_power_level(DatabasePool& db,
    const std::string& room_id, const std::string& action) {
  StateStore state(db);
  auto pl_event = state.get_current_state_event(room_id, "m.room.power_levels", "");

  int64_t required = 50;
  if (!pl_event) return required;

  EventsStore evs(db);
  auto ev = evs.get_event(*pl_event);
  if (!ev || !(*ev).contains("content")) return required;

  auto& content = (*ev)["content"];
  if (action == "invite") required = content.value("invite", 0);
  else if (action == "kick") required = content.value("kick", 50);
  else if (action == "ban") required = content.value("ban", 50);
  else if (action == "redact") required = content.value("redact", 50);
  else if (action == "state_default") required = content.value("state_default", 50);
  else if (action == "events_default") required = content.value("events_default", 0);
  else if (action == "notifications.room")
    required = content.value("notifications", json::object()).value("room", 50);
  return required;
}

static bool has_power_to(DatabasePool& db, const std::string& room_id,
                           const std::string& user_id, const std::string& action) {
  int64_t user_pl = get_user_power_level(db, room_id, user_id);
  int64_t required = get_required_power_level(db, room_id, action);
  return user_pl >= required;
}

// ============================================================================
// Join rules helpers
// ============================================================================

static std::string get_join_rule(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto jr_event = state.get_current_state_event(room_id, "m.room.join_rules", "");
  if (!jr_event) return "invite";

  EventsStore evs(db);
  auto ev = evs.get_event(*jr_event);
  if (!ev) return "invite";

  return (*ev)["content"].value("join_rule", "invite");
}

static std::string get_guest_access(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto ga_event = state.get_current_state_event(room_id, "m.room.guest_access", "");
  if (!ga_event) return "forbidden";

  EventsStore evs(db);
  auto ev = evs.get_event(*ga_event);
  if (!ev) return "forbidden";

  return (*ev)["content"].value("guest_access", "forbidden");
}

// ============================================================================
// 15. Server ACL enforcement
// ============================================================================

struct ServerAclResult {
  bool allowed;
  std::string reason;
};

static ServerAclResult check_server_acl(DatabasePool& db, const std::string& room_id,
                                          const std::string& server_name) {
  ServerAclResult result;
  result.allowed = true;

  StateStore state(db);
  auto acl_event = state.get_current_state_event(room_id, "m.room.server_acl", "");
  if (!acl_event) return result; // No ACL = allow all

  EventsStore evs(db);
  auto ev = evs.get_event(*acl_event);
  if (!ev) return result;

  auto& content = (*ev)["content"];

  // Check if IP literals are allowed
  bool allow_ip_literals = content.value("allow_ip_literals", true);
  if (!allow_ip_literals) {
    // Check if server_name looks like an IP address
    bool is_ip = false;
    struct in_addr ipv4;
    struct in6_addr ipv6;
    if (inet_pton(AF_INET, server_name.c_str(), &ipv4) == 1) is_ip = true;
    if (inet_pton(AF_INET6, server_name.c_str(), &ipv6) == 1) is_ip = true;
    if (is_ip) {
      result.allowed = false;
      result.reason = "IP literal server names not allowed by ACL";
      return result;
    }
  }

  // Check deny list
  if (content.contains("deny") && content["deny"].is_array()) {
    for (auto& rule : content["deny"]) {
      std::string pattern = rule.value("pattern", "");
      if (!pattern.empty()) {
        try {
          std::regex re(pattern, std::regex::icase);
          if (std::regex_match(server_name, re)) {
            result.allowed = false;
            result.reason = "Server '" + server_name + "' denied by ACL pattern: " + pattern;
            return result;
          }
        } catch (const std::regex_error&) {
          // Simple glob-style matching fallback
          if (server_name.find(pattern) != std::string::npos ||
              pattern == "*") {
            result.allowed = false;
            result.reason = "Server '" + server_name + "' denied by ACL pattern: " + pattern;
            return result;
          }
        }
      }
    }
  }

  // Check allow list (if non-empty, deny by default)
  if (content.contains("allow") && content["allow"].is_array() &&
      !content["allow"].empty()) {
    for (auto& rule : content["allow"]) {
      std::string pattern = rule.value("pattern", "");
      if (!pattern.empty()) {
        try {
          std::regex re(pattern, std::regex::icase);
          if (std::regex_match(server_name, re)) {
            return result; // Allowed
          }
        } catch (const std::regex_error&) {
          if (server_name.find(pattern) != std::string::npos ||
              pattern == "*") {
            return result; // Allowed
          }
        }
      }
    }
    // Not in allow list
    result.allowed = false;
    result.reason = "Server '" + server_name + "' not in allowed ACL list";
  }

  return result;
}

static ServerAclResult check_user_acl(DatabasePool& db, const std::string& room_id,
                                        const std::string& user_id) {
  std::string server = extract_domain(user_id);
  return check_server_acl(db, room_id, server);
}

// ============================================================================
// 14. Join rule enforcement
// ============================================================================

struct JoinRuleCheck {
  bool can_join;
  std::string reason;
};

static JoinRuleCheck check_join_rules(DatabasePool& db, const std::string& room_id,
                                       const std::string& user_id,
                                       const std::string& current_membership) {
  JoinRuleCheck result;
  result.can_join = false;

  std::string join_rule = get_join_rule(db, room_id);

  if (join_rule == "public") {
    result.can_join = true;
    return result;
  }

  if (join_rule == "invite") {
    if (current_membership == "invite") {
      result.can_join = true;
    } else {
      result.reason = "You are not invited to this room";
    }
    return result;
  }

  if (join_rule == "knock") {
    if (current_membership == "invite") {
      result.can_join = true;
    } else if (current_membership == "knock") {
      result.reason = "Your knock has not been accepted yet";
    } else {
      result.reason = "This room requires knocking. Use /knock endpoint first.";
    }
    return result;
  }

  if (join_rule == "restricted") {
    if (current_membership == "invite") {
      result.can_join = true;
      return result;
    }
    // Check if user is in an allowed room
    StateStore state(db);
    auto jr_ev_id = state.get_current_state_event(room_id, "m.room.join_rules", "");
    if (jr_ev_id) {
      EventsStore evs(db);
      auto jr_ev = evs.get_event(*jr_ev_id);
      if (jr_ev && (*jr_ev)["content"].contains("allow")) {
        for (auto& allow_rule : (*jr_ev)["content"]["allow"]) {
          std::string allow_type = allow_rule.value("type", "");
          if (allow_type == "m.room_membership") {
            std::string allow_room = allow_rule.value("room_id", "");
            if (!allow_room.empty() && is_user_in_room(db, allow_room, user_id)) {
              result.can_join = true;
              return result;
            }
          }
        }
      }
    }
    result.reason = "You are not allowed to join this restricted room";
    return result;
  }

  if (join_rule == "private") {
    if (current_membership == "invite") {
      result.can_join = true;
    } else {
      result.reason = "This is a private room";
    }
    return result;
  }

  result.reason = "Unknown join rule: " + join_rule;
  return result;
}

// ============================================================================
// 13. Guest access enforcement
// ============================================================================

struct GuestAccessCheck {
  bool allowed;
  std::string reason;
};

static GuestAccessCheck check_guest_access(DatabasePool& db, const std::string& room_id,
                                             bool is_guest, const std::string& action) {
  GuestAccessCheck result;
  result.allowed = true;

  if (!is_guest) return result;

  std::string access = get_guest_access(db, room_id);

  if (action == "join" || action == "knock") {
    if (access != "can_join") {
      result.allowed = false;
      result.reason = "Guest access not allowed in this room";
    }
  } else if (action == "invite" || action == "kick" || action == "ban") {
    result.allowed = false;
    result.reason = "Guest users cannot perform membership changes on others";
  }

  return result;
}

// ============================================================================
// 16. Power level enforcement for membership changes
// ============================================================================

struct PowerLevelCheck {
  bool has_power;
  std::string reason;
};

static PowerLevelCheck check_power_for_membership_action(
    DatabasePool& db, const std::string& room_id, const std::string& user_id,
    const std::string& action, const std::string& target_user_id = "") {

  PowerLevelCheck result;
  result.has_power = false;

  if (user_id.empty()) {
    result.reason = "No user provided";
    return result;
  }

  int64_t user_pl = get_user_power_level(db, room_id, user_id);

  // Server admins always have power
  RegistrationStore reg(db);
  auto user_info = reg.get_user_by_id(user_id);
  bool is_admin = user_info && user_info->is_admin;
  if (is_admin) {
    result.has_power = true;
    return result;
  }

  // For self-actions like join/leave/knock, always allowed
  if (action == "join" && user_id == target_user_id) {
    result.has_power = true;
    return result;
  }
  if (action == "leave" && user_id == target_user_id) {
    result.has_power = true;
    return result;
  }
  if (action == "knock" && user_id == target_user_id) {
    result.has_power = true;
    return result;
  }

  // Check power level requirements
  int64_t required = get_required_power_level(db, room_id, action);

  // Special case: users can always kick/ban users with lower power level
  if ((action == "kick" || action == "ban") && !target_user_id.empty()) {
    int64_t target_pl = get_user_power_level(db, room_id, target_user_id);
    if (target_pl >= user_pl) {
      result.reason = "Cannot " + action + " a user with equal or higher power level";
      return result;
    }
  }

  if (user_pl >= required) {
    result.has_power = true;
    return result;
  }

  result.reason = "Insufficient power level for '" + action +
                  "' (need " + std::to_string(required) +
                  ", have " + std::to_string(user_pl) + ")";
  return result;
}

// ============================================================================
// Event building helpers
// ============================================================================

struct BuiltMembershipEvent {
  std::string event_id;
  std::string room_id;
  std::string sender;
  std::string target_user_id;
  std::string membership;
  json content;
  int64_t origin_server_ts;
  int64_t stream_ordering;
  int64_t depth;
  std::vector<std::string> prev_events;
  std::vector<std::string> auth_events;
  std::string room_version;
  std::optional<std::string> reason;
};

static BuiltMembershipEvent build_membership_event(
    DatabasePool& db, const std::string& room_id, const std::string& sender,
    const std::string& target_user_id, const std::string& membership,
    const json& extra_content = json::object(),
    std::optional<std::string> reason = std::nullopt) {

  BuiltMembershipEvent ev;
  ev.event_id = gen_id("$mem");
  ev.room_id = room_id;
  ev.sender = sender;
  ev.target_user_id = target_user_id;
  ev.membership = membership;
  ev.origin_server_ts = now_ms();
  ev.stream_ordering = now_ms();
  ev.room_version = "1";
  ev.reason = reason;

  // Build content
  ev.content = extra_content;
  ev.content["membership"] = membership;

  if (reason) {
    ev.content["reason"] = *reason;
  }

  // Add display name and avatar from profile
  ProfileStore profile(db);
  auto display_name = profile.get_display_name(sender);
  if (display_name && !display_name->empty()) {
    ev.content["displayname"] = *display_name;
  }
  auto avatar_url = profile.get_avatar_url(sender);
  if (avatar_url && !avatar_url->empty()) {
    ev.content["avatar_url"] = *avatar_url;
  }

  // Compute depth and prev_events
  EventFederationWorkerStore fed(db);
  auto info = fed.get_room_federation_info(room_id);
  ev.depth = info.event_count + 1;
  for (auto& ext : info.forward_extremities) {
    ev.prev_events.push_back(ext);
  }

  // Build auth events
  StateStore state(db);
  auto current = state.get_current_state(room_id);
  for (auto& [key, eid] : current) {
    if (key.first == "m.room.create" || key.first == "m.room.power_levels" ||
        key.first == "m.room.join_rules" || key.first == "m.room.member") {
      ev.auth_events.push_back(eid);
    }
  }

  return ev;
}

// ============================================================================
// Persistence helper
// ============================================================================

static void persist_membership_event(DatabasePool& db,
                                      const BuiltMembershipEvent& ev) {
  auto txn = db.cursor("persist_membership_event");
  if (!txn) return;

  // Build event JSON
  json event_json;
  event_json["event_id"] = ev.event_id;
  event_json["room_id"] = ev.room_id;
  event_json["sender"] = ev.sender;
  event_json["type"] = "m.room.member";
  event_json["state_key"] = ev.target_user_id;
  event_json["content"] = ev.content;
  event_json["origin_server_ts"] = ev.origin_server_ts;
  event_json["stream_ordering"] = ev.stream_ordering;
  event_json["depth"] = ev.depth;
  event_json["prev_events"] = ev.prev_events;
  event_json["auth_events"] = ev.auth_events;

  std::string json_str = event_json.dump();

  // Insert into events table
  std::string sql = "INSERT OR REPLACE INTO events "
                    "(event_id, room_id, sender, type, state_key, json, "
                    "stream_ordering, origin_server_ts, depth, outlier, instance_name) "
                    "VALUES (?,?,?,?,?,?,?,?,?,0,'master')";
  txn->execute(sql, {ev.event_id, ev.room_id, ev.sender,
                     "m.room.member", ev.target_user_id, json_str,
                     std::to_string(ev.stream_ordering),
                     std::to_string(ev.origin_server_ts),
                     std::to_string(ev.depth)});

  // Update current state
  std::string state_sql = "INSERT OR REPLACE INTO current_state_events "
                          "(room_id, type, state_key, event_id) VALUES (?,?,?,?)";
  txn->execute(state_sql, {ev.room_id, "m.room.member", ev.target_user_id, ev.event_id});

  // Update room membership table
  RoomMemberStore members(db);
  members.update_membership(ev.room_id, ev.target_user_id, ev.sender,
                            ev.membership, ev.event_id, ev.stream_ordering);

  // Update stream ordering
  std::string stream_sql = "UPDATE stream_ordering SET stream_id = ?";
  txn->execute(stream_sql, {std::to_string(ev.stream_ordering)});

  txn->commit();

  g_membership_event_count.fetch_add(1);
}

// ============================================================================
// 17. Federation push helper
// ============================================================================

static std::vector<std::string> get_room_participating_servers(
    DatabasePool& db, const std::string& room_id) {
  std::vector<std::string> servers;
  RoomMemberStore members(db);
  auto all_members = members.get_joined_members(room_id);
  std::set<std::string> seen;
  seen.insert("localhost"); // Don't push to self
  for (auto& m : all_members) {
    std::string server = extract_domain(m.user_id);
    if (!server.empty() && seen.insert(server).second) {
      servers.push_back(server);
    }
  }
  return servers;
}

static void federate_membership_event(DatabasePool& db,
                                       const BuiltMembershipEvent& ev) {
  std::lock_guard<std::mutex> lock(g_federation_push_lock);

  auto servers = get_room_participating_servers(db, ev.room_id);

  // Also federate to the target user's server if different
  std::string target_server = extract_domain(ev.target_user_id);
  if (!target_server.empty() && target_server != "localhost") {
    bool found = false;
    for (auto& s : servers) {
      if (s == target_server) { found = true; break; }
    }
    if (!found) servers.push_back(target_server);
  }

  for (auto& dest : servers) {
    json pdu;
    pdu["event_id"] = ev.event_id;
    pdu["room_id"] = ev.room_id;
    pdu["sender"] = ev.sender;
    pdu["type"] = "m.room.member";
    pdu["state_key"] = ev.target_user_id;
    pdu["content"] = ev.content;
    pdu["origin_server_ts"] = ev.origin_server_ts;
    pdu["depth"] = ev.depth;
    pdu["prev_events"] = ev.prev_events;
    pdu["auth_events"] = ev.auth_events;
    pdu["origin"] = "localhost";

    std::string fed_sql = "INSERT OR REPLACE INTO federation_stream "
                          "(type, room_id, event_id, destination, json_data, stream_id) "
                          "VALUES ('pdu',?,?,?,?,?)";
    auto txn = db.cursor("fed_push_membership");
    if (txn) {
      txn->execute(fed_sql, {ev.room_id, ev.event_id, dest, pdu.dump(),
                              std::to_string(now_ms())});
      txn->commit();
    }
  }
}

// ============================================================================
// 21. Membership rate limiting
// ============================================================================

struct RateLimitBucket {
  std::deque<int64_t> timestamps;
  int64_t window_ms;
  int max_events;

  bool allow(int64_t now) {
    // Remove old entries
    while (!timestamps.empty() && (now - timestamps.front()) > window_ms) {
      timestamps.pop_front();
    }
    if (static_cast<int>(timestamps.size()) >= max_events) {
      return false;
    }
    timestamps.push_back(now);
    return true;
  }

  int64_t retry_after_ms(int64_t now) const {
    if (timestamps.empty()) return 0;
    return window_ms - (now - timestamps.front());
  }
};

static std::mutex g_rl_mutex;
static std::unordered_map<std::string, RateLimitBucket> g_membership_rate_limits;

struct RateLimitConfig {
  int64_t invite_window_ms = 60000;    // 1 minute
  int max_invites = 20;
  int64_t join_window_ms = 30000;      // 30 seconds
  int max_joins = 30;
  int64_t leave_window_ms = 30000;
  int max_leaves = 30;
  int64_t kick_window_ms = 60000;
  int max_kicks = 20;
  int64_t ban_window_ms = 60000;
  int max_bans = 20;
  int64_t knock_window_ms = 60000;
  int max_knocks = 20;
};

static RateLimitConfig g_rate_config;

static bool check_membership_rate_limit(const std::string& user_id,
                                         const std::string& action) {
  std::lock_guard<std::mutex> lock(g_rl_mutex);

  std::string key = user_id + ":" + action;
  auto& bucket = g_membership_rate_limits[key];

  int64_t window = 60000;
  int max_events = 20;

  if (action == "invite") { window = g_rate_config.invite_window_ms; max_events = g_rate_config.max_invites; }
  else if (action == "join") { window = g_rate_config.join_window_ms; max_events = g_rate_config.max_joins; }
  else if (action == "leave") { window = g_rate_config.leave_window_ms; max_events = g_rate_config.max_leaves; }
  else if (action == "kick") { window = g_rate_config.kick_window_ms; max_events = g_rate_config.max_kicks; }
  else if (action == "ban") { window = g_rate_config.ban_window_ms; max_events = g_rate_config.max_bans; }
  else if (action == "knock") { window = g_rate_config.knock_window_ms; max_events = g_rate_config.max_knocks; }

  bucket.window_ms = window;
  bucket.max_events = max_events;

  int64_t now = now_ms();
  bool allowed = bucket.allow(now);

  if (!allowed) {
    g_rate_limit_hits.fetch_add(1);
  }

  return allowed;
}

// ============================================================================
// HeroEntry - Display information for a single room hero
// ============================================================================

struct HeroEntry {
  std::string user_id;
  std::string display_name;
  std::string avatar_url;
  int64_t join_order{0};
  int64_t last_active_ts{0};
  bool currently_active{false};
  std::string membership;

  bool operator==(const HeroEntry& other) const {
    return user_id == other.user_id;
  }

  json to_json() const {
    json j;
    j["user_id"] = user_id;
    if (!display_name.empty()) j["display_name"] = display_name;
    if (!avatar_url.empty()) j["avatar_url"] = avatar_url;
    return j;
  }
};

// ============================================================================
// LazyLoadingContext - Configuration for lazy loading decisions
// ============================================================================

struct LazyLoadingContext {
  bool lazy_load_members{false};
  bool include_redundant_members{false};
  std::string filter_spec;
  int max_heroes{5};
  std::unordered_set<std::string> excluded_user_ids;
  std::unordered_set<std::string> required_user_ids;

  static LazyLoadingContext from_sync_filter(const json& filter) {
    LazyLoadingContext ctx;
    if (filter.contains("lazy_load_members")) {
      ctx.lazy_load_members = filter["lazy_load_members"].get<bool>();
    }
    if (filter.contains("include_redundant_members")) {
      ctx.include_redundant_members = filter["include_redundant_members"].get<bool>();
    }
    if (filter.contains("filter_spec") && filter["filter_spec"].is_string()) {
      ctx.filter_spec = filter["filter_spec"].get<std::string>();
    }
    return ctx;
  }
};

// ============================================================================
// LazyLoadedMember - Single member entry for lazy-loaded sync responses
// ============================================================================

struct LazyLoadedMember {
  std::string user_id;
  std::string display_name;
  std::string avatar_url;
  std::string membership;
  int64_t event_stream_ordering{0};
  int64_t origin_server_ts{0};

  json to_json() const {
    json j;
    j["user_id"] = user_id;
    if (!display_name.empty()) j["display_name"] = display_name;
    if (!avatar_url.empty()) j["avatar_url"] = avatar_url;
    j["membership"] = membership;
    return j;
  }
};

// ============================================================================
// MembershipSummary - Aggregated room membership summary
// ============================================================================

struct MembershipSummary {
  std::string room_id;
  int joined_member_count{0};
  int invited_member_count{0};
  int banned_member_count{0};
  int knocked_member_count{0};
  int left_member_count{0};
  int total_member_count{0};
  std::vector<HeroEntry> heroes;
  std::string computed_room_name;
  std::string computed_room_avatar;
  std::string join_rule;
  bool world_readable{false};
  bool guests_can_join{false};
  bool encrypted{false};
  std::string room_type;
  std::string creator;
  std::string canonical_alias;
  std::string topic;
  int64_t last_activity_ts{0};
  int notification_count{0};
  int highlight_count{0};

  json to_json() const {
    json j;
    j["room_id"] = room_id;
    j["m.joined_member_count"] = joined_member_count;
    j["m.invited_member_count"] = invited_member_count;
    if (!computed_room_name.empty()) j["name"] = computed_room_name;
    if (!computed_room_avatar.empty()) j["avatar_url"] = computed_room_avatar;
    if (!canonical_alias.empty()) j["canonical_alias"] = canonical_alias;
    if (!topic.empty()) j["topic"] = topic;
    if (!heroes.empty()) {
      json hero_arr = json::array();
      for (const auto& h : heroes) {
        hero_arr.push_back(h.to_json());
      }
      j["m.heroes"] = hero_arr;
      j["heroes"] = hero_arr;
    }
    if (!join_rule.empty()) j["join_rule"] = join_rule;
    if (world_readable) j["world_readable"] = true;
    if (guests_can_join) j["guest_can_join"] = true;
    if (encrypted) j["encryption"] = "m.megolm.v1.aes-sha2";
    if (!room_type.empty()) j["room_type"] = room_type;
    if (!creator.empty()) j["creator"] = creator;
    if (last_activity_ts > 0) j["last_activity_ts"] = last_activity_ts;
    j["notification_count"] = notification_count;
    j["highlight_count"] = highlight_count;
    return j;
  }
};

// ============================================================================
// MembershipEngine - Core membership management and lazy loading engine
// ============================================================================

class MembershipEngine {
public:
  explicit MembershipEngine(DatabasePool& db)
      : db_(db) {}

  // ========================================================================
  // 7. Lazy loading member computation
  // ========================================================================

  std::vector<LazyLoadedMember> compute_lazy_loaded_members(
      const std::string& room_id, const std::string& viewer_user_id,
      const LazyLoadingContext& context) {

    g_lazy_load_computations.fetch_add(1);

    std::vector<LazyLoadedMember> result;
    std::unordered_set<std::string> included_users;

    // Step 1: Always include the viewer
    if (!viewer_user_id.empty() && included_users.insert(viewer_user_id).second) {
      auto member = load_single_member(room_id, viewer_user_id);
      if (member) result.push_back(*member);
    }

    // Step 2: Include explicitly required users
    for (const auto& uid : context.required_user_ids) {
      if (included_users.insert(uid).second) {
        auto member = load_single_member(room_id, uid);
        if (member) result.push_back(*member);
      }
    }

    // Step 3: Include heroes (the core lazy-load set)
    auto heroes = select_heroes(room_id, viewer_user_id, context.max_heroes);
    for (const auto& hero : heroes) {
      if (included_users.insert(hero.user_id).second) {
        LazyLoadedMember member;
        member.user_id = hero.user_id;
        member.display_name = hero.display_name;
        member.avatar_url = hero.avatar_url;
        member.membership = "join";

        auto m = load_single_member(room_id, hero.user_id);
        if (m) {
          member.membership = m->membership;
          member.event_stream_ordering = m->event_stream_ordering;
        }
        result.push_back(member);
      }
    }

    // Step 4: Include recently active senders (last N events)
    auto recent_senders = get_recent_active_senders(room_id, 10);
    for (const auto& uid : recent_senders) {
      if (included_users.insert(uid).second) {
        auto member = load_single_member(room_id, uid);
        if (member) result.push_back(*member);
      }
    }

    // Step 5: If include_redundant_members is set, include all members
    // Otherwise, for non-lazy-load, include all members (traditional sync behavior)
    if (context.include_redundant_members || !context.lazy_load_members) {
      if (!context.lazy_load_members) {
        // Full sync: include all members
        auto all_members = load_all_members(room_id);
        for (const auto& m : all_members) {
          if (included_users.insert(m.user_id).second) {
            result.push_back(m);
          }
        }
      }
    }

    return result;
  }

  // ========================================================================
  // 25. Lazy load member filter
  // ========================================================================

  std::vector<LazyLoadedMember> lazy_load_member_filter(
      const std::vector<LazyLoadedMember>& all_members,
      const std::string& viewer_user_id,
      const LazyLoadingContext& context,
      const std::string& room_id) {

    if (!context.lazy_load_members) {
      return all_members;
    }

    std::vector<LazyLoadedMember> result;
    std::unordered_set<std::string> included;

    // Always include the viewer
    for (const auto& m : all_members) {
      if (m.user_id == viewer_user_id) {
        result.push_back(m);
        included.insert(m.user_id);
        break;
      }
    }

    // Include heroes
    auto heroes = select_heroes(room_id, viewer_user_id, context.max_heroes);
    for (const auto& hero : heroes) {
      if (included.count(hero.user_id)) continue;
      for (const auto& m : all_members) {
        if (m.user_id == hero.user_id) {
          result.push_back(m);
          included.insert(m.user_id);
          break;
        }
      }
    }

    // Include required user IDs
    for (const auto& uid : context.required_user_ids) {
      if (included.count(uid)) continue;
      for (const auto& m : all_members) {
        if (m.user_id == uid) {
          result.push_back(m);
          included.insert(m.user_id);
          break;
        }
      }
    }

    // Include remaining if include_redundant_members is set
    if (context.include_redundant_members) {
      for (const auto& m : all_members) {
        if (!included.count(m.user_id)) {
          result.push_back(m);
        }
      }
    }

    return result;
  }

  // ========================================================================
  // 9. Hero selection algorithm
  // ========================================================================

  std::vector<HeroEntry> select_heroes(const std::string& room_id,
                                        const std::string& viewer_user_id,
                                        int count = 5,
                                        bool include_leaving = false) {
    g_hero_selections.fetch_add(1);

    std::vector<HeroEntry> all_heroes;
    auto members = load_members_detailed(room_id);

    for (const auto& m : members) {
      std::string uid = safe_str(m, "user_id", "");
      if (uid.empty()) continue;

      bool is_leaving = (safe_str(m, "membership", "join") != "join");
      if (is_leaving && !include_leaving) {
        // Only include if viewer
        if (uid != viewer_user_id) continue;
      }

      HeroEntry hero;
      hero.user_id = uid;
      hero.display_name = get_display_name(uid);
      hero.avatar_url = get_avatar_url(uid);
      hero.join_order = safe_int(m, "stream_ordering", 0);
      hero.membership = safe_str(m, "membership", "join");
      hero.last_active_ts = get_last_active_ts(room_id, uid);
      hero.currently_active = (now_ms() - hero.last_active_ts) < 300000;

      all_heroes.push_back(hero);
    }

    // Sort heroes using the hero ordering algorithm
    order_heroes_in_place(all_heroes);

    // Select top `count` heroes
    std::vector<HeroEntry> result;
    std::unordered_set<std::string> seen;

    for (const auto& h : all_heroes) {
      if (static_cast<int>(result.size()) >= count) break;
      if (seen.insert(h.user_id).second) {
        result.push_back(h);
      }
    }

    // Ensure viewer is included if specified
    if (!viewer_user_id.empty() && !seen.count(viewer_user_id)) {
      for (const auto& h : all_heroes) {
        if (h.user_id == viewer_user_id) {
          if (!result.empty()) {
            result.back() = h;
          } else {
            result.push_back(h);
          }
          break;
        }
      }
    }

    return result;
  }

  // ========================================================================
  // 10. Hero ordering (joined first, active, alphabetical)
  // ========================================================================

  void order_heroes_in_place(std::vector<HeroEntry>& heroes) {
    std::sort(heroes.begin(), heroes.end(),
              [](const HeroEntry& a, const HeroEntry& b) {
                // Priority 1: Joined members before non-joined
                bool a_joined = (a.membership == "join");
                bool b_joined = (b.membership == "join");
                if (a_joined != b_joined) return a_joined > b_joined;

                // Priority 2: Earlier joiners first (lower join_order)
                if (a.join_order != b.join_order)
                  return a.join_order < b.join_order;

                // Priority 3: Currently active first
                if (a.currently_active != b.currently_active)
                  return a.currently_active > b.currently_active;

                // Priority 4: Recently active first
                if (a.last_active_ts != b.last_active_ts)
                  return a.last_active_ts > b.last_active_ts;

                // Priority 5: Alphabetical by display name
                std::string na = a.display_name.empty() ?
                    extract_localpart(a.user_id) : a.display_name;
                std::string nb = b.display_name.empty() ?
                    extract_localpart(b.user_id) : b.display_name;
                std::transform(na.begin(), na.end(), na.begin(), ::tolower);
                std::transform(nb.begin(), nb.end(), nb.begin(), ::tolower);
                return na < nb;
              });
  }

  std::vector<HeroEntry> order_heroes(const std::vector<HeroEntry>& heroes) {
    std::vector<HeroEntry> result = heroes;
    order_heroes_in_place(result);
    return result;
  }

  // ========================================================================
  // 11. Room name from heroes
  // ========================================================================

  std::string room_name_from_heroes(const std::vector<HeroEntry>& heroes,
                                      const std::string& viewer_user_id) {
    std::vector<HeroEntry> filtered;
    for (const auto& h : heroes) {
      if (h.user_id != viewer_user_id) {
        filtered.push_back(h);
      }
    }

    size_t count = filtered.size();

    if (count == 0) {
      return "Empty Room";
    }

    if (count == 1) {
      std::string dn = filtered[0].display_name;
      if (dn.empty()) dn = extract_localpart(filtered[0].user_id);
      return dn;
    }

    if (count == 2) {
      std::string dn1 = filtered[0].display_name;
      if (dn1.empty()) dn1 = extract_localpart(filtered[0].user_id);
      std::string dn2 = filtered[1].display_name;
      if (dn2.empty()) dn2 = extract_localpart(filtered[1].user_id);
      return dn1 + " and " + dn2;
    }

    // 3+ members: "A, B and N others"
    std::string dn1 = filtered[0].display_name;
    if (dn1.empty()) dn1 = extract_localpart(filtered[0].user_id);
    std::string dn2 = filtered[1].display_name;
    if (dn2.empty()) dn2 = extract_localpart(filtered[1].user_id);

    int remaining = static_cast<int>(count) - 2;
    return dn1 + ", " + dn2 + " and " + std::to_string(remaining) + " others";
  }

  // ========================================================================
  // Room name fallback algorithms for various scenarios
  // ========================================================================

  std::string compute_room_name_from_canonical_alias(const std::string& room_id) {
    StateStore state(db_);
    auto alias_ev = state.get_current_state_event(room_id, "m.room.canonical_alias", "");
    if (!alias_ev) return "";

    EventsStore evs(db_);
    auto ev = evs.get_event(*alias_ev);
    if (!ev) return "";

    return (*ev)["content"].value("alias", "");
  }

  std::string compute_room_name_empty(const std::string& viewer_user_id) {
    if (viewer_user_id.empty()) return "Empty Room";
    std::string lp = extract_localpart(viewer_user_id);
    return lp + " (Empty Room)";
  }

  std::string room_name_fallback(const std::string& room_id,
                                   const std::string& viewer_user_id) {
    int count = get_joined_member_count(room_id);
    if (count == 0) return compute_room_name_empty(viewer_user_id);
    return "Room " + room_id.substr(0, 12) + "...";
  }

  // ========================================================================
  // 12. Room avatar from member avatars
  // ========================================================================

  std::string room_avatar_from_members(const std::string& room_id) {
    // Check m.room.avatar state event first
    StateStore state(db_);
    auto avatar_ev_id = state.get_current_state_event(room_id, "m.room.avatar", "");
    if (avatar_ev_id) {
      EventsStore evs(db_);
      auto ev = evs.get_event(*avatar_ev_id);
      if (ev) {
        std::string url = (*ev)["content"].value("url", "");
        if (!url.empty()) return url;
      }
    }

    // Fallback: use first hero's avatar
    auto heroes = select_heroes(room_id, "", 3);
    if (!heroes.empty() && !heroes[0].avatar_url.empty()) {
      return heroes[0].avatar_url;
    }

    // Generate default avatar from room name
    std::string name = compute_room_name_fallback(room_id);
    return generate_default_avatar(name);
  }

  std::string room_avatar_from_member_list(const std::vector<HeroEntry>& heroes) {
    if (heroes.empty()) return "";

    // Use the first joined member's avatar
    for (const auto& h : heroes) {
      if (h.membership == "join" && !h.avatar_url.empty()) {
        return h.avatar_url;
      }
    }

    // Fallback to any hero's avatar
    if (!heroes[0].avatar_url.empty()) {
      return heroes[0].avatar_url;
    }

    return generate_default_avatar(heroes[0].display_name);
  }

  std::string generate_default_avatar(const std::string& name) {
    size_t hash = std::hash<std::string>{}(name);
    const char* colors[] = {
      "#e53935", "#d81b60", "#8e24aa", "#5e35b1", "#3949ab",
      "#1e88e5", "#039be5", "#00acc1", "#00897b", "#43a047",
      "#7cb342", "#c0ca33", "#fdd835", "#ffb300", "#fb8c00",
      "#f4511e", "#6d4c41", "#757575", "#546e7a"
    };
    std::string bg = colors[hash % 19];

    std::string letter;
    if (!name.empty()) {
      for (char c : name) {
        if (std::isalnum(static_cast<unsigned char>(c))) {
          letter = std::string(1, static_cast<char>(std::toupper(c)));
          break;
        }
      }
    }
    if (letter.empty()) letter = "#";

    return "data:image/svg+xml,"
           "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
           "<rect fill='" + bg + "' width='100' height='100' rx='15'/>"
           "<text fill='white' font-size='50' font-weight='bold' "
           "x='50' y='68' text-anchor='middle' font-family='sans-serif'>" +
           letter + "</text></svg>";
  }

  // ========================================================================
  // 24. Room summary computation from members
  // ========================================================================

  MembershipSummary compute_membership_summary(
      const std::string& room_id, const std::string& viewer_user_id = "") {

    MembershipSummary summary;
    summary.room_id = room_id;

    // Load all state events needed
    json create_event = load_state_event(room_id, "m.room.create", "");
    json name_event = load_state_event(room_id, "m.room.name", "");
    json topic_event = load_state_event(room_id, "m.room.topic", "");
    json jr_event = load_state_event(room_id, "m.room.join_rules", "");
    json ga_event = load_state_event(room_id, "m.room.guest_access", "");
    json enc_event = load_state_event(room_id, "m.room.encryption", "");
    json hv_event = load_state_event(room_id, "m.room.history_visibility", "");
    json alias_event = load_state_event(room_id, "m.room.canonical_alias", "");

    // Room type and creator from create event
    if (!create_event.empty()) {
      summary.room_type = safe_str(create_event, "type", "");
      summary.creator = safe_str(create_event, "creator", "");
    }

    // Room name computation
    if (!name_event.empty()) {
      summary.computed_room_name = safe_str(name_event, "name", "");
      if (summary.computed_room_name.empty() &&
          name_event.contains("content") && name_event["content"].is_object()) {
        summary.computed_room_name = safe_str(name_event["content"], "name", "");
      }
    }
    if (summary.computed_room_name.empty()) {
      // Try canonical alias
      if (!alias_event.empty()) {
        summary.canonical_alias = safe_str(alias_event, "alias", "");
        if (!summary.canonical_alias.empty()) {
          summary.computed_room_name = summary.canonical_alias;
        }
      }
    }
    if (summary.computed_room_name.empty()) {
      // Compute from heroes
      auto heroes = select_heroes(room_id, viewer_user_id, 5);
      summary.computed_room_name = room_name_from_heroes(heroes, viewer_user_id);
    }

    // Topic
    if (!topic_event.empty()) {
      summary.topic = safe_str(topic_event, "topic", "");
      if (summary.topic.empty() &&
          topic_event.contains("content") && topic_event["content"].is_object()) {
        summary.topic = safe_str(topic_event["content"], "topic", "");
      }
    }

    // Avatar
    summary.computed_room_avatar = room_avatar_from_members(room_id);

    // Join rule
    if (!jr_event.empty()) {
      summary.join_rule = safe_str(jr_event, "join_rule", "public");
      if (summary.join_rule.empty() &&
          jr_event.contains("content") && jr_event["content"].is_object()) {
        summary.join_rule = safe_str(jr_event["content"], "join_rule", "public");
      }
    }

    // Guest access
    if (!ga_event.empty()) {
      std::string ga = safe_str(ga_event, "guest_access", "");
      if (ga.empty() && ga_event.contains("content")) {
        ga = safe_str(ga_event["content"], "guest_access", "forbidden");
      }
      summary.guests_can_join = (ga == "can_join");
    }

    // History visibility / world readable
    if (!hv_event.empty()) {
      std::string hv = safe_str(hv_event, "history_visibility", "shared");
      if (hv.empty() && hv_event.contains("content")) {
        hv = safe_str(hv_event["content"], "history_visibility", "shared");
      }
      summary.world_readable = (hv == "world_readable");
    }

    // Encryption
    if (!enc_event.empty()) {
      std::string algo = safe_str(enc_event, "algorithm", "");
      if (algo.empty() && enc_event.contains("content")) {
        algo = safe_str(enc_event["content"], "algorithm", "");
      }
      summary.encrypted = !algo.empty();
    }

    // Member counts
    summary.joined_member_count = get_joined_member_count(room_id);
    summary.invited_member_count = get_invited_member_count(room_id);
    summary.banned_member_count = get_banned_member_count(room_id);
    summary.knocked_member_count = get_knocked_member_count(room_id);
    summary.left_member_count = 0; // Not commonly tracked
    summary.total_member_count = summary.joined_member_count +
                                  summary.invited_member_count +
                                  summary.banned_member_count +
                                  summary.knocked_member_count;

    // Heroes
    summary.heroes = select_heroes(room_id, viewer_user_id, 5);

    // Last activity
    summary.last_activity_ts = get_last_room_activity_ts(room_id);

    // Notification counts
    if (!viewer_user_id.empty()) {
      auto counts = get_unread_counts(room_id, viewer_user_id);
      summary.notification_count = safe_int(counts, "notification_count");
      summary.highlight_count = safe_int(counts, "highlight_count");
    }

    return summary;
  }

  // ========================================================================
  // 18. Membership history
  // ========================================================================

  std::vector<json> get_membership_history(const std::string& room_id,
                                            const std::string& user_id,
                                            int limit = 100) {
    std::lock_guard<std::mutex> lock(g_membership_history_lock);

    auto rows = db_.execute(
        "get_membership_history",
        "SELECT event_id, sender, type, state_key, content, origin_server_ts, "
        "stream_ordering, depth FROM events "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "AND type='m.room.member' AND state_key='" + sql_escape(user_id) + "' "
        "ORDER BY depth DESC LIMIT " + std::to_string(limit));

    std::vector<json> history;
    history.reserve(rows.size());

    for (const auto& row : rows) {
      json ev;
      for (const auto& col : row) {
        if (col.name == "event_id" && col.value)
          ev["event_id"] = *col.value;
        else if (col.name == "sender" && col.value)
          ev["sender"] = *col.value;
        else if (col.name == "type" && col.value)
          ev["type"] = *col.value;
        else if (col.name == "state_key" && col.value)
          ev["state_key"] = *col.value;
        else if (col.name == "origin_server_ts" && col.value)
          ev["origin_server_ts"] = *col.value;
        else if (col.name == "depth" && col.value) {
          try { ev["depth"] = std::stoll(*col.value); } catch (...) {}
        }
        else if (col.name == "content" && col.value) {
          try {
            ev["content"] = json::parse(*col.value);
          } catch (...) {
            ev["content"] = json::object();
          }
        }
      }
      if (ev.contains("event_id")) {
        history.push_back(ev);
      }
    }

    return history;
  }

  std::vector<json> get_full_membership_history(const std::string& room_id,
                                                  int limit = 500) {
    auto rows = db_.execute(
        "get_full_membership_history",
        "SELECT event_id, sender, type, state_key, content, origin_server_ts, "
        "depth FROM events "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "AND type='m.room.member' "
        "ORDER BY depth DESC LIMIT " + std::to_string(limit));

    std::vector<json> history;
    history.reserve(rows.size());

    for (const auto& row : rows) {
      json ev;
      for (const auto& col : row) {
        if (col.name == "event_id" && col.value)
          ev["event_id"] = *col.value;
        else if (col.name == "sender" && col.value)
          ev["sender"] = *col.value;
        else if (col.name == "state_key" && col.value)
          ev["state_key"] = *col.value;
        else if (col.name == "origin_server_ts" && col.value)
          ev["origin_server_ts"] = *col.value;
        else if (col.name == "content" && col.value) {
          try { ev["content"] = json::parse(*col.value); }
          catch (...) { ev["content"] = json::object(); }
        }
      }
      if (ev.contains("event_id")) {
        history.push_back(ev);
      }
    }

    return history;
  }

  // ========================================================================
  // 23. Handle incoming membership event from federation
  // ========================================================================

  struct IncomingMembershipResult {
    bool accepted;
    std::string event_id;
    std::string reason;
    json state_resolution;
  };

  IncomingMembershipResult handle_incoming_membership_event(
      const json& event, const std::string& origin_server) {

    IncomingMembershipResult result;
    result.accepted = false;

    std::string event_id = safe_str(event, "event_id", "");
    std::string room_id = safe_str(event, "room_id", "");
    std::string sender = safe_str(event, "sender", "");
    std::string state_key = safe_str(event, "state_key", "");
    json content = event.value("content", json::object());
    std::string membership = safe_str(content, "membership", "");

    if (event_id.empty() || room_id.empty() || sender.empty() ||
        state_key.empty() || membership.empty()) {
      result.reason = "Invalid event: missing required fields";
      return result;
    }

    // Check server ACL for the origin server
    auto acl = check_server_acl(db_, room_id, origin_server);
    if (!acl.allowed) {
      result.reason = "Server ACL denied: " + acl.reason;
      return result;
    }

    // Check power levels for the membership change
    if (sender != state_key) {
      auto pl = check_power_for_membership_action(
          db_, room_id, sender, membership, state_key);
      if (!pl.has_power) {
        result.reason = "Power level insufficient: " + pl.reason;
        return result;
      }
    }

    // Check membership transition
    std::string current_membership = get_membership_cached(db_, room_id, state_key);
    MembershipState current = membership_state_from_str(current_membership);
    MembershipState target = membership_state_from_str(membership);

    auto sender_info = get_user_info(sender);
    bool is_admin = sender_info && sender_info->is_admin;
    bool is_targeting_self = (sender == state_key);

    auto transition = MembershipTransition::validate(
        current, target, is_targeting_self,
        has_power_to(db_, room_id, sender, "invite"),
        has_power_to(db_, room_id, sender, "kick"),
        has_power_to(db_, room_id, sender, "ban"),
        is_admin);

    if (!transition.is_allowed) {
      result.reason = "Invalid transition: " + transition.reason_if_blocked;
      return result;
    }

    // Build and persist the event
    BuiltMembershipEvent built;
    built.event_id = event_id;
    built.room_id = room_id;
    built.sender = sender;
    built.target_user_id = state_key;
    built.membership = membership;
    built.content = content;
    built.origin_server_ts = safe_int(event, "origin_server_ts", now_ms());
    built.stream_ordering = now_ms();
    built.depth = safe_int(event, "depth", 1);
    built.room_version = "1";

    if (event.contains("prev_events") && event["prev_events"].is_array()) {
      for (auto& pe : event["prev_events"]) {
        if (pe.is_string()) built.prev_events.push_back(pe.get<std::string>());
      }
    }
    if (event.contains("auth_events") && event["auth_events"].is_array()) {
      for (auto& ae : event["auth_events"]) {
        if (ae.is_string()) built.auth_events.push_back(ae.get<std::string>());
      }
    }

    persist_membership_event(db_, built);
    federate_membership_event(db_, built);

    result.accepted = true;
    result.event_id = event_id;
    return result;
  }

  // ========================================================================
  // 20. Notification count for membership events
  // ========================================================================

  int compute_notification_for_membership(const std::string& room_id,
                                           const std::string& target_user_id,
                                           const std::string& membership_type) {
    // Different membership events generate different notification levels
    if (membership_type == "invite") {
      // Invites are highlighted for the target user
      auto counts = get_unread_counts(room_id, target_user_id);
      int highlight = safe_int(counts, "highlight_count");
      return highlight > 0 ? highlight : 1; // At least 1 notification for invite
    }

    if (membership_type == "join") {
      // Joins generate low-priority notifications
      return 0; // Joins are not typically highlighted
    }

    if (membership_type == "knock") {
      // Knocks generate notifications for users with kick power
      return 1;
    }

    if (membership_type == "leave" || membership_type == "ban" ||
        membership_type == "kick") {
      return 0; // These are typically not notified via push
    }

    return 0;
  }

  int get_highlight_count_for_membership(const std::string& room_id,
                                           const std::string& user_id) {
    auto counts = get_unread_counts(room_id, user_id);
    return safe_int(counts, "highlight_count");
  }

  int get_notification_count_for_membership(const std::string& room_id,
                                              const std::string& user_id) {
    auto counts = get_unread_counts(room_id, user_id);
    return safe_int(counts, "notification_count");
  }

  // ========================================================================
  // 22. Validate membership transition
  // ========================================================================

  struct TransitionValidation {
    bool valid;
    std::string error;
    std::string errcode;
    int http_status;
    MembershipState current;
    MembershipState target;
  };

  TransitionValidation validate_membership_transition(
      const std::string& room_id, const std::string& user_id,
      const std::string& target_membership, bool is_server_admin) {

    TransitionValidation result;
    result.target = membership_state_from_str(target_membership);
    result.valid = false;

    std::string current_str = get_membership_cached(db_, room_id, user_id);
    result.current = membership_state_from_str(current_str);

    // Simplified check: certain transitions are always allowed
    bool is_targeting_self = true; // This is the common case for non-admin actions

    auto transition = MembershipTransition::validate(
        result.current, result.target, is_targeting_self,
        has_power_to(db_, room_id, user_id, "invite"),
        has_power_to(db_, room_id, user_id, "kick"),
        has_power_to(db_, room_id, user_id, "ban"),
        is_server_admin);

    if (!transition.is_allowed) {
      result.error = transition.reason_if_blocked;
      result.errcode = "M_FORBIDDEN";
      result.http_status = 403;
      return result;
    }

    result.valid = true;
    return result;
  }

  // ========================================================================
  // Join rule enforcement (extended)
  // ========================================================================

  JoinRuleCheck enforce_join_rules_extended(const std::string& room_id,
                                              const std::string& user_id,
                                              bool is_guest) {
    std::string current_membership = get_membership_cached(db_, room_id, user_id);

    auto check = check_join_rules(db_, room_id, user_id, current_membership);
    if (!check.can_join) return check;

    // Additional checks for restricted rooms with allow lists
    std::string join_rule = get_join_rule(db_, room_id);
    if (join_rule == "restricted") {
      // Already handled in check_join_rules, but double-check
      StateStore state(db_);
      auto jr_ev_id = state.get_current_state_event(room_id, "m.room.join_rules", "");
      if (jr_ev_id) {
        EventsStore evs(db_);
        auto jr_ev = evs.get_event(*jr_ev_id);
        if (jr_ev && (*jr_ev)["content"].contains("allow")) {
          bool found_valid_rule = false;
          for (auto& allow_rule : (*jr_ev)["content"]["allow"]) {
            std::string allow_type = allow_rule.value("type", "");
            if (allow_type == "m.room_membership") {
              found_valid_rule = true;
              std::string allow_room = allow_rule.value("room_id", "");
              if (!allow_room.empty() &&
                  is_user_in_room(db_, allow_room, user_id)) {
                return check; // Allowed
              }
            }
          }
          if (found_valid_rule) {
            check.can_join = false;
            check.reason = "Not in any of the allowed rooms for restricted join";
          }
        }
      }
    }

    return check;
  }

  // ========================================================================
  // Guest access enforcement (extended)
  // ========================================================================

  GuestAccessCheck enforce_guest_access_extended(const std::string& room_id,
                                                   bool is_guest,
                                                   const std::string& action) {
    GuestAccessCheck result;
    result.allowed = true;

    if (!is_guest) return result;

    std::string access = get_guest_access(db_, room_id);

    if (action == "join" || action == "knock") {
      if (access != "can_join") {
        result.allowed = false;
        result.reason = "Guest access not allowed in this room (current: " + access + ")";
        return result;
      }
    } else if (action == "invite" || action == "kick" || action == "ban" ||
               action == "unban") {
      result.allowed = false;
      result.reason = "Guest users cannot perform '" + action + "' on others";
      return result;
    }

    return result;
  }

  // ========================================================================
  // Server ACL enforcement (extended with caching)
  // ========================================================================

  struct AclCache {
    std::string room_id;
    int64_t cached_at;
    ServerAclResult result;
  };

  static std::unordered_map<std::string, AclCache> acl_cache;
  static std::mutex acl_cache_mutex;

  ServerAclResult enforce_server_acl_cached(const std::string& room_id,
                                              const std::string& server_name) {
    {
      std::lock_guard<std::mutex> lock(acl_cache_mutex);
      auto it = acl_cache.find(room_id);
      if (it != acl_cache.end()) {
        int64_t age = now_ms() - it->second.cached_at;
        if (age < 60000) { // 1 minute cache
          return it->second.result;
        }
      }
    }

    auto result = check_server_acl(db_, room_id, server_name);

    {
      std::lock_guard<std::mutex> lock(acl_cache_mutex);
      acl_cache[room_id] = {room_id, now_ms(), result};
    }

    return result;
  }

  // ========================================================================
  // Power level enforcement (extended)
  // ========================================================================

  PowerLevelCheck enforce_power_level_extended(const std::string& room_id,
                                                 const std::string& user_id,
                                                 const std::string& action,
                                                 const std::string& target_user_id) {

    auto check = check_power_for_membership_action(
        db_, room_id, user_id, action, target_user_id);

    if (!check.has_power) return check;

    // Additional check: you cannot kick/ban the room creator unless you're
    // the creator yourself or an admin
    if (action == "kick" || action == "ban") {
      StateStore state(db_);
      auto create_ev_id = state.get_current_state_event(room_id, "m.room.create", "");
      if (create_ev_id) {
        EventsStore evs(db_);
        auto ev = evs.get_event(*create_ev_id);
        if (ev) {
          std::string creator = (*ev)["content"].value("creator", "");
          if (target_user_id == creator && user_id != creator) {
            RegistrationStore reg(db_);
            auto user_info = reg.get_user_by_id(user_id);
            if (!user_info || !user_info->is_admin) {
              check.has_power = false;
              check.reason = "Cannot kick or ban the room creator";
            }
          }
        }
      }
    }

    return check;
  }

  // ========================================================================
  // Membership event federation (extended)
  // ========================================================================

  void federate_membership_event_extended(const BuiltMembershipEvent& ev,
                                           bool force_all_servers = false) {
    federate_membership_event(db_, ev);

    if (force_all_servers) {
      // Also push to all servers known in the room, not just participating
      auto all_members = load_all_members(ev.room_id);
      std::set<std::string> all_servers;
      for (const auto& m : all_members) {
        std::string server = extract_domain(m.user_id);
        if (!server.empty() && server != "localhost") {
          all_servers.insert(server);
        }
      }

      for (const auto& dest : all_servers) {
        json pdu;
        pdu["event_id"] = ev.event_id;
        pdu["room_id"] = ev.room_id;
        pdu["sender"] = ev.sender;
        pdu["type"] = "m.room.member";
        pdu["state_key"] = ev.target_user_id;
        pdu["content"] = ev.content;
        pdu["origin_server_ts"] = ev.origin_server_ts;
        pdu["depth"] = ev.depth;
        pdu["origin"] = "localhost";

        std::string fed_sql = "INSERT OR REPLACE INTO federation_stream "
                              "(type, room_id, event_id, destination, json_data, stream_id) "
                              "VALUES ('pdu',?,?,?,?,?)";
        auto txn = db_.cursor("fed_push_membership_ext");
        if (txn) {
          txn->execute(fed_sql, {ev.room_id, ev.event_id, dest, pdu.dump(),
                                  std::to_string(now_ms())});
          txn->commit();
        }
      }
    }
  }

  // ========================================================================
  // Additional membership queries
  // ========================================================================

  bool is_room_empty(const std::string& room_id) {
    return get_joined_member_count(room_id) == 0;
  }

  bool is_room_direct(const std::string& room_id, const std::string& user_id) {
    int count = get_joined_member_count(room_id);
    if (count <= 2) return true;

    // Check m.direct account data
    auto rows = db_.execute(
        "is_room_direct",
        "SELECT content FROM account_data WHERE user_id='" +
        sql_escape(user_id) + "' AND type='m.direct'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "content" && col.value) {
          try {
            json content = json::parse(*col.value);
            if (content.is_object()) {
              for (auto& [key, val] : content.items()) {
                if (val.is_array()) {
                  for (const auto& rid : val) {
                    if (rid.is_string() && rid.get<std::string>() == room_id) {
                      return true;
                    }
                  }
                }
              }
            }
          } catch (...) {}
          break;
        }
      }
    }

    return count == 2;
  }

  std::vector<std::string> get_joined_user_ids(const std::string& room_id) {
    auto members = load_members(room_id, "join");
    std::vector<std::string> result;
    result.reserve(members.size());
    for (const auto& m : members) {
      std::string uid = safe_str(m, "user_id", "");
      if (!uid.empty()) result.push_back(uid);
    }
    return result;
  }

  std::vector<std::string> get_invited_user_ids(const std::string& room_id) {
    auto members = load_members(room_id, "invite");
    std::vector<std::string> result;
    result.reserve(members.size());
    for (const auto& m : members) {
      std::string uid = safe_str(m, "user_id", "");
      if (!uid.empty()) result.push_back(uid);
    }
    return result;
  }

  std::vector<std::string> get_banned_user_ids(const std::string& room_id) {
    auto members = load_members(room_id, "ban");
    std::vector<std::string> result;
    result.reserve(members.size());
    for (const auto& m : members) {
      std::string uid = safe_str(m, "user_id", "");
      if (!uid.empty()) result.push_back(uid);
    }
    return result;
  }

  int64_t get_user_join_timestamp(const std::string& room_id,
                                    const std::string& user_id) {
    auto rows = db_.execute(
        "get_user_join_ts",
        "SELECT origin_server_ts FROM room_memberships WHERE room_id='" +
        sql_escape(room_id) + "' AND user_id='" + sql_escape(user_id) +
        "' AND membership='join'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "origin_server_ts" && col.value) {
          try { return std::stoll(*col.value); } catch (...) { return 0; }
        }
      }
    }
    return 0;
  }

  bool is_user_member(const std::string& room_id, const std::string& user_id) {
    auto m = get_membership_cached(db_, room_id, user_id);
    return m == "join";
  }

  bool can_user_see_room(const std::string& room_id, const std::string& user_id) {
    auto m = get_membership_cached(db_, room_id, user_id);
    if (m == "join" || m == "invite") return true;

    // Check world_readable
    StateStore state(db_);
    auto hv_ev_id = state.get_current_state_event(room_id, "m.room.history_visibility", "");
    if (hv_ev_id) {
      EventsStore evs(db_);
      auto ev = evs.get_event(*hv_ev_id);
      if (ev) {
        std::string hv = (*ev)["content"].value("history_visibility", "shared");
        if (hv == "world_readable") return true;
      }
    }

    return false;
  }

private:
  DatabasePool& db_;

  // ========================================================================
  // Internal helpers
  // ========================================================================

  std::optional<LazyLoadedMember> load_single_member(
      const std::string& room_id, const std::string& user_id) {
    auto rows = db_.execute(
        "load_single_member",
        "SELECT user_id, sender, membership, event_stream_ordering, "
        "origin_server_ts FROM room_memberships "
        "WHERE room_id='" + sql_escape(room_id) +
        "' AND user_id='" + sql_escape(user_id) + "' LIMIT 1");

    if (rows.empty()) return std::nullopt;

    LazyLoadedMember member;
    for (const auto& col : rows[0]) {
      if (col.name == "user_id" && col.value)
        member.user_id = *col.value;
      else if (col.name == "membership" && col.value)
        member.membership = *col.value;
      else if (col.name == "event_stream_ordering" && col.value) {
        try { member.event_stream_ordering = std::stoll(*col.value); }
        catch (...) {}
      }
      else if (col.name == "origin_server_ts" && col.value)
        member.origin_server_ts = *col.value;
    }

    // Load profile info
    member.display_name = get_display_name(user_id);
    member.avatar_url = get_avatar_url(user_id);

    return member;
  }

  std::vector<LazyLoadedMember> load_all_members(const std::string& room_id) {
    auto rows = db_.execute(
        "load_all_members_engine",
        "SELECT user_id, sender, membership, event_stream_ordering, "
        "origin_server_ts FROM room_memberships "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "ORDER BY event_stream_ordering ASC");

    std::vector<LazyLoadedMember> members;
    members.reserve(rows.size());

    for (const auto& row : rows) {
      LazyLoadedMember m;
      for (const auto& col : row) {
        if (col.name == "user_id" && col.value)
          m.user_id = *col.value;
        else if (col.name == "membership" && col.value)
          m.membership = *col.value;
        else if (col.name == "event_stream_ordering" && col.value) {
          try { m.event_stream_ordering = std::stoll(*col.value); }
          catch (...) {}
        }
        else if (col.name == "origin_server_ts" && col.value)
          m.origin_server_ts = *col.value;
      }

      if (!m.user_id.empty()) {
        m.display_name = get_display_name(m.user_id);
        m.avatar_url = get_avatar_url(m.user_id);
        members.push_back(m);
      }
    }

    return members;
  }

  std::vector<json> load_members(const std::string& room_id,
                                  const std::string& membership) {
    auto rows = db_.execute(
        "load_members_engine",
        "SELECT user_id, sender, event_stream_ordering, origin_server_ts "
        "FROM room_memberships WHERE room_id='" + sql_escape(room_id) +
        "' AND membership='" + sql_escape(membership) + "' "
        "ORDER BY event_stream_ordering ASC");

    std::vector<json> members;
    members.reserve(rows.size());

    for (const auto& row : rows) {
      json m;
      for (const auto& col : row) {
        if (col.name == "user_id" && col.value)
          m["user_id"] = *col.value;
        else if (col.name == "sender" && col.value)
          m["sender"] = *col.value;
        else if (col.name == "event_stream_ordering" && col.value) {
          try { m["stream_ordering"] = std::stoll(*col.value); }
          catch (...) {}
        }
        else if (col.name == "origin_server_ts" && col.value)
          m["origin_server_ts"] = *col.value;
      }
      if (m.contains("user_id")) members.push_back(m);
    }

    return members;
  }

  std::vector<json> load_members_detailed(const std::string& room_id) {
    auto rows = db_.execute(
        "load_members_detailed",
        "SELECT user_id, sender, membership, event_stream_ordering, "
        "origin_server_ts FROM room_memberships "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "ORDER BY event_stream_ordering ASC");

    std::vector<json> members;
    members.reserve(rows.size());

    for (const auto& row : rows) {
      json m;
      for (const auto& col : row) {
        if (col.name == "user_id" && col.value)
          m["user_id"] = *col.value;
        else if (col.name == "sender" && col.value)
          m["sender"] = *col.value;
        else if (col.name == "membership" && col.value)
          m["membership"] = *col.value;
        else if (col.name == "event_stream_ordering" && col.value) {
          try { m["stream_ordering"] = std::stoll(*col.value); }
          catch (...) {}
        }
        else if (col.name == "origin_server_ts" && col.value)
          m["origin_server_ts"] = *col.value;
      }
      if (m.contains("user_id")) members.push_back(m);
    }

    return members;
  }

  std::vector<std::string> get_recent_active_senders(
      const std::string& room_id, int limit) {
    auto rows = db_.execute(
        "get_recent_senders",
        "SELECT DISTINCT sender FROM events "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "AND sender IS NOT NULL AND sender != '' "
        "ORDER BY MAX(stream_ordering) DESC LIMIT " + std::to_string(limit));

    std::vector<std::string> senders;
    senders.reserve(rows.size());

    for (const auto& row : rows) {
      for (const auto& col : row) {
        if (col.name == "sender" && col.value && !col.value->empty()) {
          senders.push_back(*col.value);
          break;
        }
      }
    }

    return senders;
  }

  std::string get_display_name(const std::string& user_id) {
    auto rows = db_.execute(
        "get_display_name_engine",
        "SELECT display_name FROM profiles WHERE user_id='" +
        sql_escape(user_id) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "display_name" && col.value && !col.value->empty())
          return *col.value;
      }
    }

    return extract_localpart(user_id);
  }

  std::string get_avatar_url(const std::string& user_id) {
    auto rows = db_.execute(
        "get_avatar_url_engine",
        "SELECT avatar_url FROM profiles WHERE user_id='" +
        sql_escape(user_id) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "avatar_url" && col.value && !col.value->empty())
          return *col.value;
      }
    }

    return "";
  }

  int64_t get_last_active_ts(const std::string& room_id,
                               const std::string& user_id) {
    auto rows = db_.execute(
        "get_last_active_ts_engine",
        "SELECT last_active_ts FROM presence_state WHERE user_id='" +
        sql_escape(user_id) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "last_active_ts" && col.value) {
          try { return std::stoll(*col.value); } catch (...) {}
        }
      }
    }

    // Fallback to last event timestamp
    auto event_rows = db_.execute(
        "get_last_msg_ts_engine",
        "SELECT MAX(origin_server_ts) as mts FROM events WHERE room_id='" +
        sql_escape(room_id) + "' AND sender='" + sql_escape(user_id) + "'");

    if (!event_rows.empty()) {
      for (const auto& col : event_rows[0]) {
        if (col.name == "mts" && col.value && !col.value->empty()) {
          try { return std::stoll(*col.value); } catch (...) {}
        }
      }
    }

    return 0;
  }

  int64_t get_last_room_activity_ts(const std::string& room_id) {
    auto rows = db_.execute(
        "get_last_room_activity_ts",
        "SELECT MAX(origin_server_ts) as mts FROM events WHERE room_id='" +
        sql_escape(room_id) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "mts" && col.value && !col.value->empty()) {
          try { return std::stoll(*col.value); } catch (...) {}
        }
      }
    }

    return 0;
  }

  json load_state_event(const std::string& room_id,
                          const std::string& event_type,
                          const std::string& state_key = "") {
    StateStore state(db_);
    auto ev_id = state.get_current_state_event(room_id, event_type, state_key);
    if (!ev_id) return json();

    EventsStore evs(db_);
    auto ev = evs.get_event(*ev_id);
    if (!ev) return json();

    return *ev;
  }

  int get_joined_member_count(const std::string& room_id) {
    auto rows = db_.execute(
        "get_joined_member_count_engine",
        "SELECT COUNT(*) as c FROM room_memberships WHERE room_id='" +
        sql_escape(room_id) + "' AND membership='join'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "c" && col.value) {
          try { return std::stoi(*col.value); } catch (...) {}
          break;
        }
      }
    }
    return 0;
  }

  int get_invited_member_count(const std::string& room_id) {
    auto rows = db_.execute(
        "get_invited_member_count_engine",
        "SELECT COUNT(*) as c FROM room_memberships WHERE room_id='" +
        sql_escape(room_id) + "' AND membership='invite'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "c" && col.value) {
          try { return std::stoi(*col.value); } catch (...) {}
          break;
        }
      }
    }
    return 0;
  }

  int get_banned_member_count(const std::string& room_id) {
    auto rows = db_.execute(
        "get_banned_member_count_engine",
        "SELECT COUNT(*) as c FROM room_memberships WHERE room_id='" +
        sql_escape(room_id) + "' AND membership='ban'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "c" && col.value) {
          try { return std::stoi(*col.value); } catch (...) {}
          break;
        }
      }
    }
    return 0;
  }

  int get_knocked_member_count(const std::string& room_id) {
    auto rows = db_.execute(
        "get_knocked_member_count_engine",
        "SELECT COUNT(*) as c FROM room_memberships WHERE room_id='" +
        sql_escape(room_id) + "' AND membership='knock'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "c" && col.value) {
          try { return std::stoi(*col.value); } catch (...) {}
          break;
        }
      }
    }
    return 0;
  }

  json get_unread_counts(const std::string& room_id, const std::string& user_id) {
    json result;
    result["notification_count"] = 0;
    result["highlight_count"] = 0;

    auto rows = db_.execute(
        "get_unread_counts_engine",
        "SELECT notif_count, highlight_count FROM event_push_summary "
        "WHERE user_id='" + sql_escape(user_id) + "' AND room_id='" +
        sql_escape(room_id) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "notif_count" && col.value) {
          try { result["notification_count"] = std::stoi(*col.value); }
          catch (...) {}
        }
        if (col.name == "highlight_count" && col.value) {
          try { result["highlight_count"] = std::stoi(*col.value); }
          catch (...) {}
        }
      }
    }

    return result;
  }

  std::string compute_room_name_fallback(const std::string& room_id) {
    StateStore state(db_);
    auto name_ev_id = state.get_current_state_event(room_id, "m.room.name", "");
    if (name_ev_id) {
      EventsStore evs(db_);
      auto ev = evs.get_event(*name_ev_id);
      if (ev) {
        std::string name = (*ev)["content"].value("name", "");
        if (!name.empty()) return name;
      }
    }

    auto alias_ev_id = state.get_current_state_event(room_id, "m.room.canonical_alias", "");
    if (alias_ev_id) {
      EventsStore evs(db_);
      auto ev = evs.get_event(*alias_ev_id);
      if (ev) {
        std::string alias = (*ev)["content"].value("alias", "");
        if (!alias.empty()) return alias;
      }
    }

    // Compute from members
    auto heroes = select_heroes(room_id, "", 5);
    return room_name_from_heroes(heroes, "");
  }

  std::optional<UserInfo> get_user_info(const std::string& user_id) {
    RegistrationStore reg(db_);
    return reg.get_user_by_id(user_id);
  }
};

// ============================================================================
// Global membership engine singleton
// ============================================================================

static std::unique_ptr<MembershipEngine> g_membership_engine;
static std::mutex g_engine_mutex;
static DatabasePool* g_current_db = nullptr;

static MembershipEngine& get_engine(DatabasePool& db) {
  std::lock_guard<std::mutex> lock(g_engine_mutex);
  if (!g_membership_engine || g_current_db != &db) {
    g_membership_engine = std::make_unique<MembershipEngine>(db);
    g_current_db = &db;
  }
  return *g_membership_engine;
}

// ============================================================================
// PUBLIC HANDLER APIs
// ============================================================================

// ============================================================================
// 1. INVITE HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/invite
//
// Invites a user to a room. The inviter must have invite permission.
// Generates an m.room.member event with membership=invite for the target.
// Federates the invite to the target user's server.
// Enforces: auth, room existence, membership state, invite power level,
//           server ACL, guest access, rate limiting.

json handle_membership_invite(DatabasePool& db, const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id,
                               const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Parse target user ----
  std::string target_user_id = safe_str(request_body, "user_id", "");
  if (target_user_id.empty()) {
    return make_error(400, "M_INVALID_PARAM", "Missing user_id");
  }
  if (!validate_user_id(target_user_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid user_id: " + target_user_id);
  }

  // ---- 4. Cannot invite self ----
  if (target_user_id == auth.user_id) {
    return make_error(400, "M_INVALID_PARAM", "Cannot invite yourself");
  }

  // ---- 5. Check room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 6. Check inviter is in the room ----
  std::string inviter_membership = get_membership_cached(db, room_id, auth.user_id);
  if (inviter_membership != "join") {
    return make_error(403, "M_FORBIDDEN",
                      "You must be a member of the room to invite others");
  }

  // ---- 7. Check target's current membership ----
  auto& engine = get_engine(db);
  std::string target_membership = get_membership_cached(db, room_id, target_user_id);

  // ---- 8. Validate membership transition ----
  MembershipState current = membership_state_from_str(target_membership);
  MembershipState target_state = MembershipState::INVITE;

  RegistrationStore reg(db);
  auto sender_info = reg.get_user_by_id(auth.user_id);
  bool is_admin = sender_info && sender_info->is_admin;

  auto transition = MembershipTransition::validate(
      current, target_state, false,
      has_power_to(db, room_id, auth.user_id, "invite"),
      has_power_to(db, room_id, auth.user_id, "kick"),
      has_power_to(db, room_id, auth.user_id, "ban"),
      is_admin);

  if (!transition.is_allowed) {
    return make_error(403, "M_FORBIDDEN", transition.reason_if_blocked);
  }

  // ---- 9. Check power level ----
  auto pl_check = check_power_for_membership_action(
      db, room_id, auth.user_id, "invite", target_user_id);
  if (!pl_check.has_power) {
    return make_error(403, "M_FORBIDDEN", pl_check.reason);
  }

  // ---- 10. Guest access check ----
  auto guest_check = check_guest_access(db, room_id, auth.is_guest, "invite");
  if (!guest_check.allowed) {
    return make_error(403, "M_FORBIDDEN", guest_check.reason);
  }

  // ---- 11. Server ACL check ----
  auto acl_check = check_user_acl(db, room_id, target_user_id);
  if (!acl_check.allowed) {
    return make_error(403, "M_FORBIDDEN", acl_check.reason);
  }

  // ---- 12. Rate limit ----
  if (!check_membership_rate_limit(auth.user_id, "invite")) {
    return make_error(429, "M_LIMIT_EXCEEDED",
                      "Too many invites. Try again later.");
  }

  // ---- 13. Parse optional reason ----
  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string()) {
    reason = request_body["reason"].get<std::string>();
  }

  // ---- 14. Build and persist invite event ----
  auto ev = build_membership_event(db, room_id, auth.user_id,
                                    target_user_id, "invite",
                                    json::object(), reason);
  persist_membership_event(db, ev);

  // ---- 15. Federate the invite ----
  federate_membership_event(db, ev);

  // ---- 16. Return response ----
  json body;
  body["event_id"] = ev.event_id;
  body["room_id"] = room_id;
  return make_response(200, body);
}

// ============================================================================
// 2. JOIN HANDLER (lazy-load aware)
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/join
// POST /_matrix/client/v3/join/{roomIdOrAlias}
//
// Joins a room. Resolves aliases. Enforces join rules, guest access,
// banned state, restricted access. Generates m.room.member event with
// membership=join. Supports server_name and via parameters for federation.

json handle_membership_join(DatabasePool& db, const std::string& auth_header,
                              const std::string& access_token_param,
                              const std::string& room_id_or_alias,
                              const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Resolve alias if needed ----
  std::string room_id = room_id_or_alias;
  std::vector<std::string> server_names;

  if (!room_id_or_alias.empty() && room_id_or_alias[0] == '#') {
    DirectoryStore dir(db);
    auto resolved = dir.get_room_id(room_id_or_alias);
    if (!resolved) {
      return make_error(404, "M_NOT_FOUND",
                        "Room alias not found: " + room_id_or_alias);
    }
    room_id = *resolved;

    auto servers = dir.get_servers_for_alias(room_id_or_alias);
    for (auto& s : servers) server_names.push_back(s);
  }

  // Parse server_name / via from request body
  if (request_body.contains("server_name")) {
    const auto& sn = request_body["server_name"];
    if (sn.is_array()) {
      for (auto& s : sn)
        if (s.is_string()) server_names.push_back(s.get<std::string>());
    } else if (sn.is_string()) {
      server_names.push_back(sn.get<std::string>());
    }
  }
  if (request_body.contains("via") && request_body["via"].is_array()) {
    for (auto& v : request_body["via"])
      if (v.is_string()) server_names.push_back(v.get<std::string>());
  }

  // ---- 3. Validate room ID ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 4. Check room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    if (!server_names.empty()) {
      return make_error(404, "M_NOT_FOUND",
                        "Room not found on this server. Try joining via federation: " +
                        (server_names.empty() ? "unknown" : server_names[0]));
    }
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 5. Check current membership ----
  std::string current_membership = get_membership_cached(db, room_id, auth.user_id);

  // Already joined
  if (current_membership == "join") {
    json body;
    body["room_id"] = room_id;
    return make_response(200, body);
  }

  // Banned
  if (current_membership == "ban") {
    return make_error(403, "M_FORBIDDEN", "You are banned from this room");
  }

  // ---- 6. Check join rules ----
  auto& engine = get_engine(db);
  auto jr_check = engine.enforce_join_rules_extended(room_id, auth.user_id, auth.is_guest);
  if (!jr_check.can_join) {
    return make_error(403, "M_FORBIDDEN", jr_check.reason);
  }

  // ---- 7. Guest access check ----
  auto guest_check = check_guest_access(db, room_id, auth.is_guest, "join");
  if (!guest_check.allowed) {
    return make_error(403, "M_FORBIDDEN", guest_check.reason);
  }

  // ---- 8. Server ACL check ----
  std::string user_server = extract_domain(auth.user_id);
  auto acl_check = check_server_acl(db, room_id, user_server);
  if (!acl_check.allowed) {
    return make_error(403, "M_FORBIDDEN", acl_check.reason);
  }

  // ---- 9. Rate limit ----
  if (!check_membership_rate_limit(auth.user_id, "join")) {
    return make_error(429, "M_LIMIT_EXCEEDED",
                      "Too many join attempts. Try again later.");
  }

  // ---- 10. Validate membership transition ----
  RegistrationStore reg(db);
  auto sender_info = reg.get_user_by_id(auth.user_id);
  bool is_admin = sender_info && sender_info->is_admin;

  auto transition = MembershipTransition::validate(
      membership_state_from_str(current_membership),
      MembershipState::JOIN, true,
      has_power_to(db, room_id, auth.user_id, "invite"),
      has_power_to(db, room_id, auth.user_id, "kick"),
      has_power_to(db, room_id, auth.user_id, "ban"),
      is_admin);

  if (!transition.is_allowed) {
    return make_error(403, "M_FORBIDDEN", transition.reason_if_blocked);
  }

  // ---- 11. Parse optional reason and third-party signed ----
  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string()) {
    reason = request_body["reason"].get<std::string>();
  }

  std::optional<json> third_party_signed;
  if (request_body.contains("third_party_signed") &&
      request_body["third_party_signed"].is_object()) {
    third_party_signed = request_body["third_party_signed"];
  }

  // ---- 12. Build and persist join event ----
  json extra_content;
  if (third_party_signed) extra_content["third_party_signed"] = *third_party_signed;

  auto ev = build_membership_event(db, room_id, auth.user_id,
                                    auth.user_id, "join",
                                    extra_content, reason);
  persist_membership_event(db, ev);

  // ---- 13. Federate the join ----
  federate_membership_event(db, ev);

  // ---- 14. Return response ----
  json body;
  body["room_id"] = room_id;

  if (request_body.value("include_summary", false)) {
    body["summary"] = engine.compute_membership_summary(room_id, auth.user_id).to_json();
  }

  return make_response(200, body);
}

// ============================================================================
// 3. LEAVE HANDLER
// ============================================================================

json handle_membership_leave(DatabasePool& db, const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id,
                               const json& request_body) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  if (!validate_room_id(room_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");

  RoomStore rooms(db);
  if (!rooms.get_room(room_id))
    return make_error(404, "M_NOT_FOUND", "Room not found");

  std::string current = get_membership_cached(db, room_id, auth.user_id);

  if (current == "leave")
    return make_response(200, json::object());

  if (current == "ban")
    return make_error(403, "M_FORBIDDEN", "Cannot leave a room you are banned from");

  if (current != "join" && current != "invite" && current != "knock")
    return make_error(403, "M_FORBIDDEN", "Not a member of this room");

  // Rate limit
  if (!check_membership_rate_limit(auth.user_id, "leave"))
    return make_error(429, "M_LIMIT_EXCEEDED", "Too many leave requests. Try again later.");

  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string())
    reason = request_body["reason"].get<std::string>();

  auto ev = build_membership_event(db, room_id, auth.user_id,
                                    auth.user_id, "leave",
                                    json::object(), reason);
  persist_membership_event(db, ev);
  federate_membership_event(db, ev);

  return make_response(200, json::object());
}

// ============================================================================
// 4. BAN HANDLER
// ============================================================================

json handle_membership_ban(DatabasePool& db, const std::string& auth_header,
                             const std::string& access_token_param,
                             const std::string& room_id,
                             const json& request_body) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  if (!validate_room_id(room_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");

  std::string target_user_id = safe_str(request_body, "user_id", "");
  if (target_user_id.empty())
    return make_error(400, "M_INVALID_PARAM", "Missing user_id");
  if (!validate_user_id(target_user_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid user_id");

  RoomStore rooms(db);
  if (!rooms.get_room(room_id))
    return make_error(404, "M_NOT_FOUND", "Room not found");

  // Check banner is in the room
  std::string banner_membership = get_membership_cached(db, room_id, auth.user_id);
  if (banner_membership != "join")
    return make_error(403, "M_FORBIDDEN", "You must be a member to ban users");

  // Check power level
  auto pl_check = check_power_for_membership_action(
      db, room_id, auth.user_id, "ban", target_user_id);
  if (!pl_check.has_power)
    return make_error(403, "M_FORBIDDEN", pl_check.reason);

  // Guest check
  auto guest_check = check_guest_access(db, room_id, auth.is_guest, "ban");
  if (!guest_check.allowed)
    return make_error(403, "M_FORBIDDEN", guest_check.reason);

  // Membership transition check
  std::string current = get_membership_cached(db, room_id, target_user_id);

  RegistrationStore reg(db);
  auto sender_info = reg.get_user_by_id(auth.user_id);
  bool is_admin = sender_info && sender_info->is_admin;

  auto transition = MembershipTransition::validate(
      membership_state_from_str(current), MembershipState::BAN, false,
      has_power_to(db, room_id, auth.user_id, "invite"),
      has_power_to(db, room_id, auth.user_id, "kick"),
      has_power_to(db, room_id, auth.user_id, "ban"),
      is_admin);

  if (!transition.is_allowed)
    return make_error(403, "M_FORBIDDEN", transition.reason_if_blocked);

  // Rate limit
  if (!check_membership_rate_limit(auth.user_id, "ban"))
    return make_error(429, "M_LIMIT_EXCEEDED", "Too many bans. Try again later.");

  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string())
    reason = request_body["reason"].get<std::string>();

  auto ev = build_membership_event(db, room_id, auth.user_id,
                                    target_user_id, "ban",
                                    json::object(), reason);
  persist_membership_event(db, ev);
  federate_membership_event(db, ev);

  json body;
  body["event_id"] = ev.event_id;
  body["room_id"] = room_id;
  return make_response(200, body);
}

// ============================================================================
// 5. KICK HANDLER
// ============================================================================

json handle_membership_kick(DatabasePool& db, const std::string& auth_header,
                              const std::string& access_token_param,
                              const std::string& room_id,
                              const json& request_body) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  if (!validate_room_id(room_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");

  std::string target_user_id = safe_str(request_body, "user_id", "");
  if (target_user_id.empty())
    return make_error(400, "M_INVALID_PARAM", "Missing user_id");
  if (!validate_user_id(target_user_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid user_id");

  if (target_user_id == auth.user_id)
    return make_error(400, "M_INVALID_PARAM",
                      "Cannot kick yourself. Use /leave instead.");

  RoomStore rooms(db);
  if (!rooms.get_room(room_id))
    return make_error(404, "M_NOT_FOUND", "Room not found");

  // Check kicker is in the room
  std::string kicker_membership = get_membership_cached(db, room_id, auth.user_id);
  if (kicker_membership != "join")
    return make_error(403, "M_FORBIDDEN", "You must be a member to kick users");

  // Check target is in the room
  std::string target_membership = get_membership_cached(db, room_id, target_user_id);
  if (target_membership != "join")
    return make_error(403, "M_FORBIDDEN", "Target user is not in the room");

  // Power level check
  auto pl_check = check_power_for_membership_action(
      db, room_id, auth.user_id, "kick", target_user_id);
  if (!pl_check.has_power)
    return make_error(403, "M_FORBIDDEN", pl_check.reason);

  // Guest check
  auto guest_check = check_guest_access(db, room_id, auth.is_guest, "kick");
  if (!guest_check.allowed)
    return make_error(403, "M_FORBIDDEN", guest_check.reason);

  // Rate limit
  if (!check_membership_rate_limit(auth.user_id, "kick"))
    return make_error(429, "M_LIMIT_EXCEEDED", "Too many kicks. Try again later.");

  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string())
    reason = request_body["reason"].get<std::string>();

  auto ev = build_membership_event(db, room_id, auth.user_id,
                                    target_user_id, "leave",
                                    json::object(), reason);
  persist_membership_event(db, ev);
  federate_membership_event(db, ev);

  json body;
  body["event_id"] = ev.event_id;
  body["room_id"] = room_id;
  return make_response(200, body);
}

// ============================================================================
// 6. KNOCK HANDLER
// ============================================================================

json handle_membership_knock(DatabasePool& db, const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id_or_alias,
                               const json& request_body) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  // Resolve alias if needed
  std::string room_id = room_id_or_alias;
  std::vector<std::string> server_names;

  if (!room_id_or_alias.empty() && room_id_or_alias[0] == '#') {
    DirectoryStore dir(db);
    auto resolved = dir.get_room_id(room_id_or_alias);
    if (!resolved)
      return make_error(404, "M_NOT_FOUND",
                        "Room alias not found: " + room_id_or_alias);
    room_id = *resolved;
  }

  if (request_body.contains("server_name")) {
    const auto& sn = request_body["server_name"];
    if (sn.is_array()) {
      for (auto& s : sn)
        if (s.is_string()) server_names.push_back(s.get<std::string>());
    } else if (sn.is_string()) {
      server_names.push_back(sn.get<std::string>());
    }
  }

  if (!validate_room_id(room_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");

  RoomStore rooms(db);
  if (!rooms.get_room(room_id)) {
    if (!server_names.empty()) {
      return make_error(404, "M_NOT_FOUND",
                        "Room not found locally. Try knocking via federation: " +
                        server_names[0]);
    }
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // Check join rule allows knocking
  std::string join_rule = get_join_rule(db, room_id);
  if (join_rule != "knock" && join_rule != "public") {
    return make_error(403, "M_FORBIDDEN",
                      "This room does not allow knocking (join_rule=" + join_rule + ")");
  }

  std::string current = get_membership_cached(db, room_id, auth.user_id);

  if (current == "join") {
    json body;
    body["room_id"] = room_id;
    return make_response(200, body);
  }

  if (current == "ban")
    return make_error(403, "M_FORBIDDEN", "You are banned from this room");

  if (current == "knock")
    return make_error(403, "M_FORBIDDEN",
                      "You have already knocked on this room. Please wait for an invitation.");

  // Guest check
  auto guest_check = check_guest_access(db, room_id, auth.is_guest, "knock");
  if (!guest_check.allowed)
    return make_error(403, "M_FORBIDDEN", guest_check.reason);

  // Rate limit
  if (!check_membership_rate_limit(auth.user_id, "knock"))
    return make_error(429, "M_LIMIT_EXCEEDED",
                      "Too many knock attempts. Try again later.");

  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string())
    reason = request_body["reason"].get<std::string>();

  auto ev = build_membership_event(db, room_id, auth.user_id,
                                    auth.user_id, "knock",
                                    json::object(), reason);
  persist_membership_event(db, ev);

  // Federation for knock: push to all participating servers
  auto participants = get_room_participating_servers(db, room_id);
  for (auto& srv : participants) {
    json pdu;
    pdu["event_id"] = ev.event_id;
    pdu["room_id"] = ev.room_id;
    pdu["sender"] = ev.sender;
    pdu["type"] = "m.room.member";
    pdu["state_key"] = ev.target_user_id;
    pdu["content"] = ev.content;
    pdu["origin_server_ts"] = ev.origin_server_ts;
    pdu["depth"] = ev.depth;
    pdu["origin"] = "localhost";

    auto txn = db.cursor("fed_push_knock");
    if (txn) {
      txn->execute(
        "INSERT OR REPLACE INTO federation_stream "
        "(type, room_id, event_id, destination, json_data, stream_id) "
        "VALUES ('pdu',?,?,?,?,?)",
        {ev.room_id, ev.event_id, srv, pdu.dump(), std::to_string(now_ms())});
      txn->commit();
    }
  }

  json body;
  body["room_id"] = room_id;
  return make_response(200, body);
}

// ============================================================================
// 7. UNBAN HANDLER
// ============================================================================

json handle_membership_unban(DatabasePool& db, const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id,
                               const json& request_body) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  if (!validate_room_id(room_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");

  std::string target_user_id = safe_str(request_body, "user_id", "");
  if (target_user_id.empty())
    return make_error(400, "M_INVALID_PARAM", "Missing user_id");
  if (!validate_user_id(target_user_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid user_id");

  RoomStore rooms(db);
  if (!rooms.get_room(room_id))
    return make_error(404, "M_NOT_FOUND", "Room not found");

  // Check target is currently banned
  std::string target_membership = get_membership_cached(db, room_id, target_user_id);
  if (target_membership != "ban")
    return make_error(400, "M_BAD_STATE", "User is not banned");

  // Check power level
  auto pl_check = check_power_for_membership_action(
      db, room_id, auth.user_id, "ban", target_user_id);
  if (!pl_check.has_power)
    return make_error(403, "M_FORBIDDEN", pl_check.reason);

  // Guest check
  auto guest_check = check_guest_access(db, room_id, auth.is_guest, "unban");
  if (!guest_check.allowed)
    return make_error(403, "M_FORBIDDEN", guest_check.reason);

  // Rate limit
  if (!check_membership_rate_limit(auth.user_id, "ban"))
    return make_error(429, "M_LIMIT_EXCEEDED",
                      "Too many membership changes. Try again later.");

  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string())
    reason = request_body["reason"].get<std::string>();

  auto ev = build_membership_event(db, room_id, auth.user_id,
                                    target_user_id, "leave",
                                    json::object(), reason);
  persist_membership_event(db, ev);
  federate_membership_event(db, ev);

  json body;
  body["event_id"] = ev.event_id;
  body["room_id"] = room_id;
  return make_response(200, body);
}

// ============================================================================
// 8. LAZY LOADING QUERY API
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/members?lazy_load=true
//
// Returns a lazy-loaded member list for the given room.
// Supports filtering by membership, pagination, and the lazy loading
// algorithm that returns heroes + viewer + recent senders.

json handle_lazy_loaded_members(DatabasePool& db, const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& room_id,
                                  const json& query_params) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  if (!validate_room_id(room_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");

  // Check user can see the room
  auto& engine = get_engine(db);
  if (!engine.can_user_see_room(room_id, auth.user_id))
    return make_error(403, "M_FORBIDDEN", "You cannot see this room");

  // Parse filter options
  bool lazy_load = query_params.value("lazy_load", false);
  bool include_redundant = query_params.value("include_redundant", false);
  int max_heroes = query_params.value("max_heroes", 5);

  LazyLoadingContext ctx;
  ctx.lazy_load_members = lazy_load;
  ctx.include_redundant_members = include_redundant;
  ctx.max_heroes = max_heroes;

  // Parse required/excluded users
  if (query_params.contains("required_user_ids") &&
      query_params["required_user_ids"].is_array()) {
    for (auto& uid : query_params["required_user_ids"]) {
      if (uid.is_string()) ctx.required_user_ids.insert(uid.get<std::string>());
    }
  }
  if (query_params.contains("excluded_user_ids") &&
      query_params["excluded_user_ids"].is_array()) {
    for (auto& uid : query_params["excluded_user_ids"]) {
      if (uid.is_string()) ctx.excluded_user_ids.insert(uid.get<std::string>());
    }
  }

  // Compute lazy loaded members
  auto members = engine.compute_lazy_loaded_members(room_id, auth.user_id, ctx);

  // Build response
  json body;
  body["chunk"] = json::array();
  for (const auto& m : members) {
    body["chunk"].push_back(m.to_json());
  }

  // Include heroes separately (as per spec)
  auto heroes = engine.select_heroes(room_id, auth.user_id, 5);
  body["heroes"] = json::array();
  for (const auto& h : heroes) {
    body["heroes"].push_back(h.to_json());
  }

  // Include member counts
  auto summary = engine.compute_membership_summary(room_id, auth.user_id);
  body["total_member_count"] = summary.total_member_count;
  body["joined_member_count"] = summary.joined_member_count;
  body["invited_member_count"] = summary.invited_member_count;

  return make_response(200, body);
}

// ============================================================================
// 24. ROOM SUMMARY FROM MEMBERS
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/summary
//
// Returns a complete room summary computed from the member list,
// including heroes, room name, avatar, etc.

json handle_room_summary_from_members(DatabasePool& db,
                                        const std::string& auth_header,
                                        const std::string& access_token_param,
                                        const std::string& room_id,
                                        const json& query_params) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  if (!validate_room_id(room_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");

  auto& engine = get_engine(db);
  if (!engine.can_user_see_room(room_id, auth.user_id))
    return make_error(403, "M_FORBIDDEN", "You cannot see this room");

  // Compute full summary
  auto summary = engine.compute_membership_summary(room_id, auth.user_id);
  json body = summary.to_json();

  // Add extra detail if requested
  if (query_params.value("include_hero_details", false)) {
    body["hero_details"] = json::array();
    for (const auto& h : summary.heroes) {
      json hd = h.to_json();
      hd["membership"] = h.membership;
      hd["currently_active"] = h.currently_active;
      hd["last_active_ts"] = h.last_active_ts;
      hd["join_order"] = h.join_order;
      body["hero_details"].push_back(hd);
    }
  }

  if (query_params.value("include_member_lists", false)) {
    auto joined = engine.get_joined_user_ids(room_id);
    auto invited = engine.get_invited_user_ids(room_id);
    auto banned = engine.get_banned_user_ids(room_id);

    body["joined_members"] = joined;
    body["invited_members"] = invited;
    body["banned_members"] = banned;
  }

  return make_response(200, body);
}

// ============================================================================
// MEMBERSHIP HISTORY QUERY
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/membership_history
//
// Returns the membership history for a room or specific user.

json handle_membership_history(DatabasePool& db, const std::string& auth_header,
                                 const std::string& access_token_param,
                                 const std::string& room_id,
                                 const json& query_params) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  if (!validate_room_id(room_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");

  auto& engine = get_engine(db);
  if (!engine.can_user_see_room(room_id, auth.user_id))
    return make_error(403, "M_FORBIDDEN", "You cannot see this room");

  int limit = query_params.value("limit", 100);
  if (limit > 500) limit = 500;

  std::string user_id = safe_str(query_params, "user_id", "");
  std::vector<json> history;

  if (!user_id.empty()) {
    history = engine.get_membership_history(room_id, user_id, limit);
  } else {
    history = engine.get_full_membership_history(room_id, limit);
  }

  json body;
  body["chunk"] = history;
  body["room_id"] = room_id;
  if (!user_id.empty()) body["user_id"] = user_id;

  return make_response(200, body);
}

// ============================================================================
// HEROES QUERY
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/heroes
//
// Returns the hero list for a room.

json handle_heroes_query(DatabasePool& db, const std::string& auth_header,
                           const std::string& access_token_param,
                           const std::string& room_id,
                           const json& query_params) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  if (!validate_room_id(room_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");

  auto& engine = get_engine(db);
  if (!engine.can_user_see_room(room_id, auth.user_id))
    return make_error(403, "M_FORBIDDEN", "You cannot see this room");

  int count = query_params.value("count", 5);
  if (count < 1) count = 1;
  if (count > 20) count = 20;

  auto heroes = engine.select_heroes(room_id, auth.user_id, count);

  json body;
  body["room_id"] = room_id;
  body["heroes"] = json::array();
  for (const auto& h : heroes) {
    body["heroes"].push_back(h.to_json());
  }

  return make_response(200, body);
}

// ============================================================================
// ROOM NAME FROM MEMBERS
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/computed_name
//
// Returns the computed room name from heroes/members.

json handle_room_name_from_members(DatabasePool& db, const std::string& auth_header,
                                     const std::string& access_token_param,
                                     const std::string& room_id) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  if (!validate_room_id(room_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");

  auto& engine = get_engine(db);
  auto summary = engine.compute_membership_summary(room_id, auth.user_id);

  json body;
  body["room_id"] = room_id;
  body["name"] = summary.computed_room_name;
  body["name_source"] = "computed_from_heroes";

  return make_response(200, body);
}

// ============================================================================
// ROOM AVATAR FROM MEMBERS
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/computed_avatar
//
// Returns the computed room avatar from member avatars.

json handle_room_avatar_from_members(DatabasePool& db,
                                       const std::string& auth_header,
                                       const std::string& access_token_param,
                                       const std::string& room_id) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  if (!validate_room_id(room_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");

  auto& engine = get_engine(db);
  std::string avatar = engine.room_avatar_from_members(room_id);

  json body;
  body["room_id"] = room_id;
  body["avatar_url"] = avatar;
  body["avatar_source"] = avatar.empty() ? "generated" : "member_avatar";

  return make_response(200, body);
}

// ============================================================================
// MEMBERSHIP NOTIFICATION COUNTS
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/membership_notification_counts
//
// Returns notification counts relevant to membership events for a user.

json handle_membership_notification_counts(DatabasePool& db,
                                             const std::string& auth_header,
                                             const std::string& access_token_param,
                                             const std::string& room_id) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  if (!validate_room_id(room_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");

  auto& engine = get_engine(db);
  int notif_count = engine.get_notification_count_for_membership(room_id, auth.user_id);
  int highlight_count = engine.get_highlight_count_for_membership(room_id, auth.user_id);

  json body;
  body["room_id"] = room_id;
  body["notification_count"] = notif_count;
  body["highlight_count"] = highlight_count;

  return make_response(200, body);
}

// ============================================================================
// MEMBERSHIP VALIDATION (dry-run)
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/validate_membership
//
// Validates whether a membership transition would be allowed without
// actually performing it. Useful for client UI pre-validation.

json handle_validate_membership(DatabasePool& db, const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& room_id,
                                  const json& request_body) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  if (!validate_room_id(room_id))
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");

  std::string target_user_id = safe_str(request_body, "user_id", auth.user_id);
  std::string target_membership = safe_str(request_body, "membership", "");

  if (target_membership.empty())
    return make_error(400, "M_INVALID_PARAM", "Missing membership field");

  RegistrationStore reg(db);
  auto sender_info = reg.get_user_by_id(auth.user_id);
  bool is_admin = sender_info && sender_info->is_admin;

  auto& engine = get_engine(db);
  auto validation = engine.validate_membership_transition(
      room_id, target_user_id, target_membership, is_admin);

  json body;
  body["room_id"] = room_id;
  body["user_id"] = target_user_id;
  body["target_membership"] = target_membership;
  body["current_membership"] = membership_state_str(validation.current);
  body["valid"] = validation.valid;
  if (!validation.valid) {
    body["error"] = validation.error;
    body["errcode"] = validation.errcode;
  }

  return make_response(200, body);
}

// ============================================================================
// INCOMING MEMBERSHIP EVENT (federation endpoint)
// ============================================================================
// PUT /_matrix/federation/v1/send/{txnId}
//
// Process incoming membership events from federation.

json handle_incoming_membership_event(DatabasePool& db,
                                        const json& event,
                                        const std::string& origin_server) {
  auto& engine = get_engine(db);
  auto result = engine.handle_incoming_membership_event(event, origin_server);

  json body;
  body["accepted"] = result.accepted;
  if (!result.accepted) {
    body["reason"] = result.reason;
  } else {
    body["event_id"] = result.event_id;
  }

  return make_response(result.accepted ? 200 : 403, body);
}

// ============================================================================
// LAZY LOAD FILTER (for use by sync handlers)
// ============================================================================

json filter_members_for_lazy_sync(DatabasePool& db,
                                    const std::string& room_id,
                                    const std::string& viewer_user_id,
                                    const json& members_chunk,
                                    const json& filter) {
  auto& engine = get_engine(db);

  // Convert chunk to LazyLoadedMember vector
  std::vector<LazyLoadedMember> all_members;
  if (members_chunk.is_array()) {
    for (const auto& m : members_chunk) {
      LazyLoadedMember lm;
      lm.user_id = safe_str(m, "user_id", "");
      if (lm.user_id.empty()) continue;
      lm.display_name = safe_str(m, "display_name", "");
      lm.avatar_url = safe_str(m, "avatar_url", "");
      lm.membership = safe_str(m, "membership", "join");
      all_members.push_back(lm);
    }
  }

  LazyLoadingContext ctx = LazyLoadingContext::from_sync_filter(filter);
  auto filtered = engine.lazy_load_member_filter(
      all_members, viewer_user_id, ctx, room_id);

  json result = json::array();
  for (const auto& m : filtered) {
    result.push_back(m.to_json());
  }

  return result;
}

// ============================================================================
// Bulk membership summary query (for room list rendering)
// ============================================================================

json handle_bulk_membership_summaries(DatabasePool& db,
                                        const std::string& auth_header,
                                        const std::string& access_token_param,
                                        const json& request_body) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  if (!request_body.contains("room_ids") || !request_body["room_ids"].is_array())
    return make_error(400, "M_INVALID_PARAM", "Missing room_ids array");

  auto& engine = get_engine(db);
  json body;
  body["summaries"] = json::array();

  for (const auto& rid : request_body["room_ids"]) {
    if (!rid.is_string()) continue;
    std::string room_id = rid.get<std::string>();

    if (!engine.can_user_see_room(room_id, auth.user_id)) continue;

    auto summary = engine.compute_membership_summary(room_id, auth.user_id);
    body["summaries"].push_back(summary.to_json());
  }

  return make_response(200, body);
}

// ============================================================================
// Rate limit status query
// ============================================================================

json handle_membership_rate_limit_status(DatabasePool& db,
                                           const std::string& auth_header,
                                           const std::string& access_token_param) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");

  json body;
  body["total_membership_events"] = g_membership_event_count.load();
  body["lazy_load_computations"] = g_lazy_load_computations.load();
  body["hero_selections"] = g_hero_selections.load();
  body["rate_limit_hits"] = g_rate_limit_hits.load();

  return make_response(200, body);
}

} // namespace progressive::handlers
