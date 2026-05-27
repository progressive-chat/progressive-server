// ============================================================================
// room_join_handler.cpp — Matrix Room Membership Operations, Full SQL,
//                          Event Creation, State Management, Authorization,
//                          Joins, Leaves, Kicks, Bans, Invites, Knocks,
//                          Restricted Joins, Federation Join Handlers,
//                          Membership History, and Forgotten Rooms
//
// Implements:
//   - RoomMembershipStore: Full SQL DDL for room_memberships,
//     current_state_events, room_membership_history, knock_queue,
//     room_forgotten, and related tables. Complete CRUD with transaction-safe
//     methods.
//   - RoomJoinEngine: Join room flow — validate join rules, check bans,
//     check membership state, create m.room.member join event, persist
//     membership, update current state, handle restricted joins, notify
//     room members, update user directory, update room stats.
//   - RoomLeaveEngine: Leave room flow — create m.room.member leave event,
//     update membership to "leave", remove from current state, notify
//     members, handle room-level cleanup, support leave reasons.
//   - RoomKickEngine: Kick user from room — authorization (power level
//     check), create m.room.member leave event with sender being kicker,
//     update membership, notify kicked user, optional reason.
//   - RoomBanEngine: Ban user from room — authorization (power level
//     check, cannot ban users with higher/equal power), create
//     m.room.member ban event, kick if currently joined, notify users,
//     track ban reason, unban support.
//   - RoomInviteEngine: Invite user to room — authorization (power level
//     check), check membership state (no double invite), create
//     m.room.member invite event, persist invite, notify invitee, third-party
//     invite fallback, invite expiry, invite acceptance/rejection.
//   - RoomKnockEngine: Handle knock requests on knock/knock_restricted rooms —
//     validate knock rules, persist knock, notify room admins, knock
//     approval/rejection, knock expiry, deduplication.
//   - MembershipStateResolver: State resolution for m.room.member events across
//     state groups — resolve correct membership for each user in room,
//     handle join/leave/invite/ban/knock ordering, state group inheritance,
//     conflict resolution.
//   - EventCreator: Create properly formatted m.room.member events with
//     correct content, prev_events, auth_events, depth, state_key.
//     Generate event IDs per room version rules.
//   - FederationJoinHandler: Handle joins from federated servers — validate
//     remote join events, send_membership_event via /send_join, process
//     incoming state from remote server, resolve join authorization across
//     federation, handle partial state joins, send join to other servers.
//   - MembershipHistoryTracker: Track complete membership history for each
//     (room, user) pair — all membership transitions with timestamps,
//     event IDs, and metadata. Support query, export, audit.
//   - ForgottenRoomManager: Mark rooms as forgotten by users, hide from
//     room list and sync, support unforget, track forgotten state.
//   - RoomJoinCoordinator: Orchestrator that ties together all the above
//     components. Handles the complete lifecycle from request validation
//     through event creation, persistence, notification, and federation.
//
// Namespace: progressive::
// Equivalent to:
//   synapse/handlers/room_member.py (~2500 lines) — Room member handler
//   synapse/storage/databases/main/roommember.py (~1800 lines) — Membership store
//   synapse/event_auth.py (~400 lines) — Event auth checks
//   synapse/handlers/federation.py (join handling, ~600 lines)
//   synapse/handlers/room.py (~300 lines) — Room-level operations
//   matrix-org/matrix-spec: Client-Server API /rooms/{roomId}/join|leave|kick|ban|invite
//   matrix-org/matrix-spec: Server-Server API /send_join, /make_join
//
// Target: 3000+ lines of production-grade C++ with explicit descriptions.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
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
class RoomMembershipStore;
class RoomJoinEngine;
class RoomLeaveEngine;
class RoomKickEngine;
class RoomBanEngine;
class RoomInviteEngine;
class RoomKnockEngine;
class MembershipStateResolver;
class EventCreator;
class FederationJoinHandler;
class MembershipHistoryTracker;
class ForgottenRoomManager;
class RoomJoinCoordinator;

// ============================================================================
// Forward-declare txn helpers for this compilation unit
// ============================================================================
namespace storage {
class DatabasePool;
class LoggingTransaction;

// ---------- convenience time helper ----------
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
// Membership types — all valid Matrix membership states
// ============================================================================

// Enumerates all valid room membership states per the Matrix specification.
// Each value maps to the content.membership field in m.room.member events.
enum class Membership : uint8_t {
  kJoin = 0,          // User is a full member of the room
  kLeave = 1,         // User has left the room (was previously joined)
  kInvite = 2,        // User has been invited to join
  kBan = 3,           // User is banned from the room
  kKnock = 4,         // User has knocked to request entry (spec v7+)
  kNone = 5,          // No membership (not present in room state)
  kUnknown = 6,       // Unknown/invalid membership value
};

// Maps a C++ string to a Membership enum value. Case-sensitive comparison
// against the Matrix spec's canonical membership values. Returns kUnknown
// for unrecognized strings.
inline Membership membership_from_string(const std::string& s) {
  if (s == "join")   return Membership::kJoin;
  if (s == "leave")  return Membership::kLeave;
  if (s == "invite") return Membership::kInvite;
  if (s == "ban")    return Membership::kBan;
  if (s == "knock")  return Membership::kKnock;
  return Membership::kUnknown;
}

// Maps a Membership enum value to the canonical Matrix string representation.
inline std::string membership_to_string(Membership m) {
  switch (m) {
    case Membership::kJoin:   return "join";
    case Membership::kLeave:  return "leave";
    case Membership::kInvite: return "invite";
    case Membership::kBan:    return "ban";
    case Membership::kKnock:  return "knock";
    default:                   return "";
  }
}

// ============================================================================
// Join authorization result — outcome of a join authorization check
// ============================================================================

// Encapsulates the result of an authorization check for room membership
// operations. Includes whether the action is permitted, an error code
// and message for denial, and optional metadata such as the authorizing
// room for restricted joins.
struct AuthResult {
  bool allowed = true;                  // Whether the action is authorized
  std::string errcode;                  // Matrix error code on denial (e.g., "M_FORBIDDEN")
  std::string error;                    // Human-readable error message
  std::optional<std::string> authorizing_room;  // Room that authorizes (restricted joins)
  bool requires_invite = false;         // Whether an invite would allow the action
  bool is_banned = false;               // Whether the user is banned

  // Construct an allow result
  static AuthResult allow() {
    AuthResult r;
    r.allowed = true;
    return r;
  }

  // Construct a deny result with error code and message
  static AuthResult deny(const std::string& code, const std::string& msg) {
    AuthResult r;
    r.allowed = false;
    r.errcode = code;
    r.error = msg;
    return r;
  }
};

// ============================================================================
// Random ID generation helpers (used for event IDs, token generation)
// ============================================================================

// Thread-local random engine for generating unique IDs without requiring
// a global mutex.
inline std::mt19937_64& random_engine() {
  static thread_local std::random_device rd;
  static thread_local std::mt19937_64 gen(rd());
  return gen;
}

// Generate a random alphanumeric string of the specified length.
// Uses characters [A-Za-z0-9] for URL-safe random tokens.
inline std::string random_string(size_t length) {
  static const char charset[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static const size_t max_index = sizeof(charset) - 2;

  std::uniform_int_distribution<size_t> dist(0, max_index);
  std::string result;
  result.reserve(length);
  for (size_t i = 0; i < length; ++i) {
    result += charset[dist(random_engine())];
  }
  return result;
}

// Generate a Matrix event ID in the format "$<base64hash><localpart>".
// The server_name portion encodes the domain and a random component.
inline std::string generate_event_id(const std::string& domain) {
  std::string localpart = random_string(40);
  return "$" + localpart + ":" + domain;
}

// ============================================================================
// 1. RoomMembershipStore — Full SQL DDL and CRUD for room membership tables
// ============================================================================
//
// This store provides the complete persistence layer for room membership
// operations. It manages the following tables:
//   - room_memberships: Current membership state for every (room, user) pair.
//   - room_membership_history: Full audit trail of all membership transitions.
//   - knock_queue: Active knock requests awaiting admin approval.
//   - room_forgotten: Rooms marked as forgotten by specific users.
//   - room_join_time_tracking: Timestamps of first/last join per (room, user).
//   - room_ban_list: Active bans with reasons and expiry.
//   - room_invite_state: Active invitations with metadata.
//   - room_member_profile: Cached display_name and avatar_url per (room, user).
//   - room_hosts: Servers participating in a room (for federation).
//
// All methods use the _txn suffix and accept a LoggingTransaction reference.
// DDL is provided via a static create_tables method.
//
class RoomMembershipStore {
public:
  explicit RoomMembershipStore(DatabasePool& db) : db_(db) {}

  // ---- DDL: create all tables and indices ----
  static void create_tables(LoggingTransaction& txn);

  // ---- room_memberships: current membership state ----
  // Upserts the membership state for a (room_id, user_id) pair. On conflict,
  // updates the existing row. This is the canonical source of truth for
  // "is this user currently a member of this room?"
  void upsert_membership_txn(LoggingTransaction& txn,
                              const std::string& room_id,
                              const std::string& user_id,
                              const std::string& membership,
                              const std::string& event_id,
                              const std::string& sender,
                              int64_t origin_server_ts,
                              const std::optional<std::string>& display_name = std::nullopt,
                              const std::optional<std::string>& avatar_url = std::nullopt,
                              const std::optional<std::string>& reason = std::nullopt);

  // Retrieves the membership state for a (room_id, user_id) pair.
  // Returns an empty json object if no membership exists.
  json get_membership_txn(LoggingTransaction& txn,
                           const std::string& room_id,
                           const std::string& user_id);

  // Returns the membership string (e.g., "join", "leave", "ban") for a
  // (room_id, user_id) pair, or empty string if no record exists.
  std::string get_membership_state_txn(LoggingTransaction& txn,
                                        const std::string& room_id,
                                        const std::string& user_id);

  // Checks whether a user is currently in the room with the given membership.
  bool is_membership_txn(LoggingTransaction& txn,
                          const std::string& room_id,
                          const std::string& user_id,
                          const std::string& membership);

  // Deletes a membership entry (used when all history is redacted/purged).
  void delete_membership_txn(LoggingTransaction& txn,
                              const std::string& room_id,
                              const std::string& user_id);

  // ---- multi-user queries ----
  // Returns all users with a given membership in a room, as JSON array of
  // {user_id, display_name, avatar_url} objects.
  json get_users_with_membership_txn(LoggingTransaction& txn,
                                      const std::string& room_id,
                                      const std::string& membership,
                                      int limit = 1000);

  // Returns all rooms for a user with a given membership, as JSON array of
  // {room_id} objects.
  json get_rooms_for_user_with_membership_txn(LoggingTransaction& txn,
                                               const std::string& user_id,
                                               const std::string& membership,
                                               int limit = 1000);

  // Count users with a particular membership in a room.
  int64_t count_members_txn(LoggingTransaction& txn,
                             const std::string& room_id,
                             const std::string& membership);

  // Count rooms for a user with a particular membership.
  int64_t count_rooms_for_user_txn(LoggingTransaction& txn,
                                    const std::string& user_id,
                                    const std::string& membership);

  // Returns all distinct memberships for a user across all rooms.
  json get_all_memberships_for_user_txn(LoggingTransaction& txn,
                                         const std::string& user_id,
                                         int limit = 1000);

  // Batch check: which of the given user_ids are joined to the room?
  std::set<std::string> filter_joined_users_txn(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::vector<std::string>& user_ids);

  // Get the set of user IDs that both users share rooms with.
  std::set<std::string> get_shared_rooms_txn(LoggingTransaction& txn,
                                              const std::string& user_id_a,
                                              const std::string& user_id_b);

  // ---- room_membership_history: audit trail ----
  // Records a membership transition event, creating a complete audit trail
  // of every membership change for every (room, user) pair.
  void record_membership_event_txn(LoggingTransaction& txn,
                                    const std::string& room_id,
                                    const std::string& user_id,
                                    const std::string& prev_membership,
                                    const std::string& new_membership,
                                    const std::string& event_id,
                                    const std::string& sender,
                                    int64_t timestamp,
                                    const std::optional<std::string>& reason = std::nullopt,
                                    const std::optional<json>& content = std::nullopt);

  // Retrieves the complete membership history for a (room, user) pair,
  // ordered by timestamp ascending (oldest first).
  json get_membership_history_txn(LoggingTransaction& txn,
                                   const std::string& room_id,
                                   const std::string& user_id,
                                   int limit = 500);

  // Retrieves recent membership events in a room (all users),
  // ordered by timestamp descending (newest first).
  json get_recent_membership_events_txn(LoggingTransaction& txn,
                                         const std::string& room_id,
                                         int limit = 100);

  // ---- knock_queue: knock requests awaiting approval ----
  // Inserts a knock request into the queue. Rejects duplicates.
  void enqueue_knock_txn(LoggingTransaction& txn,
                          const std::string& room_id,
                          const std::string& user_id,
                          const std::string& event_id,
                          const std::string& reason,
                          int64_t timestamp);

  // Retrieves all pending knock requests for a room.
  json get_pending_knocks_txn(LoggingTransaction& txn,
                               const std::string& room_id,
                               int limit = 100);

  // Retrieves all knock requests made by a specific user.
  json get_knocks_by_user_txn(LoggingTransaction& txn,
                               const std::string& user_id,
                               int limit = 100);

  // Marks a knock as approved (removes from pending queue).
  void approve_knock_txn(LoggingTransaction& txn,
                          const std::string& room_id,
                          const std::string& user_id,
                          const std::string& approved_by,
                          int64_t approved_ts);

  // Marks a knock as rejected (removes from pending queue).
  void reject_knock_txn(LoggingTransaction& txn,
                         const std::string& room_id,
                         const std::string& user_id,
                         const std::string& rejected_by,
                         const std::string& rejection_reason,
                         int64_t rejected_ts);

  // Checks whether a user has a pending knock for a room.
  bool has_pending_knock_txn(LoggingTransaction& txn,
                              const std::string& room_id,
                              const std::string& user_id);

  // Removes expired knocks (older than the specified cutoff time).
  int64_t purge_expired_knocks_txn(LoggingTransaction& txn,
                                    int64_t older_than_ts);

  // ---- room_forgotten: rooms marked as forgotten ----
  // Marks a room as forgotten for a user. Forgotten rooms are hidden
  // from room lists and not included in incremental sync.
  void forget_room_txn(LoggingTransaction& txn,
                        const std::string& user_id,
                        const std::string& room_id,
                        int64_t timestamp);

  // Unmarks a forgotten room, restoring it to the user's room list.
  void unforget_room_txn(LoggingTransaction& txn,
                          const std::string& user_id,
                          const std::string& room_id);

  // Checks whether a room is forgotten for a user.
  bool is_room_forgotten_txn(LoggingTransaction& txn,
                              const std::string& user_id,
                              const std::string& room_id);

  // Returns all forgotten rooms for a user.
  json get_forgotten_rooms_txn(LoggingTransaction& txn,
                               const std::string& user_id,
                               int limit = 500);

  // ---- room_join_time_tracking: join timestamps ----
  // Records the first join time for a (room, user) pair (idempotent).
  void record_first_join_txn(LoggingTransaction& txn,
                              const std::string& room_id,
                              const std::string& user_id,
                              int64_t timestamp);

  // Updates the last join time for a (room, user) pair.
  void record_last_join_txn(LoggingTransaction& txn,
                             const std::string& room_id,
                             const std::string& user_id,
                             int64_t timestamp);

  // Gets the join timestamps for a (room, user) pair.
  json get_join_times_txn(LoggingTransaction& txn,
                           const std::string& room_id,
                           const std::string& user_id);

  // ---- room_ban_list: active bans with metadata ----
  // Records a ban for a user in a room.
  void record_ban_txn(LoggingTransaction& txn,
                       const std::string& room_id,
                       const std::string& user_id,
                       const std::string& banned_by,
                       const std::string& reason,
                       int64_t timestamp);

  // Removes a ban (unban), marking it as revoked.
  void unban_txn(LoggingTransaction& txn,
                  const std::string& room_id,
                  const std::string& user_id,
                  const std::string& unbanned_by,
                  int64_t timestamp);

  // Checks whether a user is banned from a room.
  bool is_banned_txn(LoggingTransaction& txn,
                      const std::string& room_id,
                      const std::string& user_id);

  // Returns all active bans in a room.
  json get_active_bans_txn(LoggingTransaction& txn,
                            const std::string& room_id,
                            int limit = 500);

  // Returns all active bans against a user across all rooms.
  json get_bans_for_user_txn(LoggingTransaction& txn,
                              const std::string& user_id,
                              int limit = 100);

  // ---- room_invite_state: active invitations ----
  // Records an invitation for a user in a room.
  void record_invite_txn(LoggingTransaction& txn,
                          const std::string& room_id,
                          const std::string& user_id,
                          const std::string& invited_by,
                          int64_t timestamp,
                          const std::optional<std::string>& reason = std::nullopt);

  // Marks an invitation as accepted.
  void accept_invite_txn(LoggingTransaction& txn,
                          const std::string& room_id,
                          const std::string& user_id,
                          int64_t accepted_ts);

  // Marks an invitation as rejected.
  void reject_invite_txn(LoggingTransaction& txn,
                          const std::string& room_id,
                          const std::string& user_id,
                          int64_t rejected_ts);

  // Returns pending invitations for a user.
  json get_pending_invites_txn(LoggingTransaction& txn,
                                const std::string& user_id,
                                int limit = 500);

  // Returns pending invitations for a room.
  json get_pending_invites_for_room_txn(LoggingTransaction& txn,
                                         const std::string& room_id,
                                         int limit = 500);

  // Checks whether a user has a pending invitation to a room.
  bool has_pending_invite_txn(LoggingTransaction& txn,
                               const std::string& room_id,
                               const std::string& user_id);

  // ---- room_member_profile: cached profile info ----
  // Updates the cached profile for a user in a room's membership context.
  void update_member_profile_txn(LoggingTransaction& txn,
                                  const std::string& room_id,
                                  const std::string& user_id,
                                  const std::optional<std::string>& display_name,
                                  const std::optional<std::string>& avatar_url);

  // Retrieves the cached profile for a user in a room.
  json get_member_profile_txn(LoggingTransaction& txn,
                               const std::string& room_id,
                               const std::string& user_id);

  // ---- room_hosts: servers participating in a room ----
  // Records a server as a host for a room (for federation).
  void add_room_host_txn(LoggingTransaction& txn,
                          const std::string& room_id,
                          const std::string& server_name);

  // Removes a server as a host for a room.
  void remove_room_host_txn(LoggingTransaction& txn,
                             const std::string& room_id,
                             const std::string& server_name);

  // Returns all servers hosting a room.
  json get_room_hosts_txn(LoggingTransaction& txn,
                           const std::string& room_id);

  // ---- maintenance & stats ----
  // Deletes all membership data for a room (used on room deletion/purge).
  void delete_all_for_room_txn(LoggingTransaction& txn,
                                const std::string& room_id);

  // Deletes all membership data for a user (used on user deactivation).
  void delete_all_for_user_txn(LoggingTransaction& txn,
                                const std::string& user_id);

  // Returns membership stats for a room: counts of each membership type.
  json get_room_membership_stats_txn(LoggingTransaction& txn,
                                      const std::string& room_id);

  // Returns total membership count across all tables for capacity planning.
  json get_store_stats_txn(LoggingTransaction& txn);

private:
  DatabasePool& db_;
};

// ============================================================================
// 2. EventCreator — Build properly formatted m.room.member events
// ============================================================================
//
// Creates complete m.room.member events with all required fields:
//   - event_id: Generated per room version rules
//   - type: "m.room.member"
//   - sender: The user performing the action
//   - state_key: The user whose membership is changing
//   - content.membership: join, leave, invite, ban, knock
//   - content.displayname: Optional display name
//   - content.avatar_url: Optional avatar URL
//   - content.reason: Optional reason for the membership change
//   - origin_server_ts: Timestamp in milliseconds
//   - prev_events: List of previous event IDs for linearization
//   - auth_events: List of auth event IDs for authorization
//   - depth: Current depth + 1
//   - unsigned: Redacted_because, age, etc.
//   - room_id: The room this event belongs to
//
class EventCreator {
public:
  EventCreator() = default;

  // Build a complete m.room.member event JSON object suitable for persisting
  // and sending over federation. Returns a fully-constructed JSON event.
  //
  // Parameters:
  //   domain: The homeserver domain (for event ID generation)
  //   room_id: The room this event belongs to
  //   sender: The user performing the action (the actor)
  //   state_key: The user whose membership is changing (the subject)
  //   membership: The new membership state (join/leave/invite/ban/knock)
  //   prev_events: Previous event IDs (for linearizing the event DAG)
  //   auth_events: Auth event IDs (for authorization checks)
  //   depth: The event depth (current max depth + 1)
  //   display_name: Optional display name for the subject
  //   avatar_url: Optional avatar URL for the subject
  //   reason: Optional reason for the membership change
  //   is_direct: Whether this is a direct (1:1) room invite
  json build_member_event(const std::string& domain,
                           const std::string& room_id,
                           const std::string& sender,
                           const std::string& state_key,
                           const std::string& membership,
                           const std::vector<std::string>& prev_events,
                           const std::vector<std::string>& auth_events,
                           int64_t depth,
                           const std::optional<std::string>& display_name = std::nullopt,
                           const std::optional<std::string>& avatar_url = std::nullopt,
                           const std::optional<std::string>& reason = std::nullopt,
                           bool is_direct = false);

  // Build a leave event with explicit membership="leave" and sender being
  // either the user themselves (voluntary leave) or a kicker.
  json build_leave_event(const std::string& domain,
                          const std::string& room_id,
                          const std::string& sender,
                          const std::string& state_key,
                          const std::vector<std::string>& prev_events,
                          const std::vector<std::string>& auth_events,
                          int64_t depth,
                          const std::optional<std::string>& reason = std::nullopt,
                          bool is_kick = false);

  // Build an invite event for inviting a user. Includes is_direct flag
  // in the content for direct (1:1) room invitations.
  json build_invite_event(const std::string& domain,
                           const std::string& room_id,
                           const std::string& sender,
                           const std::string& state_key,
                           const std::vector<std::string>& prev_events,
                           const std::vector<std::string>& auth_events,
                           int64_t depth,
                           const std::optional<std::string>& reason = std::nullopt,
                           bool is_direct = false);

  // Build a ban event with optional reason.
  json build_ban_event(const std::string& domain,
                        const std::string& room_id,
                        const std::string& sender,
                        const std::string& state_key,
                        const std::vector<std::string>& prev_events,
                        const std::vector<std::string>& auth_events,
                        int64_t depth,
                        const std::optional<std::string>& reason = std::nullopt);

  // Build a knock event. Knock events have membership="knock" and
  // include a reason field in the content describing why the user
  // wants to join.
  json build_knock_event(const std::string& domain,
                          const std::string& room_id,
                          const std::string& sender,
                          const std::string& state_key,
                          const std::vector<std::string>& prev_events,
                          const std::vector<std::string>& auth_events,
                          int64_t depth,
                          const std::optional<std::string>& reason = std::nullopt);

  // Build the content portion of an m.room.member event. This is the
  // inner "content" JSON that gets embedded in the event.
  json build_member_content(const std::string& membership,
                             const std::optional<std::string>& display_name = std::nullopt,
                             const std::optional<std::string>& avatar_url = std::nullopt,
                             const std::optional<std::string>& reason = std::nullopt,
                             bool is_direct = false);

  // Validate that an m.room.member event has all required fields and
  // valid values. Returns a pair of (valid, error_message).
  static std::pair<bool, std::string> validate_member_event(const json& event);

  // Extract the membership from an m.room.member event content.
  static std::string extract_membership(const json& content);

  // Extract the display_name from an m.room.member event content.
  static std::optional<std::string> extract_display_name(const json& content);

private:
  // Build the standard event skeleton with type, sender, origin_server_ts,
  // origin, prev_events, auth_events, depth, room_id.
  json build_event_skeleton(const std::string& domain,
                             const std::string& room_id,
                             const std::string& sender,
                             const std::string& type,
                             const std::string& state_key,
                             const std::vector<std::string>& prev_events,
                             const std::vector<std::string>& auth_events,
                             int64_t depth,
                             const json& content);
};

// ============================================================================
// 3. MembershipStateResolver — Resolve correct membership from state groups
// ============================================================================
//
// Matrix rooms maintain state via state groups. The current state of a room
// is determined by resolving the state from all active state groups.
// This class resolves the correct m.room.member state for each user
// by traversing state group chains, handling conflicts via version-specific
// state resolution algorithms.
//
class MembershipStateResolver {
public:
  MembershipStateResolver() = default;

  // Resolve the current membership for a user in a room, given the set
  // of state groups at the current state. Returns the resolved membership
  // string (e.g., "join", "leave", etc.), or empty string if not found.
  //
  // Resolution strategy:
  //   1. Gather all m.room.member events from all active state groups
  //   2. Apply room-version-specific state resolution:
  //      - v1-v2, v3-v6: Origin server timestamp tiebreak
  //      - v7-v9:   Modified with power level consideration
  //      - v10+:    Further refined resolution
  //   3. Return the winning membership
  std::string resolve_membership(
      const std::string& room_id,
      const std::string& user_id,
      const std::string& room_version,
      const std::vector<std::string>& state_group_ids,
      LoggingTransaction& txn);

  // Bulk resolve: returns a map of user_id -> membership for all users
  // in the room, given the current state group set.
  std::unordered_map<std::string, std::string> resolve_all_memberships(
      const std::string& room_id,
      const std::string& room_version,
      const std::vector<std::string>& state_group_ids,
      LoggingTransaction& txn);

  // Resolve the authorizing membership for restricted join checks.
  // Determines whether a user has membership in a room that authorizes
  // restricted joins. Returns the room_id of the authorizing room, or
  // empty string if not authorized via any restricted join rule.
  std::optional<std::string> resolve_restricted_join_authorization(
      const std::string& room_id,
      const std::string& user_id,
      const std::vector<std::string>& allowed_room_ids,
      LoggingTransaction& txn);

  // Determine whether a state group includes a specific membership state.
  // Used during state resolution to gather all candidate events.
  bool state_group_has_member_event(
      const std::string& state_group_id,
      const std::string& room_id,
      const std::string& user_id,
      LoggingTransaction& txn);

private:
  // Apply room version 1-2 state resolution: origin_server_ts wins,
  // then lexicographic event_id comparison on tie.
  std::string resolve_v1_v2(const std::vector<json>& candidate_events);

  // Apply room version 3-9 state resolution: similar to v1-v2 with
  // modified tiebreaking for state events.
  std::string resolve_v3_v9(const std::vector<json>& candidate_events);

  // Apply room version 10+ state resolution.
  std::string resolve_v10_plus(const std::vector<json>& candidate_events);
};

// ============================================================================
// 4. RoomJoinEngine — Handle /rooms/{roomId}/join flow
// ============================================================================
//
// Orchestrates the complete join flow for a user joining a room:
//   1. Validate the room exists and user is not already joined
//   2. Check join rules (public, invite, knock, restricted)
//   3. Check if user is banned
//   4. For restricted rooms: verify user has membership in an allowed room
//   5. Create the m.room.member join event
//   6. Persist membership in the store
//   7. Update current state
//   8. Notify room members
//   9. Update user directory
//  10. Update room stats
//  11. Propagate join to federated servers
//
class RoomJoinEngine {
public:
  RoomJoinEngine(std::shared_ptr<RoomMembershipStore> store,
                 std::shared_ptr<EventCreator> event_creator,
                 std::shared_ptr<MembershipStateResolver> state_resolver)
    : store_(std::move(store)),
      event_creator_(std::move(event_creator)),
      state_resolver_(std::move(state_resolver)) {}

  // === Core join operation ===
  // Attempts to join a user to a room. Returns a JSON result containing
  // the room_id on success, or an error response on failure.
  //
  // This is the primary entry point called by the REST handler
  // for POST /_matrix/client/v3/rooms/{roomId}/join.
  //
  // Parameters:
  //   domain:   The homeserver domain
  //   room_id:  The room to join
  //   user_id:  The user attempting to join
  //   room_version: The Matrix room version
  //   third_party_signed: Optional signed third-party invite data
  //   reason:   Optional reason for joining (shown in membership event)
  //   txn:      Active database transaction
  //
  // Returns: JSON {room_id: "...", event_id: "..."} on success
  json join_room(const std::string& domain,
                  const std::string& room_id,
                  const std::string& user_id,
                  const std::string& room_version,
                  const std::optional<json>& third_party_signed,
                  const std::optional<std::string>& reason,
                  LoggingTransaction& txn);

  // === Pre-join validation ===
  // Checks all conditions that must be met before a join is allowed.
  // Returns an authorization result with allow/deny and error details.
  AuthResult validate_join(const std::string& room_id,
                            const std::string& user_id,
                            const std::string& room_version,
                            const std::string& join_rule,
                            const json& allow_list,
                            LoggingTransaction& txn);

  // === Join via restricted rooms ===
  // Checks if a user can join a restricted room by virtue of membership
  // in one or more allowed rooms (or spaces).
  AuthResult check_restricted_join(const std::string& room_id,
                                    const std::string& user_id,
                                    const json& allow_rules,
                                    LoggingTransaction& txn);

  // === Join via knock approval ===
  // When a knock is approved by a room admin, this method performs the
  // actual join. Different from regular join because it doesn't re-check
  // join rules (the admin approval bypasses that).
  json join_via_knock_approval(const std::string& domain,
                                const std::string& room_id,
                                const std::string& user_id,
                                const std::string& approved_by,
                                const std::string& room_version,
                                LoggingTransaction& txn);

  // === Join via invitation ===
  // When a user accepts an invitation, this method performs the actual
  // join. Doesn't re-check join rules since the invite bypasses them.
  json join_via_invite(const std::string& domain,
                        const std::string& room_id,
                        const std::string& user_id,
                        const std::string& room_version,
                        LoggingTransaction& txn);

  // === Re-join after leave ===
  // Handles the case where a user is re-joining a room they previously left.
  // Used by the sync engine to handle re-discovered joined rooms.
  json rejoin_room(const std::string& domain,
                    const std::string& room_id,
                    const std::string& user_id,
                    const std::string& room_version,
                    LoggingTransaction& txn);

private:
  // Performs the actual event creation, persistence, state update, and
  // notification steps common to all join paths.
  json execute_join(const std::string& domain,
                     const std::string& room_id,
                     const std::string& user_id,
                     const std::string& sender,
                     const std::string& room_version,
                     const std::optional<std::string>& reason,
                     const std::optional<std::string>& display_name,
                     const std::optional<std::string>& avatar_url,
                     LoggingTransaction& txn);

  // Get the current set of prev_events for the room (forward extremities).
  std::vector<std::string> get_prev_events(const std::string& room_id,
                                            LoggingTransaction& txn);

  // Get the current set of auth_events for the room.
  std::vector<std::string> get_auth_events(const std::string& room_id,
                                            LoggingTransaction& txn);

  // Get the current max depth for the room.
  int64_t get_max_depth(const std::string& room_id,
                         LoggingTransaction& txn);

  // Notify room members about a membership change (used for push,
  // presence, and sync updates).
  void notify_membership_change(const std::string& room_id,
                                 const std::string& user_id,
                                 const std::string& membership,
                                 LoggingTransaction& txn);

  std::shared_ptr<RoomMembershipStore> store_;
  std::shared_ptr<EventCreator> event_creator_;
  std::shared_ptr<MembershipStateResolver> state_resolver_;
};

// ============================================================================
// 5. RoomLeaveEngine — Handle /rooms/{roomId}/leave flow
// ============================================================================
//
// Handles voluntary leave operations. A user can leave any room they
// are joined to. The leave flow:
//   1. Validate the user is currently joined
//   2. Create the m.room.member leave event (sender == state_key)
//   3. Update membership to "leave"
//   4. Remove from current state
//   5. Notify room members
//   6. Update user's room list
//
class RoomLeaveEngine {
public:
  RoomLeaveEngine(std::shared_ptr<RoomMembershipStore> store,
                  std::shared_ptr<EventCreator> event_creator)
    : store_(std::move(store)),
      event_creator_(std::move(event_creator)) {}

  // Core leave operation: user voluntarily leaves a room.
  // Returns JSON containing the leave event_id on success.
  json leave_room(const std::string& domain,
                   const std::string& room_id,
                   const std::string& user_id,
                   const std::string& room_version,
                   const std::optional<std::string>& reason,
                   LoggingTransaction& txn);

  // Validate that a leave is possible (user is indeed joined).
  std::pair<bool, std::string> validate_leave(const std::string& room_id,
                                               const std::string& user_id,
                                               LoggingTransaction& txn);

private:
  std::shared_ptr<RoomMembershipStore> store_;
  std::shared_ptr<EventCreator> event_creator_;
};

// ============================================================================
// 6. RoomKickEngine — Handle /rooms/{roomId}/kick flow
// ============================================================================
//
// Handles kick operations: one user (the kicker) forces another user
// (the kicked) to leave the room. The kick flow:
//   1. Validate kicker has permission (power level check)
//   2. Validate the target user is currently joined
//   3. Validate kicker cannot kick users with equal/higher power level
//   4. Create the m.room.member leave event (sender = kicker, state_key = kicked)
//   5. Update membership to "leave"
//   6. Notify kicked user and room members
//
class RoomKickEngine {
public:
  RoomKickEngine(std::shared_ptr<RoomMembershipStore> store,
                 std::shared_ptr<EventCreator> event_creator)
    : store_(std::move(store)),
      event_creator_(std::move(event_creator)) {}

  // Kick a user from a room.
  // Parameters:
  //   domain:  Homeserver domain
  //   room_id: The room
  //   kicker:  The user performing the kick
  //   kicked:  The user being kicked
  //   room_version: Room version
  //   reason:  Optional reason for the kick
  json kick_user(const std::string& domain,
                  const std::string& room_id,
                  const std::string& kicker,
                  const std::string& kicked,
                  const std::string& room_version,
                  const std::optional<std::string>& reason,
                  LoggingTransaction& txn);

  // Validate that a kick is authorized.
  // Returns (allowed, error_message). Checks:
  //   - Kicker has "kick" power level
  //   - Kicker's power level > kicked user's power level
  //   - Target is actually in the room
  std::pair<bool, std::string> validate_kick(const std::string& room_id,
                                              const std::string& kicker,
                                              const std::string& kicked,
                                              LoggingTransaction& txn);

private:
  std::shared_ptr<RoomMembershipStore> store_;
  std::shared_ptr<EventCreator> event_creator_;
};

// ============================================================================
// 7. RoomBanEngine — Handle /rooms/{roomId}/ban and /unban flow
// ============================================================================
//
// Handles ban and unban operations. Banning removes a user from the room
// and prevents them from rejoining. The ban flow:
//   1. Validate banner has permission (power level check)
//   2. Validate banner cannot ban users with equal/higher power level
//   3. Create the m.room.member ban event
//   4. Update membership to "ban"
//   5. If the user is currently joined, kick them first
//   6. Record the active ban
//   7. Notify banned user and room members
//
// Unbanning reverses a ban, allowing the user to rejoin if invited or if
// the room is public.
//
class RoomBanEngine {
public:
  RoomBanEngine(std::shared_ptr<RoomMembershipStore> store,
                std::shared_ptr<EventCreator> event_creator)
    : store_(std::move(store)),
      event_creator_(std::move(event_creator)) {}

  // Ban a user from a room. If the user is currently in the room,
  // they are also kicked.
  json ban_user(const std::string& domain,
                 const std::string& room_id,
                 const std::string& banner,
                 const std::string& banned,
                 const std::string& room_version,
                 const std::optional<std::string>& reason,
                 LoggingTransaction& txn);

  // Unban a user, allowing them to potentially rejoin.
  json unban_user(const std::string& domain,
                   const std::string& room_id,
                   const std::string& unbanner,
                   const std::string& unbanned,
                   const std::string& room_version,
                   LoggingTransaction& txn);

  // Validate that a ban is authorized.
  std::pair<bool, std::string> validate_ban(const std::string& room_id,
                                             const std::string& banner,
                                             const std::string& banned,
                                             LoggingTransaction& txn);

  // Validate that an unban is authorized.
  std::pair<bool, std::string> validate_unban(const std::string& room_id,
                                               const std::string& unbanner,
                                               const std::string& unbanned,
                                               LoggingTransaction& txn);

private:
  std::shared_ptr<RoomMembershipStore> store_;
  std::shared_ptr<EventCreator> event_creator_;
};

// ============================================================================
// 8. RoomInviteEngine — Handle /rooms/{roomId}/invite flow
// ============================================================================
//
// Handles invitation operations: one user invites another to join a room.
// The invite flow:
//   1. Validate inviter has permission (power level check)
//   2. Validate target is not already a member (or banned)
//   3. Validate target doesn't already have a pending invite
//   4. Create the m.room.member invite event
//   5. Record the active invitation
//   6. Notify invitee (push notification, sync)
//   7. For direct rooms: set is_direct flag
//   8. Optionally propagate invite over federation
//
class RoomInviteEngine {
public:
  RoomInviteEngine(std::shared_ptr<RoomMembershipStore> store,
                   std::shared_ptr<EventCreator> event_creator)
    : store_(std::move(store)),
      event_creator_(std::move(event_creator)) {}

  // Invite a user to a room.
  json invite_user(const std::string& domain,
                    const std::string& room_id,
                    const std::string& inviter,
                    const std::string& invitee,
                    const std::string& room_version,
                    const std::optional<std::string>& reason,
                    bool is_direct,
                    LoggingTransaction& txn);

  // Accept an invitation (user joins the room after being invited).
  json accept_invite(const std::string& domain,
                      const std::string& room_id,
                      const std::string& user_id,
                      const std::string& room_version,
                      LoggingTransaction& txn);

  // Reject an invitation (user declines without joining).
  json reject_invite(const std::string& domain,
                      const std::string& room_id,
                      const std::string& user_id,
                      LoggingTransaction& txn);

  // Validate that an invite is authorized.
  std::pair<bool, std::string> validate_invite(const std::string& room_id,
                                                const std::string& inviter,
                                                const std::string& invitee,
                                                LoggingTransaction& txn);

private:
  std::shared_ptr<RoomMembershipStore> store_;
  std::shared_ptr<EventCreator> event_creator_;
};

// ============================================================================
// 9. RoomKnockEngine — Handle knock requests on knock/knock_restricted rooms
// ============================================================================
//
// Handles knock operations (Matrix spec v7+). A user can "knock" on a room
// with join_rules "knock" or "knock_restricted" to request entry.
// Room admins can then approve or reject the knock. The knock flow:
//   1. Validate room has knock or knock_restricted join rules
//   2. Validate user is not already a member, not banned
//   3. Validate user doesn't already have a pending knock
//   4. Create the m.room.member knock event
//   5. Persist the knock in the knock queue
//   6. Notify room admins (power level "kick" or higher)
//
class RoomKnockEngine {
public:
  RoomKnockEngine(std::shared_ptr<RoomMembershipStore> store,
                  std::shared_ptr<EventCreator> event_creator)
    : store_(std::move(store)),
      event_creator_(std::move(event_creator)) {}

  // Submit a knock request to a room.
  json submit_knock(const std::string& domain,
                     const std::string& room_id,
                     const std::string& user_id,
                     const std::string& room_version,
                     const std::string& reason,
                     LoggingTransaction& txn);

  // Validate that a knock can be submitted.
  std::pair<bool, std::string> validate_knock(const std::string& room_id,
                                               const std::string& user_id,
                                               LoggingTransaction& txn);

  // Approve a knock request (admin action), which effectively joins the user.
  json approve_knock(const std::string& domain,
                      const std::string& room_id,
                      const std::string& knocked_user,
                      const std::string& approved_by,
                      const std::string& room_version,
                      LoggingTransaction& txn);

  // Reject a knock request (admin action).
  json reject_knock(const std::string& domain,
                     const std::string& room_id,
                     const std::string& knocked_user,
                     const std::string& rejected_by,
                     const std::string& rejection_reason,
                     LoggingTransaction& txn);

  // Get all pending knocks for a room (admin action).
  json get_pending_knocks(const std::string& room_id,
                           LoggingTransaction& txn);

  // Purge all expired knocks (maintenance action).
  int64_t purge_expired_knocks(int64_t older_than_ts,
                                LoggingTransaction& txn);

private:
  std::shared_ptr<RoomMembershipStore> store_;
  std::shared_ptr<EventCreator> event_creator_;
};

// ============================================================================
// 10. FederationJoinHandler — Handle joins over federation
// ============================================================================
//
// Matrix federation requires servers to cooperate when users join rooms
// hosted on other servers. This class handles:
//   - Processing incoming /send_join requests from remote servers
//   - Sending /make_join and /send_join to remote servers
//   - Resolving join authorization across federated servers
//   - Handling partial state joins (joining before full state is synced)
//   - Propagating joins to other participating servers
//
class FederationJoinHandler {
public:
  explicit FederationJoinHandler(std::shared_ptr<RoomMembershipStore> store)
    : store_(std::move(store)) {}

  // Process an incoming /send_join request from a remote server.
  // The remote server has already performed a /make_join and is now
  // sending the completed event. We must:
  //   1. Validate the event signature from the originating server
  //   2. Validate join authorization (join rules, bans, etc.)
  //   3. Accept any new state events included with the join
  //   4. Persist the join event and update membership
  //   5. Return the current room state to the remote server
  //   6. Notify other federated servers of the new member
  //
  // Returns the complete room state response to send back.
  json handle_send_join(const std::string& room_id,
                          const std::string& event_id,
                          const json& event,
                          const std::string& room_version,
                          const std::string& origin,
                          LoggingTransaction& txn);

  // Make a /make_join request to a remote server to get a template
  // join event. This is the first step of the remote join flow:
  //   1. Contact the remote server for a /make_join
  //   2. Remote server returns event template + current state
  //   3. We sign the event and fill in missing fields
  //   4. We send the completed event via /send_join
  //
  // Returns the template event and room version from the remote server.
  json make_join(const std::string& room_id,
                  const std::string& user_id,
                  const std::string& remote_server,
                  LoggingTransaction& txn);

  // Send the completed join event to the remote server via /send_join.
  // This is the second step of the remote join flow. Returns the room
  // state that the remote server sends back.
  json send_join(const std::string& room_id,
                  const std::string& event_id,
                  const json& event,
                  const std::string& remote_server,
                  LoggingTransaction& txn);

  // Process incoming state from a federated join (/send_join response).
  // The remote server returns the full current room state, which we
  // must persist and integrate into our local state.
  json process_join_response(const std::string& room_id,
                              const std::string& user_id,
                              const json& remote_state,
                              const std::string& room_version,
                              LoggingTransaction& txn);

  // Notify other participating servers in the room that a new user
  // has joined. This is done after processing a remote join.
  void propagate_join_to_servers(const std::string& room_id,
                                  const std::string& user_id,
                                  const std::string& event_id,
                                  LoggingTransaction& txn);

  // Handle a join for a user on a remote server (outbound federation).
  // This is the complete flow: make_join -> complete event -> send_join.
  json join_remote_room(const std::string& room_id,
                         const std::string& user_id,
                         const std::string& remote_server,
                         const std::string& room_version,
                         const std::optional<std::string>& reason,
                         LoggingTransaction& txn);

private:
  // Validate the remote server's join event authorization.
  AuthResult validate_remote_join(const json& event,
                                   const std::string& room_id,
                                   const std::string& user_id,
                                   LoggingTransaction& txn);

  // Resolve and persist state events received from a remote server.
  void persist_remote_state(const std::string& room_id,
                             const json& state_events,
                             LoggingTransaction& txn);

  std::shared_ptr<RoomMembershipStore> store_;
};

// ============================================================================
// 11. MembershipHistoryTracker — Track and query membership event history
// ============================================================================
//
// Maintains a complete audit trail of all membership transitions for
// every (room, user) pair. Supports:
//   - Querying the full history for a user in a room
//   - Exporting membership history (GDPR data portability)
//   - Analyzing membership patterns (join/leave frequency)
//   - Detecting abuse (rapid join/leave cycles)
//
class MembershipHistoryTracker {
public:
  explicit MembershipHistoryTracker(std::shared_ptr<RoomMembershipStore> store)
    : store_(std::move(store)) {}

  // Record a membership transition in the history table.
  void record_transition(const std::string& room_id,
                          const std::string& user_id,
                          const std::string& prev_membership,
                          const std::string& new_membership,
                          const std::string& event_id,
                          const std::string& sender,
                          int64_t timestamp,
                          const std::optional<std::string>& reason,
                          LoggingTransaction& txn);

  // Get the complete membership history for a (room, user) pair.
  json get_history(const std::string& room_id,
                    const std::string& user_id,
                    int limit,
                    LoggingTransaction& txn);

  // Get recent membership changes in a room (all users).
  json get_recent_room_changes(const std::string& room_id,
                                int limit,
                                LoggingTransaction& txn);

  // Export all membership data for a user (GDPR data portability).
  json export_user_membership_data(const std::string& user_id,
                                    LoggingTransaction& txn);

  // Check if a user has had suspicious join/leave patterns.
  // Returns a JSON object with abuse indicators.
  json detect_suspicious_patterns(const std::string& user_id,
                                   LoggingTransaction& txn);

private:
  std::shared_ptr<RoomMembershipStore> store_;
};

// ============================================================================
// 12. ForgottenRoomManager — Manage forgotten rooms
// ============================================================================
//
// Users can mark rooms as "forgotten" to hide them from their room list
// and exclude them from sync responses. The forgotten state is stored
// per-user. Forgotten rooms can be "unforgotten" to restore visibility.
// After a room is forgotten and the user is not a member, the server
// may stop pulling updates for that room.
//
class ForgottenRoomManager {
public:
  explicit ForgottenRoomManager(std::shared_ptr<RoomMembershipStore> store)
    : store_(std::move(store)) {}

  // Mark a room as forgotten for a user.
  json forget_room(const std::string& user_id,
                    const std::string& room_id,
                    LoggingTransaction& txn);

  // Unmark a room as forgotten for a user.
  json unforget_room(const std::string& user_id,
                      const std::string& room_id,
                      LoggingTransaction& txn);

  // Get the list of forgotten rooms for a user.
  json get_forgotten_rooms(const std::string& user_id,
                            LoggingTransaction& txn);

  // Check if a room is forgotten by a user.
  bool is_forgotten(const std::string& user_id,
                    const std::string& room_id,
                    LoggingTransaction& txn);

  // Automatically forget rooms where the user has left and the room
  // has been inactive for a long time (configurable threshold).
  int64_t auto_forget_stale_rooms(const std::string& user_id,
                                   int64_t stale_threshold_ms,
                                   LoggingTransaction& txn);

private:
  std::shared_ptr<RoomMembershipStore> store_;
};

// ============================================================================
// 13. RoomJoinCoordinator — Master orchestrator for all room join operations
// ============================================================================
//
// Ties together all the individual engines and handlers into a single
// coordinating class. Provides convenience methods that delegate to the
// appropriate sub-component. This is the primary public interface for
// room membership operations.
//
class RoomJoinCoordinator {
public:
  RoomJoinCoordinator()
    : store_(std::make_shared<RoomMembershipStore>(db_)),
      event_creator_(std::make_shared<EventCreator>()),
      state_resolver_(std::make_shared<MembershipStateResolver>()),
      join_engine_(std::make_shared<RoomJoinEngine>(
          store_, event_creator_, state_resolver_)),
      leave_engine_(std::make_shared<RoomLeaveEngine>(store_, event_creator_)),
      kick_engine_(std::make_shared<RoomKickEngine>(store_, event_creator_)),
      ban_engine_(std::make_shared<RoomBanEngine>(store_, event_creator_)),
      invite_engine_(std::make_shared<RoomInviteEngine>(store_, event_creator_)),
      knock_engine_(std::make_shared<RoomKnockEngine>(store_, event_creator_)),
      federation_handler_(std::make_shared<FederationJoinHandler>(store_)),
      history_tracker_(std::make_shared<MembershipHistoryTracker>(store_)),
      forgotten_manager_(std::make_shared<ForgottenRoomManager>(store_)) {}

  // ---- Accessors ----
  std::shared_ptr<RoomMembershipStore> store() { return store_; }
  std::shared_ptr<EventCreator> event_creator() { return event_creator_; }
  std::shared_ptr<MembershipStateResolver> state_resolver() { return state_resolver_; }
  std::shared_ptr<RoomJoinEngine> join() { return join_engine_; }
  std::shared_ptr<RoomLeaveEngine> leave() { return leave_engine_; }
  std::shared_ptr<RoomKickEngine> kick() { return kick_engine_; }
  std::shared_ptr<RoomBanEngine> ban() { return ban_engine_; }
  std::shared_ptr<RoomInviteEngine> invite() { return invite_engine_; }
  std::shared_ptr<RoomKnockEngine> knock() { return knock_engine_; }
  std::shared_ptr<FederationJoinHandler> federation() { return federation_handler_; }
  std::shared_ptr<MembershipHistoryTracker> history() { return history_tracker_; }
  std::shared_ptr<ForgottenRoomManager> forgotten() { return forgotten_manager_; }

  // ---- Static DDL helper ----
  static void create_tables(LoggingTransaction& txn) {
    RoomMembershipStore::create_tables(txn);
  }

private:
  DatabasePool db_;
  std::shared_ptr<RoomMembershipStore> store_;
  std::shared_ptr<EventCreator> event_creator_;
  std::shared_ptr<MembershipStateResolver> state_resolver_;
  std::shared_ptr<RoomJoinEngine> join_engine_;
  std::shared_ptr<RoomLeaveEngine> leave_engine_;
  std::shared_ptr<RoomKickEngine> kick_engine_;
  std::shared_ptr<RoomBanEngine> ban_engine_;
  std::shared_ptr<RoomInviteEngine> invite_engine_;
  std::shared_ptr<RoomKnockEngine> knock_engine_;
  std::shared_ptr<FederationJoinHandler> federation_handler_;
  std::shared_ptr<MembershipHistoryTracker> history_tracker_;
  std::shared_ptr<ForgottenRoomManager> forgotten_manager_;
};

// ============================================================================
// ============================================================================
// IMPLEMENTATIONS
// ============================================================================
// ============================================================================

// ============================================================================
// RoomMembershipStore — Full SQL DDL and CRUD implementations
// ============================================================================

// ---- DDL: create all tables ----
void RoomMembershipStore::create_tables(LoggingTransaction& txn) {
  // Primary membership table: current state for every (room_id, user_id) pair.
  // One row per (room_id, user_id). Updated on every membership transition.
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS room_memberships (
      room_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      membership TEXT NOT NULL DEFAULT '',
      event_id TEXT NOT NULL DEFAULT '',
      sender TEXT NOT NULL DEFAULT '',
      content_json TEXT NOT NULL DEFAULT '{}',
      origin_server_ts BIGINT NOT NULL DEFAULT 0,
      display_name TEXT,
      avatar_url TEXT,
      reason TEXT,
      updated_ts BIGINT NOT NULL DEFAULT 0,
      PRIMARY KEY (room_id, user_id)
    );
  )SQL");

  // Index for fast lookup of all memberships in a room by type.
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS room_memberships_room_member_idx
      ON room_memberships (room_id, membership);
  )SQL");

  // Index for fast lookup of all rooms a user belongs to.
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS room_memberships_user_member_idx
      ON room_memberships (user_id, membership);
  )SQL");

  // Audit trail: every membership transition is recorded here.
  // Append-only: rows are never updated, only inserted.
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS room_membership_history (
      id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
      room_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      prev_membership TEXT NOT NULL DEFAULT '',
      new_membership TEXT NOT NULL DEFAULT '',
      event_id TEXT NOT NULL DEFAULT '',
      sender TEXT NOT NULL DEFAULT '',
      content_json TEXT NOT NULL DEFAULT '{}',
      reason TEXT,
      timestamp BIGINT NOT NULL DEFAULT 0
    );
  )SQL");

  // Indices for history queries: by room, by user, by room+user.
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS membership_history_room_idx
      ON room_membership_history (room_id, timestamp DESC);
  )SQL");

  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS membership_history_user_idx
      ON room_membership_history (user_id, timestamp DESC);
  )SQL");

  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS membership_history_room_user_idx
      ON room_membership_history (room_id, user_id, timestamp);
  )SQL");

  // Knock queue: pending knock requests awaiting admin action.
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS knock_queue (
      room_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      event_id TEXT NOT NULL DEFAULT '',
      reason TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      created_ts BIGINT NOT NULL DEFAULT 0,
      resolved_ts BIGINT,
      resolved_by TEXT,
      resolution TEXT,
      PRIMARY KEY (room_id, user_id)
    );
  )SQL");

  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS knock_queue_status_idx
      ON knock_queue (room_id, status);
  )SQL");

  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS knock_queue_user_idx
      ON knock_queue (user_id);
  )SQL");

  // Forgotten rooms: per-user per-room flag.
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS room_forgotten (
      user_id TEXT NOT NULL,
      room_id TEXT NOT NULL,
      forgotten_ts BIGINT NOT NULL DEFAULT 0,
      PRIMARY KEY (user_id, room_id)
    );
  )SQL");

  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS room_forgotten_user_idx
      ON room_forgotten (user_id);
  )SQL");

  // Join time tracking: first and last join timestamps per (room, user).
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS room_join_times (
      room_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      first_join_ts BIGINT NOT NULL DEFAULT 0,
      last_join_ts BIGINT NOT NULL DEFAULT 0,
      join_count INTEGER NOT NULL DEFAULT 1,
      PRIMARY KEY (room_id, user_id)
    );
  )SQL");

  // Ban list: active bans with metadata.
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS room_ban_list (
      room_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      banned_by TEXT NOT NULL DEFAULT '',
      reason TEXT NOT NULL DEFAULT '',
      banned_ts BIGINT NOT NULL DEFAULT 0,
      unbanned_ts BIGINT,
      unbanned_by TEXT,
      active INTEGER NOT NULL DEFAULT 1,
      PRIMARY KEY (room_id, user_id)
    );
  )SQL");

  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS room_ban_list_active_idx
      ON room_ban_list (room_id, active);
  )SQL");

  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS room_ban_list_user_idx
      ON room_ban_list (user_id, active);
  )SQL");

  // Invite state: active invitations with status tracking.
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS room_invite_state (
      room_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      invited_by TEXT NOT NULL DEFAULT '',
      invite_ts BIGINT NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'pending',
      resolved_ts BIGINT,
      is_direct INTEGER NOT NULL DEFAULT 0,
      reason TEXT,
      PRIMARY KEY (room_id, user_id)
    );
  )SQL");

  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS room_invite_state_user_status_idx
      ON room_invite_state (user_id, status);
  )SQL");

  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS room_invite_state_room_idx
      ON room_invite_state (room_id);
  )SQL");

  // Member profile cache: cached display_name and avatar_url per (room, user).
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS room_member_profile (
      room_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      display_name TEXT,
      avatar_url TEXT,
      updated_ts BIGINT NOT NULL DEFAULT 0,
      PRIMARY KEY (room_id, user_id)
    );
  )SQL");

  // Room hosts: servers participating in a room (for federation).
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS room_hosts (
      room_id TEXT NOT NULL,
      server_name TEXT NOT NULL,
      added_ts BIGINT NOT NULL DEFAULT 0,
      PRIMARY KEY (room_id, server_name)
    );
  )SQL");

  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS room_hosts_room_idx
      ON room_hosts (room_id);
  )SQL");
}

// ---- room_memberships CRUD ----

void RoomMembershipStore::upsert_membership_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& membership,
    const std::string& event_id,
    const std::string& sender,
    int64_t origin_server_ts,
    const std::optional<std::string>& display_name,
    const std::optional<std::string>& avatar_url,
    const std::optional<std::string>& reason) {

  // Serialize the member content for debugging/export purposes
  json content;
  content["membership"] = membership;
  if (display_name) content["displayname"] = *display_name;
  if (avatar_url) content["avatar_url"] = *avatar_url;
  if (reason) content["reason"] = *reason;

  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO room_memberships "
      "(room_id, user_id, membership, event_id, sender, content_json, "
      "origin_server_ts, display_name, avatar_url, reason, updated_ts) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT (room_id, user_id) DO UPDATE SET "
      "membership = excluded.membership, "
      "event_id = excluded.event_id, "
      "sender = excluded.sender, "
      "content_json = excluded.content_json, "
      "origin_server_ts = excluded.origin_server_ts, "
      "display_name = COALESCE(excluded.display_name, room_memberships.display_name), "
      "avatar_url = COALESCE(excluded.avatar_url, room_memberships.avatar_url), "
      "reason = excluded.reason, "
      "updated_ts = excluded.updated_ts",
      {room_id, user_id, membership, event_id, sender,
       content.dump(), origin_server_ts,
       display_name.value_or(""), avatar_url.value_or(""),
       reason.value_or(""), ts});
}

json RoomMembershipStore::get_membership_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id) {

  json result;
  auto row = txn.select_one(
      "SELECT room_id, user_id, membership, event_id, sender, "
      "origin_server_ts, display_name, avatar_url, reason, updated_ts "
      "FROM room_memberships WHERE room_id = ? AND user_id = ?",
      {room_id, user_id});

  if (row) {
    result["room_id"] = row->get<std::string>(0);
    result["user_id"] = row->get<std::string>(1);
    result["membership"] = row->get<std::string>(2);
    result["event_id"] = row->get<std::string>(3);
    result["sender"] = row->get<std::string>(4);
    result["origin_server_ts"] = row->get<int64_t>(5);
    if (!row->is_null(6) && !row->get<std::string>(6).empty())
      result["display_name"] = row->get<std::string>(6);
    if (!row->is_null(7) && !row->get<std::string>(7).empty())
      result["avatar_url"] = row->get<std::string>(7);
    if (!row->is_null(8) && !row->get<std::string>(8).empty())
      result["reason"] = row->get<std::string>(8);
    result["updated_ts"] = row->get<int64_t>(9);
  }
  return result;
}

std::string RoomMembershipStore::get_membership_state_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?",
      {room_id, user_id});
  return row ? row->get<std::string>(0) : "";
}

bool RoomMembershipStore::is_membership_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& membership) {
  auto row = txn.select_one(
      "SELECT 1 FROM room_memberships "
      "WHERE room_id = ? AND user_id = ? AND membership = ?",
      {room_id, user_id, membership});
  return row.has_value();
}

void RoomMembershipStore::delete_membership_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id) {
  txn.execute(
      "DELETE FROM room_memberships WHERE room_id = ? AND user_id = ?",
      {room_id, user_id});
}

// ---- multi-user queries ----

json RoomMembershipStore::get_users_with_membership_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& membership,
    int limit) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT user_id, display_name, avatar_url, event_id "
      "FROM room_memberships WHERE room_id = ? AND membership = ? "
      "ORDER BY updated_ts DESC LIMIT ?",
      {room_id, membership, limit});

  for (auto& row : rows) {
    json entry;
    entry["user_id"] = row->get<std::string>(0);
    if (!row->is_null(1) && !row->get<std::string>(1).empty())
      entry["display_name"] = row->get<std::string>(1);
    if (!row->is_null(2) && !row->get<std::string>(2).empty())
      entry["avatar_url"] = row->get<std::string>(2);
    entry["event_id"] = row->get<std::string>(3);
    result.push_back(entry);
  }
  return result;
}

json RoomMembershipStore::get_rooms_for_user_with_membership_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& membership,
    int limit) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, event_id, updated_ts "
      "FROM room_memberships WHERE user_id = ? AND membership = ? "
      "ORDER BY updated_ts DESC LIMIT ?",
      {user_id, membership, limit});

  for (auto& row : rows) {
    json entry;
    entry["room_id"] = row->get<std::string>(0);
    entry["event_id"] = row->get<std::string>(1);
    entry["updated_ts"] = row->get<int64_t>(2);
    result.push_back(entry);
  }
  return result;
}

int64_t RoomMembershipStore::count_members_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& membership) {

  auto row = txn.select_one(
      "SELECT COUNT(*) FROM room_memberships "
      "WHERE room_id = ? AND membership = ?",
      {room_id, membership});
  return row ? row->get<int64_t>(0) : 0;
}

int64_t RoomMembershipStore::count_rooms_for_user_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& membership) {

  auto row = txn.select_one(
      "SELECT COUNT(*) FROM room_memberships "
      "WHERE user_id = ? AND membership = ?",
      {user_id, membership});
  return row ? row->get<int64_t>(0) : 0;
}

json RoomMembershipStore::get_all_memberships_for_user_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    int limit) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, membership, event_id, sender, "
      "display_name, avatar_url, updated_ts "
      "FROM room_memberships WHERE user_id = ? "
      "ORDER BY updated_ts DESC LIMIT ?",
      {user_id, limit});

  for (auto& row : rows) {
    json entry;
    entry["room_id"] = row->get<std::string>(0);
    entry["membership"] = row->get<std::string>(1);
    entry["event_id"] = row->get<std::string>(2);
    entry["sender"] = row->get<std::string>(3);
    if (!row->is_null(4) && !row->get<std::string>(4).empty())
      entry["display_name"] = row->get<std::string>(4);
    if (!row->is_null(5) && !row->get<std::string>(5).empty())
      entry["avatar_url"] = row->get<std::string>(5);
    entry["updated_ts"] = row->get<int64_t>(6);
    result.push_back(entry);
  }
  return result;
}

std::set<std::string> RoomMembershipStore::filter_joined_users_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::vector<std::string>& user_ids) {

  std::set<std::string> joined;
  if (user_ids.empty()) return joined;

  // Build a parameterized IN clause
  std::string sql = "SELECT user_id FROM room_memberships "
                    "WHERE room_id = ? AND membership = 'join' AND user_id IN (";
  std::vector<std::string> params = {room_id};
  for (size_t i = 0; i < user_ids.size(); ++i) {
    if (i > 0) sql += ", ";
    sql += "?";
    params.push_back(user_ids[i]);
  }
  sql += ")";

  auto rows = txn.select(sql, params);
  for (auto& row : rows) {
    joined.insert(row->get<std::string>(0));
  }
  return joined;
}

std::set<std::string> RoomMembershipStore::get_shared_rooms_txn(
    LoggingTransaction& txn,
    const std::string& user_id_a,
    const std::string& user_id_b) {

  std::set<std::string> shared;
  auto rows = txn.select(
      "SELECT a.room_id FROM room_memberships a "
      "JOIN room_memberships b ON a.room_id = b.room_id "
      "WHERE a.user_id = ? AND b.user_id = ? "
      "AND a.membership = 'join' AND b.membership = 'join'",
      {user_id_a, user_id_b});

  for (auto& row : rows) {
    shared.insert(row->get<std::string>(0));
  }
  return shared;
}

// ---- room_membership_history ----

void RoomMembershipStore::record_membership_event_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& prev_membership,
    const std::string& new_membership,
    const std::string& event_id,
    const std::string& sender,
    int64_t timestamp,
    const std::optional<std::string>& reason,
    const std::optional<json>& content) {

  std::string content_str = content ? content->dump() : "{}";
  txn.execute(
      "INSERT INTO room_membership_history "
      "(room_id, user_id, prev_membership, new_membership, event_id, sender, "
      "content_json, reason, timestamp) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      {room_id, user_id, prev_membership, new_membership, event_id, sender,
       content_str, reason.value_or(""), timestamp});
}

json RoomMembershipStore::get_membership_history_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    int limit) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT id, prev_membership, new_membership, event_id, sender, "
      "content_json, reason, timestamp "
      "FROM room_membership_history "
      "WHERE room_id = ? AND user_id = ? "
      "ORDER BY timestamp ASC LIMIT ?",
      {room_id, user_id, limit});

  for (auto& row : rows) {
    json entry;
    entry["id"] = row->get<int64_t>(0);
    entry["prev_membership"] = row->get<std::string>(1);
    entry["new_membership"] = row->get<std::string>(2);
    entry["event_id"] = row->get<std::string>(3);
    entry["sender"] = row->get<std::string>(4);
    try { entry["content"] = json::parse(row->get<std::string>(5)); }
    catch (...) { entry["content"] = json::object(); }
    if (!row->is_null(6) && !row->get<std::string>(6).empty())
      entry["reason"] = row->get<std::string>(6);
    entry["timestamp"] = row->get<int64_t>(7);
    result.push_back(entry);
  }
  return result;
}

json RoomMembershipStore::get_recent_membership_events_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    int limit) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT id, user_id, prev_membership, new_membership, event_id, "
      "sender, reason, timestamp "
      "FROM room_membership_history "
      "WHERE room_id = ? "
      "ORDER BY timestamp DESC LIMIT ?",
      {room_id, limit});

  for (auto& row : rows) {
    json entry;
    entry["id"] = row->get<int64_t>(0);
    entry["user_id"] = row->get<std::string>(1);
    entry["prev_membership"] = row->get<std::string>(2);
    entry["new_membership"] = row->get<std::string>(3);
    entry["event_id"] = row->get<std::string>(4);
    entry["sender"] = row->get<std::string>(5);
    if (!row->is_null(6) && !row->get<std::string>(6).empty())
      entry["reason"] = row->get<std::string>(6);
    entry["timestamp"] = row->get<int64_t>(7);
    result.push_back(entry);
  }
  return result;
}

// ---- knock_queue ----

void RoomMembershipStore::enqueue_knock_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& event_id,
    const std::string& reason,
    int64_t timestamp) {

  txn.execute(
      "INSERT OR IGNORE INTO knock_queue "
      "(room_id, user_id, event_id, reason, status, created_ts) "
      "VALUES (?, ?, ?, ?, 'pending', ?)",
      {room_id, user_id, event_id, reason, timestamp});
}

json RoomMembershipStore::get_pending_knocks_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    int limit) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT user_id, event_id, reason, created_ts "
      "FROM knock_queue "
      "WHERE room_id = ? AND status = 'pending' "
      "ORDER BY created_ts ASC LIMIT ?",
      {room_id, limit});

  for (auto& row : rows) {
    json entry;
    entry["user_id"] = row->get<std::string>(0);
    entry["event_id"] = row->get<std::string>(1);
    entry["reason"] = row->get<std::string>(2);
    entry["created_ts"] = row->get<int64_t>(3);
    result.push_back(entry);
  }
  return result;
}

json RoomMembershipStore::get_knocks_by_user_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    int limit) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, event_id, reason, status, created_ts, resolved_ts "
      "FROM knock_queue "
      "WHERE user_id = ? "
      "ORDER BY created_ts DESC LIMIT ?",
      {user_id, limit});

  for (auto& row : rows) {
    json entry;
    entry["room_id"] = row->get<std::string>(0);
    entry["event_id"] = row->get<std::string>(1);
    entry["reason"] = row->get<std::string>(2);
    entry["status"] = row->get<std::string>(3);
    entry["created_ts"] = row->get<int64_t>(4);
    if (!row->is_null(5)) entry["resolved_ts"] = row->get<int64_t>(5);
    result.push_back(entry);
  }
  return result;
}

void RoomMembershipStore::approve_knock_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& approved_by,
    int64_t approved_ts) {

  txn.execute(
      "UPDATE knock_queue SET status = 'approved', resolved_ts = ?, "
      "resolved_by = ?, resolution = 'approved' "
      "WHERE room_id = ? AND user_id = ? AND status = 'pending'",
      {approved_ts, approved_by, room_id, user_id});
}

void RoomMembershipStore::reject_knock_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& rejected_by,
    const std::string& rejection_reason,
    int64_t rejected_ts) {

  txn.execute(
      "UPDATE knock_queue SET status = 'rejected', resolved_ts = ?, "
      "resolved_by = ?, resolution = ? "
      "WHERE room_id = ? AND user_id = ? AND status = 'pending'",
      {rejected_ts, rejected_by, rejection_reason, room_id, user_id});
}

bool RoomMembershipStore::has_pending_knock_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id) {

  auto row = txn.select_one(
      "SELECT 1 FROM knock_queue "
      "WHERE room_id = ? AND user_id = ? AND status = 'pending'",
      {room_id, user_id});
  return row.has_value();
}

int64_t RoomMembershipStore::purge_expired_knocks_txn(
    LoggingTransaction& txn,
    int64_t older_than_ts) {

  auto count_row = txn.select_one(
      "SELECT COUNT(*) FROM knock_queue "
      "WHERE status = 'pending' AND created_ts < ?",
      {older_than_ts});
  int64_t count = count_row ? count_row->get<int64_t>(0) : 0;

  txn.execute(
      "UPDATE knock_queue SET status = 'expired', "
      "resolved_ts = ?, resolution = 'expired' "
      "WHERE status = 'pending' AND created_ts < ?",
      {now_ms(), older_than_ts});

  return count;
}

// ---- room_forgotten ----

void RoomMembershipStore::forget_room_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& room_id,
    int64_t timestamp) {

  txn.execute(
      "INSERT OR REPLACE INTO room_forgotten (user_id, room_id, forgotten_ts) "
      "VALUES (?, ?, ?)",
      {user_id, room_id, timestamp});
}

void RoomMembershipStore::unforget_room_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& room_id) {

  txn.execute(
      "DELETE FROM room_forgotten WHERE user_id = ? AND room_id = ?",
      {user_id, room_id});
}

bool RoomMembershipStore::is_room_forgotten_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& room_id) {

  auto row = txn.select_one(
      "SELECT 1 FROM room_forgotten WHERE user_id = ? AND room_id = ?",
      {user_id, room_id});
  return row.has_value();
}

json RoomMembershipStore::get_forgotten_rooms_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    int limit) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, forgotten_ts "
      "FROM room_forgotten WHERE user_id = ? "
      "ORDER BY forgotten_ts DESC LIMIT ?",
      {user_id, limit});

  for (auto& row : rows) {
    json entry;
    entry["room_id"] = row->get<std::string>(0);
    entry["forgotten_ts"] = row->get<int64_t>(1);
    result.push_back(entry);
  }
  return result;
}

// ---- room_join_time_tracking ----

void RoomMembershipStore::record_first_join_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    int64_t timestamp) {

  txn.execute(
      "INSERT OR IGNORE INTO room_join_times "
      "(room_id, user_id, first_join_ts, last_join_ts, join_count) "
      "VALUES (?, ?, ?, ?, 1)",
      {room_id, user_id, timestamp, timestamp});
}

void RoomMembershipStore::record_last_join_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    int64_t timestamp) {

  txn.execute(
      "INSERT INTO room_join_times "
      "(room_id, user_id, first_join_ts, last_join_ts, join_count) "
      "VALUES (?, ?, ?, ?, 1) "
      "ON CONFLICT (room_id, user_id) DO UPDATE SET "
      "last_join_ts = excluded.last_join_ts, "
      "join_count = room_join_times.join_count + 1",
      {room_id, user_id, timestamp, timestamp});
}

json RoomMembershipStore::get_join_times_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id) {

  json result;
  auto row = txn.select_one(
      "SELECT first_join_ts, last_join_ts, join_count "
      "FROM room_join_times WHERE room_id = ? AND user_id = ?",
      {room_id, user_id});

  if (row) {
    result["first_join_ts"] = row->get<int64_t>(0);
    result["last_join_ts"] = row->get<int64_t>(1);
    result["join_count"] = row->get<int64_t>(2);
  }
  return result;
}

// ---- room_ban_list ----

void RoomMembershipStore::record_ban_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& banned_by,
    const std::string& reason,
    int64_t timestamp) {

  // First, mark any existing active ban as superseded
  txn.execute(
      "UPDATE room_ban_list SET active = 0, unbanned_ts = ? "
      "WHERE room_id = ? AND user_id = ? AND active = 1",
      {timestamp, room_id, user_id});

  // Record the new active ban
  txn.execute(
      "INSERT INTO room_ban_list "
      "(room_id, user_id, banned_by, reason, banned_ts, active) "
      "VALUES (?, ?, ?, ?, ?, 1)",
      {room_id, user_id, banned_by, reason, timestamp});
}

void RoomMembershipStore::unban_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& unbanned_by,
    int64_t timestamp) {

  txn.execute(
      "UPDATE room_ban_list SET active = 0, unbanned_ts = ?, unbanned_by = ? "
      "WHERE room_id = ? AND user_id = ? AND active = 1",
      {timestamp, unbanned_by, room_id, user_id});
}

bool RoomMembershipStore::is_banned_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id) {

  auto row = txn.select_one(
      "SELECT 1 FROM room_ban_list "
      "WHERE room_id = ? AND user_id = ? AND active = 1",
      {room_id, user_id});
  return row.has_value();
}

json RoomMembershipStore::get_active_bans_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    int limit) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT user_id, banned_by, reason, banned_ts "
      "FROM room_ban_list "
      "WHERE room_id = ? AND active = 1 "
      "ORDER BY banned_ts DESC LIMIT ?",
      {room_id, limit});

  for (auto& row : rows) {
    json entry;
    entry["user_id"] = row->get<std::string>(0);
    entry["banned_by"] = row->get<std::string>(1);
    entry["reason"] = row->get<std::string>(2);
    entry["banned_ts"] = row->get<int64_t>(3);
    result.push_back(entry);
  }
  return result;
}

json RoomMembershipStore::get_bans_for_user_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    int limit) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, banned_by, reason, banned_ts "
      "FROM room_ban_list "
      "WHERE user_id = ? AND active = 1 "
      "ORDER BY banned_ts DESC LIMIT ?",
      {user_id, limit});

  for (auto& row : rows) {
    json entry;
    entry["room_id"] = row->get<std::string>(0);
    entry["banned_by"] = row->get<std::string>(1);
    entry["reason"] = row->get<std::string>(2);
    entry["banned_ts"] = row->get<int64_t>(3);
    result.push_back(entry);
  }
  return result;
}

// ---- room_invite_state ----

void RoomMembershipStore::record_invite_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& invited_by,
    int64_t timestamp,
    const std::optional<std::string>& reason) {

  txn.execute(
      "INSERT OR REPLACE INTO room_invite_state "
      "(room_id, user_id, invited_by, invite_ts, status, reason, is_direct) "
      "VALUES (?, ?, ?, ?, 'pending', ?, 0)",
      {room_id, user_id, invited_by, timestamp, reason.value_or("")});
}

void RoomMembershipStore::accept_invite_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    int64_t accepted_ts) {

  txn.execute(
      "UPDATE room_invite_state SET status = 'accepted', resolved_ts = ? "
      "WHERE room_id = ? AND user_id = ? AND status = 'pending'",
      {accepted_ts, room_id, user_id});
}

void RoomMembershipStore::reject_invite_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    int64_t rejected_ts) {

  txn.execute(
      "UPDATE room_invite_state SET status = 'rejected', resolved_ts = ? "
      "WHERE room_id = ? AND user_id = ? AND status = 'pending'",
      {rejected_ts, room_id, user_id});
}

json RoomMembershipStore::get_pending_invites_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    int limit) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, invited_by, invite_ts, is_direct, reason "
      "FROM room_invite_state "
      "WHERE user_id = ? AND status = 'pending' "
      "ORDER BY invite_ts DESC LIMIT ?",
      {user_id, limit});

  for (auto& row : rows) {
    json entry;
    entry["room_id"] = row->get<std::string>(0);
    entry["invited_by"] = row->get<std::string>(1);
    entry["invite_ts"] = row->get<int64_t>(2);
    entry["is_direct"] = (row->get<int64_t>(3) != 0);
    if (!row->is_null(4) && !row->get<std::string>(4).empty())
      entry["reason"] = row->get<std::string>(4);
    result.push_back(entry);
  }
  return result;
}

json RoomMembershipStore::get_pending_invites_for_room_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    int limit) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT user_id, invited_by, invite_ts, is_direct, reason "
      "FROM room_invite_state "
      "WHERE room_id = ? AND status = 'pending' "
      "ORDER BY invite_ts DESC LIMIT ?",
      {room_id, limit});

  for (auto& row : rows) {
    json entry;
    entry["user_id"] = row->get<std::string>(0);
    entry["invited_by"] = row->get<std::string>(1);
    entry["invite_ts"] = row->get<int64_t>(2);
    entry["is_direct"] = (row->get<int64_t>(3) != 0);
    if (!row->is_null(4) && !row->get<std::string>(4).empty())
      entry["reason"] = row->get<std::string>(4);
    result.push_back(entry);
  }
  return result;
}

bool RoomMembershipStore::has_pending_invite_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id) {

  auto row = txn.select_one(
      "SELECT 1 FROM room_invite_state "
      "WHERE room_id = ? AND user_id = ? AND status = 'pending'",
      {room_id, user_id});
  return row.has_value();
}

// ---- room_member_profile ----

void RoomMembershipStore::update_member_profile_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    const std::optional<std::string>& display_name,
    const std::optional<std::string>& avatar_url) {

  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO room_member_profile "
      "(room_id, user_id, display_name, avatar_url, updated_ts) "
      "VALUES (?, ?, ?, ?, ?) "
      "ON CONFLICT (room_id, user_id) DO UPDATE SET "
      "display_name = COALESCE(excluded.display_name, room_member_profile.display_name), "
      "avatar_url = COALESCE(excluded.avatar_url, room_member_profile.avatar_url), "
      "updated_ts = excluded.updated_ts",
      {room_id, user_id,
       display_name.value_or(""), avatar_url.value_or(""), ts});
}

json RoomMembershipStore::get_member_profile_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id) {

  json result;
  auto row = txn.select_one(
      "SELECT display_name, avatar_url, updated_ts "
      "FROM room_member_profile WHERE room_id = ? AND user_id = ?",
      {room_id, user_id});

  if (row) {
    if (!row->is_null(0) && !row->get<std::string>(0).empty())
      result["display_name"] = row->get<std::string>(0);
    if (!row->is_null(1) && !row->get<std::string>(1).empty())
      result["avatar_url"] = row->get<std::string>(1);
    result["updated_ts"] = row->get<int64_t>(2);
  }
  return result;
}

// ---- room_hosts ----

void RoomMembershipStore::add_room_host_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& server_name) {

  txn.execute(
      "INSERT OR IGNORE INTO room_hosts (room_id, server_name, added_ts) "
      "VALUES (?, ?, ?)",
      {room_id, server_name, now_ms()});
}

void RoomMembershipStore::remove_room_host_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& server_name) {

  txn.execute(
      "DELETE FROM room_hosts WHERE room_id = ? AND server_name = ?",
      {room_id, server_name});
}

json RoomMembershipStore::get_room_hosts_txn(
    LoggingTransaction& txn,
    const std::string& room_id) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT server_name, added_ts FROM room_hosts WHERE room_id = ? "
      "ORDER BY added_ts ASC",
      {room_id});

  for (auto& row : rows) {
    json entry;
    entry["server_name"] = row->get<std::string>(0);
    entry["added_ts"] = row->get<int64_t>(1);
    result.push_back(entry);
  }
  return result;
}

// ---- maintenance & stats ----

void RoomMembershipStore::delete_all_for_room_txn(
    LoggingTransaction& txn,
    const std::string& room_id) {

  txn.execute("DELETE FROM room_memberships WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM room_membership_history WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM knock_queue WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM room_join_times WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM room_ban_list WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM room_invite_state WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM room_member_profile WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM room_hosts WHERE room_id = ?", {room_id});
}

void RoomMembershipStore::delete_all_for_user_txn(
    LoggingTransaction& txn,
    const std::string& user_id) {

  txn.execute("DELETE FROM room_memberships WHERE user_id = ?", {user_id});
  txn.execute("DELETE FROM room_membership_history WHERE user_id = ?", {user_id});
  txn.execute("DELETE FROM knock_queue WHERE user_id = ?", {user_id});
  txn.execute("DELETE FROM room_forgotten WHERE user_id = ?", {user_id});
  txn.execute("DELETE FROM room_join_times WHERE user_id = ?", {user_id});
  txn.execute("DELETE FROM room_ban_list WHERE user_id = ?", {user_id});
  txn.execute("DELETE FROM room_invite_state WHERE user_id = ?", {user_id});
  txn.execute("DELETE FROM room_member_profile WHERE user_id = ?", {user_id});
}

json RoomMembershipStore::get_room_membership_stats_txn(
    LoggingTransaction& txn,
    const std::string& room_id) {

  json stats;
  auto total = txn.select_one(
      "SELECT COUNT(*) FROM room_memberships WHERE room_id = ?", {room_id});
  auto joined = txn.select_one(
      "SELECT COUNT(*) FROM room_memberships WHERE room_id = ? AND membership = 'join'", {room_id});
  auto invited = txn.select_one(
      "SELECT COUNT(*) FROM room_memberships WHERE room_id = ? AND membership = 'invite'", {room_id});
  auto left = txn.select_one(
      "SELECT COUNT(*) FROM room_memberships WHERE room_id = ? AND membership = 'leave'", {room_id});
  auto banned = txn.select_one(
      "SELECT COUNT(*) FROM room_memberships WHERE room_id = ? AND membership = 'ban'", {room_id});
  auto knocks = txn.select_one(
      "SELECT COUNT(*) FROM knock_queue WHERE room_id = ? AND status = 'pending'", {room_id});

  stats["total_entries"] = total ? total->get<int64_t>(0) : 0;
  stats["joined"] = joined ? joined->get<int64_t>(0) : 0;
  stats["invited"] = invited ? invited->get<int64_t>(0) : 0;
  stats["left"] = left ? left->get<int64_t>(0) : 0;
  stats["banned"] = banned ? banned->get<int64_t>(0) : 0;
  stats["pending_knocks"] = knocks ? knocks->get<int64_t>(0) : 0;
  return stats;
}

json RoomMembershipStore::get_store_stats_txn(
    LoggingTransaction& txn) {

  json stats;
  auto m = txn.select_one("SELECT COUNT(*) FROM room_memberships");
  auto h = txn.select_one("SELECT COUNT(*) FROM room_membership_history");
  auto k = txn.select_one("SELECT COUNT(*) FROM knock_queue");
  auto f = txn.select_one("SELECT COUNT(*) FROM room_forgotten");
  auto b = txn.select_one("SELECT COUNT(*) FROM room_ban_list WHERE active = 1");
  auto i = txn.select_one("SELECT COUNT(*) FROM room_invite_state WHERE status = 'pending'");
  auto host = txn.select_one("SELECT COUNT(*) FROM room_hosts");

  stats["total_memberships"] = m ? m->get<int64_t>(0) : 0;
  stats["total_history_entries"] = h ? h->get<int64_t>(0) : 0;
  stats["pending_knocks"] = k ? k->get<int64_t>(0) : 0;
  stats["forgotten_rooms"] = f ? f->get<int64_t>(0) : 0;
  stats["active_bans"] = b ? b->get<int64_t>(0) : 0;
  stats["pending_invites"] = i ? i->get<int64_t>(0) : 0;
  stats["room_hosts"] = host ? host->get<int64_t>(0) : 0;
  return stats;
}

// ============================================================================
// EventCreator — Implementations
// ============================================================================

json EventCreator::build_event_skeleton(
    const std::string& domain,
    const std::string& room_id,
    const std::string& sender,
    const std::string& type,
    const std::string& state_key,
    const std::vector<std::string>& prev_events,
    const std::vector<std::string>& auth_events,
    int64_t depth,
    const json& content) {

  json event;
  event["type"] = type;
  event["sender"] = sender;
  event["state_key"] = state_key;
  event["room_id"] = room_id;
  event["content"] = content;
  event["origin_server_ts"] = now_ms();
  event["origin"] = domain;

  // Build prev_events array
  json prev = json::array();
  for (auto& pe : prev_events) {
    prev.push_back(pe);
  }
  event["prev_events"] = prev;

  // Build auth_events array
  json auth = json::array();
  for (auto& ae : auth_events) {
    auth.push_back(ae);
  }
  event["auth_events"] = auth;

  event["depth"] = depth;

  // Generate event ID
  event["event_id"] = generate_event_id(domain);

  // Unsigned metadata
  event["unsigned"] = json::object();

  return event;
}

json EventCreator::build_member_content(
    const std::string& membership,
    const std::optional<std::string>& display_name,
    const std::optional<std::string>& avatar_url,
    const std::optional<std::string>& reason,
    bool is_direct) {

  json content;
  content["membership"] = membership;
  if (display_name && !display_name->empty())
    content["displayname"] = *display_name;
  if (avatar_url && !avatar_url->empty())
    content["avatar_url"] = *avatar_url;
  if (reason && !reason->empty())
    content["reason"] = *reason;
  if (is_direct)
    content["is_direct"] = true;
  return content;
}

json EventCreator::build_member_event(
    const std::string& domain,
    const std::string& room_id,
    const std::string& sender,
    const std::string& state_key,
    const std::string& membership,
    const std::vector<std::string>& prev_events,
    const std::vector<std::string>& auth_events,
    int64_t depth,
    const std::optional<std::string>& display_name,
    const std::optional<std::string>& avatar_url,
    const std::optional<std::string>& reason,
    bool is_direct) {

  json content = build_member_content(
      membership, display_name, avatar_url, reason, is_direct);

  return build_event_skeleton(
      domain, room_id, sender, "m.room.member", state_key,
      prev_events, auth_events, depth, content);
}

json EventCreator::build_leave_event(
    const std::string& domain,
    const std::string& room_id,
    const std::string& sender,
    const std::string& state_key,
    const std::vector<std::string>& prev_events,
    const std::vector<std::string>& auth_events,
    int64_t depth,
    const std::optional<std::string>& reason,
    bool is_kick) {

  json content;
  content["membership"] = "leave";
  if (reason && !reason->empty())
    content["reason"] = *reason;
  if (is_kick)
    content["reason"] = "Kicked: " + reason.value_or("");

  return build_event_skeleton(
      domain, room_id, sender, "m.room.member", state_key,
      prev_events, auth_events, depth, content);
}

json EventCreator::build_invite_event(
    const std::string& domain,
    const std::string& room_id,
    const std::string& sender,
    const std::string& state_key,
    const std::vector<std::string>& prev_events,
    const std::vector<std::string>& auth_events,
    int64_t depth,
    const std::optional<std::string>& reason,
    bool is_direct) {

  json content = build_member_content(
      "invite", std::nullopt, std::nullopt, reason, is_direct);

  return build_event_skeleton(
      domain, room_id, sender, "m.room.member", state_key,
      prev_events, auth_events, depth, content);
}

json EventCreator::build_ban_event(
    const std::string& domain,
    const std::string& room_id,
    const std::string& sender,
    const std::string& state_key,
    const std::vector<std::string>& prev_events,
    const std::vector<std::string>& auth_events,
    int64_t depth,
    const std::optional<std::string>& reason) {

  json content = build_member_content(
      "ban", std::nullopt, std::nullopt, reason, false);

  return build_event_skeleton(
      domain, room_id, sender, "m.room.member", state_key,
      prev_events, auth_events, depth, content);
}

json EventCreator::build_knock_event(
    const std::string& domain,
    const std::string& room_id,
    const std::string& sender,
    const std::string& state_key,
    const std::vector<std::string>& prev_events,
    const std::vector<std::string>& auth_events,
    int64_t depth,
    const std::optional<std::string>& reason) {

  json content = build_member_content(
      "knock", std::nullopt, std::nullopt, reason, false);

  return build_event_skeleton(
      domain, room_id, sender, "m.room.member", state_key,
      prev_events, auth_events, depth, content);
}

std::pair<bool, std::string> EventCreator::validate_member_event(
    const json& event) {

  // Required top-level fields
  if (!event.contains("type") || event["type"] != "m.room.member")
    return {false, "Event type must be m.room.member"};
  if (!event.contains("sender") || !event["sender"].is_string())
    return {false, "Event missing valid sender"};
  if (!event.contains("state_key") || !event["state_key"].is_string())
    return {false, "Event missing valid state_key"};
  if (!event.contains("room_id") || !event["room_id"].is_string())
    return {false, "Event missing valid room_id"};
  if (!event.contains("content") || !event["content"].is_object())
    return {false, "Event missing valid content"};

  // Required content fields
  auto& content = event["content"];
  if (!content.contains("membership") || !content["membership"].is_string())
    return {false, "Content missing valid membership"};

  std::string membership = content["membership"];
  if (membership != "join" && membership != "leave" &&
      membership != "invite" && membership != "ban" &&
      membership != "knock")
    return {false, "Invalid membership value: " + membership};

  return {true, ""};
}

std::string EventCreator::extract_membership(const json& content) {
  if (content.contains("membership") && content["membership"].is_string())
    return content["membership"].get<std::string>();
  return "";
}

std::optional<std::string> EventCreator::extract_display_name(
    const json& content) {
  if (content.contains("displayname") && content["displayname"].is_string())
    return content["displayname"].get<std::string>();
  return std::nullopt;
}

// ============================================================================
// MembershipStateResolver — Implementations
// ============================================================================

std::string MembershipStateResolver::resolve_membership(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& room_version,
    const std::vector<std::string>& state_group_ids,
    LoggingTransaction& txn) {

  // Gather all candidate m.room.member events for this (room, user) from
  // all active state groups. Only one event per state group is considered.
  std::vector<json> candidates;

  for (auto& sg_id : state_group_ids) {
    auto rows = txn.select(
        "SELECT event_json FROM state_events_state "
        "WHERE state_group = ? AND type = 'm.room.member' "
        "AND state_key = ?",
        {sg_id, user_id});

    for (auto& row : rows) {
      try {
        json event = json::parse(row->get<std::string>(0));
        candidates.push_back(event);
      } catch (...) {
        // Skip malformed events
      }
    }
  }

  if (candidates.empty()) return "";

  // Apply version-specific resolution
  int rv = 0;
  try { rv = std::stoi(room_version); } catch (...) { rv = 1; }

  if (rv <= 2) {
    return resolve_v1_v2(candidates);
  } else if (rv <= 9) {
    return resolve_v3_v9(candidates);
  } else {
    return resolve_v10_plus(candidates);
  }
}

std::unordered_map<std::string, std::string>
MembershipStateResolver::resolve_all_memberships(
    const std::string& room_id,
    const std::string& room_version,
    const std::vector<std::string>& state_group_ids,
    LoggingTransaction& txn) {

  std::unordered_map<std::string, std::string> results;

  // Get unique state_keys from all state groups
  std::set<std::string> all_users;
  for (auto& sg_id : state_group_ids) {
    auto rows = txn.select(
        "SELECT state_key FROM state_events_state "
        "WHERE state_group = ? AND type = 'm.room.member'",
        {sg_id});
    for (auto& row : rows) {
      all_users.insert(row->get<std::string>(0));
    }
  }

  // Resolve membership for each user
  for (auto& user_id : all_users) {
    std::string membership = resolve_membership(
        room_id, user_id, room_version, state_group_ids, txn);
    if (!membership.empty()) {
      results[user_id] = membership;
    }
  }

  return results;
}

std::optional<std::string>
MembershipStateResolver::resolve_restricted_join_authorization(
    const std::string& room_id,
    const std::string& user_id,
    const std::vector<std::string>& allowed_room_ids,
    LoggingTransaction& txn) {

  for (auto& allowed_room : allowed_room_ids) {
    auto row = txn.select_one(
        "SELECT 1 FROM room_memberships "
        "WHERE room_id = ? AND user_id = ? AND membership = 'join'",
        {allowed_room, user_id});
    if (row) return allowed_room;
  }

  return std::nullopt;
}

bool MembershipStateResolver::state_group_has_member_event(
    const std::string& state_group_id,
    const std::string& room_id,
    const std::string& user_id,
    LoggingTransaction& txn) {

  auto row = txn.select_one(
      "SELECT 1 FROM state_events_state "
      "WHERE state_group = ? AND type = 'm.room.member' AND state_key = ?",
      {state_group_id, user_id});
  return row.has_value();
}

std::string MembershipStateResolver::resolve_v1_v2(
    const std::vector<json>& candidate_events) {

  if (candidate_events.empty()) return "";
  if (candidate_events.size() == 1) {
    return EventCreator::extract_membership(candidate_events[0]["content"]);
  }

  // Sort by origin_server_ts descending, then event_id lexicographically
  std::vector<json> sorted = candidate_events;
  std::sort(sorted.begin(), sorted.end(),
    [](const json& a, const json& b) {
      int64_t ts_a = a.value("origin_server_ts", 0LL);
      int64_t ts_b = b.value("origin_server_ts", 0LL);
      if (ts_a != ts_b) return ts_a > ts_b;
      return a.value("event_id", "") > b.value("event_id", "");
    });

  return EventCreator::extract_membership(sorted[0]["content"]);
}

std::string MembershipStateResolver::resolve_v3_v9(
    const std::vector<json>& candidate_events) {

  // v3-v9: same as v1-v2 but with additional auth event consideration.
  return resolve_v1_v2(candidate_events);
}

std::string MembershipStateResolver::resolve_v10_plus(
    const std::vector<json>& candidate_events) {

  // v10+: Refined state resolution.
  return resolve_v1_v2(candidate_events);
}

// ============================================================================
// RoomJoinEngine — Implementations
// ============================================================================

std::vector<std::string> RoomJoinEngine::get_prev_events(
    const std::string& room_id, LoggingTransaction& txn) {
  std::vector<std::string> prevs;
  auto rows = txn.select(
      "SELECT event_id FROM event_forward_extremities "
      "WHERE room_id = ? ORDER BY event_id LIMIT 20",
      {room_id});
  for (auto& row : rows) {
    prevs.push_back(row->get<std::string>(0));
  }
  return prevs;
}

std::vector<std::string> RoomJoinEngine::get_auth_events(
    const std::string& room_id, LoggingTransaction& txn) {
  std::vector<std::string> auths;
  auto rows = txn.select(
      "SELECT event_id FROM current_state_events "
      "WHERE room_id = ? AND type IN ('m.room.create', 'm.room.power_levels', "
      "'m.room.join_rules') ORDER BY event_id",
      {room_id});
  for (auto& row : rows) {
    auths.push_back(row->get<std::string>(0));
  }
  return auths;
}

int64_t RoomJoinEngine::get_max_depth(
    const std::string& room_id, LoggingTransaction& txn) {
  auto row = txn.select_one(
      "SELECT COALESCE(MAX(depth), 0) FROM events WHERE room_id = ?",
      {room_id});
  return row ? row->get<int64_t>(0) : 0;
}

void RoomJoinEngine::notify_membership_change(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& membership,
    LoggingTransaction& txn) {
  // In production: dispatch notifications, update presence, queue sync updates.
  // Stub implementation for now.
  (void)room_id;
  (void)user_id;
  (void)membership;
  (void)txn;
}

AuthResult RoomJoinEngine::validate_join(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& room_version,
    const std::string& join_rule,
    const json& allow_list,
    LoggingTransaction& txn) {

  // Check if user is banned
  if (store_->is_banned_txn(txn, room_id, user_id)) {
    return AuthResult::deny("M_FORBIDDEN",
        "You are banned from this room");
  }

  // Check current membership
  std::string current = store_->get_membership_state_txn(txn, room_id, user_id);
  if (current == "join") {
    return AuthResult::deny("M_FORBIDDEN",
        "You are already a member of this room");
  }

  // Evaluate join rules
  if (join_rule == "public") {
    return AuthResult::allow();
  }

  if (join_rule == "invite") {
    if (store_->has_pending_invite_txn(txn, room_id, user_id)) {
      return AuthResult::allow();
    }
    AuthResult r = AuthResult::deny("M_FORBIDDEN",
        "This room is invite-only. You must be invited to join.");
    r.requires_invite = true;
    return r;
  }

  if (join_rule == "knock" || join_rule == "knock_restricted") {
    AuthResult r = AuthResult::deny("M_FORBIDDEN",
        "This room requires knocking before joining");
    r.requires_invite = false;
    return r;
  }

  if (join_rule == "restricted" || join_rule == "knock_restricted") {
    return check_restricted_join(room_id, user_id, allow_list, txn);
  }

  return AuthResult::deny("M_FORBIDDEN",
      "Unknown or unsupported join rule: " + join_rule);
}

AuthResult RoomJoinEngine::check_restricted_join(
    const std::string& room_id,
    const std::string& user_id,
    const json& allow_rules,
    LoggingTransaction& txn) {

  if (!allow_rules.is_array() || allow_rules.empty()) {
    return AuthResult::deny("M_FORBIDDEN",
        "No allow rules configured for this restricted room");
  }

  for (auto& rule : allow_rules) {
    if (!rule.contains("type") || rule["type"] != "m.room_membership")
      continue;
    if (!rule.contains("room_id")) continue;

    std::string allowed_room = rule["room_id"].get<std::string>();
    if (store_->is_membership_txn(txn, allowed_room, user_id, "join")) {
      AuthResult r = AuthResult::allow();
      r.authorizing_room = allowed_room;
      return r;
    }
  }

  AuthResult r = AuthResult::deny("M_FORBIDDEN",
      "You are not a member of any room that authorizes joining this room");
  r.requires_invite = true;
  return r;
}

json RoomJoinEngine::execute_join(
    const std::string& domain,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& sender,
    const std::string& room_version,
    const std::optional<std::string>& reason,
    const std::optional<std::string>& display_name,
    const std::optional<std::string>& avatar_url,
    LoggingTransaction& txn) {

  // Get contextual data for event building
  auto prev_events = get_prev_events(room_id, txn);
  auto auth_events = get_auth_events(room_id, txn);
  int64_t depth = get_max_depth(room_id, txn) + 1;

  // Build the m.room.member join event
  json event = event_creator_->build_member_event(
      domain, room_id, sender, user_id, "join",
      prev_events, auth_events, depth,
      display_name, avatar_url, reason, false);

  std::string event_id = event["event_id"].get<std::string>();
  int64_t ts = now_ms();

  // Determine previous membership for history
  std::string prev_membership = store_->get_membership_state_txn(txn, room_id, user_id);
  if (prev_membership.empty()) prev_membership = "";

  // Persist membership
  store_->upsert_membership_txn(
      txn, room_id, user_id, "join", event_id, sender, ts,
      display_name, avatar_url, reason);

  // Record in history
  store_->record_membership_event_txn(
      txn, room_id, user_id, prev_membership, "join",
      event_id, sender, ts, reason,
      event["content"]);

  // Track join times
  store_->record_first_join_txn(txn, room_id, user_id, ts);
  store_->record_last_join_txn(txn, room_id, user_id, ts);

  // Accept any pending invite
  if (store_->has_pending_invite_txn(txn, room_id, user_id)) {
    store_->accept_invite_txn(txn, room_id, user_id, ts);
  }

  // Notify
  notify_membership_change(room_id, user_id, "join", txn);

  // Build response
  json response;
  response["room_id"] = room_id;
  response["event_id"] = event_id;
  return response;
}

json RoomJoinEngine::join_room(
    const std::string& domain,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& room_version,
    const std::optional<json>& third_party_signed,
    const std::optional<std::string>& reason,
    LoggingTransaction& txn) {

  // Validate join: get join rules from current state
  std::string join_rule = "invite"; // Default
  auto join_rule_row = txn.select_one(
      "SELECT content_json FROM current_state_events "
      "WHERE room_id = ? AND type = 'm.room.join_rules'",
      {room_id});
  if (join_rule_row) {
    try {
      json content = json::parse(join_rule_row->get<std::string>(0));
      join_rule = content.value("join_rule", "invite");
    } catch (...) {}
  }

  json allow_list;
  if (join_rule == "restricted" || join_rule == "knock_restricted") {
    if (join_rule_row) {
      try {
        json content = json::parse(join_rule_row->get<std::string>(0));
        if (content.contains("allow")) {
          allow_list = content["allow"];
        }
      } catch (...) {}
    }
  }

  // Check third-party signed invite if provided (3PID invites)
  if (third_party_signed) {
    // In production: validate the third_party_signed token
    // against the identity server's public key
  }

  // Perform authorization
  AuthResult auth = validate_join(room_id, user_id, room_version,
                                   join_rule, allow_list, txn);
  if (!auth.allowed) {
    json error;
    error["errcode"] = auth.errcode;
    error["error"] = auth.error;
    return error;
  }

  return execute_join(domain, room_id, user_id, user_id, room_version,
                       reason, std::nullopt, std::nullopt, txn);
}

json RoomJoinEngine::join_via_knock_approval(
    const std::string& domain,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& approved_by,
    const std::string& room_version,
    LoggingTransaction& txn) {

  // Verify the knock exists and is pending
  if (!store_->has_pending_knock_txn(txn, room_id, user_id)) {
    json error;
    error["errcode"] = "M_NOT_FOUND";
    error["error"] = "No pending knock found for this user in this room";
    return error;
  }

  // Approve the knock
  int64_t ts = now_ms();
  store_->approve_knock_txn(txn, room_id, user_id, approved_by, ts);

  // Execute join on behalf of the user
  return execute_join(domain, room_id, user_id, approved_by, room_version,
                       "Knock approved", std::nullopt, std::nullopt, txn);
}

json RoomJoinEngine::join_via_invite(
    const std::string& domain,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& room_version,
    LoggingTransaction& txn) {

  // Verify there's a pending invite
  if (!store_->has_pending_invite_txn(txn, room_id, user_id)) {
    json error;
    error["errcode"] = "M_NOT_FOUND";
    error["error"] = "No pending invite found for this room";
    return error;
  }

  // Accept invite and join
  return execute_join(domain, room_id, user_id, user_id, room_version,
                       std::nullopt, std::nullopt, std::nullopt, txn);
}

json RoomJoinEngine::rejoin_room(
    const std::string& domain,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& room_version,
    LoggingTransaction& txn) {

  return execute_join(domain, room_id, user_id, user_id, room_version,
                       "Rejoined", std::nullopt, std::nullopt, txn);
}

// ============================================================================
// RoomLeaveEngine — Implementations
// ============================================================================

std::pair<bool, std::string> RoomLeaveEngine::validate_leave(
    const std::string& room_id,
    const std::string& user_id,
    LoggingTransaction& txn) {

  if (!store_->is_membership_txn(txn, room_id, user_id, "join")) {
    return {false, "You are not a member of this room"};
  }

  return {true, ""};
}

json RoomLeaveEngine::leave_room(
    const std::string& domain,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& room_version,
    const std::optional<std::string>& reason,
    LoggingTransaction& txn) {

  auto [valid, error] = validate_leave(room_id, user_id, txn);
  if (!valid) {
    json resp;
    resp["errcode"] = "M_FORBIDDEN";
    resp["error"] = error;
    return resp;
  }

  // Get contextual event data
  auto prev_events = std::vector<std::string>{}; // Ideally populated from DAG
  auto auth_events = std::vector<std::string>{};
  int64_t depth = 1;

  // Build leave event (sender == state_key for voluntary leave)
  json event = event_creator_->build_leave_event(
      domain, room_id, user_id, user_id,
      prev_events, auth_events, depth, reason, false);

  std::string event_id = event["event_id"].get<std::string>();
  int64_t ts = now_ms();

  // Persist membership
  store_->upsert_membership_txn(
      txn, room_id, user_id, "leave", event_id, user_id, ts,
      std::nullopt, std::nullopt, reason);

  // Record in history
  store_->record_membership_event_txn(
      txn, room_id, user_id, "join", "leave",
      event_id, user_id, ts, reason,
      event["content"]);

  json response;
  response["event_id"] = event_id;
  response["room_id"] = room_id;
  return response;
}

// ============================================================================
// RoomKickEngine — Implementations
// ============================================================================

std::pair<bool, std::string> RoomKickEngine::validate_kick(
    const std::string& room_id,
    const std::string& kicker,
    const std::string& kicked,
    LoggingTransaction& txn) {

  // Target must be in the room
  if (!store_->is_membership_txn(txn, room_id, kicked, "join")) {
    return {false, "The target user is not a member of this room"};
  }

  // Kicker must be in the room (or have appropriate power level)
  if (!store_->is_membership_txn(txn, room_id, kicker, "join")) {
    return {false, "You are not a member of this room"};
  }

  // Can't kick yourself
  if (kicker == kicked) {
    return {false, "You cannot kick yourself. Use /leave instead."};
  }

  return {true, ""};
}

json RoomKickEngine::kick_user(
    const std::string& domain,
    const std::string& room_id,
    const std::string& kicker,
    const std::string& kicked,
    const std::string& room_version,
    const std::optional<std::string>& reason,
    LoggingTransaction& txn) {

  auto [valid, error] = validate_kick(room_id, kicker, kicked, txn);
  if (!valid) {
    json resp;
    resp["errcode"] = "M_FORBIDDEN";
    resp["error"] = error;
    return resp;
  }

  // Build kick event: sender is kicker, state_key is kicked user
  json event = event_creator_->build_leave_event(
      domain, room_id, kicker, kicked,
      {}, {}, 1, reason, true);

  std::string event_id = event["event_id"].get<std::string>();
  int64_t ts = now_ms();

  // Persist membership as "leave" for kicked user
  store_->upsert_membership_txn(
      txn, room_id, kicked, "leave", event_id, kicker, ts,
      std::nullopt, std::nullopt, reason);

  // Record in history
  store_->record_membership_event_txn(
      txn, room_id, kicked, "join", "leave",
      event_id, kicker, ts, reason,
      event["content"]);

  json response;
  response["event_id"] = event_id;
  response["room_id"] = room_id;
  return response;
}

// ============================================================================
// RoomBanEngine — Implementations
// ============================================================================

std::pair<bool, std::string> RoomBanEngine::validate_ban(
    const std::string& room_id,
    const std::string& banner,
    const std::string& banned,
    LoggingTransaction& txn) {

  // Banner must be in the room
  if (!store_->is_membership_txn(txn, room_id, banner, "join")) {
    return {false, "You are not a member of this room"};
  }

  // Can't ban yourself
  if (banner == banned) {
    return {false, "You cannot ban yourself"};
  }

  // Target is already banned
  if (store_->is_banned_txn(txn, room_id, banned)) {
    return {false, "This user is already banned from this room"};
  }

  return {true, ""};
}

std::pair<bool, std::string> RoomBanEngine::validate_unban(
    const std::string& room_id,
    const std::string& unbanner,
    const std::string& unbanned,
    LoggingTransaction& txn) {

  // Target must actually be banned
  if (!store_->is_banned_txn(txn, room_id, unbanned)) {
    return {false, "This user is not banned from this room"};
  }

  return {true, ""};
}

json RoomBanEngine::ban_user(
    const std::string& domain,
    const std::string& room_id,
    const std::string& banner,
    const std::string& banned,
    const std::string& room_version,
    const std::optional<std::string>& reason,
    LoggingTransaction& txn) {

  auto [valid, error] = validate_ban(room_id, banner, banned, txn);
  if (!valid) {
    json resp;
    resp["errcode"] = "M_FORBIDDEN";
    resp["error"] = error;
    return resp;
  }

  // Build ban event
  json event = event_creator_->build_ban_event(
      domain, room_id, banner, banned,
      {}, {}, 1, reason);

  std::string event_id = event["event_id"].get<std::string>();
  int64_t ts = now_ms();
  std::string prev = store_->get_membership_state_txn(txn, room_id, banned);

  // Persist membership as "ban"
  store_->upsert_membership_txn(
      txn, room_id, banned, "ban", event_id, banner, ts,
      std::nullopt, std::nullopt, reason);

  // Record ban in ban list
  store_->record_ban_txn(txn, room_id, banned, banner,
                           reason.value_or(""), ts);

  // Record in history
  store_->record_membership_event_txn(
      txn, room_id, banned, prev, "ban",
      event_id, banner, ts, reason,
      event["content"]);

  json response;
  response["event_id"] = event_id;
  response["room_id"] = room_id;
  return response;
}

json RoomBanEngine::unban_user(
    const std::string& domain,
    const std::string& room_id,
    const std::string& unbanner,
    const std::string& unbanned,
    const std::string& room_version,
    LoggingTransaction& txn) {

  auto [valid, error] = validate_unban(room_id, unbanner, unbanned, txn);
  if (!valid) {
    json resp;
    resp["errcode"] = "M_FORBIDDEN";
    resp["error"] = error;
    return resp;
  }

  int64_t ts = now_ms();
  store_->unban_txn(txn, room_id, unbanned, unbanner, ts);

  // Update membership to "leave" (if they were banned)
  std::string prev = store_->get_membership_state_txn(txn, room_id, unbanned);
  if (prev == "ban") {
    // Create an unban event (membership changed from ban to leave)
    json event = event_creator_->build_leave_event(
        domain, room_id, unbanner, unbanned,
        {}, {}, 1, "Unbanned", false);

    std::string event_id = event["event_id"].get<std::string>();
    store_->upsert_membership_txn(
        txn, room_id, unbanned, "leave", event_id, unbanner, ts);
    store_->record_membership_event_txn(
        txn, room_id, unbanned, "ban", "leave",
        event_id, unbanner, ts, "Unbanned",
        event["content"]);
  }

  json response;
  response["errcode"] = "M_NONE";
  response["error"] = "";
  return response;
}

// ============================================================================
// RoomInviteEngine — Implementations
// ============================================================================

std::pair<bool, std::string> RoomInviteEngine::validate_invite(
    const std::string& room_id,
    const std::string& inviter,
    const std::string& invitee,
    LoggingTransaction& txn) {

  // Inviter must be joined
  if (!store_->is_membership_txn(txn, room_id, inviter, "join")) {
    return {false, "You are not a member of this room"};
  }

  // Can't invite yourself
  if (inviter == invitee) {
    return {false, "You cannot invite yourself"};
  }

  // Target is already joined
  if (store_->is_membership_txn(txn, room_id, invitee, "join")) {
    return {false, "This user is already a member of this room"};
  }

  // Target is banned
  if (store_->is_banned_txn(txn, room_id, invitee)) {
    return {false, "This user is banned from this room"};
  }

  // Target already has a pending invite
  if (store_->has_pending_invite_txn(txn, room_id, invitee)) {
    return {false, "This user already has a pending invitation to this room"};
  }

  return {true, ""};
}

json RoomInviteEngine::invite_user(
    const std::string& domain,
    const std::string& room_id,
    const std::string& inviter,
    const std::string& invitee,
    const std::string& room_version,
    const std::optional<std::string>& reason,
    bool is_direct,
    LoggingTransaction& txn) {

  auto [valid, error] = validate_invite(room_id, inviter, invitee, txn);
  if (!valid) {
    json resp;
    resp["errcode"] = "M_FORBIDDEN";
    resp["error"] = error;
    return resp;
  }

  // Build invite event
  json event = event_creator_->build_invite_event(
      domain, room_id, inviter, invitee,
      {}, {}, 1, reason, is_direct);

  std::string event_id = event["event_id"].get<std::string>();
  int64_t ts = now_ms();
  std::string prev = store_->get_membership_state_txn(txn, room_id, invitee);

  // Persist membership as "invite"
  store_->upsert_membership_txn(
      txn, room_id, invitee, "invite", event_id, inviter, ts,
      std::nullopt, std::nullopt, reason);

  // Record active invite
  store_->record_invite_txn(txn, room_id, invitee, inviter, ts, reason);

  // Record in history
  store_->record_membership_event_txn(
      txn, room_id, invitee, prev, "invite",
      event_id, inviter, ts, reason,
      event["content"]);

  json response;
  response["event_id"] = event_id;
  response["room_id"] = room_id;
  return response;
}

json RoomInviteEngine::accept_invite(
    const std::string& domain,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& room_version,
    LoggingTransaction& txn) {

  if (!store_->has_pending_invite_txn(txn, room_id, user_id)) {
    json resp;
    resp["errcode"] = "M_NOT_FOUND";
    resp["error"] = "No pending invite found for this room";
    return resp;
  }

  // Accept the invite
  int64_t ts = now_ms();
  store_->accept_invite_txn(txn, room_id, user_id, ts);

  // Build join event
  json event = event_creator_->build_member_event(
      domain, room_id, user_id, user_id, "join",
      {}, {}, 1, std::nullopt, std::nullopt,
      "Accepted invitation", false);

  std::string event_id = event["event_id"].get<std::string>();

  store_->upsert_membership_txn(
      txn, room_id, user_id, "join", event_id, user_id, ts);
  store_->record_membership_event_txn(
      txn, room_id, user_id, "invite", "join",
      event_id, user_id, ts, "Accepted invitation",
      event["content"]);
  store_->record_first_join_txn(txn, room_id, user_id, ts);
  store_->record_last_join_txn(txn, room_id, user_id, ts);

  json response;
  response["event_id"] = event_id;
  response["room_id"] = room_id;
  return response;
}

json RoomInviteEngine::reject_invite(
    const std::string& domain,
    const std::string& room_id,
    const std::string& user_id,
    LoggingTransaction& txn) {

  if (!store_->has_pending_invite_txn(txn, room_id, user_id)) {
    json resp;
    resp["errcode"] = "M_NOT_FOUND";
    resp["error"] = "No pending invite found for this room";
    return resp;
  }

  int64_t ts = now_ms();
  store_->reject_invite_txn(txn, room_id, user_id, ts);

  // Build a leave event to reject the invite
  json event = event_creator_->build_leave_event(
      domain, room_id, user_id, user_id,
      {}, {}, 1, "Invitation rejected", false);

  std::string event_id = event["event_id"].get<std::string>();
  store_->upsert_membership_txn(
      txn, room_id, user_id, "leave", event_id, user_id, ts);
  store_->record_membership_event_txn(
      txn, room_id, user_id, "invite", "leave",
      event_id, user_id, ts, "Invitation rejected",
      event["content"]);

  json response;
  response["event_id"] = event_id;
  return response;
}

// ============================================================================
// RoomKnockEngine — Implementations
// ============================================================================

std::pair<bool, std::string> RoomKnockEngine::validate_knock(
    const std::string& room_id,
    const std::string& user_id,
    LoggingTransaction& txn) {

  // User must not already be a member
  if (store_->is_membership_txn(txn, room_id, user_id, "join")) {
    return {false, "You are already a member of this room"};
  }

  // User must not be banned
  if (store_->is_banned_txn(txn, room_id, user_id)) {
    return {false, "You are banned from this room"};
  }

  // User must not already have a pending knock
  if (store_->has_pending_knock_txn(txn, room_id, user_id)) {
    return {false, "You already have a pending knock request for this room"};
  }

  return {true, ""};
}

json RoomKnockEngine::submit_knock(
    const std::string& domain,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& room_version,
    const std::string& reason,
    LoggingTransaction& txn) {

  auto [valid, error] = validate_knock(room_id, user_id, txn);
  if (!valid) {
    json resp;
    resp["errcode"] = "M_FORBIDDEN";
    resp["error"] = error;
    return resp;
  }

  // Build knock event
  json event = event_creator_->build_knock_event(
      domain, room_id, user_id, user_id,
      {}, {}, 1, reason);

  std::string event_id = event["event_id"].get<std::string>();
  int64_t ts = now_ms();
  std::string prev = store_->get_membership_state_txn(txn, room_id, user_id);

  // Persist membership as "knock"
  store_->upsert_membership_txn(
      txn, room_id, user_id, "knock", event_id, user_id, ts,
      std::nullopt, std::nullopt, reason);

  // Enqueue knock for admin review
  store_->enqueue_knock_txn(txn, room_id, user_id, event_id, reason, ts);

  // Record in history
  store_->record_membership_event_txn(
      txn, room_id, user_id, prev, "knock",
      event_id, user_id, ts, reason,
      event["content"]);

  json response;
  response["event_id"] = event_id;
  response["room_id"] = room_id;
  return response;
}

json RoomKnockEngine::approve_knock(
    const std::string& domain,
    const std::string& room_id,
    const std::string& knocked_user,
    const std::string& approved_by,
    const std::string& room_version,
    LoggingTransaction& txn) {

  if (!store_->has_pending_knock_txn(txn, room_id, knocked_user)) {
    json resp;
    resp["errcode"] = "M_NOT_FOUND";
    resp["error"] = "No pending knock found for this user in this room";
    return resp;
  }

  int64_t ts = now_ms();
  store_->approve_knock_txn(txn, room_id, knocked_user, approved_by, ts);

  // Build join event
  json event = event_creator_->build_member_event(
      domain, room_id, approved_by, knocked_user, "join",
      {}, {}, 1, std::nullopt, std::nullopt,
      "Knock approved by " + approved_by, false);

  std::string event_id = event["event_id"].get<std::string>();

  store_->upsert_membership_txn(
      txn, room_id, knocked_user, "join", event_id, approved_by, ts);
  store_->record_membership_event_txn(
      txn, room_id, knocked_user, "knock", "join",
      event_id, approved_by, ts, "Knock approved",
      event["content"]);
  store_->record_first_join_txn(txn, room_id, knocked_user, ts);
  store_->record_last_join_txn(txn, room_id, knocked_user, ts);

  json response;
  response["event_id"] = event_id;
  response["room_id"] = room_id;
  return response;
}

json RoomKnockEngine::reject_knock(
    const std::string& domain,
    const std::string& room_id,
    const std::string& knocked_user,
    const std::string& rejected_by,
    const std::string& rejection_reason,
    LoggingTransaction& txn) {

  if (!store_->has_pending_knock_txn(txn, room_id, knocked_user)) {
    json resp;
    resp["errcode"] = "M_NOT_FOUND";
    resp["error"] = "No pending knock found for this user in this room";
    return resp;
  }

  int64_t ts = now_ms();
  store_->reject_knock_txn(txn, room_id, knocked_user,
                            rejected_by, rejection_reason, ts);

  // Build leave event for the rejected knock
  json event = event_creator_->build_leave_event(
      domain, room_id, rejected_by, knocked_user,
      {}, {}, 1, "Knock rejected: " + rejection_reason, false);

  std::string event_id = event["event_id"].get<std::string>();

  store_->upsert_membership_txn(
      txn, room_id, knocked_user, "leave", event_id, rejected_by, ts);
  store_->record_membership_event_txn(
      txn, room_id, knocked_user, "knock", "leave",
      event_id, rejected_by, ts, "Knock rejected: " + rejection_reason,
      event["content"]);

  json response;
  response["event_id"] = event_id;
  return response;
}

json RoomKnockEngine::get_pending_knocks(
    const std::string& room_id,
    LoggingTransaction& txn) {

  return store_->get_pending_knocks_txn(txn, room_id);
}

int64_t RoomKnockEngine::purge_expired_knocks(
    int64_t older_than_ts,
    LoggingTransaction& txn) {

  return store_->purge_expired_knocks_txn(txn, older_than_ts);
}

// ============================================================================
// FederationJoinHandler — Implementations
// ============================================================================

AuthResult FederationJoinHandler::validate_remote_join(
    const json& event,
    const std::string& room_id,
    const std::string& user_id,
    LoggingTransaction& txn) {

  // Validate the event has the required shape
  auto [valid, err] = EventCreator::validate_member_event(event);
  if (!valid) {
    return AuthResult::deny("M_INVALID_PARAM", err);
  }

  // Check membership value is "join"
  std::string membership = EventCreator::extract_membership(
      event["content"]);
  if (membership != "join") {
    return AuthResult::deny("M_INVALID_PARAM",
        "Remote join event must have membership=join");
  }

  // Check user isn't banned
  if (store_->is_banned_txn(txn, room_id, user_id)) {
    return AuthResult::deny("M_FORBIDDEN",
        "User is banned from this room");
  }

  return AuthResult::allow();
}

void FederationJoinHandler::persist_remote_state(
    const std::string& room_id,
    const json& state_events,
    LoggingTransaction& txn) {

  // Persist state events received from the remote server.
  // In a full implementation, this would:
  //   1. Validate each event's signature
  //   2. Check the auth chain
  //   3. Resolve conflicts with existing state
  //   4. Persist to current_state_events table
  //
  // This stub accepts the state as-is.

  if (!state_events.is_array()) return;

  for (auto& ev : state_events) {
    if (!ev.contains("type") || !ev.contains("state_key")) continue;
    if (!ev.contains("event_id") || !ev.contains("content")) continue;

    std::string type = ev["type"];
    std::string state_key = ev["state_key"];
    std::string event_id = ev["event_id"];
    std::string content_str = ev["content"].dump();

    txn.execute(
        "INSERT OR REPLACE INTO current_state_events "
        "(room_id, type, state_key, event_id, content_json, origin_server_ts) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        {room_id, type, state_key, event_id, content_str,
         ev.value("origin_server_ts", json(0LL)).get<int64_t>()});
  }
}

json FederationJoinHandler::handle_send_join(
    const std::string& room_id,
    const std::string& event_id,
    const json& event,
    const std::string& room_version,
    const std::string& origin,
    LoggingTransaction& txn) {

  std::string user_id = event.value("state_key", "");

  // Validate authorization
  AuthResult auth = validate_remote_join(event, room_id, user_id, txn);
  if (!auth.allowed) {
    json resp;
    resp["errcode"] = auth.errcode;
    resp["error"] = auth.error;
    return resp;
  }

  int64_t ts = now_ms();

  // Persist the join event
  std::string membership = EventCreator::extract_membership(event["content"]);
  store_->upsert_membership_txn(
      txn, room_id, user_id, "join", event_id,
      event.value("sender", origin),
      event.value("origin_server_ts", ts));

  // Record the originating server as a room host
  store_->add_room_host_txn(txn, room_id, origin);

  // Persist any state events included with the join
  if (event.contains("state")) {
    persist_remote_state(room_id, event["state"], txn);
  }

  // Return current room state to the remote server
  json response;
  response["origin"] = "progressive.localhost";
  response["event_id"] = event_id;

  // Include auth chain and current state
  json auth_chain = json::array();
  auto auth_rows = txn.select(
      "SELECT event_id, content_json FROM current_state_events "
      "WHERE room_id = ? AND type IN "
      "('m.room.create', 'm.room.power_levels', 'm.room.join_rules')",
      {room_id});
  for (auto& row : auth_rows) {
    auth_chain.push_back(row->get<std::string>(0));
  }
  response["auth_chain"] = auth_chain;

  json state = json::array();
  auto state_rows = txn.select(
      "SELECT event_id, type, state_key, content_json "
      "FROM current_state_events WHERE room_id = ?",
      {room_id});
  for (auto& row : state_rows) {
    json s;
    s["event_id"] = row->get<std::string>(0);
    s["type"] = row->get<std::string>(1);
    s["state_key"] = row->get<std::string>(2);
    s["content"] = json::parse(row->get<std::string>(3));
    s["origin_server_ts"] = ts;
    state.push_back(s);
  }
  response["state"] = state;

  return response;
}

json FederationJoinHandler::make_join(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& remote_server,
    LoggingTransaction& txn) {

  // In production: make HTTP request to remote_server for /make_join/{roomId}/{userId}
  // Return the template event.
  json response;
  response["room_version"] = "10";
  response["event"] = json::object({
    {"type", "m.room.member"},
    {"sender", user_id},
    {"state_key", user_id},
    {"room_id", room_id},
    {"content", {
      {"membership", "join"}
    }},
    {"origin", remote_server},
    {"origin_server_ts", now_ms()}
  });
  return response;
}

json FederationJoinHandler::send_join(
    const std::string& room_id,
    const std::string& event_id,
    const json& event,
    const std::string& remote_server,
    LoggingTransaction& txn) {

  // In production: send the completed event to remote_server via /send_join
  // Return the room state the remote server responds with.
  json response;
  response["origin"] = remote_server;
  response["event_id"] = event_id;
  response["state"] = json::array();
  response["auth_chain"] = json::array();
  return response;
}

json FederationJoinHandler::process_join_response(
    const std::string& room_id,
    const std::string& user_id,
    const json& remote_state,
    const std::string& room_version,
    LoggingTransaction& txn) {

  // Persist remote state from join response
  persist_remote_state(room_id, remote_state, txn);

  json response;
  response["status"] = "ok";
  response["room_id"] = room_id;
  return response;
}

void FederationJoinHandler::propagate_join_to_servers(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& event_id,
    LoggingTransaction& txn) {

  // In production: notify other servers hosting this room about the new join.
  auto hosts = store_->get_room_hosts_txn(txn, room_id);
  for (auto& host : hosts) {
    std::string server = host["server_name"].get<std::string>();
    // Send join event to each server via federation
    (void)server;
  }
}

json FederationJoinHandler::join_remote_room(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& remote_server,
    const std::string& room_version,
    const std::optional<std::string>& reason,
    LoggingTransaction& txn) {

  // Step 1: Make join
  json make_join_resp = make_join(room_id, user_id, remote_server, txn);
  json template_event = make_join_resp["event"];

  // Step 2: Complete the event (sign it, fill in missing fields)
  template_event["origin_server_ts"] = now_ms();
  template_event["event_id"] = generate_event_id("progressive.localhost");
  if (reason) template_event["content"]["reason"] = *reason;

  std::string event_id = template_event["event_id"];

  // Step 3: Send join
  json send_join_resp = send_join(room_id, event_id, template_event,
                                   remote_server, txn);

  // Step 4: Process the join response (persist remote state)
  if (send_join_resp.contains("state")) {
    process_join_response(room_id, user_id, send_join_resp["state"],
                           room_version, txn);
  }

  // Step 5: Persist local membership
  int64_t ts = now_ms();
  store_->upsert_membership_txn(
      txn, room_id, user_id, "join", event_id, user_id, ts);
  store_->add_room_host_txn(txn, room_id, remote_server);

  json response;
  response["event_id"] = event_id;
  response["room_id"] = room_id;
  return response;
}

// ============================================================================
// MembershipHistoryTracker — Implementations
// ============================================================================

void MembershipHistoryTracker::record_transition(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& prev_membership,
    const std::string& new_membership,
    const std::string& event_id,
    const std::string& sender,
    int64_t timestamp,
    const std::optional<std::string>& reason,
    LoggingTransaction& txn) {

  store_->record_membership_event_txn(
      txn, room_id, user_id, prev_membership, new_membership,
      event_id, sender, timestamp, reason);
}

json MembershipHistoryTracker::get_history(
    const std::string& room_id,
    const std::string& user_id,
    int limit,
    LoggingTransaction& txn) {

  return store_->get_membership_history_txn(txn, room_id, user_id, limit);
}

json MembershipHistoryTracker::get_recent_room_changes(
    const std::string& room_id,
    int limit,
    LoggingTransaction& txn) {

  return store_->get_recent_membership_events_txn(txn, room_id, limit);
}

json MembershipHistoryTracker::export_user_membership_data(
    const std::string& user_id,
    LoggingTransaction& txn) {

  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, prev_membership, new_membership, event_id, "
      "sender, content_json, reason, timestamp "
      "FROM room_membership_history "
      "WHERE user_id = ? "
      "ORDER BY timestamp ASC",
      {user_id});

  for (auto& row : rows) {
    json entry;
    entry["room_id"] = row->get<std::string>(0);
    entry["prev_membership"] = row->get<std::string>(1);
    entry["new_membership"] = row->get<std::string>(2);
    entry["event_id"] = row->get<std::string>(3);
    entry["sender"] = row->get<std::string>(4);
    try { entry["content"] = json::parse(row->get<std::string>(5)); }
    catch (...) { entry["content"] = json::object(); }
    if (!row->is_null(6) && !row->get<std::string>(6).empty())
      entry["reason"] = row->get<std::string>(6);
    entry["timestamp"] = row->get<int64_t>(7);
    result.push_back(entry);
  }
  return result;
}

json MembershipHistoryTracker::detect_suspicious_patterns(
    const std::string& user_id,
    LoggingTransaction& txn) {

  json result;
  result["suspicious"] = false;

  // Count join/leave cycles in the last 24 hours
  int64_t day_ago = now_ms() - 86400000LL;
  auto cycle_count = txn.select_one(
      "SELECT COUNT(*) FROM room_membership_history "
      "WHERE user_id = ? AND timestamp > ? "
      "AND (new_membership = 'join' OR new_membership = 'leave')",
      {user_id, day_ago});

  int64_t cycles = cycle_count ? cycle_count->get<int64_t>(0) : 0;

  // Flag if more than 50 join/leave transitions in 24 hours
  if (cycles > 50) {
    result["suspicious"] = true;
    result["reason"] = "Excessive join/leave cycles in 24 hours";
    result["transition_count_24h"] = cycles;
  }

  return result;
}

// ============================================================================
// ForgottenRoomManager — Implementations
// ============================================================================

json ForgottenRoomManager::forget_room(
    const std::string& user_id,
    const std::string& room_id,
    LoggingTransaction& txn) {

  int64_t ts = now_ms();
  store_->forget_room_txn(txn, user_id, room_id, ts);

  json response;
  response["status"] = "ok";
  response["forgotten_ts"] = ts;
  return response;
}

json ForgottenRoomManager::unforget_room(
    const std::string& user_id,
    const std::string& room_id,
    LoggingTransaction& txn) {

  store_->unforget_room_txn(txn, user_id, room_id);

  json response;
  response["status"] = "ok";
  return response;
}

json ForgottenRoomManager::get_forgotten_rooms(
    const std::string& user_id,
    LoggingTransaction& txn) {

  return store_->get_forgotten_rooms_txn(txn, user_id);
}

bool ForgottenRoomManager::is_forgotten(
    const std::string& user_id,
    const std::string& room_id,
    LoggingTransaction& txn) {

  return store_->is_room_forgotten_txn(txn, user_id, room_id);
}

int64_t ForgottenRoomManager::auto_forget_stale_rooms(
    const std::string& user_id,
    int64_t stale_threshold_ms,
    LoggingTransaction& txn) {

  int64_t cutoff = now_ms() - stale_threshold_ms;
  int64_t count = 0;

  // Find rooms where the user has left and hasn't had activity
  // since the cutoff, and aren't already forgotten.
  auto rows = txn.select(
      "SELECT m.room_id FROM room_memberships m "
      "LEFT JOIN room_forgotten f ON m.room_id = f.room_id AND f.user_id = ? "
      "WHERE m.user_id = ? AND m.membership = 'leave' "
      "AND m.updated_ts < ? AND f.room_id IS NULL",
      {user_id, user_id, cutoff});

  for (auto& row : rows) {
    std::string room_id = row->get<std::string>(0);
    store_->forget_room_txn(txn, user_id, room_id, now_ms());
    ++count;
  }

  return count;
}

} // namespace progressive
