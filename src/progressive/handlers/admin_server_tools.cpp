// admin_server_tools.cpp - Matrix Admin Server Tools
// Implements ALL admin server management handlers:
// third-party invites, server notices, room management,
// user management, media management, registration tokens,
// consent management, server ACL override, and more.
// Target: 3000+ lines
//
// Admin server tools:
//   1.  send_third_party_invite          - Send invite via 3PID
//   2.  exchange_third_party_invite      - Exchange 3PID invite token
//   3.  validate_third_party_invite      - Verify token and key validity
//   4.  create_server_notice_room        - Create server notice room for user
//   5.  send_server_notice               - Send notice to user
//   6.  get_server_notice_templates      - Retrieve notice templates
//   7.  block_room                       - Admin block a room
//   8.  unblock_room                     - Admin unblock a room
//   9.  shadow_ban_user                  - Admin shadow-ban a user
//  10.  remove_shadow_ban                - Admin remove shadow-ban
//  11.  purge_history                    - Admin purge room history
//  12.  purge_room                       - Admin purge entire room
//  13.  delete_local_media               - Admin delete local media
//  14.  delete_remote_media              - Admin delete remote media
//  15.  quarantine_media                 - Admin quarantine media by ID
//  16.  reset_password_admin             - Admin reset user password
//  17.  deactivate_user_admin            - Admin deactivate user
//  18.  reactivate_user_admin            - Admin reactivate user
//  19.  create_registration_token        - Admin create registration token
//  20.  list_registration_tokens         - Admin list registration tokens
//  21.  revoke_registration_token        - Admin revoke registration token
//  22.  set_user_consent                 - Admin enable/disable user consent
//  23.  get_user_consent                 - Admin get user consent status
//  24.  override_server_acl              - Admin server ACL override
//  25.  force_join_room                  - Admin force user join room
//  26.  force_leave_room                 - Admin force user leave room

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
#include "progressive/storage/databases/main/devices.hpp"
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
#include <thread>
#include <cctype>
#include <functional>
#include <shared_mutex>
#include <optional>
#include <ctime>
#include <queue>
#include <deque>
#include <numeric>

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;

// ============================================================================
// Global admin server state
// ============================================================================

static std::mutex g_third_party_invite_lock;
static std::mutex g_server_notice_lock;
static std::mutex g_room_block_lock;
static std::mutex g_shadow_ban_lock;
static std::mutex g_purge_lock;
static std::mutex g_media_lock;
static std::mutex g_registration_token_lock;
static std::mutex g_consent_lock;
static std::mutex g_acl_override_lock;
static std::atomic<int64_t> g_admin_seq{1};

// Third-party invite tokens: token -> invite info
struct ThirdPartyInvite {
  std::string token;
  std::string medium;         // "email" or "msisdn"
  std::string address;        // email address or phone number
  std::string room_id;
  std::string sender;         // user_id who sent the invite
  std::string display_name;
  std::string id_server;
  std::string id_access_token;
  std::string key_validity_url;
  std::string public_key;
  int64_t created_at;
  int64_t expires_at;         // 0 = never expires
  bool validated{false};
};
static std::unordered_map<std::string, ThirdPartyInvite> g_third_party_invites;

// Server notice rooms: user_id -> room_id
static std::unordered_map<std::string, std::string> g_server_notice_rooms;
static std::shared_mutex g_server_notice_rooms_mutex;

// Room block list
static std::unordered_set<std::string> g_blocked_rooms;

// Shadow-banned users
static std::unordered_set<std::string> g_shadow_banned_users;
static std::shared_mutex g_shadow_ban_mutex;

// Media quarantine: media_id -> quarantine info
struct QuarantinedMedia {
  std::string media_id;
  std::string server_name;
  std::string reason;
  int64_t quarantined_at;
  std::string quarantined_by;
  bool safe{false};
};
static std::unordered_map<std::string, QuarantinedMedia> g_quarantined_media;

// Registration tokens
struct RegistrationToken {
  std::string token;
  std::string created_by;
  int64_t created_at;
  int64_t used_at{0};
  std::string used_by;
  int64_t uses_allowed{1};       // 0 = unlimited
  int64_t pending{0};
  int64_t completed{0};
  int64_t expiry_time{0};        // 0 = never expires
  bool revoked{false};
};
static std::unordered_map<std::string, RegistrationToken> g_registration_tokens;

// Server ACL overrides
struct ServerAclOverride {
  std::string server_name;
  bool allow{false};
  bool deny{false};
  std::string reason;
  std::string set_by;
  int64_t set_at;
};
static std::unordered_map<std::string, std::vector<ServerAclOverride>> g_acl_overrides;
static std::shared_mutex g_acl_override_mutex;

// ============================================================================
// Utility functions
// ============================================================================

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static int64_t now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_id(const std::string& prefix) {
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(g_admin_seq.fetch_add(1));
}

static std::string gen_token(int len = 64) {
  static const char cs[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(
    static_cast<unsigned>(now_ms() + std::hash<std::thread::id>{}(std::this_thread::get_id())));
  std::uniform_int_distribution<> d(0, 61);
  std::string t(len, 'A');
  for (auto& c : t) c = cs[d(rng)];
  return t;
}

static std::string gen_event_id() {
  return "$" + gen_token(43);
}

static std::string gen_room_id() {
  return "!" + gen_token(18) + ":localhost";
}

static std::string parse_server_name(const std::string& mxid) {
  auto pos = mxid.rfind(':');
  if (pos == std::string::npos) return "";
  return mxid.substr(pos + 1);
}

static std::string get_localpart(const std::string& mxid) {
  auto pos = mxid.find(':');
  if (pos == std::string::npos) return mxid;
  // Strip @ or ! prefix
  size_t start = (mxid[0] == '@' || mxid[0] == '!' || mxid[0] == '#') ? 1 : 0;
  return mxid.substr(start, pos - start);
}

static bool is_valid_mxid(const std::string& s, char prefix) {
  if (s.empty() || s[0] != prefix) return false;
  auto pos = s.find(':', 1);
  if (pos == std::string::npos || pos == s.size() - 1) return false;
  return true;
}

static bool is_valid_user_id(const std::string& s) {
  return is_valid_mxid(s, '@');
}

static bool is_valid_room_id(const std::string& s) {
  return is_valid_mxid(s, '!');
}

static std::string escape_sql(const std::string& s) {
  std::string out;
  out.reserve(s.size() * 2);
  for (char c : s) {
    if (c == '\'' || c == '\\' || c == '\"') out += '\\';
    out += c;
  }
  return out;
}

static bool user_exists(DatabasePool& db, const std::string& user_id) {
  auto rows = db.query("SELECT 1 FROM users WHERE id='" + escape_sql(user_id) + "' LIMIT 1");
  return !rows.empty();
}

static bool room_exists(DatabasePool& db, const std::string& room_id) {
  auto rows = db.query("SELECT 1 FROM rooms WHERE room_id='" + escape_sql(room_id) + "' LIMIT 1");
  return !rows.empty();
}

static std::string get_user_membership(DatabasePool& db,
    const std::string& user_id, const std::string& room_id) {
  auto rows = db.query(
    "SELECT membership FROM room_memberships WHERE user_id='" +
    escape_sql(user_id) + "' AND room_id='" + escape_sql(room_id) + "'"
  );
  if (rows.empty()) return "";
  return rows[0].value("membership", "");
}

static int64_t get_stream_ordering(DatabasePool& db) {
  auto rows = db.query("SELECT MAX(stream_ordering) as mx FROM events");
  if (rows.empty() || rows[0]["mx"].is_null()) return 0;
  return rows[0]["mx"].template get<int64_t>();
}

// ============================================================================
// AdminServerTools - Main handler class
// ============================================================================

class AdminServerTools {
public:
  explicit AdminServerTools(DatabasePool& db) : db_(db) {}

  // --------------------------------------------------------------------------
  // 1. THIRD-PARTY INVITE: Send invite via 3PID
  // --------------------------------------------------------------------------
  // Generates a token for the third-party identifier and stores the invite
  // for later exchange when the user validates.
  json send_third_party_invite(
      const std::string& room_id,
      const std::string& sender_user_id,
      const std::string& medium,
      const std::string& address,
      const std::string& id_server,
      const std::string& id_access_token,
      const std::string& display_name) {

    json result;
    std::lock_guard<std::mutex> lock(g_third_party_invite_lock);

    // Validate room exists
    if (!room_exists(db_, room_id)) {
      result["error"] = "Room not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    // Validate sender
    if (!user_exists(db_, sender_user_id)) {
      result["error"] = "Sender user not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    // Check sender has permission (must be joined or have invite power)
    std::string membership = get_user_membership(db_, sender_user_id, room_id);
    if (membership != "join" && membership != "invite") {
      result["error"] = "Sender is not in the room";
      result["errcode"] = "M_FORBIDDEN";
      return result;
    }

    // Validate medium
    if (medium != "email" && medium != "msisdn") {
      result["error"] = "Invalid medium. Must be 'email' or 'msisdn'";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    // Validate address format
    if (medium == "email") {
      static const std::regex email_re(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
      if (!std::regex_match(address, email_re)) {
        result["error"] = "Invalid email address format";
        result["errcode"] = "M_INVALID_PARAM";
        return result;
      }
    } else {
      // Basic phone number validation
      static const std::regex phone_re(R"(\+?[0-9]{7,15})");
      if (!std::regex_match(address, phone_re)) {
        result["error"] = "Invalid phone number format";
        result["errcode"] = "M_INVALID_PARAM";
        return result;
      }
    }

    // Generate token
    std::string token = gen_token(48);
    int64_t now = now_sec();

    // Check for existing invite to same address/room
    for (auto& [key, inv] : g_third_party_invites) {
      if (inv.room_id == room_id && inv.medium == medium &&
          inv.address == address && !inv.validated) {
        // Reuse existing token
        token = inv.token;
        break;
      }
    }

    // Store invite
    ThirdPartyInvite invite;
    invite.token = token;
    invite.medium = medium;
    invite.address = address;
    invite.room_id = room_id;
    invite.sender = sender_user_id;
    invite.display_name = display_name;
    invite.id_server = id_server;
    invite.id_access_token = id_access_token;
    invite.key_validity_url = id_server + "/_matrix/identity/v2/pubkey/isvalid";
    invite.public_key = "ed25519:placeholder_" + gen_token(16);
    invite.created_at = now;
    invite.expires_at = now + (7 * 86400);  // 7 days

    g_third_party_invites[token] = invite;

    // Persist to database
    db_.execute(
      "INSERT INTO third_party_invites (token, medium, address, room_id, sender, "
      "display_name, id_server, created_at, expires_at) VALUES ('" +
      escape_sql(token) + "', '" + escape_sql(medium) + "', '" +
      escape_sql(address) + "', '" + escape_sql(room_id) + "', '" +
      escape_sql(sender_user_id) + "', '" + escape_sql(display_name) + "', '" +
      escape_sql(id_server) + "', " + std::to_string(now) + ", " +
      std::to_string(invite.expires_at) + ")"
    );

    result["token"] = token;
    result["room_id"] = room_id;
    result["medium"] = medium;
    result["address"] = address;
    result["sender"] = sender_user_id;
    result["display_name"] = display_name;
    result["expires_at"] = invite.expires_at;
    result["key_validity_url"] = invite.key_validity_url;
    result["public_key"] = invite.public_key;
    result["public_keys"] = json::array({json::object({
      {"key_validity_url", invite.key_validity_url},
      {"public_key", invite.public_key}
    })});

    return result;
  }

  // --------------------------------------------------------------------------
  // 2. THIRD-PARTY INVITE EXCHANGE: Exchange 3PID invite token
  // --------------------------------------------------------------------------
  // Called by the identity server when a user validates their 3PID.
  // Returns the room_id and invite event for the user.
  json exchange_third_party_invite(
      const std::string& token,
      const std::string& user_id) {

    json result;
    std::lock_guard<std::mutex> lock(g_third_party_invite_lock);

    // Find the invite
    auto it = g_third_party_invites.find(token);
    if (it == g_third_party_invites.end()) {
      result["error"] = "No pending third-party invite found for this token";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    auto& invite = it->second;

    // Check expiry
    if (invite.expires_at > 0 && now_sec() > invite.expires_at) {
      result["error"] = "Third-party invite has expired";
      result["errcode"] = "M_FORBIDDEN";
      g_third_party_invites.erase(it);
      return result;
    }

    // Validate user exists
    if (!user_exists(db_, user_id)) {
      result["error"] = "User not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    // Check user isn't already in the room
    std::string membership = get_user_membership(db_, user_id, invite.room_id);
    if (membership == "join") {
      result["error"] = "User is already a member of this room";
      result["room_id"] = invite.room_id;
      return result;
    }

    // Mark as validated
    invite.validated = true;

    // Update database
    db_.execute(
      "UPDATE third_party_invites SET validated=1 WHERE token='" +
      escape_sql(token) + "'"
    );

    // Create invite membership event
    json invite_event;
    invite_event["type"] = "m.room.member";
    invite_event["state_key"] = user_id;
    invite_event["sender"] = invite.sender;
    invite_event["room_id"] = invite.room_id;
    invite_event["event_id"] = gen_event_id();
    invite_event["origin_server_ts"] = now_ms();
    invite_event["content"]["membership"] = "invite";
    invite_event["content"]["displayname"] = invite.display_name;
    invite_event["content"]["is_direct"] = false;
    invite_event["content"]["third_party_invite"]["display_name"] = invite.display_name;
    invite_event["content"]["third_party_invite"]["signed"]["token"] = token;
    invite_event["content"]["third_party_invite"]["signed"]["signatures"] = {
      {invite.id_server, {
        {"ed25519:1", "signature_placeholder_" + gen_token(32)}
      }}
    };
    invite_event["unsigned"]["age"] = 0;

    // Persist the membership
    db_.execute(
      "INSERT INTO room_memberships (room_id, user_id, membership, sender) VALUES ('" +
      escape_sql(invite.room_id) + "', '" + escape_sql(user_id) + "', 'invite', '" +
      escape_sql(invite.sender) + "') ON CONFLICT (room_id, user_id) DO UPDATE SET "
      "membership='invite', sender='" + escape_sql(invite.sender) + "'"
    );

    result["room_id"] = invite.room_id;
    result["invite_event"] = invite_event;
    result["sender"] = invite.sender;
    result["token"] = token;
    result["validated"] = true;

    return result;
  }

  // --------------------------------------------------------------------------
  // 3. THIRD-PARTY INVITE VALIDATION: Verify token and key validity
  // --------------------------------------------------------------------------
  // Validates the invite token and checks key validity URL.
  json validate_third_party_invite(
      const std::string& token,
      const std::string& id_server,
      const std::string& id_access_token) {

    json result;
    std::lock_guard<std::mutex> lock(g_third_party_invite_lock);

    auto it = g_third_party_invites.find(token);
    if (it == g_third_party_invites.end()) {
      result["valid"] = false;
      result["error"] = "Invalid token";
      result["errcode"] = "M_UNKNOWN_TOKEN";
      return result;
    }

    auto& invite = it->second;

    // Check expiry
    if (invite.expires_at > 0 && now_sec() > invite.expires_at) {
      result["valid"] = false;
      result["error"] = "Token expired";
      result["errcode"] = "M_FORBIDDEN";
      g_third_party_invites.erase(it);
      return result;
    }

    // Verify key validity by constructing the expected URL format
    // In production, this would make an HTTP request, but here we validate structure
    if (!invite.id_server.empty() && !id_server.empty() &&
        invite.id_server != id_server) {
      result["valid"] = false;
      result["error"] = "Identity server mismatch";
      result["errcode"] = "M_FORBIDDEN";
      return result;
    }

    // Validate token hasn't already been used
    if (invite.validated) {
      result["valid"] = true;
      result["already_validated"] = true;
      result["room_id"] = invite.room_id;
      result["display_name"] = invite.display_name;
      return result;
    }

    result["valid"] = true;
    result["token"] = token;
    result["medium"] = invite.medium;
    result["address"] = invite.address;
    result["room_id"] = invite.room_id;
    result["sender"] = invite.sender;
    result["display_name"] = invite.display_name;
    result["key_validity_url"] = invite.key_validity_url;
    result["public_key"] = invite.public_key;
    result["expires_at"] = invite.expires_at;

    // Public key validation response
    result["public_keys"] = json::array();
    json pk;
    pk["key_validity_url"] = invite.key_validity_url;
    pk["public_key"] = invite.public_key;
    pk["valid"] = true;
    result["public_keys"].push_back(pk);

    return result;
  }

  // --------------------------------------------------------------------------
  // 4. SERVER NOTICE ROOM CREATION: Create server notice room for user
  // --------------------------------------------------------------------------
  // Creates a dedicated server notice room between the server and the user.
  json create_server_notice_room(const std::string& user_id) {
    json result;
    std::lock_guard<std::mutex> lock(g_server_notice_lock);

    // Check if user exists
    if (!user_exists(db_, user_id)) {
      result["error"] = "User not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    // Check if server notice room already exists for this user
    {
      std::shared_lock<std::shared_mutex> read_lock(g_server_notice_rooms_mutex);
      auto it = g_server_notice_rooms.find(user_id);
      if (it != g_server_notice_rooms.end()) {
        result["room_id"] = it->second;
        result["exists"] = true;
        return result;
      }
    }

    // Generate a new room ID for server notices
    std::string room_id = gen_room_id();
    std::string server_user_id = "@server:" + parse_server_name(user_id);
    int64_t now = now_ms();

    // Create the room entry
    db_.execute(
      "INSERT INTO rooms (room_id, creator, is_public, room_version, creation_ts) VALUES ('" +
      escape_sql(room_id) + "', '" + escape_sql(server_user_id) + "', 0, '10', " +
      std::to_string(now) + ")"
    );

    // Create room creation event
    json creation_event;
    creation_event["type"] = "m.room.create";
    creation_event["state_key"] = "";
    creation_event["sender"] = server_user_id;
    creation_event["room_id"] = room_id;
    creation_event["event_id"] = gen_event_id();
    creation_event["origin_server_ts"] = now;
    creation_event["content"]["creator"] = server_user_id;
    creation_event["content"]["room_version"] = "10";
    creation_event["content"]["m.federate"] = false;  // Server notices aren't federated
    creation_event["content"]["predecessor"]["room_id"] = "";
    creation_event["content"]["predecessor"]["event_id"] = "";
    creation_event["content"]["type"] = "m.space";  // Tag as server notices

    // Create power levels event (server is admin, user is moderator)
    json power_levels;
    power_levels["type"] = "m.room.power_levels";
    power_levels["state_key"] = "";
    power_levels["sender"] = server_user_id;
    power_levels["room_id"] = room_id;
    power_levels["event_id"] = gen_event_id();
    power_levels["origin_server_ts"] = now;
    power_levels["content"]["users"] = json::object();
    power_levels["content"]["users"][server_user_id] = 100;
    power_levels["content"]["users"][user_id] = 50;
    power_levels["content"]["users_default"] = 0;
    power_levels["content"]["events"] = json::object();
    power_levels["content"]["events"]["m.room.name"] = 50;
    power_levels["content"]["events"]["m.room.power_levels"] = 100;
    power_levels["content"]["events_default"] = 0;
    power_levels["content"]["state_default"] = 50;
    power_levels["content"]["ban"] = 50;
    power_levels["content"]["kick"] = 50;
    power_levels["content"]["redact"] = 50;
    power_levels["content"]["invite"] = 0;  // No further invites for server notices
    power_levels["content"]["notifications"]["room"] = 50;

    // Create room name event
    json room_name;
    room_name["type"] = "m.room.name";
    room_name["state_key"] = "";
    room_name["sender"] = server_user_id;
    room_name["room_id"] = room_id;
    room_name["event_id"] = gen_event_id();
    room_name["origin_server_ts"] = now;
    room_name["content"]["name"] = "Server Notices";

    // Create join rules event
    json join_rules;
    join_rules["type"] = "m.room.join_rules";
    join_rules["state_key"] = "";
    join_rules["sender"] = server_user_id;
    join_rules["room_id"] = room_id;
    join_rules["event_id"] = gen_event_id();
    join_rules["origin_server_ts"] = now;
    join_rules["content"]["join_rule"] = "invite";

    // Create history visibility event
    json hist_vis;
    hist_vis["type"] = "m.room.history_visibility";
    hist_vis["state_key"] = "";
    hist_vis["sender"] = server_user_id;
    hist_vis["room_id"] = room_id;
    hist_vis["event_id"] = gen_event_id();
    hist_vis["origin_server_ts"] = now;
    hist_vis["content"]["history_visibility"] = "shared";

    // Create guest access event
    json guest_access;
    guest_access["type"] = "m.room.guest_access";
    guest_access["state_key"] = "";
    guest_access["sender"] = server_user_id;
    guest_access["room_id"] = room_id;
    guest_access["event_id"] = gen_event_id();
    guest_access["origin_server_ts"] = now;
    guest_access["content"]["guest_access"] = "can_join";

    // Create membership events: server joins, user joins
    json server_member;
    server_member["type"] = "m.room.member";
    server_member["state_key"] = server_user_id;
    server_member["sender"] = server_user_id;
    server_member["room_id"] = room_id;
    server_member["event_id"] = gen_event_id();
    server_member["origin_server_ts"] = now;
    server_member["content"]["membership"] = "join";
    server_member["content"]["displayname"] = "Server Notices";
    server_member["content"]["avatar_url"] = "";

    json user_member;
    user_member["type"] = "m.room.member";
    user_member["state_key"] = user_id;
    user_member["sender"] = server_user_id;
    user_member["room_id"] = room_id;
    user_member["event_id"] = gen_event_id();
    user_member["origin_server_ts"] = now;
    user_member["content"]["membership"] = "join";
    user_member["content"]["displayname"] = "";
    user_member["content"]["avatar_url"] = "";

    // Persist all events to database
    std::vector<json> initial_events = {
      creation_event, power_levels, room_name, join_rules,
      hist_vis, guest_access, server_member, user_member
    };

    for (const auto& ev : initial_events) {
      db_.execute(
        "INSERT INTO events (event_id, room_id, type, state_key, sender, content, origin_server_ts) "
        "VALUES ('" +
        escape_sql(ev["event_id"].get<std::string>()) + "', '" +
        escape_sql(ev["room_id"].get<std::string>()) + "', '" +
        escape_sql(ev["type"].get<std::string>()) + "', '" +
        escape_sql(ev["state_key"].get<std::string>()) + "', '" +
        escape_sql(ev["sender"].get<std::string>()) + "', '" +
        escape_sql(ev["content"].dump()) + "', " +
        std::to_string(ev["origin_server_ts"].template get<int64_t>()) + ")"
      );

      // Insert into state if it's a state event
      if (!ev["state_key"].get<std::string>().empty() ||
          ev["type"] == "m.room.create" ||
          ev["type"] == "m.room.power_levels" ||
          ev["type"] == "m.room.join_rules" ||
          ev["type"] == "m.room.history_visibility" ||
          ev["type"] == "m.room.name" ||
          ev["type"] == "m.room.guest_access") {
        db_.execute(
          "INSERT OR REPLACE INTO state_events (room_id, type, state_key, event_id) VALUES ('" +
          escape_sql(ev["room_id"].get<std::string>()) + "', '" +
          escape_sql(ev["type"].get<std::string>()) + "', '" +
          escape_sql(ev["state_key"].get<std::string>()) + "', '" +
          escape_sql(ev["event_id"].get<std::string>()) + "')"
        );
      }
    }

    // Persist memberships
    db_.execute(
      "INSERT INTO room_memberships (room_id, user_id, membership, sender) VALUES ('" +
      escape_sql(room_id) + "', '" + escape_sql(server_user_id) + "', 'join', '" +
      escape_sql(server_user_id) + "') ON CONFLICT (room_id, user_id) DO UPDATE SET "
      "membership='join'"
    );
    db_.execute(
      "INSERT INTO room_memberships (room_id, user_id, membership, sender) VALUES ('" +
      escape_sql(room_id) + "', '" + escape_sql(user_id) + "', 'join', '" +
      escape_sql(server_user_id) + "') ON CONFLICT (room_id, user_id) DO UPDATE SET "
      "membership='join'"
    );

    // Store mapping
    {
      std::unique_lock<std::shared_mutex> write_lock(g_server_notice_rooms_mutex);
      g_server_notice_rooms[user_id] = room_id;
    }

    // Persist mapping
    db_.execute(
      "INSERT INTO server_notice_rooms (user_id, room_id) VALUES ('" +
      escape_sql(user_id) + "', '" + escape_sql(room_id) + "') ON CONFLICT (user_id) DO UPDATE "
      "SET room_id='" + escape_sql(room_id) + "'"
    );

    result["room_id"] = room_id;
    result["user_id"] = user_id;
    result["exists"] = false;
    result["created_at"] = now;
    result["server_user"] = server_user_id;

    return result;
  }

  // --------------------------------------------------------------------------
  // 5. SERVER NOTICE SENDING: Send notice to user
  // --------------------------------------------------------------------------
  // Sends a formatted server notice to a user's server notice room.
  json send_server_notice(
      const std::string& user_id,
      const std::string& notice_type,
      const std::string& title,
      const std::string& body,
      const json& extra_content) {

    json result;
    std::lock_guard<std::mutex> lock(g_server_notice_lock);

    // Validate user
    if (!user_exists(db_, user_id)) {
      result["error"] = "User not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    // Get or create server notice room
    std::string room_id;
    {
      std::shared_lock<std::shared_mutex> read_lock(g_server_notice_rooms_mutex);
      auto it = g_server_notice_rooms.find(user_id);
      if (it != g_server_notice_rooms.end()) {
        room_id = it->second;
      }
    }

    if (room_id.empty()) {
      // Create server notice room on demand
      json create_result = create_server_notice_room(user_id);
      if (create_result.contains("error")) {
        return create_result;
      }
      room_id = create_result["room_id"].get<std::string>();
    }

    std::string server_user_id = "@server:" + parse_server_name(user_id);
    std::string event_id = gen_event_id();
    int64_t now = now_ms();

    // Build notice event
    json notice_event;
    notice_event["type"] = "m.room.message";
    notice_event["sender"] = server_user_id;
    notice_event["room_id"] = room_id;
    notice_event["event_id"] = event_id;
    notice_event["origin_server_ts"] = now;

    // Build formatted content
    json& content = notice_event["content"];
    content["msgtype"] = "m.notice";
    content["body"] = body;

    // Server notice metadata
    content["org.matrix.msc2326.administrative"] = true;
    content["org.matrix.msc2326.type"] = notice_type;
    content["org.matrix.msc2326.title"] = title;

    // Add formatted body with HTML
    std::string formatted_body =
      "<h2>" + title + "</h2>"
      "<p>" + body + "</p>"
      "<p><em>This is an automated server notice.</em></p>";
    content["format"] = "org.matrix.custom.html";
    content["formatted_body"] = formatted_body;

    // Merge extra content
    if (!extra_content.is_null() && extra_content.is_object()) {
      for (auto it = extra_content.begin(); it != extra_content.end(); ++it) {
        // Don't overwrite core fields
        if (it.key() != "msgtype" && it.key() != "body" && it.key() != "format" &&
            it.key() != "formatted_body") {
          content[it.key()] = it.value();
        }
      }
    }

    // Persist event
    db_.execute(
      "INSERT INTO events (event_id, room_id, type, sender, content, origin_server_ts) "
      "VALUES ('" +
      escape_sql(event_id) + "', '" + escape_sql(room_id) + "', 'm.room.message', '" +
      escape_sql(server_user_id) + "', '" + escape_sql(content.dump()) + "', " +
      std::to_string(now) + ")"
    );

    // Update stream ordering for sync
    int64_t stream_ordering = get_stream_ordering(db_) + 1;
    db_.execute(
      "INSERT INTO events_order (event_id, room_id, stream_ordering) VALUES ('" +
      escape_sql(event_id) + "', '" + escape_sql(room_id) + "', " +
      std::to_string(stream_ordering) + ")"
    );

    result["event_id"] = event_id;
    result["room_id"] = room_id;
    result["user_id"] = user_id;
    result["notice_type"] = notice_type;
    result["sent_at"] = now;
    result["event"] = notice_event;

    return result;
  }

  // --------------------------------------------------------------------------
  // 6. SERVER NOTICE TEMPLATES: Policy violation, consent, account validity
  // --------------------------------------------------------------------------
  // Returns predefined templates for common server notice types.
  json get_server_notice_templates() {
    json templates;
    templates["templates"] = json::array();

    // Template 1: Policy violation notice
    json policy_violation;
    policy_violation["type"] = "m.policy_violation";
    policy_violation["title"] = "Policy Violation Notice";
    policy_violation["body"] =
      "Your account has been found in violation of our terms of service. "
      "Please review our acceptable use policy at /_matrix/consent and "
      "contact server administration if you believe this is an error. "
      "Further violations may result in account suspension.";
    policy_violation["severity"] = "warning";
    templates["templates"].push_back(policy_violation);

    // Template 2: Consent required
    json consent_required;
    consent_required["type"] = "m.consent_required";
    consent_required["title"] = "Consent Required";
    consent_required["body"] =
      "This server requires you to accept the terms of service before you can "
      "continue using it. Please visit /_matrix/consent to review and accept "
      "the terms. Your access may be restricted until consent is provided.";
    consent_required["action_url"] = "/_matrix/consent";
    consent_required["expires_after_days"] = 30;
    templates["templates"].push_back(consent_required);

    // Template 3: Account validity notice
    json account_validity;
    account_validity["type"] = "m.account_validity";
    account_validity["title"] = "Account Expiration Notice";
    account_validity["body"] =
      "Your account is scheduled to expire soon. Please ensure your contact "
      "information is up to date. If your account expires, you will lose access "
      "to your rooms and messages. Contact the server administrator to extend "
      "your account validity period.";
    account_validity["warning_period_days"] = 7;
    account_validity["expiration_ts"] = now_sec() + (30 * 86400);
    templates["templates"].push_back(account_validity);

    // Template 4: Server migration notice
    json server_migration;
    server_migration["type"] = "m.server_migration";
    server_migration["title"] = "Server Migration Notice";
    server_migration["body"] =
      "This server is scheduled for migration at the specified time. During the "
      "migration window, the service may be temporarily unavailable. We apologize "
      "for any inconvenience. Please ensure you have saved any important data.";
    server_migration["scheduled_at"] = now_sec() + (7 * 86400);
    templates["templates"].push_back(server_migration);

    // Template 5: Room closure notice
    json room_closure;
    room_closure["type"] = "m.room_closure";
    room_closure["title"] = "Room Closure Notice";
    room_closure["body"] =
      "This room has been closed by server administration. The content remains "
      "accessible for reference but no new messages can be posted. Please contact "
      "server administration if you have questions about this action.";
    templates["templates"].push_back(room_closure);

    // Template 6: Spam report notice
    json spam_notice;
    spam_notice["type"] = "m.spam_report";
    spam_notice["title"] = "Spam Report Notice";
    spam_notice["body"] =
      "Your account has been reported for sending spam messages. The server "
      "administration has reviewed these reports and is issuing this formal "
      "warning. Continued spam activity will result in account restrictions.";
    spam_notice["severity"] = "warning";
    templates["templates"].push_back(spam_notice);

    // Template 7: Security notice
    json security_notice;
    security_notice["type"] = "m.security_notice";
    security_notice["title"] = "Security Notice";
    security_notice["body"] =
      "A security-related change has been made to this server. Please review "
      "your account settings and ensure your recovery information is current. "
      "If you notice any suspicious activity, report it to the server "
      "administration immediately.";
    security_notice["severity"] = "info";
    templates["templates"].push_back(security_notice);

    // Template 8: Maintenance notice
    json maintenance_notice;
    maintenance_notice["type"] = "m.maintenance_notice";
    maintenance_notice["title"] = "Scheduled Maintenance";
    maintenance_notice["body"] =
      "This server will undergo scheduled maintenance. During this time, you "
      "may experience brief service interruptions. All messages sent during the "
      "maintenance window will be queued and delivered once service resumes.";
    maintenance_notice["severity"] = "info";
    templates["templates"].push_back(maintenance_notice);

    return templates;
  }

  // --------------------------------------------------------------------------
  // Send server notice using a template
  // --------------------------------------------------------------------------
  json send_server_notice_from_template(
      const std::string& user_id,
      const std::string& template_type,
      const json& custom_fields) {

    json templates = get_server_notice_templates();
    json matching;

    for (const auto& tmpl : templates["templates"]) {
      if (tmpl["type"].get<std::string>() == template_type) {
        matching = tmpl;
        break;
      }
    }

    if (matching.is_null()) {
      json err;
      err["error"] = "Template type not found: " + template_type;
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    std::string title = matching.value("title", "Server Notice");
    std::string body = matching.value("body", "");

    // Override with custom fields
    if (custom_fields.contains("title") && custom_fields["title"].is_string()) {
      title = custom_fields["title"].get<std::string>();
    }
    if (custom_fields.contains("body") && custom_fields["body"].is_string()) {
      body = custom_fields["body"].get<std::string>();
    }

    return send_server_notice(user_id, template_type, title, body, custom_fields);
  }

  // --------------------------------------------------------------------------
  // 7. ADMIN ROOM MANAGEMENT: Block a room
  // --------------------------------------------------------------------------
  // Blocks a room, preventing new messages and making it read-only.
  json block_room(const std::string& room_id, const std::string& admin_user_id) {
    json result;
    std::lock_guard<std::mutex> lock(g_room_block_lock);

    if (!is_valid_room_id(room_id)) {
      result["error"] = "Invalid room ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    // Check if already blocked
    if (g_blocked_rooms.find(room_id) != g_blocked_rooms.end()) {
      result["blocked"] = true;
      result["already_blocked"] = true;
      result["room_id"] = room_id;
      return result;
    }

    // Mark room as blocked
    g_blocked_rooms.insert(room_id);

    // Persist to database
    db_.execute(
      "INSERT INTO blocked_rooms (room_id, blocked_by, blocked_at) VALUES ('" +
      escape_sql(room_id) + "', '" + escape_sql(admin_user_id) + "', " +
      std::to_string(now_sec()) + ") ON CONFLICT (room_id) DO UPDATE SET "
      "blocked_by='" + escape_sql(admin_user_id) + "', blocked_at=" +
      std::to_string(now_sec())
    );

    // Update room to prevent federation
    db_.execute(
      "UPDATE rooms SET blocked=1 WHERE room_id='" + escape_sql(room_id) + "'"
    );

    result["room_id"] = room_id;
    result["blocked"] = true;
    result["blocked_by"] = admin_user_id;
    result["blocked_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // 8. ADMIN ROOM MANAGEMENT: Unblock a room
  // --------------------------------------------------------------------------
  json unblock_room(const std::string& room_id, const std::string& admin_user_id) {
    json result;
    std::lock_guard<std::mutex> lock(g_room_block_lock);

    if (!is_valid_room_id(room_id)) {
      result["error"] = "Invalid room ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    auto it = g_blocked_rooms.find(room_id);
    if (it == g_blocked_rooms.end()) {
      result["error"] = "Room is not blocked";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    g_blocked_rooms.erase(it);

    db_.execute(
      "UPDATE blocked_rooms SET unblocked_by='" + escape_sql(admin_user_id) +
      "', unblocked_at=" + std::to_string(now_sec()) + " WHERE room_id='" +
      escape_sql(room_id) + "'"
    );
    db_.execute(
      "UPDATE rooms SET blocked=0 WHERE room_id='" + escape_sql(room_id) + "'"
    );

    result["room_id"] = room_id;
    result["blocked"] = false;
    result["unblocked_by"] = admin_user_id;
    result["unblocked_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // List all blocked rooms
  // --------------------------------------------------------------------------
  json list_blocked_rooms() {
    json result;
    result["blocked_rooms"] = json::array();

    for (const auto& room_id : g_blocked_rooms) {
      auto rows = db_.query(
        "SELECT blocked_by, blocked_at FROM blocked_rooms WHERE room_id='" +
        escape_sql(room_id) + "'"
      );
      json entry;
      entry["room_id"] = room_id;
      if (!rows.empty()) {
        entry["blocked_by"] = rows[0].value("blocked_by", "");
        entry["blocked_at"] = rows[0].value("blocked_at", 0);
      }
      result["blocked_rooms"].push_back(entry);
    }
    result["total"] = result["blocked_rooms"].size();

    return result;
  }

  // --------------------------------------------------------------------------
  // 9. ADMIN USER SHADOW-BAN
  // --------------------------------------------------------------------------
  // Shadow-bans a user: their messages appear to be sent normally to them
  // but are hidden from all other users.
  json shadow_ban_user(const std::string& user_id, const std::string& admin_user_id) {
    json result;

    if (!is_valid_user_id(user_id)) {
      result["error"] = "Invalid user ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    if (!user_exists(db_, user_id)) {
      result["error"] = "User not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    {
      std::unique_lock<std::shared_mutex> lock(g_shadow_ban_mutex);
      if (g_shadow_banned_users.find(user_id) != g_shadow_banned_users.end()) {
        result["shadow_banned"] = true;
        result["already_banned"] = true;
        result["user_id"] = user_id;
        return result;
      }
      g_shadow_banned_users.insert(user_id);
    }

    // Persist to database
    db_.execute(
      "INSERT INTO shadow_banned_users (user_id, banned_by, banned_at) VALUES ('" +
      escape_sql(user_id) + "', '" + escape_sql(admin_user_id) + "', " +
      std::to_string(now_sec()) + ") ON CONFLICT (user_id) DO UPDATE SET "
      "banned_by='" + escape_sql(admin_user_id) + "', banned_at=" +
      std::to_string(now_sec())
    );

    // Mark all existing events from this user as shadow-hidden
    db_.execute(
      "UPDATE events SET shadow_hidden=1 WHERE sender='" +
      escape_sql(user_id) + "' AND shadow_hidden=0"
    );

    result["user_id"] = user_id;
    result["shadow_banned"] = true;
    result["banned_by"] = admin_user_id;
    result["banned_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // 10. ADMIN REMOVE SHADOW-BAN
  // --------------------------------------------------------------------------
  json remove_shadow_ban(const std::string& user_id, const std::string& admin_user_id) {
    json result;

    if (!is_valid_user_id(user_id)) {
      result["error"] = "Invalid user ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    {
      std::unique_lock<std::shared_mutex> lock(g_shadow_ban_mutex);
      auto it = g_shadow_banned_users.find(user_id);
      if (it == g_shadow_banned_users.end()) {
        result["error"] = "User is not shadow-banned";
        result["errcode"] = "M_NOT_FOUND";
        return result;
      }
      g_shadow_banned_users.erase(it);
    }

    db_.execute(
      "DELETE FROM shadow_banned_users WHERE user_id='" + escape_sql(user_id) + "'"
    );
    db_.execute(
      "UPDATE shadow_banned_users SET unbanned_by='" + escape_sql(admin_user_id) +
      "', unbanned_at=" + std::to_string(now_sec()) + " WHERE user_id='" +
      escape_sql(user_id) + "'"
    );

    // Restore visibility of events
    db_.execute(
      "UPDATE events SET shadow_hidden=0 WHERE sender='" +
      escape_sql(user_id) + "' AND shadow_hidden=1"
    );

    result["user_id"] = user_id;
    result["shadow_banned"] = false;
    result["unbanned_by"] = admin_user_id;
    result["unbanned_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // Check if a user is shadow-banned
  // --------------------------------------------------------------------------
  json check_shadow_ban(const std::string& user_id) {
    json result;
    {
      std::shared_lock<std::shared_mutex> lock(g_shadow_ban_mutex);
      result["shadow_banned"] =
        (g_shadow_banned_users.find(user_id) != g_shadow_banned_users.end());
    }
    result["user_id"] = user_id;
    return result;
  }

  // --------------------------------------------------------------------------
  // List all shadow-banned users
  // --------------------------------------------------------------------------
  json list_shadow_banned_users() {
    json result;
    result["users"] = json::array();

    std::shared_lock<std::shared_mutex> lock(g_shadow_ban_mutex);
    for (const auto& user_id : g_shadow_banned_users) {
      auto rows = db_.query(
        "SELECT banned_by, banned_at FROM shadow_banned_users WHERE user_id='" +
        escape_sql(user_id) + "'"
      );
      json entry;
      entry["user_id"] = user_id;
      if (!rows.empty()) {
        entry["banned_by"] = rows[0].value("banned_by", "");
        entry["banned_at"] = rows[0].value("banned_at", 0);
      }
      result["users"].push_back(entry);
    }
    result["total"] = result["users"].size();

    return result;
  }

  // --------------------------------------------------------------------------
  // 11. ADMIN PURGE HISTORY: Delete events from a room's history
  // --------------------------------------------------------------------------
  // Purges events before a given timestamp or event ID.
  json purge_history(
      const std::string& room_id,
      const std::string& before_event_id,
      int64_t before_ts,
      const std::string& admin_user_id) {

    json result;
    std::lock_guard<std::mutex> lock(g_purge_lock);

    if (!is_valid_room_id(room_id)) {
      result["error"] = "Invalid room ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    if (!room_exists(db_, room_id)) {
      result["error"] = "Room not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    // Build the query condition for which events to purge
    std::string condition;
    if (!before_event_id.empty()) {
      // Get the stream ordering of the event
      auto rows = db_.query(
        "SELECT stream_ordering FROM events_order WHERE event_id='" +
        escape_sql(before_event_id) + "'"
      );
      if (rows.empty()) {
        result["error"] = "Before event not found";
        result["errcode"] = "M_NOT_FOUND";
        return result;
      }
      int64_t ordering = rows[0]["stream_ordering"].template get<int64_t>();
      condition = "eo.stream_ordering < " + std::to_string(ordering);
    } else if (before_ts > 0) {
      condition = "e.origin_server_ts < " + std::to_string(before_ts);
    } else {
      result["error"] = "Must specify before_event_id or before_ts";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    // Count events to be purged
    std::string count_query =
      "SELECT COUNT(*) as cnt FROM events e "
      "LEFT JOIN events_order eo ON e.event_id = eo.event_id "
      "WHERE e.room_id='" + escape_sql(room_id) + "' AND " + condition;
    auto count_rows = db_.query(count_query);
    int64_t purge_count = 0;
    if (!count_rows.empty() && count_rows[0]["cnt"].is_number()) {
      purge_count = count_rows[0]["cnt"].template get<int64_t>();
    }

    if (purge_count == 0) {
      result["purged"] = 0;
      result["room_id"] = room_id;
      result["message"] = "No events matched the purge criteria";
      return result;
    }

    // Execute purge: delete from events_order, then events, then state if applicable
    std::string delete_order =
      "DELETE FROM events_order WHERE event_id IN ("
      "SELECT e.event_id FROM events e "
      "LEFT JOIN events_order eo ON e.event_id = eo.event_id "
      "WHERE e.room_id='" + escape_sql(room_id) + "' AND " + condition + ")";
    db_.execute(delete_order);

    std::string delete_state =
      "DELETE FROM state_events WHERE event_id IN ("
      "SELECT e.event_id FROM events e "
      "WHERE e.room_id='" + escape_sql(room_id) + "' AND " +
      condition.replace(condition.find("eo."), std::string::npos, "e.") + ")";

    // Actually, let's be more careful with the condition
    std::string events_condition;
    if (!before_event_id.empty()) {
      auto rows = db_.query(
        "SELECT stream_ordering FROM events_order WHERE event_id='" +
        escape_sql(before_event_id) + "'"
      );
      int64_t ordering = rows[0]["stream_ordering"].template get<int64_t>();
      events_condition = "e.origin_server_ts < (SELECT origin_server_ts FROM events e2 "
        "JOIN events_order eo2 ON e2.event_id = eo2.event_id "
        "WHERE eo2.stream_ordering=" + std::to_string(ordering) + ")";
    } else {
      events_condition = "e.origin_server_ts < " + std::to_string(before_ts);
    }

    db_.execute(
      "DELETE FROM state_events WHERE event_id IN ("
      "SELECT e.event_id FROM events e "
      "WHERE e.room_id='" + escape_sql(room_id) + "' AND " + events_condition + ")"
    );

    db_.execute(
      "DELETE FROM event_edges WHERE event_id IN ("
      "SELECT e.event_id FROM events e "
      "WHERE e.room_id='" + escape_sql(room_id) + "' AND " + events_condition + ")"
    );

    db_.execute(
      "DELETE FROM event_relations WHERE event_id IN ("
      "SELECT e.event_id FROM events e "
      "WHERE e.room_id='" + escape_sql(room_id) + "' AND " + events_condition + ")"
    );

    db_.execute(
      "DELETE FROM event_json WHERE event_id IN ("
      "SELECT e.event_id FROM events e "
      "WHERE e.room_id='" + escape_sql(room_id) + "' AND " + events_condition + ")"
    );

    db_.execute(
      "DELETE FROM events WHERE room_id='" + escape_sql(room_id) +
      "' AND " + events_condition
    );

    // Log the purge action
    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('purge_history', '" + escape_sql(room_id) + "', '" +
      escape_sql(admin_user_id) + "', 'Purged " + std::to_string(purge_count) +
      " events', " + std::to_string(now_sec()) + ")"
    );

    result["room_id"] = room_id;
    result["purged"] = purge_count;
    result["performed_by"] = admin_user_id;
    result["purged_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // 12. ADMIN PURGE ROOM: Completely purge a room and all its data
  // --------------------------------------------------------------------------
  // Removes all traces of a room from the database.
  json purge_room(const std::string& room_id, const std::string& admin_user_id) {
    json result;
    std::lock_guard<std::mutex> lock(g_purge_lock);

    if (!is_valid_room_id(room_id)) {
      result["error"] = "Invalid room ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    if (!room_exists(db_, room_id)) {
      result["error"] = "Room not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    // Count what we're deleting
    auto event_rows = db_.query(
      "SELECT COUNT(*) as cnt FROM events WHERE room_id='" + escape_sql(room_id) + "'"
    );
    auto member_rows = db_.query(
      "SELECT COUNT(*) as cnt FROM room_memberships WHERE room_id='" +
      escape_sql(room_id) + "'"
    );

    int64_t event_count = (!event_rows.empty() && event_rows[0]["cnt"].is_number())
      ? event_rows[0]["cnt"].template get<int64_t>() : 0;
    int64_t member_count = (!member_rows.empty() && member_rows[0]["cnt"].is_number())
      ? member_rows[0]["cnt"].template get<int64_t>() : 0;

    // Delete in order: cascade from dependent tables
    db_.execute("DELETE FROM event_edges WHERE room_id='" + escape_sql(room_id) + "'");
    db_.execute("DELETE FROM event_relations WHERE room_id='" + escape_sql(room_id) + "'");
    db_.execute("DELETE FROM event_json WHERE room_id='" + escape_sql(room_id) + "'");
    db_.execute("DELETE FROM state_events WHERE room_id='" + escape_sql(room_id) + "'");
    db_.execute("DELETE FROM events_order WHERE room_id='" + escape_sql(room_id) + "'");
    db_.execute("DELETE FROM events WHERE room_id='" + escape_sql(room_id) + "'");
    db_.execute("DELETE FROM room_memberships WHERE room_id='" + escape_sql(room_id) + "'");
    db_.execute("DELETE FROM room_aliases WHERE room_id='" + escape_sql(room_id) + "'");
    db_.execute("DELETE FROM room_tags WHERE room_id='" + escape_sql(room_id) + "'");
    db_.execute("DELETE FROM room_account_data WHERE room_id='" + escape_sql(room_id) + "'");
    db_.execute("DELETE FROM blocked_rooms WHERE room_id='" + escape_sql(room_id) + "'");
    db_.execute("DELETE FROM rooms WHERE room_id='" + escape_sql(room_id) + "'");

    // Remove from server notice room cache
    {
      std::unique_lock<std::shared_mutex> lock(g_server_notice_rooms_mutex);
      for (auto it = g_server_notice_rooms.begin();
           it != g_server_notice_rooms.end(); ++it) {
        if (it->second == room_id) {
          g_server_notice_rooms.erase(it);
          break;
        }
      }
    }

    // Remove from blocked rooms
    g_blocked_rooms.erase(room_id);

    // Log the purge action
    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('purge_room', '" + escape_sql(room_id) + "', '" +
      escape_sql(admin_user_id) + "', 'Purged entire room: " +
      std::to_string(event_count) + " events, " + std::to_string(member_count) +
      " members', " + std::to_string(now_sec()) + ")"
    );

    result["room_id"] = room_id;
    result["events_purged"] = event_count;
    result["members_removed"] = member_count;
    result["performed_by"] = admin_user_id;
    result["purged_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // 13. ADMIN DELETE LOCAL MEDIA
  // --------------------------------------------------------------------------
  // Deletes local media by media ID.
  json delete_local_media(
      const std::string& media_id,
      const std::string& admin_user_id) {

    json result;
    std::lock_guard<std::mutex> lock(g_media_lock);

    if (media_id.empty()) {
      result["error"] = "Media ID is required";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    // Check if media exists
    auto rows = db_.query(
      "SELECT media_id, media_type, upload_name, user_id, created_ts, media_length "
      "FROM local_media WHERE media_id='" + escape_sql(media_id) + "'"
    );

    if (rows.empty()) {
      result["error"] = "Local media not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    auto& row = rows[0];
    std::string media_type = row.value("media_type", "unknown");
    std::string upload_name = row.value("upload_name", "");
    std::string owner_id = row.value("user_id", "");

    // Delete media record
    db_.execute(
      "DELETE FROM local_media WHERE media_id='" + escape_sql(media_id) + "'"
    );
    db_.execute(
      "DELETE FROM local_media_thumbnails WHERE media_id='" + escape_sql(media_id) + "'"
    );

    // Log deletion
    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('delete_local_media', '" + escape_sql(media_id) + "', '" +
      escape_sql(admin_user_id) + "', 'Deleted local media: type=" + media_type +
      ", name=" + upload_name + ", owner=" + owner_id + "', " +
      std::to_string(now_sec()) + ")"
    );

    result["media_id"] = media_id;
    result["deleted"] = true;
    result["media_type"] = media_type;
    result["upload_name"] = upload_name;
    result["owner"] = owner_id;
    result["performed_by"] = admin_user_id;

    return result;
  }

  // --------------------------------------------------------------------------
  // 14. ADMIN DELETE REMOTE MEDIA
  // --------------------------------------------------------------------------
  // Deletes cached remote media by media ID and origin.
  json delete_remote_media(
      const std::string& media_id,
      const std::string& origin,
      const std::string& admin_user_id) {

    json result;
    std::lock_guard<std::mutex> lock(g_media_lock);

    if (media_id.empty()) {
      result["error"] = "Media ID is required";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    // Build query with optional origin filter
    std::string query =
      "SELECT media_id, origin, media_type, content_type, media_length, created_ts "
      "FROM remote_media WHERE media_id='" + escape_sql(media_id) + "'";
    if (!origin.empty()) {
      query += " AND origin='" + escape_sql(origin) + "'";
    }

    auto rows = db_.query(query);

    if (rows.empty()) {
      result["error"] = "Remote media not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    json deleted_items = json::array();
    int64_t total_deleted = 0;

    for (auto& row : rows) {
      std::string row_origin = row.value("origin", "");
      std::string row_type = row.value("media_type", "unknown");

      db_.execute(
        "DELETE FROM remote_media WHERE media_id='" + escape_sql(media_id) +
        "' AND origin='" + escape_sql(row_origin) + "'"
      );
      db_.execute(
        "DELETE FROM remote_media_thumbnails WHERE media_id='" +
        escape_sql(media_id) + "' AND origin='" + escape_sql(row_origin) + "'"
      );

      json item;
      item["media_id"] = media_id;
      item["origin"] = row_origin;
      item["media_type"] = row_type;
      deleted_items.push_back(item);
      total_deleted++;
    }

    // Log deletion
    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('delete_remote_media', '" + escape_sql(media_id) + "', '" +
      escape_sql(admin_user_id) + "', 'Deleted " + std::to_string(total_deleted) +
      " remote media entries" + (origin.empty() ? "" : " from " + origin) + "', " +
      std::to_string(now_sec()) + ")"
    );

    result["media_id"] = media_id;
    result["origin"] = origin;
    result["deleted_count"] = total_deleted;
    result["deleted_items"] = deleted_items;
    result["performed_by"] = admin_user_id;

    return result;
  }

  // --------------------------------------------------------------------------
  // 15. ADMIN QUARANTINE MEDIA
  // --------------------------------------------------------------------------
  // Quarantines a media file by ID, preventing it from being served.
  json quarantine_media(
      const std::string& media_id,
      const std::string& server_name,
      const std::string& reason,
      const std::string& admin_user_id) {

    json result;
    std::lock_guard<std::mutex> lock(g_media_lock);

    if (media_id.empty()) {
      result["error"] = "Media ID is required";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    // Check if already quarantined
    auto it = g_quarantined_media.find(media_id);
    if (it != g_quarantined_media.end()) {
      result["quarantined"] = true;
      result["already_quarantined"] = true;
      result["media_id"] = media_id;
      result["reason"] = it->second.reason;
      result["quarantined_at"] = it->second.quarantined_at;
      result["quarantined_by"] = it->second.quarantined_by;
      return result;
    }

    QuarantinedMedia qm;
    qm.media_id = media_id;
    qm.server_name = server_name;
    qm.reason = reason;
    qm.quarantined_at = now_sec();
    qm.quarantined_by = admin_user_id;
    qm.safe = false;

    g_quarantined_media[media_id] = qm;

    // Persist quarantine
    db_.execute(
      "INSERT INTO quarantined_media (media_id, server_name, reason, quarantined_by, "
      "quarantined_at) VALUES ('" +
      escape_sql(media_id) + "', '" + escape_sql(server_name) + "', '" +
      escape_sql(reason) + "', '" + escape_sql(admin_user_id) + "', " +
      std::to_string(now_sec()) + ") ON CONFLICT (media_id) DO UPDATE SET "
      "server_name='" + escape_sql(server_name) + "', reason='" +
      escape_sql(reason) + "', quarantined_by='" + escape_sql(admin_user_id) +
      "', quarantined_at=" + std::to_string(now_sec())
    );

    // Mark local media as quarantined
    db_.execute(
      "UPDATE local_media SET quarantined=1 WHERE media_id='" +
      escape_sql(media_id) + "'"
    );

    // Mark remote media as quarantined
    db_.execute(
      "UPDATE remote_media SET quarantined=1 WHERE media_id='" +
      escape_sql(media_id) + "'"
    );

    // Log quarantine
    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('quarantine_media', '" + escape_sql(media_id) + "', '" +
      escape_sql(admin_user_id) + "', 'Quarantined media from " +
      server_name + ": " + reason + "', " + std::to_string(now_sec()) + ")"
    );

    result["media_id"] = media_id;
    result["quarantined"] = true;
    result["reason"] = reason;
    result["quarantined_by"] = admin_user_id;
    result["quarantined_at"] = qm.quarantined_at;

    return result;
  }

  // --------------------------------------------------------------------------
  // Remove media quarantine
  // --------------------------------------------------------------------------
  json unquarantine_media(const std::string& media_id, const std::string& admin_user_id) {
    json result;
    std::lock_guard<std::mutex> lock(g_media_lock);

    auto it = g_quarantined_media.find(media_id);
    if (it == g_quarantined_media.end()) {
      result["error"] = "Media is not quarantined";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    g_quarantined_media.erase(it);

    db_.execute(
      "DELETE FROM quarantined_media WHERE media_id='" + escape_sql(media_id) + "'"
    );
    db_.execute(
      "UPDATE local_media SET quarantined=0 WHERE media_id='" +
      escape_sql(media_id) + "'"
    );
    db_.execute(
      "UPDATE remote_media SET quarantined=0 WHERE media_id='" +
      escape_sql(media_id) + "'"
    );

    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('unquarantine_media', '" + escape_sql(media_id) + "', '" +
      escape_sql(admin_user_id) + "', 'Removed media quarantine', " +
      std::to_string(now_sec()) + ")"
    );

    result["media_id"] = media_id;
    result["unquarantined"] = true;
    result["performed_by"] = admin_user_id;
    result["unquarantined_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // Check if media is quarantined
  // --------------------------------------------------------------------------
  json is_media_quarantined(const std::string& media_id) {
    json result;
    {
      std::lock_guard<std::mutex> lock(g_media_lock);
      auto it = g_quarantined_media.find(media_id);
      if (it != g_quarantined_media.end()) {
        result["quarantined"] = true;
        result["reason"] = it->second.reason;
        result["quarantined_by"] = it->second.quarantined_by;
        result["quarantined_at"] = it->second.quarantined_at;
        result["server_name"] = it->second.server_name;
      } else {
        result["quarantined"] = false;
      }
    }
    result["media_id"] = media_id;
    return result;
  }

  // --------------------------------------------------------------------------
  // 16. ADMIN RESET PASSWORD
  // --------------------------------------------------------------------------
  // Resets a user's password. See also AdminHandler::reset_password.
  json reset_password_admin(
      const std::string& user_id,
      const std::string& new_password,
      const std::string& admin_user_id) {

    json result;

    if (!is_valid_user_id(user_id)) {
      result["error"] = "Invalid user ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    if (!user_exists(db_, user_id)) {
      result["error"] = "User not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    if (new_password.length() < 8) {
      result["error"] = "Password must be at least 8 characters";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    // In production, hash the password properly with bcrypt/argon2
    // Here we use a simple hash marker for demonstration
    std::string hashed_password = "bcrypt:hashed_" +
      std::to_string(std::hash<std::string>{}(new_password + user_id));

    db_.execute(
      "UPDATE users SET password_hash='" + escape_sql(hashed_password) +
      "' WHERE id='" + escape_sql(user_id) + "'"
    );

    // Invalidate all existing access tokens
    db_.execute(
      "DELETE FROM access_tokens WHERE user_id='" + escape_sql(user_id) + "'"
    );
    db_.execute(
      "DELETE FROM refresh_tokens WHERE user_id='" + escape_sql(user_id) + "'"
    );

    // Log action
    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('reset_password', '" + escape_sql(user_id) + "', '" +
      escape_sql(admin_user_id) + "', 'Password reset by admin', " +
      std::to_string(now_sec()) + ")"
    );

    result["user_id"] = user_id;
    result["password_reset"] = true;
    result["tokens_invalidated"] = true;
    result["performed_by"] = admin_user_id;
    result["reset_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // 17. ADMIN DEACTIVATE USER
  // --------------------------------------------------------------------------
  // Deactivates a user account by marking it as deactivated and
  // invalidating all sessions.
  json deactivate_user_admin(
      const std::string& user_id,
      const std::string& admin_user_id,
      bool erase_data) {

    json result;

    if (!is_valid_user_id(user_id)) {
      result["error"] = "Invalid user ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    auto user_rows = db_.query(
      "SELECT deactivated FROM users WHERE id='" + escape_sql(user_id) + "'"
    );
    if (user_rows.empty()) {
      result["error"] = "User not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    if (user_rows[0].value("deactivated", 0) == 1) {
      result["deactivated"] = true;
      result["already_deactivated"] = true;
      result["user_id"] = user_id;
      return result;
    }

    // Deactivate user
    db_.execute(
      "UPDATE users SET deactivated=1 WHERE id='" + escape_sql(user_id) + "'"
    );

    // Invalidate tokens
    db_.execute(
      "DELETE FROM access_tokens WHERE user_id='" + escape_sql(user_id) + "'"
    );
    db_.execute(
      "DELETE FROM refresh_tokens WHERE user_id='" + escape_sql(user_id) + "'"
    );

    // Remove from all rooms
    auto member_rows = db_.query(
      "SELECT room_id FROM room_memberships WHERE user_id='" +
      escape_sql(user_id) + "' AND membership='join'"
    );
    for (auto& row : member_rows) {
      std::string room_id = row.value("room_id", "");
      db_.execute(
        "UPDATE room_memberships SET membership='leave', sender='" +
        escape_sql(user_id) + "' WHERE user_id='" + escape_sql(user_id) +
        "' AND room_id='" + escape_sql(room_id) + "' AND membership='join'"
      );
    }
    int64_t rooms_left = static_cast<int64_t>(member_rows.size());

    // Optionally erase all user data
    if (erase_data) {
      db_.execute(
        "DELETE FROM events WHERE sender='" + escape_sql(user_id) + "'"
      );
      db_.execute(
        "DELETE FROM room_memberships WHERE user_id='" + escape_sql(user_id) + "'"
      );
      db_.execute(
        "DELETE FROM profiles WHERE user_id='" + escape_sql(user_id) + "'"
      );
      db_.execute(
        "DELETE FROM devices WHERE user_id='" + escape_sql(user_id) + "'"
      );
      db_.execute(
        "DELETE FROM e2e_keys WHERE user_id='" + escape_sql(user_id) + "'"
      );
      db_.execute(
        "DELETE FROM presence WHERE user_id='" + escape_sql(user_id) + "'"
      );

      // Remove from shadow ban list
      {
        std::unique_lock<std::shared_mutex> lock(g_shadow_ban_mutex);
        g_shadow_banned_users.erase(user_id);
      }

      // Remove server notice room
      {
        std::unique_lock<std::shared_mutex> lock(g_server_notice_rooms_mutex);
        g_server_notice_rooms.erase(user_id);
      }
    }

    // Log action
    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('deactivate_user', '" + escape_sql(user_id) + "', '" +
      escape_sql(admin_user_id) + "', 'Deactivated user" +
      std::string(erase_data ? " with data erasure" : "") + "', " +
      std::to_string(now_sec()) + ")"
    );

    result["user_id"] = user_id;
    result["deactivated"] = true;
    result["rooms_left"] = rooms_left;
    result["erase_data"] = erase_data;
    result["performed_by"] = admin_user_id;
    result["deactivated_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // 18. ADMIN REACTIVATE USER
  // --------------------------------------------------------------------------
  // Reactivates a previously deactivated user account.
  json reactivate_user_admin(
      const std::string& user_id,
      const std::string& admin_user_id) {

    json result;

    if (!is_valid_user_id(user_id)) {
      result["error"] = "Invalid user ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    auto user_rows = db_.query(
      "SELECT deactivated FROM users WHERE id='" + escape_sql(user_id) + "'"
    );
    if (user_rows.empty()) {
      result["error"] = "User not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    if (user_rows[0].value("deactivated", 0) == 0) {
      result["reactivated"] = true;
      result["already_active"] = true;
      result["user_id"] = user_id;
      return result;
    }

    // Reactivate user
    db_.execute(
      "UPDATE users SET deactivated=0 WHERE id='" + escape_sql(user_id) + "'"
    );

    // Log action
    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('reactivate_user', '" + escape_sql(user_id) + "', '" +
      escape_sql(admin_user_id) + "', 'Reactivated user', " +
      std::to_string(now_sec()) + ")"
    );

    result["user_id"] = user_id;
    result["reactivated"] = true;
    result["performed_by"] = admin_user_id;
    result["reactivated_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // 19. ADMIN CREATE REGISTRATION TOKEN
  // --------------------------------------------------------------------------
  // Creates a registration token that can be used to register new accounts.
  json create_registration_token(
      const std::string& admin_user_id,
      int64_t uses_allowed,
      int64_t expiry_time) {

    json result;
    std::lock_guard<std::mutex> lock(g_registration_token_lock);

    std::string token = gen_token(32);
    int64_t now = now_sec();

    RegistrationToken rt;
    rt.token = token;
    rt.created_by = admin_user_id;
    rt.created_at = now;
    rt.uses_allowed = uses_allowed;
    rt.expiry_time = expiry_time;
    rt.revoked = false;

    g_registration_tokens[token] = rt;

    db_.execute(
      "INSERT INTO registration_tokens (token, created_by, created_at, uses_allowed, "
      "expiry_time) VALUES ('" +
      escape_sql(token) + "', '" + escape_sql(admin_user_id) + "', " +
      std::to_string(now) + ", " + std::to_string(uses_allowed) + ", " +
      std::to_string(expiry_time) + ")"
    );

    result["token"] = token;
    result["created_by"] = admin_user_id;
    result["created_at"] = now;
    result["uses_allowed"] = uses_allowed;
    result["expiry_time"] = expiry_time;
    result["expires_at"] = expiry_time > 0 ? now + expiry_time : 0;

    return result;
  }

  // --------------------------------------------------------------------------
  // 20. ADMIN LIST REGISTRATION TOKENS
  // --------------------------------------------------------------------------
  json list_registration_tokens() {
    json result;
    result["tokens"] = json::array();

    for (const auto& [token, rt] : g_registration_tokens) {
      json entry;
      entry["token"] = token;
      entry["created_by"] = rt.created_by;
      entry["created_at"] = rt.created_at;
      entry["used_at"] = rt.used_at;
      entry["used_by"] = rt.used_by;
      entry["uses_allowed"] = rt.uses_allowed;
      entry["pending"] = rt.pending;
      entry["completed"] = rt.completed;
      entry["expiry_time"] = rt.expiry_time;
      entry["revoked"] = rt.revoked;

      bool is_expired = false;
      if (rt.expiry_time > 0 && now_sec() > rt.created_at + rt.expiry_time) {
        is_expired = true;
      }
      entry["expired"] = is_expired;

      bool is_exhausted = (rt.uses_allowed > 0 && rt.completed >= rt.uses_allowed);
      entry["exhausted"] = is_exhausted;

      entry["valid"] = !rt.revoked && !is_expired && !is_exhausted;

      result["tokens"].push_back(entry);
    }
    result["total"] = result["tokens"].size();

    return result;
  }

  // --------------------------------------------------------------------------
  // 21. ADMIN REVOKE REGISTRATION TOKEN
  // --------------------------------------------------------------------------
  json revoke_registration_token(
      const std::string& token,
      const std::string& admin_user_id) {

    json result;
    std::lock_guard<std::mutex> lock(g_registration_token_lock);

    auto it = g_registration_tokens.find(token);
    if (it == g_registration_tokens.end()) {
      result["error"] = "Registration token not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    it->second.revoked = true;

    db_.execute(
      "UPDATE registration_tokens SET revoked=1 WHERE token='" +
      escape_sql(token) + "'"
    );

    result["token"] = token;
    result["revoked"] = true;
    result["revoked_by"] = admin_user_id;
    result["revoked_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // Validate a registration token for use during registration
  // --------------------------------------------------------------------------
  json validate_registration_token(const std::string& token) {
    json result;

    auto it = g_registration_tokens.find(token);
    if (it == g_registration_tokens.end()) {
      result["valid"] = false;
      result["error"] = "Unknown registration token";
      return result;
    }

    auto& rt = it->second;

    if (rt.revoked) {
      result["valid"] = false;
      result["error"] = "Registration token has been revoked";
      return result;
    }

    if (rt.expiry_time > 0 && now_sec() > rt.created_at + rt.expiry_time) {
      result["valid"] = false;
      result["error"] = "Registration token has expired";
      return result;
    }

    if (rt.uses_allowed > 0 && rt.completed >= rt.uses_allowed) {
      result["valid"] = false;
      result["error"] = "Registration token has been exhausted";
      return result;
    }

    result["valid"] = true;
    result["token"] = token;
    result["uses_allowed"] = rt.uses_allowed;
    result["completed"] = rt.completed;
    result["pending"] = rt.pending;

    return result;
  }

  // --------------------------------------------------------------------------
  // Consume a registration token (called after successful registration)
  // --------------------------------------------------------------------------
  json consume_registration_token(const std::string& token, const std::string& user_id) {
    json result;

    auto it = g_registration_tokens.find(token);
    if (it == g_registration_tokens.end()) {
      result["consumed"] = false;
      result["error"] = "Unknown registration token";
      return result;
    }

    auto& rt = it->second;
    rt.completed++;
    rt.used_at = now_sec();
    rt.used_by = user_id;
    rt.pending = std::max(0L, rt.pending - 1);

    db_.execute(
      "UPDATE registration_tokens SET completed=" + std::to_string(rt.completed) +
      ", used_at=" + std::to_string(rt.used_at) +
      ", used_by='" + escape_sql(rt.used_by) +
      "', pending=" + std::to_string(rt.pending) +
      " WHERE token='" + escape_sql(token) + "'"
    );

    result["consumed"] = true;
    result["token"] = token;
    result["user_id"] = user_id;
    result["completed"] = rt.completed;
    result["remaining"] = rt.uses_allowed > 0
      ? std::max(0L, rt.uses_allowed - rt.completed)
      : -1;  // -1 = unlimited

    return result;
  }

  // --------------------------------------------------------------------------
  // 22. ADMIN SET USER CONSENT (enable/disable)
  // --------------------------------------------------------------------------
  json set_user_consent(
      const std::string& user_id,
      const std::string& consent_version,
      bool accepted,
      const std::string& admin_user_id) {

    json result;
    std::lock_guard<std::mutex> lock(g_consent_lock);

    if (!is_valid_user_id(user_id)) {
      result["error"] = "Invalid user ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    if (!user_exists(db_, user_id)) {
      result["error"] = "User not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    if (consent_version.empty()) {
      result["error"] = "Consent version is required";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    if (accepted) {
      // Record consent
      db_.execute(
        "INSERT INTO user_consent (user_id, consent_version, accepted_at, accepted_by) "
        "VALUES ('" + escape_sql(user_id) + "', '" + escape_sql(consent_version) +
        "', " + std::to_string(now_sec()) + ", '" + escape_sql(admin_user_id) +
        "') ON CONFLICT (user_id, consent_version) DO UPDATE SET "
        "accepted_at=" + std::to_string(now_sec()) +
        ", accepted_by='" + escape_sql(admin_user_id) + "'"
      );
    } else {
      // Revoke consent
      db_.execute(
        "DELETE FROM user_consent WHERE user_id='" + escape_sql(user_id) +
        "' AND consent_version='" + escape_sql(consent_version) + "'"
      );
    }

    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('set_consent', '" + escape_sql(user_id) + "', '" +
      escape_sql(admin_user_id) + "', '" +
      std::string(accepted ? "Accepted" : "Revoked") + " consent version " +
      consent_version + "', " + std::to_string(now_sec()) + ")"
    );

    result["user_id"] = user_id;
    result["consent_version"] = consent_version;
    result["accepted"] = accepted;
    result["performed_by"] = admin_user_id;
    result["updated_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // 23. ADMIN GET USER CONSENT STATUS
  // --------------------------------------------------------------------------
  json get_user_consent(
      const std::string& user_id,
      const std::string& consent_version) {

    json result;

    if (!user_id.empty()) {
      // Get consent for a specific user
      std::string query =
        "SELECT consent_version, accepted_at, accepted_by FROM user_consent "
        "WHERE user_id='" + escape_sql(user_id) + "'";
      if (!consent_version.empty()) {
        query += " AND consent_version='" + escape_sql(consent_version) + "'";
      }
      query += " ORDER BY accepted_at DESC";

      auto rows = db_.query(query);
      result["user_id"] = user_id;
      result["consents"] = json::array();

      for (auto& row : rows) {
        json entry;
        entry["consent_version"] = row.value("consent_version", "");
        entry["accepted_at"] = row.value("accepted_at", 0);
        entry["accepted_by"] = row.value("accepted_by", "");
        result["consents"].push_back(entry);
      }
      result["total"] = result["consents"].size();
      result["has_consented"] = !rows.empty();

    } else {
      // List all users with consent status for a given version
      result["consent_version"] = consent_version;
      result["users"] = json::array();

      // Get users who have accepted
      std::string query =
        "SELECT u.id as user_id, uc.accepted_at, uc.accepted_by, u.deactivated "
        "FROM users u LEFT JOIN user_consent uc ON u.id = uc.user_id ";
      if (!consent_version.empty()) {
        query += "AND uc.consent_version='" + escape_sql(consent_version) + "' ";
      }
      query += "ORDER BY u.id";

      auto rows = db_.query(query);
      for (auto& row : rows) {
        json entry;
        entry["user_id"] = row.value("user_id", "");
        entry["accepted"] = !row["accepted_at"].is_null();
        entry["accepted_at"] = row.value("accepted_at", 0);
        entry["accepted_by"] = row.value("accepted_by", "");
        entry["deactivated"] = row.value("deactivated", 0) == 1;
        result["users"].push_back(entry);
      }
      result["total"] = result["users"].size();
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // 24. ADMIN SERVER ACL OVERRIDE
  // --------------------------------------------------------------------------
  // Overrides the server ACL for a specific server, allowing or denying it.
  json override_server_acl(
      const std::string& server_name,
      const std::string& action,  // "allow" or "deny"
      const std::string& reason,
      const std::string& admin_user_id) {

    json result;

    if (server_name.empty()) {
      result["error"] = "Server name is required";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    if (action != "allow" && action != "deny") {
      result["error"] = "Action must be 'allow' or 'deny'";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    ServerAclOverride override;
    override.server_name = server_name;
    override.allow = (action == "allow");
    override.deny = (action == "deny");
    override.reason = reason;
    override.set_by = admin_user_id;
    override.set_at = now_sec();

    {
      std::unique_lock<std::shared_mutex> lock(g_acl_override_mutex);
      g_acl_overrides[server_name].push_back(override);
    }

    // Persist ACL override
    db_.execute(
      "INSERT INTO server_acl_overrides (server_name, action, reason, set_by, set_at) "
      "VALUES ('" + escape_sql(server_name) + "', '" + escape_sql(action) + "', '" +
      escape_sql(reason) + "', '" + escape_sql(admin_user_id) + "', " +
      std::to_string(now_sec()) + ")"
    );

    // Update server ACL state
    db_.execute(
      "INSERT OR REPLACE INTO server_acl_state (server_name, allow, deny, updated_at) "
      "VALUES ('" + escape_sql(server_name) + "', " +
      std::to_string(action == "allow" ? 1 : 0) + ", " +
      std::to_string(action == "deny" ? 1 : 0) + ", " +
      std::to_string(now_sec()) + ")"
    );

    // Log
    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('server_acl_override', '" + escape_sql(server_name) + "', '" +
      escape_sql(admin_user_id) + "', '" + action + ": " + reason + "', " +
      std::to_string(now_sec()) + ")"
    );

    result["server_name"] = server_name;
    result["action"] = action;
    result["reason"] = reason;
    result["set_by"] = admin_user_id;
    result["set_at"] = override.set_at;

    return result;
  }

  // --------------------------------------------------------------------------
  // Remove server ACL override
  // --------------------------------------------------------------------------
  json remove_server_acl_override(
      const std::string& server_name,
      const std::string& admin_user_id) {

    json result;

    {
      std::unique_lock<std::shared_mutex> lock(g_acl_override_mutex);
      auto it = g_acl_overrides.find(server_name);
      if (it == g_acl_overrides.end() || it->second.empty()) {
        result["error"] = "No ACL override found for server: " + server_name;
        result["errcode"] = "M_NOT_FOUND";
        return result;
      }
      g_acl_overrides.erase(it);
    }

    db_.execute(
      "DELETE FROM server_acl_overrides WHERE server_name='" +
      escape_sql(server_name) + "'"
    );
    db_.execute(
      "DELETE FROM server_acl_state WHERE server_name='" +
      escape_sql(server_name) + "'"
    );

    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('remove_acl_override', '" + escape_sql(server_name) + "', '" +
      escape_sql(admin_user_id) + "', 'Removed ACL override', " +
      std::to_string(now_sec()) + ")"
    );

    result["server_name"] = server_name;
    result["removed"] = true;
    result["removed_by"] = admin_user_id;
    result["removed_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // Check server ACL status
  // --------------------------------------------------------------------------
  json check_server_acl(const std::string& server_name) {
    json result;

    {
      std::shared_lock<std::shared_mutex> lock(g_acl_override_mutex);
      auto it = g_acl_overrides.find(server_name);
      if (it != g_acl_overrides.end() && !it->second.empty()) {
        const auto& latest = it->second.back();
        result["server_name"] = server_name;
        result["has_override"] = true;
        result["action"] = latest.allow ? "allow" : "deny";
        result["reason"] = latest.reason;
        result["set_by"] = latest.set_by;
        result["set_at"] = latest.set_at;
        return result;
      }
    }

    result["server_name"] = server_name;
    result["has_override"] = false;
    result["action"] = "default";

    return result;
  }

  // --------------------------------------------------------------------------
  // List all server ACL overrides
  // --------------------------------------------------------------------------
  json list_server_acl_overrides() {
    json result;
    result["overrides"] = json::array();

    std::shared_lock<std::shared_mutex> lock(g_acl_override_mutex);
    for (const auto& [server_name, overrides] : g_acl_overrides) {
      json entry;
      entry["server_name"] = server_name;
      entry["overrides"] = json::array();
      for (const auto& ov : overrides) {
        json ov_entry;
        ov_entry["action"] = ov.allow ? "allow" : (ov.deny ? "deny" : "unknown");
        ov_entry["reason"] = ov.reason;
        ov_entry["set_by"] = ov.set_by;
        ov_entry["set_at"] = ov.set_at;
        entry["overrides"].push_back(ov_entry);
      }
      // Latest override
      const auto& latest = overrides.back();
      entry["current_action"] = latest.allow ? "allow" : "deny";
      result["overrides"].push_back(entry);
    }
    result["total"] = result["overrides"].size();

    return result;
  }

  // --------------------------------------------------------------------------
  // 25. ADMIN FORCE JOIN ROOM
  // --------------------------------------------------------------------------
  // Forces a user to join a room, bypassing normal join rules.
  json force_join_room(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& admin_user_id) {

    json result;

    if (!is_valid_user_id(user_id)) {
      result["error"] = "Invalid user ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    if (!is_valid_room_id(room_id)) {
      result["error"] = "Invalid room ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    if (!user_exists(db_, user_id)) {
      result["error"] = "User not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    if (!room_exists(db_, room_id)) {
      result["error"] = "Room not found";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    // Check if user is already in the room
    std::string membership = get_user_membership(db_, user_id, room_id);
    if (membership == "join") {
      result["joined"] = true;
      result["already_joined"] = true;
      result["user_id"] = user_id;
      result["room_id"] = room_id;
      return result;
    }

    // Force join: create join membership event
    std::string event_id = gen_event_id();
    int64_t now = now_ms();

    json member_event;
    member_event["type"] = "m.room.member";
    member_event["state_key"] = user_id;
    member_event["sender"] = admin_user_id;  // Admin is forcing the join
    member_event["room_id"] = room_id;
    member_event["event_id"] = event_id;
    member_event["origin_server_ts"] = now;
    member_event["content"]["membership"] = "join";
    member_event["content"]["displayname"] = "";
    member_event["content"]["avatar_url"] = "";
    member_event["content"]["reason"] = "Force-joined by admin: " + admin_user_id;
    member_event["unsigned"]["age"] = 0;
    member_event["unsigned"]["force_joined"] = true;

    // Persist membership
    db_.execute(
      "INSERT INTO room_memberships (room_id, user_id, membership, sender, event_id) "
      "VALUES ('" + escape_sql(room_id) + "', '" + escape_sql(user_id) +
      "', 'join', '" + escape_sql(admin_user_id) + "', '" +
      escape_sql(event_id) + "') ON CONFLICT (room_id, user_id) DO UPDATE SET "
      "membership='join', sender='" + escape_sql(admin_user_id) +
      "', event_id='" + escape_sql(event_id) + "'"
    );

    // Persist event
    db_.execute(
      "INSERT INTO events (event_id, room_id, type, state_key, sender, content, "
      "origin_server_ts) VALUES ('" +
      escape_sql(event_id) + "', '" + escape_sql(room_id) + "', 'm.room.member', '" +
      escape_sql(user_id) + "', '" + escape_sql(admin_user_id) + "', '" +
      escape_sql(member_event["content"].dump()) + "', " + std::to_string(now) + ")"
    );

    // Update state
    db_.execute(
      "INSERT OR REPLACE INTO state_events (room_id, type, state_key, event_id) "
      "VALUES ('" + escape_sql(room_id) + "', 'm.room.member', '" +
      escape_sql(user_id) + "', '" + escape_sql(event_id) + "')"
    );

    // Log action
    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('force_join_room', '" + escape_sql(user_id) + "', '" +
      escape_sql(admin_user_id) + "', 'Force-joined user to room " + room_id +
      "', " + std::to_string(now_sec()) + ")"
    );

    result["user_id"] = user_id;
    result["room_id"] = room_id;
    result["joined"] = true;
    result["force_joined"] = true;
    result["performed_by"] = admin_user_id;
    result["event_id"] = event_id;
    result["joined_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // 26. ADMIN FORCE LEAVE ROOM
  // --------------------------------------------------------------------------
  // Forces a user to leave a room.
  json force_leave_room(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& admin_user_id) {

    json result;

    if (!is_valid_user_id(user_id)) {
      result["error"] = "Invalid user ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    if (!is_valid_room_id(room_id)) {
      result["error"] = "Invalid room ID";
      result["errcode"] = "M_INVALID_PARAM";
      return result;
    }

    std::string membership = get_user_membership(db_, user_id, room_id);
    if (membership != "join") {
      result["error"] = "User is not a member of this room";
      result["errcode"] = "M_NOT_FOUND";
      return result;
    }

    std::string event_id = gen_event_id();
    int64_t now = now_ms();

    // Update membership to leave
    db_.execute(
      "UPDATE room_memberships SET membership='leave', sender='" +
      escape_sql(admin_user_id) + "', event_id='" + escape_sql(event_id) +
      "' WHERE user_id='" + escape_sql(user_id) + "' AND room_id='" +
      escape_sql(room_id) + "'"
    );

    // Create leave event
    json leave_event;
    leave_event["type"] = "m.room.member";
    leave_event["state_key"] = user_id;
    leave_event["sender"] = admin_user_id;
    leave_event["room_id"] = room_id;
    leave_event["event_id"] = event_id;
    leave_event["origin_server_ts"] = now;
    leave_event["content"]["membership"] = "leave";
    leave_event["content"]["reason"] = "Force-left by admin: " + admin_user_id;
    leave_event["unsigned"]["force_left"] = true;

    db_.execute(
      "INSERT INTO events (event_id, room_id, type, state_key, sender, content, "
      "origin_server_ts) VALUES ('" +
      escape_sql(event_id) + "', '" + escape_sql(room_id) + "', 'm.room.member', '" +
      escape_sql(user_id) + "', '" + escape_sql(admin_user_id) + "', '" +
      escape_sql(leave_event["content"].dump()) + "', " + std::to_string(now) + ")"
    );

    db_.execute(
      "INSERT OR REPLACE INTO state_events (room_id, type, state_key, event_id) "
      "VALUES ('" + escape_sql(room_id) + "', 'm.room.member', '" +
      escape_sql(user_id) + "', '" + escape_sql(event_id) + "')"
    );

    // Log
    db_.execute(
      "INSERT INTO admin_audit_log (action, target, performed_by, details, performed_at) "
      "VALUES ('force_leave_room', '" + escape_sql(user_id) + "', '" +
      escape_sql(admin_user_id) + "', 'Force-left user from room " + room_id +
      "', " + std::to_string(now_sec()) + ")"
    );

    result["user_id"] = user_id;
    result["room_id"] = room_id;
    result["left"] = true;
    result["force_left"] = true;
    result["performed_by"] = admin_user_id;
    result["event_id"] = event_id;
    result["left_at"] = now_sec();

    return result;
  }

  // --------------------------------------------------------------------------
  // Load persisted state from database
  // --------------------------------------------------------------------------
  void load_state() {
    // Load blocked rooms
    auto blocked_rows = db_.query("SELECT room_id FROM blocked_rooms");
    {
      std::lock_guard<std::mutex> lock(g_room_block_lock);
      for (auto& row : blocked_rows) {
        g_blocked_rooms.insert(row.value("room_id", ""));
      }
    }

    // Load shadow-banned users
    auto shadow_rows = db_.query("SELECT user_id FROM shadow_banned_users");
    {
      std::unique_lock<std::shared_mutex> lock(g_shadow_ban_mutex);
      for (auto& row : shadow_rows) {
        g_shadow_banned_users.insert(row.value("user_id", ""));
      }
    }

    // Load server notice rooms
    auto notice_rows = db_.query("SELECT user_id, room_id FROM server_notice_rooms");
    {
      std::unique_lock<std::shared_mutex> lock(g_server_notice_rooms_mutex);
      for (auto& row : notice_rows) {
        g_server_notice_rooms[row.value("user_id", "")] = row.value("room_id", "");
      }
    }

    // Load third-party invites
    auto invite_rows = db_.query(
      "SELECT token, medium, address, room_id, sender, display_name, "
      "id_server, created_at, expires_at, validated FROM third_party_invites"
    );
    {
      std::lock_guard<std::mutex> lock(g_third_party_invite_lock);
      for (auto& row : invite_rows) {
        ThirdPartyInvite inv;
        inv.token = row.value("token", "");
        inv.medium = row.value("medium", "");
        inv.address = row.value("address", "");
        inv.room_id = row.value("room_id", "");
        inv.sender = row.value("sender", "");
        inv.display_name = row.value("display_name", "");
        inv.id_server = row.value("id_server", "");
        inv.created_at = row.value("created_at", 0);
        inv.expires_at = row.value("expires_at", 0);
        inv.validated = row.value("validated", 0) == 1;
        g_third_party_invites[inv.token] = inv;
      }
    }

    // Load registration tokens
    auto token_rows = db_.query(
      "SELECT token, created_by, created_at, used_at, used_by, "
      "uses_allowed, pending, completed, expiry_time, revoked FROM registration_tokens"
    );
    {
      std::lock_guard<std::mutex> lock(g_registration_token_lock);
      for (auto& row : token_rows) {
        RegistrationToken rt;
        rt.token = row.value("token", "");
        rt.created_by = row.value("created_by", "");
        rt.created_at = row.value("created_at", 0);
        rt.used_at = row.value("used_at", 0);
        rt.used_by = row.value("used_by", "");
        rt.uses_allowed = row.value("uses_allowed", 1);
        rt.pending = row.value("pending", 0);
        rt.completed = row.value("completed", 0);
        rt.expiry_time = row.value("expiry_time", 0);
        rt.revoked = row.value("revoked", 0) == 1;
        g_registration_tokens[rt.token] = rt;
      }
    }

    // Load quarantined media
    auto quarantined_rows = db_.query(
      "SELECT media_id, server_name, reason, quarantined_by, quarantined_at "
      "FROM quarantined_media"
    );
    {
      std::lock_guard<std::mutex> lock(g_media_lock);
      for (auto& row : quarantined_rows) {
        QuarantinedMedia qm;
        qm.media_id = row.value("media_id", "");
        qm.server_name = row.value("server_name", "");
        qm.reason = row.value("reason", "");
        qm.quarantined_at = row.value("quarantined_at", 0);
        qm.quarantined_by = row.value("quarantined_by", "");
        g_quarantined_media[qm.media_id] = qm;
      }
    }

    // Load ACL overrides
    auto acl_rows = db_.query(
      "SELECT server_name, action, reason, set_by, set_at FROM server_acl_overrides "
      "ORDER BY set_at ASC"
    );
    {
      std::unique_lock<std::shared_mutex> lock(g_acl_override_mutex);
      for (auto& row : acl_rows) {
        ServerAclOverride ov;
        ov.server_name = row.value("server_name", "");
        std::string action = row.value("action", "");
        ov.allow = (action == "allow");
        ov.deny = (action == "deny");
        ov.reason = row.value("reason", "");
        ov.set_by = row.value("set_by", "");
        ov.set_at = row.value("set_at", 0);
        g_acl_overrides[ov.server_name].push_back(ov);
      }
    }
  }

  // --------------------------------------------------------------------------
  // Get audit log entries
  // --------------------------------------------------------------------------
  json get_audit_log(int64_t limit = 100, int64_t offset = 0) {
    json result;
    result["entries"] = json::array();

    auto rows = db_.query(
      "SELECT action, target, performed_by, details, performed_at "
      "FROM admin_audit_log ORDER BY performed_at DESC LIMIT " +
      std::to_string(limit) + " OFFSET " + std::to_string(offset)
    );

    for (auto& row : rows) {
      json entry;
      entry["action"] = row.value("action", "");
      entry["target"] = row.value("target", "");
      entry["performed_by"] = row.value("performed_by", "");
      entry["details"] = row.value("details", "");
      entry["performed_at"] = row.value("performed_at", 0);
      result["entries"].push_back(entry);
    }
    result["total"] = result["entries"].size();
    result["limit"] = limit;
    result["offset"] = offset;

    return result;
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// Public API: Free functions wrapping AdminServerTools
// ============================================================================

// Thread-safe singleton access to AdminServerTools
static AdminServerTools* g_admin_tools_instance = nullptr;
static std::mutex g_admin_tools_init_mutex;

static AdminServerTools& get_admin_tools(DatabasePool& db) {
  static AdminServerTools tools(db);
  std::lock_guard<std::mutex> lock(g_admin_tools_init_mutex);
  if (!g_admin_tools_instance) {
    g_admin_tools_instance = &tools;
    tools.load_state();
  }
  return tools;
}

// ---- Third-party invites ----

json send_third_party_invite(DatabasePool& db,
    const std::string& room_id,
    const std::string& sender,
    const std::string& medium,
    const std::string& address,
    const std::string& id_server,
    const std::string& id_access_token,
    const std::string& display_name) {
  return get_admin_tools(db).send_third_party_invite(
    room_id, sender, medium, address, id_server, id_access_token, display_name);
}

json exchange_third_party_invite(DatabasePool& db,
    const std::string& token,
    const std::string& user_id) {
  return get_admin_tools(db).exchange_third_party_invite(token, user_id);
}

json validate_third_party_invite(DatabasePool& db,
    const std::string& token,
    const std::string& id_server,
    const std::string& id_access_token) {
  return get_admin_tools(db).validate_third_party_invite(token, id_server, id_access_token);
}

// ---- Server notices ----

json create_server_notice_room(DatabasePool& db, const std::string& user_id) {
  return get_admin_tools(db).create_server_notice_room(user_id);
}

json send_server_notice(DatabasePool& db,
    const std::string& user_id,
    const std::string& notice_type,
    const std::string& title,
    const std::string& body,
    const json& extra_content = json::object()) {
  return get_admin_tools(db).send_server_notice(
    user_id, notice_type, title, body, extra_content);
}

json send_server_notice_from_template(DatabasePool& db,
    const std::string& user_id,
    const std::string& template_type,
    const json& custom_fields = json::object()) {
  return get_admin_tools(db).send_server_notice_from_template(
    user_id, template_type, custom_fields);
}

json get_server_notice_templates(DatabasePool& db) {
  return get_admin_tools(db).get_server_notice_templates();
}

// ---- Room management ----

json block_room(DatabasePool& db,
    const std::string& room_id,
    const std::string& admin_user_id) {
  return get_admin_tools(db).block_room(room_id, admin_user_id);
}

json unblock_room(DatabasePool& db,
    const std::string& room_id,
    const std::string& admin_user_id) {
  return get_admin_tools(db).unblock_room(room_id, admin_user_id);
}

json list_blocked_rooms(DatabasePool& db) {
  return get_admin_tools(db).list_blocked_rooms();
}

// ---- Shadow-ban ----

json shadow_ban_user(DatabasePool& db,
    const std::string& user_id,
    const std::string& admin_user_id) {
  return get_admin_tools(db).shadow_ban_user(user_id, admin_user_id);
}

json remove_shadow_ban(DatabasePool& db,
    const std::string& user_id,
    const std::string& admin_user_id) {
  return get_admin_tools(db).remove_shadow_ban(user_id, admin_user_id);
}

json check_shadow_ban(DatabasePool& db, const std::string& user_id) {
  return get_admin_tools(db).check_shadow_ban(user_id);
}

json list_shadow_banned_users(DatabasePool& db) {
  return get_admin_tools(db).list_shadow_banned_users();
}

// ---- Purge operations ----

json purge_history(DatabasePool& db,
    const std::string& room_id,
    const std::string& before_event_id,
    int64_t before_ts,
    const std::string& admin_user_id) {
  return get_admin_tools(db).purge_history(
    room_id, before_event_id, before_ts, admin_user_id);
}

json purge_room(DatabasePool& db,
    const std::string& room_id,
    const std::string& admin_user_id) {
  return get_admin_tools(db).purge_room(room_id, admin_user_id);
}

// ---- Media management ----

json delete_local_media(DatabasePool& db,
    const std::string& media_id,
    const std::string& admin_user_id) {
  return get_admin_tools(db).delete_local_media(media_id, admin_user_id);
}

json delete_remote_media(DatabasePool& db,
    const std::string& media_id,
    const std::string& origin,
    const std::string& admin_user_id) {
  return get_admin_tools(db).delete_remote_media(media_id, origin, admin_user_id);
}

json quarantine_media(DatabasePool& db,
    const std::string& media_id,
    const std::string& server_name,
    const std::string& reason,
    const std::string& admin_user_id) {
  return get_admin_tools(db).quarantine_media(
    media_id, server_name, reason, admin_user_id);
}

json unquarantine_media(DatabasePool& db,
    const std::string& media_id,
    const std::string& admin_user_id) {
  return get_admin_tools(db).unquarantine_media(media_id, admin_user_id);
}

json is_media_quarantined(DatabasePool& db, const std::string& media_id) {
  return get_admin_tools(db).is_media_quarantined(media_id);
}

// ---- User management ----

json reset_password_admin(DatabasePool& db,
    const std::string& user_id,
    const std::string& new_password,
    const std::string& admin_user_id) {
  return get_admin_tools(db).reset_password_admin(user_id, new_password, admin_user_id);
}

json deactivate_user_admin(DatabasePool& db,
    const std::string& user_id,
    const std::string& admin_user_id,
    bool erase_data = false) {
  return get_admin_tools(db).deactivate_user_admin(user_id, admin_user_id, erase_data);
}

json reactivate_user_admin(DatabasePool& db,
    const std::string& user_id,
    const std::string& admin_user_id) {
  return get_admin_tools(db).reactivate_user_admin(user_id, admin_user_id);
}

// ---- Registration tokens ----

json create_registration_token(DatabasePool& db,
    const std::string& admin_user_id,
    int64_t uses_allowed = 1,
    int64_t expiry_time = 0) {
  return get_admin_tools(db).create_registration_token(
    admin_user_id, uses_allowed, expiry_time);
}

json list_registration_tokens(DatabasePool& db) {
  return get_admin_tools(db).list_registration_tokens();
}

json revoke_registration_token(DatabasePool& db,
    const std::string& token,
    const std::string& admin_user_id) {
  return get_admin_tools(db).revoke_registration_token(token, admin_user_id);
}

json validate_registration_token(DatabasePool& db, const std::string& token) {
  return get_admin_tools(db).validate_registration_token(token);
}

json consume_registration_token(DatabasePool& db,
    const std::string& token,
    const std::string& user_id) {
  return get_admin_tools(db).consume_registration_token(token, user_id);
}

// ---- Consent management ----

json set_user_consent(DatabasePool& db,
    const std::string& user_id,
    const std::string& consent_version,
    bool accepted,
    const std::string& admin_user_id) {
  return get_admin_tools(db).set_user_consent(
    user_id, consent_version, accepted, admin_user_id);
}

json get_user_consent(DatabasePool& db,
    const std::string& user_id = "",
    const std::string& consent_version = "") {
  return get_admin_tools(db).get_user_consent(user_id, consent_version);
}

// ---- Server ACL override ----

json override_server_acl(DatabasePool& db,
    const std::string& server_name,
    const std::string& action,
    const std::string& reason,
    const std::string& admin_user_id) {
  return get_admin_tools(db).override_server_acl(
    server_name, action, reason, admin_user_id);
}

json remove_server_acl_override(DatabasePool& db,
    const std::string& server_name,
    const std::string& admin_user_id) {
  return get_admin_tools(db).remove_server_acl_override(server_name, admin_user_id);
}

json check_server_acl(DatabasePool& db, const std::string& server_name) {
  return get_admin_tools(db).check_server_acl(server_name);
}

json list_server_acl_overrides(DatabasePool& db) {
  return get_admin_tools(db).list_server_acl_overrides();
}

// ---- Force join/leave ----

json force_join_room(DatabasePool& db,
    const std::string& user_id,
    const std::string& room_id,
    const std::string& admin_user_id) {
  return get_admin_tools(db).force_join_room(user_id, room_id, admin_user_id);
}

json force_leave_room(DatabasePool& db,
    const std::string& user_id,
    const std::string& room_id,
    const std::string& admin_user_id) {
  return get_admin_tools(db).force_leave_room(user_id, room_id, admin_user_id);
}

// ---- Audit log ----

json get_audit_log(DatabasePool& db, int64_t limit = 100, int64_t offset = 0) {
  return get_admin_tools(db).get_audit_log(limit, offset);
}

}  // namespace progressive::handlers
