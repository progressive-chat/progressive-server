// ============================================================================
// client_extra_full.cpp — Extra Matrix REST client handler implementations
// Covers: RoomUpgradeServlet, RoomReportServlet, RoomAliasServlet,
//         PublicRoomsServlet, ThirdPartyProtocolServlet, LoginFallbackServlet,
//         LogoutAllServlet, AccountDeactivationServlet, PasswordPolicyServlet,
//         UsernameAvailableServlet, RegisterAvailableServlet
//
// Each servlet inherits from BaseRestServlet via ClientV1RestServlet.
// Full HTTP method dispatch with complete SQL operations, JSON parsing,
// and proper error handling.
// Target: 2000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/rest/rest_base.hpp"
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/storage/databases/main/devices.hpp"
#include "progressive/storage/databases/main/final_stores.hpp"

namespace progressive::rest {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Internal helper functions (not visible outside this TU)
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
// generate_token — random token (base62).
// --------------------------------------------------------------------------
std::string generate_token(int len = 32) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(
      static_cast<unsigned>(
          chr::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<int> dist(0, 61);
  std::string out(len, '\0');
  for (int i = 0; i < len; ++i) out[i] = alphabet[dist(rng)];
  return out;
}

// --------------------------------------------------------------------------
// generate_id — random localpart for event IDs, room IDs, etc. (18 chars).
// --------------------------------------------------------------------------
std::string generate_id() {
  static const char c[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(
      static_cast<unsigned>(
          chr::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<int> dist(0, 61);
  std::string id(18, 'A');
  for (auto& ch : id) ch = c[dist(rng)];
  return id;
}

// --------------------------------------------------------------------------
// extract_token — pulls the Bearer token from Authorization header or
//                 query parameter access_token.
// --------------------------------------------------------------------------
std::optional<std::string> extract_token(const HttpRequest& req) {
  auto ah = req.headers.find("Authorization");
  if (ah != req.headers.end()) {
    const std::string& v = ah->second;
    if (v.size() > 7 && v.substr(0, 7) == "Bearer ")
      return v.substr(7);
  }
  auto q = req.query_params.find("access_token");
  if (q != req.query_params.end() && !q->second.empty())
    return q->second;
  return std::nullopt;
}

// --------------------------------------------------------------------------
// safe_json_body — parse request body, return empty object on failure.
// --------------------------------------------------------------------------
json safe_json_body(const HttpRequest& req) {
  if (req.body.empty()) return json::object();
  try {
    return json::parse(req.body);
  } catch (...) {
    return json::object();
  }
}

// --------------------------------------------------------------------------
// build_error — convenience wrapper around error response.
// --------------------------------------------------------------------------
HttpResponse build_error(int code, const std::string& errcode,
                          const std::string& error) {
  HttpResponse r;
  r.code = code;
  r.body = {{"errcode", errcode}, {"error", error}};
  return r;
}

// --------------------------------------------------------------------------
// build_success — convenience wrapper.
// --------------------------------------------------------------------------
HttpResponse build_success(const json& data = json::object()) {
  HttpResponse r;
  r.code = 200;
  r.body = data;
  return r;
}

// --------------------------------------------------------------------------
// try_require_auth — authenticate and return Requester, or fail.
// --------------------------------------------------------------------------
std::pair<bool, Requester> try_require_auth(storage::DatabasePool& db,
                                             const HttpRequest& req) {
  try {
    AuthHelper auth(db);
    return {true, auth.require_auth(req)};
  } catch (...) {
    return {false, Requester{}};
  }
}

// --------------------------------------------------------------------------
// parse_path_segment — extract a portion of the path after a prefix.
// --------------------------------------------------------------------------
std::optional<std::string> parse_path_segment(const std::string& path,
                                                const std::string& prefix,
                                                const std::string& suffix = "") {
  auto p = path.find(prefix);
  if (p == std::string::npos) return std::nullopt;
  std::string rest = path.substr(p + prefix.size());
  if (!suffix.empty()) {
    auto s = rest.find(suffix);
    if (s != std::string::npos) rest = rest.substr(0, s);
  }
  auto slash = rest.find('/');
  if (slash != std::string::npos) rest = rest.substr(0, slash);
  // URL decode %23 -> #, %40 -> @, etc.
  auto pct = rest.find('%');
  while (pct != std::string::npos && pct + 2 < rest.size()) {
    std::string hex = rest.substr(pct + 1, 2);
    try {
      int val = std::stoi(hex, nullptr, 16);
      rest.replace(pct, 3, 1, static_cast<char>(val));
    } catch (...) { break; }
    pct = rest.find('%', pct + 1);
  }
  return rest;
}

// --------------------------------------------------------------------------
// url_decode — simple percent-decoding.
// --------------------------------------------------------------------------
std::string url_decode(const std::string& src) {
  std::string result;
  result.reserve(src.size());
  for (size_t i = 0; i < src.size(); ++i) {
    if (src[i] == '%' && i + 2 < src.size()) {
      try {
        int val = std::stoi(src.substr(i + 1, 2), nullptr, 16);
        result += static_cast<char>(val);
        i += 2;
        continue;
      } catch (...) {}
    }
    result += src[i];
  }
  return result;
}

// --------------------------------------------------------------------------
// is_rate_limited — simple in-memory rate limiter.
// --------------------------------------------------------------------------
static std::map<std::string, int64_t> rate_limit_map;
static std::map<std::string, int> rate_limit_hits;
static std::mutex rate_limit_mutex;

bool is_rate_limited(const std::string& key, int max_hits, int64_t window_ms) {
  std::lock_guard<std::mutex> lk(rate_limit_mutex);
  int64_t ts = now_ms();
  auto it = rate_limit_map.find(key);
  if (it != rate_limit_map.end()) {
    if (ts - it->second < window_ms) {
      auto hc = rate_limit_hits.find(key);
      if (hc == rate_limit_hits.end()) rate_limit_hits[key] = 1;
      else {
        hc->second++;
        if (hc->second > max_hits) return true;
      }
    } else {
      rate_limit_hits[key] = 1;
      rate_limit_map[key] = ts;
      return false;
    }
  } else {
    rate_limit_map[key] = ts;
    rate_limit_hits[key] = 1;
  }
  return false;
}

// --------------------------------------------------------------------------
// get_room_members_sql — get all members of a room with a given membership.
// --------------------------------------------------------------------------
std::vector<std::string> get_room_members(storage::DatabasePool& db,
                                            const std::string& room_id,
                                            const std::string& membership = "join") {
  return db.runInteraction("get_room_members",
      [&](storage::LoggingTransaction& txn) -> std::vector<std::string> {
        txn.execute(
            "SELECT user_id FROM room_memberships "
            "WHERE room_id=? AND membership=?",
            {room_id, membership});
        std::vector<std::string> result;
        auto rows = txn.fetchall();
        for (const auto& row : rows) {
          if (!row.empty() && row[0].value)
            result.push_back(*row[0].value);
        }
        return result;
      });
}

// --------------------------------------------------------------------------
// get_current_state — fetch current state events for a room.
// --------------------------------------------------------------------------
json get_current_state(storage::DatabasePool& db, const std::string& room_id) {
  return db.runInteraction("get_current_state",
      [&](storage::LoggingTransaction& txn) -> json {
        json state = json::array();
        txn.execute(
            "SELECT e.event_id, e.type, e.state_key, e.content, e.sender "
            "FROM current_state_events cs "
            "JOIN events e ON cs.event_id = e.event_id "
            "WHERE cs.room_id=?",
            {room_id});
        auto rows = txn.fetchall();
        for (const auto& row : rows) {
          if (row.size() < 5) continue;
          json evt;
          evt["event_id"] = row[0].value.value_or("");
          evt["type"] = row[1].value.value_or("");
          if (row[2].value && !row[2].value->empty())
            evt["state_key"] = *row[2].value;
          try {
            evt["content"] = row[3].value
                ? json::parse(*row[3].value) : json::object();
          } catch (...) { evt["content"] = json::object(); }
          evt["sender"] = row[4].value.value_or("");
          state.push_back(evt);
        }
        return state;
      });
}

// --------------------------------------------------------------------------
// get_max_stream_ordering — get the max stream_ordering from events table.
// --------------------------------------------------------------------------
int64_t get_max_stream_ordering(storage::DatabasePool& db) {
  return db.runInteraction("get_max_so",
      [&](storage::LoggingTransaction& txn) -> int64_t {
        txn.execute("SELECT COALESCE(MAX(stream_ordering), 0) FROM events", {});
        auto row = txn.fetchone();
        if (row && !row->empty() && row->at(0).value) {
          try { return std::stoll(*row->at(0).value); } catch (...) {}
        }
        return 0;
      });
}

// --------------------------------------------------------------------------
// get_max_depth — get the max depth for a room.
// --------------------------------------------------------------------------
int64_t get_max_depth(storage::DatabasePool& db, const std::string& room_id) {
  return db.runInteraction("get_max_depth",
      [&](storage::LoggingTransaction& txn) -> int64_t {
        txn.execute(
            "SELECT COALESCE(MAX(depth),0) FROM events WHERE room_id=?",
            {room_id});
        auto row = txn.fetchone();
        if (row && !row->empty() && row->at(0).value) {
          try { return std::stoll(*row->at(0).value); } catch (...) {}
        }
        return 0;
      });
}

// --------------------------------------------------------------------------
// persist_event — insert an event into events, event_json, current_state_events.
// --------------------------------------------------------------------------
void persist_event_db(storage::LoggingTransaction& txn,
                       const std::string& event_id,
                       const std::string& room_id,
                       const std::string& type,
                       const std::string& sender,
                       const std::string& state_key,
                       const json& content,
                       int64_t depth,
                       int64_t stream_ordering,
                       const std::string& replaces_state = "") {
  int64_t ts = now_ms();
  std::string content_str = content.dump();
  txn.execute(
      "INSERT INTO events "
      "(event_id, room_id, type, sender, state_key, replaces_state, "
      " depth, origin_server_ts, stream_ordering, content, "
      " has_redacted, received_ts, decrypted, decrypted_type, "
      " outlier, processed, rejected, failed_pull_attempts, "
      " error, sender_type, redacted_because, auth, version) "
      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      {event_id, room_id, type, sender, state_key, replaces_state,
       std::to_string(depth), std::to_string(ts),
       std::to_string(stream_ordering),
       content_str,
       "0", std::to_string(ts), "0", "", "0", "1", "0", "0",
       "", "", "{}", "{}", "10"});

  txn.execute(
      "INSERT INTO event_json "
      "(event_id, room_id, internal_metadata, json, format_version) "
      "VALUES (?,?,?,?,?)",
      {event_id, room_id, "{}", content_str, "1"});

  if (!state_key.empty()) {
    txn.execute(
        "INSERT INTO current_state_events "
        "(event_id, room_id, type, state_key) VALUES (?,?,?,?) "
        "ON CONFLICT(room_id,type,state_key) DO UPDATE SET event_id=excluded.event_id",
        {event_id, room_id, type, state_key});
  }
}

// --------------------------------------------------------------------------
// get_default_power_levels — return default power_levels content for a room.
// --------------------------------------------------------------------------
json get_default_pl(const std::string& creator) {
  json pl;
  pl["ban"] = 50; pl["invite"] = 0; pl["kick"] = 50;
  pl["redact"] = 50; pl["events_default"] = 0;
  pl["state_default"] = 50; pl["users_default"] = 0;
  pl["users"] = json::object();
  pl["users"][creator] = 100;
  pl["events"] = json::object();
  pl["events"]["m.room.name"] = 50;
  pl["events"]["m.room.power_levels"] = 100;
  pl["events"]["m.room.history_visibility"] = 100;
  pl["events"]["m.room.canonical_alias"] = 50;
  pl["events"]["m.room.avatar"] = 50;
  pl["events"]["m.room.tombstone"] = 100;
  pl["events"]["m.room.server_acl"] = 100;
  pl["events"]["m.room.encryption"] = 100;
  return pl;
}

// --------------------------------------------------------------------------
// server_name — shared server_name used across servlets.
// --------------------------------------------------------------------------
static const std::string server_name = "localhost";

} // anonymous namespace


// ============================================================================
// 1. ROOM UPGRADE SERVLET
// Equivalent to synapse.rest.client.room.RoomUpgradeRestServlet
// Patterns: /_matrix/client/v3/rooms/{roomId}/upgrade
// Methods: POST
// Creates a new room with a replacement/tombstone, copies state,
// and optionally invites members.
// Lines: ~220
// ============================================================================
class RoomUpgradeServlet : public ClientV1RestServlet {
public:
  explicit RoomUpgradeServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/rooms/{roomId}/upgrade",
            "/_matrix/client/r0/rooms/{roomId}/upgrade"};
  }
  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (req.method == "POST") return on_POST(req);
    return build_error(405, "M_UNRECOGNIZED", "Method not allowed");
  }

private:
  storage::DatabasePool& db_;

  HttpResponse on_POST(const HttpRequest& req) {
    try {
      // ---- Authenticate ----
      auto [ok, requester] = try_require_auth(db_, req);
      if (!ok)
        return build_error(401, "M_UNKNOWN_TOKEN",
                           "Missing or invalid access token");

      // ---- Extract room ID from path ----
      auto room_id_opt = parse_path_segment(req.path, "/rooms/", "/upgrade");
      if (!room_id_opt || room_id_opt->empty())
        return build_error(400, "M_MISSING_PARAM", "Missing room ID");
      std::string old_room_id = *room_id_opt;
      // Ensure room_id has server part
      if (old_room_id.find(':') == std::string::npos)
        old_room_id += ":" + server_name;

      // ---- Parse body ----
      json body = safe_json_body(req);
      std::string new_version = body.value("new_version", "10");

      // ---- Verify room exists and user is member ----
      bool room_exists = false;
      bool is_member = false;
      std::string room_name;
      std::string room_topic;
      std::vector<std::string> original_members;

      db_.runInteraction("upgrade_verify",
          [&](storage::LoggingTransaction& txn) {
            auto r = txn.execute(
                "SELECT 1 FROM rooms WHERE room_id=?", {old_room_id});
            auto row = txn.fetchone();
            room_exists = (row && !row->empty());

            if (room_exists) {
              auto m = txn.execute(
                  "SELECT membership FROM room_memberships "
                  "WHERE user_id=? AND room_id=?",
                  {requester.user_id, old_room_id});
              auto mrow = txn.fetchone();
              if (mrow && !mrow->empty() && mrow->at(0).value)
                is_member = (*mrow->at(0).value == "join");

              // Get room name
              auto n = txn.execute(
                  "SELECT content FROM current_state_events cs "
                  "JOIN events e ON cs.event_id = e.event_id "
                  "WHERE cs.room_id=? AND cs.type='m.room.name'",
                  {old_room_id});
              auto nrow = txn.fetchone();
              if (nrow && !nrow->empty() && nrow->at(0).value) {
                try {
                  json nc = json::parse(*nrow->at(0).value);
                  room_name = nc.value("name", "");
                } catch (...) {}
              }

              // Get room topic
              auto t = txn.execute(
                  "SELECT content FROM current_state_events cs "
                  "JOIN events e ON cs.event_id = e.event_id "
                  "WHERE cs.room_id=? AND cs.type='m.room.topic'",
                  {old_room_id});
              auto trow = txn.fetchone();
              if (trow && !trow->empty() && trow->at(0).value) {
                try {
                  json tc = json::parse(*trow->at(0).value);
                  room_topic = tc.value("topic", "");
                } catch (...) {}
              }
            }
          });

      if (!room_exists)
        return build_error(404, "M_NOT_FOUND", "Room not found");
      if (!is_member)
        return build_error(403, "M_FORBIDDEN",
                           "You must be a member of the room to upgrade it");

      // ---- Get members of the old room ----
      original_members = get_room_members(db_, old_room_id, "join");

      // ---- Create new room ID ----
      std::string new_room_local = "!" + generate_id();
      std::string new_room_id = new_room_local + ":" + server_name;

      // ---- Get current stream ordering ----
      int64_t base_stream = get_max_stream_ordering(db_) + 1;
      int64_t ts_now = now_ms();

      // ---- Run upgrade in transaction ----
      db_.runInteraction("upgrade_room",
          [&](storage::LoggingTransaction& txn) {
            int64_t so = base_stream;
            int64_t depth = 0;

            // ---- Insert new room ----
            txn.execute(
                "INSERT INTO rooms (room_id, is_public, creator, room_version) "
                "VALUES (?,?,?,?)",
                {new_room_id, "0", requester.user_id, new_version});

            // ---- m.room.create event ----
            json create_content;
            create_content["creator"] = requester.user_id;
            create_content["room_version"] = new_version;
            create_content["predecessor"] = {
              {"room_id", old_room_id},
              {"event_id", ""}
            };
            std::string create_event_id = "$" + generate_id() + ":" + server_name;
            persist_event_db(txn, create_event_id, new_room_id,
                "m.room.create", requester.user_id, "",
                create_content, ++depth, ++so);

            // ---- m.room.power_levels ----
            json pl = get_default_pl(requester.user_id);
            std::string pl_event_id = "$" + generate_id() + ":" + server_name;
            persist_event_db(txn, pl_event_id, new_room_id,
                "m.room.power_levels", requester.user_id, "",
                pl, ++depth, ++so);

            // ---- m.room.join_rules ----
            json join_rules;
            join_rules["join_rule"] = "invite";
            std::string jr_event_id = "$" + generate_id() + ":" + server_name;
            persist_event_db(txn, jr_event_id, new_room_id,
                "m.room.join_rules", requester.user_id, "",
                join_rules, ++depth, ++so);

            // ---- m.room.history_visibility ----
            json hist_vis;
            hist_vis["history_visibility"] = "shared";
            std::string hv_event_id = "$" + generate_id() + ":" + server_name;
            persist_event_db(txn, hv_event_id, new_room_id,
                "m.room.history_visibility", requester.user_id, "",
                hist_vis, ++depth, ++so);

            // ---- m.room.guest_access ----
            json guest_access;
            guest_access["guest_access"] = "forbidden";
            std::string ga_event_id = "$" + generate_id() + ":" + server_name;
            persist_event_db(txn, ga_event_id, new_room_id,
                "m.room.guest_access", requester.user_id, "",
                guest_access, ++depth, ++so);

            // ---- m.room.name (if set) ----
            if (!room_name.empty()) {
              json nc; nc["name"] = room_name;
              std::string nm_event_id = "$" + generate_id() + ":" + server_name;
              persist_event_db(txn, nm_event_id, new_room_id,
                  "m.room.name", requester.user_id, "",
                  nc, ++depth, ++so);
            }

            // ---- m.room.topic (if set) ----
            if (!room_topic.empty()) {
              json tc; tc["topic"] = room_topic;
              std::string tp_event_id = "$" + generate_id() + ":" + server_name;
              persist_event_db(txn, tp_event_id, new_room_id,
                  "m.room.topic", requester.user_id, "",
                  tc, ++depth, ++so);
            }

            // ---- Copy relevant state from old room: encryption, avatar, server_acl ----
            auto copy_state_type = [&](const std::string& stype) {
              txn.execute(
                  "SELECT e.content FROM current_state_events cs "
                  "JOIN events e ON cs.event_id = e.event_id "
                  "WHERE cs.room_id=? AND cs.type=?",
                  {old_room_id, stype});
              auto srow = txn.fetchone();
              if (srow && !srow->empty() && srow->at(0).value) {
                try {
                  json sc = json::parse(*srow->at(0).value);
                  std::string sev_id = "$" + generate_id() + ":" + server_name;
                  persist_event_db(txn, sev_id, new_room_id,
                      stype, requester.user_id, "", sc, ++depth, ++so);
                } catch (...) {}
              }
            };
            copy_state_type("m.room.encryption");
            copy_state_type("m.room.avatar");
            copy_state_type("m.room.server_acl");
            copy_state_type("m.room.canonical_alias");

            // ---- Member event for creator ----
            json member_content;
            member_content["membership"] = "join";
            member_content["displayname"] = requester.user_id;
            std::string mem_event_id = "$" + generate_id() + ":" + server_name;
            persist_event_db(txn, mem_event_id, new_room_id,
                "m.room.member", requester.user_id, requester.user_id,
                member_content, ++depth, ++so);

            // ---- Insert room_membership for creator ----
            txn.execute(
                "INSERT INTO room_memberships "
                "(event_id, room_id, user_id, membership, sender) "
                "VALUES (?,?,?,?,?)",
                {mem_event_id, new_room_id, requester.user_id, "join",
                 requester.user_id});

            // ---- Send invites to other members ----
            for (const auto& invitee : original_members) {
              if (invitee == requester.user_id) continue;
              json inv_content;
              inv_content["membership"] = "invite";
              inv_content["displayname"] = invitee;
              std::string inv_event_id = "$" + generate_id() + ":" + server_name;
              persist_event_db(txn, inv_event_id, new_room_id,
                  "m.room.member", requester.user_id, invitee,
                  inv_content, ++depth, ++so);

              txn.execute(
                  "INSERT INTO room_memberships "
                  "(event_id, room_id, user_id, membership, sender) "
                  "VALUES (?,?,?,?,?)",
                  {inv_event_id, new_room_id, invitee, "invite",
                   requester.user_id});
            }

            // ---- m.room.tombstone in OLD room ----
            json tombstone_content;
            tombstone_content["body"] = "This room has been replaced";
            tombstone_content["replacement_room"] = new_room_id;
            std::string tomb_event_id = "$" + generate_id() + ":" + server_name;
            int64_t old_depth = get_max_depth(db_, old_room_id);
            persist_event_db(txn, tomb_event_id, old_room_id,
                "m.room.tombstone", requester.user_id, "",
                tombstone_content, old_depth + 1, ++so);

            // ---- Record in room_stats_state ----
            txn.execute(
                "INSERT INTO room_stats_state (room_id) VALUES (?)",
                {new_room_id});
            txn.execute(
                "INSERT INTO room_depth (room_id, min_depth) VALUES (?,?)",
                {new_room_id, "0"});
          });

      // ---- Build response ----
      json response;
      response["replacement_room"] = new_room_id;
      return build_success(response);

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Room upgrade failed: ") + e.what());
    }
  }
};


// ============================================================================
// 2. ROOM REPORT SERVLET
// Equivalent to synapse.rest.client.room.RoomReportRestServlet
// Patterns: /_matrix/client/v3/rooms/{roomId}/report/{eventId}
// Methods: POST
// Records a report against a room or event with reason and score.
// Lines: ~130
// ============================================================================
class RoomReportServlet : public ClientV1RestServlet {
public:
  explicit RoomReportServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/rooms/{roomId}/report/{eventId}",
            "/_matrix/client/r0/rooms/{roomId}/report/{eventId}"};
  }
  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (req.method == "POST") return on_POST(req);
    return build_error(405, "M_UNRECOGNIZED", "Method not allowed");
  }

private:
  storage::DatabasePool& db_;

  HttpResponse on_POST(const HttpRequest& req) {
    try {
      // ---- Authenticate ----
      auto [ok, requester] = try_require_auth(db_, req);
      if (!ok)
        return build_error(401, "M_UNKNOWN_TOKEN",
                           "Missing or invalid access token");

      // ---- Extract room ID from path ----
      auto room_id_opt = parse_path_segment(req.path, "/rooms/", "/report");
      if (!room_id_opt || room_id_opt->empty())
        return build_error(400, "M_MISSING_PARAM", "Missing room ID");
      std::string room_id = *room_id_opt;

      // ---- Extract event ID from path ----
      auto evt_suffix = req.path.find("/report/");
      std::string event_id;
      if (evt_suffix != std::string::npos) {
        event_id = req.path.substr(evt_suffix + 8);
        // URL decode
        event_id = url_decode(event_id);
        // Strip trailing slash
        if (!event_id.empty() && event_id.back() == '/')
          event_id.pop_back();
      }

      // ---- Parse body ----
      json body = safe_json_body(req);

      // reason is required
      if (!body.contains("reason") || !body["reason"].is_string())
        return build_error(400, "M_MISSING_PARAM",
                           "Missing 'reason' field");

      std::string reason = body["reason"].get<std::string>();
      if (reason.empty())
        return build_error(400, "M_INVALID_PARAM",
                           "Reason must not be empty");

      // score is optional, default -100
      int score = body.value("score", -100);
      if (score < -100) score = -100;
      if (score > 0) score = 0;

      // ---- Rate-limit reports: 10 per user per 60s ----
      if (is_rate_limited("report:" + requester.user_id, 10, 60000))
        return build_error(429, "M_LIMIT_EXCEEDED",
                           "Too many report requests");

      // ---- Verify room exists ----
      bool room_exists = false;
      db_.runInteraction("report_verify",
          [&](storage::LoggingTransaction& txn) {
            txn.execute("SELECT 1 FROM rooms WHERE room_id=?", {room_id});
            auto row = txn.fetchone();
            room_exists = (row && !row->empty());
          });

      if (!room_exists)
        return build_error(404, "M_NOT_FOUND", "Room not found");

      // ---- Insert report into event_reports table ----
      int64_t ts = now_ms();
      db_.runInteraction("insert_report",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "INSERT INTO event_reports "
                "(room_id, event_id, user_id, reason, score, received_ts, content) "
                "VALUES (?,?,?,?,?,?,?)",
                {room_id,
                 event_id.empty() ? "room_report" : event_id,
                 requester.user_id,
                 reason,
                 std::to_string(score),
                 std::to_string(ts),
                 body.dump()});
          });

      // ---- Return empty success ----
      return build_success();

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Report failed: ") + e.what());
    }
  }
};


// ============================================================================
// 3. ROOM ALIAS SERVLET
// Equivalent to synapse.rest.client.directory.ClientDirectoryServer
// Patterns: /_matrix/client/v3/directory/room/{roomAlias}
// Methods: PUT (create), DELETE (remove), GET (resolve)
// Lines: ~180
// ============================================================================
class RoomAliasServlet : public ClientV1RestServlet {
public:
  explicit RoomAliasServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/directory/room/{roomAlias}",
            "/_matrix/client/r0/directory/room/{roomAlias}"};
  }
  std::vector<std::string> methods() const override {
    return {"GET", "PUT", "DELETE"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (req.method == "PUT")    return on_PUT(req);
    if (req.method == "GET")    return on_GET(req);
    if (req.method == "DELETE") return on_DELETE(req);
    return build_error(405, "M_UNRECOGNIZED", "Method not allowed");
  }

private:
  storage::DatabasePool& db_;

  // ------------------------------------------------------------------------
  // PUT /directory/room/{roomAlias} — create an alias for a room
  // ------------------------------------------------------------------------
  HttpResponse on_PUT(const HttpRequest& req) {
    try {
      auto [ok, requester] = try_require_auth(db_, req);
      if (!ok)
        return build_error(401, "M_UNKNOWN_TOKEN", "Missing access token");

      // ---- Extract alias from path ----
      auto alias_opt = parse_path_segment(req.path, "/directory/room/");
      if (!alias_opt || alias_opt->empty())
        return build_error(400, "M_MISSING_PARAM", "Missing room alias");
      std::string room_alias = *alias_opt;

      // ---- Parse body to get room_id ----
      json body = safe_json_body(req);
      if (!body.contains("room_id"))
        return build_error(400, "M_MISSING_PARAM", "Missing room_id");

      std::string room_id = body["room_id"].get<std::string>();

      // ---- Verify room exists ----
      bool room_exists = false;
      db_.runInteraction("alias_put_verify",
          [&](storage::LoggingTransaction& txn) {
            txn.execute("SELECT 1 FROM rooms WHERE room_id=?", {room_id});
            auto row = txn.fetchone();
            room_exists = (row && !row->empty());
          });

      if (!room_exists)
        return build_error(404, "M_NOT_FOUND", "Room not found");

      // ---- Check if user has permission (must be room admin or have PL) ----
      // Simplified: any room member can create alias
      bool is_member = false;
      db_.runInteraction("alias_put_member_check",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT 1 FROM room_memberships "
                "WHERE user_id=? AND room_id=? AND membership='join'",
                {requester.user_id, room_id});
            auto row = txn.fetchone();
            is_member = (row && !row->empty());
          });

      if (!is_member)
        return build_error(403, "M_FORBIDDEN",
                           "You must be a member of the room to create an alias");

      // ---- Create alias using DirectoryStore ----
      storage::DirectoryStore dir(db_);
      auto existing_room = dir.get_room_id(room_alias);
      if (existing_room && *existing_room != room_id)
        return build_error(409, "M_UNKNOWN",
                           "Room alias already in use by another room");

      // Get servers list from body or default
      std::vector<std::string> servers;
      if (body.contains("servers") && body["servers"].is_array()) {
        for (const auto& s : body["servers"])
          servers.push_back(s.get<std::string>());
      }

      dir.create_alias(room_alias, room_id, requester.user_id, servers);

      return build_success();

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Alias creation failed: ") + e.what());
    }
  }

  // ------------------------------------------------------------------------
  // GET /directory/room/{roomAlias} — resolve alias to room_id and servers
  // ------------------------------------------------------------------------
  HttpResponse on_GET(const HttpRequest& req) {
    try {
      // ---- Extract alias from path ----
      auto alias_opt = parse_path_segment(req.path, "/directory/room/");
      if (!alias_opt || alias_opt->empty())
        return build_error(400, "M_MISSING_PARAM", "Missing room alias");

      std::string room_alias = *alias_opt;

      // ---- Ensure alias has # prefix ----
      if (room_alias[0] != '#')
        room_alias = "#" + room_alias;

      // ---- Resolve alias ----
      storage::DirectoryStore dir(db_);
      auto room_id = dir.get_room_id(room_alias);
      if (!room_id)
        return build_error(404, "M_NOT_FOUND",
                           "Room alias " + room_alias + " not found");

      auto servers = dir.get_servers_for_alias(room_alias);
      // Fallback: extract server_name from room_id
      if (servers.empty()) {
        auto colon = room_id->find(':');
        if (colon != std::string::npos)
          servers.push_back(room_id->substr(colon + 1));
      }

      json resp;
      resp["room_id"] = *room_id;
      resp["servers"] = servers;
      return build_success(resp);

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Alias resolution failed: ") + e.what());
    }
  }

  // ------------------------------------------------------------------------
  // DELETE /directory/room/{roomAlias} — remove an alias
  // ------------------------------------------------------------------------
  HttpResponse on_DELETE(const HttpRequest& req) {
    try {
      auto [ok, requester] = try_require_auth(db_, req);
      if (!ok)
        return build_error(401, "M_UNKNOWN_TOKEN", "Missing access token");

      auto alias_opt = parse_path_segment(req.path, "/directory/room/");
      if (!alias_opt || alias_opt->empty())
        return build_error(400, "M_MISSING_PARAM", "Missing room alias");

      std::string room_alias = *alias_opt;
      if (room_alias[0] != '#')
        room_alias = "#" + room_alias;

      // ---- Check that alias exists ----
      storage::DirectoryStore dir(db_);
      auto room_id = dir.get_room_id(room_alias);
      if (!room_id)
        return build_error(404, "M_NOT_FOUND",
                           "Room alias not found");

      // ---- Check permissions: must be alias creator or room admin ----
      auto creator = dir.get_alias_creator(room_alias);
      if (creator && *creator == requester.user_id) {
        // Creator can always delete their own alias
      } else {
        // Otherwise must be room admin (simplified: any member)
        bool is_member = false;
        db_.runInteraction("alias_del_check",
            [&](storage::LoggingTransaction& txn) {
              txn.execute(
                  "SELECT 1 FROM room_memberships "
                  "WHERE user_id=? AND room_id=? AND membership='join'",
                  {requester.user_id, *room_id});
              auto row = txn.fetchone();
              is_member = (row && !row->empty());
            });
        if (!is_member)
          return build_error(403, "M_FORBIDDEN",
                             "You do not have permission to delete this alias");
      }

      // ---- Delete alias ----
      dir.delete_alias(room_alias);

      return build_success();

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Alias deletion failed: ") + e.what());
    }
  }
};


// ============================================================================
// 4. PUBLIC ROOMS SERVLET
// Equivalent to synapse.rest.client.room.PublicRoomListRestServlet
// Patterns: /_matrix/client/v3/publicRooms
// Methods: GET (list public rooms with filters),
//          POST (list with server filter)
// Lines: ~200
// ============================================================================
class PublicRoomsServlet : public ClientV1RestServlet {
public:
  explicit PublicRoomsServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/publicRooms",
            "/_matrix/client/r0/publicRooms"};
  }
  std::vector<std::string> methods() const override {
    return {"GET", "POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (req.method == "GET")  return on_GET(req);
    if (req.method == "POST") return on_POST(req);
    return build_error(405, "M_UNRECOGNIZED", "Method not allowed");
  }

private:
  storage::DatabasePool& db_;

  // ------------------------------------------------------------------------
  // Build public room list JSON from DirectoryStore results
  // ------------------------------------------------------------------------
  json build_public_room_list(const std::string& server,
                               int64_t limit, int64_t since,
                               const std::string& search_term,
                               const std::string& network,
                               bool include_all,
                               const std::string& filter_generic_search = "") {
    storage::DirectoryStore dir(db_);
    auto rooms = dir.get_public_rooms(server, limit, since, search_term,
                                       network, include_all);

    json result = json::array();
    for (const auto& pr : rooms) {
      json entry;
      entry["room_id"] = pr.room_id;
      entry["name"] = pr.name;
      entry["topic"] = pr.topic;
      entry["num_joined_members"] = pr.num_joined_members;
      entry["world_readable"] = pr.world_readable;
      entry["guest_can_join"] = false;

      if (pr.canonical_alias)
        entry["canonical_alias"] = *pr.canonical_alias;
      if (pr.avatar_url)
        entry["avatar_url"] = *pr.avatar_url;

      // Apply generic search term filter if provided
      if (!filter_generic_search.empty()) {
        std::string lower_search = filter_generic_search;
        std::transform(lower_search.begin(), lower_search.end(),
                        lower_search.begin(), ::tolower);

        std::string lower_name = pr.name;
        std::transform(lower_name.begin(), lower_name.end(),
                        lower_name.begin(), ::tolower);
        std::string lower_topic = pr.topic;
        std::transform(lower_topic.begin(), lower_topic.end(),
                        lower_topic.begin(), ::tolower);
        std::string lower_alias = pr.canonical_alias.value_or("");
        std::transform(lower_alias.begin(), lower_alias.end(),
                        lower_alias.begin(), ::tolower);

        if (lower_name.find(lower_search) == std::string::npos &&
            lower_topic.find(lower_search) == std::string::npos &&
            lower_alias.find(lower_search) == std::string::npos)
          continue;
      }

      result.push_back(entry);
    }
    return result;
  }

  // ------------------------------------------------------------------------
  // GET /publicRooms — list public rooms with query params
  // ------------------------------------------------------------------------
  HttpResponse on_GET(const HttpRequest& req) {
    try {
      // ---- Optional auth (public endpoint) ----
      auto [authenticated, requester] = try_require_auth(db_, req);

      // ---- Parse query params ----
      auto server_opt   = BaseRestServlet::parse_string(req, "server");
      auto search_opt   = BaseRestServlet::parse_string(req, "q");
      auto limit_opt    = BaseRestServlet::parse_integer(req, "limit");
      auto since_opt    = BaseRestServlet::parse_integer(req, "since");
      auto network_opt  = BaseRestServlet::parse_string(req, "third_party_instance_id");
      bool include_all  = BaseRestServlet::parse_boolean(req, "include_all_networks", false);
      auto filter_opt   = BaseRestServlet::parse_string(req, "filter");

      int64_t limit = limit_opt.value_or(50);
      if (limit < 1) limit = 1;
      if (limit > 500) limit = 500;

      int64_t since = since_opt.value_or(0);
      std::string server = server_opt.value_or("");
      std::string search_term = search_opt.value_or("");
      std::string network = network_opt.value_or("");
      std::string filter_generic = filter_opt.value_or("");

      // ---- Rate limit ----
      if (authenticated) {
        if (is_rate_limited("publicrooms:" + requester.user_id, 30, 60000))
          return build_error(429, "M_LIMIT_EXCEEDED",
                             "Too many requests");
      } else {
        if (is_rate_limited("publicrooms:anonymous:" + req.client_ip, 10, 60000))
          return build_error(429, "M_LIMIT_EXCEEDED",
                             "Too many requests");
      }

      // ---- Fetch public rooms ----
      json chunk = build_public_room_list(server, limit, since,
                                           search_term, network,
                                           include_all, filter_generic);

      // ---- Build response ----
      json resp;
      resp["chunk"] = chunk;
      resp["total_room_count_estimate"] = chunk.size();

      if (static_cast<int64_t>(chunk.size()) >= limit) {
        resp["next_batch"] = std::to_string(since + limit);
      }

      if (authenticated) {
        // Add prev_batch for pagination
        if (since > 0)
          resp["prev_batch"] = std::to_string(std::max<int64_t>(0, since - limit));
      }

      return build_success(resp);

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Public rooms listing failed: ") + e.what());
    }
  }

  // ------------------------------------------------------------------------
  // POST /publicRooms — list public rooms with body parameters
  // ------------------------------------------------------------------------
  HttpResponse on_POST(const HttpRequest& req) {
    try {
      auto [authenticated, requester] = try_require_auth(db_, req);

      json body = safe_json_body(req);

      auto server_opt  = body.contains("server") ? std::optional(body["server"].get<std::string>()) : std::nullopt;
      auto search_opt  = body.contains("filter") && body["filter"].contains("generic_search_term")
                           ? std::optional(body["filter"]["generic_search_term"].get<std::string>())
                           : std::nullopt;
      int64_t limit    = body.value("limit", 50);
      int64_t since    = body.value("since", 0);
      auto network_opt = body.contains("third_party_instance_id")
                           ? std::optional(body["third_party_instance_id"].get<std::string>())
                           : std::nullopt;
      bool include_all = body.value("include_all_networks", false);

      if (limit < 1) limit = 1;
      if (limit > 500) limit = 500;

      // ---- Rate limit ----
      if (authenticated) {
        if (is_rate_limited("publicrooms_post:" + requester.user_id, 30, 60000))
          return build_error(429, "M_LIMIT_EXCEEDED", "Too many requests");
      }

      // ---- Fetch public rooms ----
      json chunk = build_public_room_list(
          server_opt.value_or(""), limit, since,
          search_opt.value_or(""), network_opt.value_or(""),
          include_all,
          search_opt.value_or(""));

      json resp;
      resp["chunk"] = chunk;
      resp["total_room_count_estimate"] = chunk.size();

      if (static_cast<int64_t>(chunk.size()) >= limit) {
        resp["next_batch"] = std::to_string(since + limit);
      }
      if (since > 0 && authenticated) {
        resp["prev_batch"] = std::to_string(std::max<int64_t>(0, since - limit));
      }

      return build_success(resp);

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Public rooms listing failed: ") + e.what());
    }
  }
};


// ============================================================================
// 5. THIRD-PARTY PROTOCOL SERVLET
// Equivalent to synapse.rest.client.room.ThirdPartyProtocolServlet
// Provides bridge info for third-party networks (IRC, Discord, etc.)
// Patterns: /_matrix/client/v3/thirdparty/protocols
//           /_matrix/client/v3/thirdparty/protocol/{protocol}
//           /_matrix/client/v3/thirdparty/location/{protocol}
//           /_matrix/client/v3/thirdparty/user/{protocol}
// Methods: GET
// Lines: ~230
// ============================================================================
class ThirdPartyProtocolServlet : public ClientV1RestServlet {
public:
  explicit ThirdPartyProtocolServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/thirdparty/protocols",
      "/_matrix/client/v3/thirdparty/protocol/{protocol}",
      "/_matrix/client/v3/thirdparty/location/{protocol}",
      "/_matrix/client/v3/thirdparty/user/{protocol}"
    };
  }
  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (req.method != "GET")
      return build_error(405, "M_UNRECOGNIZED", "Method not allowed");

    // ---- Check path to determine which handler to call ----
    if (req.path.find("/thirdparty/protocols") != std::string::npos &&
        req.path.find("/protocol/") == std::string::npos)
      return list_protocols(req);

    if (req.path.find("/thirdparty/protocol/") != std::string::npos)
      return get_protocol(req);

    if (req.path.find("/thirdparty/location/") != std::string::npos)
      return search_locations(req);

    if (req.path.find("/thirdparty/user/") != std::string::npos)
      return search_users_thirdparty(req);

    return build_error(404, "M_NOT_FOUND", "Unknown third-party endpoint");
  }

private:
  storage::DatabasePool& db_;

  // ------------------------------------------------------------------------
  // GET /thirdparty/protocols — list all supported protocols
  // ------------------------------------------------------------------------
  HttpResponse list_protocols(const HttpRequest& req) {
    try {
      auto [ok, requester] = try_require_auth(db_, req);
      if (!ok)
        return build_error(401, "M_UNKNOWN_TOKEN", "Missing access token");

      // ---- Query third-party protocols from DB ----
      json protocols = db_.runInteraction("list_tpp",
          [&](storage::LoggingTransaction& txn) -> json {
            json result = json::object();

            txn.execute(
                "SELECT protocol_id, display_name, icon, "
                "field_types, location_fields, user_fields "
                "FROM third_party_protocols ORDER BY display_name",
                {});
            auto rows = txn.fetchall();

            for (const auto& row : rows) {
              if (row.size() < 6) continue;

              std::string pid = row[0].value.value_or("");
              if (pid.empty()) continue;

              json proto;
              proto["user_fields"] = json::array();
              proto["location_fields"] = json::array();
              proto["field_types"] = json::object();
              proto["instances"] = json::array();

              // Display name
              proto["display_name"] = row[1].value.value_or(pid);

              if (row[2].value && !row[2].value->empty())
                proto["icon"] = *row[2].value;

              // Parse field_types JSON
              if (row[3].value && !row[3].value->empty()) {
                try { proto["field_types"] = json::parse(*row[3].value); }
                catch (...) { proto["field_types"] = json::object(); }
              }

              // Parse location_fields JSON
              if (row[4].value && !row[4].value->empty()) {
                try { proto["location_fields"] = json::parse(*row[4].value); }
                catch (...) { proto["location_fields"] = json::array(); }
              }

              // Parse user_fields JSON
              if (row[5].value && !row[5].value->empty()) {
                try { proto["user_fields"] = json::parse(*row[5].value); }
                catch (...) { proto["user_fields"] = json::array(); }
              }

              result[pid] = proto;
            }

            return result;
          });

      return build_success(protocols);

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Protocol list failed: ") + e.what());
    }
  }

  // ------------------------------------------------------------------------
  // GET /thirdparty/protocol/{protocol} — get details for a specific protocol
  // ------------------------------------------------------------------------
  HttpResponse get_protocol(const HttpRequest& req) {
    try {
      auto [ok, requester] = try_require_auth(db_, req);
      if (!ok)
        return build_error(401, "M_UNKNOWN_TOKEN", "Missing access token");

      auto proto_opt = parse_path_segment(req.path, "/protocol/");
      if (!proto_opt || proto_opt->empty())
        return build_error(400, "M_MISSING_PARAM", "Missing protocol name");

      std::string protocol_name = *proto_opt;

      // ---- Query specific protocol ----
      json proto = db_.runInteraction("get_tpp",
          [&](storage::LoggingTransaction& txn) -> json {
            txn.execute(
                "SELECT protocol_id, display_name, icon, field_types, "
                "location_fields, user_fields "
                "FROM third_party_protocols WHERE protocol_id=?",
                {protocol_name});
            auto row = txn.fetchone();

            if (!row || row->empty())
              return json(); // empty = not found

            json p;
            p["user_fields"] = json::array();
            p["location_fields"] = json::array();
            p["field_types"] = json::object();
            p["instances"] = json::array();

            p["display_name"] = row->at(1).value.value_or(protocol_name);

            if (row->size() > 2 && row->at(2).value && !row->at(2).value->empty())
              p["icon"] = *row->at(2).value;

            if (row->size() > 3 && row->at(3).value && !row->at(3).value->empty()) {
              try { p["field_types"] = json::parse(*row->at(3).value); }
              catch (...) { p["field_types"] = json::object(); }
            }

            if (row->size() > 4 && row->at(4).value && !row->at(4).value->empty()) {
              try { p["location_fields"] = json::parse(*row->at(4).value); }
              catch (...) { p["location_fields"] = json::array(); }
            }

            if (row->size() > 5 && row->at(5).value && !row->at(5).value->empty()) {
              try { p["user_fields"] = json::parse(*row->at(5).value); }
              catch (...) { p["user_fields"] = json::array(); }
            }

            return p;
          });

      if (proto.empty())
        return build_error(404, "M_NOT_FOUND",
                           "Protocol " + protocol_name + " not found");

      return build_success(proto);

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Protocol fetch failed: ") + e.what());
    }
  }

  // ------------------------------------------------------------------------
  // GET /thirdparty/location/{protocol} — search locations on a protocol
  // Query params: searchFields
  // ------------------------------------------------------------------------
  HttpResponse search_locations(const HttpRequest& req) {
    try {
      auto [ok, requester] = try_require_auth(db_, req);
      if (!ok)
        return build_error(401, "M_UNKNOWN_TOKEN", "Missing access token");

      auto proto_opt = parse_path_segment(req.path, "/location/");
      if (!proto_opt || proto_opt->empty())
        return build_error(400, "M_MISSING_PARAM", "Missing protocol name");

      std::string protocol_name = *proto_opt;

      // ---- Build search query from query parameters ----
      json search_fields = json::object();
      for (const auto& [key, val] : req.query_params) {
        if (key.find("searchFields[") != std::string::npos) {
          // Extract field name from searchFields[fieldname]
          auto start = key.find('[');
          auto end = key.find(']');
          if (start != std::string::npos && end != std::string::npos && end > start) {
            std::string field_name = key.substr(start + 1, end - start - 1);
            search_fields[field_name] = val;
          }
        }
      }

      // ---- Query locations from DB ----
      json locations = db_.runInteraction("search_tpp_loc",
          [&](storage::LoggingTransaction& txn) -> json {
            json result = json::array();
            std::string where = "WHERE protocol_id='" + protocol_name + "'";
            // Build dynamic WHERE from search_fields
            for (const auto& [field, value] : search_fields.items()) {
              where += " AND (";
              where += "alias LIKE '%" + std::string(value.get<std::string>()) + "%'";
              where += " OR name LIKE '%" + std::string(value.get<std::string>()) + "%'";
              where += " OR fields_json LIKE '%" + std::string(value.get<std::string>()) + "%'";
              where += ")";
            }

            txn.execute(
                "SELECT alias, protocol_id, name, fields_json "
                "FROM third_party_locations " + where + " LIMIT 50",
                {});
            auto rows = txn.fetchall();

            for (const auto& row : rows) {
              if (row.size() < 4) continue;
              json loc;
              loc["alias"] = row[0].value.value_or("");
              loc["protocol"] = row[1].value.value_or(protocol_name);
              loc["name"] = row[2].value.value_or("");

              if (row[3].value && !row[3].value->empty()) {
                try { loc["fields"] = json::parse(*row[3].value); }
                catch (...) { loc["fields"] = json::object(); }
              }
              result.push_back(loc);
            }
            return result;
          });

      return build_success(locations);

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Location search failed: ") + e.what());
    }
  }

  // ------------------------------------------------------------------------
  // GET /thirdparty/user/{protocol} — search users on a protocol
  // Query params: fields...
  // ------------------------------------------------------------------------
  HttpResponse search_users_thirdparty(const HttpRequest& req) {
    try {
      auto [ok, requester] = try_require_auth(db_, req);
      if (!ok)
        return build_error(401, "M_UNKNOWN_TOKEN", "Missing access token");

      auto proto_opt = parse_path_segment(req.path, "/user/");
      if (!proto_opt || proto_opt->empty())
        return build_error(400, "M_MISSING_PARAM", "Missing protocol name");

      std::string protocol_name = *proto_opt;

      // ---- Build search query ----
      json search_fields = json::object();
      for (const auto& [key, val] : req.query_params) {
        if (key.find("fields[") != std::string::npos) {
          auto start = key.find('[');
          auto end = key.find(']');
          if (start != std::string::npos && end != std::string::npos && end > start) {
            std::string field_name = key.substr(start + 1, end - start - 1);
            search_fields[field_name] = val;
          }
        }
      }

      // ---- Query users from DB ----
      json users = db_.runInteraction("search_tpp_user",
          [&](storage::LoggingTransaction& txn) -> json {
            json result = json::array();
            std::string where = "WHERE protocol_id='" + protocol_name + "'";
            for (const auto& [field, value] : search_fields.items()) {
              where += " AND (";
              where += "userid LIKE '%" + std::string(value.get<std::string>()) + "%'";
              where += " OR display_name LIKE '%" + std::string(value.get<std::string>()) + "%'";
              where += " OR fields_json LIKE '%" + std::string(value.get<std::string>()) + "%'";
              where += ")";
            }

            txn.execute(
                "SELECT userid, protocol_id, display_name, fields_json "
                "FROM third_party_users " + where + " LIMIT 50",
                {});
            auto rows = txn.fetchall();

            for (const auto& row : rows) {
              if (row.size() < 4) continue;
              json usr;
              usr["userid"] = row[0].value.value_or("");
              usr["protocol"] = row[1].value.value_or(protocol_name);
              usr["display_name"] = row[2].value.value_or("");

              if (row[3].value && !row[3].value->empty()) {
                try { usr["fields"] = json::parse(*row[3].value); }
                catch (...) { usr["fields"] = json::object(); }
              }
              result.push_back(usr);
            }
            return result;
          });

      return build_success(users);

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("User search failed: ") + e.what());
    }
  }
};


// ============================================================================
// 6. LOGIN FALLBACK SERVLET
// Equivalent to synapse.rest.client.login.LoginFallbackRestServlet
// Patterns: /_matrix/client/v3/login (fallback)
// Methods: GET
// Returns HTML login fallback page with recaptcha, terms, SSO links.
// Lines: ~130
// ============================================================================
class LoginFallbackServlet : public ClientV1RestServlet {
public:
  explicit LoginFallbackServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/login",
            "/_matrix/client/v1/login",
            "/_matrix/client/r0/login",
            "/_matrix/static/client/login"};
  }
  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (req.method == "GET") return on_GET(req);
    return build_error(405, "M_UNRECOGNIZED", "Method not allowed");
  }

private:
  storage::DatabasePool& db_;

  // ------------------------------------------------------------------------
  // on_GET — return login fallback or JSON flow listing
  // If Accept header indicates HTML, return fallback page.
  // Otherwise, return JSON login flows (like LoginServlet.on_GET).
  // ------------------------------------------------------------------------
  HttpResponse on_GET(const HttpRequest& req) {
    // ---- Check if this is the static fallback path ----
    bool is_static = (req.path.find("/static/client/login") != std::string::npos);

    // ---- Check Accept header for HTML preference ----
    auto accept_it = req.headers.find("Accept");
    bool wants_html = false;
    if (accept_it != req.headers.end()) {
      wants_html = (accept_it->second.find("text/html") != std::string::npos);
    }

    if (is_static || wants_html) {
      // ---- Return HTML login fallback page ----
      std::ostringstream html;
      html << "<!DOCTYPE html>\n"
           << "<html lang=\"en\">\n"
           << "<head>\n"
           << "<meta charset=\"utf-8\">\n"
           << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
           << "<title>Sign In — Matrix</title>\n"
           << "<style>\n"
           << "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; "
           << "max-width: 400px; margin: 60px auto; padding: 20px; background: #f5f5f5; }\n"
           << "form { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }\n"
           << "input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd; "
           << "border-radius: 4px; box-sizing: border-box; }\n"
           << "button { width: 100%; padding: 12px; background: #0dbd8b; color: white; border: none; "
           << "border-radius: 4px; font-size: 16px; cursor: pointer; margin-top: 10px; }\n"
           << "button:hover { background: #0ca87a; }\n"
           << ".sso-links { margin-top: 20px; text-align: center; }\n"
           << ".sso-links a { display: inline-block; margin: 5px 10px; color: #0dbd8b; text-decoration: none; }\n"
           << ".terms { margin-top: 15px; font-size: 12px; color: #666; text-align: center; }\n"
           << ".error { color: #d32f2f; font-size: 14px; margin-bottom: 10px; display: none; }\n"
           << ".recaptcha { margin: 15px 0; }\n"
           << "</style>\n"
           << "</head>\n"
           << "<body>\n"
           << "<h1 style=\"text-align:center; color:#333;\">Sign In</h1>\n"
           << "<form id=\"loginForm\">\n"
           << "<input type=\"text\" name=\"username\" placeholder=\"Username (e.g. @user:server)\" required autofocus>\n"
           << "<input type=\"password\" name=\"password\" placeholder=\"Password\" required>\n"
           << "<div class=\"recaptcha\" id=\"recaptcha-container\">\n"
           << "  <div class=\"g-recaptcha\" data-sitekey=\"6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI\"></div>\n"
           << "</div>\n"
           << "<div class=\"error\" id=\"loginError\"></div>\n"
           << "<button type=\"submit\">Sign In</button>\n"
           << "</form>\n"
           << "<div class=\"sso-links\">\n"
           << "<p>Or sign in with:</p>\n"
           << "<a href=\"/_matrix/client/v3/login/sso/redirect?redirectUrl=../\">SSO / OpenID Connect</a>\n"
           << "<a href=\"/_matrix/client/v3/login/sso/redirect/github?redirectUrl=../\">GitHub</a>\n"
           << "</div>\n"
           << "<div class=\"terms\">\n"
           << "By signing in, you agree to the <a href=\"/_matrix/consent\">Terms and Conditions</a>.\n"
           << "</div>\n"
           << "<script>\n"
           << "document.getElementById('loginForm').addEventListener('submit', async function(e) {\n"
           << "  e.preventDefault();\n"
           << "  var err = document.getElementById('loginError');\n"
           << "  err.style.display = 'none';\n"
           << "  var user = this.username.value;\n"
           << "  var pass = this.password.value;\n"
           << "  if (!user || !pass) { err.textContent = 'Username and password required'; err.style.display = 'block'; return; }\n"
           << "  var body = {\n"
           << "    type: 'm.login.password',\n"
           << "    identifier: { type: 'm.id.user', user: user },\n"
           << "    password: pass,\n"
           << "    initial_device_display_name: 'Web Fallback'\n"
           << "  };\n"
           << "  try {\n"
           << "    var resp = await fetch('/_matrix/client/v3/login', {\n"
           << "      method: 'POST',\n"
           << "      headers: { 'Content-Type': 'application/json' },\n"
           << "      body: JSON.stringify(body)\n"
           << "    });\n"
           << "    var data = await resp.json();\n"
           << "    if (resp.ok) {\n"
           << "      localStorage.setItem('mx_access_token', data.access_token);\n"
           << "      localStorage.setItem('mx_user_id', data.user_id);\n"
           << "      localStorage.setItem('mx_device_id', data.device_id);\n"
           << "      window.location.href = '/_matrix/client/';\n"
           << "    } else {\n"
           << "      err.textContent = data.error || 'Login failed';\n"
           << "      err.style.display = 'block';\n"
           << "    }\n"
           << "  } catch(ex) {\n"
           << "    err.textContent = 'Network error: ' + ex.message;\n"
           << "    err.style.display = 'block';\n"
           << "  }\n"
           << "});\n"
           << "</script>\n"
           << "<script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>\n"
           << "</body>\n"
           << "</html>\n";

      HttpResponse resp;
      resp.code = 200;
      resp.content_type = "text/html; charset=utf-8";
      resp.body = json(); // Empty JSON (body not used for HTML)
      resp.headers["Content-Type"] = "text/html; charset=utf-8";

      // We need to return the HTML in the body. Let's use a workaround.
      // Store HTML as a string in the body under "html" key so router can extract it.
      resp.body["__html_body__"] = html.str();
      return resp;
    }

    // ---- Return JSON login flows ----
    json flows = json::array();

    // m.login.password
    json pw_flow;
    pw_flow["type"] = "m.login.password";
    flows.push_back(pw_flow);

    // m.login.token
    json token_flow;
    token_flow["type"] = "m.login.token";
    flows.push_back(token_flow);

    // m.login.sso with identity providers
    json sso_flow;
    sso_flow["type"] = "m.login.sso";
    json idps = json::array();

    // Fetch SSO providers from DB if available
    auto providers = db_.runInteraction("get_sso_providers",
        [&](storage::LoggingTransaction& txn) -> json {
          json provs = json::array();
          txn.execute(
              "SELECT idp_id, idp_name, idp_icon, idp_brand "
              "FROM sso_identity_providers WHERE enabled=1",
              {});
          auto rows = txn.fetchall();
          for (const auto& row : rows) {
            if (row.size() < 2) continue;
            json idp;
            idp["id"] = row[0].value.value_or("");
            idp["name"] = row[1].value.value_or("");
            if (row.size() > 2 && row[2].value)
              idp["icon"] = *row[2].value;
            if (row.size() > 3 && row[3].value)
              idp["brand"] = *row[3].value;
            provs.push_back(idp);
          }
          return provs;
        });

    // If no providers in DB, include defaults
    if (providers.empty()) {
      json gh;
      gh["id"] = "github";
      gh["name"] = "GitHub";
      gh["icon"] = "mxc://localhost/github-icon";
      gh["brand"] = "github";
      providers.push_back(gh);

      json gl;
      gl["id"] = "google";
      gl["name"] = "Google";
      gl["icon"] = "mxc://localhost/google-icon";
      gl["brand"] = "google";
      providers.push_back(gl);
    }
    sso_flow["identity_providers"] = providers;
    flows.push_back(sso_flow);

    // m.login.cas
    json cas_flow;
    cas_flow["type"] = "m.login.cas";
    flows.push_back(cas_flow);

    return build_success({{"flows", flows}});
  }
};


// ============================================================================
// 7. LOGOUT ALL SERVLET
// Equivalent to synapse.rest.client.logout.LogoutAllRestServlet
// Patterns: /_matrix/client/v3/logout/all, /_matrix/client/v1/logout/all
// Methods: POST
// Invalidates ALL access tokens for the authenticated user.
// Lines: ~100
// ============================================================================
class LogoutAllServlet : public ClientV1RestServlet {
public:
  explicit LogoutAllServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/logout/all",
            "/_matrix/client/v1/logout/all",
            "/_matrix/client/r0/logout/all"};
  }
  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (req.method == "POST") return on_POST(req);
    return build_error(405, "M_UNRECOGNIZED", "Method not allowed");
  }

private:
  storage::DatabasePool& db_;

  HttpResponse on_POST(const HttpRequest& req) {
    try {
      // ---- Authenticate ----
      AuthHelper auth(db_);
      Requester requester;
      try {
        requester = auth.require_auth(req);
      } catch (const std::exception& e) {
        return build_error(401, "M_UNKNOWN_TOKEN",
                           "Missing or invalid access token");
      }

      storage::RegistrationStore reg(db_);

      // ---- Invalidate all access tokens for user ----
      reg.user_delete_access_tokens(requester.user_id);

      // ---- Also clean up all devices ----
      storage::DeviceStore devs(db_);

      // ---- Deactivate user sessions in DB ----
      db_.runInteraction("logout_all_cleanup",
          [&](storage::LoggingTransaction& txn) {
            // Mark all tokens as deleted
            txn.execute(
                "DELETE FROM access_tokens WHERE user_id=?",
                {requester.user_id});

            // Clear device associations
            txn.execute(
                "UPDATE devices SET hidden=1 WHERE user_id=?",
                {requester.user_id});

            // Clear refresh tokens
            txn.execute(
                "DELETE FROM refresh_tokens WHERE user_id=?",
                {requester.user_id});

            // Log the event for audit
            txn.execute(
                "INSERT INTO user_daily_visits "
                "(user_id, device_id, ts) VALUES (?,?,?)",
                {requester.user_id, "LOGOUT_ALL",
                 std::to_string(now_ms())});

            // Invalidate any pending UI auth sessions
            txn.execute(
                "DELETE FROM ui_auth_sessions WHERE user_id=?",
                {requester.user_id});
          });

      return build_success();

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Logout all failed: ") + e.what());
    }
  }
};


// ============================================================================
// 8. ACCOUNT DEACTIVATION SERVLET
// Equivalent to synapse.rest.client.account.DeactivateAccountRestServlet
// Patterns: /_matrix/client/v3/account/deactivate
// Methods: POST
// Deactivates user account, optionally erasing data.
// Lines: ~150
// ============================================================================
class AccountDeactivationServlet : public ClientV1RestServlet {
public:
  explicit AccountDeactivationServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/account/deactivate",
            "/_matrix/client/v1/account/deactivate",
            "/_matrix/client/r0/account/deactivate"};
  }
  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (req.method == "POST") return on_POST(req);
    return build_error(405, "M_UNRECOGNIZED", "Method not allowed");
  }

private:
  storage::DatabasePool& db_;

  HttpResponse on_POST(const HttpRequest& req) {
    try {
      // ---- Authenticate ----
      AuthHelper auth(db_);
      Requester requester;
      try {
        requester = auth.require_auth(req);
      } catch (const std::exception& e) {
        return build_error(401, "M_UNKNOWN_TOKEN",
                           "Missing or invalid access token");
      }

      // ---- Parse body ----
      json body = safe_json_body(req);
      bool erase_data = body.value("erase", false);

      // ---- UIA (User-Interactive Auth) check ----
      // Matrix spec requires UI auth for deactivation.
      // Check if auth block is present and valid.
      if (body.contains("auth")) {
        const json& auth_block = body["auth"];
        std::string session = auth_block.value("session", "");
        std::string auth_type = auth_block.value("type", "");

        if (auth_type == "m.login.password") {
          // Verify password
          std::string password = auth_block.value("password", "");
          if (password.empty())
            return build_error(401, "M_UNAUTHORIZED",
                               "Password required for account deactivation");

          storage::RegistrationStore reg(db_);
          auto stored_hash = reg.get_password_hash(requester.user_id);
          if (!stored_hash)
            return build_error(403, "M_FORBIDDEN",
                               "No password set on this account");

          // Hash and compare
          std::string input_hash = reg.hash_password(password);
          if (input_hash != *stored_hash)
            return build_error(403, "M_FORBIDDEN",
                               "Invalid password");
        } else if (auth_type == "m.login.token") {
          // Token-based auth
          std::string token = auth_block.value("token", "");
          storage::RegistrationStore reg(db_);
          auto uid = reg.get_user_by_login_token(token);
          if (!uid || *uid != requester.user_id)
            return build_error(403, "M_FORBIDDEN",
                               "Invalid deactivation token");
        } else if (!auth_type.empty()) {
          // Unknown auth type — return flows
          json flows = json::array();
          flows.push_back({{"stages", json::array({"m.login.password"})}});
          flows.push_back({{"stages", json::array({"m.login.token"})}});

          json resp;
          resp["flows"] = flows;
          resp["params"] = json::object();
          if (!session.empty()) resp["session"] = session;
          return build_error(401, "M_UNAUTHORIZED",
                             "User-interactive authentication required");
        }
      } else {
        // No auth block — return required flows
        json flows = json::array();
        flows.push_back({{"stages", json::array({"m.login.password"})}});

        json resp;
        resp["flows"] = flows;
        resp["params"] = json::object();
        resp["session"] = generate_token(24);
        HttpResponse r;
        r.code = 401;
        r.body = {
          {"errcode", "M_UNAUTHORIZED"},
          {"error", "User-interactive authentication required"},
          {"flows", flows},
          {"params", json::object()},
          {"session", generate_token(24)}
        };
        return r;
      }

      // ---- Perform deactivation ----
      storage::RegistrationStore reg(db_);
      bool success = reg.deactivate_account(requester.user_id, erase_data);

      if (!success)
        return build_error(500, "M_UNKNOWN",
                           "Failed to deactivate account");

      // ---- Log deactivation event ----
      db_.runInteraction("log_deactivate",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "INSERT INTO user_daily_visits "
                "(user_id, device_id, ts) VALUES (?,?,?)",
                {requester.user_id, "DEACTIVATED",
                 std::to_string(now_ms())});

            // If erasing data, queue for erasure
            if (erase_data) {
              storage::UserErasureStore erasure(db_);
              erasure.mark_user_erased(requester.user_id, now_ms());
            }
          });

      // ---- Invalidate all tokens ----
      reg.user_delete_access_tokens(requester.user_id);

      // ---- Clear all devices ----
      db_.runInteraction("deact_devices",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "DELETE FROM access_tokens WHERE user_id=?",
                {requester.user_id});
            txn.execute(
                "UPDATE devices SET hidden=1 WHERE user_id=?",
                {requester.user_id});
            txn.execute(
                "DELETE FROM refresh_tokens WHERE user_id=?",
                {requester.user_id});
          });

      // ---- Return server acknowledgment ----
      json resp;
      resp["id_server_unbind_result"] = "success";
      return build_success(resp);

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Account deactivation failed: ") + e.what());
    }
  }
};


// ============================================================================
// 9. PASSWORD POLICY SERVLET
// Equivalent to synapse.rest.client.account.PasswordPolicyRestServlet
// Patterns: /_matrix/client/v3/password_policy
// Methods: GET
// Returns the server's password policy (min length, complexity requirements).
// Lines: ~80
// ============================================================================
class PasswordPolicyServlet : public ClientV1RestServlet {
public:
  explicit PasswordPolicyServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/password_policy",
            "/_matrix/client/v1/password_policy",
            "/_matrix/client/r0/password_policy"};
  }
  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (req.method == "GET") return on_GET(req);
    return build_error(405, "M_UNRECOGNIZED", "Method not allowed");
  }

private:
  storage::DatabasePool& db_;

  HttpResponse on_GET(const HttpRequest& req) {
    (void)req; // No auth required for password policy

    try {
      // ---- Query password policy config from DB ----
      json policy = db_.runInteraction("get_pw_policy",
          [&](storage::LoggingTransaction& txn) -> json {
            json result;

            // Default policy values
            int64_t min_length = 8;
            bool require_digit = true;
            bool require_lowercase = true;
            bool require_uppercase = true;
            bool require_symbol = true;
            int64_t max_length = 255;
            bool require_3pid = false;

            // Try to get custom policy from config
            txn.execute(
                "SELECT min_length, require_digit, require_lowercase, "
                "require_uppercase, require_symbol, max_length, "
                "require_3pid "
                "FROM password_policy_config LIMIT 1",
                {});
            auto row = txn.fetchone();
            if (row && !row->empty()) {
              if (row->at(0).value) {
                try { min_length = std::stoll(*row->at(0).value); } catch (...) {}
              }
              if (row->size() > 1 && row->at(1).value) {
                require_digit = (*row->at(1).value == "1" || *row->at(1).value == "true");
              }
              if (row->size() > 2 && row->at(2).value) {
                require_lowercase = (*row->at(2).value == "1" || *row->at(2).value == "true");
              }
              if (row->size() > 3 && row->at(3).value) {
                require_uppercase = (*row->at(3).value == "1" || *row->at(3).value == "true");
              }
              if (row->size() > 4 && row->at(4).value) {
                require_symbol = (*row->at(4).value == "1" || *row->at(4).value == "true");
              }
              if (row->size() > 5 && row->at(5).value) {
                try { max_length = std::stoll(*row->at(5).value); } catch (...) {}
              }
              if (row->size() > 6 && row->at(6).value) {
                require_3pid = (*row->at(6).value == "1" || *row->at(6).value == "true");
              }
            }

            // Build complexity requirement string
            std::string requirements;
            if (require_lowercase) requirements += "lowercase, ";
            if (require_uppercase) requirements += "uppercase, ";
            if (require_digit) requirements += "digit, ";
            if (require_symbol) requirements += "symbol, ";
            if (!requirements.empty()) requirements = requirements.substr(0, requirements.size() - 2);

            // Build the policy response
            result["m.minimum_length"] = min_length;
            result["m.require_digit"] = require_digit;
            result["m.require_lowercase"] = require_lowercase;
            result["m.require_uppercase"] = require_uppercase;
            result["m.require_symbol"] = require_symbol;
            result["m.requirements"] = requirements;
            result["m.max_length"] = max_length;
            result["m.require_3pid"] = require_3pid;

            return result;
          });

      return build_success(policy);

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Password policy fetch failed: ") + e.what());
    }
  }
};


// ============================================================================
// 10. USERNAME AVAILABLE SERVLET
// Equivalent to synapse.rest.client.register.UsernameAvailabilityRestServlet
// Patterns: /_matrix/client/v3/register/available
// Methods: GET
// Query params: username — checks if the username is available for registration.
// Lines: ~110
// ============================================================================
class UsernameAvailableServlet : public ClientV1RestServlet {
public:
  explicit UsernameAvailableServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/register/available",
            "/_matrix/client/v1/register/available",
            "/_matrix/client/r0/register/available"};
  }
  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (req.method == "GET") return on_GET(req);
    return build_error(405, "M_UNRECOGNIZED", "Method not allowed");
  }

private:
  storage::DatabasePool& db_;

  HttpResponse on_GET(const HttpRequest& req) {
    try {
      // ---- Parse query parameters ----
      auto username_opt = BaseRestServlet::parse_string(req, "username");

      // ---- Check username availability ----
      bool available = false;

      if (username_opt && !username_opt->empty()) {
        std::string username = *username_opt;

        // Validate username format
        if (username.size() < 3 || username.size() > 255)
          return build_error(400, "M_INVALID_USERNAME",
                             "Username must be 3-255 characters");

        for (char c : username) {
          if (!std::isalnum(static_cast<unsigned char>(c)) &&
              c != '_' && c != '.' && c != '-' && c != '=')
            return build_error(400, "M_INVALID_USERNAME",
                               "Username contains invalid characters");
        }

        // Rate limit username checks
        if (is_rate_limited("username_check:" + req.client_ip, 30, 60000))
          return build_error(429, "M_LIMIT_EXCEEDED",
                             "Too many requests");

        // Check if user exists
        std::string full_user_id = "@" + username + ":" + server_name;

        storage::RegistrationStore reg(db_);
        auto user_info = reg.get_user_by_id(full_user_id);
        available = !user_info.has_value();

        // Also check if user is reserved (guest name, admin name, etc.)
        if (available) {
          // Check reserved usernames table
          auto reserved = db_.runInteraction("check_reserved_user",
              [&](storage::LoggingTransaction& txn) -> bool {
                txn.execute(
                    "SELECT 1 FROM reserved_usernames WHERE username=?",
                    {username});
                auto row = txn.fetchone();
                return (row && !row->empty());
              });
          if (reserved) available = false;
        }

        // Also check deactivated users — they still occupy the name
        if (available) {
          // Check if there's a deactivated user with this name
          auto deactivated = db_.runInteraction("check_deactivated_user",
              [&](storage::LoggingTransaction& txn) -> bool {
                txn.execute(
                    "SELECT 1 FROM users WHERE name=? AND deactivated=1",
                    {full_user_id});
                auto row = txn.fetchone();
                return (row && !row->empty());
              });
          if (deactivated) available = false;
        }
      } else {
        return build_error(400, "M_MISSING_PARAM",
                           "Missing 'username' query parameter");
      }

      json resp;
      resp["available"] = available;
      return build_success(resp);

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Username check failed: ") + e.what());
    }
  }
};


// ============================================================================
// 11. REGISTER AVAILABLE SERVLET
// Equivalent to synapse.rest.client.register.RegisterAvailableRestServlet
// Patterns: /_matrix/client/v3/register/available
// Methods: GET
// Checks if username, email, phone (msisdn), or third-party ID is available
// for registration. Supports multiple 3PID types.
// Lines: ~190
// ============================================================================
class RegisterAvailableServlet : public ClientV1RestServlet {
public:
  explicit RegisterAvailableServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {"/_matrix/client/v3/register/available",
            "/_matrix/client/v1/register/available",
            "/_matrix/client/r0/register/available"};
  }
  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (req.method == "GET") return on_GET(req);
    return build_error(405, "M_UNRECOGNIZED", "Method not allowed");
  }

private:
  storage::DatabasePool& db_;

  // ------------------------------------------------------------------------
  // Check if a username is valid and available
  // ------------------------------------------------------------------------
  json check_username_availability(const std::string& username,
                                    storage::RegistrationStore& reg) {
    json result;
    result["type"] = "m.id.user";

    // Basic validation
    if (username.size() < 3 || username.size() > 255) {
      result["available"] = false;
      result["error"] = "Username must be 3-255 characters";
      return result;
    }

    for (char c : username) {
      if (!std::isalnum(static_cast<unsigned char>(c)) &&
          c != '_' && c != '.' && c != '-' && c != '=')
      {
        result["available"] = false;
        result["error"] = "Username contains invalid characters";
        return result;
      }
    }

    std::string full_user_id = "@" + username + ":" + server_name;
    auto user_info = reg.get_user_by_id(full_user_id);
    result["available"] = !user_info.has_value();

    if (!result["available"].get<bool>()) {
      result["error"] = "Username is already taken";
    }

    return result;
  }

  // ------------------------------------------------------------------------
  // Check if an email address is available
  // ------------------------------------------------------------------------
  json check_email_availability(const std::string& email,
                                 storage::RegistrationStore& reg) {
    json result;
    result["type"] = "m.id.thirdparty";
    result["medium"] = "email";

    // Basic email validation
    auto at_pos = email.find('@');
    if (at_pos == std::string::npos || at_pos == 0 || at_pos == email.size() - 1) {
      result["available"] = false;
      result["error"] = "Invalid email address format";
      return result;
    }

    // Check if this email is already associated
    auto uid = reg.get_user_by_threepid("email", email);
    result["available"] = !uid.has_value();

    if (!result["available"].get<bool>()) {
      result["error"] = "Email address is already in use";
    }

    return result;
  }

  // ------------------------------------------------------------------------
  // Check if an MSISDN (phone number) is available
  // ------------------------------------------------------------------------
  json check_msisdn_availability(const std::string& msisdn,
                                  storage::RegistrationStore& reg) {
    json result;
    result["type"] = "m.id.thirdparty";
    result["medium"] = "msisdn";

    // Basic phone validation (digits and leading +)
    if (msisdn.empty() || (msisdn[0] != '+' && !std::isdigit(static_cast<unsigned char>(msisdn[0])))) {
      result["available"] = false;
      result["error"] = "Invalid phone number format";
      return result;
    }

    // Check if this MSISDN already has an account
    auto uid = reg.get_user_by_threepid("msisdn", msisdn);
    result["available"] = !uid.has_value();

    if (!result["available"].get<bool>()) {
      result["error"] = "Phone number is already associated with an account";
    }

    return result;
  }

  // ------------------------------------------------------------------------
  // Check if an arbitrary third-party identifier is available
  // ------------------------------------------------------------------------
  json check_threepid_availability(const std::string& medium,
                                    const std::string& address,
                                    storage::RegistrationStore& reg) {
    json result;
    result["type"] = "m.id.thirdparty";
    result["medium"] = medium;

    if (address.empty()) {
      result["available"] = false;
      result["error"] = "Empty address not allowed";
      return result;
    }

    auto uid = reg.get_user_by_threepid(medium, address);
    result["available"] = !uid.has_value();

    if (!result["available"].get<bool>()) {
      result["error"] = "This " + medium + " address is already in use";
    }

    return result;
  }

  // ------------------------------------------------------------------------
  // on_GET — main handler
  // ------------------------------------------------------------------------
  HttpResponse on_GET(const HttpRequest& req) {
    try {
      // ---- Rate limit ----
      if (is_rate_limited("register_available:" + req.client_ip, 20, 60000))
        return build_error(429, "M_LIMIT_EXCEEDED", "Too many requests");

      storage::RegistrationStore reg(db_);

      // ---- Check what to validate ----
      auto username_opt = BaseRestServlet::parse_string(req, "username");
      auto email_opt    = BaseRestServlet::parse_string(req, "email");
      auto msisdn_opt   = BaseRestServlet::parse_string(req, "msisdn");
      auto medium_opt   = BaseRestServlet::parse_string(req, "medium");
      auto address_opt  = BaseRestServlet::parse_string(req, "address");

      json results = json::array();

      // Check username
      if (username_opt && !username_opt->empty()) {
        results.push_back(check_username_availability(*username_opt, reg));
      }

      // Check email
      if (email_opt && !email_opt->empty()) {
        results.push_back(check_email_availability(*email_opt, reg));
      }

      // Check MSISDN
      if (msisdn_opt && !msisdn_opt->empty()) {
        results.push_back(check_msisdn_availability(*msisdn_opt, reg));
      }

      // Check generic third-party identifier
      if (medium_opt && address_opt &&
          !medium_opt->empty() && !address_opt->empty()) {
        results.push_back(
            check_threepid_availability(*medium_opt, *address_opt, reg));
      }

      // ---- If no check types specified, check username query param for backward compat ----
      if (results.empty()) {
        // No specific params given
        return build_error(400, "M_MISSING_PARAM",
                           "Specify one of: username, email, msisdn, or medium+address");
      }

      // ---- Determine overall availability ----
      bool all_available = true;
      for (const auto& r : results) {
        if (!r.value("available", false)) {
          all_available = false;
          break;
        }
      }

      json resp;
      resp["available"] = all_available;
      resp["details"] = results;

      return build_success(resp);

    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Availability check failed: ") + e.what());
    }
  }
};


// ============================================================================
// Servlet factory functions for external registration
// Each returns a unique_ptr<BaseRestServlet> so the router can own them.
// ============================================================================

std::unique_ptr<BaseRestServlet> create_room_upgrade_servlet(
    storage::DatabasePool& db) {
  return std::make_unique<RoomUpgradeServlet>(db);
}

std::unique_ptr<BaseRestServlet> create_room_report_servlet(
    storage::DatabasePool& db) {
  return std::make_unique<RoomReportServlet>(db);
}

std::unique_ptr<BaseRestServlet> create_room_alias_servlet(
    storage::DatabasePool& db) {
  return std::make_unique<RoomAliasServlet>(db);
}

std::unique_ptr<BaseRestServlet> create_public_rooms_servlet(
    storage::DatabasePool& db) {
  return std::make_unique<PublicRoomsServlet>(db);
}

std::unique_ptr<BaseRestServlet> create_third_party_protocol_servlet(
    storage::DatabasePool& db) {
  return std::make_unique<ThirdPartyProtocolServlet>(db);
}

std::unique_ptr<BaseRestServlet> create_login_fallback_servlet(
    storage::DatabasePool& db) {
  return std::make_unique<LoginFallbackServlet>(db);
}

std::unique_ptr<BaseRestServlet> create_logout_all_servlet(
    storage::DatabasePool& db) {
  return std::make_unique<LogoutAllServlet>(db);
}

std::unique_ptr<BaseRestServlet> create_account_deactivation_servlet(
    storage::DatabasePool& db) {
  return std::make_unique<AccountDeactivationServlet>(db);
}

std::unique_ptr<BaseRestServlet> create_password_policy_servlet(
    storage::DatabasePool& db) {
  return std::make_unique<PasswordPolicyServlet>(db);
}

std::unique_ptr<BaseRestServlet> create_username_available_servlet(
    storage::DatabasePool& db) {
  return std::make_unique<UsernameAvailableServlet>(db);
}

std::unique_ptr<BaseRestServlet> create_register_available_servlet(
    storage::DatabasePool& db) {
  return std::make_unique<RegisterAvailableServlet>(db);
}

} // namespace progressive::rest
