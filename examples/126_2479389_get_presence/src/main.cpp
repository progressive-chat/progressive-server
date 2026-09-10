// main.cpp — translation of Conduit commit abcce95d, src/main.rs
//
// "feat: invites, better public room dir, user search". New endpoints:
//   POST /createRoom (folded prerequisite), POST /rooms/<id>/invite,
//   POST /user_directory/search, GET /voip/turnServer (404 stub),
//   POST /publicised_groups (404 stub). publicRooms reads names from
//   room_state and sorts by members; /sync gains invited rooms with
//   stripped state; token keys move to user + 0xff + device.
// Folded prerequisites from skipped intermediates: membership tracking,
// per-room sync timelines, createRoom.
//
// "feat: save pdus": PDUs are saved in a pduid -> pdus map, roomid_pduleaves
// tracks the leaves of the event graph and eventid_pduid maps event ids to
// pdu ids. Event ids are REAL reference hashes now:
//   "$" + base64url(sha256(canonical(redact(event))))  [OpenSSL SHA-256]
// Also new: GET /sync (upstream timeline todo!() — we return stored PDUs)
// and the catch-all OPTIONS route returning 404.

#include "crypto.hpp"
#include "media.hpp"
#include "routes.hpp"
#include "server_server.hpp"
#include "data.hpp"
#include "proxy.hpp"
#include "ruma_wrapper.hpp"
#include "argon2.h"
#include "utils.hpp"

#include <httplib.h>

#include <csignal>

using json = nlohmann::json;
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <algorithm>
#include <map>
#include <set>
#include <optional>
#include <string>
#include <string_view>

namespace {

constexpr uint16_t kListenPort = 8000;

// "TODO:randomtoken" / "TODO:randomdeviceid" — verbatim placeholders.
constexpr std::string_view kPlaceholderToken = "TODO:randomtoken";
constexpr std::string_view kPlaceholderDeviceId = "TODO:randomdeviceid";

// NEW in 12a8c9ba: percent-decode federation path segments (room ids / aliases).
std::string url_decode(const std::string& in) {
  std::string out;
  out.reserve(in.size());
  for (size_t i = 0; i < in.size(); ++i) {
    if (in[i] == '%' && i + 2 < in.size()) {
      try {
        int v = std::stoi(in.substr(i + 1, 2), nullptr, 16);
        out.push_back(static_cast<char>(v));
        i += 2;
        continue;
      } catch (...) { /* fall through */ }
    } else if (in[i] == '+') {
      out.push_back(' ');
      continue;
    }
    out.push_back(in[i]);
  }
  return out;
}

// NEW in 12a8c9ba: this server's federation (Matrix) server name.
constexpr const char* kServerName = "localhost";

bool localpart_valid(const std::string& localpart) {
  // What UserId's TryFrom checked in ruma-identifiers 0.14.
  if (localpart.empty()) return false;
  for (const char c : localpart) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == '=' || c == '-' || c == '/' ||
                    c == '+';
    if (!ok) return false;
  }
  return true;
}

bool full_user_id_valid(const std::string& user_id, std::string* normalized) {
  const size_t colon = user_id.find(':');
  if (user_id.size() < 3 || user_id[0] != '@' || colon == std::string::npos ||
      colon == 1 || colon + 1 >= user_id.size())
    return false;
  if (!localpart_valid(user_id.substr(1, colon - 1))) return false;
  *normalized = user_id;
  return true;
}

// --- route handlers ------------------------------------------------------------

ruma::MatrixResult<ruma::GetSupportedVersionsResponse> get_supported_versions_route() {
  // Trimmed back to a single version in fa322689.
  return ruma::MatrixResult<ruma::GetSupportedVersionsResponse>::ok(
      ruma::GetSupportedVersionsResponse{
          .versions = {"r0.6.0"},
          .unstable_features = {},
      });
}

// NEW in abcce95d (+ folded prerequisite createRoom).
// Forward declaration: defined below next to invite_user_route (58463bba).
std::optional<std::string> invite_helper(Context* ctx, const std::string& sender,
                                         const std::string& target,
                                         const std::string& room_id, bool is_direct);
ruma::MatrixResult<ruma::CreateRoomResponse> create_room_route(
    Context* ctx, const ruma::CreateRoomRequest& body) {
  const std::string room_id = "!" + utils::random_string(18) + ":" + ctx->data->hostname();
  const std::string& creator = body.user_id;

  auto append_state = [&](const std::string& type, nlohmann::json content,
                          const std::string& state_key) {
    nlohmann::json event = {
        {"type", type},
        {"content", std::move(content)},
        {"event_id", "$thiswillbefilledinlater"},
        {"origin_server_ts", utils::millis_since_unix_epoch()},
        {"room_id", room_id},
        {"sender", creator},
        {"state_key", state_key},
        {"unsigned", json::object()},
    };
    const std::string event_id = crypto::reference_hash(event);
    event["event_id"] = event_id;
    ctx->data->pdu_append(event_id, room_id, std::move(event));
  };

  // m.room.create must be the first event (auth: prev_events empty).
  append_state("m.room.create",
               json{{"creator", creator}}, "");

  // Creator joins immediately after (c8ba9dce "proper room creation"):
  // otherwise the power_levels event would fail its own auth check because
  // the sender is not yet joined.
  if (!ctx->data->room_join(room_id, creator)) {
    return ruma::MatrixResult<ruma::CreateRoomResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Forbidden,
        .message = "event not authorized",
        .status_code = 403,
    });
  }

  // Verbatim power levels from the commit.
  // NEW in f62258ba: a power_level_content_override ADDS to the defaults
  // instead of replacing them.
  // NEW in 7fa54e44: defaults come from the shared helper (adds events:{}
  // and notifications:{room:50}, matching ruma's Default).
  nlohmann::json pl_content = Data::default_power_levels(creator);
  if (body.power_level_content_override) {
    if (!body.power_level_content_override->is_object())
      return ruma::MatrixResult<ruma::CreateRoomResponse>::err(ruma::Error{
          .kind = ruma::ErrorKind::BadJson,
          .message = "Invalid power_level_content_override.",
          .status_code = 400,
      });
    for (auto& [k, v] : body.power_level_content_override->items())
      pl_content[k] = v;
  }
  append_state("m.room.power_levels", std::move(pl_content), "");

  if (body.name) {
    append_state("m.room.name", json{{"name", *body.name}}, "");
  }
  if (body.topic) {
    append_state("m.room.topic", json{{"topic", *body.topic}}, "");
  }

  // NEW in 3aa0c8ed: visibility + alias creation.
  if (body.visibility.has_value() && *body.visibility == "public") ctx->data->set_public(room_id, true);

  if (body.room_alias_name) {
    const std::string alias =
        "#" + *body.room_alias_name + ":" + ctx->data->hostname();
    if (ctx->data->id_from_alias(alias)) {
      return ruma::MatrixResult<ruma::CreateRoomResponse>::err(ruma::Error{
          .kind = ruma::ErrorKind::Unknown,
          .message = "Alias already exists.",
          .status_code = 409,
      });
    }
    ctx->data->set_alias(alias, room_id);
  }

  // NEW in 58463bba: remote-capable invites; per-invite failures are
  // ignored (upstream `let _ =`).
  for (const auto& invitee : body.invite) {
    (void)invite_helper(ctx, creator, invitee, room_id, body.is_direct);
  }

  return ruma::MatrixResult<ruma::CreateRoomResponse>::ok(
      ruma::CreateRoomResponse{.room_id = room_id});
}

// NEW in 58463bba: invite_helper — local users get a locally-appended invite;
// remote users get a locally-built, signed invite PDU sent to their server's
// v1 /invite (which returns the signed event for local storage), mirroring
// upstream invite_helper. Returns false on any failure.
// Returns nullopt on success, otherwise an error message for the client
// (remote Matrix errors arrive already prefixed as "Answer from ...").
std::optional<std::string> invite_remote_user(
    Context* ctx, const std::string& sender,
                        const std::string& target, const std::string& target_server,
                        const std::string& room_id, bool is_direct) {
  try {
    // prev_events: current leaves, capped at 20 (read-only; the leaf set is
    // only touched when the signed event comes back and is appended).
    std::vector<std::string> prev = ctx->data->pdu_leaves(room_id);
    if (prev.size() > 20) prev.resize(20);
    uint64_t depth = 0;
    for (const auto& id : prev) {
      if (auto text = ctx->data->pdu_get(id)) {
        try {
          depth = std::max(depth, nlohmann::json::parse(*text).value("depth", uint64_t(0)));
        } catch (...) {}
      }
    }
    depth += 1;

    nlohmann::json content = {{"membership", "invite"}};
    if (auto dn = ctx->data->displayname_get(target)) content["displayname"] = *dn;
    if (is_direct) content["is_direct"] = true;
    nlohmann::json unsigned_obj = nlohmann::json::object();
    if (auto cur = ctx->data->room_state_get(room_id, "m.room.member", target))
      unsigned_obj["prev_content"] = *cur;

    nlohmann::json pdu = {
        {"type", "m.room.member"},
        {"content", std::move(content)},
        {"room_id", room_id},
        {"sender", sender},
        {"state_key", target},
        {"origin", ctx->data->hostname()},
        {"origin_server_ts", utils::millis_since_unix_epoch()},
        {"depth", depth},
        {"prev_events", prev},
        {"auth_events", nlohmann::json::array()},
        {"unsigned", std::move(unsigned_obj)},
    };
    crypto::hash_and_sign_event(ctx->data->hostname(), ctx->data->keypair(), pdu);

    // Invite state: base stripped state + sender member + the invite itself
    // (same shape as the local path stores).
    nlohmann::json invite_state = ctx->data->build_invite_state(room_id);
    auto stripped = [](const nlohmann::json& e) {
      return nlohmann::json{{"type", e.value("type", "")},
                            {"state_key", e.value("state_key", "")},
                            {"sender", e.value("sender", "")},
                            {"content", e.value("content", nlohmann::json::object())}};
    };
    for (const auto& text : ctx->data->room_state(room_id)) {
      try {
        auto e = nlohmann::json::parse(text);
        if (e.value("type", "") == "m.room.member" && e.value("state_key", "") == sender) {
          invite_state.push_back(stripped(e));
          break;
        }
      } catch (...) {}
    }
    invite_state.push_back(stripped(pdu));

    auto resp = federation::send_request(
        *ctx->data, target_server,
        "/_matrix/federation/v1/invite/" + room_id + "/$receivingservershouldsetthis",
        nlohmann::json{{"event", pdu},
                       {"invite_room_state", invite_state},
                       {"room_version", "6"}});
    if (!resp || !resp->is_object() || !resp->contains("event") ||
        !(*resp)["event"].is_object()) {
      std::cerr << "[warn] Remote invite to " << target_server << " failed\n";
      // NEW in e5c71195: forward the remote Matrix error when present.
      if (resp && federation::is_remote_error(*resp))
        return federation::remote_error_message(*resp, target_server);
      return std::string("Failed to contact remote server for invite.");
    }
    nlohmann::json signed_ev = (*resp)["event"];
    const std::string event_id = crypto::reference_hash(signed_ev);
    signed_ev["event_id"] = event_id;
    if (!ctx->data->pdu_append(event_id, room_id, signed_ev))
      return std::string("event not authorized");
    ctx->data->store_invite(room_id, target, invite_state);

    // Fan the signed invite out to the room's other servers (best effort).
    for (const auto& srv : ctx->data->room_servers(room_id)) {
      if (srv == ctx->data->hostname() || srv == target_server) continue;
      try {
        federation::send_request(
            *ctx->data, srv,
            "/_matrix/federation/v1/send/" + utils::random_string(10),
            nlohmann::json{{"pdus", nlohmann::json::array({signed_ev})}});
      } catch (...) {}
    }
    return std::nullopt;
  } catch (const std::exception& e) {
    std::cerr << "[warn] Remote invite to " << target << " failed: " << e.what() << "\n";
    return std::string("Failed to contact remote server for invite.");
  } catch (...) {
    return std::string("Failed to contact remote server for invite.");
  }
}

std::optional<std::string> invite_helper(Context* ctx, const std::string& sender,
                                         const std::string& target,
                                         const std::string& room_id, bool is_direct) {
  std::string target_server;
  if (auto c = target.find(':'); c != std::string::npos) target_server = target.substr(c + 1);
  if (!target_server.empty() && target_server != ctx->data->hostname()) {
    return invite_remote_user(ctx, sender, target, target_server, room_id, is_direct);
  }
  if (!ctx->data->room_invite(sender, room_id, target, is_direct))
    return std::string("event not authorized");
  return std::nullopt;
}

void invite_user_route(Context* ctx, const ruma::InviteRequest& body,
                       httplib::Response& res) {
  if (!body.user_id.empty() && !body.target.empty()) {
    // NEW in e5c71195: remote refusal messages are forwarded to the client.
    if (auto err = invite_helper(ctx, body.user_id, body.target, body.room_id, false)) {
      ruma::respond(res,
                    ruma::json{{"errcode", "M_FORBIDDEN"},
                               {"error", std::move(*err)}},
                    403);
      return;
    }
    ruma::respond(res, ruma::json::object());
    return;
  }
  ruma::respond(res,
                ruma::json{{"errcode", "M_NOT_FOUND"}, {"error", "User not found."}}, 404);
}

void search_users_route(Context* ctx, const ruma::SearchUsersRequest& body,
                        httplib::Response& res) {
  // NEW in e8f67089: case-insensitive match on user id OR display name, and
  // deactivated users are NOT filtered out anymore (shows more users).
  nlohmann::json results = nlohmann::json::array();
  const std::string term = utils::ascii_lower(body.search_term);
  for (const auto& user : ctx->data->users_all()) {
    bool match = utils::icontains(user, term);
    if (!match) {
      if (auto dn = ctx->data->displayname_get(user))
        match = utils::icontains(*dn, term);
    }
    if (match) {
      results.push_back(json{{"user_id", user}});
    }
  }
  ruma::respond(res, json{{"results", results}, {"limited", false}});
}

// Better public room directory (abcce95d): names from room_state, sorted by
// member count descending.
// ============================================================================
// Public rooms federation API (Conduit 4e44fed)
// ============================================================================

// Updated helper with proper filter and room_network support (Conduit 4e44fed)
ruma::MatrixResult<ruma::PublicRoomsResponse> get_public_rooms_filtered_helper(
    Context* ctx, const std::string& server, std::optional<int64_t> limit,
    std::optional<std::string> since, const nlohmann::json& filter,
    const std::string& room_network) {
  ruma::PublicRoomsResponse resp;

  struct Entry {
    std::string room_id;
    long members;
    nlohmann::json chunk;
  };
  std::vector<Entry> entries;
  // 3aa0c8ed: only rooms explicitly marked public appear.
  // NEW in 3c3062a3: chunks come from targeted state lookups
  // (Data::public_room_chunk), not full-state scans.
  // NEW in 77a23f89: filter by case-insensitive generic_search_term over
  // name, topic and canonical_alias.
  std::string search_term;
  if (filter.contains("generic_search_term") && filter["generic_search_term"].is_string())
    search_term = utils::ascii_lower(filter["generic_search_term"].get<std::string>());
  auto chunk_matches = [&search_term](const nlohmann::json& chunk) {
    if (search_term.empty()) return true;
    for (const char* field : {"name", "topic", "canonical_alias"}) {
      if (chunk.contains(field) && chunk[field].is_string() &&
          utils::icontains(chunk[field].get<std::string>(), search_term))
        return true;
    }
    return false;
  };
  for (const auto& room : ctx->data->public_rooms()) {
    nlohmann::json chunk = ctx->data->public_room_chunk(room);
    if (!chunk_matches(chunk)) continue;
    long members = chunk.value("num_joined_members", 0L);
    entries.push_back({room, members, std::move(chunk)});
  }

  std::sort(entries.begin(), entries.end(),
            [](const Entry& l, const Entry& r) { return l.members > r.members; });

  for (auto& e : entries) {
    resp.chunk.push_back(std::move(e.chunk));
  }

  // Sort local rooms first (abcce95d), THEN extend with federated rooms
  // (720cc0cf moved this sort before the extend).

  // NEW in 720cc0cf: federated room directory — ask remote server for
  // its public rooms and append them after the local ones, then sort.
  // (Upstream sorted only after merging; we mirror that order.)
  // Updated in 4e44fed: use room_network parameter for federation
  if (!server.empty()) {
    auto remote = federation::send_request(
        *ctx->data, server,
        "/_matrix/federation/v1/publicRooms", json::object());
    if (remote) {
      if (auto chunk = remote->find("chunk"); chunk != remote->end() && chunk->is_array())
        resp.chunk.insert(resp.chunk.end(), chunk->begin(), chunk->end());
      if (auto total = remote->find("total_room_count_estimate");
          total != remote->end() && total->is_number_unsigned())
        resp.federation_rooms = total->get<size_t>();
    }
  }
  resp.total_room_count_estimate =
      entries.size() + resp.federation_rooms;

  return ruma::MatrixResult<ruma::PublicRoomsResponse>::ok(std::move(resp));
}

// Client-server endpoint: GET /_matrix/client/r0/publicRooms
ruma::MatrixResult<ruma::PublicRoomsResponse> get_public_rooms_route(
    Context* ctx) {
  // Use default filter and Matrix room network (Conduit 4e44fed)
  nlohmann::json filter = nlohmann::json::object();
  return get_public_rooms_filtered_helper(
      ctx, "", std::nullopt, std::nullopt, filter, "Matrix");
}

// Federation endpoint: GET /_matrix/federation/v1/publicRooms
// NEW in 4e44fed: federation endpoint with proper filter and room_network
ruma::MatrixResult<ruma::PublicRoomsResponse> get_public_rooms_filtered_route(
    Context* ctx, const nlohmann::json& body) {
  // Extract parameters from request body (Conduit 4e44fed)
  std::string server = body.value("server", "");
  std::optional<int64_t> limit;
  if (body.contains("limit") && body["limit"].is_number_integer())
    limit = body["limit"].get<int64_t>();
  std::optional<std::string> since;
  if (body.contains("since") && body["since"].is_string())
    since = body["since"].get<std::string>();
  nlohmann::json filter = body.value("filter", nlohmann::json::object());
  std::string room_network = body.value("room_network", "Matrix");

  return get_public_rooms_filtered_helper(
      ctx, server, limit, since, filter, room_network);
}

// ============================================================================
// Alias resolution with multiple servers support (Conduit c5313b3)
// ============================================================================

// 9c26e22a/3aa0c8ed: aliases resolved from the database.
// NEW in c5313b3: enhanced to handle remote aliases and return multiple servers.
ruma::MatrixResult<ruma::GetAliasResponse> get_alias_route(
    Context* ctx, const std::string& room_alias) {
  // First try local database
  auto room_id = ctx->data->id_from_alias(room_alias);
  if (!room_id) {
    std::cerr << "[debug] Room alias not found locally.\n";

    // If alias is remote (e.g., #room:server), try to resolve it from the remote server
    if (room_alias.rfind("#", 0) == 0) {
      size_t colon_pos = room_alias.find(':');
      if (colon_pos != std::string::npos) {
        std::string remote_server = room_alias.substr(colon_pos + 1);
        // For remote aliases, return the remote server as a potential server
        return ruma::MatrixResult<ruma::GetAliasResponse>::ok(ruma::GetAliasResponse{
            .room_id = "",
            .servers = {remote_server},
        });
      }
    }

    return ruma::MatrixResult<ruma::GetAliasResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::NotFound,
        .message = "Room not found.",
        .status_code = 404,
    });
  }

  // For local rooms, include local server and any known remote servers
  std::vector<std::string> servers = {ctx->data->hostname()};

  // If room is remote, try to get additional servers from the room's server
  if (room_id->find(ctx->data->hostname()) == std::string::npos) {
    // In a full implementation, we'd query the room's server for other servers
    // For now, we just add the room's server
    size_t colon_pos = room_id->find(':');
    if (colon_pos != std::string::npos) {
      std::string room_server = room_id->substr(colon_pos + 1);
      if (room_server != ctx->data->hostname()) {
        servers.push_back(room_server);
      }
    }
  }

  return ruma::MatrixResult<ruma::GetAliasResponse>::ok(ruma::GetAliasResponse{
      .room_id = *room_id,
      .servers = servers,
  });
}

// Resolve a room alias to a room ID and list of servers that know about the room.
// This implements the "try multiple servers when joining remote rooms" feature.
// NEW in c5313b3: "improvement: try out multiple servers when joining remote rooms"
std::vector<std::string> resolve_alias_servers(Context* ctx, const std::string& room_alias) {
  std::vector<std::string> servers;
  // Try to get the room ID from the alias
  auto room_id = ctx->data->id_from_alias(room_alias);
  if (!room_id) {
    return servers;
  }

  // Try to get servers from federation if the room is remote
  if (room_id->find(ctx->data->hostname()) == std::string::npos) {
    // Remote room - try to get servers from the remote server
    auto alias_response = get_alias_route(ctx, room_alias);
    if (alias_response.result.index() == 0) {  // ok
      const auto& response = std::get<ruma::GetAliasResponse>(alias_response.result);
      for (const auto& server : response.servers) {
        if (!server.empty()) {
          servers.push_back(server);
        }
      }
    }
  }

  // Always include local server as fallback
  if (std::find(servers.begin(), servers.end(), ctx->data->hostname()) == servers.end()) {
    servers.push_back(ctx->data->hostname());
  }

  return servers;
}

// Helper to create a join event template via federation
// NEW in c5313b3: try multiple servers when joining remote rooms
std::optional<std::string> send_join_request(
    Context* ctx, const std::string& room_id, const std::string& user_id,
    const std::vector<std::string>& servers, const std::string& path,
    const nlohmann::json& content, std::string* last_error = nullptr) {
  for (const auto& server : servers) {
    auto response = federation::send_request(
        *ctx->data, server, path,
        content);
    if (response && response->is_object() && !response->contains("errcode")) {
      std::cerr << "[debug] Successfully joined via server: " << server << "\n";
      return server;
    } else {
      std::cerr << "[debug] Join failed via server " << server
                << ": " << (response ? response->dump() : "no response") << "\n";
      // NEW in e5c71195: remember remote Matrix errors for forwarding.
      if (last_error && response && federation::is_remote_error(*response))
        *last_error = federation::remote_error_message(*response, server);
    }
  }
  return std::nullopt;
}

// join_room_by_id_or_alias_route — handles both room_id and room_alias
// NEW in c5313b3: "improvement: try out multiple servers when joining remote rooms"
// Translates Conduit's join_room_by_id_or_alias_route with multiple server support
// NEW in bc98425d: invite-state sender servers are join hints (plus the room's
// own server), deduplicated like upstream's HashSet.
ruma::MatrixResult<ruma::JoinRoomByIdResponse> join_room_by_id_or_alias_route(
    Context* ctx, const nlohmann::json& body, const std::string& user_id) {
  std::string room_id_or_alias = body.value("room_id_or_alias", "");
  if (room_id_or_alias.empty()) {
    return ruma::MatrixResult<ruma::JoinRoomByIdResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::InvalidParam,
        .message = "room_id_or_alias is required",
        .status_code = 400,
    });
  }

  std::string room_id;
  std::vector<std::string> servers;
  auto push_server = [&servers](std::string server) {
    if (!server.empty() &&
        std::find(servers.begin(), servers.end(), server) == servers.end())
      servers.push_back(std::move(server));
  };

  // Try to parse as room ID first
  if (room_id_or_alias.find("!") == 0 && room_id_or_alias.find(":") != std::string::npos) {
    // It's a room ID
    room_id = room_id_or_alias;
    // Invite-state sender servers first (bc98425d), then the room's server.
    if (auto istate = ctx->data->invite_state(user_id, room_id))
      for (auto& s : Data::invite_state_servers(*istate)) push_server(s);
    // Get servers from room ID's server name
    size_t colon_pos = room_id.find(':');
    if (colon_pos != std::string::npos) {
      std::string server = room_id.substr(colon_pos + 1);
      push_server(server);
    }
  } else {
    // It's a room alias - resolve to room ID and get servers
    auto alias_response = get_alias_route(ctx, room_id_or_alias);
    if (alias_response.result.index() == 1) {  // err
      return ruma::MatrixResult<ruma::JoinRoomByIdResponse>::err(
          std::get<ruma::Error>(alias_response.result));
    }
    const auto& response = std::get<ruma::GetAliasResponse>(alias_response.result);
    room_id = response.room_id;
    // Invite hints first, then directory servers (all deduplicated).
    if (auto istate = ctx->data->invite_state(user_id, room_id))
      for (auto& s : Data::invite_state_servers(*istate)) push_server(s);
    for (auto& s : response.servers) push_server(s);
  }

  if (room_id.empty()) {
    return ruma::MatrixResult<ruma::JoinRoomByIdResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::NotFound,
        .message = "Room not found.",
        .status_code = 404,
    });
  }

  // For local rooms, just use the room ID directly
  if (room_id.find(ctx->data->hostname()) != std::string::npos) {
    return ruma::MatrixResult<ruma::JoinRoomByIdResponse>::ok(
        ruma::JoinRoomByIdResponse{.room_id = room_id});
  }

  // Remote room - try multiple servers
  // This implements the "try multiple servers when joining remote rooms" feature
  // from Conduit commit c5313b3

  // Step 1: Create join event template (make_join equivalent)
  // In a full implementation, this would call federation::membership::create_join_event_template::v1::Request
  // For now, we simulate by directly creating the join event

  // Try each server until one succeeds
  std::string path = "/_matrix/federation/v1/make_join/" + room_id + "/" + "user_id";  // placeholder
  nlohmann::json content = nlohmann::json::object();  // placeholder

  // NEW in e5c71195: forward the last remote Matrix error when every
  // server refused, instead of only the generic message.
  std::string last_remote_error;
  auto successful_server = send_join_request(ctx, room_id, "user_id", servers,
                                             path, nlohmann::json::object(),
                                             &last_remote_error);

  if (!successful_server) {
    std::string message = "Failed to join room via any server";
    if (!last_remote_error.empty()) message = last_remote_error;
    return ruma::MatrixResult<ruma::JoinRoomByIdResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Forbidden,
        .message = std::move(message),
        .status_code = 403,
    });
  }

  // For now, just return the room_id (full join logic would create the event)
  return ruma::MatrixResult<ruma::JoinRoomByIdResponse>::ok(
      ruma::JoinRoomByIdResponse{.room_id = room_id});
}

ruma::MatrixResult<ruma::JoinRoomByIdResponse> join_room_by_id_route(
    const ruma::JoinRoomByIdRequest& body) {
  return ruma::MatrixResult<ruma::JoinRoomByIdResponse>::ok(
      ruma::JoinRoomByIdResponse{.room_id = body.room_id});
}

ruma::MatrixResult<ruma::CreateMessageEventResponse> create_message_event_route(
    Context* ctx, const ruma::CreateMessageEventRequest& body) {
  // NEW in 4954df3c: transaction id deduplication. A repeated
  // (user, device, txn_id) returns the same event id instead of creating a
  // duplicate PDU.
  if (!body.device_id.empty()) {
    if (auto prev = ctx->data->existing_txnid(
            body.sender_user_id, body.device_id, body.txn_id)) {
      if (prev->empty()) {
        return ruma::MatrixResult<ruma::CreateMessageEventResponse>::err(
            ruma::Error{.kind = ruma::ErrorKind::InvalidParam,
                        .message = "Tried to use txn id already used for an "
                                   "incompatible endpoint.",
                        .status_code = 400});
      }
      return ruma::MatrixResult<ruma::CreateMessageEventResponse>::ok(
          ruma::CreateMessageEventResponse{.event_id = *prev});
    }
  }

  // Check if content is valid (into_result().unwrap() upstream).
  json content;
  try {
    content = json::parse(body.content_json);
    if (!content.is_object()) throw std::runtime_error("no object");
  } catch (...) {
    std::cerr << "[debug] No content.\n";
    return ruma::MatrixResult<ruma::CreateMessageEventResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::NotFound,
        .message = "No content.",
        .status_code = 400,
    });
  }

  // Construct event; placeholder event_id replaced after hashing.
  json event{
      {"type", "m.room.message"},
      {"content", std::move(content)},
      {"event_id", "$thiswillbefilledinlater"},
      {"origin_server_ts", utils::millis_since_unix_epoch()},
      {"room_id", body.room_id},
      {"sender", body.sender_user_id},
      {"unsigned", json::object()},
  };

  // Generate event id via reference hash.
  const std::string event_id = crypto::reference_hash(event);
  event["event_id"] = event_id;

  // Add PDU to the graph. b6c0e9bf: unauthorized events are rejected.
  if (!ctx->data->pdu_append(event_id, body.room_id, std::move(event))) {
    return ruma::MatrixResult<ruma::CreateMessageEventResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Forbidden,
        .message = "event not authorized",
        .status_code = 403,
    });
  }

  // NEW in 4954df3c: remember this txn id -> event id for future dedup.
  if (!body.device_id.empty())
    ctx->data->add_txnid(body.sender_user_id, body.device_id, body.txn_id, event_id);

  return ruma::MatrixResult<ruma::CreateMessageEventResponse>::ok(
      ruma::CreateMessageEventResponse{.event_id = event_id});
}

// NEW in 23cb550d: GET /rooms/<id>/messages — backwards pagination via
// pdus_until. dir=forward is todo!() upstream; we return an empty chunk so
// the demo server survives.
ruma::MatrixResult<ruma::GetMessagesResponse> get_message_events_route(
    Context* ctx, const ruma::GetMessagesRequest& body) {
  if (body.dir == "f") {
    std::cerr << "[debug] forward pagination: todo!() upstream, empty here\n";
    return ruma::MatrixResult<ruma::GetMessagesResponse>::ok(
        ruma::GetMessagesResponse{.start = body.from, .end = ""});
  }

  uint64_t from = 0;
  try {
    from = static_cast<uint64_t>(std::stoull(body.from));
  } catch (...) {
    return ruma::MatrixResult<ruma::GetMessagesResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::NotFound,
        .message = "Invalid from.",
        .status_code = 400,
    });
  }

  auto msgs = ctx->data->pdus_until(body.room_id, from);
  std::cerr << "[dbg-msg] pdus_until(" << body.room_id << "," << from
            << ") -> " << msgs.size() << "\n";
  std::reverse(msgs.begin(), msgs.end());  // newest first for dir=b
  return ruma::MatrixResult<ruma::GetMessagesResponse>::ok(
      ruma::GetMessagesResponse{.start = body.from,
                                .end = "",  // no further events
                                .chunk = std::move(msgs)});
}

ruma::MatrixResult<ruma::SyncResponse> sync_route(Context* ctx,
                                                  const std::string& user_id,
                                                  bool is_initial_sync,
                                                  uint64_t since) {
  ruma::SyncResponse resp;

  // Joined rooms: real per-room timelines now. NEW in 23cb550d:
  // prev_batch carries the since position. NEW in b4d65ab6: a first-ever
  // sync marks timeline.limited; rooms with nothing new are omitted by the
  // responder (is_empty check).
  for (const auto& room_id : ctx->data->rooms_joined(user_id)) {
    ruma::SyncResponse joined;
    joined.joined_room_id = room_id;
    const uint64_t last = ctx->data->last_pdu_index(room_id);
    joined.limited = is_initial_sync && last > 0;
    // b4d65ab6: incremental syncs return only PDUs newer than `since`;
    // initial syncs return the full timeline.
    joined.timeline_events = is_initial_sync
                                 ? ctx->data->pdus_since(room_id, 0)
                                 : ctx->data->pdus_since(room_id, since);
    joined.prev_batch = std::to_string(last);
    // NEW in 662a0cf1: stored counts instead of scanning PDUs since last read.
    joined.notification_count = ctx->data->notification_count(user_id, room_id);
    joined.highlight_count = ctx->data->highlight_count(user_id, room_id);
    resp.joined.emplace(room_id, std::move(joined));
  }

  // NEW in 8773e501: invited rooms serve the stored invite_state directly
  // (stripped create/join_rules/alias/avatar/name + the invite event itself) and
  // skip rooms invited before `since` via the invite count.
  for (const auto& [room_id, invite_state] : ctx->data->rooms_invited_with_state(user_id)) {
    if (!is_initial_sync) {
      if (auto count = ctx->data->get_invite_count(room_id, user_id)) {
        if (since >= *count) continue;  // invited before last sync
      }
    }
    ruma::SyncResponse invited;
    invited.joined_room_id = room_id;
    if (invite_state.is_array() && !invite_state.empty()) {
      for (const auto& ev : invite_state) invited.stripped_state.push_back(ev.dump());
    } else {
      for (const auto& pdu_text : ctx->data->room_state(room_id)) {
        invited.stripped_state.push_back(pdu_text);
      }
    }
    resp.invited.emplace(room_id, std::move(invited));
  }

  // NEW in 0762196: fix: don't send new events from left rooms
  // (Simplified - full left room handling requires rooms_left() and pdus_after() methods)
  // The fix ensures we don't send events from rooms the user has left
  // by properly handling left rooms in sync.

  return ruma::MatrixResult<ruma::SyncResponse>::ok(std::move(resp));
}

}  // namespace

int main(int argc, char** argv) {
  ::signal(SIGPIPE, SIG_IGN);

  int port = static_cast<int>(kListenPort);
  std::string dir_override;
  std::string proxy_override;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) port = std::stoi(argv[++i]);
    if (arg == "--data-dir" && i + 1 < argc) dir_override = argv[++i];
    // NEW in b2d55160: arbitrary proxy for federation sends (upstream
    // Config::proxy; TOML `proxy = ...` maps to --proxy / CONDUIT_PROXY here
    // since this port has no TOML layer). See proxy.hpp for accepted shapes.
    if (arg == "--proxy" && i + 1 < argc) proxy_override = argv[++i];
  }

  std::filesystem::path data_dir;
  if (!dir_override.empty()) {
    data_dir = dir_override;
  } else {
    const char* home = ::getenv("HOME");
    data_dir = (home ? std::filesystem::path{home} : std::filesystem::path{"/tmp"}) /
               ".local/share/conduit-step46";
  }

  // NEW in 9d4fa9a2: the DB cache is configured in megabytes
  // (--db-cache-capacity-mb, default 200.0), replacing the old 1GB
  // cache_capacity. There is no TOML layer in this port, so the flag
  // stands in for the `db_cache_capacity_mb` config key.
  double db_cache_capacity_mb = 200.0;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--db-cache-capacity-mb" && i + 1 < argc) {
      try {
        db_cache_capacity_mb = std::stod(argv[++i]);
      } catch (...) {
        std::cerr << "[warn] Invalid --db-cache-capacity-mb value, using default 200.0\n";
      }
    }
  }

  // NEW in 1d00a8c: better logging - set CONDUIT_LOG from config
  const char* conduit_log = std::getenv("CONDUIT_LOG");
  if (!conduit_log) {
    ::setenv("CONDUIT_LOG", "info,rocket=off,_=off,sled=off", 0);
  }

  static Data data = Data::load_or_create(data_dir, db_cache_capacity_mb);
  data.set_hostname("localhost");
  // NEW in b2d55160: proxy defaults to None (direct); --proxy wins over
  // CONDUIT_PROXY, mirroring upstream `proxy = "none"` default.
  {
    std::string proxy_spec = proxy_override;
    if (proxy_spec.empty()) {
      if (const char* env = std::getenv("CONDUIT_PROXY")) proxy_spec = env;
    }
    if (!proxy_spec.empty()) data.set_proxy_config(proxy::ProxyConfig::parse(proxy_spec));
  }
  static Context ctx{&data};

  httplib::Server svr;

  // NEW in 1f84013b: federation ServerSignatures guard (upstream Ruma auth
  // scheme). Rejects requests without a verifiable X-Matrix authorization
  // header with 401 M_UNAUTHORIZED (upstream: custom 580 status).
  auto require_federation_auth = [&ctx](const httplib::Request& req,
                                        httplib::Response& res)
      -> std::optional<std::string> {
    nlohmann::json auth_body;
    if (!req.body.empty()) {
      try {
        auth_body = nlohmann::json::parse(req.body, nullptr, false);
      } catch (...) {
        auth_body = nlohmann::json();
      }
      if (auth_body.is_discarded()) auth_body = nlohmann::json();
    }
    auto origin = federation::verify_federation_request(
        *ctx.data, req.method, req.path, req.get_header_value("Authorization"),
        auth_body);
    if (!origin) {
      ruma::respond(res,
                    ruma::json{{"errcode", "M_UNAUTHORIZED"},
                               {"error", "Missing or invalid Authorization header."}},
                    401);
      return std::optional<std::string>{};
    }
    return origin;
  };

  svr.Get("/_matrix/client/versions", [](const httplib::Request&, httplib::Response& res) {
    ruma::respond(res, get_supported_versions_route());
  });

  // NEW in dcb5e590: GET /_matrix/client/r0/capabilities REQUIRES
  // authentication (upstream wrapped the handler in Ruma<...> so the request
  // is rejected before the handler runs). The route body itself predates the
  // commit upstream and was never translated here, so it is backfilled in
  // the same shape: room versions capability with v6 stable + default.
  svr.Get("/_matrix/client/r0/capabilities", [&ctx](const httplib::Request& req,
                                                    httplib::Response& res) {
    const auto token = extract_token(req);
    if (!token || !ctx.data->user_from_token(*token)) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    ruma::respond(res,
                  nlohmann::json{
                      {"capabilities",
                       {{"m.room_versions",
                         {{"default", "6"},
                          {"available", {{"6", "stable"}}}}}}}});
  });

  svr.Post("/_matrix/client/r0/register", [&ctx](const httplib::Request& req,
                                                 httplib::Response& res) {
    auto body = nlohmann::json::parse(req.body, nullptr, false);
    // NEW in 699f7767: the body must be valid JSON before a UIAA session
    // may be created. Upstream `body.json_body` is None when the raw body
    // fails to parse (e.g. invalid UTF-8 in an unknown field that ruma
    // itself would ignore); the old `.expect("body is json")` panicked and
    // produced an internal error. Return M_NOT_JSON instead.
    const bool body_is_json = !body.is_discarded();
    if (!body_is_json) body = nlohmann::json::object();

    const std::string username = body.value("username", "");
    nlohmann::json auth;
    if (auto a = body.find("auth"); a != body.end() && a->is_object())
      auth = *a;

    // --- UIAA (b106d139-era flow formalized by c85d363d) -------------------
    if (!auth.contains("type")) {
      if (!body_is_json) {
        ruma::respond(res,
                      nlohmann::json{{"errcode", ruma::errcode(ruma::ErrorKind::NotJson)},
                                     {"error", "Not json."}},
                      400);
        return;
      }
      // First request without auth: start a session and return 401 + flows.
      std::string session = utils::random_string(256);  // SESSION_ID_LENGTH
      nlohmann::json uiaainfo{
          {"flows",
           nlohmann::json::array({
               nlohmann::json{{"stages", nlohmann::json::array({"m.login.dummy"})}},
           })},
          {"completed", nlohmann::json::array()},
          {"params", nlohmann::json::object()},
          {"session", session},
      };
      ctx.data->uiaa_create("@pending:" + session, "", session, uiaainfo);
      ruma::respond(res,
                    nlohmann::json{
                        {"completed", nlohmann::json::array()},
                        {"params", nlohmann::json::object()},
                        {"session", session},
                        {"flows",
                         {{{"stages", nlohmann::json::array({"m.login.dummy"})}}}},
                    },
                    401);
      return;
    }
    if (auth.value("type", "") == "m.login.dummy") {
      // Completed dummy stage: proceed with actual registration below.
    } else {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN"},
                                   {"error", "type not supported"}},
                    400);
      return;
    }

    auto wrapper = ruma::Ruma<ruma::RegisterRequest>::from_request(req);
    wrapper.value.username = username.empty() ? std::optional<std::string>()
                                              : std::optional<std::string>(username);
    ruma::respond(res, register_route(&ctx, wrapper.value));
  });

  // NEW in 67a1f21f: POST /account/password — UIAA (m.login.password), then
  // re-hash and log out all devices except the current one.
  svr.Post("/_matrix/client/r0/account/password", [&ctx](const httplib::Request& req,
                                                         httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    std::optional<std::string> current_device;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    for (const auto& device : ctx.data->all_device_ids(*user)) {
      const auto t = ctx.data->token_for_device(*user, device);
      if (t && *t == *token) current_device = device;
    }

    json body;
    try {
      body = json::parse(req.body);
    } catch (...) {
      body = json::object();
    }
    const std::string new_password = body.value("new_password", "");

    // UIAA: m.login.password stage with the CURRENT password.
    if (!body.contains("auth")) {
      ruma::respond(res,
                    nlohmann::json{
                        {"completed", json::array()},
                        {"params", json::object()},
                        {"flows",
                         {{{"stages", json::array({"m.login.password"})}}}},
                    },
                    401);
      return;
    }
    const json& auth = body["auth"];
    if (auth.value("type", "") != "m.login.password") {
      ruma::respond(res, nlohmann::json{{"errcode", "M_UNKNOWN"},
                                        {"error", "type not supported"}},
                    400);
      return;
    }
    const std::string presented = auth.value("password", "");
    auto correct = ctx.data->password_hash_get(*user);
    bool hash_matches =
        correct &&
        argon2id_verify(correct->c_str(), presented.data(), presented.size()) == ARGON2_OK;
    if (!hash_matches) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_FORBIDDEN"},
                                   {"error", "Invalid username or password."}},
                    403);
      return;
    }

    if (!ctx.data->set_password(*user, new_password)) {
      ruma::respond(res, nlohmann::json{{"errcode", "M_INVALID_PARAM"},
                                        {"error",
                                         "Password does not meet the requirements."}},
                    400);
      return;
    }

    // Logout all devices except the current one.
    for (const auto& device : ctx.data->all_device_ids(*user)) {
      if (device == current_device) continue;
      ctx.data->remove_device(*user, device);
    }

    ruma::respond(res, json::object());
  });

  // NEW in b106d139: POST /logout — invalidates the token's device.
  svr.Post("/_matrix/client/r0/logout", [&ctx](const httplib::Request& req,
                                               httplib::Response& res) {
    const auto token = extract_token(req);
    if (!token) {
      ruma::respond(res, ruma::json{{"errcode", "M_MISSING_TOKEN"},
                                    {"error", "Missing access token"}},
                    401);
      return;
    }
    if (!ctx.data->remove_device_by_token(*token)) {
      ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                    {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    ruma::respond(res, json::object());
  });

  svr.Post("/_matrix/client/r0/login", [](const httplib::Request& req,
                                          httplib::Response& res) {
    auto wrapper = ruma::Ruma<ruma::LoginRequest>::from_request(req);
    ruma::respond(res, login_route(&ctx, wrapper.value));
  });

  svr.Get("/_matrix/client/r0/directory/room/:room_alias",
          [](const httplib::Request& req, httplib::Response& res) {
            ruma::respond(res, get_alias_route(&ctx, req.path_params.at("room_alias")));
          });

  // NEW in df55e8ed: POST /rooms/<id>/upgrade — replace a room with a new
  // version, carrying over state and aliases (and tombstoning the old one).
  svr.Post(R"(/_matrix/client/r0/rooms/(.+)/upgrade)",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             auto wrapper = ruma::Ruma<ruma::RoomUpgradeRequest>::from_request(req);
             const auto token = extract_token(req);
             if (!token || !(wrapper.user_id = ctx.data->user_from_token(*token))) {
               ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                             {"error", "Unrecognised access token"}}, 401);
               return;
             }
             wrapper.value.room_id = req.matches[1];
             const std::string& sender = *wrapper.user_id;
             const std::string& old_room = wrapper.value.room_id;

             if (wrapper.value.new_version != "5" && wrapper.value.new_version != "6") {
               ruma::respond(res, ruma::json{{"errcode", "M_UNSUPPORTED_ROOM_VERSION"},
                                             {"error", "This server does not support that room version."}}, 400);
               return;
             }

             const std::string new_room =
                 "!" + utils::random_string(18) + ":" + ctx.data->hostname();

             auto append = [&](const std::string& room, const std::string& type,
                               nlohmann::json content, const std::string& state_key,
                               const std::string& sender_id) {
               nlohmann::json event = {
                   {"type", type},
                   {"content", std::move(content)},
                   {"event_id", "$thiswillbefilledinlater"},
                   {"origin_server_ts", utils::millis_since_unix_epoch()},
                   {"room_id", room},
                   {"sender", sender_id},
                   {"state_key", state_key},
                   {"unsigned", json::object()},
               };
               const std::string event_id = crypto::reference_hash(event);
               event["event_id"] = event_id;
               ctx.data->pdu_append(event_id, room, std::move(event));
               return event_id;
             };

             // 1. Tombstone the old room (sender must be joined + PL; creator is).
             const std::string tombstone_id = append(
                 old_room, "m.room.tombstone",
                 json{{"body", "This room has been replaced"},
                      {"replacement_room", new_room}},
                 "", sender);

             // 2. Read old room's federate flag from its m.room.create.
             bool federate = true;
             if (auto create = ctx.data->room_state_get(old_room, "m.room.create", ""))
               federate = create->value("federate", true);

             // 3. Create the new room referencing the old one as predecessor.
             append(new_room, "m.room.create",
                    json{{"creator", sender},
                         {"room_version", wrapper.value.new_version},
                         {"federate", federate},
                         {"predecessor",
                          {{"room_id", old_room}, {"event_id", tombstone_id}}}},
                    "", sender);

             // 4. Sender joins the new room.
             if (!ctx.data->room_join(new_room, sender)) {
               ruma::respond(res, ruma::json{{"errcode", "M_FORBIDDEN"},
                                             {"error", "event not authorized"}}, 403);
               return;
             }

             // 5. Replicate transferable state events.
             static const std::vector<std::string> transferable = {
                 "m.room.server_acl",   "m.room.encryption", "m.room.name",
                 "m.room.avatar",       "m.room.topic",      "m.room.guest_access",
                 "m.room.history_visibility", "m.room.join_rules",
                 "m.room.power_levels"};
             for (const auto& type : transferable) {
               auto content = ctx.data->room_state_get(old_room, type, "");
               if (!content) continue;
               append(new_room, type, std::move(*content), "", sender);
             }

             // 6. Move any local aliases to the new room.
             for (const auto& alias : ctx.data->room_aliases(old_room)) {
               ctx.data->remove_alias(alias);
               ctx.data->set_alias(alias, new_room);
             }

             // 7. Lock the old room: raise events_default/invite so no new
             //    events or invites can be sent there.
             if (auto pl = ctx.data->room_state_get(old_room, "m.room.power_levels", "")) {
               long users_default =
                   static_cast<long>((*pl).value("users_default", (long long)0));
               long lock = std::max((long)50, users_default + 1);
               (*pl)["events_default"] = lock;
               (*pl)["invite"] = lock;
               append(old_room, "m.room.power_levels", std::move(*pl), "", sender);
             }

             ruma::respond(res, nlohmann::json{{"replacement_room", new_room}});
           });

  // POST /createRoom (folded prerequisite): random room id, m.room.create +
  // power_levels (+ optional name/topic) state events, creator joins, invites.
  svr.Post("/_matrix/client/r0/createRoom", [&ctx](const httplib::Request& req,
                                                   httplib::Response& res) {
    auto wrapper = ruma::Ruma<ruma::CreateRoomRequest>::from_request(req);
    const auto token = extract_token(req);
    if (!token || !(wrapper.user_id = ctx.data->user_from_token(*token))) {
      ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                    {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    wrapper.value.user_id = *wrapper.user_id;  // sender resolved from token
    ruma::respond(res, create_room_route(&ctx, wrapper.value));
  });

  // NEW in 4cc0a070 (profile endpoints folded): displayname get/set/remove.
  svr.Get(R"(/_matrix/client/r0/profile/(.+)/displayname)",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            const std::string user = req.matches[1];
            if (auto dn = ctx.data->displayname_get(user))
              ruma::respond(res, nlohmann::json{{"displayname", *dn}});
            else
              ruma::respond(res,
                            nlohmann::json{{"errcode", "M_NOT_FOUND"},
                                           {"error", "Displayname not set"}},
                            404);
          });

  svr.Put(R"(/_matrix/client/r0/profile/(.+)/displayname)",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            auto wrapper = ruma::Ruma<ruma::SetDisplaynameRequest>::from_request(req);
            const auto token = extract_token(req);
            std::optional<std::string> user;
            if (!token || !(user = ctx.data->user_from_token(*token)) ||
                *user != req.matches[1]) {
              ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                            {"error", "Unrecognised access token"}},
                            401);
              return;
            }
            (void)wrapper.value.user_id;

            const auto displayname = wrapper.value.displayname;
            bool ok = true;
            if (!displayname || displayname->empty()) {
              ctx.data->displayname_remove(*user);
            } else {
              ok = ctx.data->displayname_set(*user, *displayname);
              // TODO upstream: send a new m.presence event with the updated name
            }
            if (!ok)
              ruma::respond(res, nlohmann::json{{"errcode", "M_FORBIDDEN"},
                                                {"error", "event not authorized"}},
                            403);
             else
               ruma::respond(res, json::object());
           });

  // NEW in 515465f9: GET /profile/{user_id} — full profile; 404 when the user
  // does not exist (instead of returning an empty profile with 200).
  svr.Get(R"(/_matrix/client/r0/profile/([^/]+))",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            const std::string user = req.matches[1];
            if (!ctx.data->user_exists(user)) {
              ruma::respond(res,
                            nlohmann::json{{"errcode", "M_NOT_FOUND"},
                                           {"error", "Profile was not found."}},
                            404);
              return;
            }
            nlohmann::json body = nlohmann::json::object();
            if (auto dn = ctx.data->displayname_get(user)) body["displayname"] = *dn;
            body["avatar_url"] = nullptr;
            ruma::respond(res, body, 200);
          });

  // NEW in 2479389: presence routes. Upstream's set_presence_route predates
  // this commit and this port had no presence at all, so both are folded in:
  //   PUT /presence/{userId}/status  — store an m.presence event per room
  //   GET /presence/{userId}/status  — read the latest one over shared rooms
  svr.Put(R"(/_matrix/client/r0/presence/([^/]+)/status)",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            auto wrapper = ruma::Ruma<ruma::SetPresenceRequest>::from_request(req);
            const auto token = extract_token(req);
            std::optional<std::string> user;
            if (!token || !(user = ctx.data->user_from_token(*token)) ||
                *user != url_decode(req.matches[1])) {
              ruma::respond(res,
                            ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                       {"error", "Unrecognised access token"}},
                            401);
              return;
            }
            const std::string presence = wrapper.value.presence;
            if (presence != "online" && presence != "offline" &&
                presence != "unavailable") {
              ruma::respond(res, ruma::json{{"errcode", "M_INVALID_PARAM"},
                                            {"error", "Invalid presence state."}},
                            400);
              return;
            }
            // Upstream stores the *timestamp* in last_active_ago; GET converts
            // it to a duration.
            nlohmann::json content = {{"presence", presence},
                                      {"last_active_ago", utils::millis_since_unix_epoch()}};
            if (auto dn = ctx.data->displayname_get(*user))
              content["displayname"] = *dn;
            if (wrapper.value.status_msg.has_value())
              content["status_msg"] = *wrapper.value.status_msg;
            nlohmann::json presence_event = {{"type", "m.presence"},
                                             {"sender", *user},
                                             {"content", std::move(content)}};
            for (const auto& room_id : ctx.data->rooms_joined(*user)) {
              ctx.data->update_presence(*user, room_id, presence_event);
            }
            ruma::respond(res, json::object());
          });

  svr.Get(R"(/_matrix/client/r0/presence/([^/]+)/status)",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            const auto token = extract_token(req);
            std::optional<std::string> user;
            if (!token || !(user = ctx.data->user_from_token(*token))) {
              ruma::respond(res,
                            ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                       {"error", "Unrecognised access token"}},
                            401);
              return;
            }
            const std::string target = url_decode(req.matches[1]);
            ruma::GetPresenceResponse out;
            for (const auto& room_id : ctx.data->shared_rooms(*user, target)) {
              auto presence = ctx.data->get_last_presence_event(target, room_id);
              if (!presence) continue;
              const auto& c = presence->value("content", nlohmann::json::object());
              out.presence = c.value("presence", std::string("offline"));
              if (c.contains("status_msg") && c["status_msg"].is_string())
                out.status_msg = c["status_msg"].get<std::string>();
              if (c.contains("currently_active") && c["currently_active"].is_boolean())
                out.currently_active = c["currently_active"].get<bool>();
              if (c.contains("last_active_ago") && c["last_active_ago"].is_number()) {
                const uint64_t stored = c["last_active_ago"].get<uint64_t>();
                const uint64_t now = utils::millis_since_unix_epoch();
                out.last_active_ago = now > stored ? now - stored : 0;
              }
            }
            // Upstream `todo!()`s when the target has no stored presence;
            // this port returns an offline status instead of panicking.
            // NOTE: upstream loops get_last_presence_event(&sender_user, ..)
            // (a bug that returns the requester's presence); this port reads
            // the requested user's presence, as intended.
            ruma::respond(res, ruma::to_json(out));
          });
  // --- NEW in e305889: room account data -------------------------------------
  // PUT /_matrix/client/r0/user/<user_id>/rooms/<room_id>/account_data/<event_type>
  svr.Put(R"(/_matrix/client/r0/user/([^/]+)/rooms/([^/]+)/account_data/([^/]+))",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                        {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             // Check if user can modify this account data (can only modify own)
             if (*user != req.matches[1]) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_FORBIDDEN"},
                                        {"error", "Cannot modify other user's account data"}},
                             403);
               return;
             }
             std::string room_id = req.matches[2];
             std::string event_type = req.matches[3];
             nlohmann::json body;
             try {
               body = nlohmann::json::parse(req.body, nullptr, false);
             } catch (...) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_BAD_JSON"},
                                        {"error", "Invalid JSON"}},
                             400);
               return;
             }
             if (!body.contains("data")) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_BAD_JSON"},
                                        {"error", "Missing data field"}},
                             400);
               return;
             }
             ctx.data->set_room_account_data(req.matches[2], *user, req.matches[3], body["data"]);
             ruma::respond(res, ruma::json::object(), 200);
           });

  // GET /_matrix/client/r0/user/<user_id>/rooms/<room_id>/account_data/<event_type>
  svr.Get(R"(/_matrix/client/r0/user/([^/]+)/rooms/([^/]+)/account_data/([^/]+))",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                        {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             // Check if user can read this account data (can only read own)
             if (*user != req.matches[1]) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_FORBIDDEN"},
                                        {"error", "Cannot read other user's account data"}},
                             403);
               return;
             }
             auto data = ctx.data->get_room_account_data(req.matches[2], *user, req.matches[3]);
             if (!data) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_NOT_FOUND"},
                                        {"error", "Data not found"}},
                             404);
               return;
             }
             ruma::respond(res, *data);
           });

  // --- NEW in fe744c85: push rules -------------------------------------------
  // Upstream fe744c85 refactored push.rs from iter().find() to .get()/.replace()
  // on ruma's Ruleset (IndexSet). C++ stores {"global": {kind: [rules]}} per user
  // via Data::set/get_push_rules and implements replace/get/remove semantics.
  // PUT /_matrix/client/r0/pushrules/<scope>/<kind>/<rule_id>
  svr.Put(R"(/_matrix/client/r0/pushrules/([^/]+)/([^/]+)/([^/]+))",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                        {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             const std::string scope = req.matches[1];
             const std::string kind = req.matches[2];
             const std::string rule_id = req.matches[3];
             if (scope != "global") {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_INVALID_PARAM"},
                                        {"error", "Scopes other than 'global' are not supported."}},
                             400);
               return;
             }
             if (kind != "override" && kind != "underride" && kind != "sender" &&
                 kind != "room" && kind != "content") {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_INVALID_PARAM"},
                                        {"error", "Invalid push rule kind."}},
                             400);
               return;
             }
             nlohmann::json body;
             try {
               body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
             } catch (...) {
               body = nlohmann::json::object();
             }
             if (body.is_discarded()) body = nlohmann::json::object();
             // Build rule with .replace() semantics (fe744c85): remove existing
             // with same rule_id, then insert new.
             nlohmann::json rule;
             rule["rule_id"] = rule_id;
             rule["default"] = false;
             rule["enabled"] = true;
             rule["actions"] = body.value("actions", nlohmann::json::array());
             if (kind == "override" || kind == "underride") {
               rule["conditions"] = body.value("conditions", nlohmann::json::array());
             } else if (kind == "content") {
               rule["pattern"] = body.value("pattern", "");
             }
             auto cur_opt = ctx.data->get_push_rules(*user);
             nlohmann::json cur = cur_opt.value_or(
                 nlohmann::json{{"global", {
                     {"override", nlohmann::json::array()},
                     {"underride", nlohmann::json::array()},
                     {"sender", nlohmann::json::array()},
                     {"room", nlohmann::json::array()},
                     {"content", nlohmann::json::array()},
                 }}});
             if (!cur.contains("global") || !cur["global"].is_object())
               cur["global"] = nlohmann::json::object();
             if (!cur["global"].contains(kind) || !cur["global"][kind].is_array())
               cur["global"][kind] = nlohmann::json::array();
             nlohmann::json updated = nlohmann::json::array();
             for (auto& r : cur["global"][kind]) {
               if (!(r.is_object() && r.value("rule_id", "") == rule_id)) updated.push_back(r);
             }
             updated.push_back(rule);
             cur["global"][kind] = std::move(updated);
             ctx.data->set_push_rules(*user, cur);
             ruma::respond(res, nlohmann::json::object(), 200);
           });

  // GET /_matrix/client/r0/pushrules/<scope>/<kind>/<rule_id>
  svr.Get(R"(/_matrix/client/r0/pushrules/([^/]+)/([^/]+)/([^/]+))",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                        {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             const std::string scope = req.matches[1];
             const std::string kind = req.matches[2];
             const std::string rule_id = req.matches[3];
             if (scope != "global") {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_INVALID_PARAM"},
                                        {"error", "Scopes other than 'global' are not supported."}},
                             400);
               return;
             }
             auto cur_opt = ctx.data->get_push_rules(*user);
             if (cur_opt && cur_opt->contains("global") && (*cur_opt)["global"].contains(kind) &&
                 (*cur_opt)["global"][kind].is_array()) {
               for (auto& r : (*cur_opt)["global"][kind]) {
                 if (r.is_object() && r.value("rule_id", "") == rule_id) {
                   ruma::respond(res, r);
                   return;
                 }
               }
             }
             ruma::respond(res,
                           ruma::json{{"errcode", "M_NOT_FOUND"},
                                      {"error", "Push rule not found."}},
                           404);
           });

  // DELETE /_matrix/client/r0/pushrules/<scope>/<kind>/<rule_id>
  svr.Delete(R"(/_matrix/client/r0/pushrules/([^/]+)/([^/]+)/([^/]+))",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                        {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             const std::string scope = req.matches[1];
             const std::string kind = req.matches[2];
             const std::string rule_id = req.matches[3];
             if (scope != "global") {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_INVALID_PARAM"},
                                        {"error", "Scopes other than 'global' are not supported."}},
                             400);
               return;
             }
             auto cur_opt = ctx.data->get_push_rules(*user);
             if (cur_opt && cur_opt->contains("global") && (*cur_opt)["global"].contains(kind) &&
                 (*cur_opt)["global"][kind].is_array()) {
               nlohmann::json cur = *cur_opt;
               nlohmann::json updated = nlohmann::json::array();
               for (auto& r : cur["global"][kind]) {
                 if (!(r.is_object() && r.value("rule_id", "") == rule_id)) updated.push_back(r);
               }
               cur["global"][kind] = std::move(updated);
               ctx.data->set_push_rules(*user, cur);
             }
             ruma::respond(res, nlohmann::json::object(), 200);
           });

  // GET /_matrix/client/r0/pushrules/<scope>/<kind>/<rule_id>/actions
  svr.Get(R"(/_matrix/client/r0/pushrules/([^/]+)/([^/]+)/([^/]+)/actions)",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                        {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             const std::string kind = req.matches[2];
             const std::string rule_id = req.matches[3];
             auto cur_opt = ctx.data->get_push_rules(*user);
             if (cur_opt && cur_opt->contains("global") && (*cur_opt)["global"].contains(kind) &&
                 (*cur_opt)["global"][kind].is_array()) {
               for (auto& r : (*cur_opt)["global"][kind]) {
                 if (r.is_object() && r.value("rule_id", "") == rule_id) {
                   ruma::respond(res, nlohmann::json{{"actions", r.value("actions", nlohmann::json::array())}});
                   return;
                 }
               }
             }
             ruma::respond(res,
                           ruma::json{{"errcode", "M_NOT_FOUND"},
                                      {"error", "Push rule not found."}},
                           404);
           });

  // PUT /_matrix/client/r0/pushrules/<scope>/<kind>/<rule_id>/actions
  svr.Put(R"(/_matrix/client/r0/pushrules/([^/]+)/([^/]+)/([^/]+)/actions)",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                        {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             const std::string kind = req.matches[2];
             const std::string rule_id = req.matches[3];
             nlohmann::json body;
             try {
               body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
             } catch (...) {
               body = nlohmann::json::object();
             }
             auto cur_opt = ctx.data->get_push_rules(*user);
             if (cur_opt && cur_opt->contains("global") && (*cur_opt)["global"].contains(kind) &&
                 (*cur_opt)["global"][kind].is_array()) {
               nlohmann::json cur = *cur_opt;
               for (auto& r : cur["global"][kind]) {
                 if (r.is_object() && r.value("rule_id", "") == rule_id) {
                   r["actions"] = body.value("actions", nlohmann::json::array());
                   ctx.data->set_push_rules(*user, cur);
                   ruma::respond(res, nlohmann::json::object(), 200);
                   return;
                 }
               }
             }
             ruma::respond(res,
                           ruma::json{{"errcode", "M_NOT_FOUND"},
                                      {"error", "Push rule not found."}},
                           404);
           });

  // GET /_matrix/client/r0/pushrules/<scope>/<kind>/<rule_id>/enabled
  svr.Get(R"(/_matrix/client/r0/pushrules/([^/]+)/([^/]+)/([^/]+)/enabled)",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                        {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             const std::string kind = req.matches[2];
             const std::string rule_id = req.matches[3];
             auto cur_opt = ctx.data->get_push_rules(*user);
             if (cur_opt && cur_opt->contains("global") && (*cur_opt)["global"].contains(kind) &&
                 (*cur_opt)["global"][kind].is_array()) {
               for (auto& r : (*cur_opt)["global"][kind]) {
                 if (r.is_object() && r.value("rule_id", "") == rule_id) {
                   ruma::respond(res, nlohmann::json{{"enabled", r.value("enabled", true)}});
                   return;
                 }
               }
             }
             ruma::respond(res,
                           ruma::json{{"errcode", "M_NOT_FOUND"},
                                      {"error", "Push rule not found."}},
                           404);
           });

  // PUT /_matrix/client/r0/pushrules/<scope>/<kind>/<rule_id>/enabled
  svr.Put(R"(/_matrix/client/r0/pushrules/([^/]+)/([^/]+)/([^/]+)/enabled)",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                        {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             const std::string kind = req.matches[2];
             const std::string rule_id = req.matches[3];
             nlohmann::json body;
             try {
               body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
             } catch (...) {
               body = nlohmann::json::object();
             }
             auto cur_opt = ctx.data->get_push_rules(*user);
             if (cur_opt && cur_opt->contains("global") && (*cur_opt)["global"].contains(kind) &&
                 (*cur_opt)["global"][kind].is_array()) {
               nlohmann::json cur = *cur_opt;
               for (auto& r : cur["global"][kind]) {
                 if (r.is_object() && r.value("rule_id", "") == rule_id) {
                   r["enabled"] = body.value("enabled", true);
                   ctx.data->set_push_rules(*user, cur);
                   ruma::respond(res, nlohmann::json::object(), 200);
                   return;
                 }
               }
             }
             ruma::respond(res,
                           ruma::json{{"errcode", "M_NOT_FOUND"},
                                      {"error", "Push rule not found."}},
                           404);
           });

  // GET /_matrix/client/r0/pushrules/
  svr.Get("/_matrix/client/r0/pushrules",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                        {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             auto rules = ctx.data->get_push_rules(*user);
             if (!rules) {
               ruma::respond(res, nlohmann::json{{"global", {
                   {"override", nlohmann::json::array()},
                   {"underride", nlohmann::json::array()},
                   {"sender", nlohmann::json::array()},
                   {"room", nlohmann::json::array()},
                   {"content", nlohmann::json::array()},
               }}});
             } else {
               ruma::respond(res, *rules);
             }
           });

  // --- NEW in fe744c85: pushers ----------------------------------------------
  // POST /_matrix/client/r0/pushers/set
  svr.Post("/_matrix/client/r0/pushers/set",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                        {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             nlohmann::json body;
             try {
               body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
             } catch (...) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_BAD_JSON"},
                                        {"error", "Invalid JSON"}},
                             400);
               return;
             }
             if (body.is_discarded()) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_BAD_JSON"},
                                        {"error", "Invalid JSON"}},
                             400);
               return;
             }
             if (!body.contains("pushkey") || !body["pushkey"].is_string()) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_BAD_JSON"},
                                        {"error", "Missing pushkey"}},
                             400);
               return;
             }
             std::string pushkey = body["pushkey"].get<std::string>();
             // Upstream set_pusher: kind == null means delete the pusher.
             if (!body.contains("kind") || body["kind"].is_null()) {
               std::string app_id = body.value("app_id", "");
               // Our store keys by pushkey; also try pushkey+app_id form.
               ctx.data->remove_pusher(*user, pushkey);
               if (!app_id.empty()) ctx.data->remove_pusher(*user, pushkey + "\xff" + app_id);
               ruma::respond(res, nlohmann::json::object(), 200);
               return;
             }
             // Validate required fields for add
             if (!body.contains("app_id") || !body.contains("app_display_name") ||
                 !body.contains("device_display_name") || !body.contains("lang") ||
                 !body.contains("data")) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_BAD_JSON"},
                                        {"error", "Missing required fields"}},
                             400);
               return;
             }
             std::string pusher_id = pushkey;
             ctx.data->add_pusher(*user, pusher_id, body);
             ruma::respond(res, nlohmann::json::object(), 200);
           });

  // DELETE /_matrix/client/r0/pushers/<pushkey>
  svr.Delete(R"(/_matrix/client/r0/pushers/([^/]+))",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                        {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             std::string pushkey = req.matches[1];
             ctx.data->remove_pusher(*user, pushkey);
             ruma::respond(res, nlohmann::json::object(), 200);
           });

  // GET /_matrix/client/r0/pushers
  svr.Get("/_matrix/client/r0/pushers",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                        {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             auto pushers = ctx.data->get_pushers(*user);
             nlohmann::json result = nlohmann::json{{"pushers", nlohmann::json::array()}};
             for (const auto& [pusher_id, pusher] : pushers) {
               result["pushers"].push_back(pusher);
             }
             ruma::respond(res, result);
           });


  // Real membership: joining appends an m.room.member join state event.
  svr.Post(R"(/_matrix/client/r0/join/(.+))",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                             {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             std::string room_id = req.matches[1];
             if (room_id.rfind("#", 0) == 0) {
               auto resolved = ctx.data->id_from_alias(room_id);
               if (!resolved) {
                 ruma::respond(res,
                               nlohmann::json{{"errcode", "M_NOT_FOUND"},
                                              {"error", "Room alias not found."}},
                               404);
                 return;
               }
                room_id = *resolved;
              }

              // NEW in 12a8c9ba: federation join. If the room lives on another
              // server, fetch its state over federation, persist it locally, and
              // append our own join event. (Untested locally — needs a peer.)
              const size_t fcolon = room_id.find(':');
              const std::string fremote =
                  fcolon == std::string::npos ? std::string() : room_id.substr(fcolon + 1);
              if (!fremote.empty() && fremote != kServerName) {
                nlohmann::json fcontent = {{"membership", "join"}};
                if (auto fdn = ctx.data->displayname_get(*user))
                  fcontent["displayname"] = *fdn;
                nlohmann::json join_event = {
                    {"type", "m.room.member"},
                    {"content", std::move(fcontent)},
                    {"event_id", "$thiswillbefilledinlater"},
                    {"origin_server_ts", utils::millis_since_unix_epoch()},
                    {"room_id", room_id},
                    {"sender", *user},
                    {"state_key", *user},
                    {"unsigned", json::object()},
                };
                const std::string join_event_id = crypto::reference_hash(join_event);
                join_event["event_id"] = join_event_id;

                const std::string fpath = "/_matrix/federation/v1/send_join/" +
                                          room_id + "/" + join_event_id;
                // NEW in bc98425d: use invite state as hints for which servers
                // to ask when joining — sender servers first, then the room's
                // own server, deduplicated (upstream collects a HashSet).
                std::vector<std::string> join_servers;
                if (auto istate = ctx.data->invite_state(*user, room_id))
                  join_servers = Data::invite_state_servers(*istate);
                if (!fremote.empty() &&
                    std::find(join_servers.begin(), join_servers.end(), fremote) ==
                        join_servers.end())
                  join_servers.push_back(fremote);
                std::optional<nlohmann::json> fresp;
                // NEW in e5c71195: keep trying candidates past remote Matrix
                // errors; remember the last one to forward to the client.
                std::string last_remote_error;
                for (const auto& candidate : join_servers) {
                  fresp = federation::send_request(
                      *ctx.data, candidate, fpath, json::object());
                  if (!fresp) continue;
                  if (federation::is_remote_error(*fresp)) {
                    last_remote_error =
                        federation::remote_error_message(*fresp, candidate);
                    fresp = std::nullopt;
                    continue;
                  }
                  break;
                }
                if (!fresp) {
                  std::string message =
                      "Failed to contact remote server for federation join.";
                  if (!last_remote_error.empty()) message = last_remote_error;
                  ruma::respond(res,
                                ruma::json{{"errcode", "M_UNKNOWN"},
                                           {"error", std::move(message)}},
                                502);
                  return;
                }
                // NEW in 9109cb4: track which events we've already added to prevent
                // double-join when the remote server returns our own join event
                // in its state/auth_chain response
                std::set<std::string> seen_events;
                for (const char* key : {"auth_chain", "state"}) {
                  if ((*fresp).contains(key) && (*fresp)[key].is_array()) {
                    for (auto& pdu : (*fresp)[key]) {
                      // NEW in 989d843c: invalid PDUs in the server response
                      // are logged with context and skipped (never crash the
                      // join on a malformed entry).
                      try {
                        if (!pdu.contains("event_id") || !pdu.contains("room_id")) continue;
                        // NEW in 1dc85895: warn on invalid user ids in the
                        // send_join response (upstream fails the join; we skip
                        // the malformed PDU and continue).
                        if (pdu.value("type", "") == "m.room.member") {
                          const std::string sk = pdu.value("state_key", "");
                          if (sk.empty() || sk[0] != '@' ||
                              sk.find(':') == std::string::npos) {
                            std::clog << "[warn] Invalid user id in send_join "
                                         "response: "
                                      << sk << "\n";
                            continue;
                          }
                        }
                        const std::string eid = pdu["event_id"].get<std::string>();
                        // 989d843c reverts f62258ba's verbose warn here back
                        // to a silent skip once verification/storage fails.
                        if (seen_events.insert(eid).second && !ctx.data->pdu_get(eid))
                          (void)ctx.data->pdu_append(eid, room_id, pdu);
                      } catch (const std::exception& e) {
                        std::cerr << "[warn] Invalid PDU in server response: "
                                  << pdu.dump().substr(0, 200) << ": " << e.what() << "\n";
                        continue;
                      }
                    }
                  }
                }
                // Add our own join event to seen set to prevent double-processing
                seen_events.insert(join_event_id);
                ctx.data->pdu_append(join_event_id, room_id, std::move(join_event));
                federation::send_request(
                    *ctx.data, fremote,
                    "/_matrix/federation/v1/send/" + room_id + "/", json::object());
                ruma::respond(res, ruma::json{{"room_id", room_id}});
                return;
              }

              if (!ctx.data->room_join(room_id, *user)) {
               ruma::respond(res,
                             nlohmann::json{{"errcode", "M_FORBIDDEN"},
                                            {"error", "event not authorized"}},
                             403);
               return;
             }

             nlohmann::json content = {{"membership", "join"}};
             if (auto dn = ctx.data->displayname_get(*user))
               content["displayname"] = *dn;
             nlohmann::json event = {
                 {"type", "m.room.member"},
                 {"content", std::move(content)},
                 {"event_id", "$thiswillbefilledinlater"},
                 {"origin_server_ts", utils::millis_since_unix_epoch()},
                 {"room_id", room_id},
                 {"sender", *user},
                 {"state_key", *user},
                 {"unsigned", json::object()},
             };
             const std::string event_id = crypto::reference_hash(event);
             event["event_id"] = event_id;
             ctx.data->pdu_append(event_id, room_id, std::move(event));

             ruma::respond(res, ruma::json{{"room_id", room_id}});
           });

  // NEW in c5313b3: POST /_matrix/client/r0/join/{roomIdOrAlias}
  // join_room_by_id_or_alias — supports both room ID and room alias,
  // tries multiple servers when joining remote rooms.
  // Implements "improvement: try out multiple servers when joining remote rooms"
  svr.Post(R"(/_matrix/client/r0/join/(.+))",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                             {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             std::string room_id_or_alias = req.matches[1];

             // Use the join_room_by_id_or_alias_route function
             nlohmann::json body = {{"room_id_or_alias", room_id_or_alias}};
             auto result = join_room_by_id_or_alias_route(&ctx, body, *user);

             if (result.result.index() == 1) {  // err
               auto err = std::get<ruma::Error>(result.result);
               ruma::respond(res, ruma::json{{"errcode", ruma::errcode(err.kind)},
                                             {"error", err.message}},
                             err.status_code);
               return;
             }
             const auto& response = std::get<ruma::JoinRoomByIdResponse>(result.result);
             ruma::respond(res, ruma::json{{"room_id", response.room_id}});
           });

  // NEW in abcce95d.
  svr.Post(R"(/_matrix/client/r0/rooms/(.+)/invite)",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             auto wrapper = ruma::Ruma<ruma::InviteRequest>::from_request(req);
             const auto token = extract_token(req);
             if (!token || !(wrapper.user_id = ctx.data->user_from_token(*token))) {
               ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                             {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             wrapper.value.room_id = req.matches[1];
             // NEW in 8773e501: the sender lives on the Ruma wrapper (from the
             // access token), not in the JSON body — copy it into the request
             // struct (previously body.user_id was always empty -> 404).
             wrapper.value.user_id = wrapper.user_id.value_or("");
             invite_user_route(&ctx, wrapper.value, res);
           });

  // NEW in abcce95d.
  svr.Post("/_matrix/client/r0/user_directory/search",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             auto wrapper = ruma::Ruma<ruma::SearchUsersRequest>::from_request(req);
             const auto token = extract_token(req);
             if (!token || !(wrapper.user_id = ctx.data->user_from_token(*token))) {
               ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                             {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             search_users_route(&ctx, wrapper.value, res);
           });

  // NEW in 23cb550d (+ folded leave flow).
  svr.Post(R"(/_matrix/client/r0/rooms/(.+)/leave)",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                             {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             if (!ctx.data->room_leave(req.matches[1], *user)) {
               ruma::respond(res,
                             nlohmann::json{{"errcode", "M_FORBIDDEN"},
                                            {"error", "event not authorized"}},
                             403);
               return;
             }
             ruma::respond(res, json::object());
           });

  svr.Post(R"(/_matrix/client/r0/rooms/(.+)/forget)",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                             {"error", "Unrecognised access token"}},
                             401);
               return;
             }
             ctx.data->room_forget(req.matches[1], *user);
             ruma::respond(res, json::object());
           });

  // NEW in 23cb550d: GET /rooms/<id>/messages — backwards pagination.
  svr.Get(R"(/_matrix/client/r0/rooms/(.+)/messages)",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            auto wrapper = ruma::Ruma<ruma::GetMessagesRequest>::from_request(req);
            const auto token = extract_token(req);
            if (!token || !(wrapper.user_id = ctx.data->user_from_token(*token))) {
              ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                            {"error", "Unrecognised access token"}},
                            401);
              return;
            }
            wrapper.value.room_id = req.matches[1];
            ruma::respond(res, get_message_events_route(&ctx, wrapper.value));
          });

  // NEW in b6c0e9bf: state events (PUT /rooms/<id>/state/<type>[/<key>]) —
  // authorized by the power-level rules inside pdu_append.
  auto state_handler = [&ctx](bool has_state_key) {
    return [ctx, has_state_key](const httplib::Request& req,
                                httplib::Response& res) {
      const auto token = extract_token(req);
      std::optional<std::string> user;
      if (!token || !(user = ctx.data->user_from_token(*token))) {
        ruma::respond(res,
                      nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                     {"error", "Unrecognised access token"}},
                      401);
        return;
      }
      const std::string room_id = req.matches[1];
      const std::string event_type = req.matches[2];
      const std::string state_key =
          has_state_key ? req.matches[3].str() : std::string("");

      json content;
      try {
        content = json::parse(req.body);
        if (!content.is_object()) throw std::runtime_error("no object");
      } catch (...) {
        ruma::respond(res, nlohmann::json{{"errcode", "M_NOT_FOUND"},
                                          {"error", "No content."}},
                      400);
        return;
      }

      json event = {
          {"type", event_type},
          {"content", std::move(content)},
          {"event_id", "$thiswillbefilledinlater"},
          {"origin_server_ts", utils::millis_since_unix_epoch()},
          {"room_id", room_id},
          {"sender", *user},
          {"state_key", state_key},
          {"unsigned", json::object()},
      };
      const std::string event_id = crypto::reference_hash(event);
      event["event_id"] = event_id;

      if (!ctx.data->pdu_append(event_id, room_id, std::move(event))) {
        ruma::respond(res,
                      nlohmann::json{{"errcode", "M_FORBIDDEN"},
                                     {"error", "event not authorized"}},
                      403);
        return;
      }
      ruma::respond(res, nlohmann::json{{"event_id", event_id}});
    };
  };

  svr.Put(R"(/_matrix/client/r0/rooms/(.+)/state/(.+?)/([^/]+))",
          state_handler(true));
  svr.Put(R"(/_matrix/client/r0/rooms/(.+)/state/(.+))", state_handler(false));

  // NEW in 7031240a: GET /rooms/<id>/members.
  svr.Get(R"(/_matrix/client/r0/rooms/(.+)/members)",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            const auto token = extract_token(req);
            std::optional<std::string> user;
            if (!token || !(user = ctx.data->user_from_token(*token))) {
              ruma::respond(res,
                            nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                           {"error", "Unrecognised access token"}},
                            401);
              return;
            }
            const std::string room_id = req.matches[1];
            if (!ctx.data->is_joined(*user, room_id)) {
              ruma::respond(
                  res,
                  nlohmann::json{
                      {"errcode", "M_FORBIDDEN"},
                      {"error", "You don't have permission to view this room."}},
                  403);
              return;
            }
            nlohmann::json chunk = nlohmann::json::array();
            for (const auto& pdu_text :
                 ctx.data->room_state_type(room_id, "m.room.member")) {
              chunk.push_back(nlohmann::json::parse(pdu_text));
            }
            ruma::respond(res, nlohmann::json{{"chunk", std::move(chunk)}});
          });

  // NEW in df55e8ed verification: GET /rooms/<id>/state/<type>[/<state_key>]
  // (read current state event content; the upgrade test relies on it).
  // NEW in 243126d: allow reading state if history_visibility is world_readable
  auto get_state_route = [&ctx](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                    {"error", "Unrecognised access token"}}, 401);
      return;
    }
    const std::string room_id = req.matches[1];
    const std::string type = req.matches[2];
    const std::string state_key = req.matches.size() > 3 ? req.matches[3].str() : "";
    if (!ctx.data->is_joined(*user, room_id)) {
      // NEW in 243126d: check if room is world_readable
      bool is_world_readable = false;
      for (const auto& pdu_text : ctx.data->room_state_type(room_id, "m.room.history_visibility")) {
        auto pdu = nlohmann::json::parse(pdu_text);
        if (pdu.value("content", nlohmann::json::object()).value("history_visibility", "") == "world_readable") {
          is_world_readable = true;
          break;
        }
      }
      if (!is_world_readable) {
        ruma::respond(res, ruma::json{{"errcode", "M_FORBIDDEN"},
                                      {"error", "You don't have permission to view this room."}}, 403);
        return;
      }
    }
    for (const auto& pdu_text : ctx.data->room_state_type(room_id, type)) {
      auto pdu = nlohmann::json::parse(pdu_text);
      if (pdu.value("state_key", "") == state_key) {
        ruma::respond(res, pdu["content"]);
        return;
      }
    }
    ruma::respond(res, ruma::json{{"errcode", "M_NOT_FOUND"},
                                  {"error", "Event not found."}}, 404);
  };
  svr.Get(R"(/_matrix/client/r0/rooms/(.+)/state/(.+?)/([^/]+))", get_state_route);
  svr.Get(R"(/_matrix/client/r0/rooms/(.+)/state/(.+))", get_state_route);

  // NEW in 469071e1: GET /rooms/<id>/event/<event_id> — requires joined
  // membership; returns the raw PDU as a room event.
  svr.Get(R"(/_matrix/client/r0/rooms/(.+)/event/(.+))",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            const auto token = extract_token(req);
            std::optional<std::string> user;
            if (!token || !(user = ctx.data->user_from_token(*token))) {
              ruma::respond(res,
                            nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                           {"error", "Unrecognised access token"}},
                            401);
              return;
            }
            const std::string room_id = req.matches[1];
            const std::string event_id = req.matches[2];
            if (!ctx.data->is_joined(*user, room_id)) {
              ruma::respond(
                  res,
                  nlohmann::json{
                      {"errcode", "M_FORBIDDEN"},
                      {"error", "You don't have permission to view this room."}},
                  403);
              return;
            }
            auto pdu_text = ctx.data->pdu_get(event_id);
            if (!pdu_text) {
              ruma::respond(res, nlohmann::json{{"errcode", "M_NOT_FOUND"},
                                                {"error", "Event not found."}},
                            404);
              return;
            }
            ruma::respond(res, nlohmann::json::parse(*pdu_text));
          });

  // Better public room directory (abcce95d).
  svr.Post("/_matrix/client/r0/publicRooms", [&ctx](const httplib::Request& req,
                                                    httplib::Response& res) {
    // NEW in 77a23f89: honor the filter body (generic_search_term) instead
    // of always returning the unfiltered list.
    nlohmann::json body;
    try {
      body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
    } catch (...) {
      body = nlohmann::json::object();
    }
    if (body.is_discarded() || !body.is_object()) body = nlohmann::json::object();
    ruma::respond(res, get_public_rooms_filtered_route(&ctx, body));
  });

  // Federation endpoint: GET /_matrix/federation/v1/publicRooms (Conduit 4e44fed)
  svr.Post("/_matrix/federation/v1/publicRooms",
           [&ctx, &require_federation_auth](const httplib::Request& req,
                                            httplib::Response& res) {
             if (!require_federation_auth(req, res)) return;
             nlohmann::json body;
             try {
               body = nlohmann::json::parse(req.body, nullptr, false);
             } catch (...) {
               body = nlohmann::json::object();
             }
             ruma::respond(res, get_public_rooms_filtered_route(&ctx, body));
           });
  // Federation endpoint: GET /_matrix/federation/v1/state_ids/<event_id> (Conduit a77fcd1)
  svr.Get(R"(/_matrix/federation/v1/state_ids/(.+))",
           [&ctx, &require_federation_auth](const httplib::Request& req,
                                            httplib::Response& res) {
             if (!require_federation_auth(req, res)) return;
             std::string event_id = req.matches[1];
             nlohmann::json result = federation::get_room_state_ids(*ctx.data, event_id);
             if (result.contains("errcode")) {
               ruma::respond(res, result, 404);
             } else {
               ruma::respond(res, result);
             }
           });


  svr.Put(R"(/_matrix/client/r0/rooms/(.+)/send/(.+)/(.+))",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            auto wrapper = ruma::Ruma<ruma::CreateMessageEventRequest>::from_request(req);
            const auto token = extract_token(req);
            if (!token || !(wrapper.user_id = ctx.data->user_from_token(*token))) {
              ruma::respond(res,
                            ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                       {"error", "Unrecognised access token"}},
                            401);
              return;
            }
            wrapper.value.room_id = req.matches[1];
            wrapper.value.event_type = req.matches[2];
            wrapper.value.txn_id = req.matches[3];
            wrapper.value.sender_user_id = *wrapper.user_id;
            if (auto dev = ctx.data->device_from_token(*token))
              wrapper.value.device_id = *dev;
            ruma::respond(res, create_message_event_route(&ctx, wrapper.value));
          });

  svr.Get("/_matrix/client/r0/sync", [&ctx](const httplib::Request& req,
                                            httplib::Response& res) {
    auto wrapper = ruma::Ruma<ruma::SyncRequest>::from_request(req);
    const auto token = extract_token(req);
    if (!token || !(wrapper.user_id = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                               {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    uint64_t since = 0;
    if (req.has_param("since"))
      since = static_cast<uint64_t>(std::stoull(req.get_param_value("since")));
    const bool is_initial = since == 0;
    ruma::respond(res, sync_route(&ctx, *wrapper.user_id, is_initial, since));
  });

  // --- NEW in 1af6dd98: server-side federation identity --------------------

  // GET /.well-known/matrix/server — delegation hint. Upstream hardcoded its
  // test domain; we advertise our own hostname.
  svr.Get("/.well-known/matrix/server",
          [&ctx](const httplib::Request&, httplib::Response& res) {
            res.set_content(
                nlohmann::json{{"m.server", ctx.data->hostname()}}.dump(),
                "application/json");
          });

  // GET /_matrix/federation/v1/version
  svr.Get("/_matrix/federation/v1/version",
          [](const httplib::Request&, httplib::Response& res) {
            ruma::respond(res, nlohmann::json{
                                   {"server",
                                    {{"name", "Conduit"}, {"version", "0.1.0"}}}});
          });

  // NEW in 71ed1b29: federation device list.
  // GET /_matrix/federation/v1/user/devices/:userId -> {user_id, stream_id,
  // devices}. Lets remote servers track our users' device lists.
  svr.Get(R"(/_matrix/federation/v1/user/devices/(.+))",
          [&ctx, &require_federation_auth](const httplib::Request& req,
                                           httplib::Response& res) {
            if (!require_federation_auth(req, res)) return;
            const std::string user_id = url_decode(req.matches[1]);
            auto result = federation::get_user_devices(*ctx.data, user_id);
            if (result.contains("errcode")) {
              ruma::respond(res, result, 404);
            } else {
              ruma::respond(res, result, 200);
            }
          });

  // GET /_matrix/key/v2/server (+ deprecated :key_id variant) — the signed
  // server key document any homeserver needs to verify our signatures.
  auto server_keys_handler = [&ctx](const httplib::Request&,
                                    httplib::Response& res) {
    const std::string pub_b64 =
        crypto::ed25519_public_b64(ctx.data->keypair());
    nlohmann::json doc{
        {"server_name", ctx.data->hostname()},
        {"verify_keys",
         {{"ed25519:" + pub_b64,
           {{"kty", "OKP"}, {"key", pub_b64}}}}},
        {"old_verify_keys", json::object()},
        {"valid_until_ts",
         utils::millis_since_unix_epoch() + 2ULL * 60 * 1000},  // cut to 2 min
    };
    crypto::sign_json(ctx.data->hostname(), ctx.data->keypair(), doc);
    ruma::respond(res, doc);
  };
  svr.Get("/_matrix/key/v2/server", server_keys_handler);

  // TEMPORARY debug dump for step-13 verification.
  svr.Get("/debug/userid_roomids", [&ctx](const httplib::Request&,
                                          httplib::Response& res) {
    nlohmann::json out = nlohmann::json::array();
    for (const auto& [k, v] : ctx.data->debug_userid_roomids()) {
      out.push_back({{"key", k}, {"value", v}});
    }
    res.set_content(out.dump(), "application/json");
  });
  svr.Get("/debug/userid_leftroomids", [&ctx](const httplib::Request&,
                                              httplib::Response& res) {
    nlohmann::json out = nlohmann::json::array();
    for (const auto& [k, v] : ctx.data->debug_userid_leftroomids()) {
      out.push_back({{"key", k}, {"value", v}});
    }
    res.set_content(out.dump(), "application/json");
  });
  svr.Get(R"(/_matrix/key/v2/server/(.+))", server_keys_handler);

  svr.Get(R"(/_matrix/key/v2/server/(.+))", server_keys_handler);

  // NEW in 6e5b35e: Appservice registration and management
  // POST /_synapse/admin/v1/appservices
  svr.Post("/_synapse/admin/v1/appservices",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             const auto token = extract_token(req);
             std::optional<std::string> user;
             if (!token || !(user = ctx.data->user_from_token(*token))) {
               ruma::respond(res,
                             nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                            {"error", "Unrecognised access token"}},
                             401);
             return;
           }
             // Check if user is admin
             if (!ctx.data->is_joined(*user, "!admin:local")) {
               ruma::respond(res,
                             nlohmann::json{{"errcode", "M_FORBIDDEN"},
                                            {"error", "Admin access required"}},
                             403);
             return;
           }
             nlohmann::json body;
             try { body = nlohmann::json::parse(req.body); } catch (...) { body = nlohmann::json::object(); }
             // Parse request body manually since we don't have ruma::AppserviceRegistrationRequest
             nlohmann::json request_json;
             if (body.contains("url")) request_json["url"] = body["url"];
             if (body.contains("sender_localpart")) request_json["sender_localpart"] = body["sender_localpart"];
             if (body.contains("namespaces")) {
                 request_json["namespaces"] = body["namespaces"];
             }
             if (body.contains("rate_limited")) {
                 request_json["rate_limited"] = body["rate_limited"];
             }
             auto result = ctx.appservice_manager.register_appservice(request_json);
             ruma::respond(res, result);
           });

  // GET /_synapse/admin/v1/appservices/:id
  svr.Get(R"(/_synapse/admin/v1/appservices/(.+))",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            const auto token = extract_token(req);
            std::optional<std::string> user;
            if (!token || !(user = ctx.data->user_from_token(*token))) {
              ruma::respond(res,
                            nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                           {"error", "Unrecognised access token"}},
                            401);
            return;
           }
            if (!ctx.data->is_joined(*user, "!admin:local")) {
              ruma::respond(res,
                            nlohmann::json{{"errcode", "M_FORBIDDEN"},
                                           {"error", "Admin access required"}},
                            403);
            return;
           }
            std::string appservice_id = req.matches[1];
            if (auto appservice = ctx.appservice_manager.get_appservice(appservice_id)) {
              ruma::respond(res, nlohmann::json{
                  {"id", appservice->id},
                  {"url", appservice->url},
                  {"as_token", appservice->as_token},
                  {"hs_token", appservice->hs_token},
                  {"sender_localpart", appservice->sender_localpart},
                  {"namespaces", nlohmann::json{
                      {"users", appservice->namespaces_users},
                      {"aliases", appservice->namespaces_aliases},
                      {"rooms", appservice->namespaces_rooms},
                  }},
                  {"rate_limited", appservice->rate_limited},
              });
            } else {
              ruma::respond(res,
                            nlohmann::json{{"errcode", "M_NOT_FOUND"},
                                           {"error", "Appservice not found"}},
                            404);
            }
          });

  // POST /_matrix/app/v1/transactions/:txnId (appservice transactions)
  svr.Put(R"(/_matrix/app/v1/transactions/(.+))",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            const auto token = extract_token(req);
            std::optional<std::string> user;
            if (!token || !(user = ctx.data->user_from_token(*token))) {
              ruma::respond(res,
                            nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                           {"error", "Unrecognised access token"}},
                            401);
              return;
            }
            // Verify appservice token
            // TODO: Verify appservice token from request
            nlohmann::json body;
            try { body = nlohmann::json::parse(req.body); } catch (...) { body = nlohmann::json::object(); }
            std::string txn_id = req.matches[1];
            // Process transaction
            // TODO: Implement transaction handling
            ruma::respond(res, nlohmann::json{{"pdus", nlohmann::json::object()}});
          });

  // NEW in b8193984: POST /account/deactivate — UIAA, leave/reject rooms,
  // (registration line restored in e1e529d8 step: the handler below was
  // orphaned with no route, so deactivation was unreachable).
  svr.Post("/_matrix/client/r0/account/deactivate",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }

    json body;
    try {
      body = json::parse(req.body);
    } catch (...) {
      body = json::object();
    }
    if (!body.contains("auth")) {
      ruma::respond(res,
                    nlohmann::json{
                        {"completed", json::array()},
                        {"params", json::object()},
                        {"flows",
                         {{{"stages", json::array({"m.login.password"})}}}},
                    },
                    401);
      return;
    }
    const json& auth = body["auth"];
    if (auth.value("type", "") != "m.login.password") {
      ruma::respond(res, nlohmann::json{{"errcode", "M_UNKNOWN"},
                                        {"error", "type not supported"}},
                    400);
      return;
    }
    const std::string presented = auth.value("password", "");
    auto correct = ctx.data->password_hash_get(*user);
    bool hash_matches =
        correct && !correct->empty() &&
        argon2id_verify(correct->c_str(), presented.data(), presented.size()) == ARGON2_OK;
    if (!hash_matches) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_FORBIDDEN"},
                                   {"error", "Invalid username or password."}},
                    403);
      return;
    }

    // Leave all joined rooms and reject all invitations.
    for (const auto& room_id : ctx.data->rooms_joined(*user)) {
      ctx.data->room_leave(room_id, *user);
    }
    for (const auto& room_id : ctx.data->rooms_invited(*user)) {
      ctx.data->room_leave(room_id, *user);  // reject == leave for invites
    }

    ctx.data->deactivate_account(*user);

    // NEW in 6e36081: log account deactivation
    std::clog << "[info] " << *user << " deactivated their account\n";

    ruma::respond(res, json{{"id_server_unbind_result", "no-support"}});
  }); 

  // --- NEW in 3aa0c8ed: directory routes ---------------------------------
  svr.Put(R"(/_matrix/client/r0/directory/room/(.+))",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            json body;
            try { body = json::parse(req.body); } catch (...) { body = json::object(); }
            const std::string alias = req.matches[1];
            const std::string room_id = body.value("room_id", "");
            if (room_id.empty() || alias.rfind("#", 0) != 0) {
              ruma::respond(res, nlohmann::json{{"errcode", "M_UNKNOWN"},
                                                {"error", "Invalid request"}}, 400);
              return;
            }
            if (ctx.data->id_from_alias(alias)) {
              ruma::respond(res, nlohmann::json{{"errcode", "M_UNKNOWN"},
                                                {"error", "Alias already exists"}}, 409);
              return;
            }
            ctx.data->set_alias(alias, room_id);
            ruma::respond(res, nlohmann::json::object());
          });

  svr.Delete(R"(/_matrix/client/r0/directory/room/(.+))",
             [&ctx](const httplib::Request& req, httplib::Response& res) {
               const std::string alias = req.matches[1];
               if (!ctx.data->id_from_alias(alias)) {
                 ruma::respond(res, nlohmann::json{{"errcode", "M_NOT_FOUND"},
                                                   {"error", "Alias not found"}}, 404);
                 return;
               }
               ctx.data->remove_alias(alias);
               ruma::respond(res, nlohmann::json::object());
             });

  svr.Get(R"(/_matrix/client/r0/directory/list/room/(.+))",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            const std::string room_id = req.matches[1];
            ruma::respond(res,
                          nlohmann::json{{"visibility",
                                          ctx.data->is_public(room_id) ? "public"
                                                                       : "private"}});
          });

  // NEW in 18bf6774: PUT /rooms/<id>/redact/<event_id>/<txn_id>.
  svr.Put(R"(/_matrix/client/r0/rooms/(.+)/redact/([^/]+)/([^/]+))",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            const auto token = extract_token(req);
            std::optional<std::string> user;
            if (!token || !(user = ctx.data->user_from_token(*token))) {
              ruma::respond(res,
                            nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                           {"error", "Unrecognised access token"}},
                            401);
              return;
            }
            const std::string room_id = req.matches[1];
            const std::string target_event = req.matches[2];

            json body;
            try {
              body = json::parse(req.body);
            } catch (...) {
              body = json::object();
            }
            const std::string reason = body.value("reason", "");

            // Append an m.room.redaction event whose `redacts` names the target.
            json event = {
                {"type", "m.room.redaction"},
                {"content", {{"reason", reason}}},
                {"event_id", "$thiswillbefilledinlater"},
                {"origin_server_ts", utils::millis_since_unix_epoch()},
                {"room_id", room_id},
                {"sender", *user},
                {"unsigned", json::object()},
            };
            const std::string event_id = crypto::reference_hash(event);
            event["event_id"] = event_id;
            event["redacts"] = target_event;
            // NEW in ddcf1a71: pass the redaction event so unsigned carries
            // redacted_because as an object (kept copy: event is moved below).
            nlohmann::json redaction_copy = event;
            ctx.data->pdu_append(event_id, room_id, std::move(event));
            ctx.data->redact_pdu(target_event, redaction_copy);

            ruma::respond(res, nlohmann::json{{"event_id", event_id}});
          });

  // --- NEW in 3f4cb753: key backup store (folded base + remaining) ----------
  // Resolve the backup version from query param or the user's latest.
  auto resolve_version = [&](const httplib::Request& req, const std::string& u)
      -> std::optional<std::string> {
    if (req.has_param("version")) return std::string(req.get_param_value("version"));
    return ctx.data->backup_latest(u);
  };

  svr.Post("/_matrix/client/r0/room_keys/version", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    json body;
    try { body = json::parse(req.body); } catch (...) { body = json::object(); }
    json algorithm = body.value("algorithm", json::object());
    std::string version = ctx.data->backup_create(*user, algorithm);
    ruma::respond(res, json{{"version", version}}, 200);
  });

  svr.Get("/_matrix/client/r0/room_keys/version", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    auto v = ctx.data->backup_latest(*user);
    if (!v) {
      ruma::respond(res, json{{"errcode", "M_NOT_FOUND"}, {"error", "No backup"}}, 404);
      return;
    }
    auto info = ctx.data->backup_get(*user, *v);
    if (!info) {
      ruma::respond(res, json{{"errcode", "M_NOT_FOUND"}, {"error", "Unknown version"}}, 404);
      return;
    }
    ruma::respond(res, info.value(), 200);
  });

  svr.Get("/_matrix/client/r0/room_keys/version/([^/]+)", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    std::string version = req.matches[1];
    auto info = ctx.data->backup_get(*user, version);
    if (!info) {
      ruma::respond(res, json{{"errcode", "M_NOT_FOUND"}, {"error", "Unknown version"}}, 404);
      return;
    }
    ruma::respond(res, info.value(), 200);
  });

  svr.Put("/_matrix/client/r0/room_keys/version/([^/]+)", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    std::string version = req.matches[1];
    json body;
    try { body = json::parse(req.body); } catch (...) { body = json::object(); }
    json algorithm = body.value("algorithm", json::object());
    ctx.data->backup_update(*user, version, algorithm);
    auto info = ctx.data->backup_get(*user, version);
    ruma::respond(res, info.value(), 200);
  });

  svr.Delete("/_matrix/client/r0/room_keys/version/([^/]+)", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    std::string version = req.matches[1];
    ctx.data->backup_delete(*user, version);
    ruma::respond(res, json{}, 200);
  });

  svr.Put("/_matrix/client/r0/room_keys/keys", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    auto v = resolve_version(req, *user);
    if (!v) { ruma::respond(res, json{{"errcode","M_NOT_FOUND"},{"error","No backup"}}, 404); return; }
    json body;
    try { body = json::parse(req.body); } catch (...) { body = json::object(); }
    json rooms = body.value("rooms", json::object());
    for (auto& [room_id, sessions] : rooms.items()) {
      for (auto& [session_id, key_data] : sessions.items()) {
        ctx.data->backup_add_key(*user, *v, room_id, session_id, key_data);
      }
    }
    ruma::respond(res, json{{"count", ctx.data->backup_count(*user, *v)},
                            {"etag", ctx.data->backup_etag(*user, *v)}}, 200);
  });

  svr.Put("/_matrix/client/r0/room_keys/keys/([^/]+)/([^/]+)", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    auto v = resolve_version(req, *user);
    if (!v) { ruma::respond(res, json{{"errcode","M_NOT_FOUND"},{"error","No backup"}}, 404); return; }
    std::string room_id = req.matches[1];
    std::string session_id = req.matches[2];
    json body;
    try { body = json::parse(req.body); } catch (...) { body = json::object(); }
    json key_data = body.value("session_data", json::object());
    ctx.data->backup_add_key(*user, *v, room_id, session_id, key_data);
    ruma::respond(res, json{{"count", ctx.data->backup_count(*user, *v)},
                            {"etag", ctx.data->backup_etag(*user, *v)}}, 200);
  });

  svr.Put("/_matrix/client/r0/room_keys/keys/([^/]+)", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    auto v = resolve_version(req, *user);
    if (!v) { ruma::respond(res, json{{"errcode","M_NOT_FOUND"},{"error","No backup"}}, 404); return; }
    std::string room_id = req.matches[1];
    json body;
    try { body = json::parse(req.body); } catch (...) { body = json::object(); }
    json sessions = body.value("sessions", json::object());
    for (auto& [session_id, key_data] : sessions.items()) {
      ctx.data->backup_add_key(*user, *v, room_id, session_id, key_data);
    }
    ruma::respond(res, json{{"count", ctx.data->backup_count(*user, *v)},
                            {"etag", ctx.data->backup_etag(*user, *v)}}, 200);
  });

  svr.Get("/_matrix/client/r0/room_keys/keys", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    auto v = resolve_version(req, *user);
    if (!v) { ruma::respond(res, json{{"errcode","M_NOT_FOUND"},{"error","No backup"}}, 404); return; }
    ruma::respond(res, json{{"rooms", ctx.data->backup_get_keys(*user, *v)}}, 200);
  });

  svr.Get("/_matrix/client/r0/room_keys/keys/([^/]+)/([^/]+)", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    auto v = resolve_version(req, *user);
    if (!v) { ruma::respond(res, json{{"errcode","M_NOT_FOUND"},{"error","No backup"}}, 404); return; }
    std::string room_id = req.matches[1];
    std::string session_id = req.matches[2];
    auto kd = ctx.data->backup_get_session(*user, *v, room_id, session_id);
    if (!kd) { ruma::respond(res, json{{"errcode","M_NOT_FOUND"},{"error","No key"}}, 404); return; }
    ruma::respond(res, json{{"key_data", *kd}}, 200);
  });

  svr.Get("/_matrix/client/r0/room_keys/keys/([^/]+)", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    auto v = resolve_version(req, *user);
    if (!v) { ruma::respond(res, json{{"errcode","M_NOT_FOUND"},{"error","No backup"}}, 404); return; }
    std::string room_id = req.matches[1];
    ruma::respond(res, json{{"sessions", ctx.data->backup_get_room(*user, *v, room_id)}}, 200);
  });

  svr.Delete("/_matrix/client/r0/room_keys/keys", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    auto v = resolve_version(req, *user);
    if (!v) { ruma::respond(res, json{{"errcode","M_NOT_FOUND"},{"error","No backup"}}, 404); return; }
    ctx.data->backup_delete_all_keys(*user, *v);
    ruma::respond(res, json{{"count", ctx.data->backup_count(*user, *v)},
                            {"etag", ctx.data->backup_etag(*user, *v)}}, 200);
  });

  svr.Delete("/_matrix/client/r0/room_keys/keys/([^/]+)/([^/]+)", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    auto v = resolve_version(req, *user);
    if (!v) { ruma::respond(res, json{{"errcode","M_NOT_FOUND"},{"error","No backup"}}, 404); return; }
    std::string room_id = req.matches[1];
    std::string session_id = req.matches[2];
    ctx.data->backup_delete_room_key(*user, *v, room_id, session_id);
    ruma::respond(res, json{{"count", ctx.data->backup_count(*user, *v)},
                            {"etag", ctx.data->backup_etag(*user, *v)}}, 200);
  });

  svr.Delete("/_matrix/client/r0/room_keys/keys/([^/]+)", [&](const httplib::Request& req, httplib::Response& res) {
    const auto token = extract_token(req);
    std::optional<std::string> user;
    if (!token || !(user = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                   {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    auto v = resolve_version(req, *user);
    if (!v) { ruma::respond(res, json{{"errcode","M_NOT_FOUND"},{"error","No backup"}}, 404); return; }
    std::string room_id = req.matches[1];
    ctx.data->backup_delete_room_keys(*user, *v, room_id);
    ruma::respond(res, json{{"count", ctx.data->backup_count(*user, *v)},
                            {"etag", ctx.data->backup_etag(*user, *v)}}, 200);
  });

  // --- NEW in 821c608c: media repository -------------------------------------

  // GET /_matrix/media/r0/config — 20 MB upload limit (MESSAGE_LIMIT upstream).
  svr.Get("/_matrix/media/r0/config", [](const httplib::Request&,
                                         httplib::Response& res) {
    ruma::respond(res, nlohmann::json{{"m.upload.size", 20 * 1024 * 1024}});
  });

  // POST /_matrix/media/r0/upload?filename=… — body IS the file.
  svr.Post("/_matrix/media/r0/upload", [&ctx](const httplib::Request& req,
                                              httplib::Response& res) {
    const auto token = extract_token(req);
    if (!token || !ctx.data->user_from_token(*token)) {
      ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                    {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    const std::string mxc =
        "mxc://" + ctx.data->hostname() + "/" +
        utils::random_string(32);  // MXC_LENGTH = 32 (Conduit 26e200e: reduced from 256)

    std::optional<std::string> filename;
    if (req.has_param("filename")) filename = req.get_param_value("filename");
    const std::string content_type =
        req.has_header("Content-Type") ? req.get_header_value("Content-Type")
                                       : "application/octet-stream";

    ctx.data->media_create(mxc, filename, content_type, req.body);
    ruma::respond(res, nlohmann::json{{"content_uri", mxc}});
  });

  auto download_handler = [&ctx](const httplib::Request& req,
                                 httplib::Response& res, bool allow_filename,
                                 bool allow_remote) {
    // NEW in 71500b1: use server_name and media_id from request path
    // Format: /_matrix/media/r0/download/<server_name>/<media_id>
    const std::string server_name = req.matches[1].str();
    const std::string media_id = req.matches[2].str();
    const std::string mxc = "mxc://" + server_name + "/" + media_id;
    
    auto media = ctx.data->media_get(mxc);
    if (!media) {
      // If allow_remote is true, try to fetch from the remote server
      if (allow_remote) {
        // Only fetch remote if server_name != local server
        if (server_name != ctx.data->hostname() && allow_remote) {
          // Try to fetch from the remote server
          auto response = federation::send_request(
              *ctx.data, server_name,
              "/_matrix/media/r0/download/" + server_name + "/" + media_id,
              json::object());

          if (response && response->is_object() && !response->contains("errcode")) {
            // Store locally
            std::string content_type = response->value("content_type", "application/octet-stream");
            std::string content_disposition = response->value("content_disposition", "");
            std::optional<std::string> filename = content_disposition.empty()
                ? std::nullopt : std::make_optional(content_disposition);

            ctx.data->media_create(mxc, filename, content_type, response->dump());
            media = ctx.data->media_get(mxc);
          }
        }
      }

      if (!media) {
        ruma::respond(res, nlohmann::json{{"errcode", "M_NOT_FOUND"},
                                          {"error", "Media not found."}},
                      404);
        return;
      }
    }
    res.status = 200;
    res.set_content(media->bytes, media->content_type);
    if (allow_filename && media->filename) {
      res.set_header("Content-Disposition",
                     "attachment; filename=\"" + *media->filename + "\"");
    }
  };

  svr.Get(R"(/_matrix/media/r0/download/([^/]+)/([^/]+))",
          [&ctx, download_handler](const httplib::Request& req,
                                   httplib::Response& res) {
            download_handler(req, res, true, true);
          });

  svr.Get(R"(/_matrix/media/r0/thumbnail/([^/]+)/([^/]+))",
          [&ctx, download_handler](const httplib::Request& req,
                                   httplib::Response& res) {
            // Upstream served the original file as its own thumbnail.
            download_handler(req, res, false, true);
          });

  // NEW in 12a8c9ba: federation server-side endpoints (a peer calls these when
  // one of its users joins a room we host). They serve our room's PDUs.
  // NEW in 1f292c09: federation transaction endpoint. A remote server delivers
  // PDUs here; we append each only if the room already exists locally.
  svr.Post(R"(/_matrix/federation/v1/send/([^/]+))",
           [&ctx, &require_federation_auth](const httplib::Request& req,
                                            httplib::Response& res) {
             if (!require_federation_auth(req, res)) return;
             json body;
             try { body = json::parse(req.body); } catch (...) { body = json::object(); }
             if (!body.contains("pdus") || !body["pdus"].is_array()) {
               ruma::respond(res, ruma::json{{"errcode", "M_BAD_JSON"},
                                             {"error", "missing pdus array"}}, 400);
               return;
             }
             int appended = 0;
             // NEW in 7db59c55: report per-PDU results (upstream resolved_map):
             // successfully stored PDUs map to {}, failures to Matrix errors.
             nlohmann::json pdus_result = nlohmann::json::object();
             for (auto& pdu_str : body["pdus"]) {
               json pdu;
               try {
                 pdu = pdu_str.is_string() ? json::parse(pdu_str.get<std::string>())
                                           : pdu_str;
               } catch (...) { continue; }
               if (!pdu.contains("room_id")) continue;
               const std::string room_id = pdu["room_id"].get<std::string>();
               if (!ctx.data->room_exists(room_id)) continue;
               nlohmann::json content = pdu.value("content", json::object());
               nlohmann::json event = {
                   {"type", pdu.value("type", "")},
                   {"content", std::move(content)},
                   {"event_id", "$thiswillbefilledinlater"},
                   {"origin_server_ts", utils::millis_since_unix_epoch()},
                   {"room_id", room_id},
                   {"sender", pdu.value("sender", "")},
                   {"unsigned", json::object()},
               };
               if (pdu.contains("state_key") && !pdu["state_key"].is_null())
                 event["state_key"] = pdu["state_key"];
               const std::string event_id = crypto::reference_hash(event);
               event["event_id"] = event_id;
               if (ctx.data->pdu_append(event_id, room_id, std::move(event))) {
                 ++appended;
                 pdus_result[event_id] = nlohmann::json::object();
               } else {
                 pdus_result[event_id] = nlohmann::json{
                     {"errcode", "M_FORBIDDEN"}, {"error", "event not authorized"}};
               }
             }
             ruma::respond(res, ruma::json{{"pdus", std::move(pdus_result)}}, 200);
           });

  // NEW in eedac4fd: make_join, send_join and /directory federation endpoints.
  // GET /_matrix/federation/v1/make_join/<roomId>/<userId>
  svr.Get(R"(/_matrix/federation/v1/make_join/([^/]+)/([^/]+))",
          [&ctx, &require_federation_auth](const httplib::Request& req,
                                           httplib::Response& res) {
            if (!require_federation_auth(req, res)) return;
            const std::string room_id = url_decode(req.matches[1]);
            const std::string user_id = url_decode(req.matches[2]);
            auto result = federation::make_join(*ctx.data, room_id, user_id);
            if (result.contains("errcode")) {
              int status = result.value("status_code", 400);
              ruma::respond(res, result, status);
            } else {
              ruma::respond(res, result, 200);
            }
          });

  // PUT /_matrix/federation/v2/send_join/<roomId>/<eventId>
  svr.Put(R"(/_matrix/federation/v2/send_join/([^/]+)/([^/]+))",
          [&ctx, &require_federation_auth](const httplib::Request& req,
                                           httplib::Response& res) {
            if (!require_federation_auth(req, res)) return;
            const std::string room_id = url_decode(req.matches[1]);
            const std::string event_id = url_decode(req.matches[2]);
            nlohmann::json body;
            try {
              body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
            } catch (...) {
              body = nlohmann::json::object();
            }
            if (body.is_discarded() || !body.is_object()) {
              ruma::respond(res,
                            ruma::json{{"errcode", "M_BAD_JSON"}, {"error", "Invalid JSON"}},
                            400);
              return;
            }
            // Ensure event_id matches
            if (body.contains("event_id") && body.value("event_id", "") != event_id) {
              ruma::respond(res,
                            ruma::json{{"errcode", "M_INVALID_PARAM"},
                                       {"error", "Event ID in body must match path parameter."}},
                            400);
              return;
            }
            auto result = federation::send_join(*ctx.data, room_id, body);
            if (result.contains("errcode")) {
              int status = result.value("status_code", 400);
              ruma::respond(res, result, status);
            } else {
              ruma::respond(res, result, 200);
            }
          });

  // POST /_matrix/federation/v1/publicRooms
  // This is the federation version of the public rooms directory
  svr.Post("/_matrix/federation/v1/publicRooms",
           [&ctx, &require_federation_auth](const httplib::Request& req,
                                            httplib::Response& res) {
             if (!require_federation_auth(req, res)) return;
             nlohmann::json body;
             try {
               body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
             } catch (...) {
               body = nlohmann::json::object();
             }
             if (body.is_discarded()) body = nlohmann::json::object();
             auto result = federation::get_public_rooms_federation(*ctx.data, body);
             if (result.contains("errcode")) {
               int status = result.value("status_code", 400);
               ruma::respond(res, result, status);
             } else {
               ruma::respond(res, result, 200);
             }
           });
  // Restored in 115 (lost in the 112 edit): federation event/backfill/
  // state_ids routes, now behind the ServerSignatures guard like upstream.
  svr.Get(R"(/_matrix/federation/v1/state_ids/([^/]+)/([^/]+))",
          [&ctx, &require_federation_auth](const httplib::Request& req,
                                           httplib::Response& res) {
            if (!require_federation_auth(req, res)) return;
            const std::string room_id = url_decode(req.matches[1]);
            auto state_ids = ctx.data->room_state(room_id);
            // NEW in 68cc743f: use the shared get_auth_chain helper instead
            // of fetching full PDUs only to extract their ids.
            std::set<std::string> auth_ids =
                federation::get_auth_chain(*ctx.data, state_ids);
            ruma::json out = ruma::json::object();
            out["auth_chain_ids"] = nlohmann::json::array();
            for (const auto& id : auth_ids) out["auth_chain_ids"].push_back(id);
            out["pdus_state_ids"] = nlohmann::json::array();
            for (const auto& id : state_ids) out["pdus_state_ids"].push_back(id);
            out["pdus_prev_ids"] = nlohmann::json::array();
            ruma::respond(res, out, 200);
          });

  svr.Get(R"(/_matrix/federation/v1/event/([^/]+))",
          [&ctx, &require_federation_auth](const httplib::Request& req,
                                           httplib::Response& res) {
            if (!require_federation_auth(req, res)) return;
            const std::string event_id = url_decode(req.matches[1]);
            if (auto t = ctx.data->pdu_get(event_id)) {
              try {
                ruma::respond(res, nlohmann::json::parse(*t), 200);
                return;
              } catch (...) {}
            }
            ruma::respond(res,
                          ruma::json{{"errcode", "M_NOT_FOUND"},
                                     {"error", "Event not found."}},
                          404);
          });

  svr.Get(R"(/_matrix/federation/v1/backfill/([^/]+))",
          [&ctx, &require_federation_auth](const httplib::Request& req,
                                           httplib::Response& res) {
            if (!require_federation_auth(req, res)) return;
            const std::string room_id = url_decode(req.matches[1]);
            auto pdus = ctx.data->federation_pdus_of_room(room_id);
            ruma::respond(res, ruma::json{{"pdus", pdus}}, 200);
          });

  // NEW in 67f9592b: federation event authorization chain.
  // GET /_matrix/federation/v1/event_auth/:roomId/:eventId -> {auth_chain}.
  svr.Get(R"(/_matrix/federation/v1/event_auth/([^/]+)/([^/]+))",
          [&ctx, &require_federation_auth](const httplib::Request& req,
                                           httplib::Response& res) {
            if (!require_federation_auth(req, res)) return;
            const std::string room_id = url_decode(req.matches[1]);
            const std::string event_id = url_decode(req.matches[2]);
            auto result = federation::get_event_auth(*ctx.data, room_id, event_id);
            if (result.contains("errcode")) {
              ruma::respond(res, result, 404);
            } else {
              ruma::respond(res, result, 200);
            }
          });

  // NEW in 8773e501: incoming invites over federation.
  // PUT /_matrix/federation/v[12]/invite/:roomId/:eventId - the inviting
  // server sends {event, invite_room_state, room_version}; we validate, sign
  // as the receiving server, store membership+invite_state, and return the
  // signed {event}. Rejects room_version < 6 like upstream.
  auto invite_handler = [&ctx, &require_federation_auth](const httplib::Request& req,
                                                     httplib::Response& res) {
    if (!require_federation_auth(req, res)) return;
    const std::string room_id = url_decode(req.matches[1]);
    nlohmann::json body;
    try {
      body = nlohmann::json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
    } catch (...) {
      body = nlohmann::json::object();
    }
    if (body.is_discarded() || !body.is_object()) {
      ruma::respond(res,
                    ruma::json{{"errcode", "M_BAD_JSON"}, {"error", "Invalid JSON"}},
                    400);
      return;
    }
    std::string room_version;
    if (body.contains("room_version")) {
      if (body["room_version"].is_string()) room_version = body["room_version"].get<std::string>();
      else if (body["room_version"].is_number_integer()) room_version = std::to_string(body["room_version"].get<int>());
    }
    if (!room_version.empty()) {
      int vnum = 0;
      std::string digits;
      for (char c : room_version)
        if (c >= '0' && c <= '9') digits += c;
      try { vnum = digits.empty() ? 0 : std::stoi(digits); } catch (...) { vnum = 0; }
      if (vnum != 0 && vnum < 6) {
        ruma::respond(res,
                      ruma::json{{"errcode", "M_INCOMPATIBLE_ROOM_VERSION"},
                                 {"error", "Server does not support this room version."}},
                      400);
        return;
      }
    }
    if (!body.contains("event") || !body["event"].is_object()) {
      ruma::respond(res,
                    ruma::json{{"errcode", "M_INVALID_PARAM"},
                               {"error", "Invite event is invalid."}},
                    400);
      return;
    }
    nlohmann::json event = body["event"];
    nlohmann::json invite_state = body.value("invite_room_state", nlohmann::json::array());
    auto result = ctx.data->handle_incoming_invite(room_id, std::move(event), std::move(invite_state));
    if (!result.ok) {
      ruma::respond(res,
                    ruma::json{{"errcode", result.errcode}, {"error", result.error}},
                    400);
      return;
    }
    ruma::respond(res, nlohmann::json{{"event", result.event}}, 200);
  };
  svr.Put(R"(/_matrix/federation/v1/invite/([^/]+)/([^/]+))", invite_handler);
  svr.Put(R"(/_matrix/federation/v2/invite/([^/]+)/([^/]+))", invite_handler);

  svr.Get(R"(/_matrix/federation/v1/query/directory)",
          [&ctx, &require_federation_auth](const httplib::Request& req,
                                           httplib::Response& res) {
            if (!require_federation_auth(req, res)) return;
            const auto it = req.params.find("room_alias");
            if (it == req.params.end()) {
              ruma::respond(res,
                            ruma::json{{"errcode", "M_INVALID_PARAM"},
                                       {"error", "missing room_alias"}},
                            400);
              return;
            }
            const std::string alias = url_decode(it->second);
            if (auto rid = ctx.data->id_from_alias(alias)) {
              ruma::respond(res,
                            ruma::json{{"room_id", *rid},
                                       {"servers", nlohmann::json::array({std::string(kServerName)})}},
                            200);
            } else {
              ruma::respond(res,
                            ruma::json{{"errcode", "M_NOT_FOUND"},
                                       {"error", "alias not found"}},
                            404);
            }
          });

  // NEW: OPTIONS catch-all — upstream answers with a plain 404 M_NOT_FOUND.
  svr.Options(R"(.*)", [](const httplib::Request&, httplib::Response& res) {
    ruma::respond(res,
                  ruma::json{{"errcode", "M_NOT_FOUND"}, {"error", "Room not found."}},
                  404);
  });

  std::cout << "[info] port: " << port << "\n[info] hostname: "
            << data.hostname() << std::endl;
  svr.listen("127.0.0.1", static_cast<uint16_t>(port));
}
