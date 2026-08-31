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
#include "rate_limiting.hpp"
#include "data.hpp"
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

// NEW in f7816b11d: best-effort delivery of a locally-appended PDU to the
// other servers participating in the room. No-op for rooms with no remote
// servers (i.e. local-only rooms). Never throws into the caller.
void federation_send_to_remotes(Context* ctx, const std::string& room_id,
                                 const std::string& pdu_json) {
  try {
    // NEW in 1bf614b0f: the locally-stored PDU carries an unsigned
    // transaction_id used for client deduplication; it must not be sent to
    // other servers over federation.
    json pdu = json::parse(pdu_json);
    if (pdu.is_object() && pdu.contains("unsigned") &&
        pdu["unsigned"].is_object())
      pdu["unsigned"].erase("transaction_id");
    // NEW in f4078a29e: synapse rejects federation PDUs without an `origin`
    // (it is required by the spec); stamp it before delivery.
    if (pdu.is_object()) pdu["origin"] = kServerName;
    for (const auto& srv : ctx->data->room_servers(room_id)) {
      if (srv == ctx->data->hostname()) continue;
      const std::string txn = utils::random_string(16);
      federation::send_request(ctx->data->hostname(), ctx->data->keypair(), srv,
                               "/_matrix/federation/v1/send/" + txn, pdu);
    }
  } catch (...) { /* federation delivery is best-effort */ }
}

// NEW in b7ab57897: federation delivery must not slow down the client request.
// Hand the (best-effort, possibly blocking) send off to a detached background
// thread so the event returns to the client immediately.
void federation_send_background(Context* ctx, const std::string& room_id,
                               std::string pdu_json) {
  std::thread([ctx, room_id, pdu_json = std::move(pdu_json)]() mutable {
    federation_send_to_remotes(ctx, room_id, std::move(pdu_json));
  }).detach();
}

bool localpart_valid(const std::string& localpart) {
  // What UserId's TryFrom checked in ruma-identifiers 0.14, tightened in
  // 3248efbe4b to the strict grammar: drop '+' (and uppercase/'~' were already
  // disallowed). Kept in sync with handlers.cpp.
  if (localpart.empty()) return false;
  for (const char c : localpart) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == '=' || c == '-' || c == '/';
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
          .versions = {"r0.6.0", "v1.6", "v1.7", "v1.8", "v1.9", "v1.10",
                       "v1.11", "v1.12"},
          // NEW in a6797ca0a2: advertise MSC3916 (authenticated media) support.
          // Our ruma models unstable_features as map<string,string>, so the flag
          // value is the string "true" (Conduit uses bool; semantically identical).
          .unstable_features = {{"org.matrix.msc3916.stable", "true"}},
      });
}

// NEW in abcce95d (+ folded prerequisite createRoom).
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
  append_state("m.room.power_levels",
               json{{"ban", 50},
                    {"events_default", 0},
                    {"invite", 50},
                    {"kick", 50},
                    {"redact", 50},
                    {"state_default", 50},
                    {"users", {{creator, 100}}},
                    {"users_default", 0}},
               "");

  if (body.name) {
    append_state("m.room.name", json{{"name", *body.name}}, "");
  }
  if (body.topic) {
    append_state("m.room.topic", json{{"topic", *body.topic}}, "");
  }

  // NEW in 3aa0c8ed: visibility + alias creation.
  if (body.visibility == "public") ctx->data->set_public(room_id, true);

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

  for (const auto& invitee : body.invite) {
    ctx->data->room_invite(creator, room_id, invitee);
  }

  return ruma::MatrixResult<ruma::CreateRoomResponse>::ok(
      ruma::CreateRoomResponse{.room_id = room_id});
}

void invite_user_route(Context* ctx, const ruma::InviteRequest& body,
                       httplib::Response& res) {
  if (!body.user_id.empty() && !body.target.empty()) {
    if (!ctx->data->room_invite(body.user_id, body.room_id, body.target,
                                body.reason)) {
      ruma::respond(res,
                    nlohmann::json{{"errcode", "M_FORBIDDEN"},
                                   {"error", "event not authorized"}},
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
  nlohmann::json results = nlohmann::json::array();
  for (const auto& user : ctx->data->users_all()) {
    if (ctx->data->is_deactivated(user)) continue;  // NEW in b8193984
    if (user.find(body.search_term) != std::string::npos) {
      results.push_back(json{{"user_id", user}});
    }
  }
  ruma::respond(res, json{{"results", results}, {"limited", false}});
}

// Better public room directory (abcce95d): names from room_state, sorted by
// member count descending.
ruma::MatrixResult<ruma::PublicRoomsResponse> get_public_rooms_filtered_route(
    Context* ctx, const std::string& search = "") {
  ruma::PublicRoomsResponse resp;

  auto ci_contains = [](const std::string& hay, const std::string& needle) {
    if (needle.empty()) return true;
    auto lower = [](std::string s) {
      std::transform(s.begin(), s.end(), s.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      return s;
    };
    return lower(hay).find(lower(needle)) != std::string::npos;
  };

  struct Entry {
    std::string room_id;
    long members;
    std::optional<std::string> name;
  };
  std::vector<Entry> entries;
  // 3aa0c8ed: only rooms explicitly marked public appear.
  for (const auto& room : ctx->data->public_rooms()) {
    entries.push_back({room, static_cast<long>(ctx->data->room_users(room)), std::nullopt});
    for (const auto& pdu_text : ctx->data->room_state(room)) {
      auto pdu = nlohmann::json::parse(pdu_text);
      if (pdu.value("type", "") == "m.room.name") {
        entries.back().name = pdu["content"].value("name", "");
        break;
      }
    }
  }

  // NEW in 9f05ef926: honour the public-room directory search term.
  if (!search.empty()) {
    std::vector<Entry> filtered;
    for (auto& e : entries) {
      if (ci_contains(e.room_id, search) ||
          (e.name && ci_contains(*e.name, search)))
        filtered.push_back(std::move(e));
    }
    entries = std::move(filtered);
  }

  std::sort(entries.begin(), entries.end(),
            [](const Entry& l, const Entry& r) { return l.members > r.members; });

  for (const auto& e : entries) {
    nlohmann::json chunk_entry{
        {"guest_can_join", true},
        {"num_joined_members", e.members},
        {"room_id", e.room_id},
        {"world_readable", false},
    };
    if (e.name) chunk_entry["name"] = *e.name;
    resp.chunk.push_back(std::move(chunk_entry));
  }

  // Sort local rooms first (abcce95d), THEN extend with federated rooms
  // (720cc0cf moved this sort before the extend).

  // NEW in 720cc0cf: federated room directory — ask chat.privacytools.io for
  // its public rooms and append them after the local ones, then sort.
  // (Upstream sorted only after merging; we mirror that order.)
  if (auto remote = federation::send_request(
          ctx->data->hostname(), ctx->data->keypair(), "privacytools.io",
          "/_matrix/federation/v1/publicRooms", json::object())) {
    if (auto chunk = remote->find("chunk"); chunk != remote->end() && chunk->is_array())
      resp.chunk.insert(resp.chunk.end(), chunk->begin(), chunk->end());
    if (auto total = remote->find("total_room_count_estimate");
        total != remote->end() && total->is_number_unsigned())
      resp.federation_rooms = total->get<size_t>();
  }
  resp.total_room_count_estimate =
      entries.size() + resp.federation_rooms;

  return ruma::MatrixResult<ruma::PublicRoomsResponse>::ok(std::move(resp));
}

// 9c26e22a/3aa0c8ed: aliases resolved from the database.
ruma::MatrixResult<ruma::GetAliasResponse> get_alias_route(
    Context* ctx, const std::string& room_alias) {
  auto room_id = ctx->data->id_from_alias(room_alias);
  if (!room_id) {
    std::cerr << "[debug] Room alias not found.\n";
    return ruma::MatrixResult<ruma::GetAliasResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::NotFound,
        .message = "Room not found.",
        .status_code = 404,
    });
  }
  return ruma::MatrixResult<ruma::GetAliasResponse>::ok(ruma::GetAliasResponse{
      .room_id = *room_id,
      .servers = {ctx->data->hostname()},
  });
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

  // NEW in f7816b11d: deliver the new PDU to any remote servers in the room.
  // b7ab57897: do it off the request path so sending never blocks the client.
  if (auto pdu_text = ctx->data->pdu_get(event_id))
    federation_send_background(ctx, body.room_id, *pdu_text);

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
    resp.joined.emplace(room_id, std::move(joined));
  }

  // NEW in abcce95d: invited rooms carry stripped state events.
  for (const auto& room_id : ctx->data->rooms_invited(user_id)) {
    ruma::SyncResponse invited;
    invited.joined_room_id = room_id;
    for (const auto& pdu_text : ctx->data->room_state(room_id)) {
      invited.stripped_state.push_back(pdu_text);
    }
    resp.invited.emplace(room_id, std::move(invited));
  }

  return ruma::MatrixResult<ruma::SyncResponse>::ok(std::move(resp));
}

}  // namespace

int main(int argc, char** argv) {
  ::signal(SIGPIPE, SIG_IGN);

  int port = static_cast<int>(kListenPort);
  std::string dir_override;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) port = std::stoi(argv[++i]);
    if (arg == "--data-dir" && i + 1 < argc) dir_override = argv[++i];
  }

  std::filesystem::path data_dir;
  if (!dir_override.empty()) {
    data_dir = dir_override;
  } else {
    const char* home = ::getenv("HOME");
    data_dir = (home ? std::filesystem::path{home} : std::filesystem::path{"/tmp"}) /
               ".local/share/conduit-step45";
  }

  static Data data = Data::load_or_create(data_dir);
  data.set_hostname("localhost");
  // NEW in c1f69565: optional .well-known overrides (mirror conduit.toml
  // [global.well_known] client/server); unset => Conduit defaults.
  if (const char* c = ::getenv("WELL_KNOWN_CLIENT")) data.set_well_known_client(c);
  if (const char* s = ::getenv("WELL_KNOWN_SERVER")) data.set_well_known_server(s);
  static Context ctx{&data};

  // NEW in 11a9d053b0: rate limiting. Conduit's implementation lives behind an
  // elaborate preset/shadow config DSL + a dedicated service; our port keeps the
  // observable behaviour (sliding-window limit per action + IP/token, returning
  // M_LIMIT_EXCEEDED with retry_after_ms) with hard-coded PrivateSmall defaults.
  rate_limiting::RateLimiter rl;
  ctx.rate_limiter = &rl;

  httplib::Server svr;

  // NEW in 63ba157e: reject incoming federation requests whose X-Matrix
  // `destination` does not match our server name (Conduit's axum ruma_wrapper
  // auth check, applied to every request via the pre-routing handler; client
  // requests carry no X-Matrix header so they pass through untouched).
  // NEW in a87f4b6171: also reject oversized request bodies with 413
  // (M_TOO_LARGE), mirroring Conduit's request-size limit. We check the
  // Content-Length header here and return the exact Matrix error body; a
  // payload_max_length backstop below covers chunked/streamed bodies.
  svr.set_pre_routing_handler([&ctx](const httplib::Request& req,
                                      httplib::Response& res) {
    // NEW in 11a9d053b0: rate limiting. Bucket by (action, IP+token) in a
    // sliding window; on overflow reply 429 M_LIMIT_EXCEEDED with retry_after_ms,
    // mirroring Conduit's rate_limiting service.
    if (ctx.rate_limiter) {
      rate_limiting::Restriction r = rate_limiting::classify(req);
      if (r != rate_limiting::Restriction::Unknown) {
        std::string key = req.remote_addr + "\n";
        if (auto t = extract_token(req)) key += *t;
        else key += "-";
        int64_t retry_ms = 0;
        if (!ctx.rate_limiter->check(r, key, retry_ms)) {
          res.status = 429;
          res.set_header("Content-Type", "application/json");
          res.set_content(
              R"({"errcode":"M_LIMIT_EXCEEDED","error":"Too many requests.","retry_after_ms":)" +
                  std::to_string(retry_ms) + "}",
              "application/json");
          return httplib::Server::HandlerResponse::Handled;
        }
      }
    }
    const std::string cl = req.get_header_value("Content-Length");
    if (!cl.empty()) {
      try {
        if (std::stoull(cl) > 20ULL * 1024 * 1024) {
          res.status = 413;
          res.set_content(
              R"({"errcode":"M_TOO_LARGE","error":"Reached maximum request size"})",
              "application/json");
          return httplib::Server::HandlerResponse::Handled;
        }
      } catch (...) {
      }
    }
    if (!federation::xmatrix_destination_ok(req.get_header_value("Authorization"),
                                            ctx.data->hostname())) {
      res.status = 401;
      res.set_header("Content-Type", "application/json");
      res.set_content(
          R"({"errcode":"M_FORBIDDEN","error":"X-Matrix destination field does not match server name."})",
          "application/json");
      return httplib::Server::HandlerResponse::Handled;
    }
    return httplib::Server::HandlerResponse::Unhandled;
  });

  // NEW in 1dbb3433e: add a Content-Security-Policy header to every response to
  // prevent any potential XSS via the media repo (Conduit's set_csp_header
  // axum middleware, applied globally to all responses).
  svr.set_post_routing_handler([](const httplib::Request&,
                                  httplib::Response& res) {
    res.set_header("Content-Security-Policy",
                   "sandbox; default-src 'none'; script-src 'none'; "
                   "plugin-types application/pdf; style-src 'unsafe-inline'; "
                   "object-src 'self';");
  });

  // NEW in a87f4b6171: backstop for bodies without a Content-Length (chunked /
  // streamed) — httplib returns 413 Payload Too Large past this limit.
  svr.set_payload_max_length(20ULL * 1024 * 1024);

  svr.Get("/_matrix/client/versions", [](const httplib::Request&, httplib::Response& res) {
    ruma::respond(res, get_supported_versions_route());
  });

  // NEW in c1f69565: GET /.well-known/matrix/client — client discovery.
  // Mirrors Conduit's src/api/client_server/well_known.rs
  // (ruma discover_homeserver::Response: m.homeserver.base_url +
  //  org.matrix.msc3575.proxy.url; identity_server omitted when None).
  svr.Get("/.well-known/matrix/client",
          [&ctx](const httplib::Request&, httplib::Response& res) {
            const std::string client_url = ctx.data->well_known_client();
            nlohmann::json body{
                {"m.homeserver", {{"base_url", client_url}}},
                {"org.matrix.msc3575.proxy", {{"url", client_url}}}};
            res.set_content(body.dump(), "application/json");
          });

  svr.Post("/_matrix/client/r0/register", [&ctx](const httplib::Request& req,
                                                 httplib::Response& res) {
    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded()) body = nlohmann::json::object();

    const std::string username = body.value("username", "");
    nlohmann::json auth;
    if (auto a = body.find("auth"); a != body.end() && a->is_object())
      auth = *a;

    // --- UIAA (b106d139-era flow formalized by c85d363d) -------------------
    if (!auth.contains("type")) {
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
      ctx.data->uiaa_create("@pending:" + session, "", uiaainfo);
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
             }              std::string room_id = req.matches[1];
              // NEW in c5313b3e: when joining by alias, the response's
              // `servers` field is the candidate list for federation. We
              // first try local id_from_alias, then fall back to a remote
              // query/directory call to the alias's home server.
              std::vector<std::string> alias_servers;
              if (room_id.rfind("#", 0) == 0) {
                auto resolved = ctx.data->id_from_alias(room_id);
                if (resolved) {
                  room_id = *resolved;
                } else {
                  // Alias not local — ask the alias's home server
                  // (the part after `:`) for the room_id and a list of
                  // candidate servers. Mirrors Conduit's get_alias_helper.
                  const size_t acolon = room_id.find(':');
                  const std::string ahome =
                      acolon == std::string::npos
                          ? std::string()
                          : room_id.substr(acolon + 1);
                  if (!ahome.empty() && ahome != kServerName) {
                    const std::string qpath =
                        "/_matrix/federation/v1/query/directory?room_alias=" +
                        room_id;
                    auto qresp = federation::send_request(
                        ctx.data->hostname(), ctx.data->keypair(), ahome,
                        qpath);
                    if (qresp && qresp->contains("room_id")) {
                      room_id = (*qresp)["room_id"].get<std::string>();
                      if (qresp->contains("servers") &&
                          (*qresp)["servers"].is_array()) {
                        for (const auto& s : (*qresp)["servers"])
                          if (s.is_string())
                            alias_servers.push_back(s.get<std::string>());
                      }
                      if (alias_servers.empty()) alias_servers.push_back(ahome);
                    } else {
                      ruma::respond(res,
                                    nlohmann::json{{"errcode", "M_NOT_FOUND"},
                                                   {"error",
                                                    "Room alias not found."}},
                                    404);
                      return;
                    }
                  } else {
                    ruma::respond(res,
                                  nlohmann::json{{"errcode", "M_NOT_FOUND"},
                                                 {"error",
                                                  "Room alias not found."}},
                                  404);
                    return;
                  }
                }
              }

              // NEW in 12a8c9ba: federation join. If the room lives on another
              // server, fetch its state over federation, persist it locally, and
              // append our own join event. (Untested locally — needs a peer.)
              // NEW in c5313b3e: try each candidate server in turn. For room_id
              // joins the list is just [room's home server]; for alias joins it
              // is the `servers` field from the alias resolution response.
              const size_t fcolon = room_id.find(':');
              const std::string fremote =
                  fcolon == std::string::npos ? std::string() : room_id.substr(fcolon + 1);
              if (!fremote.empty() && fremote != kServerName) {
                // If the join came from an alias resolution, the candidate
                // list came from the alias's servers field; otherwise we
                // start with just the room's home server.
                std::vector<std::string> servers =
                    alias_servers.empty()
                        ? std::vector<std::string>{fremote}
                        : alias_servers;
                bool joined = false;
                std::string join_event_id;
                for (const auto& srv : servers) {
                  // Step 1: make_join — the remote returns an unsigned join
                  // event template with auth_events + prev_events filled in.
                  // We use this as the skeleton, then sign + echo back via
                  // send_join.
                  const std::string mjpath =
                      "/_matrix/federation/v1/make_join/" + room_id + "/" + *user;
                  auto mjresp = federation::send_request(
                      ctx.data->hostname(), ctx.data->keypair(), srv, mjpath);
                  if (!mjresp) continue;
                  if (!mjresp->contains("event")) continue;
                  nlohmann::json join_event = (*mjresp)["event"];
                  if (join_event.contains("content") &&
                      join_event["content"].is_object()) {
                    join_event["content"]["membership"] = "join";
                  }
                  if (auto fdn = ctx.data->displayname_get(*user))
                    join_event["content"]["displayname"] = *fdn;
                  join_event["origin_server_ts"] = utils::millis_since_unix_epoch();
                  join_event["event_id"] = "$thiswillbefilledinlater";
                  join_event["unsigned"] = json::object();
                  join_event_id = crypto::reference_hash(join_event);
                  join_event["event_id"] = join_event_id;

                  // Step 2: send_join — the remote merges our join event into
                  // the room and returns the full state + auth_chain for our
                  // local cache.
                  const std::string fpath =
                      "/_matrix/federation/v1/send_join/" + room_id + "/" +
                      join_event_id;
                  auto fresp = federation::send_request(
                      ctx.data->hostname(), ctx.data->keypair(), srv, fpath);
                  if (!fresp) continue;
                  for (const char* key : {"auth_chain", "state"}) {
                    if ((*fresp).contains(key) && (*fresp)[key].is_array()) {
                      for (auto& pdu : (*fresp)[key]) {
                        if (pdu.contains("event_id") && pdu.contains("room_id")) {
                          const std::string eid = pdu["event_id"].get<std::string>();
                          if (!ctx.data->pdu_get(eid))
                            ctx.data->pdu_append(eid, room_id, pdu);
                        }
                      }
                    }
                  }
                  ctx.data->pdu_append(join_event_id, room_id, std::move(join_event));
                  federation::send_request(ctx.data->hostname(), ctx.data->keypair(), srv,
                                           "/_matrix/federation/v1/send/" + room_id + "/",
                                           json::object());
                  joined = true;
                  break;
                }
                if (!joined) {
                  ruma::respond(res,
                                nlohmann::json{{"errcode", "M_UNKNOWN"},
                                           {"error", "Failed to contact any remote server "
                                                     "for federation join."}},
                                502);
                  return;
                }
                ruma::respond(res, nlohmann::json{{"room_id", room_id}});
                return;
              }            if (!ctx.data->room_join(room_id, *user)) {
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
              json body;
              try {
                body = json::parse(req.body);
              } catch (...) {
                body = json::object();
              }
              const std::string reason = body.value("reason", "");
              if (!ctx.data->room_leave(req.matches[1], *user, reason)) {
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
      ruma::respond(res, ruma::json{{"errcode", "M_FORBIDDEN"},
                                    {"error", "You don't have permission to view this room."}}, 403);
      return;
    }
    for (const auto& pdu_text : ctx.data->room_state_type(room_id, type)) {
      auto pdu = nlohmann::json::parse(pdu_text);
      if (pdu.value("state_key", "") == state_key) {
        // NEW in bc5145f092: support ?format=event to return the full state
        // event (matching Conduit's get_state_event_for_key format param); the
        // default (and ?format=content) returns just the event content.
        const std::string fmt = req.get_param_value("format");
        ruma::respond(res, (fmt == "event") ? pdu : pdu["content"]);
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
    std::string search;
    try {
      auto body = json::parse(req.body);
      if (body.contains("filter") && body["filter"].contains("generic_search_term"))
        search = body["filter"]["generic_search_term"].get<std::string>();
    } catch (...) {}
    ruma::respond(res, get_public_rooms_filtered_route(&ctx, search));
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

  // GET /.well-known/matrix/server — delegation hint. NEW in c1f69565: the
  // advertised server name now defaults to <host>:443 when no port is set
  // (matching Conduit's well_known_server()); overridable via WELL_KNOWN_SERVER.
  svr.Get("/.well-known/matrix/server",
          [&ctx](const httplib::Request&, httplib::Response& res) {
            res.set_content(
                nlohmann::json{{"m.server", ctx.data->well_known_server()}}.dump(),
                "application/json");
          });

  // GET /_matrix/federation/v1/version
  svr.Get("/_matrix/federation/v1/version",
          [](const httplib::Request&, httplib::Response& res) {
            ruma::respond(res, nlohmann::json{
                                   {"server",
                                    {{"name", "Conduit"}, {"version", "0.1.0"}}}});
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

  // NEW in b8193984: POST /account/deactivate — UIAA, leave/reject rooms,
  // remove devices, blank password.
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
            ctx.data->pdu_append(event_id, room_id, std::move(event));
            ctx.data->redact_pdu(target_event);

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
        utils::random_string(256);  // MXC_LENGTH = 256 upstream

    std::optional<std::string> filename;
    if (req.has_param("filename")) filename = req.get_param_value("filename");
    const std::string content_type =
        req.has_header("Content-Type") ? req.get_header_value("Content-Type")
                                       : "application/octet-stream";

    ctx.data->media_create(mxc, filename, content_type, req.body);
    ruma::respond(res, nlohmann::json{{"content_uri", mxc}});
  });

  // 1dbb3433e0 reverts the 965b6df83 content-type forcing: instead of
  // reporting application/octet-stream, media endpoints return the real stored
  // Content-Type and rely on the global Content-Security-Policy header added
  // above to sandbox any rendered media.
  auto download_handler = [&ctx](const httplib::Request& req,
                                 httplib::Response& res, bool allow_filename,
                                 bool allow_remote) {
    const std::string server = req.matches[1].str();
    const std::string mxc =
        "mxc://" + server + "/" + req.matches[2].str();
    // NEW in 71500b14b: only serve (or proxy) media for our own server unless
    // the caller explicitly allows remote media.
    if (server != std::string(kServerName) && !allow_remote) {
      ruma::respond(res, nlohmann::json{{"errcode", "M_NOT_FOUND"},
                                        {"error", "Media not found."}},
                    404);
      return;
    }
    auto media = ctx.data->media_get(mxc);
    if (!media) {
      ruma::respond(res, nlohmann::json{{"errcode", "M_NOT_FOUND"},
                                        {"error", "Media not found."}},
                    404);
      return;
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

  // NEW in aa5e9e60: federation media — a peer downloads our media/thumbnails.
  svr.Get(R"(/_matrix/federation/v1/media/download/([^/]+)/([^/]+))",
          [&ctx, download_handler](const httplib::Request& req,
                                    httplib::Response& res) {
            download_handler(req, res, true, true);
          });

  svr.Get(R"(/_matrix/federation/v1/media/thumbnail/([^/]+)/([^/]+))",
          [&ctx, download_handler](const httplib::Request& req,
                                    httplib::Response& res) {
            download_handler(req, res, false, true);
          });

  // NEW in 27d6d9435: MSC3916 authenticated media. The client v1 endpoints
  // require a valid access token (unlike the unauthenticated r0 media routes).
  auto v1_media_auth = [&ctx](const httplib::Request& req,
                              httplib::Response& res) -> bool {
    const auto token = extract_token(req);
    if (!token || !ctx.data->user_from_token(*token)) {
      ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                    {"error", "Unrecognised access token"}},
                    401);
      return false;
    }
    return true;
  };

  // GET /_matrix/client/v1/media/config — requires auth.
  svr.Get("/_matrix/client/v1/media/config",
          [&ctx, v1_media_auth](const httplib::Request& req,
                                httplib::Response& res) {
            if (!v1_media_auth(req, res)) return;
            ruma::respond(res, nlohmann::json{{"m.upload.size", 20 * 1024 * 1024}});
          });

// POST /_matrix/client/v1/media/upload?filename=… — auth-gated upload for
  // MSC3916. Same wire shape as the r0 endpoint; the v1 path is the unstable
  // location that authenticated media is served from. Body IS the file;
  // Content-Type is the file's media type (defaults to application/octet-stream).
  svr.Post("/_matrix/client/v1/media/upload",
           [&ctx, v1_media_auth](const httplib::Request& req,
                                 httplib::Response& res) {
             if (!v1_media_auth(req, res)) return;
             const std::string mxc =
                 "mxc://" + ctx.data->hostname() + "/" +
                 utils::random_string(256);
             std::optional<std::string> filename;
             if (req.has_param("filename")) filename = req.get_param_value("filename");
             const std::string content_type =
                 req.has_header("Content-Type")
                     ? req.get_header_value("Content-Type")
                     : "application/octet-stream";
             ctx.data->media_create(mxc, filename, content_type, req.body);
             ruma::respond(res, nlohmann::json{{"content_uri", mxc}});
           });

  // GET /_matrix/client/v1/media/download/{server}/{id}/{filename} — inline
  // disposition with the requested filename. Registered before the 2-segment
  // download route so the more specific path wins.
  svr.Get(R"(/_matrix/client/v1/media/download/([^/]+)/([^/]+)/([^/]+))",
          [&ctx, v1_media_auth](const httplib::Request& req,
                                httplib::Response& res) {
            if (!v1_media_auth(req, res)) return;
            const std::string server = req.matches[1].str();
            const std::string mxc =
                "mxc://" + server + "/" + req.matches[2].str();
            const std::string filename = req.matches[3].str();
            if (server != std::string(kServerName)) {
              ruma::respond(res, ruma::json{{"errcode", "M_NOT_FOUND"},
                                            {"error", "Media not found."}},
                            404);
              return;
            }
            auto media = ctx.data->media_get(mxc);
            if (!media) {
              ruma::respond(res, ruma::json{{"errcode", "M_NOT_FOUND"},
                                            {"error", "Media not found."}},
                            404);
              return;
            }
            res.status = 200;
            res.set_content(media->bytes, media->content_type);
            res.set_header("Content-Disposition",
                           "inline; filename=\"" + filename + "\"");
          });

  // GET /_matrix/client/v1/media/download/{server}/{id} — requires auth.
  svr.Get(R"(/_matrix/client/v1/media/download/([^/]+)/([^/]+))",
          [&ctx, download_handler, v1_media_auth](const httplib::Request& req,
                                                   httplib::Response& res) {
            if (!v1_media_auth(req, res)) return;
            download_handler(req, res, true, true);
          });

  // GET /_matrix/client/v1/media/thumbnail/{server}/{id} — requires auth.
  svr.Get(R"(/_matrix/client/v1/media/thumbnail/([^/]+)/([^/]+))",
          [&ctx, download_handler, v1_media_auth](const httplib::Request& req,
                                                   httplib::Response& res) {
            if (!v1_media_auth(req, res)) return;
            // Upstream served the original file as its own thumbnail.
            download_handler(req, res, false, true);
          });


  // NEW in 12a8c9ba: federation server-side endpoints (a peer calls these when
  // one of its users joins a room we host). They serve our room's PDUs.
  // NEW in 1f292c09: federation transaction endpoint. A remote server delivers
  // PDUs here; we append each only if the room already exists locally.
  svr.Post(R"(/_matrix/federation/v1/send/([^/]+))",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             json body;
             try { body = json::parse(req.body); } catch (...) { body = json::object(); }
             if (!body.contains("pdus") || !body["pdus"].is_array()) {
               ruma::respond(res, ruma::json{{"errcode", "M_BAD_JSON"},
                                             {"error", "missing pdus array"}}, 400);
               return;
             }
             int appended = 0;
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
               if (ctx.data->pdu_append(event_id, room_id, std::move(event)))
                 ++appended;
             }
             ruma::respond(res, ruma::json{{"pdus", json::object()}}, 200);
           });

  // NEW in eedac4f: make_join (federation) — return an unsigned join event
  // template for the remote to sign. The remote will then POST the signed
  // event to /send_join. Adapted: we report a default room version (1) and
  // include a basic event stub; full auth-events collection is not done
  // because we don't track per-room versions or full state-res locally.
  svr.Get(R"(/_matrix/federation/v1/make_join/([^/]+)/([^/]+))",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            const std::string room_id = url_decode(req.matches[1]);
            const std::string user_id = url_decode(req.matches[2]);
            if (ctx.data->room_state(room_id).empty()) {
              ruma::respond(res,
                            ruma::json{{"errcode", "M_NOT_FOUND"},
                                       {"error", "Room not found."}},
                            404);
              return;
            }
            // Build a basic join event template. The remote will sign and
            // re-send via /send_join. We do not include full prev_events
            // here — that is appended during /send_join's state/auth_chain
            // merge step.
            nlohmann::json event = {
                {"type", "m.room.member"},
                {"content", {{"membership", "join"}}},
                {"room_id", room_id},
                {"sender", user_id},
                {"state_key", user_id},
            };
            ruma::respond(res,
                          ruma::json{{"room_version", "1"},
                                     {"event", std::move(event)}},
                          200);
          });


  svr.Get(R"(/_matrix/federation/v1/send_join/([^/]+)/([^/]+))",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            const std::string room_id = url_decode(req.matches[1]);
            if (ctx.data->room_state(room_id).empty()) {
              ruma::respond(res,
                            ruma::json{{"errcode", "M_NOT_FOUND"},
                                       {"error", "Room not found."}},
                            404);
              return;
            }
            auto state = ctx.data->federation_full_state(room_id);
            std::vector<std::string> state_ids;
            for (const auto& p : state)
              if (p.contains("event_id"))
                state_ids.push_back(p["event_id"].get<std::string>());
            auto auth_chain =
                ctx.data->federation_auth_chain(room_id, state_ids);
            ruma::respond(res,
                          ruma::json{{"auth_chain", auth_chain}, {"state", state}},
                          200);
          });

  svr.Get(R"(/_matrix/federation/v1/state_ids/([^/]+)/([^/]+))",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            const std::string room_id = url_decode(req.matches[1]);
            auto state_ids = ctx.data->room_state(room_id);
            std::set<std::string> auth_ids;
            for (const auto& p :
                 ctx.data->federation_auth_chain(room_id, state_ids))
              if (p.contains("event_id")) auth_ids.insert(p["event_id"].get<std::string>());
            ruma::json out = ruma::json::object();
            out["auth_chain_ids"] = nlohmann::json::array();
            for (const auto& id : auth_ids) out["auth_chain_ids"].push_back(id);
            out["pdus_state_ids"] = nlohmann::json::array();
            for (const auto& id : state_ids) out["pdus_state_ids"].push_back(id);
            out["pdus_prev_ids"] = nlohmann::json::array();
            ruma::respond(res, out, 200);
          });

  svr.Get(R"(/_matrix/federation/v1/event/([^/]+))",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
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
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            const std::string room_id = url_decode(req.matches[1]);
            auto pdus = ctx.data->federation_pdus_of_room(room_id);
            ruma::respond(res, ruma::json{{"pdus", pdus}}, 200);
          });

  svr.Get(R"(/_matrix/federation/v1/query/directory)",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
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

  // NEW in 4e44fedbc: federation public room directory — a peer lists our public
  // rooms via GET /_matrix/federation/v1/publicRooms. Reuses the same helper as
  // the client /publicRooms route.
  svr.Get(R"(/_matrix/federation/v1/publicRooms)",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            std::string search;
            auto it = req.params.find("filter");
            if (it != req.params.end()) search = url_decode(it->second);
            ruma::respond(res, get_public_rooms_filtered_route(&ctx, search));
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
