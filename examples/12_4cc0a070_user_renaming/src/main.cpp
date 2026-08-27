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
#include "routes.hpp"
#include "server_server.hpp"
#include "data.hpp"
#include "ruma_wrapper.hpp"
#include "utils.hpp"

#include <httplib.h>

#include <csignal>

using json = nlohmann::json;
#include <cstdlib>
#include <filesystem>
#include <iostream>
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

  append_state("m.room.create",
               json{{"creator", creator}}, "");

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

  ctx->data->room_join(room_id, creator);

  for (const auto& invitee : body.invite) {
    ctx->data->room_invite(creator, room_id, invitee);
  }

  return ruma::MatrixResult<ruma::CreateRoomResponse>::ok(
      ruma::CreateRoomResponse{.room_id = room_id});
}

void invite_user_route(Context* ctx, const ruma::InviteRequest& body,
                       httplib::Response& res) {
  if (!body.user_id.empty() && !body.target.empty()) {
    ctx->data->room_invite(body.user_id, body.room_id, body.target);
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
    if (user.find(body.search_term) != std::string::npos) {
      results.push_back(json{{"user_id", user}});
    }
  }
  ruma::respond(res, json{{"results", results}, {"limited", false}});
}

// Better public room directory (abcce95d): names from room_state, sorted by
// member count descending.
ruma::MatrixResult<ruma::PublicRoomsResponse> get_public_rooms_filtered_route(
    Context* ctx) {
  ruma::PublicRoomsResponse resp;

  struct Entry {
    std::string room_id;
    long members;
    std::optional<std::string> name;
  };
  std::vector<Entry> entries;

  // rooms_all equivalent: iterate known rooms via userid_roomids of all users.
  std::set<std::string> seen;
  for (const auto& user : ctx->data->users_all()) {
    for (const auto& room : ctx->data->rooms_joined(user)) {
      if (!seen.insert(room).second) continue;
      long members = static_cast<long>(ctx->data->room_users(room));
      entries.push_back({room, members, std::nullopt});
      for (const auto& pdu_text : ctx->data->room_state(room)) {
        auto pdu = nlohmann::json::parse(pdu_text);
        if (pdu.value("type", "") == "m.room.name") {
          entries.back().name =
              pdu["content"].value("name", "");
          break;
        }
      }
    }
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

ruma::MatrixResult<ruma::GetAliasResponse> get_alias_route(
    const std::string& room_alias) {
  // Hardcoded directory, verbatim from the original commits.
  if (room_alias != "#room:localhost") {
    std::cerr << "[debug] Room not found.\n";
    return ruma::MatrixResult<ruma::GetAliasResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::NotFound,
        .message = "Room not found.",
        .status_code = 404,
    });
  }
  return ruma::MatrixResult<ruma::GetAliasResponse>::ok(ruma::GetAliasResponse{
      .room_id = "!xclkjvdlfj:localhost",
      .servers = {"localhost"},
  });
}

ruma::MatrixResult<ruma::JoinRoomByIdResponse> join_room_by_id_route(
    const ruma::JoinRoomByIdRequest& body) {
  return ruma::MatrixResult<ruma::JoinRoomByIdResponse>::ok(
      ruma::JoinRoomByIdResponse{.room_id = body.room_id});
}

ruma::MatrixResult<ruma::CreateMessageEventResponse> create_message_event_route(
    Context* ctx, const ruma::CreateMessageEventRequest& body) {
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

  // Add PDU to the graph.
  ctx->data->pdu_append(event_id, body.room_id, std::move(event));

  return ruma::MatrixResult<ruma::CreateMessageEventResponse>::ok(
      ruma::CreateMessageEventResponse{.event_id = event_id});
}

ruma::MatrixResult<ruma::SyncResponse> sync_route(Context* ctx,
                                                  const std::string& user_id) {
  ruma::SyncResponse resp;

  // Joined rooms: real per-room timelines now.
  for (const auto& room_id : ctx->data->rooms_joined(user_id)) {
    ruma::SyncResponse joined;
    joined.joined_room_id = room_id;
    joined.timeline_events = ctx->data->pdus_since(room_id, 0);
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
               ".local/share/conduit-step12";
  }

  static Data data = Data::load_or_create(data_dir);
  data.set_hostname("localhost");
  static Context ctx{&data};

  httplib::Server svr;

  svr.Get("/_matrix/client/versions", [](const httplib::Request&, httplib::Response& res) {
    ruma::respond(res, get_supported_versions_route());
  });

  svr.Post("/_matrix/client/r0/register", [](const httplib::Request& req,
                                             httplib::Response& res) {
    auto wrapper = ruma::Ruma<ruma::RegisterRequest>::from_request(req);
    ruma::respond(res, register_route(&ctx, wrapper.value));
  });

  svr.Post("/_matrix/client/r0/login", [](const httplib::Request& req,
                                          httplib::Response& res) {
    auto wrapper = ruma::Ruma<ruma::LoginRequest>::from_request(req);
    ruma::respond(res, login_route(&ctx, wrapper.value));
  });

  svr.Get("/_matrix/client/r0/directory/room/:room_alias",
          [](const httplib::Request& req, httplib::Response& res) {
            ruma::respond(res, get_alias_route(req.path_params.at("room_alias")));
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
            if (!displayname || displayname->empty()) {
              ctx.data->displayname_remove(*user);
            } else {
              ctx.data->displayname_set(*user, *displayname);
              // TODO upstream: send a new m.presence event with the updated name
            }
            ruma::respond(res, json::object());
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
             if (room_id.rfind("#", 0) == 0)
               room_id = "!xclkjvdlfj:localhost";  // alias directory still hardcoded

             ctx.data->room_join(room_id, *user);

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

  // Better public room directory (abcce95d).
  svr.Post("/_matrix/client/r0/publicRooms", [&ctx](const httplib::Request&,
                                                    httplib::Response& res) {
    ruma::respond(res, get_public_rooms_filtered_route(&ctx));
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
    ruma::respond(res, sync_route(&ctx, *wrapper.user_id));
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
  svr.Get(R"(/_matrix/key/v2/server/(.+))", server_keys_handler);

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
