// main.cpp — translation of Conduit commit fa322689, src/main.rs
//
// "feat: save pdus". PDUs are saved in a pduid -> pdus map. roomid_pduleaves
// keeps track of the leaves of the event graph and eventid -> pduid maps event
// ids to pdus. Event ids become REAL reference hashes now: SHA-256 over the
// canonical JSON of the redacted event (ruma_signatures::reference_hash).
// Also new: GET /_matrix/client/r0/sync (upstream timeline was todo!(); we
// return the stored PDUs) and a catch-all OPTIONS route.
//
// Superseded from 533260ed:
//
//   * register/login now provision devices and access tokens through the new
//     four-tree model (device_add/token_replace). Tokens are still the
//     placeholder "TODO:randomtoken" upstream — randomness comes later.
//   * login FINALLY checks passwords. Wrong password -> M_UNKNOWN with an
//     empty message at HTTP 403; account without password -> M_FORBIDDEN "".
//   * create_message_event requires authentication now: the Ruma extractor
//     resolves the sender from Authorization/ ?access_token= and 401s if
//     missing or unknown. The handler builds a MessageEvent (with real
//     origin_server_ts) and calls room_event_add — which is todo!() upstream,
//     i.e. sending a message PANICS Conduit here. We log instead of crashing.
//
// Unchanged: alias/join/versions stay open (no auth metadata).

#include "crypto.hpp"
#include "data.hpp"
#include "json_value.hpp"
#include "ruma_wrapper.hpp"
#include "utils.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <strings.h>  // strcasecmp

namespace {

constexpr uint16_t kListenPort = 8000;

// "TODO:randomtoken" / "TODO:randomdeviceid" — verbatim placeholders.
constexpr std::string_view kPlaceholderToken = "TODO:randomtoken";
constexpr std::string_view kPlaceholderDeviceId = "TODO:randomdeviceid";

// --- JSON writer -------------------------------------------------------------

std::string json_escape(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (const char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[7];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out.push_back(c);
        }
    }
  }
  return out;
}

std::string json_string_field(std::string_view key, std::string_view value,
                              bool first = false) {
  return std::string(first ? "" : ",") + "\"" + json_escape(key) + "\":\"" +
         json_escape(value) + "\"";
}

std::string to_json(const ruma::RegisterResponse& r) {
  return "{" + json_string_field("access_token", r.access_token, true) +
         json_string_field("device_id", r.device_id) +
         json_string_field("home_server", r.home_server) +
         json_string_field("user_id", r.user_id) + "}";
}

std::string to_json(const ruma::LoginResponse& r) {
  std::string out = "{" + json_string_field("access_token", r.access_token, true) +
                    json_string_field("device_id", r.device_id);
  if (r.home_server) {
    out += json_string_field("home_server", *r.home_server);
  }
  return out + json_string_field("user_id", r.user_id) + "}";
}

std::string to_json(const ruma::GetSupportedVersionsResponse& r) {
  std::string out = "{\"versions\":[";
  for (size_t i = 0; i < r.versions.size(); ++i) {
    if (i > 0) out += ',';
    out += '"' + json_escape(r.versions[i]) + '"';
  }
  out += "],\"unstable_features\":{";
  bool first = true;
  for (const auto& [flag, enabled] : r.unstable_features) {
    if (!first) out += ',';
    out += '"' + json_escape(flag) + "\":\"" + json_escape(enabled) + '"';
    first = false;
  }
  return out + "}}";
}

std::string to_json(const ruma::GetAliasResponse& r) {
  std::string servers = "[";
  for (size_t i = 0; i < r.servers.size(); ++i) {
    if (i > 0) servers += ',';
    servers += '"' + json_escape(r.servers[i]) + '"';
  }
  servers += "]";
  return "{" + json_string_field("room_id", r.room_id, true) +
         ",\"servers\":" + servers + "}";
}

std::string to_json(const ruma::JoinRoomByIdResponse& r) {
  return "{" + json_string_field("room_id", r.room_id, true) + "}";
}

std::string to_json(const ruma::CreateMessageEventResponse& r) {
  return "{" + json_string_field("event_id", r.event_id, true) + "}";
}

// sync_events::Response skeleton — only join.<room>.timeline.events filled.
std::string to_json(const ruma::SyncResponse& r) {
  std::string events;
  bool first_event = true;
  for (const auto& pdu : r.timeline_events) {
    if (!first_event) events += ',';
    first_event = false;
    events += pdu;  // already canonical JSON
  }

  std::string out = "{\"next_batch\":\"\""
                    ",\"rooms\":{\"invite\":{}"
                    ",\"join\":{\"" + json_escape(r.joined_room_id) + "\":{"
                    "\"account_data\":{\"events\":[]}"
                    ",\"ephemeral\":{\"events\":[]}"
                    ",\"state\":{\"events\":[]}"
                    ",\"summary\":{}"
                    ",\"unread_notifications\":{}"
                    ",\"timeline\":{\"events\":[" + events + "]}}}"
                    ",\"leave\":{}}"
                    ",\"to_device\":{\"events\":[]}}";
  return out;
}

std::string to_error_json(const ruma::Error& e) {
  return "{" + json_string_field("errcode", ruma::errcode(e.kind), true) +
         json_string_field("error", e.message) + "}";
}

const char* reason(int status) {
  switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";  // NEW in 533260ed
    case 403: return "Forbidden";     // wrong password / unknown account now use 403
    case 404: return "Not Found";
    default: return "";
  }
}

struct HttpResponse {
  int status;
  std::string body;
};

template <typename T>
HttpResponse respond(const ruma::MatrixResult<T>& result) {
  if (result.result.index() == 0) {
    return {200, to_json(std::get<0>(result.result))};
  }
  const ruma::Error& e = std::get<1>(result.result);
  return {e.status_code, to_error_json(e)};
}

// --- HTTP plumbing -------------------------------------------------------------

struct HttpRequest {
  std::string method;
  std::string path;   // without query string
  std::map<std::string, std::string> query;  // NEW: needed for ?access_token=
  std::map<std::string, std::string> headers;
  size_t content_length = 0;
  std::string body;
};

std::string url_decode(std::string_view s) {
  std::string out;
  const auto hex = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '%' && i + 2 < s.size()) {
      const int hi = hex(s[i + 1]);
      const int lo = hex(s[i + 2]);
      if (hi >= 0 && lo >= 0) {
        out.push_back(static_cast<char>((hi << 4) | lo));
        i += 2;
        continue;
      }
    }
    out.push_back(s[i]);
  }
  return out;
}

bool read_request(int fd, HttpRequest* req) {
  std::string raw;
  char buf[4096];
  size_t header_end;

  while ((header_end = raw.find("\r\n\r\n")) == std::string::npos) {
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) return false;
    raw.append(buf, static_cast<size_t>(n));
  }

  const size_t line_end = raw.find("\r\n");
  const std::string request_line = raw.substr(0, line_end);
  const size_t sp1 = request_line.find(' ');
  const size_t sp2 = request_line.find(' ', sp1 + 1);
  if (sp1 == std::string::npos || sp2 == std::string::npos) return false;
  req->method = request_line.substr(0, sp1);
  req->path = request_line.substr(sp1 + 1, sp2 - sp1 - 1);

  // Split "?access_token=..." off the path (Rocket did this transparently).
  if (const size_t qmark = req->path.find('?'); qmark != std::string::npos) {
    std::string_view query(req->path.data() + qmark + 1,
                           req->path.size() - qmark - 1);
    req->path.resize(qmark);
    size_t start = 0;
    while (start < query.size()) {
      const size_t amp = query.find('&', start);
      const auto pair =
          query.substr(start, amp == std::string_view::npos ? amp : amp - start);
      if (const size_t eq = pair.find('='); eq != std::string_view::npos) {
        req->query[std::string(pair.substr(0, eq))] =
            url_decode(pair.substr(eq + 1));
      }
      if (amp == std::string_view::npos) break;
      start = amp + 1;
    }
  }

  for (size_t pos = line_end + 2; pos < header_end;) {
    const size_t eol = raw.find("\r\n", pos);
    const std::string header = raw.substr(pos, eol - pos);
    if (const size_t colon = header.find(':'); colon != std::string::npos) {
      size_t value_start = colon + 1;
      while (value_start < header.size() && header[value_start] == ' ') ++value_start;
      req->headers[header.substr(0, colon)] = header.substr(value_start);
      if (strcasecmp(header.substr(0, colon).c_str(), "content-length") == 0) {
        req->content_length = std::stoul(header.substr(value_start));
      }
    }
    pos = eol + 2;
  }

  const size_t body_start = header_end + 4;
  while (raw.size() - body_start < req->content_length) {
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    raw.append(buf, static_cast<size_t>(n));
  }
  req->body = raw.substr(body_start, req->content_length);
  return true;
}

void write_response(int fd, int status, std::string_view json_body) {
  std::string out = "HTTP/1.1 " + std::to_string(status) + " ";
  out += reason(status);
  out += "\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: ";
  out += std::to_string(json_body.size());
  out += "\r\n\r\n";
  out.append(json_body);
  ::send(fd, out.data(), out.size(), MSG_NOSIGNAL);
}

std::vector<std::string_view> split_path(std::string_view path) {
  std::vector<std::string_view> segments;
  size_t start = 0;
  while (true) {
    const size_t slash = path.find('/', start);
    if (slash == std::string_view::npos) {
      if (start < path.size()) segments.push_back(path.substr(start));
      break;
    }
    if (slash > start) segments.push_back(path.substr(start, slash - start));
    start = slash + 1;
  }
  return segments;
}

bool match_route(std::string_view pattern, const HttpRequest& req,
                 std::map<std::string, std::string>* params) {
  const auto pat = split_path(pattern);
  const auto seg = split_path(req.path);
  if (pat.size() != seg.size()) return false;
  for (size_t i = 0; i < pat.size(); ++i) {
    if (!pat[i].empty() && pat[i].front() == '<') {
      (*params)[std::string(pat[i].substr(1, pat[i].size() - 2))] =
          url_decode(seg[i]);
    } else if (pat[i] != seg[i]) {
      return false;
    }
  }
  return true;
}

// --- state ---------------------------------------------------------------------

struct Context {
  Data* data;
};

bool localpart_valid(const std::string& localpart) {
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
      colon == 1 || colon + 1 >= user_id.size()) {
    return false;
  }
  if (!localpart_valid(user_id.substr(1, colon - 1))) return false;
  *normalized = user_id;
  return true;
}

ruma::MatrixResult<ruma::RegisterResponse> register_route(
    Context* ctx, const ruma::RegisterRequest& body) {
  const std::string localpart = body.username.value_or("randomname");
  std::string user_id;

  if (!localpart_valid(localpart)) {
    std::printf("[debug] Username was invalid\n");
    return ruma::MatrixResult<ruma::RegisterResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::InvalidUsername,
        .message = "Username was invalid.",
        .status_code = 400,
    });
  }
  user_id = "@" + localpart + ":" + ctx->data->hostname();

  if (ctx->data->user_exists(user_id)) {
    std::printf("[debug] ID already taken\n");
    return ruma::MatrixResult<ruma::RegisterResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::UserInUse,
        .message = "Desired user ID is already taken.",
        .status_code = 400,
    });
  }

  // Create user
  ctx->data->user_add(user_id, body.password);

  // Generate new device id if the user didn't specify one
  const std::string device_id = body.device_id.value_or(std::string{kPlaceholderDeviceId});

  // Add device
  ctx->data->device_add(user_id, device_id);

  // Generate new token for the device
  const std::string token{kPlaceholderToken};
  ctx->data->token_replace(user_id, device_id, token);

  return ruma::MatrixResult<ruma::RegisterResponse>::ok(ruma::RegisterResponse{
      .access_token = token,          // was hardcoded "randomtoken"
      .home_server = ctx->data->hostname(),
      .user_id = std::move(user_id),
      .device_id = device_id,         // was hardcoded "randomid"
  });
}

ruma::MatrixResult<ruma::LoginResponse> login_route(Context* ctx,
                                                    const ruma::LoginRequest& body) {
  std::optional<std::string> user_id;

  // if let (UserInfo::MatrixId(mut username), LoginInfo::Password{password}) = ...
  if (body.user_is_matrix_id && body.password) {
    std::string username = *body.user_localpart;
    if (username.find(':') == std::string::npos) {
      username = "@" + username + ":" + ctx->data->hostname();
    }

    std::string validated;
    if (full_user_id_valid(username, &validated)) {
      // Check password — THE new thing in this commit.
      if (const auto correct_password = ctx->data->password_get(validated)) {
        if (*body.password == *correct_password) {
          user_id = std::move(validated);  // Success!
        } else {
          std::printf("[debug] Invalid password.\n");
          return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
              .kind = ruma::ErrorKind::Unknown,
              .message = "",  // empty message upstream!
              .status_code = 403,
          });
        }
      } else {
        std::printf("[debug] UserId does not exist (has no assigned password). Can't log in.\n");
        return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
            .kind = ruma::ErrorKind::Forbidden,
            .message = "",
            .status_code = 403,
        });
      }
    } else {
      std::printf("[debug] Invalid UserId.\n");
      return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
          .kind = ruma::ErrorKind::Unknown,
          .message = "Bad login type.",
          .status_code = 400,
      });
    }
  } else {
    std::printf("[debug] Bad login type\n");
    return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Unknown,
        .message = "Bad login type.",
        .status_code = 400,
    });
  }

  // Generate new device id if the user didn't specify one
  const std::string device_id = body.device_id.value_or(std::string{kPlaceholderDeviceId});

  // Add device (TODO: We might not want to call it when using an existing device)
  ctx->data->device_add(*user_id, device_id);

  // Generate a new token for the device
  const std::string token{kPlaceholderToken};
  ctx->data->token_replace(*user_id, device_id, token);

  return ruma::MatrixResult<ruma::LoginResponse>::ok(ruma::LoginResponse{
      .user_id = *user_id,
      .access_token = token,
      .home_server = ctx->data->hostname(),  // was hardcoded "localhost"
      .device_id = device_id,
  });
}

ruma::MatrixResult<ruma::GetSupportedVersionsResponse> get_supported_versions_route() {
  // Trimmed back to a single version in fa322689.
  return ruma::MatrixResult<ruma::GetSupportedVersionsResponse>::ok(
      ruma::GetSupportedVersionsResponse{
          .versions = {"r0.6.0"},
          .unstable_features = {},
      });
}

ruma::MatrixResult<ruma::GetAliasResponse> get_alias_route(
    const std::string& room_alias) {
  if (room_alias != "#room:localhost") {
    std::printf("[debug] Room not found.\n");
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
  // Check if content is valid (EventResult -> into_result().unwrap() upstream)
  json::Value content;
  try {
    content = json::Value::parse(body.content_json);
  } catch (const std::exception&) {
    std::printf("[debug] No content.\n");
    return ruma::MatrixResult<ruma::CreateMessageEventResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::NotFound,
        .message = "No content.",
        .status_code = 400,
    });
  }

  // Construct event — event_id placeholder gets replaced after hashing.
  json::Object event_obj{
      {"type", json::Value("m.room.message")},
      {"content", std::move(content)},
      {"event_id", json::Value("$thiswillbefilledinlater")},
      {"origin_server_ts", json::Value(utils::millis_since_unix_epoch())},
      {"room_id", json::Value(body.room_id)},
      {"sender", json::Value(body.sender_user_id)},
      {"unsigned", json::Value(json::Object{})},
  };
  json::Value event(std::move(event_obj));

  // Generate event id: reference hash of the redacted, canonical event.
  const std::string event_id = crypto::reference_hash(event);

  // Insert event id
  event.as_object_mut()["event_id"] = json::Value(event_id);

  // Add PDU to the graph
  ctx->data->pdu_append(event_id, body.room_id, std::move(event));

  return ruma::MatrixResult<ruma::CreateMessageEventResponse>::ok(
      ruma::CreateMessageEventResponse{.event_id = event_id});
}

// NEW in fa322689. Upstream left timeline.events as todo!(); we return the
// stored PDUs so clients can actually see history.
ruma::MatrixResult<ruma::SyncResponse> sync_route(Context* ctx) {
  ruma::SyncResponse resp;
  for (const auto& pdu : ctx->data->pdus_all()) {
    resp.timeline_events.push_back(pdu);
  }
  resp.joined_room_id = "!roomid:" + ctx->data->hostname();
  return ruma::MatrixResult<ruma::SyncResponse>::ok(std::move(resp));
}

// --- auth extractor: Ruma<T>'s FromRequest when REQUIRES_AUTH -------------------

// Token from Authorization header ("Bearer x") or ?access_token= query param.
std::optional<std::string> extract_token(const HttpRequest& req) {
  if (const auto it = req.headers.find("Authorization"); it != req.headers.end()) {
    constexpr std::string_view kBearer = "Bearer ";
    std::string_view v(it->second);
    if (v.rfind(kBearer, 0) == 0) v.remove_prefix(kBearer.size());
    if (!v.empty()) return std::string(v);
  }
  if (const auto it = req.query.find("access_token"); it != req.query.end()) {
    if (!it->second.empty()) return it->second;
  }
  return std::nullopt;  // TODO upstream: should be M_MISSING_TOKEN
}

template <typename T>
bool authenticate(Context* ctx, const HttpRequest& req, ruma::Ruma<T>* wrapper,
                  HttpResponse* fail) {
  if (!T::REQUIRES_AUTH) return true;

  const auto token = extract_token(req);
  if (!token) {
    *fail = {401, to_error_json(ruma::Error{.kind = ruma::ErrorKind::MissingToken,
                                            .message = "Missing access token",
                                            .status_code = 401})};
    return false;
  }

  // TODO upstream: should be M_UNKNOWN_TOKEN
  const auto user_id = ctx->data->user_from_token(*token);
  if (!user_id) {
    *fail = {401, to_error_json(ruma::Error{.kind = ruma::ErrorKind::UnknownToken,
                                            .message = "Unrecognised access token",
                                            .status_code = 401})};
    return false;
  }
  wrapper->user_id = *user_id;
  return true;
}

// --- server loop -----------------------------------------------------------------

std::string db_dir;

int run_server(Data* data) {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    std::perror("socket");
    return 1;
  }

  int one = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(kListenPort);
  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
      ::listen(fd, 16) < 0) {
    std::perror("bind/listen");
    return 1;
  }

  Context ctx{data};
  std::printf("[info] port: %u\n[info] hostname: %s\n", kListenPort,
              data->hostname().c_str());
  std::fflush(stdout);

  while (true) {
    const int client = ::accept(fd, nullptr, nullptr);
    if (client < 0) continue;

    HttpRequest req;
    if (!read_request(client, &req)) {
      ::close(client);
      continue;
    }

    std::map<std::string, std::string> params;

    HttpResponse resp{404, to_error_json(ruma::Error{
                               .kind = ruma::ErrorKind::NotFound,
                               .message = "Unrecognized request",
                               .status_code = 404,
                           })};

    if (req.method == "GET" && match_route("/_matrix/client/versions", req, &params)) {
      resp = respond(get_supported_versions_route());
    } else if (req.method == "POST" &&
               match_route("/_matrix/client/r0/register", req, &params)) {
      ruma::Ruma<ruma::RegisterRequest> wrapper =
          ruma::Ruma<ruma::RegisterRequest>::from_body(req.body);
      if (authenticate(&ctx, req, &wrapper, &resp)) {
        resp = respond(register_route(&ctx, wrapper.value));
      }
    } else if (req.method == "POST" &&
               match_route("/_matrix/client/r0/login", req, &params)) {
      ruma::Ruma<ruma::LoginRequest> wrapper =
          ruma::Ruma<ruma::LoginRequest>::from_body(req.body);
      if (authenticate(&ctx, req, &wrapper, &resp)) {
        resp = respond(login_route(&ctx, wrapper.value));
      }
    } else if (req.method == "GET" &&
               match_route("/_matrix/client/r0/directory/room/<room_alias>", req, &params)) {
      resp = respond(get_alias_route(params.at("room_alias")));
    } else if (req.method == "POST" &&
               match_route("/_matrix/client/r0/rooms/<room_id>/join", req, &params)) {
      ruma::Ruma<ruma::JoinRoomByIdRequest> wrapper =
          ruma::Ruma<ruma::JoinRoomByIdRequest>::from_body(req.body);
      if (authenticate(&ctx, req, &wrapper, &resp)) {
        wrapper.value.room_id = params.at("room_id");
        resp = respond(join_room_by_id_route(wrapper.value));
      }
    } else if (req.method == "PUT" &&
               match_route("/_matrix/client/r0/rooms/<room_id>/send/<event_type>/<txn_id>",
                           req, &params)) {
      ruma::Ruma<ruma::CreateMessageEventRequest> wrapper =
          ruma::Ruma<ruma::CreateMessageEventRequest>::from_body(req.body);
      if (authenticate(&ctx, req, &wrapper, &resp)) {
        wrapper.value.room_id = params.at("room_id");
        wrapper.value.event_type = params.at("event_type");
        wrapper.value.txn_id = params.at("txn_id");
        wrapper.value.sender_user_id = *wrapper.user_id;
        resp = respond(create_message_event_route(&ctx, wrapper.value));
      }
    }

    // NEW: OPTIONS catch-all — upstream returns a plain 404 M_NOT_FOUND.
    if (req.method == "OPTIONS") {
      resp = {404, to_error_json(ruma::Error{
                       .kind = ruma::ErrorKind::NotFound,
                       .message = "Room not found.",
                       .status_code = 404,
                   })};
    } else if (req.method == "GET" &&
               match_route("/_matrix/client/r0/sync", req, &params)) {
      ruma::Ruma<ruma::SyncRequest> wrapper =
          ruma::Ruma<ruma::SyncRequest>::from_body(req.body);
      if (authenticate(&ctx, req, &wrapper, &resp)) {
        resp = respond(sync_route(&ctx));
      }
    }

    write_response(client, resp.status, resp.body);
    ::close(client);
  }
}

}  // namespace

int main() {
  ::signal(SIGPIPE, SIG_IGN);

  const char* home = ::getenv("HOME");
  db_dir = (home ? std::filesystem::path{home} : std::filesystem::path{"/tmp"}) /
           ".local/share/conduit-step06";

  static Data data = Data::load_or_create(db_dir);
  data.set_hostname("localhost");
  return run_server(&data);
}
