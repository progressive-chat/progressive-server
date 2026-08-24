// main.cpp — translation of Conduit commit 34a53ce2, src/main.rs
//
// "Better database structure". Deltas from c2c18b46:
//
//   * handlers no longer see the raw Db — they get State<Data> and call named
//     domain methods (user_exists/user_add/hostname). Context now wraps Data.
//   * tree "users" renamed "username_password" inside the new data layer.
//   * hostname is stored in the database and appended when building user IDs;
//     register's home_server echoes it too.
//   * login accepts a full user id ("@neo:localhost") or bare localpart
//     ("neo"); malformed ids fail with M_UNKNOWN instead of M_FORBIDDEN.
//   * versions response lists r0.0.1..r0.6.0 + unstable_features.
//   * debug!() logging sprinkled in — printf [debug] here.

#include "data.hpp"
#include "ruma_wrapper.hpp"

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
  if (r.home_server) {  // Option<String>: omitted when None, like serde skip_serializing_if
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

std::string to_error_json(const ruma::Error& e) {
  return "{" + json_string_field("errcode", ruma::errcode(e.kind), true) +
         json_string_field("error", e.message) + "}";
}

const char* reason(int status) {
  switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
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

// --- HTTP plumbing (unchanged since step 2) ----------------------------------

struct HttpRequest {
  std::string method;
  std::string path;
  size_t content_length = 0;
  std::string body;
};

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

  for (size_t pos = line_end + 2; pos < header_end;) {
    const size_t eol = raw.find("\r\n", pos);
    const std::string header = raw.substr(pos, eol - pos);
    if (const size_t colon = header.find(':'); colon != std::string::npos) {
      size_t value_start = colon + 1;
      while (value_start < header.size() && header[value_start] == ' ') ++value_start;
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

// --- state: rocket .manage(data) -> explicit Context --------------------------
//
// State<Db> became State<Data>: handlers see domain methods, never the store.

struct Context {
  Data* data;
};

bool localpart_valid(const std::string& localpart) {
  // What UserId's TryFrom checked in ruma-identifiers 0.14: non-empty
  // localpart limited to a-z 0-9 . _ = - / +.
  if (localpart.empty()) return false;
  for (const char c : localpart) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == '=' || c == '-' || c == '/' ||
                    c == '+';
    if (!ok) return false;
  }
  return true;
}

// NEW in 34a53ce2: login may receive a full "@user:server" id. Mirrors
// UserId's TryFrom on strings that already contain a ':'.
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
  // data: State<Data>
  const std::string localpart = body.username.value_or("randomname");
  std::string user_id;

  // format!("@{}:{}", username, data.hostname()) — hostname from the DB now.
  if (!localpart_valid(localpart)) {
    std::printf("[debug] Username was invalid\n");
    return ruma::MatrixResult<ruma::RegisterResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::InvalidUsername,
        .message = "Username was invalid.",
        .status_code = 400,
    });
  }
  user_id = "@" + localpart + ":" + ctx->data->hostname();

  // debug!("ID already taken"); + data.user_exists(&user_id)
  if (ctx->data->user_exists(user_id)) {
    std::printf("[debug] ID already taken\n");
    return ruma::MatrixResult<ruma::RegisterResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::UserInUse,
        .message = "Desired user ID is already taken.",
        .status_code = 400,
    });
  }

  // data.user_add(user_id.clone(), body.password.clone())
  ctx->data->user_add(user_id, body.password);

  return ruma::MatrixResult<ruma::RegisterResponse>::ok(ruma::RegisterResponse{
      .access_token = "randomtoken",
      .home_server = ctx->data->hostname(),  // was hardcoded "localhost"
      .user_id = std::move(user_id),
      .device_id = body.device_id.value_or("randomid"),
  });
}

ruma::MatrixResult<ruma::LoginResponse> login_route(Context* ctx,
                                                    const ruma::LoginRequest& body) {
  // let username = if let UserInfo::MatrixId(mut username) = &body.user { ... }
  if (!body.user_is_matrix_id) {
    std::printf("[debug] Bad login type\n");
    return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Unknown,
        .message = "Bad login type.",
        .status_code = 400,
    });
  }

  std::string username = *body.user_localpart;
  if (username.find(':') == std::string::npos) {  // bare localpart?
    username = "@" + username + ":" + ctx->data->hostname();
  }

  std::string user_id;
  if (!full_user_id_valid(username, &user_id)) {
    // NEW: malformed full ids now fail with M_UNKNOWN ("Invalid UserId."),
    // previously any string went straight to the contains_key check.
    std::printf("[debug] Invalid UserId.\n");
    return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Unknown,
        .message = "Bad login type.",
        .status_code = 400,
    });
  }

  if (!ctx->data->user_exists(user_id)) {
    std::printf("[debug] Userid does not exist. Can't log in.\n");
    return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Forbidden,
        .message = "UserId not found.",
        .status_code = 400,  // BAD_REQUEST in the original, not 403
    });
  }

  // Password ignored! Any password logs you in until far later commits.
  return ruma::MatrixResult<ruma::LoginResponse>::ok(ruma::LoginResponse{
      .user_id = user_id,
      .access_token = "randomtoken",
      .home_server = std::string{"localhost"},  // still hardcoded upstream!
      .device_id = body.device_id.value_or("randomid"),
  });
}

ruma::MatrixResult<ruma::GetSupportedVersionsResponse> get_supported_versions_route() {
  // Expanded in 34a53ce2 to advertise the full r0.x range.
  return ruma::MatrixResult<ruma::GetSupportedVersionsResponse>::ok(
      ruma::GetSupportedVersionsResponse{
          .versions = {"r0.0.1", "r0.1.0", "r0.2.0", "r0.3.0", "r0.4.0",
                       "r0.5.0", "r0.6.0"},
          .unstable_features = {},
      });
}

ruma::MatrixResult<ruma::GetAliasResponse> get_alias_route(
    const std::string& room_alias) {
  if (room_alias != "#room:localhost") {
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
    const ruma::CreateMessageEventRequest& body) {
  std::printf("[debug] create_message_event content: %s\n", body.content_json.c_str());
  std::fflush(stdout);
  return ruma::MatrixResult<ruma::CreateMessageEventResponse>::ok(
      ruma::CreateMessageEventResponse{.event_id = "$randomeventid"});
}

// --- server loop ---------------------------------------------------------------

std::string db_dir;  // set in main(), printed by run_server

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

  Context ctx{data};  // rocket .manage(data)
  std::printf("[info] port: %u\n[info] data dir: %s\n[info] hostname: %s\n",
              kListenPort, db_dir.c_str(), data->hostname().c_str());
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
      const auto wrapper = ruma::Ruma<ruma::RegisterRequest>::from_body(req.body);
      resp = respond(register_route(&ctx, wrapper.value));
    } else if (req.method == "POST" &&
               match_route("/_matrix/client/r0/login", req, &params)) {
      // added in c2c18b46, reworked in 34a53ce2
      const auto wrapper = ruma::Ruma<ruma::LoginRequest>::from_body(req.body);
      resp = respond(login_route(&ctx, wrapper.value));
    } else if (req.method == "GET" &&
               match_route("/_matrix/client/r0/directory/room/<room_alias>", req, &params)) {
      resp = respond(get_alias_route(params.at("room_alias")));
    } else if (req.method == "POST" &&
               match_route("/_matrix/client/r0/rooms/<room_id>/join", req, &params)) {
      auto wrapper = ruma::Ruma<ruma::JoinRoomByIdRequest>::from_body(req.body);
      wrapper.value.room_id = params.at("room_id");
      resp = respond(join_room_by_id_route(wrapper.value));
    } else if (req.method == "PUT" &&
               match_route("/_matrix/client/r0/rooms/<room_id>/send/<event_type>/<txn_id>",
                           req, &params)) {
      auto wrapper = ruma::Ruma<ruma::CreateMessageEventRequest>::from_body(req.body);
      wrapper.value.room_id = params.at("room_id");
      wrapper.value.event_type = params.at("event_type");
      wrapper.value.txn_id = params.at("txn_id");
      resp = respond(create_message_event_route(wrapper.value));
    }

    write_response(client, resp.status, resp.body);
    ::close(client);
  }
}

}  // namespace

int main() {
  ::signal(SIGPIPE, SIG_IGN);

  // ProjectDirs::from("xyz","koesters","matrixserver").data_dir() equivalent.
  const char* home = ::getenv("HOME");
  db_dir = (home ? std::filesystem::path{home} : std::filesystem::path{"/tmp"}) /
           ".local/share/conduit-step04";

  static Data data = Data::load_or_create(db_dir);  // let data = Data::load_or_create()
  data.set_hostname("localhost");                   // data.set_hostname("localhost")
  return run_server(&data);
}
