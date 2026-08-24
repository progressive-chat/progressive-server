// main.cpp — translation of Conduit's initial-commit src/main.rs
//
// Rust original (commit 6264628c, 2020-02-15, timokoesters/conduit):
//
//   #![feature(proc_macro_hygiene, decl_macro)]
//   mod ruma_wrapper;
//
//   use {
//       rocket::{get, post, routes},
//       ruma_client_api::r0::account::register,
//       ruma_wrapper::Ruma,
//       std::convert::TryInto,
//   };
//
//   #[post("/_matrix/client/r0/register", data = "<body>")]
//   fn register_route(body: Ruma<register::Request>) -> Ruma<register::Response> {
//       Ruma(register::Response {
//           access_token: "42".to_owned(),
//           home_server: "deprecated".to_owned(),
//           user_id: "@yourrequestedid:homeserver.com".try_into().unwrap(),
//           device_id: body.device_id.clone().unwrap_or_default(),
//       })
//   }
//
//   fn main() {
//       pretty_env_logger::init();
//       rocket::ignite()
//           .mount("/", routes![register_route])
//           .launch();
//   }
//
// Rocket gave Conduit three things for free: a listening socket, HTTP parsing,
// and routing. Below, each of those is written out explicitly — this is exactly
// the layer Boost.Beast provides in progressive-server and tokio/hyper provide
// in tuwunel.

#include "ruma_wrapper.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

namespace {

constexpr uint16_t kListenPort = 8000;  // Rocket's default port

// --- tiny JSON writer (serde_json::to_string in the original) ---------------

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

std::string to_json(const ruma::RegisterResponse& r) {
  // Keys alphabetical, like serde_json/nlohmann emit by default.
  return "{\"access_token\":\"" + json_escape(r.access_token) +
         "\",\"device_id\":\"" + json_escape(r.device_id) +
         "\",\"home_server\":\"" + json_escape(r.home_server) +
         "\",\"user_id\":\"" + json_escape(r.user_id) + "\"}";
}

// --- what #[post(...)] + routes![] expanded to -------------------------------

struct HttpRequest {
  std::string method;
  std::string path;
  size_t content_length = 0;
  std::string body;
};

ruma::RegisterResponse register_route(const ruma::RegisterRequest& body) {
  return ruma::RegisterResponse{
      .access_token = "42",
      .home_server = "deprecated",
      .user_id = "@yourrequestedid:homeserver.com",  // ruma: .try_into().unwrap()
      .device_id = body.device_id.value_or(""),
  };
}

// --- what rocket::ignite().mount().launch() expanded to ---------------------

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
      const std::string name = header.substr(0, colon);
      size_t value_start = colon + 1;
      while (value_start < header.size() && header[value_start] == ' ') ++value_start;
      if (strcasecmp(name.c_str(), "content-length") == 0) {
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

void write_response(int fd, int status, std::string_view reason, std::string_view json_body) {
  std::string out = "HTTP/1.1 " + std::to_string(status) + " ";
  out.append(reason);
  out += "\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: ";
  out += std::to_string(json_body.size());
  out += "\r\n\r\n";
  out.append(json_body);
  ::send(fd, out.data(), out.size(), MSG_NOSIGNAL);
}

int run_server() {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    std::perror("socket");
    return 1;
  }

  int one = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // dev server; Rocket bound all interfaces
  addr.sin_port = htons(kListenPort);
  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 || ::listen(fd, 16) < 0) {
    std::perror("bind/listen");
    return 1;
  }

  std::printf("[info] Configured for stub.\n[info] address: 127.0.0.1\n[info] port: %u\n", kListenPort);
  std::printf("[info] POST /_matrix/client/r0/register available.\n");
  std::fflush(stdout);

  while (true) {
    const int client = ::accept(fd, nullptr, nullptr);
    if (client < 0) continue;

    HttpRequest req;
    if (!read_request(client, &req)) {
      ::close(client);
      continue;
    }

    if (req.method == "POST" && req.path == "/_matrix/client/r0/register") {
      const auto wrapper = ruma::Ruma<ruma::RegisterRequest>::from_body(req.body);
      const ruma::RegisterResponse resp = register_route(wrapper.value);
      write_response(client, 200, "OK", to_json(resp));
    } else {
      write_response(client, 404, "Not Found", "{\"errcode\":\"M_UNRECOGNIZED\",\"error\":\"Unrecognized request\"}");
    }
    ::close(client);
  }
}

}  // namespace

int main() {
  ::signal(SIGPIPE, SIG_IGN);  // keep-alive clients may hang up mid-write
  return run_server();
}
