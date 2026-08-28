// server_server.cpp — translation of Conduit commit 720cc0cf's
// src/server_server.rs send_request.
//
//   * request bodies travel under the "content" key of the signed JSON
//     (that was fix 873d1915: "http body as content when signing")
//   * federation traffic targets port 8448
//   * the SIGNED request map's "destination" is the real target server
//     name (the room/join destination), and the TLS connection is opened to
//     that same host[:port] — matching ruma-signatures / Conduit's
//     send_request (real Ed25519 signing with this server's persisted key).
//
// Everything else (sign_json, X-Matrix header) matches ruma-signatures.

#include "server_server.hpp"

#include "crypto.hpp"
#include "data.hpp"

#include <httplib.h>

namespace federation {

std::optional<nlohmann::json> send_request(
    const std::string& hostname, const std::string& keypair_seed,
    const std::string& destination, const std::string& path,
    const nlohmann::json& content) {
  using json = nlohmann::json;

  // NEW in 0b263208e: don't panic on bad server names. Reject empty/invalid
  // destinations up front instead of letting the HTTP client throw.
  if (destination.empty()) {
    std::cerr << "[warn] federation request with empty destination; skipping\n";
    return std::nullopt;
  }
  for (char c : destination) {
    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' ||
          c == ':' || c == '_')) {
      std::cerr << "[warn] federation request to invalid destination '"
                << destination << "'; skipping\n";
      return std::nullopt;
    }
  }

  json request_map = json::object();

  // if !http_request.body().is_empty() { request_map.insert("content", ...) }
  if (content.is_object() && !content.empty()) {
    request_map["content"] = content;
  }

  request_map["method"] = "POST";
  request_map["uri"] = path;
  request_map["origin"] = hostname;
  request_map["destination"] = destination;

  crypto::sign_json(hostname, keypair_seed, request_map);

  // X-Matrix origin=...,destination="...",key="...",sig="..." — NEW in
  // 63ba157e: include the destination so peers can validate it.
  std::string auth = "X-Matrix origin=" + hostname + ",destination=\"" +
                     destination + "\",key=\"";
  for (const auto& [server, sigs] : request_map["signatures"].items()) {
    for (auto it = sigs.begin(); it != sigs.end(); ++it) {
      auth += it.key() + "\",sig=\"" + it.value().get<std::string>() + "\"";
    }
    break;  // single key at this commit
  }

  // https://destination:8448<path> — federation port. NEW in dd749b8ae: a
  // server name may itself carry a port (e.g. "localhost:8448"); only append
  // the default 8448 when no port is present.
  std::string host = destination;
  int port = 8448;
  const auto colon = destination.find(':');
  if (colon != std::string::npos &&
      destination.find(':', colon + 1) == std::string::npos) {
    host = destination.substr(0, colon);
    try {
      port = std::stoi(destination.substr(colon + 1));
    } catch (...) {
      port = 8448;
    }
  }

  httplib::SSLClient client(host, static_cast<uint16_t>(port));
  client.enable_server_certificate_verification(false);  // sandbox proxy MITM
  client.set_connection_timeout(5);
  client.set_read_timeout(5);
  client.set_write_timeout(5);
  // NEW in 8def22bfb8: identify ourselves on outbound federation requests,
  // mirroring Conduit's reqwest user_agent("Conduit/<version>"). httplib has no
  // per-client default header, so it travels on every request via the Headers.
  httplib::Headers headers{
      {"Authorization", auth},
      {"Content-Type", "application/json"},
      {"User-Agent", "Conduit/0.11.0-alpha"},
  };
  auto res = client.Post(path, headers, request_map.dump(), "application/json");
  if (!res) {
    // a567cd81d: surface the failure reason so deserialization/transport
    // problems are diagnosable instead of silently swallowed.
    std::cerr << "[error] federation request to " << destination << path
              << " failed: " << httplib::to_string(res.error()) << "\n";
    return std::nullopt;
  }
  return json::parse(res->body, nullptr, false);
}

bool xmatrix_destination_ok(const std::string& authorization,
                            const std::string& self) {
  // Authorization: X-Matrix origin=...,destination="...",key="...",sig="..."
  const std::string prefix = "X-Matrix";
  if (authorization.size() <= prefix.size() ||
      authorization.compare(0, prefix.size(), prefix) != 0) {
    return true;  // not an X-Matrix request -> nothing to validate
  }
  const std::string rest = authorization.substr(prefix.size());
  const std::string key = "destination=";
  auto pos = rest.find(key);
  if (pos == std::string::npos) return true;  // no destination field -> ok
  pos += key.size();
  std::string val;
  if (pos < rest.size() && rest[pos] == '"') {
    const auto end = rest.find('"', pos + 1);
    val = rest.substr(pos + 1, (end == std::string::npos ? rest.size() : end) - pos - 1);
  } else {
    const auto end = rest.find_first_of(", ", pos);
    val = rest.substr(pos, (end == std::string::npos ? rest.size() : end) - pos);
  }
  return val == self;
}

}  // namespace federation
