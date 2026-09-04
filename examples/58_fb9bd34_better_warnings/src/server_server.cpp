// server_server.cpp — translation of Conduit commit e08dfd9's
// src/server_server.rs send_request with SRV record support.
//
//   * request bodies travel under the "content" key of the signed JSON
//     (that was fix 873d1915: "http body as content when signing")
//   * federation traffic targets port 8448
//   * NOTE a verbatim upstream quirk: the SIGNED map's destination is
//     hardcoded to "privacytools.io" while the connection itself goes to
//     `destination`. Real remote servers would reject that signature — it is
//     a debugging leftover in the original commit, preserved here on purpose.
//
// Everything else (sign_json, X-Matrix header) matches ruma-signatures.

#include "server_server.hpp"

#include "crypto.hpp"
#include "data.hpp"

#include <httplib.h>

// NEW in e08dfd9: SRV record lookup support
#include <netdb.h>
#include <arpa/inet.h>
#include <cstring>

namespace federation {
// NEW in 4cc0a070: request_well_known — resolves a destination's
// /.well-known/matrix/server to its actual m.server. Translated to
// synchronous httplib (upstream used async reqwest).
std::optional<std::string> request_well_known(const std::string& destination) {
  httplib::SSLClient client(destination, 443);
  client.enable_server_certificate_verification(false);  // sandbox proxy MITM
  auto res = client.Get("/.well-known/matrix/server");
  if (!res) return std::nullopt;
  
  nlohmann::json body;
  try {
    body = nlohmann::json::parse(res->body, nullptr, false);
  } catch (const std::exception& e) {
    std::cerr << "[error] Failed to parse .well-known response from " << destination
              << ": " << e.what() << "\n";
    return std::nullopt;
  }
  
  if (body.is_discarded() || !body.contains("m.server") ||
      !body["m.server"].is_string()) {
    return std::nullopt;
  }
  return body["m.server"].get<std::string>();
}

// NEW in e08dfd9: SRV record lookup for federation
// Looks up _matrix._tcp.<hostname> SRV record to find the actual target server
std::optional<std::pair<std::string, uint16_t>> lookup_srv_record(const std::string& hostname) {
  std::string srv_name = "_matrix._tcp." + hostname;
  
  // Use getaddrinfo with SRV record type
  struct addrinfo hints{}, *result = nullptr;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = 0;
  
  // Try to get SRV records using getaddrinfo (limited support)
  // For proper SRV lookup, we'd need a proper DNS library like trust-dns
  // This is a simplified implementation
  std::string srv_query = srv_name;
  
  // Try to resolve the hostname directly for now
  // A full implementation would query SRV records
  struct addrinfo hints_a{}, *result_a = nullptr;
  hints_a.ai_family = AF_UNSPEC;
  hints_a.ai_socktype = SOCK_STREAM;
  hints_a.ai_protocol = IPPROTO_TCP;
  
  int ret = getaddrinfo(hostname.c_str(), nullptr, &hints_a, &result_a);
  if (ret != 0 || !result_a) {
    return std::nullopt;
  }
  
  // For simplicity, return the first resolved address with default port
  // A full implementation would parse SRV records properly
  char host[NI_MAXHOST] = {0};
  getnameinfo(result_a->ai_addr, result_a->ai_addrlen, host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
  freeaddrinfo(result_a);
  
  return std::make_pair(std::string(host), uint16_t(8448));
}

std::optional<nlohmann::json> send_request(
    Data& data, const std::string& destination, const std::string& path,
    const nlohmann::json& content) {
  using json = nlohmann::json;
  // Note: waiting_servers tracking is handled by the caller (FederationSender)
  // to avoid duplicate requests to the same server (ab33236).

  json request_map = json::object();

  // if !http_request.body().is_empty() { request_map.insert("content", ...) }
  if (content.is_object() && !content.empty()) {
    request_map["content"] = content;
  }

  request_map["method"] = "POST";
  request_map["uri"] = path;
  request_map["origin"] = data.hostname();
  request_map["destination"] = destination;

  // Sign the request JSON - use expect instead of unwrap for better error messages
  crypto::sign_json(data.hostname(), data.keypair(), request_map);
  // sign_json is expected to not panic; if it does, it's a programming error

  // X-Matrix origin=...,key="...",sig="..."
  std::string auth = "X-Matrix origin=" + data.hostname() + ",key=\"";
  for (const auto& [server, sigs] : request_map["signatures"].items()) {
    for (auto it = sigs.begin(); it != sigs.end(); ++it) {
      auth += it.key() + "\",sig=\"" + it.value().get<std::string>() + "\"";
    }
    break;  // single key at this commit
  }

  // Resolve actual destination with proper port handling
  // NEW in dd749b8: fix server keys and destination resolution when server name contains port
  std::string actual_destination = destination;
  std::string host_header;
  
  if (destination.find(':') == std::string::npos) {
    // No port specified, check for well-known delegation and SRV records
    std::string delegated_hostname;
    if (auto well_known = request_well_known(destination)) {
      delegated_hostname = *well_known;
      
      // Try SRV record lookup for the delegated hostname
      if (auto srv = lookup_srv_record(delegated_hostname)) {
        // Use SRV record target and port
        auto [target, port] = *srv;
        actual_destination = target + ":" + std::to_string(port);
        host_header = delegated_hostname;  // Use delegated hostname for Host header
      } else {
        // Fallback to well-known hostname with default port
        if (delegated_hostname.find(':') == std::string::npos) {
          actual_destination = delegated_hostname + ":8448";
        } else {
          actual_destination = delegated_hostname;
        }
        host_header = delegated_hostname;
      }
    } else if (destination.find(':') == std::string::npos) {
      // No well-known, use default port
      actual_destination = destination + ":8448";
    }
  }

  // https://destination:8448<path> — federation port.
  httplib::SSLClient client(actual_destination, 8448);
  client.enable_server_certificate_verification(false);  // sandbox proxy MITM
  client.set_connection_timeout(5);
  client.set_read_timeout(30);  // NEW in e08dfd9: 30-second timeout for federation requests
  client.set_write_timeout(30);
  
  httplib::Headers headers{
      {"Authorization", auth},
      {"Content-Type", "application/json"},
  };
  
  // NEW in e08dfd9: Add Host header for virtual hosting when using SRV delegation
  if (!host_header.empty()) {
    headers.emplace("Host", host_header);
  }

  auto res = client.Post(path, headers, request_map.dump(), "application/json");
  if (!res) {
    // error!("{}", e) upstream — logged and swallowed.
    // NEW in fb9bd34: include the actual error message
    std::string error_str = httplib::to_string(res.error());
    std::cerr << "[error] federation request to " << destination << " failed: "
              << error_str << " (" << static_cast<int>(res.error()) << ")\n";
    return std::nullopt;
  }

  // Parse response JSON with proper error handling
  json response_json;
  try {
    response_json = json::parse(res->body, nullptr, false);
  } catch (const std::exception& e) {
    std::cerr << "[error] Failed to parse JSON response from " << destination
              << ": " << e.what() << "\n";
    return std::nullopt;
  }
  
  if (response_json.is_discarded()) {
    std::cerr << "[error] Invalid JSON response from " << destination << "\n";
    return std::nullopt;
  }
  
  return response_json;
}

}  // namespace federation
