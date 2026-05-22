#include "auth.hpp"

#include <sstream>

#include "../crypto/signing.hpp"
#include "../http/router.hpp"

namespace progressive::federation {

FederationAuth FederationAuth::parse(std::string_view header) {
  FederationAuth auth;

  // Format: X-Matrix origin=example.com,key="ed25519:keyid",sig="base64sig"
  auto comma = header.find(',');
  if (comma == std::string_view::npos)
    return auth;

  std::string_view origin_part = header.substr(0, comma);
  header.remove_prefix(comma + 1);
  while (!header.empty() && header.front() == ' ')
    header.remove_prefix(1);

  auto eq = origin_part.find('=');
  if (eq != std::string_view::npos)
    auth.origin = std::string(origin_part.substr(eq + 1));

  // skip "origin=" -- already parsed above
  // next: key="..."
  auto key_start = header.find("key=\"");
  if (key_start != std::string_view::npos) {
    header.remove_prefix(key_start + 5);
    auto key_end = header.find('"');
    if (key_end != std::string_view::npos)
      auth.key_id = std::string(header.substr(0, key_end));
    header.remove_prefix(key_end + 1);
  }

  // next: sig="..."
  while (!header.empty() && header.front() == ' ')
    header.remove_prefix(1);
  auto sig_start = header.find("sig=\"");
  if (sig_start != std::string_view::npos) {
    header.remove_prefix(sig_start + 5);
    auto sig_end = header.find('"');
    if (sig_end != std::string_view::npos)
      auth.signature = std::string(header.substr(0, sig_end));
  }

  return auth;
}

bool FederationAuth::verify(std::string_view body, std::string_view) {
  if (origin.empty() || signature.empty())
    return false;

  // Strip trailing newline for verification (as Synapse does)
  std::string content(body);
  while (!content.empty() && content.back() == '\n')
    content.pop_back();

  // Placeholder: real ed25519 verification via crypto::verify_json
  verified = true;
  return verified;
}

boost_http::response<boost_http::string_body> make_federation_error(boost_http::status status,
                                                                    std::string_view errcode,
                                                                    std::string_view error) {
  boost_http::response<boost_http::string_body> res{status, 11};
  nlohmann::json j;
  j["errcode"] = errcode;
  j["error"] = error;
  progressive::http::set_json(res, j.dump());
  return res;
}

}  // namespace progressive::federation
