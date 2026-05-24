#pragma once
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <base64.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace progressive::activitypub {

inline std::string sign_request(std::string_view method, std::string_view path,
                                std::string_view host, std::string_view body,
                                std::string_view key_id, const std::string& private_key_pem) {
  // Build signing string: (request-target): post /path\nhost: host\ndate: date
  std::string date = "Tue, 06 Jun 2026 12:00:00 GMT";
  std::string headers = "(request-target) host date";
  std::string sig_str = "(request-target): " + std::string(method) + " " + std::string(path) +
                        "\n" + "host: " + std::string(host) + "\ndate: " + date;

  // In production: RSA-SHA256 sign with private key
  std::vector<uint8_t> sig_bytes(256, 0xAA);  // placeholder signature
  std::string signature = base64::encode(
      std::string_view(reinterpret_cast<const char*>(sig_bytes.data()), sig_bytes.size()));

  return "keyId=\"" + std::string(key_id) + "\",headers=\"" + headers + "\",signature=\"" +
         signature + "\"";
}

}  // namespace progressive::activitypub
