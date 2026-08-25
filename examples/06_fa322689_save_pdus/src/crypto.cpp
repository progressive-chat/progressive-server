#include "crypto.hpp"

#include <openssl/evp.h>

namespace crypto {

std::string sha256(const std::string& input) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int length = 0;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(ctx, input.data(), input.size());
  EVP_DigestFinal_ex(ctx, digest, &length);
  EVP_MD_CTX_free(ctx);
  return std::string(reinterpret_cast<const char*>(digest), length);
}

std::string base64_url_nopad(const std::string& raw) {
  static const char* kB64 =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve(((raw.size() + 2) / 3) * 4);

  size_t i = 0;
  for (; i + 2 < raw.size(); i += 3) {
    const uint32_t n = (static_cast<unsigned char>(raw[i]) << 16) |
                       (static_cast<unsigned char>(raw[i + 1]) << 8) |
                       static_cast<unsigned char>(raw[i + 2]);
    out.push_back(kB64[(n >> 18) & 63]);
    out.push_back(kB64[(n >> 12) & 63]);
    out.push_back(kB64[(n >> 6) & 63]);
    out.push_back(kB64[n & 63]);
  }
  if (i < raw.size()) {
    const uint32_t byte0 = static_cast<unsigned char>(raw[i]);
    if (i + 1 == raw.size()) {
      out.push_back(kB64[(byte0 >> 2) & 63]);
      out.push_back(kB64[(byte0 & 3) << 4]);  // no '=' padding
    } else {
      const uint32_t n = (byte0 << 8) | static_cast<unsigned char>(raw[i + 1]);
      out.push_back(kB64[(n >> 10) & 63]);
      out.push_back(kB64[(n >> 4) & 63]);
      out.push_back(kB64[(n & 15) << 2]);
    }
  }
  return out;
}

json redact(const json& event) {
  static const char* kAllowed[] = {"auth_events", "content",    "depth",
                                   "hashes",      "origin",     "origin_server_ts",
                                   "prev_events", "prev_state", "room_id",
                                   "sender",      "signatures", "state_key",
                                   "type",        "event_id"};
  struct ContentRule {
    const char* type;
    std::vector<const char*> keys;
  };
  static const ContentRule kContentRules[] = {
      {"m.room.member", {"membership"}},
      {"m.room.create", {"creator"}},
      {"m.room.join_rules", {"join_rule"}},
      {"m.room.power_levels",
       {"ban", "events", "kick", "redact", "state_default", "users",
        "users_default", "invite"}},
      {"m.room.history_visibility", {"history_visibility"}},
  };

  const std::string type = event.value("type", "");
  json redacted = json::object();

  for (const char* key : kAllowed) {
    if (!event.contains(key)) continue;
    if (std::string(key) == "content") {
      json filtered = json::object();
      for (const ContentRule& rule : kContentRules) {
        if (type != rule.type) continue;
        for (const char* allowed : rule.keys) {
          if (event["content"].contains(allowed)) filtered[allowed] = event["content"][allowed];
        }
      }
      redacted["content"] = std::move(filtered);
    } else {
      redacted[key] = event[key];
    }
  }
  return redacted;
}

std::string reference_hash(const json& event) {
  return "$" + base64_url_nopad(sha256(redact(event).dump()));
}

}  // namespace crypto
