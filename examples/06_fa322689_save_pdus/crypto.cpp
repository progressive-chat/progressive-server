#include "crypto.hpp"

// --- SHA-256 (FIPS 180-4). Standard compact implementation. -------------------

namespace {

constexpr uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

std::string sha256_impl(const std::string& input) {
  // Message schedule + padding per FIPS 180-4.
  std::string message = input;
  const uint64_t bit_len = static_cast<uint64_t>(message.size()) * 8;
  message.push_back(static_cast<char>(0x80));
  while (message.size() % 64 != 56) message.push_back('\0');
  for (int i = 7; i >= 0; --i) {
    message.push_back(static_cast<char>((bit_len >> (i * 8)) & 0xFF));
  }

  uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

  for (size_t chunk = 0; chunk < message.size(); chunk += 64) {
    uint32_t w[64];
    for (int t = 0; t < 16; ++t) {
      w[t] = (static_cast<uint32_t>(static_cast<unsigned char>(message[chunk + t * 4])) << 24) |
             (static_cast<uint32_t>(static_cast<unsigned char>(message[chunk + t * 4 + 1])) << 16) |
             (static_cast<uint32_t>(static_cast<unsigned char>(message[chunk + t * 4 + 2])) << 8) |
             static_cast<uint32_t>(static_cast<unsigned char>(message[chunk + t * 4 + 3]));
    }
    for (int t = 16; t < 64; ++t) {
      const uint32_t s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
      const uint32_t s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
      w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

    for (int t = 0; t < 64; ++t) {
      const uint32_t big_s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const uint32_t ch = (e & f) ^ (~e & g);
      const uint32_t temp1 = hh + big_s1 + ch + kK[t] + w[t];
      const uint32_t big_s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temp2 = big_s0 + maj;

      hh = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }

  std::string out;
  out.reserve(32);
  for (const uint32_t word : h) {
    for (int i = 3; i >= 0; --i) {
      out.push_back(static_cast<char>((word >> (i * 8)) & 0xFF));
    }
  }
  return out;
}

}  // namespace

namespace crypto {

std::string sha256(const std::string& input) { return sha256_impl(input); }

std::string sha256_hex(const std::string& input) {
  static const char* kHex = "0123456789abcdef";
  const std::string raw = sha256(input);
  std::string out;
  out.reserve(64);
  for (const char byte : raw) {
    out.push_back(kHex[(byte >> 4) & 0xF]);
    out.push_back(kHex[byte & 0xF]);
  }
  return out;
}

std::string base64_url_nopad(const std::string& raw) {
  static const char* kB64 =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";  // url-safe alphabet
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

json::Value redact(const json::Value& event) {
  // Keys kept on every event (room v1-v4 era algorithm).
  static const char* kAllowed[] = {"auth_events",     "content",       "depth",
                                   "hashes",          "origin",        "origin_server_ts",
                                   "prev_events",     "prev_state",    "room_id",
                                   "sender",          "signatures",    "state_key",
                                   "type",            "event_id"};
  // Content keys that survive redaction, per event type.
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

  const auto& obj = event.as_object();
  const std::string type = [&] {
    const auto it = obj.find("type");
    return it != obj.end() && it->second.is_string() ? it->second.as_string() : "";
  }();

  json::Object redacted;
  for (const char* key : kAllowed) {
    const auto it = obj.find(key);
    if (it == obj.end()) continue;
    if (std::string(key) == "content") {
      json::Object filtered;
      for (const ContentRule& rule : kContentRules) {
        if (type != rule.type) continue;
        for (const char* allowed_key : rule.keys) {
          const auto cit = it->second.as_object().find(allowed_key);
          if (cit != it->second.as_object().end()) {
            filtered.emplace(cit->first, cit->second);
          }
        }
      }
      redacted.emplace("content", json::Value(std::move(filtered)));
    } else {
      redacted.emplace(key, it->second);
    }
  }
  return json::Value(std::move(redacted));
}

std::string reference_hash(const json::Value& event) {
  const json::Value redacted_event = redact(event);
  return "$" + base64_url_nopad(sha256(redacted_event.canonical()));
}

}  // namespace crypto
