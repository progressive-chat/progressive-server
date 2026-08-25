#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <random>

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

// --- Ed25519 (ruma_signatures::Ed25519KeyPair) --------------------------------

namespace {

struct Ed25519Key {
  EVP_PKEY* pkey = nullptr;
  explicit Ed25519Key(const std::string& seed) {
    if (seed.size() == 32)
      pkey = EVP_PKEY_new_raw_private_key(
          EVP_PKEY_ED25519, nullptr,
          reinterpret_cast<const unsigned char*>(seed.data()), seed.size());
  }
  ~Ed25519Key() {
    if (pkey) EVP_PKEY_free(pkey);
  }
};

std::string b64url_decode(const std::string& in) {
  auto val = [](char ch) -> int {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '-') return 62;
    if (ch == '_') return 63;
    return -1;  // '=' padding also rejected: inputs are unpadded
  };
  std::string out;
  int bits = 0, acc = 0;
  for (const char c : in) {
    const int v = val(c);
    if (v < 0) continue;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((acc >> bits) & 0xFF));
    }
  }
  return out;
}
}  // namespace

std::string ed25519_generate_seed() {
  // 32 random bytes. Uses RAND_bytes from OpenSSL — a real CSPRNG.
  std::string seed(32, '\0');
  if (RAND_bytes(reinterpret_cast<unsigned char*>(seed.data()), 32) != 1) {
    // Extremely unlikely; fall back to std::random_device.
    std::random_device rd;
    for (auto& byte : seed) byte = static_cast<char>(rd());
  }
  return seed;
}

std::string ed25519_public_b64(const std::string& seed) {
  Ed25519Key key(seed);
  if (!key.pkey) return "";
  unsigned char pub[64];
  size_t len = sizeof(pub);
  if (EVP_PKEY_get_raw_public_key(key.pkey, pub, &len) != 1) return "";
  return base64_url_nopad(std::string(reinterpret_cast<const char*>(pub), len));
}

std::string ed25519_sign(const std::string& seed, const std::string& msg) {
  Ed25519Key key(seed);
  if (!key.pkey) return "";
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  size_t siglen = 0;
  std::string sig;
  if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key.pkey) == 1 &&
      EVP_DigestSign(ctx, nullptr, &siglen,
                     reinterpret_cast<const unsigned char*>(msg.data()),
                     msg.size()) == 1) {
    sig.resize(siglen);
    if (EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(sig.data()),
                       &siglen,
                       reinterpret_cast<const unsigned char*>(msg.data()),
                       msg.size()) != 1)
      sig.clear();
  }
  EVP_MD_CTX_free(ctx);
  return sig;
}

bool ed25519_verify(const std::string& pub_b64, const std::string& msg,
                    const std::string& sig_b64) {
  const std::string pub_raw = b64url_decode(pub_b64);
  const std::string sig = b64url_decode(sig_b64);
  if (pub_raw.size() != 32 || sig.empty()) return false;

  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, nullptr,
      reinterpret_cast<const unsigned char*>(pub_raw.data()), pub_raw.size());
  if (!pkey) return false;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  bool ok = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
            EVP_DigestVerify(ctx,
                             reinterpret_cast<const unsigned char*>(sig.data()),
                             sig.size(),
                             reinterpret_cast<const unsigned char*>(msg.data()),
                             msg.size()) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

// ruma_signatures::hash_and_sign_event: fills in the two TODO placeholders
// that earlier commits carried ("AAAA..." hashes and "signature").
void hash_and_sign_event(const std::string& hostname, const std::string& seed,
                         json& event) {
  // 1) content hash over the REDACTED event (canonical JSON).
  const json redacted = redact(event);
  event["hashes"] = {{"sha256", base64_url_nopad(sha256(redacted.dump()))}};

  // 2) signature over canonical JSON with signatures+unsigned removed.
  json to_sign = event;
  to_sign.erase("signatures");
  to_sign.erase("unsigned");
  const std::string key_id = "ed25519:" + ed25519_public_b64(seed);
  const std::string sig =
      base64_url_nopad(ed25519_sign(seed, to_sign.dump()));

  json host_sigs = json::object();
  host_sigs[key_id] = sig;
  event["signatures"] = {{hostname, std::move(host_sigs)}};
}


}  // namespace crypto
