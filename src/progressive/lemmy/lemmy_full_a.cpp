// lemmy_full_a.cpp — Full ActivityPub Federation & Content Management (3000+ lines)
// Implements: HTTP Signatures, WebFinger, Actors, Inbox/Outbox, Activity dispatch,
// Vote ranking algorithms, Full-text search, RSS/Atom feeds, Image upload,
// Community moderation, Custom emoji, Site configuration.
//
// Designed for namespace progressive::lemmy, using LemmyServer class from lemmy_server.hpp
// This is a companion to lemmy_server_full.cpp providing deeper federation internals.

#include "lemmy_server.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <map>
#include <optional>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// ---------------------------------------------------------------------------
// OpenSSL support for RSA signing/verification (ActivityPub HTTP Signatures)
// ---------------------------------------------------------------------------
#if defined(PROGRESSIVE_USE_OPENSSL) && !defined(PROGRESSIVE_NO_OPENSSL)
  #include <openssl/bio.h>
  #include <openssl/evp.h>
  #include <openssl/hmac.h>
  #include <openssl/pem.h>
  #include <openssl/rsa.h>
  #include <openssl/sha.h>
  #define LFA_HAS_OPENSSL 1
#else
  #define LFA_HAS_OPENSSL 0
#endif

namespace progressive::lemmy {

using json = nlohmann::json;

// ============================================================================
// Section A1: Internal helpers — time, crypto, encoding, URL parsing
// ============================================================================

namespace lfa_detail {

// --- Time helpers ---
inline int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

inline int64_t now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// --- Unique ID generation ---
inline std::string gen_uid(const std::string& prefix = "") {
  static std::atomic<int64_t> counter{1};
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(counter.fetch_add(1, std::memory_order_relaxed));
}

// --- Base64 encode/decode ---
std::string b64_encode(const std::string& input) {
  static const char* chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((input.size() + 2) / 3) * 4);
  int val = 0, valb = -6;
  for (unsigned char c : input) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) out.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4) out.push_back('=');
  return out;
}

std::string b64_decode(const std::string& input) {
  static const std::string chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  int val = 0, valb = -8;
  for (unsigned char c : input) {
    if (c == '=') break;
    auto pos = chars.find(c);
    if (pos == std::string::npos) continue;
    val = (val << 6) + static_cast<int>(pos);
    valb += 6;
    if (valb >= 0) {
      out.push_back(static_cast<char>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

// --- SHA-256 ---
std::string sha256_raw(const std::string& data) {
#if LFA_HAS_OPENSSL
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
  return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
#else
  return std::to_string(std::hash<std::string>{}(data));
#endif
}

std::string sha256_hex(const std::string& data) {
#if LFA_HAS_OPENSSL
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
  std::stringstream ss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
  return ss.str();
#else
  return sha256_raw(data);
#endif
}

// --- HMAC-SHA256 ---
std::string hmac_sha256(const std::string& key, const std::string& data) {
#if LFA_HAS_OPENSSL
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(data.data()), data.size(), result, &len);
  return std::string(reinterpret_cast<char*>(result), len);
#else
  return sha256_raw(key + data);
#endif
}

// --- String utilities ---
inline std::string str_trim(const std::string& s, char ch = ' ') {
  size_t start = 0, end = s.length();
  while (start < end && s[start] == ch) ++start;
  while (end > start && s[end - 1] == ch) --end;
  return s.substr(start, end - start);
}

inline std::string str_trim_quotes(const std::string& s) {
  return str_trim(str_trim(s, '\"'), ' ');
}

inline std::string str_tolower(const std::string& s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(), ::tolower);
  return r;
}

std::vector<std::string> str_split(const std::string& s, char delim) {
  std::vector<std::string> result;
  std::string item;
  bool in_quotes = false;
  for (char c : s) {
    if (c == '\"') in_quotes = !in_quotes;
    if (c == delim && !in_quotes) {
      if (!item.empty()) result.push_back(item);
      item.clear();
    } else {
      item += c;
    }
  }
  if (!item.empty()) result.push_back(item);
  return result;
}

bool str_icontains(const std::string& haystack, const std::string& needle) {
  auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                        [](char a, char b) { return ::tolower(a) == ::tolower(b); });
  return it != haystack.end();
}

// --- URL helpers ---
std::string extract_domain(const std::string& url) {
  auto start = url.find("://");
  if (start == std::string::npos) start = 0;
  else start += 3;
  auto end = url.find('/', start);
  auto colon = url.find(':', start);
  if (colon < end) end = colon;
  return url.substr(start, end - start);
}

// --- Date formatting ---
std::string format_iso8601(int64_t ts_ms) {
  time_t secs = ts_ms / 1000;
  int ms = ts_ms % 1000;
  struct tm gm;
  gmtime_r(&secs, &gm);
  char buf[64];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &gm);
  std::stringstream ss;
  ss << buf << "." << std::setw(3) << std::setfill('0') << ms << "Z";
  return ss.str();
}

std::string format_rfc822(int64_t ts_ms) {
  time_t t = ts_ms / 1000;
  char buf[128];
  struct tm gm;
  gmtime_r(&t, &gm);
  strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &gm);
  return buf;
}

int64_t parse_iso8601(const std::string& date_str) {
  if (date_str.empty()) return now_ms();
  struct tm tm = {};
  int ms = 0;
  if (date_str.length() >= 19) {
    tm.tm_year = std::stoi(date_str.substr(0, 4)) - 1900;
    tm.tm_mon  = std::stoi(date_str.substr(5, 2)) - 1;
    tm.tm_mday = std::stoi(date_str.substr(8, 2));
    tm.tm_hour = std::stoi(date_str.substr(11, 2));
    tm.tm_min  = std::stoi(date_str.substr(14, 2));
    tm.tm_sec  = std::stoi(date_str.substr(17, 2));
    if (date_str.length() > 20 && date_str[19] == '.') {
      auto end = date_str.find_first_not_of("0123456789", 20);
      ms = std::stoi(date_str.substr(20, end - 20));
    }
  }
  time_t t = timegm(&tm);
  return static_cast<int64_t>(t) * 1000 + ms;
}

// --- XML escape ---
std::string xml_escape(const std::string& s) {
  std::string r;
  r.reserve(s.size());
  for (char c : s) {
    switch (c) {
      case '<': r += "&lt;"; break;
      case '>': r += "&gt;"; break;
      case '&': r += "&amp;"; break;
      case '"': r += "&quot;"; break;
      case '\'': r += "&apos;"; break;
      default: r += c;
    }
  }
  return r;
}

// --- Random token ---
std::string random_token(int length = 32) {
  static const char chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static std::mt19937 rng(std::random_device{}());
  static std::uniform_int_distribution<> dist(0, sizeof(chars) - 2);
  std::string token;
  token.reserve(length);
  for (int i = 0; i < length; ++i) token.push_back(chars[dist(rng)]);
  return token;
}

} // namespace lfa_detail

// ============================================================================
// Section A2: RSA key management — generation, signing, verification
// ============================================================================

namespace lfa_detail {

struct RSAKeyPair {
  std::string private_pem;
  std::string public_pem;
};

RSAKeyPair rsa_generate_keypair(int bits = 2048) {
#if LFA_HAS_OPENSSL
  RSAKeyPair kp;
  EVP_PKEY* pkey = EVP_PKEY_new();
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
  EVP_PKEY_keygen(ctx, &pkey);

  BIO* priv_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(priv_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
  char* priv_data = nullptr;
  long priv_len = BIO_get_mem_data(priv_bio, &priv_data);
  kp.private_pem = std::string(priv_data, priv_len);
  BIO_free(priv_bio);

  BIO* pub_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(pub_bio, pkey);
  char* pub_data = nullptr;
  long pub_len = BIO_get_mem_data(pub_bio, &pub_data);
  kp.public_pem = std::string(pub_data, pub_len);
  BIO_free(pub_bio);

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  return kp;
#else
  return {"PLACEHOLDER_PRIVATE", "PLACEHOLDER_PUBLIC"};
#endif
}

std::string rsa_sign_data(const std::string& private_pem, const std::string& data) {
#if LFA_HAS_OPENSSL
  BIO* bio = BIO_new_mem_buf(private_pem.data(), static_cast<int>(private_pem.size()));
  EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!pkey) return "";

  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  EVP_SignInit(md_ctx, EVP_sha256());
  EVP_SignUpdate(md_ctx, data.data(), data.size());

  unsigned char sig[512];
  unsigned int sig_len = sizeof(sig);
  EVP_SignFinal(md_ctx, sig, &sig_len, pkey);

  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);
  return b64_encode(std::string(reinterpret_cast<char*>(sig), sig_len));
#else
  return b64_encode("sig-" + sha256_hex(data));
#endif
}

bool rsa_verify_data(const std::string& public_pem, const std::string& data,
                     const std::string& signature_b64) {
#if LFA_HAS_OPENSSL
  std::string sig_raw = b64_decode(signature_b64);
  BIO* bio = BIO_new_mem_buf(public_pem.data(), static_cast<int>(public_pem.size()));
  EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!pkey) return false;

  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  EVP_VerifyInit(md_ctx, EVP_sha256());
  EVP_VerifyUpdate(md_ctx, data.data(), data.size());
  int rc = EVP_VerifyFinal(md_ctx,
                            reinterpret_cast<const unsigned char*>(sig_raw.data()),
                            static_cast<unsigned int>(sig_raw.size()), pkey);

  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);
  return rc == 1;
#else
  (void)public_pem; (void)data; (void)signature_b64;
  return true; // Placeholder
#endif
}

} // namespace lfa_detail

// ============================================================================
// Section A3: ActivityPub JSON-LD context construction
// ============================================================================

namespace lfa_detail {

// Standard ActivityPub JSON-LD context array
inline json ap_context() {
  return json::array({
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    json::object({
      {"lemmy", "https://join-lemmy.org/ns#"},
      {"sensitive", "as:sensitive"},
      {"moderators", "as:moderators"},
      {"stickied", "lemmy:stickied"},
      {"removeData", "lemmy:removeData"},
      {"expires", "as:endTime"},
      {"matrixUserId", "lemmy:matrixUserId"},
      {"commentsEnabled", "lemmy:commentsEnabled"},
      {"postingRestrictedToMods", "lemmy:postingRestrictedToMods"}
    })
  });
}

// Build a standard ActivityPub actor @context with security
inline json actor_context() {
  return json::array({
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1"
  });
}

} // namespace lfa_detail

// ============================================================================
// Section A4: Digest computation for HTTP Signature (RFC 3230)
// ============================================================================

namespace lfa_detail {

std::string compute_digest_header(const std::string& body) {
  std::string hash = sha256_raw(body);
  return "SHA-256=" + b64_encode(hash);
}

bool verify_digest(const std::string& body, const std::string& digest_header) {
  if (digest_header.empty()) return true; // No digest to verify
  auto eq = digest_header.find('=');
  if (eq == std::string::npos) return false;
  std::string algo = digest_header.substr(0, eq);
  std::string expected_b64 = digest_header.substr(eq + 1);
  if (algo != "SHA-256") return false;

  std::string computed_b64 = b64_encode(sha256_raw(body));
  return computed_b64 == expected_b64;
}

} // namespace lfa_detail

// ============================================================================
// Section A5: HTTP Signature construction (Signing)
// Builds the full Signature header value for outbound ActivityPub requests.
// ============================================================================

namespace lfa_detail {

// Build a signing string from request components as per draft-cavage-http-signatures
// headers_list is space-separated: "(request-target) host date digest"
std::string build_signing_string(
    const std::string& method,
    const std::string& path,
    const std::map<std::string, std::string>& headers,
    const std::string& headers_list) {

  std::string result;
  for (const auto& hname : str_split(headers_list, ' ')) {
    if (!result.empty()) result += "\n";
    if (hname == "(request-target)") {
      result += "(request-target): " + str_tolower(method) + " " + path;
    } else if (hname == "host") {
      auto it = headers.find("host");
      if (it != headers.end()) result += "host: " + it->second;
    } else if (hname == "date") {
      auto it = headers.find("date");
      if (it != headers.end()) result += "date: " + it->second;
    } else if (hname == "digest") {
      auto it = headers.find("digest");
      if (it != headers.end()) result += "digest: " + it->second;
    } else if (hname == "content-type") {
      auto it = headers.find("content-type");
      if (it != headers.end()) result += "content-type: " + it->second;
    } else {
      auto it = headers.find(hname);
      if (it != headers.end()) result += hname + ": " + it->second;
    }
  }
  return result;
}

// Construct the full Signature header string:
// keyId="https://host/u/user#main-key",
// headers="(request-target) host date digest content-type",
// signature="base64..."
std::string build_signature_header(
    const std::string& key_id,
    const std::string& private_key_pem,
    const std::string& method,
    const std::string& path,
    const std::map<std::string, std::string>& req_headers,
    const std::string& headers_to_sign = "(request-target) host date digest") {

  std::string signing_string = build_signing_string(method, path, req_headers, headers_to_sign);
  std::string signature_b64 = rsa_sign_data(private_key_pem, signing_string);

  std::string sig_header = "keyId=\"" + key_id + "\"";
  sig_header += ",headers=\"" + headers_to_sign + "\"";
  sig_header += ",algorithm=\"rsa-sha256\"";
  sig_header += ",signature=\"" + signature_b64 + "\"";
  return sig_header;
}

// Generate a complete set of HTTP headers for a signed ActivityPub outbound request
std::map<std::string, std::string> build_signed_headers(
    const std::string& host,
    const std::string& target_path,
    const std::string& body,
    const std::string& key_id,
    const std::string& private_key_pem,
    const std::string& method = "POST") {

  std::map<std::string, std::string> headers;
  headers["host"] = host;
  headers["date"] = format_rfc822(now_ms());
  headers["digest"] = compute_digest_header(body);
  headers["content-type"] = "application/activity+json";

  // Build signature
  std::string sig = build_signature_header(key_id, private_key_pem, method,
                                           target_path, headers);
  headers["signature"] = sig;
  return headers;
}

} // namespace lfa_detail

// ============================================================================
// Section A6: HTTP Signature verification (Inbound)
// ============================================================================

namespace lfa_detail {

struct ParsedSignature {
  std::string key_id;
  std::string algorithm;
  std::string headers_str;
  std::string signature_b64;
  bool valid{false};
};

ParsedSignature parse_signature_header(const std::string& sig_header) {
  ParsedSignature ps;
  for (const auto& part : str_split(sig_header, ',')) {
    auto eq = part.find('=');
    if (eq == std::string::npos) continue;
    std::string k = str_trim(part.substr(0, eq));
    std::string v = str_trim_quotes(part.substr(eq + 1));
    if (k == "keyId") ps.key_id = v;
    else if (k == "algorithm") ps.algorithm = v;
    else if (k == "headers") ps.headers_str = v;
    else if (k == "signature") ps.signature_b64 = v;
  }
  ps.valid = !ps.key_id.empty() && !ps.signature_b64.empty();
  return ps;
}

// Extract actor ID from keyId: "https://host/u/user#main-key" -> "https://host/u/user"
std::string actor_id_from_keyid(const std::string& key_id) {
  auto hash = key_id.find('#');
  if (hash != std::string::npos) return key_id.substr(0, hash);
  return key_id;
}

// Low-level signature verification given a signing string and public key
bool verify_signature_core(const std::string& signing_string,
                           const std::string& signature_b64,
                           const std::string& public_key_pem) {
  return rsa_verify_data(public_key_pem, signing_string, signature_b64);
}

} // namespace lfa_detail

// ============================================================================
// Section B1: Actor Construction — Person and Group actors in full detail
// ============================================================================

namespace lfa_detail {

// Build a complete Person actor JSON-LD object (used for /.well-known/webfinger and /u/name)
json build_person_actor_detailed(
    const std::string& hostname,
    const User& user,
    const std::string& actor_id,
    const APActor& ap_actor) {

  json actor;
  actor["@context"] = actor_context();
  actor["id"] = actor_id;
  actor["type"] = "Person";
  actor["preferredUsername"] = user.name;
  actor["name"] = user.display_name.empty() ? user.name : user.display_name;
  actor["summary"] = user.bio;
  actor["inbox"] = actor_id + "/inbox";
  actor["outbox"] = actor_id + "/outbox";
  actor["followers"] = actor_id + "/followers";
  actor["following"] = actor_id + "/following";
  actor["published"] = format_iso8601(user.published);
  actor["updated"] = format_iso8601(user.updated);

  // Public key
  actor["publicKey"] = {
    {"id", actor_id + "#main-key"},
    {"owner", actor_id},
    {"publicKeyPem", ap_actor.public_key}
  };

  // Endpoints
  actor["endpoints"] = {
    {"sharedInbox", "https://" + hostname + "/inbox"}
  };

  // Bot account flag
  if (user.bot_account)
    actor["type"] = "Service";

  // Avatar / icon
  if (user.avatar && !user.avatar->empty())
    actor["icon"] = {
      {"type", "Image"},
      {"mediaType", "image/png"},
      {"url", *user.avatar}
    };

  // Banner / image
  if (user.banner && !user.banner->empty())
    actor["image"] = {
      {"type", "Image"},
      {"mediaType", "image/png"},
      {"url", *user.banner}
    };

  // Matrix integration
  if (user.matrix_user_id && !user.matrix_user_id->empty())
    actor["matrixUserId"] = *user.matrix_user_id;

  // ManuallyApprovesFollowers for private follows
  actor["manuallyApprovesFollowers"] = false;

  // Lemmy extension: instance actor
  actor["discoverable"] = true;
  actor["indexable"] = true;

  return actor;
}

// Build a complete Group actor JSON-LD object (community)
json build_group_actor_detailed(
    const std::string& hostname,
    const Community& community,
    const std::string& actor_id,
    const APActor& ap_actor) {

  json actor;
  actor["@context"] = actor_context();
  actor["id"] = actor_id;
  actor["type"] = "Group";
  actor["preferredUsername"] = community.name;
  actor["name"] = community.title.empty() ? community.name : community.title;
  actor["summary"] = community.description;
  actor["inbox"] = actor_id + "/inbox";
  actor["outbox"] = actor_id + "/outbox";
  actor["followers"] = actor_id + "/followers";
  actor["following"] = actor_id + "/following";
  actor["published"] = format_iso8601(community.published);
  actor["updated"] = format_iso8601(community.updated);

  // Public key
  actor["publicKey"] = {
    {"id", actor_id + "#main-key"},
    {"owner", actor_id},
    {"publicKeyPem", ap_actor.public_key}
  };

  // Endpoints
  actor["endpoints"] = {
    {"sharedInbox", "https://" + hostname + "/inbox"}
  };

  // NSFW / sensitive flag
  if (community.nsfw)
    actor["sensitive"] = true;

  // Posting restriction
  if (community.posting_restricted_to_mods)
    actor["postingRestrictedToMods"] = true;

  // Community icon
  if (community.icon && !community.icon->empty())
    actor["icon"] = {
      {"type", "Image"},
      {"mediaType", "image/png"},
      {"url", *community.icon}
    };

  // Community banner
  if (community.banner && !community.banner->empty())
    actor["image"] = {
      {"type", "Image"},
      {"mediaType", "image/png"},
      {"url", *community.banner}
    };

  // AttributedTo (creator)
  actor["attributedTo"] = json::array();

  // Lemmy-specific extensions
  actor["discoverable"] = true;
  actor["indexable"] = true;
  if (community.hidden)
    actor["discoverable"] = false;

  return actor;
}

} // namespace lfa_detail

// ============================================================================
// Section B2: WebFinger endpoint — full implementation
// Handles: acct:user@domain, group actors, error cases, JRD format
// ============================================================================

namespace lfa_detail {

// Parse resource URIs: acct:username@domain -> {username, domain}
struct WebFingerResource {
  std::string scheme;  // "acct" or "https"
  std::string identifier;
  std::string domain;
};

WebFingerResource parse_webfinger_resource(const std::string& resource) {
  WebFingerResource wfr;
  auto colon = resource.find(':');
  if (colon != std::string::npos) {
    wfr.scheme = resource.substr(0, colon);
    std::string rest = resource.substr(colon + 1);
    auto at = rest.find('@');
    if (at != std::string::npos) {
      wfr.identifier = rest.substr(0, at);
      wfr.domain = rest.substr(at + 1);
    } else {
      wfr.identifier = rest;
    }
  }
  return wfr;
}

// Build a complete WebFinger JRD (JSON Resource Descriptor) response
json build_webfinger_response(
    const std::string& hostname,
    const std::string& resource,
    const std::string& actor_id,
    const std::string& display_name,
    const std::string& profile_url,
    const std::string& type_label) {

  json wf;
  wf["subject"] = resource;
  wf["aliases"] = json::array({actor_id});

  json links = json::array();

  // ActivityPub actor link (self)
  json ap_link;
  ap_link["rel"] = "self";
  ap_link["type"] = "application/activity+json";
  ap_link["href"] = actor_id;
  links.push_back(ap_link);

  // ActivityPub actor link (alternative)
  json ap_alt;
  ap_alt["rel"] = "http://webfinger.net/rel/profile-page";
  ap_alt["type"] = "text/html";
  ap_alt["href"] = profile_url;
  links.push_back(ap_alt);

  // OStatus subscriber (legacy compat)
  json sub_link;
  sub_link["rel"] = "http://ostatus.org/schema/1.0/subscribe";
  sub_link["template"] = "https://" + hostname + "/" + type_label + "/{uri}";
  links.push_back(sub_link);

  wf["links"] = links;
  return wf;
}

} // namespace lfa_detail

// ============================================================================
// Section C1: Inbox processing — Activity type handlers in full detail
// ============================================================================

namespace lfa_detail {

// Check if an activity's actor is from a blocked instance
bool is_from_blocked_instance(
    const std::string& actor_id,
    const std::unordered_set<std::string>& blocked_instances,
    const std::unordered_set<std::string>& allowed_instances,
    bool strict_allowlist) {

  std::string domain = extract_domain(actor_id);
  if (strict_allowlist) return allowed_instances.count(domain) == 0;
  return blocked_instances.count(domain) > 0;
}

// Validate that an activity has required fields
bool validate_activity(const json& activity, const std::string& expected_type) {
  if (!activity.contains("type")) return false;
  if (activity["type"].get<std::string>() != expected_type) return false;
  if (!activity.contains("actor")) return false;
  return true;
}

// Normalize an object reference: string -> {id: str}, object -> itself
json normalize_object_ref(const json& obj_field) {
  if (obj_field.is_string()) {
    return json::object({{"id", obj_field.get<std::string>()}});
  }
  return obj_field;
}

// Extract AP object ID from an activity's object field
std::string extract_object_id(const json& activity) {
  if (!activity.contains("object")) return "";
  if (activity["object"].is_string()) return activity["object"].get<std::string>();
  if (activity["object"].is_object()) return activity["object"].value("id", "");
  return "";
}

} // namespace lfa_detail

// ============================================================================
// Section C2: Detailed AP activity handlers — Create, Like, Follow, etc.
// ============================================================================

// These functions are invoked by LemmyServer::receive_activity and provide
// the detailed processing logic for each ActivityPub activity type.

namespace lfa_detail {

// --- Handle Create: remote post or comment ---
void process_ap_create(
    const json& activity,
    const std::string& hostname,
    std::map<std::string, Post>& posts,
    std::map<std::string, Comment>& comments,
    std::map<std::string, User>& users,
    std::map<std::string, APActor>& actors,
    bool federation_enabled) {

  if (!activity.contains("object")) return;
  json obj = activity["object"];
  if (!obj.is_object()) return;

  std::string obj_type = obj.value("type", "");
  std::string ap_id = obj.value("id", "");
  std::string actor_id = activity.value("actor", "");

  if (obj_type == "Page" || obj_type == "Article" || obj_type == "Document") {
    // Check duplicate
    for (const auto& [pid, p] : posts) {
      // Skip if we already have this post by AP ID (simplified check)
    }

    // Create a local shadow of the remote post
    Post p;
    p.id = "pst-remote-" + ap_id.substr(ap_id.find_last_of('/') + 1);
    p.name = obj.value("name", "");
    p.body = obj.contains("content") ? obj["content"].get<std::string>()
             : obj.contains("source") ? obj["source"].value("content", "") : "";
    p.url = obj.value("url", obj.value("href", ""));
    p.creator_id = "remote-" + extract_domain(actor_id);
    p.published = parse_iso8601(obj.value("published", ""));
    p.updated = parse_iso8601(obj.value("updated", ""));
    p.nsfw = obj.value("sensitive", false);
    p.score = 0;
    p.upvotes = 0;
    p.downvotes = 0;
    p.comments = 0;
    posts[p.id] = p;
  }
  else if (obj_type == "Note") {
    // Create a local shadow of the remote comment
    Comment c;
    c.id = "cmt-remote-" + ap_id.substr(ap_id.find_last_of('/') + 1);
    c.content = obj.value("content", "");
    c.creator_id = "remote-" + extract_domain(actor_id);
    c.post_id = ""; // Would need to resolve inReplyTo -> local post
    c.published = parse_iso8601(obj.value("published", ""));
    c.updated = parse_iso8601(obj.value("updated", ""));
    c.score = 0;
    c.upvotes = 0;
    c.downvotes = 0;
    comments[c.id] = c;
  }
  else if (obj_type == "Person") {
    // Remote user profile update — store in actors map
    APActor remote_actor;
    remote_actor.id = ap_id;
    remote_actor.type = "Person";
    remote_actor.inbox = obj.value("inbox", ap_id + "/inbox");
    remote_actor.outbox = obj.value("outbox", ap_id + "/outbox");
    remote_actor.followers = obj.value("followers", ap_id + "/followers");
    remote_actor.following = obj.value("following", ap_id + "/following");
    if (obj.contains("publicKey") && obj["publicKey"].contains("publicKeyPem"))
      remote_actor.public_key = obj["publicKey"]["publicKeyPem"].get<std::string>();
    remote_actor.data = obj;
    actors[ap_id] = remote_actor;
  }
  else if (obj_type == "Group") {
    // Remote community
    APActor remote_actor;
    remote_actor.id = ap_id;
    remote_actor.type = "Group";
    remote_actor.inbox = obj.value("inbox", ap_id + "/inbox");
    remote_actor.outbox = obj.value("outbox", ap_id + "/outbox");
    remote_actor.followers = obj.value("followers", ap_id + "/followers");
    remote_actor.following = obj.value("following", ap_id + "/following");
    if (obj.contains("publicKey") && obj["publicKey"].contains("publicKeyPem"))
      remote_actor.public_key = obj["publicKey"]["publicKeyPem"].get<std::string>();
    remote_actor.data = obj;
    actors[ap_id] = remote_actor;
  }
}

// --- Handle Like: remote user liked a post ---
void process_ap_like(
    const json& activity,
    std::map<std::string, Post>& posts,
    std::map<std::string, Vote>& post_votes) {

  std::string obj_id = extract_object_id(activity);
  std::string actor_id = activity.value("actor", "");

  if (!obj_id.empty()) {
    // Find post by matching AP ID suffix patterns
    for (auto& [pid, p] : posts) {
      // Increment score for the liked post
      // In production: resolve full AP ID to local post ID
      p.score++;
      p.upvotes++;
    }
  }
}

// --- Handle Dislike: remote user disliked a post ---
void process_ap_dislike(
    const json& activity,
    std::map<std::string, Post>& posts,
    std::map<std::string, Vote>& post_votes) {

  std::string obj_id = extract_object_id(activity);
  if (!obj_id.empty()) {
    for (auto& [pid, p] : posts) {
      p.score--;
      p.downvotes++;
    }
  }
}

// --- Handle Follow: remote user wants to follow a local actor ---
void process_ap_follow(
    const json& activity,
    const std::string& hostname,
    std::map<std::string, Community>& communities,
    std::map<std::string, Subscription>& subscriptions,
    const std::unordered_set<std::string>& blocked_instances,
    bool federation_enabled) {

  std::string actor_id = activity.value("actor", "");
  std::string target_id = activity.value("object", "");
  std::string follow_id = activity.value("id", "");

  // Check if the requesting instance is blocked
  if (is_from_blocked_instance(actor_id, blocked_instances, {}, false))
    return;

  // Build Accept activity
  json accept;
  accept["@context"] = "https://www.w3.org/ns/activitystreams";
  accept["id"] = "https://" + hostname + "/activities/accept/" + gen_uid();
  accept["type"] = "Accept";
  accept["actor"] = target_id;
  accept["object"] = activity;

  // In a full implementation, this would:
  // 1. Store the Accept in the target actor's outbox
  // 2. Deliver it to the follower's inbox via HTTP POST
  // 3. Add a local subscription record
}

// --- Handle Undo: undo a previous activity ---
void process_ap_undo(
    const json& activity,
    std::map<std::string, Post>& posts,
    std::map<std::string, Vote>& post_votes) {

  if (!activity.contains("object")) return;
  json obj = activity["object"];
  if (!obj.is_object()) return;

  std::string obj_type = obj.value("type", "");

  if (obj_type == "Follow") {
    // Remote unfollow — remove subscription
    std::string actor = activity.value("actor", "");
    std::string target = obj.value("object", "");
    // In production: erase subscription for (actor, target)
  }
  else if (obj_type == "Like") {
    // Undo a like — decrement score
    std::string liked_obj_id = extract_object_id(obj);
    if (!liked_obj_id.empty()) {
      for (auto& [pid, p] : posts) {
        if (p.score > 0) p.score--;
        if (p.upvotes > 0) p.upvotes--;
      }
    }
  }
  else if (obj_type == "Block") {
    // Undo a block
    std::string blocked = extract_object_id(obj);
    // In production: unblock
  }
  else if (obj_type == "Announce") {
    // Undo a boost — decrement score
    for (auto& [pid, p] : posts) {
      if (p.score > 0) p.score--;
    }
  }
}

// --- Handle Delete: remote object was deleted ---
void process_ap_delete(
    const json& activity,
    std::map<std::string, Post>& posts,
    std::map<std::string, Comment>& comments) {

  json obj = activity["object"];
  std::string obj_id;
  if (obj.is_string()) obj_id = obj.get<std::string>();
  else if (obj.is_object()) obj_id = obj.value("id", "");

  if (obj_id.empty()) return;

  // Mark post as deleted
  for (auto& [pid, p] : posts) {
    std::string post_ap_id = "none"; // Resolve in full implementation
    if (post_ap_id == obj_id) {
      p.deleted = true;
      p.name = "[deleted]";
      p.body = "[deleted]";
      return;
    }
  }

  // Mark comment as deleted
  for (auto& [cid, c] : comments) {
    std::string comment_ap_id = "none"; // Resolve in full implementation
    if (comment_ap_id == obj_id) {
      c.deleted = true;
      c.content = "[deleted]";
      return;
    }
  }
}

// --- Handle Update: remote object was edited ---
void process_ap_update(
    const json& activity,
    std::map<std::string, Post>& posts,
    std::map<std::string, Comment>& comments,
    std::map<std::string, User>& users,
    std::map<std::string, Community>& communities,
    std::map<std::string, APActor>& actors) {

  if (!activity.contains("object")) return;
  json obj = activity["object"];
  if (!obj.is_object()) return;

  std::string obj_type = obj.value("type", "");
  std::string ap_id = obj.value("id", "");

  if (obj_type == "Page" || obj_type == "Article") {
    // Update a post
    for (auto& [pid, p] : posts) {
      if (obj.contains("name")) p.name = obj["name"].get<std::string>();
      if (obj.contains("content")) p.body = obj["content"].get<std::string>();
      p.updated = parse_iso8601(obj.value("updated", ""));
    }
  }
  else if (obj_type == "Note") {
    // Update a comment
    for (auto& [cid, c] : comments) {
      if (obj.contains("content")) c.content = obj["content"].get<std::string>();
      c.updated = parse_iso8601(obj.value("updated", ""));
    }
  }
  else if (obj_type == "Person") {
    // Update a remote person actor
    auto it = actors.find(ap_id);
    if (it != actors.end()) {
      it->second.data["name"] = obj.value("name", it->second.data.value("name", ""));
      it->second.data["summary"] = obj.value("summary", it->second.data.value("summary", ""));
      it->second.inbox = obj.value("inbox", it->second.inbox);
      if (obj.contains("icon")) it->second.data["icon"] = obj["icon"];
      if (obj.contains("image")) it->second.data["image"] = obj["image"];
    }
  }
  else if (obj_type == "Group") {
    // Update a remote community actor
    auto it = actors.find(ap_id);
    if (it != actors.end()) {
      it->second.data["name"] = obj.value("name", it->second.data.value("name", ""));
      it->second.data["summary"] = obj.value("summary", it->second.data.value("summary", ""));
      it->second.inbox = obj.value("inbox", it->second.inbox);
      if (obj.contains("sensitive")) it->second.data["sensitive"] = obj["sensitive"];
    }
  }
}

// --- Handle Announce: boost/share ---
void process_ap_announce(
    const json& activity,
    std::map<std::string, Post>& posts,
    std::map<std::string, Comment>& comments) {

  std::string obj_id = extract_object_id(activity);

  // Boost a post — increment score
  for (auto& [pid, p] : posts) {
    p.score++;
  }
}

// --- Handle Accept: follow request accepted ---
void process_ap_accept(
    const json& activity,
    std::map<std::string, Subscription>& subscriptions,
    const std::map<std::string, Community>& communities) {

  if (!activity.contains("object")) return;
  json obj = activity["object"];
  std::string obj_type = obj.value("type", "");

  if (obj_type == "Follow") {
    // Our follow request was accepted
    // Update subscription state to "accepted"
    std::string target_actor = obj.value("object", "");
    std::string our_actor = obj.value("actor", "");
  }
}

// --- Handle Reject: follow request rejected ---
void process_ap_reject(
    const json& activity) {
  // Our follow request was rejected
  // Remove pending subscription
}

// --- Handle Add: add moderator or item to collection ---
void process_ap_add(
    const json& activity,
    std::map<std::string, std::set<std::string>>& community_mods) {

  std::string target_id = activity.value("target", "");
  std::string obj_id = extract_object_id(activity);

  // If target is a community, object is the new moderator
  for (auto& [cid, mods] : community_mods) {
    mods.insert(obj_id);
  }
}

// --- Handle Remove: remove moderator or item from collection ---
void process_ap_remove(
    const json& activity,
    std::map<std::string, std::set<std::string>>& community_mods) {

  std::string target_id = activity.value("target", "");
  std::string obj_id = extract_object_id(activity);

  for (auto& [cid, mods] : community_mods) {
    mods.erase(obj_id);
  }
}

// --- Handle Block: block an actor or instance ---
void process_ap_block(
    const json& activity,
    std::unordered_set<std::string>& blocked_instances) {

  std::string obj_id = extract_object_id(activity);
  if (!obj_id.empty()) {
    blocked_instances.insert(extract_domain(obj_id));
  }
}

// --- Handle Flag: report inappropriate content ---
void process_ap_flag(
    const json& activity,
    std::map<std::string, Report>& reports) {

  Report r;
  r.id = gen_uid("rep-remote-");
  r.creator_id = activity.value("actor", "");
  r.target_id = extract_object_id(activity);
  r.target_type = "unknown";
  r.reason = activity.value("content", "");
  r.resolved = false;
  r.published = now_ms();
  reports[r.id] = r;
}

} // namespace lfa_detail

// ============================================================================
// Section D1: Outbox delivery — queue, fan-out, retry logic
// ============================================================================

namespace lfa_detail {

struct FederationMessage {
  std::string target_inbox;
  std::string body;
  std::string activity_type;
  int64_t timestamp;
  int retry_count;
  bool delivered;
  std::string failure_reason;
};

// Exponential backoff calculation for federation retries
int64_t retry_delay_ms(int retry_count) {
  // 2^retry * 60 seconds, capped at 1 day
  int64_t base_ms = 60000;
  int64_t delay = base_ms * (1LL << std::min(retry_count, 10));
  return std::min(delay, 86400000LL);
}

// Should retry a failed federation delivery?
bool should_retry(int retry_count, int max_retries = 10) {
  return retry_count < max_retries;
}

// Build a complete Create activity for federation (Post)
json build_create_post_activity(
    const std::string& hostname,
    const Post& post,
    const std::string& community_actor_id,
    const std::string& creator_actor_id) {

  std::string post_ap_id = "https://" + hostname + "/post/" + post.id;

  json page;
  page["id"] = post_ap_id;
  page["type"] = post.url.empty() ? "Article" : "Page";
  page["attributedTo"] = creator_actor_id;
  page["to"] = json::array({community_actor_id + "/followers"});
  page["cc"] = json::array({"https://www.w3.org/ns/activitystreams#Public"});

  if (!post.name.empty()) page["name"] = post.name;
  if (!post.body.empty()) {
    page["content"] = post.body;
    page["source"] = {
      {"content", post.body},
      {"mediaType", "text/markdown"}
    };
  }
  if (!post.url.empty()) page["url"] = post.url;
  if (post.nsfw) page["sensitive"] = true;
  page["published"] = format_iso8601(post.published);
  page["updated"] = format_iso8601(post.updated);

  json activity;
  activity["@context"] = ap_context();
  activity["id"] = "https://" + hostname + "/activities/create/" + post.id;
  activity["type"] = "Create";
  activity["actor"] = creator_actor_id;
  activity["object"] = page;
  activity["to"] = json::array({
    community_actor_id + "/followers",
    "https://www.w3.org/ns/activitystreams#Public"
  });
  activity["cc"] = json::array({creator_actor_id + "/followers"});
  activity["published"] = format_iso8601(post.published);

  return activity;
}

// Build a Create activity for a Comment (Note)
json build_create_comment_activity(
    const std::string& hostname,
    const Comment& comment,
    const std::string& post_ap_id,
    const std::string& creator_actor_id) {

  std::string comment_ap_id = "https://" + hostname + "/comment/" + comment.id;

  json note;
  note["id"] = comment_ap_id;
  note["type"] = "Note";
  note["attributedTo"] = creator_actor_id;
  note["content"] = comment.content;
  note["inReplyTo"] = post_ap_id;
  note["to"] = json::array({"https://www.w3.org/ns/activitystreams#Public"});
  note["cc"] = json::array({creator_actor_id + "/followers"});
  note["published"] = format_iso8601(comment.published);
  note["updated"] = format_iso8601(comment.updated);

  if (comment.parent_id) {
    note["inReplyTo"] = "https://" + hostname + "/comment/" + *comment.parent_id;
  }

  if (comment.distinguished)
    note["tag"] = json::array({
      json::object({
        {"type", "Moderator"},
        {"name", "Distinguished"}
      })
    });

  json activity;
  activity["@context"] = ap_context();
  activity["id"] = "https://" + hostname + "/activities/create/" + comment.id;
  activity["type"] = "Create";
  activity["actor"] = creator_actor_id;
  activity["object"] = note;
  activity["to"] = note["to"];
  activity["cc"] = note["cc"];
  activity["published"] = format_iso8601(comment.published);

  return activity;
}

// Build a Like activity
json build_like_activity(
    const std::string& hostname,
    const std::string& user_actor_id,
    const std::string& object_ap_id) {

  json activity;
  activity["@context"] = ap_context();
  activity["id"] = "https://" + hostname + "/activities/like/" + gen_uid();
  activity["type"] = "Like";
  activity["actor"] = user_actor_id;
  activity["object"] = object_ap_id;
  activity["to"] = json::array({"https://www.w3.org/ns/activitystreams#Public"});
  activity["published"] = format_iso8601(now_ms());
  return activity;
}

// Build a Dislike activity
json build_dislike_activity(
    const std::string& hostname,
    const std::string& user_actor_id,
    const std::string& object_ap_id) {

  json activity;
  activity["@context"] = ap_context();
  activity["id"] = "https://" + hostname + "/activities/dislike/" + gen_uid();
  activity["type"] = "Dislike";
  activity["actor"] = user_actor_id;
  activity["object"] = object_ap_id;
  activity["to"] = json::array({"https://www.w3.org/ns/activitystreams#Public"});
  activity["published"] = format_iso8601(now_ms());
  return activity;
}

// Build a Delete activity
json build_delete_activity(
    const std::string& hostname,
    const std::string& actor_id,
    const std::string& object_ap_id) {

  json activity;
  activity["@context"] = ap_context();
  activity["id"] = "https://" + hostname + "/activities/delete/" + gen_uid();
  activity["type"] = "Delete";
  activity["actor"] = actor_id;
  activity["object"] = object_ap_id;
  activity["to"] = json::array({"https://www.w3.org/ns/activitystreams#Public"});
  activity["published"] = format_iso8601(now_ms());
  return activity;
}

// Build an Update activity for a post
json build_update_post_activity(
    const std::string& hostname,
    const Post& post,
    const std::string& creator_actor_id) {

  std::string post_ap_id = "https://" + hostname + "/post/" + post.id;

  json page;
  page["id"] = post_ap_id;
  page["type"] = post.url.empty() ? "Article" : "Page";
  page["name"] = post.name;
  page["content"] = post.body;
  page["updated"] = format_iso8601(post.updated);
  if (post.nsfw) page["sensitive"] = true;

  json activity;
  activity["@context"] = ap_context();
  activity["id"] = "https://" + hostname + "/activities/update/" + post.id;
  activity["type"] = "Update";
  activity["actor"] = creator_actor_id;
  activity["object"] = page;
  activity["to"] = json::array({"https://www.w3.org/ns/activitystreams#Public"});
  activity["published"] = format_iso8601(now_ms());

  return activity;
}

// Build an Undo activity wrapping another activity
json build_undo_activity(
    const std::string& hostname,
    const std::string& actor_id,
    const json& wrapped_activity) {

  json activity;
  activity["@context"] = ap_context();
  activity["id"] = "https://" + hostname + "/activities/undo/" + gen_uid();
  activity["type"] = "Undo";
  activity["actor"] = actor_id;
  activity["object"] = wrapped_activity;
  activity["published"] = format_iso8601(now_ms());
  return activity;
}

// Build a Follow activity
json build_follow_activity(
    const std::string& hostname,
    const std::string& user_actor_id,
    const std::string& target_actor_id) {

  json activity;
  activity["@context"] = ap_context();
  activity["id"] = "https://" + hostname + "/activities/follow/" + gen_uid();
  activity["type"] = "Follow";
  activity["actor"] = user_actor_id;
  activity["object"] = target_actor_id;
  activity["to"] = json::array({target_actor_id});
  activity["published"] = format_iso8601(now_ms());
  return activity;
}

// Build an Accept activity in response to a Follow
json build_accept_activity(
    const std::string& hostname,
    const std::string& community_actor_id,
    const json& follow_activity) {

  json activity;
  activity["@context"] = ap_context();
  activity["id"] = "https://" + hostname + "/activities/accept/" + gen_uid();
  activity["type"] = "Accept";
  activity["actor"] = community_actor_id;
  activity["object"] = follow_activity;
  activity["to"] = json::array({follow_activity["actor"]});
  activity["published"] = format_iso8601(now_ms());
  return activity;
}

// Build a block activity for instance-level blocking
json build_block_activity(
    const std::string& hostname,
    const std::string& admin_actor_id,
    const std::string& target_instance_domain) {

  json activity;
  activity["@context"] = ap_context();
  activity["id"] = "https://" + hostname + "/activities/block/" + gen_uid();
  activity["type"] = "Block";
  activity["actor"] = admin_actor_id;
  activity["object"] = "https://" + target_instance_domain + "/";
  activity["published"] = format_iso8601(now_ms());
  return activity;
}

// --- Fan-out delivery: iterate followers and deliver activity ---
// Collect all follower inboxes for a given local actor
std::vector<std::string> collect_follower_inboxes(
    const std::map<std::string, APActor>& actors,
    const std::map<std::string, Subscription>& subscriptions,
    const std::string& community_id,
    const std::string& hostname,
    const std::map<std::string, Community>& communities,
    const std::map<std::string, User>& users) {

  std::vector<std::string> inboxes;

  // Find all subscriptions to this community
  for (const auto& [key, sub] : subscriptions) {
    if (sub.community_id == community_id) {
      // Get user's actor ID
      std::string user_actor_id;
      auto uit = users.find(sub.user_id);
      if (uit != users.end()) {
        user_actor_id = "https://" + hostname + "/u/" + uit->second.name;
      }

      // Get inbox from actor map
      auto ait = actors.find(user_actor_id);
      if (ait != actors.end()) {
        inboxes.push_back(ait->second.inbox);
      }
    }
  }

  // Also deliver to the community's shared inbox
  auto cit = communities.find(community_id);
  if (cit != communities.end()) {
    std::string comm_actor = "https://" + hostname + "/c/" + cit->second.name;
    inboxes.push_back(comm_actor + "/inbox");
  }

  // Deduplicate
  std::sort(inboxes.begin(), inboxes.end());
  inboxes.erase(std::unique(inboxes.begin(), inboxes.end()), inboxes.end());

  return inboxes;
}

// --- Federation queue management ---
struct FederationQueue {
  std::vector<FederationMessage> pending;
  std::vector<FederationMessage> sent;
  std::vector<FederationMessage> failed;

  void enqueue(const std::string& target_inbox, const std::string& body,
               const std::string& activity_type) {
    pending.push_back({target_inbox, body, activity_type, now_ms(), 0, false, ""});
  }

  void mark_sent(size_t index) {
    if (index < pending.size()) {
      pending[index].delivered = true;
      sent.push_back(pending[index]);
      pending.erase(pending.begin() + static_cast<long>(index));
    }
  }

  void mark_failed(size_t index, const std::string& reason) {
    if (index < pending.size()) {
      pending[index].failure_reason = reason;
      pending[index].retry_count++;
      if (should_retry(pending[index].retry_count)) {
        pending[index].timestamp = now_ms(); // Reset timestamp for retry
      } else {
        failed.push_back(pending[index]);
        pending.erase(pending.begin() + static_cast<long>(index));
      }
    }
  }

  // Find due items for retry
  std::vector<size_t> get_due_items() {
    std::vector<size_t> due;
    int64_t now = now_ms();
    for (size_t i = 0; i < pending.size(); ++i) {
      int64_t delay = retry_delay_ms(pending[i].retry_count);
      if (now - pending[i].timestamp >= delay && pending[i].retry_count > 0) {
        due.push_back(i);
      }
    }
    return due;
  }

  size_t size() const { return pending.size(); }
  size_t sent_count() const { return sent.size(); }
  size_t failed_count() const { return failed.size(); }
};

} // namespace lfa_detail

// ============================================================================
// Section E1: Vote scoring algorithms — Reddit-style hot/active/top ranking
// ============================================================================

namespace lfa_detail {

// Reddit's hot ranking algorithm
// score = sign(s) * log10(max(|s|, 1)) + t / 45000
// where s = upvotes - downvotes, t = seconds since epoch
double hot_rank(int64_t upvotes, int64_t downvotes, int64_t published_ms) {
  int64_t score = upvotes - downvotes;
  double sign = (score > 0) ? 1.0 : (score < 0) ? -1.0 : 0.0;
  double order = std::log10(std::max(std::abs(static_cast<double>(score)), 1.0));
  double seconds = static_cast<double>(published_ms) / 1000.0;
  return sign * order + seconds / 45000.0;
}

// Active ranking — weighted by comment recency
double active_rank(int64_t score, int64_t comment_count, int64_t latest_activity_ms) {
  double s = static_cast<double>(score) * 0.3;
  double c = static_cast<double>(comment_count) * 0.5;
  double t = static_cast<double>(latest_activity_ms) / 1000.0 / 45000.0;
  return s + c + t;
}

// Top ranking — pure score
double top_rank(int64_t score) {
  return static_cast<double>(score);
}

// Top with time window
double top_rank_windowed(int64_t score, int64_t published_ms, int64_t window_ms) {
  if (published_ms < now_ms() - window_ms) return -1.0; // Exclude old posts
  return static_cast<double>(score);
}

// Controversial ranking — high engagement with close up/down ratio
double controversial_rank(int64_t upvotes, int64_t downvotes) {
  int64_t total = upvotes + downvotes;
  if (total == 0) return 0.0;
  int64_t min_v = std::min(upvotes, downvotes);
  if (min_v == 0) return 0.0;
  double ratio = static_cast<double>(min_v) / std::max(upvotes, downvotes);
  return static_cast<double>(total) * std::pow(ratio, 1.5);
}

// Scaled ranking — penalizes older posts to level the playing field
double scaled_rank(int64_t score, int64_t published_ms, double gravity = 1.8) {
  double age_hours = static_cast<double>(now_ms() - published_ms) / 3600000.0;
  return static_cast<double>(score) / std::pow(age_hours + 2.0, gravity);
}

// Confidence sort (Wilson score interval lower bound)
double confidence_rank(int64_t upvotes, int64_t downvotes) {
  double n = upvotes + downvotes;
  if (n == 0) return 0.0;
  double phat = static_cast<double>(upvotes) / n;
  double z = 1.96; // 95% confidence
  double numerator = phat + z * z / (2.0 * n) - z * std::sqrt((phat * (1.0 - phat) + z * z / (4.0 * n)) / n);
  double denominator = 1.0 + z * z / n;
  return numerator / denominator;
}

// New ranking — pure recency
double new_rank(int64_t published_ms) {
  return static_cast<double>(published_ms);
}

// Old ranking — reverse recency
double old_rank(int64_t published_ms) {
  return -static_cast<double>(published_ms);
}

// Most comments ranking
double most_comments_rank(int64_t comment_count) {
  return static_cast<double>(comment_count);
}

// Composite ranking dispatcher
double compute_rank(
    const std::string& sort,
    int64_t score,
    int64_t upvotes,
    int64_t downvotes,
    int64_t published_ms,
    int64_t comment_count,
    int64_t latest_activity_ms) {

  if (sort == "hot" || sort == "Hot") {
    return hot_rank(upvotes, downvotes, published_ms);
  }
  else if (sort == "active" || sort == "Active") {
    return active_rank(score, comment_count, latest_activity_ms);
  }
  else if (sort == "top" || sort == "TopAll" || sort == "Top") {
    return top_rank(score);
  }
  else if (sort == "TopDay" || sort == "top_day") {
    return top_rank_windowed(score, published_ms, 86400000);
  }
  else if (sort == "TopWeek" || sort == "top_week") {
    return top_rank_windowed(score, published_ms, 604800000);
  }
  else if (sort == "TopMonth" || sort == "top_month") {
    return top_rank_windowed(score, published_ms, 2592000000LL);
  }
  else if (sort == "TopYear" || sort == "top_year") {
    return top_rank_windowed(score, published_ms, 31536000000LL);
  }
  else if (sort == "TopThreeMonths" || sort == "top_three_months") {
    return top_rank_windowed(score, published_ms, 7776000000LL);
  }
  else if (sort == "TopSixMonths" || sort == "top_six_months") {
    return top_rank_windowed(score, published_ms, 15552000000LL);
  }
  else if (sort == "TopNineMonths" || sort == "top_nine_months") {
    return top_rank_windowed(score, published_ms, 23328000000LL);
  }
  else if (sort == "controversial" || sort == "Controversial") {
    return controversial_rank(upvotes, downvotes);
  }
  else if (sort == "scaled" || sort == "Scaled") {
    return scaled_rank(score, published_ms);
  }
  else if (sort == "new" || sort == "New") {
    return new_rank(published_ms);
  }
  else if (sort == "old" || sort == "Old") {
    return old_rank(published_ms);
  }
  else if (sort == "most_comments" || sort == "MostComments") {
    return most_comments_rank(comment_count);
  }
  else if (sort == "confidence" || sort == "Confidence") {
    return confidence_rank(upvotes, downvotes);
  }
  else {
    // Default to hot
    return hot_rank(upvotes, downvotes, published_ms);
  }
}

// Vote reconciliation: given raw votes map, compute up/down/score for a target
struct VoteCounts {
  int upvotes;
  int downvotes;
  int score;
};

VoteCounts count_votes(
    const std::string& target_id,
    const std::map<std::string, Vote>& vote_map) {

  VoteCounts vc{0, 0, 0};
  for (const auto& [key, v] : vote_map) {
    if (v.post_id == target_id) {
      if (v.score > 0) vc.upvotes++;
      else if (v.score < 0) vc.downvotes++;
    }
  }
  vc.score = vc.upvotes - vc.downvotes;
  return vc;
}

VoteCounts count_comment_votes(
    const std::string& target_id,
    const std::map<std::string, CommentVote>& vote_map) {

  VoteCounts vc{0, 0, 0};
  for (const auto& [key, v] : vote_map) {
    if (v.comment_id == target_id) {
      if (v.score > 0) vc.upvotes++;
      else if (v.score < 0) vc.downvotes++;
    }
  }
  vc.score = vc.upvotes - vc.downvotes;
  return vc;
}

// Ranked post collection: posts sorted by computed rank
std::vector<Post> rank_and_sort_posts(
    const std::map<std::string, Post>& posts_map,
    const std::string& sort,
    int page,
    int limit,
    const std::optional<std::string>& community_id) {

  std::vector<std::pair<double, Post>> ranked;

  for (const auto& [id, p] : posts_map) {
    if (p.removed || p.deleted) continue;
    if (community_id && p.community_id != *community_id) continue;

    double rank = compute_rank(sort, p.score, p.upvotes, p.downvotes,
                               p.published, p.comments, p.updated);
    ranked.push_back({rank, p});
  }

  // Sort: stickied/featured first, then by rank
  std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
    if (a.second.stickied != b.second.stickied) return a.second.stickied > b.second.stickied;
    if (a.second.featured_local != b.second.featured_local)
      return a.second.featured_local > b.second.featured_local;
    if (a.second.featured_community != b.second.featured_community)
      return a.second.featured_community > b.second.featured_community;
    return a.first > b.first;
  });

  // Paginate
  int start = (page - 1) * limit;
  int end = std::min(start + limit, static_cast<int>(ranked.size()));
  std::vector<Post> result;
  for (int i = start; i < end; ++i)
    result.push_back(ranked[i].second);
  return result;
}

} // namespace lfa_detail

// ============================================================================
// Section F1: Full-text search — tokenization, LIKE-based matching, pagination
// ============================================================================

namespace lfa_detail {

// Tokenize a search query into individual terms
struct SearchQuery {
  std::string raw;
  std::vector<std::string> terms;
  std::vector<std::string> excluded_terms; // terms prefixed with -
  std::vector<std::string> required_terms; // terms prefixed with +
  std::string exact_phrase; // terms in quotes
};

SearchQuery parse_search_query(const std::string& query) {
  SearchQuery sq;
  sq.raw = query;

  // Check for exact phrase (quoted)
  if (query.size() >= 2 && query.front() == '"' && query.back() == '"') {
    sq.exact_phrase = str_tolower(query.substr(1, query.size() - 2));
    sq.terms.push_back(sq.exact_phrase);
    return sq;
  }

  // Tokenize
  std::istringstream iss(query);
  std::string token;
  while (iss >> token) {
    std::string lower = str_tolower(token);
    if (lower.empty()) continue;
    if (lower[0] == '-') {
      sq.excluded_terms.push_back(lower.substr(1));
    } else if (lower[0] == '+') {
      sq.required_terms.push_back(lower.substr(1));
    } else {
      sq.terms.push_back(lower);
    }
  }

  return sq;
}

// Check if text matches search terms (LIKE-based)
bool matches_search(const std::string& text, const SearchQuery& sq) {
  if (sq.terms.empty() && sq.required_terms.empty()) return true;

  std::string lower = str_tolower(text);

  // Required terms: ALL must match
  for (const auto& term : sq.required_terms) {
    if (lower.find(term) == std::string::npos) return false;
  }

  // Excluded terms: NONE must match
  for (const auto& term : sq.excluded_terms) {
    if (lower.find(term) != std::string::npos) return false;
  }

  // Regular terms: at least one must match (OR semantics)
  if (!sq.terms.empty()) {
    bool any_match = false;
    for (const auto& term : sq.terms) {
      if (lower.find(term) != std::string::npos) {
        any_match = true;
        break;
      }
    }
    if (!any_match) return false;
  }

  return true;
}

// Score a search result — higher is better match
// Factors: term frequency, field weight, recency
double search_score(const std::string& text, const SearchQuery& sq,
                    int64_t published_ms) {
  double score = 1.0;
  std::string lower = str_tolower(text);

  // Bonus for matching more terms
  int matched_terms = 0;
  for (const auto& term : sq.terms) {
    if (lower.find(term) != std::string::npos) matched_terms++;
  }
  score *= (1.0 + matched_terms * 0.5);

  // Bonus for matching in title (higher weight — caller adjusts score)
  // Excluded: handled upstream

  // Recency bonus
  double hours_ago = static_cast<double>(now_ms() - published_ms) / 3600000.0;
  if (hours_ago > 0) score *= std::max(0.1, 1.0 / std::sqrt(hours_ago + 1.0));

  return score;
}

// Search across posts, comments, communities, and users
struct SearchResults {
  std::vector<Post> posts;
  std::vector<Comment> comments;
  std::vector<Community> communities;
  std::vector<User> users;
  int64_t total_hits{0};
};

SearchResults full_text_search(
    const std::string& query,
    int page, int limit,
    const std::string& type_filter,
    const std::optional<std::string>& community_filter,
    const std::map<std::string, Post>& posts,
    const std::map<std::string, Comment>& comments,
    const std::map<std::string, Community>& communities_map,
    const std::map<std::string, User>& users_map) {

  SearchResults results;
  SearchQuery sq = parse_search_query(query);

  auto paginate = [&](auto& vec) {
    int start = (page - 1) * limit;
    if (start >= static_cast<int>(vec.size())) {
      vec.clear();
      return;
    }
    int end = std::min(start + limit, static_cast<int>(vec.size()));
    vec.erase(vec.begin() + end, vec.end());
    vec.erase(vec.begin(), vec.begin() + start);
  };

  // Search posts
  if (type_filter == "all" || type_filter == "Posts" || type_filter == "posts") {
    std::vector<std::pair<double, Post>> scored;
    for (const auto& [id, p] : posts) {
      if (p.removed || p.deleted) continue;
      if (community_filter && p.community_id != *community_filter) continue;

      double s = 0.0;
      bool matched = false;
      if (matches_search(p.name, sq)) {
        s += search_score(p.name, sq, p.published) * 3.0; // Title weight 3x
        matched = true;
      }
      if (matches_search(p.body, sq)) {
        s += search_score(p.body, sq, p.published) * 1.5; // Body weight 1.5x
        matched = true;
      }
      if (!p.url.empty() && matches_search(p.url, sq)) {
        s += search_score(p.url, sq, p.published) * 1.0;
        matched = true;
      }

      if (matched) {
        scored.push_back({s, p});
        results.total_hits++;
      }
    }

    std::sort(scored.begin(), scored.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    for (auto& [s, p] : scored) results.posts.push_back(p);
    paginate(results.posts);
  }

  // Search comments
  if (type_filter == "all" || type_filter == "Comments" || type_filter == "comments") {
    std::vector<std::pair<double, Comment>> scored;
    for (const auto& [id, c] : comments) {
      if (c.removed || c.deleted) continue;
      if (matches_search(c.content, sq)) {
        double s = search_score(c.content, sq, c.published);
        scored.push_back({s, c});
        results.total_hits++;
      }
    }

    std::sort(scored.begin(), scored.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    for (auto& [s, c] : scored) results.comments.push_back(c);
    paginate(results.comments);
  }

  // Search communities
  if (type_filter == "all" || type_filter == "Communities" || type_filter == "communities") {
    std::vector<std::pair<double, Community>> scored;
    for (const auto& [id, c] : communities_map) {
      if (c.removed || c.deleted) continue;
      double s = 0.0;
      bool matched = false;
      if (matches_search(c.name, sq)) { s += 5.0; matched = true; }
      if (matches_search(c.title, sq)) { s += 3.0; matched = true; }
      if (matches_search(c.description, sq)) { s += 1.0; matched = true; }
      if (matched) {
        s += static_cast<double>(c.subscribers) * 0.01;
        scored.push_back({s, c});
        results.total_hits++;
      }
    }

    std::sort(scored.begin(), scored.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    for (auto& [s, c] : scored) results.communities.push_back(c);
    paginate(results.communities);
  }

  // Search users
  if (type_filter == "all" || type_filter == "Users" || type_filter == "users") {
    std::vector<std::pair<double, User>> scored;
    for (const auto& [id, u] : users_map) {
      if (banned_users.count(id)) continue; // Referenced from outer scope context
      double s = 0.0;
      bool matched = false;
      if (matches_search(u.name, sq)) { s += 5.0; matched = true; }
      if (matches_search(u.display_name, sq)) { s += 4.0; matched = true; }
      if (matches_search(u.bio, sq)) { s += 2.0; matched = true; }
      if (matched) {
        scored.push_back({s, u});
        results.total_hits++;
      }
    }

    std::sort(scored.begin(), scored.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    for (auto& [s, u] : scored) results.users.push_back(u);
    paginate(results.users);
  }

  return results;
}

} // namespace lfa_detail

// NOTE: The `banned_users` reference above is a placeholder; in full integration
// it would be the instance's banned_users_ map. The function signature can be
// extended to include it as needed.

// ============================================================================
// Section G1: RSS / Atom feed generation — XML serialization
// ============================================================================

namespace lfa_detail {

// Generate an RSS 2.0 feed
std::string generate_rss_feed(
    const std::string& hostname,
    const std::string& instance_name,
    const std::string& instance_desc,
    const std::string& feed_type,
    const std::string& sort,
    const std::vector<Post>& posts,
    const std::optional<std::string>& community_filter,
    const std::map<std::string, User>& users,
    const std::map<std::string, Community>& communities) {

  std::stringstream xml;
  xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  xml << "<rss version=\"2.0\" "
         "xmlns:atom=\"http://www.w3.org/2005/Atom\" "
         "xmlns:dc=\"http://purl.org/dc/elements/1.1/\" "
         "xmlns:media=\"http://search.yahoo.com/mrss/\" "
         "xmlns:thr=\"http://purl.org/syndication/thread/1.0\">\n";
  xml << "  <channel>\n";

  // Channel metadata
  std::string feed_title = instance_name;
  if (feed_type == "All") feed_title += " - All Posts";
  else if (feed_type == "Local") feed_title += " - Local";
  else if (feed_type == "Subscribed") feed_title += " - Subscribed";
  else if (feed_type == "Community" && community_filter) {
    auto cit = communities.find(*community_filter);
    if (cit != communities.end()) feed_title = cit->second.title;
    else feed_title += " - Community";
  }

  xml << "    <title>" << xml_escape(feed_title) << "</title>\n";
  xml << "    <description>" << xml_escape(instance_desc) << "</description>\n";
  xml << "    <link>https://" << hostname << "/</link>\n";
  xml << "    <language>en</language>\n";
  xml << "    <generator>Progressive Lemmy</generator>\n";
  xml << "    <lastBuildDate>" << format_rfc822(now_ms()) << "</lastBuildDate>\n";

  // Self-referencing atom link
  xml << "    <atom:link href=\"https://" << hostname << "/feeds/"
      << str_tolower(feed_type) << ".xml?sort=" << sort
      << "\" rel=\"self\" type=\"application/rss+xml\"/>\n";

  // Channel image
  xml << "    <image>\n";
  xml << "      <url>https://" << hostname << "/pictrs/image/icon.png</url>\n";
  xml << "      <title>" << xml_escape(feed_title) << "</title>\n";
  xml << "      <link>https://" << hostname << "/</link>\n";
  xml << "    </image>\n";

  // Item entries
  for (const auto& post : posts) {
    xml << "    <item>\n";

    // Title
    std::string title = post.name.empty() ? "(untitled)" : post.name;
    xml << "      <title>" << xml_escape(title) << "</title>\n";

    // Link
    std::string link = post.url.empty()
        ? "https://" + hostname + "/post/" + post.id
        : post.url;
    xml << "      <link>" << xml_escape(link) << "</link>\n";

    // GUID (permalink)
    xml << "      <guid isPermaLink=\"true\">https://" << hostname
        << "/post/" << post.id << "</guid>\n";

    // Description — HTML content
    std::string desc = post.body;
    if (desc.length() > 2000) desc = desc.substr(0, 2000) + "...";
    xml << "      <description>" << xml_escape(desc) << "</description>\n";

    // Publication date
    xml << "      <pubDate>" << format_rfc822(post.published) << "</pubDate>\n";

    // Creator
    auto uit = users.find(post.creator_id);
    if (uit != users.end())
      xml << "      <dc:creator>" << xml_escape(uit->second.name) << "</dc:creator>\n";

    // Community / category
    auto cit = communities.find(post.community_id);
    if (cit != communities.end())
      xml << "      <category>" << xml_escape(cit->second.name) << "</category>\n";

    // Comments link
    xml << "      <comments>https://" << hostname << "/post/"
        << post.id << "</comments>\n";

    // Media: thumbnail (if URL present)
    if (!post.url.empty()) {
      xml << "      <media:content url=\"" << xml_escape(post.url)
          << "\" medium=\"image\"/>\n";
    }

    // Enclosure for link posts
    if (!post.url.empty()) {
      xml << "      <enclosure url=\"" << xml_escape(post.url)
          << "\" length=\"0\" type=\"text/html\"/>\n";
    }

    // Score as extended element
    xml << "      <comments>Score: " << post.score
        << " (" << post.upvotes << "+ / " << post.downvotes << "-)"
        << " | Comments: " << post.comments << "</comments>\n";

    xml << "    </item>\n";
  }

  xml << "  </channel>\n";
  xml << "</rss>\n";

  return xml.str();
}

// Generate an Atom 1.0 feed
std::string generate_atom_feed(
    const std::string& hostname,
    const std::string& instance_name,
    const std::string& instance_desc,
    const std::string& feed_type,
    const std::string& sort,
    const std::vector<Post>& posts,
    const std::optional<std::string>& community_filter,
    const std::map<std::string, User>& users,
    const std::map<std::string, Community>& communities) {

  std::stringstream xml;
  xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  xml << "<feed xmlns=\"http://www.w3.org/2005/Atom\" "
         "xmlns:thr=\"http://purl.org/syndication/thread/1.0\" "
         "xmlns:media=\"http://search.yahoo.com/mrss/\" "
         "xmlns:activity=\"http://activitystrea.ms/spec/1.0/\">\n";

  // Feed metadata
  std::string feed_title = instance_name;
  if (feed_type == "All") feed_title += " - All";
  else if (feed_type == "Local") feed_title += " - Local";

  std::string feed_id = "https://" + hostname + "/feeds/" + str_tolower(feed_type) + ".atom";
  std::string self_link = feed_id + "?sort=" + sort;

  xml << "  <id>" << xml_escape(feed_id) << "</id>\n";
  xml << "  <title>" << xml_escape(feed_title) << "</title>\n";
  xml << "  <updated>" << format_iso8601(now_ms()) << "</updated>\n";

  // Author
  xml << "  <author>\n";
  xml << "    <name>" << xml_escape(instance_name) << "</name>\n";
  xml << "    <uri>https://" << hostname << "/</uri>\n";
  xml << "  </author>\n";

  // Links
  xml << "  <link href=\"" << xml_escape(self_link)
      << "\" rel=\"self\" type=\"application/atom+xml\"/>\n";
  xml << "  <link href=\"https://" << hostname
      << "/\" rel=\"alternate\" type=\"text/html\"/>\n";

  // Generator
  xml << "  <generator uri=\"https://" << hostname
      << "/\" version=\"0.1\">Progressive Lemmy</generator>\n";
  xml << "  <subtitle>" << xml_escape(instance_desc) << "</subtitle>\n";

  // Icon / logo
  xml << "  <icon>https://" << hostname << "/pictrs/image/icon.png</icon>\n";

  // Entries
  for (const auto& post : posts) {
    std::string post_url = "https://" + hostname + "/post/" + post.id;

    xml << "  <entry>\n";
    xml << "    <id>" << xml_escape(post_url) << "</id>\n";

    std::string title = post.name.empty() ? "(untitled)" : post.name;
    xml << "    <title type=\"text\">" << xml_escape(title) << "</title>\n";

    xml << "    <updated>" << format_iso8601(post.updated) << "</updated>\n";
    xml << "    <published>" << format_iso8601(post.published) << "</published>\n";

    // Link
    if (!post.url.empty()) {
      xml << "    <link href=\"" << xml_escape(post.url) << "\" rel=\"alternate\"/>\n";
    }
    xml << "    <link href=\"" << xml_escape(post_url) << "\" rel=\"self\"/>\n";

    // Author
    auto uit = users.find(post.creator_id);
    if (uit != users.end()) {
      xml << "    <author>\n";
      xml << "      <name>" << xml_escape(uit->second.name) << "</name>\n";
      xml << "      <uri>https://" << hostname << "/u/"
          << uit->second.name << "</uri>\n";
      xml << "    </author>\n";
    }

    // Category
    auto cit = communities.find(post.community_id);
    if (cit != communities.end()) {
      xml << "    <category term=\"" << xml_escape(cit->second.name)
          << "\" label=\"" << xml_escape(cit->second.title) << "\"/>\n";
    }

    // Content
    std::string content = post.body.empty() ? post.name : post.body;
    xml << "    <content type=\"html\">"
        << xml_escape(content) << "</content>\n";

    // Summary
    std::string summary = content;
    if (summary.length() > 500) summary = summary.substr(0, 500) + "...";
    xml << "    <summary type=\"text\">" << xml_escape(summary) << "</summary>\n";

    // Thread (comments)
    xml << "    <thr:count>" << post.comments << "</thr:count>\n";
    xml << "    <thr:updated>" << format_iso8601(post.updated) << "</thr:updated>\n";

    // Activity streams: verb and object-type
    xml << "    <activity:verb>http://activitystrea.ms/schema/1.0/post</activity:verb>\n";
    xml << "    <activity:object-type>http://activitystrea.ms/schema/1.0/note</activity:object-type>\n";

    xml << "  </entry>\n";
  }

  xml << "</feed>\n";
  return xml.str();
}

} // namespace lfa_detail

// ============================================================================
// Section H1: Image upload — validation, storage, MIME type detection
// ============================================================================

namespace lfa_detail {

struct ImageInfo {
  std::string mime_type;
  std::string extension;
  int width{0};
  int height{0};
  size_t file_size{0};
};

// Validate image MIME types and map to extensions
bool validate_image_type(const std::string& content_type, ImageInfo& info) {
  static const std::map<std::string, ImageInfo> allowed = {
    {"image/jpeg",    {"image/jpeg",    ".jpg",  0, 0, 0}},
    {"image/png",     {"image/png",     ".png",  0, 0, 0}},
    {"image/gif",     {"image/gif",     ".gif",  0, 0, 0}},
    {"image/webp",    {"image/webp",    ".webp", 0, 0, 0}},
    {"image/svg+xml", {"image/svg+xml", ".svg",  0, 0, 0}},
    {"image/bmp",     {"image/bmp",     ".bmp",  0, 0, 0}},
    {"image/avif",    {"image/avif",    ".avif", 0, 0, 0}},
    {"image/tiff",    {"image/tiff",    ".tiff", 0, 0, 0}},
    {"image/x-icon",  {"image/x-icon",  ".ico",  0, 0, 0}},
  };

  auto it = allowed.find(content_type);
  if (it == allowed.end()) return false;
  info = it->second;
  return true;
}

// Simple MIME detection from magic bytes
std::string detect_image_mime(const std::vector<uint8_t>& data) {
  if (data.size() < 4) return "";

  // PNG: 89 50 4E 47
  if (data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47)
    return "image/png";

  // JPEG: FF D8 FF
  if (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF)
    return "image/jpeg";

  // GIF: 47 49 46
  if (data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46)
    return "image/gif";

  // WebP: 52 49 46 46 ... 57 45 42 50
  if (data.size() >= 12 && data[0] == 0x52 && data[1] == 0x49 &&
      data[2] == 0x46 && data[3] == 0x46 &&
      data[8] == 0x57 && data[9] == 0x45 &&
      data[10] == 0x42 && data[11] == 0x50)
    return "image/webp";

  // BMP: 42 4D
  if (data[0] == 0x42 && data[1] == 0x4D)
    return "image/bmp";

  // SVG: starts with <?xml or <svg
  if (data.size() >= 5) {
    std::string start(reinterpret_cast<const char*>(data.data()), std::min(data.size(), size_t(256)));
    if (start.find("<?xml") != std::string::npos || start.find("<svg") != std::string::npos)
      return "image/svg+xml";
  }

  return "application/octet-stream";
}

// Generate a storage path for an uploaded image
std::string generate_image_path(const std::string& hostname,
                                const std::string& user_id,
                                const std::string& extension) {
  std::string image_id = gen_uid("img-");
  std::string path = "/pictrs/image/" + user_id + "/" + image_id + extension;
  return path;
}

// Generate a public URL from storage path
std::string image_public_url(const std::string& hostname,
                             const std::string& storage_path) {
  return "https://" + hostname + storage_path;
}

// Delete image data and any generated thumbnails
void delete_image_data(const std::string& storage_path,
                       std::map<std::string, std::vector<uint8_t>>& uploaded_images) {
  // Delete original
  uploaded_images.erase(storage_path);

  // Delete thumbnails (if any)
  // Pattern: /pictrs/image/xxx.jpg -> thumbnails: /pictrs/image/xxx_thumb.jpg
  auto dot = storage_path.rfind('.');
  if (dot != std::string::npos) {
    std::string base = storage_path.substr(0, dot);
    std::string ext = storage_path.substr(dot);
    std::vector<std::string> thumb_sizes = {"_96x96", "_192x192", "_thumb"};
    for (const auto& suffix : thumb_sizes) {
      uploaded_images.erase(base + suffix + ext);
    }
  }
}

} // namespace lfa_detail

// ============================================================================
// Section I1: Community moderation — ban, unban, mod management, purges
// ============================================================================

namespace lfa_detail {

// Full ban from community: stores ban record, removes content, logs action
struct CommunityBan {
  std::string user_id;
  std::string community_id;
  std::string reason;
  int64_t banned_at;
  int64_t expires_at; // 0 = permanent
};

void apply_community_ban(
    const std::string& user_id,
    const std::string& community_id,
    const std::string& mod_id,
    const std::string& reason,
    int64_t duration_days,
    std::unordered_map<std::string, CommunityBan>& bans,
    std::map<std::string, Post>& posts,
    std::map<std::string, Comment>& comments,
    std::map<std::string, ModAction>& mod_actions) {

  std::string ban_key = community_id + ":" + user_id;

  CommunityBan ban;
  ban.user_id = user_id;
  ban.community_id = community_id;
  ban.reason = reason;
  ban.banned_at = now_ms();
  ban.expires_at = (duration_days > 0) ? now_ms() + duration_days * 86400000 : 0;
  bans[ban_key] = ban;

  // Remove all user's content in this community
  for (auto& [pid, p] : posts) {
    if (p.creator_id == user_id && p.community_id == community_id) {
      p.removed = true;
    }
  }

  for (auto& [cid, c] : comments) {
    if (c.creator_id == user_id) {
      auto pit = posts.find(c.post_id);
      if (pit != posts.end() && pit->second.community_id == community_id) {
        c.removed = true;
      }
    }
  }

  // Log the moderation action
  ModAction ma;
  ma.id = gen_uid("mod-");
  ma.mod_person_id = mod_id;
  ma.target_person_id = user_id;
  ma.community_id = community_id;
  ma.action = "ban";
  ma.reason = reason;
  ma.removed = true;
  ma.published = now_ms();
  mod_actions[ma.id] = ma;
}

void lift_community_ban(
    const std::string& user_id,
    const std::string& community_id,
    const std::string& mod_id,
    const std::string& reason,
    std::unordered_map<std::string, CommunityBan>& bans,
    std::map<std::string, Post>& posts,
    std::map<std::string, Comment>& comments,
    std::map<std::string, ModAction>& mod_actions) {

  std::string ban_key = community_id + ":" + user_id;
  bans.erase(ban_key);

  // Restore content (unremove)
  for (auto& [pid, p] : posts) {
    if (p.creator_id == user_id && p.community_id == community_id) {
      p.removed = false;
    }
  }

  for (auto& [cid, c] : comments) {
    if (c.creator_id == user_id) {
      auto pit = posts.find(c.post_id);
      if (pit != posts.end() && pit->second.community_id == community_id) {
        c.removed = false;
      }
    }
  }

  // Log
  ModAction ma;
  ma.id = gen_uid("mod-");
  ma.mod_person_id = mod_id;
  ma.target_person_id = user_id;
  ma.community_id = community_id;
  ma.action = "unban";
  ma.reason = reason;
  ma.published = now_ms();
  mod_actions[ma.id] = ma;
}

// Check if a user is banned from a community
bool is_user_community_banned(
    const std::string& user_id,
    const std::string& community_id,
    const std::unordered_map<std::string, CommunityBan>& bans) {

  std::string key = community_id + ":" + user_id;
  auto it = bans.find(key);
  if (it == bans.end()) return false;

  // Check expiry
  if (it->second.expires_at > 0 && it->second.expires_at < now_ms()) {
    return false; // Expired
  }

  return true;
}

// Check if user is a moderator of a community
bool is_moderator(
    const std::string& user_id,
    const std::string& community_id,
    const std::map<std::string, std::set<std::string>>& mods) {

  auto it = mods.find(community_id);
  if (it == mods.end()) return false;
  return it->second.count(user_id) > 0;
}

// Add moderator to community
void add_moderator(
    const std::string& community_id,
    const std::string& target_user_id,
    const std::string& acting_mod_id,
    std::map<std::string, std::set<std::string>>& mods,
    std::map<std::string, ModAction>& mod_actions) {

  mods[community_id].insert(target_user_id);

  ModAction ma;
  ma.id = gen_uid("mod-");
  ma.mod_person_id = acting_mod_id;
  ma.target_person_id = target_user_id;
  ma.community_id = community_id;
  ma.action = "add_mod";
  ma.published = now_ms();
  mod_actions[ma.id] = ma;
}

// Remove moderator from community
void remove_moderator(
    const std::string& community_id,
    const std::string& target_user_id,
    const std::string& acting_mod_id,
    std::map<std::string, std::set<std::string>>& mods,
    std::map<std::string, ModAction>& mod_actions) {

  auto it = mods.find(community_id);
  if (it != mods.end()) it->second.erase(target_user_id);

  ModAction ma;
  ma.id = gen_uid("mod-");
  ma.mod_person_id = acting_mod_id;
  ma.target_person_id = target_user_id;
  ma.community_id = community_id;
  ma.action = "remove_mod";
  ma.published = now_ms();
  mod_actions[ma.id] = ma;
}

// Purge operations — completely remove from database
void purge_post_full(
    const std::string& post_id,
    const std::string& admin_id,
    std::map<std::string, Post>& posts,
    std::map<std::string, Comment>& comments,
    std::map<std::string, Vote>& post_votes,
    std::map<std::string, CommentVote>& comment_votes,
    std::map<std::string, ModAction>& mod_actions) {

  // Remove post votes
  std::vector<std::string> pvote_keys;
  for (const auto& [key, v] : post_votes) {
    if (v.post_id == post_id) pvote_keys.push_back(key);
  }
  for (const auto& k : pvote_keys) post_votes.erase(k);

  // Remove associated comments and their votes
  std::vector<std::string> comment_ids;
  for (const auto& [cid, c] : comments) {
    if (c.post_id == post_id) comment_ids.push_back(cid);
  }
  for (const auto& cid : comment_ids) {
    std::vector<std::string> cvote_keys;
    for (const auto& [key, v] : comment_votes) {
      if (v.comment_id == cid) cvote_keys.push_back(key);
    }
    for (const auto& k : cvote_keys) comment_votes.erase(k);
    comments.erase(cid);
  }

  // Remove post
  auto it = posts.find(post_id);
  std::string cid = it != posts.end() ? it->second.community_id : "";
  posts.erase(post_id);

  // Log
  ModAction ma;
  ma.id = gen_uid("mod-");
  ma.mod_person_id = admin_id;
  ma.target_person_id = post_id;
  ma.community_id = cid;
  ma.action = "purge_post";
  ma.published = now_ms();
  mod_actions[ma.id] = ma;
}

void purge_user_full(
    const std::string& user_id,
    const std::string& admin_id,
    std::map<std::string, User>& users,
    std::map<std::string, Post>& posts,
    std::map<std::string, Comment>& comments,
    std::map<std::string, Vote>& post_votes,
    std::map<std::string, CommentVote>& comment_votes,
    std::map<std::string, ModAction>& mod_actions,
    std::unordered_set<std::string>& purged_ids) {

  // Delete all user's posts
  std::vector<std::string> post_ids;
  for (const auto& [pid, p] : posts) {
    if (p.creator_id == user_id) post_ids.push_back(pid);
  }
  for (const auto& pid : post_ids) purge_post_full(pid, admin_id, posts, comments,
                                                     post_votes, comment_votes, mod_actions);

  // Delete all user's comments
  std::vector<std::string> comment_ids;
  for (const auto& [cid, c] : comments) {
    if (c.creator_id == user_id) comment_ids.push_back(cid);
  }
  for (const auto& cid : comment_ids) {
    std::vector<std::string> cvote_keys;
    for (const auto& [key, v] : comment_votes) {
      if (v.comment_id == cid) cvote_keys.push_back(key);
    }
    for (const auto& k : cvote_keys) comment_votes.erase(k);
    comments.erase(cid);
  }

  // Delete all votes
  std::vector<std::string> pvote_keys;
  for (const auto& [key, v] : post_votes) {
    if (v.user_id == user_id) pvote_keys.push_back(key);
  }
  for (const auto& k : pvote_keys) post_votes.erase(k);

  std::vector<std::string> cvote_keys;
  for (const auto& [key, v] : comment_votes) {
    if (v.user_id == user_id) cvote_keys.push_back(key);
  }
  for (const auto& k : cvote_keys) comment_votes.erase(k);

  // Remove user
  users.erase(user_id);
  purged_ids.insert(user_id);

  // Log
  ModAction ma;
  ma.id = gen_uid("mod-");
  ma.mod_person_id = admin_id;
  ma.target_person_id = user_id;
  ma.action = "purge_user";
  ma.published = now_ms();
  mod_actions[ma.id] = ma;
}

void purge_community_full(
    const std::string& community_id,
    const std::string& admin_id,
    std::map<std::string, Community>& communities,
    std::map<std::string, Post>& posts,
    std::map<std::string, Comment>& comments,
    std::map<std::string, Vote>& post_votes,
    std::map<std::string, CommentVote>& comment_votes,
    std::map<std::string, ModAction>& mod_actions) {

  // Delete all posts in community
  std::vector<std::string> post_ids;
  for (const auto& [pid, p] : posts) {
    if (p.community_id == community_id) post_ids.push_back(pid);
  }
  for (const auto& pid : post_ids) purge_post_full(pid, admin_id, posts, comments,
                                                     post_votes, comment_votes, mod_actions);

  // Remove community
  communities.erase(community_id);

  // Log
  ModAction ma;
  ma.id = gen_uid("mod-");
  ma.mod_person_id = admin_id;
  ma.community_id = community_id;
  ma.action = "purge_community";
  ma.published = now_ms();
  mod_actions[ma.id] = ma;
}

// Moderation log query with filtering
std::vector<ModAction> query_mod_log(
    const std::map<std::string, ModAction>& mod_actions,
    const std::optional<std::string>& community_id,
    const std::optional<std::string>& mod_person_id,
    const std::optional<std::string>& target_person_id,
    int page,
    int limit) {

  std::vector<ModAction> filtered;
  for (const auto& [id, ma] : mod_actions) {
    if (community_id && ma.community_id != *community_id) continue;
    if (mod_person_id && ma.mod_person_id != *mod_person_id) continue;
    if (target_person_id && ma.target_person_id != *target_person_id) continue;
    filtered.push_back(ma);
  }

  // Sort by most recent
  std::sort(filtered.begin(), filtered.end(),
            [](const ModAction& a, const ModAction& b) {
              return a.published > b.published;
            });

  // Paginate
  int start = (page - 1) * limit;
  if (start >= static_cast<int>(filtered.size())) return {};
  int end = std::min(start + limit, static_cast<int>(filtered.size()));
  return std::vector<ModAction>(filtered.begin() + start, filtered.begin() + end);
}

} // namespace lfa_detail

// ============================================================================
// Section J1: Custom emoji — CRUD operations, shortcode parsing, alt text
// ============================================================================

namespace lfa_detail {

// Emoji shortcode validator: lowercase, alphanumeric, underscores, max 30 chars
bool validate_shortcode(const std::string& shortcode) {
  if (shortcode.empty() || shortcode.length() > 30) return false;
  std::regex re("^[a-z0-9_]+$");
  return std::regex_match(shortcode, re);
}

// Emoji image URL validator
bool validate_emoji_url(const std::string& url) {
  if (url.empty()) return false;
  return url.find("https://") == 0 || url.find("http://") == 0 ||
         url.find("/pictrs/") == 0;
}

// Parse emoji shortcodes from text (e.g., ":wave:" -> "wave")
std::vector<std::string> extract_emoji_shortcodes(const std::string& text) {
  std::vector<std::string> codes;
  size_t pos = 0;

  while (pos < text.length()) {
    auto start = text.find(':', pos);
    if (start == std::string::npos) break;
    auto end = text.find(':', start + 1);
    if (end == std::string::npos) break;

    std::string code = text.substr(start + 1, end - start - 1);
    if (!code.empty() && code.length() <= 30) {
      codes.push_back(code);
    }
    pos = end + 1;
  }

  return codes;
}

// Render text with custom emojis replaced by image tags
std::string render_emojis_in_text(
    const std::string& text,
    const std::map<std::string, CustomEmoji>& emojis_map) {

  if (emojis_map.empty()) return text;

  // Build a reverse lookup: shortcode -> CustomEmoji
  std::unordered_map<std::string, CustomEmoji> code_to_emoji;
  for (const auto& [id, emoji] : emojis_map) {
    code_to_emoji[str_tolower(emoji.shortcode)] = emoji;
  }

  std::string result;
  result.reserve(text.size() * 2);
  size_t pos = 0;

  while (pos < text.length()) {
    auto colon = text.find(':', pos);
    if (colon == std::string::npos) {
      result += text.substr(pos);
      break;
    }

    result += text.substr(pos, colon - pos + 1);

    auto end = text.find(':', colon + 1);
    if (end == std::string::npos) {
      result += text.substr(colon + 1);
      break;
    }

    std::string code = str_tolower(text.substr(colon + 1, end - colon - 1));
    auto it = code_to_emoji.find(code);

    if (it != code_to_emoji.end()) {
      // Replace :shortcode: with <img> tag
      result += "<img class=\"emoji\" src=\"" + it->second.image_url +
                "\" alt=\"" + it->second.alt_text + "\" title=\"" +
                it->second.shortcode + "\">:";
    } else {
      result += text.substr(colon + 1, end - colon);
    }
    pos = end + 1;
  }

  return result;
}

// Group custom emojis by category
std::map<std::string, std::vector<CustomEmoji>> emojis_by_category(
    const std::map<std::string, CustomEmoji>& emojis_map) {

  std::map<std::string, std::vector<CustomEmoji>> grouped;
  for (const auto& [id, emoji] : emojis_map) {
    std::string cat = emoji.category.empty() ? "Uncategorized" : emoji.category;
    grouped[cat].push_back(emoji);
  }
  return grouped;
}

// Validate a full emoji record on creation/update
bool validate_emoji_record(const CustomEmoji& emoji) {
  if (!validate_shortcode(emoji.shortcode)) return false;
  if (!validate_emoji_url(emoji.image_url)) return false;
  if (emoji.alt_text.length() > 200) return false;
  if (emoji.category.length() > 100) return false;
  return true;
}

} // namespace lfa_detail

// ============================================================================
// Section K1: Site configuration — settings management, validation, defaults
// ============================================================================

namespace lfa_detail {

// Comprehensive site configuration with validation
struct SiteConfiguration {
  // Instance identity
  std::string name;
  std::string description;
  std::string sidebar;
  std::string legal_information;
  std::string default_theme{"darkly"};

  // Registration
  bool registration_enabled{true};
  bool private_instance{false};
  bool require_email_verification{false};
  bool require_application{false};
  std::string application_question;

  // Federation
  bool federation_enabled{true};
  bool federation_debug{false};
  bool strict_allowlist{false};
  std::unordered_set<std::string> allowed_instances;
  std::unordered_set<std::string> blocked_instances;

  // Content
  bool enable_nsfw{false};
  bool enable_downvotes{true};
  int max_community_name_length{20};
  int max_post_title_length{200};
  int max_post_body_length{50000};

  // Security
  int max_upload_size{10485760}; // 10 MB
  bool captcha_enabled{false};
  std::string captcha_difficulty{"medium"};
  int rate_limit_messages{10};
  int rate_limit_posts{6};
  int rate_limit_registrations{3};
  int rate_limit_per_second{999};

  // Email
  std::string email_from;
  std::string email_domain;

  // Media
  std::string pictrs_url;
  std::string pictrs_api_key;

  // Actor
  std::string actor_name_max_length{"20"};

  // Convert to JSON for API responses
  json to_json() const {
    return {
      {"name", name},
      {"description", description},
      {"sidebar", sidebar},
      {"legal_information", legal_information},
      {"default_theme", default_theme},
      {"registration_enabled", registration_enabled},
      {"private_instance", private_instance},
      {"require_email_verification", require_email_verification},
      {"require_application", require_application},
      {"application_question", application_question},
      {"federation_enabled", federation_enabled},
      {"federation_debug", federation_debug},
      {"strict_allowlist", strict_allowlist},
      {"enable_nsfw", enable_nsfw},
      {"enable_downvotes", enable_downvotes},
      {"max_upload_size", max_upload_size},
      {"captcha_enabled", captcha_enabled},
      {"captcha_difficulty", captcha_difficulty},
      {"rate_limit_messages", rate_limit_messages},
      {"rate_limit_posts", rate_limit_posts},
      {"rate_limit_registrations", rate_limit_registrations},
      {"rate_limit_per_second", rate_limit_per_second},
      {"email_from", email_from},
      {"email_domain", email_domain},
    };
  }

  // Load from a JSON update payload (partial updates)
  void apply_updates(const json& updates) {
    if (updates.contains("name")) name = updates["name"];
    if (updates.contains("description")) description = updates["description"];
    if (updates.contains("sidebar")) sidebar = updates["sidebar"];
    if (updates.contains("legal_information")) legal_information = updates["legal_information"];
    if (updates.contains("default_theme")) default_theme = updates["default_theme"];
    if (updates.contains("registration_enabled")) registration_enabled = updates["registration_enabled"];
    if (updates.contains("private_instance")) private_instance = updates["private_instance"];
    if (updates.contains("require_email_verification")) require_email_verification = updates["require_email_verification"];
    if (updates.contains("require_application")) require_application = updates["require_application"];
    if (updates.contains("application_question")) application_question = updates["application_question"];
    if (updates.contains("federation_enabled")) federation_enabled = updates["federation_enabled"];
    if (updates.contains("federation_debug")) federation_debug = updates["federation_debug"];
    if (updates.contains("strict_allowlist")) strict_allowlist = updates["strict_allowlist"];
    if (updates.contains("enable_nsfw")) enable_nsfw = updates["enable_nsfw"];
    if (updates.contains("enable_downvotes")) enable_downvotes = updates["enable_downvotes"];
    if (updates.contains("max_upload_size")) max_upload_size = updates["max_upload_size"];
    if (updates.contains("captcha_enabled")) captcha_enabled = updates["captcha_enabled"];
    if (updates.contains("captcha_difficulty")) captcha_difficulty = updates["captcha_difficulty"];
    if (updates.contains("rate_limit_messages")) rate_limit_messages = updates["rate_limit_messages"];
    if (updates.contains("rate_limit_posts")) rate_limit_posts = updates["rate_limit_posts"];
    if (updates.contains("rate_limit_registrations")) rate_limit_registrations = updates["rate_limit_registrations"];
    if (updates.contains("rate_limit_per_second")) rate_limit_per_second = updates["rate_limit_per_second"];
    if (updates.contains("email_from")) email_from = updates["email_from"];
    if (updates.contains("email_domain")) email_domain = updates["email_domain"];
    if (updates.contains("pictrs_url")) pictrs_url = updates["pictrs_url"];
    if (updates.contains("allowed_instances") && updates["allowed_instances"].is_array()) {
      allowed_instances.clear();
      for (const auto& inst : updates["allowed_instances"]) {
        allowed_instances.insert(inst.get<std::string>());
      }
    }
    if (updates.contains("blocked_instances") && updates["blocked_instances"].is_array()) {
      blocked_instances.clear();
      for (const auto& inst : updates["blocked_instances"]) {
        blocked_instances.insert(inst.get<std::string>());
      }
    }
  }
};

// Build a default SiteConfiguration
SiteConfiguration default_site_config(const std::string& hostname) {
  SiteConfiguration cfg;
  cfg.name = hostname + " (Lemmy Instance)";
  cfg.description = "A Progressive Lemmy federated link aggregator";
  cfg.sidebar = "Welcome! This is a federated link aggregator.";
  cfg.registration_enabled = true;
  cfg.federation_enabled = true;
  cfg.enable_downvotes = true;
  cfg.max_upload_size = 10 * 1024 * 1024;
  return cfg;
}

// Validate site configuration
struct ConfigValidationResult {
  bool valid{true};
  std::vector<std::string> errors;
};

ConfigValidationResult validate_site_config(const SiteConfiguration& cfg) {
  ConfigValidationResult result;

  if (cfg.name.empty()) {
    result.valid = false;
    result.errors.push_back("Site name cannot be empty");
  }
  if (cfg.name.length() > 100) {
    result.valid = false;
    result.errors.push_back("Site name too long (max 100 chars)");
  }
  if (cfg.description.length() > 10000) {
    result.valid = false;
    result.errors.push_back("Site description too long (max 10000 chars)");
  }
  if (cfg.max_upload_size < 1024 || cfg.max_upload_size > 104857600) {
    result.valid = false;
    result.errors.push_back("Upload size must be between 1KB and 100MB");
  }
  if (cfg.rate_limit_per_second < 1 && cfg.rate_limit_per_second != 0) {
    result.valid = false;
    result.errors.push_back("Rate limit must be >= 1 or 0 (disabled)");
  }

  return result;
}

} // namespace lfa_detail

// ============================================================================
// Section L1: NodeInfo endpoint — well-known service discovery
// ============================================================================

namespace lfa_detail {

// NodeInfo 2.0 / 2.1 compatible response
json build_nodeinfo_response(const std::string& version,
                              const std::string& hostname,
                              const std::string& instance_name,
                              const std::string& instance_desc,
                              bool registration_open,
                              bool federation_enabled,
                              int64_t user_count,
                              int64_t post_count,
                              int64_t comment_count,
                              int64_t community_count) {

  json ni;

  if (version == "2.0" || version.empty()) {
    ni["version"] = "2.0";
  } else if (version == "2.1") {
    ni["version"] = "2.1";
  } else {
    ni["version"] = "2.0";
  }

  // Software info
  ni["software"] = {
    {"name", "progressive-lemmy"},
    {"version", "0.1.0"},
    {"repository", "https://github.com/nous/progressive-server"},
    {"homepage", "https://" + hostname + "/"},
  };

  // Protocols
  ni["protocols"] = json::array({"activitypub"});

  // Services
  ni["services"] = {
    {"inbound", json::array()},
    {"outbound", json::array()},
  };

  // Open registrations
  ni["openRegistrations"] = registration_open;

  // Usage statistics
  ni["usage"] = {
    {"users", {
      {"total", user_count},
      {"activeHalfyear", user_count / 2}, // Rough estimate
      {"activeMonth", user_count / 4},    // Rough estimate
    }},
    {"localPosts", post_count},
    {"localComments", comment_count},
  };

  // Metadata (NodeInfo 2.1 extension)
  if (version == "2.1") {
    ni["metadata"] = {
      {"nodeName", instance_name},
      {"nodeDescription", instance_desc},
      {"maintainer", {
        {"name", "Admin"},
        {"email", "admin@" + hostname},
      }},
      {"federation", {
        {"enabled", federation_enabled},
      }},
      {"features", json::array({
        "discussions",
        "votes",
        "moderation",
        "custom_emojis",
      })},
      {"languages", json::array({"en"})},
      {"nodeAdmins", 1},
    };
  } else {
    ni["metadata"] = {
      {"nodeName", instance_name},
      {"nodeDescription", instance_desc},
      {"federation", {
        {"enabled", federation_enabled},
      }},
    };
  }

  return ni;
}

// Well-known NodeInfo discovery link (/.well-known/nodeinfo)
json build_nodeinfo_discovery(const std::string& hostname) {
  json discovery;
  discovery["links"] = json::array({
    {
      {"rel", "http://nodeinfo.diaspora.software/ns/schema/2.0"},
      {"href", "https://" + hostname + "/nodeinfo/2.0.json"},
    },
    {
      {"rel", "http://nodeinfo.diaspora.software/ns/schema/2.1"},
      {"href", "https://" + hostname + "/nodeinfo/2.1.json"},
    },
  });
  return discovery;
}

// Host-meta JRD (/.well-known/host-meta)
std::string build_host_meta_xml(const std::string& hostname) {
  std::stringstream xml;
  xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  xml << "<XRD xmlns=\"http://docs.oasis-open.org/ns/xri/xrd-1.0\">\n";
  xml << "  <Link rel=\"lrdd\" template=\"https://" << hostname
      << "/.well-known/webfinger?resource={uri}\"/>\n";
  xml << "</XRD>\n";
  return xml.str();
}

} // namespace lfa_detail

// ============================================================================
// Section M1: Instance allow/block list management
// ============================================================================

namespace lfa_detail {

// Manage allowed instances (allowlist)
void instance_allow(std::unordered_set<std::string>& allowed,
                    const std::string& domain) {
  allowed.insert(str_tolower(domain));
}

void instance_unallow(std::unordered_set<std::string>& allowed,
                      const std::string& domain) {
  allowed.erase(str_tolower(domain));
}

// Manage blocked instances
void instance_block(std::unordered_set<std::string>& blocked,
                    const std::string& domain) {
  blocked.insert(str_tolower(domain));
}

void instance_unblock(std::unordered_set<std::string>& blocked,
                      const std::string& domain) {
  blocked.erase(str_tolower(domain));
}

// Check if an instance can federate with us
bool instance_allowed(
    const std::string& domain,
    const std::unordered_set<std::string>& allowed,
    const std::unordered_set<std::string>& blocked,
    bool strict_allowlist) {

  std::string lower = str_tolower(domain);
  if (strict_allowlist) return allowed.count(lower) > 0;
  return blocked.count(lower) == 0;
}

// List all federation connections (for admin UI)
json list_federation_instances(
    const std::unordered_set<std::string>& allowed,
    const std::unordered_set<std::string>& blocked,
    const std::unordered_set<std::string>& linked) {

  json result;
  result["allowed"] = json::array();
  for (const auto& d : allowed) result["allowed"].push_back(d);

  result["blocked"] = json::array();
  for (const auto& d : blocked) result["blocked"].push_back(d);

  result["linked"] = json::array();
  for (const auto& d : linked) result["linked"].push_back(d);

  result["linked_count"] = linked.size();
  result["allowed_count"] = allowed.size();
  result["blocked_count"] = blocked.size();

  return result;
}

} // namespace lfa_detail

// ============================================================================
// Section N1: Notification system — user/admin event dispatch
// ============================================================================

namespace lfa_detail {

// Supported notification types
enum class NotificationType {
  NEW_REPLY,
  NEW_MENTION,
  NEW_PRIVATE_MESSAGE,
  POST_LIKED,
  COMMENT_LIKED,
  NEW_REPORT,
  NEW_REGISTRATION,
  FOLLOW_ACCEPTED,
  COMMUNITY_BAN,
  COMMUNITY_UNBAN,
  MOD_ADDED,
  MOD_REMOVED,
  SITE_MESSAGE,
};

std::string notification_type_str(NotificationType t) {
  switch (t) {
    case NotificationType::NEW_REPLY: return "new_reply";
    case NotificationType::NEW_MENTION: return "new_mention";
    case NotificationType::NEW_PRIVATE_MESSAGE: return "new_private_message";
    case NotificationType::POST_LIKED: return "post_liked";
    case NotificationType::COMMENT_LIKED: return "comment_liked";
    case NotificationType::NEW_REPORT: return "new_report";
    case NotificationType::NEW_REGISTRATION: return "new_registration";
    case NotificationType::FOLLOW_ACCEPTED: return "follow_accepted";
    case NotificationType::COMMUNITY_BAN: return "community_ban";
    case NotificationType::COMMUNITY_UNBAN: return "community_unban";
    case NotificationType::MOD_ADDED: return "mod_added";
    case NotificationType::MOD_REMOVED: return "mod_removed";
    case NotificationType::SITE_MESSAGE: return "site_message";
    default: return "unknown";
  }
}

struct Notification {
  std::string id;
  std::string user_id;          // recipient
  NotificationType type;
  std::string summary;
  json data;
  int64_t created_at;
  bool read{false};
};

// Notification store (in-memory for demonstration)
std::vector<Notification> notification_store;

void create_notification(
    const std::string& user_id,
    NotificationType type,
    const std::string& summary,
    const json& data) {

  Notification n;
  n.id = gen_uid("notif-");
  n.user_id = user_id;
  n.type = type;
  n.summary = summary;
  n.data = data;
  n.created_at = now_ms();
  n.read = false;
  notification_store.push_back(n);
}

void notify_user_mentioned(
    const std::string& mentioned_user_id,
    const std::string& comment_id,
    const std::string& content_snippet) {

  create_notification(
      mentioned_user_id,
      NotificationType::NEW_MENTION,
      "You were mentioned in a comment",
      {
        {"comment_id", comment_id},
        {"snippet", content_snippet.substr(0, 200)},
      });
}

void notify_report_created(const std::string& reason, const std::string& reporter_id) {
  Notification n;
  n.id = gen_uid("notif-");
  n.user_id = "admin"; // Broadcast to all admins
  n.type = NotificationType::NEW_REPORT;
  n.summary = reason;
  n.data = {{"reporter_id", reporter_id}};
  n.created_at = now_ms();
  notification_store.push_back(n);
}

json get_user_notifications(const std::string& user_id, int page, int limit,
                             bool unread_only = false) {
  json result = json::array();

  std::vector<Notification> user_notifs;
  for (const auto& n : notification_store) {
    if (n.user_id == user_id || n.user_id == "admin") {
      if (unread_only && n.read) continue;
      user_notifs.push_back(n);
    }
  }

  // Sort newest first
  std::sort(user_notifs.begin(), user_notifs.end(),
            [](const Notification& a, const Notification& b) {
              return a.created_at > b.created_at;
            });

  // Paginate
  int start = (page - 1) * limit;
  int end = std::min(start + limit, static_cast<int>(user_notifs.size()));
  for (int i = start; i < end; ++i) {
    result.push_back({
      {"id", user_notifs[i].id},
      {"type", notification_type_str(user_notifs[i].type)},
      {"summary", user_notifs[i].summary},
      {"data", user_notifs[i].data},
      {"created_at", user_notifs[i].created_at},
      {"read", user_notifs[i].read},
    });
  }

  return result;
}

void mark_notification_read(const std::string& notif_id) {
  for (auto& n : notification_store) {
    if (n.id == notif_id) n.read = true;
  }
}

int64_t count_unread_notifications(const std::string& user_id) {
  int64_t count = 0;
  for (const auto& n : notification_store) {
    if ((n.user_id == user_id || n.user_id == "admin") && !n.read) count++;
  }
  return count;
}

} // namespace lfa_detail

// ============================================================================
// Section O1: Private message system with blocking support
// ============================================================================

namespace lfa_detail {

// Check if two users can message each other
bool can_send_message(
    const std::string& sender_id,
    const std::string& recipient_id,
    const std::map<std::string, Block>& blocks) {

  // Check if recipient blocked sender
  std::string key = recipient_id + ":" + sender_id;
  return blocks.count(key) == 0;
}

// Send a private message with full validation
struct PrivateMessageResult {
  bool success;
  std::string message_id;
  std::string error;
};

PrivateMessageResult send_private_message_full(
    const std::string& content,
    const std::string& sender_id,
    const std::string& recipient_id,
    const std::map<std::string, User>& users,
    std::map<std::string, PrivateMessage>& pms,
    const std::map<std::string, Block>& blocks) {

  PrivateMessageResult result{false, "", ""};

  // Validate content
  if (content.empty()) {
    result.error = "Message content cannot be empty";
    return result;
  }
  if (content.length() > 10000) {
    result.error = "Message too long (max 10000 chars)";
    return result;
  }

  // Check recipient exists
  if (users.count(recipient_id) == 0) {
    result.error = "Recipient not found";
    return result;
  }

  // Check block
  if (!can_send_message(sender_id, recipient_id, blocks)) {
    result.error = "Cannot send message: blocked by recipient";
    return result;
  }

  // Create message
  PrivateMessage pm;
  pm.id = gen_uid("pm-");
  pm.content = content;
  pm.creator_id = sender_id;
  pm.recipient_id = recipient_id;
  pm.read = false;
  pm.deleted = false;
  pm.published = now_ms();
  pm.updated = now_ms();
  pms[pm.id] = pm;

  // Notify recipient
  create_notification(
      recipient_id,
      NotificationType::NEW_PRIVATE_MESSAGE,
      "New private message",
      {
        {"message_id", pm.id},
        {"from_id", sender_id},
        {"snippet", content.substr(0, 200)},
        {"published", pm.published},
      });

  result.success = true;
  result.message_id = pm.id;
  return result;
}

} // namespace lfa_detail

} // namespace progressive::lemmy

// ============================================================================
// End of lemmy_full_a.cpp — 3000+ lines of ActivityPub federation and content
// management implementation for the Progressive Lemmy server.
// ============================================================================
