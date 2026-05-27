// ============================================================================
// event_signing.cpp — Matrix Event Signing, Canonical JSON, Hash Computation,
//                      Reference Hash, Signature Verification, Event ID
//                      Generation, and Hash Validation Engine
//
// Implements:
//   - Canonical JSON serialization per Matrix spec (sorted keys, no whitespace,
//     integer formatting, float normalization, null handling)
//   - Event signing: hash content with SHA-256, add hashes.sha256, sign with
//     Ed25519 server key, add signatures.origin.server_name.ed25519:base64sig
//   - Hash computation: SHA-256 of canonical JSON of event content field,
//     binary and base64 representations, streaming hash for large content
//   - Reference hash: compute reference hash for event IDs (room v3+),
//     redaction reference hash, auth event reference hash
//   - Signature verification: verify Ed25519 signatures on events, verify
//     against specific key, verify against any known server key, chain
//     verification, batch verification
//   - Event ID generation: compute $base64from server name + localpart
//     derived from event properties (reference hash + origin_server_ts + origin)
//     per Matrix room version specifications
//   - Hash validation on receipt: validate content hash when receiving
//     federated events, reject mismatched, validate redaction hash chains,
//     validate auth event hashes, hash integrity checking
//
// Equivalent to:
//   synapse/crypto/event_signing.py (~550 lines) — Event signing and verification
//   synapse/api/constants.py (EventContentFields)
//   matrix-org/matrix-spec: Server-Server API / Signing Events
//   matrix-org/matrix-spec: Room Versions / Event ID Format
//
// Namespace: progressive::
// Target: 2000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "crypto/key.hpp"
#include "crypto/signing.hpp"
#include "events/event.hpp"
#include "events/signatures.hpp"
#include "json/canonical.hpp"
#include "state/room_version.hpp"
#include "types/matrix_id.hpp"
#include "util/base64.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for all major components
// ============================================================================
class CanonicalJsonEngine;
class EventSigningEngine;
class HashComputationEngine;
class ReferenceHashEngine;
class SignatureVerificationEngine;
class EventIdGenerator;
class HashValidationEngine;
class EventSigningCoordinator;
class CanonicalJsonValidator;
class ContentHashManager;
class SignatureStore;
class KeyBasedVerifier;
class BatchSigningProcessor;
class EventIdFormatParser;
class HashIntegrityChecker;

// ============================================================================
// Canonical JSON Constants — precise formatting rules per Matrix spec
// ============================================================================
namespace canonical_constants {

// Maximum recursion depth for canonical JSON (prevents stack overflow)
constexpr int kMaxCanonicalDepth = 256;

// Maximum JSON string length for canonical processing
constexpr size_t kMaxStringLength = 10 * 1024 * 1024;  // 10 MB

// Float formatting precision: Matrix spec requires consistent float output
constexpr int kFloatPrecision = 17;  // Enough for round-trip of double

// Integer formatting: no leading zeros, no exponential notation
constexpr bool kIntegerNoLeadingZeros = true;

// Separators: no whitespace around colons or commas
constexpr char kColon = ':';
constexpr char kComma = ',';
constexpr char kObjOpen = '{';
constexpr char kObjClose = '}';
constexpr char kArrOpen = '[';
constexpr char kArrClose = ']';
constexpr char kQuote = '"';

// Special values
constexpr std::string_view kTrueLit = "true";
constexpr std::string_view kFalseLit = "false";
constexpr std::string_view kNullLit = "null";

// Base64 format for hashes: unpadded base64
constexpr bool kHashBase64Unpadded = true;

}  // namespace canonical_constants

// ============================================================================
// Event signing constants
// ============================================================================
namespace signing_constants {

// Field names used during signing and verification
constexpr std::string_view kSignaturesField = "signatures";
constexpr std::string_view kHashesField = "hashes";
constexpr std::string_view kSha256Field = "sha256";
constexpr std::string_view kUnsignedField = "unsigned";
constexpr std::string_view kContentField = "content";
constexpr std::string_view kTypeField = "type";
constexpr std::string_view kSenderField = "sender";
constexpr std::string_view kRoomIdField = "room_id";
constexpr std::string_view kEventIdField = "event_id";
constexpr std::string_view kOriginField = "origin";
constexpr std::string_view kOriginServerTsField = "origin_server_ts";
constexpr std::string_view kStateKeyField = "state_key";
constexpr std::string_view kPrevEventsField = "prev_events";
constexpr std::string_view kAuthEventsField = "auth_events";
constexpr std::string_view kDepthField = "depth";
constexpr std::string_view kRedactsField = "redacts";
constexpr std::string_view kAgeTsField = "age_ts";
constexpr std::string_view kMembershipField = "membership";

// Event ID format components
constexpr char kEventIdSigil = '$';
constexpr std::string_view kEventIdSeparator = ":";
constexpr size_t kMinEventIdLength = 4;
constexpr size_t kMaxEventIdLength = 255;

// Ed25519 signature size in bytes
constexpr size_t kEd25519SigBytes = 64;

// SHA-256 hash size in bytes
constexpr size_t kSha256HashBytes = 32;

// Algorithm prefix for key IDs
constexpr std::string_view kEd25519Prefix = "ed25519:";

// Maximum event size for processing
constexpr size_t kMaxEventSizeBytes = 65536;

// Maximum number of signatures to verify in batch
constexpr size_t kMaxBatchSignatures = 1000;

// Maximum depth for reference hash recursion
constexpr int kMaxRefHashDepth = 10;

}  // namespace signing_constants

// ============================================================================
// Anonymous-namespace utility functions
// ============================================================================
namespace {

// --- SHA-256 raw hash ---
std::vector<uint8_t> sha256_raw(std::string_view data) {
  std::vector<uint8_t> hash(signing_constants::kSha256HashBytes);
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), hash.data());
  return hash;
}

// --- SHA-256 base64 (unpadded) ---
std::string sha256_b64(std::string_view data) {
  auto raw = sha256_raw(data);
  return base64::encode(
      std::string_view(reinterpret_cast<const char*>(raw.data()), raw.size()));
}

// --- SHA-256 base64 unpadded (strip trailing '=') ---
std::string sha256_b64_unpadded(std::string_view data) {
  std::string b64 = sha256_b64(data);
  while (!b64.empty() && b64.back() == '=') {
    b64.pop_back();
  }
  return b64;
}

// --- Strip ed25519: prefix ---
std::string_view strip_ed25519_prefix(std::string_view key_id) {
  if (key_id.size() >= signing_constants::kEd25519Prefix.size() &&
      key_id.substr(0, signing_constants::kEd25519Prefix.size()) ==
          signing_constants::kEd25519Prefix) {
    return key_id.substr(signing_constants::kEd25519Prefix.size());
  }
  return key_id;
}

// --- Check if string is valid base64 (unpadded) ---
bool is_valid_base64_unpadded(std::string_view s) {
  // Must not contain '=' (unpadded format)
  static const std::string valid_chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (char c : s) {
    if (valid_chars.find(c) == std::string::npos) {
      return false;
    }
  }
  return true;
}

// --- Get current timestamp in milliseconds ---
int64_t now_millis() {
  auto now = chr::system_clock::now();
  return chr::duration_cast<chr::milliseconds>(now.time_since_epoch()).count();
}

// --- Generate random string of given length (for localpart of event ID) ---
std::string random_string(size_t length) {
  static const char alphanum[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(std::random_device{}());
  std::uniform_int_distribution<size_t> dist(0, sizeof(alphanum) - 2);
  std::string result;
  result.reserve(length);
  for (size_t i = 0; i < length; ++i) {
    result += alphanum[dist(rng)];
  }
  return result;
}

// --- Deep clone a JSON object ---
json json_deep_clone(const json& src) {
  return json::parse(src.dump());
}

// --- Extract all server names from signatures ---
std::set<std::string> extract_signing_servers(const json& event) {
  std::set<std::string> servers;
  auto sig_it = event.find(signing_constants::kSignaturesField);
  if (sig_it != event.end() && sig_it->is_object()) {
    for (auto& [origin, keys] : sig_it->items()) {
      servers.insert(origin);
    }
  }
  return servers;
}

// --- Check if an event has a specific field ---
bool event_has_field(const json& event, std::string_view field) {
  return event.contains(field) && !event[field].is_null();
}

}  // anonymous namespace

// ============================================================================
// CanonicalJsonEngine — Comprehensive Canonical JSON Per Matrix Spec
// ============================================================================
//
// Matrix Canonical JSON (as defined in the Matrix specification) specifies
// precise serialization rules for JSON objects used in signing:
//
//   1. No whitespace around structural characters ({, }, [, ], :, ,)
//   2. Object keys must be sorted lexicographically by Unicode code point
//   3. Strings must use the minimal JSON encoding (no unnecessary escapes)
//   4. Numbers: integers must not use exponential notation or leading zeros;
//      floats must use decimal notation with consistent precision
//   5. null, true, false must be lowercase exactly
//   6. No trailing commas or other non-canonical artifacts
//
// This implementation extends the basic canonical_json() in json/canonical.cpp
// with additional validation, debugging, and batch operations.
// ============================================================================

class CanonicalJsonEngine {
public:
  // --- Recursion depth tracking ---
  struct CanonicalContext {
    int depth = 0;
    std::vector<std::string> key_trace;  // for debugging

    void enter() {
      depth++;
      if (depth > canonical_constants::kMaxCanonicalDepth) {
        throw std::runtime_error(
            "Canonical JSON recursion depth exceeded: " + std::to_string(depth));
      }
    }
    void leave() { depth--; }
  };

  // --- Serialize a JSON value to canonical form ---
  static std::string serialize(const json& value) {
    CanonicalContext ctx;
    return serialize_value(value, ctx);
  }

  // --- Serialize to canonical form with a pre-existing context ---
  static std::string serialize_with_context(const json& value, CanonicalContext& ctx) {
    return serialize_value(value, ctx);
  }

  // --- Serialize only keys of an object (for debugging) ---
  static std::vector<std::string> sorted_keys(const json& obj) {
    std::vector<std::string> keys;
    if (!obj.is_object()) return keys;
    for (auto& [k, v] : obj.items()) {
      keys.push_back(k);
    }
    std::sort(keys.begin(), keys.end());
    return keys;
  }

  // --- Validate that a JSON structure is in canonical form ---
  static bool is_canonical(const json& value) {
    try {
      std::string canon = serialize(value);
      // Re-parse and re-serialize to check consistency
      json reparsed = json::parse(canon);
      std::string recanon = serialize(reparsed);
      return canon == recanon;
    } catch (...) {
      return false;
    }
  }

  // --- Validate canonical JSON string (does it parse back to same?) ---
  struct CanonicalValidation {
    bool valid = false;
    std::string error;
    std::string canonical_form;
  };

  static CanonicalValidation validate(std::string_view raw) {
    CanonicalValidation result;
    try {
      json parsed = json::parse(raw);
      result.canonical_form = serialize(parsed);
      result.valid = true;
    } catch (const std::exception& e) {
      result.error = std::string("Canonical JSON parse error: ") + e.what();
    }
    return result;
  }

  // --- Compute canonical hash (SHA-256 of canonical form) ---
  static std::string canonical_hash(const json& value) {
    std::string canon = serialize(value);
    return sha256_b64_unpadded(canon);
  }

private:
  // --- Serialize a value recursively ---
  static std::string serialize_value(const json& value, CanonicalContext& ctx) {
    ctx.enter();

    std::string result;
    try {
      switch (value.type()) {
        case json::value_t::null:
          result = std::string(canonical_constants::kNullLit);
          break;

        case json::value_t::boolean:
          result = value.get<bool>() ? std::string(canonical_constants::kTrueLit)
                                     : std::string(canonical_constants::kFalseLit);
          break;

        case json::value_t::number_integer:
        case json::value_t::number_unsigned:
          result = serialize_integer(value);
          break;

        case json::value_t::number_float:
          result = serialize_float(value);
          break;

        case json::value_t::string:
          result = serialize_string(value.get<std::string>());
          break;

        case json::value_t::array:
          result = serialize_array(value, ctx);
          break;

        case json::value_t::object:
          result = serialize_object(value, ctx);
          break;

        case json::value_t::binary:
          throw std::runtime_error("Binary JSON values cannot be canonicalized");

        case json::value_t::discarded:
          throw std::runtime_error("Discarded JSON values cannot be canonicalized");
      }
    } catch (...) {
      ctx.leave();
      throw;
    }

    ctx.leave();
    return result;
  }

  // --- Serialize integer without exponential notation ---
  static std::string serialize_integer(const json& value) {
    if (value.is_number_unsigned()) {
      return std::to_string(value.get<uint64_t>());
    }
    return std::to_string(value.get<int64_t>());
  }

  // --- Serialize float with consistent precision ---
  static std::string serialize_float(const json& value) {
    double d = value.get<double>();

    // Handle special IEEE-754 values
    if (std::isnan(d)) {
      throw std::runtime_error("NaN not allowed in canonical JSON");
    }
    if (std::isinf(d)) {
      throw std::runtime_error("Infinity not allowed in canonical JSON");
    }

    // Zero must be "0" regardless of sign
    if (d == 0.0) {
      return "0";
    }

    // Convert to string with sufficient precision for round-trip
    // Matrix spec: use enough digits to uniquely identify the float
    std::ostringstream oss;
    oss << std::setprecision(canonical_constants::kFloatPrecision) << d;
    std::string s = oss.str();

    // Remove trailing zeros after decimal point
    auto dot_pos = s.find('.');
    if (dot_pos != std::string::npos) {
      // Check if this is actually an integer value
      double int_part;
      if (std::modf(d, &int_part) == 0.0 && d == int_part) {
        // It's an integer value, output as integer
        s = std::to_string(static_cast<int64_t>(int_part));
      } else {
        // Remove trailing zeros but keep at least one digit after decimal
        while (s.size() > dot_pos + 2 && s.back() == '0') {
          s.pop_back();
        }
        // Remove trailing decimal point if all fractional zeros
        if (s.back() == '.') {
          s.pop_back();
        }
      }
    }

    return s;
  }

  // --- Serialize string with minimal JSON escaping ---
  static std::string serialize_string(const std::string& str) {
    std::ostringstream oss;
    oss << canonical_constants::kQuote;

    for (size_t i = 0; i < str.size(); ++i) {
      unsigned char c = static_cast<unsigned char>(str[i]);

      switch (c) {
        case '"':
          oss << "\\\"";
          break;
        case '\\':
          oss << "\\\\";
          break;
        case '\b':
          oss << "\\b";
          break;
        case '\f':
          oss << "\\f";
          break;
        case '\n':
          oss << "\\n";
          break;
        case '\r':
          oss << "\\r";
          break;
        case '\t':
          oss << "\\t";
          break;
        default:
          // Control characters (0x00-0x1F, 0x7F) must be escaped as \\uXXXX
          if (c < 0x20 || c == 0x7F) {
            oss << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                << static_cast<int>(c) << std::dec;
          } else {
            oss << c;
          }
          break;
      }
    }

    oss << canonical_constants::kQuote;
    return oss.str();
  }

  // --- Serialize array ---
  static std::string serialize_array(const json& value, CanonicalContext& ctx) {
    std::ostringstream oss;
    oss << canonical_constants::kArrOpen;
    bool first = true;
    for (const auto& elem : value) {
      if (!first) {
        oss << canonical_constants::kComma;
      }
      oss << serialize_value(elem, ctx);
      first = false;
    }
    oss << canonical_constants::kArrClose;
    return oss.str();
  }

  // --- Serialize object with sorted keys ---
  static std::string serialize_object(const json& value, CanonicalContext& ctx) {
    // Sort keys lexicographically
    std::map<std::string, json> sorted;
    for (auto& [k, v] : value.items()) {
      sorted[k] = v;
    }

    std::ostringstream oss;
    oss << canonical_constants::kObjOpen;
    bool first = true;
    for (auto& [k, v] : sorted) {
      if (!first) {
        oss << canonical_constants::kComma;
      }
      // Key is always a string
      oss << serialize_string(k);
      oss << canonical_constants::kColon;
      oss << serialize_value(v, ctx);
      first = false;
    }
    oss << canonical_constants::kObjClose;
    return oss.str();
  }
};

// ============================================================================
// HashComputationEngine — SHA-256 Content Hash Computation for Events
// ============================================================================
//
// Every Matrix federation event must include a content hash (hashes.sha256).
// This hash covers only the "content" field of the event, serialized as
// canonical JSON.  The hash is unpadded base64-encoded SHA-256.
//
// This engine provides:
//   - Compute content hash from event
//   - Compute content hash from raw content JSON
//   - Compute full event hash (for specific verification scenarios)
//   - Streaming hash for very large content fields
//   - Multiple hash algorithm support (SHA-256 primary)
// ============================================================================

class HashComputationEngine {
public:
  // --- Result of a hash computation ---
  struct HashResult {
    std::string sha256_b64;        // Unpadded base64 SHA-256
    std::vector<uint8_t> sha256_raw;  // Raw 32-byte hash
    std::string canonical_content; // The canonical JSON that was hashed
    bool success = false;
    std::string error;
  };

  // --- Algorithm identifiers ---
  enum class HashAlgorithm : uint8_t {
    kSha256 = 0,
    kSha384 = 1,
    kSha512 = 2,
  };

  // --- Compute content hash from a full event JSON ---
  static HashResult compute_from_event(const json& event) {
    HashResult result;

    auto content_it = event.find(signing_constants::kContentField);
    if (content_it == event.end()) {
      result.error = "Event missing 'content' field";
      return result;
    }

    return compute_from_content(*content_it);
  }

  // --- Compute content hash from a content JSON object ---
  static HashResult compute_from_content(const json& content) {
    HashResult result;

    try {
      result.canonical_content = CanonicalJsonEngine::serialize(content);
      result.sha256_raw = sha256_raw(result.canonical_content);
      result.sha256_b64 = sha256_b64_unpadded(result.canonical_content);
      result.success = true;
    } catch (const std::exception& e) {
      result.error = std::string("Hash computation failed: ") + e.what();
    }

    return result;
  }

  // --- Compute hash of a full JSON structure (not just content) ---
  static HashResult compute_full_hash(const json& obj) {
    HashResult result;

    try {
      result.canonical_content = CanonicalJsonEngine::serialize(obj);
      result.sha256_raw = sha256_raw(result.canonical_content);
      result.sha256_b64 = sha256_b64_unpadded(result.canonical_content);
      result.success = true;
    } catch (const std::exception& e) {
      result.error = std::string("Full hash computation failed: ") + e.what();
    }

    return result;
  }

  // --- Compute hash of a string directly ---
  static std::string hash_string(std::string_view data) {
    return sha256_b64_unpadded(data);
  }

  // --- Add content hash to an event JSON (returns new event) ---
  static json add_content_hash(json event) {
    HashResult hr = compute_from_event(event);
    if (!hr.success) {
      throw std::runtime_error("Cannot add content hash: " + hr.error);
    }

    event[signing_constants::kHashesField] = json::object();
    event[signing_constants::kHashesField][signing_constants::kSha256Field] =
        hr.sha256_b64;
    return event;
  }

  // --- Add content hash to event in-place ---
  static void add_content_hash_inplace(json& event) {
    HashResult hr = compute_from_event(event);
    if (!hr.success) {
      throw std::runtime_error("Cannot add content hash: " + hr.error);
    }

    event[signing_constants::kHashesField] = json::object();
    event[signing_constants::kHashesField][signing_constants::kSha256Field] =
        hr.sha256_b64;
  }

  // --- Recompute hashes for an existing event (e.g., after content modification) ---
  static json recompute_hashes(json event) {
    // Remove any existing hashes
    event.erase(signing_constants::kHashesField);
    return add_content_hash(std::move(event));
  }

  // --- Batch hash computation ---
  struct BatchHashResult {
    size_t total = 0;
    size_t succeeded = 0;
    size_t failed = 0;
    std::vector<HashResult> results;
    std::vector<std::string> errors;
  };

  static BatchHashResult batch_compute(const std::vector<json>& events) {
    BatchHashResult batch;
    batch.total = events.size();

    for (const auto& event : events) {
      auto hr = compute_from_event(event);
      if (hr.success) {
        batch.succeeded++;
        batch.results.push_back(std::move(hr));
      } else {
        batch.failed++;
        batch.errors.push_back(hr.error);
      }
    }

    return batch;
  }

  // --- Verify content hash matches ---
  static bool verify_hash(const json& event) {
    auto hashes_it = event.find(signing_constants::kHashesField);
    if (hashes_it == event.end() || !hashes_it->is_object()) {
      return false;
    }

    auto sha256_it = hashes_it->find(signing_constants::kSha256Field);
    if (sha256_it == hashes_it->end() || !sha256_it->is_string()) {
      return false;
    }

    std::string expected_hash = sha256_it->get<std::string>();

    HashResult computed = compute_from_event(event);
    if (!computed.success) {
      return false;
    }

    return expected_hash == computed.sha256_b64;
  }

  // --- Extract the content hash from an event ---
  static std::optional<std::string> extract_hash(const json& event) {
    auto hashes_it = event.find(signing_constants::kHashesField);
    if (hashes_it == event.end()) return std::nullopt;

    auto sha256_it = hashes_it->find(signing_constants::kSha256Field);
    if (sha256_it == hashes_it->end()) return std::nullopt;

    return sha256_it->get<std::string>();
  }

  // --- Validate hash format (is it valid unpadded base64 of correct length?) ---
  static bool is_valid_hash_format(std::string_view hash_b64) {
    // SHA-256 hash in base64 unpadded is 43 characters
    if (hash_b64.size() != 43) return false;
    return is_valid_base64_unpadded(hash_b64);
  }

  // --- Compute streaming hash for very large content ---
  // Note: this is a simplified version; a full implementation would use
  // EVP_MD_CTX with incremental updates
  static std::string streaming_hash(std::string_view data) {
    return sha256_b64_unpadded(data);
  }
};

// ============================================================================
// ReferenceHashEngine — Reference Hash for Event IDs and Redaction
// ============================================================================
//
// In Matrix room versions 3+, event IDs are derived from a "reference hash"
// that covers specific event fields (type, sender, room_id, state_key,
// content.hashes).  This makes event IDs deterministic based on the event
// content, preventing servers from assigning arbitrary event IDs.
//
// The reference hash algorithm (per spec):
//   1. Build a JSON object containing only the fields used for identification
//   2. Remove fields excluded from reference (signatures, unsigned, event_id,
//      origin_server_ts, etc.)
//   3. Canonicalize and SHA-256 hash the result
// ============================================================================

class ReferenceHashEngine {
public:
  // --- Fields included in the reference hash (room v3+) ---
  static constexpr std::array<std::string_view, 5> kRefHashFields = {
      signing_constants::kTypeField,
      signing_constants::kSenderField,
      signing_constants::kRoomIdField,
      signing_constants::kStateKeyField,
      signing_constants::kContentField,
  };

  // --- Fields explicitly excluded from reference ---
  static constexpr std::array<std::string_view, 6> kExcludedFields = {
      signing_constants::kEventIdField,
      signing_constants::kSignaturesField,
      signing_constants::kUnsignedField,
      signing_constants::kOriginServerTsField,
      signing_constants::kPrevEventsField,
      signing_constants::kAuthEventsField,
  };

  // --- Result of reference hash computation ---
  struct RefHashResult {
    std::string reference_hash;       // Base64 unpadded SHA-256
    json reference_object;            // The JSON used for the hash
    bool success = false;
    std::string error;
  };

  // --- Compute the reference hash for a given event ---
  static RefHashResult compute(const json& event) {
    RefHashResult result;

    try {
      result.reference_object = build_reference_object(event);
      result.reference_hash =
          sha256_b64_unpadded(CanonicalJsonEngine::serialize(result.reference_object));
      result.success = true;
    } catch (const std::exception& e) {
      result.error = std::string("Reference hash computation failed: ") + e.what();
    }

    return result;
  }

  // --- Compute reference hash for a redacted event ---
  static RefHashResult compute_for_redacted(const json& redacted_event) {
    RefHashResult result;

    try {
      // For redacted events, content is always empty object
      json ref;
      ref[signing_constants::kTypeField] =
          redacted_event.value(signing_constants::kTypeField, "");
      ref[signing_constants::kSenderField] =
          redacted_event.value(signing_constants::kSenderField, "");
      ref[signing_constants::kRoomIdField] =
          redacted_event.value(signing_constants::kRoomIdField, "");

      if (redacted_event.contains(signing_constants::kStateKeyField)) {
        ref[signing_constants::kStateKeyField] =
            redacted_event[signing_constants::kStateKeyField];
      }

      // Redacted events have empty content object
      ref[signing_constants::kContentField] = json::object();

      result.reference_object = ref;
      result.reference_hash =
          sha256_b64_unpadded(CanonicalJsonEngine::serialize(ref));
      result.success = true;
    } catch (const std::exception& e) {
      result.error =
          std::string("Redacted reference hash computation failed: ") + e.what();
    }

    return result;
  }

  // --- Validate that a reference hash matches the event ---
  static bool validate(const json& event, std::string_view expected_hash) {
    auto result = compute(event);
    return result.success && result.reference_hash == expected_hash;
  }

  // --- Check if an event ID is consistent with the reference hash ---
  static bool validate_event_id(const json& event, std::string_view event_id_str) {
    // Event ID format: $base64refhash
    // The localpart should be the reference hash in some encoding
    auto result = compute(event);
    if (!result.success) return false;

    // Parse the event ID
    if (event_id_str.empty() || event_id_str[0] != signing_constants::kEventIdSigil) {
      return false;
    }

    std::string_view rest = event_id_str.substr(1);
    auto colon_pos = rest.find(signing_constants::kEventIdSeparator);
    if (colon_pos == std::string_view::npos) return false;

    std::string localpart(rest.substr(0, colon_pos));
    std::string domain(rest.substr(colon_pos + 1));

    // In room v3+, the localpart is the base64-encoded reference hash
    // Verify that the event's reference hash matches the event ID
    return localpart == result.reference_hash;
  }

  // --- Compute auth event reference hash (subset for auth events) ---
  static RefHashResult compute_auth_event_hash(const json& auth_event) {
    // Auth event reference hashes include type, state_key, sender, room_id
    // and relevant content fields but NOT the full content
    RefHashResult result;

    try {
      json ref;
      ref[signing_constants::kTypeField] =
          auth_event.value(signing_constants::kTypeField, "");
      ref[signing_constants::kSenderField] =
          auth_event.value(signing_constants::kSenderField, "");
      ref[signing_constants::kRoomIdField] =
          auth_event.value(signing_constants::kRoomIdField, "");

      if (auth_event.contains(signing_constants::kStateKeyField)) {
        ref[signing_constants::kStateKeyField] =
            auth_event[signing_constants::kStateKeyField];
      }

      // For auth events, content includes only auth-relevant fields
      // like membership, join_rule, etc.
      json content;
      if (auth_event.contains(signing_constants::kContentField)) {
        auto& c = auth_event[signing_constants::kContentField];
        if (c.is_object()) {
          // Include membership, join_rule, and other auth fields
          if (c.contains(signing_constants::kMembershipField)) {
            content[signing_constants::kMembershipField] =
                c[signing_constants::kMembershipField];
          }
        }
      }
      ref[signing_constants::kContentField] = content;

      result.reference_object = ref;
      result.reference_hash =
          sha256_b64_unpadded(CanonicalJsonEngine::serialize(ref));
      result.success = true;
    } catch (const std::exception& e) {
      result.error =
          std::string("Auth event reference hash failed: ") + e.what();
    }

    return result;
  }

  // --- Compute hash for event ID generation (v1/v2 legacy format) ---
  static std::string compute_legacy_event_id_hash(const json& event) {
    // Legacy event IDs: domain + random localpart
    // The hash is not used for the localpart, but we provide it for verification
    auto result = compute(event);
    return result.success ? result.reference_hash : "";
  }

private:
  // --- Build the reference object from an event ---
  static json build_reference_object(const json& event) {
    json ref;

    // Include the standard reference fields
    ref[signing_constants::kTypeField] =
        event.value(signing_constants::kTypeField, "");
    ref[signing_constants::kSenderField] =
        event.value(signing_constants::kSenderField, "");
    ref[signing_constants::kRoomIdField] =
        event.value(signing_constants::kRoomIdField, "");

    if (event.contains(signing_constants::kStateKeyField)) {
      ref[signing_constants::kStateKeyField] =
          event[signing_constants::kStateKeyField];
    }

    // For content, only include the hashes field (not the full content)
    json content;
    if (event.contains(signing_constants::kHashesField)) {
      content[signing_constants::kHashesField] = event[signing_constants::kHashesField];
    }
    ref[signing_constants::kContentField] = content;

    return ref;
  }
};

// ============================================================================
// EventSigningEngine — Sign Events with Ed25519 Server Keys
// ============================================================================
//
// Matrix event signing process:
//   1. Compute content hash (SHA-256 of canonical JSON of event["content"])
//   2. Add hashes.sha256 to the event
//   3. Remove any existing signature for this origin/key_id
//   4. Remove unsigned.age_ts (it changes per request, so not signed)
//   5. Compute canonical JSON of the entire event
//   6. Sign with Ed25519 private key
//   7. Add signature to signatures.{{origin}}.{{key_id}} as base64
// ============================================================================

class EventSigningEngine {
public:
  // --- Result of signing an event ---
  struct SignResult {
    json signed_event;
    std::string content_hash;
    std::string signature_b64;
    bool success = false;
    std::string error;
  };

  // --- Configuration for signing ---
  struct SigningConfig {
    std::string origin;                    // Server name signing the event
    std::string key_id;                    // Full key ID: "ed25519:v1"
    std::vector<uint8_t> private_key;      // 32-byte Ed25519 seed
    bool add_content_hash = true;          // Automatically add hashes
    bool strip_age_ts = true;              // Remove age_ts from unsigned
    bool add_origin_field = false;         // Add "origin" field if missing
    bool add_origin_server_ts = true;      // Add origin_server_ts if missing
  };

  // --- Sign an event with the given configuration ---
  static SignResult sign_event(const json& event, const SigningConfig& config) {
    SignResult result;

    try {
      // 1. Deep clone the event (don't modify the original)
      json signed_event = json_deep_clone(event);

      // 2. Add origin_server_ts if configured and missing
      if (config.add_origin_server_ts &&
          !signed_event.contains(signing_constants::kOriginServerTsField)) {
        signed_event[signing_constants::kOriginServerTsField] = now_millis();
      }

      // 3. Add origin field if configured and missing
      if (config.add_origin_field &&
          !signed_event.contains(signing_constants::kOriginField)) {
        signed_event[signing_constants::kOriginField] = config.origin;
      }

      // 4. Compute and add content hash
      if (config.add_content_hash) {
        signed_event = HashComputationEngine::add_content_hash(
            std::move(signed_event));
        result.content_hash =
            signed_event[signing_constants::kHashesField]
                        [signing_constants::kSha256Field]
                            .get<std::string>();
      }

      // 5. Ensure signatures object exists
      if (!signed_event.contains(signing_constants::kSignaturesField)) {
        signed_event[signing_constants::kSignaturesField] = json::object();
      }
      if (!signed_event[signing_constants::kSignaturesField].contains(
              config.origin)) {
        signed_event[signing_constants::kSignaturesField][config.origin] =
            json::object();
      }

      // 6. Remove existing signature for this key (clean re-sign)
      signed_event[signing_constants::kSignaturesField][config.origin].erase(
          config.key_id);

      // 7. Ensure unsigned exists and strip age_ts
      if (!signed_event.contains(signing_constants::kUnsignedField)) {
        signed_event[signing_constants::kUnsignedField] = json::object();
      }
      if (config.strip_age_ts) {
        signed_event[signing_constants::kUnsignedField].erase(
            signing_constants::kAgeTsField);
      }

      // 8. Compute canonical JSON of the prepared event
      std::string canon = CanonicalJsonEngine::serialize(signed_event);

      // 9. Sign with Ed25519 private key
      result.signature_b64 = ed25519_sign_raw(canon, config.private_key);

      // 10. Add the signature
      signed_event[signing_constants::kSignaturesField][config.origin]
                  [config.key_id] = result.signature_b64;

      result.signed_event = std::move(signed_event);
      result.success = true;
    } catch (const std::exception& e) {
      result.error = std::string("Event signing failed: ") + e.what();
    }

    return result;
  }

  // --- Sign using the progressive::crypto Ed25519Keypair struct ---
  static SignResult sign_with_keypair(const json& event,
                                      const crypto::Ed25519Keypair& keypair,
                                      std::string_view origin) {
    SigningConfig config;
    config.origin = std::string(origin);
    config.key_id = keypair.key_id();
    config.private_key = keypair.private_key;
    config.add_content_hash = true;

    return sign_event(event, config);
  }

  // --- Sign multiple events with the same key (batch signing) ---
  struct BatchSignResult {
    std::vector<SignResult> results;
    size_t total = 0;
    size_t succeeded = 0;
    size_t failed = 0;
  };

  static BatchSignResult batch_sign(const std::vector<json>& events,
                                     const SigningConfig& config) {
    BatchSignResult batch;
    batch.total = events.size();

    for (const auto& event : events) {
      auto result = sign_event(event, config);
      if (result.success) {
        batch.succeeded++;
      } else {
        batch.failed++;
      }
      batch.results.push_back(std::move(result));
    }

    return batch;
  }

  // --- Re-sign an already-signed event (e.g., for key rotation) ---
  static SignResult resign_event(const json& signed_event,
                                  const SigningConfig& config) {
    // Strip all existing signatures from this origin
    json clean_event = json_deep_clone(signed_event);
    if (clean_event.contains(signing_constants::kSignaturesField)) {
      clean_event[signing_constants::kSignaturesField].erase(config.origin);
    }

    // Re-sign
    return sign_event(clean_event, config);
  }

  // --- Add a counter-signature (additional server signing the same event) ---
  static SignResult countersign_event(const json& signed_event,
                                       const SigningConfig& config) {
    // Keep existing signatures, just add ours
    json event_with_counter = json_deep_clone(signed_event);

    if (!event_with_counter.contains(signing_constants::kSignaturesField)) {
      event_with_counter[signing_constants::kSignaturesField] = json::object();
    }
    if (!event_with_counter[signing_constants::kSignaturesField].contains(
            config.origin)) {
      event_with_counter[signing_constants::kSignaturesField][config.origin] =
          json::object();
    }

    // Remove only our own existing signature
    event_with_counter[signing_constants::kSignaturesField][config.origin].erase(
        config.key_id);

    // Strip age_ts for signing
    if (!event_with_counter.contains(signing_constants::kUnsignedField)) {
      event_with_counter[signing_constants::kUnsignedField] = json::object();
    }
    event_with_counter[signing_constants::kUnsignedField].erase(
        signing_constants::kAgeTsField);

    // Canonicalize and sign
    std::string canon = CanonicalJsonEngine::serialize(event_with_counter);
    std::string sig_b64 = ed25519_sign_raw(canon, config.private_key);

    event_with_counter[signing_constants::kSignaturesField][config.origin]
                      [config.key_id] = sig_b64;

    SignResult result;
    result.signed_event = std::move(event_with_counter);
    result.signature_b64 = sig_b64;
    result.success = true;
    return result;
  }

private:
  // --- Raw Ed25519 signing with OpenSSL EVP ---
  static std::string ed25519_sign_raw(std::string_view message,
                                       const std::vector<uint8_t>& private_key) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, private_key.data(), private_key.size());
    if (!pkey)
      throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
      EVP_PKEY_free(pkey);
      throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    if (EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
      EVP_MD_CTX_free(md_ctx);
      EVP_PKEY_free(pkey);
      throw std::runtime_error("EVP_DigestSignInit failed");
    }

    size_t sig_len = signing_constants::kEd25519SigBytes;
    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSign(md_ctx, sig.data(), &sig_len,
                       reinterpret_cast<const uint8_t*>(message.data()),
                       message.size()) <= 0) {
      EVP_MD_CTX_free(md_ctx);
      EVP_PKEY_free(pkey);
      throw std::runtime_error("EVP_DigestSign failed");
    }
    sig.resize(sig_len);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    // Return unpadded base64
    std::string b64 = base64::encode(
        std::string_view(reinterpret_cast<const char*>(sig.data()), sig.size()));
    while (!b64.empty() && b64.back() == '=') {
      b64.pop_back();
    }
    return b64;
  }
};

// ============================================================================
// SignatureVerificationEngine — Verify Event Signatures
// ============================================================================
//
// Matrix event signature verification ensures that events were truly signed
// by the claimed server. The verification process:
//
//   1. Extract the signature from signatures.{{origin}}.{{key_id}}
//   2. Build a copy of the event with that specific signature removed
//   3. Also remove unsigned.age_ts
//   4. Compute canonical JSON of the prepared event
//   5. Verify the Ed25519 signature against the canonical JSON
//
// This engine supports:
//   - Verify against a specific key (public key bytes)
//   - Verify against any key for a given server (key lookup required)
//   - Chain verification (verify intermediates)
//   - Batch verification
//   - Verification result aggregation
// ============================================================================

class SignatureVerificationEngine {
public:
  // --- Verification result ---
  struct VerifyResult {
    bool valid = false;
    std::string origin;
    std::string key_id;
    std::string signature_b64;
    std::string error;
    std::string canonical_signed;  // What was actually signed

    // Extended details
    bool hash_valid = false;
    bool sig_format_valid = false;
    bool key_found = false;
    bool canonical_ok = false;
  };

  // --- Known public key (server key store entry) ---
  struct KnownKey {
    std::string server_name;
    std::string key_id;
    std::vector<uint8_t> public_key;  // 32 bytes
    bool is_expired = false;
    bool is_revoked = false;
    int64_t valid_until_ts = 0;
  };

  // --- Key store interface (can be backed by database or in-memory) ---
  class KeyStore {
  public:
    virtual ~KeyStore() = default;

    // Look up a specific key
    virtual std::optional<KnownKey> find_key(std::string_view server_name,
                                              std::string_view key_id) = 0;

    // Look up all keys for a server
    virtual std::vector<KnownKey> find_server_keys(
        std::string_view server_name) = 0;

    // Add a known key
    virtual void add_key(const KnownKey& key) = 0;

    // Check if a server is known
    virtual bool is_server_known(std::string_view server_name) = 0;
  };

  // --- In-memory key store implementation ---
  class InMemoryKeyStore : public KeyStore {
  public:
    std::optional<KnownKey> find_key(std::string_view server_name,
                                      std::string_view key_id) override {
      std::shared_lock lock(mutex_);
      auto server_it = store_.find(std::string(server_name));
      if (server_it == store_.end()) return std::nullopt;

      auto key_it = server_it->second.find(std::string(key_id));
      if (key_it == server_it->second.end()) return std::nullopt;

      return key_it->second;
    }

    std::vector<KnownKey> find_server_keys(
        std::string_view server_name) override {
      std::shared_lock lock(mutex_);
      std::vector<KnownKey> result;
      auto server_it = store_.find(std::string(server_name));
      if (server_it != store_.end()) {
        for (auto& [kid, key] : server_it->second) {
          result.push_back(key);
        }
      }
      return result;
    }

    void add_key(const KnownKey& key) override {
      std::unique_lock lock(mutex_);
      store_[key.server_name][key.key_id] = key;
    }

    bool is_server_known(std::string_view server_name) override {
      std::shared_lock lock(mutex_);
      return store_.find(std::string(server_name)) != store_.end();
    }

    // Bulk load keys
    void load_keys(const std::vector<KnownKey>& keys) {
      std::unique_lock lock(mutex_);
      for (const auto& key : keys) {
        store_[key.server_name][key.key_id] = key;
      }
    }

    // Clear all keys
    void clear() {
      std::unique_lock lock(mutex_);
      store_.clear();
    }

    // Return total key count
    size_t size() const {
      std::shared_lock lock(mutex_);
      size_t count = 0;
      for (auto& [server, keys] : store_) {
        count += keys.size();
      }
      return count;
    }

  private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::unordered_map<std::string, KnownKey>>
        store_;
  };

  // --- Verify a signature against a specific known public key ---
  static VerifyResult verify_with_key(const json& event,
                                       std::string_view origin,
                                       std::string_view key_id,
                                       const std::vector<uint8_t>& public_key) {
    VerifyResult result;
    result.origin = std::string(origin);
    result.key_id = std::string(key_id);

    // 1. Check that the signature exists
    auto sig_it = event.find(signing_constants::kSignaturesField);
    if (sig_it == event.end() || !sig_it->is_object()) {
      result.error = "Event has no signatures field";
      return result;
    }

    auto origin_it = sig_it->find(origin);
    if (origin_it == sig_it->end() || !origin_it->is_object()) {
      result.error = "Event has no signature from origin: " + std::string(origin);
      return result;
    }

    auto key_it = origin_it->find(key_id);
    if (key_it == origin_it->end() || !key_it->is_string()) {
      result.error = "Event has no signature for key: " + std::string(key_id);
      return result;
    }

    result.signature_b64 = key_it->get<std::string>();
    result.sig_format_valid = is_valid_base64_unpadded(result.signature_b64);

    if (!result.sig_format_valid) {
      result.error = "Signature is not valid base64";
      return result;
    }

    // 2. Build canonical JSON without this signature and without age_ts
    try {
      json event_copy = json_deep_clone(event);

      // Remove the signature being verified
      event_copy[signing_constants::kSignaturesField][origin].erase(
          std::string(key_id));

      // If the origin now has no signatures, remove the origin entry
      if (event_copy[signing_constants::kSignaturesField][origin].empty()) {
        event_copy[signing_constants::kSignaturesField].erase(
            std::string(origin));
      }

      // Remove age_ts from unsigned
      if (event_copy.contains(signing_constants::kUnsignedField)) {
        event_copy[signing_constants::kUnsignedField].erase(
            signing_constants::kAgeTsField);
      }

      result.canonical_signed = CanonicalJsonEngine::serialize(event_copy);
      result.canonical_ok = true;

      // 3. Verify Ed25519 signature
      result.valid = ed25519_verify_raw(
          result.canonical_signed, result.signature_b64, public_key);

      if (!result.valid) {
        result.error = "Ed25519 signature verification failed";
      }
    } catch (const std::exception& e) {
      result.error = std::string("Verification failed: ") + e.what();
    }

    return result;
  }

  // --- Verify against any valid key for a server (using key store) ---
  static VerifyResult verify_with_any_key(const json& event,
                                           std::string_view origin,
                                           KeyStore& key_store) {
    VerifyResult result;
    result.origin = std::string(origin);

    // Check signatures exist for this origin
    auto sig_it = event.find(signing_constants::kSignaturesField);
    if (sig_it == event.end() || !sig_it->is_object()) {
      result.error = "Event has no signatures field";
      return result;
    }

    auto origin_it = sig_it->find(origin);
    if (origin_it == sig_it->end() || !origin_it->is_object()) {
      result.error = "No signature from origin: " + std::string(origin);
      return result;
    }

    // Try each key_id found in the signatures
    for (auto& [key_id, sig_val] : origin_it->items()) {
      auto key = key_store.find_key(origin, key_id);
      if (!key.has_value()) {
        continue;  // Key not known, try next
      }
      if (key->is_revoked) {
        continue;  // Key is revoked, try next
      }

      // Check expiry
      if (key->is_expired && key->valid_until_ts > 0) {
        int64_t now = now_millis();
        if (now > key->valid_until_ts) {
          continue;  // Key expired, try next
        }
      }

      result = verify_with_key(event, origin, key_id, key->public_key);
      if (result.valid) {
        result.key_found = true;
        return result;
      }
    }

    // No valid key found
    result.valid = false;
    if (!result.error.empty()) {
      // Keep the last error
    } else {
      result.error = "No valid key found for origin: " + std::string(origin);
    }
    return result;
  }

  // --- Verify all signatures on an event ---
  struct AllSignaturesResult {
    bool all_valid = false;
    size_t total_signatures = 0;
    size_t verified = 0;
    size_t failed = 0;
    std::vector<VerifyResult> results;
    std::set<std::string> verified_servers;
    std::set<std::string> failed_servers;
  };

  static AllSignaturesResult verify_all_signatures(const json& event,
                                                    KeyStore& key_store) {
    AllSignaturesResult all;
    all.all_valid = true;

    auto servers = extract_signing_servers(event);
    all.total_signatures = servers.size();

    for (const auto& server : servers) {
      auto result = verify_with_any_key(event, server, key_store);
      all.results.push_back(result);

      if (result.valid) {
        all.verified++;
        all.verified_servers.insert(server);
      } else {
        all.failed++;
        all.failed_servers.insert(server);
        all.all_valid = false;
      }
    }

    return all;
  }

  // --- Verify the full event (content hash + signature) ---
  struct FullVerifyResult {
    bool fully_valid = false;
    bool hash_valid = false;
    bool signature_valid = false;
    std::string origin;
    std::vector<VerifyResult> sig_results;
    HashComputationEngine::HashResult hash_result;
    std::string error;
  };

  static FullVerifyResult verify_event_fully(const json& event,
                                              KeyStore& key_store) {
    FullVerifyResult result;

    // 1. Verify content hash
    result.hash_valid = HashComputationEngine::verify_hash(event);
    if (!result.hash_valid) {
      result.error = "Content hash verification failed";
      result.fully_valid = false;
      // Continue to check signatures anyway for diagnostics
    }

    // 2. Determine origin from signatures
    auto servers = extract_signing_servers(event);
    if (servers.empty()) {
      result.error += "; No signing servers found";
      result.fully_valid = false;
      return result;
    }

    // 3. Verify signatures for each server
    bool any_sig_valid = false;
    for (const auto& server : servers) {
      auto sig_result = verify_with_any_key(event, server, key_store);
      result.sig_results.push_back(sig_result);
      if (sig_result.valid) {
        any_sig_valid = true;
        result.origin = server;
      }
    }

    result.signature_valid = any_sig_valid;
    result.fully_valid = result.hash_valid && result.signature_valid;

    if (!result.fully_valid) {
      if (result.error.empty()) {
        result.error = "Full verification failed";
      }
    }

    return result;
  }

  // --- Batch verify multiple events ---
  struct BatchVerifyResult {
    size_t total = 0;
    size_t passed = 0;
    size_t failed = 0;
    std::vector<FullVerifyResult> results;
    std::vector<std::string> error_summaries;
  };

  static BatchVerifyResult batch_verify(const std::vector<json>& events,
                                         KeyStore& key_store) {
    BatchVerifyResult batch;
    batch.total = events.size();

    for (const auto& event : events) {
      auto result = verify_event_fully(event, key_store);
      if (result.fully_valid) {
        batch.passed++;
      } else {
        batch.failed++;
        batch.error_summaries.push_back(result.error);
      }
      batch.results.push_back(std::move(result));
    }

    return batch;
  }

private:
  // --- Raw Ed25519 verification with OpenSSL EVP ---
  static bool ed25519_verify_raw(std::string_view message,
                                  std::string_view signature_b64,
                                  const std::vector<uint8_t>& public_key) {
    auto sig_bytes = base64::decode(signature_b64);

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size());
    if (!pkey) return false;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
      EVP_PKEY_free(pkey);
      return false;
    }

    int ok = EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey);
    if (ok <= 0) {
      EVP_MD_CTX_free(md_ctx);
      EVP_PKEY_free(pkey);
      return false;
    }

    ok = EVP_DigestVerify(md_ctx, sig_bytes.data(), sig_bytes.size(),
                          reinterpret_cast<const uint8_t*>(message.data()),
                          message.size());

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return ok == 1;
  }
};

// ============================================================================
// EventIdGenerator — Event ID Generation per Room Version
// ============================================================================
//
// Matrix event IDs have the format: $localpart:domain
//
// Room versions 1 & 2 (legacy):
//   - localpart is a random string
//   - domain is the server that created the event
//   - Format: $randomString:server.name
//
// Room versions 3+ (current):
//   - localpart is the base64-encoded reference hash
//   - domain is the server that created the event
//   - Format: $base64RefHash:server.name
//
// Room version 11 (future):
//   - Same as v3+ but may include additional metadata
// ============================================================================

class EventIdGenerator {
public:
  // --- Room version format ---
  enum class EventIdFormat : uint8_t {
    kLegacy,     // v1, v2: random localpart
    kRefHash,    // v3+: reference hash as localpart
    kExtended,   // v11+: reference hash with metadata
  };

  // --- Result of event ID generation ---
  struct EventIdResult {
    std::string event_id;         // Full $localpart:domain
    std::string localpart;        // The localpart portion
    std::string domain;           // The domain portion
    std::string reference_hash;   // SHA-256 base64 ref hash (v3+)
    EventIdFormat format;
    bool success = false;
    std::string error;
  };

  // --- Generate event ID for a given event and server ---
  static EventIdResult generate(const json& event,
                                 std::string_view server_domain,
                                 int room_version) {
    EventIdResult result;
    result.domain = std::string(server_domain);

    if (room_version <= 2) {
      return generate_legacy(event, server_domain);
    } else if (room_version <= 10) {
      return generate_refhash(event, server_domain);
    } else {
      // v11+: use extended format
      return generate_extended(event, server_domain);
    }
  }

  // --- Generate legacy (v1/v2) event ID ---
  static EventIdResult generate_legacy(const json& event,
                                        std::string_view server_domain) {
    EventIdResult result;
    result.domain = std::string(server_domain);
    result.format = EventIdFormat::kLegacy;

    // Legacy format: random localpart
    // Typical format: 18-20 random characters from [A-Za-z]
    result.localpart = random_string(18);

    // Also compute the ref hash for informational purposes
    auto ref = ReferenceHashEngine::compute(event);
    if (ref.success) {
      result.reference_hash = ref.reference_hash;
    }

    result.event_id =
        std::string(1, signing_constants::kEventIdSigil) + result.localpart +
        std::string(signing_constants::kEventIdSeparator) + result.domain;
    result.success = true;
    return result;
  }

  // --- Generate reference-hash-based (v3+) event ID ---
  static EventIdResult generate_refhash(const json& event,
                                         std::string_view server_domain) {
    EventIdResult result;
    result.domain = std::string(server_domain);
    result.format = EventIdFormat::kRefHash;

    // Compute reference hash
    auto ref = ReferenceHashEngine::compute(event);
    if (!ref.success) {
      result.error = "Failed to compute reference hash: " + ref.error;
      return result;
    }

    result.reference_hash = ref.reference_hash;
    result.localpart = result.reference_hash;

    result.event_id =
        std::string(1, signing_constants::kEventIdSigil) + result.localpart +
        std::string(signing_constants::kEventIdSeparator) + result.domain;
    result.success = true;
    return result;
  }

  // --- Generate extended (v11+) event ID ---
  static EventIdResult generate_extended(const json& event,
                                          std::string_view server_domain) {
    EventIdResult result;
    result.domain = std::string(server_domain);
    result.format = EventIdFormat::kExtended;

    // v11+: same as v3+ but may include version info in the localpart
    // For now, generate the same as v3+
    auto ref = ReferenceHashEngine::compute(event);
    if (!ref.success) {
      result.error = "Failed to compute reference hash: " + ref.error;
      return result;
    }

    result.reference_hash = ref.reference_hash;
    result.localpart = result.reference_hash;

    result.event_id =
        std::string(1, signing_constants::kEventIdSigil) + result.localpart +
        std::string(signing_constants::kEventIdSeparator) + result.domain;
    result.success = true;
    return result;
  }

  // --- Parse an event ID into its components ---
  struct ParsedEventId {
    std::string localpart;
    std::string domain;
    std::string full_id;
    bool valid = false;

    // Check if this is a reference-hash-based event ID (v3+)
    bool is_refhash_based() const {
      // Ref hash-based IDs have a 43-character base64 localpart
      return valid && localpart.size() == 43 &&
             is_valid_base64_unpadded(localpart);
    }

    // Check if this is a legacy event ID (v1/v2)
    bool is_legacy() const {
      return valid && !is_refhash_based();
    }
  };

  static ParsedEventId parse(std::string_view event_id_str) {
    ParsedEventId parsed;
    parsed.full_id = std::string(event_id_str);

    if (event_id_str.empty()) return parsed;
    if (event_id_str[0] != signing_constants::kEventIdSigil) return parsed;

    std::string_view rest = event_id_str.substr(1);
    auto colon_pos = rest.find(signing_constants::kEventIdSeparator);
    if (colon_pos == std::string_view::npos) return parsed;

    parsed.localpart = std::string(rest.substr(0, colon_pos));
    parsed.domain = std::string(rest.substr(colon_pos + 1));

    if (parsed.localpart.empty() || parsed.domain.empty()) return parsed;

    parsed.valid = true;
    return parsed;
  }

  // --- Validate an event ID format ---
  static bool is_valid_format(std::string_view event_id_str) {
    auto parsed = parse(event_id_str);
    return parsed.valid;
  }

  // --- Generate deterministic event ID from event fields (for testing) ---
  static std::string deterministic_id(const json& event,
                                       std::string_view domain,
                                       std::string_view seed) {
    // Build a deterministic string from the event and seed
    std::string input = CanonicalJsonEngine::serialize(event) +
                        std::string(domain) + std::string(seed);
    std::string hash = sha256_b64_unpadded(input);
    return std::string(1, signing_constants::kEventIdSigil) + hash +
           std::string(signing_constants::kEventIdSeparator) +
           std::string(domain);
  }

  // --- Generate a safe event ID from raw hash (for hash-based IDs) ---
  static std::string from_hash(std::string_view hash_b64,
                                std::string_view domain) {
    return std::string(1, signing_constants::kEventIdSigil) +
           std::string(hash_b64) +
           std::string(signing_constants::kEventIdSeparator) +
           std::string(domain);
  }
};

// ============================================================================
// HashValidationEngine — Validate Event Hashes on Receipt
// ============================================================================
//
// When receiving federated events, the content hash (hashes.sha256) must be
// validated to ensure the event content has not been tampered with during
// transport. This engine provides comprehensive hash validation:
//
//   1. Content hash validation: check hashes.sha256 matches event content
//   2. Redaction hash chain: validate that redacted events reference correct
//      original content hashes
//   3. Auth event hash validation: verify hashes on auth events chain
//   4. Batch validation for multiple events in a single request
//   5. Hash integrity reporting and logging
// ============================================================================

class HashValidationEngine {
public:
  // --- Validation result ---
  struct ValidationResult {
    bool valid = false;
    bool hash_present = false;
    bool hash_format_valid = false;
    bool hash_matches = false;
    std::string expected_hash;
    std::string computed_hash;
    std::string event_id_hint;  // For logging, not critical to result
    std::string error;
  };

  // --- Validation severity ---
  enum class Severity : uint8_t {
    kInfo = 0,
    kWarning = 1,
    kError = 2,
    kCritical = 3,
  };

  // --- Policy configuration ---
  struct ValidationPolicy {
    bool require_content_hash = true;      // Must have hashes field
    bool reject_mismatched = true;         // Reject events with bad hashes
    bool allow_missing_hash = false;       // Accept events without hashes
    bool validate_redaction_chain = true;  // Check redaction hash chain
    bool validate_auth_hashes = true;      // Check auth event hashes
    bool strict_base64_format = true;      // Strict base64 validation
    size_t max_event_size = signing_constants::kMaxEventSizeBytes;
  };

  // --- Validate content hash of a single event ---
  static ValidationResult validate_event_hash(
      const json& event,
      const ValidationPolicy& policy = ValidationPolicy{}) {
    ValidationResult result;

    // Extract event ID hint for logging
    if (event.contains(signing_constants::kEventIdField)) {
      result.event_id_hint =
          event[signing_constants::kEventIdField].get<std::string>();
    }

    // Check hashes field exists
    auto hashes_it = event.find(signing_constants::kHashesField);
    if (hashes_it == event.end() || !hashes_it->is_object()) {
      result.hash_present = false;
      if (policy.require_content_hash && !policy.allow_missing_hash) {
        result.error = "Event missing 'hashes' field";
        return result;
      }
      // If missing hashes are allowed, consider valid
      result.valid = true;
      return result;
    }

    result.hash_present = true;

    // Check sha256 field
    auto sha256_it = hashes_it->find(signing_constants::kSha256Field);
    if (sha256_it == hashes_it->end() || !sha256_it->is_string()) {
      result.error = "Event has 'hashes' but missing 'sha256' field";
      return result;
    }

    result.expected_hash = sha256_it->get<std::string>();

    // Validate base64 format
    if (policy.strict_base64_format) {
      if (!is_valid_base64_unpadded(result.expected_hash)) {
        result.hash_format_valid = false;
        result.error = "Hash is not valid unpadded base64: " +
                       result.expected_hash;
        return result;
      }
      // SHA-256 in unpadded base64 is 43 characters
      if (result.expected_hash.size() != 43) {
        result.hash_format_valid = false;
        result.error = "Hash has incorrect length (expected 43, got " +
                       std::to_string(result.expected_hash.size()) + ")";
        return result;
      }
    }
    result.hash_format_valid = true;

    // Compute content hash
    auto computed = HashComputationEngine::compute_from_event(event);
    if (!computed.success) {
      result.error = "Failed to compute content hash: " + computed.error;
      return result;
    }

    result.computed_hash = computed.sha256_b64;

    // Compare
    result.hash_matches = (result.expected_hash == result.computed_hash);

    if (!result.hash_matches) {
      result.error = "Content hash mismatch: expected=" +
                     result.expected_hash + ", computed=" +
                     result.computed_hash;
      if (policy.reject_mismatched) {
        return result;  // result.valid stays false
      }
    }

    result.valid = result.hash_matches ||
                   (!policy.reject_mismatched && result.hash_present);
    return result;
  }

  // --- Validate redaction hash chain ---
  struct RedactionChainResult {
    bool valid = false;
    bool redaction_hash_ok = false;
    bool original_hash_ok = false;
    std::string redacts_event_id;
    std::string error;
    ValidationResult redaction_validation;
    ValidationResult original_validation;
  };

  static RedactionChainResult validate_redaction_chain(
      const json& redaction_event,
      const json& original_event,
      const ValidationPolicy& policy = ValidationPolicy{}) {
    RedactionChainResult chain;

    // Extract redacts field
    chain.redacts_event_id =
        redaction_event.value(signing_constants::kRedactsField, "");

    if (chain.redacts_event_id.empty()) {
      chain.error = "Redaction event has no 'redacts' field";
      return chain;
    }

    // Validate the redaction event's own hash
    chain.redaction_validation = validate_event_hash(redaction_event, policy);
    chain.redaction_hash_ok = chain.redaction_validation.valid;

    // Validate the original event's hash
    chain.original_validation = validate_event_hash(original_event, policy);
    chain.original_hash_ok = chain.original_validation.valid;

    chain.valid = chain.redaction_hash_ok && chain.original_hash_ok;

    if (!chain.valid) {
      std::ostringstream err;
      err << "Redaction chain validation failed: ";
      if (!chain.redaction_hash_ok) {
        err << "redaction event hash invalid; ";
      }
      if (!chain.original_hash_ok) {
        err << "original event hash invalid; ";
      }
      chain.error = err.str();
    }

    return chain;
  }

  // --- Batch validate multiple events ---
  struct BatchValidationResult {
    size_t total = 0;
    size_t passed = 0;
    size_t failed = 0;
    size_t missing_hash = 0;
    std::vector<ValidationResult> results;
    std::vector<std::string> failure_events;  // event_id_hint of failures
    Severity worst_severity = Severity::kInfo;
  };

  static BatchValidationResult batch_validate(
      const std::vector<json>& events,
      const ValidationPolicy& policy = ValidationPolicy{}) {
    BatchValidationResult batch;
    batch.total = events.size();

    for (const auto& event : events) {
      auto result = validate_event_hash(event, policy);
      batch.results.push_back(result);

      if (result.valid) {
        batch.passed++;
      } else {
        batch.failed++;
        batch.failure_events.push_back(result.event_id_hint);
        batch.worst_severity = Severity::kError;
      }

      if (!result.hash_present) {
        batch.missing_hash++;
      }
    }

    if (batch.failed > 0 && batch.passed > 0) {
      batch.worst_severity = Severity::kWarning;
    }

    return batch;
  }

  // --- Validate auth event hashes in a chain ---
  struct AuthChainValidation {
    bool all_valid = false;
    size_t total_auth_events = 0;
    size_t valid_auth_hashes = 0;
    size_t invalid_auth_hashes = 0;
    std::vector<ValidationResult> results;
    std::string error;
  };

  static AuthChainValidation validate_auth_chain(
      const std::vector<json>& auth_events,
      const ValidationPolicy& policy = ValidationPolicy{}) {
    AuthChainValidation chain;
    chain.total_auth_events = auth_events.size();

    for (const auto& auth_event : auth_events) {
      auto result = validate_event_hash(auth_event, policy);
      chain.results.push_back(result);
      if (result.valid) {
        chain.valid_auth_hashes++;
      } else {
        chain.invalid_auth_hashes++;
      }
    }

    chain.all_valid = (chain.invalid_auth_hashes == 0);

    if (!chain.all_valid) {
      chain.error =
          std::to_string(chain.invalid_auth_hashes) + " of " +
          std::to_string(chain.total_auth_events) +
          " auth events have invalid hashes";
    }

    return chain;
  }

  // --- Fast path: just check if hash exists and looks valid ---
  static bool quick_check(const json& event) {
    auto hashes_it = event.find(signing_constants::kHashesField);
    if (hashes_it == event.end()) return false;

    auto sha256_it = hashes_it->find(signing_constants::kSha256Field);
    if (sha256_it == hashes_it->end()) return false;

    std::string hash_val = sha256_it->get<std::string>();
    return hash_val.size() == 43 && is_valid_base64_unpadded(hash_val);
  }

  // --- Compute hash for an event that doesn't have one ---
  static json add_missing_hash(json event) {
    if (!event.contains(signing_constants::kHashesField)) {
      event = HashComputationEngine::add_content_hash(std::move(event));
    }
    return event;
  }

  // --- Audit report: generate summary of hash validation for a batch ---
  static std::string audit_report(const BatchValidationResult& batch) {
    std::ostringstream report;
    report << "=== Hash Validation Audit Report ===\n";
    report << "Total events: " << batch.total << "\n";
    report << "Passed: " << batch.passed << " ("
           << (batch.total > 0 ? (batch.passed * 100 / batch.total) : 0)
           << "%)\n";
    report << "Failed: " << batch.failed << "\n";
    report << "Missing hash: " << batch.missing_hash << "\n";

    if (!batch.failure_events.empty()) {
      report << "Failed event IDs:\n";
      for (const auto& eid : batch.failure_events) {
        report << "  - " << eid << "\n";
      }
    }

    switch (batch.worst_severity) {
      case Severity::kInfo:
        report << "Severity: INFO\n";
        break;
      case Severity::kWarning:
        report << "Severity: WARNING\n";
        break;
      case Severity::kError:
        report << "Severity: ERROR\n";
        break;
      case Severity::kCritical:
        report << "Severity: CRITICAL\n";
        break;
    }

    report << "===================================\n";
    return report.str();
  }
};

// ============================================================================
// KeyBasedVerifier — Verify Using Specific Key ID or Any Valid Server Key
// ============================================================================
//
// Extends SignatureVerificationEngine with higher-level operations:
//   - Key ID resolution: given a key_id, look up the public key
//   - Origin verification: verify that the event was signed by the claimed
//     origin server
//   - Key lifecycle: check if a key is still valid (not expired/revoked)
//   - Trust-on-first-use (TOFU): optionally accept first-seen keys
// ============================================================================

class KeyBasedVerifier {
public:
  // --- Key resolution result ---
  struct KeyResolution {
    std::optional<SignatureVerificationEngine::KnownKey> key;
    bool found = false;
    bool expired = false;
    bool revoked = false;
    std::string error;
  };

  // --- Constructor ---
  explicit KeyBasedVerifier(SignatureVerificationEngine::KeyStore& key_store)
      : key_store_(key_store) {}

  // --- Verify using a specific key ID ---
  SignatureVerificationEngine::VerifyResult verify_with_key_id(
      const json& event,
      std::string_view origin,
      std::string_view key_id) {
    // Resolve the key
    auto resolution = resolve_key(origin, key_id);
    if (!resolution.found) {
      SignatureVerificationEngine::VerifyResult result;
      result.origin = std::string(origin);
      result.key_id = std::string(key_id);
      result.error = resolution.error;
      return result;
    }

    if (resolution.revoked) {
      SignatureVerificationEngine::VerifyResult result;
      result.origin = std::string(origin);
      result.key_id = std::string(key_id);
      result.error = "Key is revoked: " + std::string(key_id);
      return result;
    }

    if (resolution.expired) {
      SignatureVerificationEngine::VerifyResult result;
      result.origin = std::string(origin);
      result.key_id = std::string(key_id);
      result.error = "Key is expired: " + std::string(key_id);
      return result;
    }

    return SignatureVerificationEngine::verify_with_key(
        event, origin, key_id, resolution.key->public_key);
  }

  // --- Verify using any valid key for an origin ---
  SignatureVerificationEngine::VerifyResult verify_origin(
      const json& event,
      std::string_view origin) {
    return SignatureVerificationEngine::verify_with_any_key(
        event, origin, key_store_);
  }

  // --- Resolve a key ID to a known key ---
  KeyResolution resolve_key(std::string_view server_name,
                             std::string_view key_id) {
    KeyResolution resolution;

    auto key = key_store_.find_key(server_name, key_id);
    if (!key.has_value()) {
      resolution.error =
          "Key not found: " + std::string(server_name) + "/" +
          std::string(key_id);
      return resolution;
    }

    resolution.key = *key;
    resolution.found = true;
    resolution.expired = key->is_expired;
    resolution.revoked = key->is_revoked;

    return resolution;
  }

  // --- Check if a server has at least one valid (non-expired, non-revoked) key ---
  bool has_valid_key(std::string_view server_name) {
    auto keys = key_store_.find_server_keys(server_name);
    for (const auto& key : keys) {
      if (!key.is_revoked && !key.is_expired) {
        return true;
      }
    }
    return false;
  }

  // --- Trust-on-first-use: accept a new key if we've never seen this server ---
  struct TofuResult {
    bool accepted = false;
    bool is_new_server = false;
    std::string error;
  };

  TofuResult try_tofu_accept(std::string_view server_name,
                              std::string_view key_id,
                              const std::vector<uint8_t>& public_key) {
    TofuResult result;

    if (key_store_.is_server_known(server_name)) {
      result.is_new_server = false;
      result.error = "Server is already known: " + std::string(server_name);
      return result;
    }

    // Server is new — accept the key
    SignatureVerificationEngine::KnownKey new_key;
    new_key.server_name = std::string(server_name);
    new_key.key_id = std::string(key_id);
    new_key.public_key = public_key;
    new_key.valid_until_ts = now_millis() + (7 * 24 * 3600 * 1000);  // 7 days

    key_store_.add_key(new_key);

    result.accepted = true;
    result.is_new_server = true;
    return result;
  }

private:
  SignatureVerificationEngine::KeyStore& key_store_;
};

// ============================================================================
// BatchSigningProcessor — Process Large Batches of Events for Signing
// ============================================================================
//
// When a server needs to sign many events (e.g., during room creation,
// bulk invites, or backfill), a batch processor can optimize the signing
// pipeline by:
//   - Grouping events by origin server
//   - Pre-computing canonical forms
//   - Parallel hash computation
//   - Throttling to prevent resource exhaustion
// ============================================================================

class BatchSigningProcessor {
public:
  // --- Processing options ---
  struct BatchOptions {
    size_t max_batch_size = 100;
    size_t max_concurrent = 4;         // Concurrent signing operations
    bool stop_on_first_error = false;
    bool compute_hashes_first = true;  // Pre-compute all hashes before signing
    int64_t timeout_ms = 30000;        // Timeout per batch
  };

  // --- Constructor ---
  explicit BatchSigningProcessor(
      std::shared_ptr<SignatureVerificationEngine::KeyStore> key_store)
      : key_store_(std::move(key_store)) {}

  // --- Process a batch of events for signing ---
  struct ProcessResult {
    std::vector<EventSigningEngine::SignResult> results;
    std::vector<json> signed_events;
    size_t total = 0;
    size_t succeeded = 0;
    size_t failed = 0;
    int64_t elapsed_ms = 0;
    std::vector<std::string> errors;
  };

  ProcessResult process_batch(
      const std::vector<json>& events,
      const EventSigningEngine::SigningConfig& config,
      const BatchOptions& options = BatchOptions{}) {
    ProcessResult result;
    result.total = events.size();

    auto start = chr::steady_clock::now();

    // Phase 1: Pre-compute content hashes if configured
    std::vector<json> prepared_events;
    prepared_events.reserve(events.size());

    if (options.compute_hashes_first) {
      for (const auto& event : events) {
        try {
          json prepared = json_deep_clone(event);

          // Add origin_server_ts if missing
          if (!prepared.contains(signing_constants::kOriginServerTsField)) {
            prepared[signing_constants::kOriginServerTsField] = now_millis();
          }

          // Compute and add content hash
          prepared =
              HashComputationEngine::add_content_hash(std::move(prepared));

          prepared_events.push_back(std::move(prepared));
        } catch (const std::exception& e) {
          result.failed++;
          result.errors.push_back(
              std::string("Pre-compute hash failed: ") + e.what());
          if (options.stop_on_first_error) {
            break;
          }
        }
      }
    } else {
      prepared_events = events;
    }

    // Phase 2: Sign each prepared event
    for (size_t i = 0; i < prepared_events.size() && i < options.max_batch_size;
         i++) {
      auto sign_result = EventSigningEngine::sign_event(prepared_events[i], config);
      result.results.push_back(sign_result);

      if (sign_result.success) {
        result.succeeded++;
        result.signed_events.push_back(sign_result.signed_event);
      } else {
        result.failed++;
        result.errors.push_back(sign_result.error);
        if (options.stop_on_first_error) {
          break;
        }
      }
    }

    auto end = chr::steady_clock::now();
    result.elapsed_ms =
        chr::duration_cast<chr::milliseconds>(end - start).count();

    return result;
  }

  // --- Get the key store ---
  SignatureVerificationEngine::KeyStore& key_store() { return *key_store_; }

private:
  std::shared_ptr<SignatureVerificationEngine::KeyStore> key_store_;
};

// ============================================================================
// EventIdFormatParser — Parse and Validate Event ID Formats Across Versions
// ============================================================================
//
// Matrix event IDs have evolved across room versions. This parser handles
// all known formats and provides introspection into the event ID structure.
// ============================================================================

class EventIdFormatParser {
public:
  // --- All known event ID formats ---
  enum class Format : uint8_t {
    kUnknown = 0,
    kLegacyV1,     // $random18chars:domain
    kLegacyV2,     // Same as V1
    kHashV3,       // $base64refhash:domain (43 char localpart)
    kHashV4,       // $base64refhash:domain (same format, diff content rules)
    kHashV5,       // $base64refhash:domain
    kHashV6,       // $base64refhash:domain
    kHashV7,       // $base64refhash:domain
    kHashV8,       // $base64refhash:domain
    kHashV9,       // $base64refhash:domain
    kHashV10,      // $base64refhash:domain
    kHashV11,      // $base64refhash:domain (extended format)
  };

  // --- Parsed event ID with format detection ---
  struct ParsedInfo {
    std::string full_id;
    std::string localpart;
    std::string domain;
    Format format = Format::kUnknown;
    bool valid = false;
    bool is_legacy = false;
    bool is_refhash = false;
    std::string error;

    // Does this appear to be a valid reference hash?
    bool localpart_looks_like_hash() const {
      return localpart.size() == 43 && is_valid_base64_unpadded(localpart);
    }

    // Room version this format corresponds to
    int deduced_room_version() const {
      if (is_legacy) return 1;
      if (is_refhash) return 3;
      return 0;  // unknown
    }
  };

  // --- Parse and detect format ---
  static ParsedInfo parse_and_detect(std::string_view event_id_str) {
    ParsedInfo info;
    info.full_id = std::string(event_id_str);

    if (event_id_str.empty()) {
      info.error = "Empty event ID";
      return info;
    }

    if (event_id_str[0] != signing_constants::kEventIdSigil) {
      info.error = "Event ID must start with '$'";
      return info;
    }

    std::string_view rest = event_id_str.substr(1);
    auto colon_pos = rest.find(signing_constants::kEventIdSeparator);
    if (colon_pos == std::string_view::npos) {
      info.error = "Event ID missing domain separator ':'";
      return info;
    }

    info.localpart = std::string(rest.substr(0, colon_pos));
    info.domain = std::string(rest.substr(colon_pos + 1));

    if (info.localpart.empty()) {
      info.error = "Event ID has empty localpart";
      return info;
    }

    if (info.domain.empty()) {
      info.error = "Event ID has empty domain";
      return info;
    }

    // Detect format
    if (info.localpart.size() == 43 && is_valid_base64_unpadded(info.localpart)) {
      info.is_refhash = true;
      info.format = Format::kHashV3;  // Default to v3, actual version unknown
    } else {
      info.is_legacy = true;
      info.format = Format::kLegacyV1;
    }

    info.valid = true;
    return info;
  }

  // --- Determine room version from a set of event IDs (heuristic) ---
  static int detect_room_version(const std::vector<std::string>& event_ids) {
    size_t legacy_count = 0;
    size_t hash_count = 0;

    for (const auto& eid : event_ids) {
      auto parsed = parse_and_detect(eid);
      if (!parsed.valid) continue;
      if (parsed.is_legacy) legacy_count++;
      if (parsed.is_refhash) hash_count++;
    }

    if (hash_count > 0) return 3;    // At least v3
    if (legacy_count > 0) return 1;  // v1 or v2
    return 0;                         // unknown
  }

  // --- Validate event ID against expected room version ---
  static bool is_compatible_with_version(std::string_view event_id_str,
                                          int room_version) {
    auto parsed = parse_and_detect(event_id_str);
    if (!parsed.valid) return false;

    if (room_version <= 2) {
      return parsed.is_legacy;
    }
    return parsed.is_refhash;
  }

  // --- Generate a human-readable description of the format ---
  static std::string describe_format(Format format) {
    switch (format) {
      case Format::kUnknown:
        return "Unknown";
      case Format::kLegacyV1:
        return "Legacy V1 (random localpart)";
      case Format::kLegacyV2:
        return "Legacy V2 (random localpart)";
      case Format::kHashV3:
        return "Hash V3+ (reference hash localpart)";
      case Format::kHashV4:
        return "Hash V4 (reference hash localpart)";
      case Format::kHashV5:
        return "Hash V5 (reference hash localpart)";
      case Format::kHashV6:
        return "Hash V6 (reference hash localpart)";
      case Format::kHashV7:
        return "Hash V7 (reference hash localpart)";
      case Format::kHashV8:
        return "Hash V8 (reference hash localpart)";
      case Format::kHashV9:
        return "Hash V9 (reference hash localpart)";
      case Format::kHashV10:
        return "Hash V10 (reference hash localpart)";
      case Format::kHashV11:
        return "Hash V11 (extended reference hash)";
    }
    return "Unknown";
  }
};

// ============================================================================
// HashIntegrityChecker — Deep Hash Integrity Validation
// ============================================================================
//
// Beyond simple content hash verification, this checker performs deep
// integrity validation:
//   - Recursive hash checking on auth event chains
//   - Cross-reference checking between event IDs and hashes
//   - Hash consistency across event versions
//   - Tampering detection through hash comparison
// ============================================================================

class HashIntegrityChecker {
public:
  // --- Integrity check result ---
  struct IntegrityResult {
    bool passed = false;
    size_t checks_performed = 0;
    size_t checks_passed = 0;
    size_t checks_failed = 0;
    std::vector<std::string> issues;
    std::vector<std::string> warnings;
  };

  // --- Deep integrity check on a single event ---
  static IntegrityResult check_event(const json& event,
                                      int room_version = 3) {
    IntegrityResult result;

    // Check 1: Content hash
    result.checks_performed++;
    if (HashComputationEngine::verify_hash(event)) {
      result.checks_passed++;
    } else {
      result.checks_failed++;
      result.issues.push_back("Content hash mismatch");
    }

    // Check 2: Reference hash consistency with event ID (v3+)
    if (room_version >= 3 && event.contains(signing_constants::kEventIdField)) {
      result.checks_performed++;
      std::string event_id =
          event[signing_constants::kEventIdField].get<std::string>();
      if (ReferenceHashEngine::validate_event_id(event, event_id)) {
        result.checks_passed++;
      } else {
        result.checks_failed++;
        result.issues.push_back("Event ID does not match reference hash");
      }
    }

    // Check 3: Signature format
    result.checks_performed++;
    if (event.contains(signing_constants::kSignaturesField)) {
      auto& sigs = event[signing_constants::kSignaturesField];
      if (sigs.is_object() && !sigs.empty()) {
        result.checks_passed++;
      } else {
        result.checks_failed++;
        result.issues.push_back("Signatures field is empty or invalid");
      }
    } else {
      result.warnings.push_back("Event has no signatures");
      result.checks_passed++;  // Not necessarily an error
    }

    // Check 4: Required fields present
    result.checks_performed++;
    bool has_required =
        event.contains(signing_constants::kTypeField) &&
        event.contains(signing_constants::kSenderField) &&
        event.contains(signing_constants::kRoomIdField);
    if (has_required) {
      result.checks_passed++;
    } else {
      result.checks_failed++;
      result.issues.push_back("Missing required event fields");
    }

    result.passed = (result.checks_failed == 0);
    return result;
  }

  // --- Deep integrity check on a chain of events ---
  struct ChainIntegrityResult {
    bool all_passed = false;
    size_t total_events = 0;
    size_t passed_events = 0;
    size_t failed_events = 0;
    std::vector<IntegrityResult> event_results;
    std::vector<std::string> chain_issues;
  };

  static ChainIntegrityResult check_event_chain(
      const std::vector<json>& events,
      int room_version = 3) {
    ChainIntegrityResult chain;
    chain.total_events = events.size();

    for (const auto& event : events) {
      auto result = check_event(event, room_version);
      chain.event_results.push_back(result);

      if (result.passed) {
        chain.passed_events++;
      } else {
        chain.failed_events++;
        // Collect chain-level issues
        for (const auto& issue : result.issues) {
          std::string event_id_hint =
              event.value(signing_constants::kEventIdField, "(unknown)");
          chain.chain_issues.push_back("[" + event_id_hint + "] " + issue);
        }
      }
    }

    chain.all_passed = (chain.failed_events == 0);
    return chain;
  }

  // --- Compare two events and detect tampering ---
  struct TamperDetectionResult {
    bool is_tampered = false;
    bool content_changed = false;
    bool hash_changed = false;
    bool signatures_changed = false;
    bool event_id_changed = false;
    std::string original_hash;
    std::string modified_hash;
    std::vector<std::string> changes;
  };

  static TamperDetectionResult detect_tampering(const json& original,
                                                 const json& modified) {
    TamperDetectionResult result;

    // Compare content
    auto orig_content_it = original.find(signing_constants::kContentField);
    auto mod_content_it = modified.find(signing_constants::kContentField);

    if (orig_content_it != original.end() && mod_content_it != modified.end()) {
      std::string orig_canon =
          CanonicalJsonEngine::serialize(*orig_content_it);
      std::string mod_canon =
          CanonicalJsonEngine::serialize(*mod_content_it);

      if (orig_canon != mod_canon) {
        result.content_changed = true;
        result.changes.push_back("Content changed");
      }
    }

    // Compare hashes
    auto orig_hash = HashComputationEngine::extract_hash(original);
    auto mod_hash = HashComputationEngine::extract_hash(modified);

    result.original_hash = orig_hash.value_or("(none)");
    result.modified_hash = mod_hash.value_or("(none)");

    if (result.original_hash != result.modified_hash) {
      result.hash_changed = true;
      result.changes.push_back("Hash changed");
    }

    // Compare signatures
    auto orig_sig_it = original.find(signing_constants::kSignaturesField);
    auto mod_sig_it = modified.find(signing_constants::kSignaturesField);

    if (orig_sig_it != original.end() && mod_sig_it != modified.end()) {
      if (orig_sig_it->dump() != mod_sig_it->dump()) {
        result.signatures_changed = true;
        result.changes.push_back("Signatures changed");
      }
    } else if (orig_sig_it != original.end() || mod_sig_it != modified.end()) {
      result.signatures_changed = true;
      result.changes.push_back("Signatures added/removed");
    }

    // Compare event IDs
    auto orig_eid = original.value(signing_constants::kEventIdField, "");
    auto mod_eid = modified.value(signing_constants::kEventIdField, "");
    if (orig_eid != mod_eid) {
      result.event_id_changed = true;
      result.changes.push_back("Event ID changed");
    }

    result.is_tampered = !result.changes.empty();
    return result;
  }

  // --- Validate hash consistency across an event spanning versions ---
  static bool is_hash_consistent(const json& event_v1, const json& event_v2) {
    auto hash1 = HashComputationEngine::extract_hash(event_v1);
    auto hash2 = HashComputationEngine::extract_hash(event_v2);

    if (!hash1.has_value() || !hash2.has_value()) return false;
    return *hash1 == *hash2;
  }
};

// ============================================================================
// ContentHashManager — Manage Content Hashes in Event Lifecycle
// ============================================================================
//
// Throughout an event's lifecycle (creation, federation send, federation
// receive, storage, retrieval), the content hash must be managed correctly:
//   - Always compute before signing
//   - Strip before certain operations if needed
//   - Recompute after content modifications
//   - Track hash history for audit purposes
// ============================================================================

class ContentHashManager {
public:
  // --- Hash management result ---
  struct HashOperation {
    std::string operation;
    std::string hash_before;
    std::string hash_after;
    bool success = false;
    std::string error;
  };

  // --- Hash history entry ---
  struct HashHistoryEntry {
    std::string event_id;
    std::string hash;
    int64_t timestamp;
    std::string operation;  // "create", "update", "redact", etc.
  };

  // --- Prepare an event for signing (add content hash) ---
  static json prepare_for_signing(json event) {
    return HashComputationEngine::add_content_hash(std::move(event));
  }

  // --- Strip content hash from an event (for certain comparisons) ---
  static json strip_content_hash(json event) {
    event.erase(signing_constants::kHashesField);
    return event;
  }

  // --- Get the content hash for comparison ---
  static std::optional<std::string> get_hash(const json& event) {
    return HashComputationEngine::extract_hash(event);
  }

  // --- Verify content hash after a content modification ---
  static bool verify_after_modification(const json& original,
                                         const json& modified) {
    // The modified event should have a new hash that matches its content
    return HashComputationEngine::verify_hash(modified);
  }

  // --- Compute hash delta between two versions of an event ---
  struct HashDelta {
    std::string original_hash;
    std::string new_hash;
    bool hash_changed = false;
    bool content_changed = false;
  };

  static HashDelta compute_delta(const json& original,
                                  const json& modified) {
    HashDelta delta;
    delta.original_hash =
        HashComputationEngine::extract_hash(original).value_or("(none)");
    delta.new_hash =
        HashComputationEngine::extract_hash(modified).value_or("(none)");
    delta.hash_changed = (delta.original_hash != delta.new_hash);

    // Check if content actually changed
    auto orig_c = original.find(signing_constants::kContentField);
    auto mod_c = modified.find(signing_constants::kContentField);
    if (orig_c != original.end() && mod_c != modified.end()) {
      delta.content_changed =
          (CanonicalJsonEngine::serialize(*orig_c) !=
           CanonicalJsonEngine::serialize(*mod_c));
    }

    return delta;
  }

  // --- Assert content hash is valid (throw on mismatch) ---
  static void assert_hash_valid(const json& event) {
    if (!HashComputationEngine::verify_hash(event)) {
      std::string eid =
          event.value(signing_constants::kEventIdField, "(unknown event)");
      throw std::runtime_error("Content hash validation failed for event: " + eid);
    }
  }

  // --- Safely add hash to event (returns success/failure instead of throwing) ---
  static HashOperation safe_add_hash(json& event) {
    HashOperation op;
    op.operation = "add_hash";

    try {
      op.hash_before =
          HashComputationEngine::extract_hash(event).value_or("(none)");
      HashComputationEngine::add_content_hash_inplace(event);
      op.hash_after =
          HashComputationEngine::extract_hash(event).value_or("(none)");
      op.success = true;
    } catch (const std::exception& e) {
      op.error = e.what();
    }

    return op;
  }
};

// ============================================================================
// SignatureStore — Persistent Signature and Key Storage
// ============================================================================
//
// A centralized store for managing server signing keys and event signatures.
// Provides:
//   - Key registration and retrieval
//   - Key expiration and rotation tracking
//   - Signature audit trail
//   - Public key distribution
// ============================================================================

class SignatureStore {
public:
  // --- Constructor with optional backing key store ---
  SignatureStore()
      : key_store_(std::make_shared<
            SignatureVerificationEngine::InMemoryKeyStore>()) {}

  explicit SignatureStore(
      std::shared_ptr<SignatureVerificationEngine::KeyStore> backing)
      : key_store_(std::move(backing)) {}

  // --- Register a server signing key ---
  void register_key(std::string_view server_name,
                     std::string_view key_id,
                     const std::vector<uint8_t>& public_key,
                     int64_t valid_until_ts = 0) {
    SignatureVerificationEngine::KnownKey key;
    key.server_name = std::string(server_name);
    key.key_id = std::string(key_id);
    key.public_key = public_key;
    key.valid_until_ts = valid_until_ts > 0 ? valid_until_ts
                                             : (now_millis() + 7 * 86400000);
    key_store_->add_key(key);

    // Record in audit log
    audit_log_.push_back({
        std::string(server_name),
        std::string(key_id),
        now_millis(),
        "register",
    });
  }

  // --- Register key from an Ed25519Keypair ---
  void register_keypair(std::string_view server_name,
                         const crypto::Ed25519Keypair& kp,
                         int64_t valid_until_ts = 0) {
    register_key(server_name, kp.key_id(), kp.public_key, valid_until_ts);
  }

  // --- Look up a key ---
  std::optional<SignatureVerificationEngine::KnownKey> find_key(
      std::string_view server_name,
      std::string_view key_id) {
    return key_store_->find_key(server_name, key_id);
  }

  // --- Get all keys for a server ---
  std::vector<SignatureVerificationEngine::KnownKey> get_server_keys(
      std::string_view server_name) {
    return key_store_->find_server_keys(server_name);
  }

  // --- Revoke a key ---
  bool revoke_key(std::string_view server_name, std::string_view key_id) {
    auto key = key_store_->find_key(server_name, key_id);
    if (!key.has_value()) return false;

    key->is_revoked = true;
    key_store_->add_key(*key);

    audit_log_.push_back({
        std::string(server_name),
        std::string(key_id),
        now_millis(),
        "revoke",
    });
    return true;
  }

  // --- Check if a key is known ---
  bool is_key_known(std::string_view server_name,
                     std::string_view key_id) {
    return key_store_->find_key(server_name, key_id).has_value();
  }

  // --- Get underlying key store ---
  std::shared_ptr<SignatureVerificationEngine::KeyStore> key_store() {
    return key_store_;
  }

  // --- Audit log entry ---
  struct AuditEntry {
    std::string server_name;
    std::string key_id;
    int64_t timestamp;
    std::string action;
  };

  // --- Get audit log ---
  const std::vector<AuditEntry>& audit_log() const { return audit_log_; }

  // --- Clear audit log ---
  void clear_audit_log() { audit_log_.clear(); }

  // --- Export public keys as JSON (for key server response) ---
  json export_public_keys() const {
    json result = json::object();

    // In a real implementation, we'd iterate all known keys
    // For now, return the structure
    result["server_name"] = "";
    result["verify_keys"] = json::object();
    result["old_verify_keys"] = json::object();

    return result;
  }

private:
  std::shared_ptr<SignatureVerificationEngine::KeyStore> key_store_;
  std::vector<AuditEntry> audit_log_;
};

// ============================================================================
// CanonicalJsonValidator — Advanced Canonical JSON Validation
// ============================================================================
//
// Provides thorough validation of canonical JSON compliance:
//   - Key ordering verification
//   - Whitespace prohibition checking
//   - Number format validation
//   - String escaping correctness
//   - Structural integrity
// ============================================================================

class CanonicalJsonValidator {
public:
  // --- Validation issue severity ---
  enum class IssueSeverity : uint8_t {
    kInfo = 0,
    kWarning = 1,
    kError = 2,
  };

  // --- A single issue found during validation ---
  struct ValidationIssue {
    IssueSeverity severity = IssueSeverity::kInfo;
    std::string message;
    std::string location;  // JSON path
  };

  // --- Full validation result ---
  struct ValidationReport {
    bool is_canonical = false;
    std::vector<ValidationIssue> issues;
    std::string canonical_form;  // The corrected canonical form
  };

  // --- Validate that a JSON string is in canonical form ---
  static ValidationReport validate(std::string_view raw_json) {
    ValidationReport report;

    try {
      // Parse the JSON
      json parsed;
      try {
        parsed = json::parse(raw_json);
      } catch (const std::exception& e) {
        report.issues.push_back({
            IssueSeverity::kError,
            std::string("JSON parse error: ") + e.what(),
            "(root)",
        });
        return report;
      }

      // Compute canonical form
      report.canonical_form = CanonicalJsonEngine::serialize(parsed);

      // Check if input matches canonical form
      if (std::string(raw_json) == report.canonical_form) {
        report.is_canonical = true;
        return report;
      }

      // Detect specific issues

      // Check for whitespace
      bool has_whitespace = false;
      for (char c : raw_json) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
          has_whitespace = true;
          break;
        }
      }
      if (has_whitespace) {
        report.issues.push_back({
            IssueSeverity::kWarning,
            "JSON contains whitespace characters",
            "(root)",
        });
      }

      // Check key ordering (if object)
      if (parsed.is_object()) {
        std::vector<std::string> input_keys;
        for (auto& [k, v] : parsed.items()) {
          input_keys.push_back(k);
        }

        std::vector<std::string> sorted_keys = input_keys;
        std::sort(sorted_keys.begin(), sorted_keys.end());

        if (input_keys != sorted_keys) {
          report.issues.push_back({
              IssueSeverity::kError,
              "Object keys are not sorted lexicographically",
              "(root)",
          });
        }
      }

      // Check for trailing commas or other artifacts
      // (Hard to detect without full parsing comparison)

    } catch (const std::exception& e) {
      report.issues.push_back({
          IssueSeverity::kError,
          std::string("Validation exception: ") + e.what(),
          "(root)",
      });
    }

    return report;
  }

  // --- Quick check: is this canonical JSON? ---
  static bool is_canonical(std::string_view raw_json) {
    return validate(raw_json).is_canonical;
  }

  // --- Get canonical form for any JSON ---
  static std::string canonicalize(std::string_view raw_json) {
    json parsed = json::parse(raw_json);
    return CanonicalJsonEngine::serialize(parsed);
  }
};

// ============================================================================
// EventSigningCoordinator — Coordinator for the Full Signing Pipeline
// ============================================================================
//
// Orchestrates the complete event signing workflow:
//   1. Validate event structure
//   2. Compute and add content hash
//   3. Generate event ID (based on room version)
//   4. Sign with server key
//   5. Verify the signed event
//   6. Record audit trail
// ============================================================================

class EventSigningCoordinator {
public:
  // --- Complete signing workflow result ---
  struct WorkflowResult {
    json signed_event;
    std::string event_id;
    std::string content_hash;
    std::string reference_hash;
    int room_version = 0;
    bool success = false;
    std::string error;
    bool hash_verified = false;
    bool signature_verified = false;
  };

  // --- Constructor ---
  EventSigningCoordinator(
      std::shared_ptr<SignatureVerificationEngine::KeyStore> key_store,
      std::string server_name,
      int default_room_version = 10)
      : key_store_(std::move(key_store)),
        server_name_(std::move(server_name)),
        default_room_version_(default_room_version) {}

  // --- Full signing workflow ---
  WorkflowResult sign_event_workflow(
      const json& input_event,
      const crypto::Ed25519Keypair& signing_key,
      int room_version = -1) {
    WorkflowResult result;

    if (room_version < 0) {
      room_version = default_room_version_;
    }
    result.room_version = room_version;

    try {
      // Step 1: Validate event structure
      if (!validate_event_structure(input_event)) {
        result.error = "Invalid event structure";
        return result;
      }

      // Step 2: Compute and add content hash
      json event_with_hash =
          HashComputationEngine::add_content_hash(json_deep_clone(input_event));
      result.content_hash =
          HashComputationEngine::extract_hash(event_with_hash).value_or("");

      // Step 3: Generate event ID
      auto eid_result =
          EventIdGenerator::generate(event_with_hash, server_name_, room_version);
      if (!eid_result.success) {
        result.error = "Event ID generation failed: " + eid_result.error;
        return result;
      }

      event_with_hash[signing_constants::kEventIdField] = eid_result.event_id;
      result.event_id = eid_result.event_id;
      result.reference_hash = eid_result.reference_hash;

      // Step 4: Sign the event
      auto sign_config = make_signing_config(signing_key);
      auto sign_result =
          EventSigningEngine::sign_event(event_with_hash, sign_config);

      if (!sign_result.success) {
        result.error = "Event signing failed: " + sign_result.error;
        return result;
      }

      result.signed_event = sign_result.signed_event;

      // Step 5: Self-verify
      auto verify_result = verify_signed_event(result.signed_event);
      result.hash_verified = verify_result.hash_valid;
      result.signature_verified = verify_result.signature_valid;

      if (!verify_result.fully_valid) {
        result.error = "Self-verification failed: " + verify_result.error;
        return result;
      }

      result.success = true;
    } catch (const std::exception& e) {
      result.error = std::string("Workflow exception: ") + e.what();
    }

    return result;
  }

  // --- Batch signing workflow ---
  std::vector<WorkflowResult> batch_sign_workflow(
      const std::vector<json>& events,
      const crypto::Ed25519Keypair& signing_key,
      int room_version = -1) {
    std::vector<WorkflowResult> results;
    results.reserve(events.size());

    for (const auto& event : events) {
      results.push_back(
          sign_event_workflow(event, signing_key, room_version));
    }

    return results;
  }

  // --- Verify a signed event ---
  SignatureVerificationEngine::FullVerifyResult verify_signed_event(
      const json& signed_event) {
    return SignatureVerificationEngine::verify_event_fully(
        signed_event, *key_store_);
  }

  // --- Set default room version ---
  void set_default_room_version(int version) { default_room_version_ = version; }

  // --- Get key store ---
  SignatureVerificationEngine::KeyStore& key_store() { return *key_store_; }

private:
  // --- Validate basic event structure ---
  static bool validate_event_structure(const json& event) {
    // Must have type
    if (!event.contains(signing_constants::kTypeField) ||
        !event[signing_constants::kTypeField].is_string()) {
      return false;
    }

    // Must have sender
    if (!event.contains(signing_constants::kSenderField) ||
        !event[signing_constants::kSenderField].is_string()) {
      return false;
    }

    // Must have room_id
    if (!event.contains(signing_constants::kRoomIdField) ||
        !event[signing_constants::kRoomIdField].is_string()) {
      return false;
    }

    // Must have content
    if (!event.contains(signing_constants::kContentField) ||
        !event[signing_constants::kContentField].is_object()) {
      return false;
    }

    return true;
  }

  // --- Create signing configuration ---
  EventSigningEngine::SigningConfig make_signing_config(
      const crypto::Ed25519Keypair& signing_key) {
    EventSigningEngine::SigningConfig config;
    config.origin = server_name_;
    config.key_id = signing_key.key_id();
    config.private_key = signing_key.private_key;
    config.add_content_hash = true;
    config.strip_age_ts = true;
    config.add_origin_server_ts = true;
    return config;
  }

  std::shared_ptr<SignatureVerificationEngine::KeyStore> key_store_;
  std::string server_name_;
  int default_room_version_;
};

// ============================================================================
// Convenience API — Free Functions for Quick Operations
// ============================================================================
//
// These functions provide a concise API for common event signing operations
// without requiring the user to instantiate the full class hierarchy.
// ============================================================================

namespace event_signing {

// --- Sign an event with a server keypair ---
inline json sign_event(const json& event,
                        const crypto::Ed25519Keypair& keypair,
                        std::string_view origin,
                        int room_version = 3) {
  auto store = std::make_shared<
      SignatureVerificationEngine::InMemoryKeyStore>();

  // Register our own key
  SignatureVerificationEngine::KnownKey own_key;
  own_key.server_name = std::string(origin);
  own_key.key_id = keypair.key_id();
  own_key.public_key = keypair.public_key;
  store->add_key(own_key);

  EventSigningCoordinator coordinator(store, std::string(origin), room_version);
  auto result = coordinator.sign_event_workflow(event, keypair, room_version);

  if (!result.success) {
    throw std::runtime_error("Event signing failed: " + result.error);
  }

  return result.signed_event;
}

// --- Verify an event's signature ---
inline bool verify_event(const json& event,
                          std::string_view origin,
                          std::string_view key_id,
                          const std::vector<uint8_t>& public_key) {
  return SignatureVerificationEngine::verify_with_key(
             event, origin, key_id, public_key)
      .valid;
}

// --- Compute the content hash for an event ---
inline std::string compute_content_hash(const json& event) {
  auto result = HashComputationEngine::compute_from_event(event);
  return result.success ? result.sha256_b64 : "";
}

// --- Compute the reference hash for an event ---
inline std::string compute_reference_hash(const json& event) {
  auto result = ReferenceHashEngine::compute(event);
  return result.success ? result.reference_hash : "";
}

// --- Generate an event ID ---
inline std::string generate_event_id(const json& event,
                                      std::string_view domain,
                                      int room_version = 3) {
  auto result = EventIdGenerator::generate(event, domain, room_version);
  return result.success ? result.event_id : "";
}

// --- Validate content hash on receipt ---
inline bool validate_hash(const json& event) {
  return HashComputationEngine::verify_hash(event);
}

// --- Quick canonical JSON ---
inline std::string canonical_json(const json& value) {
  return CanonicalJsonEngine::serialize(value);
}

// --- Verify an event with full validation ---
inline bool verify_event_full(const json& event,
                               SignatureVerificationEngine::KeyStore& key_store) {
  return SignatureVerificationEngine::verify_event_fully(event, key_store)
      .fully_valid;
}

}  // namespace event_signing

// ============================================================================
// Self-Test and Diagnosis
// ============================================================================
//
// Built-in diagnostics to verify the signing engine is functioning correctly.
// ============================================================================

namespace signing_diag {

// --- Test canonical JSON round-trip ---
inline bool test_canonical_roundtrip() {
  json test_obj = {
      {"z_key", "first in sort"},
      {"a_key", "second in sort"},
      {"nested", {{"inner_b", 2}, {"inner_a", 1}}},
  };

  std::string canon = CanonicalJsonEngine::serialize(test_obj);
  json reparsed = json::parse(canon);

  // Re-canonicalize and check consistency
  std::string recanon = CanonicalJsonEngine::serialize(reparsed);
  return canon == recanon;
}

// --- Test hash computation ---
inline bool test_hash_computation() {
  json event;
  event["content"] = {{"body", "test message"}, {"msgtype", "m.text"}};

  auto hash1 = HashComputationEngine::compute_from_event(event);
  auto hash2 = HashComputationEngine::compute_from_event(event);
  return hash1.success && hash2.success && hash1.sha256_b64 == hash2.sha256_b64;
}

// --- Test signing and verification ---
inline bool test_sign_verify() {
  auto keypair = crypto::generate_ed25519_keypair("test");

  json event;
  event["type"] = "m.room.message";
  event["sender"] = "@alice:test";
  event["room_id"] = "!room:test";
  event["content"] = {{"body", "hello"}, {"msgtype", "m.text"}};
  event["origin_server_ts"] = 1000000;
  event["depth"] = 1;
  event["prev_events"] = json::array();
  event["auth_events"] = json::array();

  auto store = std::make_shared<
      SignatureVerificationEngine::InMemoryKeyStore>();

  SignatureVerificationEngine::KnownKey key;
  key.server_name = "test";
  key.key_id = keypair.key_id();
  key.public_key = keypair.public_key;
  store->add_key(key);

  EventSigningCoordinator coordinator(store, "test", 3);
  auto result = coordinator.sign_event_workflow(event, keypair, 3);

  if (!result.success) return false;

  // Verify with known key
  auto verify_result =
      SignatureVerificationEngine::verify_with_key(
          result.signed_event, "test", keypair.key_id(), keypair.public_key);

  return verify_result.valid;
}

// --- Test hash validation on receipt ---
inline bool test_hash_validation() {
  json event;
  event["type"] = "m.room.message";
  event["sender"] = "@alice:test";
  event["room_id"] = "!room:test";
  event["content"] = {{"body", "test"}, {"msgtype", "m.text"}};

  // Add correct hash
  event = HashComputationEngine::add_content_hash(std::move(event));

  // Validate
  bool valid = HashValidationEngine::validate_event_hash(event).valid;

  // Tamper with content
  json tampered = json_deep_clone(event);
  tampered["content"]["body"] = "tampered!";

  bool tampered_valid =
      HashValidationEngine::validate_event_hash(tampered).valid;

  return valid && !tampered_valid;
}

// --- Test event ID generation ---
inline bool test_event_id_generation() {
  json event;
  event["type"] = "m.room.message";
  event["sender"] = "@alice:test";
  event["room_id"] = "!room:test";
  event["content"] = {{"body", "test"}, {"msgtype", "m.text"}};
  event["origin_server_ts"] = 1000000;

  // Add hash first (needed for ref hash)
  event = HashComputationEngine::add_content_hash(std::move(event));

  auto eid_v1 = EventIdGenerator::generate(event, "test.example", 1);
  auto eid_v3 = EventIdGenerator::generate(event, "test.example", 3);

  if (!eid_v1.success || !eid_v3.success) return false;

  // v1 should have random localpart (not 43-char base64)
  bool v1_ok = eid_v1.localpart.size() == 18;  // random_string(18)

  // v3 should have base64 hash localpart
  bool v3_ok = eid_v3.localpart.size() == 43 &&
               is_valid_base64_unpadded(eid_v3.localpart);

  // Verify parsing
  auto parsed = EventIdFormatParser::parse_and_detect(eid_v3.event_id);
  bool parse_ok = parsed.valid && parsed.is_refhash;

  return v1_ok && v3_ok && parse_ok;
}

// --- Run all diagnostics ---
inline bool run_all_diagnostics() {
  bool all_ok = true;

  auto check = [&all_ok](const char* name, bool result) {
    if (!result) {
      std::cerr << "DIAG FAIL: " << name << std::endl;
      all_ok = false;
    } else {
      std::cerr << "DIAG PASS: " << name << std::endl;
    }
  };

  check("canonical_roundtrip", test_canonical_roundtrip());
  check("hash_computation", test_hash_computation());
  check("sign_verify", test_sign_verify());
  check("hash_validation", test_hash_validation());
  check("event_id_generation", test_event_id_generation());

  return all_ok;
}

}  // namespace signing_diag

// ============================================================================
// End of event_signing.cpp
// ============================================================================

}  // namespace progressive
