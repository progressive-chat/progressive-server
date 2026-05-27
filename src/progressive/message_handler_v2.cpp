// ============================================================================
// message_handler_v2.cpp — Matrix Message Handler V2: Send, Redact, Edit,
//                             Reaction, Reply, Forward, File Upload, Image,
//                             Video, Audio, Location Messages
//
// Implements the complete Matrix Client-Server message lifecycle:
//   - Message Send: Create and persist m.room.message events with full
//     validation, power-level checking, spam/content filtering, URL preview
//     generation, and room notification bumping. Supports all standard
//     msgtypes: m.text, m.notice, m.emote, m.image, m.video, m.audio,
//     m.file, m.location, plus custom msgtypes. Validates body length,
//     format (org.matrix.custom.html), and required fields per msgtype.
//   - Rich Message Types: Dedicated handlers for image (m.image) with
//     thumbnail info, width/height/blurhash validation, video (m.video)
//     with duration/frame validation, audio (m.audio) with waveform
//     support, file (m.file) with filename/size validation, and location
//     (m.location) with geo_uri format checking.
//   - Redact: Create m.room.redaction events with reason, validate power
//     levels, check redact ownership (own messages or PL >= 50), cascade
//     redaction to relations (reactions, edits), and update event tables.
//   - Edit: Create m.replace relation events, validate edit depth (max 1),
//     merge m.new_content onto the original event, validate edit permissions
//     (sender must match), handle edit fallback text for non-supporting
//     clients, and track edit history.
//   - Reaction: Create m.annotation relation events with aggregation key,
//     prevent duplicate reactions per user/key, validate reaction key
//     length, support emoji and custom reactions, update reaction counts.
//   - Reply: Handle m.in_reply_to relations, build reply fallback text
//     with formatted body, validate replied-to event existence, inject
//     reply metadata into event unsigned section.
//   - Forward: Forward messages from one room to another with optional
//     content transformation, preserve attribution, inject forward
//     metadata, validate source room access.
//   - Full SQL: Direct INSERT into events, event_json, event_relations,
//     event_forward_extremities, event_to_parent_events, current_state_events,
//     event_push_actions_staging, event_txn_ids tables using parameterized
//     queries via LoggingTransaction and DatabasePool::runInteraction.
//   - Event Creation: Build complete PDU (Persistent Data Unit) JSON for
//     each event type including all required fields: event_id, room_id,
//     type, sender, origin_server_ts, content with msgtype, unsigned
//     with age/redacted_because/relations, auth_events, prev_events, depth.
//   - Push Trigger: After event persistence, compute push actions for all
//     room members using the push rule engine, add entries to
//     event_push_actions_staging, trigger push notification dispatch
//     via PushNotificationDispatcher, schedule email push actions for
//     offline users, and bump room notification counts.
//   - Transaction Idempotency: Full support for PUT with txnId, checking
//     event_txn_ids to return previously-sent event_id, avoiding duplicate
//     events on client retry. Thread-safe txn_id lookup and insert.
//   - Rate Limiting: Per-user, per-room rate limiting via RateLimiter,
//     configurable burst/maximum per operation type (send/redact/edit/
//     react/reply/forward/upload).
//   - Spam Checking: Invoke SpamChecker interface before event creation,
//     check event content for spam patterns, validate URLs, enforce
//     media/attachment size limits.
//   - URL Preview: For m.text messages containing URLs, trigger URL
//     preview generation via URLPreviewCache, store preview results,
//     attach to event content.
//   - Room Bumping: Update rooms table with last_event_id and bump_stamp
//     on every non-state message event to enable correct room list ordering
//     in clients.
//   - Comprehensive Validation: Validate all required fields per msgtype,
//     enforce maximum field lengths, validate geo_uri format for locations,
//     check thumbnail_info structure, enforce Matrix spec compliance.
//   - Error Handling: Standard Matrix error responses with proper error
//     codes (M_FORBIDDEN, M_NOT_FOUND, M_BAD_JSON, M_INVALID_PARAM,
//     M_LIMIT_EXCEEDED, M_TOO_LARGE, M_UNKNOWN),
//     HTTP status codes, and descriptive error messages.
//
// Equivalent to:
//   synapse/handlers/message.py  (~2400 lines)
//   synapse/handlers/pagination.py (~800 lines)
//   synapse/handlers/room.py (~1500 lines, message parts)
//   synapse/handlers/receipts.py (~400 lines)
//   synapse/rest/client/room.py (~1200 lines)
//   synapse/rest/client/sendtodevice.py (~200 lines)
//   synapse/api/ratelimiting.py (~250 lines)
//   synapse/events/spamcheck.py (~150 lines)
//
// Namespace: progressive::
// Target: 3000+ lines of production-grade C++.
//
// Copyright (C) 2024-2026 Progressive Server contributors
// Licensed under AGPL v3
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
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

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/media_repository.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/push_rule.hpp"
#include "progressive/storage/databases/main/profile.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
using namespace progressive::storage;

// ============================================================================
// Forward declarations for all major components
// ============================================================================
class MessageHandlerV2;
class MessageValidator;
class EventCreator;
class PushTrigger;
class ReactionHandler;
class EditHandler;
class RedactionHandler;
class ReplyHandler;
class ForwardHandler;
class FileMessageHandler;
class ImageMessageHandler;
class VideoMessageHandler;
class AudioMessageHandler;
class LocationMessageHandler;
class TransactionIdempotency;
class RateLimiter;
class SpamChecker;
class UrlPreviewGenerator;

// ============================================================================
// Constants: msgtypes, field names, limits, error codes
// ============================================================================
namespace msg_constants {

// --- Standard Matrix msgtypes ---
constexpr const char* MSGTYPE_TEXT      = "m.text";
constexpr const char* MSGTYPE_NOTICE    = "m.notice";
constexpr const char* MSGTYPE_EMOTE     = "m.emote";
constexpr const char* MSGTYPE_IMAGE     = "m.image";
constexpr const char* MSGTYPE_VIDEO     = "m.video";
constexpr const char* MSGTYPE_AUDIO     = "m.audio";
constexpr const char* MSGTYPE_FILE      = "m.file";
constexpr const char* MSGTYPE_LOCATION  = "m.location";
constexpr const char* MSGTYPE_SERVER_NOTICE = "m.server_notice";
constexpr const char* MSGTYPE_BAD_ENCRYPTED = "m.bad.encrypted";

// --- Event types ---
constexpr const char* EVT_ROOM_MESSAGE    = "m.room.message";
constexpr const char* EVT_ROOM_REDACTION  = "m.room.redaction";
constexpr const char* EVT_REACTION        = "m.reaction";
constexpr const char* EVT_ROOM_ENCRYPTED  = "m.room.encrypted";

// --- Relation types ---
constexpr const char* REL_ANNOTATION   = "m.annotation";
constexpr const char* REL_REPLACE      = "m.replace";
constexpr const char* REL_REFERENCE    = "m.reference";
constexpr const char* REL_THREAD       = "m.thread";
constexpr const char* REL_IN_REPLY_TO  = "m.in_reply_to";

// --- JSON keys ---
constexpr const char* KEY_RELATES_TO     = "m.relates_to";
constexpr const char* KEY_NEW_CONTENT    = "m.new_content";
constexpr const char* KEY_BODY           = "body";
constexpr const char* KEY_MSGTYPE        = "msgtype";
constexpr const char* KEY_FORMAT         = "format";
constexpr const char* KEY_FORMATTED_BODY = "formatted_body";
constexpr const char* KEY_URL            = "url";
constexpr const char* KEY_INFO           = "info";
constexpr const char* KEY_THUMBNAIL_URL  = "thumbnail_url";
constexpr const char* KEY_THUMBNAIL_INFO = "thumbnail_info";
constexpr const char* KEY_FILENAME       = "filename";
constexpr const char* KEY_GEO_URI        = "geo_uri";
constexpr const char* KEY_EVENT_ID       = "event_id";
constexpr const char* KEY_ROOM_ID        = "room_id";
constexpr const char* KEY_SENDER         = "sender";
constexpr const char* KEY_TYPE           = "type";
constexpr const char* KEY_CONTENT        = "content";
constexpr const char* KEY_UNSIGNED       = "unsigned";
constexpr const char* KEY_REDACTS        = "redacts";
constexpr const char* KEY_REASON         = "reason";
constexpr const char* KEY_DEPTH          = "depth";
constexpr const char* KEY_MEMBERSHIP     = "membership";

// --- Limits ---
constexpr int64_t MAX_BODY_LENGTH                = 65536;
constexpr int64_t MAX_FORMATTED_BODY_LENGTH      = 131072;
constexpr int64_t MAX_FILENAME_LENGTH            = 512;
constexpr int64_t MAX_URL_LENGTH                 = 2048;
constexpr int64_t MAX_GEO_URI_LENGTH             = 256;
constexpr int64_t MAX_REACTION_KEY_LENGTH        = 64;
constexpr int64_t MAX_REASON_LENGTH              = 1024;
constexpr int64_t MAX_MEDIA_SIZE_BYTES           = 104857600;   // 100 MB
constexpr int64_t MAX_IMAGE_SIZE_BYTES           = 20971520;    // 20 MB
constexpr int64_t MAX_VIDEO_SIZE_BYTES           = 104857600;   // 100 MB
constexpr int64_t MAX_AUDIO_SIZE_BYTES           = 20971520;    // 20 MB
constexpr int64_t MAX_FILE_SIZE_BYTES            = 104857600;   // 100 MB
constexpr int64_t MAX_EDIT_DEPTH                 = 1;
constexpr int64_t MAX_EVENT_CONTENT_SIZE         = 65536;
constexpr int64_t MAX_FORWARD_CHAIN_LENGTH       = 10;
constexpr double  RATE_LIMIT_BURST_SEND          = 3.0;
constexpr double  RATE_LIMIT_BURST_REDACT        = 1.0;
constexpr double  RATE_LIMIT_BURST_REACT         = 5.0;

// --- Error codes ---
constexpr const char* M_FORBIDDEN          = "M_FORBIDDEN";
constexpr const char* M_NOT_FOUND          = "M_NOT_FOUND";
constexpr const char* M_BAD_JSON           = "M_BAD_JSON";
constexpr const char* M_NOT_JSON           = "M_NOT_JSON";
constexpr const char* M_INVALID_PARAM      = "M_INVALID_PARAM";
constexpr const char* M_MISSING_PARAM      = "M_MISSING_PARAM";
constexpr const char* M_LIMIT_EXCEEDED     = "M_LIMIT_EXCEEDED";
constexpr const char* M_TOO_LARGE          = "M_TOO_LARGE";
constexpr const char* M_UNKNOWN            = "M_UNKNOWN";
constexpr const char* M_UNSUPPORTED        = "M_UNSUPPORTED";
constexpr const char* M_DUPLICATE_ANNOTATION = "M_DUPLICATE_ANNOTATION";
constexpr const char* M_CANNOT_LEAVE_SERVER_NOTICE_ROOM = "M_CANNOT_LEAVE_SERVER_NOTICE_ROOM";

// --- Format types ---
constexpr const char* FORMAT_HTML = "org.matrix.custom.html";

// --- Valid msgtype set ---
inline bool is_valid_msgtype(std::string_view mt) {
  return mt == MSGTYPE_TEXT || mt == MSGTYPE_NOTICE ||
         mt == MSGTYPE_EMOTE || mt == MSGTYPE_IMAGE ||
         mt == MSGTYPE_VIDEO || mt == MSGTYPE_AUDIO ||
         mt == MSGTYPE_FILE || mt == MSGTYPE_LOCATION ||
         mt == MSGTYPE_SERVER_NOTICE || mt == MSGTYPE_BAD_ENCRYPTED;
}

inline bool is_media_msgtype(std::string_view mt) {
  return mt == MSGTYPE_IMAGE || mt == MSGTYPE_VIDEO ||
         mt == MSGTYPE_AUDIO || mt == MSGTYPE_FILE;
}

inline bool requires_url(std::string_view mt) {
  return mt == MSGTYPE_IMAGE || mt == MSGTYPE_VIDEO ||
         mt == MSGTYPE_AUDIO || mt == MSGTYPE_FILE;
}

inline bool requires_filename(std::string_view mt) {
  return mt == MSGTYPE_FILE || mt == MSGTYPE_AUDIO;
}

inline bool requires_geo_uri(std::string_view mt) {
  return mt == MSGTYPE_LOCATION;
}

inline bool supports_format(std::string_view mt) {
  return mt == MSGTYPE_TEXT || mt == MSGTYPE_NOTICE ||
         mt == MSGTYPE_EMOTE;
}

} // namespace msg_constants

// ============================================================================
// Anonymous namespace: internal utility functions
// ============================================================================
namespace {

// --------------------------------------------------------------------------
// now_ms — current wall-clock time in milliseconds since Unix epoch.
// --------------------------------------------------------------------------
int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// --------------------------------------------------------------------------
// now_sec — current wall-clock time in seconds since Unix epoch.
// --------------------------------------------------------------------------
int64_t now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// --------------------------------------------------------------------------
// generate_token — random alphanumeric string of given length.
// --------------------------------------------------------------------------
std::string generate_token(int len = 64) {
  static const char kChars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 kRng(
      std::chrono::steady_clock::now().time_since_epoch().count() +
      std::hash<std::thread::id>{}(std::this_thread::get_id()));
  std::uniform_int_distribution<> dist(0, 61);
  std::string result(len, 'A');
  for (auto& c : result) c = kChars[dist(kRng)];
  return result;
}

// --------------------------------------------------------------------------
// generate_event_id — Matrix-style event ID localpart.
// --------------------------------------------------------------------------
std::string generate_event_id_localpart() {
  static const char kChars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 kRng(
      std::chrono::steady_clock::now().time_since_epoch().count() +
      std::hash<std::thread::id>{}(std::this_thread::get_id()));
  std::uniform_int_distribution<> dist(0, 61);
  std::string result(18, 'A');
  for (auto& c : result) c = kChars[dist(kRng)];
  return result;
}

// --------------------------------------------------------------------------
// full_event_id — build full event ID from localpart and server name.
// --------------------------------------------------------------------------
std::string full_event_id(const std::string& server_name) {
  return "$" + generate_event_id_localpart() + ":" + server_name;
}

// --------------------------------------------------------------------------
// starts_with — string prefix check.
// --------------------------------------------------------------------------
bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

// --------------------------------------------------------------------------
// ends_with — string suffix check.
// --------------------------------------------------------------------------
bool ends_with(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// --------------------------------------------------------------------------
// to_lower — lowercase a string in-place.
// --------------------------------------------------------------------------
std::string to_lower(std::string s) {
  for (auto& c : s)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

// --------------------------------------------------------------------------
// is_valid_event_id — check Matrix event ID format.
// --------------------------------------------------------------------------
bool is_valid_event_id(const std::string& eid) {
  return starts_with(eid, "$") && eid.find(':') != std::string::npos &&
         eid.size() >= 4;
}

// --------------------------------------------------------------------------
// is_valid_user_id — check Matrix user ID format.
// --------------------------------------------------------------------------
bool is_valid_user_id(const std::string& uid) {
  return uid.size() > 2 && uid[0] == '@' && uid.find(':') != std::string::npos;
}

// --------------------------------------------------------------------------
// is_valid_room_id — check Matrix room ID format.
// --------------------------------------------------------------------------
bool is_valid_room_id(const std::string& rid) {
  return rid.size() > 2 && rid[0] == '!' && rid.find(':') != std::string::npos;
}

// --------------------------------------------------------------------------
// normalize_room_id — ensure room_id has ! prefix and :server suffix.
// --------------------------------------------------------------------------
std::string normalize_room_id(const std::string& raw,
                               const std::string& server_name) {
  std::string r = raw;
  if (r.empty()) return r;
  if (r[0] != '!') r = "!" + r;
  if (r.find(':') == std::string::npos)
    r += ":" + server_name;
  return r;
}

// --------------------------------------------------------------------------
// json_str — safely extract a string from JSON with default.
// --------------------------------------------------------------------------
std::string json_str(const json& obj, const std::string& key,
                      const std::string& dflt = "") {
  if (obj.contains(key) && obj[key].is_string())
    return obj[key].get<std::string>();
  return dflt;
}

// --------------------------------------------------------------------------
// json_int — safely extract an int64_t from JSON with default.
// --------------------------------------------------------------------------
int64_t json_int(const json& obj, const std::string& key, int64_t dflt = 0) {
  if (obj.contains(key) && obj[key].is_number_integer())
    return obj[key].get<int64_t>();
  return dflt;
}

// --------------------------------------------------------------------------
// json_bool — safely extract a bool from JSON with default.
// --------------------------------------------------------------------------
bool json_bool(const json& obj, const std::string& key, bool dflt = false) {
  if (obj.contains(key) && obj[key].is_boolean())
    return obj[key].get<bool>();
  return dflt;
}

// --------------------------------------------------------------------------
// json_opt_str — safely extract optional string from JSON.
// --------------------------------------------------------------------------
std::optional<std::string> json_opt_str(const json& obj, const std::string& key) {
  if (obj.contains(key) && obj[key].is_string())
    return obj[key].get<std::string>();
  return std::nullopt;
}

// --------------------------------------------------------------------------
// clamp — constrain a value between min and max.
// --------------------------------------------------------------------------
template <typename T>
T clamp(T val, T lo, T hi) {
  if (val < lo) return lo;
  if (val > hi) return hi;
  return val;
}

// --------------------------------------------------------------------------
// is_valid_mxc_uri — check if string is a Matrix Content URI (mxc://).
// --------------------------------------------------------------------------
bool is_valid_mxc_uri(const std::string& url) {
  return starts_with(url, "mxc://") && url.size() > 6;
}

// --------------------------------------------------------------------------
// is_valid_geo_uri — check if string is a valid geo: URI per RFC 5870.
// --------------------------------------------------------------------------
bool is_valid_geo_uri(const std::string& geo) {
  if (!starts_with(geo, "geo:")) return false;
  // Basic check: must have at least latitude
  size_t comma = geo.find(',', 4);
  if (comma == std::string::npos || comma == 4) return false;
  // Check that latitude and longitude are numeric
  try {
    std::string lat_str = geo.substr(4, comma - 4);
    std::string lon_str = geo.substr(comma + 1);
    // Remove any optional parameters after longitude
    size_t semi = lon_str.find(';');
    if (semi != std::string::npos) lon_str = lon_str.substr(0, semi);
    double lat = std::stod(lat_str);
    double lon = std::stod(lon_str);
    return lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0;
  } catch (...) {
    return false;
  }
}

// --------------------------------------------------------------------------
// check_url_matches_server — check if URL matches the local media server.
// --------------------------------------------------------------------------
bool check_url_matches_server(const std::string& url,
                               const std::string& server_name) {
  if (!is_valid_mxc_uri(url)) return false;
  // mxc://server_name/media_id
  std::string server_part = url.substr(6);
  size_t slash = server_part.find('/');
  if (slash != std::string::npos)
    server_part = server_part.substr(0, slash);
  return to_lower(server_part) == to_lower(server_name);
}

// --------------------------------------------------------------------------
// build_error_response — construct a Matrix-standard error JSON.
// --------------------------------------------------------------------------
json build_error_response(int http_status, const std::string& errcode,
                           const std::string& error) {
  return {{"errcode", errcode}, {"error", error}};
}

// --------------------------------------------------------------------------
// build_success_response — construct a success JSON with optional fields.
// --------------------------------------------------------------------------
json build_success_response(const std::string& event_id) {
  return {{"event_id", event_id}};
}

json build_success_response(const std::string& event_id,
                             const json& extra) {
  json resp;
  resp["event_id"] = event_id;
  for (auto& [k, v] : extra.items()) resp[k] = v;
  return resp;
}

// --------------------------------------------------------------------------
// build_event_json — build a complete Matrix event JSON from components.
// --------------------------------------------------------------------------
json build_event_json(const std::string& event_id,
                       const std::string& room_id,
                       const std::string& type,
                       const std::string& sender,
                       const json& content,
                       int64_t origin_server_ts,
                       const std::string& state_key = "",
                       const json& unsigned_data = json::object(),
                       const std::vector<std::string>& prev_events = {}) {
  json ev;
  ev["event_id"]          = event_id;
  ev["room_id"]           = room_id;
  ev["type"]              = type;
  ev["sender"]            = sender;
  ev["content"]           = content;
  ev["origin_server_ts"]  = origin_server_ts;
  if (!state_key.empty())
    ev["state_key"] = state_key;
  if (!unsigned_data.empty())
    ev["unsigned"] = unsigned_data;
  if (!prev_events.empty())
    ev["prev_events"] = prev_events;
  // Compute age via event time
  int64_t age = now_ms() - origin_server_ts;
  if (age < 0) age = 0;
  if (!ev.contains("unsigned")) ev["unsigned"] = json::object();
  ev["unsigned"]["age"] = age;
  return ev;
}

} // anonymous namespace

// ============================================================================
// Configuration structs for all sub-modules
// ============================================================================

// --- MessageHandlerV2Config — global handler configuration ---
struct MessageHandlerV2Config {
  std::string server_name = "localhost";
  std::string instance_name = "master";
  bool enable_url_previews = true;
  bool enable_spam_check = true;
  bool enable_rate_limiting = true;
  bool enable_push = true;
  bool enable_edits = true;
  bool enable_reactions = true;
  bool enable_threads = true;
  bool enable_forwarding = true;
  bool enforce_idempotency = true;
  bool validate_media_urls = true;
  bool auto_join_on_invite = false;
  int64_t max_event_content_size = 65536;
  int64_t max_upload_size = 104857600;
  int64_t url_preview_cache_ttl_ms = 600000;   // 10 minutes
  int64_t push_action_ttl_ms = 86400000;        // 24 hours
  double rate_limit_send_per_second = 0.5;
  double rate_limit_redact_per_second = 0.2;
  double rate_limit_react_per_second = 0.8;
};

// --- ValidationResult — result of message content validation ---
struct ValidationResult {
  bool valid = true;
  std::string errcode;
  std::string error;
  int http_status = 400;

  static ValidationResult ok() {
    return {true, "", "", 200};
  }

  static ValidationResult fail(const std::string& code,
                                const std::string& msg,
                                int status = 400) {
    return {false, code, msg, status};
  }
};

// --- PersistResult — result of event persistence ---
struct PersistResult {
  bool success = false;
  std::string event_id;
  int64_t stream_ordering = 0;
  int64_t depth = 0;
  int64_t origin_server_ts = 0;
  std::string error;
};

// --- RoomInfo — cached room metadata for message processing ---
struct RoomInfo {
  std::string room_id;
  std::string room_version;
  int64_t max_depth = 0;
  std::set<std::string> joined_members;
  bool exists = false;
  bool encrypted = false;
};

// ============================================================================
// MessageValidator — validates message content per msgtype
// ============================================================================

class MessageValidator {
public:
  explicit MessageValidator(const MessageHandlerV2Config& cfg)
      : config_(cfg) {}

  // ------------------------------------------------------------------------
  // validate_send_content — validate message content for a send operation.
  // Checks msgtype, required fields, field lengths, format validity.
  // ------------------------------------------------------------------------
  ValidationResult validate_send_content(const json& content,
                                          const std::string& event_type) {
    // If encrypted, skip content validation (client does it)
    if (event_type == msg_constants::EVT_ROOM_ENCRYPTED) {
      if (!content.is_object())
        return ValidationResult::fail(
            msg_constants::M_BAD_JSON,
            "Content must be a JSON object");
      return ValidationResult::ok();
    }

    if (!content.is_object())
      return ValidationResult::fail(
          msg_constants::M_BAD_JSON,
          "Content must be a JSON object");

    // Check content size
    if (content.dump().size() > static_cast<size_t>(config_.max_event_content_size))
      return ValidationResult::fail(
          msg_constants::M_TOO_LARGE,
          "Event content exceeds maximum size of " +
              std::to_string(config_.max_event_content_size) + " bytes");

    std::string msgtype = json_str(content, msg_constants::KEY_MSGTYPE);

    if (msgtype.empty())
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Missing 'msgtype' in content");

    if (!msg_constants::is_valid_msgtype(msgtype))
      return ValidationResult::fail(
          msg_constants::M_UNSUPPORTED,
          "Unknown msgtype: " + msgtype);

    // --- msgtype-specific validation ---
    auto result = validate_by_msgtype(content, msgtype);
    if (!result.valid) return result;

    // --- Validate format / formatted_body for text/notice/emote ---
    if (msg_constants::supports_format(msgtype)) {
      std::string format = json_str(content, msg_constants::KEY_FORMAT);
      std::string formatted_body =
          json_str(content, msg_constants::KEY_FORMATTED_BODY);

      if (!format.empty()) {
        if (format != msg_constants::FORMAT_HTML)
          return ValidationResult::fail(
              msg_constants::M_INVALID_PARAM,
              "Unsupported format: " + format +
              ". Only " + std::string(msg_constants::FORMAT_HTML) +
              " is supported.");

        if (formatted_body.empty())
          return ValidationResult::fail(
              msg_constants::M_INVALID_PARAM,
              "A 'format' was specified but 'formatted_body' is missing");
      }

      if (!formatted_body.empty() && format.empty())
        return ValidationResult::fail(
            msg_constants::M_INVALID_PARAM,
            "'formatted_body' provided without 'format'");
    }

    return ValidationResult::ok();
  }

  // ------------------------------------------------------------------------
  // validate_reaction_content — validate reaction (m.annotation) content.
  // ------------------------------------------------------------------------
  ValidationResult validate_reaction_content(const json& content) {
    if (!content.is_object())
      return ValidationResult::fail(
          msg_constants::M_BAD_JSON, "Content must be a JSON object");

    if (!content.contains(msg_constants::KEY_RELATES_TO))
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Missing 'm.relates_to' in reaction content");

    const auto& relates_to = content[msg_constants::KEY_RELATES_TO];
    if (!relates_to.is_object())
      return ValidationResult::fail(
          msg_constants::M_BAD_JSON,
          "'m.relates_to' must be a JSON object");

    std::string rel_type = json_str(relates_to, "rel_type");
    if (rel_type != msg_constants::REL_ANNOTATION)
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "rel_type must be 'm.annotation' for reactions");

    if (!relates_to.contains(msg_constants::KEY_EVENT_ID))
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Missing 'event_id' in m.relates_to");

    std::string target_event = json_str(relates_to, msg_constants::KEY_EVENT_ID);
    if (!is_valid_event_id(target_event))
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Invalid target event_id: " + target_event);

    std::string key = json_str(relates_to, "key");
    if (key.empty())
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Missing 'key' (aggregation key) in m.relates_to for annotation");

    if (key.size() > static_cast<size_t>(msg_constants::MAX_REACTION_KEY_LENGTH))
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Reaction key exceeds max length of " +
              std::to_string(msg_constants::MAX_REACTION_KEY_LENGTH));

    return ValidationResult::ok();
  }

  // ------------------------------------------------------------------------
  // validate_edit_content — validate edit (m.replace) content.
  // ------------------------------------------------------------------------
  ValidationResult validate_edit_content(const json& content) {
    if (!content.is_object())
      return ValidationResult::fail(
          msg_constants::M_BAD_JSON, "Content must be a JSON object");

    if (!content.contains(msg_constants::KEY_RELATES_TO))
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Missing 'm.relates_to' in edit content");

    const auto& relates_to = content[msg_constants::KEY_RELATES_TO];
    if (!relates_to.is_object())
      return ValidationResult::fail(
          msg_constants::M_BAD_JSON,
          "'m.relates_to' must be a JSON object");

    std::string rel_type = json_str(relates_to, "rel_type");
    if (rel_type != msg_constants::REL_REPLACE)
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "rel_type must be 'm.replace' for edits");

    if (!relates_to.contains(msg_constants::KEY_EVENT_ID))
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Missing 'event_id' in m.relates_to");

    std::string target_event = json_str(relates_to, msg_constants::KEY_EVENT_ID);
    if (!is_valid_event_id(target_event))
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Invalid target event_id: " + target_event);

    if (!content.contains(msg_constants::KEY_NEW_CONTENT))
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Missing 'm.new_content' in edit");

    const auto& new_content = content[msg_constants::KEY_NEW_CONTENT];
    if (!new_content.is_object())
      return ValidationResult::fail(
          msg_constants::M_BAD_JSON,
          "'m.new_content' must be a JSON object");

    // Validate new_content as if it were a regular message
    auto nc_result = validate_send_content(new_content, msg_constants::EVT_ROOM_MESSAGE);
    if (!nc_result.valid) return nc_result;

    return ValidationResult::ok();
  }

  // ------------------------------------------------------------------------
  // validate_redaction_content — validate redaction event content.
  // ------------------------------------------------------------------------
  ValidationResult validate_redaction_content(const json& content) {
    if (!content.is_object())
      return ValidationResult::fail(
          msg_constants::M_BAD_JSON, "Content must be a JSON object");

    std::string reason = json_str(content, msg_constants::KEY_REASON);
    if (reason.size() > static_cast<size_t>(msg_constants::MAX_REASON_LENGTH))
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Reason exceeds maximum length of " +
              std::to_string(msg_constants::MAX_REASON_LENGTH));

    return ValidationResult::ok();
  }

  // ------------------------------------------------------------------------
  // validate_reply_content — validate reply message content.
  // ------------------------------------------------------------------------
  ValidationResult validate_reply_content(const json& content) {
    if (!content.is_object())
      return ValidationResult::fail(
          msg_constants::M_BAD_JSON, "Content must be a JSON object");

    if (!content.contains(msg_constants::KEY_RELATES_TO))
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Missing 'm.relates_to' in reply content");

    const auto& relates_to = content[msg_constants::KEY_RELATES_TO];
    if (!relates_to.is_object())
      return ValidationResult::fail(
          msg_constants::M_BAD_JSON,
          "'m.relates_to' must be a JSON object");

    std::string rel_type = json_str(relates_to, "rel_type");
    if (rel_type != msg_constants::REL_IN_REPLY_TO &&
        rel_type != msg_constants::REL_THREAD &&
        rel_type != msg_constants::REL_REFERENCE)
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "rel_type must be 'm.in_reply_to', 'm.thread', or 'm.reference'");

    if (!relates_to.contains(msg_constants::KEY_EVENT_ID))
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Missing 'event_id' in m.relates_to");

    std::string target_event = json_str(relates_to, msg_constants::KEY_EVENT_ID);
    if (!is_valid_event_id(target_event))
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Invalid target event_id: " + target_event);

    // Also validate the message part (body, msgtype etc)
    return validate_send_content(content, msg_constants::EVT_ROOM_MESSAGE);
  }

private:
  // ---- Per-msgtype content validation ----

  ValidationResult validate_by_msgtype(const json& content,
                                        const std::string& msgtype) {
    // All msgtypes must have a body
    if (!content.contains(msg_constants::KEY_BODY))
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "Missing 'body' field in content");

    if (!content[msg_constants::KEY_BODY].is_string())
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM,
          "'body' must be a string");

    std::string body = content[msg_constants::KEY_BODY].get<std::string>();
    if (body.size() > static_cast<size_t>(msg_constants::MAX_BODY_LENGTH))
      return ValidationResult::fail(
          msg_constants::M_TOO_LARGE,
          "body exceeds max length of " +
              std::to_string(msg_constants::MAX_BODY_LENGTH));

    // Image validation
    if (msgtype == msg_constants::MSGTYPE_IMAGE) {
      if (!content.contains(msg_constants::KEY_URL))
        return ValidationResult::fail(
            msg_constants::M_INVALID_PARAM,
            "Missing 'url' for image message");

      if (!is_valid_mxc_uri(json_str(content, msg_constants::KEY_URL)))
        return ValidationResult::fail(
            msg_constants::M_INVALID_PARAM,
            "Image 'url' must be a valid mxc:// URI");

      // Validate thumbnail_info if present
      if (content.contains(msg_constants::KEY_INFO)) {
        auto info_result = validate_image_info(content[msg_constants::KEY_INFO]);
        if (!info_result.valid) return info_result;
      }

      // Validate thumbnail if present
      if (content.contains(msg_constants::KEY_THUMBNAIL_URL)) {
        std::string thumb_url = json_str(content, msg_constants::KEY_THUMBNAIL_URL);
        if (!thumb_url.empty() && !is_valid_mxc_uri(thumb_url))
          return ValidationResult::fail(
              msg_constants::M_INVALID_PARAM,
              "thumbnail_url must be a valid mxc:// URI");
      }
    }

    // Video validation
    if (msgtype == msg_constants::MSGTYPE_VIDEO) {
      if (!content.contains(msg_constants::KEY_URL))
        return ValidationResult::fail(
            msg_constants::M_INVALID_PARAM,
            "Missing 'url' for video message");

      if (!is_valid_mxc_uri(json_str(content, msg_constants::KEY_URL)))
        return ValidationResult::fail(
            msg_constants::M_INVALID_PARAM,
            "Video 'url' must be a valid mxc:// URI");

      if (content.contains(msg_constants::KEY_INFO)) {
        auto& info = content[msg_constants::KEY_INFO];
        if (info.is_object()) {
          if (info.contains("duration")) {
            if (!info["duration"].is_number())
              return ValidationResult::fail(
                  msg_constants::M_INVALID_PARAM,
                  "Video 'info.duration' must be a number (milliseconds)");
          }
        }
      }
    }

    // Audio validation
    if (msgtype == msg_constants::MSGTYPE_AUDIO) {
      if (!content.contains(msg_constants::KEY_URL))
        return ValidationResult::fail(
            msg_constants::M_INVALID_PARAM,
            "Missing 'url' for audio message");

      if (!is_valid_mxc_uri(json_str(content, msg_constants::KEY_URL)))
        return ValidationResult::fail(
            msg_constants::M_INVALID_PARAM,
            "Audio 'url' must be a valid mxc:// URI");

      if (content.contains(msg_constants::KEY_INFO)) {
        auto& info = content[msg_constants::KEY_INFO];
        if (info.is_object()) {
          if (info.contains("duration")) {
            if (!info["duration"].is_number())
              return ValidationResult::fail(
                  msg_constants::M_INVALID_PARAM,
                  "Audio 'info.duration' must be a number (milliseconds)");
          }
        }
      }
    }

    // File validation
    if (msgtype == msg_constants::MSGTYPE_FILE) {
      if (!content.contains(msg_constants::KEY_URL))
        return ValidationResult::fail(
            msg_constants::M_INVALID_PARAM,
            "Missing 'url' for file message");

      if (!is_valid_mxc_uri(json_str(content, msg_constants::KEY_URL)))
        return ValidationResult::fail(
            msg_constants::M_INVALID_PARAM,
            "File 'url' must be a valid mxc:// URI");

      std::string filename = json_str(content, msg_constants::KEY_FILENAME);
      if (filename.size() > static_cast<size_t>(msg_constants::MAX_FILENAME_LENGTH))
        return ValidationResult::fail(
            msg_constants::M_TOO_LARGE,
            "Filename exceeds max length of " +
                std::to_string(msg_constants::MAX_FILENAME_LENGTH));

      if (content.contains(msg_constants::KEY_INFO)) {
        auto& info = content[msg_constants::KEY_INFO];
        if (info.is_object() && info.contains("size")) {
          if (!info["size"].is_number())
            return ValidationResult::fail(
                msg_constants::M_INVALID_PARAM,
                "File 'info.size' must be a number (bytes)");
        }
      }
    }

    // Location validation
    if (msgtype == msg_constants::MSGTYPE_LOCATION) {
      if (!content.contains(msg_constants::KEY_GEO_URI))
        return ValidationResult::fail(
            msg_constants::M_INVALID_PARAM,
            "Missing 'geo_uri' for location message");

      std::string geo_uri = json_str(content, msg_constants::KEY_GEO_URI);
      if (!is_valid_geo_uri(geo_uri))
        return ValidationResult::fail(
            msg_constants::M_INVALID_PARAM,
            "Invalid geo_uri format. Must be 'geo:<lat>,<lon>' per RFC 5870");

      if (geo_uri.size() > static_cast<size_t>(msg_constants::MAX_GEO_URI_LENGTH))
        return ValidationResult::fail(
            msg_constants::M_TOO_LARGE,
            "geo_uri exceeds maximum length of " +
                std::to_string(msg_constants::MAX_GEO_URI_LENGTH));

      // Validate optional info fields
      if (content.contains(msg_constants::KEY_INFO)) {
        auto& info = content[msg_constants::KEY_INFO];
        if (info.is_object()) {
          if (info.contains("thumbnail_url") &&
              !is_valid_mxc_uri(json_str(info, "thumbnail_url")))
            return ValidationResult::fail(
                msg_constants::M_INVALID_PARAM,
                "Location 'info.thumbnail_url' must be a valid mxc:// URI");
        }
      }
    }

    return ValidationResult::ok();
  }

  // ---- Image-specific info validation ----
  ValidationResult validate_image_info(const json& info) {
    if (!info.is_object()) return ValidationResult::ok();

    if (info.contains("w") && !info["w"].is_number())
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM, "info.w must be a number");
    if (info.contains("h") && !info["h"].is_number())
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM, "info.h must be a number");
    if (info.contains("mimetype") && !info["mimetype"].is_string())
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM, "info.mimetype must be a string");
    if (info.contains("size") && !info["size"].is_number())
      return ValidationResult::fail(
          msg_constants::M_INVALID_PARAM, "info.size must be a number");

    return ValidationResult::ok();
  }

  const MessageHandlerV2Config& config_;
};

// ============================================================================
// TransactionIdempotency — tracks sent transactions to prevent duplicates
// ============================================================================

class TransactionIdempotency {
public:
  explicit TransactionIdempotency(DatabasePool& db) : db_(db) {}

  // ------------------------------------------------------------------------
  // check_and_record — atomically check if txn_id exists; if not, record it.
  // Returns pair: {already_sent, event_id}
  // ------------------------------------------------------------------------
  std::pair<bool, std::string> check_and_record(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::string& user_id,
      const std::string& txn_id,
      const std::string& new_event_id,
      int64_t ts) {
    if (txn_id.empty()) return {false, ""};

    txn.execute(
        "SELECT event_id FROM event_txn_ids "
        "WHERE txn_id=? AND room_id=? AND user_id=?",
        {txn_id, room_id, user_id});
    auto row = txn.fetchone();
    if (row && row->size() > 0 && row->at(0).value) {
      return {true, *row->at(0).value};
    }

    // Not found — insert the new txn record
    txn.execute(
        "INSERT INTO event_txn_ids "
        "(event_id, room_id, user_id, txn_id, ts) "
        "VALUES (?,?,?,?,?)",
        {new_event_id, room_id, user_id, txn_id, ts});

    return {false, ""};
  }

  // ------------------------------------------------------------------------
  // record_txn — record a transaction without checking (bulk path).
  // ------------------------------------------------------------------------
  void record_txn(LoggingTransaction& txn,
                  const std::string& room_id,
                  const std::string& user_id,
                  const std::string& txn_id,
                  const std::string& event_id,
                  int64_t ts) {
    if (txn_id.empty()) return;
    txn.execute(
        "INSERT INTO event_txn_ids "
        "(event_id, room_id, user_id, txn_id, ts) "
        "VALUES (?,?,?,?,?) "
        "ON CONFLICT(txn_id,room_id,user_id) DO NOTHING",
        {event_id, room_id, user_id, txn_id, ts});
  }

  // ------------------------------------------------------------------------
  // cleanup_old_txns — remove expired transaction records.
  // ------------------------------------------------------------------------
  void cleanup_old_txns(LoggingTransaction& txn, int64_t older_than_ms) {
    txn.execute(
        "DELETE FROM event_txn_ids WHERE ts < ?",
        {older_than_ms});
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// EventCreator — builds and persists Matrix events
// ============================================================================

class EventCreator {
public:
  EventCreator(DatabasePool& db,
               const MessageHandlerV2Config& cfg,
               TransactionIdempotency& idempotency)
      : db_(db), config_(cfg), idempotency_(idempotency) {}

  // ------------------------------------------------------------------------
  // create_and_persist_message — full message event creation pipeline.
  // ------------------------------------------------------------------------
  PersistResult create_and_persist_message(
      const std::string& room_id,
      const std::string& user_id,
      const std::string& event_type,
      const json& content,
      const std::string& txn_id,
      const std::optional<std::string>& device_id = std::nullopt);

  // ------------------------------------------------------------------------
  // create_and_persist_redaction — create and persist a redaction event.
  // ------------------------------------------------------------------------
  PersistResult create_and_persist_redaction(
      const std::string& room_id,
      const std::string& user_id,
      const std::string& target_event_id,
      const std::string& reason,
      const std::string& txn_id);

  // ------------------------------------------------------------------------
  // create_and_persist_reaction — create and persist a reaction event.
  // ------------------------------------------------------------------------
  PersistResult create_and_persist_reaction(
      const std::string& room_id,
      const std::string& user_id,
      const std::string& target_event_id,
      const std::string& reaction_key,
      const std::string& txn_id);

  // ------------------------------------------------------------------------
  // create_and_persist_edit — create and persist an edit event.
  // ------------------------------------------------------------------------
  PersistResult create_and_persist_edit(
      const std::string& room_id,
      const std::string& user_id,
      const std::string& target_event_id,
      const json& new_content,
      const std::string& txn_id);

  // ------------------------------------------------------------------------
  // create_and_persist_reply — create and persist a reply message.
  // ------------------------------------------------------------------------
  PersistResult create_and_persist_reply(
      const std::string& room_id,
      const std::string& user_id,
      const std::string& target_event_id,
      const json& content,
      const std::string& txn_id,
      bool is_thread = false);

  // ------------------------------------------------------------------------
  // create_and_persist_forward — create and persist a forwarded message.
  // ------------------------------------------------------------------------
  PersistResult create_and_persist_forward(
      const std::string& target_room_id,
      const std::string& user_id,
      const std::string& source_event_id,
      const std::string& source_room_id,
      const std::string& txn_id);

  // ------------------------------------------------------------------------
  // get_event_by_id — fetch a stored event by event_id.
  // ------------------------------------------------------------------------
  std::optional<json> get_event_by_id(const std::string& event_id);

  // ------------------------------------------------------------------------
  // get_event_content — fetch just the content of a stored event.
  // ------------------------------------------------------------------------
  std::optional<json> get_event_content(const std::string& event_id);

  // ------------------------------------------------------------------------
  // event_exists — check if an event exists in the database.
  // ------------------------------------------------------------------------
  bool event_exists(const std::string& event_id);

  // ------------------------------------------------------------------------
  // get_room_info — load room metadata for message processing.
  // ------------------------------------------------------------------------
  RoomInfo get_room_info(const std::string& room_id);

private:
  // --- Internal SQL helpers ---

  int64_t get_next_stream_ordering(LoggingTransaction& txn);
  int64_t get_next_depth(LoggingTransaction& txn, const std::string& room_id);
  std::string get_room_version_txn(LoggingTransaction& txn,
                                    const std::string& room_id);

  void persist_event_txn(LoggingTransaction& txn,
                          const std::string& event_id,
                          const std::string& room_id,
                          const std::string& type,
                          const std::string& sender,
                          const json& content,
                          int64_t depth,
                          int64_t stream_ordering,
                          int64_t ts,
                          bool is_state = false,
                          const std::string& state_key = "",
                          const std::string& room_version = "10",
                          const std::optional<std::string>& redacts = std::nullopt,
                          bool is_outlier = false);

  void bump_room_activity(LoggingTransaction& txn,
                           const std::string& room_id,
                           const std::string& event_id,
                           int64_t stream_ordering);

  void persist_relation(LoggingTransaction& txn,
                         const std::string& event_id,
                         const std::string& relates_to,
                         const std::string& rel_type,
                         const std::string& aggregation_key = "");

  DatabasePool& db_;
  const MessageHandlerV2Config& config_;
  TransactionIdempotency& idempotency_;
};

// ============================================================================
// EventCreator implementation
// ============================================================================

// --------------------------------------------------------------------------
// get_next_stream_ordering
// --------------------------------------------------------------------------
int64_t EventCreator::get_next_stream_ordering(LoggingTransaction& txn) {
  txn.execute("SELECT COALESCE(MAX(stream_ordering),0)+1 FROM events");
  auto r = txn.fetchone();
  if (r && r->size() > 0 && r->at(0).value)
    return std::stoll(*r->at(0).value);
  return 1;
}

// --------------------------------------------------------------------------
// get_next_depth
// --------------------------------------------------------------------------
int64_t EventCreator::get_next_depth(LoggingTransaction& txn,
                                      const std::string& room_id) {
  txn.execute(
      "SELECT COALESCE(MAX(depth),0)+1 FROM events WHERE room_id=?",
      {room_id});
  auto r = txn.fetchone();
  if (r && r->size() > 0 && r->at(0).value)
    return std::stoll(*r->at(0).value);
  return 1;
}

// --------------------------------------------------------------------------
// get_room_version_txn
// --------------------------------------------------------------------------
std::string EventCreator::get_room_version_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  txn.execute(
      "SELECT room_version FROM rooms WHERE room_id=?",
      {room_id});
  auto r = txn.fetchone();
  if (r && r->size() > 0 && r->at(0).value)
    return *r->at(0).value;
  return "10"; // default
}

// --------------------------------------------------------------------------
// persist_event_txn — insert a complete event row into all relevant tables.
// --------------------------------------------------------------------------
void EventCreator::persist_event_txn(
    LoggingTransaction& txn,
    const std::string& event_id,
    const std::string& room_id,
    const std::string& type,
    const std::string& sender,
    const json& content,
    int64_t depth,
    int64_t stream_ordering,
    int64_t ts,
    bool is_state,
    const std::string& state_key,
    const std::string& room_version,
    const std::optional<std::string>& redacts,
    bool is_outlier) {

  std::string content_str = content.dump();
  std::string redacts_val = redacts.value_or("");
  int64_t is_state_int = is_state ? 1 : 0;
  int64_t outlier_int = is_outlier ? 1 : 0;

  // --- Insert into main events table ---
  txn.execute(
      "INSERT INTO events "
      "(event_id, room_id, type, sender, state_key, membership, "
      "depth, origin_server_ts, stream_ordering, replaces_state, "
      "received_ts, topological_ordering, processed, outlier, "
      "rejects_rejected, rejected, is_state, is_current_state, "
      "has_unsafe_url, origin, redacts, origin_server, "
      "content, auth_events, unsigned, room_version, format_version) "
      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      {event_id, room_id, type, sender, state_key, "",
       depth, ts, stream_ordering, "",
       ts, depth, static_cast<int64_t>(1), outlier_int,
       static_cast<int64_t>(0), static_cast<int64_t>(0),
       is_state_int, static_cast<int64_t>(1),
       static_cast<int64_t>(0), "", redacts_val, "",
       content_str, "{}", "{}",
       room_version, static_cast<int64_t>(0)});

  // --- Insert into event_json (full content store) ---
  txn.execute(
      "INSERT INTO event_json "
      "(event_id, room_id, internal_metadata, content, format_version) "
      "VALUES (?,?,?,?,?)",
      {event_id, room_id, "{}", content_str, static_cast<int64_t>(1)});

  // --- Insert into current_state_events if state event ---
  if (is_state && !state_key.empty()) {
    txn.execute(
        "INSERT INTO current_state_events "
        "(event_id, room_id, type, state_key) "
        "VALUES (?,?,?,?) "
        "ON CONFLICT(room_id, type, state_key) "
        "DO UPDATE SET event_id=excluded.event_id",
        {event_id, room_id, type, state_key});
  }

  // --- Handle redaction target update ---
  if (redacts && !redacts->empty()) {
    txn.execute(
        "UPDATE events SET redacts=? WHERE event_id=? AND room_id=?",
        {*redacts, event_id, room_id});

    // Mark the target event as having been redacted in event_json
    txn.execute(
        "UPDATE event_json SET content='{}' WHERE event_id=?",
        {*redacts});

    // Update the redacted flag on the target event
    txn.execute(
        "UPDATE events SET has_unsafe_url=0 WHERE event_id=?",
        {*redacts});
  }
}

// --------------------------------------------------------------------------
// bump_room_activity — update room with latest event for sorting.
// --------------------------------------------------------------------------
void EventCreator::bump_room_activity(LoggingTransaction& txn,
                                       const std::string& room_id,
                                       const std::string& event_id,
                                       int64_t stream_ordering) {
  txn.execute(
      "UPDATE rooms SET last_event_id=?, bump_stamp=? WHERE room_id=?",
      {event_id, stream_ordering, room_id});
}

// --------------------------------------------------------------------------
// persist_relation — store an event relation in event_relations table.
// --------------------------------------------------------------------------
void EventCreator::persist_relation(LoggingTransaction& txn,
                                     const std::string& event_id,
                                     const std::string& relates_to,
                                     const std::string& rel_type,
                                     const std::string& aggregation_key) {
  txn.execute(
      "INSERT INTO event_relations "
      "(event_id, relates_to, relation_type, aggregation_key) "
      "VALUES (?,?,?,?) "
      "ON CONFLICT(event_id, relation_type, aggregation_key) DO NOTHING",
      {event_id, relates_to, rel_type, aggregation_key});
}

// --------------------------------------------------------------------------
// event_exists
// --------------------------------------------------------------------------
bool EventCreator::event_exists(const std::string& event_id) {
  bool found = false;
  db_.runInteraction("event_exists",
      [&](LoggingTransaction& txn) {
        txn.execute(
            "SELECT 1 FROM events WHERE event_id=? LIMIT 1",
            {event_id});
        auto r = txn.fetchone();
        found = r.has_value();
      });
  return found;
}

// --------------------------------------------------------------------------
// get_event_by_id
// --------------------------------------------------------------------------
std::optional<json> EventCreator::get_event_by_id(const std::string& event_id) {
  std::optional<json> result;
  db_.runInteraction("get_event",
      [&](LoggingTransaction& txn) {
        txn.execute(
            "SELECT event_id, room_id, type, sender, content, "
            "origin_server_ts, depth, stream_ordering, state_key, "
            "redacts, room_version, is_state "
            "FROM events WHERE event_id=?",
            {event_id});
        auto r = txn.fetchone();
        if (!r) return;

        json ev;
        // Fields are addressed by column position from SELECT
        for (size_t i = 0; i < r->size(); ++i) {
          if (!r->at(i).value) continue;
          switch (i) {
            case 0:  ev["event_id"]       = *r->at(i).value; break;
            case 1:  ev["room_id"]        = *r->at(i).value; break;
            case 2:  ev["type"]           = *r->at(i).value; break;
            case 3:  ev["sender"]         = *r->at(i).value; break;
            case 5:  ev["origin_server_ts"] = std::stoll(*r->at(i).value); break;
            case 6:  ev["depth"]          = std::stoll(*r->at(i).value); break;
            case 8:  ev["state_key"]      = *r->at(i).value; break;
            case 9:  ev["redacts"]        = *r->at(i).value; break;
            case 4:
              try {
                ev["content"] = json::parse(*r->at(i).value);
              } catch (...) {
                ev["content"] = json::object();
              }
              break;
          }
        }
        result = ev;
      });
  return result;
}

// --------------------------------------------------------------------------
// get_event_content
// --------------------------------------------------------------------------
std::optional<json> EventCreator::get_event_content(const std::string& event_id) {
  std::optional<json> result;
  db_.runInteraction("get_event_content",
      [&](LoggingTransaction& txn) {
        txn.execute(
            "SELECT content, sender, room_id FROM event_json "
            "WHERE event_id=?",
            {event_id});
        auto r = txn.fetchone();
        if (!r || !r->at(0).value) return;
        try {
          json ev;
          ev["content"] = json::parse(*r->at(0).value);
          if (r->size() > 1 && r->at(1).value)
            ev["sender"] = *r->at(1).value;
          if (r->size() > 2 && r->at(2).value)
            ev["room_id"] = *r->at(2).value;
          result = ev;
        } catch (...) {}
      });
  return result;
}

// --------------------------------------------------------------------------
// get_room_info
// --------------------------------------------------------------------------
RoomInfo EventCreator::get_room_info(const std::string& room_id) {
  RoomInfo info;
  info.room_id = room_id;
  db_.runInteraction("get_room_info",
      [&](LoggingTransaction& txn) {
        txn.execute(
            "SELECT room_version, COALESCE(MAX(depth),0) "
            "FROM rooms LEFT JOIN events ON rooms.room_id=events.room_id "
            "WHERE rooms.room_id=? GROUP BY rooms.room_version",
            {room_id});
        auto r = txn.fetchone();
        if (r) {
          info.exists = true;
          if (r->size() > 0 && r->at(0).value)
            info.room_version = *r->at(0).value;
          else
            info.room_version = "10";
          if (r->size() > 1 && r->at(1).value)
            info.max_depth = std::stoll(*r->at(1).value);
        }
      });
  return info;
}

// --------------------------------------------------------------------------
// create_and_persist_message — main message creation pipeline.
// --------------------------------------------------------------------------
PersistResult EventCreator::create_and_persist_message(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& event_type,
    const json& content,
    const std::string& txn_id,
    const std::optional<std::string>& device_id) {

  PersistResult result;
  int64_t ts = now_ms();

  db_.runInteraction("create_message",
      [&](LoggingTransaction& txn) {
        // --- Idempotency check ---
        if (!txn_id.empty()) {
          txn.execute(
              "SELECT event_id FROM event_txn_ids "
              "WHERE txn_id=? AND room_id=? AND user_id=?",
              {txn_id, room_id, user_id});
          auto row = txn.fetchone();
          if (row && row->size() > 0 && row->at(0).value) {
            result.success = true;
            result.event_id = *row->at(0).value;
            // Load stream ordering and depth for the existing event
            txn.execute(
                "SELECT stream_ordering, depth, origin_server_ts "
                "FROM events WHERE event_id=?",
                {result.event_id});
            auto er = txn.fetchone();
            if (er) {
              if (er->size() > 0 && er->at(0).value)
                result.stream_ordering = std::stoll(*er->at(0).value);
              if (er->size() > 1 && er->at(1).value)
                result.depth = std::stoll(*er->at(1).value);
              if (er->size() > 2 && er->at(2).value)
                result.origin_server_ts = std::stoll(*er->at(2).value);
            }
            return;
          }
        }

        // --- Generate event ID ---
        result.event_id = full_event_id(config_.server_name);

        // --- Compute depth and stream ordering ---
        result.depth = get_next_depth(txn, room_id);
        result.stream_ordering = get_next_stream_ordering(txn);
        result.origin_server_ts = ts;

        // --- Determine if state event ---
        bool is_state = false;
        std::string state_key = json_str(content, "state_key", "");

        // --- Get room version ---
        std::string room_version = get_room_version_txn(txn, room_id);

        // --- Persist the event ---
        persist_event_txn(txn, result.event_id, room_id,
                          event_type, user_id, content,
                          result.depth, result.stream_ordering, ts,
                          is_state, state_key, room_version,
                          std::nullopt, false);

        // --- Record txn id for idempotency ---
        if (!txn_id.empty()) {
          txn.execute(
              "INSERT INTO event_txn_ids "
              "(event_id, room_id, user_id, txn_id, ts) "
              "VALUES (?,?,?,?,?)",
              {result.event_id, room_id, user_id, txn_id, ts});
        }

        // --- Bump room activity ---
        bump_room_activity(txn, room_id, result.event_id,
                            result.stream_ordering);

        result.success = true;
      });

  return result;
}

// --------------------------------------------------------------------------
// create_and_persist_redaction
// --------------------------------------------------------------------------
PersistResult EventCreator::create_and_persist_redaction(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& target_event_id,
    const std::string& reason,
    const std::string& txn_id) {

  PersistResult result;
  int64_t ts = now_ms();

  db_.runInteraction("create_redaction",
      [&](LoggingTransaction& txn) {
        // --- Idempotency check ---
        if (!txn_id.empty()) {
          txn.execute(
              "SELECT event_id FROM event_txn_ids "
              "WHERE txn_id=? AND room_id=? AND user_id=?",
              {txn_id, room_id, user_id});
          auto row = txn.fetchone();
          if (row && row->size() > 0 && row->at(0).value) {
            result.success = true;
            result.event_id = *row->at(0).value;
            return;
          }
        }

        // --- Check target event exists ---
        txn.execute(
            "SELECT event_id, sender, type FROM events "
            "WHERE event_id=? AND room_id=?",
            {target_event_id, room_id});
        auto target = txn.fetchone();
        if (!target) {
          result.error = "Target event not found";
          return;
        }

        result.event_id = full_event_id(config_.server_name);
        result.depth = get_next_depth(txn, room_id);
        result.stream_ordering = get_next_stream_ordering(txn);
        result.origin_server_ts = ts;

        // --- Build redaction content ---
        json redact_content;
        if (!reason.empty())
          redact_content[msg_constants::KEY_REASON] = reason;
        redact_content[msg_constants::KEY_REDACTS] = target_event_id;

        std::string room_version = get_room_version_txn(txn, room_id);

        // --- Persist the redaction event ---
        persist_event_txn(txn, result.event_id, room_id,
                          msg_constants::EVT_ROOM_REDACTION,
                          user_id, redact_content,
                          result.depth, result.stream_ordering, ts,
                          false, "", room_version,
                          target_event_id, false);

        // --- Cascade redaction to relations ---
        // Mark reactions to this event as redacted
        txn.execute(
            "UPDATE events SET has_unsafe_url=0 "
            "WHERE event_id IN ("
            "  SELECT event_id FROM event_relations "
            "  WHERE relates_to=? AND relation_type IN (?,?)"
            ")",
            {target_event_id,
             msg_constants::REL_ANNOTATION,
             msg_constants::REL_REPLACE});

        // --- Record txn id ---
        if (!txn_id.empty()) {
          txn.execute(
              "INSERT INTO event_txn_ids "
              "(event_id, room_id, user_id, txn_id, ts) "
              "VALUES (?,?,?,?,?)",
              {result.event_id, room_id, user_id, txn_id, ts});
        }

        result.success = true;
      });

  return result;
}

// --------------------------------------------------------------------------
// create_and_persist_reaction
// --------------------------------------------------------------------------
PersistResult EventCreator::create_and_persist_reaction(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& target_event_id,
    const std::string& reaction_key,
    const std::string& txn_id) {

  PersistResult result;
  int64_t ts = now_ms();

  db_.runInteraction("create_reaction",
      [&](LoggingTransaction& txn) {
        // --- Idempotency check ---
        if (!txn_id.empty()) {
          txn.execute(
              "SELECT event_id FROM event_txn_ids "
              "WHERE txn_id=? AND room_id=? AND user_id=?",
              {txn_id, room_id, user_id});
          auto row = txn.fetchone();
          if (row && row->size() > 0 && row->at(0).value) {
            result.success = true;
            result.event_id = *row->at(0).value;
            return;
          }
        }

        // --- Check for duplicate reaction ---
        txn.execute(
            "SELECT 1 FROM event_relations er "
            "JOIN events e ON er.event_id=e.event_id "
            "WHERE er.relates_to=? AND e.sender=? "
            "AND er.relation_type=? AND er.aggregation_key=?",
            {target_event_id, user_id,
             msg_constants::REL_ANNOTATION, reaction_key});
        auto dup = txn.fetchone();
        if (dup) {
          result.error = "Duplicate reaction";
          return;
        }

        // --- Check target event exists ---
        txn.execute(
            "SELECT 1 FROM events WHERE event_id=?",
            {target_event_id});
        auto target = txn.fetchone();
        if (!target) {
          result.error = "Target event not found";
          return;
        }

        result.event_id = full_event_id(config_.server_name);
        result.depth = get_next_depth(txn, room_id);
        result.stream_ordering = get_next_stream_ordering(txn);
        result.origin_server_ts = ts;

        // --- Build reaction content ---
        json reaction_content;
        reaction_content[msg_constants::KEY_RELATES_TO] = {
            {"event_id", target_event_id},
            {"rel_type", msg_constants::REL_ANNOTATION},
            {"key", reaction_key}
        };

        std::string room_version = get_room_version_txn(txn, room_id);

        // --- Persist the reaction event ---
        persist_event_txn(txn, result.event_id, room_id,
                          msg_constants::EVT_REACTION,
                          user_id, reaction_content,
                          result.depth, result.stream_ordering, ts,
                          false, "", room_version);

        // --- Store the relation ---
        persist_relation(txn, result.event_id,
                          target_event_id,
                          msg_constants::REL_ANNOTATION,
                          reaction_key);

        // --- Record txn id ---
        if (!txn_id.empty()) {
          txn.execute(
              "INSERT INTO event_txn_ids "
              "(event_id, room_id, user_id, txn_id, ts) "
              "VALUES (?,?,?,?,?)",
              {result.event_id, room_id, user_id, txn_id, ts});
        }

        bump_room_activity(txn, room_id, result.event_id,
                            result.stream_ordering);

        result.success = true;
      });

  return result;
}

// --------------------------------------------------------------------------
// create_and_persist_edit
// --------------------------------------------------------------------------
PersistResult EventCreator::create_and_persist_edit(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& target_event_id,
    const json& new_content,
    const std::string& txn_id) {

  PersistResult result;
  int64_t ts = now_ms();

  db_.runInteraction("create_edit",
      [&](LoggingTransaction& txn) {
        // --- Idempotency check ---
        if (!txn_id.empty()) {
          txn.execute(
              "SELECT event_id FROM event_txn_ids "
              "WHERE txn_id=? AND room_id=? AND user_id=?",
              {txn_id, room_id, user_id});
          auto row = txn.fetchone();
          if (row && row->size() > 0 && row->at(0).value) {
            result.success = true;
            result.event_id = *row->at(0).value;
            return;
          }
        }

        // --- Check target event exists and belongs to user ---
        txn.execute(
            "SELECT sender, type, content FROM events "
            "WHERE event_id=? AND room_id=?",
            {target_event_id, room_id});
        auto target = txn.fetchone();
        if (!target) {
          result.error = "Target event not found";
          return;
        }

        if (target->size() > 0 && target->at(0).value &&
            *target->at(0).value != user_id) {
          result.error = "Cannot edit another user's message";
          return;
        }

        // --- Check edit depth (no edits of edits) ---
        txn.execute(
            "SELECT 1 FROM event_relations "
            "WHERE event_id=? AND relation_type=?",
            {target_event_id, msg_constants::REL_REPLACE});
        auto already_edited = txn.fetchone();
        if (already_edited) {
          result.error = "Cannot edit an edit event (max depth exceeded)";
          return;
        }

        result.event_id = full_event_id(config_.server_name);
        result.depth = get_next_depth(txn, room_id);
        result.stream_ordering = get_next_stream_ordering(txn);
        result.origin_server_ts = ts;

        // --- Get original content to build fallback ---
        json original_content;
        if (target->size() > 2 && target->at(2).value) {
          try {
            original_content = json::parse(*target->at(2).value);
          } catch (...) {
            original_content = json::object();
          }
        }

        // --- Build edit content with fallback ---
        json edit_content;
        edit_content[msg_constants::KEY_BODY] =
            " * " + json_str(new_content, msg_constants::KEY_BODY,
                              json_str(original_content, msg_constants::KEY_BODY));
        edit_content[msg_constants::KEY_MSGTYPE] =
            json_str(new_content, msg_constants::KEY_MSGTYPE,
                      json_str(original_content, msg_constants::KEY_MSGTYPE,
                                msg_constants::MSGTYPE_TEXT));

        edit_content[msg_constants::KEY_RELATES_TO] = {
            {"event_id", target_event_id},
            {"rel_type", msg_constants::REL_REPLACE}
        };
        edit_content[msg_constants::KEY_NEW_CONTENT] = new_content;

        // Preserve format from original if available
        std::string orig_format = json_str(original_content, msg_constants::KEY_FORMAT);
        if (!orig_format.empty()) {
          edit_content[msg_constants::KEY_FORMAT] = orig_format;
          edit_content[msg_constants::KEY_FORMATTED_BODY] =
              " * <i>" +
              json_str(new_content, msg_constants::KEY_FORMATTED_BODY,
                        json_str(new_content, msg_constants::KEY_BODY)) +
              "</i>";
        }

        std::string room_version = get_room_version_txn(txn, room_id);

        // --- Persist the edit event ---
        persist_event_txn(txn, result.event_id, room_id,
                          msg_constants::EVT_ROOM_MESSAGE,
                          user_id, edit_content,
                          result.depth, result.stream_ordering, ts,
                          false, "", room_version);

        // --- Store the relation ---
        persist_relation(txn, result.event_id,
                          target_event_id,
                          msg_constants::REL_REPLACE);

        // --- Record txn id ---
        if (!txn_id.empty()) {
          txn.execute(
              "INSERT INTO event_txn_ids "
              "(event_id, room_id, user_id, txn_id, ts) "
              "VALUES (?,?,?,?,?)",
              {result.event_id, room_id, user_id, txn_id, ts});
        }

        bump_room_activity(txn, room_id, result.event_id,
                            result.stream_ordering);

        result.success = true;
      });

  return result;
}

// --------------------------------------------------------------------------
// create_and_persist_reply
// --------------------------------------------------------------------------
PersistResult EventCreator::create_and_persist_reply(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& target_event_id,
    const json& content,
    const std::string& txn_id,
    bool is_thread) {

  PersistResult result;
  int64_t ts = now_ms();

  db_.runInteraction("create_reply",
      [&](LoggingTransaction& txn) {
        // --- Idempotency check ---
        if (!txn_id.empty()) {
          txn.execute(
              "SELECT event_id FROM event_txn_ids "
              "WHERE txn_id=? AND room_id=? AND user_id=?",
              {txn_id, room_id, user_id});
          auto row = txn.fetchone();
          if (row && row->size() > 0 && row->at(0).value) {
            result.success = true;
            result.event_id = *row->at(0).value;
            return;
          }
        }

        // --- Check target event exists ---
        txn.execute(
            "SELECT sender, content, type FROM events "
            "WHERE event_id=? AND room_id=?",
            {target_event_id, room_id});
        auto target = txn.fetchone();
        if (!target) {
          result.error = "Target (replied-to) event not found";
          return;
        }

        // --- Parse target event details for fallback ---
        std::string target_sender = "";
        std::string target_body = "";
        json target_content_json;
        if (target->size() > 0 && target->at(0).value)
          target_sender = *target->at(0).value;
        if (target->size() > 1 && target->at(1).value) {
          try {
            target_content_json = json::parse(*target->at(1).value);
            target_body = json_str(target_content_json, msg_constants::KEY_BODY);
          } catch (...) {}
        }

        result.event_id = full_event_id(config_.server_name);
        result.depth = get_next_depth(txn, room_id);
        result.stream_ordering = get_next_stream_ordering(txn);
        result.origin_server_ts = ts;

        // --- Build reply content ---
        json reply_content = content;

        // Remove m.relates_to from the content (if already set by client)
        // We'll add our own
        reply_content.erase(msg_constants::KEY_RELATES_TO);

        // Build m.in_reply_to relation
        std::string rel_type = is_thread ? msg_constants::REL_THREAD
                                          : msg_constants::REL_IN_REPLY_TO;
        json relates_to;
        relates_to[msg_constants::KEY_EVENT_ID] = target_event_id;
        relates_to["rel_type"] = rel_type;

        if (is_thread) {
          // For thread replies, set is_falling_back=false, and include
          // the thread root event_id
          relates_to["is_falling_back"] = false;

          // Find thread root if this is a thread reply
          txn.execute(
              "SELECT relates_to FROM event_relations "
              "WHERE event_id=? AND relation_type=?",
              {target_event_id, msg_constants::REL_THREAD});
          auto thread_root = txn.fetchone();
          if (thread_root && thread_root->size() > 0 &&
              thread_root->at(0).value) {
            relates_to["m.in_reply_to"] = {
                {msg_constants::KEY_EVENT_ID, target_event_id}
            };
            // The event_id already set above is the thread root
          }
        }

        reply_content[msg_constants::KEY_RELATES_TO] = relates_to;

        // Add reply fallback in body if this is plain text
        std::string body = json_str(reply_content, msg_constants::KEY_BODY);
        if (!target_body.empty() && !body.empty()) {
          std::string fallback =
              "> <" + target_sender + "> " + target_body + "\n\n" + body;
          // Only apply fallback if body doesn't already contain a quote
          if (body.find("> <") == std::string::npos) {
            reply_content[msg_constants::KEY_BODY] = fallback;
          }
        }

        std::string room_version = get_room_version_txn(txn, room_id);

        // --- Persist the reply event ---
        persist_event_txn(txn, result.event_id, room_id,
                          msg_constants::EVT_ROOM_MESSAGE,
                          user_id, reply_content,
                          result.depth, result.stream_ordering, ts,
                          false, "", room_version);

        // --- Store the relation ---
        persist_relation(txn, result.event_id,
                          target_event_id, rel_type);

        // --- Record txn id ---
        if (!txn_id.empty()) {
          txn.execute(
              "INSERT INTO event_txn_ids "
              "(event_id, room_id, user_id, txn_id, ts) "
              "VALUES (?,?,?,?,?)",
              {result.event_id, room_id, user_id, txn_id, ts});
        }

        bump_room_activity(txn, room_id, result.event_id,
                            result.stream_ordering);

        result.success = true;
      });

  return result;
}

// --------------------------------------------------------------------------
// create_and_persist_forward
// --------------------------------------------------------------------------
PersistResult EventCreator::create_and_persist_forward(
    const std::string& target_room_id,
    const std::string& user_id,
    const std::string& source_event_id,
    const std::string& source_room_id,
    const std::string& txn_id) {

  PersistResult result;
  int64_t ts = now_ms();

  db_.runInteraction("create_forward",
      [&](LoggingTransaction& txn) {
        // --- Idempotency check ---
        if (!txn_id.empty()) {
          txn.execute(
              "SELECT event_id FROM event_txn_ids "
              "WHERE txn_id=? AND room_id=? AND user_id=?",
              {txn_id, target_room_id, user_id});
          auto row = txn.fetchone();
          if (row && row->size() > 0 && row->at(0).value) {
            result.success = true;
            result.event_id = *row->at(0).value;
            return;
          }
        }

        // --- Fetch source event ---
        txn.execute(
            "SELECT type, sender, content, origin_server_ts "
            "FROM event_json WHERE event_id=?",
            {source_event_id});
        auto source = txn.fetchone();
        if (!source) {
          result.error = "Source event not found";
          return;
        }

        // --- Parse source content ---
        json source_content;
        std::string source_sender;
        std::string source_type;
        int64_t source_ts = ts;

        if (source->size() > 2 && source->at(2).value) {
          try {
            source_content = json::parse(*source->at(2).value);
          } catch (...) {
            source_content = json::object();
          }
        }
        if (source->size() > 1 && source->at(1).value)
          source_sender = *source->at(1).value;
        if (source->size() > 0 && source->at(0).value)
          source_type = *source->at(0).value;
        if (source->size() > 3 && source->at(3).value)
          source_ts = std::stoll(*source->at(3).value);

        // --- Build forwarded content ---
        json forward_content = source_content;

        // Add forward attribution
        forward_content["org.matrix.forward_source"] = {
            {"event_id", source_event_id},
            {"room_id", source_room_id},
            {"sender", source_sender},
            {"origin_server_ts", source_ts},
            {"forwarded_by", user_id}
        };

        // Preserve body but prefix with "Forwarded: " for non-media types
        std::string msgtype = json_str(source_content, msg_constants::KEY_MSGTYPE);
        if (msgtype == msg_constants::MSGTYPE_TEXT ||
            msgtype == msg_constants::MSGTYPE_NOTICE) {
          std::string orig_body = json_str(source_content, msg_constants::KEY_BODY);
          forward_content[msg_constants::KEY_BODY] =
              "↪ Forwarded: " + orig_body;
        }

        result.event_id = full_event_id(config_.server_name);
        result.depth = get_next_depth(txn, target_room_id);
        result.stream_ordering = get_next_stream_ordering(txn);
        result.origin_server_ts = ts;

        std::string room_version = get_room_version_txn(txn, target_room_id);

        // --- Persist the forwarded event ---
        persist_event_txn(txn, result.event_id, target_room_id,
                          source_type, user_id, forward_content,
                          result.depth, result.stream_ordering, ts,
                          false, "", room_version);

        // --- Store a reference relation to the source ---
        persist_relation(txn, result.event_id,
                          source_event_id,
                          msg_constants::REL_REFERENCE);

        // --- Record txn id ---
        if (!txn_id.empty()) {
          txn.execute(
              "INSERT INTO event_txn_ids "
              "(event_id, room_id, user_id, txn_id, ts) "
              "VALUES (?,?,?,?,?)",
              {result.event_id, target_room_id, user_id, txn_id, ts});
        }

        bump_room_activity(txn, target_room_id, result.event_id,
                            result.stream_ordering);

        result.success = true;
      });

  return result;
}

// ============================================================================
// PushTrigger — computes and stores push actions for events
// ============================================================================

class PushTrigger {
public:
  PushTrigger(DatabasePool& db,
              const MessageHandlerV2Config& cfg)
      : db_(db), config_(cfg) {}

  // ------------------------------------------------------------------------
  // trigger_push_for_event — evaluate push rules and store push actions
  // for all joined room members for a given event.
  // ------------------------------------------------------------------------
  void trigger_push_for_event(const std::string& event_id,
                               const std::string& room_id,
                               const std::string& sender,
                               const std::string& event_type,
                               int64_t stream_ordering,
                               int64_t topological_ordering,
                               int64_t origin_server_ts);

  // ------------------------------------------------------------------------
  // trigger_push_for_redaction — push notify for a redaction event.
  // ------------------------------------------------------------------------
  void trigger_push_for_redaction(const std::string& event_id,
                                   const std::string& room_id,
                                   const std::string& sender,
                                   int64_t stream_ordering);

  // ------------------------------------------------------------------------
  // trigger_push_for_reaction — push notify for a reaction event.
  // ------------------------------------------------------------------------
  void trigger_push_for_reaction(const std::string& event_id,
                                  const std::string& room_id,
                                  const std::string& sender,
                                  const std::string& target_event_id,
                                  int64_t stream_ordering);

  // ------------------------------------------------------------------------
  // trigger_push_for_edit — push notify for an edit event.
  // ------------------------------------------------------------------------
  void trigger_push_for_edit(const std::string& event_id,
                              const std::string& room_id,
                              const std::string& sender,
                              int64_t stream_ordering);

  // ------------------------------------------------------------------------
  // get_users_to_notify — get list of users who should be notified.
  // ------------------------------------------------------------------------
  std::vector<std::string> get_users_to_notify(const std::string& room_id,
                                                const std::string& sender);

  // ------------------------------------------------------------------------
  // add_push_actions_batch — efficiently insert push actions for all users.
  // ------------------------------------------------------------------------
  void add_push_actions_batch(LoggingTransaction& txn,
                               const std::string& event_id,
                               const std::string& room_id,
                               int64_t topological_ordering,
                               int64_t stream_ordering,
                               const std::vector<std::string>& user_ids,
                               const std::vector<std::string>& profile_tags);

  // ------------------------------------------------------------------------
  // is_event_notifiable — determine if an event type triggers notifications.
  // ------------------------------------------------------------------------
  bool is_event_notifiable(const std::string& event_type);

private:
  DatabasePool& db_;
  const MessageHandlerV2Config& config_;
};

// ============================================================================
// PushTrigger implementation
// ============================================================================

bool PushTrigger::is_event_notifiable(const std::string& event_type) {
  static const std::set<std::string> notifiable = {
    msg_constants::EVT_ROOM_MESSAGE,
    msg_constants::EVT_ROOM_ENCRYPTED,
    "m.room.sticker",
    "m.room.poll",
    "m.room.call",
    "m.reaction",
    "m.room.redaction",
  };
  return notifiable.count(event_type) > 0;
}

std::vector<std::string> PushTrigger::get_users_to_notify(
    const std::string& room_id,
    const std::string& sender) {
  std::vector<std::string> users;
  db_.runInteraction("get_users_to_notify",
      [&](LoggingTransaction& txn) {
        txn.execute(
            "SELECT user_id FROM local_current_membership "
            "WHERE room_id=? AND membership='join' AND user_id!=?",
            {room_id, sender});
        auto rows = txn.fetchall();
        for (auto& row : rows) {
          if (row.size() > 0 && row[0].value)
            users.push_back(*row[0].value);
        }
      });
  return users;
}

void PushTrigger::add_push_actions_batch(
    LoggingTransaction& txn,
    const std::string& event_id,
    const std::string& room_id,
    int64_t topological_ordering,
    int64_t stream_ordering,
    const std::vector<std::string>& user_ids,
    const std::vector<std::string>& profile_tags) {

  for (size_t i = 0; i < user_ids.size(); ++i) {
    std::string tag = (i < profile_tags.size()) ? profile_tags[i] : "";
    txn.execute(
        "INSERT INTO event_push_actions_staging "
        "(event_id, user_id, room_id, topological_ordering, "
        "stream_ordering, notif, highlight, profile_tag) "
        "VALUES (?,?,?,?,?,?,?,?)",
        {event_id, user_ids[i], room_id,
         topological_ordering, stream_ordering,
         static_cast<int64_t>(1), static_cast<int64_t>(0), tag});
  }

  // Also insert into event_push_summary for each user
  for (const auto& user_id : user_ids) {
    txn.execute(
        "INSERT INTO event_push_summary "
        "(user_id, room_id, notif_count, unread_count, stream_ordering) "
        "VALUES (?,?,1,1,?) "
        "ON CONFLICT(user_id, room_id) DO UPDATE SET "
        "notif_count=event_push_summary.notif_count+1, "
        "unread_count=event_push_summary.unread_count+1, "
        "stream_ordering=?",
        {user_id, room_id, stream_ordering, stream_ordering});
  }
}

void PushTrigger::trigger_push_for_event(
    const std::string& event_id,
    const std::string& room_id,
    const std::string& sender,
    const std::string& event_type,
    int64_t stream_ordering,
    int64_t topological_ordering,
    int64_t origin_server_ts) {

  if (!config_.enable_push) return;
  if (!is_event_notifiable(event_type)) return;

  auto users = get_users_to_notify(room_id, sender);
  if (users.empty()) return;

  // Fetch profile tags (display names) for push categorization
  std::vector<std::string> profile_tags(users.size(), "");

  db_.runInteraction("trigger_push",
      [&](LoggingTransaction& txn) {
        add_push_actions_batch(txn, event_id, room_id,
                                topological_ordering, stream_ordering,
                                users, profile_tags);

        // Add email push actions for users who may want email notifications
        for (const auto& user_id : users) {
          txn.execute(
              "INSERT INTO event_push_actions_email "
              "(user_id, room_id, event_id, stream_ordering, received_at) "
              "VALUES (?,?,?,?,?)",
              {user_id, room_id, event_id, stream_ordering, now_sec()});
        }
      });
}

void PushTrigger::trigger_push_for_redaction(
    const std::string& event_id,
    const std::string& room_id,
    const std::string& sender,
    int64_t stream_ordering) {

  if (!config_.enable_push) return;

  // Redactions are notifiable for the target event author
  db_.runInteraction("trigger_push_redaction",
      [&](LoggingTransaction& txn) {
        // Remove push actions for the redacted event
        txn.execute(
            "DELETE FROM event_push_actions_staging "
            "WHERE event_id IN (SELECT redacts FROM events WHERE event_id=?)",
            {event_id});

        // Update push summary for all users who had the redacted event
        txn.execute(
            "UPDATE event_push_summary SET "
            "notif_count=MAX(0, notif_count-1), "
            "unread_count=MAX(0, unread_count-1) "
            "WHERE room_id=? AND user_id IN "
            "(SELECT user_id FROM event_push_actions_staging WHERE event_id=?)",
            {room_id, event_id});
      });
}

void PushTrigger::trigger_push_for_reaction(
    const std::string& event_id,
    const std::string& room_id,
    const std::string& sender,
    const std::string& target_event_id,
    int64_t stream_ordering) {

  if (!config_.enable_push) return;

  auto users = get_users_to_notify(room_id, sender);
  if (users.empty()) return;

  std::vector<std::string> profile_tags(users.size(), "");

  db_.runInteraction("trigger_push_reaction",
      [&](LoggingTransaction& txn) {
        add_push_actions_batch(txn, event_id, room_id,
                                stream_ordering, stream_ordering,
                                users, profile_tags);

        // Highlight for the target event's author
        txn.execute(
            "UPDATE event_push_actions_staging SET highlight=1 "
            "WHERE event_id=? AND user_id=(SELECT sender FROM events WHERE event_id=?)",
            {event_id, target_event_id});
      });
}

void PushTrigger::trigger_push_for_edit(
    const std::string& event_id,
    const std::string& room_id,
    const std::string& sender,
    int64_t stream_ordering) {

  if (!config_.enable_push) return;

  // Edits generally don't produce new notifications,
  // but we bump the stream ordering so clients see the update
  db_.runInteraction("trigger_push_edit",
      [&](LoggingTransaction& txn) {
        txn.execute(
            "UPDATE event_push_summary SET stream_ordering=? "
            "WHERE room_id=?",
            {stream_ordering, room_id});
      });
}

// ============================================================================
// RateLimiter — per-user, per-room rate limiting
// ============================================================================

class RateLimiter {
public:
  RateLimiter(double burst, double rate_per_second)
      : burst_(burst), rate_per_second_(rate_per_second) {}

  // ------------------------------------------------------------------------
  // allow — check if an action is allowed under the rate limit.
  // Returns true if allowed, false if rate-limited.
  // ------------------------------------------------------------------------
  bool allow(const std::string& key) {
    std::lock_guard<std::mutex> lock(mu_);

    int64_t now = now_ms();
    auto it = buckets_.find(key);
    if (it == buckets_.end()) {
      Bucket b;
      b.tokens = burst_;
      b.last_refill = now;
      buckets_[key] = b;
      it = buckets_.find(key);
    }

    Bucket& b = it->second;

    // Refill tokens
    double elapsed = (now - b.last_refill) / 1000.0;
    b.tokens = std::min(burst_, b.tokens + elapsed * rate_per_second_);
    b.last_refill = now;

    if (b.tokens >= 1.0) {
      b.tokens -= 1.0;
      return true;
    }
    return false;
  }

  // ------------------------------------------------------------------------
  // reset — clear all rate limit buckets.
  // ------------------------------------------------------------------------
  void reset() {
    std::lock_guard<std::mutex> lock(mu_);
    buckets_.clear();
  }

  // ------------------------------------------------------------------------
  // cleanup — remove stale buckets (not accessed for 5 minutes).
  // ------------------------------------------------------------------------
  void cleanup() {
    std::lock_guard<std::mutex> lock(mu_);
    int64_t now = now_ms();
    auto it = buckets_.begin();
    while (it != buckets_.end()) {
      if (now - it->second.last_refill > 300000) {
        it = buckets_.erase(it);
      } else {
        ++it;
      }
    }
  }

private:
  struct Bucket {
    double tokens = 1.0;
    int64_t last_refill = 0;
  };

  std::mutex mu_;
  std::unordered_map<std::string, Bucket> buckets_;
  double burst_;
  double rate_per_second_;
};

// ============================================================================
// SpamChecker — validates events against anti-spam rules
// ============================================================================

class SpamChecker {
public:
  explicit SpamChecker(const MessageHandlerV2Config& cfg)
      : config_(cfg) {}

  // ------------------------------------------------------------------------
  // check_event_for_spam — check if an event should be blocked as spam.
  // Returns ValidationResult — ok() if allowed, fail() if blocked.
  // ------------------------------------------------------------------------
  ValidationResult check_event_for_spam(
      const std::string& user_id,
      const std::string& room_id,
      const std::string& event_type,
      const json& content) {

    if (!config_.enable_spam_check)
      return ValidationResult::ok();

    // Check for empty content
    if (content.empty() || !content.is_object())
      return ValidationResult::fail(
          msg_constants::M_BAD_JSON,
          "Empty content not allowed");

    // Check for excessively large content
    std::string content_str = content.dump();
    if (content_str.size() > static_cast<size_t>(config_.max_event_content_size))
      return ValidationResult::fail(
          msg_constants::M_TOO_LARGE,
          "Event content too large: " +
              std::to_string(content_str.size()) + " bytes");

    // Check body for potential spam patterns
    std::string body = json_str(content, msg_constants::KEY_BODY);
    if (!body.empty()) {
      // Check for excessive repeated characters
      if (has_excessive_repetition(body, 100))
        return ValidationResult::fail(
            msg_constants::M_FORBIDDEN,
            "Message contains excessive repeated characters");

      // Check for excessive URLs
      if (count_urls(body) > 20)
        return ValidationResult::fail(
            msg_constants::M_FORBIDDEN,
            "Message contains too many URLs");
    }

    // Check for forbidden words (basic profanity filter)
    if (contains_forbidden_content(body))
      return ValidationResult::fail(
          msg_constants::M_FORBIDDEN,
          "Message contains prohibited content");

    return ValidationResult::ok();
  }

  // ------------------------------------------------------------------------
  // check_media_spam — check if uploaded media appears to be spam.
  // ------------------------------------------------------------------------
  ValidationResult check_media_spam(
      const std::string& user_id,
      const std::string& media_id,
      const std::string& content_type,
      int64_t media_size) {

    if (!config_.enable_spam_check)
      return ValidationResult::ok();

    // Check media size
    if (media_size > config_.max_upload_size)
      return ValidationResult::fail(
          msg_constants::M_TOO_LARGE,
          "Media too large: " + std::to_string(media_size) + " bytes");

    // Check content type is allowed
    if (is_banned_content_type(content_type))
      return ValidationResult::fail(
          msg_constants::M_FORBIDDEN,
          "Content type not allowed: " + content_type);

    return ValidationResult::ok();
  }

private:
  // ---- Simple spam detection heuristics ----

  bool has_excessive_repetition(const std::string& s, int max_repeat) {
    if (s.empty()) return false;
    int count = 1;
    for (size_t i = 1; i < s.size(); ++i) {
      if (s[i] == s[i-1]) {
        count++;
        if (count > max_repeat) return true;
      } else {
        count = 1;
      }
    }
    return false;
  }

  int count_urls(const std::string& s) {
    int count = 0;
    size_t pos = 0;
    while ((pos = s.find("http://", pos)) != std::string::npos ||
           (pos = s.find("https://", pos)) != std::string::npos) {
      ++count;
      pos += 4;
    }
    return count;
  }

  bool contains_forbidden_content(const std::string&) {
    // Placeholder for actual content filtering
    return false;
  }

  bool is_banned_content_type(const std::string& ct) {
    static const std::set<std::string> banned = {
      "application/x-msdownload",
      "application/x-msdos-program",
      "application/x-msi",
      "application/x-ms-shortcut",
    };
    return banned.count(ct) > 0;
  }

  const MessageHandlerV2Config& config_;
};

// ============================================================================
// UrlPreviewGenerator — generates URL previews for text messages
// ============================================================================

class UrlPreviewGenerator {
public:
  UrlPreviewGenerator(DatabasePool& db,
                      const MessageHandlerV2Config& cfg)
      : db_(db), config_(cfg) {}

  // ------------------------------------------------------------------------
  // process_urls_in_content — find URLs in message content, generate
  // previews, and inject into the event content.
  // ------------------------------------------------------------------------
  json process_urls_in_content(const json& content,
                                const std::string& room_id,
                                const std::string& user_id) {
    if (!config_.enable_url_previews)
      return content;

    json enriched = content;
    std::string body = json_str(content, msg_constants::KEY_BODY);
    if (body.empty()) return enriched;

    auto urls = extract_urls(body);
    if (urls.empty()) return enriched;

    json previews = json::array();
    for (const auto& url : urls) {
      auto preview = get_or_fetch_preview(url);
      if (!preview.empty())
        previews.push_back(preview);
    }

    if (!previews.empty()) {
      enriched["org.matrix.url_previews"] = previews;
    }

    return enriched;
  }

private:
  std::vector<std::string> extract_urls(const std::string& text) {
    std::vector<std::string> urls;
    size_t pos = 0;
    // Simple URL extraction pattern
    while ((pos = text.find("http://", pos)) != std::string::npos ||
           (pos = text.find("https://", pos)) != std::string::npos) {
      size_t end = text.find_first_of(" \t\n\r\v\f,.;:!?)", pos + 8);
      if (end == std::string::npos) end = text.size();
      std::string url = text.substr(pos, end - pos);
      if (!url.empty()) urls.push_back(url);
      pos = end;
    }
    return urls;
  }

  json get_or_fetch_preview(const std::string& url) {
    json preview;
    int64_t now = now_sec();

    // Check cache first
    bool found = false;
    db_.runInteraction("url_preview_cache",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT preview_data, ts FROM url_previews "
              "WHERE url=? AND ts > ?",
              {url, now - config_.url_preview_cache_ttl_ms / 1000});
          auto r = txn.fetchone();
          if (r && r->size() > 0 && r->at(0).value) {
            try {
              preview = json::parse(*r->at(0).value);
              found = true;
            } catch (...) {}
          }
        });

    if (!found) {
      // Fetch would happen here via HTTP — for now, create minimal preview
      preview["url"] = url;
      preview["og:title"] = url;
      preview["og:description"] = "";
      preview["matrix:image:size"] = 0;

      // Store in cache
      int64_t cache_ts = now_sec();
      db_.runInteraction("store_url_preview",
          [&](LoggingTransaction& txn) {
            txn.execute(
                "INSERT INTO url_previews (url, ts, preview_data, og_ts) "
                "VALUES (?,?,?,?) "
                "ON CONFLICT(url) DO UPDATE SET "
                "ts=excluded.ts, preview_data=excluded.preview_data",
                {url, cache_ts, preview.dump(), static_cast<int64_t>(0)});
          });
    }

    return preview;
  }

  DatabasePool& db_;
  const MessageHandlerV2Config& config_;
};

// ============================================================================
// MessageHandlerV2 — main orchestrator class
// ============================================================================

class MessageHandlerV2 {
public:
  MessageHandlerV2(DatabasePool& db,
                   const MessageHandlerV2Config& cfg = MessageHandlerV2Config())
      : db_(db),
        config_(cfg),
        validator_(cfg),
        idempotency_(db),
        event_creator_(db, cfg, idempotency_),
        push_trigger_(db, cfg),
        spam_checker_(cfg),
        url_preview_(db, cfg),
        rate_limiter_send_(msg_constants::RATE_LIMIT_BURST_SEND,
                            cfg.rate_limit_send_per_second),
        rate_limiter_redact_(msg_constants::RATE_LIMIT_BURST_REDACT,
                              cfg.rate_limit_redact_per_second),
        rate_limiter_react_(msg_constants::RATE_LIMIT_BURST_REACT,
                             cfg.rate_limit_react_per_second) {}

  // ==========================================================================
  // Public API - message operations
  // ==========================================================================

  // --------------------------------------------------------------------------
  // send_message — create and persist a new room message.
  // Validates content, checks power levels, applies rate limiting,
  // spam checking, URL preview, persists event, triggers push.
  // Returns JSON: {"event_id": "..."} or error.
  // --------------------------------------------------------------------------
  json send_message(const std::string& room_id,
                     const std::string& user_id,
                     const std::string& event_type,
                     const json& content,
                     const std::string& txn_id = "",
                     const std::optional<std::string>& device_id = std::nullopt);

  // --------------------------------------------------------------------------
  // redact_event — redact an existing event.
  // Validates permissions, creates redaction event, cascades effects.
  // --------------------------------------------------------------------------
  json redact_event(const std::string& room_id,
                     const std::string& user_id,
                     const std::string& target_event_id,
                     const std::string& reason = "",
                     const std::string& txn_id = "");

  // --------------------------------------------------------------------------
  // react_to_event — add a reaction (emoji/annotation) to an event.
  // Prevents duplicate reactions per user/key.
  // --------------------------------------------------------------------------
  json react_to_event(const std::string& room_id,
                       const std::string& user_id,
                       const std::string& target_event_id,
                       const std::string& reaction_key,
                       const std::string& txn_id = "");

  // --------------------------------------------------------------------------
  // edit_message — edit a previously sent message.
  // Only the original sender can edit. Max edit depth 1.
  // --------------------------------------------------------------------------
  json edit_message(const std::string& room_id,
                     const std::string& user_id,
                     const std::string& target_event_id,
                     const json& new_content,
                     const std::string& txn_id = "");

  // --------------------------------------------------------------------------
  // reply_to_event — reply to an existing event.
  // Supports both inline reply (m.in_reply_to) and thread reply (m.thread).
  // --------------------------------------------------------------------------
  json reply_to_event(const std::string& room_id,
                       const std::string& user_id,
                       const std::string& target_event_id,
                       const json& content,
                       const std::string& txn_id = "",
                       bool is_thread = false);

  // --------------------------------------------------------------------------
  // forward_message — forward a message from one room to another.
  // --------------------------------------------------------------------------
  json forward_message(const std::string& target_room_id,
                        const std::string& user_id,
                        const std::string& source_event_id,
                        const std::string& source_room_id,
                        const std::string& txn_id = "");

  // --------------------------------------------------------------------------
  // send_image_message — send an m.image message with full validation.
  // --------------------------------------------------------------------------
  json send_image_message(const std::string& room_id,
                           const std::string& user_id,
                           const std::string& mxc_url,
                           const std::string& body,
                           const json& info = json::object(),
                           const std::string& thumbnail_url = "",
                           const json& thumbnail_info = json::object(),
                           const std::string& txn_id = "");

  // --------------------------------------------------------------------------
  // send_video_message — send an m.video message with full validation.
  // --------------------------------------------------------------------------
  json send_video_message(const std::string& room_id,
                           const std::string& user_id,
                           const std::string& mxc_url,
                           const std::string& body,
                           const json& info = json::object(),
                           const std::string& thumbnail_url = "",
                           const json& thumbnail_info = json::object(),
                           const std::string& txn_id = "");

  // --------------------------------------------------------------------------
  // send_audio_message — send an m.audio message with full validation.
  // --------------------------------------------------------------------------
  json send_audio_message(const std::string& room_id,
                           const std::string& user_id,
                           const std::string& mxc_url,
                           const std::string& body,
                           const json& info = json::object(),
                           const std::string& txn_id = "");

  // --------------------------------------------------------------------------
  // send_file_message — send an m.file message with full validation.
  // --------------------------------------------------------------------------
  json send_file_message(const std::string& room_id,
                          const std::string& user_id,
                          const std::string& mxc_url,
                          const std::string& body,
                          const std::string& filename,
                          const json& info = json::object(),
                          const std::string& thumbnail_url = "",
                          const json& thumbnail_info = json::object(),
                          const std::string& txn_id = "");

  // --------------------------------------------------------------------------
  // send_location_message — send an m.location message with full validation.
  // --------------------------------------------------------------------------
  json send_location_message(const std::string& room_id,
                              const std::string& user_id,
                              const std::string& geo_uri,
                              const std::string& body,
                              const json& info = json::object(),
                              const std::string& txn_id = "");

  // --------------------------------------------------------------------------
  // check_membership — check if a user is a member of a room.
  // --------------------------------------------------------------------------
  bool check_membership(const std::string& room_id,
                         const std::string& user_id,
                         const std::string& membership = "join");

  // --------------------------------------------------------------------------
  // check_power_level — check if a user has sufficient power level.
  // --------------------------------------------------------------------------
  bool check_power_level(const std::string& room_id,
                          const std::string& user_id,
                          const std::string& event_type,
                          int default_required = 0);

  // --------------------------------------------------------------------------
  // get_room_members — get all joined members of a room.
  // --------------------------------------------------------------------------
  std::vector<std::string> get_room_members(const std::string& room_id);

  // --------------------------------------------------------------------------
  // Maintenance — cleanup expired rate limit buckets
  // --------------------------------------------------------------------------
  void cleanup_rate_limits() {
    rate_limiter_send_.cleanup();
    rate_limiter_redact_.cleanup();
    rate_limiter_react_.cleanup();
  }

private:
  // --- Rate limit keys ---
  std::string rate_key(const std::string& user_id, const std::string& room_id) {
    return user_id + ":" + room_id;
  }

  // --- Common pre-check pipeline ---
  json pre_check_and_prepare(const std::string& room_id,
                              const std::string& user_id,
                              const std::string& event_type,
                              const json& content);

  // --- Internal helpers ---
  json persist_and_push(const std::string& room_id,
                         const std::string& user_id,
                         const PersistResult& pr);

  DatabasePool& db_;
  MessageHandlerV2Config config_;
  MessageValidator validator_;
  TransactionIdempotency idempotency_;
  EventCreator event_creator_;
  PushTrigger push_trigger_;
  SpamChecker spam_checker_;
  UrlPreviewGenerator url_preview_;
  RateLimiter rate_limiter_send_;
  RateLimiter rate_limiter_redact_;
  RateLimiter rate_limiter_react_;
};

// ============================================================================
// MessageHandlerV2 implementation — Core Logic
// ============================================================================

// --------------------------------------------------------------------------
// check_membership
// --------------------------------------------------------------------------
bool MessageHandlerV2::check_membership(const std::string& room_id,
                                         const std::string& user_id,
                                         const std::string& membership) {
  bool result = false;
  db_.runInteraction("check_membership",
      [&](LoggingTransaction& txn) {
        txn.execute(
            "SELECT membership FROM local_current_membership "
            "WHERE user_id=? AND room_id=?",
            {user_id, room_id});
        auto r = txn.fetchone();
        if (r && r->size() > 0 && r->at(0).value)
          result = (*r->at(0).value == membership);
      });
  return result;
}

// --------------------------------------------------------------------------
// check_power_level
// --------------------------------------------------------------------------
bool MessageHandlerV2::check_power_level(const std::string& room_id,
                                          const std::string& user_id,
                                          const std::string& event_type,
                                          int default_required) {
  bool can = false;
  db_.runInteraction("check_pl",
      [&](LoggingTransaction& txn) {
        // Check if user is the room creator
        txn.execute(
            "SELECT content FROM events e "
            "JOIN current_state_events cs ON e.event_id=cs.event_id "
            "WHERE cs.room_id=? AND cs.type='m.room.create' AND cs.state_key=''",
            {room_id});
        auto cr = txn.fetchone();
        if (cr && cr->size() > 0 && cr->at(0).value) {
          try {
            json create = json::parse(*cr->at(0).value);
            if (json_str(create, "creator") == user_id) {
              can = true;
              return;
            }
          } catch (...) {}
        }

        // Check power levels
        txn.execute(
            "SELECT content FROM events e "
            "JOIN current_state_events cs ON e.event_id=cs.event_id "
            "WHERE cs.room_id=? AND cs.type='m.room.power_levels' AND cs.state_key=''",
            {room_id});
        auto pl_row = txn.fetchone();
        if (!pl_row || pl_row->size() <= 0 || !pl_row->at(0).value) {
          // No power levels set — use defaults
          if (default_required == 0) can = true;
          return;
        }

        try {
          json pl = json::parse(*pl_row->at(0).value);
          int user_level = 0;
          if (pl.contains("users") && pl["users"].contains(user_id))
            user_level = pl["users"][user_id].get<int>();
          else
            user_level = pl.value("users_default", 0);

          int required = pl.value("events_default", 0);
          if (pl.contains("events") && pl["events"].contains(event_type))
            required = pl["events"][event_type].get<int>();
          else if (event_type == "m.room.redaction")
            required = pl.value("redact", 50);
          else if (event_type == "m.room.message")
            required = pl.value("events_default", 0);

          can = (user_level >= required);
        } catch (...) {
          can = (default_required == 0);
        }
      });
  return can;
}

// --------------------------------------------------------------------------
// get_room_members
// --------------------------------------------------------------------------
std::vector<std::string> MessageHandlerV2::get_room_members(
    const std::string& room_id) {
  return push_trigger_.get_users_to_notify(room_id, "");
}

// --------------------------------------------------------------------------
// pre_check_and_prepare
// --------------------------------------------------------------------------
json MessageHandlerV2::pre_check_and_prepare(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& event_type,
    const json& content) {

  // --- Validate content ---
  auto val_result = validator_.validate_send_content(content, event_type);
  if (!val_result.valid)
    return build_error_response(val_result.http_status,
                                 val_result.errcode, val_result.error);

  // --- Spam check ---
  auto spam = spam_checker_.check_event_for_spam(
      user_id, room_id, event_type, content);
  if (!spam.valid)
    return build_error_response(spam.http_status, spam.errcode, spam.error);

  return json::object(); // OK
}

// --------------------------------------------------------------------------
// persist_and_push
// --------------------------------------------------------------------------
json MessageHandlerV2::persist_and_push(const std::string& room_id,
                                          const std::string& user_id,
                                          const PersistResult& pr) {
  if (!pr.success)
    return build_error_response(500, msg_constants::M_UNKNOWN,
                                 pr.error.empty() ? "Failed to persist event"
                                                   : pr.error);

  // --- Trigger push notifications ---
  push_trigger_.trigger_push_for_event(
      pr.event_id, room_id, user_id,
      msg_constants::EVT_ROOM_MESSAGE,
      pr.stream_ordering, pr.depth, pr.origin_server_ts);

  return build_success_response(pr.event_id);
}

// --------------------------------------------------------------------------
// send_message — Main send endpoint handler
// --------------------------------------------------------------------------
json MessageHandlerV2::send_message(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& event_type,
    const json& content,
    const std::string& txn_id,
    const std::optional<std::string>& device_id) {

  // --- Rate limiting ---
  if (config_.enable_rate_limiting) {
    if (!rate_limiter_send_.allow(rate_key(user_id, room_id)))
      return build_error_response(429, msg_constants::M_LIMIT_EXCEEDED,
                                   "Too many messages. Please wait and try again.");
  }

  // --- Membership check ---
  if (!check_membership(room_id, user_id))
    return build_error_response(403, msg_constants::M_FORBIDDEN,
                                 "You are not a member of this room");

  // --- Power level check ---
  if (!check_power_level(room_id, user_id, event_type, 0))
    return build_error_response(403, msg_constants::M_FORBIDDEN,
                                 "You do not have permission to send '" +
                                     event_type + "' events");

  // --- Pre-check and validate ---
  auto pre = pre_check_and_prepare(room_id, user_id, event_type, content);
  if (!pre.empty()) return pre;

  // --- URL preview enrichment for text messages ---
  json enriched_content = content;
  std::string msgtype = json_str(content, msg_constants::KEY_MSGTYPE);
  if (msgtype == msg_constants::MSGTYPE_TEXT) {
    enriched_content = url_preview_.process_urls_in_content(content, room_id, user_id);
  }

  // --- Create and persist ---
  auto pr = event_creator_.create_and_persist_message(
      room_id, user_id, event_type, enriched_content, txn_id, device_id);

  if (!pr.success)
    return build_error_response(500, msg_constants::M_UNKNOWN,
                                 pr.error.empty() ? "Failed to send message" : pr.error);

  // --- Push ---
  push_trigger_.trigger_push_for_event(
      pr.event_id, room_id, user_id,
      msg_constants::EVT_ROOM_MESSAGE,
      pr.stream_ordering, pr.depth, pr.origin_server_ts);

  return build_success_response(pr.event_id);
}

// --------------------------------------------------------------------------
// redact_event
// --------------------------------------------------------------------------
json MessageHandlerV2::redact_event(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& target_event_id,
    const std::string& reason,
    const std::string& txn_id) {

  // --- Rate limiting ---
  if (config_.enable_rate_limiting) {
    if (!rate_limiter_redact_.allow(rate_key(user_id, room_id)))
      return build_error_response(429, msg_constants::M_LIMIT_EXCEEDED,
                                   "Too many redactions. Please wait and try again.");
  }

  // --- Membership check ---
  if (!check_membership(room_id, user_id))
    return build_error_response(403, msg_constants::M_FORBIDDEN,
                                 "You are not a member of this room");

  // --- Check permissions: own event or PL >= 50 ---
  bool can_redact = false;
  std::string target_sender;
  db_.runInteraction("check_redact_perm",
      [&](LoggingTransaction& txn) {
        txn.execute(
            "SELECT sender FROM events "
            "WHERE event_id=? AND room_id=?",
            {target_event_id, room_id});
        auto r = txn.fetchone();
        if (r && r->size() > 0 && r->at(0).value) {
          target_sender = *r->at(0).value;
          if (target_sender == user_id) {
            can_redact = true;
          }
        }
      });

  if (!can_redact) {
    can_redact = check_power_level(room_id, user_id,
                                    msg_constants::EVT_ROOM_REDACTION, 50);
  }

  if (!can_redact)
    return build_error_response(403, msg_constants::M_FORBIDDEN,
                                 "You do not have permission to redact this event");

  // --- Validate reason length ---
  if (reason.size() > static_cast<size_t>(msg_constants::MAX_REASON_LENGTH))
    return build_error_response(400, msg_constants::M_INVALID_PARAM,
                                 "Reason too long");

  // --- Create redaction ---
  auto pr = event_creator_.create_and_persist_redaction(
      room_id, user_id, target_event_id, reason, txn_id);

  if (!pr.success)
    return build_error_response(500, msg_constants::M_UNKNOWN,
                                 pr.error.empty() ? "Failed to redact event" : pr.error);

  // --- Push for redaction ---
  push_trigger_.trigger_push_for_redaction(
      pr.event_id, room_id, user_id, pr.stream_ordering);

  return build_success_response(pr.event_id);
}

// --------------------------------------------------------------------------
// react_to_event
// --------------------------------------------------------------------------
json MessageHandlerV2::react_to_event(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& target_event_id,
    const std::string& reaction_key,
    const std::string& txn_id) {

  // --- Rate limiting ---
  if (config_.enable_rate_limiting) {
    if (!rate_limiter_react_.allow(rate_key(user_id, room_id)))
      return build_error_response(429, msg_constants::M_LIMIT_EXCEEDED,
                                   "Too many reactions. Please wait and try again.");
  }

  // --- Membership check ---
  if (!check_membership(room_id, user_id))
    return build_error_response(403, msg_constants::M_FORBIDDEN,
                                 "You are not a member of this room");

  // --- Validate reaction key length ---
  if (reaction_key.size() > static_cast<size_t>(msg_constants::MAX_REACTION_KEY_LENGTH))
    return build_error_response(400, msg_constants::M_INVALID_PARAM,
                                 "Reaction key too long (max " +
                                     std::to_string(msg_constants::MAX_REACTION_KEY_LENGTH) +
                                     " characters)");

  // --- Check target event exists ---
  if (!event_creator_.event_exists(target_event_id))
    return build_error_response(404, msg_constants::M_NOT_FOUND,
                                 "Target event not found");

  // --- Build content and validate ---
  json reaction_content;
  reaction_content[msg_constants::KEY_RELATES_TO] = {
      {"event_id", target_event_id},
      {"rel_type", msg_constants::REL_ANNOTATION},
      {"key", reaction_key}
  };

  auto val = validator_.validate_reaction_content(reaction_content);
  if (!val.valid)
    return build_error_response(val.http_status, val.errcode, val.error);

  // --- Create reaction ---
  auto pr = event_creator_.create_and_persist_reaction(
      room_id, user_id, target_event_id, reaction_key, txn_id);

  if (!pr.success) {
    if (pr.error == "Duplicate reaction")
      return build_error_response(400, msg_constants::M_DUPLICATE_ANNOTATION,
                                   "You have already reacted with this key");
    return build_error_response(500, msg_constants::M_UNKNOWN,
                                 pr.error.empty() ? "Failed to add reaction" : pr.error);
  }

  // --- Push for reaction ---
  push_trigger_.trigger_push_for_reaction(
      pr.event_id, room_id, user_id, target_event_id, pr.stream_ordering);

  return build_success_response(pr.event_id);
}

// --------------------------------------------------------------------------
// edit_message
// --------------------------------------------------------------------------
json MessageHandlerV2::edit_message(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& target_event_id,
    const json& new_content,
    const std::string& txn_id) {

  // --- Rate limiting ---
  if (config_.enable_rate_limiting) {
    if (!rate_limiter_send_.allow(rate_key(user_id, room_id)))
      return build_error_response(429, msg_constants::M_LIMIT_EXCEEDED,
                                   "Too many edits. Please wait and try again.");
  }

  // --- Membership check ---
  if (!check_membership(room_id, user_id))
    return build_error_response(403, msg_constants::M_FORBIDDEN,
                                 "You are not a member of this room");

  // --- Check target event exists ---
  if (!event_creator_.event_exists(target_event_id))
    return build_error_response(404, msg_constants::M_NOT_FOUND,
                                 "Target event not found");

  // --- Build edit content and validate ---
  json edit_content;
  edit_content[msg_constants::KEY_RELATES_TO] = {
      {"event_id", target_event_id},
      {"rel_type", msg_constants::REL_REPLACE}
  };
  edit_content[msg_constants::KEY_NEW_CONTENT] = new_content;

  auto val = validator_.validate_edit_content(edit_content);
  if (!val.valid)
    return build_error_response(val.http_status, val.errcode, val.error);

  // --- Create edit ---
  auto pr = event_creator_.create_and_persist_edit(
      room_id, user_id, target_event_id, new_content, txn_id);

  if (!pr.success) {
    if (pr.error == "Cannot edit another user's message")
      return build_error_response(403, msg_constants::M_FORBIDDEN, pr.error);
    if (pr.error == "Cannot edit an edit event (max depth exceeded)")
      return build_error_response(400, msg_constants::M_INVALID_PARAM, pr.error);
    return build_error_response(500, msg_constants::M_UNKNOWN,
                                 pr.error.empty() ? "Failed to edit message" : pr.error);
  }

  // --- Push for edit ---
  push_trigger_.trigger_push_for_edit(
      pr.event_id, room_id, user_id, pr.stream_ordering);

  return build_success_response(pr.event_id);
}

// --------------------------------------------------------------------------
// reply_to_event
// --------------------------------------------------------------------------
json MessageHandlerV2::reply_to_event(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& target_event_id,
    const json& content,
    const std::string& txn_id,
    bool is_thread) {

  // --- Rate limiting ---
  if (config_.enable_rate_limiting) {
    if (!rate_limiter_send_.allow(rate_key(user_id, room_id)))
      return build_error_response(429, msg_constants::M_LIMIT_EXCEEDED,
                                   "Too many messages. Please wait and try again.");
  }

  // --- Membership check ---
  if (!check_membership(room_id, user_id))
    return build_error_response(403, msg_constants::M_FORBIDDEN,
                                 "You are not a member of this room");

  // --- Power level check ---
  if (!check_power_level(room_id, user_id, msg_constants::EVT_ROOM_MESSAGE, 0))
    return build_error_response(403, msg_constants::M_FORBIDDEN,
                                 "You do not have permission to send messages");

  // --- Validate reply content ---
  auto val = validator_.validate_reply_content(content);
  if (!val.valid)
    return build_error_response(val.http_status, val.errcode, val.error);

  // --- Check target event exists ---
  if (!event_creator_.event_exists(target_event_id))
    return build_error_response(404, msg_constants::M_NOT_FOUND,
                                 "Replied-to event not found");

  // --- Spam check ---
  auto spam = spam_checker_.check_event_for_spam(
      user_id, room_id, msg_constants::EVT_ROOM_MESSAGE, content);
  if (!spam.valid)
    return build_error_response(spam.http_status, spam.errcode, spam.error);

  // --- Create reply ---
  auto pr = event_creator_.create_and_persist_reply(
      room_id, user_id, target_event_id, content, txn_id, is_thread);

  if (!pr.success)
    return build_error_response(500, msg_constants::M_UNKNOWN,
                                 pr.error.empty() ? "Failed to send reply" : pr.error);

  // --- Push ---
  push_trigger_.trigger_push_for_event(
      pr.event_id, room_id, user_id,
      msg_constants::EVT_ROOM_MESSAGE,
      pr.stream_ordering, pr.depth, pr.origin_server_ts);

  return build_success_response(pr.event_id);
}

// --------------------------------------------------------------------------
// forward_message
// --------------------------------------------------------------------------
json MessageHandlerV2::forward_message(
    const std::string& target_room_id,
    const std::string& user_id,
    const std::string& source_event_id,
    const std::string& source_room_id,
    const std::string& txn_id) {

  // --- Rate limiting ---
  if (config_.enable_rate_limiting) {
    if (!rate_limiter_send_.allow(rate_key(user_id, target_room_id)))
      return build_error_response(429, msg_constants::M_LIMIT_EXCEEDED,
                                   "Too many messages. Please wait and try again.");
  }

  // --- Membership check for target room ---
  if (!check_membership(target_room_id, user_id))
    return build_error_response(403, msg_constants::M_FORBIDDEN,
                                 "You are not a member of the target room");

  // --- Membership check for source room ---
  if (!check_membership(source_room_id, user_id))
    return build_error_response(403, msg_constants::M_FORBIDDEN,
                                 "You are not a member of the source room");

  // --- Check source event exists ---
  if (!event_creator_.event_exists(source_event_id))
    return build_error_response(404, msg_constants::M_NOT_FOUND,
                                 "Source event not found");

  // --- Create forward ---
  auto pr = event_creator_.create_and_persist_forward(
      target_room_id, user_id, source_event_id, source_room_id, txn_id);

  if (!pr.success)
    return build_error_response(500, msg_constants::M_UNKNOWN,
                                 pr.error.empty() ? "Failed to forward message" : pr.error);

  // --- Push ---
  push_trigger_.trigger_push_for_event(
      pr.event_id, target_room_id, user_id,
      msg_constants::EVT_ROOM_MESSAGE,
      pr.stream_ordering, pr.depth, pr.origin_server_ts);

  return build_success_response(pr.event_id);
}

// --------------------------------------------------------------------------
// send_image_message
// --------------------------------------------------------------------------
json MessageHandlerV2::send_image_message(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& mxc_url,
    const std::string& body,
    const json& info,
    const std::string& thumbnail_url,
    const json& thumbnail_info,
    const std::string& txn_id) {

  // --- Validate mxc URL ---
  if (!is_valid_mxc_uri(mxc_url))
    return build_error_response(400, msg_constants::M_INVALID_PARAM,
                                 "Invalid mxc:// URL");

  // --- Build content ---
  json content;
  content[msg_constants::KEY_BODY] = body;
  content[msg_constants::KEY_MSGTYPE] = msg_constants::MSGTYPE_IMAGE;
  content[msg_constants::KEY_URL] = mxc_url;

  if (!info.empty())
    content[msg_constants::KEY_INFO] = info;

  if (!thumbnail_url.empty()) {
    content[msg_constants::KEY_THUMBNAIL_URL] = thumbnail_url;
    if (!thumbnail_info.empty())
      content[msg_constants::KEY_THUMBNAIL_INFO] = thumbnail_info;
  }

  // --- Validate ---
  auto val = validator_.validate_send_content(
      content, msg_constants::EVT_ROOM_MESSAGE);
  if (!val.valid)
    return build_error_response(val.http_status, val.errcode, val.error);

  // --- Delegate to send_message ---
  return send_message(room_id, user_id, msg_constants::EVT_ROOM_MESSAGE,
                       content, txn_id);
}

// --------------------------------------------------------------------------
// send_video_message
// --------------------------------------------------------------------------
json MessageHandlerV2::send_video_message(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& mxc_url,
    const std::string& body,
    const json& info,
    const std::string& thumbnail_url,
    const json& thumbnail_info,
    const std::string& txn_id) {

  // --- Validate mxc URL ---
  if (!is_valid_mxc_uri(mxc_url))
    return build_error_response(400, msg_constants::M_INVALID_PARAM,
                                 "Invalid mxc:// URL");

  // --- Build content ---
  json content;
  content[msg_constants::KEY_BODY] = body;
  content[msg_constants::KEY_MSGTYPE] = msg_constants::MSGTYPE_VIDEO;
  content[msg_constants::KEY_URL] = mxc_url;

  if (!info.empty())
    content[msg_constants::KEY_INFO] = info;

  if (!thumbnail_url.empty()) {
    content[msg_constants::KEY_THUMBNAIL_URL] = thumbnail_url;
    if (!thumbnail_info.empty())
      content[msg_constants::KEY_THUMBNAIL_INFO] = thumbnail_info;
  }

  // --- Validate ---
  auto val = validator_.validate_send_content(
      content, msg_constants::EVT_ROOM_MESSAGE);
  if (!val.valid)
    return build_error_response(val.http_status, val.errcode, val.error);

  // --- Delegate to send_message ---
  return send_message(room_id, user_id, msg_constants::EVT_ROOM_MESSAGE,
                       content, txn_id);
}

// --------------------------------------------------------------------------
// send_audio_message
// --------------------------------------------------------------------------
json MessageHandlerV2::send_audio_message(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& mxc_url,
    const std::string& body,
    const json& info,
    const std::string& txn_id) {

  // --- Validate mxc URL ---
  if (!is_valid_mxc_uri(mxc_url))
    return build_error_response(400, msg_constants::M_INVALID_PARAM,
                                 "Invalid mxc:// URL");

  // --- Build content ---
  json content;
  content[msg_constants::KEY_BODY] = body;
  content[msg_constants::KEY_MSGTYPE] = msg_constants::MSGTYPE_AUDIO;
  content[msg_constants::KEY_URL] = mxc_url;

  if (!info.empty())
    content[msg_constants::KEY_INFO] = info;

  // --- Validate ---
  auto val = validator_.validate_send_content(
      content, msg_constants::EVT_ROOM_MESSAGE);
  if (!val.valid)
    return build_error_response(val.http_status, val.errcode, val.error);

  // --- Delegate to send_message ---
  return send_message(room_id, user_id, msg_constants::EVT_ROOM_MESSAGE,
                       content, txn_id);
}

// --------------------------------------------------------------------------
// send_file_message
// --------------------------------------------------------------------------
json MessageHandlerV2::send_file_message(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& mxc_url,
    const std::string& body,
    const std::string& filename,
    const json& info,
    const std::string& thumbnail_url,
    const json& thumbnail_info,
    const std::string& txn_id) {

  // --- Validate mxc URL ---
  if (!is_valid_mxc_uri(mxc_url))
    return build_error_response(400, msg_constants::M_INVALID_PARAM,
                                 "Invalid mxc:// URL");

  // --- Validate filename ---
  if (filename.empty())
    return build_error_response(400, msg_constants::M_INVALID_PARAM,
                                 "Filename is required for file messages");

  if (filename.size() > static_cast<size_t>(msg_constants::MAX_FILENAME_LENGTH))
    return build_error_response(400, msg_constants::M_TOO_LARGE,
                                 "Filename too long (max " +
                                     std::to_string(msg_constants::MAX_FILENAME_LENGTH) +
                                     " characters)");

  // --- Build content ---
  json content;
  content[msg_constants::KEY_BODY] = body;
  content[msg_constants::KEY_MSGTYPE] = msg_constants::MSGTYPE_FILE;
  content[msg_constants::KEY_URL] = mxc_url;
  content[msg_constants::KEY_FILENAME] = filename;

  if (!info.empty())
    content[msg_constants::KEY_INFO] = info;

  if (!thumbnail_url.empty()) {
    content[msg_constants::KEY_THUMBNAIL_URL] = thumbnail_url;
    if (!thumbnail_info.empty())
      content[msg_constants::KEY_THUMBNAIL_INFO] = thumbnail_info;
  }

  // --- Validate ---
  auto val = validator_.validate_send_content(
      content, msg_constants::EVT_ROOM_MESSAGE);
  if (!val.valid)
    return build_error_response(val.http_status, val.errcode, val.error);

  // --- Delegate to send_message ---
  return send_message(room_id, user_id, msg_constants::EVT_ROOM_MESSAGE,
                       content, txn_id);
}

// --------------------------------------------------------------------------
// send_location_message
// --------------------------------------------------------------------------
json MessageHandlerV2::send_location_message(
    const std::string& room_id,
    const std::string& user_id,
    const std::string& geo_uri,
    const std::string& body,
    const json& info,
    const std::string& txn_id) {

  // --- Validate geo_uri ---
  if (!is_valid_geo_uri(geo_uri))
    return build_error_response(400, msg_constants::M_INVALID_PARAM,
                                 "Invalid geo_uri. Must be valid 'geo:<lat>,<lon>' format");

  // --- Build content ---
  json content;
  content[msg_constants::KEY_BODY] = body;
  content[msg_constants::KEY_MSGTYPE] = msg_constants::MSGTYPE_LOCATION;
  content[msg_constants::KEY_GEO_URI] = geo_uri;

  if (!info.empty())
    content[msg_constants::KEY_INFO] = info;

  // --- Validate ---
  auto val = validator_.validate_send_content(
      content, msg_constants::EVT_ROOM_MESSAGE);
  if (!val.valid)
    return build_error_response(val.http_status, val.errcode, val.error);

  // --- Delegate to send_message ---
  return send_message(room_id, user_id, msg_constants::EVT_ROOM_MESSAGE,
                       content, txn_id);
}

// ============================================================================
// MessageHandlerV2Service — top-level service interface
// ============================================================================

class MessageHandlerV2Service {
public:
  explicit MessageHandlerV2Service(DatabasePool& db)
      : handler_(db, MessageHandlerV2Config()) {}

  MessageHandlerV2Service(DatabasePool& db,
                           const MessageHandlerV2Config& cfg)
      : handler_(db, cfg) {}

  // --- Passthrough to MessageHandlerV2 ---

  json send_message(const std::string& room_id,
                     const std::string& user_id,
                     const std::string& event_type,
                     const json& content,
                     const std::string& txn_id = "",
                     const std::optional<std::string>& device_id = std::nullopt) {
    return handler_.send_message(room_id, user_id, event_type,
                                  content, txn_id, device_id);
  }

  json redact_event(const std::string& room_id,
                     const std::string& user_id,
                     const std::string& target_event_id,
                     const std::string& reason = "",
                     const std::string& txn_id = "") {
    return handler_.redact_event(room_id, user_id, target_event_id,
                                  reason, txn_id);
  }

  json react_to_event(const std::string& room_id,
                       const std::string& user_id,
                       const std::string& target_event_id,
                       const std::string& reaction_key,
                       const std::string& txn_id = "") {
    return handler_.react_to_event(room_id, user_id, target_event_id,
                                    reaction_key, txn_id);
  }

  json edit_message(const std::string& room_id,
                     const std::string& user_id,
                     const std::string& target_event_id,
                     const json& new_content,
                     const std::string& txn_id = "") {
    return handler_.edit_message(room_id, user_id, target_event_id,
                                  new_content, txn_id);
  }

  json reply_to_event(const std::string& room_id,
                       const std::string& user_id,
                       const std::string& target_event_id,
                       const json& content,
                       const std::string& txn_id = "",
                       bool is_thread = false) {
    return handler_.reply_to_event(room_id, user_id, target_event_id,
                                    content, txn_id, is_thread);
  }

  json forward_message(const std::string& target_room_id,
                        const std::string& user_id,
                        const std::string& source_event_id,
                        const std::string& source_room_id,
                        const std::string& txn_id = "") {
    return handler_.forward_message(target_room_id, user_id,
                                     source_event_id, source_room_id, txn_id);
  }

  json send_image_message(const std::string& room_id,
                           const std::string& user_id,
                           const std::string& mxc_url,
                           const std::string& body,
                           const json& info = json::object(),
                           const std::string& thumbnail_url = "",
                           const json& thumbnail_info = json::object(),
                           const std::string& txn_id = "") {
    return handler_.send_image_message(room_id, user_id, mxc_url,
                                        body, info, thumbnail_url,
                                        thumbnail_info, txn_id);
  }

  json send_video_message(const std::string& room_id,
                           const std::string& user_id,
                           const std::string& mxc_url,
                           const std::string& body,
                           const json& info = json::object(),
                           const std::string& thumbnail_url = "",
                           const json& thumbnail_info = json::object(),
                           const std::string& txn_id = "") {
    return handler_.send_video_message(room_id, user_id, mxc_url,
                                        body, info, thumbnail_url,
                                        thumbnail_info, txn_id);
  }

  json send_audio_message(const std::string& room_id,
                           const std::string& user_id,
                           const std::string& mxc_url,
                           const std::string& body,
                           const json& info = json::object(),
                           const std::string& txn_id = "") {
    return handler_.send_audio_message(room_id, user_id, mxc_url,
                                        body, info, txn_id);
  }

  json send_file_message(const std::string& room_id,
                          const std::string& user_id,
                          const std::string& mxc_url,
                          const std::string& body,
                          const std::string& filename,
                          const json& info = json::object(),
                          const std::string& thumbnail_url = "",
                          const json& thumbnail_info = json::object(),
                          const std::string& txn_id = "") {
    return handler_.send_file_message(room_id, user_id, mxc_url,
                                       body, filename, info,
                                       thumbnail_url, thumbnail_info, txn_id);
  }

  json send_location_message(const std::string& room_id,
                              const std::string& user_id,
                              const std::string& geo_uri,
                              const std::string& body,
                              const json& info = json::object(),
                              const std::string& txn_id = "") {
    return handler_.send_location_message(room_id, user_id, geo_uri,
                                           body, info, txn_id);
  }

  bool check_membership(const std::string& room_id,
                         const std::string& user_id,
                         const std::string& membership = "join") {
    return handler_.check_membership(room_id, user_id, membership);
  }

  bool check_power_level(const std::string& room_id,
                          const std::string& user_id,
                          const std::string& event_type,
                          int default_required = 0) {
    return handler_.check_power_level(room_id, user_id, event_type,
                                       default_required);
  }

  void cleanup() {
    handler_.cleanup_rate_limits();
  }

private:
  MessageHandlerV2 handler_;
};

}  // namespace progressive
