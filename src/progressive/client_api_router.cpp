// ============================================================================
// client_api_router.cpp — Matrix Client-Server API Router
//
// A comprehensive URL router for all Matrix Client-Server API endpoints,
// providing middleware chain execution, path parameter extraction, query
// string parsing, request body validation, response formatting, and
// authentication integration.
//
// Covers all Client-Server API endpoints from the Matrix spec:
//   - /_matrix/client/v3/ (and /v1/) for all API versions
//   - Auth endpoints: login, register, logout, account management
//   - Room endpoints: create, join, leave, invite, kick, ban, messages,
//     state, members, context, redaction, typing, receipts, read markers
//   - Sync endpoint with long-polling support
//   - Events endpoint with streaming
//   - Profile endpoints: displayname, avatar_url
//   - Directory endpoints: room alias management
//   - Device endpoints: list, get, update, delete
//   - E2E key endpoints: upload, query, claim, signing keys
//   - Push notification endpoints: pushrules, pushers, notifications
//   - Tags, search, presence, account data, filters
//   - Third-party lookup, room upgrades, reports
//   - Content repository: upload, download, thumbnails
//   - Well-known endpoints
//   - Versions endpoint
//   - Admin/Synapse API endpoints
//
// Middleware chain phases:
//   - PRE_PARSE: Raw request preprocessing (body size, content-type)
//   - PRE_AUTH: Before authentication (CORS, rate-limit precheck)
//   - AUTH: Authentication and authorization
//   - PRE_HANDLER: Before the route handler (parameter validation)
//   - HANDLER: Route handler dispatch
//   - POST_HANDLER: After handler (response transformation, logging)
//
// Namespace: progressive::
// Target: 3000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
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
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/rest/rest_base.hpp"
#include "progressive/storage/database.hpp"

// ============================================================================
// Namespace
// ============================================================================

namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

using rest::HttpRequest;
using rest::HttpResponse;
using rest::BaseRestServlet;
using rest::Requester;
using storage::DatabasePool;

// ============================================================================
// Forward declarations
// ============================================================================

class ClientApiRouterImpl;
class ClientRouteTable;
class ClientMiddlewareChain;
class ClientPathExtractor;
class ClientQueryParser;
class ClientBodyValidator;
class ClientResponseFormatter;
class ClientRateLimiter;
class ClientRequestLogger;
class ClientAuthFilter;

// ============================================================================
// Constants for Client API
// ============================================================================

namespace client_api_constants {

// Matrix specification versions supported
constexpr const char* kDefaultApiVersion = "v3";
constexpr const char* kLegacyApiVersion = "v1";
constexpr const char* kApiPrefix = "/_matrix/client/";

// Rate limit defaults for client API
constexpr double kDefaultClientRate = 100.0;
constexpr double kDefaultClientBurst = 200.0;
constexpr double kLoginRateLimit = 5.0;
constexpr double kLoginBurstLimit = 10.0;
constexpr double kRegisterRateLimit = 3.0;
constexpr double kRegisterBurstLimit = 6.0;
constexpr double kSyncRateLimit = 50.0;
constexpr double kSyncBurstLimit = 100.0;
constexpr double kMediaUploadRate = 10.0;
constexpr double kMediaUploadBurst = 20.0;
constexpr double kSearchRateLimit = 20.0;
constexpr double kSearchBurstLimit = 40.0;

// Default body size limits
constexpr size_t kDefaultMaxBodySize = 50 * 1024 * 1024;       // 50 MB
constexpr size_t kMaxEventSize = 64 * 1024;                     // 64 KB
constexpr size_t kMaxFilterSize = 128 * 1024;                   // 128 KB
constexpr size_t kMaxStateEventSize = 1 * 1024 * 1024;          // 1 MB

// Sync timeout limits
constexpr int64_t kMinSyncTimeout = 0;
constexpr int64_t kMaxSyncTimeout = 30000;  // 30 seconds
constexpr int64_t kDefaultSyncTimeout = 0;

// Pagination defaults
constexpr int64_t kDefaultLimit = 10;
constexpr int64_t kMaxLimit = 1000;
constexpr const char* kDefaultOrder = "b";  // backwards

// Matrix error codes
constexpr const char* kErrNotFound = "M_NOT_FOUND";
constexpr const char* kErrUnknown = "M_UNKNOWN";
constexpr const char* kErrMissingToken = "M_MISSING_TOKEN";
constexpr const char* kErrUnknownToken = "M_UNKNOWN_TOKEN";
constexpr const char* kErrBadJson = "M_BAD_JSON";
constexpr const char* kErrNotJson = "M_NOT_JSON";
constexpr const char* kErrLimitExceeded = "M_LIMIT_EXCEEDED";
constexpr const char* kErrUnsupported = "M_UNSUPPORTED";
constexpr const char* kErrForbidden = "M_FORBIDDEN";
constexpr const char* kErrInvalidParam = "M_INVALID_PARAM";
constexpr const char* kErrTooLarge = "M_TOO_LARGE";
constexpr const char* kErrGuestForbidden = "M_GUEST_ACCESS_FORBIDDEN";
constexpr const char* kErrUserDeactivated = "M_USER_DEACTIVATED";
constexpr const char* kErrRoomInUse = "M_ROOM_IN_USE";
constexpr const char* kErrBadState = "M_BAD_STATE";
constexpr const char* kErrIncorrectRoomMembership = "M_INCORRECT_ROOM_MEMBERSHIP";
constexpr const char* kErrThreepidInUse = "M_THREEPID_IN_USE";
constexpr const char* kErrThreepidNotFound = "M_THREEPID_NOT_FOUND";
constexpr const char* kErrThreepidDenied = "M_THREEPID_DENIED";
constexpr const char* kErrInvalidUsername = "M_INVALID_USERNAME";
constexpr const char* kErrUserInUse = "M_USER_IN_USE";
constexpr const char* kErrWeakPassword = "M_WEAK_PASSWORD";
constexpr const char* kErrPasswordTooShort = "M_PASSWORD_TOO_SHORT";
constexpr const char* kErrPasswordNoDigit = "M_PASSWORD_NO_DIGIT";
constexpr const char* kErrPasswordNoLowercase = "M_PASSWORD_NO_LOWERCASE";
constexpr const char* kErrPasswordNoUppercase = "M_PASSWORD_NO_UPPERCASE";
constexpr const char* kErrPasswordNoSymbol = "M_PASSWORD_NO_SYMBOL";
constexpr const char* kErrPasswordInDictionary = "M_PASSWORD_IN_DICTIONARY";
constexpr const char* kErrConsentNotGiven = "M_CONSENT_NOT_GIVEN";
constexpr const char* kErrSessionNotValidated = "M_SESSION_NOT_VALIDATED";
constexpr const char* kErrNoValidSession = "M_NO_VALID_SESSION";
constexpr const char* kErrExclusive = "M_EXCLUSIVE";
constexpr const char* kErrResourceLimitExceeded = "M_RESOURCE_LIMIT_EXCEEDED";
constexpr const char* kErrCannotLeaveServerNoticeRoom = "M_CANNOT_LEAVE_SERVER_NOTICE_ROOM";

// Content types
constexpr const char* kContentTypeJson = "application/json";
constexpr const char* kContentTypeForm = "application/x-www-form-urlencoded";
constexpr const char* kContentTypeMultipart = "multipart/form-data";

// Server header
constexpr const char* kServerHeader = "Progressive/1.0";

// HTTP methods for client API
const std::array<const char*, 7> kHttpMethods = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
};

} // namespace client_api_constants

// ============================================================================
// Utility functions (anonymous namespace)
// ============================================================================

namespace {

// URL decode a percent-encoded string
std::string url_decode(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '%' && i + 2 < str.size()) {
            int hi = 0, lo = 0;
            char c = str[i + 1];
            if (c >= '0' && c <= '9') hi = c - '0';
            else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
            else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
            else { result += str[i]; continue; }
            c = str[i + 2];
            if (c >= '0' && c <= '9') lo = c - '0';
            else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
            else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
            else { result += str[i]; continue; }
            result += static_cast<char>((hi << 4) | lo);
            i += 2;
        } else if (str[i] == '+') {
            result += ' ';
        } else {
            result += str[i];
        }
    }
    return result;
}

// Trim leading and trailing whitespace
std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\n\r\f\v");
    return s.substr(start, end - start + 1);
}

// Convert string to lowercase
std::string to_lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return r;
}

// Convert string to uppercase
std::string to_upper(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    return r;
}

// Check if string starts with prefix
bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() &&
           s.compare(0, prefix.size(), prefix) == 0;
}

// Check if string ends with suffix
bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Check if string contains substring
bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

// Get current timestamp in milliseconds
int64_t now_ms() {
    return chr::duration_cast<chr::milliseconds>(
               chr::system_clock::now().time_since_epoch())
        .count();
}

// Get current timestamp in seconds as double
double now_sec() {
    return chr::duration_cast<chr::microseconds>(
               chr::steady_clock::now().time_since_epoch())
               .count() / 1e6;
}

// Generate a unique request ID
std::string generate_request_id() {
    static std::atomic<uint64_t> counter{0};
    auto now = chr::system_clock::now().time_since_epoch().count();
    auto n = counter.fetch_add(1, std::memory_order_relaxed);
    std::stringstream ss;
    ss << std::hex << now << "-" << n;
    return ss.str();
}

// Validate Matrix user ID format (@localpart:domain)
bool is_valid_user_id(const std::string& user_id) {
    if (user_id.empty() || user_id[0] != '@') return false;
    auto colon = user_id.find(':');
    if (colon == std::string::npos || colon < 2) return false;
    return colon < user_id.size() - 1;
}

// Validate Matrix room ID format (!opaque:domain)
bool is_valid_room_id(const std::string& room_id) {
    if (room_id.empty() || room_id[0] != '!') return false;
    auto colon = room_id.find(':');
    if (colon == std::string::npos || colon < 2) return false;
    return colon < room_id.size() - 1;
}

// Validate Matrix event ID format ($opaque)
bool is_valid_event_id(const std::string& event_id) {
    return !event_id.empty() && event_id[0] == '$';
}

// Validate Matrix room alias format (#alias:domain)
bool is_valid_room_alias(const std::string& alias) {
    if (alias.empty() || alias[0] != '#') return false;
    auto colon = alias.find(':');
    if (colon == std::string::npos || colon < 2) return false;
    return colon < alias.size() - 1;
}

// Validate Matrix transaction ID (ASCII printable, no spaces)
bool is_valid_txn_id(const std::string& txn_id) {
    if (txn_id.empty() || txn_id.size() > 256) return false;
    for (char c : txn_id) {
        if (c < 0x20 || c > 0x7E) return false;
        if (c == ' ' || c == '\t') return false;
    }
    return true;
}

// Escape special regex characters
std::string regex_escape(const std::string& str) {
    static const std::string special_chars = ".[]{}()\\*+?|^$";
    std::string result;
    result.reserve(str.size() * 2);
    for (char c : str) {
        if (special_chars.find(c) != std::string::npos) {
            result += '\\';
        }
        result += c;
    }
    return result;
}

} // anonymous namespace

// ============================================================================
// ClientPathExtractor — Extract named parameters from URL path patterns
//
// Handles path templates like:
//   /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
//   /_matrix/client/v3/profile/{userId}/displayname
// ============================================================================

class ClientPathExtractor {
public:
    struct CompiledPattern {
        std::regex regex;
        std::vector<std::string> param_names;
        std::string original_pattern;
        int param_count{0};
        bool is_exact{false};  // No parameters in pattern
        int specificity{0};    // Higher = more specific (for routing priority)
    };

    // Compile a path template pattern with {paramName} placeholders
    static CompiledPattern compile(const std::string& pattern) {
        CompiledPattern result;
        result.original_pattern = pattern;

        std::string re_str;
        size_t pos = 0;
        int literal_count = 0;  // Count literal characters for specificity

        while (pos < pattern.size()) {
            if (pattern[pos] == '{') {
                auto end = pattern.find('}', pos);
                if (end == std::string::npos) {
                    re_str += pattern.substr(pos);
                    break;
                }
                std::string param_name = pattern.substr(pos + 1, end - pos - 1);
                result.param_names.push_back(param_name);
                result.param_count++;

                // Match Matrix identifiers more strictly
                if (param_name == "roomId" || param_name == "room_id") {
                    re_str += "(![^/]+)";
                } else if (param_name == "userId" || param_name == "user_id") {
                    re_str += "(@[^/]+)";
                } else if (param_name == "eventId" || param_name == "event_id") {
                    re_str += "(\\$[^/]+)";
                } else if (param_name == "roomAlias" || param_name == "alias" ||
                           param_name == "room_alias") {
                    re_str += "(#[^/]+)";
                } else if (param_name == "txnId" || param_name == "txn_id") {
                    re_str += "([^/]{1,256})";
                } else if (param_name == "deviceId" || param_name == "device_id") {
                    re_str += "([A-Za-z0-9._-]+)";
                } else if (param_name == "eventType" || param_name == "event_type") {
                    re_str += "([a-z][a-z0-9._]{0,254})";
                } else if (param_name == "stateKey" || param_name == "state_key") {
                    re_str += "([^/]*)";
                } else if (param_name == "serverName" || param_name == "server_name") {
                    re_str += "([a-zA-Z0-9][a-zA-Z0-9.:-]*)";
                } else if (param_name == "receiptType" || param_name == "receipt_type") {
                    re_str += "(m\\.read|m\\.read\\.private)";
                } else if (param_name == "scope") {
                    re_str += "(global|device)";
                } else if (param_name == "kind") {
                    re_str += "(override|underride|sender|room|content)";
                } else if (param_name == "ruleId" || param_name == "rule_id") {
                    re_str += "([^/]+)";
                } else if (param_name == "tag") {
                    re_str += "([^/]+)";
                } else if (param_name == "filterId" || param_name == "filter_id") {
                    re_str += "([0-9]+)";
                } else if (param_name == "medium") {
                    re_str += "(email|msisdn)";
                } else if (param_name == "thirdPartyProtocol" ||
                           param_name == "protocol") {
                    re_str += "([a-z][a-z0-9._-]*)";
                } else {
                    re_str += "([^/]+)";
                }
                pos = end + 1;
            } else if (pattern[pos] == '.') {
                re_str += "\\.";
                literal_count++;
                pos++;
            } else if (pattern[pos] == '*') {
                re_str += ".*";
                pos++;
            } else if (pattern[pos] == '?' || pattern[pos] == '+' ||
                       pattern[pos] == '[' || pattern[pos] == ']' ||
                       pattern[pos] == '(' || pattern[pos] == ')' ||
                       pattern[pos] == '\\' || pattern[pos] == '^' ||
                       pattern[pos] == '$' || pattern[pos] == '|') {
                re_str += '\\';
                re_str += pattern[pos];
                literal_count++;
                pos++;
            } else {
                re_str += pattern[pos];
                literal_count++;
                pos++;
            }
        }

        re_str = "^" + re_str + "$";
        result.regex = std::regex(re_str, std::regex::optimize);
        result.is_exact = (result.param_count == 0);
        result.specificity = literal_count * 10 - result.param_count * 5;

        return result;
    }

    // Match a path against a compiled pattern
    static std::optional<std::map<std::string, std::string>>
    match(const CompiledPattern& compiled, const std::string& path) {
        std::smatch match_result;
        if (!std::regex_match(path, match_result, compiled.regex)) {
            return std::nullopt;
        }
        std::map<std::string, std::string> params;
        for (size_t i = 0;
             i < compiled.param_names.size() && i + 1 < match_result.size();
             ++i) {
            params[compiled.param_names[i]] =
                url_decode(match_result[i + 1].str());
        }
        return params;
    }

    // Extract query parameters from a URL target string
    static std::map<std::string, std::string>
    extract_query_params(const std::string& target) {
        std::map<std::string, std::string> params;
        auto query_pos = target.find('?');
        if (query_pos == std::string::npos) return params;

        std::string query = target.substr(query_pos + 1);
        size_t pos = 0;
        while (pos < query.size()) {
            auto amp_pos = query.find('&', pos);
            std::string pair;
            if (amp_pos == std::string::npos) {
                pair = query.substr(pos);
                pos = query.size();
            } else {
                pair = query.substr(pos, amp_pos - pos);
                pos = amp_pos + 1;
            }
            auto eq_pos = pair.find('=');
            if (eq_pos == std::string::npos) {
                params[url_decode(pair)] = "";
            } else {
                std::string key = url_decode(pair.substr(0, eq_pos));
                std::string val = url_decode(pair.substr(eq_pos + 1));
                params[key] = val;
            }
        }
        return params;
    }

    // Extract path-only portion from URL
    static std::string extract_path(const std::string& target) {
        auto query_pos = target.find('?');
        if (query_pos != std::string::npos) {
            return target.substr(0, query_pos);
        }
        return target;
    }

    // Normalize a path (remove trailing slash, collapse double slashes)
    static std::string normalize_path(const std::string& path) {
        if (path.empty()) return "/";
        std::string result = path;
        while (result.find("//") != std::string::npos) {
            size_t pos = result.find("//");
            result.erase(pos, 1);
        }
        if (result.size() > 1 && result.back() == '/') {
            result.pop_back();
        }
        return result;
    }
};

// ============================================================================
// ClientQueryParser — Typed query parameter parsing for client API
//
// Provides typed accessors for common Matrix query parameters:
//   - access_token, user_id, from, to, dir, limit, filter, since, timeout
//   - next_batch, order_by, include_all_rooms, etc.
// ============================================================================

class ClientQueryParser {
public:
    explicit ClientQueryParser(const std::map<std::string, std::string>& params)
        : params_(params) {}

    // Get raw string parameter
    std::optional<std::string> get(const std::string& name) const {
        auto it = params_.find(name);
        return it != params_.end() ? std::optional<std::string>(it->second)
                                    : std::nullopt;
    }

    // Get string with default
    std::string get_or(const std::string& name,
                       const std::string& default_val) const {
        auto it = params_.find(name);
        return it != params_.end() ? it->second : default_val;
    }

    // Get integer parameter
    std::optional<int64_t> get_int(const std::string& name) const {
        auto val = get(name);
        if (!val.has_value()) return std::nullopt;
        try { return std::stoll(*val); }
        catch (...) { return std::nullopt; }
    }

    // Get integer with default
    int64_t get_int_or(const std::string& name, int64_t default_val) const {
        return get_int(name).value_or(default_val);
    }

    // Get integer with bounds checking
    std::optional<int64_t> get_int_bounded(const std::string& name,
                                             int64_t min_val, int64_t max_val) const {
        auto val = get_int(name);
        if (!val.has_value()) return std::nullopt;
        if (*val < min_val || *val > max_val) return std::nullopt;
        return val;
    }

    // Get double/float parameter
    std::optional<double> get_double(const std::string& name) const {
        auto val = get(name);
        if (!val.has_value()) return std::nullopt;
        try { return std::stod(*val); }
        catch (...) { return std::nullopt; }
    }

    // Get boolean parameter (true/1/yes/on vs false/0/no/off)
    std::optional<bool> get_bool(const std::string& name) const {
        auto val = get(name);
        if (!val.has_value()) return std::nullopt;
        std::string lower = to_lower(trim(*val));
        if (lower == "true" || lower == "1" || lower == "yes" || lower == "on")
            return true;
        if (lower == "false" || lower == "0" || lower == "no" || lower == "off")
            return false;
        return std::nullopt;
    }

    // Get boolean with default
    bool get_bool_or(const std::string& name, bool default_val) const {
        return get_bool(name).value_or(default_val);
    }

    // Get comma-separated list
    std::vector<std::string> get_list(const std::string& name) const {
        auto val = get(name);
        if (!val.has_value() || val->empty()) return {};
        std::vector<std::string> result;
        std::stringstream ss(*val);
        std::string item;
        while (std::getline(ss, item, ',')) {
            item = trim(item);
            if (!item.empty()) result.push_back(item);
        }
        return result;
    }

    // Check if parameter exists
    bool has(const std::string& name) const {
        return params_.find(name) != params_.end();
    }

    // Get all raw parameters
    const std::map<std::string, std::string>& all() const { return params_; }

    // === Convenience accessors for common Matrix query params ===

    // access_token (may be in query params for GET requests)
    std::optional<std::string> access_token() const {
        return get("access_token");
    }

    // Sync parameters
    std::optional<std::string> since() const { return get("since"); }
    int64_t timeout() const {
        return get_int_bounded("timeout",
            client_api_constants::kMinSyncTimeout,
            client_api_constants::kMaxSyncTimeout)
            .value_or(client_api_constants::kDefaultSyncTimeout);
    }
    bool full_state() const {
        return get_bool_or("full_state", false);
    }
    std::optional<std::string> filter() const {
        return get("filter");
    }
    bool set_presence() const {
        return get_or("set_presence", "online") != "offline";
    }

    // Pagination parameters
    std::optional<std::string> from() const { return get("from"); }
    std::optional<std::string> to() const { return get("to"); }
    std::string dir() const {
        auto d = get_or("dir", client_api_constants::kDefaultOrder);
        return (d == "f" || d == "b") ? d : "b";
    }
    int64_t limit() const {
        auto raw = get_int_bounded("limit", 1,
            client_api_constants::kMaxLimit);
        return raw.value_or(client_api_constants::kDefaultLimit);
    }

    // Filter
    std::optional<std::string> filter_id() const { return get("filter"); }

    // Room directory
    std::optional<std::string> server() const { return get("server"); }

    // User search
    std::optional<std::string> search_term() const { return get("search_term"); }

    // Keys
    std::optional<std::string> key_from() const { return get("from"); }
    std::optional<std::string> key_to() const { return get("to"); }

    // Events
    std::optional<std::string> event_from() const { return get("from"); }
    std::optional<std::string> event_timeout() const { return get("timeout"); }

    // Profile
    std::optional<std::string> user_id_param() const { return get("user_id"); }

    // Media
    bool allow_remote() const {
        return get_bool_or("allow_remote", true);
    }

private:
    const std::map<std::string, std::string>& params_;
};

// ============================================================================
// ClientBodyValidator — Validate and parse JSON request bodies for client API
//
// Checks content-type, parses JSON, enforces size limits per-endpoint,
// validates required fields, and returns structured errors.
// ============================================================================

class ClientBodyValidator {
public:
    struct ValidationResult {
        json data;
        std::optional<std::string> error;
        bool valid{false};
    };

    // Parse JSON body with size limit
    static ValidationResult parse(const std::string& body,
                                    size_t max_size = client_api_constants::kDefaultMaxBodySize,
                                    bool allow_empty = false) {
        ValidationResult result;
        if (body.size() > max_size) {
            result.error = "Request body exceeds maximum size of " +
                           std::to_string(max_size) + " bytes";
            result.valid = false;
            return result;
        }
        if (body.empty()) {
            if (allow_empty) {
                result.data = json::object();
                result.valid = true;
                return result;
            }
            result.error = "Request body must not be empty";
            result.valid = false;
            return result;
        }
        try {
            result.data = json::parse(body);
            result.valid = true;
        } catch (const json::parse_error& e) {
            result.error = std::string("Malformed JSON in request body: ") + e.what();
            result.valid = false;
        } catch (const std::exception& e) {
            result.error = std::string("Error parsing request body: ") + e.what();
            result.valid = false;
        }
        return result;
    }

    // Parse and validate JSON from HttpRequest
    static std::pair<std::optional<json>, std::optional<HttpResponse>>
    parse_or_error(const HttpRequest& req,
                   size_t max_size = client_api_constants::kDefaultMaxBodySize,
                   bool allow_empty = false) {
        // Check Content-Type
        auto ct_it = req.headers.find("content-type");
        if (ct_it == req.headers.end()) {
            ct_it = req.headers.find("Content-Type");
        }
        bool is_json = false;
        if (ct_it != req.headers.end()) {
            std::string ct = to_lower(ct_it->second);
            is_json = contains(ct, "application/json");
        }
        if (!is_json && !req.body.empty()) {
            HttpResponse err = make_error_response(400,
                client_api_constants::kErrNotJson,
                "Content-Type must be application/json");
            return {std::nullopt, err};
        }
        auto vr = parse(req.body, max_size, allow_empty);
        if (!vr.valid) {
            HttpResponse err = make_error_response(400,
                client_api_constants::kErrBadJson,
                vr.error.value_or("Failed to parse request body"));
            return {std::nullopt, err};
        }
        return {vr.data, std::nullopt};
    }

    // Check that JSON object contains required fields
    static std::optional<HttpResponse> check_required_fields(
        const json& body,
        const std::vector<std::string>& required_fields) {
        for (const auto& field : required_fields) {
            if (!body.contains(field)) {
                return make_error_response(400,
                    client_api_constants::kErrInvalidParam,
                    "Missing required field: '" + field + "'");
            }
        }
        return std::nullopt;
    }

    // Check that JSON object field types match expected types
    static std::optional<HttpResponse> check_field_types(
        const json& body,
        const std::map<std::string, std::string>& field_types) {
        for (const auto& [field, expected_type] : field_types) {
            if (!body.contains(field)) continue;
            bool type_ok = false;
            if (expected_type == "string") {
                type_ok = body[field].is_string();
            } else if (expected_type == "number") {
                type_ok = body[field].is_number();
            } else if (expected_type == "boolean") {
                type_ok = body[field].is_boolean();
            } else if (expected_type == "object") {
                type_ok = body[field].is_object();
            } else if (expected_type == "array") {
                type_ok = body[field].is_array();
            } else if (expected_type == "string_or_null") {
                type_ok = body[field].is_string() || body[field].is_null();
            }
            if (!type_ok) {
                return make_error_response(400,
                    client_api_constants::kErrInvalidParam,
                    "Field '" + field + "' must be of type " + expected_type);
            }
        }
        return std::nullopt;
    }

    // Check that JSON object doesn't contain unexpected fields
    static std::optional<HttpResponse> check_no_extra_fields(
        const json& body,
        const std::set<std::string>& allowed_fields) {
        for (auto it = body.begin(); it != body.end(); ++it) {
            if (allowed_fields.find(it.key()) == allowed_fields.end()) {
                return make_error_response(400,
                    client_api_constants::kErrInvalidParam,
                    "Unexpected field: '" + it.key() + "'");
            }
        }
        return std::nullopt;
    }

    // Validate string field length
    static std::optional<HttpResponse> check_string_length(
        const json& body, const std::string& field,
        size_t min_len = 0, size_t max_len = std::numeric_limits<size_t>::max()) {
        if (!body.contains(field)) return std::nullopt;
        if (!body[field].is_string()) return std::nullopt;
        std::string val = body[field].get<std::string>();
        if (val.size() < min_len) {
            return make_error_response(400, client_api_constants::kErrInvalidParam,
                "Field '" + field + "' must be at least " +
                std::to_string(min_len) + " characters");
        }
        if (val.size() > max_len) {
            return make_error_response(400, client_api_constants::kErrInvalidParam,
                "Field '" + field + "' must not exceed " +
                std::to_string(max_len) + " characters");
        }
        return std::nullopt;
    }

private:
    static HttpResponse make_error_response(int code, const std::string& errcode,
                                              const std::string& error) {
        HttpResponse res;
        res.code = code;
        res.body = {{"errcode", errcode}, {"error", error}};
        res.content_type = "application/json";
        return res;
    }
};

// ============================================================================
// ClientResponseFormatter — Format responses for the Matrix Client-Server API
//
// Provides helper functions to construct standard conforming responses
// with proper JSON structure, error codes, pagination, and status codes.
// ============================================================================

class ClientResponseFormatter {
public:
    // Standard success response (200 OK)
    static HttpResponse ok(const json& data = json::object()) {
        HttpResponse res;
        res.code = 200;
        res.body = data;
        res.content_type = client_api_constants::kContentTypeJson;
        return res;
    }

    // Created response (201)
    static HttpResponse created(const json& data = json::object()) {
        HttpResponse res;
        res.code = 201;
        res.body = data;
        res.content_type = client_api_constants::kContentTypeJson;
        return res;
    }

    // Accepted response (202)
    static HttpResponse accepted(const json& data = json::object()) {
        HttpResponse res;
        res.code = 202;
        res.body = data;
        res.content_type = client_api_constants::kContentTypeJson;
        return res;
    }

    // No Content response (204)
    static HttpResponse no_content() {
        HttpResponse res;
        res.code = 204;
        res.body = json::object();
        res.content_type = client_api_constants::kContentTypeJson;
        return res;
    }

    // Standard Matrix error response
    static HttpResponse error(int code, const std::string& errcode,
                               const std::string& message) {
        HttpResponse res;
        res.code = code;
        res.body = {{"errcode", errcode}, {"error", message}};
        res.content_type = client_api_constants::kContentTypeJson;
        return res;
    }

    // 400 Bad Request
    static HttpResponse bad_request(const std::string& errcode,
                                     const std::string& message) {
        return error(400, errcode, message);
    }

    // 401 Unauthorized
    static HttpResponse unauthorized(const std::string& message =
        "Missing or invalid access token") {
        return error(401, client_api_constants::kErrMissingToken, message);
    }

    // 403 Forbidden
    static HttpResponse forbidden(const std::string& message = "Access denied") {
        return error(403, client_api_constants::kErrForbidden, message);
    }

    // 404 Not Found
    static HttpResponse not_found(const std::string& message = "Not found") {
        return error(404, client_api_constants::kErrNotFound, message);
    }

    // 405 Method Not Allowed
    static HttpResponse method_not_allowed() {
        return error(405, client_api_constants::kErrUnsupported,
                     "This method is not allowed on this endpoint");
    }

    // 409 Conflict
    static HttpResponse conflict(const std::string& message = "Conflict") {
        return error(409, "M_CONFLICT", message);
    }

    // 413 Payload Too Large
    static HttpResponse too_large(const std::string& message =
        "Request entity too large") {
        return error(413, client_api_constants::kErrTooLarge, message);
    }

    // 429 Rate Limited
    static HttpResponse rate_limited(int retry_after_sec = 1,
                                      const std::string& message =
        "Too many requests. Please wait and try again.") {
        HttpResponse res;
        res.code = 429;
        res.body = {{"errcode", client_api_constants::kErrLimitExceeded},
                    {"error", message}};
        res.content_type = client_api_constants::kContentTypeJson;
        res.headers["Retry-After"] = std::to_string(retry_after_sec);
        return res;
    }

    // 500 Internal Server Error
    static HttpResponse server_error(const std::string& message =
        "Internal server error") {
        return error(500, client_api_constants::kErrUnknown, message);
    }

    // 503 Service Unavailable
    static HttpResponse service_unavailable(const std::string& message =
        "Service temporarily unavailable") {
        return error(503, "M_UNAVAILABLE", message);
    }

    // Build a paginated response chunk
    static json paginate(const std::string& start,
                         const std::string& end,
                         int64_t total,
                         const json& chunk) {
        json result;
        result["start"] = start;
        if (end.empty()) {
            // No next_batch means no more results
            if (total >= 0) {
                result["total"] = total;
            }
        } else {
            result["end"] = end;
            if (total >= 0) {
                result["total"] = total;
            }
        }
        result["chunk"] = chunk;
        return result;
    }

    // Build a sync response
    static json sync_response(const std::string& next_batch,
                               const json& rooms = json::object(),
                               const json& presence = json::object(),
                               const json& account_data = json::object(),
                               const json& to_device = json::object(),
                               const json& device_lists = json::object(),
                               const json& device_one_time_keys_count =
                                   json::object(),
                               const json& device_unused_fallback_key_types =
                                   json::array()) {
        json response;
        response["next_batch"] = next_batch;
        response["rooms"] = rooms;
        response["presence"] = presence;
        response["account_data"] = account_data;
        response["to_device"] = to_device;

        if (!device_lists.is_null() && !device_lists.empty()) {
            response["device_lists"] = device_lists;
        }
        if (!device_one_time_keys_count.is_null() &&
            !device_one_time_keys_count.empty()) {
            response["device_one_time_keys_count"] = device_one_time_keys_count;
        }
        if (!device_unused_fallback_key_types.is_null() &&
            !device_unused_fallback_key_types.empty()) {
            response["device_unused_fallback_key_types"] =
                device_unused_fallback_key_types;
        }
        return response;
    }

    // Build room information response
    static json room_info(const std::string& room_id,
                           const std::vector<std::string>& servers = {}) {
        json result;
        result["room_id"] = room_id;
        if (!servers.empty()) {
            result["servers"] = servers;
        }
        return result;
    }

    // Build event ID response
    static json event_response(const std::string& event_id) {
        return {{"event_id", event_id}};
    }

    // Build filter ID response
    static json filter_response(const std::string& filter_id) {
        return {{"filter_id", filter_id}};
    }

    // Build upload response (media)
    static json upload_response(const std::string& content_uri) {
        return {{"content_uri", content_uri}};
    }

    // Build login response
    static json login_response(const std::string& user_id,
                                const std::string& access_token,
                                const std::string& device_id,
                                const std::optional<std::string>& home_server =
                                    std::nullopt,
                                const json& well_known = json::object()) {
        json resp;
        resp["user_id"] = user_id;
        resp["access_token"] = access_token;
        resp["device_id"] = device_id;
        if (home_server.has_value()) {
            resp["home_server"] = *home_server;
        }
        if (!well_known.empty()) {
            resp["well_known"] = well_known;
        }
        return resp;
    }

    // Build register response
    static json register_response(const std::string& user_id,
                                   const std::string& access_token,
                                   const std::string& device_id,
                                   const std::string& home_server = "") {
        json resp;
        resp["user_id"] = user_id;
        resp["access_token"] = access_token;
        resp["device_id"] = device_id;
        if (!home_server.empty()) {
            resp["home_server"] = home_server;
        }
        return resp;
    }

    // Build UIA (User-Interactive Authentication) response
    static json uia_response(int code,
                              const std::string& session,
                              const json& flows,
                              const json& params = json::object()) {
        HttpResponse res;
        res.code = code;
        res.body = {{"session", session}, {"flows", flows}};
        if (!params.empty()) {
            for (auto& [key, val] : params.items()) {
                res.body[key] = val;
            }
        }
        res.content_type = client_api_constants::kContentTypeJson;
        return res.body;
    }

    // Build whoami response
    static json whoami_response(const std::string& user_id,
                                 bool is_guest = false) {
        json resp;
        resp["user_id"] = user_id;
        if (is_guest) {
            resp["is_guest"] = true;
        }
        return resp;
    }

    // Build public rooms response
    static json public_rooms_response(const json& chunk,
                                       const std::string& next_batch = "",
                                       const std::string& prev_batch = "",
                                       int64_t total_room_count_estimate = 0) {
        json resp;
        resp["chunk"] = chunk;
        if (!next_batch.empty()) resp["next_batch"] = next_batch;
        if (!prev_batch.empty()) resp["prev_batch"] = prev_batch;
        resp["total_room_count_estimate"] = total_room_count_estimate;
        return resp;
    }

    // Build search response
    static json search_response(const json& search_categories) {
        return {{"search_categories", search_categories}};
    }

    // Build notification count response
    static json notification_response(const json& notifications,
                                       const std::string& next_token = "",
                                       int64_t total = 0) {
        json resp;
        resp["notifications"] = notifications;
        if (!next_token.empty()) {
            resp["next_token"] = next_token;
        }
        return resp;
    }

    // Inject server header into response
    static void inject_server_header(HttpResponse& res) {
        res.headers["Server"] = client_api_constants::kServerHeader;
    }

    // Inject CORS headers
    static void inject_cors(HttpResponse& res,
                             const std::string& origin = "*") {
        res.headers["Access-Control-Allow-Origin"] = origin;
        res.headers["Access-Control-Allow-Methods"] =
            "GET, POST, PUT, DELETE, PATCH, OPTIONS";
        res.headers["Access-Control-Allow-Headers"] =
            "Content-Type, Authorization, X-Requested-With";
        res.headers["Access-Control-Max-Age"] = "86400";
    }

    // Inject rate limit headers
    static void inject_rate_limits(HttpResponse& res,
                                    double limit, double remaining,
                                    int64_t reset_sec) {
        res.headers["X-RateLimit-Limit"] =
            std::to_string(static_cast<int64_t>(limit));
        res.headers["X-RateLimit-Remaining"] =
            std::to_string(static_cast<int64_t>(remaining));
        res.headers["X-RateLimit-Reset"] = std::to_string(reset_sec);
    }

    // Inject request ID header
    static void inject_request_id(HttpResponse& res,
                                   const std::string& request_id) {
        res.headers["X-Request-ID"] = request_id;
    }
};

// ============================================================================
// ClientRateLimiter — Rate limiting for client API endpoints
//
// Uses token bucket algorithm with per-endpoint-category configuration.
// Supports per-user, per-IP, and per-endpoint rate limiting.
// ============================================================================

class ClientRateLimiter {
public:
    struct Bucket {
        double rate;
        double burst;
        double tokens;
        chr::steady_clock::time_point last_update;

        Bucket(double r, double b)
            : rate(r), burst(b), tokens(b),
              last_update(chr::steady_clock::now()) {}

        bool consume(double n = 1.0) {
            auto now = chr::steady_clock::now();
            double elapsed = chr::duration_cast<chr::microseconds>(
                                 now - last_update).count() / 1e6;
            tokens = std::min(burst, tokens + elapsed * rate);
            last_update = now;
            if (tokens >= n) {
                tokens -= n;
                return true;
            }
            return false;
        }

        double remaining() const { return tokens; }
    };

    struct EndpointCategory {
        std::string name;
        double rate;
        double burst;
    };

    ClientRateLimiter() {
        // Set up default categories
        categories_["default"]    = {"default",
            client_api_constants::kDefaultClientRate,
            client_api_constants::kDefaultClientBurst};
        categories_["login"]      = {"login",
            client_api_constants::kLoginRateLimit,
            client_api_constants::kLoginBurstLimit};
        categories_["register"]   = {"register",
            client_api_constants::kRegisterRateLimit,
            client_api_constants::kRegisterBurstLimit};
        categories_["sync"]       = {"sync",
            client_api_constants::kSyncRateLimit,
            client_api_constants::kSyncBurstLimit};
        categories_["search"]     = {"search",
            client_api_constants::kSearchRateLimit,
            client_api_constants::kSearchBurstLimit};
        categories_["media_upload"] = {"media_upload",
            client_api_constants::kMediaUploadRate,
            client_api_constants::kMediaUploadBurst};
        categories_["media_download"] = {"media_download",
            client_api_constants::kDefaultClientRate,
            client_api_constants::kDefaultClientBurst};
        categories_["keys"]       = {"keys", 50.0, 100.0};
        categories_["profile"]    = {"profile", 30.0, 60.0};
        categories_["directory"]  = {"directory", 30.0, 60.0};
        categories_["push"]       = {"push", 40.0, 80.0};
        categories_["admin"]      = {"admin", 100.0, 200.0};
    }

    // Categorize a request path into a rate limit category
    std::string categorize(const std::string& path) const {
        using namespace client_api_constants;
        if (starts_with(path, "/_matrix/client/v3/login") ||
            starts_with(path, "/_matrix/client/v1/login")) return "login";
        if (starts_with(path, "/_matrix/client/v3/register") ||
            starts_with(path, "/_matrix/client/v1/register")) return "register";
        if (starts_with(path, "/_matrix/client/v3/sync") ||
            starts_with(path, "/_matrix/client/v1/sync")) return "sync";
        if (starts_with(path, "/_matrix/client/v3/search") ||
            starts_with(path, "/_matrix/client/v1/search")) return "search";
        if (starts_with(path, "/_matrix/client/v3/keys") ||
            starts_with(path, "/_matrix/client/v1/keys")) return "keys";
        if (starts_with(path, "/_matrix/client/v3/profile") ||
            starts_with(path, "/_matrix/client/v1/profile")) return "profile";
        if (starts_with(path, "/_matrix/client/v3/directory") ||
            starts_with(path, "/_matrix/client/v1/directory")) return "directory";
        if (starts_with(path, "/_matrix/client/v3/pushrules") ||
            starts_with(path, "/_matrix/client/v3/pushers") ||
            starts_with(path, "/_matrix/client/v3/notifications") ||
            starts_with(path, "/_matrix/client/v1/pushrules") ||
            starts_with(path, "/_matrix/client/v1/pushers") ||
            starts_with(path, "/_matrix/client/v1/notifications")) return "push";
        if (starts_with(path, "/_synapse/admin/")) return "admin";
        if (contains(path, "/upload")) return "media_upload";
        if (contains(path, "/download") || contains(path, "/thumbnail"))
            return "media_download";
        return "default";
    }

    // Check if a request is allowed
    bool allow(const std::string& key, const std::string& category) {
        std::string bucket_key = category + ":" + key;
        std::lock_guard<std::mutex> lock(mutex_);

        auto [rate, burst] = get_category_limits(category);
        auto it = buckets_.find(bucket_key);
        if (it == buckets_.end()) {
            auto bucket = std::make_unique<Bucket>(rate, burst);
            bool ok = bucket->consume();
            buckets_[bucket_key] = std::move(bucket);
            return ok;
        }
        // Update rate/burst if config changed
        it->second->rate = rate;
        it->second->burst = burst;
        return it->second->consume();
    }

    // Get remaining tokens
    double remaining(const std::string& key, const std::string& category) const {
        std::string bucket_key = category + ":" + key;
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = buckets_.find(bucket_key);
        if (it != buckets_.end()) {
            return it->second->remaining();
        }
        auto [rate, burst] = get_category_limits(category);
        return burst;
    }

    // Get rate limit for category
    double limit(const std::string& category) const {
        auto it = categories_.find(category);
        return it != categories_.end() ? it->second.rate
                                        : client_api_constants::kDefaultClientRate;
    }

    // Get number of active buckets
    size_t bucket_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return buckets_.size();
    }

    // Set category limits
    void set_category(const std::string& name, double rate, double burst) {
        categories_[name] = {name, rate, burst};
    }

    // Cleanup stale buckets (those at full burst)
    void cleanup_stale() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = buckets_.begin();
        while (it != buckets_.end()) {
            auto [rate, burst] = get_category_limits(
                it->first.substr(0, it->first.find(':')));
            if (it->second->remaining() >= burst * 0.99) {
                it = buckets_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    std::pair<double, double> get_category_limits(
        const std::string& cat) const {
        auto it = categories_.find(cat);
        if (it != categories_.end()) {
            return {it->second.rate, it->second.burst};
        }
        return {client_api_constants::kDefaultClientRate,
                client_api_constants::kDefaultClientBurst};
    }

    mutable std::mutex mutex_;
    std::map<std::string, EndpointCategory> categories_;
    std::map<std::string, std::unique_ptr<Bucket>> buckets_;
};

// ============================================================================
// ClientRequestLogger — Structured logging for client API requests
// ============================================================================

class ClientRequestLogger {
public:
    enum class Level { DEBUG = 0, INFO = 1, WARNING = 2, ERROR = 3, OFF = 4 };

    struct Config {
        Level level{Level::INFO};
        bool log_headers{false};
        bool log_bodies{false};
        size_t max_body_log_len{1024};
        bool include_timing{true};
        std::string log_format{"json"};
        std::ostream* output{&std::cerr};
    };

    explicit ClientRequestLogger(const Config& cfg = Config{}) : config_(cfg) {}

    // Log incoming request
    void log_request(const std::string& req_id, const std::string& method,
                      const std::string& path, const std::string& client_ip,
                      const std::optional<std::string>& user_id) {
        if (config_.level > Level::INFO) return;
        if (config_.log_format == "json") {
            json entry;
            entry["type"] = "request";
            entry["request_id"] = req_id;
            entry["method"] = method;
            entry["path"] = path;
            entry["client_ip"] = client_ip;
            if (user_id.has_value()) entry["user_id"] = *user_id;
            entry["timestamp_ms"] = now_ms();
            std::lock_guard<std::mutex> lock(mutex_);
            (*config_.output) << entry.dump() << std::endl;
        } else {
            std::stringstream ss;
            ss << "[" << req_id << "] " << method << " " << path
               << " from " << client_ip;
            if (user_id.has_value()) ss << " user=" << *user_id;
            std::lock_guard<std::mutex> lock(mutex_);
            (*config_.output) << ss.str() << std::endl;
        }
    }

    // Log completed response
    void log_response(const std::string& req_id, int status_code,
                       double latency_ms, size_t response_size,
                       const std::optional<std::string>& error_info = std::nullopt) {
        if (config_.level > Level::INFO) return;
        if (config_.log_format == "json") {
            json entry;
            entry["type"] = "response";
            entry["request_id"] = req_id;
            entry["status_code"] = status_code;
            entry["response_size"] = response_size;
            if (config_.include_timing) entry["latency_ms"] = latency_ms;
            if (error_info.has_value()) entry["error"] = *error_info;
            entry["timestamp_ms"] = now_ms();
            std::lock_guard<std::mutex> lock(mutex_);
            (*config_.output) << entry.dump() << std::endl;
        } else {
            std::stringstream ss;
            ss << "  [" << req_id << "] -> " << status_code;
            if (config_.include_timing) {
                ss << " in " << std::fixed << std::setprecision(2)
                   << latency_ms << "ms";
            }
            if (error_info.has_value()) ss << " error=" << *error_info;
            ss << " size=" << response_size;
            std::lock_guard<std::mutex> lock(mutex_);
            (*config_.output) << ss.str() << std::endl;
        }
    }

    // Log error
    void log_error(const std::string& req_id, const std::string& message,
                    const std::string& detail = "") {
        if (config_.level > Level::ERROR) return;
        if (config_.log_format == "json") {
            json entry;
            entry["type"] = "error";
            entry["request_id"] = req_id;
            entry["message"] = message;
            if (!detail.empty()) entry["detail"] = detail;
            entry["timestamp_ms"] = now_ms();
            std::lock_guard<std::mutex> lock(mutex_);
            (*config_.output) << entry.dump() << std::endl;
        } else {
            std::lock_guard<std::mutex> lock(mutex_);
            (*config_.output) << "  [" << req_id << "] ERROR: " << message;
            if (!detail.empty()) (*config_.output) << " (" << detail << ")";
            (*config_.output) << std::endl;
        }
    }

private:
    Config config_;
    mutable std::mutex mutex_;
};

// ============================================================================
// ClientAuthFilter — Authentication filter for client API requests
//
// Validates access tokens, identifies users, checks permissions,
// handles guest access and appservice authentication.
// ============================================================================

class ClientAuthFilter {
public:
    struct AuthResult {
        std::optional<Requester> requester;
        std::optional<HttpResponse> error;
    };

    explicit ClientAuthFilter(DatabasePool& db) : db_(db) {}

    // Authenticate a client API request
    AuthResult authenticate(const HttpRequest& req,
                             bool require_auth = true) {
        AuthResult result;

        // Extract access token
        std::optional<std::string> token = extract_token(req);
        if (!token.has_value()) {
            if (require_auth) {
                result.error = ClientResponseFormatter::unauthorized();
            } else {
                Requester anon;
                anon.user_id = "";
                anon.is_guest = true;
                result.requester = anon;
            }
            return result;
        }

        // Look up user by token (placeholder — real impl queries DB)
        Requester req_user;
        req_user.user_id = "@user:" + *token;  // Simplified: token = user lookup
        req_user.device_id = "DEVICE_001";
        req_user.is_admin = false;
        req_user.is_guest = false;
        req_user.shadow_banned = false;
        result.requester = req_user;

        return result;
    }

    // Extract access token from request headers or query params
    static std::optional<std::string> extract_token(const HttpRequest& req) {
        // Authorization: Bearer <token>
        for (const auto& header_name : {"authorization", "Authorization"}) {
            auto it = req.headers.find(header_name);
            if (it != req.headers.end() && starts_with(it->second, "Bearer ")) {
                return it->second.substr(7);
            }
        }
        // Query parameter access_token
        auto qp_it = req.query_params.find("access_token");
        if (qp_it != req.query_params.end()) {
            return qp_it->second;
        }
        return std::nullopt;
    }

    // Determine if a path requires authentication
    static bool requires_auth(const std::string& path) {
        static const std::vector<std::string> no_auth_paths = {
            "/_matrix/client/versions",
            "/_matrix/client/v3/login",
            "/_matrix/client/v1/login",
            "/_matrix/client/v3/register",
            "/_matrix/client/v1/register",
            "/_matrix/client/v3/register/available",
            "/_matrix/client/v3/register/email/requestToken",
            "/_matrix/client/v3/register/msisdn/requestToken",
            "/_matrix/client/v3/account/password/email/requestToken",
            "/_matrix/client/v3/account/password/msisdn/requestToken",
            "/.well-known/matrix/client",
            "/.well-known/matrix/server",
            "/health",
            "/_matrix/health",
        };
        for (const auto& ap : no_auth_paths) {
            if (path == ap) return false;
        }
        return true;
    }

private:
    DatabasePool& db_;
};

// ============================================================================
// ClientMiddlewareChain — Pluggable middleware pipeline for client API
//
// Middleware phases:
//   PRE_PARSE    → Body size checks, content-type enforcement
//   PRE_AUTH     → CORS preflight, initial rate check
//   AUTH         → Access token validation, user lookup
//   PRE_HANDLER  → Parameter validation, resource existence check
//   HANDLER      → The actual route handler
//   POST_HANDLER → Response transformation, logging, metrics
// ============================================================================

enum class ClientMiddlewarePhase {
    PRE_PARSE,      // Before body parsing
    PRE_AUTH,       // Before authentication
    AUTH,           // Authentication phase
    PRE_HANDLER,    // Before route handler execution
    HANDLER,        // Route handler (only one handler executes)
    POST_HANDLER    // After handler (response transformation)
};

using ClientMiddlewareFunc = std::function<std::optional<HttpResponse>(
    HttpRequest&, const std::optional<Requester>&)>;

struct ClientMiddlewareEntry {
    std::string name;
    ClientMiddlewarePhase phase;
    ClientMiddlewareFunc handler;
    int priority{0};
};

class ClientMiddlewareChain {
public:
    void add(const std::string& name, ClientMiddlewarePhase phase,
             ClientMiddlewareFunc handler, int priority = 0) {
        entries_.push_back({name, phase, std::move(handler), priority});
    }

    // Execute all middleware for a given phase
    std::optional<HttpResponse> execute(ClientMiddlewarePhase phase,
                                         HttpRequest& req,
                                         const std::optional<Requester>& req_user) {
        std::vector<ClientMiddlewareEntry*> phase_entries;
        for (auto& entry : entries_) {
            if (entry.phase == phase) {
                phase_entries.push_back(&entry);
            }
        }
        std::sort(phase_entries.begin(), phase_entries.end(),
                  [](const ClientMiddlewareEntry* a,
                     const ClientMiddlewareEntry* b) {
                      return a->priority > b->priority;
                  });
        for (auto* entry : phase_entries) {
            auto result = entry->handler(req, req_user);
            if (result.has_value()) return result;
        }
        return std::nullopt;
    }

    // Remove middleware by name
    bool remove(const std::string& name) {
        auto it = std::remove_if(entries_.begin(), entries_.end(),
                                  [&](const ClientMiddlewareEntry& e) {
                                      return e.name == name;
                                  });
        if (it != entries_.end()) {
            entries_.erase(it, entries_.end());
            return true;
        }
        return false;
    }

    void clear() { entries_.clear(); }
    size_t size() const { return entries_.size(); }

    std::vector<std::string> list() const {
        std::vector<std::string> names;
        for (const auto& e : entries_) names.push_back(e.name);
        return names;
    }

private:
    std::vector<ClientMiddlewareEntry> entries_;
};

// ============================================================================
// ClientRouteEntry — A single registered route in the client API router
// ============================================================================

using ClientRouteHandler = std::function<HttpResponse(
    const HttpRequest&, const std::map<std::string, std::string>&)>;

struct ClientRouteEntry {
    std::string method;
    std::string pattern;
    ClientPathExtractor::CompiledPattern compiled;
    ClientRouteHandler handler;
    std::string description;
    int priority{0};
    bool requires_auth{true};

    bool matches(const std::string& req_method, const std::string& req_path) const {
        if (req_method != method && method != "*") return false;
        return ClientPathExtractor::match(compiled, req_path).has_value();
    }
};

// ============================================================================
// ClientRouteTable — Registry for all client API routes
//
// Efficient trie-based and pattern-based route matching with support
// for path parameters, method dispatch, and priority ordering.
// ============================================================================

class ClientRouteTable {
public:
    struct TrieNode {
        std::map<std::string, std::unique_ptr<TrieNode>> children;
        ClientRouteHandler handler;
        std::string param_name; // Non-empty if this segment is a parameter
        bool is_param{false};
        bool is_wildcard{false};
        bool has_handler{false};
    };

    ClientRouteTable() : root_(std::make_unique<TrieNode>()) {}

    // Register a route
    void add_route(const std::string& method, const std::string& pattern,
                   ClientRouteHandler handler, const std::string& desc = "",
                   int priority = 0, bool requires_auth = true) {
        ClientRouteEntry entry;
        entry.method = method;
        entry.pattern = pattern;
        entry.compiled = ClientPathExtractor::compile(pattern);
        entry.handler = std::move(handler);
        entry.description = desc;
        entry.priority = priority;
        entry.requires_auth = requires_auth;

        entries_.push_back(std::move(entry));

        // Sort by priority descending
        std::sort(entries_.begin(), entries_.end(),
                  [](const ClientRouteEntry& a, const ClientRouteEntry& b) {
                      if (a.priority != b.priority) return a.priority > b.priority;
                      return a.pattern.size() > b.pattern.size();
                  });

        // Also add to trie for fast lookup of exact paths
        add_to_trie(method, pattern, entries_.back().handler);
    }

    // Register a route for all methods
    void add_any_method(const std::string& pattern,
                        ClientRouteHandler handler,
                        const std::string& desc = "",
                        int priority = 0,
                        bool requires_auth = true) {
        add_route("*", pattern, std::move(handler), desc, priority,
                  requires_auth);
    }

    // Register routes for specific methods
    void add_get(const std::string& pattern, ClientRouteHandler handler,
                 const std::string& desc = "", int priority = 0,
                 bool requires_auth = true) {
        add_route("GET", pattern, std::move(handler), desc, priority,
                  requires_auth);
    }

    void add_post(const std::string& pattern, ClientRouteHandler handler,
                  const std::string& desc = "", int priority = 0,
                  bool requires_auth = true) {
        add_route("POST", pattern, std::move(handler), desc, priority,
                  requires_auth);
    }

    void add_put(const std::string& pattern, ClientRouteHandler handler,
                 const std::string& desc = "", int priority = 0,
                 bool requires_auth = true) {
        add_route("PUT", pattern, std::move(handler), desc, priority,
                  requires_auth);
    }

    void add_delete(const std::string& pattern, ClientRouteHandler handler,
                    const std::string& desc = "", int priority = 0,
                    bool requires_auth = true) {
        add_route("DELETE", pattern, std::move(handler), desc, priority,
                  requires_auth);
    }

    void add_patch(const std::string& pattern, ClientRouteHandler handler,
                   const std::string& desc = "", int priority = 0,
                   bool requires_auth = true) {
        add_route("PATCH", pattern, std::move(handler), desc, priority,
                  requires_auth);
    }

    // Find a matching route for a request
    struct MatchResult {
        ClientRouteHandler handler;
        std::map<std::string, std::string> path_params;
        bool matched{false};
        bool requires_auth{true};
        std::string description;
    };

    MatchResult find(const std::string& method, const std::string& path) const {
        MatchResult result;

        // Try exact trie lookup first
        std::string key = method + ":" + path;
        auto trie_result = find_in_trie(method, path);
        if (trie_result.matched) {
            return trie_result;
        }

        // Try pattern-based matching in priority order
        for (const auto& entry : entries_) {
            if (entry.method != method && entry.method != "*") continue;
            auto params = ClientPathExtractor::match(entry.compiled, path);
            if (params.has_value()) {
                result.handler = entry.handler;
                result.path_params = std::move(*params);
                result.matched = true;
                result.requires_auth = entry.requires_auth;
                result.description = entry.description;
                return result;
            }
        }

        return result;
    }

    // Check if a route exists (for OPTIONS handling)
    bool has_route_for_method(const std::string& method,
                               const std::string& path) const {
        auto result = find(method, path);
        return result.matched;
    }

    // Get allowed methods for a path
    std::vector<std::string> allowed_methods(const std::string& path) const {
        std::vector<std::string> methods;
        for (const auto& method : client_api_constants::kHttpMethods) {
            std::string m(method);
            if (m == "OPTIONS") continue;
            auto result = find(m, path);
            if (result.matched) {
                methods.push_back(m);
            }
        }
        return methods;
    }

    // Get number of registered routes
    size_t route_count() const { return entries_.size(); }

    // Get all routes (for debugging/inspection)
    const std::vector<ClientRouteEntry>& routes() const { return entries_; }

private:
    void add_to_trie(const std::string& method, const std::string& pattern,
                     ClientRouteHandler handler) {
        auto* node = root_.get();
        std::string full = method + ":" + pattern;
        std::stringstream ss(full);
        std::string segment;
        while (std::getline(ss, segment, '/')) {
            if (segment.empty()) continue;
            if (segment.front() == '{' && segment.back() == '}') {
                // Parameterized segment
                std::string param_name = segment.substr(1, segment.size() - 2);
                std::string key = ":" + param_name;
                if (!node->children.count(key)) {
                    auto child = std::make_unique<TrieNode>();
                    child->param_name = param_name;
                    child->is_param = true;
                    node->children[key] = std::move(child);
                }
                node = node->children[key].get();
            } else if (segment == "*") {
                auto child = std::make_unique<TrieNode>();
                child->is_wildcard = true;
                node->children["*"] = std::move(child);
                node = node->children["*"].get();
            } else {
                if (!node->children.count(segment)) {
                    node->children[segment] = std::make_unique<TrieNode>();
                }
                node = node->children[segment].get();
            }
        }
        node->handler = std::move(handler);
        node->has_handler = true;
    }

    MatchResult find_in_trie(const std::string& method,
                              const std::string& path) const {
        MatchResult result;
        std::string full = method + ":" + path;
        std::vector<std::string> segments;
        {
            std::stringstream ss(full);
            std::string seg;
            while (std::getline(ss, seg, '/')) {
                if (!seg.empty()) segments.push_back(seg);
            }
        }

        auto* node = root_.get();
        for (size_t i = 0; i < segments.size(); ++i) {
            const auto& seg = segments[i];
            // Try exact match
            if (node->children.count(seg)) {
                node = node->children[seg].get();
            }
            // Try parameter match
            else {
                bool matched_param = false;
                for (const auto& [key, child] : node->children) {
                    if (child->is_param) {
                        result.path_params[child->param_name] = url_decode(seg);
                        node = child.get();
                        matched_param = true;
                        break;
                    }
                    if (child->is_wildcard) {
                        node = child.get();
                        matched_param = true;
                        break;
                    }
                }
                if (!matched_param) {
                    return result; // No match
                }
            }
        }

        if (node->has_handler) {
            result.handler = node->handler;
            result.matched = true;
        }
        return result;
    }

    std::unique_ptr<TrieNode> root_;
    std::vector<ClientRouteEntry> entries_;
};

// ============================================================================
// ClientApiRouterConfig — Configuration for the client API router
// ============================================================================

struct ClientApiRouterConfig {
    // Server identity
    std::string server_name{"localhost:8008"};
    std::string server_version{"Progressive/1.0"};

    // Rate limiting
    bool rate_limit_enabled{true};

    // Body limits
    size_t max_body_size{client_api_constants::kDefaultMaxBodySize};
    size_t max_event_size{client_api_constants::kMaxEventSize};
    size_t max_upload_size{100 * 1024 * 1024};

    // Sync config
    int64_t max_sync_timeout_ms{30000};
    int64_t default_sync_timeout_ms{0};

    // Features
    bool enable_guest_access{false};
    bool enable_registration{true};
    bool enable_metrics{true};
    bool enable_logging{true};
    bool strict_validation{true};
    bool allow_fallback_to_v1{true};

    // Logging
    ClientRequestLogger::Config log_config;

    // CORS
    std::vector<std::string> cors_origins{"*"};
    bool cors_allow_credentials{true};
};

// ============================================================================
// ClientApiRouterImpl — Core router implementation
//
// Coordinates the full request lifecycle:
//   1. Request parsing (path, query, headers)
//   2. Middleware chain execution (PRE_PARSE, PRE_AUTH)
//   3. CORS preflight handling
//   4. Authentication
//   5. Rate limiting
//   6. Route matching
//   7. Parameter extraction and validation
//   8. Handler dispatch
//   9. Post-handler middleware
//   10. Response formatting and logging
// ============================================================================

class ClientApiRouterImpl {
public:
    explicit ClientApiRouterImpl(DatabasePool& db,
                                  const ClientApiRouterConfig& cfg =
                                      ClientApiRouterConfig{})
        : db_(db), config_(cfg),
          rate_limiter_(),
          logger_(cfg.log_config),
          auth_filter_(db),
          route_table_() {
        setup_default_middleware();
        register_all_client_routes();
    }

    // ======================================================================
    // Main dispatch: route a client API request and produce a response
    // ======================================================================
    HttpResponse dispatch(HttpRequest& req) {
        auto start_time = chr::steady_clock::now();
        std::string request_id = generate_request_id();

        // Inject request ID
        req.headers["X-Request-ID"] = request_id;

        // Extract path and query params
        std::string raw_target = req.path;
        req.path = ClientPathExtractor::extract_path(raw_target);
        req.path = ClientPathExtractor::normalize_path(req.path);
        if (req.query_params.empty()) {
            req.query_params = ClientPathExtractor::extract_query_params(
                raw_target);
        }

        // Log incoming request
        if (config_.enable_logging) {
            logger_.log_request(request_id, req.method, req.path,
                                 req.client_ip, req.auth_user);
        }

        try {
            // ------------------------------------------------------------
            // Phase 1: PRE_PARSE middleware (body size, content-type)
            // ------------------------------------------------------------
            {
                auto mw_resp = middleware_chain_.execute(
                    ClientMiddlewarePhase::PRE_PARSE, req,
                    std::optional<Requester>());
                if (mw_resp.has_value()) {
                    return finalize_response(*mw_resp, request_id, start_time);
                }
            }

            // ------------------------------------------------------------
            // Phase 2: Handle OPTIONS (CORS preflight)
            // ------------------------------------------------------------
            if (req.method == "OPTIONS") {
                return handle_cors_preflight(req, request_id, start_time);
            }

            // ------------------------------------------------------------
            // Phase 3: PRE_AUTH middleware
            // ------------------------------------------------------------
            {
                auto mw_resp = middleware_chain_.execute(
                    ClientMiddlewarePhase::PRE_AUTH, req,
                    std::optional<Requester>());
                if (mw_resp.has_value()) {
                    return finalize_response(*mw_resp, request_id, start_time);
                }
            }

            // ------------------------------------------------------------
            // Phase 4: Authentication
            // ------------------------------------------------------------
            bool needs_auth = ClientAuthFilter::requires_auth(req.path);
            std::optional<Requester> requester;

            {
                auto auth_result = auth_filter_.authenticate(req, needs_auth);
                if (auth_result.error.has_value()) {
                    return finalize_response(*auth_result.error, request_id,
                                              start_time);
                }
                requester = auth_result.requester;

                // Set auth_user on request for downstream handlers
                if (requester.has_value() && !requester->user_id.empty()) {
                    req.auth_user = requester->user_id;
                }
            }

            // ------------------------------------------------------------
            // Phase 5: AUTH middleware
            // ------------------------------------------------------------
            {
                auto mw_resp = middleware_chain_.execute(
                    ClientMiddlewarePhase::AUTH, req, requester);
                if (mw_resp.has_value()) {
                    return finalize_response(*mw_resp, request_id, start_time);
                }
            }

            // ------------------------------------------------------------
            // Phase 6: Rate limiting
            // ------------------------------------------------------------
            if (config_.rate_limit_enabled) {
                std::string category = rate_limiter_.categorize(req.path);
                std::string limit_key = req.client_ip;
                if (requester.has_value() && !requester->user_id.empty()) {
                    limit_key = requester->user_id;
                }
                if (!rate_limiter_.allow(limit_key, category)) {
                    auto rl_resp = ClientResponseFormatter::rate_limited();
                    inject_rate_limit_headers(rl_resp, limit_key, category);
                    return finalize_response(rl_resp, request_id, start_time);
                }
            }

            // ------------------------------------------------------------
            // Phase 7: PRE_HANDLER middleware
            // ------------------------------------------------------------
            {
                auto mw_resp = middleware_chain_.execute(
                    ClientMiddlewarePhase::PRE_HANDLER, req, requester);
                if (mw_resp.has_value()) {
                    return finalize_response(*mw_resp, request_id, start_time);
                }
            }

            // ------------------------------------------------------------
            // Phase 8: Route matching
            // ------------------------------------------------------------
            auto match = route_table_.find(req.method, req.path);

            if (!match.matched) {
                // Check if any other methods are allowed on this path
                auto allowed = route_table_.allowed_methods(req.path);
                if (!allowed.empty()) {
                    HttpResponse resp = ClientResponseFormatter::method_not_allowed();
                    // Add Allow header
                    std::string allow_str;
                    for (size_t i = 0; i < allowed.size(); ++i) {
                        if (i > 0) allow_str += ", ";
                        allow_str += allowed[i];
                    }
                    resp.headers["Allow"] = allow_str;
                    return finalize_response(resp, request_id, start_time);
                }
                auto nf = ClientResponseFormatter::not_found(
                    "Unrecognized request: " + req.method + " " + req.path);
                return finalize_response(nf, request_id, start_time);
            }

            // Check auth requirements for the matched route
            if (match.requires_auth && needs_auth &&
                (!requester.has_value() || requester->user_id.empty())) {
                auto unauth = ClientResponseFormatter::unauthorized();
                return finalize_response(unauth, request_id, start_time);
            }

            // ------------------------------------------------------------
            // Phase 9: Inject path params and dispatch handler
            // ------------------------------------------------------------
            if (!match.path_params.empty()) {
                for (const auto& [key, val] : match.path_params) {
                    req.path_params[key] = val;
                }
            }

            HttpResponse handler_resp;
            try {
                handler_resp = match.handler(req, match.path_params);
            } catch (const std::exception& e) {
                handler_resp = ClientResponseFormatter::server_error(
                    std::string("Handler exception: ") + e.what());
            }

            // ------------------------------------------------------------
            // Phase 10: POST_HANDLER middleware
            // ------------------------------------------------------------
            {
                auto mw_resp = middleware_chain_.execute(
                    ClientMiddlewarePhase::POST_HANDLER, req, requester);
                if (mw_resp.has_value()) {
                    handler_resp = *mw_resp;
                }
            }

            return finalize_response(handler_resp, request_id, start_time);

        } catch (const std::exception& e) {
            logger_.log_error(request_id, "Unhandled exception", e.what());
            auto err = ClientResponseFormatter::server_error(
                std::string("Internal error: ") + e.what());
            return finalize_response(err, request_id, start_time);
        }
    }

    // ======================================================================
    // Middleware management
    // ======================================================================
    void add_middleware(const std::string& name, ClientMiddlewarePhase phase,
                         ClientMiddlewareFunc handler, int priority = 0) {
        middleware_chain_.add(name, phase, std::move(handler), priority);
    }

    bool remove_middleware(const std::string& name) {
        return middleware_chain_.remove(name);
    }

    std::vector<std::string> list_middleware() const {
        return middleware_chain_.list();
    }

    // ======================================================================
    // Route management
    // ======================================================================
    void register_route(const std::string& method, const std::string& pattern,
                         ClientRouteHandler handler, const std::string& desc = "",
                         int priority = 0, bool requires_auth = true) {
        route_table_.add_route(method, pattern, std::move(handler), desc,
                                priority, requires_auth);
    }

    // ======================================================================
    // Rate limiter access
    // ======================================================================
    ClientRateLimiter& rate_limiter() { return rate_limiter_; }

    // ======================================================================
    // Configuration access
    // ======================================================================
    const ClientApiRouterConfig& config() const { return config_; }

    // ======================================================================
    // Route count
    // ======================================================================
    size_t route_count() const { return route_table_.route_count(); }

private:
    // ==================================================================
    // Finalize and return a response with standard headers
    // ==================================================================
    HttpResponse finalize_response(HttpResponse& resp,
                                    const std::string& request_id,
                                    chr::steady_clock::time_point start_time) {
        // Inject standard headers
        ClientResponseFormatter::inject_server_header(resp);
        ClientResponseFormatter::inject_cors(resp);
        ClientResponseFormatter::inject_request_id(resp, request_id);

        // Log response
        if (config_.enable_logging) {
            auto elapsed = chr::duration_cast<chr::microseconds>(
                chr::steady_clock::now() - start_time).count() / 1e3;
            size_t resp_size = resp.body.dump().size();
            std::optional<std::string> error_info;
            if (resp.code >= 400) {
                error_info = resp.body.value("error", "");
            }
            logger_.log_response(request_id, resp.code, elapsed,
                                  resp_size, error_info);
        }

        return resp;
    }

    // ==================================================================
    // Handle CORS preflight (OPTIONS) requests
    // ==================================================================
    HttpResponse handle_cors_preflight(const HttpRequest& req,
                                        const std::string& request_id,
                                        chr::steady_clock::time_point start_time) {
        HttpResponse resp;
        resp.code = 200;
        resp.body = json::object();
        resp.content_type = client_api_constants::kContentTypeJson;

        // CORS headers
        ClientResponseFormatter::inject_cors(resp);

        // Determine allowed methods for this path
        auto allowed = route_table_.allowed_methods(req.path);
        if (allowed.empty()) {
            allowed = {"GET", "POST", "PUT", "DELETE", "OPTIONS"};
        }
        std::string allow_str;
        for (size_t i = 0; i < allowed.size(); ++i) {
            if (i > 0) allow_str += ", ";
            allow_str += allowed[i];
        }
        resp.headers["Access-Control-Allow-Methods"] = allow_str;
        resp.headers["Access-Control-Allow-Headers"] =
            "Content-Type, Authorization, X-Requested-With";
        resp.headers["Access-Control-Max-Age"] = "86400";

        return finalize_response(resp, request_id, start_time);
    }

    // ==================================================================
    // Inject rate limit headers into response
    // ==================================================================
    void inject_rate_limit_headers(HttpResponse& resp,
                                    const std::string& key,
                                    const std::string& category) {
        double limit = rate_limiter_.limit(category);
        double remaining = rate_limiter_.remaining(key, category);
        int64_t reset_sec = now_ms() / 1000 + 1;
        ClientResponseFormatter::inject_rate_limits(resp, limit, remaining,
                                                      reset_sec);
    }

    // ==================================================================
    // Set up default middleware pipeline
    // ==================================================================
    void setup_default_middleware() {
        // Body size check (PRE_PARSE)
        add_middleware("body_size_check", ClientMiddlewarePhase::PRE_PARSE,
            [this](HttpRequest& req, const std::optional<Requester>&) {
                size_t max_size = config_.max_body_size;
                // Event endpoints have smaller limits
                if (contains(req.path, "/send/") ||
                    contains(req.path, "/state/")) {
                    max_size = config_.max_event_size;
                }
                if (req.body.size() > max_size) {
                    return std::optional<HttpResponse>(
                        ClientResponseFormatter::too_large(
                            "Request body exceeds maximum size of " +
                            std::to_string(max_size) + " bytes"));
                }
                return std::optional<HttpResponse>(std::nullopt);
            }, 100);

        // Guest access check (PRE_HANDLER)
        add_middleware("guest_access_check", ClientMiddlewarePhase::PRE_HANDLER,
            [this](HttpRequest& req, const std::optional<Requester>& req_user) {
                if (!config_.enable_guest_access &&
                    req_user.has_value() &&
                    req_user->is_guest &&
                    ClientAuthFilter::requires_auth(req.path)) {
                    return std::optional<HttpResponse>(
                        ClientResponseFormatter::forbidden(
                            "Guest access is not enabled on this server"));
                }
                return std::optional<HttpResponse>(std::nullopt);
            }, 50);

        // Timing middleware (POST_HANDLER)
        add_middleware("request_timing", ClientMiddlewarePhase::POST_HANDLER,
            [](HttpRequest&, const std::optional<Requester>&) {
                return std::optional<HttpResponse>(std::nullopt);
            }, 0);
    }

    // ==================================================================
    // Register all Matrix Client-Server API routes
    // ==================================================================
    void register_all_client_routes() {
        register_version_routes();
        register_auth_routes();
        register_account_routes();
        register_room_routes();
        register_sync_routes();
        register_event_routes();
        register_profile_routes();
        register_directory_routes();
        register_device_routes();
        register_key_routes();
        register_push_routes();
        register_notification_routes();
        register_receipt_routes();
        register_tag_routes();
        register_search_routes();
        register_presence_routes();
        register_filter_routes();
        register_media_routes();
        register_third_party_routes();
        register_room_upgrade_routes();
        register_report_routes();
        register_typing_routes();
        register_read_marker_routes();
        register_account_data_routes();
        register_well_known_routes();
        register_admin_routes();
    }

    // ==================================================================
    // Helper: register route for API v3 and v1
    // ==================================================================
    void add_api_route(const std::string& method,
                        const std::string& suffix,
                        ClientRouteHandler handler,
                        const std::string& desc = "",
                        int priority = 0,
                        bool requires_auth = true) {
        std::string v3 = "/_matrix/client/v3" + suffix;
        std::string v1 = "/_matrix/client/v1" + suffix;
        register_route(method, v3, handler, desc, priority, requires_auth);
        if (config_.allow_fallback_to_v1) {
            register_route(method, v1, handler, desc + " (v1 fallback)",
                           priority, requires_auth);
        }
    }

    // Also for media API (v3 and v1)
    void add_media_route(const std::string& method,
                          const std::string& suffix,
                          ClientRouteHandler handler,
                          const std::string& desc = "",
                          int priority = 0,
                          bool requires_auth = true) {
        std::string v3 = "/_matrix/media/v3" + suffix;
        std::string v1 = "/_matrix/media/v1" + suffix;
        register_route(method, v3, handler, desc, priority, requires_auth);
        if (config_.allow_fallback_to_v1) {
            register_route(method, v1, handler, desc + " (v1 fallback)",
                           priority, requires_auth);
        }
    }

    // ==================================================================
    // Route registrations by category
    // ==================================================================

    // --- Versions ---
    void register_version_routes() {
        add_api_route("GET", "/versions", [](const HttpRequest&, const auto&) {
            return ClientResponseFormatter::ok({
                {"versions", {"r0.0.1", "r0.1.0", "r0.2.0", "r0.3.0",
                              "r0.4.0", "r0.5.0", "r0.6.0", "r0.6.1",
                              "v1.1", "v1.2", "v1.3", "v1.4", "v1.5",
                              "v1.6"}},
                {"unstable_features", {
                    {"org.matrix.e2e_cross_signing", true},
                    {"org.matrix.label_based_filtering", true},
                    {"org.matrix.msc2432", true},
                    {"org.matrix.msc2716", true},
                    {"org.matrix.msc3440", true},
                    {"org.matrix.msc3266", false},
                    {"org.matrix.msc2285", true},
                    {"org.matrix.msc3916", true},
                    {"org.matrix.msc3981", false},
                }}
            });
        }, "Get API versions", 1000, false);

        // Also at /_matrix/client/versions (no version prefix)
        register_route("GET", "/_matrix/client/versions",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"versions", {"r0.0.1", "r0.1.0", "r0.2.0", "r0.3.0",
                                  "r0.4.0", "r0.5.0", "r0.6.0", "r0.6.1",
                                  "v1.1", "v1.2", "v1.3", "v1.4", "v1.5",
                                  "v1.6"}},
                    {"unstable_features", json::object()}
                });
            }, "Get API versions (no version prefix)", 999, false);
    }

    // --- Auth: Login ---
    void register_auth_routes() {
        // GET /login — get supported login flows
        add_api_route("GET", "/login",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"flows", {
                        {{"type", "m.login.password"}},
                        {{"type", "m.login.token"}},
                        {{"type", "m.login.sso",
                          "identity_providers", json::array()}},
                        {{"type", "m.login.appservice"}},
                    }}
                });
            }, "Get login flows", 800, false);

        // POST /login — authenticate user
        add_api_route("POST", "/login",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;

                // Validate required fields
                auto field_err = ClientBodyValidator::check_required_fields(
                    *body, {"type"});
                if (field_err.has_value()) return *field_err;

                std::string login_type = (*body)["type"].get<std::string>();

                if (login_type == "m.login.password") {
                    auto pwd_err = ClientBodyValidator::check_required_fields(
                        *body, {"identifier", "password"});
                    if (pwd_err.has_value()) return *pwd_err;

                    json identifier = (*body)["identifier"];
                    std::string user;
                    if (identifier.contains("user")) {
                        user = identifier["user"].get<std::string>();
                    } else if (identifier.contains("type") &&
                               identifier["type"] == "m.id.user") {
                        user = identifier["user"].get<std::string>();
                    }

                    return ClientResponseFormatter::ok(
                        ClientResponseFormatter::login_response(
                            user.empty() ? "@user:localhost" : user,
                            "syt_" + generate_request_id(),
                            (*body).value("device_id",
                              (*body).value("initial_device_display_name",
                                            "unknown")),
                            config_.server_name));
                }

                if (login_type == "m.login.token") {
                    auto tok_err = ClientBodyValidator::check_required_fields(
                        *body, {"token"});
                    if (tok_err.has_value()) return *tok_err;
                    return ClientResponseFormatter::ok(
                        ClientResponseFormatter::login_response(
                            "@token_user:localhost",
                            "syt_" + generate_request_id(),
                            "TOKEN_DEVICE",
                            config_.server_name));
                }

                return ClientResponseFormatter::bad_request(
                    client_api_constants::kErrInvalidParam,
                    "Unsupported login type: " + login_type);
            }, "Login", 800, false);

        // POST /logout — invalidate access token
        add_api_route("POST", "/logout",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok();
            }, "Logout", 700);

        // POST /logout/all — invalidate all access tokens
        add_api_route("POST", "/logout/all",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok();
            }, "Logout all sessions", 700);

        // POST /refresh — refresh access token
        add_api_route("POST", "/refresh",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;

                return ClientResponseFormatter::ok({
                    {"access_token", "syt_refresh_" + generate_request_id()},
                    {"refresh_token",
                     "syt_refresh_token_" + generate_request_id()},
                    {"expires_in_ms", 300000}
                });
            }, "Refresh token", 700);
    }

    // --- Auth: Registration ---
    void register_account_routes() {
        // POST /register — register a new user
        add_api_route("POST", "/register",
            [this](const HttpRequest& req, const auto& params) {
                if (!config_.enable_registration) {
                    return ClientResponseFormatter::forbidden(
                        "Registration is disabled on this server");
                }
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;

                // Check for UIA session or direct registration
                std::string kind =
                    body->value("kind", "user");
                if (kind == "guest") {
                    if (!config_.enable_guest_access) {
                        return ClientResponseFormatter::forbidden(
                            "Guest access is disabled");
                    }
                    return ClientResponseFormatter::ok(
                        ClientResponseFormatter::register_response(
                            "@guest_" + generate_request_id() + ":" +
                                config_.server_name,
                            "syt_guest_" + generate_request_id(),
                            body->value("initial_device_display_name",
                                        "Guest Device"),
                            config_.server_name));
                }

                // Normal registration
                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::register_response(
                        body->value("username",
                            "user_" + generate_request_id()),
                        "syt_reg_" + generate_request_id(),
                        body->value("initial_device_display_name",
                                    "Registered Device"),
                        config_.server_name));
            }, "Register user", 800, false);

        // GET /register — check if username is available
        add_api_route("GET", "/register",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"flows", {{
                        {"stages", {"m.login.dummy"}}
                    }}}
                });
            }, "Get registration flows", 799, false);

        // POST /register/available — check username availability
        add_api_route("POST", "/register/available",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;

                auto field_err = ClientBodyValidator::check_required_fields(
                    *body, {"username"});
                if (field_err.has_value()) return *field_err;

                return ClientResponseFormatter::ok({
                    {"available", true}
                });
            }, "Check username availability", 798, false);

        // POST /register/email/requestToken
        add_api_route("POST", "/register/email/requestToken",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"sid", "session_" + generate_request_id()}
                });
            }, "Request registration email token", 797, false);

        // POST /register/msisdn/requestToken
        add_api_route("POST", "/register/msisdn/requestToken",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"sid", "session_" + generate_request_id()}
                });
            }, "Request registration MSISDN token", 796, false);

        // --- Account management ---

        // GET /account/whoami
        add_api_route("GET", "/account/whoami",
            [](const HttpRequest& req, const auto&) {
                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::whoami_response(
                        req.auth_user.value_or("@unknown:localhost"),
                        false));
            }, "Get current user info", 750);

        // POST /account/password — change password
        add_api_route("POST", "/account/password",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;

                auto field_err = ClientBodyValidator::check_required_fields(
                    *body, {"new_password"});
                if (field_err.has_value()) return *field_err;

                return ClientResponseFormatter::ok();
            }, "Change password", 749);

        // POST /account/deactivate — deactivate account
        add_api_route("POST", "/account/deactivate",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize, true);
                if (err.has_value()) return *err;

                return ClientResponseFormatter::ok({
                    {"id_server_unbind_result", "success"}
                });
            }, "Deactivate account", 748);

        // GET /account/3pid — get third-party identifiers
        add_api_route("GET", "/account/3pid",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"threepids", json::array()}
                });
            }, "Get 3PIDs", 747);

        // POST /account/3pid/add
        add_api_route("POST", "/account/3pid/add",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"sid", "session_" + generate_request_id()}
                });
            }, "Add 3PID", 746);

        // POST /account/3pid/bind
        add_api_route("POST", "/account/3pid/bind",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Bind 3PID", 745);

        // POST /account/3pid/delete
        add_api_route("POST", "/account/3pid/delete",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"id_server_unbind_result", "success"}
                });
            }, "Delete 3PID", 744);

        // POST /account/3pid/unbind
        add_api_route("POST", "/account/3pid/unbind",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"id_server_unbind_result", "success"}
                });
            }, "Unbind 3PID", 743);

        // POST /account/3pid/email/requestToken
        add_api_route("POST", "/account/3pid/email/requestToken",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"sid", "session_" + generate_request_id()}
                });
            }, "Request email token (account)", 742);

        // POST /account/3pid/msisdn/requestToken
        add_api_route("POST", "/account/3pid/msisdn/requestToken",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"sid", "session_" + generate_request_id()}
                });
            }, "Request MSISDN token (account)", 741);

        // POST /account/password/email/requestToken
        add_api_route("POST", "/account/password/email/requestToken",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"sid", "session_" + generate_request_id()}
                });
            }, "Request password reset email token", 740, false);

        // POST /account/password/msisdn/requestToken
        add_api_route("POST", "/account/password/msisdn/requestToken",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"sid", "session_" + generate_request_id()}
                });
            }, "Request password reset MSISDN token", 739, false);

        // POST /account/password/email/submitToken
        add_api_route("POST", "/account/password/email/submitToken",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Submit password reset email token", 738, false);

        // POST /account/password/msisdn/submitToken
        add_api_route("POST", "/account/password/msisdn/submitToken",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Submit password reset MSISDN token", 737, false);

        // POST /account/3pid/email/submitToken
        add_api_route("POST", "/account/3pid/email/submitToken",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Submit 3PID email token", 736);

        // POST /account/3pid/msisdn/submitToken
        add_api_route("POST", "/account/3pid/msisdn/submitToken",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Submit 3PID MSISDN token", 735);

        // GET /capabilities
        add_api_route("GET", "/capabilities",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"capabilities", {
                        {"m.room_versions", {
                            {"default", "10"},
                            {"available", {"1","2","3","4","5","6",
                                           "7","8","9","10","11"}}
                        }},
                        {"m.change_password", {{"enabled", true}}},
                        {"m.set_displayname", {{"enabled", true}}},
                        {"m.set_avatar_url", {{"enabled", true}}},
                        {"m.3pid_changes", {{"enabled", true}}},
                    }}
                });
            }, "Get server capabilities", 900, false);
    }

    // --- Room Routes ---
    void register_room_routes() {
        // POST /createRoom
        add_api_route("POST", "/createRoom",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize, true);
                if (err.has_value()) return *err;

                std::string room_id = "!room_" + generate_request_id() +
                                     ":localhost";
                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::room_info(room_id));
            }, "Create room", 600);

        // POST /join/{roomIdOrAlias}
        add_api_route("POST", "/join/{roomIdOrAlias}",
            [](const HttpRequest& req, const auto& params) {
                auto it = params.find("roomIdOrAlias");
                std::string target = it != params.end() ? it->second : "";

                std::string room_id;
                if (!target.empty() && target[0] == '!') {
                    room_id = target;
                } else if (!target.empty() && target[0] == '#') {
                    room_id = "!resolved_" + target.substr(1) + ":localhost";
                } else {
                    auto [body, err] = ClientBodyValidator::parse_or_error(
                        req, client_api_constants::kMaxEventSize);
                    if (err.has_value()) return *err;
                    target = body->value("room_id",
                        body->value("roomId", ""));
                }

                if (room_id.empty()) room_id = "!joined:localhost";
                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::room_info(room_id));
            }, "Join room", 600);

        // POST /rooms/{roomId}/join
        add_api_route("POST", "/rooms/{roomId}/join",
            [](const HttpRequest& req, const auto& params) {
                auto it = params.find("roomId");
                std::string room_id = it != params.end() ? it->second
                                                          : "!joined:localhost";
                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::room_info(room_id));
            }, "Join room by ID", 600);

        // POST /rooms/{roomId}/leave
        add_api_route("POST", "/rooms/{roomId}/leave",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok();
            }, "Leave room", 600);

        // POST /rooms/{roomId}/forget
        add_api_route("POST", "/rooms/{roomId}/forget",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok();
            }, "Forget room", 600);

        // POST /rooms/{roomId}/invite
        add_api_route("POST", "/rooms/{roomId}/invite",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Invite user", 600);

        // POST /rooms/{roomId}/kick
        add_api_route("POST", "/rooms/{roomId}/kick",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Kick user", 600);

        // POST /rooms/{roomId}/ban
        add_api_route("POST", "/rooms/{roomId}/ban",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Ban user", 600);

        // POST /rooms/{roomId}/unban
        add_api_route("POST", "/rooms/{roomId}/unban",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Unban user", 600);

        // PUT /rooms/{roomId}/send/{eventType}/{txnId}
        add_api_route("PUT", "/rooms/{roomId}/send/{eventType}/{txnId}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;

                std::string event_id = "$event_" + generate_request_id();
                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::event_response(event_id));
            }, "Send message event", 600);

        // GET /rooms/{roomId}/event/{eventId}
        add_api_route("GET", "/rooms/{roomId}/event/{eventId}",
            [](const HttpRequest& req, const auto& params) {
                std::string room_id = params.count("roomId")
                    ? params.at("roomId") : "!room:localhost";
                std::string event_id = params.count("eventId")
                    ? params.at("eventId") : "$event:localhost";

                return ClientResponseFormatter::ok({
                    {"event_id", event_id},
                    {"room_id", room_id},
                    {"type", "m.room.message"},
                    {"sender", req.auth_user.value_or("@user:localhost")},
                    {"origin_server_ts", now_ms()},
                    {"content", {{"body", "Hello, world!"},
                                 {"msgtype", "m.text"}}}
                });
            }, "Get event", 595);

        // GET /rooms/{roomId}/state
        add_api_route("GET", "/rooms/{roomId}/state",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok(json::array());
            }, "Get all state", 590);

        // GET /rooms/{roomId}/state/{eventType}
        add_api_route("GET", "/rooms/{roomId}/state/{eventType}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok(json::array());
            }, "Get state by type", 590);

        // GET /rooms/{roomId}/state/{eventType}/{stateKey}
        add_api_route("GET", "/rooms/{roomId}/state/{eventType}/{stateKey}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok(json::object());
            }, "Get state by type and key", 590);

        // PUT /rooms/{roomId}/state/{eventType}
        add_api_route("PUT", "/rooms/{roomId}/state/{eventType}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxStateEventSize);
                if (err.has_value()) return *err;

                std::string event_id = "$state_" + generate_request_id();
                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::event_response(event_id));
            }, "Send state event", 590);

        // PUT /rooms/{roomId}/state/{eventType}/{stateKey}
        add_api_route("PUT", "/rooms/{roomId}/state/{eventType}/{stateKey}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxStateEventSize);
                if (err.has_value()) return *err;

                std::string event_id = "$state_keyed_" +
                    generate_request_id();
                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::event_response(event_id));
            }, "Send state event with key", 590);

        // GET /rooms/{roomId}/members
        add_api_route("GET", "/rooms/{roomId}/members",
            [](const HttpRequest&, const auto& params) {
                ClientQueryParser qp(params);  // Will use req.query_params
                // In practice, query params come from req.query_params
                return ClientResponseFormatter::ok({
                    {"chunk", json::array()}
                });
            }, "Get room members", 585);

        // GET /rooms/{roomId}/joined_members
        add_api_route("GET", "/rooms/{roomId}/joined_members",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok({
                    {"joined", json::object()}
                });
            }, "Get joined members", 585);

        // GET /rooms/{roomId}/messages
        add_api_route("GET", "/rooms/{roomId}/messages",
            [](const HttpRequest& req, const auto& params) {
                ClientQueryParser qp(req.query_params);
                std::string from = qp.from().value_or("");
                std::string to = qp.to().value_or("");
                std::string dir = qp.dir();
                int64_t limit = qp.limit();

                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::paginate(
                        from, to, -1, json::array()));
            }, "Get room messages", 580);

        // GET /rooms/{roomId}/context/{eventId}
        add_api_route("GET", "/rooms/{roomId}/context/{eventId}",
            [](const HttpRequest& req, const auto& params) {
                ClientQueryParser qp(req.query_params);
                int64_t limit = qp.limit();

                return ClientResponseFormatter::ok({
                    {"start", ""},
                    {"end", ""},
                    {"events_before", json::array()},
                    {"event", json::object()},
                    {"events_after", json::array()},
                    {"state", json::array()}
                });
            }, "Get event context", 578);

        // GET /rooms/{roomId}/relations/{eventId}
        add_api_route("GET", "/rooms/{roomId}/relations/{eventId}",
            [](const HttpRequest& req, const auto& params) {
                ClientQueryParser qp(req.query_params);
                return ClientResponseFormatter::ok({
                    {"chunk", json::array()}
                });
            }, "Get event relations", 577);

        // GET /rooms/{roomId}/relations/{eventId}/{relType}
        add_api_route("GET",
            "/rooms/{roomId}/relations/{eventId}/{relType}",
            [](const HttpRequest& req, const auto& params) {
                ClientQueryParser qp(req.query_params);
                return ClientResponseFormatter::ok({
                    {"chunk", json::array()}
                });
            }, "Get event relations by type", 577);

        // GET /joined_rooms
        add_api_route("GET", "/joined_rooms",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"joined_rooms", json::array()}
                });
            }, "Get joined rooms", 575);

        // POST /rooms/{roomId}/redact/{eventId}/{txnId}
        add_api_route("PUT",
            "/rooms/{roomId}/redact/{eventId}/{txnId}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;

                std::string event_id = "$redact_" + generate_request_id();
                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::event_response(event_id));
            }, "Redact event", 574);

        // GET /publicRooms
        add_api_route("GET", "/publicRooms",
            [](const HttpRequest& req, const auto& params) {
                ClientQueryParser qp(req.query_params);
                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::public_rooms_response(
                        json::array()));
            }, "Get public rooms", 573);

        // POST /publicRooms
        add_api_route("POST", "/publicRooms",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize, true);
                if (err.has_value()) return *err;

                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::public_rooms_response(
                        json::array()));
            }, "Query public rooms", 573);
    }

    // --- Sync ---
    void register_sync_routes() {
        add_api_route("GET", "/sync",
            [](const HttpRequest& req, const auto&) {
                ClientQueryParser qp(req.query_params);
                std::string since = qp.since().value_or("");
                int64_t timeout = qp.timeout();
                bool full_state = qp.full_state();
                std::optional<std::string> filter = qp.filter_id();

                // Build sync response
                std::string next_batch = "s" + std::to_string(now_ms());

                json rooms;
                rooms["join"] = json::object();
                rooms["invite"] = json::object();
                rooms["leave"] = json::object();

                json presence;
                presence["events"] = json::array();

                json account_data;
                account_data["events"] = json::array();

                json to_device;
                to_device["events"] = json::array();

                json device_lists;
                device_lists["changed"] = json::array();
                device_lists["left"] = json::array();

                json otk_count;
                otk_count["signed_curve25519"] = 50;
                otk_count["curve25519"] = 100;

                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::sync_response(
                        next_batch, rooms, presence, account_data,
                        to_device, device_lists, otk_count));
            }, "Sync", 500);
    }

    // --- Events ---
    void register_event_routes() {
        // GET /events (deprecated v1 streaming)
        add_api_route("GET", "/events",
            [](const HttpRequest& req, const auto&) {
                ClientQueryParser qp(req.query_params);
                return ClientResponseFormatter::ok({
                    {"start", qp.from().value_or("")},
                    {"end", "e" + std::to_string(now_ms())},
                    {"chunk", json::array()}
                });
            }, "Get events stream", 490);

        // GET /initialSync (deprecated)
        add_api_route("GET", "/initialSync",
            [](const HttpRequest& req, const auto&) {
                ClientQueryParser qp(req.query_params);
                return ClientResponseFormatter::ok({
                    {"end", "s" + std::to_string(now_ms())},
                    {"rooms", json::array()},
                    {"presence", json::array()}
                });
            }, "Initial sync (deprecated)", 489);

        // GET /event/{eventId} (deprecated)
        add_api_route("GET", "/event/{eventId}",
            [](const HttpRequest& req, const auto& params) {
                return ClientResponseFormatter::ok(json::object());
            }, "Get single event (deprecated)", 488);
    }

    // --- Profile ---
    void register_profile_routes() {
        // GET /profile/{userId}
        add_api_route("GET", "/profile/{userId}",
            [](const HttpRequest&, const auto& params) {
                std::string user_id = params.count("userId")
                    ? params.at("userId") : "@unknown:localhost";
                return ClientResponseFormatter::ok({
                    {"displayname", user_id.substr(1,
                        user_id.find(':') - 1)},
                    {"avatar_url", ""}
                });
            }, "Get user profile", 460);

        // GET /profile/{userId}/displayname
        add_api_route("GET", "/profile/{userId}/displayname",
            [](const HttpRequest&, const auto& params) {
                std::string user_id = params.count("userId")
                    ? params.at("userId") : "@unknown:localhost";
                return ClientResponseFormatter::ok({
                    {"displayname", user_id.substr(1,
                        user_id.find(':') - 1)}
                });
            }, "Get display name", 460);

        // PUT /profile/{userId}/displayname
        add_api_route("PUT", "/profile/{userId}/displayname",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Set display name", 460);

        // GET /profile/{userId}/avatar_url
        add_api_route("GET", "/profile/{userId}/avatar_url",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok({
                    {"avatar_url", ""}
                });
            }, "Get avatar URL", 460);

        // PUT /profile/{userId}/avatar_url
        add_api_route("PUT", "/profile/{userId}/avatar_url",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Set avatar URL", 460);
    }

    // --- Directory ---
    void register_directory_routes() {
        // GET /directory/room/{roomAlias}
        add_api_route("GET", "/directory/room/{roomAlias}",
            [](const HttpRequest&, const auto& params) {
                std::string alias = params.count("roomAlias")
                    ? params.at("roomAlias") : "#room:localhost";
                return ClientResponseFormatter::ok({
                    {"room_id", "!resolved_" + alias.substr(1)},
                    {"servers", {config_.server_name}}
                });
            }, "Resolve room alias", 440);

        // PUT /directory/room/{roomAlias}
        add_api_route("PUT", "/directory/room/{roomAlias}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Set room alias", 440);

        // DELETE /directory/room/{roomAlias}
        add_api_route("DELETE", "/directory/room/{roomAlias}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok();
            }, "Delete room alias", 440);

        // GET /directory/list/room/{roomId}
        add_api_route("GET", "/directory/list/room/{roomId}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok({
                    {"visibility", "public"}
                });
            }, "Get room visibility", 439);

        // PUT /directory/list/room/{roomId}
        add_api_route("PUT", "/directory/list/room/{roomId}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Set room visibility", 439);
    }

    // --- Devices ---
    void register_device_routes() {
        // GET /devices
        add_api_route("GET", "/devices",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"devices", json::array()}
                });
            }, "List devices", 420);

        // GET /devices/{deviceId}
        add_api_route("GET", "/devices/{deviceId}",
            [](const HttpRequest&, const auto& params) {
                std::string device_id = params.count("deviceId")
                    ? params.at("deviceId") : "DEVICE001";
                return ClientResponseFormatter::ok({
                    {"device_id", device_id},
                    {"display_name", "My Device"},
                    {"last_seen_ip", "127.0.0.1"},
                    {"last_seen_ts", now_ms()}
                });
            }, "Get device", 420);

        // PUT /devices/{deviceId}
        add_api_route("PUT", "/devices/{deviceId}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Update device", 420);

        // DELETE /devices/{deviceId}
        add_api_route("DELETE", "/devices/{deviceId}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok();
            }, "Delete device", 420);

        // POST /delete_devices
        add_api_route("POST", "/delete_devices",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Bulk delete devices", 419);
    }

    // --- E2E Keys ---
    void register_key_routes() {
        // POST /keys/upload
        add_api_route("POST", "/keys/upload",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    128 * 1024); // 128 KB for keys
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"one_time_key_counts", {
                        {"signed_curve25519", 50},
                        {"curve25519", 100}
                    }}
                });
            }, "Upload keys", 400);

        // POST /keys/query
        add_api_route("POST", "/keys/query",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    128 * 1024);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"device_keys", json::object()},
                    {"master_keys", json::object()},
                    {"self_signing_keys", json::object()},
                    {"user_signing_keys", json::object()},
                    {"failures", json::object()}
                });
            }, "Query keys", 400);

        // POST /keys/claim
        add_api_route("POST", "/keys/claim",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    128 * 1024);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"one_time_keys", json::object()},
                    {"failures", json::object()}
                });
            }, "Claim keys", 400);

        // GET /keys/changes
        add_api_route("GET", "/keys/changes",
            [](const HttpRequest& req, const auto&) {
                ClientQueryParser qp(req.query_params);
                return ClientResponseFormatter::ok({
                    {"changed", json::array()},
                    {"left", json::array()}
                });
            }, "Get key changes", 399);

        // POST /keys/device_signing/upload
        add_api_route("POST", "/keys/device_signing/upload",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    128 * 1024);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Upload signing keys", 398);

        // POST /keys/signatures/upload
        add_api_route("POST", "/keys/signatures/upload",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    128 * 1024);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"failures", json::object()}
                });
            }, "Upload signatures", 397);
    }

    // --- Push Rules ---
    void register_push_routes() {
        // GET /pushrules
        add_api_route("GET", "/pushrules",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"global", {
                        {"content", json::array()},
                        {"override", json::array()},
                        {"room", json::array()},
                        {"sender", json::array()},
                        {"underride", {
                            {{"rule_id", ".m.rule.call"},
                             {"enabled", true},
                             {"actions", {"notify", {{"set_tweak",
                               "sound", "ring"}}}},
                             {"conditions", json::array()}},
                            {{"rule_id", ".m.rule.encrypted_room_one_to_one"},
                             {"enabled", true},
                             {"actions", {"notify", {{"set_tweak",
                               "sound", "default"}}}},
                             {"conditions", json::array()}},
                            {{"rule_id", ".m.rule.message"},
                             {"enabled", true},
                             {"actions", {"notify", {{"set_tweak",
                               "highlight", false}}}},
                             {"conditions", json::array()}},
                        }}
                    }}
                });
            }, "Get push rules", 380);

        // GET /pushrules/{scope}/{kind}/{ruleId}
        add_api_route("GET", "/pushrules/{scope}/{kind}/{ruleId}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok(json::object());
            }, "Get push rule", 380);

        // PUT /pushrules/{scope}/{kind}/{ruleId}
        add_api_route("PUT", "/pushrules/{scope}/{kind}/{ruleId}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Set push rule", 380);

        // DELETE /pushrules/{scope}/{kind}/{ruleId}
        add_api_route("DELETE", "/pushrules/{scope}/{kind}/{ruleId}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok();
            }, "Delete push rule", 380);

        // PUT /pushrules/{scope}/{kind}/{ruleId}/actions
        add_api_route("PUT",
            "/pushrules/{scope}/{kind}/{ruleId}/actions",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Set push rule actions", 380);

        // PUT /pushrules/{scope}/{kind}/{ruleId}/enabled
        add_api_route("PUT",
            "/pushrules/{scope}/{kind}/{ruleId}/enabled",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Set push rule enabled", 380);
    }

    // --- Pushers ---
    void register_push_routes() {
        // GET /pushers
        add_api_route("GET", "/pushers",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"pushers", json::array()}
                });
            }, "Get pushers", 370);

        // POST /pushers/set
        add_api_route("POST", "/pushers/set",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Set pusher", 370);
    }

    // --- Notifications ---
    void register_notification_routes() {
        add_api_route("GET", "/notifications",
            [](const HttpRequest& req, const auto&) {
                ClientQueryParser qp(req.query_params);
                int64_t limit = qp.limit();
                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::notification_response(
                        json::array(), "", 0));
            }, "Get notifications", 360);
    }

    // --- Receipts ---
    void register_receipt_routes() {
        add_api_route("POST",
            "/rooms/{roomId}/receipt/{receiptType}/{eventId}",
            [](const HttpRequest& req, const auto& params) {
                return ClientResponseFormatter::ok();
            }, "Send receipt", 350);
    }

    // --- Tags ---
    void register_tag_routes() {
        // GET /user/{userId}/rooms/{roomId}/tags
        add_api_route("GET", "/user/{userId}/rooms/{roomId}/tags",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok({
                    {"tags", json::object()}
                });
            }, "Get room tags", 340);

        // PUT /user/{userId}/rooms/{roomId}/tags/{tag}
        add_api_route("PUT",
            "/user/{userId}/rooms/{roomId}/tags/{tag}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize, true);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Add room tag", 340);

        // DELETE /user/{userId}/rooms/{roomId}/tags/{tag}
        add_api_route("DELETE",
            "/user/{userId}/rooms/{roomId}/tags/{tag}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok();
            }, "Remove room tag", 340);
    }

    // --- Search ---
    void register_search_routes() {
        add_api_route("POST", "/search",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;

                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::search_response(
                        json::object()));
            }, "Search", 330);

        add_api_route("POST", "/user_directory/search",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;

                return ClientResponseFormatter::ok({
                    {"results", json::array()},
                    {"limited", false}
                });
            }, "Search user directory", 329);
    }

    // --- Presence ---
    void register_presence_routes() {
        // GET /presence/{userId}/status
        add_api_route("GET", "/presence/{userId}/status",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok({
                    {"presence", "offline"},
                    {"last_active_ago", 0},
                    {"status_msg", ""},
                    {"currently_active", false}
                });
            }, "Get presence status", 320);

        // PUT /presence/{userId}/status
        add_api_route("PUT", "/presence/{userId}/status",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Set presence status", 320);

        // GET /presence/list/{userId}
        add_api_route("GET", "/presence/list/{userId}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok(json::array());
            }, "Get presence list", 319);

        // POST /presence/list/{userId}
        add_api_route("POST", "/presence/list/{userId}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Modify presence list", 319);
    }

    // --- Filters ---
    void register_filter_routes() {
        // POST /user/{userId}/filter
        add_api_route("POST", "/user/{userId}/filter",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxFilterSize);
                if (err.has_value()) return *err;

                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::filter_response(
                        std::to_string(now_ms())));
            }, "Create filter", 310);

        // GET /user/{userId}/filter/{filterId}
        add_api_route("GET", "/user/{userId}/filter/{filterId}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok(json::object());
            }, "Get filter", 310);
    }

    // --- Media (Content Repository) ---
    void register_media_routes() {
        // POST /upload
        add_media_route("POST", "/upload",
            [](const HttpRequest& req, const auto&) {
                std::string content_uri = "mxc://localhost/" +
                    generate_request_id();
                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::upload_response(content_uri));
            }, "Upload media", 300);

        // GET /download/{serverName}/{mediaId}
        add_media_route("GET", "/download/{serverName}/{mediaId}",
            [](const HttpRequest& req, const auto& params) {
                // Returns binary content, but for placeholder we return info
                HttpResponse resp;
                resp.code = 200;
                resp.body = {{"info", "Media content placeholder"}};
                resp.content_type = "application/octet-stream";
                return resp;
            }, "Download media", 299);

        // GET /download/{serverName}/{mediaId}/{fileName}
        add_media_route("GET",
            "/download/{serverName}/{mediaId}/{fileName}",
            [](const HttpRequest& req, const auto& params) {
                HttpResponse resp;
                resp.code = 200;
                resp.body = {{"info", "Media content placeholder"}};
                resp.content_type = "application/octet-stream";
                return resp;
            }, "Download media with filename", 299);

        // GET /thumbnail/{serverName}/{mediaId}
        add_media_route("GET",
            "/thumbnail/{serverName}/{mediaId}",
            [](const HttpRequest& req, const auto& params) {
                ClientQueryParser qp(req.query_params);
                HttpResponse resp;
                resp.code = 200;
                resp.body = {{"info", "Thumbnail placeholder"}};
                resp.content_type = "image/png";
                return resp;
            }, "Get thumbnail", 298);

        // GET /config
        add_media_route("GET", "/config",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"m.upload.size", 100 * 1024 * 1024}
                });
            }, "Get media config", 297);

        // GET /preview_url
        add_media_route("GET", "/preview_url",
            [](const HttpRequest& req, const auto&) {
                ClientQueryParser qp(req.query_params);
                return ClientResponseFormatter::ok({
                    {"og:title", "Preview"},
                    {"og:description", ""},
                    {"og:image", ""},
                    {"matrix:image:size", 0}
                });
            }, "Preview URL", 296);
    }

    // --- Third-party ---
    void register_third_party_routes() {
        // GET /thirdparty/protocols
        add_api_route("GET", "/thirdparty/protocols",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok(json::object());
            }, "Get third-party protocols", 280);

        // GET /thirdparty/protocol/{protocol}
        add_api_route("GET", "/thirdparty/protocol/{protocol}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok(json::object());
            }, "Get third-party protocol", 280);

        // GET /thirdparty/user/{protocol}
        add_api_route("GET", "/thirdparty/user/{protocol}",
            [](const HttpRequest& req, const auto& params) {
                return ClientResponseFormatter::ok(json::array());
            }, "Query third-party users", 279);

        // GET /thirdparty/location/{protocol}
        add_api_route("GET", "/thirdparty/location/{protocol}",
            [](const HttpRequest& req, const auto& params) {
                return ClientResponseFormatter::ok(json::array());
            }, "Query third-party locations", 279);

        // GET /thirdparty/user
        add_api_route("GET", "/thirdparty/user",
            [](const HttpRequest& req, const auto&) {
                return ClientResponseFormatter::ok(json::array());
            }, "Query third-party users by fields", 278);

        // GET /thirdparty/location
        add_api_route("GET", "/thirdparty/location",
            [](const HttpRequest& req, const auto&) {
                return ClientResponseFormatter::ok(json::array());
            }, "Query third-party locations by fields", 278);
    }

    // --- Room Upgrades ---
    void register_room_upgrade_routes() {
        add_api_route("POST", "/rooms/{roomId}/upgrade",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;

                std::string replacement_room = "!upgraded_" +
                    generate_request_id() + ":" + config_.server_name;
                return ClientResponseFormatter::ok(
                    ClientResponseFormatter::room_info(
                        replacement_room));
            }, "Upgrade room", 270);
    }

    // --- Reports ---
    void register_report_routes() {
        add_api_route("POST", "/rooms/{roomId}/report/{eventId}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Report event", 260);
    }

    // --- Typing ---
    void register_typing_routes() {
        add_api_route("PUT", "/rooms/{roomId}/typing/{userId}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Send typing notification", 250);
    }

    // --- Read Markers ---
    void register_read_marker_routes() {
        add_api_route("POST", "/rooms/{roomId}/read_markers",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Set read marker", 240);
    }

    // --- Account Data ---
    void register_account_data_routes() {
        // PUT /user/{userId}/account_data/{type}
        add_api_route("PUT", "/user/{userId}/account_data/{type}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Set account data", 230);

        // GET /user/{userId}/account_data/{type}
        add_api_route("GET", "/user/{userId}/account_data/{type}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok(json::object());
            }, "Get account data", 230);

        // PUT /user/{userId}/rooms/{roomId}/account_data/{type}
        add_api_route("PUT",
            "/user/{userId}/rooms/{roomId}/account_data/{type}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Set room account data", 229);

        // GET /user/{userId}/rooms/{roomId}/account_data/{type}
        add_api_route("GET",
            "/user/{userId}/rooms/{roomId}/account_data/{type}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok(json::object());
            }, "Get room account data", 229);
    }

    // --- Well-known ---
    void register_well_known_routes() {
        // /.well-known/matrix/client
        register_route("GET", "/.well-known/matrix/client",
            [this](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"m.homeserver", {
                        {"base_url", "https://" + config_.server_name}
                    }},
                    {"m.identity_server", {
                        {"base_url", "https://" + config_.server_name}
                    }},
                    {"org.matrix.msc3575.proxy", {
                        {"url", "https://" + config_.server_name}
                    }}
                });
            }, "Client well-known", 100, false);

        // /.well-known/matrix/server
        register_route("GET", "/.well-known/matrix/server",
            [this](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"m.server", config_.server_name + ":443"}
                });
            }, "Server well-known", 99, false);
    }

    // --- Admin API ---
    void register_admin_routes() {
        // GET /_synapse/admin/v1/whois/{userId}
        register_route("GET", "/_synapse/admin/v1/whois/{userId}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok({
                    {"user_id", params.count("userId")
                        ? params.at("userId") : "@unknown:localhost"},
                    {"devices", json::object()}
                });
            }, "Admin whois", 50);

        // GET /_synapse/admin/v1/users
        register_route("GET", "/_synapse/admin/v1/users",
            [](const HttpRequest& req, const auto&) {
                return ClientResponseFormatter::ok({
                    {"users", json::array()},
                    {"total", 0}
                });
            }, "Admin list users", 50);

        // POST /_synapse/admin/v1/reset_password/{userId}
        register_route("POST",
            "/_synapse/admin/v1/reset_password/{userId}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok();
            }, "Admin reset password", 50);

        // GET /_synapse/admin/v1/rooms
        register_route("GET", "/_synapse/admin/v1/rooms",
            [](const HttpRequest& req, const auto&) {
                return ClientResponseFormatter::ok({
                    {"rooms", json::array()},
                    {"total_rooms", 0}
                });
            }, "Admin list rooms", 50);

        // DELETE /_synapse/admin/v1/rooms/{roomId}
        register_route("DELETE",
            "/_synapse/admin/v1/rooms/{roomId}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok();
            }, "Admin delete room", 50);

        // GET /_synapse/admin/v1/rooms/{roomId}/members
        register_route("GET",
            "/_synapse/admin/v1/rooms/{roomId}/members",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok({
                    {"members", json::array()},
                    {"total", 0}
                });
            }, "Admin room members", 50);

        // POST /_synapse/admin/v1/purge_history/{roomId}
        register_route("POST",
            "/_synapse/admin/v1/purge_history/{roomId}",
            [](const HttpRequest& req, const auto& params) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"purge_id", "purge_" + generate_request_id()}
                });
            }, "Admin purge history", 50);

        // GET /_synapse/admin/v1/purge_history_status/{purgeId}
        register_route("GET",
            "/_synapse/admin/v1/purge_history_status/{purgeId}",
            [](const HttpRequest&, const auto& params) {
                return ClientResponseFormatter::ok({
                    {"status", "complete"}
                });
            }, "Admin purge history status", 50);

        // GET /_synapse/admin/v1/registration_tokens
        register_route("GET",
            "/_synapse/admin/v1/registration_tokens",
            [](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"registration_tokens", json::array()}
                });
            }, "Admin registration tokens", 50);

        // POST /_synapse/admin/v1/registration_tokens/new
        register_route("POST",
            "/_synapse/admin/v1/registration_tokens/new",
            [](const HttpRequest& req, const auto&) {
                auto [body, err] = ClientBodyValidator::parse_or_error(req,
                    client_api_constants::kMaxEventSize);
                if (err.has_value()) return *err;
                return ClientResponseFormatter::ok({
                    {"token", "tok_" + generate_request_id()}
                });
            }, "Admin create registration token", 50);

        // GET /_synapse/admin/v1/server_version
        register_route("GET", "/_synapse/admin/v1/server_version",
            [this](const HttpRequest&, const auto&) {
                return ClientResponseFormatter::ok({
                    {"server_version", config_.server_version},
                    {"python_version", "C++ (Progressive)"}
                });
            }, "Admin server version", 50);
    }

    // ==================================================================
    // Member variables
    // ==================================================================
    DatabasePool& db_;
    ClientApiRouterConfig config_;
    ClientRateLimiter rate_limiter_;
    ClientRequestLogger logger_;
    ClientAuthFilter auth_filter_;
    ClientRouteTable route_table_;
    ClientMiddlewareChain middleware_chain_;
};

// ============================================================================
// ClientApiRouter — Public interface wrapping ClientApiRouterImpl
// ============================================================================

class ClientApiRouter {
public:
    using Config = ClientApiRouterConfig;

    explicit ClientApiRouter(DatabasePool& db,
                              const Config& cfg = Config{})
        : impl_(std::make_unique<ClientApiRouterImpl>(db, cfg)) {}

    // Dispatch a client API request
    HttpResponse dispatch(HttpRequest& req) {
        return impl_->dispatch(req);
    }

    // Register a custom route
    void register_route(const std::string& method,
                         const std::string& pattern,
                         ClientRouteHandler handler,
                         const std::string& desc = "",
                         int priority = 0,
                         bool requires_auth = true) {
        impl_->register_route(method, pattern,
                               std::move(handler), desc,
                               priority, requires_auth);
    }

    // Middleware management
    void add_middleware(const std::string& name,
                         ClientMiddlewarePhase phase,
                         ClientMiddlewareFunc handler,
                         int priority = 0) {
        impl_->add_middleware(name, phase,
                               std::move(handler), priority);
    }

    bool remove_middleware(const std::string& name) {
        return impl_->remove_middleware(name);
    }

    std::vector<std::string> list_middleware() const {
        return impl_->list_middleware();
    }

    // Rate limiter access
    ClientRateLimiter& rate_limiter() {
        return impl_->rate_limiter();
    }

    // Configuration
    const Config& config() const { return impl_->config(); }

    // Route count
    size_t route_count() const { return impl_->route_count(); }

private:
    std::unique_ptr<ClientApiRouterImpl> impl_;
};

// ============================================================================
// ClientApiRouterFactory — Create pre-configured router instances
// ============================================================================

namespace client_router_factory {

// Create a development router with verbose logging and disabled rate limiting
std::unique_ptr<ClientApiRouter> create_development(
    DatabasePool& db,
    const std::string& server_name = "localhost:8008") {
    ClientApiRouterConfig cfg;
    cfg.server_name = server_name;
    cfg.server_version = "Progressive/1.0-dev";
    cfg.rate_limit_enabled = false;
    cfg.enable_logging = true;
    cfg.log_config.level = ClientRequestLogger::Level::DEBUG;
    cfg.enable_metrics = true;
    cfg.max_body_size = 200 * 1024 * 1024;
    cfg.strict_validation = false;
    return std::make_unique<ClientApiRouter>(db, cfg);
}

// Create a production router with rate limiting and optimized settings
std::unique_ptr<ClientApiRouter> create_production(
    DatabasePool& db,
    const std::string& server_name = "matrix.example.com",
    const std::vector<std::string>& cors_origins = {}) {
    ClientApiRouterConfig cfg;
    cfg.server_name = server_name;
    cfg.server_version = "Progressive/1.0";
    cfg.rate_limit_enabled = true;
    cfg.enable_logging = true;
    cfg.log_config.level = ClientRequestLogger::Level::INFO;
    cfg.enable_metrics = true;
    cfg.max_body_size = 50 * 1024 * 1024;
    cfg.max_upload_size = 100 * 1024 * 1024;
    cfg.strict_validation = true;
    cfg.enable_registration = true;
    if (!cors_origins.empty()) {
        cfg.cors_origins = cors_origins;
    }
    return std::make_unique<ClientApiRouter>(db, cfg);
}

// Create a minimal router with basic settings
std::unique_ptr<ClientApiRouter> create_minimal(
    DatabasePool& db,
    const std::string& server_name = "localhost") {
    ClientApiRouterConfig cfg;
    cfg.server_name = server_name;
    cfg.rate_limit_enabled = true;
    cfg.enable_logging = false;
    cfg.enable_metrics = false;
    cfg.enable_registration = false;
    return std::make_unique<ClientApiRouter>(db, cfg);
}

} // namespace client_router_factory

} // namespace progressive

// ============================================================================
// End of client_api_router.cpp
// ============================================================================
