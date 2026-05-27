// ============================================================================
// error_handler.cpp — Matrix Error Handling Codes, Responses, and Framework
//
// Implements:
//   - ErrorCode: Enumeration of all Matrix specification error codes with
//     canonical string representations, HTTP status code mappings, and
//     categorization (client error, server error, auth error, rate limit,
//     federation error, etc.).
//   - ErrorCategory: Classification system grouping error codes by semantic
//     domain — AUTH, PERMISSION, VALIDATION, NOT_FOUND, RATE_LIMIT, SERVER,
//     FEDERATION, ROOM, USER_DATA, THREEPID, UNKNOWN.
//   - ErrorResponse: Structured, immutable error response builder that
//     produces JSON conforming to the Matrix Client-Server API error
//     schema: {"errcode": "...", "error": "..."} with optional fields
//     for retry_after_ms, soft_logout, admin_contact, consent_uri,
//     completed stages, session, params, flows.
//   - ErrorRegistry: Thread-safe singleton catalog of all known error
//     codes with metadata — default HTTP status, default message, category,
//     description, deprecation status, Matrix spec version introduced.
//   - ErrorResponseBuilder: Fluent builder pattern for constructing
//     error responses with optional fields, localization, and logging.
//   - HttpErrorMapper: Maps between internal error codes and HTTP status
//     codes with RFC 7807 Problem Details support.
//   - LocalizedErrorMessages: Multi-language error message catalog with
//     fallback chain (requested language → server default → English).
//   - ErrorContext: Rich error context carrying request ID, user context,
//     room context, event context, and stack trace information for
//     structured logging and debugging.
//   - RetryAfterCalculator: Computes retry_after_ms values for rate-limited
//     errors using exponential backoff, token bucket state, or fixed windows.
//   - FederationErrorHandler: Specialized error handling for server-to-server
//     (S2S) federation API errors. Handles M_UNREACHABLE, M_CONNECTION_FAILED,
//     M_DNS_ERROR, M_TLS_ERROR, M_SIGNATURE_INVALID, M_UNKNOWN_ENDPOINT,
//     M_UNSUPPORTED_ROOM_VERSION, M_INCOMPATIBLE_ROOM_VERSION.
//   - ClientErrorHandler: Specialized error handling for Client-Server API
//     errors. Handles user-facing error messages, session management errors
//     (M_UNKNOWN_TOKEN, M_MISSING_TOKEN, soft_logout), consent errors.
//   - AdminErrorHandler: Specialized error handling for Admin API and
//     server management endpoints.
//   - ErrorAuditLogger: Logs all errors with structured metadata for
//     monitoring, alerting, and debugging. Supports error rate tracking
//     and anomaly detection hooks.
//   - ErrorSanitizer: Sanitizes error messages to prevent information
//     leakage — redacts internal paths, stack traces, database details
//     from client-facing error responses while logging full details.
//   - ErrorTemplateLibrary: Pre-built error response templates for
//     common Matrix scenarios (room not found, user not in room,
//     invalid event, power level insufficient, etc.).
//   - MatrixErrorException: C++ exception type that carries an
//     ErrorResponse, allowing deep call stacks to propagate structured
//     errors without losing Matrix error code information.
//   - ErrorResponseSerialization: JSON serialization/deserialization
//     of error responses for logging, federation forwarding, and
//     test fixtures.
//   - ErrorMetrics: Counters, histograms, and gauges for error rates
//     by code, endpoint, user agent, and time window.
//
// Equivalent to:
//   synapse/api/errors.py (SynapseError, Codes, error classes)
//   synapse/http/server.py (error response formatting)
//   synapse/http/site.py (error page rendering)
//   synapse/api/ratelimiting.py (rate limit error responses)
//   synapse/federation/federation_base.py (federation error mapping)
//   matrix-org/matrix-spec: Client-Server API / Standard error response
//   matrix-org/matrix-spec: Appendices / Matrix error codes
//   RFC 7807 (Problem Details for HTTP APIs)
//
// Namespace: progressive::
// Target: 3000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
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
#include <type_traits>
#include <unordered_map>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

// Platform-specific includes
#ifdef __linux__
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <execinfo.h>
#endif

namespace progressive {

// ============================================================================
// Forward declarations
// ============================================================================
class ErrorResponse;
class ErrorRegistry;
class ErrorResponseBuilder;
class HttpErrorMapper;
class LocalizedErrorMessages;
class ErrorContext;
class RetryAfterCalculator;
class FederationErrorHandler;
class ClientErrorHandler;
class AdminErrorHandler;
class ErrorAuditLogger;
class ErrorSanitizer;
class ErrorTemplateLibrary;
class ErrorMetrics;

// ============================================================================
// Constants
// ============================================================================

// Matrix error code string constants — canonical representations
namespace error_codes {

// --- Standard Client-Server API error codes ---
constexpr const char* M_FORBIDDEN               = "M_FORBIDDEN";
constexpr const char* M_UNKNOWN_TOKEN           = "M_UNKNOWN_TOKEN";
constexpr const char* M_MISSING_TOKEN           = "M_MISSING_TOKEN";
constexpr const char* M_BAD_JSON                = "M_BAD_JSON";
constexpr const char* M_NOT_JSON                = "M_NOT_JSON";
constexpr const char* M_NOT_FOUND               = "M_NOT_FOUND";
constexpr const char* M_LIMIT_EXCEEDED          = "M_LIMIT_EXCEEDED";
constexpr const char* M_UNKNOWN                 = "M_UNKNOWN";
constexpr const char* M_UNRECOGNIZED            = "M_UNRECOGNIZED";
constexpr const char* M_UNAUTHORIZED            = "M_UNAUTHORIZED";
constexpr const char* M_USER_DEACTIVATED        = "M_USER_DEACTIVATED";
constexpr const char* M_USER_IN_USE             = "M_USER_IN_USE";
constexpr const char* M_INVALID_USERNAME        = "M_INVALID_USERNAME";
constexpr const char* M_ROOM_IN_USE             = "M_ROOM_IN_USE";
constexpr const char* M_INVALID_ROOM_STATE      = "M_INVALID_ROOM_STATE";
constexpr const char* M_THREEPID_IN_USE         = "M_THREEPID_IN_USE";
constexpr const char* M_THREEPID_NOT_FOUND      = "M_THREEPID_NOT_FOUND";
constexpr const char* M_THREEPID_AUTH_FAILED    = "M_THREEPID_AUTH_FAILED";
constexpr const char* M_THREEPID_DENIED         = "M_THREEPID_DENIED";
constexpr const char* M_SERVER_NOT_TRUSTED      = "M_SERVER_NOT_TRUSTED";
constexpr const char* M_UNSUPPORTED_ROOM_VERSION = "M_UNSUPPORTED_ROOM_VERSION";
constexpr const char* M_INCOMPATIBLE_ROOM_VERSION = "M_INCOMPATIBLE_ROOM_VERSION";
constexpr const char* M_BAD_STATE               = "M_BAD_STATE";
constexpr const char* M_GUEST_ACCESS_FORBIDDEN  = "M_GUEST_ACCESS_FORBIDDEN";
constexpr const char* M_CAPTCHA_NEEDED          = "M_CAPTCHA_NEEDED";
constexpr const char* M_CAPTCHA_INVALID         = "M_CAPTCHA_INVALID";
constexpr const char* M_MISSING_PARAM           = "M_MISSING_PARAM";
constexpr const char* M_INVALID_PARAM           = "M_INVALID_PARAM";
constexpr const char* M_TOO_LARGE               = "M_TOO_LARGE";
constexpr const char* M_EXCLUSIVE               = "M_EXCLUSIVE";
constexpr const char* M_RESOURCE_LIMIT_EXCEEDED = "M_RESOURCE_LIMIT_EXCEEDED";
constexpr const char* M_CANNOT_LEAVE_SERVER_NOTICE_ROOM = "M_CANNOT_LEAVE_SERVER_NOTICE_ROOM";
constexpr const char* M_WEAK_PASSWORD           = "M_WEAK_PASSWORD";
constexpr const char* M_EXPIRED_ACCOUNT         = "M_EXPIRED_ACCOUNT";
constexpr const char* M_SESSION_EXPIRED         = "M_SESSION_EXPIRED";
constexpr const char* M_UNKNOWN_SESSION         = "M_UNKNOWN_SESSION";
constexpr const char* M_CONSENT_NOT_GIVEN       = "M_CONSENT_NOT_GIVEN";
constexpr const char* M_TERMS_NOT_SIGNED        = "M_TERMS_NOT_SIGNED";
constexpr const char* M_BAD_PAGINATION          = "M_BAD_PAGINATION";
constexpr const char* M_UNKNOWN_POSITION        = "M_UNKNOWN_POSITION";
constexpr const char* M_NOT_YET_UPLOADED        = "M_NOT_YET_UPLOADED";
constexpr const char* M_ROOM_VERSION_UNSUPPORTED = "M_ROOM_VERSION_UNSUPPORTED";

// --- User-Interactive Authentication error codes ---
constexpr const char* M_UIA_AUTH_NOT_SUPPORTED  = "M_AUTH_NOT_SUPPORTED";
constexpr const char* M_UIA_STAGE_NOT_COMPLETED = "M_STAGE_NOT_COMPLETED";
constexpr const char* M_UIA_STAGE_EXPIRED       = "M_AUTH_STAGE_EXPIRED";
constexpr const char* M_UIA_NO_VALID_SESSION    = "M_NO_VALID_SESSION";

// --- Federation error codes ---
constexpr const char* M_UNREACHABLE             = "M_UNREACHABLE";
constexpr const char* M_CONNECTION_FAILED       = "M_CONNECTION_FAILED";
constexpr const char* M_DNS_ERROR               = "M_DNS_ERROR";
constexpr const char* M_TLS_ERROR               = "M_TLS_ERROR";
constexpr const char* M_SIGNATURE_INVALID       = "M_SIGNATURE_INVALID";
constexpr const char* M_SIGNATURE_MISMATCH      = "M_SIGNATURE_MISMATCH";
constexpr const char* M_UNKNOWN_ENDPOINT        = "M_UNKNOWN_ENDPOINT";
constexpr const char* M_WRONG_ROOM_KEYS_VERSION = "M_WRONG_ROOM_KEYS_VERSION";
constexpr const char* M_EVENT_NOT_FOUND         = "M_EVENT_NOT_FOUND";
constexpr const char* M_ALREADY_JOINED          = "M_ALREADY_JOINED";
constexpr const char* M_NOT_JOINED              = "M_NOT_JOINED";
constexpr const char* M_INCOMPATIBLE_PRESENCE   = "M_INCOMPATIBLE_PRESENCE";

// --- Rate limiting ---
constexpr const char* M_RATE_LIMITED            = "M_LIMIT_EXCEEDED";
constexpr const char* M_REQUEST_FAILED          = "M_REQUEST_FAILED";

// --- Media errors ---
constexpr const char* M_MEDIA_TOO_LARGE         = "M_TOO_LARGE";
constexpr const char* M_MEDIA_UNSUPPORTED       = "M_UNSUPPORTED_MEDIA";
constexpr const char* M_MEDIA_NOT_FOUND         = "M_NOT_FOUND";
constexpr const char* M_MEDIA_UPLOAD_FAILED     = "M_UNKNOWN";
constexpr const char* M_MEDIA_QUARANTINED       = "M_FORBIDDEN";

// --- Device management ---
constexpr const char* M_NO_SUCH_DEVICE          = "M_NOT_FOUND";
constexpr const char* M_DEVICE_EXISTS           = "M_EXCLUSIVE";
constexpr const char* M_TOO_MANY_DEVICES        = "M_RESOURCE_LIMIT_EXCEEDED";

// --- Push notifications ---
constexpr const char* M_PUSH_RULE_NOT_FOUND     = "M_NOT_FOUND";
constexpr const char* M_PUSH_RULE_EXISTS        = "M_EXCLUSIVE";

// --- Room errors (extended) ---
constexpr const char* M_ROOM_NOT_FOUND          = "M_NOT_FOUND";
constexpr const char* M_USER_NOT_IN_ROOM        = "M_FORBIDDEN";
constexpr const char* M_BANNED_FROM_ROOM        = "M_FORBIDDEN";
constexpr const char* M_INVITE_NOT_FOUND        = "M_NOT_FOUND";
constexpr const char* M_ALIAS_IN_USE            = "M_ROOM_IN_USE";
constexpr const char* M_ALIAS_NOT_FOUND         = "M_NOT_FOUND";
constexpr const char* M_POWER_LEVEL_INSUFFICIENT = "M_FORBIDDEN";
constexpr const char* M_MEMBERSHIP_LIMIT_REACHED = "M_RESOURCE_LIMIT_EXCEEDED";

// --- Account / Registration ---
constexpr const char* M_REGISTRATION_DISABLED   = "M_FORBIDDEN";
constexpr const char* M_LOGIN_FAILED            = "M_FORBIDDEN";
constexpr const char* M_PASSWORD_TOO_SHORT      = "M_WEAK_PASSWORD";
constexpr const char* M_PASSWORD_NO_DIGIT       = "M_WEAK_PASSWORD";
constexpr const char* M_PASSWORD_NO_UPPERCASE   = "M_WEAK_PASSWORD";
constexpr const char* M_PASSWORD_NO_LOWERCASE   = "M_WEAK_PASSWORD";
constexpr const char* M_PASSWORD_NO_SYMBOL      = "M_WEAK_PASSWORD";
constexpr const char* M_PASSWORD_IN_DICTIONARY  = "M_WEAK_PASSWORD";
constexpr const char* M_EMAIL_NOT_VERIFIED      = "M_THREEPID_AUTH_FAILED";
constexpr const char* M_MSISDN_NOT_VERIFIED     = "M_THREEPID_AUTH_FAILED";
constexpr const char* M_TOKEN_EXPIRED           = "M_UNKNOWN_TOKEN";
constexpr const char* M_TOKEN_NOT_FOUND         = "M_UNKNOWN_TOKEN";

// --- SSO / OIDC ---
constexpr const char* M_SSO_NOT_SUPPORTED        = "M_UNKNOWN";
constexpr const char* M_OIDC_PROVIDER_ERROR      = "M_UNKNOWN";
constexpr const char* M_OIDC_STATE_MISMATCH      = "M_FORBIDDEN";

// --- Application Service ---
constexpr const char* M_AS_EXCLUSIVE            = "M_EXCLUSIVE";
constexpr const char* M_AS_UNKNOWN_NAMESPACE    = "M_UNKNOWN";

// --- Admin ---
constexpr const char* M_ADMIN_ONLY              = "M_FORBIDDEN";
constexpr const char* M_SERVER_SHUTTING_DOWN    = "M_UNKNOWN";
constexpr const char* M_MAINTENANCE_MODE        = "M_UNKNOWN";

// --- Internal / implementation-specific ---
constexpr const char* M_INTERNAL_ERROR          = "M_UNKNOWN";
constexpr const char* M_DATABASE_ERROR          = "M_UNKNOWN";
constexpr const char* M_CACHE_ERROR             = "M_UNKNOWN";
constexpr const char* M_CONFIG_ERROR            = "M_UNKNOWN";
constexpr const char* M_WORKER_ERROR            = "M_UNKNOWN";
constexpr const char* M_TIMEOUT                 = "M_REQUEST_FAILED";

} // namespace error_codes

// ============================================================================
// ErrorCategory — semantic classification of error codes
// ============================================================================
enum class ErrorCategory : uint8_t {
    UNKNOWN         = 0,
    AUTH            = 1,   // Authentication and authorization
    PERMISSION      = 2,   // Insufficient permissions
    VALIDATION      = 3,   // Input validation failures
    NOT_FOUND       = 4,   // Resource not found
    RATE_LIMIT      = 5,   // Rate limiting
    SERVER          = 6,   // Internal server errors
    FEDERATION      = 7,   // Federation / S2S errors
    ROOM            = 8,   // Room-specific errors
    USER_DATA       = 9,   // User account and profile errors
    THREEPID        = 10,  // Third-party identifier errors
    MEDIA           = 11,  // Media repository errors
    DEVICE          = 12,  // Device management errors
    UIA             = 13,  // User-interactive authentication
    CONSENT         = 14,  // Terms of service / consent
    CONFIGURATION   = 15,  // Server configuration errors
    RESOURCE        = 16,  // Resource exhaustion
    CRYPTO          = 17,  // Cryptographic / E2EE errors
    SYNC            = 18,  // Sync-related errors
    PUSH            = 19,  // Push notification errors
    SSO             = 20,  // Single sign-on errors
    APP_SERVICE     = 21,  // Application service errors
    ADMIN           = 22,  // Admin API errors
    MAINTENANCE     = 23,  // Maintenance mode errors
    SIZE            = 24,  // Count of categories
};

// Category to string
constexpr const char* error_category_name(ErrorCategory cat) {
    switch (cat) {
        case ErrorCategory::UNKNOWN:       return "UNKNOWN";
        case ErrorCategory::AUTH:          return "AUTH";
        case ErrorCategory::PERMISSION:    return "PERMISSION";
        case ErrorCategory::VALIDATION:    return "VALIDATION";
        case ErrorCategory::NOT_FOUND:     return "NOT_FOUND";
        case ErrorCategory::RATE_LIMIT:    return "RATE_LIMIT";
        case ErrorCategory::SERVER:        return "SERVER";
        case ErrorCategory::FEDERATION:    return "FEDERATION";
        case ErrorCategory::ROOM:          return "ROOM";
        case ErrorCategory::USER_DATA:     return "USER_DATA";
        case ErrorCategory::THREEPID:      return "THREEPID";
        case ErrorCategory::MEDIA:         return "MEDIA";
        case ErrorCategory::DEVICE:        return "DEVICE";
        case ErrorCategory::UIA:           return "UIA";
        case ErrorCategory::CONSENT:       return "CONSENT";
        case ErrorCategory::CONFIGURATION: return "CONFIGURATION";
        case ErrorCategory::RESOURCE:      return "RESOURCE";
        case ErrorCategory::CRYPTO:        return "CRYPTO";
        case ErrorCategory::SYNC:          return "SYNC";
        case ErrorCategory::PUSH:          return "PUSH";
        case ErrorCategory::SSO:           return "SSO";
        case ErrorCategory::APP_SERVICE:   return "APP_SERVICE";
        case ErrorCategory::ADMIN:         return "ADMIN";
        case ErrorCategory::MAINTENANCE:   return "MAINTENANCE";
        default:                           return "UNKNOWN";
    }
}

// HTTP status code ranges
constexpr bool is_client_error(int http_status) {
    return http_status >= 400 && http_status < 500;
}

constexpr bool is_server_error(int http_status) {
    return http_status >= 500 && http_status < 600;
}

constexpr bool is_error_http_status(int http_status) {
    return http_status >= 400;
}

// ============================================================================
// ErrorSeverity — severity level for logging and alerting
// ============================================================================
enum class ErrorSeverity : uint8_t {
    DEBUG     = 0,
    INFO      = 1,
    WARNING   = 2,
    ERROR     = 3,
    CRITICAL  = 4,
    EMERGENCY = 5,
};

constexpr const char* severity_name(ErrorSeverity s) {
    switch (s) {
        case ErrorSeverity::DEBUG:     return "DEBUG";
        case ErrorSeverity::INFO:      return "INFO";
        case ErrorSeverity::WARNING:   return "WARNING";
        case ErrorSeverity::ERROR:     return "ERROR";
        case ErrorSeverity::CRITICAL:  return "CRITICAL";
        case ErrorSeverity::EMERGENCY: return "EMERGENCY";
        default:                       return "UNKNOWN_SEVERITY";
    }
}

// ============================================================================
// ErrorCodeMetadata — full metadata for a single error code
// ============================================================================
struct ErrorCodeMetadata {
    std::string code;              // Canonical code string: "M_FORBIDDEN"
    int default_http_status;      // Default HTTP status: 403
    std::string default_message;  // Default human-readable message
    ErrorCategory category;       // Semantic category
    ErrorSeverity severity;       // Severity level
    std::string description;      // Long description of the error
    std::string spec_version;     // Matrix spec version introduced
    bool deprecated;              // Whether this code is deprecated
    bool is_client_error;         // True for 4xx, false for 5xx
    bool requires_soft_logout;    // Whether this error should trigger soft logout
};

// ============================================================================
// ErrorResponse — structured, immutable error response
// ============================================================================
class ErrorResponse {
public:
    // --- Construction ---
    ErrorResponse() = default;

    ErrorResponse(int http_status, std::string errcode, std::string error_msg)
        : http_status_(http_status)
        , errcode_(std::move(errcode))
        , error_msg_(std::move(error_msg))
    {}

    // --- Accessors ---
    int http_status() const noexcept { return http_status_; }
    const std::string& errcode() const noexcept { return errcode_; }
    const std::string& error_msg() const noexcept { return error_msg_; }
    const std::optional<int64_t>& retry_after_ms() const noexcept { return retry_after_ms_; }
    bool soft_logout() const noexcept { return soft_logout_; }
    const std::optional<std::string>& admin_contact() const noexcept { return admin_contact_; }
    const std::optional<std::string>& consent_uri() const noexcept { return consent_uri_; }
    const std::optional<json>& completed() const noexcept { return completed_; }
    const std::optional<std::string>& session() const noexcept { return session_; }
    const std::optional<json>& params() const noexcept { return params_; }
    const std::optional<json>& flows() const noexcept { return flows_; }
    const std::optional<std::string>& request_id() const noexcept { return request_id_; }
    const std::optional<ErrorCategory>& category() const noexcept { return category_; }
    const std::optional<ErrorSeverity>& severity() const noexcept { return severity_; }
    const std::optional<std::string>& localized_message() const noexcept { return localized_message_; }

    // --- Mutators (for builder use) ---
    void set_retry_after_ms(int64_t ms) { retry_after_ms_ = ms; }
    void set_soft_logout(bool v) { soft_logout_ = v; }
    void set_admin_contact(std::string contact) { admin_contact_ = std::move(contact); }
    void set_consent_uri(std::string uri) { consent_uri_ = std::move(uri); }
    void set_completed(json stages) { completed_ = std::move(stages); }
    void set_session(std::string s) { session_ = std::move(s); }
    void set_params(json p) { params_ = std::move(p); }
    void set_flows(json f) { flows_ = std::move(f); }
    void set_request_id(std::string rid) { request_id_ = std::move(rid); }
    void set_category(ErrorCategory cat) { category_ = cat; }
    void set_severity(ErrorSeverity sev) { severity_ = sev; }
    void set_localized_message(std::string msg) { localized_message_ = std::move(msg); }

    // --- JSON serialization ---
    json to_json() const {
        json j;
        j["errcode"] = errcode_;
        j["error"] = error_msg_;

        if (retry_after_ms_.has_value()) {
            j["retry_after_ms"] = retry_after_ms_.value();
        }
        if (soft_logout_) {
            j["soft_logout"] = true;
        }
        if (admin_contact_.has_value()) {
            j["admin_contact"] = admin_contact_.value();
        }
        if (consent_uri_.has_value()) {
            j["consent_uri"] = consent_uri_.value();
        }
        if (completed_.has_value()) {
            j["completed"] = completed_.value();
        }
        if (session_.has_value()) {
            j["session"] = session_.value();
        }
        if (params_.has_value()) {
            j["params"] = params_.value();
        }
        if (flows_.has_value()) {
            j["flows"] = flows_.value();
        }
        if (localized_message_.has_value()) {
            j["error_localized"] = localized_message_.value();
        }

        return j;
    }

    std::string to_json_string() const {
        return to_json().dump();
    }

    std::string to_json_string_pretty() const {
        return to_json().dump(2);
    }

    // --- Utility ---
    bool is_client_error() const noexcept {
        return http_status_ >= 400 && http_status_ < 500;
    }

    bool is_server_error() const noexcept {
        return http_status_ >= 500;
    }

    bool is_rate_limited() const noexcept {
        return errcode_ == error_codes::M_LIMIT_EXCEEDED ||
               errcode_ == error_codes::M_RATE_LIMITED;
    }

    bool is_auth_error() const noexcept {
        return errcode_ == error_codes::M_UNKNOWN_TOKEN ||
               errcode_ == error_codes::M_MISSING_TOKEN ||
               errcode_ == error_codes::M_UNAUTHORIZED ||
               errcode_ == error_codes::M_FORBIDDEN;
    }

    std::string to_log_string() const {
        std::ostringstream oss;
        oss << "[" << http_status_ << "] " << errcode_ << ": " << error_msg_;
        if (request_id_.has_value()) {
            oss << " (req=" << request_id_.value() << ")";
        }
        return oss.str();
    }

private:
    int http_status_ = 500;
    std::string errcode_ = error_codes::M_UNKNOWN;
    std::string error_msg_ = "An unknown error occurred";
    std::optional<int64_t> retry_after_ms_;
    bool soft_logout_ = false;
    std::optional<std::string> admin_contact_;
    std::optional<std::string> consent_uri_;
    std::optional<json> completed_;    // UIA completed stages
    std::optional<std::string> session_; // UIA session
    std::optional<json> params_;       // UIA auth params
    std::optional<json> flows_;        // UIA available flows
    std::optional<std::string> request_id_;
    std::optional<ErrorCategory> category_;
    std::optional<ErrorSeverity> severity_;
    std::optional<std::string> localized_message_;
};

// ============================================================================
// MatrixErrorException — C++ exception carrying an ErrorResponse
// ============================================================================
class MatrixErrorException : public std::runtime_error {
public:
    explicit MatrixErrorException(ErrorResponse error)
        : std::runtime_error(error.error_msg())
        , error_(std::move(error))
    {}

    explicit MatrixErrorException(int http_status, std::string errcode, std::string error_msg)
        : std::runtime_error(error_msg)
        , error_(http_status, std::move(errcode), std::move(error_msg))
    {}

    const ErrorResponse& error() const noexcept { return error_; }

    int http_status() const noexcept { return error_.http_status(); }
    const std::string& errcode() const noexcept { return error_.errcode(); }

private:
    ErrorResponse error_;
};

// ============================================================================
// ErrorRegistry — thread-safe singleton catalog of all error codes
// ============================================================================
class ErrorRegistry {
public:
    static ErrorRegistry& instance() {
        static ErrorRegistry registry;
        return registry;
    }

    // Register an error code
    void register_code(ErrorCodeMetadata metadata) {
        std::unique_lock lock(mutex_);
        codes_[metadata.code] = std::move(metadata);
    }

    // Look up metadata by error code string
    std::optional<ErrorCodeMetadata> lookup(const std::string& code) const {
        std::shared_lock lock(mutex_);
        auto it = codes_.find(code);
        if (it != codes_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Get default HTTP status for an error code
    int default_http_status(const std::string& code) const {
        auto meta = lookup(code);
        return meta ? meta->default_http_status : 500;
    }

    // Get default message for an error code
    std::string default_message(const std::string& code) const {
        auto meta = lookup(code);
        return meta ? meta->default_message : "An unknown error occurred";
    }

    // Get category for an error code
    ErrorCategory category(const std::string& code) const {
        auto meta = lookup(code);
        return meta ? meta->category : ErrorCategory::UNKNOWN;
    }

    // Check if an error code is known
    bool is_known(const std::string& code) const {
        std::shared_lock lock(mutex_);
        return codes_.find(code) != codes_.end();
    }

    // Get all registered codes
    std::vector<std::string> all_codes() const {
        std::shared_lock lock(mutex_);
        std::vector<std::string> result;
        result.reserve(codes_.size());
        for (const auto& [code, _] : codes_) {
            result.push_back(code);
        }
        return result;
    }

    // Get codes by category
    std::vector<std::string> codes_by_category(ErrorCategory cat) const {
        std::shared_lock lock(mutex_);
        std::vector<std::string> result;
        for (const auto& [code, meta] : codes_) {
            if (meta.category == cat) {
                result.push_back(code);
            }
        }
        return result;
    }

    // Get all metadata
    std::vector<ErrorCodeMetadata> all_metadata() const {
        std::shared_lock lock(mutex_);
        std::vector<ErrorCodeMetadata> result;
        result.reserve(codes_.size());
        for (const auto& [_, meta] : codes_) {
            result.push_back(meta);
        }
        return result;
    }

    // Dump entire registry as JSON (for debugging/admin)
    json dump_json() const {
        std::shared_lock lock(mutex_);
        json j = json::array();
        for (const auto& [code, meta] : codes_) {
            json entry;
            entry["code"] = meta.code;
            entry["http_status"] = meta.default_http_status;
            entry["message"] = meta.default_message;
            entry["category"] = error_category_name(meta.category);
            entry["severity"] = severity_name(meta.severity);
            entry["description"] = meta.description;
            entry["spec_version"] = meta.spec_version;
            entry["deprecated"] = meta.deprecated;
            j.push_back(entry);
        }
        return j;
    }

    size_t size() const {
        std::shared_lock lock(mutex_);
        return codes_.size();
    }

private:
    ErrorRegistry() { initialize_defaults(); }

    void initialize_defaults();

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, ErrorCodeMetadata> codes_;
};

// Initialize the error registry with all Matrix-spec error codes
void ErrorRegistry::initialize_defaults() {
    // =========================================================================
    // Client-Server API Standard Errors
    // =========================================================================

    register_code({
        error_codes::M_FORBIDDEN,
        403,
        "You do not have permission to perform this action.",
        ErrorCategory::PERMISSION,
        ErrorSeverity::WARNING,
        "The requester does not have sufficient permission to access or modify "
        "the requested resource. This includes cases where the user lacks the "
        "required power level in a room, or the server has denied the action "
        "due to policy.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_UNKNOWN_TOKEN,
        401,
        "The access token specified was not recognised.",
        ErrorCategory::AUTH,
        ErrorSeverity::WARNING,
        "The provided access token is unknown, expired, or has been revoked. "
        "The client should prompt the user to re-authenticate. The soft_logout "
        "field should be set to true if the client should retain encryption state.",
        "r0.0.0",
        false,
        true,
        true
    });

    register_code({
        error_codes::M_MISSING_TOKEN,
        401,
        "No access token was specified for the request.",
        ErrorCategory::AUTH,
        ErrorSeverity::WARNING,
        "The request did not include an access token via the Authorization header "
        "or the access_token query parameter. All authenticated endpoints require "
        "a valid access token.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_BAD_JSON,
        400,
        "The request body could not be parsed as valid JSON.",
        ErrorCategory::VALIDATION,
        ErrorSeverity::INFO,
        "The Content-Type was application/json but the request body was not valid "
        "JSON. This includes malformed JSON, trailing commas, unquoted keys, or "
        "invalid escape sequences.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_NOT_JSON,
        400,
        "The request body did not contain valid JSON.",
        ErrorCategory::VALIDATION,
        ErrorSeverity::INFO,
        "The Content-Type header was not application/json, or the request body "
        "was empty when JSON was expected.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_NOT_FOUND,
        404,
        "The requested resource was not found.",
        ErrorCategory::NOT_FOUND,
        ErrorSeverity::INFO,
        "The requested endpoint, room, event, user, or other resource does not "
        "exist or is not visible to the requester.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_LIMIT_EXCEEDED,
        429,
        "Too many requests have been sent in a short period of time.",
        ErrorCategory::RATE_LIMIT,
        ErrorSeverity::WARNING,
        "The client has exceeded the rate limit for the requested endpoint. "
        "The retry_after_ms field indicates how long to wait before retrying. "
        "The server may also include a Retry-After HTTP header.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_UNKNOWN,
        500,
        "An unknown error occurred.",
        ErrorCategory::UNKNOWN,
        ErrorSeverity::ERROR,
        "An unexpected error occurred that does not fit any other error category. "
        "This is typically used as a fallback when the server encounters an "
        "unhandled exception or internal state inconsistency.",
        "r0.0.0",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_UNRECOGNIZED,
        400,
        "The server did not understand the request.",
        ErrorCategory::VALIDATION,
        ErrorSeverity::INFO,
        "The server could not parse or understand the request. This differs from "
        "M_BAD_JSON in that the JSON may be valid but the structure or values "
        "are not what the endpoint expects.",
        "r0.0.1",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_UNAUTHORIZED,
        401,
        "Authentication is required to access this resource.",
        ErrorCategory::AUTH,
        ErrorSeverity::WARNING,
        "The request requires authentication, but no valid credentials were "
        "provided. This is more general than M_UNKNOWN_TOKEN and may apply to "
        "endpoints that require auth but received none at all.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_USER_DEACTIVATED,
        403,
        "This account has been deactivated.",
        ErrorCategory::USER_DATA,
        ErrorSeverity::WARNING,
        "The user account associated with the access token has been deactivated. "
        "The user cannot perform any actions and should be logged out.",
        "r0.2.0",
        false,
        true,
        true
    });

    register_code({
        error_codes::M_USER_IN_USE,
        400,
        "The desired user ID is already in use.",
        ErrorCategory::USER_DATA,
        ErrorSeverity::INFO,
        "The requested user ID is already taken by another user on this server. "
        "The client should prompt the user to choose a different user ID.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_INVALID_USERNAME,
        400,
        "The requested user ID is not valid.",
        ErrorCategory::VALIDATION,
        ErrorSeverity::INFO,
        "The provided user ID does not meet the server's username requirements. "
        "This may be due to invalid characters, length restrictions, reserved "
        "usernames, or namespaces reserved for application services.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_ROOM_IN_USE,
        400,
        "The requested room alias is already in use.",
        ErrorCategory::ROOM,
        ErrorSeverity::INFO,
        "The room alias requested is already mapped to an existing room on this "
        "server. The client should either use the existing room or choose a "
        "different alias.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_INVALID_ROOM_STATE,
        400,
        "The request would result in an invalid room state.",
        ErrorCategory::ROOM,
        ErrorSeverity::WARNING,
        "The requested state event would result in an invalid or disallowed "
        "room state. This could be due to violating room version rules, state "
        "resolution conflicts, or policy restrictions.",
        "r0.3.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_THREEPID_IN_USE,
        400,
        "The third-party identifier is already in use.",
        ErrorCategory::THREEPID,
        ErrorSeverity::INFO,
        "The email address or phone number is already associated with another "
        "account on this server.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_THREEPID_NOT_FOUND,
        404,
        "The third-party identifier was not found.",
        ErrorCategory::THREEPID,
        ErrorSeverity::INFO,
        "The email address or phone number is not associated with any account "
        "on this server.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_THREEPID_AUTH_FAILED,
        400,
        "Third-party identifier authentication failed.",
        ErrorCategory::THREEPID,
        ErrorSeverity::WARNING,
        "The authentication of the third-party identifier (email or phone) "
        "failed. The token may be invalid, expired, or already used.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_THREEPID_DENIED,
        403,
        "Third-party identifier is not allowed.",
        ErrorCategory::THREEPID,
        ErrorSeverity::WARNING,
        "The server's policy does not permit using this third-party identifier. "
        "This may be because the domain is not trusted, the identifier is on a "
        "blocklist, or the server requires specific identity server validation.",
        "r0.4.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_SERVER_NOT_TRUSTED,
        403,
        "The identity server is not trusted.",
        ErrorCategory::THREEPID,
        ErrorSeverity::WARNING,
        "The provided identity server is not trusted by this homeserver. The "
        "server administrator must configure trusted identity servers.",
        "r0.3.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_UNSUPPORTED_ROOM_VERSION,
        400,
        "The server does not support the requested room version.",
        ErrorCategory::ROOM,
        ErrorSeverity::WARNING,
        "The room version requested is not supported by this homeserver. The "
        "client should try a different room version or the server admin should "
        "upgrade the server to support newer room versions.",
        "r0.5.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_INCOMPATIBLE_ROOM_VERSION,
        400,
        "The room version is incompatible with the requested operation.",
        ErrorCategory::ROOM,
        ErrorSeverity::WARNING,
        "The room uses a version that does not support the requested operation. "
        "For example, attempting to set a state event that is not defined in "
        "that room version's specification.",
        "r0.7.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_BAD_STATE,
        400,
        "The request conflicts with the current room state.",
        ErrorCategory::ROOM,
        ErrorSeverity::WARNING,
        "The request would result in a state conflict. This may occur when two "
        "clients try to modify the same state concurrently, or when a state "
        "event references a previous state that has changed.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_GUEST_ACCESS_FORBIDDEN,
        403,
        "Guest access is not permitted for this resource.",
        ErrorCategory::PERMISSION,
        ErrorSeverity::INFO,
        "The endpoint or resource does not allow guest accounts. The user must "
        "register a full account or the server admin must enable guest access "
        "for this resource.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_CAPTCHA_NEEDED,
        401,
        "A CAPTCHA is required to complete this action.",
        ErrorCategory::UIA,
        ErrorSeverity::INFO,
        "The server requires a CAPTCHA challenge to be completed before the "
        "action can proceed. The response includes CAPTCHA parameters for the "
        "client to present to the user.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_CAPTCHA_INVALID,
        400,
        "The CAPTCHA response was invalid.",
        ErrorCategory::UIA,
        ErrorSeverity::INFO,
        "The provided CAPTCHA solution was incorrect. The user should be "
        "presented with a new CAPTCHA challenge.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_MISSING_PARAM,
        400,
        "A required parameter was missing from the request.",
        ErrorCategory::VALIDATION,
        ErrorSeverity::INFO,
        "The request is missing a required parameter. The error message should "
        "indicate which parameter is missing.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_INVALID_PARAM,
        400,
        "A parameter in the request was invalid.",
        ErrorCategory::VALIDATION,
        ErrorSeverity::INFO,
        "One or more parameters in the request had invalid values. The error "
        "message should indicate which parameter is invalid and why.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_TOO_LARGE,
        413,
        "The request body or uploaded content is too large.",
        ErrorCategory::VALIDATION,
        ErrorSeverity::INFO,
        "The request body, uploaded file, or message content exceeds the "
        "server's configured size limit.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_EXCLUSIVE,
        400,
        "The requested resource already exists with a different value.",
        ErrorCategory::VALIDATION,
        ErrorSeverity::INFO,
        "The resource being created or modified would conflict with an existing "
        "resource that has different properties. This is used for cases like "
        "account data keys that already exist.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_RESOURCE_LIMIT_EXCEEDED,
        400,
        "A resource limit has been exceeded.",
        ErrorCategory::RESOURCE,
        ErrorSeverity::WARNING,
        "The request would exceed a server-configured resource limit, such as "
        "maximum number of rooms, maximum number of devices, or maximum "
        "upload quota.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_CANNOT_LEAVE_SERVER_NOTICE_ROOM,
        403,
        "You cannot leave this server notice room.",
        ErrorCategory::ROOM,
        ErrorSeverity::INFO,
        "The user attempted to leave a server notice room, which is not "
        "permitted. Server notice rooms are managed by the server and users "
        "cannot voluntarily leave them.",
        "r0.4.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_WEAK_PASSWORD,
        400,
        "The provided password does not meet security requirements.",
        ErrorCategory::VALIDATION,
        ErrorSeverity::WARNING,
        "The password does not satisfy the server's password policy. This could "
        "be due to insufficient length, missing required character types, or "
        "the password appearing in a known compromised password list.",
        "v1.1",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_EXPIRED_ACCOUNT,
        403,
        "This account has expired.",
        ErrorCategory::USER_DATA,
        ErrorSeverity::WARNING,
        "The user's account has passed its expiration date and can no longer "
        "be used. The account may need to be renewed or re-registered.",
        "v1.2",
        false,
        true,
        true
    });

    register_code({
        error_codes::M_SESSION_EXPIRED,
        400,
        "The user-interactive authentication session has expired.",
        ErrorCategory::UIA,
        ErrorSeverity::INFO,
        "The UIA session has timed out or been invalidated. The client should "
        "start a new UIA flow.",
        "v1.2",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_UNKNOWN_SESSION,
        400,
        "The user-interactive authentication session is unknown.",
        ErrorCategory::UIA,
        ErrorSeverity::INFO,
        "The provided UIA session ID is not valid or does not exist. The "
        "client should start a new UIA flow.",
        "v1.2",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_CONSENT_NOT_GIVEN,
        403,
        "User has not given consent to the terms of service.",
        ErrorCategory::CONSENT,
        ErrorSeverity::WARNING,
        "The user must consent to the server's terms of service before "
        "performing this action. The response includes a consent_uri field "
        "pointing to the terms that must be accepted.",
        "v1.3",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_BAD_PAGINATION,
        400,
        "The pagination parameters were invalid.",
        ErrorCategory::VALIDATION,
        ErrorSeverity::INFO,
        "The pagination token or parameters provided were invalid. This could "
        "be due to a malformed token, an expired token, or incompatible "
        "pagination direction.",
        "v1.3",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_UNKNOWN_POSITION,
        400,
        "The pagination position is unknown.",
        ErrorCategory::VALIDATION,
        ErrorSeverity::INFO,
        "The requested pagination position does not exist in the stream. This "
        "may occur when the token refers to a position that has been purged "
        "or is in the future.",
        "v1.3",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_NOT_YET_UPLOADED,
        400,
        "The media has not been fully uploaded yet.",
        ErrorCategory::MEDIA,
        ErrorSeverity::INFO,
        "The client attempted to use or reference media that was uploaded with "
        "a multipart upload but the upload has not been completed.",
        "v1.7",
        false,
        true,
        false
    });

    // =========================================================================
    // User-Interactive Authentication (UIA) Errors
    // =========================================================================

    register_code({
        error_codes::M_UIA_AUTH_NOT_SUPPORTED,
        400,
        "The requested authentication type is not supported.",
        ErrorCategory::UIA,
        ErrorSeverity::INFO,
        "The authentication type requested by the client is not supported by "
        "the server. The server's response includes the supported flows.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_UIA_STAGE_NOT_COMPLETED,
        401,
        "A required authentication stage has not been completed.",
        ErrorCategory::UIA,
        ErrorSeverity::INFO,
        "The user has not completed one or more required stages of the "
        "user-interactive authentication flow. The response includes "
        "completed stages and remaining required stages.",
        "v1.1",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_UIA_STAGE_EXPIRED,
        400,
        "The authentication stage has expired.",
        ErrorCategory::UIA,
        ErrorSeverity::INFO,
        "The current UIA stage has timed out. The client should restart the "
        "authentication flow.",
        "v1.5",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_UIA_NO_VALID_SESSION,
        401,
        "No valid user-interactive authentication session found.",
        ErrorCategory::UIA,
        ErrorSeverity::WARNING,
        "No valid UIA session exists for this request. The client must "
        "initiate a new UIA flow.",
        "v1.5",
        false,
        true,
        false
    });

    // =========================================================================
    // Federation / Server-to-Server (S2S) Errors
    // =========================================================================

    register_code({
        error_codes::M_UNREACHABLE,
        502,
        "The remote server could not be reached.",
        ErrorCategory::FEDERATION,
        ErrorSeverity::ERROR,
        "The homeserver was unable to connect to the remote server. This could "
        "be due to DNS resolution failure, network unreachability, connection "
        "timeout, or the remote server being down.",
        "r0.0.0",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_CONNECTION_FAILED,
        502,
        "The connection to the remote server failed.",
        ErrorCategory::FEDERATION,
        ErrorSeverity::ERROR,
        "A connection was established but failed during the request. This could "
        "be a TCP reset, TLS handshake failure, or HTTP protocol error.",
        "r0.0.0",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_DNS_ERROR,
        502,
        "DNS resolution for the remote server failed.",
        ErrorCategory::FEDERATION,
        ErrorSeverity::ERROR,
        "The server's domain name could not be resolved. This includes NXDOMAIN "
        "responses, SERVFAIL, or timeout during DNS resolution.",
        "r0.0.0",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_TLS_ERROR,
        502,
        "TLS handshake with the remote server failed.",
        ErrorCategory::FEDERATION,
        ErrorSeverity::ERROR,
        "The TLS handshake failed due to certificate verification failure, "
        "protocol version mismatch, cipher suite incompatibility, or hostname "
        "verification failure.",
        "r0.0.0",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_SIGNATURE_INVALID,
        401,
        "The request signature was invalid.",
        ErrorCategory::FEDERATION,
        ErrorSeverity::WARNING,
        "The signature on a federation request could not be verified. This "
        "could be due to a key that has been revoked, an incorrect signing "
        "algorithm, or a tampered request body.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_SIGNATURE_MISMATCH,
        401,
        "The request signature does not match the expected value.",
        ErrorCategory::FEDERATION,
        ErrorSeverity::WARNING,
        "The signature on the request matches a known key but the signed "
        "content does not match the request. This may indicate request "
        "tampering or a bug in the signing implementation.",
        "r0.5.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_UNKNOWN_ENDPOINT,
        404,
        "The requested federation endpoint is not recognised.",
        ErrorCategory::FEDERATION,
        ErrorSeverity::WARNING,
        "The remote server sent a request to a federation endpoint that "
        "this server does not recognise.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_WRONG_ROOM_KEYS_VERSION,
        400,
        "The room keys version is incorrect.",
        ErrorCategory::CRYPTO,
        ErrorSeverity::WARNING,
        "The client uploaded room keys with an incorrect version number. "
        "The client should fetch the current version and retry.",
        "v1.1",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_EVENT_NOT_FOUND,
        404,
        "The requested event was not found.",
        ErrorCategory::NOT_FOUND,
        ErrorSeverity::INFO,
        "The event ID referenced in the request does not exist or is not "
        "visible to the requesting server or user.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_ALREADY_JOINED,
        400,
        "The user is already a member of this room.",
        ErrorCategory::ROOM,
        ErrorSeverity::INFO,
        "The user attempted to join a room they are already a member of. "
        "This is not an error in some contexts but may be returned by "
        "federation join endpoints.",
        "r0.3.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_NOT_JOINED,
        400,
        "The user is not a member of this room.",
        ErrorCategory::ROOM,
        ErrorSeverity::INFO,
        "The user attempted an action that requires room membership but "
        "they are not a member of the room.",
        "r0.3.0",
        false,
        true,
        false
    });

    // =========================================================================
    // Additional internal / extended error codes
    // =========================================================================

    register_code({
        error_codes::M_INTERNAL_ERROR,
        500,
        "An internal server error occurred.",
        ErrorCategory::SERVER,
        ErrorSeverity::ERROR,
        "An unexpected internal error occurred. The error has been logged and "
        "the server administrator has been notified if monitoring is configured.",
        "-",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_DATABASE_ERROR,
        500,
        "A database error occurred.",
        ErrorCategory::SERVER,
        ErrorSeverity::CRITICAL,
        "The server encountered a database error while processing the request. "
        "This may be a transient connection issue or a persistent data "
        "corruption problem.",
        "-",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_CACHE_ERROR,
        500,
        "A cache error occurred.",
        ErrorCategory::SERVER,
        ErrorSeverity::ERROR,
        "The server's cache layer encountered an error. The request may be "
        "retried.",
        "-",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_CONFIG_ERROR,
        500,
        "A server configuration error occurred.",
        ErrorCategory::CONFIGURATION,
        ErrorSeverity::CRITICAL,
        "The server's configuration is invalid or inconsistent. An "
        "administrator must fix the configuration before the server can "
        "process requests normally.",
        "-",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_WORKER_ERROR,
        500,
        "A worker process error occurred.",
        ErrorCategory::SERVER,
        ErrorSeverity::ERROR,
        "A background worker process encountered an error. The operation may "
        "be retried automatically.",
        "-",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_TIMEOUT,
        504,
        "The request timed out.",
        ErrorCategory::SERVER,
        ErrorSeverity::WARNING,
        "The server took too long to process the request and timed out. "
        "The client should retry with exponential backoff.",
        "-",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_REGISTRATION_DISABLED,
        403,
        "Registration is disabled on this server.",
        ErrorCategory::CONFIGURATION,
        ErrorSeverity::INFO,
        "The server administrator has disabled new user registration. "
        "Contact the server administrator for an invitation.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_LOGIN_FAILED,
        403,
        "Login failed. Invalid username or password.",
        ErrorCategory::AUTH,
        ErrorSeverity::WARNING,
        "The provided login credentials were incorrect. The user should "
        "verify their username and password and try again.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_PASSWORD_TOO_SHORT,
        400,
        "The password is too short.",
        ErrorCategory::VALIDATION,
        ErrorSeverity::INFO,
        "The password does not meet the minimum length requirement "
        "configured by the server administrator.",
        "v1.1",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_EMAIL_NOT_VERIFIED,
        400,
        "The email address has not been verified.",
        ErrorCategory::THREEPID,
        ErrorSeverity::INFO,
        "The email address must be verified before it can be used. The "
        "server should have sent a verification email.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_MSISDN_NOT_VERIFIED,
        400,
        "The phone number has not been verified.",
        ErrorCategory::THREEPID,
        ErrorSeverity::INFO,
        "The phone number must be verified before it can be used. The "
        "server should have sent a verification SMS.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_TOKEN_EXPIRED,
        401,
        "The access token has expired.",
        ErrorCategory::AUTH,
        ErrorSeverity::WARNING,
        "The access token has passed its expiration time. The client should "
        "refresh the token or prompt the user to re-authenticate.",
        "v1.3",
        false,
        true,
        true
    });

    register_code({
        error_codes::M_SSO_NOT_SUPPORTED,
        400,
        "Single sign-on is not supported on this server.",
        ErrorCategory::SSO,
        ErrorSeverity::INFO,
        "The server does not have SSO/OIDC configured. The user must use "
        "password-based authentication.",
        "v1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_OIDC_PROVIDER_ERROR,
        502,
        "The OIDC provider returned an error.",
        ErrorCategory::SSO,
        ErrorSeverity::ERROR,
        "The configured OpenID Connect provider returned an error during "
        "authentication. This may be a transient error or a configuration "
        "problem.",
        "v1.0",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_OIDC_STATE_MISMATCH,
        400,
        "The OIDC state parameter does not match.",
        ErrorCategory::SSO,
        ErrorSeverity::WARNING,
        "The state parameter returned by the OIDC provider does not match "
        "the one sent. This could indicate a CSRF attack or a misconfigured "
        "provider.",
        "v1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_AS_EXCLUSIVE,
        400,
        "The namespace is already registered by another application service.",
        ErrorCategory::APP_SERVICE,
        ErrorSeverity::WARNING,
        "The user/alias namespace requested by the application service is "
        "already exclusively claimed by another application service.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_AS_UNKNOWN_NAMESPACE,
        400,
        "The application service namespace is not registered.",
        ErrorCategory::APP_SERVICE,
        ErrorSeverity::WARNING,
        "The application service attempted to act on a namespace it has not "
        "registered.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_ADMIN_ONLY,
        403,
        "This endpoint is restricted to server administrators.",
        ErrorCategory::ADMIN,
        ErrorSeverity::WARNING,
        "The requested admin API endpoint requires administrative privileges.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_SERVER_SHUTTING_DOWN,
        503,
        "The server is shutting down.",
        ErrorCategory::MAINTENANCE,
        ErrorSeverity::WARNING,
        "The server is in the process of shutting down and is not accepting "
        "new requests. Retry after the shutdown is complete.",
        "v1.2",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_MAINTENANCE_MODE,
        503,
        "The server is in maintenance mode.",
        ErrorCategory::MAINTENANCE,
        ErrorSeverity::WARNING,
        "The server is in maintenance mode and is not accepting requests. "
        "Normal operation will resume soon.",
        "v1.2",
        false,
        false,
        false
    });

    register_code({
        error_codes::M_MEDIA_TOO_LARGE,
        413,
        "The uploaded media exceeds the maximum file size.",
        ErrorCategory::MEDIA,
        ErrorSeverity::INFO,
        "The uploaded file exceeds the server's configured maximum upload "
        "size. The client should compress or resize the file before "
        "uploading.",
        "v1.1",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_MEDIA_UNSUPPORTED,
        415,
        "The media format is not supported.",
        ErrorCategory::MEDIA,
        ErrorSeverity::INFO,
        "The uploaded file's MIME type is not in the server's allowed list "
        "of media types.",
        "v1.1",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_MEDIA_QUARANTINED,
        403,
        "The requested media has been quarantined by a server administrator.",
        ErrorCategory::MEDIA,
        ErrorSeverity::WARNING,
        "The media has been flagged and quarantined by an administrator. "
        "It is not available for download.",
        "v1.3",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_NO_SUCH_DEVICE,
        404,
        "The device was not found.",
        ErrorCategory::DEVICE,
        ErrorSeverity::INFO,
        "The device ID specified does not exist for this user.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_DEVICE_EXISTS,
        400,
        "A device with this ID already exists.",
        ErrorCategory::DEVICE,
        ErrorSeverity::INFO,
        "A device with the given device ID is already registered. Use a "
        "different device ID or delete the existing device first.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_TOO_MANY_DEVICES,
        400,
        "The maximum number of devices has been reached.",
        ErrorCategory::DEVICE,
        ErrorSeverity::WARNING,
        "The user has reached the maximum number of allowed devices. "
        "Existing devices must be deleted before new ones can be created.",
        "v1.1",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_PUSH_RULE_NOT_FOUND,
        404,
        "The push rule was not found.",
        ErrorCategory::PUSH,
        ErrorSeverity::INFO,
        "The specified push rule does not exist for this user.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_PUSH_RULE_EXISTS,
        400,
        "A push rule with this ID already exists.",
        ErrorCategory::PUSH,
        ErrorSeverity::INFO,
        "A push rule with the given parameters already exists. Delete the "
        "existing rule or modify it instead.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_BANNED_FROM_ROOM,
        403,
        "You are banned from this room.",
        ErrorCategory::ROOM,
        ErrorSeverity::WARNING,
        "The user has been banned from the room and cannot perform this "
        "action. The ban must be lifted by a room administrator.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_INVITE_NOT_FOUND,
        404,
        "The invite was not found.",
        ErrorCategory::ROOM,
        ErrorSeverity::INFO,
        "The specified invite does not exist or has expired.",
        "r0.2.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_ALIAS_IN_USE,
        400,
        "The room alias is already in use.",
        ErrorCategory::ROOM,
        ErrorSeverity::INFO,
        "The requested room alias is already mapped to a room. Choose a "
        "different alias.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_ALIAS_NOT_FOUND,
        404,
        "The room alias was not found.",
        ErrorCategory::ROOM,
        ErrorSeverity::INFO,
        "The specified room alias does not exist on this server.",
        "r0.0.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_POWER_LEVEL_INSUFFICIENT,
        403,
        "You do not have sufficient power level to perform this action.",
        ErrorCategory::ROOM,
        ErrorSeverity::WARNING,
        "The user's power level in the room is insufficient to perform this "
        "action. A room administrator or moderator must perform it, or the "
        "user's power level must be raised.",
        "r0.1.0",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_MEMBERSHIP_LIMIT_REACHED,
        400,
        "The room has reached its membership limit.",
        ErrorCategory::ROOM,
        ErrorSeverity::WARNING,
        "The room has reached the maximum number of members allowed by the "
        "server configuration. No new members can join until existing "
        "members leave or the limit is raised.",
        "v1.3",
        false,
        true,
        false
    });

    register_code({
        error_codes::M_INCOMPATIBLE_PRESENCE,
        400,
        "The presence state is incompatible with the current room state.",
        ErrorCategory::SYNC,
        ErrorSeverity::INFO,
        "The requested presence update conflicts with the user's current "
        "room membership state.",
        "v1.4",
        false,
        true,
        false
    });
}

// ============================================================================
// ErrorResponseBuilder — fluent builder for ErrorResponse objects
// ============================================================================
class ErrorResponseBuilder {
public:
    ErrorResponseBuilder() = default;

    explicit ErrorResponseBuilder(const std::string& errcode)
        : errcode_(errcode)
    {
        auto meta = ErrorRegistry::instance().lookup(errcode);
        if (meta) {
            http_status_ = meta->default_http_status;
            error_msg_ = meta->default_message;
            category_ = meta->category;
            severity_ = meta->severity;
        }
    }

    ErrorResponseBuilder(int http_status, std::string errcode, std::string error_msg)
        : http_status_(http_status)
        , errcode_(std::move(errcode))
        , error_msg_(std::move(error_msg))
    {}

    // --- Fluent setters ---

    ErrorResponseBuilder& http_status(int status) {
        http_status_ = status;
        return *this;
    }

    ErrorResponseBuilder& errcode(std::string code) {
        errcode_ = std::move(code);
        return *this;
    }

    ErrorResponseBuilder& error_msg(std::string msg) {
        error_msg_ = std::move(msg);
        return *this;
    }

    ErrorResponseBuilder& retry_after_ms(int64_t ms) {
        retry_after_ms_ = ms;
        return *this;
    }

    ErrorResponseBuilder& soft_logout(bool v = true) {
        soft_logout_ = v;
        return *this;
    }

    ErrorResponseBuilder& admin_contact(std::string contact) {
        admin_contact_ = std::move(contact);
        return *this;
    }

    ErrorResponseBuilder& consent_uri(std::string uri) {
        consent_uri_ = std::move(uri);
        return *this;
    }

    ErrorResponseBuilder& completed(json stages) {
        completed_ = std::move(stages);
        return *this;
    }

    ErrorResponseBuilder& session(std::string s) {
        session_ = std::move(s);
        return *this;
    }

    ErrorResponseBuilder& params(json p) {
        params_ = std::move(p);
        return *this;
    }

    ErrorResponseBuilder& flows(json f) {
        flows_ = std::move(f);
        return *this;
    }

    ErrorResponseBuilder& request_id(std::string rid) {
        request_id_ = std::move(rid);
        return *this;
    }

    ErrorResponseBuilder& category(ErrorCategory cat) {
        category_ = cat;
        return *this;
    }

    ErrorResponseBuilder& severity(ErrorSeverity sev) {
        severity_ = sev;
        return *this;
    }

    ErrorResponseBuilder& localized_message(std::string msg) {
        localized_message_ = std::move(msg);
        return *this;
    }

    // --- Build ---

    ErrorResponse build() const {
        ErrorResponse resp(http_status_, errcode_, error_msg_);
        if (retry_after_ms_.has_value()) resp.set_retry_after_ms(retry_after_ms_.value());
        if (soft_logout_) resp.set_soft_logout(true);
        if (admin_contact_.has_value()) resp.set_admin_contact(admin_contact_.value());
        if (consent_uri_.has_value()) resp.set_consent_uri(consent_uri_.value());
        if (completed_.has_value()) resp.set_completed(completed_.value());
        if (session_.has_value()) resp.set_session(session_.value());
        if (params_.has_value()) resp.set_params(params_.value());
        if (flows_.has_value()) resp.set_flows(flows_.value());
        if (request_id_.has_value()) resp.set_request_id(request_id_.value());
        if (category_.has_value()) resp.set_category(category_.value());
        if (severity_.has_value()) resp.set_severity(severity_.value());
        if (localized_message_.has_value()) resp.set_localized_message(localized_message_.value());
        return resp;
    }

    json build_json() const {
        return build().to_json();
    }

    std::string build_json_string() const {
        return build().to_json_string();
    }

private:
    int http_status_ = 500;
    std::string errcode_ = error_codes::M_UNKNOWN;
    std::string error_msg_ = "An unknown error occurred";
    std::optional<int64_t> retry_after_ms_;
    bool soft_logout_ = false;
    std::optional<std::string> admin_contact_;
    std::optional<std::string> consent_uri_;
    std::optional<json> completed_;
    std::optional<std::string> session_;
    std::optional<json> params_;
    std::optional<json> flows_;
    std::optional<std::string> request_id_;
    std::optional<ErrorCategory> category_;
    std::optional<ErrorSeverity> severity_;
    std::optional<std::string> localized_message_;
};

// ============================================================================
// HttpErrorMapper — maps error codes to HTTP status codes
// ============================================================================
class HttpErrorMapper {
public:
    // Map an error code string to the appropriate HTTP status code
    static int to_http_status(const std::string& errcode) {
        // Check the registry first
        auto meta = ErrorRegistry::instance().lookup(errcode);
        if (meta) {
            return meta->default_http_status;
        }

        // Fallback mappings for unknown or custom error codes
        if (errcode.find("M_FORBIDDEN") != std::string::npos) return 403;
        if (errcode.find("M_UNKNOWN_TOKEN") != std::string::npos) return 401;
        if (errcode.find("M_MISSING_TOKEN") != std::string::npos) return 401;
        if (errcode.find("M_UNAUTHORIZED") != std::string::npos) return 401;
        if (errcode.find("M_NOT_FOUND") != std::string::npos) return 404;
        if (errcode.find("M_BAD_JSON") != std::string::npos) return 400;
        if (errcode.find("M_NOT_JSON") != std::string::npos) return 400;
        if (errcode.find("M_LIMIT_EXCEEDED") != std::string::npos) return 429;
        if (errcode.find("M_TOO_LARGE") != std::string::npos) return 413;
        if (errcode.find("M_UNSUPPORTED") != std::string::npos) return 400;
        if (errcode.find("M_UNREACHABLE") != std::string::npos) return 502;
        if (errcode.find("M_CONNECTION_FAILED") != std::string::npos) return 502;
        if (errcode.find("M_DNS_ERROR") != std::string::npos) return 502;
        if (errcode.find("M_TLS_ERROR") != std::string::npos) return 502;
        if (errcode.find("M_TIMEOUT") != std::string::npos) return 504;
        if (errcode.find("M_CONFIG") != std::string::npos) return 500;
        if (errcode.find("M_WEAK_PASSWORD") != std::string::npos) return 400;
        if (errcode.find("M_CONSENT") != std::string::npos) return 403;
        if (errcode.find("M_MAINTENANCE") != std::string::npos) return 503;

        return 500; // Default for unknown error codes
    }

    // Map an HTTP status code to a canonical error code
    static std::string from_http_status(int http_status) {
        switch (http_status) {
            case 400: return error_codes::M_UNKNOWN;
            case 401: return error_codes::M_UNAUTHORIZED;
            case 403: return error_codes::M_FORBIDDEN;
            case 404: return error_codes::M_NOT_FOUND;
            case 405: return error_codes::M_UNKNOWN; // Method Not Allowed
            case 406: return error_codes::M_UNKNOWN; // Not Acceptable
            case 408: return error_codes::M_TIMEOUT;
            case 409: return error_codes::M_EXCLUSIVE;
            case 410: return error_codes::M_NOT_FOUND; // Gone
            case 413: return error_codes::M_TOO_LARGE;
            case 414: return error_codes::M_TOO_LARGE; // URI Too Long
            case 415: return error_codes::M_MEDIA_UNSUPPORTED;
            case 422: return error_codes::M_INVALID_PARAM; // Unprocessable Entity
            case 429: return error_codes::M_LIMIT_EXCEEDED;
            case 500: return error_codes::M_UNKNOWN;
            case 501: return error_codes::M_UNKNOWN; // Not Implemented
            case 502: return error_codes::M_UNREACHABLE;
            case 503: return error_codes::M_MAINTENANCE_MODE;
            case 504: return error_codes::M_TIMEOUT;
            default:
                if (http_status >= 500) return error_codes::M_UNKNOWN;
                return error_codes::M_UNKNOWN;
        }
    }

    // Get a human-readable phrase for an HTTP status code
    static std::string http_status_phrase(int http_status) {
        switch (http_status) {
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 402: return "Payment Required";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 406: return "Not Acceptable";
            case 407: return "Proxy Authentication Required";
            case 408: return "Request Timeout";
            case 409: return "Conflict";
            case 410: return "Gone";
            case 411: return "Length Required";
            case 412: return "Precondition Failed";
            case 413: return "Payload Too Large";
            case 414: return "URI Too Long";
            case 415: return "Unsupported Media Type";
            case 416: return "Range Not Satisfiable";
            case 417: return "Expectation Failed";
            case 421: return "Misdirected Request";
            case 422: return "Unprocessable Entity";
            case 423: return "Locked";
            case 424: return "Failed Dependency";
            case 425: return "Too Early";
            case 426: return "Upgrade Required";
            case 428: return "Precondition Required";
            case 429: return "Too Many Requests";
            case 431: return "Request Header Fields Too Large";
            case 451: return "Unavailable For Legal Reasons";
            case 500: return "Internal Server Error";
            case 501: return "Not Implemented";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            case 504: return "Gateway Timeout";
            case 505: return "HTTP Version Not Supported";
            case 506: return "Variant Also Negotiates";
            case 507: return "Insufficient Storage";
            case 508: return "Loop Detected";
            case 510: return "Not Extended";
            case 511: return "Network Authentication Required";
            default:  return "Unknown Status";
        }
    }
};

// ============================================================================
// LocalizedErrorMessages — multi-language error message catalog
// ============================================================================
class LocalizedErrorMessages {
public:
    static LocalizedErrorMessages& instance() {
        static LocalizedErrorMessages catalog;
        return catalog;
    }

    // Get a localized message for an error code
    std::string get(const std::string& errcode, const std::string& locale = "en") const {
        std::shared_lock lock(mutex_);

        // Try exact locale
        auto locale_it = messages_.find(locale);
        if (locale_it != messages_.end()) {
            auto code_it = locale_it->second.find(errcode);
            if (code_it != locale_it->second.end()) {
                return code_it->second;
            }
        }

        // Try language-only (e.g., "fr" from "fr-FR")
        if (locale.size() >= 2) {
            std::string lang = locale.substr(0, 2);
            if (lang != locale) {
                auto lang_it = messages_.find(lang);
                if (lang_it != messages_.end()) {
                    auto code_it = lang_it->second.find(errcode);
                    if (code_it != lang_it->second.end()) {
                        return code_it->second;
                    }
                }
            }
        }

        // Fall back to English
        auto en_it = messages_.find("en");
        if (en_it != messages_.end()) {
            auto code_it = en_it->second.find(errcode);
            if (code_it != en_it->second.end()) {
                return code_it->second;
            }
        }

        // Fall back to default message from registry
        return ErrorRegistry::instance().default_message(errcode);
    }

    // Register a localized message
    void register_message(const std::string& errcode, const std::string& locale,
                          const std::string& message) {
        std::unique_lock lock(mutex_);
        messages_[locale][errcode] = message;
    }

    // Check if a locale is supported
    bool supports_locale(const std::string& locale) const {
        std::shared_lock lock(mutex_);
        return messages_.find(locale) != messages_.end();
    }

    // Get available locales
    std::vector<std::string> available_locales() const {
        std::shared_lock lock(mutex_);
        std::vector<std::string> result;
        result.reserve(messages_.size());
        for (const auto& [locale, _] : messages_) {
            result.push_back(locale);
        }
        return result;
    }

private:
    LocalizedErrorMessages() { initialize_defaults(); }

    void initialize_defaults() {
        // English (en) — default messages
        messages_["en"] = {
            {error_codes::M_FORBIDDEN, "You do not have permission to perform this action."},
            {error_codes::M_UNKNOWN_TOKEN, "The access token specified was not recognised."},
            {error_codes::M_MISSING_TOKEN, "No access token was specified for the request."},
            {error_codes::M_BAD_JSON, "The request body could not be parsed as valid JSON."},
            {error_codes::M_NOT_JSON, "The request body did not contain valid JSON."},
            {error_codes::M_NOT_FOUND, "The requested resource was not found."},
            {error_codes::M_LIMIT_EXCEEDED, "Too many requests. Please wait and try again."},
            {error_codes::M_UNKNOWN, "An unknown error occurred."},
            {error_codes::M_USER_IN_USE, "This username is already taken."},
            {error_codes::M_ROOM_IN_USE, "This room alias is already in use."},
            {error_codes::M_BAD_STATE, "The requested operation conflicts with the current state."},
            {error_codes::M_GUEST_ACCESS_FORBIDDEN, "Guests are not allowed to perform this action."},
            {error_codes::M_THREEPID_IN_USE, "This email or phone number is already associated with an account."},
            {error_codes::M_THREEPID_NOT_FOUND, "This email or phone number was not found."},
            {error_codes::M_THREEPID_AUTH_FAILED, "Failed to authenticate the email or phone number."},
            {error_codes::M_TOO_LARGE, "The uploaded content is too large."},
            {error_codes::M_EXCLUSIVE, "The requested resource already exists."},
            {error_codes::M_WEAK_PASSWORD, "The password does not meet security requirements."},
            {error_codes::M_CONSENT_NOT_GIVEN, "You must accept the terms of service to continue."},
            {error_codes::M_UNSUPPORTED_ROOM_VERSION, "This room version is not supported."},
            {error_codes::M_RESOURCE_LIMIT_EXCEEDED, "A resource limit has been exceeded."},
            {error_codes::M_UNAUTHORIZED, "Authentication is required."},
            {error_codes::M_USER_DEACTIVATED, "This account has been deactivated."},
        };

        // French (fr)
        messages_["fr"] = {
            {error_codes::M_FORBIDDEN, "Vous n'avez pas la permission d'effectuer cette action."},
            {error_codes::M_UNKNOWN_TOKEN, "Le jeton d'accès spécifié n'a pas été reconnu."},
            {error_codes::M_MISSING_TOKEN, "Aucun jeton d'accès n'a été spécifié pour la requête."},
            {error_codes::M_BAD_JSON, "Le corps de la requête n'a pas pu être analysé comme JSON valide."},
            {error_codes::M_NOT_JSON, "Le corps de la requête ne contient pas de JSON valide."},
            {error_codes::M_NOT_FOUND, "La ressource demandée est introuvable."},
            {error_codes::M_LIMIT_EXCEEDED, "Trop de requêtes. Veuillez patienter et réessayer."},
            {error_codes::M_UNKNOWN, "Une erreur inconnue est survenue."},
            {error_codes::M_USER_IN_USE, "Ce nom d'utilisateur est déjà pris."},
            {error_codes::M_UNAUTHORIZED, "Authentification requise."},
        };

        // German (de)
        messages_["de"] = {
            {error_codes::M_FORBIDDEN, "Sie haben keine Berechtigung für diese Aktion."},
            {error_codes::M_UNKNOWN_TOKEN, "Das angegebene Zugriffstoken wurde nicht erkannt."},
            {error_codes::M_MISSING_TOKEN, "Kein Zugriffstoken für die Anfrage angegeben."},
            {error_codes::M_BAD_JSON, "Der Anfragekörper konnte nicht als gültiges JSON analysiert werden."},
            {error_codes::M_NOT_FOUND, "Die angeforderte Ressource wurde nicht gefunden."},
            {error_codes::M_LIMIT_EXCEEDED, "Zu viele Anfragen. Bitte warten und erneut versuchen."},
            {error_codes::M_UNKNOWN, "Ein unbekannter Fehler ist aufgetreten."},
            {error_codes::M_UNAUTHORIZED, "Authentifizierung erforderlich."},
        };

        // Spanish (es)
        messages_["es"] = {
            {error_codes::M_FORBIDDEN, "No tienes permiso para realizar esta acción."},
            {error_codes::M_UNKNOWN_TOKEN, "El token de acceso especificado no fue reconocido."},
            {error_codes::M_MISSING_TOKEN, "No se especificó ningún token de acceso."},
            {error_codes::M_BAD_JSON, "El cuerpo de la solicitud no pudo ser analizado como JSON válido."},
            {error_codes::M_NOT_FOUND, "El recurso solicitado no fue encontrado."},
            {error_codes::M_LIMIT_EXCEEDED, "Demasiadas solicitudes. Por favor espera e inténtalo de nuevo."},
            {error_codes::M_UNKNOWN, "Ocurrió un error desconocido."},
            {error_codes::M_UNAUTHORIZED, "Se requiere autenticación."},
        };

        // Japanese (ja)
        messages_["ja"] = {
            {error_codes::M_FORBIDDEN, "この操作を実行する権限がありません。"},
            {error_codes::M_UNKNOWN_TOKEN, "指定されたアクセストークンが認識されませんでした。"},
            {error_codes::M_MISSING_TOKEN, "リクエストにアクセストークンが指定されていません。"},
            {error_codes::M_BAD_JSON, "リクエスト本文を有効なJSONとして解析できませんでした。"},
            {error_codes::M_NOT_FOUND, "要求されたリソースが見つかりませんでした。"},
            {error_codes::M_LIMIT_EXCEEDED, "リクエストが多すぎます。しばらく待ってから再試行してください。"},
            {error_codes::M_UNKNOWN, "不明なエラーが発生しました。"},
            {error_codes::M_UNAUTHORIZED, "認証が必要です。"},
        };
    }

    mutable std::shared_mutex mutex_;
    // locale -> (errcode -> message)
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> messages_;
};

// ============================================================================
// ErrorContext — rich error metadata for logging and debugging
// ============================================================================
class ErrorContext {
public:
    ErrorContext() = default;

    // --- Setters ---
    ErrorContext& with_request_id(std::string rid) {
        request_id_ = std::move(rid);
        return *this;
    }

    ErrorContext& with_user_id(std::string uid) {
        user_id_ = std::move(uid);
        return *this;
    }

    ErrorContext& with_device_id(std::string did) {
        device_id_ = std::move(did);
        return *this;
    }

    ErrorContext& with_room_id(std::string rid) {
        room_id_ = std::move(rid);
        return *this;
    }

    ErrorContext& with_event_id(std::string eid) {
        event_id_ = std::move(eid);
        return *this;
    }

    ErrorContext& with_endpoint(std::string ep) {
        endpoint_ = std::move(ep);
        return *this;
    }

    ErrorContext& with_method(std::string m) {
        method_ = std::move(m);
        return *this;
    }

    ErrorContext& with_client_ip(std::string ip) {
        client_ip_ = std::move(ip);
        return *this;
    }

    ErrorContext& with_user_agent(std::string ua) {
        user_agent_ = std::move(ua);
        return *this;
    }

    ErrorContext& with_error_code(std::string ec) {
        error_code_ = std::move(ec);
        return *this;
    }

    ErrorContext& with_error_message(std::string em) {
        error_message_ = std::move(em);
        return *this;
    }

    ErrorContext& with_http_status(int status) {
        http_status_ = status;
        return *this;
    }

    ErrorContext& with_timestamp(std::chrono::system_clock::time_point ts) {
        timestamp_ = ts;
        return *this;
    }

    ErrorContext& with_duration_ms(int64_t ms) {
        duration_ms_ = ms;
        return *this;
    }

    ErrorContext& with_source_file(std::string file) {
        source_file_ = std::move(file);
        return *this;
    }

    ErrorContext& with_source_line(int line) {
        source_line_ = line;
        return *this;
    }

    ErrorContext& with_source_function(std::string func) {
        source_function_ = std::move(func);
        return *this;
    }

    ErrorContext& with_stack_trace(std::string trace) {
        stack_trace_ = std::move(trace);
        return *this;
    }

    ErrorContext& with_category(ErrorCategory cat) {
        category_ = cat;
        return *this;
    }

    ErrorContext& with_severity(ErrorSeverity sev) {
        severity_ = sev;
        return *this;
    }

    ErrorContext& with_additional_data(json data) {
        additional_data_ = std::move(data);
        return *this;
    }

    // --- Accessors ---
    const std::optional<std::string>& request_id() const noexcept { return request_id_; }
    const std::optional<std::string>& user_id() const noexcept { return user_id_; }
    const std::optional<std::string>& device_id() const noexcept { return device_id_; }
    const std::optional<std::string>& room_id() const noexcept { return room_id_; }
    const std::optional<std::string>& event_id() const noexcept { return event_id_; }
    const std::optional<std::string>& endpoint() const noexcept { return endpoint_; }
    const std::optional<std::string>& method() const noexcept { return method_; }
    const std::optional<std::string>& client_ip() const noexcept { return client_ip_; }
    const std::optional<std::string>& user_agent() const noexcept { return user_agent_; }
    const std::optional<std::string>& error_code() const noexcept { return error_code_; }
    const std::optional<std::string>& error_message() const noexcept { return error_message_; }
    int http_status() const noexcept { return http_status_; }
    std::chrono::system_clock::time_point timestamp() const noexcept { return timestamp_; }
    int64_t duration_ms() const noexcept { return duration_ms_; }
    const std::optional<std::string>& source_file() const noexcept { return source_file_; }
    int source_line() const noexcept { return source_line_; }
    const std::optional<std::string>& source_function() const noexcept { return source_function_; }

    // --- Serialization ---
    json to_json() const {
        json j;
        j["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp_.time_since_epoch()).count();
        j["http_status"] = http_status_;

        if (error_code_.has_value()) j["errcode"] = error_code_.value();
        if (error_message_.has_value()) j["error"] = error_message_.value();
        if (request_id_.has_value()) j["request_id"] = request_id_.value();
        if (user_id_.has_value()) j["user_id"] = user_id_.value();
        if (device_id_.has_value()) j["device_id"] = device_id_.value();
        if (room_id_.has_value()) j["room_id"] = room_id_.value();
        if (event_id_.has_value()) j["event_id"] = event_id_.value();
        if (endpoint_.has_value()) j["endpoint"] = endpoint_.value();
        if (method_.has_value()) j["method"] = method_.value();
        if (client_ip_.has_value()) j["client_ip"] = client_ip_.value();
        if (user_agent_.has_value()) j["user_agent"] = user_agent_.value();
        if (duration_ms_ > 0) j["duration_ms"] = duration_ms_;
        if (category_.has_value()) j["category"] = error_category_name(category_.value());
        if (severity_.has_value()) j["severity"] = severity_name(severity_.value());
        if (source_file_.has_value()) j["source_file"] = source_file_.value();
        if (source_line_ > 0) j["source_line"] = source_line_;
        if (source_function_.has_value()) j["source_function"] = source_function_.value();
        if (additional_data_.has_value() && !additional_data_.value().empty()) {
            j["additional_data"] = additional_data_.value();
        }

        return j;
    }

    std::string to_log_line() const {
        std::ostringstream oss;
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp_.time_since_epoch()).count();
        oss << "[" << ms << "] ";

        if (severity_.has_value()) {
            oss << severity_name(severity_.value()) << " ";
        }

        oss << "HTTP " << http_status_;

        if (error_code_.has_value()) {
            oss << " " << error_code_.value();
        }

        if (error_message_.has_value()) {
            oss << " - " << error_message_.value();
        }

        if (request_id_.has_value()) {
            oss << " [req=" << request_id_.value() << "]";
        }
        if (user_id_.has_value()) {
            oss << " [user=" << user_id_.value() << "]";
        }
        if (endpoint_.has_value() && method_.has_value()) {
            oss << " [" << method_.value() << " " << endpoint_.value() << "]";
        }
        if (client_ip_.has_value()) {
            oss << " [ip=" << client_ip_.value() << "]";
        }
        if (duration_ms_ > 0) {
            oss << " [duration=" << duration_ms_ << "ms]";
        }

        return oss.str();
    }

private:
    std::optional<std::string> request_id_;
    std::optional<std::string> user_id_;
    std::optional<std::string> device_id_;
    std::optional<std::string> room_id_;
    std::optional<std::string> event_id_;
    std::optional<std::string> endpoint_;
    std::optional<std::string> method_;
    std::optional<std::string> client_ip_;
    std::optional<std::string> user_agent_;
    std::optional<std::string> error_code_;
    std::optional<std::string> error_message_;
    int http_status_ = 500;
    std::chrono::system_clock::time_point timestamp_ = std::chrono::system_clock::now();
    int64_t duration_ms_ = 0;
    std::optional<std::string> source_file_;
    int source_line_ = 0;
    std::optional<std::string> source_function_;
    std::optional<std::string> stack_trace_;
    std::optional<ErrorCategory> category_;
    std::optional<ErrorSeverity> severity_;
    std::optional<json> additional_data_;
};

// ============================================================================
// RetryAfterCalculator — computes retry_after_ms for rate-limited errors
// ============================================================================
class RetryAfterCalculator {
public:
    // --- Configuration ---
    struct Config {
        int64_t base_delay_ms = 1000;       // 1 second base
        int64_t max_delay_ms = 300000;      // 5 minutes max
        double backoff_multiplier = 2.0;    // Exponential factor
        double jitter_factor = 0.1;         // +/- 10% jitter
        bool use_exponential_backoff = true;
        int64_t fixed_window_ms = 60000;    // 1 minute for fixed window
    };

    explicit RetryAfterCalculator(Config config = {}) : config_(std::move(config)) {
        rng_.seed(std::random_device{}());
    }

    // Calculate retry_after for exponential backoff based on attempt count
    int64_t exponential_backoff(int attempt) const {
        if (attempt <= 0) return config_.base_delay_ms;

        double delay = config_.base_delay_ms * std::pow(config_.backoff_multiplier, attempt);
        delay = std::min(delay, static_cast<double>(config_.max_delay_ms));
        delay = apply_jitter(delay);

        return static_cast<int64_t>(delay);
    }

    // Calculate retry_after for a fixed window rate limiter
    int64_t fixed_window(int64_t window_start_ms) const {
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        int64_t window_end = window_start_ms + config_.fixed_window_ms;
        if (now >= window_end) return 0; // Already in new window

        int64_t remaining = window_end - now;
        return apply_jitter(static_cast<double>(remaining));
    }

    // Calculate retry_after for token bucket rate limiter
    int64_t token_bucket(double tokens_needed, double refill_rate_per_ms) const {
        if (refill_rate_per_ms <= 0) return config_.max_delay_ms;

        double ms_to_refill = (tokens_needed / refill_rate_per_ms);
        double delay = std::min(ms_to_refill, static_cast<double>(config_.max_delay_ms));
        delay = apply_jitter(delay);

        return static_cast<int64_t>(std::max(delay, static_cast<double>(config_.base_delay_ms)));
    }

    // Get a simple fixed retry_after
    int64_t fixed(int64_t ms) const {
        return apply_jitter(static_cast<double>(ms));
    }

    // Standard rate limit response
    int64_t standard_rate_limit() const {
        return apply_jitter(static_cast<double>(config_.base_delay_ms));
    }

    // Get recommended retry header value (including Retry-After HTTP header)
    std::string retry_after_header_value(int64_t retry_after_ms) const {
        // Use delay-seconds format for HTTP Retry-After header
        int64_t seconds = (retry_after_ms + 999) / 1000; // Ceiling division
        if (seconds < 1) seconds = 1;
        return std::to_string(seconds);
    }

private:
    double apply_jitter(double delay) const {
        if (config_.jitter_factor <= 0) return delay;

        std::uniform_real_distribution<double> dist(
            -config_.jitter_factor, config_.jitter_factor);
        double jitter = dist(rng_);
        return delay * (1.0 + jitter);
    }

    Config config_;
    mutable std::mt19937_64 rng_;
};

// ============================================================================
// ErrorSanitizer — prevent information leakage in client-facing errors
// ============================================================================
class ErrorSanitizer {
public:
    // Sanitize an error message for client-facing responses.
    // Replaces internal details (paths, stack traces, DB info) with
    // generic messages while logging the full error internally.
    static std::string sanitize_message(const std::string& raw_message,
                                         bool is_production = true) {
        if (!is_production) return raw_message;

        std::string sanitized = raw_message;

        // Redact file system paths
        static const std::regex path_regex(
            R"((?:/[\w.-]+)+/\w+\.\w+)",
            std::regex::ECMAScript | std::regex::optimize);
        sanitized = std::regex_replace(sanitized, path_regex, "[redacted-path]");

        // Redact SQL statements
        static const std::regex sql_regex(
            R"((?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE)\s+.+?(?:;|$))",
            std::regex::ECMAScript | std::regex::optimize | std::regex::icase);
        sanitized = std::regex_replace(sanitized, sql_regex, "[redacted-sql]");

        // Redact IP addresses
        static const std::regex ip_regex(
            R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)",
            std::regex::ECMAScript | std::regex::optimize);
        sanitized = std::regex_replace(sanitized, ip_regex, "[redacted-ip]");

        // Redact potential passwords / tokens in error messages
        static const std::regex secret_regex(
            R"((?:password|token|secret|key|auth)\s*[:=]\s*\S+)",
            std::regex::ECMAScript | std::regex::optimize | std::regex::icase);
        sanitized = std::regex_replace(sanitized, secret_regex, "$1=[redacted]");

        return sanitized;
    }

    // Determine if an error message is safe to show to the client
    static bool is_safe_for_client(const std::string& errcode) {
        // Specific error codes that always have safe defaults
        static const std::set<std::string> always_safe = {
            error_codes::M_FORBIDDEN,
            error_codes::M_UNKNOWN_TOKEN,
            error_codes::M_MISSING_TOKEN,
            error_codes::M_BAD_JSON,
            error_codes::M_NOT_JSON,
            error_codes::M_NOT_FOUND,
            error_codes::M_LIMIT_EXCEEDED,
            error_codes::M_USER_IN_USE,
            error_codes::M_INVALID_USERNAME,
            error_codes::M_ROOM_IN_USE,
            error_codes::M_WEAK_PASSWORD,
            error_codes::M_CONSENT_NOT_GIVEN,
            error_codes::M_GUEST_ACCESS_FORBIDDEN,
        };

        return always_safe.find(errcode) != always_safe.end();
    }

    // Sanitize an ErrorResponse for client delivery
    static ErrorResponse sanitize_response(const ErrorResponse& error, bool is_production = true) {
        if (!is_production) return error;

        ErrorResponse sanitized = error;

        // Replace internal error messages with generic ones
        if (!is_safe_for_client(error.errcode())) {
            auto meta = ErrorRegistry::instance().lookup(error.errcode());
            if (meta) {
                // Create response with default message
                sanitized = ErrorResponse(
                    error.http_status(),
                    error.errcode(),
                    meta->default_message
                );
            } else {
                sanitized = ErrorResponse(
                    error.http_status(),
                    error_codes::M_UNKNOWN,
                    "An unknown error occurred"
                );
            }
        }

        return sanitized;
    }
};

// ============================================================================
// ErrorTemplateLibrary — pre-built error responses for common scenarios
// ============================================================================
class ErrorTemplateLibrary {
public:
    // --- Auth errors ---
    static ErrorResponse missing_token() {
        return ErrorResponseBuilder(error_codes::M_MISSING_TOKEN).build();
    }

    static ErrorResponse unknown_token(bool soft_logout = false) {
        auto builder = ErrorResponseBuilder(error_codes::M_UNKNOWN_TOKEN);
        if (soft_logout) builder.soft_logout(true);
        return builder.build();
    }

    static ErrorResponse forbidden(const std::string& detail = "") {
        auto builder = ErrorResponseBuilder(error_codes::M_FORBIDDEN);
        if (!detail.empty()) builder.error_msg(detail);
        return builder.build();
    }

    static ErrorResponse unauthorized(const std::string& detail = "") {
        auto builder = ErrorResponseBuilder(error_codes::M_UNAUTHORIZED);
        if (!detail.empty()) builder.error_msg(detail);
        return builder.build();
    }

    // --- Validation errors ---
    static ErrorResponse bad_json() {
        return ErrorResponseBuilder(error_codes::M_BAD_JSON).build();
    }

    static ErrorResponse not_json() {
        return ErrorResponseBuilder(error_codes::M_NOT_JSON).build();
    }

    static ErrorResponse missing_param(const std::string& param_name) {
        return ErrorResponseBuilder(error_codes::M_MISSING_PARAM)
            .error_msg("Missing required parameter: " + param_name)
            .build();
    }

    static ErrorResponse invalid_param(const std::string& detail) {
        return ErrorResponseBuilder(error_codes::M_INVALID_PARAM)
            .error_msg(detail)
            .build();
    }

    static ErrorResponse too_large(const std::string& detail = "") {
        auto builder = ErrorResponseBuilder(error_codes::M_TOO_LARGE);
        if (!detail.empty()) builder.error_msg(detail);
        return builder.build();
    }

    // --- Not found errors ---
    static ErrorResponse not_found(const std::string& resource = "") {
        auto builder = ErrorResponseBuilder(error_codes::M_NOT_FOUND);
        if (!resource.empty()) {
            builder.error_msg(resource + " not found");
        }
        return builder.build();
    }

    static ErrorResponse room_not_found() {
        return ErrorResponseBuilder(error_codes::M_NOT_FOUND)
            .error_msg("Room not found")
            .build();
    }

    static ErrorResponse event_not_found() {
        return ErrorResponseBuilder(error_codes::M_NOT_FOUND)
            .error_msg("Event not found")
            .build();
    }

    static ErrorResponse user_not_found() {
        return ErrorResponseBuilder(error_codes::M_NOT_FOUND)
            .error_msg("User not found")
            .build();
    }

    // --- Rate limiting ---
    static ErrorResponse rate_limited(int64_t retry_after_ms = 0) {
        auto builder = ErrorResponseBuilder(error_codes::M_LIMIT_EXCEEDED);
        if (retry_after_ms > 0) builder.retry_after_ms(retry_after_ms);
        return builder.build();
    }

    // --- Room errors ---
    static ErrorResponse not_in_room() {
        return ErrorResponseBuilder(403, error_codes::M_FORBIDDEN,
            "You are not a member of this room").build();
    }

    static ErrorResponse banned_from_room() {
        return ErrorResponseBuilder(403, error_codes::M_FORBIDDEN,
            "You are banned from this room").build();
    }

    static ErrorResponse insufficient_power() {
        return ErrorResponseBuilder(403, error_codes::M_FORBIDDEN,
            "You do not have sufficient power level to perform this action").build();
    }

    static ErrorResponse room_alias_in_use() {
        return ErrorResponseBuilder(error_codes::M_ROOM_IN_USE).build();
    }

    static ErrorResponse room_alias_not_found() {
        return ErrorResponseBuilder(error_codes::M_NOT_FOUND)
            .error_msg("Room alias not found")
            .build();
    }

    // --- User / Account errors ---
    static ErrorResponse user_in_use() {
        return ErrorResponseBuilder(error_codes::M_USER_IN_USE).build();
    }

    static ErrorResponse invalid_username(const std::string& detail = "") {
        auto builder = ErrorResponseBuilder(error_codes::M_INVALID_USERNAME);
        if (!detail.empty()) builder.error_msg(detail);
        return builder.build();
    }

    static ErrorResponse user_deactivated() {
        return ErrorResponseBuilder(error_codes::M_USER_DEACTIVATED)
            .soft_logout(true)
            .build();
    }

    static ErrorResponse weak_password(const std::string& detail = "") {
        auto builder = ErrorResponseBuilder(error_codes::M_WEAK_PASSWORD);
        if (!detail.empty()) builder.error_msg(detail);
        return builder.build();
    }

    // --- Threepid errors ---
    static ErrorResponse threepid_in_use() {
        return ErrorResponseBuilder(error_codes::M_THREEPID_IN_USE).build();
    }

    static ErrorResponse threepid_not_found() {
        return ErrorResponseBuilder(error_codes::M_THREEPID_NOT_FOUND).build();
    }

    static ErrorResponse threepid_auth_failed() {
        return ErrorResponseBuilder(error_codes::M_THREEPID_AUTH_FAILED).build();
    }

    // --- Consent ---
    static ErrorResponse consent_not_given(const std::string& consent_uri = "") {
        auto builder = ErrorResponseBuilder(error_codes::M_CONSENT_NOT_GIVEN);
        if (!consent_uri.empty()) builder.consent_uri(consent_uri);
        return builder.build();
    }

    // --- Server errors ---
    static ErrorResponse internal_error(const std::string& detail = "") {
        auto builder = ErrorResponseBuilder(error_codes::M_UNKNOWN);
        if (!detail.empty()) builder.error_msg(detail);
        return builder.build();
    }

    static ErrorResponse unavailable(const std::string& detail = "") {
        auto builder = ErrorResponseBuilder(error_codes::M_MAINTENANCE_MODE);
        if (!detail.empty()) builder.error_msg(detail);
        return builder.build();
    }

    static ErrorResponse timeout() {
        return ErrorResponseBuilder(error_codes::M_TIMEOUT).build();
    }

    // --- Federation errors ---
    static ErrorResponse unreachable() {
        return ErrorResponseBuilder(error_codes::M_UNREACHABLE).build();
    }

    static ErrorResponse signature_invalid() {
        return ErrorResponseBuilder(error_codes::M_SIGNATURE_INVALID).build();
    }

    // --- Resource exhaustion ---
    static ErrorResponse resource_limit_exceeded(const std::string& detail = "") {
        auto builder = ErrorResponseBuilder(error_codes::M_RESOURCE_LIMIT_EXCEEDED);
        if (!detail.empty()) builder.error_msg(detail);
        return builder.build();
    }

    // --- Guest access ---
    static ErrorResponse guest_access_forbidden() {
        return ErrorResponseBuilder(error_codes::M_GUEST_ACCESS_FORBIDDEN).build();
    }

    // --- UIA ---
    static ErrorResponse uia_required(const json& flows,
                                       const json& params,
                                       const std::string& session = "") {
        auto builder = ErrorResponseBuilder(401, error_codes::M_UIA_STAGE_NOT_COMPLETED, "")
            .error_msg("User-interactive authentication required")
            .flows(flows)
            .params(params);
        if (!session.empty()) builder.session(session);
        return builder.build();
    }

    // --- Device errors ---
    static ErrorResponse device_not_found() {
        return ErrorResponseBuilder(error_codes::M_NO_SUCH_DEVICE).build();
    }

    static ErrorResponse too_many_devices() {
        return ErrorResponseBuilder(error_codes::M_TOO_MANY_DEVICES).build();
    }

    // --- Generic ---
    static ErrorResponse unknown(const std::string& detail = "") {
        auto builder = ErrorResponseBuilder(error_codes::M_UNKNOWN);
        if (!detail.empty()) builder.error_msg(detail);
        return builder.build();
    }
};

// ============================================================================
// FederationErrorHandler — specialized S2S federation error handling
// ============================================================================
class FederationErrorHandler {
public:
    // Map a network/system error to a Matrix federation error code
    static std::string classify_network_error(int sys_errno) {
        switch (sys_errno) {
            case 0:             return error_codes::M_UNKNOWN;
#ifdef ECONNREFUSED
            case ECONNREFUSED:  return error_codes::M_CONNECTION_FAILED;
#endif
#ifdef ETIMEDOUT
            case ETIMEDOUT:     return error_codes::M_TIMEOUT;
#endif
#ifdef ENETUNREACH
            case ENETUNREACH:   return error_codes::M_UNREACHABLE;
#endif
#ifdef EHOSTUNREACH
            case EHOSTUNREACH:  return error_codes::M_UNREACHABLE;
#endif
#ifdef EHOSTDOWN
            case EHOSTDOWN:     return error_codes::M_UNREACHABLE;
#endif
#ifdef ECONNRESET
            case ECONNRESET:    return error_codes::M_CONNECTION_FAILED;
#endif
#ifdef EPIPE
            case EPIPE:         return error_codes::M_CONNECTION_FAILED;
#endif
            default:            return error_codes::M_UNREACHABLE;
        }
    }

    // Map an HTTP status from a remote server to a Matrix error code
    static std::string classify_http_response(int http_status) {
        switch (http_status) {
            case 400: return error_codes::M_UNKNOWN;
            case 401: return error_codes::M_SIGNATURE_INVALID;
            case 403: return error_codes::M_FORBIDDEN;
            case 404: return error_codes::M_UNKNOWN_ENDPOINT;
            case 429: return error_codes::M_LIMIT_EXCEEDED;
            case 502: return error_codes::M_UNREACHABLE;
            case 503: return error_codes::M_UNREACHABLE;
            case 504: return error_codes::M_TIMEOUT;
            default:
                if (http_status >= 500) return error_codes::M_UNREACHABLE;
                return error_codes::M_UNKNOWN;
        }
    }

    // Build a federation error response from a transport error
    static ErrorResponse from_transport_error(const std::string& server_name,
                                               const std::string& endpoint,
                                               int sys_errno,
                                               const std::string& detail) {
        std::string errcode = classify_network_error(sys_errno);
        return ErrorResponseBuilder(HttpErrorMapper::to_http_status(errcode), errcode,
            "Failed to connect to " + server_name + " for " + endpoint + ": " + detail)
            .build();
    }

    // Build a federation error from a remote server's error response
    static ErrorResponse from_remote_error(const std::string& server_name,
                                            int http_status,
                                            const std::string& remote_errcode,
                                            const std::string& remote_error) {
        // Try to use the remote server's error code if it's a standard one
        if (ErrorRegistry::instance().is_known(remote_errcode)) {
            return ErrorResponseBuilder(http_status, remote_errcode,
                "Error from " + server_name + ": " + remote_error).build();
        }

        // Otherwise classify based on HTTP status
        std::string errcode = classify_http_response(http_status);
        return ErrorResponseBuilder(http_status, errcode,
            "Error from " + server_name + ": " + remote_error).build();
    }

    // Check if a federation error is retryable
    static bool is_retryable(const std::string& errcode) {
        static const std::set<std::string> retryable = {
            error_codes::M_UNREACHABLE,
            error_codes::M_CONNECTION_FAILED,
            error_codes::M_TIMEOUT,
            error_codes::M_DNS_ERROR,
            error_codes::M_LIMIT_EXCEEDED,
        };
        return retryable.find(errcode) != retryable.end();
    }

    // Check if a federation error is terminal (should not be retried)
    static bool is_terminal(const std::string& errcode) {
        static const std::set<std::string> terminal = {
            error_codes::M_FORBIDDEN,
            error_codes::M_SIGNATURE_INVALID,
            error_codes::M_SIGNATURE_MISMATCH,
            error_codes::M_UNKNOWN_ENDPOINT,
            error_codes::M_UNSUPPORTED_ROOM_VERSION,
            error_codes::M_INCOMPATIBLE_ROOM_VERSION,
        };
        return terminal.find(errcode) != terminal.end();
    }

    // Estimate retry delay for federation errors
    static int64_t retry_delay_ms(const std::string& errcode, int attempt) {
        static RetryAfterCalculator calculator;
        return calculator.exponential_backoff(attempt);
    }
};

// ============================================================================
// ClientErrorHandler — specialized Client-Server API error handling
// ============================================================================
class ClientErrorHandler {
public:
    // Process an exception and produce a safe client-facing error response
    static ErrorResponse from_exception(const std::exception& e,
                                         bool is_production = true) {
        // If it's already a MatrixErrorException, use it directly
        if (auto* matrix_err = dynamic_cast<const MatrixErrorException*>(&e)) {
            return ErrorSanitizer::sanitize_response(matrix_err->error(), is_production);
        }

        // Standard exception types
        if (auto* invalid_arg = dynamic_cast<const std::invalid_argument*>(&e)) {
            return ErrorResponseBuilder(error_codes::M_INVALID_PARAM)
                .error_msg(ErrorSanitizer::sanitize_message(invalid_arg->what(), is_production))
                .build();
        }

        if (auto* out_of_range = dynamic_cast<const std::out_of_range*>(&e)) {
            return ErrorResponseBuilder(error_codes::M_NOT_FOUND)
                .error_msg(ErrorSanitizer::sanitize_message(out_of_range->what(), is_production))
                .build();
        }

        if (auto* runtime_err = dynamic_cast<const std::runtime_error*>(&e)) {
            return ErrorResponseBuilder(error_codes::M_UNKNOWN)
                .error_msg(is_production ? "An internal error occurred"
                                         : ErrorSanitizer::sanitize_message(runtime_err->what(), false))
                .build();
        }

        // Generic fallback
        return ErrorResponseBuilder(error_codes::M_UNKNOWN)
            .error_msg(is_production ? "An unexpected error occurred"
                                     : ErrorSanitizer::sanitize_message(e.what(), false))
            .build();
    }

    // Handle JSON parse errors specifically
    static ErrorResponse from_json_parse_error(const std::string& detail) {
        return ErrorResponseBuilder(error_codes::M_BAD_JSON)
            .error_msg("Invalid JSON: " + detail)
            .build();
    }

    // Handle missing request body
    static ErrorResponse missing_body() {
        return ErrorResponseBuilder(error_codes::M_NOT_JSON)
            .error_msg("Request must contain a JSON body")
            .build();
    }

    // Handle unsupported HTTP method
    static ErrorResponse unsupported_method(const std::string& method) {
        return ErrorResponseBuilder(405, error_codes::M_UNKNOWN,
            "Method " + method + " is not allowed for this endpoint").build();
    }

    // Handle session management
    static ErrorResponse session_expired(bool soft_logout = true) {
        return ErrorResponseBuilder(401, error_codes::M_UNKNOWN_TOKEN,
            "Your session has expired. Please log in again.")
            .soft_logout(soft_logout)
            .build();
    }

    // Handle consent requirement
    static ErrorResponse consent_required(const std::string& consent_uri) {
        return ErrorResponseBuilder(error_codes::M_CONSENT_NOT_GIVEN)
            .consent_uri(consent_uri)
            .error_msg("You must consent to the terms of service to use this server")
            .build();
    }
};

// ============================================================================
// AdminErrorHandler — specialized Admin API error handling
// ============================================================================
class AdminErrorHandler {
public:
    static ErrorResponse not_admin() {
        return ErrorResponseBuilder(error_codes::M_ADMIN_ONLY)
            .error_msg("This endpoint requires server administrator privileges")
            .build();
    }

    static ErrorResponse user_not_found(const std::string& user_id = "") {
        return ErrorResponseBuilder(error_codes::M_NOT_FOUND)
            .error_msg(user_id.empty() ? "User not found"
                                       : "User " + user_id + " not found")
            .build();
    }

    static ErrorResponse room_not_found(const std::string& room_id = "") {
        return ErrorResponseBuilder(error_codes::M_NOT_FOUND)
            .error_msg(room_id.empty() ? "Room not found"
                                       : "Room " + room_id + " not found")
            .build();
    }

    static ErrorResponse invalid_user_id(const std::string& detail = "") {
        return ErrorResponseBuilder(error_codes::M_INVALID_PARAM)
            .error_msg(detail.empty() ? "Invalid user ID" : detail)
            .build();
    }

    static ErrorResponse server_not_ready() {
        return ErrorResponseBuilder(error_codes::M_MAINTENANCE_MODE)
            .error_msg("Server is not ready to process admin requests")
            .build();
    }

    static ErrorResponse operation_failed(const std::string& detail) {
        return ErrorResponseBuilder(error_codes::M_UNKNOWN)
            .error_msg("Admin operation failed: " + detail)
            .build();
    }

    static ErrorResponse missing_parameter(const std::string& param) {
        return ErrorResponseBuilder(error_codes::M_MISSING_PARAM)
            .error_msg("Required parameter '" + param + "' is missing")
            .build();
    }

    static ErrorResponse bad_request(const std::string& detail) {
        return ErrorResponseBuilder(error_codes::M_INVALID_PARAM)
            .error_msg(detail)
            .build();
    }
};

// ============================================================================
// ErrorAuditLogger — structured error logging with rate tracking
// ============================================================================
class ErrorAuditLogger {
public:
    static ErrorAuditLogger& instance() {
        static ErrorAuditLogger logger;
        return logger;
    }

    // Log an error with full context
    void log_error(const ErrorResponse& error, const ErrorContext& context) {
        std::unique_lock lock(mutex_);

        // Build structured log entry
        json log_entry;
        log_entry["type"] = "error_audit";
        log_entry["error"] = error.to_json();
        log_entry["context"] = context.to_json();
        log_entry["log_timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Add to in-memory ring buffer
        recent_errors_.push_back(log_entry);
        if (recent_errors_.size() > max_recent_errors_) {
            recent_errors_.pop_front();
        }

        // Increment counters
        total_errors_++;
        auto& counter = error_counters_[error.errcode()];
        counter.total++;
        counter.last_seen = std::chrono::system_clock::now();

        // Call log hook if set
        if (log_hook_) {
            log_hook_(log_entry);
        }
    }

    // Set a custom log hook (e.g., to forward to logging system)
    using LogHook = std::function<void(const json&)>;
    void set_log_hook(LogHook hook) {
        std::unique_lock lock(mutex_);
        log_hook_ = std::move(hook);
    }

    // Get error statistics
    struct ErrorStats {
        uint64_t total = 0;
        std::chrono::system_clock::time_point last_seen;
    };

    std::optional<ErrorStats> stats_for(const std::string& errcode) const {
        std::shared_lock lock(mutex_);
        auto it = error_counters_.find(errcode);
        if (it != error_counters_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    uint64_t total_errors() const {
        std::shared_lock lock(mutex_);
        return total_errors_;
    }

    // Get recent errors as JSON
    json recent_errors_json(size_t limit = 100) const {
        std::shared_lock lock(mutex_);
        json arr = json::array();
        size_t count = 0;
        for (auto it = recent_errors_.rbegin();
             it != recent_errors_.rend() && count < limit; ++it, ++count) {
            arr.push_back(*it);
        }
        return arr;
    }

    // Reset statistics
    void reset_stats() {
        std::unique_lock lock(mutex_);
        error_counters_.clear();
        total_errors_ = 0;
        recent_errors_.clear();
    }

    // Get top errors by frequency
    std::vector<std::pair<std::string, uint64_t>> top_errors(size_t n = 10) const {
        std::shared_lock lock(mutex_);
        std::vector<std::pair<std::string, uint64_t>> sorted;
        sorted.reserve(error_counters_.size());
        for (const auto& [code, stats] : error_counters_) {
            sorted.emplace_back(code, stats.total);
        }
        std::sort(sorted.begin(), sorted.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });
        if (sorted.size() > n) sorted.resize(n);
        return sorted;
    }

private:
    ErrorAuditLogger() = default;

    static constexpr size_t max_recent_errors_ = 10000;
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, ErrorStats> error_counters_;
    uint64_t total_errors_ = 0;
    std::deque<json> recent_errors_;
    LogHook log_hook_;
};

// ============================================================================
// ErrorMetrics — error rate counters, histograms, and gauges
// ============================================================================
class ErrorMetrics {
public:
    static ErrorMetrics& instance() {
        static ErrorMetrics metrics;
        return metrics;
    }

    // Record an error occurrence
    void record_error(const std::string& errcode, const std::string& endpoint = "",
                      const std::string& user_agent = "") {
        auto now = std::chrono::steady_clock::now();

        std::unique_lock lock(mutex_);

        // Global counter
        total_count_++;

        // Per-code counter
        code_counters_[errcode]++;

        // Per-endpoint counter
        if (!endpoint.empty()) {
            endpoint_counters_[endpoint]++;
        }

        // Per-user-agent counter
        if (!user_agent.empty()) {
            ua_counters_[user_agent]++;
        }

        // Track in time-bucketed window (1-minute buckets)
        int64_t bucket = time_bucket(now);
        window_errors_[bucket][errcode]++;

        // Cleanup old windows (keep last 60 minutes)
        cleanup_old_windows(now);
    }

    // Get total error count
    uint64_t total_count() const {
        std::shared_lock lock(mutex_);
        return total_count_;
    }

    // Get error count for a specific code
    uint64_t count_for(const std::string& errcode) const {
        std::shared_lock lock(mutex_);
        auto it = code_counters_.find(errcode);
        return (it != code_counters_.end()) ? it->second : 0;
    }

    // Get error count for an endpoint
    uint64_t count_for_endpoint(const std::string& endpoint) const {
        std::shared_lock lock(mutex_);
        auto it = endpoint_counters_.find(endpoint);
        return (it != endpoint_counters_.end()) ? it->second : 0;
    }

    // Get error rate per minute for a code (over the last N minutes)
    double rate_per_minute(const std::string& errcode, int window_minutes = 5) const {
        std::shared_lock lock(mutex_);
        auto now = std::chrono::steady_clock::now();
        int64_t current_bucket = time_bucket(now);

        uint64_t count = 0;
        for (int i = 0; i < window_minutes; i++) {
            int64_t bucket = current_bucket - i;
            auto it = window_errors_.find(bucket);
            if (it != window_errors_.end()) {
                auto code_it = it->second.find(errcode);
                if (code_it != it->second.end()) {
                    count += code_it->second;
                }
            }
        }

        return static_cast<double>(count) / window_minutes;
    }

    // Get all metrics as JSON
    json dump_json() const {
        std::shared_lock lock(mutex_);
        json j;
        j["total_errors"] = total_count_;

        json code_counts = json::object();
        for (const auto& [code, count] : code_counters_) {
            code_counts[code] = count;
        }
        j["by_code"] = code_counts;

        json ep_counts = json::object();
        for (const auto& [ep, count] : endpoint_counters_) {
            ep_counts[ep] = count;
        }
        j["by_endpoint"] = ep_counts;

        return j;
    }

    // Reset all metrics
    void reset() {
        std::unique_lock lock(mutex_);
        total_count_ = 0;
        code_counters_.clear();
        endpoint_counters_.clear();
        ua_counters_.clear();
        window_errors_.clear();
    }

private:
    ErrorMetrics() = default;

    static int64_t time_bucket(std::chrono::steady_clock::time_point now) {
        return std::chrono::duration_cast<std::chrono::minutes>(
            now.time_since_epoch()).count();
    }

    void cleanup_old_windows(std::chrono::steady_clock::time_point now) {
        int64_t cutoff = time_bucket(now) - 60; // Keep 60 minutes
        auto it = window_errors_.begin();
        while (it != window_errors_.end() && it->first < cutoff) {
            it = window_errors_.erase(it);
        }
    }

    mutable std::shared_mutex mutex_;
    uint64_t total_count_ = 0;
    std::unordered_map<std::string, uint64_t> code_counters_;
    std::unordered_map<std::string, uint64_t> endpoint_counters_;
    std::unordered_map<std::string, uint64_t> ua_counters_;
    // time_bucket -> (errcode -> count)
    std::map<int64_t, std::unordered_map<std::string, uint64_t>> window_errors_;
};

// ============================================================================
// Convenience free functions for quick error response creation
// ============================================================================

// Create an error response from just an error code
inline ErrorResponse make_error(const std::string& errcode) {
    return ErrorResponseBuilder(errcode).build();
}

// Create an error response with a custom message
inline ErrorResponse make_error(const std::string& errcode, const std::string& message) {
    return ErrorResponseBuilder(HttpErrorMapper::to_http_status(errcode), errcode, message).build();
}

// Create an error response with explicit status, code, and message
inline ErrorResponse make_error(int http_status, const std::string& errcode,
                                 const std::string& message) {
    return ErrorResponseBuilder(http_status, errcode, message).build();
}

// Create a rate-limited error response
inline ErrorResponse make_rate_limit_error(int64_t retry_after_ms) {
    return ErrorResponseBuilder(error_codes::M_LIMIT_EXCEEDED)
        .retry_after_ms(retry_after_ms)
        .build();
}

// Create a JSON error object (for embedding in larger responses)
inline json json_error(const std::string& errcode, const std::string& message) {
    return ErrorResponseBuilder(HttpErrorMapper::to_http_status(errcode), errcode, message)
        .build_json();
}

// ============================================================================
// Error response validation utilities
// ============================================================================

// Validate that an error response conforms to the Matrix spec
inline bool validate_error_response(const ErrorResponse& resp) {
    if (resp.errcode().empty()) return false;
    if (resp.error_msg().empty()) return false;
    if (resp.http_status() < 400 || resp.http_status() > 599) return false;

    // Check that the error code is prefixed appropriately
    if (resp.errcode().size() < 2 || resp.errcode()[0] != 'M' || resp.errcode()[1] != '_') {
        return false; // Not a standard Matrix error code prefix
    }

    return true;
}

// Validate that JSON conforms to the error schema
inline bool is_valid_error_json(const json& j) {
    if (!j.is_object()) return false;
    if (!j.contains("errcode") || !j["errcode"].is_string()) return false;
    if (!j.contains("error") || !j["error"].is_string()) return false;
    return true;
}

// Parse an error from JSON (for federation response parsing)
inline std::optional<ErrorResponse> parse_error_from_json(const json& j) {
    if (!is_valid_error_json(j)) return std::nullopt;

    std::string errcode = j["errcode"].get<std::string>();
    std::string error_msg = j["error"].get<std::string>();

    int http_status = HttpErrorMapper::to_http_status(errcode);

    ErrorResponse resp(http_status, std::move(errcode), std::move(error_msg));

    if (j.contains("retry_after_ms") && j["retry_after_ms"].is_number()) {
        resp.set_retry_after_ms(j["retry_after_ms"].get<int64_t>());
    }
    if (j.contains("soft_logout") && j["soft_logout"].is_boolean()) {
        resp.set_soft_logout(j["soft_logout"].get<bool>());
    }
    if (j.contains("admin_contact") && j["admin_contact"].is_string()) {
        resp.set_admin_contact(j["admin_contact"].get<std::string>());
    }
    if (j.contains("consent_uri") && j["consent_uri"].is_string()) {
        resp.set_consent_uri(j["consent_uri"].get<std::string>());
    }

    return resp;
}

// ============================================================================
// Error response comparison and hashing
// ============================================================================

inline bool operator==(const ErrorResponse& a, const ErrorResponse& b) {
    return a.http_status() == b.http_status() &&
           a.errcode() == b.errcode() &&
           a.error_msg() == b.error_msg() &&
           a.retry_after_ms() == b.retry_after_ms() &&
           a.soft_logout() == b.soft_logout();
}

inline bool operator!=(const ErrorResponse& a, const ErrorResponse& b) {
    return !(a == b);
}

// Make ErrorResponse hashable
struct ErrorResponseHash {
    std::size_t operator()(const ErrorResponse& e) const {
        std::size_t h = std::hash<int>{}(e.http_status());
        h ^= std::hash<std::string>{}(e.errcode()) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<std::string>{}(e.error_msg()) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

// ============================================================================
// ErrorHandler — top-level orchestrator combining all subsystems
// ============================================================================
class ErrorHandler {
public:
    static ErrorHandler& instance() {
        static ErrorHandler handler;
        return handler;
    }

    // --- Configuration ---
    struct Config {
        bool production_mode = true;
        std::string default_locale = "en";
        std::string admin_contact;
        bool enable_audit_logging = true;
        bool enable_metrics = true;
        bool sanitize_client_errors = true;
        bool include_stack_trace_in_logs = false;
        RetryAfterCalculator::Config retry_config;
    };

    void configure(Config config) {
        std::unique_lock lock(mutex_);
        config_ = std::move(config);
    }

    Config get_config() const {
        std::shared_lock lock(mutex_);
        return config_;
    }

    // --- Error creation methods ---

    // Create a standard Matrix error response
    ErrorResponse create_error(const std::string& errcode,
                                const std::string& message = "",
                                const std::string& locale = "") {
        std::string actual_message = message;

        // Use default message from registry if none provided
        if (actual_message.empty()) {
            actual_message = ErrorRegistry::instance().default_message(errcode);
        }

        // Localize if a locale is specified
        std::string used_locale = locale.empty() ? config_.default_locale : locale;
        std::string localized = LocalizedErrorMessages::instance().get(errcode, used_locale);

        int http_status = HttpErrorMapper::to_http_status(errcode);

        auto builder = ErrorResponseBuilder(http_status, errcode, actual_message)
            .localized_message(localized);

        if (!config_.admin_contact.empty()) {
            builder.admin_contact(config_.admin_contact);
        }

        return builder.build();
    }

    // Create a client-safe error response (sanitized in production)
    ErrorResponse create_client_error(const std::string& errcode,
                                       const std::string& raw_message = "",
                                       const std::string& locale = "") {
        auto error = create_error(errcode, raw_message, locale);

        if (config_.sanitize_client_errors && config_.production_mode) {
            error = ErrorSanitizer::sanitize_response(error, true);
        }

        return error;
    }

    // Handle an exception and produce a client-safe error
    ErrorResponse handle_exception(const std::exception& e,
                                    const ErrorContext& context = {}) {
        auto error = ClientErrorHandler::from_exception(e, config_.production_mode);

        // Log the error
        if (config_.enable_audit_logging) {
            ErrorAuditLogger::instance().log_error(error, context);
        }

        // Record metrics
        if (config_.enable_metrics) {
            ErrorMetrics::instance().record_error(
                error.errcode(),
                context.endpoint().value_or(""),
                context.user_agent().value_or(""));
        }

        return error;
    }

    // Handle a federation error
    ErrorResponse handle_federation_error(const std::string& server_name,
                                           const std::string& endpoint,
                                           int sys_errno,
                                           const std::string& detail) {
        auto error = FederationErrorHandler::from_transport_error(
            server_name, endpoint, sys_errno, detail);

        if (config_.enable_audit_logging) {
            ErrorContext ctx;
            ctx.with_error_code(error.errcode())
               .with_error_message(error.error_msg())
               .with_endpoint(endpoint);
            ErrorAuditLogger::instance().log_error(error, ctx);
        }

        return error;
    }

    // Get a localized error message
    std::string localized_message(const std::string& errcode,
                                   const std::string& locale = "") {
        std::string used_locale = locale.empty() ? config_.default_locale : locale;
        return LocalizedErrorMessages::instance().get(errcode, used_locale);
    }

private:
    ErrorHandler() = default;

    mutable std::shared_mutex mutex_;
    Config config_;
};

// ============================================================================
// Utility: capture stack trace (Linux/glibc)
// ============================================================================
#ifdef __linux__
inline std::string capture_stack_trace(int max_frames = 50) {
    std::string result;
    void* buffer[max_frames];
    int frames = backtrace(buffer, max_frames);
    char** symbols = backtrace_symbols(buffer, frames);
    if (symbols) {
        for (int i = 0; i < frames; i++) {
            if (i > 0) result += "\n";
            result += "  #" + std::to_string(i) + " " + std::string(symbols[i]);
        }
        free(symbols);
    }
    return result;
}
#else
inline std::string capture_stack_trace(int = 50) {
    return "(stack trace not available on this platform)";
}
#endif

// ============================================================================
// Utility: create ErrorContext from current execution point
// ============================================================================
#define ERROR_CONTEXT_HERE() \
    progressive::ErrorContext() \
        .with_source_file(__FILE__) \
        .with_source_line(__LINE__) \
        .with_source_function(__func__)

// ============================================================================
// Pre-built error responses for common HTTP status codes
// ============================================================================
namespace http_errors {

inline ErrorResponse bad_request(const std::string& detail = "Bad request") {
    return ErrorResponseBuilder(400, error_codes::M_UNKNOWN, detail).build();
}

inline ErrorResponse unauthorized(const std::string& detail = "Unauthorized") {
    return ErrorResponseBuilder(401, error_codes::M_UNAUTHORIZED, detail).build();
}

inline ErrorResponse payment_required(const std::string& detail = "Payment required") {
    return ErrorResponseBuilder(402, error_codes::M_UNKNOWN, detail).build();
}

inline ErrorResponse forbidden(const std::string& detail = "Forbidden") {
    return ErrorResponseBuilder(403, error_codes::M_FORBIDDEN, detail).build();
}

inline ErrorResponse not_found(const std::string& detail = "Not found") {
    return ErrorResponseBuilder(404, error_codes::M_NOT_FOUND, detail).build();
}

inline ErrorResponse method_not_allowed(const std::string& detail = "Method not allowed") {
    return ErrorResponseBuilder(405, error_codes::M_UNKNOWN, detail).build();
}

inline ErrorResponse not_acceptable(const std::string& detail = "Not acceptable") {
    return ErrorResponseBuilder(406, error_codes::M_UNKNOWN, detail).build();
}

inline ErrorResponse request_timeout(const std::string& detail = "Request timeout") {
    return ErrorResponseBuilder(408, error_codes::M_TIMEOUT, detail).build();
}

inline ErrorResponse conflict(const std::string& detail = "Conflict") {
    return ErrorResponseBuilder(409, error_codes::M_EXCLUSIVE, detail).build();
}

inline ErrorResponse gone(const std::string& detail = "Gone") {
    return ErrorResponseBuilder(410, error_codes::M_NOT_FOUND, detail).build();
}

inline ErrorResponse payload_too_large(const std::string& detail = "Payload too large") {
    return ErrorResponseBuilder(413, error_codes::M_TOO_LARGE, detail).build();
}

inline ErrorResponse uri_too_long(const std::string& detail = "URI too long") {
    return ErrorResponseBuilder(414, error_codes::M_TOO_LARGE, detail).build();
}

inline ErrorResponse unsupported_media_type(const std::string& detail = "Unsupported media type") {
    return ErrorResponseBuilder(415, error_codes::M_MEDIA_UNSUPPORTED, detail).build();
}

inline ErrorResponse unprocessable_entity(const std::string& detail = "Unprocessable entity") {
    return ErrorResponseBuilder(422, error_codes::M_INVALID_PARAM, detail).build();
}

inline ErrorResponse too_many_requests(int64_t retry_after_ms = 0) {
    auto builder = ErrorResponseBuilder(429, error_codes::M_LIMIT_EXCEEDED,
        "Too many requests");
    if (retry_after_ms > 0) builder.retry_after_ms(retry_after_ms);
    return builder.build();
}

inline ErrorResponse internal_server_error(const std::string& detail = "Internal server error") {
    return ErrorResponseBuilder(500, error_codes::M_UNKNOWN, detail).build();
}

inline ErrorResponse not_implemented(const std::string& detail = "Not implemented") {
    return ErrorResponseBuilder(501, error_codes::M_UNKNOWN, detail).build();
}

inline ErrorResponse bad_gateway(const std::string& detail = "Bad gateway") {
    return ErrorResponseBuilder(502, error_codes::M_UNREACHABLE, detail).build();
}

inline ErrorResponse service_unavailable(const std::string& detail = "Service unavailable") {
    return ErrorResponseBuilder(503, error_codes::M_MAINTENANCE_MODE, detail).build();
}

inline ErrorResponse gateway_timeout(const std::string& detail = "Gateway timeout") {
    return ErrorResponseBuilder(504, error_codes::M_TIMEOUT, detail).build();
}

} // namespace http_errors

// ============================================================================
// Error response with RFC 7807 Problem Details support
// ============================================================================
class ProblemDetailsBuilder {
public:
    ProblemDetailsBuilder& type(std::string t) { type_ = std::move(t); return *this; }
    ProblemDetailsBuilder& title(std::string t) { title_ = std::move(t); return *this; }
    ProblemDetailsBuilder& status(int s) { status_ = s; return *this; }
    ProblemDetailsBuilder& detail(std::string d) { detail_ = std::move(d); return *this; }
    ProblemDetailsBuilder& instance(std::string i) { instance_ = std::move(i); return *this; }
    ProblemDetailsBuilder& errcode(std::string ec) { errcode_ = std::move(ec); return *this; }

    // Add an extension field
    ProblemDetailsBuilder& extension(std::string key, json value) {
        extensions_[std::move(key)] = std::move(value);
        return *this;
    }

    json build() const {
        json j;
        if (type_.has_value()) j["type"] = type_.value();
        if (title_.has_value()) j["title"] = title_.value();
        j["status"] = status_;
        if (detail_.has_value()) j["detail"] = detail_.value();
        if (instance_.has_value()) j["instance"] = instance_.value();

        // Matrix-specific extension
        if (errcode_.has_value()) j["errcode"] = errcode_.value();

        // Custom extensions
        for (const auto& [key, value] : extensions_) {
            j[key] = value;
        }

        return j;
    }

    std::string build_string() const {
        return build().dump();
    }

private:
    std::optional<std::string> type_;
    std::optional<std::string> title_;
    int status_ = 500;
    std::optional<std::string> detail_;
    std::optional<std::string> instance_;
    std::optional<std::string> errcode_;
    std::map<std::string, json> extensions_;
};

} // namespace progressive
