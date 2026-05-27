// ============================================================================
// server_operations.cpp - Matrix Admin Server Operations & Maintenance Tools
// 3500+ lines providing comprehensive admin APIs for config management,
// server lifecycle, maintenance operations, diagnostics, and monitoring.
// Namespace: progressive::admin
// Include: ../json.hpp
//
// Feature coverage:
//   1.  GET  /_synapse/admin/v1/config                        - Server config dump (redacted)
//   2.  POST /_synapse/admin/v1/server/restart                - Restart API
//   3.  POST /_synapse/admin/v1/server/shutdown               - Shutdown API
//   4.  POST /_synapse/admin/v1/server/worker/restart         - Worker restart
//   5.  POST /_synapse/admin/v1/caches/flush                  - Flush caches
//   6.  POST /_synapse/admin/v1/server/reload_tls             - Reload TLS certs
//   7.  POST /_synapse/admin/v1/server/rotate_signing_keys    - Rotate signing keys
//   8.  POST /_synapse/admin/v1/database/integrity_check      - DB integrity check
//   9.  POST /_synapse/admin/v1/database/vacuum               - DB vacuum
//  10.  POST /_synapse/admin/v1/database/reindex              - DB reindex
//  11.  GET  /_synapse/admin/v1/event_stream/diagnostics      - Event stream diagnostics
//  12.  GET  /_synapse/admin/v1/rooms/{roomId}/forward_extremities - Forward extremity view
//  13.  GET  /_synapse/admin/v1/rooms/{roomId}/state_groups   - State group view
//  14.  GET  /_synapse/admin/v1/rooms/{roomId}/state_diagnostic - Room state diagnostic
//  15.  GET  /_synapse/admin/v1/devices/diagnostic            - Device diagnostic
//  16.  GET  /_synapse/admin/v1/sessions/diagnostic           - Session diagnostic
//  17.  GET  /_synapse/admin/v1/federation/queue              - Federation queue view
//  18.  GET  /_synapse/admin/v1/pushers/diagnostic            - Pusher diagnostic
//  19.  GET  /_synapse/admin/v1/background_updates/view       - Background update view
//  20.  GET  /_synapse/admin/v1/caches/eviction_stats          - Cache eviction stats
// ============================================================================

#include "../json.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace progressive {
namespace admin {

// ============================================================================
// Forward declarations – HTTP request/response abstraction
// (shared with other admin modules; re-declared for self-contained compilation)
// ============================================================================

struct HttpRequest {
    std::string method;
    std::string path;
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<std::string, std::string> query_params;
    std::unordered_map<std::string, std::string> path_params;
    std::string body;
    std::string remote_addr;
    std::string user_agent;
};

struct HttpResponse {
    int status_code = 200;
    std::unordered_map<std::string, std::string> headers;
    std::string body;

    HttpResponse() {
        headers["Content-Type"] = "application/json";
        headers["Access-Control-Allow-Origin"] = "*";
        headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
        headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
    }

    static HttpResponse json_response(int code, const json& data) {
        HttpResponse resp;
        resp.status_code = code;
        resp.body = data.dump(2);
        return resp;
    }

    static HttpResponse error(int code, const std::string& errcode,
                               const std::string& error) {
        json j;
        j["errcode"] = errcode;
        j["error"] = error;
        return json_response(code, j);
    }

    static HttpResponse not_found(const std::string& msg = "Not found") {
        return error(404, "M_NOT_FOUND", msg);
    }

    static HttpResponse bad_request(const std::string& msg = "Bad request") {
        return error(400, "M_BAD_REQUEST", msg);
    }

    static HttpResponse forbidden(const std::string& msg = "Forbidden") {
        return error(403, "M_FORBIDDEN", msg);
    }

    static HttpResponse internal_error(const std::string& msg = "Internal server error") {
        return error(500, "M_UNKNOWN", msg);
    }

    static HttpResponse not_implemented(const std::string& msg = "Not implemented") {
        return error(501, "M_NOT_IMPLEMENTED", msg);
    }

    static HttpResponse ok(const json& data = json::object()) {
        return json_response(200, data);
    }
};

// ============================================================================
// Route entry definition (for unified route table)
// ============================================================================

struct RouteEntry {
    std::string method;
    std::string path;
    std::function<HttpResponse(const HttpRequest&)> handler;
};

// ============================================================================
// Anonymous namespace – all internal state and helpers
// ============================================================================

namespace {

// ---------------------------------------------------------------------------
// Global mutex for thread-safe access to shared state
// ---------------------------------------------------------------------------

std::mutex g_mutex;

// Server version constants
const std::string SERVER_NAME = "progressive-server";
const std::string SERVER_VERSION = "1.0.0";
const std::string PYTHON_VERSION = "3.11.0";
const std::string MATRIX_VERSION = "v1.9";

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static int64_t now_sec() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_token(int len = 64) {
    static const char cs[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static thread_local std::mt19937 rng(
        static_cast<unsigned>(now_ms() + std::hash<std::thread::id>{}(std::this_thread::get_id())));
    std::uniform_int_distribution<> d(0, 61);
    std::string t(len, 'A');
    for (auto& c : t) c = cs[d(rng)];
    return t;
}

static std::string gen_uuid() {
    static thread_local std::mt19937 rng(
        static_cast<unsigned>(now_ms() + std::hash<std::thread::id>{}(std::this_thread::get_id())));
    std::uniform_int_distribution<> dc(0, 15);
    std::uniform_int_distribution<> dv(0, 15);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; ++i) oss << std::setw(1) << dc(rng);
    oss << "-";
    for (int i = 0; i < 4; ++i) oss << std::setw(1) << dc(rng);
    oss << "-4"; // version 4
    for (int i = 0; i < 3; ++i) oss << std::setw(1) << dc(rng);
    oss << "-";
    oss << std::setw(1) << (8 + (dc(rng) % 4));
    for (int i = 0; i < 3; ++i) oss << std::setw(1) << dc(rng);
    oss << "-";
    for (int i = 0; i < 12; ++i) oss << std::setw(1) << dc(rng);
    return oss.str();
}

// Parse query parameter helpers
static std::string query_param(const HttpRequest& req, const std::string& key,
                               const std::string& default_val = "") {
    auto it = req.query_params.find(key);
    return (it != req.query_params.end()) ? it->second : default_val;
}

static int query_param_int(const HttpRequest& req, const std::string& key, int default_val = 0) {
    auto it = req.query_params.find(key);
    if (it != req.query_params.end()) {
        try { return std::stoi(it->second); } catch (...) { return default_val; }
    }
    return default_val;
}

static bool query_param_bool(const HttpRequest& req, const std::string& key, bool default_val = false) {
    auto it = req.query_params.find(key);
    if (it != req.query_params.end()) {
        std::string val = it->second;
        std::transform(val.begin(), val.end(), val.begin(), ::tolower);
        return (val == "true" || val == "1" || val == "yes");
    }
    return default_val;
}

static std::string path_param(const HttpRequest& req, const std::string& key) {
    auto it = req.path_params.find(key);
    return (it != req.path_params.end()) ? it->second : "";
}

// URL decode helper
static std::string url_decode(const std::string& src) {
    std::string result;
    result.reserve(src.size());
    for (size_t i = 0; i < src.size(); ++i) {
        if (src[i] == '%' && i + 2 < src.size()) {
            int c;
            try {
                c = std::stoi(src.substr(i + 1, 2), nullptr, 16);
                result.push_back(static_cast<char>(c));
                i += 2;
            } catch (...) {
                result.push_back(src[i]);
            }
        } else if (src[i] == '+') {
            result.push_back(' ');
        } else {
            result.push_back(src[i]);
        }
    }
    return result;
}

static bool parse_json_body(const HttpRequest& req, json& out) {
    if (req.body.empty()) return false;
    try {
        out = json::parse(req.body);
        return true;
    } catch (...) {
        return false;
    }
}

// Admin auth check helper (simulated)
static std::optional<HttpResponse> require_admin(const HttpRequest& req) {
    auto it = req.headers.find("Authorization");
    if (it == req.headers.end()) {
        return HttpResponse::error(401, "M_MISSING_TOKEN", "Missing Authorization header");
    }
    // In production this would validate a real admin access token
    std::string auth = it->second;
    if (auth.find("Bearer ") == std::string::npos &&
        auth.find("bearer ") == std::string::npos) {
        return HttpResponse::error(401, "M_UNKNOWN_TOKEN", "Invalid Authorization header format");
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// SECTION 1 – Server Config Management  (lines ~250–500)
// ============================================================================
// Server config dump with secret redaction.
// Mirrors Synapse's configuration hierarchy with categories.
// ---------------------------------------------------------------------------

struct ConfigEntry {
    std::string key;
    std::string value;
    bool is_secret = false;
    std::string category;
    std::string description;
    std::string source; // "yaml", "env", "default", "runtime"
};

std::vector<ConfigEntry> g_config_entries;
std::mutex g_config_mutex;

// Current signing key state
struct SigningKeyInfo {
    std::string key_id;
    std::string algorithm;    // "ed25519"
    std::string public_key_base64;
    int64_t created_at;
    int64_t expires_at;       // 0 = no expiry
    bool is_current = false;
    bool is_old_verify_only = false;
    int version = 1;
};

std::vector<SigningKeyInfo> g_signing_keys;
std::mutex g_signing_key_mutex;

// TLS certificate state
struct TlsCertInfo {
    std::string cert_path;
    std::string key_path;
    std::string subject;
    std::string issuer;
    std::string serial_number;
    int64_t not_before;
    int64_t not_after;
    std::string fingerprint_sha256;
    int days_until_expiry = 0;
    bool loaded = false;
    int64_t last_reload_ts = 0;
};

TlsCertInfo g_tls_cert_info;
std::mutex g_tls_mutex;

void init_server_config() {
    std::lock_guard<std::mutex> lock(g_config_mutex);
    if (!g_config_entries.empty()) return;

    // =========================================================================
    // General server config
    // =========================================================================
    g_config_entries.push_back({"server_name", "localhost", false, "general",
        "The domain name of the server", "yaml"});
    g_config_entries.push_back({"pid_file", "/var/run/matrix-synapse.pid", false, "general",
        "Path to the PID file", "yaml"});
    g_config_entries.push_back({"web_client_location", "/usr/share/matrix-synapse/webclient", false, "general",
        "Path to static web client resources", "yaml"});
    g_config_entries.push_back({"soft_file_limit", "65536", false, "general",
        "Soft limit on open file descriptors", "yaml"});
    g_config_entries.push_back({"presence.enabled", "true", false, "general",
        "Enable presence tracking", "yaml"});
    g_config_entries.push_back({"presence.offline_timeout", "300000", false, "general",
        "Time before a user is shown as offline (ms)", "default"});
    g_config_entries.push_back({"require_auth_for_profile_requests", "false", false, "general",
        "Require auth for profile lookups", "yaml"});
    g_config_entries.push_back({"allow_public_rooms_over_federation", "true", false, "general",
        "Allow remote servers to query public rooms", "yaml"});
    g_config_entries.push_back({"default_room_version", "10", false, "general",
        "Default room version for new rooms", "yaml"});
    g_config_entries.push_back({"enable_search", "true", false, "general",
        "Enable the search API", "yaml"});
    g_config_entries.push_back({"user_directory.enabled", "true", false, "general",
        "Enable the user directory", "yaml"});
    g_config_entries.push_back({"user_directory.search_all_users", "false", false, "general",
        "Search all users in user directory", "yaml"});

    // =========================================================================
    // Listener / binding config
    // =========================================================================
    g_config_entries.push_back({"listeners[0].port", "8008", false, "listeners",
        "Client-server API port", "yaml"});
    g_config_entries.push_back({"listeners[0].type", "http", false, "listeners",
        "Listener type", "yaml"});
    g_config_entries.push_back({"listeners[0].bind_addresses", "0.0.0.0", false, "listeners",
        "Listener bind addresses", "yaml"});
    g_config_entries.push_back({"listeners[0].resources[0].names", "client", false, "listeners",
        "Resource names served", "yaml"});
    g_config_entries.push_back({"listeners[1].port", "8448", false, "listeners",
        "Federation API port", "yaml"});
    g_config_entries.push_back({"listeners[1].type", "http", false, "listeners",
        "Listener type", "yaml"});
    g_config_entries.push_back({"listeners[1].resources[0].names", "federation", false, "listeners",
        "Resource names served", "yaml"});
    g_config_entries.push_back({"no_tls", "false", false, "listeners",
        "Disable TLS entirely", "yaml"});
    g_config_entries.push_back({"use_presence", "true", false, "listeners",
        "Enable HTTP presence tracking", "yaml"});

    // =========================================================================
    // TLS configuration
    // =========================================================================
    g_config_entries.push_back({"tls_certificate_path", "/etc/matrix-synapse/server.crt", false, "tls",
        "Path to TLS certificate", "yaml"});
    g_config_entries.push_back({"tls_private_key_path", "/etc/matrix-synapse/server.key", true, "tls",
        "Path to TLS private key", "yaml"});
    g_config_entries.push_back({"tls_dh_params_path", "/etc/matrix-synapse/dhparams.pem", false, "tls",
        "Path to Diffie-Hellman parameters", "yaml"});
    g_config_entries.push_back({"federation_verify_certificates", "true", false, "tls",
        "Verify certificates on federation connections", "yaml"});
    g_config_entries.push_back({"federation_custom_ca_list", "", false, "tls",
        "Custom CA list for federation", "yaml"});

    // =========================================================================
    // Database config
    // =========================================================================
    g_config_entries.push_back({"database.name", "psycopg2", false, "database",
        "Database engine name", "yaml"});
    g_config_entries.push_back({"database.args.user", "synapse_user", false, "database",
        "Database user", "yaml"});
    g_config_entries.push_back({"database.args.password", "********", true, "database",
        "Database password", "yaml"});
    g_config_entries.push_back({"database.args.database", "synapse", false, "database",
        "Database name", "yaml"});
    g_config_entries.push_back({"database.args.host", "localhost", false, "database",
        "Database host", "yaml"});
    g_config_entries.push_back({"database.args.port", "5432", false, "database",
        "Database port", "yaml"});
    g_config_entries.push_back({"database.args.cp_min", "5", false, "database",
        "Connection pool minimum size", "yaml"});
    g_config_entries.push_back({"database.args.cp_max", "20", false, "database",
        "Connection pool maximum size", "yaml"});
    g_config_entries.push_back({"allow_unsafe_locale", "false", false, "database",
        "Allow unsafe database locale", "yaml"});

    // =========================================================================
    // Logging config
    // =========================================================================
    g_config_entries.push_back({"log_config", "/etc/matrix-synapse/log.yaml", false, "logging",
        "Path to logging configuration file", "yaml"});
    g_config_entries.push_back({"log.level", "INFO", false, "logging",
        "Log level", "yaml"});
    g_config_entries.push_back({"log.format", "json", false, "logging",
        "Log output format", "yaml"});

    // =========================================================================
    // Rate limiting config
    // =========================================================================
    g_config_entries.push_back({"rc_messages_per_second", "0.2", false, "ratelimiting",
        "Client message rate limit per second", "yaml"});
    g_config_entries.push_back({"rc_message_burst_count", "10", false, "ratelimiting",
        "Client message burst count", "yaml"});
    g_config_entries.push_back({"rc_registration.per_second", "0.17", false, "ratelimiting",
        "Registration rate limit per second", "yaml"});
    g_config_entries.push_back({"rc_registration.burst_count", "3", false, "ratelimiting",
        "Registration burst count", "yaml"});
    g_config_entries.push_back({"rc_login.address.per_second", "0.17", false, "ratelimiting",
        "Login rate limit per address per second", "yaml"});
    g_config_entries.push_back({"rc_login.account.per_second", "0.17", false, "ratelimiting",
        "Login rate limit per account per second", "yaml"});
    g_config_entries.push_back({"rc_login.burst_count", "3", false, "ratelimiting",
        "Login burst count", "yaml"});
    g_config_entries.push_back({"rc_federation.per_second", "0.1", false, "ratelimiting",
        "Federation rate limit per second", "yaml"});
    g_config_entries.push_back({"rc_federation.window_size", "1000", false, "ratelimiting",
        "Federation rate limit window size (ms)", "yaml"});
    g_config_entries.push_back({"rc_admin_redaction.per_second", "1", false, "ratelimiting",
        "Admin redaction rate limit per second", "default"});
    g_config_entries.push_back({"federation_rr_transactions_per_room_per_second", "50", false, "ratelimiting",
        "Per-room federation transaction rate", "default"});

    // =========================================================================
    // Media config
    // =========================================================================
    g_config_entries.push_back({"media_store_path", "/var/lib/matrix-synapse/media", false, "media",
        "Path to media store", "yaml"});
    g_config_entries.push_back({"max_upload_size", "50M", false, "media",
        "Maximum upload size", "yaml"});
    g_config_entries.push_back({"max_image_pixels", "32M", false, "media",
        "Maximum image pixel count", "yaml"});
    g_config_entries.push_back({"enable_media_repo", "true", false, "media",
        "Enable the media repository", "yaml"});
    g_config_entries.push_back({"url_preview_enabled", "true", false, "media",
        "Enable URL previews", "yaml"});
    g_config_entries.push_back({"url_preview_ip_range_blacklist", "127.0.0.0/8, 10.0.0.0/8", false, "media",
        "IP ranges blacklisted for URL preview", "yaml"});
    g_config_entries.push_back({"url_preview_url_blacklist", "", false, "media",
        "URL blacklist for preview", "yaml"});
    g_config_entries.push_back({"url_preview_max_spider_size", "10M", false, "media",
        "Max spiderable page size for preview", "default"});
    g_config_entries.push_back({"dynamic_thumbnails", "true", false, "media",
        "Generate thumbnails dynamically", "default"});
    g_config_entries.push_back({"thumbnail_sizes", "32x32,96x96,320x240,640x480,800x600", false, "media",
        "Thumbnail size presets", "yaml"});

    // =========================================================================
    // Registration config
    // =========================================================================
    g_config_entries.push_back({"enable_registration", "false", false, "registration",
        "Enable open registration", "yaml"});
    g_config_entries.push_back({"registrations_require_3pid", "false", false, "registration",
        "Require third-party ID for registration", "yaml"});
    g_config_entries.push_back({"disable_msisdn_registration", "true", false, "registration",
        "Disable MSISDN registration", "default"});
    g_config_entries.push_back({"enable_registration_captcha", "false", false, "registration",
        "Require CAPTCHA for registration", "yaml"});
    g_config_entries.push_back({"recaptcha_public_key", "", false, "registration",
        "reCAPTCHA public key", "yaml"});
    g_config_entries.push_back({"recaptcha_private_key", "", true, "registration",
        "reCAPTCHA private key", "yaml"});
    g_config_entries.push_back({"enable_registration_token", "false", false, "registration",
        "Require registration tokens", "yaml"});
    g_config_entries.push_back({"auto_join_rooms", "", false, "registration",
        "Rooms to auto-join on registration", "yaml"});
    g_config_entries.push_back({"autocreate_auto_join_rooms", "false", false, "registration",
        "Auto-create auto-join rooms if needed", "yaml"});

    // =========================================================================
    // Account validity config
    // =========================================================================
    g_config_entries.push_back({"account_validity.enabled", "false", false, "account",
        "Enable account validity enforcement", "yaml"});
    g_config_entries.push_back({"account_validity.period", "0", false, "account",
        "Account validity period in ms (0=unlimited)", "yaml"});
    g_config_entries.push_back({"account_validity.startup_job_max_delta", "86400000", false, "account",
        "Max delta for startup renewal job (ms)", "default"});
    g_config_entries.push_back({"account_validity.renew_email_subject", "Renew your Matrix account", false, "account",
        "Subject of renewal notification email", "yaml"});

    // =========================================================================
    // Metrics config
    // =========================================================================
    g_config_entries.push_back({"enable_metrics", "true", false, "metrics",
        "Enable Prometheus metrics", "yaml"});
    g_config_entries.push_back({"metrics_port", "9090", false, "metrics",
        "Metrics HTTP server port", "yaml"});
    g_config_entries.push_back({"metrics_flags.known_servers", "true", false, "metrics",
        "Track known servers metric", "yaml"});

    // =========================================================================
    // API config
    // =========================================================================
    g_config_entries.push_back({"room_invite_state_types", "", false, "api",
        "State types included in invite events", "yaml"});
    g_config_entries.push_back({"report_stats", "true", false, "api",
        "Report anonymized stats to Matrix.org", "yaml"});
    g_config_entries.push_back({"turn_uris", "", false, "api",
        "TURN server URIs", "yaml"});
    g_config_entries.push_back({"turn_shared_secret", "", true, "api",
        "TURN shared secret", "yaml"});
    g_config_entries.push_back({"turn_username_lifetime", "3600000", false, "api",
        "TURN username lifetime (ms)", "default"});
    g_config_entries.push_back({"turn_allow_guests", "true", false, "api",
        "Allow guest users to use TURN", "default"});

    // =========================================================================
    // Signing keys config
    // =========================================================================
    g_config_entries.push_back({"signing_key_path", "/etc/matrix-synapse/signing.key", true, "crypto",
        "Path to the signing key file", "yaml"});
    g_config_entries.push_back({"old_signing_keys", "{}", false, "crypto",
        "Map of old signing key IDs to keys", "yaml"});
    g_config_entries.push_back({"key_refresh_interval", "86400000", false, "crypto",
        "Interval between automatic key refreshes (ms)", "default"});
    g_config_entries.push_back({"suppress_key_server_warning", "false", false, "crypto",
        "Suppress key server warning", "default"});

    // =========================================================================
    // Federation config
    // =========================================================================
    g_config_entries.push_back({"send_federation", "true", false, "federation",
        "Enable federation sending", "yaml"});
    g_config_entries.push_back({"federation_domain_whitelist", "", false, "federation",
        "Federation domain whitelist", "yaml"});
    g_config_entries.push_back({"federation_rc_window_size", "1000", false, "federation",
        "Federation rate limiting window (ms)", "default"});
    g_config_entries.push_back({"federation_rc_sleep_limit", "10", false, "federation",
        "Federation rate limiting sleep limit", "default"});
    g_config_entries.push_back({"federation_rc_sleep_delay", "500", false, "federation",
        "Federation rate limiting sleep delay (ms)", "default"});
    g_config_entries.push_back({"federation_rc_reject_limit", "50", false, "federation",
        "Federation rate limiting reject limit", "default"});
    g_config_entries.push_back({"federation_rc_concurrent", "3", false, "federation",
        "Maximum concurrent federation connections per server", "default"});

    // =========================================================================
    // Caches config
    // =========================================================================
    g_config_entries.push_back({"caches.global_factor", "0.5", false, "caches",
        "Global cache size factor", "yaml"});
    g_config_entries.push_back({"caches.per_cache_factors.events", "1.0", false, "caches",
        "Event cache size factor", "yaml"});
    g_config_entries.push_back({"caches.per_cache_factors.state", "1.0", false, "caches",
        "State cache size factor", "yaml"});
    g_config_entries.push_back({"caches.per_cache_factors.state_group", "1.0", false, "caches",
        "State group cache size factor", "yaml"});
    g_config_entries.push_back({"caches.expiry_time.get_users_in_room", "300000", false, "caches",
        "get_users_in_room cache expiry (ms)", "yaml"});
    g_config_entries.push_back({"caches.expiry_time.signing_key", "86400000", false, "caches",
        "Signing key cache expiry (ms)", "default"});
    g_config_entries.push_back({"caches.expiry_time.room_member", "1800000", false, "caches",
        "Room member cache expiry (ms)", "default"});
    g_config_entries.push_back({"caches.evict_on_hash_change", "false", false, "caches",
        "Evict caches on DB hash change", "yaml"});

    // =========================================================================
    // Password policy config
    // =========================================================================
    g_config_entries.push_back({"password_config.enabled", "false", false, "password_policy",
        "Enable password policy enforcement", "yaml"});
    g_config_entries.push_back({"password_config.minimum_length", "8", false, "password_policy",
        "Minimum password length", "yaml"});

    // =========================================================================
    // SSO config
    // =========================================================================
    g_config_entries.push_back({"saml2_enabled", "false", false, "sso",
        "Enable SAML2 SSO", "yaml"});
    g_config_entries.push_back({"oidc_enabled", "false", false, "sso",
        "Enable OIDC SSO", "yaml"});
    g_config_entries.push_back({"cas_enabled", "false", false, "sso",
        "Enable CAS SSO", "yaml"});

    // =========================================================================
    // Retention config
    // =========================================================================
    g_config_entries.push_back({"retention_enabled", "false", false, "retention",
        "Enable message retention", "yaml"});
    g_config_entries.push_back({"retention_default_policy.max_lifetime", "infinity", false, "retention",
        "Default max message lifetime", "yaml"});
    g_config_entries.push_back({"retention_allowed_lifetime_min", "86400000", false, "retention",
        "Minimum allowed lifetime (ms)", "default"});
    g_config_entries.push_back({"retention_allowed_lifetime_max", "31536000000", false, "retention",
        "Maximum allowed lifetime (ms)", "default"});

    // =========================================================================
    // Spam checker config
    // =========================================================================
    g_config_entries.push_back({"spam_checker[0].module", "synapse.module_checker.SpamChecker", false, "spam",
        "Spam checker module", "yaml"});
    g_config_entries.push_back({"spam_checker[0].config.block_invites", "false", false, "spam",
        "Block invites via spam checker", "yaml"});

    // =========================================================================
    // Modules / experimental config
    // =========================================================================
    g_config_entries.push_back({"experimental_features.msc3026", "true", false, "experimental",
        "Enable MSC3026 (busy presence)", "yaml"});
    g_config_entries.push_back({"experimental_features.msc3030", "false", false, "experimental",
        "Enable MSC3030 (jump to date API)", "yaml"});
    g_config_entries.push_back({"experimental_features.msc3881", "false", false, "experimental",
        "Enable MSC3881 (remotely toggle push notifications)", "yaml"});
    g_config_entries.push_back({"experimental_features.msc3886", "false", false, "experimental",
        "Enable MSC3886 (simple client relationship)", "yaml"});

    // =========================================================================
    // Workers config
    // =========================================================================
    g_config_entries.push_back({"worker_replication_host", "127.0.0.1", false, "workers",
        "Replication listener host for workers", "yaml"});
    g_config_entries.push_back({"worker_replication_http_port", "9093", false, "workers",
        "Replication HTTP port for workers", "yaml"});
    g_config_entries.push_back({"worker_replication_secret", "", true, "workers",
        "Replication shared secret", "yaml"});
    g_config_entries.push_back({"worker_name", "master", false, "workers",
        "Name of this worker", "yaml"});
    g_config_entries.push_back({"run_background_tasks_on", "", false, "workers",
        "Worker to run background tasks on", "yaml"});

    // =========================================================================
    // Consent config
    // =========================================================================
    g_config_entries.push_back({"user_consent.server_notice_content.text", "", false, "consent",
        "Consent notice text for server notices", "yaml"});
    g_config_entries.push_back({"user_consent.require_at_registration", "false", false, "consent",
        "Require consent at registration", "yaml"});
    g_config_entries.push_back({"user_consent.policy_name", "Privacy Policy", false, "consent",
        "Policy name for consent", "yaml"});
    g_config_entries.push_back({"form_secret", "", true, "consent",
        "Secret for form hashing", "yaml"});
    g_config_entries.push_back({"trusted_key_servers[0].server_name", "matrix.org", false, "consent",
        "Trusted key server name", "default"});

    // =========================================================================
    // Opentracing config
    // =========================================================================
    g_config_entries.push_back({"opentracing.enabled", "false", false, "tracing",
        "Enable OpenTracing", "yaml"});
    g_config_entries.push_back({"opentracing.homeserver_whitelist", "", false, "tracing",
        "Homeserver whitelist for tracing", "yaml"});

    // =========================================================================
    // Push config
    // =========================================================================
    g_config_entries.push_back({"push.enabled", "true", false, "push",
        "Enable push notifications", "yaml"});
    g_config_entries.push_back({"push.include_content", "true", false, "push",
        "Include message content in push payload", "yaml"});
    g_config_entries.push_back({"push.group_unread_count_by_room", "true", false, "push",
        "Group unread count by room in push payload", "default"});

    // =========================================================================
    // CAS / Third-party ID config
    // =========================================================================
    g_config_entries.push_back({"cas_server_url", "", false, "cas",
        "CAS server URL", "yaml"});
    g_config_entries.push_back({"account_threepid_delegate.email", "", false, "threepid",
        "Email third-party ID delegation endpoint", "yaml"});
    g_config_entries.push_back({"account_threepid_delegate.msisdn", "", false, "threepid",
        "MSISDN third-party ID delegation endpoint", "yaml"});

    // =========================================================================
    // MAC secret key
    // =========================================================================
    g_config_entries.push_back({"macaroon_secret_key", "", true, "crypto",
        "Macaroon secret key for token generation", "yaml"});
    g_config_entries.push_back({"registration_shared_secret", "", true, "crypto",
        "Shared secret for admin registration API", "yaml"});

    // =========================================================================
    // Email config
    // =========================================================================
    g_config_entries.push_back({"email.smtp_host", "localhost", false, "email",
        "SMTP host for email sending", "yaml"});
    g_config_entries.push_back({"email.smtp_port", "25", false, "email",
        "SMTP port", "yaml"});
    g_config_entries.push_back({"email.smtp_user", "", false, "email",
        "SMTP username", "yaml"});
    g_config_entries.push_back({"email.smtp_pass", "", true, "email",
        "SMTP password", "yaml"});
    g_config_entries.push_back({"email.notif_from", "matrix@localhost", false, "email",
        "From address for notification emails", "yaml"});
    g_config_entries.push_back({"email.notif_template_html", "", false, "email",
        "Path to HTML notification template", "yaml"});
    g_config_entries.push_back({"email.notif_template_text", "", false, "email",
        "Path to text notification template", "yaml"});

    // Init signing keys
    {
        std::lock_guard<std::mutex> sk_lock(g_signing_key_mutex);
        if (g_signing_keys.empty()) {
            SigningKeyInfo sk;
            sk.key_id = "ed25519:a_abc123";
            sk.algorithm = "ed25519";
            sk.public_key_base64 = "ABCdefGHIjklMNOpqrSTUvwxYZ1234567890abCdEfGhIjKlMnOpQrStUvWxYz";
            sk.created_at = now_sec() - 86400 * 90;
            sk.expires_at = now_sec() + 86400 * 30;
            sk.is_current = true;
            sk.version = 1;
            g_signing_keys.push_back(sk);

            SigningKeyInfo sk_old;
            sk_old.key_id = "ed25519:a_old456";
            sk_old.algorithm = "ed25519";
            sk_old.public_key_base64 = "OLDkeyMATERIALforVERIFICATIONonlyZZZZzzzzZZZZzzzzZZZZzzzzZZZZ";
            sk_old.created_at = now_sec() - 86400 * 180;
            sk_old.expires_at = 0;
            sk_old.is_current = false;
            sk_old.is_old_verify_only = true;
            sk_old.version = 0;
            g_signing_keys.push_back(sk_old);
        }
    }

    // Init TLS cert info
    {
        std::lock_guard<std::mutex> tl_lock(g_tls_mutex);
        g_tls_cert_info.cert_path = "/etc/matrix-synapse/server.crt";
        g_tls_cert_info.key_path = "/etc/matrix-synapse/server.key";
        g_tls_cert_info.subject = "CN=matrix.localhost, O=Matrix, C=US";
        g_tls_cert_info.issuer = "CN=Matrix Internal CA, O=Matrix, C=US";
        g_tls_cert_info.serial_number = "01:23:45:67:89:AB:CD:EF";
        g_tls_cert_info.not_before = now_sec() - 86400 * 30;
        g_tls_cert_info.not_after = now_sec() + 86400 * 335;
        g_tls_cert_info.fingerprint_sha256 = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";
        g_tls_cert_info.loaded = true;
        g_tls_cert_info.last_reload_ts = now_sec() - 86400;
        g_tls_cert_info.days_until_expiry = 335;
    }
}

// ---------------------------------------------------------------------------
// SECTION 1 HANDLERS – Server config
// ---------------------------------------------------------------------------

// GET /_synapse/admin/v1/config
// Returns the full server configuration with secrets redacted.
// Query params: ?category=general  to filter by category
HttpResponse handle_server_config(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_server_config();
    std::string filter_category = query_param(req, "category", "");

    std::lock_guard<std::mutex> lock(g_config_mutex);

    json resp;
    resp["server_name"] = SERVER_NAME;
    resp["server_version"] = SERVER_VERSION;
    resp["config_entries"] = json::array();
    resp["total_entries"] = 0;

    json entries_by_category = json::object();

    int count = 0;
    for (const auto& entry : g_config_entries) {
        if (!filter_category.empty() && entry.category != filter_category) continue;

        json je;
        je["key"] = entry.key;
        je["value"] = entry.is_secret ? "[REDACTED]" : entry.value;
        je["is_secret"] = entry.is_secret;
        je["category"] = entry.category;
        je["description"] = entry.description;
        je["source"] = entry.source;

        entries_by_category[entry.category].push_back(je);
        resp["config_entries"].push_back(je);
        count++;
    }

    resp["total_entries"] = count;
    resp["categories"] = json::array();
    std::set<std::string> seen_categories;
    for (const auto& entry : g_config_entries) {
        if (!filter_category.empty() && entry.category != filter_category) continue;
        if (seen_categories.insert(entry.category).second) {
            resp["categories"].push_back(entry.category);
        }
    }

    resp["entries_by_category"] = entries_by_category;
    resp["secrets_redacted"] = true;
    resp["queried_at_ms"] = now_ms();

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 2 – Server Lifecycle Management  (lines ~750–1100)
// ============================================================================
// Server restart, shutdown, worker restart APIs.
// These are admin-only endpoints that orchestrate graceful server transitions.
// ============================================================================

// Server lifecycle state
struct ServerLifecycleState {
    std::string status;          // "running", "restarting", "shutting_down", "stopped"
    std::string last_action;
    int64_t last_action_ts = 0;
    std::string last_action_by;
    int64_t server_started_at;
    int restart_count = 0;
    int64_t last_restart_ts = 0;
    bool restart_scheduled = false;
    int64_t restart_scheduled_at = 0;
    int restart_delay_ms = 5000;  // 5 second delay before restart
    bool shutdown_complete = false;
};

ServerLifecycleState g_server_lifecycle;
std::mutex g_lifecycle_mutex;
std::atomic<bool> g_shutdown_flag{false};

// Worker state tracking
struct WorkerInfo {
    std::string worker_name;
    std::string worker_type;     // "generic_worker", "media_repository", "pusher", "federation_sender", "appservice"
    int pid = 0;
    std::string host;
    int port = 0;
    std::string status;          // "running", "restarting", "stopped"
    int64_t started_at = 0;
    int64_t last_heartbeat = 0;
    double cpu_percent = 0.0;
    int64_t memory_rss_bytes = 0;
    int connections = 0;
    int restart_count = 0;
    int64_t last_restart_ts = 0;
};

std::vector<WorkerInfo> g_worker_infos;
std::mutex g_worker_mutex;

void init_lifecycle_state() {
    std::lock_guard<std::mutex> lock(g_lifecycle_mutex);
    if (g_server_lifecycle.server_started_at > 0) return;
    g_server_lifecycle.status = "running";
    g_server_lifecycle.server_started_at = now_sec() - 86400 * 2; // started 2 days ago
    g_server_lifecycle.restart_count = 0;
    g_server_lifecycle.shutdown_complete = false;
}

void init_workers() {
    std::lock_guard<std::mutex> lock(g_worker_mutex);
    if (!g_worker_infos.empty()) return;

    g_worker_infos.push_back({
        "synapse.app.generic_worker1", "generic_worker",
        12346, "127.0.0.1", 8083,
        "running", now_sec() - 172800, now_sec(),
        15.2, 256LL * 1024 * 1024, 42, 0, 0
    });
    g_worker_infos.push_back({
        "synapse.app.generic_worker2", "generic_worker",
        12347, "127.0.0.1", 8084,
        "running", now_sec() - 172800, now_sec(),
        12.8, 240LL * 1024 * 1024, 38, 0, 0
    });
    g_worker_infos.push_back({
        "synapse.app.media_repository", "media_repository",
        12348, "127.0.0.1", 8085,
        "running", now_sec() - 172800, now_sec(),
        5.4, 128LL * 1024 * 1024, 15, 0, 0
    });
    g_worker_infos.push_back({
        "synapse.app.federation_sender", "federation_sender",
        12349, "127.0.0.1", 8086,
        "running", now_sec() - 172800, now_sec(),
        8.1, 180LL * 1024 * 1024, 22, 0, 0
    });
    g_worker_infos.push_back({
        "synapse.app.pusher", "pusher",
        12350, "127.0.0.1", 8087,
        "running", now_sec() - 172800, now_sec(),
        3.2, 96LL * 1024 * 1024, 10, 0, 0
    });
    g_worker_infos.push_back({
        "synapse.app.appservice", "appservice",
        12351, "127.0.0.1", 8088,
        "running", now_sec() - 172800, now_sec(),
        2.1, 72LL * 1024 * 1024, 5, 0, 0
    });
}

// ---------------------------------------------------------------------------
// SECTION 2 HANDLERS – Server lifecycle
// ---------------------------------------------------------------------------

// POST /_synapse/admin/v1/server/restart
// Initiates a graceful server restart.
// Body (optional): { "delay_ms": 5000, "reason": "maintenance" }
HttpResponse handle_server_restart(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_lifecycle_state();

    json body;
    int delay_ms = 5000;
    std::string reason = "Administrative restart";
    std::string requested_by = "admin";

    if (parse_json_body(req, body)) {
        if (body.contains("delay_ms")) delay_ms = body["delay_ms"].get<int>();
        if (body.contains("reason")) reason = body["reason"].get<std::string>();
        if (body.contains("requested_by")) requested_by = body["requested_by"].get<std::string>();
    }

    std::lock_guard<std::mutex> lock(g_lifecycle_mutex);

    if (g_server_lifecycle.status == "shutting_down") {
        return HttpResponse::bad_request("Server is currently shutting down, cannot restart");
    }

    if (g_server_lifecycle.restart_scheduled) {
        return HttpResponse::bad_request("A restart is already scheduled");
    }

    g_server_lifecycle.status = "restarting";
    g_server_lifecycle.last_action = "restart";
    g_server_lifecycle.last_action_ts = now_ms();
    g_server_lifecycle.last_action_by = requested_by;
    g_server_lifecycle.restart_scheduled = true;
    g_server_lifecycle.restart_scheduled_at = now_ms();
    g_server_lifecycle.restart_delay_ms = delay_ms;
    g_server_lifecycle.restart_count++;

    json resp;
    resp["status"] = "restart_scheduled";
    resp["delay_ms"] = delay_ms;
    resp["scheduled_at_ms"] = g_server_lifecycle.restart_scheduled_at;
    resp["estimated_restart_at_ms"] = g_server_lifecycle.restart_scheduled_at + delay_ms;
    resp["reason"] = reason;
    resp["requested_by"] = requested_by;
    resp["restart_count"] = g_server_lifecycle.restart_count;
    resp["server_started_at"] = g_server_lifecycle.server_started_at;
    resp["uptime_seconds"] = now_sec() - g_server_lifecycle.server_started_at;
    resp["message"] = "Server restart scheduled with " + std::to_string(delay_ms) +
                      "ms delay. Server will gracefully drain connections before restarting.";

    return HttpResponse::ok(resp);
}

// POST /_synapse/admin/v1/server/shutdown
// Initiates a graceful server shutdown.
// Body (optional): { "reason": "maintenance", "force": false }
HttpResponse handle_server_shutdown(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_lifecycle_state();

    json body;
    std::string reason = "Administrative shutdown";
    bool force = false;
    std::string requested_by = "admin";

    if (parse_json_body(req, body)) {
        if (body.contains("reason")) reason = body["reason"].get<std::string>();
        if (body.contains("force")) force = body["force"].get<bool>();
        if (body.contains("requested_by")) requested_by = body["requested_by"].get<std::string>();
    }

    std::lock_guard<std::mutex> lock(g_lifecycle_mutex);

    if (g_server_lifecycle.shutdown_complete) {
        return HttpResponse::bad_request("Server is already shut down");
    }

    g_server_lifecycle.status = "shutting_down";
    g_server_lifecycle.last_action = "shutdown";
    g_server_lifecycle.last_action_ts = now_ms();
    g_server_lifecycle.last_action_by = requested_by;
    g_shutdown_flag.store(true);

    json resp;
    resp["status"] = "shutting_down";
    resp["force"] = force;
    resp["reason"] = reason;
    resp["requested_by"] = requested_by;
    resp["shutdown_at_ms"] = now_ms();
    resp["server_started_at"] = g_server_lifecycle.server_started_at;
    resp["uptime_seconds"] = now_sec() - g_server_lifecycle.server_started_at;
    resp["message"] = force ?
        "Server shutdown initiated (forced). Connections will be dropped immediately." :
        "Server shutdown initiated. Connections will be gracefully drained.";

    return HttpResponse::ok(resp);
}

// GET /_synapse/admin/v1/server/status
// Returns current server lifecycle status.
HttpResponse handle_server_status(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_lifecycle_state();
    init_workers();

    std::lock_guard<std::mutex> lock(g_lifecycle_mutex);

    json resp;
    resp["status"] = g_server_lifecycle.status;
    resp["server_name"] = SERVER_NAME;
    resp["server_version"] = SERVER_VERSION;
    resp["matrix_version"] = MATRIX_VERSION;
    resp["python_version"] = PYTHON_VERSION;
    resp["server_started_at"] = g_server_lifecycle.server_started_at;
    resp["uptime_seconds"] = now_sec() - g_server_lifecycle.server_started_at;
    resp["uptime_human"] = []() -> std::string {
        int64_t uptime = now_sec() - g_server_lifecycle.server_started_at;
        int days = uptime / 86400;
        int hours = (uptime % 86400) / 3600;
        int mins = (uptime % 3600) / 60;
        std::ostringstream oss;
        oss << days << "d " << hours << "h " << mins << "m";
        return oss.str();
    }();
    resp["restart_count"] = g_server_lifecycle.restart_count;
    resp["last_action"] = g_server_lifecycle.last_action;
    resp["last_action_ts"] = g_server_lifecycle.last_action_ts;

    {
        std::lock_guard<std::mutex> wlock(g_worker_mutex);
        resp["total_workers"] = static_cast<int>(g_worker_infos.size());
        json workers_arr = json::array();
        for (const auto& w : g_worker_infos) {
            json jw;
            jw["name"] = w.worker_name;
            jw["type"] = w.worker_type;
            jw["pid"] = w.pid;
            jw["status"] = w.status;
            jw["cpu_percent"] = w.cpu_percent;
            jw["memory_rss_bytes"] = w.memory_rss_bytes;
            jw["connections"] = w.connections;
            jw["uptime_seconds"] = now_sec() - w.started_at;
            jw["restart_count"] = w.restart_count;
            workers_arr.push_back(jw);
        }
        resp["workers"] = workers_arr;
    }

    return HttpResponse::ok(resp);
}

// POST /_synapse/admin/v1/server/worker/{workerName}/restart
// Restarts a specific worker process.
HttpResponse handle_worker_restart(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_workers();

    std::string worker_name = url_decode(path_param(req, "workerName"));
    if (worker_name.empty()) {
        return HttpResponse::bad_request("Missing workerName path parameter");
    }

    json body;
    int delay_ms = 2000;
    std::string reason = "Worker restart requested";

    if (parse_json_body(req, body)) {
        if (body.contains("delay_ms")) delay_ms = body["delay_ms"].get<int>();
        if (body.contains("reason")) reason = body["reason"].get<std::string>();
    }

    std::lock_guard<std::mutex> lock(g_worker_mutex);

    WorkerInfo* target = nullptr;
    for (auto& w : g_worker_infos) {
        if (w.worker_name == worker_name) {
            target = &w;
            break;
        }
    }

    if (!target) {
        return HttpResponse::not_found("Worker not found: " + worker_name);
    }

    if (target->status == "restarting") {
        return HttpResponse::bad_request("Worker " + worker_name + " is already restarting");
    }

    target->status = "restarting";
    target->last_restart_ts = now_ms();
    target->restart_count++;

    json resp;
    resp["worker_name"] = worker_name;
    resp["worker_type"] = target->worker_type;
    resp["status"] = "restarting";
    resp["delay_ms"] = delay_ms;
    resp["reason"] = reason;
    resp["restart_count"] = target->restart_count;
    resp["previous_pid"] = target->pid;
    resp["scheduled_at_ms"] = now_ms();
    resp["message"] = "Worker " + worker_name + " restart scheduled with " +
                      std::to_string(delay_ms) + "ms delay";

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 3 – Cache Management Operations  (lines ~1100–1300)
// ============================================================================
// Flush caches and cache eviction statistics.
// ============================================================================

// Cache eviction tracking
struct CacheEvictionStats {
    std::string cache_name;
    int64_t max_entries = 0;
    int64_t current_entries = 0;
    int64_t evictions_since_start = 0;
    int64_t evictions_last_hour = 0;
    int64_t evictions_last_minute = 0;
    double eviction_rate_per_sec = 0.0;
    int64_t last_eviction_ts = 0;
    std::string eviction_policy;  // "LRU", "LFU", "TTL", "FIFO"
    double avg_entry_age_ms = 0.0;
    double max_entry_age_ms = 0.0;
    int64_t entries_evicted_due_to_expiry = 0;
    int64_t entries_evicted_due_to_size = 0;
    double cache_fill_percent = 0.0;
};

std::vector<CacheEvictionStats> g_cache_eviction_stats;
std::mutex g_cache_eviction_mutex;
std::atomic<int64_t> g_total_cache_flushes{0};
std::atomic<int64_t> g_last_cache_flush_ts{0};

void init_cache_eviction_stats() {
    std::lock_guard<std::mutex> lock(g_cache_eviction_mutex);
    if (!g_cache_eviction_stats.empty()) return;

    // Simulated cache eviction stats for all major caches
    std::vector<std::tuple<std::string, int64_t, int64_t, std::string>> cache_defs = {
        {"events", 100000, 87234, "LRU"},
        {"event_auth", 50000, 42100, "LRU"},
        {"state", 100000, 78120, "LRU"},
        {"state_group", 50000, 32450, "LRU"},
        {"state_group_membership", 20000, 15320, "LRU"},
        {"get_users_in_room", 10000, 7823, "TTL"},
        {"get_rooms_for_user", 10000, 6540, "LRU"},
        {"room_member", 50000, 43210, "LRU"},
        {"room_summary", 5000, 3200, "LRU"},
        {"profile", 10000, 5430, "TTL"},
        {"device", 20000, 12340, "LRU"},
        {"signing_key", 100, 23, "TTL"},
        {"server_key", 100, 45, "TTL"},
        {"federation_destination", 1000, 342, "LRU"},
        {"federation_ratelimit", 1000, 567, "FIFO"},
        {"event_push_actions", 5000, 2340, "LRU"},
        {"media_repository", 5000, 1890, "LRU"},
        {"url_preview", 2000, 876, "TTL"},
        {"thumbnails", 5000, 2100, "LRU"},
        {"presence", 10000, 4560, "LRU"},
    };

    for (const auto& [name, max_entries, current, policy] : cache_defs) {
        CacheEvictionStats ces;
        ces.cache_name = name;
        ces.max_entries = max_entries;
        ces.current_entries = current;
        ces.eviction_policy = policy;
        ces.evictions_since_start = static_cast<int64_t>(current * 0.15);
        ces.evictions_last_hour = static_cast<int64_t>(current * 0.01);
        ces.evictions_last_minute = static_cast<int64_t>(current * 0.0003);
        ces.eviction_rate_per_sec = ces.evictions_last_minute / 60.0;
        ces.last_eviction_ts = now_ms() - (rand() % 60000);
        ces.avg_entry_age_ms = 300000.0 + (rand() % 600000);
        ces.max_entry_age_ms = 3600000.0 + (rand() % 7200000);
        ces.entries_evicted_due_to_expiry = ces.evictions_since_start / 3;
        ces.entries_evicted_due_to_size = ces.evictions_since_start - ces.entries_evicted_due_to_expiry;
        ces.cache_fill_percent = max_entries > 0 ? (100.0 * current / max_entries) : 0.0;
        g_cache_eviction_stats.push_back(ces);
    }

    g_total_cache_flushes.store(0);
    g_last_cache_flush_ts.store(0);
}

// ---------------------------------------------------------------------------
// SECTION 3 HANDLERS – Cache management
// ---------------------------------------------------------------------------

// POST /_synapse/admin/v1/caches/flush
// Flushes all server caches.
// Query: ?cache=events  to flush a specific cache
HttpResponse handle_flush_caches(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_cache_eviction_stats();

    std::string target_cache = query_param(req, "cache", "");
    bool dry_run = query_param_bool(req, "dry_run", false);

    int flushed_count = 0;
    int64_t entries_flushed = 0;
    json flushed_caches = json::array();

    {
        std::lock_guard<std::mutex> lock(g_cache_eviction_mutex);

        for (auto& ces : g_cache_eviction_stats) {
            if (!target_cache.empty() && ces.cache_name != target_cache) continue;

            if (!dry_run) {
                entries_flushed += ces.current_entries;
                ces.current_entries = 0;
                ces.cache_fill_percent = 0.0;
                ces.last_eviction_ts = now_ms();
            }

            json jc;
            jc["cache_name"] = ces.cache_name;
            jc["entries_flushed"] = dry_run ? 0 : ces.evictions_since_start;
            jc["was_fill_percent"] = ces.cache_fill_percent;
            flushed_caches.push_back(jc);
            flushed_count++;
        }

        if (!dry_run) {
            g_total_cache_flushes.fetch_add(1);
            g_last_cache_flush_ts.store(now_ms());
        }
    }

    json resp;
    resp["flushed"] = dry_run ? "dry_run" : "completed";
    resp["flushed_caches_count"] = flushed_count;
    resp["total_entries_flushed"] = entries_flushed;
    resp["flushed_caches"] = flushed_caches;
    resp["total_flushes_since_start"] = g_total_cache_flushes.load();
    resp["last_flush_ts"] = g_last_cache_flush_ts.load();
    resp["message"] = dry_run ?
        "Dry run complete. " + std::to_string(flushed_count) + " caches would be flushed." :
        "Successfully flushed " + std::to_string(flushed_count) + " caches (" +
        std::to_string(entries_flushed) + " entries)";

    return HttpResponse::ok(resp);
}

// GET /_synapse/admin/v1/caches/eviction_stats
// Returns detailed eviction statistics for all caches.
HttpResponse handle_cache_eviction_stats(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_cache_eviction_stats();

    std::lock_guard<std::mutex> lock(g_cache_eviction_mutex);

    json resp;
    resp["caches"] = json::array();

    int64_t total_evictions_since_start = 0;
    int64_t total_evictions_last_hour = 0;
    int64_t total_current_entries = 0;
    int64_t total_max_entries = 0;

    for (const auto& ces : g_cache_eviction_stats) {
        json jc;
        jc["cache_name"] = ces.cache_name;
        jc["eviction_policy"] = ces.eviction_policy;
        jc["max_entries"] = ces.max_entries;
        jc["current_entries"] = ces.current_entries;
        jc["cache_fill_percent"] = std::round(ces.cache_fill_percent * 100.0) / 100.0;
        jc["evictions_since_start"] = ces.evictions_since_start;
        jc["evictions_last_hour"] = ces.evictions_last_hour;
        jc["evictions_last_minute"] = ces.evictions_last_minute;
        jc["eviction_rate_per_sec"] = std::round(ces.eviction_rate_per_sec * 1000.0) / 1000.0;
        jc["entries_evicted_due_to_expiry"] = ces.entries_evicted_due_to_expiry;
        jc["entries_evicted_due_to_size"] = ces.entries_evicted_due_to_size;
        jc["avg_entry_age_ms"] = ces.avg_entry_age_ms;
        jc["max_entry_age_ms"] = ces.max_entry_age_ms;
        jc["last_eviction_ts"] = ces.last_eviction_ts;

        resp["caches"].push_back(jc);

        total_evictions_since_start += ces.evictions_since_start;
        total_evictions_last_hour += ces.evictions_last_hour;
        total_current_entries += ces.current_entries;
        total_max_entries += ces.max_entries;
    }

    resp["total_caches"] = static_cast<int>(g_cache_eviction_stats.size());
    resp["total_evictions_since_start"] = total_evictions_since_start;
    resp["total_evictions_last_hour"] = total_evictions_last_hour;
    resp["total_current_entries"] = total_current_entries;
    resp["total_max_entries"] = total_max_entries;
    resp["global_fill_percent"] = total_max_entries > 0 ?
        std::round(10000.0 * total_current_entries / total_max_entries) / 100.0 : 0.0;
    resp["total_flushes"] = g_total_cache_flushes.load();
    resp["last_flush_ts"] = g_last_cache_flush_ts.load();

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 4 – TLS Certificate Management  (lines ~1300–1500)
// ============================================================================
// Reload TLS certificates without server restart.
// ============================================================================

// ---------------------------------------------------------------------------
// SECTION 4 HANDLERS – TLS
// ---------------------------------------------------------------------------

// POST /_synapse/admin/v1/server/reload_tls
// Reloads TLS certificates from disk.
// Body (optional): { "cert_path": "/path/to/cert", "key_path": "/path/to/key" }
HttpResponse handle_reload_tls_certs(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_server_config();

    json body;
    std::string new_cert_path;
    std::string new_key_path;

    if (parse_json_body(req, body)) {
        if (body.contains("cert_path")) new_cert_path = body["cert_path"].get<std::string>();
        if (body.contains("key_path")) new_key_path = body["key_path"].get<std::string>();
    }

    std::lock_guard<std::mutex> lock(g_tls_mutex);

    json resp;
    resp["action"] = "reload_tls";

    std::string old_cert_path = g_tls_cert_info.cert_path;
    std::string old_key_path = g_tls_cert_info.key_path;

    if (!new_cert_path.empty()) g_tls_cert_info.cert_path = new_cert_path;
    if (!new_key_path.empty()) g_tls_cert_info.key_path = new_key_path;

    g_tls_cert_info.loaded = true;
    g_tls_cert_info.last_reload_ts = now_sec();

    // Simulate reading new cert info
    g_tls_cert_info.fingerprint_sha256 = gen_token(64);
    g_tls_cert_info.serial_number = gen_token(8);
    g_tls_cert_info.not_before = now_sec() - 86400;
    g_tls_cert_info.not_after = now_sec() + 86400 * 365;
    g_tls_cert_info.days_until_expiry = 365;

    resp["previous_cert_path"] = old_cert_path;
    resp["previous_key_path"] = old_key_path;
    resp["current_cert_path"] = g_tls_cert_info.cert_path;
    resp["current_key_path"] = g_tls_cert_info.key_path;
    resp["loaded"] = g_tls_cert_info.loaded;
    resp["reloaded_at"] = g_tls_cert_info.last_reload_ts;
    resp["fingerprint_sha256"] = g_tls_cert_info.fingerprint_sha256;
    resp["days_until_expiry"] = g_tls_cert_info.days_until_expiry;
    resp["cert_info"] = json::object({
        {"subject", g_tls_cert_info.subject},
        {"issuer", g_tls_cert_info.issuer},
        {"serial_number", g_tls_cert_info.serial_number},
        {"not_before", g_tls_cert_info.not_before},
        {"not_after", g_tls_cert_info.not_after},
    });
    resp["message"] = "TLS certificates reloaded successfully. Active connections will use new certs.";

    return HttpResponse::ok(resp);
}

// GET /_synapse/admin/v1/server/tls_info
// Returns current TLS certificate info.
HttpResponse handle_tls_info(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_server_config();

    std::lock_guard<std::mutex> lock(g_tls_mutex);

    json resp;
    resp["loaded"] = g_tls_cert_info.loaded;
    resp["cert_path"] = g_tls_cert_info.cert_path;
    resp["key_path"] = g_tls_cert_info.key_path;
    resp["subject"] = g_tls_cert_info.subject;
    resp["issuer"] = g_tls_cert_info.issuer;
    resp["serial_number"] = g_tls_cert_info.serial_number;
    resp["not_before"] = g_tls_cert_info.not_before;
    resp["not_after"] = g_tls_cert_info.not_after;
    resp["fingerprint_sha256"] = g_tls_cert_info.fingerprint_sha256;
    resp["days_until_expiry"] = g_tls_cert_info.days_until_expiry;
    resp["last_reload_ts"] = g_tls_cert_info.last_reload_ts;

    // Expiry warning
    if (g_tls_cert_info.days_until_expiry < 30) {
        resp["warning"] = "Certificate expires in " + std::to_string(g_tls_cert_info.days_until_expiry) + " days!";
    } else if (g_tls_cert_info.days_until_expiry < 60) {
        resp["warning"] = "Certificate expires in " + std::to_string(g_tls_cert_info.days_until_expiry) + " days.";
    }

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 5 – Signing Key Rotation  (lines ~1500–1750)
// ============================================================================
// Rotate the server's signing keys.
// ============================================================================

// ---------------------------------------------------------------------------
// SECTION 5 HANDLERS – Signing keys
// ---------------------------------------------------------------------------

// POST /_synapse/admin/v1/server/rotate_signing_keys
// Rotates the server signing keys.
// Body: { "algorithm": "ed25519", "expiry_days": 30 }
HttpResponse handle_rotate_signing_keys(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_server_config();

    json body;
    std::string algorithm = "ed25519";
    int expiry_days = 30;
    std::string reason = "Administrative key rotation";

    if (parse_json_body(req, body)) {
        if (body.contains("algorithm")) algorithm = body["algorithm"].get<std::string>();
        if (body.contains("expiry_days")) expiry_days = body["expiry_days"].get<int>();
        if (body.contains("reason")) reason = body["reason"].get<std::string>();
    }

    std::lock_guard<std::mutex> lock(g_signing_key_mutex);

    // Move current key to old
    for (auto& sk : g_signing_keys) {
        if (sk.is_current) {
            sk.is_current = false;
            sk.is_old_verify_only = true;
            sk.expires_at = now_sec() + 86400 * 7; // 7 day grace period
        }
    }

    // Create new key
    SigningKeyInfo new_key;
    new_key.key_id = algorithm + ":" + gen_token(6);
    new_key.algorithm = algorithm;
    new_key.public_key_base64 = gen_token(43);
    new_key.created_at = now_sec();
    new_key.expires_at = expiry_days > 0 ? now_sec() + 86400 * expiry_days : 0;
    new_key.is_current = true;
    new_key.version = 1;
    g_signing_keys.push_back(new_key);

    json resp;
    resp["action"] = "rotate_signing_keys";
    resp["new_key"] = json::object({
        {"key_id", new_key.key_id},
        {"algorithm", new_key.algorithm},
        {"public_key_base64", new_key.public_key_base64},
        {"created_at", new_key.created_at},
        {"expires_at", new_key.expires_at},
        {"version", new_key.version},
    });

    json old_keys = json::array();
    for (const auto& sk : g_signing_keys) {
        if (!sk.is_current) {
            json jk;
            jk["key_id"] = sk.key_id;
            jk["is_old_verify_only"] = sk.is_old_verify_only;
            jk["expires_at"] = sk.expires_at;
            old_keys.push_back(jk);
        }
    }
    resp["old_keys"] = old_keys;
    resp["total_keys"] = static_cast<int>(g_signing_keys.size());
    resp["reason"] = reason;
    resp["message"] = "Signing key rotated successfully. New key ID: " + new_key.key_id +
                      ". Old keys will be retained for " + std::to_string(expiry_days) +
                      " days for signature verification.";

    return HttpResponse::ok(resp);
}

// GET /_synapse/admin/v1/server/signing_keys
// Returns current signing key information (public keys only).
HttpResponse handle_get_signing_keys(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_server_config();

    std::lock_guard<std::mutex> lock(g_signing_key_mutex);

    json resp;
    resp["keys"] = json::array();

    for (const auto& sk : g_signing_keys) {
        json jk;
        jk["key_id"] = sk.key_id;
        jk["algorithm"] = sk.algorithm;
        jk["public_key_base64"] = sk.public_key_base64;
        jk["created_at"] = sk.created_at;
        jk["expires_at"] = sk.expires_at;
        jk["is_current"] = sk.is_current;
        jk["is_old_verify_only"] = sk.is_old_verify_only;
        jk["version"] = sk.version;
        resp["keys"].push_back(jk);
    }

    resp["total_keys"] = static_cast<int>(g_signing_keys.size());
    resp["current_key_id"] = [&]() -> std::string {
        for (const auto& sk : g_signing_keys)
            if (sk.is_current) return sk.key_id;
        return "";
    }();

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 6 – Database Maintenance  (lines ~1750–2100)
// ============================================================================
// DB integrity check, vacuum, and reindex operations.
// ============================================================================

// Database table info
struct DbTableInfo {
    std::string table_name;
    int64_t row_count = 0;
    int64_t total_size_bytes = 0;
    int64_t index_size_bytes = 0;
    int64_t dead_tuples = 0;
    double bloat_percent = 0.0;
    int64_t last_vacuum_ts = 0;
    int64_t last_analyze_ts = 0;
    int64_t last_reindex_ts = 0;
    bool has_errors = false;
    std::string error_message;
};

std::vector<DbTableInfo> g_db_tables;
std::mutex g_db_mutex;
std::atomic<int> g_db_integrity_check_count{0};
std::atomic<int> g_db_vacuum_count{0};
std::atomic<int> g_db_reindex_count{0};

void init_db_tables() {
    std::lock_guard<std::mutex> lock(g_db_mutex);
    if (!g_db_tables.empty()) return;

    // Full list of Synapse database tables
    std::vector<std::pair<std::string, int64_t>> tables = {
        {"events", 2850000},
        {"event_json", 2850000},
        {"state_events", 1850000},
        {"state_groups", 120000},
        {"state_groups_state", 5200000},
        {"current_state_events", 380000},
        {"room_memberships", 450000},
        {"rooms", 15000},
        {"room_aliases", 32000},
        {"event_auth", 7200000},
        {"event_edges", 1200000},
        {"event_forward_extremities", 280000},
        {"event_push_actions", 850000},
        {"event_push_actions_staging", 120000},
        {"event_reports", 1200},
        {"event_search", 150000},
        {"redactions", 45000},
        {"event_relations", 680000},
        {"receipts_graph", 1800000},
        {"receipts_linearized", 1800000},
        {"users", 8500},
        {"user_ips", 520000},
        {"user_daily_visits", 280000},
        {"profiles", 8200},
        {"devices", 18500},
        {"access_tokens", 22000},
        {"e2e_room_keys", 35000},
        {"e2e_one_time_keys_json", 120000},
        {"device_inbox", 950000},
        {"device_lists_outbound_pokes", 25000},
        {"device_lists_stream", 48000},
        {"presence_stream", 120000},
        {"presence_list", 8500},
        {"pushers", 1800},
        {"push_rules", 22000},
        {"push_rules_enable", 18500},
        {"appservice_room_list", 3200},
        {"application_services_state", 1500},
        {"federation_stream_position", 1},
        {"destinations", 350},
        {"destination_rooms", 8500},
        {"stream_ordering_to_exterm", 120000},
        {"exterm_outlier_stream", 15000},
        {"cache_invalidation_stream_by_instance", 42000},
        {"account_validity", 8500},
        {"registration_tokens", 250},
        {"ui_auth_sessions", 180},
        {"ui_auth_sessions_credentials", 350},
        {"ui_auth_sessions_ips", 520},
        {"user_threepids", 3200},
        {"user_threepid_id_server", 1500},
        {"stats_incremental_position", 1},
        {"local_media_repository", 65000},
        {"local_media_repository_thumbnails", 120000},
        {"remote_media_cache", 185000},
        {"remote_media_cache_thumbnails", 95000},
        {"deleted_local_media", 1200},
        {"url_cache", 8500},
    };

    for (const auto& [name, rows] : tables) {
        DbTableInfo ti;
        ti.table_name = name;
        ti.row_count = rows;
        ti.total_size_bytes = rows * 180; // rough estimate
        ti.index_size_bytes = rows * 80;
        ti.dead_tuples = static_cast<int64_t>(rows * 0.02); // 2% dead tuples
        ti.bloat_percent = 5.0 + (rand() % 30); // 5-35% bloat
        ti.last_vacuum_ts = now_sec() - 86400 * (rand() % 7); // within last week
        ti.last_analyze_ts = now_sec() - 86400 * (rand() % 3);
        ti.last_reindex_ts = now_sec() - 86400 * (rand() % 14);
        ti.has_errors = (rand() % 100) < 2; // 2% chance of errors
        if (ti.has_errors) {
            ti.error_message = "Index corruption detected on index idx_" + name + "_stream_ordering";
        }
        g_db_tables.push_back(ti);
    }
}

// ---------------------------------------------------------------------------
// SECTION 6 HANDLERS – Database maintenance
// ---------------------------------------------------------------------------

// POST /_synapse/admin/v1/database/integrity_check
// Runs a database integrity check across all tables.
// Query: ?table=events  to check a specific table
HttpResponse handle_db_integrity_check(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_db_tables();

    std::string target_table = query_param(req, "table", "");
    bool full_check = query_param_bool(req, "full", false);

    std::lock_guard<std::mutex> lock(g_db_mutex);

    json resp;
    resp["check_id"] = gen_uuid();
    resp["check_type"] = full_check ? "full" : "quick";
    resp["started_at_ms"] = now_ms();
    resp["results"] = json::array();

    int tables_checked = 0;
    int tables_with_errors = 0;
    int tables_skipped = 0;

    for (const auto& table : g_db_tables) {
        if (!target_table.empty() && table.table_name != target_table) {
            tables_skipped++;
            continue;
        }

        json jt;
        jt["table"] = table.table_name;
        jt["row_count"] = table.row_count;
        jt["size_bytes"] = table.total_size_bytes;
        jt["index_size_bytes"] = table.index_size_bytes;
        jt["has_errors"] = table.has_errors;

        if (full_check) {
            // Simulated integrity check results
            jt["check_passed"] = !table.has_errors;
            jt["constraints_valid"] = true;
            jt["referential_integrity_ok"] = !table.has_errors;
            jt["index_valid"] = !table.has_errors;
            jt["no_corruption"] = !table.has_errors;
        } else {
            jt["check_passed"] = !table.has_errors;
        }

        if (table.has_errors) {
            jt["error_message"] = table.error_message;
            tables_with_errors++;
        }

        resp["results"].push_back(jt);
        tables_checked++;
    }

    g_db_integrity_check_count.fetch_add(1);

    resp["tables_checked"] = tables_checked;
    resp["tables_with_errors"] = tables_with_errors;
    resp["tables_skipped"] = tables_skipped;
    resp["overall_pass"] = (tables_with_errors == 0);
    resp["completed_at_ms"] = now_ms();
    resp["duration_ms"] = resp["completed_at_ms"].get<int64_t>() - resp["started_at_ms"].get<int64_t>();
    resp["check_count_total"] = g_db_integrity_check_count.load();
    resp["message"] = tables_with_errors == 0 ?
        "Database integrity check passed. All " + std::to_string(tables_checked) + " tables OK." :
        "Database integrity check found " + std::to_string(tables_with_errors) + " table(s) with errors.";

    return HttpResponse::ok(resp);
}

// POST /_synapse/admin/v1/database/vacuum
// Runs VACUUM (or VACUUM FULL) on database tables.
// Body: { "table": "events", "full": false, "analyze": true }
HttpResponse handle_db_vacuum(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_db_tables();

    json body;
    std::string target_table = "";
    bool full_vacuum = false;
    bool analyze = true;
    bool dry_run = false;

    if (parse_json_body(req, body)) {
        if (body.contains("table")) target_table = body["table"].get<std::string>();
        if (body.contains("full")) full_vacuum = body["full"].get<bool>();
        if (body.contains("analyze")) analyze = body["analyze"].get<bool>();
        if (body.contains("dry_run")) dry_run = body["dry_run"].get<bool>();
    }

    // Fallback to query param
    if (target_table.empty()) target_table = query_param(req, "table", "");

    std::lock_guard<std::mutex> lock(g_db_mutex);

    json resp;
    resp["vacuum_id"] = gen_uuid();
    resp["vacuum_type"] = full_vacuum ? "FULL" : "standard";
    resp["analyze"] = analyze;
    resp["dry_run"] = dry_run;
    resp["started_at_ms"] = now_ms();
    resp["results"] = json::array();

    int tables_processed = 0;
    int64_t bytes_freed_estimate = 0;

    for (auto& table : g_db_tables) {
        if (!target_table.empty() && table.table_name != target_table) continue;

        json jt;
        jt["table"] = table.table_name;
        jt["dead_tuples_before"] = table.dead_tuples;
        jt["bloat_percent_before"] = table.bloat_percent;
        jt["size_before_bytes"] = table.total_size_bytes;

        if (!dry_run) {
            int64_t freed = static_cast<int64_t>(table.total_size_bytes * table.bloat_percent / 100.0);
            bytes_freed_estimate += freed;
            table.total_size_bytes -= freed;
            table.dead_tuples = 0;
            table.bloat_percent = 1.0;
            table.last_vacuum_ts = now_sec();
            if (analyze) table.last_analyze_ts = now_sec();
        }

        jt["dead_tuples_after"] = table.dead_tuples;
        jt["bloat_percent_after"] = table.bloat_percent;
        jt["size_after_bytes"] = table.total_size_bytes;
        jt["bytes_freed"] = table.total_size_bytes > 0 ?
            (jt["size_before_bytes"].get<int64_t>() - table.total_size_bytes) : 0;

        resp["results"].push_back(jt);
        tables_processed++;
    }

    if (!dry_run) g_db_vacuum_count.fetch_add(1);

    resp["tables_processed"] = tables_processed;
    resp["total_bytes_freed"] = bytes_freed_estimate;
    resp["completed_at_ms"] = now_ms();
    resp["duration_ms"] = resp["completed_at_ms"].get<int64_t>() - resp["started_at_ms"].get<int64_t>();
    resp["vacuum_count_total"] = g_db_vacuum_count.load();
    resp["message"] = dry_run ?
        "Dry run: " + std::to_string(tables_processed) + " tables would be vacuumed, ~" +
        std::to_string(bytes_freed_estimate / (1024*1024)) + " MB would be freed." :
        "Vacuum completed on " + std::to_string(tables_processed) + " tables. Freed ~" +
        std::to_string(bytes_freed_estimate / (1024*1024)) + " MB.";

    return HttpResponse::ok(resp);
}

// POST /_synapse/admin/v1/database/reindex
// Reindexes database tables.
// Body: { "table": "events", "index": "idx_events_stream_ordering" }
HttpResponse handle_db_reindex(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_db_tables();

    json body;
    std::string target_table = "";
    std::string target_index = "";

    if (parse_json_body(req, body)) {
        if (body.contains("table")) target_table = body["table"].get<std::string>();
        if (body.contains("index")) target_index = body["index"].get<std::string>();
    }

    if (target_table.empty()) target_table = query_param(req, "table", "");

    std::lock_guard<std::mutex> lock(g_db_mutex);

    json resp;
    resp["reindex_id"] = gen_uuid();
    resp["started_at_ms"] = now_ms();
    resp["results"] = json::array();

    int tables_processed = 0;

    for (auto& table : g_db_tables) {
        if (!target_table.empty() && table.table_name != target_table) continue;

        json jt;
        jt["table"] = table.table_name;
        jt["indexes_rebuilt"] = json::array();

        // Simulate reindexing each table's typical indexes
        std::vector<std::string> indexes = {
            "idx_" + table.table_name + "_stream_ordering",
            "idx_" + table.table_name + "_room_id",
            "idx_" + table.table_name + "_topological_ordering",
        };

        for (const auto& idx : indexes) {
            if (!target_index.empty() && idx != target_index) continue;

            json ji;
            ji["index_name"] = idx;
            ji["rebuilt"] = true;
            ji["index_size_before_bytes"] = table.index_size_bytes;
            ji["index_size_after_bytes"] = static_cast<int64_t>(table.index_size_bytes * 0.85);
            jt["indexes_rebuilt"].push_back(ji);
        }

        table.last_reindex_ts = now_sec();
        resp["results"].push_back(jt);
        tables_processed++;
    }

    g_db_reindex_count.fetch_add(1);

    resp["tables_processed"] = tables_processed;
    resp["completed_at_ms"] = now_ms();
    resp["duration_ms"] = resp["completed_at_ms"].get<int64_t>() - resp["started_at_ms"].get<int64_t>();
    resp["reindex_count_total"] = g_db_reindex_count.load();
    resp["message"] = "Reindex completed on " + std::to_string(tables_processed) + " tables.";

    return HttpResponse::ok(resp);
}

// GET /_synapse/admin/v1/database/table_stats
// Returns detailed table statistics.
HttpResponse handle_db_table_stats(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_db_tables();

    std::string sort_by = query_param(req, "sort_by", "row_count");
    std::string sort_order = query_param(req, "sort_order", "desc");

    std::lock_guard<std::mutex> lock(g_db_mutex);

    json resp;
    resp["tables"] = json::array();

    // Sort tables
    std::vector<DbTableInfo> sorted = g_db_tables;
    if (sort_by == "row_count") {
        std::sort(sorted.begin(), sorted.end(), [&](const DbTableInfo& a, const DbTableInfo& b) {
            return sort_order == "asc" ? a.row_count < b.row_count : a.row_count > b.row_count;
        });
    } else if (sort_by == "size") {
        std::sort(sorted.begin(), sorted.end(), [&](const DbTableInfo& a, const DbTableInfo& b) {
            return sort_order == "asc" ? a.total_size_bytes < b.total_size_bytes : a.total_size_bytes > b.total_size_bytes;
        });
    } else if (sort_by == "bloat") {
        std::sort(sorted.begin(), sorted.end(), [&](const DbTableInfo& a, const DbTableInfo& b) {
            return sort_order == "asc" ? a.bloat_percent < b.bloat_percent : a.bloat_percent > b.bloat_percent;
        });
    }

    int64_t total_rows = 0;
    int64_t total_size = 0;
    int64_t total_index_size = 0;

    for (const auto& table : sorted) {
        json jt;
        jt["table_name"] = table.table_name;
        jt["row_count"] = table.row_count;
        jt["total_size_bytes"] = table.total_size_bytes;
        jt["total_size_mb"] = std::round(table.total_size_bytes / 10485.76) / 100.0;
        jt["index_size_bytes"] = table.index_size_bytes;
        jt["index_size_mb"] = std::round(table.index_size_bytes / 10485.76) / 100.0;
        jt["dead_tuples"] = table.dead_tuples;
        jt["bloat_percent"] = std::round(table.bloat_percent * 100.0) / 100.0;
        jt["last_vacuum_ts"] = table.last_vacuum_ts;
        jt["last_analyze_ts"] = table.last_analyze_ts;
        jt["last_reindex_ts"] = table.last_reindex_ts;
        jt["has_errors"] = table.has_errors;

        resp["tables"].push_back(jt);

        total_rows += table.row_count;
        total_size += table.total_size_bytes;
        total_index_size += table.index_size_bytes;
    }

    resp["total_tables"] = static_cast<int>(sorted.size());
    resp["total_rows"] = total_rows;
    resp["total_size_bytes"] = total_size;
    resp["total_size_gb"] = std::round(total_size / 10737418.24) / 100.0;
    resp["total_index_size_bytes"] = total_index_size;
    resp["total_index_size_gb"] = std::round(total_index_size / 10737418.24) / 100.0;
    resp["vacuum_count"] = g_db_vacuum_count.load();
    resp["reindex_count"] = g_db_reindex_count.load();
    resp["integrity_check_count"] = g_db_integrity_check_count.load();

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 7 – Event Stream Diagnostics  (lines ~2100–2400)
// ============================================================================
// Event stream performance and health diagnostics.
// ============================================================================

struct EventStreamSnapshot {
    int64_t current_stream_ordering = 0;
    int64_t min_stream_ordering = 0;
    int64_t max_stream_ordering = 0;
    int64_t events_in_stream = 0;
    int64_t pdus_processed = 0;
    int64_t edus_processed = 0;
    double events_per_second = 0.0;
    double avg_event_processing_time_us = 0.0;
    double max_event_processing_time_us = 0.0;
    int64_t events_dropped = 0;
    int64_t events_retried = 0;
    int64_t stream_gaps = 0;
    int64_t lag_from_master_ms = 0;
    bool is_catching_up = false;
    int64_t catchup_remaining = 0;
    int64_t last_event_ts = 0;
    int64_t oldest_unresolved_event_ts = 0;
};

EventStreamSnapshot g_event_stream_snapshot;
std::mutex g_event_stream_mutex;
std::deque<std::pair<int64_t, double>> g_event_throughput_history; // (timestamp, events_per_sec)
const size_t MAX_THROUGHPUT_SAMPLES = 100;

void init_event_stream_diagnostics() {
    std::lock_guard<std::mutex> lock(g_event_stream_mutex);
    if (g_event_stream_snapshot.current_stream_ordering > 0) return;

    g_event_stream_snapshot.current_stream_ordering = 28500000;
    g_event_stream_snapshot.min_stream_ordering = 1;
    g_event_stream_snapshot.max_stream_ordering = 28500000;
    g_event_stream_snapshot.events_in_stream = 2850000;
    g_event_stream_snapshot.pdus_processed = 2600000;
    g_event_stream_snapshot.edus_processed = 250000;
    g_event_stream_snapshot.events_per_second = 12.5;
    g_event_stream_snapshot.avg_event_processing_time_us = 350.0;
    g_event_stream_snapshot.max_event_processing_time_us = 25000.0;
    g_event_stream_snapshot.events_dropped = 120;
    g_event_stream_snapshot.events_retried = 450;
    g_event_stream_snapshot.stream_gaps = 15;
    g_event_stream_snapshot.lag_from_master_ms = 0; // master itself
    g_event_stream_snapshot.is_catching_up = false;
    g_event_stream_snapshot.catchup_remaining = 0;
    g_event_stream_snapshot.last_event_ts = now_ms();
    g_event_stream_snapshot.oldest_unresolved_event_ts = now_ms() - 120000;

    // Populate throughput history
    for (size_t i = 0; i < MAX_THROUGHPUT_SAMPLES; ++i) {
        g_event_throughput_history.push_back({
            now_ms() - static_cast<int64_t>((MAX_THROUGHPUT_SAMPLES - i) * 30000),
            8.0 + (rand() % 200) / 10.0
        });
    }
}

// ---------------------------------------------------------------------------
// SECTION 7 HANDLERS – Event stream diagnostics
// ---------------------------------------------------------------------------

// GET /_synapse/admin/v1/event_stream/diagnostics
HttpResponse handle_event_stream_diagnostics(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_event_stream_diagnostics();

    std::lock_guard<std::mutex> lock(g_event_stream_mutex);

    json resp;
    resp["diagnostics"] = json::object({
        {"current_stream_ordering", g_event_stream_snapshot.current_stream_ordering},
        {"min_stream_ordering", g_event_stream_snapshot.min_stream_ordering},
        {"max_stream_ordering", g_event_stream_snapshot.max_stream_ordering},
        {"events_in_stream", g_event_stream_snapshot.events_in_stream},
        {"pdus_processed", g_event_stream_snapshot.pdus_processed},
        {"edus_processed", g_event_stream_snapshot.edus_processed},
        {"events_per_second", std::round(g_event_stream_snapshot.events_per_second * 100.0) / 100.0},
        {"avg_event_processing_time_us", std::round(g_event_stream_snapshot.avg_event_processing_time_us * 100.0) / 100.0},
        {"max_event_processing_time_us", std::round(g_event_stream_snapshot.max_event_processing_time_us * 100.0) / 100.0},
        {"events_dropped", g_event_stream_snapshot.events_dropped},
        {"events_retried", g_event_stream_snapshot.events_retried},
        {"stream_gaps", g_event_stream_snapshot.stream_gaps},
        {"lag_from_master_ms", g_event_stream_snapshot.lag_from_master_ms},
        {"is_catching_up", g_event_stream_snapshot.is_catching_up},
        {"catchup_remaining", g_event_stream_snapshot.catchup_remaining},
        {"last_event_ts", g_event_stream_snapshot.last_event_ts},
        {"oldest_unresolved_event_ts", g_event_stream_snapshot.oldest_unresolved_event_ts},
    });

    // Throughput history (last 30 samples)
    json throughput = json::array();
    size_t start = g_event_throughput_history.size() > 30 ?
        g_event_throughput_history.size() - 30 : 0;
    for (size_t i = start; i < g_event_throughput_history.size(); ++i) {
        json jt;
        jt["timestamp_ms"] = g_event_throughput_history[i].first;
        jt["events_per_second"] = std::round(g_event_throughput_history[i].second * 100.0) / 100.0;
        throughput.push_back(jt);
    }
    resp["throughput_history"] = throughput;

    // Health assessment
    std::string health = "healthy";
    std::vector<std::string> warnings;

    if (g_event_stream_snapshot.events_dropped > 100) {
        warnings.push_back("High number of dropped events");
    }
    if (g_event_stream_snapshot.stream_gaps > 10) {
        warnings.push_back("Stream gaps detected");
    }
    if (g_event_stream_snapshot.max_event_processing_time_us > 20000) {
        warnings.push_back("High max event processing time");
        health = "degraded";
    }
    if (g_event_stream_snapshot.is_catching_up) {
        warnings.push_back("Stream is catching up to master");
        health = "degraded";
    }

    resp["health"] = health;
    resp["warnings"] = warnings;
    resp["snapshot_at_ms"] = now_ms();

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 8 – Forward Extremity View  (lines ~2400–2600)
// ============================================================================
// Diagnose forward extremities per room.
// ============================================================================

struct ForwardExtremityInfo {
    std::string event_id;
    std::string room_id;
    int depth = 0;
    std::string received_ts;
    std::string type;
    std::string sender;
    bool is_outlier = false;
    int prev_events_count = 0;
    int auth_events_count = 0;
    int64_t stream_ordering = 0;
};

std::unordered_map<std::string, std::vector<ForwardExtremityInfo>> g_forward_extremities; // room_id -> FEs
std::mutex g_fe_mutex;

void init_forward_extremities() {
    std::lock_guard<std::mutex> lock(g_fe_mutex);
    if (!g_forward_extremities.empty()) return;

    std::vector<std::string> room_ids = {
        "!general:localhost",
        "!random:localhost",
        "!dev:localhost",
        "!announcements:localhost",
        "!secretproject:localhost",
    };

    for (const auto& room_id : room_ids) {
        std::vector<ForwardExtremityInfo> fes;
        int num_fes = 2 + (rand() % 8); // 2-9 extremities per room
        for (int i = 0; i < num_fes; ++i) {
            ForwardExtremityInfo fe;
            fe.event_id = "$" + gen_token(43);
            fe.room_id = room_id;
            fe.depth = 500 + (rand() % 5000);
            fe.received_ts = std::to_string(now_ms() - (rand() % 3600000));
            fe.type = (i == 0) ? "m.room.message" : "m.room.member";
            fe.sender = "@user" + std::to_string(rand() % 50) + ":localhost";
            fe.is_outlier = (rand() % 100) < 10;
            fe.prev_events_count = 1 + (rand() % 5);
            fe.auth_events_count = 3 + (rand() % 7);
            fe.stream_ordering = 28400000 + (rand() % 100000);
            fes.push_back(fe);
        }
        g_forward_extremities[room_id] = fes;
    }
}

// ---------------------------------------------------------------------------
// SECTION 8 HANDLERS – Forward extremities
// ---------------------------------------------------------------------------

// GET /_synapse/admin/v1/rooms/{roomId}/forward_extremities
HttpResponse handle_forward_extremity_view(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    if (room_id.empty()) {
        return HttpResponse::bad_request("Missing roomId path parameter");
    }

    init_forward_extremities();

    std::lock_guard<std::mutex> lock(g_fe_mutex);

    json resp;
    resp["room_id"] = room_id;

    auto it = g_forward_extremities.find(room_id);
    if (it == g_forward_extremities.end()) {
        resp["forward_extremities"] = json::array();
        resp["count"] = 0;
        resp["message"] = "No forward extremities found for room " + room_id;
        return HttpResponse::ok(resp);
    }

    resp["count"] = static_cast<int>(it->second.size());
    resp["forward_extremities"] = json::array();

    int max_depth = 0;
    int min_depth = INT_MAX;
    int outlier_count = 0;

    for (const auto& fe : it->second) {
        json jfe;
        jfe["event_id"] = fe.event_id;
        jfe["depth"] = fe.depth;
        jfe["received_ts"] = fe.received_ts;
        jfe["type"] = fe.type;
        jfe["sender"] = fe.sender;
        jfe["is_outlier"] = fe.is_outlier;
        jfe["prev_events_count"] = fe.prev_events_count;
        jfe["auth_events_count"] = fe.auth_events_count;
        jfe["stream_ordering"] = fe.stream_ordering;
        resp["forward_extremities"].push_back(jfe);

        if (fe.depth > max_depth) max_depth = fe.depth;
        if (fe.depth < min_depth) min_depth = fe.depth;
        if (fe.is_outlier) outlier_count++;
    }

    resp["max_depth"] = max_depth;
    resp["min_depth"] = min_depth == INT_MAX ? 0 : min_depth;
    resp["depth_spread"] = max_depth - min_depth;
    resp["outlier_count"] = outlier_count;
    resp["health"] = [&]() -> std::string {
        if (it->second.size() > 10) return "critical";
        if (it->second.size() > 5) return "warning";
        if (outlier_count > 2) return "warning";
        return "healthy";
    }();
    resp["recommendation"] = [&]() -> std::string {
        if (it->second.size() > 5) {
            return "Room has many forward extremities (" + std::to_string(it->second.size()) +
                   "). Consider running state resolution or checking for fed issues.";
        }
        if (outlier_count > 0) {
            return "Room has " + std::to_string(outlier_count) +
                   " outlier extremities. These may resolve when events are backfilled.";
        }
        return "Room forward extremities look healthy.";
    }();

    return HttpResponse::ok(resp);
}

// GET /_synapse/admin/v1/forward_extremities
// List all rooms with forward extremity info.
HttpResponse handle_all_forward_extremities(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_forward_extremities();

    std::lock_guard<std::mutex> lock(g_fe_mutex);

    json resp;
    resp["rooms"] = json::array();

    int total_extremities = 0;
    int rooms_with_issues = 0;

    for (const auto& [room_id, fes] : g_forward_extremities) {
        json jr;
        jr["room_id"] = room_id;
        jr["forward_extremity_count"] = static_cast<int>(fes.size());

        int max_depth = 0;
        int outliers = 0;
        for (const auto& fe : fes) {
            if (fe.depth > max_depth) max_depth = fe.depth;
            if (fe.is_outlier) outliers++;
        }
        jr["max_depth"] = max_depth;
        jr["outliers"] = outliers;
        jr["has_issues"] = (fes.size() > 5 || outliers > 2);

        resp["rooms"].push_back(jr);
        total_extremities += fes.size();
        if (fes.size() > 5 || outliers > 2) rooms_with_issues++;
    }

    resp["total_rooms"] = static_cast<int>(g_forward_extremities.size());
    resp["total_extremities"] = total_extremities;
    resp["avg_extremities_per_room"] = g_forward_extremities.empty() ? 0.0 :
        std::round(100.0 * total_extremities / g_forward_extremities.size()) / 100.0;
    resp["rooms_with_issues"] = rooms_with_issues;

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 9 – State Group View  (lines ~2600–2800)
// ============================================================================
// State group diagnostic view per room.
// ============================================================================

struct StateGroupInfo {
    int64_t id = 0;
    std::string room_id;
    int64_t prev_group_id = 0;
    int64_t event_count = 0;
    int64_t member_count = 0;
    int64_t total_state_entries = 0;
    int64_t stream_ordering = 0;
    int depth = 0;
    std::string created_at;
};

std::unordered_map<std::string, std::vector<StateGroupInfo>> g_state_groups; // room_id -> state_groups
std::mutex g_sg_mutex;

void init_state_groups() {
    std::lock_guard<std::mutex> lock(g_sg_mutex);
    if (!g_state_groups.empty()) return;

    std::vector<std::string> room_ids = {
        "!general:localhost",
        "!random:localhost",
        "!dev:localhost",
        "!announcements:localhost",
    };

    for (const auto& room_id : room_ids) {
        std::vector<StateGroupInfo> sgs;
        int num_groups = 100 + (rand() % 900);
        int64_t base_id = (rand() % 100000000);

        for (int i = 0; i < num_groups; ++i) {
            StateGroupInfo sg;
            sg.id = base_id + i;
            sg.room_id = room_id;
            sg.prev_group_id = (i > 0) ? (base_id + i - 1) : 0;
            sg.event_count = 50 + (rand() % 150);
            sg.member_count = 10 + (rand() % 200);
            sg.total_state_entries = sg.event_count + sg.member_count;
            sg.stream_ordering = 28000000 + i * 10 + (rand() % 5);
            sg.depth = 100 + i * 2 + (rand() % 3);
            sg.created_at = std::to_string(now_ms() - (num_groups - i) * 60000);
            sgs.push_back(sg);
        }
        g_state_groups[room_id] = sgs;
    }
}

// ---------------------------------------------------------------------------
// SECTION 9 HANDLERS – State groups
// ---------------------------------------------------------------------------

// GET /_synapse/admin/v1/rooms/{roomId}/state_groups
HttpResponse handle_state_group_view(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    if (room_id.empty()) {
        return HttpResponse::bad_request("Missing roomId path parameter");
    }

    init_state_groups();

    int offset = query_param_int(req, "offset", 0);
    int limit = query_param_int(req, "limit", 50);
    if (limit < 1) limit = 1;
    if (limit > 500) limit = 500;

    std::lock_guard<std::mutex> lock(g_sg_mutex);

    json resp;
    resp["room_id"] = room_id;

    auto it = g_state_groups.find(room_id);
    if (it == g_state_groups.end()) {
        resp["state_groups"] = json::array();
        resp["total"] = 0;
        resp["message"] = "No state groups found for room " + room_id;
        return HttpResponse::ok(resp);
    }

    resp["total"] = static_cast<int>(it->second.size());
    resp["offset"] = offset;
    resp["limit"] = limit;

    auto& sgs = it->second;
    int64_t total_state_entries = 0;
    int64_t total_members = 0;

    json sg_arr = json::array();
    int end = std::min(offset + limit, static_cast<int>(sgs.size()));
    for (int i = offset; i < end; ++i) {
        const auto& sg = sgs[i];
        json jsg;
        jsg["id"] = sg.id;
        jsg["prev_group_id"] = sg.prev_group_id;
        jsg["event_count"] = sg.event_count;
        jsg["member_count"] = sg.member_count;
        jsg["total_state_entries"] = sg.total_state_entries;
        jsg["stream_ordering"] = sg.stream_ordering;
        jsg["depth"] = sg.depth;
        jsg["created_at"] = sg.created_at;
        sg_arr.push_back(jsg);

        total_state_entries += sg.total_state_entries;
        total_members += sg.member_count;
    }

    resp["state_groups"] = sg_arr;

    // Aggregate stats across all state groups
    int64_t all_total_state_entries = 0;
    for (const auto& sg : sgs) all_total_state_entries += sg.total_state_entries;

    resp["aggregate"] = json::object({
        {"total_state_groups", static_cast<int>(sgs.size())},
        {"total_state_entries_all_groups", all_total_state_entries},
        {"avg_entries_per_group", sgs.empty() ? 0.0 :
            std::round(100.0 * all_total_state_entries / sgs.size()) / 100.0},
        {"page_total_entries", total_state_entries},
        {"page_total_members", total_members},
    });

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 10 – Room State Diagnostic  (lines ~2800–3000)
// ============================================================================
// Comprehensive room state diagnostics.
// ============================================================================

struct RoomStateDiagnostic {
    std::string room_id;
    std::string room_name;
    std::string room_version;
    int64_t joined_members = 0;
    int64_t invited_members = 0;
    int64_t banned_members = 0;
    int64_t total_members = 0;
    int64_t state_events_count = 0;
    int64_t current_state_size_bytes = 0;
    int64_t forward_extremity_count = 0;
    int64_t state_group_count = 0;
    int64_t event_count = 0;
    bool is_encrypted = false;
    std::string encryption_algorithm;
    int64_t last_event_ts = 0;
    int64_t last_active_ts = 0;
    std::vector<std::string> current_state_types;
    std::string creator;
    int64_t created_ts = 0;
    std::string join_rules;
    std::string history_visibility;
    int federation_depth = 0;
};

std::unordered_map<std::string, RoomStateDiagnostic> g_room_diagnostics; // room_id -> diagnostic
std::mutex g_room_diag_mutex;

void init_room_state_diagnostics() {
    std::lock_guard<std::mutex> lock(g_room_diag_mutex);
    if (!g_room_diagnostics.empty()) return;

    std::vector<std::string> room_ids = {
        "!general:localhost",
        "!random:localhost",
        "!dev:localhost",
        "!announcements:localhost",
        "!secretproject:localhost",
        "!social:localhost",
        "!support:localhost",
        "!bots:localhost",
        "!offtopic:localhost",
        "!lobby:localhost",
    };

    static const char* room_names[] = {
        "General Discussion", "Random", "Development", "Announcements",
        "Secret Project", "Social", "Support", "Bot Playground",
        "Off-Topic", "Lobby"
    };

    std::vector<std::string> state_types = {
        "m.room.name", "m.room.topic", "m.room.avatar", "m.room.canonical_alias",
        "m.room.create", "m.room.join_rules", "m.room.power_levels", "m.room.encryption",
        "m.room.history_visibility", "m.room.guest_access", "m.room.tombstone",
        "m.room.server_acl", "m.space.child", "m.space.parent"
    };

    static const char* join_rules_opts[] = {"public", "invite", "knock", "restricted"};

    for (size_t i = 0; i < room_ids.size(); ++i) {
        RoomStateDiagnostic rsd;
        rsd.room_id = room_ids[i];
        rsd.room_name = room_names[i % 10];
        rsd.room_version = (i < 8) ? "10" : "9";
        rsd.joined_members = 5 + (rand() % 200);
        rsd.invited_members = rand() % 20;
        rsd.banned_members = rand() % 5;
        rsd.total_members = rsd.joined_members + rsd.invited_members + rsd.banned_members;
        rsd.state_events_count = 50 + (rand() % 200);
        rsd.current_state_size_bytes = rsd.state_events_count * 1200;
        rsd.forward_extremity_count = 2 + (rand() % 8);
        rsd.state_group_count = 100 + (rand() % 900);
        rsd.event_count = 1000 + (rand() % 50000);
        rsd.is_encrypted = (rand() % 100) < 70;
        rsd.encryption_algorithm = rsd.is_encrypted ? "m.megolm.v1.aes-sha2" : "";
        rsd.last_event_ts = now_ms() - (rand() % 300000);
        rsd.last_active_ts = now_ms() - (rand() % 600000);
        rsd.current_state_types = state_types;
        rsd.creator = "@admin:localhost";
        rsd.created_ts = now_sec() - 86400 * (30 + rand() % 365);
        rsd.join_rules = join_rules_opts[rand() % 4];
        rsd.history_visibility = (rand() % 2 == 0) ? "shared" : "world_readable";
        rsd.federation_depth = 10 + (rand() % 100);

        g_room_diagnostics[room_ids[i]] = rsd;
    }
}

// ---------------------------------------------------------------------------
// SECTION 10 HANDLERS – Room state diagnostic
// ---------------------------------------------------------------------------

// GET /_synapse/admin/v1/rooms/{roomId}/state_diagnostic
HttpResponse handle_room_state_diagnostic(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    if (room_id.empty()) {
        return HttpResponse::bad_request("Missing roomId path parameter");
    }

    init_room_state_diagnostics();

    std::lock_guard<std::mutex> lock(g_room_diag_mutex);

    auto it = g_room_diagnostics.find(room_id);
    if (it == g_room_diagnostics.end()) {
        return HttpResponse::not_found("Room not found for diagnostic: " + room_id);
    }

    const auto& rsd = it->second;

    json resp;
    resp["room_id"] = rsd.room_id;
    resp["room_name"] = rsd.room_name;
    resp["room_version"] = rsd.room_version;
    resp["creator"] = rsd.creator;
    resp["created_at"] = rsd.created_ts;
    resp["join_rules"] = rsd.join_rules;
    resp["history_visibility"] = rsd.history_visibility;
    resp["is_encrypted"] = rsd.is_encrypted;
    resp["encryption_algorithm"] = rsd.encryption_algorithm;

    resp["members"] = json::object({
        {"joined", rsd.joined_members},
        {"invited", rsd.invited_members},
        {"banned", rsd.banned_members},
        {"total", rsd.total_members},
    });

    resp["state"] = json::object({
        {"state_events_count", rsd.state_events_count},
        {"current_state_size_bytes", rsd.current_state_size_bytes},
        {"current_state_size_kb", std::round(rsd.current_state_size_bytes / 102.4) / 10.0},
        {"state_group_count", rsd.state_group_count},
        {"forward_extremity_count", rsd.forward_extremity_count},
        {"state_types_tracked", rsd.current_state_types},
    });

    resp["events"] = json::object({
        {"total_event_count", rsd.event_count},
        {"last_event_ts", rsd.last_event_ts},
        {"last_active_ts", rsd.last_active_ts},
    });

    resp["federation_depth"] = rsd.federation_depth;

    // Health assessment
    json health = json::object();
    std::vector<std::string> warnings;
    std::string health_status = "healthy";

    if (rsd.forward_extremity_count > 5) {
        warnings.push_back("High forward extremity count: " + std::to_string(rsd.forward_extremity_count));
        health_status = "warning";
    }
    if (rsd.forward_extremity_count > 10) {
        health_status = "critical";
    }
    if (rsd.state_group_count > 500) {
        warnings.push_back("High state group count: " + std::to_string(rsd.state_group_count));
        if (health_status == "healthy") health_status = "warning";
    }
    if (rsd.state_group_count > 1000) {
        health_status = "critical";
    }
    if (rsd.current_state_size_bytes > 10 * 1024 * 1024) {
        warnings.push_back("Large state size: " +
            std::to_string(rsd.current_state_size_bytes / (1024*1024)) + " MB");
    }
    if (rsd.joined_members > 500) {
        warnings.push_back("Very large room: " + std::to_string(rsd.joined_members) + " joined members");
    }

    health["status"] = health_status;
    health["warnings"] = warnings;
    resp["health"] = health;

    return HttpResponse::ok(resp);
}

// GET /_synapse/admin/v1/rooms/diagnostics
// Returns summary diagnostics for all rooms.
HttpResponse handle_all_room_diagnostics(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_room_state_diagnostics();
    init_forward_extremities();

    std::lock_guard<std::mutex> lock(g_room_diag_mutex);

    json resp;
    resp["rooms"] = json::array();

    int total_rooms = 0;
    int64_t total_members = 0;
    int64_t total_events = 0;
    int rooms_with_issues = 0;

    for (const auto& [room_id, rsd] : g_room_diagnostics) {
        json jr;
        jr["room_id"] = rsd.room_id;
        jr["room_name"] = rsd.room_name;
        jr["room_version"] = rsd.room_version;
        jr["joined_members"] = rsd.joined_members;
        jr["total_members"] = rsd.total_members;
        jr["event_count"] = rsd.event_count;
        jr["forward_extremity_count"] = rsd.forward_extremity_count;
        jr["state_group_count"] = rsd.state_group_count;
        jr["is_encrypted"] = rsd.is_encrypted;
        jr["join_rules"] = rsd.join_rules;
        jr["last_active_ts"] = rsd.last_active_ts;
        jr["has_issues"] = rsd.forward_extremity_count > 5 || rsd.state_group_count > 500;

        resp["rooms"].push_back(jr);

        total_rooms++;
        total_members += rsd.total_members;
        total_events += rsd.event_count;
        if (rsd.forward_extremity_count > 5 || rsd.state_group_count > 500) rooms_with_issues++;
    }

    resp["total_rooms"] = total_rooms;
    resp["total_members"] = total_members;
    resp["total_events"] = total_events;
    resp["rooms_with_issues"] = rooms_with_issues;
    resp["avg_members_per_room"] = total_rooms > 0 ?
        std::round(100.0 * total_members / total_rooms) / 100.0 : 0.0;
    resp["avg_events_per_room"] = total_rooms > 0 ?
        std::round(100.0 * total_events / total_rooms) / 100.0 : 0.0;

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 11 – Device Diagnostic  (lines ~3000–3200)
// ============================================================================
// Comprehensive device diagnostic for the entire server.
// ============================================================================

struct DeviceDiagnosticEntry {
    std::string user_id;
    std::string device_id;
    std::string display_name;
    std::string device_type;
    std::string last_seen_ip;
    std::string last_seen_ts;
    std::string user_agent;
    bool is_active = true;
    int64_t one_time_keys_count = 0;
    bool has_fallback_key = false;
    std::string last_key_upload_ts;
    int64_t device_lists_outbound_pokes = 0;
    int64_t to_device_messages_pending = 0;
    int64_t since_stream_id = 0;
};

std::vector<DeviceDiagnosticEntry> g_device_diagnostics;
std::mutex g_device_diag_mutex;

void init_device_diagnostics() {
    std::lock_guard<std::mutex> lock(g_device_diag_mutex);
    if (!g_device_diagnostics.empty()) return;

    std::vector<std::string> user_ids = {
        "@alice:localhost", "@bob:localhost", "@charlie:localhost",
        "@dave:localhost", "@eve:localhost", "@frank:localhost",
        "@grace:localhost", "@heidi:localhost", "@ivan:localhost",
        "@judy:localhost", "@admin:localhost"
    };

    static const char* device_types[] = {"mobile", "web", "desktop", "unknown"};
    static const char* user_agents[] = {
        "Element/1.6.4 (Android 14; Pixel 8)", "Element/1.6.4 (iOS 17; iPhone 15)",
        "Element/1.11.50 (Linux; x86_64)", "Element/1.11.50 (Windows; x86_64)",
        "Element/1.11.50 (macOS; arm64)", "FluffyChat/1.12.0 (Android)",
        "Nheko/0.12.0 (Linux)", "Fractal/5.0 (Linux)"
    };

    static const char* display_names[] = {
        "Alice's Phone", "Alice's Desktop", "Bob's Laptop", "Bob's Tablet",
        "Charlie's iPhone", "Dave's Desktop", "Eve's Browser", "Frank's Android",
        "Grace's iPad", "Heidi's Laptop", "Ivan's Desktop", "Judy's Phone",
        "Admin Workstation", "Admin Mobile"
    };

    for (size_t i = 0; i < 50; ++i) {
        DeviceDiagnosticEntry dde;
        dde.user_id = user_ids[i % user_ids.size()];
        dde.device_id = "DEV" + gen_token(8);
        dde.display_name = display_names[i % 14];
        dde.device_type = device_types[i % 4];
        dde.last_seen_ip = "192.168.1." + std::to_string(1 + (i % 254));
        dde.last_seen_ts = std::to_string(now_ms() - (rand() % 86400000));
        dde.user_agent = user_agents[i % 8];
        dde.is_active = (rand() % 100) < 85;
        dde.one_time_keys_count = dde.is_active ? (rand() % 100) : 0;
        dde.has_fallback_key = (rand() % 100) < 80;
        dde.last_key_upload_ts = std::to_string(now_ms() - (rand() % 3600000));
        dde.device_lists_outbound_pokes = rand() % 10;
        dde.to_device_messages_pending = rand() % 5;
        dde.since_stream_id = 28400000 + (rand() % 100000);
        g_device_diagnostics.push_back(dde);
    }
}

// ---------------------------------------------------------------------------
// SECTION 11 HANDLERS – Device diagnostic
// ---------------------------------------------------------------------------

// GET /_synapse/admin/v1/devices/diagnostic
// Query: ?user_id=@alice:localhost&inactive=true&limit=100
HttpResponse handle_device_diagnostic(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_device_diagnostics();

    std::string filter_user = query_param(req, "user_id", "");
    bool show_inactive = query_param_bool(req, "inactive", false);
    std::string device_type_filter = query_param(req, "device_type", "");
    int limit = query_param_int(req, "limit", 100);
    if (limit > 500) limit = 500;

    std::lock_guard<std::mutex> lock(g_device_diag_mutex);

    json resp;
    resp["devices"] = json::array();

    int total_devices = 0;
    int active_devices = 0;
    int inactive_devices = 0;
    int devices_with_low_keys = 0;
    int devices_with_pending = 0;

    json device_list = json::array();

    for (const auto& dde : g_device_diagnostics) {
        if (!filter_user.empty() && dde.user_id != filter_user) continue;
        if (!device_type_filter.empty() && dde.device_type != device_type_filter) continue;
        if (!show_inactive && !dde.is_active) continue;

        json jd;
        jd["user_id"] = dde.user_id;
        jd["device_id"] = dde.device_id;
        jd["display_name"] = dde.display_name;
        jd["device_type"] = dde.device_type;
        jd["last_seen_ip"] = dde.last_seen_ip;
        jd["last_seen_ts"] = dde.last_seen_ts;
        jd["user_agent"] = dde.user_agent;
        jd["is_active"] = dde.is_active;
        jd["one_time_keys_count"] = dde.one_time_keys_count;
        jd["has_fallback_key"] = dde.has_fallback_key;
        jd["last_key_upload_ts"] = dde.last_key_upload_ts;
        jd["device_lists_outbound_pokes"] = dde.device_lists_outbound_pokes;
        jd["to_device_messages_pending"] = dde.to_device_messages_pending;
        jd["since_stream_id"] = dde.since_stream_id;

        device_list.push_back(jd);
        total_devices++;

        if (dde.is_active) active_devices++;
        else inactive_devices++;

        if (dde.one_time_keys_count < 10) devices_with_low_keys++;
        if (dde.to_device_messages_pending > 0) devices_with_pending++;

        if (static_cast<int>(device_list.size()) >= limit) break;
    }

    resp["devices"] = device_list;
    resp["total_matching"] = total_devices;
    resp["returned"] = static_cast<int>(device_list.size());
    resp["active_devices"] = active_devices;
    resp["inactive_devices"] = inactive_devices;
    resp["devices_with_low_otk"] = devices_with_low_keys;
    resp["devices_with_pending_messages"] = devices_with_pending;

    // Aggregate stats
    std::unordered_map<std::string, int> device_type_counts;
    for (const auto& dde : g_device_diagnostics) {
        device_type_counts[dde.device_type]++;
    }
    json dtc = json::object();
    for (const auto& [dt, count] : device_type_counts) {
        dtc[dt] = count;
    }
    resp["device_type_distribution"] = dtc;

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 12 – Session Diagnostic  (lines ~3200–3400)
// ============================================================================
// Comprehensive session diagnostic for all active sessions.
// ============================================================================

struct SessionDiagnosticEntry {
    std::string user_id;
    std::string session_id;
    std::string device_id;
    std::string access_token_hash;
    std::string ip_address;
    std::string user_agent;
    int64_t created_ts = 0;
    int64_t last_active_ts = 0;
    int64_t expires_ts = 0;
    bool valid_until_expiry = true;
    bool is_admin = false;
    int request_count = 0;
    int failed_auth_count = 0;
};

std::vector<SessionDiagnosticEntry> g_session_diagnostics;
std::mutex g_session_diag_mutex;

void init_session_diagnostics() {
    std::lock_guard<std::mutex> lock(g_session_diag_mutex);
    if (!g_session_diagnostics.empty()) return;

    std::vector<std::string> user_ids = {
        "@alice:localhost", "@bob:localhost", "@charlie:localhost",
        "@admin:localhost", "@dave:localhost", "@eve:localhost"
    };

    static const char* ips[] = {
        "192.168.1.100", "10.0.0.15", "172.16.0.50",
        "203.0.113.42", "198.51.100.7", "192.0.2.99"
    };

    static const char* agents[] = {
        "Element/1.6.4 Android", "Element Desktop/1.11.50",
        "FluffyChat/1.12.0", "Nheko/0.12.0", "Element iOS/1.6.4",
        "matrix-android-sdk2/1.5.0"
    };

    for (size_t i = 0; i < 30; ++i) {
        SessionDiagnosticEntry sde;
        sde.user_id = user_ids[i % user_ids.size()];
        sde.session_id = gen_token(32);
        sde.device_id = "DEV" + gen_token(6);
        sde.access_token_hash = "sha256:" + gen_token(43);
        sde.ip_address = ips[i % 6];
        sde.user_agent = agents[i % 6];
        sde.created_ts = now_sec() - (rand() % 2592000); // within last 30 days
        sde.last_active_ts = now_sec() - (rand() % 3600);
        sde.expires_ts = sde.created_ts + 86400 * 90; // 90 day expiry
        sde.valid_until_expiry = true;
        sde.is_admin = (sde.user_id == "@admin:localhost");
        sde.request_count = 100 + (rand() % 10000);
        sde.failed_auth_count = rand() % 5;
        g_session_diagnostics.push_back(sde);
    }
}

// ---------------------------------------------------------------------------
// SECTION 12 HANDLERS – Session diagnostic
// ---------------------------------------------------------------------------

// GET /_synapse/admin/v1/sessions/diagnostic
HttpResponse handle_session_diagnostic(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_session_diagnostics();

    std::string filter_user = query_param(req, "user_id", "");
    bool expired = query_param_bool(req, "show_expired", false);
    int limit = query_param_int(req, "limit", 100);

    std::lock_guard<std::mutex> lock(g_session_diag_mutex);

    json resp;
    resp["sessions"] = json::array();

    int total_sessions = 0;
    int active_sessions = 0;
    int expired_sessions = 0;
    int admin_sessions = 0;
    int64_t total_requests = 0;

    // Per-user session counts
    std::unordered_map<std::string, int> user_session_counts;

    json session_list = json::array();

    for (const auto& sde : g_session_diagnostics) {
        if (!filter_user.empty() && sde.user_id != filter_user) continue;

        bool is_expired = (now_sec() > sde.expires_ts);
        if (is_expired && !expired) continue;

        json js;
        js["user_id"] = sde.user_id;
        js["session_id"] = sde.session_id;
        js["device_id"] = sde.device_id;
        js["access_token_hash"] = sde.access_token_hash;
        js["ip_address"] = sde.ip_address;
        js["user_agent"] = sde.user_agent;
        js["created_at"] = sde.created_ts;
        js["last_active_at"] = sde.last_active_ts;
        js["expires_at"] = sde.expires_ts;
        js["is_expired"] = is_expired;
        js["seconds_until_expiry"] = sde.expires_ts - now_sec();
        js["is_admin"] = sde.is_admin;
        js["request_count"] = sde.request_count;
        js["failed_auth_count"] = sde.failed_auth_count;
        session_list.push_back(js);

        total_sessions++;
        if (is_expired) expired_sessions++;
        else active_sessions++;
        if (sde.is_admin) admin_sessions++;
        total_requests += sde.request_count;
        user_session_counts[sde.user_id]++;

        if (static_cast<int>(session_list.size()) >= limit) break;
    }

    resp["sessions"] = session_list;
    resp["total_matching"] = total_sessions;
    resp["returned"] = static_cast<int>(session_list.size());
    resp["active_sessions"] = active_sessions;
    resp["expired_sessions"] = expired_sessions;
    resp["admin_sessions"] = admin_sessions;
    resp["total_requests_served"] = total_requests;

    // Per-user session distribution
    json user_dist = json::object();
    for (const auto& [uid, count] : user_session_counts) {
        user_dist[uid] = count;
    }
    resp["sessions_per_user"] = user_dist;

    // Unique IPs
    std::set<std::string> unique_ips;
    for (const auto& sde : g_session_diagnostics) {
        unique_ips.insert(sde.ip_address);
    }
    resp["unique_ip_addresses"] = static_cast<int>(unique_ips.size());

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 13 – Federation Queue View  (lines ~3400–3600)
// ============================================================================
// View the federation transaction queue.
// ============================================================================

struct FederationQueueEntry {
    std::string transaction_id;
    std::string destination;
    std::string queue_name;      // "pdus", "edus", "devices", "presence", "key"
    int events_in_transaction = 0;
    int64_t queued_at_ms = 0;
    int64_t last_attempt_ms = 0;
    int retry_count = 0;
    int max_retries = 10;
    std::string status;          // "queued", "sending", "failed", "delivered"
    int64_t next_retry_at_ms = 0;
    std::string last_error;
    int64_t total_bytes = 0;
    int64_t age_ms = 0;
};

std::deque<FederationQueueEntry> g_federation_queue;
std::mutex g_fed_queue_mutex;

void init_federation_queue() {
    std::lock_guard<std::mutex> lock(g_fed_queue_mutex);
    if (!g_federation_queue.empty()) return;

    std::vector<std::string> destinations = {
        "matrix.org", "matrix-client.matrix.org", "t2bot.io",
        "feneas.org", "privacytools.io", "conduit.rs",
        "dendrite.matrix.org", "synapse.matrix.org", "envs.net",
        "chat.weho.st", "aria-net.org", "nordgedanken.dev"
    };

    static const char* queue_names[] = {"pdus", "edus", "devices", "presence", "key"};
    static const char* statuses[] = {"queued", "sending", "failed", "delivered"};

    for (int i = 0; i < 50; ++i) {
        FederationQueueEntry fqe;
        fqe.transaction_id = "txn" + std::to_string(now_ms()) + "-" + std::to_string(i);
        fqe.destination = destinations[i % destinations.size()];
        fqe.queue_name = queue_names[i % 5];
        fqe.events_in_transaction = 1 + (rand() % 50);
        fqe.queued_at_ms = now_ms() - (rand() % 600000);
        fqe.last_attempt_ms = fqe.queued_at_ms + (rand() % 30000);
        fqe.retry_count = rand() % 5;
        fqe.max_retries = 10;
        fqe.status = statuses[rand() % 4];
        fqe.next_retry_at_ms = fqe.last_attempt_ms + 60000 * (fqe.retry_count + 1);
        fqe.total_bytes = fqe.events_in_transaction * (500 + (rand() % 5000));
        fqe.age_ms = now_ms() - fqe.queued_at_ms;

        if (fqe.status == "failed" && fqe.retry_count > 3) {
            fqe.last_error = "Connection timeout after 30000ms to " + fqe.destination;
        }

        g_federation_queue.push_back(fqe);
    }

    // Sort by queued time descending
    std::sort(g_federation_queue.begin(), g_federation_queue.end(),
        [](const FederationQueueEntry& a, const FederationQueueEntry& b) {
            return a.queued_at_ms > b.queued_at_ms;
        });
}

// ---------------------------------------------------------------------------
// SECTION 13 HANDLERS – Federation queue
// ---------------------------------------------------------------------------

// GET /_synapse/admin/v1/federation/queue
// Query: ?destination=matrix.org&queue=pdus&status=failed
HttpResponse handle_federation_queue_view(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_federation_queue();

    std::string filter_dest = query_param(req, "destination", "");
    std::string filter_queue = query_param(req, "queue", "");
    std::string filter_status = query_param(req, "status", "");
    int limit = query_param_int(req, "limit", 50);
    int offset = query_param_int(req, "offset", 0);

    std::lock_guard<std::mutex> lock(g_fed_queue_mutex);

    json resp;
    resp["queue"] = json::array();

    int total = 0;
    int queued = 0;
    int sending = 0;
    int failed = 0;
    int delivered = 0;
    int64_t total_bytes_queued = 0;
    int64_t oldest_age_ms = 0;

    // Count by destination
    std::unordered_map<std::string, int> dest_counts;
    // Count by queue type
    std::unordered_map<std::string, int> queue_counts;

    json entries = json::array();
    int skipped = 0;

    for (const auto& fqe : g_federation_queue) {
        if (!filter_dest.empty() && fqe.destination != filter_dest) continue;
        if (!filter_queue.empty() && fqe.queue_name != filter_queue) continue;
        if (!filter_status.empty() && fqe.status != filter_status) continue;

        if (skipped < offset) { skipped++; continue; }

        total++;
        dest_counts[fqe.destination]++;
        queue_counts[fqe.queue_name]++;

        switch (fqe.status[0]) {
            case 'q': queued++; break;
            case 's': sending++; break;
            case 'f': failed++; break;
            case 'd': delivered++; break;
        }

        total_bytes_queued += fqe.total_bytes;
        if (fqe.age_ms > oldest_age_ms) oldest_age_ms = fqe.age_ms;

        if (static_cast<int>(entries.size()) < limit) {
            json je;
            je["transaction_id"] = fqe.transaction_id;
            je["destination"] = fqe.destination;
            je["queue"] = fqe.queue_name;
            je["events"] = fqe.events_in_transaction;
            je["queued_at_ms"] = fqe.queued_at_ms;
            je["last_attempt_ms"] = fqe.last_attempt_ms;
            je["retry_count"] = fqe.retry_count;
            je["max_retries"] = fqe.max_retries;
            je["status"] = fqe.status;
            je["next_retry_at_ms"] = fqe.next_retry_at_ms;
            je["age_ms"] = fqe.age_ms;
            je["total_bytes"] = fqe.total_bytes;
            if (!fqe.last_error.empty()) je["last_error"] = fqe.last_error;
            entries.push_back(je);
        }
    }

    resp["queue"] = entries;
    resp["returned"] = static_cast<int>(entries.size());
    resp["offset"] = offset;

    json summary;
    summary["total_matching"] = total;
    summary["queued"] = queued;
    summary["sending"] = sending;
    summary["failed"] = failed;
    summary["delivered"] = delivered;
    summary["total_bytes_queued"] = total_bytes_queued;
    summary["total_bytes_mb"] = std::round(total_bytes_queued / 10485.76) / 100.0;
    summary["oldest_entry_age_ms"] = oldest_age_ms;
    summary["oldest_entry_age_sec"] = oldest_age_ms / 1000;

    json by_dest = json::object();
    for (const auto& [dest, count] : dest_counts) by_dest[dest] = count;
    summary["by_destination"] = by_dest;

    json by_queue = json::object();
    for (const auto& [q, count] : queue_counts) by_queue[q] = count;
    summary["by_queue_type"] = by_queue;

    resp["summary"] = summary;

    // Health
    if (failed > 10) {
        resp["health"] = "degraded";
        resp["warning"] = "High number of failed federation transactions: " + std::to_string(failed);
    } else if (queued > 30) {
        resp["health"] = "warning";
        resp["warning"] = "Federation queue backlog: " + std::to_string(queued) + " items queued";
    } else {
        resp["health"] = "healthy";
    }

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 14 – Pusher Diagnostic  (lines ~3600–3750)
// ============================================================================
// Comprehensive pusher diagnostics.
// ============================================================================

struct PusherDiagnosticEntry {
    std::string pusher_id;
    std::string user_id;
    std::string app_id;
    std::string app_display_name;
    std::string device_display_name;
    std::string pushkey;
    std::string kind;          // "http", "email"
    std::string lang;
    bool enabled = true;
    int64_t created_ts = 0;
    int64_t last_success_ts = 0;
    int64_t last_failure_ts = 0;
    int failed_attempts = 0;
    int consecutive_failures = 0;
    int64_t pushes_sent = 0;
    int64_t pushes_failed = 0;
    double success_rate_percent = 100.0;
    bool is_throttled = false;
    int64_t throttle_until_ts = 0;
};

std::vector<PusherDiagnosticEntry> g_pusher_diagnostics;
std::mutex g_pusher_diag_mutex;

void init_pusher_diagnostics() {
    std::lock_guard<std::mutex> lock(g_pusher_diag_mutex);
    if (!g_pusher_diagnostics.empty()) return;

    for (int i = 0; i < 15; ++i) {
        PusherDiagnosticEntry pde;
        pde.pusher_id = "pusher_" + gen_token(8);
        pde.user_id = "@user" + std::to_string(i % 8) + ":localhost";
        pde.app_id = (i % 3 == 0) ? "org.matrix.matrix_client.Element.android" :
                     (i % 3 == 1) ? "org.matrix.matrix_client.Element.ios" :
                     "org.matrix.matrix_client.Element.linux";
        pde.app_display_name = (i % 3 == 0) ? "Element Android" :
                               (i % 3 == 1) ? "Element iOS" : "Element Desktop";
        pde.device_display_name = "Device " + std::to_string(i);
        pde.pushkey = gen_token(64);
        pde.kind = (i % 5 == 0) ? "email" : "http";
        pde.lang = "en";
        pde.enabled = (rand() % 100) < 90;
        pde.created_ts = now_sec() - 86400 * (30 + rand() % 180);
        pde.last_success_ts = pde.enabled ? now_sec() - (rand() % 3600) : 0;
        pde.failed_attempts = rand() % 20;
        pde.consecutive_failures = rand() % 5;
        pde.pushes_sent = 100 + (rand() % 5000);
        pde.pushes_failed = pde.failed_attempts;
        pde.success_rate_percent = pde.pushes_sent > 0 ?
            100.0 * (pde.pushes_sent - pde.pushes_failed) / pde.pushes_sent : 100.0;
        pde.is_throttled = (pde.consecutive_failures > 3);
        pde.throttle_until_ts = pde.is_throttled ? now_sec() + 600 : 0;

        if (pde.consecutive_failures > 3) {
            pde.last_failure_ts = now_sec() - 60;
        }

        g_pusher_diagnostics.push_back(pde);
    }
}

// ---------------------------------------------------------------------------
// SECTION 14 HANDLERS – Pusher diagnostic
// ---------------------------------------------------------------------------

// GET /_synapse/admin/v1/pushers/diagnostic
HttpResponse handle_pusher_diagnostic(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_pusher_diagnostics();

    std::string filter_user = query_param(req, "user_id", "");
    std::string filter_kind = query_param(req, "kind", "");
    bool throttled_only = query_param_bool(req, "throttled_only", false);

    std::lock_guard<std::mutex> lock(g_pusher_diag_mutex);

    json resp;
    resp["pushers"] = json::array();

    int total = 0;
    int enabled = 0;
    int disabled = 0;
    int throttled = 0;
    int http_pushers = 0;
    int email_pushers = 0;
    int64_t total_pushes_sent = 0;
    int64_t total_pushes_failed = 0;

    for (const auto& pde : g_pusher_diagnostics) {
        if (!filter_user.empty() && pde.user_id != filter_user) continue;
        if (!filter_kind.empty() && pde.kind != filter_kind) continue;
        if (throttled_only && !pde.is_throttled) continue;

        json jp;
        jp["pusher_id"] = pde.pusher_id;
        jp["user_id"] = pde.user_id;
        jp["app_id"] = pde.app_id;
        jp["app_display_name"] = pde.app_display_name;
        jp["device_display_name"] = pde.device_display_name;
        jp["kind"] = pde.kind;
        jp["lang"] = pde.lang;
        jp["enabled"] = pde.enabled;
        jp["created_ts"] = pde.created_ts;
        jp["last_success_ts"] = pde.last_success_ts;
        jp["last_failure_ts"] = pde.last_failure_ts;
        jp["failed_attempts"] = pde.failed_attempts;
        jp["consecutive_failures"] = pde.consecutive_failures;
        jp["pushes_sent"] = pde.pushes_sent;
        jp["pushes_failed"] = pde.pushes_failed;
        jp["success_rate_percent"] = std::round(pde.success_rate_percent * 100.0) / 100.0;
        jp["is_throttled"] = pde.is_throttled;
        if (pde.is_throttled) jp["throttle_until_ts"] = pde.throttle_until_ts;

        resp["pushers"].push_back(jp);

        total++;
        if (pde.enabled) enabled++; else disabled++;
        if (pde.is_throttled) throttled++;
        if (pde.kind == "http") http_pushers++;
        else if (pde.kind == "email") email_pushers++;
        total_pushes_sent += pde.pushes_sent;
        total_pushes_failed += pde.pushes_failed;
    }

    resp["total"] = total;
    resp["enabled"] = enabled;
    resp["disabled"] = disabled;
    resp["throttled"] = throttled;
    resp["http_pushers"] = http_pushers;
    resp["email_pushers"] = email_pushers;
    resp["total_pushes_sent"] = total_pushes_sent;
    resp["total_pushes_failed"] = total_pushes_failed;
    resp["overall_success_rate"] = total_pushes_sent > 0 ?
        std::round(10000.0 * (total_pushes_sent - total_pushes_failed) / total_pushes_sent) / 100.0 : 100.0;
    resp["health"] = throttled > 3 ? "degraded" : "healthy";

    if (throttled > 0) {
        resp["warning"] = std::to_string(throttled) + " pusher(s) are currently throttled due to delivery failures.";
    }

    return HttpResponse::ok(resp);
}

// ---------------------------------------------------------------------------
// SECTION 15 – Background Update View  (lines ~3750–3950)
// ============================================================================
// View and manage background database updates.
// ============================================================================

struct BackgroundUpdateInfo {
    std::string update_name;
    std::string description;
    std::string depends_on;
    bool enabled = true;
    bool running = false;
    int64_t progress_total = 0;
    int64_t progress_complete = 0;
    double progress_percent = 0.0;
    int64_t started_ts = 0;
    int64_t completed_ts = 0;
    double duration_seconds = 0.0;
    std::string error_msg;
    int retry_count = 0;
    int64_t estimated_remaining_ms = 0;
    std::string table_affected;
    int batch_size = 100;
};

std::vector<BackgroundUpdateInfo> g_background_updates;
std::mutex g_bg_update_diag_mutex;

void init_background_updates_view() {
    std::lock_guard<std::mutex> lock(g_bg_update_diag_mutex);
    if (!g_background_updates.empty()) return;

    // Simulated background updates matching Synapse's real set
    std::vector<std::pair<std::string, std::string>> updates = {
        {"event_push_actions_stream_ordering_index", "Add index to event_push_actions stream_ordering"},
        {"event_push_summary_unique_index", "Add unique index to event_push_summary"},
        {"event_search_event_id_idx", "Add index on event_search event_id"},
        {"state_group_edges_unique_idx", "Add unique index on state_group_edges"},
        {"event_relations_reference_idx", "Add index for event_relations references"},
        {"populate_stats_process_rooms", "Populate room statistics"},
        {"populate_stats_process_users", "Populate user statistics"},
        {"populate_user_directory_createtables", "Create user_directory tables"},
        {"populate_user_directory_process_users", "Populate user directory"},
        {"populate_user_directory_process_rooms", "Process rooms for user directory"},
        {"delete_old_current_state_events", "Clean up old current_state_events"},
        {"cleanup_extremities_without_metadata", "Clean up extremities records"},
        {"remove_deactivated_users_from_user_directory", "Remove deactivated users"},
        {"remove_media_from_unknown_rooms", "Purge orphaned media"},
        {"device_lists_outbound_last_success_id_idx", "Add index on device_lists_outbound"},
        {"receipts_graph_force_index", "Force index on receipts_graph"},
        {"redactions_received_ts_index", "Add index on redactions received_ts"},
        {"rooms_creator_index", "Add index on rooms creator"},
        {"db_update_validate_membership", "Validate room membership integrity"},
    };

    for (const auto& [name, desc] : updates) {
        BackgroundUpdateInfo bui;
        bui.update_name = name;
        bui.description = desc;
        bui.depends_on = "";
        bui.enabled = true;
        bui.running = (rand() % 100) < 20; // 20% chance of running
        bui.progress_total = 10000 + (rand() % 100000);
        bui.progress_complete = bui.running ? (bui.progress_total * (20 + rand() % 80) / 100) : 0;
        bui.progress_percent = bui.progress_total > 0 ?
            std::round(10000.0 * bui.progress_complete / bui.progress_total) / 100.0 : 0.0;
        bui.started_ts = bui.running ? now_sec() - (rand() % 7200) : 0;
        bui.completed_ts = (!bui.running && rand() % 2 == 0) ? now_sec() - rand() % 86400 : 0;
        bui.duration_seconds = bui.completed_ts > 0 ? (bui.completed_ts - bui.started_ts) : 0.0;
        bui.retry_count = rand() % 3;
        bui.estimated_remaining_ms = bui.running ?
            (int64_t)((bui.progress_total - bui.progress_complete) * 50) : 0;
        bui.table_affected = "events";
        bui.batch_size = 100;
        g_background_updates.push_back(bui);
    }
}

// ---------------------------------------------------------------------------
// SECTION 15 HANDLERS – Background update view
// ---------------------------------------------------------------------------

// GET /_synapse/admin/v1/background_updates/view
HttpResponse handle_background_update_view(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    init_background_updates_view();

    std::string filter_status = query_param(req, "status", ""); // "running", "completed", "pending"

    std::lock_guard<std::mutex> lock(g_bg_update_diag_mutex);

    json resp;
    resp["background_updates"] = json::array();

    int total = 0;
    int running = 0;
    int completed = 0;
    int pending = 0;
    int failed = 0;
    int64_t total_progress_total = 0;
    int64_t total_progress_complete = 0;

    for (const auto& bui : g_background_updates) {
        std::string status;
        if (bui.running) status = "running";
        else if (bui.progress_complete >= bui.progress_total && bui.progress_total > 0) status = "completed";
        else if (!bui.error_msg.empty()) status = "failed";
        else status = "pending";

        if (!filter_status.empty() && status != filter_status) continue;

        json jb;
        jb["update_name"] = bui.update_name;
        jb["description"] = bui.description;
        jb["status"] = status;
        jb["progress_total"] = bui.progress_total;
        jb["progress_complete"] = bui.progress_complete;
        jb["progress_percent"] = bui.progress_percent;
        jb["started_ts"] = bui.started_ts;
        jb["completed_ts"] = bui.completed_ts;
        jb["duration_seconds"] = bui.duration_seconds;
        jb["estimated_remaining_ms"] = bui.estimated_remaining_ms;
        jb["table_affected"] = bui.table_affected;
        jb["batch_size"] = bui.batch_size;
        jb["retry_count"] = bui.retry_count;
        if (!bui.error_msg.empty()) jb["error"] = bui.error_msg;
        if (!bui.depends_on.empty()) jb["depends_on"] = bui.depends_on;

        resp["background_updates"].push_back(jb);

        total++;
        if (status == "running") running++;
        else if (status == "completed") completed++;
        else if (status == "failed") failed++;
        else pending++;

        total_progress_total += bui.progress_total;
        total_progress_complete += bui.progress_complete;
    }

    resp["total"] = total;
    resp["running"] = running;
    resp["completed"] = completed;
    resp["pending"] = pending;
    resp["failed"] = failed;
    resp["overall_progress_percent"] = total_progress_total > 0 ?
        std::round(10000.0 * total_progress_complete / total_progress_total) / 100.0 : 0.0;

    return HttpResponse::ok(resp);
}

// ============================================================================
// Route registration – returns vector of RouteEntry for unified routing
// ============================================================================

std::vector<RouteEntry> get_server_operations_routes() {
    init_server_config();
    init_lifecycle_state();
    init_workers();
    init_cache_eviction_stats();
    init_db_tables();
    init_event_stream_diagnostics();
    init_forward_extremities();
    init_state_groups();
    init_room_state_diagnostics();
    init_device_diagnostics();
    init_session_diagnostics();
    init_federation_queue();
    init_pusher_diagnostics();
    init_background_updates_view();

    return {
        // Server config
        {"GET",    "/_synapse/admin/v1/config",                               handle_server_config},

        // Server lifecycle
        {"POST",   "/_synapse/admin/v1/server/restart",                       handle_server_restart},
        {"POST",   "/_synapse/admin/v1/server/shutdown",                      handle_server_shutdown},
        {"GET",    "/_synapse/admin/v1/server/status",                        handle_server_status},
        {"POST",   "/_synapse/admin/v1/server/worker/{workerName}/restart",   handle_worker_restart},

        // Cache management
        {"POST",   "/_synapse/admin/v1/caches/flush",                         handle_flush_caches},
        {"GET",    "/_synapse/admin/v1/caches/eviction_stats",                handle_cache_eviction_stats},

        // TLS management
        {"POST",   "/_synapse/admin/v1/server/reload_tls",                    handle_reload_tls_certs},
        {"GET",    "/_synapse/admin/v1/server/tls_info",                      handle_tls_info},

        // Signing key rotation
        {"POST",   "/_synapse/admin/v1/server/rotate_signing_keys",           handle_rotate_signing_keys},
        {"GET",    "/_synapse/admin/v1/server/signing_keys",                  handle_get_signing_keys},

        // Database maintenance
        {"POST",   "/_synapse/admin/v1/database/integrity_check",             handle_db_integrity_check},
        {"POST",   "/_synapse/admin/v1/database/vacuum",                      handle_db_vacuum},
        {"POST",   "/_synapse/admin/v1/database/reindex",                     handle_db_reindex},
        {"GET",    "/_synapse/admin/v1/database/table_stats",                 handle_db_table_stats},

        // Event stream diagnostics
        {"GET",    "/_synapse/admin/v1/event_stream/diagnostics",             handle_event_stream_diagnostics},

        // Forward extremities
        {"GET",    "/_synapse/admin/v1/rooms/{roomId}/forward_extremities",   handle_forward_extremity_view},
        {"GET",    "/_synapse/admin/v1/forward_extremities",                  handle_all_forward_extremities},

        // State groups
        {"GET",    "/_synapse/admin/v1/rooms/{roomId}/state_groups",          handle_state_group_view},

        // Room state diagnostic
        {"GET",    "/_synapse/admin/v1/rooms/{roomId}/state_diagnostic",      handle_room_state_diagnostic},
        {"GET",    "/_synapse/admin/v1/rooms/diagnostics",                    handle_all_room_diagnostics},

        // Device diagnostic
        {"GET",    "/_synapse/admin/v1/devices/diagnostic",                   handle_device_diagnostic},

        // Session diagnostic
        {"GET",    "/_synapse/admin/v1/sessions/diagnostic",                  handle_session_diagnostic},

        // Federation queue
        {"GET",    "/_synapse/admin/v1/federation/queue",                     handle_federation_queue_view},

        // Pusher diagnostic
        {"GET",    "/_synapse/admin/v1/pushers/diagnostic",                   handle_pusher_diagnostic},

        // Background updates
        {"GET",    "/_synapse/admin/v1/background_updates/view",              handle_background_update_view},
    };
}

} // anonymous namespace

} // namespace admin
} // namespace progressive
