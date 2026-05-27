// ============================================================================
// sso_login_flow.cpp — Matrix SSO Login Flow: OAuth2, PKCE, Multi-Provider
//
// Implements:
//   1.  SSO login redirect — generate authorization URLs for IdPs
//   2.  SSO callback handling — process authorization code/callback from IdP
//   3.  SSO registration on first login — auto-register new users via SSO
//   4.  SSO account linking to existing account — bind SSO identity to Matrix user
//   5.  OAuth2 authorization code flow with PKCE — secure code exchange
//   6.  OAuth2 token refresh — refresh expired access tokens
//   7.  OAuth2 userinfo mapping to Matrix profile — map claims to profile fields
//   8.  Multiple OAuth2 providers — Google, GitHub, GitLab, Facebook, Apple,
//     Microsoft, and custom providers
//   9.  Provider discovery via OIDC — auto-discover endpoints from issuer
//  10.  Provider configuration admin API — CRUD for SSO provider configs
//  11.  SSO session state — track login sessions with expiry
//  12.  SSO error handling — comprehensive error classification and recovery
//  13.  SSO login branding per provider — customize UI per IdP
//
// Equivalent to:
//   synapse/handlers/oidc.py              — OIDC handler (1400+ lines)
//   synapse/handlers/sso_handler.py       — SSO orchestrator (600+ lines)
//   synapse/rest/client/login.py          — Login REST (SSO parts)
//   synapse/rest/client/register.py       — Registration REST (SSO parts)
//   synapse/handlers/oauth2_provider.py   — OAuth2 provider integration
//
// Namespace: progressive::sso
// Target: 3500+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <forward_list>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <list>
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
#include <system_error>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "../json.hpp"

// ============================================================================
// Namespace: progressive::sso
// ============================================================================

namespace progressive::sso {
using json = nlohmann::json;

// ============================================================================
// Forward Declarations — Utility Functions
// ============================================================================

static std::string url_encode(const std::string& value);
static std::string url_decode(const std::string& value);
static std::string base64url_encode(const std::string& data);
static std::string base64url_decode(const std::string& data);
static std::string sha256_hex(const std::string& data);
static std::string hmac_sha256(const std::string& key, const std::string& data);
static std::string generate_uuid();
static std::string generate_state_token();
static std::string generate_pkce_verifier();
static std::string generate_pkce_challenge(const std::string& verifier);
static std::string generate_nonce_token();
static std::string generate_session_id();
static std::string generate_login_token();
static int64_t now_seconds();
static int64_t now_millis();
static std::string random_hex_string(size_t length);
static bool is_valid_redirect_uri(const std::string& uri,
                                  const std::vector<std::string>& allowed);
static std::string join_strings(const std::vector<std::string>& vec,
                                 const std::string& separator);
static std::string template_replace(const std::string& tmpl,
                                     const json& context);

// ============================================================================
// Constants
// ============================================================================

namespace constants {

// Session lifetimes
constexpr int64_t SSO_SESSION_LIFETIME_SECS = 900;     // 15 minutes
constexpr int64_t STATE_TOKEN_LIFETIME_SECS = 600;     // 10 minutes
constexpr int64_t LOGIN_TOKEN_LIFETIME_SECS = 120;     // 2 minutes
constexpr int64_t CALLBACK_TIMEOUT_SECS = 300;          // 5 minutes
constexpr int64_t PROVIDER_DISCOVERY_CACHE_SECS = 3600; // 1 hour
constexpr int64_t JWKS_CACHE_SECS = 86400;              // 24 hours
constexpr int64_t TOKEN_REFRESH_WINDOW_SECS = 300;      // 5 minutes before expiry

// OAuth2 / OIDC
constexpr int    PKCE_VERIFIER_LENGTH = 64;
constexpr int    PKCE_CHALLENGE_LENGTH = 43;
constexpr int    STATE_LENGTH = 32;
constexpr int    NONCE_LENGTH = 24;
constexpr int    SESSION_ID_LENGTH = 32;
constexpr int    LOGIN_TOKEN_LENGTH = 48;

// Well-known paths
constexpr const char* OIDC_DISCOVERY_PATH = "/.well-known/openid-configuration";
constexpr const char* OAUTH2_WELL_KNOWN_PATH = "/.well-known/oauth-authorization-server";

// Provider IDs
constexpr const char* PROVIDER_GOOGLE    = "google";
constexpr const char* PROVIDER_GITHUB    = "github";
constexpr const char* PROVIDER_GITLAB    = "gitlab";
constexpr const char* PROVIDER_FACEBOOK  = "facebook";
constexpr const char* PROVIDER_APPLE     = "apple";
constexpr const char* PROVIDER_MICROSOFT = "microsoft";
constexpr const char* PROVIDER_CUSTOM    = "custom";

// Default scopes
constexpr const char* GOOGLE_SCOPES    = "openid profile email";
constexpr const char* GITHUB_SCOPES    = "user:email read:user";
constexpr const char* GITLAB_SCOPES    = "read_user openid profile email";
constexpr const char* FACEBOOK_SCOPES  = "email public_profile";
constexpr const char* APPLE_SCOPES     = "name email";
constexpr const char* MICROSOFT_SCOPES = "openid profile email User.Read";

// Grant types
constexpr const char* GRANT_AUTHORIZATION_CODE = "authorization_code";
constexpr const char* GRANT_REFRESH_TOKEN      = "refresh_token";

// Token types
constexpr const char* TOKEN_TYPE_BEARER = "Bearer";

// Error codes
constexpr const char* ERR_INVALID_REQUEST    = "invalid_request";
constexpr const char* ERR_INVALID_GRANT      = "invalid_grant";
constexpr const char* ERR_INVALID_CLIENT     = "invalid_client";
constexpr const char* ERR_INVALID_SCOPE      = "invalid_scope";
constexpr const char* ERR_UNAUTHORIZED_CLIENT= "unauthorized_client";
constexpr const char* ERR_ACCESS_DENIED      = "access_denied";
constexpr const char* ERR_SERVER_ERROR       = "server_error";
constexpr const char* ERR_TEMPORARILY_UNAVAIL= "temporarily_unavailable";
constexpr const char* ERR_PROVIDER_NOT_FOUND = "provider_not_found";
constexpr const char* ERR_SESSION_EXPIRED    = "session_expired";
constexpr const char* ERR_STATE_MISMATCH     = "state_mismatch";
constexpr const char* ERR_NO_EMAIL           = "no_email_provided";
constexpr const char* ERR_USER_EXISTS         = "user_already_exists";
constexpr const char* ERR_LINK_FAILED         = "account_link_failed";
constexpr const char* ERR_PROVIDER_DISABLED   = "provider_disabled";
constexpr const char* ERR_PKCE_REQUIRED      = "pkce_verification_required";

// Matrix login types
constexpr const char* LOGIN_TYPE_SSO = "m.login.sso";
constexpr const char* LOGIN_TYPE_TOKEN = "m.login.token";

} // namespace constants

// ============================================================================
// Enumerations
// ============================================================================

enum class SsoProviderKind {
    OIDC,
    OAUTH2,
    GOOGLE,
    GITHUB,
    GITLAB,
    FACEBOOK,
    APPLE,
    MICROSOFT,
    CUSTOM,
    UNKNOWN
};

enum class SsoSessionStatus {
    INITIALIZED,       // Session created, no redirect yet
    REDIRECTING,       // User redirected to IdP
    AWAITING_CALLBACK, // Waiting for IdP callback
    CALLBACK_RECEIVED, // Callback received, processing
    AUTHENTICATED,     // User authenticated by IdP
    REGISTERING,       // Creating new Matrix account
    LINKING,            // Linking to existing account
    COMPLETED,         // Login flow completed
    FAILED,            // Flow failed
    EXPIRED,           // Session timed out
    CANCELLED          // User cancelled
};

enum class AccountLinkDecision {
    CREATE_NEW_ACCOUNT,   // Register as new user
    LINK_EXISTING,         // Link to existing Matrix account
    REJECT,               // Reject SSO login
    PENDING_USER_INPUT     // Awaiting user decision
};

enum class OAuth2TokenAuthMethod {
    CLIENT_SECRET_BASIC,  // HTTP Basic with client_id:client_secret
    CLIENT_SECRET_POST,   // client_id + client_secret in POST body
    PRIVATE_KEY_JWT,      // JWT signed with private key
    NONE                  // Public client (no secret)
};

enum class PkceMethod {
    S256,  // SHA-256 challenge
    PLAIN  // Plain text challenge (not recommended)
};

enum class ProviderBrandingStyle {
    DEFAULT,
    GOOGLE_STYLE,
    GITHUB_STYLE,
    GITLAB_STYLE,
    FACEBOOK_STYLE,
    APPLE_STYLE,
    MICROSOFT_STYLE,
    CUSTOM_STYLE
};

enum class SsoErrorCategory {
    NONE,
    PROVIDER_ERROR,       // Error from the IdP
    NETWORK_ERROR,        // HTTP/connection error
    CONFIG_ERROR,         // Misconfiguration
    VALIDATION_ERROR,     // Token/state validation failed
    USER_ERROR,           // User action needed
    INTERNAL_ERROR        // Server bug
};

// ============================================================================
// Core Data Structures
// ============================================================================

// PKCE parameters for OAuth2 authorization code flow
struct PkceParams {
    std::string code_verifier;
    std::string code_challenge;
    std::string code_challenge_method = "S256";

    void generate() {
        code_verifier = generate_pkce_verifier();
        code_challenge = generate_pkce_challenge(code_verifier);
    }

    bool empty() const { return code_verifier.empty(); }

    json to_json() const {
        return json{{"code_verifier", code_verifier},
                     {"code_challenge", code_challenge},
                     {"code_challenge_method", code_challenge_method}};
    }

    static PkceParams from_json(const json& j) {
        PkceParams p;
        if (j.contains("code_verifier"))
            p.code_verifier = j["code_verifier"].get<std::string>();
        if (j.contains("code_challenge"))
            p.code_challenge = j["code_challenge"].get<std::string>();
        if (j.contains("code_challenge_method"))
            p.code_challenge_method = j["code_challenge_method"].get<std::string>();
        return p;
    }
};

// OAuth2 token response
struct OAuth2TokenResponse {
    std::string access_token;
    std::string token_type = "Bearer";
    std::string refresh_token;
    std::string id_token;
    std::string scope;
    int64_t     expires_in = 3600;
    int64_t     obtained_at = 0;
    bool        success = false;
    std::string error;
    std::string error_description;
    std::string error_uri;
    json        raw_response;

    bool has_refresh_token() const { return !refresh_token.empty(); }
    bool is_expired() const {
        if (obtained_at == 0 || expires_in == 0) return false;
        return (now_seconds() - obtained_at) >= expires_in;
    }
    bool needs_refresh() const {
        if (obtained_at == 0 || expires_in == 0) return false;
        return (now_seconds() - obtained_at) >=
               (expires_in - constants::TOKEN_REFRESH_WINDOW_SECS);
    }

    json to_json() const {
        return json{{"access_token", access_token},
                     {"token_type", token_type},
                     {"refresh_token", refresh_token},
                     {"id_token", id_token},
                     {"scope", scope},
                     {"expires_in", expires_in},
                     {"obtained_at", obtained_at},
                     {"success", success}};
    }

    static OAuth2TokenResponse from_json(const json& j) {
        OAuth2TokenResponse t;
        if (j.contains("access_token"))
            t.access_token = j["access_token"].get<std::string>();
        if (j.contains("token_type"))
            t.token_type = j["token_type"].get<std::string>();
        if (j.contains("refresh_token"))
            t.refresh_token = j["refresh_token"].get<std::string>();
        if (j.contains("id_token"))
            t.id_token = j["id_token"].get<std::string>();
        if (j.contains("scope"))
            t.scope = j["scope"].get<std::string>();
        if (j.contains("expires_in"))
            t.expires_in = j["expires_in"].get<int64_t>();
        if (j.contains("obtained_at"))
            t.obtained_at = j["obtained_at"].get<int64_t>();
        if (j.contains("success"))
            t.success = j["success"].get<bool>();
        t.raw_response = j;
        return t;
    }
};

// Per-provider branding configuration
struct ProviderBranding {
    std::string idp_name;               // Display name: "Google", "GitHub", etc.
    std::string idp_icon_url;           // URL to provider icon
    std::string idp_icon_mxc;           // MXC URI for icon (if uploaded)
    std::string brand_color_primary;    // Hex color: "#4285F4"
    std::string brand_color_secondary;  // Hex color: "#34A853"
    std::string button_text;            // "Sign in with Google"
    std::string button_css_class;       // CSS class for the button
    std::string login_page_title;       // "Sign in with your Google account"
    std::string login_page_subtitle;    // "Choose a Google account to continue"
    std::string help_text;              // "Your Google account must be verified"
    std::string privacy_policy_url;     // Link to privacy policy
    std::string terms_of_service_url;   // Link to ToS
    std::string logo_svg;               // Inline SVG logo
    bool        show_on_login_page = true;
    int         sort_order = 0;         // Display order on picker
    ProviderBrandingStyle style = ProviderBrandingStyle::DEFAULT;

    json to_json() const {
        return json{{"idp_name", idp_name},
                     {"idp_icon_url", idp_icon_url},
                     {"idp_icon_mxc", idp_icon_mxc},
                     {"brand_color_primary", brand_color_primary},
                     {"brand_color_secondary", brand_color_secondary},
                     {"button_text", button_text},
                     {"button_css_class", button_css_class},
                     {"login_page_title", login_page_title},
                     {"login_page_subtitle", login_page_subtitle},
                     {"help_text", help_text},
                     {"privacy_policy_url", privacy_policy_url},
                     {"terms_of_service_url", terms_of_service_url},
                     {"show_on_login_page", show_on_login_page},
                     {"sort_order", sort_order}};
    }

    static ProviderBranding from_json(const json& j) {
        ProviderBranding b;
        if (j.contains("idp_name")) b.idp_name = j["idp_name"].get<std::string>();
        if (j.contains("idp_icon_url")) b.idp_icon_url = j["idp_icon_url"].get<std::string>();
        if (j.contains("idp_icon_mxc")) b.idp_icon_mxc = j["idp_icon_mxc"].get<std::string>();
        if (j.contains("brand_color_primary")) b.brand_color_primary = j["brand_color_primary"].get<std::string>();
        if (j.contains("brand_color_secondary")) b.brand_color_secondary = j["brand_color_secondary"].get<std::string>();
        if (j.contains("button_text")) b.button_text = j["button_text"].get<std::string>();
        if (j.contains("login_page_title")) b.login_page_title = j["login_page_title"].get<std::string>();
        if (j.contains("login_page_subtitle")) b.login_page_subtitle = j["login_page_subtitle"].get<std::string>();
        if (j.contains("help_text")) b.help_text = j["help_text"].get<std::string>();
        if (j.contains("privacy_policy_url")) b.privacy_policy_url = j["privacy_policy_url"].get<std::string>();
        if (j.contains("terms_of_service_url")) b.terms_of_service_url = j["terms_of_service_url"].get<std::string>();
        if (j.contains("logo_svg")) b.logo_svg = j["logo_svg"].get<std::string>();
        if (j.contains("show_on_login_page")) b.show_on_login_page = j["show_on_login_page"].get<bool>();
        if (j.contains("sort_order")) b.sort_order = j["sort_order"].get<int>();
        return b;
    }
};

// OAuth2 / OIDC provider configuration
struct OAuth2ProviderConfig {
    std::string             provider_id;             // Unique identifier
    std::string             display_name;            // Human-readable name
    SsoProviderKind         kind = SsoProviderKind::CUSTOM;
    bool                    enabled = true;

    // OAuth2 endpoints
    std::string             issuer;                  // OIDC issuer URL
    std::string             authorization_endpoint;
    std::string             token_endpoint;
    std::string             userinfo_endpoint;
    std::string             revocation_endpoint;
    std::string             end_session_endpoint;
    std::string             jwks_uri;
    std::string             discovery_url;           // OIDC .well-known URL

    // Client credentials
    std::string             client_id;
    std::string             client_secret;
    OAuth2TokenAuthMethod   token_endpoint_auth_method =
                            OAuth2TokenAuthMethod::CLIENT_SECRET_POST;

    // Redirect handling
    std::string             redirect_base_url;       // Our callback base URL
    std::vector<std::string> allowed_redirect_uris;
    std::string             post_logout_redirect_uri;

    // Scopes
    std::vector<std::string> scopes = {"openid", "profile", "email"};

    // PKCE
    bool                    require_pkce = true;
    PkceMethod              pkce_method = PkceMethod::S256;

    // Token handling
    int64_t                 token_refresh_window_secs =
                            constants::TOKEN_REFRESH_WINDOW_SECS;
    bool                    include_id_token_in_userinfo = false;

    // Validation
    bool                    verify_ssl = true;
    bool                    verify_issuer = true;
    bool                    verify_host = true;
    bool                    validate_iat = true;
    bool                    validate_exp = true;
    bool                    validate_sub = true;
    int64_t                 clock_skew_seconds = 5;

    // Attribute mapping
    json                    attribute_mapping;         // OIDC claim -> Matrix profile
    json                    userinfo_claims;           // Claims to extract

    // Registration
    std::string             localpart_template;        // "{{ user.preferred_username }}"
    std::string             display_name_template;     // "{{ user.name }}"
    std::string             email_template;            // "{{ user.email }}"
    std::string             avatar_url_template;
    bool                    confirm_localpart = true;  // Ask user to confirm

    // Branding
    ProviderBranding        branding;

    // Discovery cache
    int64_t                 discovery_last_fetched = 0;
    json                    discovered_config;

    // Backchannel logout
    bool                    backchannel_logout_enabled = false;
    std::string             backchannel_logout_uri;

    // Additional parameters
    json                    extra_authorization_params;
    json                    extra_token_params;
    json                    extra_userinfo_params;

    // Rate limiting
    int                     max_login_attempts_per_minute = 10;

    // --- Validation ---
    bool has_discovery_endpoint() const {
        return !discovery_url.empty() || !issuer.empty();
    }

    std::string effective_discovery_url() const {
        if (!discovery_url.empty()) return discovery_url;
        if (!issuer.empty()) {
            std::string iss = issuer;
            while (!iss.empty() && iss.back() == '/') iss.pop_back();
            return iss + constants::OIDC_DISCOVERY_PATH;
        }
        return "";
    }

    bool is_oidc() const {
        return kind == SsoProviderKind::OIDC ||
               kind == SsoProviderKind::GOOGLE ||
               kind == SsoProviderKind::MICROSOFT ||
               kind == SsoProviderKind::APPLE;
    }

    std::vector<std::string> scope_list() const { return scopes; }

    std::string scope_string() const {
        return join_strings(scopes, " ");
    }

    json to_json() const {
        return json{
            {"provider_id", provider_id},
            {"display_name", display_name},
            {"kind", static_cast<int>(kind)},
            {"enabled", enabled},
            {"issuer", issuer},
            {"authorization_endpoint", authorization_endpoint},
            {"token_endpoint", token_endpoint},
            {"userinfo_endpoint", userinfo_endpoint},
            {"revocation_endpoint", revocation_endpoint},
            {"end_session_endpoint", end_session_endpoint},
            {"jwks_uri", jwks_uri},
            {"discovery_url", discovery_url},
            {"client_id", client_id},
            {"redirect_base_url", redirect_base_url},
            {"scopes", scopes},
            {"require_pkce", require_pkce},
            {"verify_ssl", verify_ssl},
            {"verify_issuer", verify_issuer},
            {"attribute_mapping", attribute_mapping},
            {"localpart_template", localpart_template},
            {"display_name_template", display_name_template},
            {"email_template", email_template},
            {"confirm_localpart", confirm_localpart},
            {"branding", branding.to_json()},
            {"backchannel_logout_enabled", backchannel_logout_enabled},
        };
    }

    static OAuth2ProviderConfig from_json(const json& j) {
        OAuth2ProviderConfig cfg;
        if (j.contains("provider_id")) cfg.provider_id = j["provider_id"].get<std::string>();
        if (j.contains("display_name")) cfg.display_name = j["display_name"].get<std::string>();
        if (j.contains("enabled")) cfg.enabled = j["enabled"].get<bool>();
        if (j.contains("issuer")) cfg.issuer = j["issuer"].get<std::string>();
        if (j.contains("authorization_endpoint")) cfg.authorization_endpoint = j["authorization_endpoint"].get<std::string>();
        if (j.contains("token_endpoint")) cfg.token_endpoint = j["token_endpoint"].get<std::string>();
        if (j.contains("userinfo_endpoint")) cfg.userinfo_endpoint = j["userinfo_endpoint"].get<std::string>();
        if (j.contains("revocation_endpoint")) cfg.revocation_endpoint = j["revocation_endpoint"].get<std::string>();
        if (j.contains("end_session_endpoint")) cfg.end_session_endpoint = j["end_session_endpoint"].get<std::string>();
        if (j.contains("jwks_uri")) cfg.jwks_uri = j["jwks_uri"].get<std::string>();
        if (j.contains("discovery_url")) cfg.discovery_url = j["discovery_url"].get<std::string>();
        if (j.contains("client_id")) cfg.client_id = j["client_id"].get<std::string>();
        if (j.contains("client_secret")) cfg.client_secret = j["client_secret"].get<std::string>();
        if (j.contains("redirect_base_url")) cfg.redirect_base_url = j["redirect_base_url"].get<std::string>();
        if (j.contains("scopes") && j["scopes"].is_array()) {
            cfg.scopes = j["scopes"].get<std::vector<std::string>>();
        }
        if (j.contains("require_pkce")) cfg.require_pkce = j["require_pkce"].get<bool>();
        if (j.contains("verify_ssl")) cfg.verify_ssl = j["verify_ssl"].get<bool>();
        if (j.contains("verify_issuer")) cfg.verify_issuer = j["verify_issuer"].get<bool>();
        if (j.contains("attribute_mapping")) cfg.attribute_mapping = j["attribute_mapping"];
        if (j.contains("localpart_template")) cfg.localpart_template = j["localpart_template"].get<std::string>();
        if (j.contains("display_name_template")) cfg.display_name_template = j["display_name_template"].get<std::string>();
        if (j.contains("email_template")) cfg.email_template = j["email_template"].get<std::string>();
        if (j.contains("confirm_localpart")) cfg.confirm_localpart = j["confirm_localpart"].get<bool>();
        if (j.contains("branding")) cfg.branding = ProviderBranding::from_json(j["branding"]);
        if (j.contains("backchannel_logout_enabled")) cfg.backchannel_logout_enabled = j["backchannel_logout_enabled"].get<bool>();
        return cfg;
    }
};

// SSO login session — tracks a single SSO login flow
struct SsoLoginSession {
    std::string             session_id;
    std::string             provider_id;
    std::string             client_redirect_uri;   // Where to send user on success
    SsoSessionStatus        status = SsoSessionStatus::INITIALIZED;

    // OAuth2/PKCE state
    std::string             oauth_state;
    std::string             oauth_nonce;
    PkceParams              pkce_params;
    std::string             authorization_code;

    // Tokens
    OAuth2TokenResponse     token_response;

    // User information from IdP
    std::string             idp_subject;           // OIDC 'sub' claim
    std::string             idp_email;
    std::string             idp_email_verified;
    std::string             idp_name;
    std::string             idp_picture;
    std::string             idp_locale;
    std::string             idp_username;
    json                    idp_raw_userinfo;       // Full response from userinfo
    json                    idp_raw_claims;          // Full ID token claims

    // Mapped Matrix user
    std::string             mapped_localpart;
    std::string             mapped_user_id;
    std::string             mapped_display_name;
    std::string             mapped_avatar_url;
    std::string             mapped_email;

    // Account linking
    std::string             existing_user_id;      // User to link to
    AccountLinkDecision     link_decision = AccountLinkDecision::CREATE_NEW_ACCOUNT;

    // Error tracking
    std::string             error_code;
    std::string             error_description;
    SsoErrorCategory        error_category = SsoErrorCategory::NONE;
    int                     retry_count = 0;

    // Timing
    int64_t                 created_at = 0;
    int64_t                 last_activity_at = 0;
    int64_t                 expires_at = 0;

    // Login token for client exchange
    std::string             login_token;

    // Request params
    json                    initial_request_params;

    // UI state
    std::string             ui_step;               // Current UI step for registration flow
    json                    ui_state;               // UI state between steps

    bool is_expired() const {
        return expires_at > 0 && now_seconds() > expires_at;
    }

    bool is_active() const {
        return status != SsoSessionStatus::COMPLETED &&
               status != SsoSessionStatus::FAILED &&
               status != SsoSessionStatus::CANCELLED &&
               status != SsoSessionStatus::EXPIRED &&
               !is_expired();
    }

    json to_json() const {
        return json{
            {"session_id", session_id},
            {"provider_id", provider_id},
            {"client_redirect_uri", client_redirect_uri},
            {"status", static_cast<int>(status)},
            {"oauth_state", oauth_state},
            {"pkce_params", pkce_params.to_json()},
            {"token_response", token_response.to_json()},
            {"idp_subject", idp_subject},
            {"idp_email", idp_email},
            {"idp_name", idp_name},
            {"mapped_user_id", mapped_user_id},
            {"mapped_display_name", mapped_display_name},
            {"existing_user_id", existing_user_id},
            {"link_decision", static_cast<int>(link_decision)},
            {"error_code", error_code},
            {"error_description", error_description},
            {"created_at", created_at},
            {"expires_at", expires_at},
            {"login_token", login_token},
            {"idp_raw_userinfo", idp_raw_userinfo},
        };
    }

    static SsoLoginSession from_json(const json& j) {
        SsoLoginSession s;
        if (j.contains("session_id")) s.session_id = j["session_id"].get<std::string>();
        if (j.contains("provider_id")) s.provider_id = j["provider_id"].get<std::string>();
        if (j.contains("client_redirect_uri")) s.client_redirect_uri = j["client_redirect_uri"].get<std::string>();
        if (j.contains("status")) s.status = static_cast<SsoSessionStatus>(j["status"].get<int>());
        if (j.contains("oauth_state")) s.oauth_state = j["oauth_state"].get<std::string>();
        if (j.contains("pkce_params")) s.pkce_params = PkceParams::from_json(j["pkce_params"]);
        if (j.contains("token_response")) s.token_response = OAuth2TokenResponse::from_json(j["token_response"]);
        if (j.contains("idp_subject")) s.idp_subject = j["idp_subject"].get<std::string>();
        if (j.contains("idp_email")) s.idp_email = j["idp_email"].get<std::string>();
        if (j.contains("idp_name")) s.idp_name = j["idp_name"].get<std::string>();
        if (j.contains("mapped_user_id")) s.mapped_user_id = j["mapped_user_id"].get<std::string>();
        if (j.contains("mapped_display_name")) s.mapped_display_name = j["mapped_display_name"].get<std::string>();
        if (j.contains("existing_user_id")) s.existing_user_id = j["existing_user_id"].get<std::string>();
        if (j.contains("link_decision")) s.link_decision = static_cast<AccountLinkDecision>(j["link_decision"].get<int>());
        if (j.contains("error_code")) s.error_code = j["error_code"].get<std::string>();
        if (j.contains("error_description")) s.error_description = j["error_description"].get<std::string>();
        if (j.contains("created_at")) s.created_at = j["created_at"].get<int64_t>();
        if (j.contains("expires_at")) s.expires_at = j["expires_at"].get<int64_t>();
        if (j.contains("login_token")) s.login_token = j["login_token"].get<std::string>();
        if (j.contains("idp_raw_userinfo")) s.idp_raw_userinfo = j["idp_raw_userinfo"];
        if (j.contains("last_activity_at")) s.last_activity_at = j["last_activity_at"].get<int64_t>();
        if (j.contains("retry_count")) s.retry_count = j["retry_count"].get<int>();
        return s;
    }
};

// OIDC discovery document
struct OidcDiscoveryDocument {
    std::string issuer;
    std::string authorization_endpoint;
    std::string token_endpoint;
    std::string userinfo_endpoint;
    std::string jwks_uri;
    std::string registration_endpoint;
    std::string revocation_endpoint;
    std::string end_session_endpoint;
    std::string introspection_endpoint;
    std::vector<std::string> scopes_supported;
    std::vector<std::string> response_types_supported;
    std::vector<std::string> grant_types_supported;
    std::vector<std::string> subject_types_supported;
    std::vector<std::string> id_token_signing_alg_values_supported;
    std::vector<std::string> token_endpoint_auth_methods_supported;
    std::vector<std::string> claims_supported;
    std::vector<std::string> code_challenge_methods_supported;
    bool backchannel_logout_supported = false;
    bool frontchannel_logout_supported = false;
    bool request_parameter_supported = false;
    bool claims_parameter_supported = false;
    int64_t fetched_at = 0;
    json   raw_document;

    bool is_expired() const {
        return (now_seconds() - fetched_at) > constants::PROVIDER_DISCOVERY_CACHE_SECS;
    }

    static OidcDiscoveryDocument from_json(const json& j) {
        OidcDiscoveryDocument d;
        if (j.contains("issuer")) d.issuer = j["issuer"].get<std::string>();
        if (j.contains("authorization_endpoint")) d.authorization_endpoint = j["authorization_endpoint"].get<std::string>();
        if (j.contains("token_endpoint")) d.token_endpoint = j["token_endpoint"].get<std::string>();
        if (j.contains("userinfo_endpoint")) d.userinfo_endpoint = j["userinfo_endpoint"].get<std::string>();
        if (j.contains("jwks_uri")) d.jwks_uri = j["jwks_uri"].get<std::string>();
        if (j.contains("registration_endpoint")) d.registration_endpoint = j["registration_endpoint"].get<std::string>();
        if (j.contains("revocation_endpoint")) d.revocation_endpoint = j["revocation_endpoint"].get<std::string>();
        if (j.contains("end_session_endpoint")) d.end_session_endpoint = j["end_session_endpoint"].get<std::string>();
        if (j.contains("introspection_endpoint")) d.introspection_endpoint = j["introspection_endpoint"].get<std::string>();
        if (j.contains("scopes_supported") && j["scopes_supported"].is_array())
            d.scopes_supported = j["scopes_supported"].get<std::vector<std::string>>();
        if (j.contains("response_types_supported") && j["response_types_supported"].is_array())
            d.response_types_supported = j["response_types_supported"].get<std::vector<std::string>>();
        if (j.contains("grant_types_supported") && j["grant_types_supported"].is_array())
            d.grant_types_supported = j["grant_types_supported"].get<std::vector<std::string>>();
        if (j.contains("subject_types_supported") && j["subject_types_supported"].is_array())
            d.subject_types_supported = j["subject_types_supported"].get<std::vector<std::string>>();
        if (j.contains("id_token_signing_alg_values_supported") && j["id_token_signing_alg_values_supported"].is_array())
            d.id_token_signing_alg_values_supported = j["id_token_signing_alg_values_supported"].get<std::vector<std::string>>();
        if (j.contains("token_endpoint_auth_methods_supported") && j["token_endpoint_auth_methods_supported"].is_array())
            d.token_endpoint_auth_methods_supported = j["token_endpoint_auth_methods_supported"].get<std::vector<std::string>>();
        if (j.contains("claims_supported") && j["claims_supported"].is_array())
            d.claims_supported = j["claims_supported"].get<std::vector<std::string>>();
        if (j.contains("code_challenge_methods_supported") && j["code_challenge_methods_supported"].is_array())
            d.code_challenge_methods_supported = j["code_challenge_methods_supported"].get<std::vector<std::string>>();
        if (j.contains("backchannel_logout_supported"))
            d.backchannel_logout_supported = j["backchannel_logout_supported"].get<bool>();
        if (j.contains("frontchannel_logout_supported"))
            d.frontchannel_logout_supported = j["frontchannel_logout_supported"].get<bool>();
        d.raw_document = j;
        d.fetched_at = now_seconds();
        return d;
    }
};

// OAuth2 userinfo response mapped to Matrix profile
struct MappedUserProfile {
    std::string localpart;
    std::string user_id;          // full @localpart:domain
    std::string display_name;
    std::string avatar_url;
    std::string email;
    std::string matrix_server_name;  // the domain part
    json        extra_attributes;    // additional claims for custom use

    bool is_complete() const {
        return !localpart.empty() && !user_id.empty();
    }

    json to_matrix_profile() const {
        json profile;
        if (!display_name.empty()) profile["displayname"] = display_name;
        if (!avatar_url.empty()) profile["avatar_url"] = avatar_url;
        return profile;
    }

    json to_json() const {
        return json{
            {"localpart", localpart},
            {"user_id", user_id},
            {"display_name", display_name},
            {"avatar_url", avatar_url},
            {"email", email},
            {"matrix_server_name", matrix_server_name},
            {"extra_attributes", extra_attributes},
        };
    }
};

// SSO error with full context for client and logging
struct SsoError {
    std::string        error_code;
    std::string        error_description;
    std::string        error_uri;
    SsoErrorCategory   category = SsoErrorCategory::NONE;
    std::string        provider_id;
    std::string        session_id;
    int                http_status = 400;
    bool               retryable = false;
    json               extra_debug_info;

    json to_client_error() const {
        json err{
            {"errcode", error_code.empty() ? "M_UNKNOWN" : error_code},
            {"error", error_description},
        };
        if (!error_uri.empty()) err["error_uri"] = error_uri;
        if (!retryable) err["soft_logout"] = false;
        return err;
    }

    static SsoError make_provider_not_found(const std::string& provider_id) {
        SsoError e;
        e.error_code = constants::ERR_PROVIDER_NOT_FOUND;
        e.error_description = "SSO provider '" + provider_id + "' not found";
        e.category = SsoErrorCategory::CONFIG_ERROR;
        e.provider_id = provider_id;
        e.http_status = 404;
        return e;
    }

    static SsoError make_session_expired(const std::string& session_id) {
        SsoError e;
        e.error_code = constants::ERR_SESSION_EXPIRED;
        e.error_description = "SSO session '" + session_id + "' has expired";
        e.category = SsoErrorCategory::VALIDATION_ERROR;
        e.session_id = session_id;
        e.http_status = 401;
        return e;
    }

    static SsoError make_state_mismatch() {
        SsoError e;
        e.error_code = constants::ERR_STATE_MISMATCH;
        e.error_description = "OAuth2 state parameter mismatch";
        e.category = SsoErrorCategory::VALIDATION_ERROR;
        e.http_status = 400;
        return e;
    }

    static SsoError make_provider_error(const std::string& err,
                                         const std::string& desc) {
        SsoError e;
        e.error_code = err.empty() ? constants::ERR_SERVER_ERROR : err;
        e.error_description = desc;
        e.category = SsoErrorCategory::PROVIDER_ERROR;
        e.http_status = 502;
        return e;
    }

    static SsoError make_internal(const std::string& desc) {
        SsoError e;
        e.error_code = constants::ERR_SERVER_ERROR;
        e.error_description = desc;
        e.category = SsoErrorCategory::INTERNAL_ERROR;
        e.http_status = 500;
        return e;
    }
};

// Result container for SSO operations
template <typename T>
struct SsoResult {
    bool        success = false;
    T           value;
    SsoError    error;

    static SsoResult<T> ok(T val) {
        SsoResult<T> r;
        r.success = true;
        r.value = std::move(val);
        return r;
    }

    static SsoResult<T> err(SsoError e) {
        SsoResult<T> r;
        r.success = false;
        r.error = std::move(e);
        return r;
    }
};

// ============================================================================
// Pre-defined provider templates
// ============================================================================

static OAuth2ProviderConfig make_google_provider(
        const std::string& client_id,
        const std::string& client_secret,
        const std::string& redirect_base) {
    OAuth2ProviderConfig cfg;
    cfg.provider_id = constants::PROVIDER_GOOGLE;
    cfg.display_name = "Google";
    cfg.kind = SsoProviderKind::GOOGLE;
    cfg.issuer = "https://accounts.google.com";
    cfg.authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    cfg.token_endpoint = "https://oauth2.googleapis.com/token";
    cfg.userinfo_endpoint = "https://openidconnect.googleapis.com/v1/userinfo";
    cfg.revocation_endpoint = "https://oauth2.googleapis.com/revoke";
    cfg.jwks_uri = "https://www.googleapis.com/oauth2/v3/certs";
    cfg.discovery_url = "https://accounts.google.com/.well-known/openid-configuration";
    cfg.client_id = client_id;
    cfg.client_secret = client_secret;
    cfg.redirect_base_url = redirect_base;
    cfg.scopes = {"openid", "profile", "email"};
    cfg.require_pkce = true;
    cfg.pkce_method = PkceMethod::S256;
    cfg.token_endpoint_auth_method = OAuth2TokenAuthMethod::CLIENT_SECRET_POST;
    cfg.localpart_template = "{{ user.email | localpart_from_email }}";
    cfg.display_name_template = "{{ user.name }}";
    cfg.email_template = "{{ user.email }}";
    cfg.avatar_url_template = "{{ user.picture }}";
    cfg.attribute_mapping = json{
        {"sub", "sub"},
        {"email", "email"},
        {"email_verified", "email_verified"},
        {"name", "name"},
        {"given_name", "given_name"},
        {"family_name", "family_name"},
        {"picture", "picture"},
        {"locale", "locale"},
        {"hd", "hd"},
    };
    cfg.branding.idp_name = "Google";
    cfg.branding.brand_color_primary = "#4285F4";
    cfg.branding.brand_color_secondary = "#34A853";
    cfg.branding.button_text = "Sign in with Google";
    cfg.branding.button_css_class = "sso-button-google";
    cfg.branding.login_page_title = "Sign in with your Google account";
    cfg.branding.login_page_subtitle = "Choose a Google account to continue to Matrix";
    cfg.branding.style = ProviderBrandingStyle::GOOGLE_STYLE;
    cfg.branding.sort_order = 10;
    return cfg;
}

static OAuth2ProviderConfig make_github_provider(
        const std::string& client_id,
        const std::string& client_secret,
        const std::string& redirect_base) {
    OAuth2ProviderConfig cfg;
    cfg.provider_id = constants::PROVIDER_GITHUB;
    cfg.display_name = "GitHub";
    cfg.kind = SsoProviderKind::GITHUB;
    cfg.authorization_endpoint = "https://github.com/login/oauth/authorize";
    cfg.token_endpoint = "https://github.com/login/oauth/access_token";
    cfg.userinfo_endpoint = "https://api.github.com/user";
    cfg.client_id = client_id;
    cfg.client_secret = client_secret;
    cfg.redirect_base_url = redirect_base;
    cfg.scopes = {"user:email", "read:user"};
    cfg.require_pkce = true;
    cfg.pkce_method = PkceMethod::S256;
    cfg.token_endpoint_auth_method = OAuth2TokenAuthMethod::CLIENT_SECRET_BASIC;
    cfg.localpart_template = "{{ user.login }}";
    cfg.display_name_template = "{{ user.name }}";
    cfg.email_template = "{{ email.primary }}";
    cfg.avatar_url_template = "{{ user.avatar_url }}";
    cfg.attribute_mapping = json{
        {"sub", "id"},
        {"email", "email"},
        {"name", "name"},
        {"login", "login"},
        {"avatar_url", "avatar_url"},
        {"html_url", "html_url"},
    };
    cfg.branding.idp_name = "GitHub";
    cfg.branding.brand_color_primary = "#24292E";
    cfg.branding.brand_color_secondary = "#0366D6";
    cfg.branding.button_text = "Sign in with GitHub";
    cfg.branding.button_css_class = "sso-button-github";
    cfg.branding.login_page_title = "Sign in with your GitHub account";
    cfg.branding.login_page_subtitle = "Authorize Matrix to access your GitHub account";
    cfg.branding.style = ProviderBrandingStyle::GITHUB_STYLE;
    cfg.branding.sort_order = 20;
    return cfg;
}

static OAuth2ProviderConfig make_gitlab_provider(
        const std::string& client_id,
        const std::string& client_secret,
        const std::string& redirect_base) {
    OAuth2ProviderConfig cfg;
    cfg.provider_id = constants::PROVIDER_GITLAB;
    cfg.display_name = "GitLab";
    cfg.kind = SsoProviderKind::GITLAB;
    cfg.issuer = "https://gitlab.com";
    cfg.authorization_endpoint = "https://gitlab.com/oauth/authorize";
    cfg.token_endpoint = "https://gitlab.com/oauth/token";
    cfg.userinfo_endpoint = "https://gitlab.com/oauth/userinfo";
    cfg.discovery_url = "https://gitlab.com/.well-known/openid-configuration";
    cfg.client_id = client_id;
    cfg.client_secret = client_secret;
    cfg.redirect_base_url = redirect_base;
    cfg.scopes = {"openid", "profile", "email", "read_user"};
    cfg.require_pkce = true;
    cfg.pkce_method = PkceMethod::S256;
    cfg.token_endpoint_auth_method = OAuth2TokenAuthMethod::CLIENT_SECRET_POST;
    cfg.localpart_template = "{{ user.nickname }}";
    cfg.display_name_template = "{{ user.name }}";
    cfg.email_template = "{{ user.email }}";
    cfg.avatar_url_template = "{{ user.picture }}";
    cfg.attribute_mapping = json{
        {"sub", "sub"},
        {"email", "email"},
        {"name", "name"},
        {"nickname", "nickname"},
        {"picture", "picture"},
        {"profile", "profile"},
        {"website", "website"},
    };
    cfg.branding.idp_name = "GitLab";
    cfg.branding.brand_color_primary = "#FC6D26";
    cfg.branding.brand_color_secondary = "#E24329";
    cfg.branding.button_text = "Sign in with GitLab";
    cfg.branding.button_css_class = "sso-button-gitlab";
    cfg.branding.login_page_title = "Sign in with your GitLab account";
    cfg.branding.login_page_subtitle = "Authorize Matrix to access your GitLab account";
    cfg.branding.style = ProviderBrandingStyle::GITLAB_STYLE;
    cfg.branding.sort_order = 30;
    return cfg;
}

static OAuth2ProviderConfig make_facebook_provider(
        const std::string& client_id,
        const std::string& client_secret,
        const std::string& redirect_base) {
    OAuth2ProviderConfig cfg;
    cfg.provider_id = constants::PROVIDER_FACEBOOK;
    cfg.display_name = "Facebook";
    cfg.kind = SsoProviderKind::FACEBOOK;
    cfg.authorization_endpoint = "https://www.facebook.com/v18.0/dialog/oauth";
    cfg.token_endpoint = "https://graph.facebook.com/v18.0/oauth/access_token";
    cfg.userinfo_endpoint = "https://graph.facebook.com/me?fields=id,name,email,picture";
    cfg.client_id = client_id;
    cfg.client_secret = client_secret;
    cfg.redirect_base_url = redirect_base;
    cfg.scopes = {"email", "public_profile"};
    cfg.require_pkce = true;
    cfg.pkce_method = PkceMethod::S256;
    cfg.token_endpoint_auth_method = OAuth2TokenAuthMethod::CLIENT_SECRET_POST;
    cfg.localpart_template = "fb_{{ user.id }}";
    cfg.display_name_template = "{{ user.name }}";
    cfg.email_template = "{{ user.email }}";
    cfg.avatar_url_template = "{{ user.picture.data.url }}";
    cfg.attribute_mapping = json{
        {"sub", "id"},
        {"email", "email"},
        {"name", "name"},
        {"picture", "picture.data.url"},
    };
    cfg.branding.idp_name = "Facebook";
    cfg.branding.brand_color_primary = "#1877F2";
    cfg.branding.brand_color_secondary = "#42B72A";
    cfg.branding.button_text = "Continue with Facebook";
    cfg.branding.button_css_class = "sso-button-facebook";
    cfg.branding.login_page_title = "Continue with your Facebook account";
    cfg.branding.login_page_subtitle = "Log in to Matrix using your Facebook account";
    cfg.branding.style = ProviderBrandingStyle::FACEBOOK_STYLE;
    cfg.branding.sort_order = 40;
    return cfg;
}

static OAuth2ProviderConfig make_apple_provider(
        const std::string& client_id,
        const std::string& client_secret,
        const std::string& redirect_base) {
    OAuth2ProviderConfig cfg;
    cfg.provider_id = constants::PROVIDER_APPLE;
    cfg.display_name = "Apple";
    cfg.kind = SsoProviderKind::APPLE;
    cfg.issuer = "https://appleid.apple.com";
    cfg.authorization_endpoint = "https://appleid.apple.com/auth/authorize";
    cfg.token_endpoint = "https://appleid.apple.com/auth/token";
    cfg.discovery_url = "https://appleid.apple.com/.well-known/openid-configuration";
    cfg.client_id = client_id;
    cfg.client_secret = client_secret;  // For Apple, this is the client secret JWT
    cfg.redirect_base_url = redirect_base;
    cfg.scopes = {"name", "email"};
    cfg.require_pkce = true;
    cfg.pkce_method = PkceMethod::S256;
    cfg.token_endpoint_auth_method = OAuth2TokenAuthMethod::CLIENT_SECRET_POST;
    cfg.localpart_template = "apple_{{ user.sub | truncate(8,'') }}";
    cfg.display_name_template = "{{ user.name }}";
    cfg.email_template = "{{ user.email }}";
    cfg.attribute_mapping = json{
        {"sub", "sub"},
        {"email", "email"},
        {"email_verified", "email_verified"},
        {"name", "name"},
    };
    cfg.branding.idp_name = "Apple";
    cfg.branding.brand_color_primary = "#000000";
    cfg.branding.brand_color_secondary = "#A2AAAD";
    cfg.branding.button_text = "Sign in with Apple";
    cfg.branding.button_css_class = "sso-button-apple";
    cfg.branding.login_page_title = "Sign in with your Apple ID";
    cfg.branding.login_page_subtitle = "Use your Apple ID to sign in to Matrix";
    cfg.branding.style = ProviderBrandingStyle::APPLE_STYLE;
    cfg.branding.sort_order = 50;
    return cfg;
}

static OAuth2ProviderConfig make_microsoft_provider(
        const std::string& client_id,
        const std::string& client_secret,
        const std::string& redirect_base) {
    OAuth2ProviderConfig cfg;
    cfg.provider_id = constants::PROVIDER_MICROSOFT;
    cfg.display_name = "Microsoft";
    cfg.kind = SsoProviderKind::MICROSOFT;
    cfg.issuer = "https://login.microsoftonline.com/common/v2.0";
    cfg.authorization_endpoint =
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
    cfg.token_endpoint =
        "https://login.microsoftonline.com/common/oauth2/v2.0/token";
    cfg.userinfo_endpoint = "https://graph.microsoft.com/oidc/userinfo";
    cfg.discovery_url =
        "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";
    cfg.client_id = client_id;
    cfg.client_secret = client_secret;
    cfg.redirect_base_url = redirect_base;
    cfg.scopes = {"openid", "profile", "email", "User.Read"};
    cfg.require_pkce = true;
    cfg.pkce_method = PkceMethod::S256;
    cfg.token_endpoint_auth_method = OAuth2TokenAuthMethod::CLIENT_SECRET_POST;
    cfg.localpart_template = "{{ user.preferred_username | localpart_from_email }}";
    cfg.display_name_template = "{{ user.name }}";
    cfg.email_template = "{{ user.email }}";
    cfg.avatar_url_template = "";
    cfg.attribute_mapping = json{
        {"sub", "sub"},
        {"email", "email"},
        {"name", "name"},
        {"preferred_username", "preferred_username"},
        {"oid", "oid"},
        {"tid", "tid"},
    };
    cfg.branding.idp_name = "Microsoft";
    cfg.branding.brand_color_primary = "#00A4EF";
    cfg.branding.brand_color_secondary = "#7FBA00";
    cfg.branding.button_text = "Sign in with Microsoft";
    cfg.branding.button_css_class = "sso-button-microsoft";
    cfg.branding.login_page_title = "Sign in with your Microsoft account";
    cfg.branding.login_page_subtitle = "Use your Microsoft work or personal account";
    cfg.branding.style = ProviderBrandingStyle::MICROSOFT_STYLE;
    cfg.branding.sort_order = 60;
    return cfg;
}

// ============================================================================
// OAuth2Client — HTTP communication with OAuth2/OIDC providers
// ============================================================================

class OAuth2Client {
public:
    OAuth2Client() = default;
    virtual ~OAuth2Client() = default;

    // Build the authorization URL for the OAuth2 provider
    virtual std::string build_authorization_url(
            const OAuth2ProviderConfig& config,
            const std::string& state,
            const std::string& nonce,
            const PkceParams& pkce,
            const std::string& redirect_uri,
            const std::string& login_hint = "") {
        std::ostringstream url;
        url << config.authorization_endpoint;
        url << "?response_type=code";
        url << "&client_id=" << url_encode(config.client_id);
        url << "&redirect_uri=" << url_encode(redirect_uri);
        url << "&scope=" << url_encode(join_strings(config.scopes, " "));
        url << "&state=" << url_encode(state);

        if (!nonce.empty()) {
            url << "&nonce=" << url_encode(nonce);
        }

        if (!pkce.empty()) {
            url << "&code_challenge=" << url_encode(pkce.code_challenge);
            url << "&code_challenge_method=S256";
        }

        if (!login_hint.empty()) {
            url << "&login_hint=" << url_encode(login_hint);
        }

        // Add extra params from config
        if (!config.extra_authorization_params.empty()) {
            for (auto& [key, val] : config.extra_authorization_params.items()) {
                if (val.is_string()) {
                    url << "&" << url_encode(key)
                        << "=" << url_encode(val.get<std::string>());
                }
            }
        }

        // Provider-specific parameters
        switch (config.kind) {
            case SsoProviderKind::GOOGLE:
                url << "&access_type=offline";
                url << "&prompt=consent";
                url << "&include_granted_scopes=true";
                break;
            case SsoProviderKind::APPLE:
                url << "&response_mode=form_post";
                break;
            case SsoProviderKind::FACEBOOK:
                url << "&auth_type=rerequest";
                break;
            case SsoProviderKind::MICROSOFT:
                url << "&response_mode=query";
                break;
            default:
                break;
        }

        return url.str();
    }

    // Exchange authorization code for tokens
    virtual OAuth2TokenResponse exchange_code_for_tokens(
            const OAuth2ProviderConfig& config,
            const std::string& code,
            const PkceParams& pkce,
            const std::string& redirect_uri) {
        OAuth2TokenResponse response;

        // Build token request body
        std::ostringstream body;
        body << "grant_type=" << url_encode(constants::GRANT_AUTHORIZATION_CODE);
        body << "&code=" << url_encode(code);
        body << "&redirect_uri=" << url_encode(redirect_uri);

        if (!pkce.empty()) {
            body << "&code_verifier=" << url_encode(pkce.code_verifier);
        }

        // Add extra token params
        if (!config.extra_token_params.empty()) {
            for (auto& [key, val] : config.extra_token_params.items()) {
                if (val.is_string()) {
                    body << "&" << url_encode(key)
                         << "=" << url_encode(val.get<std::string>());
                }
            }
        }

        // Determine auth method
        bool use_basic_auth =
            config.token_endpoint_auth_method ==
            OAuth2TokenAuthMethod::CLIENT_SECRET_BASIC;

        if (config.token_endpoint_auth_method ==
            OAuth2TokenAuthMethod::CLIENT_SECRET_POST) {
            body << "&client_id=" << url_encode(config.client_id);
            body << "&client_secret=" << url_encode(config.client_secret);
        }

        // Simulate HTTP POST to token endpoint
        // In production, this would use an HTTP client with TLS
        try {
            // Build simulated token response based on provider type
            response.access_token = "sso_at_" + generate_state_token();
            response.token_type = constants::TOKEN_TYPE_BEARER;
            response.expires_in = 3600;
            response.obtained_at = now_seconds();
            response.success = true;

            // Simulate refresh_token for providers that support it
            if (config.kind != SsoProviderKind::APPLE) {
                response.refresh_token = "sso_rt_" + generate_state_token();
            }

            // Simulate id_token for OIDC providers
            if (config.is_oidc()) {
                response.id_token = "sso_id_" + generate_state_token();
            }

            // Provider-specific response handling
            switch (config.kind) {
                case SsoProviderKind::GITHUB:
                    // GitHub uses non-standard response format
                    response.token_type = "bearer";
                    break;
                case SsoProviderKind::GITLAB:
                    response.expires_in = 7200;  // GitLab uses 2-hour tokens
                    break;
                case SsoProviderKind::FACEBOOK:
                    response.token_type = "bearer";
                    response.expires_in = 5184000;  // Facebook long-lived tokens
                    break;
                default:
                    break;
            }

            response.raw_response = response.to_json();
        } catch (const std::exception& e) {
            response.success = false;
            response.error = constants::ERR_SERVER_ERROR;
            response.error_description = std::string("Token exchange failed: ") + e.what();
        }

        return response;
    }

    // Refresh an expired access token
    virtual OAuth2TokenResponse refresh_access_token(
            const OAuth2ProviderConfig& config,
            const std::string& refresh_token) {
        OAuth2TokenResponse response;

        if (refresh_token.empty()) {
            response.success = false;
            response.error = constants::ERR_INVALID_REQUEST;
            response.error_description = "No refresh token provided";
            return response;
        }

        std::ostringstream body;
        body << "grant_type=" << url_encode(constants::GRANT_REFRESH_TOKEN);
        body << "&refresh_token=" << url_encode(refresh_token);
        body << "&client_id=" << url_encode(config.client_id);

        if (config.token_endpoint_auth_method ==
            OAuth2TokenAuthMethod::CLIENT_SECRET_POST) {
            body << "&client_secret=" << url_encode(config.client_secret);
        }

        try {
            response.access_token = "sso_at_refreshed_" + generate_state_token();
            response.token_type = constants::TOKEN_TYPE_BEARER;
            response.expires_in = 3600;
            response.obtained_at = now_seconds();
            response.success = true;

            // Some providers issue a new refresh token
            if (config.kind == SsoProviderKind::GOOGLE ||
                config.kind == SsoProviderKind::GITLAB) {
                response.refresh_token = "sso_rt_new_" + generate_state_token();
            } else {
                response.refresh_token = refresh_token;  // Re-use existing
            }

            response.raw_response = response.to_json();
        } catch (const std::exception& e) {
            response.success = false;
            response.error = constants::ERR_INVALID_GRANT;
            response.error_description = std::string("Token refresh failed: ") + e.what();
        }

        return response;
    }

    // Fetch userinfo from the provider
    virtual json fetch_userinfo(
            const OAuth2ProviderConfig& config,
            const std::string& access_token) {
        json userinfo;

        if (access_token.empty()) {
            userinfo["error"] = "No access token provided";
            return userinfo;
        }

        try {
            // Simulate userinfo response based on provider
            switch (config.kind) {
                case SsoProviderKind::GOOGLE:
                    userinfo["sub"] = "google-uid-" + generate_state_token().substr(0, 12);
                    userinfo["email"] = "user@gmail.com";
                    userinfo["email_verified"] = true;
                    userinfo["name"] = "Google User";
                    userinfo["given_name"] = "Google";
                    userinfo["family_name"] = "User";
                    userinfo["picture"] = "https://lh3.googleusercontent.com/a/default-user";
                    userinfo["locale"] = "en";
                    userinfo["hd"] = "gmail.com";
                    break;

                case SsoProviderKind::GITHUB: {
                    userinfo["id"] = 12345678;
                    userinfo["login"] = "githubuser";
                    userinfo["name"] = "GitHub User";
                    userinfo["avatar_url"] = "https://avatars.githubusercontent.com/u/12345678";
                    userinfo["html_url"] = "https://github.com/githubuser";
                    userinfo["email"] = "user@github.com";
                    userinfo["type"] = "User";
                    userinfo["site_admin"] = false;
                    userinfo["company"] = "Acme Inc";
                    userinfo["location"] = "San Francisco";
                    userinfo["bio"] = "Matrix enthusiast";
                    break;
                }

                case SsoProviderKind::GITLAB:
                    userinfo["sub"] = "gl-sub-" + generate_state_token().substr(0, 8);
                    userinfo["email"] = "user@gitlab.com";
                    userinfo["email_verified"] = true;
                    userinfo["name"] = "GitLab User";
                    userinfo["nickname"] = "gitlabuser";
                    userinfo["picture"] = "https://gitlab.com/uploads/-/system/user/avatar/1/avatar.png";
                    userinfo["profile"] = "https://gitlab.com/gitlabuser";
                    userinfo["website"] = "https://gitlabuser.dev";
                    break;

                case SsoProviderKind::FACEBOOK:
                    userinfo["id"] = "fb-id-" + generate_state_token().substr(0, 12);
                    userinfo["email"] = "user@facebook.com";
                    userinfo["name"] = "Facebook User";
                    userinfo["picture"] = json{
                        {"data", {
                            {"url", "https://graph.facebook.com/v18.0/me/picture"},
                            {"width", 320},
                            {"height", 320},
                        }}
                    };
                    break;

                case SsoProviderKind::APPLE:
                    userinfo["sub"] = "apple-sub-" + generate_state_token().substr(0, 16);
                    userinfo["email"] = "user@privaterelay.appleid.com";
                    userinfo["email_verified"] = true;
                    break;

                case SsoProviderKind::MICROSOFT:
                    userinfo["sub"] = "ms-sub-" + generate_state_token().substr(0, 16);
                    userinfo["email"] = "user@outlook.com";
                    userinfo["name"] = "Microsoft User";
                    userinfo["preferred_username"] = "user@outlook.com";
                    userinfo["oid"] = generate_uuid();
                    userinfo["tid"] = generate_uuid();
                    break;

                default:
                    // Generic OIDC / custom provider
                    userinfo["sub"] = "custom-sub-" + generate_state_token().substr(0, 12);
                    userinfo["email"] = "user@example.com";
                    userinfo["email_verified"] = true;
                    userinfo["name"] = "Custom User";
                    userinfo["preferred_username"] = "customuser";
                    userinfo["picture"] = "https://example.com/avatar.png";
                    break;
            }

        } catch (const std::exception& e) {
            userinfo["error"] = std::string("Userinfo fetch failed: ") + e.what();
        }

        return userinfo;
    }

    // Fetch OIDC discovery document
    virtual OidcDiscoveryDocument fetch_discovery_document(
            const std::string& discovery_url,
            bool verify_ssl = true) {
        OidcDiscoveryDocument doc;

        try {
            // Simulate discovery for well-known providers
            if (discovery_url.find("accounts.google.com") != std::string::npos) {
                doc.issuer = "https://accounts.google.com";
                doc.authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth";
                doc.token_endpoint = "https://oauth2.googleapis.com/token";
                doc.userinfo_endpoint = "https://openidconnect.googleapis.com/v1/userinfo";
                doc.jwks_uri = "https://www.googleapis.com/oauth2/v3/certs";
                doc.revocation_endpoint = "https://oauth2.googleapis.com/revoke";
                doc.scopes_supported = {"openid", "profile", "email", "address", "phone"};
                doc.response_types_supported = {"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"};
                doc.grant_types_supported = {"authorization_code", "refresh_token"};
                doc.subject_types_supported = {"public"};
                doc.id_token_signing_alg_values_supported = {"RS256"};
                doc.token_endpoint_auth_methods_supported = {"client_secret_post", "client_secret_basic"};
                doc.claims_supported = {"aud", "email", "email_verified", "exp", "family_name", "given_name", "iat", "iss", "locale", "name", "picture", "sub"};
                doc.code_challenge_methods_supported = {"S256"};
            } else if (discovery_url.find("appleid.apple.com") != std::string::npos) {
                doc.issuer = "https://appleid.apple.com";
                doc.authorization_endpoint = "https://appleid.apple.com/auth/authorize";
                doc.token_endpoint = "https://appleid.apple.com/auth/token";
                doc.jwks_uri = "https://appleid.apple.com/auth/keys";
                doc.scopes_supported = {"openid", "email", "name"};
                doc.response_types_supported = {"code", "code id_token"};
                doc.grant_types_supported = {"authorization_code", "refresh_token"};
                doc.subject_types_supported = {"pairwise"};
                doc.id_token_signing_alg_values_supported = {"RS256"};
                doc.token_endpoint_auth_methods_supported = {"client_secret_post", "client_secret_basic", "private_key_jwt"};
                doc.code_challenge_methods_supported = {"S256"};
            } else if (discovery_url.find("microsoftonline.com") != std::string::npos) {
                doc.issuer = "https://login.microsoftonline.com/common/v2.0";
                doc.authorization_endpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
                doc.token_endpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
                doc.userinfo_endpoint = "https://graph.microsoft.com/oidc/userinfo";
                doc.jwks_uri = "https://login.microsoftonline.com/common/discovery/v2.0/keys";
                doc.end_session_endpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/logout";
                doc.scopes_supported = {"openid", "profile", "email", "offline_access", "User.Read"};
                doc.response_types_supported = {"code", "id_token", "code id_token", "id_token token"};
                doc.grant_types_supported = {"authorization_code", "refresh_token", "client_credentials"};
                doc.subject_types_supported = {"pairwise"};
                doc.id_token_signing_alg_values_supported = {"RS256", "RS384"};
                doc.token_endpoint_auth_methods_supported = {"client_secret_post", "client_secret_basic", "private_key_jwt"};
                doc.code_challenge_methods_supported = {"S256", "plain"};
            } else if (discovery_url.find("gitlab.com") != std::string::npos) {
                doc.issuer = "https://gitlab.com";
                doc.authorization_endpoint = "https://gitlab.com/oauth/authorize";
                doc.token_endpoint = "https://gitlab.com/oauth/token";
                doc.userinfo_endpoint = "https://gitlab.com/oauth/userinfo";
                doc.jwks_uri = "https://gitlab.com/oauth/discovery/keys";
                doc.scopes_supported = {"openid", "profile", "email", "api", "read_user", "read_api"};
                doc.response_types_supported = {"code"};
                doc.grant_types_supported = {"authorization_code", "refresh_token"};
                doc.subject_types_supported = {"public"};
                doc.id_token_signing_alg_values_supported = {"RS256"};
                doc.token_endpoint_auth_methods_supported = {"client_secret_basic", "client_secret_post"};
                doc.code_challenge_methods_supported = {"S256", "plain"};
            } else {
                // Generic OIDC discovery response
                doc.issuer = discovery_url;
                size_t well_known_pos = discovery_url.find("/.well-known/");
                if (well_known_pos != std::string::npos) {
                    doc.issuer = discovery_url.substr(0, well_known_pos);
                }
                doc.authorization_endpoint = doc.issuer + "/authorize";
                doc.token_endpoint = doc.issuer + "/token";
                doc.userinfo_endpoint = doc.issuer + "/userinfo";
                doc.jwks_uri = doc.issuer + "/jwks";
                doc.scopes_supported = {"openid", "profile", "email"};
                doc.response_types_supported = {"code"};
                doc.grant_types_supported = {"authorization_code", "refresh_token"};
                doc.subject_types_supported = {"public"};
                doc.id_token_signing_alg_values_supported = {"RS256"};
                doc.token_endpoint_auth_methods_supported = {"client_secret_basic", "client_secret_post"};
                doc.code_challenge_methods_supported = {"S256"};
            }

            doc.fetched_at = now_seconds();
            doc.raw_document = json{};
        } catch (const std::exception& e) {
            // Return empty doc on failure
            doc.issuer = "";
        }

        return doc;
    }

    // Revoke a token
    virtual bool revoke_token(
            const OAuth2ProviderConfig& config,
            const std::string& token,
            const std::string& token_type_hint = "access_token") {
        if (config.revocation_endpoint.empty()) {
            return false;  // Provider doesn't support revocation
        }
        // Simulate successful revocation
        return true;
    }
};

// ============================================================================
// OAuth2UserinfoMapper — Map OAuth2 userinfo claims to Matrix profile
// ============================================================================

class OAuth2UserinfoMapper {
public:
    OAuth2UserinfoMapper() = default;

    // Map OIDC/OAuth2 userinfo to a Matrix user profile
    MappedUserProfile map_userinfo(
            const OAuth2ProviderConfig& config,
            const json& userinfo,
            const std::string& matrix_server_name) {
        MappedUserProfile profile;
        profile.matrix_server_name = matrix_server_name;

        if (userinfo.empty()) {
            return profile;
        }

        // Extract attributes based on provider type and mapping config
        json mapping_context = build_mapping_context(config, userinfo);

        // Map localpart (username part of Matrix ID)
        profile.localpart = map_localpart(config, mapping_context);
        if (profile.localpart.empty()) {
            // Fallback: use sub claim
            std::string sub = extract_claim(userinfo, config, "sub");
            if (!sub.empty()) {
                profile.localpart = sanitize_localpart(sub);
            }
        }

        // Build full user_id
        if (!profile.localpart.empty() && !matrix_server_name.empty()) {
            profile.user_id = "@" + profile.localpart + ":" + matrix_server_name;
        }

        // Map display name
        profile.display_name = map_display_name(config, mapping_context);
        if (profile.display_name.empty()) {
            profile.display_name = extract_claim(userinfo, config, "name");
        }

        // Map avatar URL
        profile.avatar_url = map_avatar_url(config, mapping_context);
        if (profile.avatar_url.empty()) {
            profile.avatar_url = extract_claim(userinfo, config, "picture");
        }
        // Handle nested picture objects (Facebook etc.)
        if (profile.avatar_url.empty() && userinfo.contains("picture")) {
            if (userinfo["picture"].is_object()) {
                if (userinfo["picture"].contains("data") &&
                    userinfo["picture"]["data"].is_object() &&
                    userinfo["picture"]["data"].contains("url")) {
                    profile.avatar_url =
                        userinfo["picture"]["data"]["url"].get<std::string>();
                }
            }
        }

        // Map email
        profile.email = map_email(config, mapping_context);
        if (profile.email.empty()) {
            profile.email = extract_claim(userinfo, config, "email");
        }

        // Store extra attributes for custom use
        profile.extra_attributes = userinfo;

        return profile;
    }

    // Build a template rendering context from userinfo
    json build_mapping_context(
            const OAuth2ProviderConfig& config,
            const json& userinfo) {
        json context;
        context["user"] = userinfo;

        // Provider-specific computed fields
        switch (config.kind) {
            case SsoProviderKind::GOOGLE:
                context["email"] = json{
                    {"primary", extract_nested(userinfo, "email")},
                    {"verified", extract_nested(userinfo, "email_verified")},
                };
                break;
            case SsoProviderKind::GITHUB:
                context["email"] = json{
                    {"primary", extract_nested(userinfo, "email")},
                };
                break;
            case SsoProviderKind::GITLAB:
                context["email"] = json{
                    {"primary", extract_nested(userinfo, "email")},
                    {"verified", extract_nested(userinfo, "email_verified")},
                };
                break;
            case SsoProviderKind::FACEBOOK:
                context["email"] = json{
                    {"primary", extract_nested(userinfo, "email")},
                };
                break;
            case SsoProviderKind::APPLE:
                context["email"] = json{
                    {"primary", extract_nested(userinfo, "email")},
                    {"verified", extract_nested(userinfo, "email_verified")},
                };
                break;
            case SsoProviderKind::MICROSOFT:
                context["email"] = json{
                    {"primary", extract_nested(userinfo, "email")},
                };
                break;
            default:
                context["email"] = json{
                    {"primary", extract_nested(userinfo, "email")},
                };
                break;
        }

        return context;
    }

private:
    std::string map_localpart(
            const OAuth2ProviderConfig& config,
            const json& context) {
        if (!config.localpart_template.empty()) {
            return apply_template(config.localpart_template, context);
        }

        // Provider-specific default localpart logic
        switch (config.kind) {
            case SsoProviderKind::GITHUB:
                return sanitize_localpart(
                    extract_nested(context["user"], "login"));

            case SsoProviderKind::GOOGLE:
            case SsoProviderKind::MICROSOFT: {
                std::string email = extract_nested(context["user"], "email");
                return localpart_from_email(email);
            }

            case SsoProviderKind::GITLAB:
                return sanitize_localpart(
                    extract_nested(context["user"], "nickname"));

            case SsoProviderKind::FACEBOOK: {
                std::string id = extract_nested(context["user"], "id");
                return "fb_" + sanitize_localpart(id);
            }

            case SsoProviderKind::APPLE: {
                std::string sub = extract_nested(context["user"], "sub");
                return "apple_" + sanitize_localpart(sub).substr(0, 16);
            }

            default: {
                // Try preferred_username, then name, then sub
                std::string username = extract_nested(
                    context["user"], "preferred_username");
                if (username.empty()) {
                    username = extract_nested(context["user"], "nickname");
                }
                if (username.empty()) {
                    username = extract_nested(context["user"], "sub");
                }
                return sanitize_localpart(username);
            }
        }
    }

    std::string map_display_name(
            const OAuth2ProviderConfig& config,
            const json& context) {
        if (!config.display_name_template.empty()) {
            return apply_template(config.display_name_template, context);
        }

        std::string name = extract_nested(context["user"], "name");
        if (!name.empty()) return name;

        // Fallback: combine given_name + family_name
        std::string given = extract_nested(context["user"], "given_name");
        std::string family = extract_nested(context["user"], "family_name");
        if (!given.empty() || !family.empty()) {
            if (given.empty()) return family;
            if (family.empty()) return given;
            return given + " " + family;
        }

        return "";
    }

    std::string map_avatar_url(
            const OAuth2ProviderConfig& config,
            const json& context) {
        if (!config.avatar_url_template.empty()) {
            return apply_template(config.avatar_url_template, context);
        }
        return "";
    }

    std::string map_email(
            const OAuth2ProviderConfig& config,
            const json& context) {
        if (!config.email_template.empty()) {
            return apply_template(config.email_template, context);
        }
        return extract_nested(context["user"], "email");
    }

    // Extract a claim using the attribute mapping config
    std::string extract_claim(
            const json& userinfo,
            const OAuth2ProviderConfig& config,
            const std::string& claim_name) {
        // Check if we have a mapping for this claim
        std::string mapped_name = claim_name;
        if (config.attribute_mapping.contains(claim_name)) {
            auto& mapped = config.attribute_mapping[claim_name];
            if (mapped.is_string()) {
                mapped_name = mapped.get<std::string>();
            }
        }
        return extract_nested(userinfo, mapped_name);
    }

    // Extract a possibly-nested value from JSON using dot notation
    std::string extract_nested(const json& obj, const std::string& path) {
        if (obj.empty() || path.empty()) return "";

        // Split path by dots
        std::vector<std::string> parts;
        std::istringstream iss(path);
        std::string part;
        while (std::getline(iss, part, '.')) {
            parts.push_back(part);
        }

        const json* current = &obj;
        for (const auto& p : parts) {
            if (!current->is_object() || !current->contains(p)) {
                return "";
            }
            current = &(*current)[p];
        }

        if (current->is_string()) return current->get<std::string>();
        if (current->is_number_integer()) return std::to_string(current->get<int64_t>());
        if (current->is_number_float()) return std::to_string(current->get<double>());
        if (current->is_boolean()) return current->get<bool>() ? "true" : "false";
        return current->dump();
    }

    // Apply a simple template with {{ path }} substitutions
    std::string apply_template(
            const std::string& tmpl,
            const json& context) {
        std::string result = tmpl;

        // Find {{ ... }} patterns
        std::regex pattern(R"(\{\{\s*([^}]+)\s*\}\})");
        std::smatch match;
        std::string working = tmpl;

        // Simple regex replace loop
        while (std::regex_search(working, match, pattern)) {
            std::string full_match = match[0];
            std::string expression = match[1];

            // Trim whitespace
            expression.erase(0, expression.find_first_not_of(" \t\n\r"));
            expression.erase(expression.find_last_not_of(" \t\n\r") + 1);

            // Check for filters like "| localpart_from_email"
            std::string filter;
            auto pipe_pos = expression.find('|');
            if (pipe_pos != std::string::npos) {
                filter = expression.substr(pipe_pos + 1);
                expression = expression.substr(0, pipe_pos);
                // Trim
                expression.erase(expression.find_last_not_of(" \t\n\r") + 1);
                filter.erase(0, filter.find_first_not_of(" \t\n\r"));
                filter.erase(filter.find_last_not_of(" \t\n\r") + 1);
            }

            std::string replacement = extract_nested(context, expression);

            // Apply filters
            if (!replacement.empty() && !filter.empty()) {
                if (filter == "localpart_from_email") {
                    replacement = localpart_from_email(replacement);
                } else if (filter.find("truncate") == 0) {
                    // Simple truncate filter
                    replacement = replacement.substr(0, 16);
                }
            }

            working = match.prefix().str() + replacement + match.suffix().str();
        }

        return working;
    }

    // Sanitize a string to be a valid Matrix localpart
    std::string sanitize_localpart(const std::string& input) {
        if (input.empty()) return "";
        std::string result;
        result.reserve(input.size());
        for (char c : input) {
            if (std::isalnum(static_cast<unsigned char>(c)) ||
                c == '.' || c == '_' || c == '-' || c == '=' || c == '/') {
                result += std::tolower(static_cast<unsigned char>(c));
            } else {
                result += '_';
            }
        }
        // Ensure it doesn't start with underscore (reserved for application services)
        if (!result.empty() && result[0] == '_') {
            result = "u" + result;
        }
        // Truncate to max localpart length
        constexpr size_t MAX_LOCALPART = 255;
        if (result.size() > MAX_LOCALPART) {
            result.resize(MAX_LOCALPART);
        }
        return result.empty() ? "sso_user" : result;
    }

    // Extract localpart from email
    std::string localpart_from_email(const std::string& email) {
        auto at_pos = email.find('@');
        if (at_pos == std::string::npos) {
            return sanitize_localpart(email);
        }
        return sanitize_localpart(email.substr(0, at_pos));
    }
};

// ============================================================================
// SsoSessionManager — Manage SSO login sessions
// ============================================================================

class SsoSessionManager {
public:
    SsoSessionManager() = default;

    // Create a new SSO login session
    SsoLoginSession create_session(
            const std::string& provider_id,
            const std::string& client_redirect_uri,
            const json& request_params = json{}) {
        SsoLoginSession session;
        session.session_id = generate_session_id();
        session.provider_id = provider_id;
        session.client_redirect_uri = client_redirect_uri;
        session.status = SsoSessionStatus::INITIALIZED;
        session.created_at = now_seconds();
        session.last_activity_at = session.created_at;
        session.expires_at = session.created_at + constants::SSO_SESSION_LIFETIME_SECS;
        session.initial_request_params = request_params;

        // Generate OAuth2 state and nonce
        session.oauth_state = generate_state_token();
        session.oauth_nonce = generate_nonce_token();

        // Store
        {
            std::lock_guard<std::mutex> lock(mutex_);
            sessions_[session.session_id] = session;
        }

        return session;
    }

    // Retrieve a session by ID
    std::optional<SsoLoginSession> get_session(const std::string& session_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            return std::nullopt;
        }

        auto session = it->second;
        if (session.is_expired()) {
            session.status = SsoSessionStatus::EXPIRED;
            it->second = session;
        }

        return session;
    }

    // Update an existing session
    bool update_session(const SsoLoginSession& session) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session.session_id);
        if (it == sessions_.end()) {
            return false;
        }
        it->second = session;
        it->second.last_activity_at = now_seconds();
        return true;
    }

    // Delete a session
    bool delete_session(const std::string& session_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return sessions_.erase(session_id) > 0;
    }

    // Find a session by OAuth2 state token
    std::optional<SsoLoginSession> find_by_oauth_state(
            const std::string& state) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, session] : sessions_) {
            if (session.oauth_state == state && session.is_active()) {
                return session;
            }
        }
        return std::nullopt;
    }

    // Find all active sessions for a provider
    std::vector<SsoLoginSession> get_provider_sessions(
            const std::string& provider_id) {
        std::vector<SsoLoginSession> result;
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, session] : sessions_) {
            if (session.provider_id == provider_id && session.is_active()) {
                result.push_back(session);
            }
        }
        return result;
    }

    // Clean up expired sessions
    size_t cleanup_expired() {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        auto it = sessions_.begin();
        while (it != sessions_.end()) {
            if (it->second.is_expired()) {
                it = sessions_.erase(it);
                count++;
            } else {
                ++it;
            }
        }
        return count;
    }

    // Get session count
    size_t active_session_count() {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (auto& [id, session] : sessions_) {
            if (session.is_active()) count++;
        }
        return count;
    }

    // Get all sessions (for admin API)
    std::vector<SsoLoginSession> all_sessions() {
        std::vector<SsoLoginSession> result;
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, session] : sessions_) {
            result.push_back(session);
        }
        return result;
    }

private:
    std::unordered_map<std::string, SsoLoginSession> sessions_;
    std::mutex mutex_;
};

// ============================================================================
// ProviderConfigManager — Manage OAuth2 provider configurations
// ============================================================================

class ProviderConfigManager {
public:
    ProviderConfigManager() = default;

    // Add or update a provider configuration
    void set_provider(const OAuth2ProviderConfig& config) {
        std::lock_guard<std::shared_mutex> lock(mutex_);
        providers_[config.provider_id] = config;
    }

    // Remove a provider configuration
    bool remove_provider(const std::string& provider_id) {
        std::lock_guard<std::shared_mutex> lock(mutex_);
        return providers_.erase(provider_id) > 0;
    }

    // Get a provider configuration
    std::optional<OAuth2ProviderConfig> get_provider(
            const std::string& provider_id) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = providers_.find(provider_id);
        if (it == providers_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    // Get all provider configurations (for admin API)
    std::vector<OAuth2ProviderConfig> all_providers() {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<OAuth2ProviderConfig> result;
        for (auto& [id, cfg] : providers_) {
            result.push_back(cfg);
        }
        // Sort by branding sort_order
        std::sort(result.begin(), result.end(),
                  [](const OAuth2ProviderConfig& a,
                     const OAuth2ProviderConfig& b) {
                      return a.branding.sort_order < b.branding.sort_order;
                  });
        return result;
    }

    // Get all enabled providers (for login page)
    std::vector<OAuth2ProviderConfig> enabled_providers() {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<OAuth2ProviderConfig> result;
        for (auto& [id, cfg] : providers_) {
            if (cfg.enabled) {
                result.push_back(cfg);
            }
        }
        std::sort(result.begin(), result.end(),
                  [](const OAuth2ProviderConfig& a,
                     const OAuth2ProviderConfig& b) {
                      return a.branding.sort_order < b.branding.sort_order;
                  });
        return result;
    }

    // Check if a provider exists
    bool has_provider(const std::string& provider_id) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return providers_.find(provider_id) != providers_.end();
    }

    // Get provider count
    size_t provider_count() {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return providers_.size();
    }

    // Load default/built-in providers
    void load_builtin_providers(
            const std::string& redirect_base_url,
            const json& credentials) {
        // Only load providers that have credentials configured
        if (credentials.contains("google")) {
            auto& creds = credentials["google"];
            if (creds.contains("client_id") && creds.contains("client_secret")) {
                auto cfg = make_google_provider(
                    creds["client_id"].get<std::string>(),
                    creds["client_secret"].get<std::string>(),
                    redirect_base_url);
                set_provider(cfg);
            }
        }

        if (credentials.contains("github")) {
            auto& creds = credentials["github"];
            if (creds.contains("client_id") && creds.contains("client_secret")) {
                auto cfg = make_github_provider(
                    creds["client_id"].get<std::string>(),
                    creds["client_secret"].get<std::string>(),
                    redirect_base_url);
                set_provider(cfg);
            }
        }

        if (credentials.contains("gitlab")) {
            auto& creds = credentials["gitlab"];
            if (creds.contains("client_id") && creds.contains("client_secret")) {
                auto cfg = make_gitlab_provider(
                    creds["client_id"].get<std::string>(),
                    creds["client_secret"].get<std::string>(),
                    redirect_base_url);
                set_provider(cfg);
            }
        }

        if (credentials.contains("facebook")) {
            auto& creds = credentials["facebook"];
            if (creds.contains("client_id") && creds.contains("client_secret")) {
                auto cfg = make_facebook_provider(
                    creds["client_id"].get<std::string>(),
                    creds["client_secret"].get<std::string>(),
                    redirect_base_url);
                set_provider(cfg);
            }
        }

        if (credentials.contains("apple")) {
            auto& creds = credentials["apple"];
            if (creds.contains("client_id") && creds.contains("client_secret")) {
                auto cfg = make_apple_provider(
                    creds["client_id"].get<std::string>(),
                    creds["client_secret"].get<std::string>(),
                    redirect_base_url);
                set_provider(cfg);
            }
        }

        if (credentials.contains("microsoft")) {
            auto& creds = credentials["microsoft"];
            if (creds.contains("client_id") && creds.contains("client_secret")) {
                auto cfg = make_microsoft_provider(
                    creds["client_id"].get<std::string>(),
                    creds["client_secret"].get<std::string>(),
                    redirect_base_url);
                set_provider(cfg);
            }
        }

        // Load any custom providers
        if (credentials.contains("custom_providers") &&
            credentials["custom_providers"].is_array()) {
            for (auto& custom_cfg : credentials["custom_providers"]) {
                auto cfg = OAuth2ProviderConfig::from_json(custom_cfg);
                cfg.kind = SsoProviderKind::CUSTOM;
                cfg.redirect_base_url = redirect_base_url;
                set_provider(cfg);
            }
        }
    }

    // Export all provider configs as JSON (for admin API)
    json export_configs() {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        json result = json::array();
        for (auto& [id, cfg] : providers_) {
            json provider_json = cfg.to_json();
            // Remove secret for export
            provider_json.erase("client_secret");
            result.push_back(provider_json);
        }
        return result;
    }

    // Export provider branding for login page
    json export_branding_for_login_page() {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        json result = json::array();
        for (auto& [id, cfg] : providers_) {
            if (!cfg.enabled) continue;
            json entry;
            entry["idp_id"] = cfg.provider_id;
            entry["idp_name"] = cfg.branding.idp_name;
            entry["idp_icon_url"] = cfg.branding.idp_icon_url;
            entry["idp_icon_mxc"] = cfg.branding.idp_icon_mxc;
            entry["brand_color_primary"] = cfg.branding.brand_color_primary;
            entry["brand_color_secondary"] = cfg.branding.brand_color_secondary;
            entry["button_text"] = cfg.branding.button_text;
            entry["button_css_class"] = cfg.branding.button_css_class;
            entry["login_page_title"] = cfg.branding.login_page_title;
            entry["login_page_subtitle"] = cfg.branding.login_page_subtitle;
            entry["sort_order"] = cfg.branding.sort_order;
            result.push_back(entry);
        }
        return result;
    }

private:
    std::unordered_map<std::string, OAuth2ProviderConfig> providers_;
    mutable std::shared_mutex mutex_;
};

// ============================================================================
// DiscoveryService — OIDC Provider Discovery
// ============================================================================

class DiscoveryService {
public:
    DiscoveryService() : oauth2_client_(std::make_unique<OAuth2Client>()) {}

    explicit DiscoveryService(std::unique_ptr<OAuth2Client> client)
        : oauth2_client_(std::move(client)) {}

    // Discover OIDC provider configuration from an issuer URL
    OidcDiscoveryDocument discover_from_issuer(
            const std::string& issuer,
            bool verify_ssl = true) {
        // Build discovery URL
        std::string iss = issuer;
        while (!iss.empty() && iss.back() == '/') iss.pop_back();
        std::string discovery_url = iss + constants::OIDC_DISCOVERY_PATH;

        return discover_from_url(discovery_url, verify_ssl);
    }

    // Discover from explicit discovery URL
    OidcDiscoveryDocument discover_from_url(
            const std::string& discovery_url,
            bool verify_ssl = true) {
        // Check cache first
        {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            auto it = discovery_cache_.find(discovery_url);
            if (it != discovery_cache_.end() && !it->second.is_expired()) {
                return it->second;
            }
        }

        // Fetch from provider
        OidcDiscoveryDocument doc =
            oauth2_client_->fetch_discovery_document(discovery_url, verify_ssl);

        // Cache it
        if (!doc.issuer.empty()) {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            discovery_cache_[discovery_url] = doc;
        }

        return doc;
    }

    // Apply discovered endpoints to a provider configuration
    OAuth2ProviderConfig apply_discovery(
            const OAuth2ProviderConfig& config) {
        if (!config.has_discovery_endpoint()) {
            return config;
        }

        std::string discovery_url = config.effective_discovery_url();
        OidcDiscoveryDocument doc = discover_from_url(
            discovery_url, config.verify_ssl);

        if (doc.issuer.empty()) {
            return config;  // Discovery failed, keep existing config
        }

        OAuth2ProviderConfig updated = config;

        // Apply discovered endpoints
        if (!doc.authorization_endpoint.empty())
            updated.authorization_endpoint = doc.authorization_endpoint;
        if (!doc.token_endpoint.empty())
            updated.token_endpoint = doc.token_endpoint;
        if (!doc.userinfo_endpoint.empty())
            updated.userinfo_endpoint = doc.userinfo_endpoint;
        if (!doc.jwks_uri.empty())
            updated.jwks_uri = doc.jwks_uri;
        if (!doc.revocation_endpoint.empty())
            updated.revocation_endpoint = doc.revocation_endpoint;
        if (!doc.end_session_endpoint.empty())
            updated.end_session_endpoint = doc.end_session_endpoint;

        // Apply supported scopes
        if (!doc.scopes_supported.empty()) {
            std::vector<std::string> common_scopes;
            for (auto& s : config.scopes) {
                if (std::find(doc.scopes_supported.begin(),
                              doc.scopes_supported.end(), s) !=
                    doc.scopes_supported.end()) {
                    common_scopes.push_back(s);
                }
            }
            if (!common_scopes.empty()) {
                updated.scopes = common_scopes;
            }
        }

        // Determine PKCE support
        if (!doc.code_challenge_methods_supported.empty()) {
            if (std::find(doc.code_challenge_methods_supported.begin(),
                          doc.code_challenge_methods_supported.end(), "S256") !=
                doc.code_challenge_methods_supported.end()) {
                updated.pkce_method = PkceMethod::S256;
            } else if (std::find(doc.code_challenge_methods_supported.begin(),
                                 doc.code_challenge_methods_supported.end(),
                                 "plain") !=
                       doc.code_challenge_methods_supported.end()) {
                updated.pkce_method = PkceMethod::PLAIN;
            } else {
                updated.require_pkce = false;
            }
        }

        // Store discovered config
        updated.discovery_last_fetched = doc.fetched_at;
        updated.discovered_config = doc.raw_document;

        return updated;
    }

    // Clear the discovery cache
    void clear_cache() {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        discovery_cache_.clear();
    }

private:
    std::unique_ptr<OAuth2Client> oauth2_client_;
    std::unordered_map<std::string, OidcDiscoveryDocument> discovery_cache_;
    std::mutex cache_mutex_;
};

// ============================================================================
// LoginTokenService — Issue and validate one-time login tokens
// ============================================================================

class LoginTokenService {
public:
    LoginTokenService() = default;

    // Issue a login token for a user
    std::string issue_token(const std::string& user_id) {
        std::string token = generate_login_token();

        LoginTokenEntry entry;
        entry.token = token;
        entry.user_id = user_id;
        entry.created_at = now_seconds();
        entry.expires_at = entry.created_at + constants::LOGIN_TOKEN_LIFETIME_SECS;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            tokens_[token] = entry;
        }

        return token;
    }

    // Validate a login token and return the user_id
    std::optional<std::string> validate_token(const std::string& token) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tokens_.find(token);
        if (it == tokens_.end()) {
            return std::nullopt;
        }

        if (it->second.used || now_seconds() > it->second.expires_at) {
            tokens_.erase(it);
            return std::nullopt;
        }

        it->second.used = true;
        std::string user_id = it->second.user_id;
        tokens_.erase(it);  // One-time use
        return user_id;
    }

    // Clean up expired tokens
    size_t cleanup_expired() {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        auto it = tokens_.begin();
        while (it != tokens_.end()) {
            if (it->second.used || now_seconds() > it->second.expires_at) {
                it = tokens_.erase(it);
                count++;
            } else {
                ++it;
            }
        }
        return count;
    }

private:
    struct LoginTokenEntry {
        std::string token;
        std::string user_id;
        int64_t     created_at = 0;
        int64_t     expires_at = 0;
        bool        used = false;
    };

    std::unordered_map<std::string, LoginTokenEntry> tokens_;
    std::mutex mutex_;
};

// ============================================================================
// SsoLoginFlow — The main SSO login flow orchestrator
// ============================================================================

class SsoLoginFlow {
public:
    SsoLoginFlow()
        : session_manager_(std::make_unique<SsoSessionManager>()),
          provider_manager_(std::make_unique<ProviderConfigManager>()),
          discovery_service_(std::make_unique<DiscoveryService>()),
          userinfo_mapper_(std::make_unique<OAuth2UserinfoMapper>()),
          oauth2_client_(std::make_unique<OAuth2Client>()),
          login_token_service_(std::make_unique<LoginTokenService>()) {}

    // ========================================================================
    // SSO Login Redirect — Start the SSO login flow
    // ========================================================================

    // Generate the SSO redirect for a client request
    SsoResult<std::string> start_sso_login(
            const std::string& provider_id,
            const std::string& client_redirect_uri,
            const std::string& matrix_server_name,
            const json& request_params = json{}) {

        // Validate provider exists and is enabled
        auto provider_opt = provider_manager_->get_provider(provider_id);
        if (!provider_opt.has_value()) {
            return SsoResult<std::string>::err(
                SsoError::make_provider_not_found(provider_id));
        }

        auto config = provider_opt.value();
        if (!config.enabled) {
            SsoError err;
            err.error_code = constants::ERR_PROVIDER_DISABLED;
            err.error_description = "SSO provider '" + provider_id + "' is disabled";
            err.category = SsoErrorCategory::CONFIG_ERROR;
            err.provider_id = provider_id;
            err.http_status = 403;
            return SsoResult<std::string>::err(err);
        }

        // Run discovery if needed and not recently done
        if (config.has_discovery_endpoint() &&
            (config.discovery_last_fetched == 0 ||
             (now_seconds() - config.discovery_last_fetched) >
              constants::PROVIDER_DISCOVERY_CACHE_SECS)) {
            config = discovery_service_->apply_discovery(config);
            provider_manager_->set_provider(config);
        }

        // Validate we have necessary endpoints
        if (config.authorization_endpoint.empty()) {
            return SsoResult<std::string>::err(
                SsoError::make_internal(
                    "Provider '" + provider_id +
                    "' has no authorization endpoint configured"));
        }

        // Create session
        auto session = session_manager_->create_session(
            provider_id, client_redirect_uri, request_params);
        session.mapped_user_id = ""; // Will be set after authentication
        session.status = SsoSessionStatus::REDIRECTING;

        // Generate PKCE params if required
        if (config.require_pkce) {
            session.pkce_params.generate();
        }

        // Build redirect URI
        std::string redirect_uri = build_callback_uri(
            config, session.session_id);

        // Build authorization URL
        std::string auth_url = oauth2_client_->build_authorization_url(
            config,
            session.oauth_state,
            session.oauth_nonce,
            session.pkce_params,
            redirect_uri,
            request_params.value("login_hint", ""));

        // Update session
        session_manager_->update_session(session);

        return SsoResult<std::string>::ok(auth_url);
    }

    // Get the list of available SSO providers for the login page
    json get_available_providers() {
        return provider_manager_->export_branding_for_login_page();
    }

    // ========================================================================
    // SSO Callback Handling — Process the OAuth2 callback from the IdP
    // ========================================================================

    // Handle the OAuth2 callback (GET /_matrix/client/r0/login/sso/redirect)
    SsoResult<json> handle_sso_callback(
            const std::string& state,
            const std::string& code,
            const std::string& error,
            const std::string& error_description,
            const std::string& matrix_server_name) {

        // Check for error from provider
        if (!error.empty()) {
            return SsoResult<json>::err(
                SsoError::make_provider_error(error, error_description));
        }

        // Validate state parameter
        if (state.empty()) {
            return SsoResult<json>::err(
                SsoError::make_internal("Missing state parameter in callback"));
        }

        // Find session by state
        auto session_opt = session_manager_->find_by_oauth_state(state);
        if (!session_opt.has_value()) {
            return SsoResult<json>::err(SsoError::make_state_mismatch());
        }

        auto session = session_opt.value();

        // Check session hasn't expired
        if (session.is_expired()) {
            session.status = SsoSessionStatus::EXPIRED;
            session_manager_->update_session(session);
            return SsoResult<json>::err(
                SsoError::make_session_expired(session.session_id));
        }

        // Validate authorization code
        if (code.empty()) {
            SsoError err;
            err.error_code = constants::ERR_INVALID_REQUEST;
            err.error_description = "Missing authorization code in callback";
            err.category = SsoErrorCategory::VALIDATION_ERROR;
            err.session_id = session.session_id;
            err.http_status = 400;
            return SsoResult<json>::err(err);
        }

        // Get provider config
        auto config_opt = provider_manager_->get_provider(session.provider_id);
        if (!config_opt.has_value()) {
            return SsoResult<json>::err(
                SsoError::make_provider_not_found(session.provider_id));
        }
        auto config = config_opt.value();

        // Build redirect URI
        std::string redirect_uri = build_callback_uri(config, session.session_id);

        // Exchange authorization code for tokens
        OAuth2TokenResponse token_response =
            oauth2_client_->exchange_code_for_tokens(
                config, code, session.pkce_params, redirect_uri);

        if (!token_response.success) {
            session.status = SsoSessionStatus::FAILED;
            session.error_code = token_response.error;
            session.error_description = token_response.error_description;
            session_manager_->update_session(session);

            return SsoResult<json>::err(
                SsoError::make_provider_error(
                    token_response.error, token_response.error_description));
        }

        // Store token response
        session.token_response = token_response;
        session.status = SsoSessionStatus::CALLBACK_RECEIVED;

        // Fetch userinfo
        json userinfo = oauth2_client_->fetch_userinfo(
            config, token_response.access_token);

        if (userinfo.contains("error")) {
            session.status = SsoSessionStatus::FAILED;
            session.error_code = constants::ERR_SERVER_ERROR;
            session.error_description = "Failed to fetch userinfo: " +
                userinfo["error"].get<std::string>();
            session_manager_->update_session(session);

            return SsoResult<json>::err(
                SsoError::make_internal(session.error_description));
        }

        // Store userinfo
        session.idp_raw_userinfo = userinfo;
        session.idp_raw_claims = userinfo;

        // Extract key claims
        session.idp_subject = extract_string(userinfo, "sub",
            extract_string(userinfo, "id", ""));
        session.idp_email = extract_string(userinfo, "email", "");
        session.idp_name = extract_string(userinfo, "name", "");
        session.idp_picture = extract_string(userinfo, "picture", "");
        session.idp_username = extract_string(userinfo, "preferred_username",
            extract_string(userinfo, "login", ""));

        // Map to Matrix profile
        MappedUserProfile profile = userinfo_mapper_->map_userinfo(
            config, userinfo, matrix_server_name);
        session.mapped_localpart = profile.localpart;
        session.mapped_user_id = profile.user_id;
        session.mapped_display_name = profile.display_name;
        session.mapped_avatar_url = profile.avatar_url;
        session.mapped_email = profile.email;

        session.status = SsoSessionStatus::AUTHENTICATED;
        session_manager_->update_session(session);

        // Build callback response
        json response;
        response["session_id"] = session.session_id;
        response["status"] = "authenticated";
        response["provider"] = config.provider_id;
        response["display_name"] = session.mapped_display_name;
        response["mapped_user_id"] = session.mapped_user_id;
        response["email"] = session.mapped_email;

        return SsoResult<json>::ok(response);
    }

    // ========================================================================
    // SSO Registration on First Login
    // ========================================================================

    // Register a new user from SSO session
    SsoResult<json> register_sso_user(
            const std::string& session_id,
            const std::string& desired_localpart,
            const std::string& matrix_server_name,
            bool admin = false) {

        auto session_opt = session_manager_->get_session(session_id);
        if (!session_opt.has_value()) {
            return SsoResult<json>::err(
                SsoError::make_session_expired(session_id));
        }

        auto session = session_opt.value();
        if (session.status != SsoSessionStatus::AUTHENTICATED) {
            SsoError err;
            err.error_code = "M_INVALID_SESSION_STATE";
            err.error_description =
                "Session is not in authenticated state. Current: " +
                std::to_string(static_cast<int>(session.status));
            err.session_id = session_id;
            err.http_status = 400;
            return SsoResult<json>::err(err);
        }

        // Determine localpart
        std::string localpart = desired_localpart;
        if (localpart.empty()) {
            localpart = session.mapped_localpart;
        }
        if (localpart.empty()) {
            localpart = "sso_" + session.idp_subject.substr(0, 16);
        }

        // Build user_id
        std::string user_id = "@" + localpart + ":" + matrix_server_name;

        // Simulate user registration
        // In production, this would call the registration handler
        session.mapped_localpart = localpart;
        session.mapped_user_id = user_id;
        session.status = SsoSessionStatus::REGISTERING;

        // Generate login token for the new user
        std::string login_token = login_token_service_->issue_token(user_id);
        session.login_token = login_token;

        session.status = SsoSessionStatus::COMPLETED;
        session_manager_->update_session(session);

        // Build registration response
        json response;
        response["user_id"] = user_id;
        response["access_token"] = "sso_registered_at_" + generate_state_token();
        response["device_id"] = "SSO_DEVICE_" + generate_state_token().substr(0, 8);
        response["login_token"] = login_token;
        response["home_server"] = matrix_server_name;
        response["well_known"] = json::object();
        response["is_new_user"] = true;

        // Include profile info if available
        if (!session.mapped_display_name.empty()) {
            response["display_name"] = session.mapped_display_name;
        }
        if (!session.mapped_avatar_url.empty()) {
            response["avatar_url"] = session.mapped_avatar_url;
        }

        return SsoResult<json>::ok(response);
    }

    // Get registration info for the UI (before finalizing registration)
    SsoResult<json> get_registration_info(
            const std::string& session_id) {
        auto session_opt = session_manager_->get_session(session_id);
        if (!session_opt.has_value()) {
            return SsoResult<json>::err(
                SsoError::make_session_expired(session_id));
        }

        auto& session = session_opt.value();
        if (session.status != SsoSessionStatus::AUTHENTICATED) {
            SsoError err;
            err.error_code = "M_INVALID_SESSION_STATE";
            err.error_description = "Session not ready for registration";
            err.session_id = session_id;
            err.http_status = 400;
            return SsoResult<json>::err(err);
        }

        json info;
        info["session_id"] = session.session_id;
        info["provider"] = session.provider_id;
        info["suggested_localpart"] = session.mapped_localpart;
        info["suggested_display_name"] = session.mapped_display_name;
        info["email"] = session.mapped_email;
        info["avatar_url"] = session.mapped_avatar_url;
        info["idp_name"] = session.idp_name;
        info["idp_email"] = session.idp_email;
        info["confirm_localpart"] = true;
        info["requires_email_verification"] = false;

        // Include provider branding for the registration page
        auto config_opt = provider_manager_->get_provider(session.provider_id);
        if (config_opt.has_value()) {
            info["branding"] = config_opt->branding.to_json();
        }

        return SsoResult<json>::ok(info);
    }

    // ========================================================================
    // SSO Account Linking — Link SSO identity to existing Matrix account
    // ========================================================================

    // Link SSO session to an existing user
    SsoResult<json> link_sso_to_existing_account(
            const std::string& session_id,
            const std::string& existing_user_id,
            const std::string& matrix_server_name) {

        auto session_opt = session_manager_->get_session(session_id);
        if (!session_opt.has_value()) {
            return SsoResult<json>::err(
                SsoError::make_session_expired(session_id));
        }

        auto session = session_opt.value();
        if (session.status != SsoSessionStatus::AUTHENTICATED) {
            SsoError err;
            err.error_code = "M_INVALID_SESSION_STATE";
            err.error_description = "Session is not in authenticated state";
            err.session_id = session_id;
            err.http_status = 400;
            return SsoResult<json>::err(err);
        }

        // Validate existing user
        if (existing_user_id.empty()) {
            SsoError err;
            err.error_code = constants::ERR_INVALID_REQUEST;
            err.error_description = "No existing user ID provided for linking";
            err.http_status = 400;
            return SsoResult<json>::err(err);
        }

        // In production: verify the existing user exists
        // In production: verify the requesting user owns the existing account

        session.existing_user_id = existing_user_id;
        session.link_decision = AccountLinkDecision::LINK_EXISTING;
        session.status = SsoSessionStatus::LINKING;

        // Store the SSO external ID mapping
        // In production: store in database: (idp_id, idp_subject) -> user_id
        std::string external_id = build_external_id(
            session.provider_id, session.idp_subject);

        // Generate login token
        std::string login_token = login_token_service_->issue_token(
            existing_user_id);
        session.login_token = login_token;

        session.status = SsoSessionStatus::COMPLETED;
        session_manager_->update_session(session);

        json response;
        response["user_id"] = existing_user_id;
        response["access_token"] = "sso_linked_at_" + generate_state_token();
        response["login_token"] = login_token;
        response["is_new_user"] = false;
        response["linked"] = true;
        response["external_id"] = external_id;

        return SsoResult<json>::ok(response);
    }

    // Get linking info — find if this SSO identity already has a linked account
    SsoResult<json> get_linking_info(
            const std::string& session_id) {
        auto session_opt = session_manager_->get_session(session_id);
        if (!session_opt.has_value()) {
            return SsoResult<json>::err(
                SsoError::make_session_expired(session_id));
        }

        auto& session = session_opt.value();

        json info;
        info["session_id"] = session.session_id;
        info["provider"] = session.provider_id;
        info["idp_subject"] = session.idp_subject;
        info["idp_name"] = session.idp_name;
        info["idp_email"] = session.idp_email;
        info["has_existing_link"] = false;  // Check DB in production

        return SsoResult<json>::ok(info);
    }

    // ========================================================================
    // OAuth2 Token Refresh
    // ========================================================================

    // Refresh an access token using a refresh token
    SsoResult<OAuth2TokenResponse> refresh_token(
            const std::string& provider_id,
            const std::string& refresh_token) {

        auto config_opt = provider_manager_->get_provider(provider_id);
        if (!config_opt.has_value()) {
            return SsoResult<OAuth2TokenResponse>::err(
                SsoError::make_provider_not_found(provider_id));
        }

        auto config = config_opt.value();

        OAuth2TokenResponse response =
            oauth2_client_->refresh_access_token(config, refresh_token);

        if (!response.success) {
            return SsoResult<OAuth2TokenResponse>::err(
                SsoError::make_provider_error(
                    response.error, response.error_description));
        }

        return SsoResult<OAuth2TokenResponse>::ok(response);
    }

    // Check if a stored token needs refresh and refresh if necessary
    SsoResult<OAuth2TokenResponse> ensure_fresh_token(
            const std::string& provider_id,
            OAuth2TokenResponse& current_token) {

        if (!current_token.needs_refresh()) {
            return SsoResult<OAuth2TokenResponse>::ok(current_token);
        }

        if (!current_token.has_refresh_token()) {
            SsoError err;
            err.error_code = constants::ERR_INVALID_GRANT;
            err.error_description =
                "Token expired and no refresh token available";
            err.category = SsoErrorCategory::VALIDATION_ERROR;
            err.http_status = 401;
            return SsoResult<OAuth2TokenResponse>::err(err);
        }

        return refresh_token(provider_id, current_token.refresh_token);
    }

    // ========================================================================
    // Provider Configuration Admin API
    // ========================================================================

    // List all provider configs
    json admin_list_providers() {
        return provider_manager_->export_configs();
    }

    // Get a specific provider config (without secrets)
    json admin_get_provider(const std::string& provider_id) {
        auto cfg_opt = provider_manager_->get_provider(provider_id);
        if (!cfg_opt.has_value()) {
            return json{{"error", "Provider not found"}};
        }
        json cfg = cfg_opt->to_json();
        cfg.erase("client_secret");
        return cfg;
    }

    // Create or update a provider configuration
    json admin_set_provider(const json& provider_config) {
        try {
            auto cfg = OAuth2ProviderConfig::from_json(provider_config);

            // Validate required fields
            if (cfg.provider_id.empty()) {
                return json{{"error", "provider_id is required"}};
            }
            if (cfg.client_id.empty()) {
                return json{{"error", "client_id is required"}};
            }

            // Run discovery if issuer/discovery_url is provided
            if (cfg.has_discovery_endpoint()) {
                cfg = discovery_service_->apply_discovery(cfg);
            }

            provider_manager_->set_provider(cfg);

            json result;
            result["success"] = true;
            result["provider_id"] = cfg.provider_id;
            result["message"] = "Provider configuration saved";
            return result;

        } catch (const std::exception& e) {
            return json{
                {"error", std::string("Invalid provider config: ") + e.what()}};
        }
    }

    // Delete a provider configuration
    json admin_delete_provider(const std::string& provider_id) {
        bool removed = provider_manager_->remove_provider(provider_id);
        json result;
        result["success"] = removed;
        result["provider_id"] = provider_id;
        result["message"] = removed
            ? "Provider configuration deleted"
            : "Provider not found";
        return result;
    }

    // Toggle provider enabled/disabled
    json admin_toggle_provider(const std::string& provider_id, bool enabled) {
        auto cfg_opt = provider_manager_->get_provider(provider_id);
        if (!cfg_opt.has_value()) {
            return json{{"error", "Provider not found"}};
        }
        auto cfg = cfg_opt.value();
        cfg.enabled = enabled;
        provider_manager_->set_provider(cfg);

        json result;
        result["success"] = true;
        result["provider_id"] = provider_id;
        result["enabled"] = enabled;
        return result;
    }

    // Test a provider connection (discovery + basic connectivity)
    json admin_test_provider(const std::string& provider_id) {
        auto cfg_opt = provider_manager_->get_provider(provider_id);
        if (!cfg_opt.has_value()) {
            return json{{"error", "Provider not found"}};
        }

        auto cfg = cfg_opt.value();
        json result;
        result["provider_id"] = provider_id;

        // Test discovery
        if (cfg.has_discovery_endpoint()) {
            std::string discovery_url = cfg.effective_discovery_url();
            OidcDiscoveryDocument doc =
                discovery_service_->discover_from_url(discovery_url);

            if (!doc.issuer.empty()) {
                result["discovery"] = "ok";
                result["discovered_issuer"] = doc.issuer;
                result["discovered_endpoints"] = json{
                    {"authorization_endpoint", doc.authorization_endpoint},
                    {"token_endpoint", doc.token_endpoint},
                    {"userinfo_endpoint", doc.userinfo_endpoint},
                    {"jwks_uri", doc.jwks_uri},
                };
            } else {
                result["discovery"] = "failed";
                result["discovery_error"] = "Could not fetch discovery document";
            }
        } else {
            result["discovery"] = "skipped (no discovery URL configured)";
        }

        // Validate endpoints are configured
        result["endpoints_configured"] = json{
            {"authorization", !cfg.authorization_endpoint.empty()},
            {"token", !cfg.token_endpoint.empty()},
            {"userinfo", !cfg.userinfo_endpoint.empty()},
        };

        return result;
    }

    // Get admin session statistics
    json admin_session_stats() {
        json stats;
        stats["active_sessions"] = session_manager_->active_session_count();
        stats["total_providers"] = provider_manager_->provider_count();
        return stats;
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    // Get session status
    SsoResult<json> get_session_status(const std::string& session_id) {
        auto session_opt = session_manager_->get_session(session_id);
        if (!session_opt.has_value()) {
            return SsoResult<json>::err(
                SsoError::make_session_expired(session_id));
        }

        auto& session = session_opt.value();

        json status;
        status["session_id"] = session.session_id;
        status["status"] = sso_session_status_to_string(session.status);
        status["provider_id"] = session.provider_id;

        if (session.status == SsoSessionStatus::COMPLETED) {
            status["user_id"] = session.mapped_user_id;
            status["login_token"] = session.login_token;
        }

        if (session.status == SsoSessionStatus::FAILED) {
            status["error_code"] = session.error_code;
            status["error_description"] = session.error_description;
        }

        return SsoResult<json>::ok(status);
    }

    // Cancel an active SSO session
    SsoResult<json> cancel_session(const std::string& session_id) {
        auto session_opt = session_manager_->get_session(session_id);
        if (!session_opt.has_value()) {
            return SsoResult<json>::err(
                SsoError::make_session_expired(session_id));
        }

        auto session = session_opt.value();
        session.status = SsoSessionStatus::CANCELLED;
        session_manager_->update_session(session);

        json result;
        result["session_id"] = session_id;
        result["status"] = "cancelled";
        return SsoResult<json>::ok(result);
    }

    // Validate a login token and complete the login
    SsoResult<json> complete_login_with_token(
            const std::string& login_token) {
        auto user_id_opt = login_token_service_->validate_token(login_token);
        if (!user_id_opt.has_value()) {
            SsoError err;
            err.error_code = constants::ERR_INVALID_GRANT;
            err.error_description = "Invalid or expired login token";
            err.category = SsoErrorCategory::VALIDATION_ERROR;
            err.http_status = 401;
            return SsoResult<json>::err(err);
        }

        json response;
        response["user_id"] = user_id_opt.value();
        response["access_token"] = "sso_final_at_" + generate_state_token();
        response["device_id"] = "SSO_DEV_" + generate_state_token().substr(0, 8);
        return SsoResult<json>::ok(response);
    }

    // ========================================================================
    // Maintenance
    // ========================================================================

    // Periodic cleanup of expired sessions and tokens
    json run_maintenance() {
        size_t sessions_cleaned = session_manager_->cleanup_expired();
        size_t tokens_cleaned = login_token_service_->cleanup_expired();

        json result;
        result["expired_sessions_removed"] = sessions_cleaned;
        result["expired_tokens_removed"] = tokens_cleaned;
        return result;
    }

    // Clear discovery cache
    void clear_discovery_cache() {
        discovery_service_->clear_cache();
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    ProviderConfigManager& provider_manager() { return *provider_manager_; }
    SsoSessionManager& session_manager() { return *session_manager_; }

private:
    std::unique_ptr<SsoSessionManager> session_manager_;
    std::unique_ptr<ProviderConfigManager> provider_manager_;
    std::unique_ptr<DiscoveryService> discovery_service_;
    std::unique_ptr<OAuth2UserinfoMapper> userinfo_mapper_;
    std::unique_ptr<OAuth2Client> oauth2_client_;
    std::unique_ptr<LoginTokenService> login_token_service_;

    // Build the callback URI for a provider
    std::string build_callback_uri(
            const OAuth2ProviderConfig& config,
            const std::string& session_id) {
        std::string base = config.redirect_base_url;
        if (base.empty()) {
            base = "/_matrix/client/r0/login/sso/redirect";
        }
        while (!base.empty() && base.back() == '/') base.pop_back();
        return base + "/" + config.provider_id + "/callback?session=" + session_id;
    }

    // Build external ID string for account linking
    std::string build_external_id(
            const std::string& provider_id,
            const std::string& subject) {
        return provider_id + ":" + subject;
    }

    // Helper to extract string from JSON
    static std::string extract_string(
            const json& obj,
            const std::string& key,
            const std::string& default_val = "") {
        if (obj.contains(key) && obj[key].is_string()) {
            return obj[key].get<std::string>();
        }
        return default_val;
    }

    // Convert session status enum to string
    static std::string sso_session_status_to_string(SsoSessionStatus status) {
        switch (status) {
            case SsoSessionStatus::INITIALIZED:       return "initialized";
            case SsoSessionStatus::REDIRECTING:       return "redirecting";
            case SsoSessionStatus::AWAITING_CALLBACK: return "awaiting_callback";
            case SsoSessionStatus::CALLBACK_RECEIVED: return "callback_received";
            case SsoSessionStatus::AUTHENTICATED:     return "authenticated";
            case SsoSessionStatus::REGISTERING:       return "registering";
            case SsoSessionStatus::LINKING:           return "linking";
            case SsoSessionStatus::COMPLETED:         return "completed";
            case SsoSessionStatus::FAILED:            return "failed";
            case SsoSessionStatus::EXPIRED:           return "expired";
            case SsoSessionStatus::CANCELLED:         return "cancelled";
            default:                                  return "unknown";
        }
    }
};

// ============================================================================
// SsoLoginFlowBuilder — Convenience builder for SsoLoginFlow
// ============================================================================

class SsoLoginFlowBuilder {
public:
    SsoLoginFlowBuilder() : flow_(std::make_unique<SsoLoginFlow>()) {}

    SsoLoginFlowBuilder& with_google(
            const std::string& client_id,
            const std::string& client_secret,
            const std::string& redirect_base) {
        auto cfg = make_google_provider(client_id, client_secret, redirect_base);
        flow_->provider_manager().set_provider(cfg);
        return *this;
    }

    SsoLoginFlowBuilder& with_github(
            const std::string& client_id,
            const std::string& client_secret,
            const std::string& redirect_base) {
        auto cfg = make_github_provider(client_id, client_secret, redirect_base);
        flow_->provider_manager().set_provider(cfg);
        return *this;
    }

    SsoLoginFlowBuilder& with_gitlab(
            const std::string& client_id,
            const std::string& client_secret,
            const std::string& redirect_base) {
        auto cfg = make_gitlab_provider(client_id, client_secret, redirect_base);
        flow_->provider_manager().set_provider(cfg);
        return *this;
    }

    SsoLoginFlowBuilder& with_facebook(
            const std::string& client_id,
            const std::string& client_secret,
            const std::string& redirect_base) {
        auto cfg = make_facebook_provider(client_id, client_secret, redirect_base);
        flow_->provider_manager().set_provider(cfg);
        return *this;
    }

    SsoLoginFlowBuilder& with_apple(
            const std::string& client_id,
            const std::string& client_secret,
            const std::string& redirect_base) {
        auto cfg = make_apple_provider(client_id, client_secret, redirect_base);
        flow_->provider_manager().set_provider(cfg);
        return *this;
    }

    SsoLoginFlowBuilder& with_microsoft(
            const std::string& client_id,
            const std::string& client_secret,
            const std::string& redirect_base) {
        auto cfg = make_microsoft_provider(client_id, client_secret, redirect_base);
        flow_->provider_manager().set_provider(cfg);
        return *this;
    }

    SsoLoginFlowBuilder& with_custom_provider(
            const OAuth2ProviderConfig& config) {
        auto cfg = config;
        cfg.kind = SsoProviderKind::CUSTOM;
        flow_->provider_manager().set_provider(cfg);
        return *this;
    }

    SsoLoginFlowBuilder& with_credentials(
            const std::string& redirect_base,
            const json& credentials) {
        flow_->provider_manager().load_builtin_providers(
            redirect_base, credentials);
        return *this;
    }

    std::unique_ptr<SsoLoginFlow> build() {
        return std::move(flow_);
    }

private:
    std::unique_ptr<SsoLoginFlow> flow_;
};

// ============================================================================
// Global SSO Login Flow Instance
// ============================================================================

static std::unique_ptr<SsoLoginFlow> g_sso_login_flow;
static std::mutex g_sso_login_flow_mutex;

// Initialize the global SSO login flow
void init_sso_login_flow() {
    std::lock_guard<std::mutex> lock(g_sso_login_flow_mutex);
    if (!g_sso_login_flow) {
        g_sso_login_flow = std::make_unique<SsoLoginFlow>();
    }
}

// Initialize with builder
void init_sso_login_flow(std::unique_ptr<SsoLoginFlow> flow) {
    std::lock_guard<std::mutex> lock(g_sso_login_flow_mutex);
    g_sso_login_flow = std::move(flow);
}

// Get the global SSO login flow
SsoLoginFlow& get_sso_login_flow() {
    if (!g_sso_login_flow) {
        init_sso_login_flow();
    }
    return *g_sso_login_flow;
}

// ============================================================================
// Utility Function Implementations
// ============================================================================

static std::string url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : value) {
        if (std::isalnum(static_cast<unsigned char>(c)) ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2)
                    << static_cast<int>(static_cast<unsigned char>(c));
            escaped << std::nouppercase;
        }
    }
    return escaped.str();
}

static std::string url_decode(const std::string& value) {
    std::ostringstream decoded;
    for (size_t i = 0; i < value.size(); i++) {
        if (value[i] == '%' && i + 2 < value.size()) {
            int hex_val;
            std::istringstream iss(value.substr(i + 1, 2));
            iss >> std::hex >> hex_val;
            decoded << static_cast<char>(hex_val);
            i += 2;
        } else if (value[i] == '+') {
            decoded << ' ';
        } else {
            decoded << value[i];
        }
    }
    return decoded.str();
}

static std::string base64url_encode(const std::string& data) {
    static const char* table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);
    int val = 0;
    int valb = -6;
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        result.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    // Remove padding
    while (!result.empty() && result.back() == '=') result.pop_back();
    return result;
}

static std::string base64url_decode(const std::string& data) {
    // Add padding
    std::string padded = data;
    while (padded.size() % 4 != 0) padded += '=';
    // Replace URL-safe chars
    for (char& c : padded) {
        if (c == '-') c = '+';
        if (c == '_') c = '/';
    }
    // Decode
    static const std::string table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[static_cast<unsigned char>(table[i])] = i;
    int val = 0, valb = -8;
    for (unsigned char c : padded) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            result.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return result;
}

static std::string sha256_hex(const std::string& data) {
    // Simulated SHA-256: in production, use OpenSSL or similar
    // Return a deterministic-looking hash based on input
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    for (size_t i = 0; i < data.size(); i++) {
        h[i % 8] ^= static_cast<unsigned char>(data[i]) << ((i % 4) * 8);
        h[i % 8] = (h[i % 8] * 1103515245 + 12345) & 0xFFFFFFFF;
    }
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; i++) {
        oss << std::setw(8) << h[i];
    }
    return oss.str();
}

static std::string hmac_sha256(
        const std::string& key, const std::string& data) {
    // Simulated HMAC-SHA256
    std::string combined = key + "::hmac::" + data;
    return sha256_hex(combined);
}

static std::string generate_uuid() {
    std::string hex = random_hex_string(32);
    // Format: 8-4-4-4-12
    return hex.substr(0, 8) + "-" +
           hex.substr(8, 4) + "-" +
           hex.substr(12, 4) + "-" +
           hex.substr(16, 4) + "-" +
           hex.substr(20, 12);
}

static std::string generate_state_token() {
    return random_hex_string(constants::STATE_LENGTH);
}

static std::string generate_pkce_verifier() {
    static const char* chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    std::string result;
    result.reserve(constants::PKCE_VERIFIER_LENGTH);
    for (int i = 0; i < constants::PKCE_VERIFIER_LENGTH; i++) {
        result += chars[rand() % 66];
    }
    return result;
}

static std::string generate_pkce_challenge(const std::string& verifier) {
    std::string hash = sha256_hex(verifier);
    return base64url_encode(hash.substr(0, 32));
}

static std::string generate_nonce_token() {
    return random_hex_string(constants::NONCE_LENGTH);
}

static std::string generate_session_id() {
    return "sso_session_" + random_hex_string(constants::SESSION_ID_LENGTH);
}

static std::string generate_login_token() {
    return "m.login.token." + random_hex_string(constants::LOGIN_TOKEN_LENGTH);
}

static int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static int64_t now_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static std::string random_hex_string(size_t length) {
    static const char* hex_chars = "0123456789abcdef";
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; i++) {
        result += hex_chars[rand() % 16];
    }
    return result;
}

static bool is_valid_redirect_uri(
        const std::string& uri,
        const std::vector<std::string>& allowed) {
    if (allowed.empty()) return true;
    for (const auto& allowed_uri : allowed) {
        if (uri.find(allowed_uri) == 0) return true;
    }
    return false;
}

static std::string join_strings(
        const std::vector<std::string>& vec,
        const std::string& separator) {
    std::string result;
    for (size_t i = 0; i < vec.size(); i++) {
        if (i > 0) result += separator;
        result += vec[i];
    }
    return result;
}

static std::string template_replace(
        const std::string& tmpl, const json& context) {
    return tmpl; // Simplified; real implementation would parse {{ }} templates
}

// ============================================================================
// SSO Login Flow API — Convenience free functions for external callers
// ============================================================================

json start_sso_login_api(
        const std::string& provider_id,
        const std::string& redirect_uri,
        const std::string& server_name,
        const json& params) {
    auto result = get_sso_login_flow().start_sso_login(
        provider_id, redirect_uri, server_name, params);

    if (!result.success) {
        json err;
        err["errcode"] = result.error.error_code;
        err["error"] = result.error.error_description;
        err["http_status"] = result.error.http_status;
        return err;
    }

    json response;
    response["redirect_url"] = result.value;
    response["flow_type"] = constants::LOGIN_TYPE_SSO;
    return response;
}

json handle_sso_callback_api(
        const std::string& state,
        const std::string& code,
        const std::string& error,
        const std::string& error_description,
        const std::string& server_name) {
    auto result = get_sso_login_flow().handle_sso_callback(
        state, code, error, error_description, server_name);

    if (!result.success) {
        json err;
        err["errcode"] = result.error.error_code;
        err["error"] = result.error.error_description;
        return err;
    }

    return result.value;
}

json register_sso_user_api(
        const std::string& session_id,
        const std::string& localpart,
        const std::string& server_name) {
    auto result = get_sso_login_flow().register_sso_user(
        session_id, localpart, server_name);

    if (!result.success) {
        json err;
        err["errcode"] = result.error.error_code;
        err["error"] = result.error.error_description;
        return err;
    }

    return result.value;
}

json link_sso_account_api(
        const std::string& session_id,
        const std::string& existing_user_id,
        const std::string& server_name) {
    auto result = get_sso_login_flow().link_sso_to_existing_account(
        session_id, existing_user_id, server_name);

    if (!result.success) {
        json err;
        err["errcode"] = result.error.error_code;
        err["error"] = result.error.error_description;
        return err;
    }

    return result.value;
}

json complete_sso_login_api(const std::string& login_token) {
    auto result = get_sso_login_flow().complete_login_with_token(login_token);

    if (!result.success) {
        json err;
        err["errcode"] = result.error.error_code;
        err["error"] = result.error.error_description;
        return err;
    }

    return result.value;
}

// ============================================================================
// End namespace
// ============================================================================

} // namespace progressive::sso
