// =============================================================================
// interactive_auth_terms.cpp
// Progressive Matrix Server - User-Interactive Authentication & Terms of Service
// =============================================================================
//
// Implements the complete User-Interactive Authentication (UIA) framework as
// specified in the Matrix Client-Server API, plus Terms of Service management,
// consent tracking, and enforcement.
//
// Namespace: progressive::auth
// Dependencies: ../json.hpp (nlohmann/json single-header)
// =============================================================================

#include <string>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <optional>
#include <variant>
#include <functional>
#include <chrono>
#include <random>
#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <regex>

#include "../json.hpp"

using json = nlohmann::json;

// =============================================================================
// Forward declarations & namespace
// =============================================================================

namespace progressive {
namespace auth {

// Forward declarations
class AuthSession;
class AuthStage;
class TermsOfServiceManager;
class ConsentTracker;
class PrivacyPolicyManager;
class UIAHandler;

// =============================================================================
// Constants & Configuration
// =============================================================================

constexpr std::chrono::seconds DEFAULT_SESSION_TIMEOUT{300};       // 5 minutes
constexpr std::chrono::seconds DEFAULT_SESSION_CLEANUP_INTERVAL{60}; // 1 minute
constexpr size_t MAX_SESSION_STAGES{10};
constexpr size_t SESSION_ID_LENGTH{32};
constexpr size_t MAX_TERMS_VERSIONS{100};
constexpr size_t MAX_CONSENT_RECORDS_PER_USER{500};

// Supported auth types
const std::set<std::string> SUPPORTED_AUTH_TYPES = {
    "m.login.password",
    "m.login.recaptcha",
    "m.login.email.identity",
    "m.login.msisdn",
    "m.login.sso",
    "m.login.dummy",
    "m.login.terms",
    "m.login.token"
};

// =============================================================================
// Utility Functions
// =============================================================================

namespace {

std::string generate_session_id() {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    static thread_local std::mt19937 rng(
        std::random_device{}() ^
        static_cast<uint32_t>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<> dist(0, sizeof(alphanum) - 2);
    std::string id;
    id.reserve(SESSION_ID_LENGTH);
    for (size_t i = 0; i < SESSION_ID_LENGTH; ++i) {
        id.push_back(alphanum[dist(rng)]);
    }
    return id;
}

std::string make_error_json(const std::string& errcode, const std::string& error) {
    json j;
    j["errcode"] = errcode;
    j["error"] = error;
    return j.dump();
}

int64_t now_epoch_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string sha256_hex(const std::string& data) {
    // Inlined SHA-256 for self-contained implementation
    static const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92c,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0c3c,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    auto rotr = [](uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); };
    auto ch  = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); };
    auto maj = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); };
    auto S0  = [&](uint32_t x) { return rotr(x,2)^rotr(x,13)^rotr(x,22); };
    auto S1  = [&](uint32_t x) { return rotr(x,6)^rotr(x,11)^rotr(x,25); };
    auto s0  = [&](uint32_t x) { return rotr(x,7)^rotr(x,18)^(x>>3); };
    auto s1  = [&](uint32_t x) { return rotr(x,17)^rotr(x,19)^(x>>10); };

    std::vector<uint8_t> msg(data.begin(), data.end());
    uint64_t bit_len = msg.size() * 8;
    msg.push_back(0x80);
    while ((msg.size() + 8) % 64 != 0) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i) msg.push_back((bit_len >> (i * 8)) & 0xff);

    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

    for (size_t i = 0; i < msg.size(); i += 64) {
        uint32_t w[64];
        for (int t = 0; t < 16; ++t)
            w[t] = (msg[i+t*4]<<24)|(msg[i+t*4+1]<<16)|(msg[i+t*4+2]<<8)|msg[i+t*4+3];
        for (int t = 16; t < 64; ++t)
            w[t] = s1(w[t-2]) + w[t-7] + s0(w[t-15]) + w[t-16];

        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int t = 0; t < 64; ++t) {
            uint32_t t1 = hh + S1(e) + ch(e,f,g) + k[t] + w[t];
            uint32_t t2 = S0(a) + maj(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; ++i) oss << std::setw(8) << h[i];
    return oss.str();
}

} // anonymous namespace

// =============================================================================
// AuthStage - Abstract base for individual authentication stages
// =============================================================================

class AuthStage {
public:
    virtual ~AuthStage() = default;

    /// The Matrix auth type identifier (e.g., "m.login.password")
    virtual std::string auth_type() const = 0;

    /// Return the params dict that clients need to complete this stage.
    /// Empty object means no additional params are required.
    virtual json stage_params(const std::string& session_id) const {
        (void)session_id;
        return json::object();
    }

    /// Attempt to authenticate using the provided auth dict for this stage.
    /// Returns true if the stage completed successfully.
    virtual bool authenticate(const std::string& session_id,
                              const std::string& user_id,
                              const json& auth_dict) = 0;

    /// Called when a session is destroyed to clean up stage-specific state.
    virtual void cleanup_session(const std::string& session_id) {
        (void)session_id;
    }

    /// Whether this stage requires user interaction (vs being auto-completable).
    virtual bool requires_user_interaction() const { return true; }
};

// =============================================================================
// PasswordAuthStage - m.login.password
// =============================================================================

class PasswordAuthStage : public AuthStage {
public:
    struct UserCredentials {
        std::string password_hash;
        std::string salt;
        std::string hash_algorithm;
    };

    explicit PasswordAuthStage(
        std::function<std::optional<UserCredentials>(const std::string&)> lookup)
        : lookup_fn_(std::move(lookup)) {}

    std::string auth_type() const override { return "m.login.password"; }

    json stage_params(const std::string&) const override {
        return json::object();
    }

    bool authenticate(const std::string& session_id,
                      const std::string& user_id,
                      const json& auth_dict) override {
        (void)session_id;
        if (!auth_dict.contains("password")) return false;
        std::string password = auth_dict["password"].get<std::string>();

        if (auth_dict.contains("identifier")) {
            // In a real implementation, resolve identifier to user_id
            const auto& ident = auth_dict["identifier"];
            if (ident.contains("user")) {
                // user_id already provided
            }
        }

        auto creds = lookup_fn_(user_id);
        if (!creds) return false;

        std::string computed;
        if (creds->hash_algorithm == "sha256") {
            computed = sha256_hex(password + creds->salt);
        } else {
            // Default to sha256
            computed = sha256_hex(password + creds->salt);
        }

        if (computed != creds->password_hash) return false;

        // Mark as completed
        completed_sessions_.insert(session_id);
        return true;
    }

    void cleanup_session(const std::string& session_id) override {
        completed_sessions_.erase(session_id);
    }

private:
    std::function<std::optional<UserCredentials>(const std::string&)> lookup_fn_;
    std::unordered_set<std::string> completed_sessions_;
};

// =============================================================================
// ReCaptchaAuthStage - m.login.recaptcha
// =============================================================================

class ReCaptchaAuthStage : public AuthStage {
public:
    struct Config {
        std::string public_key;
        std::string private_key;
        std::string verify_url = "https://www.google.com/recaptcha/api/siteverify";
        bool enabled = true;
    };

    explicit ReCaptchaAuthStage(Config config) : config_(std::move(config)) {}

    std::string auth_type() const override { return "m.login.recaptcha"; }

    json stage_params(const std::string&) const override {
        json params;
        if (config_.enabled && !config_.public_key.empty()) {
            params["public_key"] = config_.public_key;
        }
        return params;
    }

    bool authenticate(const std::string& session_id,
                      const std::string& user_id,
                      const json& auth_dict) override {
        (void)user_id;
        if (!config_.enabled) return true; // Bypass if disabled

        if (!auth_dict.contains("response")) return false;
        std::string response = auth_dict["response"].get<std::string>();

        // In production, verify with Google's API.
        // Here we accept any non-empty response for testing.
        if (response.empty()) return false;

        completed_sessions_.insert(session_id);
        return true;
    }

    void cleanup_session(const std::string& session_id) override {
        completed_sessions_.erase(session_id);
    }

private:
    Config config_;
    std::unordered_set<std::string> completed_sessions_;
};

// =============================================================================
// EmailIdentityAuthStage - m.login.email.identity
// =============================================================================

class EmailIdentityAuthStage : public AuthStage {
public:
    struct PendingVerification {
        std::string email;
        std::string code;
        int64_t expires_at;
        int attempts;
    };

    struct Config {
        std::string smtp_host;
        int smtp_port = 587;
        std::string smtp_username;
        std::string smtp_password;
        std::string from_address;
        std::string email_subject_template = "Your verification code: {{code}}";
        std::string email_body_template = "Enter this code to verify: {{code}}";
        int code_length = 6;
        int max_attempts = 3;
        std::chrono::seconds code_ttl{600}; // 10 minutes
    };

    explicit EmailIdentityAuthStage(Config config) : config_(std::move(config)) {}

    std::string auth_type() const override { return "m.login.email.identity"; }

    json stage_params(const std::string& session_id) const override {
        json params;
        // Only return params if a verification is pending for this session
        std::shared_lock lock(mutex_);
        auto it = pending_.find(session_id);
        if (it != pending_.end()) {
            params["threepid_creds"] = json::object();
            // Don't expose the email directly as per spec in some cases;
            // but since client already knows its email, we include a masked version
            params["threepid_creds"]["client_secret"] = session_id.substr(0, 8);
        }
        return params;
    }

    bool request_token(const std::string& session_id,
                       const std::string& email,
                       const std::string& client_secret,
                       int send_attempt) {
        (void)client_secret;
        std::unique_lock lock(mutex_);

        PendingVerification pv;
        pv.email = email;
        pv.code = generate_code_();
        pv.expires_at = now_epoch_ms() +
            std::chrono::duration_cast<std::chrono::milliseconds>(config_.code_ttl).count();
        pv.attempts = 0;

        pending_[session_id] = std::move(pv);

        // In production, send email via SMTP
        send_email_(email, pending_[session_id].code, send_attempt);
        return true;
    }

    bool authenticate(const std::string& session_id,
                      const std::string& user_id,
                      const json& auth_dict) override {
        (void)user_id;
        std::unique_lock lock(mutex_);

        auto it = pending_.find(session_id);
        if (it == pending_.end()) return false;

        if (now_epoch_ms() > it->second.expires_at) {
            pending_.erase(it);
            return false;
        }

        if (it->second.attempts >= config_.max_attempts) {
            pending_.erase(it);
            return false;
        }

        std::string submitted_code;
        if (auth_dict.contains("threepid_creds")) {
            const auto& creds = auth_dict["threepid_creds"];
            if (creds.contains("client_secret") && creds.contains("sid")) {
                submitted_code = auth_dict.value("token", "");
            }
        } else if (auth_dict.contains("token")) {
            submitted_code = auth_dict["token"].get<std::string>();
        }

        it->second.attempts++;

        if (submitted_code != it->second.code) return false;

        // Success - record email association
        verified_emails_[user_id].insert(it->second.email);
        completed_sessions_.insert(session_id);
        pending_.erase(it);
        return true;
    }

    std::set<std::string> get_verified_emails(const std::string& user_id) const {
        std::shared_lock lock(mutex_);
        auto it = verified_emails_.find(user_id);
        if (it != verified_emails_.end()) return it->second;
        return {};
    }

    void cleanup_session(const std::string& session_id) override {
        std::unique_lock lock(mutex_);
        pending_.erase(session_id);
        completed_sessions_.erase(session_id);
    }

private:
    std::string generate_code_() {
        static thread_local std::mt19937 rng(
            std::random_device{}() ^
            static_cast<uint32_t>(
                std::chrono::steady_clock::now().time_since_epoch().count()));
        std::uniform_int_distribution<> dist(0, 9);
        std::string code;
        code.reserve(config_.code_length);
        for (int i = 0; i < config_.code_length; ++i) {
            code.push_back('0' + dist(rng));
        }
        return code;
    }

    void send_email_(const std::string& to, const std::string& code, int attempt) {
        // Stub: In production, integrate with SMTP library
        (void)to;
        (void)code;
        (void)attempt;
    }

    Config config_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, PendingVerification> pending_;
    std::unordered_map<std::string, std::set<std::string>> verified_emails_;
    std::unordered_set<std::string> completed_sessions_;
};

// =============================================================================
// MSISDNAuthStage - m.login.msisdn
// =============================================================================

class MSISDNAuthStage : public AuthStage {
public:
    struct PendingSMS {
        std::string msisdn;
        std::string code;
        int64_t expires_at;
        int attempts;
        std::string client_secret;
    };

    struct Config {
        std::string sms_provider; // "twilio", "nexmo", etc.
        std::string account_sid;
        std::string auth_token;
        std::string from_number;
        std::string message_template = "Your verification code: {{code}}";
        int code_length = 6;
        int max_attempts = 3;
        std::chrono::seconds code_ttl{600};
        int resend_cooldown_seconds = 60;
    };

    explicit MSISDNAuthStage(Config config) : config_(std::move(config)) {}

    std::string auth_type() const override { return "m.login.msisdn"; }

    json stage_params(const std::string& session_id) const override {
        json params;
        std::shared_lock lock(mutex_);
        auto it = pending_.find(session_id);
        if (it != pending_.end()) {
            params["threepid_creds"]["client_secret"] = it->second.client_secret;
            params["threepid_creds"]["sid"] = session_id;
        }
        return params;
    }

    bool request_token(const std::string& session_id,
                       const std::string& country,
                       const std::string& phone_number,
                       const std::string& client_secret,
                       int send_attempt) {
        std::unique_lock lock(mutex_);

        std::string msisdn = country + phone_number;

        // Rate limit: check cooldown
        auto now = now_epoch_seconds();
        auto rit = last_resend_.find(session_id);
        if (rit != last_resend_.end() && send_attempt > 1) {
            if (now - rit->second < config_.resend_cooldown_seconds) {
                return false;
            }
        }
        last_resend_[session_id] = now;

        PendingSMS ps;
        ps.msisdn = msisdn;
        ps.code = generate_code_();
        ps.expires_at = now_epoch_ms() +
            std::chrono::duration_cast<std::chrono::milliseconds>(config_.code_ttl).count();
        ps.attempts = 0;
        ps.client_secret = client_secret;

        pending_[session_id] = std::move(ps);

        // In production, send SMS via provider
        send_sms_(msisdn, pending_[session_id].code);
        return true;
    }

    bool authenticate(const std::string& session_id,
                      const std::string& user_id,
                      const json& auth_dict) override {
        std::unique_lock lock(mutex_);

        auto it = pending_.find(session_id);
        if (it == pending_.end()) return false;

        if (now_epoch_ms() > it->second.expires_at) {
            pending_.erase(it);
            return false;
        }

        if (it->second.attempts >= config_.max_attempts) {
            pending_.erase(it);
            return false;
        }

        std::string token;
        if (auth_dict.contains("threepid_creds")) {
            const auto& creds = auth_dict["threepid_creds"];
            if (creds.contains("sid") && creds["sid"].get<std::string>() == session_id) {
                token = auth_dict.value("token", "");
            }
        } else if (auth_dict.contains("token")) {
            token = auth_dict["token"].get<std::string>();
        }

        it->second.attempts++;

        if (token != it->second.code) return false;

        verified_msisdns_[user_id].insert(it->second.msisdn);
        completed_sessions_.insert(session_id);
        pending_.erase(it);
        return true;
    }

    std::set<std::string> get_verified_msisdns(const std::string& user_id) const {
        std::shared_lock lock(mutex_);
        auto it = verified_msisdns_.find(user_id);
        if (it != verified_msisdns_.end()) return it->second;
        return {};
    }

    void cleanup_session(const std::string& session_id) override {
        std::unique_lock lock(mutex_);
        pending_.erase(session_id);
        completed_sessions_.erase(session_id);
        last_resend_.erase(session_id);
    }

private:
    std::string generate_code_() {
        static thread_local std::mt19937 rng(
            std::random_device{}() ^
            static_cast<uint32_t>(
                std::chrono::steady_clock::now().time_since_epoch().count()));
        std::uniform_int_distribution<> dist(0, 9);
        std::string code;
        code.reserve(config_.code_length);
        for (int i = 0; i < config_.code_length; ++i) {
            code.push_back('0' + dist(rng));
        }
        return code;
    }

    void send_sms_(const std::string& to, const std::string& code) {
        // Stub: integrate with SMS provider in production
        (void)to;
        (void)code;
    }

    Config config_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, PendingSMS> pending_;
    std::unordered_map<std::string, std::set<std::string>> verified_msisdns_;
    std::unordered_map<std::string, int64_t> last_resend_;
    std::unordered_set<std::string> completed_sessions_;
};

// =============================================================================
// SSOAuthStage - m.login.sso
// =============================================================================

class SSOAuthStage : public AuthStage {
public:
    struct SSOProvider {
        std::string id;
        std::string name;
        std::string icon;         // mxc:// URI
        std::string brand;        // "google", "github", "apple", "facebook", "gitlab", "twitter"
    };

    struct Config {
        std::vector<SSOProvider> identity_providers;
        std::string default_provider;
        std::string base_url;     // Base URL for SSO redirect
        std::string token_endpoint;
        std::string userinfo_endpoint;
        std::string client_id;
        std::string client_secret;
        std::string redirect_uri;
        std::chrono::seconds token_ttl{3600};
    };

    explicit SSOAuthStage(Config config) : config_(std::move(config)) {}

    std::string auth_type() const override { return "m.login.sso"; }

    json stage_params(const std::string& session_id) const override {
        // SSO is special: we return identity_providers for the client to display
        // The actual flow is handled through the /login/sso/redirect endpoint
        std::shared_lock lock(mutex_);
        (void)session_id;
        json providers = json::array();
        for (const auto& idp : config_.identity_providers) {
            json p;
            p["id"] = idp.id;
            p["name"] = idp.name;
            if (!idp.icon.empty()) p["icon"] = idp.icon;
            if (!idp.brand.empty()) p["brand"] = idp.brand;
            providers.push_back(p);
        }
        return providers;
    }

    bool authenticate(const std::string& session_id,
                      const std::string& user_id,
                      const json& auth_dict) override {
        (void)user_id;
        // SSO authentication requires the client to complete the OAuth2 flow
        // externally and provide a token
        if (!auth_dict.contains("token")) return false;

        std::string token = auth_dict["token"].get<std::string>();

        // Verify token with identity provider
        std::shared_lock lock(mutex_);
        bool valid = verify_sso_token_(token);

        if (!valid) return false;

        completed_sessions_.insert(session_id);
        return true;
    }

    std::string get_redirect_url(const std::string& provider_id) const {
        std::shared_lock lock(mutex_);
        std::string base = config_.base_url;
        if (base.back() != '/') base += '/';
        return base + "login/sso/redirect?provider=" + provider_id;
    }

    bool requires_user_interaction() const override { return true; }

    void cleanup_session(const std::string& session_id) override {
        completed_sessions_.erase(session_id);
    }

private:
    bool verify_sso_token_(const std::string& token) {
        // Stub: In production, validate token with the OAuth2 provider's
        // token introspection endpoint
        (void)token;
        return true; // For testing, accept any non-empty token
    }

    Config config_;
    mutable std::shared_mutex mutex_;
    std::unordered_set<std::string> completed_sessions_;
};

// =============================================================================
// DummyAuthStage - m.login.dummy
// =============================================================================

class DummyAuthStage : public AuthStage {
public:
    DummyAuthStage() = default;

    std::string auth_type() const override { return "m.login.dummy"; }

    json stage_params(const std::string&) const override {
        return json::object();
    }

    bool authenticate(const std::string& session_id,
                      const std::string& user_id,
                      const json& auth_dict) override {
        (void)user_id;
        (void)auth_dict;
        // Dummy always succeeds - used for testing
        std::unique_lock lock(mutex_);
        completed_sessions_.insert(session_id);
        return true;
    }

    bool requires_user_interaction() const override { return false; }

    void cleanup_session(const std::string& session_id) override {
        std::unique_lock lock(mutex_);
        completed_sessions_.erase(session_id);
    }

private:
    std::mutex mutex_;
    std::unordered_set<std::string> completed_sessions_;
};

// =============================================================================
// TermsAuthStage - m.login.terms
// =============================================================================

class TermsAuthStage : public AuthStage {
public:
    struct TermsPolicy {
        std::string short_description;
        int64_t created_at;
        std::string lang;
        std::string url; // mxc:// URI
    };

    explicit TermsAuthStage(
        std::shared_ptr<class TermsOfServiceManager> tos_manager)
        : tos_manager_(std::move(tos_manager)) {}

    std::string auth_type() const override { return "m.login.terms"; }

    json stage_params(const std::string& session_id) const override {
        (void)session_id;
        // Return the list of policies that require consent
        json policies = json::object();
        if (tos_manager_) {
            auto terms = tos_manager_->get_pending_terms();
            if (!terms.empty()) {
                policies["policies"] = terms;
            }
        }
        return policies;
    }

    bool authenticate(const std::string& session_id,
                      const std::string& user_id,
                      const json& auth_dict) override {
        (void)session_id;
        if (!tos_manager_) return true;

        if (!auth_dict.contains("policies")) return false;

        const auto& policies = auth_dict["policies"];
        if (!policies.is_object()) return false;

        // Each key is a policy version URL, value must be true
        for (auto it = policies.begin(); it != policies.end(); ++it) {
            if (!it.value().is_boolean() || !it.value().get<bool>()) {
                return false;
            }
            // Record consent
            tos_manager_->record_consent(user_id, it.key(), now_epoch_ms());
        }

        return true;
    }

    bool requires_user_interaction() const override { return true; }

private:
    std::shared_ptr<class TermsOfServiceManager> tos_manager_;
};

// =============================================================================
// TokenAuthStage - m.login.token (for token-based login)
// =============================================================================

class TokenAuthStage : public AuthStage {
public:
    using TokenValidator = std::function<bool(const std::string& token,
                                               const std::string& user_id)>;

    explicit TokenAuthStage(TokenValidator validator)
        : validator_(std::move(validator)) {}

    std::string auth_type() const override { return "m.login.token"; }

    json stage_params(const std::string&) const override {
        return json::object();
    }

    bool authenticate(const std::string& session_id,
                      const std::string& user_id,
                      const json& auth_dict) override {
        if (!auth_dict.contains("token")) return false;
        std::string token = auth_dict["token"].get<std::string>();

        if (!validator_(token, user_id)) return false;

        std::unique_lock lock(mutex_);
        completed_sessions_.insert(session_id);
        return true;
    }

    void cleanup_session(const std::string& session_id) override {
        std::unique_lock lock(mutex_);
        completed_sessions_.erase(session_id);
    }

private:
    TokenValidator validator_;
    std::mutex mutex_;
    std::unordered_set<std::string> completed_sessions_;
};

// =============================================================================
// AuthFlow - Describes a sequence of auth stages to complete
// =============================================================================

struct AuthFlow {
    std::vector<std::string> stages; // ordered list of auth types
    bool is_supported;               // all stages have registered handlers

    json to_json() const {
        json j;
        j["stages"] = stages;
        return j;
    }
};

// =============================================================================
// AuthSession - Tracks a single UIA session
// =============================================================================

class AuthSession {
public:
    struct State {
        std::string session_id;
        std::string user_id;
        std::string operation;        // e.g., "account_deactivation", "password_change"
        std::vector<std::string> required_stages;
        std::set<std::string> completed_stages; // auth types completed
        std::set<std::string> flows_seen;       // for dedup
        int64_t created_at;
        int64_t expires_at;
        json params;                  // operation-specific params
        bool completed;
        bool cancelled;
    };

    explicit AuthSession(std::string session_id,
                          std::string user_id,
                          std::string operation,
                          std::vector<std::string> required_stages,
                          int64_t ttl_ms)
        : state_() {
        state_.session_id = std::move(session_id);
        state_.user_id = std::move(user_id);
        state_.operation = std::move(operation);
        state_.required_stages = std::move(required_stages);
        state_.created_at = now_epoch_ms();
        state_.expires_at = state_.created_at + ttl_ms;
        state_.completed = false;
        state_.cancelled = false;
    }

    const State& get_state() const {
        std::shared_lock lock(mutex_);
        return state_;
    }

    bool is_expired() const {
        std::shared_lock lock(mutex_);
        return now_epoch_ms() >= state_.expires_at;
    }

    bool is_completed() const {
        std::shared_lock lock(mutex_);
        return state_.completed;
    }

    bool is_cancelled() const {
        std::shared_lock lock(mutex_);
        return state_.cancelled;
    }

    void complete_stage(const std::string& auth_type) {
        std::unique_lock lock(mutex_);
        state_.completed_stages.insert(auth_type);
        // Check if all required stages are complete
        bool all_done = true;
        for (const auto& stage : state_.required_stages) {
            if (state_.completed_stages.find(stage) == state_.completed_stages.end()) {
                all_done = false;
                break;
            }
        }
        if (all_done) {
            state_.completed = true;
        }
    }

    void cancel() {
        std::unique_lock lock(mutex_);
        state_.cancelled = true;
    }

    void set_params(const json& p) {
        std::unique_lock lock(mutex_);
        state_.params = p;
    }

    bool has_completed_stage(const std::string& auth_type) const {
        std::shared_lock lock(mutex_);
        return state_.completed_stages.find(auth_type) != state_.completed_stages.end();
    }

    std::vector<std::string> pending_stages() const {
        std::shared_lock lock(mutex_);
        std::vector<std::string> pending;
        for (const auto& stage : state_.required_stages) {
            if (state_.completed_stages.find(stage) == state_.completed_stages.end()) {
                pending.push_back(stage);
            }
        }
        return pending;
    }

private:
    mutable std::shared_mutex mutex_;
    State state_;
};

// =============================================================================
// AuthSessionManager - Manages all UIA sessions
// =============================================================================

class AuthSessionManager {
public:
    using StageFactory = std::function<std::shared_ptr<AuthStage>()>;

    AuthSessionManager()
        : session_timeout_(DEFAULT_SESSION_TIMEOUT),
          cleanup_interval_(DEFAULT_SESSION_CLEANUP_INTERVAL) {
        start_cleanup_thread();
    }

    ~AuthSessionManager() {
        stop_cleanup_thread();
    }

    // -------------------------------------------------------------------------
    // Stage Registration
    // -------------------------------------------------------------------------

    void register_stage(const std::string& auth_type, StageFactory factory) {
        std::unique_lock lock(mutex_);
        stage_factories_[auth_type] = std::move(factory);
    }

    std::shared_ptr<AuthStage> get_stage(const std::string& auth_type) {
        std::shared_lock lock(mutex_);
        auto it = stage_factories_.find(auth_type);
        if (it != stage_factories_.end()) {
            return it->second();
        }
        return nullptr;
    }

    std::set<std::string> get_supported_types() const {
        std::shared_lock lock(mutex_);
        std::set<std::string> types;
        for (const auto& [t, _] : stage_factories_) {
            types.insert(t);
        }
        return types;
    }

    // -------------------------------------------------------------------------
    // Flow Management
    // -------------------------------------------------------------------------

    void add_flow(const std::string& operation, const std::vector<std::string>& stages) {
        std::unique_lock lock(mutex_);
        configured_flows_[operation].push_back(stages);
    }

    std::vector<AuthFlow> get_flows(const std::string& operation) const {
        std::shared_lock lock(mutex_);
        std::vector<AuthFlow> result;
        auto it = configured_flows_.find(operation);
        if (it != configured_flows_.end()) {
            for (const auto& stages : it->second) {
                AuthFlow flow;
                flow.stages = stages;
                flow.is_supported = true;
                for (const auto& s : stages) {
                    if (stage_factories_.find(s) == stage_factories_.end()) {
                        flow.is_supported = false;
                        break;
                    }
                }
                if (flow.is_supported) {
                    result.push_back(flow);
                }
            }
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // Session Management
    // -------------------------------------------------------------------------

    std::string create_session(const std::string& user_id,
                                const std::string& operation) {
        auto flows = get_flows(operation);
        if (flows.empty()) {
            // Default to an empty flow (no auth needed, operation succeeds)
            return "";
        }

        std::string session_id = generate_session_id();
        int64_t ttl_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            session_timeout_).count();

        // Use the first flow
        auto session = std::make_shared<AuthSession>(
            session_id, user_id, operation,
            flows[0].stages, ttl_ms);

        std::unique_lock lock(mutex_);
        sessions_[session_id] = std::move(session);
        return session_id;
    }

    bool has_session(const std::string& session_id) const {
        std::shared_lock lock(mutex_);
        return sessions_.find(session_id) != sessions_.end();
    }

    std::shared_ptr<AuthSession> get_session(const std::string& session_id) {
        std::shared_lock lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end()) {
            return it->second;
        }
        return nullptr;
    }

    bool authenticate_stage(const std::string& session_id,
                            const std::string& auth_type,
                            const json& auth_dict) {
        auto session = get_session(session_id);
        if (!session || session->is_expired() || session->is_cancelled()) {
            return false;
        }

        auto stage = get_stage(auth_type);
        if (!stage) return false;

        bool result = stage->authenticate(
            session_id,
            session->get_state().user_id,
            auth_dict);

        if (result) {
            session->complete_stage(auth_type);
        }

        return result;
    }

    bool is_session_complete(const std::string& session_id) const {
        auto session = get_session(session_id);
        if (!session) return true; // No session means no auth needed
        return session->is_completed();
    }

    json get_session_info(const std::string& session_id,
                           const std::string& operation) const {
        auto session = get_session(session_id);
        if (!session) {
            // No session - build fresh info
            return build_auth_info(operation);
        }

        json response;
        response["session"] = session_id;

        // Return flows
        auto flows = get_flows(operation);
        json flow_array = json::array();
        for (const auto& f : flows) {
            flow_array.push_back(f.to_json());
        }
        response["flows"] = flow_array;

        // Return params for pending stages
        json params = json::object();
        auto pending = session->pending_stages();
        for (const auto& stage_type : pending) {
            auto stage = get_stage(stage_type);
            if (stage) {
                json stage_params = stage->stage_params(session_id);
                if (!stage_params.empty()) {
                    // Map is type -> params
                    params[stage_type] = stage_params;
                }
            }
        }
        if (!params.empty()) {
            response["params"] = params;
        }

        // Return completed stages
        auto completed = session->get_state().completed_stages;
        if (!completed.empty()) {
            response["completed"] = std::vector<std::string>(completed.begin(), completed.end());
        }

        return response;
    }

    json build_auth_info(const std::string& operation) const {
        json response;

        auto flows = get_flows(operation);
        if (flows.empty()) {
            // No auth required
            return response;
        }

        json flow_array = json::array();
        for (const auto& f : flows) {
            flow_array.push_back(f.to_json());
        }
        response["flows"] = flow_array;

        // Collect params from all stages that need them
        json params = json::object();
        auto supported = get_supported_types();
        for (const auto& stype : supported) {
            auto stage = get_stage(stype);
            if (stage && !stage->requires_user_interaction()) {
                // Auto-completable stages don't need params in the initial response
                continue;
            }
            if (stage) {
                json sp = stage->stage_params("");
                if (!sp.empty()) {
                    params[stype] = sp;
                }
            }
        }
        if (!params.empty()) {
            response["params"] = params;
        }

        return response;
    }

    void cancel_session(const std::string& session_id) {
        auto session = get_session(session_id);
        if (session) {
            session->cancel();
        }
    }

    void cleanup_session(const std::string& session_id) {
        std::unique_lock lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it != sessions_.end()) {
            // Cleanup stage-specific state
            for (const auto& [type, _] : stage_factories_) {
                auto stage = get_stage(type);
                if (stage) {
                    stage->cleanup_session(session_id);
                }
            }
            sessions_.erase(it);
        }
    }

    void set_session_timeout(std::chrono::seconds timeout) {
        session_timeout_ = timeout;
    }

    void start_cleanup_thread() {
        cleanup_running_ = true;
        cleanup_thread_ = std::thread([this]() {
            while (cleanup_running_) {
                std::this_thread::sleep_for(cleanup_interval_);
                if (!cleanup_running_) break;
                expire_sessions_();
            }
        });
    }

    void stop_cleanup_thread() {
        cleanup_running_ = false;
        if (cleanup_thread_.joinable()) {
            cleanup_thread_.join();
        }
    }

private:
    void expire_sessions_() {
        std::unique_lock lock(mutex_);
        std::vector<std::string> to_remove;
        for (auto& [id, session] : sessions_) {
            if (session->is_expired() || session->is_cancelled()) {
                to_remove.push_back(id);
            }
        }
        for (const auto& id : to_remove) {
            // Cleanup stage state
            for (const auto& [type, _] : stage_factories_) {
                // Re-acquire stage for cleanup
            }
            sessions_.erase(id);
        }
    }

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, StageFactory> stage_factories_;
    std::unordered_map<std::string, std::vector<std::vector<std::string>>> configured_flows_;
    std::unordered_map<std::string, std::shared_ptr<AuthSession>> sessions_;
    std::chrono::seconds session_timeout_;
    std::chrono::seconds cleanup_interval_;

    std::thread cleanup_thread_;
    std::atomic<bool> cleanup_running_{false};
};

// =============================================================================
// TermsOfServiceManager - Manages ToS versions and publishing
// =============================================================================

class TermsOfServiceManager {
public:
    struct TermsVersion {
        std::string version;
        std::string language;
        std::string content_url;       // mxc:// URI to the terms document
        std::string title;
        std::string short_description;
        int64_t created_at;
        int64_t published_at;          // 0 = not yet published
        int64_t deprecated_at;         // 0 = not deprecated
        std::string created_by;
        bool requires_explicit_consent;
        int priority;                  // Higher number = higher priority
        std::string hash;              // SHA-256 of content
    };

    TermsOfServiceManager() = default;

    // -------------------------------------------------------------------------
    // Version Management
    // -------------------------------------------------------------------------

    std::string create_version(const std::string& language,
                                const std::string& content_url,
                                const std::string& title,
                                const std::string& short_description,
                                const std::string& created_by,
                                bool requires_explicit_consent,
                                int priority) {
        std::unique_lock lock(mutex_);

        TermsVersion tv;
        tv.version = generate_version_(language);
        tv.language = language;
        tv.content_url = content_url;
        tv.title = title;
        tv.short_description = short_description;
        tv.created_at = now_epoch_ms();
        tv.published_at = 0;
        tv.deprecated_at = 0;
        tv.created_by = created_by;
        tv.requires_explicit_consent = requires_explicit_consent;
        tv.priority = priority;
        tv.hash = ""; // Compute when content is available

        versions_.push_back(std::move(tv));
        return versions_.back().version;
    }

    bool publish_version(const std::string& version) {
        std::unique_lock lock(mutex_);

        auto* tv = find_version_(version);
        if (!tv || tv->published_at != 0) return false;

        tv->published_at = now_epoch_ms();

        // If this version has a higher priority in the same language,
        // it automatically deprecates the previous active one
        for (auto& v : versions_) {
            if (v.language == tv->language &&
                v.version != tv->version &&
                v.deprecated_at == 0 &&
                v.published_at != 0 &&
                v.priority <= tv->priority) {
                v.deprecated_at = now_epoch_ms();
            }
        }

        return true;
    }

    bool deprecate_version(const std::string& version) {
        std::unique_lock lock(mutex_);

        auto* tv = find_version_(version);
        if (!tv || tv->deprecated_at != 0) return false;

        tv->deprecated_at = now_epoch_ms();
        return true;
    }

    bool set_version_hash(const std::string& version, const std::string& hash) {
        std::unique_lock lock(mutex_);

        auto* tv = find_version_(version);
        if (!tv) return false;

        tv->hash = hash;
        return true;
    }

    bool delete_version(const std::string& version) {
        std::unique_lock lock(mutex_);

        auto it = std::find_if(versions_.begin(), versions_.end(),
            [&](const TermsVersion& v) { return v.version == version; });
        if (it == versions_.end()) return false;

        versions_.erase(it);
        return true;
    }

    // -------------------------------------------------------------------------
    // Querying
    // -------------------------------------------------------------------------

    std::optional<TermsVersion> get_version(const std::string& version) const {
        std::shared_lock lock(mutex_);
        for (const auto& v : versions_) {
            if (v.version == version) return v;
        }
        return std::nullopt;
    }

    std::vector<TermsVersion> get_active_versions(
        const std::string& language = "") const {
        std::shared_lock lock(mutex_);
        std::vector<TermsVersion> active;
        for (const auto& v : versions_) {
            if (v.published_at != 0 && v.deprecated_at == 0) {
                if (language.empty() || v.language == language) {
                    active.push_back(v);
                }
            }
        }
        // Sort by priority descending
        std::sort(active.begin(), active.end(),
            [](const TermsVersion& a, const TermsVersion& b) {
                return a.priority > b.priority;
            });
        return active;
    }

    std::vector<TermsVersion> get_all_versions() const {
        std::shared_lock lock(mutex_);
        return versions_;
    }

    std::vector<TermsVersion> get_published_versions() const {
        std::shared_lock lock(mutex_);
        std::vector<TermsVersion> result;
        for (const auto& v : versions_) {
            if (v.published_at != 0) {
                result.push_back(v);
            }
        }
        return result;
    }

    std::vector<std::string> get_all_languages() const {
        std::shared_lock lock(mutex_);
        std::set<std::string> langs;
        for (const auto& v : versions_) {
            langs.insert(v.language);
        }
        return std::vector<std::string>(langs.begin(), langs.end());
    }

    // -------------------------------------------------------------------------
    // Consent Management
    // -------------------------------------------------------------------------

    void record_consent(const std::string& user_id,
                         const std::string& version,
                         int64_t timestamp_ms) {
        std::unique_lock lock(mutex_);
        consent_records_[user_id][version] = timestamp_ms;
    }

    bool has_consented(const std::string& user_id,
                        const std::string& version) const {
        std::shared_lock lock(mutex_);
        auto uit = consent_records_.find(user_id);
        if (uit == consent_records_.end()) return false;
        auto vit = uit->second.find(version);
        return vit != uit->second.end();
    }

    bool has_consented_to_all_active(const std::string& user_id,
                                      const std::string& language = "") const {
        std::shared_lock lock(mutex_);
        auto active = get_active_versions(language);
        auto uit = consent_records_.find(user_id);
        if (uit == consent_records_.end()) {
            return active.empty();
        }
        for (const auto& v : active) {
            if (v.requires_explicit_consent) {
                if (uit->second.find(v.version) == uit->second.end()) {
                    return false;
                }
            }
        }
        return true;
    }

    std::vector<TermsVersion> get_pending_terms(
        const std::string& user_id = "",
        const std::string& language = "") const {
        std::shared_lock lock(mutex_);
        std::vector<TermsVersion> pending;
        auto active = get_active_versions(language);

        if (user_id.empty()) {
            for (const auto& v : active) {
                if (v.requires_explicit_consent) {
                    pending.push_back(v);
                }
            }
            return pending;
        }

        auto uit = consent_records_.find(user_id);
        for (const auto& v : active) {
            if (!v.requires_explicit_consent) continue;
            if (uit == consent_records_.end() ||
                uit->second.find(v.version) == uit->second.end()) {
                pending.push_back(v);
            }
        }
        return pending;
    }

    std::map<std::string, int64_t> get_user_consents(const std::string& user_id) const {
        std::shared_lock lock(mutex_);
        auto it = consent_records_.find(user_id);
        if (it != consent_records_.end()) return it->second;
        return {};
    }

    bool revoke_consent(const std::string& user_id, const std::string& version) {
        std::unique_lock lock(mutex_);
        auto it = consent_records_.find(user_id);
        if (it == consent_records_.end()) return false;
        return it->second.erase(version) > 0;
    }

    bool revoke_all_consent(const std::string& user_id) {
        std::unique_lock lock(mutex_);
        auto it = consent_records_.find(user_id);
        if (it == consent_records_.end()) return false;
        it->second.clear();
        return true;
    }

    // -------------------------------------------------------------------------
    // JSON Serialization
    // -------------------------------------------------------------------------

    json to_json() const {
        std::shared_lock lock(mutex_);
        json j;
        j["versions"] = json::array();
        for (const auto& v : versions_) {
            json vj;
            vj["version"] = v.version;
            vj["language"] = v.language;
            vj["content_url"] = v.content_url;
            vj["title"] = v.title;
            vj["short_description"] = v.short_description;
            vj["created_at"] = v.created_at;
            vj["published_at"] = v.published_at;
            vj["deprecated_at"] = v.deprecated_at;
            vj["created_by"] = v.created_by;
            vj["requires_explicit_consent"] = v.requires_explicit_consent;
            vj["priority"] = v.priority;
            vj["hash"] = v.hash;
            j["versions"].push_back(vj);
        }
        return j;
    }

    json get_pending_terms() const {
        // Returns the Matrix-compatible "policies" format
        auto pending = get_pending_terms();
        json policies = json::object();
        for (const auto& term : pending) {
            json policy;
            policy["version"] = term.version;
            if (!term.short_description.empty()) {
                // Matrix spec uses nested policy data
            }
            // The key is the content_url as per spec, value has version info
        }
        return policies;
    }

private:
    TermsVersion* find_version_(const std::string& version) {
        for (auto& v : versions_) {
            if (v.version == version) return &v;
        }
        return nullptr;
    }

    std::string generate_version_(const std::string& language) {
        // Format: "vYYYYMMDD-NNN-lang"
        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        std::ostringstream oss;
        oss << "v"
            << std::setw(4) << std::setfill('0') << (tm.tm_year + 1900)
            << std::setw(2) << std::setfill('0') << (tm.tm_mon + 1)
            << std::setw(2) << std::setfill('0') << tm.tm_mday
            << "-"
            << std::setw(3) << std::setfill('0') << (versions_.size() + 1)
            << "-"
            << language;
        return oss.str();
    }

    mutable std::shared_mutex mutex_;
    std::vector<TermsVersion> versions_;
    std::unordered_map<std::string, std::map<std::string, int64_t>> consent_records_;
};

// =============================================================================
// ConsentTracker - Tracks user consent across all policy types
// =============================================================================

class ConsentTracker {
public:
    enum class ConsentStatus {
        NOT_REQUIRED,
        PENDING,
        GRANTED,
        REVOKED,
        EXPIRED
    };

    enum class PolicyType {
        TERMS_OF_SERVICE,
        PRIVACY_POLICY,
        COOKIE_POLICY,
        COMMUNITY_GUIDELINES,
        CUSTOM
    };

    struct ConsentRecord {
        std::string user_id;
        std::string policy_id;
        std::string version;
        PolicyType policy_type;
        ConsentStatus status;
        int64_t granted_at;
        int64_t revoked_at;
        int64_t expires_at; // 0 = never expires
        std::string granted_via; // "uia", "admin", "server_notice"
        std::string ip_address;
        std::string user_agent;
        json metadata;
    };

    ConsentTracker() = default;

    // -------------------------------------------------------------------------
    // Consent Operations
    // -------------------------------------------------------------------------

    bool grant_consent(const std::string& user_id,
                        const std::string& policy_id,
                        const std::string& version,
                        PolicyType policy_type,
                        const std::string& granted_via,
                        const std::string& ip_address,
                        const std::string& user_agent,
                        int64_t expires_at,
                        const json& metadata = json::object()) {
        std::unique_lock lock(mutex_);

        ConsentRecord record;
        record.user_id = user_id;
        record.policy_id = policy_id;
        record.version = version;
        record.policy_type = policy_type;
        record.status = ConsentStatus::GRANTED;
        record.granted_at = now_epoch_ms();
        record.revoked_at = 0;
        record.expires_at = expires_at;
        record.granted_via = granted_via;
        record.ip_address = ip_address;
        record.user_agent = user_agent;
        record.metadata = metadata;

        // Revoke any previous consent for the same policy
        revoke_consent_internal_(user_id, policy_id, false);

        auto key = make_key_(user_id, policy_id, version);
        records_[key] = std::move(record);

        // Also update the latest-consent index
        latest_consent_[user_id][policy_id] = version;

        return true;
    }

    bool revoke_consent(const std::string& user_id,
                         const std::string& policy_id) {
        std::unique_lock lock(mutex_);
        return revoke_consent_internal_(user_id, policy_id, true);
    }

    ConsentStatus check_consent(const std::string& user_id,
                                 const std::string& policy_id,
                                 const std::string& min_version = "") const {
        std::shared_lock lock(mutex_);

        auto uit = latest_consent_.find(user_id);
        if (uit == latest_consent_.end()) return ConsentStatus::PENDING;

        auto pit = uit->second.find(policy_id);
        if (pit == uit->second.end()) return ConsentStatus::PENDING;

        auto key = make_key_(user_id, policy_id, pit->second);
        auto rit = records_.find(key);
        if (rit == records_.end()) return ConsentStatus::PENDING;

        const auto& rec = rit->second;

        // Check expiry
        if (rec.expires_at > 0 && now_epoch_ms() >= rec.expires_at) {
            return ConsentStatus::EXPIRED;
        }

        if (rec.status == ConsentStatus::REVOKED) {
            return ConsentStatus::REVOKED;
        }

        if (!min_version.empty() && rec.version < min_version) {
            return ConsentStatus::PENDING;
        }

        return ConsentStatus::GRANTED;
    }

    bool is_action_blocked(const std::string& user_id,
                            const std::string& policy_id) const {
        auto status = check_consent(user_id, policy_id);
        return status != ConsentStatus::GRANTED &&
               status != ConsentStatus::NOT_REQUIRED;
    }

    std::vector<ConsentRecord> get_user_consent_history(
        const std::string& user_id) const {
        std::shared_lock lock(mutex_);
        std::vector<ConsentRecord> history;
        for (const auto& [key, rec] : records_) {
            if (rec.user_id == user_id) {
                history.push_back(rec);
            }
        }
        std::sort(history.begin(), history.end(),
            [](const ConsentRecord& a, const ConsentRecord& b) {
                return a.granted_at > b.granted_at;
            });
        return history;
    }

    std::vector<ConsentRecord> get_policy_consent_history(
        const std::string& policy_id) const {
        std::shared_lock lock(mutex_);
        std::vector<ConsentRecord> history;
        for (const auto& [key, rec] : records_) {
            if (rec.policy_id == policy_id) {
                history.push_back(rec);
            }
        }
        return history;
    }

    size_t get_consent_count(const std::string& policy_id) const {
        std::shared_lock lock(mutex_);
        size_t count = 0;
        for (const auto& [key, rec] : records_) {
            if (rec.policy_id == policy_id &&
                rec.status == ConsentStatus::GRANTED) {
                count++;
            }
        }
        return count;
    }

    void purge_expired() {
        std::unique_lock lock(mutex_);
        auto now = now_epoch_ms();
        for (auto it = records_.begin(); it != records_.end(); ) {
            if (it->second.expires_at > 0 && now >= it->second.expires_at) {
                it->second.status = ConsentStatus::EXPIRED;
            }
            ++it;
        }
    }

    // -------------------------------------------------------------------------
    // JSON Serialization
    // -------------------------------------------------------------------------

    json to_json() const {
        std::shared_lock lock(mutex_);
        json j;
        j["records"] = json::array();
        for (const auto& [key, rec] : records_) {
            json rj;
            rj["user_id"] = rec.user_id;
            rj["policy_id"] = rec.policy_id;
            rj["version"] = rec.version;
            rj["policy_type"] = policy_type_to_string_(rec.policy_type);
            rj["status"] = consent_status_to_string_(rec.status);
            rj["granted_at"] = rec.granted_at;
            rj["revoked_at"] = rec.revoked_at;
            rj["expires_at"] = rec.expires_at;
            rj["granted_via"] = rec.granted_via;
            rj["ip_address"] = rec.ip_address;
            rj["user_agent"] = rec.user_agent;
            if (!rec.metadata.empty()) rj["metadata"] = rec.metadata;
            j["records"].push_back(rj);
        }
        j["total_records"] = records_.size();
        return j;
    }

private:
    bool revoke_consent_internal_(const std::string& user_id,
                                   const std::string& policy_id,
                                   bool clear_latest) {
        auto uit = latest_consent_.find(user_id);
        if (uit == latest_consent_.end()) return false;

        auto pit = uit->second.find(policy_id);
        if (pit == uit->second.end()) return false;

        auto key = make_key_(user_id, policy_id, pit->second);
        auto rit = records_.find(key);
        if (rit != records_.end()) {
            rit->second.status = ConsentStatus::REVOKED;
            rit->second.revoked_at = now_epoch_ms();
        }

        if (clear_latest) {
            uit->second.erase(pit);
            if (uit->second.empty()) {
                latest_consent_.erase(uit);
            }
        }

        return true;
    }

    std::string make_key_(const std::string& user_id,
                           const std::string& policy_id,
                           const std::string& version) const {
        return user_id + "::" + policy_id + "::" + version;
    }

    static std::string policy_type_to_string_(PolicyType t) {
        switch (t) {
            case PolicyType::TERMS_OF_SERVICE: return "terms_of_service";
            case PolicyType::PRIVACY_POLICY: return "privacy_policy";
            case PolicyType::COOKIE_POLICY: return "cookie_policy";
            case PolicyType::COMMUNITY_GUIDELINES: return "community_guidelines";
            case PolicyType::CUSTOM: return "custom";
        }
        return "unknown";
    }

    static std::string consent_status_to_string_(ConsentStatus s) {
        switch (s) {
            case ConsentStatus::NOT_REQUIRED: return "not_required";
            case ConsentStatus::PENDING: return "pending";
            case ConsentStatus::GRANTED: return "granted";
            case ConsentStatus::REVOKED: return "revoked";
            case ConsentStatus::EXPIRED: return "expired";
        }
        return "unknown";
    }

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, ConsentRecord> records_;
    std::unordered_map<std::string,
        std::unordered_map<std::string, std::string>> latest_consent_;
};

// =============================================================================
// PrivacyPolicyManager - Manages privacy policy versions
// =============================================================================

class PrivacyPolicyManager {
public:
    struct PrivacyPolicyVersion {
        std::string version;
        std::string language;
        std::string title;
        std::string content_url;
        std::string summary;
        int64_t created_at;
        int64_t effective_at;
        int64_t superseded_at;
        std::string created_by;
        std::string status; // "draft", "published", "superseded", "archived"
        std::vector<std::string> changes; // Summary of changes from previous version
    };

    PrivacyPolicyManager() = default;

    std::string create_version(const std::string& language,
                                const std::string& title,
                                const std::string& content_url,
                                const std::string& summary,
                                const std::string& created_by,
                                const std::vector<std::string>& changes) {
        std::unique_lock lock(mutex_);

        PrivacyPolicyVersion ppv;
        ppv.version = generate_privacy_version_(language);
        ppv.language = language;
        ppv.title = title;
        ppv.content_url = content_url;
        ppv.summary = summary;
        ppv.created_at = now_epoch_ms();
        ppv.effective_at = 0;
        ppv.superseded_at = 0;
        ppv.created_by = created_by;
        ppv.status = "draft";
        ppv.changes = changes;

        privacy_versions_.push_back(std::move(ppv));
        return privacy_versions_.back().version;
    }

    bool publish_version(const std::string& version,
                          int64_t effective_at = 0) {
        std::unique_lock lock(mutex_);

        auto* ppv = find_privacy_version_(version);
        if (!ppv || ppv->status != "draft") return false;

        if (effective_at == 0) {
            effective_at = now_epoch_ms();
        }

        // Supersede the previously published version in the same language
        for (auto& v : privacy_versions_) {
            if (v.language == ppv->language &&
                v.version != version &&
                v.status == "published") {
                v.status = "superseded";
                v.superseded_at = now_epoch_ms();
            }
        }

        ppv->status = "published";
        ppv->effective_at = effective_at;
        return true;
    }

    bool archive_version(const std::string& version) {
        std::unique_lock lock(mutex_);

        auto* ppv = find_privacy_version_(version);
        if (!ppv) return false;

        ppv->status = "archived";
        return true;
    }

    std::optional<PrivacyPolicyVersion> get_current(const std::string& language = "en") const {
        std::shared_lock lock(mutex_);

        for (const auto& v : privacy_versions_) {
            if (v.language == language && v.status == "published") {
                return v;
            }
        }
        // Fallback to any published version
        for (const auto& v : privacy_versions_) {
            if (v.status == "published") {
                return v;
            }
        }
        return std::nullopt;
    }

    std::optional<PrivacyPolicyVersion> get_version(const std::string& version) const {
        std::shared_lock lock(mutex_);
        for (const auto& v : privacy_versions_) {
            if (v.version == version) return v;
        }
        return std::nullopt;
    }

    std::vector<PrivacyPolicyVersion> get_all_versions() const {
        std::shared_lock lock(mutex_);
        return privacy_versions_;
    }

    std::vector<PrivacyPolicyVersion> get_published_versions() const {
        std::shared_lock lock(mutex_);
        std::vector<PrivacyPolicyVersion> result;
        for (const auto& v : privacy_versions_) {
            if (v.status == "published" || v.status == "superseded") {
                result.push_back(v);
            }
        }
        return result;
    }

    std::vector<std::string> get_all_languages() const {
        std::shared_lock lock(mutex_);
        std::set<std::string> langs;
        for (const auto& v : privacy_versions_) {
            langs.insert(v.language);
        }
        return std::vector<std::string>(langs.begin(), langs.end());
    }

    json to_json() const {
        std::shared_lock lock(mutex_);
        json j;
        j["policies"] = json::array();
        for (const auto& v : privacy_versions_) {
            json pj;
            pj["version"] = v.version;
            pj["language"] = v.language;
            pj["title"] = v.title;
            pj["content_url"] = v.content_url;
            pj["summary"] = v.summary;
            pj["created_at"] = v.created_at;
            pj["effective_at"] = v.effective_at;
            pj["superseded_at"] = v.superseded_at;
            pj["created_by"] = v.created_by;
            pj["status"] = v.status;
            pj["changes"] = v.changes;
            j["policies"].push_back(pj);
        }
        return j;
    }

private:
    PrivacyPolicyVersion* find_privacy_version_(const std::string& version) {
        for (auto& v : privacy_versions_) {
            if (v.version == version) return &v;
        }
        return nullptr;
    }

    std::string generate_privacy_version_(const std::string& language) {
        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        std::ostringstream oss;
        oss << "pp-"
            << std::setw(4) << std::setfill('0') << (tm.tm_year + 1900)
            << std::setw(2) << std::setfill('0') << (tm.tm_mon + 1)
            << std::setw(2) << std::setfill('0') << tm.tm_mday
            << "-"
            << std::setw(3) << std::setfill('0') << (privacy_versions_.size() + 1)
            << "-"
            << language;
        return oss.str();
    }

    mutable std::shared_mutex mutex_;
    std::vector<PrivacyPolicyVersion> privacy_versions_;
};

// =============================================================================
// ServerNoticeSender - Sends server notices for consent requests
// =============================================================================

class ServerNoticeSender {
public:
    struct Config {
        std::string server_notice_user;    // e.g., "@server:example.com"
        std::string consent_notice_type = "m.consent_request";
        std::string default_language = "en";
    };

    explicit ServerNoticeSender(Config config,
                                 std::shared_ptr<TermsOfServiceManager> tos,
                                 std::shared_ptr<ConsentTracker> consent)
        : config_(std::move(config)),
          tos_manager_(std::move(tos)),
          consent_tracker_(std::move(consent)) {}

    /**
     * Send consent request to a user for all pending terms.
     * Returns true if a notice was sent.
     */
    bool send_consent_request(const std::string& user_id) {
        std::string language = config_.default_language;

        auto pending = tos_manager_->get_pending_terms(user_id, language);
        if (pending.empty()) return false;

        // Build the server notice event
        json notice;
        notice["type"] = config_.consent_notice_type;
        notice["msgtype"] = "m.text";
        notice["body"] = build_consent_body_(user_id, pending);
        notice["format"] = "org.matrix.custom.html";
        notice["formatted_body"] = build_consent_html_body_(user_id, pending);

        // The policies the user must accept
        json policies = json::object();
        for (const auto& term : pending) {
            json policy;
            policy["version"] = term.version;
            policy["title"] = term.title;
            policy["url"] = term.content_url;
            policies[term.version] = policy;
        }
        notice["policies"] = policies;

        // Record that a notice was sent
        {
            std::unique_lock lock(notices_mutex_);
            NoticeRecord nr;
            nr.user_id = user_id;
            nr.sent_at = now_epoch_ms();
            nr.policy_versions = {};
            for (const auto& t : pending) {
                nr.policy_versions.push_back(t.version);
            }
            notice_history_[user_id].push_back(std::move(nr));
        }

        // In production, this would push the event via the room's send path
        send_notice_event_(user_id, notice);
        return true;
    }

    /**
     * Send consent request to all users who haven't consented.
     */
    void send_bulk_consent_requests(const std::vector<std::string>& user_ids) {
        for (const auto& uid : user_ids) {
            send_consent_request(uid);
        }
    }

    /**
     * Check if a user has unread consent notices.
     */
    bool has_pending_consent_request(const std::string& user_id) const {
        std::shared_lock lock(notices_mutex_);
        auto it = notice_history_.find(user_id);
        if (it == notice_history_.end()) return false;

        // Check if the latest notice has been acknowledged
        if (it->second.empty()) return false;

        const auto& last = it->second.back();
        for (const auto& ver : last.policy_versions) {
            if (!tos_manager_->has_consented(user_id, ver)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Mark a consent notice as acknowledged.
     */
    void acknowledge_notice(const std::string& user_id) {
        std::unique_lock lock(notices_mutex_);
        auto it = notice_history_.find(user_id);
        if (it != notice_history_.end() && !it->second.empty()) {
            it->second.back().acknowledged_at = now_epoch_ms();
        }
    }

    std::vector<json> get_notice_history(const std::string& user_id) const {
        std::shared_lock lock(notices_mutex_);
        std::vector<json> result;
        auto it = notice_history_.find(user_id);
        if (it != notice_history_.end()) {
            for (const auto& nr : it->second) {
                json j;
                j["user_id"] = nr.user_id;
                j["sent_at"] = nr.sent_at;
                j["acknowledged_at"] = nr.acknowledged_at;
                j["policy_versions"] = nr.policy_versions;
                result.push_back(j);
            }
        }
        return result;
    }

private:
    struct NoticeRecord {
        std::string user_id;
        int64_t sent_at;
        int64_t acknowledged_at = 0;
        std::vector<std::string> policy_versions;
    };

    std::string build_consent_body_(const std::string& user_id,
                                     const std::vector<TermsOfServiceManager::TermsVersion>& terms) {
        std::ostringstream oss;
        oss << "Hello " << user_id << ",\n\n"
            << "To continue using this service, you must review and accept the "
            << "following terms:\n\n";
        for (const auto& term : terms) {
            oss << "- " << term.title << " (v" << term.version << "): ";
            oss << term.content_url << "\n";
        }
        oss << "\nPlease accept these terms to continue using the service.\n";
        return oss.str();
    }

    std::string build_consent_html_body_(const std::string& user_id,
                                          const std::vector<TermsOfServiceManager::TermsVersion>& terms) {
        std::ostringstream oss;
        oss << "<p>Hello " << user_id << ",</p>"
            << "<p>To continue using this service, you must review and accept the "
            << "following terms:</p><ul>";
        for (const auto& term : terms) {
            oss << "<li><a href=\"" << term.content_url << "\">"
                << term.title << " (v" << term.version << ")</a></li>";
        }
        oss << "</ul><p>Please accept these terms to continue using the service.</p>";
        return oss.str();
    }

    void send_notice_event_(const std::string& user_id, const json& notice) {
        // Stub: In production, push the event to the user's server notice room
        (void)user_id;
        (void)notice;
    }

    Config config_;
    std::shared_ptr<TermsOfServiceManager> tos_manager_;
    std::shared_ptr<ConsentTracker> consent_tracker_;
    mutable std::shared_mutex notices_mutex_;
    std::unordered_map<std::string, std::vector<NoticeRecord>> notice_history_;
};

// =============================================================================
// ConsentEnforcer - Blocks actions until consent is given
// =============================================================================

class ConsentEnforcer {
public:
    struct BlockedAction {
        std::string name;
        std::string description;
        std::string policy_id;
        bool block_on_pending;
        int severity; // 0=warning, 1=soft_block, 2=hard_block
    };

    ConsentEnforcer(std::shared_ptr<ConsentTracker> tracker,
                     std::shared_ptr<TermsOfServiceManager> tos)
        : consent_tracker_(std::move(tracker)),
          tos_manager_(std::move(tos)) {}

    /**
     * Register an action that requires consent.
     */
    void register_blocked_action(const BlockedAction& action) {
        std::unique_lock lock(mutex_);
        blocked_actions_[action.name] = action;
    }

    /**
     * Register default blocked actions.
     */
    void register_defaults() {
        register_blocked_action({
            "send_message", "Sending messages",
            "terms_of_service", true, 2
        });
        register_blocked_action({
            "create_room", "Creating rooms",
            "terms_of_service", true, 2
        });
        register_blocked_action({
            "upload_media", "Uploading media",
            "terms_of_service", true, 2
        });
        register_blocked_action({
            "invite_users", "Inviting users",
            "terms_of_service", true, 2
        });
        register_blocked_action({
            "join_room", "Joining rooms",
            "terms_of_service", true, 2
        });
        register_blocked_action({
            "set_displayname", "Setting display name",
            "terms_of_service", true, 1
        });
        register_blocked_action({
            "set_avatar", "Setting avatar",
            "terms_of_service", true, 1
        });
        register_blocked_action({
            "manage_3pid", "Managing 3PIDs",
            "terms_of_service", true, 2
        });
    }

    /**
     * Check if an action is blocked for a user.
     * Returns a pair: {blocked, reason}
     */
    std::pair<bool, std::string> check_action(const std::string& user_id,
                                                const std::string& action_name) {
        std::shared_lock lock(mutex_);

        auto it = blocked_actions_.find(action_name);
        if (it == blocked_actions_.end()) {
            return {false, ""}; // Not a blocked action
        }

        const auto& action = it->second;
        if (!action.block_on_pending) {
            return {false, ""};
        }

        // Check ToS consent
        if (!tos_manager_->has_consented_to_all_active(user_id)) {
            return {true, "You must accept the terms of service to perform this action."};
        }

        // Check generic consent tracker
        auto status = consent_tracker_->check_consent(user_id, action.policy_id);
        if (status != ConsentTracker::ConsentStatus::GRANTED &&
            status != ConsentTracker::ConsentStatus::NOT_REQUIRED) {
            std::string reason = "Consent required for: " + action.description;
            return {true, reason};
        }

        return {false, ""};
    }

    /**
     * Check if ANY action is blocked.
     */
    bool is_user_blocked(const std::string& user_id) {
        std::shared_lock lock(mutex_);
        for (const auto& [name, action] : blocked_actions_) {
            if (action.block_on_pending && action.severity >= 2) {
                if (!tos_manager_->has_consented_to_all_active(user_id)) {
                    return true;
                }
                auto status = consent_tracker_->check_consent(user_id, action.policy_id);
                if (status == ConsentTracker::ConsentStatus::PENDING ||
                    status == ConsentTracker::ConsentStatus::REVOKED) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Get a list of all pending actions for a user.
     */
    std::vector<std::string> get_pending_actions(const std::string& user_id) {
        std::shared_lock lock(mutex_);
        std::vector<std::string> pending;
        for (const auto& [name, action] : blocked_actions_) {
            if (action.block_on_pending) {
                if (!tos_manager_->has_consented_to_all_active(user_id)) {
                    pending.push_back(name);
                    continue;
                }
                auto status = consent_tracker_->check_consent(user_id, action.policy_id);
                if (status != ConsentTracker::ConsentStatus::GRANTED &&
                    status != ConsentTracker::ConsentStatus::NOT_REQUIRED) {
                    pending.push_back(name);
                }
            }
        }
        return pending;
    }

    /**
     * Build a JSON error response for blocked actions.
     */
    json build_blocked_response(const std::string& user_id,
                                 const std::string& action_name) {
        auto [blocked, reason] = check_action(user_id, action_name);
        if (!blocked) return json::object();

        json response;
        response["errcode"] = "M_CONSENT_NOT_GIVEN";
        response["error"] = reason;
        response["consent_uri"] = "/_matrix/client/v3/terms";

        // Include pending terms so the client can prompt the user
        auto pending = tos_manager_->get_pending_terms(user_id);
        json policies = json::object();
        for (const auto& term : pending) {
            json policy;
            policy["version"] = term.version;
            policy["title"] = term.title;
            policy["url"] = term.content_url;
            policies[term.version] = policy;
        }
        if (!policies.empty()) {
            response["policies"] = policies;
        }

        return response;
    }

private:
    std::shared_ptr<ConsentTracker> consent_tracker_;
    std::shared_ptr<TermsOfServiceManager> tos_manager_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, BlockedAction> blocked_actions_;
};

// =============================================================================
// UIAOperation - Base class for UIA-protected operations
// =============================================================================

class UIAOperation {
public:
    virtual ~UIAOperation() = default;

    /// The operation identifier used in flow configuration
    virtual std::string operation_id() const = 0;

    /// Execute the operation once UIA is completed.
    /// Returns JSON result or throws on error.
    virtual json execute(const std::string& user_id,
                          const json& session_params) = 0;

    /// Whether this operation requires a fresh UIA session
    virtual bool requires_uia() const { return true; }

    /// Validate operation-specific parameters
    virtual bool validate_params(const json& params) const = 0;
};

// =============================================================================
// AccountDeactivationOperation
// =============================================================================

class AccountDeactivationOperation : public UIAOperation {
public:
    struct Config {
        bool erase_data = true;        // GDPR-style full erasure
        bool require_id_server_unbind = false;
    };

    explicit AccountDeactivationOperation(
        Config config,
        std::function<bool(const std::string&)> deactivator)
        : config_(std::move(config)),
          deactivator_(std::move(deactivator)) {}

    std::string operation_id() const override { return "account_deactivation"; }

    json execute(const std::string& user_id,
                  const json& session_params) override {
        bool erase = session_params.value("erase", config_.erase_data);

        if (config_.require_id_server_unbind) {
            // Ensure identity server unbind is done
            if (!session_params.contains("id_server_unbind_result")) {
                throw std::runtime_error(
                    make_error_json("M_MISSING_PARAM",
                                     "Identity server unbind required"));
            }
        }

        bool success = deactivator_(user_id);
        if (!success) {
            throw std::runtime_error(
                make_error_json("M_UNKNOWN", "Failed to deactivate account"));
        }

        json result;
        result["success"] = true;
        result["erased"] = erase;
        return result;
    }

    bool validate_params(const json& params) const override {
        // Accept "erase" bool, "auth" dict
        if (params.contains("erase") && !params["erase"].is_boolean()) {
            return false;
        }
        return true;
    }

private:
    Config config_;
    std::function<bool(const std::string&)> deactivator_;
};

// =============================================================================
// PasswordChangeOperation
// =============================================================================

class PasswordChangeOperation : public UIAOperation {
public:
    explicit PasswordChangeOperation(
        std::function<bool(const std::string&, const std::string&)> password_changer)
        : password_changer_(std::move(password_changer)) {}

    std::string operation_id() const override { return "password_change"; }

    json execute(const std::string& user_id,
                  const json& session_params) override {
        if (!session_params.contains("new_password")) {
            throw std::runtime_error(
                make_error_json("M_MISSING_PARAM", "new_password required"));
        }

        std::string new_password = session_params["new_password"].get<std::string>();

        if (new_password.length() < 8) {
            throw std::runtime_error(
                make_error_json("M_WEAK_PASSWORD",
                                 "Password must be at least 8 characters"));
        }

        // Optional: check password strength
        if (session_params.value("logout_devices", true)) {
            // In production, invalidate all existing access tokens
        }

        bool success = password_changer_(user_id, new_password);
        if (!success) {
            throw std::runtime_error(
                make_error_json("M_UNKNOWN", "Failed to change password"));
        }

        json result;
        result["success"] = true;
        return result;
    }

    bool validate_params(const json& params) const override {
        if (params.contains("new_password")) {
            if (!params["new_password"].is_string()) return false;
        }
        if (params.contains("logout_devices")) {
            if (!params["logout_devices"].is_boolean()) return false;
        }
        return true;
    }

private:
    std::function<bool(const std::string&, const std::string&)> password_changer_;
};

// =============================================================================
// ThreePIDAdditionOperation
// =============================================================================

class ThreePIDAdditionOperation : public UIAOperation {
public:
    struct ThreePID {
        std::string medium;    // "email" or "msisdn"
        std::string address;
    };

    explicit ThreePIDAdditionOperation(
        std::function<bool(const std::string&, const ThreePID&)> adder)
        : adder_(std::move(adder)) {}

    std::string operation_id() const override { return "add_3pid"; }

    json execute(const std::string& user_id,
                  const json& session_params) override {
        ThreePID threepid;
        if (!session_params.contains("three_pid_creds")) {
            throw std::runtime_error(
                make_error_json("M_MISSING_PARAM", "three_pid_creds required"));
        }

        const auto& creds = session_params["three_pid_creds"];
        if (!creds.contains("client_secret") || !creds.contains("sid")) {
            throw std::runtime_error(
                make_error_json("M_MISSING_PARAM",
                                 "three_pid_creds must include client_secret and sid"));
        }

        // In production, validate the three_pid_creds with the identity server
        threepid.medium = creds.value("medium", "");
        threepid.address = creds.value("address", "");

        bool success = adder_(user_id, threepid);
        if (!success) {
            throw std::runtime_error(
                make_error_json("M_UNKNOWN", "Failed to add 3PID"));
        }

        json result;
        result["success"] = true;
        return result;
    }

    bool validate_params(const json& params) const override {
        if (!params.contains("three_pid_creds")) return false;
        const auto& creds = params["three_pid_creds"];
        if (!creds.contains("client_secret")) return false;
        if (!creds.contains("sid")) return false;
        return true;
    }

private:
    std::function<bool(const std::string&, const ThreePID&)> adder_;
};

// =============================================================================
// CrossSigningResetOperation
// =============================================================================

class CrossSigningResetOperation : public UIAOperation {
public:
    explicit CrossSigningResetOperation(
        std::function<bool(const std::string&)> resetter)
        : resetter_(std::move(resetter)) {}

    std::string operation_id() const override { return "cross_signing_reset"; }

    json execute(const std::string& user_id,
                  const json& session_params) override {
        (void)session_params;
        bool success = resetter_(user_id);
        if (!success) {
            throw std::runtime_error(
                make_error_json("M_UNKNOWN",
                                 "Failed to reset cross-signing keys"));
        }

        json result;
        result["success"] = true;
        return result;
    }

    bool validate_params(const json& params) const override {
        (void)params;
        return true; // No additional params needed beyond auth
    }

private:
    std::function<bool(const std::string&)> resetter_;
};

// =============================================================================
// DehydratedDeviceOperation
// =============================================================================

class DehydratedDeviceOperation : public UIAOperation {
public:
    struct DehydratedDeviceData {
        std::string device_id;
        json device_keys;
        std::string algorithm;
    };

    explicit DehydratedDeviceOperation(
        std::function<bool(const std::string&, const DehydratedDeviceData&)> creator)
        : creator_(std::move(creator)) {}

    std::string operation_id() const override { return "dehydrated_device"; }

    json execute(const std::string& user_id,
                  const json& session_params) override {
        DehydratedDeviceData data;
        data.device_id = session_params.value("device_id", "");
        data.device_keys = session_params.value("device_keys", json::object());
        data.algorithm = session_params.value("algorithm", "m.olm.v1.curve25519-aes-sha2");

        if (data.device_id.empty()) {
            throw std::runtime_error(
                make_error_json("M_MISSING_PARAM", "device_id required"));
        }

        bool success = creator_(user_id, data);
        if (!success) {
            throw std::runtime_error(
                make_error_json("M_UNKNOWN",
                                 "Failed to create dehydrated device"));
        }

        json result;
        result["success"] = true;
        result["device_id"] = data.device_id;
        return result;
    }

    bool validate_params(const json& params) const override {
        if (!params.contains("device_id")) return false;
        if (!params["device_id"].is_string()) return false;
        if (params.contains("device_keys") && !params["device_keys"].is_object()) {
            return false;
        }
        return true;
    }

private:
    std::function<bool(const std::string&, const DehydratedDeviceData&)> creator_;
};

// =============================================================================
// UIAHandler - High-level handler that ties everything together
// =============================================================================

class UIAHandler {
public:
    UIAHandler()
        : session_manager_(std::make_shared<AuthSessionManager>()),
          tos_manager_(std::make_shared<TermsOfServiceManager>()),
          consent_tracker_(std::make_shared<ConsentTracker>()),
          privacy_manager_(std::make_shared<PrivacyPolicyManager>()),
          consent_enforcer_(
              std::make_shared<ConsentEnforcer>(consent_tracker_, tos_manager_)) {
        consent_enforcer_->register_defaults();
    }

    // -------------------------------------------------------------------------
    // Initialization
    // -------------------------------------------------------------------------

    void initialize_default_stages(
        std::function<std::optional<PasswordAuthStage::UserCredentials>(const std::string&)> pwd_lookup,
        const ReCaptchaAuthStage::Config& recaptcha_cfg,
        const EmailIdentityAuthStage::Config& email_cfg,
        const MSISDNAuthStage::Config& msisdn_cfg,
        const SSOAuthStage::Config& sso_cfg) {

        // Register stage factories
        session_manager_->register_stage("m.login.password",
            [pwd_lookup]() -> std::shared_ptr<AuthStage> {
                return std::make_shared<PasswordAuthStage>(pwd_lookup);
            });

        session_manager_->register_stage("m.login.recaptcha",
            [recaptcha_cfg]() -> std::shared_ptr<AuthStage> {
                return std::make_shared<ReCaptchaAuthStage>(recaptcha_cfg);
            });

        session_manager_->register_stage("m.login.email.identity",
            [email_cfg]() -> std::shared_ptr<AuthStage> {
                return std::make_shared<EmailIdentityAuthStage>(email_cfg);
            });

        session_manager_->register_stage("m.login.msisdn",
            [msisdn_cfg]() -> std::shared_ptr<AuthStage> {
                return std::make_shared<MSISDNAuthStage>(msisdn_cfg);
            });

        session_manager_->register_stage("m.login.sso",
            [sso_cfg]() -> std::shared_ptr<AuthStage> {
                return std::make_shared<SSOAuthStage>(sso_cfg);
            });

        session_manager_->register_stage("m.login.dummy",
            []() -> std::shared_ptr<AuthStage> {
                return std::make_shared<DummyAuthStage>();
            });

        session_manager_->register_stage("m.login.terms",
            [this]() -> std::shared_ptr<AuthStage> {
                return std::make_shared<TermsAuthStage>(tos_manager_);
            });

        // Register default flows
        register_default_flows_();
    }

    void register_operation(std::shared_ptr<UIAOperation> operation) {
        std::unique_lock lock(operations_mutex_);
        operations_[operation->operation_id()] = std::move(operation);
    }

    // -------------------------------------------------------------------------
    // UIA Protocol Handling
    // -------------------------------------------------------------------------

    /**
     * Begin a UIA-protected operation.
     * Returns the auth info JSON if authentication is required,
     * or an empty object if no auth is needed.
     */
    json begin_operation(const std::string& user_id,
                          const std::string& operation_id,
                          const json& params = json::object()) {
        auto operation = get_operation_(operation_id);
        if (!operation) {
            return json{{"errcode", "M_UNRECOGNIZED"},
                         {"error", "Unknown operation: " + operation_id}};
        }

        // Validate params
        if (!operation->validate_params(params)) {
            return json{{"errcode", "M_INVALID_PARAM"},
                         {"error", "Invalid parameters for operation"}};
        }

        // Check consent
        auto [blocked, reason] = consent_enforcer_->check_action(user_id, operation_id);
        if (blocked) {
            return consent_enforcer_->build_blocked_response(user_id, operation_id);
        }

        // If operation doesn't require UIA, execute immediately
        if (!operation->requires_uia()) {
            try {
                json session_params = params;
                session_params["operation"] = operation_id;
                return operation->execute(user_id, session_params);
            } catch (const std::exception& e) {
                json err = json::parse(e.what());
                return err;
            }
        }

        // Create a UIA session
        std::string session_id = session_manager_->create_session(user_id, operation_id);

        if (session_id.empty()) {
            // No flows configured - operation succeeds without UIA
            try {
                json session_params = params;
                session_params["operation"] = operation_id;
                return operation->execute(user_id, session_params);
            } catch (const std::exception& e) {
                json err = json::parse(e.what());
                return err;
            }
        }

        // Store operation params in the session
        auto session = session_manager_->get_session(session_id);
        if (session) {
            session->set_params(params);
        }

        // Return UIA challenge
        json response;
        response["session"] = session_id;
        auto auth_info = session_manager_->get_session_info(session_id, operation_id);
        if (auth_info.contains("flows")) {
            response["flows"] = auth_info["flows"];
        }
        if (auth_info.contains("params")) {
            response["params"] = auth_info["params"];
        }
        return response;
    }

    /**
     * Continue a UIA session by providing auth for a stage.
     */
    json continue_operation(const std::string& session_id,
                             const json& auth_dict) {
        auto session = session_manager_->get_session(session_id);
        if (!session) {
            return json{{"errcode", "M_UNKNOWN"},
                         {"error", "Unknown or expired session"}};
        }

        if (session->is_expired()) {
            return json{{"errcode", "M_SESSION_EXPIRED"},
                         {"error", "Authentication session has expired"}};
        }

        if (session->is_cancelled()) {
            return json{{"errcode", "M_USER_DEACTIVATED"},
                         {"error", "Session was cancelled"}};
        }

        // Determine which stage this auth dict is for
        std::string auth_type;
        if (auth_dict.contains("type")) {
            auth_type = auth_dict["type"].get<std::string>();
        } else {
            return json{{"errcode", "M_MISSING_PARAM"},
                         {"error", "Missing 'type' in auth dict"}};
        }

        // Authenticate the stage
        bool stage_ok = session_manager_->authenticate_stage(
            session_id, auth_type, auth_dict);

        if (!stage_ok) {
            return json{{"errcode", "M_UNAUTHORIZED"},
                         {"error", "Authentication failed for stage: " + auth_type}};
        }

        // Check if session is now complete
        if (session_manager_->is_session_complete(session_id)) {
            // Execute the operation
            auto state = session->get_state();
            auto operation = get_operation_(state.operation);

            if (!operation) {
                session_manager_->cleanup_session(session_id);
                return json{{"errcode", "M_UNKNOWN"},
                             {"error", "Unknown operation"}};
            }

            try {
                json result = operation->execute(state.user_id, state.params);

                // Record consent if terms were accepted
                if (session->has_completed_stage("m.login.terms")) {
                    // Consent was already recorded by TermsAuthStage
                }

                session_manager_->cleanup_session(session_id);

                // Add completed stages to result
                json completed_stages = json::array();
                for (const auto& s : state.completed_stages) {
                    completed_stages.push_back(s);
                }
                result["completed"] = completed_stages;

                return result;
            } catch (const std::exception& e) {
                session_manager_->cleanup_session(session_id);
                json err = json::parse(e.what());
                return err;
            }
        }

        // Session not yet complete - return updated auth info
        auto state = session->get_state();
        json response;
        response["session"] = session_id;
        auto auth_info = session_manager_->get_session_info(session_id, state.operation);
        if (auth_info.contains("flows")) {
            response["flows"] = auth_info["flows"];
        }
        if (auth_info.contains("params")) {
            response["params"] = auth_info["params"];
        }

        // List completed stages
        json completed = json::array();
        for (const auto& s : state.completed_stages) {
            completed.push_back(s);
        }
        if (!completed.empty()) {
            response["completed"] = completed;
        }

        return response;
    }

    /**
     * Cancel an in-progress UIA session.
     */
    json cancel_operation(const std::string& session_id) {
        session_manager_->cancel_session(session_id);
        session_manager_->cleanup_session(session_id);
        return json{{"success", true}};
    }

    // -------------------------------------------------------------------------
    // Terms of Service Management - Public API
    // -------------------------------------------------------------------------

    std::shared_ptr<TermsOfServiceManager> get_tos_manager() {
        return tos_manager_;
    }

    std::shared_ptr<ConsentTracker> get_consent_tracker() {
        return consent_tracker_;
    }

    std::shared_ptr<PrivacyPolicyManager> get_privacy_manager() {
        return privacy_manager_;
    }

    std::shared_ptr<ConsentEnforcer> get_consent_enforcer() {
        return consent_enforcer_;
    }

    /**
     * Create a server notice sender.
     */
    std::shared_ptr<ServerNoticeSender> create_server_notice_sender(
        const ServerNoticeSender::Config& config) {
        return std::make_shared<ServerNoticeSender>(
            config, tos_manager_, consent_tracker_);
    }

    // -------------------------------------------------------------------------
    // Terms API Endpoint Handlers
    // -------------------------------------------------------------------------

    /**
     * Handle GET /_matrix/client/v3/terms
     * Returns all active terms that the user needs to accept.
     */
    json handle_get_terms(const std::string& user_id = "") {
        json response;

        auto pending = tos_manager_->get_pending_terms(user_id);
        if (pending.empty() && user_id.empty()) {
            pending = tos_manager_->get_pending_terms();
        }

        json policies = json::object();
        for (const auto& term : pending) {
            json policy;
            policy["version"] = term.version;
            if (!term.title.empty()) {
                // Matrix spec uses nested structure for policy data
                json lang_data;
                lang_data["name"] = term.title;
                lang_data["url"] = term.content_url;
                // Policy key is the URL per spec
                if (!policies.contains(term.content_url)) {
                    policies[term.content_url] = json::object();
                }
                policies[term.content_url][term.language] = lang_data;
            }
        }

        if (!policies.empty()) {
            response["policies"] = policies;
        }

        return response;
    }

    /**
     * Handle POST /_matrix/client/v3/terms
     * Accept terms by providing user_accepts with version URLs.
     */
    json handle_accept_terms(const std::string& user_id, const json& body) {
        if (!body.contains("user_accepts")) {
            return json{{"errcode", "M_MISSING_PARAM"},
                         {"error", "Missing user_accepts"}};
        }

        const auto& accepts = body["user_accepts"];
        if (!accepts.is_array()) {
            return json{{"errcode", "M_INVALID_PARAM"},
                         {"error", "user_accepts must be an array"}};
        }

        std::vector<std::string> accepted;
        std::vector<std::string> errors;

        for (const auto& url : accepts) {
            if (!url.is_string()) {
                errors.push_back("Invalid URL entry");
                continue;
            }
            std::string url_str = url.get<std::string>();

            // Record consent
            tos_manager_->record_consent(user_id, url_str, now_epoch_ms());
            consent_tracker_->grant_consent(
                user_id, url_str, "latest",
                ConsentTracker::PolicyType::TERMS_OF_SERVICE,
                "direct", "", "", 0);

            accepted.push_back(url_str);
        }

        json response;
        response["accepted"] = accepted;
        if (!errors.empty()) {
            response["errors"] = errors;
        }
        return response;
    }

    // -------------------------------------------------------------------------
    // Admin API
    // -------------------------------------------------------------------------

    /**
     * Create, publish, deprecate terms.
     */
    json admin_create_terms(const std::string& language,
                             const std::string& content_url,
                             const std::string& title,
                             const std::string& short_description,
                             const std::string& created_by,
                             bool requires_explicit_consent,
                             int priority) {
        std::string version = tos_manager_->create_version(
            language, content_url, title, short_description,
            created_by, requires_explicit_consent, priority);

        json response;
        response["version"] = version;
        response["success"] = true;
        return response;
    }

    json admin_publish_terms(const std::string& version) {
        bool ok = tos_manager_->publish_version(version);
        json response;
        response["success"] = ok;
        if (!ok) {
            response["error"] = "Failed to publish version: " + version;
        }
        return response;
    }

    json admin_deprecate_terms(const std::string& version) {
        bool ok = tos_manager_->deprecate_version(version);
        json response;
        response["success"] = ok;
        return response;
    }

    json admin_get_terms_history() {
        auto versions = tos_manager_->get_all_versions();
        json result;
        result["versions"] = json::array();
        for (const auto& v : versions) {
            json vj;
            vj["version"] = v.version;
            vj["language"] = v.language;
            vj["title"] = v.title;
            vj["content_url"] = v.content_url;
            vj["created_at"] = v.created_at;
            vj["published_at"] = v.published_at;
            vj["deprecated_at"] = v.deprecated_at;
            vj["created_by"] = v.created_by;
            vj["requires_explicit_consent"] = v.requires_explicit_consent;
            vj["priority"] = v.priority;
            vj["status"] = (v.published_at == 0) ? "draft" :
                           (v.deprecated_at != 0) ? "deprecated" : "published";
            result["versions"].push_back(vj);
        }
        return result;
    }

    json admin_get_consent_stats() {
        json stats;
        auto versions = tos_manager_->get_published_versions();
        stats["total_versions"] = versions.size();

        json by_version = json::object();
        for (const auto& v : versions) {
            by_version[v.version] = consent_tracker_->get_consent_count(v.version);
        }
        stats["consents_by_version"] = by_version;

        return stats;
    }

    // -------------------------------------------------------------------------
    // Session Management
    // -------------------------------------------------------------------------

    void set_session_timeout(std::chrono::seconds timeout) {
        session_manager_->set_session_timeout(timeout);
    }

    size_t cleanup_expired_sessions() {
        // SessionManager runs its own cleanup thread.
        // This is a manual trigger.
        return 0; // Handled by background thread
    }

private:
    void register_default_flows_() {
        // Account deactivation flows
        session_manager_->add_flow("account_deactivation",
            {"m.login.password"});
        session_manager_->add_flow("account_deactivation",
            {"m.login.password", "m.login.terms"});

        // Password change flows
        session_manager_->add_flow("password_change",
            {"m.login.password"});

        // 3PID addition flows
        session_manager_->add_flow("add_3pid",
            {"m.login.password"});
        session_manager_->add_flow("add_3pid",
            {"m.login.email.identity"});
        session_manager_->add_flow("add_3pid",
            {"m.login.password", "m.login.email.identity"});

        // Cross-signing reset flows
        session_manager_->add_flow("cross_signing_reset",
            {"m.login.password"});
        session_manager_->add_flow("cross_signing_reset",
            {"m.login.password", "m.login.terms"});

        // Dehydrated device flows
        session_manager_->add_flow("dehydrated_device",
            {"m.login.password"});

        // SSO login flows
        session_manager_->add_flow("login",
            {"m.login.sso"});
        session_manager_->add_flow("login",
            {"m.login.password"});
        session_manager_->add_flow("login",
            {"m.login.password", "m.login.terms"});
        session_manager_->add_flow("login",
            {"m.login.recaptcha"});
        session_manager_->add_flow("login",
            {"m.login.dummy"});

        // Registration flows
        session_manager_->add_flow("register",
            {"m.login.recaptcha"});
        session_manager_->add_flow("register",
            {"m.login.recaptcha", "m.login.terms"});
        session_manager_->add_flow("register",
            {"m.login.dummy"});
        session_manager_->add_flow("register",
            {"m.login.dummy", "m.login.terms"});
    }

    std::shared_ptr<UIAOperation> get_operation_(const std::string& op_id) {
        std::shared_lock lock(operations_mutex_);
        auto it = operations_.find(op_id);
        if (it != operations_.end()) return it->second;
        return nullptr;
    }

    std::shared_ptr<AuthSessionManager> session_manager_;
    std::shared_ptr<TermsOfServiceManager> tos_manager_;
    std::shared_ptr<ConsentTracker> consent_tracker_;
    std::shared_ptr<PrivacyPolicyManager> privacy_manager_;
    std::shared_ptr<ConsentEnforcer> consent_enforcer_;

    mutable std::shared_mutex operations_mutex_;
    std::unordered_map<std::string, std::shared_ptr<UIAOperation>> operations_;
};

// =============================================================================
// Global/Convenience Factory
// =============================================================================

/**
 * Create a fully-configured UIAHandler with default stages.
 *
 * @param pwd_lookup Function to look up user password credentials
 * @param recaptcha_site_key Public reCAPTCHA site key
 * @param recaptcha_secret_key Private reCAPTCHA secret key
 * @return A shared pointer to the configured UIAHandler
 */
std::shared_ptr<UIAHandler> create_default_uia_handler(
    std::function<std::optional<PasswordAuthStage::UserCredentials>(const std::string&)> pwd_lookup,
    const std::string& recaptcha_site_key = "",
    const std::string& recaptcha_secret_key = "") {

    auto handler = std::make_shared<UIAHandler>();

    ReCaptchaAuthStage::Config recaptcha_cfg;
    recaptcha_cfg.public_key = recaptcha_site_key;
    recaptcha_cfg.private_key = recaptcha_secret_key;
    recaptcha_cfg.enabled = !recaptcha_site_key.empty();

    EmailIdentityAuthStage::Config email_cfg;
    // Configure with defaults; in production set SMTP settings

    MSISDNAuthStage::Config msisdn_cfg;
    // Configure with defaults

    SSOAuthStage::Config sso_cfg;
    // Configure with defaults

    handler->initialize_default_stages(
        pwd_lookup, recaptcha_cfg, email_cfg, msisdn_cfg, sso_cfg);

    // Register common operations
    handler->register_operation(
        std::make_shared<AccountDeactivationOperation>(
            AccountDeactivationOperation::Config{},
            [](const std::string&) -> bool { return true; }));

    handler->register_operation(
        std::make_shared<PasswordChangeOperation>(
            [](const std::string&, const std::string&) -> bool { return true; }));

    handler->register_operation(
        std::make_shared<ThreePIDAdditionOperation>(
            [](const std::string&, const ThreePIDAdditionOperation::ThreePID&) -> bool {
                return true;
            }));

    handler->register_operation(
        std::make_shared<CrossSigningResetOperation>(
            [](const std::string&) -> bool { return true; }));

    handler->register_operation(
        std::make_shared<DehydratedDeviceOperation>(
            [](const std::string&, const DehydratedDeviceOperation::DehydratedDeviceData&) -> bool {
                return true;
            }));

    return handler;
}

// =============================================================================
// Session Cleanup Worker
// =============================================================================

class SessionCleanupWorker {
public:
    explicit SessionCleanupWorker(
        std::shared_ptr<UIAHandler> handler,
        std::chrono::seconds interval = DEFAULT_SESSION_CLEANUP_INTERVAL)
        : handler_(std::move(handler)),
          interval_(interval),
          running_(false) {}

    void start() {
        running_ = true;
        worker_thread_ = std::thread([this]() {
            while (running_) {
                std::this_thread::sleep_for(interval_);
                if (!running_) break;
                handler_->cleanup_expired_sessions();
            }
        });
    }

    void stop() {
        running_ = false;
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }

    ~SessionCleanupWorker() {
        stop();
    }

private:
    std::shared_ptr<UIAHandler> handler_;
    std::chrono::seconds interval_;
    std::atomic<bool> running_;
    std::thread worker_thread_;
};

// =============================================================================
// Terms Version Migrator
// =============================================================================

class TermsVersionMigrator {
public:
    explicit TermsVersionMigrator(
        std::shared_ptr<TermsOfServiceManager> tos,
        std::shared_ptr<ConsentTracker> consent)
        : tos_(std::move(tos)),
          consent_(std::move(consent)) {}

    /**
     * Migrate consent from old_version to new_version for all users
     * who had consented to the old version.
     */
    size_t migrate_consents(const std::string& old_version,
                             const std::string& new_version) {
        auto history = consent_->get_policy_consent_history(old_version);
        size_t migrated = 0;

        for (const auto& record : history) {
            if (record.status == ConsentTracker::ConsentStatus::GRANTED) {
                consent_->grant_consent(
                    record.user_id,
                    new_version,
                    new_version,
                    record.policy_type,
                    "migration",
                    "",
                    "",
                    record.expires_at);
                migrated++;
            }
        }

        return migrated;
    }

    /**
     * Migrate all consents from one policy to another.
     */
    size_t migrate_policy(const std::string& old_policy_id,
                           const std::string& new_policy_id) {
        auto history = consent_->get_policy_consent_history(old_policy_id);
        size_t migrated = 0;

        for (const auto& record : history) {
            if (record.status == ConsentTracker::ConsentStatus::GRANTED) {
                consent_->grant_consent(
                    record.user_id,
                    new_policy_id,
                    "migrated",
                    record.policy_type,
                    "policy_migration",
                    "",
                    "",
                    record.expires_at);
                migrated++;
            }
        }

        return migrated;
    }

private:
    std::shared_ptr<TermsOfServiceManager> tos_;
    std::shared_ptr<ConsentTracker> consent_;
};

// =============================================================================
// Audit Logger
// =============================================================================

class AuditLogger {
public:
    struct AuditEvent {
        int64_t timestamp;
        std::string event_type;
        std::string user_id;
        std::string session_id;
        std::string details;
        std::string ip_address;
        std::string result; // "success", "failure", "cancelled"
    };

    AuditLogger() = default;

    void log_uia_start(const std::string& user_id,
                        const std::string& session_id,
                        const std::string& operation,
                        const std::string& ip = "") {
        AuditEvent evt;
        evt.timestamp = now_epoch_ms();
        evt.event_type = "uia_start";
        evt.user_id = user_id;
        evt.session_id = session_id;
        evt.details = "operation=" + operation;
        evt.ip_address = ip;
        evt.result = "started";
        log_(std::move(evt));
    }

    void log_stage_attempt(const std::string& user_id,
                            const std::string& session_id,
                            const std::string& stage,
                            bool success,
                            const std::string& ip = "") {
        AuditEvent evt;
        evt.timestamp = now_epoch_ms();
        evt.event_type = "uia_stage";
        evt.user_id = user_id;
        evt.session_id = session_id;
        evt.details = "stage=" + stage;
        evt.ip_address = ip;
        evt.result = success ? "success" : "failure";
        log_(std::move(evt));
    }

    void log_uia_complete(const std::string& user_id,
                           const std::string& session_id,
                           const std::string& operation,
                           bool success,
                           const std::string& ip = "") {
        AuditEvent evt;
        evt.timestamp = now_epoch_ms();
        evt.event_type = "uia_complete";
        evt.user_id = user_id;
        evt.session_id = session_id;
        evt.details = "operation=" + operation;
        evt.ip_address = ip;
        evt.result = success ? "success" : "failure";
        log_(std::move(evt));
    }

    void log_consent(const std::string& user_id,
                      const std::string& policy,
                      const std::string& version,
                      const std::string& ip = "") {
        AuditEvent evt;
        evt.timestamp = now_epoch_ms();
        evt.event_type = "consent_granted";
        evt.user_id = user_id;
        evt.details = "policy=" + policy + " version=" + version;
        evt.ip_address = ip;
        evt.result = "success";
        log_(std::move(evt));
    }

    void log_consent_revocation(const std::string& user_id,
                                 const std::string& policy,
                                 const std::string& ip = "") {
        AuditEvent evt;
        evt.timestamp = now_epoch_ms();
        evt.event_type = "consent_revoked";
        evt.user_id = user_id;
        evt.details = "policy=" + policy;
        evt.ip_address = ip;
        evt.result = "success";
        log_(std::move(evt));
    }

    void log_terms_published(const std::string& admin_user,
                              const std::string& version,
                              const std::string& ip = "") {
        AuditEvent evt;
        evt.timestamp = now_epoch_ms();
        evt.event_type = "terms_published";
        evt.user_id = admin_user;
        evt.details = "version=" + version;
        evt.ip_address = ip;
        evt.result = "success";
        log_(std::move(evt));
    }

    void log_terms_deprecated(const std::string& admin_user,
                               const std::string& version,
                               const std::string& ip = "") {
        AuditEvent evt;
        evt.timestamp = now_epoch_ms();
        evt.event_type = "terms_deprecated";
        evt.user_id = admin_user;
        evt.details = "version=" + version;
        evt.ip_address = ip;
        evt.result = "success";
        log_(std::move(evt));
    }

    std::vector<AuditEvent> get_events(const std::string& user_id = "",
                                        const std::string& event_type = "",
                                        int64_t since = 0,
                                        int limit = 100) const {
        std::shared_lock lock(mutex_);
        std::vector<AuditEvent> result;
        for (auto it = events_.rbegin(); it != events_.rend(); ++it) {
            if (!user_id.empty() && it->user_id != user_id) continue;
            if (!event_type.empty() && it->event_type != event_type) continue;
            if (since > 0 && it->timestamp < since) continue;
            result.push_back(*it);
            if (static_cast<int>(result.size()) >= limit) break;
        }
        return result;
    }

    std::vector<AuditEvent> get_recent_failures(const std::string& user_id = "",
                                                  int limit = 50) const {
        std::shared_lock lock(mutex_);
        std::vector<AuditEvent> result;
        for (auto it = events_.rbegin(); it != events_.rend(); ++it) {
            if (!user_id.empty() && it->user_id != user_id) continue;
            if (it->result != "failure") continue;
            result.push_back(*it);
            if (static_cast<int>(result.size()) >= limit) break;
        }
        return result;
    }

    json to_json() const {
        std::shared_lock lock(mutex_);
        json j;
        j["events"] = json::array();
        for (const auto& evt : events_) {
            json ej;
            ej["timestamp"] = evt.timestamp;
            ej["event_type"] = evt.event_type;
            ej["user_id"] = evt.user_id;
            ej["session_id"] = evt.session_id;
            ej["details"] = evt.details;
            ej["ip_address"] = evt.ip_address;
            ej["result"] = evt.result;
            j["events"].push_back(ej);
        }
        j["total_events"] = events_.size();
        return j;
    }

private:
    void log_(AuditEvent evt) {
        std::unique_lock lock(mutex_);
        events_.push_back(std::move(evt));
        // Trim old events if too many
        constexpr size_t MAX_EVENTS = 100000;
        while (events_.size() > MAX_EVENTS) {
            events_.pop_front();
        }
    }

    mutable std::shared_mutex mutex_;
    std::deque<AuditEvent> events_;
};

// =============================================================================
// Rate Limiter for UIA
// =============================================================================

class UIARateLimiter {
public:
    struct Config {
        int max_attempts_per_stage = 5;
        int max_sessions_per_user = 10;
        std::chrono::seconds window_duration{60};
        std::chrono::seconds cooldown_after_failure{5};
    };

    explicit UIARateLimiter(Config config) : config_(std::move(config)) {}

    bool allow_attempt(const std::string& user_id,
                        const std::string& stage) {
        std::unique_lock lock(mutex_);

        auto key = user_id + ":" + stage;
        auto& entry = attempts_[key];
        auto now = now_epoch_seconds();

        // Clean old entries
        entry.erase(
            std::remove_if(entry.begin(), entry.end(),
                [&](int64_t ts) {
                    return (now - ts) >
                        std::chrono::duration_cast<std::chrono::seconds>(
                            config_.window_duration).count();
                }),
            entry.end());

        if (static_cast<int>(entry.size()) >= config_.max_attempts_per_stage) {
            return false;
        }

        entry.push_back(now);
        return true;
    }

    bool allow_new_session(const std::string& user_id) {
        std::unique_lock lock(mutex_);

        auto now = now_epoch_seconds();
        auto& sessions = active_sessions_[user_id];

        // Clean expired
        sessions.erase(
            std::remove_if(sessions.begin(), sessions.end(),
                [&](const SessionEntry& se) {
                    return se.expires_at < now;
                }),
            sessions.end());

        if (static_cast<int>(sessions.size()) >= config_.max_sessions_per_user) {
            return false;
        }

        return true;
    }

    void record_session(const std::string& user_id,
                         const std::string& session_id,
                         int64_t ttl_seconds) {
        std::unique_lock lock(mutex_);
        SessionEntry se;
        se.session_id = session_id;
        se.created_at = now_epoch_seconds();
        se.expires_at = se.created_at + ttl_seconds;
        active_sessions_[user_id].push_back(std::move(se));
    }

    void remove_session(const std::string& user_id,
                         const std::string& session_id) {
        std::unique_lock lock(mutex_);
        auto it = active_sessions_.find(user_id);
        if (it != active_sessions_.end()) {
            it->second.erase(
                std::remove_if(it->second.begin(), it->second.end(),
                    [&](const SessionEntry& se) {
                        return se.session_id == session_id;
                    }),
                it->second.end());
        }
    }

    int get_active_session_count(const std::string& user_id) const {
        std::shared_lock lock(mutex_);
        auto it = active_sessions_.find(user_id);
        if (it == active_sessions_.end()) return 0;
        auto now = now_epoch_seconds();
        int count = 0;
        for (const auto& se : it->second) {
            if (se.expires_at > now) count++;
        }
        return count;
    }

    void clear_user(const std::string& user_id) {
        std::unique_lock lock(mutex_);
        active_sessions_.erase(user_id);
        // Clean attempts for this user
        for (auto it = attempts_.begin(); it != attempts_.end(); ) {
            if (it->first.find(user_id + ":") == 0) {
                it = attempts_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    struct SessionEntry {
        std::string session_id;
        int64_t created_at;
        int64_t expires_at;
    };

    Config config_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::vector<int64_t>> attempts_;
    std::unordered_map<std::string, std::vector<SessionEntry>> active_sessions_;
};

// =============================================================================
// Consent Export (GDPR Data Portability)
// =============================================================================

class ConsentExporter {
public:
    explicit ConsentExporter(
        std::shared_ptr<ConsentTracker> consent,
        std::shared_ptr<TermsOfServiceManager> tos)
        : consent_(std::move(consent)),
          tos_(std::move(tos)) {}

    /**
     * Export all consent data for a user in machine-readable JSON.
     */
    json export_user_consent_data(const std::string& user_id) {
        json data;
        data["user_id"] = user_id;
        data["export_timestamp"] = now_epoch_ms();
        data["export_format_version"] = "1.0";

        // Consent records
        auto history = consent_->get_user_consent_history(user_id);
        json consents = json::array();
        for (const auto& rec : history) {
            json cj;
            cj["policy_id"] = rec.policy_id;
            cj["version"] = rec.version;
            cj["status"] = (rec.status == ConsentTracker::ConsentStatus::GRANTED)
                           ? "granted" : "revoked";
            cj["granted_at"] = rec.granted_at;
            if (rec.revoked_at > 0) cj["revoked_at"] = rec.revoked_at;
            if (rec.expires_at > 0) cj["expires_at"] = rec.expires_at;
            cj["granted_via"] = rec.granted_via;
            consents.push_back(cj);
        }
        data["consents"] = consents;

        // Terms versions the user has seen
        auto user_consents = tos_->get_user_consents(user_id);
        json terms_data = json::object();
        for (const auto& [version, timestamp] : user_consents) {
            auto tv = tos_->get_version(version);
            if (tv) {
                json td;
                td["title"] = tv->title;
                td["accepted_at"] = timestamp;
                td["content_url"] = tv->content_url;
                terms_data[version] = td;
            }
        }
        data["terms_of_service"] = terms_data;

        // Privacy policy
        // (would integrate with PrivacyPolicyManager here)

        return data;
    }

    /**
     * Export for GDPR Article 20 (data portability).
     */
    std::string export_gdpr_portable(const std::string& user_id) {
        return export_user_consent_data(user_id).dump(2);
    }

private:
    std::shared_ptr<ConsentTracker> consent_;
    std::shared_ptr<TermsOfServiceManager> tos_;
};

} // namespace auth
} // namespace progressive

// =============================================================================
// End of file
// =============================================================================
