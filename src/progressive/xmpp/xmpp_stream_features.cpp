// xmpp_stream_features.cpp - Full XMPP stream features, SASL, TLS, stream management
// RFC 6120/6121, XEP-0030, XEP-0138, XEP-0198, XEP-0199, XEP-0206, RFC 7395
// Complete stream lifecycle: open → features → TLS → restart → SASL → bind → session → ready
// 3500+ lines of production-grade stream negotiation

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <deque>
#include <memory>
#include <functional>
#include <optional>
#include <variant>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>
#include <cstring>
#include <ctime>
#include <regex>
#include <set>
#include <thread>

// OpenSSL for TLS and crypto
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

// zlib for stream compression (XEP-0138)
#include <zlib.h>

// nlohmann json for config
#include <nlohmann/json.hpp>

// =============================================================================
// progressive::xmpp namespace
// =============================================================================
namespace progressive {
namespace xmpp {

using json = nlohmann::json;

// =============================================================================
// XML namespace URIs (XEP-0030, RFC 6120)
// =============================================================================
namespace ns {
    constexpr const char* STREAMS    = "http://etherx.jabber.org/streams";
    constexpr const char* CLIENT     = "jabber:client";
    constexpr const char* SERVER     = "jabber:server";
    constexpr const char* TLS        = "urn:ietf:params:xml:ns:xmpp-tls";
    constexpr const char* SASL       = "urn:ietf:params:xml:ns:xmpp-sasl";
    constexpr const char* BIND       = "urn:ietf:params:xml:ns:xmpp-bind";
    constexpr const char* SESSION    = "urn:ietf:params:xml:ns:xmpp-session";
    constexpr const char* STREAM_MGMT = "urn:xmpp:sm:3";
    constexpr const char* STREAM_MGMT_ACK = "urn:xmpp:sm:3:ack";
    constexpr const char* COMPRESS   = "http://jabber.org/features/compress";
    constexpr const char* COMPRESS_METHOD = "http://jabber.org/protocol/compress";
    constexpr const char* STREAM_ERR = "urn:ietf:params:xml:ns:xmpp-streams";
    constexpr const char* BOSH       = "urn:xmpp:bosh";
    constexpr const char* HTTP_BIND  = "http://jabber.org/protocol/httpbind";
    constexpr const char* WEBSOCKET  = "urn:xmpp:websocket";
    constexpr const char* DISCO_INFO = "http://jabber.org/protocol/disco#info";
    constexpr const char* DISCO_ITEMS = "http://jabber.org/protocol/disco#items";
    constexpr const char* CARBONS    = "urn:xmpp:carbons:2";
    constexpr const char* CSI        = "urn:xmpp:csi:0";
}

// =============================================================================
// Forward declarations
// =============================================================================
struct Jid;
struct StreamSession;
class  StreamFeaturesManager;

// =============================================================================
// JID (Jabber Identifier)
// =============================================================================
struct Jid {
    std::string node;
    std::string domain;
    std::string resource;

    Jid() = default;
    Jid(const std::string& bare) { parse(bare); }
    Jid(const std::string& n, const std::string& d, const std::string& r = "")
        : node(n), domain(d), resource(r) {}

    static std::optional<Jid> from_string(const std::string& str) {
        Jid j;
        if (j.parse(str)) return j;
        return std::nullopt;
    }

    bool parse(const std::string& str) {
        if (str.empty()) return false;
        std::string s = str;
        size_t slash = s.find('/');
        if (slash != std::string::npos) {
            resource = s.substr(slash + 1);
            s = s.substr(0, slash);
        }
        size_t at = s.find('@');
        if (at != std::string::npos) {
            node = s.substr(0, at);
            domain = s.substr(at + 1);
        } else {
            domain = s;
        }
        return !domain.empty();
    }

    std::string bare() const {
        if (node.empty()) return domain;
        return node + "@" + domain;
    }

    std::string full() const {
        std::string result = bare();
        if (!resource.empty()) result += "/" + resource;
        return result;
    }

    bool operator==(const Jid& o) const {
        return node == o.node && domain == o.domain && resource == o.resource;
    }

    bool bare_eq(const Jid& o) const {
        return node == o.node && domain == o.domain;
    }

    bool empty() const { return domain.empty(); }
};

// =============================================================================
// Utility functions
// =============================================================================
namespace {

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t now_sec() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string xml_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default: out += c;
        }
    }
    return out;
}

std::string gen_stream_id() {
    static std::atomic<int64_t> counter{1};
    std::ostringstream oss;
    oss << "sid-" << std::hex << now_ms() << "-"
        << std::dec << counter.fetch_add(1, std::memory_order_relaxed);
    return oss.str();
}

std::string gen_nonce(size_t len = 24) {
    static const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static thread_local std::mt19937 rng(
        static_cast<unsigned>(now_ms() ^
        std::hash<std::thread::id>{}(std::this_thread::get_id())));
    std::uniform_int_distribution<> dist(0, 61);
    std::string nonce(len, 'A');
    for (auto& c : nonce) c = charset[dist(rng)];
    return nonce;
}

std::string gen_salt(size_t len = 16) {
    std::string salt(len, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&salt[0]),
                   static_cast<int>(len)) != 1) {
        // fallback
        static thread_local std::mt19937 rng(static_cast<unsigned>(now_ms()));
        std::uniform_int_distribution<> dist(0, 255);
        for (auto& c : salt) c = static_cast<char>(dist(rng));
    }
    return salt;
}

// =============================================================================
// Base64 codec (RFC 4648)
// =============================================================================
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    int val = 0, valb = -6;
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64_table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(b64_table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string base64_decode(const std::string& s) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(unsigned char)b64_table[i]] = i;
    int val = 0, valb = -8;
    for (unsigned char c : s) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// =============================================================================
// Hash functions (OpenSSL-based)
// =============================================================================
std::string sha1(const std::string& data) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(data.data()),
         data.size(), hash);
    return std::string(reinterpret_cast<char*>(hash), SHA_DIGEST_LENGTH);
}

std::string sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(hash, &ctx);
    return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

std::string sha512(const std::string& data) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, data.data(), data.size());
    SHA512_Final(hash, &ctx);
    return std::string(reinterpret_cast<char*>(hash), SHA512_DIGEST_LENGTH);
}

std::string hmac_sha1(const std::string& key, const std::string& data) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()),
         data.size(), result, &len);
    return std::string(reinterpret_cast<char*>(result), len);
}

std::string hmac_sha256(const std::string& key, const std::string& data) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()),
         data.size(), result, &len);
    return std::string(reinterpret_cast<char*>(result), len);
}

std::string hmac_sha512(const std::string& key, const std::string& data) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha512(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()),
         data.size(), result, &len);
    return std::string(reinterpret_cast<char*>(result), len);
}

std::string hex_encode(const std::string& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : data) oss << std::setw(2) << (int)c;
    return oss.str();
}

std::string hex_decode(const std::string& hex) {
    std::string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int val;
        std::istringstream iss(hex.substr(i, 2));
        iss >> std::hex >> val;
        out.push_back(static_cast<char>(val));
    }
    return out;
}

std::string xor_strings(const std::string& a, const std::string& b) {
    std::string out;
    out.reserve(std::min(a.size(), b.size()));
    for (size_t i = 0; i < a.size() && i < b.size(); i++)
        out.push_back(a[i] ^ b[i]);
    return out;
}

std::string pbkdf2_hmac_sha1(const std::string& password,
                              const std::string& salt,
                              int iterations, int key_len) {
    std::string result(key_len, '\0');
    PKCS5_PBKDF2_HMAC_SHA1(password.data(),
        static_cast<int>(password.size()),
        reinterpret_cast<const unsigned char*>(salt.data()),
        static_cast<int>(salt.size()), iterations, key_len,
        reinterpret_cast<unsigned char*>(&result[0]));
    return result;
}

std::string pbkdf2_hmac_sha256(const std::string& password,
                                const std::string& salt,
                                int iterations, int key_len) {
    std::string result(key_len, '\0');
    PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
        reinterpret_cast<const unsigned char*>(salt.data()),
        static_cast<int>(salt.size()), iterations, EVP_sha256(),
        key_len, reinterpret_cast<unsigned char*>(&result[0]));
    return result;
}

std::string pbkdf2_hmac_sha512(const std::string& password,
                                const std::string& salt,
                                int iterations, int key_len) {
    std::string result(key_len, '\0');
    PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
        reinterpret_cast<const unsigned char*>(salt.data()),
        static_cast<int>(salt.size()), iterations, EVP_sha512(),
        key_len, reinterpret_cast<unsigned char*>(&result[0]));
    return result;
}

// =============================================================================
// XML element builder
// =============================================================================
class XMLElement {
public:
    XMLElement() = default;
    explicit XMLElement(const std::string& tag) : tag_(tag) {}
    XMLElement(const std::string& tag, const std::string& text)
        : tag_(tag), text_(text) {}

    XMLElement& attr(const std::string& name, const std::string& value) {
        attrs_.push_back({name, value});
        return *this;
    }
    XMLElement& xmlns(const std::string& ns) {
        return attr("xmlns", ns);
    }
    XMLElement& child(const XMLElement& el) {
        children_.push_back(el);
        return *this;
    }
    XMLElement& child(const std::string& raw_xml) {
        XMLElement raw;
        raw.tag_ = "";  // raw text marker
        raw.text_ = raw_xml;
        children_.push_back(raw);
        return *this;
    }
    XMLElement& text(const std::string& t) {
        text_ = t;
        return *this;
    }
    XMLElement& add_child(const std::string& tag) {
        children_.emplace_back(tag);
        return children_.back();
    }

    std::string to_string() const {
        std::ostringstream oss;
        write(oss, 0);
        return oss.str();
    }

private:
    void write(std::ostream& os, int) const {
        if (tag_.empty()) {
            os << xml_escape(text_);
            return;
        }
        os << "<" << tag_;
        for (auto& [k, v] : attrs_)
            os << " " << k << "='" << xml_escape(v) << "'";
        if (text_.empty() && children_.empty()) {
            os << "/>";
        } else {
            os << ">";
            if (!text_.empty()) os << xml_escape(text_);
            if (!children_.empty()) {
                for (auto& c : children_) c.write(os, 0);
            }
            os << "</" << tag_ << ">";
        }
    }

    std::string tag_;
    std::string text_;
    std::vector<std::pair<std::string, std::string>> attrs_;
    std::vector<XMLElement> children_;
};

// =============================================================================
// Stream error types (RFC 6120 §4.9)
// =============================================================================
enum class StreamErrorType {
    BAD_FORMAT,
    BAD_NAMESPACE_PREFIX,
    CONFLICT,
    CONNECTION_TIMEOUT,
    HOST_GONE,
    HOST_UNKNOWN,
    IMPROPER_ADDRESSING,
    INTERNAL_SERVER_ERROR,
    INVALID_FROM,
    INVALID_NAMESPACE,
    INVALID_XML,
    NOT_AUTHORIZED,
    NOT_WELL_FORMED,
    POLICY_VIOLATION,
    REMOTE_CONNECTION_FAILED,
    RESET,
    RESOURCE_CONSTRAINT,
    RESTRICTED_XML,
    SEE_OTHER_HOST,
    SYSTEM_SHUTDOWN,
    UNDEFINED_CONDITION,
    UNSUPPORTED_ENCODING,
    UNSUPPORTED_FEATURE,
    UNSUPPORTED_STANZA_TYPE,
    UNSUPPORTED_VERSION,
};

struct StreamError {
    StreamErrorType type = StreamErrorType::UNDEFINED_CONDITION;
    std::string condition;
    std::string text;
    std::string app_specific_ns;
    std::string app_specific_text;

    static StreamError make(StreamErrorType t, const std::string& txt = "") {
        StreamError e;
        e.type = t;
        e.condition = stream_error_condition(t);
        e.text = txt;
        return e;
    }

    std::string to_xml() const {
        XMLElement err("stream:error");
        XMLElement cond(condition);
        cond.xmlns(ns::STREAM_ERR);
        err.child(cond);
        if (!text.empty())
            err.child(XMLElement("text", text).xmlns(ns::STREAM_ERR));
        if (!app_specific_ns.empty())
            err.child(XMLElement(app_specific_ns, app_specific_text));
        return err.to_string();
    }

    static const char* stream_error_condition(StreamErrorType t) {
        switch (t) {
            case StreamErrorType::BAD_FORMAT:                 return "bad-format";
            case StreamErrorType::BAD_NAMESPACE_PREFIX:       return "bad-namespace-prefix";
            case StreamErrorType::CONFLICT:                   return "conflict";
            case StreamErrorType::CONNECTION_TIMEOUT:         return "connection-timeout";
            case StreamErrorType::HOST_GONE:                  return "host-gone";
            case StreamErrorType::HOST_UNKNOWN:               return "host-unknown";
            case StreamErrorType::IMPROPER_ADDRESSING:        return "improper-addressing";
            case StreamErrorType::INTERNAL_SERVER_ERROR:      return "internal-server-error";
            case StreamErrorType::INVALID_FROM:               return "invalid-from";
            case StreamErrorType::INVALID_NAMESPACE:          return "invalid-namespace";
            case StreamErrorType::INVALID_XML:                return "invalid-xml";
            case StreamErrorType::NOT_AUTHORIZED:             return "not-authorized";
            case StreamErrorType::NOT_WELL_FORMED:            return "not-well-formed";
            case StreamErrorType::POLICY_VIOLATION:           return "policy-violation";
            case StreamErrorType::REMOTE_CONNECTION_FAILED:   return "remote-connection-failed";
            case StreamErrorType::RESET:                      return "reset";
            case StreamErrorType::RESOURCE_CONSTRAINT:        return "resource-constraint";
            case StreamErrorType::RESTRICTED_XML:             return "restricted-xml";
            case StreamErrorType::SEE_OTHER_HOST:             return "see-other-host";
            case StreamErrorType::SYSTEM_SHUTDOWN:            return "system-shutdown";
            case StreamErrorType::UNDEFINED_CONDITION:        return "undefined-condition";
            case StreamErrorType::UNSUPPORTED_ENCODING:       return "unsupported-encoding";
            case StreamErrorType::UNSUPPORTED_FEATURE:        return "unsupported-feature";
            case StreamErrorType::UNSUPPORTED_STANZA_TYPE:    return "unsupported-stanza-type";
            case StreamErrorType::UNSUPPORTED_VERSION:        return "unsupported-version";
        }
        return "undefined-condition";
    }
};

// =============================================================================
// SASL error types (RFC 6120 §6.5)
// =============================================================================
struct SaslError {
    std::string condition;
    std::string text;

    static SaslError aborted()            { return {"aborted", ""}; }
    static SaslError account_disabled()   { return {"account-disabled", ""}; }
    static SaslError credentials_expired(){ return {"credentials-expired", ""}; }
    static SaslError encryption_required(){ return {"encryption-required", ""}; }
    static SaslError incorrect_encoding() { return {"incorrect-encoding", ""}; }
    static SaslError invalid_authzid()    { return {"invalid-authzid", ""}; }
    static SaslError invalid_mechanism()  { return {"invalid-mechanism", ""}; }
    static SaslError malformed_request()  { return {"malformed-request", ""}; }
    static SaslError mechanism_too_weak() { return {"mechanism-too-weak", ""}; }
    static SaslError not_authorized()     { return {"not-authorized", ""}; }
    static SaslError temporary_auth_failure() { return {"temporary-auth-failure", ""}; }

    std::string to_xml() const {
        XMLElement f("failure");
        f.xmlns(ns::SASL);
        f.child(XMLElement(condition));
        if (!text.empty())
            f.child(XMLElement("text", text));
        return f.to_string();
    }

    std::string to_xml_with_optional() const {
        XMLElement f("failure");
        f.xmlns(ns::SASL);
        f.child(XMLElement(condition));
        if (!text.empty())
            f.child(XMLElement("text", text));
        return f.to_string();
    }
};

// =============================================================================
// TLS Context - OpenSSL wrapper
// =============================================================================
class TlsContext {
public:
    TlsContext() {
        ctx_ = SSL_CTX_new(TLS_server_method());
        if (!ctx_) throw std::runtime_error("Failed to create SSL_CTX");
        SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
        SSL_CTX_set_options(ctx_,
            SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
            SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
            SSL_OP_CIPHER_SERVER_PREFERENCE);
        SSL_CTX_set_mode(ctx_, SSL_MODE_ENABLE_PARTIAL_WRITE |
                               SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        set_cipher_list("HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4:@STRENGTH");
    }

    ~TlsContext() {
        if (ctx_) SSL_CTX_free(ctx_);
    }

    bool load_certificate(const std::string& cert_file,
                          const std::string& key_file) {
        if (SSL_CTX_use_certificate_file(ctx_, cert_file.c_str(),
                                          SSL_FILETYPE_PEM) <= 0)
            return false;
        if (SSL_CTX_use_PrivateKey_file(ctx_, key_file.c_str(),
                                          SSL_FILETYPE_PEM) <= 0)
            return false;
        if (!SSL_CTX_check_private_key(ctx_))
            return false;
        return true;
    }

    bool load_certificate_chain(const std::string& chain_file) {
        return SSL_CTX_use_certificate_chain_file(ctx_, chain_file.c_str()) > 0;
    }

    bool load_certificate_from_memory(const std::string& cert_pem,
                                       const std::string& key_pem) {
        BIO* cert_bio = BIO_new_mem_buf(cert_pem.data(),
                                         static_cast<int>(cert_pem.size()));
        X509* cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
        BIO_free(cert_bio);
        if (!cert) return false;
        if (SSL_CTX_use_certificate(ctx_, cert) <= 0) {
            X509_free(cert);
            return false;
        }
        X509_free(cert);

        BIO* key_bio = BIO_new_mem_buf(key_pem.data(),
                                        static_cast<int>(key_pem.size()));
        EVP_PKEY* key = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
        BIO_free(key_bio);
        if (!key) return false;
        if (SSL_CTX_use_PrivateKey(ctx_, key) <= 0) {
            EVP_PKEY_free(key);
            return false;
        }
        EVP_PKEY_free(key);

        return SSL_CTX_check_private_key(ctx_) > 0;
    }

    void set_cipher_list(const std::string& ciphers) {
        SSL_CTX_set_cipher_list(ctx_, ciphers.c_str());
    }

    void set_verify_client(bool verify) {
        if (verify) {
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                               nullptr);
        } else {
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
        }
    }

    void set_ca_file(const std::string& ca_file) {
        SSL_CTX_load_verify_locations(ctx_, ca_file.c_str(), nullptr);
    }

    void set_dh_params(const std::string& dh_file) {
        BIO* bio = BIO_new_file(dh_file.c_str(), "r");
        if (bio) {
            DH* dh = PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr);
            if (dh) {
                SSL_CTX_set_tmp_dh(ctx_, dh);
                DH_free(dh);
            }
            BIO_free(bio);
        }
    }

    void set_ecdh_curve(const std::string& curve = "prime256v1") {
        SSL_CTX_set_ecdh_auto(ctx_, 1);
    }

    SSL_CTX* ctx() { return ctx_; }

private:
    SSL_CTX* ctx_ = nullptr;
};

// =============================================================================
// TLS Handshake state machine per connection
// =============================================================================
class TlsHandshake {
public:
    TlsHandshake(TlsContext& tls_ctx) : tls_ctx_(tls_ctx) {}

    bool init(int fd) {
        ssl_ = SSL_new(tls_ctx_.ctx());
        if (!ssl_) return false;
        SSL_set_fd(ssl_, fd);
        SSL_set_accept_state(ssl_);
        return true;
    }

    int do_handshake() {
        if (!ssl_) return -1;
        int ret = SSL_do_handshake(ssl_);
        if (ret == 1) {
            handshake_complete_ = true;
            return 1;
        }
        int err = SSL_get_error(ssl_, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return 0;
        return -1;
    }

    bool is_complete() const { return handshake_complete_; }

    int read(char* buf, int len) {
        if (!ssl_) return -1;
        return SSL_read(ssl_, buf, len);
    }

    int write(const char* buf, int len) {
        if (!ssl_) return -1;
        return SSL_write(ssl_, buf, len);
    }

    int pending() {
        if (!ssl_) return 0;
        return SSL_pending(ssl_);
    }

    std::string get_peer_cert_subject() const {
        if (!ssl_) return "";
        X509* cert = SSL_get_peer_certificate(ssl_);
        if (!cert) return "";
        char* subj = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        std::string result(subj ? subj : "");
        OPENSSL_free(subj);
        X509_free(cert);
        return result;
    }

    std::string get_peer_cert_fingerprint(const std::string& algo = "sha256") const {
        if (!ssl_) return "";
        X509* cert = SSL_get_peer_certificate(ssl_);
        if (!cert) return "";
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;
        const EVP_MD* evp = EVP_sha256();
        if (algo == "sha1") evp = EVP_sha1();
        else if (algo == "sha512") evp = EVP_sha512();
        X509_digest(cert, evp, md, &md_len);
        X509_free(cert);
        std::string fp(reinterpret_cast<char*>(md), md_len);
        return hex_encode(fp);
    }

    std::string get_cipher() const {
        if (!ssl_) return "";
        return SSL_get_cipher(ssl_);
    }

    std::string get_protocol_version() const {
        if (!ssl_) return "";
        return SSL_get_version(ssl_);
    }

    void shutdown() {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
    }

    ~TlsHandshake() { shutdown(); }

private:
    TlsContext& tls_ctx_;
    SSL* ssl_ = nullptr;
    bool handshake_complete_ = false;
};

// =============================================================================
// Stream compression (XEP-0138) - zlib
// =============================================================================
class StreamCompression {
public:
    enum Method {
        ZLIB,
        LZMA,
    };

    bool init_zlib_compress() {
        memset(&z_stream_out_, 0, sizeof(z_stream_out_));
        if (deflateInit(&z_stream_out_, Z_DEFAULT_COMPRESSION) != Z_OK)
            return false;
        compression_active_ = true;
        method_ = ZLIB;
        return true;
    }

    bool init_zlib_decompress() {
        memset(&z_stream_in_, 0, sizeof(z_stream_in_));
        if (inflateInit(&z_stream_in_) != Z_OK)
            return false;
        decompression_active_ = true;
        method_ = ZLIB;
        return true;
    }

    std::string compress(const std::string& data) {
        if (!compression_active_) return data;
        z_stream_out_.next_in = reinterpret_cast<Bytef*>(
            const_cast<char*>(data.data()));
        z_stream_out_.avail_in = static_cast<uInt>(data.size());

        std::string out;
        out.resize(data.size() + data.size() / 100 + 13);

        z_stream_out_.next_out = reinterpret_cast<Bytef*>(&out[0]);
        z_stream_out_.avail_out = static_cast<uInt>(out.size());

        if (deflate(&z_stream_out_, Z_SYNC_FLUSH) != Z_OK)
            return data;

        out.resize(out.size() - z_stream_out_.avail_out);
        return out;
    }

    std::string decompress(const std::string& data) {
        if (!decompression_active_) return data;
        z_stream_in_.next_in = reinterpret_cast<Bytef*>(
            const_cast<char*>(data.data()));
        z_stream_in_.avail_in = static_cast<uInt>(data.size());

        std::string out;
        out.resize(data.size() * 4);

        z_stream_in_.next_out = reinterpret_cast<Bytef*>(&out[0]);
        z_stream_in_.avail_out = static_cast<uInt>(out.size());

        int ret = inflate(&z_stream_in_, Z_SYNC_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END)
            return data;

        out.resize(out.size() - z_stream_in_.avail_out);

        if (ret == Z_STREAM_END) {
            inflateReset(&z_stream_in_);
        }

        return out;
    }

    bool is_compressed() const { return compression_active_; }
    Method method() const { return method_; }

    void reset() {
        if (compression_active_)
            deflateEnd(&z_stream_out_);
        if (decompression_active_)
            inflateEnd(&z_stream_in_);
        compression_active_ = false;
        decompression_active_ = false;
    }

    ~StreamCompression() { reset(); }

private:
    z_stream z_stream_out_{};
    z_stream z_stream_in_{};
    bool compression_active_ = false;
    bool decompression_active_ = false;
    Method method_ = ZLIB;
};

// =============================================================================
// SCRAM state (RFC 5802)
// =============================================================================
struct ScramState {
    // Server-side state
    std::string stored_key;     // H(ClientKey)
    std::string server_key;
    std::string salt;
    int iterations = 4096;
    std::string nonce;          // server + client combined nonce
    std::string client_first_message_bare;
    std::string client_final_message_wo_proof;
    std::string server_signature;
    std::string auth_message;
    bool client_proof_verified = false;

    // Hash function type
    enum HashType { SHA1, SHA256, SHA512 };
    HashType hash_type = SHA256;
    size_t hash_len = SHA256_DIGEST_LENGTH;
    bool saslprep_needed = false;
};

// =============================================================================
// Stream Management (XEP-0198) state
// =============================================================================
struct StreamManagementState {
    bool enabled = false;
    bool resumed = false;
    std::string sm_id;
    uint32_t inbound_count = 0;
    uint32_t outbound_count = 0;
    uint32_t last_ack_from_client = 0;
    uint32_t last_ack_to_client = 0;
    std::deque<std::string> unacked_stanzas;
    size_t max_unacked = 100;
    int64_t last_ack_time = 0;
    int64_t resume_timeout_sec = 300;

    // Resume state (stored server-side when connection drops)
    std::string resume_jid;
    std::string resume_stream_id;
    std::string prev_sm_id;
    int64_t session_start_time = 0;
};

// =============================================================================
// Stream Session - complete per-connection state
// =============================================================================
enum class StreamState : uint8_t {
    INIT,
    STREAM_OPEN_SENT,
    STREAM_OPEN_RECEIVED,
    FEATURES_SENT,
    STARTTLS_REQUESTED,
    TLS_NEGOTIATING,
    TLS_ESTABLISHED,
    SASL_NEGOTIATING,
    SASL_AUTHENTICATED,
    RESOURCE_BINDING,
    SESSION_ESTABLISHING,
    READY,
    CLOSING,
    CLOSED,
};

struct StreamSession {
    int fd = -1;
    StreamState state = StreamState::INIT;
    Jid user_jid;
    std::string stream_id;
    std::string stream_namespace;  // jabber:client or jabber:server
    std::string xml_lang = "en";
    std::string stream_from;
    std::string stream_to;
    std::string stream_version = "1.0";
    std::string ip_address;
    int port = 0;

    // TLS state
    bool tls_enabled = false;
    bool tls_requested = false;
    std::unique_ptr<TlsHandshake> tls_handshake;
    std::string tls_cipher;
    std::string tls_protocol;

    // SASL state
    bool sasl_authenticated = false;
    std::string sasl_mechanism;
    std::string sasl_authzid;
    std::string sasl_authcid;
    std::string sasl_password;
    ScramState scram;
    int sasl_round = 0;

    // Resource binding
    bool resource_bound = false;
    std::string bound_resource;
    std::string bound_jid_full;

    // Session establishment
    bool session_established = false;

    // Compression
    std::unique_ptr<StreamCompression> compression;
    bool compression_offered = false;

    // Stream management (XEP-0198)
    StreamManagementState sm;

    // Stream feature caching
    std::string cached_features;        // last computed features XML
    StreamState cached_features_state;  // state at which they were computed
    int64_t features_generated_at = 0;
    bool features_need_refresh = true;

    // Timing
    int64_t connected_at = 0;
    int64_t last_activity = 0;
    int64_t stream_opened_at = 0;

    // Buffers
    std::string xml_buffer;
    std::deque<std::string> send_queue;

    // BOSH/WebSocket flags
    bool is_bosh = false;
    bool is_websocket = false;
    std::string bosh_sid;
    int bosh_wait = 60;
    int bosh_hold = 1;
    int bosh_requests = 0;

    // CSI
    bool csi_active = false;

    // Error state
    bool has_error = false;
    StreamError last_error;

    void invalidate_features_cache() {
        features_need_refresh = true;
    }
};

// =============================================================================
// SCRAM implementation - supports SHA-1, SHA-256, SHA-512
// =============================================================================
class ScramAuth {
public:
    using HashFunc = std::function<std::string(const std::string&)>;
    using HmacFunc = std::function<std::string(const std::string&, const std::string&)>;

    struct HashInfo {
        std::string name;
        HashFunc hash;
        HmacFunc hmac;
        size_t digest_len;
        int iteration_count;
    };

    static const HashInfo& get_hash_info(const std::string& mechanism) {
        static std::unordered_map<std::string, HashInfo> infos = {
            {"SCRAM-SHA-1", {"SHA-1", sha1, hmac_sha1,
                             SHA_DIGEST_LENGTH, 4096}},
            {"SCRAM-SHA-256", {"SHA-256", sha256, hmac_sha256,
                               SHA256_DIGEST_LENGTH, 4096}},
            {"SCRAM-SHA-512", {"SHA-512", sha512, hmac_sha512,
                               SHA512_DIGEST_LENGTH, 4096}},
        };
        return infos.at(mechanism);
    }

    // Hi(str, salt, i) = PBKDF2 with HMAC
    static std::string hi(const HashInfo& info, const std::string& str,
                          const std::string& salt, int iterations) {
        return pbkdf2_hmac_sha256(str, salt, iterations,
                                   static_cast<int>(info.digest_len));
    }

    static std::string hi_sha1(const std::string& str, const std::string& salt,
                                int iterations, int dk_len) {
        return pbkdf2_hmac_sha1(str, salt, iterations, dk_len);
    }

    static std::string hi_sha256(const std::string& str, const std::string& salt,
                                  int iterations, int dk_len) {
        return pbkdf2_hmac_sha256(str, salt, iterations, dk_len);
    }

    static std::string hi_sha512(const std::string& str, const std::string& salt,
                                  int iterations, int dk_len) {
        return pbkdf2_hmac_sha512(str, salt, iterations, dk_len);
    }

    // Generate server-first message
    static std::string server_first(ScramState& state, const std::string& mechanism,
                                     const std::string& stored_key_base64,
                                     const std::string& server_key_base64,
                                     int iterations, const std::string& salt_base64) {
        const auto& info = get_hash_info(mechanism);
        state.hash_type = (mechanism == "SCRAM-SHA-1") ? ScramState::SHA1 :
                          (mechanism == "SCRAM-SHA-256") ? ScramState::SHA256 :
                                                           ScramState::SHA512;
        state.hash_len = info.digest_len;
        state.nonce = gen_nonce(24);
        state.salt = base64_decode(salt_base64.empty() ?
                                   base64_encode(gen_salt(16)) : salt_base64);
        state.iterations = iterations > 0 ? iterations : 4096;

        std::string msg = "r=" + state.nonce +
                          ",s=" + base64_encode(state.salt) +
                          ",i=" + std::to_string(state.iterations);

        return base64_encode(msg);
    }

    // Parse client-first message
    static bool parse_client_first(const std::string& b64_msg,
                                    std::string& gs2_header,
                                    std::string& authzid,
                                    std::string& username,
                                    std::string& client_nonce) {
        std::string msg = base64_decode(b64_msg);
        if (msg.empty()) return false;

        // GS2 header: n,, or n,a=authzid, or y,,
        size_t pos = 0;
        if (msg.size() < 3) return false;

        char gs2_cbind_flag = msg[pos++];
        if (gs2_cbind_flag != 'n' && gs2_cbind_flag != 'y' &&
            gs2_cbind_flag != 'p')
            return false;

        gs2_header = std::string(1, gs2_cbind_flag);

        if (msg[pos] == ',') {
            pos++;
        } else if (msg[pos] == '=') {
            // authzid present
            size_t end = msg.find(',', pos);
            if (end == std::string::npos) return false;
            authzid = msg.substr(pos + 1, end - pos - 1);
            gs2_header += ",a=" + authzid;
            pos = end + 1;
            if (msg[pos] == ',') pos++;
        }

        if (pos >= msg.size()) return false;

        size_t comma1 = msg.find(',', pos);
        if (comma1 == std::string::npos) return false;

        std::string kv1 = msg.substr(pos, comma1 - pos);
        if (kv1.size() < 2 || kv1[0] != 'n' || kv1[1] != '=')
            return false;
        username = kv1.substr(2);

        std::string kv2 = msg.substr(comma1 + 1);
        if (kv2.size() < 2 || kv2[0] != 'r' || kv2[1] != '=')
            return false;
        client_nonce = kv2.substr(2);

        return true;
    }

    // Compute server signature
    static std::string compute_server_signature(ScramState& state,
                                                 const std::string& mechanism,
                                                 const std::string& password) {
        const auto& info = get_hash_info(mechanism);

        // SaltedPassword = Hi(Normalize(password), salt, i)
        std::string salted_password;
        if (mechanism == "SCRAM-SHA-1")
            salted_password = hi_sha1(password, state.salt, state.iterations,
                                       static_cast<int>(info.digest_len));
        else if (mechanism == "SCRAM-SHA-256")
            salted_password = hi_sha256(password, state.salt, state.iterations,
                                         static_cast<int>(info.digest_len));
        else
            salted_password = hi_sha512(password, state.salt, state.iterations,
                                         static_cast<int>(info.digest_len));

        // ClientKey = HMAC(SaltedPassword, "Client Key")
        std::string client_key = info.hmac(salted_password, "Client Key");

        // StoredKey = H(ClientKey)
        state.stored_key = info.hash(client_key);

        // ServerKey = HMAC(SaltedPassword, "Server Key")
        state.server_key = info.hmac(salted_password, "Server Key");

        // ServerSignature = HMAC(ServerKey, AuthMessage)
        state.server_signature = info.hmac(state.server_key, state.auth_message);

        return base64_encode(state.server_signature);
    }

    // Verify client proof and return server final message
    static bool verify_client_proof(ScramState& state, const std::string& mechanism,
                                     const std::string& client_proof_b64,
                                     const std::string& client_final_wo_proof,
                                     const std::string& auth_message) {
        const auto& info = get_hash_info(mechanism);

        state.auth_message = auth_message;

        std::string client_proof = base64_decode(client_proof_b64);

        // ClientSignature = HMAC(StoredKey, AuthMessage)
        std::string client_signature = info.hmac(state.stored_key, auth_message);

        // ClientKey = ClientSignature XOR ClientProof
        std::string client_key = xor_strings(client_signature, client_proof);

        // Verify: H(ClientKey) == StoredKey
        std::string computed_stored = info.hash(client_key);
        if (computed_stored != state.stored_key)
            return false;

        state.client_proof_verified = true;

        // ServerSignature = HMAC(ServerKey, AuthMessage)
        state.server_signature = info.hmac(state.server_key, auth_message);

        return true;
    }

    // Generate server final with verification value
    static std::string server_final_with_verifier(ScramState& state) {
        return "v=" + base64_encode(state.server_signature);
    }

    // Escape '=' and ',' for SCRAM (RFC 5802 §2.2)
    static std::string saslname_escape(const std::string& s) {
        std::string out;
        for (char c : s) {
            if (c == ',') out += "=2C";
            else if (c == '=') out += "=3D";
            else out += c;
        }
        return out;
    }

    static std::string saslname_unescape(const std::string& s) {
        std::string out;
        for (size_t i = 0; i < s.size(); i++) {
            if (s[i] == '=' && i + 2 < s.size()) {
                std::string code = s.substr(i + 1, 2);
                if (code == "2C") { out += ','; i += 2; continue; }
                if (code == "3D") { out += '='; i += 2; continue; }
            }
            out += s[i];
        }
        return out;
    }
};

// =============================================================================
// SASL Mechanism implementations
// =============================================================================

// --- SASL PLAIN (RFC 4616) ---
class SaslPlain {
public:
    struct PlainAuth {
        std::string authzid;
        std::string authcid;
        std::string password;
    };

    static PlainAuth parse(const std::string& b64_data) {
        std::string decoded = base64_decode(b64_data);
        PlainAuth auth;

        size_t pos1 = decoded.find('\0');
        if (pos1 == std::string::npos) return auth;

        auth.authzid = decoded.substr(0, pos1);

        size_t pos2 = decoded.find('\0', pos1 + 1);
        if (pos2 == std::string::npos) return auth;

        auth.authcid = decoded.substr(pos1 + 1, pos2 - pos1 - 1);
        auth.password = decoded.substr(pos2 + 1);

        return auth;
    }

    static std::string encode(const std::string& authzid,
                               const std::string& authcid,
                               const std::string& password) {
        std::string data = authzid + '\0' + authcid + '\0' + password;
        return base64_encode(data);
    }

    static std::string success_data(const std::string& authcid = "") {
        if (authcid.empty()) return "<success xmlns='" + std::string(ns::SASL) + "'/>";
        return "<success xmlns='" + std::string(ns::SASL) + "'>" +
               base64_encode(authcid) + "</success>";
    }
};

// --- SASL EXTERNAL (RFC 4422) ---
class SaslExternal {
public:
    static std::string parse_authzid(const std::string& b64_data) {
        if (b64_data.empty() || b64_data == "=") return "";
        std::string decoded = base64_decode(b64_data);
        return decoded;
    }

    static std::string success(const std::string& authzid = "") {
        if (authzid.empty())
            return "<success xmlns='" + std::string(ns::SASL) + "'/>";
        return "<success xmlns='" + std::string(ns::SASL) + "'>" +
               base64_encode(authzid) + "</success>";
    }
};

// --- SASL ANONYMOUS (RFC 4505) ---
class SaslAnonymous {
public:
    static std::string parse_trace(const std::string& b64_data) {
        if (b64_data.empty() || b64_data == "=") return "";
        return base64_decode(b64_data);
    }

    static std::string challenge() {
        return "<challenge xmlns='" + std::string(ns::SASL) + "'/>";
    }

    static std::string success() {
        return "<success xmlns='" + std::string(ns::SASL) + "'/>";
    }
};

// =============================================================================
// STARTTLS handler
// =============================================================================
class StartTlsHandler {
public:
    StartTlsHandler(TlsContext& ctx) : tls_ctx_(ctx) {}

    bool is_tls_available() const { return tls_available_; }
    void set_tls_available(bool v) { tls_available_ = v; }

    // Build the STARTTLS feature XML
    std::string get_feature_xml() const {
        if (!tls_available_) return "";
        return "<starttls xmlns='" + std::string(ns::TLS) + "'>"
               "<required/></starttls>";
    }

    std::string get_feature_xml_optional() const {
        if (!tls_available_) return "";
        return "<starttls xmlns='" + std::string(ns::TLS) + "'/>";
    }

    // Client sends: <starttls xmlns='...'/>
    // Server responds: <proceed xmlns='...'/>
    std::string on_starttls_request() {
        return "<proceed xmlns='" + std::string(ns::TLS) + "'/>";
    }

    // TLS failure
    std::string on_tls_failure() {
        return "<failure xmlns='" + std::string(ns::TLS) + "'/>";
    }

    // Start TLS handshake on session
    bool initiate_handshake(StreamSession& session) {
        session.tls_handshake = std::make_unique<TlsHandshake>(tls_ctx_);
        if (!session.tls_handshake->init(session.fd))
            return false;
        session.state = StreamState::TLS_NEGOTIATING;
        session.tls_requested = true;
        return true;
    }

    // Non-blocking handshake step; returns:
    //   1 = complete, 0 = in progress, -1 = error
    int handshake_step(StreamSession& session) {
        if (!session.tls_handshake) return -1;
        return session.tls_handshake->do_handshake();
    }

    void complete_handshake(StreamSession& session) {
        if (session.tls_handshake) {
            session.tls_cipher = session.tls_handshake->get_cipher();
            session.tls_protocol = session.tls_handshake->get_protocol_version();
        }
        session.tls_enabled = true;
        session.state = StreamState::TLS_ESTABLISHED;
        session.invalidate_features_cache();
    }

    std::string get_peer_cert_subject(StreamSession& session) {
        if (!session.tls_handshake) return "";
        return session.tls_handshake->get_peer_cert_subject();
    }

    std::string get_peer_cert_fingerprint(StreamSession& session,
                                           const std::string& algo = "sha256") {
        if (!session.tls_handshake) return "";
        return session.tls_handshake->get_peer_cert_fingerprint(algo);
    }

    TlsContext& context() { return tls_ctx_; }

private:
    TlsContext& tls_ctx_;
    bool tls_available_ = true;
};

// =============================================================================
// Resource binding (RFC 6120 §7)
// =============================================================================
class ResourceBinder {
public:
    static std::string get_feature_xml() {
        return "<bind xmlns='" + std::string(ns::BIND) + "'/>";
    }

    // Server generates a resource if client requests auto
    static std::string generate_resource(const std::string& prefix = "progressive") {
        static std::atomic<int64_t> counter{1};
        std::ostringstream oss;
        oss << prefix << "-" << std::hex
            << (now_ms() & 0xFFFFF) << "-"
            << counter.fetch_add(1, std::memory_order_relaxed);
        return oss.str();
    }

    // Build bind result
    static std::string bind_result(const std::string& id,
                                    const std::string& jid_full) {
        XMLElement iq("iq");
        iq.attr("type", "result");
        iq.attr("id", id);
        XMLElement bind("bind");
        bind.xmlns(ns::BIND);
        bind.child(XMLElement("jid", jid_full));
        iq.child(bind);
        return iq.to_string();
    }

    static std::string bind_error(const std::string& id,
                                   const std::string& error_type,
                                   const std::string& condition) {
        XMLElement iq("iq");
        iq.attr("type", "error");
        iq.attr("id", id);
        XMLElement error("error");
        error.attr("type", error_type);
        error.child(XMLElement(condition).xmlns(ns::STREAM_ERR));
        iq.child(error);
        return iq.to_string();
    }
};

// =============================================================================
// Session establishment (RFC 6120 §7, XEP-0199 §3.2)
// =============================================================================
class SessionEstablisher {
public:
    static std::string get_feature_xml() {
        return "<session xmlns='" + std::string(ns::SESSION) + "'/>";
    }

    static std::string session_result(const std::string& id) {
        XMLElement iq("iq");
        iq.attr("type", "result");
        iq.attr("id", id);
        XMLElement sess("session");
        sess.xmlns(ns::SESSION);
        iq.child(sess);
        return iq.to_string();
    }

    static std::string session_error(const std::string& id,
                                      const std::string& condition) {
        XMLElement iq("iq");
        iq.attr("type", "error");
        iq.attr("id", id);
        XMLElement error("error");
        error.attr("type", "cancel");
        error.child(XMLElement(condition).xmlns(ns::STREAM_ERR));
        iq.child(error);
        return iq.to_string();
    }
};

// =============================================================================
// Stream compression handler (XEP-0138)
// =============================================================================
class CompressionHandler {
public:
    static std::string get_feature_xml() {
        XMLElement comp("compression");
        comp.xmlns(ns::COMPRESS);
        comp.child(XMLElement("method", "zlib"));
        return comp.to_string();
    }

    // Client: <compress xmlns='http://jabber.org/protocol/compress'>
    //            <method>zlib</method>
    //         </compress>
    // Server: <compressed xmlns='http://jabber.org/protocol/compress'/>
    static std::string on_compress_request(const std::string& method) {
        if (method == "zlib")
            return "<compressed xmlns='" + std::string(ns::COMPRESS_METHOD) + "'/>";
        XMLElement f("failure");
        f.xmlns(ns::COMPRESS_METHOD);
        f.child(XMLElement("unsupported-method"));
        return f.to_string();
    }

    static std::string on_compress_failure(const std::string& reason) {
        XMLElement f("failure");
        f.xmlns(ns::COMPRESS_METHOD);
        f.child(XMLElement(reason));
        return f.to_string();
    }

    bool activate_compression(StreamSession& session) {
        session.compression = std::make_unique<StreamCompression>();
        if (!session.compression->init_zlib_compress()) return false;
        if (!session.compression->init_zlib_decompress()) return false;
        session.compression_offered = false;
        session.invalidate_features_cache();
        return true;
    }
};

// =============================================================================
// Stream management (XEP-0198)
// =============================================================================
class StreamManager {
public:
    static std::string get_feature_xml() {
        return "<sm xmlns='" + std::string(ns::STREAM_MGMT) + "'/>";
    }

    // Enable SM
    std::string handle_enable(StreamSession& session,
                               bool resume = true,
                               int max_resume_sec = 300) {
        session.sm.enabled = true;
        session.sm.inbound_count = 0;
        session.sm.outbound_count = 0;
        session.sm.last_ack_from_client = 0;
        session.sm.last_ack_to_client = 0;
        session.sm.unacked_stanzas.clear();
        session.sm.resume_timeout_sec = max_resume_sec;

        if (resume) {
            session.sm.sm_id = gen_stream_id();
            session.sm.session_start_time = now_sec();
            store_resume_state(session);
        }

        std::string result = "<enabled xmlns='" + std::string(ns::STREAM_MGMT) + "'";
        if (resume && !session.sm.sm_id.empty()) {
            result += " id='" + session.sm.sm_id + "'";
            result += " resume='true'";
            result += " max='" + std::to_string(max_resume_sec) + "'";
        }
        result += "/>";
        session.invalidate_features_cache();
        return result;
    }

    // Request client ack
    std::string request_ack(StreamSession& session) {
        std::ostringstream oss;
        oss << "<r xmlns='" << ns::STREAM_MGMT << "'/>";
        return oss.str();
    }

    // Send ack to client
    std::string send_ack(StreamSession& session) {
        uint32_t h = session.sm.inbound_count;
        std::ostringstream oss;
        oss << "<a xmlns='" << ns::STREAM_MGMT << "' h='" << h << "'/>";
        return oss.str();
    }

    // Handle client ack
    void handle_client_ack(StreamSession& session, uint32_t h) {
        uint32_t old = session.sm.last_ack_from_client;
        session.sm.last_ack_from_client = h;

        // Remove acked stanzas from unacked queue
        uint32_t to_remove = h - old;
        while (to_remove > 0 && !session.sm.unacked_stanzas.empty()) {
            session.sm.unacked_stanzas.pop_front();
            to_remove--;
        }
        session.sm.last_ack_time = now_sec();
    }

    // Count an inbound stanza
    void count_inbound(StreamSession& session) {
        if (!session.sm.enabled) return;
        session.sm.inbound_count++;
    }

    // Count an outbound stanza (and queue for possible resend)
    void count_outbound(StreamSession& session, const std::string& stanza_xml) {
        if (!session.sm.enabled) return;
        session.sm.outbound_count++;
        session.sm.unacked_stanzas.push_back(stanza_xml);
        while (session.sm.unacked_stanzas.size() > session.sm.max_unacked) {
            session.sm.unacked_stanzas.pop_front();
        }
    }

    // Handle resume
    std::string handle_resume(StreamSession& session,
                               const std::string& prev_id, uint32_t h) {
        auto* saved = find_resume_state(prev_id);
        if (!saved) {
            // Resume failed
            std::ostringstream oss;
            oss << "<failed xmlns='" << ns::STREAM_MGMT << "'";
            oss << " h='" << session.sm.inbound_count << "'/>";
            session.invalidate_features_cache();
            return oss.str();
        }

        // Restore session state
        session.sm.enabled = true;
        session.sm.resumed = true;
        session.sm.sm_id = prev_id;
        session.sm.prev_sm_id = saved->sm_id;
        session.sm.inbound_count = saved->inbound_count;
        session.sm.last_ack_from_client = h;

        // Resend unacked stanzas from h
        std::ostringstream oss;
        oss << "<resumed xmlns='" << ns::STREAM_MGMT << "'";
        oss << " h='" << saved->outbound_count << "'";
        oss << " previd='" << prev_id << "'/>";

        // Resend unacked stanzas from the saved session
        for (auto& stanza : saved->unacked_stanzas) {
            session.send_queue.push_back(stanza);
        }

        // Clean up saved state
        remove_resume_state(prev_id);

        session.invalidate_features_cache();
        return oss.str();
    }

    // Store resume state for later recovery
    void store_resume_state(const StreamSession& session) {
        std::lock_guard<std::mutex> lock(resume_mutex_);
        resume_states_[session.sm.sm_id] = session.sm;
        resume_states_[session.sm.sm_id].resume_jid = session.user_jid.full();
        resume_states_[session.sm.sm_id].resume_stream_id = session.stream_id;
    }

    StreamManagementState* find_resume_state(const std::string& sm_id) {
        std::lock_guard<std::mutex> lock(resume_mutex_);
        auto it = resume_states_.find(sm_id);
        if (it == resume_states_.end()) return nullptr;
        // Check timeout
        if (now_sec() - it->second.last_ack_time > it->second.resume_timeout_sec) {
            resume_states_.erase(it);
            return nullptr;
        }
        return &it->second;
    }

    void remove_resume_state(const std::string& sm_id) {
        std::lock_guard<std::mutex> lock(resume_mutex_);
        resume_states_.erase(sm_id);
    }

    void cleanup_expired_resume_states() {
        std::lock_guard<std::mutex> lock(resume_mutex_);
        auto now = now_sec();
        for (auto it = resume_states_.begin(); it != resume_states_.end();) {
            if (now - it->second.last_ack_time > it->second.resume_timeout_sec) {
                it = resume_states_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    std::mutex resume_mutex_;
    std::unordered_map<std::string, StreamManagementState> resume_states_;
};

// =============================================================================
// Stream features builder - constructs stream:features XML per session state
// =============================================================================
class StreamFeaturesBuilder {
public:
    StreamFeaturesBuilder() = default;

    void set_server_domain(const std::string& domain) {
        server_domain_ = domain;
    }

    void set_tls_available(bool v) { tls_available_ = v; }
    void set_tls_required(bool v) { tls_required_ = v; }
    void set_compression_available(bool v) { compression_available_ = v; }
    void set_sm_enabled(bool v) { sm_enabled_ = v; }
    void set_carbons_enabled(bool v) { carbons_enabled_ = v; }
    void set_csi_enabled(bool v) { csi_enabled_ = v; }

    void add_sasl_mechanism(const std::string& mech) {
        sasl_mechanisms_.push_back(mech);
    }

    std::string build_features(const StreamSession& session) {
        // If cached and state hasn't changed, return cache
        if (!session.features_need_refresh &&
            session.state == session.cached_features_state &&
            !session.cached_features.empty())
            return session.cached_features;

        XMLElement features("stream:features");

        // --- Pre-authentication features ---
        if (!session.sasl_authenticated) {
            // STARTTLS
            if (tls_available_ && !session.tls_enabled && !session.tls_requested) {
                XMLElement starttls("starttls");
                starttls.xmlns(ns::TLS);
                if (tls_required_) {
                    starttls.child(XMLElement("required"));
                }
                features.child(starttls);
            }

            // SASL mechanisms
            if (session.tls_enabled || !tls_required_) {
                if (!sasl_mechanisms_.empty()) {
                    XMLElement mechs("mechanisms");
                    mechs.xmlns(ns::SASL);
                    for (auto& m : sasl_mechanisms_) {
                        mechs.child(XMLElement("mechanism", m));
                    }
                    features.child(mechs);
                }
            }
        }

        // --- Post-authentication features ---
        if (session.sasl_authenticated && !session.resource_bound) {
            features.child(ResourceBinder::get_feature_xml());
        }

        if (session.sasl_authenticated && !session.session_established) {
            features.child(SessionEstablisher::get_feature_xml());
        }

        // --- Post-session features ---
        if (session.sasl_authenticated && session.resource_bound &&
            session.session_established) {

            // Stream compression (offer after auth but before traffic)
            if (compression_available_ && !session.compression &&
                !session.compression_offered) {
                features.child(CompressionHandler::get_feature_xml());
            }

            // Stream management (XEP-0198)
            if (sm_enabled_ && !session.sm.enabled) {
                features.child(StreamManager::get_feature_xml());
            }

            // Message carbons (XEP-0280)
            if (carbons_enabled_) {
                features.child(XMLElement("carbons").xmlns(ns::CARBONS));
            }

            // Client State Indication (XEP-0352)
            if (csi_enabled_) {
                features.child(XMLElement("csi").xmlns(ns::CSI));
            }
        }

        // Update cache on the session
        std::string xml = features.to_string();
        const_cast<StreamSession&>(session).cached_features = xml;
        const_cast<StreamSession&>(session).cached_features_state = session.state;
        const_cast<StreamSession&>(session).features_generated_at = now_ms();
        const_cast<StreamSession&>(session).features_need_refresh = false;

        return xml;
    }

    void invalidate_cache(StreamSession& session) {
        session.invalidate_features_cache();
    }

private:
    std::string server_domain_;
    bool tls_available_ = true;
    bool tls_required_ = false;
    bool compression_available_ = false;
    bool sm_enabled_ = true;
    bool carbons_enabled_ = true;
    bool csi_enabled_ = true;
    std::vector<std::string> sasl_mechanisms_ = {
        "SCRAM-SHA-512", "SCRAM-SHA-256", "SCRAM-SHA-1",
        "PLAIN", "EXTERNAL", "ANONYMOUS"
    };
};

// =============================================================================
// BOSH (XEP-0206) stream feature support
// =============================================================================
class BoshStreamFeatures {
public:
    struct BoshSession {
        std::string sid;
        std::string jid;          // full JID of connected user
        int wait = 60;
        int hold = 1;
        int polling = 5;
        int inactivity = 30;
        int max_pause = 300;
        int requests = 2;
        std::string to;           // target domain
        std::string from;         // client from
        std::string route;
        std::string stream_id;
        std::string authid;
        std::string version = "1.0";
        std::string content = "text/xml; charset=utf-8";
        std::string accept;
        std::string charsets;
        std::string ack;
        int64_t created_at = 0;
        int64_t last_activity = 0;
        bool restart = false;
        bool pause = false;
        bool terminated = false;
        bool secure = false;
        std::deque<std::string> pending_packets;
    };

    // Create new BOSH session
    static BoshSession create_session(const std::string& sid,
                                       int wait, int hold,
                                       const std::string& to) {
        BoshSession s;
        s.sid = sid;
        s.wait = wait;
        s.hold = hold;
        s.to = to;
        s.created_at = now_ms();
        s.last_activity = now_ms();
        s.stream_id = gen_stream_id();
        return s;
    }

    // Build BOSH stream:features response
    static std::string get_features_xml(const BoshSession& session) {
        std::ostringstream oss;
        oss << "<body xmlns='" << ns::HTTP_BIND << "'"
            << " sid='" << session.sid << "'"
            << " wait='" << session.wait << "'"
            << " hold='" << session.hold << "'"
            << " polling='" << session.polling << "'"
            << " inactivity='" << session.inactivity << "'"
            << " maxpause='" << session.max_pause << "'"
            << " requests='" << session.requests << "'"
            << " authid='" << session.stream_id << "'"
            << " secure='true'"
            << " xmlns:stream='" << ns::STREAMS << "'";

        if (!session.version.empty())
            oss << " ver='" << session.version << "'";
        if (!session.from.empty())
            oss << " from='" << xml_escape(session.from) << "'";

        oss << ">";

        // Include stream:features
        oss << "<stream:features>";

        // SASL
        oss << "<mechanisms xmlns='" << ns::SASL << "'>"
            << "<mechanism>PLAIN</mechanism>"
            << "<mechanism>SCRAM-SHA-1</mechanism>"
            << "<mechanism>SCRAM-SHA-256</mechanism>"
            << "<mechanism>SCRAM-SHA-512</mechanism>"
            << "</mechanisms>";

        // Bind + Session
        oss << "<bind xmlns='" << ns::BIND << "'/>";
        oss << "<session xmlns='" << ns::SESSION << "'/>";

        // Stream management via BOSH
        oss << "<sm xmlns='" << ns::STREAM_MGMT << "'/>";

        oss << "</stream:features>";

        oss << "</body>";
        return oss.str();
    }

    // BOSH terminate response
    static std::string terminate_response(const std::string& sid,
                                           const std::string& condition = "") {
        std::ostringstream oss;
        oss << "<body xmlns='" << ns::HTTP_BIND << "'"
            << " type='terminate'"
            << " sid='" << sid << "'";
        if (!condition.empty())
            oss << " condition='" << condition << "'";
        oss << "/>";
        return oss.str();
    }
};

// =============================================================================
// WebSocket (RFC 7395) stream feature support
// =============================================================================
class WebSocketStreamFeatures {
public:
    struct WsSession {
        std::string stream_id;
        std::string domain;
        bool stream_open = false;
        bool authenticated = false;
        bool resource_bound = false;
        Jid user_jid;
        std::deque<std::string> send_queue;
        int64_t connected_at = 0;
    };

    // RFC 7395: After WebSocket upgrade, client sends stream open
    // Server responds with stream open and features
    static std::string stream_open_response(const std::string& stream_id,
                                             const std::string& domain,
                                             const std::string& from) {
        std::ostringstream oss;
        oss << "<open xmlns='" << ns::STREAMS << "'"
            << " from='" << xml_escape(domain) << "'"
            << " id='" << stream_id << "'"
            << " version='1.0'"
            << " xml:lang='en'"
            << " xmlns:xmpp='" << ns::STREAMS << "'";
        if (!from.empty())
            oss << " to='" << xml_escape(from) << "'";
        oss << "/>";
        return oss.str();
    }

    // Build WebSocket stream:features
    static std::string get_features_xml() {
        XMLElement features("stream:features");
        features.attr("xmlns:stream", ns::STREAMS);

        // SASL mechanisms
        XMLElement mechs("mechanisms");
        mechs.xmlns(ns::SASL);
        mechs.child(XMLElement("mechanism", "SCRAM-SHA-512"));
        mechs.child(XMLElement("mechanism", "SCRAM-SHA-256"));
        mechs.child(XMLElement("mechanism", "SCRAM-SHA-1"));
        mechs.child(XMLElement("mechanism", "PLAIN"));
        mechs.child(XMLElement("mechanism", "EXTERNAL"));
        mechs.child(XMLElement("mechanism", "ANONYMOUS"));
        features.child(mechs);

        // Bind
        features.child(XMLElement("bind").xmlns(ns::BIND));
        features.child(XMLElement("session").xmlns(ns::SESSION));

        // Stream management
        features.child(XMLElement("sm").xmlns(ns::STREAM_MGMT));

        // Carbons + CSI
        features.child(XMLElement("carbons").xmlns(ns::CARBONS));
        features.child(XMLElement("csi").xmlns(ns::CSI));

        return features.to_string();
    }

    // WebSocket close frame
    static std::string close_frame() {
        return "<close xmlns='" + std::string(ns::STREAMS) + "'/>";
    }
};

// =============================================================================
// Stream XML builder - constructs the stream open/close/error XML
// =============================================================================
class StreamXmlBuilder {
public:
    static std::string stream_open(const std::string& from,
                                    const std::string& to,
                                    const std::string& id,
                                    const std::string& stream_ns = ns::CLIENT,
                                    const std::string& lang = "en",
                                    const std::string& version = "1.0") {
        std::ostringstream oss;
        oss << "<?xml version='1.0' encoding='UTF-8'?>";
        oss << "<stream:stream"
            << " xmlns='" << stream_ns << "'"
            << " xmlns:stream='" << ns::STREAMS << "'"
            << " version='" << version << "'"
            << " from='" << xml_escape(from) << "'"
            << " id='" << id << "'"
            << " xml:lang='" << lang << "'";
        if (!to.empty())
            oss << " to='" << xml_escape(to) << "'";
        oss << ">";
        return oss.str();
    }

    static std::string stream_close() {
        return "</stream:stream>";
    }

    // Stream restart (after TLS or compression)
    static std::string stream_restart(const std::string& from,
                                       const std::string& to,
                                       const std::string& id,
                                       const std::string& stream_ns = ns::CLIENT) {
        return stream_open(from, to, id, stream_ns);
    }

    // Stream error with closing tag
    static std::string stream_error(const StreamError& error) {
        return error.to_xml() + "</stream:stream>";
    }

    // Convenience: simple stream error
    static std::string stream_error(const std::string& condition,
                                     const std::string& text = "") {
        StreamError e;
        e.condition = condition;
        e.type = StreamErrorType::UNDEFINED_CONDITION;
        e.text = text;
        return stream_error(e);
    }

    // SASL success
    static std::string sasl_success(const std::string& extra_data = "") {
        if (extra_data.empty())
            return "<success xmlns='" + std::string(ns::SASL) + "'/>";
        return "<success xmlns='" + std::string(ns::SASL) + "'>" +
               extra_data + "</success>";
    }

    // SASL failure
    static std::string sasl_failure(const std::string& condition,
                                     const std::string& text = "") {
        XMLElement f("failure");
        f.xmlns(ns::SASL);
        f.child(XMLElement(condition));
        if (!text.empty())
            f.child(XMLElement("text", text));
        return f.to_string();
    }

    // SASL challenge
    static std::string sasl_challenge(const std::string& b64_data) {
        return "<challenge xmlns='" + std::string(ns::SASL) + "'>" +
               b64_data + "</challenge>";
    }

    // IQ result (generic)
    static std::string iq_result(const std::string& id,
                                  const std::string& child_xml = "") {
        if (child_xml.empty())
            return "<iq type='result' id='" + xml_escape(id) + "'/>";
        return "<iq type='result' id='" + xml_escape(id) + "'>" +
               child_xml + "</iq>";
    }

    // IQ error
    static std::string iq_error(const std::string& id,
                                 const std::string& type,
                                 const std::string& condition,
                                 const std::string& text = "") {
        std::ostringstream oss;
        oss << "<iq type='error' id='" << xml_escape(id) << "'>"
            << "<error type='" << type << "'>"
            << "<" << condition << " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>";
        if (!text.empty())
            oss << "<text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>"
                << xml_escape(text) << "</text>";
        oss << "</error></iq>";
        return oss.str();
    }
};

// =============================================================================
// Stream parser - extracts XML elements from stream buffer
// =============================================================================
class StreamParser {
public:
    struct StreamOpenInfo {
        std::string from;
        std::string to;
        std::string id;
        std::string version;
        std::string xmlns;
        std::string xml_lang;
        bool valid = false;
    };

    // Parse stream open from buffer
    static StreamOpenInfo parse_stream_open(const std::string& buffer) {
        StreamOpenInfo info;
        std::string open_tag;
        size_t start = buffer.find("<stream:stream");
        if (start == std::string::npos) {
            start = buffer.find("<stream ");
            if (start == std::string::npos) return info;
        }

        size_t end = buffer.find('>', start);
        if (end == std::string::npos) return info;

        open_tag = buffer.substr(start, end - start + 1);
        info.valid = true;

        // Extract attributes
        info.from = extract_attr(open_tag, "from");
        info.to = extract_attr(open_tag, "to");
        info.id = extract_attr(open_tag, "id");
        info.version = extract_attr(open_tag, "version");
        info.xmlns = extract_attr(open_tag, "xmlns");
        info.xml_lang = extract_attr(open_tag, "xml:lang");

        return info;
    }

    // Extract a specific XML element from buffer (non-stream)
    static std::string extract_element(const std::string& buffer,
                                        const std::string& element_name,
                                        const std::string& xmlns = "") {
        std::string open = "<" + element_name;
        size_t start = buffer.find(open);
        if (start == std::string::npos) return "";

        // Find matching close
        int depth = 0;
        bool in_tag = false;
        bool self_close = false;
        std::string tag_name;

        for (size_t i = start; i < buffer.size(); i++) {
            char c = buffer[i];
            if (c == '<') {
                in_tag = true;
                self_close = false;
                tag_name.clear();
                continue;
            }
            if (c == '>' && in_tag) {
                in_tag = false;
                if (self_close) continue;
                if (!tag_name.empty() && tag_name[0] == '/') {
                    depth--;
                } else {
                    depth++;
                }
                if (depth == 0) {
                    return buffer.substr(start, i - start + 1);
                }
                continue;
            }
            if (c == '/' && in_tag && tag_name.empty()) {
                self_close = true;
                continue;
            }
            if (in_tag && c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                tag_name += c;
            }
        }
        return "";
    }

    // Extract base64 content of an element
    static std::string extract_text_content(const std::string& buffer,
                                              const std::string& element_name) {
        std::string open = "<" + element_name;
        std::string close = "</" + element_name + ">";

        size_t start = buffer.find(open);
        if (start == std::string::npos) return "";

        // Find end of opening tag
        size_t tag_end = buffer.find('>', start);
        if (tag_end == std::string::npos) return "";

        // Check if self-closing
        if (buffer[tag_end - 1] == '/') return "";

        size_t content_start = tag_end + 1;
        size_t close_pos = buffer.find(close, content_start);
        if (close_pos == std::string::npos) return "";

        return buffer.substr(content_start, close_pos - content_start);
    }

    // Find attribute value in an element
    static std::string extract_attr(const std::string& xml,
                                     const std::string& attr_name) {
        std::string pat = attr_name + "='";
        size_t pos = xml.find(pat);
        if (pos == std::string::npos) {
            pat = attr_name + "=\"";
            pos = xml.find(pat);
            if (pos == std::string::npos) return "";
        }

        pos += pat.size();
        size_t end = xml.find(pat[pat.size() - 1], pos);
        if (end == std::string::npos) return "";
        return xml.substr(pos, end - pos);
    }

    // Parse SCRAM client-first-message fields
    static std::map<std::string, std::string> parse_scram_message(
        const std::string& msg) {
        std::map<std::string, std::string> fields;
        size_t pos = 0;
        while (pos < msg.size()) {
            // key=value
            size_t eq = msg.find('=', pos);
            if (eq == std::string::npos || eq == pos) break;
            std::string key = msg.substr(pos, eq - pos);
            pos = eq + 1;
            size_t comma = msg.find(',', pos);
            std::string value;
            if (comma == std::string::npos) {
                value = msg.substr(pos);
                fields[key] = value;
                break;
            } else {
                value = msg.substr(pos, comma - pos);
                fields[key] = value;
                pos = comma + 1;
            }
        }
        return fields;
    }
};

// =============================================================================
// Stream ID generator and tracker
// =============================================================================
class StreamIdTracker {
public:
    std::string generate() {
        std::string id;
        do {
            id = gen_stream_id();
        } while (!register_id(id));
        return id;
    }

    bool register_id(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (active_ids_.count(id)) return false;
        active_ids_.insert(id);
        return true;
    }

    void release_id(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex_);
        active_ids_.erase(id);
    }

    bool is_active(const std::string& id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return active_ids_.count(id) > 0;
    }

    size_t active_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return active_ids_.size();
    }

private:
    mutable std::mutex mutex_;
    std::unordered_set<std::string> active_ids_;
};

// =============================================================================
// Stream close handler - clean shutdown logic
// =============================================================================
class StreamCloseHandler {
public:
    enum class CloseMode {
        NORMAL,          // </stream:stream> from client
        ERROR,           // stream error sent
        TIMEOUT,         // connection timeout
        HOST_UNKNOWN,    // host unknown
        SEE_OTHER,       // redirect
        SYSTEM_SHUTDOWN,  // server shutting down
    };

    static std::string build_close_response(CloseMode mode,
                                             const std::string& text = "") {
        switch (mode) {
            case CloseMode::NORMAL:
                return "</stream:stream>";
            case CloseMode::ERROR:
                return StreamXmlBuilder::stream_error("undefined-condition", text);
            case CloseMode::TIMEOUT:
                return StreamXmlBuilder::stream_error("connection-timeout", text);
            case CloseMode::HOST_UNKNOWN:
                return StreamXmlBuilder::stream_error("host-unknown", text);
            case CloseMode::SEE_OTHER:
                return StreamXmlBuilder::stream_error("see-other-host", text);
            case CloseMode::SYSTEM_SHUTDOWN:
                return StreamXmlBuilder::stream_error("system-shutdown", text);
        }
        return "</stream:stream>";
    }

    static void perform_cleanup(StreamSession& session, StreamIdTracker& id_tracker) {
        session.state = StreamState::CLOSING;

        // Release stream ID
        if (!session.stream_id.empty()) {
            id_tracker.release_id(session.stream_id);
        }

        // Release SM resume state
        if (session.sm.enabled && !session.sm.sm_id.empty()) {
            // Keep for resume timeout
            session.sm.last_ack_time = now_sec();
        }

        // Close TLS
        if (session.tls_handshake) {
            session.tls_handshake->shutdown();
            session.tls_handshake.reset();
        }

        // Reset compression
        if (session.compression) {
            session.compression->reset();
            session.compression.reset();
        }

        session.state = StreamState::CLOSED;
    }
};

// =============================================================================
// Stream restart logic
// =============================================================================
class StreamRestartHandler {
public:
    // After TLS negotiation, the stream must be restarted
    static void restart_after_tls(StreamSession& session,
                                   StreamIdTracker& id_tracker) {
        // Release old stream ID
        if (!session.stream_id.empty()) {
            id_tracker.release_id(session.stream_id);
        }

        // Generate new stream ID
        session.stream_id = id_tracker.generate();

        // Reset stream-level state
        session.sasl_authenticated = false;
        session.sasl_mechanism.clear();
        session.sasl_round = 0;
        session.resource_bound = false;
        session.session_established = false;
        session.xml_buffer.clear();
        session.state = StreamState::TLS_ESTABLISHED;
        session.invalidate_features_cache();
    }

    // After SASL authentication, the stream is NOT restarted
    // But we must invalidate the features cache to advertise post-auth features
    static void after_sasl_auth(StreamSession& session) {
        session.state = StreamState::SASL_AUTHENTICATED;
        session.sasl_round = 0;
        session.invalidate_features_cache();
    }

    // After compression, the stream is restarted
    static void restart_after_compression(StreamSession& session,
                                           StreamIdTracker& id_tracker) {
        if (!session.stream_id.empty()) {
            id_tracker.release_id(session.stream_id);
        }
        session.stream_id = id_tracker.generate();
        session.sasl_authenticated = false;
        session.sasl_mechanism.clear();
        session.resource_bound = false;
        session.session_established = false;
        session.xml_buffer.clear();
        session.state = StreamState::INIT;
        session.invalidate_features_cache();
    }

    // After resource binding + session, stream goes to ready
    static void after_bind_and_session(StreamSession& session) {
        session.state = StreamState::READY;
        session.invalidate_features_cache();
    }
};

// =============================================================================
// Main Stream Features Engine - combines all subsystems
// =============================================================================
class StreamFeaturesEngine {
public:
    StreamFeaturesEngine(const std::string& domain)
        : server_domain_(domain) {
        features_builder_.set_server_domain(domain);
        features_builder_.set_tls_available(true);
        features_builder_.set_compression_available(false);
        features_builder_.set_sm_enabled(true);
        features_builder_.set_carbons_enabled(true);
        features_builder_.set_csi_enabled(true);
    }

    // --- Configuration ---
    void set_tls_context(std::shared_ptr<TlsContext> ctx) {
        tls_ctx_ = ctx;
        starttls_handler_ = std::make_unique<StartTlsHandler>(*ctx);
    }

    void set_tls_required(bool v) {
        features_builder_.set_tls_required(v);
    }

    void set_compression_enabled(bool v) {
        features_builder_.set_compression_available(v);
    }

    void set_sasl_mechanisms(const std::vector<std::string>& mechs) {
        sasl_mechanisms_ = mechs;
    }

    void enable_sm(bool v) {
        features_builder_.set_sm_enabled(v);
    }

    void enable_carbons(bool v) {
        features_builder_.set_carbons_enabled(v);
    }

    void enable_csi(bool v) {
        features_builder_.set_csi_enabled(v);
    }

    // --- Session creation ---
    std::shared_ptr<StreamSession> create_session(int fd,
                                                   const std::string& ip,
                                                   int port) {
        auto session = std::make_shared<StreamSession>();
        session->fd = fd;
        session->ip_address = ip;
        session->port = port;
        session->stream_id = id_tracker_.generate();
        session->stream_namespace = ns::CLIENT;
        session->stream_from = server_domain_;
        session->connected_at = now_ms();
        session->last_activity = now_ms();
        session->state = StreamState::INIT;
        return session;
    }

    // --- Stream open ---
    std::string on_stream_open(std::shared_ptr<StreamSession> session,
                                const std::string& client_xml) {
        auto info = StreamParser::parse_stream_open(client_xml);
        if (!info.valid) {
            return StreamXmlBuilder::stream_error("bad-format");
        }

        session->stream_to = info.from;
        if (!info.version.empty()) session->stream_version = info.version;
        if (!info.xml_lang.empty()) session->xml_lang = info.xml_lang;
        if (!info.xmlns.empty()) session->stream_namespace = info.xmlns;

        session->state = StreamState::STREAM_OPEN_RECEIVED;
        session->stream_opened_at = now_ms();
        session->invalidate_features_cache();

        // Build stream open response
        std::string response = StreamXmlBuilder::stream_open(
            server_domain_,
            session->stream_to,
            session->stream_id,
            session->stream_namespace,
            session->xml_lang,
            "1.0");

        // Append stream features
        response += features_builder_.build_features(*session);

        session->state = StreamState::FEATURES_SENT;

        return response;
    }

    // --- STARTTLS handling ---
    std::string on_starttls(std::shared_ptr<StreamSession> session) {
        if (!starttls_handler_ || !starttls_handler_->is_tls_available()) {
            return StreamXmlBuilder::stream_error("unsupported-feature",
                                                   "TLS not available");
        }

        if (session->tls_enabled) {
            return StreamXmlBuilder::stream_error("policy-violation",
                                                   "TLS already active");
        }

        // Send proceed
        std::string response = starttls_handler_->on_starttls_request();
        session->state = StreamState::STARTTLS_REQUESTED;
        session->invalidate_features_cache();
        return response;
    }

    // Initiate TLS handshake after sending <proceed/>
    bool start_tls_handshake(std::shared_ptr<StreamSession> session) {
        if (!starttls_handler_) return false;
        return starttls_handler_->initiate_handshake(*session);
    }

    // Non-blocking TLS handshake step
    // Returns: 1 = complete, 0 = in progress, -1 = error
    int tls_handshake_step(std::shared_ptr<StreamSession> session) {
        if (!starttls_handler_) return -1;
        int ret = starttls_handler_->handshake_step(*session);
        if (ret == 1) {
            starttls_handler_->complete_handshake(*session);
        }
        return ret;
    }

    // Stream restart after TLS (send new stream header)
    std::string on_tls_restart(std::shared_ptr<StreamSession> session) {
        StreamRestartHandler::restart_after_tls(*session, id_tracker_);

        std::string response = StreamXmlBuilder::stream_restart(
            server_domain_,
            session->stream_to,
            session->stream_id,
            session->stream_namespace);

        response += features_builder_.build_features(*session);
        session->state = StreamState::FEATURES_SENT;
        return response;
    }

    // --- SASL handling ---
    std::string on_sasl_auth(std::shared_ptr<StreamSession> session,
                              const std::string& mechanism,
                              const std::string& b64_data) {
        session->sasl_mechanism = mechanism;
        session->state = StreamState::SASL_NEGOTIATING;
        session->sasl_round = 1;

        if (mechanism == "PLAIN") {
            return handle_sasl_plain(session, b64_data);
        } else if (mechanism == "EXTERNAL") {
            return handle_sasl_external(session, b64_data);
        } else if (mechanism == "ANONYMOUS") {
            return handle_sasl_anonymous(session, b64_data);
        } else if (mechanism == "SCRAM-SHA-1" ||
                   mechanism == "SCRAM-SHA-256" ||
                   mechanism == "SCRAM-SHA-512") {
            return handle_sasl_scram_first(session, mechanism, b64_data);
        }

        return SaslError::invalid_mechanism().to_xml();
    }

    std::string on_sasl_response(std::shared_ptr<StreamSession> session,
                                  const std::string& b64_data) {
        if (session->sasl_mechanism.find("SCRAM-SHA-") == 0) {
            return handle_sasl_scram_final(session, b64_data);
        }

        return SaslError::not_authorized().to_xml();
    }

    // --- Stream restart after SASL ---
    std::string on_sasl_success_restart(std::shared_ptr<StreamSession> session) {
        StreamRestartHandler::after_sasl_auth(*session);

        // Send stream features for post-auth
        std::string features = features_builder_.build_features(*session);
        return features;
    }

    // --- Resource binding ---
    std::string on_bind(std::shared_ptr<StreamSession> session,
                         const std::string& iq_id,
                         const std::string& requested_resource) {
        if (!session->sasl_authenticated) {
            return ResourceBinder::bind_error(iq_id, "auth", "not-authorized");
        }

        std::string resource = requested_resource.empty()
            ? ResourceBinder::generate_resource()
            : requested_resource;

        session->bound_resource = resource;
        session->user_jid.resource = resource;
        session->bound_jid_full = session->user_jid.full();
        session->resource_bound = true;
        session->state = StreamState::SESSION_ESTABLISHING;
        session->invalidate_features_cache();

        return ResourceBinder::bind_result(iq_id, session->bound_jid_full);
    }

    // --- Session establishment ---
    std::string on_session(std::shared_ptr<StreamSession> session,
                            const std::string& iq_id) {
        if (!session->resource_bound) {
            return SessionEstablisher::session_error(iq_id, "not-allowed");
        }

        session->session_established = true;
        session->state = StreamState::READY;
        session->invalidate_features_cache();

        return SessionEstablisher::session_result(iq_id);
    }

    // --- Stream compression ---
    std::string on_compress(std::shared_ptr<StreamSession> session,
                             const std::string& method) {
        if (session->compression && session->compression->is_compressed()) {
            return CompressionHandler::on_compress_failure("setup-failed");
        }

        CompressionHandler handler;
        bool ok = handler.activate_compression(*session);
        if (!ok) {
            return CompressionHandler::on_compress_failure("setup-failed");
        }

        session->compression_offered = true;
        StreamRestartHandler::restart_after_compression(*session, id_tracker_);

        return handler.on_compress_request(method);
    }

    // --- Stream management ---
    std::string on_sm_enable(std::shared_ptr<StreamSession> session,
                              bool resume = true, int max_resume = 300) {
        return stream_manager_.handle_enable(*session, resume, max_resume);
    }

    std::string on_sm_resume(std::shared_ptr<StreamSession> session,
                              const std::string& prev_id, uint32_t h) {
        return stream_manager_.handle_resume(*session, prev_id, h);
    }

    void on_sm_ack(std::shared_ptr<StreamSession> session, uint32_t h) {
        stream_manager_.handle_client_ack(*session, h);
    }

    std::string on_sm_request(std::shared_ptr<StreamSession> session) {
        return stream_manager_.send_ack(*session);
    }

    void count_inbound_stanza(std::shared_ptr<StreamSession> session) {
        stream_manager_.count_inbound(*session);
    }

    void track_outbound_stanza(std::shared_ptr<StreamSession> session,
                                const std::string& stanza) {
        stream_manager_.count_outbound(*session, stanza);
    }

    // --- Stream close ---
    std::string on_stream_close(std::shared_ptr<StreamSession> session,
                                 StreamCloseHandler::CloseMode mode =
                                     StreamCloseHandler::CloseMode::NORMAL,
                                 const std::string& text = "") {
        std::string response = StreamCloseHandler::build_close_response(mode, text);
        StreamCloseHandler::perform_cleanup(*session, id_tracker_);
        return response;
    }

    // --- Build features (for external use) ---
    std::string get_features(std::shared_ptr<StreamSession> session) {
        return features_builder_.build_features(*session);
    }

    // --- BOSH support ---
    BoshStreamFeatures::BoshSession create_bosh_session(int wait, int hold,
                                                          const std::string& to) {
        return BoshStreamFeatures::create_session(
            id_tracker_.generate(), wait, hold, to);
    }

    std::string get_bosh_features(const BoshStreamFeatures::BoshSession& bosh_session) {
        return BoshStreamFeatures::get_features_xml(bosh_session);
    }

    // --- WebSocket support ---
    std::string get_ws_stream_open(const std::string& stream_id,
                                    const std::string& from = "") {
        return WebSocketStreamFeatures::stream_open_response(
            stream_id, server_domain_, from);
    }

    std::string get_ws_features() {
        return WebSocketStreamFeatures::get_features_xml();
    }

    // --- Stream ID management ---
    StreamIdTracker& id_tracker() { return id_tracker_; }

    // --- TLS context access ---
    std::shared_ptr<TlsContext> tls_context() { return tls_ctx_; }

    // --- Server domain ---
    const std::string& domain() const { return server_domain_; }

private:
    // --- SASL PLAIN ---
    std::string handle_sasl_plain(std::shared_ptr<StreamSession> session,
                                   const std::string& b64_data) {
        auto auth = SaslPlain::parse(b64_data);
        if (auth.authcid.empty()) {
            return SaslError::malformed_request().to_xml();
        }

        // Store credentials for authorization callback
        session->sasl_authzid = auth.authzid;
        session->sasl_authcid = auth.authcid;
        session->sasl_password = auth.password;

        // Authorization callback (to be overridden by server implementation)
        if (!authorize_plain_callback_ ||
            !authorize_plain_callback_(auth.authzid, auth.authcid, auth.password)) {
            return SaslError::not_authorized().to_xml();
        }

        session->sasl_authenticated = true;
        session->user_jid.node = auth.authcid;
        session->user_jid.domain = server_domain_;
        session->state = StreamState::SASL_AUTHENTICATED;
        session->invalidate_features_cache();

        return SaslPlain::success_data(auth.authcid);
    }

    // --- SASL EXTERNAL ---
    std::string handle_sasl_external(std::shared_ptr<StreamSession> session,
                                      const std::string& b64_data) {
        if (!session->tls_enabled && !tls_skip_for_external_) {
            return SaslError::encryption_required().to_xml();
        }

        std::string authzid = SaslExternal::parse_authzid(b64_data);

        // If no authzid provided, derive from TLS client certificate
        if (authzid.empty() && session->tls_enabled && starttls_handler_) {
            authzid = starttls_handler_->get_peer_cert_subject(*session);
        }

        if (authzid.empty()) {
            return SaslError::invalid_authzid().to_xml();
        }

        if (!authorize_external_callback_ ||
            !authorize_external_callback_(authzid)) {
            return SaslError::not_authorized().to_xml();
        }

        session->sasl_authenticated = true;
        session->user_jid.node = authzid;
        session->user_jid.domain = server_domain_;
        session->state = StreamState::SASL_AUTHENTICATED;
        session->invalidate_features_cache();

        return SaslExternal::success(authzid);
    }

    // --- SASL ANONYMOUS ---
    std::string handle_sasl_anonymous(std::shared_ptr<StreamSession> session,
                                       const std::string& b64_data) {
        std::string trace = SaslAnonymous::parse_trace(b64_data);

        if (!authorize_anonymous_callback_ ||
            !authorize_anonymous_callback_(trace)) {
            return SaslError::not_authorized().to_xml();
        }

        // Generate anonymous JID
        std::string anon_id = "anon-" + gen_nonce(8);
        session->sasl_authenticated = true;
        session->user_jid.node = anon_id;
        session->user_jid.domain = server_domain_;
        session->state = StreamState::SASL_AUTHENTICATED;
        session->invalidate_features_cache();

        return SaslAnonymous::success();
    }

    // --- SASL SCRAM (server-first-message) ---
    std::string handle_sasl_scram_first(std::shared_ptr<StreamSession> session,
                                         const std::string& mechanism,
                                         const std::string& b64_client_first) {
        // Parse client first message
        std::string gs2_header, authzid, username, client_nonce;
        if (!ScramAuth::parse_client_first(b64_client_first,
                                            gs2_header, authzid,
                                            username, client_nonce)) {
            return SaslError::malformed_request().to_xml();
        }

        // Store for later use
        session->scram.client_first_message_bare = "n=" +
            ScramAuth::saslname_escape(username) +
            ",r=" + client_nonce;

        session->sasl_authzid = authzid;
        session->sasl_authcid = username; // from client-first
        session->sasl_round = 2;

        // Lookup password for user
        std::string password;
        if (password_lookup_callback_) {
            password = password_lookup_callback_(username);
        }
        if (password.empty()) {
            return SaslError::not_authorized().to_xml();
        }

        // Generate server nonce and salt
        std::string server_nonce = gen_nonce(24);
        std::string salt = gen_salt(16);
        int iterations = 4096;

        // Build server-first-message
        std::string combined_nonce = client_nonce + server_nonce;
        std::string server_first_msg = "r=" + combined_nonce +
                                        ",s=" + base64_encode(salt) +
                                        ",i=" + std::to_string(iterations);

        session->scram.nonce = combined_nonce;
        session->scram.salt = salt;
        session->scram.iterations = iterations;

        // Compute SaltedPassword, StoredKey, ServerKey now
        size_t hash_len = (mechanism == "SCRAM-SHA-1") ? SHA_DIGEST_LENGTH :
                          (mechanism == "SCRAM-SHA-256") ? SHA256_DIGEST_LENGTH :
                                                            SHA512_DIGEST_LENGTH;
        std::string salted_password;
        if (mechanism == "SCRAM-SHA-1")
            salted_password = pbkdf2_hmac_sha1(password, salt, iterations,
                                                static_cast<int>(hash_len));
        else if (mechanism == "SCRAM-SHA-256")
            salted_password = pbkdf2_hmac_sha256(password, salt, iterations,
                                                  static_cast<int>(hash_len));
        else
            salted_password = pbkdf2_hmac_sha512(password, salt, iterations,
                                                  static_cast<int>(hash_len));

        if (mechanism == "SCRAM-SHA-1") {
            session->scram.stored_key = sha1(
                hmac_sha1(salted_password, "Client Key"));
            session->scram.server_key = hmac_sha1(salted_password, "Server Key");
        } else if (mechanism == "SCRAM-SHA-256") {
            session->scram.stored_key = sha256(
                hmac_sha256(salted_password, "Client Key"));
            session->scram.server_key = hmac_sha256(salted_password, "Server Key");
        } else {
            session->scram.stored_key = sha512(
                hmac_sha512(salted_password, "Client Key"));
            session->scram.server_key = hmac_sha512(salted_password, "Server Key");
        }

        // Build challenge
        std::string encoded_challenge = base64_encode(server_first_msg);
        return "<challenge xmlns='" + std::string(ns::SASL) + "'>" +
               encoded_challenge + "</challenge>";
    }

    // --- SASL SCRAM (client-final-message) ---
    std::string handle_sasl_scram_final(std::shared_ptr<StreamSession> session,
                                         const std::string& b64_client_final) {
        std::string mechanism = session->sasl_mechanism;
        std::string client_final = base64_decode(b64_client_final);

        // Parse fields: c=...,r=...,p=...
        auto fields = StreamParser::parse_scram_message(client_final);

        std::string channel_binding = "";
        std::string nonce = "";
        std::string proof = "";

        auto it = fields.find("c");
        if (it != fields.end()) channel_binding = it->second;
        it = fields.find("r");
        if (it != fields.end()) nonce = it->second;
        it = fields.find("p");
        if (it != fields.end()) proof = it->second;

        // Verify nonce
        if (nonce != session->scram.nonce) {
            return SaslError::not_authorized().to_xml();
        }

        // Build auth message
        std::string client_final_wo_proof = "c=" + channel_binding +
                                             ",r=" + nonce;
        std::string auth_message =
            session->scram.client_first_message_bare + "," +
            "r=" + session->scram.nonce +
            ",s=" + base64_encode(session->scram.salt) +
            ",i=" + std::to_string(session->scram.iterations) + "," +
            client_final_wo_proof;

        // Verify client proof
        std::string client_proof = base64_decode(proof);
        std::string client_key;
        std::string stored_key = session->scram.stored_key;
        std::string server_key = session->scram.server_key;

        // HMAC(stored_key, auth_message) then XOR with client_proof to get client_key
        std::string client_signature;
        if (mechanism == "SCRAM-SHA-1")
            client_signature = hmac_sha1(stored_key, auth_message);
        else if (mechanism == "SCRAM-SHA-256")
            client_signature = hmac_sha256(stored_key, auth_message);
        else
            client_signature = hmac_sha512(stored_key, auth_message);

        if (client_signature.size() != client_proof.size()) {
            return SaslError::not_authorized().to_xml();
        }

        client_key = xor_strings(client_signature, client_proof);

        // H(client_key) should equal stored_key
        std::string computed_stored;
        if (mechanism == "SCRAM-SHA-1")
            computed_stored = sha1(client_key);
        else if (mechanism == "SCRAM-SHA-256")
            computed_stored = sha256(client_key);
        else
            computed_stored = sha512(client_key);

        if (computed_stored != stored_key) {
            return SaslError::not_authorized().to_xml();
        }

        // Compute server signature
        std::string server_signature;
        if (mechanism == "SCRAM-SHA-1")
            server_signature = hmac_sha1(server_key, auth_message);
        else if (mechanism == "SCRAM-SHA-256")
            server_signature = hmac_sha256(server_key, auth_message);
        else
            server_signature = hmac_sha512(server_key, auth_message);

        std::string server_final_msg = "v=" + base64_encode(server_signature);

        // Authentication successful
        session->sasl_authenticated = true;
        session->sasl_password.clear();  // clear password from memory

        // Set user JID
        if (!session->sasl_authzid.empty()) {
            session->user_jid.node = session->sasl_authzid;
        } else {
            session->user_jid.node = session->sasl_authcid;
        }
        session->user_jid.domain = server_domain_;

        // Clear scram sensitive data
        session->scram.stored_key.clear();
        session->scram.server_key.clear();
        session->scram.salt.clear();

        session->state = StreamState::SASL_AUTHENTICATED;
        session->invalidate_features_cache();

        return "<success xmlns='" + std::string(ns::SASL) + "'>" +
               base64_encode(server_final_msg) + "</success>";
    }

    // --- Callbacks for authorization ---
public:
    using AuthorizePlainFn =
        std::function<bool(const std::string& authzid,
                           const std::string& authcid,
                           const std::string& password)>;
    using AuthorizeExternalFn =
        std::function<bool(const std::string& authzid)>;
    using AuthorizeAnonymousFn =
        std::function<bool(const std::string& trace)>;
    using PasswordLookupFn =
        std::function<std::string(const std::string& username)>;

    void set_authorize_plain(AuthorizePlainFn fn) {
        authorize_plain_callback_ = std::move(fn);
    }
    void set_authorize_external(AuthorizeExternalFn fn) {
        authorize_external_callback_ = std::move(fn);
    }
    void set_authorize_anonymous(AuthorizeAnonymousFn fn) {
        authorize_anonymous_callback_ = std::move(fn);
    }
    void set_password_lookup(PasswordLookupFn fn) {
        password_lookup_callback_ = std::move(fn);
    }
    void set_tls_skip_for_external(bool v) {
        tls_skip_for_external_ = v;
    }

private:
    std::string server_domain_;
    std::shared_ptr<TlsContext> tls_ctx_;
    std::unique_ptr<StartTlsHandler> starttls_handler_;
    StreamFeaturesBuilder features_builder_;
    StreamManager stream_manager_;
    StreamIdTracker id_tracker_;
    std::vector<std::string> sasl_mechanisms_;

    // Callbacks
    AuthorizePlainFn authorize_plain_callback_;
    AuthorizeExternalFn authorize_external_callback_;
    AuthorizeAnonymousFn authorize_anonymous_callback_;
    PasswordLookupFn password_lookup_callback_;
    bool tls_skip_for_external_ = false;
};

// =============================================================================
// Global singleton (optional)
// =============================================================================
namespace {
    std::mutex global_engine_mutex;
    std::map<std::string, std::shared_ptr<StreamFeaturesEngine>> global_engines;
}

std::shared_ptr<StreamFeaturesEngine> get_or_create_engine(
    const std::string& domain,
    std::shared_ptr<TlsContext> tls_ctx = nullptr) {
    std::lock_guard<std::mutex> lock(global_engine_mutex);
    auto it = global_engines.find(domain);
    if (it != global_engines.end()) return it->second;

    auto engine = std::make_shared<StreamFeaturesEngine>(domain);
    if (tls_ctx) {
        engine->set_tls_context(tls_ctx);
    }
    global_engines[domain] = engine;
    return engine;
}

void remove_engine(const std::string& domain) {
    std::lock_guard<std::mutex> lock(global_engine_mutex);
    global_engines.erase(domain);
}

// =============================================================================
// Convenience: complete stream negotiation helper
// =============================================================================
class StreamNegotiationHelper {
public:
    explicit StreamNegotiationHelper(std::shared_ptr<StreamFeaturesEngine> engine)
        : engine_(engine) {}

    // Process incoming XML and return response XML
    // This is a simplified state machine; for production, integrate with
    // your connection handler's event loop
    std::string process(std::shared_ptr<StreamSession> session,
                         const std::string& incoming_xml) {
        session->last_activity = now_ms();

        // --- Stream open check ---
        if (session->state == StreamState::INIT ||
            session->state == StreamState::TLS_ESTABLISHED &&
            incoming_xml.find("<stream:stream") != std::string::npos) {
            return engine_->on_stream_open(session, incoming_xml);
        }

        // --- STARTTLS ---
        if (incoming_xml.find("<starttls") != std::string::npos &&
            session->state == StreamState::FEATURES_SENT) {
            return engine_->on_starttls(session);
        }

        // --- SASL auth ---
        if (incoming_xml.find("<auth ") != std::string::npos &&
            (session->state == StreamState::FEATURES_SENT ||
             session->state == StreamState::TLS_ESTABLISHED)) {
            std::string mech = StreamParser::extract_attr(incoming_xml, "mechanism");
            std::string content = StreamParser::extract_text_content(incoming_xml, "auth");
            return engine_->on_sasl_auth(session, mech, content);
        }

        // --- SASL response (SCRAM round 2) ---
        if (incoming_xml.find("<response ") != std::string::npos &&
            session->state == StreamState::SASL_NEGOTIATING) {
            std::string content = StreamParser::extract_text_content(
                incoming_xml, "response");
            return engine_->on_sasl_response(session, content);
        }

        // --- Resource binding ---
        if (incoming_xml.find("<bind ") != std::string::npos &&
            session->state == StreamState::SASL_AUTHENTICATED) {
            std::string id = StreamParser::extract_attr(incoming_xml, "id");
            std::string resource = StreamParser::extract_text_content(
                incoming_xml, "resource");
            return engine_->on_bind(session, id, resource);
        }

        // --- Session establishment ---
        if (incoming_xml.find("<session ") != std::string::npos &&
            session->state == StreamState::SESSION_ESTABLISHING) {
            std::string id = StreamParser::extract_attr(incoming_xml, "id");
            return engine_->on_session(session, id);
        }

        // --- Stream compression ---
        if (incoming_xml.find("<compress ") != std::string::npos) {
            std::string method = StreamParser::extract_text_content(
                incoming_xml, "method");
            return engine_->on_compress(session, method);
        }

        // --- Stream management enable ---
        if (incoming_xml.find("<enable ") != std::string::npos) {
            bool resume = incoming_xml.find("resume='true'") != std::string::npos;
            return engine_->on_sm_enable(session, resume);
        }

        // --- Stream management resume ---
        if (incoming_xml.find("<resume ") != std::string::npos) {
            std::string prev_id = StreamParser::extract_attr(incoming_xml, "previd");
            std::string h_str = StreamParser::extract_attr(incoming_xml, "h");
            uint32_t h = h_str.empty() ? 0 : static_cast<uint32_t>(std::stoul(h_str));
            return engine_->on_sm_resume(session, prev_id, h);
        }

        // --- Stream management ack ---
        if (incoming_xml.find("<a ") != std::string::npos) {
            std::string h_str = StreamParser::extract_attr(incoming_xml, "h");
            if (!h_str.empty()) {
                engine_->on_sm_ack(session, static_cast<uint32_t>(std::stoul(h_str)));
            }
            return "";  // Acks have no response
        }

        // --- Stream management request ---
        if (incoming_xml.find("<r ") != std::string::npos) {
            return engine_->on_sm_request(session);
        }

        // --- Stream close ---
        if (incoming_xml.find("</stream:stream>") != std::string::npos) {
            return engine_->on_stream_close(session);
        }

        // --- Unknown / stanza (handled by upper layer) ---
        return "";
    }

private:
    std::shared_ptr<StreamFeaturesEngine> engine_;
};

// =============================================================================
// TLS certificate utilities
// =============================================================================
class TlsCertificateManager {
public:
    // Load certificate and key from file paths
    static bool load_from_files(TlsContext& ctx,
                                 const std::string& cert_path,
                                 const std::string& key_path) {
        return ctx.load_certificate(cert_path, key_path);
    }

    // Load from PEM strings in memory
    static bool load_from_memory(TlsContext& ctx,
                                  const std::string& cert_pem,
                                  const std::string& key_pem) {
        return ctx.load_certificate_from_memory(cert_pem, key_pem);
    }

    // Generate a self-signed certificate for testing
    static bool generate_self_signed(TlsContext& ctx,
                                      const std::string& common_name,
                                      const std::string& org = "Progressive XMPP") {
        EVP_PKEY* pkey = EVP_PKEY_new();
        RSA* rsa = RSA_new();
        BIGNUM* bn = BN_new();

        BN_set_word(bn, RSA_F4);
        RSA_generate_key_ex(rsa, 2048, bn, nullptr);
        EVP_PKEY_assign_RSA(pkey, rsa);

        X509* x509 = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year

        X509_set_pubkey(x509, pkey);

        X509_NAME* name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                    (unsigned char*)"US", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                    (unsigned char*)org.c_str(), -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (unsigned char*)common_name.c_str(), -1, -1, 0);

        X509_set_issuer_name(x509, name);

        X509_sign(x509, pkey, EVP_sha256());

        SSL_CTX_use_certificate(ctx.ctx(), x509);
        SSL_CTX_use_PrivateKey(ctx.ctx(), pkey);

        X509_free(x509);
        EVP_PKEY_free(pkey);
        BN_free(bn);

        return SSL_CTX_check_private_key(ctx.ctx()) > 0;
    }

    // Get certificate info as JSON
    static json get_certificate_info(TlsHandshake& handshake) {
        json info;
        info["subject"] = handshake.get_peer_cert_subject();
        info["fingerprint_sha256"] = handshake.get_peer_cert_fingerprint("sha256");
        info["fingerprint_sha1"] = handshake.get_peer_cert_fingerprint("sha1");
        info["cipher"] = handshake.get_cipher();
        info["protocol"] = handshake.get_protocol_version();
        return info;
    }
};

// =============================================================================
// XEP-0198 stream management ack request loop
// =============================================================================
class SmAckManager {
public:
    SmAckManager(StreamFeaturesEngine& engine) : engine_(engine) {}

    // Check if we should send an ack request
    bool should_request_ack(std::shared_ptr<StreamSession> session) {
        if (!session->sm.enabled) return false;
        if (session->sm.outbound_count -
            session->sm.last_ack_from_client > unacked_threshold_)
            return true;
        if (now_sec() - session->sm.last_ack_time > ack_interval_sec_)
            return true;
        return false;
    }

    std::string request_ack(std::shared_ptr<StreamSession> session) {
        return engine_.on_sm_request(session);
    }

    void set_ack_interval(int sec) { ack_interval_sec_ = sec; }
    void set_unacked_threshold(int n) { unacked_threshold_ = n; }

private:
    StreamFeaturesEngine& engine_;
    int ack_interval_sec_ = 60;
    int unacked_threshold_ = 10;
};

// =============================================================================
// Stream feature advertisement for service discovery (XEP-0030)
// =============================================================================
std::string generate_disco_info_response(const std::string& id,
                                          const std::string& from,
                                          const std::string& to,
                                          const std::vector<std::string>& features) {
    XMLElement iq("iq");
    iq.attr("type", "result");
    iq.attr("id", id);
    iq.attr("from", from);
    iq.attr("to", to);

    XMLElement query("query");
    query.xmlns(ns::DISCO_INFO);

    // Identity
    XMLElement identity("identity");
    identity.attr("category", "server");
    identity.attr("type", "im");
    identity.attr("name", "Progressive XMPP Server");
    query.child(identity);

    // Features
    for (auto& f : features) {
        query.child(XMLElement("feature").attr("var", f));
    }

    iq.child(query);
    return iq.to_string();
}

std::vector<std::string> get_default_disco_features() {
    return {
        ns::DISCO_INFO,
        ns::DISCO_ITEMS,
        ns::TLS,
        ns::SASL,
        ns::BIND,
        ns::SESSION,
        ns::STREAM_MGMT,
        ns::COMPRESS,
        ns::CARBONS,
        ns::CSI,
        ns::BOSH,
        ns::WEBSOCKET,
        "jabber:iq:roster",
        "jabber:iq:version",
        "jabber:iq:last",
        "urn:xmpp:ping",
        "urn:xmpp:time",
        "vcard-temp",
        "urn:xmpp:mam:2",
        "urn:xmpp:blocking",
        "urn:xmpp:muc",
    };
}

// =============================================================================
// OpenSSL initialization helper
// =============================================================================
class OpenSslInit {
public:
    static void init() {
        static std::once_flag flag;
        std::call_once(flag, []() {
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
        });
    }
};

// =============================================================================
// Stream feature cache manager (cross-session)
// =============================================================================
class FeatureCacheManager {
public:
    void set_default_features(const std::string& features_xml) {
        default_features_ = features_xml;
    }

    std::string get_cached_or_build(StreamSession& session,
                                     StreamFeaturesBuilder& builder) {
        return builder.build_features(session);
    }

    void invalidate_all() {
        // Sessions will auto-refresh on next build_features call
    }

private:
    std::string default_features_;
};

} // namespace xmpp
} // namespace progressive

// =============================================================================
// Extended: SCRAM stored password formats and database integration
// =============================================================================
namespace progressive::xmpp {

// SCRAM stored password record for database persistence
struct ScramStoredPassword {
    std::string mechanism;      // "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512"
    std::string stored_key;     // base64(SHA(ClientKey))
    std::string server_key;     // base64(ServerKey)
    std::string salt;           // base64(salt)
    int iterations = 4096;

    // Serialize to single string for storage: mech:id:salt:stored_key:server_key
    std::string serialize() const {
        return mechanism + ":" + std::to_string(iterations) + ":" +
               base64_encode(salt) + ":" + base64_encode(stored_key) + ":" +
               base64_encode(server_key);
    }

    // Deserialize from storage format
    static std::optional<ScramStoredPassword> deserialize(const std::string& data) {
        ScramStoredPassword ssp;
        std::vector<std::string> parts;
        size_t pos = 0;
        for (int i = 0; i < 5; i++) {
            size_t colon = data.find(':', pos);
            if (colon == std::string::npos && i < 4) return std::nullopt;
            parts.push_back(data.substr(pos, colon - pos));
            pos = colon + 1;
        }

        ssp.mechanism = parts[0];
        ssp.iterations = std::stoi(parts[1]);
        ssp.salt = base64_decode(parts[2]);
        ssp.stored_key = base64_decode(parts[3]);
        ssp.server_key = base64_decode(parts[4]);
        return ssp;
    }

    // Compute from plaintext password
    static ScramStoredPassword from_password(const std::string& mechanism,
                                              const std::string& password,
                                              const std::string& salt_override = "",
                                              int iterations = 4096) {
        ScramStoredPassword ssp;
        ssp.mechanism = mechanism;
        ssp.iterations = iterations;
        ssp.salt = salt_override.empty() ? gen_salt(16) : salt_override;

        size_t hash_len;
        std::function<std::string(const std::string&, const std::string&)> hmac_fn;
        std::function<std::string(const std::string&)> hash_fn;
        std::function<std::string(const std::string&, const std::string&, int, int)> pbkdf2_fn;

        if (mechanism == "SCRAM-SHA-1") {
            hash_len = SHA_DIGEST_LENGTH;
            hmac_fn = hmac_sha1;
            hash_fn = sha1;
            pbkdf2_fn = [](const std::string& p, const std::string& s, int i, int kl) {
                return pbkdf2_hmac_sha1(p, s, i, kl);
            };
        } else if (mechanism == "SCRAM-SHA-256") {
            hash_len = SHA256_DIGEST_LENGTH;
            hmac_fn = hmac_sha256;
            hash_fn = sha256;
            pbkdf2_fn = [](const std::string& p, const std::string& s, int i, int kl) {
                return pbkdf2_hmac_sha256(p, s, i, kl);
            };
        } else {
            hash_len = SHA512_DIGEST_LENGTH;
            hmac_fn = hmac_sha512;
            hash_fn = sha512;
            pbkdf2_fn = [](const std::string& p, const std::string& s, int i, int kl) {
                return pbkdf2_hmac_sha512(p, s, i, kl);
            };
        }

        std::string salted = pbkdf2_fn(password, ssp.salt, iterations,
                                        static_cast<int>(hash_len));
        std::string client_key = hmac_fn(salted, "Client Key");
        ssp.stored_key = hash_fn(client_key);
        ssp.server_key = hmac_fn(salted, "Server Key");

        return ssp;
    }
};

// =============================================================================
// Connection timeout & idle tracking
// =============================================================================
class ConnectionTimeoutHandler {
public:
    struct TimeoutConfig {
        int stream_open_timeout_sec = 60;    // time to complete stream open
        int tls_handshake_timeout_sec = 30;  // time for TLS handshake
        int sasl_auth_timeout_sec = 60;      // time for SASL auth
        int idle_timeout_sec = 300;           // idle connection timeout
        int max_session_duration_sec = 86400; // 24h max session
    };

    enum class TimeoutAction {
        NONE,
        SEND_ERROR,
        CLOSE,
    };

    TimeoutAction check_timeout(const StreamSession& session,
                                 const TimeoutConfig& config) {
        int64_t now = now_sec();
        int64_t elapsed = now - session.connected_at / 1000;

        // Overall session timeout
        if (elapsed > config.max_session_duration_sec) {
            return TimeoutAction::CLOSE;
        }

        // State-specific timeouts
        switch (session.state) {
            case StreamState::INIT:
            case StreamState::STREAM_OPEN_RECEIVED: {
                int64_t since_open = now - session.stream_opened_at / 1000;
                if (session.stream_opened_at > 0 &&
                    since_open > config.stream_open_timeout_sec) {
                    return TimeoutAction::SEND_ERROR;
                }
                break;
            }
            case StreamState::TLS_NEGOTIATING: {
                int64_t since_state;
                if (now - session.last_activity / 1000 > config.tls_handshake_timeout_sec) {
                    return TimeoutAction::CLOSE;
                }
                break;
            }
            case StreamState::SASL_NEGOTIATING: {
                if (now - session.last_activity / 1000 > config.sasl_auth_timeout_sec) {
                    return TimeoutAction::SEND_ERROR;
                }
                break;
            }
            case StreamState::READY: {
                if (now - session.last_activity / 1000 > config.idle_timeout_sec) {
                    return TimeoutAction::CLOSE;
                }
                break;
            }
            default:
                break;
        }

        return TimeoutAction::NONE;
    }

    static StreamError get_timeout_error(const StreamSession& session) {
        switch (session.state) {
            case StreamState::SASL_NEGOTIATING:
                return StreamError::make(StreamErrorType::NOT_AUTHORIZED,
                                          "Authentication timed out");
            case StreamState::TLS_NEGOTIATING:
                return StreamError::make(StreamErrorType::CONNECTION_TIMEOUT,
                                          "TLS handshake timed out");
            default:
                return StreamError::make(StreamErrorType::CONNECTION_TIMEOUT,
                                          "Connection timed out");
        }
    }
};

// =============================================================================
// Stream negotiation: multi-step state machine for integration
// =============================================================================
class StreamNegotiationStateMachine {
public:
    struct Step {
        enum Type { SEND_XML, INIT_TLS, TLS_HANDSHAKE, RESTART_STREAM,
                    AUTH_CHALLENGE, WAIT_CLIENT, COMPLETE, ERROR };
        Type type = SEND_XML;
        std::string send_data;
        bool needs_io = false;  // needs non-blocking I/O poll
    };

    explicit StreamNegotiationStateMachine(
        std::shared_ptr<StreamFeaturesEngine> engine)
        : engine_(std::move(engine)) {}

    Step next_step(std::shared_ptr<StreamSession> session) {
        Step step;

        switch (session->state) {
            case StreamState::INIT: {
                step.type = Step::WAIT_CLIENT;
                break;
            }
            case StreamState::FEATURES_SENT: {
                step.type = Step::WAIT_CLIENT;
                break;
            }
            case StreamState::STARTTLS_REQUESTED: {
                // Initiate TLS handshake
                step.type = Step::INIT_TLS;
                step.needs_io = true;
                break;
            }
            case StreamState::TLS_NEGOTIATING: {
                step.type = Step::TLS_HANDSHAKE;
                step.needs_io = true;
                break;
            }
            case StreamState::TLS_ESTABLISHED: {
                // Must restart stream
                step.type = Step::RESTART_STREAM;
                step.send_data = engine_->on_tls_restart(session);
                break;
            }
            case StreamState::SASL_AUTHENTICATED: {
                step.type = Step::RESTART_STREAM;
                step.send_data = engine_->on_sasl_success_restart(session);
                break;
            }
            case StreamState::READY: {
                step.type = Step::COMPLETE;
                break;
            }
            case StreamState::CLOSING:
            case StreamState::CLOSED: {
                step.type = Step::COMPLETE;
                break;
            }
            default: {
                step.type = Step::WAIT_CLIENT;
                break;
            }
        }

        return step;
    }

    void process_client_data(std::shared_ptr<StreamSession> session,
                              const std::string& xml_data,
                              std::string& response_out) {
        StreamNegotiationHelper helper(engine_);
        response_out = helper.process(session, xml_data);
    }

private:
    std::shared_ptr<StreamFeaturesEngine> engine_;
};

// =============================================================================
// Convenience factory for setting up a complete stream features engine
// =============================================================================
class StreamFeaturesFactory {
public:
    struct Config {
        std::string domain;
        std::string cert_file;
        std::string key_file;
        bool tls_required = false;
        bool compression_enabled = false;
        bool sm_enabled = true;
        bool carbons_enabled = true;
        bool csi_enabled = true;
        bool allow_anonymous = false;
        int scram_iterations = 4096;
        std::vector<std::string> sasl_mechanisms = {
            "SCRAM-SHA-512", "SCRAM-SHA-256", "SCRAM-SHA-1",
            "PLAIN", "EXTERNAL", "ANONYMOUS"
        };
    };

    static std::shared_ptr<StreamFeaturesEngine> create(const Config& config) {
        OpenSslInit::init();

        auto tls_ctx = std::make_shared<TlsContext>();
        if (!config.cert_file.empty() && !config.key_file.empty()) {
            tls_ctx->load_certificate(config.cert_file, config.key_file);
        }

        auto engine = std::make_shared<StreamFeaturesEngine>(config.domain);
        engine->set_tls_context(tls_ctx);
        engine->set_tls_required(config.tls_required);
        engine->set_compression_enabled(config.compression_enabled);
        engine->set_sasl_mechanisms(config.sasl_mechanisms);
        engine->enable_sm(config.sm_enabled);
        engine->enable_carbons(config.carbons_enabled);
        engine->enable_csi(config.csi_enabled);

        return engine;
    }

    // Create with self-signed cert for testing
    static std::shared_ptr<StreamFeaturesEngine> create_test(
        const std::string& domain) {
        Config config;
        config.domain = domain;
        config.tls_required = false;
        config.allow_anonymous = true;

        auto engine = create(config);
        auto tls_ctx = engine->tls_context();
        if (tls_ctx) {
            TlsCertificateManager::generate_self_signed(*tls_ctx, domain);
        }
        return engine;
    }
};

// =============================================================================
// Stream feature negotiation metrics / statistics
// =============================================================================
class StreamMetricsCollector {
public:
    struct Metrics {
        std::atomic<int64_t> total_connections{0};
        std::atomic<int64_t> active_connections{0};
        std::atomic<int64_t> tls_handshakes_completed{0};
        std::atomic<int64_t> tls_handshakes_failed{0};
        std::atomic<int64_t> sasl_auth_success{0};
        std::atomic<int64_t> sasl_auth_failure{0};
        std::atomic<int64_t> resource_binds{0};
        std::atomic<int64_t> sessions_established{0};
        std::atomic<int64_t> stream_errors{0};
        std::atomic<int64_t> sm_enables{0};
        std::atomic<int64_t> sm_resumes{0};
        std::atomic<int64_t> connections_closed{0};
        std::atomic<int64_t> bytes_sent{0};
        std::atomic<int64_t> bytes_received{0};
    };

    void record_connection() { metrics_.total_connections++; metrics_.active_connections++; }
    void record_disconnect() { metrics_.active_connections--; metrics_.connections_closed++; }
    void record_tls_success() { metrics_.tls_handshakes_completed++; }
    void record_tls_failure() { metrics_.tls_handshakes_failed++; }
    void record_auth_success() { metrics_.sasl_auth_success++; }
    void record_auth_failure() { metrics_.sasl_auth_failure++; }
    void record_bind() { metrics_.resource_binds++; }
    void record_session() { metrics_.sessions_established++; }
    void record_error() { metrics_.stream_errors++; }
    void record_sm_enable() { metrics_.sm_enables++; }
    void record_sm_resume() { metrics_.sm_resumes++; }
    void record_bytes_sent(int64_t n) { metrics_.bytes_sent += n; }
    void record_bytes_received(int64_t n) { metrics_.bytes_received += n; }

    json snapshot() const {
        json j;
        j["total_connections"] = metrics_.total_connections.load();
        j["active_connections"] = metrics_.active_connections.load();
        j["tls_handshakes_completed"] = metrics_.tls_handshakes_completed.load();
        j["tls_handshakes_failed"] = metrics_.tls_handshakes_failed.load();
        j["sasl_auth_success"] = metrics_.sasl_auth_success.load();
        j["sasl_auth_failure"] = metrics_.sasl_auth_failure.load();
        j["resource_binds"] = metrics_.resource_binds.load();
        j["sessions_established"] = metrics_.sessions_established.load();
        j["stream_errors"] = metrics_.stream_errors.load();
        j["sm_enables"] = metrics_.sm_enables.load();
        j["sm_resumes"] = metrics_.sm_resumes.load();
        j["connections_closed"] = metrics_.connections_closed.load();
        j["bytes_sent"] = metrics_.bytes_sent.load();
        j["bytes_received"] = metrics_.bytes_received.load();
        return j;
    }

    // Global singleton
    static StreamMetricsCollector& instance() {
        static StreamMetricsCollector collector;
        return collector;
    }

private:
    Metrics metrics_;
};

} // namespace progressive::xmpp

// =============================================================================
// End: xmpp_stream_features.cpp - 3500+ lines
// =============================================================================
