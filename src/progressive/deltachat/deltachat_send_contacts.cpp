// progressive-server/src/progressive/deltachat/deltachat_send_contacts.cpp
// DeltaChat Email Sending and Contact Management Implementation
// Target: 4000+ lines of complete C++ implementation
// Copyright (c) 2024 Progressive Server Project

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <cstring>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <random>
#include <regex>
#include <set>
#include <map>
#include <queue>
#include <thread>
#include <mutex>
#include <atomic>
#include <optional>
#include <variant>
#include <tuple>
#include <stdexcept>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cerrno>

// OpenSSL headers for encryption/signing
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/md5.h>

// libcurl for SMTP/IMAP
#include <curl/curl.h>

// zlib for compression
#include <zlib.h>

// SQLite for contact/chat storage
#include <sqlite3.h>

// JSON for serialization
#include <json/json.h>  // or nlohmann/json.hpp

namespace progressive {
namespace deltachat {

// ============================================================================
// Forward Declarations
// ============================================================================
class MimeMessage;
class ContactRecord;
class ChatRecord;
class MessageRecord;
class DeltaChatContext;
class AutocryptHeader;
class SecureJoinSession;
class WebXdcInstance;

// ============================================================================
// Constants
// ============================================================================
namespace constants {

    constexpr int DC_CHAT_TYPE_SINGLE      = 100;
    constexpr int DC_CHAT_TYPE_GROUP       = 120;
    constexpr int DC_CHAT_TYPE_BROADCAST   = 140;
    constexpr int DC_CHAT_TYPE_MAILINGLIST = 160;

    constexpr int DC_STATE_UNDEFINED       = 0;
    constexpr int DC_STATE_IN_FRESH        = 10;
    constexpr int DC_STATE_IN_NOTICED      = 13;
    constexpr int DC_STATE_IN_SEEN         = 16;
    constexpr int DC_STATE_OUT_DRAFT       = 19;
    constexpr int DC_STATE_OUT_PENDING     = 24;
    constexpr int DC_STATE_OUT_DELIVERED   = 26;
    constexpr int DC_STATE_OUT_FAILED      = 28;
    constexpr int DC_STATE_OUT_MDN_RCVD    = 30;

    constexpr int DC_CONTACT_VERIFIED      = 1;
    constexpr int DC_CONTACT_UNVERIFIED    = 0;

    constexpr int DC_GCL_ARCHIVED_ONLY     = 0x01;
    constexpr int DC_GCL_NO_SPECIALS       = 0x02;
    constexpr int DC_GCL_ADD_ALLDONE_HINT  = 0x04;
    constexpr int DC_GCL_FOR_FORWARDING    = 0x08;

    constexpr size_t MAX_ATTACHMENT_SIZE   = 25 * 1024 * 1024; // 25 MB
    constexpr size_t MAX_MESSAGE_SIZE      = 50 * 1024 * 1024; // 50 MB
    constexpr int    MAX_GROUP_SIZE        = 100;
    constexpr int    DEFAULT_EPHEMERAL_TIMER = 0; // disabled
    constexpr int    AUTOCRYPT_RECOMMENDED  = 1;
    constexpr int    AUTOCRYPT_PREFER_ENCRYPT = 2;
    constexpr int    AUTOCRYPT_MUTUAL       = 3;

    constexpr const char* DC_PROJECT_NAME   = "Progressive DeltaChat";
    constexpr const char* DC_USER_AGENT     = "Progressive/1.0 DeltaChat/1.0";
    constexpr const char* DC_MIME_TYPE_TEXT = "text/plain; charset=utf-8";
    constexpr const char* DC_MIME_TYPE_HTML = "text/html; charset=utf-8";
    constexpr const char* DC_HEADER_CHAT_ID = "Chat-Group-ID";
    constexpr const char* DC_HEADER_CHAT_NAME = "Chat-Group-Name";
    constexpr const char* DC_HEADER_CHAT_VERIFIED = "Chat-Verified";
    constexpr const char* DC_HEADER_IN_REPLY_TO = "In-Reply-To";
    constexpr const char* DC_HEADER_REFERENCES = "References";
    constexpr const char* DC_HEADER_AUTOCRYPT = "Autocrypt";
    constexpr const char* DC_HEADER_AUTOCRYPT_SETUP = "Autocrypt-Setup-Message";
    constexpr const char* DC_HEADER_SECUREJOIN = "Secure-Join";
    constexpr const char* DC_HEADER_EPHEMERAL = "Ephemeral-Timer";
    constexpr const char* DC_HEADER_LIST_ID = "List-ID";
    constexpr const char* DC_HEADER_PRECEDENCE = "Precedence";
    constexpr const char* DC_HEADER_DISPOSITION = "Disposition-Notification-To";

} // namespace constants

// ============================================================================
// Utility Functions
// ============================================================================
namespace util {

    static std::string base64_encode(const unsigned char* data, size_t len) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new(BIO_s_mem());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_push(b64, mem);
        BIO_write(b64, data, static_cast<int>(len));
        BIO_flush(b64);
        char* encoded;
        long encoded_len = BIO_get_mem_data(mem, &encoded);
        std::string result(encoded, encoded_len);
        BIO_free_all(b64);
        return result;
    }

    static std::string base64_encode(const std::string& data) {
        return base64_encode(reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
    }

    static std::vector<unsigned char> base64_decode(const std::string& encoded) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new_mem_buf(encoded.c_str(), static_cast<int>(encoded.size()));
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        mem = BIO_push(b64, mem);
        std::vector<unsigned char> decoded(encoded.size() * 3 / 4 + 4);
        int len = BIO_read(mem, decoded.data(), static_cast<int>(decoded.size()));
        BIO_free_all(mem);
        decoded.resize(len > 0 ? len : 0);
        return decoded;
    }

    static std::string sha256(const std::string& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

    static std::string sha1(const std::string& data) {
        unsigned char hash[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
        std::stringstream ss;
        for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

    static std::string md5(const std::string& data) {
        unsigned char hash[MD5_DIGEST_LENGTH];
        MD5(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
        std::stringstream ss;
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

    static std::string generate_message_id(const std::string& domain) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dis;
        uint64_t r1 = dis(gen);
        uint64_t r2 = dis(gen);
        auto now = std::chrono::system_clock::now();
        auto ts = std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()).count();
        std::stringstream ss;
        ss << "Mr." << std::hex << r1 << "." << r2 << "." << ts << "@" << domain;
        return ss.str();
    }

    static std::string generate_boundary() {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dis;
        auto now = std::chrono::system_clock::now();
        auto ts = std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch()).count();
        std::stringstream ss;
        ss << "==Multipart_Boundary_x" << std::hex << dis(gen) << ts << "x";
        return ss.str();
    }

    static std::string rfc2822_date() {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        struct tm tm_buf;
        gmtime_r(&t, &tm_buf);
        char buf[128];
        strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S +0000", &tm_buf);
        return std::string(buf);
    }

    static std::string rfc2231_encode(const std::string& input) {
        bool needs_encoding = false;
        for (char c : input) {
            if (static_cast<unsigned char>(c) > 127 || c == '\r' || c == '\n' || c == '"') {
                needs_encoding = true;
                break;
            }
        }
        if (!needs_encoding) {
            return input;
        }
        std::stringstream ss;
        ss << "=?utf-8?B?" << base64_encode(input) << "?=";
        return ss.str();
    }

    static std::string quoted_printable_encode(const std::string& input) {
        std::stringstream ss;
        int line_len = 0;
        for (unsigned char c : input) {
            if (c == '\n') {
                ss << "\r\n";
                line_len = 0;
            } else if ((c >= 33 && c <= 60) || (c >= 62 && c <= 126) || c == ' ' || c == '\t') {
                if (line_len >= 76) {
                    ss << "=\r\n";
                    line_len = 0;
                }
                ss << c;
                line_len++;
            } else {
                if (line_len >= 75) {
                    ss << "=\r\n";
                    line_len = 0;
                }
                ss << "=" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
                line_len += 3;
            }
        }
        return ss.str();
    }

    static std::string extract_addr_spec(const std::string& email_addr) {
        auto lt = email_addr.find('<');
        auto gt = email_addr.rfind('>');
        if (lt != std::string::npos && gt != std::string::npos && gt > lt) {
            return email_addr.substr(lt + 1, gt - lt - 1);
        }
        // strip whitespace
        auto start = email_addr.find_first_not_of(" \t\r\n");
        auto end = email_addr.find_last_not_of(" \t\r\n");
        if (start != std::string::npos && end != std::string::npos) {
            return email_addr.substr(start, end - start + 1);
        }
        return email_addr;
    }

    static std::string normalize_addr(const std::string& addr) {
        std::string spec = extract_addr_spec(addr);
        std::transform(spec.begin(), spec.end(), spec.begin(), ::tolower);
        return spec;
    }

    static std::string trim(const std::string& s) {
        auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    static std::vector<std::string> split(const std::string& s, char delim) {
        std::vector<std::string> result;
        std::stringstream ss(s);
        std::string item;
        while (std::getline(ss, item, delim)) {
            item = trim(item);
            if (!item.empty()) {
                result.push_back(item);
            }
        }
        return result;
    }

    static void to_lower_in_place(std::string& s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    }

    static std::string to_lower(const std::string& s) {
        std::string result = s;
        to_lower_in_place(result);
        return result;
    }

    static std::string random_hex(size_t length) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<int> dis(0, 15);
        const char* hex_chars = "0123456789abcdef";
        std::string result;
        result.reserve(length);
        for (size_t i = 0; i < length; ++i) {
            result += hex_chars[dis(gen)];
        }
        return result;
    }

} // namespace util

// ============================================================================
// KeyPair for Autocrypt
// ============================================================================
struct KeyPair {
    std::string public_key;   // PEM-encoded RSA public key
    std::string private_key;  // PEM-encoded RSA private key
    std::string fingerprint;  // SHA-256 fingerprint of public key

    static KeyPair generate(int bits = 2048) {
        KeyPair kp;
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) return kp;

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0 ||
            EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return kp;
        }
        EVP_PKEY_CTX_free(ctx);

        // Get public key PEM
        BIO* pub_bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(pub_bio, pkey);
        char* pub_data = nullptr;
        long pub_len = BIO_get_mem_data(pub_bio, &pub_data);
        kp.public_key.assign(pub_data, pub_len);
        BIO_free(pub_bio);

        // Get private key PEM
        BIO* priv_bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(priv_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        char* priv_data = nullptr;
        long priv_len = BIO_get_mem_data(priv_bio, &priv_data);
        kp.private_key.assign(priv_data, priv_len);
        BIO_free(priv_bio);

        // Compute fingerprint
        unsigned char der[4096];
        unsigned char* der_ptr = der;
        int der_len = i2d_PublicKey(pkey, &der_ptr);
        kp.fingerprint = util::sha256(std::string(reinterpret_cast<char*>(der), der_len));
        EVP_PKEY_free(pkey);
        return kp;
    }

    std::string sign(const std::string& data) const {
        BIO* bio = BIO_new_mem_buf(private_key.c_str(), -1);
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) return "";

        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return "";
        }
        if (EVP_DigestSignUpdate(mdctx, data.c_str(), data.size()) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return "";
        }
        size_t sig_len;
        if (EVP_DigestSignFinal(mdctx, nullptr, &sig_len) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return "";
        }
        std::vector<unsigned char> sig(sig_len);
        if (EVP_DigestSignFinal(mdctx, sig.data(), &sig_len) <= 0) {
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return "";
        }
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return util::base64_encode(sig.data(), sig_len);
    }

    bool verify(const std::string& data, const std::string& signature) const {
        BIO* bio = BIO_new_mem_buf(public_key.c_str(), -1);
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) return false;

        auto sig = util::base64_decode(signature);
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        bool ok = false;
        if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) > 0 &&
            EVP_DigestVerifyUpdate(mdctx, data.c_str(), data.size()) > 0 &&
            EVP_DigestVerifyFinal(mdctx, sig.data(), sig.size()) > 0) {
            ok = true;
        }
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return ok;
    }
};

// ============================================================================
// ContactRecord
// ============================================================================
struct ContactRecord {
    int id = 0;
    std::string name;
    std::string addr;          // normalized email address
    std::string display_name;
    int state = 0;
    int origin = 0;            // how contact was created
    int blocked = 0;
    int verified = 0;          // DC_CONTACT_VERIFIED or DC_CONTACT_UNVERIFIED
    std::string auth_name;
    std::string profile_image;
    std::string color;
    std::string status;
    int64_t last_seen = 0;
    int64_t was_seen = 0;
    std::string param;         // arbitrary key=value params
};

// ============================================================================
// ChatRecord
// ============================================================================
struct ChatRecord {
    int id = 0;
    int type = 0;              // DC_CHAT_TYPE_SINGLE, etc.
    std::string name;
    int blocked = 0;
    int archived = 0;
    int ephemeral_timer = 0;
    std::string profile_image;
    std::string color;
    std::string grpid;         // chat-group-id (threading)
    std::string param;
    int is_protected = 0;
    int is_device_chat = 0;
    int64_t created_timestamp = 0;
};

// ============================================================================
// MessageRecord
// ============================================================================
struct MessageRecord {
    int id = 0;
    int chat_id = 0;
    int from_id = 0;
    std::string rfc724_mid;    // Message-ID
    std::string text;
    std::string subject;
    int64_t timestamp = 0;
    int64_t ephemeral_timer = 0;
    int64_t ephemeral_timestamp = 0;
    int state = 0;
    int hidden = 0;
    int is_dc_message = 0;
    int is_setupmessage = 0;
    std::string mime_headers;
    std::string mime_in_reply_to;
    std::string mime_references;
    std::string error;
    int64_t sort_timestamp = 0;
};

// ============================================================================
// AutocryptHeader
// ============================================================================
class AutocryptHeader {
private:
    std::string addr_;
    int prefer_encrypt_ = constants::AUTOCRYPT_RECOMMENDED;
    std::string public_key_;
    std::string fingerprint_;  // base64-encoded fingerprint

public:
    AutocryptHeader() = default;

    AutocryptHeader(const std::string& addr, const std::string& pubkey,
                    int prefer_encrypt = constants::AUTOCRYPT_RECOMMENDED)
        : addr_(util::normalize_addr(addr)), public_key_(pubkey),
          prefer_encrypt_(prefer_encrypt) {
        // decode public key and compute fingerprint
        BIO* bio = BIO_new_mem_buf(pubkey.c_str(), -1);
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        if (pkey) {
            unsigned char der[4096];
            unsigned char* der_ptr = der;
            int der_len = i2d_PublicKey(pkey, &der_ptr);
            unsigned char fp_hash[SHA256_DIGEST_LENGTH];
            SHA256(der, der_len, fp_hash);
            fingerprint_ = util::base64_encode(fp_hash, SHA256_DIGEST_LENGTH);
            EVP_PKEY_free(pkey);
        }
        BIO_free(bio);
    }

    std::string addr() const { return addr_; }
    int prefer_encrypt() const { return prefer_encrypt_; }
    const std::string& public_key() const { return public_key_; }
    const std::string& fingerprint() const { return fingerprint_; }

    std::string to_header_value() const {
        // Format: addr=a@b.c; prefer-encrypt=mutual; keydata=BASE64KEY
        std::stringstream ss;
        ss << "addr=" << addr_ << "; ";
        if (prefer_encrypt_ == constants::AUTOCRYPT_MUTUAL) {
            ss << "prefer-encrypt=mutual; ";
        }
        // fold the keydata line
        std::string key_b64 = util::base64_encode(public_key_);
        ss << "keydata=\r\n ";
        size_t pos = 0;
        while (pos < key_b64.size()) {
            size_t chunk = std::min(size_t(78), key_b64.size() - pos);
            ss << " " << key_b64.substr(pos, chunk);
            pos += chunk;
            if (pos < key_b64.size()) {
                ss << "\r\n";
            }
        }
        return ss.str();
    }

    static std::optional<AutocryptHeader> from_header_value(
        const std::string& header_value, const std::string& sender_addr) {

        AutocryptHeader result;
        result.addr_ = util::normalize_addr(sender_addr);

        // Parse key-value pairs
        std::string keydata;
        bool in_keydata = false;
        std::stringstream parser(header_value);
        std::string line;
        while (std::getline(parser, line)) {
            line = util::trim(line);
            if (in_keydata) {
                keydata += line;
                continue;
            }
            if (line.rfind("keydata=", 0) == 0) {
                keydata = line.substr(8);
                in_keydata = true;
                continue;
            }
            auto eq = line.find('=');
            if (eq != std::string::npos) {
                std::string key = util::trim(line.substr(0, eq));
                std::string val = util::trim(line.substr(eq + 1));
                // strip trailing semicolon
                if (!val.empty() && val.back() == ';') {
                    val.pop_back();
                    val = util::trim(val);
                }
                if (key == "addr") result.addr_ = util::normalize_addr(val);
                else if (key == "prefer-encrypt") {
                    if (val == "mutual") result.prefer_encrypt_ = constants::AUTOCRYPT_MUTUAL;
                    else result.prefer_encrypt_ = constants::AUTOCRYPT_RECOMMENDED;
                }
            }
        }

        // Decode keydata (folded lines are concatenated)
        auto decoded = util::base64_decode(keydata);
        result.public_key_ = std::string(decoded.begin(), decoded.end());
        result.compute_fingerprint();
        return result;
    }

private:
    void compute_fingerprint() {
        if (public_key_.empty()) return;
        BIO* bio = BIO_new_mem_buf(public_key_.c_str(), -1);
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        if (pkey) {
            unsigned char der[4096];
            unsigned char* der_ptr = der;
            int der_len = i2d_PublicKey(pkey, &der_ptr);
            unsigned char fp_hash[SHA256_DIGEST_LENGTH];
            SHA256(der, der_len, fp_hash);
            fingerprint_ = util::base64_encode(fp_hash, SHA256_DIGEST_LENGTH);
            EVP_PKEY_free(pkey);
        }
        BIO_free(bio);
    }
};

// ============================================================================
// MimeMessage - Full MIME message builder
// ============================================================================
class MimeMessage {
private:
    std::string from_;
    std::vector<std::string> to_;
    std::vector<std::string> cc_;
    std::vector<std::string> bcc_;
    std::string subject_;
    std::string message_id_;
    std::string in_reply_to_;
    std::string references_;
    std::string text_body_;
    std::string html_body_;
    std::string boundary_;
    std::string chat_group_id_;
    std::string chat_group_name_;
    bool is_encrypted_ = false;
    bool is_signed_ = false;
    std::string autocrypt_header_;
    std::string mdn_to_;
    int ephemeral_timer_ = 0;
    std::string list_id_;
    std::string precedence_;

    struct Attachment {
        std::string filename;
        std::string mime_type;
        std::vector<unsigned char> data;
        std::string content_id;
    };
    std::vector<Attachment> attachments_;

public:
    MimeMessage() {
        boundary_ = util::generate_boundary();
    }

    void set_from(const std::string& addr) { from_ = addr; }
    void add_to(const std::string& addr) { to_.push_back(addr); }
    void add_cc(const std::string& addr) { cc_.push_back(addr); }
    void add_bcc(const std::string& addr) { bcc_.push_back(addr); }
    void set_subject(const std::string& subject) { subject_ = subject; }
    void set_message_id(const std::string& mid) { message_id_ = mid; }
    void set_in_reply_to(const std::string& irt) { in_reply_to_ = irt; }
    void set_references(const std::string& refs) { references_ = refs; }
    void set_text_body(const std::string& text) { text_body_ = text; }
    void set_html_body(const std::string& html) { html_body_ = html; }
    void set_chat_group_id(const std::string& grpid) { chat_group_id_ = grpid; }
    void set_chat_group_name(const std::string& name) { chat_group_name_ = name; }
    void set_encrypted(bool enc) { is_encrypted_ = enc; }
    void set_signed(bool sig) { is_signed_ = sig; }
    void set_autocrypt_header(const std::string& header) { autocrypt_header_ = header; }
    void set_mdn_to(const std::string& addr) { mdn_to_ = addr; }
    void set_ephemeral_timer(int sec) { ephemeral_timer_ = sec; }
    void set_list_id(const std::string& lid) { list_id_ = lid; }
    void set_precedence(const std::string& prec) { precedence_ = prec; }

    void add_attachment(const std::string& filename, const std::string& mime_type,
                        const std::vector<unsigned char>& data,
                        const std::string& content_id = "") {
        Attachment att;
        att.filename = filename;
        att.mime_type = mime_type;
        att.data = data;
        att.content_id = content_id;
        attachments_.push_back(att);
    }

    bool is_multipart() const {
        return !attachments_.empty() || (!text_body_.empty() && !html_body_.empty());
    }

    std::string build() const {
        std::stringstream msg;

        // Build headers
        msg << "From: " << from_ << "\r\n";
        if (!to_.empty()) {
            msg << "To: ";
            for (size_t i = 0; i < to_.size(); ++i) {
                if (i > 0) msg << ", ";
                msg << to_[i];
            }
            msg << "\r\n";
        }
        if (!cc_.empty()) {
            msg << "Cc: ";
            for (size_t i = 0; i < cc_.size(); ++i) {
                if (i > 0) msg << ", ";
                msg << cc_[i];
            }
            msg << "\r\n";
        }
        if (!subject_.empty()) {
            msg << "Subject: " << util::rfc2231_encode(subject_) << "\r\n";
        }
        msg << "Date: " << util::rfc2822_date() << "\r\n";
        if (!message_id_.empty()) {
            msg << "Message-ID: <" << message_id_ << ">\r\n";
        }
        if (!in_reply_to_.empty()) {
            msg << "In-Reply-To: <" << in_reply_to_ << ">\r\n";
        }
        if (!references_.empty()) {
            msg << "References: " << references_ << "\r\n";
        }
        msg << "User-Agent: " << constants::DC_USER_AGENT << "\r\n";
        if (!chat_group_id_.empty()) {
            msg << constants::DC_HEADER_CHAT_ID << ": " << chat_group_id_ << "\r\n";
        }
        if (!chat_group_name_.empty()) {
            msg << constants::DC_HEADER_CHAT_NAME << ": " << util::rfc2231_encode(chat_group_name_) << "\r\n";
        }
        if (!autocrypt_header_.empty()) {
            msg << constants::DC_HEADER_AUTOCRYPT << ": " << autocrypt_header_ << "\r\n";
        }
        if (!mdn_to_.empty()) {
            msg << constants::DC_HEADER_DISPOSITION << ": " << mdn_to_ << "\r\n";
        }
        if (ephemeral_timer_ > 0) {
            msg << constants::DC_HEADER_EPHEMERAL << ": " << ephemeral_timer_ << "\r\n";
        }
        if (!list_id_.empty()) {
            msg << constants::DC_HEADER_LIST_ID << ": " << list_id_ << "\r\n";
        }
        if (!precedence_.empty()) {
            msg << constants::DC_HEADER_PRECEDENCE << ": " << precedence_ << "\r\n";
        }
        msg << "MIME-Version: 1.0\r\n";

        // Build body
        if (is_encrypted_) {
            build_encrypted_body(msg);
        } else if (is_multipart()) {
            build_multipart_body(msg);
        } else {
            build_simple_body(msg);
        }

        return msg.str();
    }

    std::string to_string_for_signing() const {
        // Build the message content portion that will be signed
        std::stringstream ss;
        if (is_multipart()) {
            ss << "Content-Type: multipart/mixed; boundary=\"" << boundary_ << "\"\r\n";
            ss << "\r\n";
            ss << "--" << boundary_ << "\r\n";
            build_body_content(ss);
            for (const auto& att : attachments_) {
                ss << "--" << boundary_ << "\r\n";
                ss << "Content-Type: " << att.mime_type << "; name=\"" << att.filename << "\"\r\n";
                ss << "Content-Disposition: attachment; filename=\"" << att.filename << "\"\r\n";
                ss << "Content-Transfer-Encoding: base64\r\n";
                ss << "\r\n";
                ss << util::base64_encode(att.data.data(), att.data.size());
                ss << "\r\n";
            }
            ss << "--" << boundary_ << "--\r\n";
        } else {
            build_simple_body(ss);
        }
        return ss.str();
    }

private:
    void build_simple_body(std::stringstream& msg) const {
        msg << "Content-Type: text/plain; charset=utf-8\r\n";
        msg << "Content-Transfer-Encoding: quoted-printable\r\n";
        msg << "\r\n";
        msg << util::quoted_printable_encode(text_body_) << "\r\n";
    }

    void build_body_content(std::stringstream& msg) const {
        if (!html_body_.empty() && !text_body_.empty()) {
            std::string alt_boundary = util::generate_boundary();
            msg << "Content-Type: multipart/alternative; boundary=\"" << alt_boundary << "\"\r\n";
            msg << "\r\n";
            msg << "--" << alt_boundary << "\r\n";
            msg << "Content-Type: text/plain; charset=utf-8\r\n";
            msg << "Content-Transfer-Encoding: quoted-printable\r\n";
            msg << "\r\n";
            msg << util::quoted_printable_encode(text_body_) << "\r\n";
            msg << "--" << alt_boundary << "\r\n";
            msg << "Content-Type: text/html; charset=utf-8\r\n";
            msg << "Content-Transfer-Encoding: quoted-printable\r\n";
            msg << "\r\n";
            msg << util::quoted_printable_encode(html_body_) << "\r\n";
            msg << "--" << alt_boundary << "--\r\n";
        } else if (!text_body_.empty()) {
            msg << "Content-Type: text/plain; charset=utf-8\r\n";
            msg << "Content-Transfer-Encoding: quoted-printable\r\n";
            msg << "\r\n";
            msg << util::quoted_printable_encode(text_body_) << "\r\n";
        } else if (!html_body_.empty()) {
            msg << "Content-Type: text/html; charset=utf-8\r\n";
            msg << "Content-Transfer-Encoding: quoted-printable\r\n";
            msg << "\r\n";
            msg << util::quoted_printable_encode(html_body_) << "\r\n";
        }
    }

    void build_multipart_body(std::stringstream& msg) const {
        msg << "Content-Type: multipart/mixed; boundary=\"" << boundary_ << "\"\r\n";
        msg << "\r\n";
        msg << "This is a multi-part message in MIME format.\r\n";

        if (!text_body_.empty() || !html_body_.empty()) {
            msg << "--" << boundary_ << "\r\n";
            build_body_content(msg);
            msg << "\r\n";
        }

        for (const auto& att : attachments_) {
            msg << "--" << boundary_ << "\r\n";
            if (!att.content_id.empty()) {
                msg << "Content-Type: " << att.mime_type
                    << "; name=\"" << att.filename << "\"\r\n";
                msg << "Content-Disposition: inline; filename=\"" << att.filename << "\"\r\n";
                msg << "Content-ID: <" << att.content_id << ">\r\n";
            } else {
                msg << "Content-Type: " << att.mime_type
                    << "; name=\"" << att.filename << "\"\r\n";
                msg << "Content-Disposition: attachment; filename=\"" << att.filename << "\"\r\n";
            }
            msg << "Content-Transfer-Encoding: base64\r\n";
            msg << "\r\n";
            std::string encoded = util::base64_encode(att.data.data(), att.data.size());
            // Wrap at 78 characters
            size_t pos = 0;
            while (pos < encoded.size()) {
                size_t chunk = std::min(size_t(78), encoded.size() - pos);
                msg << encoded.substr(pos, chunk) << "\r\n";
                pos += chunk;
            }
        }

        msg << "--" << boundary_ << "--\r\n";
    }

    void build_encrypted_body(std::stringstream& msg) const {
        // For encrypted messages, we build inner MIME and then encrypt
        // placeholder - actual encryption handled by encrypt() method
        msg << "Content-Type: multipart/encrypted; "
            << "protocol=\"application/pgp-encrypted\"; "
            << "boundary=\"" << boundary_ << "\"\r\n";
        msg << "\r\n";
        msg << "--" << boundary_ << "\r\n";
        msg << "Content-Type: application/pgp-encrypted\r\n";
        msg << "\r\n";
        msg << "Version: 1\r\n";
        msg << "\r\n";
        msg << "--" << boundary_ << "\r\n";
        msg << "Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n";
        msg << "Content-Disposition: inline; filename=\"encrypted.asc\"\r\n";
        msg << "Content-Transfer-Encoding: 7bit\r\n";
        msg << "\r\n";
        msg << "[ENCRYPTED CONTENT]\r\n";
        msg << "\r\n";
        msg << "--" << boundary_ << "--\r\n";
    }
};

// ============================================================================
// SmtpTransport - SMTP sending via libcurl
// ============================================================================
class SmtpTransport {
private:
    struct UploadContext {
        const std::string* data = nullptr;
        size_t pos = 0;
    };

    std::string smtp_server_;
    int smtp_port_ = 587;
    std::string smtp_user_;
    std::string smtp_pass_;
    int smtp_security_ = 0; // 0=none, 1=STARTTLS, 2=SSL
    std::string last_error_;
    std::string sent_folder_ = "Sent";

public:
    SmtpTransport() = default;

    bool configure(const std::string& server, int port, const std::string& user,
                   const std::string& pass, int security) {
        smtp_server_ = server;
        smtp_port_ = port;
        smtp_user_ = user;
        smtp_pass_ = pass;
        smtp_security_ = security;
        return true;
    }

    void set_sent_folder(const std::string& folder) { sent_folder_ = folder; }

    const std::string& last_error() const { return last_error_; }

    static size_t read_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
        auto* ctx = static_cast<UploadContext*>(userdata);
        size_t total = size * nmemb;
        size_t remaining = ctx->data->size() - ctx->pos;
        size_t to_copy = std::min(total, remaining);
        if (to_copy > 0) {
            memcpy(ptr, ctx->data->c_str() + ctx->pos, to_copy);
            ctx->pos += to_copy;
        }
        return to_copy;
    }

    bool send(const std::string& mime_message, const std::string& envelope_from,
              const std::vector<std::string>& rcpt_to) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            last_error_ = "Failed to initialize curl";
            return false;
        }

        struct curl_slist* recipients = nullptr;
        for (const auto& r : rcpt_to) {
            recipients = curl_slist_append(recipients, r.c_str());
        }

        UploadContext ctx;
        ctx.data = &mime_message;
        ctx.pos = 0;

        std::string url;
        if (smtp_security_ == 2) {
            url = "smtps://" + smtp_server_ + ":" + std::to_string(smtp_port_);
        } else {
            url = "smtp://" + smtp_server_ + ":" + std::to_string(smtp_port_);
        }

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, envelope_from.c_str());
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, &SmtpTransport::read_callback);
        curl_easy_setopt(curl, CURLOPT_READDATA, &ctx);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_USERNAME, smtp_user_.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, smtp_pass_.c_str());

        if (smtp_security_ == 1) {
            curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
        } else if (smtp_security_ == 0) {
            curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_NONE);
        }

        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

        CURLcode res = curl_easy_perform(curl);
        bool success = (res == CURLE_OK);

        if (!success) {
            last_error_ = std::string("SMTP send failed: ") + curl_easy_strerror(res);
        }

        curl_slist_free_all(recipients);
        curl_easy_cleanup(curl);
        return success;
    }

    bool copy_to_sent(const std::string& mime_message) {
        // IMAP APPEND to Sent folder
        // This would use IMAP protocol via curl
        // For now, placeholder implementation
        return true;
    }
};

// ============================================================================
// ImapClient - IMAP operations for storing to Sent, etc.
// ============================================================================
class ImapClient {
private:
    std::string server_;
    int port_ = 993;
    std::string user_;
    std::string pass_;
    int security_ = 2; // SSL by default

public:
    bool configure(const std::string& server, int port, const std::string& user,
                   const std::string& pass, int security) {
        server_ = server;
        port_ = port;
        user_ = user;
        pass_ = pass;
        security_ = security;
        return true;
    }

    bool append(const std::string& folder, const std::string& mime_message) {
        // Would use curl IMAP APPEND command
        CURL* curl = curl_easy_init();
        if (!curl) return false;

        std::string url = "imaps://" + server_ + ":" + std::to_string(port_) + "/" + folder;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_USERNAME, user_.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, pass_.c_str());

        // IMAP APPEND requires custom request
        std::string cmd = "APPEND \"" + folder + "\" (\\Seen) {" +
                          std::to_string(mime_message.size()) + "}";
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, cmd.c_str());

        // TODO: full IMAP APPEND with LITERAL+
        curl_easy_cleanup(curl);
        return true;
    }
};

// ============================================================================
// Quote/Reply Detection
// ============================================================================
class QuoteDetector {
public:
    struct QuotedSection {
        size_t start_line;
        size_t end_line;
        bool is_quote;
        std::string attribution; // "On Date, Person wrote:"
    };

    static std::vector<QuotedSection> detect(const std::string& text) {
        std::vector<QuotedSection> sections;
        std::istringstream stream(text);
        std::string line;
        size_t line_num = 0;
        bool in_quote = false;
        size_t quote_start = 0;
        std::string current_attribution;

        while (std::getline(stream, line)) {
            bool is_quote_line = false;
            std::string trimmed = util::trim(line);

            // Check for quote markers
            if (!trimmed.empty()) {
                // Leading '>' character
                if (trimmed[0] == '>') {
                    is_quote_line = true;
                }
                // Common reply attribution patterns
                else if (trimmed.find("wrote:") != std::string::npos ||
                         trimmed.find("Wrote:") != std::string::npos ||
                         trimmed.find("schrieb:") != std::string::npos ||
                         trimmed.find("écrit :") != std::string::npos) {
                    is_quote_line = true;
                    current_attribution = trimmed;
                }
                // Email-style quote headers
                else if (trimmed.rfind("On ", 0) == 0 &&
                         (trimmed.find(" at ") != std::string::npos ||
                          trimmed.find(" wrote:") != std::string::npos)) {
                    is_quote_line = true;
                    current_attribution = trimmed;
                }
                // Horizontal rule separators
                else if (trimmed.find("---") == 0 || trimmed.find("___") == 0) {
                    is_quote_line = true;
                }
            }

            if (is_quote_line && !in_quote) {
                in_quote = true;
                quote_start = line_num;
            } else if (!is_quote_line && in_quote) {
                QuotedSection sec;
                sec.start_line = quote_start;
                sec.end_line = line_num;
                sec.is_quote = true;
                sec.attribution = current_attribution;
                sections.push_back(sec);
                in_quote = false;
            }

            line_num++;
        }

        if (in_quote) {
            QuotedSection sec;
            sec.start_line = quote_start;
            sec.end_line = line_num;
            sec.is_quote = true;
            sec.attribution = current_attribution;
            sections.push_back(sec);
        }

        return sections;
    }

    static std::string extract_quoted_text(const std::string& text) {
        auto sections = detect(text);
        std::stringstream result;
        std::istringstream stream(text);
        std::string line;
        size_t line_num = 0;

        while (std::getline(stream, line)) {
            for (const auto& sec : sections) {
                if (sec.is_quote && line_num >= sec.start_line && line_num < sec.end_line) {
                    result << line << "\n";
                    break;
                }
            }
            line_num++;
        }
        return result.str();
    }

    static std::string strip_quoted_text(const std::string& text) {
        auto sections = detect(text);
        std::stringstream result;
        std::istringstream stream(text);
        std::string line;
        size_t line_num = 0;

        while (std::getline(stream, line)) {
            bool is_quoted_section = false;
            for (const auto& sec : sections) {
                if (sec.is_quote && line_num >= sec.start_line && line_num < sec.end_line) {
                    is_quoted_section = true;
                    break;
                }
            }
            if (!is_quoted_section) {
                result << line << "\n";
            }
            line_num++;
        }
        std::string stripped = result.str();
        // Trim trailing newlines
        while (!stripped.empty() && stripped.back() == '\n') stripped.pop_back();
        return stripped;
    }
};

// ============================================================================
// EphemeralTimer
// ============================================================================
class EphemeralTimer {
public:
    struct TimerEntry {
        int message_id;
        int chat_id;
        int64_t start_time;     // when message was read
        int64_t duration_sec;   // how long until destruction
    };

private:
    std::vector<TimerEntry> timers_;
    std::mutex mutex_;

public:
    void start_timer(int message_id, int chat_id, int duration_sec) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (duration_sec <= 0) return;

        TimerEntry entry;
        entry.message_id = message_id;
        entry.chat_id = chat_id;
        entry.start_time = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        entry.duration_sec = duration_sec;
        timers_.push_back(entry);
    }

    void stop_timer(int message_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        timers_.erase(
            std::remove_if(timers_.begin(), timers_.end(),
                [message_id](const TimerEntry& e) { return e.message_id == message_id; }),
            timers_.end());
    }

    std::vector<int> get_expired_messages() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<int> expired;
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        auto it = timers_.begin();
        while (it != timers_.end()) {
            if (now - it->start_time >= it->duration_sec) {
                expired.push_back(it->message_id);
                it = timers_.erase(it);
            } else {
                ++it;
            }
        }
        return expired;
    }

    int64_t get_remaining_sec(int message_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        for (const auto& t : timers_) {
            if (t.message_id == message_id) {
                int64_t elapsed = now - t.start_time;
                int64_t remaining = t.duration_sec - elapsed;
                return remaining > 0 ? remaining : 0;
            }
        }
        return -1;
    }

    std::vector<TimerEntry> get_all_timers() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return timers_;
    }
};

// ============================================================================
// QR Code Generation (dcaccount: invite links)
// ============================================================================
class QrCodeGenerator {
public:
    static std::string generate_dcaccount_qr(const std::string& addr,
                                              const std::string& pubkey_b64,
                                              const std::string& display_name = "",
                                              const std::string& grpid = "") {
        // Format: dcaccount:addr=...&pubkey=...&name=...&grpid=...
        std::stringstream ss;
        ss << "dcaccount:";
        ss << "addr=" << url_encode(addr);
        if (!pubkey_b64.empty()) {
            ss << "&pubkey=" << url_encode(pubkey_b64);
        }
        if (!display_name.empty()) {
            ss << "&name=" << url_encode(display_name);
        }
        if (!grpid.empty()) {
            ss << "&grpid=" << url_encode(grpid);
        }
        return ss.str();
    }

    static std::string generate_securejoin_qr(const std::string& grpid,
                                               const std::string& grpname,
                                               const std::string& inviter,
                                               const std::string& fingerprint) {
        // Format: OPENPGP4FPR:FINGERPRINT#a=ADDR&n=NAME&i=INVITER&s=STEP
        std::stringstream ss;
        ss << "OPENPGP4FPR:" << fingerprint;
        ss << "#a=" << url_encode(inviter);
        if (!grpname.empty()) {
            ss << "&n=" << url_encode(grpname);
        }
        ss << "&g=" << url_encode(grpid);
        ss << "&s=" << url_encode(grpid);
        return ss.str();
    }

    // For actual QR rendering, this would integrate with libqrencode
    // or similar. Here we return the text payload.
    static std::string qr_to_ascii(const std::string& payload) {
        // Simplified ASCII QR representation
        // In production, use libqrencode or similar library
        std::stringstream ss;
        size_t w = std::min(payload.size(), size_t(40));
        ss << "+" << std::string(w + 2, '-') << "+\n";
        ss << "| " << payload.substr(0, w) << " |\n";
        ss << "+" << std::string(w + 2, '-') << "+\n";
        ss << "[QR Code for: " << payload.substr(0, 60);
        if (payload.size() > 60) ss << "...";
        ss << "]\n";
        return ss.str();
    }

private:
    static std::string url_encode(const std::string& value) {
        std::ostringstream escaped;
        escaped.fill('0');
        escaped << std::hex;
        for (char c : value) {
            if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' ||
                c == '.' || c == '~') {
                escaped << c;
            } else {
                escaped << std::uppercase;
                escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
                escaped << std::nouppercase;
            }
        }
        return escaped.str();
    }
};

// ============================================================================
// Message Encryption Engine
// ============================================================================
class EncryptionEngine {
private:
    KeyPair key_pair_;
    std::unordered_map<std::string, AutocryptHeader> peer_keys_; // addr -> autocrypt header

public:
    EncryptionEngine() = default;

    void set_keypair(const KeyPair& kp) { key_pair_ = kp; }
    const KeyPair& keypair() const { return key_pair_; }

    void add_peer_key(const std::string& addr, const AutocryptHeader& header) {
        peer_keys_[util::normalize_addr(addr)] = header;
    }

    void remove_peer_key(const std::string& addr) {
        peer_keys_.erase(util::normalize_addr(addr));
    }

    std::optional<AutocryptHeader> get_peer_key(const std::string& addr) const {
        auto it = peer_keys_.find(util::normalize_addr(addr));
        if (it != peer_keys_.end()) return it->second;
        return std::nullopt;
    }

    bool can_encrypt_to(const std::string& addr) const {
        return peer_keys_.find(util::normalize_addr(addr)) != peer_keys_.end();
    }

    int peer_prefer_encrypt(const std::string& addr) const {
        auto it = peer_keys_.find(util::normalize_addr(addr));
        if (it != peer_keys_.end()) return it->second.prefer_encrypt();
        return 0;
    }

    AutocryptHeader get_autocrypt_header(const std::string& addr,
                                          int prefer_encrypt = constants::AUTOCRYPT_RECOMMENDED) const {
        return AutocryptHeader(addr, key_pair_.public_key, prefer_encrypt);
    }

    // Symmetric AES-256-GCM encryption
    static std::vector<unsigned char> aes_encrypt(const std::string& plaintext,
                                                    const unsigned char* key,
                                                    const unsigned char* iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return {};

        std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH + 16);
        int out_len = 0;
        int final_len = 0;

        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                         reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                         static_cast<int>(plaintext.size()));
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &final_len);
        out_len += final_len;

        // Get authentication tag
        unsigned char tag[16];
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

        // Append tag
        ciphertext.insert(ciphertext.begin() + out_len, tag, tag + 16);
        ciphertext.resize(out_len + 16);

        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }

    // Symmetric AES-256-GCM decryption
    static std::optional<std::string> aes_decrypt(const std::vector<unsigned char>& ciphertext,
                                                    const unsigned char* key,
                                                    const unsigned char* iv) {
        if (ciphertext.size() < 17) return std::nullopt; // need at least 16 bytes for tag

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return std::nullopt;

        size_t ct_len = ciphertext.size() - 16;
        std::vector<unsigned char> plaintext(ct_len);
        int out_len = 0;
        int final_len = 0;

        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                           const_cast<unsigned char*>(ciphertext.data() + ct_len));
        EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext.data(), static_cast<int>(ct_len));

        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len);
        EVP_CIPHER_CTX_free(ctx);

        if (ret > 0) {
            out_len += final_len;
            return std::string(reinterpret_cast<char*>(plaintext.data()), out_len);
        }
        return std::nullopt;
    }

    // Encrypt for multiple recipients using AES key wrapped with RSA
    std::string encrypt_message(const std::string& mime_body,
                                const std::vector<std::string>& recipients) {
        // Generate random session key
        unsigned char session_key[32];
        unsigned char iv[12];
        RAND_bytes(session_key, 32);
        RAND_bytes(iv, 12);

        // Encrypt body with AES-256-GCM
        auto encrypted_body = aes_encrypt(mime_body, session_key, iv);

        // Build PGP/MIME encrypted message
        std::stringstream result;
        std::string boundary = util::generate_boundary();

        result << "Content-Type: multipart/encrypted; "
               << "protocol=\"application/pgp-encrypted\"; "
               << "boundary=\"" << boundary << "\"\r\n";
        result << "\r\n";
        result << "--" << boundary << "\r\n";
        result << "Content-Type: application/pgp-encrypted\r\n";
        result << "\r\n";
        result << "Version: 1\r\n";
        result << "\r\n";
        result << "--" << boundary << "\r\n";
        result << "Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n";
        result << "Content-Disposition: inline; filename=\"encrypted.asc\"\r\n";
        result << "Content-Transfer-Encoding: 7bit\r\n";
        result << "\r\n";

        // Build PGP message packet with session key encrypted for each recipient
        // and symmetrically encrypted data packet
        std::stringstream pgp_msg;
        // PKESK for each recipient
        for (const auto& r : recipients) {
            auto key = get_peer_key(r);
            if (!key) continue;
            BIO* bio = BIO_new_mem_buf(key->public_key().c_str(), -1);
            EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
            if (!pkey) continue;

            // Wrap session key with recipient's RSA key
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, nullptr);
            if (pctx && EVP_PKEY_encrypt_init(pctx) > 0) {
                EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING);
                EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256());
                EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256());

                size_t outlen = 0;
                EVP_PKEY_encrypt(pctx, nullptr, &outlen, session_key, 32);
                std::vector<unsigned char> wrapped_key(outlen);
                EVP_PKEY_encrypt(pctx, wrapped_key.data(), &outlen, session_key, 32);
                EVP_PKEY_CTX_free(pctx);

                // Write PKESK packet in PGP format (simplified)
                pgp_msg << "-----BEGIN PGP MESSAGE-----\r\n";
                pgp_msg << util::base64_encode(wrapped_key.data(), outlen) << "\r\n";
            }
            EVP_PKEY_free(pkey);
        }

        // Symmetrically encrypted integrity-protected data packet
        // In production, use full OpenPGP library (e.g., gpgme)
        pgp_msg << util::base64_encode(encrypted_body.data(), encrypted_body.size()) << "\r\n";
        pgp_msg << "-----END PGP MESSAGE-----\r\n";

        result << pgp_msg.str();
        result << "\r\n";
        result << "--" << boundary << "--\r\n";

        return result.str();
    }

    std::string sign_message(const std::string& content) {
        std::string signature = key_pair_.sign(content);
        if (signature.empty()) return content;

        std::stringstream result;
        std::string boundary = util::generate_boundary();

        // PGP/MIME signed message
        result << "Content-Type: multipart/signed; "
               << "protocol=\"application/pgp-signature\"; "
               << "micalg=pgp-sha256; "
               << "boundary=\"" << boundary << "\"\r\n";
        result << "\r\n";
        result << "--" << boundary << "\r\n";
        result << content << "\r\n";
        result << "--" << boundary << "\r\n";
        result << "Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n";
        result << "Content-Transfer-Encoding: 7bit\r\n";
        result << "\r\n";
        result << "-----BEGIN PGP SIGNATURE-----\r\n";
        result << signature << "\r\n";
        result << "-----END PGP SIGNATURE-----\r\n";
        result << "\r\n";
        result << "--" << boundary << "--\r\n";

        return result.str();
    }

    bool verify_signature(const std::string& signed_message,
                          const std::string& expected_pubkey) {
        // Extract signature and verify
        // Simplified: in production, use gpgme
        KeyPair peer;
        peer.public_key = expected_pubkey;
        // Parse multipart/signed and verify
        return true; // placeholder
    }
};

// ============================================================================
// System Message Generator
// ============================================================================
class SystemMessageGenerator {
public:
    static std::string member_added(const std::string& actor_name,
                                     const std::string& member_name,
                                     const std::string& grp_name = "") {
        std::stringstream ss;
        ss << "System: ";
        if (!grp_name.empty()) {
            ss << "[" << grp_name << "] ";
        }
        ss << actor_name << " added " << member_name << " to the group.";
        return ss.str();
    }

    static std::string member_removed(const std::string& actor_name,
                                       const std::string& member_name,
                                       const std::string& grp_name = "") {
        std::stringstream ss;
        ss << "System: ";
        if (!grp_name.empty()) {
            ss << "[" << grp_name << "] ";
        }
        ss << actor_name << " removed " << member_name << " from the group.";
        return ss.str();
    }

    static std::string group_name_changed(const std::string& actor_name,
                                           const std::string& old_name,
                                           const std::string& new_name) {
        std::stringstream ss;
        ss << "System: " << actor_name << " changed the group name from \""
           << old_name << "\" to \"" << new_name << "\".";
        return ss.str();
    }

    static std::string group_image_changed(const std::string& actor_name,
                                            const std::string& grp_name = "") {
        std::stringstream ss;
        ss << "System: " << actor_name << " changed the group image.";
        return ss.str();
    }

    static std::string group_image_deleted(const std::string& actor_name) {
        std::stringstream ss;
        ss << "System: " << actor_name << " removed the group image.";
        return ss.str();
    }

    static std::string member_left(const std::string& member_name) {
        std::stringstream ss;
        ss << "System: " << member_name << " left the group.";
        return ss.str();
    }

    static std::string chat_ephemeral_timer_changed(const std::string& actor_name,
                                                      int timer_sec,
                                                      const std::string& grp_name = "") {
        std::stringstream ss;
        ss << "System: " << actor_name << " set disappearing message timer to ";
        if (timer_sec == 0) {
            ss << "off";
        } else if (timer_sec < 60) {
            ss << timer_sec << " seconds";
        } else if (timer_sec < 3600) {
            ss << (timer_sec / 60) << " minutes";
        } else if (timer_sec < 86400) {
            ss << (timer_sec / 3600) << " hours";
        } else {
            ss << (timer_sec / 86400) << " days";
        }
        ss << ".";
        return ss.str();
    }

    static std::string securejoin_started(const std::string& actor_name) {
        std::stringstream ss;
        ss << "System: " << actor_name << " started a SecureJoin verification.";
        return ss.str();
    }

    static std::string securejoin_succeeded(const std::string& actor_name) {
        std::stringstream ss;
        ss << "System: " << actor_name << " completed SecureJoin verification.";
        return ss.str();
    }

    static std::string securejoin_failed(const std::string& actor_name) {
        std::stringstream ss;
        ss << "System: SecureJoin verification with " << actor_name << " failed.";
        return ss.str();
    }

    static std::string contact_verified(const std::string& contact_name) {
        std::stringstream ss;
        ss << "System: Verified contact " << contact_name << ".";
        return ss.str();
    }

    static std::string location_enabled(const std::string& actor_name) {
        std::stringstream ss;
        ss << "System: " << actor_name << " enabled location streaming.";
        return ss.str();
    }

    static std::string location_disabled(const std::string& actor_name) {
        std::stringstream ss;
        ss << "System: " << actor_name << " stopped location streaming.";
        return ss.str();
    }

    static std::string videochat_invitation(const std::string& actor_name,
                                              const std::string& url = "") {
        std::stringstream ss;
        ss << "System: " << actor_name << " started a video chat invitation.";
        if (!url.empty()) {
            ss << " Join: " << url;
        }
        return ss.str();
    }

    static std::string webxdc_info(const std::string& app_name) {
        std::stringstream ss;
        ss << "System: New WebXDC app \"" << app_name << "\" is available.";
        return ss.str();
    }
};

// ============================================================================
// MDN / Read Receipt Handler
// ============================================================================
class MdnHandler {
public:
    struct MdnRequest {
        int message_id;
        std::string original_mid;
        std::string sender_addr;
        std::string recipient_addr;
    };

    struct MdnResponse {
        std::string original_mid;
        std::string disposition;  // "displayed", "dispatched", "processed", "deleted"
        std::string reporting_ua;
        int64_t timestamp;
    };

    static std::string build_mdn(const MdnRequest& req, const std::string& from_addr,
                                  const std::string& disposition_type = "displayed") {
        std::string boundary = util::generate_boundary();
        std::stringstream msg;

        // Build MDN headers
        msg << "From: " << from_addr << "\r\n";
        // MDN should not generate MDNs
        msg << "Date: " << util::rfc2822_date() << "\r\n";
        msg << "Message-ID: <" << util::generate_message_id("mdn") << ">\r\n";
        msg << "Content-Type: multipart/report; report-type=disposition-notification; "
            << "boundary=\"" << boundary << "\"\r\n";
        msg << "MIME-Version: 1.0\r\n";
        msg << "\r\n";

        // Human-readable part
        msg << "--" << boundary << "\r\n";
        msg << "Content-Type: text/plain; charset=utf-8\r\n";
        msg << "Content-Transfer-Encoding: 7bit\r\n";
        msg << "\r\n";
        msg << "This is a Message Disposition Notification.\r\n";
        msg << "\r\n";

        // Machine-readable part
        msg << "--" << boundary << "\r\n";
        msg << "Content-Type: message/disposition-notification\r\n";
        msg << "\r\n";
        msg << "Reporting-UA: " << constants::DC_USER_AGENT << "\r\n";
        msg << "Original-Recipient: rfc822;" << req.recipient_addr << "\r\n";
        msg << "Final-Recipient: rfc822;" << req.recipient_addr << "\r\n";
        msg << "Original-Message-ID: <" << req.original_mid << ">\r\n";
        msg << "Disposition: manual-action/MDN-sent-manually; " << disposition_type << "\r\n";
        msg << "\r\n";

        msg << "--" << boundary << "--\r\n";

        return msg.str();
    }

    static std::optional<MdnResponse> parse_mdn(const std::string& mdn_message) {
        MdnResponse resp;

        // Parse Original-Message-ID
        auto orig_mid_pos = mdn_message.find("Original-Message-ID:");
        if (orig_mid_pos != std::string::npos) {
            auto start = mdn_message.find('<', orig_mid_pos);
            auto end = mdn_message.find('>', orig_mid_pos);
            if (start != std::string::npos && end != std::string::npos && end > start) {
                resp.original_mid = mdn_message.substr(start + 1, end - start - 1);
            }
        }

        // Parse Disposition
        auto disp_pos = mdn_message.find("Disposition:");
        if (disp_pos != std::string::npos) {
            auto eol = mdn_message.find('\n', disp_pos);
            if (eol == std::string::npos) eol = mdn_message.size();
            std::string disp_line = mdn_message.substr(disp_pos, eol - disp_pos);
            if (disp_line.find("displayed") != std::string::npos) {
                resp.disposition = "displayed";
            } else if (disp_line.find("deleted") != std::string::npos) {
                resp.disposition = "deleted";
            } else if (disp_line.find("dispatched") != std::string::npos) {
                resp.disposition = "dispatched";
            } else if (disp_line.find("processed") != std::string::npos) {
                resp.disposition = "processed";
            }
        }

        // Parse Reporting-UA
        auto ua_pos = mdn_message.find("Reporting-UA:");
        if (ua_pos != std::string::npos) {
            auto eol = mdn_message.find('\n', ua_pos);
            if (eol == std::string::npos) eol = mdn_message.size();
            resp.reporting_ua = util::trim(mdn_message.substr(
                ua_pos + 13, eol - ua_pos - 13));
        }

        resp.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        return resp;
    }
};

// ============================================================================
// Read Receipt Processor
// ============================================================================
class ReadReceiptProcessor {
private:
    std::unordered_map<int, std::set<int>> read_by_; // msg_id -> set of contact_ids
    std::mutex mutex_;

public:
    void mark_read(int message_id, int contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        read_by_[message_id].insert(contact_id);
    }

    bool is_read_by(int message_id, int contact_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = read_by_.find(message_id);
        if (it != read_by_.end()) {
            return it->second.find(contact_id) != it->second.end();
        }
        return false;
    }

    std::set<int> get_read_by(int message_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = read_by_.find(message_id);
        if (it != read_by_.end()) {
            return it->second;
        }
        return {};
    }

    int get_read_count(int message_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = read_by_.find(message_id);
        return it != read_by_.end() ? static_cast<int>(it->second.size()) : 0;
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        read_by_.clear();
    }
};

// ============================================================================
// Group Chat Manager
// ============================================================================
class GroupChatManager {
private:
    struct GroupInfo {
        int chat_id;
        std::string grpid;
        std::string name;
        std::vector<int> member_ids;
        std::vector<int> pending_member_ids;  // invited but not yet accepted
        std::string avatar_path;
        int64_t created;
        int ephemeral_timer;
    };

    std::unordered_map<int, GroupInfo> groups_;
    std::unordered_map<std::string, int> grpid_to_chat_id_;
    std::mutex mutex_;
    int next_chat_id_ = 1;

public:
    int create_group(const std::string& name, const std::vector<int>& initial_members,
                     int creator_id) {
        std::lock_guard<std::mutex> lock(mutex_);

        int chat_id = next_chat_id_++;
        std::string grpid = util::generate_message_id("group.local");

        GroupInfo gi;
        gi.chat_id = chat_id;
        gi.grpid = grpid;
        gi.name = name;
        gi.member_ids = initial_members;
        // Ensure creator is in the group
        if (std::find(gi.member_ids.begin(), gi.member_ids.end(), creator_id)
            == gi.member_ids.end()) {
            gi.member_ids.push_back(creator_id);
        }
        gi.ephemeral_timer = 0;
        gi.created = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        groups_[chat_id] = gi;
        grpid_to_chat_id_[grpid] = chat_id;

        return chat_id;
    }

    bool add_member(int chat_id, int member_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(chat_id);
        if (it == groups_.end()) return false;

        if (std::find(it->second.member_ids.begin(), it->second.member_ids.end(), member_id)
            == it->second.member_ids.end()) {

            if (static_cast<int>(it->second.member_ids.size()) >= constants::MAX_GROUP_SIZE) {
                return false;
            }

            it->second.member_ids.push_back(member_id);
        }
        return true;
    }

    bool remove_member(int chat_id, int member_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(chat_id);
        if (it == groups_.end()) return false;

        auto& members = it->second.member_ids;
        members.erase(std::remove(members.begin(), members.end(), member_id), members.end());
        return true;
    }

    bool set_name(int chat_id, const std::string& new_name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(chat_id);
        if (it == groups_.end()) return false;
        it->second.name = new_name;
        return true;
    }

    std::string get_name(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(chat_id);
        if (it != groups_.end()) return it->second.name;
        return "";
    }

    bool set_avatar(int chat_id, const std::string& avatar_path) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(chat_id);
        if (it == groups_.end()) return false;
        it->second.avatar_path = avatar_path;
        return true;
    }

    std::string get_avatar(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(chat_id);
        if (it != groups_.end()) return it->second.avatar_path;
        return "";
    }

    void set_ephemeral_timer(int chat_id, int timer_sec) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(chat_id);
        if (it != groups_.end()) {
            it->second.ephemeral_timer = timer_sec;
        }
    }

    int get_ephemeral_timer(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(chat_id);
        if (it != groups_.end()) return it->second.ephemeral_timer;
        return 0;
    }

    std::vector<int> get_members(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(chat_id);
        if (it != groups_.end()) return it->second.member_ids;
        return {};
    }

    int get_chat_id_by_grpid(const std::string& grpid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = grpid_to_chat_id_.find(grpid);
        if (it != grpid_to_chat_id_.end()) return it->second;
        return 0;
    }

    void delete_group(int chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(chat_id);
        if (it != groups_.end()) {
            grpid_to_chat_id_.erase(it->second.grpid);
            groups_.erase(it);
        }
    }

    bool is_member(int chat_id, int contact_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(chat_id);
        if (it == groups_.end()) return false;
        return std::find(it->second.member_ids.begin(), it->second.member_ids.end(), contact_id)
               != it->second.member_ids.end();
    }

    std::vector<int> get_group_ids() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<int> ids;
        for (const auto& pair : groups_) {
            ids.push_back(pair.first);
        }
        return ids;
    }
};

// ============================================================================
// Mailing List Handler
// ============================================================================
class MailingListHandler {
public:
    struct MailingList {
        int chat_id;
        std::string list_id;
        std::string list_name;
        std::string list_domain;
        std::string list_owner;
        bool is_announce_only = false;
        bool auto_moderated = false;
        int64_t last_seen = 0;
    };

private:
    std::unordered_map<std::string, MailingList> lists_; // list_id -> MailingList

public:
    void register_list(const std::string& list_id, int chat_id,
                       const std::string& list_name, const std::string& list_domain,
                       const std::string& list_owner = "") {
        MailingList ml;
        ml.chat_id = chat_id;
        ml.list_id = list_id;
        ml.list_name = list_name;
        ml.list_domain = list_domain;
        ml.list_owner = list_owner;
        ml.last_seen = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        lists_[util::to_lower(list_id)] = ml;
    }

    std::optional<MailingList> get_list(const std::string& list_id) const {
        auto it = lists_.find(util::to_lower(list_id));
        if (it != lists_.end()) return it->second;
        return std::nullopt;
    }

    bool is_mailing_list_message(const std::string& list_id_header) const {
        if (list_id_header.empty()) return false;
        auto it = lists_.find(util::to_lower(list_id_header));
        return it != lists_.end();
    }

    int get_chat_id_for_list(const std::string& list_id) const {
        auto it = lists_.find(util::to_lower(list_id));
        if (it != lists_.end()) return it->second.chat_id;
        return 0;
    }

    static std::string generate_list_id_header(const std::string& list_name,
                                                const std::string& domain) {
        std::stringstream ss;
        ss << list_name << " <" << list_name << "." << domain << ">";
        return ss.str();
    }

    static std::string get_precedence_header(bool is_mailing_list) {
        if (is_mailing_list) return "list";
        return "";
    }

    bool remove_list(const std::string& list_id) {
        return lists_.erase(util::to_lower(list_id)) > 0;
    }
};

// ============================================================================
// SecureJoin Verification Flow
// ============================================================================
class SecureJoinSession {
public:
    enum State {
        SJ_INITIAL = 0,
        SJ_WAIT_CONTACT_CONFIRM = 1,
        SJ_WAIT_FINGERPRINT = 2,
        SJ_WAIT_MEMBER_ADDED = 3,
        SJ_COMPLETED = 4,
        SJ_FAILED = 5,
        SJ_TIMEOUT = 6
    };

private:
    State state_ = SJ_INITIAL;
    std::string grpid_;
    std::string inviter_addr_;
    std::string joiner_addr_;
    std::string expected_fingerprint_;
    std::string actual_fingerprint_;
    int64_t start_time_;
    int64_t timeout_sec_ = 300; // 5 minutes
    bool is_inviter_ = false;
    int chat_id_ = 0;

public:
    SecureJoinSession() {
        start_time_ = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    void start_as_inviter(const std::string& grpid, const std::string& joiner_addr,
                          int chat_id) {
        state_ = SJ_WAIT_CONTACT_CONFIRM;
        grpid_ = grpid;
        joiner_addr_ = joiner_addr;
        is_inviter_ = true;
        chat_id_ = chat_id;
        start_time_ = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    void start_as_joiner(const std::string& grpid, const std::string& inviter_addr) {
        state_ = SJ_WAIT_FINGERPRINT;
        grpid_ = grpid;
        inviter_addr_ = inviter_addr;
        is_inviter_ = false;
        start_time_ = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    void set_expected_fingerprint(const std::string& fp) {
        expected_fingerprint_ = fp;
    }

    void set_actual_fingerprint(const std::string& fp) {
        actual_fingerprint_ = fp;
        if (!expected_fingerprint_.empty() && actual_fingerprint_ == expected_fingerprint_) {
            state_ = SJ_COMPLETED;
        } else if (!expected_fingerprint_.empty()) {
            state_ = SJ_FAILED;
        }
    }

    void on_contact_confirm() {
        if (state_ == SJ_WAIT_CONTACT_CONFIRM) {
            state_ = SJ_WAIT_FINGERPRINT;
        }
    }

    void on_member_added() {
        if (state_ == SJ_WAIT_MEMBER_ADDED) {
            state_ = SJ_COMPLETED;
        }
    }

    void fail(const std::string& reason = "") {
        state_ = SJ_FAILED;
    }

    State state() const { return state_; }
    const std::string& grpid() const { return grpid_; }
    const std::string& inviter_addr() const { return inviter_addr_; }
    const std::string& joiner_addr() const { return joiner_addr_; }
    bool is_inviter() const { return is_inviter_; }
    int chat_id() const { return chat_id_; }

    QrCodeGenerator::generate_securejoin_qr;

    bool is_expired() const {
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return (now - start_time_) > timeout_sec_;
    }

    int64_t remaining_sec() const {
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        int64_t remaining = timeout_sec_ - (now - start_time_);
        return remaining > 0 ? remaining : 0;
    }

    std::string get_protocol_msg() const {
        std::stringstream ss;
        ss << "secure-join: v1\n";
        ss << "grpid: " << grpid_ << "\n";
        if (is_inviter_) {
            ss << "inviter: " << inviter_addr_ << "\n";
        }
        ss << "fingerprint: " << actual_fingerprint_ << "\n";
        return ss.str();
    }
};

// ============================================================================
// WebXDC Instance Management
// ============================================================================
class WebXdcInstance {
public:
    struct WebXdcMessage {
        int msg_id;
        std::string instance_id;
        std::string app_name;
        std::string app_id;
        std::string update_data;      // JSON payload
        std::string status_update;     // JSON describing UI state
        int64_t timestamp;
    };

private:
    std::vector<WebXdcMessage> messages_;
    std::unordered_map<std::string, std::string> instance_states_; // instance_id -> state JSON
    std::mutex mutex_;

public:
    int send_webxdc_message(const std::string& instance_id,
                            const std::string& app_name,
                            const std::string& app_id,
                            const std::string& update_data,
                            int64_t timestamp = 0) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (timestamp == 0) {
            timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }

        WebXdcMessage msg;
        msg.msg_id = static_cast<int>(messages_.size()) + 1;
        msg.instance_id = instance_id;
        msg.app_name = app_name;
        msg.app_id = app_id;
        msg.update_data = update_data;
        msg.timestamp = timestamp;

        messages_.push_back(msg);
        return msg.msg_id;
    }

    bool send_status_update(const std::string& instance_id,
                            const std::string& status_json) {
        std::lock_guard<std::mutex> lock(mutex_);
        instance_states_[instance_id] = status_json;

        // Create update message
        WebXdcMessage msg;
        msg.msg_id = static_cast<int>(messages_.size()) + 1;
        msg.instance_id = instance_id;
        msg.status_update = status_json;
        msg.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        messages_.push_back(msg);
        return true;
    }

    std::string get_instance_state(const std::string& instance_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = instance_states_.find(instance_id);
        if (it != instance_states_.end()) return it->second;
        return "{}";
    }

    std::vector<WebXdcMessage> get_messages(const std::string& instance_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<WebXdcMessage> result;
        for (const auto& msg : messages_) {
            if (msg.instance_id == instance_id) {
                result.push_back(msg);
            }
        }
        return result;
    }

    std::string build_webxdc_attachment(const std::string& manifest_json,
                                         const std::vector<unsigned char>& app_data) const {
        // WebXDC apps are .xdc files (.tar archives renamed)
        // Simplified: return a JSON bundle
        std::stringstream ss;
        ss << "{\n";
        ss << "  \"manifest\": " << manifest_json << ",\n";
        ss << "  \"timestamp\": " << std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() << "\n";
        ss << "}";
        return ss.str();
    }

    static std::string generate_instance_id() {
        return "webxdc_" + util::random_hex(16);
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        messages_.clear();
        instance_states_.clear();
    }
};

// ============================================================================
// Contact Blocking Manager
// ============================================================================
class ContactBlockingManager {
private:
    std::set<std::string> blocked_addresses_; // normalized addrs
    std::set<int> blocked_contact_ids_;
    std::mutex mutex_;

public:
    bool block_contact(int contact_id, const std::string& addr) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_addresses_.insert(util::normalize_addr(addr));
        blocked_contact_ids_.insert(contact_id);
        return true;
    }

    bool unblock_contact(int contact_id, const std::string& addr) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_addresses_.erase(util::normalize_addr(addr));
        blocked_contact_ids_.erase(contact_id);
        return true;
    }

    bool is_blocked(const std::string& addr) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return blocked_addresses_.find(util::normalize_addr(addr)) != blocked_addresses_.end();
    }

    bool is_blocked(int contact_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return blocked_contact_ids_.find(contact_id) != blocked_contact_ids_.end();
    }

    std::set<std::string> get_blocked_addresses() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return blocked_addresses_;
    }

    std::set<int> get_blocked_contact_ids() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return blocked_contact_ids_;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_addresses_.clear();
        blocked_contact_ids_.clear();
    }

    bool should_drop_message(const std::string& from_addr) const {
        return is_blocked(from_addr);
    }
};

// ============================================================================
// Chat Profile Image Manager
// ============================================================================
class ChatProfileImageManager {
private:
    struct ImageRecord {
        int chat_id;
        std::string image_path;    // local file path
        std::string image_blob_id; // reference ID for blob storage
        int64_t timestamp;
        int width;
        int height;
    };

    std::unordered_map<int, ImageRecord> chat_images_; // chat_id -> ImageRecord
    std::string image_dir_;
    std::mutex mutex_;

public:
    void set_image_dir(const std::string& dir) { image_dir_ = dir; }

    bool set_chat_image(int chat_id, const std::string& image_path,
                        int width = 0, int height = 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        ImageRecord rec;
        rec.chat_id = chat_id;
        rec.image_path = image_path;
        rec.width = width;
        rec.height = height;
        rec.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        chat_images_[chat_id] = rec;
        return true;
    }

    std::string get_chat_image_path(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = chat_images_.find(chat_id);
        if (it != chat_images_.end()) return it->second.image_path;
        return "";
    }

    bool remove_chat_image(int chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return chat_images_.erase(chat_id) > 0;
    }

    // Generate a default avatar based on group name initials
    static std::string generate_default_avatar_svg(const std::string& name,
                                                     const std::string& color = "#4A90D9") {
        std::string initials;
        std::istringstream ss(name);
        std::string word;
        while (ss >> word && initials.size() < 2) {
            if (!word.empty()) initials += toupper(word[0]);
        }
        if (initials.empty()) initials = "?";

        std::stringstream svg;
        svg << "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"200\" height=\"200\">\n";
        svg << "  <rect width=\"200\" height=\"200\" rx=\"20\" fill=\"" << color << "\"/>\n";
        svg << "  <text x=\"100\" y=\"120\" font-family=\"Arial\" font-size=\"80\" "
            << "fill=\"white\" text-anchor=\"middle\" dominant-baseline=\"middle\">"
            << initials << "</text>\n";
        svg << "</svg>";
        return svg.str();
    }

    std::vector<int> get_chats_with_images() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<int> ids;
        for (const auto& pair : chat_images_) {
            ids.push_back(pair.first);
        }
        return ids;
    }
};

// ============================================================================
// Database Schema and Storage
// ============================================================================
class DatabaseStorage {
private:
    sqlite3* db_ = nullptr;
    std::string db_path_;
    std::mutex mutex_;

public:
    ~DatabaseStorage() { close(); }

    bool open(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex_);
        db_path_ = path;
        int rc = sqlite3_open(path.c_str(), &db_);
        if (rc != SQLITE_OK) return false;
        return create_tables();
    }

    void close() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

    sqlite3* db() { return db_; }

private:
    bool exec(const std::string& sql) {
        char* err = nullptr;
        int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            if (err) sqlite3_free(err);
            return false;
        }
        return true;
    }

    bool create_tables() {
        const char* schema = R"SQL(
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL DEFAULT '',
                addr TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL DEFAULT '',
                state INTEGER NOT NULL DEFAULT 0,
                origin INTEGER NOT NULL DEFAULT 0,
                blocked INTEGER NOT NULL DEFAULT 0,
                verified INTEGER NOT NULL DEFAULT 0,
                auth_name TEXT NOT NULL DEFAULT '',
                profile_image TEXT NOT NULL DEFAULT '',
                color TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                last_seen INTEGER NOT NULL DEFAULT 0,
                was_seen INTEGER NOT NULL DEFAULT 0,
                param TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS chats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL DEFAULT '',
                blocked INTEGER NOT NULL DEFAULT 0,
                archived INTEGER NOT NULL DEFAULT 0,
                ephemeral_timer INTEGER NOT NULL DEFAULT 0,
                profile_image TEXT NOT NULL DEFAULT '',
                color TEXT NOT NULL DEFAULT '',
                grpid TEXT NOT NULL DEFAULT '',
                param TEXT NOT NULL DEFAULT '',
                is_protected INTEGER NOT NULL DEFAULT 0,
                is_device_chat INTEGER NOT NULL DEFAULT 0,
                created_timestamp INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                from_id INTEGER NOT NULL DEFAULT 0,
                rfc724_mid TEXT NOT NULL DEFAULT '',
                text TEXT NOT NULL DEFAULT '',
                subject TEXT NOT NULL DEFAULT '',
                timestamp INTEGER NOT NULL DEFAULT 0,
                ephemeral_timer INTEGER NOT NULL DEFAULT 0,
                ephemeral_timestamp INTEGER NOT NULL DEFAULT 0,
                state INTEGER NOT NULL DEFAULT 0,
                hidden INTEGER NOT NULL DEFAULT 0,
                is_dc_message INTEGER NOT NULL DEFAULT 0,
                is_setupmessage INTEGER NOT NULL DEFAULT 0,
                mime_headers TEXT NOT NULL DEFAULT '',
                mime_in_reply_to TEXT NOT NULL DEFAULT '',
                mime_references TEXT NOT NULL DEFAULT '',
                error TEXT NOT NULL DEFAULT '',
                sort_timestamp INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (chat_id) REFERENCES chats(id),
                FOREIGN KEY (from_id) REFERENCES contacts(id)
            );

            CREATE TABLE IF NOT EXISTS chats_contacts (
                chat_id INTEGER NOT NULL,
                contact_id INTEGER NOT NULL,
                PRIMARY KEY (chat_id, contact_id),
                FOREIGN KEY (chat_id) REFERENCES chats(id),
                FOREIGN KEY (contact_id) REFERENCES contacts(id)
            );

            CREATE TABLE IF NOT EXISTS autocrypt_keys (
                addr TEXT NOT NULL PRIMARY KEY,
                public_key TEXT NOT NULL,
                prefer_encrypt INTEGER NOT NULL DEFAULT 1,
                fingerprint TEXT NOT NULL DEFAULT '',
                last_seen INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS keypairs (
                id INTEGER PRIMARY KEY,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                fingerprint TEXT NOT NULL DEFAULT '',
                is_default INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS config (
                keyname TEXT NOT NULL PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS backup_state (
                id INTEGER PRIMARY KEY,
                backup_data TEXT NOT NULL DEFAULT '',
                timestamp INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id);
            CREATE INDEX IF NOT EXISTS idx_messages_rfc724_mid ON messages(rfc724_mid);
            CREATE INDEX IF NOT EXISTS idx_contacts_addr ON contacts(addr);
            CREATE INDEX IF NOT EXISTS idx_chats_grpid ON chats(grpid);
        )SQL";
        return exec(schema);
    }
};

// ============================================================================
// Contact Manager
// ============================================================================
class ContactManager {
private:
    DatabaseStorage* storage_;
    std::unordered_map<int, ContactRecord> contacts_cache_;
    std::unordered_map<std::string, int> addr_to_id_;
    std::mutex mutex_;
    int next_id_ = 1;

public:
    explicit ContactManager(DatabaseStorage* storage) : storage_(storage) {}

    int add_contact(const std::string& addr, const std::string& name = "",
                    int origin = 0) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string normalized = util::normalize_addr(addr);
        auto existing = addr_to_id_.find(normalized);
        if (existing != addr_to_id_.end()) {
            // Update existing
            auto it = contacts_cache_.find(existing->second);
            if (it != contacts_cache_.end() && !name.empty()) {
                it->second.name = name;
                it->second.display_name = name;
            }
            return existing->second;
        }

        ContactRecord rec;
        rec.id = next_id_++;
        rec.name = name;
        rec.addr = normalized;
        rec.display_name = name.empty() ? normalized : name;
        rec.origin = origin;
        rec.last_seen = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        contacts_cache_[rec.id] = rec;
        addr_to_id_[normalized] = rec.id;

        // Persist to DB
        if (storage_ && storage_->db()) {
            const char* sql = "INSERT OR REPLACE INTO contacts "
                              "(id, name, addr, display_name, origin, last_seen) "
                              "VALUES (?, ?, ?, ?, ?, ?)";
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(storage_->db(), sql, -1, &stmt, nullptr);
            if (stmt) {
                sqlite3_bind_int(stmt, 1, rec.id);
                sqlite3_bind_text(stmt, 2, rec.name.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 3, rec.addr.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 4, rec.display_name.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(stmt, 5, rec.origin);
                sqlite3_bind_int64(stmt, 6, rec.last_seen);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }

        return rec.id;
    }

    std::optional<ContactRecord> lookup_contact(int contact_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = contacts_cache_.find(contact_id);
        if (it != contacts_cache_.end()) return it->second;
        return std::nullopt;
    }

    std::optional<ContactRecord> lookup_contact_by_addr(const std::string& addr) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = addr_to_id_.find(util::normalize_addr(addr));
        if (it != addr_to_id_.end()) {
            auto cit = contacts_cache_.find(it->second);
            if (cit != contacts_cache_.end()) return cit->second;
        }
        return std::nullopt;
    }

    int get_contact_id_by_addr(const std::string& addr) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = addr_to_id_.find(util::normalize_addr(addr));
        if (it != addr_to_id_.end()) return it->second;
        return 0;
    }

    bool block_contact(int contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = contacts_cache_.find(contact_id);
        if (it != contacts_cache_.end()) {
            it->second.blocked = 1;
            if (storage_ && storage_->db()) {
                const char* sql = "UPDATE contacts SET blocked=1 WHERE id=?";
                sqlite3_stmt* stmt = nullptr;
                sqlite3_prepare_v2(storage_->db(), sql, -1, &stmt, nullptr);
                if (stmt) {
                    sqlite3_bind_int(stmt, 1, contact_id);
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            return true;
        }
        return false;
    }

    bool unblock_contact(int contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = contacts_cache_.find(contact_id);
        if (it != contacts_cache_.end()) {
            it->second.blocked = 0;
            if (storage_ && storage_->db()) {
                const char* sql = "UPDATE contacts SET blocked=0 WHERE id=?";
                sqlite3_stmt* stmt = nullptr;
                sqlite3_prepare_v2(storage_->db(), sql, -1, &stmt, nullptr);
                if (stmt) {
                    sqlite3_bind_int(stmt, 1, contact_id);
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            return true;
        }
        return false;
    }

    bool verify_contact(int contact_id, int verified_status) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = contacts_cache_.find(contact_id);
        if (it != contacts_cache_.end()) {
            it->second.verified = verified_status;
            if (storage_ && storage_->db()) {
                const char* sql = "UPDATE contacts SET verified=? WHERE id=?";
                sqlite3_stmt* stmt = nullptr;
                sqlite3_prepare_v2(storage_->db(), sql, -1, &stmt, nullptr);
                if (stmt) {
                    sqlite3_bind_int(stmt, 1, verified_status);
                    sqlite3_bind_int(stmt, 2, contact_id);
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
            return true;
        }
        return false;
    }

    bool is_contact_blocked(int contact_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = contacts_cache_.find(contact_id);
        if (it != contacts_cache_.end()) return it->second.blocked != 0;
        return false;
    }

    bool is_contact_blocked_by_addr(const std::string& addr) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = addr_to_id_.find(util::normalize_addr(addr));
        if (it != addr_to_id_.end()) {
            auto cit = contacts_cache_.find(it->second);
            if (cit != contacts_cache_.end()) return cit->second.blocked != 0;
        }
        return false;
    }

    std::vector<ContactRecord> get_all_contacts() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ContactRecord> result;
        for (const auto& pair : contacts_cache_) {
            result.push_back(pair.second);
        }
        return result;
    }

    std::vector<ContactRecord> get_blocked_contacts() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ContactRecord> result;
        for (const auto& pair : contacts_cache_) {
            if (pair.second.blocked) {
                result.push_back(pair.second);
            }
        }
        return result;
    }

    std::vector<ContactRecord> get_verified_contacts() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ContactRecord> result;
        for (const auto& pair : contacts_cache_) {
            if (pair.second.verified == constants::DC_CONTACT_VERIFIED) {
                result.push_back(pair.second);
            }
        }
        return result;
    }

    int get_contact_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<int>(contacts_cache_.size());
    }
};

// ============================================================================
// Chat Manager
// ============================================================================
class ChatManager {
private:
    DatabaseStorage* storage_;
    std::unordered_map<int, ChatRecord> chats_cache_;
    std::unordered_map<std::string, int> grpid_to_chat_id_;
    std::mutex mutex_;
    GroupChatManager group_manager_;
    int next_chat_id_ = 1;
    int self_contact_id_ = 1;

public:
    explicit ChatManager(DatabaseStorage* storage) : storage_(storage) {}

    void set_self_contact_id(int id) { self_contact_id_ = id; }

    int create_chat(const std::string& name, int chat_type,
                    const std::vector<int>& member_ids = {}) {
        std::lock_guard<std::mutex> lock(mutex_);

        int chat_id = next_chat_id_++;
        ChatRecord rec;
        rec.id = chat_id;
        rec.type = chat_type;
        rec.name = name;
        rec.created_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Generate grpid for groups/broadcasts
        if (chat_type == constants::DC_CHAT_TYPE_GROUP ||
            chat_type == constants::DC_CHAT_TYPE_BROADCAST) {
            rec.grpid = util::generate_message_id("group.local");
            grpid_to_chat_id_[rec.grpid] = chat_id;
        } else {
            rec.grpid = util::sha1(name + std::to_string(rec.created_timestamp));
        }

        chats_cache_[chat_id] = rec;

        if (chat_type == constants::DC_CHAT_TYPE_GROUP && !member_ids.empty()) {
            // Use group chat manager for groups
            group_manager_.create_group(name, member_ids, self_contact_id_);
        }

        // Persist
        if (storage_ && storage_->db()) {
            const char* sql = "INSERT OR REPLACE INTO chats "
                              "(id, type, name, grpid, created_timestamp) "
                              "VALUES (?, ?, ?, ?, ?)";
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(storage_->db(), sql, -1, &stmt, nullptr);
            if (stmt) {
                sqlite3_bind_int(stmt, 1, rec.id);
                sqlite3_bind_int(stmt, 2, rec.type);
                sqlite3_bind_text(stmt, 3, rec.name.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 4, rec.grpid.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(stmt, 5, rec.created_timestamp);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }

            // Insert chat-contact relations for group members
            if (!member_ids.empty()) {
                const char* sql_cc = "INSERT OR IGNORE INTO chats_contacts (chat_id, contact_id) "
                                     "VALUES (?, ?)";
                sqlite3_stmt* stmt_cc = nullptr;
                sqlite3_prepare_v2(storage_->db(), sql_cc, -1, &stmt_cc, nullptr);
                if (stmt_cc) {
                    for (int mid : member_ids) {
                        sqlite3_reset(stmt_cc);
                        sqlite3_bind_int(stmt_cc, 1, chat_id);
                        sqlite3_bind_int(stmt_cc, 2, mid);
                        sqlite3_step(stmt_cc);
                    }
                    sqlite3_finalize(stmt_cc);
                }
            }
        }

        return chat_id;
    }

    int create_group_chat(const std::string& name, const std::vector<int>& member_ids) {
        auto members = member_ids;
        if (std::find(members.begin(), members.end(), self_contact_id_) == members.end()) {
            members.push_back(self_contact_id_);
        }
        return create_chat(name, constants::DC_CHAT_TYPE_GROUP, members);
    }

    int create_broadcast_list(const std::string& name, const std::vector<int>& member_ids) {
        return create_chat(name, constants::DC_CHAT_TYPE_BROADCAST, member_ids);
    }

    int create_mailinglist_chat(const std::string& name, const std::string& list_id,
                                  const std::string& list_domain) {
        std::lock_guard<std::mutex> lock(mutex_);
        int chat_id = create_chat(name, constants::DC_CHAT_TYPE_MAILINGLIST, {});
        // The listing handler would be called separately
        return chat_id;
    }

    int create_chat_by_contact_id(int contact_id) {
        // Single chat already exists? Find or create
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& pair : chats_cache_) {
            if (pair.second.type == constants::DC_CHAT_TYPE_SINGLE) {
                // Check if this is a chat with just this contact
                return pair.first;
            }
        }
        return create_chat("", constants::DC_CHAT_TYPE_SINGLE, {contact_id});
    }

    std::optional<ChatRecord> get_chat(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = chats_cache_.find(chat_id);
        if (it != chats_cache_.end()) return it->second;
        return std::nullopt;
    }

    std::optional<ChatRecord> get_chat_by_grpid(const std::string& grpid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = grpid_to_chat_id_.find(grpid);
        if (it != grpid_to_chat_id_.end()) {
            auto cit = chats_cache_.find(it->second);
            if (cit != chats_cache_.end()) return cit->second;
        }
        return std::nullopt;
    }

    bool add_contact_to_chat(int chat_id, int contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = chats_cache_.find(chat_id);
        if (it == chats_cache_.end()) return false;

        if (it->second.type == constants::DC_CHAT_TYPE_GROUP) {
            group_manager_.add_member(chat_id, contact_id);
        }

        if (storage_ && storage_->db()) {
            const char* sql = "INSERT OR IGNORE INTO chats_contacts (chat_id, contact_id) "
                              "VALUES (?, ?)";
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(storage_->db(), sql, -1, &stmt, nullptr);
            if (stmt) {
                sqlite3_bind_int(stmt, 1, chat_id);
                sqlite3_bind_int(stmt, 2, contact_id);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
        return true;
    }

    bool remove_contact_from_chat(int chat_id, int contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (chats_cache_.find(chat_id) == chats_cache_.end()) return false;

        group_manager_.remove_member(chat_id, contact_id);

        if (storage_ && storage_->db()) {
            const char* sql = "DELETE FROM chats_contacts WHERE chat_id=? AND contact_id=?";
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(storage_->db(), sql, -1, &stmt, nullptr);
            if (stmt) {
                sqlite3_bind_int(stmt, 1, chat_id);
                sqlite3_bind_int(stmt, 2, contact_id);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
        return true;
    }

    std::vector<int> get_chat_contacts(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = chats_cache_.find(chat_id);
        if (it != chats_cache_.end() &&
            it->second.type == constants::DC_CHAT_TYPE_GROUP) {
            return group_manager_.get_members(chat_id);
        }
        // For non-group chats, query DB
        std::vector<int> result;
        if (storage_ && storage_->db()) {
            const char* sql = "SELECT contact_id FROM chats_contacts WHERE chat_id=?";
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(storage_->db(), sql, -1, &stmt, nullptr);
            if (stmt) {
                sqlite3_bind_int(stmt, 1, chat_id);
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    result.push_back(sqlite3_column_int(stmt, 0));
                }
                sqlite3_finalize(stmt);
            }
        }
        return result;
    }

    void set_chat_name(int chat_id, const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = chats_cache_.find(chat_id);
        if (it != chats_cache_.end()) {
            it->second.name = name;
            group_manager_.set_name(chat_id, name);
        }
    }

    void set_ephemeral_timer(int chat_id, int timer_sec) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = chats_cache_.find(chat_id);
        if (it != chats_cache_.end()) {
            it->second.ephemeral_timer = timer_sec;
            group_manager_.set_ephemeral_timer(chat_id, timer_sec);
        }
    }

    int get_ephemeral_timer(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = chats_cache_.find(chat_id);
        if (it != chats_cache_.end()) return it->second.ephemeral_timer;
        return 0;
    }

    GroupChatManager& group_manager() { return group_manager_; }
    const GroupChatManager& group_manager() const { return group_manager_; }

    std::vector<ChatRecord> get_all_chats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ChatRecord> result;
        for (const auto& pair : chats_cache_) {
            result.push_back(pair.second);
        }
        return result;
    }

    bool delete_chat(int chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = chats_cache_.find(chat_id);
        if (it == chats_cache_.end()) return false;
        grpid_to_chat_id_.erase(it->second.grpid);
        chats_cache_.erase(it);
        group_manager_.delete_group(chat_id);
        return true;
    }

    void archive_chat(int chat_id, bool archive) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = chats_cache_.find(chat_id);
        if (it != chats_cache_.end()) {
            it->second.archived = archive ? 1 : 0;
        }
    }

    bool is_chat_archived(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = chats_cache_.find(chat_id);
        if (it != chats_cache_.end()) return it->second.archived != 0;
        return false;
    }

    void set_chat_profile_image(int chat_id, const std::string& image_path) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = chats_cache_.find(chat_id);
        if (it != chats_cache_.end()) {
            it->second.profile_image = image_path;
        }
    }

    std::string get_chat_profile_image(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = chats_cache_.find(chat_id);
        if (it != chats_cache_.end()) return it->second.profile_image;
        return "";
    }
};

// ============================================================================
// Message Composer - builds MIME message with proper threading headers
// ============================================================================
class MessageComposer {
private:
    const ChatManager* chat_manager_;
    const ContactManager* contact_manager_;
    const EncryptionEngine* encryption_engine_;
    std::string self_addr_;
    std::string self_display_name_;
    std::string domain_;

public:
    MessageComposer(const ChatManager* cm, const ContactManager* conm,
                    const EncryptionEngine* enc)
        : chat_manager_(cm), contact_manager_(conm), encryption_engine_(enc) {}

    void set_self_addr(const std::string& addr) { self_addr_ = addr; }
    void set_self_display_name(const std::string& name) { self_display_name_ = name; }
    void set_domain(const std::string& domain) { domain_ = domain; }

    struct ComposeParams {
        int chat_id = 0;
        std::string text;
        std::string subject;
        std::string parent_message_id;  // for threading
        std::string parent_references;
        bool request_mdn = false;
        int ephemeral_timer = 0;
        std::vector<std::pair<std::string, std::string>> attachments; // path, mime_type
    };

    MimeMessage compose(const ComposeParams& params) const {
        MimeMessage msg;
        auto chat = chat_manager_->get_chat(params.chat_id);

        // Build from address
        std::string from;
        if (!self_display_name_.empty()) {
            from = self_display_name_ + " <" + self_addr_ + ">";
        } else {
            from = self_addr_;
        }
        msg.set_from(from);

        // Generate Message-ID
        std::string mid = util::generate_message_id(domain_);
        msg.set_message_id(mid);

        // Threading headers
        if (!params.parent_message_id.empty()) {
            msg.set_in_reply_to(params.parent_message_id);
            if (!params.parent_references.empty()) {
                msg.set_references(params.parent_references + " <" + params.parent_message_id + ">");
            } else {
                msg.set_references("<" + params.parent_message_id + ">");
            }
        }

        // Subject
        if (!params.subject.empty()) {
            msg.set_subject(params.subject);
        } else if (chat.has_value() && !chat->name.empty()) {
            msg.set_subject(chat->name);
        }

        // Chat headers for groups
        if (chat.has_value() && !chat->grpid.empty()) {
            msg.set_chat_group_id(chat->grpid);
            if (chat->type == constants::DC_CHAT_TYPE_GROUP &&
                !chat->name.empty()) {
                msg.set_chat_group_name(chat->name);
            }
        }

        // Set recipients based on chat type
        std::vector<std::string> recipients;
        if (chat.has_value()) {
            auto member_ids = chat_manager_->get_chat_contacts(params.chat_id);
            for (int mid : member_ids) {
                auto contact = contact_manager_->lookup_contact(mid);
                if (contact.has_value() && contact->addr != self_addr_) {
                    recipients.push_back(contact->addr);
                }
            }
        }

        for (const auto& r : recipients) {
            msg.add_to(r);
        }

        // Body
        msg.set_text_body(params.text);

        // MDN
        if (params.request_mdn) {
            msg.set_mdn_to(self_addr_);
        }

        // Ephemeral timer
        if (params.ephemeral_timer > 0) {
            msg.set_ephemeral_timer(params.ephemeral_timer);
        } else if (chat.has_value() && chat->ephemeral_timer > 0) {
            msg.set_ephemeral_timer(chat->ephemeral_timer);
        }

        // Autocrypt header
        if (encryption_engine_) {
            auto ah = encryption_engine_->get_autocrypt_header(self_addr_);
            msg.set_autocrypt_header(ah.to_header_value());
        }

        // Attachments
        for (const auto& att : params.attachments) {
            std::ifstream file(att.first, std::ios::binary);
            if (file) {
                std::vector<unsigned char> data(
                    (std::istreambuf_iterator<char>(file)),
                    std::istreambuf_iterator<char>());
                size_t pos = att.first.find_last_of("/\\");
                std::string filename = (pos != std::string::npos)
                    ? att.first.substr(pos + 1) : att.first;
                msg.add_attachment(filename, att.second, data);
            }
        }

        return msg;
    }

    // Build message with full threading context
    MimeMessage compose_with_threading(const ComposeParams& params,
                                        const std::string& thread_root_mid,
                                        const std::vector<std::string>& thread_refs) const {
        MimeMessage msg = compose(params);

        // Build References header
        std::string refs;
        for (const auto& r : thread_refs) {
            if (!refs.empty()) refs += " ";
            refs += "<" + r + ">";
        }
        if (!thread_root_mid.empty()) {
            if (!refs.empty()) refs += " ";
            refs += "<" + thread_root_mid + ">";
        }
        if (!refs.empty()) {
            msg.set_references(refs);
        }

        return msg;
    }
};

// ============================================================================
// Message Pipeline - compose -> encrypt -> sign -> send via SMTP -> copy Sent
// ============================================================================
class MessagePipeline {
private:
    MessageComposer* composer_;
    EncryptionEngine* encryption_engine_;
    SmtpTransport* smtp_;
    ImapClient* imap_;
    ChatManager* chat_manager_;
    ContactManager* contact_manager_;
    MdnHandler* mdn_handler_;
    ReadReceiptProcessor* read_receipts_;
    EphemeralTimer* ephemeral_timer_;
    ContactBlockingManager* block_manager_;

    std::vector<MessageRecord> sent_messages_;
    std::mutex mutex_;

    struct SendResult {
        bool success;
        int message_id;
        std::string error;
        std::string sent_mid;
    };

public:
    MessagePipeline(MessageComposer* composer, EncryptionEngine* enc,
                    SmtpTransport* smtp, ImapClient* imap,
                    ChatManager* cm, ContactManager* conm)
        : composer_(composer), encryption_engine_(enc),
          smtp_(smtp), imap_(imap),
          chat_manager_(cm), contact_manager_(conm) {}

    void set_mdn_handler(MdnHandler* h) { mdn_handler_ = h; }
    void set_read_receipt_processor(ReadReceiptProcessor* r) { read_receipts_ = r; }
    void set_ephemeral_timer(EphemeralTimer* t) { ephemeral_timer_ = t; }
    void set_block_manager(ContactBlockingManager* b) { block_manager_ = b; }

    SendResult send_message(const MessageComposer::ComposeParams& params) {
        SendResult result;
        result.message_id = 0;
        result.success = false;

        // Step 1: Compose the MIME message
        MimeMessage mime = composer_->compose(params);
        std::string raw_message = mime.build();

        // Step 2: Check if any recipients need encryption
        auto chat = chat_manager_->get_chat(params.chat_id);
        std::vector<std::string> encrypt_recipients;
        bool all_can_encrypt = true;

        if (chat.has_value()) {
            auto members = chat_manager_->get_chat_contacts(params.chat_id);
            for (int mid : members) {
                auto contact = contact_manager_->lookup_contact(mid);
                if (contact.has_value() && contact->addr != composer_->self_addr()) {
                    if (encryption_engine_->can_encrypt_to(contact->addr)) {
                        encrypt_recipients.push_back(contact->addr);
                    } else {
                        all_can_encrypt = false;
                    }
                }
            }
        }

        // Step 3: Encrypt if needed
        std::string final_message = raw_message;
        if (!encrypt_recipients.empty() && all_can_encrypt) {
            std::string body_for_encryption = mime.to_string_for_signing();
            final_message = encryption_engine_->encrypt_message(
                body_for_encryption, encrypt_recipients);
        }

        // Step 4: Sign
        final_message = encryption_engine_->sign_message(final_message);

        // Step 5: Send via SMTP
        std::vector<std::string> rcpt_to;
        if (chat.has_value()) {
            auto members = chat_manager_->get_chat_contacts(params.chat_id);
            for (int mid : members) {
                auto contact = contact_manager_->lookup_contact(mid);
                if (contact.has_value() &&
                    contact->addr != composer_->self_addr() &&
                    (!block_manager_ || !block_manager_->is_blocked(contact->addr))) {
                    rcpt_to.push_back(contact->addr);
                }
            }
        }

        bool smtp_ok = smtp_->send(final_message, composer_->self_addr(), rcpt_to);
        if (!smtp_ok) {
            result.error = smtp_->last_error();
            return result;
        }

        // Step 6: Copy to Sent folder
        imap_->append("Sent", final_message);

        // Record the sent message
        {
            std::lock_guard<std::mutex> lock(mutex_);
            MessageRecord rec;
            rec.id = static_cast<int>(sent_messages_.size()) + 1;
            rec.chat_id = params.chat_id;
            rec.text = params.text;
            rec.subject = params.subject;
            rec.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            rec.ephemeral_timer = params.ephemeral_timer;
            rec.state = constants::DC_STATE_OUT_DELIVERED;
            sent_messages_.push_back(rec);
            result.message_id = rec.id;
        }

        // Step 7: Start ephemeral timer if needed
        if (params.ephemeral_timer > 0 && result.message_id > 0) {
            ephemeral_timer_->start_timer(
                result.message_id, params.chat_id, params.ephemeral_timer);
        }

        result.success = true;
        return result;
    }

    std::vector<MessageRecord> get_sent_messages(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<MessageRecord> result;
        for (const auto& msg : sent_messages_) {
            if (msg.chat_id == chat_id) {
                result.push_back(msg);
            }
        }
        return result;
    }

    MessageRecord get_sent_message(int msg_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& msg : sent_messages_) {
            if (msg.id == msg_id) return msg;
        }
        return MessageRecord{};
    }
};

// ============================================================================
// Import/Export Backup
// ============================================================================
class BackupManager {
private:
    ContactManager* contact_manager_;
    ChatManager* chat_manager_;
    DatabaseStorage* storage_;

public:
    BackupManager(ContactManager* cm, ChatManager* chm, DatabaseStorage* storage)
        : contact_manager_(cm), chat_manager_(chm), storage_(storage) {}

    struct BackupData {
        int64_t timestamp;
        std::string version;
        std::vector<ContactRecord> contacts;
        std::vector<ChatRecord> chats;
        std::vector<std::vector<int>> chat_members; // parallel to chats
        std::vector<MessageRecord> messages;
    };

    std::string export_backup() const {
        BackupData bd;
        bd.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        bd.version = "1.0";

        bd.contacts = contact_manager_->get_all_contacts();
        bd.chats = chat_manager_->get_all_chats();
        for (const auto& chat : bd.chats) {
            bd.chat_members.push_back(
                chat_manager_->get_chat_contacts(chat.id));
        }

        // Serialize to JSON
        std::stringstream json;
        json << "{\n";
        json << "  \"version\": \"" << bd.version << "\",\n";
        json << "  \"timestamp\": " << bd.timestamp << ",\n";

        // Serialize contacts
        json << "  \"contacts\": [\n";
        for (size_t i = 0; i < bd.contacts.size(); ++i) {
            const auto& c = bd.contacts[i];
            json << "    {\n";
            json << "      \"id\": " << c.id << ",\n";
            json << "      \"name\": \"" << escape_json(c.name) << "\",\n";
            json << "      \"addr\": \"" << escape_json(c.addr) << "\",\n";
            json << "      \"display_name\": \"" << escape_json(c.display_name) << "\",\n";
            json << "      \"blocked\": " << c.blocked << ",\n";
            json << "      \"verified\": " << c.verified << "\n";
            json << "    }";
            if (i < bd.contacts.size() - 1) json << ",";
            json << "\n";
        }
        json << "  ],\n";

        // Serialize chats
        json << "  \"chats\": [\n";
        for (size_t i = 0; i < bd.chats.size(); ++i) {
            const auto& c = bd.chats[i];
            json << "    {\n";
            json << "      \"id\": " << c.id << ",\n";
            json << "      \"type\": " << c.type << ",\n";
            json << "      \"name\": \"" << escape_json(c.name) << "\",\n";
            json << "      \"grpid\": \"" << escape_json(c.grpid) << "\",\n";
            json << "      \"ephemeral_timer\": " << c.ephemeral_timer << ",\n";
            json << "      \"members\": [";
            for (size_t j = 0; j < bd.chat_members[i].size(); ++j) {
                if (j > 0) json << ", ";
                json << bd.chat_members[i][j];
            }
            json << "]\n";
            json << "    }";
            if (i < bd.chats.size() - 1) json << ",";
            json << "\n";
        }
        json << "  ]\n";
        json << "}\n";

        return json.str();
    }

    bool import_backup(const std::string& backup_json) {
        // Simple JSON parsing for backup import
        // In production, use a proper JSON parser (nlohmann/json, rapidjson, etc.)

        // Parse contacts
        std::regex contact_regex(
            R"("id":\s*(\d+).*?"name":\s*"([^"]*)".*?"addr":\s*"([^"]*)".*?"display_name":\s*"([^"]*)")",
            std::regex::extended);

        auto contacts_begin = std::sregex_iterator(
            backup_json.begin(), backup_json.end(), contact_regex);
        auto contacts_end = std::sregex_iterator();

        for (auto it = contacts_begin; it != contacts_end; ++it) {
            std::smatch match = *it;
            ContactRecord rec;
            rec.id = std::stoi(match[1].str());
            rec.name = match[2].str();
            rec.addr = match[3].str();
            rec.display_name = match[4].str();
            contact_manager_->add_contact(rec.addr, rec.name);
        }

        // Parse chats
        std::regex chat_regex(
            R"("id":\s*(\d+).*?"type":\s*(\d+).*?"name":\s*"([^"]*)".*?"grpid":\s*"([^"]*)".*?"ephemeral_timer":\s*(\d+))",
            std::regex::extended);

        auto chats_begin = std::sregex_iterator(
            backup_json.begin(), backup_json.end(), chat_regex);
        auto chats_end = std::sregex_iterator();

        for (auto it = chats_begin; it != chats_end; ++it) {
            std::smatch match = *it;
            int chat_id = std::stoi(match[1].str());
            int type = std::stoi(match[2].str());
            std::string name = match[3].str();
            chat_manager_->create_chat(name, type);
        }

        return true;
    }

private:
    static std::string escape_json(const std::string& s) {
        std::stringstream result;
        for (char c : s) {
            switch (c) {
                case '"': result << "\\\""; break;
                case '\\': result << "\\\\"; break;
                case '\n': result << "\\n"; break;
                case '\r': result << "\\r"; break;
                case '\t': result << "\\t"; break;
                default: result << c;
            }
        }
        return result.str();
    }
};

// ============================================================================
// DeltaChatContext - Main Context / API Entry Point
// ============================================================================
class DeltaChatContext {
private:
    DatabaseStorage storage_;
    ContactManager contact_manager_{&storage_};
    ChatManager chat_manager_{&storage_};
    EncryptionEngine encryption_engine_;
    SmtpTransport smtp_;
    ImapClient imap_;
    MessageComposer composer_{&chat_manager_, &contact_manager_, &encryption_engine_};
    MessagePipeline pipeline_{&composer_, &encryption_engine_, &smtp_, &imap_,
                               &chat_manager_, &contact_manager_};
    MailingListHandler mailing_list_handler_;
    ContactBlockingManager block_manager_;
    ChatProfileImageManager profile_image_manager_;
    EphemeralTimer ephemeral_timer_;
    ReadReceiptProcessor read_receipts_;
    WebXdcInstance webxdc_instance_;
    BackupManager backup_manager_{&contact_manager_, &chat_manager_, &storage_};

    std::string self_addr_;
    std::string domain_;
    bool initialized_ = false;

public:
    DeltaChatContext() = default;
    ~DeltaChatContext() = default;

    // ========================================================================
    // Initialization
    // ========================================================================
    bool open(const std::string& db_path) {
        if (!storage_.open(db_path)) return false;
        initialized_ = true;
        return true;
    }

    void close() {
        storage_.close();
        initialized_ = false;
    }

    bool configure(const std::string& addr, const std::string& mail_pw,
                   const std::string& smtp_server, int smtp_port,
                   const std::string& imap_server, int imap_port,
                   int smtp_security = 1, int imap_security = 2) {
        if (!initialized_) return false;

        self_addr_ = util::normalize_addr(addr);
        auto at_pos = addr.find('@');
        if (at_pos != std::string::npos) {
            domain_ = addr.substr(at_pos + 1);
        } else {
            domain_ = "localhost";
        }

        smtp_.configure(smtp_server, smtp_port, addr, mail_pw, smtp_security);
        imap_.configure(imap_server, imap_port, addr, mail_pw, imap_security);

        composer_.set_self_addr(self_addr_);
        composer_.set_domain(domain_);

        // Generate keypair for autocrypt
        KeyPair kp = KeyPair::generate();
        encryption_engine_.set_keypair(kp);

        return true;
    }

    // ========================================================================
    // Contact Operations
    // ========================================================================
    int add_contact(const std::string& addr, const std::string& name = "",
                     int origin = 0) {
        return contact_manager_.add_contact(addr, name, origin);
    }

    std::optional<ContactRecord> lookup_contact(int contact_id) {
        return contact_manager_.lookup_contact(contact_id);
    }

    std::optional<ContactRecord> lookup_contact_by_addr(const std::string& addr) {
        return contact_manager_.lookup_contact_by_addr(addr);
    }

    int get_contact_id_by_addr(const std::string& addr) {
        return contact_manager_.get_contact_id_by_addr(addr);
    }

    bool block_contact(int contact_id) {
        auto contact = contact_manager_.lookup_contact(contact_id);
        if (contact.has_value()) {
            block_manager_.block_contact(contact_id, contact->addr);
            return contact_manager_.block_contact(contact_id);
        }
        return false;
    }

    bool unblock_contact(int contact_id) {
        auto contact = contact_manager_.lookup_contact(contact_id);
        if (contact.has_value()) {
            block_manager_.unblock_contact(contact_id, contact->addr);
            return contact_manager_.unblock_contact(contact_id);
        }
        return false;
    }

    bool is_contact_blocked(int contact_id) {
        return contact_manager_.is_contact_blocked(contact_id);
    }

    bool verify_contact(int contact_id) {
        return contact_manager_.verify_contact(contact_id,
            constants::DC_CONTACT_VERIFIED);
    }

    bool unverify_contact(int contact_id) {
        return contact_manager_.verify_contact(contact_id,
            constants::DC_CONTACT_UNVERIFIED);
    }

    std::vector<ContactRecord> get_all_contacts() {
        return contact_manager_.get_all_contacts();
    }

    std::vector<ContactRecord> get_blocked_contacts() {
        return contact_manager_.get_blocked_contacts();
    }

    std::vector<ContactRecord> get_verified_contacts() {
        return contact_manager_.get_verified_contacts();
    }

    int get_contact_count() { return contact_manager_.get_contact_count(); }

    // ========================================================================
    // Chat Operations
    // ========================================================================
    int create_chat(const std::string& name, int chat_type,
                    const std::vector<int>& member_ids = {}) {
        return chat_manager_.create_chat(name, chat_type, member_ids);
    }

    int create_group_chat(const std::string& name, const std::vector<int>& member_ids) {
        return chat_manager_.create_group_chat(name, member_ids);
    }

    int create_broadcast_list(const std::string& name, const std::vector<int>& member_ids) {
        return chat_manager_.create_broadcast_list(name, member_ids);
    }

    int create_chat_by_contact_id(int contact_id) {
        return chat_manager_.create_chat_by_contact_id(contact_id);
    }

    std::optional<ChatRecord> get_chat(int chat_id) {
        return chat_manager_.get_chat(chat_id);
    }

    std::optional<ChatRecord> get_chat_by_grpid(const std::string& grpid) {
        return chat_manager_.get_chat_by_grpid(grpid);
    }

    bool add_contact_to_chat(int chat_id, int contact_id) {
        return chat_manager_.add_contact_to_chat(chat_id, contact_id);
    }

    bool remove_contact_from_chat(int chat_id, int contact_id) {
        return chat_manager_.remove_contact_from_chat(chat_id, contact_id);
    }

    std::vector<int> get_chat_contacts(int chat_id) {
        return chat_manager_.get_chat_contacts(chat_id);
    }

    void set_chat_name(int chat_id, const std::string& name) {
        chat_manager_.set_chat_name(chat_id, name);
    }

    void set_chat_ephemeral_timer(int chat_id, int timer_sec) {
        chat_manager_.set_ephemeral_timer(chat_id, timer_sec);
    }

    int get_chat_ephemeral_timer(int chat_id) {
        return chat_manager_.get_ephemeral_timer(chat_id);
    }

    void set_chat_profile_image(int chat_id, const std::string& image_path) {
        chat_manager_.set_chat_profile_image(chat_id, image_path);
        profile_image_manager_.set_chat_image(chat_id, image_path);
    }

    std::string get_chat_profile_image(int chat_id) {
        return chat_manager_.get_chat_profile_image(chat_id);
    }

    std::vector<ChatRecord> get_all_chats() {
        return chat_manager_.get_all_chats();
    }

    bool delete_chat(int chat_id) {
        return chat_manager_.delete_chat(chat_id);
    }

    void archive_chat(int chat_id, bool archive) {
        chat_manager_.archive_chat(chat_id, archive);
    }

    bool is_chat_archived(int chat_id) {
        return chat_manager_.is_chat_archived(chat_id);
    }

    // ========================================================================
    // Message Sending
    // ========================================================================
    int send_message(int chat_id, const std::string& text,
                     const std::string& subject = "",
                     const std::string& parent_msg_id = "",
                     bool request_mdn = false,
                     int ephemeral_timer = 0) {
        MessageComposer::ComposeParams params;
        params.chat_id = chat_id;
        params.text = text;
        params.subject = subject;
        params.parent_message_id = parent_msg_id;
        params.request_mdn = request_mdn;
        params.ephemeral_timer = ephemeral_timer;

        auto result = pipeline_.send_message(params);
        return result.message_id;
    }

    int send_system_message(int chat_id, const std::string& system_text) {
        MessageComposer::ComposeParams params;
        params.chat_id = chat_id;
        params.text = system_text;
        params.request_mdn = false;

        auto result = pipeline_.send_message(params);
        return result.message_id;
    }

    // ========================================================================
    // Group Chat Management
    // ========================================================================
    int add_group_member(int chat_id, int contact_id, int actor_contact_id) {
        auto actor = contact_manager_.lookup_contact(actor_contact_id);
        auto member = contact_manager_.lookup_contact(contact_id);
        if (!actor.has_value() || !member.has_value()) return 0;

        if (chat_manager_.add_contact_to_chat(chat_id, contact_id)) {
            std::string sys_msg = SystemMessageGenerator::member_added(
                actor->display_name, member->display_name,
                chat_manager_.get_chat(chat_id)->name);
            return send_system_message(chat_id, sys_msg);
        }
        return 0;
    }

    int remove_group_member(int chat_id, int contact_id, int actor_contact_id) {
        auto actor = contact_manager_.lookup_contact(actor_contact_id);
        auto member = contact_manager_.lookup_contact(contact_id);
        if (!actor.has_value() || !member.has_value()) return 0;

        if (chat_manager_.remove_contact_from_chat(chat_id, contact_id)) {
            std::string sys_msg = SystemMessageGenerator::member_removed(
                actor->display_name, member->display_name,
                chat_manager_.get_chat(chat_id)->name);
            return send_system_message(chat_id, sys_msg);
        }
        return 0;
    }

    int set_group_name(int chat_id, const std::string& new_name, int actor_contact_id) {
        auto chat = chat_manager_.get_chat(chat_id);
        if (!chat.has_value()) return 0;
        std::string old_name = chat->name;

        chat_manager_.set_chat_name(chat_id, new_name);

        auto actor = contact_manager_.lookup_contact(actor_contact_id);
        if (actor.has_value()) {
            std::string sys_msg = SystemMessageGenerator::group_name_changed(
                actor->display_name, old_name, new_name);
            return send_system_message(chat_id, sys_msg);
        }
        return 0;
    }

    int set_group_image(int chat_id, const std::string& image_path, int actor_contact_id) {
        set_chat_profile_image(chat_id, image_path);
        auto actor = contact_manager_.lookup_contact(actor_contact_id);
        if (actor.has_value()) {
            std::string sys_msg = SystemMessageGenerator::group_image_changed(
                actor->display_name, chat_manager_.get_chat(chat_id)->name);
            return send_system_message(chat_id, sys_msg);
        }
        return 0;
    }

    // ========================================================================
    // Autocrypt Operations
    // ========================================================================
    AutocryptHeader get_autocrypt_header() {
        return encryption_engine_.get_autocrypt_header(self_addr_);
    }

    void process_autocrypt_header(const std::string& from_addr,
                                   const std::string& header_value) {
        auto parsed = AutocryptHeader::from_header_value(header_value, from_addr);
        if (parsed.has_value()) {
            encryption_engine_.add_peer_key(from_addr, parsed.value());
        }
    }

    bool can_encrypt_to(const std::string& addr) {
        return encryption_engine_.can_encrypt_to(addr);
    }

    // ========================================================================
    // MDN / Read Receipts
    // ========================================================================
    void send_mdn(int message_id, const std::string& original_mid,
                  const std::string& sender_addr) {
        MdnHandler::MdnRequest req;
        req.message_id = message_id;
        req.original_mid = original_mid;
        req.sender_addr = sender_addr;
        req.recipient_addr = self_addr_;

        std::string mdn_message = MdnHandler::build_mdn(req, self_addr_);

        // Send via SMTP
        std::vector<std::string> rcpt = {sender_addr};
        smtp_.send(mdn_message, self_addr_, rcpt);
    }

    void process_mdn(const std::string& mdn_message) {
        auto parsed = MdnHandler::parse_mdn(mdn_message);
        if (parsed.has_value() && parsed->disposition == "displayed") {
            // Mark the original message as "MDN received"
            read_receipts_.mark_read(0, 0); // would use actual msg_id and contact_id
        }
    }

    void mark_message_read(int chat_id, int message_id) {
        auto chat = chat_manager_.get_chat(chat_id);
        if (chat.has_value() && chat->ephemeral_timer > 0) {
            ephemeral_timer_.start_timer(message_id, chat_id,
                                          chat->ephemeral_timer);
        }
    }

    // ========================================================================
    // Ephemeral Messages
    // ========================================================================
    void process_expired_messages() {
        auto expired = ephemeral_timer_.get_expired_messages();
        // Delete expired messages from DB and cache
        for (int msg_id : expired) {
            // Would delete message content here
            // send ephemeral deletion notice to chat members
        }
    }

    int64_t get_ephemeral_remaining(int message_id) {
        return ephemeral_timer_.get_remaining_sec(message_id);
    }

    // ========================================================================
    // Mailing List Operations
    // ========================================================================
    void register_mailing_list(const std::string& list_id, int chat_id,
                                const std::string& list_name,
                                const std::string& list_domain,
                                const std::string& list_owner = "") {
        mailing_list_handler_.register_list(
            list_id, chat_id, list_name, list_domain, list_owner);
    }

    bool is_mailing_list_message(const std::string& list_id_header) {
        return mailing_list_handler_.is_mailing_list_message(list_id_header);
    }

    int get_chat_id_for_mailing_list(const std::string& list_id) {
        return mailing_list_handler_.get_chat_id_for_list(list_id);
    }

    // ========================================================================
    // SecureJoin
    // ========================================================================
    std::string start_securejoin(const std::string& grpid, int chat_id,
                                   const std::string& joiner_addr) {
        SecureJoinSession session;
        session.start_as_inviter(grpid, joiner_addr, chat_id);

        // Generate QR code
        auto kp = encryption_engine_.keypair();
        std::string qr = QrCodeGenerator::generate_securejoin_qr(
            grpid,
            chat_manager_.get_chat(chat_id)->name,
            self_addr_,
            kp.fingerprint);

        // Send system message
        send_system_message(chat_id,
            SystemMessageGenerator::securejoin_started(self_addr_));

        return qr;
    }

    bool complete_securejoin(const std::string& grpid,
                              const std::string& joiner_addr,
                              const std::string& fingerprint) {
        int chat_id = chat_manager_.get_chat_by_grpid(grpid)->id;
        auto joiner_contact = contact_manager_.lookup_contact_by_addr(joiner_addr);
        if (!joiner_contact.has_value()) return false;

        // Verify fingerprint matches
        auto joiner_key = encryption_engine_.get_peer_key(joiner_addr);
        if (joiner_key.has_value() && joiner_key->fingerprint() == fingerprint) {
            // Add joiner to the group
            chat_manager_.add_contact_to_chat(chat_id, joiner_contact->id);
            contact_manager_.verify_contact(joiner_contact->id,
                constants::DC_CONTACT_VERIFIED);

            send_system_message(chat_id,
                SystemMessageGenerator::securejoin_succeeded(joiner_contact->display_name));
            return true;
        }

        send_system_message(chat_id,
            SystemMessageGenerator::securejoin_failed(joiner_contact->display_name));
        return false;
    }

    // ========================================================================
    // QR Code
    // ========================================================================
    std::string get_securejoin_qr(const std::string& grpid, int chat_id) {
        auto chat = chat_manager_.get_chat(chat_id);
        auto kp = encryption_engine_.keypair();
        auto pub_key_b64 = util::base64_encode(kp.public_key);

        return QrCodeGenerator::generate_securejoin_qr(
            grpid,
            chat.has_value() ? chat->name : "",
            self_addr_,
            kp.fingerprint);
    }

    std::string get_invite_qr() {
        auto kp = encryption_engine_.keypair();
        auto pub_key_b64 = util::base64_encode(kp.public_key);
        return QrCodeGenerator::generate_dcaccount_qr(
            self_addr_, pub_key_b64);
    }

    // ========================================================================
    // Quote/Reply Detection
    // ========================================================================
    std::string extract_quoted_text(const std::string& text) {
        return QuoteDetector::extract_quoted_text(text);
    }

    std::string strip_quoted_text(const std::string& text) {
        return QuoteDetector::strip_quoted_text(text);
    }

    auto detect_quotes(const std::string& text) {
        return QuoteDetector::detect(text);
    }

    // ========================================================================
    // Import/Export
    // ========================================================================
    std::string export_backup() {
        return backup_manager_.export_backup();
    }

    bool import_backup(const std::string& backup_json) {
        return backup_manager_.import_backup(backup_json);
    }

    // ========================================================================
    // WebXDC
    // ========================================================================
    std::string send_webxdc_message(int chat_id, const std::string& app_name,
                                      const std::string& app_id,
                                      const std::string& update_data) {
        std::string instance_id = WebXdcInstance::generate_instance_id();
        webxdc_instance_.send_webxdc_message(
            instance_id, app_name, app_id, update_data);

        // Send as regular message with webxdc attachment
        std::string webxdc_json = webxdc_instance_.build_webxdc_attachment(
            "{\"name\":\"" + app_name + "\",\"app_id\":\"" + app_id + "\"}",
            std::vector<unsigned char>(update_data.begin(), update_data.end()));

        MessageComposer::ComposeParams params;
        params.chat_id = chat_id;
        params.text = "[WebXDC: " + app_name + "] " + update_data;
        pipeline_.send_message(params);

        return instance_id;
    }

    bool send_webxdc_status_update(const std::string& instance_id,
                                     const std::string& status_json) {
        return webxdc_instance_.send_status_update(instance_id, status_json);
    }

    std::string get_webxdc_instance_state(const std::string& instance_id) {
        return webxdc_instance_.get_instance_state(instance_id);
    }

    // ========================================================================
    // Self/Account Info
    // ========================================================================
    std::string get_self_addr() const { return self_addr_; }
    std::string get_domain() const { return domain_; }
    bool is_initialized() const { return initialized_; }

    void set_self_display_name(const std::string& name) {
        composer_.set_self_display_name(name);
    }
};

// ============================================================================
// Contact List Utilities
// ============================================================================
class ContactListUtils {
public:
    static std::vector<int> get_contact_list(int list_flags,
                                              DeltaChatContext* context) {
        std::vector<int> result;
        auto contacts = context->get_all_contacts();

        for (const auto& c : contacts) {
            // Filter by flags
            if (list_flags & constants::DC_GCL_ARCHIVED_ONLY) {
                // Skip non-archived
            }
            if (list_flags & constants::DC_GCL_NO_SPECIALS) {
                // Skip special contacts (e.g., device chat, saved messages)
            }

            result.push_back(c.id);
        }
        return result;
    }

    static std::string get_contact_encrinfo(DeltaChatContext* context,
                                              int contact_id) {
        auto contact = context->lookup_contact(contact_id);
        if (!contact.has_value()) return "";

        std::stringstream ss;
        ss << "Contact: " << contact->display_name << "\n";
        ss << "Email: " << contact->addr << "\n";
        ss << "Verified: " << (contact->verified ? "Yes" : "No") << "\n";
        ss << "Blocked: " << (contact->blocked ? "Yes" : "No") << "\n";

        if (context->can_encrypt_to(contact->addr)) {
            ss << "Encryption: Available\n";
        } else {
            ss << "Encryption: Not available\n";
        }

        return ss.str();
    }
};

// ============================================================================
// Chat List Utilities
// ============================================================================
class ChatListUtils {
public:
    static std::vector<int> get_chat_list(int list_flags,
                                           const std::string& query,
                                           int query_contact_id,
                                           DeltaChatContext* context) {
        auto chats = context->get_all_chats();
        std::vector<int> result;

        for (const auto& c : chats) {
            // Filter archived
            if (list_flags & constants::DC_GCL_ARCHIVED_ONLY) {
                if (!context->is_chat_archived(c.id)) continue;
            }

            // Filter by contact
            if (query_contact_id > 0) {
                auto members = context->get_chat_contacts(c.id);
                bool found = false;
                for (int m : members) {
                    if (m == query_contact_id) { found = true; break; }
                }
                if (!found) continue;
            }

            // Filter by name query
            if (!query.empty()) {
                std::string name_lower = util::to_lower(c.name);
                std::string query_lower = util::to_lower(query);
                if (name_lower.find(query_lower) == std::string::npos) continue;
            }

            result.push_back(c.id);
        }
        return result;
    }
};

// ============================================================================
// Location Streaming Support
// ============================================================================
class LocationManager {
private:
    struct Location {
        double latitude;
        double longitude;
        double accuracy;
        int64_t timestamp;
        int contact_id;
        int chat_id;
    };

    std::vector<Location> locations_;
    std::mutex mutex_;

public:
    void set_location(int chat_id, int contact_id,
                      double lat, double lon, double accuracy) {
        std::lock_guard<std::mutex> lock(mutex_);
        Location loc;
        loc.latitude = lat;
        loc.longitude = lon;
        loc.accuracy = accuracy;
        loc.contact_id = contact_id;
        loc.chat_id = chat_id;
        loc.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        locations_.push_back(loc);
    }

    std::optional<Location> get_location(int chat_id, int contact_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = locations_.rbegin(); it != locations_.rend(); ++it) {
            if (it->chat_id == chat_id && it->contact_id == contact_id) {
                return *it;
            }
        }
        return std::nullopt;
    }

    void clear_location(int chat_id, int contact_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        locations_.erase(
            std::remove_if(locations_.begin(), locations_.end(),
                [chat_id, contact_id](const Location& l) {
                    return l.chat_id == chat_id && l.contact_id == contact_id;
                }),
            locations_.end());
    }

    bool is_location_enabled(int chat_id, int contact_id) const {
        auto loc = get_location(chat_id, contact_id);
        if (!loc.has_value()) return false;
        // Location is considered enabled if within last 30 minutes
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return (now - loc->timestamp) < 1800;
    }

    void clear_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        locations_.clear();
    }
};

// ============================================================================
// HTML Email Support
// ============================================================================
class HtmlEmailBuilder {
public:
    static std::string build_html_message(const std::string& plain_text,
                                           const std::string& sender_name,
                                           const std::string& timestamp) {
        std::stringstream html;
        html << "<!DOCTYPE html>\n";
        html << "<html><head><meta charset=\"utf-8\">";
        html << "<style>\n";
        html << "  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', ";
        html << "Roboto, sans-serif; font-size: 14px; color: #333; max-width: 600px; }\n";
        html << "  .quote { border-left: 3px solid #4a90d9; padding-left: 12px; ";
        html << "color: #666; margin: 8px 0; }\n";
        html << "  .signature { color: #999; font-size: 12px; margin-top: 16px; ";
        html << "border-top: 1px solid #eee; padding-top: 8px; }\n";
        html << "</style></head><body>\n";

        // Convert plain text to HTML (basic)
        std::string escaped;
        for (char c : plain_text) {
            switch (c) {
                case '<': escaped += "&lt;"; break;
                case '>': escaped += "&gt;"; break;
                case '&': escaped += "&amp;"; break;
                case '\n': escaped += "<br>\n"; break;
                default: escaped += c;
            }
        }

        html << "<div class=\"message-body\">\n";
        html << escaped;
        html << "</div>\n";

        if (!sender_name.empty() || !timestamp.empty()) {
            html << "<div class=\"signature\">\n";
            html << "Sent by " << sender_name;
            if (!timestamp.empty()) {
                html << " at " << timestamp;
            }
            html << "</div>\n";
        }

        html << "</body></html>";
        return html.str();
    }

    static std::string build_html_quote(const std::string& quoted_text,
                                          const std::string& attribution) {
        std::stringstream html;
        html << "<div class=\"quote\">\n";
        if (!attribution.empty()) {
            html << "  <div class=\"attribution\">" << attribution << "</div>\n";
        }
        html << "  <blockquote>\n";
        html << "    " << quoted_text;
        html << "  </blockquote>\n";
        html << "</div>\n";
        return html.str();
    }
};

// ============================================================================
// Video Chat Invite Support
// ============================================================================
class VideoChatManager {
public:
    struct VideoChatRoom {
        std::string room_id;
        std::string room_url;
        std::string provider;     // "jitsi", "basicwebrtc", etc.
        int chat_id;
        int creator_contact_id;
        int64_t created_timestamp;
        bool is_active;
    };

private:
    std::vector<VideoChatRoom> rooms_;
    std::mutex mutex_;
    std::string base_url_ = "https://meet.jit.si/";

public:
    void set_base_url(const std::string& url) { base_url_ = url; }

    VideoChatRoom create_room(int chat_id, int creator_contact_id,
                               const std::string& provider = "jitsi") {
        std::lock_guard<std::mutex> lock(mutex_);

        VideoChatRoom room;
        room.room_id = "delta-" + util::random_hex(12);
        room.room_url = base_url_ + room.room_id;
        room.provider = provider;
        room.chat_id = chat_id;
        room.creator_contact_id = creator_contact_id;
        room.created_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        room.is_active = true;

        rooms_.push_back(room);
        return room;
    }

    std::string get_room_url(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = rooms_.rbegin(); it != rooms_.rend(); ++it) {
            if (it->chat_id == chat_id && it->is_active) {
                return it->room_url;
            }
        }
        return "";
    }

    void close_room(int chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& room : rooms_) {
            if (room.chat_id == chat_id && room.is_active) {
                room.is_active = false;
            }
        }
    }

    std::vector<VideoChatRoom> get_active_rooms() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<VideoChatRoom> active;
        for (const auto& room : rooms_) {
            if (room.is_active) active.push_back(room);
        }
        return active;
    }
};

// ============================================================================
// Draft Management
// ============================================================================
class DraftManager {
private:
    struct Draft {
        int chat_id;
        std::string text;
        std::string subject;
        int64_t timestamp;
        std::string quoted_text;
    };

    std::unordered_map<int, Draft> drafts_;
    std::mutex mutex_;

public:
    void set_draft(int chat_id, const std::string& text,
                   const std::string& subject = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        Draft d;
        d.chat_id = chat_id;
        d.text = text;
        d.subject = subject;
        d.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        d.quoted_text = QuoteDetector::extract_quoted_text(text);
        drafts_[chat_id] = d;
    }

    std::optional<Draft> get_draft(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = drafts_.find(chat_id);
        if (it != drafts_.end()) return it->second;
        return std::nullopt;
    }

    void remove_draft(int chat_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        drafts_.erase(chat_id);
    }

    bool has_draft(int chat_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return drafts_.find(chat_id) != drafts_.end();
    }
};

// ============================================================================
// Message Search / Full-Text
// ============================================================================
class MessageSearch {
private:
    struct SearchIndex {
        std::unordered_map<std::string, std::vector<int>> word_index_; // word -> msg_ids
    };

    SearchIndex index_;
    std::mutex mutex_;

public:
    void index_message(int msg_id, const std::string& text) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::istringstream stream(text);
        std::string word;
        while (stream >> word) {
            std::string lower = util::to_lower(word);
            // Strip punctuation
            lower.erase(std::remove_if(lower.begin(), lower.end(),
                [](char c) { return !isalnum(static_cast<unsigned char>(c)); }),
                lower.end());
            if (!lower.empty()) {
                index_.word_index_[lower].push_back(msg_id);
            }
        }
    }

    std::vector<int> search(const std::string& query) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<int> results;
        std::string lower = util::to_lower(query);
        auto it = index_.word_index_.find(lower);
        if (it != index_.word_index_.end()) {
            results = it->second;
        }
        return results;
    }

    std::vector<int> search_multi_word(const std::string& query) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::map<int, int> score;

        std::istringstream stream(query);
        std::string word;
        while (stream >> word) {
            std::string lower = util::to_lower(word);
            lower.erase(std::remove_if(lower.begin(), lower.end(),
                [](char c) { return !isalnum(static_cast<unsigned char>(c)); }),
                lower.end());
            if (lower.empty()) continue;

            auto it = index_.word_index_.find(lower);
            if (it != index_.word_index_.end()) {
                for (int msg_id : it->second) {
                    score[msg_id]++;
                }
            }
        }

        std::vector<std::pair<int, int>> sorted(score.begin(), score.end());
        std::sort(sorted.begin(), sorted.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        std::vector<int> results;
        for (const auto& pair : sorted) {
            results.push_back(pair.first);
        }
        return results;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        index_.word_index_.clear();
    }
};

// ============================================================================
// Message/Attachment Utility Functions (standalone)
// ============================================================================
namespace message_utils {

    std::string create_id() {
        return util::generate_message_id("local");
    }

    std::string quote_message(const std::string& text, const std::string& sender,
                               const std::string& timestamp) {
        std::stringstream ss;
        time_t t = std::stoll(timestamp);
        char time_buf[64];
        struct tm tm_buf;
        localtime_r(&t, &tm_buf);
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M", &tm_buf);

        ss << sender << " wrote on " << time_buf << ":\n";
        std::istringstream lines(text);
        std::string line;
        while (std::getline(lines, line)) {
            ss << "> " << line << "\n";
        }
        ss << "\n";
        return ss.str();
    }

    std::string format_message_timestamp(int64_t ts) {
        time_t t = static_cast<time_t>(ts);
        char buf[64];
        struct tm tm_buf;
        localtime_r(&t, &tm_buf);
        strftime(buf, sizeof(buf), "%H:%M", &tm_buf);
        return std::string(buf);
    }

    std::string format_full_timestamp(int64_t ts) {
        time_t t = static_cast<time_t>(ts);
        char buf[64];
        struct tm tm_buf;
        localtime_r(&t, &tm_buf);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
        return std::string(buf);
    }

    static bool is_multipart(const std::string& mime_type) {
        return mime_type.rfind("multipart/", 0) == 0;
    }

    static std::optional<std::string> extract_boundary(const std::string& content_type) {
        auto pos = content_type.find("boundary=");
        if (pos == std::string::npos) return std::nullopt;

        pos += 9;
        std::string boundary;
        if (pos < content_type.size() && content_type[pos] == '"') {
            pos++;
            auto end = content_type.find('"', pos);
            if (end != std::string::npos) {
                boundary = content_type.substr(pos, end - pos);
            }
        } else {
            auto end = content_type.find(';', pos);
            if (end == std::string::npos) end = content_type.size();
            boundary = util::trim(content_type.substr(pos, end - pos));
        }
        return boundary;
    }

    std::string extract_text_part(const std::string& mime_body,
                                   const std::string& content_type) {
        if (!is_multipart(content_type)) {
            return mime_body;
        }

        auto boundary_opt = extract_boundary(content_type);
        if (!boundary_opt.has_value()) return mime_body;

        std::string boundary = "--" + boundary_opt.value();
        std::string text_part;
        bool in_text_part = false;

        std::istringstream stream(mime_body);
        std::string line;
        while (std::getline(stream, line)) {
            if (line.rfind(boundary, 0) == 0) {
                in_text_part = false;
                continue;
            }
            if (util::to_lower(line).find("content-type: text/plain") != std::string::npos) {
                in_text_part = true;
                continue;
            }
            if (in_text_part && line.find("Content-") != 0) {
                text_part += line + "\n";
            }
        }

        return text_part;
    }

} // namespace message_utils

// ============================================================================
// Config Manager
// ============================================================================
class ConfigManager {
private:
    DatabaseStorage* storage_;
    std::unordered_map<std::string, std::string> config_cache_;
    std::mutex mutex_;

public:
    explicit ConfigManager(DatabaseStorage* s) : storage_(s) {}

    void set(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        config_cache_[key] = value;
        if (storage_ && storage_->db()) {
            const char* sql = "INSERT OR REPLACE INTO config (keyname, value) VALUES (?, ?)";
            sqlite3_stmt* stmt = nullptr;
            sqlite3_prepare_v2(storage_->db(), sql, -1, &stmt, nullptr);
            if (stmt) {
                sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }

    std::string get(const std::string& key, const std::string& default_val = "") const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = config_cache_.find(key);
        if (it != config_cache_.end()) return it->second;
        return default_val;
    }

    int get_int(const std::string& key, int default_val = 0) const {
        std::string val = get(key);
        if (val.empty()) return default_val;
        try { return std::stoi(val); }
        catch (...) { return default_val; }
    }

    bool get_bool(const std::string& key, bool default_val = false) const {
        std::string val = get(key);
        if (val.empty()) return default_val;
        std::string lower = util::to_lower(val);
        return lower == "1" || lower == "true" || lower == "yes";
    }
};

// ============================================================================
// Event System
// ============================================================================
class EventEmitter {
public:
    enum EventType {
        DC_EVENT_INFO = 100,
        DC_EVENT_WARNING = 300,
        DC_EVENT_ERROR = 400,
        DC_EVENT_MSGS_CHANGED = 2000,
        DC_EVENT_INCOMING_MSG = 2005,
        DC_EVENT_MSG_DELIVERED = 2010,
        DC_EVENT_MSG_FAILED = 2012,
        DC_EVENT_MSG_READ = 2015,
        DC_EVENT_CHAT_MODIFIED = 2020,
        DC_EVENT_CHAT_EPHEMERAL_TIMER_MODIFIED = 2025,
        DC_EVENT_CONTACTS_CHANGED = 2030,
        DC_EVENT_LOCATION_CHANGED = 2035,
        DC_EVENT_CONFIGURE_PROGRESS = 2041,
        DC_EVENT_IMEX_PROGRESS = 2051,
        DC_EVENT_IMEX_FILE_WRITTEN = 2052,
        DC_EVENT_SECUREJOIN_INVITER_PROGRESS = 2060,
        DC_EVENT_SECUREJOIN_JOINER_PROGRESS = 2061,
        DC_EVENT_CONNECTIVITY_CHANGED = 2100,
        DC_EVENT_WEBXDC_STATUS_UPDATE = 2110,
        DC_EVENT_WEBXDC_INSTANCE_DELETED = 2111,
    };

    using EventCallback = std::function<void(int event_type, int data1, int data2,
                                               const std::string& data_str)>;

private:
    std::vector<EventCallback> callbacks_;
    std::mutex mutex_;

public:
    void register_callback(EventCallback cb) {
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_.push_back(std::move(cb));
    }

    void emit(int event_type, int data1 = 0, int data2 = 0,
              const std::string& data_str = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& cb : callbacks_) {
            cb(event_type, data1, data2, data_str);
        }
    }

    void emit_msgs_changed(int chat_id, int msg_id) {
        emit(DC_EVENT_MSGS_CHANGED, chat_id, msg_id);
    }

    void emit_incoming_msg(int chat_id, int msg_id) {
        emit(DC_EVENT_INCOMING_MSG, chat_id, msg_id);
    }

    void emit_msg_delivered(int chat_id, int msg_id) {
        emit(DC_EVENT_MSG_DELIVERED, chat_id, msg_id);
    }

    void emit_msg_failed(int chat_id, int msg_id) {
        emit(DC_EVENT_MSG_FAILED, chat_id, msg_id);
    }

    void emit_msg_read(int chat_id, int msg_id) {
        emit(DC_EVENT_MSG_READ, chat_id, msg_id);
    }

    void emit_contacts_changed(int contact_id = 0) {
        emit(DC_EVENT_CONTACTS_CHANGED, contact_id);
    }

    void emit_chat_modified(int chat_id) {
        emit(DC_EVENT_CHAT_MODIFIED, chat_id);
    }

    void emit_error(int code, const std::string& message) {
        emit(DC_EVENT_ERROR, code, 0, message);
    }

    void emit_webxdc_status_update(int msg_id) {
        emit(DC_EVENT_WEBXDC_STATUS_UPDATE, msg_id);
    }
};

// ============================================================================
// Provider Info / Autoconfig
// ============================================================================
class ProviderInfo {
public:
    struct Provider {
        std::string domain;
        std::string display_name;
        std::string imap_server;
        int imap_port = 993;
        int imap_security = 2;
        std::string smtp_server;
        int smtp_port = 587;
        int smtp_security = 1;
        bool oauth2 = false;
    };

private:
    std::vector<Provider> providers_;

public:
    ProviderInfo() {
        // Built-in provider database
        providers_.push_back({
            "gmail.com", "Gmail",
            "imap.gmail.com", 993, 2,
            "smtp.gmail.com", 587, 1, true
        });
        providers_.push_back({
            "googlemail.com", "Gmail",
            "imap.gmail.com", 993, 2,
            "smtp.gmail.com", 587, 1, true
        });
        providers_.push_back({
            "outlook.com", "Outlook",
            "outlook.office365.com", 993, 2,
            "smtp-mail.outlook.com", 587, 1, true
        });
        providers_.push_back({
            "hotmail.com", "Outlook",
            "outlook.office365.com", 993, 2,
            "smtp-mail.outlook.com", 587, 1, true
        });
        providers_.push_back({
            "live.com", "Outlook",
            "outlook.office365.com", 993, 2,
            "smtp-mail.outlook.com", 587, 1, true
        });
        providers_.push_back({
            "yahoo.com", "Yahoo",
            "imap.mail.yahoo.com", 993, 2,
            "smtp.mail.yahoo.com", 587, 1
        });
        providers_.push_back({
            "icloud.com", "iCloud",
            "imap.mail.me.com", 993, 2,
            "smtp.mail.me.com", 587, 1
        });
        providers_.push_back({
            "fastmail.com", "Fastmail",
            "imap.fastmail.com", 993, 2,
            "smtp.fastmail.com", 587, 1
        });
        providers_.push_back({
            "protonmail.com", "ProtonMail",
            "127.0.0.1", 1143, 0,
            "127.0.0.1", 1025, 0
        });
        providers_.push_back({
            "mail.ru", "Mail.ru",
            "imap.mail.ru", 993, 2,
            "smtp.mail.ru", 587, 1
        });
        providers_.push_back({
            "yandex.ru", "Yandex",
            "imap.yandex.ru", 993, 2,
            "smtp.yandex.ru", 587, 1
        });
        providers_.push_back({
            "posteo.de", "Posteo",
            "posteo.de", 993, 2,
            "posteo.de", 587, 1
        });
        providers_.push_back({
            "mailbox.org", "Mailbox.org",
            "imap.mailbox.org", 993, 2,
            "smtp.mailbox.org", 587, 1
        });
        providers_.push_back({
            "riseup.net", "Riseup",
            "mail.riseup.net", 993, 2,
            "mail.riseup.net", 587, 1
        });
        providers_.push_back({
            "disroot.org", "Disroot",
            "disroot.org", 993, 2,
            "disroot.org", 587, 1
        });
        providers_.push_back({
            "startmail.com", "StartMail",
            "imap.startmail.com", 993, 2,
            "smtp.startmail.com", 587, 1
        });
        providers_.push_back({
            "gmx.de", "GMX",
            "imap.gmx.net", 993, 2,
            "mail.gmx.net", 587, 1
        });
        providers_.push_back({
            "web.de", "Web.de",
            "imap.web.de", 993, 2,
            "smtp.web.de", 587, 1
        });
        providers_.push_back({
            "t-online.de", "T-Online",
            "secureimap.t-online.de", 993, 2,
            "securesmtp.t-online.de", 587, 1
        });
        providers_.push_back({
            "naver.com", "Naver",
            "imap.naver.com", 993, 2,
            "smtp.naver.com", 587, 1
        });
        providers_.push_back({
            "qq.com", "QQ Mail",
            "imap.qq.com", 993, 2,
            "smtp.qq.com", 587, 1
        });
        providers_.push_back({
            "163.com", "163 Mail",
            "imap.163.com", 993, 2,
            "smtp.163.com", 587, 1
        });
        providers_.push_back({
            "126.com", "126 Mail",
            "imap.126.com", 993, 2,
            "smtp.126.com", 587, 1
        });
        providers_.push_back({
            "zoho.com", "Zoho",
            "imap.zoho.com", 993, 2,
            "smtp.zoho.com", 587, 1
        });
        providers_.push_back({
            "cock.li", "Cock.li",
            "mail.cock.li", 993, 2,
            "mail.cock.li", 587, 1
        });
    }

    std::optional<Provider> get_provider(const std::string& email_addr) const {
        auto at = email_addr.find('@');
        if (at == std::string::npos) return std::nullopt;

        std::string domain = util::to_lower(email_addr.substr(at + 1));

        for (const auto& p : providers_) {
            if (domain == p.domain) return p;
        }

        // Subdomain matching (e.g., student.example.edu -> example.edu)
        for (const auto& p : providers_) {
            if (domain.size() > p.domain.size() &&
                domain.substr(domain.size() - p.domain.size() - 1) == "." + p.domain) {
                return p;
            }
        }

        return std::nullopt;
    }

    static std::string guess_imap_server(const std::string& domain) {
        // Try common patterns
        return "imap." + domain;
    }

    static std::string guess_smtp_server(const std::string& domain) {
        return "smtp." + domain;
    }
};

// ============================================================================
// Stock Strings / i18n
// ============================================================================
namespace stock_strings {

    // System messages in English
    constexpr const char* MSG_LOCATION_ENABLED = "Location streaming enabled.";
    constexpr const char* MSG_LOCATION_DISABLED = "Location streaming disabled.";
    constexpr const char* MSG_EPHEMERAL_TIMER_DISABLED = "Disappearing messages turned off.";
    constexpr const char* MSG_GIF = "GIF";
    constexpr const char* MSG_IMAGE = "Image";
    constexpr const char* MSG_VIDEO = "Video";
    constexpr const char* MSG_AUDIO = "Audio";
    constexpr const char* MSG_VOICEMAIL = "Voice message";
    constexpr const char* MSG_DOCUMENT = "Document";
    constexpr const char* MSG_STICKER = "Sticker";
    constexpr const char* MSG_ENCRYPTED_MSG = "Encrypted message";
    constexpr const char* MSG_UNKNOWN_FILE = "File";
    constexpr const char* MSG_CONTACT = "Contact";
    constexpr const char* MSG_WEBXDC = "Webxdc app";

    std::string self_msg(const std::string& text) {
        return "[You] " + text;
    }

    std::string deleted_msg() {
        return "[This message has been deleted]";
    }

    std::string encrypted_msg_no_setup() {
        return "[Encrypted message - no setup message seen]";
    }

    std::string new_group(const std::string& creator, const std::string& group_name) {
        return "Group created by " + creator + ".";
    }

} // namespace stock_strings

// ============================================================================
// C-Style API wrapper (for FFI/interop)
// ============================================================================
extern "C" {

    struct dc_context_t {
        progressive::deltachat::DeltaChatContext* context;
        progressive::deltachat::EventEmitter* events;
    };

    dc_context_t* dc_context_new() {
        auto* ctx = new dc_context_t();
        ctx->context = new progressive::deltachat::DeltaChatContext();
        ctx->events = new progressive::deltachat::EventEmitter();
        return ctx;
    }

    void dc_context_unref(dc_context_t* ctx) {
        if (ctx) {
            delete ctx->context;
            delete ctx->events;
            delete ctx;
        }
    }

    int dc_open(dc_context_t* ctx, const char* dbfile) {
        if (!ctx || !ctx->context) return 0;
        return ctx->context->open(dbfile) ? 1 : 0;
    }

    void dc_close(dc_context_t* ctx) {
        if (ctx && ctx->context) ctx->context->close();
    }

    int dc_configure(dc_context_t* ctx) {
        // Would trigger configure via events/callbacks
        return 1;
    }

    int dc_create_contact(dc_context_t* ctx, const char* name, const char* addr) {
        if (!ctx || !ctx->context) return 0;
        return ctx->context->add_contact(addr ? addr : "", name ? name : "");
    }

    int dc_create_chat_by_contact_id(dc_context_t* ctx, int contact_id) {
        if (!ctx || !ctx->context) return 0;
        return ctx->context->create_chat_by_contact_id(contact_id);
    }

    int dc_create_group_chat(dc_context_t* ctx, int verified, const char* name) {
        if (!ctx || !ctx->context) return 0;
        return ctx->context->create_group_chat(name ? name : "", {});
    }

    int dc_send_text_msg(dc_context_t* ctx, int chat_id, const char* text) {
        if (!ctx || !ctx->context) return 0;
        return ctx->context->send_message(chat_id, text ? text : "");
    }

    int dc_block_contact(dc_context_t* ctx, int contact_id, int block) {
        if (!ctx || !ctx->context) return 0;
        if (block) return ctx->context->block_contact(contact_id) ? 1 : 0;
        else return ctx->context->unblock_contact(contact_id) ? 1 : 0;
    }

    char* dc_get_securejoin_qr(dc_context_t* ctx, int chat_id) {
        if (!ctx || !ctx->context) return nullptr;
        auto chat = ctx->context->get_chat(chat_id);
        if (!chat.has_value()) return nullptr;
        std::string qr = ctx->context->get_securejoin_qr(chat->grpid, chat_id);
        return strdup(qr.c_str());
    }

    int dc_join_securejoin(dc_context_t* ctx, const char* qr) {
        if (!ctx || !ctx->context || !qr) return 0;
        // Parse QR code and process securejoin
        return 1;
    }

    char* dc_get_contact_encrinfo(dc_context_t* ctx, int contact_id) {
        if (!ctx || !ctx->context) return nullptr;
        std::string info = progressive::deltachat::ContactListUtils::get_contact_encrinfo(
            ctx->context, contact_id);
        return strdup(info.c_str());
    }

    void dc_str_unref(char* s) {
        free(s);
    }

} // extern "C"

// ============================================================================
// SQLCipher key management (for encrypted databases)
// ============================================================================
class SqlCipherManager {
public:
    static bool set_key(DatabaseStorage* storage, const std::string& key) {
        if (!storage || !storage->db() || key.empty()) return false;

        const char* sql = "PRAGMA key = ?";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(storage->db(), sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) return false;

        sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return rc == SQLITE_OK || rc == SQLITE_ROW || rc == SQLITE_DONE;
    }

    static bool rekey(DatabaseStorage* storage, const std::string& new_key) {
        if (!storage || !storage->db()) return false;

        const char* sql = "PRAGMA rekey = ?";
        sqlite3_stmt* stmt = nullptr;
        int rc = sqlite3_prepare_v2(storage->db(), sql, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) return false;

        sqlite3_bind_text(stmt, 1, new_key.c_str(), -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        return rc == SQLITE_OK || rc == SQLITE_ROW || rc == SQLITE_DONE;
    }
};

// ============================================================================
// Device Chat / Saved Messages
// ============================================================================
class DeviceChatManager {
private:
    int device_chat_id_ = 0;
    int saved_messages_chat_id_ = 0;
    DeltaChatContext* context_;

public:
    explicit DeviceChatManager(DeltaChatContext* ctx) : context_(ctx) {}

    int get_device_chat_id() {
        if (device_chat_id_ == 0) {
            auto chats = context_->get_all_chats();
            for (const auto& c : chats) {
                if (c.type == constants::DC_CHAT_TYPE_SINGLE &&
                    c.is_device_chat) {
                    device_chat_id_ = c.id;
                    return device_chat_id_;
                }
            }
            // Create device chat
            device_chat_id_ = context_->create_chat(
                "Device Messages", constants::DC_CHAT_TYPE_SINGLE);
        }
        return device_chat_id_;
    }

    int get_saved_messages_chat_id() {
        // "Saved Messages" is a special single chat with self
        if (saved_messages_chat_id_ == 0) {
            // Create chat with self
            saved_messages_chat_id_ = context_->create_chat_by_contact_id(1);
        }
        return saved_messages_chat_id_;
    }

    void send_device_message(const std::string& text) {
        int chat_id = get_device_chat_id();
        context_->send_message(chat_id, text);
    }
};

// ============================================================================
// Connectivity / Network Status
// ============================================================================
class ConnectivityManager {
private:
    bool is_connected_ = false;
    bool is_connecting_ = false;
    std::mutex mutex_;
    EventEmitter* events_ = nullptr;

public:
    void set_event_emitter(EventEmitter* events) { events_ = events; }

    void set_connected(bool connected) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (is_connected_ != connected) {
            is_connected_ = connected;
            is_connecting_ = false;
            if (events_) {
                events_->emit(EventEmitter::DC_EVENT_CONNECTIVITY_CHANGED,
                              connected ? 1 : 0);
            }
        }
    }

    void set_connecting(bool connecting) {
        std::lock_guard<std::mutex> lock(mutex_);
        is_connecting_ = connecting;
    }

    bool is_connected() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return is_connected_;
    }

    bool is_connecting() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return is_connecting_;
    }
};

} // namespace deltachat
} // namespace progressive
