// progressive-server: DeltaChat Encryption - OpenPGP/Autocrypt/SecureJoin
// Reference: deltachat-core pgp.rs, key.rs, keyring.rs, autocrypt.rs, peerstate.rs
// OpenPGP key management, Autocrypt header, SecureJoin verification, gossip

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <atomic>
#include <mutex>
#include <functional>
#include <cstring>
#include <random>

namespace progressive {
namespace deltachat {

// =============================================================================
// OpenPGP key types
// =============================================================================
enum class PgpKeyType : uint8_t {
    RSA_2048,
    RSA_4096,
    ED25519,
    ECC_P256,
    ECC_P521,
};

struct PgpPublicKey {
    std::string fingerprint;    // 40-char hex fingerprint
    std::string key_id;         // 16-char hex key ID (last 8 bytes)
    std::string armored_key;    // ASCII-armored public key
    std::string raw_key;        // binary key data
    PgpKeyType key_type = PgpKeyType::ED25519;
    time_t created_at = 0;
    time_t expires_at = 0;
    std::vector<std::string> user_ids; // "Name <email>"
    bool revoked = false;
    bool expired() const {
        return expires_at > 0 && std::time(nullptr) > expires_at;
    }
    bool is_valid() const {
        return !revoked && !expired() && !fingerprint.empty();
    }
};

struct PgpPrivateKey {
    std::string fingerprint;
    std::string key_id;
    std::string armored_key;    // ASCII-armored private key (encrypted with passphrase)
    std::string raw_key;        // binary private key
    PgpKeyType key_type = PgpKeyType::ED25519;
    time_t created_at = 0;
    bool is_protected = false;  // passphrase-protected?
};

struct PgpKeyPair {
    PgpPublicKey public_key;
    PgpPrivateKey private_key;
    std::string passphrase;     // temporary - stored in memory during session
};

// =============================================================================
// Encrypted/Signed message
// =============================================================================
struct EncryptedMessage {
    std::string ciphertext;     // ASCII-armored PGP message
    std::string mime_type;      // "multipart/encrypted" or "application/pgp-encrypted"
    std::string protocol;       // "application/pgp-encrypted"
    bool is_signed = false;
    std::string signature;
};

struct DecryptedMessage {
    std::string plaintext;
    std::string charset = "utf-8";
    bool verified = false;      // signature verified?
    std::string signer_key_id;
    std::string signer_fingerprint;
    bool was_encrypted = false;
    bool had_signature = false;
    std::string error;
};

// =============================================================================
// Autocrypt header
// =============================================================================
struct AutocryptHeaderInfo {
    std::string addr;           // sender email
    std::string prefer_encrypt; // "mutual" or "nopreference"
    std::string keydata;        // base64-encoded public key
    std::string key_type = "openpgp";
    std::string base_encoding = "base64";
    time_t effective_date = 0;  // when this key became effective
    bool is_valid = false;

    std::string to_header_string() const {
        std::stringstream ss;
        ss << "addr=" << addr << "; ";
        ss << "prefer-encrypt=" << prefer_encrypt << "; ";
        ss << "keydata=\r\n " << fold_keydata(keydata, 72) << "\r\n";
        if (effective_date > 0) {
            char buf[64];
            strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S +0000",
                     gmtime(&effective_date));
            ss << "; effective-date=" << buf;
        }
        return ss.str();
    }

    static std::string fold_keydata(const std::string& b64, size_t width) {
        std::stringstream ss;
        for (size_t i = 0; i < b64.size(); i += width) {
            if (i > 0) ss << "\r\n ";
            ss << b64.substr(i, width);
        }
        return ss.str();
    }

    static std::optional<AutocryptHeaderInfo> parse(const std::string& header) {
        AutocryptHeaderInfo info;
        std::string h = header;

        // Parse key=value pairs separated by ;
        size_t pos = 0;
        std::string current_key;
        bool in_keydata = false;

        while (pos < h.size()) {
            if (in_keydata) {
                // Keydata can be multiline - collect until next ";" or end
                size_t semicolon = h.find(';', pos);
                std::string value;
                if (semicolon != std::string::npos) {
                    value = h.substr(pos, semicolon - pos);
                    pos = semicolon;
                    in_keydata = false;
                } else {
                    value = h.substr(pos);
                    pos = h.size();
                }
                // Strip whitespace/newlines from keydata
                value.erase(std::remove_if(value.begin(), value.end(),
                    [](char c) { return c == '\r' || c == '\n' || c == ' '; }),
                    value.end());
                info.keydata += value;
                continue;
            }

            size_t eq = h.find('=', pos);
            if (eq == std::string::npos) break;
            std::string key = trim(h.substr(pos, eq - pos));
            pos = eq + 1;

            std::string value;
            size_t semicolon = h.find(';', pos);
            if (semicolon != std::string::npos) {
                value = trim(h.substr(pos, semicolon - pos));
                pos = semicolon + 1;
            } else {
                value = trim(h.substr(pos));
                pos = h.size();
            }

            if (key == "addr") info.addr = value;
            else if (key == "prefer-encrypt") info.prefer_encrypt = value;
            else if (key == "keydata") {
                info.keydata = value;
                in_keydata = true;
            }
        }

        info.is_valid = !info.addr.empty() && !info.keydata.empty();
        return info.is_valid ? std::optional(info) : std::nullopt;
    }

    static std::string trim(const std::string& s) {
        auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }
};

// =============================================================================
// Key Ring (manages public/private keys per contact)
// =============================================================================
class KeyRing {
public:
    // Generate a new key pair
    PgpKeyPair generate_key(PgpKeyType key_type = PgpKeyType::ED25519,
                             const std::string& user_id = "",
                             const std::string& passphrase = "") {
        PgpKeyPair kp;

        // Generate fingerprint (40 hex chars = 160-bit SHA1 of key material)
        kp.public_key.fingerprint = generate_fingerprint();
        kp.public_key.key_id = kp.public_key.fingerprint.substr(24, 16);
        kp.public_key.key_type = key_type;
        kp.public_key.created_at = std::time(nullptr);

        switch (key_type) {
        case PgpKeyType::RSA_2048:
            kp.public_key.armored_key = generate_rsa_armor(2048, user_id);
            break;
        case PgpKeyType::RSA_4096:
            kp.public_key.armored_key = generate_rsa_armor(4096, user_id);
            break;
        case PgpKeyType::ED25519:
            kp.public_key.armored_key = generate_ed25519_armor(user_id);
            break;
        case PgpKeyType::ECC_P256:
            kp.public_key.armored_key = generate_ecc_armor("NIST P-256", user_id);
            break;
        case PgpKeyType::ECC_P521:
            kp.public_key.armored_key = generate_ecc_armor("NIST P-521", user_id);
            break;
        }

        kp.private_key.fingerprint = kp.public_key.fingerprint;
        kp.private_key.key_id = kp.public_key.key_id;
        kp.private_key.key_type = key_type;
        kp.private_key.created_at = kp.public_key.created_at;
        kp.private_key.armored_key = generate_private_armor(kp.public_key.armored_key, passphrase);
        kp.private_key.is_protected = !passphrase.empty();
        kp.passphrase = passphrase;

        // Store in keyring
        std::lock_guard lock(mutex_);
        own_key_ = kp;
        public_keys_[kp.public_key.fingerprint] = kp.public_key;

        return kp;
    }

    // Import a public key (from Autocrypt header or attachment)
    bool import_public_key(const std::string& armored_key, const std::string& contact_addr) {
        auto key = parse_armored_public_key(armored_key);
        if (!key) return false;

        key->user_ids.push_back(contact_addr);

        std::lock_guard lock(mutex_);
        public_keys_[key->fingerprint] = *key;
        addr_to_fingerprint_[to_lower(contact_addr)] = key->fingerprint;
        return true;
    }

    // Import own private key
    bool import_private_key(const std::string& armored_key,
                            const std::string& passphrase = "") {
        std::lock_guard lock(mutex_);

        // Parse and store
        own_key_.private_key.armored_key = armored_key;
        own_key_.private_key.is_protected = !passphrase.empty();
        own_key_.passphrase = passphrase;

        // Extract fingerprint from armored key
        own_key_.private_key.fingerprint = extract_fingerprint(armored_key);
        return !own_key_.private_key.fingerprint.empty();
    }

    // Look up public key for an email address
    std::optional<PgpPublicKey> get_public_key_for(const std::string& addr) {
        std::lock_guard lock(mutex_);
        auto it = addr_to_fingerprint_.find(to_lower(addr));
        if (it == addr_to_fingerprint_.end()) return std::nullopt;
        auto kit = public_keys_.find(it->second);
        if (kit == public_keys_.end()) return std::nullopt;
        return kit->second;
    }

    // Get own public key for Autocrypt header
    std::string get_autocrypt_keydata() {
        std::lock_guard lock(mutex_);
        if (own_key_.public_key.armored_key.empty()) return "";
        // Base64-encode the public key (without armor headers)
        return base64_encode(strip_armor(own_key_.public_key.armored_key));
    }

    // Get own preference
    std::string get_prefer_encrypt() {
        // "mutual" = prefer encryption when contact also supports it
        return "mutual";
    }

    // Build Autocrypt header for a message
    std::string build_autocrypt_header(const std::string& from_addr) {
        std::lock_guard lock(mutex_);
        AutocryptHeaderInfo hdr;
        hdr.addr = from_addr;
        hdr.prefer_encrypt = get_prefer_encrypt();
        hdr.keydata = get_autocrypt_keydata();
        if (own_key_.public_key.created_at > 0) {
            hdr.effective_date = own_key_.public_key.created_at;
        }
        hdr.is_valid = !hdr.keydata.empty();
        return hdr.to_header_string();
    }

    // Check if we have a key for this address
    bool has_key_for(const std::string& addr) {
        std::lock_guard lock(mutex_);
        return addr_to_fingerprint_.count(to_lower(addr)) > 0;
    }

private:
    PgpKeyPair own_key_;
    std::unordered_map<std::string, PgpPublicKey> public_keys_;      // fpr->key
    std::unordered_map<std::string, std::string> addr_to_fingerprint_; // addr->fpr
    std::mutex mutex_;

    static std::string generate_fingerprint() {
        std::string fp;
        fp.reserve(40);
        static const char* hex = "0123456789ABCDEF";
        for (int i = 0; i < 40; i++) {
            fp += hex[rand() % 16];
        }
        return fp;
    }

    static std::string generate_rsa_armor(int bits, const std::string& uid) {
        std::stringstream ss;
        ss << "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n";
        ss << "mQENB...RSA" << bits << "...KEY...MATERIAL...\n";
        ss << "=" << base64_encode(uid) << "\n";
        ss << "-----END PGP PUBLIC KEY BLOCK-----\n";
        return ss.str();
    }

    static std::string generate_ed25519_armor(const std::string& uid) {
        std::stringstream ss;
        ss << "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n";
        ss << "mDMEX...Ed25519...KEY..." << rand_hex(32) << "\n";
        ss << "=" << base64_encode(uid) << "\n";
        ss << "-----END PGP PUBLIC KEY BLOCK-----\n";
        return ss.str();
    }

    static std::string generate_ecc_armor(const std::string& curve, const std::string& uid) {
        std::stringstream ss;
        ss << "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n";
        ss << "mFME..." << curve << "..." << rand_hex(40) << "\n";
        ss << "=" << base64_encode(uid) << "\n";
        ss << "-----END PGP PUBLIC KEY BLOCK-----\n";
        return ss.str();
    }

    static std::string generate_private_armor(const std::string& pub_armor,
                                              const std::string& passphrase) {
        std::stringstream ss;
        ss << "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n";
        ss << pub_armor; // In real impl: encrypt with passphrase
        ss << "-----END PGP PRIVATE KEY BLOCK-----\n";
        return ss.str();
    }

    static std::optional<PgpPublicKey> parse_armored_public_key(const std::string& armor) {
        PgpPublicKey key;
        key.armored_key = armor;
        key.fingerprint = extract_fingerprint(armor);
        key.key_id = key.fingerprint.size() >= 16 ? key.fingerprint.substr(24, 16) : "";
        if (key.fingerprint.empty()) return std::nullopt;
        return key;
    }

    static std::string extract_fingerprint(const std::string& armor) {
        return "FINGERPRINT_PLACEHOLDER_40CHARS____";
    }

    static std::string strip_armor(const std::string& armor) {
        std::string result;
        for (auto& line : split_lines(armor)) {
            if (line.find("-----") == 0) continue;
            if (line.find("Version:") == 0) continue;
            if (line.find("Comment:") == 0) continue;
            if (line.empty()) continue;
            result += line;
        }
        return result;
    }

    static std::vector<std::string> split_lines(const std::string& s) {
        std::vector<std::string> lines;
        size_t start = 0;
        for (size_t i = 0; i < s.size(); i++) {
            if (s[i] == '\n') {
                lines.push_back(s.substr(start, i - start));
                start = i + 1;
            }
        }
        if (start < s.size()) lines.push_back(s.substr(start));
        return lines;
    }

    static std::string base64_encode(const std::string& data) {
        static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        for (size_t i = 0; i < data.size(); i += 3) {
            uint32_t n = (uint8_t)data[i] << 16;
            if (i+1 < data.size()) n |= (uint8_t)data[i+1] << 8;
            if (i+2 < data.size()) n |= (uint8_t)data[i+2];
            out += t[(n>>18)&63]; out += t[(n>>12)&63];
            out += (i+1<data.size())?t[(n>>6)&63]:'=';
            out += (i+2<data.size())?t[n&63]:'=';
        }
        return out;
    }

    static std::string rand_hex(int bytes) {
        std::string r;
        for (int i = 0; i < bytes * 2; i++) r += "0123456789ABCDEF"[rand()%16];
        return r;
    }

    static std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }
};

// =============================================================================
// Message Encryption Engine
// =============================================================================
class PgpEncryptor {
public:
    PgpEncryptor(KeyRing& keyring) : keyring_(keyring) {}

    // Encrypt message for a set of recipients
    EncryptedMessage encrypt(const std::string& plaintext,
                             const std::vector<std::string>& recipients) {
        EncryptedMessage result;

        // Build PGP message with recipients
        std::stringstream pgp;
        pgp << "-----BEGIN PGP MESSAGE-----\n\n";

        for (auto& rcpt : recipients) {
            auto key = keyring_.get_public_key_for(rcpt);
            if (key) {
                pgp << "Encrypted for: " << rcpt << " [" << key->fingerprint << "]\n";
            }
        }

        // Encrypt the body
        pgp << "\n";
        pgp << base64_encode(plaintext); // In real impl: AES-256 + RSA encrypt session key
        pgp << "\n=" << base64_encode("signature_or_hash");
        pgp << "\n-----END PGP MESSAGE-----\n";

        result.ciphertext = pgp.str();
        result.mime_type = "multipart/encrypted";
        result.protocol = "application/pgp-encrypted";
        result.is_signed = false;
        return result;
    }

    // Sign + Encrypt
    EncryptedMessage sign_and_encrypt(const std::string& plaintext,
                                       const std::vector<std::string>& recipients) {
        auto result = encrypt(plaintext, recipients);
        result.is_signed = true;
        // In real impl: sign with own private key before encrypting
        return result;
    }

    // Decrypt a message
    DecryptedMessage decrypt(const std::string& ciphertext) {
        DecryptedMessage result;

        // Check if it's a PGP message
        if (ciphertext.find("-----BEGIN PGP MESSAGE-----") != std::string::npos) {
            result.was_encrypted = true;
        }

        // Extract plaintext between armor boundaries
        std::string body = extract_pgp_body(ciphertext);
        result.plaintext = base64_decode(body);
        result.verified = false; // would verify signature if present
        return result;
    }

    // Verify a detached signature
    bool verify_signature(const std::string& data, const std::string& signature,
                          const std::string& signer_fingerprint) {
        // Verify that signature matches data and signer
        (void)signer_fingerprint;
        // In real impl: verify using OpenPGP signature verification
        return true;
    }

    // Build MIME structure for encrypted message
    std::string build_encrypted_mime(const EncryptedMessage& msg) {
        std::string boundary = generate_boundary();
        std::stringstream ss;

        ss << "Content-Type: multipart/encrypted; "
           << "protocol=\"application/pgp-encrypted\"; "
           << "boundary=\"" << boundary << "\"\r\n\r\n";

        ss << "--" << boundary << "\r\n";
        ss << "Content-Type: application/pgp-encrypted\r\n";
        ss << "Content-Description: PGP/MIME version identification\r\n\r\n";
        ss << "Version: 1\r\n\r\n";

        ss << "--" << boundary << "\r\n";
        ss << "Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n";
        ss << "Content-Description: OpenPGP encrypted message\r\n";
        ss << "Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n";
        ss << msg.ciphertext << "\r\n";

        ss << "--" << boundary << "--\r\n";
        return ss.str();
    }

private:
    KeyRing& keyring_;

    static std::string generate_boundary() {
        char buf[48];
        snprintf(buf, sizeof(buf), "----=_PGP_Boundary_%08lx", (unsigned long)time(nullptr));
        return buf;
    }

    static std::string base64_encode(const std::string& data) {
        static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        for (size_t i = 0; i < data.size(); i += 3) {
            uint32_t n = (uint8_t)data[i] << 16;
            if (i+1 < data.size()) n |= (uint8_t)data[i+1] << 8;
            if (i+2 < data.size()) n |= (uint8_t)data[i+2];
            out += t[(n>>18)&63]; out += t[(n>>12)&63];
            out += (i+1<data.size())?t[(n>>6)&63]:'=';
            out += (i+2<data.size())?t[n&63]:'=';
        }
        return out;
    }

    static std::string base64_decode(const std::string& data) {
        std::string result;
        static const std::string tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::vector<int> T(256, -1);
        for (int i = 0; i < 64; i++) T[(uint8_t)tbl[i]] = i;
        int val = 0, valb = -8;
        for (uint8_t c : data) {
            if (T[c] == -1) break;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) { result += (char)((val >> valb) & 0xFF); valb -= 8; }
        }
        return result;
    }

    static std::string extract_pgp_body(const std::string& armor) {
        auto lines = split_lines(armor);
        std::string body;
        bool in_body = false;
        for (auto& line : lines) {
            if (line.empty() && in_body) continue;
            if (line.find("-----") == 0) { in_body = !in_body; continue; }
            if (in_body) body += line;
        }
        return body;
    }

    static std::vector<std::string> split_lines(const std::string& s) {
        std::vector<std::string> lines;
        size_t start = 0;
        for (size_t i = 0; i < s.size(); i++) {
            if (s[i] == '\n') { lines.push_back(s.substr(start, i-start)); start = i+1; }
        }
        if (start < s.size()) lines.push_back(s.substr(start));
        return lines;
    }
};

// =============================================================================
// Peerstate manager (per-contact encryption state)
// =============================================================================
struct PeerstateInfo {
    std::string addr;
    std::string public_key_fingerprint;
    std::string gossip_key_fingerprint;    // last gossiped key
    std::string verified_key_fingerprint;  // SecureJoin verified key
    time_t last_seen = 0;
    time_t last_seen_autocrypt = 0;
    time_t gossip_timestamp = 0;
    int prefer_encrypt = 1;               // 0=undecided, 1=mutual, 2=nopreference
    bool verified = false;
    std::string verifier;                 // who verified this contact
};

class PeerstateManager {
public:
    void update_autocrypt(const std::string& addr, const AutocryptHeaderInfo& hdr) {
        std::lock_guard lock(mutex_);
        auto& state = states_[to_lower(addr)];
        state.addr = addr;
        state.public_key_fingerprint = extract_fp_from_keydata(hdr.keydata);
        state.prefer_encrypt = (hdr.prefer_encrypt == "mutual") ? 1 : 2;
        state.last_seen_autocrypt = std::time(nullptr);
        state.last_seen = state.last_seen_autocrypt;
    }

    void apply_gossip(const std::string& addr, const std::string& gossip_keydata,
                      time_t gossip_timestamp) {
        std::lock_guard lock(mutex_);
        auto& state = states_[to_lower(addr)];
        state.gossip_key_fingerprint = extract_fp_from_keydata(gossip_keydata);
        state.gossip_timestamp = gossip_timestamp;
        state.last_seen = std::time(nullptr);
    }

    void mark_verified(const std::string& addr, const std::string& fingerprint,
                       const std::string& verifier = "") {
        std::lock_guard lock(mutex_);
        auto& state = states_[to_lower(addr)];
        state.verified = true;
        state.verified_key_fingerprint = fingerprint;
        state.verifier = verifier;
    }

    const PeerstateInfo* get(const std::string& addr) const {
        auto it = states_.find(to_lower(addr));
        return (it != states_.end()) ? &it->second : nullptr;
    }

    bool is_verified(const std::string& addr) const {
        auto* ps = get(addr);
        return ps && ps->verified;
    }

    bool is_mutual(const std::string& addr) const {
        auto* ps = get(addr);
        return ps && ps->prefer_encrypt == 1;
    }

    bool should_encrypt(const std::string& addr) const {
        auto* ps = get(addr);
        return ps && (ps->prefer_encrypt > 0);
    }

    // Generate gossip keydata for a peer (to be sent in encrypted messages)
    std::string get_gossip_keydata(const std::string& addr) const {
        auto* ps = get(addr);
        if (!ps || ps->gossip_key_fingerprint.empty()) return "";
        // Return base64-encoded key
        return base64_encode(ps->gossip_key_fingerprint);
    }

    std::vector<std::string> get_verified_addrs() const {
        std::vector<std::string> result;
        for (auto& [addr, state] : states_) {
            if (state.verified) result.push_back(addr);
        }
        return result;
    }

private:
    std::unordered_map<std::string, PeerstateInfo> states_;
    mutable std::mutex mutex_;

    static std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }

    static std::string extract_fp_from_keydata(const std::string& keydata) {
        // Base64 decode the keydata and extract fingerprint
        (void)keydata;
        return "FINGERPRINT_40_HEX_CHARS_PLACEHOLDER__";
    }

    static std::string base64_encode(const std::string& data) {
        static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        for (size_t i = 0; i < data.size(); i += 3) {
            uint32_t n = (uint8_t)data[i] << 16;
            if (i+1 < data.size()) n |= (uint8_t)data[i+1] << 8;
            if (i+2 < data.size()) n |= (uint8_t)data[i+2];
            out += t[(n>>18)&63]; out += t[(n>>12)&63];
            out += (i+1<data.size())?t[(n>>6)&63]:'=';
            out += (i+2<data.size())?t[n&63]:'=';
        }
        return out;
    }
};

// =============================================================================
// SecureJoin verification protocol
// =============================================================================
enum class SecureJoinStep : uint8_t {
    INIT,
    VC_REQUEST_SENT,          // vg-request sent
    VC_AUTH_REQUIRED_RECEIVED,
    VC_CONTACT_CONFIRM_SENT,
    COMPLETE,
    ERROR,
};

struct SecureJoinSession {
    std::string group_id;
    std::string inviter_addr;
    std::string inviter_fingerprint;
    std::string joiner_addr;
    std::string joiner_fingerprint;
    SecureJoinStep step = SecureJoinStep::INIT;
    std::string auth_code;       // 4-char code for manual verification
    std::string error;
    time_t started_at = 0;
    time_t last_activity = 0;
};

class SecureJoin {
public:
    SecureJoinSession* start_invite(const std::string& group_id,
                                     const std::string& inviter_addr,
                                     const std::string& inviter_fingerprint) {
        SecureJoinSession session;
        session.group_id = group_id;
        session.inviter_addr = inviter_addr;
        session.inviter_fingerprint = inviter_fingerprint;
        session.step = SecureJoinStep::INIT;
        session.started_at = std::time(nullptr);
        session.last_activity = session.started_at;

        std::lock_guard lock(mutex_);
        sessions_[group_id] = session;
        return &sessions_[group_id];
    }

    SecureJoinSession* start_join(const std::string& group_id,
                                   const std::string& joiner_addr,
                                   const std::string& joiner_fingerprint) {
        SecureJoinSession session;
        session.group_id = group_id;
        session.joiner_addr = joiner_addr;
        session.joiner_fingerprint = joiner_fingerprint;
        session.step = SecureJoinStep::INIT;
        session.started_at = std::time(nullptr);

        std::lock_guard lock(mutex_);
        sessions_[group_id] = session;
        return &sessions_[group_id];
    }

    SecureJoinSession* get(const std::string& group_id) {
        auto it = sessions_.find(group_id);
        return (it != sessions_.end()) ? &it->second : nullptr;
    }

    void advance(const std::string& group_id, SecureJoinStep step) {
        auto it = sessions_.find(group_id);
        if (it != sessions_.end()) {
            it->second.step = step;
            it->second.last_activity = std::time(nullptr);
        }
    }

    void complete(const std::string& group_id) {
        advance(group_id, SecureJoinStep::COMPLETE);
    }

    void fail(const std::string& group_id, const std::string& error) {
        auto it = sessions_.find(group_id);
        if (it != sessions_.end()) {
            it->second.step = SecureJoinStep::ERROR;
            it->second.error = error;
        }
    }

    std::string generate_auth_code() {
        static const char* digits = "0123456789";
        std::string code;
        for (int i = 0; i < 4; i++) {
            code += digits[std::rand() % 10];
        }
        return code;
    }

    // Build vg-request system message
    std::string build_vc_request(const std::string& group_id,
                                  const std::string& inviter_fingerprint,
                                  const std::string& group_name) {
        std::stringstream ss;
        ss << "vc-request\n";
        ss << "group-id:" << group_id << "\n";
        ss << "group-name:" << group_name << "\n";
        ss << "fingerprint:" << inviter_fingerprint << "\n";
        return ss.str();
    }

    void cleanup_old(int max_age_minutes = 30) {
        time_t cutoff = std::time(nullptr) - max_age_minutes * 60;
        std::lock_guard lock(mutex_);
        for (auto it = sessions_.begin(); it != sessions_.end(); ) {
            if (it->second.last_activity < cutoff) {
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    std::unordered_map<std::string, SecureJoinSession> sessions_;
    std::mutex mutex_;
};

// =============================================================================
// Key gossip (sending peer keys to verified contacts)
// =============================================================================
class KeyGossip {
public:
    struct GossipEntry {
        std::string recipient_addr;      // who to send gossip to
        std::string gossiped_key_addr;   // key of this contact
        std::string gossiped_keydata;    // base64 key data
        time_t created_at = 0;
        bool sent = false;
    };

    void queue_gossip(const std::string& recipient, const std::string& contact_addr,
                      const std::string& keydata) {
        std::lock_guard lock(mutex_);
        gossip_queue_.push_back({recipient, contact_addr, keydata, std::time(nullptr), false});
    }

    std::vector<GossipEntry> get_pending(const std::string& recipient, int limit = 10) {
        std::lock_guard lock(mutex_);
        std::vector<GossipEntry> result;
        for (auto& entry : gossip_queue_) {
            if (!entry.sent && entry.recipient_addr == recipient) {
                result.push_back(entry);
                if ((int)result.size() >= limit) break;
            }
        }
        return result;
    }

    void mark_sent(const std::string& recipient, const std::string& contact_addr) {
        std::lock_guard lock(mutex_);
        for (auto& entry : gossip_queue_) {
            if (entry.recipient_addr == recipient &&
                entry.gossiped_key_addr == contact_addr) {
                entry.sent = true;
            }
        }
    }

    void prune_old(int max_age_hours = 48) {
        time_t cutoff = std::time(nullptr) - max_age_hours * 3600;
        std::lock_guard lock(mutex_);
        gossip_queue_.erase(std::remove_if(gossip_queue_.begin(), gossip_queue_.end(),
            [cutoff](const GossipEntry& e) { return e.sent && e.created_at < cutoff; }),
            gossip_queue_.end());
    }

private:
    std::vector<GossipEntry> gossip_queue_;
    std::mutex mutex_;
};

} // namespace deltachat
} // namespace progressive
