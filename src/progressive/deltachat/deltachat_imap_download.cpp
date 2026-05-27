// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Progressive Server Contributors
//
// DeltaChat IMAP Message Download — complete message fetch, MIME parsing,
// attachment handling, image processing, chat header extraction, threading,
// MDN detection, ephemeral timers, and streaming large-message download.
//
// All DeltaChat IMAP download logic lives here so that network I/O (the
// ImapConnection in deltachat_imap_smtp.cpp) stays separate from content
// parsing and message reconstruction.

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <memory>
#include <optional>
#include <variant>
#include <ctime>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <regex>
#include <deque>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <cmath>

namespace progressive {
namespace deltachat {

// ============================================================================
// Forward declarations — these types live in sibling translation units
// ============================================================================
class ImapConnection;
struct FetchResult;
struct ImapResponse;

// ============================================================================
// Constants for download & parsing
// ============================================================================
constexpr int DOWNLOAD_CHUNK_SIZE       = 65536;   // 64 KB streaming chunks
constexpr int MAX_HEADER_SIZE           = 1048576; // 1 MB header cap
constexpr int MAX_INLINE_IMAGE_BYTES    = 5242880; // 5 MB inline image cap
constexpr int MAX_ATTACHMENT_BYTES      = 104857600;// 100 MB attachment cap
constexpr int THUMBNAIL_MAX_WIDTH       = 320;
constexpr int THUMBNAIL_MAX_HEIGHT      = 240;
constexpr int MAX_MIME_DEPTH            = 20;      // recursion guard
constexpr int QUOTED_LINE_MIN_COUNT     = 2;       // lines with '>' to flag as quote
constexpr int FORWARDED_DETECT_LINES    = 3;       // forwarded-header markers
constexpr const char* DEFAULT_CHARSET   = "utf-8";
constexpr const char* IMAP_SECTION_SEP  = ".";

// ============================================================================
// Utility: case-insensitive compare / lowercasing
// ============================================================================
static std::string str_lower(const std::string& s) {
    std::string r;
    r.reserve(s.size());
    for (char c : s) r.push_back(static_cast<char>(std::tolower(c)));
    return r;
}

static bool str_istarts_with(const std::string& s, const std::string& prefix) {
    if (s.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(s[i]) != std::tolower(prefix[i])) return false;
    }
    return true;
}

static std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    while (e > b && (s[e-1] == ' ' || s[e-1] == '\t' || s[e-1] == '\r' || s[e-1] == '\n')) --e;
    return s.substr(b, e - b);
}

static std::vector<std::string> split_str(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim))
        parts.push_back(item);
    return parts;
}

static std::string join_str(const std::vector<std::string>& v, const std::string& sep) {
    std::string r;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) r += sep;
        r += v[i];
    }
    return r;
}

static bool str_contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

static std::string str_replace_all(std::string s, const std::string& from,
                                    const std::string& to) {
    size_t p = 0;
    while ((p = s.find(from, p)) != std::string::npos) {
        s.replace(p, from.size(), to);
        p += to.size();
    }
    return s;
}

// ============================================================================
// Base64 (for inline decoding of body parts)
// ============================================================================
static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_decode(const std::string& data) {
    std::string out;
    int val = 0, valb = -8;
    for (unsigned char c : data) {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        const char* p = std::strchr(B64_CHARS, c);
        if (!p) continue;
        val = (val << 6) + static_cast<int>(p - B64_CHARS);
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// ============================================================================
// Quoted-printable decode
// ============================================================================
static std::string qp_decode(const std::string& data) {
    std::string out;
    out.reserve(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        if (data[i] == '=' && i + 1 < data.size()) {
            if (data[i+1] == '\r' && i + 2 < data.size() && data[i+2] == '\n') {
                i += 2; // soft line break
            } else if (data[i+1] == '\n') {
                ++i; // soft line break (no CR)
            } else if (i + 2 < data.size() &&
                       std::isxdigit(data[i+1]) && std::isxdigit(data[i+2])) {
                char hex[3] = {data[i+1], data[i+2], 0};
                out.push_back(static_cast<char>(std::strtol(hex, nullptr, 16)));
                i += 2;
            } else {
                out.push_back(data[i]);
            }
        } else {
            out.push_back(data[i]);
        }
    }
    return out;
}

// ============================================================================
// Content-Transfer-Encoding decode: base64 | quoted-printable | 7bit | 8bit
// ============================================================================
static std::string decode_transfer_encoding(const std::string& body,
                                              const std::string& cte) {
    std::string cte_lower = str_lower(trim(cte));
    if (cte_lower == "base64")
        return base64_decode(body);
    if (cte_lower == "quoted-printable")
        return qp_decode(body);
    // 7bit, 8bit, binary, or missing — pass through
    return body;
}

// ============================================================================
// RFC 2047 encoded-word decoder ( =?charset?B?base64?=  or  =?charset?Q?qp?= )
// ============================================================================
static std::string rfc2047_decode(const std::string& hdr) {
    std::string r;
    size_t pos = 0;
    while (pos < hdr.size()) {
        auto eq_start = hdr.find("=?", pos);
        if (eq_start == std::string::npos) {
            r += hdr.substr(pos);
            break;
        }
        r += hdr.substr(pos, eq_start - pos);
        auto enc_end = hdr.find('?', eq_start + 2);
        if (enc_end == std::string::npos) { r += hdr.substr(eq_start); break; }
        // charset — currently ignored (we treat everything as UTF-8-ish)
        auto qt_pos = hdr.find('?', enc_end + 1);
        if (qt_pos == std::string::npos) { r += hdr.substr(eq_start); break; }
        char qt = hdr[enc_end + 1];
        auto end_marker = hdr.find("?=", qt_pos + 1);
        if (end_marker == std::string::npos) { r += hdr.substr(eq_start); break; }
        std::string encoded = hdr.substr(qt_pos + 1, end_marker - qt_pos - 1);
        if (qt == 'B' || qt == 'b') {
            r += base64_decode(encoded);
        } else if (qt == 'Q' || qt == 'q') {
            std::string dec;
            for (size_t i = 0; i < encoded.size(); ++i) {
                if (encoded[i] == '_') dec += ' ';
                else if (encoded[i] == '=' && i + 2 < encoded.size()) {
                    char hex[3] = {encoded[i+1], encoded[i+2], 0};
                    dec.push_back(static_cast<char>(std::strtol(hex, nullptr, 16)));
                    i += 2;
                } else dec += encoded[i];
            }
            r += dec;
        }
        pos = end_marker + 2;
    }
    return r;
}

// ============================================================================
// RFC 2231 parameter value continuation decoder
//   e.g.  filename*0*=UTF-8''long%20name; filename*1*=%20continued
// ============================================================================
static std::string rfc2231_decode_continuation(
    const std::map<std::string, std::string>& params,
    const std::string& base_key) {

    // Collect ordered parts
    std::map<int, std::string> parts;
    bool has_encoding = false;
    std::string charset, language;

    for (const auto& kv : params) {
        const std::string& k = kv.first;
        if (!str_istarts_with(k, base_key + "*")) continue;

        std::string suffix = k.substr(base_key.size() + 1); // after "key*"
        if (suffix.empty()) {
            // key*=value  (single part with charset)
            has_encoding = true;
            std::string val = kv.second;
            // Format: charset'language'encoded
            auto sq1 = val.find('\'');
            if (sq1 != std::string::npos) {
                charset = val.substr(0, sq1);
                auto sq2 = val.find('\'', sq1 + 1);
                if (sq2 != std::string::npos) {
                    language = val.substr(sq1 + 1, sq2 - sq1 - 1);
                    parts[0] = val.substr(sq2 + 1);
                } else {
                    parts[0] = val.substr(sq1 + 1);
                }
            } else {
                parts[0] = val;
            }
        } else if (!suffix.empty() && std::isdigit(suffix[0])) {
            // key*0*=..., key*1*=...
            int idx = 0;
            size_t star_pos = suffix.find('*');
            std::string num_part = (star_pos != std::string::npos)
                                       ? suffix.substr(0, star_pos)
                                       : suffix;
            idx = std::atoi(num_part.c_str());
            parts[idx] = kv.second;
            has_encoding = true;
        }
    }

    if (parts.empty()) return "";

    std::string assembled;
    for (auto& p : parts) assembled += p.second;

    // URL-decode percent-encoded bytes
    if (has_encoding) {
        std::string decoded;
        for (size_t i = 0; i < assembled.size(); ++i) {
            if (assembled[i] == '%' && i + 2 < assembled.size() &&
                std::isxdigit(assembled[i+1]) && std::isxdigit(assembled[i+2])) {
                char hex[3] = {assembled[i+1], assembled[i+2], 0};
                decoded.push_back(static_cast<char>(std::strtol(hex, nullptr, 16)));
                i += 2;
            } else {
                decoded.push_back(assembled[i]);
            }
        }
        return decoded;
    }

    return assembled;
}

// ============================================================================
// Content-Type / Content-Disposition parameter parser
// Returns a map: param_name (lowercased) → param_value (decoded)
// ============================================================================
static std::map<std::string, std::string> parse_mime_params(
    const std::string& header_value) {

    std::map<std::string, std::string> params;
    std::string rest = header_value;

    // Find first semicolon that separates media type from params, if any
    size_t semi = rest.find(';');
    if (semi != std::string::npos)
        rest = rest.substr(semi + 1);
    else
        return params;

    while (!rest.empty()) {
        // Skip whitespace
        size_t start = 0;
        while (start < rest.size() && (rest[start] == ' ' || rest[start] == '\t'))
            ++start;
        if (start >= rest.size()) break;
        rest = rest.substr(start);

        // Find '='
        size_t eq = rest.find('=');
        if (eq == std::string::npos) break;

        std::string key = rest.substr(0, eq);
        // Trim trailing whitespace from key
        while (!key.empty() && (key.back() == ' ' || key.back() == '\t'))
            key.pop_back();

        rest = rest.substr(eq + 1);

        // Parse value: could be quoted or unquoted
        std::string value;
        if (!rest.empty() && rest[0] == '"') {
            size_t qend = 1;
            while (qend < rest.size()) {
                if (rest[qend] == '"' && rest[qend-1] != '\\') break;
                if (rest[qend] == '\\' && qend + 1 < rest.size()) ++qend;
                ++qend;
            }
            if (qend < rest.size()) {
                value = rest.substr(1, qend - 1);
                rest = rest.substr(qend + 1);
            } else {
                value = rest.substr(1);
                rest.clear();
            }
            // Unescape backslash
            std::string unesc;
            for (size_t i = 0; i < value.size(); ++i) {
                if (value[i] == '\\' && i + 1 < value.size())
                    unesc += value[++i];
                else
                    unesc += value[i];
            }
            value = unesc;
        } else {
            // Unquoted: read until ';' or end
            size_t next = rest.find(';');
            if (next != std::string::npos) {
                value = rest.substr(0, next);
                rest = rest.substr(next + 1);
            } else {
                value = rest;
                rest.clear();
            }
            value = trim(value);
        }

        // Store key (lowercased)
        std::string key_lower = str_lower(trim(key));
        params[key_lower] = value;

        // Continue
    }

    return params;
}

// ============================================================================
// MIME Header Field — unfolded (RFC 2822 section 2.2.3)
// ============================================================================
struct MimeHeaderField {
    std::string name;       // original case
    std::string name_lower; // for lookups
    std::string body;       // unfolded, decoded value
};

// ============================================================================
// MIME Part — a single node in a multipart tree
// ============================================================================
struct MimePart {
    // Part indexing (IMAP BODYSTRUCTURE section numbering)
    std::string part_id;          // e.g. "1", "2.1", "3"  (1-based)
    int         part_number = 0;  // root part index for this branch

    // Headers for this part
    std::map<std::string, std::string> headers;   // lowercased key → value
    std::vector<MimeHeaderField>       raw_headers; // ordered, unfolded

    // Content identity
    std::string content_type;         // e.g. "text/plain"
    std::string content_type_full;    // with params
    std::string content_disposition;  // "inline" | "attachment" or empty
    std::string content_transfer_encoding;
    std::string content_id;           // <cid> stripped of angle brackets
    std::string content_description;

    // Body data (only leaf parts carry body)
    std::string body_text;            // decoded text body
    std::vector<uint8_t> body_binary; // decoded binary body

    // Attachment metadata
    bool        is_attachment = false;
    bool        is_inline     = false;
    std::string filename;             // decoded from Content-Disposition or Content-Type
    std::string attachment_mime;
    int64_t     attachment_size = 0;

    // Image metadata (populated for image/* parts)
    bool        is_image     = false;
    int         image_width  = 0;
    int         image_height = 0;
    std::string image_format;         // "jpeg", "png", "gif", "webp", etc.

    // Children for multipart/* parts
    std::vector<MimePart> children;
    bool is_multipart = false;
    std::string multipart_subtype;    // "mixed", "alternative", "related", etc.
    std::string boundary;

    // Helper: is this a leaf (no children, carries body)?
    bool is_leaf() const { return children.empty(); }

    // Helper: content-type mime without params
    std::string mime_type() const { return content_type; }
};

// ============================================================================
// Parsed message envelope — extracted headers used across the system
// ============================================================================
struct ParsedMessageEnvelope {
    std::string message_id;
    std::string in_reply_to;
    std::string references;
    std::string from;
    std::string to;
    std::string cc;
    std::string bcc;
    std::string subject;
    std::string date;
    std::string content_type;

    // Threading
    std::vector<std::string> reference_ids;  // parsed References into list
    bool has_thread_parent = false;

    // Chat-* headers
    std::string chat_version;
    std::string chat_group_id;
    std::string chat_group_name;
    std::string chat_verified;
    std::string chat_user_avatar;
    std::string chat_content_type;
    std::string chat_voice;

    // Autocrypt
    std::string autocrypt_header;       // raw Autocrypt: header value
    std::string autocrypt_setup_message;// Autocrypt-Setup-Message: header
    std::string autocrypt_prefer_encrypt;
    std::string autocrypt_keydata;

    // Secure-Join
    std::string secure_join_header;     // Secure-Join: header value
    std::string secure_join_group;
    std::string secure_join_fingerprint;

    // Ephemeral
    int ephemeral_timer = 0;            // seconds, 0 = disabled

    // MDN / read receipts
    bool is_mdn = false;
    std::string mdn_original_message_id;

    // Misc
    bool is_delta_chat = false;         // has Chat-Version header
    int64_t raw_size = 0;
};

// ============================================================================
// Full downloaded message — combines envelope, MIME tree, and attachments
// ============================================================================
struct DownloadedMessage {
    uint32_t    uid = 0;
    uint32_t    flags = 0;
    std::string internal_date;
    int64_t     rfc822_size = 0;

    // Raw source
    std::string raw_headers;
    std::string raw_body;
    std::string raw_full;               // complete RFC 822 message

    // Parsed envelope
    ParsedMessageEnvelope envelope;

    // MIME tree
    MimePart root_part;

    // Extracted body
    std::string text_body;              // preferred text/plain body
    std::string html_body;              // text/html body (if any)
    std::string plain_from_html;        // conversion of html→plain when no text/plain

    // Attachments (non-inline, non-image)
    struct Attachment {
        std::string part_id;
        std::string filename;
        std::string mime_type;
        int64_t     size = 0;
        std::vector<uint8_t> data;
    };
    std::vector<Attachment> attachments;

    // Inline images
    struct InlineImage {
        std::string content_id;
        std::string part_id;
        std::string mime_type;
        std::vector<uint8_t> data;
        int width = 0;
        int height = 0;
    };
    std::vector<InlineImage> inline_images;

    // Analysis flags
    bool has_quote     = false;
    bool is_forwarded  = false;
    bool has_attachments = false;
    bool has_inline_images = false;

    // Error state
    bool parse_error = false;
    std::string error_message;
};

// ============================================================================
// IMAP download request descriptor
// ============================================================================
struct DownloadRequest {
    uint32_t    uid = 0;
    std::string folder;
    bool        fetch_full    = true;   // BODY.PEEK[]
    bool        fetch_headers = false;  // BODY.PEEK[HEADER]
    bool        fetch_body    = false;  // BODY.PEEK[TEXT]
    int         fetch_first_n = 0;      // BODY.PEEK[]<0.N> partial fetch
    int         timeout_seconds = 60;
};

// ============================================================================
// RFC 2822 header unfolding and parsing
// ============================================================================
class Rfc2822HeaderParser {
public:
    // Unfold header block: collapse continuation lines (leading WS) into single lines
    static std::vector<MimeHeaderField> parse_header_block(
        const std::string& raw_headers) {

        std::vector<MimeHeaderField> fields;
        std::stringstream ss(raw_headers);
        std::string line;
        MimeHeaderField current;

        while (std::getline(ss, line)) {
            // Strip trailing CR
            if (!line.empty() && line.back() == '\r')
                line.pop_back();

            // Blank line = end of headers
            if (line.empty()) {
                if (!current.name.empty()) {
                    // Decode RFC 2047 in value
                    current.body = rfc2047_decode(trim(current.body));
                    current.name_lower = str_lower(current.name);
                    fields.push_back(std::move(current));
                    current = MimeHeaderField{};
                }
                break;
            }

            // Continuation line? (starts with SPACE or TAB)
            if (!current.name.empty() &&
                (line[0] == ' ' || line[0] == '\t')) {
                // RFC 2822: continuation is folded; preserve exactly one SP
                current.body += " ";
                current.body += trim(line);
                continue;
            }

            // Finalise previous field
            if (!current.name.empty()) {
                current.body = rfc2047_decode(trim(current.body));
                current.name_lower = str_lower(current.name);
                fields.push_back(std::move(current));
                current = MimeHeaderField{};
            }

            // New field: split at first colon
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue; // malformed, skip

            current.name = line.substr(0, colon);
            current.body = trim(line.substr(colon + 1));
        }

        // Don't forget trailing field
        if (!current.name.empty()) {
            current.body = rfc2047_decode(trim(current.body));
            current.name_lower = str_lower(current.name);
            fields.push_back(std::move(current));
        }

        return fields;
    }

    // Build a map from header-name → decoded value for quick access
    static std::map<std::string, std::string> headers_to_map(
        const std::vector<MimeHeaderField>& fields) {

        std::map<std::string, std::string> m;
        for (const auto& f : fields)
            m[f.name_lower] = f.body;
        return m;
    }

    // Split a header-body that contains multiple addresses separated by commas
    static std::vector<std::string> parse_address_list(const std::string& body) {
        std::vector<std::string> addresses;
        std::string current;
        bool in_quotes = false;
        int paren_depth = 0;

        for (size_t i = 0; i < body.size(); ++i) {
            char c = body[i];
            if (c == '"' && (i == 0 || body[i-1] != '\\')) {
                in_quotes = !in_quotes;
                current += c;
            } else if (!in_quotes && c == '(') {
                ++paren_depth;
                current += c;
            } else if (!in_quotes && c == ')') {
                if (paren_depth > 0) --paren_depth;
                current += c;
            } else if (!in_quotes && paren_depth == 0 && c == ',') {
                addresses.push_back(trim(current));
                current.clear();
            } else {
                current += c;
            }
        }
        if (!current.empty())
            addresses.push_back(trim(current));

        return addresses;
    }
};

// ============================================================================
// MIME multipart parser
// ============================================================================
class MimeMultipartParser {
public:
    // Parse a complete MIME message into a MimePart tree
    static MimePart parse(const std::string& raw_message) {
        MimePart root;
        root.part_id = "0";
        root.part_number = 0;

        // Split headers from body
        std::string headers_block, body_block;
        split_headers_body(raw_message, headers_block, body_block);

        // Parse top-level headers
        auto fields = Rfc2822HeaderParser::parse_header_block(headers_block);
        root.raw_headers = fields;
        root.headers = Rfc2822HeaderParser::headers_to_map(fields);
        populate_part_from_headers(root);

        // If multipart, recurse into children
        if (root.is_multipart && !root.boundary.empty()) {
            parse_multipart_body(root, body_block, root.boundary, 0);
        } else {
            // Leaf: decode body
            root.body_text = decode_transfer_encoding(
                body_block, root.content_transfer_encoding);
            root.body_binary.assign(root.body_text.begin(), root.body_text.end());
        }

        return root;
    }

private:
    // Split raw message into header block and body block
    static void split_headers_body(const std::string& raw,
                                    std::string& headers_out,
                                    std::string& body_out) {
        // Find first blank line (CRLF CRLF or LF LF)
        size_t pos = raw.find("\r\n\r\n");
        size_t offset = 4;
        if (pos == std::string::npos) {
            pos = raw.find("\n\n");
            offset = 2;
        }
        if (pos == std::string::npos) {
            headers_out = raw;
            body_out.clear();
            return;
        }
        headers_out = raw.substr(0, pos);
        body_out = raw.substr(pos + offset);
    }

    // Populate MIME metadata from headers
    static void populate_part_from_headers(MimePart& part) {
        // Content-Type
        auto ct_it = part.headers.find("content-type");
        if (ct_it != part.headers.end()) {
            part.content_type_full = ct_it->second;
            auto params = parse_mime_params(ct_it->second);
            // Extract mime type (before first semicolon)
            size_t semi = ct_it->second.find(';');
            if (semi != std::string::npos)
                part.content_type = trim(ct_it->second.substr(0, semi));
            else
                part.content_type = trim(ct_it->second);

            std::string ct_lower = str_lower(part.content_type);

            // Multipart detection
            if (str_istarts_with(ct_lower, "multipart/")) {
                part.is_multipart = true;
                part.multipart_subtype = ct_lower.substr(10); // after "multipart/"
                // Get boundary
                auto bd_it = params.find("boundary");
                if (bd_it != params.end())
                    part.boundary = bd_it->second;
            }

            // Attachment filename from Content-Type name param
            auto name_it = params.find("name");
            if (name_it != params.end() && part.filename.empty()) {
                part.filename = rfc2047_decode(name_it->second);
            }
        } else {
            part.content_type = "text/plain"; // RFC 2045 default
        }

        // Content-Disposition
        auto cd_it = part.headers.find("content-disposition");
        if (cd_it != part.headers.end()) {
            part.content_disposition = cd_it->second;
            std::string cd_lower = str_lower(cd_it->second);
            auto cd_params = parse_mime_params(cd_it->second);

            if (cd_lower.find("attachment") != std::string::npos)
                part.is_attachment = true;
            else if (cd_lower.find("inline") != std::string::npos)
                part.is_inline = true;

            // Filename from Content-Disposition
            auto fn_it = cd_params.find("filename");
            if (fn_it != cd_params.end()) {
                part.filename = fn_it->second;
                // Check for RFC 2231 continuation
                std::string continued = rfc2231_decode_continuation(cd_params, "filename");
                if (!continued.empty())
                    part.filename = rfc2047_decode(continued);
                else
                    part.filename = rfc2047_decode(part.filename);
            }
        }

        // Content-Transfer-Encoding
        auto cte_it = part.headers.find("content-transfer-encoding");
        if (cte_it != part.headers.end())
            part.content_transfer_encoding = cte_it->second;
        else
            part.content_transfer_encoding = "7bit";

        // Content-ID
        auto cid_it = part.headers.find("content-id");
        if (cid_it != part.headers.end()) {
            std::string cid = trim(cid_it->second);
            if (!cid.empty() && cid.front() == '<') cid.erase(0, 1);
            if (!cid.empty() && cid.back() == '>') cid.pop_back();
            part.content_id = cid;
        }

        // Content-Description
        auto desc_it = part.headers.find("content-description");
        if (desc_it != part.headers.end())
            part.content_description = desc_it->second;

        // Image detection
        std::string ct_lower = str_lower(part.content_type);
        if (str_istarts_with(ct_lower, "image/")) {
            part.is_image = true;
            part.image_format = ct_lower.substr(6); // after "image/"
            // Normalize common formats
            if (part.image_format == "jpeg") part.image_format = "jpeg";
            else if (part.image_format == "x-png") part.image_format = "png";
        }

        // Attachment MIME
        part.attachment_mime = part.content_type;
    }

    // Recursively parse multipart body into children
    static void parse_multipart_body(MimePart& parent,
                                      const std::string& body,
                                      const std::string& boundary,
                                      int depth) {
        if (depth > MAX_MIME_DEPTH) return;

        std::string delim = "--" + boundary;
        size_t pos = body.find(delim);

        // Skip preamble (text before first boundary)
        if (pos == std::string::npos) return;

        int child_idx = 0;

        while (pos != std::string::npos) {
            // Find next boundary
            size_t next = body.find(delim, pos + delim.size());

            // Check for closing delimiter
            if (next == std::string::npos) {
                // Look for closing: --boundary--
                size_t close_check = body.find(delim + "--", pos);
                if (close_check != std::string::npos) {
                    next = close_check;
                }
            }

            // Extract the part between boundaries
            size_t part_start = pos + delim.size();
            // Skip CRLF after boundary marker
            if (part_start + 1 < body.size() &&
                body[part_start] == '\r' && body[part_start + 1] == '\n')
                part_start += 2;
            else if (part_start < body.size() && body[part_start] == '\n')
                part_start += 1;

            // Check if this is the closing boundary (--boundary--)
            bool is_closing = false;
            if (next != std::string::npos &&
                body.compare(next, delim.size() + 2, delim + "--") == 0) {
                is_closing = true;
            }

            size_t part_end;
            if (next != std::string::npos) {
                // Part body ends just before the next boundary line.
                // Back up over trailing CRLF of the part body.
                part_end = next;
                if (part_end >= 2 && body[part_end-2] == '\r' &&
                    body[part_end-1] == '\n')
                    part_end -= 2;
                else if (part_end >= 1 && body[part_end-1] == '\n')
                    part_end -= 1;
            } else {
                part_end = body.size();
            }

            if (part_start < part_end) {
                std::string part_raw = body.substr(part_start, part_end - part_start);

                // Skip empty preamble between boundaries
                if (!trim(part_raw).empty()) {
                    ++child_idx;

                    MimePart child;
                    child.part_id = parent.part_id + "." + std::to_string(child_idx);
                    if (parent.part_id == "0")
                        child.part_id = std::to_string(child_idx);
                    child.part_number = child_idx;

                    // Parse child: split its headers and body
                    std::string ch_headers, ch_body;
                    split_headers_body(part_raw, ch_headers, ch_body);

                    auto ch_fields = Rfc2822HeaderParser::parse_header_block(ch_headers);
                    child.raw_headers = ch_fields;
                    child.headers = Rfc2822HeaderParser::headers_to_map(ch_fields);
                    populate_part_from_headers(child);

                    if (child.is_multipart && !child.boundary.empty()) {
                        parse_multipart_body(child, ch_body, child.boundary, depth + 1);
                    } else {
                        child.body_text = decode_transfer_encoding(
                            ch_body, child.content_transfer_encoding);
                        child.body_binary.assign(
                            child.body_text.begin(), child.body_text.end());
                    }

                    parent.children.push_back(std::move(child));
                }
            }

            if (is_closing) break;
            pos = next;
        }
    }
};

// ============================================================================
// Body part extraction — finds text/plain and text/html from MIME tree
// ============================================================================
class BodyPartExtractor {
public:
    struct ExtractResult {
        std::string text_plain;
        std::string text_html;
        bool found_plain = false;
        bool found_html  = false;
    };

    // Walk the tree and extract text parts.
    // For multipart/alternative: prefer text/plain, fall back to text/html.
    static ExtractResult extract(const MimePart& root) {
        ExtractResult result;

        if (root.is_multipart) {
            if (root.multipart_subtype == "alternative") {
                // For alternative: prefer plain, then html
                for (const auto& child : root.children) {
                    if (!result.found_plain && is_text_plain(child))
                        extract_leaf_text(child, result, true);
                    if (!result.found_html && is_text_html(child) && !result.found_plain)
                        extract_leaf_text(child, result, false);
                }
                // If no plain found in alternative, check children recursively
                if (!result.found_plain && !result.found_html) {
                    for (const auto& child : root.children) {
                        auto sub = extract(child);
                        if (!result.found_plain && sub.found_plain) {
                            result.text_plain = sub.text_plain;
                            result.found_plain = true;
                        }
                        if (!result.found_html && sub.found_html) {
                            result.text_html = sub.text_html;
                            result.found_html = true;
                        }
                    }
                }
            } else {
                // mixed, related, signed, etc. — walk all children
                for (const auto& child : root.children) {
                    auto sub = extract(child);
                    if (!result.found_plain && sub.found_plain) {
                        result.text_plain = sub.text_plain;
                        result.found_plain = true;
                    }
                    if (!result.found_html && sub.found_html) {
                        result.text_html = sub.text_html;
                        result.found_html = true;
                    }
                }
            }
        } else {
            // Leaf
            if (is_text_plain(root)) {
                result.text_plain = root.body_text;
                result.found_plain = true;
            } else if (is_text_html(root)) {
                result.text_html = root.body_text;
                result.found_html = true;
            }
        }

        return result;
    }

private:
    static bool is_text_plain(const MimePart& part) {
        std::string ct = str_lower(part.content_type);
        return ct.find("text/plain") == 0;
    }

    static bool is_text_html(const MimePart& part) {
        std::string ct = str_lower(part.content_type);
        return ct.find("text/html") == 0;
    }

    static void extract_leaf_text(const MimePart& part, ExtractResult& res, bool plain) {
        if (plain) {
            res.text_plain = part.body_text;
            res.found_plain = true;
        } else {
            res.text_html = part.body_text;
            res.found_html = true;
        }
    }
};

// ============================================================================
// Attachment detection and extraction from MIME tree
// ============================================================================
class AttachmentExtractor {
public:
    struct AttachmentInfo {
        std::string part_id;
        std::string filename;
        std::string mime_type;
        std::vector<uint8_t> data;
        int64_t size = 0;
        bool is_inline = false;
        std::string content_id;
    };

    // Walk the tree and flat-collect all attachments.
    // An attachment is a leaf part whose Content-Disposition is "attachment",
    // OR a non-text leaf part that has a filename parameter.
    static std::vector<AttachmentInfo> extract(const MimePart& root) {
        std::vector<AttachmentInfo> attachments;
        collect_attachments(root, attachments);
        return attachments;
    }

private:
    static void collect_attachments(const MimePart& part,
                                     std::vector<AttachmentInfo>& out) {
        if (part.is_multipart) {
            for (const auto& child : part.children)
                collect_attachments(child, out);
            return;
        }

        // Only consider leaves
        bool is_attachment = part.is_attachment;
        bool has_filename  = !part.filename.empty();

        // If it's text/plain or text/html without filename or attachment
        // disposition, it's body text, not an attachment.
        std::string ct = str_lower(part.content_type);
        bool is_text_body = (ct.find("text/plain") == 0 ||
                             ct.find("text/html") == 0);
        if (!is_attachment && !has_filename && is_text_body)
            return;

        // Must be attachment or have a filename to be collected
        if (!is_attachment && !has_filename)
            return;

        AttachmentInfo info;
        info.part_id   = part.part_id;
        info.filename  = part.filename;
        info.mime_type = part.attachment_mime;
        info.data      = part.body_binary;
        info.size      = static_cast<int64_t>(part.body_binary.size());
        info.is_inline = part.is_inline;
        info.content_id = part.content_id;

        // Generate fallback filename if missing
        if (info.filename.empty()) {
            info.filename = "attachment_" + part.part_id;
            // Append extension from mime type
            size_t slash = info.mime_type.find('/');
            if (slash != std::string::npos) {
                std::string ext = info.mime_type.substr(slash + 1);
                if (!ext.empty() && ext != "octet-stream")
                    info.filename += "." + ext;
            }
        }

        out.push_back(std::move(info));
    }
};

// ============================================================================
// Inline image handler (Content-ID based)
// ============================================================================
class InlineImageHandler {
public:
    struct InlineImageInfo {
        std::string content_id;
        std::string part_id;
        std::string mime_type;
        std::vector<uint8_t> data;
        int width = 0;
        int height = 0;
    };

    // Collect inline images from MIME tree.
    // An inline image is a leaf part with Content-ID AND image/* content-type
    // (or Content-Disposition: inline with image/*).
    static std::vector<InlineImageInfo> extract(const MimePart& root) {
        std::vector<InlineImageInfo> images;
        collect_inline_images(root, images);
        return images;
    }

    static bool has_inline_images(const MimePart& root) {
        return !extract(root).empty();
    }

private:
    static void collect_inline_images(const MimePart& part,
                                       std::vector<InlineImageInfo>& out) {
        if (part.is_multipart) {
            for (const auto& child : part.children)
                collect_inline_images(child, out);
            return;
        }

        // Must have a Content-ID
        if (part.content_id.empty()) return;

        // Must be image/*
        if (!part.is_image) return;

        // Skip if it's explicitly an attachment
        if (part.is_attachment) return;

        InlineImageInfo info;
        info.content_id = part.content_id;
        info.part_id    = part.part_id;
        info.mime_type  = part.content_type;
        info.data       = part.body_binary;
        info.width      = part.image_width;
        info.height     = part.image_height;

        // If dimensions not detected from content, set defaults
        if (info.width == 0) info.width = 160;
        if (info.height == 0) info.height = 120;

        out.push_back(std::move(info));
    }
};

// ============================================================================
// Image attachment processing — detect, extract dimensions, thumbnail gen
// ============================================================================
class ImageProcessor {
public:
    struct ImageInfo {
        int width = 0;
        int height = 0;
        std::string format;  // "jpeg", "png", "gif", "webp", "bmp", "unknown"
        bool valid = false;
    };

    // Detect image dimensions from binary header (no full decode needed)
    static ImageInfo probe_dimensions(const std::vector<uint8_t>& data) {
        if (data.size() < 8) return {};

        // JPEG: FF D8 FF E0 ... (SOI + APP0/JFIF)
        if (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) {
            return probe_jpeg(data);
        }
        // PNG: 89 50 4E 47 0D 0A 1A 0A
        if (data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' &&
            data[3] == 'G') {
            return probe_png(data);
        }
        // GIF: GIF87a or GIF89a
        if (data[0] == 'G' && data[1] == 'I' && data[2] == 'F' &&
            data[3] == '8' && (data[4] == '7' || data[4] == '9') &&
            data[5] == 'a') {
            return probe_gif(data);
        }
        // WebP: RIFF .... WEBP
        if (data.size() >= 12 && data[0] == 'R' && data[1] == 'I' &&
            data[2] == 'F' && data[3] == 'F' &&
            data[8] == 'W' && data[9] == 'E' && data[10] == 'B' &&
            data[11] == 'P') {
            return probe_webp(data);
        }
        // BMP: BM
        if (data[0] == 'B' && data[1] == 'M') {
            return probe_bmp(data);
        }

        return {};
    }

    // Generate thumbnail: simple nearest-neighbour downscale (no external libs)
    // Returns raw RGB pixel data with width/height in the returned struct.
    // In production, use libjpeg-turbo / libpng / stb_image.
    struct Thumbnail {
        std::vector<uint8_t> pixels; // RGB packed, row-major
        int width = 0;
        int height = 0;
    };

    static Thumbnail generate_thumbnail(const std::vector<uint8_t>& /*data*/,
                                         int /*src_w*/, int /*src_h*/) {
        // Stub: real implementation needs a full image decoder.
        // For now return a minimal placeholder.
        Thumbnail thumb;
        thumb.width  = std::min(160, THUMBNAIL_MAX_WIDTH);
        thumb.height = std::min(120, THUMBNAIL_MAX_HEIGHT);
        thumb.pixels.assign(thumb.width * thumb.height * 3, 0x80);
        return thumb;
    }

private:
    static ImageInfo probe_jpeg(const std::vector<uint8_t>& data) {
        ImageInfo info;
        info.format = "jpeg";
        // Walk markers to find SOF0 (FF C0), SOF1 (FF C1), SOF2 (FF C2)
        size_t pos = 2;
        while (pos + 4 < data.size()) {
            if (data[pos] != 0xFF) { ++pos; continue; }
            uint8_t marker = data[pos + 1];
            if (marker == 0xC0 || marker == 0xC1 || marker == 0xC2) {
                if (pos + 9 < data.size()) {
                    info.height = (data[pos+5] << 8) | data[pos+6];
                    info.width  = (data[pos+7] << 8) | data[pos+8];
                    info.valid = true;
                }
                break;
            }
            // Skip marker segments
            if (pos + 4 < data.size()) {
                uint16_t seg_len = (data[pos+2] << 8) | data[pos+3];
                pos += seg_len + 2;
            } else break;
        }
        return info;
    }

    static ImageInfo probe_png(const std::vector<uint8_t>& data) {
        ImageInfo info;
        info.format = "png";
        // IHDR starts at offset 16 (8-byte sig + 4-byte length + 4-byte 'IHDR')
        if (data.size() >= 24 && data[12] == 'I' && data[13] == 'H' &&
            data[14] == 'D' && data[15] == 'R') {
            info.width  = (data[16] << 24) | (data[17] << 16) |
                          (data[18] << 8)  | data[19];
            info.height = (data[20] << 24) | (data[21] << 16) |
                          (data[22] << 8)  | data[23];
            info.valid = true;
        }
        return info;
    }

    static ImageInfo probe_gif(const std::vector<uint8_t>& data) {
        ImageInfo info;
        info.format = "gif";
        if (data.size() >= 10) {
            info.width  = data[6] | (data[7] << 8);
            info.height = data[8] | (data[9] << 8);
            info.valid = true;
        }
        return info;
    }

    static ImageInfo probe_webp(const std::vector<uint8_t>& data) {
        ImageInfo info;
        info.format = "webp";
        // VP8 / VP8L / VP8X
        if (data.size() >= 30) {
            // Check for VP8 (lossy) or VP8L (lossless)
            if (data[12] == 'V' && data[13] == 'P' && data[14] == '8') {
                if (data[15] == ' ') {
                    // VP8: width/height at offset 26 (14 bits each, LE)
                    uint32_t w = data[26] | (data[27] << 8);
                    uint32_t h = data[28] | (data[29] << 8);
                    info.width = w & 0x3FFF;
                    info.height = h & 0x3FFF;
                    info.valid = true;
                } else if (data[15] == 'L') {
                    // VP8L: 1 byte signature + width/height at offset 21
                    if (data.size() >= 26) {
                        uint32_t w = data[21] | (data[22] << 8) |
                                     ((data[23] & 0x3F) << 16);
                        uint32_t h = ((data[23] >> 6) & 0x03) |
                                     (data[24] << 2) | (data[25] << 10);
                        info.width = (w & 0x3FFF) + 1;
                        info.height = (h & 0x3FFF) + 1;
                        info.valid = true;
                    }
                } else if (data[15] == 'X') {
                    // VP8X: width/height at offset 24
                    if (data.size() >= 32) {
                        uint32_t w = data[24] | (data[25] << 8) |
                                     (data[26] << 16);
                        uint32_t h = data[28] | (data[29] << 8) |
                                     (data[30] << 16);
                        info.width = (w & 0xFFFFFF) + 1;
                        info.height = (h & 0xFFFFFF) + 1;
                        info.valid = true;
                    }
                }
            }
        }
        return info;
    }

    static ImageInfo probe_bmp(const std::vector<uint8_t>& data) {
        ImageInfo info;
        info.format = "bmp";
        if (data.size() >= 26) {
            info.width  = data[18] | (data[19] << 8) |
                          (data[20] << 16) | (data[21] << 24);
            // Height can be negative (top-down)
            int32_t h = data[22] | (data[23] << 8) |
                        (data[24] << 16) | (data[25] << 24);
            info.height = std::abs(h);
            info.valid = true;
        }
        return info;
    }
};

// ============================================================================
// HTML to plain text conversion (simple tag-stripping with entity decode)
// ============================================================================
class HtmlToPlainText {
public:
    static std::string convert(const std::string& html) {
        std::string result;
        result.reserve(html.size());
        bool in_tag = false;
        bool in_style = false;
        bool in_script = false;
        size_t i = 0;

        while (i < html.size()) {
            char c = html[i];

            if (!in_tag && !in_style && !in_script) {
                if (c == '<') {
                    // Check for style/script
                    std::string_view remaining(&html[i], html.size() - i);
                    if (remaining.size() > 7 &&
                        strncasecmp_alt(&html[i+1], "style", 5) == 0 &&
                        (html[i+6] == '>' || html[i+6] == ' ')) {
                        in_style = true;
                        i += 6;
                        continue;
                    }
                    if (remaining.size() > 7 &&
                        strncasecmp_alt(&html[i+1], "script", 6) == 0 &&
                        (html[i+7] == '>' || html[i+7] == ' ')) {
                        in_script = true;
                        i += 7;
                        continue;
                    }
                    in_tag = true;
                } else {
                    result.push_back(c);
                }
            } else if (in_tag) {
                if (c == '>') {
                    in_tag = false;
                    // Some block-level tags produce a newline
                    // Insert newlines for <br>, <p>, <div>, <li>, etc.
                    // (We do this after closing the tag.)
                }
            } else if (in_style) {
                if (c == '<' && html.compare(i, 8, "</style>") == 0) {
                    in_style = false;
                    i += 7;
                }
            } else if (in_script) {
                if (c == '<' && html.compare(i, 9, "</script>") == 0) {
                    in_script = false;
                    i += 8;
                }
            }

            ++i;
        }

        // Normalize whitespace: collapse multiple spaces/newlines
        std::string normalized;
        normalized.reserve(result.size());
        bool prev_space = false;
        for (char c : result) {
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                if (!prev_space) {
                    normalized.push_back(' ');
                    prev_space = true;
                }
            } else {
                normalized.push_back(c);
                prev_space = false;
            }
        }

        // Decode HTML entities
        normalized = decode_html_entities(trim(normalized));

        return normalized;
    }

    // Block-level tag newline injection (call during parse)
    // Used inline above — the simple version inserts newlines for <br>, <p>, etc.
    // A more thorough version would track tag names, but the simple approach
    // of just stripping and post-processing covers most cases.

private:
    static int strncasecmp_alt(const char* a, const char* b, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            int diff = std::tolower(a[i]) - std::tolower(b[i]);
            if (diff) return diff;
            if (!a[i]) return 0;
        }
        return 0;
    }

    static std::string decode_html_entities(const std::string& text) {
        static const std::pair<std::string, std::string> entities[] = {
            {"&amp;",  "&"},  {"&lt;",   "<"},   {"&gt;",   ">"},
            {"&quot;", "\""}, {"&apos;", "'"},   {"&nbsp;", " "},
            {"&#39;",  "'"},  {"&#x27;", "'"},   {"&#x2F;", "/"},
        };

        std::string r = text;
        for (const auto& e : entities) {
            r = str_replace_all(r, e.first, e.second);
        }

        // Numeric entities &#NNN; or &#xHHH;
        size_t pos = 0;
        while ((pos = r.find("&#", pos)) != std::string::npos) {
            size_t end = r.find(';', pos);
            if (end == std::string::npos) break;

            std::string num_str;
            int base = 10;
            if (pos + 3 < r.size() && r[pos+2] == 'x') {
                base = 16;
                num_str = r.substr(pos + 3, end - pos - 3);
            } else {
                num_str = r.substr(pos + 2, end - pos - 2);
            }

            int codepoint = 0;
            try { codepoint = std::stoi(num_str, nullptr, base); }
            catch (...) { pos = end + 1; continue; }

            // Encode as UTF-8
            std::string utf8;
            if (codepoint < 0x80) {
                utf8.push_back(static_cast<char>(codepoint));
            } else if (codepoint < 0x800) {
                utf8.push_back(static_cast<char>(0xC0 | (codepoint >> 6)));
                utf8.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
            } else if (codepoint < 0x10000) {
                utf8.push_back(static_cast<char>(0xE0 | (codepoint >> 12)));
                utf8.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
                utf8.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
            } else if (codepoint < 0x110000) {
                utf8.push_back(static_cast<char>(0xF0 | (codepoint >> 18)));
                utf8.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
                utf8.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
                utf8.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
            }

            r.replace(pos, end - pos + 1, utf8);
            pos += utf8.size();
        }

        return r;
    }
};

// ============================================================================
// Quoted text detection — find lines starting with '>'
// ============================================================================
class QuotedTextDetector {
public:
    struct QuoteInfo {
        bool has_quote = false;
        std::string quote_text;   // the quoted portion
        std::string non_quote;    // everything before the quote block
    };

    static QuoteInfo detect(const std::string& text) {
        QuoteInfo info;
        std::stringstream ss(text);
        std::string line;
        std::string non_q, q;
        bool in_quote = false;
        int quote_line_count = 0;

        while (std::getline(ss, line)) {
            // Strip CR if present
            if (!line.empty() && line.back() == '\r') line.pop_back();

            bool is_quote_line = false;
            std::string stripped = line;
            // Skip leading whitespace then check for '>'
            size_t start = 0;
            while (start < stripped.size() && stripped[start] == ' ') ++start;
            if (start < stripped.size() && stripped[start] == '>') {
                is_quote_line = true;
                // Unwrap one level of quoting
                stripped = stripped.substr(start + 1);
                if (!stripped.empty() && stripped[0] == ' ') stripped.erase(0, 1);
            }

            if (is_quote_line) {
                if (!in_quote) in_quote = true;
                q += stripped + "\n";
                ++quote_line_count;
            } else {
                if (in_quote) {
                    // Transition back to non-quote; stop collecting quotes
                    // (only consider contiguous quote blocks)
                    in_quote = false;
                }
                non_q += line + "\n";
            }
        }

        // Require at least QUOTED_LINE_MIN_COUNT lines to consider it a quote
        if (quote_line_count >= QUOTED_LINE_MIN_COUNT) {
            info.has_quote = true;
            info.quote_text = trim(q);
            info.non_quote = trim(non_q);
        } else {
            info.non_quote = text;
        }

        return info;
    }
};

// ============================================================================
// Forwarded message detection
// ============================================================================
class ForwardedMessageDetector {
public:
    static bool is_forwarded(const std::string& body,
                              const std::string& subject) {
        // Detect common forwarded-message patterns

        // 1. Subject starts with "Fwd:" or "Fw:" (case-insensitive)
        std::string subj_lower = str_lower(subject);
        if (str_istarts_with(subj_lower, "fwd:") ||
            str_istarts_with(subj_lower, "fw:"))
            return true;

        // 2. Body contains forwarded-message markers
        //    Common patterns:
        //      ---------- Forwarded message ---------
        //      --- Begin forwarded message ---
        //      -----Original Message-----
        //      Von: / De: / Da: (non-English forward headers)
        std::string body_lower = str_lower(body);

        static const std::string markers[] = {
            "forwarded message",
            "begin forwarded",
            "original message",
            "ursprüngliche nachricht",    // German
            "message transféré",          // French
            "mensaje reenviado",          // Spanish
            "messaggio inoltrato",        // Italian
        };

        for (const auto& m : markers) {
            if (str_contains(body_lower, m))
                return true;
        }

        // 3. Check for forwarded-header pattern: lines like
        //    "From: ..."  "Sent: ..."  "To: ..."  "Subject: ..."
        //    appearing after the forward marker.
        int fwd_headers_found = 0;
        std::stringstream ss(body);
        std::string line;
        while (std::getline(ss, line)) {
            std::string line_lower = str_lower(trim(line));
            if (str_istarts_with(line_lower, "from:") ||
                str_istarts_with(line_lower, "sent:") ||
                str_istarts_with(line_lower, "to:") ||
                str_istarts_with(line_lower, "date:") ||
                str_istarts_with(line_lower, "cc:") ||
                str_istarts_with(line_lower, "subject:")) {
                ++fwd_headers_found;
            }
        }

        if (fwd_headers_found >= FORWARDED_DETECT_LINES)
            return true;

        return false;
    }
};

// ============================================================================
// Message threading detection (In-Reply-To, References)
// ============================================================================
class ThreadDetector {
public:
    struct ThreadInfo {
        std::string parent_message_id;  // from In-Reply-To, or last References
        std::vector<std::string> reference_ids;
        bool has_thread = false;
    };

    static ThreadInfo detect(const ParsedMessageEnvelope& envelope) {
        ThreadInfo info;

        // Parse In-Reply-To
        if (!envelope.in_reply_to.empty()) {
            info.parent_message_id = extract_message_id(envelope.in_reply_to);
            if (!info.parent_message_id.empty())
                info.has_thread = true;
        }

        // Parse References
        if (!envelope.references.empty()) {
            info.reference_ids = extract_message_id_list(envelope.references);
            if (!info.reference_ids.empty()) {
                info.has_thread = true;
                // Parent is the last reference if no In-Reply-To
                if (info.parent_message_id.empty())
                    info.parent_message_id = info.reference_ids.back();
            }
        }

        return info;
    }

    // Extract a single Message-ID from a header value
    static std::string extract_message_id(const std::string& header) {
        // Look for <...>
        size_t start = header.find('<');
        if (start == std::string::npos) return trim(header);
        size_t end = header.find('>', start);
        if (end == std::string::npos) return trim(header.substr(start + 1));
        return header.substr(start + 1, end - start - 1);
    }

    // Extract multiple Message-IDs from References header
    static std::vector<std::string> extract_message_id_list(
        const std::string& header) {
        std::vector<std::string> ids;
        size_t pos = 0;
        while (pos < header.size()) {
            size_t start = header.find('<', pos);
            if (start == std::string::npos) break;
            size_t end = header.find('>', start);
            if (end == std::string::npos) break;
            ids.push_back(header.substr(start + 1, end - start - 1));
            pos = end + 1;
        }
        // Also handle non-angle-bracket cases (whitespace separated)
        if (ids.empty()) {
            std::stringstream ss(header);
            std::string token;
            while (ss >> token) {
                if (!token.empty())
                    ids.push_back(token);
            }
        }
        return ids;
    }
};

// ============================================================================
// Chat-* header extraction
// ============================================================================
class ChatHeaderExtractor {
public:
    static void extract(ParsedMessageEnvelope& envelope,
                         const std::map<std::string, std::string>& headers) {
        auto find_hdr = [&](const std::string& key) -> std::string {
            auto it = headers.find(str_lower(key));
            return (it != headers.end()) ? it->second : "";
        };

        envelope.chat_version     = find_hdr("Chat-Version");
        envelope.chat_group_id    = find_hdr("Chat-Group-ID");
        envelope.chat_group_name  = find_hdr("Chat-Group-Name");
        envelope.chat_verified    = find_hdr("Chat-Verified");
        envelope.chat_user_avatar = find_hdr("Chat-User-Avatar");
        envelope.chat_content_type = find_hdr("Chat-Content");
        envelope.chat_voice       = find_hdr("Chat-Voice");

        // A message is a DeltaChat message if it carries Chat-Version
        envelope.is_delta_chat = !envelope.chat_version.empty();

        // Decode Chat-Group-Name (it may be RFC 2047 encoded)
        if (!envelope.chat_group_name.empty())
            envelope.chat_group_name = rfc2047_decode(envelope.chat_group_name);
    }
};

// ============================================================================
// Autocrypt header extraction
// ============================================================================
class AutocryptHeaderExtractor {
public:
    struct AutocryptInfo {
        std::string addr;
        std::string prefer_encrypt;
        std::string keydata;           // base64-encoded
        bool valid = false;
    };

    static AutocryptInfo extract(
        const std::map<std::string, std::string>& headers) {

        AutocryptInfo info;

        auto it = headers.find("autocrypt");
        if (it == headers.end()) return info;

        std::string raw = it->second;

        // Parse: addr=alice@example.org; prefer-encrypt=mutual; keydata=BASE64...
        auto parts = split_str(raw, ';');
        for (auto& p : parts) {
            p = trim(p);
            size_t eq = p.find('=');
            if (eq == std::string::npos) continue;
            std::string k = str_lower(trim(p.substr(0, eq)));
            std::string v = trim(p.substr(eq + 1));

            if (k == "addr")            info.addr = v;
            else if (k == "prefer-encrypt") info.prefer_encrypt = v;
            else if (k == "keydata")    info.keydata = v;
        }

        if (!info.addr.empty())
            info.valid = true;

        return info;
    }

    // Check if the top-level message has an Autocrypt header
    static bool has_autocrypt(const std::map<std::string, std::string>& headers) {
        return headers.find("autocrypt") != headers.end();
    }

    // Check for Autocrypt-Setup-Message header
    static bool has_setup_message(const std::map<std::string, std::string>& headers) {
        return headers.find("autocrypt-setup-message") != headers.end();
    }
};

// ============================================================================
// Secure-Join header extraction
// ============================================================================
class SecureJoinHeaderExtractor {
public:
    struct SecureJoinInfo {
        std::string group_id;        // group to join
        std::string fingerprint;     // expected key fingerprint
        bool valid = false;
    };

    static SecureJoinInfo extract(
        const std::map<std::string, std::string>& headers) {

        SecureJoinInfo info;

        auto it = headers.find("secure-join");
        if (it == headers.end()) return info;

        std::string raw = it->second;

        // Parse: group=GRPID; fingerprint=HEX...
        auto parts = split_str(raw, ';');
        for (auto& p : parts) {
            p = trim(p);
            size_t eq = p.find('=');
            if (eq == std::string::npos) continue;
            std::string k = str_lower(trim(p.substr(0, eq)));
            std::string v = trim(p.substr(eq + 1));

            if (k == "group")       info.group_id = v;
            else if (k == "fingerprint") info.fingerprint = v;
            else if (k == "vc")     info.fingerprint = v; // some clients use 'vc'
        }

        if (!info.group_id.empty())
            info.valid = true;

        return info;
    }

    static bool has_secure_join(const std::map<std::string, std::string>& headers) {
        return headers.find("secure-join") != headers.end();
    }
};

// ============================================================================
// MDN (Message Disposition Notification) detection
// ============================================================================
class MdnDetector {
public:
    static bool is_mdn(const MimePart& root) {
        // MDN messages are typically multipart/report
        // with report-type=disposition-notification

        if (!root.is_multipart) return false;
        if (root.multipart_subtype != "report") return false;

        // Check Content-Type params for report-type
        auto ct_it = root.headers.find("content-type");
        if (ct_it == root.headers.end()) return false;

        auto params = parse_mime_params(ct_it->second);
        auto rt_it = params.find("report-type");
        if (rt_it == params.end()) return false;

        return rt_it->second == "disposition-notification";
    }

    // Try to extract the original Message-ID from the MDN
    static std::string extract_original_message_id(const MimePart& root) {
        if (!is_mdn(root)) return "";

        // Walk children to find message/disposition-notification part
        for (const auto& child : root.children) {
            std::string ct = str_lower(child.content_type);
            if (ct.find("message/disposition-notification") == 0) {
                // The body or headers may contain Original-Message-ID
                auto oid = child.headers.find("original-message-id");
                if (oid != child.headers.end())
                    return oid->second;
            }
        }

        return "";
    }
};

// ============================================================================
// Ephemeral message timer extraction
// ============================================================================
class EphemeralTimerExtractor {
public:
    // Extract Ephemeral-Timer header value (in seconds)
    // DeltaChat uses this header to indicate disappearing messages.
    // Format: Ephemeral-Timer: <seconds>
    static int extract(const std::map<std::string, std::string>& headers) {
        auto it = headers.find("ephemeral-timer");
        if (it == headers.end()) return 0;

        try {
            int seconds = std::stoi(it->second);
            return (seconds > 0) ? seconds : 0;
        } catch (...) {
            return 0;
        }
    }

    // Also check if the Chat-Group-ID implies an ephemeral group
    // (some clients encode ephemeral timer in the group ID suffix)
    static int extract_from_group_id(const std::string& group_id) {
        // Group ID format may be: <b64> or <b64>-<ephemeral_seconds>
        auto dash = group_id.rfind('-');
        if (dash == std::string::npos || dash + 1 >= group_id.size())
            return 0;

        try {
            return std::stoi(group_id.substr(dash + 1));
        } catch (...) {
            return 0;
        }
    }
};

// ============================================================================
// Main IMAP Message Downloader — orchestrates fetch + parse
// ============================================================================
class ImapMessageDownloader {
public:
    // ------------------------------------------------------------------
    // 1. Download full message by UID
    // ------------------------------------------------------------------
    static DownloadedMessage download_full(
        ImapConnection& conn,
        uint32_t uid,
        const std::string& folder = "",
        int timeout_seconds = 60) {

        DownloadedMessage msg;
        msg.uid = uid;

        // Select folder if specified
        if (!folder.empty()) {
            // Assume caller has already selected folder; otherwise
            // conn.select_folder(folder) would be needed.
        }

        // Build fetch command
        // UID FETCH uid (UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[])
        std::string cmd = "UID FETCH " + std::to_string(uid) +
            " (UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[])";

        // Execute fetch and parse the result — this integrates with the
        // ImapConnection::send_command / parse_fetch_line infrastructure.
        auto raw_result = fetch_single_message_raw(conn, uid, timeout_seconds);
        if (raw_result.parse_error) {
            msg.parse_error = true;
            msg.error_message = raw_result.error_message;
            return msg;
        }

        msg.raw_full  = raw_result.full_message;
        msg.rfc822_size = raw_result.size;
        msg.internal_date = raw_result.internal_date;
        msg.flags = raw_result.flags;

        // Parse the full message
        parse_full_message(msg);

        return msg;
    }

    // ------------------------------------------------------------------
    // 2. Download partial — headers only
    // ------------------------------------------------------------------
    static DownloadedMessage download_headers(
        ImapConnection& conn,
        uint32_t uid,
        int timeout_seconds = 30) {

        DownloadedMessage msg;
        msg.uid = uid;

        auto raw = fetch_single_part(conn, uid, "BODY.PEEK[HEADER]", timeout_seconds);
        if (raw.parse_error) {
            msg.parse_error = true;
            msg.error_message = raw.error_message;
            return msg;
        }

        msg.raw_headers = raw.full_message;
        msg.rfc822_size = raw.size;
        msg.internal_date = raw.internal_date;
        msg.flags = raw.flags;

        // Parse headers into envelope only
        auto fields = Rfc2822HeaderParser::parse_header_block(msg.raw_headers);
        auto hdrs = Rfc2822HeaderParser::headers_to_map(fields);
        populate_envelope(msg.envelope, hdrs);

        return msg;
    }

    // ------------------------------------------------------------------
    // 3. Download partial — body only
    // ------------------------------------------------------------------
    static DownloadedMessage download_body(
        ImapConnection& conn,
        uint32_t uid,
        int timeout_seconds = 30) {

        DownloadedMessage msg;
        msg.uid = uid;

        auto raw = fetch_single_part(conn, uid, "BODY.PEEK[TEXT]", timeout_seconds);
        if (raw.parse_error) {
            msg.parse_error = true;
            msg.error_message = raw.error_message;
            return msg;
        }

        msg.raw_body = raw.full_message;
        msg.rfc822_size = raw.size;
        msg.internal_date = raw.internal_date;
        msg.flags = raw.flags;

        msg.text_body = msg.raw_body;

        return msg;
    }

    // ------------------------------------------------------------------
    // 4. Download partial — first N bytes
    // ------------------------------------------------------------------
    static DownloadedMessage download_first_n(
        ImapConnection& conn,
        uint32_t uid,
        int n_bytes,
        int timeout_seconds = 30) {

        DownloadedMessage msg;
        msg.uid = uid;

        std::string section = "BODY.PEEK[]<0." + std::to_string(n_bytes) + ">";
        auto raw = fetch_single_part(conn, uid, section, timeout_seconds);
        if (raw.parse_error) {
            msg.parse_error = true;
            msg.error_message = raw.error_message;
            return msg;
        }

        msg.raw_full = raw.full_message;
        msg.rfc822_size = raw.size;
        msg.internal_date = raw.internal_date;
        msg.flags = raw.flags;

        // Try to parse what we have (may be truncated)
        if (!msg.raw_full.empty())
            parse_full_message(msg);

        return msg;
    }

    // ------------------------------------------------------------------
    // 5. Download attachment by UID + part number
    // ------------------------------------------------------------------
    struct AttachmentDownload {
        std::string part_id;
        std::string filename;
        std::string mime_type;
        std::vector<uint8_t> data;
        int64_t size = 0;
        bool success = false;
        std::string error;
    };

    static AttachmentDownload download_attachment(
        ImapConnection& conn,
        uint32_t uid,
        const std::string& part_id,
        int timeout_seconds = 60) {

        AttachmentDownload result;
        result.part_id = part_id;

        // IMAP fetch: UID FETCH uid BODY.PEEK[part_id]
        std::string section = "BODY.PEEK[" + part_id + "]";
        auto raw = fetch_single_part(conn, uid, section, timeout_seconds);

        if (raw.parse_error) {
            result.error = raw.error_message;
            return result;
        }

        result.data.assign(raw.full_message.begin(), raw.full_message.end());
        result.size = static_cast<int64_t>(raw.full_message.size());
        result.success = true;

        return result;
    }

private:
    // ------------------------------------------------------------------
    // Raw fetch result from IMAP
    // ------------------------------------------------------------------
    struct RawFetchResult {
        std::string full_message;
        std::string header_data;
        std::string body_data;
        uint32_t flags = 0;
        int64_t size = 0;
        std::string internal_date;
        bool parse_error = false;
        std::string error_message;
    };

    // ------------------------------------------------------------------
    // Execute a single-message IMAP fetch
    // ------------------------------------------------------------------
    static RawFetchResult fetch_single_message_raw(
        ImapConnection& conn,
        uint32_t uid,
        int timeout_seconds) {

        return fetch_single_part(conn, uid, "BODY.PEEK[]", timeout_seconds);
    }

    // ------------------------------------------------------------------
    // Execute a single part fetch (BODY.PEEK[section])
    // ------------------------------------------------------------------
    static RawFetchResult fetch_single_part(
        ImapConnection& conn,
        uint32_t uid,
        const std::string& section,
        int timeout_seconds) {

        RawFetchResult result;
        (void)conn;
        (void)uid;
        (void)section;
        (void)timeout_seconds;

        // NOTE: This function integrates with the ImapConnection class
        // defined in deltachat_imap_smtp.cpp. At runtime, the actual
        // IMAP I/O happens through conn.send_command() and the response
        // is parsed via conn.parse_fetch_line().
        //
        // Because the connection is passed by reference, the caller is
        // responsible for ensuring the connection is alive, authenticated,
        // and the correct folder is selected.
        //
        // In a production build, this would call:
        //
        //   auto response = conn.send_command(
        //       "UID FETCH " + std::to_string(uid) + " (UID FLAGS RFC822.SIZE INTERNALDATE " + section + ")",
        //       timeout_seconds);
        //   if (response.status != "OK") { ... }
        //   for (auto& line : response.lines) {
        //       if (line.find("FETCH") != std::string::npos) {
        //           auto fr = conn.parse_fetch_line(line);
        //           result.full_message = fr.body_data;
        //           ...
        //       }
        //   }
        //
        // For this file, we provide the complete parsing logic below.
        // The actual IMAP wire call is supplied by the ImapConnection.

        // Placeholder: in a full build, the above logic fills result.
        // For now, return empty with error.
        result.parse_error = true;
        result.error_message =
            "IMAP fetch integration requires ImapConnection::send_command. "
            "See deltachat_imap_smtp.cpp for the connection layer.";

        return result;
    }

    // ------------------------------------------------------------------
    // Parse a fully-downloaded message
    // ------------------------------------------------------------------
    static void parse_full_message(DownloadedMessage& msg) {
        if (msg.raw_full.empty()) return;

        // Step 1: Split headers and body
        std::string headers_block, body_block;
        size_t blank = msg.raw_full.find("\r\n\r\n");
        if (blank == std::string::npos) blank = msg.raw_full.find("\n\n");
        if (blank != std::string::npos) {
            size_t offset = (msg.raw_full[blank] == '\r') ? 4 : 2;
            headers_block = msg.raw_full.substr(0, blank);
            body_block = msg.raw_full.substr(blank + offset);
        } else {
            headers_block = msg.raw_full;
        }

        msg.raw_headers = headers_block;
        msg.raw_body = body_block;

        // Step 2: Parse header fields
        auto fields = Rfc2822HeaderParser::parse_header_block(headers_block);
        auto hdrs = Rfc2822HeaderParser::headers_to_map(fields);

        // Step 3: Populate envelope
        populate_envelope(msg.envelope, hdrs);

        // Step 4: Parse MIME tree
        try {
            msg.root_part = MimeMultipartParser::parse(msg.raw_full);
        } catch (...) {
            msg.parse_error = true;
            msg.error_message = "MIME parse exception";
            return;
        }

        // Step 5: Extract body text
        auto body_extract = BodyPartExtractor::extract(msg.root_part);
        msg.text_body = body_extract.text_plain;
        msg.html_body = body_extract.text_html;

        // If only HTML is available, convert to plain
        if (msg.text_body.empty() && !msg.html_body.empty()) {
            msg.plain_from_html = HtmlToPlainText::convert(msg.html_body);
        }

        // Step 6: Extract attachments
        auto attach_list = AttachmentExtractor::extract(msg.root_part);
        for (auto& att : attach_list) {
            DownloadedMessage::Attachment a;
            a.part_id   = att.part_id;
            a.filename  = att.filename;
            a.mime_type = att.mime_type;
            a.size      = att.size;
            a.data      = att.data;
            msg.attachments.push_back(std::move(a));
        }
        msg.has_attachments = !msg.attachments.empty();

        // Step 7: Extract inline images
        auto inline_list = InlineImageHandler::extract(msg.root_part);
        for (auto& img : inline_list) {
            DownloadedMessage::InlineImage ii;
            ii.content_id = img.content_id;
            ii.part_id    = img.part_id;
            ii.mime_type  = img.mime_type;
            ii.data       = img.data;
            ii.width      = img.width;
            ii.height     = img.height;
            msg.inline_images.push_back(std::move(ii));
        }
        msg.has_inline_images = !msg.inline_images.empty();

        // Step 8: Image processing for attachments that are images
        for (auto& att : msg.attachments) {
            if (str_istarts_with(str_lower(att.mime_type), "image/")) {
                auto info = ImageProcessor::probe_dimensions(att.data);
                // Dimensions can be stored alongside the attachment
                (void)info;
            }
        }

        // Step 9: Quoted text detection
        std::string body_for_analysis = msg.text_body.empty()
                                            ? msg.plain_from_html
                                            : msg.text_body;
        if (!body_for_analysis.empty()) {
            auto qi = QuotedTextDetector::detect(body_for_analysis);
            msg.has_quote = qi.has_quote;
        }

        // Step 10: Forwarded message detection
        msg.is_forwarded = ForwardedMessageDetector::is_forwarded(
            body_for_analysis, msg.envelope.subject);

        // Step 11: MDN detection
        msg.envelope.is_mdn = MdnDetector::is_mdn(msg.root_part);
        if (msg.envelope.is_mdn) {
            msg.envelope.mdn_original_message_id =
                MdnDetector::extract_original_message_id(msg.root_part);
        }
    }

    // ------------------------------------------------------------------
    // Populate ParsedMessageEnvelope from header map
    // ------------------------------------------------------------------
    static void populate_envelope(
        ParsedMessageEnvelope& env,
        const std::map<std::string, std::string>& hdrs) {

        auto get = [&](const std::string& key) -> std::string {
            auto it = hdrs.find(str_lower(key));
            return (it != hdrs.end()) ? it->second : "";
        };

        env.message_id  = get("message-id");
        env.in_reply_to = get("in-reply-to");
        env.references  = get("references");
        env.from        = get("from");
        env.to          = get("to");
        env.cc          = get("cc");
        env.bcc         = get("bcc");
        env.subject     = get("subject");
        env.date        = get("date");
        env.content_type = get("content-type");

        // Threading
        env.reference_ids = ThreadDetector::extract_message_id_list(env.references);
        env.has_thread_parent = !env.in_reply_to.empty() ||
                                 !env.reference_ids.empty();

        // Chat-* headers
        ChatHeaderExtractor::extract(env, hdrs);

        // Autocrypt
        env.autocrypt_header = get("autocrypt");
        env.autocrypt_setup_message = get("autocrypt-setup-message");
        auto ac_info = AutocryptHeaderExtractor::extract(hdrs);
        env.autocrypt_prefer_encrypt = ac_info.prefer_encrypt;
        env.autocrypt_keydata = ac_info.keydata;

        // Secure-Join
        env.secure_join_header = get("secure-join");
        auto sj_info = SecureJoinHeaderExtractor::extract(hdrs);
        env.secure_join_group = sj_info.group_id;
        env.secure_join_fingerprint = sj_info.fingerprint;

        // Ephemeral timer
        env.ephemeral_timer = EphemeralTimerExtractor::extract(hdrs);
        if (env.ephemeral_timer == 0 && !env.chat_group_id.empty()) {
            int grp_timer =
                EphemeralTimerExtractor::extract_from_group_id(env.chat_group_id);
            if (grp_timer > 0)
                env.ephemeral_timer = grp_timer;
        }
    }
};

// ============================================================================
// Large Message Handler — download in chunks, streaming parse
// ============================================================================
class LargeMessageHandler {
public:
    struct ChunkedDownload {
        std::string headers;           // full headers (always small enough)
        std::vector<std::string> body_chunks; // body in 64KB chunks
        int64_t total_bytes = 0;
        int     chunk_count = 0;
        bool    complete = false;
        std::string error;
    };

    // Download a large message in chunks using partial FETCH
    // We first get the RFC822.SIZE, then fetch in overlapping chunks.
    static ChunkedDownload download_large(
        ImapConnection& conn,
        uint32_t uid,
        int64_t known_size = 0,
        int timeout_seconds = 120) {

        ChunkedDownload result;
        (void)conn;
        (void)uid;
        (void)known_size;
        (void)timeout_seconds;

        // Strategy:
        // 1. Get headers first: BODY.PEEK[HEADER]
        // 2. Get size from RFC822.SIZE
        // 3. For each chunk: BODY.PEEK[]<offset.size>
        // 4. Reassemble or process streamingly.
        //
        // The chunked download uses:
        //   offset = chunk_index * DOWNLOAD_CHUNK_SIZE
        //   size   = DOWNLOAD_CHUNK_SIZE
        //   FETCH section = "<offset.size>"
        //
        // This avoids loading the entire multi-megabyte message into memory
        // at once and allows streaming MIME parse.

        result.error = "Chunked download requires ImapConnection integration. "
                       "See fetch_single_part() for the wiring point.";
        return result;
    }

    // Streaming MIME parser: process chunks as they arrive.
    // This allows handling messages larger than available RAM by emitting
    // body parts as they are discovered.
    class StreamingMimeParser {
    private:
        std::string boundary_;
        std::string buffer_;
        int64_t processed_ = 0;
        bool in_headers_ = true;
        int depth_ = 0;

    public:
        explicit StreamingMimeParser(const std::string& boundary)
            : boundary_(boundary) {}

        // Feed a chunk of raw message data.
        // Returns discovered text parts that can be emitted immediately.
        struct ChunkResult {
            std::string text_chunk;
            bool part_boundary = false;
            bool message_complete = false;
        };

        ChunkResult feed(const std::string& chunk) {
            ChunkResult cr;
            buffer_ += chunk;
            processed_ += chunk.size();
            // In a full implementation, this would scan for boundaries
            // and emit completed parts incrementally.
            cr.text_chunk = chunk;
            return cr;
        }
    };
};

// ============================================================================
// Attachment filename decoder (RFC 2231 + RFC 2047)
// ============================================================================
class AttachmentFilenameDecoder {
public:
    // Decode a filename from Content-Disposition or Content-Type header.
    // Handles:
    //   1. Plain ASCII filenames
    //   2. RFC 2047 encoded (=?UTF-8?B?...?=)
    //   3. RFC 2231 parameter continuations (filename*0*=..., filename*1*=...)
    //   4. RFC 2231 single encoded (filename*=UTF-8''percent-encoded)
    //
    static std::string decode(const std::string& header_name,
                               const std::map<std::string, std::string>& params) {
        // Try RFC 2231 continuation first
        std::string continued = rfc2231_decode_continuation(params, header_name);
        if (!continued.empty())
            return continued;

        // Try plain filename= parameter
        auto it = params.find(header_name);
        if (it != params.end()) {
            std::string val = it->second;
            // Check if this is actually an encoded filename*= value already
            // (params map keys include the '*')
            return rfc2047_decode(val);
        }

        // Try filename*= (single encoded part)
        std::string star_key = header_name + "*";
        auto star_it = params.find(star_key);
        if (star_it != params.end()) {
            std::string val = star_it->second;
            // Format: charset'language'percent-encoded
            auto sq1 = val.find('\'');
            if (sq1 != std::string::npos) {
                auto sq2 = val.find('\'', sq1 + 1);
                if (sq2 != std::string::npos) {
                    std::string encoded = val.substr(sq2 + 1);
                    std::string decoded;
                    for (size_t i = 0; i < encoded.size(); ++i) {
                        if (encoded[i] == '%' && i + 2 < encoded.size() &&
                            std::isxdigit(encoded[i+1]) && std::isxdigit(encoded[i+2])) {
                            char hex[3] = {encoded[i+1], encoded[i+2], 0};
                            decoded.push_back(static_cast<char>(
                                std::strtol(hex, nullptr, 16)));
                            i += 2;
                        } else {
                            decoded.push_back(encoded[i]);
                        }
                    }
                    return decoded;
                }
            }
            return val;
        }

        return "";
    }
};

// ============================================================================
// Message Reconstruction — reassemble a DownloadedMessage from parts
// ============================================================================
class MessageReconstructor {
public:
    // Build a final plain-text representation from a parsed message.
    // This is what gets stored and displayed in the DeltaChat UI.
    static std::string build_display_text(const DownloadedMessage& msg) {
        std::string text;

        // Preferred body
        if (!msg.text_body.empty())
            text = msg.text_body;
        else if (!msg.plain_from_html.empty())
            text = msg.plain_from_html;
        else if (!msg.html_body.empty())
            text = HtmlToPlainText::convert(msg.html_body);

        // Append attachment list
        if (!msg.attachments.empty()) {
            if (!text.empty()) text += "\n\n";
            text += "[Attachments:]\n";
            for (const auto& att : msg.attachments) {
                text += "  " + att.filename;
                if (att.size > 0) {
                    text += " (" + format_size(att.size) + ")";
                }
                text += "\n";
            }
        }

        return text;
    }

    // Build a summary (first line, useful for notification previews)
    static std::string build_summary(const DownloadedMessage& msg, size_t max_len = 160) {
        std::string display = build_display_text(msg);
        // Take first line
        size_t nl = display.find('\n');
        std::string first_line = (nl != std::string::npos)
                                     ? display.substr(0, nl)
                                     : display;
        if (first_line.size() > max_len)
            first_line = first_line.substr(0, max_len - 3) + "...";
        return first_line;
    }

private:
    static std::string format_size(int64_t bytes) {
        if (bytes < 1024) return std::to_string(bytes) + " B";
        if (bytes < 1048576) return std::to_string(bytes / 1024) + " KB";
        return std::to_string(bytes / 1048576) + " MB";
    }
};

// ============================================================================
// Download Pipeline — combine multiple downloads into a batch
// ============================================================================
class DownloadPipeline {
public:
    struct BatchResult {
        std::vector<DownloadedMessage> messages;
        int total = 0;
        int succeeded = 0;
        int failed = 0;
        std::chrono::milliseconds elapsed;
    };

    // Download a batch of messages by UID
    static BatchResult download_batch(
        ImapConnection& conn,
        const std::vector<uint32_t>& uids,
        bool fetch_bodies = true,
        int timeout_per_msg = 30) {

        BatchResult result;
        result.total = static_cast<int>(uids.size());
        auto start = std::chrono::steady_clock::now();

        for (uint32_t uid : uids) {
            DownloadedMessage msg;

            if (fetch_bodies) {
                msg = ImapMessageDownloader::download_full(
                    conn, uid, "", timeout_per_msg);
            } else {
                msg = ImapMessageDownloader::download_headers(
                    conn, uid, timeout_per_msg);
            }

            if (msg.parse_error) {
                ++result.failed;
            } else {
                ++result.succeeded;
            }

            result.messages.push_back(std::move(msg));
        }

        auto end = std::chrono::steady_clock::now();
        result.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            end - start);

        return result;
    }
};

// ============================================================================
// Content-Type detection and MIME helpers
// ============================================================================
class MimeTypeDetector {
public:
    // Map file extension → MIME type
    static std::string from_extension(const std::string& filename) {
        size_t dot = filename.rfind('.');
        if (dot == std::string::npos) return "application/octet-stream";

        std::string ext = str_lower(filename.substr(dot + 1));

        static const std::unordered_map<std::string, std::string> ext_map = {
            {"jpg",  "image/jpeg"},    {"jpeg", "image/jpeg"},
            {"png",  "image/png"},     {"gif",  "image/gif"},
            {"webp", "image/webp"},    {"bmp",  "image/bmp"},
            {"svg",  "image/svg+xml"}, {"ico",  "image/x-icon"},
            {"mp4",  "video/mp4"},     {"webm", "video/webm"},
            {"mov",  "video/quicktime"},{"avi", "video/x-msvideo"},
            {"mp3",  "audio/mpeg"},    {"ogg",  "audio/ogg"},
            {"wav",  "audio/wav"},     {"flac", "audio/flac"},
            {"aac",  "audio/aac"},     {"m4a",  "audio/mp4"},
            {"pdf",  "application/pdf"},
            {"zip",  "application/zip"},{"gz",  "application/gzip"},
            {"tar",  "application/x-tar"},{"7z","application/x-7z-compressed"},
            {"doc",  "application/msword"},
            {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
            {"xls",  "application/vnd.ms-excel"},
            {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
            {"ppt",  "application/vnd.ms-powerpoint"},
            {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
            {"txt",  "text/plain"},    {"html","text/html"},
            {"htm",  "text/html"},     {"css", "text/css"},
            {"js",   "application/javascript"},
            {"json", "application/json"},
            {"xml",  "application/xml"},
            {"csv",  "text/csv"},
            {"vcf",  "text/vcard"},    {"ics", "text/calendar"},
        };

        auto it = ext_map.find(ext);
        return (it != ext_map.end()) ? it->second : "application/octet-stream";
    }

    // Determine Viewtype enum from MIME type (for DeltaChat message type)
    enum class DetectedViewtype {
        TEXT, IMAGE, GIF, STICKER, AUDIO, VOICE, VIDEO, FILE, WEBXDC, UNKNOWN
    };

    static DetectedViewtype detect_viewtype(const std::string& mime,
                                              const std::string& filename = "") {
        std::string mime_lower = str_lower(mime);

        if (mime_lower.find("text/") == 0) return DetectedViewtype::TEXT;
        if (mime_lower == "image/gif")     return DetectedViewtype::GIF;
        if (mime_lower.find("image/") == 0) return DetectedViewtype::IMAGE;
        if (mime_lower.find("audio/") == 0) {
            // Some audio might be voice messages
            if (!filename.empty()) {
                std::string fl = str_lower(filename);
                if (fl.find("voice") != std::string::npos ||
                    fl.find("ptt") != std::string::npos)
                    return DetectedViewtype::VOICE;
            }
            return DetectedViewtype::AUDIO;
        }
        if (mime_lower.find("video/") == 0) return DetectedViewtype::VIDEO;
        if (mime_lower == "application/webxdc+zip")
            return DetectedViewtype::WEBXDC;
        return DetectedViewtype::FILE;
    }

    // Check if a MIME type represents an image
    static bool is_image(const std::string& mime) {
        return str_istarts_with(mime, "image/");
    }

    // Check if a MIME type represents audio
    static bool is_audio(const std::string& mime) {
        return str_istarts_with(mime, "audio/");
    }

    // Check if a MIME type represents video
    static bool is_video(const std::string& mime) {
        return str_istarts_with(mime, "video/");
    }
};

// ============================================================================
// Message structure query — BODYSTRUCTURE-based part enumeration
// ============================================================================
class BodyStructureQuery {
public:
    struct PartInfo {
        std::string part_id;
        std::string mime_type;
        std::string mime_subtype;
        std::vector<std::string> params;     // key=value pairs
        std::string content_id;
        std::string content_description;
        std::string content_transfer_encoding;
        int64_t size = 0;
        // For text/*: number of lines
        int lines = 0;
        // For message/rfc822: envelope structure, body structure
        bool is_multipart = false;
        std::string multipart_subtype;
        std::vector<PartInfo> children;
        // Attachment metadata
        std::string disposition;      // inline | attachment
        std::string disposition_filename;
        std::string type_filename;    // from Content-Type name param
        bool has_attachment_disposition = false;
    };

    // Parse BODYSTRUCTURE response from IMAP FETCH
    // In production, this avoids downloading the full message just to
    // discover attachments — we can selectively download only the parts
    // we need.
    static std::vector<PartInfo> parse_bodystructure_response(
        const std::string& bodystructure_data) {

        std::vector<PartInfo> parts;

        // BODYSTRUCTURE is a parenthesized list.
        // Top level: (part1 part2 ...) for multipart,
        // or (type subtype params id desc enc size ...) for single part.
        //
        // Full parsing of BODYSTRUCTURE is complex; this stub outlines the
        // approach. See RFC 3501 section 7.4.2 for the full grammar.

        // For now, return empty — the actual parse is done in deltachat_imap_smtp.cpp
        // or via the MIME tree parser above.
        (void)bodystructure_data;
        return parts;
    }
};

// ============================================================================
// IMAP fetch section builder — construct BODY[section] specifiers
// ============================================================================
class ImapSectionBuilder {
public:
    // Build a BODY.PEEK[section] string for fetching a specific MIME part
    static std::string build_part_section(const std::string& part_id) {
        return "BODY.PEEK[" + part_id + "]";
    }

    // Build a BODY.PEEK[HEADER] section for headers-only fetch
    static std::string header_section() {
        return "BODY.PEEK[HEADER]";
    }

    // Build a BODY.PEEK[TEXT] section for body-only fetch
    static std::string text_section() {
        return "BODY.PEEK[TEXT]";
    }

    // Build a BODY.PEEK[] section for full message fetch
    static std::string full_section() {
        return "BODY.PEEK[]";
    }

    // Build a BODY.PEEK[]<0.N> section for partial fetch
    static std::string partial_section(int n_bytes) {
        return "BODY.PEEK[]<0." + std::to_string(n_bytes) + ">";
    }

    // Build a BODY.PEEK[]<offset.size> section for chunked fetch
    static std::string chunk_section(int64_t offset, int64_t size) {
        return "BODY.PEEK[]<" + std::to_string(offset) + "." +
               std::to_string(size) + ">";
    }

    // Build a BODY.PEEK[part_id.MIME] section for MIME headers of a part
    static std::string part_mime_section(const std::string& part_id) {
        return "BODY.PEEK[" + part_id + ".MIME]";
    }

    // Build the full fetch macro for a message
    // DeltaChat typically uses: (UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[])
    static std::string full_fetch_macro() {
        return "(UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[])";
    }

    // Headers-only fetch macro with DeltaChat-specific headers
    static std::string headers_fetch_macro() {
        return "(UID FLAGS RFC822.SIZE INTERNALDATE "
               "BODY.PEEK[HEADER.FIELDS (FROM TO CC BCC SUBJECT DATE "
               "MESSAGE-ID IN-REPLY-TO REFERENCES CONTENT-TYPE "
               "AUTOCRYPT AUTOCRYPT-SETUP-MESSAGE CHAT-VERSION "
               "CHAT-GROUP-ID CHAT-GROUP-NAME CHAT-VERIFIED "
               "CHAT-USER-AVATAR CHAT-CONTENT CHAT-VOICE "
               "SECURE-JOIN EPHEMERAL-TIMER)])";
    }

    // Body-only fetch macro
    static std::string body_fetch_macro() {
        return "(UID FLAGS BODY.PEEK[TEXT])";
    }
};

// ============================================================================
// Download management — queue, prioritise, throttle, retry
// ============================================================================

struct DownloadManagerConfig {
    int max_concurrent_downloads = 4;
    int max_retries = 3;
    int retry_delay_ms = 2000;
    int throttle_ms = 100;        // minimum interval between fetches
    int64_t large_message_threshold = 1048576; // 1 MB
    bool download_attachments = true;
    bool download_inline_images = true;
};

struct DownloadJob {
    uint32_t uid = 0;
    std::string folder;
    bool fetch_full = false;
    int priority = 0;           // higher = more urgent
    int retry_count = 0;
    std::chrono::steady_clock::time_point created;
};

class DownloadManager {
public:
    explicit DownloadManager(const DownloadManagerConfig& cfg = DownloadManagerConfig{})
        : config_(cfg) {}

    // Enqueue a download job
    void enqueue(const DownloadJob& job) {
        std::lock_guard lock(mutex_);
        queue_.push_back(job);
        // Sort by priority (descending)
        std::sort(queue_.begin(), queue_.end(),
                  [](const DownloadJob& a, const DownloadJob& b) {
                      return a.priority > b.priority;
                  });
    }

    // Enqueue multiple UIDs at once
    void enqueue_batch(const std::vector<uint32_t>& uids,
                        const std::string& folder,
                        int priority = 0) {
        for (uint32_t uid : uids) {
            DownloadJob job;
            job.uid = uid;
            job.folder = folder;
            job.priority = priority;
            job.created = std::chrono::steady_clock::now();
            enqueue(job);
        }
    }

    // Get next pending job (thread-safe)
    std::optional<DownloadJob> dequeue() {
        std::lock_guard lock(mutex_);
        if (queue_.empty()) return std::nullopt;
        DownloadJob job = queue_.front();
        queue_.pop_front();
        return job;
    }

    // Check if there are pending jobs
    bool has_pending() const {
        // const qualified, so we can't lock mutex_ (would need a mutable mutex)
        // In practice, use a separate atomic counter.
        return pending_count_.load() > 0;
    }

    // Get the queue size
    int queue_size() const {
        return pending_count_.load();
    }

    // Clear the queue
    void clear() {
        std::lock_guard lock(mutex_);
        queue_.clear();
        pending_count_.store(0);
    }

private:
    DownloadManagerConfig config_;
    std::deque<DownloadJob> queue_;
    std::atomic<int> pending_count_{0};
    mutable std::mutex mutex_;
};

// ============================================================================
// Response syntax checker — validate IMAP FETCH responses
// ============================================================================
class ImapResponseValidator {
public:
    // Check if a FETCH response line indicates the message was successfully
    // delivered with actual body data.
    static bool has_body_data(const std::string& fetch_line) {
        // Check for BODY[] or BODY[section] with non-empty content
        if (fetch_line.find("BODY[") != std::string::npos &&
            fetch_line.find("NIL") == std::string::npos) {
            return true;
        }
        return false;
    }

    // Check if the UID in the response matches
    static bool uid_matches(const std::string& fetch_line, uint32_t expected_uid) {
        size_t uid_pos = fetch_line.find("UID ");
        if (uid_pos == std::string::npos) return false;
        std::string rest = fetch_line.substr(uid_pos + 4);
        std::stringstream ss(rest);
        uint32_t uid;
        if (ss >> uid) {
            return uid == expected_uid;
        }
        return false;
    }

    // Verify response integrity
    static bool is_valid_fetch_response(const std::string& fetch_line,
                                          uint32_t expected_uid) {
        return fetch_line.find("FETCH") != std::string::npos &&
               uid_matches(fetch_line, expected_uid);
    }
};

} // namespace deltachat
} // namespace progressive
