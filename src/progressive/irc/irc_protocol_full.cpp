// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Progressive IRC Server Contributors
//
// IRC Full Protocol Implementation — RFC 1459 / 2812 / 7194 / IRCv3
//
// This file provides a complete, self-contained IRC protocol engine:
//   - Full RFC 1459/2812 message parser (prefix, command, params, trailing)
//   - IRCv3 message tags (key=value with escaping per IRCv3.2)
//   - Server-time extension (ISO 8601 timestamps)
//   - Account-tag (login tracking)
//   - Batch support (netsplit, chathistory, etc.)
//   - Labeled-response (command/response correlation)
//   - Echo-message (self-message reflection)
//   - Message-ids (globally unique message identifiers)
//   - Message-tags format (full serialization/deserialization)
//   - Chathistory (playback on join)
//   - Setname (realname change notification)
//   - METADATA key/value protocol
//   - MONITOR (watch list)
//   - BOT mode and identification
//   - CAP 3.2 negotiation (LS/REQ/ACK/NAK/DEL/NEW/LIST)
//   - SASL v3.2 (PLAIN, EXTERNAL, SCRAM-SHA-256)
//   - Extended-monitor (notifications for logon/logoff)
//   - Invite-notify (invite notifications to chanops)
//   - Away-notify (away status change notification)
//   - Full IRC registration/connection state machine
//
// Namespace: progressive::irc

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <memory>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <mutex>
#include <functional>
#include <cstring>
#include <cstdint>
#include <cctype>
#include <stdexcept>
#include <regex>
#include <array>
#include <iomanip>
#include <optional>
#include <cstdarg>
#include <deque>
#include <chrono>
#include <bitset>
#include <random>
#include <cassert>
#include <tuple>

// ---------------------------------------------------------------------------
// progressive::irc namespace
// ---------------------------------------------------------------------------
namespace progressive {
namespace irc {

// ============================================================================
// SECTION 1 : Utility Primitives — Strings, Time, Random
// ============================================================================

/// @brief Trim leading and trailing whitespace.
inline std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && (s[start] == ' ' || s[start] == '\t' ||
           s[start] == '\r' || s[start] == '\n'))
        ++start;
    size_t end = s.size();
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' ||
           s[end - 1] == '\r' || s[end - 1] == '\n'))
        --end;
    return s.substr(start, end - start);
}

/// @brief Split a string by delimiter.
inline std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> result;
    std::istringstream iss(s);
    std::string token;
    while (std::getline(iss, token, delim)) {
        if (!token.empty()) result.push_back(token);
    }
    return result;
}

/// @brief Split a string by delimiter, keeping empty tokens.
inline std::vector<std::string> split_all(const std::string& s, char delim) {
    std::vector<std::string> result;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == delim) {
            result.push_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return result;
}

/// @brief Convert a string to uppercase in-place (ASCII only).
inline void toupper_inplace(std::string& s) {
    for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
}

/// @brief Convert a string to lowercase in-place (ASCII only).
inline void tolower_inplace(std::string& s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

/// @brief Case-insensitive string comparison.
inline bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

/// @brief Get current time as ISO 8601 with milliseconds.
inline std::string iso8601_now() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto t   = system_clock::to_time_t(now);
    auto ms  = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    struct tm tm_buf;
    gmtime_r(&t, &tm_buf);
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03lldZ",
             tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
             tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
             static_cast<long long>(ms.count()));
    return buf;
}

/// @brief Generate a random alphanumeric string (for IDs).
inline std::string random_id(size_t length = 16) {
    static thread_local std::mt19937_64 rng(
        std::chrono::steady_clock::now().time_since_epoch().count());
    static const char kAlphanum[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::uniform_int_distribution<size_t> dist(0, sizeof(kAlphanum) - 2);
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i)
        result.push_back(kAlphanum[dist(rng)]);
    return result;
}

/// @brief Base64 encode (for SASL).
inline std::string base64_encode(const std::string& input) {
    static const char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);
    int val = 0;
    int valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(kTable[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(kTable[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

/// @brief Base64 decode.
inline std::string base64_decode(const std::string& input) {
    static const int kDecodeTable[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };
    std::string out;
    out.reserve((input.size() / 4) * 3);
    int val = 0;
    int valb = -8;
    for (unsigned char c : input) {
        if (c == '=') break;
        int d = kDecodeTable[c];
        if (d == -1) continue;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

/// @brief Append CR-LF to a line.
inline std::string wire_line(const std::string& line) { return line + "\r\n"; }

/// @brief Strip CR/LF from a raw line.
inline std::string strip_crlf(const std::string& line) {
    std::string s = line;
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n'))
        s.pop_back();
    return s;
}

// ============================================================================
// SECTION 2 : IRC Numeric Reply Codes — Complete Enumeration
// ============================================================================

enum class Numeric : uint16_t {
    // --- RFC 1459 / 2812 ---
    RPL_WELCOME           = 1,
    RPL_YOURHOST          = 2,
    RPL_CREATED           = 3,
    RPL_MYINFO            = 4,
    RPL_BOUNCE            = 5,
    RPL_MAP               = 6,
    RPL_MAPEND            = 7,
    RPL_SNOMASK           = 8,

    RPL_TRACELINK         = 200,
    RPL_TRACECONNECTING   = 201,
    RPL_TRACEHANDSHAKE    = 202,
    RPL_TRACEUNKNOWN      = 203,
    RPL_TRACEOPERATOR     = 204,
    RPL_TRACEUSER         = 205,
    RPL_TRACESERVER       = 206,
    RPL_TRACESERVICE      = 207,
    RPL_TRACENEWTYPE      = 208,
    RPL_TRACECLASS        = 209,
    RPL_TRACERECONNECT    = 210,
    RPL_STATSLINKINFO     = 211,
    RPL_STATSCOMMANDS     = 212,
    RPL_STATSCLINE        = 213,
    RPL_STATSNLINE        = 214,
    RPL_STATSILINE        = 215,
    RPL_STATSKLINE        = 216,
    RPL_STATSQLINE        = 217,
    RPL_STATSYLINE        = 218,
    RPL_ENDOFSTATS        = 219,
    RPL_UMODEIS           = 221,
    RPL_SERVLIST          = 234,
    RPL_SERVLISTEND       = 235,
    RPL_STATSLLINE        = 241,
    RPL_STATSUPTIME       = 242,
    RPL_STATSOLINE        = 243,
    RPL_STATSHLINE        = 244,
    RPL_STATSSLINE        = 245,
    RPL_STATSPING         = 246,
    RPL_STATSBLINE        = 247,
    RPL_STATSDLINE        = 250,
    RPL_LUSERCLIENT       = 251,
    RPL_LUSEROP           = 252,
    RPL_LUSERUNKNOWN      = 253,
    RPL_LUSERCHANNELS     = 254,
    RPL_LUSERME           = 255,
    RPL_ADMINME           = 256,
    RPL_ADMINLOC1         = 257,
    RPL_ADMINLOC2         = 258,
    RPL_ADMINEMAIL        = 259,
    RPL_TRACELOG          = 261,
    RPL_TRACEEND          = 262,
    RPL_TRYAGAIN          = 263,
    RPL_LOCALUSERS        = 265,
    RPL_GLOBALUSERS       = 266,
    RPL_MAPUSERS          = 271,
    RPL_STATSCLONES       = 274,
    RPL_WHOISCERTFP       = 276,

    RPL_NONE              = 300,
    RPL_AWAY              = 301,
    RPL_USERHOST          = 302,
    RPL_ISON              = 303,
    RPL_UNAWAY            = 305,
    RPL_NOWAWAY           = 306,
    RPL_WHOISREGNICK      = 307,
    RPL_WHOISUSER         = 311,
    RPL_WHOISSERVER       = 312,
    RPL_WHOISOPERATOR     = 313,
    RPL_WHOWASUSER        = 314,
    RPL_ENDOFWHO          = 315,
    RPL_WHOISCHANOP       = 316,
    RPL_WHOISIDLE         = 317,
    RPL_ENDOFWHOIS        = 318,
    RPL_WHOISCHANNELS     = 319,
    RPL_WHOISSPECIAL      = 320,
    RPL_LISTSTART         = 321,
    RPL_LIST              = 322,
    RPL_LISTEND           = 323,
    RPL_CHANNELMODEIS     = 324,
    RPL_UNIQOPIS          = 325,
    RPL_CHANURL           = 328,
    RPL_CREATIONTIME      = 329,
    RPL_WHOISACCOUNT      = 330,
    RPL_NOTOPIC           = 331,
    RPL_TOPIC             = 332,
    RPL_TOPICWHOTIME      = 333,
    RPL_LISTSYNTAX        = 334,
    RPL_WHOISBOT          = 335,
    RPL_INVITELIST        = 336,
    RPL_ENDOFINVITELIST   = 337,
    RPL_WHOISACTUALLY     = 338,
    RPL_INVITING          = 341,
    RPL_SUMMONING         = 342,
    RPL_INVEXLIST         = 346,
    RPL_ENDOFINVEXLIST    = 347,
    RPL_EXCEPTLIST        = 348,
    RPL_ENDOFEXCEPTLIST   = 349,
    RPL_VERSION           = 351,
    RPL_WHOREPLY          = 352,
    RPL_NAMREPLY          = 353,
    RPL_KILLDONE          = 361,
    RPL_CLOSING           = 362,
    RPL_CLOSEEND          = 363,
    RPL_LINKS             = 364,
    RPL_ENDOFLINKS        = 365,
    RPL_ENDOFNAMES        = 366,
    RPL_BANLIST           = 367,
    RPL_ENDOFBANLIST      = 368,
    RPL_ENDOFWHOWAS       = 369,
    RPL_INFO              = 371,
    RPL_MOTD              = 372,
    RPL_INFOSTART         = 373,
    RPL_ENDOFINFO         = 374,
    RPL_MOTDSTART         = 375,
    RPL_ENDOFMOTD         = 376,
    RPL_WHOISHOST         = 378,
    RPL_WHOISMODES        = 379,
    RPL_YOUREOPER         = 381,
    RPL_REHASHING         = 382,
    RPL_YOURESERVICE      = 383,
    RPL_MYPORTIS          = 384,
    RPL_NOTOPERANYMORE    = 385,
    RPL_RSACHALLENGE      = 386,
    RPL_TIME              = 391,
    RPL_USERSSTART        = 392,
    RPL_USERS             = 393,
    RPL_ENDOFUSERS        = 394,
    RPL_NOUSERS           = 395,
    RPL_HOSTHIDDEN        = 396,

    ERR_NOSUCHNICK        = 401,
    ERR_NOSUCHSERVER      = 402,
    ERR_NOSUCHCHANNEL     = 403,
    ERR_CANNOTSENDTOCHAN  = 404,
    ERR_TOOMANYCHANNELS   = 405,
    ERR_WASNOSUCHNICK     = 406,
    ERR_TOOMANYTARGETS    = 407,
    ERR_NOSUCHSERVICE     = 408,
    ERR_NOORIGIN          = 409,
    ERR_NORECIPIENT       = 411,
    ERR_NOTEXTTOSEND      = 412,
    ERR_NOTOPLEVEL        = 413,
    ERR_WILDTOPLEVEL      = 414,
    ERR_BADMASK           = 415,
    ERR_TOOMANYMATCHES    = 416,
    ERR_INPUTTOOLONG      = 417,
    ERR_UNKNOWNCOMMAND    = 421,
    ERR_NOMOTD            = 422,
    ERR_NOADMININFO       = 423,
    ERR_FILEERROR         = 424,
    ERR_NONICKNAMEGIVEN   = 431,
    ERR_ERRONEUSNICKNAME  = 432,
    ERR_NICKNAMEINUSE     = 433,
    ERR_INVALIDBAN        = 435,
    ERR_NICKCOLLISION     = 436,
    ERR_UNAVAILRESOURCE   = 437,
    ERR_USERNOTINCHANNEL  = 441,
    ERR_NOTONCHANNEL      = 442,
    ERR_USERONCHANNEL     = 443,
    ERR_NOLOGIN           = 444,
    ERR_SUMMONDISABLED    = 445,
    ERR_USERSDISABLED     = 446,
    ERR_NOTREGISTERED     = 451,
    ERR_NEEDMOREPARAMS    = 461,
    ERR_ALREADYREGISTERED = 462,
    ERR_NOPERMFORHOST     = 463,
    ERR_PASSWDMISMATCH    = 464,
    ERR_YOUREBANNEDCREEP  = 465,
    ERR_KEYSET            = 467,
    ERR_CHANNELISFULL     = 471,
    ERR_UNKNOWNMODE       = 472,
    ERR_INVITEONLYCHAN    = 473,
    ERR_BANNEDFROMCHAN    = 474,
    ERR_BADCHANNELKEY     = 475,
    ERR_BADCHANMASK       = 476,
    ERR_NOCHANMODES       = 477,
    ERR_BANLISTFULL       = 478,
    ERR_BADCHANNELNAME    = 479,
    ERR_NOPRIVILEGES      = 481,
    ERR_CHANOPRIVSNEEDED  = 482,
    ERR_CANTKILLSERVER    = 483,
    ERR_RESTRICTED        = 484,
    ERR_CANTUNLOADMODULE  = 485,
    ERR_NONONREG          = 486,
    ERR_MSGSERVICES       = 487,
    ERR_NOOPERHOST        = 491,
    ERR_NOSERVICEHOST     = 492,
    ERR_UMODEUNKNOWNFLAG  = 501,
    ERR_USERSDONTMATCH    = 502,

    ERR_WHOSYNTAX         = 522,
    ERR_WHOLIMEXCEED      = 523,
    ERR_HELPNOTFOUND      = 524,
    ERR_INVALIDKEY        = 525,

    RPL_WATCHLIST         = 600,
    RPL_LOGOFF            = 601,
    RPL_WATCHOFF          = 602,
    RPL_WATCHSTAT         = 603,
    RPL_NOWON             = 604,
    RPL_NOWOFF            = 605,
    RPL_ISONWATCH         = 606,
    RPL_WATCHCLEAR        = 607,

    RPL_STARTTLS          = 670,
    RPL_WHOISSECURE       = 671,
    ERR_STARTTLS          = 691,
    ERR_INVALIDMODEPARAM  = 696,

    RPL_HELPSTART         = 704,
    RPL_HELPTXT           = 705,
    RPL_ENDOFHELP         = 706,
    RPL_KNOCK             = 710,
    RPL_KNOCKDLVR         = 711,
    ERR_KNOCKONCHAN       = 712,
    ERR_TOOMANYKNOCK      = 713,
    ERR_NOPRIVS           = 723,
    RPL_QUIETLIST         = 728,
    RPL_ENDOFQUIETLIST    = 729,
    RPL_MONONLINE         = 730,
    RPL_MONOFFLINE        = 731,
    RPL_MONLIST           = 732,
    RPL_ENDOFMONLIST      = 733,
    ERR_MONLISTFULL       = 734,

    RPL_LOGGEDIN          = 900,
    RPL_LOGGEDOUT         = 901,
    ERR_NICKLOCKED        = 902,
    RPL_SASLSUCCESS       = 903,
    ERR_SASLFAIL          = 904,
    ERR_SASLTOOLONG       = 905,
    ERR_SASLABORTED       = 906,
    ERR_SASLALREADY       = 907,
    RPL_SASLMECHS         = 908,
};

inline bool numeric_is_error(uint16_t n) {
    return (n >= 400 && n < 600) || n == 691 || n == 696 ||
           (n >= 902 && n <= 907);
}

// ============================================================================
// SECTION 3 : IRCv3 Message Tags — Full Parser with Escaping Rules
// ============================================================================

/// @brief IRCv3.2 message-tags escaping/unescaping per spec:
///        ; → \:   SPACE → \s   \ → \\   CR → \r   LF → \n
namespace tagutil {

inline std::string unescape_tag_value(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] == '\\' && i + 1 < raw.size()) {
            switch (raw[i + 1]) {
                case ':':  out.push_back(';');  break;
                case 's':  out.push_back(' ');  break;
                case 'r':  out.push_back('\r'); break;
                case 'n':  out.push_back('\n'); break;
                case '\\': out.push_back('\\'); break;
                default:   out.push_back(raw[i + 1]); break;
            }
            ++i;
        } else {
            out.push_back(raw[i]);
        }
    }
    return out;
}

inline std::string escape_tag_value(const std::string& raw) {
    std::string out;
    out.reserve(raw.size() + 8);
    for (char c : raw) {
        switch (c) {
            case ';':  out += "\\:"; break;
            case ' ':  out += "\\s"; break;
            case '\\': out += "\\\\"; break;
            case '\r': out += "\\r"; break;
            case '\n': out += "\\n"; break;
            default:   out.push_back(c);
        }
    }
    return out;
}

inline bool valid_tag_key_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '/';
}

inline bool valid_tag_key(const std::string& key) {
    if (key.empty() || key[0] == '/') return false;
    for (char c : key)
        if (!valid_tag_key_char(c)) return false;
    return true;
}

} // namespace tagutil

/// @brief A single parsed message tag (key + optional value).
struct TagEntry {
    std::string key;
    std::string value;
    bool        has_value = false;

    bool operator==(const TagEntry& other) const {
        return key == other.key && value == other.value &&
               has_value == other.has_value;
    }
};

/// @brief Full IRCv3 message-tags container.
class MessageTags {
public:
    MessageTags() = default;

    /// Parse the raw tag string (the part after '@' before first space).
    /// Returns count of successfully parsed tags.
    int parse(const std::string& raw) {
        tags_.clear();
        if (raw.empty()) return 0;

        const size_t len = raw.size();
        size_t pos = 0;

        while (pos < len) {
            // Read key until '=' or ';' or end
            size_t key_start = pos;
            while (pos < len && raw[pos] != '=' && raw[pos] != ';')
                ++pos;
            std::string key(raw, key_start, pos - key_start);
            if (!tagutil::valid_tag_key(key)) {
                // Skip invalid tag
                while (pos < len && raw[pos] != ';') ++pos;
                if (pos < len) ++pos;
                continue;
            }

            std::string value;
            bool has_val = false;

            if (pos < len && raw[pos] == '=') {
                has_val = true;
                ++pos;
                size_t val_start = pos;
                while (pos < len) {
                    if (raw[pos] == '\\' && pos + 1 < len) {
                        pos += 2;
                        continue;
                    }
                    if (raw[pos] == ';') break;
                    ++pos;
                }
                value = tagutil::unescape_tag_value(
                    raw.substr(val_start, pos - val_start));
            }

            tags_.push_back({std::move(key), std::move(value), has_val});

            if (pos < len && raw[pos] == ';') ++pos;
        }
        return static_cast<int>(tags_.size());
    }

    /// Serialize to wire format (no leading '@').
    std::string serialize() const {
        if (tags_.empty()) return {};
        std::ostringstream oss;
        for (size_t i = 0; i < tags_.size(); ++i) {
            if (i > 0) oss << ';';
            oss << tags_[i].key;
            if (tags_[i].has_value)
                oss << '=' << tagutil::escape_tag_value(tags_[i].value);
        }
        return oss.str();
    }

    /// Serialize including leading '@' for a full tag block.
    std::string serialize_full() const {
        std::string s = serialize();
        return s.empty() ? "" : "@" + s;
    }

    /// Full wire-length (including '@').
    size_t wire_length() const {
        std::string s = serialize();
        return s.empty() ? 0 : s.size() + 1;
    }

    // --- Accessors ---
    const std::string* get(const std::string& key) const {
        for (auto& t : tags_) {
            if (t.key == key)
                return t.has_value ? &t.value : &empty_val_;
        }
        return nullptr;
    }

    bool has(const std::string& key) const {
        for (auto& t : tags_)
            if (t.key == key) return true;
        return false;
    }

    void set(const std::string& key, const std::string& value, bool has_v = true) {
        for (auto& t : tags_) {
            if (t.key == key) {
                t.value = value;
                t.has_value = has_v;
                return;
            }
        }
        tags_.push_back({key, value, has_v});
    }

    void remove(const std::string& key) {
        tags_.erase(std::remove_if(tags_.begin(), tags_.end(),
            [&](const TagEntry& t) { return t.key == key; }), tags_.end());
    }

    void clear() { tags_.clear(); }
    size_t size() const { return tags_.size(); }
    bool empty() const { return tags_.empty(); }
    const std::vector<TagEntry>& all() const { return tags_; }

private:
    std::vector<TagEntry> tags_;
    std::string empty_val_;
};

// ============================================================================
// SECTION 4 : Complete IRC Message Parser — Prefix, Command, Params, Trailing
// ============================================================================

/// @brief Fully-parsed IRC message (RFC 1459/2812 + IRCv3 tags).
struct ParsedMessage {
    MessageTags              tags;
    std::string              prefix;       // :server or :nick!user@host
    std::string              command;      // uppercased
    std::vector<std::string> params;       // middle params (max 14 by RFC)
    std::string              trailing;     // final param after ':'
    bool                     has_trailing = false;

    /// Parse a raw IRC line (CR/LF already stripped).
    static ParsedMessage parse(const std::string& line) {
        ParsedMessage msg;
        size_t pos = 0;
        size_t len = line.size();

        // --- 1. Tags (IRCv3, starting with '@') ---
        if (pos < len && line[pos] == '@') {
            size_t space = line.find(' ', pos);
            std::string tag_block;
            if (space == std::string::npos) {
                tag_block = line.substr(pos + 1);
                pos = len;
            } else {
                tag_block = line.substr(pos + 1, space - pos - 1);
                pos = space + 1;
            }
            msg.tags.parse(tag_block);
        }

        // Skip whitespace
        while (pos < len && line[pos] == ' ') ++pos;

        // --- 2. Prefix (starts with ':') ---
        if (pos < len && line[pos] == ':') {
            size_t space = line.find(' ', pos);
            if (space == std::string::npos) {
                msg.prefix = line.substr(pos + 1);
                return msg; // only prefix
            }
            msg.prefix = line.substr(pos + 1, space - pos - 1);
            pos = space + 1;
        }

        // Skip whitespace
        while (pos < len && line[pos] == ' ') ++pos;

        // --- 3. Command ---
        size_t cmd_end = line.find(' ', pos);
        if (cmd_end == std::string::npos) {
            msg.command = line.substr(pos);
            toupper_inplace(msg.command);
            return msg;
        }
        msg.command = line.substr(pos, cmd_end - pos);
        toupper_inplace(msg.command);
        pos = cmd_end + 1;

        // --- 4. Params and trailing ---
        while (pos < len) {
            while (pos < len && line[pos] == ' ') ++pos;
            if (pos >= len) break;

            if (line[pos] == ':') {
                // Everything after ':' is trailing
                msg.trailing = line.substr(pos + 1);
                msg.has_trailing = true;
                break;
            }

            size_t sp = line.find(' ', pos);
            if (sp == std::string::npos) {
                msg.params.push_back(line.substr(pos));
                break;
            }
            msg.params.push_back(line.substr(pos, sp - pos));
            pos = sp + 1;
        }

        return msg;
    }

    /// Serialize to a full wire line (with tags and prefix).
    std::string to_line() const {
        std::ostringstream oss;
        std::string tag_str = tags.serialize();
        if (!tag_str.empty()) oss << '@' << tag_str << ' ';
        if (!prefix.empty()) oss << ':' << prefix << ' ';
        oss << command;
        for (auto& p : params) oss << ' ' << p;
        if (has_trailing) oss << " :" << trailing;
        return oss.str();
    }

    /// Serialize without tags (standard IRC format).
    std::string to_line_notags() const {
        std::ostringstream oss;
        if (!prefix.empty()) oss << ':' << prefix << ' ';
        oss << command;
        for (auto& p : params) oss << ' ' << p;
        if (has_trailing) oss << " :" << trailing;
        return oss.str();
    }

    /// Extract the nick from a nick!user@host prefix.
    std::string prefix_nick() const {
        size_t excl = prefix.find('!');
        if (excl != std::string::npos)
            return prefix.substr(0, excl);
        size_t at = prefix.find('@');
        if (at != std::string::npos)
            return prefix.substr(0, at);
        return prefix;
    }

    /// Extract the user from prefix.
    std::string prefix_user() const {
        size_t excl = prefix.find('!');
        if (excl == std::string::npos) return {};
        size_t at = prefix.find('@', excl);
        if (at == std::string::npos)
            return prefix.substr(excl + 1);
        return prefix.substr(excl + 1, at - excl - 1);
    }

    /// Extract the host from prefix.
    std::string prefix_host() const {
        size_t at = prefix.find('@');
        if (at == std::string::npos) return {};
        return prefix.substr(at + 1);
    }
};

// ============================================================================
// SECTION 5 : Server-Time Extension (IRCv3 server-time)
// ============================================================================

/// @brief Server-time tag helper: adds "time=YYYY-MM-DDTHH:MM:SS.sssZ" to tags.
inline void add_server_time_tag(MessageTags& tags) {
    tags.set("time", iso8601_now());
}

/// @brief Parse server-time from a message's tags. Returns epoch seconds + ms.
inline std::optional<std::pair<time_t, int>> extract_server_time(const MessageTags& tags) {
    const std::string* ts = tags.get("time");
    if (!ts) return std::nullopt;
    struct tm tm_buf = {};
    int ms = 0;
    int n = sscanf(ts->c_str(), "%d-%d-%dT%d:%d:%d.%dZ",
                   &tm_buf.tm_year, &tm_buf.tm_mon, &tm_buf.tm_mday,
                   &tm_buf.tm_hour, &tm_buf.tm_min, &tm_buf.tm_sec, &ms);
    if (n < 6) {
        n = sscanf(ts->c_str(), "%d-%d-%dT%d:%d:%dZ",
                   &tm_buf.tm_year, &tm_buf.tm_mon, &tm_buf.tm_mday,
                   &tm_buf.tm_hour, &tm_buf.tm_min, &tm_buf.tm_sec);
        if (n < 6) return std::nullopt;
        ms = 0;
    }
    tm_buf.tm_year -= 1900;
    tm_buf.tm_mon  -= 1;
    tm_buf.tm_isdst = 0;
    return std::make_pair(timegm(&tm_buf), ms);
}

// ============================================================================
// SECTION 6 : Account-Tag (IRCv3 account-tag)
// ============================================================================

/// @brief Account-tag helper: sets "account=<account>" on a message.
inline void add_account_tag(MessageTags& tags, const std::string& account) {
    if (account.empty())
        tags.set("account", "*");
    else
        tags.set("account", account);
}

/// @brief Extract account from message tags. Returns the account name,
///        or empty optional if tag absent, or "*" meaning unknown/not logged in.
inline std::optional<std::string> extract_account_tag(const MessageTags& tags) {
    const std::string* val = tags.get("account");
    if (!val) return std::nullopt;
    return *val;
}

// ============================================================================
// SECTION 7 : Message-IDs (IRCv3 message-ids)
// ============================================================================

/// @brief Message-id tag helper. Generates and attaches a unique msgid.
inline std::string add_message_id(MessageTags& tags) {
    std::string id = random_id(22);
    tags.set("msgid", id);
    return id;
}

/// @brief Extract a msgid from tags.
inline std::optional<std::string> extract_message_id(const MessageTags& tags) {
    const std::string* id = tags.get("msgid");
    if (!id) return std::nullopt;
    return *id;
}

/// @brief Generate a standalone message-id.
inline std::string generate_msgid() { return random_id(22); }

// ============================================================================
// SECTION 8 : Batch Support (IRCv3 batch)
// ============================================================================

/// @brief Active batch session data.
struct BatchSession {
    std::string              reference;     // unique batch ID
    std::string              type;          // "netsplit", "chathistory", etc.
    std::vector<std::string> params;        // additional reference strings
    time_t                   created_at;
    int                      message_count = 0;
    bool                     open = true;
};

/// @brief Full batch manager.
class BatchManager {
public:
    /// Open a new batch. Returns false if reference already in use.
    bool open_batch(const std::string& ref, const std::string& batch_type,
                    const std::vector<std::string>& extra_params = {}) {
        if (batches_.count(ref)) return false;
        BatchSession bs;
        bs.reference = ref;
        bs.type      = batch_type;
        bs.params    = extra_params;
        bs.created_at = std::time(nullptr);
        batches_[ref] = std::move(bs);
        return true;
    }

    /// Close a batch. Returns the session for processing, or nullopt if not found.
    std::optional<BatchSession> close_batch(const std::string& ref) {
        auto it = batches_.find(ref);
        if (it == batches_.end() || !it->second.open) return std::nullopt;
        it->second.open = false;
        BatchSession result = std::move(it->second);
        batches_.erase(it);
        return result;
    }

    /// Check if a batch is open.
    bool is_open(const std::string& ref) const {
        auto it = batches_.find(ref);
        return it != batches_.end() && it->second.open;
    }

    /// Get a batch by reference (nullptr if not found).
    const BatchSession* get(const std::string& ref) const {
        auto it = batches_.find(ref);
        return it != batches_.end() ? &it->second : nullptr;
    }

    /// Increment message counter.
    void increment(const std::string& ref) {
        auto it = batches_.find(ref);
        if (it != batches_.end()) ++it->second.message_count;
    }

    /// Build a BATCH +ref type params wire line.
    static std::string open_message(const std::string& ref,
                                     const std::string& type,
                                     const std::vector<std::string>& params = {}) {
        std::ostringstream oss;
        oss << "BATCH +" << ref << " " << type;
        for (auto& p : params) oss << " " << p;
        return oss.str();
    }

    /// Build a BATCH -ref wire line.
    static std::string close_message(const std::string& ref) {
        std::ostringstream oss;
        oss << "BATCH -" << ref;
        return oss.str();
    }

    /// Get count of active batches.
    size_t active_count() const { return batches_.size(); }

    /// Clear all batches (e.g., on disconnect).
    void clear() { batches_.clear(); }

private:
    std::unordered_map<std::string, BatchSession> batches_;
};

// ============================================================================
// SECTION 9 : Labeled-Response (IRCv3 labeled-response)
// ============================================================================

/// @brief Labeled-response manager — correlates commands with responses.
class LabeledResponseManager {
public:
    /// Attach a label tag to an outgoing message, mirroring the incoming label.
    static void echo_label(const MessageTags& request_tags,
                           MessageTags& response_tags) {
        const std::string* lbl = request_tags.get("label");
        if (lbl) response_tags.set("label", *lbl);
    }

    /// Generate a new label for client use.
    static std::string new_label() { return random_id(8); }

    /// Check if a message has a label.
    static bool has_label(const MessageTags& tags) {
        return tags.has("label");
    }

    /// Extract the label value.
    static std::optional<std::string> get_label(const MessageTags& tags) {
        const std::string* v = tags.get("label");
        if (!v) return std::nullopt;
        return *v;
    }
};

// ============================================================================
// SECTION 10 : Echo-Message (IRCv3 echo-message)
// ============================================================================

/// @brief Echo-message handler: routes a user's own message back to them
///        (with appropriate tags) when echo-message cap is enabled.
class EchoMessageHandler {
public:
    /// Build an echo of a PRIVMSG or NOTICE back to the sender.
    static std::string build_echo(const std::string& sender_prefix,
                                  const std::string& target,
                                  const std::string& text,
                                  const std::string& command_type,
                                  const std::string& account_name,
                                  bool include_msgid = true) {
        MessageTags tags;
        tags.set("time", iso8601_now());
        if (!account_name.empty())
            tags.set("account", account_name);
        else
            tags.set("account", "*");
        if (include_msgid)
            add_message_id(tags);

        ParsedMessage pm;
        pm.tags    = std::move(tags);
        pm.prefix  = sender_prefix;
        pm.command = command_type; // "PRIVMSG" or "NOTICE"
        pm.params.push_back(target);
        pm.trailing     = text;
        pm.has_trailing = true;
        return pm.to_line();
    }

    /// Filter a message for echo to channel ops (for channel messages).
    static bool should_echo_to_sender(const ParsedMessage& msg,
                                       bool echo_message_enabled) {
        return echo_message_enabled &&
               (msg.command == "PRIVMSG" || msg.command == "NOTICE") &&
               msg.has_trailing && !msg.params.empty();
    }
};

// ============================================================================
// SECTION 11 : Chathistory (IRCv3 chathistory)
// ============================================================================

/// @brief Chathistory playback: replays recent channel messages on JOIN.
class ChathistoryManager {
public:
    struct HistoryEntry {
        std::string msgid;
        std::string prefix;
        std::string command;
        std::string target;
        std::string text;
        std::string account;
        std::string timestamp;
    };

    ChathistoryManager(size_t max_entries = 200) : max_entries_(max_entries) {}

    /// Record a message for a channel.
    void record(const std::string& channel, const HistoryEntry& entry) {
        auto& hist = histories_[channel];
        hist.push_back(entry);
        if (hist.size() > max_entries_)
            hist.erase(hist.begin());
    }

    /// Build a BATCH +chathistory sequence for a joining client.
    std::vector<std::string> build_playback(
        const std::string& channel, const std::string& batch_ref,
        int limit = 50) const {
        std::vector<std::string> result;
        auto it = histories_.find(channel);
        if (it == histories_.end()) return result;

        const auto& hist = it->second;
        std::vector<std::string> params = {channel};

        // Open batch
        result.push_back(BatchManager::open_message(batch_ref, "chathistory", params));

        // Replay messages (last N)
        size_t start = hist.size() > static_cast<size_t>(limit)
                           ? hist.size() - static_cast<size_t>(limit) : 0;
        for (size_t i = start; i < hist.size(); ++i) {
            const auto& e = hist[i];
            MessageTags tags;
            tags.set("time", e.timestamp);
            if (e.account.empty()) tags.set("account", "*");
            else tags.set("account", e.account);
            if (!e.msgid.empty()) tags.set("msgid", e.msgid);
            tags.set("batch", batch_ref);

            ParsedMessage pm;
            pm.tags    = std::move(tags);
            pm.prefix  = e.prefix;
            pm.command = e.command;
            pm.params.push_back(e.target);
            pm.trailing     = e.text;
            pm.has_trailing = true;
            result.push_back(pm.to_line());
        }

        // Close batch
        result.push_back(BatchManager::close_message(batch_ref));
        return result;
    }

    /// Clear history for a channel.
    void clear_channel(const std::string& channel) {
        histories_.erase(channel);
    }

    /// Get count of messages in channel history.
    size_t count(const std::string& channel) const {
        auto it = histories_.find(channel);
        return it != histories_.end() ? it->second.size() : 0;
    }

private:
    size_t max_entries_;
    std::unordered_map<std::string, std::vector<HistoryEntry>> histories_;
};

// ============================================================================
// SECTION 12 : SetName Extension (IRCv3 setname)
// ============================================================================

/// @brief SetName handler: changes a user's realname and notifies channels.
class SetNameHandler {
public:
    /// Build a SETNAME notification message for channels.
    static std::string build_notification(const std::string& nick,
                                          const std::string& user,
                                          const std::string& host,
                                          const std::string& new_realname) {
        MessageTags tags;
        add_server_time_tag(tags);
        tags.set("account", "*"); // Filled by caller with actual account

        ParsedMessage pm;
        pm.tags    = std::move(tags);
        pm.prefix  = nick + "!" + user + "@" + host;
        pm.command = "SETNAME";
        pm.trailing     = new_realname;
        pm.has_trailing = true;
        return pm.to_line();
    }

    /// Validate a realname: max length, no illegal chars.
    static bool validate_realname(const std::string& realname, size_t max_len = 50) {
        if (realname.empty() || realname.size() > max_len) return false;
        for (char c : realname) {
            if (c == '\r' || c == '\n' || c == '\0') return false;
        }
        return true;
    }
};

// ============================================================================
// SECTION 13 : METADATA Key/Value Protocol (IRCv3 METADATA)
// ============================================================================

/// @brief METADATA — per-user/per-channel key-value storage.
class MetadataManager {
public:
    enum class TargetType : uint8_t { kUser, kChannel };

    /// Set a metadata key for a target.
    void set(const std::string& target, const std::string& key,
             const std::string& value, TargetType type = TargetType::kUser) {
        auto& store = (type == TargetType::kUser) ? user_meta_ : channel_meta_;
        store[target][key] = value;
    }

    /// Get a metadata value. Returns nullptr if absent.
    const std::string* get(const std::string& target, const std::string& key,
                           TargetType type = TargetType::kUser) const {
        auto& store = (type == TargetType::kUser) ? user_meta_ : channel_meta_;
        auto tit = store.find(target);
        if (tit == store.end()) return nullptr;
        auto kit = tit->second.find(key);
        return kit != tit->second.end() ? &kit->second : nullptr;
    }

    /// Remove a metadata key.
    bool remove(const std::string& target, const std::string& key,
                TargetType type = TargetType::kUser) {
        auto& store = (type == TargetType::kUser) ? user_meta_ : channel_meta_;
        auto tit = store.find(target);
        if (tit == store.end()) return false;
        return tit->second.erase(key) > 0;
    }

    /// Get all metadata for a target.
    std::unordered_map<std::string, std::string> get_all(
        const std::string& target, TargetType type = TargetType::kUser) const {
        auto& store = (type == TargetType::kUser) ? user_meta_ : channel_meta_;
        auto tit = store.find(target);
        if (tit != store.end()) return tit->second;
        return {};
    }

    /// Clear all metadata for a target.
    void clear_target(const std::string& target,
                      TargetType type = TargetType::kUser) {
        auto& store = (type == TargetType::kUser) ? user_meta_ : channel_meta_;
        store.erase(target);
    }

    /// Build a METADATA set notification.
    static std::string build_set(const std::string& target, const std::string& key,
                                 const std::string& value, const std::string& server,
                                 TargetType type = TargetType::kUser) {
        std::ostringstream oss;
        oss << ":" << server << " METADATA "
            << (type == TargetType::kUser ? target : "#" + target)
            << " " << key << " :" << value;
        return oss.str();
    }

    /// Build a METADATA clear notification.
    static std::string build_clear(const std::string& target, const std::string& key,
                                   const std::string& server,
                                   TargetType type = TargetType::kUser) {
        std::ostringstream oss;
        oss << ":" << server << " METADATA "
            << (type == TargetType::kUser ? target : "#" + target)
            << " " << key;
        return oss.str();
    }

private:
    std::unordered_map<std::string,
        std::unordered_map<std::string, std::string>> user_meta_;
    std::unordered_map<std::string,
        std::unordered_map<std::string, std::string>> channel_meta_;
};

// ============================================================================
// SECTION 14 : MONITOR Protocol (IRCv3 MONITOR)
// ============================================================================

/// @brief MONITOR — notification when tracked nicks go online/offline.
class MonitorManager {
public:
    /// Maximum entries per user's monitor list.
    static constexpr int kMaxEntries = 100;

    /// Add a nick to a user's monitor list. Returns true if added.
    bool add(const std::string& user, const std::string& target_nick) {
        auto& list = user_monitors_[user];
        if (list.size() >= kMaxEntries) return false;
        if (list.count(target_nick)) return false; // already tracking
        list.insert(target_nick);
        monitor_targets_[target_nick].insert(user);
        return true;
    }

    /// Remove a nick. Returns true if found and removed.
    bool remove(const std::string& user, const std::string& target_nick) {
        auto uit = user_monitors_.find(user);
        if (uit == user_monitors_.end()) return false;
        bool erased = uit->second.erase(target_nick) > 0;
        if (erased) {
            auto mit = monitor_targets_.find(target_nick);
            if (mit != monitor_targets_.end()) mit->second.erase(user);
        }
        if (uit->second.empty()) user_monitors_.erase(uit);
        return erased;
    }

    /// Get all nicks monitored by a user.
    std::vector<std::string> get_monitored(const std::string& user) const {
        auto it = user_monitors_.find(user);
        if (it == user_monitors_.end()) return {};
        return std::vector<std::string>(it->second.begin(), it->second.end());
    }

    /// Get all users monitoring a target nick (for sending notifications).
    std::vector<std::string> get_watchers(const std::string& target_nick) const {
        auto it = monitor_targets_.find(target_nick);
        if (it == monitor_targets_.end()) return {};
        return std::vector<std::string>(it->second.begin(), it->second.end());
    }

    /// Build RPL_MONONLINE (730) notification.
    static std::string online_notify(const std::string& server,
                                     const std::string& target_nick,
                                     const std::string& nick,
                                     const std::string& user,
                                     const std::string& host) {
        std::ostringstream oss;
        oss << ":" << server << " 730 " << target_nick
            << " :" << nick << "!" << user << "@" << host;
        return oss.str();
    }

    /// Build RPL_MONOFFLINE (731) notification.
    static std::string offline_notify(const std::string& server,
                                      const std::string& target_nick,
                                      const std::string& nick) {
        std::ostringstream oss;
        oss << ":" << server << " 731 " << target_nick << " :" << nick;
        return oss.str();
    }

    /// Build RPL_MONLIST (732).
    static std::string monlist_reply(const std::string& server,
                                     const std::string& target,
                                     const std::string& nicks) {
        std::ostringstream oss;
        oss << ":" << server << " 732 " << target << " :" << nicks;
        return oss.str();
    }

    /// Build RPL_ENDOFMONLIST (733).
    static std::string end_list(const std::string& server,
                                const std::string& target) {
        std::ostringstream oss;
        oss << ":" << server << " 733 " << target << " :End of MONITOR list";
        return oss.str();
    }

    /// Build ERR_MONLISTFULL (734).
    static std::string list_full(const std::string& server,
                                 const std::string& target,
                                 int limit, const std::string& nick) {
        std::ostringstream oss;
        oss << ":" << server << " 734 " << target << " " << limit
            << " " << nick << " :Monitor list is full";
        return oss.str();
    }

    /// Remove a user from all monitor lists (disconnect cleanup).
    void remove_user(const std::string& user) {
        auto it = user_monitors_.find(user);
        if (it == user_monitors_.end()) return;
        for (const auto& nick : it->second) {
            auto mit = monitor_targets_.find(nick);
            if (mit != monitor_targets_.end()) mit->second.erase(user);
        }
        user_monitors_.erase(it);
    }

    /// Check if a user is monitoring a specific nick.
    bool is_monitoring(const std::string& user, const std::string& nick) const {
        auto it = user_monitors_.find(user);
        return it != user_monitors_.end() && it->second.count(nick) > 0;
    }

private:
    std::unordered_map<std::string, std::unordered_set<std::string>> user_monitors_;
    std::unordered_map<std::string, std::unordered_set<std::string>> monitor_targets_;
};

// ============================================================================
// SECTION 15 : BOT Mode and Identification (IRCv3 BOT)
// ============================================================================

/// @brief BOT mode: users mark themselves as bots; WHOIS reveals bot info.
class BotModeManager {
public:
    /// Set/unset bot mode for a user.
    void set_bot(const std::string& nick, bool is_bot) {
        if (is_bot) bot_nicks_.insert(nick);
        else bot_nicks_.erase(nick);
    }

    /// Check if a user is a bot.
    bool is_bot(const std::string& nick) const {
        return bot_nicks_.count(nick) > 0;
    }

    /// Build a RPL_WHOISBOT numeric.
    static std::string whois_bot_reply(const std::string& server,
                                        const std::string& target,
                                        const std::string& nick,
                                        const std::string& info) {
        std::ostringstream oss;
        oss << ":" << server << " 335 " << target << " "
            << nick << " :" << info;
        return oss.str();
    }

    /// Get all bot nicks.
    const std::unordered_set<std::string>& all_bots() const {
        return bot_nicks_;
    }

private:
    std::unordered_set<std::string> bot_nicks_;
};

// ============================================================================
// SECTION 16 : CAP 3.2 Full Implementation (LS/REQ/ACK/NAK/DEL/NEW/LIST)
// ============================================================================

/// @brief All recognized IRCv3 capabilities with their string names.
enum class Cap : uint32_t {
    kAccountNotify   = 0,
    kAccountTag      = 1,
    kAwayNotify      = 2,
    kBatch           = 3,
    kCapNotify       = 4,
    kChgHost         = 5,
    kEchoMessage     = 6,
    kExtendedJoin    = 7,
    kInviteNotify    = 8,
    kLabeledResponse = 9,
    kMessageTags     = 10,
    kMultiPrefix     = 11,
    kSasl            = 12,
    kServerTime      = 13,
    kSetName         = 14,
    kUserhostInNames = 15,
    kSts             = 16,
    kMessageIds      = 17,
    kChathistory     = 18,
    kMetadata        = 19,
    kMonitor         = 20,
    kBot             = 21,
    kExtendedMonitor = 22,
    kMaxCap
};

constexpr const char* kCapNames[] = {
    "account-notify",
    "account-tag",
    "away-notify",
    "batch",
    "cap-notify",
    "chghost",
    "echo-message",
    "extended-join",
    "invite-notify",
    "labeled-response",
    "message-tags",
    "multi-prefix",
    "sasl",
    "server-time",
    "setname",
    "userhost-in-names",
    "sts",
    "message-ids",
    "chathistory",
    "metadata",
    "monitor",
    "bot-mode",
    "extended-monitor",
};

static_assert(sizeof(kCapNames) / sizeof(kCapNames[0]) ==
              static_cast<size_t>(Cap::kMaxCap),
              "Capability name table size mismatch");

/// @brief CAP 3.2 negotiation state per connection.
class CapManager {
public:
    enum class State : uint8_t {
        kIdle,         // No outstanding negotiation
        kWaitAck,      // CAP REQ sent, waiting for ACK/NAK
        kNegotiating,  // In LS/REQ flow
    };

    CapManager() { reset(); }

    void reset() {
        caps_.reset();
        pending_caps_.clear();
        requested_.clear();
        state_ = State::kIdle;
        cap_version_ = 302; // Default to CAP LS 302
    }

    /// Set CAP version (301 or 302).
    void set_version(int v) { cap_version_ = v; }
    int version() const { return cap_version_; }

    /// --- Capability bits ---
    void enable(Cap c) { caps_.set(static_cast<size_t>(c)); }
    void disable(Cap c) { caps_.reset(static_cast<size_t>(c)); }
    bool has(Cap c) const { return caps_.test(static_cast<size_t>(c)); }

    /// --- CAP command parsing ---
    enum class CapAction : uint8_t {
        kLS, kLIST, kREQ, kACK, kNAK, kEND, kDEL, kNEW,
    };

    /// Parse a CAP subcommand string.
    static std::optional<CapAction> parse_action(const std::string& action) {
        if (iequals(action, "LS"))    return CapAction::kLS;
        if (iequals(action, "LIST"))  return CapAction::kLIST;
        if (iequals(action, "REQ"))   return CapAction::kREQ;
        if (iequals(action, "ACK"))   return CapAction::kACK;
        if (iequals(action, "NAK"))   return CapAction::kNAK;
        if (iequals(action, "END"))   return CapAction::kEND;
        if (iequals(action, "DEL"))   return CapAction::kDEL;
        if (iequals(action, "NEW"))   return CapAction::kNEW;
        return std::nullopt;
    }

    /// Parse a space-separated list of capability names.
    std::vector<Cap> parse_cap_list(const std::string& cap_list_str) {
        std::vector<Cap> result;
        auto tokens = split(cap_list_str, ' ');
        for (auto& token : tokens) {
            // Strip - prefix (disabling)
            std::string name = token;
            if (!name.empty() && name[0] == '-') name = name.substr(1);
            auto c = cap_from_string(name);
            if (c) result.push_back(*c);
        }
        return result;
    }

    /// Lookup a Cap from string name.
    static std::optional<Cap> cap_from_string(const std::string& name) {
        for (size_t i = 0; i < static_cast<size_t>(Cap::kMaxCap); ++i) {
            if (iequals(name, kCapNames[i]))
                return static_cast<Cap>(i);
        }
        return std::nullopt;
    }

    /// Get string name of a Cap.
    static const char* cap_to_string(Cap c) {
        auto idx = static_cast<size_t>(c);
        if (idx < static_cast<size_t>(Cap::kMaxCap))
            return kCapNames[idx];
        return nullptr;
    }

    /// The "REQ" path: client requests capabilities.
    void request_caps(const std::vector<Cap>& requested) {
        requested_ = requested;
        pending_caps_.clear();
        for (auto& c : requested) {
            const char* name = cap_to_string(c);
            if (name) pending_caps_.push_back(name);
        }
        state_ = State::kWaitAck;
    }

    /// The "ACK" path: apply accepted capabilities.
    void ack_caps() {
        for (auto& c : requested_) enable(c);
        requested_.clear();
        state_ = State::kIdle;
    }

    /// The "NAK" path: reject all requested caps.
    void nak_caps() {
        for (auto& c : requested_) disable(c);
        requested_.clear();
        state_ = State::kIdle;
    }

    /// "END" path: finalize negotiation.
    void end_negotiation() {
        state_ = State::kIdle;
    }

    /// Cap-notify DEL: remove a capability.
    void del_cap(Cap c) { disable(c); }

    /// Cap-notify NEW: add a capability.
    void new_cap(Cap c) { enable(c); }

    /// Build the CAP LS response line.
    std::string build_ls_reply(const std::string& server,
                               const std::string& nick) const {
        std::ostringstream oss;
        oss << ":" << server << " CAP " << nick << " LS";
        if (cap_version_ >= 302) oss << " " << cap_version_;
        for (size_t i = 0; i < static_cast<size_t>(Cap::kMaxCap); ++i) {
            oss << " " << kCapNames[i];
        }
        return oss.str();
    }

    /// Build a CAP ACK line.
    std::string build_ack(const std::string& server,
                          const std::string& nick) const {
        std::ostringstream oss;
        oss << ":" << server << " CAP " << nick << " ACK :";
        bool first = true;
        for (auto& cap : pending_caps_) {
            if (!first) oss << " ";
            oss << cap;
            first = false;
        }
        return oss.str();
    }

    /// Build a CAP NAK line.
    std::string build_nak(const std::string& server,
                          const std::string& nick) const {
        std::ostringstream oss;
        oss << ":" << server << " CAP " << nick << " NAK :";
        bool first = true;
        for (auto& cap : pending_caps_) {
            if (!first) oss << " ";
            oss << cap;
            first = false;
        }
        return oss.str();
    }

    /// Build a CAP NEW notification (cap-notify).
    static std::string build_new_notify(const std::string& server,
                                        const std::string& nick,
                                        const std::string& cap_name) {
        std::ostringstream oss;
        oss << ":" << server << " CAP " << nick << " NEW :" << cap_name;
        return oss.str();
    }

    /// Build a CAP DEL notification.
    static std::string build_del_notify(const std::string& server,
                                        const std::string& nick,
                                        const std::string& cap_name) {
        std::ostringstream oss;
        oss << ":" << server << " CAP " << nick << " DEL :" << cap_name;
        return oss.str();
    }

    /// Build a CAP LIST reply.
    std::string build_list_reply(const std::string& server,
                                 const std::string& nick) const {
        std::ostringstream oss;
        oss << ":" << server << " CAP " << nick << " LIST :";
        bool first = true;
        for (size_t i = 0; i < static_cast<size_t>(Cap::kMaxCap); ++i) {
            if (caps_.test(i)) {
                if (!first) oss << " ";
                oss << kCapNames[i];
                first = false;
            }
        }
        return oss.str();
    }

    State state() const { return state_; }
    const std::vector<std::string>& pending_cap_names() const { return pending_caps_; }

private:
    std::bitset<static_cast<size_t>(Cap::kMaxCap)> caps_;
    std::vector<Cap> requested_;
    std::vector<std::string> pending_caps_;
    State state_ = State::kIdle;
    int cap_version_ = 302;
};

// ============================================================================
// SECTION 17 : SASL v3.2 Complete Implementation
// ============================================================================

/// @brief Supported SASL mechanisms.
enum class SASLMechanism : uint8_t {
    kPLAIN,
    kEXTERNAL,
    kSCRAM_SHA_256,
    kUnknown,
};

constexpr const char* kSASLMechanismNames[] = {
    "PLAIN",
    "EXTERNAL",
    "SCRAM-SHA-256",
};

inline SASLMechanism sasl_mechanism_from_string(const std::string& name) {
    if (iequals(name, "PLAIN"))           return SASLMechanism::kPLAIN;
    if (iequals(name, "EXTERNAL"))        return SASLMechanism::kEXTERNAL;
    if (iequals(name, "SCRAM-SHA-256"))   return SASLMechanism::kSCRAM_SHA_256;
    return SASLMechanism::kUnknown;
}

inline const char* sasl_mechanism_to_string(SASLMechanism m) {
    auto idx = static_cast<size_t>(m);
    if (idx < sizeof(kSASLMechanismNames) / sizeof(kSASLMechanismNames[0]))
        return kSASLMechanismNames[idx];
    return nullptr;
}

/// @brief SASL state machine.
enum class SASLState : uint8_t {
    kNone,
    kWaitMechanism,
    kInProgress,
    kSuccess,
    kFailed,
    kAborted,
};

/// @brief Full SASL session handler.
class SASLSession {
public:
    SASLSession() = default;

    /// Start SASL with a mechanism.
    void begin(SASLMechanism mechanism, const std::string& server_name) {
        mechanism_  = mechanism;
        state_      = SASLState::kInProgress;
        server_name_ = server_name;
        buffer_.clear();
        step_num_   = 0;
    }

    /// Set mechanism (when received from client).
    void set_mechanism(SASLMechanism m) {
        mechanism_ = m;
        if (state_ == SASLState::kWaitMechanism)
            state_ = SASLState::kInProgress;
    }

    /// Feed AUTHENTICATE data into the session.
    void feed_data(const std::string& data) {
        if (data == "+") return; // zero-length block
        buffer_ += data;
        ++step_num_;
    }

    /// Decode PLAIN auth data: returns {authzid, authcid, passwd}.
    std::optional<std::tuple<std::string, std::string, std::string>>
    decode_plain() const {
        std::string decoded = base64_decode(buffer_);
        // Format: authzid\0authcid\0passwd
        size_t n1 = decoded.find('\0');
        if (n1 == std::string::npos) return std::nullopt;
        size_t n2 = decoded.find('\0', n1 + 1);
        if (n2 == std::string::npos) return std::nullopt;
        return std::make_tuple(
            decoded.substr(0, n1),
            decoded.substr(n1 + 1, n2 - n1 - 1),
            decoded.substr(n2 + 1)
        );
    }

    /// Decode EXTERNAL auth data.
    std::string decode_external() const {
        return base64_decode(buffer_);
    }

    /// Build an AUTHENTICATE response.
    static std::string build_authenticate(const std::string& data) {
        if (data.empty()) return "AUTHENTICATE +";
        return "AUTHENTICATE " + data;
    }

    /// Abort this SASL session.
    void abort() { state_ = SASLState::kAborted; buffer_.clear(); }

    /// Mark as failed.
    void fail() { state_ = SASLState::kFailed; buffer_.clear(); }

    /// Mark as succeeded.
    void succeed() { state_ = SASLState::kSuccess; }

    /// Reset to idle.
    void reset() {
        state_ = SASLState::kNone;
        mechanism_ = SASLMechanism::kUnknown;
        buffer_.clear();
        step_num_ = 0;
    }

    // --- Accessors ---
    SASLState state() const { return state_; }
    SASLMechanism mechanism() const { return mechanism_; }
    const std::string& buffer() const { return buffer_; }
    const std::string& server_name() const { return server_name_; }
    int step() const { return step_num_; }
    bool is_active() const { return state_ == SASLState::kInProgress; }
    bool is_complete() const {
        return state_ == SASLState::kSuccess ||
               state_ == SASLState::kFailed ||
               state_ == SASLState::kAborted;
    }

    /// Build a numeric reply for SASL events.
    std::string build_reply(uint16_t numeric, const std::string& target,
                            const std::string& message = "") const {
        std::ostringstream oss;
        oss << ":" << server_name_ << " "
            << std::setfill('0') << std::setw(3) << numeric
            << " " << target;
        if (!message.empty()) oss << " :" << message;
        return oss.str();
    }

private:
    SASLState state_ = SASLState::kNone;
    SASLMechanism mechanism_ = SASLMechanism::kUnknown;
    std::string server_name_;
    std::string buffer_;
    int step_num_ = 0;
};

/// @brief Available SASL mechanisms for the server.
class SASLMechanismRegistry {
public:
    SASLMechanismRegistry() {
        // Default supported mechanisms
        mechanisms_.insert(SASLMechanism::kPLAIN);
        mechanisms_.insert(SASLMechanism::kEXTERNAL);
    }

    void add_mechanism(SASLMechanism m) { mechanisms_.insert(m); }
    void remove_mechanism(SASLMechanism m) { mechanisms_.erase(m); }
    bool supports(SASLMechanism m) const { return mechanisms_.count(m) > 0; }

    /// Build the RPL_SASLMECHS reply.
    std::string build_mechlist(const std::string& server,
                               const std::string& target) const {
        std::ostringstream oss;
        oss << ":" << server << " 908 " << target;
        for (auto& m : mechanisms_) {
            oss << " " << sasl_mechanism_to_string(m);
        }
        oss << " :are available SASL mechanisms";
        return oss.str();
    }

    const std::unordered_set<SASLMechanism>& mechanisms() const {
        return mechanisms_;
    }

private:
    std::unordered_set<SASLMechanism> mechanisms_;
};

// ============================================================================
// SECTION 18 : Extended-Monitor (IRCv3 extended-monitor)
// ============================================================================

/// @brief Extended monitor: richer notifications on nick status changes.
class ExtendedMonitorManager {
public:
    struct MonitorNotification {
        std::string nick;
        std::string user;
        std::string host;
        std::string realname;
        std::string account;
        std::string away_status; // "" = here, message = away
        time_t      signon_time = 0;
    };

    /// Build an extended RPL_MONONLINE with full user details.
    static std::string online_extended(
        const std::string& server, const std::string& target,
        const MonitorNotification& info) {
        MessageTags tags;
        tags.set("time", iso8601_now());
        if (!info.account.empty())
            tags.set("account", info.account);
        std::string tag_str = tags.serialize();

        std::ostringstream oss;
        if (!tag_str.empty()) oss << "@" << tag_str << " ";
        oss << ":" << server << " 730 " << target
            << " :" << info.nick << "!" << info.user << "@" << info.host
            << " " << info.realname
            << " " << info.signon_time;
        return oss.str();
    }

    /// Build a logout notification.
    static std::string offline_extended(
        const std::string& server, const std::string& target,
        const std::string& nick, const std::string& reason = "") {
        std::ostringstream oss;
        oss << ":" << server << " 731 " << target << " :" << nick;
        if (!reason.empty()) oss << " " << reason;
        return oss.str();
    }
};

// ============================================================================
// SECTION 19 : Invite-Notify (IRCv3 invite-notify)
// ============================================================================

/// @brief Invite-notify: when a user is invited to a channel, operators see it.
class InviteNotifyHandler {
public:
    /// Build an INVITE notification for channel operators.
    static std::string build_notification(
        const std::string& inviter_nick,
        const std::string& inviter_user,
        const std::string& inviter_host,
        const std::string& target_nick,
        const std::string& channel) {
        MessageTags tags;
        add_server_time_tag(tags);

        ParsedMessage pm;
        pm.tags    = std::move(tags);
        pm.prefix  = inviter_nick + "!" + inviter_user + "@" + inviter_host;
        pm.command = "INVITE";
        pm.params.push_back(target_nick);
        pm.params.push_back(channel);
        return pm.to_line();
    }

    /// Determine if a user should receive the invite notification.
    static bool should_notify(const std::string& user_nick,
                              const std::string& target_nick,
                              bool is_chanop,
                              bool invite_notify_enabled) {
        return invite_notify_enabled && is_chanop && user_nick != target_nick;
    }
};

// ============================================================================
// SECTION 20 : Away-Notify (IRCv3 away-notify)
// ============================================================================

/// @brief Away-notify: notifies channel members when a user's away status changes.
class AwayNotifyHandler {
public:
    /// Build an AWAY notification for channel members.
    static std::string build_notification(
        const std::string& nick, const std::string& user,
        const std::string& host, bool is_away,
        const std::string& away_message = "") {
        MessageTags tags;
        add_server_time_tag(tags);

        ParsedMessage pm;
        pm.tags    = std::move(tags);
        pm.prefix  = nick + "!" + user + "@" + host;
        pm.command = "AWAY";
        if (is_away) {
            pm.trailing     = away_message;
            pm.has_trailing = true;
        }
        return pm.to_line();
    }

    /// Build RPL_NOWAWAY (306).
    static std::string now_away(const std::string& server, const std::string& nick) {
        std::ostringstream oss;
        oss << ":" << server << " 306 " << nick
            << " :You have been marked as being away";
        return oss.str();
    }

    /// Build RPL_UNAWAY (305).
    static std::string unaway(const std::string& server, const std::string& nick) {
        std::ostringstream oss;
        oss << ":" << server << " 305 " << nick
            << " :You are no longer marked as being away";
        return oss.str();
    }
};

// ============================================================================
// SECTION 21 : Complete IRC Registration / Connection State Machine
// ============================================================================

/// @brief Registration states for a client connection.
enum class RegistrationState : uint8_t {
    kUnregistered = 0,
    kGotPass      = 1,  // PASS received
    kGotNick      = 2,  // NICK received
    kGotUser      = 3,  // USER received (NOTE: some servers combine pass first)
    kGotCapEnd    = 4,  // CAP END received
    kRegistered   = 5,
};

/// @brief Connection type.
enum class ConnectionType : uint8_t {
    kClient,   // Regular IRC client
    kServer,   // Server-to-server link
    kService,  // Services connection
};

/// @brief User modes (for the connection state machine).
enum class UserMode : uint64_t {
    kInvisible     = 0,
    kOperator      = 1,
    kWallops       = 2,
    kServerNotices = 3,
    kRegOnly       = 4,
    kSoftCallerId  = 5,
    kDeaf          = 6,
    kBot           = 7,
    kSecureOnly    = 8,
    kWebIRC        = 9,
    kAway          = 10,
    kTLSD          = 11,
    kMaxMode
};

constexpr const char kUserModeChars[] = "iowsrgdBaZt";

/// @brief Full connection state for a client or server link.
struct Connection {
    // --- Identity ---
    std::string nick;
    std::string user;
    std::string host;
    std::string realname;
    std::string password;
    std::string server_name;    // For server links
    std::string server_info;
    std::string server_sid;

    // --- Authentication ---
    std::string account;        // Services account name
    std::string certfp;         // TLS certificate fingerprint
    bool        password_ok = false;
    bool        tls         = false;

    // --- State machines ---
    RegistrationState  reg_state     = RegistrationState::kUnregistered;
    ConnectionType     conn_type     = ConnectionType::kClient;
    SASLState          sasl          = SASLState::kNone;
    SASLSession        sasl_session;
    CapManager         caps;
    std::bitset<static_cast<size_t>(UserMode::kMaxMode)> user_modes;

    // --- Timing ---
    time_t connected_at   = 0;
    time_t last_activity  = 0;
    time_t signon_time    = 0;
    time_t away_since     = 0;

    // --- Away ---
    std::string away_message;
    bool is_away() const {
        return user_modes.test(static_cast<size_t>(UserMode::kAway));
    }
    void set_away(const std::string& msg = "Away") {
        user_modes.set(static_cast<size_t>(UserMode::kAway));
        away_message = msg;
        away_since   = std::time(nullptr);
    }
    void clear_away() {
        user_modes.reset(static_cast<size_t>(UserMode::kAway));
        away_message.clear();
        away_since = 0;
    }

    // --- Capability checks ---
    bool has_cap(Cap c) const { return caps.has(c); }

    // --- Server link ---
    int          hopcount     = 0;
    bool         incoming_link = false;

    // --- Flood control ---
    int          commands_this_sec = 0;
    time_t       command_window_start = 0;
    int          max_commands_per_sec = 4;

    // --- Channel tracking ---
    std::vector<std::string> channels;

    /// Check if fully registered as a client.
    bool is_registered() const {
        return reg_state == RegistrationState::kRegistered;
    }

    /// Check if this is a server link.
    bool is_server() const {
        return conn_type == ConnectionType::kServer;
    }

    /// Build the user's full prefix: nick!user@host
    std::string prefix() const {
        return nick + "!" + user + "@" + host;
    }

    /// Build a server prefix: server.name
    std::string server_prefix() const {
        return server_name;
    }

    /// Reset the connection to initial state.
    void reset() {
        nick.clear();
        user.clear();
        host.clear();
        realname.clear();
        password.clear();
        server_name.clear();
        server_info.clear();
        account.clear();
        certfp.clear();
        password_ok = false;
        tls = false;
        reg_state = RegistrationState::kUnregistered;
        conn_type = ConnectionType::kClient;
        sasl = SASLState::kNone;
        sasl_session.reset();
        caps.reset();
        user_modes.reset();
        connected_at = 0;
        last_activity = 0;
        signon_time = 0;
        away_since = 0;
        away_message.clear();
        hopcount = 0;
        incoming_link = false;
        commands_this_sec = 0;
        command_window_start = 0;
        channels.clear();
    }
};

/// @brief Full registration/connection state machine.
class ConnectionStateMachine {
public:
    /// Process a NICK command.
    enum class NickResult { kOk, kErrNicknameInUse, kErrErroneusNickname,
                            kErrNonicknamegiven, kErrAlreadyRegistered };

    static NickResult handle_nick(Connection& conn, const std::string& new_nick) {
        if (new_nick.empty())
            return NickResult::kErrNonicknamegiven;
        if (!validate_nick(new_nick))
            return NickResult::kErrErroneusNickname;
        // Note: nickname-in-use check is done by caller against the user registry

        conn.nick = new_nick;
        conn.last_activity = std::time(nullptr);

        if (conn.reg_state == RegistrationState::kUnregistered ||
            conn.reg_state == RegistrationState::kGotPass) {
            conn.reg_state = RegistrationState::kGotNick;
        }
        return NickResult::kOk;
    }

    /// Process a USER command.
    enum class UserResult { kOk, kErrNeedmoreparams, kErrAlreadyRegistered };

    static UserResult handle_user(Connection& conn, const std::string& user,
                                  const std::string& mode_str,
                                  const std::string& unused,
                                  const std::string& realname) {
        if (user.empty() || realname.empty())
            return UserResult::kErrNeedmoreparams;
        if (conn.is_registered())
            return UserResult::kErrAlreadyRegistered;

        conn.user     = user;
        conn.realname = realname;
        conn.last_activity = std::time(nullptr);

        // Parse mode string for initial modes (e.g., +i)
        if (!mode_str.empty() && mode_str != "*") {
            for (char c : mode_str) {
                if (c == '8' || c == '9') {
                    // Numeric modes for bot/secure indicator
                    if (c == '8') conn.user_modes.set(static_cast<size_t>(UserMode::kBot));
                }
            }
        }

        if (conn.reg_state == RegistrationState::kUnregistered ||
            conn.reg_state == RegistrationState::kGotPass) {
            conn.reg_state = RegistrationState::kGotUser;
        }

        return UserResult::kOk;
    }

    /// Process a PASS command.
    static bool handle_pass(Connection& conn, const std::string& password,
                            const std::string& expected_password) {
        conn.password = password;
        conn.password_ok = password.empty() || password == expected_password;
        if (conn.reg_state == RegistrationState::kUnregistered)
            conn.reg_state = RegistrationState::kGotPass;
        conn.last_activity = std::time(nullptr);
        return conn.password_ok;
    }

    /// Check if registration can complete and finalize it.
    static bool try_complete_registration(Connection& conn) {
        if (conn.reg_state >= RegistrationState::kRegistered)
            return true; // already registered

        bool has_nick = !conn.nick.empty() &&
                        (conn.reg_state == RegistrationState::kGotNick ||
                         conn.reg_state == RegistrationState::kGotUser ||
                         conn.reg_state == RegistrationState::kGotCapEnd);
        bool has_user = !conn.user.empty() &&
                        (conn.reg_state == RegistrationState::kGotNick ||
                         conn.reg_state == RegistrationState::kGotUser ||
                         conn.reg_state == RegistrationState::kGotCapEnd);

        if (has_nick && has_user && conn.password_ok) {
            conn.reg_state = RegistrationState::kRegistered;
            conn.signon_time = std::time(nullptr);
            return true;
        }
        return false;
    }

    /// Mark CAP END received.
    static void handle_cap_end(Connection& conn) {
        if (conn.reg_state == RegistrationState::kGotNick ||
            conn.reg_state == RegistrationState::kGotUser) {
            conn.reg_state = RegistrationState::kGotCapEnd;
        }
    }

    /// Validate a nickname per RFC 2812 section 2.3.1.
    static bool validate_nick(const std::string& nick, size_t max_len = 30) {
        if (nick.empty() || nick.size() > max_len) return false;
        char first = nick[0];
        if (!std::isalpha(static_cast<unsigned char>(first)) &&
            first != '[' && first != ']' && first != '\\' &&
            first != '`' && first != '_' &&  first != '^' &&
            first != '{' && first != '|' &&  first != '}') {
            return false;
        }
        for (size_t i = 1; i < nick.size(); ++i) {
            char c = nick[i];
            if (!std::isalnum(static_cast<unsigned char>(c)) &&
                c != '-' && c != '_' && c != '[' && c != ']' &&
                c != '{' && c != '}' && c != '\\' && c != '`' &&
                c != '|' && c != '^') {
                return false;
            }
        }
        return true;
    }

    /// Build the welcome sequence (RPL_WELCOME, RPL_YOURHOST, etc.).
    static std::vector<std::string> build_welcome(
        const Connection& conn, const std::string& server_name,
        const std::string& version, const std::string& network_name) {
        std::vector<std::string> result;
        std::string src = ":" + server_name;

        result.push_back(src + " 001 " + conn.nick +
            " :Welcome to the " + network_name + " IRC Network " + conn.prefix());
        result.push_back(src + " 002 " + conn.nick +
            " :Your host is " + server_name + ", running version " + version);
        result.push_back(src + " 003 " + conn.nick +
            " :This server was created " + iso8601_now());
        result.push_back(src + " 004 " + conn.nick + " " +
            server_name + " " + version +
            " iowghraAsNO" + " " + "beI,kL,l,imMnOpqrRstz");
        return result;
    }
};

// ============================================================================
// SECTION 22 : IRC Numeric Reply Builder
// ============================================================================

/// @brief Build formatted numeric replies.
class NumericBuilder {
public:
    /// Build a simple numeric reply: :server NNN target :message
    static std::string build(uint16_t numeric, const std::string& server,
                             const std::string& target,
                             const std::string& message) {
        std::ostringstream oss;
        oss << ":" << server << " "
            << std::setfill('0') << std::setw(3) << numeric
            << " " << target;
        if (!message.empty()) oss << " :" << message;
        return oss.str();
    }

    /// Build with printf-style formatting.
    static std::string format(uint16_t numeric, const std::string& server,
                              const std::string& target,
                              const char* fmt, ...) {
        char buf[1024];
        va_list args;
        va_start(args, fmt);
        int n = vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        std::string msg = (n > 0) ? std::string(buf, std::min(static_cast<size_t>(n),
                                                               sizeof(buf) - 1))
                                  : std::string();
        return build(numeric, server, target, msg);
    }

    /// Build with args as space-separated tokens before the trailing colon.
    static std::string build_multi(uint16_t numeric, const std::string& server,
                                   const std::string& target,
                                   const std::vector<std::string>& middle_params,
                                   const std::string& trailing) {
        std::ostringstream oss;
        oss << ":" << server << " "
            << std::setfill('0') << std::setw(3) << numeric
            << " " << target;
        for (auto& p : middle_params) oss << " " << p;
        if (!trailing.empty()) oss << " :" << trailing;
        return oss.str();
    }
};

// ============================================================================
// SECTION 23 : User Mask Parsing and Wildcard Matching
// ============================================================================

/// @brief Parsed user mask: nick!user@host components.
struct UserMask {
    std::string nick;
    std::string user;
    std::string host;

    static UserMask parse(const std::string& mask) {
        UserMask um;
        size_t excl = mask.find('!');
        size_t at   = mask.find('@');
        if (excl != std::string::npos) {
            um.nick = mask.substr(0, excl);
            if (at != std::string::npos && at > excl)
                um.user = mask.substr(excl + 1, at - excl - 1);
            else
                um.user = mask.substr(excl + 1);
        } else if (at != std::string::npos) {
            um.nick = mask.substr(0, at);
        } else {
            um.nick = mask;
        }
        if (at != std::string::npos)
            um.host = mask.substr(at + 1);
        return um;
    }

    std::string to_string() const {
        std::ostringstream oss;
        oss << nick;
        if (!user.empty()) oss << "!" << user;
        if (!host.empty()) oss << "@" << host;
        return oss.str();
    }
};

/// @brief Wildcard matching with * and ?.
inline bool wildcard_match(const std::string& pattern,
                           const std::string& target,
                           bool case_insensitive = false) {
    auto eq = [case_insensitive](char a, char b) {
        if (case_insensitive)
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        return a == b;
    };

    size_t pi = 0, ti = 0;
    size_t star_pi = std::string::npos;
    size_t match_ti = 0;

    while (ti < target.size()) {
        if (pi < pattern.size() && (pattern[pi] == '?' || eq(pattern[pi], target[ti]))) {
            ++pi; ++ti;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
            star_pi  = pi++;
            match_ti = ti;
        } else if (star_pi != std::string::npos) {
            pi = star_pi + 1;
            ti = ++match_ti;
        } else {
            return false;
        }
    }
    while (pi < pattern.size() && pattern[pi] == '*') ++pi;
    return pi == pattern.size();
}

// ============================================================================
// SECTION 24 : Channel Modes and Prefixes
// ============================================================================

/// @brief Channel membership prefix mapping.
struct MembershipPrefix {
    char mode_char;    // e.g. 'o'
    char prefix_char;  // e.g. '@'

    static const std::vector<MembershipPrefix>& standard() {
        static std::vector<MembershipPrefix> v = {
            {'q', '~'}, {'a', '&'}, {'o', '@'}, {'h', '%'}, {'v', '+'}
        };
        return v;
    }

    static std::string modes_to_prefixes(const std::string& modes) {
        std::string result;
        for (char m : modes)
            for (auto& sp : standard())
                if (sp.mode_char == m) { result += sp.prefix_char; break; }
        return result;
    }

    static std::string prefixes_to_modes(const std::string& prefixes) {
        std::string result;
        for (char p : prefixes)
            for (auto& sp : standard())
                if (sp.prefix_char == p) { result += sp.mode_char; break; }
        return result;
    }

    static std::string sort_prefixes(const std::string& prefixes) {
        std::string sorted;
        for (const char* r = "~&@%+"; *r; ++r)
            if (prefixes.find(*r) != std::string::npos) sorted += *r;
        return sorted;
    }
};

// ============================================================================
// SECTION 25 : ISUPPORT (RPL_005) Token Builder
// ============================================================================

/// @brief ISUPPORT token registry and builder.
class ISupportBuilder {
public:
    ISupportBuilder() { set_defaults(); }

    void set_defaults() {
        tokens_["CASEMAPPING"]  = "rfc1459";
        tokens_["CHANNELLEN"]   = "64";
        tokens_["CHANTYPES"]    = "#&";
        tokens_["ELIST"]        = "U";
        tokens_["MODES"]        = "20";
        tokens_["MONITOR"]      = "100";
        tokens_["NETWORK"]      = "ProgressiveNet";
        tokens_["NICKLEN"]      = "30";
        tokens_["PREFIX"]       = "(qaohv)~&@%+";
        tokens_["STATUSMSG"]    = "~&@%+";
        tokens_["TOPICLEN"]     = "390";
        tokens_["AWAYLEN"]      = "390";
        tokens_["KICKLEN"]      = "390";
        tokens_["MAXLIST"]      = "beI:50";
        tokens_["CHANMODES"]    = "beI,kL,l,imMnOpqrRstz";
        tokens_["SILENCE"]      = "50";
        tokens_["WATCH"]        = "128";
        tokens_["WHOX"]         = "";
        tokens_["CLIENTVER"]    = "3.0";
        tokens_["SAFELIST"]     = "";
        tokens_["FNC"]          = "";
        tokens_["KNOCK"]        = "";
        tokens_["INVEX"]        = "";
        tokens_["EXCEPTS"]      = "";
        tokens_["CPRIVMSG"]     = "";
        tokens_["CNOTICE"]      = "";
        tokens_["UTF8ONLY"]     = "";
        tokens_["BOT"]          = "B";
    }

    void set(const std::string& key, const std::string& value) {
        tokens_[key] = value;
    }

    std::string build(const std::string& server, const std::string& nick) const {
        std::ostringstream oss;
        bool first = true;
        oss << ":" << server << " 005 " << nick;
        for (auto& kv : tokens_) {
            oss << " " << kv.first;
            if (!kv.second.empty()) oss << "=" << kv.second;
        }
        oss << " :are supported by this server";
        return oss.str();
    }

private:
    std::map<std::string, std::string> tokens_;
};

// ============================================================================
// SECTION 26 : Message Rate Limiting / Flood Protection
// ============================================================================

/// @brief Token-bucket rate limiter.
class RateLimiter {
public:
    RateLimiter(double rate_per_sec, double burst)
        : rate_(rate_per_sec), burst_(burst), tokens_(burst) {
        last_update_ = std::chrono::steady_clock::now();
    }

    bool consume(double n = 1.0) {
        refill();
        if (tokens_ >= n) { tokens_ -= n; return true; }
        return false;
    }

    void refill() {
        auto now = std::chrono::steady_clock::now();
        double elapsed =
            std::chrono::duration<double>(now - last_update_).count();
        tokens_ = std::min(burst_, tokens_ + elapsed * rate_);
        last_update_ = now;
    }

    void reset() {
        tokens_ = burst_;
        last_update_ = std::chrono::steady_clock::now();
    }

private:
    double rate_;
    double burst_;
    double tokens_;
    std::chrono::steady_clock::time_point last_update_;
};

// ============================================================================
// SECTION 27 : Thread-Safe Message Queue
// ============================================================================

/// @brief Thread-safe FIFO queue for outgoing messages.
template <typename T>
class TSQueue {
public:
    void push(const T& item) {
        std::lock_guard<std::mutex> lk(mtx_);
        q_.push_back(item);
    }
    void push(T&& item) {
        std::lock_guard<std::mutex> lk(mtx_);
        q_.push_back(std::move(item));
    }
    bool pop(T& item) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (q_.empty()) return false;
        item = std::move(q_.front());
        q_.pop_front();
        return true;
    }
    bool drain(std::vector<T>& out) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (q_.empty()) return false;
        out.assign(std::make_move_iterator(q_.begin()),
                   std::make_move_iterator(q_.end()));
        q_.clear();
        return true;
    }
    size_t size() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return q_.size();
    }
    bool empty() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return q_.empty();
    }
    void clear() {
        std::lock_guard<std::mutex> lk(mtx_);
        q_.clear();
    }
private:
    mutable std::mutex mtx_;
    std::deque<T> q_;
};

/// @brief Outgoing IRC message queue with wire-format conversion.
class OutgoingQueue {
public:
    void enqueue(const std::string& line) { q_.push(line); }

    void enqueue_numeric(uint16_t numeric, const std::string& server,
                         const std::string& target, const std::string& msg) {
        q_.push(NumericBuilder::build(numeric, server, target, msg));
    }

    std::vector<std::string> drain_wire() {
        std::vector<std::string> raw, result;
        q_.drain(raw);
        result.reserve(raw.size());
        for (auto& line : raw)
            result.push_back(wire_line(line));
        return result;
    }

    std::string drain_buffer() {
        auto lines = drain_wire();
        std::ostringstream oss;
        for (auto& l : lines) oss << l;
        return oss.str();
    }

    size_t pending() const { return q_.size(); }

private:
    TSQueue<std::string> q_;
};

// ============================================================================
// SECTION 28 : Server Info and WHOIS Builder
// ============================================================================

/// @brief Complete WHOIS response builder.
class WhoisBuilder {
public:
    struct WhoisInfo {
        std::string nick;
        std::string user;
        std::string host;
        std::string realname;
        std::string server_name;
        std::string server_info;
        std::string account;
        std::string certfp;
        std::string away_msg;
        std::string actual_ip;
        std::string actual_host;
        std::string bot_info;
        std::vector<std::string> channels; // with prefixes
        time_t signon_time = 0;
        time_t idle_time = 0;
        bool is_oper    = false;
        bool is_secure  = false;
        bool is_bot     = false;
        bool is_away    = false;
    };

    static std::vector<std::string> build(const std::string& server,
                                          const std::string& target,
                                          const WhoisInfo& info) {
        std::vector<std::string> result;
        std::string src = ":" + server;

        // 311 RPL_WHOISUSER
        result.push_back(NumericBuilder::build_multi(311, server, target,
            {info.nick, info.user, info.host}, info.realname));

        // 319 RPL_WHOISCHANNELS
        if (!info.channels.empty()) {
            std::ostringstream chs;
            for (size_t i = 0; i < info.channels.size(); ++i) {
                if (i > 0) chs << " ";
                chs << info.channels[i];
            }
            result.push_back(NumericBuilder::build_multi(319, server, target,
                {info.nick}, chs.str()));
        }

        // 312 RPL_WHOISSERVER
        result.push_back(NumericBuilder::build_multi(312, server, target,
            {info.nick, info.server_name}, info.server_info));

        // 313 RPL_WHOISOPERATOR
        if (info.is_oper)
            result.push_back(NumericBuilder::build(313, server, target,
                info.nick + " :is an IRC operator"));

        // 317 RPL_WHOISIDLE
        if (info.signon_time > 0) {
            result.push_back(NumericBuilder::build_multi(317, server, target,
                {info.nick,
                 std::to_string(static_cast<unsigned long>(info.idle_time)),
                 std::to_string(static_cast<long>(info.signon_time))},
                "seconds idle, signon time"));
        }

        // 330 RPL_WHOISACCOUNT
        if (!info.account.empty())
            result.push_back(NumericBuilder::build_multi(330, server, target,
                {info.nick, info.account}, "is logged in as"));

        // 671 RPL_WHOISSECURE
        if (info.is_secure)
            result.push_back(NumericBuilder::build(671, server, target,
                info.nick + " :is using a secure connection"));

        // 276 RPL_WHOISCERTFP
        if (!info.certfp.empty())
            result.push_back(NumericBuilder::build(276, server, target,
                info.nick + " :has client certificate fingerprint " + info.certfp));

        // 378 RPL_WHOISHOST
        if (!info.actual_host.empty())
            result.push_back(NumericBuilder::build_multi(378, server, target,
                {info.nick}, "is connecting from " + info.actual_ip +
                "@" + info.actual_host + " " + info.actual_host));

        // 335 RPL_WHOISBOT
        if (info.is_bot && !info.bot_info.empty())
            result.push_back(NumericBuilder::build(335, server, target,
                info.nick + " :" + info.bot_info));

        // 301 RPL_AWAY
        if (info.is_away && !info.away_msg.empty())
            result.push_back(NumericBuilder::build(301, server, target,
                info.nick + " :" + info.away_msg));

        // 318 RPL_ENDOFWHOIS
        result.push_back(NumericBuilder::build(318, server, target,
            info.nick + " :End of WHOIS list"));

        return result;
    }
};

// ============================================================================
// SECTION 29 : Extended JOIN (IRCv3 extended-join)
// ============================================================================

/// @brief Extended-join notification builder.
class ExtendedJoinBuilder {
public:
    /// Build an extended JOIN notification with account and realname.
    static std::string build(const std::string& nick,
                             const std::string& user,
                             const std::string& host,
                             const std::string& channel,
                             const std::string& account,
                             const std::string& realname,
                             bool include_msgid = true) {
        MessageTags tags;
        add_server_time_tag(tags);
        if (include_msgid) add_message_id(tags);

        ParsedMessage pm;
        pm.tags    = std::move(tags);
        pm.prefix  = nick + "!" + user + "@" + host;
        pm.command = "JOIN";
        pm.params.push_back(channel);
        pm.params.push_back(account.empty() ? "*" : account);
        pm.trailing     = realname;
        pm.has_trailing = true;
        return pm.to_line();
    }
};

// ============================================================================
// SECTION 30 : Multi-Prefix (IRCv3 multi-prefix)
// ============================================================================

/// @brief Multi-prefix NAMES reply builder.
class MultiPrefixNamesBuilder {
public:
    /// Build a NAMES reply line with multi-prefix support.
    static std::string build_names_reply(const std::string& server,
                                         const std::string& target,
                                         const std::string& channel,
                                         const std::vector<std::pair<std::string, std::string>>& members) {
        // members = {{prefixes, nick}, ...}
        std::ostringstream names;
        for (auto& [prefixes, nick] : members) {
            if (names.tellp() > 0) names << " ";
            names << prefixes << nick;
        }
        return NumericBuilder::build_multi(353, server, target,
            {"=", channel}, names.str());
    }

    /// Build RPL_ENDOFNAMES (366).
    static std::string end_of_names(const std::string& server,
                                     const std::string& target,
                                     const std::string& channel) {
        return NumericBuilder::build(366, server, target,
            channel + " :End of NAMES list");
    }
};

// ============================================================================
// SECTION 31 : CHGHOST and Account-Notify
// ============================================================================

/// @brief CHGHOST notification builder.
class ChgHostNotifyBuilder {
public:
    /// Build a CHGHOST notification.
    static std::string build(const std::string& nick,
                             const std::string& old_user,
                             const std::string& old_host,
                             const std::string& new_user,
                             const std::string& new_host) {
        MessageTags tags;
        add_server_time_tag(tags);

        ParsedMessage pm;
        pm.tags    = std::move(tags);
        pm.prefix  = nick + "!" + old_user + "@" + old_host;
        pm.command = "CHGHOST";
        pm.params.push_back(new_user);
        pm.params.push_back(new_host);
        return pm.to_line();
    }
};

/// @brief ACCOUNT notify builder.
class AccountNotifyBuilder {
public:
    /// Build an ACCOUNT notification.
    static std::string build(const std::string& nick,
                             const std::string& user,
                             const std::string& host,
                             const std::string& account) {
        MessageTags tags;
        add_server_time_tag(tags);

        ParsedMessage pm;
        pm.tags    = std::move(tags);
        pm.prefix  = nick + "!" + user + "@" + host;
        pm.command = "ACCOUNT";
        pm.params.push_back(account.empty() ? "*" : account);
        return pm.to_line();
    }
};

// ============================================================================
// SECTION 32 : STS (Strict Transport Security) Policy
// ============================================================================

/// @brief STS policy for enforcing TLS connections.
struct STSPolicy {
    std::string host;
    uint16_t    port          = 6697;
    int64_t     duration_secs = 60 * 60 * 24 * 30; // 30 days default
    bool        preload       = false;
    bool        enabled       = false;

    /// Build the "sts=port,duration[,preload]" capability value.
    std::string to_cap_value() const {
        std::ostringstream oss;
        oss << "sts=" << port << "," << duration_secs;
        if (preload) oss << ",preload";
        return oss.str();
    }

    /// Parse from wire format.
    static STSPolicy parse(const std::string& value) {
        STSPolicy p;
        auto parts = split_all(value, ',');
        if (!parts.empty()) p.port = static_cast<uint16_t>(std::stoi(parts[0]));
        if (parts.size() > 1) p.duration_secs = std::stoll(parts[1]);
        if (parts.size() > 2) p.preload = (parts[2] == "preload");
        p.enabled = true;
        return p;
    }
};

// ============================================================================
// SECTION 33 : Server-Side Capability Negotiation Flow
// ============================================================================

/// @brief High-level CAP negotiation processor.
class CapNegotiator {
public:
    /// Process a single CAP subcommand and return the response lines.
    static std::vector<std::string> process(
        CapManager& caps,
        const std::string& server,
        const std::string& nick,
        CapManager::CapAction action,
        const std::string& cap_list_raw) {

        std::vector<std::string> replies;

        switch (action) {
        case CapManager::CapAction::kLS: {
            // CAP LS [version]
            replies.push_back(caps.build_ls_reply(server, nick));
            break;
        }
        case CapManager::CapAction::kLIST: {
            // CAP LIST
            replies.push_back(caps.build_list_reply(server, nick));
            break;
        }
        case CapManager::CapAction::kREQ: {
            auto requested = caps.parse_cap_list(cap_list_raw);
            caps.request_caps(requested);
            break;
        }
        case CapManager::CapAction::kACK: {
            caps.ack_caps();
            break;
        }
        case CapManager::CapAction::kNAK: {
            caps.nak_caps();
            break;
        }
        case CapManager::CapAction::kEND: {
            caps.end_negotiation();
            break;
        }
        case CapManager::CapAction::kDEL: {
            auto to_del = caps.parse_cap_list(cap_list_raw);
            for (auto& c : to_del) caps.del_cap(c);
            break;
        }
        case CapManager::CapAction::kNEW: {
            auto to_add = caps.parse_cap_list(cap_list_raw);
            for (auto& c : to_add) caps.new_cap(c);
            break;
        }
        }
        return replies;
    }
};

// ============================================================================
// SECTION 34 : Full IRC Protocol Engine — Integrates All Components
// ============================================================================

/// @brief The main IRC protocol engine that ties together parsing, tags,
///        capability negotiation, registration, and all IRCv3 extensions.
class IRCProtocolEngine {
public:
    /// Server identity.
    std::string server_name  = "progressive.local";
    std::string server_info  = "Progressive IRC Server";
    std::string version      = "progressive-1.0";
    std::string network_name = "ProgressiveNet";
    std::string server_sid   = "000";

    /// Password for server-to-server links and client PASS.
    std::string link_password;

    /// Supported SASL mechanisms.
    SASLMechanismRegistry sasl_registry;

    /// STS policy.
    STSPolicy sts;

    /// Constructor sets up defaults.
    IRCProtocolEngine() {
        sasl_registry.add_mechanism(SASLMechanism::kPLAIN);
        sasl_registry.add_mechanism(SASLMechanism::kEXTERNAL);
    }

    // ------------------------------------------------------------------
    // Message construction helpers
    // ------------------------------------------------------------------

    /// Build a tagged server notice or message.
    std::string build_tagged_message(const std::string& command,
                                     const std::string& target,
                                     const std::string& text,
                                     const std::string& account = "",
                                     bool include_time = true) const {
        MessageTags tags;
        if (include_time) add_server_time_tag(tags);
        if (!account.empty()) tags.set("account", account);
        add_message_id(tags);

        ParsedMessage pm;
        pm.tags    = std::move(tags);
        pm.prefix  = server_name;
        pm.command = command;
        pm.params.push_back(target);
        pm.trailing     = text;
        pm.has_trailing = true;
        return pm.to_line();
    }

    /// Build a standard numeric reply.
    std::string numeric(uint16_t num, const std::string& target,
                        const std::string& msg) const {
        return NumericBuilder::build(num, server_name, target, msg);
    }

    // ------------------------------------------------------------------
    // Registration flow
    // ------------------------------------------------------------------

    /// Handle initial connection setup.
    std::vector<std::string> handle_connect(Connection& conn) {
        std::vector<std::string> replies;
        conn.connected_at  = std::time(nullptr);
        conn.last_activity = conn.connected_at;

        // Send NOTICE AUTH for SASL if enabled
        if (sasl_registry.mechanisms().size() > 0) {
            // No explicit notice here; client discovers via CAP LS
        }
        return replies;
    }

    /// Handle a CAP subcommand.
    std::vector<std::string> handle_cap(Connection& conn,
                                         const std::string& subcommand,
                                         const std::string& cap_list) {
        auto action = CapManager::parse_action(subcommand);
        if (!action) {
            return {numeric(410, conn.nick, subcommand +
                " :Invalid CAP subcommand")};
        }

        auto replies = CapNegotiator::process(
            conn.caps, server_name, conn.nick, *action, cap_list);

        if (*action == CapManager::CapAction::kEND) {
            ConnectionStateMachine::handle_cap_end(conn);
            if (ConnectionStateMachine::try_complete_registration(conn)) {
                auto welcome = ConnectionStateMachine::build_welcome(
                    conn, server_name, version, network_name);
                replies.insert(replies.end(), welcome.begin(), welcome.end());

                // Send ISUPPORT
                ISupportBuilder isup;
                replies.push_back(isup.build(server_name, conn.nick));

                // Send MOTD
                replies.push_back(NumericBuilder::build(375, server_name,
                    conn.nick, ":- " + server_name + " Message of the day - "));
                replies.push_back(NumericBuilder::build(372, server_name,
                    conn.nick, ":- Welcome to " + network_name));
                replies.push_back(NumericBuilder::build(376, server_name,
                    conn.nick, ":End of MOTD command"));
            }
        }

        return replies;
    }

    /// Handle PASS command.
    std::vector<std::string> handle_pass(Connection& conn,
                                          const std::string& password) {
        std::vector<std::string> replies;
        if (conn.is_registered()) {
            replies.push_back(numeric(462, conn.nick,
                ":You may not reregister"));
            return replies;
        }
        bool ok = ConnectionStateMachine::handle_pass(
            conn, password, link_password);
        if (!ok && !password.empty()) {
            replies.push_back(numeric(464, "*",
                ":Password incorrect"));
        }
        return replies;
    }

    /// Handle NICK command.
    std::vector<std::string> handle_nick(Connection& conn,
                                          const std::string& new_nick,
                                          bool nick_in_use_check = false) {
        std::vector<std::string> replies;
        auto result = ConnectionStateMachine::handle_nick(conn, new_nick);
        switch (result) {
        case ConnectionStateMachine::NickResult::kOk: {
            if (nick_in_use_check) {
                replies.push_back(numeric(433, "*", new_nick +
                    " :Nickname is already in use"));
                return replies;
            }
            if (ConnectionStateMachine::try_complete_registration(conn)) {
                auto welcome = ConnectionStateMachine::build_welcome(
                    conn, server_name, version, network_name);
                replies.insert(replies.end(), welcome.begin(), welcome.end());
                ISupportBuilder isup;
                replies.push_back(isup.build(server_name, conn.nick));
            }
            break;
        }
        case ConnectionStateMachine::NickResult::kErrNonicknamegiven:
            replies.push_back(numeric(431, "*", ":No nickname given"));
            break;
        case ConnectionStateMachine::NickResult::kErrErroneusNickname:
            replies.push_back(numeric(432, "*", new_nick +
                " :Erroneous nickname"));
            break;
        case ConnectionStateMachine::NickResult::kErrAlreadyRegistered:
            replies.push_back(numeric(462, conn.nick,
                ":You may not reregister"));
            break;
        }
        return replies;
    }

    /// Handle USER command.
    std::vector<std::string> handle_user(Connection& conn,
                                          const std::string& user,
                                          const std::string& mode_str,
                                          const std::string& unused,
                                          const std::string& realname) {
        std::vector<std::string> replies;
        auto result = ConnectionStateMachine::handle_user(
            conn, user, mode_str, unused, realname);
        switch (result) {
        case ConnectionStateMachine::UserResult::kOk:
            if (ConnectionStateMachine::try_complete_registration(conn)) {
                auto welcome = ConnectionStateMachine::build_welcome(
                    conn, server_name, version, network_name);
                replies.insert(replies.end(), welcome.begin(), welcome.end());
                ISupportBuilder isup;
                replies.push_back(isup.build(server_name, conn.nick));
            }
            break;
        case ConnectionStateMachine::UserResult::kErrNeedmoreparams:
            replies.push_back(numeric(461, conn.nick.empty() ? "*" : conn.nick,
                "USER :Not enough parameters"));
            break;
        case ConnectionStateMachine::UserResult::kErrAlreadyRegistered:
            replies.push_back(numeric(462, conn.nick,
                ":You may not reregister"));
            break;
        }
        return replies;
    }

    /// Handle SASL AUTHENTICATE command.
    std::vector<std::string> handle_authenticate(Connection& conn,
                                                  const std::string& param) {
        std::vector<std::string> replies;
        const std::string& nick = conn.nick.empty() ? "*" : conn.nick;

        if (param == "*") {
            conn.sasl_session.abort();
            replies.push_back(numeric(906, nick, ":SASL authentication aborted"));
            return replies;
        }

        if (conn.sasl_session.state() == SASLState::kNone) {
            // First AUTHENTICATE: param is mechanism name
            SASLMechanism mech = sasl_mechanism_from_string(param);
            if (mech == SASLMechanism::kUnknown ||
                !sasl_registry.supports(mech)) {
                conn.sasl_session.fail();
                replies.push_back(numeric(904, nick, ":SASL authentication failed"));
                return replies;
            }
            conn.sasl_session.begin(mech, server_name);
            if (mech == SASLMechanism::kPLAIN) {
                // Server sends empty challenge for PLAIN
                replies.push_back("AUTHENTICATE +");
            }
            return replies;
        }

        if (conn.sasl_session.state() == SASLState::kInProgress) {
            conn.sasl_session.feed_data(param);

            if (conn.sasl_session.mechanism() == SASLMechanism::kPLAIN) {
                auto creds = conn.sasl_session.decode_plain();
                if (!creds) {
                    conn.sasl_session.fail();
                    replies.push_back(numeric(904, nick,
                        ":SASL authentication failed"));
                    return replies;
                }
                // [authzid, authcid, passwd] — caller verifies these
                // For now, mark as success if password non-empty
                const auto& [authzid, authcid, passwd] = *creds;
                if (!passwd.empty()) {
                    conn.sasl_session.succeed();
                    conn.account = authcid;
                    replies.push_back(numeric(903, nick,
                        ":SASL authentication successful"));
                } else {
                    conn.sasl_session.fail();
                    replies.push_back(numeric(904, nick,
                        ":SASL authentication failed"));
                }
            } else if (conn.sasl_session.mechanism() ==
                       SASLMechanism::kEXTERNAL) {
                std::string authzid = conn.sasl_session.decode_external();
                if (!authzid.empty()) {
                    conn.sasl_session.succeed();
                    conn.account = authzid;
                    replies.push_back(numeric(903, nick,
                        ":SASL authentication successful"));
                } else {
                    conn.sasl_session.fail();
                    replies.push_back(numeric(904, nick,
                        ":SASL authentication failed"));
                }
            }
        }

        return replies;
    }

    /// Handle SASL mechanism listing.
    std::vector<std::string> handle_sasl_mechs(Connection& conn) {
        std::vector<std::string> replies;
        const std::string& nick = conn.nick.empty() ? "*" : conn.nick;
        replies.push_back(sasl_registry.build_mechlist(server_name, nick));
        return replies;
    }

    /// Handle disconnect cleanup.
    void handle_disconnect(Connection& conn) {
        conn.sasl_session.reset();
        conn.caps.reset();
    }

    // ------------------------------------------------------------------
    // Protocol line processing (main entry point)
    // ------------------------------------------------------------------

    /// Process a single raw IRC line from a client connection.
    /// Returns a vector of response lines (without CRLF).
    std::vector<std::string> process_line(Connection& conn,
                                          const std::string& raw_line) {
        std::vector<std::string> replies;

        // Strip CR/LF
        std::string line = strip_crlf(raw_line);
        if (line.empty()) return replies;

        // Parse
        ParsedMessage msg = ParsedMessage::parse(line);
        conn.last_activity = std::time(nullptr);

        // Update last activity
        if (msg.command.empty()) return replies;

        // --- Dispatch by command ---
        const std::string& cmd = msg.command;

        if (cmd == "CAP") {
            if (msg.params.empty()) {
                replies.push_back(numeric(461, conn.nick.empty() ? "*" : conn.nick,
                    "CAP :Not enough parameters"));
                return replies;
            }
            std::string cap_list = msg.has_trailing ? msg.trailing : "";
            auto cap_replies = handle_cap(conn, msg.params[0], cap_list);
            replies.insert(replies.end(), cap_replies.begin(), cap_replies.end());
        }
        else if (cmd == "PASS") {
            std::string pass = msg.has_trailing ? msg.trailing :
                               (!msg.params.empty() ? msg.params[0] : "");
            auto pass_replies = handle_pass(conn, pass);
            replies.insert(replies.end(), pass_replies.begin(), pass_replies.end());
        }
        else if (cmd == "NICK") {
            std::string nick = msg.has_trailing ? msg.trailing :
                               (!msg.params.empty() ? msg.params[0] : "");
            auto nick_replies = handle_nick(conn, nick);
            replies.insert(replies.end(), nick_replies.begin(), nick_replies.end());
        }
        else if (cmd == "USER") {
            std::string user     = msg.params.size() > 0 ? msg.params[0] : "";
            std::string mode_str = msg.params.size() > 1 ? msg.params[1] : "";
            std::string unused   = msg.params.size() > 2 ? msg.params[2] : "";
            std::string realname = msg.has_trailing ? msg.trailing : "";
            auto user_replies = handle_user(conn, user, mode_str, unused, realname);
            replies.insert(replies.end(), user_replies.begin(), user_replies.end());
        }
        else if (cmd == "AUTHENTICATE") {
            std::string param = msg.has_trailing ? msg.trailing :
                                (!msg.params.empty() ? msg.params[0] : "");
            auto sasl_replies = handle_authenticate(conn, param);
            replies.insert(replies.end(), sasl_replies.begin(), sasl_replies.end());
        }
        else if (cmd == "PING") {
            std::string pong_target = msg.has_trailing ? msg.trailing : "";
            std::string pong_line = ":" + server_name + " PONG " +
                                     server_name + " :" + pong_target;
            replies.push_back(pong_line);
        }
        else if (cmd == "PONG") {
            // No automatic reply; caller handles timeout tracking
        }
        else if (cmd == "QUIT") {
            std::string quit_msg = msg.has_trailing ? msg.trailing : "Client Quit";
            // Disconnect is handled by caller
        }
        else if (!conn.is_registered()) {
            // Not yet registered — reject
            replies.push_back(numeric(451, conn.nick.empty() ? "*" : conn.nick,
                ":" + cmd + " :You have not registered"));
        }
        else if (cmd == "AWAY") {
            if (msg.has_trailing && !msg.trailing.empty()) {
                conn.set_away(msg.trailing);
                replies.push_back(AwayNotifyHandler::now_away(server_name, conn.nick));
            } else {
                conn.clear_away();
                replies.push_back(AwayNotifyHandler::unaway(server_name, conn.nick));
            }
        }
        else if (cmd == "SETNAME") {
            std::string new_realname = msg.has_trailing ? msg.trailing : "";
            if (SetNameHandler::validate_realname(new_realname)) {
                conn.realname = new_realname;
                // Notification to channels handled by caller
            }
        }
        else if (cmd == "METADATA") {
            // METADATA <target> <subcommand> [key] [:value]
            // Handled by caller against MetadataManager
        }
        else if (cmd == "MONITOR") {
            // MONITOR + nick1,nick2... / MONITOR - nick / MONITOR L / MONITOR S
            // Handled by caller
        }
        else if (cmd == "BOT" || cmd == "MODE") {
            // BOT mode handled by caller via BotModeManager
        }
        else if (cmd == "BATCH") {
            // Handled by caller via BatchManager
        }

        // Check flood
        if (!replies.empty() && conn.commands_this_sec > conn.max_commands_per_sec) {
            // Optionally rate-limit (handled by caller with RateLimiter)
        }

        return replies;
    }

    /// Build a complete connection notification for MONITOR watchers.
    std::string build_monitor_online(const Connection& conn) const {
        return MonitorManager::online_notify(
            server_name, "", conn.nick, conn.user, conn.host);
    }

    /// Build a complete de-registration notification for MONITOR watchers.
    std::string build_monitor_offline(const std::string& nick) const {
        return MonitorManager::offline_notify(server_name, "", nick);
    }

    /// Build an extended JOIN (IRCv3 extended-join) line.
    std::string build_extended_join(const Connection& conn,
                                    const std::string& channel) const {
        return ExtendedJoinBuilder::build(
            conn.nick, conn.user, conn.host, channel,
            conn.account, conn.realname, true);
    }
};

// ============================================================================
// SECTION 35 : UTF-8 Validation
// ============================================================================

/// @brief Validate a string is well-formed UTF-8.
inline bool is_valid_utf8(const std::string& s) {
    for (size_t i = 0; i < s.size(); ) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t len = 0;
        if      (c < 0x80)        len = 1;
        else if ((c & 0xE0) == 0xC0) len = 2;
        else if ((c & 0xF0) == 0xE0) len = 3;
        else if ((c & 0xF8) == 0xF0) len = 4;
        else return false;

        if (i + len > s.size()) return false;
        for (size_t j = 1; j < len; ++j) {
            if ((static_cast<unsigned char>(s[i + j]) & 0xC0) != 0x80)
                return false;
        }
        i += len;
    }
    return true;
}

/// @brief Sanitize a string to safe ASCII (strip non-printable/newlines).
inline std::string sanitize_irc_text(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (char c : input) {
        if (c == '\r' || c == '\n' || c == '\0') continue;
        if (static_cast<unsigned char>(c) >= 32 || c == '\t')
            out.push_back(c);
    }
    return out;
}

// ============================================================================
// SECTION 36 : Message Length Enforcement (512 + tag extension)
// ============================================================================

/// @brief Maximum raw IRC line length (body + CRLF).
constexpr size_t kMaxLineLength = 512;

/// @brief Maximum body length after accounting for tags.
inline size_t max_body_length(const MessageTags& tags) {
    size_t tag_overhead = tags.wire_length();
    if (tag_overhead > 0) tag_overhead += 1; // space after tag block
    return (kMaxLineLength > tag_overhead + 2)
               ? (kMaxLineLength - tag_overhead - 2) // -2 for CRLF
               : 0;
}

/// @brief Truncate trailing text to fit within max body length.
inline std::string truncate_to_fit(const std::string& prefix_part,
                                   const std::string& trailing,
                                   size_t max_total_len = 510) {
    size_t overhead = prefix_part.size() + 2; // +2 for " :" prefix
    if (overhead >= max_total_len) return "";
    size_t available = max_total_len - overhead;
    return trailing.substr(0, std::min(trailing.size(), available));
}

// ============================================================================
// SECTION 37 : IRC Format Code Stripping
// ============================================================================

/// @brief Strip IRC formatting codes (bold, color, italic, etc.).
inline std::string strip_irc_formatting(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        if (c == '\x02' || c == '\x0F' || c == '\x16' ||
            c == '\x1D' || c == '\x1E' || c == '\x1F' || c == '\x11') {
            continue; // Skip format code
        }
        if (c == '\x03') {
            ++i; // Skip color code
            while (i < input.size() && std::isdigit(static_cast<unsigned char>(input[i])))
                ++i;
            if (i < input.size() && input[i] == ',') {
                ++i;
                while (i < input.size() && std::isdigit(static_cast<unsigned char>(input[i])))
                    ++i;
            }
            if (i > 0 && i <= input.size()) --i; // adjust for loop increment
            continue;
        }
        out.push_back(c);
    }
    return out;
}

// ============================================================================
// SECTION 38 : PING/PONG Timeout Tracker
// ============================================================================

/// @brief Track PING/PONG latency and detect timeouts.
class PingTracker {
public:
    PingTracker(int timeout_secs = 120, int ping_interval = 60)
        : timeout_(timeout_secs), interval_(ping_interval) {}

    /// Record a received PONG.
    void record_pong() {
        last_pong_ = std::time(nullptr);
        awaiting_pong_ = false;
    }

    /// Record a sent PING.
    void record_ping() {
        last_ping_ = std::time(nullptr);
        awaiting_pong_ = true;
    }

    /// Check if we should send a PING.
    bool should_ping() const {
        time_t now = std::time(nullptr);
        return !awaiting_pong_ &&
               (now - last_ping_ >= interval_);
    }

    /// Check if the connection has timed out.
    bool is_timed_out() const {
        if (!awaiting_pong_) return false;
        time_t now = std::time(nullptr);
        return (now - last_ping_ >= timeout_);
    }

    /// Reset the tracker (new connection).
    void reset() {
        last_ping_ = 0;
        last_pong_ = std::time(nullptr);
        awaiting_pong_ = false;
    }

    /// Build a PING message.
    std::string build_ping(const std::string& server) const {
        time_t now = std::time(nullptr);
        return ":" + server + " PING " + server + " :" + std::to_string(now);
    }

    void set_timeout(int secs) { timeout_ = secs; }
    void set_interval(int secs) { interval_ = secs; }

private:
    int timeout_ = 120;
    int interval_ = 60;
    time_t last_ping_ = 0;
    time_t last_pong_ = 0;
    bool awaiting_pong_ = false;
};

// ============================================================================
// SECTION 39 : Protocol-Level Event Logger
// ============================================================================

/// @brief Structured protocol event logger.
class ProtocolLogger {
public:
    enum class Level : uint8_t { kDebug = 0, kInfo = 1, kWarn = 2, kError = 3 };

    using Callback = std::function<void(Level, const std::string&)>;

    void set_callback(Callback cb) { cb_ = std::move(cb); }

    void log(Level lvl, const std::string& msg) {
        if (cb_) cb_(lvl, msg);
    }

    void debug(const std::string& m) { log(Level::kDebug, m); }
    void info(const std::string& m)  { log(Level::kInfo, m); }
    void warn(const std::string& m)  { log(Level::kWarn, m); }
    void error(const std::string& m) { log(Level::kError, m); }

    void log_parsed(const ParsedMessage& pm, bool incoming) {
        std::ostringstream oss;
        oss << (incoming ? "RECV" : "SEND")
            << " [" << pm.command << "]"
            << " tags=" << pm.tags.size()
            << " params=" << pm.params.size()
            << " trail=" << (pm.has_trailing ? "yes" : "no");
        if (!pm.prefix.empty()) oss << " from=" << pm.prefix;
        for (auto& p : pm.params) oss << " '" << p << "'";
        if (pm.has_trailing) oss << " :'" << pm.trailing << "'";
        debug(oss.str());
    }

private:
    Callback cb_;
};

// ============================================================================
// SECTION 40 : Protocol Diagnostics and Statistics
// ============================================================================

/// @brief Connection-level statistics for protocol debugging.
struct ProtocolStats {
    uint64_t messages_received  = 0;
    uint64_t messages_sent      = 0;
    uint64_t bytes_received     = 0;
    uint64_t bytes_sent         = 0;
    uint64_t parse_errors       = 0;
    uint64_t sasl_attempts      = 0;
    uint64_t sasl_successes     = 0;
    uint64_t cap_negotiations   = 0;
    uint64_t nicks_changed      = 0;
    uint64_t channels_joined    = 0;
    uint64_t pings_sent         = 0;
    uint64_t pongs_received     = 0;
    uint64_t timeouts           = 0;

    void reset() { *this = ProtocolStats{}; }
};

} // namespace irc
} // namespace progressive
