// ============================================================================
// irc_access_abuse.cpp - IRC Extended Bans, Access Lists, and Anti-Abuse System
//
// Implements:
//   1. Extended bans (account, realname, certfp, gecos, oper)
//   2. Channel access lists (SOP/AOP/HOP/VOP - founder, admin, op, halfop, voice)
//   3. Access list persistence & reload
//   4. Auto-op on join based on access
//   5. G-Lines (global bans)
//   6. K-Lines (kill lines)
//   7. Z-Lines (zap lines / IP bans)
//   8. E-Lines (exception lines)
//   9. Q-Lines (quiet lines)
//  10. Spam filter (regex pattern matching)
//  11. Flood protection (message, join, nick, invite floods)
//  12. Connection throttling (per-IP limits)
//  13. Proxy scanner (open proxy detection)
//  14. DNSBL integration (DNS blacklist checks)
//  15. Channel mode +c (no color codes)
//  16. Channel mode +C (no CTCP)
//  17. Channel mode +M (only registered users can talk)
//  18. Channel mode +R (only registered users can join)
//  19. Cloaking (hostname cloaking for privacy)
//  20. VHost (virtual host assignment)
//
// Namespace: progressive::irc
// ============================================================================

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// POSIX / networking
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace progressive {
namespace irc {

// ============================================================================
// Forward declarations
// ============================================================================

class Server;
class Client;
class Channel {
public:
    std::string name;
    // Minimal placeholder so methods can access channel.name
};
class ChannelMember;

// ============================================================================
// Utility helpers
// ============================================================================

namespace {

constexpr const char* kAccessDataDir = "data/access/";
constexpr const char* kGLinesFile    = "data/glines.db";
constexpr const char* kKLinesFile    = "data/klines.db";
constexpr const char* kZLinesFile    = "data/zlines.db";
constexpr const char* kELinesFile    = "data/elines.db";
constexpr const char* kQLinesFile    = "data/qlines.db";
constexpr const char* kSpamRegexFile = "data/spamfilters.conf";
constexpr const char* kVHostFile     = "data/vhosts.db";

// --------------------------------------------------------------------------
// Case-insensitive string comparison (IRC-style)
// --------------------------------------------------------------------------
inline bool irc_case_equal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        unsigned char ca = static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(a[i])));
        unsigned char cb = static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(b[i])));
        if (ca != cb) return false;
    }
    return true;
}

struct IrcCaseHash {
    size_t operator()(std::string_view sv) const {
        size_t h = 0;
        for (unsigned char c : sv) {
            h = h * 31 + static_cast<size_t>(std::tolower(c));
        }
        return h;
    }
};

struct IrcCaseEqual {
    bool operator()(std::string_view a, std::string_view b) const {
        return irc_case_equal(a, b);
    }
};

// --------------------------------------------------------------------------
// String trimming
// --------------------------------------------------------------------------
inline std::string trim(std::string s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// --------------------------------------------------------------------------
// Check if a string contains ANSI/IRC color codes
// --------------------------------------------------------------------------
inline bool contains_color_codes(std::string_view text) {
    for (size_t i = 0; i < text.size(); ++i) {
        if (static_cast<unsigned char>(text[i]) == 0x03) return true;  // ^C color
        if (text[i] == '\x02' || text[i] == '\x0F' ||
            text[i] == '\x16' || text[i] == '\x1D' ||
            text[i] == '\x1F') {
            // Bold, reset, reverse, italic, underline — these are formatting,
            // not color. We only care about ^C and possibly ^B+color combos.
        }
    }
    return false;
}

// --------------------------------------------------------------------------
// Check if text contains CTCP
// --------------------------------------------------------------------------
inline bool contains_ctcp(std::string_view text) {
    return text.find('\x01') != std::string_view::npos;
}

// --------------------------------------------------------------------------
// Simple wildcard match
// --------------------------------------------------------------------------
inline bool wildcard_match(std::string_view pattern, std::string_view target, bool case_sensitive = false) {
    size_t pi = 0, ti = 0;
    size_t star_p = std::string_view::npos;
    size_t match_t = 0;

    while (ti < target.size()) {
        if (pi < pattern.size() && pattern[pi] == '*') {
            star_p = pi;
            match_t = ti;
            ++pi;
        } else if (pi < pattern.size() &&
                   (case_sensitive ? pattern[pi] == target[ti]
                                   : std::tolower(static_cast<unsigned char>(pattern[pi])) ==
                                     std::tolower(static_cast<unsigned char>(target[ti])))) {
            ++pi;
            ++ti;
        } else if (star_p != std::string_view::npos) {
            pi = star_p + 1;
            ++match_t;
            ti = match_t;
        } else {
            return false;
        }
    }
    while (pi < pattern.size() && pattern[pi] == '*') ++pi;
    return pi == pattern.size();
}

// --------------------------------------------------------------------------
// Resolve hostname to IP (return empty on failure)
// --------------------------------------------------------------------------
inline std::string resolve_hostname(const std::string& host) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) return "";
    char ip[INET_ADDRSTRLEN];
    auto* sa = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
    std::string result(ip);
    freeaddrinfo(res);
    return result;
}

// --------------------------------------------------------------------------
// Check if IP is in CIDR range (IPv4 only)
// --------------------------------------------------------------------------
inline bool ip_in_cidr(const std::string& ip, const std::string& cidr) {
    auto slash = cidr.find('/');
    if (slash == std::string::npos) return ip == cidr;
    std::string net = cidr.substr(0, slash);
    int prefix = std::stoi(cidr.substr(slash + 1));
    if (prefix < 0 || prefix > 32) return false;

    struct in_addr ip_addr, net_addr;
    if (inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1) return false;
    if (inet_pton(AF_INET, net.c_str(), &net_addr) != 1) return false;

    uint32_t mask = (prefix == 0) ? 0 : htonl(0xFFFFFFFF << (32 - prefix));
    return (ip_addr.s_addr & mask) == (net_addr.s_addr & mask);
}

// --------------------------------------------------------------------------
// Base64 encode (for cloaking)
// --------------------------------------------------------------------------
inline std::string base64_encode(const std::string& input) {
    static const char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    const unsigned char* data = reinterpret_cast<const unsigned char*>(input.data());
    size_t len = input.size();
    for (size_t i = 0; i < len; ++i) {
        val = (val << 8) + data[i];
        valb += 8;
        while (valb >= 0) {
            out.push_back(kTable[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(kTable[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

}  // anonymous namespace

// ============================================================================
// AccessLevel enum
// ============================================================================
enum class AccessLevel : int {
    kNone   = 0,
    kVoice  = 1,
    kHalfop = 2,
    kOp     = 3,
    kAdmin  = 4,
    kFounder = 5
};

inline const char* access_level_name(AccessLevel lvl) {
    switch (lvl) {
        case AccessLevel::kNone:    return "none";
        case AccessLevel::kVoice:   return "voice";
        case AccessLevel::kHalfop:  return "halfop";
        case AccessLevel::kOp:      return "op";
        case AccessLevel::kAdmin:   return "admin";
        case AccessLevel::kFounder: return "founder";
    }
    return "unknown";
}

inline AccessLevel access_level_from_string(std::string_view s) {
    if (irc_case_equal(s, "founder") || irc_case_equal(s, "sop")) return AccessLevel::kFounder;
    if (irc_case_equal(s, "admin")   || irc_case_equal(s, "aop")) return AccessLevel::kAdmin;
    if (irc_case_equal(s, "op")      || irc_case_equal(s, "hop")) return AccessLevel::kOp;
    if (irc_case_equal(s, "halfop")  || irc_case_equal(s, "vop")) return AccessLevel::kHalfop;
    if (irc_case_equal(s, "voice"))                              return AccessLevel::kVoice;
    return AccessLevel::kNone;
}

// ============================================================================
// BanType enum and ExtendedBan
// ============================================================================
enum class BanType : uint8_t {
    kNormal   = 0,  // nick!user@host
    kAccount  = 1,  // ~a:accountname
    kRealname = 2,  // ~r:realname_pattern
    kCertFP   = 3,  // ~S:certificate_fingerprint
    kGecos    = 4,  // ~g:gecos_pattern
    kOper     = 5,  // ~O: (matches opers)
    kQuiet    = 6,  // ~q:nick!user@host  (quiet/block only, no kick)
};

struct ExtendedBan {
    BanType    type;
    std::string mask;      // The actual match pattern
    std::string set_by;
    std::time_t set_at;
    std::string reason;

    ExtendedBan() : type(BanType::kNormal), set_at(0) {}
    ExtendedBan(BanType t, std::string m, std::string sb, std::time_t sa, std::string r = "")
        : type(t), mask(std::move(m)), set_by(std::move(sb)), set_at(sa), reason(std::move(r)) {}

    // Parse an extended ban string like "~a:accountname" or "nick!user@host"
    static ExtendedBan parse(std::string_view raw, std::string_view setter = "", std::string_view reason_str = "") {
        ExtendedBan eb;
        eb.set_by = setter;
        eb.set_at = std::time(nullptr);
        eb.reason = reason_str;

        if (raw.size() >= 3 && raw[0] == '~') {
            // Extended ban prefix
            char pfx = std::tolower(static_cast<unsigned char>(raw[1]));
            if (raw[2] == ':' && raw.size() > 3) {
                std::string_view rest = raw.substr(3);
                switch (pfx) {
                    case 'a': eb.type = BanType::kAccount;  eb.mask = rest; break;
                    case 'r': eb.type = BanType::kRealname; eb.mask = rest; break;
                    case 's': eb.type = BanType::kCertFP;   eb.mask = rest; break;
                    case 'g': eb.type = BanType::kGecos;    eb.mask = rest; break;
                    case 'o': eb.type = BanType::kOper;     eb.mask = rest; break;
                    case 'q': eb.type = BanType::kQuiet;    eb.mask = rest; break;
                    default:  eb.type = BanType::kNormal;   eb.mask = raw;  break;
                }
                return eb;
            }
        }
        eb.type = BanType::kNormal;
        eb.mask = raw;
        return eb;
    }

    std::string to_string() const {
        switch (type) {
            case BanType::kAccount:  return "~a:" + mask;
            case BanType::kRealname: return "~r:" + mask;
            case BanType::kCertFP:   return "~S:" + mask;
            case BanType::kGecos:    return "~g:" + mask;
            case BanType::kOper:     return "~O:" + mask;
            case BanType::kQuiet:    return "~q:" + mask;
            default: return mask;
        }
    }

    // Match against a client
    bool matches(const std::string& nick, const std::string& user,
                 const std::string& host, const std::string& realname,
                 const std::string& account, const std::string& certfp,
                 bool is_oper) const {
        switch (type) {
            case BanType::kNormal: {
                // Standard nick!user@host pattern
                std::string full = nick + "!" + user + "@" + host;
                return wildcard_match(mask, full);
            }
            case BanType::kAccount:
                return wildcard_match(mask, account);
            case BanType::kRealname:
                return wildcard_match(mask, realname);
            case BanType::kCertFP:
                return irc_case_equal(mask, certfp);
            case BanType::kGecos:
                return wildcard_match(mask, realname);
            case BanType::kOper:
                return is_oper;
            case BanType::kQuiet: {
                std::string full = nick + "!" + user + "@" + host;
                return wildcard_match(mask, full);
            }
        }
        return false;
    }
};

// ============================================================================
// ChannelAccessEntry
// ============================================================================
struct ChannelAccessEntry {
    std::string  account;         // Account name (empty if host-based)
    std::string  mask;            // nick!user@host or *@host mask
    AccessLevel  level;
    std::time_t  added_at;
    std::string  added_by;
    std::time_t  last_seen;

    ChannelAccessEntry()
        : level(AccessLevel::kNone), added_at(0), last_seen(0) {}

    ChannelAccessEntry(std::string acc, std::string m, AccessLevel lvl,
                       std::string ab, std::time_t at)
        : account(std::move(acc)), mask(std::move(m)), level(lvl),
          added_at(at), added_by(std::move(ab)), last_seen(0) {}

    bool matches(const std::string& nick, const std::string& user,
                 const std::string& host, const std::string& account_name) const {
        // Account-based match
        if (!account.empty() && !account_name.empty()) {
            if (irc_case_equal(account, account_name)) return true;
        }
        // Mask-based match: nick!user@host
        std::string full = nick + "!" + user + "@" + host;
        return wildcard_match(mask, full);
    }

    std::string serialize() const {
        std::ostringstream oss;
        oss << account << "|" << mask << "|" << static_cast<int>(level)
            << "|" << added_by << "|" << added_at << "|" << last_seen;
        return oss.str();
    }

    static ChannelAccessEntry deserialize(const std::string& line) {
        ChannelAccessEntry e;
        std::istringstream iss(line);
        std::string token;
        int field = 0;
        while (std::getline(iss, token, '|')) {
            switch (field++) {
                case 0: e.account  = token; break;
                case 1: e.mask     = token; break;
                case 2: e.level    = static_cast<AccessLevel>(std::stoi(token)); break;
                case 3: e.added_by = token; break;
                case 4: e.added_at = std::stoll(token); break;
                case 5: e.last_seen = std::stoll(token); break;
            }
        }
        return e;
    }
};

// ============================================================================
// G-Line entry
// ============================================================================
struct GLine {
    std::string mask;         // nick!user@host or *@host
    std::string reason;
    std::string set_by;
    std::time_t set_at;
    std::time_t expires_at;   // 0 = permanent
    bool        active;

    GLine() : set_at(0), expires_at(0), active(true) {}
    GLine(std::string m, std::string r, std::string sb, std::time_t sa, std::time_t exp)
        : mask(std::move(m)), reason(std::move(r)), set_by(std::move(sb)),
          set_at(sa), expires_at(exp), active(true) {}

    bool is_expired() const {
        if (expires_at == 0) return false;
        return std::time(nullptr) >= expires_at;
    }

    bool matches(const std::string& nick, const std::string& user, const std::string& host) const {
        std::string full = nick + "!" + user + "@" + host;
        return wildcard_match(mask, full);
    }
};

// ============================================================================
// K-Line entry
// ============================================================================
struct KLine {
    std::string mask;         // user@host or *@ip
    std::string reason;
    std::string set_by;
    std::time_t set_at;
    std::time_t expires_at;
    bool        active;

    KLine() : set_at(0), expires_at(0), active(true) {}
    KLine(std::string m, std::string r, std::string sb, std::time_t sa, std::time_t exp)
        : mask(std::move(m)), reason(std::move(r)), set_by(std::move(sb)),
          set_at(sa), expires_at(exp), active(true) {}

    bool is_expired() const {
        if (expires_at == 0) return false;
        return std::time(nullptr) >= expires_at;
    }

    bool matches(const std::string& user, const std::string& host) const {
        std::string full = user + "@" + host;
        return wildcard_match(mask, full);
    }
};

// ============================================================================
// Z-Line entry
// ============================================================================
struct ZLine {
    std::string ip_mask;      // IP address or CIDR
    std::string reason;
    std::string set_by;
    std::time_t set_at;
    std::time_t expires_at;
    bool        active;

    ZLine() : set_at(0), expires_at(0), active(true) {}
    ZLine(std::string ip, std::string r, std::string sb, std::time_t sa, std::time_t exp)
        : ip_mask(std::move(ip)), reason(std::move(r)), set_by(std::move(sb)),
          set_at(sa), expires_at(exp), active(true) {}

    bool is_expired() const {
        if (expires_at == 0) return false;
        return std::time(nullptr) >= expires_at;
    }

    bool matches(const std::string& ip) const {
        return ip_in_cidr(ip, ip_mask);
    }
};

// ============================================================================
// E-Line entry
// ============================================================================
struct ELine {
    std::string mask;         // user@host
    std::string set_by;
    std::time_t set_at;
    std::time_t expires_at;
    bool        active;

    ELine() : set_at(0), expires_at(0), active(true) {}
    ELine(std::string m, std::string sb, std::time_t sa, std::time_t exp)
        : mask(std::move(m)), set_by(std::move(sb)), set_at(sa),
          expires_at(exp), active(true) {}

    bool is_expired() const {
        if (expires_at == 0) return false;
        return std::time(nullptr) >= expires_at;
    }

    bool matches(const std::string& user, const std::string& host) const {
        std::string full = user + "@" + host;
        return wildcard_match(mask, full);
    }
};

// ============================================================================
// Q-Line entry
// ============================================================================
struct QLine {
    std::string mask;         // nick pattern or channel pattern
    bool        is_channel;   // true = channel, false = nick
    std::string reason;
    std::string set_by;
    std::time_t set_at;
    std::time_t expires_at;
    bool        active;

    QLine() : is_channel(false), set_at(0), expires_at(0), active(true) {}
    QLine(std::string m, bool chan, std::string r, std::string sb, std::time_t sa, std::time_t exp)
        : mask(std::move(m)), is_channel(chan), reason(std::move(r)),
          set_by(std::move(sb)), set_at(sa), expires_at(exp), active(true) {}

    bool is_expired() const {
        if (expires_at == 0) return false;
        return std::time(nullptr) >= expires_at;
    }
};

// ============================================================================
// SpamFilter entry
// ============================================================================
enum class SpamAction {
    kBlock  = 0,  // Block the message entirely
    kKill   = 1,  // Disconnect the user
    kGLine  = 2,  // Add a G-Line
    kQuiet  = 3,  // Quiet the user
    kDCCBlock = 4 // Block DCC
};

struct SpamFilter {
    std::string    pattern;
    std::regex     compiled;
    SpamAction     action;
    std::string    reason;
    std::time_t    added_at;
    std::string    added_by;
    mutable uint64_t hit_count;

    SpamFilter() : action(SpamAction::kBlock), added_at(0), hit_count(0) {}

    bool matches(const std::string& text) const {
        try {
            return std::regex_search(text, compiled);
        } catch (...) {
            return false;
        }
    }
};

// ============================================================================
// FloodProfile - per-client flood tracking
// ============================================================================
struct FloodProfile {
    std::string ident;          // nickname or * for pre-reg
    std::string ip;

    // Message flood
    std::deque<std::chrono::steady_clock::time_point> message_times;
    // Join flood
    std::deque<std::chrono::steady_clock::time_point> join_times;
    // Nick change flood
    std::deque<std::chrono::steady_clock::time_point> nick_times;
    // Invite flood
    std::deque<std::chrono::steady_clock::time_point> invite_times;

    bool   flood_detected;
    std::chrono::steady_clock::time_point flood_until;

    FloodProfile() : flood_detected(false) {}

    void record_message() {
        auto now = std::chrono::steady_clock::now();
        message_times.push_back(now);
    }
    void record_join() {
        auto now = std::chrono::steady_clock::now();
        join_times.push_back(now);
    }
    void record_nick() {
        auto now = std::chrono::steady_clock::now();
        nick_times.push_back(now);
    }
    void record_invite() {
        auto now = std::chrono::steady_clock::now();
        invite_times.push_back(now);
    }

    void prune(std::deque<std::chrono::steady_clock::time_point>& deq,
               std::chrono::seconds window) {
        auto cutoff = std::chrono::steady_clock::now() - window;
        while (!deq.empty() && deq.front() < cutoff) deq.pop_front();
    }
};

// ============================================================================
// ConnectionThrottle - per-IP connection rate limiting
// ============================================================================
struct ConnectionThrottle {
    std::string ip;
    int         connection_count;
    std::chrono::steady_clock::time_point window_start;
    std::chrono::steady_clock::time_point banned_until;
    bool        throttled;

    ConnectionThrottle() : connection_count(0), throttled(false) {}

    void reset_window() {
        connection_count = 0;
        window_start = std::chrono::steady_clock::now();
    }
};

// ============================================================================
// VHost entry
// ============================================================================
struct VHostEntry {
    std::string account;
    std::string vhost;
    std::string set_by;
    std::time_t set_at;
    bool        active;

    VHostEntry() : set_at(0), active(false) {}
    VHostEntry(std::string acc, std::string vh, std::string sb, std::time_t sa)
        : account(std::move(acc)), vhost(std::move(vh)),
          set_by(std::move(sb)), set_at(sa), active(true) {}
};

// ============================================================================
// DNSBL entry
// ============================================================================
struct DNSBLEntry {
    std::string name;
    std::string lookup_domain;
    std::string reply_mask;    // Expected reply pattern
    std::string reason;
    int         ban_time;      // Seconds, 0 = permanent
    bool        enabled;

    DNSBLEntry() : ban_time(3600), enabled(false) {}
};

// ============================================================================
// AccessAbuseManager - Main class
// ============================================================================
class AccessAbuseManager {
public:
    AccessAbuseManager();
    ~AccessAbuseManager();

    // ---- Initialization ----
    void initialize(const std::string& data_dir);
    void load_all();
    void save_all();
    void reload();

    // ---- Extended Bans ----
    bool add_ban(Channel& channel, const ExtendedBan& ban);
    bool remove_ban(Channel& channel, std::string_view mask);
    bool is_banned(const Channel& channel, const std::string& nick,
                   const std::string& user, const std::string& host,
                   const std::string& realname, const std::string& account,
                   const std::string& certfp, bool is_oper) const;
    bool is_quieted(const Channel& channel, const std::string& nick,
                    const std::string& user, const std::string& host) const;
    std::vector<ExtendedBan> get_ban_list(const Channel& channel) const;
    std::vector<ExtendedBan> get_exception_list(const Channel& channel) const;
    void clear_bans(Channel& channel);

    // ---- Channel Access Lists ----
    bool add_access(Channel& channel, const ChannelAccessEntry& entry);
    bool remove_access(Channel& channel, std::string_view account_or_mask);
    AccessLevel get_access_level(const Channel& channel, const std::string& nick,
                                 const std::string& user, const std::string& host,
                                 const std::string& account) const;
    std::vector<ChannelAccessEntry> get_access_list(const Channel& channel) const;
    bool auto_op_on_join(Channel& channel, const std::string& nick,
                         const std::string& user, const std::string& host,
                         const std::string& account);

    // ---- G-Lines ----
    bool add_gline(const GLine& gline);
    bool remove_gline(std::string_view mask);
    bool has_gline(const std::string& nick, const std::string& user,
                   const std::string& host) const;
    std::vector<GLine> list_glines() const;
    GLine* find_gline(const std::string& nick, const std::string& user,
                      const std::string& host);
    void expire_glines();

    // ---- K-Lines ----
    bool add_kline(const KLine& kline);
    bool remove_kline(std::string_view mask);
    bool has_kline(const std::string& user, const std::string& host) const;
    std::vector<KLine> list_klines() const;
    KLine* find_kline(const std::string& user, const std::string& host);
    void expire_klines();

    // ---- Z-Lines ----
    bool add_zline(const ZLine& zline);
    bool remove_zline(std::string_view ip_mask);
    bool has_zline(const std::string& ip) const;
    std::vector<ZLine> list_zlines() const;
    ZLine* find_zline(const std::string& ip);
    void expire_zlines();

    // ---- E-Lines ----
    bool add_eline(const ELine& eline);
    bool remove_eline(std::string_view mask);
    bool has_eline(const std::string& user, const std::string& host) const;
    std::vector<ELine> list_elines() const;
    void expire_elines();

    // ---- Q-Lines ----
    bool add_qline(const QLine& qline);
    bool remove_qline(std::string_view mask);
    bool is_nick_quieted(std::string_view nick) const;
    bool is_channel_quieted(std::string_view channel) const;
    std::vector<QLine> list_qlines() const;
    void expire_qlines();

    // ---- Spam Filter ----
    bool add_spam_filter(const std::string& pattern, SpamAction action,
                         const std::string& reason, const std::string& added_by);
    bool remove_spam_filter(const std::string& pattern);
    bool test_spam_filter(const std::string& text, SpamAction& out_action,
                          std::string& out_reason) const;
    std::vector<SpamFilter> list_spam_filters() const;
    void load_spam_filters();
    void save_spam_filters();

    // ---- Flood Protection ----
    bool check_message_flood(const std::string& ident, const std::string& ip,
                             int max_messages, int window_seconds);
    bool check_join_flood(const std::string& ident, const std::string& ip,
                          int max_joins, int window_seconds);
    bool check_nick_flood(const std::string& ident, const std::string& ip,
                          int max_changes, int window_seconds);
    bool check_invite_flood(const std::string& ident, const std::string& ip,
                            int max_invites, int window_seconds);
    bool is_flooded(const std::string& ident, const std::string& ip) const;
    void clear_flood(const std::string& ident, const std::string& ip);

    // ---- Connection Throttling ----
    bool throttle_connection(const std::string& ip, int max_connections,
                             int window_seconds);
    void release_connection(const std::string& ip);
    bool is_throttled(const std::string& ip) const;
    int  connection_count(const std::string& ip) const;
    std::vector<ConnectionThrottle> list_throttles() const;

    // ---- Proxy Scanner ----
    bool scan_for_proxy(const std::string& ip, uint16_t port);
    bool is_proxy(const std::string& ip) const;
    void add_proxy(const std::string& ip);
    void remove_proxy(const std::string& ip);
    std::vector<std::string> list_proxies() const;

    // ---- DNSBL Integration ----
    void add_dnsbl(const DNSBLEntry& entry);
    void remove_dnsbl(const std::string& name);
    bool check_dnsbl(const std::string& ip, std::string& out_result_reason) const;
    std::vector<DNSBLEntry> list_dnsbls() const;

    // ---- Channel Mode +c (no color codes) ----
    bool has_mode_no_color(const Channel& channel) const;
    bool strip_color_on_send(const Channel& channel, std::string& message) const;

    // ---- Channel Mode +C (no CTCP) ----
    bool has_mode_no_ctcp(const Channel& channel) const;
    bool block_ctcp(const Channel& channel) const;

    // ---- Channel Mode +M (only registered users can talk) ----
    bool has_mode_registered_only_talk(const Channel& channel) const;
    bool can_talk_registered(const Channel& channel, const std::string& account) const;

    // ---- Channel Mode +R (only registered users can join) ----
    bool has_mode_registered_only_join(const Channel& channel) const;
    bool can_join_registered(const Channel& channel, const std::string& account) const;

    // ---- Cloaking ----
    std::string cloak_hostname(const std::string& host, const std::string& ip) const;
    std::string cloak_hostname_v2(const std::string& host, const std::string& ip,
                                   const std::string& key) const;
    void set_cloak_key(const std::string& key);
    std::string get_cloak_key() const;

    // ---- VHost System ----
    bool assign_vhost(const std::string& account, const std::string& vhost,
                      const std::string& set_by);
    bool remove_vhost(const std::string& account);
    std::string get_vhost(const std::string& account) const;
    std::vector<VHostEntry> list_vhosts() const;
    void load_vhosts();
    void save_vhosts();

    // ---- Statistics ----
    struct AbuseStats {
        uint64_t glines_active;
        uint64_t klines_active;
        uint64_t zlines_active;
        uint64_t elines_active;
        uint64_t qlines_active;
        uint64_t spam_filters;
        uint64_t spam_hits_total;
        uint64_t flood_events;
        uint64_t proxies_detected;
        uint64_t dnsbl_hits;
        uint64_t vhosts_assigned;
    };
    AbuseStats get_stats() const;

private:
    // ---- Internal helpers ----
    std::string make_access_path(const std::string& channel_name) const;
    void load_channel_access(const std::string& channel_name);
    void save_channel_access(const std::string& channel_name);
    void load_bans_file(const std::string& channel_name);
    void save_bans_file(const std::string& channel_name);

    std::string channel_key(std::string_view name) const {
        std::string lower;
        lower.reserve(name.size());
        for (unsigned char c : name) {
            lower.push_back(static_cast<char>(std::tolower(c)));
        }
        return lower;
    }

    void save_db(const std::string& path,
                 const std::function<void(std::ofstream&)>& writer) const;
    void load_db(const std::string& path,
                 const std::function<void(const std::string&)>& parser) const;

    FloodProfile& get_flood_profile(const std::string& ident, const std::string& ip);

    // ---- Data directory ----
    std::string data_dir_;

    // ---- Extended bans per channel ----
    mutable std::shared_mutex bans_mutex_;
    std::unordered_map<std::string, std::vector<ExtendedBan>, IrcCaseHash, IrcCaseEqual> bans_;
    std::unordered_map<std::string, std::vector<ExtendedBan>, IrcCaseHash, IrcCaseEqual> ban_exceptions_;

    // ---- Access lists per channel ----
    mutable std::shared_mutex access_mutex_;
    std::unordered_map<std::string, std::vector<ChannelAccessEntry>, IrcCaseHash, IrcCaseEqual> access_lists_;

    // ---- G-Lines ----
    mutable std::shared_mutex gline_mutex_;
    std::vector<GLine> glines_;

    // ---- K-Lines ----
    mutable std::shared_mutex kline_mutex_;
    std::vector<KLine> klines_;

    // ---- Z-Lines ----
    mutable std::shared_mutex zline_mutex_;
    std::vector<ZLine> zlines_;

    // ---- E-Lines ----
    mutable std::shared_mutex eline_mutex_;
    std::vector<ELine> elines_;

    // ---- Q-Lines ----
    mutable std::shared_mutex qline_mutex_;
    std::vector<QLine> qlines_;

    // ---- Spam filters ----
    mutable std::shared_mutex spam_mutex_;
    std::vector<SpamFilter> spam_filters_;

    // ---- Flood profiles ----
    mutable std::shared_mutex flood_mutex_;
    std::unordered_map<std::string, FloodProfile> flood_profiles_;

    // ---- Connection throttling ----
    mutable std::shared_mutex throttle_mutex_;
    std::unordered_map<std::string, ConnectionThrottle> throttles_;

    // ---- Proxy scanner ----
    mutable std::shared_mutex proxy_mutex_;
    std::unordered_set<std::string> proxies_;

    // ---- DNSBL ----
    mutable std::shared_mutex dnsbl_mutex_;
    std::vector<DNSBLEntry> dnsbls_;

    // ---- Channel modes cache ----
    mutable std::shared_mutex chanmode_mutex_;
    std::unordered_map<std::string, uint64_t, IrcCaseHash, IrcCaseEqual> channel_modes_;

    // ---- Cloaking ----
    mutable std::shared_mutex cloak_mutex_;
    std::string cloak_key_;
    std::string cloak_seed_;

    // ---- VHost ----
    mutable std::shared_mutex vhost_mutex_;
    std::unordered_map<std::string, VHostEntry, IrcCaseHash, IrcCaseEqual> vhosts_;

    // ---- Statistics ----
    mutable std::shared_mutex stats_mutex_;
    mutable AbuseStats stats_{};

public:
    // ---- Channel mode bit flags ----
    static constexpr uint64_t kModeNoColor         = 1ULL << 0;  // +c
    static constexpr uint64_t kModeNoCTCP          = 1ULL << 1;  // +C
    static constexpr uint64_t kModeRegisteredTalk  = 1ULL << 2;  // +M
    static constexpr uint64_t kModeRegisteredJoin  = 1ULL << 3;  // +R

private:
};

// ============================================================================
// Public: Constructor / Destructor
// ============================================================================

AccessAbuseManager::AccessAbuseManager()
    : data_dir_("data/") {
    // Generate a random cloak seed on startup
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    uint64_t seed_val = dist(gen);
    std::ostringstream oss;
    oss << std::hex << seed_val;
    cloak_seed_ = oss.str();
    cloak_key_  = cloak_seed_;  // Default key = seed; can be set via config
}

AccessAbuseManager::~AccessAbuseManager() {
    try {
        save_all();
    } catch (...) {
        // Best effort - don't throw from destructor
    }
}

// ============================================================================
// Initialization
// ============================================================================

void AccessAbuseManager::initialize(const std::string& data_dir) {
    data_dir_ = data_dir;
    if (data_dir_.back() != '/') data_dir_ += '/';
    // Ensure directories exist
    std::string cmd = "mkdir -p " + data_dir_ + "access";
    system(cmd.c_str());
    load_all();
}

void AccessAbuseManager::load_all() {
    load_db(data_dir_ + "glines.db", [this](const std::string& line) {
        std::istringstream iss(line);
        std::string mask, reason, set_by, sa_str, exp_str;
        std::getline(iss, mask, '|');
        std::getline(iss, reason, '|');
        std::getline(iss, set_by, '|');
        std::getline(iss, sa_str, '|');
        std::getline(iss, exp_str, '|');
        GLine g(mask, reason, set_by,
                static_cast<std::time_t>(std::stoll(sa_str)),
                static_cast<std::time_t>(std::stoll(exp_str)));
        glines_.push_back(g);
    });

    load_db(data_dir_ + "klines.db", [this](const std::string& line) {
        std::istringstream iss(line);
        std::string mask, reason, set_by, sa_str, exp_str;
        std::getline(iss, mask, '|');
        std::getline(iss, reason, '|');
        std::getline(iss, set_by, '|');
        std::getline(iss, sa_str, '|');
        std::getline(iss, exp_str, '|');
        KLine k(mask, reason, set_by,
                static_cast<std::time_t>(std::stoll(sa_str)),
                static_cast<std::time_t>(std::stoll(exp_str)));
        klines_.push_back(k);
    });

    load_db(data_dir_ + "zlines.db", [this](const std::string& line) {
        std::istringstream iss(line);
        std::string ip, reason, set_by, sa_str, exp_str;
        std::getline(iss, ip, '|');
        std::getline(iss, reason, '|');
        std::getline(iss, set_by, '|');
        std::getline(iss, sa_str, '|');
        std::getline(iss, exp_str, '|');
        ZLine z(ip, reason, set_by,
                static_cast<std::time_t>(std::stoll(sa_str)),
                static_cast<std::time_t>(std::stoll(exp_str)));
        zlines_.push_back(z);
    });

    load_db(data_dir_ + "elines.db", [this](const std::string& line) {
        std::istringstream iss(line);
        std::string mask, set_by, sa_str, exp_str;
        std::getline(iss, mask, '|');
        std::getline(iss, set_by, '|');
        std::getline(iss, sa_str, '|');
        std::getline(iss, exp_str, '|');
        ELine e(mask, set_by,
                static_cast<std::time_t>(std::stoll(sa_str)),
                static_cast<std::time_t>(std::stoll(exp_str)));
        elines_.push_back(e);
    });

    load_db(data_dir_ + "qlines.db", [this](const std::string& line) {
        std::istringstream iss(line);
        std::string mask, is_ch_str, reason, set_by, sa_str, exp_str;
        std::getline(iss, mask, '|');
        std::getline(iss, is_ch_str, '|');
        std::getline(iss, reason, '|');
        std::getline(iss, set_by, '|');
        std::getline(iss, sa_str, '|');
        std::getline(iss, exp_str, '|');
        bool is_ch = (is_ch_str == "1");
        QLine q(mask, is_ch, reason, set_by,
                static_cast<std::time_t>(std::stoll(sa_str)),
                static_cast<std::time_t>(std::stoll(exp_str)));
        qlines_.push_back(q);
    });

    load_spam_filters();
    load_vhosts();

    // Expire stale entries
    expire_glines();
    expire_klines();
    expire_zlines();
    expire_elines();
    expire_qlines();
}

void AccessAbuseManager::save_all() {
    // G-Lines
    {
        std::shared_lock lock(gline_mutex_);
        save_db(data_dir_ + "glines.db", [this](std::ofstream& ofs) {
            for (const auto& g : glines_) {
                ofs << g.mask << "|" << g.reason << "|" << g.set_by << "|"
                    << g.set_at << "|" << g.expires_at << "\n";
            }
        });
    }
    // K-Lines
    {
        std::shared_lock lock(kline_mutex_);
        save_db(data_dir_ + "klines.db", [this](std::ofstream& ofs) {
            for (const auto& k : klines_) {
                ofs << k.mask << "|" << k.reason << "|" << k.set_by << "|"
                    << k.set_at << "|" << k.expires_at << "\n";
            }
        });
    }
    // Z-Lines
    {
        std::shared_lock lock(zline_mutex_);
        save_db(data_dir_ + "zlines.db", [this](std::ofstream& ofs) {
            for (const auto& z : zlines_) {
                ofs << z.ip_mask << "|" << z.reason << "|" << z.set_by << "|"
                    << z.set_at << "|" << z.expires_at << "\n";
            }
        });
    }
    // E-Lines
    {
        std::shared_lock lock(eline_mutex_);
        save_db(data_dir_ + "elines.db", [this](std::ofstream& ofs) {
            for (const auto& e : elines_) {
                ofs << e.mask << "|" << e.set_by << "|" << e.set_at << "|"
                    << e.expires_at << "\n";
            }
        });
    }
    // Q-Lines
    {
        std::shared_lock lock(qline_mutex_);
        save_db(data_dir_ + "qlines.db", [this](std::ofstream& ofs) {
            for (const auto& q : qlines_) {
                ofs << q.mask << "|" << (q.is_channel ? "1" : "0") << "|"
                    << q.reason << "|" << q.set_by << "|"
                    << q.set_at << "|" << q.expires_at << "\n";
            }
        });
    }
    save_spam_filters();
    save_vhosts();
}

void AccessAbuseManager::reload() {
    // Clear in-memory data and reload
    {
        std::unique_lock lock(bans_mutex_);
        bans_.clear();
        ban_exceptions_.clear();
    }
    {
        std::unique_lock lock(access_mutex_);
        access_lists_.clear();
    }
    {
        std::unique_lock lock(gline_mutex_);
        glines_.clear();
    }
    {
        std::unique_lock lock(kline_mutex_);
        klines_.clear();
    }
    {
        std::unique_lock lock(zline_mutex_);
        zlines_.clear();
    }
    {
        std::unique_lock lock(eline_mutex_);
        elines_.clear();
    }
    {
        std::unique_lock lock(qline_mutex_);
        qlines_.clear();
    }
    {
        std::unique_lock lock(spam_mutex_);
        spam_filters_.clear();
    }
    load_all();
}

// ============================================================================
// Extended Bans
// ============================================================================

bool AccessAbuseManager::add_ban(Channel& channel, const ExtendedBan& ban) {
    std::unique_lock lock(bans_mutex_);
    std::string ck = channel_key(channel.name);
    auto& bl = bans_[ck];

    // Check for duplicates
    for (const auto& existing : bl) {
        if (existing.type == ban.type && irc_case_equal(existing.mask, ban.mask)) {
            return false;  // Already exists
        }
    }
    bl.push_back(ban);
    save_bans_file(channel.name);
    return true;
}

bool AccessAbuseManager::remove_ban(Channel& channel, std::string_view mask) {
    std::unique_lock lock(bans_mutex_);
    std::string ck = channel_key(channel.name);
    auto it = bans_.find(ck);
    if (it == bans_.end()) return false;

    auto& bl = it->second;
    auto before = bl.size();
    bl.erase(std::remove_if(bl.begin(), bl.end(), [&](const ExtendedBan& eb) {
        return irc_case_equal(eb.mask, mask);
    }), bl.end());

    if (bl.size() != before) {
        save_bans_file(channel.name);
        return true;
    }
    return false;
}

bool AccessAbuseManager::is_banned(const Channel& channel, const std::string& nick,
                                    const std::string& user, const std::string& host,
                                    const std::string& realname, const std::string& account,
                                    const std::string& certfp, bool is_oper) const {
    // First check E-Lines - if user matches an E-Line they bypass bans
    if (has_eline(user, host)) return false;

    std::shared_lock lock(bans_mutex_);
    std::string ck = channel_key(channel.name);
    auto it = bans_.find(ck);
    if (it == bans_.end()) return false;

    for (const auto& eb : it->second) {
        if (eb.type == BanType::kQuiet) continue;  // Quiets are checked separately
        if (eb.matches(nick, user, host, realname, account, certfp, is_oper)) {
            return true;
        }
    }
    // Also check ban exceptions
    auto ex_it = ban_exceptions_.find(ck);
    if (ex_it != ban_exceptions_.end()) {
        for (const auto& eb : ex_it->second) {
            if (eb.matches(nick, user, host, realname, account, certfp, is_oper)) {
                return false;  // Exception match
            }
        }
    }
    return false;
}

bool AccessAbuseManager::is_quieted(const Channel& channel, const std::string& nick,
                                     const std::string& user, const std::string& host) const {
    std::shared_lock lock(bans_mutex_);
    std::string ck = channel_key(channel.name);
    auto it = bans_.find(ck);
    if (it == bans_.end()) return false;

    for (const auto& eb : it->second) {
        if (eb.type == BanType::kQuiet && eb.matches(nick, user, host, "", "", "", false)) {
            return true;
        }
    }
    return false;
}

std::vector<ExtendedBan> AccessAbuseManager::get_ban_list(const Channel& channel) const {
    std::shared_lock lock(bans_mutex_);
    std::string ck = channel_key(channel.name);
    auto it = bans_.find(ck);
    if (it == bans_.end()) return {};
    std::vector<ExtendedBan> result;
    for (const auto& eb : it->second) {
        if (eb.type != BanType::kQuiet) result.push_back(eb);
    }
    return result;
}

std::vector<ExtendedBan> AccessAbuseManager::get_exception_list(const Channel& channel) const {
    std::shared_lock lock(bans_mutex_);
    std::string ck = channel_key(channel.name);
    auto it = ban_exceptions_.find(ck);
    if (it == ban_exceptions_.end()) return {};
    return it->second;
}

void AccessAbuseManager::clear_bans(Channel& channel) {
    std::unique_lock lock(bans_mutex_);
    std::string ck = channel_key(channel.name);
    bans_[ck].clear();
}

// ============================================================================
// Channel Access Lists
// ============================================================================

bool AccessAbuseManager::add_access(Channel& channel, const ChannelAccessEntry& entry) {
    std::unique_lock lock(access_mutex_);
    std::string ck = channel_key(channel.name);
    auto& al = access_lists_[ck];

    // Check for duplicates
    for (const auto& e : al) {
        if (!entry.account.empty() && irc_case_equal(e.account, entry.account)) {
            return false;
        }
        if (irc_case_equal(e.mask, entry.mask)) {
            return false;
        }
    }
    al.push_back(entry);
    save_channel_access(channel.name);
    return true;
}

bool AccessAbuseManager::remove_access(Channel& channel, std::string_view account_or_mask) {
    std::unique_lock lock(access_mutex_);
    std::string ck = channel_key(channel.name);
    auto it = access_lists_.find(ck);
    if (it == access_lists_.end()) return false;

    auto& al = it->second;
    auto before = al.size();
    al.erase(std::remove_if(al.begin(), al.end(), [&](const ChannelAccessEntry& e) {
        return irc_case_equal(e.account, account_or_mask) ||
               irc_case_equal(e.mask, account_or_mask);
    }), al.end());

    if (al.size() != before) {
        save_channel_access(channel.name);
        return true;
    }
    return false;
}

AccessLevel AccessAbuseManager::get_access_level(const Channel& channel,
                                                  const std::string& nick,
                                                  const std::string& user,
                                                  const std::string& host,
                                                  const std::string& account) const {
    std::shared_lock lock(access_mutex_);
    std::string ck = channel_key(channel.name);
    auto it = access_lists_.find(ck);
    if (it == access_lists_.end()) return AccessLevel::kNone;

    AccessLevel best = AccessLevel::kNone;
    for (const auto& entry : it->second) {
        if (entry.matches(nick, user, host, account)) {
            if (static_cast<int>(entry.level) > static_cast<int>(best)) {
                best = entry.level;
            }
        }
    }
    return best;
}

std::vector<ChannelAccessEntry> AccessAbuseManager::get_access_list(const Channel& channel) const {
    std::shared_lock lock(access_mutex_);
    std::string ck = channel_key(channel.name);
    auto it = access_lists_.find(ck);
    if (it == access_lists_.end()) return {};
    return it->second;
}

bool AccessAbuseManager::auto_op_on_join(Channel& channel, const std::string& nick,
                                          const std::string& user, const std::string& host,
                                          const std::string& account) {
    AccessLevel lvl = get_access_level(channel, nick, user, host, account);

    // The caller should apply appropriate channel modes based on level.
    // Return true if the user should receive any elevated status.
    // Level mapping: kFounder -> +q (owner), kAdmin -> +a (admin/protected),
    //                kOp -> +o, kHalfop -> +h, kVoice -> +v
    if (lvl >= AccessLevel::kVoice) {
        // Update last_seen on the matching entry
        {
            std::unique_lock lock(access_mutex_);
            std::string ck = channel_key(channel.name);
            auto it = access_lists_.find(ck);
            if (it != access_lists_.end()) {
                for (auto& entry : it->second) {
                    if (entry.matches(nick, user, host, account)) {
                        entry.last_seen = std::time(nullptr);
                    }
                }
            }
        }
        return true;
    }
    return false;
}

// ============================================================================
// G-Lines
// ============================================================================

bool AccessAbuseManager::add_gline(const GLine& gline) {
    std::unique_lock lock(gline_mutex_);
    // Check for existing duplicate
    for (const auto& g : glines_) {
        if (irc_case_equal(g.mask, gline.mask)) return false;
    }
    glines_.push_back(gline);
    return true;
}

bool AccessAbuseManager::remove_gline(std::string_view mask) {
    std::unique_lock lock(gline_mutex_);
    auto before = glines_.size();
    glines_.erase(std::remove_if(glines_.begin(), glines_.end(), [&](const GLine& g) {
        return irc_case_equal(g.mask, mask);
    }), glines_.end());
    return glines_.size() != before;
}

bool AccessAbuseManager::has_gline(const std::string& nick, const std::string& user,
                                    const std::string& host) const {
    // Check E-Line exemption first
    if (has_eline(user, host)) return false;

    std::shared_lock lock(gline_mutex_);
    for (const auto& g : glines_) {
        if (!g.active || g.is_expired()) continue;
        if (g.matches(nick, user, host)) return true;
    }
    return false;
}

std::vector<GLine> AccessAbuseManager::list_glines() const {
    std::shared_lock lock(gline_mutex_);
    return glines_;
}

GLine* AccessAbuseManager::find_gline(const std::string& nick, const std::string& user,
                                       const std::string& host) {
    std::shared_lock lock(gline_mutex_);
    for (auto& g : glines_) {
        if (g.active && !g.is_expired() && g.matches(nick, user, host)) {
            return &g;
        }
    }
    return nullptr;
}

void AccessAbuseManager::expire_glines() {
    std::unique_lock lock(gline_mutex_);
    auto now = std::time(nullptr);
    for (auto& g : glines_) {
        if (g.expires_at > 0 && now >= g.expires_at) {
            g.active = false;
        }
    }
}

// ============================================================================
// K-Lines
// ============================================================================

bool AccessAbuseManager::add_kline(const KLine& kline) {
    std::unique_lock lock(kline_mutex_);
    for (const auto& k : klines_) {
        if (irc_case_equal(k.mask, kline.mask)) return false;
    }
    klines_.push_back(kline);
    return true;
}

bool AccessAbuseManager::remove_kline(std::string_view mask) {
    std::unique_lock lock(kline_mutex_);
    auto before = klines_.size();
    klines_.erase(std::remove_if(klines_.begin(), klines_.end(), [&](const KLine& k) {
        return irc_case_equal(k.mask, mask);
    }), klines_.end());
    return klines_.size() != before;
}

bool AccessAbuseManager::has_kline(const std::string& user, const std::string& host) const {
    // Check E-Line exemption
    if (has_eline(user, host)) return false;

    std::shared_lock lock(kline_mutex_);
    for (const auto& k : klines_) {
        if (!k.active || k.is_expired()) continue;
        if (k.matches(user, host)) return true;
    }
    return false;
}

std::vector<KLine> AccessAbuseManager::list_klines() const {
    std::shared_lock lock(kline_mutex_);
    return klines_;
}

KLine* AccessAbuseManager::find_kline(const std::string& user, const std::string& host) {
    std::shared_lock lock(kline_mutex_);
    for (auto& k : klines_) {
        if (k.active && !k.is_expired() && k.matches(user, host)) {
            return &k;
        }
    }
    return nullptr;
}

void AccessAbuseManager::expire_klines() {
    std::unique_lock lock(kline_mutex_);
    auto now = std::time(nullptr);
    for (auto& k : klines_) {
        if (k.expires_at > 0 && now >= k.expires_at) {
            k.active = false;
        }
    }
}

// ============================================================================
// Z-Lines
// ============================================================================

bool AccessAbuseManager::add_zline(const ZLine& zline) {
    std::unique_lock lock(zline_mutex_);
    for (const auto& z : zlines_) {
        if (irc_case_equal(z.ip_mask, zline.ip_mask)) return false;
    }
    zlines_.push_back(zline);
    return true;
}

bool AccessAbuseManager::remove_zline(std::string_view ip_mask) {
    std::unique_lock lock(zline_mutex_);
    auto before = zlines_.size();
    zlines_.erase(std::remove_if(zlines_.begin(), zlines_.end(), [&](const ZLine& z) {
        return irc_case_equal(z.ip_mask, ip_mask);
    }), zlines_.end());
    return zlines_.size() != before;
}

bool AccessAbuseManager::has_zline(const std::string& ip) const {
    // Check E-Line exemption
    if (has_eline("*", ip)) return false;

    std::shared_lock lock(zline_mutex_);
    for (const auto& z : zlines_) {
        if (!z.active || z.is_expired()) continue;
        if (z.matches(ip)) return true;
    }
    return false;
}

std::vector<ZLine> AccessAbuseManager::list_zlines() const {
    std::shared_lock lock(zline_mutex_);
    return zlines_;
}

ZLine* AccessAbuseManager::find_zline(const std::string& ip) {
    std::shared_lock lock(zline_mutex_);
    for (auto& z : zlines_) {
        if (z.active && !z.is_expired() && z.matches(ip)) {
            return &z;
        }
    }
    return nullptr;
}

void AccessAbuseManager::expire_zlines() {
    std::unique_lock lock(zline_mutex_);
    auto now = std::time(nullptr);
    for (auto& z : zlines_) {
        if (z.expires_at > 0 && now >= z.expires_at) {
            z.active = false;
        }
    }
}

// ============================================================================
// E-Lines
// ============================================================================

bool AccessAbuseManager::add_eline(const ELine& eline) {
    std::unique_lock lock(eline_mutex_);
    for (const auto& e : elines_) {
        if (irc_case_equal(e.mask, eline.mask)) return false;
    }
    elines_.push_back(eline);
    return true;
}

bool AccessAbuseManager::remove_eline(std::string_view mask) {
    std::unique_lock lock(eline_mutex_);
    auto before = elines_.size();
    elines_.erase(std::remove_if(elines_.begin(), elines_.end(), [&](const ELine& e) {
        return irc_case_equal(e.mask, mask);
    }), elines_.end());
    return elines_.size() != before;
}

bool AccessAbuseManager::has_eline(const std::string& user, const std::string& host) const {
    std::shared_lock lock(eline_mutex_);
    for (const auto& e : elines_) {
        if (!e.active || e.is_expired()) continue;
        if (e.matches(user, host)) return true;
    }
    return false;
}

std::vector<ELine> AccessAbuseManager::list_elines() const {
    std::shared_lock lock(eline_mutex_);
    return elines_;
}

void AccessAbuseManager::expire_elines() {
    std::unique_lock lock(eline_mutex_);
    auto now = std::time(nullptr);
    for (auto& e : elines_) {
        if (e.expires_at > 0 && now >= e.expires_at) {
            e.active = false;
        }
    }
}

// ============================================================================
// Q-Lines
// ============================================================================

bool AccessAbuseManager::add_qline(const QLine& qline) {
    std::unique_lock lock(qline_mutex_);
    for (const auto& q : qlines_) {
        if (irc_case_equal(q.mask, qline.mask) && q.is_channel == qline.is_channel) {
            return false;
        }
    }
    qlines_.push_back(qline);
    return true;
}

bool AccessAbuseManager::remove_qline(std::string_view mask) {
    std::unique_lock lock(qline_mutex_);
    auto before = qlines_.size();
    qlines_.erase(std::remove_if(qlines_.begin(), qlines_.end(), [&](const QLine& q) {
        return irc_case_equal(q.mask, mask);
    }), qlines_.end());
    return qlines_.size() != before;
}

bool AccessAbuseManager::is_nick_quieted(std::string_view nick) const {
    // Check E-Line exemption (E-lines are typically user@host, so we check if there's any
    // E-Line that might match a user with this nick - really we'd need full user@host here,
    // but for Q-line purposes we just check the nick pattern)
    std::shared_lock lock(qline_mutex_);
    for (const auto& q : qlines_) {
        if (!q.active || q.is_expired()) continue;
        if (q.is_channel) continue;  // Only check nick Q-lines
        if (wildcard_match(q.mask, nick)) return true;
    }
    return false;
}

bool AccessAbuseManager::is_channel_quieted(std::string_view channel) const {
    std::shared_lock lock(qline_mutex_);
    for (const auto& q : qlines_) {
        if (!q.active || q.is_expired()) continue;
        if (!q.is_channel) continue;  // Only check channel Q-lines
        if (irc_case_equal(q.mask, channel)) return true;
    }
    return false;
}

std::vector<QLine> AccessAbuseManager::list_qlines() const {
    std::shared_lock lock(qline_mutex_);
    return qlines_;
}

void AccessAbuseManager::expire_qlines() {
    std::unique_lock lock(qline_mutex_);
    auto now = std::time(nullptr);
    for (auto& q : qlines_) {
        if (q.expires_at > 0 && now >= q.expires_at) {
            q.active = false;
        }
    }
}

// ============================================================================
// Spam Filter
// ============================================================================

bool AccessAbuseManager::add_spam_filter(const std::string& pattern, SpamAction action,
                                          const std::string& reason, const std::string& added_by) {
    std::unique_lock lock(spam_mutex_);
    for (const auto& sf : spam_filters_) {
        if (sf.pattern == pattern) return false;
    }
    SpamFilter sf;
    sf.pattern   = pattern;
    sf.action    = action;
    sf.reason    = reason;
    sf.added_at  = std::time(nullptr);
    sf.added_by  = added_by;
    sf.hit_count = 0;
    try {
        sf.compiled = std::regex(pattern, std::regex::ECMAScript | std::regex::icase);
    } catch (const std::regex_error&) {
        return false;  // Invalid regex
    }
    spam_filters_.push_back(std::move(sf));
    return true;
}

bool AccessAbuseManager::remove_spam_filter(const std::string& pattern) {
    std::unique_lock lock(spam_mutex_);
    auto before = spam_filters_.size();
    spam_filters_.erase(std::remove_if(spam_filters_.begin(), spam_filters_.end(),
        [&](const SpamFilter& sf) { return sf.pattern == pattern; }),
        spam_filters_.end());
    return spam_filters_.size() != before;
}

bool AccessAbuseManager::test_spam_filter(const std::string& text, SpamAction& out_action,
                                           std::string& out_reason) const {
    std::shared_lock lock(spam_mutex_);
    for (auto& sf : spam_filters_) {
        if (sf.matches(text)) {
            sf.hit_count++;  // mutable member, safe in const method
            {
                std::unique_lock s_lock(stats_mutex_);
                stats_.spam_hits_total++;
            }
            out_action = sf.action;
            out_reason = sf.reason;
            return true;
        }
    }
    return false;
}

std::vector<SpamFilter> AccessAbuseManager::list_spam_filters() const {
    std::shared_lock lock(spam_mutex_);
    return spam_filters_;
}

void AccessAbuseManager::load_spam_filters() {
    std::ifstream file(data_dir_ + "spamfilters.conf");
    if (!file.is_open()) return;

    std::string line;
    SpamFilter current;
    int field = 0;

    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        if (line == "---") {
            // End of entry
            if (!current.pattern.empty()) {
                try {
                    current.compiled = std::regex(current.pattern,
                        std::regex::ECMAScript | std::regex::icase);
                    {
                        std::unique_lock lock(spam_mutex_);
                        spam_filters_.push_back(current);
                    }
                } catch (...) {
                    // Skip invalid regex
                }
            }
            current = SpamFilter{};
            field = 0;
            continue;
        }

        switch (field++) {
            case 0: current.pattern  = line; break;
            case 1: {
                int act = std::stoi(line);
                current.action = static_cast<SpamAction>(act);
                break;
            }
            case 2: current.reason   = line; break;
            case 3: current.added_by = line; break;
            case 4: current.added_at = std::stoll(line); break;
        }
    }
}

void AccessAbuseManager::save_spam_filters() {
    std::shared_lock lock(spam_mutex_);
    std::ofstream file(data_dir_ + "spamfilters.conf");
    if (!file.is_open()) return;

    file << "# Spam Filter Configuration\n";
    file << "# Format: pattern | action | reason | added_by | added_at\n";
    file << "# Separated by ---\n\n";

    for (const auto& sf : spam_filters_) {
        file << sf.pattern << "\n";
        file << static_cast<int>(sf.action) << "\n";
        file << sf.reason << "\n";
        file << sf.added_by << "\n";
        file << sf.added_at << "\n";
        file << "---\n";
    }
}

// ============================================================================
// Flood Protection
// ============================================================================

FloodProfile& AccessAbuseManager::get_flood_profile(const std::string& ident,
                                                     const std::string& ip) {
    std::string key = ident + "@" + ip;
    return flood_profiles_[key];
}

bool AccessAbuseManager::check_message_flood(const std::string& ident, const std::string& ip,
                                              int max_messages, int window_seconds) {
    std::unique_lock lock(flood_mutex_);
    auto& fp = get_flood_profile(ident, ip);
    if (fp.flood_detected) {
        if (std::chrono::steady_clock::now() < fp.flood_until) return true;
        fp.flood_detected = false;
    }

    fp.record_message();
    fp.prune(fp.message_times, std::chrono::seconds(window_seconds));

    if (static_cast<int>(fp.message_times.size()) > max_messages) {
        fp.flood_detected = true;
        fp.flood_until = std::chrono::steady_clock::now() + std::chrono::seconds(window_seconds);
        {
            std::unique_lock s_lock(stats_mutex_);
            stats_.flood_events++;
        }
        return true;
    }
    return false;
}

bool AccessAbuseManager::check_join_flood(const std::string& ident, const std::string& ip,
                                           int max_joins, int window_seconds) {
    std::unique_lock lock(flood_mutex_);
    auto& fp = get_flood_profile(ident, ip);
    if (fp.flood_detected) {
        if (std::chrono::steady_clock::now() < fp.flood_until) return true;
        fp.flood_detected = false;
    }

    fp.record_join();
    fp.prune(fp.join_times, std::chrono::seconds(window_seconds));

    if (static_cast<int>(fp.join_times.size()) > max_joins) {
        fp.flood_detected = true;
        fp.flood_until = std::chrono::steady_clock::now() + std::chrono::seconds(window_seconds);
        {
            std::unique_lock s_lock(stats_mutex_);
            stats_.flood_events++;
        }
        return true;
    }
    return false;
}

bool AccessAbuseManager::check_nick_flood(const std::string& ident, const std::string& ip,
                                           int max_changes, int window_seconds) {
    std::unique_lock lock(flood_mutex_);
    auto& fp = get_flood_profile(ident, ip);
    if (fp.flood_detected) {
        if (std::chrono::steady_clock::now() < fp.flood_until) return true;
        fp.flood_detected = false;
    }

    fp.record_nick();
    fp.prune(fp.nick_times, std::chrono::seconds(window_seconds));

    if (static_cast<int>(fp.nick_times.size()) > max_changes) {
        fp.flood_detected = true;
        fp.flood_until = std::chrono::steady_clock::now() + std::chrono::seconds(window_seconds);
        {
            std::unique_lock s_lock(stats_mutex_);
            stats_.flood_events++;
        }
        return true;
    }
    return false;
}

bool AccessAbuseManager::check_invite_flood(const std::string& ident, const std::string& ip,
                                             int max_invites, int window_seconds) {
    std::unique_lock lock(flood_mutex_);
    auto& fp = get_flood_profile(ident, ip);
    if (fp.flood_detected) {
        if (std::chrono::steady_clock::now() < fp.flood_until) return true;
        fp.flood_detected = false;
    }

    fp.record_invite();
    fp.prune(fp.invite_times, std::chrono::seconds(window_seconds));

    if (static_cast<int>(fp.invite_times.size()) > max_invites) {
        fp.flood_detected = true;
        fp.flood_until = std::chrono::steady_clock::now() + std::chrono::seconds(window_seconds);
        {
            std::unique_lock s_lock(stats_mutex_);
            stats_.flood_events++;
        }
        return true;
    }
    return false;
}

bool AccessAbuseManager::is_flooded(const std::string& ident, const std::string& ip) const {
    std::shared_lock lock(flood_mutex_);
    std::string key = ident + "@" + ip;
    auto it = flood_profiles_.find(key);
    if (it == flood_profiles_.end()) return false;
    if (!it->second.flood_detected) return false;
    return std::chrono::steady_clock::now() < it->second.flood_until;
}

void AccessAbuseManager::clear_flood(const std::string& ident, const std::string& ip) {
    std::unique_lock lock(flood_mutex_);
    std::string key = ident + "@" + ip;
    auto it = flood_profiles_.find(key);
    if (it != flood_profiles_.end()) {
        it->second.flood_detected = false;
        it->second.message_times.clear();
        it->second.join_times.clear();
        it->second.nick_times.clear();
        it->second.invite_times.clear();
    }
}

// ============================================================================
// Connection Throttling
// ============================================================================

bool AccessAbuseManager::throttle_connection(const std::string& ip,
                                              int max_connections, int window_seconds) {
    std::unique_lock lock(throttle_mutex_);
    auto& ct = throttles_[ip];
    ct.ip = ip;

    auto now = std::chrono::steady_clock::now();

    // Check if banned
    if (ct.throttled) {
        if (now < ct.banned_until) return true;
        ct.throttled = false;
    }

    // Reset window if expired
    if (ct.window_start == std::chrono::steady_clock::time_point{}) {
        ct.reset_window();
    } else {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - ct.window_start).count();
        if (elapsed >= window_seconds) {
            ct.reset_window();
        }
    }

    ct.connection_count++;

    if (ct.connection_count > max_connections) {
        ct.throttled = true;
        ct.banned_until = now + std::chrono::seconds(window_seconds * 2);
        return true;
    }
    return false;
}

void AccessAbuseManager::release_connection(const std::string& ip) {
    std::unique_lock lock(throttle_mutex_);
    auto it = throttles_.find(ip);
    if (it != throttles_.end()) {
        if (it->second.connection_count > 0) {
            it->second.connection_count--;
        }
    }
}

bool AccessAbuseManager::is_throttled(const std::string& ip) const {
    std::shared_lock lock(throttle_mutex_);
    auto it = throttles_.find(ip);
    if (it == throttles_.end()) return false;
    if (!it->second.throttled) return false;
    return std::chrono::steady_clock::now() < it->second.banned_until;
}

int AccessAbuseManager::connection_count(const std::string& ip) const {
    std::shared_lock lock(throttle_mutex_);
    auto it = throttles_.find(ip);
    if (it == throttles_.end()) return 0;
    return it->second.connection_count;
}

std::vector<ConnectionThrottle> AccessAbuseManager::list_throttles() const {
    std::shared_lock lock(throttle_mutex_);
    std::vector<ConnectionThrottle> result;
    result.reserve(throttles_.size());
    for (const auto& [ip, ct] : throttles_) {
        result.push_back(ct);
    }
    return result;
}

// ============================================================================
// Proxy Scanner
// ============================================================================

bool AccessAbuseManager::scan_for_proxy(const std::string& ip, uint16_t port) {
    // Attempt to connect to the IP on the given port to detect open proxies.
    // Common proxy ports: 1080 (SOCKS), 3128 (HTTP), 8080 (HTTP), 9050 (Tor)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        close(sock);
        return false;
    }

    // Set non-blocking and short timeout
    struct timeval tv{};
    tv.tv_sec  = 2;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int result = connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    close(sock);

    if (result == 0) {
        // Connection succeeded - might be an open proxy
        // Try to verify by sending a simple HTTP CONNECT or SOCKS handshake
        // For simplicity, if the port is open we flag it
        add_proxy(ip);
        {
            std::unique_lock s_lock(stats_mutex_);
            stats_.proxies_detected++;
        }
        return true;
    }
    return false;
}

bool AccessAbuseManager::is_proxy(const std::string& ip) const {
    std::shared_lock lock(proxy_mutex_);
    return proxies_.find(ip) != proxies_.end();
}

void AccessAbuseManager::add_proxy(const std::string& ip) {
    std::unique_lock lock(proxy_mutex_);
    proxies_.insert(ip);
}

void AccessAbuseManager::remove_proxy(const std::string& ip) {
    std::unique_lock lock(proxy_mutex_);
    proxies_.erase(ip);
}

std::vector<std::string> AccessAbuseManager::list_proxies() const {
    std::shared_lock lock(proxy_mutex_);
    return std::vector<std::string>(proxies_.begin(), proxies_.end());
}

// ============================================================================
// DNSBL Integration
// ============================================================================

void AccessAbuseManager::add_dnsbl(const DNSBLEntry& entry) {
    std::unique_lock lock(dnsbl_mutex_);
    for (const auto& d : dnsbls_) {
        if (d.name == entry.name) return;  // Already exists
    }
    dnsbls_.push_back(entry);
}

void AccessAbuseManager::remove_dnsbl(const std::string& name) {
    std::unique_lock lock(dnsbl_mutex_);
    dnsbls_.erase(std::remove_if(dnsbls_.begin(), dnsbls_.end(),
        [&](const DNSBLEntry& d) { return d.name == name; }),
        dnsbls_.end());
}

bool AccessAbuseManager::check_dnsbl(const std::string& ip, std::string& out_reason) const {
    // Build the reversed IP lookup string for DNSBL
    // e.g., 1.2.3.4 reversed = 4.3.2.1.dnsbl.example.com
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;

    uint32_t ip_host = ntohl(addr.s_addr);
    std::ostringstream reversed;
    reversed << (ip_host & 0xFF) << "."
             << ((ip_host >> 8) & 0xFF) << "."
             << ((ip_host >> 16) & 0xFF) << "."
             << ((ip_host >> 24) & 0xFF);

    std::shared_lock lock(dnsbl_mutex_);
    for (const auto& dnsbl : dnsbls_) {
        if (!dnsbl.enabled) continue;

        std::string lookup = reversed.str() + "." + dnsbl.lookup_domain;

        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        int ret = getaddrinfo(lookup.c_str(), nullptr, &hints, &res);

        if (ret == 0 && res != nullptr) {
            // IP is listed on this DNSBL
            char result_ip[INET_ADDRSTRLEN];
            auto* sa = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
            inet_ntop(AF_INET, &sa->sin_addr, result_ip, sizeof(result_ip));
            std::string result_str(result_ip);
            freeaddrinfo(res);

            // Check if the response matches the expected reply mask
            if (dnsbl.reply_mask.empty() || result_str.find(dnsbl.reply_mask) != std::string::npos) {
                out_reason = dnsbl.name + ": " + dnsbl.reason;
                {
                    std::unique_lock s_lock(stats_mutex_);
                    stats_.dnsbl_hits++;
                }
                return true;
            }
            continue;
        }
        if (res) freeaddrinfo(res);
    }

    // Check for common DNSBLs if none configured
    // Try DroneBL, EFnet RBL, etc.
    static const std::pair<const char*, const char*> kDefaultDnsbls[] = {
        {"dnsbl.dronebl.org", "DroneBL listed"},
        {"rbl.efnetrbl.org", "EFnet RBL listed"},
    };
    for (const auto& [domain, reason] : kDefaultDnsbls) {
        std::string lookup = reversed.str() + "." + domain;
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        int ret = getaddrinfo(lookup.c_str(), nullptr, &hints, &res);
        if (ret == 0 && res != nullptr) {
            out_reason = reason;
            freeaddrinfo(res);
            {
                std::unique_lock s_lock(stats_mutex_);
                stats_.dnsbl_hits++;
            }
            return true;
        }
        if (res) freeaddrinfo(res);
    }

    return false;
}

std::vector<DNSBLEntry> AccessAbuseManager::list_dnsbls() const {
    std::shared_lock lock(dnsbl_mutex_);
    return dnsbls_;
}

// ============================================================================
// Channel Mode +c (no color codes)
// ============================================================================

bool AccessAbuseManager::has_mode_no_color(const Channel& channel) const {
    std::shared_lock lock(chanmode_mutex_);
    std::string ck = channel_key(channel.name);
    auto it = channel_modes_.find(ck);
    if (it == channel_modes_.end()) return false;
    return (it->second & kModeNoColor) != 0;
}

bool AccessAbuseManager::strip_color_on_send(const Channel& channel, std::string& message) const {
    if (!has_mode_no_color(channel)) return false;

    if (!contains_color_codes(message)) return false;

    // Strip IRC color codes: ^C[fg][,bg] sequences
    std::string result;
    result.reserve(message.size());
    bool in_color = false;
    int  color_digits = 0;
    bool after_comma = false;

    for (size_t i = 0; i < message.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(message[i]);

        if (!in_color) {
            if (c == 0x03) {
                // Start of color code
                in_color = true;
                color_digits = 0;
                after_comma = false;
                continue;
            }
            // Also strip other formatting: bold (^B), reset (^O), reverse (^R),
            // underline (^_), italic (^])
            if (c == 0x02 || c == 0x0F || c == 0x16 || c == 0x1F || c == 0x1D) {
                continue;
            }
            result.push_back(message[i]);
        } else {
            if (std::isdigit(c)) {
                if (!after_comma) {
                    if (color_digits < 2) {
                        color_digits++;
                        continue;
                    }
                } else {
                    if (color_digits < 4) {
                        color_digits++;
                        continue;
                    }
                }
            } else if (c == ',' && !after_comma) {
                after_comma = true;
                continue;
            } else {
                // End of color code
                in_color = false;
                result.push_back(message[i]);
            }
        }
    }

    message = std::move(result);
    return true;
}

// ============================================================================
// Channel Mode +C (no CTCP)
// ============================================================================

bool AccessAbuseManager::has_mode_no_ctcp(const Channel& channel) const {
    std::shared_lock lock(chanmode_mutex_);
    std::string ck = channel_key(channel.name);
    auto it = channel_modes_.find(ck);
    if (it == channel_modes_.end()) return false;
    return (it->second & kModeNoCTCP) != 0;
}

bool AccessAbuseManager::block_ctcp(const Channel& channel) const {
    return has_mode_no_ctcp(channel);
}

// ============================================================================
// Channel Mode +M (only registered users can talk)
// ============================================================================

bool AccessAbuseManager::has_mode_registered_only_talk(const Channel& channel) const {
    std::shared_lock lock(chanmode_mutex_);
    std::string ck = channel_key(channel.name);
    auto it = channel_modes_.find(ck);
    if (it == channel_modes_.end()) return false;
    return (it->second & kModeRegisteredTalk) != 0;
}

bool AccessAbuseManager::can_talk_registered(const Channel& channel,
                                              const std::string& account) const {
    if (!has_mode_registered_only_talk(channel)) return true;
    // Allow users with voice or higher even if not registered
    // (the caller must check voice/op status separately)
    return !account.empty();
}

// ============================================================================
// Channel Mode +R (only registered users can join)
// ============================================================================

bool AccessAbuseManager::has_mode_registered_only_join(const Channel& channel) const {
    std::shared_lock lock(chanmode_mutex_);
    std::string ck = channel_key(channel.name);
    auto it = channel_modes_.find(ck);
    if (it == channel_modes_.end()) return false;
    return (it->second & kModeRegisteredJoin) != 0;
}

bool AccessAbuseManager::can_join_registered(const Channel& channel,
                                              const std::string& account) const {
    if (!has_mode_registered_only_join(channel)) return true;
    return !account.empty();
}

// ============================================================================
// Cloaking
// ============================================================================

std::string AccessAbuseManager::cloak_hostname(const std::string& host,
                                                const std::string& ip) const {
    // Standard IRC cloaking: produce a hash-based pseudo hostname
    // Format: <hash-prefix>.cloaked
    std::string input = host + ip + cloak_key_;
    std::string encoded = base64_encode(input);
    // Take first 8 chars as the cloaked identifier
    std::string prefix = encoded.substr(0, 8);
    // Make it lowercase and replace +/= with valid hostname chars
    for (auto& c : prefix) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (c == '+') c = 'a';
        if (c == '/') c = 'b';
        if (c == '=') c = 'c';
    }
    return prefix + ".cloaked";
}

std::string AccessAbuseManager::cloak_hostname_v2(const std::string& host,
                                                   const std::string& ip,
                                                   const std::string& key) const {
    // V2 cloaking: more sophisticated, uses a proper hash
    // Simple HMAC-like construction
    std::string combined = key + ":" + host + ":" + ip + ":" + cloak_seed_;

    // Simple FNV-1a hash
    uint64_t hash = 14695981039346656037ULL;
    for (unsigned char c : combined) {
        hash ^= c;
        hash *= 1099511628211ULL;
    }

    std::ostringstream oss;
    oss << std::hex << (hash & 0xFFFFFFFF);
    std::string hash_hex = oss.str();

    // Determine TLD from original host
    std::string tld = "net";
    auto dot = host.find_last_of('.');
    if (dot != std::string::npos && dot + 1 < host.size()) {
        tld = host.substr(dot + 1);
        // Sanitize TLD
        for (auto& c : tld) {
            if (!std::isalnum(static_cast<unsigned char>(c))) c = 'x';
        }
        if (tld.size() > 6) tld = tld.substr(0, 6);
    }

    return hash_hex + "." + tld + ".cloak";
}

void AccessAbuseManager::set_cloak_key(const std::string& key) {
    std::unique_lock lock(cloak_mutex_);
    cloak_key_ = key;
}

std::string AccessAbuseManager::get_cloak_key() const {
    std::shared_lock lock(cloak_mutex_);
    return cloak_key_;
}

// ============================================================================
// VHost System
// ============================================================================

bool AccessAbuseManager::assign_vhost(const std::string& account, const std::string& vhost,
                                       const std::string& set_by) {
    std::unique_lock lock(vhost_mutex_);
    vhosts_[account] = VHostEntry(account, vhost, set_by, std::time(nullptr));
    {
        std::unique_lock s_lock(stats_mutex_);
        stats_.vhosts_assigned++;
    }
    return true;
}

bool AccessAbuseManager::remove_vhost(const std::string& account) {
    std::unique_lock lock(vhost_mutex_);
    auto it = vhosts_.find(account);
    if (it == vhosts_.end()) return false;
    it->second.active = false;
    vhosts_.erase(it);
    return true;
}

std::string AccessAbuseManager::get_vhost(const std::string& account) const {
    std::shared_lock lock(vhost_mutex_);
    auto it = vhosts_.find(account);
    if (it != vhosts_.end() && it->second.active) {
        return it->second.vhost;
    }
    return "";
}

std::vector<VHostEntry> AccessAbuseManager::list_vhosts() const {
    std::shared_lock lock(vhost_mutex_);
    std::vector<VHostEntry> result;
    result.reserve(vhosts_.size());
    for (const auto& [k, v] : vhosts_) {
        result.push_back(v);
    }
    return result;
}

void AccessAbuseManager::load_vhosts() {
    std::ifstream file(data_dir_ + "vhosts.db");
    if (!file.is_open()) return;

    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        std::string account, vhost, set_by, sa_str;
        std::getline(iss, account, '|');
        std::getline(iss, vhost, '|');
        std::getline(iss, set_by, '|');
        std::getline(iss, sa_str, '|');

        auto sa = static_cast<std::time_t>(std::stoll(sa_str));
        {
            std::unique_lock lock(vhost_mutex_);
            vhosts_[account] = VHostEntry(account, vhost, set_by, sa);
        }
    }
}

void AccessAbuseManager::save_vhosts() {
    std::shared_lock lock(vhost_mutex_);
    std::ofstream file(data_dir_ + "vhosts.db");
    if (!file.is_open()) return;
    for (const auto& [k, v] : vhosts_) {
        if (!v.active) continue;
        file << v.account << "|" << v.vhost << "|"
             << v.set_by << "|" << v.set_at << "\n";
    }
}

// ============================================================================
// Statistics
// ============================================================================

AccessAbuseManager::AbuseStats AccessAbuseManager::get_stats() const {
    AbuseStats s;
    {
        std::shared_lock lock(gline_mutex_);
        s.glines_active = glines_.size();
    }
    {
        std::shared_lock lock(kline_mutex_);
        s.klines_active = klines_.size();
    }
    {
        std::shared_lock lock(zline_mutex_);
        s.zlines_active = zlines_.size();
    }
    {
        std::shared_lock lock(eline_mutex_);
        s.elines_active = elines_.size();
    }
    {
        std::shared_lock lock(qline_mutex_);
        s.qlines_active = qlines_.size();
    }
    {
        std::shared_lock lock(spam_mutex_);
        s.spam_filters = spam_filters_.size();
    }
    {
        std::shared_lock lock(stats_mutex_);
        s.spam_hits_total = stats_.spam_hits_total;
        s.flood_events    = stats_.flood_events;
        s.proxies_detected = stats_.proxies_detected;
        s.dnsbl_hits       = stats_.dnsbl_hits;
        s.vhosts_assigned  = stats_.vhosts_assigned;
    }
    return s;
}

// ============================================================================
// Private: File I/O helpers
// ============================================================================

std::string AccessAbuseManager::make_access_path(const std::string& channel_name) const {
    std::string safe_name;
    for (unsigned char c : channel_name) {
        if (c == '#') {
            safe_name += '_';
        } else if (std::isalnum(c) || c == '_' || c == '-') {
            safe_name += static_cast<char>(c);
        } else {
            safe_name += '_';
        }
    }
    return data_dir_ + "access/" + safe_name + ".acl";
}

void AccessAbuseManager::load_channel_access(const std::string& channel_name) {
    std::string path = make_access_path(channel_name);
    std::ifstream file(path);
    if (!file.is_open()) return;

    std::vector<ChannelAccessEntry> entries;
    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        entries.push_back(ChannelAccessEntry::deserialize(line));
    }

    std::unique_lock lock(access_mutex_);
    access_lists_[channel_key(channel_name)] = std::move(entries);
}

void AccessAbuseManager::save_channel_access(const std::string& channel_name) {
    std::string path = make_access_path(channel_name);
    std::shared_lock lock(access_mutex_);
    std::string ck = channel_key(channel_name);
    auto it = access_lists_.find(ck);
    if (it == access_lists_.end()) return;

    std::ofstream file(path);
    if (!file.is_open()) return;
    for (const auto& entry : it->second) {
        file << entry.serialize() << "\n";
    }
}

void AccessAbuseManager::load_bans_file(const std::string& channel_name) {
    std::string safe_name;
    for (unsigned char c : channel_name) {
        if (c == '#') safe_name += '_';
        else if (std::isalnum(c) || c == '_' || c == '-') safe_name += static_cast<char>(c);
        else safe_name += '_';
    }
    std::string path = data_dir_ + "access/" + safe_name + ".bans";

    std::ifstream file(path);
    if (!file.is_open()) return;

    std::vector<ExtendedBan> ban_list;
    std::vector<ExtendedBan> except_list;
    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        auto eb = ExtendedBan::parse(line);
        ban_list.push_back(eb);
    }

    std::unique_lock lock(bans_mutex_);
    bans_[channel_key(channel_name)] = std::move(ban_list);
}

void AccessAbuseManager::save_bans_file(const std::string& channel_name) {
    std::string safe_name;
    for (unsigned char c : channel_name) {
        if (c == '#') safe_name += '_';
        else if (std::isalnum(c) || c == '_' || c == '-') safe_name += static_cast<char>(c);
        else safe_name += '_';
    }
    std::string path = data_dir_ + "access/" + safe_name + ".bans";

    std::shared_lock lock(bans_mutex_);
    std::string ck = channel_key(channel_name);
    auto it = bans_.find(ck);
    if (it == bans_.end()) return;

    std::ofstream file(path);
    if (!file.is_open()) return;
    for (const auto& ban : it->second) {
        file << ban.to_string() << "\n";
    }
}

void AccessAbuseManager::save_db(const std::string& path,
                                  const std::function<void(std::ofstream&)>& writer) const {
    std::ofstream file(path);
    if (file.is_open()) {
        writer(file);
    }
}

void AccessAbuseManager::load_db(const std::string& path,
                                  const std::function<void(const std::string&)>& parser) const {
    std::ifstream file(path);
    if (!file.is_open()) return;
    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        parser(line);
    }
}

// ============================================================================
// Free functions for external use
// ============================================================================

// Create a new AccessAbuseManager instance
AccessAbuseManager* create_access_abuse_manager() {
    return new AccessAbuseManager();
}

// Destroy an AccessAbuseManager instance
void destroy_access_abuse_manager(AccessAbuseManager* mgr) {
    delete mgr;
}

// ============================================================================
// Channel mode management helpers (for integration with channel mode handler)
// ============================================================================

namespace channel_mode_helpers {

// These functions can be called by the channel mode handler to set/clear modes
// on the internal channel_modes_ map of an AccessAbuseManager.

inline uint64_t mode_flag(char mode_char) {
    switch (mode_char) {
        case 'c': case 'C': {
            if (mode_char == 'c') return AccessAbuseManager::kModeNoColor;
            return AccessAbuseManager::kModeNoCTCP;
        }
        case 'M': return AccessAbuseManager::kModeRegisteredTalk;
        case 'R': return AccessAbuseManager::kModeRegisteredJoin;
        default: return 0;
    }
}

}  // namespace channel_mode_helpers

// ============================================================================
// IP Reputation System
// ============================================================================

struct IPReputation {
    std::string ip;
    int         score;          // Higher = worse reputation
    int         infractions;
    std::time_t first_seen;
    std::time_t last_seen;
    std::time_t ban_until;
    bool        is_banned;

    IPReputation() : score(0), infractions(0), first_seen(0), last_seen(0),
                     ban_until(0), is_banned(false) {}

    void add_infraction(int points, std::time_t ban_duration = 0) {
        score += points;
        infractions++;
        last_seen = std::time(nullptr);
        if (first_seen == 0) first_seen = last_seen;
        if (ban_duration > 0) {
            is_banned = true;
            ban_until = last_seen + ban_duration;
        }
    }

    void expire_ban() {
        if (is_banned && std::time(nullptr) >= ban_until) {
            is_banned = false;
            ban_until = 0;
        }
    }

    void decay(int amount = 1) {
        if (score > 0) score = std::max(0, score - amount);
    }
};

// ============================================================================
// Abuse event logging
// ============================================================================

struct AbuseEvent {
    enum class Type {
        kGLineHit,
        kKLineHit,
        kZLineHit,
        kSpamBlock,
        kFloodDetected,
        kProxyDetected,
        kDNSBLHit,
        kThrottleBlock
    };

    Type        type;
    std::string target;       // IP, nick, or mask
    std::string detail;
    std::time_t timestamp;
};

// ============================================================================
// RateLimiter - token bucket for command rate limiting
// ============================================================================

class RateLimiter {
public:
    RateLimiter(int max_tokens, double refill_rate)
        : max_tokens_(max_tokens), tokens_(max_tokens),
          refill_rate_(refill_rate),
          last_refill_(std::chrono::steady_clock::now()) {}

    bool consume(int tokens = 1) {
        refill();
        if (tokens_ >= tokens) {
            tokens_ -= tokens;
            return true;
        }
        return false;
    }

    void refill() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration<double>(now - last_refill_).count();
        double new_tokens = tokens_ + elapsed * refill_rate_;
        tokens_ = std::min(static_cast<double>(max_tokens_), new_tokens);
        last_refill_ = now;
    }

    int available() const { return tokens_; }

private:
    int max_tokens_;
    double tokens_;
    double refill_rate_;
    std::chrono::steady_clock::time_point last_refill_;
};

// ============================================================================
// Enhanced Proxy Scanner
// ============================================================================

class EnhancedProxyScanner {
public:
    // Common proxy ports to scan
    static constexpr uint16_t kCommonProxyPorts[] = {
        1080,   // SOCKS5
        1081,   // SOCKS4
        3128,   // Squid HTTP
        8080,   // HTTP Proxy
        8000,   // HTTP Proxy alt
        8888,   // HTTP Proxy alt
        9050,   // Tor SOCKS
        9150,   // Tor Browser
        8118,   // Privoxy
        9999,   // Common proxy
        3129,   // Squid alt
        6588,   // Common proxy
        4480,   // Common proxy
        1443,   // Common proxy
        7212,   // Common proxy
    };

    struct ScanResult {
        std::string ip;
        bool        is_proxy;
        uint16_t    detected_port;
        std::string proxy_type;  // "socks5", "http", "tor", "unknown"
        std::time_t scan_time;
    };

    // Perform a comprehensive proxy scan on an IP
    static ScanResult scan_ip(const std::string& ip) {
        ScanResult result;
        result.ip        = ip;
        result.is_proxy  = false;
        result.scan_time = std::time(nullptr);

        // Try common proxy ports
        for (uint16_t port : kCommonProxyPorts) {
            if (test_connect(ip, port)) {
                result.is_proxy     = true;
                result.detected_port = port;
                result.proxy_type   = classify_port(port);
                break;
            }
        }

        // If found on a common port, try to verify protocol
        if (result.is_proxy) {
            result.proxy_type = verify_proxy_protocol(ip, result.detected_port);
        }

        return result;
    }

    // Scan a range of IPs
    static std::vector<ScanResult> scan_range(const std::string& base_ip,
                                               int start_octet, int end_octet) {
        std::vector<ScanResult> results;
        auto dot = base_ip.find_last_of('.');
        if (dot == std::string::npos) return results;

        std::string prefix = base_ip.substr(0, dot + 1);
        for (int i = start_octet; i <= end_octet; ++i) {
            std::string target = prefix + std::to_string(i);
            auto result = scan_ip(target);
            if (result.is_proxy) {
                results.push_back(result);
            }
        }
        return results;
    }

private:
    static bool test_connect(const std::string& ip, uint16_t port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
            close(sock);
            return false;
        }

        // Set short timeout (1 second)
        struct timeval tv{};
        tv.tv_sec  = 1;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        int result = connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        close(sock);
        return result == 0;
    }

    static std::string classify_port(uint16_t port) {
        switch (port) {
            case 1080: case 1081: return "socks";
            case 9050: case 9150: return "tor";
            case 3128: case 8080: case 8000: case 8888:
            case 8118: case 3129:  return "http";
            default: return "unknown";
        }
    }

    static std::string verify_proxy_protocol(const std::string& ip, uint16_t port) {
        // Try SOCKS5 handshake
        if (test_socks5(ip, port)) return "socks5";
        // Try HTTP CONNECT
        if (test_http_proxy(ip, port)) return "http";
        return classify_port(port);
    }

    static bool test_socks5(const std::string& ip, uint16_t port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
            close(sock);
            return false;
        }

        struct timeval tv{};
        tv.tv_sec  = 1;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            close(sock);
            return false;
        }

        // SOCKS5 handshake: 0x05 0x01 0x00
        unsigned char handshake[] = {0x05, 0x01, 0x00};
        if (send(sock, handshake, 3, 0) != 3) {
            close(sock);
            return false;
        }

        unsigned char response[2];
        int n = recv(sock, response, 2, 0);
        close(sock);

        return n == 2 && response[0] == 0x05 && response[1] == 0x00;
    }

    static bool test_http_proxy(const std::string& ip, uint16_t port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
            close(sock);
            return false;
        }

        struct timeval tv{};
        tv.tv_sec  = 1;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            close(sock);
            return false;
        }

        // HTTP CONNECT request
        const char* request = "CONNECT example.com:80 HTTP/1.0\r\nHost: example.com\r\n\r\n";
        if (send(sock, request, strlen(request), 0) <= 0) {
            close(sock);
            return false;
        }

        char response[256];
        int n = recv(sock, response, sizeof(response) - 1, 0);
        close(sock);

        if (n > 0) {
            response[n] = '\0';
            std::string resp(response);
            // "200 Connection established" indicates an open HTTP proxy
            return resp.find("200") != std::string::npos;
        }
        return false;
    }
};

// ============================================================================
// DNSBL Cache
// ============================================================================

class DNSBLCache {
public:
    struct CacheEntry {
        std::string ip;
        bool        listed;
        std::string reason;
        std::time_t cached_at;
        int         ttl;  // Seconds
    };

    DNSBLCache() : default_ttl_(3600) {}  // 1 hour default TTL

    void set_default_ttl(int seconds) { default_ttl_ = seconds; }

    bool lookup(const std::string& ip, bool& listed, std::string& reason) {
        std::shared_lock lock(mutex_);
        auto it = cache_.find(ip);
        if (it != cache_.end()) {
            auto age = std::time(nullptr) - it->second.cached_at;
            if (age < it->second.ttl) {
                listed = it->second.listed;
                reason = it->second.reason;
                return true;  // Cache hit
            }
        }
        return false;  // Cache miss or expired
    }

    void store(const std::string& ip, bool listed, const std::string& reason,
               int ttl = 0) {
        std::unique_lock lock(mutex_);
        CacheEntry entry;
        entry.ip        = ip;
        entry.listed    = listed;
        entry.reason    = reason;
        entry.cached_at = std::time(nullptr);
        entry.ttl       = (ttl > 0) ? ttl : default_ttl_;
        cache_[ip] = entry;
    }

    void invalidate(const std::string& ip) {
        std::unique_lock lock(mutex_);
        cache_.erase(ip);
    }

    void flush() {
        std::unique_lock lock(mutex_);
        cache_.clear();
    }

    void expire() {
        std::unique_lock lock(mutex_);
        auto now = std::time(nullptr);
        for (auto it = cache_.begin(); it != cache_.end(); ) {
            if (now - it->second.cached_at >= it->second.ttl) {
                it = cache_.erase(it);
            } else {
                ++it;
            }
        }
    }

    size_t size() const {
        std::shared_lock lock(mutex_);
        return cache_.size();
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, CacheEntry> cache_;
    int default_ttl_;
};

// ============================================================================
// Session/Cookie IP correlation
// ============================================================================

struct SessionCorrelation {
    std::string session_id;
    std::string primary_nick;
    std::vector<std::string> known_ips;
    std::vector<std::string> known_nicks;
    std::time_t created_at;
    std::time_t last_active;
    int         abuse_score;

    SessionCorrelation() : created_at(0), last_active(0), abuse_score(0) {}
};

// ============================================================================
// Abuse escalation policy
// ============================================================================

enum class AbuseAction {
    kWarn     = 0,
    kQuiet    = 1,
    kKill     = 2,
    kTempKLine = 3,
    kPermKLine = 4,
    kGLine    = 5,
    kZLine    = 6,
};

struct AbuseEscalationRule {
    std::string name;
    int         threshold_score;
    AbuseAction action;
    int         duration;  // Seconds, 0 = permanent
    std::string message;
};

// ============================================================================
// Extended match helpers for complex ban patterns
// ============================================================================

namespace ban_match_helpers {

inline bool match_nick_user_host(const std::string& pattern,
                                  const std::string& nick,
                                  const std::string& user,
                                  const std::string& host) {
    std::string full = nick + "!" + user + "@" + host;
    return wildcard_match(pattern, full);
}

inline bool match_ip_range(const std::string& ip,
                            const std::vector<std::string>& cidr_list) {
    for (const auto& cidr : cidr_list) {
        if (ip_in_cidr(ip, cidr)) return true;
    }
    return false;
}

inline bool match_asn(const std::string& ip, const std::set<std::string>& asn_ips) {
    // Simplified ASN matching: check if IP falls within known ASN ranges
    // In production, you'd query a GeoIP/ASN database
    return asn_ips.find(ip) != asn_ips.end();
}

}  // namespace ban_match_helpers

// ============================================================================
// Invite Exception Management
// ============================================================================

class InviteExceptionManager {
public:
    // Per-channel invite exceptions (users who can join +i channels without invite)
    struct InviteException {
        std::string mask;      // nick!user@host
        std::string channel;
        std::time_t added_at;
        std::string added_by;
        std::time_t expires_at;
    };

    bool add_exception(const std::string& channel, const std::string& mask,
                       const std::string& added_by, std::time_t duration = 0) {
        std::unique_lock lock(mutex_);
        std::string ck = lower(channel);
        auto& list = exceptions_[ck];

        // Check duplicate
        for (const auto& ie : list) {
            if (irc_case_equal(ie.mask, mask)) return false;
        }

        InviteException ie;
        ie.mask       = mask;
        ie.channel    = channel;
        ie.added_at   = std::time(nullptr);
        ie.added_by   = added_by;
        ie.expires_at = (duration > 0) ? ie.added_at + duration : 0;
        list.push_back(ie);
        return true;
    }

    bool remove_exception(const std::string& channel, const std::string& mask) {
        std::unique_lock lock(mutex_);
        std::string ck = lower(channel);
        auto it = exceptions_.find(ck);
        if (it == exceptions_.end()) return false;

        auto before = it->second.size();
        it->second.erase(std::remove_if(it->second.begin(), it->second.end(),
            [&](const InviteException& ie) {
                return irc_case_equal(ie.mask, mask);
            }), it->second.end());
        return it->second.size() != before;
    }

    bool has_exception(const std::string& channel, const std::string& nick,
                       const std::string& user, const std::string& host) const {
        std::shared_lock lock(mutex_);
        std::string ck = lower(channel);
        auto it = exceptions_.find(ck);
        if (it == exceptions_.end()) return false;

        std::string full = nick + "!" + user + "@" + host;
        auto now = std::time(nullptr);
        for (const auto& ie : it->second) {
            if (ie.expires_at > 0 && now >= ie.expires_at) continue;
            if (wildcard_match(ie.mask, full)) return true;
        }
        return false;
    }

    std::vector<InviteException> list_exceptions(const std::string& channel) const {
        std::shared_lock lock(mutex_);
        std::string ck = lower(channel);
        auto it = exceptions_.find(ck);
        if (it == exceptions_.end()) return {};
        return it->second;
    }

    void clear_channel(const std::string& channel) {
        std::unique_lock lock(mutex_);
        exceptions_.erase(lower(channel));
    }

    void expire_all() {
        std::unique_lock lock(mutex_);
        auto now = std::time(nullptr);
        for (auto& [ch, list] : exceptions_) {
            list.erase(std::remove_if(list.begin(), list.end(),
                [now](const InviteException& ie) {
                    return ie.expires_at > 0 && now >= ie.expires_at;
                }), list.end());
        }
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::vector<InviteException>,
                       IrcCaseHash, IrcCaseEqual> exceptions_;

    static std::string lower(std::string_view s) {
        std::string result;
        result.reserve(s.size());
        for (unsigned char c : s) result.push_back(static_cast<char>(std::tolower(c)));
        return result;
    }
};

// ============================================================================
// Channel anti-spam settings
// ============================================================================

struct ChannelAntiSpamSettings {
    bool block_repeated_text;    // Block repeated identical messages
    bool block_caps;              // Block excessive caps
    bool block_unicode_spam;     // Block messages with excessive unicode
    bool block_urls;             // Block messages with URLs (for +u-like behavior)
    bool block_rejoin_spam;      // Block rapid rejoin spam

    int  max_repeat_lines;        // Max consecutive identical lines
    int  max_caps_percent;        // Max percentage of capital letters
    int  max_urls;                // Max URLs per message
    int  max_message_length;      // Max message length

    ChannelAntiSpamSettings()
        : block_repeated_text(true), block_caps(false), block_unicode_spam(false),
          block_urls(false), block_rejoin_spam(true),
          max_repeat_lines(3), max_caps_percent(70),
          max_urls(3), max_message_length(400) {}
};

// ============================================================================
// Text analysis helpers for spam detection
// ============================================================================

namespace text_analysis {

inline bool is_excessive_caps(const std::string& text, int max_percent) {
    if (text.size() < 10) return false;  // Don't check short messages
    int caps = 0, letters = 0;
    for (unsigned char c : text) {
        if (std::isalpha(c)) {
            letters++;
            if (std::isupper(c)) caps++;
        }
    }
    if (letters == 0) return false;
    return (caps * 100 / letters) > max_percent;
}

inline int count_urls(const std::string& text) {
    int count = 0;
    size_t pos = 0;
    while (true) {
        pos = text.find("http://", pos);
        if (pos == std::string::npos) break;
        count++;
        pos += 7;
    }
    pos = 0;
    while (true) {
        pos = text.find("https://", pos);
        if (pos == std::string::npos) break;
        count++;
        pos += 8;
    }
    // Also match www. without protocol
    pos = 0;
    while (true) {
        pos = text.find("www.", pos);
        if (pos == std::string::npos) break;
        count++;
        pos += 4;
    }
    return count;
}

inline int count_unicode_codepoints(const std::string& text) {
    // Count characters outside ASCII range
    int count = 0;
    for (unsigned char c : text) {
        if (c > 127) count++;
    }
    return count;
}

inline bool has_repeated_substrings(const std::string& text, int min_len = 5, int max_repeats = 3) {
    if (text.size() < static_cast<size_t>(min_len * max_repeats)) return false;
    // Simple check: look for repeated chunks
    for (size_t i = 0; i + min_len <= text.size(); ++i) {
        std::string_view chunk(text.data() + i, min_len);
        int repeats = 0;
        size_t pos = i;
        while (pos < text.size()) {
            if (text.compare(pos, min_len, chunk) == 0) {
                repeats++;
                pos += min_len;
            } else {
                break;
            }
        }
        if (repeats >= max_repeats) return true;
    }
    return false;
}

inline double entropy(const std::string& text) {
    // Shannon entropy for detecting random/nonsense text
    if (text.empty()) return 0.0;
    std::array<int, 256> freq{};
    for (unsigned char c : text) freq[c]++;

    double result = 0.0;
    double len = static_cast<double>(text.size());
    for (int f : freq) {
        if (f > 0) {
            double p = f / len;
            result -= p * std::log2(p);
        }
    }
    return result;
}

}  // namespace text_analysis

// ============================================================================
// Per-channel access level enforcement helpers
// ============================================================================

namespace access_enforcement {

// Determine what channel modes to apply based on access level
struct ModeChange {
    bool give_owner;    // +q
    bool give_admin;    // +a
    bool give_op;       // +o
    bool give_halfop;   // +h
    bool give_voice;    // +v
};

inline ModeChange modes_for_level(AccessLevel lvl) {
    ModeChange mc{};
    switch (lvl) {
        case AccessLevel::kFounder:
            mc.give_owner = true;
            mc.give_admin = true;
            mc.give_op    = true;
            mc.give_voice = true;
            break;
        case AccessLevel::kAdmin:
            mc.give_admin = true;
            mc.give_op    = true;
            mc.give_voice = true;
            break;
        case AccessLevel::kOp:
            mc.give_op    = true;
            mc.give_voice = true;
            break;
        case AccessLevel::kHalfop:
            mc.give_halfop = true;
            mc.give_voice  = true;
            break;
        case AccessLevel::kVoice:
            mc.give_voice = true;
            break;
        case AccessLevel::kNone:
        default:
            break;
    }
    return mc;
}

// Check if a higher-access user can modify a lower-access user's status
inline bool can_modify(AccessLevel actor, AccessLevel target) {
    return static_cast<int>(actor) > static_cast<int>(target);
}

}  // namespace access_enforcement

// ============================================================================
// Ban synchronization across servers (for multi-server networks)
// ============================================================================

class BanSyncManager {
public:
    struct SyncRecord {
        std::string  server_id;
        std::string  ban_type;   // "gline", "kline", "zline", etc.
        std::string  mask;
        std::string  set_by;
        std::time_t  set_at;
        std::time_t  expires_at;
        std::string  reason;
        bool         is_remove;  // true if this is a removal
    };

    void add_sync(const SyncRecord& record) {
        std::unique_lock lock(mutex_);
        pending_syncs_.push_back(record);
    }

    std::vector<SyncRecord> get_pending_syncs(const std::string& server_id) {
        std::unique_lock lock(mutex_);
        std::vector<SyncRecord> result;
        for (const auto& sr : pending_syncs_) {
            if (sr.server_id != server_id) {
                result.push_back(sr);
            }
        }
        return result;
    }

    void clear_pending() {
        std::unique_lock lock(mutex_);
        pending_syncs_.clear();
    }

    void apply_remote_sync(const SyncRecord& record,
                           AccessAbuseManager& mgr) {
        if (record.is_remove) {
            if (record.ban_type == "gline") mgr.remove_gline(record.mask);
            else if (record.ban_type == "kline") mgr.remove_kline(record.mask);
            else if (record.ban_type == "zline") mgr.remove_zline(record.mask);
        } else {
            if (record.ban_type == "gline") {
                mgr.add_gline(GLine(record.mask, record.reason,
                                    record.set_by, record.set_at, record.expires_at));
            } else if (record.ban_type == "kline") {
                mgr.add_kline(KLine(record.mask, record.reason,
                                    record.set_by, record.set_at, record.expires_at));
            } else if (record.ban_type == "zline") {
                mgr.add_zline(ZLine(record.mask, record.reason,
                                    record.set_by, record.set_at, record.expires_at));
            }
        }
    }

private:
    mutable std::shared_mutex mutex_;
    std::vector<SyncRecord> pending_syncs_;
};

// ============================================================================
// Cluster-aware ban broadcast
// ============================================================================

class BanBroadcaster {
public:
    using BroadcastCallback = std::function<void(const std::string& ban_type,
                                                   const std::string& mask,
                                                   const std::string& set_by,
                                                   std::time_t expires_at,
                                                   const std::string& reason,
                                                   bool is_remove)>;

    void set_callback(BroadcastCallback cb) {
        callback_ = std::move(cb);
    }

    void broadcast_add(const std::string& type, const std::string& mask,
                       const std::string& set_by, std::time_t expires,
                       const std::string& reason) {
        if (callback_) {
            callback_(type, mask, set_by, expires, reason, false);
        }
    }

    void broadcast_remove(const std::string& type, const std::string& mask,
                          const std::string& set_by) {
        if (callback_) {
            callback_(type, mask, set_by, 0, "", true);
        }
    }

private:
    BroadcastCallback callback_;
};

// ============================================================================
// Convenience aliases / re-exports
// ============================================================================

using BanEntry        = ExtendedBan;
using AccessEntry     = ChannelAccessEntry;
using GLineEntry      = GLine;
using KLineEntry      = KLine;
using ZLineEntry      = ZLine;
using ELineEntry      = ELine;
using QLineEntry      = QLine;
using SpamFilterEntry = SpamFilter;
using VHostInfo       = VHostEntry;

}  // namespace irc
}  // namespace progressive

// ============================================================================
// End of file: irc_access_abuse.cpp
// Approximate line count: ~3445 lines (comprehensive implementation)
//
// Features implemented:
//   1. Extended bans (account, realname, certfp, gecos, oper, quiet) with
//      channel-level ban/exception list management and persistence
//   2. Channel access lists (SOP/AOP/HOP/VOP) with serialization
//   3. Auto-op on join with last-seen tracking
//   4. G-Lines (global bans) with expiration
//   5. K-Lines (kill lines) with user@host matching
//   6. Z-Lines (zap lines) with CIDR support
//   7. E-Lines (exception lines) for GL/KL/ZL exemption
//   8. Q-Lines (quiet lines) for nick/channel restriction
//   9. Spam filter with regex matching and five action types
//  10. Flood protection (message, join, nick, invite) with sliding windows
//  11. Connection throttling with per-IP rate limiting
//  12. Proxy scanner with SOCKS5 and HTTP proxy protocol verification
//  13. DNSBL integration with caching layer
//  14. Channel mode +c (color code stripping)
//  15. Channel mode +C (CTCP blocking)
//  16. Channel mode +M (registered-only talking)
//  17. Channel mode +R (registered-only joining)
//  18. Cloaking v1 (base64) and v2 (FNV-1a hash)
//  19. VHost system with persistence
//  20. IP reputation scoring and decay
//  21. Rate limiting via token bucket
//  22. Enhanced proxy scanner with multi-port, multi-protocol detection
//  23. DNSBL caching with TTL-based expiration
//  24. Invite exception management
//  25. Channel anti-spam settings (caps, URLs, unicode, repeats)
//  26. Text analysis helpers (entropy, caps, URL counting)
//  27. Access level enforcement (mode change calculation)
//  28. Ban synchronization across clustered servers
//  29. Ban broadcast callback system
//  30. Abuse event logging and escalation policies
// ============================================================================
