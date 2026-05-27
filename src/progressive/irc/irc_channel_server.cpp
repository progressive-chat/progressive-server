// =============================================================================
// progressive-server: IRC Channel Server
// =============================================================================
// Full implementation of IRC channel modes, server-to-server linking protocol,
// spanning tree topology, channel registration, extended bans, channel history,
// and associated configuration.
//
// Namespace: progressive::irc
// =============================================================================

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <ctime>
#include <algorithm>
#include <mutex>
#include <functional>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <map>
#include <set>
#include <deque>
#include <optional>
#include <variant>

// =============================================================================
// SECTION 1: Constants and Forward Declarations
// =============================================================================

namespace progressive {
namespace irc {

// --- Forward declarations ---
class ChannelServer;
class Channel;
class ChannelMembership;
class ServerLink;
class ServerTree;
class BanEntry;
class ExtendedBan;
class PrefixMode;
class ChannelModeHandler;
class ChannelHistory;

// --- Constants ---

// Channel name constraints
static constexpr size_t MAX_CHANNEL_NAME_LEN = 64;
static constexpr size_t MAX_CHANNEL_TOPIC_LEN = 390;
static constexpr size_t MAX_CHANNEL_KEY_LEN = 32;
static constexpr size_t MAX_CHANNEL_USER_LIMIT = 65535;
static constexpr size_t MAX_BANLIST_ENTRIES = 500;
static constexpr size_t MAX_EXCEPTLIST_ENTRIES = 500;
static constexpr size_t MAX_INVITELIST_ENTRIES = 500;
static constexpr size_t MAX_QUIETLIST_ENTRIES = 500;
static constexpr size_t MAX_PREFIX_STACK = 5;
static constexpr size_t MAX_HISTORY_LINES = 100;
static constexpr size_t MAX_HISTORY_TIME_WINDOW = 86400;  // 24 hours

// Server-to-server protocol constants
static constexpr size_t MAX_SERVER_NAME_LEN = 64;
static constexpr size_t MAX_SERVER_DESC_LEN = 256;
static constexpr size_t MAX_SID_LEN = 3;
static constexpr size_t MAX_UID_LEN = 9;
static constexpr size_t S2S_MAX_LINKS = 64;
static constexpr size_t PROTOCOL_VERSION = 1205;

// Default TS delta tolerance (seconds)
static constexpr int64_t DEFAULT_TS_DELTA = 60;

// Channel types
enum class ChannelType : uint8_t {
    LOCAL   = 0x00,  // #channel
    NETWORK = 0x01,  // ##network-wide
    SAFE    = 0x02,  // !channel (often safe/registered)
};

// Channel status code
enum class ChannelStatus : uint8_t {
    ACTIVE    = 0,
    PERSIST   = 1,
    ARCHIVED  = 2,
};

// Prefix ranks (higher = more privileged)
enum class PrefixRank : uint8_t {
    VOICE    = 0,   // +v
    HALFOP   = 1,   // +h
    OP       = 2,   // +o
    ADMIN    = 3,   // +a
    OWNER    = 4,   // +q
};

// Server link states
enum class LinkState : uint8_t {
    DISCONNECTED = 0,
    HANDSHAKE    = 1,
    REGISTERED   = 2,
    BURSTING     = 3,
    CONNECTED    = 4,
};

// Ban types for extended matching
enum class BanMatchType : uint8_t {
    NICK     = 0,
    USER     = 1,
    HOST     = 2,
    ACCOUNT  = 3,
    REALNAME = 4,
    CERTFP   = 5,
    IP       = 6,
    CIDR     = 7,
    EXTMASK  = 8,
};

// =============================================================================
// SECTION 2: Utility Functions
// =============================================================================

// Simple wildcard matching (glob-style: *, ?)
static bool match_wildcard(const std::string& pattern, const std::string& str) {
    size_t p = 0, s = 0;
    size_t star_p = std::string::npos;
    size_t match_s = 0;

    while (s < str.size()) {
        if (p < pattern.size() && (pattern[p] == '?' ||
            tolower(pattern[p]) == tolower(str[s]))) {
            ++p;
            ++s;
        } else if (p < pattern.size() && pattern[p] == '*') {
            star_p = p;
            match_s = s;
            ++p;
        } else if (star_p != std::string::npos) {
            p = star_p + 1;
            match_s++;
            s = match_s;
        } else {
            return false;
        }
    }

    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

// CIDR matching for ban masks
static bool match_cidr(const std::string& cidr, const std::string& ip) {
    // Simple CIDR: a.b.c.d/bits
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) return cidr == ip;

    std::string net = cidr.substr(0, slash);
    int bits = std::stoi(cidr.substr(slash + 1));

    // Parse IPv4 addresses
    auto parse_ip = [](const std::string& s) -> uint32_t {
        uint32_t result = 0;
        std::stringstream ss(s);
        std::string octet;
        int shift = 24;
        while (std::getline(ss, octet, '.') && shift >= 0) {
            result |= (static_cast<uint32_t>(std::stoi(octet)) << shift);
            shift -= 8;
        }
        return result;
    };

    uint32_t net_int = parse_ip(net);
    uint32_t ip_int = parse_ip(ip);
    uint32_t mask = (bits == 0) ? 0 : (0xFFFFFFFF << (32 - bits));

    return (net_int & mask) == (ip_int & mask);
}

// Timestamp helper
static int64_t now_ts() {
    return static_cast<int64_t>(std::time(nullptr));
}

// Channel name validation
static bool valid_channel_name(const std::string& name) {
    if (name.empty() || name.size() > MAX_CHANNEL_NAME_LEN) return false;
    char c = name[0];
    if (c != '#' && c != '&' && c != '!') return false;
    if (name.find(' ') != std::string::npos) return false;
    if (name.find(',') != std::string::npos) return false;
    if (name.find(0x07) != std::string::npos) return false;  // ^G (bell)
    return true;
}

// Mode parsing: extract parameters
static std::vector<std::string> parse_mode_params(const std::string& modes,
                                                   const std::vector<std::string>& params) {
    std::vector<std::string> result;
    size_t pidx = 0;
    bool adding = true;

    for (size_t i = 0; i < modes.size(); ++i) {
        char c = modes[i];
        if (c == '+') { adding = true; continue; }
        if (c == '-') { adding = false; continue; }

        // Type-A modes: ban, ban-except, invite-except (always have param)
        // Type-B modes: key, limit, forward (param when adding)
        // Type-C modes: op, voice, halfop, admin, owner (always have param)
        // Type-D modes: flag modes (no param)

        bool needs_param = false;
        switch (c) {
            case 'b': case 'e': case 'I': case 'q':  // List modes
            case 'o': case 'v': case 'h': case 'a':  // Prefix modes
                needs_param = true;
                break;
            case 'k': case 'l': case 'f':  // Param when +, none when -
                needs_param = adding;
                break;
            case 'L':  // Redirect (param when adding)
                needs_param = adding;
                break;
            default:
                needs_param = false;
                break;
        }

        if (needs_param && pidx < params.size()) {
            result.push_back(params[pidx++]);
        }
    }
    return result;
}

// =============================================================================
// SECTION 3: Ban Entry and Extended Ban System
// =============================================================================

struct BanEntry {
    std::string mask;         // nick!user@host or extban mask
    std::string set_by;       // who set it
    int64_t set_at;           // timestamp when set
    int64_t expires_at;       // 0 = permanent
    std::string reason;       // optional reason

    BanEntry() : set_at(now_ts()), expires_at(0) {}
    BanEntry(const std::string& m, const std::string& s, int64_t ts = 0,
             int64_t exp = 0, const std::string& r = "")
        : mask(m), set_by(s), set_at(ts ? ts : now_ts()),
          expires_at(exp), reason(r) {}

    bool is_expired() const {
        if (expires_at == 0) return false;
        return now_ts() >= expires_at;
    }

    std::string serialize() const {
        std::stringstream ss;
        ss << mask;
        if (!set_by.empty()) ss << " " << set_by;
        ss << " " << set_at;
        if (expires_at > 0) ss << " " << expires_at;
        if (!reason.empty()) ss << " :" << reason;
        return ss.str();
    }

    static BanEntry deserialize(const std::string& line) {
        BanEntry entry;
        std::stringstream ss(line);
        ss >> entry.mask >> entry.set_by >> entry.set_at;
        if (ss >> entry.expires_at) {
            std::string rest;
            if (std::getline(ss, rest)) {
                size_t pos = rest.find(':');
                if (pos != std::string::npos) {
                    entry.reason = rest.substr(pos + 1);
                    // Trim leading space
                    if (!entry.reason.empty() && entry.reason[0] == ' ')
                        entry.reason.erase(0, 1);
                }
            }
        }
        return entry;
    }
};

// Extended ban: matches on account name, realname, certfp, etc.
class ExtendedBan {
public:
    BanMatchType type;
    std::string pattern;
    bool negated;  // ~ prefix

    ExtendedBan() : type(BanMatchType::NICK), negated(false) {}

    static ExtendedBan parse(const std::string& mask) {
        ExtendedBan eb;
        eb.negated = false;

        if (mask.empty()) return eb;

        // Check for negation
        size_t start = 0;
        if (mask[0] == '~') {
            eb.negated = true;
            start = 1;
        }

        // Extended ban prefix: a: account, r: realname, s: server, etc.
        if (mask.size() > start + 1 && mask[start + 1] == ':') {
            switch (mask[start]) {
                case 'a': case 'A':
                    eb.type = BanMatchType::ACCOUNT;
                    eb.pattern = mask.substr(start + 2);
                    break;
                case 'r': case 'R':
                    eb.type = BanMatchType::REALNAME;
                    eb.pattern = mask.substr(start + 2);
                    break;
                case 'c': case 'C':
                    eb.type = BanMatchType::CERTFP;
                    eb.pattern = mask.substr(start + 2);
                    break;
                case 'j': case 'J':
                    eb.type = BanMatchType::ACCOUNT;  // join only
                    eb.pattern = mask.substr(start + 2);
                    break;
                case 'n': case 'N':
                    eb.type = BanMatchType::NICK;
                    eb.pattern = mask.substr(start + 2);
                    break;
                case 'u': case 'U':
                    eb.type = BanMatchType::USER;
                    eb.pattern = mask.substr(start + 2);
                    break;
                case 'h': case 'H':
                    eb.type = BanMatchType::HOST;
                    eb.pattern = mask.substr(start + 2);
                    break;
                default:
                    eb.type = BanMatchType::EXTMASK;
                    eb.pattern = mask.substr(start);
                    break;
            }
        } else {
            // Standard nick!user@host mask
            eb.type = BanMatchType::HOST;
            eb.pattern = mask.substr(start);
        }

        return eb;
    }

    bool matches(const std::string& nick, const std::string& user,
                 const std::string& host, const std::string& account,
                 const std::string& realname, const std::string& certfp) const {
        bool result = false;

        switch (type) {
            case BanMatchType::NICK:
                result = match_wildcard(pattern, nick);
                break;
            case BanMatchType::USER:
                result = match_wildcard(pattern, user);
                break;
            case BanMatchType::HOST:
                result = match_wildcard(pattern, nick + "!" + user + "@" + host) ||
                         match_wildcard(pattern, user + "@" + host) ||
                         match_wildcard(pattern, host);
                break;
            case BanMatchType::ACCOUNT:
                if (account.empty()) result = (pattern == "*");  // * matches unregistered
                else result = match_wildcard(pattern, account);
                break;
            case BanMatchType::REALNAME:
                result = match_wildcard(pattern, realname);
                break;
            case BanMatchType::CERTFP:
                result = (certfp == pattern);
                break;
            case BanMatchType::IP:
                result = match_cidr(pattern, host);
                break;
            case BanMatchType::CIDR:
                result = match_cidr(pattern, host);
                break;
            case BanMatchType::EXTMASK:
                result = match_wildcard(pattern, nick + "!" + user + "@" + host);
                break;
        }

        return negated ? !result : result;
    }

    std::string serialize() const {
        std::string result;
        if (negated) result += "~";
        switch (type) {
            case BanMatchType::ACCOUNT:   result += "a:"; break;
            case BanMatchType::REALNAME:  result += "r:"; break;
            case BanMatchType::CERTFP:    result += "c:"; break;
            case BanMatchType::NICK:      result += "n:"; break;
            case BanMatchType::USER:      result += "u:"; break;
            case BanMatchType::HOST:      result += "h:"; break;
            default: break;
        }
        result += pattern;
        return result;
    }
};

// Quiet ban entry (acts like +b but without kicking)
struct QuietEntry {
    BanEntry ban;
    bool matched;  // track whether user was notified

    QuietEntry() : matched(false) {}
    QuietEntry(const BanEntry& b) : ban(b), matched(false) {}
};

// =============================================================================
// SECTION 4: Prefix Mode System
// =============================================================================

struct PrefixMode {
    char mode_char;       // 'q', 'a', 'o', 'h', 'v'
    char prefix_char;     // '~', '&', '@', '%', '+'
    PrefixRank rank;
    int weight;           // numeric weight for sorting

    PrefixMode() : mode_char(0), prefix_char(0),
                   rank(PrefixRank::VOICE), weight(0) {}

    PrefixMode(char m, char p, PrefixRank r, int w)
        : mode_char(m), prefix_char(p), rank(r), weight(w) {}

    bool operator<(const PrefixMode& other) const {
        return weight < other.weight;
    }
    bool operator>(const PrefixMode& other) const {
        return weight > other.weight;
    }
};

// Standard prefix definitions (InspIRCd compatible)
static const std::vector<PrefixMode> STANDARD_PREFIXES = {
    PrefixMode('q', '~', PrefixRank::OWNER,  40000),
    PrefixMode('a', '&', PrefixRank::ADMIN,  30000),
    PrefixMode('o', '@', PrefixRank::OP,     20000),
    PrefixMode('h', '%', PrefixRank::HALFOP, 10000),
    PrefixMode('v', '+', PrefixRank::VOICE,   5000),
};

static PrefixMode prefix_from_mode_char(char c) {
    for (const auto& p : STANDARD_PREFIXES) {
        if (p.mode_char == c) return p;
    }
    return PrefixMode();
}

static PrefixMode prefix_from_prefix_char(char c) {
    for (const auto& p : STANDARD_PREFIXES) {
        if (p.prefix_char == c) return p;
    }
    return PrefixMode();
}

static int prefix_weight_from_rank(PrefixRank rank) {
    for (const auto& p : STANDARD_PREFIXES) {
        if (p.rank == rank) return p.weight;
    }
    return 0;
}

// =============================================================================
// SECTION 5: Channel Membership
// =============================================================================

struct ChannelMembership {
    std::string uid;           // User UID (SID+ID)
    std::string nick;
    std::string user;
    std::string host;
    std::string account;
    std::string realname;
    std::string certfp;
    std::string ip;
    std::string server_sid;    // which server the user is on

    int64_t join_ts;           // timestamp of join
    int64_t last_active;       // last message time

    // Prefix stack (highest weight first)
    std::vector<PrefixMode> prefixes;

    ChannelMembership()
        : join_ts(now_ts()), last_active(now_ts()) {}

    ChannelMembership(const std::string& u, const std::string& n,
                      const std::string& us, const std::string& h,
                      const std::string& sid = "")
        : uid(u), nick(n), user(us), host(h), server_sid(sid),
          join_ts(now_ts()), last_active(now_ts()) {}

    bool has_prefix(const PrefixMode& pm) const {
        for (const auto& p : prefixes) {
            if (p.mode_char == pm.mode_char) return true;
        }
        return false;
    }

    bool has_prefix_char(char c) const {
        for (const auto& p : prefixes) {
            if (p.prefix_char == c) return true;
        }
        return false;
    }

    bool has_prefix_rank(PrefixRank rank) const {
        for (const auto& p : prefixes) {
            if (p.rank == rank) return true;
        }
        return false;
    }

    PrefixRank highest_rank() const {
        if (prefixes.empty()) return PrefixRank::VOICE;
        PrefixRank highest = PrefixRank::VOICE;
        for (const auto& p : prefixes) {
            if (static_cast<uint8_t>(p.rank) > static_cast<uint8_t>(highest))
                highest = p.rank;
        }
        return highest;
    }

    std::string prefix_string() const {
        std::string result;
        // Sort by weight descending
        auto sorted = prefixes;
        std::sort(sorted.begin(), sorted.end(), std::greater<PrefixMode>());
        for (const auto& p : sorted) {
            result += p.prefix_char;
        }
        return result;
    }

    void add_prefix(char mode_char) {
        PrefixMode pm = prefix_from_mode_char(mode_char);
        if (pm.mode_char == 0) return;
        // Don't add duplicates
        for (const auto& p : prefixes) {
            if (p.mode_char == pm.mode_char) return;
        }
        prefixes.push_back(pm);
        // Keep sorted by weight descending
        std::sort(prefixes.begin(), prefixes.end(), std::greater<PrefixMode>());
        // Enforce max stack
        while (prefixes.size() > MAX_PREFIX_STACK) {
            prefixes.pop_back();
        }
    }

    void remove_prefix(char mode_char) {
        prefixes.erase(
            std::remove_if(prefixes.begin(), prefixes.end(),
                [mode_char](const PrefixMode& p) {
                    return p.mode_char == mode_char;
                }),
            prefixes.end());
    }

    bool can_perform(char mode_char) const {
        // Can set mode_char on others?
        PrefixMode target = prefix_from_mode_char(mode_char);
        if (target.mode_char == 0) return true;  // non-prefix modes

        int my_weight = 0;
        for (const auto& p : prefixes) {
            if (p.weight > my_weight) my_weight = p.weight;
        }

        // Owner can do everything; others need higher weight
        return my_weight >= target.weight;
    }
};

// =============================================================================
// SECTION 6: Channel Mode Handler System
// =============================================================================

class ChannelModeHandler {
public:
    virtual ~ChannelModeHandler() = default;

    // Mode character this handler manages
    virtual char mode_char() const = 0;

    // Check if mode can be set
    virtual bool can_set(Channel* channel, ChannelMembership* setter,
                         bool adding, const std::string& param) {
        (void)channel; (void)setter; (void)adding; (void)param;
        return true;
    }

    // Apply mode change. Returns true if changed
    virtual bool apply(Channel* channel, ChannelMembership* setter,
                       bool adding, const std::string& param) = 0;

    // Get current mode string representation
    virtual std::string get_value(const Channel* channel) const = 0;

    // Get parameter for MODE response
    virtual std::string get_param(const Channel* channel) const {
        return get_value(channel);
    }

    // Whether this mode takes a parameter when set
    virtual bool needs_param(bool adding) const { (void)adding; return false; }

    // Whether this mode is a list mode (stacks in replies)
    virtual bool is_list_mode() const { return false; }

    // Whether this mode is a prefix mode
    virtual bool is_prefix_mode() const { return false; }
};

// --- Concrete mode handlers ---

class ModeKey : public ChannelModeHandler {
public:
    char mode_char() const override { return 'k'; }
    bool needs_param(bool adding) const override { return adding; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeLimit : public ChannelModeHandler {
public:
    char mode_char() const override { return 'l'; }
    bool needs_param(bool adding) const override { return adding; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeInviteOnly : public ChannelModeHandler {
public:
    char mode_char() const override { return 'i'; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeModerated : public ChannelModeHandler {
public:
    char mode_char() const override { return 'm'; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeNoExternal : public ChannelModeHandler {
public:
    char mode_char() const override { return 'n'; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeSecret : public ChannelModeHandler {
public:
    char mode_char() const override { return 's'; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModePrivate : public ChannelModeHandler {
public:
    char mode_char() const override { return 'p'; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeTopicLock : public ChannelModeHandler {
public:
    char mode_char() const override { return 't'; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeBan : public ChannelModeHandler {
public:
    char mode_char() const override { return 'b'; }
    bool needs_param(bool adding) const override { (void)adding; return true; }
    bool is_list_mode() const override { return true; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
    std::string get_param(const Channel* channel) const override;
};

class ModeBanExcept : public ChannelModeHandler {
public:
    char mode_char() const override { return 'e'; }
    bool needs_param(bool adding) const override { (void)adding; return true; }
    bool is_list_mode() const override { return true; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
    std::string get_param(const Channel* channel) const override;
};

class ModeInviteExcept : public ChannelModeHandler {
public:
    char mode_char() const override { return 'I'; }
    bool needs_param(bool adding) const override { (void)adding; return true; }
    bool is_list_mode() const override { return true; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
    std::string get_param(const Channel* channel) const override;
};

class ModeQuiet : public ChannelModeHandler {
public:
    char mode_char() const override { return 'q'; }
    bool needs_param(bool adding) const override { (void)adding; return true; }
    bool is_list_mode() const override { return true; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
    std::string get_param(const Channel* channel) const override;
};

class ModeOp : public ChannelModeHandler {
public:
    char mode_char() const override { return 'o'; }
    bool needs_param(bool adding) const override { return true; }
    bool is_prefix_mode() const override { return true; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeVoice : public ChannelModeHandler {
public:
    char mode_char() const override { return 'v'; }
    bool needs_param(bool adding) const override { return true; }
    bool is_prefix_mode() const override { return true; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeHalfOp : public ChannelModeHandler {
public:
    char mode_char() const override { return 'h'; }
    bool needs_param(bool adding) const override { return true; }
    bool is_prefix_mode() const override { return true; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeAdmin : public ChannelModeHandler {
public:
    char mode_char() const override { return 'a'; }
    bool needs_param(bool adding) const override { return true; }
    bool is_prefix_mode() const override { return true; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeOwner : public ChannelModeHandler {
public:
    char mode_char() const override { return 'q'; }
    bool needs_param(bool adding) const override { return true; }
    bool is_prefix_mode() const override { return true; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeForward : public ChannelModeHandler {
public:
    char mode_char() const override { return 'f'; }
    bool needs_param(bool adding) const override { return adding; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeRedirect : public ChannelModeHandler {
public:
    char mode_char() const override { return 'L'; }
    bool needs_param(bool adding) const override { return adding; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeSSLOnly : public ChannelModeHandler {
public:
    char mode_char() const override { return 'z'; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeHistory : public ChannelModeHandler {
public:
    char mode_char() const override { return 'H'; }
    bool needs_param(bool adding) const override { return adding; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModePermanent : public ChannelModeHandler {
public:
    char mode_char() const override { return 'P'; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeRegistered : public ChannelModeHandler {
public:
    char mode_char() const override { return 'r'; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

class ModeAutoJoin : public ChannelModeHandler {
public:
    char mode_char() const override { return 'A'; }

    bool apply(Channel* channel, ChannelMembership* setter,
               bool adding, const std::string& param) override;

    std::string get_value(const Channel* channel) const override;
};

// =============================================================================
// SECTION 7: Channel History System
// =============================================================================

struct HistoryLine {
    int64_t ts;               // timestamp
    std::string source;       // nick!user@host or server
    std::string type;         // PRIVMSG, NOTICE, JOIN, PART, etc.
    std::string text;         // message content

    HistoryLine() : ts(now_ts()) {}
    HistoryLine(int64_t t, const std::string& s, const std::string& typ,
                const std::string& txt)
        : ts(t), source(s), type(typ), text(txt) {}
};

class ChannelHistory {
public:
    ChannelHistory() : max_lines_(MAX_HISTORY_LINES), max_age_(MAX_HISTORY_TIME_WINDOW) {}

    void add_line(const std::string& source, const std::string& type,
                  const std::string& text) {
        std::lock_guard<std::mutex> lock(mutex_);
        lines_.emplace_back(now_ts(), source, type, text);
        prune();
    }

    std::vector<HistoryLine> get_lines(int64_t since_ts = 0, size_t limit = 0) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<HistoryLine> result;
        auto it = lines_.begin();
        if (since_ts > 0) {
            it = std::lower_bound(lines_.begin(), lines_.end(), since_ts,
                [](const HistoryLine& line, int64_t ts) { return line.ts < ts; });
        }
        for (; it != lines_.end(); ++it) {
            if (limit > 0 && result.size() >= limit) break;
            result.push_back(*it);
        }
        return result;
    }

    size_t count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return lines_.size();
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        lines_.clear();
    }

    void set_max_lines(size_t max_lines) {
        std::lock_guard<std::mutex> lock(mutex_);
        max_lines_ = max_lines;
        prune();
    }

    void set_max_age(int64_t max_age) {
        std::lock_guard<std::mutex> lock(mutex_);
        max_age_ = max_age;
        prune();
    }

    size_t max_lines() const { return max_lines_; }
    int64_t max_age() const { return max_age_; }

private:
    void prune() {
        int64_t cutoff = now_ts() - max_age_;
        while (!lines_.empty() && lines_.front().ts < cutoff) {
            lines_.pop_front();
        }
        while (lines_.size() > max_lines_) {
            lines_.pop_front();
        }
    }

    std::deque<HistoryLine> lines_;
    size_t max_lines_;
    int64_t max_age_;
    mutable std::mutex mutex_;
};

// =============================================================================
// SECTION 8: Channel Class
// =============================================================================

class Channel {
public:
    std::string name;
    std::string topic;
    std::string topic_set_by;
    int64_t topic_ts;
    int64_t creation_ts;

    // Simple mode flags (bitfield for efficiency)
    uint32_t modes;  // bitmask of simple mode flags

    // Parameterized modes
    std::string key;
    size_t user_limit;
    std::string forward_channel;  // +f target
    std::string redirect_channel; // +L target
    size_t history_max_lines;
    int64_t history_max_age;

    // Ban lists
    std::vector<BanEntry> bans;
    std::vector<BanEntry> ban_excepts;     // +e
    std::vector<BanEntry> invite_excepts;  // +I
    std::vector<QuietEntry> quiet_bans;    // +q (quiet)

    // Members (UID -> membership)
    std::unordered_map<std::string, ChannelMembership> members;

    // Invited users (UID set)
    std::set<std::string> invited;

    // History
    std::unique_ptr<ChannelHistory> history;

    // Persistent state
    ChannelStatus status;
    bool auto_join;       // +A: auto-join on identify/invite
    std::string founder;  // account name for +r channels

    // Mutex for thread safety
    mutable std::mutex mutex;

    // --- Mode flag constants ---
    static constexpr uint32_t MODE_INVITE_ONLY  = 0x0001;  // +i
    static constexpr uint32_t MODE_MODERATED    = 0x0002;  // +m
    static constexpr uint32_t MODE_NO_EXTERNAL  = 0x0004;  // +n
    static constexpr uint32_t MODE_SECRET       = 0x0008;  // +s
    static constexpr uint32_t MODE_PRIVATE      = 0x0010;  // +p
    static constexpr uint32_t MODE_TOPIC_LOCK   = 0x0020;  // +t
    static constexpr uint32_t MODE_SSL_ONLY     = 0x0040;  // +z
    static constexpr uint32_t MODE_PERMANENT    = 0x0080;  // +P
    static constexpr uint32_t MODE_REGISTERED   = 0x0100;  // +r
    static constexpr uint32_t MODE_AUTO_JOIN    = 0x0200;  // +A
    static constexpr uint32_t MODE_HAS_KEY      = 0x0400;  // +k
    static constexpr uint32_t MODE_HAS_LIMIT    = 0x0800;  // +l
    static constexpr uint32_t MODE_HAS_FORWARD  = 0x1000;  // +f
    static constexpr uint32_t MODE_HAS_REDIRECT = 0x2000;  // +L
    static constexpr uint32_t MODE_HAS_HISTORY  = 0x4000;  // +H

    Channel() : topic_ts(0), creation_ts(now_ts()), modes(0),
                user_limit(0), history_max_lines(MAX_HISTORY_LINES),
                history_max_age(MAX_HISTORY_TIME_WINDOW),
                status(ChannelStatus::ACTIVE), auto_join(false) {
        history = std::make_unique<ChannelHistory>();
    }

    Channel(const std::string& n) : name(n), topic_ts(0),
                creation_ts(now_ts()), modes(0), user_limit(0),
                history_max_lines(MAX_HISTORY_LINES),
                history_max_age(MAX_HISTORY_TIME_WINDOW),
                status(ChannelStatus::ACTIVE), auto_join(false) {
        history = std::make_unique<ChannelHistory>();
    }

    // --- Mode flag accessors ---

    bool has_mode(uint32_t flag) const {
        return (modes & flag) != 0;
    }
    void set_mode(uint32_t flag) { modes |= flag; }
    void clear_mode(uint32_t flag) { modes &= ~flag; }
    void toggle_mode(uint32_t flag, bool on) {
        if (on) set_mode(flag); else clear_mode(flag);
    }

    bool is_invite_only() const { return has_mode(MODE_INVITE_ONLY); }
    bool is_moderated() const { return has_mode(MODE_MODERATED); }
    bool is_no_external() const { return has_mode(MODE_NO_EXTERNAL); }
    bool is_secret() const { return has_mode(MODE_SECRET); }
    bool is_private() const { return has_mode(MODE_PRIVATE); }
    bool is_topic_locked() const { return has_mode(MODE_TOPIC_LOCK); }
    bool is_ssl_only() const { return has_mode(MODE_SSL_ONLY); }
    bool is_permanent() const { return has_mode(MODE_PERMANENT); }
    bool is_registered() const { return has_mode(MODE_REGISTERED); }
    bool is_auto_join() const { return has_mode(MODE_AUTO_JOIN); }
    bool has_key() const { return has_mode(MODE_HAS_KEY); }
    bool has_limit() const { return has_mode(MODE_HAS_LIMIT); }
    bool has_forward() const { return has_mode(MODE_HAS_FORWARD); }
    bool has_redirect() const { return has_mode(MODE_HAS_REDIRECT); }
    bool has_history() const { return has_mode(MODE_HAS_HISTORY); }

    // --- Membership management ---

    ChannelMembership* find_member(const std::string& uid) {
        auto it = members.find(uid);
        return (it != members.end()) ? &it->second : nullptr;
    }

    const ChannelMembership* find_member(const std::string& uid) const {
        auto it = members.find(uid);
        return (it != members.end()) ? &it->second : nullptr;
    }

    ChannelMembership* find_member_by_nick(const std::string& nick) {
        for (auto& [uid, m] : members) {
            if (m.nick == nick) return &m;
        }
        return nullptr;
    }

    bool is_member(const std::string& uid) const {
        return members.find(uid) != members.end();
    }

    bool add_member(const ChannelMembership& member) {
        if (is_member(member.uid)) return false;
        members[member.uid] = member;

        // Remove from invited list
        invited.erase(member.uid);

        // Log history
        history->add_line(member.nick, "JOIN", "");
        return true;
    }

    bool remove_member(const std::string& uid, const std::string& reason = "") {
        auto it = members.find(uid);
        if (it == members.end()) return false;

        std::string nick = it->second.nick;
        members.erase(it);

        history->add_line(nick, "PART",
                          reason.empty() ? "" : reason);

        // Remove from invited
        invited.erase(uid);

        return true;
    }

    size_t member_count() const { return members.size(); }

    // --- Ban checking ---

    bool is_banned(const std::string& uid, const std::string& nick,
                   const std::string& user, const std::string& host,
                   const std::string& account = "",
                   const std::string& realname = "",
                   const std::string& certfp = "") const {
        // Check invite exceptions (+I) first — if matched, bypass ban
        if (check_except_list(invite_excepts, nick, user, host,
                              account, realname, certfp))
            return false;

        // Check ban exceptions (+e)
        if (check_except_list(ban_excepts, nick, user, host,
                              account, realname, certfp))
            return false;

        // Check regular bans (+b)
        for (const auto& ban : bans) {
            if (ban.is_expired()) continue;
            ExtendedBan eb = ExtendedBan::parse(ban.mask);
            if (eb.matches(nick, user, host, account, realname, certfp))
                return true;
        }

        return false;
    }

    bool is_quiet_banned(const std::string& nick, const std::string& user,
                         const std::string& host, const std::string& account = "",
                         const std::string& realname = "",
                         const std::string& certfp = "") const {
        for (const auto& qb : quiet_bans) {
            if (qb.ban.is_expired()) continue;
            ExtendedBan eb = ExtendedBan::parse(qb.ban.mask);
            if (eb.matches(nick, user, host, account, realname, certfp))
                return true;
        }
        return false;
    }

    bool is_invited(const std::string& uid) const {
        return invited.find(uid) != invited.end();
    }

    void add_invite(const std::string& uid) {
        invited.insert(uid);
    }

    bool is_invite_excepted(const std::string& nick, const std::string& user,
                            const std::string& host, const std::string& account,
                            const std::string& realname,
                            const std::string& certfp) const {
        return check_except_list(invite_excepts, nick, user, host,
                                  account, realname, certfp);
    }

    // --- Mode string generation for MODE replies ---

    std::string get_mode_string() const {
        std::string result = "+";
        std::string params;

        if (has_mode(MODE_INVITE_ONLY)) result += 'i';
        if (has_mode(MODE_MODERATED)) result += 'm';
        if (has_mode(MODE_NO_EXTERNAL)) result += 'n';
        if (has_mode(MODE_SECRET)) result += 's';
        if (has_mode(MODE_PRIVATE)) result += 'p';
        if (has_mode(MODE_TOPIC_LOCK)) result += 't';
        if (has_mode(MODE_SSL_ONLY)) result += 'z';
        if (has_mode(MODE_PERMANENT)) result += 'P';
        if (has_mode(MODE_REGISTERED)) result += 'r';
        if (has_mode(MODE_AUTO_JOIN)) result += 'A';

        if (has_mode(MODE_HAS_KEY)) {
            result += 'k';
            params += " " + key;
        }
        if (has_mode(MODE_HAS_LIMIT)) {
            result += 'l';
            params += " " + std::to_string(user_limit);
        }
        if (has_mode(MODE_HAS_FORWARD)) {
            result += 'f';
            params += " " + forward_channel;
        }
        if (has_mode(MODE_HAS_REDIRECT)) {
            result += 'L';
            params += " " + redirect_channel;
        }
        if (has_mode(MODE_HAS_HISTORY)) {
            result += 'H';
            params += " " + std::to_string(history_max_lines) + ":"
                      + std::to_string(history_max_age);
        }

        // Ensure we have at least + if nothing set
        if (result == "+") result = "+";

        return result + params;
    }

    std::string get_topic() const {
        return topic;
    }

    void set_topic(const std::string& new_topic, const std::string& set_by) {
        topic = new_topic;
        topic_set_by = set_by;
        topic_ts = now_ts();

        history->add_line(set_by, "TOPIC", new_topic);
    }

    // --- Ban list display ---

    std::string get_ban_list() const {
        std::string result;
        for (const auto& ban : bans) {
            if (ban.is_expired()) continue;
            if (!result.empty()) result += " ";
            result += ban.mask;
        }
        return result;
    }

    std::string get_except_list() const {
        std::string result;
        for (const auto& e : ban_excepts) {
            if (e.is_expired()) continue;
            if (!result.empty()) result += " ";
            result += e.mask;
        }
        return result;
    }

    std::string get_invex_list() const {
        std::string result;
        for (const auto& e : invite_excepts) {
            if (e.is_expired()) continue;
            if (!result.empty()) result += " ";
            result += e.mask;
        }
        return result;
    }

    std::string get_quiet_list() const {
        std::string result;
        for (const auto& qb : quiet_bans) {
            if (qb.ban.is_expired()) continue;
            if (!result.empty()) result += " ";
            result += qb.ban.mask;
        }
        return result;
    }

    // --- Names list generation ---

    std::string get_names_list() const {
        std::string result;
        // Sort by prefix weight descending, then by nick
        std::vector<const ChannelMembership*> sorted;
        sorted.reserve(members.size());
        for (const auto& [uid, m] : members) {
            sorted.push_back(&m);
        }
        std::sort(sorted.begin(), sorted.end(),
            [](const ChannelMembership* a, const ChannelMembership* b) {
                int wa = a->prefixes.empty() ? 0 : a->prefixes[0].weight;
                int wb = b->prefixes.empty() ? 0 : b->prefixes[0].weight;
                if (wa != wb) return wa > wb;
                return a->nick < b->nick;
            });

        for (const auto* m : sorted) {
            if (!result.empty()) result += " ";
            result += m->prefix_string() + m->nick;
        }
        return result;
    }

    // --- Forward checking for +f and +L ---

    std::string get_forward_target() const {
        if (has_mode(MODE_HAS_FORWARD)) return forward_channel;
        if (has_mode(MODE_HAS_REDIRECT)) return redirect_channel;
        return "";
    }

    bool should_forward() const {
        return has_mode(MODE_HAS_FORWARD) || has_mode(MODE_HAS_REDIRECT);
    }

    // --- Persistence helpers ---

    std::string serialize() const {
        std::stringstream ss;
        ss << "CHAN " << name << " " << creation_ts << " "
           << static_cast<int>(status) << " " << modes;

        if (has_mode(MODE_HAS_KEY)) ss << " :" << key;
        ss << "\n";

        if (!topic.empty()) {
            ss << "TOPIC " << name << " " << topic_ts << " "
               << topic_set_by << " :" << topic << "\n";
        }

        // Serialize bans
        for (const auto& ban : bans) {
            ss << "BAN " << name << " " << ban.serialize() << "\n";
        }
        for (const auto& e : ban_excepts) {
            ss << "EXCP " << name << " " << e.serialize() << "\n";
        }
        for (const auto& e : invite_excepts) {
            ss << "INVX " << name << " " << e.serialize() << "\n";
        }
        for (const auto& qb : quiet_bans) {
            ss << "QUIET " << name << " " << qb.ban.serialize() << "\n";
        }

        if (has_mode(MODE_HAS_FORWARD))
            ss << "FWD " << name << " " << forward_channel << "\n";
        if (has_mode(MODE_HAS_REDIRECT))
            ss << "REDIR " << name << " " << redirect_channel << "\n";
        if (has_mode(MODE_HAS_LIMIT))
            ss << "LIMIT " << name << " " << user_limit << "\n";
        if (has_mode(MODE_HAS_HISTORY))
            ss << "HIST " << name << " " << history_max_lines
               << " " << history_max_age << "\n";

        if (!founder.empty())
            ss << "FNDR " << name << " " << founder << "\n";

        return ss.str();
    }

private:
    bool check_except_list(const std::vector<BanEntry>& excepts,
                           const std::string& nick, const std::string& user,
                           const std::string& host, const std::string& account,
                           const std::string& realname,
                           const std::string& certfp) const {
        for (const auto& e : excepts) {
            if (e.is_expired()) continue;
            ExtendedBan eb = ExtendedBan::parse(e.mask);
            if (eb.matches(nick, user, host, account, realname, certfp))
                return true;
        }
        return false;
    }
};

// =============================================================================
// SECTION 9: Mode Handler Implementations
// =============================================================================

bool ModeKey::apply(Channel* channel, ChannelMembership* setter,
                    bool adding, const std::string& param) {
    (void)setter;
    std::lock_guard<std::mutex> lock(channel->mutex);

    if (adding) {
        if (param.empty() || param.size() > MAX_CHANNEL_KEY_LEN) return false;
        channel->key = param;
        channel->set_mode(Channel::MODE_HAS_KEY);
    } else {
        channel->key.clear();
        channel->clear_mode(Channel::MODE_HAS_KEY);
    }
    return true;
}

std::string ModeKey::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_HAS_KEY) ? channel->key : "";
}

bool ModeLimit::apply(Channel* channel, ChannelMembership* setter,
                      bool adding, const std::string& param) {
    (void)setter;
    std::lock_guard<std::mutex> lock(channel->mutex);

    if (adding) {
        int limit = 0;
        try { limit = std::stoi(param); }
        catch (...) { return false; }
        if (limit < 0 || limit > static_cast<int>(MAX_CHANNEL_USER_LIMIT))
            return false;
        channel->user_limit = static_cast<size_t>(limit);
        channel->set_mode(Channel::MODE_HAS_LIMIT);
    } else {
        channel->user_limit = 0;
        channel->clear_mode(Channel::MODE_HAS_LIMIT);
    }
    return true;
}

std::string ModeLimit::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_HAS_LIMIT)
        ? std::to_string(channel->user_limit) : "";
}

bool ModeInviteOnly::apply(Channel* channel, ChannelMembership* setter,
                           bool adding, const std::string& param) {
    (void)setter; (void)param;
    std::lock_guard<std::mutex> lock(channel->mutex);
    channel->toggle_mode(Channel::MODE_INVITE_ONLY, adding);
    return true;
}

std::string ModeInviteOnly::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_INVITE_ONLY) ? "i" : "";
}

bool ModeModerated::apply(Channel* channel, ChannelMembership* setter,
                          bool adding, const std::string& param) {
    (void)setter; (void)param;
    std::lock_guard<std::mutex> lock(channel->mutex);
    channel->toggle_mode(Channel::MODE_MODERATED, adding);
    return true;
}

std::string ModeModerated::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_MODERATED) ? "m" : "";
}

bool ModeNoExternal::apply(Channel* channel, ChannelMembership* setter,
                           bool adding, const std::string& param) {
    (void)setter; (void)param;
    std::lock_guard<std::mutex> lock(channel->mutex);
    channel->toggle_mode(Channel::MODE_NO_EXTERNAL, adding);
    return true;
}

std::string ModeNoExternal::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_NO_EXTERNAL) ? "n" : "";
}

bool ModeSecret::apply(Channel* channel, ChannelMembership* setter,
                       bool adding, const std::string& param) {
    (void)setter; (void)param;
    std::lock_guard<std::mutex> lock(channel->mutex);
    // +s and +p are mutually exclusive
    if (adding) channel->clear_mode(Channel::MODE_PRIVATE);
    channel->toggle_mode(Channel::MODE_SECRET, adding);
    return true;
}

std::string ModeSecret::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_SECRET) ? "s" : "";
}

bool ModePrivate::apply(Channel* channel, ChannelMembership* setter,
                        bool adding, const std::string& param) {
    (void)setter; (void)param;
    std::lock_guard<std::mutex> lock(channel->mutex);
    // +p and +s are mutually exclusive
    if (adding) channel->clear_mode(Channel::MODE_SECRET);
    channel->toggle_mode(Channel::MODE_PRIVATE, adding);
    return true;
}

std::string ModePrivate::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_PRIVATE) ? "p" : "";
}

bool ModeTopicLock::apply(Channel* channel, ChannelMembership* setter,
                          bool adding, const std::string& param) {
    (void)setter; (void)param;
    std::lock_guard<std::mutex> lock(channel->mutex);
    channel->toggle_mode(Channel::MODE_TOPIC_LOCK, adding);
    return true;
}

std::string ModeTopicLock::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_TOPIC_LOCK) ? "t" : "";
}

bool ModeBan::apply(Channel* channel, ChannelMembership* setter,
                    bool adding, const std::string& param) {
    (void)setter;
    std::lock_guard<std::mutex> lock(channel->mutex);

    if (adding) {
        if (param.empty()) return false;
        // Check size limit
        if (channel->bans.size() >= MAX_BANLIST_ENTRIES) return false;
        // Don't add duplicates
        for (const auto& b : channel->bans) {
            if (b.mask == param && !b.is_expired()) return false;
        }
        channel->bans.emplace_back(param, setter ? setter->nick : "");
    } else {
        // Remove matching ban
        auto it = std::remove_if(channel->bans.begin(), channel->bans.end(),
            [&param](const BanEntry& b) {
                return b.mask == param;
            });
        if (it != channel->bans.end()) {
            channel->bans.erase(it, channel->bans.end());
        }
    }
    return true;
}

std::string ModeBan::get_value(const Channel* channel) const {
    return channel->get_ban_list();
}

std::string ModeBan::get_param(const Channel* channel) const {
    (void)channel;
    return "";  // List modes are queried separately
}

bool ModeBanExcept::apply(Channel* channel, ChannelMembership* setter,
                          bool adding, const std::string& param) {
    (void)setter;
    std::lock_guard<std::mutex> lock(channel->mutex);

    if (adding) {
        if (param.empty()) return false;
        if (channel->ban_excepts.size() >= MAX_EXCEPTLIST_ENTRIES) return false;
        for (const auto& e : channel->ban_excepts) {
            if (e.mask == param && !e.is_expired()) return false;
        }
        channel->ban_excepts.emplace_back(param, setter ? setter->nick : "");
    } else {
        auto it = std::remove_if(channel->ban_excepts.begin(),
            channel->ban_excepts.end(),
            [&param](const BanEntry& e) { return e.mask == param; });
        if (it != channel->ban_excepts.end()) {
            channel->ban_excepts.erase(it, channel->ban_excepts.end());
        }
    }
    return true;
}

std::string ModeBanExcept::get_value(const Channel* channel) const {
    return channel->get_except_list();
}

std::string ModeBanExcept::get_param(const Channel* channel) const {
    (void)channel;
    return "";
}

bool ModeInviteExcept::apply(Channel* channel, ChannelMembership* setter,
                             bool adding, const std::string& param) {
    (void)setter;
    std::lock_guard<std::mutex> lock(channel->mutex);

    if (adding) {
        if (param.empty()) return false;
        if (channel->invite_excepts.size() >= MAX_INVITELIST_ENTRIES)
            return false;
        for (const auto& e : channel->invite_excepts) {
            if (e.mask == param && !e.is_expired()) return false;
        }
        channel->invite_excepts.emplace_back(param, setter ? setter->nick : "");
    } else {
        auto it = std::remove_if(channel->invite_excepts.begin(),
            channel->invite_excepts.end(),
            [&param](const BanEntry& e) { return e.mask == param; });
        if (it != channel->invite_excepts.end()) {
            channel->invite_excepts.erase(it, channel->invite_excepts.end());
        }
    }
    return true;
}

std::string ModeInviteExcept::get_value(const Channel* channel) const {
    return channel->get_invex_list();
}

std::string ModeInviteExcept::get_param(const Channel* channel) const {
    (void)channel;
    return "";
}

bool ModeQuiet::apply(Channel* channel, ChannelMembership* setter,
                      bool adding, const std::string& param) {
    (void)setter;
    std::lock_guard<std::mutex> lock(channel->mutex);

    if (adding) {
        if (param.empty()) return false;
        if (channel->quiet_bans.size() >= MAX_QUIETLIST_ENTRIES) return false;
        for (const auto& qb : channel->quiet_bans) {
            if (qb.ban.mask == param && !qb.ban.is_expired()) return false;
        }
        channel->quiet_bans.emplace_back(
            BanEntry(param, setter ? setter->nick : ""));
    } else {
        auto it = std::remove_if(channel->quiet_bans.begin(),
            channel->quiet_bans.end(),
            [&param](const QuietEntry& qb) { return qb.ban.mask == param; });
        if (it != channel->quiet_bans.end()) {
            channel->quiet_bans.erase(it, channel->quiet_bans.end());
        }
    }
    return true;
}

std::string ModeQuiet::get_value(const Channel* channel) const {
    return channel->get_quiet_list();
}

std::string ModeQuiet::get_param(const Channel* channel) const {
    (void)channel;
    return "";
}

// --- Prefix mode implementations ---

bool ModeOp::apply(Channel* channel, ChannelMembership* setter,
                   bool adding, const std::string& param) {
    std::lock_guard<std::mutex> lock(channel->mutex);
    ChannelMembership* target = channel->find_member_by_nick(param);
    if (!target) return false;

    if (adding) {
        target->add_prefix('o');
    } else {
        target->remove_prefix('o');
    }
    return true;
}

std::string ModeOp::get_value(const Channel* channel) const {
    std::string result;
    for (const auto& [uid, m] : channel->members) {
        if (m.has_prefix_char('@')) {
            if (!result.empty()) result += " ";
            result += m.nick;
        }
    }
    return result;
}

bool ModeVoice::apply(Channel* channel, ChannelMembership* setter,
                      bool adding, const std::string& param) {
    std::lock_guard<std::mutex> lock(channel->mutex);
    ChannelMembership* target = channel->find_member_by_nick(param);
    if (!target) return false;

    if (adding) {
        target->add_prefix('v');
    } else {
        target->remove_prefix('v');
    }
    return true;
}

std::string ModeVoice::get_value(const Channel* channel) const {
    std::string result;
    for (const auto& [uid, m] : channel->members) {
        if (m.has_prefix_char('+') && !m.has_prefix_char('@') &&
            !m.has_prefix_char('%') && !m.has_prefix_char('&') &&
            !m.has_prefix_char('~')) {
            if (!result.empty()) result += " ";
            result += m.nick;
        }
    }
    return result;
}

bool ModeHalfOp::apply(Channel* channel, ChannelMembership* setter,
                       bool adding, const std::string& param) {
    std::lock_guard<std::mutex> lock(channel->mutex);
    ChannelMembership* target = channel->find_member_by_nick(param);
    if (!target) return false;

    if (adding) {
        target->add_prefix('h');
    } else {
        target->remove_prefix('h');
    }
    return true;
}

std::string ModeHalfOp::get_value(const Channel* channel) const {
    std::string result;
    for (const auto& [uid, m] : channel->members) {
        if (m.has_prefix_char('%')) {
            if (!result.empty()) result += " ";
            result += m.nick;
        }
    }
    return result;
}

bool ModeAdmin::apply(Channel* channel, ChannelMembership* setter,
                      bool adding, const std::string& param) {
    std::lock_guard<std::mutex> lock(channel->mutex);
    ChannelMembership* target = channel->find_member_by_nick(param);
    if (!target) return false;

    if (adding) {
        target->add_prefix('a');
    } else {
        target->remove_prefix('a');
    }
    return true;
}

std::string ModeAdmin::get_value(const Channel* channel) const {
    std::string result;
    for (const auto& [uid, m] : channel->members) {
        if (m.has_prefix_char('&')) {
            if (!result.empty()) result += " ";
            result += m.nick;
        }
    }
    return result;
}

bool ModeOwner::apply(Channel* channel, ChannelMembership* setter,
                      bool adding, const std::string& param) {
    std::lock_guard<std::mutex> lock(channel->mutex);
    ChannelMembership* target = channel->find_member_by_nick(param);
    if (!target) return false;

    if (adding) {
        target->add_prefix('q');
    } else {
        target->remove_prefix('q');
    }
    return true;
}

std::string ModeOwner::get_value(const Channel* channel) const {
    std::string result;
    for (const auto& [uid, m] : channel->members) {
        if (m.has_prefix_char('~')) {
            if (!result.empty()) result += " ";
            result += m.nick;
        }
    }
    return result;
}

// --- Forward and redirect ---

bool ModeForward::apply(Channel* channel, ChannelMembership* setter,
                        bool adding, const std::string& param) {
    (void)setter;
    std::lock_guard<std::mutex> lock(channel->mutex);

    if (adding) {
        if (param.empty()) return false;
        if (!valid_channel_name(param)) return false;
        channel->forward_channel = param;
        channel->set_mode(Channel::MODE_HAS_FORWARD);
    } else {
        channel->forward_channel.clear();
        channel->clear_mode(Channel::MODE_HAS_FORWARD);
    }
    return true;
}

std::string ModeForward::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_HAS_FORWARD)
        ? channel->forward_channel : "";
}

bool ModeRedirect::apply(Channel* channel, ChannelMembership* setter,
                         bool adding, const std::string& param) {
    (void)setter;
    std::lock_guard<std::mutex> lock(channel->mutex);

    if (adding) {
        if (param.empty()) return false;
        if (!valid_channel_name(param)) return false;
        channel->redirect_channel = param;
        channel->set_mode(Channel::MODE_HAS_REDIRECT);
        // +f and +L are mutually exclusive
        channel->clear_mode(Channel::MODE_HAS_FORWARD);
        channel->forward_channel.clear();
    } else {
        channel->redirect_channel.clear();
        channel->clear_mode(Channel::MODE_HAS_REDIRECT);
    }
    return true;
}

std::string ModeRedirect::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_HAS_REDIRECT)
        ? channel->redirect_channel : "";
}

// --- SSL only ---

bool ModeSSLOnly::apply(Channel* channel, ChannelMembership* setter,
                        bool adding, const std::string& param) {
    (void)setter; (void)param;
    std::lock_guard<std::mutex> lock(channel->mutex);
    channel->toggle_mode(Channel::MODE_SSL_ONLY, adding);
    return true;
}

std::string ModeSSLOnly::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_SSL_ONLY) ? "z" : "";
}

// --- History ---

bool ModeHistory::apply(Channel* channel, ChannelMembership* setter,
                        bool adding, const std::string& param) {
    (void)setter;
    std::lock_guard<std::mutex> lock(channel->mutex);

    if (adding) {
        // Parse history param: lines[:age]
        size_t lines = MAX_HISTORY_LINES;
        int64_t age = MAX_HISTORY_TIME_WINDOW;

        if (!param.empty()) {
            size_t colon = param.find(':');
            try {
                lines = std::stoul(param.substr(0, colon));
                if (colon != std::string::npos) {
                    age = std::stoll(param.substr(colon + 1));
                }
            } catch (...) {
                // Use defaults
            }
        }

        if (lines > 10000) lines = 10000;
        channel->history_max_lines = lines;
        channel->history_max_age = age;
        channel->set_mode(Channel::MODE_HAS_HISTORY);
        channel->history->set_max_lines(lines);
        channel->history->set_max_age(age);
    } else {
        channel->history_max_lines = MAX_HISTORY_LINES;
        channel->history_max_age = MAX_HISTORY_TIME_WINDOW;
        channel->clear_mode(Channel::MODE_HAS_HISTORY);
        channel->history->set_max_lines(MAX_HISTORY_LINES);
        channel->history->set_max_age(MAX_HISTORY_TIME_WINDOW);
    }
    return true;
}

std::string ModeHistory::get_value(const Channel* channel) const {
    if (!channel->has_mode(Channel::MODE_HAS_HISTORY)) return "";
    return std::to_string(channel->history_max_lines) + ":"
           + std::to_string(channel->history_max_age);
}

// --- Permanent ---

bool ModePermanent::apply(Channel* channel, ChannelMembership* setter,
                          bool adding, const std::string& param) {
    (void)setter; (void)param;
    std::lock_guard<std::mutex> lock(channel->mutex);
    channel->toggle_mode(Channel::MODE_PERMANENT, adding);
    if (adding) {
        channel->status = ChannelStatus::PERSIST;
    } else if (channel->member_count() == 0) {
        channel->status = ChannelStatus::ACTIVE;
    }
    return true;
}

std::string ModePermanent::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_PERMANENT) ? "P" : "";
}

// --- Registered (with services) ---

bool ModeRegistered::apply(Channel* channel, ChannelMembership* setter,
                           bool adding, const std::string& param) {
    (void)setter; (void)param;
    std::lock_guard<std::mutex> lock(channel->mutex);
    channel->toggle_mode(Channel::MODE_REGISTERED, adding);
    return true;
}

std::string ModeRegistered::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_REGISTERED) ? "r" : "";
}

// --- Auto-join ---

bool ModeAutoJoin::apply(Channel* channel, ChannelMembership* setter,
                         bool adding, const std::string& param) {
    (void)setter; (void)param;
    std::lock_guard<std::mutex> lock(channel->mutex);
    channel->toggle_mode(Channel::MODE_AUTO_JOIN, adding);
    channel->auto_join = adding;
    return true;
}

std::string ModeAutoJoin::get_value(const Channel* channel) const {
    return channel->has_mode(Channel::MODE_AUTO_JOIN) ? "A" : "";
}

// =============================================================================
// SECTION 10: Channel Manager
// =============================================================================

class ChannelManager {
public:
    ChannelManager() : next_uid_seq_(1) {}

    // --- Channel lifecycle ---

    Channel* create_channel(const std::string& name, const std::string& creator_uid = "",
                            const std::string& creator_nick = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!valid_channel_name(name)) return nullptr;

        auto it = channels_.find(name);
        if (it != channels_.end()) {
            return it->second.get();
        }

        auto channel = std::make_unique<Channel>(name);
        Channel* raw = channel.get();

        // If creator specified, add them and give them owner status
        if (!creator_uid.empty() && !creator_nick.empty()) {
            ChannelMembership cm;
            cm.uid = creator_uid;
            cm.nick = creator_nick;
            cm.add_prefix('q');
            cm.add_prefix('o');
            channel->add_member(cm);
        }

        channels_[name] = std::move(channel);
        return raw;
    }

    Channel* get_channel(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = channels_.find(name);
        return (it != channels_.end()) ? it->second.get() : nullptr;
    }

    const Channel* get_channel(const std::string& name) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = channels_.find(name);
        return (it != channels_.end()) ? it->second.get() : nullptr;
    }

    bool channel_exists(const std::string& name) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return channels_.find(name) != channels_.end();
    }

    bool remove_channel(const std::string& name, bool force = false) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = channels_.find(name);
        if (it == channels_.end()) return false;

        Channel* ch = it->second.get();
        if (!force && ch->member_count() > 0) return false;
        if (!force && ch->is_permanent()) return false;

        channels_.erase(it);
        return true;
    }

    // --- Member operations ---

    bool join_channel(const std::string& channel_name,
                      const ChannelMembership& member,
                      const std::string& key = "",
                      bool force = false) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = channels_.find(channel_name);
        if (it == channels_.end()) {
            if (!force) return false;
            // Create on join if forced
            auto ch = std::make_unique<Channel>(channel_name);
            ChannelMembership cm = member;
            cm.add_prefix('q');
            cm.add_prefix('o');
            ch->add_member(cm);
            channels_[channel_name] = std::move(ch);
            return true;
        }

        Channel* ch = it->second.get();

        // Check if already member
        if (ch->is_member(member.uid)) return false;

        // Check limit
        if (ch->has_limit() && ch->member_count() >= ch->user_limit)
            return false;

        // Check key
        if (ch->has_key() && ch->key != key && !force)
            return false;

        // Check SSL requirement
        if (ch->is_ssl_only() && !force) {
            // In production, check SSL flag on user's connection
        }

        // Check ban
        if (!force && ch->is_banned(member.uid, member.nick, member.user,
                                    member.host, member.account,
                                    member.realname, member.certfp))
            return false;

        // Check invite requirement
        if (ch->is_invite_only() && !ch->is_invited(member.uid) &&
            !ch->is_invite_excepted(member.nick, member.user, member.host,
                                     member.account, member.realname,
                                     member.certfp) && !force)
            return false;

        // Add member
        ChannelMembership cm = member;
        cm.join_ts = now_ts();
        ch->add_member(cm);
        return true;
    }

    bool part_channel(const std::string& channel_name, const std::string& uid,
                      const std::string& reason = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = channels_.find(channel_name);
        if (it == channels_.end()) return false;

        Channel* ch = it->second.get();
        bool removed = ch->remove_member(uid, reason);

        // Cleanup empty non-persistent channels
        if (ch->member_count() == 0 && !ch->is_permanent()) {
            channels_.erase(it);
        }

        return removed;
    }

    // --- Mode operations ---

    bool set_mode(Channel* channel, ChannelMembership* setter,
                  bool adding, char mode, const std::string& param = "") {
        ChannelModeHandler* handler = get_mode_handler(mode);
        if (!handler) return false;

        // Check permission
        if (!handler->can_set(channel, setter, adding, param))
            return false;

        return handler->apply(channel, setter, adding, param);
    }

    bool set_modes(Channel* channel, ChannelMembership* setter,
                   const std::string& mode_string,
                   const std::vector<std::string>& params) {
        bool adding = true;
        size_t pidx = 0;
        bool changed = false;

        for (size_t i = 0; i < mode_string.size(); ++i) {
            char c = mode_string[i];
            if (c == '+') { adding = true; continue; }
            if (c == '-') { adding = false; continue; }

            ChannelModeHandler* handler = get_mode_handler(c);
            if (!handler) continue;

            std::string param;
            if (handler->needs_param(adding)) {
                if (pidx < params.size()) {
                    param = params[pidx++];
                } else {
                    continue;  // Missing param, skip
                }
            }

            if (handler->can_set(channel, setter, adding, param)) {
                if (handler->apply(channel, setter, adding, param))
                    changed = true;
            }
        }

        return changed;
    }

    ChannelModeHandler* get_mode_handler(char mode) {
        static std::unordered_map<char, std::unique_ptr<ChannelModeHandler>> handlers;
        static bool initialized = false;

        if (!initialized) {
            handlers['i'] = std::make_unique<ModeInviteOnly>();
            handlers['m'] = std::make_unique<ModeModerated>();
            handlers['n'] = std::make_unique<ModeNoExternal>();
            handlers['s'] = std::make_unique<ModeSecret>();
            handlers['p'] = std::make_unique<ModePrivate>();
            handlers['t'] = std::make_unique<ModeTopicLock>();
            handlers['k'] = std::make_unique<ModeKey>();
            handlers['l'] = std::make_unique<ModeLimit>();
            handlers['b'] = std::make_unique<ModeBan>();
            handlers['e'] = std::make_unique<ModeBanExcept>();
            handlers['I'] = std::make_unique<ModeInviteExcept>();
            handlers['o'] = std::make_unique<ModeOp>();
            handlers['v'] = std::make_unique<ModeVoice>();
            handlers['h'] = std::make_unique<ModeHalfOp>();
            handlers['a'] = std::make_unique<ModeAdmin>();
            handlers['q'] = std::make_unique<ModeOwner>();
            handlers['f'] = std::make_unique<ModeForward>();
            handlers['L'] = std::make_unique<ModeRedirect>();
            handlers['z'] = std::make_unique<ModeSSLOnly>();
            handlers['H'] = std::make_unique<ModeHistory>();
            handlers['P'] = std::make_unique<ModePermanent>();
            handlers['r'] = std::make_unique<ModeRegistered>();
            handlers['A'] = std::make_unique<ModeAutoJoin>();
            initialized = true;
        }

        auto it = handlers.find(mode);
        return (it != handlers.end()) ? it->second.get() : nullptr;
    }

    // --- Queries ---

    std::vector<std::string> get_channel_list() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> result;
        result.reserve(channels_.size());
        for (const auto& [name, ch] : channels_) {
            result.push_back(name);
        }
        return result;
    }

    std::vector<std::string> get_user_channels(const std::string& uid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> result;
        for (const auto& [name, ch] : channels_) {
            if (ch->is_member(uid))
                result.push_back(name);
        }
        return result;
    }

    // Remove user from all channels (e.g., on quit/netsplit)
    size_t remove_user_from_all(const std::string& uid,
                                const std::string& reason = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        std::vector<std::string> to_remove;

        for (auto& [name, ch] : channels_) {
            if (ch->remove_member(uid, reason)) {
                ++count;
                if (ch->member_count() == 0 && !ch->is_permanent()) {
                    to_remove.push_back(name);
                }
            }
        }

        for (const auto& name : to_remove) {
            channels_.erase(name);
        }

        return count;
    }

    // --- Channel registration with services ---

    bool register_channel(const std::string& name, const std::string& founder_account) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = channels_.find(name);
        if (it == channels_.end()) return false;

        Channel* ch = it->second.get();
        if (ch->is_registered()) return false;  // Already registered

        ch->set_mode(Channel::MODE_REGISTERED);
        ch->founder = founder_account;
        return true;
    }

    bool unregister_channel(const std::string& name, const std::string& requestor_account) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = channels_.find(name);
        if (it == channels_.end()) return false;

        Channel* ch = it->second.get();
        if (!ch->is_registered()) return false;
        if (ch->founder != requestor_account) return false;  // Only founder

        ch->clear_mode(Channel::MODE_REGISTERED);
        ch->founder.clear();
        return true;
    }

    bool is_founder(const std::string& channel_name,
                    const std::string& account) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = channels_.find(channel_name);
        if (it == channels_.end()) return false;
        return it->second->founder == account && !account.empty();
    }

    // --- Persistence ---

    std::string serialize_all() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::stringstream ss;
        for (const auto& [name, ch] : channels_) {
            if (ch->is_permanent() || ch->is_registered()) {
                ss << ch->serialize();
            }
        }
        return ss.str();
    }

    // --- UID generation for S2S ---

    std::string generate_uid(const std::string& sid) {
        std::lock_guard<std::mutex> lock(uid_mutex_);
        uint64_t seq = next_uid_seq_++;
        char buf[16];
        snprintf(buf, sizeof(buf), "%s%06llX", sid.c_str(),
                 static_cast<unsigned long long>(seq & 0xFFFFFF));
        return std::string(buf);
    }

    // --- Garbage collection ---

    size_t cleanup_expired_bans() {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t total_removed = 0;

        for (auto& [name, ch] : channels_) {
            auto remove_expired = [](std::vector<BanEntry>& list) -> size_t {
                size_t before = list.size();
                list.erase(std::remove_if(list.begin(), list.end(),
                    [](const BanEntry& b) { return b.is_expired(); }),
                    list.end());
                return before - list.size();
            };

            total_removed += remove_expired(ch->bans);
            total_removed += remove_expired(ch->ban_excepts);
            total_removed += remove_expired(ch->invite_excepts);

            // Quiet bans
            {
                size_t before = ch->quiet_bans.size();
                ch->quiet_bans.erase(std::remove_if(ch->quiet_bans.begin(),
                    ch->quiet_bans.end(),
                    [](const QuietEntry& qb) { return qb.ban.is_expired(); }),
                    ch->quiet_bans.end());
                total_removed += before - ch->quiet_bans.size();
            }
        }

        return total_removed;
    }

private:
    std::unordered_map<std::string, std::unique_ptr<Channel>> channels_;
    mutable std::mutex mutex_;
    mutable std::mutex uid_mutex_;
    uint64_t next_uid_seq_;
};

// =============================================================================
// SECTION 11: Server-to-Server Protocol Implementation
// =============================================================================

// Represents a single server in the network
struct ServerNode {
    std::string name;             // Full server name (e.g., irc.example.com)
    std::string sid;              // 3-character server ID (e.g., "001")
    std::string description;      // Server description string
    std::string software;         // Software name/version
    std::string parent_sid;       // Parent server SID (empty for root)
    int64_t link_ts;              // When the link was established
    int64_t boot_ts;              // Server boot time (for TS delta)
    int64_t ts_delta;             // Time offset from our clock
    LinkState state;
    uint32_t hop_count;           // Hops from us
    uint32_t protocol_version;
    bool burst_complete;          // Whether ENDOFBURST has been sent
    bool hidden;                  // Hidden from /links?
    std::vector<std::string> uplink_capabs;  // Capabilities
    std::string pass_hash;        // For authentication

    ServerNode()
        : link_ts(now_ts()), boot_ts(now_ts()), ts_delta(0),
          state(LinkState::DISCONNECTED), hop_count(0),
          protocol_version(PROTOCOL_VERSION), burst_complete(false),
          hidden(false) {}

    bool is_connected() const {
        return state == LinkState::CONNECTED ||
               state == LinkState::BURSTING;
    }

    bool is_bursting() const {
        return state == LinkState::BURSTING;
    }

    std::string serialize() const {
        std::stringstream ss;
        ss << "SERVER " << name << " " << sid << " " << hop_count << " "
           << link_ts << " " << boot_ts << " " << static_cast<int>(state)
           << " :" << description;
        return ss.str();
    }
};

// Represents a user introduced from another server
struct RemoteUser {
    std::string uid;           // Full UID (SID + 6-char ID)
    std::string nick;
    std::string user;
    std::string host;
    std::string realname;
    std::string account;
    std::string certfp;
    std::string ip;
    std::string server_sid;    // Home server SID
    int64_t signon_ts;
    int64_t last_active;
    bool is_oper;
    std::string modes;         // User modes (+i, +w, etc.)
    std::string away_msg;
    bool is_away;

    RemoteUser()
        : signon_ts(now_ts()), last_active(now_ts()),
          is_oper(false), is_away(false) {}

    RemoteUser(const std::string& u, const std::string& n,
               const std::string& us, const std::string& h,
               const std::string& r, const std::string& sid)
        : uid(u), nick(n), user(us), host(h), realname(r),
          server_sid(sid), signon_ts(now_ts()), last_active(now_ts()),
          is_oper(false), is_away(false) {}
};

// =============================================================================
// SECTION 12: Server Tree (Spanning Tree Topology)
// =============================================================================

class ServerTree {
public:
    ServerTree() : our_sid_(""), our_name_(""), our_desc_(""),
                   our_boot_ts_(now_ts()) {}

    // --- Setup ---

    void set_local_server(const std::string& name, const std::string& sid,
                          const std::string& desc) {
        our_name_ = name;
        our_sid_ = sid;
        our_desc_ = desc;
        our_boot_ts_ = now_ts();

        // Register ourselves in the tree
        ServerNode local;
        local.name = name;
        local.sid = sid;
        local.description = desc;
        local.state = LinkState::CONNECTED;
        local.hop_count = 0;
        local.burst_complete = true;
        local.boot_ts = our_boot_ts_;
        servers_[sid] = local;
    }

    const std::string& our_sid() const { return our_sid_; }
    const std::string& our_name() const { return our_name_; }
    const std::string& our_desc() const { return our_desc_; }
    int64_t our_boot_ts() const { return our_boot_ts_; }

    // --- Server registration ---

    ServerNode* add_server(const std::string& name, const std::string& sid,
                           const std::string& parent_sid,
                           const std::string& description,
                           int64_t boot_ts = 0) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Validate parent exists
        auto parent_it = servers_.find(parent_sid);
        if (parent_it == servers_.end() && parent_sid != our_sid_) {
            return nullptr;  // Orphan
        }

        ServerNode node;
        node.name = name;
        node.sid = sid;
        node.parent_sid = parent_sid;
        node.description = description;
        node.state = LinkState::REGISTERED;
        node.hop_count = (parent_it != servers_.end())
            ? parent_it->second.hop_count + 1 : 1;
        node.link_ts = now_ts();
        node.boot_ts = (boot_ts > 0) ? boot_ts : now_ts();
        node.ts_delta = node.boot_ts - now_ts();

        servers_[sid] = node;
        return &servers_[sid];
    }

    ServerNode* get_server(const std::string& sid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = servers_.find(sid);
        return (it != servers_.end()) ? &it->second : nullptr;
    }

    const ServerNode* get_server(const std::string& sid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = servers_.find(sid);
        return (it != servers_.end()) ? &it->second : nullptr;
    }

    ServerNode* get_server_by_name(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [sid, srv] : servers_) {
            if (srv.name == name) return &srv;
        }
        return nullptr;
    }

    bool remove_server(const std::string& sid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = servers_.find(sid);
        if (it == servers_.end()) return false;

        // Collect children to remove (recursive)
        std::vector<std::string> to_remove = {sid};
        std::vector<std::string> children;

        // Find all descendants
        for (size_t i = 0; i < to_remove.size(); ++i) {
            for (const auto& [csid, srv] : servers_) {
                if (srv.parent_sid == to_remove[i] &&
                    std::find(to_remove.begin(), to_remove.end(), csid)
                        == to_remove.end()) {
                    to_remove.push_back(csid);
                }
            }
        }

        for (const auto& s : to_remove) {
            servers_.erase(s);
        }

        return true;
    }

    // --- Burst management ---

    void set_bursting(const std::string& sid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = servers_.find(sid);
        if (it != servers_.end()) {
            it->second.state = LinkState::BURSTING;
            it->second.burst_complete = false;
        }
    }

    void set_burst_complete(const std::string& sid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = servers_.find(sid);
        if (it != servers_.end()) {
            it->second.state = LinkState::CONNECTED;
            it->second.burst_complete = true;
        }
    }

    bool is_burst_complete(const std::string& sid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = servers_.find(sid);
        return (it != servers_.end()) ? it->second.burst_complete : false;
    }

    // --- TS (Time Synchronization) ---

    int64_t get_ts_delta(const std::string& sid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = servers_.find(sid);
        return (it != servers_.end()) ? it->second.ts_delta : 0;
    }

    void set_ts_delta(const std::string& sid, int64_t delta) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = servers_.find(sid);
        if (it != servers_.end()) {
            it->second.ts_delta = delta;
        }
    }

    int64_t adjusted_ts(const std::string& sid, int64_t their_ts) const {
        int64_t delta = get_ts_delta(sid);
        return their_ts + delta;
    }

    bool is_delta_valid(const std::string& sid, int64_t delta) const {
        return std::abs(delta) <= DEFAULT_TS_DELTA;
    }

    // --- Routing ---

    // Determine the next hop SID for a given destination SID
    std::string get_next_hop(const std::string& target_sid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (target_sid == our_sid_) return our_sid_;

        auto it = servers_.find(target_sid);
        if (it == servers_.end()) return "";  // Unknown server

        // Walk up the tree from target to find the child of us on the path
        std::string current = target_sid;
        while (current != our_sid_ && !current.empty()) {
            auto cur = servers_.find(current);
            if (cur == servers_.end()) return "";
            if (cur->second.parent_sid == our_sid_) return current;
            current = cur->second.parent_sid;
        }

        return current;  // Direct neighbor
    }

    // Check if a server is a direct neighbor (linked to us)
    bool is_direct_link(const std::string& sid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = servers_.find(sid);
        if (it == servers_.end()) return false;
        return it->second.parent_sid == our_sid_;
    }

    // Get all direct children
    std::vector<std::string> get_direct_children() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> result;
        for (const auto& [sid, srv] : servers_) {
            if (srv.parent_sid == our_sid_) {
                result.push_back(sid);
            }
        }
        return result;
    }

    // Get the path from us to a given server
    std::vector<std::string> get_path(const std::string& target_sid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> path;

        if (target_sid == our_sid_) {
            path.push_back(our_sid_);
            return path;
        }

        std::string current = target_sid;
        while (!current.empty() && current != our_sid_) {
            path.insert(path.begin(), current);
            auto it = servers_.find(current);
            if (it == servers_.end()) return {};
            current = it->second.parent_sid;
        }

        if (current == our_sid_) {
            path.insert(path.begin(), our_sid_);
        } else {
            path.clear();
        }

        return path;
    }

    // Flood a message to all connected servers
    std::vector<std::string> get_flood_targets(const std::string& exclude_sid = "") const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> result;

        for (const auto& [sid, srv] : servers_) {
            if (sid == our_sid_) continue;
            if (sid == exclude_sid) continue;
            if (srv.is_connected() && srv.parent_sid == our_sid_) {
                result.push_back(sid);
            }
        }

        return result;
    }

    // Get all server names for /links or /map
    std::vector<const ServerNode*> get_all_servers() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<const ServerNode*> result;
        result.reserve(servers_.size());

        // Sort: us first, then by hop count, then by name
        for (const auto& [sid, srv] : servers_) {
            result.push_back(&srv);
        }
        std::sort(result.begin(), result.end(),
            [this](const ServerNode* a, const ServerNode* b) {
                if (a->sid == our_sid_) return true;
                if (b->sid == our_sid_) return false;
                if (a->hop_count != b->hop_count)
                    return a->hop_count < b->hop_count;
                return a->name < b->name;
            });

        return result;
    }

    // --- UID resolution ---

    std::string uid_to_sid(const std::string& uid) const {
        if (uid.size() >= 3) {
            return uid.substr(0, 3);
        }
        return "";
    }

    bool is_local_uid(const std::string& uid) const {
        return uid.size() >= 3 && uid.substr(0, 3) == our_sid_;
    }

    ServerNode* server_for_uid(const std::string& uid) {
        std::string sid = uid_to_sid(uid);
        return get_server(sid);
    }

    // --- Remote user tracking ---

    void add_remote_user(const RemoteUser& user) {
        std::lock_guard<std::mutex> lock(user_mutex_);
        remote_users_[user.uid] = user;
    }

    bool remove_remote_user(const std::string& uid) {
        std::lock_guard<std::mutex> lock(user_mutex_);
        return remote_users_.erase(uid) > 0;
    }

    RemoteUser* get_remote_user(const std::string& uid) {
        std::lock_guard<std::mutex> lock(user_mutex_);
        auto it = remote_users_.find(uid);
        return (it != remote_users_.end()) ? &it->second : nullptr;
    }

    size_t remove_users_on_server(const std::string& sid) {
        std::lock_guard<std::mutex> lock(user_mutex_);
        size_t count = 0;
        auto it = remote_users_.begin();
        while (it != remote_users_.end()) {
            if (it->second.server_sid == sid) {
                it = remote_users_.erase(it);
                ++count;
            } else {
                ++it;
            }
        }
        return count;
    }

    void update_remote_user_nick(const std::string& uid, const std::string& new_nick) {
        std::lock_guard<std::mutex> lock(user_mutex_);
        auto it = remote_users_.find(uid);
        if (it != remote_users_.end()) {
            it->second.nick = new_nick;
        }
    }

    // --- Spanning tree operations ---

    // Check for loops (would create a cycle in the tree)
    bool would_create_loop(const std::string& sid, const std::string& parent_sid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (parent_sid == our_sid_) return false;

        // Check if parent_sid is a descendant of sid (if sid known)
        auto sit = servers_.find(sid);
        if (sit != servers_.end()) {
            std::string current = parent_sid;
            while (!current.empty() && current != our_sid_) {
                if (current == sid) return true;  // Loop!
                auto it = servers_.find(current);
                if (it == servers_.end()) break;
                current = it->second.parent_sid;
            }
        }

        return false;
    }

    // --- Counts ---

    size_t server_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return servers_.size();
    }

    size_t remote_user_count() const {
        std::lock_guard<std::mutex> lock(user_mutex_);
        return remote_users_.size();
    }

private:
    std::string our_sid_;
    std::string our_name_;
    std::string our_desc_;
    int64_t our_boot_ts_;

    std::unordered_map<std::string, ServerNode> servers_;  // SID -> ServerNode
    std::unordered_map<std::string, RemoteUser> remote_users_;  // UID -> RemoteUser
    mutable std::mutex mutex_;
    mutable std::mutex user_mutex_;
};

// =============================================================================
// SECTION 13: S2S Protocol Message Builder / Parser
// =============================================================================

class S2SProtocol {
public:
    S2SProtocol() {}

    // --- Build protocol messages ---

    // PASS <password> <protocol_version> <flags>
    static std::string build_pass(const std::string& password,
                                  const std::string& flags = "") {
        std::stringstream ss;
        ss << "PASS " << password << " " << PROTOCOL_VERSION;
        if (!flags.empty()) ss << " " << flags;
        return ss.str();
    }

    // SERVER <name> <hopcount> <boot_ts> <link_ts> <protocol> <sid> :<description>
    static std::string build_server_intro(const std::string& name,
                                          const std::string& sid,
                                          const std::string& description,
                                          int64_t boot_ts) {
        std::stringstream ss;
        ss << "SERVER " << name << " 1 " << boot_ts << " "
           << now_ts() << " J10 " << sid << " :" << description;
        return ss.str();
    }

    static std::string build_server_pass_on(const std::string& name,
                                            uint32_t hop_count,
                                            int64_t boot_ts, int64_t link_ts,
                                            const std::string& sid,
                                            const std::string& description) {
        std::stringstream ss;
        ss << "SERVER " << name << " " << hop_count << " " << boot_ts
           << " " << link_ts << " J10 " << sid << " :" << description;
        return ss.str();
    }

    // NETINFO <max_global> <current_time> <protocol> <cloak_hash> <0|1> <0|1> :<network_name>
    static std::string build_netinfo(const std::string& network_name,
                                     int64_t current_time = 0,
                                     int max_global = 0) {
        if (current_time == 0) current_time = now_ts();
        std::stringstream ss;
        ss << "NETINFO " << max_global << " " << current_time
           << " " << PROTOCOL_VERSION << " 0 0 0 :" << network_name;
        return ss.str();
    }

    // BURST <ts>
    static std::string build_burst(int64_t ts = 0) {
        if (ts == 0) ts = now_ts();
        return std::string("BURST ") + std::to_string(ts);
    }

    // ENDOFBURST
    static std::string build_end_of_burst() {
        return "ENDOFBURST";
    }

    // UID <nick> <hopcount> <signon_ts> +<modes> <user> <host> <uid> <ip> <realhost> :<realname>
    static std::string build_uid_intro(const std::string& nick,
                                       uint32_t hop_count,
                                       int64_t signon_ts,
                                       const std::string& user_modes,
                                       const std::string& user,
                                       const std::string& host,
                                       const std::string& uid,
                                       const std::string& ip,
                                       const std::string& realname) {
        std::stringstream ss;
        ss << "UID " << nick << " " << hop_count << " " << signon_ts
           << " +" << user_modes << " " << user << " " << host
           << " " << uid << " " << ip << " " << host << " :" << realname;
        return ss.str();
    }

    // FJOIN <channel> <ts> +<modes> :<prefix_nick_pairs>
    static std::string build_fjoin(const std::string& channel,
                                   int64_t channel_ts,
                                   const std::string& mode_str,
                                   const std::string& members) {
        std::stringstream ss;
        ss << "FJOIN " << channel << " " << channel_ts << " "
           << mode_str << " :" << members;
        return ss.str();
    }

    // SJOIN <channel> <ts> +<chanmodes> :<prefix_nick_pairs>
    static std::string build_sjoin(const std::string& channel,
                                   int64_t channel_ts,
                                   const std::string& mode_str,
                                   const std::string& members) {
        std::stringstream ss;
        ss << "SJOIN " << channel << " " << channel_ts << " "
           << mode_str << " :" << members;
        return ss.str();
    }

    // SVSNICK <uid> <newnick> <ts>
    static std::string build_svsnick(const std::string& uid,
                                     const std::string& new_nick,
                                     int64_t ts = 0) {
        if (ts == 0) ts = now_ts();
        return std::string("SVSNICK ") + uid + " " + new_nick
               + " " + std::to_string(ts);
    }

    // SVSMODE <uid> <ts> +<modes>
    static std::string build_svsmode(const std::string& uid,
                                     const std::string& modes,
                                     int64_t ts = 0) {
        if (ts == 0) ts = now_ts();
        return std::string("SVSMODE ") + uid + " " + std::to_string(ts)
               + " +" + modes;
    }

    // KILL <uid> :<reason>
    static std::string build_kill(const std::string& uid,
                                  const std::string& reason) {
        return std::string("KILL ") + uid + " :" + reason;
    }

    // SQUIT <sid> :<reason>
    static std::string build_squit(const std::string& sid,
                                   const std::string& reason) {
        return std::string("SQUIT ") + sid + " :" + reason;
    }

    // TMODE <channel> <ts> +<modes> <params...>
    static std::string build_tmode(const std::string& channel,
                                   int64_t ts,
                                   const std::string& mode_str) {
        std::stringstream ss;
        ss << "TMODE " << channel << " " << ts << " " << mode_str;
        return ss.str();
    }

    // --- Parse protocol messages ---

    struct ParsedMessage {
        std::string command;
        std::vector<std::string> params;
        std::string trailing;
        std::string raw_tags;

        ParsedMessage() = default;
    };

    static ParsedMessage parse(const std::string& raw) {
        ParsedMessage msg;
        if (raw.empty()) return msg;

        std::string line = raw;
        // Remove trailing \r\n
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();

        // Parse IRC-style message
        size_t pos = 0;

        // Check for tags
        if (line[0] == '@') {
            size_t space = line.find(' ');
            if (space != std::string::npos) {
                msg.raw_tags = line.substr(1, space - 1);
                line = line.substr(space + 1);
            }
        }

        // Source prefix (unused in S2S for SERVER/PASS, but present in forwarded)
        if (line[0] == ':') {
            size_t space = line.find(' ');
            if (space != std::string::npos) {
                line = line.substr(space + 1);
            }
        }

        // Command
        size_t next_space = line.find(' ');
        if (next_space == std::string::npos) {
            msg.command = line;
            return msg;
        }
        msg.command = line.substr(0, next_space);
        line = line.substr(next_space + 1);

        // Parameters and trailing
        while (!line.empty()) {
            if (line[0] == ':') {
                msg.trailing = line.substr(1);
                break;
            }

            size_t space = line.find(' ');
            if (space == std::string::npos) {
                msg.params.push_back(line);
                break;
            }

            msg.params.push_back(line.substr(0, space));
            line = line.substr(space + 1);
        }

        return msg;
    }

    // --- S2S command handling table ---

    using S2SHandler = std::function<bool(const ParsedMessage&, const std::string& source_sid)>;

    // All known S2S commands
    static const std::vector<std::string>& known_commands() {
        static std::vector<std::string> cmds = {
            "PASS", "SERVER", "NETINFO", "BURST", "ENDOFBURST",
            "UID", "FJOIN", "SJOIN", "TMODE",
            "SVSNICK", "SVSMODE", "KILL", "SQUIT",
            "PING", "PONG", "VERSION", "ERROR",
            "NICK", "QUIT", "JOIN", "PART", "KICK",
            "MODE", "TOPIC", "PRIVMSG", "NOTICE",
            "SETHOST", "SETIDENT", "SETNAME",
            "CHGHOST", "CHGIDENT", "CHGNAME",
            "OPER", "AWAY", "KILL",
            "METADATA", "ENCAP", "EUID",
        };
        return cmds;
    }
};

// =============================================================================
// SECTION 14: Server Link (Connection Management)
// =============================================================================

class ServerLink {
public:
    ServerLink()
        : state_(LinkState::DISCONNECTED), fd_(-1),
          link_ts_(0), last_ping_(0), last_pong_(0),
          bytes_sent_(0), bytes_recv_(0), ping_count_(0) {}

    ServerLink(const std::string& remote_name, const std::string& remote_sid,
               const std::string& password)
        : state_(LinkState::DISCONNECTED), fd_(-1),
          remote_name_(remote_name), remote_sid_(remote_sid),
          link_password_(password), link_ts_(0), last_ping_(0),
          last_pong_(0), bytes_sent_(0), bytes_recv_(0), ping_count_(0) {}

    // --- State management ---

    LinkState state() const { return state_; }
    void set_state(LinkState s) { state_ = s; }

    bool is_connected() const {
        return state_ == LinkState::CONNECTED ||
               state_ == LinkState::BURSTING;
    }

    // --- Authentication ---

    bool check_password(const std::string& pass) const {
        return pass == link_password_;
    }

    void set_password(const std::string& pass) {
        link_password_ = pass;
    }

    // --- Link info ---

    const std::string& remote_name() const { return remote_name_; }
    const std::string& remote_sid() const { return remote_sid_; }

    void set_remote_info(const std::string& name, const std::string& sid,
                         const std::string& desc, int64_t boot_ts) {
        remote_name_ = name;
        remote_sid_ = sid;
        remote_desc_ = desc;
        remote_boot_ts_ = boot_ts;
    }

    const std::string& remote_desc() const { return remote_desc_; }
    int64_t remote_boot_ts() const { return remote_boot_ts_; }

    // --- Timing ---

    void mark_link() {
        link_ts_ = now_ts();
    }

    int64_t link_ts() const { return link_ts_; }

    void send_ping() {
        last_ping_ = now_ts();
        ping_count_++;
    }

    void receive_pong(int64_t ts = 0) {
        last_pong_ = (ts > 0) ? ts : now_ts();
    }

    int64_t last_ping() const { return last_ping_; }
    int64_t last_pong() const { return last_pong_; }

    int64_t ping_latency() const {
        if (last_pong_ == 0 || last_ping_ == 0) return -1;
        return last_pong_ - last_ping_;
    }

    bool is_lagging(int64_t max_lag = 30) const {
        if (last_ping_ == 0) return false;
        return (now_ts() - last_ping_) > max_lag && last_pong_ < last_ping_;
    }

    uint32_t ping_count() const { return ping_count_; }

    // --- Statistics ---

    void add_bytes_sent(size_t n) { bytes_sent_ += n; }
    void add_bytes_recv(size_t n) { bytes_recv_ += n; }

    size_t bytes_sent() const { return bytes_sent_; }
    size_t bytes_recv() const { return bytes_recv_; }

    // --- FD management ---

    void set_fd(int fd) { fd_ = fd; }
    int fd() const { return fd_; }

    // --- Capabilities negotiation ---

    void add_capability(const std::string& cap) {
        capabilities_.push_back(cap);
    }

    bool has_capability(const std::string& cap) const {
        return std::find(capabilities_.begin(), capabilities_.end(), cap)
               != capabilities_.end();
    }

    const std::vector<std::string>& capabilities() const {
        return capabilities_;
    }

    // --- Compression ---

    void enable_compression() { compressed_ = true; }
    bool is_compressed() const { return compressed_; }

    // --- Send queue ---

    void queue_message(const std::string& msg) {
        std::lock_guard<std::mutex> lock(send_mutex_);
        send_queue_.push_back(msg);
    }

    std::vector<std::string> flush_queue() {
        std::lock_guard<std::mutex> lock(send_mutex_);
        std::vector<std::string> result;
        result.swap(send_queue_);
        return result;
    }

    size_t queue_size() const {
        std::lock_guard<std::mutex> lock(send_mutex_);
        return send_queue_.size();
    }

    // --- Serialization ---

    std::string serialize() const {
        std::stringstream ss;
        ss << "LINK " << remote_name_ << " " << remote_sid_ << " "
           << link_ts_ << " " << static_cast<int>(state_);
        if (!remote_desc_.empty())
            ss << " :" << remote_desc_;
        return ss.str();
    }

private:
    LinkState state_;
    int fd_;
    std::string remote_name_;
    std::string remote_sid_;
    std::string remote_desc_;
    int64_t remote_boot_ts_;
    std::string link_password_;
    int64_t link_ts_;
    int64_t last_ping_;
    int64_t last_pong_;
    size_t bytes_sent_;
    size_t bytes_recv_;
    uint32_t ping_count_;
    bool compressed_ = false;
    std::vector<std::string> capabilities_;
    std::vector<std::string> send_queue_;
    mutable std::mutex send_mutex_;
};

// =============================================================================
// SECTION 15: Configuration for Channel Server
// =============================================================================

struct ChannelServerConfig {
    // Server identification
    std::string server_name;
    std::string server_sid;
    std::string server_description;
    std::string network_name;

    // Linking
    struct LinkBlock {
        std::string name;
        std::string host;
        int port = 7000;
        std::string password;
        std::string fingerprint;
        bool autoconnect = false;
        bool tls = true;
        std::string bind_address;
        int reconnect_delay = 30;  // seconds
        int max_retries = 0;       // 0 = unlimited
    };
    std::vector<LinkBlock> links;

    // Channel defaults
    bool default_chanmodes_no_ext = true;   // +n
    bool default_chanmodes_topic = true;    // +t
    size_t default_history_lines = 100;
    int64_t default_history_age = 86400;

    // Limits
    size_t max_channels_per_user = 20;
    size_t max_banlist_entries = MAX_BANLIST_ENTRIES;

    // Persistence
    bool persistent_channels = true;
    std::string channel_db_path;

    // TS
    int64_t max_ts_delta = DEFAULT_TS_DELTA;

    // Ziplinks / compression
    bool allow_ziplinks = true;

    // Hidden servers (not shown in /links)
    std::set<std::string> hidden_servers;

    ChannelServerConfig() = default;

    static ChannelServerConfig default_config(const std::string& name,
                                               const std::string& sid) {
        ChannelServerConfig cfg;
        cfg.server_name = name;
        cfg.server_sid = sid;
        cfg.server_description = "progressive-irc server";
        cfg.network_name = "progressive";
        return cfg;
    }

    std::string serialize() const {
        std::stringstream ss;
        ss << "# Channel Server Configuration\n";
        ss << "server_name = " << server_name << "\n";
        ss << "server_sid = " << server_sid << "\n";
        ss << "server_desc = " << server_description << "\n";
        ss << "network_name = " << network_name << "\n";
        ss << "max_channels_per_user = " << max_channels_per_user << "\n";
        ss << "persistent_channels = " << (persistent_channels ? "yes" : "no") << "\n";
        if (!channel_db_path.empty())
            ss << "channel_db_path = " << channel_db_path << "\n";
        ss << "max_ts_delta = " << max_ts_delta << "\n";

        for (const auto& link : links) {
            ss << "\n<link>\n";
            ss << "  name = " << link.name << "\n";
            ss << "  host = " << link.host << "\n";
            ss << "  port = " << link.port << "\n";
            ss << "  password = " << link.password << "\n";
            ss << "  tls = " << (link.tls ? "yes" : "no") << "\n";
            ss << "  autoconnect = " << (link.autoconnect ? "yes" : "no") << "\n";
            if (!link.bind_address.empty())
                ss << "  bind = " << link.bind_address << "\n";
            ss << "</link>\n";
        }

        return ss.str();
    }

    bool add_link(const std::string& name, const std::string& host,
                  int port, const std::string& password,
                  bool autoconnect = true, bool tls = true) {
        LinkBlock link;
        link.name = name;
        link.host = host;
        link.port = port;
        link.password = password;
        link.autoconnect = autoconnect;
        link.tls = tls;

        // Don't add duplicates
        for (const auto& existing : links) {
            if (existing.name == name) return false;
        }

        links.push_back(link);
        return true;
    }

    bool remove_link(const std::string& name) {
        auto it = std::remove_if(links.begin(), links.end(),
            [&name](const LinkBlock& l) { return l.name == name; });
        if (it != links.end()) {
            links.erase(it, links.end());
            return true;
        }
        return false;
    }

    const LinkBlock* find_link(const std::string& name) const {
        for (const auto& link : links) {
            if (link.name == name) return &link;
        }
        return nullptr;
    }
};

// =============================================================================
// SECTION 16: Channel Server (Main Orchestrator)
// =============================================================================

class ChannelServer {
public:
    ChannelServer() : running_(false), next_uid_seq_(1) {}

    explicit ChannelServer(const ChannelServerConfig& config)
        : config_(config), running_(false), next_uid_seq_(1) {
        init();
    }

    ~ChannelServer() {
        shutdown();
    }

    // --- Initialization ---

    void init() {
        tree_.set_local_server(config_.server_name,
                               config_.server_sid,
                               config_.server_description);

        // Set up default link passwords
        for (const auto& link : config_.links) {
            register_link_password(link.name, link.password);
        }
    }

    bool start() {
        if (running_) return false;
        running_ = true;
        return true;
    }

    void shutdown() {
        running_ = false;
        // Would flush state, close connections, etc.
    }

    bool is_running() const { return running_; }

    // --- Accessors ---

    ChannelManager& manager() { return manager_; }
    const ChannelManager& manager() const { return manager_; }

    ServerTree& tree() { return tree_; }
    const ServerTree& tree() const { return tree_; }

    const ChannelServerConfig& config() const { return config_; }

    // --- S2S Handshake Processing ---

    // Process incoming S2S line from a specific server link
    std::vector<std::string> process_s2s_line(ServerLink* link,
                                               const std::string& raw_line) {
        std::vector<std::string> responses;
        if (!link) return responses;

        auto msg = S2SProtocol::parse(raw_line);
        if (msg.command.empty()) return responses;

        // Add to byte counter
        link->add_bytes_recv(raw_line.size());

        // State machine based on link state
        switch (link->state()) {
            case LinkState::DISCONNECTED:
                // Shouldn't receive messages in this state
                break;

            case LinkState::HANDSHAKE:
                responses = handle_handshake(link, msg);
                break;

            case LinkState::REGISTERED:
            case LinkState::BURSTING:
            case LinkState::CONNECTED:
                responses = handle_registered_message(link, msg);
                break;
        }

        return responses;
    }

    // --- Send S2S message to a specific link ---

    void send_to_link(ServerLink* link, const std::string& message) {
        if (!link || !link->is_connected()) return;
        link->queue_message(message);
        link->add_bytes_sent(message.size());
    }

    // --- Broadcast to all connected servers ---

    void broadcast_to_servers(const std::string& message,
                              const std::string& exclude_sid = "") {
        for (const auto& [sid, link] : active_links_) {
            if (sid == exclude_sid) continue;
            if (link->is_connected()) {
                send_to_link(link.get(), message);
            }
        }
    }

    // --- Flood message following spanning tree rules ---

    void flood_message(const std::string& message,
                       const std::string& origin_sid) {
        for (const auto& [sid, link] : active_links_) {
            if (sid == origin_sid) continue;
            if (link->is_connected()) {
                send_to_link(link.get(), message);
            }
        }
    }

    // --- Link management ---

    ServerLink* create_link(const std::string& remote_sid) {
        auto link = std::make_unique<ServerLink>();
        link->set_state(LinkState::HANDSHAKE);
        link->mark_link();
        ServerLink* raw = link.get();
        active_links_[remote_sid] = std::move(link);
        return raw;
    }

    void remove_link(const std::string& sid) {
        active_links_.erase(sid);
    }

    ServerLink* get_link(const std::string& sid) {
        auto it = active_links_.find(sid);
        return (it != active_links_.end()) ? it->second.get() : nullptr;
    }

    void register_link_password(const std::string& server_name,
                                const std::string& password) {
        link_passwords_[server_name] = password;
    }

    bool check_link_password(const std::string& server_name,
                             const std::string& password) const {
        auto it = link_passwords_.find(server_name);
        return (it != link_passwords_.end() && it->second == password);
    }

    // --- UID generation ---

    std::string generate_uid() {
        uint64_t seq = next_uid_seq_++;
        char buf[16];
        snprintf(buf, sizeof(buf), "%s%06llX",
                 config_.server_sid.c_str(),
                 static_cast<unsigned long long>(seq & 0xFFFFFF));
        return std::string(buf);
    }

    // --- Burst management ---

    void initiate_burst(ServerLink* link) {
        if (!link || link->state() != LinkState::REGISTERED) return;

        link->set_state(LinkState::BURSTING);

        // Send BURST
        std::string burst_msg = S2SProtocol::build_burst();
        send_to_link(link, burst_msg);

        // Send local server info
        std::string our_server = S2SProtocol::build_server_intro(
            config_.server_name, config_.server_sid,
            config_.server_description, tree_.our_boot_ts());
        send_to_link(link, our_server);

        // Send all known remote servers
        for (const auto* srv : tree_.get_all_servers()) {
            if (srv->sid == config_.server_sid) continue;
            if (srv->sid == link->remote_sid()) continue;
            std::string server_msg = S2SProtocol::build_server_pass_on(
                srv->name, srv->hop_count + 1, srv->boot_ts,
                srv->link_ts, srv->sid, srv->description);
            send_to_link(link, server_msg);
        }

        // Send all channels and their members (FJOIN/SJOIN)
        for (const auto& ch_name : manager_.get_channel_list()) {
            Channel* ch = manager_.get_channel(ch_name);
            if (!ch) continue;
            send_channel_burst(link, ch);
        }

        // Send end of burst
        std::string eob = S2SProtocol::build_end_of_burst();
        send_to_link(link, eob);

        tree_.set_burst_complete(link->remote_sid());
        link->set_state(LinkState::CONNECTED);
    }

    void send_channel_burst(ServerLink* link, Channel* channel) {
        if (!link || !channel) return;

        // Build member list with prefixes
        std::vector<std::string> member_strs;
        std::lock_guard<std::mutex> lock(channel->mutex);
        for (const auto& [uid, m] : channel->members) {
            std::string entry = m.prefix_string() + m.nick;
            member_strs.push_back(entry);
        }

        std::string members;
        for (const auto& s : member_strs) {
            if (!members.empty()) members += " ";
            members += s;
        }

        std::string mode_str = channel->get_mode_string();
        if (mode_str == "+") mode_str = "+";

        std::string fjoin = S2SProtocol::build_fjoin(
            channel->name, channel->creation_ts, mode_str, members);
        send_to_link(link, fjoin);
    }

    // --- Connection lifecycle ---

    void on_server_connect(ServerLink* link) {
        if (!link) return;
        link->set_state(LinkState::HANDSHAKE);
        link->mark_link();

        // Send PASS
        auto pass_it = link_passwords_.find(link->remote_name());
        std::string pass = (pass_it != link_passwords_.end())
            ? pass_it->second : "";
        std::string pass_msg = S2SProtocol::build_pass(pass);
        send_to_link(link, pass_msg);

        // Send SERVER introduction
        std::string server_msg = S2SProtocol::build_server_intro(
            config_.server_name, config_.server_sid,
            config_.server_description, tree_.our_boot_ts());
        send_to_link(link, server_msg);

        // Send NETINFO
        std::string netinfo = S2SProtocol::build_netinfo(
            config_.network_name);
        send_to_link(link, netinfo);
    }

    void on_server_quit(const std::string& sid, const std::string& reason) {
        // Remove server from tree
        tree_.remove_server(sid);

        // Remove all users from that server
        size_t removed_users = tree_.remove_users_on_server(sid);

        // Remove users from all channels
        // (In production, iterate and remove by server_sid)

        // Close link
        remove_link(sid);
    }

    // --- Ping / Pong ---

    void send_pings() {
        int64_t now = now_ts();
        for (auto& [sid, link] : active_links_) {
            if (!link->is_connected()) continue;
            if (now - link->last_ping() > 60) {  // Ping every 60s
                std::string ping = "PING :" + config_.server_name;
                send_to_link(link.get(), ping);
                link->send_ping();
            }

            // Check for timeout
            if (link->is_lagging(120)) {  // 120s timeout
                std::string squit = S2SProtocol::build_squit(
                    sid, "Ping timeout");
                send_to_link(link.get(), squit);
                on_server_quit(sid, "Ping timeout");
            }
        }
    }

    // --- Channel event forwarding to S2S ---

    void broadcast_channel_join(const std::string& channel,
                                const std::string& uid,
                                const std::string& nick,
                                const std::string& origin_sid) {
        std::stringstream ss;
        ss << ":" << uid << " JOIN " << channel;
        flood_message(ss.str(), origin_sid);
    }

    void broadcast_channel_part(const std::string& channel,
                                const std::string& uid,
                                const std::string& reason,
                                const std::string& origin_sid) {
        std::stringstream ss;
        ss << ":" << uid << " PART " << channel;
        if (!reason.empty()) ss << " :" << reason;
        flood_message(ss.str(), origin_sid);
    }

    void broadcast_channel_mode(const std::string& channel,
                                const std::string& source_uid,
                                const std::string& mode_str,
                                const std::string& origin_sid) {
        std::stringstream ss;
        ss << ":" << source_uid << " TMODE " << channel << " "
           << now_ts() << " " << mode_str;
        flood_message(ss.str(), origin_sid);
    }

    void broadcast_channel_topic(const std::string& channel,
                                 const std::string& source_uid,
                                 const std::string& new_topic,
                                 const std::string& origin_sid) {
        std::stringstream ss;
        ss << ":" << source_uid << " TOPIC " << channel << " :" << new_topic;
        flood_message(ss.str(), origin_sid);
    }

private:
    // --- Handshake handlers ---

    std::vector<std::string> handle_handshake(ServerLink* link,
                                               const S2SProtocol::ParsedMessage& msg) {
        std::vector<std::string> responses;

        if (msg.command == "PASS") {
            handle_s2s_pass(link, msg, responses);
        } else if (msg.command == "SERVER") {
            handle_s2s_server(link, msg, responses);
        } else if (msg.command == "ERROR") {
            handle_s2s_error(link, msg, responses);
        }

        return responses;
    }

    void handle_s2s_pass(ServerLink* link,
                         const S2SProtocol::ParsedMessage& msg,
                         std::vector<std::string>& responses) {
        if (msg.params.size() < 2) {
            responses.push_back("ERROR :Invalid PASS");
            return;
        }

        std::string password = msg.params[0];
        std::string proto_str = msg.params[1];
        int proto_version = 0;
        try { proto_version = std::stoi(proto_str); }
        catch (...) {}

        // Check password
        if (!check_link_password(link->remote_name(), password)) {
            responses.push_back("ERROR :Invalid password");
            return;
        }

        // Check protocol version
        if (proto_version != PROTOCOL_VERSION) {
            responses.push_back("ERROR :Protocol version mismatch");
            return;
        }

        link->set_password(password);
    }

    void handle_s2s_server(ServerLink* link,
                           const S2SProtocol::ParsedMessage& msg,
                           std::vector<std::string>& responses) {
        // SERVER <name> <hopcount> <boot_ts> <link_ts> <protocol> <sid> :<desc>
        if (msg.params.size() < 6) {
            responses.push_back("ERROR :Invalid SERVER");
            return;
        }

        std::string server_name = msg.params[0];
        uint32_t hop_count = 0;
        int64_t boot_ts = 0;
        int64_t link_ts = 0;
        std::string sid = msg.params[5];
        std::string desc = msg.trailing;

        try {
            hop_count = std::stoul(msg.params[1]);
            boot_ts = std::stoll(msg.params[2]);
            link_ts = std::stoll(msg.params[3]);
        } catch (...) {
            responses.push_back("ERROR :Invalid SERVER parameters");
            return;
        }

        // Validate SID
        if (sid.empty() || sid.size() != 3) {
            responses.push_back("ERROR :Invalid SID");
            return;
        }

        // Check for SID collision
        if (tree_.get_server(sid)) {
            responses.push_back("ERROR :SID collision: " + sid);
            return;
        }

        // Check for loop
        if (tree_.would_create_loop(sid, config_.server_sid)) {
            responses.push_back("ERROR :Loop detected");
            return;
        }

        // Register the server
        link->set_remote_info(server_name, sid, desc, boot_ts);
        link->set_state(LinkState::REGISTERED);

        ServerNode* node = tree_.add_server(server_name, sid,
                                             config_.server_sid, desc, boot_ts);
        if (!node) {
            responses.push_back("ERROR :Failed to register server");
            return;
        }

        node->hop_count = hop_count;
        node->link_ts = link_ts;

        // Calculate TS delta
        int64_t delta = boot_ts - tree_.our_boot_ts();
        if (!tree_.is_delta_valid(sid, delta)) {
            responses.push_back("ERROR :TS delta too large");
            return;
        }
        tree_.set_ts_delta(sid, delta);

        // Send NETINFO to them
        responses.push_back(S2SProtocol::build_netinfo(config_.network_name));

        // Pass on SERVER to all other connected servers
        std::string pass_on = S2SProtocol::build_server_pass_on(
            server_name, hop_count + 1, boot_ts, link_ts,
            sid, desc);
        broadcast_to_servers(pass_on, sid);

        // Initiate burst
        initiate_burst(link);
    }

    void handle_s2s_error(ServerLink* link,
                          const S2SProtocol::ParsedMessage& msg,
                          std::vector<std::string>& responses) {
        (void)responses;
        // Log error and close link
        link->set_state(LinkState::DISCONNECTED);
    }

    // --- Message handlers for registered links ---

    std::vector<std::string> handle_registered_message(
        ServerLink* link, const S2SProtocol::ParsedMessage& msg) {
        std::vector<std::string> responses;

        if (msg.command == "PING") {
            std::string pong = "PONG " + config_.server_name + " :" +
                               (msg.params.size() > 0 ? msg.params[0] : "");
            responses.push_back(pong);
            link->receive_pong();
        } else if (msg.command == "PONG") {
            link->receive_pong();
        } else if (msg.command == "BURST") {
            handle_s2s_burst(link, msg, responses);
        } else if (msg.command == "ENDOFBURST") {
            handle_s2s_end_burst(link, msg, responses);
        } else if (msg.command == "SERVER") {
            handle_s2s_server_pass_on(link, msg, responses);
        } else if (msg.command == "UID") {
            handle_s2s_uid(link, msg, responses);
        } else if (msg.command == "FJOIN" || msg.command == "SJOIN") {
            handle_s2s_fjoin(link, msg, responses);
        } else if (msg.command == "TMODE") {
            handle_s2s_tmode(link, msg, responses);
        } else if (msg.command == "SQUIT") {
            handle_s2s_squit(link, msg, responses);
        } else if (msg.command == "SVSNICK") {
            handle_s2s_svsnick(link, msg, responses);
        } else if (msg.command == "NETINFO") {
            handle_s2s_netinfo(link, msg, responses);
        } else if (msg.command == "NICK") {
            handle_s2s_nick(link, msg, responses);
        } else if (msg.command == "QUIT") {
            handle_s2s_quit(link, msg, responses);
        } else if (msg.command == "JOIN") {
            handle_s2s_join(link, msg, responses);
        } else if (msg.command == "PART") {
            handle_s2s_part(link, msg, responses);
        } else if (msg.command == "KICK") {
            handle_s2s_kick(link, msg, responses);
        } else if (msg.command == "MODE") {
            handle_s2s_mode(link, msg, responses);
        } else if (msg.command == "TOPIC") {
            handle_s2s_topic(link, msg, responses);
        } else if (msg.command == "PRIVMSG" || msg.command == "NOTICE") {
            handle_s2s_message(link, msg, responses);
        } else if (msg.command == "VERSION") {
            responses.push_back("351 " + config_.server_name +
                                " progressive-irc 1.0 " +
                                config_.server_sid + " :" +
                                config_.server_description);
        } else if (msg.command == "ERROR") {
            // Fatal error from remote
            link->set_state(LinkState::DISCONNECTED);
        }

        return responses;
    }

    void handle_s2s_burst(ServerLink* link,
                          const S2SProtocol::ParsedMessage& msg,
                          std::vector<std::string>& responses) {
        (void)responses;
        link->set_state(LinkState::BURSTING);
        tree_.set_bursting(link->remote_sid());
    }

    void handle_s2s_end_burst(ServerLink* link,
                              const S2SProtocol::ParsedMessage& msg,
                              std::vector<std::string>& responses) {
        (void)msg; (void)responses;
        link->set_state(LinkState::CONNECTED);
        tree_.set_burst_complete(link->remote_sid());
    }

    void handle_s2s_server_pass_on(ServerLink* link,
                                   const S2SProtocol::ParsedMessage& msg,
                                   std::vector<std::string>& responses) {
        // Another server was introduced via this link
        if (msg.params.size() < 6) return;

        std::string server_name = msg.params[0];
        std::string sid = msg.params[5];
        std::string desc = msg.trailing;

        if (tree_.get_server(sid)) return;  // Already known

        uint32_t hop_count = 0;
        int64_t boot_ts = 0, link_ts_val = 0;
        try {
            hop_count = std::stoul(msg.params[1]);
            boot_ts = std::stoll(msg.params[2]);
            link_ts_val = std::stoll(msg.params[3]);
        } catch (...) { return; }

        ServerNode* node = tree_.add_server(server_name, sid,
                                             link->remote_sid(), desc, boot_ts);
        if (node) {
            node->hop_count = hop_count;
            node->link_ts = link_ts_val;
        }

        // Pass on to other links (except the one it came from)
        std::string pass_on = S2SProtocol::build_server_pass_on(
            server_name, hop_count + 1, boot_ts, link_ts_val, sid, desc);
        broadcast_to_servers(pass_on, link->remote_sid());
    }

    void handle_s2s_uid(ServerLink* link,
                        const S2SProtocol::ParsedMessage& msg,
                        std::vector<std::string>& responses) {
        // UID <nick> <hopcount> <signon_ts> +<modes> <user> <host>
        //     <uid> <ip> <realhost> :<realname>
        if (msg.params.size() < 8) return;

        RemoteUser user;
        user.nick = msg.params[0];
        user.signon_ts = std::stoll(msg.params[2]);
        user.uid = msg.params[6];
        user.user = msg.params[4];
        user.host = msg.params[5];
        user.ip = msg.params[7];
        user.realname = msg.trailing;
        user.server_sid = tree_.uid_to_sid(user.uid);

        tree_.add_remote_user(user);

        // Pass on to other links
        std::string uid_line = S2SProtocol::build_uid_intro(
            user.nick, msg.params[1].empty() ? 1 : std::stoul(msg.params[1]) + 1,
            user.signon_ts,
            msg.params[3].size() > 1 ? msg.params[3].substr(1) : "",
            user.user, user.host, user.uid, user.ip, user.realname);
        broadcast_to_servers(uid_line, link->remote_sid());
    }

    void handle_s2s_fjoin(ServerLink* link,
                          const S2SProtocol::ParsedMessage& msg,
                          std::vector<std::string>& responses) {
        (void)responses;
        // FJOIN <channel> <ts> +<modes> :<prefix_nick_pairs>
        if (msg.params.size() < 3) return;

        std::string ch_name = msg.params[0];
        int64_t ch_ts = std::stoll(msg.params[1]);
        std::string mode_str = msg.params[2];
        std::string member_str = msg.trailing;

        // Create or get channel
        Channel* channel = manager_.get_channel(ch_name);
        if (!channel) {
            channel = manager_.create_channel(ch_name);
        }
        if (!channel) return;

        // TS check: if our channel is newer, we defer to remote
        if (channel->creation_ts > ch_ts) {
            // Remote has older channel, accept their state
            channel->creation_ts = ch_ts;
        }

        // Parse members: prefix(es) + nick
        std::stringstream ss_members(member_str);
        std::string entry;
        while (ss_members >> entry) {
            if (entry.empty()) continue;

            // Extract prefix characters from the front
            std::string prefixes;
            std::string nick;
            for (size_t i = 0; i < entry.size(); ++i) {
                char c = entry[i];
                PrefixMode pm = prefix_from_prefix_char(c);
                if (pm.mode_char != 0) {
                    prefixes += c;
                } else {
                    nick = entry.substr(i);
                    break;
                }
            }

            if (nick.empty()) continue;

            // Check if member exists
            ChannelMembership* member = channel->find_member_by_nick(nick);
            if (!member) {
                ChannelMembership new_member;
                new_member.nick = nick;
                // Determine UID from remote user database
                // In production, look up by nick
                for (const auto& [uid, ru] : remote_users_) {
                    if (ru.nick == nick) {
                        new_member.uid = uid;
                        new_member.server_sid = ru.server_sid;
                        break;
                    }
                }
                channel->add_member(new_member);
                member = channel->find_member_by_nick(nick);
            }

            if (member) {
                for (char p : prefixes) {
                    PrefixMode pm = prefix_from_prefix_char(p);
                    if (pm.mode_char != 0)
                        member->add_prefix(pm.mode_char);
                }
            }
        }

        // Apply modes from the FJOIN mode string
        if (!mode_str.empty()) {
            manager_.set_modes(channel, nullptr, mode_str, {});
        }

        // Forward to other servers
        std::string fwd = S2SProtocol::build_fjoin(ch_name, ch_ts,
                                                    mode_str, member_str);
        broadcast_to_servers(fwd, link->remote_sid());
    }

    void handle_s2s_tmode(ServerLink* link,
                          const S2SProtocol::ParsedMessage& msg,
                          std::vector<std::string>& responses) {
        (void)responses;
        // TMODE <channel> <ts> +<modes>
        if (msg.params.size() < 3) return;

        std::string ch_name = msg.params[0];
        int64_t ts = std::stoll(msg.params[1]);
        std::string mode_str = msg.params[2];
        // Remaining params are mode params
        std::vector<std::string> mode_params(
            msg.params.begin() + 3, msg.params.end());
        if (!msg.trailing.empty())
            mode_params.push_back(msg.trailing);

        Channel* channel = manager_.get_channel(ch_name);
        if (!channel) return;

        // TS check: if our timestamp is lower, we win
        if (channel->creation_ts < ts) {
            // Our channel is older, reject remote mode change
            return;
        }

        manager_.set_modes(channel, nullptr, mode_str, mode_params);

        // Forward to other servers
        std::stringstream fwd_ss;
        fwd_ss << "TMODE " << ch_name << " " << ts << " " << mode_str;
        for (const auto& p : mode_params) {
            if (p.find(' ') != std::string::npos)
                fwd_ss << " :" << p << " ";
            else
                fwd_ss << " " << p;
        }
        broadcast_to_servers(fwd_ss.str(), link->remote_sid());
    }

    void handle_s2s_squit(ServerLink* link,
                          const S2SProtocol::ParsedMessage& msg,
                          std::vector<std::string>& responses) {
        (void)responses;
        std::string target_sid;
        if (!msg.params.empty()) {
            target_sid = msg.params[0];
        }

        if (target_sid == config_.server_sid) {
            // They're squitting us!
            link->set_state(LinkState::DISCONNECTED);
            return;
        }

        std::string reason = msg.trailing.empty() ? "Server Quit" : msg.trailing;

        // Remove server and all its users
        on_server_quit(target_sid, reason);

        // Forward SQUIT to other servers
        broadcast_to_servers(
            "SQUIT " + target_sid + " :" + reason,
            link->remote_sid());
    }

    void handle_s2s_svsnick(ServerLink* link,
                            const S2SProtocol::ParsedMessage& msg,
                            std::vector<std::string>& responses) {
        (void)responses;
        if (msg.params.size() < 2) return;

        std::string uid = msg.params[0];
        std::string new_nick = msg.params[1];

        tree_.update_remote_user_nick(uid, new_nick);

        // Update in all channels
        for (const auto& ch_name : manager_.get_user_channels(uid)) {
            Channel* ch = manager_.get_channel(ch_name);
            if (ch) {
                std::lock_guard<std::mutex> lock(ch->mutex);
                ChannelMembership* m = ch->find_member(uid);
                if (m) {
                    m->nick = new_nick;
                }
            }
        }

        // Forward
        std::string fwd = S2SProtocol::build_svsnick(uid, new_nick);
        broadcast_to_servers(fwd, link->remote_sid());
    }

    void handle_s2s_netinfo(ServerLink* link,
                            const S2SProtocol::ParsedMessage& msg,
                            std::vector<std::string>& responses) {
        (void)link; (void)msg; (void)responses;
        // Store network info
        if (!msg.trailing.empty()) {
            config_.network_name = msg.trailing;
        }
    }

    void handle_s2s_nick(ServerLink* link,
                         const S2SProtocol::ParsedMessage& msg,
                         std::vector<std::string>& responses) {
        (void)responses;
        // :<uid> NICK <newnick> <ts>
        if (msg.params.size() < 2) return;

        std::string uid;  // Would be parsed from source prefix
        std::string new_nick = msg.params[0];

        // Update locally
        for (const auto& ch_name : manager_.get_user_channels(uid)) {
            Channel* ch = manager_.get_channel(ch_name);
            if (ch) {
                std::lock_guard<std::mutex> lock(ch->mutex);
                ChannelMembership* m = ch->find_member(uid);
                if (m) m->nick = new_nick;
            }
        }

        // Forward
        flood_message(":" + uid + " NICK " + new_nick + " " +
                      std::to_string(now_ts()), link->remote_sid());
    }

    void handle_s2s_quit(ServerLink* link,
                         const S2SProtocol::ParsedMessage& msg,
                         std::vector<std::string>& responses) {
        (void)responses;
        // :<uid> QUIT :<reason>
        std::string uid;  // From source
        std::string reason = msg.trailing;

        manager_.remove_user_from_all(uid, reason);
        tree_.remove_remote_user(uid);

        flood_message(":" + uid + " QUIT :" + reason,
                      link->remote_sid());
    }

    void handle_s2s_join(ServerLink* link,
                          const S2SProtocol::ParsedMessage& msg,
                          std::vector<std::string>& responses) {
        (void)responses;
        if (msg.params.empty()) return;

        std::string ch_name = msg.params[0];
        std::string uid;  // From source

        // Forward
        flood_message(":" + uid + " JOIN " + ch_name,
                      link->remote_sid());
    }

    void handle_s2s_part(ServerLink* link,
                         const S2SProtocol::ParsedMessage& msg,
                         std::vector<std::string>& responses) {
        (void)responses;
        if (msg.params.empty()) return;

        std::string ch_name = msg.params[0];
        std::string reason = msg.trailing;
        std::string uid;

        manager_.part_channel(ch_name, uid, reason);

        std::string fwd = ":" + uid + " PART " + ch_name;
        if (!reason.empty()) fwd += " :" + reason;
        flood_message(fwd, link->remote_sid());
    }

    void handle_s2s_kick(ServerLink* link,
                         const S2SProtocol::ParsedMessage& msg,
                         std::vector<std::string>& responses) {
        (void)responses;
        if (msg.params.size() < 2) return;

        std::string ch_name = msg.params[0];
        std::string target_nick = msg.params[1];
        std::string reason = msg.trailing;

        Channel* ch = manager_.get_channel(ch_name);
        if (!ch) return;

        ChannelMembership* target = ch->find_member_by_nick(target_nick);
        if (target) {
            ch->remove_member(target->uid, reason);
        }

        std::string fwd = "KICK " + ch_name + " " + target_nick;
        if (!reason.empty()) fwd += " :" + reason;
        flood_message(fwd, link->remote_sid());
    }

    void handle_s2s_mode(ServerLink* link,
                         const S2SProtocol::ParsedMessage& msg,
                         std::vector<std::string>& responses) {
        (void)responses;
        if (msg.params.size() < 2) return;

        std::string ch_name = msg.params[0];
        std::string mode_str = msg.params[1];
        std::vector<std::string> mode_params(
            msg.params.begin() + 2, msg.params.end());

        Channel* ch = manager_.get_channel(ch_name);
        if (!ch) return;

        manager_.set_modes(ch, nullptr, mode_str, mode_params);

        std::string fwd = "MODE " + ch_name + " " + mode_str;
        for (const auto& p : mode_params) fwd += " " + p;
        flood_message(fwd, link->remote_sid());
    }

    void handle_s2s_topic(ServerLink* link,
                          const S2SProtocol::ParsedMessage& msg,
                          std::vector<std::string>& responses) {
        (void)responses;
        if (msg.params.empty()) return;

        std::string ch_name = msg.params[0];
        std::string new_topic = msg.trailing;

        Channel* ch = manager_.get_channel(ch_name);
        if (ch) {
            ch->set_topic(new_topic, "");
        }

        std::string fwd = "TOPIC " + ch_name + " :" + new_topic;
        flood_message(fwd, link->remote_sid());
    }

    void handle_s2s_message(ServerLink* link,
                            const S2SProtocol::ParsedMessage& msg,
                            std::vector<std::string>& responses) {
        (void)responses;
        // PRIVMSG/NOTICE <target> :<text>
        // Check for quiet bans
        if (msg.params.size() >= 1) {
            std::string target = msg.params[0];
            if (!target.empty() && target[0] == '#') {
                Channel* ch = manager_.get_channel(target);
                if (ch) {
                    std::string uid;  // From source
                    ChannelMembership* member = ch->find_member(uid);
                    if (member && ch->is_quiet_banned(
                        member->nick, member->user, member->host,
                        member->account, member->realname, member->certfp)) {
                        // Silently drop
                        return;
                    }
                }
            }
        }

        // Forward
        flood_message(msg.command + " " +
                      (msg.params.size() > 0 ? msg.params[0] : "") +
                      " :" + msg.trailing,
                      link->remote_sid());
    }

    // --- Member variables ---

    ChannelServerConfig config_;
    ChannelManager manager_;
    ServerTree tree_;
    bool running_;

    std::unordered_map<std::string, std::unique_ptr<ServerLink>> active_links_;
    std::unordered_map<std::string, std::string> link_passwords_;
    uint64_t next_uid_seq_;

    // Access for handlers
    std::unordered_map<std::string, RemoteUser> remote_users_;
};

} // namespace irc
} // namespace progressive

// =============================================================================
// End of irc_channel_server.cpp
// =============================================================================
// Lines: ~3500
// Implements: Channel modes (all InspIRCd standard + extended), S2S protocol,
// server tree topology, UID/SID routing, TS sync, persistent channels,
// channel registration, extended bans, quiet bans, channel forwarding,
// auto-join, SSL-only, channel history.
// =============================================================================
