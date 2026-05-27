// =============================================================================
// irc_s2s.cpp - IRC Server-to-Server Protocol Implementation
// =============================================================================
// Comprehensive S2S protocol handler implementing:
//   TS6 / InspIRCd 2.0-style server linking with spanning tree topology.
//   Covers handshake, burst, routing, netsplit recovery, and service commands.
//
// Namespace: progressive::irc
// =============================================================================

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <deque>
#include <queue>
#include <memory>
#include <functional>
#include <algorithm>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <chrono>
#include <optional>
#include <variant>
#include <cstdarg>
#include <cstdio>
#include <random>
#include <cmath>
#include <fstream>

// =============================================================================
// SECTION 1: Utility Helpers
// =============================================================================

namespace progressive {
namespace irc {

namespace s2s_detail {

// Thread-safe timestamp helper
inline int64_t now_ts() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

inline int64_t now_sec() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

// String formatting
inline std::string fmt(const char* format, ...) {
    char buf[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    return std::string(buf);
}

// Split string by delimiter
inline std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> result;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); i++) {
        if (i == s.size() || s[i] == delim) {
            if (i > start) result.push_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return result;
}

// Trim whitespace
inline std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Safe string-to-int64 conversion
inline int64_t safe_atoi64(const std::string& s, int64_t def = 0) {
    try { return std::stoll(s); } catch (...) { return def; }
}

inline int safe_atoi(const std::string& s, int def = 0) {
    try { return std::stoi(s); } catch (...) { return def; }
}

// Case-insensitive comparison for IRC nicks/servers
inline bool iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

inline std::string tolower_str(const std::string& s) {
    std::string r = s;
    for (auto& c : r)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return r;
}

// SHA256-like simple hash for fingerprints (placeholder - in production use OpenSSL)
inline std::string simple_fingerprint(const std::string& data) {
    // Placeholder hash - real implementation would use SHA256
    uint64_t h = 14695981039346656037ULL;
    for (char c : data) {
        h ^= static_cast<uint64_t>(static_cast<unsigned char>(c));
        h *= 1099511628211ULL;
    }
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << h;
    return ss.str();
}

// Base64 encode (simple)
inline std::string base64_encode(const std::string& in) {
    static const char* chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

// Generate random string
inline std::string random_string(size_t length) {
    static const char chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static std::mt19937 rng(static_cast<unsigned>(std::time(nullptr)));
    static std::uniform_int_distribution<size_t> dist(0, sizeof(chars) - 2);
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; i++)
        result += chars[dist(rng)];
    return result;
}

// Wildcard match (for ban masks, etc.)
inline bool wildcard_match(const std::string& text, const std::string& pattern) {
    size_t ti = 0, pi = 0, star_ti = 0;
    size_t star_pi = std::string::npos;
    while (ti < text.size()) {
        if (pi < pattern.size() &&
            (pattern[pi] == '?' ||
             std::tolower(static_cast<unsigned char>(pattern[pi])) ==
                 std::tolower(static_cast<unsigned char>(text[ti])))) {
            ti++; pi++;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
            star_pi = pi++;
            star_ti = ti;
        } else if (star_pi != std::string::npos) {
            pi = star_pi + 1;
            ti = ++star_ti;
        } else {
            return false;
        }
    }
    while (pi < pattern.size() && pattern[pi] == '*') pi++;
    return pi == pattern.size();
}

}  // namespace s2s_detail

using namespace s2s_detail;

// =============================================================================
// SECTION 2: Protocol Constants
// =============================================================================

namespace S2SConstants {

constexpr size_t MAX_SERVER_NAME_LEN     = 64;
constexpr size_t MAX_SERVER_DESC_LEN     = 256;
constexpr size_t MAX_SID_LEN             = 3;
constexpr size_t MAX_UID_LEN             = 9;
constexpr size_t MAX_NICK_LEN            = 30;
constexpr size_t MAX_CHANNEL_LEN         = 64;
constexpr size_t MAX_TOPIC_LEN           = 390;
constexpr size_t MAX_KICK_REASON_LEN     = 255;
constexpr size_t MAX_AWAY_MSG_LEN        = 200;
constexpr size_t MAX_MODES_PER_LINE      = 20;
constexpr size_t MAX_BURST_QUEUE_SIZE    = 10000;
constexpr size_t S2S_MAX_LINKS           = 64;
constexpr size_t DEFAULT_PING_INTERVAL   = 60;     // seconds
constexpr size_t DEFAULT_PING_TIMEOUT    = 180;    // seconds
constexpr int64_t DEFAULT_TS_DELTA       = 60;     // seconds
constexpr int64_t DEFAULT_RECONNECT_DELAY = 30;    // seconds
constexpr uint32_t PROTOCOL_VERSION_MIN  = 1200;
constexpr uint32_t PROTOCOL_VERSION_MAX  = 1205;
constexpr uint32_t PROTOCOL_VERSION_CUR  = 1205;
constexpr const char* PROTOCOL_FLAGS     = "J10";

// Standard capabilities
constexpr const char* CAPAB_NAMES[] = {
    "CHANMODES", "CHANNELLEN", "CHANTYPES", "EXCEPTS", "HALFOP",
    "IDENTIFY-MSG", "INVEX", "KNOCK", "MAXLIST", "NICKLEN", "PREFIX",
    "SAFELIST", "SERVER_MODE", "STATUSMSG", "TOPICLEN", "USERMODES",
    "VL", "WHOX", "UHNAMES", "PROTOCOL", "NAMESX", "CLIENTVER",
    "CHW", "WATCH", "ACCOUNT"
};
constexpr size_t CAPAB_COUNT = sizeof(CAPAB_NAMES) / sizeof(CAPAB_NAMES[0]);

}  // namespace S2SConstants
using namespace S2SConstants;

// =============================================================================
// SECTION 3: Data Structures
// =============================================================================

// --- S2S Link State ---
enum class S2SLinkState : uint8_t {
    DISCONNECTED   = 0,
    CONNECTING     = 1,
    TLS_HANDSHAKE  = 2,
    WAIT_PASS      = 3,
    WAIT_SERVER    = 4,
    WAIT_CAPAB     = 5,
    BURSTING       = 6,
    CONNECTED      = 7,
    CLOSING        = 8,
    CLOSED         = 9,
};

inline const char* link_state_str(S2SLinkState s) {
    switch (s) {
        case S2SLinkState::DISCONNECTED:  return "DISCONNECTED";
        case S2SLinkState::CONNECTING:    return "CONNECTING";
        case S2SLinkState::TLS_HANDSHAKE: return "TLS_HANDSHAKE";
        case S2SLinkState::WAIT_PASS:     return "WAIT_PASS";
        case S2SLinkState::WAIT_SERVER:   return "WAIT_SERVER";
        case S2SLinkState::WAIT_CAPAB:    return "WAIT_CAPAB";
        case S2SLinkState::BURSTING:      return "BURSTING";
        case S2SLinkState::CONNECTED:     return "CONNECTED";
        case S2SLinkState::CLOSING:       return "CLOSING";
        case S2SLinkState::CLOSED:        return "CLOSED";
        default: return "UNKNOWN";
    }
}

// --- Link Direction ---
enum class LinkDirection : uint8_t {
    OUTGOING,  // We initiated the connection
    INCOMING,  // They connected to us
};

// --- S2S Capability flags ---
struct S2SCapabilities {
    bool chw          = false;
    bool namesx       = false;
    bool uhnames      = false;
    bool clientver    = false;
    bool account      = false;
    bool watch        = false;
    bool server_mode  = false;
    bool halfop       = false;
    bool excepts      = false;
    bool invex         = false;
    bool maxlist      = false;
    bool safelist     = false;
    bool whox         = false;
    bool knock        = false;
    bool extsj3       = false;  // Extended SJOIN/SJOIN3
    bool tls          = false;  // Link is TLS encrypted
    bool ziplink      = false;  // Link compression
    bool identify_msg = false;
    uint32_t max_channel_len = 64;
    uint32_t max_nick_len    = 30;
    uint32_t max_topic_len   = 390;

    std::string serialize() const {
        std::string cap;
        if (chw)          cap += " CHW";
        if (namesx)       cap += " NAMESX";
        if (uhnames)      cap += " UHNAMES";
        if (clientver)    cap += " CLIENTVER=3.1";
        if (account)      cap += " ACCOUNT";
        if (watch)        cap += " WATCH";
        if (server_mode)  cap += " SERVER_MODE";
        if (halfop)       cap += " HALFOP";
        if (excepts)      cap += " EXCEPTS";
        if (invex)        cap += " INVEX";
        if (maxlist)      cap += " MAXLIST";
        if (safelist)     cap += " SAFELIST";
        if (whox)          cap += " WHOX";
        if (knock)        cap += " KNOCK";
        if (extsj3)       cap += " EXTSJ3";
        if (ziplink)      cap += " ZIPLINK";
        if (identify_msg) cap += " IDENTIFY-MSG";
        cap += fmt(" CHANNELLEN=%u NICKLEN=%u TOPICLEN=%u",
                    max_channel_len, max_nick_len, max_topic_len);
        return trim(cap);
    }

    static S2SCapabilities parse(const std::string& cap_str) {
        S2SCapabilities caps;
        auto tokens = split(cap_str, ' ');
        for (const auto& t : tokens) {
            if (t == "CHW")              caps.chw = true;
            else if (t == "NAMESX")       caps.namesx = true;
            else if (t == "UHNAMES")      caps.uhnames = true;
            else if (t.find("CLIENTVER") == 0) caps.clientver = true;
            else if (t == "ACCOUNT")      caps.account = true;
            else if (t == "WATCH")        caps.watch = true;
            else if (t == "SERVER_MODE")  caps.server_mode = true;
            else if (t == "HALFOP")       caps.halfop = true;
            else if (t == "EXCEPTS")      caps.excepts = true;
            else if (t == "INVEX")        caps.invex = true;
            else if (t == "MAXLIST")      caps.maxlist = true;
            else if (t == "SAFELIST")     caps.safelist = true;
            else if (t == "WHOX")         caps.whox = true;
            else if (t == "KNOCK")        caps.knock = true;
            else if (t == "EXTSJ3")       caps.extsj3 = true;
            else if (t == "ZIPLINK")      caps.ziplink = true;
            else if (t == "IDENTIFY-MSG") caps.identify_msg = true;
            else if (t.find("CHANNELLEN=") == 0)
                caps.max_channel_len = static_cast<uint32_t>(
                    safe_atoi(t.substr(11), 64));
            else if (t.find("NICKLEN=") == 0)
                caps.max_nick_len = static_cast<uint32_t>(
                    safe_atoi(t.substr(8), 30));
            else if (t.find("TOPICLEN=") == 0)
                caps.max_topic_len = static_cast<uint32_t>(
                    safe_atoi(t.substr(9), 390));
        }
        return caps;
    }
};

// --- Server Node ---
// Represents a server in the IRC network spanning tree
struct S2SServerNode {
    std::string name;            // Full server name: irc.example.com
    std::string sid;             // 3-char server ID: "001", "0AA"
    std::string description;     // Human-readable description
    std::string software;        // Software name/version
    std::string parent_sid;      // Parent SID in tree (empty = root)
    std::string parent_name;     // Parent server name
    int64_t link_ts     = 0;     // When link was established
    int64_t boot_ts     = 0;     // Server boot timestamp
    int64_t ts_delta    = 0;     // Clock offset from us
    S2SLinkState state   = S2SLinkState::DISCONNECTED;
    uint32_t hop_count   = 0;    // Hops from us
    uint32_t protocol_version = PROTOCOL_VERSION_CUR;
    bool burst_complete  = false;
    bool hidden          = false; // Hidden from /links?
    bool is_ulined       = false; // U-lined (services server)
    std::vector<std::string> capabilities;
    std::set<std::string> capab_set;     // Fast lookup
    std::string network_name;
    uint32_t max_global_users = 0;
    int64_t last_netinfo_ts = 0;
    std::string ssl_fingerprint;    // TLS certificate fingerprint
    bool link_encrypted = false;

    bool is_connected() const {
        return state == S2SLinkState::CONNECTED ||
               state == S2SLinkState::BURSTING;
    }
    bool is_bursting() const { return state == S2SLinkState::BURSTING; }
    bool has_capab(const std::string& cap) const {
        return capab_set.count(cap) > 0;
    }
};

// --- Remote User ---
// User record for a client connected to a remote server
struct S2SRemoteUser {
    std::string uid;           // Full UID: SID + 6-char ID
    std::string nick;
    std::string ident;         // ident / username
    std::string host;          // visible host
    std::string realhost;      // real host / cloaked host
    std::string realname;      // GECOS
    std::string server_sid;    // Home server SID
    std::string ip;            // IP address
    std::string account;       // Services account name
    std::string certfp;        // SSL cert fingerprint
    int64_t signon_ts   = 0;
    int64_t last_active  = 0;
    bool is_oper        = false;
    bool is_away        = false;
    bool is_hidden      = false;
    std::string away_msg;
    std::string modes;         // User mode string (+i, +w, +x, etc.)
    std::set<char> mode_set;   // Fast mode lookup
    uint32_t hop_count  = 1;

    std::string mask() const {
        return nick + "!" + ident + "@" + host;
    }
    bool has_mode(char m) const { return mode_set.count(m) > 0; }
};

// --- Burst Queue Entry ---
struct BurstEntry {
    enum class Type : uint8_t {
        UID, FJOIN, SJOIN, TMODE, METADATA, ENCAP, SERVER_INTRO,
    };
    Type type;
    std::string raw_message;
    std::string target_sid;  // Specific server or empty for broadcast
    int64_t timestamp;

    BurstEntry() : type(Type::UID), timestamp(now_ts()) {}
    BurstEntry(Type t, const std::string& msg, const std::string& target = "")
        : type(t), raw_message(msg), target_sid(target), timestamp(now_ts()) {}
};

// =============================================================================
// SECTION 4: S2S Message Builder (Protocol Serialization)
// =============================================================================

class S2SMessageBuilder {
public:
    // --- Handshake messages ---

    // PASS <password> <TS> <protocol_version> [<flags>]
    static std::string pass(const std::string& password, uint32_t proto_ver,
                            const std::string& flags = PROTOCOL_FLAGS) {
        return fmt("PASS %s %lld %u %s",
                   password.c_str(),
                   static_cast<long long>(now_ts()),
                   proto_ver, flags.c_str());
    }

    // SERVER <servername> <hopcount> <boot_ts> <link_ts> <protocol> <sid> :<description>
    static std::string server_intro(const std::string& name,
                                     uint32_t hop_count,
                                     int64_t boot_ts,
                                     const std::string& sid,
                                     const std::string& description) {
        return fmt("SERVER %s %u %lld %lld %s %s :%s",
                   name.c_str(), hop_count,
                   static_cast<long long>(boot_ts),
                   static_cast<long long>(now_ts()),
                   PROTOCOL_FLAGS, sid.c_str(),
                   description.c_str());
    }

    // BURST [<ts>]
    static std::string burst(int64_t ts = 0) {
        if (ts == 0) ts = now_ts();
        return fmt("BURST %lld", static_cast<long long>(ts));
    }

    // ENDBURST (some implementations use ENDOFBURST)
    static std::string endburst() {
        return "ENDBURST";
    }
    static std::string end_of_burst() {
        return "ENDOFBURST";
    }

    // CAPAB :<space_separated_capabilities>
    static std::string capab(const std::string& capabilities) {
        return std::string("CAPAB :") + capabilities;
    }

    // NETINFO <max_global> <current_time> <protocol> <cloak_hash> <0|1> <0|1> :<network_name>
    static std::string netinfo(uint32_t max_global, const std::string& network_name,
                                int64_t ts = 0) {
        if (ts == 0) ts = now_ts();
        return fmt("NETINFO %u %lld %u 1 0 0 :%s",
                   max_global, static_cast<long long>(ts),
                   PROTOCOL_VERSION_CUR, network_name.c_str());
    }

    // --- User messages ---

    // UID <nick> <hopcount> <ts> +<modes> <ident> <host> <uid>
    //     <realhost_ip> <cloaked_host> :<realname>
    static std::string uid(const std::string& nick, uint32_t hop_count,
                           int64_t signon_ts, const std::string& user_modes,
                           const std::string& ident, const std::string& host,
                           const std::string& uid, const std::string& ip,
                           const std::string& realhost,
                           const std::string& realname) {
        return fmt("UID %s %u %lld +%s %s %s %s %s %s :%s",
                   nick.c_str(), hop_count,
                   static_cast<long long>(signon_ts),
                   user_modes.c_str(), ident.c_str(), host.c_str(),
                   uid.c_str(), ip.c_str(), realhost.c_str(),
                   realname.c_str());
    }

    // NICK <uid> <newnick> <ts>
    static std::string nick_change(const std::string& uid,
                                    const std::string& new_nick,
                                    int64_t ts = 0) {
        if (ts == 0) ts = now_ts();
        return fmt("NICK %s %s %lld",
                   uid.c_str(), new_nick.c_str(),
                   static_cast<long long>(ts));
    }

    // QUIT :<reason>
    static std::string quit(const std::string& uid, const std::string& reason) {
        return fmt("QUIT %s :%s", uid.c_str(), reason.c_str());
    }

    // --- Channel messages ---

    // FJOIN <channel> <ts> +<modes> :<prefix_nick_pairs>
    static std::string fjoin(const std::string& channel, int64_t channel_ts,
                              const std::string& chan_modes,
                              const std::string& member_list) {
        return fmt("FJOIN %s %lld +%s :%s",
                   channel.c_str(),
                   static_cast<long long>(channel_ts),
                   chan_modes.c_str(), member_list.c_str());
    }

    // SJOIN <channel> <ts> +<modes> :<prefix_nick_pairs>
    static std::string sjoin(const std::string& channel, int64_t channel_ts,
                              const std::string& chan_modes,
                              const std::string& member_list) {
        return fmt("SJOIN %s %lld +%s :%s",
                   channel.c_str(),
                   static_cast<long long>(channel_ts),
                   chan_modes.c_str(), member_list.c_str());
    }

    // TMODE <channel> <ts> +<modes> [params...]
    static std::string tmode(const std::string& channel, int64_t ts,
                              const std::string& mode_str) {
        return fmt("TMODE %s %lld %s",
                   channel.c_str(),
                   static_cast<long long>(ts), mode_str.c_str());
    }

    // --- Service-forced commands ---

    // SVSNICK <uid> <newnick> <ts>
    static std::string svsnick(const std::string& uid,
                                const std::string& new_nick,
                                int64_t ts = 0) {
        if (ts == 0) ts = now_ts();
        return fmt("SVSNICK %s %s %lld",
                   uid.c_str(), new_nick.c_str(),
                   static_cast<long long>(ts));
    }

    // SVSMODE <uid> <ts> +<modes>
    static std::string svsmode(const std::string& uid,
                                const std::string& modes,
                                int64_t ts = 0) {
        if (ts == 0) ts = now_ts();
        return fmt("SVSMODE %s %lld +%s",
                   uid.c_str(),
                   static_cast<long long>(ts), modes.c_str());
    }

    // SVSJOIN <uid> <channel>
    static std::string svsjoin(const std::string& uid,
                                const std::string& channel) {
        return fmt("SVSJOIN %s %s", uid.c_str(), channel.c_str());
    }

    // SVSPART <uid> <channel> [:reason]
    static std::string svspart(const std::string& uid,
                                const std::string& channel,
                                const std::string& reason = "") {
        if (reason.empty())
            return fmt("SVSPART %s %s", uid.c_str(), channel.c_str());
        return fmt("SVSPART %s %s :%s",
                   uid.c_str(), channel.c_str(), reason.c_str());
    }

    // --- Management commands ---

    // KILL <uid> :<reason>
    static std::string kill(const std::string& uid,
                             const std::string& reason) {
        return fmt("KILL %s :%s", uid.c_str(), reason.c_str());
    }

    // SQUIT <sid> :<reason>
    static std::string squit(const std::string& sid,
                              const std::string& reason) {
        return fmt("SQUIT %s :%s", sid.c_str(), reason.c_str());
    }

    // SQUIT <server_name> :<reason> (by name variant)
    static std::string squit_by_name(const std::string& server_name,
                                      const std::string& reason) {
        return fmt("SQUIT %s :%s", server_name.c_str(), reason.c_str());
    }

    // PING <sid> <token>
    static std::string ping(const std::string& source_sid,
                             const std::string& token) {
        return fmt(":%s PING %s :%s",
                   source_sid.c_str(), source_sid.c_str(), token.c_str());
    }

    // PONG <sid> <token>
    static std::string pong(const std::string& source_sid,
                             const std::string& token) {
        return fmt(":%s PONG %s :%s",
                   source_sid.c_str(), source_sid.c_str(), token.c_str());
    }

    // SERVER <name> <hopcount> <ts> <proto> <sid> :<desc>
    // (for passing through server introductions from other links)
    static std::string server_pass_on(const std::string& name,
                                       uint32_t hop_count,
                                       int64_t boot_ts, int64_t link_ts,
                                       const std::string& sid,
                                       const std::string& description) {
        return fmt("SERVER %s %u %lld %lld %s %s :%s",
                   name.c_str(), hop_count,
                   static_cast<long long>(boot_ts),
                   static_cast<long long>(link_ts),
                   PROTOCOL_FLAGS, sid.c_str(),
                   description.c_str());
    }

    // AWAY <uid> :<message> (empty message to unset)
    static std::string away(const std::string& uid, const std::string& msg) {
        return fmt(":%s AWAY :%s", uid.c_str(), msg.c_str());
    }

    // OPER <uid>
    static std::string oper(const std::string& uid) {
        return fmt("OPER %s", uid.c_str());
    }

    // MODE <uid> +<modes>
    static std::string user_mode(const std::string& uid,
                                  const std::string& modes) {
        return fmt("MODE %s +%s", uid.c_str(), modes.c_str());
    }

    // METADATA <uid> <key> :<value>
    static std::string metadata(const std::string& uid,
                                 const std::string& key,
                                 const std::string& value) {
        return fmt("METADATA %s %s :%s",
                   uid.c_str(), key.c_str(), value.c_str());
    }

    // ENCAP <target_sid> <subcommand> <params...>
    static std::string encap(const std::string& target_sid,
                              const std::string& subcommand,
                              const std::string& params) {
        return fmt("ENCAP %s %s %s",
                   target_sid.c_str(), subcommand.c_str(), params.c_str());
    }

    // Error
    static std::string error(const std::string& message) {
        return fmt("ERROR :%s", message.c_str());
    }

    // VERSION <sid> :<version_string>
    static std::string version_reply(const std::string& sid,
                                      const std::string& version) {
        return fmt("VERSION %s :%s", sid.c_str(), version.c_str());
    }

    // WALLOPS :<message>
    static std::string wallops(const std::string& message) {
        return fmt("WALLOPS :%s", message.c_str());
    }
};

// =============================================================================
// SECTION 5: S2S Message Parser
// =============================================================================

struct S2SParsedMessage {
    std::string raw;
    std::string prefix;       // Source prefix (server name or SID)
    std::string command;      // PASS, SERVER, UID, FJOIN, etc.
    std::vector<std::string> params;  // Space-separated params
    std::string trailing;     // After the : delimiter
    bool has_prefix = false;
    int64_t received_ts;

    S2SParsedMessage() : received_ts(now_ts()) {}

    // Get param safely
    std::string param(size_t idx) const {
        return idx < params.size() ? params[idx] : "";
    }
    int64_t param_int64(size_t idx, int64_t def = 0) const {
        return idx < params.size() ? safe_atoi64(params[idx], def) : def;
    }
    int param_int(size_t idx, int def = 0) const {
        return idx < params.size() ? safe_atoi(params[idx], def) : def;
    }

    static S2SParsedMessage parse(const std::string& raw_line) {
        S2SParsedMessage msg;
        msg.raw = raw_line;
        if (raw_line.empty()) return msg;

        std::string line = raw_line;
        // Strip \r\n
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();

        const char* p = line.c_str();
        const char* end = p + line.size();

        // Parse optional prefix: :server.name CMD ...
        if (*p == ':') {
            p++;
            const char* space = static_cast<const char*>(memchr(p, ' ', end - p));
            if (space) {
                msg.prefix = std::string(p, space - p);
                msg.has_prefix = true;
                p = space + 1;
            } else {
                // Whole line is prefix? Unusual but handle it
                msg.prefix = std::string(p, end - p);
                msg.has_prefix = true;
                return msg;
            }
        }

        // Command
        const char* cmd_start = p;
        while (p < end && *p != ' ') p++;
        msg.command = std::string(cmd_start, p - cmd_start);
        // Uppercase the command for case-insensitive matching
        for (auto& c : msg.command)
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

        // Skip spaces after command
        while (p < end && *p == ' ') p++;

        // Parameters and trailing
        while (p < end) {
            if (*p == ':') {
                // Everything from here to end is trailing
                msg.trailing = std::string(p + 1, end - p - 1);
                break;
            }
            const char* start = p;
            while (p < end && *p != ' ') p++;
            msg.params.push_back(std::string(start, p - start));
            while (p < end && *p == ' ') p++;
        }

        return msg;
    }
};

// =============================================================================
// SECTION 6: SSL/TLS Certificate Management (Placeholder)
// =============================================================================

// In production this would use OpenSSL. This provides the interface and
// configuration logic for certificate-pinned server links.

class S2SCertificateManager {
public:
    struct CertificateFingerprint {
        std::string server_name;
        std::string fingerprint;   // SHA256 hex digest
        bool trusted = false;
        int64_t added_ts = 0;
    };

    S2SCertificateManager() = default;

    // Add a trusted server fingerprint
    void add_trusted_fingerprint(const std::string& server_name,
                                  const std::string& fp) {
        std::lock_guard<std::mutex> lock(mutex_);
        CertificateFingerprint cf;
        cf.server_name = server_name;
        cf.fingerprint = fp;
        cf.trusted = true;
        cf.added_ts = now_ts();
        trusted_fingerprints_[server_name] = cf;
    }

    // Check if a fingerprint is trusted for a given server
    bool is_fingerprint_trusted(const std::string& server_name,
                                 const std::string& fp) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = trusted_fingerprints_.find(server_name);
        if (it == trusted_fingerprints_.end()) return false;
        return it->second.trusted &&
               iequals(it->second.fingerprint, fp);
    }

    // Auto-trust on first connect (TOFU - Trust On First Use)
    void trust_on_first_use(const std::string& server_name,
                            const std::string& fp) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = trusted_fingerprints_.find(server_name);
        if (it == trusted_fingerprints_.end()) {
            CertificateFingerprint cf;
            cf.server_name = server_name;
            cf.fingerprint = fp;
            cf.trusted = true;
            cf.added_ts = now_ts();
            trusted_fingerprints_[server_name] = cf;
        }
    }

    // Remove trust
    void remove_trust(const std::string& server_name) {
        std::lock_guard<std::mutex> lock(mutex_);
        trusted_fingerprints_.erase(server_name);
    }

    // Get fingerprint for a server
    std::optional<std::string> get_fingerprint(const std::string& server_name) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = trusted_fingerprints_.find(server_name);
        if (it != trusted_fingerprints_.end())
            return it->second.fingerprint;
        return std::nullopt;
    }

    // Check if we have a trusted fingerprint for this server
    bool has_fingerprint(const std::string& server_name) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return trusted_fingerprints_.count(server_name) > 0;
    }

    // SSL Context configuration (placeholder -- in production use OpenSSL context)
    struct SSLConfig {
        std::string cert_file;
        std::string key_file;
        std::string ca_file;
        bool verify_peer = true;
        bool require_client_cert = false;
        int ssl_protocol_version = 0;  // 0 = auto-negotiate best
    };

    void configure_ssl(const SSLConfig& config) {
        ssl_config_ = config;
    }

    const SSLConfig& ssl_config() const { return ssl_config_; }

    // Simulate verification of a peer certificate
    bool verify_peer_certificate(const std::string& server_name,
                                  const std::string& peer_fingerprint) {
        // If we have a trusted fingerprint, verify against it
        if (has_fingerprint(server_name)) {
            return is_fingerprint_trusted(server_name, peer_fingerprint);
        }
        // If TOFU is enabled (no fingerprint yet), accept and record
        if (ssl_config_.verify_peer) {
            trust_on_first_use(server_name, peer_fingerprint);
            return true;
        }
        return !ssl_config_.verify_peer;  // If peer verification is off, accept
    }

private:
    std::unordered_map<std::string, CertificateFingerprint> trusted_fingerprints_;
    mutable std::mutex mutex_;
    SSLConfig ssl_config_;
};

// =============================================================================
// SECTION 7: Burst Queue Manager
// =============================================================================

class S2SBurstQueue {
public:
    S2SBurstQueue() : max_size_(MAX_BURST_QUEUE_SIZE), enabled_(true) {}

    explicit S2SBurstQueue(size_t max_size)
        : max_size_(max_size), enabled_(true) {}

    // Queue a message during burst
    bool enqueue(BurstEntry::Type type, const std::string& message,
                 const std::string& target_sid = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!enabled_) return false;
        if (queue_.size() >= max_size_) {
            // Drop oldest if queue full
            queue_.pop_front();
        }
        queue_.emplace_back(type, message, target_sid);
        return true;
    }

    // Flush all queued messages to a callback
    size_t flush(std::function<void(BurstEntry::Type, const std::string&,
                                     const std::string&)> callback) {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = queue_.size();
        while (!queue_.empty()) {
            auto& entry = queue_.front();
            callback(entry.type, entry.raw_message, entry.target_sid);
            queue_.pop_front();
        }
        return count;
    }

    // Get queued message count
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    // Clear the queue
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
    }

    // Enable/disable burst queueing
    void set_enabled(bool enabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        enabled_ = enabled;
    }

    bool is_enabled() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return enabled_;
    }

    // Drain all pending (used during netsplit to avoid sending stale data)
    void drain() {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
    }

    // Get entries without removing them (for re-sending)
    std::vector<BurstEntry> snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return std::vector<BurstEntry>(queue_.begin(), queue_.end());
    }

private:
    std::deque<BurstEntry> queue_;
    size_t max_size_;
    bool enabled_;
    mutable std::mutex mutex_;
};

// =============================================================================
// SECTION 8: UID Generator
// =============================================================================

class S2SUIDGenerator {
public:
    S2SUIDGenerator(const std::string& sid)
        : sid_(sid), seq_(0) {
        // Validate SID
        if (sid_.size() > MAX_SID_LEN) {
            sid_ = sid_.substr(0, MAX_SID_LEN);
        }
    }

    // Generate the next unique UID
    std::string next_uid() {
        uint64_t seq;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            seq = seq_++;
        }
        char buf[16];
        // Format: SID + 6 hex digits
        snprintf(buf, sizeof(buf), "%s%06llX",
                 sid_.c_str(),
                 static_cast<unsigned long long>(seq & 0xFFFFFF));
        return std::string(buf);
    }

    // Peek at next UID without incrementing
    std::string peek_uid() const {
        std::lock_guard<std::mutex> lock(mutex_);
        char buf[16];
        snprintf(buf, sizeof(buf), "%s%06llX",
                 sid_.c_str(),
                 static_cast<unsigned long long>(seq_ & 0xFFFFFF));
        return std::string(buf);
    }

    // Reset sequence (dangerous - only for testing)
    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        seq_ = 0;
    }

    // Set sequence to a specific value (for recovery)
    void set_seq(uint64_t s) {
        std::lock_guard<std::mutex> lock(mutex_);
        seq_ = s;
    }

    // Get the SID component
    const std::string& sid() const { return sid_; }

private:
    std::string sid_;
    uint64_t seq_;
    mutable std::mutex mutex_;
};

// =============================================================================
// SECTION 9: SID-Based Routing Table
// =============================================================================

class S2SRoutingTable {
public:
    S2SRoutingTable() = default;

    // Set our own SID
    void set_local_sid(const std::string& sid) {
        our_sid_ = sid;
    }

    const std::string& local_sid() const { return our_sid_; }

    // --- Server tree management ---

    // Add a server to the routing table
    bool add_server(const std::string& name, const std::string& sid,
                    const std::string& parent_sid,
                    const std::string& description,
                    int64_t boot_ts = 0) {
        std::lock_guard<std::shared_mutex> lock(mutex_);

        // Check for duplicate SID
        if (servers_.count(sid) > 0) return false;

        // Validate parent exists (unless this is the root/our server)
        if (parent_sid != our_sid_ && servers_.count(parent_sid) == 0) {
            return false;  // Orphan - parent doesn't exist
        }

        // Check for loops
        if (would_create_loop(sid, parent_sid)) return false;

        S2SServerNode node;
        node.name = name;
        node.sid = sid;
        node.parent_sid = parent_sid;
        node.description = description;
        node.state = S2SLinkState::CONNECTED;
        node.link_ts = now_ts();
        node.boot_ts = (boot_ts > 0) ? boot_ts : now_ts();
        node.ts_delta = node.boot_ts - now_ts();

        // Calculate hop count
        if (parent_sid == our_sid_ || parent_sid.empty()) {
            node.hop_count = 1;
        } else {
            auto pit = servers_.find(parent_sid);
            node.hop_count = (pit != servers_.end()) ? pit->second.hop_count + 1 : 1;
        }

        servers_[sid] = std::move(node);
        name_to_sid_[tolower_str(name)] = sid;
        return true;
    }

    // Remove a server and all its descendants
    bool remove_server(const std::string& sid) {
        std::lock_guard<std::shared_mutex> lock(mutex_);

        if (servers_.count(sid) == 0) return false;

        // Collect all descendants
        std::vector<std::string> to_remove;
        collect_descendants(sid, to_remove);

        for (const auto& s : to_remove) {
            auto it = servers_.find(s);
            if (it != servers_.end()) {
                name_to_sid_.erase(tolower_str(it->second.name));
                servers_.erase(it);
            }
        }
        return true;
    }

    // Get a server by SID
    S2SServerNode* get_server(const std::string& sid) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = servers_.find(sid);
        return (it != servers_.end()) ? &it->second : nullptr;
    }

    const S2SServerNode* get_server(const std::string& sid) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = servers_.find(sid);
        return (it != servers_.end()) ? &it->second : nullptr;
    }

    // Get server by name
    S2SServerNode* get_server_by_name(const std::string& name) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = name_to_sid_.find(tolower_str(name));
        if (it == name_to_sid_.end()) return nullptr;
        auto sit = servers_.find(it->second);
        return (sit != servers_.end()) ? &sit->second : nullptr;
    }

    // Check if a server exists
    bool has_server(const std::string& sid) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return servers_.count(sid) > 0;
    }

    // --- Routing ---

    // Get the next-hop SID to reach a target server
    std::string get_next_hop(const std::string& target_sid) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);

        if (target_sid == our_sid_) return our_sid_;

        auto it = servers_.find(target_sid);
        if (it == servers_.end()) {
            // Unknown server - return empty (broadcast needed)
            return "";
        }

        // Walk up from target to find our direct child
        std::string current = target_sid;
        int max_hops = 256;  // Safety limit
        while (current != our_sid_ && !current.empty() && max_hops-- > 0) {
            auto cur = servers_.find(current);
            if (cur == servers_.end()) return "";
            if (cur->second.parent_sid == our_sid_)
                return current;  // Direct neighbor
            current = cur->second.parent_sid;
        }
        return current;
    }

    // Get all direct neighbors (servers linked directly to us)
    std::vector<std::string> get_direct_neighbors() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<std::string> result;
        for (const auto& [sid, node] : servers_) {
            if (node.parent_sid == our_sid_ && node.is_connected()) {
                result.push_back(sid);
            }
        }
        return result;
    }

    // Get flood targets: all direct neighbors except the exclude
    std::vector<std::string> get_flood_targets(
        const std::string& exclude_sid = "") const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<std::string> result;
        for (const auto& [sid, node] : servers_) {
            if (sid == our_sid_) continue;
            if (sid == exclude_sid) continue;
            if (node.is_connected() && node.parent_sid == our_sid_) {
                result.push_back(sid);
            }
        }
        return result;
    }

    // Get the SID from a UID (first 3 chars)
    static std::string uid_to_sid(const std::string& uid) {
        return uid.size() >= 3 ? uid.substr(0, 3) : "";
    }

    // Check if a UID is local
    bool is_local_uid(const std::string& uid) const {
        return uid.size() >= 3 && uid.substr(0, 3) == our_sid_;
    }

    // Get all server names for /links /map
    std::vector<const S2SServerNode*> get_all_servers() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<const S2SServerNode*> result;
        result.reserve(servers_.size());
        for (const auto& [sid, node] : servers_) {
            result.push_back(&node);
        }
        std::sort(result.begin(), result.end(),
                  [this](const S2SServerNode* a, const S2SServerNode* b) {
                      if (a->sid == our_sid_) return true;
                      if (b->sid == our_sid_) return false;
                      if (a->hop_count != b->hop_count)
                          return a->hop_count < b->hop_count;
                      return a->name < b->name;
                  });
        return result;
    }

    // --- Spanning tree helpers ---

    // Check if adding a server would create a cycle
    bool would_create_loop(const std::string& sid,
                           const std::string& parent_sid) const {
        // Walk from parent_sid up to root; if we hit 'sid', that's a loop
        std::string current = parent_sid;
        int max_depth = 256;
        while (current != our_sid_ && !current.empty() && max_depth-- > 0) {
            if (current == sid) return true;
            auto it = servers_.find(current);
            if (it == servers_.end()) break;
            current = it->second.parent_sid;
        }
        return false;
    }

    // Get the path from us to a target SID
    std::vector<std::string> get_path(const std::string& target_sid) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
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
        if (current == our_sid_)
            path.insert(path.begin(), our_sid_);
        else
            path.clear();
        return path;
    }

    // --- U-lined servers (services) ---

    void set_ulined(const std::string& sid, bool ulined) {
        std::lock_guard<std::shared_mutex> lock(mutex_);
        auto it = servers_.find(sid);
        if (it != servers_.end()) {
            it->second.is_ulined = ulined;
        }
    }

    bool is_ulined(const std::string& sid) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = servers_.find(sid);
        return (it != servers_.end()) ? it->second.is_ulined : false;
    }

    // --- Counts ---
    size_t server_count() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return servers_.size();
    }

private:
    void collect_descendants(const std::string& sid,
                             std::vector<std::string>& result) {
        result.push_back(sid);
        for (const auto& [csid, node] : servers_) {
            if (node.parent_sid == sid) {
                collect_descendants(csid, result);
            }
        }
    }

    std::string our_sid_;
    std::unordered_map<std::string, S2SServerNode> servers_;
    std::unordered_map<std::string, std::string> name_to_sid_;
    mutable std::shared_mutex mutex_;
};

// =============================================================================
// SECTION 10: Remote User Registry
// =============================================================================

class S2SRemoteUserRegistry {
public:
    S2SRemoteUserRegistry() = default;

    // Add a remote user
    void add_user(const S2SRemoteUser& user) {
        std::lock_guard<std::shared_mutex> lock(mutex_);
        users_by_uid_[user.uid] = user;
        if (!user.nick.empty())
            users_by_nick_[tolower_str(user.nick)] = user.uid;
    }

    // Remove a user by UID
    bool remove_user(const std::string& uid) {
        std::lock_guard<std::shared_mutex> lock(mutex_);
        auto it = users_by_uid_.find(uid);
        if (it == users_by_uid_.end()) return false;
        users_by_nick_.erase(tolower_str(it->second.nick));
        users_by_uid_.erase(it);
        return true;
    }

    // Remove all users on a server (netsplit)
    size_t remove_users_on_server(const std::string& sid) {
        std::lock_guard<std::shared_mutex> lock(mutex_);
        size_t count = 0;
        auto it = users_by_uid_.begin();
        while (it != users_by_uid_.end()) {
            if (it->second.server_sid == sid) {
                users_by_nick_.erase(tolower_str(it->second.nick));
                it = users_by_uid_.erase(it);
                ++count;
            } else {
                ++it;
            }
        }
        return count;
    }

    // Get user by UID
    S2SRemoteUser* get_user_by_uid(const std::string& uid) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = users_by_uid_.find(uid);
        return (it != users_by_uid_.end()) ? &it->second : nullptr;
    }

    // Get user by nick
    S2SRemoteUser* get_user_by_nick(const std::string& nick) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = users_by_nick_.find(tolower_str(nick));
        if (it == users_by_nick_.end()) return nullptr;
        auto uit = users_by_uid_.find(it->second);
        return (uit != users_by_uid_.end()) ? &uit->second : nullptr;
    }

    // Update nick
    bool update_nick(const std::string& uid, const std::string& new_nick) {
        std::lock_guard<std::shared_mutex> lock(mutex_);
        auto it = users_by_uid_.find(uid);
        if (it == users_by_uid_.end()) return false;
        users_by_nick_.erase(tolower_str(it->second.nick));
        it->second.nick = new_nick;
        users_by_nick_[tolower_str(new_nick)] = uid;
        return true;
    }

    // Check if nick exists
    bool has_nick(const std::string& nick) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return users_by_nick_.count(tolower_str(nick)) > 0;
    }

    // Get all users on a specific server
    std::vector<S2SRemoteUser> users_on_server(const std::string& sid) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<S2SRemoteUser> result;
        for (const auto& [uid, user] : users_by_uid_) {
            if (user.server_sid == sid) result.push_back(user);
        }
        return result;
    }

    // Total user count
    size_t user_count() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return users_by_uid_.size();
    }

    // Clear all users
    void clear() {
        std::lock_guard<std::shared_mutex> lock(mutex_);
        users_by_uid_.clear();
        users_by_nick_.clear();
    }

private:
    std::unordered_map<std::string, S2SRemoteUser> users_by_uid_;
    std::unordered_map<std::string, std::string> users_by_nick_;
    mutable std::shared_mutex mutex_;
};

// =============================================================================
// SECTION 11: Channel TS Synchronization
// =============================================================================

class S2SChannelSync {
public:
    S2SChannelSync() = default;

    // Record channel creation TS received via burst
    void set_channel_ts(const std::string& channel, int64_t ts,
                        const std::string& source_sid) {
        std::lock_guard<std::shared_mutex> lock(mutex_);
        ChannelTSInfo info;
        info.ts = ts;
        info.source_sid = source_sid;
        info.last_updated = now_ts();
        channel_ts_[tolower_str(channel)] = info;
    }

    // Get the known TS for a channel
    int64_t get_channel_ts(const std::string& channel) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = channel_ts_.find(tolower_str(channel));
        return (it != channel_ts_.end()) ? it->second.ts : 0;
    }

    // Resolve TS conflict: lower TS wins
    // Returns true if our TS should be accepted over theirs
    bool resolve_ts_conflict(const std::string& channel,
                              int64_t remote_ts,
                              int64_t local_ts) const {
        if (remote_ts == 0) return true;   // They don't know, we win
        if (local_ts == 0) return false;    // We don't know, they win
        if (remote_ts < local_ts) return false;  // They're older, they win
        return true;  // We're older (or equal, we win)
    }

    // Check if a remote mode change should be applied
    bool should_apply_tmode(const std::string& channel,
                             int64_t remote_ts,
                             int64_t our_channel_ts) const {
        // If remote TS is older, accept; if newer, reject
        if (remote_ts < our_channel_ts) return true;
        if (remote_ts > our_channel_ts) return false;
        // Equal TS - apply (tiebreak could be by SID but simpler to apply)
        return true;
    }

    // Remove channel TS data
    void remove_channel(const std::string& channel) {
        std::lock_guard<std::shared_mutex> lock(mutex_);
        channel_ts_.erase(tolower_str(channel));
    }

    // Clear all data (for netsplit recovery)
    void clear() {
        std::lock_guard<std::shared_mutex> lock(mutex_);
        channel_ts_.clear();
    }

private:
    struct ChannelTSInfo {
        int64_t ts = 0;
        std::string source_sid;
        int64_t last_updated = 0;
    };
    std::unordered_map<std::string, ChannelTSInfo> channel_ts_;
    mutable std::shared_mutex mutex_;
};

// =============================================================================
// SECTION 12: NetSplit Manager
// =============================================================================

class S2SNetsplitManager {
public:
    S2SNetsplitManager() = default;

    // Record a netsplit event
    struct NetsplitEvent {
        std::string server_sid;
        std::string server_name;
        std::string reason;
        int64_t split_ts;
        std::vector<std::string> affected_servers;  // All SIDs that split off
        size_t users_lost = 0;
    };

    // Start tracking a split
    void begin_split(const std::string& server_sid,
                     const std::string& server_name,
                     const std::string& reason,
                     const std::vector<std::string>& affected_servers) {
        std::lock_guard<std::mutex> lock(mutex_);
        NetsplitEvent event;
        event.server_sid = server_sid;
        event.server_name = server_name;
        event.reason = reason;
        event.split_ts = now_ts();
        event.affected_servers = affected_servers;
        active_splits_[server_sid] = event;
    }

    // End a split (server reconnects)
    void end_split(const std::string& server_sid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = active_splits_.find(server_sid);
        if (it != active_splits_.end()) {
            past_splits_.push_back(it->second);
            active_splits_.erase(it);
            // Limit history
            while (past_splits_.size() > 1000) past_splits_.pop_front();
        }
    }

    // Check if a SID is currently split
    bool is_split(const std::string& sid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return active_splits_.count(sid) > 0;
    }

    // Get active split events
    std::vector<NetsplitEvent> active_events() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<NetsplitEvent> result;
        for (const auto& [sid, event] : active_splits_)
            result.push_back(event);
        return result;
    }

    // Get past split events
    std::vector<NetsplitEvent> past_events() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return std::vector<NetsplitEvent>(past_splits_.begin(),
                                           past_splits_.end());
    }

    // Generate quit messages for split users
    std::string split_quit_message(const std::string& server1,
                                    const std::string& server2) const {
        return server1 + " " + server2;
    }

    // Clear all state
    void clear_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        active_splits_.clear();
        past_splits_.clear();
    }

private:
    std::unordered_map<std::string, NetsplitEvent> active_splits_;
    std::deque<NetsplitEvent> past_splits_;
    mutable std::mutex mutex_;
};

// =============================================================================
// SECTION 13: Link Compression Support
// =============================================================================

class S2SCompression {
public:
    S2SCompression() : enabled_(false), compression_level_(6), algo_("zlib") {}

    void set_enabled(bool enabled) { enabled_ = enabled; }
    bool is_enabled() const { return enabled_; }

    void set_level(int level) {
        compression_level_ = std::max(1, std::min(9, level));
    }
    int level() const { return compression_level_; }

    void set_algorithm(const std::string& algo) { algo_ = algo; }
    const std::string& algorithm() const { return algo_; }

    // Compress data (placeholder - real impl uses zlib)
    std::string compress(const std::string& data) {
        if (!enabled_ || data.empty()) return data;
        // In production: use zlib deflate
        // For now, minimal placeholder: prefix with compression marker
        // Real implementation would use zlib compress/deflate
        std::string result;
        result.reserve(data.size() + 1);
        result += '\x01';  // Compression marker
        // TODO: actual zlib compression
        result += data;    // Placeholder: send uncompressed
        return result;
    }

    // Decompress data
    std::string decompress(const std::string& data) {
        if (!enabled_ || data.empty()) return data;
        if (data[0] == '\x01') {
            // Compressed frame
            return data.substr(1);  // Placeholder: strip marker, data was uncompressed
        }
        return data;  // Uncompressed frame
    }

private:
    bool enabled_;
    int compression_level_;
    std::string algo_;
};

// =============================================================================
// SECTION 14: Server Link Handshake Handler
// =============================================================================

// Forward declaration
class S2SProtocolEngine;

// Outgoing connection attempt record
struct S2SOutgoingAttempt {
    std::string server_name;
    std::string host;
    int port = 7000;
    std::string password;
    std::string bind_address;
    bool use_tls = true;
    bool auto_reconnect = true;
    int reconnect_delay = 30;
    int max_retries = 0;  // 0 = unlimited
    int retries = 0;
    int64_t last_attempt = 0;
    int64_t next_attempt = 0;
};

// =============================================================================
// SECTION 15: Main S2S Protocol Engine
// =============================================================================

class S2SProtocolEngine {
public:
    S2SProtocolEngine() = default;

    // =====================================================================
    // Initialization
    // =====================================================================

    void set_local_server(const std::string& name, const std::string& sid,
                          const std::string& description,
                          const std::string& network_name = "progressive") {
        local_name_ = name;
        local_sid_ = sid;
        local_desc_ = description;
        local_network_ = network_name;
        local_boot_ts_ = now_ts();

        routing_.set_local_sid(sid);
        uid_gen_ = std::make_unique<S2SUIDGenerator>(sid);

        // Register ourselves in the routing table
        routing_.add_server(name, sid, "", description, local_boot_ts_);
    }

    const std::string& local_name() const { return local_name_; }
    const std::string& local_sid() const { return local_sid_; }
    const std::string& local_desc() const { return local_desc_; }
    const std::string& local_network() const { return local_network_; }
    int64_t local_boot_ts() const { return local_boot_ts_; }

    // =====================================================================
    // Link Configuration
    // =====================================================================

    // Add an outgoing link definition
    void add_link_block(const std::string& name, const std::string& host,
                        int port, const std::string& password,
                        bool auto_connect = false, bool tls = true,
                        const std::string& bind_addr = "") {
        S2SOutgoingAttempt link;
        link.server_name = name;
        link.host = host;
        link.port = port;
        link.password = password;
        link.use_tls = tls;
        link.auto_reconnect = auto_connect;
        link.bind_address = bind_addr;
        outgoing_links_[tolower_str(name)] = link;
    }

    // Register link password for incoming connections
    void register_incoming_password(const std::string& server_name,
                                     const std::string& password) {
        incoming_passwords_[tolower_str(server_name)] = password;
    }

    // =====================================================================
    // Connection Handshake (Incoming)
    // =====================================================================

    // Process a line from an S2S connection
    // Returns the response to send, or empty if no immediate response
    struct HandshakeResult {
        std::string response;              // Line to send back
        bool handshake_complete = false;   // Handshake finished
        bool accepted = false;            // Connection accepted
        bool error = false;               // Error occurred
        std::string error_reason;
        std::string remote_sid;           // Remote server SID (if known)
    };

    // Handle a handshake line from a connecting server
    HandshakeResult process_incoming_line(const std::string& line,
                                           S2SLinkState& state,
                                           std::string& remote_sid) {
        HandshakeResult result;
        auto msg = S2SParsedMessage::parse(line);

        if (msg.command.empty()) {
            result.error = true;
            result.error_reason = "Empty line";
            return result;
        }

        switch (state) {
            case S2SLinkState::WAIT_PASS:
                return handle_incoming_pass(msg, state, remote_sid, result);

            case S2SLinkState::WAIT_SERVER:
                return handle_incoming_server(msg, state, remote_sid, result);

            case S2SLinkState::WAIT_CAPAB:
                return handle_incoming_capab(msg, state, remote_sid, result);

            case S2SLinkState::BURSTING:
                return handle_incoming_bursting(msg, state, remote_sid, result);

            case S2SLinkState::CONNECTED:
                // Normal message dispatching (not handshake)
                result.handshake_complete = true;
                result.accepted = true;
                result.remote_sid = remote_sid;
                return result;

            default:
                result.error = true;
                result.error_reason = fmt("Unexpected state: %s",
                                           link_state_str(state));
                return result;
        }
    }

    // =====================================================================
    // Handshake sub-handlers
    // =====================================================================

    HandshakeResult handle_incoming_pass(const S2SParsedMessage& msg,
                                          S2SLinkState& state,
                                          std::string& remote_sid,
                                          HandshakeResult& result) {
        // PASS <password> <ts> <protocol> [flags]
        if (msg.params.size() < 3) {
            result.error = true;
            result.error_reason = "Invalid PASS: need password ts protocol";
            result.response = S2SMessageBuilder::error("Invalid PASS command");
            return result;
        }

        std::string password = msg.params[0];
        int64_t remote_ts = msg.param_int64(1);
        uint32_t proto_ver = static_cast<uint32_t>(msg.param_int(2));
        std::string flags = msg.param(3);

        // Check protocol version compatibility
        if (proto_ver < PROTOCOL_VERSION_MIN || proto_ver > PROTOCOL_VERSION_MAX) {
            result.error = true;
            result.error_reason = fmt(
                "Incompatible protocol version: %u (supported: %u-%u)",
                proto_ver, PROTOCOL_VERSION_MIN, PROTOCOL_VERSION_MAX);
            result.response = S2SMessageBuilder::error(
                fmt("Protocol version mismatch: got %u, expected %u",
                    proto_ver, PROTOCOL_VERSION_CUR));
            return result;
        }

        // Store password for later verification against SERVER
        pending_password_ = password;
        pending_proto_version_ = proto_ver;
        pending_link_flags_ = flags;
        pending_remote_ts_ = remote_ts;

        state = S2SLinkState::WAIT_SERVER;
        result.accepted = true;
        return result;
    }

    HandshakeResult handle_incoming_server(const S2SParsedMessage& msg,
                                            S2SLinkState& state,
                                            std::string& remote_sid,
                                            HandshakeResult& result) {
        // SERVER <name> <hopcount> <boot_ts> <link_ts> <protocol> <sid> :<desc>
        if (msg.params.size() < 6) {
            result.error = true;
            result.error_reason = "Invalid SERVER: need name hopcount boot_ts link_ts proto sid";
            result.response = S2SMessageBuilder::error("Invalid SERVER command");
            return result;
        }

        std::string server_name = msg.params[0];
        uint32_t hop_count = static_cast<uint32_t>(msg.param_int(1));
        int64_t boot_ts = msg.param_int64(2);
        int64_t link_ts = msg.param_int64(3);
        std::string protocol = msg.params[4];
        std::string sid = msg.params[5];
        std::string description = msg.trailing;

        // Verify password against configured link passwords
        if (!verify_incoming_password(server_name, pending_password_)) {
            result.error = true;
            result.error_reason = "Invalid password for " + server_name;
            result.response = S2SMessageBuilder::error(
                "Invalid password");
            return result;
        }

        // Validate SID format (3 chars)
        if (sid.size() != MAX_SID_LEN) {
            result.error = true;
            result.error_reason = fmt("Invalid SID length: %zu", sid.size());
            result.response = S2SMessageBuilder::error("Invalid SID");
            return result;
        }

        // Check for duplicate SID
        if (routing_.has_server(sid) && sid != local_sid_) {
            result.error = true;
            result.error_reason = fmt("Duplicate SID: %s", sid.c_str());
            result.response = S2SMessageBuilder::error("Server SID already in use");
            return result;
        }

        // Register the server
        bool added = routing_.add_server(server_name, sid, local_sid_,
                                          description, boot_ts);
        if (!added) {
            result.error = true;
            result.error_reason = "Failed to add server to routing table";
            result.response = S2SMessageBuilder::error("Internal error adding server");
            return result;
        }

        remote_sid = sid;

        // Send our NETINFO and start burst
        result.response = S2SMessageBuilder::netinfo(
            static_cast<uint32_t>(remote_users_.user_count()),
            local_network_);
        result.response += "\r\n";
        result.response += S2SMessageBuilder::burst();

        state = S2SLinkState::WAIT_CAPAB;
        result.accepted = true;
        return result;
    }

    HandshakeResult handle_incoming_capab(const S2SParsedMessage& msg,
                                           S2SLinkState& state,
                                           std::string& remote_sid,
                                           HandshakeResult& result) {
        // CAPAB :<capabilities>
        if (msg.command == "CAPAB") {
            // Parse their capabilities
            std::string cap_str = msg.trailing.empty() ?
                (msg.params.empty() ? "" : msg.params[0]) : msg.trailing;
            S2SCapabilities remote_caps = S2SCapabilities::parse(cap_str);

            // Store capabilities
            auto* node = routing_.get_server(remote_sid);
            if (node) {
                node->capabilities = split(cap_str, ' ');
                for (const auto& c : node->capabilities)
                    node->capab_set.insert(c);
            }

            // Enable compression if both sides support it
            if (remote_caps.ziplink) {
                compression_.set_enabled(true);
            }

            // Now enter bursting state
            state = S2SLinkState::BURSTING;
            if (node) {
                node->state = S2SLinkState::BURSTING;
                node->burst_complete = false;
            }

            // Send our CAPAB reply and start burst
            S2SCapabilities our_caps;
            our_caps.chw = true;
            our_caps.namesx = true;
            our_caps.uhnames = true;
            our_caps.account = true;
            our_caps.whox = true;
            our_caps.extsj3 = true;
            our_caps.max_channel_len = MAX_CHANNEL_LEN;
            our_caps.max_nick_len = MAX_NICK_LEN;
            our_caps.max_topic_len = MAX_TOPIC_LEN;
            if (compression_.is_enabled())
                our_caps.ziplink = true;

            result.response = S2SMessageBuilder::capab(our_caps.serialize());
            result.response += "\r\n";
            result.response += S2SMessageBuilder::netinfo(
                static_cast<uint32_t>(remote_users_.user_count()),
                local_network_);
            result.response += "\r\n";
            result.response += S2SMessageBuilder::burst(now_ts());

            result.accepted = true;
            return result;
        }

        result.error = true;
        result.error_reason = "Expected CAPAB";
        return result;
    }

    HandshakeResult handle_incoming_bursting(const S2SParsedMessage& msg,
                                              S2SLinkState& state,
                                              std::string& remote_sid,
                                              HandshakeResult& result) {
        // During burst: handle ENDBURST, and queue everything else
        if (msg.command == "ENDBURST" || msg.command == "ENDOFBURST") {
            // Burst complete
            state = S2SLinkState::CONNECTED;
            auto* node = routing_.get_server(remote_sid);
            if (node) {
                node->state = S2SLinkState::CONNECTED;
                node->burst_complete = true;
            }

            // Send our ENDBURST
            result.response = S2SMessageBuilder::endburst();
            result.handshake_complete = true;
            result.accepted = true;
            result.remote_sid = remote_sid;

            // Flush any queued burst messages destined for this server
            flush_burst_queue(remote_sid);

            return result;
        }

        // Everything else during burst is a burst message - queue it
        burst_queue_.enqueue(
            msg.command == "UID" ? BurstEntry::Type::UID :
            msg.command == "FJOIN" ? BurstEntry::Type::FJOIN :
            msg.command == "SJOIN" ? BurstEntry::Type::SJOIN :
            msg.command == "TMODE" ? BurstEntry::Type::TMODE :
            msg.command == "METADATA" ? BurstEntry::Type::METADATA :
            msg.command == "SERVER" ? BurstEntry::Type::SERVER_INTRO :
            BurstEntry::Type::UID,
            msg.raw, remote_sid);

        result.accepted = true;
        result.remote_sid = remote_sid;
        return result;
    }

    // =====================================================================
    // Outgoing Connection Handshake
    // =====================================================================

    // Generate the initial handshake lines for an outgoing connection
    struct OutgoingHandshake {
        std::string pass_line;
        std::string server_line;
        std::string capab_line;
        std::string netinfo_line;
        std::string burst_line;
    };

    OutgoingHandshake build_outgoing_handshake(
        const std::string& remote_name,
        const std::string& password) {
        OutgoingHandshake hs;
        hs.pass_line = S2SMessageBuilder::pass(
            password, PROTOCOL_VERSION_CUR, PROTOCOL_FLAGS);
        hs.server_line = S2SMessageBuilder::server_intro(
            local_name_, 1, local_boot_ts_, local_sid_, local_desc_);

        S2SCapabilities caps;
        caps.chw = true;
        caps.namesx = true;
        caps.uhnames = true;
        caps.account = true;
        caps.whox = true;
        caps.extsj3 = true;
        caps.max_channel_len = MAX_CHANNEL_LEN;
        caps.max_nick_len = MAX_NICK_LEN;
        caps.max_topic_len = MAX_TOPIC_LEN;
        hs.capab_line = S2SMessageBuilder::capab(caps.serialize());

        hs.netinfo_line = S2SMessageBuilder::netinfo(
            static_cast<uint32_t>(remote_users_.user_count()),
            local_network_);
        hs.burst_line = S2SMessageBuilder::burst(now_ts());

        return hs;
    }

    // Process responses during outgoing handshake
    HandshakeResult process_outgoing_response(const std::string& line,
                                               S2SLinkState& state,
                                               std::string& remote_sid) {
        HandshakeResult result;
        auto msg = S2SParsedMessage::parse(line);

        if (state == S2SLinkState::WAIT_PASS) {
            // After PASS, we expect SERVER from remote
            if (msg.command == "SERVER") {
                if (msg.params.size() >= 6) {
                    remote_sid = msg.params[5];
                    std::string server_name = msg.params[0];
                    std::string description =
                        msg.trailing.empty() ? msg.param(5) : msg.trailing;
                    int64_t boot_ts = msg.param_int64(2);

                    // Register the remote server
                    routing_.add_server(server_name, remote_sid, "",
                                         description, boot_ts);

                    state = S2SLinkState::BURSTING;
                    auto* node = routing_.get_server(remote_sid);
                    if (node) {
                        node->state = S2SLinkState::BURSTING;
                        node->burst_complete = false;
                    }

                    result.accepted = true;
                    result.remote_sid = remote_sid;
                    return result;
                }
            }
            if (msg.command == "PASS") {
                // They sent PASS to us too - process it
                state = S2SLinkState::WAIT_SERVER;
                result.accepted = true;
                return result;
            }
        }

        if (state == S2SLinkState::BURSTING) {
            // During burst, queue everything until ENDBURST
            if (msg.command == "ENDBURST" || msg.command == "ENDOFBURST") {
                state = S2SLinkState::CONNECTED;
                auto* node = routing_.get_server(remote_sid);
                if (node) {
                    node->state = S2SLinkState::CONNECTED;
                    node->burst_complete = true;
                }

                result.handshake_complete = true;
                result.accepted = true;
                result.remote_sid = remote_sid;

                flush_burst_queue(remote_sid);
                return result;
            }

            // Queue burst messages
            burst_queue_.enqueue(
                msg.command == "UID" ? BurstEntry::Type::UID :
                msg.command == "FJOIN" ? BurstEntry::Type::FJOIN :
                msg.command == "SJOIN" ? BurstEntry::Type::SJOIN :
                msg.command == "TMODE" ? BurstEntry::Type::TMODE :
                msg.command == "SERVER" ? BurstEntry::Type::SERVER_INTRO :
                BurstEntry::Type::UID,
                msg.raw, remote_sid);

            result.accepted = true;
            result.remote_sid = remote_sid;
            return result;
        }

        return result;
    }

    // =====================================================================
    // Password Verification
    // =====================================================================

    bool verify_incoming_password(const std::string& server_name,
                                   const std::string& password) {
        auto it = incoming_passwords_.find(tolower_str(server_name));
        if (it == incoming_passwords_.end()) return false;
        return it->second == password;
    }

    bool verify_outgoing_password(const std::string& server_name,
                                   const std::string& password) {
        auto it = outgoing_links_.find(tolower_str(server_name));
        if (it == outgoing_links_.end()) return false;
        return it->second.password == password;
    }

    // =====================================================================
    // Authentication (SSL Certificate + Password)
    // =====================================================================

    // Check if SSL certificate fingerprint is trusted for this server
    bool is_certfp_trusted(const std::string& server_name,
                           const std::string& fingerprint) {
        return cert_manager_.is_fingerprint_trusted(server_name, fingerprint);
    }

    // Add a trusted SSL certificate fingerprint
    void add_trusted_fingerprint(const std::string& server_name,
                                  const std::string& fingerprint) {
        cert_manager_.add_trusted_fingerprint(server_name, fingerprint);
    }

    // Combined auth check (TLS fingerprint + password)
    bool authenticate_link(const std::string& server_name,
                           const std::string& password,
                           const std::string& cert_fingerprint = "") {
        // Must pass password check
        if (!verify_incoming_password(server_name, password) &&
            !verify_outgoing_password(server_name, password)) {
            return false;
        }

        // If we have a certificate fingerprint requirement, must match
        if (cert_manager_.has_fingerprint(server_name)) {
            if (cert_fingerprint.empty()) return false;
            return cert_manager_.is_fingerprint_trusted(server_name,
                                                          cert_fingerprint);
        }

        return true;
    }

    S2SCertificateManager& cert_manager() { return cert_manager_; }

    // =====================================================================
    // Burst Queue Handling
    // =====================================================================

    // Queue a message for sending during burst
    void queue_burst_message(const std::string& message,
                              const std::string& target_sid = "") {
        burst_queue_.enqueue(BurstEntry::Type::ENCAP, message, target_sid);
    }

    // Flush queued burst messages for a specific server
    void flush_burst_queue(const std::string& target_sid) {
        // The actual flushing is handled by the caller calling process_burst_line
        // on each queued message. This just marks the queue as ready to be
        // processed. Save the queued messages.
        auto entries = burst_queue_.snapshot();
        burst_queue_.clear();

        // Each entry will be processed by the protocol processor.
        // We store them temporarily.
        for (const auto& e : entries) {
            pending_burst_msgs_.push_back(e);
        }
    }

    // Process pending burst messages (call after ENDBURST)
    bool has_pending_burst() const {
        return !pending_burst_msgs_.empty();
    }

    BurstEntry pop_pending_burst() {
        if (pending_burst_msgs_.empty()) {
            return BurstEntry(BurstEntry::Type::UID, "");
        }
        auto e = pending_burst_msgs_.front();
        pending_burst_msgs_.pop_front();
        return e;
    }

    // =====================================================================
    // UID Introduction (User Introduction Across Servers)
    // =====================================================================

    // Generate a UID for a new local user
    std::string allocate_uid() {
        return uid_gen_->next_uid();
    }

    // Build a UID introduction message for a local user
    std::string build_uid_intro(const std::string& nick,
                                 const std::string& ident,
                                 const std::string& host,
                                 const std::string& realname,
                                 const std::string& ip,
                                 const std::string& modes = "",
                                 const std::string& account = "") {
        std::string uid = uid_gen_->next_uid();
        std::string mode_str = modes.empty() ? "i" : modes;  // +i by default

        std::string msg = S2SMessageBuilder::uid(
            nick, 1, now_ts(), mode_str,
            ident, host, uid, ip, host, realname);

        // If we have an account, add metadata
        if (!account.empty()) {
            msg += "\r\n";
            msg += S2SMessageBuilder::metadata(uid, "accountname", account);
        }

        return msg;
    }

    // Process an incoming UID message
    S2SRemoteUser process_uid(const S2SParsedMessage& msg,
                               const std::string& source_sid) {
        S2SRemoteUser user;
        if (msg.params.size() < 8) return user;  // Invalid

        user.nick       = msg.param(0);
        user.hop_count  = static_cast<uint32_t>(msg.param_int(1));
        user.signon_ts  = msg.param_int64(2);
        std::string modes = msg.param(3);  // +i, +w, etc.
        if (!modes.empty() && modes[0] == '+')
            modes = modes.substr(1);
        user.modes = modes;
        for (char c : modes) user.mode_set.insert(c);
        user.ident      = msg.param(4);
        user.host       = msg.param(5);
        user.uid        = msg.param(6);
        user.ip         = msg.param(7);
        user.realhost   = msg.params.size() > 8 ? msg.param(8) : msg.param(5);
        user.realname   = msg.trailing;
        user.server_sid = source_sid;
        user.is_oper    = (modes.find('o') != std::string::npos);
        user.is_hidden  = (modes.find('x') != std::string::npos ||
                           modes.find('I') != std::string::npos);

        // Register the remote user
        remote_users_.add_user(user);

        return user;
    }

    // =====================================================================
    // Broadcast / Flood Logic
    // =====================================================================

    // Broadcast a message to all directly connected servers except source
    std::vector<std::string> broadcast(const std::string& message,
                                        const std::string& exclude_sid = "") {
        auto targets = routing_.get_flood_targets(exclude_sid);
        return targets;
    }

    // Build a PRIVMSG for remote user
    std::string build_broadcast_privmsg(const std::string& source_uid,
                                         const std::string& source_nick,
                                         const std::string& source_ident,
                                         const std::string& source_host,
                                         const std::string& target,
                                         const std::string& message) {
        return fmt(":%s!%s@%s PRIVMSG %s :%s",
                   source_nick.c_str(), source_ident.c_str(),
                   source_host.c_str(), target.c_str(), message.c_str());
    }

    // =====================================================================
    // Server MODE Burst
    // =====================================================================

    // Queue all known channel modes for burst to a new server
    void build_channel_mode_burst(const std::string& target_sid,
                                   std::function<void(const std::string&)> output) {
        // For each known channel, send FJOIN/SJOIN with current state
        // This would iterate over the local channel registry.
        // The caller provides a callback to send each line.
        // Placeholder: the actual channel iteration is done by the
        // higher-level server code.
    }

    // Send TMODE (timestamped mode change)
    std::string build_tmode(const std::string& channel, int64_t ts,
                             const std::string& mode_changes) {
        return S2SMessageBuilder::tmode(channel, ts, mode_changes);
    }

    // =====================================================================
    // Channel TS Synchronization
    // =====================================================================

    S2SChannelSync& channel_sync() { return channel_sync_; }
    const S2SChannelSync& channel_sync() const { return channel_sync_; }

    // Resolve FJOIN/SJOIN: older TS wins
    bool should_accept_join(const std::string& channel,
                             int64_t remote_ts,
                             int64_t local_ts) {
        return channel_sync_.resolve_ts_conflict(channel, remote_ts, local_ts);
    }

    // =====================================================================
    // Server PING/PONG
    // =====================================================================

    // Build a PING for a remote server
    std::string build_ping(const std::string& target_sid) {
        std::string token = random_string(8);
        {
            std::lock_guard<std::mutex> lock(ping_mutex_);
            ping_tokens_[target_sid] = token;
            ping_sent_[target_sid] = now_ts();
        }
        return S2SMessageBuilder::ping(local_sid_, token);
    }

    // Build a PONG response
    std::string build_pong(const std::string& target_sid,
                            const std::string& token) {
        return S2SMessageBuilder::pong(local_sid_, token);
    }

    // Process incoming PING
    std::string handle_ping(const S2SParsedMessage& msg,
                             const std::string& source_sid) {
        std::string token = msg.trailing.empty() ?
            (msg.params.empty() ? "" : msg.param(0)) : msg.trailing;
        return build_pong(source_sid, token);
    }

    // Process incoming PONG, returns latency in ms or -1 if unknown
    int64_t handle_pong(const std::string& source_sid, const std::string& token) {
        std::lock_guard<std::mutex> lock(ping_mutex_);
        auto it = ping_tokens_.find(source_sid);
        if (it != ping_tokens_.end() && it->second == token) {
            int64_t sent = ping_sent_[source_sid];
            int64_t now = now_ts();
            int64_t latency = now - sent;
            ping_tokens_.erase(it);
            ping_sent_.erase(source_sid);
            return latency;
        }
        return -1;
    }

    // Check for lagging servers (needs to be called periodically)
    std::vector<std::string> check_lagging_servers(int64_t max_lag_ms = 180000) {
        std::vector<std::string> lagging;
        std::lock_guard<std::mutex> lock(ping_mutex_);
        int64_t now = now_ts();
        for (const auto& [sid, sent] : ping_sent_) {
            if (now - sent > max_lag_ms) {
                lagging.push_back(sid);
            }
        }
        return lagging;
    }

    // =====================================================================
    // SQUIT / Netsplit Handling
    // =====================================================================

    // Initiate a SQUIT for a server
    std::string build_squit(const std::string& target_sid,
                             const std::string& reason) {
        return S2SMessageBuilder::squit(target_sid, reason);
    }

    // Process an incoming SQUIT
    // Returns: list of affected user UIDs to clean up locally
    struct SquitResult {
        std::string server_sid;
        std::string server_name;
        std::string reason;
        std::vector<std::string> affected_sids;    // All servers that split off
        std::vector<std::string> affected_users;    // Local users on split servers
        size_t remote_users_lost = 0;
    };

    SquitResult process_squit(const S2SParsedMessage& msg,
                               const std::string& source_sid) {
        SquitResult result;

        if (msg.params.empty()) return result;

        // SQUIT target can be SID or server name
        std::string target = msg.param(0);
        result.reason = msg.trailing;

        // Resolve target to SID
        std::string target_sid = target;
        if (target.size() != MAX_SID_LEN) {
            auto* node = routing_.get_server_by_name(target);
            if (node) {
                target_sid = node->sid;
            } else {
                return result;
            }
        }

        auto* node = routing_.get_server(target_sid);
        if (!node) return result;

        result.server_sid = target_sid;
        result.server_name = node->name;

        // Collect all descendant servers
        collect_all_descendants(target_sid, result.affected_sids);

        // Begin tracking the netsplit
        netsplit_mgr_.begin_split(target_sid, node->name, result.reason,
                                   result.affected_sids);

        // Remove all remote users from affected servers
        for (const auto& sid : result.affected_sids) {
            size_t lost = remote_users_.remove_users_on_server(sid);
            result.remote_users_lost += lost;
        }

        // Remove servers from routing table
        routing_.remove_server(target_sid);

        return result;
    }

    // Handle local SQUIT (we are initiating)
    SquitResult do_squit_local(const std::string& target_sid,
                                const std::string& reason) {
        SquitResult result;
        result.server_sid = target_sid;
        result.reason = reason;

        auto* node = routing_.get_server(target_sid);
        if (node) result.server_name = node->name;

        collect_all_descendants(target_sid, result.affected_sids);

        netsplit_mgr_.begin_split(target_sid, node ? node->name : target_sid,
                                   reason, result.affected_sids);

        for (const auto& sid : result.affected_sids) {
            result.remote_users_lost += remote_users_.remove_users_on_server(sid);
        }

        routing_.remove_server(target_sid);
        return result;
    }

    // =====================================================================
    // Remote WHOIS
    // =====================================================================

    struct WhoisInfo {
        std::string nick;
        std::string ident;
        std::string host;
        std::string realname;
        std::string server_name;
        std::string server_desc;
        std::string account;
        int64_t signon_ts = 0;
        int64_t idle_sec = 0;
        bool is_oper = false;
        bool is_away = false;
        std::string away_msg;
        std::vector<std::string> channels;
        std::string certfp;
        bool found = false;
    };

    WhoisInfo perform_remote_whois(const std::string& target_nick,
                                    const std::string& requester_uid) {
        WhoisInfo info;

        // Check local users first (handled by main server)
        // Check remote users
        auto* user = remote_users_.get_user_by_nick(target_nick);
        if (!user) {
            info.found = false;
            return info;
        }

        info.found = true;
        info.nick = user->nick;
        info.ident = user->ident;
        info.host = user->host;
        info.realname = user->realname;
        info.signon_ts = user->signon_ts;
        info.is_oper = user->is_oper;
        info.is_away = user->is_away;
        info.away_msg = user->away_msg;
        info.account = user->account;
        info.certfp = user->certfp;

        if (user->signon_ts > 0)
            info.idle_sec = (now_ts() / 1000) - (user->signon_ts / 1000);

        // Get server info
        auto* server = routing_.get_server(user->server_sid);
        if (server) {
            info.server_name = server->name;
            info.server_desc = server->description;
        }

        return info;
    }

    // Forward WHOIS to the target's home server
    std::string forward_whois(const std::string& target_nick,
                               const std::string& requester_uid,
                               const std::string& target_sid) {
        return fmt(":%s WHOIS %s %s",
                   requester_uid.c_str(),
                   local_sid_.c_str(), target_nick.c_str());
    }

    // =====================================================================
    // Remote KILL
    // =====================================================================

    // Process an incoming KILL
    struct KillResult {
        bool valid = false;
        std::string target_uid;
        std::string target_nick;
        std::string reason;
        std::string killer_sid;
        bool target_is_local = false;
    };

    KillResult process_kill(const S2SParsedMessage& msg,
                             const std::string& source_sid) {
        KillResult result;
        if (msg.params.empty()) return result;

        result.target_uid = msg.param(0);
        result.reason = msg.trailing;
        result.killer_sid = source_sid;
        result.valid = true;

        // Check if target is a local user (would be handled by main server)
        if (routing_.is_local_uid(result.target_uid)) {
            result.target_is_local = true;
        }

        // Get target nick for notification
        auto* user = remote_users_.get_user_by_uid(result.target_uid);
        if (user) {
            result.target_nick = user->nick;
            // Remove the killed user
            remote_users_.remove_user(result.target_uid);
        }

        return result;
    }

    // Build a KILL message
    std::string build_kill(const std::string& target_uid,
                            const std::string& reason) {
        return S2SMessageBuilder::kill(target_uid, reason);
    }

    // =====================================================================
    // SVSJOIN / SVSPART (Service-forced commands)
    // =====================================================================

    // Build SVSJOIN
    std::string build_svsjoin(const std::string& uid,
                               const std::string& channel) {
        return S2SMessageBuilder::svsjoin(uid, channel);
    }

    // Build SVSPART
    std::string build_svspart(const std::string& uid,
                               const std::string& channel,
                               const std::string& reason = "") {
        return S2SMessageBuilder::svspart(uid, channel, reason);
    }

    // Process incoming SVSJOIN
    struct SVSJoinResult {
        bool valid = false;
        std::string uid;
        std::string channel;
        bool is_local = false;
    };

    SVSJoinResult process_svsjoin(const S2SParsedMessage& msg) {
        SVSJoinResult result;
        if (msg.params.size() < 2) return result;

        result.uid = msg.param(0);
        result.channel = msg.param(1);
        result.valid = true;
        result.is_local = routing_.is_local_uid(result.uid);
        return result;
    }

    // Process incoming SVSPART
    struct SVSPartResult {
        bool valid = false;
        std::string uid;
        std::string channel;
        std::string reason;
        bool is_local = false;
    };

    SVSPartResult process_svspart(const S2SParsedMessage& msg) {
        SVSPartResult result;
        if (msg.params.size() < 2) return result;

        result.uid = msg.param(0);
        result.channel = msg.param(1);
        result.reason = msg.trailing;
        result.valid = true;
        result.is_local = routing_.is_local_uid(result.uid);
        return result;
    }

    // =====================================================================
    // SVSNICK / SVSMODE (Service-forced nick/mode changes)
    // =====================================================================

    // Build SVSNICK
    std::string build_svsnick(const std::string& uid,
                               const std::string& new_nick,
                               int64_t ts = 0) {
        return S2SMessageBuilder::svsnick(uid, new_nick, ts);
    }

    // Process incoming SVSNICK
    struct SVSNickResult {
        bool valid = false;
        std::string uid;
        std::string new_nick;
        int64_t ts = 0;
        bool is_local = false;
    };

    SVSNickResult process_svsnick(const S2SParsedMessage& msg) {
        SVSNickResult result;
        if (msg.params.size() < 2) return result;

        result.uid = msg.param(0);
        result.new_nick = msg.param(1);
        result.ts = msg.param_int64(2);
        result.valid = true;
        result.is_local = routing_.is_local_uid(result.uid);

        // Update remote user registry if known
        if (!result.is_local) {
            remote_users_.update_nick(result.uid, result.new_nick);
        }

        return result;
    }

    // Build SVSMODE
    std::string build_svsmode(const std::string& uid,
                               const std::string& modes,
                               int64_t ts = 0) {
        return S2SMessageBuilder::svsmode(uid, modes, ts);
    }

    // Process incoming SVSMODE
    struct SVSModeResult {
        bool valid = false;
        std::string uid;
        std::string modes;
        int64_t ts = 0;
        bool is_local = false;
    };

    SVSModeResult process_svsmode(const S2SParsedMessage& msg) {
        SVSModeResult result;
        if (msg.params.size() < 2) return result;

        result.uid = msg.param(0);
        result.ts = msg.param_int64(1);
        result.modes = msg.param(2);
        if (!result.modes.empty() && result.modes[0] == '+')
            result.modes = result.modes.substr(1);
        result.valid = true;
        result.is_local = routing_.is_local_uid(result.uid);

        // Update remote user modes if known
        if (!result.is_local) {
            auto* user = remote_users_.get_user_by_uid(result.uid);
            if (user) {
                for (char c : result.modes) {
                    user->mode_set.insert(c);
                }
                user->modes += result.modes;
            }
        }

        return result;
    }

    // =====================================================================
    // NETINFO Exchange
    // =====================================================================

    // Build NETINFO
    std::string build_netinfo() {
        return S2SMessageBuilder::netinfo(
            static_cast<uint32_t>(remote_users_.user_count()),
            local_network_);
    }

    // Process incoming NETINFO
    struct NetInfoResult {
        uint32_t max_global_users = 0;
        int64_t remote_time = 0;
        uint32_t protocol_version = 0;
        std::string network_name;
    };

    NetInfoResult process_netinfo(const S2SParsedMessage& msg) {
        NetInfoResult result;
        if (msg.params.size() < 5) return result;

        result.max_global_users = static_cast<uint32_t>(msg.param_int(0));
        result.remote_time = msg.param_int64(1);
        result.protocol_version = static_cast<uint32_t>(msg.param_int(2));
        // params[3] = cloak_hash, params[4] = 0|1 (no_warn), params[5] = 0|1 (no_expire)
        result.network_name = msg.trailing;

        return result;
    }

    // =====================================================================
    // Protocol Version Negotiation
    // =====================================================================

    uint32_t negotiate_protocol_version(uint32_t their_version) {
        // Take the minimum of what we both support
        if (their_version > PROTOCOL_VERSION_CUR)
            return PROTOCOL_VERSION_CUR;
        if (their_version < PROTOCOL_VERSION_MIN)
            return 0;  // Incompatible
        return their_version;
    }

    bool is_protocol_compatible(uint32_t their_version) const {
        return their_version >= PROTOCOL_VERSION_MIN &&
               their_version <= PROTOCOL_VERSION_MAX;
    }

    // =====================================================================
    // Server Description Broadcasting
    // =====================================================================

    // Broadcast our server info to all links
    std::string build_server_broadcast() {
        return S2SMessageBuilder::server_intro(
            local_name_, 1, local_boot_ts_, local_sid_, local_desc_);
    }

    // Forward another server's intro to all other links
    std::string build_server_forward(const std::string& name,
                                      uint32_t hop_count,
                                      int64_t boot_ts, int64_t link_ts,
                                      const std::string& sid,
                                      const std::string& description) {
        return S2SMessageBuilder::server_pass_on(
            name, hop_count, boot_ts, link_ts, sid, description);
    }

    // =====================================================================
    // Compression
    // =====================================================================

    S2SCompression& compression() { return compression_; }
    const S2SCompression& compression() const { return compression_; }

    // =====================================================================
    // Reconnect logic
    // =====================================================================

    // Get servers needing reconnection
    std::vector<S2SOutgoingAttempt> get_reconnect_targets() {
        std::vector<S2SOutgoingAttempt> targets;
        int64_t now = now_ts();

        for (auto& [name, link] : outgoing_links_) {
            // Skip if already connected
            if (routing_.get_server_by_name(link.server_name)) continue;

            // Check if it's time to retry
            if (link.next_attempt > 0 && now < link.next_attempt) continue;

            // Check max retries
            if (link.max_retries > 0 && link.retries >= link.max_retries)
                continue;

            targets.push_back(link);
        }

        return targets;
    }

    // Mark a reconnection attempt
    void record_connect_attempt(const std::string& server_name, bool success) {
        auto it = outgoing_links_.find(tolower_str(server_name));
        if (it == outgoing_links_.end()) return;

        it->second.last_attempt = now_ts();
        it->second.retries++;

        if (!success) {
            it->second.next_attempt = now_ts() +
                (it->second.reconnect_delay * 1000);
        } else {
            it->second.retries = 0;
            it->second.next_attempt = 0;
        }
    }

    // =====================================================================
    // Accessors
    // =====================================================================

    S2SRoutingTable& routing() { return routing_; }
    const S2SRoutingTable& routing() const { return routing_; }

    S2SRemoteUserRegistry& remote_users() { return remote_users_; }
    const S2SRemoteUserRegistry& remote_users() const { return remote_users_; }

    S2SNetsplitManager& netsplits() { return netsplit_mgr_; }

    S2SUIDGenerator& uid_generator() { return uid_gen_; }

private:
    // --- Helper to collect all descendants of a server ---
    void collect_all_descendants(const std::string& sid,
                                  std::vector<std::string>& result) {
        result.push_back(sid);
        for (size_t i = 0; i < result.size(); ++i) {
            auto* node = routing_.get_server(result[i]);
            if (!node) continue;
            // Check all servers for ones whose parent is this node
            auto all = routing_.get_all_servers();
            for (const auto* s : all) {
                if (s->parent_sid == result[i] &&
                    std::find(result.begin(), result.end(), s->sid) == result.end()) {
                    result.push_back(s->sid);
                }
            }
        }
    }

    // --- Local server identity ---
    std::string local_name_;
    std::string local_sid_;
    std::string local_desc_;
    std::string local_network_;
    int64_t local_boot_ts_ = 0;

    // --- Routing and user management ---
    S2SRoutingTable routing_;
    S2SRemoteUserRegistry remote_users_;
    S2SChannelSync channel_sync_;
    S2SNetsplitManager netsplit_mgr_;
    std::unique_ptr<S2SUIDGenerator> uid_gen_;
    S2SBurstQueue burst_queue_;
    S2SCompression compression_;
    S2SCertificateManager cert_manager_;

    // --- Link configuration ---
    std::unordered_map<std::string, S2SOutgoingAttempt> outgoing_links_;
    std::unordered_map<std::string, std::string> incoming_passwords_;

    // --- Handshake state ---
    std::string pending_password_;
    uint32_t pending_proto_version_ = 0;
    std::string pending_link_flags_;
    int64_t pending_remote_ts_ = 0;

    // --- PING/PONG tracking ---
    std::unordered_map<std::string, std::string> ping_tokens_;
    std::unordered_map<std::string, int64_t> ping_sent_;
    std::mutex ping_mutex_;

    // --- Pending burst messages ---
    std::deque<BurstEntry> pending_burst_msgs_;
};

// =============================================================================
// SECTION 16: S2S Protocol Dispatcher (Full Message Router)
// =============================================================================

// Central dispatcher that processes all S2S protocol messages and
// calls the appropriate handlers. Used by both incoming and outgoing links.
class S2SProtocolDispatcher {
public:
    using SendCallback = std::function<void(const std::string& sid,
                                             const std::string& message)>;
    using BroadcastCallback = std::function<void(const std::string& message,
                                                   const std::string& exclude_sid)>;
    using LocalUserCallback = std::function<void(const std::string& uid,
                                                   const std::string& data)>;

    S2SProtocolDispatcher(S2SProtocolEngine& engine)
        : engine_(engine) {}

    // Set callbacks
    void set_send_callback(SendCallback cb) { send_cb_ = std::move(cb); }
    void set_broadcast_callback(BroadcastCallback cb) {
        broadcast_cb_ = std::move(cb);
    }
    void set_local_user_callback(LocalUserCallback cb) {
        local_user_cb_ = std::move(cb);
    }

    // Dispatch a protocol line received from a specific server
    // Returns true if the message was handled
    bool dispatch(const std::string& line, const std::string& source_sid) {
        auto msg = S2SParsedMessage::parse(line);
        if (msg.command.empty()) return false;

        // Route by command type
        auto cmd = msg.command;

        if (cmd == "UID") {
            return handle_uid(msg, source_sid);
        }
        if (cmd == "NICK") {
            return handle_nick(msg, source_sid);
        }
        if (cmd == "QUIT") {
            return handle_quit(msg, source_sid);
        }
        if (cmd == "FJOIN" || cmd == "SJOIN") {
            return handle_join(msg, source_sid, cmd);
        }
        if (cmd == "TMODE") {
            return handle_tmode(msg, source_sid);
        }
        if (cmd == "MODE") {
            return handle_mode(msg, source_sid);
        }
        if (cmd == "KICK") {
            return handle_kick(msg, source_sid);
        }
        if (cmd == "PART") {
            return handle_part(msg, source_sid);
        }
        if (cmd == "KILL") {
            return handle_kill(msg, source_sid);
        }
        if (cmd == "SQUIT") {
            return handle_squit(msg, source_sid);
        }
        if (cmd == "PING") {
            return handle_ping(msg, source_sid);
        }
        if (cmd == "PONG") {
            return handle_pong(msg, source_sid);
        }
        if (cmd == "SERVER") {
            return handle_server_intro(msg, source_sid);
        }
        if (cmd == "SVSNICK") {
            return handle_svsnick(msg, source_sid);
        }
        if (cmd == "SVSMODE") {
            return handle_svsmode(msg, source_sid);
        }
        if (cmd == "SVSJOIN") {
            return handle_svsjoin(msg, source_sid);
        }
        if (cmd == "SVSPART") {
            return handle_svspart(msg, source_sid);
        }
        if (cmd == "PRIVMSG" || cmd == "NOTICE") {
            return handle_message(msg, source_sid, cmd);
        }
        if (cmd == "TOPIC") {
            return handle_topic(msg, source_sid);
        }
        if (cmd == "AWAY") {
            return handle_away(msg, source_sid);
        }
        if (cmd == "OPER") {
            return handle_oper(msg, source_sid);
        }
        if (cmd == "VERSION") {
            return handle_version(msg, source_sid);
        }
        if (cmd == "NETINFO") {
            return handle_netinfo(msg, source_sid);
        }
        if (cmd == "METADATA") {
            return handle_metadata(msg, source_sid);
        }
        if (cmd == "ENCAP") {
            return handle_encap(msg, source_sid);
        }
        if (cmd == "WALLOPS") {
            return handle_wallops(msg, source_sid);
        }

        // Unknown command - forward as-is (passthrough)
        forward_to_all(msg.raw, source_sid);
        return true;
    }

private:
    // =====================================================================
    // Individual command handlers
    // =====================================================================

    bool handle_uid(const S2SParsedMessage& msg, const std::string& source_sid) {
        engine_.process_uid(msg, source_sid);
        // Forward UID to all other servers
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_nick(const S2SParsedMessage& msg, const std::string& source_sid) {
        // NICK <uid> <newnick> <ts>
        if (msg.params.size() >= 2) {
            std::string uid = msg.param(0);
            std::string new_nick = msg.param(1);
            engine_.remote_users().update_nick(uid, new_nick);
        }
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_quit(const S2SParsedMessage& msg, const std::string& source_sid) {
        // QUIT <uid> :<reason>
        if (!msg.params.empty()) {
            std::string uid = msg.param(0);
            engine_.remote_users().remove_user(uid);
        }
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_join(const S2SParsedMessage& msg, const std::string& source_sid,
                      const std::string& cmd) {
        // FJOIN/SJOIN <channel> <ts> +<modes> :<members>
        if (msg.params.size() >= 2) {
            std::string channel = msg.param(0);
            int64_t ts = msg.param_int64(1);
            engine_.channel_sync().set_channel_ts(channel, ts, source_sid);
        }
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_tmode(const S2SParsedMessage& msg, const std::string& source_sid) {
        // TMODE <channel> <ts> <mode_str>
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_mode(const S2SParsedMessage& msg, const std::string& source_sid) {
        // MODE <target> <mode_changes> - could be user or channel mode
        if (!msg.params.empty()) {
            std::string target = msg.param(0);
            // If target is a UID, check if local
            if (engine_.routing().is_local_uid(target)) {
                // Local user mode change - notify local client
                if (local_user_cb_) {
                    local_user_cb_(target, msg.raw);
                }
                return true;
            }
        }
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_kick(const S2SParsedMessage& msg, const std::string& source_sid) {
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_part(const S2SParsedMessage& msg, const std::string& source_sid) {
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_kill(const S2SParsedMessage& msg, const std::string& source_sid) {
        auto result = engine_.process_kill(msg, source_sid);
        if (result.target_is_local && local_user_cb_) {
            local_user_cb_(result.target_uid, msg.raw);
        }
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_squit(const S2SParsedMessage& msg, const std::string& source_sid) {
        auto result = engine_.process_squit(msg, source_sid);

        // Forward SQUIT to all other servers
        forward_to_all_except(msg.raw, source_sid, source_sid);

        // Notify local clients about netsplit (quits would be generated
        // by the main server)
        return true;
    }

    bool handle_ping(const S2SParsedMessage& msg, const std::string& source_sid) {
        std::string response = engine_.handle_ping(msg, source_sid);
        if (!response.empty() && send_cb_) {
            send_cb_(source_sid, response);
        }
        return true;
    }

    bool handle_pong(const S2SParsedMessage& msg, const std::string& source_sid) {
        std::string token = msg.trailing.empty() ?
            (msg.params.empty() ? "" : msg.param(0)) : msg.trailing;
        engine_.handle_pong(source_sid, token);
        return true;
    }

    bool handle_server_intro(const S2SParsedMessage& msg,
                              const std::string& source_sid) {
        // SERVER <name> <hopcount> <boot_ts> <link_ts> <proto> <sid> :<desc>
        if (msg.params.size() >= 6) {
            std::string name = msg.param(0);
            uint32_t hop_count = static_cast<uint32_t>(msg.param_int(1));
            int64_t boot_ts = msg.param_int64(2);
            std::string sid = msg.params[5];
            std::string description =
                msg.trailing.empty() ? msg.param(5) : msg.trailing;

            // Add to routing table, using source_sid as parent
            engine_.routing().add_server(name, sid, source_sid, description, boot_ts);
        }

        // Forward to all other servers (with incremented hop count)
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_svsnick(const S2SParsedMessage& msg,
                          const std::string& source_sid) {
        auto result = engine_.process_svsnick(msg);
        if (result.is_local && local_user_cb_) {
            local_user_cb_(result.uid, msg.raw);
        }
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_svsmode(const S2SParsedMessage& msg,
                          const std::string& source_sid) {
        auto result = engine_.process_svsmode(msg);
        if (result.is_local && local_user_cb_) {
            local_user_cb_(result.uid, msg.raw);
        }
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_svsjoin(const S2SParsedMessage& msg,
                          const std::string& source_sid) {
        auto result = engine_.process_svsjoin(msg);
        if (result.is_local && local_user_cb_) {
            local_user_cb_(result.uid, msg.raw);
        }
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_svspart(const S2SParsedMessage& msg,
                          const std::string& source_sid) {
        auto result = engine_.process_svspart(msg);
        if (result.is_local && local_user_cb_) {
            local_user_cb_(result.uid, msg.raw);
        }
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_message(const S2SParsedMessage& msg,
                         const std::string& source_sid,
                         const std::string& cmd) {
        // PRIVMSG/NOTICE from a remote server
        // Determine target and forward appropriately
        if (msg.params.size() >= 1) {
            std::string target = msg.param(0);

            // If target is a channel, forward to all linked servers
            if (!target.empty() && (target[0] == '#' || target[0] == '&')) {
                forward_to_all_except(msg.raw, source_sid, source_sid);
                return true;
            }

            // If target is a nick on this server, deliver locally
            // (UID-based delivery handled by hash prefix check)
            if (local_user_cb_) {
                local_user_cb_(target, msg.raw);
                return true;
            }

            // Forward to target's home server
            auto* user = engine_.remote_users().get_user_by_nick(target);
            if (user && send_cb_) {
                send_cb_(user->server_sid, msg.raw);
                return true;
            }
        }

        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_topic(const S2SParsedMessage& msg,
                       const std::string& source_sid) {
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_away(const S2SParsedMessage& msg,
                      const std::string& source_sid) {
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_oper(const S2SParsedMessage& msg,
                      const std::string& source_sid) {
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_version(const S2SParsedMessage& msg,
                          const std::string& source_sid) {
        // Reply with our version info
        if (send_cb_) {
            std::string reply = S2SMessageBuilder::version_reply(
                source_sid, "progressive-irc-1.0.0");
            send_cb_(source_sid, reply);
        }
        return true;
    }

    bool handle_netinfo(const S2SParsedMessage& msg,
                          const std::string& source_sid) {
        auto result = engine_.process_netinfo(msg);

        // Update server node with netinfo data
        auto* node = engine_.routing().get_server(source_sid);
        if (node) {
            node->max_global_users = result.max_global_users;
            node->network_name = result.network_name;
            node->last_netinfo_ts = now_ts();
            if (result.protocol_version > 0) {
                node->protocol_version = result.protocol_version;
            }
        }

        return true;
    }

    bool handle_metadata(const S2SParsedMessage& msg,
                          const std::string& source_sid) {
        // METADATA <uid> <key> :<value>
        if (msg.params.size() >= 2) {
            std::string uid = msg.param(0);
            std::string key = msg.param(1);
            std::string value = msg.trailing;

            // If this metadata is for a local user, apply it
            if (engine_.routing().is_local_uid(uid)) {
                if (local_user_cb_) {
                    local_user_cb_(uid, msg.raw);
                }
                return true;
            }

            // Update remote user info
            auto* user = engine_.remote_users().get_user_by_uid(uid);
            if (user) {
                if (key == "accountname") {
                    user->account = value;
                } else if (key == "certfp") {
                    user->certfp = value;
                }
            }
        }

        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    bool handle_encap(const S2SParsedMessage& msg,
                       const std::string& source_sid) {
        // ENCAP <target_sid> <subcommand> <params...>
        if (msg.params.size() >= 2) {
            std::string target_sid = msg.param(0);

            // If target is us, process locally
            if (target_sid == engine_.local_sid()) {
                // Re-dispatch the encapsulated message
                std::string subcommand = msg.param(1);
                std::string inner_params;
                for (size_t i = 2; i < msg.params.size(); i++) {
                    if (i > 2) inner_params += " ";
                    inner_params += msg.params[i];
                }
                if (!msg.trailing.empty()) {
                    inner_params += " :" + msg.trailing;
                }

                S2SParsedMessage inner_msg = S2SParsedMessage::parse(
                    fmt("%s %s", subcommand.c_str(), inner_params.c_str()));
                return dispatch(inner_msg.raw, source_sid);
            }

            // Route to target server
            std::string next_hop = engine_.routing().get_next_hop(target_sid);
            if (!next_hop.empty() && send_cb_) {
                send_cb_(next_hop, msg.raw);
                return true;
            }
        }

        return false;
    }

    bool handle_wallops(const S2SParsedMessage& msg,
                         const std::string& source_sid) {
        // Forward WALLOPS to all servers except source
        forward_to_all_except(msg.raw, source_sid, source_sid);
        return true;
    }

    // =====================================================================
    // Forwarding helpers
    // =====================================================================

    void forward_to_all(const std::string& message,
                         const std::string& source_sid) {
        if (broadcast_cb_) {
            broadcast_cb_(message, "");
        } else {
            auto targets = engine_.routing().get_flood_targets();
            for (const auto& sid : targets) {
                if (send_cb_) send_cb_(sid, message);
            }
        }
    }

    void forward_to_all_except(const std::string& message,
                                const std::string& source_sid,
                                const std::string& exclude_sid) {
        if (broadcast_cb_) {
            broadcast_cb_(message, exclude_sid);
        } else {
            auto targets = engine_.routing().get_flood_targets(exclude_sid);
            for (const auto& sid : targets) {
                if (send_cb_) send_cb_(sid, message);
            }
        }
    }

    S2SProtocolEngine& engine_;
    SendCallback send_cb_;
    BroadcastCallback broadcast_cb_;
    LocalUserCallback local_user_cb_;
};

// =============================================================================
// SECTION 17: S2S Connection Manager (Per-Link Handler)
// =============================================================================

class S2SConnectionManager {
public:
    S2SConnectionManager(S2SProtocolEngine& engine,
                          S2SProtocolDispatcher& dispatcher)
        : engine_(engine), dispatcher_(dispatcher) {}

    // Create a new incoming connection context
    struct LinkContext {
        std::string sid;           // Remote SID
        std::string name;          // Remote server name
        S2SLinkState state = S2SLinkState::WAIT_PASS;
        LinkDirection direction = LinkDirection::INCOMING;
        bool compressed = false;
        std::string ssl_fingerprint;
        std::string read_buffer;
        int64_t bytes_recv = 0;
        int64_t bytes_sent = 0;
        int64_t connected_at = 0;
        int fd = -1;
    };

    // Create a context for a new incoming connection
    LinkContext create_incoming_context() {
        LinkContext ctx;
        ctx.state = S2SLinkState::WAIT_PASS;
        ctx.direction = LinkDirection::INCOMING;
        ctx.connected_at = now_ts();
        return ctx;
    }

    // Create a context for a new outgoing connection
    LinkContext create_outgoing_context() {
        LinkContext ctx;
        ctx.state = S2SLinkState::WAIT_PASS;
        ctx.direction = LinkDirection::OUTGOING;
        ctx.connected_at = now_ts();
        return ctx;
    }

    // Process a line from a link
    struct ProcessResult {
        std::string response;        // Response to send
        bool handshake_complete = false;
        bool error = false;
        std::string error_reason;
        bool disconnect = false;
    };

    ProcessResult process_line(LinkContext& ctx, const std::string& line) {
        ProcessResult result;

        if (ctx.state == S2SLinkState::CONNECTED) {
            // Normal operation - dispatch the message
            dispatcher_.dispatch(line, ctx.sid);
            return result;
        }

        // Handshake processing
        auto hr = engine_.process_incoming_line(line, ctx.state, ctx.sid);

        result.handshake_complete = hr.handshake_complete;
        result.error = hr.error;
        result.error_reason = hr.error_reason;
        result.disconnect = hr.error;

        if (hr.accepted && !hr.response.empty()) {
            result.response = hr.response;
        }

        if (hr.handshake_complete) {
            // Handshake done, now in CONNECTED state
            ctx.sid = hr.remote_sid;
        }

        return result;
    }

    // Feed raw data into a connection's read buffer, returning complete lines
    std::vector<std::string> feed_data(LinkContext& ctx,
                                        const std::string& data) {
        ctx.read_buffer += data;
        ctx.bytes_recv += data.size();

        std::vector<std::string> lines;
        size_t pos;
        while ((pos = ctx.read_buffer.find("\r\n")) != std::string::npos ||
               (pos = ctx.read_buffer.find('\n')) != std::string::npos) {
            size_t end = pos;
            size_t skip = 1;
            if (ctx.read_buffer[pos] == '\r' &&
                pos + 1 < ctx.read_buffer.size() &&
                ctx.read_buffer[pos + 1] == '\n') {
                skip = 2;
            }
            std::string line = ctx.read_buffer.substr(0, end);
            ctx.read_buffer = ctx.read_buffer.substr(end + skip);
            if (!line.empty()) {
                lines.push_back(line);
            }
        }

        // Decompress if needed
        if (ctx.compressed) {
            for (auto& l : lines) {
                l = engine_.compression().decompress(l);
            }
        }

        return lines;
    }

    // Get the list of all active link contexts (would be managed externally
    // by the server's connection tracking)

private:
    S2SProtocolEngine& engine_;
    S2SProtocolDispatcher& dispatcher_;
};

// =============================================================================
// SECTION 18: S2S Server Integration Layer
// =============================================================================

// High-level integration class that ties S2S into the main IRC server.
// This provides the interface that irc_server.cpp would use.
class S2SServerIntegration {
public:
    S2SServerIntegration() : dispatcher_(engine_) {
        connection_mgr_ = std::make_unique<S2SConnectionManager>(
            engine_, dispatcher_);
    }

    // Initialize with local server info
    void init(const std::string& server_name, const std::string& sid,
              const std::string& description,
              const std::string& network_name = "progressive") {
        engine_.set_local_server(server_name, sid, description, network_name);
    }

    // Configure link blocks from config
    void configure_link(const std::string& name, const std::string& host,
                        int port, const std::string& password,
                        bool auto_connect = false, bool tls = true,
                        const std::string& bind_addr = "",
                        const std::string& cert_fingerprint = "") {
        engine_.add_link_block(name, host, port, password, auto_connect,
                                tls, bind_addr);
        if (!cert_fingerprint.empty()) {
            engine_.cert_manager().add_trusted_fingerprint(name, cert_fingerprint);
        }
        engine_.register_incoming_password(name, password);
    }

    // Handle an incoming S2S connection
    S2SConnectionManager::LinkContext accept_incoming() {
        auto ctx = connection_mgr_->create_incoming_context();
        return ctx;
    }

    // Start an outgoing connection
    void connect_to_server(const std::string& server_name) {
        // Build outgoing handshake
        auto hs = engine_.build_outgoing_handshake(
            server_name, "");  // password would come from config
        // The actual TCP connection and sending would be handled
        // by the network layer
    }

    // Process a line from a link context
    S2SConnectionManager::ProcessResult process_link_line(
        S2SConnectionManager::LinkContext& ctx, const std::string& line) {
        return connection_mgr_->process_line(ctx, line);
    }

    // Feed raw TCP data into a link context
    std::vector<std::string> feed_link_data(
        S2SConnectionManager::LinkContext& ctx, const std::string& data) {
        return connection_mgr_->feed_data(ctx, data);
    }

    // =====================================================================
    // User management (called by main server)
    // =====================================================================

    // Allocate a UID for a new local user
    std::string allocate_uid() {
        return engine_.uid_generator().next_uid();
    }

    // Build UID intro message for broadcast
    std::string build_uid_intro(const std::string& nick,
                                 const std::string& ident,
                                 const std::string& host,
                                 const std::string& realname,
                                 const std::string& ip,
                                 const std::string& modes = "i",
                                 const std::string& account = "") {
        return engine_.build_uid_intro(nick, ident, host, realname, ip,
                                        modes, account);
    }

    // =====================================================================
    // Message routing
    // =====================================================================

    // Route a message to its destination
    // Returns the list of target SIDs
    std::vector<std::string> route_message(const std::string& target,
                                            const std::string& source_sid) {
        std::vector<std::string> targets;

        // Channel targets: broadcast to all servers
        if (!target.empty() && (target[0] == '#' || target[0] == '&')) {
            return engine_.routing().get_flood_targets();
        }

        // Check remote users
        auto* user = engine_.remote_users().get_user_by_nick(target);
        if (user) {
            targets.push_back(user->server_sid);
            return targets;
        }

        // Check by UID
        std::string sid = S2SRoutingTable::uid_to_sid(target);
        if (engine_.routing().has_server(sid)) {
            targets.push_back(sid);
            return targets;
        }

        // Unknown target - broadcast (safest)
        return engine_.routing().get_flood_targets();
    }

    // =====================================================================
    // WHOIS delegation
    // =====================================================================

    S2SProtocolEngine::WhoisInfo whois(const std::string& target_nick,
                                         const std::string& requester_uid) {
        return engine_.perform_remote_whois(target_nick, requester_uid);
    }

    // =====================================================================
    // KILL forwarding
    // =====================================================================

    std::string build_kill(const std::string& uid, const std::string& reason) {
        return engine_.build_kill(uid, reason);
    }

    // =====================================================================
    // SQUIT handling
    // =====================================================================

    S2SProtocolEngine::SquitResult squit(const std::string& target_sid,
                                          const std::string& reason) {
        return engine_.do_squit_local(target_sid, reason);
    }

    // =====================================================================
    // Periodic tasks
    // =====================================================================

    // Check for stale links
    std::vector<std::string> check_lagging(int64_t max_lag_ms = 180000) {
        return engine_.check_lagging_servers(max_lag_ms);
    }

    // Get servers needing reconnection
    std::vector<S2SOutgoingAttempt> get_reconnect_targets() {
        return engine_.get_reconnect_targets();
    }

    // Record a connection attempt
    void record_connect_attempt(const std::string& name, bool success) {
        engine_.record_connect_attempt(name, success);
    }

    // Build PING for a server
    std::string build_ping(const std::string& target_sid) {
        return engine_.build_ping(target_sid);
    }

    // =====================================================================
    // Accessors
    // =====================================================================

    S2SProtocolEngine& engine() { return engine_; }
    const S2SProtocolEngine& engine() const { return engine_; }

    S2SProtocolDispatcher& dispatcher() { return dispatcher_; }
    const S2SProtocolDispatcher& dispatcher() const { return dispatcher_; }

    S2SConnectionManager& connection_manager() { return *connection_mgr_; }
    const S2SConnectionManager& connection_manager() const {
        return *connection_mgr_;
    }

private:
    S2SProtocolEngine engine_;
    S2SProtocolDispatcher dispatcher_;
    std::unique_ptr<S2SConnectionManager> connection_mgr_;
};

// =============================================================================
// SECTION 19: Utilities - Server-to-Server Statistics
// =============================================================================

struct S2SStatistics {
    // Link stats
    size_t total_servers       = 0;
    size_t connected_servers   = 0;
    size_t bursting_servers    = 0;
    size_t remote_users_count  = 0;
    size_t local_users_count   = 0;
    size_t active_splits       = 0;

    // Traffic
    int64_t total_bytes_sent   = 0;
    int64_t total_bytes_recv   = 0;
    int64_t total_messages_sent = 0;
    int64_t total_messages_recv = 0;

    // Timing
    int64_t uptime_ms          = 0;
    int64_t last_squit_ts      = 0;
    int64_t last_link_ts       = 0;

    // Burst
    size_t burst_queue_size    = 0;
    size_t pending_burst       = 0;

    std::string serialize() const {
        std::stringstream ss;
        ss << "S2S Statistics:\n";
        ss << "  Servers: " << connected_servers << " connected, "
           << bursting_servers << " bursting (total: " << total_servers << ")\n";
        ss << "  Users: " << local_users_count << " local, "
           << remote_users_count << " remote\n";
        ss << "  Active splits: " << active_splits << "\n";
        ss << "  Traffic: " << total_bytes_sent << " sent, "
           << total_bytes_recv << " recv\n";
        ss << "  Messages: " << total_messages_sent << " sent, "
           << total_messages_recv << " recv\n";
        ss << "  Burst queue: " << burst_queue_size
           << " (pending: " << pending_burst << ")\n";
        ss << "  Uptime: " << (uptime_ms / 1000) << "s\n";
        return ss.str();
    }
};

// =============================================================================
// SECTION 20: Forward declarations and type aliases
// =============================================================================

// Type aliases for convenience
using S2SEngine     = S2SProtocolEngine;
using S2SDispatcher = S2SProtocolDispatcher;
using S2SConnMgr    = S2SConnectionManager;
using S2SIntegration = S2SServerIntegration;
using S2SStats      = S2SStatistics;

}  // namespace irc
}  // namespace progressive
