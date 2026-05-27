// progressive-server: IRC User & Connection Management
// Reference: InspIRCd user.cpp/users.cpp/socketengine.cpp (15,000+ lines combined)
// Full user state machine, nickname tracking, mode cache, privilege handling

#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <memory>
#include <ctime>
#include <mutex>
#include <shared_mutex>
#include <optional>
#include <variant>
#include <chrono>

namespace progressive {
namespace irc {

// =============================================================================
// Numeric replies (RFC 1459, 2812)
// =============================================================================
#define RPL_WELCOME        1
#define RPL_YOURHOST       2
#define RPL_CREATED        3
#define RPL_MYINFO         4
#define RPL_ISUPPORT       5
#define RPL_BOUNCE         10
#define RPL_USERHOST       302
#define RPL_ISON           303
#define RPL_UNAWAY         305
#define RPL_NOWAWAY        306
#define RPL_WHOISUSER      311
#define RPL_WHOISSERVER    312
#define RPL_WHOISOPERATOR  313
#define RPL_WHOISIDLE      317
#define RPL_ENDOFWHOIS     318
#define RPL_WHOISCHANNELS  319
#define RPL_WHOISACCOUNT   330
#define RPL_WHOISSECURE    371
#define RPL_WHOWASUSER     314
#define RPL_ENDOFWHOWAS    369
#define RPL_LISTSTART      321
#define RPL_LIST           322
#define RPL_LISTEND        323
#define RPL_CHANNELMODEIS  324
#define RPL_UNIQOPIS       325
#define RPL_NOTOPIC        331
#define RPL_TOPIC          332
#define RPL_TOPICTIME      333
#define RPL_INVITING       341
#define RPL_SUMMONING      342
#define RPL_VERSION        351
#define RPL_WHOREPLY       352
#define RPL_ENDOFWHO       315
#define RPL_NAMREPLY       353
#define RPL_ENDOFNAMES     366
#define RPL_LINKS          364
#define RPL_ENDOFLINKS     365
#define RPL_BANLIST        367
#define RPL_ENDOFBANLIST   368
#define RPL_INFO           371
#define RPL_ENDOFINFO      374
#define RPL_MOTDSTART      375
#define RPL_MOTD           372
#define RPL_ENDOFMOTD      376
#define RPL_YOUREOPER      381
#define RPL_REHASHING      382
#define RPL_TIME           391
#define RPL_USERSSTART     392
#define RPL_USERS          393
#define RPL_ENDOFUSERS     394
#define RPL_NOUSERS        395
#define RPL_TRACELINK      200
#define RPL_TRACECONNECTING 201
#define RPL_TRACEHANDSHAKE  202
#define RPL_TRACEUNKNOWN   203
#define RPL_TRACEOPERATOR  204
#define RPL_TRACEUSER      205
#define RPL_TRACESERVER    206
#define RPL_TRACENEWTYPE   208
#define RPL_TRACECLASS     209
#define RPL_TRACELOG       261
#define RPL_STATSLINKINFO  211
#define RPL_STATSCOMMANDS  212
#define RPL_STATSCLINE     213
#define RPL_STATSNLINE     214
#define RPL_STATSILINE     215
#define RPL_STATSKLINE     216
#define RPL_STATSYLINE     218
#define RPL_ENDOFSTATS     219
#define RPL_UMODEIS        221
#define RPL_STATSQLINE     228
#define RPL_STATSUPTIME    242
#define RPL_STATSOLINE     243
#define RPL_LUSERCLIENT    251
#define RPL_LUSEROP        252
#define RPL_LUSERUNKNOWN   253
#define RPL_LUSERCHANNELS  254
#define RPL_LUSERME        255
#define RPL_ADMINME        256
#define RPL_ADMINLOC1      257
#define RPL_ADMINLOC2      258
#define RPL_ADMINEMAIL     259
#define RPL_LOCALUSERS     265
#define RPL_GLOBALUSERS    266
#define RPL_CREATIONTIME   329
#define RPL_AWAY           301
#define ERR_NOSUCHNICK     401
#define ERR_NOSUCHSERVER   402
#define ERR_NOSUCHCHANNEL  403
#define ERR_CANNOTSENDTOCHAN 404
#define ERR_TOOMANYCHANNELS 405
#define ERR_WASNOSUCHNICK  406
#define ERR_TOOMANYTARGETS 407
#define ERR_NOORIGIN       409
#define ERR_NORECIPIENT    411
#define ERR_NOTEXTTOSEND   412
#define ERR_NOTOPLEVEL     413
#define ERR_WILDTOPLEVEL   414
#define ERR_UNKNOWNCOMMAND 421
#define ERR_NOMOTD         422
#define ERR_NOADMININFO    423
#define ERR_FILEERROR      424
#define ERR_NONICKNAMEGIVEN 431
#define ERR_ERRONEUSNICKNAME 432
#define ERR_NICKNAMEINUSE  433
#define ERR_NICKCOLLISION  436
#define ERR_USERNOTINCHANNEL 441
#define ERR_NOTONCHANNEL   442
#define ERR_USERONCHANNEL  443
#define ERR_NOLOGIN        444
#define ERR_SUMMONDISABLED 445
#define ERR_USERSDISABLED  446
#define ERR_NOTREGISTERED  451
#define ERR_NEEDMOREPARAMS 461
#define ERR_ALREADYREGISTRED 462
#define ERR_NOPERMFORHOST  463
#define ERR_PASSWDMISMATCH 464
#define ERR_YOUREBANNEDCREEP 465
#define ERR_CHANNELISFULL  471
#define ERR_UNKNOWNMODE    472
#define ERR_INVITEONLYCHAN 473
#define ERR_BANNEDFROMCHAN 474
#define ERR_BADCHANNELKEY  475
#define ERR_BADCHANMASK    476
#define ERR_CHANOPRIVSNEEDED 482
#define ERR_NOPRIVILEGES   481
#define ERR_CANTKILLSERVER 483
#define ERR_NOOPERHOST     491
#define ERR_UMODEUNKNOWNFLAG 501
#define ERR_USERSDONTMATCH  502
#define ERR_NEEDREGGEDNICK  477
#define ERR_SSLONLYCHAN     489
#define ERR_STARTTLS        691

// =============================================================================
// Formatted string builder (avoiding fmtlib dependency in standalone files)
// =============================================================================
namespace detail {
inline std::string vformat(const char* fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    return std::string(buf);
}

inline std::vector<std::string> split_str(const std::string& s, char delim) {
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

inline bool wildcard_match(const std::string& text, const std::string& pattern) {
    size_t ti = 0, pi = 0, star_ti = 0, star_pi = std::string::npos;
    while (ti < text.size()) {
        if (pi < pattern.size() && (pattern[pi] == '?' || pattern[pi] == text[ti])) {
            ti++; pi++;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
            star_pi = pi++;
            star_ti = ti;
        } else if (star_pi != std::string::npos) {
            pi = star_pi + 1;
            ti = ++star_ti;
        } else return false;
    }
    while (pi < pattern.size() && pattern[pi] == '*') pi++;
    return pi == pattern.size();
}

inline std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

inline bool str_contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

inline std::string strip_ctcp(const std::string& text) {
    // Remove \001 markers
    std::string result;
    for (char c : text) {
        if (c != '\001') result += c;
    }
    return result;
}

inline std::pair<std::string, std::string> parse_ctcp(const std::string& text) {
    if (text.size() < 2 || text[0] != '\001') return {};
    size_t end = text.find('\001', 1);
    if (end == std::string::npos) return {};
    std::string inner = text.substr(1, end - 1);
    size_t space = inner.find(' ');
    if (space != std::string::npos) {
        return {inner.substr(0, space), inner.substr(space + 1)};
    }
    return {inner, ""};
}

inline std::string safe_str(const std::string& s, size_t maxlen = 1024) {
    return s.size() > maxlen ? s.substr(0, maxlen) : s;
}

inline std::string ctime_fmt(time_t t) {
    char buf[64];
    std::strftime(buf, sizeof(buf), "%a %b %d %H:%M:%S %Y", std::localtime(&t));
    return std::string(buf);
}

inline int safe_toi(const std::string& s, int def = 0) {
    try { return std::stoi(s); } catch (...) { return def; }
}

inline int64_t safe_toi64(const std::string& s, int64_t def = 0) {
    try { return std::stoll(s); } catch (...) { return def; }
}

inline std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}
} // namespace detail

using detail::vformat;
using detail::split_str;
using detail::wildcard_match;
using detail::to_lower;
using detail::ctime_fmt;
using detail::safe_toi;

// =============================================================================
// IrcMessage - Parsed IRC message
// =============================================================================
struct IrcMessage {
    std::string raw;
    std::string prefix;      // :nick!user@host
    std::string nick;
    std::string ident;
    std::string host;
    std::string command;
    std::vector<std::string> params;

    static std::optional<IrcMessage> parse(const std::string& raw_line) {
        if (raw_line.empty()) return std::nullopt;
        IrcMessage msg;
        msg.raw = raw_line;

        const char* p = raw_line.c_str();
        const char* end = p + raw_line.size();

        // Parse prefix
        if (*p == ':') {
            p++;
            const char* space = (const char*)memchr(p, ' ', end - p);
            if (!space) return std::nullopt;
            msg.prefix = std::string(p, space - p);
            p = space + 1;

            // Parse nick!user@host from prefix
            size_t excl = msg.prefix.find('!');
            size_t at = msg.prefix.find('@');
            if (excl != std::string::npos) {
                msg.nick = msg.prefix.substr(0, excl);
                if (at != std::string::npos && at > excl) {
                    msg.ident = msg.prefix.substr(excl + 1, at - excl - 1);
                    msg.host = msg.prefix.substr(at + 1);
                }
            } else {
                msg.nick = msg.prefix;
            }
        }

        // Parse command
        const char* cmd_start = p;
        while (p < end && *p != ' ') p++;
        msg.command = std::string(cmd_start, p - cmd_start);

        // Parse params
        while (p < end && *p == ' ') p++;
        while (p < end) {
            if (*p == ':') {
                msg.params.push_back(std::string(p + 1, end - p - 1));
                break;
            }
            const char* space = (const char*)memchr(p, ' ', end - p);
            if (!space) {
                msg.params.push_back(std::string(p, end - p));
                break;
            }
            msg.params.push_back(std::string(p, space - p));
            p = space;
            while (p < end && *p == ' ') p++;
        }

        return msg;
    }
};

// =============================================================================
// Socket / Connection types
// =============================================================================
enum class ConnectionState : uint8_t {
    HANDSHAKE,          // TCP accepted, no data yet
    NEGOTIATING,        // STARTTLS / SSL handshake
    REGISTERING,        // NICK/USER not yet complete
    REGISTERED,         // Fully registered
    DISCONNECTING,      // Cleaning up
    CLOSED              // Socket closed
};

enum class ConnectionType : uint8_t {
    CLIENT,             // Regular user connection
    SERVER,             // Server-to-server link
    SERVICE,            // Services connection (NickServ, etc.)
    WEBIRC,             // Web IRC gateway
    UNIX_SOCKET,        // Local UNIX socket
    WEBSOCKET           // WebSocket connection
};

struct ConnectionStats {
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;
    uint64_t messages_in = 0;
    uint64_t messages_out = 0;
    time_t connected_at = 0;
    time_t last_activity = 0;
    std::string remote_addr;
    uint16_t remote_port = 0;
    bool ssl = false;
    std::string ssl_cipher;
    std::string ssl_fingerprint;
};

// =============================================================================
// Ban / Except / Invite masks
// =============================================================================
struct BanMask {
    std::string mask;
    time_t set_at;
    std::string set_by;

    bool matches(const std::string& nick, const std::string& ident,
                 const std::string& host) const {
        std::string target = nick + "!" + ident + "@" + host;
        return wildcard_match(target, mask);
    }
};

// =============================================================================
// IRC User
// =============================================================================
class IrcUser {
public:
    using ptr = std::shared_ptr<IrcUser>;
    using wptr = std::weak_ptr<IrcUser>;

    explicit IrcUser(const std::string& uuid) : uuid_(uuid) {
        signon_time_ = std::time(nullptr);
        last_activity_ = signon_time_;
        last_pong_ = signon_time_;
    }

    // ===== Identity =====
    const std::string& uuid() const { return uuid_; }
    const std::string& nick() const { return nick_; }
    const std::string& ident() const { return ident_; }
    const std::string& hostname() const { return hostname_; }
    const std::string& realname() const { return realname_; }
    const std::string& remote_addr() const { return conn_stats_.remote_addr; }

    void set_nick(const std::string& n) {
        previous_nicks_.push_back({nick_, std::time(nullptr)});
        if (previous_nicks_.size() > 10) previous_nicks_.erase(previous_nicks_.begin());
        nick_ = n;
    }
    void set_ident(const std::string& i) { ident_ = i; }
    void set_hostname(const std::string& h) { hostname_ = h; }
    void set_realname(const std::string& r) { realname_ = r; }

    // Nick history entry
    struct NickEntry {
        std::string nick;
        time_t changed_at;
    };
    const std::vector<NickEntry>& nick_history() const { return previous_nicks_; }

    // ===== Connection =====
    ConnectionState state() const { return state_; }
    void set_state(ConnectionState s) { state_ = s; }
    ConnectionType conn_type() const { return conn_type_; }
    void set_conn_type(ConnectionType t) { conn_type_ = t; }

    bool is_registered() const { return state_ >= ConnectionState::REGISTERED; }
    void set_registered(bool v) {
        state_ = v ? ConnectionState::REGISTERED : ConnectionState::REGISTERING;
        if (v) signon_time_ = std::time(nullptr);
    }

    // ===== Password =====
    const std::string& password() const { return password_; }
    void set_password(const std::string& p) { password_ = p; }

    // ===== Modes =====
    bool has_mode(char mode) const {
        return user_modes_.find(mode) != user_modes_.end();
    }
    void set_mode(char mode, bool on) {
        if (on) user_modes_.insert(mode);
        else user_modes_.erase(mode);
    }
    void add_mode(char mode) { user_modes_.insert(mode); }
    void remove_mode(char mode) { user_modes_.erase(mode); }
    std::string mode_string() const {
        std::string result;
        for (char c : user_modes_) result += c;
        std::sort(result.begin(), result.end());
        return result;
    }

    bool is_invisible() const { return has_mode('i'); }
    bool is_oper() const { return has_mode('o'); }
    bool is_wallops() const { return has_mode('w'); }
    void set_oper(bool v) {
        if (v) add_mode('o'); else remove_mode('o');
    }

    // ===== Channel membership =====
    void add_channel(const std::string& name) {
        channels_[name] = std::time(nullptr);
    }
    void remove_channel(const std::string& name) {
        channels_.erase(name);
    }
    void clear_channels() { channels_.clear(); }
    const std::unordered_map<std::string, time_t>& channels() const { return channels_; }
    bool is_in_channel(const std::string& name) const {
        return channels_.count(to_lower(name)) > 0;
    }
    size_t channel_count() const { return channels_.size(); }

    // ===== Away =====
    bool is_away() const { return away_; }
    const std::string& away_message() const { return away_msg_; }
    void set_away(bool v) { away_ = v; }
    void set_away_message(const std::string& m) { away_msg_ = m; }

    // ===== SSL =====
    bool is_ssl() const { return conn_stats_.ssl; }
    void set_ssl(bool v) { conn_stats_.ssl = v; }
    const std::string& ssl_cipher() const { return conn_stats_.ssl_cipher; }
    const std::string& ssl_fingerprint() const { return conn_stats_.ssl_fingerprint; }

    // ===== Registered account (NickServ) =====
    const std::string& account() const { return account_; }
    void set_account(const std::string& a) { account_ = a; }
    bool is_registered_nick() const { return !account_.empty(); }

    // ===== Timing =====
    time_t signon_time() const { return signon_time_; }
    void set_signon_time(time_t t) { signon_time_ = t; }
    time_t last_activity() const { return last_activity_; }
    void mark_activity() { last_activity_ = std::time(nullptr); }
    void set_last_pong(time_t t) { last_pong_ = t; }
    time_t last_pong() const { return last_pong_; }
    int64_t idle_seconds() const {
        return std::time(nullptr) - last_activity_;
    }
    time_t last_activity_time() const { return last_activity_; }

    // ===== Connection stats =====
    ConnectionStats& stats() { return conn_stats_; }
    const ConnectionStats& stats() const { return conn_stats_; }

    // ===== Numeric helpers =====
    void numeric(int num, const std::string& a1 = "", const std::string& a2 = "",
                 const std::string& a3 = "", const std::string& a4 = "") {
        std::string msg = vformat(":%s %03d %s", server_name_.c_str(), num, nick_.c_str());
        if (!a1.empty()) msg += " " + a1;
        if (!a2.empty()) msg += " :" + a2;
        if (!a3.empty()) msg += " " + a3;
        if (!a4.empty()) msg += " " + a4;
        send_queue_.push_back(msg);
    }

    void raw(const std::string& line) {
        send_queue_.push_back(line);
    }

    std::vector<std::string> drain_queue() {
        std::vector<std::string> result;
        std::swap(result, send_queue_);
        return result;
    }

    // ===== ACL / Flags =====
    enum class Flag : uint32_t {
        NONE              = 0,
        DEAF              = 1 << 0,    // Doesn't receive channel messages
        NO_CALLERID       = 1 << 1,    // Can't use callerid
        CUSTOM_TITLE      = 1 << 2,
        NO_HIGHLIGHT      = 1 << 3,
        ALLOW_BOT         = 1 << 4,
        WEBIRC            = 1 << 5,
        CLIENT_CERT       = 1 << 6,
        PERSISTENT        = 1 << 7,
        CANNOT_CHANGE_IDENT = 1 << 8,
        SPAMBOT           = 1 << 9,
        ANTISPAM_BYPASS   = 1 << 10
    };

    void set_flag(Flag f, bool on) {
        if (on) flags_ |= static_cast<uint32_t>(f);
        else flags_ &= ~static_cast<uint32_t>(f);
    }
    bool has_flag(Flag f) const { return (flags_ & static_cast<uint32_t>(f)) != 0; }

    // ===== WHOX / extended fields =====
    std::string who_fields(const std::string& fields) const {
        std::string result;
        for (char c : fields) {
            switch (c) {
            case 'a': result += account_.empty() ? "0 " : (account_ + " "); break;
            case 'n': result += nick_ + " "; break;
            case 'u': result += ident_ + " "; break;
            case 'h': result += hostname_ + " "; break;
            case 'r': result += realname_ + " "; break;
            case 's': result += server_name_ + " "; break;
            case 'i': result += std::to_string(idle_seconds()) + " "; break;
            case 'o': result += (is_oper() ? "1 " : "0 "); break;
            case 'd': result += std::to_string(0) + " "; break; // hop count
            case 'l': result += std::to_string(0) + " "; break; // server level
            case 'c': result += account_ + " "; break;
            case 'f': result += std::to_string(flags_) + " "; break;
            }
        }
        if (!result.empty()) result.pop_back(); // trailing space
        return result;
    }

    void set_server_name(const std::string& s) { server_name_ = s; }

private:
    std::string uuid_;
    std::string nick_;
    std::string ident_ = "~user";
    std::string hostname_;
    std::string realname_ = "Real Name";
    std::string password_;
    std::string account_;
    std::string server_name_ = "progressive.local";

    ConnectionState state_ = ConnectionState::HANDSHAKE;
    ConnectionType conn_type_ = ConnectionType::CLIENT;
    ConnectionStats conn_stats_;

    std::unordered_set<char> user_modes_;        // i, w, s, o, x
    std::unordered_map<std::string, time_t> channels_; // name -> join time
    std::vector<NickEntry> previous_nicks_;

    bool away_ = false;
    std::string away_msg_;

    time_t signon_time_ = 0;
    time_t last_activity_ = 0;
    time_t last_pong_ = 0;

    uint32_t flags_ = 0;

    std::vector<std::string> send_queue_;
};

// =============================================================================
// Channel Membership
// =============================================================================
class IrcMembership {
public:
    using ptr = std::shared_ptr<IrcMembership>;

    IrcMembership(const std::string& uuid, const std::string& channel)
        : user_uuid_(uuid), channel_name_(channel) {
        join_time_ = std::time(nullptr);
    }

    const std::string& uuid() const { return user_uuid_; }
    const std::string& channel() const { return channel_name_; }
    time_t join_time() const { return join_time_; }
    void set_join_time(time_t t) { join_time_ = t; }

    // Prefix modes: o(operator), v(voice), h(halfop), a(protect/admin), q(founder/owner)
    bool has_mode(char c) const {
        return prefix_modes_.find(c) != prefix_modes_.end();
    }
    void set_prefix_mode(char c, bool on) {
        if (on) prefix_modes_.insert(c);
        else prefix_modes_.erase(c);
    }
    std::string prefix_string() const {
        std::string result;
        if (has_mode('q')) result += '~';
        else if (has_mode('a')) result += '&';
        else if (has_mode('o')) result += '@';
        else if (has_mode('h')) result += '%';
        else if (has_mode('v')) result += '+';
        return result;
    }

    bool is_operator() const { return has_mode('o') || has_mode('a') || has_mode('q'); }
    bool is_voiced() const { return has_mode('v') || is_operator(); }

private:
    std::string user_uuid_;
    std::string channel_name_;
    time_t join_time_ = 0;
    std::unordered_set<char> prefix_modes_;
};

// =============================================================================
// Channel
// =============================================================================
class IrcChannel {
public:
    using ptr = std::shared_ptr<IrcChannel>;

    explicit IrcChannel(const std::string& name, time_t created = 0)
        : name_(name), creation_time_(created ? created : std::time(nullptr)) {}

    const std::string& name() const { return name_; }
    time_t creation_time() const { return creation_time_; }

    // ===== Topic =====
    const std::string& topic() const { return topic_; }
    void set_topic(const std::string& t) { topic_ = t; }
    const std::string& topic_setter() const { return topic_setter_; }
    void set_topic_setter(const std::string& s) { topic_setter_ = s; }
    time_t topic_time() const { return topic_time_; }
    void set_topic_time(time_t t) { topic_time_ = t; }

    // ===== Membership =====
    void add_member(IrcMembership::ptr memb) {
        std::lock_guard lock(mutex_);
        members_.push_back(memb);
        member_index_[memb->uuid()] = members_.size() - 1;
    }
    void remove_member(const std::string& uuid) {
        std::lock_guard lock(mutex_);
        auto it = member_index_.find(uuid);
        if (it != member_index_.end()) {
            size_t idx = it->second;
            if (idx < members_.size()) {
                // Move last to this position and pop
                if (idx != members_.size() - 1) {
                    members_[idx] = std::move(members_.back());
                    member_index_[members_[idx]->uuid()] = idx;
                }
                members_.pop_back();
            }
            member_index_.erase(it);
        }
    }
    IrcMembership::ptr find_member(const std::string& uuid) {
        auto it = member_index_.find(uuid);
        if (it != member_index_.end() && it->second < members_.size()) {
            return members_[it->second];
        }
        return nullptr;
    }
    bool has_member(const std::string& uuid) const {
        return member_index_.count(uuid) > 0;
    }
    size_t member_count() const { return members_.size(); }
    size_t visible_member_count() const {
        // Count non-invisible members (used for LIST)
        return members_.size();
    }
    const std::vector<IrcMembership::ptr>& members() const { return members_; }

    // ===== Broadcast =====
    template<typename SendFunc>
    void broadcast(const std::string& message, const std::string& skip_uuid,
                   SendFunc send_fn) {
        std::lock_guard lock(mutex_);
        for (auto& m : members_) {
            if (m->uuid() != skip_uuid) {
                send_fn(m->uuid(), message);
            }
        }
    }

    // ===== Channel modes (flag) =====
    void set_topic_restricted(bool v) { set_flag(FLAG_TOPICRESTRICT, v); }
    bool is_topic_restricted() const { return has_flag(FLAG_TOPICRESTRICT); }
    void set_invite_only(bool v) { set_flag(FLAG_INVITEONLY, v); }
    bool is_invite_only() const { return has_flag(FLAG_INVITEONLY); }
    void set_moderated(bool v) { set_flag(FLAG_MODERATED, v); }
    bool is_moderated() const { return has_flag(FLAG_MODERATED); }
    void set_no_external(bool v) { set_flag(FLAG_NOEXTERNAL, v); }
    bool is_no_external() const { return has_flag(FLAG_NOEXTERNAL); }
    void set_secret(bool v) { set_flag(FLAG_SECRET, v); }
    bool is_secret() const { return has_flag(FLAG_SECRET); }
    void set_private(bool v) { set_flag(FLAG_PRIVATE, v); }
    bool is_private() const { return has_flag(FLAG_PRIVATE); }
    void set_registered_only(bool v) { set_flag(FLAG_REGONLY, v); }
    bool is_registered_only() const { return has_flag(FLAG_REGONLY); }
    void set_ssl_only(bool v) { set_flag(FLAG_SSLONLY, v); }
    bool is_ssl_only() const { return has_flag(FLAG_SSLONLY); }
    void set_no_colors(bool v) { set_flag(FLAG_NOCOLORS, v); }
    bool is_no_colors() const { return has_flag(FLAG_NOCOLORS); }
    void set_no_ctcp(bool v) { set_flag(FLAG_NOCTCP, v); }
    bool is_no_ctcp() const { return has_flag(FLAG_NOCTCP); }
    void set_no_nick_change(bool v) { set_flag(FLAG_NONICKCHG, v); }
    bool is_no_nick_change() const { return has_flag(FLAG_NONICKCHG); }
    void set_no_kick(bool v) { set_flag(FLAG_NOKICK, v); }
    bool is_no_kick() const { return has_flag(FLAG_NOKICK); }
    void set_no_notice(bool v) { set_flag(FLAG_NONOTICE, v); }
    bool is_no_notice() const { return has_flag(FLAG_NONOTICE); }
    void set_no_invite(bool v) { set_flag(FLAG_NOINVITE, v); }
    bool is_no_invite() const { return has_flag(FLAG_NOINVITE); }
    void set_no_privmsg(bool v) { set_flag(FLAG_NOPRIVMSG, v); }
    bool is_no_privmsg() const { return has_flag(FLAG_NOPRIVMSG); }
    void set_strip_color(bool v) { set_flag(FLAG_STRIPCOLOR, v); }
    bool is_strip_color() const { return has_flag(FLAG_STRIPCOLOR); }
    void set_no_knock(bool v) { set_flag(FLAG_NOKNOCK, v); }
    bool is_no_knock() const { return has_flag(FLAG_NOKNOCK); }
    void set_blockcaps(bool v) { set_flag(FLAG_BLOCKCAPS, v); }
    bool is_blockcaps() const { return has_flag(FLAG_BLOCKCAPS); }
    void set_op_moderated(bool v) { set_flag(FLAG_OPMODERATED, v); }
    bool is_op_moderated() const { return has_flag(FLAG_OPMODERATED); }
    void set_permanent(bool v) { set_flag(FLAG_PERMANENT, v); }
    bool is_permanent() const { return has_flag(FLAG_PERMANENT); }
    void set_persistent(bool v) { set_flag(FLAG_PERSISTENT, v); }
    bool is_persistent() const { return has_flag(FLAG_PERSISTENT); }
    void set_auto_op(bool v) { set_flag(FLAG_AUTOOP, v); }
    bool is_auto_op() const { return has_flag(FLAG_AUTOOP); }

    std::string mode_string() const {
        std::string result;
        if (is_invite_only()) result += 'i';
        if (is_moderated()) result += 'm';
        if (is_no_external()) result += 'n';
        if (is_secret()) result += 's';
        if (is_topic_restricted()) result += 't';
        if (is_registered_only()) result += 'r';
        if (is_ssl_only()) result += 'z';
        if (is_no_colors()) result += 'c';
        if (is_no_ctcp()) result += 'C';
        if (is_no_nick_change()) result += 'N';
        if (is_no_kick()) result += 'K';
        if (is_strip_color()) result += 'G';
        if (is_blockcaps()) result += 'B';
        if (is_op_moderated()) result += 'U';
        if (is_no_notice()) result += 'T';
        if (is_no_privmsg()) result += 'M';
        if (is_permanent()) result += 'P';
        if (is_no_knock()) result += 'J';
        std::sort(result.begin(), result.end());
        if (!key_.empty()) result += "k";
        if (user_limit_ > 0) result += "l";
        return result;
    }

    // ===== Key =====
    const std::string& key() const { return key_; }
    void set_key(const std::string& k) { key_ = k; }

    // ===== User limit =====
    int user_limit() const { return user_limit_; }
    void set_user_limit(int l) { user_limit_ = l; }

    // ===== Bans =====
    void add_ban(const std::string& mask) {
        ban_list_.push_back({mask, std::time(nullptr), ""});
    }
    void remove_ban(const std::string& mask) {
        ban_list_.erase(std::remove_if(ban_list_.begin(), ban_list_.end(),
            [&](const BanMask& b) { return b.mask == mask; }), ban_list_.end());
    }
    bool is_banned(const std::string& full_mask) const {
        for (auto& b : ban_list_) {
            if (wildcard_match(full_mask, b.mask)) return true;
        }
        return false;
    }
    const std::vector<BanMask>& bans() const { return ban_list_; }

    // ===== Ban exceptions =====
    void add_except(const std::string& mask) {
        except_list_.push_back({mask, std::time(nullptr), ""});
    }
    void remove_except(const std::string& mask) {
        except_list_.erase(std::remove_if(except_list_.begin(), except_list_.end(),
            [&](const BanMask& b) { return b.mask == mask; }), except_list_.end());
    }
    const std::vector<BanMask>& excepts() const { return except_list_; }

    // ===== Invite exceptions =====
    void add_invex(const std::string& mask) {
        invex_list_.push_back({mask, std::time(nullptr), ""});
    }
    void remove_invex(const std::string& mask) {
        invex_list_.erase(std::remove_if(invex_list_.begin(), invex_list_.end(),
            [&](const BanMask& b) { return b.mask == mask; }), invex_list_.end());
    }
    const std::vector<BanMask>& invexes() const { return invex_list_; }

    // ===== Invites =====
    void add_invite(const std::string& uuid) { invites_.insert(uuid); }
    bool has_invite(const std::string& uuid) const { return invites_.count(uuid) > 0; }
    void clear_invites() { invites_.clear(); }

    // ===== Forward =====
    const std::string& forward_channel() const { return forward_channel_; }
    void set_forward_channel(const std::string& f) { forward_channel_ = f; }

private:
    enum Flags : uint64_t {
        FLAG_INVITEONLY    = 1ULL << 0,
        FLAG_MODERATED     = 1ULL << 1,
        FLAG_NOEXTERNAL    = 1ULL << 2,
        FLAG_TOPICRESTRICT = 1ULL << 3,
        FLAG_SECRET        = 1ULL << 4,
        FLAG_PRIVATE       = 1ULL << 5,
        FLAG_REGONLY       = 1ULL << 6,
        FLAG_SSLONLY       = 1ULL << 7,
        FLAG_NOCOLORS      = 1ULL << 8,
        FLAG_NOCTCP        = 1ULL << 9,
        FLAG_NONICKCHG     = 1ULL << 10,
        FLAG_NOKICK        = 1ULL << 11,
        FLAG_NONOTICE      = 1ULL << 12,
        FLAG_NOINVITE      = 1ULL << 13,
        FLAG_NOPRIVMSG     = 1ULL << 14,
        FLAG_STRIPCOLOR    = 1ULL << 15,
        FLAG_NOKNOCK       = 1ULL << 16,
        FLAG_BLOCKCAPS     = 1ULL << 17,
        FLAG_OPMODERATED   = 1ULL << 18,
        FLAG_PERMANENT     = 1ULL << 19,
        FLAG_PERSISTENT    = 1ULL << 20,
        FLAG_AUTOOP        = 1ULL << 21,
    };

    void set_flag(Flags f, bool v) {
        if (v) flags_ |= f; else flags_ &= ~f;
    }
    bool has_flag(Flags f) const { return (flags_ & f) != 0; }

    std::string name_;
    time_t creation_time_;
    std::string topic_;
    std::string topic_setter_;
    time_t topic_time_ = 0;
    std::string key_;
    int user_limit_ = 0;
    uint64_t flags_ = FLAG_NOEXTERNAL; // +n by default

    std::vector<IrcMembership::ptr> members_;
    std::unordered_map<std::string, size_t> member_index_;
    std::vector<BanMask> ban_list_;
    std::vector<BanMask> except_list_;
    std::vector<BanMask> invex_list_;
    std::unordered_set<std::string> invites_;
    std::string forward_channel_;

    mutable std::mutex mutex_;
};

// =============================================================================
// Whowas entry
// =============================================================================
struct WhowasEntry {
    std::string nick;
    std::string ident;
    std::string hostname;
    std::string realname;
    std::string server_name;
    time_t signoff_time;
};

// =============================================================================
// Server link (S2S)
// =============================================================================
struct ServerLink {
    std::string name;
    std::string description;
    std::string host;
    uint16_t port = 0;
    std::string password;
    std::string fingerprint;
    bool auto_connect = false;
    bool tls = true;
    int sent = 0;
    int received = 0;
    std::string uptime = "0 days";
    int connections = 0;
};

// =============================================================================
// IRC Server main class
// =============================================================================
class IrcServerInstance {
public:
    IrcServerInstance() = default;

    // ========== User management ==========
    IrcUser::ptr find_user_by_uuid(const std::string& uuid) {
        auto it = users_by_uuid_.find(uuid);
        return (it != users_by_uuid_.end()) ? it->second : nullptr;
    }

    IrcUser::ptr find_user_by_nick(const std::string& nick) {
        auto it = users_by_nick_.find(to_lower(nick));
        return (it != users_by_nick_.end()) ? it->second : nullptr;
    }

    void add_user(IrcUser::ptr user) {
        users_by_uuid_[user->uuid()] = user;
        if (!user->nick().empty()) {
            users_by_nick_[to_lower(user->nick())] = user;
        }
    }

    void remove_user(const std::string& uuid) {
        auto it = users_by_uuid_.find(uuid);
        if (it != users_by_uuid_.end()) {
            auto user = it->second;
            if (!user->nick().empty()) {
                users_by_nick_.erase(to_lower(user->nick()));
            }
            // Save to whowas
            WhowasEntry entry;
            entry.nick = user->nick();
            entry.ident = user->ident();
            entry.hostname = user->hostname();
            entry.realname = user->realname();
            entry.signoff_time = std::time(nullptr);
            whowas_[to_lower(user->nick())].push_back(entry);
            if (whowas_[to_lower(user->nick())].size() > 10) {
                whowas_[to_lower(user->nick())].erase(
                    whowas_[to_lower(user->nick())].begin());
            }
            users_by_uuid_.erase(it);
        }
    }

    void update_user_nick(const std::string& old_nick, const std::string& new_nick,
                          IrcUser::ptr user) {
        if (!old_nick.empty()) users_by_nick_.erase(to_lower(old_nick));
        users_by_nick_[to_lower(new_nick)] = user;
    }

    std::vector<IrcUser::ptr> get_all_users() const {
        std::vector<IrcUser::ptr> result;
        for (auto& [_, user] : users_by_uuid_) {
            result.push_back(user);
        }
        return result;
    }

    size_t user_count() const { return users_by_uuid_.size(); }
    size_t oper_count() const {
        size_t count = 0;
        for (auto& [_, u] : users_by_uuid_) {
            if (u->is_oper()) count++;
        }
        return count;
    }
    size_t invisible_count() const {
        size_t count = 0;
        for (auto& [_, u] : users_by_uuid_) {
            if (u->is_invisible()) count++;
        }
        return count;
    }

    // ========== Whowas ==========
    std::vector<WhowasEntry> get_whowas(const std::string& nick, int count = 1) {
        auto it = whowas_.find(to_lower(nick));
        if (it == whowas_.end()) return {};
        auto& entries = it->second;
        std::vector<WhowasEntry> result;
        int start = std::max(0, (int)entries.size() - count);
        for (int i = start; i < (int)entries.size(); i++) {
            result.push_back(entries[i]);
        }
        return result;
    }

    // ========== Channel management ==========
    IrcChannel::ptr find_channel(const std::string& name) {
        auto it = channels_.find(to_lower(name));
        return (it != channels_.end()) ? it->second : nullptr;
    }

    IrcChannel::ptr create_channel(const std::string& name) {
        auto ch = std::make_shared<IrcChannel>(name);
        channels_[to_lower(name)] = ch;
        return ch;
    }

    void destroy_channel(const std::string& name) {
        channels_.erase(to_lower(name));
    }

    const std::unordered_map<std::string, IrcChannel::ptr>& all_channels() const {
        return channels_;
    }

    size_t channel_count() const { return channels_.size(); }

    bool shares_channel(IrcUser::ptr a, IrcUser::ptr b) {
        for (auto& [ch_name, _] : a->channels()) {
            auto ch = find_channel(ch_name);
            if (ch && ch->has_member(b->uuid())) return true;
        }
        return false;
    }

    // ========== Config ==========
    const std::string& server_name() const { return server_name_; }
    void set_server_name(const std::string& n) { server_name_ = n; }
    const std::string& network_name() const { return network_name_; }
    void set_network_name(const std::string& n) { network_name_ = n; }
    const std::string& server_desc() const { return server_desc_; }
    void set_server_desc(const std::string& d) { server_desc_ = d; }
    const std::string& version_string() const { return version_string_; }
    void set_version_string(const std::string& v) { version_string_ = v; }

    time_t creation_time() const { return creation_time_; }
    void set_creation_time(time_t t) { creation_time_ = t; }

    // ========== MOTD ==========
    void set_motd(const std::vector<std::string>& lines) { motd_ = lines; }
    const std::vector<std::string>& motd() const { return motd_; }

    // ========== Info / Admin ==========
    struct AdminEntry {
        std::string location;
        std::string description;
        std::string email;
    };
    void set_admin_info(const std::vector<AdminEntry>& admins) { admin_info_ = admins; }
    const std::vector<AdminEntry>& admin_info() const { return admin_info_; }

    void set_info_lines(const std::vector<std::string>& lines) { info_lines_ = lines; }
    const std::vector<std::string>& info_lines() const { return info_lines_; }

    // ========== Server links ==========
    void add_server_link(const ServerLink& link) { server_links_.push_back(link); }
    const std::vector<ServerLink>& server_links() const { return server_links_; }

    // ========== Stats ==========
    struct ServerStats {
        int visible_users = 0;
        int invisible_users = 0;
        int operators = 0;
        int unknown_connections = 0;
        int channels = 0;
        int servers = 1;
        int local_users = 0;
        int local_servers = 0;
        int max_local_users = 0;
        int global_users = 0;
        int max_global_users = 0;
    };

    ServerStats get_stats() {
        ServerStats s;
        s.visible_users = (int)user_count() - (int)invisible_count();
        s.invisible_users = (int)invisible_count();
        s.operators = (int)oper_count();
        s.channels = (int)channel_count();
        s.local_users = (int)user_count();
        s.local_servers = 0;
        return s;
    }

    // ========== Oper ==========
    bool check_oper_credentials(const std::string& name, const std::string& pass) {
        for (auto& op : oper_configs_) {
            if (op.name == name && op.password == pass) return true;
        }
        return false;
    }

    struct OperConfig {
        std::string name;
        std::string password;
        std::string host;
        std::string type;
    };

    void add_oper_config(const OperConfig& cfg) { oper_configs_.push_back(cfg); }
    const std::vector<OperConfig>& oper_configs() const { return oper_configs_; }

    // ========== Password ==========
    bool verify_password(const std::string& pass) {
        if (server_pass_.empty()) return true;
        return pass == server_pass_;
    }
    void set_server_password(const std::string& p) { server_pass_ = p; }

    // ========== Connect blocks ==========
    struct ConnectBlock {
        std::string host;
        std::string name;
        int port;
        std::string class_name;
    };
    void add_connect_block(const ConnectBlock& b) { connect_blocks_.push_back(b); }
    const std::vector<ConnectBlock>& connect_blocks() const { return connect_blocks_; }

    // ========== Compile info ==========
    const std::string& compile_info() const { return compile_info_; }
    void set_compile_info(const std::string& i) { compile_info_ = i; }

    // ========== Account ==========
    std::string get_account(const std::string& uuid) {
        auto user = find_user_by_uuid(uuid);
        return user ? user->account() : "";
    }

    void link_account(const std::string& uuid, const std::string& account) {
        auto user = find_user_by_uuid(uuid);
        if (user) user->set_account(account);
    }

    // ========== Time ==========
    int64_t uptime_seconds() const {
        return std::time(nullptr) - creation_time_;
    }

    std::string uptime_str() const {
        int64_t secs = uptime_seconds();
        int days = secs / 86400;
        int hours = (secs % 86400) / 3600;
        int mins = (secs % 3600) / 60;
        return vformat("%d days %02d:%02d:%02d", days, hours, mins,
                       (int)(secs % 60));
    }

private:
    std::string server_name_ = "progressive.local";
    std::string network_name_ = "Progressive";
    std::string server_desc_ = "Progressive IRC Server";
    std::string version_string_ = "progressive-server-0.1.0";
    std::string compile_info_ = "gcc 16.1 C++20";
    std::string server_pass_;

    time_t creation_time_ = std::time(nullptr);

    std::unordered_map<std::string, IrcUser::ptr> users_by_uuid_;
    std::unordered_map<std::string, IrcUser::ptr> users_by_nick_;
    std::unordered_map<std::string, std::vector<WhowasEntry>> whowas_;
    std::unordered_map<std::string, IrcChannel::ptr> channels_;

    std::vector<std::string> motd_;
    std::vector<std::string> info_lines_;
    std::vector<AdminEntry> admin_info_;
    std::vector<ServerLink> server_links_;
    std::vector<OperConfig> oper_configs_;
    std::vector<ConnectBlock> connect_blocks_;
};

} // namespace irc
} // namespace progressive
