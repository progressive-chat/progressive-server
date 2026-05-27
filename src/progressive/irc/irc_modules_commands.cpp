// progressive-server: IRC extended commands, module system, operator tools
// Reference: InspIRCd modules/*, core_info/cmd_*.cpp, m_*.cpp (80+ modules)
// WHOX, MONITOR, WATCH, KNOCK, SILENCE, ACCEPT, CALLERID, oper override

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <functional>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <atomic>
#include <mutex>
#include <deque>

namespace progressive {
namespace irc {

// Forward declaration
class IrcUser; using UserPtr = std::shared_ptr<IrcUser>;

// =============================================================================
// Module system
// =============================================================================
enum class ModulePriority : uint8_t {
    FIRST = 0, EARLY = 25, NORMAL = 50, LATE = 75, LAST = 100
};

enum class HookType : uint8_t {
    ON_USER_CONNECT, ON_USER_DISCONNECT, ON_USER_REGISTER,
    ON_USER_JOIN, ON_USER_PART, ON_USER_KICK, ON_USER_QUIT,
    ON_USER_MESSAGE, ON_USER_NOTICE, ON_USER_NICK_CHANGE,
    ON_CHANNEL_CREATE, ON_CHANNEL_DESTROY,
    ON_OPER_LOGIN, ON_OPER_LOGOUT,
    ON_PRE_COMMAND, ON_POST_COMMAND,
    ON_CHECK_BAN, ON_CHECK_INVITE,
    ON_STATS, ON_WHOIS, ON_NAMES,
    ON_ACCEPT_CONNECTION,
    ON_SERVER_LINK, ON_SERVER_SPLIT,
    ON_MODULE_LOAD, ON_MODULE_UNLOAD,
    ON_BACKGROUND_TIMER,
    ON_DNS_RESOLVED,
    ON_RAW_MESSAGE,
};

struct ModuleHook {
    std::string module_name;
    HookType type;
    ModulePriority priority;
    std::function<bool(UserPtr, const std::string&)> callback;
};

class ModuleManager {
public:
    struct Module {
        std::string name;
        std::string version;
        std::string description;
        std::string author;
        bool loaded = false;
        void* handle = nullptr; // dlopen handle
    };

    bool load_module(const std::string& name) {
        if (modules_.count(name)) return false;

        Module mod;
        mod.name = name;
        mod.loaded = true;
        modules_[name] = mod;
        fire_hook(HookType::ON_MODULE_LOAD, nullptr, name);
        return true;
    }

    bool unload_module(const std::string& name) {
        auto it = modules_.find(name);
        if (it == modules_.end()) return false;

        fire_hook(HookType::ON_MODULE_UNLOAD, nullptr, name);
        modules_.erase(it);
        return true;
    }

    void register_hook(const std::string& module_name, HookType type,
                       ModulePriority priority,
                       std::function<bool(UserPtr, const std::string&)> cb) {
        hooks_.push_back({module_name, type, priority, cb});
        std::sort(hooks_.begin(), hooks_.end(),
            [](const ModuleHook& a, const ModuleHook& b) {
                return static_cast<int>(a.priority) < static_cast<int>(b.priority);
            });
    }

    // Fire a hook — returns true if event should be blocked
    bool fire_hook(HookType type, UserPtr user, const std::string& data = "") {
        for (auto& hook : hooks_) {
            if (hook.type == type && modules_.count(hook.module_name) &&
                modules_[hook.module_name].loaded) {
                if (hook.callback(user, data)) return true; // event blocked
            }
        }
        return false;
    }

    std::vector<std::string> loaded_modules() const {
        std::vector<std::string> result;
        for (auto& [name, mod] : modules_) {
            result.push_back(name);
        }
        return result;
    }

    const Module* get_module(const std::string& name) const {
        auto it = modules_.find(name);
        return (it != modules_.end()) ? &it->second : nullptr;
    }

private:
    std::unordered_map<std::string, Module> modules_;
    std::vector<ModuleHook> hooks_;
};

// =============================================================================
// WHOX (extended WHO with field selection)
// =============================================================================
struct WhoxField {
    char flag;           // 'a','n','u','h','r','s','i','o','d','l','c','f','t'
    std::string label;   // descriptive name
    std::function<std::string(UserPtr, const std::string& channel)> extractor;
};

class WhoxEngine {
public:
    WhoxEngine() {
        register_field('a', "account", [](UserPtr u, const std::string&) {
            return u->account().empty() ? "0" : u->account();
        });
        register_field('n', "nick", [](UserPtr u, const std::string&) {
            return u->nick();
        });
        register_field('u', "username", [](UserPtr u, const std::string&) {
            return u->ident();
        });
        register_field('h', "hostname", [](UserPtr u, const std::string&) {
            return u->hostname();
        });
        register_field('r', "realname", [](UserPtr u, const std::string&) {
            return u->realname();
        });
        register_field('s', "servername", [](UserPtr u, const std::string&) {
            return "server.name";
        });
        register_field('i', "idle", [](UserPtr u, const std::string&) {
            return std::to_string(u->idle_seconds());
        });
        register_field('o', "opLevel", [](UserPtr u, const std::string&) {
            return u->is_oper() ? "1" : "0";
        });
        register_field('d', "hopcount", [](UserPtr u, const std::string&) {
            return "0"; // local user
        });
        register_field('l', "idle-ts", [](UserPtr u, const std::string&) {
            return std::to_string(u->last_activity_time());
        });
        register_field('c', "channel", [](UserPtr u, const std::string& ch) {
            return ch;
        });
        register_field('f', "flags", [](UserPtr u, const std::string&) {
            std::string f;
            if (u->has_mode('i')) f += 'i';
            if (u->has_mode('w')) f += 'w';
            if (u->has_mode('x')) f += 'x';
            if (u->is_oper()) f += 'o';
            return f.empty() ? "0" : f;
        });
        register_field('t', "querytype", [](UserPtr u, const std::string&) {
            return "0";
        });
    }

    void register_field(char flag, const std::string& label,
                        std::function<std::string(UserPtr, const std::string&)> extractor) {
        fields_[flag] = {flag, label, extractor};
    }

    std::string format_who(UserPtr user, const std::string& fields_str,
                           const std::string& channel) {
        std::string result;
        for (char c : fields_str) {
            auto it = fields_.find(c);
            if (it != fields_.end()) {
                if (!result.empty()) result += ' ';
                result += it->second.extractor(user, channel);
            }
        }
        return result;
    }

    std::string get_whox_fields() const {
        std::string result;
        for (auto& [flag, field] : fields_) {
            result += flag;
            result += ':';
            result += field.label;
            result += ' ';
        }
        if (!result.empty()) result.pop_back();
        return result;
    }

    bool valid_field(char c) const {
        return fields_.count(c) > 0;
    }

private:
    std::unordered_map<char, WhoxField> fields_;
};

// =============================================================================
// MONITOR / WATCH (user presence notification)
// =============================================================================
class MonitorList {
public:
    void add(const std::string& target_nick, UserPtr watcher) {
        std::lock_guard lock(mutex_);
        watches_[to_lower(target_nick)].insert(watcher->uuid());
        watching_[watcher->uuid()].insert(to_lower(target_nick));
    }

    void remove(const std::string& target_nick, UserPtr watcher) {
        std::lock_guard lock(mutex_);
        auto it = watches_.find(to_lower(target_nick));
        if (it != watches_.end()) {
            it->second.erase(watcher->uuid());
            if (it->second.empty()) watches_.erase(it);
        }
        watching_[watcher->uuid()].erase(to_lower(target_nick));
    }

    void remove_all(UserPtr watcher) {
        std::lock_guard lock(mutex_);
        auto it = watching_.find(watcher->uuid());
        if (it != watching_.end()) {
            for (auto& nick : it->second) {
                watches_[nick].erase(watcher->uuid());
                if (watches_[nick].empty()) watches_.erase(nick);
            }
            watching_.erase(it);
        }
    }

    void notify_online(UserPtr user,
                       std::function<void(const std::string&, const std::string&)> notifier) {
        std::lock_guard lock(mutex_);
        auto it = watches_.find(to_lower(user->nick()));
        if (it != watches_.end()) {
            for (auto& watcher_uuid : it->second) {
                notifier(watcher_uuid, user->nick() + "!" + user->ident() + "@" + user->hostname());
            }
        }
    }

    void notify_offline(const std::string& nick,
                        std::function<void(const std::string&, const std::string&)> notifier) {
        std::lock_guard lock(mutex_);
        auto it = watches_.find(to_lower(nick));
        if (it != watches_.end()) {
            for (auto& watcher_uuid : it->second) {
                notifier(watcher_uuid, nick + "!" + nick + "@unknown");
            }
        }
    }

    bool is_watching(UserPtr user, const std::string& nick) const {
        auto it = watching_.find(user->uuid());
        if (it == watching_.end()) return false;
        return it->second.count(to_lower(nick)) > 0;
    }

    std::vector<std::string> get_watching(UserPtr user) const {
        std::vector<std::string> result;
        auto it = watching_.find(user->uuid());
        if (it != watching_.end()) {
            for (auto& nick : it->second) result.push_back(nick);
        }
        return result;
    }

    bool has_entries(UserPtr user) const {
        auto it = watching_.find(user->uuid());
        return it != watching_.end() && !it->second.empty();
    }

    size_t count(UserPtr user) const {
        auto it = watching_.find(user->uuid());
        return (it != watching_.end()) ? it->second.size() : 0;
    }

    static constexpr int MAX_MONITOR = 100; // max per user per RFC

private:
    std::unordered_map<std::string, std::unordered_set<std::string>> watches_; // nick->watchers
    std::unordered_map<std::string, std::unordered_set<std::string>> watching_; // watcher->nicks
    mutable std::mutex mutex_;

    static std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }
};

// =============================================================================
// SILENCE (client-side ignore)
// =============================================================================
class SilenceList {
public:
    void add(UserPtr user, const std::string& mask) {
        std::lock_guard lock(mutex_);
        silences_[user->uuid()].push_back({mask, std::time(nullptr)});
        if (silences_[user->uuid()].size() > MAX_SILENCE) {
            silences_[user->uuid()].erase(silences_[user->uuid()].begin());
        }
    }

    void remove(UserPtr user, const std::string& mask) {
        std::lock_guard lock(mutex_);
        auto it = silences_.find(user->uuid());
        if (it != silences_.end()) {
            it->second.erase(
                std::remove_if(it->second.begin(), it->second.end(),
                    [&](const SilenceEntry& e) { return e.mask == mask; }),
                it->second.end());
        }
    }

    void clear(UserPtr user) {
        std::lock_guard lock(mutex_);
        silences_.erase(user->uuid());
    }

    bool is_silenced(UserPtr user, const std::string& source_mask) const {
        auto it = silences_.find(user->uuid());
        if (it == silences_.end()) return false;
        for (auto& entry : it->second) {
            if (match_mask(source_mask, entry.mask)) return true;
        }
        return false;
    }

    std::vector<std::string> list(UserPtr user) const {
        std::vector<std::string> result;
        auto it = silences_.find(user->uuid());
        if (it != silences_.end()) {
            for (auto& entry : it->second) {
                result.push_back(entry.mask);
            }
        }
        return result;
    }

    static constexpr int MAX_SILENCE = 50;

private:
    struct SilenceEntry {
        std::string mask;
        time_t set_at;
    };

    std::unordered_map<std::string, std::vector<SilenceEntry>> silences_;
    mutable std::mutex mutex_;

    bool match_mask(const std::string& target, const std::string& mask) const {
        // Simple wildcard: nick!user@host
        size_t ti = 0, mi = 0;
        while (ti < target.size() && mi < mask.size()) {
            if (mask[mi] == '*') {
                mi++;
                if (mi >= mask.size()) return true;
                while (ti < target.size() && target[ti] != mask[mi]) ti++;
            } else if (mask[mi] == '?' || tolower(target[ti]) == tolower(mask[mi])) {
                ti++; mi++;
            } else return false;
        }
        return ti == target.size() && mi == mask.size();
    }

    static char tolower(char c) { return std::tolower((unsigned char)c); }
};

// =============================================================================
// ACCEPT / CALLERID
// =============================================================================
class CallerId {
public:
    void add_accept(UserPtr user, const std::string& nick) {
        std::lock_guard lock(mutex_);
        accept_list_[user->uuid()].insert(to_lower(nick));
    }

    void remove_accept(UserPtr user, const std::string& nick) {
        std::lock_guard lock(mutex_);
        accept_list_[user->uuid()].erase(to_lower(nick));
    }

    bool is_accepted(UserPtr target, UserPtr sender) {
        if (!target->has_mode('g')) return true; // callerid not enabled
        std::lock_guard lock(mutex_);
        auto it = accept_list_.find(target->uuid());
        if (it == accept_list_.end()) return false;
        return it->second.count(to_lower(sender->nick())) > 0;
    }

    std::vector<std::string> get_accept_list(UserPtr user) {
        std::vector<std::string> result;
        auto it = accept_list_.find(user->uuid());
        if (it != accept_list_.end()) {
            for (auto& nick : it->second) result.push_back(nick);
        }
        return result;
    }

    static constexpr int MAX_ACCEPT = 100;

private:
    std::unordered_map<std::string, std::unordered_set<std::string>> accept_list_;
    mutable std::mutex mutex_;

    static std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }
};

// =============================================================================
// KNOCK command
// =============================================================================
class KnockHandler {
public:
    struct KnockRequest {
        std::string channel;
        std::string nick;
        std::string reason;
        time_t when;
    };

    void knock(const std::string& channel, UserPtr user, const std::string& reason,
               std::function<void(const std::string&, const std::string&)> notifier) {
        for (auto& [uuid, member] : get_channel_ops(channel)) {
            notifier(uuid, ":" + user->nick() + "!" + user->ident() + "@" +
                     user->hostname() + " NOTICE @" + channel + " :[" + user->nick() +
                     " is knocking: " + reason + "]");
        }
        recent_knocks_.push_back({channel, user->nick(), reason, std::time(nullptr)});
        if (recent_knocks_.size() > 100) recent_knocks_.erase(recent_knocks_.begin());
    }

private:
    std::vector<KnockRequest> recent_knocks_;

    std::vector<std::pair<std::string, std::string>> get_channel_ops(const std::string& ch) {
        // In real implementation: iterate channel members with +o/+a/+q
        return {};
    }
};

// =============================================================================
// HELP command
// =============================================================================
struct HelpEntry {
    std::string command;
    std::string syntax;
    std::string description;
    std::string module;
    bool oper_only = false;
};

class HelpDatabase {
public:
    void add_entry(const HelpEntry& entry) {
        entries_[to_lower(entry.command)] = entry;
    }

    const HelpEntry* lookup(const std::string& cmd) const {
        auto it = entries_.find(to_lower(cmd));
        return (it != entries_.end()) ? &it->second : nullptr;
    }

    std::vector<HelpEntry> search(const std::string& query) const {
        std::vector<HelpEntry> result;
        for (auto& [cmd, entry] : entries_) {
            if (to_lower(cmd).find(to_lower(query)) != std::string::npos ||
                to_lower(entry.description).find(to_lower(query)) != std::string::npos) {
                result.push_back(entry);
            }
        }
        return result;
    }

    std::vector<HelpEntry> all_entries() const {
        std::vector<HelpEntry> result;
        for (auto& [cmd, entry] : entries_) result.push_back(entry);
        return result;
    }

    void register_defaults() {
        add_entry({"NICK", "NICK <nickname>", "Change your nickname", "core"});
        add_entry({"USER", "USER <ident> <mode> <unused> <realname>", "Register connection", "core"});
        add_entry({"JOIN", "JOIN <#channel>[,<#channel>] [<key>[,<key>]]", "Join channels", "core"});
        add_entry({"PART", "PART <#channel>[,<#channel>] [<reason>]", "Leave channels", "core"});
        add_entry({"PRIVMSG", "PRIVMSG <target> <message>", "Send private message", "core"});
        add_entry({"NOTICE", "NOTICE <target> <message>", "Send notice", "core"});
        add_entry({"TOPIC", "TOPIC <#channel> [<topic>]", "View/set channel topic", "core"});
        add_entry({"MODE", "MODE <target> [<modes> [<params>...]]", "View/set modes", "core"});
        add_entry({"WHO", "WHO <mask> [o]", "List users matching mask", "core"});
        add_entry({"WHOIS", "WHOIS <nickname>", "Show user information", "core"});
        add_entry({"WHOWAS", "WHOWAS <nickname> [<count>]", "Show nick history", "core"});
        add_entry({"KICK", "KICK <#channel> <nickname> [<reason>]", "Kick user", "core"});
        add_entry({"INVITE", "INVITE <nickname> <#channel>", "Invite user", "core"});
        add_entry({"LIST", "LIST [<pattern>]", "List channels", "core"});
        add_entry({"NAMES", "NAMES [<#channel>[,<#channel>]]", "List channel members", "core"});
        add_entry({"AWAY", "AWAY [<message>]", "Set away status", "core"});
        add_entry({"QUIT", "QUIT [<reason>]", "Disconnect", "core"});
        add_entry({"OPER", "OPER <name> <password>", "Become IRC operator", "core", true});
        add_entry({"KILL", "KILL <nickname> <reason>", "Force-disconnect user", "core", true});
        add_entry({"WALLOPS", "WALLOPS <message>", "Send to all operators", "core", true});
        add_entry({"STATS", "STATS <query> [<server>]", "Server statistics", "core", true});
        add_entry({"REHASH", "REHASH", "Reload configuration", "core", true});
        add_entry({"RESTART", "RESTART", "Restart server", "core", true});
        add_entry({"DIE", "DIE", "Shutdown server", "core", true});
        add_entry({"MONITOR", "MONITOR <+|-> <nick>[,<nick>]", "Watch user signon/off", "monitor"});
        add_entry({"WATCH", "WATCH [+<nick>] [-<nick>] [l]", "Watch users (alternative)", "watch"});
        add_entry({"SILENCE", "SILENCE [+<mask>] [-<mask>]", "Manage ignore list", "silence"});
        add_entry({"ACCEPT", "ACCEPT <nick>", "Accept callerid message", "callerid"});
        add_entry({"KNOCK", "KNOCK <#channel> [<reason>]", "Request invite", "knock"});
        add_entry({"SETNAME", "SETNAME <realname>", "Change realname", "setname"});
        add_entry({"USERIP", "USERIP <nickname>", "Get user IP (opers only)", "userip", true});
        add_entry({"SAPART", "SAPART <nickname> <#channel>", "Force part (opers)", "opers", true});
        add_entry({"SAJOIN", "SAJOIN <nickname> <#channel>", "Force join (opers)", "opers", true});
        add_entry({"SANICK", "SANICK <oldnick> <newnick>", "Force nick change (opers)", "opers", true});
        add_entry({"SAQUIT", "SAQUIT <nickname> <reason>", "Force quit (opers)", "opers", true});
        add_entry({"SAMODE", "SAMODE <target> <modes> [params]", "Force mode change", "opers", true});
    }

private:
    std::unordered_map<std::string, HelpEntry> entries_;

    static std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }
};

// =============================================================================
// SNOMASK (Server Notice Mask) for operators
// =============================================================================
class SnomaskManager {
public:
    enum Snomask : uint32_t {
        SNO_KILL      = 1 << 0,   // +k - kills
        SNO_CLIENT    = 1 << 1,   // +c - client connects/disconnects
        SNO_SERVER    = 1 << 2,   // +s - server connects/splits
        SNO_OPER      = 1 << 3,   // +o - oper up/down
        SNO_FLOOD     = 1 << 4,   // +f - flood notices
        SNO_GLINE     = 1 << 5,   // +g - g-line changes
        SNO_ERROR     = 1 << 6,   // +e - errors
        SNO_NETWORK   = 1 << 7,   // +n - network changes
        SNO_REHASH    = 1 << 8,   // +r - rehash
        SNO_DEBUG     = 1 << 9,   // +d - debug
        SNO_XLINE     = 1 << 10,  // +x - x-line changes
        SNO_RESV      = 1 << 11,  // +v - reserved nicks/channels
        SNO_MODULE    = 1 << 12,  // +m - module load/unload
        SNO_SPAMFILTER = 1 << 13, // +S - spam filter
        SNO_REMOTE    = 1 << 14,  // +R - remote server notices
    };

    void set(UserPtr user, const std::string& mask_str) {
        uint32_t mask = 0;
        bool adding = true;

        for (char c : mask_str) {
            if (c == '+') { adding = true; continue; }
            if (c == '-') { adding = false; continue; }

            uint32_t bit = char_to_bit(c);
            if (bit == 0) continue;

            if (adding) mask |= bit;
            else mask &= ~bit;
        }

        snomasks_[user->uuid()] = mask;
    }

    void add(UserPtr user, uint32_t mask) {
        snomasks_[user->uuid()] |= mask;
    }

    bool has_mask(UserPtr user, Snomask mask) const {
        auto it = snomasks_.find(user->uuid());
        return it != snomasks_.end() && (it->second & mask);
    }

    void send_sno(Snomask mask, const std::string& message,
                  std::function<void(const std::string&, const std::string&)> sender) {
        for (auto& [uuid, user_mask] : snomasks_) {
            if (user_mask & mask) {
                sender(uuid, ":" + get_server_name() + " NOTICE " + uuid + " :" + message);
            }
        }
    }

    static std::string mask_to_string(uint32_t mask) {
        std::string result;
        if (mask & SNO_KILL) result += 'k';
        if (mask & SNO_CLIENT) result += 'c';
        if (mask & SNO_SERVER) result += 's';
        if (mask & SNO_OPER) result += 'o';
        if (mask & SNO_FLOOD) result += 'f';
        if (mask & SNO_GLINE) result += 'g';
        if (mask & SNO_ERROR) result += 'e';
        if (mask & SNO_NETWORK) result += 'n';
        if (mask & SNO_REHASH) result += 'r';
        if (mask & SNO_DEBUG) result += 'd';
        if (mask & SNO_XLINE) result += 'x';
        if (mask & SNO_RESV) result += 'v';
        if (mask & SNO_MODULE) result += 'm';
        if (mask & SNO_SPAMFILTER) result += 'S';
        if (mask & SNO_REMOTE) result += 'R';
        return result;
    }

private:
    std::unordered_map<std::string, uint32_t> snomasks_;

    static uint32_t char_to_bit(char c) {
        switch (c) {
        case 'k': return SNO_KILL;
        case 'c': return SNO_CLIENT;
        case 's': return SNO_SERVER;
        case 'o': return SNO_OPER;
        case 'f': return SNO_FLOOD;
        case 'g': return SNO_GLINE;
        case 'e': return SNO_ERROR;
        case 'n': return SNO_NETWORK;
        case 'r': return SNO_REHASH;
        case 'd': return SNO_DEBUG;
        case 'x': return SNO_XLINE;
        case 'v': return SNO_RESV;
        case 'm': return SNO_MODULE;
        case 'S': return SNO_SPAMFILTER;
        case 'R': return SNO_REMOTE;
        default: return 0;
        }
    }

    static std::string get_server_name() { return "progressive.local"; }
};

// =============================================================================
// Anti-flood / command throttling
// =============================================================================
class CommandThrottle {
public:
    struct ThrottleConfig {
        int max_commands_per_sec = 10;
        int max_join_per_sec = 3;
        int max_privmsg_per_sec = 5;
        int max_notice_per_sec = 5;
        int penalty_normal = 1;
        int penalty_join = 300;
        int penalty_privmsg = 200;
        int penalty_notice = 100;
        int penalty_recover_per_sec = 1000;
    };

    void configure(const ThrottleConfig& cfg) { config_ = cfg; }

    // Returns true if command is allowed, false if rate limited
    bool check(UserPtr user, const std::string& command) {
        std::lock_guard lock(mutex_);
        time_t now = std::time(nullptr);

        auto& state = cmd_states_[user->uuid()];

        // Recover penalty over time
        time_t elapsed = now - state.last_check;
        if (elapsed > 0) {
            state.penalty -= (int)(elapsed * config_.penalty_recover_per_sec);
            if (state.penalty < 0) state.penalty = 0;
        }
        state.last_check = now;

        // Apply penalty
        int cmd_penalty = get_penalty(command);
        state.penalty += cmd_penalty;

        // Check burst limit per second
        if (now == state.last_sec) {
            state.sec_count++;
        } else {
            state.last_sec = now;
            state.sec_count = 1;
        }

        if (state.sec_count > config_.max_commands_per_sec) {
            return false;
        }

        return state.penalty < 10000; // max penalty before block
    }

private:
    ThrottleConfig config_;

    struct CmdState {
        time_t last_check = 0;
        time_t last_sec = 0;
        int penalty = 0;
        int sec_count = 0;
    };

    std::unordered_map<std::string, CmdState> cmd_states_;
    std::mutex mutex_;

    int get_penalty(const std::string& cmd) {
        std::string upper = to_upper(cmd);
        if (upper == "JOIN") return config_.penalty_join;
        if (upper == "PRIVMSG") return config_.penalty_privmsg;
        if (upper == "NOTICE") return config_.penalty_notice;
        return config_.penalty_normal;
    }

    static std::string to_upper(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::toupper);
        return s;
    }
};

// =============================================================================
// STATS handlers
// =============================================================================
struct StatsHandler {
    char letter;
    std::string description;
    std::function<std::vector<std::string>(UserPtr, const std::string&)> handler;
    bool oper_only = true;
};

class StatsEngine {
public:
    void register_handler(const StatsHandler& handler) {
        handlers_[handler.letter] = handler;
    }

    std::vector<std::string> handle(UserPtr user, char letter, const std::string& target = "") {
        auto it = handlers_.find(letter);
        if (it == handlers_.end()) return {"No such stats query"};

        if (it->second.oper_only && !user->is_oper()) {
            return {"Permission Denied"};
        }

        return it->second.handler(user, target);
    }

    std::string get_available_queries() const {
        std::string result;
        for (auto& [letter, handler] : handlers_) {
            result += letter;
        }
        std::sort(result.begin(), result.end());
        return result;
    }

private:
    std::unordered_map<char, StatsHandler> handlers_;
};

// =============================================================================
// Command aliases
// =============================================================================
class CommandAliases {
public:
    void add_alias(const std::string& alias, const std::string& target,
                   const std::string& format = "") {
        aliases_[to_lower(alias)] = {target, format};
    }

    std::optional<std::pair<std::string, std::string>> resolve(const std::string& cmd) const {
        auto it = aliases_.find(to_lower(cmd));
        if (it != aliases_.end()) {
            return std::make_pair(it->second.target, it->second.format);
        }
        return std::nullopt;
    }

    void register_defaults() {
        aliases_["j"] = {"JOIN", ""};
        aliases_["msg"] = {"PRIVMSG", ""};
        aliases_["m"] = {"PRIVMSG", ""};
        aliases_["p"] = {"PART", ""};
        aliases_["ns"] = {"PRIVMSG", "NickServ :%s"};
        aliases_["cs"] = {"PRIVMSG", "ChanServ :%s"};
        aliases_["ms"] = {"PRIVMSG", "MemoServ :%s"};
        aliases_["hs"] = {"PRIVMSG", "HostServ :%s"};
        aliases_["os"] = {"PRIVMSG", "OperServ :%s"};
        aliases_["bs"] = {"PRIVMSG", "BotServ :%s"};
        aliases_["umode"] = {"MODE", "%s"};
    }

private:
    struct Alias {
        std::string target;      // actual command
        std::string format;      // parameter format string (%s substitution)
    };

    std::unordered_map<std::string, Alias> aliases_;

    static std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }
};

// =============================================================================
// Oper override commands
// =============================================================================
class OperOverride {
public:
    // SAPART - force part a user from a channel
    static std::string sapart(const std::string& nick, const std::string& channel,
                               const std::string& reason = "Operator override") {
        return ":" + nick + "!" + nick + "@operator.override PART " + channel + " :" + reason;
    }

    // SAJOIN - force join a user to a channel
    static std::string sajoin(const std::string& nick, const std::string& channel) {
        return ":" + nick + "!" + nick + "@operator.override JOIN " + channel;
    }

    // SANICK - force nick change
    static std::string sanick(const std::string& old_nick, const std::string& new_nick) {
        return ":" + old_nick + "!" + old_nick + "@operator.override NICK :" + new_nick;
    }

    // SAQUIT - force disconnect with reason
    static std::string saquit(const std::string& nick, const std::string& reason = "Operator override") {
        return ":" + nick + "!" + nick + "@operator.override QUIT :" + reason;
    }

    // SAMODE - force mode change
    static std::string samode(const std::string& target, const std::string& modes,
                               const std::string& params = "") {
        return ":operator.override MODE " + target + " " + modes +
               (params.empty() ? "" : " " + params);
    }

    // KILL - force disconnect with kill message
    static std::string kill(const std::string& oper_nick, const std::string& target_nick,
                            const std::string& reason) {
        return ":" + oper_nick + "!" + oper_nick + "@operator.override KILL " +
               target_nick + " :" + reason;
    }
};

// =============================================================================
// Extended LIST (safe/modern LIST)
// =============================================================================
struct ListFilter {
    std::string pattern = "*";
    int min_users = 0;
    int max_users = 0;
    int min_age = 0;
    int max_age = 0;
    std::string topic_filter;
    bool show_secret = false;
    bool show_hidden = false;
    bool match_topic = false;
    int page = 1;
    int limit = 50;
};

class ListEngine {
public:
    struct ListEntry {
        std::string name;
        int visible_users;
        std::string topic;
        time_t created_at;
    };

    void set_channels(std::function<std::vector<ListEntry>(const ListFilter&)> provider) {
        provider_ = provider;
    }

    std::vector<ListEntry> query(const ListFilter& filter) {
        if (!provider_) return {};
        return provider_(filter);
    }

    static ListFilter parse_list_params(const std::string& params) {
        ListFilter filter;
        if (params.empty()) return filter;

        auto parts = split_str(params, ' ');
        for (auto& part : parts) {
            if (part.empty()) continue;
            if (part[0] == '>') {
                filter.min_users = safe_stoi(part.substr(1));
            } else if (part[0] == '<') {
                filter.max_users = safe_stoi(part.substr(1));
            } else if (part[0] == 'C' && part.size() > 1) {
                if (part[1] == '>') filter.min_age = safe_stoi(part.substr(2));
                else if (part[1] == '<') filter.max_age = safe_stoi(part.substr(2));
            } else if (part[0] == 'T' && part.size() > 1) {
                filter.topic_filter = part.substr(1);
                filter.match_topic = true;
            } else {
                filter.pattern = part;
            }
        }

        return filter;
    }

private:
    std::function<std::vector<ListEntry>(const ListFilter&)> provider_;

    static std::vector<std::string> split_str(const std::string& s, char delim) {
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

    static int safe_stoi(const std::string& s, int def = 0) {
        try { return std::stoi(s); } catch (...) { return def; }
    }
};

// =============================================================================
// MAP command (network map)
// =============================================================================
class NetworkMap {
public:
    struct ServerNode {
        std::string name;
        std::string parent;
        int hop_count = 1;
        int user_count = 0;
        int oper_count = 0;
        std::string description;
    };

    void add_server(const ServerNode& node) {
        servers_[node.name] = node;
    }

    std::string generate_map(const std::string& viewer_server) {
        std::stringstream ss;
        ss << "Network map:\n";

        // Find root servers (no parent or parent not in list)
        for (auto& [name, node] : servers_) {
            if (node.parent.empty() || !servers_.count(node.parent)) {
                render_node(ss, name, 0, viewer_server);
            }
        }
        return ss.str();
    }

private:
    std::unordered_map<std::string, ServerNode> servers_;

    void render_node(std::stringstream& ss, const std::string& name,
                     int indent, const std::string& viewer) {
        for (int i = 0; i < indent; i++) ss << "  ";

        if (name == viewer) ss << "* ";
        else ss << "`- ";

        ss << name;
        auto it = servers_.find(name);
        if (it != servers_.end()) {
            ss << " [" << it->second.user_count << " users]";
            ss << " " << it->second.description;
        }
        ss << "\n";

        // Render children
        for (auto& [child_name, child] : servers_) {
            if (child.parent == name) {
                render_node(ss, child_name, indent + 1, viewer);
            }
        }
    }
};

// =============================================================================
// USERIP command
// =============================================================================
class UserIpResolver {
public:
    std::string resolve(UserPtr user, UserPtr requester) {
        if (!requester->is_oper()) return "";
        return user->nick() + "=" + (user->is_oper() ? "+" : "-") +
               user->ident() + "@" + user->remote_addr();
    }
};

} // namespace irc
} // namespace progressive
