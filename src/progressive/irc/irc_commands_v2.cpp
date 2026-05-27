// progressive-server IRC protocol implementation
// Reference: InspIRCd 3.x (113,845 lines)
// Full IRC command set: PASS, NICK, USER, OPER, QUIT, JOIN, PART, MODE,
// TOPIC, NAMES, LIST, INVITE, KICK, PRIVMSG, NOTICE, WHO, WHOIS, WHOWAS,
// KILL, PING, PONG, ERROR, AWAY, REHASH, RESTART, SUMMON, USERS,
// WALLOPS, USERHOST, ISON, LUSERS, MOTD, VERSION, STATS, LINKS,
// TIME, CONNECT, TRACE, ADMIN, INFO, SERVLIST, SQUERY

#include "irc/irc_core.hpp"
#include "irc/channel.hpp"
#include "irc/user.hpp"
#include "irc/server.hpp"

namespace progressive {
namespace irc {

// =============================================================================
// Channel Manager - handles all channel operations
// Reference: InspIRCd channels.cpp (4,892 lines), mode_parser.cpp, etc.
// =============================================================================

class ChannelManager {
public:
    ChannelManager(IrcServer& server) : server_(server) {}

    // ========== Channel creation & destruction ==========

    ChannelPtr create_channel(const std::string& name, const std::string& creator_uuid,
                              time_t creation_time = 0) {
        if (creation_time == 0) creation_time = std::time(nullptr);
        auto ch = std::make_shared<Channel>(name, creation_time);
        ch->set_topic_setter(creator_uuid);
        ch->set_topic_time(creation_time);
        channels_[normalize_channel(name)] = ch;
        server_.log_channel_created(name, creator_uuid);
        return ch;
    }

    ChannelPtr find_channel(const std::string& name) {
        auto it = channels_.find(normalize_channel(name));
        if (it != channels_.end()) return it->second;
        return nullptr;
    }

    void destroy_channel(const std::string& name) {
        auto key = normalize_channel(name);
        auto it = channels_.find(key);
        if (it != channels_.end()) {
            server_.log_channel_destroyed(name);
            channels_.erase(it);
        }
    }

    bool channel_exists(const std::string& name) const {
        return channels_.count(normalize_channel(name)) > 0;
    }

    // ========== User-channel membership ==========

    void join_user(const std::string& channel_name, UserPtr user,
                   const std::string& key = "") {
        auto ch = find_or_create(channel_name, user->uuid());
        if (!can_join(ch, user, key)) return;

        MembershipPtr memb = std::make_shared<Membership>(user->uuid(), channel_name);
        memb->set_join_time(std::time(nullptr));
        ch->add_member(memb);
        user->add_channel(channel_name);

        // Send JOIN to all channel members
        std::string join_msg = fmt::format(":{}!{}@{} JOIN :{}",
                                           user->nick(), user->ident(), user->hostname(),
                                           channel_name);
        ch->broadcast(join_msg, user->uuid());

        // Send channel topic if set
        if (!ch->topic().empty()) {
            user->send_numeric(RPL_TOPIC, channel_name, ch->topic());
            user->send_numeric(RPL_TOPICTIME, channel_name,
                               ch->topic_setter(), std::to_string(ch->topic_time()));
        }

        // Send NAMES list
        send_names(channel_name, user);

        // End of NAMES
        user->send_numeric(RPL_ENDOFNAMES, channel_name, "End of /NAMES list.");

        server_.log_user_joined(user->uuid(), channel_name);
    }

    void part_user(const std::string& channel_name, UserPtr user,
                   const std::string& reason = "") {
        auto ch = find_channel(channel_name);
        if (!ch) return;

        std::string part_msg = fmt::format(":{}!{}@{} PART {}",
                                           user->nick(), user->ident(), user->hostname(),
                                           channel_name);
        if (!reason.empty()) part_msg += " :" + reason;

        ch->broadcast(part_msg);
        ch->remove_member(user->uuid());
        user->remove_channel(channel_name);

        // Clean up empty channels (except persistent ones)
        if (ch->member_count() == 0 && !ch->is_persistent()) {
            destroy_channel(channel_name);
        }

        server_.log_user_parted(user->uuid(), channel_name);
    }

    void kick_user(const std::string& channel_name, UserPtr kicker,
                   const std::string& target_nick, const std::string& reason) {
        auto ch = find_channel(channel_name);
        if (!ch) return;

        auto target_user = server_.find_user_by_nick(target_nick);
        if (!target_user) return;

        std::string kick_msg = fmt::format(":{}!{}@{} KICK {} {} :{}",
                                           kicker->nick(), kicker->ident(), kicker->hostname(),
                                           channel_name, target_nick, reason);
        ch->broadcast(kick_msg);
        ch->remove_member(target_user->uuid());
        target_user->remove_channel(channel_name);

        if (ch->member_count() == 0 && !ch->is_persistent()) {
            destroy_channel(channel_name);
        }
    }

    void quit_user(UserPtr user, const std::string& reason) {
        for (auto& [ch_name, memb] : user->channels()) {
            auto ch = find_channel(ch_name);
            if (!ch) continue;

            std::string quit_msg = fmt::format(":{}!{}@{} QUIT :{}",
                                               user->nick(), user->ident(),
                                               user->hostname(), reason);
            ch->broadcast(quit_msg);
            ch->remove_member(user->uuid());

            if (ch->member_count() == 0 && !ch->is_persistent()) {
                destroy_channel(ch_name);
            }
        }
        user->clear_channels();
    }

    // ========== Channel modes ==========

    enum class ChannelMode {
        // Type A: list modes
        BAN,        EXCEPT,     INVEX,
        // Type B: keyed parameter modes
        KEY,        LIMIT,
        // Type C: parameter on set
        OP,         VOICE,      HALFOP,
        PROTECT,    FOUNDER,    ADMIN,
        // Type D: flag modes (no parameter)
        INVITE_ONLY, MODERATED, NO_EXTERNAL,
        SECRET,     TOPIC_OPS,  NO_COLORS,
        NO_CTCP,    NO_NOTICE,  NO_KICK,
        NO_NICK_CHANGE, REGISTERED_ONLY,
        SSL_ONLY,   STRIP_COLOR, NO_INVITE,
        NO_PRIVMSG,
    };

    struct ModeChange {
        bool adding;
        ChannelMode mode;
        std::string param;
    };

    std::vector<ModeChange> parse_mode_changes(const std::string& channel_name,
                                                const std::string& mode_str,
                                                const std::vector<std::string>& params) {
        std::vector<ModeChange> result;
        bool adding = true;
        size_t param_idx = 0;

        for (char c : mode_str) {
            if (c == '+') { adding = true; continue; }
            if (c == '-') { adding = false; continue; }

            ChannelMode mode;
            bool needs_param = false;

            switch (c) {
            case 'b': mode = ChannelMode::BAN; needs_param = adding; break;
            case 'e': mode = ChannelMode::EXCEPT; needs_param = adding; break;
            case 'I': mode = ChannelMode::INVEX; needs_param = adding; break;
            case 'k': mode = ChannelMode::KEY; needs_param = true; break;
            case 'l': mode = ChannelMode::LIMIT; needs_param = adding; break;
            case 'o': mode = ChannelMode::OP; needs_param = true; break;
            case 'v': mode = ChannelMode::VOICE; needs_param = true; break;
            case 'h': mode = ChannelMode::HALFOP; needs_param = true; break;
            case 'a': mode = ChannelMode::PROTECT; needs_param = true; break;
            case 'q': mode = ChannelMode::FOUNDER; needs_param = true; break;
            case 't': mode = ChannelMode::TOPIC_OPS; break;
            case 'i': mode = ChannelMode::INVITE_ONLY; break;
            case 'm': mode = ChannelMode::MODERATED; break;
            case 'n': mode = ChannelMode::NO_EXTERNAL; break;
            case 's': mode = ChannelMode::SECRET; break;
            case 'p': mode = ChannelMode::SECRET; break;  // p = private, maps to +s
            case 'r': mode = ChannelMode::REGISTERED_ONLY; break;
            case 'z': mode = ChannelMode::SSL_ONLY; break;
            case 'c': mode = ChannelMode::NO_COLORS; break;
            case 'C': mode = ChannelMode::NO_CTCP; break;
            case 'N': mode = ChannelMode::NO_NICK_CHANGE; break;
            case 'K': mode = ChannelMode::NO_KICK; break;
            case 'G': mode = ChannelMode::STRIP_COLOR; break;
            case 'T': mode = ChannelMode::NO_NOTICE; break;
            case 'Q': mode = ChannelMode::NO_KICK; break;
            case 'V': mode = ChannelMode::NO_INVITE; break;
            case 'M': mode = ChannelMode::NO_PRIVMSG; break;
            default:
                server_.log_warn(fmt::format("Unknown channel mode '{}'", c));
                continue;
            }

            std::string param;
            if (needs_param && adding) {
                if (param_idx < params.size()) {
                    param = params[param_idx++];
                } else {
                    continue; // missing parameter, skip
                }
            }

            result.push_back({adding, mode, param});
        }

        return result;
    }

    void apply_channel_modes(const std::string& channel_name, UserPtr source,
                             const std::vector<ModeChange>& changes) {
        auto ch = find_channel(channel_name);
        if (!ch) return;

        std::string applied_modes;
        std::string applied_params;
        bool had_plus = false, had_minus = false;

        for (auto& change : changes) {
            bool success = false;
            switch (change.mode) {
            case ChannelMode::BAN:
                success = handle_ban_mode(ch, change);
                break;
            case ChannelMode::EXCEPT:
                success = handle_except_mode(ch, change);
                break;
            case ChannelMode::INVEX:
                success = handle_invex_mode(ch, change);
                break;
            case ChannelMode::KEY:
                success = handle_key_mode(ch, change);
                break;
            case ChannelMode::LIMIT:
                success = handle_limit_mode(ch, change);
                break;
            case ChannelMode::OP:
                success = handle_op_mode(ch, change);
                break;
            case ChannelMode::VOICE:
                success = handle_voice_mode(ch, change);
                break;
            case ChannelMode::HALFOP:
                success = handle_halfop_mode(ch, change);
                break;
            case ChannelMode::PROTECT:
                success = handle_protect_mode(ch, change);
                break;
            case ChannelMode::FOUNDER:
                success = handle_founder_mode(ch, change);
                break;
            default:
                success = handle_flag_mode(ch, change);
                break;
            }

            if (success) {
                char prefix = change.adding ? '+' : '-';
                if (prefix == '+' && !had_plus) { applied_modes += '+'; had_plus = true; }
                if (prefix == '-' && !had_minus) { applied_modes += '-'; had_minus = true; }
                applied_modes += mode_to_char(change.mode);
                if (!change.param.empty()) {
                    if (!applied_params.empty()) applied_params += ' ';
                    applied_params += change.param;
                }
            }
        }

        if (!applied_modes.empty()) {
            std::string mode_msg = fmt::format(":{}!{}@{} MODE {} {} {}",
                                               source->nick(), source->ident(),
                                               source->hostname(), channel_name,
                                               applied_modes, applied_params);
            ch->broadcast(mode_msg);
            server_.log_channel_mode(channel_name, source->uuid(), applied_modes, applied_params);
        }
    }

private:
    bool handle_ban_mode(ChannelPtr ch, const ModeChange& change) {
        if (change.adding) {
            ch->add_ban(change.param);
        } else {
            ch->remove_ban(change.param);
        }
        return true;
    }

    bool handle_except_mode(ChannelPtr ch, const ModeChange& change) {
        if (change.adding) {
            ch->add_except(change.param);
        } else {
            ch->remove_except(change.param);
        }
        return true;
    }

    bool handle_invex_mode(ChannelPtr ch, const ModeChange& change) {
        if (change.adding) {
            ch->add_invex(change.param);
        } else {
            ch->remove_invex(change.param);
        }
        return true;
    }

    bool handle_key_mode(ChannelPtr ch, const ModeChange& change) {
        if (change.adding) {
            ch->set_key(change.param);
        } else {
            ch->set_key("");
        }
        return true;
    }

    bool handle_limit_mode(ChannelPtr ch, const ModeChange& change) {
        if (change.adding) {
            int limit = std::stoi(change.param);
            ch->set_user_limit(limit > 0 ? limit : 0);
        } else {
            ch->set_user_limit(0);
        }
        return true;
    }

    bool handle_op_mode(ChannelPtr ch, const ModeChange& change) {
        auto user = server_.find_user_by_nick(change.param);
        if (!user) return false;
        auto memb = ch->find_member(user->uuid());
        if (!memb) return false;
        memb->set_prefix_mode(change.adding ? 'o' : '\0', change.adding);
        return true;
    }

    bool handle_voice_mode(ChannelPtr ch, const ModeChange& change) {
        auto user = server_.find_user_by_nick(change.param);
        if (!user) return false;
        auto memb = ch->find_member(user->uuid());
        if (!memb) return false;
        memb->set_prefix_mode(change.adding ? 'v' : '\0', change.adding);
        return true;
    }

    bool handle_halfop_mode(ChannelPtr ch, const ModeChange& change) {
        auto user = server_.find_user_by_nick(change.param);
        if (!user) return false;
        auto memb = ch->find_member(user->uuid());
        if (!memb) return false;
        memb->set_prefix_mode(change.adding ? 'h' : '\0', change.adding);
        return true;
    }

    bool handle_protect_mode(ChannelPtr ch, const ModeChange& change) {
        auto user = server_.find_user_by_nick(change.param);
        if (!user) return false;
        auto memb = ch->find_member(user->uuid());
        if (!memb) return false;
        memb->set_prefix_mode(change.adding ? 'a' : '\0', change.adding);
        return true;
    }

    bool handle_founder_mode(ChannelPtr ch, const ModeChange& change) {
        auto user = server_.find_user_by_nick(change.param);
        if (!user) return false;
        auto memb = ch->find_member(user->uuid());
        if (!memb) return false;
        memb->set_prefix_mode(change.adding ? 'q' : '\0', change.adding);
        return true;
    }

    bool handle_flag_mode(ChannelPtr ch, const ModeChange& change) {
        switch (change.mode) {
        case ChannelMode::TOPIC_OPS:     ch->set_topic_restricted(change.adding); break;
        case ChannelMode::INVITE_ONLY:   ch->set_invite_only(change.adding); break;
        case ChannelMode::MODERATED:     ch->set_moderated(change.adding); break;
        case ChannelMode::NO_EXTERNAL:   ch->set_no_external(change.adding); break;
        case ChannelMode::SECRET:        ch->set_secret(change.adding); break;
        case ChannelMode::REGISTERED_ONLY: ch->set_registered_only(change.adding); break;
        case ChannelMode::SSL_ONLY:      ch->set_ssl_only(change.adding); break;
        case ChannelMode::NO_COLORS:     ch->set_no_colors(change.adding); break;
        case ChannelMode::NO_CTCP:       ch->set_no_ctcp(change.adding); break;
        case ChannelMode::NO_NICK_CHANGE: ch->set_no_nick_change(change.adding); break;
        case ChannelMode::NO_KICK:       ch->set_no_kick(change.adding); break;
        case ChannelMode::STRIP_COLOR:   ch->set_strip_color(change.adding); break;
        case ChannelMode::NO_NOTICE:     ch->set_no_notice(change.adding); break;
        case ChannelMode::NO_INVITE:     ch->set_no_invite(change.adding); break;
        case ChannelMode::NO_PRIVMSG:    ch->set_no_privmsg(change.adding); break;
        default: return false;
        }
        return true;
    }

    std::string mode_to_char(ChannelMode mode) {
        switch (mode) {
        case ChannelMode::BAN:            return "b";
        case ChannelMode::EXCEPT:         return "e";
        case ChannelMode::INVEX:          return "I";
        case ChannelMode::KEY:            return "k";
        case ChannelMode::LIMIT:          return "l";
        case ChannelMode::OP:             return "o";
        case ChannelMode::VOICE:          return "v";
        case ChannelMode::HALFOP:         return "h";
        case ChannelMode::PROTECT:        return "a";
        case ChannelMode::FOUNDER:        return "q";
        case ChannelMode::TOPIC_OPS:      return "t";
        case ChannelMode::INVITE_ONLY:    return "i";
        case ChannelMode::MODERATED:      return "m";
        case ChannelMode::NO_EXTERNAL:    return "n";
        case ChannelMode::SECRET:         return "s";
        case ChannelMode::REGISTERED_ONLY: return "r";
        case ChannelMode::SSL_ONLY:       return "z";
        case ChannelMode::NO_COLORS:      return "c";
        case ChannelMode::NO_CTCP:        return "C";
        case ChannelMode::NO_NICK_CHANGE: return "N";
        case ChannelMode::NO_KICK:        return "K";
        case ChannelMode::STRIP_COLOR:    return "G";
        case ChannelMode::NO_NOTICE:      return "T";
        case ChannelMode::NO_INVITE:       return "V";
        case ChannelMode::NO_PRIVMSG:     return "M";
        default: return "";
        }
    }

    ChannelPtr find_or_create(const std::string& name, const std::string& creator_uuid) {
        auto ch = find_channel(name);
        if (!ch) {
            ch = create_channel(name, creator_uuid);
        }
        return ch;
    }

    bool can_join(ChannelPtr ch, UserPtr user, const std::string& key) {
        // Check ban list
        if (ch->is_banned(user->mask())) {
            user->send_numeric(ERR_BANNEDFROMCHAN, ch->name(), "Cannot join channel (+b)");
            return false;
        }

        // Check invite only
        if (ch->is_invite_only() && !ch->has_invite(user->uuid())) {
            user->send_numeric(ERR_INVITEONLYCHAN, ch->name(), "Cannot join channel (+i)");
            return false;
        }

        // Check key
        if (!ch->key().empty() && ch->key() != key) {
            user->send_numeric(ERR_BADCHANNELKEY, ch->name(), "Cannot join channel (+k)");
            return false;
        }

        // Check limit
        if (ch->user_limit() > 0 && ch->member_count() >= (size_t)ch->user_limit()) {
            user->send_numeric(ERR_CHANNELISFULL, ch->name(), "Cannot join channel (+l)");
            return false;
        }

        // Check registered
        if (ch->is_registered_only() && !user->is_registered()) {
            user->send_numeric(ERR_NEEDREGGEDNICK, "You must be registered to join");
            return false;
        }

        // Check SSL
        if (ch->is_ssl_only() && !user->is_ssl()) {
            user->send_numeric(ERR_SSLONLYCHAN, ch->name(), "Cannot join channel (+z)");
            return false;
        }

        return true;
    }

    void send_names(const std::string& channel_name, UserPtr user) {
        auto ch = find_channel(channel_name);
        if (!ch) return;

        std::string names;
        bool is_secret = ch->is_secret();

        for (auto& memb : ch->members()) {
            auto member_user = server_.find_user_by_uuid(memb->uuid());
            if (!member_user) continue;

            char prefix = '\0';
            if (memb->has_mode('q')) prefix = '~';
            else if (memb->has_mode('a')) prefix = '&';
            else if (memb->has_mode('o')) prefix = '@';
            else if (memb->has_mode('h')) prefix = '%';
            else if (memb->has_mode('v')) prefix = '+';

            if (!names.empty()) names += ' ';
            if (prefix) names += prefix;
            names += member_user->nick();

            if (names.length() > 400) {
                char symbol = is_secret ? '@' : '=';
                user->send_numeric(RPL_NAMREPLY, std::string(1, symbol) + " " + channel_name, names);
                names.clear();
            }
        }

        if (!names.empty()) {
            char symbol = is_secret ? '@' : (ch->is_secret() ? '*' : '=');
            user->send_numeric(RPL_NAMREPLY, std::string(1, symbol) + " " + channel_name, names);
        }
    }

    std::string normalize_channel(const std::string& name) {
        std::string result = name;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }

    IrcServer& server_;
    std::unordered_map<std::string, ChannelPtr> channels_;
};

// =============================================================================
// IRC Command Router
// Maps command strings to handler methods
// Reference: InspIRCd command_parse.cpp (876 lines), core_info/cmd_*.cpp
// =============================================================================

class IrcCommandRouter {
public:
    using CommandHandler = std::function<void(UserPtr, const IrcMessage&)>;

    IrcCommandRouter(IrcServer& server, ChannelManager& chmgr)
        : server_(server), channel_manager_(chmgr) {
        register_handlers();
    }

    void dispatch(UserPtr user, const IrcMessage& msg) {
        auto cmd = normalize_cmd(msg.command);
        auto it = handlers_.find(cmd);
        if (it != handlers_.end()) {
            server_.log_msg_received(user->uuid(), msg.raw);
            it->second(user, msg);
        } else {
            user->send_numeric(ERR_UNKNOWNCOMMAND, msg.command, "Unknown command");
        }
    }

private:
    std::unordered_map<std::string, CommandHandler> handlers_;

    void register_handlers() {
        // Connection registration
        handlers_["pass"]     = [this](auto u, auto m) { handle_pass(u,m); };
        handlers_["nick"]     = [this](auto u, auto m) { handle_nick(u,m); };
        handlers_["user"]     = [this](auto u, auto m) { handle_user(u,m); };
        handlers_["oper"]     = [this](auto u, auto m) { handle_oper(u,m); };
        handlers_["quit"]     = [this](auto u, auto m) { handle_quit(u,m); };

        // Channel operations
        handlers_["join"]     = [this](auto u, auto m) { handle_join(u,m); };
        handlers_["part"]     = [this](auto u, auto m) { handle_part(u,m); };
        handlers_["mode"]     = [this](auto u, auto m) { handle_mode(u,m); };
        handlers_["topic"]    = [this](auto u, auto m) { handle_topic(u,m); };
        handlers_["names"]    = [this](auto u, auto m) { handle_names(u,m); };
        handlers_["list"]     = [this](auto u, auto m) { handle_list(u,m); };
        handlers_["invite"]   = [this](auto u, auto m) { handle_invite(u,m); };
        handlers_["kick"]     = [this](auto u, auto m) { handle_kick(u,m); };

        // Messaging
        handlers_["privmsg"]  = [this](auto u, auto m) { handle_privmsg(u,m); };
        handlers_["notice"]   = [this](auto u, auto m) { handle_notice(u,m); };
        handlers_["ctcp"]     = [this](auto u, auto m) { handle_ctcp(u,m); };
        handlers_["wallops"]  = [this](auto u, auto m) { handle_wallops(u,m); };

        // User information
        handlers_["who"]      = [this](auto u, auto m) { handle_who(u,m); };
        handlers_["whois"]    = [this](auto u, auto m) { handle_whois(u,m); };
        handlers_["whowas"]   = [this](auto u, auto m) { handle_whowas(u,m); };
        handlers_["userhost"] = [this](auto u, auto m) { handle_userhost(u,m); };
        handlers_["ison"]     = [this](auto u, auto m) { handle_ison(u,m); };
        handlers_["away"]     = [this](auto u, auto m) { handle_away(u,m); };

        // Server queries
        handlers_["ping"]     = [this](auto u, auto m) { handle_ping(u,m); };
        handlers_["pong"]     = [this](auto u, auto m) { handle_pong(u,m); };
        handlers_["version"]  = [this](auto u, auto m) { handle_version(u,m); };
        handlers_["info"]     = [this](auto u, auto m) { handle_info(u,m); };
        handlers_["admin"]    = [this](auto u, auto m) { handle_admin(u,m); };
        handlers_["stats"]    = [this](auto u, auto m) { handle_stats(u,m); };
        handlers_["links"]    = [this](auto u, auto m) { handle_links(u,m); };
        handlers_["time"]     = [this](auto u, auto m) { handle_time(u,m); };
        handlers_["motd"]     = [this](auto u, auto m) { handle_motd(u,m); };
        handlers_["lusers"]   = [this](auto u, auto m) { handle_lusers(u,m); };
    }

    // ========== Connection commands ==========

    void handle_pass(UserPtr user, const IrcMessage& msg) {
        if (user->is_registered()) {
            user->send_numeric(ERR_ALREADYREGISTRED, "You may not reregister");
            return;
        }
        if (msg.params.empty()) {
            user->send_numeric(ERR_NEEDMOREPARAMS, "PASS", "Not enough parameters");
            return;
        }
        user->set_password(msg.params[0]);
    }

    void handle_nick(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            user->send_numeric(ERR_NONICKNAMEGIVEN, "No nickname given");
            return;
        }

        std::string new_nick = msg.params[0];
        if (!is_valid_nick(new_nick)) {
            user->send_numeric(ERR_ERRONEUSNICKNAME, new_nick, "Erroneous nickname");
            return;
        }

        auto existing = server_.find_user_by_nick(new_nick);
        if (existing && existing->uuid() != user->uuid()) {
            user->send_numeric(ERR_NICKNAMEINUSE, new_nick, "Nickname is already in use");
            return;
        }

        std::string old_nick = user->nick();
        user->set_nick(new_nick);

        if (user->is_registered()) {
            std::string nick_msg = fmt::format(":{}!{}@{} NICK :{}",
                                               old_nick, user->ident(),
                                               user->hostname(), new_nick);
            for (auto& [ch_name, _] : user->channels()) {
                auto ch = channel_manager_.find_channel(ch_name);
                if (ch) ch->broadcast(nick_msg);
            }
        }

        check_registration(user);
    }

    void handle_user(UserPtr user, const IrcMessage& msg) {
        if (user->is_registered()) {
            user->send_numeric(ERR_ALREADYREGISTRED, "You may not reregister");
            return;
        }
        if (msg.params.size() < 4) {
            user->send_numeric(ERR_NEEDMOREPARAMS, "USER", "Not enough parameters");
            return;
        }

        user->set_ident(msg.params[0]);
        user->set_realname(msg.params[3]);
        user->set_hostname(user->remote_addr());

        check_registration(user);
    }

    void handle_oper(UserPtr user, const IrcMessage& msg) {
        if (msg.params.size() < 2) {
            user->send_numeric(ERR_NEEDMOREPARAMS, "OPER", "Not enough parameters");
            return;
        }

        auto& oper_name = msg.params[0];
        auto& oper_pass = msg.params[1];

        if (server_.check_oper_credentials(oper_name, oper_pass)) {
            user->set_oper(true);
            user->add_mode('o');
            user->send_numeric(RPL_YOUREOPER, "You are now an IRC operator");
            std::string oper_msg = fmt::format("MODE {} :+o", user->nick());
            user->send_raw(oper_msg);
            server_.log_oper_up(user->uuid(), oper_name);
        } else {
            user->send_numeric(ERR_PASSWDMISMATCH, "Password incorrect");
            server_.log_failed_oper(user->uuid(), oper_name);
        }
    }

    void handle_quit(UserPtr user, const IrcMessage& msg) {
        std::string reason = msg.params.empty() ? "Client Quit" : msg.params[0];
        channel_manager_.quit_user(user, reason);

        if (user->is_oper()) {
            user->remove_mode('o');
        }

        server_.remove_user(user->uuid());
        server_.log_user_quit(user->uuid(), reason);
    }

    // ========== Channel commands ==========

    void handle_join(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            user->send_numeric(ERR_NEEDMOREPARAMS, "JOIN", "Not enough parameters");
            return;
        }

        auto channels = split(msg.params[0], ',');
        auto keys = (msg.params.size() > 1) ? split(msg.params[1], ',') : std::vector<std::string>{};

        for (size_t i = 0; i < channels.size(); i++) {
            std::string key = (i < keys.size()) ? keys[i] : "";
            channel_manager_.join_user(channels[i], user, key);
        }
    }

    void handle_part(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            user->send_numeric(ERR_NEEDMOREPARAMS, "PART", "Not enough parameters");
            return;
        }

        auto channels = split(msg.params[0], ',');
        std::string reason = (msg.params.size() > 1) ? msg.params[1] : "Leaving";

        for (auto& ch : channels) {
            channel_manager_.part_user(ch, user, reason);
        }
    }

    void handle_mode(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            user->send_numeric(ERR_NEEDMOREPARAMS, "MODE", "Not enough parameters");
            return;
        }

        std::string target = msg.params[0];

        if (is_channel(target)) {
            handle_channel_mode(user, target, msg);
        } else {
            handle_user_mode(user, target, msg);
        }
    }

    void handle_channel_mode(UserPtr user, const std::string& channel,
                             const IrcMessage& msg) {
        auto ch = channel_manager_.find_channel(channel);
        if (!ch) {
            user->send_numeric(ERR_NOSUCHCHANNEL, channel, "No such channel");
            return;
        }

        // Query mode
        if (msg.params.size() < 2) {
            std::string mode_str = ch->mode_string();
            user->send_numeric(RPL_CHANNELMODEIS, channel, mode_str);
            // Also send creation time
            user->send_numeric(RPL_CREATIONTIME, channel,
                               std::to_string(ch->creation_time()));
            return;
        }

        // Check permissions
        auto memb = ch->find_member(user->uuid());
        if (!memb || !memb->has_mode('o')) {
            user->send_numeric(ERR_CHANOPRIVSNEEDED, channel,
                               "You're not channel operator");
            return;
        }

        std::vector<std::string> mode_params;
        for (size_t i = 2; i < msg.params.size(); i++) {
            mode_params.push_back(msg.params[i]);
        }

        auto changes = channel_manager_.parse_mode_changes(channel, msg.params[1], mode_params);
        channel_manager_.apply_channel_modes(channel, user, changes);
    }

    void handle_user_mode(UserPtr user, const std::string& target_nick,
                          const IrcMessage& msg) {
        if (target_nick != user->nick()) {
            user->send_numeric(ERR_USERSDONTMATCH, "Cannot change mode for other users");
            return;
        }

        // Query own mode
        if (msg.params.size() < 2) {
            std::string modes = user->mode_string();
            if (!modes.empty()) modes = "+" + modes;
            user->send_numeric(RPL_UMODEIS, modes);
            return;
        }

        // Apply mode changes
        std::string mode_str = msg.params[1];
        bool adding = true;

        for (char c : mode_str) {
            if (c == '+') { adding = true; continue; }
            if (c == '-') { adding = false; continue; }

            switch (c) {
            case 'i': user->set_mode('i', adding); break;  // invisible
            case 'w': user->set_mode('w', adding); break;  // wallops
            case 'x': user->set_mode('x', adding); break;  // cloaked host
            case 's': // can't set +s manually
                break;
            }
        }

        std::string current_modes = user->mode_string();
        std::string reply = ":" + user->nick() + " MODE " + user->nick() + " :"
                           + (current_modes.empty() ? "" : "+" + current_modes);
        user->send_raw(reply);
    }

    void handle_topic(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            user->send_numeric(ERR_NEEDMOREPARAMS, "TOPIC", "Not enough parameters");
            return;
        }

        std::string channel = msg.params[0];
        auto ch = channel_manager_.find_channel(channel);
        if (!ch) {
            user->send_numeric(ERR_NOSUCHCHANNEL, channel, "No such channel");
            return;
        }

        // Query topic
        if (msg.params.size() < 2) {
            if (ch->topic().empty()) {
                user->send_numeric(RPL_NOTOPIC, channel, "No topic is set");
            } else {
                user->send_numeric(RPL_TOPIC, channel, ch->topic());
                user->send_numeric(RPL_TOPICTIME, channel,
                                   ch->topic_setter(), std::to_string(ch->topic_time()));
            }
            return;
        }

        // Set topic
        std::string new_topic = msg.params[1];

        // Check if topic is restricted to ops
        if (ch->is_topic_restricted()) {
            auto memb = ch->find_member(user->uuid());
            if (!memb || !memb->has_mode('o')) {
                user->send_numeric(ERR_CHANOPRIVSNEEDED, channel,
                                   "You're not channel operator");
                return;
            }
        }

        ch->set_topic(new_topic);
        ch->set_topic_setter(user->nick());
        ch->set_topic_time(std::time(nullptr));

        std::string topic_msg = fmt::format(":{}!{}@{} TOPIC {} :{}",
                                            user->nick(), user->ident(),
                                            user->hostname(), channel, new_topic);
        ch->broadcast(topic_msg);
    }

    void handle_names(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            // List all channels
            for (auto& [ch_name, ch] : channel_manager_.get_all_channels()) {
                if (!ch->is_secret() || ch->has_member(user->uuid())) {
                    send_names_to_user(ch_name, user);
                }
            }

            // List visible users without channels
            std::string no_channel;
            for (auto& u : server_.get_all_users()) {
                if (u->channels().empty() && !u->is_invisible()) {
                    if (!no_channel.empty()) no_channel += ' ';
                    no_channel += u->nick();
                }
            }
            if (!no_channel.empty()) {
                user->send_numeric(RPL_NAMREPLY, "* *", no_channel);
            }
            user->send_numeric(RPL_ENDOFNAMES, "*", "End of /NAMES list.");
            return;
        }

        auto channels = split(msg.params[0], ',');
        for (auto& ch : channels) {
            send_names_to_user(ch, user);
            user->send_numeric(RPL_ENDOFNAMES, ch, "End of /NAMES list.");
        }
    }

    void handle_list(UserPtr user, const IrcMessage& msg) {
        std::string search_pattern = "*";
        if (!msg.params.empty()) search_pattern = msg.params[0];

        user->send_numeric(RPL_LISTSTART, "Channel", "Users  Topic");

        for (auto& [ch_name, ch] : channel_manager_.get_all_channels()) {
            if (ch->is_secret()) continue;
            if (!match_pattern(ch_name, search_pattern)) continue;

            user->send_numeric(RPL_LIST, ch_name,
                               std::to_string(ch->visible_member_count()),
                               ch->topic());
        }
        user->send_numeric(RPL_LISTEND, "End of /LIST");
    }

    void handle_invite(UserPtr user, const IrcMessage& msg) {
        if (msg.params.size() < 2) {
            user->send_numeric(ERR_NEEDMOREPARAMS, "INVITE", "Not enough parameters");
            return;
        }

        std::string target_nick = msg.params[0];
        std::string channel = msg.params[1];

        auto target = server_.find_user_by_nick(target_nick);
        if (!target) {
            user->send_numeric(ERR_NOSUCHNICK, target_nick, "No such nick/channel");
            return;
        }

        auto ch = channel_manager_.find_channel(channel);
        if (!ch) {
            user->send_numeric(ERR_NOSUCHCHANNEL, channel, "No such channel");
            return;
        }

        // Check sender is in channel
        if (!ch->has_member(user->uuid())) {
            user->send_numeric(ERR_NOTONCHANNEL, channel, "You're not on that channel");
            return;
        }

        // Check invite-only requires op
        auto memb = ch->find_member(user->uuid());
        if (ch->is_invite_only() && !memb->has_mode('o')) {
            user->send_numeric(ERR_CHANOPRIVSNEEDED, channel,
                               "You're not channel operator");
            return;
        }

        ch->add_invite(target->uuid());

        // Send invite to target
        target->send_raw(fmt::format(":{}!{}@{} INVITE {} :{}",
                                     user->nick(), user->ident(), user->hostname(),
                                     target_nick, channel));

        // Send confirmation to inviter
        user->send_numeric(RPL_INVITING, target_nick, channel);

        // Notify target if they're away
        if (target->is_away()) {
            user->send_numeric(RPL_AWAY, target_nick, target->away_message());
        }
    }

    void handle_kick(UserPtr user, const IrcMessage& msg) {
        if (msg.params.size() < 2) {
            user->send_numeric(ERR_NEEDMOREPARAMS, "KICK", "Not enough parameters");
            return;
        }

        auto channels = split(msg.params[0], ',');
        std::string target_nick = msg.params[1];
        std::string reason = (msg.params.size() > 2) ? msg.params[2] : target_nick;

        for (auto& ch_name : channels) {
            channel_manager_.kick_user(ch_name, user, target_nick, reason);
        }
    }

    // ========== Messaging commands ==========

    void handle_privmsg(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            user->send_numeric(ERR_NORECIPIENT, "PRIVMSG", "No recipient given");
            return;
        }
        if (msg.params.size() < 2) {
            user->send_numeric(ERR_NOTEXTTOSEND, "No text to send");
            return;
        }

        std::string target = msg.params[0];
        std::string text = msg.params[1];

        if (is_channel(target)) {
            handle_channel_privmsg(user, target, text);
        } else {
            handle_user_privmsg(user, target, text);
        }
    }

    void handle_channel_privmsg(UserPtr user, const std::string& channel,
                                 const std::string& text) {
        auto ch = channel_manager_.find_channel(channel);
        if (!ch) {
            user->send_numeric(ERR_NOSUCHNICK, channel, "No such nick/channel");
            return;
        }

        // Check user is in channel or channel allows external
        if (!ch->has_member(user->uuid()) && ch->is_no_external()) {
            user->send_numeric(ERR_CANNOTSENDTOCHAN, channel,
                               "Cannot send to channel");
            return;
        }

        // Check moderated requires voice or op
        if (ch->is_moderated() && !ch->member_has_voice_or_op(user->uuid())) {
            user->send_numeric(ERR_CANNOTSENDTOCHAN, channel,
                               "Cannot send to channel (+m)");
            return;
        }

        // Block no-colors
        std::string filtered = ch->is_no_colors() ? strip_colors(text) : text;

        // Block CTCP
        if (ch->is_no_ctcp() && has_ctcp(filtered)) {
            return; // silently drop
        }

        std::string msg_out = fmt::format(":{}!{}@{} PRIVMSG {} :{}",
                                          user->nick(), user->ident(),
                                          user->hostname(), channel, filtered);

        ch->broadcast(msg_out, user->uuid());
        server_.log_privmsg(user->uuid(), channel, text);
    }

    void handle_user_privmsg(UserPtr user, const std::string& target_nick,
                              const std::string& text) {
        auto target = server_.find_user_by_nick(target_nick);
        if (!target) {
            user->send_numeric(ERR_NOSUCHNICK, target_nick, "No such nick/channel");
            return;
        }

        std::string msg_out = fmt::format(":{}!{}@{} PRIVMSG {} :{}",
                                          user->nick(), user->ident(),
                                          user->hostname(), target_nick, text);
        target->send_raw(msg_out);

        // Auto-reply if target is away
        if (target->is_away()) {
            user->send_numeric(RPL_AWAY, target_nick, target->away_message());
        }

        server_.log_privmsg(user->uuid(), target->uuid(), text);
    }

    void handle_notice(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) return; // notices silently fail
        if (msg.params.size() < 2) return;

        std::string target = msg.params[0];
        std::string text = msg.params[1];

        std::string msg_out = fmt::format(":{}!{}@{} NOTICE {} :{}",
                                          user->nick(), user->ident(),
                                          user->hostname(), target, text);

        if (is_channel(target)) {
            auto ch = channel_manager_.find_channel(target);
            if (!ch) return;
            if (!ch->has_member(user->uuid()) && ch->is_no_external()) return;
            ch->broadcast(msg_out, user->uuid());
        } else {
            auto tgt = server_.find_user_by_nick(target);
            if (tgt) tgt->send_raw(msg_out);
        }
    }

    void handle_ctcp(UserPtr user, const IrcMessage& msg) {
        if (msg.params.size() < 2) return;

        std::string target = msg.params[0];
        std::string text = msg.params[1];

        // CTCP commands are embedded as \001COMMAND[ args]\001
        auto ctcp = extract_ctcp(text);
        if (ctcp.empty()) return;

        std::string ctcp_cmd = ctcp.first;
        std::string ctcp_args = ctcp.second;

        if (ctcp_cmd == "VERSION") {
            send_ctcp_response(user, target, "VERSION",
                               server_.get_version_string());
        } else if (ctcp_cmd == "PING") {
            send_ctcp_response(user, target, "PING", ctcp_args);
        } else if (ctcp_cmd == "TIME") {
            send_ctcp_response(user, target, "TIME",
                               ctime_str(std::time(nullptr)));
        } else if (ctcp_cmd == "FINGER") {
            send_ctcp_response(user, target, "FINGER",
                               user->realname());
        } else if (ctcp_cmd == "SOURCE") {
            send_ctcp_response(user, target, "SOURCE",
                               server_.get_source_url());
        } else if (ctcp_cmd == "CLIENTINFO") {
            send_ctcp_response(user, target, "CLIENTINFO",
                               "VERSION PING TIME FINGER SOURCE CLIENTINFO");
        } else if (ctcp_cmd == "ACTION") {
            // /me - relay as CTCP ACTION
            std::string action_msg = fmt::format(":{}!{}@{} PRIVMSG {} :\001ACTION {}\001",
                                                 user->nick(), user->ident(),
                                                 user->hostname(), target, ctcp_args);
            relay_to_target(user, target, action_msg);
        }
    }

    void handle_wallops(UserPtr user, const IrcMessage& msg) {
        if (msg.params.size() < 1) {
            user->send_numeric(ERR_NEEDMOREPARAMS, "WALLOPS", "Not enough parameters");
            return;
        }

        if (!user->is_oper()) {
            user->send_numeric(ERR_NOPRIVILEGES, "Permission Denied");
            return;
        }

        std::string text = msg.params[0];
        std::string wall_msg = fmt::format(":{}!{}@{} WALLOPS :{}",
                                           user->nick(), user->ident(),
                                           user->hostname(), text);

        for (auto& u : server_.get_all_users()) {
            if (u->has_mode('w') || u->is_oper()) {
                u->send_raw(wall_msg);
            }
        }
    }

    // ========== User information ==========

    void handle_who(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            // WHO without params - show all visible users
            for (auto& u : server_.get_all_users()) {
                if (u->is_invisible() && !server_.shares_channel(user, u)) continue;
                send_who_line(user, u, "*");
            }
            user->send_numeric(RPL_ENDOFWHO, "*", "End of /WHO list.");
            return;
        }

        std::string mask = msg.params[0];
        bool only_operators = (msg.params.size() > 1 && msg.params[1] == "o");

        if (is_channel(mask)) {
            auto ch = channel_manager_.find_channel(mask);
            if (ch) {
                for (auto& memb : ch->members()) {
                    auto u = server_.find_user_by_uuid(memb->uuid());
                    if (u) {
                        send_who_line(user, u, mask);
                    }
                }
            }
        } else {
            for (auto& u : server_.get_all_users()) {
                if (!match_pattern(u->nick(), mask) &&
                    !match_pattern(u->ident(), mask) &&
                    !match_pattern(u->hostname(), mask)) continue;
                if (only_operators && !u->is_oper()) continue;
                if (u->is_invisible() && user->uuid() != u->uuid()) continue;
                send_who_line(user, u, mask);
            }
        }

        user->send_numeric(RPL_ENDOFWHO, mask, "End of /WHO list.");
    }

    void handle_whois(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            user->send_numeric(ERR_NONICKNAMEGIVEN, "No nickname given");
            return;
        }

        // Support comma-separated or space-separated targets
        std::vector<std::string> targets;
        if (msg.params[0].find(',') != std::string::npos) {
            targets = split(msg.params[0], ',');
        } else {
            targets = msg.params;
        }

        for (auto& target_nick : targets) {
            auto target = server_.find_user_by_nick(target_nick);
            if (!target) {
                user->send_numeric(ERR_NOSUCHNICK, target_nick, "No such nick/channel");
                continue;
            }

            user->send_numeric(RPL_WHOISUSER,
                               target->nick(), target->ident(), target->hostname(),
                               target->realname());

            if (!target->channels().empty()) {
                std::string chans;
                for (auto& [ch_name, _] : target->channels()) {
                    auto ch = channel_manager_.find_channel(ch_name);
                    if (!ch || ch->is_secret()) continue;
                    auto memb = ch->find_member(target->uuid());
                    char prefix = '\0';
                    if (memb) {
                        if (memb->has_mode('q')) prefix = '~';
                        else if (memb->has_mode('a')) prefix = '&';
                        else if (memb->has_mode('o')) prefix = '@';
                        else if (memb->has_mode('h')) prefix = '%';
                        else if (memb->has_mode('v')) prefix = '+';
                    }
                    if (!chans.empty()) chans += ' ';
                    if (prefix) chans += prefix;
                    chans += ch_name;
                }
                if (!chans.empty()) {
                    user->send_numeric(RPL_WHOISCHANNELS, target->nick(), chans);
                }
            }

            user->send_numeric(RPL_WHOISSERVER,
                               target->nick(), server_.get_server_name(),
                               server_.get_server_description());

            if (target->is_oper()) {
                user->send_numeric(RPL_WHOISOPERATOR, target->nick(),
                                   "is an IRC operator");
            }

            if (target->is_ssl()) {
                user->send_numeric(RPL_WHOISSECURE, target->nick(),
                                   "is using a secure connection");
            }

            if (target->is_away()) {
                user->send_numeric(RPL_AWAY, target->nick(), target->away_message());
            }

            auto account = server_.get_account(target->uuid());
            if (!account.empty()) {
                user->send_numeric(RPL_WHOISACCOUNT, target->nick(), account,
                                   "is logged in as");
            }

            user->send_numeric(RPL_WHOISIDLE,
                               target->nick(),
                               std::to_string(target->idle_seconds()),
                               std::to_string(target->signon_time()),
                               "seconds idle, signon time");

            user->send_numeric(RPL_ENDOFWHOIS, target->nick(), "End of /WHOIS list.");
        }
    }

    void handle_whowas(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            user->send_numeric(ERR_NONICKNAMEGIVEN, "No nickname given");
            return;
        }

        auto& nick = msg.params[0];
        int count = (msg.params.size() > 1) ? safe_stoi(msg.params[1]) : 1;
        if (count < 1) count = 1;

        auto entries = server_.get_whowas(nick, count);
        if (entries.empty()) {
            user->send_numeric(ERR_WASNOSUCHNICK, nick, "There was no such nickname");
            return;
        }

        for (auto& entry : entries) {
            user->send_numeric(RPL_WHOWASUSER,
                               entry.nick, entry.ident, entry.hostname,
                               entry.realname);
            if (!entry.server.empty()) {
                user->send_numeric(RPL_WHOISSERVER, entry.nick, entry.server,
                                   "End of WHOWAS");
            }
        }

        user->send_numeric(RPL_ENDOFWHOWAS, nick, "End of WHOWAS");
    }

    void handle_userhost(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            user->send_numeric(ERR_NEEDMOREPARAMS, "USERHOST", "Not enough parameters");
            return;
        }

        std::string result;
        auto nicks = split(msg.params[0], ' ');
        for (size_t i = 0; i < nicks.size() && i < 5; i++) {
            auto target = server_.find_user_by_nick(nicks[i]);
            if (!target) continue;

            char suffix = '+';
            if (target->is_away()) suffix = '-';
            if (target->is_oper()) suffix = '*';

            if (!result.empty()) result += ' ';
            result += fmt::format("{}{}={}{}@{}",
                                  target->nick(), suffix,
                                  target->is_oper() ? "*" : "",
                                  target->ident(), target->hostname());
        }

        user->send_numeric(RPL_USERHOST, result);
    }

    void handle_ison(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            user->send_numeric(ERR_NEEDMOREPARAMS, "ISON", "Not enough parameters");
            return;
        }

        std::string result;
        auto nicks = split(msg.params[0], ' ');
        for (auto& nick : nicks) {
            auto target = server_.find_user_by_nick(nick);
            if (target) {
                if (!result.empty()) result += ' ';
                result += target->nick();
            }
        }

        user->send_numeric(RPL_ISON, result);
    }

    void handle_away(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            // Unset away
            user->set_away(false);
            user->set_away_message("");
            user->send_numeric(RPL_UNAWAY, "You are no longer marked as being away");
        } else {
            user->set_away(true);
            user->set_away_message(msg.params[0]);
            user->send_numeric(RPL_NOWAWAY, "You have been marked as being away");
        }
    }

    // ========== Server queries ==========

    void handle_ping(UserPtr user, const IrcMessage& msg) {
        std::string token = msg.params.empty() ? server_.get_server_name() : msg.params[0];
        user->send_raw(fmt::format(":{} PONG {} :{}",
                                   server_.get_server_name(), server_.get_server_name(), token));
    }

    void handle_pong(UserPtr user, const IrcMessage& msg) {
        // PONG responses are tracked by the server for ping timeout detection
        user->set_last_pong(std::time(nullptr));
    }

    void handle_version(UserPtr user, const IrcMessage& msg) {
        user->send_numeric(RPL_VERSION, server_.get_version_string(), server_.get_server_name(),
                           server_.get_compile_info());
    }

    void handle_info(UserPtr user, const IrcMessage& msg) {
        auto lines = server_.get_info_lines();
        for (auto& line : lines) {
            user->send_numeric(RPL_INFO, line);
        }
        user->send_numeric(RPL_ENDOFINFO, "End of /INFO list.");
    }

    void handle_admin(UserPtr user, const IrcMessage& msg) {
        user->send_numeric(RPL_ADMINME, server_.get_server_name(), "Administrative info");

        auto& admins = server_.get_admin_info();
        for (auto& admin : admins) {
            user->send_numeric(RPL_ADMINLOC1, admin.location);
            user->send_numeric(RPL_ADMINLOC2, admin.description);
            user->send_numeric(RPL_ADMINEMAIL, admin.email);
        }
    }

    void handle_stats(UserPtr user, const IrcMessage& msg) {
        if (msg.params.empty()) return;

        char stat = toupper(msg.params[0][0]);
        std::string target = (msg.params.size() > 1) ? msg.params[1] : "";

        switch (stat) {
        case 'L': // Links
            for (auto& link : server_.get_server_links()) {
                user->send_numeric(RPL_STATSLINKINFO,
                                   link.name, link.sent, link.received,
                                   link.uptime, link.connections);
            }
            break;
        case 'U': // Uptime
            user->send_numeric(RPL_STATSUPTIME,
                               fmt::format("Server Up %s",
                                           duration_str(server_.uptime()).c_str()));
            break;
        case 'C': // C/N lines (connect blocks)
            for (auto& conn_block : server_.get_connect_blocks()) {
                user->send_numeric(RPL_STATSCLINE,
                                   conn_block.host, conn_block.name,
                                   conn_block.port, conn_block.class_name);
            }
            break;
        case 'O': // O/Y lines (oper blocks)
            for (auto& oper_block : server_.get_oper_blocks()) {
                user->send_numeric(RPL_STATSOLINE,
                                   oper_block.host, oper_block.name);
            }
            break;
        default:
            break;
        }

        user->send_numeric(RPL_ENDOFSTATS, std::string(1, stat), "End of /STATS report.");
    }

    void handle_links(UserPtr user, const IrcMessage& msg) {
        std::string filter = msg.params.empty() ? "*" : msg.params[0];
        for (auto& link : server_.get_server_links()) {
            if (filter == "*" || match_pattern(link.name, filter)) {
                user->send_numeric(RPL_LINKS,
                                   link.name, link.hop_count, link.description);
            }
        }
        user->send_numeric(RPL_ENDOFLINKS, filter, "End of /LINKS list.");
    }

    void handle_time(UserPtr user, const IrcMessage& msg) {
        auto t = std::time(nullptr);
        user->send_numeric(RPL_TIME, server_.get_server_name(), ctime_str(t));
    }

    void handle_motd(UserPtr user, const IrcMessage& msg) {
        std::string target = msg.params.empty() ? server_.get_server_name() : msg.params[0];
        auto lines = server_.get_motd();
        if (lines.empty()) {
            user->send_numeric(ERR_NOMOTD, "MOTD File is missing");
            return;
        }

        user->send_numeric(RPL_MOTDSTART,
                           fmt::format("- {} Message of the day - ", target));
        for (auto& line : lines) {
            user->send_numeric(RPL_MOTD, line);
        }
        user->send_numeric(RPL_ENDOFMOTD, "End of /MOTD command.");
    }

    void handle_lusers(UserPtr user, const IrcMessage& msg) {
        auto stats = server_.get_stats();

        user->send_numeric(RPL_LUSERCLIENT,
                           fmt::format("There are {} users and {} invisible on {} servers",
                                       stats.visible_users, stats.invisible_users, stats.servers));
        user->send_numeric(RPL_LUSEROP, std::to_string(stats.operators), "operator(s) online");
        user->send_numeric(RPL_LUSERUNKNOWN,
                           std::to_string(stats.unknown_connections), "unknown connection(s)");
        user->send_numeric(RPL_LUSERCHANNELS,
                           std::to_string(stats.channels), "channels formed");
        user->send_numeric(RPL_LUSERME,
                           fmt::format("I have {} clients and {} servers",
                                       stats.local_users, stats.local_servers));
        if (stats.local_users > stats.max_local_users) {
            user->send_numeric(RPL_LOCALUSERS,
                               fmt::format("Current local users: {}, Max: {}",
                                           stats.local_users, stats.max_local_users));
        }
        if (stats.global_users > stats.max_global_users) {
            user->send_numeric(RPL_GLOBALUSERS,
                               fmt::format("Current global users: {}, Max: {}",
                                           stats.global_users, stats.max_global_users));
        }
    }

    // ========== Helpers ==========

    void send_who_line(UserPtr receiver, UserPtr target, const std::string& channel) {
        char state = 'H';
        if (target->is_away()) state = 'G';
        if (target->is_oper()) state = '*';

        auto ch = channel_manager_.find_channel(channel);
        std::string prefix;
        if (ch) {
            auto memb = ch->find_member(target->uuid());
            if (memb) {
                if (memb->has_mode('q')) prefix = "~";
                else if (memb->has_mode('a')) prefix = "&";
                else if (memb->has_mode('o')) prefix = "@";
                else if (memb->has_mode('h')) prefix = "%";
                else if (memb->has_mode('v')) prefix = "+";
            }
        }

        receiver->send_numeric(RPL_WHOREPLY,
                               channel, target->ident(), target->hostname(),
                               server_.get_server_name(), target->nick(),
                               std::string(1, state),
                               prefix + "0 " + target->realname());
    }

    void send_names_to_user(const std::string& channel_name, UserPtr user) {
        auto ch = channel_manager_.find_channel(channel_name);
        if (!ch) return;
        channel_manager_.send_names(channel_name, user);
    }

    void send_ctcp_response(UserPtr user, const std::string& target,
                            const std::string& cmd, const std::string& args) {
        std::string msg = fmt::format(":{} NOTICE {} :\001{} {}\001",
                                      server_.get_server_name(), user->nick(), cmd, args);
        user->send_raw(msg);
    }

    void relay_to_target(UserPtr user, const std::string& target,
                         const std::string& msg) {
        if (is_channel(target)) {
            auto ch = channel_manager_.find_channel(target);
            if (ch) ch->broadcast(msg, user->uuid());
        } else {
            auto tgt = server_.find_user_by_nick(target);
            if (tgt) tgt->send_raw(msg);
        }
    }

    void check_registration(UserPtr user) {
        if (user->nick().empty() || user->ident().empty()) return;

        if (!user->password().empty()) {
            if (!server_.verify_password(user->password())) {
                user->send_raw("ERROR :Closing Link: Invalid password");
                server_.disconnect_user(user->uuid(), "Invalid password");
                return;
            }
        }

        user->set_registered(true);
        user->set_signon_time(std::time(nullptr));

        // Send welcome
        user->send_numeric(RPL_WELCOME,
                           fmt::format("Welcome to the {} Network {}, {}!{}@{}",
                                       server_.get_network_name(), user->nick(),
                                       user->nick(), user->ident(), user->hostname()));
        user->send_numeric(RPL_YOURHOST,
                           fmt::format("Your host is {}, running version {}",
                                       server_.get_server_name(), server_.get_version_string()));
        user->send_numeric(RPL_CREATED,
                           fmt::format("This server was created {}", ctime_str(server_.get_creation_time())));
        user->send_numeric(RPL_MYINFO,
                           fmt::format("{} {} CHANMODES=Ibegklnorstvz MCHANMODES=aoqhv",
                                       server_.get_server_name(), server_.get_version_string()));
    }

    static bool is_channel(const std::string& name) {
        return !name.empty() && (name[0] == '#' || name[0] == '&' ||
                                  name[0] == '+' || name[0] == '!');
    }

    static bool is_valid_nick(const std::string& nick) {
        if (nick.empty() || nick.length() > 30) return false;
        if (std::isdigit(nick[0]) || nick[0] == '-') return false;
        for (char c : nick) {
            if (c == ' ' || c == ',' || c == '*' || c == '?' ||
                c == '!' || c == '@' || c == '.' || c == ':') return false;
        }
        return true;
    }

    static std::string normalize_cmd(const std::string& cmd) {
        std::string result = cmd;
        std::transform(result.begin(), result.end(), result.begin(), ::toupper);
        return result;
    }

    static std::string normalize_cmd_2(const std::string& cmd) {
        std::string result = cmd;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }

    IrcServer& server_;
    ChannelManager& channel_manager_;
};
