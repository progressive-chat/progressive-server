#pragma once
// irc_server.hpp - Full IRC server implementation (InspIRCd 113,845 lines reference)
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>

namespace progressive::irc {

using json = nlohmann::json;

// ============================================================================
// IRC Protocol Constants (RFC 1459, 2810-2813)
// ============================================================================
struct IRCUser {
  std::string nick; std::string user; std::string host; std::string realname;
  std::string server; std::string id; bool oper{false}; bool away{false};
  std::string away_msg; std::string modes; int64_t signon_time{0};
  int64_t last_active{0}; std::string ip; int port{0};
};

struct IRCChannel {
  std::string name; std::string topic; std::string topic_setter;
  int64_t topic_ts{0}; std::string modes; std::set<std::string> members;
  std::map<std::string,std::string> member_modes; // nick -> modes
  std::set<std::string> bans; std::set<std::string> excepts;
  std::set<std::string> invites; std::string key; int64_t user_limit{0};
  int64_t created_ts{0};
};

struct IRCServer {
  std::string name; std::string description; int hop_count{0};
  std::string version; std::set<std::string> users;
};

// Numeric replies (RFC 1459)
namespace Numerics {
  constexpr int RPL_WELCOME = 1; constexpr int RPL_YOURHOST = 2;
  constexpr int RPL_CREATED = 3; constexpr int RPL_MYINFO = 4;
  constexpr int RPL_BOUNCE = 5; constexpr int RPL_TOPIC = 332;
  constexpr int RPL_TOPICWHOTIME = 333; constexpr int RPL_NAMREPLY = 353;
  constexpr int RPL_ENDOFNAMES = 366; constexpr int RPL_MOTD = 372;
  constexpr int RPL_MOTDSTART = 375; constexpr int RPL_ENDOFMOTD = 376;
  constexpr int RPL_WHOISUSER = 311; constexpr int RPL_WHOISSERVER = 312;
  constexpr int RPL_WHOISOPERATOR = 313; constexpr int RPL_WHOISIDLE = 317;
  constexpr int RPL_ENDOFWHOIS = 318; constexpr int RPL_LIST = 322;
  constexpr int RPL_LISTEND = 323; constexpr int RPL_CHANNELMODEIS = 324;
  constexpr int RPL_CREATIONTIME = 329; constexpr int RPL_NOTOPIC = 331;
  constexpr int RPL_WHOREPLY = 352; constexpr int RPL_ENDOFWHO = 315;
  constexpr int RPL_AWAY = 301; constexpr int RPL_UNAWAY = 305;
  constexpr int RPL_NOWAWAY = 306; constexpr int RPL_WHOISCHANNELS = 319;
  constexpr int RPL_VERSION = 351; constexpr int ERR_NOSUCHNICK = 401;
  constexpr int ERR_NOSUCHCHANNEL = 403; constexpr int ERR_CANNOTSENDTOCHAN = 404;
  constexpr int ERR_NORECIPIENT = 411; constexpr int ERR_NOTEXTTOSEND = 412;
  constexpr int ERR_UNKNOWNCOMMAND = 421; constexpr int ERR_NOMOTD = 422;
  constexpr int ERR_NONICKNAMEGIVEN = 431; constexpr int ERR_ERRONEUSNICKNAME = 432;
  constexpr int ERR_NICKNAMEINUSE = 433; constexpr int ERR_USERNOTINCHANNEL = 441;
  constexpr int ERR_NOTONCHANNEL = 442; constexpr int ERR_USERONCHANNEL = 443;
  constexpr int ERR_NOTREGISTERED = 451; constexpr int ERR_NEEDMOREPARAMS = 461;
  constexpr int ERR_ALREADYREGISTERED = 462; constexpr int ERR_PASSWDMISMATCH = 464;
  constexpr int ERR_CHANNELISFULL = 471; constexpr int ERR_UNKNOWNMODE = 472;
  constexpr int ERR_INVITEONLYCHAN = 473; constexpr int ERR_BANNEDFROMCHAN = 474;
  constexpr int ERR_BADCHANNELKEY = 475; constexpr int ERR_BADCHANMASK = 476;
  constexpr int ERR_NOCHANMODES = 477; constexpr int ERR_CHANOPRIVSNEEDED = 482;
  constexpr int ERR_UMODEUNKNOWNFLAG = 501; constexpr int ERR_USERSDONTMATCH = 502;
}

// ============================================================================
// IRC Server Core
// ============================================================================
class IRCServer {
public:
  IRCServer(const std::string& server_name, const std::string& description,
            const std::string& network_name);

  // Start/stop
  void start(int port);
  void stop();

  // Connection management
  struct IRCConnection {
    int fd; std::string nick; std::string user; std::string host;
    std::string realname; std::string modes; std::string buffer;
    bool registered{false}; bool password_ok{false}; bool sent_001{false};
    int64_t connected_since{0}; std::string ip; int port{0};
  };
  IRCConnection* accept_connection(int fd, const std::string& ip, int port);
  void close_connection(IRCConnection* conn);
  void process_data(IRCConnection* conn, const std::string& data);

  // Command handlers
  void handle_nick(IRCConnection* conn, const std::string& nick);
  void handle_user(IRCConnection* conn, const std::string& user,
                   const std::string& host, const std::string& server,
                   const std::string& realname);
  void handle_pass(IRCConnection* conn, const std::string& password);
  void handle_quit(IRCConnection* conn, const std::string& reason);
  void handle_join(IRCConnection* conn, const std::string& channel,
                   const std::string& key);
  void handle_part(IRCConnection* conn, const std::string& channel,
                   const std::string& reason);
  void handle_privmsg(IRCConnection* conn, const std::string& target,
                      const std::string& message);
  void handle_notice(IRCConnection* conn, const std::string& target,
                     const std::string& message);
  void handle_topic(IRCConnection* conn, const std::string& channel,
                    const std::optional<std::string>& topic);
  void handle_kick(IRCConnection* conn, const std::string& channel,
                   const std::string& target, const std::string& reason);
  void handle_mode(IRCConnection* conn, const std::string& target,
                   const std::string& modes, const std::vector<std::string>& params);
  void handle_invite(IRCConnection* conn, const std::string& target,
                     const std::string& channel);
  void handle_whois(IRCConnection* conn, const std::string& target);
  void handle_who(IRCConnection* conn, const std::string& mask, bool ops_only);
  void handle_list(IRCConnection* conn, const std::string& pattern);
  void handle_names(IRCConnection* conn, const std::string& channel);
  void handle_ping(IRCConnection* conn, const std::string& token);
  void handle_pong(IRCConnection* conn, const std::string& token);
  void handle_version(IRCConnection* conn);
  void handle_stats(IRCConnection* conn, const std::string& query);
  void handle_links(IRCConnection* conn);
  void handle_time(IRCConnection* conn);
  void handle_info(IRCConnection* conn);
  void handle_motd(IRCConnection* conn);
  void handle_away(IRCConnection* conn, const std::optional<std::string>& msg);
  void handle_oper(IRCConnection* conn, const std::string& name,
                   const std::string& password);
  void handle_kill(IRCConnection* conn, const std::string& target,
                   const std::string& reason);
  void handle_squit(IRCConnection* conn, const std::string& server,
                    const std::string& reason);
  void handle_wallops(IRCConnection* conn, const std::string& message);
  void handle_cap(IRCConnection* conn, const std::string& subcommand,
                  const std::vector<std::string>& caps);
  void handle_sasl(IRCConnection* conn, const std::string& mechanism,
                   const std::string& data);

  // Channel management
  IRCChannel* get_channel(const std::string& name);
  IRCChannel* create_channel(const std::string& name);
  void delete_channel(const std::string& name);
  bool is_channel(const std::string& name);

  // User management
  IRCUser* get_user(const std::string& nick);
  IRCUser* add_user(const std::string& nick, const std::string& user,
                    const std::string& host, const std::string& realname);
  void remove_user(const std::string& nick);
  void change_nick(const std::string& oldnick, const std::string& newnick);

  // Send functions
  void send_to(IRCConnection* conn, const std::string& msg);
  void send_numeric(IRCConnection* conn, int numeric, const std::string& msg);
  void send_to_channel(const std::string& channel, const std::string& msg,
                        const std::optional<std::string>& except = std::nullopt);
  void send_to_server(const std::string& server_name, const std::string& msg);

  // Module system (InspIRCd-style)
  struct IRCModule {
    std::string name; std::string version; std::string description;
    std::function<void(IRCServer&)> on_load;
    std::function<void(IRCServer&)> on_unload;
    std::function<bool(IRCConnection*,const std::string&)> on_user_message;
    std::function<bool(IRCConnection*,const std::string&,const std::string&)> on_join;
    std::function<bool(IRCConnection*,const std::string&,const std::string&)> on_part;
    std::function<bool(IRCConnection*,const std::string&,const std::string&)> on_kick;
    std::function<bool(IRCConnection*,const std::string&,const std::string&,
                        const std::vector<std::string>&)> on_mode;
    std::function<bool(const std::string&,const std::string&)> on_nick_change;
    std::function<bool(IRCConnection*)> on_user_register;
  };
  void load_module(const IRCModule& mod);
  void unload_module(const std::string& name);

  // Server-to-server (S2S)
  void connect_server(const std::string& host, int port, const std::string& password);
  void introduce_user(const IRCUser& user);
  void introduce_channel(const IRCChannel& channel);
  void send_server_notice(const std::string& message);

  // Configuration
  struct ServerConfig {
    std::string server_name; std::string description; std::string network_name;
    std::string admin_name; std::string admin_email; int max_channels{20};
    int max_nick_length{30}; int max_topic_length{390}; int max_kick_length{255};
    int max_away_length{200}; int ping_frequency{120}; int default_port{6667};
    bool allow_remote_oper{false}; std::string oper_password;
    std::string server_password; std::string motd; std::vector<std::string> motd_lines;
    std::map<std::string,std::string> oper_blocks;
  };
  ServerConfig& config() { return config_; }

  // Statistics
  int64_t user_count() const;
  int64_t channel_count() const;
  int64_t server_count() const;
  int64_t max_local_users() const;
  int64_t max_global_users() const;

private:
  std::map<std::string, IRCUser> users_;
  std::map<std::string, IRCChannel> channels_;
  std::map<int, IRCConnection> connections_;
  std::map<std::string, IRCModule> modules_;
  std::vector<IRCServer> linked_servers_;
  ServerConfig config_;
  bool running_{false};
  int listen_fd_{-1};
  int64_t start_time_{0};
  int64_t max_local_users_seen_{0};
};

} // namespace progressive::irc
