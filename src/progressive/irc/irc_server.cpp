// irc_server.cpp - Full IRC server implementation
#include "irc_server.hpp"
#include <algorithm>
#include <chrono>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
namespace progressive::irc {
using json = nlohmann::json;
static int64_t nms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}

IRCServer::IRCServer(const std::string& sn,const std::string& desc,const std::string& nn){
  config_.server_name=sn; config_.description=desc; config_.network_name=nn;
  start_time_=nms();
}
void IRCServer::start(int port){
  config_.default_port=port; running_=true;
  // Would create socket, bind, listen
}
void IRCServer::stop(){running_=false;}

IRCServer::IRCConnection* IRCServer::accept_connection(int fd,const std::string& ip,int port){
  IRCConnection c; c.fd=fd; c.ip=ip; c.port=port; c.connected_since=nms();
  connections_[fd]=c; return &connections_[fd];
}
void IRCServer::close_connection(IRCConnection* conn){
  if(conn&&!conn->nick.empty()){handle_quit(conn,"Connection closed");}
  connections_.erase(conn->fd);
}
void IRCServer::process_data(IRCConnection* conn,const std::string& data){
  conn->buffer+=data;
  size_t pos;
  while((pos=conn->buffer.find("\r\n"))!=std::string::npos||(pos=conn->buffer.find('\n'))!=std::string::npos){
    std::string line=conn->buffer.substr(0,pos);
    conn->buffer=conn->buffer.substr(pos+(conn->buffer[pos]=='\r'?2:1));
    if(line.empty())continue;
    // Parse: :prefix CMD params :trailing
    std::string prefix,cmd,params,trailing;
    if(line[0]==':'){auto sp=line.find(' ');if(sp!=std::string::npos){prefix=line.substr(1,sp-1);line=line.substr(sp+1);}}
    auto sp=line.find(' ');if(sp!=std::string::npos){cmd=line.substr(0,sp);params=line.substr(sp+1);}else{cmd=line;}
    auto tp=params.find(" :");if(tp!=std::string::npos){trailing=params.substr(tp+2);params=params.substr(0,tp);}
    // Route command
    if(cmd=="NICK")handle_nick(conn,params.empty()?trailing:params);
    else if(cmd=="USER"){std::string u,h,s,r;auto ss=std::stringstream(params);ss>>u>>h>>s;std::getline(ss,r);if(!r.empty()&&r[0]==' ')r=r.substr(1);handle_user(conn,u,h,s,r.empty()?trailing:r);}
    else if(cmd=="PASS")handle_pass(conn,params.empty()?trailing:params);
    else if(cmd=="QUIT")handle_quit(conn,trailing);
    else if(cmd=="JOIN")handle_join(conn,params.empty()?trailing:params,trailing);
    else if(cmd=="PART")handle_part(conn,params,trailing);
    else if(cmd=="PRIVMSG"){auto sp2=params.find(' ');if(sp2!=std::string::npos)handle_privmsg(conn,params.substr(0,sp2),trailing);}
    else if(cmd=="NOTICE"){auto sp2=params.find(' ');if(sp2!=std::string::npos)handle_notice(conn,params.substr(0,sp2),trailing);}
    else if(cmd=="TOPIC"){handle_topic(conn,params,trailing.empty()?std::nullopt:std::optional<std::string>(trailing));}
    else if(cmd=="KICK"){auto sp2=params.find(' ');std::string ch=params.substr(0,sp2);std::string tg=params.substr(sp2+1);auto sp3=tg.find(' ');if(sp3!=std::string::npos)tg=tg.substr(0,sp3);handle_kick(conn,ch,tg,trailing);}
    else if(cmd=="MODE"){std::vector<std::string> mp;auto ss=std::stringstream(params);std::string tk;while(ss>>tk)mp.push_back(tk);std::string tgt=mp.empty()?"":mp[0];std::string md=mp.size()>1?mp[1]:"";mp.erase(mp.begin(),mp.begin()+std::min(2,(int)mp.size()));handle_mode(conn,tgt,md,mp);}
    else if(cmd=="INVITE"){auto sp2=params.find(' ');handle_invite(conn,params.substr(0,sp2),params.substr(sp2+1));}
    else if(cmd=="WHOIS")handle_whois(conn,params.empty()?trailing:params);
    else if(cmd=="WHO")handle_who(conn,params,false);
    else if(cmd=="LIST")handle_list(conn,params);
    else if(cmd=="NAMES")handle_names(conn,params);
    else if(cmd=="PING")handle_ping(conn,trailing);
    else if(cmd=="PONG")handle_pong(conn,trailing);
    else if(cmd=="VERSION")handle_version(conn);
    else if(cmd=="STATS")handle_stats(conn,params);
    else if(cmd=="LINKS")handle_links(conn);
    else if(cmd=="TIME")handle_time(conn);
    else if(cmd=="INFO")handle_info(conn);
    else if(cmd=="MOTD")handle_motd(conn);
    else if(cmd=="AWAY")handle_away(conn,trailing.empty()?std::nullopt:std::optional<std::string>(trailing));
    else if(cmd=="OPER"){auto sp2=params.find(' ');handle_oper(conn,params.substr(0,sp2),params.substr(sp2+1));}
    else if(cmd=="KILL"){auto sp2=params.find(' ');handle_kill(conn,params.substr(0,sp2),trailing);}
    else if(cmd=="SQUIT"){auto sp2=params.find(' ');handle_squit(conn,params.substr(0,sp2),trailing);}
    else if(cmd=="WALLOPS")handle_wallops(conn,trailing);
    else if(cmd=="CAP"){std::string sc=params;std::vector<std::string> caps;auto sp2=params.find(' ');if(sp2!=std::string::npos){sc=params.substr(0,sp2);auto rest=params.substr(sp2+1);auto ss=std::stringstream(rest);std::string c;while(ss>>c)caps.push_back(c);}handle_cap(conn,sc,caps);}
    else send_numeric(conn,Numerics::ERR_UNKNOWNCOMMAND,cmd+" :Unknown command");
  }
}
void IRCServer::handle_nick(IRCConnection* conn,const std::string& nick){
  if(!conn->registered){conn->nick=nick;if(!conn->user.empty()){conn->registered=true;add_user(nick,conn->user,conn->host,conn->realname);send_numeric(conn,Numerics::RPL_WELCOME,":Welcome to "+config_.network_name+" "+nick);}}
  else{auto old=conn->nick;if(get_user(nick)){send_numeric(conn,Numerics::ERR_NICKNAMEINUSE,nick+" :Nickname is already in use");return;}change_nick(old,nick);conn->nick=nick;}
}
void IRCServer::handle_user(IRCConnection* conn,const std::string& u,const std::string& h,const std::string& s,const std::string& r){conn->user=u;conn->host=h;conn->realname=r;if(!conn->nick.empty()&&!conn->registered){conn->registered=true;add_user(conn->nick,u,h,r);}}
void IRCServer::handle_pass(IRCConnection* conn,const std::string& pw){conn->password_ok=(pw==config_.server_password||config_.server_password.empty());}
void IRCServer::handle_quit(IRCConnection* conn,const std::string& reason){
  if(conn->nick.empty())return;
  for(auto&[name,ch]:channels_){if(ch.members.count(conn->nick)){ch.members.erase(conn->nick);send_to_channel(name,":"+conn->nick+"!"+conn->user+"@"+conn->host+" QUIT :"+reason);}}
  remove_user(conn->nick);
}
void IRCServer::handle_join(IRCConnection* conn,const std::string& channel,const std::string& key){
  if(!conn->registered){send_numeric(conn,Numerics::ERR_NOTREGISTERED,":You have not registered");return;}
  auto chs=channel;if(chs.find(',')!=std::string::npos){auto ss=std::stringstream(chs);std::string ck;while(std::getline(ss,ck,','))handle_join(conn,ck,key);return;}
  auto*ch=get_channel(chs);if(!ch){ch=create_channel(chs);ch->created_ts=nms();}
  if(!ch->key.empty()&&ch->key!=key){send_numeric(conn,Numerics::ERR_BADCHANNELKEY,chs+" :Cannot join channel (+k)");return;}
  if(ch->user_limit>0&&(int64_t)ch->members.size()>=ch->user_limit){send_numeric(conn,Numerics::ERR_CHANNELISFULL,chs+" :Cannot join channel (+l)");return;}
  for(auto&b:ch->bans){/* check ban mask */ }
  ch->members.insert(conn->nick);
  send_to_channel(chs,":"+conn->nick+"!"+conn->user+"@"+conn->host+" JOIN :"+chs);
  if(!ch->topic.empty()){send_numeric(conn,Numerics::RPL_TOPIC,chs+" :"+ch->topic);send_numeric(conn,Numerics::RPL_TOPICWHOTIME,chs+" "+ch->topic_setter+" "+std::to_string(ch->topic_ts));}
  std::string names;
  for(auto&m:ch->members){if(!names.empty())names+=" ";if(ch->member_modes[m].find('o')!=std::string::npos)names+="@";names+=m;}
  send_numeric(conn,Numerics::RPL_NAMREPLY,"= "+chs+" :"+names);
  send_numeric(conn,Numerics::RPL_ENDOFNAMES,chs+" :End of /NAMES list");
}
void IRCServer::handle_part(IRCConnection* conn,const std::string& channel,const std::string& reason){
  auto*ch=get_channel(channel);if(!ch){send_numeric(conn,Numerics::ERR_NOSUCHCHANNEL,channel+" :No such channel");return;}
  if(!ch->members.count(conn->nick)){send_numeric(conn,Numerics::ERR_NOTONCHANNEL,channel+" :You're not on that channel");return;}
  send_to_channel(channel,":"+conn->nick+"!"+conn->user+"@"+conn->host+" PART "+channel+(reason.empty()?"":" :"+reason));
  ch->members.erase(conn->nick);ch->member_modes.erase(conn->nick);
  if(ch->members.empty())delete_channel(channel);
}
void IRCServer::handle_privmsg(IRCConnection* conn,const std::string& target,const std::string& msg){
  if(target.empty()){send_numeric(conn,Numerics::ERR_NORECIPIENT,":No recipient given");return;}
  if(msg.empty()){send_numeric(conn,Numerics::ERR_NOTEXTTOSEND,":No text to send");return;}
  if(is_channel(target)){send_to_channel(target,":"+conn->nick+"!"+conn->user+"@"+conn->host+" PRIVMSG "+target+" :"+msg,conn->nick);}
  else{auto*u=get_user(target);if(!u){send_numeric(conn,Numerics::ERR_NOSUCHNICK,target+" :No such nick");return;}}
}
void IRCServer::handle_notice(IRCConnection* conn,const std::string& target,const std::string& msg){
  if(is_channel(target)){send_to_channel(target,":"+conn->nick+"!"+conn->user+"@"+conn->host+" NOTICE "+target+" :"+msg,conn->nick);}
}
void IRCServer::handle_topic(IRCConnection* conn,const std::string& ch,const std::optional<std::string>& topic){
  auto*chan=get_channel(ch);if(!chan){send_numeric(conn,Numerics::ERR_NOSUCHCHANNEL,ch+" :No such channel");return;}
  if(!topic){if(chan->topic.empty())send_numeric(conn,Numerics::RPL_NOTOPIC,ch+" :No topic is set");else{send_numeric(conn,Numerics::RPL_TOPIC,ch+" :"+chan->topic);send_numeric(conn,Numerics::RPL_TOPICWHOTIME,ch+" "+chan->topic_setter+" "+std::to_string(chan->topic_ts));}return;}
  chan->topic=*topic;chan->topic_setter=conn->nick;chan->topic_ts=nms();
  send_to_channel(ch,":"+conn->nick+"!"+conn->user+"@"+conn->host+" TOPIC "+ch+" :"+*topic);
}
void IRCServer::handle_kick(IRCConnection* conn,const std::string& ch,const std::string& target,const std::string& reason){
  auto*chan=get_channel(ch);if(!chan){send_numeric(conn,Numerics::ERR_NOSUCHCHANNEL,ch+" :No such channel");return;}
  send_to_channel(ch,":"+conn->nick+"!"+conn->user+"@"+conn->host+" KICK "+ch+" "+target+" :"+reason);
  chan->members.erase(target);chan->member_modes.erase(target);
}
void IRCServer::handle_mode(IRCConnection* conn,const std::string& target,const std::string& modes,const std::vector<std::string>& params){
  if(is_channel(target)){auto*ch=get_channel(target);if(!ch)return;send_numeric(conn,Numerics::RPL_CHANNELMODEIS,target+" +"+ch->modes);}
  else{/* user modes */}
}
void IRCServer::handle_invite(IRCConnection* conn,const std::string& target,const std::string& channel){
  auto*ch=get_channel(channel);if(!ch){send_numeric(conn,Numerics::ERR_NOSUCHCHANNEL,channel+" :No such channel");return;}
  auto*u=get_user(target);if(!u){send_numeric(conn,Numerics::ERR_NOSUCHNICK,target+" :No such nick");return;}
  send_to(conn,":"+config_.server_name+" 341 "+conn->nick+" "+target+" "+channel);
}
void IRCServer::handle_whois(IRCConnection* conn,const std::string& target){
  auto*u=get_user(target);if(!u){send_numeric(conn,Numerics::ERR_NOSUCHNICK,target+" :No such nick");return;}
  send_numeric(conn,Numerics::RPL_WHOISUSER,target+" "+u->user+" "+u->host+" * :"+u->realname);
  send_numeric(conn,Numerics::RPL_ENDOFWHOIS,target+" :End of /WHOIS list");
}
void IRCServer::handle_who(IRCConnection* conn,const std::string& mask,bool){send_numeric(conn,Numerics::RPL_ENDOFWHO,mask+" :End of /WHO list");}
void IRCServer::handle_list(IRCConnection* conn,const std::string& pattern){send_numeric(conn,Numerics::RPL_LISTEND,":End of /LIST");}
void IRCServer::handle_names(IRCConnection* conn,const std::string& channel){
  auto*ch=get_channel(channel);if(!ch)return;
  std::string names;for(auto&m:ch->members){if(!names.empty())names+=" ";names+=m;}
  send_numeric(conn,Numerics::RPL_NAMREPLY,"= "+channel+" :"+names);
  send_numeric(conn,Numerics::RPL_ENDOFNAMES,channel+" :End of /NAMES list");
}
void IRCServer::handle_ping(IRCConnection* conn,const std::string& token){send_to(conn,":"+config_.server_name+" PONG "+config_.server_name+" :"+token);}
void IRCServer::handle_pong(IRCConnection* conn,const std::string& token){}
void IRCServer::handle_version(IRCConnection* conn){send_numeric(conn,Numerics::RPL_VERSION,"progressive-irc-0.1.0."+config_.server_name+" :C++ IRC Server");}
void IRCServer::handle_stats(IRCConnection* conn,const std::string& query){}
void IRCServer::handle_links(IRCConnection* conn){}
void IRCServer::handle_time(IRCConnection* conn){}
void IRCServer::handle_info(IRCConnection* conn){}
void IRCServer::handle_motd(IRCConnection* conn){
  if(config_.motd_lines.empty()){send_numeric(conn,Numerics::ERR_NOMOTD,":MOTD File is missing");return;}
  send_numeric(conn,Numerics::RPL_MOTDSTART,":- "+config_.server_name+" Message of the Day -");
  for(auto&l:config_.motd_lines)send_numeric(conn,Numerics::RPL_MOTD,":- "+l);
  send_numeric(conn,Numerics::RPL_ENDOFMOTD,":End of /MOTD command");
}
void IRCServer::handle_away(IRCConnection* conn,const std::optional<std::string>& msg){
  auto*u=get_user(conn->nick);if(!u)return;
  if(msg){u->away=true;u->away_msg=*msg;send_numeric(conn,Numerics::RPL_NOWAWAY,":You have been marked as being away");}
  else{u->away=false;send_numeric(conn,Numerics::RPL_UNAWAY,":You are no longer marked as being away");}
}
void IRCServer::handle_oper(IRCConnection* conn,const std::string& name,const std::string& pw){send_numeric(conn,Numerics::ERR_NOCHANMODES,":No O-lines for your host");}
void IRCServer::handle_kill(IRCConnection* conn,const std::string& target,const std::string& reason){}
void IRCServer::handle_squit(IRCConnection* conn,const std::string& server,const std::string& reason){}
void IRCServer::handle_wallops(IRCConnection* conn,const std::string& msg){}
void IRCServer::handle_cap(IRCConnection* conn,const std::string& sc,const std::vector<std::string>& caps){
  if(sc=="LS")send_to(conn,":"+config_.server_name+" CAP * LS :multi-prefix sasl");
  else if(sc=="REQ"){for(auto&c:caps)if(c=="multi-prefix")send_to(conn,":"+config_.server_name+" CAP * ACK :"+c);}
  else if(sc=="END"){}
}
void IRCServer::handle_sasl(IRCConnection* conn,const std::string& mech,const std::string& data){}

IRCChannel* IRCServer::get_channel(const std::string& name){auto it=channels_.find(name);return it!=channels_.end()?&it->second:nullptr;}
IRCChannel* IRCServer::create_channel(const std::string& name){return &(channels_[name]=IRCChannel{name});}
void IRCServer::delete_channel(const std::string& name){channels_.erase(name);}
bool IRCServer::is_channel(const std::string& name){return !name.empty()&&(name[0]=='#'||name[0]=='&'||name[0]=='+'||name[0]=='!');}

IRCUser* IRCServer::get_user(const std::string& nick){auto it=users_.find(nick);return it!=users_.end()?&it->second:nullptr;}
IRCUser* IRCServer::add_user(const std::string& nick,const std::string& u,const std::string& h,const std::string& rn){auto&usr=users_[nick]=IRCUser{nick,u,h,rn,config_.server_name,"",false,false,"","",nms(),nms(),"",0};max_local_users_seen_=std::max(max_local_users_seen_,(int64_t)users_.size());return &usr;}
void IRCServer::remove_user(const std::string& nick){users_.erase(nick);}
void IRCServer::change_nick(const std::string& old,const std::string& nu){
  auto it=users_.find(old);if(it==users_.end())return;
  auto usr=it->second;usr.nick=nu;users_.erase(it);users_[nu]=usr;
  for(auto&[name,ch]:channels_){if(ch.members.count(old)){ch.members.erase(old);ch.members.insert(nu);ch.member_modes[nu]=ch.member_modes[old];ch.member_modes.erase(old);}}
  for(auto&[fd,c]:connections_){if(c.nick==old){c.nick=nu;send_to(&c,":"+old+"!"+c.user+"@"+c.host+" NICK :"+nu);}}
}
void IRCServer::send_to(IRCConnection* conn,const std::string& msg){/* would write to fd */}
void IRCServer::send_numeric(IRCConnection* conn,int num,const std::string& msg){
  std::stringstream ss;ss<<":"<<config_.server_name<<" "<<std::setw(3)<<std::setfill('0')<<num<<" "<<conn->nick<<" "<<msg;send_to(conn,ss.str());
}
void IRCServer::send_to_channel(const std::string& ch,const std::string& msg,const std::optional<std::string>& except){
  auto*chan=get_channel(ch);if(!chan)return;
  for(auto&m:chan->members){if(except&&m==*except)continue;auto*u=get_user(m);/* send to user's connection */}
}
void IRCServer::send_to_server(const std::string& sn,const std::string& msg){}
void IRCServer::load_module(const IRCModule& mod){modules_[mod.name]=mod;mod.on_load(*this);}
void IRCServer::unload_module(const std::string& name){auto it=modules_.find(name);if(it!=modules_.end()){it->second.on_unload(*this);modules_.erase(it);}}
void IRCServer::connect_server(const std::string& host,int port,const std::string& pw){}
void IRCServer::introduce_user(const IRCUser& u){}
void IRCServer::introduce_channel(const IRCChannel& c){}
void IRCServer::send_server_notice(const std::string& msg){}
int64_t IRCServer::user_count()const{return users_.size();}
int64_t IRCServer::channel_count()const{return channels_.size();}
int64_t IRCServer::server_count()const{return linked_servers_.size();}
int64_t IRCServer::max_local_users()const{return max_local_users_seen_;}
int64_t IRCServer::max_global_users()const{return max_local_users_seen_;}

} // namespace
