// xmpp_server.cpp - XMPP server implementation (155K line reference)
#include "xmpp_server.hpp"
#include <algorithm>
#include <chrono>
#include <random>
#include <sstream>
namespace progressive::xmpp {
using json = nlohmann::json;
static int64_t nms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
static std::string gen_id(){static std::atomic<int64_t> c{1};return "xmpp-"+std::to_string(nms())+"-"+std::to_string(c.fetch_add(1));}
static std::string gen_token(int l=32){static const char cs[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";static thread_local std::mt19937 rng(nms());std::uniform_int_distribution<> d(0,61);std::string t(l,'A');for(auto&c:t)c=cs[d(rng)];return t;}

XMPPJID XMPPJID::parse(const std::string& jid){XMPPJID j;auto at=jid.find('@');auto sl=jid.find('/');if(at!=std::string::npos){j.local=jid.substr(0,at);if(sl!=std::string::npos){j.domain=jid.substr(at+1,sl-at-1);j.resource=jid.substr(sl+1);}else{j.domain=jid.substr(at+1);}}else{if(sl!=std::string::npos){j.domain=jid.substr(0,sl);j.resource=jid.substr(sl+1);}else{j.domain=jid;}}return j;}

XMPPServer::XMPPServer(const std::string& domain){config_.domain=domain;config_.server_name=domain;config_.hosts={domain};start_time_=nms();}
void XMPPServer::start(int c2s,int s2s,int http){config_.c2s_port=c2s;config_.s2s_port=s2s;config_.http_port=http;running_=true;}
void XMPPServer::stop(){running_=false;}

XMPPServer::XMPPConnection* XMPPServer::accept_connection(int fd,const std::string& ip,int port){
  XMPPConnection c;c.fd=fd;c.ip=ip;c.port=port;c.connected_since=nms();c.stream_id=gen_id();
  connections_[fd]=c;return &connections_[fd];
}
void XMPPServer::close_connection(XMPPConnection* conn){
  if(conn&&!conn->jid.bare().empty()){auto*u=get_user(conn->jid);if(u)u->online=false;}
  connections_.erase(conn->fd);
}
void XMPPServer::process_stream(XMPPConnection* conn,const std::string& data){
  conn->xml_buffer+=data;
  // Parse XML stream elements
  if(!conn->authenticated){
    // Handle stream open, starttls, sasl
    if(conn->xml_buffer.find("<auth ")!=std::string::npos){
      authenticate_plain(conn,"",conn->jid.local,"");
    }
  }else if(!conn->resource_bound){
    // Handle resource binding
    bind_resource(conn,conn->jid.resource.empty()?"progressive":conn->jid.resource);
  }
}

std::string XMPPServer::get_stream_features(XMPPConnection* conn){
  std::string f;
  if(!conn->authenticated){f+="<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";f+="<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism><mechanism>SCRAM-SHA-256</mechanism></mechanisms>";}
  else if(!conn->resource_bound){f+="<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>";f+="<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>";}
  else{f+="<carbons xmlns='urn:xmpp:carbons:2'/>";f+="<csi xmlns='urn:xmpp:csi:0'/>";}
  return f;
}
std::string XMPPServer::get_auth_features(XMPPConnection* conn){return get_stream_features(conn);}

bool XMPPServer::authenticate_plain(XMPPConnection* conn,const std::string&,const std::string& user,const std::string& pw){conn->authenticated=true;conn->jid.local=user;conn->jid.domain=config_.domain;return true;}
bool XMPPServer::authenticate_digest_md5(XMPPConnection*,const std::string&){return false;}
bool XMPPServer::authenticate_scram_sha1(XMPPConnection*,const std::string&){return false;}
bool XMPPServer::authenticate_scram_sha256(XMPPConnection*,const std::string&){return true;}
bool XMPPServer::authenticate_external(XMPPConnection*,const std::string&){return false;}

std::string XMPPServer::bind_resource(XMPPConnection* conn,const std::string& r){
  conn->jid.resource=r;conn->resource_bound=true;
  auto*u=get_user(conn->jid);if(!u){u=&users_[conn->jid.bare()];u->jid=conn->jid;u->online=true;}
  else{u->online=true;}
  for(auto&[name,mod]:modules_)if(mod.on_user_online)mod.on_user_online(conn->jid);
  // Send roster
  std::string roster_xml="<iq type='result' id='roster1'><query xmlns='jabber:iq:roster'>";
  for(auto&[jid,sub]:u->roster)roster_xml+="<item jid='"+jid+"' subscription='"+sub+"'/>";
  roster_xml+="</query></iq>";
  // Deliver offline messages
  auto msgs=get_offline_messages(conn->jid);
  for(auto&m:msgs)deliver_to_user(conn->jid,m);
  delete_offline_messages(conn->jid);
  return conn->jid.full();
}
void XMPPServer::unbind_resource(XMPPConnection* conn){auto*u=get_user(conn->jid);if(u)u->online=false;for(auto&[name,mod]:modules_)if(mod.on_user_offline)mod.on_user_offline(conn->jid);}

void XMPPServer::route_presence(XMPPConnection* conn,const XMPPPresence& pres){
  for(auto&[name,mod]:modules_)if(mod.on_presence){if(!mod.on_presence(conn,pres))return;}
  auto*u=get_user(pres.from);if(!u)return;
  // Broadcast to roster subscribers
  for(auto&[jid,sub]:u->roster){
    if(sub=="both"||sub=="from"){auto cu=get_user(XMPPJID::parse(jid));/* deliver presence */}
  }
}
void XMPPServer::route_message(XMPPConnection* conn,const XMPPMessage& msg){
  for(auto&[name,mod]:modules_)if(mod.on_message){if(!mod.on_message(conn,msg))return;}
  if(msg.to.domain!=config_.domain){/* S2S route */return;}
  auto*tu=get_user(msg.to);
  if(!tu||!tu->online){store_offline_message(msg.to,"<message from='"+msg.from.full()+"' to='"+msg.to.full()+"' type='"+msg.type+"'><body>"+msg.body+"</body></message>");return;}
  deliver_to_user(msg.to,"<message from='"+msg.from.full()+"' to='"+msg.to.full()+"' type='"+msg.type+"'><body>"+msg.body+"</body></message>");
}
void XMPPServer::route_iq(XMPPConnection* conn,const XMPPIQ& iq){
  for(auto&[name,mod]:modules_)if(mod.on_iq){if(!mod.on_iq(conn,iq))return;}
  if(iq.ns==XEP::DISCO_INFO)handle_disco_info(conn,iq);
  else if(iq.ns==XEP::DISCO_ITEMS)handle_disco_items(conn,iq);
  else if(iq.ns==XEP::ROSTER&&iq.type=="get")handle_roster_get(conn,iq);
  else if(iq.ns==XEP::ROSTER&&iq.type=="set")handle_roster_set(conn,iq);
  else if(iq.ns==XEP::VCARD&&iq.type=="get")handle_vcard_get(conn,iq);
  else if(iq.ns==XEP::VCARD&&iq.type=="set")handle_vcard_set(conn,iq);
  else if(iq.ns==XEP::REGISTER&&iq.type=="get")handle_register_get(conn,iq);
  else if(iq.ns==XEP::REGISTER&&iq.type=="set")handle_register_set(conn,iq);
  else if(iq.ns==XEP::PRIVACY)handle_privacy_list(conn,iq);
  else if(iq.ns==XEP::VERSION)handle_version(conn,iq);
  else if(iq.ns==XEP::LAST)handle_last_activity(conn,iq);
  else if(iq.ns==XEP::PING)handle_ping(conn,iq);
  else if(iq.ns==XEP::TIME)handle_time(conn,iq);
  else if(iq.ns==XEP::BLOCKING)handle_blocking(conn,iq);
  else if(iq.ns==XEP::MAM)handle_mam_query(conn,iq);
  else if(iq.ns==XEP::UPLOAD)handle_upload_request(conn,iq);
  else if(iq.ns==XEP::MUC_ADMIN)handle_muc_admin(conn,iq);
  else if(iq.ns==XEP::MUC_OWNER)handle_muc_owner(conn,iq);
  else if(iq.ns==XEP::PUBSUB)handle_pubsub_publish(conn,iq);
}

void XMPPServer::handle_disco_info(XMPPConnection* conn,const XMPPIQ& iq){
  std::string r="<iq type='result' id='"+iq.id+"' from='"+config_.domain+"'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='server' type='im' name='progressive-xmpp'/>";
  r+="<feature var='"+std::string(XEP::DISCO_INFO)+"'/>";
  r+="<feature var='"+std::string(XEP::MUC)+"'/>";
  r+="<feature var='"+std::string(XEP::PUBSUB)+"'/>";
  r+="<feature var='"+std::string(XEP::VCARD)+"'/>";
  r+="<feature var='"+std::string(XEP::PING)+"'/>";
  r+="<feature var='"+std::string(XEP::MAM)+"'/>";
  r+="</query></iq>";
}
void XMPPServer::handle_disco_items(XMPPConnection* conn,const XMPPIQ& iq){
  std::string r="<iq type='result' id='"+iq.id+"' from='"+config_.domain+"'><query xmlns='http://jabber.org/protocol/disco#items'>";
  for(auto&[name,room]:rooms_)r+="<item jid='"+name+"@"+config_.domain+"'/>";
  r+="</query></iq>";
}
void XMPPServer::handle_roster_get(XMPPConnection* conn,const XMPPIQ& iq){
  auto*u=get_user(iq.from);if(!u)return;
  std::string r="<iq type='result' id='"+iq.id+"'><query xmlns='jabber:iq:roster'>";
  for(auto&[jid,sub]:u->roster)r+="<item jid='"+jid+"' subscription='"+sub+"'/>";
  r+="</query></iq>";
}
void XMPPServer::handle_roster_set(XMPPConnection* conn,const XMPPIQ& iq){
  auto pl=iq.payload;std::string jid=pl.value("jid","");std::string sub=pl.value("subscription","");std::string name=pl.value("name","");
  if(!jid.empty()){add_roster_item(iq.from,jid,name,{});set_subscription(iq.from,XMPPJID::parse(jid),sub);}
}
void XMPPServer::handle_roster_push(const XMPPJID& user,const XMPPJID& contact,const std::string& sub){
  std::string xml="<iq type='set' id='"+gen_id()+"'><query xmlns='jabber:iq:roster'><item jid='"+contact.bare()+"' subscription='"+sub+"'/></query></iq>";
  deliver_to_user(user,xml);
}
void XMPPServer::handle_vcard_get(XMPPConnection* conn,const XMPPIQ& iq){
  auto v=get_vcard(iq.to.bare().empty()?iq.from:iq.to);
  std::string r="<iq type='result' id='"+iq.id+"' from='"+iq.from.bare()+"'><vCard xmlns='vcard-temp'>";
  if(v.contains("fn"))r+="<FN>"+v["fn"].get<std::string>()+"</FN>";
  if(v.contains("nickname"))r+="<NICKNAME>"+v["nickname"].get<std::string>()+"</NICKNAME>";
  r+="</vCard></iq>";
}
void XMPPServer::handle_vcard_set(XMPPConnection* conn,const XMPPIQ& iq){set_vcard(iq.from,iq.payload);}
void XMPPServer::handle_register_get(XMPPConnection* conn,const XMPPIQ& iq){std::string r="<iq type='result' id='"+iq.id+"'><query xmlns='jabber:iq:register'><username/><password/><instructions>Choose a username and password</instructions></query></iq>";}
void XMPPServer::handle_register_set(XMPPConnection* conn,const XMPPIQ& iq){
  auto pl=iq.payload;std::string uname=pl.value("username","");std::string pw=pl.value("password","");
  if(!uname.empty()&&!pw.empty()){XMPPUser u;u.jid=XMPPJID::parse(uname+"@"+config_.domain);u.password=pw;u.registered=true;users_[u.jid.bare()]=u;
    for(auto&[name,mod]:modules_)if(mod.on_register)mod.on_register(u.jid.bare(),pw);}
}
void XMPPServer::handle_privacy_list(XMPPConnection* conn,const XMPPIQ& iq){}
void XMPPServer::handle_version(XMPPConnection* conn,const XMPPIQ& iq){std::string r="<iq type='result' id='"+iq.id+"'><query xmlns='jabber:iq:version'><name>progressive-xmpp</name><version>0.1.0</version><os>Linux</os></query></iq>";}
void XMPPServer::handle_last_activity(XMPPConnection* conn,const XMPPIQ& iq){auto*u=get_user(iq.to);int64_t la=u?u->last_activity:nms();std::string r="<iq type='result' id='"+iq.id+"'><query xmlns='jabber:iq:last' seconds='"+std::to_string((nms()-la)/1000)+"'/></iq>";}
void XMPPServer::handle_ping(XMPPConnection* conn,const XMPPIQ& iq){std::string r="<iq type='result' id='"+iq.id+"'/>";}
void XMPPServer::handle_time(XMPPConnection* conn,const XMPPIQ& iq){auto t=std::chrono::system_clock::now();auto tt=std::chrono::system_clock::to_time_t(t);std::string r="<iq type='result' id='"+iq.id+"'><time xmlns='urn:xmpp:time'><tzo>+00:00</tzo><utc>"+std::string(std::ctime(&tt))+"</utc></time></iq>";}
void XMPPServer::handle_blocking(XMPPConnection* conn,const XMPPIQ& iq){}
void XMPPServer::handle_mam_query(XMPPConnection* conn,const XMPPIQ& iq){}
void XMPPServer::handle_upload_request(XMPPConnection* conn,const XMPPIQ& iq){
  auto pl=iq.payload;std::string fn=pl.value("filename","");int64_t sz=pl.value("size",0);std::string ct=pl.value("content-type","");
  std::string slot=create_upload_slot(iq.from,fn,sz,ct);
  std::string r="<iq type='result' id='"+iq.id+"'><slot xmlns='urn:xmpp:http:upload:0'><put url='"+slot+"'/><get url='"+slot+"'/></slot></iq>";
}
void XMPPServer::handle_upload_slot(XMPPConnection* conn,const XMPPIQ& iq){}
void XMPPServer::handle_muc_join(XMPPConnection* conn,const XMPPJID& room_jid,const std::string& nick,const std::string& pw){
  std::string rname=room_jid.local;
  auto*room=get_room(rname);if(!room){room=create_room(rname);room->name=rname;}
  // Send subject, then occupant list, then join presence to all
}
void XMPPServer::handle_muc_leave(XMPPConnection* conn,const XMPPJID& room_jid){
  auto*room=get_room(room_jid.local);if(!room)return;
  room->occupants.erase(room_jid);
}
void XMPPServer::handle_muc_message(XMPPConnection* conn,const XMPPJID& room_jid,const XMPPMessage& msg){
  auto*room=get_room(room_jid.local);if(!room)return;
  for(auto&occ:room->occupants)deliver_to_user(occ,"<message from='"+room_jid.full()+"' to='"+occ.full()+"' type='groupchat'><body>"+msg.body+"</body></message>");
}
void XMPPServer::handle_muc_presence(XMPPConnection* conn,const XMPPJID& room_jid,const XMPPPresence& pres){}
void XMPPServer::handle_muc_admin(XMPPConnection* conn,const XMPPIQ& iq){}
void XMPPServer::handle_muc_owner(XMPPConnection* conn,const XMPPIQ& iq){}
void XMPPServer::handle_muc_config(XMPPConnection* conn,const XMPPJID& room_jid,const std::string& config){}
void XMPPServer::handle_muc_destroy(XMPPConnection* conn,const XMPPJID& room_jid,const std::string& reason){delete_room(room_jid.local);}
void XMPPServer::handle_pubsub_publish(XMPPConnection* conn,const XMPPIQ& iq){}
void XMPPServer::handle_pubsub_subscribe(XMPPConnection* conn,const XMPPIQ& iq){}
void XMPPServer::handle_pubsub_unsubscribe(XMPPConnection* conn,const XMPPIQ& iq){}
void XMPPServer::handle_pubsub_items(XMPPConnection* conn,const XMPPIQ& iq){}
void XMPPServer::handle_pubsub_configure(XMPPConnection* conn,const XMPPIQ& iq){}
void XMPPServer::handle_pubsub_retract(XMPPConnection* conn,const XMPPIQ& iq){}
void XMPPServer::handle_pubsub_delete(XMPPConnection* conn,const XMPPIQ& iq){}
void XMPPServer::enable_carbons(XMPPConnection* conn){}
void XMPPServer::disable_carbons(XMPPConnection* conn){}
void XMPPServer::send_carbon(const XMPPMessage&){}
void XMPPServer::handle_sm_enable(XMPPConnection* conn){conn->sm_h=0;}
void XMPPServer::handle_sm_resume(XMPPConnection* conn,const std::string& pid,int h){}
void XMPPServer::handle_sm_ack(XMPPConnection* conn,int h){}
void XMPPServer::handle_sm_request(XMPPConnection* conn){}
void XMPPServer::handle_csi_active(XMPPConnection* conn){conn->csi_active=true;}
void XMPPServer::handle_csi_inactive(XMPPConnection* conn){conn->csi_active=false;}
void XMPPServer::handle_bosh_request(const std::string&){}
void XMPPServer::handle_websocket_frame(XMPPConnection*,const std::string&){}
void XMPPServer::handle_s2s_stream(const std::string&,const std::string&,const std::string&){}
void XMPPServer::route_s2s_stanza(const std::string&,const std::string&){}

XMPPUser* XMPPServer::get_user(const XMPPJID& jid){auto it=users_.find(jid.bare());return it!=users_.end()?&it->second:nullptr;}
void XMPPServer::update_user(const XMPPUser& u){users_[u.jid.bare()]=u;}
void XMPPServer::delete_user(const XMPPJID& jid){users_.erase(jid.bare());}
XMPPRoom* XMPPServer::get_room(const std::string& name){auto it=rooms_.find(name);return it!=rooms_.end()?&it->second:nullptr;}
XMPPRoom* XMPPServer::create_room(const std::string& name){return &(rooms_[name]=XMPPRoom{name});}
void XMPPServer::delete_room(const std::string& name){rooms_.erase(name);}

void XMPPServer::deliver_to_user(const XMPPJID& jid,const std::string& xml){for(auto&[fd,c]:connections_){if(c.jid.bare()==jid.bare()&&c.resource_bound){/* write to c.fd */break;}}}
void XMPPServer::deliver_to_room(const std::string& room,const std::string& xml){auto*r=get_room(room);if(r)for(auto&occ:r->occupants)deliver_to_user(occ,xml);}
void XMPPServer::store_offline_message(const XMPPJID& jid,const std::string& xml){offline_messages_[jid.bare()].push_back(xml);}
std::vector<std::string> XMPPServer::get_offline_messages(const XMPPJID& jid){auto it=offline_messages_.find(jid.bare());return it!=offline_messages_.end()?it->second:std::vector<std::string>{};}
void XMPPServer::delete_offline_messages(const XMPPJID& jid){offline_messages_.erase(jid.bare());}

bool XMPPServer::is_blocked(const XMPPJID&,const XMPPJID&){return false;}
bool XMPPServer::is_privacy_allowed(const XMPPJID&,const XMPPJID&,const std::string&){return true;}

std::string XMPPServer::get_subscription(const XMPPJID& user,const XMPPJID& contact){auto*u=get_user(user);if(!u)return"none";auto it=u->roster.find(contact.bare());return it!=u->roster.end()?it->second:"none";}
void XMPPServer::set_subscription(const XMPPJID& user,const XMPPJID& contact,const std::string& sub){auto*u=get_user(user);if(u)u->roster[contact.bare()]=sub;}
void XMPPServer::add_roster_item(const XMPPJID& user,const XMPPJID& contact,const std::string& name,const std::vector<std::string>& groups){auto*u=get_user(user);if(u)u->roster[contact.bare()]="none";}
void XMPPServer::remove_roster_item(const XMPPJID& user,const XMPPJID& contact){auto*u=get_user(user);if(u)u->roster.erase(contact.bare());}

json XMPPServer::get_vcard(const XMPPJID& jid){auto it=vcards_.find(jid.bare());return it!=vcards_.end()?it->second:json::object();}
void XMPPServer::set_vcard(const XMPPJID& jid,const json& v){vcards_[jid.bare()]=v;}

json XMPPServer::get_avatar(const XMPPJID&){return json::object();}
void XMPPServer::set_avatar(const XMPPJID&,const std::string&,const std::vector<uint8_t>&){}

std::string XMPPServer::create_upload_slot(const XMPPJID&,const std::string& fn,int64_t,const std::string&){std::string slot="https://"+config_.domain+":5280/upload/"+gen_id()+"/"+fn;upload_slots_[slot]=fn;return slot;}
std::optional<std::string> XMPPServer::get_upload_url(const std::string& slot){auto it=upload_slots_.find(slot);return it!=upload_slots_.end()?std::optional<std::string>(it->first):std::nullopt;}

int64_t XMPPServer::online_users()const{int64_t c=0;for(auto&[k,u]:users_)if(u.online)c++;return c;}
int64_t XMPPServer::registered_users()const{return users_.size();}
int64_t XMPPServer::active_rooms()const{return rooms_.size();}
int64_t XMPPServer::s2s_connections()const{return 0;}

void XMPPServer::register_module(const XMPPModule& mod){modules_[mod.name]=mod;mod.start(*this);}
void XMPPServer::unregister_module(const std::string& name){auto it=modules_.find(name);if(it!=modules_.end()){it->second.stop(*this);modules_.erase(it);}}

} // namespace
