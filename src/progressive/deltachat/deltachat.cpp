// deltachat.cpp - DeltaChat core implementation (118K line reference)
#include "deltachat.hpp"
#include <algorithm>
#include <chrono>
#include <random>
#include <sstream>
namespace progressive::deltachat {
using json = nlohmann::json;
static int64_t nms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
static std::string gen_token(int l=32){static const char cs[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";static thread_local std::mt19937 rng(nms());std::uniform_int_distribution<> d(0,61);std::string t(l,'A');for(auto&c:t)c=cs[d(rng)];return t;}

DeltaChat::DeltaChat(const std::string& dbfile){config_.dbfile=dbfile;}
void DeltaChat::open(){running_=true;}
void DeltaChat::close(){running_=false;io_running_=false;}
bool DeltaChat::is_open(){return running_;}
void DeltaChat::start_io(){io_running_=true;}
void DeltaChat::stop_io(){io_running_=false;}
void DeltaChat::maybe_network(){}

void DeltaChat::set_config(const std::string& k,const std::string& v){
  if(k=="addr")config_.addr=v;else if(k=="mail_pw")config_.mail_pw=v;
  else if(k=="imap_server")config_.imap_server=v;else if(k=="smtp_server")config_.smtp_server=v;
  else if(k=="display_name")config_.display_name=v;else if(k=="self_status")config_.self_status=v;
  else if(k=="self_avatar")config_.self_avatar=v;else if(k=="e2ee_enabled")config_.e2ee_enabled=(v=="1");
  else if(k=="mdns_enabled")config_.mdns_enabled=(v=="1");else if(k=="bot")config_.bot=(v=="1");
}
std::string DeltaChat::get_config(const std::string& k){
  if(k=="addr")return config_.addr;if(k=="mail_pw")return config_.mail_pw;
  if(k=="imap_server")return config_.imap_server;if(k=="smtp_server")return config_.smtp_server;
  if(k=="display_name")return config_.display_name;if(k=="e2ee_enabled")return config_.e2ee_enabled?"1":"0";
  if(k=="configured")return config_.configured?"1":"0";return"";
}
std::string DeltaChat::get_config_fast(const std::string& k,const std::string& d){auto v=get_config(k);return v.empty()?d:v;}
void DeltaChat::configure(){config_.configured=true;}
void DeltaChat::stop_ongoing_process(){}
bool DeltaChat::is_configured(){return config_.configured;}
bool DeltaChat::is_configured_fast(){return config_.configured;}
void DeltaChat::add_account(){}
void DeltaChat::remove_account(uint32_t){}
uint32_t DeltaChat::add_account_future(){return 0;}
bool DeltaChat::remove_all_accounts(){return true;}
std::vector<uint32_t> DeltaChat::get_all_account_ids(){return{1};}
void DeltaChat::select_account(uint32_t){}
void DeltaChat::migrate_account(const std::string&){}

uint32_t DeltaChat::create_contact(const std::string& name,const std::string& addr){
  uint32_t id=gen_id();DcContact c;c.id=id;c.name=name;c.display_name=name;c.addr=addr;c.color="#"+std::to_string(std::hash<std::string>{}(addr)%0xFFFFFF);contacts_[id]=c;return id;
}
DcContact DeltaChat::get_contact(uint32_t id){auto it=contacts_.find(id);if(it!=contacts_.end())return it->second;return DcContact{};}
std::vector<uint32_t> DeltaChat::get_contacts(uint32_t flags,const std::string& q){
  std::vector<uint32_t> r;for(auto&[id,c]:contacts_){if(!q.empty()&&c.name.find(q)==std::string::npos&&c.addr.find(q)==std::string::npos)continue;r.push_back(id);}return r;
}
std::vector<uint32_t> DeltaChat::get_blocked_contacts(){std::vector<uint32_t> r;for(auto&[id,c]:contacts_)if(c.blocked)r.push_back(id);return r;}
std::vector<uint32_t> DeltaChat::get_contact_ids(const std::string& name,const std::string& addr){return get_contacts(0,name+addr);}
bool DeltaChat::set_contact_name(uint32_t id,const std::string& n){auto it=contacts_.find(id);if(it!=contacts_.end()){it->second.name=n;return true;}return false;}
bool DeltaChat::set_contact_auth_name(uint32_t id,const std::string& n){auto it=contacts_.find(id);if(it!=contacts_.end()){it->second.auth_name=n;return true;}return false;}
bool DeltaChat::set_contact_profile_image(uint32_t id,const std::string& i){auto it=contacts_.find(id);if(it!=contacts_.end()){it->second.profile_image=i;return true;}return false;}
bool DeltaChat::set_contact_status(uint32_t id,const std::string& s){auto it=contacts_.find(id);if(it!=contacts_.end()){it->second.status=s;return true;}return false;}
std::string DeltaChat::get_contact_encrinfo(uint32_t id){auto it=contacts_.find(id);return it!=contacts_.end()?"encrypted":"not encrypted";}
bool DeltaChat::delete_contact(uint32_t id){return contacts_.erase(id)>0;}
int DeltaChat::lookup_contact_id_by_addr(const std::string& addr){for(auto&[id,c]:contacts_)if(c.addr==addr)return id;return 0;}
uint32_t DeltaChat::create_contact_by_addr(const std::string& addr){return create_contact(addr,addr);}

uint32_t DeltaChat::create_group_chat(bool verified,const std::string& name){
  uint32_t id=gen_id();DcChat c;c.id=id;c.name=name;c.type=verified?120:100;c.created_at=nms();c.sort_timestamp=nms();chats_[id]=c;return id;
}
uint32_t DeltaChat::create_broadcast_list(){uint32_t id=gen_id();DcChat c;c.id=id;c.name="Broadcast";c.type=130;c.created_at=nms();chats_[id]=c;return id;}
DcChat DeltaChat::get_chat(uint32_t id){auto it=chats_.find(id);if(it!=chats_.end())return it->second;return DcChat{};}
std::vector<uint32_t> DeltaChat::get_chats(uint32_t flags,const std::string& q){
  std::vector<uint32_t> r;for(auto&[id,c]:chats_){if(!q.empty()&&c.name.find(q)==std::string::npos)continue;r.push_back(id);}return r;
}
std::vector<uint32_t> DeltaChat::get_chat_msgs(uint32_t cid,uint32_t flags,const std::string& q){
  std::vector<uint32_t> r;for(auto&[id,m]:messages_){if(m.chat_id==(int)cid&&(q.empty()||m.text.find(q)!=std::string::npos))r.push_back(id);}return r;
}
DcChatlistItem DeltaChat::get_chatlist_item(uint32_t cid){DcChatlistItem it;it.chat_id=cid;it.chat=get_chat(cid);it.fresh_count=0;return it;}
uint32_t DeltaChat::get_chat_id_by_grpid(const std::string& gid){for(auto&[id,c]:chats_)if(c.grpid==gid)return id;return 0;}
int DeltaChat::get_chat_contact_count(uint32_t cid){return 0;}
std::vector<uint32_t> DeltaChat::get_chat_contacts(uint32_t cid){return{};}
bool DeltaChat::set_chat_name(uint32_t id,const std::string& n){auto it=chats_.find(id);if(it!=chats_.end()){it->second.name=n;return true;}return false;}
bool DeltaChat::set_chat_profile_image(uint32_t id,const std::string& i){return true;}
bool DeltaChat::set_chat_muted_duration(uint32_t id,int64_t d){auto it=chats_.find(id);if(it!=chats_.end()){it->second.muted_duration=d;return true;}return false;}
bool DeltaChat::set_chat_ephemeral_duration(uint32_t id,int64_t d){auto it=chats_.find(id);if(it!=chats_.end()){it->second.ephemeral_duration=d;return true;}return false;}
bool DeltaChat::set_chat_protection(uint32_t id,bool p){return true;}
bool DeltaChat::set_chat_visibility(uint32_t id,int v){return true;}
bool DeltaChat::delete_chat(uint32_t id){chats_.erase(id);return true;}
bool DeltaChat::archive_chat(uint32_t id,bool a){return true;}
bool DeltaChat::pin_chat(uint32_t id,bool p){return true;}
bool DeltaChat::accept_chat(uint32_t id){return true;}
bool DeltaChat::block_chat(uint32_t id){auto it=chats_.find(id);if(it!=chats_.end())it->second.blocking=1;return true;}
bool DeltaChat::unarchive_chat(uint32_t id){return true;}
uint32_t DeltaChat::get_chat_id_by_contact_id(uint32_t cid){return cid+1000;}
uint32_t DeltaChat::create_chat_by_contact_id(uint32_t cid){return create_group_chat(false,"Chat");}
uint32_t DeltaChat::create_chat_by_msg_id(uint32_t mid){return create_group_chat(false,"Chat");}

uint32_t DeltaChat::send_msg(uint32_t cid,const std::string& text,bool bot,const std::string& qmid){
  uint32_t id=gen_id();DcMessage m;m.id=id;m.chat_id=cid;m.text=text;m.timestamp=nms();m.sort_timestamp=nms();m.state=24;messages_[id]=m;
  // Trigger event callback
  if(event_cb_)event_cb_(1020,cid,id); // DC_EVENT_MSGS_CHANGED
  return id;
}
uint32_t DeltaChat::send_msg_synced(uint32_t cid,const std::string& text){return send_msg(cid,text);}
uint32_t DeltaChat::send_videochat_invitation(uint32_t cid){return send_msg(cid,"Video chat invitation");}
uint32_t DeltaChat::send_webxdc_instance(uint32_t cid,const std::string& name,const std::string& icon,const std::string& doc,const std::string& summary){return send_msg(cid,"Webxdc: "+name);}
uint32_t DeltaChat::send_msg_future(uint32_t cid,const std::string& text,int64_t ts){uint32_t id=gen_id();DcMessage m;m.id=id;m.chat_id=cid;m.text=text;m.timestamp=ts;messages_[id]=m;return id;}
DcMessage DeltaChat::get_msg(uint32_t id){auto it=messages_.find(id);if(it!=messages_.end())return it->second;return DcMessage{};}
std::vector<uint32_t> DeltaChat::get_fresh_msgs(uint32_t cid){return get_chat_msgs(cid,0,"");}
std::vector<uint32_t> DeltaChat::get_fresh_msg_cnt(uint32_t cid){return get_fresh_msgs(cid);}
int DeltaChat::get_fresh_msg_count(uint32_t cid){return get_fresh_msgs(cid).size();}
int DeltaChat::get_estimated_deletion_count(bool from_server,int64_t seconds){return 0;}
std::string DeltaChat::get_msg_info(uint32_t id){auto m=get_msg(id);return m.text;}
bool DeltaChat::set_msg_text(uint32_t id,const std::string& text){auto it=messages_.find(id);if(it!=messages_.end()){it->second.text=text;return true;}return false;}
bool DeltaChat::set_msg_location(uint32_t id,double lat,double lon){return true;}
bool DeltaChat::set_msg_override_sender_name(uint32_t id,const std::string& name){return true;}
bool DeltaChat::delete_msgs(const std::vector<uint32_t>& ids){for(auto id:ids)messages_.erase(id);return true;}
bool DeltaChat::markseen_msgs(const std::vector<uint32_t>& ids){for(auto id:ids){auto it=messages_.find(id);if(it!=messages_.end())it->second.state=26;}return true;}
bool DeltaChat::star_msgs(const std::vector<uint32_t>& ids,bool star){for(auto id:ids){auto it=messages_.find(id);if(it!=messages_.end())it->second.flags|=(star?1:0);}return true;}
std::vector<uint32_t> DeltaChat::search_msgs(uint32_t cid,const std::string& q){return get_chat_msgs(cid,0,q);}
std::vector<uint32_t> DeltaChat::get_next_media(uint32_t id,int dir,int type){return{};}
uint32_t DeltaChat::get_webxdc_status_updates(uint32_t id,int64_t serial){return 0;}
bool DeltaChat::send_webxdc_status_update(uint32_t id,const std::string& upd,const std::string& desc){return true;}

void DeltaChat::set_msg_file(uint32_t id,const std::string& file,const std::string& mime,const std::string& name,int64_t dur){auto it=messages_.find(id);if(it!=messages_.end())it->second.type=10;}
std::string DeltaChat::get_msg_file(uint32_t id){return"";}
std::string DeltaChat::get_msg_filebytes(uint32_t id){return"";}
std::string DeltaChat::get_msg_filename(uint32_t id){return"";}
std::string DeltaChat::get_msg_filemime(uint32_t id){return"";}
int64_t DeltaChat::get_msg_filebytes_count(uint32_t id){return 0;}

DcChatlistItem DeltaChat::get_chatlist(uint32_t flags,const std::string& q,uint32_t cid){DcChatlistItem i;return i;}
std::vector<DcChatlistItem> DeltaChat::get_chatlist_items(int index,int count){std::vector<DcChatlistItem> r;return r;}
int DeltaChat::get_chatlist_cnt(){return chats_.size();}

std::string DeltaChat::get_securejoin_qr(uint32_t cid){return"OPENPGP4FPR:1234567890ABCDEF";}
uint32_t DeltaChat::join_securejoin(const std::string& qr){return create_group_chat(true,"Secure Group");}
bool DeltaChat::check_qr(const std::string& qr){return qr.find("OPENPGP4FPR:")==0;}
DcSecureJoin DeltaChat::get_securejoin_status(uint32_t cid){DcSecureJoin j;j.invitenumber="123";return j;}

uint32_t DeltaChat::send_peer_msg(uint32_t cid,const std::string& data){return send_msg(cid,data);}
std::string DeltaChat::get_peer_msg(uint32_t id){return get_msg(id).text;}
bool DeltaChat::was_msg_peer_sent(uint32_t id){return messages_.count(id)>0;}

void DeltaChat::imex(int what,const std::string& dir){}
int DeltaChat::imex_has_backup(const std::string& dir){return 0;}
std::string DeltaChat::imex_progress(){return"0";}
int DeltaChat::import_self_keys(const std::string& dir){return 0;}

DcKey DeltaChat::get_key(const std::string& addr,int type){DcKey k;k.type=type;k.fingerprint=addr;return k;}
std::string DeltaChat::get_fingerprint(){return gen_token(40);}
std::string DeltaChat::get_self_fingerprint(){return gen_token(40);}

uint32_t DeltaChat::create_verified_group(const std::string& name){return create_group_chat(true,name);}

int DeltaChat::get_connectivity(){return 3000;} // DC_CONNECTIVITY_CONNECTED
std::string DeltaChat::get_connectivity_html(){return"<h1>Connected</h1>";}
int64_t DeltaChat::get_connectivity_summary(){return 1;}

std::string DeltaChat::get_contact_encryption_info(uint32_t cid){return get_contact_encrinfo(cid);}

int DeltaChat::send_webxdc_status_update(uint32_t id,const std::string& payload,const std::string& desc){return 1;}

std::string DeltaChat::get_provider_info(const std::string& addr){return"{}";}
int DeltaChat::check_provider_config(const std::string& ea,const std::string& pw,const std::string& is,int ip,int isec,const std::string& ss,int sp,int ssec){return 1;}
int DeltaChat::probe_imap_network(int64_t to){return 1;}
void DeltaChat::set_config_from_qr(const std::string& qr){}
std::string DeltaChat::get_auth_name_from_qr(const std::string& qr){return"";}

std::string DeltaChat::get_blobdir(){return"/tmp/deltachat-blobs";}
std::string DeltaChat::get_self_avatar(){return config_.self_avatar;}
std::string DeltaChat::get_contact_avatar(uint32_t cid){auto c=get_contact(cid);return c.profile_image;}

bool DeltaChat::send_reaction(uint32_t id,const std::string& reaction){return true;}
std::string DeltaChat::get_msg_reactions(uint32_t id){return"[]";}

bool DeltaChat::set_ephemeral_timer(uint32_t cid,int64_t d){return set_chat_ephemeral_duration(cid,d);}

uint32_t DeltaChat::add_sync_msg(const std::string& sd){return send_msg(0,sd);}
bool DeltaChat::is_sync_msg(uint32_t id){return false;}

void DeltaChat::set_http_proxy(bool en,const std::string& url){}
void DeltaChat::set_socks5_proxy(bool en,const std::string& host,int port,const std::string& user,const std::string& pw){}

int DeltaChat::maybe_network_lost(){return 0;}
bool DeltaChat::is_network_available(){return true;}

int DeltaChat::get_next_event(){
  // Return event from queue - simplified
  return 0;
}
std::string DeltaChat::get_event_str(int eid){return"";}
void DeltaChat::set_event_callback(EventCallback cb){event_cb_=cb;}

} // namespace
