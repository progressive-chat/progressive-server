// handlers_identity.cpp - presence, device, e2e_keys, oidc, register, room_summary, appservice
#include "handlers_identity.hpp"
#include <chrono>
#include <random>
namespace progressive::handlers {
using json = nlohmann::json;
static int64_t now_ms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
static std::string gen_id(const std::string& p){static std::atomic<int64_t> c{1};return p+std::to_string(now_ms())+"-"+std::to_string(c.fetch_add(1));}
static std::string gen_token(int l=32){static const char cs[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";static thread_local std::mt19937 rng(now_ms());std::uniform_int_distribution<> d(0,61);std::string t(l,'A');for(auto&c:t)c=cs[d(rng)];return t;}

// ====== PresenceHandler ======
PresenceHandler::PresenceHandler(DatabasePool& db):db_(db),presence_store_(db){}
PresenceHandler::PresenceInfo PresenceHandler::get_presence(const std::string& uid){
  auto p=presence_store_.get_presence(uid);PresenceInfo i; i.user_id=uid;
  if(p){i.state=p->state.state;i.last_active_ago=(now_ms()-p->state.last_active_ts)/1000;i.currently_active=p->state.currently_active;i.status_msg=p->state.status_msg;}
  else{i.state="offline";i.last_active_ago=0;i.currently_active=false;}
  return i;
}
void PresenceHandler::set_presence(const std::string& uid,const std::string& state,const std::optional<std::string>& msg){
  set_state(uid,state,msg.value_or(""),now_ms(),state=="online");
}
std::map<std::string,PresenceHandler::PresenceInfo> PresenceHandler::get_presence_for_users(const std::set<std::string>& uids){
  std::map<std::string,PresenceInfo> r;for(auto&u:uids)r[u]=get_presence(u);return r;
}
void PresenceHandler::user_syncing(const std::string& uid,bool s,int64_t ts){presence_store_.update_presence_last_sync(uid,ts);}
std::vector<PresenceHandler::PresenceInfo> PresenceHandler::get_presence_for_federation(int64_t ft,int l){
  auto states=presence_store_.get_all_presence_for_federation(ft,l);std::vector<PresenceInfo> r;for(auto&s:states)r.push_back({s.user_id,s.state,0,s.currently_active,s.status_msg});return r;
}
void PresenceHandler::propagate_presence(const std::string& uid){auto info=get_presence(uid);notify_interested_parties(uid,info);}
void PresenceHandler::handle_timeout(){auto stale=presence_store_.get_stale_presence(300000,100);presence_store_.clear_stale_presence(stale);}
void PresenceHandler::handle_timeout_for_user(const std::string& uid){presence_store_.clear_stale_presence({uid});}
int64_t PresenceHandler::get_timeout_ms(){return 300000;}
void PresenceHandler::process_federation_presence(const std::string&,const std::string& uid,const PresenceInfo& pi){set_state(uid,pi.state,pi.status_msg.value_or(""),now_ms(),pi.currently_active);}
void PresenceHandler::set_state(const std::string& uid,const std::string& s,const std::string& msg,int64_t lat,bool ca){presence_store_.set_presence_state(uid,s,msg,lat,ca);}
std::set<std::string> PresenceHandler::get_interested_remotes(const std::string& uid){return {};}
void PresenceHandler::notify_interested_parties(const std::string& uid,const PresenceInfo& info){}
void PresenceHandler::send_presence_to_destinations(const std::string& uid,const PresenceInfo& info){}

// ====== DeviceHandler ======
DeviceHandler::DeviceHandler(DatabasePool& db):db_(db),device_store_(db){}
std::vector<DeviceInfo> DeviceHandler::get_devices(const std::string& uid){return device_store_.get_devices_by_user(uid);}
std::optional<DeviceInfo> DeviceHandler::get_device(const std::string& uid,const std::string& did){return device_store_.get_device(uid,did);}
std::string DeviceHandler::create_device(const std::string& uid,const std::optional<std::string>& did,const std::optional<std::string>& dn){std::string d=did.value_or(generate_device_id());device_store_.store_device(uid,d,dn);return d;}
void DeviceHandler::update_device(const std::string& uid,const std::string& did,const std::optional<std::string>& dn,const std::optional<std::string>& dt,bool h){device_store_.update_device(uid,did,dn,dt,h);}
void DeviceHandler::delete_device(const std::string& uid,const std::string& did){device_store_.delete_device(uid,did);}
void DeviceHandler::delete_devices(const std::string& uid,const std::vector<std::string>& dids){for(auto&d:dids)device_store_.delete_device(uid,d);}
void DeviceHandler::update_device_last_seen(const std::string& uid,const std::string& did,const std::string& ip,const std::string& ua){device_store_.update_device_last_seen(uid,did,ip,ua);}
void DeviceHandler::notify_device_list_update(const std::string& uid,const std::vector<std::string>& dids){auto sid=device_store_.add_device_change_to_stream(uid,dids,"");}
void DeviceHandler::process_federation_device_list_update(const std::string&,const std::string& uid,const std::vector<std::string>& dids){}
bool DeviceHandler::device_exists(const std::string& uid,const std::string& did){return device_store_.get_device(uid,did).has_value();}
int64_t DeviceHandler::get_device_stream_token(){return device_store_.get_device_stream_token();}
std::map<std::string,std::vector<std::string>> DeviceHandler::get_users_whose_devices_changed(int64_t f,int64_t t){return device_store_.get_users_whose_devices_changed(f,t);}
void DeviceHandler::handle_device_list_update_edu(const std::string&,const std::string& uid,int64_t,const std::vector<std::string>&,const std::vector<std::string>&){}
std::string DeviceHandler::generate_device_id(){return gen_id("DEV");}

// ====== E2eKeysHandler ======
E2eKeysHandler::E2eKeysHandler(DatabasePool& db):db_(db),e2e_store_(db){}
E2eKeysHandler::UploadResult E2eKeysHandler::upload_keys(const std::string& uid,const std::string& did,const json& dk,const json& otk,const json& fbk){
  int64_t ts=now_ms();e2e_store_.set_e2e_device_keys(uid,did,ts,dk);
  if(!otk.empty()){std::map<std::string,std::map<std::string,json>> kmap;for(auto&[algo,keys]:otk.items())for(auto&[kid,kd]:keys.items())kmap[algo][kid]=kd;e2e_store_.add_e2e_one_time_keys(uid,did,ts,kmap);}
  auto counts=e2e_store_.count_e2e_one_time_keys(uid,did);json cts;for(auto&[k,v]:counts)cts[k]=v;
  return {cts,did,dk,otk,fbk};
}
E2eKeysHandler::QueryResult E2eKeysHandler::query_keys(const json& query){
  QueryResult r; r.device_keys=json::object(); r.master_keys=json::object(); r.self_signing_keys=json::object(); r.user_signing_keys=json::object(); r.failures=json::object();
  for(auto&[uid,devs]:query.value("device_keys",json::object()).items()){for(auto&did:devs){auto dk=e2e_store_.get_e2e_device_keys_txn(*static_cast<LoggingTransaction*>(nullptr),uid,did.get<std::string>());if(!dk.empty())r.device_keys[uid][did.get<std::string>()]=dk;}}
  return r;
}
E2eKeysHandler::ClaimResult E2eKeysHandler::claim_one_time_keys(const json& claim){
  ClaimResult r; r.one_time_keys=json::object(); r.failures=json::object();
  std::map<std::string,std::map<std::string,std::map<std::string,int>>> query;
  for(auto&[uid,dmap]:claim.value("one_time_keys",json::object()).items())for(auto&[did,amap]:dmap.items())for(auto&[algo,_]:amap.items())query[uid][did][algo]=1;
  auto claimed=e2e_store_.claim_e2e_one_time_keys(query);
  for(auto&[uid,dmap]:claimed)for(auto&[did,kmap]:dmap){std::string algo=kmap.begin()->first;algo=algo.substr(0,algo.find(':'));r.one_time_keys[uid][did][algo]=kmap.begin()->second;}
  return r;
}
json E2eKeysHandler::count_one_time_keys(const std::string& uid,const std::string& did){auto c=e2e_store_.count_e2e_one_time_keys(uid,did);json r;for(auto&[k,v]:c)r[k]=v;return r;}
void E2eKeysHandler::upload_signing_keys(const std::string& uid,const std::optional<json>& mk,const std::optional<json>& ssk,const std::optional<json>& usk){int64_t ts=now_ms();if(mk)e2e_store_.set_e2e_cross_signing_key(uid,"master",*mk,ts);if(ssk)e2e_store_.set_e2e_cross_signing_key(uid,"self_signing",*ssk,ts);if(usk)e2e_store_.set_e2e_cross_signing_key(uid,"user_signing",*usk,ts);}
void E2eKeysHandler::upload_signatures(const std::string& uid,const std::map<std::string,std::map<std::string,json>>& sigs){std::map<std::string,std::map<std::string,std::string>> ss;for(auto&[t,m]:sigs)for(auto&[d,s]:m)ss[t][d]=s.dump();e2e_store_.store_e2e_cross_signing_signatures(uid,ss);}
std::map<std::string,std::map<std::string,json>> E2eKeysHandler::get_cross_signing_keys(const std::set<std::string>& uids){return e2e_store_.get_e2e_cross_signing_keys_bulk(uids);}
bool E2eKeysHandler::verify_device_key_signature(const std::string&,const std::string&,const json&){return true;}
E2eKeysHandler::QueryResult E2eKeysHandler::query_keys_for_federation(const std::string& uid,const std::vector<std::string>& dids){
  QueryResult r;r.device_keys=json::object(); for(auto&did:dids){auto dk=e2e_store_.get_e2e_device_keys_txn(*static_cast<LoggingTransaction*>(nullptr),uid,did);if(!dk.empty())r.device_keys[uid][did]=dk;} return r;
}
E2eKeysHandler::ClaimResult E2eKeysHandler::claim_keys_for_federation(const json& claim){return claim_one_time_keys(claim);}
json E2eKeysHandler::get_key_changes(const std::string&,const std::string&){return json::object();}

// ====== OidcHandler ======
OidcHandler::OidcHandler(DatabasePool& db):db_(db){}
OidcHandler::OidcCallbackResult OidcHandler::handle_oidc_callback(const json& tr,const std::string&,const std::string&){
  std::string sub=tr.value("sub","");std::string uid=map_oidc_user("default",sub,{});
  return {uid,gen_token(64),"oidc-device",std::nullopt};
}
json OidcHandler::validate_oidc_token(const std::string&,const std::string&){return json::object();}
std::string OidcHandler::map_oidc_user(const std::string& pid,const std::string& sub,const std::map<std::string,std::string>& attrs){return "@oidc_"+sub+":localhost";}
json OidcHandler::query_userinfo(const std::string&,const std::string&){return json::object();}
OidcHandler::OidcProviderConfig OidcHandler::get_provider_config(const std::string&){return{};}
json OidcHandler::get_jwks(const std::string&){return json::object();}
bool OidcHandler::verify_jwt_signature(const std::string&,const json&){return true;}
void OidcHandler::handle_oidc_logout(const std::string&){}

// ====== RegisterHandler ======
RegisterHandler::RegisterHandler(DatabasePool& db):db_(db),reg_store_(db){}
RegisterHandler::RegisterResult RegisterHandler::register_user(const json& params){
  std::string uname=params.value("username","");std::string pw=params.value("password","");
  std::string uid=generate_user_id(uname);
  reg_store_.register_user(uid,pw,uname);
  std::string did=params.value("device_id",gen_id("DEV"));
  std::string at=reg_store_.add_access_token_to_user(uid,did);
  return {uid,at,did,"localhost",gen_token(64)};
}
bool RegisterHandler::is_username_available(const std::string& uname){return true;}
bool RegisterHandler::is_username_valid(const std::string& uname){return !uname.empty()&&uname.find(':')==std::string::npos;}
std::string RegisterHandler::generate_user_id(const std::string& uname){return "@"+uname+":localhost";}
RegisterHandler::RegisterResult RegisterHandler::register_guest(const json& p){
  std::string uid="@"+gen_id("guest")+":localhost";reg_store_.register_user(uid,std::nullopt,"Guest",false,true);
  std::string did=gen_id("DEV");std::string at=reg_store_.add_access_token_to_user(uid,did);
  return {uid,at,did,"localhost"};
}
std::string RegisterHandler::create_registration_session(const json&){return gen_id("reg");}
RegisterHandler::RegisterResult RegisterHandler::complete_registration(const std::string&,const json& p){return register_user(p);}
void RegisterHandler::add_threepid_to_registration(const std::string&,const std::string&,const std::string&){}
bool RegisterHandler::is_registration_allowed(){return true;}
std::vector<json> RegisterHandler::get_registration_flows(){return {{{"type","m.login.password"}},{{"type","m.login.dummy"}}};}

// ====== RoomSummaryHandler ======
RoomSummaryHandler::RoomSummaryHandler(DatabasePool& db):db_(db){}
RoomSummaryHandler::RoomSummary RoomSummaryHandler::get_room_summary(const std::string& uid,const std::string& rid){
  RoomMemberStore members(db_); auto m=members.get_member(rid,uid);
  RoomSummary s; s.heroes=calculate_heroes(rid);
  if(m){s.joined_members=0;s.membership=m->membership;s.is_direct=is_direct_room(uid,rid);}
  s.room_name=get_room_display_name(uid,rid); return s;
}
std::map<std::string,RoomSummaryHandler::RoomSummary> RoomSummaryHandler::get_room_summaries(const std::string& uid,const std::set<std::string>& rids){std::map<std::string,RoomSummary> r;for(auto&rid:rids)r[rid]=get_room_summary(uid,rid);return r;}
std::vector<std::string> RoomSummaryHandler::calculate_heroes(const std::string& rid,int l){RoomMemberStore m(db_);auto members=m.get_joined_members(rid);std::vector<std::string> h;int c=0;for(auto&mb:members){if(c>=l)break;if(mb.membership=="join"){h.push_back(mb.user_id);c++;}}return h;}
bool RoomSummaryHandler::is_direct_room(const std::string& uid,const std::string& rid){return false;}
std::string RoomSummaryHandler::get_room_display_name(const std::string& uid,const std::string& rid){RoomStore rooms(db_);auto r=rooms.get_room(rid);return r&&(*r).contains("name")?(*r)["name"].get<std::string>():rid;}
void RoomSummaryHandler::invalidate_room_summary(const std::string&){}
void RoomSummaryHandler::invalidate_user_room_summaries(const std::string&){}
std::optional<json> RoomSummaryHandler::get_last_room_event(const std::string& rid){EventsStore evs(db_);auto events=evs.get_recent_events_for_room(rid,1,INT64_MAX);if(!events.empty())return events[0];return std::nullopt;}

// ====== AppserviceHandler ======
AppserviceHandler::AppserviceHandler(DatabasePool& db):db_(db),as_store_(db){}
void AppserviceHandler::register_appservice(const ApplicationService& s){as_store_.add_appservice(s);}
void AppserviceHandler::unregister_appservice(const std::string& sid){as_store_.remove_appservice(sid);}
void AppserviceHandler::notify_appservices(const std::string& rid,const std::string& eid,const std::string& et){auto svcs=get_interested_services(rid);for(auto&sid:svcs){if(et!="m.room.member"||rid=="")schedule_appservice_transaction(sid);}}
std::vector<std::string> AppserviceHandler::get_interested_services(const std::string& rid){return{};}
void AppserviceHandler::schedule_appservice_transaction(const std::string& sid){as_store_.create_appservice_txn(sid,gen_id("as"));}
void AppserviceHandler::send_pending_transactions(const std::string& sid){}
bool AppserviceHandler::handle_ping(const std::string& sid,const std::string&){return true;}
bool AppserviceHandler::is_appservice_user(const std::string& uid){return uid.find("@_")!=std::string::npos;}
std::optional<ApplicationService> AppserviceHandler::get_appservice_for_user(const std::string& uid){return as_store_.get_appservice(uid);}
bool AppserviceHandler::is_exclusive_alias(const std::string& a){return as_store_.is_exclusive_alias(a);}
bool AppserviceHandler::is_exclusive_user(const std::string& uid){return as_store_.is_exclusive_user(uid);}
void AppserviceHandler::process_appservice_events(const std::string&,const std::vector<json>&){}
void AppserviceHandler::handle_appservice_ephemeral(const std::string&,const std::string&,const std::vector<json>&){}

} // namespace
