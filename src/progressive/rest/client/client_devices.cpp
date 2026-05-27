// client_devices.cpp - devices, keys, push, notifications, receipts, tags, search, presence REST
#include "client_devices.hpp"
#include <chrono>
namespace progressive::rest {
using json = nlohmann::json;

static int64_t now_ms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}

// ====== DevicesRestServlet ======
DevicesRestServlet::DevicesRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse DevicesRestServlet::on_request(const HttpRequest& req){
  std::string did; auto p=req.path.find("/devices/"); if(p!=std::string::npos){did=req.path.substr(p+9);if(did.find('/')!=std::string::npos)did=did.substr(0,did.find('/'));}
  if(req.path.find("/delete_devices")!=std::string::npos)return delete_devices(req);
  if(!did.empty()&&req.method=="GET")return get_device(did);
  if(!did.empty()&&req.method=="PUT")return update_device(req,did);
  if(!did.empty()&&req.method=="DELETE")return delete_device(req,did);
  return get_devices(req);
}
HttpResponse DevicesRestServlet::get_devices(const HttpRequest& req){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req);
    storage::DeviceStore devs(db_); auto devices=devs.get_devices_by_user(r.user_id);
    json arr=json::array(); for(auto&d:devices){json j;j["device_id"]=d.device_id;j["display_name"]=d.display_name.value_or("");j["last_seen_ip"]=d.last_seen_ip.value_or("");j["last_seen_ts"]=d.last_seen_ts;arr.push_back(j);}
    return success_response({{"devices",arr}});
  }catch(...){return error_response(401,"M_UNKNOWN_TOKEN","");}
}
HttpResponse DevicesRestServlet::get_device(const std::string& did){
  return success_response({{"device_id",did}});
}
HttpResponse DevicesRestServlet::update_device(const HttpRequest& req,const std::string& did){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req); auto body=parse_json_body(req);
    storage::DeviceStore devs(db_); devs.update_device(r.user_id,did,body.value("display_name",""));
    return success_response();
  }catch(...){return error_response(400,"M_BAD_JSON","");}
}
HttpResponse DevicesRestServlet::delete_device(const HttpRequest& req,const std::string& did){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req);
    storage::DeviceStore devs(db_); devs.delete_device(r.user_id,did);
    return success_response();
  }catch(...){return error_response(401,"M_UNKNOWN_TOKEN","");}
}
HttpResponse DevicesRestServlet::delete_devices(const HttpRequest& req){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req); auto body=parse_json_body(req);
    storage::DeviceStore devs(db_);
    for(auto&did:body["devices"]) devs.delete_device(r.user_id,did.get<std::string>());
    return success_response();
  }catch(...){return error_response(400,"M_BAD_JSON","");}
}

// ====== KeysRestServlet ======
KeysRestServlet::KeysRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse KeysRestServlet::on_request(const HttpRequest& req){
  if(req.path.find("/upload")!=std::string::npos&&req.path.find("/device_signing")==std::string::npos&&req.path.find("/signatures")==std::string::npos)return upload_keys(req);
  if(req.path.find("/query")!=std::string::npos)return query_keys(req);
  if(req.path.find("/claim")!=std::string::npos)return claim_keys(req);
  if(req.path.find("/device_signing/upload")!=std::string::npos)return upload_signing_keys(req);
  if(req.path.find("/signatures/upload")!=std::string::npos)return upload_signatures(req);
  if(req.path.find("/changes")!=std::string::npos)return get_key_changes(req);
  return error_response(404,"M_NOT_FOUND","");
}
HttpResponse KeysRestServlet::upload_keys(const HttpRequest& req){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req); auto body=parse_json_body(req);
    storage::EndToEndKeyStore keys(db_);
    if(body.contains("device_keys")){keys.set_e2e_device_keys(r.user_id,r.device_id.value_or("unknown"),now_ms(),body["device_keys"]);}
    if(body.contains("one_time_keys")){keys.add_e2e_one_time_keys(r.user_id,r.device_id.value_or("unknown"),now_ms(),body["one_time_keys"]);}
    auto counts=keys.count_e2e_one_time_keys(r.user_id,r.device_id.value_or("unknown"));
    json cts=json::object();for(auto&[k,v]:counts)cts[k]=v;
    return success_response({{"one_time_key_counts",cts}});
  }catch(...){return error_response(400,"M_BAD_JSON","");}
}
HttpResponse KeysRestServlet::query_keys(const HttpRequest& req){
  try{ auto body=parse_json_body(req);
    json device_keys=json::object(),failures=json::object();
    std::map<std::string,json> devs;for(auto&[uid,devs_json]:body["device_keys"].items()){for(auto&did:devs_json)devs[uid][did.get<std::string>()]=json::object();}
    storage::EndToEndKeyStore keys(db_);
    for(auto&[uid,dmap]:devs){for(auto&[did,_]:dmap.items()){auto dk=keys.get_e2e_device_keys_txn(*static_cast<storage::LoggingTransaction*>(nullptr),uid,did);if(!dk.empty())device_keys[uid][did]=dk;}}
    return success_response({{"device_keys",device_keys},{"failures",failures}});
  }catch(...){return error_response(400,"M_BAD_JSON","");}
}
HttpResponse KeysRestServlet::claim_keys(const HttpRequest& req){
  try{ auto body=parse_json_body(req);
    storage::EndToEndKeyStore keys(db_);
    std::map<std::string,std::map<std::string,std::map<std::string,int>>> query;
    for(auto&[uid,dmap]:body["one_time_keys"].items())for(auto&[did,amap]:dmap.items())for(auto&[algo,_]:amap.items())query[uid][did][algo]=1;
    auto claimed=keys.claim_e2e_one_time_keys(query);
    json result=json::object();for(auto&[uid,dmap]:claimed){for(auto&[did,kmap]:dmap){std::string algo=kmap.begin()->first;algo=algo.substr(0,algo.find(':'));result[uid][did][algo]=kmap.begin()->second;}}
    return success_response({{"one_time_keys",result}});
  }catch(...){return error_response(400,"M_BAD_JSON","");}
}
HttpResponse KeysRestServlet::upload_signing_keys(const HttpRequest& req){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req); auto body=parse_json_body(req);
    storage::EndToEndKeyStore keys(db_);
    if(body.contains("master_key"))keys.set_e2e_cross_signing_key(r.user_id,"master",body["master_key"],now_ms());
    if(body.contains("self_signing_key"))keys.set_e2e_cross_signing_key(r.user_id,"self_signing",body["self_signing_key"],now_ms());
    if(body.contains("user_signing_key"))keys.set_e2e_cross_signing_key(r.user_id,"user_signing",body["user_signing_key"],now_ms());
    return success_response();
  }catch(...){return error_response(400,"M_BAD_JSON","");}
}
HttpResponse KeysRestServlet::upload_signatures(const HttpRequest& req){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req); auto body=parse_json_body(req);
    storage::EndToEndKeyStore keys(db_);
    std::map<std::string,std::map<std::string,std::string>> sigs;
    for(auto&[uid,smap]:body.items())for(auto&[did,sig]:smap.items())sigs[uid][did]=sig.dump();
    keys.store_e2e_cross_signing_signatures(r.user_id,sigs);
    return success_response();
  }catch(...){return error_response(400,"M_BAD_JSON","");}
}
HttpResponse KeysRestServlet::get_key_changes(const HttpRequest& req){
  try{ std::string from=parse_string(req,"from","0").value();std::string to=parse_string(req,"to",std::to_string(now_ms())).value();
    json changed=json::array(),left=json::array();
    return success_response({{"changed",changed},{"left",left}});
  }catch(...){return error_response(400,"M_UNKNOWN","");}
}

// ====== PushRulesRestServlet ======
PushRulesRestServlet::PushRulesRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse PushRulesRestServlet::on_request(const HttpRequest& req){
  std::string scope,kind,rule_id;
  auto p=req.path.find("/pushrules/");if(p!=std::string::npos){auto rest=req.path.substr(p+11);auto s1=rest.find('/');if(s1!=std::string::npos){scope=rest.substr(0,s1);auto s2=rest.find('/',s1+1);if(s2!=std::string::npos){kind=rest.substr(s1+1,s2-s1-1);auto s3=rest.find('/',s2+1);if(s3!=std::string::npos){rule_id=rest.substr(s2+1,s3-s2-1);}}}}
  if(rule_id.empty())return get_push_rules(req);
  if(req.path.find("/actions")!=std::string::npos)return set_rule_actions(req,scope,kind,rule_id);
  if(req.path.find("/enabled")!=std::string::npos)return set_rule_enabled(req,scope,kind,rule_id);
  if(req.method=="GET")return get_push_rule(scope,kind,rule_id);
  if(req.method=="PUT")return set_push_rule(req,scope,kind,rule_id);
  if(req.method=="DELETE")return delete_push_rule(scope,kind,rule_id);
  return error_response(404,"M_NOT_FOUND","");
}
HttpResponse PushRulesRestServlet::get_push_rules(const HttpRequest& req){try{AuthHelper auth(db_);auto r=auth.require_auth(req);return success_response({{"global",json::object()}});}catch(...){return error_response(401,"M_UNKNOWN_TOKEN","");}}
HttpResponse PushRulesRestServlet::get_push_rule(const std::string&,const std::string&,const std::string&){return success_response(json::object());}
HttpResponse PushRulesRestServlet::set_push_rule(const HttpRequest&,const std::string&,const std::string&,const std::string&){return success_response();}
HttpResponse PushRulesRestServlet::delete_push_rule(const std::string&,const std::string&,const std::string&){return success_response();}
HttpResponse PushRulesRestServlet::set_rule_actions(const HttpRequest&,const std::string&,const std::string&,const std::string&){return success_response();}
HttpResponse PushRulesRestServlet::set_rule_enabled(const HttpRequest&,const std::string&,const std::string&,const std::string&){return success_response();}

// ====== PusherRestServlet ======
PusherRestServlet::PusherRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse PusherRestServlet::on_request(const HttpRequest& req){
  if(req.method=="GET")return get_pushers(req);
  if(req.method=="POST")return set_pusher(req);
  return error_response(405,"M_UNKNOWN","");
}
HttpResponse PusherRestServlet::get_pushers(const HttpRequest& req){try{AuthHelper auth(db_);auto r=auth.require_auth(req);return success_response({{"pushers",json::array()}});}catch(...){return error_response(401,"M_UNKNOWN_TOKEN","");}}
HttpResponse PusherRestServlet::set_pusher(const HttpRequest& req){try{AuthHelper auth(db_);auto r=auth.require_auth(req);auto body=parse_json_body(req);return success_response();}catch(...){return error_response(400,"M_BAD_JSON","");}}

// ====== NotificationsRestServlet ======
NotificationsRestServlet::NotificationsRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse NotificationsRestServlet::on_request(const HttpRequest& req){try{AuthHelper auth(db_);auto r=auth.require_auth(req);return success_response({{"notifications",json::array()},{"next_token",""}});}catch(...){return error_response(401,"M_UNKNOWN_TOKEN","");}}

// ====== ReceiptsRestServlet ======
ReceiptsRestServlet::ReceiptsRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse ReceiptsRestServlet::on_request(const HttpRequest& req){try{AuthHelper auth(db_);auto r=auth.require_auth(req);return success_response();}catch(...){return error_response(401,"M_UNKNOWN_TOKEN","");}}

// ====== TagsRestServlet ======
TagsRestServlet::TagsRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse TagsRestServlet::on_request(const HttpRequest& req){
  std::string uid,rid,tag;
  auto p=req.path.find("/user/");if(p!=std::string::npos){auto rest=req.path.substr(p+6);auto s1=rest.find('/');if(s1!=std::string::npos){uid=rest.substr(0,s1);auto s2=rest.find("/rooms/",s1);if(s2!=std::string::npos){auto s3=rest.find('/',s2+7);if(s3!=std::string::npos){rid=rest.substr(s2+7,s3-s2-7);if(rest.find("/tags/",s3)!=std::string::npos)tag=rest.substr(rest.find("/tags/",s3)+6);}}}}
  if(tag.empty())return get_tags(uid,rid);
  if(req.method=="PUT")return add_tag(req,uid,rid,tag);
  if(req.method=="DELETE")return delete_tag(uid,rid,tag);
  return error_response(404,"M_NOT_FOUND","");
}
HttpResponse TagsRestServlet::get_tags(const std::string& uid,const std::string& rid){return success_response({{"tags",json::object()}});}
HttpResponse TagsRestServlet::add_tag(const HttpRequest& req,const std::string& uid,const std::string& rid,const std::string& tag){return success_response();}
HttpResponse TagsRestServlet::delete_tag(const std::string& uid,const std::string& rid,const std::string& tag){return success_response();}

// ====== SearchRestServlet ======
SearchRestServlet::SearchRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse SearchRestServlet::on_request(const HttpRequest& req){if(req.path.find("/user_directory")!=std::string::npos)return search_user_directory(req);return search(req);}
HttpResponse SearchRestServlet::search(const HttpRequest& req){try{AuthHelper auth(db_);auto r=auth.require_auth(req);return success_response({{"search_categories",json::object()}});}catch(...){return error_response(401,"M_UNKNOWN_TOKEN","");}}
HttpResponse SearchRestServlet::search_user_directory(const HttpRequest& req){try{AuthHelper auth(db_);auto r=auth.require_auth(req);std::string term=parse_string(req,"search_term","").value();return success_response({{"results",json::array()},{"limited",false}});}catch(...){return error_response(401,"M_UNKNOWN_TOKEN","");}}

// ====== PresenceRestServlet ======
PresenceRestServlet::PresenceRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse PresenceRestServlet::on_request(const HttpRequest& req){
  std::string uid;auto p=req.path.find("/presence/");if(p!=std::string::npos){uid=req.path.substr(p+10);if(uid.find('/')!=std::string::npos)uid=uid.substr(0,uid.find('/'));}
  if(req.path.find("/status")!=std::string::npos){if(req.method=="GET")return get_presence(uid);if(req.method=="PUT")return set_presence(req,uid);}
  if(req.path.find("/list")!=std::string::npos){if(req.method=="GET")return get_presence_list(uid);if(req.method=="POST")return modify_presence_list(req,uid);}
  return error_response(404,"M_NOT_FOUND","");
}
HttpResponse PresenceRestServlet::get_presence(const std::string& uid){return success_response({{"presence","offline"},{"last_active_ago",0},{"currently_active",false}});}
HttpResponse PresenceRestServlet::set_presence(const HttpRequest& req,const std::string& uid){try{AuthHelper auth(db_);auto r=auth.require_auth(req);auto body=parse_json_body(req);return success_response();}catch(...){return error_response(400,"M_BAD_JSON","");}}
HttpResponse PresenceRestServlet::get_presence_list(const std::string& uid){return success_response(json::array());}
HttpResponse PresenceRestServlet::modify_presence_list(const HttpRequest& req,const std::string& uid){return success_response();}

} // namespace
