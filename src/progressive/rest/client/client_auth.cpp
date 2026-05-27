// client_auth.cpp - auth, register, login, logout, account REST servlets
#include "client_auth.hpp"
#include <chrono>
#include <sstream>
#include <random>
namespace progressive::rest {
using json = nlohmann::json;

static std::string generate_token(int len=64) {
  static const char cs[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
  std::uniform_int_distribution<> d(0,61); std::string t(len,'A');
  for(auto&c:t)c=cs[d(rng)]; return t;
}

RegisterRestServlet::RegisterRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse RegisterRestServlet::on_request(const HttpRequest& req){
  if(req.method=="POST")return on_POST(req);
  if(req.method=="GET")return on_GET(req);
  return error_response(405,"M_UNKNOWN","Method not allowed");
}
HttpResponse RegisterRestServlet::on_POST(const HttpRequest& req){
  try{ auto body=parse_json_body(req);
    std::string username=body.value("username",""); std::string password=body.value("password","");
    std::string device_id=body.value("initial_device_display_name","");
    bool inhibit_login=body.value("inhibit_login",false);
    if(username.empty()&&password.empty())return error_response(400,"M_MISSING_PARAM","Missing username or password");
    std::string user_id="@"+username+":localhost";
    storage::RegistrationStore reg(db_);
    try{ reg.register_user(user_id,password,username); }catch(const storage::ExternalIDReuseException&){return error_response(400,"M_USER_IN_USE","User ID already taken");}
    std::string access_token=reg.add_access_token_to_user(user_id,device_id);
    HttpResponse r; r.code=200; r.body={{"user_id",user_id},{"access_token",access_token},{"device_id",device_id},{"home_server","localhost"}}; return r;
  }catch(const std::exception& e){return error_response(400,"M_BAD_JSON",e.what());}
}
HttpResponse RegisterRestServlet::on_GET(const HttpRequest& req){
  HttpResponse r; r.code=200; r.body={{"auth",{{"type","m.login.dummy"}}}}; return r;
}

LoginRestServlet::LoginRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse LoginRestServlet::on_request(const HttpRequest& req){
  if(req.method=="POST")return on_POST_login(req);
  if(req.method=="GET")return on_GET_login(req);
  return error_response(405,"M_UNKNOWN","Method not allowed");
}
HttpResponse LoginRestServlet::on_POST_login(const HttpRequest& req){
  try{ auto body=parse_json_body(req);
    std::string type=body.value("type","m.login.password");
    std::string user=body.value("user",""); std::string medium=body.value("medium","");
    std::string address=body.value("address",""); std::string password=body.value("password","");
    std::string token=body.value("token",""); std::string device_id=body.value("device_id","");
    storage::RegistrationStore reg(db_);
    std::string user_id;
    if(!user.empty()){ user_id=user;
    }else if(!medium.empty()&&!address.empty()){
      auto uid=reg.get_user_by_threepid(medium,address);
      if(!uid)return error_response(403,"M_FORBIDDEN","Invalid threepid"); user_id=*uid;
    }
    if(user_id.empty())return error_response(400,"M_MISSING_PARAM","Missing user identifier");
    auto pw_hash=reg.get_password_hash(user_id);
    if(!pw_hash)return error_response(403,"M_FORBIDDEN","Invalid password");
    std::string access_token=reg.add_access_token_to_user(user_id,device_id);
    HttpResponse r; r.code=200; r.body={{"user_id",user_id},{"access_token",access_token},{"device_id",device_id},{"home_server","localhost"}}; return r;
  }catch(const std::exception& e){return error_response(400,"M_BAD_JSON",e.what());}
}
HttpResponse LoginRestServlet::on_GET_login(const HttpRequest& req){
  HttpResponse r; r.code=200; r.body={{"flows",json::array({{{"type","m.login.password"}},{{"type","m.login.token"}}})}}; return r;
}

LogoutRestServlet::LogoutRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse LogoutRestServlet::on_request(const HttpRequest& req){
  try{ AuthHelper auth(db_); auto requester=auth.require_auth(req);
    storage::RegistrationStore reg(db_); reg.delete_access_token(requester.access_token);
    return success_response(); }catch(...){ return error_response(401,"M_UNKNOWN_TOKEN",""); }
}

AuthRestServlet::AuthRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse AuthRestServlet::on_request(const HttpRequest& req){
  HttpResponse r; r.code=200; r.body={{"flows",json::array({{{"type","m.login.password"}}})}}; return r;
}

AccountRestServlet::AccountRestServlet(storage::DatabasePool& db):db_(db){}
HttpResponse AccountRestServlet::on_request(const HttpRequest& req){
  if(req.path.find("/whoami")!=std::string::npos)return whoami(req);
  if(req.path.find("/password")!=std::string::npos && req.method=="POST")return change_password(req);
  if(req.path.find("/deactivate")!=std::string::npos)return deactivate_account(req);
  if(req.path.find("/3pid/delete")!=std::string::npos||req.path.find("/3pid/unbind")!=std::string::npos)return delete_threepid(req);
  if(req.path.find("/3pid/add")!=std::string::npos||req.path.find("/3pid/bind")!=std::string::npos)return add_threepid(req);
  if(req.path.find("/3pid/email/requestToken")!=std::string::npos)return request_email_token(req);
  if(req.path.find("/3pid")!=std::string::npos)return get_threepids(req);
  return error_response(404,"M_NOT_FOUND","Unknown account endpoint");
}
HttpResponse AccountRestServlet::whoami(const HttpRequest& req){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req);
    HttpResponse res; res.body={{"user_id",r.user_id}}; return res;
  }catch(...){return error_response(401,"M_UNKNOWN_TOKEN","");}
}
HttpResponse AccountRestServlet::change_password(const HttpRequest& req){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req);
    auto body=parse_json_body(req); std::string new_pw=body.value("new_password","");
    if(new_pw.empty())return error_response(400,"M_MISSING_PARAM","Missing new_password");
    storage::RegistrationStore reg(db_); reg.set_password(r.user_id,new_pw);
    return success_response();
  }catch(...){return error_response(400,"M_BAD_JSON","");}
}
HttpResponse AccountRestServlet::deactivate_account(const HttpRequest& req){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req);
    auto body=parse_json_body(req); bool erase=body.value("erase",false);
    storage::RegistrationStore reg(db_); reg.deactivate_account(r.user_id,erase);
    return success_response();
  }catch(...){return error_response(400,"M_UNKNOWN","");}
}
HttpResponse AccountRestServlet::get_threepids(const HttpRequest& req){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req);
    storage::RegistrationStore reg(db_); auto tps=reg.get_threepids_for_user(r.user_id);
    json arr=json::array();
    for(auto&tp:tps){ json j; j["medium"]=tp.medium; j["address"]=tp.address; j["validated_at"]=tp.validated_at; j["added_at"]=tp.added_at; arr.push_back(j); }
    return success_response({{"threepids",arr}});
  }catch(...){return error_response(401,"M_UNKNOWN_TOKEN","");}
}
HttpResponse AccountRestServlet::add_threepid(const HttpRequest& req){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req);
    auto body=parse_json_body(req);
    storage::RegistrationStore reg(db_);
    int64_t now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    reg.user_add_threepid(r.user_id,body.value("medium",""),body.value("address",""),0,now);
    return success_response();
  }catch(...){return error_response(400,"M_BAD_JSON","");}
}
HttpResponse AccountRestServlet::bind_threepid(const HttpRequest& req){
  return add_threepid(req);
}
HttpResponse AccountRestServlet::delete_threepid(const HttpRequest& req){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req);
    auto body=parse_json_body(req);
    storage::RegistrationStore reg(db_);
    reg.user_delete_threepid(r.user_id,body.value("medium",""),body.value("address",""));
    return success_response();
  }catch(...){return error_response(400,"M_BAD_JSON","");}
}
HttpResponse AccountRestServlet::request_email_token(const HttpRequest& req){
  try{ AuthHelper auth(db_); auto r=auth.require_auth(req);
    auto body=parse_json_body(req);
    return success_response({{"sid",generate_token(16)}});
  }catch(...){return error_response(400,"M_BAD_JSON","");}
}

} // namespace
