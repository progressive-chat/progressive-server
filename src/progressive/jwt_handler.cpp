#include <nlohmann/json.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
using json=nlohmann::json;
namespace progressive{

// ===== JWT / OIDC Token Handler =====
struct JWTHeader{std::string alg,typ,kid;json to_json()const{return{{"alg",alg},{"typ",typ},{"kid",kid}};}static JWTHeader from_json(const json&j){return{j.value("alg","RS256"),j.value("typ","JWT"),j.value("kid","")};}};
struct JWTPayload{std::string iss,sub,aud,azp;int64_t exp,iat,nbf;std::string nonce,at_hash,c_hash;json claims;std::string raw;json to_json()const{json j{{"iss",iss},{"sub",sub},{"aud",aud},{"exp",exp},{"iat",iat}};if(!azp.empty())j["azp"]=azp;if(nbf)j["nbf"]=nbf;if(!nonce.empty())j["nonce"]=nonce;return j;}};
struct JWK{std::string kty,use,alg,kid,n,e,crv,x,y;json to_json()const{json j{{"kty",kty},{"use",use},{"alg",alg},{"kid",kid}};if(!n.empty()){j["n"]=n;j["e"]=e;}if(!crv.empty()){j["crv"]=crv;j["x"]=x;j["y"]=y;}return j;}};
struct JWKS{std::vector<JWK> keys;json to_json()const{json j;j["keys"]=json::array();for(auto&k:keys)j["keys"].push_back(k.to_json());return j;}};
struct OIDCConfig{std::string issuer,auth_endpoint,token_endpoint,userinfo_endpoint,jwks_uri,registration_endpoint;std::vector<std::string> scopes_supported,response_types,grant_types,subject_types,id_token_signing_alg_values;json to_json()const{json j{{"issuer",issuer},{"authorization_endpoint",auth_endpoint},{"token_endpoint",token_endpoint},{"userinfo_endpoint",userinfo_endpoint},{"jwks_uri",jwks_uri},{"scopes_supported",scopes_supported},{"response_types_supported",response_types},{"grant_types_supported",grant_types},{"subject_types_supported",subject_types},{"id_token_signing_alg_values_supported",id_token_signing_alg_values}};return j;}};

class JWTValidator{public:
  static bool validate_times(const JWTPayload& p,int64_t clock_skew=60){int64_t now=std::time(nullptr);if(p.exp&&now>p.exp+clock_skew)return false;if(p.nbf&&now<p.nbf-clock_skew)return false;if(p.iat&&now<p.iat-clock_skew)return false;return true;}
  static bool validate_iss(const JWTPayload& p,const std::string& expected){return p.iss==expected;}
  static bool validate_aud(const JWTPayload& p,const std::string& expected){if(p.aud.find(expected)!=std::string::npos)return true;return p.aud==expected||p.aud.find(expected+",")==0;}
  static bool validate_nonce(const JWTPayload& p,const std::string& expected){return p.nonce==expected;}
  static bool validate_sub(const JWTPayload& p){return!p.sub.empty();}
};

class Base64URL{public:
  static std::string encode(const std::string& d){static const char*cs="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";std::string r;int v=0,b=0;for(auto c:d){v=(v<<8)|(unsigned char)c;b+=8;while(b>=6){r+=cs[(v>>(b-6))&63];b-=6;}}if(b>0)r+=cs[(v<<(6-b))&63];while(!r.empty()&&r.back()=='=')r.pop_back();return r;}
  static std::string decode(const std::string& s){std::string r;int v=0,b=0;for(auto c:s){int idx=0;if(c>='A'&&c<='Z')idx=c-'A';else if(c>='a'&&c<='z')idx=c-'a'+26;else if(c>='0'&&c<='9')idx=c-'0'+52;else if(c=='-')idx=62;else if(c=='_')idx=63;else continue;v=(v<<6)|idx;b+=6;if(b>=8){r+=(char)((v>>(b-8))&0xFF);b-=8;}}return r;}
};

class JWTParser{public:
  static std::string encode(const JWTHeader& h,const JWTPayload& p,const std::string& sig){return Base64URL::encode(h.to_json().dump())+"."+Base64URL::encode(p.to_json().dump())+"."+sig;}
  static std::tuple<JWTHeader,JWTPayload,std::string> decode(const std::string& token){auto d1=token.find('.');auto d2=token.find('.',d1+1);if(d1==std::string::npos||d2==std::string::npos)throw std::runtime_error("invalid JWT format");std::string h=Base64URL::decode(token.substr(0,d1));std::string p=Base64URL::decode(token.substr(d1+1,d2-d1-1));std::string s=token.substr(d2+1);return{JWTHeader::from_json(json::parse(h)),parse_payload(json::parse(p)),s};}
private:
  static JWTPayload parse_payload(const json&j){JWTPayload p;p.iss=j.value("iss","");p.sub=j.value("sub","");p.aud=j.value("aud","");p.azp=j.value("azp","");p.exp=j.value("exp",0);p.iat=j.value("iat",0);p.nbf=j.value("nbf",0);p.nonce=j.value("nonce","");p.at_hash=j.value("at_hash","");p.c_hash=j.value("c_hash","");p.claims=j;p.raw=j.dump();return p;}
};

class JWKSCache{private:std::map<std::string,JWKS> cache_;std::map<std::string,int64_t> expiry_;public:
  void set(const std::string& uri,const JWKS& ks,int64_t ttl_sec){cache_[uri]=ks;expiry_[uri]=std::time(nullptr)+ttl_sec;}
  std::optional<JWKS> get(const std::string& uri){auto it=cache_.find(uri);if(it==cache_.end())return std::nullopt;if(expiry_[uri]<std::time(nullptr)){cache_.erase(uri);expiry_.erase(uri);return std::nullopt;}return it->second;}
  bool has(const std::string& uri){auto it=cache_.find(uri);if(it==cache_.end())return false;if(expiry_[uri]<std::time(nullptr)){cache_.erase(uri);expiry_.erase(uri);return false;}return true;}
  void invalidate(const std::string& uri){cache_.erase(uri);expiry_.erase(uri);}
  void clear(){cache_.clear();expiry_.clear();}
  json stats_json()const{json j;j["cached"]=cache_.size();return j;}
};

class RefreshTokenRotator{private:int64_t rotation_interval_;int64_t absolute_expiry_;public:
  RefreshTokenRotator(int64_t ri=86400,int64_t ae=2592000):rotation_interval_(ri),absolute_expiry_(ae){}
  bool should_rotate(int64_t created_at){return(std::time(nullptr)-created_at)>rotation_interval_;}
  bool is_expired(int64_t created_at){return(std::time(nullptr)-created_at)>absolute_expiry_;}
  std::string generate_token(){std::string t(48,'x');for(auto&c:t)c="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[rand()%64];return t;}
};

class OIDCDiscovery{public:
  static std::optional<OIDCConfig> discover(const std::string& issuer_url){
    std::string well_known=issuer_url;if(well_known.back()=='/')well_known.pop_back();
    well_known+="/.well-known/openid-configuration";
    OIDCConfig c;c.issuer=issuer_url;c.auth_endpoint=issuer_url+"/authorize";c.token_endpoint=issuer_url+"/token";c.userinfo_endpoint=issuer_url+"/userinfo";c.jwks_uri=issuer_url+"/jwks";
    c.scopes_supported={"openid","profile","email","address","phone"};
    c.response_types={"code","id_token","token id_token"};
    c.grant_types={"authorization_code","implicit","refresh_token"};
    c.subject_types={"public"};
    c.id_token_signing_alg_values={"RS256"};
    return c;
  }
};

class TokenValidationResult{public:bool valid{false};std::string error,sub,issuer;json claims;JWTPayload payload;
  json to_json()const{json j{{"valid",valid}};if(!error.empty())j["error"]=error;if(!sub.empty())j["sub"]=sub;return j;}
  static TokenValidationResult success(const std::string& s,const std::string& i,const json& c){TokenValidationResult r;r.valid=true;r.sub=s;r.issuer=i;r.claims=c;return r;}
  static TokenValidationResult fail(const std::string& e){TokenValidationResult r;r.valid=false;r.error=e;return r;}
};

class JWTHandler{public:
  TokenValidationResult validate_id_token(const std::string& token,const std::string& issuer,const std::string& client_id,const std::string& nonce=""){
    try{auto[h,p,sig]=JWTParser::decode(token);auto r=JWTValidator::validate_times(p);if(!r)return TokenValidationResult::fail("token expired or not yet valid");if(!JWTValidator::validate_iss(p,issuer))return TokenValidationResult::fail("invalid issuer");if(!JWTValidator::validate_aud(p,client_id))return TokenValidationResult::fail("invalid audience");if(!nonce.empty()&&!JWTValidator::validate_nonce(p,nonce))return TokenValidationResult::fail("invalid nonce");if(!JWTValidator::validate_sub(p))return TokenValidationResult::fail("missing subject");return TokenValidationResult::success(p.sub,issuer,p.claims);}catch(std::exception&e){return TokenValidationResult::fail(e.what());}
  }
  TokenValidationResult validate_access_token(const std::string& token,const std::string& issuer,const std::string& client_id){return validate_id_token(token,issuer,client_id);}
  std::string create_id_token(const std::string& sub,const std::string& iss,const std::string& aud,const std::string& nonce,int64_t ttl=3600){
    JWTHeader h;h.alg="RS256";h.typ="JWT";
    JWTPayload p;p.iss=iss;p.sub=sub;p.aud=aud;p.iat=std::time(nullptr);p.exp=std::time(nullptr)+ttl;if(!nonce.empty())p.nonce=nonce;
    return JWTParser::encode(h,p,"placeholder_signature");
  }
};

}
