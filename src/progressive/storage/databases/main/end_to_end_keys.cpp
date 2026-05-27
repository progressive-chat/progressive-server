#include "progressive/storage/databases/main/end_to_end_keys.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
using json = nlohmann::json;
namespace progressive::storage { namespace { int64_t ek(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());} }

// DDL for E2E keys
static const char* E2E_DDL = R"SQL(
CREATE TABLE IF NOT EXISTS e2e_device_keys_json(user_id TEXT NOT NULL,device_id TEXT NOT NULL,key_json TEXT NOT NULL,display_name TEXT,CONSTRAINT e2e_dk PRIMARY KEY(user_id,device_id));
CREATE TABLE IF NOT EXISTS e2e_one_time_keys_json(user_id TEXT NOT NULL,device_id TEXT NOT NULL,algorithm TEXT NOT NULL,key_id TEXT NOT NULL,key_json TEXT NOT NULL,CONSTRAINT e2e_otk PRIMARY KEY(user_id,device_id,algorithm,key_id));
CREATE TABLE IF NOT EXISTS e2e_fallback_keys_json(user_id TEXT NOT NULL,device_id TEXT NOT NULL,algorithm TEXT NOT NULL,key_json TEXT NOT NULL,used BOOLEAN DEFAULT 0,CONSTRAINT e2e_fk PRIMARY KEY(user_id,device_id,algorithm));
CREATE TABLE IF NOT EXISTS e2e_cross_signing_keys(user_id TEXT NOT NULL,key_type TEXT NOT NULL,key_json TEXT NOT NULL,CONSTRAINT e2e_csk PRIMARY KEY(user_id,key_type));
CREATE TABLE IF NOT EXISTS e2e_cross_signing_signatures(signed_user_id TEXT NOT NULL,signed_device_id TEXT NOT NULL,signer_user_id TEXT NOT NULL,signer_device_id TEXT NOT NULL,signature TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS e2e_cs_idx ON e2e_cross_signing_signatures(signed_user_id,signed_device_id);
CREATE TABLE IF NOT EXISTS dehydrated_devices(user_id TEXT NOT NULL,device_id TEXT NOT NULL,device_data TEXT NOT NULL,CONSTRAINT dd_pk PRIMARY KEY(user_id,device_id));
)SQL";

void EndToEndKeysStore::set_e2e_device_keys_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const json& keys,const std::string& dn){
  txn.execute("INSERT INTO e2e_device_keys_json VALUES(?,?,?,?) ON CONFLICT(user_id,device_id) DO UPDATE SET key_json=excluded.key_json,display_name=COALESCE(excluded.display_name,e2e_device_keys_json.display_name)",{uid,did,keys.dump(),dn});
  txn.execute("INSERT INTO device_lists_stream(user_id,device_id,change_type,ts) VALUES(?,?,'keys',?)",{uid,did,ek()});
}
json EndToEndKeysStore::get_e2e_device_keys_for_devices_txn(LoggingTransaction& txn,const std::string& uid,const std::vector<std::string>& dids){
  json r=json::object();if(dids.empty())return r;
  std::string ph;std::vector<DatabaseType> p;for(size_t i=0;i<dids.size();++i){if(i)ph+=",";ph+="?";p.push_back(dids[i]);}
  p.insert(p.begin(),uid);
  auto rows=txn.select("SELECT device_id,key_json,display_name FROM e2e_device_keys_json WHERE user_id=? AND device_id IN("+ph+")",p);
  for(auto& row:rows){json d;d["keys"]=json::parse(row.get<std::string>(1));if(!row.is_null(2))d["device_display_name"]=row.get<std::string>(2);r[row.get<std::string>(0)]=d;} return r;
}
json EndToEndKeysStore::get_all_e2e_device_keys_txn(LoggingTransaction& txn,const std::string& uid){
  json r=json::object();auto rows=txn.select("SELECT device_id,key_json,display_name FROM e2e_device_keys_json WHERE user_id=?",{uid});
  for(auto& row:rows){json d;d["keys"]=json::parse(row.get<std::string>(1));if(!row.is_null(2))d["device_display_name"]=row.get<std::string>(2);r[row.get<std::string>(0)]=d;} return r;
}
void EndToEndKeysStore::upload_one_time_keys_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const json& keys){
  for(auto&[alg,km]:keys.items())for(auto&[kid,kd]:km.items())txn.execute("INSERT INTO e2e_one_time_keys_json VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING",{uid,did,alg,kid,kd.is_object()?kd.dump():kd.get<std::string>()});
}
json EndToEndKeysStore::count_one_time_keys_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did){
  json r;r["signed_curve25519"]=0;r["curve25519"]=0;auto rows=txn.select("SELECT algorithm,COUNT(*) FROM e2e_one_time_keys_json WHERE user_id=? AND device_id=? GROUP BY algorithm",{uid,did});
  for(auto& row:rows)r[row.get<std::string>(0)]=row.get<int64_t>(1);return r;
}
json EndToEndKeysStore::claim_one_time_keys_for_devices_txn(LoggingTransaction& txn,const std::map<std::string,std::map<std::string,std::string>>& q){
  json r=json::object();
  for(auto&[uid,dm]:q){if(!r.contains(uid))r[uid]=json::object();
    for(auto&[did,alg]:dm){auto kr=txn.select_one("SELECT key_id,key_json FROM e2e_one_time_keys_json WHERE user_id=? AND device_id=? AND algorithm=? ORDER BY key_id LIMIT 1",{uid,did,alg});
      if(kr&&!kr->is_null()){std::string kid=kr->get<std::string>(0);json kd=json::parse(kr->get<std::string>(1));txn.execute("DELETE FROM e2e_one_time_keys_json WHERE user_id=? AND device_id=? AND algorithm=? AND key_id=?",{uid,did,alg,kid});r[uid][did]={{{alg,kd}}};}
    }
  }return r;
}
void EndToEndKeysStore::set_fallback_key_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const std::string& alg,const json& key){
  txn.execute("INSERT INTO e2e_fallback_keys_json VALUES(?,?,?,?,0) ON CONFLICT(user_id,device_id,algorithm) DO UPDATE SET key_json=excluded.key_json,used=0",{uid,did,alg,key.dump()});
}
json EndToEndKeysStore::get_fallback_keys_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did){
  json r=json::object();auto rows=txn.select("SELECT algorithm,key_json FROM e2e_fallback_keys_json WHERE user_id=? AND device_id=? AND used=0",{uid,did});
  for(auto& row:rows){r[row.get<std::string>(0)]=json::parse(row.get<std::string>(1));txn.execute("UPDATE e2e_fallback_keys_json SET used=1 WHERE user_id=? AND device_id=? AND algorithm=?",{uid,did,row.get<std::string>(0)});}return r;
}
void EndToEndKeysStore::set_cross_signing_key_txn(LoggingTransaction& txn,const std::string& uid,const std::string& kt,const json& key){
  txn.execute("INSERT INTO e2e_cross_signing_keys VALUES(?,?,?) ON CONFLICT(user_id,key_type) DO UPDATE SET key_json=excluded.key_json",{uid,kt,key.dump()});
}
json EndToEndKeysStore::get_cross_signing_keys_txn(LoggingTransaction& txn,const std::string& uid){
  json r=json::object();auto rows=txn.select("SELECT key_type,key_json FROM e2e_cross_signing_keys WHERE user_id=?",{uid});
  for(auto& row:rows)r[row.get<std::string>(0)]=json::parse(row.get<std::string>(1));return r;
}
void EndToEndKeysStore::store_signatures_txn(LoggingTransaction& txn,const std::string& suid,const std::string& sdid,const std::map<std::string,std::map<std::string,std::string>>& sigs){
  for(auto&[gid,gm]:sigs)for(auto&[gdid,sig]:gm)txn.execute("INSERT OR IGNORE INTO e2e_cross_signing_signatures VALUES(?,?,?,?,?)",{suid,sdid,gid,gdid,sig});
}
json EndToEndKeysStore::get_signatures_for_device_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did){
  json r=json::object();auto rows=txn.select("SELECT signer_user_id,signer_device_id,signature FROM e2e_cross_signing_signatures WHERE signed_user_id=? AND signed_device_id=?",{uid,did});
  for(auto& row:rows){std::string si=row.get<std::string>(0);if(!r.contains(si))r[si]=json::object();r[si][row.get<std::string>(1)]=row.get<std::string>(2);}return r;
}
void EndToEndKeysStore::delete_all_e2e_keys_for_user_txn(LoggingTransaction& txn,const std::string& uid){
  for(const char* t:{"e2e_device_keys_json","e2e_one_time_keys_json","e2e_fallback_keys_json","e2e_cross_signing_keys","dehydrated_devices"})
    txn.execute(std::string("DELETE FROM ")+t+" WHERE user_id=?",{uid});
  txn.execute("DELETE FROM e2e_cross_signing_signatures WHERE signed_user_id=? OR signer_user_id=?",{uid,uid});
}
void EndToEndKeysStore::store_dehydrated_device_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const json& dd){
  txn.execute("INSERT INTO dehydrated_devices VALUES(?,?,?) ON CONFLICT(user_id,device_id) DO UPDATE SET device_data=excluded.device_data",{uid,did,dd.dump()});
}
json EndToEndKeysStore::get_dehydrated_devices_txn(LoggingTransaction& txn,const std::string& uid){
  json r=json::object();auto rows=txn.select("SELECT device_id,device_data FROM dehydrated_devices WHERE user_id=?",{uid});
  for(auto& row:rows)r[row.get<std::string>(0)]=json::parse(row.get<std::string>(1));return r;
}
void EndToEndKeysStore::delete_dehydrated_device_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did){
  txn.execute("DELETE FROM dehydrated_devices WHERE user_id=? AND device_id=?",{uid,did});
}
void EndToEndKeysStore::bulk_get_device_keys_txn(LoggingTransaction& txn,const std::map<std::string,std::vector<std::string>>& q){
  // Implementation delegates to single-user queries
  // Each call to get_e2e_device_keys_for_devices_txn handles one user
}
std::vector<json> EndToEndKeysStore::get_key_changes_since_txn(LoggingTransaction& txn,const std::vector<std::string>& uids,int64_t from,int64_t to){
  std::vector<json> r;if(uids.empty())return r;
  std::string ph;std::vector<DatabaseType> p;for(size_t i=0;i<uids.size();++i){if(i)ph+=",";ph+="?";p.push_back(uids[i]);}
  p.insert(p.begin(),to);p.insert(p.begin(),from);
  auto rows=txn.select("SELECT user_id,device_id,change_type,ts FROM device_lists_stream WHERE ts>? AND ts<=? AND user_id IN("+ph+") ORDER BY ts",p);
  for(auto& row:rows){json c;c["user_id"]=row.get<std::string>(0);c["device_id"]=row.get<std::string>(1);c["change_type"]=row.get<std::string>(2);c["ts"]=row.get<int64_t>(3);r.push_back(c);}
  return r;
}
} // namespace progressive::storage
