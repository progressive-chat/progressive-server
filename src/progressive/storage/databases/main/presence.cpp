#include "progressive/storage/databases/main/presence.hpp"
#include <nlohmann/json.hpp>
using json=nlohmann::json;
namespace progressive::storage{namespace{int64_t pr_ts(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}}
static const char* PRES_DDL=R"SQL(
CREATE TABLE IF NOT EXISTS presence_stream(stream_id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,user_id TEXT NOT NULL,state TEXT NOT NULL,status_msg TEXT,last_active_ts BIGINT,last_federation_update_ts BIGINT,last_user_sync_ts BIGINT,currently_active BOOLEAN DEFAULT 0);
CREATE INDEX IF NOT EXISTS presence_user_idx ON presence_stream(user_id);
CREATE TABLE IF NOT EXISTS presence_list(user_id TEXT NOT NULL,observed_user_id TEXT NOT NULL,accepted BOOLEAN NOT NULL DEFAULT 0,CONSTRAINT pl_pk PRIMARY KEY(user_id,observed_user_id));
CREATE TABLE IF NOT EXISTS presence_allow_inbound(user_id TEXT NOT NULL,observer_user_id TEXT NOT NULL,CONSTRAINT pai_pk PRIMARY KEY(user_id,observer_user_id));
)SQL";
void PresenceStore::update_presence_txn(LoggingTransaction& txn,const std::string& uid,const std::string& state,const std::string& msg,bool active){
  int64_t ts=pr_ts();txn.execute("INSERT INTO presence_stream(user_id,state,status_msg,last_active_ts,last_user_sync_ts,currently_active) VALUES(?,?,?,?,?,?)",{uid,state,msg,ts,ts,active?1:0});
}
std::vector<json> PresenceStore::get_presence_for_users_txn(LoggingTransaction& txn,const std::vector<std::string>& uids){
  std::vector<json> r;if(uids.empty())return r;
  std::string ph;std::vector<DatabaseType> p;for(size_t i=0;i<uids.size();++i){if(i)ph+=",";ph+="?";p.push_back(uids[i]);}
  auto rows=txn.select("SELECT user_id,state,status_msg,last_active_ts,currently_active FROM presence_stream WHERE user_id IN("+ph+") ORDER BY stream_id DESC",p);
  std::map<std::string,json> seen;for(auto& row:rows){std::string u=row.get<std::string>(0);if(!seen.count(u)){json pr;pr["user_id"]=u;pr["presence"]=row.get<std::string>(1);if(!row.is_null(2))pr["status_msg"]=row.get<std::string>(2);pr["last_active_ago"]=pr_ts()-row.get<int64_t>(3);pr["currently_active"]=row.get<int64_t>(4)!=0;seen[u]=pr;}}
  for(auto& uid:uids)if(seen.count(uid))r.push_back(seen[uid]);return r;
}
std::optional<json> PresenceStore::get_presence_txn(LoggingTransaction& txn,const std::string& uid){
  auto row=txn.select_one("SELECT state,status_msg,last_active_ts,currently_active FROM presence_stream WHERE user_id=? ORDER BY stream_id DESC LIMIT 1",{uid});
  if(row&&!row->is_null()){json p;p["presence"]=row->get<std::string>(0);if(!row.is_null(1))p["status_msg"]=row->get<std::string>(1);p["last_active_ago"]=pr_ts()-row->get<int64_t>(2);p["currently_active"]=row->get<int64_t>(3)!=0;return p;}return std::nullopt;
}
void PresenceStore::add_presence_list_pending_txn(LoggingTransaction& txn,const std::string& uid,const std::string& obs){txn.execute("INSERT OR IGNORE INTO presence_list VALUES(?,?,0)",{uid,obs});}
void PresenceStore::set_presence_list_accepted_txn(LoggingTransaction& txn,const std::string& uid,const std::string& obs){txn.execute("UPDATE presence_list SET accepted=1 WHERE user_id=? AND observed_user_id=?",{uid,obs});}
void PresenceStore::remove_presence_list_txn(LoggingTransaction& txn,const std::string& uid,const std::string& obs){txn.execute("DELETE FROM presence_list WHERE user_id=? AND observed_user_id=?",{uid,obs});}
std::vector<std::string> PresenceStore::get_presence_list_observers_txn(LoggingTransaction& txn,const std::string& uid){std::vector<std::string> r;auto rows=txn.select("SELECT user_id FROM presence_list WHERE observed_user_id=? AND accepted=1",{uid});for(auto& row:rows)r.push_back(row.get<std::string>(0));return r;}
std::vector<std::string> PresenceStore::get_presence_list_subscribed_txn(LoggingTransaction& txn,const std::string& uid){std::vector<std::string> r;auto rows=txn.select("SELECT observed_user_id FROM presence_list WHERE user_id=? AND accepted=1",{uid});for(auto& row:rows)r.push_back(row.get<std::string>(0));return r;}
void PresenceStore::clear_stale_presence_txn(LoggingTransaction& txn,int64_t max_age_ms){txn.execute("DELETE FROM presence_stream WHERE last_active_ts<?",{pr_ts()-max_age_ms});}
} // namespace progressive::storage
