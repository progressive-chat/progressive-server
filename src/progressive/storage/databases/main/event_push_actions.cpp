#include "progressive/storage/databases/main/event_push_actions.hpp"
#include <nlohmann/json.hpp>
using json=nlohmann::json;
namespace progressive::storage {
namespace{int64_t pa_ts(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());}}

static const char* PA_DDL=R"SQL(
CREATE TABLE IF NOT EXISTS event_push_actions(room_id TEXT NOT NULL,event_id TEXT NOT NULL,user_id TEXT NOT NULL,profile_tag TEXT NOT NULL,actions TEXT NOT NULL,stream_ordering BIGINT NOT NULL,topological_ordering BIGINT NOT NULL,notif SMALLINT NOT NULL,highlight SMALLINT NOT NULL,CONSTRAINT epa_pk PRIMARY KEY(room_id,event_id,user_id));
CREATE INDEX IF NOT EXISTS epa_user_stream_idx ON event_push_actions(user_id,stream_ordering);
CREATE TABLE IF NOT EXISTS event_push_actions_staging(event_id TEXT NOT NULL PRIMARY KEY,user_id TEXT NOT NULL,actions TEXT NOT NULL,notif SMALLINT,highlight SMALLINT);
CREATE TABLE IF NOT EXISTS event_push_summary(user_id TEXT NOT NULL,room_id TEXT NOT NULL,notif_count BIGINT DEFAULT 0,highlight_count BIGINT DEFAULT 0,last_event_id TEXT,last_stream_ordering BIGINT,CONSTRAINT eps_pk PRIMARY KEY(user_id,room_id));
CREATE TABLE IF NOT EXISTS event_push_summary_stream(room_id TEXT NOT NULL,user_id TEXT NOT NULL,stream_ordering BIGINT NOT NULL,notif_count BIGINT,highlight_count BIGINT);
)SQL";

void EventPushActionsStore::stage_push_actions_txn(LoggingTransaction& txn,const std::string& eid,const std::string& uid,const json& actions){
  bool n=false,h=false;if(actions.is_array())for(auto& a:actions){std::string s=a.get<std::string>();if(s=="notify")n=true;if(s.find("highlight")!=std::string::npos)h=true;}
  txn.execute("INSERT INTO event_push_actions_staging VALUES(?,?,?,?,?)",{eid,uid,actions.dump(),n?1:0,h?1:0});
}
void EventPushActionsStore::set_push_actions_txn(LoggingTransaction& txn,const std::string& eid,const std::string& uid,const json& actions,const std::string& rid,const std::string& pt,int64_t so,int64_t to){
  bool n=false,h=false;if(actions.is_array())for(auto& a:actions){std::string s=a.get<std::string>();if(s=="notify")n=true;if(s.find("highlight")!=std::string::npos)h=true;}
  txn.execute("INSERT INTO event_push_actions VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(room_id,event_id,user_id) DO UPDATE SET actions=excluded.actions,notif=excluded.notif,highlight=excluded.highlight",{rid,eid,uid,pt,actions.dump(),so,to,n?1:0,h?1:0});
  if(n||h){txn.execute("INSERT INTO event_push_summary VALUES(?,?,?,?,?,?) ON CONFLICT(user_id,room_id) DO UPDATE SET notif_count=event_push_summary.notif_count+excluded.notif_count,highlight_count=event_push_summary.highlight_count+excluded.highlight_count,last_event_id=excluded.last_event_id,last_stream_ordering=excluded.last_stream_ordering",{uid,rid,n?1:0,h?1:0,eid,so});}
}
std::vector<json> EventPushActionsStore::get_push_actions_for_user_txn(LoggingTransaction& txn,const std::string& uid,int64_t f,int64_t t,int l){
  std::vector<json> r;auto rows=txn.select("SELECT room_id,event_id,actions,stream_ordering,highlight,notif FROM event_push_actions WHERE user_id=? AND stream_ordering>? AND stream_ordering<=? ORDER BY stream_ordering ASC LIMIT ?",{uid,f,t,l});
  for(auto& row:rows){json a;a["room_id"]=row.get<std::string>(0);a["event_id"]=row.get<std::string>(1);a["actions"]=json::parse(row.get<std::string>(2));a["stream_ordering"]=row.get<int64_t>(3);a["highlight"]=row.get<int64_t>(4)!=0;a["notify"]=row.get<int64_t>(5)!=0;r.push_back(a);}return r;
}
json EventPushActionsStore::get_push_summary_txn(LoggingTransaction& txn,const std::string& uid){
  json s=json::object();auto rows=txn.select("SELECT room_id,notif_count,highlight_count,last_event_id,last_stream_ordering FROM event_push_summary WHERE user_id=?",{uid});
  for(auto& row:rows){json r;r["notification_count"]=row.get<int64_t>(1);r["highlight_count"]=row.get<int64_t>(2);if(!row.is_null(3))r["last_event_id"]=row.get<std::string>(3);if(!row.is_null(4))r["last_stream_ordering"]=row.get<int64_t>(4);s[row.get<std::string>(0)]=r;}return s;
}
void EventPushActionsStore::delete_push_actions_for_event_txn(LoggingTransaction& txn,const std::string& eid){
  auto rows=txn.select("SELECT user_id,room_id,notif,highlight FROM event_push_actions WHERE event_id=?",{eid});
  for(auto& row:rows)txn.execute("UPDATE event_push_summary SET notif_count=MAX(notif_count-?,0),highlight_count=MAX(highlight_count-?,0) WHERE user_id=? AND room_id=?",{row.get<int64_t>(2),row.get<int64_t>(3),row.get<std::string>(0),row.get<std::string>(1)});
  txn.execute("DELETE FROM event_push_actions WHERE event_id=?",{eid});
}
void EventPushActionsStore::delete_old_push_actions_txn(LoggingTransaction& txn,int64_t bs){txn.execute("DELETE FROM event_push_actions WHERE stream_ordering<?",{bs});txn.execute("DELETE FROM event_push_summary_stream WHERE stream_ordering<?",{bs});}
std::vector<std::string> EventPushActionsStore::get_users_with_pending_push_txn(LoggingTransaction& txn){std::vector<std::string> r;auto rows=txn.select("SELECT DISTINCT user_id FROM event_push_actions");for(auto& row:rows)r.push_back(row.get<std::string>(0));return r;}
} // namespace progressive::storage
