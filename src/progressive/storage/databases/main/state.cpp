#include "progressive/storage/databases/main/state.hpp"
#include <nlohmann/json.hpp>
using json=nlohmann::json;
namespace progressive::storage{
static const char* STATE_DDL=R"SQL(
CREATE TABLE IF NOT EXISTS state_groups(id BIGINT NOT NULL PRIMARY KEY,room_id TEXT NOT NULL,event_id TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS state_groups_room_idx ON state_groups(room_id);
CREATE TABLE IF NOT EXISTS state_group_edges(state_group BIGINT NOT NULL,prev_state_group BIGINT NOT NULL,CONSTRAINT sge_pk PRIMARY KEY(state_group,prev_state_group));
CREATE TABLE IF NOT EXISTS state_groups_state(state_group BIGINT NOT NULL,room_id TEXT NOT NULL,type TEXT NOT NULL,state_key TEXT NOT NULL,event_id TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS sgs_sg_idx ON state_groups_state(state_group);
CREATE INDEX IF NOT EXISTS sgs_room_type_idx ON state_groups_state(room_id,type,state_key);
CREATE TABLE IF NOT EXISTS event_to_state_groups(event_id TEXT NOT NULL PRIMARY KEY,state_group BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS etsg_sg_idx ON event_to_state_groups(state_group);
CREATE TABLE IF NOT EXISTS current_state_events(event_id TEXT NOT NULL,room_id TEXT NOT NULL,type TEXT NOT NULL,state_key TEXT NOT NULL,CONSTRAINT cse_pk PRIMARY KEY(room_id,type,state_key));
CREATE TABLE IF NOT EXISTS state_events(event_id TEXT NOT NULL,room_id TEXT NOT NULL,type TEXT NOT NULL,state_key TEXT NOT NULL,prev_state TEXT);
CREATE TABLE IF NOT EXISTS ex_outlier_stream(event_stream_ordering BIGINT NOT NULL,event_id TEXT NOT NULL,state_group BIGINT NOT NULL,instance_name TEXT NOT NULL);
)SQL";

int64_t StateStore::create_state_group_txn(LoggingTransaction& txn,const std::string& rid,const std::string& eid,int64_t(*next_id)(LoggingTransaction&,int64_t)){
  auto ex=txn.select_one("SELECT id FROM state_groups WHERE event_id=?",{eid});if(ex&&!ex->is_null())return ex->get<int64_t>(0);
  int64_t sg=next_id(txn,1);txn.execute("INSERT INTO state_groups(id,room_id,event_id) VALUES(?,?,?)",{sg,rid,eid});return sg;
}
int64_t StateStore::get_state_group_for_event_txn(LoggingTransaction& txn,const std::string& eid){auto r=txn.select_one("SELECT state_group FROM event_to_state_groups WHERE event_id=?",{eid});return r&&!r->is_null()?r->get<int64_t>(0):-1;}
void StateStore::set_state_group_for_event_txn(LoggingTransaction& txn,const std::string& eid,int64_t sg){txn.execute("INSERT OR IGNORE INTO event_to_state_groups VALUES(?,?)",{eid,sg});}
json StateStore::get_state_for_group_txn(LoggingTransaction& txn,int64_t sg,const std::string& rid){
  json s=json::object();auto rows=txn.select("SELECT type,state_key,event_id FROM state_groups_state WHERE state_group=?",{sg});
  for(auto& row:rows){std::string t=row.get<std::string>(0);std::string sk=row.get<std::string>(1);std::string eid=row.get<std::string>(2);if(!s.contains(t))s[t]=json::object();s[t][sk]=eid;}return s;
}
void StateStore::set_state_group_state_txn(LoggingTransaction& txn,int64_t sg,const std::string& rid,const std::string& type,const std::string& sk,const std::string& eid){
  txn.execute("INSERT INTO state_groups_state(state_group,room_id,type,state_key,event_id) VALUES(?,?,?,?,?)",{sg,rid,type,sk,eid});
}
void StateStore::add_state_group_edge_txn(LoggingTransaction& txn,int64_t sg,int64_t psg){txn.execute("INSERT OR IGNORE INTO state_group_edges VALUES(?,?)",{sg,psg});}
json StateStore::get_current_state_txn(LoggingTransaction& txn,const std::string& rid){
  json s=json::object();auto rows=txn.select("SELECT type,state_key,event_id FROM current_state_events WHERE room_id=?",{rid});
  for(auto& row:rows){std::string t=row.get<std::string>(0);std::string sk=row.get<std::string>(1);if(!s.contains(t))s[t]=json::object();s[t][sk]=row.get<std::string>(2);}return s;
}
std::optional<std::string> StateStore::get_current_state_event_txn(LoggingTransaction& txn,const std::string& rid,const std::string& type,const std::string& sk){
  auto r=txn.select_one("SELECT event_id FROM current_state_events WHERE room_id=? AND type=? AND state_key=?",{rid,type,sk});if(r&&!r->is_null())return r->get<std::string>(0);return std::nullopt;
}
void StateStore::update_current_state_txn(LoggingTransaction& txn,const std::string& eid,const std::string& rid,const std::string& type,const std::string& sk){
  txn.execute("INSERT INTO current_state_events VALUES(?,?,?,?) ON CONFLICT(room_id,type,state_key) DO UPDATE SET event_id=excluded.event_id",{eid,rid,type,sk});
}
void StateStore::delete_current_state_entry_txn(LoggingTransaction& txn,const std::string& rid,const std::string& type,const std::string& sk){
  txn.execute("DELETE FROM current_state_events WHERE room_id=? AND type=? AND state_key=?",{rid,type,sk});
}
void StateStore::delete_all_current_state_for_room_txn(LoggingTransaction& txn,const std::string& rid){txn.execute("DELETE FROM current_state_events WHERE room_id=?",{rid});}
std::vector<int64_t> StateStore::get_prev_state_groups_txn(LoggingTransaction& txn,int64_t sg){std::vector<int64_t> r;auto rows=txn.select("SELECT prev_state_group FROM state_group_edges WHERE state_group=?",{sg});for(auto& row:rows)r.push_back(row.get<int64_t>(0));return r;}
json StateStore::resolve_state_groups_txn(LoggingTransaction& txn,const std::vector<int64_t>& groups){
  // Walk state groups to find the unified state
  json state=json::object();std::set<int64_t> visited;std::vector<int64_t> stack=groups;
  while(!stack.empty()){int64_t sg=stack.back();stack.pop_back();if(visited.count(sg))continue;visited.insert(sg);
    auto rows=txn.select("SELECT type,state_key,event_id FROM state_groups_state WHERE state_group=?",{sg});
    for(auto& row:rows){std::string t=row.get<std::string>(0);std::string sk=row.get<std::string>(1);if(!state.contains(t))state[t]=json::object();if(!state[t].contains(sk))state[t][sk]=row.get<std::string>(2);}
    auto prevs=txn.select("SELECT prev_state_group FROM state_group_edges WHERE state_group=?",{sg});for(auto& row:prevs)stack.push_back(row.get<int64_t>(0));
  }return state;
}
} // namespace progressive::storage
