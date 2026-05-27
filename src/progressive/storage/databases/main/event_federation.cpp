#include "progressive/storage/databases/main/event_federation.hpp"
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
namespace progressive::storage {
namespace { int64_t fm_now(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();} }

// ====== Event Federation Store (translates synapse event_federation.py 2561 lines) ======

static const char* FED_EVENTS_DDL = R"SQL(
CREATE TABLE IF NOT EXISTS federation_stream_position(type TEXT NOT NULL PRIMARY KEY, stream_id BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS event_auth_chain(event_id TEXT NOT NULL, auth_event_id TEXT NOT NULL, CONSTRAINT eac_pkey PRIMARY KEY(event_id,auth_event_id));
CREATE INDEX IF NOT EXISTS eac_auth_idx ON event_auth_chain(auth_event_id);
CREATE TABLE IF NOT EXISTS event_auth_chain_to_calculate(event_id TEXT NOT NULL PRIMARY KEY, room_id TEXT NOT NULL, type TEXT NOT NULL, state_key TEXT);
)SQL";

// Get backfill events for a room - events we need to fetch from other servers
std::vector<json> EventFederationStore::get_missing_events_txn(LoggingTransaction& txn, const std::string& room_id, const std::vector<std::string>& earliest_events, const std::vector<std::string>& latest_events, int limit) {
  std::vector<json> r;
  if(earliest_events.empty()||latest_events.empty())return r;
  std::string eph; for(size_t i=0;i<earliest_events.size();++i){if(i)eph+=",";eph+="?";}
  std::string lph; for(size_t i=0;i<latest_events.size();++i){if(i)lph+=",";lph+="?";}
  std::vector<DatabaseType> ep(earliest_events.begin(),earliest_events.end());
  auto min_so=txn.select_one("SELECT COALESCE(MIN(stream_ordering),0) FROM events WHERE event_id IN("+eph+")",ep);
  std::vector<DatabaseType> lp(latest_events.begin(),latest_events.end());
  auto max_so=txn.select_one("SELECT COALESCE(MAX(stream_ordering),0) FROM events WHERE event_id IN("+lph+")",lp);
  int64_t mn=min_so?min_so->get<int64_t>(0):0; int64_t mx=max_so?max_so->get<int64_t>(0):0;
  if(mn>=mx)return r;
  auto rows=txn.select("SELECT event_id,type,sender,stream_ordering FROM events WHERE room_id=? AND stream_ordering>? AND stream_ordering<? AND is_outlier=0 ORDER BY stream_ordering ASC LIMIT ?",{room_id,mn,mx,limit});
  for(auto& row:rows){json e;e["event_id"]=row.get<std::string>(0);e["type"]=row.get<std::string>(1);e["sender"]=row.get<std::string>(2);e["stream_ordering"]=row.get<int64_t>(3);r.push_back(e);}
  return r;
}

// Get events that have the given events as prev_events
std::vector<std::string> EventFederationStore::get_successor_events_txn(LoggingTransaction& txn, const std::vector<std::string>& event_ids) {
  std::vector<std::string> r;
  if(event_ids.empty())return r;
  std::string ph; for(size_t i=0;i<event_ids.size();++i){if(i)ph+=",";ph+="?";}
  std::vector<DatabaseType> p(event_ids.begin(),event_ids.end());
  auto rows=txn.select("SELECT DISTINCT event_id FROM event_edges WHERE prev_event_id IN("+ph+")",p);
  for(auto& row:rows)r.push_back(row.get<std::string>(0));
  return r;
}

// Get the latest event in a room (for federation catch-up)
std::optional<json> EventFederationStore::get_latest_event_in_room_txn(LoggingTransaction& txn, const std::string& room_id) {
  auto row=txn.select_one("SELECT event_id,depth,stream_ordering,origin_server_ts FROM events WHERE room_id=? AND is_outlier=0 ORDER BY stream_ordering DESC LIMIT 1",{room_id});
  if(!row||row->is_null())return std::nullopt;
  json e;e["event_id"]=row->get<std::string>(0);e["depth"]=row->get<int64_t>(1);e["stream_ordering"]=row->get<int64_t>(2);e["origin_server_ts"]=row->get<int64_t>(3);return e;
}

// Get the auth chain for a set of events (BFS)
std::vector<std::string> EventFederationStore::get_auth_chain_txn(LoggingTransaction& txn, const std::vector<std::string>& event_ids, bool include_given) {
  std::vector<std::string> r; std::set<std::string> seen; std::vector<std::string> stack=event_ids;
  if(include_given){for(auto& e:event_ids){seen.insert(e);r.push_back(e);}}
  while(!stack.empty()){
    auto batch=std::vector<std::string>(stack.end()-std::min(100,(int)stack.size()),stack.end()); stack.resize(stack.size()-batch.size());
    std::string ph; std::vector<DatabaseType> p; for(size_t i=0;i<batch.size();++i){if(i)ph+=",";ph+="?";p.push_back(batch[i]);}
    auto rows=txn.select("SELECT auth_event_id FROM event_auth_chain WHERE event_id IN("+ph+")",p);
    for(auto& row:rows){std::string ae=row.get<std::string>(0); if(seen.insert(ae).second){r.push_back(ae);stack.push_back(ae);}}
  }
  return r;
}

// Get the difference between two state sets' auth chains
std::vector<std::string> EventFederationStore::get_auth_chain_difference_txn(LoggingTransaction& txn, const std::vector<std::string>& s1, const std::vector<std::string>& s2) {
  auto c1=get_auth_chain_txn(txn,s1,true); auto c2=get_auth_chain_txn(txn,s2,true);
  std::set<std::string> set2(c2.begin(),c2.end()); std::vector<std::string> r;
  for(auto& e:c1)if(!set2.count(e))r.push_back(e);
  for(auto& e:c2){std::set<std::string> set1(c1.begin(),c1.end()); if(!set1.count(e))r.push_back(e);}
  return r;
}

// Store auth chain for an event
void EventFederationStore::store_auth_chain_for_event_txn(LoggingTransaction& txn, const std::string& event_id, const std::vector<std::string>& auth_event_ids) {
  for(auto& ae:auth_event_ids)txn.execute("INSERT OR IGNORE INTO event_auth_chain(event_id,auth_event_id) VALUES(?,?)",{event_id,ae});
}

// Get backfill points for a room
std::vector<std::string> EventFederationStore::get_backfill_points_in_room_txn(LoggingTransaction& txn, const std::string& room_id, int limit) {
  std::vector<std::string> r; auto rows=txn.select("SELECT event_id FROM event_backward_extremities WHERE room_id=? LIMIT ?",{room_id,limit});
  for(auto& row:rows)r.push_back(row.get<std::string>(0)); return r;
}

// Delete backfill point after successful federation fetch
void EventFederationStore::delete_backfill_point_txn(LoggingTransaction& txn, const std::string& event_id) {
  txn.execute("DELETE FROM event_backward_extremities WHERE event_id=?",{event_id});
}

// Add backfill point
void EventFederationStore::add_backfill_point_txn(LoggingTransaction& txn, const std::string& event_id, const std::string& room_id) {
  txn.execute("INSERT OR IGNORE INTO event_backward_extremities(event_id,room_id) VALUES(?,?)",{event_id,room_id});
}

// Get all rooms that need backfill
std::vector<std::string> EventFederationStore::get_rooms_with_backfill_txn(LoggingTransaction& txn) {
  std::vector<std::string> r; auto rows=txn.select("SELECT DISTINCT room_id FROM event_backward_extremities");
  for(auto& row:rows)r.push_back(row.get<std::string>(0)); return r;
}

// Get the state at an event (by walking auth chain)
json EventFederationStore::get_state_at_event_txn(LoggingTransaction& txn, const std::string& event_id) {
  json state=json::object();
  auto sg=txn.select_one("SELECT state_group FROM event_to_state_groups WHERE event_id=?",{event_id});
  if(!sg||sg->is_null())return state;
  auto rows=txn.select("SELECT type,state_key,event_id FROM state_groups_state WHERE state_group=?",{sg->get<int64_t>(0)});
  for(auto& row:rows){std::string t=row.get<std::string>(0);std::string sk=row.get<std::string>(1);std::string eid=row.get<std::string>(2);if(!state.contains(t))state[t]=json::object();state[t][sk]=eid;}
  return state;
}

// Get the state at an event for federation make_join
json EventFederationStore::get_state_for_federation_join_txn(LoggingTransaction& txn, const std::string& room_id, const std::string& user_id) {
  json state=json::object();
  auto rows=txn.select("SELECT type,state_key,event_id FROM current_state_events WHERE room_id=?",{room_id});
  for(auto& row:rows){std::string t=row.get<std::string>(0);std::string sk=row.get<std::string>(1);std::string eid=row.get<std::string>(2);
    auto ev=txn.select_one("SELECT content,origin_server_ts,sender FROM event_json JOIN events ON event_json.event_id=events.event_id WHERE event_json.event_id=?",{eid});
    json se;se["event_id"]=eid;se["type"]=t;se["state_key"]=sk;se["sender"]=ev&&!ev->is_null()?ev->get<std::string>(2):"";se["content"]=ev&&!ev->is_null()?json::parse(ev->get<std::string>(0)):json::object();if(!state.contains(t))state[t]=json::object();state[t][sk]=se;}
  return state;
}

// Append event to auth chain calculation queue
void EventFederationStore::queue_auth_chain_calculation_txn(LoggingTransaction& txn, const std::string& event_id, const std::string& room_id, const std::string& type, const std::string& state_key) {
  txn.execute("INSERT OR IGNORE INTO event_auth_chain_to_calculate(event_id,room_id,type,state_key) VALUES(?,?,?,?)",{event_id,room_id,type,state_key});
}

// Get events that need auth chain calculation
std::vector<json> EventFederationStore::get_auth_chain_calculation_queue_txn(LoggingTransaction& txn, int batch_size) {
  std::vector<json> r; auto rows=txn.select("SELECT event_id,room_id,type,state_key FROM event_auth_chain_to_calculate LIMIT ?",{batch_size});
  for(auto& row:rows){json e;e["event_id"]=row.get<std::string>(0);e["room_id"]=row.get<std::string>(1);e["type"]=row.get<std::string>(2);if(!row.is_null(3))e["state_key"]=row.get<std::string>(3);r.push_back(e);}
  return r;
}

// Remove from calculation queue after processing
void EventFederationStore::dequeue_auth_chain_calculation_txn(LoggingTransaction& txn, const std::string& event_id) {
  txn.execute("DELETE FROM event_auth_chain_to_calculate WHERE event_id=?",{event_id});
}

// Federation stream position tracking
void EventFederationStore::update_federation_stream_position_txn(LoggingTransaction& txn, const std::string& type, int64_t stream_id) {
  txn.execute("INSERT INTO federation_stream_position(type,stream_id) VALUES(?,?) ON CONFLICT(type) DO UPDATE SET stream_id=excluded.stream_id",{type,stream_id});
}

int64_t EventFederationStore::get_federation_stream_position_txn(LoggingTransaction& txn, const std::string& type) {
  auto row=txn.select_one("SELECT stream_id FROM federation_stream_position WHERE type=?",{type}); return row?row->get<int64_t>(0):0;
}

// Get all federation stream positions
json EventFederationStore::get_all_federation_stream_positions_txn(LoggingTransaction& txn) {
  json pos=json::object(); auto rows=txn.select("SELECT type,stream_id FROM federation_stream_position");
  for(auto& row:rows)pos[row.get<std::string>(0)]=row.get<int64_t>(1); return pos;
}

// Check if a room has full auth chain indexed
bool EventFederationStore::has_auth_chain_index_txn(LoggingTransaction& txn, const std::string& room_id) {
  auto row=txn.select_one("SELECT has_auth_chain_index FROM rooms WHERE room_id=?",{room_id});
  return row&&!row->is_null()&&row->get<int64_t>(0)!=0;
}

// Mark room as having full auth chain
void EventFederationStore::mark_auth_chain_indexed_txn(LoggingTransaction& txn, const std::string& room_id) {
  txn.execute("UPDATE rooms SET has_auth_chain_index=1 WHERE room_id=?",{room_id});
}

// Get events that reference a given auth event
std::vector<std::string> EventFederationStore::get_events_referencing_auth_txn(LoggingTransaction& txn, const std::string& auth_event_id) {
  std::vector<std::string> r; auto rows=txn.select("SELECT event_id FROM event_auth_chain WHERE auth_event_id=?",{auth_event_id});
  for(auto& row:rows)r.push_back(row.get<std::string>(0)); return r;
}

} // namespace progressive::storage
