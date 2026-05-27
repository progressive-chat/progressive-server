#include "progressive/storage/databases/main/receipts.hpp"
#include <nlohmann/json.hpp>
using json=nlohmann::json;
namespace progressive::storage{namespace{int64_t rc_ts(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}}
static const char* REC_DDL=R"SQL(
CREATE TABLE IF NOT EXISTS receipts_linearized(stream_id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,room_id TEXT NOT NULL,receipt_type TEXT NOT NULL,user_id TEXT NOT NULL,event_id TEXT NOT NULL,data TEXT NOT NULL,thread_id TEXT);
CREATE INDEX IF NOT EXISTS rl_room_idx ON receipts_linearized(room_id);
CREATE INDEX IF NOT EXISTS rl_user_idx ON receipts_linearized(user_id);
CREATE TABLE IF NOT EXISTS receipts_graph(room_id TEXT NOT NULL,receipt_type TEXT NOT NULL,user_id TEXT NOT NULL,event_ids TEXT NOT NULL,data TEXT NOT NULL,CONSTRAINT rg_pk PRIMARY KEY(room_id,receipt_type,user_id));
)SQL";
void ReceiptsStore::insert_receipt_txn(LoggingTransaction& txn,const std::string& rid,const std::string& type,const std::string& uid,const std::string& eid,const json& data,const std::string& thread_id){
  int64_t ts=rc_ts();txn.execute("INSERT INTO receipts_linearized(room_id,receipt_type,user_id,event_id,data,thread_id) VALUES(?,?,?,?,?,?)",{rid,type,uid,eid,data.dump(),thread_id});
  txn.execute("INSERT OR REPLACE INTO receipts_graph(room_id,receipt_type,user_id,event_ids,data) VALUES(?,?,?,?,?)",{rid,type,uid,eid,data.dump()});
}
json ReceiptsStore::get_receipts_for_user_txn(LoggingTransaction& txn,const std::string& uid,int64_t from,int64_t to){
  json r=json::array();auto rows=txn.select("SELECT room_id,receipt_type,event_id,data,stream_id FROM receipts_linearized WHERE user_id=? AND stream_id>? AND stream_id<=? ORDER BY stream_id",{uid,from,to});
  for(auto& row:rows){json rec;rec["room_id"]=row.get<std::string>(0);rec["type"]=row.get<std::string>(1);rec["event_id"]=row.get<std::string>(2);rec["data"]=json::parse(row.get<std::string>(3));rec["stream_id"]=row.get<int64_t>(4);r.push_back(rec);}return r;
}
json ReceiptsStore::get_receipts_for_room_txn(LoggingTransaction& txn,const std::string& rid,const std::string& type){
  json r=json::object();auto rows=txn.select("SELECT user_id,event_ids,data FROM receipts_graph WHERE room_id=? AND receipt_type=?",{rid,type});
  for(auto& row:rows){json rec;rec["event_ids"]=json::parse(row.get<std::string>(1));rec["data"]=json::parse(row.get<std::string>(2));r[row.get<std::string>(0)]=rec;}return r;
}
void ReceiptsStore::delete_receipts_for_room_txn(LoggingTransaction& txn,const std::string& rid){txn.execute("DELETE FROM receipts_linearized WHERE room_id=?",{rid});txn.execute("DELETE FROM receipts_graph WHERE room_id=?",{rid});}
std::optional<std::string> ReceiptsStore::get_last_read_event_txn(LoggingTransaction& txn,const std::string& uid,const std::string& rid){
  auto r=txn.select_one("SELECT event_ids FROM receipts_graph WHERE room_id=? AND receipt_type='m.read' AND user_id=?",{rid,uid});std::string eid;if(r&&!r->is_null())eid=r->get<std::string>(0);return eid.empty()?std::nullopt:std::make_optional(eid);
}
int64_t ReceiptsStore::get_max_receipt_stream_id_txn(LoggingTransaction& txn){auto r=txn.select_one("SELECT COALESCE(MAX(stream_id),0) FROM receipts_linearized");return r?r->get<int64_t>(0):0;}
void ReceiptsStore::add_receipts_to_linearized_txn(LoggingTransaction& txn,const std::vector<std::tuple<std::string,std::string,std::string,std::string,json>>& recs){
  for(auto&[rid,type,uid,eid,data]:recs){int64_t ts=rc_ts();txn.execute("INSERT INTO receipts_linearized VALUES(NULL,?,?,?,?,?,'')",{rid,type,uid,eid,data.dump()});}
}
} // namespace
