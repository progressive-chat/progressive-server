#include "progressive/storage/databases/main/filtering.hpp"
#include <nlohmann/json.hpp>
using json=nlohmann::json;
namespace progressive::storage{
static const char* FILT_DDL=R"SQL(
CREATE TABLE IF NOT EXISTS user_filters(user_id TEXT NOT NULL,filter_id BIGINT NOT NULL,filter_json TEXT NOT NULL,CONSTRAINT uf_pk PRIMARY KEY(user_id,filter_id));
CREATE INDEX IF NOT EXISTS uf_user_id_idx ON user_filters(user_id);
)SQL";
int64_t FilteringStore::add_user_filter_txn(LoggingTransaction& txn,const std::string& uid,const json& filter){
  auto max_id=txn.select_one("SELECT COALESCE(MAX(filter_id),0)+1 FROM user_filters WHERE user_id=?",{uid});int64_t fid=max_id&&!max_id->is_null()?max_id->get<int64_t>(0):1;
  txn.execute("INSERT INTO user_filters VALUES(?,?,?)",{uid,fid,filter.dump()});return fid;
}
json FilteringStore::get_user_filter_txn(LoggingTransaction& txn,const std::string& uid,int64_t fid){
  auto r=txn.select_one("SELECT filter_json FROM user_filters WHERE user_id=? AND filter_id=?",{uid,fid});return r&&!r->is_null()?json::parse(r->get<std::string>(0)):json::object();
}
std::vector<json> FilteringStore::get_all_user_filters_txn(LoggingTransaction& txn,const std::string& uid){
  std::vector<json> r;auto rows=txn.select("SELECT filter_id,filter_json FROM user_filters WHERE user_id=?",{uid});
  for(auto& row:rows){json f=json::parse(row.get<std::string>(1));f["filter_id"]=row.get<int64_t>(0);r.push_back(f);}return r;
}
void FilteringStore::delete_user_filter_txn(LoggingTransaction& txn,const std::string& uid,int64_t fid){txn.execute("DELETE FROM user_filters WHERE user_id=? AND filter_id=?",{uid,fid});}
} // namespace
