#include "progressive/storage/databases/main/media_repository.hpp"
#include <nlohmann/json.hpp>
using json=nlohmann::json;
namespace progressive::storage{namespace{int64_t mr_ts(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}}
static const char* MEDIA_DDL=R"SQL(
CREATE TABLE IF NOT EXISTS local_media_repository(media_id TEXT NOT NULL PRIMARY KEY,media_type TEXT NOT NULL,media_length BIGINT NOT NULL,created_ts BIGINT NOT NULL,upload_name TEXT,user_id TEXT NOT NULL,quarantined_by TEXT,safe_from_quarantine BOOLEAN DEFAULT 0,last_access_ts BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS lmr_user_idx ON local_media_repository(user_id);
CREATE TABLE IF NOT EXISTS remote_media_cache(media_origin TEXT NOT NULL,media_id TEXT NOT NULL,media_type TEXT NOT NULL,media_length BIGINT NOT NULL,filesystem_id TEXT NOT NULL,created_ts BIGINT NOT NULL,upload_name TEXT,last_access_ts BIGINT NOT NULL,etag TEXT,CONSTRAINT rmc_pk PRIMARY KEY(media_origin,media_id));
CREATE INDEX IF NOT EXISTS rmc_last_access_idx ON remote_media_cache(last_access_ts);
CREATE TABLE IF NOT EXISTS local_media_repository_thumbnails(media_id TEXT NOT NULL,thumbnail_width INTEGER NOT NULL,thumbnail_height INTEGER NOT NULL,thumbnail_type TEXT NOT NULL,thumbnail_method TEXT NOT NULL,thumbnail_length BIGINT NOT NULL,CONSTRAINT lmrt_pk PRIMARY KEY(media_id,thumbnail_width,thumbnail_height,thumbnail_type,thumbnail_method));
CREATE TABLE IF NOT EXISTS remote_media_cache_thumbnails(media_origin TEXT NOT NULL,media_id TEXT NOT NULL,thumbnail_width INTEGER NOT NULL,thumbnail_height INTEGER NOT NULL,thumbnail_type TEXT NOT NULL,thumbnail_method TEXT NOT NULL,thumbnail_length BIGINT NOT NULL,filesystem_id TEXT NOT NULL,CONSTRAINT rmct_pk PRIMARY KEY(media_origin,media_id,thumbnail_width,thumbnail_height,thumbnail_type,thumbnail_method));
)SQL";
void MediaRepositoryStore::store_local_media_txn(LoggingTransaction& txn,const std::string& mid,const std::string& uid,int64_t length,const std::string& type,const std::string& name){
  int64_t ts=mr_ts();txn.execute("INSERT INTO local_media_repository(media_id,media_type,media_length,created_ts,upload_name,user_id,last_access_ts) VALUES(?,?,?,?,?,?,?)",{mid,type,length,ts,name,uid,ts});
}
std::optional<json> MediaRepositoryStore::get_local_media_txn(LoggingTransaction& txn,const std::string& mid){
  auto r=txn.select_one("SELECT media_type,media_length,created_ts,upload_name,user_id,last_access_ts,quarantined_by FROM local_media_repository WHERE media_id=?",{mid});
  if(r&&!r->is_null()){json m;m["media_type"]=r->get<std::string>(0);m["media_length"]=r->get<int64_t>(1);m["created_ts"]=r->get<int64_t>(2);if(!r.is_null(3))m["upload_name"]=r->get<std::string>(3);m["user_id"]=r->get<std::string>(4);m["last_access_ts"]=r->get<int64_t>(5);if(!r.is_null(6))m["quarantined_by"]=r->get<std::string>(6);return m;}return std::nullopt;
}
void MediaRepositoryStore::store_remote_media_txn(LoggingTransaction& txn,const std::string& origin,const std::string& mid,const std::string& fid,int64_t length,const std::string& type,const std::string& name){
  int64_t ts=mr_ts();txn.execute("INSERT INTO remote_media_cache VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(media_origin,media_id) DO UPDATE SET media_type=excluded.media_type,media_length=excluded.media_length,filesystem_id=excluded.filesystem_id,last_access_ts=excluded.last_access_ts",{origin,mid,type,length,fid,ts,name,ts,""});
}
void MediaRepositoryStore::store_local_thumbnail_txn(LoggingTransaction& txn,const std::string& mid,int w,int h,const std::string& type,const std::string& method,int64_t length){
  txn.execute("INSERT INTO local_media_repository_thumbnails VALUES(?,?,?,?,?,?) ON CONFLICT(media_id,thumbnail_width,thumbnail_height,thumbnail_type,thumbnail_method) DO UPDATE SET thumbnail_length=excluded.thumbnail_length",{mid,w,h,type,method,length});
}
void MediaRepositoryStore::quarantine_media_txn(LoggingTransaction& txn,const std::string& mid,const std::string& by){txn.execute("UPDATE local_media_repository SET quarantined_by=? WHERE media_id=?",{by,mid});}
void MediaRepositoryStore::quarantine_media_by_user_txn(LoggingTransaction& txn,const std::string& uid){txn.execute("UPDATE local_media_repository SET quarantined_by='admin' WHERE user_id=?",{uid});}
void MediaRepositoryStore::delete_local_media_txn(LoggingTransaction& txn,const std::string& mid){txn.execute("DELETE FROM local_media_repository WHERE media_id=?",{mid});txn.execute("DELETE FROM local_media_repository_thumbnails WHERE media_id=?",{mid});}
void MediaRepositoryStore::delete_remote_media_txn(LoggingTransaction& txn,const std::string& origin,const std::string& mid){txn.execute("DELETE FROM remote_media_cache WHERE media_origin=? AND media_id=?",{origin,mid});}
int64_t MediaRepositoryStore::get_local_media_size_txn(LoggingTransaction& txn){auto r=txn.select_one("SELECT COALESCE(SUM(media_length),0) FROM local_media_repository");return r?r->get<int64_t>(0):0;}
int64_t MediaRepositoryStore::get_remote_media_size_txn(LoggingTransaction& txn){auto r=txn.select_one("SELECT COALESCE(SUM(media_length),0) FROM remote_media_cache");return r?r->get<int64_t>(0):0;}
void MediaRepositoryStore::update_cached_last_access_txn(LoggingTransaction& txn,const std::string& origin,const std::string& mid){txn.execute("UPDATE remote_media_cache SET last_access_ts=? WHERE media_origin=? AND media_id=?",{mr_ts(),origin,mid});}
std::vector<json> MediaRepositoryStore::get_expired_remote_media_txn(LoggingTransaction& txn,int64_t expiry_ms,int lim){
  std::vector<json> r;int64_t cutoff=mr_ts()-expiry_ms;auto rows=txn.select("SELECT media_origin,media_id,media_length FROM remote_media_cache WHERE last_access_ts<? ORDER BY last_access_ts LIMIT ?",{cutoff,lim});
  for(auto& row:rows){json m;m["media_origin"]=row.get<std::string>(0);m["media_id"]=row.get<std::string>(1);m["media_length"]=row.get<int64_t>(2);r.push_back(m);}return r;
}
} // namespace
