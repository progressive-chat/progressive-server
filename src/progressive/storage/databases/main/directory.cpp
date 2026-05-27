#include "progressive/storage/databases/main/directory.hpp"
#include <nlohmann/json.hpp>
using json=nlohmann::json;
namespace progressive::storage{
static const char* DIR_DDL=R"SQL(
CREATE TABLE IF NOT EXISTS room_aliases(room_alias TEXT NOT NULL PRIMARY KEY,room_id TEXT NOT NULL,creator TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ra_room_idx ON room_aliases(room_id);
CREATE TABLE IF NOT EXISTS room_stats_state(room_id TEXT NOT NULL PRIMARY KEY,name TEXT,topic TEXT,canonical_alias TEXT,joined_members INTEGER DEFAULT 0,invited_members INTEGER DEFAULT 0,left_members INTEGER DEFAULT 0,banned_members INTEGER DEFAULT 0,total_members INTEGER DEFAULT 0,local_users_in_room INTEGER DEFAULT 0,history_visibility TEXT,join_rules TEXT,guest_access TEXT,encryption TEXT,room_type TEXT,is_federatable BOOLEAN DEFAULT 1);
CREATE TABLE IF NOT EXISTS public_room_list_stream(stream_id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,room_id TEXT NOT NULL,visibility TEXT NOT NULL,appservice_id TEXT,network_id TEXT);
)SQL";

void DirectoryStore::create_room_alias_txn(LoggingTransaction& txn,const std::string& alias,const std::string& rid,const std::string& creator){
  txn.execute("INSERT INTO room_aliases VALUES(?,?,?)",{alias,rid,creator});
  txn.execute("INSERT INTO public_room_list_stream(room_id,visibility) SELECT ?,CASE WHEN is_public THEN 'public' ELSE 'private' END FROM rooms WHERE room_id=?",{rid,rid});
}
void DirectoryStore::delete_room_alias_txn(LoggingTransaction& txn,const std::string& alias){txn.execute("DELETE FROM room_aliases WHERE room_alias=?",{alias});}
std::optional<std::string> DirectoryStore::get_room_id_for_alias_txn(LoggingTransaction& txn,const std::string& alias){
  auto r=txn.select_one("SELECT room_id FROM room_aliases WHERE room_alias=?",{alias});return r&&!r->is_null()?std::make_optional(r->get<std::string>(0)):std::nullopt;
}
std::vector<std::string> DirectoryStore::get_aliases_for_room_txn(LoggingTransaction& txn,const std::string& rid){
  std::vector<std::string> r;auto rows=txn.select("SELECT room_alias FROM room_aliases WHERE room_id=?",{rid});for(auto& row:rows)r.push_back(row.get<std::string>(0));return r;
}
std::string DirectoryStore::get_canonical_alias_txn(LoggingTransaction& txn,const std::string& rid){
  auto r=txn.select_one("SELECT event_id FROM current_state_events WHERE room_id=? AND type='m.room.canonical_alias' AND state_key=''",{rid});
  if(r&&!r->is_null()){auto c=txn.select_one("SELECT json FROM event_json WHERE event_id=?",{r->get<std::string>(0)});if(c&&!c->is_null()){json j=json::parse(c->get<std::string>(0));if(j.contains("alias"))return j["alias"];}}return "";
}
std::vector<json> DirectoryStore::get_public_rooms_txn(LoggingTransaction& txn,const std::string& server,int64_t since,int lim,const std::string& filter,const std::string& third_party_instance_id){
  std::vector<json> r;std::string q="SELECT r.room_id,rs.name,rs.topic,rs.canonical_alias,rs.joined_members,rs.total_members,rs.room_type,rs.is_federatable FROM rooms r LEFT JOIN room_stats_state rs ON r.room_id=rs.room_id WHERE r.is_public=1";
  std::vector<DatabaseType> p;if(!filter.empty()){q+=" AND (rs.name LIKE ? OR rs.topic LIKE ?)";p.push_back("%"+filter+"%");p.push_back("%"+filter+"%");}
  if(!third_party_instance_id.empty()){q+=" AND EXISTS(SELECT 1 FROM public_room_list_stream prls WHERE prls.room_id=r.room_id AND prls.network_id=?)";p.push_back(third_party_instance_id);}
  q+=" ORDER BY rs.joined_members DESC LIMIT ? OFFSET ?";p.push_back(lim);p.push_back(since);
  auto rows=txn.select(q,p);for(auto& row:rows){json room;room["room_id"]=row.get<std::string>(0);if(!row.is_null(1))room["name"]=row.get<std::string>(1);if(!row.is_null(2))room["topic"]=row.get<std::string>(2);if(!row.is_null(3))room["canonical_alias"]=row.get<std::string>(3);room["num_joined_members"]=row.get<int64_t>(4);room["world_readable"]=true;room["guest_can_join"]=false;if(!row.is_null(6))room["room_type"]=row.get<std::string>(6);r.push_back(room);}return r;
}
void DirectoryStore::set_room_is_public_txn(LoggingTransaction& txn,const std::string& rid,bool pub){txn.execute("UPDATE rooms SET is_public=? WHERE room_id=?",{pub?1:0,rid});txn.execute("INSERT INTO public_room_list_stream(room_id,visibility) VALUES(?,?)",{rid,pub?"public":"private"});}
bool DirectoryStore::room_is_public_txn(LoggingTransaction& txn,const std::string& rid){auto r=txn.select_one("SELECT is_public FROM rooms WHERE room_id=?",{rid});return r&&!r->is_null()&&r->get<int64_t>(0)!=0;}
std::vector<json> DirectoryStore::get_changes_in_public_rooms_txn(LoggingTransaction& txn,int64_t since,int64_t to,int lim){
  std::vector<json> r;auto rows=txn.select("SELECT stream_id,room_id,visibility FROM public_room_list_stream WHERE stream_id>? AND stream_id<=? ORDER BY stream_id LIMIT ?",{since,to,lim});
  for(auto& row:rows){json c;c["stream_id"]=row.get<int64_t>(0);c["room_id"]=row.get<std::string>(1);c["visibility"]=row.get<std::string>(2);r.push_back(c);}return r;
}
} // namespace
