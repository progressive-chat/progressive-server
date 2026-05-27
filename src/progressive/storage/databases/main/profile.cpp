#include "progressive/storage/databases/main/profile.hpp"
#include <nlohmann/json.hpp>
using json=nlohmann::json;
namespace progressive::storage{
static const char* PROFILE_DDL=R"SQL(
CREATE TABLE IF NOT EXISTS profiles(user_id TEXT NOT NULL PRIMARY KEY,display_name TEXT,avatar_url TEXT,blob TEXT);
)SQL";
void ProfileStore::set_display_name_txn(LoggingTransaction& txn,const std::string& uid,const std::string& dn){txn.execute("INSERT INTO profiles(user_id,display_name) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET display_name=excluded.display_name",{uid,dn});}
std::optional<std::string> ProfileStore::get_display_name_txn(LoggingTransaction& txn,const std::string& uid){auto r=txn.select_one("SELECT display_name FROM profiles WHERE user_id=?",{uid});return r&&!r->is_null()&&!r->get<std::string>(0).empty()?std::make_optional(r->get<std::string>(0)):std::nullopt;}
void ProfileStore::set_avatar_url_txn(LoggingTransaction& txn,const std::string& uid,const std::string& av){txn.execute("INSERT INTO profiles(user_id,avatar_url) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET avatar_url=excluded.avatar_url",{uid,av});}
std::optional<std::string> ProfileStore::get_avatar_url_txn(LoggingTransaction& txn,const std::string& uid){auto r=txn.select_one("SELECT avatar_url FROM profiles WHERE user_id=?",{uid});return r&&!r->is_null()&&!r->get<std::string>(0).empty()?std::make_optional(r->get<std::string>(0)):std::nullopt;}
json ProfileStore::get_profile_txn(LoggingTransaction& txn,const std::string& uid){json p;auto r=txn.select_one("SELECT display_name,avatar_url FROM profiles WHERE user_id=?",{uid});if(r&&!r->is_null()){if(!r->is_null(0))p["displayname"]=r->get<std::string>(0);if(!r->is_null(1))p["avatar_url"]=r->get<std::string>(1);}return p;}
void ProfileStore::delete_profile_txn(LoggingTransaction& txn,const std::string& uid){txn.execute("DELETE FROM profiles WHERE user_id=?",{uid});}
void ProfileStore::set_profile_blob_txn(LoggingTransaction& txn,const std::string& uid,const json& blob){txn.execute("INSERT INTO profiles(user_id,blob) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET blob=excluded.blob",{uid,blob.dump()});}
json ProfileStore::get_profile_blob_txn(LoggingTransaction& txn,const std::string& uid){auto r=txn.select_one("SELECT blob FROM profiles WHERE user_id=?",{uid});return r&&!r->is_null()?json::parse(r->get<std::string>(0)):json::object();}
std::vector<json> ProfileStore::get_profiles_for_users_txn(LoggingTransaction& txn,const std::vector<std::string>& uids){
  std::vector<json> r;if(uids.empty())return r;
  std::string ph;std::vector<DatabaseType> p;for(size_t i=0;i<uids.size();++i){if(i)ph+=",";ph+="?";p.push_back(uids[i]);}
  auto rows=txn.select("SELECT user_id,display_name,avatar_url FROM profiles WHERE user_id IN("+ph+")",p);
  for(auto& row:rows){json prof;prof["user_id"]=row.get<std::string>(0);if(!row.is_null(1))prof["displayname"]=row.get<std::string>(1);if(!row.is_null(2))prof["avatar_url"]=row.get<std::string>(2);r.push_back(prof);}return r;
}
} // namespace progressive::storage
