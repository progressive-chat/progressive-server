#include "progressive/storage/databases/main/roommember.hpp"
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
namespace { int64_t rm_ts(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());} }

void RoomMemberStore::upsert_member_txn(LoggingTransaction& txn,const std::string& eid,const std::string& uid,const std::string& sender,const std::string& rid,const std::string& mem,const std::string& dn,const std::string& av){
  txn.execute("INSERT INTO room_memberships(event_id,user_id,sender,room_id,membership,display_name,avatar_url) VALUES(?,?,?,?,?,?,?) ON CONFLICT(event_id) DO UPDATE SET membership=excluded.membership,display_name=COALESCE(excluded.display_name,room_memberships.display_name),avatar_url=COALESCE(excluded.avatar_url,room_memberships.avatar_url)",{eid,uid,sender,rid,mem,dn,av});
  if(mem=="join")txn.execute("INSERT INTO local_current_membership VALUES(?,?,?,?) ON CONFLICT(user_id,room_id) DO UPDATE SET event_id=excluded.event_id,membership=excluded.membership",{rid,uid,eid,mem});
  else if(mem=="leave"||mem=="ban")txn.execute("DELETE FROM local_current_membership WHERE user_id=? AND room_id=?",{uid,rid});
  else txn.execute("INSERT OR REPLACE INTO local_current_membership VALUES(?,?,?,?)",{rid,uid,eid,mem});
}
std::vector<json> RoomMemberStore::get_members_txn(LoggingTransaction& txn,const std::string& rid,const std::optional<std::string>& mf,int lim,int off){
  std::vector<json> r;std::string q="SELECT user_id,sender,display_name,avatar_url,membership,event_id FROM room_memberships WHERE room_id=?";std::vector<DatabaseType> p={rid};
  if(mf){q+=" AND membership=?";p.push_back(*mf);}q+=" ORDER BY user_id LIMIT ? OFFSET ?";p.push_back(lim);p.push_back(off);
  auto rows=txn.select(q,p);for(auto& row:rows){json m;m["user_id"]=row.get<std::string>(0);m["sender"]=row.get<std::string>(1);if(!row.is_null(2))m["display_name"]=row.get<std::string>(2);if(!row.is_null(3))m["avatar_url"]=row.get<std::string>(3);m["membership"]=row.get<std::string>(4);m["event_id"]=row.get<std::string>(5);r.push_back(m);}return r;
}
std::vector<std::string> RoomMemberStore::get_rooms_for_user_txn(LoggingTransaction& txn,const std::string& uid,const std::optional<std::string>& mf){
  std::vector<std::string> r;std::string q="SELECT room_id FROM local_current_membership WHERE user_id=?";std::vector<DatabaseType> p={uid};if(mf){q+=" AND membership=?";p.push_back(*mf);}
  auto rows=txn.select(q,p);for(auto& row:rows)r.push_back(row.get<std::string>(0));return r;
}
std::string RoomMemberStore::get_membership_txn(LoggingTransaction& txn,const std::string& uid,const std::string& rid){
  auto row=txn.select_one("SELECT membership FROM local_current_membership WHERE user_id=? AND room_id=?",{uid,rid});return row&&!row->is_null()?row->get<std::string>(0):"";
}
bool RoomMemberStore::is_in_room_txn(LoggingTransaction& txn,const std::string& uid,const std::string& rid){auto row=txn.select_one("SELECT 1 FROM local_current_membership WHERE user_id=? AND room_id=? AND membership='join'",{uid,rid});return row&&!row->is_null();}
int64_t RoomMemberStore::count_joined_txn(LoggingTransaction& txn,const std::string& rid){auto row=txn.select_one("SELECT COUNT(*) FROM local_current_membership WHERE room_id=? AND membership='join'",{rid});return row?row->get<int64_t>(0):0;}
std::vector<std::string> RoomMemberStore::get_joined_users_txn(LoggingTransaction& txn,const std::string& rid){std::vector<std::string> r;auto rows=txn.select("SELECT user_id FROM local_current_membership WHERE room_id=? AND membership='join'",{rid});for(auto& row:rows)r.push_back(row.get<std::string>(0));return r;}
std::vector<std::string> RoomMemberStore::get_joined_hosts_txn(LoggingTransaction& txn,const std::string& rid){
  std::set<std::string> h;auto rows=txn.select("SELECT user_id FROM local_current_membership WHERE room_id=? AND membership='join'",{rid});
  for(auto& row:rows){std::string u=row.get<std::string>(0);auto c=u.find(':');if(c!=std::string::npos)h.insert(u.substr(c+1));}return std::vector<std::string>(h.begin(),h.end());
}
void RoomMemberStore::forget_txn(LoggingTransaction& txn,const std::string& uid,const std::string& rid){txn.execute("UPDATE room_memberships SET forgotten=1 WHERE user_id=? AND room_id=?",{uid,rid});txn.execute("DELETE FROM local_current_membership WHERE user_id=? AND room_id=?",{uid,rid});}
std::vector<json> RoomMemberStore::get_membership_history_txn(LoggingTransaction& txn,const std::string& uid,int lim){std::vector<json> r;auto rows=txn.select("SELECT event_id,room_id,membership,sender FROM room_memberships WHERE user_id=? ORDER BY event_id DESC LIMIT ?",{uid,lim});for(auto& row:rows){json m;m["event_id"]=row.get<std::string>(0);m["room_id"]=row.get<std::string>(1);m["membership"]=row.get<std::string>(2);m["sender"]=row.get<std::string>(3);r.push_back(m);}return r;}
std::optional<json> RoomMemberStore::get_member_info_txn(LoggingTransaction& txn,const std::string& uid,const std::string& rid){auto row=txn.select_one("SELECT membership,event_id,display_name,avatar_url FROM room_memberships WHERE user_id=? AND room_id=? ORDER BY event_id DESC LIMIT 1",{uid,rid});if(row&&!row->is_null()){json i;i["membership"]=row->get<std::string>(0);i["event_id"]=row.get<std::string>(1);if(!row.is_null(2))i["display_name"]=row.get<std::string>(2);if(!row.is_null(3))i["avatar_url"]=row.get<std::string>(3);return i;}return std::nullopt;}
std::vector<std::string> RoomMemberStore::get_shared_rooms_txn(LoggingTransaction& txn,const std::string& u1,const std::string& u2){std::vector<std::string> r;auto rows=txn.select("SELECT a.room_id FROM local_current_membership a JOIN local_current_membership b ON a.room_id=b.room_id WHERE a.user_id=? AND b.user_id=? AND a.membership='join' AND b.membership='join'",{u1,u2});for(auto& row:rows)r.push_back(row.get<std::string>(0));return r;}
void RoomMemberStore::update_member_profile_txn(LoggingTransaction& txn,const std::string& uid,const std::string& rid,const std::string& dn,const std::string& av){txn.execute("UPDATE room_memberships SET display_name=COALESCE(?,display_name),avatar_url=COALESCE(?,avatar_url) WHERE user_id=? AND room_id=?",{dn,av,uid,rid});}
} // namespace progressive::storage
