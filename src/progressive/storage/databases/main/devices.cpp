#include "progressive/storage/databases/main/devices.hpp"
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
namespace {
int64_t nms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
std::string gid(){static int c=0;return "d"+std::to_string(nms())+"-"+std::to_string(++c);}
}

// Device DDL
static const char* DEVICES_DDL = R"SQL(
CREATE TABLE IF NOT EXISTS devices (
    user_id TEXT NOT NULL, device_id TEXT NOT NULL, display_name TEXT,
    last_seen BIGINT, ip TEXT, user_agent TEXT, hidden BOOLEAN DEFAULT 0,
    device_type TEXT, device_metadata TEXT DEFAULT '{}',
    CONSTRAINT devices_pkey PRIMARY KEY (user_id, device_id));
CREATE INDEX IF NOT EXISTS devices_user_idx ON devices (user_id);
)SQL";

// ---------- Device CRUD ----------
void DevicesStore::store_device_txn(LoggingTransaction& txn, const std::string& uid,
    const std::string& did, const std::string& dn, int64_t ls) {
    txn.execute("INSERT INTO devices VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id,device_id) DO UPDATE SET display_name=COALESCE(excluded.display_name,devices.display_name),last_seen=excluded.last_seen,ip=COALESCE(excluded.ip,devices.ip),user_agent=COALESCE(excluded.user_agent,devices.user_agent)",
        {uid,did,dn,ls,"","",0,"","{}"});
}

void DevicesStore::update_device_txn(LoggingTransaction& txn, const std::string& uid,
    const std::string& did, const json& updates) {
    std::string set; std::vector<DatabaseType> p;
    if(updates.contains("display_name")){set+="display_name=?,"; p.push_back(updates["display_name"]);}
    if(updates.contains("last_seen")){set+="last_seen=?,"; p.push_back(updates["last_seen"]);}
    if(updates.contains("hidden")){set+="hidden=?,"; p.push_back(updates["hidden"]);}
    if(set.empty())return; set.pop_back(); p.push_back(uid); p.push_back(did);
    txn.execute("UPDATE devices SET "+set+" WHERE user_id=? AND device_id=?",p);
}

void DevicesStore::delete_device_txn(LoggingTransaction& txn, const std::string& uid, const std::string& did) {
    txn.execute("DELETE FROM devices WHERE user_id=? AND device_id=?",{uid,did});
    txn.execute("DELETE FROM access_tokens WHERE user_id=? AND device_id=?",{uid,did});
    txn.execute("DELETE FROM device_inbox WHERE user_id=? AND device_id=?",{uid,did});
}

void DevicesStore::delete_all_devices_for_user_txn(LoggingTransaction& txn, const std::string& uid) {
    txn.execute("DELETE FROM devices WHERE user_id=?",{uid});
    txn.execute("DELETE FROM access_tokens WHERE user_id=?",{uid});
}

std::vector<json> DevicesStore::get_devices_by_user_txn(LoggingTransaction& txn, const std::string& uid) {
    std::vector<json> r; auto rows=txn.select("SELECT device_id,display_name,last_seen,ip,user_agent,hidden,device_type,device_metadata FROM devices WHERE user_id=? AND hidden=0",{uid});
    for(auto& row:rows){json d;d["device_id"]=row.get<std::string>(0);if(!row.is_null(1))d["display_name"]=row.get<std::string>(1);d["last_seen"]=row.get<int64_t>(2);if(!row.is_null(3))d["ip"]=row.get<std::string>(3);if(!row.is_null(4))d["user_agent"]=row.get<std::string>(4);d["hidden"]=row.get<int64_t>(5)!=0;if(!row.is_null(6))d["device_type"]=row.get<std::string>(6);r.push_back(d);}
    return r;
}

std::optional<json> DevicesStore::get_device_txn(LoggingTransaction& txn, const std::string& uid, const std::string& did) {
    auto row=txn.select_one("SELECT display_name,last_seen,ip,user_agent,hidden,device_type,device_metadata FROM devices WHERE user_id=? AND device_id=?",{uid,did});
    if(!row||row->is_null())return std::nullopt;
    json d;d["device_id"]=did;if(!row->is_null(0))d["display_name"]=row->get<std::string>(0);d["last_seen"]=row->get<int64_t>(1);if(!row->is_null(2))d["ip"]=row->get<std::string>(2);if(!row->is_null(3))d["user_agent"]=row->get<std::string>(3);d["hidden"]=row->get<int64_t>(4)!=0;if(!row->is_null(5))d["device_type"]=row->get<std::string>(5);return d;
}

int64_t DevicesStore::count_devices_for_user_txn(LoggingTransaction& txn, const std::string& uid) {
    auto row=txn.select_one("SELECT COUNT(*) FROM devices WHERE user_id=? AND hidden=0",{uid}); return row?row->get<int64_t>(0):0;
}

void DevicesStore::mark_device_hidden_txn(LoggingTransaction& txn, const std::string& uid, const std::string& did, bool hidden) {
    txn.execute("UPDATE devices SET hidden=? WHERE user_id=? AND device_id=?",{hidden?1:0,uid,did});
}

void DevicesStore::update_device_last_seen_txn(LoggingTransaction& txn, const std::string& uid, const std::string& did, const std::string& ip, const std::string& ua) {
    txn.execute("UPDATE devices SET last_seen=?,ip=?,user_agent=? WHERE user_id=? AND device_id=?",{nms(),ip,ua,uid,did});
}

std::vector<std::string> DevicesStore::get_device_ids_for_user_txn(LoggingTransaction& txn, const std::string& uid) {
    std::vector<std::string> r; auto rows=txn.select("SELECT device_id FROM devices WHERE user_id=?",{uid});
    for(auto& row:rows)r.push_back(row.get<std::string>(0)); return r;
}

bool DevicesStore::device_exists_txn(LoggingTransaction& txn, const std::string& uid, const std::string& did) {
    auto row=txn.select_one("SELECT 1 FROM devices WHERE user_id=? AND device_id=?",{uid,did}); return row&&!row->is_null();
}

// ---------- Device list changed tracking ----------
void DevicesStore::mark_device_list_as_changed_txn(LoggingTransaction& txn, const std::string& uid) {
    txn.execute("INSERT INTO device_lists_changed (user_id,changed_at) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET changed_at=excluded.changed_at",{uid,nms()});
}

std::vector<std::string> DevicesStore::get_users_whose_devices_changed_txn(LoggingTransaction& txn, int64_t from_ts) {
    std::vector<std::string> r; auto rows=txn.select("SELECT user_id FROM device_lists_changed WHERE changed_at>?",{from_ts});
    for(auto& row:rows)r.push_back(row.get<std::string>(0)); return r;
}

void DevicesStore::update_device_metadata_txn(LoggingTransaction& txn, const std::string& uid, const std::string& did, const json& meta) {
    txn.execute("UPDATE devices SET device_metadata=? WHERE user_id=? AND device_id=?",{meta.dump(),uid,did});
}

std::vector<json> DevicesStore::get_all_user_devices_changed_txn(LoggingTransaction& txn, const std::string& uid) {
    std::vector<json> r; auto rows=txn.select("SELECT device_id,display_name,last_seen FROM devices WHERE user_id=?",{uid});
    for(auto& row:rows){json d;d["device_id"]=row.get<std::string>(0);if(!row.is_null(1))d["display_name"]=row.get<std::string>(1);d["last_seen"]=row.get<int64_t>(2);r.push_back(d);} return r;
}

void DevicesStore::update_remote_device_list_cache_txn(LoggingTransaction& txn, const std::string& uid, const std::string& origin, const json& devices) {
    txn.execute("INSERT INTO device_lists_remote_cache VALUES (?,?,?,?) ON CONFLICT(user_id,origin) DO UPDATE SET devices_json=excluded.devices_json,updated_at=excluded.updated_at",{uid,origin,devices.dump(),nms()});
}

std::optional<json> DevicesStore::get_cached_remote_devices_txn(LoggingTransaction& txn, const std::string& uid) {
    auto row=txn.select_one("SELECT devices_json FROM device_lists_remote_cache WHERE user_id=? ORDER BY updated_at DESC LIMIT 1",{uid});
    if(row&&!row->is_null())return json::parse(row->get<std::string>(0)); return std::nullopt;
}

void DevicesStore::prune_old_devices_txn(LoggingTransaction& txn, int64_t max_age_ms) {
    int64_t cutoff=nms()-max_age_ms;
    txn.execute("DELETE FROM devices WHERE last_seen<? AND device_id NOT IN (SELECT DISTINCT device_id FROM access_tokens WHERE user_id=devices.user_id)",{cutoff});
}

// ============ END DEVICES ============
} // namespace


// ============================================================
// DEVICES STORE EXPANSION - Full Synapse-equivalent methods
// ============================================================
namespace progressive::storage {
namespace {
int64_t dev_now_ms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
}

void DevicesStore::store_device_full_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const std::string& dn,const std::string& ip,const std::string& ua,int64_t ls) {
  txn.execute("INSERT INTO devices(user_id,device_id,display_name,last_seen,ip,user_agent) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id,device_id) DO UPDATE SET display_name=COALESCE(excluded.display_name,devices.display_name),last_seen=excluded.last_seen,ip=COALESCE(excluded.ip,devices.ip),user_agent=COALESCE(excluded.user_agent,devices.user_agent)",{uid,did,dn,ls,ip,ua});
}
void DevicesStore::delete_devices_for_user_txn(LoggingTransaction& txn,const std::string& uid) {
  auto rows=txn.select("SELECT device_id FROM devices WHERE user_id=?",{uid});
  for(auto& r:rows){std::string did=r.get<std::string>(0); txn.execute("DELETE FROM access_tokens WHERE user_id=? AND device_id=?",{uid,did}); txn.execute("DELETE FROM e2e_device_keys WHERE user_id=? AND device_id=?",{uid,did});}
  txn.execute("DELETE FROM devices WHERE user_id=?",{uid});
}
std::vector<json> DevicesStore::get_devices_with_keys_txn(LoggingTransaction& txn,const std::string& uid) {
  std::vector<json> r; auto rows=txn.select("SELECT d.device_id,d.display_name,d.last_seen,d.ip,d.user_agent,k.key_json FROM devices d LEFT JOIN e2e_device_keys k ON d.user_id=k.user_id AND d.device_id=k.device_id WHERE d.user_id=? AND d.hidden=0",{uid});
  for(auto& row:rows){json dev;dev["device_id"]=row.get<std::string>(0);if(!row.is_null(1))dev["display_name"]=row.get<std::string>(1);dev["last_seen"]=row.get<int64_t>(2);if(!row.is_null(3))dev["ip"]=row.get<std::string>(3);if(!row.is_null(4))dev["user_agent"]=row.get<std::string>(4);if(!row.is_null(5))dev["keys"]=json::parse(row.get<std::string>(5));r.push_back(dev);}
  return r;
}
void DevicesStore::update_device_last_seen_ip_ua_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const std::string& ip,const std::string& ua) {
  txn.execute("UPDATE devices SET last_seen=?,ip=?,user_agent=? WHERE user_id=? AND device_id=?",{dev_now_ms(),ip,ua,uid,did});
}
int64_t DevicesStore::get_last_device_update_ts_txn(LoggingTransaction& txn,const std::string& uid) {
  auto row=txn.select_one("SELECT COALESCE(MAX(last_seen),0) FROM devices WHERE user_id=?",{uid}); return row?row->get<int64_t>(0):0;
}
void DevicesStore::set_device_hidden_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,bool h) {
  txn.execute("UPDATE devices SET hidden=? WHERE user_id=? AND device_id=?",{h?1:0,uid,did});
}
void DevicesStore::add_device_change_to_stream_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const std::string& change_type) {
  int64_t ts=dev_now_ms(); txn.execute("INSERT INTO device_lists_stream(user_id,device_id,change_type,ts) VALUES(?,?,?,?)",{uid,did,change_type,ts});
}
std::vector<json> DevicesStore::get_device_changes_since_txn(LoggingTransaction& txn,const std::string& uid,int64_t since_ts) {
  std::vector<json> r; auto rows=txn.select("SELECT device_id,change_type,ts FROM device_lists_stream WHERE user_id=? AND ts>? ORDER BY ts",{uid,since_ts});
  for(auto& row:rows){json c;c["device_id"]=row.get<std::string>(0);c["change_type"]=row.get<std::string>(1);c["ts"]=row.get<int64_t>(2);r.push_back(c);} return r;
}
void DevicesStore::remove_device_change_from_stream_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did) {
  txn.execute("DELETE FROM device_lists_stream WHERE user_id=? AND device_id=?",{uid,did});
}
void DevicesStore::add_remote_device_change_to_pending_txn(LoggingTransaction& txn,const std::string& uid) {
  txn.execute("INSERT OR IGNORE INTO device_lists_outbound_pokes(user_id,ts,sent) VALUES(?,?,0)",{uid,dev_now_ms()});
}
std::vector<std::string> DevicesStore::get_pending_device_outbound_pokes_txn(LoggingTransaction& txn,int limit) {
  std::vector<std::string> r; auto rows=txn.select("SELECT user_id FROM device_lists_outbound_pokes WHERE sent=0 ORDER BY ts LIMIT ?",{limit});
  for(auto& row:rows)r.push_back(row.get<std::string>(0)); return r;
}
void DevicesStore::mark_device_outbound_poke_sent_txn(LoggingTransaction& txn,const std::string& uid) {
  txn.execute("UPDATE device_lists_outbound_pokes SET sent=1 WHERE user_id=?",{uid});
}
void DevicesStore::add_user_signature_chain_txn(LoggingTransaction& txn,const std::string& uid,const json& chain) {
  txn.execute("INSERT INTO device_signature_chains(user_id,chain_json,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET chain_json=excluded.chain_json,updated_at=excluded.updated_at",{uid,chain.dump(),dev_now_ms()});
}
std::optional<json> DevicesStore::get_user_signature_chain_txn(LoggingTransaction& txn,const std::string& uid) {
  auto row=txn.select_one("SELECT chain_json FROM device_signature_chains WHERE user_id=?",{uid});
  if(row&&!row->is_null())return json::parse(row.get<std::string>(0)); return std::nullopt;
}
void DevicesStore::prune_device_list_outbound_pokes_txn(LoggingTransaction& txn,int64_t max_age_ms) {
  txn.execute("DELETE FROM device_lists_outbound_pokes WHERE ts<?",{dev_now_ms()-max_age_ms});
}
void DevicesStore::store_device_one_time_keys_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const std::string& algorithm,const std::string& key_id,const json& key_data) {
  txn.execute("INSERT INTO e2e_one_time_keys_json(user_id,device_id,algorithm,key_id,key_json) VALUES(?,?,?,?,?)",{uid,did,algorithm,key_id,key_data.dump()});
}
int64_t DevicesStore::count_one_time_keys_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const std::string& algorithm) {
  auto row=txn.select_one("SELECT COUNT(*) FROM e2e_one_time_keys_json WHERE user_id=? AND device_id=? AND algorithm=?",{uid,did,algorithm}); return row?row->get<int64_t>(0):0;
}
json DevicesStore::get_one_time_keys_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const std::string& algorithm,int limit) {
  json r=json::object(); auto rows=txn.select("SELECT key_id,key_json FROM e2e_one_time_keys_json WHERE user_id=? AND device_id=? AND algorithm=? ORDER BY key_id LIMIT ?",{uid,did,algorithm,limit});
  for(auto& row:rows){r[row.get<std::string>(0)]=json::parse(row.get<std::string>(1));} return r;
}
void DevicesStore::delete_one_time_key_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const std::string& algorithm,const std::string& key_id) {
  txn.execute("DELETE FROM e2e_one_time_keys_json WHERE user_id=? AND device_id=? AND algorithm=? AND key_id=?",{uid,did,algorithm,key_id});
}
void DevicesStore::claim_one_time_keys_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const std::map<std::string,int>& algorithms) {
  for(auto&[alg,count]:algorithms){
    auto rows=txn.select("SELECT key_id FROM e2e_one_time_keys_json WHERE user_id=? AND device_id=? AND algorithm=? ORDER BY key_id LIMIT ?",{uid,did,alg,count});
    std::vector<std::string> claimed;
    for(auto& row:rows)claimed.push_back(row.get<std::string>(0));
    for(auto& kid:claimed)txn.execute("DELETE FROM e2e_one_time_keys_json WHERE user_id=? AND device_id=? AND algorithm=? AND key_id=?",{uid,did,alg,kid});
  }
}
void DevicesStore::add_device_fallback_key_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const std::string& algorithm,const json& key_data) {
  txn.execute("INSERT INTO e2e_fallback_keys_json(user_id,device_id,algorithm,key_json,used) VALUES(?,?,?,?,0) ON CONFLICT(user_id,device_id,algorithm) DO UPDATE SET key_json=excluded.key_json,used=0",{uid,did,algorithm,key_data.dump()});
}
std::optional<json> DevicesStore::get_device_fallback_key_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const std::string& algorithm) {
  auto row=txn.select_one("SELECT key_json FROM e2e_fallback_keys_json WHERE user_id=? AND device_id=? AND algorithm=? AND used=0",{uid,did,algorithm});
  if(row&&!row->is_null()){txn.execute("UPDATE e2e_fallback_keys_json SET used=1 WHERE user_id=? AND device_id=? AND algorithm=?",{uid,did,algorithm});return json::parse(row->get<std::string>(0));} return std::nullopt;
}
void DevicesStore::reset_fallback_key_used_txn(LoggingTransaction& txn,const std::string& uid,const std::string& did,const std::string& algorithm) {
  txn.execute("UPDATE e2e_fallback_keys_json SET used=0 WHERE user_id=? AND device_id=? AND algorithm=?",{uid,did,algorithm});
}
} // namespace progressive::storage

// ==========================================
// EXTENDED DEVICES: Complete Synapse-level device management
// ==========================================
namespace progressive::storage { namespace {
int64_t _nowdev(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());}
}

// Device registration with full metadata
void DevicesStore::register_device_txn(LoggingTransaction& txn, const std::string& user_id, const std::string& device_id, const std::string& display_name, const std::string& device_type, const json& initial_device_display_name) {
  int64_t ts=_nowdev();
  txn.execute("INSERT INTO devices(user_id,device_id,display_name,last_seen,device_type,device_metadata) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id,device_id) DO UPDATE SET display_name=COALESCE(excluded.display_name,devices.display_name),last_seen=excluded.last_seen,device_type=COALESCE(excluded.device_type,devices.device_type)",{user_id,device_id,display_name,ts,device_type,initial_device_display_name.dump()});
  txn.execute("INSERT INTO device_lists_stream(user_id,device_id,change_type,ts) VALUES(?,?,'register',?)",{user_id,device_id,ts});
}

// Get all devices for a user with full key info
std::vector<json> DevicesStore::get_user_devices_with_keys_txn(LoggingTransaction& txn, const std::string& user_id) {
  std::vector<json> result;
  auto rows=txn.select("SELECT d.device_id,d.display_name,d.last_seen,d.ip,d.user_agent,d.hidden,d.device_type,k.key_json,k.display_name as key_display_name FROM devices d LEFT JOIN e2e_device_keys k ON d.user_id=k.user_id AND d.device_id=k.device_id WHERE d.user_id=?",{user_id});
  for(auto& row:rows){
    json dev; dev["device_id"]=row.get<std::string>(0);
    if(!row.is_null(1))dev["display_name"]=row.get<std::string>(1);
    dev["last_seen"]=row.get<int64_t>(2);
    if(!row.is_null(3))dev["last_seen_ip"]=row.get<std::string>(3);
    if(!row.is_null(4))dev["user_agent"]=row.get<std::string>(4);
    dev["hidden"]=row.get<int64_t>(5)!=0;
    if(!row.is_null(6))dev["device_type"]=row.get<std::string>(6);
    if(!row.is_null(7))dev["keys"]=json::parse(row.get<std::string>(7));
    if(!row.is_null(8))dev["key_display_name"]=row.get<std::string>(8);
    result.push_back(dev);
  }
  return result;
}

// Track which users need device list updates pushed to them
void DevicesStore::mark_device_list_as_outdated_txn(LoggingTransaction& txn, const std::string& user_id) {
  txn.execute("INSERT INTO device_lists_outbound_pokes(user_id,ts,sent,destination) SELECT ?,?,0,user_id FROM local_current_membership WHERE room_id IN (SELECT room_id FROM local_current_membership WHERE user_id=?)",{user_id,_nowdev(),user_id});
}

// Get all destinations that need device list updates
std::vector<json> DevicesStore::get_destinations_for_device_list_updates_txn(LoggingTransaction& txn, int limit) {
  std::vector<json> r;
  auto rows=txn.select("SELECT DISTINCT destination,MIN(ts) as earliest FROM device_lists_outbound_pokes WHERE sent=0 GROUP BY destination ORDER BY earliest LIMIT ?",{limit});
  for(auto& row:rows){json d;d["destination"]=row.get<std::string>(0);d["earliest"]=row.get<int64_t>(1);r.push_back(d);}
  return r;
}

// Delete device and all associated data (access tokens, keys, inbox)
void DevicesStore::delete_device_full_txn(LoggingTransaction& txn, const std::string& user_id, const std::string& device_id) {
  txn.execute("DELETE FROM access_tokens WHERE user_id=? AND device_id=?",{user_id,device_id});
  txn.execute("DELETE FROM refresh_tokens WHERE user_id=? AND device_id=?",{user_id,device_id});
  txn.execute("DELETE FROM e2e_device_keys WHERE user_id=? AND device_id=?",{user_id,device_id});
  txn.execute("DELETE FROM e2e_one_time_keys_json WHERE user_id=? AND device_id=?",{user_id,device_id});
  txn.execute("DELETE FROM e2e_fallback_keys_json WHERE user_id=? AND device_id=?",{user_id,device_id});
  txn.execute("DELETE FROM device_inbox WHERE user_id=? AND device_id=?",{user_id,device_id});
  txn.execute("DELETE FROM device_lists_stream WHERE user_id=? AND device_id=?",{user_id,device_id});
  txn.execute("DELETE FROM devices WHERE user_id=? AND device_id=?",{user_id,device_id});
}

// Multi-device deletion - support for GDPR erasure
void DevicesStore::delete_multiple_devices_txn(LoggingTransaction& txn, const std::vector<std::pair<std::string,std::string>>& devices) {
  for(auto&[uid,did]:devices)delete_device_full_txn(txn,uid,did);
}

// Get device count statistics
json DevicesStore::get_device_statistics_txn(LoggingTransaction& txn) {
  json stats;
  auto total=txn.select_one("SELECT COUNT(*) FROM devices");stats["total_devices"]=total?total->get<int64_t>(0):0;
  auto active=txn.select_one("SELECT COUNT(*) FROM devices WHERE last_seen>?",{_nowdev()-86400000});stats["active_devices_24h"]=active?active->get<int64_t>(0):0;
  auto hidden=txn.select_one("SELECT COUNT(*) FROM devices WHERE hidden=1");stats["hidden_devices"]=hidden?hidden->get<int64_t>(0):0;
  return stats;
}

// Search for device by display name (admin function)
std::vector<json> DevicesStore::search_devices_by_display_name_txn(LoggingTransaction& txn, const std::string& search_term, int limit) {
  std::vector<json> r; auto rows=txn.select("SELECT d.user_id,d.device_id,d.display_name,d.last_seen,d.device_type,u.display_name as user_dn FROM devices d JOIN users u ON d.user_id=u.name WHERE d.display_name LIKE ? LIMIT ?",{"%"+search_term+"%",limit});
  for(auto& row:rows){json dev;dev["user_id"]=row.get<std::string>(0);dev["device_id"]=row.get<std::string>(1);dev["display_name"]=row.get<std::string>(2);dev["last_seen"]=row.get<int64_t>(3);dev["device_type"]=row.get<std::string>(4);dev["user_display_name"]=row.get<std::string>(5);r.push_back(dev);}
  return r;
}

// Add device to a user's device group for notification purposes
void DevicesStore::add_device_to_group_txn(LoggingTransaction& txn, const std::string& user_id, const std::string& device_id, const std::string& group_name) {
  txn.execute("INSERT INTO device_groups(user_id,device_id,group_name) VALUES(?,?,?) ON CONFLICT DO NOTHING",{user_id,device_id,group_name});
}

// Get all devices in a group
std::vector<std::string> DevicesStore::get_devices_in_group_txn(LoggingTransaction& txn, const std::string& user_id, const std::string& group_name) {
  std::vector<std::string> r; auto rows=txn.select("SELECT device_id FROM device_groups WHERE user_id=? AND group_name=?",{user_id,group_name});
  for(auto& row:rows)r.push_back(row.get<std::string>(0)); return r;
}

// Remove device from group
void DevicesStore::remove_device_from_group_txn(LoggingTransaction& txn, const std::string& user_id, const std::string& device_id, const std::string& group_name) {
  txn.execute("DELETE FROM device_groups WHERE user_id=? AND device_id=? AND group_name=?",{user_id,device_id,group_name});
}

// Get all device groups for a user
std::vector<std::string> DevicesStore::get_device_groups_for_user_txn(LoggingTransaction& txn, const std::string& user_id) {
  std::vector<std::string> r; auto rows=txn.select("SELECT DISTINCT group_name FROM device_groups WHERE user_id=?",{user_id});
  for(auto& row:rows)r.push_back(row.get<std::string>(0)); return r;
}

} // namespace progressive::storage
