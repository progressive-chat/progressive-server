#include "progressive/storage/databases/main/final_stores.hpp"
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

namespace { int64_t now_ms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();} }

// ====== CACHE STORE (synapse cache.py - 912 lines) ======

std::optional<json> CacheInvalidationStore::get_cache_invalidation_by_key_txn(LoggingTransaction& txn, const std::string& cache_name, const std::string& cache_key) {
  auto row = txn.select_one("SELECT value FROM cache_invalidation_stream WHERE cache_name = ? AND cache_key = ?", {cache_name, cache_key});
  if (row && !row->is_null()) return json::parse(row->get<std::string>(0));
  return std::nullopt;
}

void CacheInvalidationStore::invalidate_cache_entry_txn(LoggingTransaction& txn, const std::string& cache_name, const std::string& cache_key) {
  txn.execute("INSERT OR REPLACE INTO cache_invalidation_stream (cache_name, cache_key, invalidation_ts) VALUES (?, ?, ?)", {cache_name, cache_key, now_ms()});
}

std::vector<json> CacheInvalidationStore::get_all_cache_invalidations_txn(LoggingTransaction& txn, int64_t since_ts) {
  std::vector<json> r;
  auto rows = txn.select("SELECT cache_name, cache_key, invalidation_ts FROM cache_invalidation_stream WHERE invalidation_ts > ?", {since_ts});
  for (auto& row : rows) { json e; e["cache_name"]=row.get<std::string>(0); e["cache_key"]=row.get<std::string>(1); e["invalidation_ts"]=row.get<int64_t>(2); r.push_back(e); }
  return r;
}

// ====== CLIENT IPS STORE (synapse client_ips.py - 816 lines) ======

void ClientIpsStore::insert_client_ip_txn(LoggingTransaction& txn, const std::string& user_id, const std::string& access_token, const std::string& ip, const std::string& user_agent, const std::string& device_id) {
  int64_t ts=now_ms();
  txn.execute("INSERT INTO user_ips (user_id, access_token, device_id, ip, user_agent, last_seen) VALUES (?, ?, ?, ?, ?, ?)", {user_id, access_token, device_id, ip, user_agent, ts});
}

std::vector<json> ClientIpsStore::get_last_client_ip_by_device_txn(LoggingTransaction& txn, const std::string& user_id, const std::string& device_id) {
  std::vector<json> r;
  auto rows=txn.select("SELECT ip, user_agent, last_seen FROM user_ips WHERE user_id=? AND device_id=? ORDER BY last_seen DESC LIMIT 1",{user_id,device_id});
  for(auto& row:rows){json e;e["ip"]=row.get<std::string>(0);e["user_agent"]=row.get<std::string>(1);e["last_seen"]=row.get<int64_t>(2);r.push_back(e);}
  return r;
}

json ClientIpsStore::get_user_ip_and_agents_txn(LoggingTransaction& txn, const std::string& user_id) {
  json r=json::object(); auto rows=txn.select("SELECT device_id, ip, user_agent, last_seen FROM user_ips WHERE user_id=? ORDER BY last_seen DESC",{user_id});
  for(auto& row:rows){json e;e["ip"]=row.get<std::string>(1);e["user_agent"]=row.get<std::string>(2);e["last_seen"]=row.get<int64_t>(3);if(!r.contains(row.get<std::string>(0)))r[row.get<std::string>(0)]=json::array();r[row.get<std::string>(0)].push_back(e);}
  return r;
}

std::vector<json> ClientIpsStore::get_all_user_ips_txn(LoggingTransaction& txn, int limit) {
  std::vector<json> r; auto rows=txn.select("SELECT user_id, device_id, ip, user_agent, last_seen FROM user_ips ORDER BY last_seen DESC LIMIT ?",{limit});
  for(auto& row:rows){json e;e["user_id"]=row.get<std::string>(0);e["device_id"]=row.get<std::string>(1);e["ip"]=row.get<std::string>(2);e["user_agent"]=row.get<std::string>(3);e["last_seen"]=row.get<int64_t>(4);r.push_back(e);}
  return r;
}

void ClientIpsStore::track_user_last_seen_txn(LoggingTransaction& txn, const std::string& user_id) {
  txn.execute("INSERT INTO user_daily_visits (user_id, timestamp) VALUES (?, ?)",{user_id,now_ms()});
}

int64_t ClientIpsStore::get_daily_active_users_txn(LoggingTransaction& txn, int64_t since_ts) {
  auto row=txn.select_one("SELECT COUNT(DISTINCT user_id) FROM user_daily_visits WHERE timestamp > ?",{since_ts});
  return row?row->get<int64_t>(0):0;
}

// ====== CENSOR EVENTS STORE ======

void CensorEventsStore::censor_event_txn(LoggingTransaction& txn, const std::string& event_id, const std::string& reason) {
  txn.execute("INSERT OR IGNORE INTO censored_events (event_id, reason, censored_ts) VALUES (?, ?, ?)",{event_id,reason,now_ms()});
}

bool CensorEventsStore::is_censored_txn(LoggingTransaction& txn, const std::string& event_id) {
  auto row=txn.select_one("SELECT 1 FROM censored_events WHERE event_id=?",{event_id}); return row&&!row->is_null();
}

// ====== DELAYED EVENTS STORE (synapse delayed_events.py - 584 lines) ======

void DelayedEventsStore::add_delayed_event_txn(LoggingTransaction& txn, const std::string& event_id, const std::string& room_id, int64_t delay_ms) {
  txn.execute("INSERT INTO delayed_events (event_id, room_id, processing_ts) VALUES (?, ?, ?)",{event_id,room_id,now_ms()+delay_ms});
}

std::vector<json> DelayedEventsStore::get_delayed_events_to_process_txn(LoggingTransaction& txn) {
  std::vector<json> r; auto rows=txn.select("SELECT event_id, room_id, processing_ts FROM delayed_events WHERE processing_ts <= ?",{now_ms()});
  for(auto& row:rows){json e;e["event_id"]=row.get<std::string>(0);e["room_id"]=row.get<std::string>(1);e["processing_ts"]=row.get<int64_t>(2);r.push_back(e);}
  return r;
}

void DelayedEventsStore::delete_delayed_event_txn(LoggingTransaction& txn, const std::string& event_id) {
  txn.execute("DELETE FROM delayed_events WHERE event_id=?",{event_id});
}

// ====== DEVICE INBOX STORE (synapse deviceinbox.py - 1272 lines) ======

void DeviceInboxStore::add_to_device_message_txn(LoggingTransaction& txn, const std::string& user_id, const std::string& device_id, const std::string& message_id, const json& content) {
  int64_t ts=now_ms(); txn.execute("INSERT INTO device_inbox (user_id, device_id, message_id, content, received_ts) VALUES (?, ?, ?, ?, ?)",{user_id,device_id,message_id,content.dump(),ts});
}

std::vector<json> DeviceInboxStore::get_to_device_messages_txn(LoggingTransaction& txn, const std::string& user_id, const std::string& device_id) {
  std::vector<json> r; auto rows=txn.select("SELECT message_id, content, received_ts FROM device_inbox WHERE user_id=? AND device_id=? ORDER BY received_ts ASC",{user_id,device_id});
  for(auto& row:rows){json m=json::parse(row.get<std::string>(1));m["message_id"]=row.get<std::string>(0);m["received_ts"]=row.get<int64_t>(2);r.push_back(m);}
  return r;
}

void DeviceInboxStore::delete_to_device_messages_txn(LoggingTransaction& txn, const std::string& user_id, const std::string& device_id, int64_t up_to_ts) {
  txn.execute("DELETE FROM device_inbox WHERE user_id=? AND device_id=? AND received_ts <= ?",{user_id,device_id,up_to_ts});
}

int64_t DeviceInboxStore::count_to_device_messages_txn(LoggingTransaction& txn, const std::string& user_id) {
  auto row=txn.select_one("SELECT COUNT(*) FROM device_inbox WHERE user_id=?",{user_id}); return row?row->get<int64_t>(0):0;
}

// ====== E2E ROOM KEYS STORE (synapse e2e_room_keys.py - 689 lines) ======

void E2eRoomKeysStore::set_e2e_room_key_txn(LoggingTransaction& txn, const std::string& user_id, const std::string& room_id, const std::string& session_id, const json& key_data) {
  txn.execute("INSERT INTO e2e_room_keys (user_id, room_id, session_id, key_data) VALUES (?, ?, ?, ?) ON CONFLICT (user_id, room_id, session_id) DO UPDATE SET key_data=excluded.key_data",{user_id,room_id,session_id,key_data.dump()});
}

std::optional<json> E2eRoomKeysStore::get_e2e_room_key_txn(LoggingTransaction& txn, const std::string& user_id, const std::string& room_id, const std::string& session_id) {
  auto row=txn.select_one("SELECT key_data FROM e2e_room_keys WHERE user_id=? AND room_id=? AND session_id=?",{user_id,room_id,session_id});
  if(row&&!row->is_null())return json::parse(row->get<std::string>(0)); return std::nullopt;
}

std::vector<json> E2eRoomKeysStore::get_all_e2e_room_keys_txn(LoggingTransaction& txn, const std::string& user_id) {
  std::vector<json> r; auto rows=txn.select("SELECT room_id, session_id, key_data FROM e2e_room_keys WHERE user_id=?",{user_id});
  for(auto& row:rows){json k=json::parse(row.get<std::string>(2));k["room_id"]=row.get<std::string>(0);k["session_id"]=row.get<std::string>(1);r.push_back(k);} return r;
}

void E2eRoomKeysStore::delete_e2e_room_key_txn(LoggingTransaction& txn, const std::string& user_id, const std::string& room_id, const std::string& session_id) {
  txn.execute("DELETE FROM e2e_room_keys WHERE user_id=? AND room_id=? AND session_id=?",{user_id,room_id,session_id});
}

void E2eRoomKeysStore::delete_all_e2e_room_keys_txn(LoggingTransaction& txn, const std::string& user_id) {
  txn.execute("DELETE FROM e2e_room_keys WHERE user_id=?",{user_id});
}

int64_t E2eRoomKeysStore::count_e2e_room_keys_txn(LoggingTransaction& txn, const std::string& user_id) {
  auto row=txn.select_one("SELECT COUNT(*) FROM e2e_room_keys WHERE user_id=?",{user_id}); return row?row->get<int64_t>(0):0;
}

// ====== FORWARD EXTREMITIES STORE ======

std::vector<std::string> ForwardExtremitiesStore::get_auth_chain_for_event_txn(LoggingTransaction& txn, const std::string& event_id) {
  std::vector<std::string> r; auto rows=txn.select("SELECT auth_id FROM event_auth WHERE event_id=?",{event_id});
  for(auto& row:rows)r.push_back(row.get<std::string>(0)); return r;
}

// ====== EXPERIMENTAL FEATURES STORE ======

void ExperimentalFeaturesStore::set_feature_enabled_txn(LoggingTransaction& txn, const std::string& feature, bool enabled) {
  txn.execute("INSERT INTO experimental_features (feature_name, enabled) VALUES (?,?) ON CONFLICT(feature_name) DO UPDATE SET enabled=excluded.enabled",{feature,enabled?1:0});
}

std::map<std::string,bool> ExperimentalFeaturesStore::get_all_features_txn(LoggingTransaction& txn) {
  std::map<std::string,bool> r; auto rows=txn.select("SELECT feature_name, enabled FROM experimental_features");
  for(auto& row:rows)r[row.get<std::string>(0)]=row.get<int64_t>(1)!=0; return r;
}

// ====== LOCK STORE (synapse lock.py - 556 lines) ======

bool LockStore::try_acquire_lock_txn(LoggingTransaction& txn, const std::string& lock_name, const std::string& lock_key, int64_t timeout_ms) {
  int64_t now=now_ms(); txn.execute("DELETE FROM locks WHERE expires_ts < ?",{now});
  auto existing=txn.select_one("SELECT lock_key FROM locks WHERE lock_name=?",{lock_name});
  if(existing&&!existing->is_null())return false;
  txn.execute("INSERT INTO locks (lock_name, lock_key, acquired_ts, expires_ts) VALUES (?,?,?,?)",{lock_name,lock_key,now,now+timeout_ms});
  return true;
}

void LockStore::release_lock_txn(LoggingTransaction& txn, const std::string& lock_name, const std::string& lock_key) {
  txn.execute("DELETE FROM locks WHERE lock_name=? AND lock_key=?",{lock_name,lock_key});
}

void LockStore::renew_lock_txn(LoggingTransaction& txn, const std::string& lock_name, const std::string& lock_key, int64_t timeout_ms) {
  txn.execute("UPDATE locks SET expires_ts=? WHERE lock_name=? AND lock_key=?",{now_ms()+timeout_ms,lock_name,lock_key});
}

// ====== METRICS STORE (synapse metrics.py - 684 lines) ======

void MetricsStore::store_metrics_txn(LoggingTransaction& txn, const json& metrics) {
  txn.execute("INSERT INTO server_metrics (timestamp, metrics_json) VALUES (?,?)",{now_ms(),metrics.dump()});
}

json MetricsStore::get_metrics_txn(LoggingTransaction& txn, int64_t from_ts, int64_t to_ts, int limit) {
  json r=json::array(); auto rows=txn.select("SELECT timestamp, metrics_json FROM server_metrics WHERE timestamp>=? AND timestamp<=? ORDER BY timestamp DESC LIMIT ?",{from_ts,to_ts,limit});
  for(auto& row:rows){json m=json::parse(row.get<std::string>(1));m["timestamp"]=row.get<int64_t>(0);r.push_back(m);} return r;
}

json MetricsStore::get_latest_metrics_txn(LoggingTransaction& txn) {
  auto row=txn.select_one("SELECT metrics_json FROM server_metrics ORDER BY timestamp DESC LIMIT 1");
  if(row&&!row->is_null())return json::parse(row.get<std::string>(0)); return json::object();
}

// ====== MONTHLY ACTIVE USERS STORE (synapse mau.py) ======

void MonthlyActiveUsersStore::upsert_mau_txn(LoggingTransaction& txn, const std::string& user_id) {
  txn.execute("INSERT INTO monthly_active_users (user_id, timestamp) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET timestamp=excluded.timestamp",{user_id,now_ms()});
}

int64_t MonthlyActiveUsersStore::count_mau_txn(LoggingTransaction& txn, int64_t since_ts) {
  auto row=txn.select_one("SELECT COUNT(*) FROM monthly_active_users WHERE timestamp > ?",{since_ts}); return row?row->get<int64_t>(0):0;
}

int64_t MonthlyActiveUsersStore::get_max_mau_value_txn(LoggingTransaction& txn) {
  auto row=txn.select_one("SELECT COALESCE(reserved_users,0) FROM mau_limits ORDER BY id DESC LIMIT 1");
  return row?row->get<int64_t>(0):0;
}

bool MonthlyActiveUsersStore::is_mau_limit_reached_txn(LoggingTransaction& txn) {
  int64_t limit=get_max_mau_value_txn(txn); if(limit<=0)return false;
  int64_t now=now_ms(); int64_t count=count_mau_txn(txn,now-2592000000);
  return count>limit;
}

// ====== PURGE EVENTS STORE (synapse purge_events.py) ======

void PurgeEventsStore::purge_events_before_txn(LoggingTransaction& txn, const std::string& room_id, const std::string& before_event_id) {
  txn.execute("DELETE FROM events WHERE room_id=? AND event_id<?",{room_id,before_event_id});
  txn.execute("DELETE FROM event_json WHERE room_id=? AND event_id<?",{room_id,before_event_id});
  txn.execute("DELETE FROM event_edges WHERE room_id=? AND event_id<?",{room_id,before_event_id});
  txn.execute("DELETE FROM event_auth WHERE room_id=? AND event_id<?",{room_id,before_event_id});
  txn.execute("DELETE FROM state_events WHERE room_id=? AND event_id<?",{room_id,before_event_id});
  txn.execute("DELETE FROM event_relations WHERE event_id IN (SELECT event_id FROM events WHERE room_id=? AND event_id<?)",{room_id,before_event_id});
  txn.execute("DELETE FROM event_search WHERE event_id IN (SELECT event_id FROM events WHERE room_id=? AND event_id<?)",{room_id,before_event_id});
}

void PurgeEventsStore::purge_events_before_ts_txn(LoggingTransaction& txn, const std::string& room_id, int64_t before_ts) {
  txn.execute("DELETE FROM events WHERE room_id=? AND origin_server_ts<?",{room_id,before_ts});
}

// ====== REJECTIONS STORE ======

void RejectionsStore::add_rejection_txn(LoggingTransaction& txn, const std::string& event_id, const std::string& reason) {
  txn.execute("INSERT OR IGNORE INTO event_rejections (event_id, reason, last_check) VALUES (?,?,?)",{event_id,reason,now_ms()});
}

bool RejectionsStore::is_rejected_txn(LoggingTransaction& txn, const std::string& event_id) {
  auto row=txn.select_one("SELECT 1 FROM event_rejections WHERE event_id=?",{event_id}); return row&&!row->is_null();
}

// ====== STICKY EVENTS STORE ======

void StickyEventsStore::insert_sticky_event_txn(LoggingTransaction& txn, const std::string& room_id, const std::string& event_type, const std::string& state_key) {
  txn.execute("INSERT OR IGNORE INTO sticky_events (room_id, event_type, state_key) VALUES (?,?,?)",{room_id,event_type,state_key});
}

void StickyEventsStore::delete_sticky_event_txn(LoggingTransaction& txn, const std::string& room_id, const std::string& event_type, const std::string& state_key) {
  txn.execute("DELETE FROM sticky_events WHERE room_id=? AND event_type=? AND state_key=?",{room_id,event_type,state_key});
}

std::vector<json> StickyEventsStore::get_sticky_events_for_room_txn(LoggingTransaction& txn, const std::string& room_id) {
  std::vector<json> r; auto rows=txn.select("SELECT event_type, state_key FROM sticky_events WHERE room_id=?",{room_id});
  for(auto& row:rows){json e;e["type"]=row.get<std::string>(0);e["state_key"]=row.get<std::string>(1);r.push_back(e);} return r;
}

// ====== TASK SCHEDULER STORE ======

void TaskSchedulerStore::schedule_task_txn(LoggingTransaction& txn, const std::string& task_id, const json& task_data, int64_t scheduled_at) {
  txn.execute("INSERT INTO scheduled_tasks (task_id, task_data, scheduled_at, status) VALUES (?,?,?,?)",{task_id,task_data.dump(),scheduled_at>0?scheduled_at:now_ms(),"pending"});
}

std::vector<json> TaskSchedulerStore::get_pending_tasks_txn(LoggingTransaction& txn, int limit) {
  std::vector<json> r; auto rows=txn.select("SELECT task_id, task_data, scheduled_at FROM scheduled_tasks WHERE status='pending' AND scheduled_at<=? ORDER BY scheduled_at LIMIT ?",{now_ms(),limit});
  for(auto& row:rows){json t=json::parse(row.get<std::string>(1));t["task_id"]=row.get<std::string>(0);t["scheduled_at"]=row.get<int64_t>(2);r.push_back(t);} return r;
}

void TaskSchedulerStore::mark_task_complete_txn(LoggingTransaction& txn, const std::string& task_id) {
  txn.execute("UPDATE scheduled_tasks SET status='completed', completed_at=? WHERE task_id=?",{now_ms(),task_id});
}

void TaskSchedulerStore::mark_task_failed_txn(LoggingTransaction& txn, const std::string& task_id, const std::string& error) {
  txn.execute("UPDATE scheduled_tasks SET status='failed', error=?, failed_at=? WHERE task_id=?",{error,now_ms(),task_id});
}

// ====== THREADS STORE ======

std::vector<json> ThreadsStore::get_threads_for_room_txn(LoggingTransaction& txn, const std::string& room_id, int limit) {
  std::vector<json> r; auto rows=txn.select("SELECT er.relates_to_id as thread_root, COUNT(*) as reply_count, MAX(e.origin_server_ts) as latest FROM event_relations er JOIN events e ON er.event_id=e.event_id WHERE er.relation_type='m.thread' AND e.room_id=? GROUP BY er.relates_to_id ORDER BY latest DESC LIMIT ?",{room_id,limit});
  for(auto& row:rows){json t;t["event_id"]=row.get<std::string>(0);t["count"]=row.get<int64_t>(1);t["latest"]=row.get<int64_t>(2);
    auto root=txn.select_one("SELECT content FROM event_json WHERE event_id=?",{row.get<std::string>(0)});
    if(root&&!root->is_null())t["content"]=json::parse(root->get<std::string>(0));
    r.push_back(t);
  } return r;
}

// ====== USER ERASURE STORE ======

void UserErasureStore::mark_user_for_erasure_txn(LoggingTransaction& txn, const std::string& user_id) {
  txn.execute("INSERT INTO user_erasure (user_id, requested_ts) VALUES (?,?) ON CONFLICT DO NOTHING",{user_id,now_ms()});
}

bool UserErasureStore::is_user_erased_txn(LoggingTransaction& txn, const std::string& user_id) {
  auto row=txn.select_one("SELECT 1 FROM user_erasure WHERE user_id=?",{user_id}); return row&&!row->is_null();
}

void UserErasureStore::erase_user_data_txn(LoggingTransaction& txn, const std::string& user_id) {
  for(const char* tbl:{"events","event_json","access_tokens","refresh_tokens","user_ips","user_daily_visits","device_inbox","e2e_room_keys","room_tags","room_account_data","user_account_data"})
    txn.execute("DELETE FROM "+std::string(tbl)+" WHERE user_id=?",{user_id});
  txn.execute("UPDATE room_memberships SET display_name=NULL, avatar_url=NULL WHERE user_id=?",{user_id});
  txn.execute("UPDATE user_threepids SET address=NULL WHERE user_id=?",{user_id});
  txn.execute("UPDATE user_directory SET display_name=NULL, avatar_url=NULL WHERE user_id=?",{user_id});
  txn.execute("UPDATE users SET deactivated=1, display_name=NULL, avatar_url=NULL, password_hash=NULL WHERE name=?",{user_id});
}

FinalStores::FinalStores(DatabasePool& db):cache_store(db),client_ips(db),censor_store(db),delayed_events(db),device_inbox(db),e2e_room_keys(db),forward_extremities(db),experimental(db),lock_store(db),metrics_store(db),mau_store(db),purge_events(db),rejections(db),sticky_events(db),task_scheduler(db),threads_store(db),user_erasure(db){}

} // namespace
