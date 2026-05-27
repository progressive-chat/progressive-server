#include "progressive/storage/databases/main/small_stores.hpp"
#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace progressive::storage {

// ====== PUSHER STORE (synapse/storage/databases/main/pusher.py - 793 lines) ======

namespace pusher_sql {
static const char* PUSHERS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS pushers (
    id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
    user_name TEXT NOT NULL,
    access_token BIGINT,
    profile_tag TEXT NOT NULL,
    kind TEXT NOT NULL,
    app_id TEXT NOT NULL,
    app_display_name TEXT NOT NULL,
    device_display_name TEXT,
    pushkey TEXT NOT NULL,
    ts BIGINT NOT NULL,
    lang TEXT,
    data TEXT,
    last_stream_ordering BIGINT,
    last_success BIGINT,
    failing_since BIGINT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS pushers_user_idx ON pushers (user_name);
CREATE INDEX IF NOT EXISTS pushers_app_idx ON pushers (app_id, pushkey);
CREATE INDEX IF NOT EXISTS pushers_enabled_idx ON pushers (enabled);
)SQL";

static const char* PUSHER_THROTTLE_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS pusher_throttle (
    pusher BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    last_sent_ts BIGINT NOT NULL,
    throttle_ms BIGINT NOT NULL,
    CONSTRAINT pusher_throttle_pkey PRIMARY KEY (pusher, room_id),
    CONSTRAINT pusher_throttle_fkey FOREIGN KEY (pusher) REFERENCES pushers (id)
);
)SQL";

static const char* DELETED_PUSHERS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS deleted_pushers (
    stream_id BIGINT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    pushkey TEXT NOT NULL
);
)SQL";
} // namespace pusher_sql

// ---------- Pusher Store ----------

void PusherStore::add_pusher_txn(LoggingTransaction& txn,
                                  const std::string& user_name,
                                  const std::string& access_token,
                                  const std::string& kind,
                                  const std::string& app_id,
                                  const std::string& app_display_name,
                                  const std::string& device_display_name,
                                  const std::string& pushkey,
                                  const std::string& lang,
                                  const std::string& profile_tag,
                                  const json& data,
                                  int64_t last_stream_ordering,
                                  int64_t last_success) {
  int64_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  
  // Remove any existing pusher with same app_id + pushkey
  txn.execute(
      "DELETE FROM pushers WHERE app_id = ? AND pushkey = ?",
      {app_id, pushkey});
  
  txn.execute(
      "INSERT INTO pushers (user_name, access_token, profile_tag, kind, app_id, "
      "app_display_name, device_display_name, pushkey, ts, lang, data, "
      "last_stream_ordering, last_success) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      {user_name, access_token, profile_tag, kind, app_id,
       app_display_name, device_display_name, pushkey, ts, lang,
       data.dump(), last_stream_ordering, last_success});
}

void PusherStore::update_pusher_last_stream_ordering_and_success_txn(
    LoggingTransaction& txn,
    const std::string& app_id,
    const std::string& pushkey,
    int64_t last_stream_ordering,
    int64_t last_success) {
  txn.execute(
      "UPDATE pushers SET last_stream_ordering = ?, last_success = ?, "
      "failing_since = NULL WHERE app_id = ? AND pushkey = ?",
      {last_stream_ordering, last_success, app_id, pushkey});
}

void PusherStore::update_pusher_failing_since_txn(
    LoggingTransaction& txn,
    const std::string& app_id,
    const std::string& pushkey,
    int64_t failing_since) {
  txn.execute(
      "UPDATE pushers SET failing_since = ? WHERE app_id = ? AND pushkey = ?",
      {failing_since, app_id, pushkey});
}

void PusherStore::delete_pusher_by_app_id_pushkey_txn(
    LoggingTransaction& txn,
    const std::string& app_id,
    const std::string& pushkey) {
  txn.execute(
      "DELETE FROM pushers WHERE app_id = ? AND pushkey = ?",
      {app_id, pushkey});
}

std::vector<json> PusherStore::get_pushers_by_user_txn(
    LoggingTransaction& txn, const std::string& user_name) {
  std::vector<json> result;
  auto rows = txn.select(
      "SELECT id, user_name, access_token, profile_tag, kind, app_id, "
      "app_display_name, device_display_name, pushkey, ts, lang, data, "
      "last_stream_ordering, last_success, failing_since, enabled "
      "FROM pushers WHERE user_name = ? AND enabled = 1", {user_name});
  for (auto& row : rows) {
    json p;
    p["id"] = row.get<int64_t>(0);
    p["user_name"] = row.get<std::string>(1);
    if (!row.is_null(2)) p["access_token"] = row.get<std::string>(2);
    p["profile_tag"] = row.get<std::string>(3);
    p["kind"] = row.get<std::string>(4);
    p["app_id"] = row.get<std::string>(5);
    p["app_display_name"] = row.get<std::string>(6);
    if (!row.is_null(7)) p["device_display_name"] = row.get<std::string>(7);
    p["pushkey"] = row.get<std::string>(8);
    p["ts"] = row.get<int64_t>(9);
    if (!row.is_null(10)) p["lang"] = row.get<std::string>(10);
    if (!row.is_null(11)) p["data"] = json::parse(row.get<std::string>(11));
    if (!row.is_null(12)) p["last_stream_ordering"] = row.get<int64_t>(12);
    if (!row.is_null(13)) p["last_success"] = row.get<int64_t>(13);
    if (!row.is_null(14)) p["failing_since"] = row.get<int64_t>(14);
    p["enabled"] = row.get<int64_t>(15) != 0;
    result.push_back(p);
  }
  return result;
}

std::vector<json> PusherStore::get_all_pushers_txn(LoggingTransaction& txn) {
  std::vector<json> result;
  auto rows = txn.select(
      "SELECT id, user_name, access_token, profile_tag, kind, app_id, "
      "app_display_name, device_display_name, pushkey, ts, lang, data, "
      "last_stream_ordering, last_success, failing_since, enabled "
      "FROM pushers WHERE enabled = 1");
  for (auto& row : rows) {
    json p;
    p["id"] = row.get<int64_t>(0);
    p["user_name"] = row.get<std::string>(1);
    if (!row.is_null(2)) p["access_token"] = row.get<std::string>(2);
    p["profile_tag"] = row.get<std::string>(3);
    p["kind"] = row.get<std::string>(4);
    p["app_id"] = row.get<std::string>(5);
    p["app_display_name"] = row.get<std::string>(6);
    if (!row.is_null(7)) p["device_display_name"] = row.get<std::string>(7);
    p["pushkey"] = row.get<std::string>(8);
    if (!row.is_null(11)) p["data"] = json::parse(row.get<std::string>(11));
    if (!row.is_null(14)) p["failing_since"] = row.get<int64_t>(14);
    p["enabled"] = row.get<int64_t>(15) != 0;
    result.push_back(p);
  }
  return result;
}

void PusherStore::set_pusher_enabled_txn(LoggingTransaction& txn,
                                          int64_t pusher_id, bool enabled) {
  txn.execute("UPDATE pushers SET enabled = ? WHERE id = ?",
              {enabled ? 1 : 0, pusher_id});
}

void PusherStore::set_throttle_txn(LoggingTransaction& txn,
                                    int64_t pusher_id,
                                    const std::string& room_id,
                                    int64_t throttle_ms) {
  int64_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  txn.execute(
      "INSERT INTO pusher_throttle (pusher, room_id, last_sent_ts, throttle_ms) "
      "VALUES (?, ?, ?, ?) ON CONFLICT (pusher, room_id) DO UPDATE SET "
      "last_sent_ts = excluded.last_sent_ts, throttle_ms = excluded.throttle_ms",
      {pusher_id, room_id, ts, throttle_ms});
}

bool PusherStore::is_throttled_txn(LoggingTransaction& txn,
                                    int64_t pusher_id, const std::string& room_id) {
  int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  auto row = txn.select_one(
      "SELECT last_sent_ts, throttle_ms FROM pusher_throttle "
      "WHERE pusher = ? AND room_id = ? AND last_sent_ts + throttle_ms > ?",
      {pusher_id, room_id, now});
  return row && !row->is_null();
}

// ====== SEARCH STORE (synapse/storage/databases/main/search.py - 939 lines) ======

void SearchStore::store_search_entries_txn(LoggingTransaction& txn,
                                            const std::vector<SearchEntry>& entries) {
  for (const auto& entry : entries) {
    txn.execute(
        "INSERT INTO event_search (event_id, room_id, sender, key, stream_ordering, "
        "origin_server_ts) VALUES (?, ?, ?, ?, ?, ?)",
        {entry.event_id, entry.room_id, entry.sender, entry.key,
         entry.stream_ordering, entry.origin_server_ts});
  }
}

std::vector<SearchEntry> SearchStore::search_msgs_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& search_term,
    int limit) {
  std::vector<SearchEntry> result;
  auto rows = txn.select(
      "SELECT event_id, room_id, key, stream_ordering, origin_server_ts "
      "FROM event_search WHERE room_id = ? AND key LIKE ? "
      "ORDER BY stream_ordering DESC LIMIT ?",
      {room_id, "%" + search_term + "%", limit});
  for (auto& row : rows) {
    SearchEntry se;
    se.event_id = row.get<std::string>(0);
    se.room_id = row.get<std::string>(1);
    se.key = row.get<std::string>(2);
    se.stream_ordering = row.get<int64_t>(3);
    se.origin_server_ts = row.get<int64_t>(4);
    result.push_back(se);
  }
  return result;
}

std::vector<SearchEntry> SearchStore::search_msgs_global_txn(
    LoggingTransaction& txn,
    const std::string& search_term,
    int limit) {
  std::vector<SearchEntry> result;
  auto rows = txn.select(
      "SELECT event_id, room_id, key, stream_ordering, origin_server_ts "
      "FROM event_search WHERE key LIKE ? "
      "ORDER BY stream_ordering DESC LIMIT ?",
      {"%" + search_term + "%", limit});
  for (auto& row : rows) {
    SearchEntry se;
    se.event_id = row.get<std::string>(0);
    se.room_id = row.get<std::string>(1);
    se.key = row.get<std::string>(2);
    se.stream_ordering = row.get<int64_t>(3);
    se.origin_server_ts = row.get<int64_t>(4);
    result.push_back(se);
  }
  return result;
}

void SearchStore::delete_search_entries_for_room_txn(LoggingTransaction& txn,
                                                      const std::string& room_id) {
  txn.execute("DELETE FROM event_search WHERE room_id = ?", {room_id});
}

// ====== TAGS STORE (synapse/storage/databases/main/tags.py) ======

void TagsStore::add_tag_to_room_txn(LoggingTransaction& txn,
                                     const std::string& user_id,
                                     const std::string& room_id,
                                     const std::string& tag,
                                     const json& content) {
  txn.execute(
      "INSERT INTO room_tags (user_id, room_id, tag, content) VALUES (?, ?, ?, ?) "
      "ON CONFLICT (user_id, room_id, tag) DO UPDATE SET content = excluded.content",
      {user_id, room_id, tag, content.dump()});
}

void TagsStore::remove_tag_from_room_txn(LoggingTransaction& txn,
                                          const std::string& user_id,
                                          const std::string& room_id,
                                          const std::string& tag) {
  txn.execute(
      "DELETE FROM room_tags WHERE user_id = ? AND room_id = ? AND tag = ?",
      {user_id, room_id, tag});
}

json TagsStore::get_tags_for_user_txn(LoggingTransaction& txn,
                                       const std::string& user_id,
                                       const std::string& room_id) {
  json result = json::object();
  auto rows = txn.select(
      "SELECT tag, content FROM room_tags WHERE user_id = ? AND room_id = ?",
      {user_id, room_id});
  for (auto& row : rows) {
    result[row.get<std::string>(0)] = json::parse(row.get<std::string>(1));
  }
  return result;
}

json TagsStore::get_all_user_tags_txn(LoggingTransaction& txn,
                                       const std::string& user_id) {
  json result = json::object();
  auto rows = txn.select(
      "SELECT room_id, tag, content FROM room_tags WHERE user_id = ?",
      {user_id});
  for (auto& row : rows) {
    std::string room_id = row.get<std::string>(0);
    if (!result.contains(room_id)) {
      result[room_id] = json::object();
    }
    result[room_id][row.get<std::string>(1)] = json::parse(row.get<std::string>(2));
  }
  return result;
}

// ====== ACCOUNT DATA STORE ======

void AccountDataStore::add_account_data_for_user_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& data_type,
    const json& content) {
  txn.execute(
      "INSERT INTO user_account_data (user_id, data_type, content) VALUES (?, ?, ?) "
      "ON CONFLICT (user_id, data_type) DO UPDATE SET content = excluded.content",
      {user_id, data_type, content.dump()});
}

void AccountDataStore::add_account_data_for_room_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& room_id,
    const std::string& data_type,
    const json& content) {
  txn.execute(
      "INSERT INTO room_account_data (user_id, room_id, account_data_type, content) "
      "VALUES (?, ?, ?, ?) "
      "ON CONFLICT (user_id, room_id, account_data_type) DO UPDATE SET "
      "content = excluded.content",
      {user_id, room_id, data_type, content.dump()});
}

json AccountDataStore::get_global_account_data_for_user_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  json result = json::object();
  auto rows = txn.select(
      "SELECT data_type, content FROM user_account_data WHERE user_id = ?",
      {user_id});
  for (auto& row : rows) {
    result[row.get<std::string>(0)] = json::parse(row.get<std::string>(1));
  }
  return result;
}

json AccountDataStore::get_account_data_for_room_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& room_id) {
  json result = json::object();
  auto rows = txn.select(
      "SELECT account_data_type, content FROM room_account_data "
      "WHERE user_id = ? AND room_id = ?", {user_id, room_id});
  for (auto& row : rows) {
    result[row.get<std::string>(0)] = json::parse(row.get<std::string>(1));
  }
  return result;
}

std::optional<json> AccountDataStore::get_account_data_for_user_and_type_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& data_type) {
  auto row = txn.select_one(
      "SELECT content FROM user_account_data WHERE user_id = ? AND data_type = ?",
      {user_id, data_type});
  if (row && !row->is_null()) {
    return json::parse(row->get<std::string>(0));
  }
  return std::nullopt;
}

// ====== RELATIONS STORE (synapse/storage/databases/main/relations.py - 1116 lines) ======

void RelationsStore::add_relation_txn(LoggingTransaction& txn,
                                       const std::string& event_id,
                                       const std::string& relates_to_id,
                                       const std::string& relation_type,
                                       const std::string& aggregation_key) {
  txn.execute(
      "INSERT INTO event_relations (event_id, relates_to_id, relation_type, aggregation_key) "
      "VALUES (?, ?, ?, ?)",
      {event_id, relates_to_id, relation_type, aggregation_key});
}

std::vector<json> RelationsStore::get_relations_for_event_txn(
    LoggingTransaction& txn,
    const std::string& event_id,
    const std::string& relation_type,
    const std::string& direction) {
  std::vector<json> result;
  
  std::string query;
  std::vector<DatabaseType> params;
  
  if (direction == "up") {
    // Events that relate TO this event
    query = "SELECT er.event_id, er.relation_type, er.aggregation_key "
            "FROM event_relations er JOIN events e ON er.event_id = e.event_id "
            "WHERE er.relates_to_id = ?";
    params.push_back(event_id);
  } else if (direction == "down") {
    // Events that this event relates TO
    query = "SELECT er.relates_to_id, er.relation_type, er.aggregation_key "
            "FROM event_relations er "
            "WHERE er.event_id = ?";
    params.push_back(event_id);
  } else {
    // Both directions
    query = "SELECT er.event_id, er.relates_to_id, er.relation_type, er.aggregation_key "
            "FROM event_relations er "
            "WHERE er.event_id = ? OR er.relates_to_id = ?";
    params.push_back(event_id);
    params.push_back(event_id);
  }
  
  if (!relation_type.empty()) {
    query += " AND er.relation_type = ?";
    params.push_back(relation_type);
  }
  
  query += " ORDER BY e.stream_ordering";
  
  auto rows = txn.select(query, params);
  for (auto& row : rows) {
    json rel;
    rel["event_id"] = row.get<std::string>(0);
    if (row.column_count() > 2) {
      rel["relates_to_id"] = row.get<std::string>(1);
      rel["relation_type"] = row.get<std::string>(2);
      if (!row.is_null(3)) rel["aggregation_key"] = row.get<std::string>(3);
    } else {
      rel["relation_type"] = row.get<std::string>(1);
      if (!row.is_null(2)) rel["aggregation_key"] = row.get<std::string>(2);
    }
    result.push_back(rel);
  }
  return result;
}

json RelationsStore::get_aggregation_groups_txn(
    LoggingTransaction& txn,
    const std::string& event_id,
    const std::string& relation_type) {
  json result = json::object();
  auto rows = txn.select(
      "SELECT aggregation_key, COUNT(*) as cnt FROM event_relations "
      "WHERE relates_to_id = ? AND relation_type = ? AND aggregation_key IS NOT NULL "
      "GROUP BY aggregation_key",
      {event_id, relation_type});
  for (auto& row : rows) {
    result[row.get<std::string>(0)] = row.get<int64_t>(1);
  }
  return result;
}

int64_t RelationsStore::get_relation_count_txn(
    LoggingTransaction& txn,
    const std::string& event_id,
    const std::string& relation_type) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM event_relations WHERE relates_to_id = ? AND relation_type = ?",
      {event_id, relation_type});
  return row ? row->get<int64_t>(0) : 0;
}

std::vector<std::string> RelationsStore::get_threads_for_user_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    int limit) {
  std::vector<std::string> result;
  auto rows = txn.select(
      "SELECT DISTINCT er.relates_to_id FROM event_relations er "
      "JOIN events e ON er.event_id = e.event_id "
      "WHERE er.relation_type = 'm.thread' AND e.sender = ? "
      "ORDER BY e.stream_ordering DESC LIMIT ?",
      {user_id, limit});
  for (auto& row : rows) {
    result.push_back(row.get<std::string>(0));
  }
  return result;
}

void RelationsStore::delete_relations_for_event_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  txn.execute("DELETE FROM event_relations WHERE event_id = ?", {event_id});
  txn.execute("DELETE FROM event_relations WHERE relates_to_id = ?", {event_id});
}

// ====== COMBINED SMALL STORES ======

SmallStores::SmallStores(DatabasePool& db_pool)
    : pusher_store(db_pool),
      search_store(db_pool),
      tags_store(db_pool),
      account_data_store(db_pool),
      relations_store(db_pool) {}

// ====== EVENT FORWARD EXTREMITIES STORE ======

std::vector<std::string> ForwardExtremitiesStore::get_forward_extremities_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  std::vector<std::string> result;
  auto rows = txn.select(
      "SELECT event_id FROM event_forward_extremities WHERE room_id = ?",
      {room_id});
  for (auto& row : rows) {
    result.push_back(row.get<std::string>(0));
  }
  return result;
}

void ForwardExtremitiesStore::delete_forward_extremities_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  txn.execute("DELETE FROM event_forward_extremities WHERE room_id = ?", {room_id});
}

void ForwardExtremitiesStore::replace_forward_extremities_for_room_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::vector<std::string>& event_ids) {
  txn.execute("DELETE FROM event_forward_extremities WHERE room_id = ?", {room_id});
  for (const auto& eid : event_ids) {
    txn.execute(
        "INSERT INTO event_forward_extremities (event_id, room_id) VALUES (?, ?)",
        {eid, room_id});
  }
}

// ====== EVENT FEDERATION STORE ======

std::vector<std::string> EventFederationStore::get_backfill_events_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    int limit) {
  std::vector<std::string> result;
  auto rows = txn.select(
      "SELECT event_id FROM event_backward_extremities WHERE room_id = ? LIMIT ?",
      {room_id, limit});
  for (auto& row : rows) {
    result.push_back(row.get<std::string>(0));
  }
  return result;
}

// ====== CLIENT IPS STORE ======

void ClientIpsStore::store_device_txn(LoggingTransaction& txn,
                                       const std::string& user_id,
                                       const std::string& device_id,
                                       const std::string& display_name,
                                       int64_t last_seen) {
  txn.execute(
      "INSERT INTO devices (user_id, device_id, display_name, last_seen) "
      "VALUES (?, ?, ?, ?) "
      "ON CONFLICT (user_id, device_id) DO UPDATE SET "
      "display_name = COALESCE(excluded.display_name, devices.display_name), "
      "last_seen = excluded.last_seen",
      {user_id, device_id, display_name, last_seen});
}

std::vector<json> ClientIpsStore::get_user_devices_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  std::vector<json> result;
  auto rows = txn.select(
      "SELECT user_id, device_id, display_name, last_seen, ip, user_agent, hidden "
      "FROM devices WHERE user_id = ? AND hidden = 0", {user_id});
  for (auto& row : rows) {
    json d;
    d["user_id"] = row.get<std::string>(0);
    d["device_id"] = row.get<std::string>(1);
    if (!row.is_null(2)) d["display_name"] = row.get<std::string>(2);
    if (!row.is_null(3)) d["last_seen"] = row.get<int64_t>(3);
    if (!row.is_null(4)) d["ip"] = row.get<std::string>(4);
    if (!row.is_null(5)) d["user_agent"] = row.get<std::string>(5);
    d["hidden"] = row.get<int64_t>(6) != 0;
    result.push_back(d);
  }
  return result;
}

// ====== DEVICE INBOX STORE ======

void DeviceInboxStore::add_messages_to_device_inbox_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& device_id,
    int64_t stream_id,
    const std::vector<json>& messages) {
  for (const auto& msg : messages) {
    txn.execute(
        "INSERT INTO device_inbox (user_id, device_id, stream_id, message_json) "
        "VALUES (?, ?, ?, ?)",
        {user_id, device_id, stream_id, msg.dump()});
  }
}

std::vector<json> DeviceInboxStore::get_messages_from_device_inbox_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& device_id,
    std::optional<int64_t> since_stream_id,
    int limit) {
  std::vector<json> result;
  std::string query = 
      "SELECT stream_id, message_json FROM device_inbox "
      "WHERE user_id = ? AND device_id = ?";
  std::vector<DatabaseType> params = {user_id, device_id};
  
  if (since_stream_id) {
    query += " AND stream_id > ?";
    params.push_back(*since_stream_id);
  }
  
  query += " ORDER BY stream_id ASC LIMIT ?";
  params.push_back(limit);
  
  auto rows = txn.select(query, params);
  for (auto& row : rows) {
    json msg = json::parse(row.get<std::string>(1));
    msg["stream_id"] = row.get<int64_t>(0);
    result.push_back(msg);
  }
  return result;
}

void DeviceInboxStore::delete_messages_for_device_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& device_id,
    int64_t up_to_stream_id) {
  txn.execute(
      "DELETE FROM device_inbox WHERE user_id = ? AND device_id = ? AND stream_id <= ?",
      {user_id, device_id, up_to_stream_id});
}

// ====== E2E ROOM KEYS STORE ======

void E2eRoomKeysStore::set_e2e_room_keys_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& room_id,
    const json& keys) {
  txn.execute(
      "INSERT INTO e2e_room_keys (user_id, room_id, keys_json) VALUES (?, ?, ?) "
      "ON CONFLICT (user_id, room_id) DO UPDATE SET keys_json = excluded.keys_json",
      {user_id, room_id, keys.dump()});
}

std::optional<json> E2eRoomKeysStore::get_e2e_room_keys_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& room_id) {
  auto row = txn.select_one(
      "SELECT keys_json FROM e2e_room_keys WHERE user_id = ? AND room_id = ?",
      {user_id, room_id});
  if (row && !row->is_null()) {
    return json::parse(row->get<std::string>(0));
  }
  return std::nullopt;
}

void E2eRoomKeysStore::delete_e2e_room_keys_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  txn.execute("DELETE FROM e2e_room_keys WHERE user_id = ?", {user_id});
}

// ====== MONTHLY ACTIVE USERS STORE ======

void MonthlyActiveUsersStore::upsert_monthly_active_user_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  int64_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  txn.execute(
      "INSERT INTO monthly_active_users (user_id, timestamp) VALUES (?, ?) "
      "ON CONFLICT (user_id) DO UPDATE SET timestamp = excluded.timestamp",
      {user_id, ts});
}

int64_t MonthlyActiveUsersStore::count_monthly_active_users_txn(
    LoggingTransaction& txn, int64_t since_ts) {
  auto row = txn.select_one(
      "SELECT COUNT(DISTINCT user_id) FROM monthly_active_users WHERE timestamp > ?",
      {since_ts});
  return row ? row->get<int64_t>(0) : 0;
}

// ====== EXPERIMENTAL FEATURES STORE ======

void ExperimentalFeaturesStore::set_experimental_feature_txn(
    LoggingTransaction& txn,
    const std::string& feature_name,
    bool enabled) {
  txn.execute(
      "INSERT INTO experimental_features (feature_name, enabled) VALUES (?, ?) "
      "ON CONFLICT (feature_name) DO UPDATE SET enabled = excluded.enabled",
      {feature_name, enabled ? 1 : 0});
}

bool ExperimentalFeaturesStore::is_experimental_feature_enabled_txn(
    LoggingTransaction& txn, const std::string& feature_name) {
  auto row = txn.select_one(
      "SELECT enabled FROM experimental_features WHERE feature_name = ?",
      {feature_name});
  return row && !row->is_null() && row->get<int64_t>(0) != 0;
}

// ====== LOCK STORE ======

void LockStore::acquire_lock_txn(LoggingTransaction& txn,
                                  const std::string& lock_name,
                                  const std::string& lock_key,
                                  int64_t timeout_ms) {
  int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  int64_t expires = now + timeout_ms;
  
  // Delete expired locks
  txn.execute("DELETE FROM locks WHERE expires_ts < ?", {now});
  
  // Try to acquire
  txn.execute(
      "INSERT INTO locks (lock_name, lock_key, expires_ts) VALUES (?, ?, ?) "
      "ON CONFLICT (lock_name) DO NOTHING",
      {lock_name, lock_key, expires});
}

void LockStore::release_lock_txn(LoggingTransaction& txn,
                                  const std::string& lock_name,
                                  const std::string& lock_key) {
  txn.execute(
      "DELETE FROM locks WHERE lock_name = ? AND lock_key = ?",
      {lock_name, lock_key});
}

bool LockStore::is_lock_held_txn(LoggingTransaction& txn,
                                  const std::string& lock_name,
                                  const std::string& lock_key) {
  int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  auto row = txn.select_one(
      "SELECT 1 FROM locks WHERE lock_name = ? AND lock_key = ? AND expires_ts > ?",
      {lock_name, lock_key, now});
  return row && !row->is_null();
}

// ====== CENSOR EVENTS STORE ======

void CensorEventsStore::add_censored_event_txn(LoggingTransaction& txn,
                                                 const std::string& event_id) {
  txn.execute("INSERT OR IGNORE INTO censored_events (event_id) VALUES (?)", {event_id});
}

bool CensorEventsStore::is_event_censored_txn(LoggingTransaction& txn,
                                                const std::string& event_id) {
  auto row = txn.select_one(
      "SELECT 1 FROM censored_events WHERE event_id = ?", {event_id});
  return row && !row->is_null();
}

// ====== PURGE EVENTS STORE ======

void PurgeEventsStore::purge_history_txn(LoggingTransaction& txn,
                                          const std::string& room_id,
                                          const std::string& token) {
  // Delete events older than the token
  txn.execute("DELETE FROM event_json WHERE room_id = ? AND event_id < ?", {room_id, token});
  txn.execute("DELETE FROM events WHERE room_id = ? AND event_id < ?", {room_id, token});
  txn.execute("DELETE FROM event_edges WHERE room_id = ? AND event_id < ?", {room_id, token});
  txn.execute("DELETE FROM event_auth WHERE room_id = ? AND event_id < ?", {room_id, token});
  txn.execute("DELETE FROM event_search WHERE room_id = ? AND event_id < ?", {room_id, token});
  txn.execute("DELETE FROM event_relations WHERE event_id IN (SELECT event_id FROM events WHERE room_id = ? AND event_id < ?)", {room_id, token});
}

// ====== SESSION STORE ======

void SessionStore::set_session_data_txn(LoggingTransaction& txn,
                                          const std::string& session_id,
                                          const json& data,
                                          int64_t expiry_ms) {
  int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  txn.execute(
      "INSERT INTO sessions (session_id, data, created_ms, expiry_ms) VALUES (?, ?, ?, ?) "
      "ON CONFLICT (session_id) DO UPDATE SET data = excluded.data, expiry_ms = excluded.expiry_ms",
      {session_id, data.dump(), now, expiry_ms});
}

std::optional<json> SessionStore::get_session_data_txn(
    LoggingTransaction& txn, const std::string& session_id) {
  int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  auto row = txn.select_one(
      "SELECT data FROM sessions WHERE session_id = ? AND expiry_ms > ?",
      {session_id, now});
  if (row && !row->is_null()) {
    return json::parse(row->get<std::string>(0));
  }
  return std::nullopt;
}

} // namespace progressive::storage
