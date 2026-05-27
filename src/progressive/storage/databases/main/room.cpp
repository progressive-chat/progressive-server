#include "progressive/storage/databases/main/room.hpp"
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

// ============ Room SQL DDL ============
namespace room_sql {
static const char* ROOMS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS rooms (
    room_id TEXT NOT NULL PRIMARY KEY,
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    creator TEXT NOT NULL,
    room_version TEXT NOT NULL DEFAULT '1',
    has_auth_chain_index BOOLEAN NOT NULL DEFAULT FALSE
);
)SQL";

static const char* ROOM_ALIASES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS room_aliases (
    room_alias TEXT NOT NULL PRIMARY KEY,
    room_id TEXT NOT NULL,
    creator TEXT NOT NULL,
    CONSTRAINT room_aliases_fkey FOREIGN KEY (room_id) REFERENCES rooms (room_id)
);
CREATE INDEX IF NOT EXISTS room_aliases_room_idx ON room_aliases (room_id);
)SQL";

static const char* ROOM_DEPTH_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS room_depth (
    room_id TEXT NOT NULL PRIMARY KEY,
    min_depth BIGINT NOT NULL DEFAULT 0
);
)SQL";

static const char* ROOM_STATS_CURRENT_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS room_stats_current (
    room_id TEXT NOT NULL PRIMARY KEY,
    completed_delta_stream_id BIGINT NOT NULL DEFAULT 0
);
)SQL";

static const char* ROOM_STATS_EARLIEST_TOKEN = R"SQL(
CREATE TABLE IF NOT EXISTS room_stats_earliest_token (
    token BIGINT NOT NULL PRIMARY KEY
);
)SQL";

static const char* EVENT_REPORTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_reports (
    id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
    received_ts BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    reason TEXT,
    content TEXT
);
CREATE INDEX IF NOT EXISTS event_reports_room_idx ON event_reports (room_id);
CREATE INDEX IF NOT EXISTS event_reports_user_idx ON event_reports (user_id);
)SQL";

static const char* CURRENT_STATE_DELTA_STREAM_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS current_state_delta_stream (
    stream_id BIGINT NOT NULL PRIMARY KEY,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    event_id TEXT,
    prev_event_id TEXT
);
)SQL";

static const char* ROOM_RETENTION_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS room_retention (
    room_id TEXT NOT NULL PRIMARY KEY,
    event_id TEXT NOT NULL,
    min_lifetime BIGINT,
    max_lifetime BIGINT
);
)SQL";

static const char* ROOM_TAGS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS room_tags (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    content TEXT NOT NULL,
    CONSTRAINT room_tags_pkey PRIMARY KEY (user_id, room_id, tag)
);
)SQL";

static const char* ROOM_ACCOUNT_DATA_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS room_account_data (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    account_data_type TEXT NOT NULL,
    content TEXT NOT NULL,
    CONSTRAINT room_account_data_pkey PRIMARY KEY (user_id, room_id, account_data_type)
);
)SQL";

} // namespace room_sql

// ============ RoomStore Implementation ============

RoomStore::RoomStore(DatabasePool& db_pool, const std::string& server_name)
    : db_pool_(db_pool), server_name_(server_name) {}

// ---------- Room Creation and Management ----------

std::string RoomStore::store_room_txn(LoggingTransaction& txn,
                                       const std::string& room_id,
                                       const std::string& room_creator_id,
                                       bool is_public,
                                       const std::string& room_version) {
  txn.execute(
      "INSERT INTO rooms (room_id, is_public, creator, room_version) "
      "VALUES (?, ?, ?, ?)",
      {room_id, is_public ? 1 : 0, room_creator_id, room_version});
  return room_id;
}

bool RoomStore::room_exists_txn(LoggingTransaction& txn, const std::string& room_id) {
  auto row = txn.select_one("SELECT 1 FROM rooms WHERE room_id = ?", {room_id});
  return row && !row->is_null();
}

std::optional<std::string> RoomStore::get_room_version_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  auto row = txn.select_one(
      "SELECT room_version FROM rooms WHERE room_id = ?", {room_id});
  if (row && !row->is_null()) {
    return row->get<std::string>(0);
  }
  return std::nullopt;
}

void RoomStore::set_room_is_public_txn(LoggingTransaction& txn,
                                        const std::string& room_id,
                                        bool is_public) {
  txn.execute(
      "UPDATE rooms SET is_public = ? WHERE room_id = ?",
      {is_public ? 1 : 0, room_id});
}

void RoomStore::set_room_has_auth_chain_index_txn(LoggingTransaction& txn,
                                                    const std::string& room_id,
                                                    bool has_index) {
  txn.execute(
      "UPDATE rooms SET has_auth_chain_index = ? WHERE room_id = ?",
      {has_index ? 1 : 0, room_id});
}

std::vector<std::string> RoomStore::get_public_room_ids_txn(LoggingTransaction& txn) {
  std::vector<std::string> result;
  auto rows = txn.select("SELECT room_id FROM rooms WHERE is_public = 1");
  for (auto& row : rows) {
    if (!row.is_null()) result.push_back(row.get<std::string>(0));
  }
  return result;
}

// ---------- Room Aliases ----------

void RoomStore::create_room_alias_txn(LoggingTransaction& txn,
                                       const std::string& room_alias,
                                       const std::string& room_id,
                                       const std::string& creator) {
  txn.execute(
      "INSERT INTO room_aliases (room_alias, room_id, creator) VALUES (?, ?, ?)",
      {room_alias, room_id, creator});
}

void RoomStore::delete_room_alias_txn(LoggingTransaction& txn,
                                       const std::string& room_alias) {
  txn.execute("DELETE FROM room_aliases WHERE room_alias = ?", {room_alias});
}

std::optional<std::string> RoomStore::get_room_id_for_alias_txn(
    LoggingTransaction& txn, const std::string& room_alias) {
  auto row = txn.select_one(
      "SELECT room_id FROM room_aliases WHERE room_alias = ?", {room_alias});
  if (row && !row->is_null()) {
    return row->get<std::string>(0);
  }
  return std::nullopt;
}

std::vector<std::string> RoomStore::get_aliases_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  std::vector<std::string> result;
  auto rows = txn.select(
      "SELECT room_alias FROM room_aliases WHERE room_id = ?", {room_id});
  for (auto& row : rows) {
    if (!row.is_null()) result.push_back(row.get<std::string>(0));
  }
  return result;
}

std::string RoomStore::get_canonical_alias_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  // Get from current_state_events where type='m.room.canonical_alias' and state_key=''
  auto row = txn.select_one(
      "SELECT event_id FROM current_state_events "
      "WHERE room_id = ? AND type = 'm.room.canonical_alias' AND state_key = ''",
      {room_id});
  if (!row || row->is_null()) return "";
  
  // Get the content to extract alias
  auto content = txn.select_one(
      "SELECT json FROM event_json WHERE event_id = ?",
      {row->get<std::string>(0)});
  if (content && !content->is_null()) {
    json j = json::parse(content->get<std::string>(0));
    if (j.contains("alias") && j["alias"].is_string()) {
      return j["alias"].get<std::string>();
    }
  }
  return "";
}

// ---------- Room Depth ----------

int64_t RoomStore::get_min_depth_for_room_txn(LoggingTransaction& txn, 
                                                const std::string& room_id) {
  auto row = txn.select_one(
      "SELECT min_depth FROM room_depth WHERE room_id = ?", {room_id});
  if (row && !row->is_null()) {
    return row->get<int64_t>(0);
  }
  return 0;
}

void RoomStore::update_min_depth_for_room_txn(LoggingTransaction& txn,
                                               const std::string& room_id,
                                               int64_t depth) {
  txn.execute(
      "INSERT INTO room_depth (room_id, min_depth) VALUES (?, ?) "
      "ON CONFLICT (room_id) DO UPDATE SET min_depth = MIN(room_depth.min_depth, ?)",
      {room_id, depth, depth});
}

// ---------- Room Stats ----------

json RoomStore::get_room_stats_txn(LoggingTransaction& txn,
                                    const std::string& room_id) {
  auto row = txn.select_one(
      "SELECT name, topic, canonical_alias, joined_members, invited_members, "
      "left_members, banned_members, total_members, local_users_in_room, "
      "history_visibility, join_rules, guest_access, encryption, room_type, "
      "is_federatable FROM room_stats_state WHERE room_id = ?",
      {room_id});
  
  json stats;
  if (row && !row->is_null()) {
    stats["room_id"] = room_id;
    if (!row->is_null(0)) stats["name"] = row->get<std::string>(0);
    if (!row->is_null(1)) stats["topic"] = row->get<std::string>(1);
    if (!row->is_null(2)) stats["canonical_alias"] = row->get<std::string>(2);
    stats["joined_members"] = row->get<int64_t>(3);
    stats["invited_members"] = row->get<int64_t>(4);
    stats["left_members"] = row->get<int64_t>(5);
    stats["banned_members"] = row->get<int64_t>(6);
    stats["total_members"] = row->get<int64_t>(7);
    stats["local_users_in_room"] = row->get<int64_t>(8);
    if (!row->is_null(9)) stats["history_visibility"] = row->get<std::string>(9);
    if (!row->is_null(10)) stats["join_rules"] = row->get<std::string>(10);
    if (!row->is_null(11)) stats["guest_access"] = row->get<std::string>(11);
    if (!row->is_null(12)) stats["encryption"] = row->get<std::string>(12);
    if (!row->is_null(13)) stats["room_type"] = row->get<std::string>(13);
    stats["is_federatable"] = row->get<int64_t>(14) != 0;
  }
  return stats;
}

std::vector<json> RoomStore::get_room_stats_for_rooms_txn(
    LoggingTransaction& txn, const std::vector<std::string>& room_ids) {
  std::vector<json> result;
  if (room_ids.empty()) return result;
  
  std::string placeholders;
  std::vector<DatabaseType> params;
  for (size_t i = 0; i < room_ids.size(); ++i) {
    if (i > 0) placeholders += ", ";
    placeholders += "?";
    params.push_back(room_ids[i]);
  }
  
  auto rows = txn.select(
      "SELECT room_id, name, topic, canonical_alias, joined_members, "
      "invited_members, left_members, banned_members, total_members, "
      "local_users_in_room, history_visibility, join_rules, guest_access, "
      "encryption, room_type, is_federatable "
      "FROM room_stats_state WHERE room_id IN (" + placeholders + ")",
      params);
  
  for (auto& row : rows) {
    json stats;
    stats["room_id"] = row.get<std::string>(0);
    if (!row.is_null(1)) stats["name"] = row.get<std::string>(1);
    if (!row.is_null(2)) stats["topic"] = row.get<std::string>(2);
    if (!row.is_null(3)) stats["canonical_alias"] = row.get<std::string>(3);
    stats["joined_members"] = row.get<int64_t>(4);
    stats["invited_members"] = row.get<int64_t>(5);
    stats["left_members"] = row.get<int64_t>(6);
    stats["banned_members"] = row.get<int64_t>(7);
    stats["total_members"] = row.get<int64_t>(8);
    stats["local_users_in_room"] = row.get<int64_t>(9);
    if (!row.is_null(10)) stats["history_visibility"] = row.get<std::string>(10);
    if (!row.is_null(11)) stats["join_rules"] = row.get<std::string>(11);
    if (!row.is_null(12)) stats["guest_access"] = row.get<std::string>(12);
    if (!row.is_null(13)) stats["encryption"] = row.get<std::string>(13);
    if (!row.is_null(14)) stats["room_type"] = row.get<std::string>(14);
    stats["is_federatable"] = row.get<int64_t>(15) != 0;
    result.push_back(stats);
  }
  return result;
}

void RoomStore::update_room_stats_txn(LoggingTransaction& txn,
                                       const std::string& room_id,
                                       const json& stats) {
  // Gather all settable fields
  std::string set_clauses;
  std::vector<DatabaseType> params;
  
  auto add_field = [&](const std::string& col, const DatabaseType& val) {
    if (!set_clauses.empty()) set_clauses += ", ";
    set_clauses += col + " = ?";
    params.push_back(val);
  };
  
  if (stats.contains("name")) add_field("name", stats["name"].get<std::string>());
  if (stats.contains("topic")) add_field("topic", stats["topic"].get<std::string>());
  if (stats.contains("canonical_alias")) add_field("canonical_alias", stats["canonical_alias"].get<std::string>());
  if (stats.contains("joined_members")) add_field("joined_members", stats["joined_members"].get<int64_t>());
  if (stats.contains("invited_members")) add_field("invited_members", stats["invited_members"].get<int64_t>());
  if (stats.contains("left_members")) add_field("left_members", stats["left_members"].get<int64_t>());
  if (stats.contains("banned_members")) add_field("banned_members", stats["banned_members"].get<int64_t>());
  if (stats.contains("total_members")) add_field("total_members", stats["total_members"].get<int64_t>());
  if (stats.contains("local_users_in_room")) add_field("local_users_in_room", stats["local_users_in_room"].get<int64_t>());
  if (stats.contains("history_visibility")) add_field("history_visibility", stats["history_visibility"].get<std::string>());
  if (stats.contains("join_rules")) add_field("join_rules", stats["join_rules"].get<std::string>());
  if (stats.contains("guest_access")) add_field("guest_access", stats["guest_access"].get<std::string>());
  if (stats.contains("encryption")) add_field("encryption", stats["encryption"].get<std::string>());
  if (stats.contains("room_type")) add_field("room_type", stats["room_type"].get<std::string>());
  if (stats.contains("is_federatable")) add_field("is_federatable", stats["is_federatable"].get<bool>() ? 1 : 0);
  
  if (set_clauses.empty()) return;
  
  params.push_back(room_id);
  txn.execute(
      "INSERT INTO room_stats_state (room_id) VALUES (?) "
      "ON CONFLICT (room_id) DO NOTHING",
      {room_id});
  txn.execute(
      "UPDATE room_stats_state SET " + set_clauses + " WHERE room_id = ?",
      params);
}

void RoomStore::bulk_update_room_stats_txn(
    LoggingTransaction& txn,
    const std::vector<std::pair<std::string, json>>& updates) {
  for (const auto& [room_id, stats] : updates) {
    update_room_stats_txn(txn, room_id, stats);
  }
}

// ---------- Room Retention ----------

void RoomStore::set_room_retention_txn(LoggingTransaction& txn,
                                        const std::string& room_id,
                                        const std::string& event_id,
                                        std::optional<int64_t> min_lifetime,
                                        std::optional<int64_t> max_lifetime) {
  txn.execute(
      "INSERT INTO room_retention (room_id, event_id, min_lifetime, max_lifetime) "
      "VALUES (?, ?, ?, ?) "
      "ON CONFLICT (room_id) DO UPDATE SET "
      "event_id = excluded.event_id, "
      "min_lifetime = excluded.min_lifetime, "
      "max_lifetime = excluded.max_lifetime",
      {room_id, event_id,
       min_lifetime ? min_lifetime.value() : (int64_t)-1,
       max_lifetime ? max_lifetime.value() : (int64_t)-1});
}

std::optional<json> RoomStore::get_room_retention_txn(LoggingTransaction& txn,
                                                       const std::string& room_id) {
  auto row = txn.select_one(
      "SELECT event_id, min_lifetime, max_lifetime FROM room_retention WHERE room_id = ?",
      {room_id});
  if (row && !row->is_null()) {
    json result;
    result["event_id"] = row->get<std::string>(0);
    int64_t min_l = row->get<int64_t>(1);
    int64_t max_l = row->get<int64_t>(2);
    if (min_l >= 0) result["min_lifetime"] = min_l;
    if (max_l >= 0) result["max_lifetime"] = max_l;
    return result;
  }
  return std::nullopt;
}

// ---------- Room Tags ----------

void RoomStore::set_room_tag_txn(LoggingTransaction& txn,
                                  const std::string& user_id,
                                  const std::string& room_id,
                                  const std::string& tag,
                                  const json& content) {
  txn.execute(
      "INSERT INTO room_tags (user_id, room_id, tag, content) VALUES (?, ?, ?, ?) "
      "ON CONFLICT (user_id, room_id, tag) DO UPDATE SET content = excluded.content",
      {user_id, room_id, tag, content.dump()});
}

void RoomStore::delete_room_tag_txn(LoggingTransaction& txn,
                                     const std::string& user_id,
                                     const std::string& room_id,
                                     const std::string& tag) {
  txn.execute(
      "DELETE FROM room_tags WHERE user_id = ? AND room_id = ? AND tag = ?",
      {user_id, room_id, tag});
}

json RoomStore::get_room_tags_for_user_txn(LoggingTransaction& txn,
                                            const std::string& user_id,
                                            const std::string& room_id) {
  json result = json::object();
  auto rows = txn.select(
      "SELECT tag, content FROM room_tags WHERE user_id = ? AND room_id = ?",
      {user_id, room_id});
  for (auto& row : rows) {
    std::string tag = row.get<std::string>(0);
    json content = json::parse(row.get<std::string>(1));
    result[tag] = content;
  }
  return result;
}

// ---------- Room Account Data ----------

void RoomStore::set_room_account_data_txn(LoggingTransaction& txn,
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

json RoomStore::get_room_account_data_txn(LoggingTransaction& txn,
                                           const std::string& user_id,
                                           const std::string& room_id,
                                           const std::string& data_type) {
  auto row = txn.select_one(
      "SELECT content FROM room_account_data WHERE user_id = ? AND room_id = ? AND account_data_type = ?",
      {user_id, room_id, data_type});
  if (row && !row->is_null()) {
    return json::parse(row->get<std::string>(0));
  }
  return json::object();
}

// ---------- Room Visibility ----------

std::vector<json> RoomStore::get_rooms_paginate_txn(
    LoggingTransaction& txn, int64_t start, int64_t limit,
    const std::string& order_by,
    const std::string& search_term,
    const std::string& server_name) {
  std::vector<json> result;
  
  std::string query = 
      "SELECT r.room_id, r.is_public, r.creator, r.room_version, "
      "rs.name, rs.topic, rs.canonical_alias, rs.joined_members, "
      "rs.invited_members, rs.left_members, rs.banned_members, "
      "rs.total_members, rs.local_users_in_room, rs.room_type, "
      "rs.is_federatable "
      "FROM rooms r "
      "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id "
      "WHERE r.is_public = 1";
  
  std::vector<DatabaseType> params;
  if (!search_term.empty()) {
    query += " AND (rs.name LIKE ? OR rs.topic LIKE ? OR rs.canonical_alias LIKE ?)";
    std::string st = "%" + search_term + "%";
    params.push_back(st);
    params.push_back(st);
    params.push_back(st);
  }
  
  if (!server_name.empty()) {
    // Filter by server name in room alias
    query += " AND EXISTS (SELECT 1 FROM room_aliases ra WHERE ra.room_id = r.room_id AND ra.room_alias LIKE ?)";
    params.push_back("%" + server_name + "%");
  }
  
  // Order
  if (order_by == "joined_members") {
    query += " ORDER BY rs.joined_members DESC";
  } else if (order_by == "total_members") {
    query += " ORDER BY rs.total_members DESC";
  } else if (order_by == "name") {
    query += " ORDER BY rs.name ASC";
  } else {
    query += " ORDER BY rs.joined_members DESC";
  }
  
  query += " LIMIT ? OFFSET ?";
  params.push_back(limit);
  params.push_back(start);
  
  auto rows = txn.select(query, params);
  for (auto& row : rows) {
    json r;
    r["room_id"] = row.get<std::string>(0);
    r["is_public"] = row.get<int64_t>(1) != 0;
    r["creator"] = row.get<std::string>(2);
    r["room_version"] = row.get<std::string>(3);
    if (!row.is_null(4)) r["name"] = row.get<std::string>(4);
    if (!row.is_null(5)) r["topic"] = row.get<std::string>(5);
    if (!row.is_null(6)) r["canonical_alias"] = row.get<std::string>(6);
    r["joined_members"] = row.get<int64_t>(7);
    r["invited_members"] = row.get<int64_t>(8);
    r["left_members"] = row.get<int64_t>(9);
    r["banned_members"] = row.get<int64_t>(10);
    r["total_members"] = row.get<int64_t>(11);
    r["local_users_in_room"] = row.get<int64_t>(12);
    if (!row.is_null(13)) r["room_type"] = row.get<std::string>(13);
    r["is_federatable"] = row.get<int64_t>(14) != 0;
    result.push_back(r);
  }
  
  return result;
}

int64_t RoomStore::count_public_rooms_txn(LoggingTransaction& txn) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM rooms WHERE is_public = 1");
  if (row && !row->is_null()) return row->get<int64_t>(0);
  return 0;
}

// ---------- Event Reports ----------

int64_t RoomStore::add_event_report_txn(LoggingTransaction& txn,
                                         const std::string& room_id,
                                         const std::string& event_id,
                                         const std::string& user_id,
                                         const std::string& reason,
                                         const json& content,
                                         int64_t received_ts) {
  txn.execute(
      "INSERT INTO event_reports "
      "(received_ts, room_id, event_id, user_id, reason, content) "
      "VALUES (?, ?, ?, ?, ?, ?)",
      {received_ts, room_id, event_id, user_id, reason, 
       content.is_null() ? "" : content.dump()});
  
  auto id_row = txn.select_one("SELECT last_insert_rowid()");
  return id_row ? id_row->get<int64_t>(0) : 0;
}

std::vector<json> RoomStore::get_event_reports_txn(LoggingTransaction& txn,
                                                     int64_t limit, int64_t offset,
                                                     const std::string& user_id,
                                                     const std::string& room_id) {
  std::vector<json> result;
  
  std::string query = "SELECT id, received_ts, room_id, event_id, user_id, reason, content "
      "FROM event_reports WHERE 1=1";
  std::vector<DatabaseType> params;
  
  if (!user_id.empty()) {
    query += " AND user_id = ?";
    params.push_back(user_id);
  }
  if (!room_id.empty()) {
    query += " AND room_id = ?";
    params.push_back(room_id);
  }
  
  query += " ORDER BY received_ts DESC LIMIT ? OFFSET ?";
  params.push_back(limit);
  params.push_back(offset);
  
  auto rows = txn.select(query, params);
  for (auto& row : rows) {
    json r;
    r["id"] = row.get<int64_t>(0);
    r["received_ts"] = row.get<int64_t>(1);
    r["room_id"] = row.get<std::string>(2);
    r["event_id"] = row.get<std::string>(3);
    r["user_id"] = row.get<std::string>(4);
    if (!row.is_null(5)) r["reason"] = row.get<std::string>(5);
    if (!row.is_null(6)) r["content"] = json::parse(row.get<std::string>(6));
    result.push_back(r);
  }
  return result;
}

// ---------- Room Purge ----------

void RoomStore::purge_room_txn(LoggingTransaction& txn, const std::string& room_id) {
  // Delete everything related to a room
  txn.execute("DELETE FROM event_json WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM events WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM event_edges WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM event_auth WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM state_events WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM current_state_events WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM room_memberships WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM local_current_membership WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM event_forward_extremities WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM event_backward_extremities WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM event_relations WHERE room_id IN "
      "(SELECT event_id FROM events WHERE room_id = ?)", {room_id});
  txn.execute("DELETE FROM event_search WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM event_reports WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM room_aliases WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM room_tags WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM room_account_data WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM room_stats_state WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM room_depth WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM rooms WHERE room_id = ?", {room_id});
}

// ---------- Current State Deltas ----------

void RoomStore::record_state_delta_txn(LoggingTransaction& txn,
                                        int64_t stream_id,
                                        const std::string& room_id,
                                        const std::string& type,
                                        const std::string& state_key,
                                        const std::string* event_id,
                                        const std::string* prev_event_id) {
  txn.execute(
      "INSERT INTO current_state_delta_stream "
      "(stream_id, room_id, type, state_key, event_id, prev_event_id) "
      "VALUES (?, ?, ?, ?, ?, ?)",
      {stream_id, room_id, type, state_key,
       event_id ? *event_id : std::string(""),
       prev_event_id ? *prev_event_id : std::string("")});
}

std::vector<json> RoomStore::get_current_state_deltas_txn(
    LoggingTransaction& txn, int64_t from_stream, int64_t to_stream) {
  std::vector<json> result;
  auto rows = txn.select(
      "SELECT stream_id, room_id, type, state_key, event_id, prev_event_id "
      "FROM current_state_delta_stream "
      "WHERE stream_id > ? AND stream_id <= ? "
      "ORDER BY stream_id ASC",
      {from_stream, to_stream});
  for (auto& row : rows) {
    json delta;
    delta["stream_id"] = row.get<int64_t>(0);
    delta["room_id"] = row.get<std::string>(1);
    delta["type"] = row.get<std::string>(2);
    delta["state_key"] = row.get<std::string>(3);
    if (!row.is_null(4) && !row.get<std::string>(4).empty())
      delta["event_id"] = row.get<std::string>(4);
    if (!row.is_null(5) && !row.get<std::string>(5).empty())
      delta["prev_event_id"] = row.get<std::string>(5);
    result.push_back(delta);
  }
  return result;
}

// ---------- Room Uniqueness ----------

bool RoomStore::is_room_blocked_txn(LoggingTransaction& txn,
                                     const std::string& room_id) {
  auto row = txn.select_one(
      "SELECT 1 FROM blocked_rooms WHERE room_id = ?", {room_id});
  return row && !row->is_null();
}

void RoomStore::block_room_txn(LoggingTransaction& txn,
                                const std::string& room_id,
                                const std::string& user_id) {
  txn.execute(
      "INSERT OR IGNORE INTO blocked_rooms (room_id, blocked_by) VALUES (?, ?)",
      {room_id, user_id});
}

void RoomStore::unblock_room_txn(LoggingTransaction& txn,
                                  const std::string& room_id) {
  txn.execute("DELETE FROM blocked_rooms WHERE room_id = ?", {room_id});
}

// ---------- Room Predecessor ----------

std::optional<std::string> RoomStore::get_predecessor_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  // Look for m.room.tombstone in room state
  auto row = txn.select_one(
      "SELECT event_id FROM current_state_events "
      "WHERE room_id = ? AND type = 'm.room.tombstone' AND state_key = ''",
      {room_id});
  if (!row || row->is_null()) return std::nullopt;
  
  auto content_row = txn.select_one(
      "SELECT json FROM event_json WHERE event_id = ?",
      {row->get<std::string>(0)});
  if (content_row && !content_row->is_null()) {
    json j = json::parse(content_row->get<std::string>(0));
    if (j.contains("replacement_room") && j["replacement_room"].is_string()) {
      return j["replacement_room"].get<std::string>();
    }
  }
  return std::nullopt;
}

bool RoomStore::room_has_space_child_txn(LoggingTransaction& txn,
                                          const std::string& room_id,
                                          const std::string& child_room_id) {
  auto row = txn.select_one(
      "SELECT event_id FROM current_state_events "
      "WHERE room_id = ? AND type = 'm.space.child' AND state_key = ?",
      {room_id, child_room_id});
  return row && !row->is_null();
}

std::vector<std::string> RoomStore::get_space_children_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  std::vector<std::string> result;
  auto rows = txn.select(
      "SELECT state_key FROM current_state_events "
      "WHERE room_id = ? AND type = 'm.space.child'",
      {room_id});
  for (auto& row : rows) {
    if (!row.is_null()) result.push_back(row.get<std::string>(0));
  }
  return result;
}

// ---------- Room Forgetting ----------

void RoomStore::forget_room_txn(LoggingTransaction& txn,
                                 const std::string& user_id,
                                 const std::string& room_id) {
  // Mark room membership as forgotten
  txn.execute(
      "UPDATE room_memberships SET forgotten = 1 "
      "WHERE room_id = ? AND user_id = ? AND membership = 'leave'",
      {room_id, user_id});
  
  // Remove from local_current_membership
  txn.execute(
      "DELETE FROM local_current_membership WHERE room_id = ? AND user_id = ?",
      {room_id, user_id});
}

std::vector<std::string> RoomStore::get_forgotten_rooms_for_user_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  std::vector<std::string> result;
  auto rows = txn.select(
      "SELECT room_id FROM room_memberships WHERE user_id = ? AND forgotten = 1",
      {user_id});
  for (auto& row : rows) {
    if (!row.is_null()) result.push_back(row.get<std::string>(0));
  }
  return result;
}

} // namespace progressive::storage
