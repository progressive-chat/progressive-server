#include "progressive/storage/databases/main/remaining_stores.hpp"
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

// ====== SLIDING SYNC STORE ======
// Translates synapse/storage/databases/main/sliding_sync.py (883 lines)

void SlidingSyncStore::add_sliding_sync_joined_room_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    int64_t bump_stamp,
    const std::optional<std::string>& room_type,
    const std::optional<bool>& is_encrypted,
    const std::optional<std::string>& room_name) {
  txn.execute(
      "INSERT INTO sliding_sync_joined_rooms (room_id, bump_stamp, room_type, is_encrypted, room_name) "
      "VALUES (?, ?, ?, ?, ?) "
      "ON CONFLICT (room_id) DO UPDATE SET bump_stamp = excluded.bump_stamp, "
      "room_type = COALESCE(excluded.room_type, sliding_sync_joined_rooms.room_type), "
      "is_encrypted = COALESCE(excluded.is_encrypted, sliding_sync_joined_rooms.is_encrypted), "
      "room_name = COALESCE(excluded.room_name, sliding_sync_joined_rooms.room_name)",
      {room_id, bump_stamp, room_type.value_or(""),
       is_encrypted ? (is_encrypted.value() ? "1" : "0") : std::optional<std::string>(),
       room_name.value_or("")});
}

void SlidingSyncStore::remove_sliding_sync_joined_room_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  txn.execute("DELETE FROM sliding_sync_joined_rooms WHERE room_id = ?", {room_id});
}

json SlidingSyncStore::get_sliding_sync_joined_rooms_txn(
    LoggingTransaction& txn, int64_t from_bump_stamp) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, bump_stamp, room_type, is_encrypted, room_name, "
      "tombstone_successor_room_id "
      "FROM sliding_sync_joined_rooms WHERE bump_stamp > ? "
      "ORDER BY bump_stamp DESC",
      {from_bump_stamp});
  for (auto& row : rows) {
    json r;
    r["room_id"] = row.get<std::string>(0);
    r["bump_stamp"] = row.get<int64_t>(1);
    if (!row.is_null(2)) r["room_type"] = row.get<std::string>(2);
    if (!row.is_null(3)) r["is_encrypted"] = row.get<int64_t>(3) != 0;
    if (!row.is_null(4)) r["room_name"] = row.get<std::string>(4);
    if (!row.is_null(5)) r["tombstone_successor_room_id"] = row.get<std::string>(5);
    result.push_back(r);
  }
  return result;
}

void SlidingSyncStore::add_sliding_sync_membership_snapshot_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& user_id,
    const std::string& sender,
    const std::string& membership_event_id,
    const std::string& membership,
    const std::optional<bool>& has_known_state,
    const std::optional<std::string>& room_type,
    const std::optional<bool>& is_encrypted,
    const std::optional<std::string>& room_name) {
  txn.execute(
      "INSERT INTO sliding_sync_membership_snapshots "
      "(room_id, user_id, sender, membership_event_id, membership, "
      "has_known_state, room_type, is_encrypted, room_name) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT (room_id, user_id) DO UPDATE SET "
      "sender = excluded.sender, "
      "membership_event_id = excluded.membership_event_id, "
      "membership = excluded.membership, "
      "has_known_state = COALESCE(excluded.has_known_state, "
      "sliding_sync_membership_snapshots.has_known_state), "
      "room_type = COALESCE(excluded.room_type, "
      "sliding_sync_membership_snapshots.room_type), "
      "is_encrypted = COALESCE(excluded.is_encrypted, "
      "sliding_sync_membership_snapshots.is_encrypted), "
      "room_name = COALESCE(excluded.room_name, "
      "sliding_sync_membership_snapshots.room_name)",
      {room_id, user_id, sender, membership_event_id, membership,
       has_known_state ? (has_known_state.value() ? "1" : "0") : std::optional<std::string>(),
       room_type.value_or(""),
       is_encrypted ? (is_encrypted.value() ? "1" : "0") : std::optional<std::string>(),
       room_name.value_or("")});
}

json SlidingSyncStore::get_sliding_sync_membership_snapshots_txn(
    LoggingTransaction& txn, const std::string& user_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, sender, membership_event_id, membership, has_known_state, "
      "room_type, is_encrypted, room_name, forgotten "
      "FROM sliding_sync_membership_snapshots WHERE user_id = ? LIMIT ?",
      {user_id, limit});
  for (auto& row : rows) {
    json s;
    s["room_id"] = row.get<std::string>(0);
    s["sender"] = row.get<std::string>(1);
    s["membership_event_id"] = row.get<std::string>(2);
    s["membership"] = row.get<std::string>(3);
    if (!row.is_null(4)) s["has_known_state"] = row.get<int64_t>(4) != 0;
    if (!row.is_null(5)) s["room_type"] = row.get<std::string>(5);
    if (!row.is_null(6)) s["is_encrypted"] = row.get<int64_t>(6) != 0;
    if (!row.is_null(7)) s["room_name"] = row.get<std::string>(7);
    s["forgotten"] = row.get<int64_t>(8) != 0;
    result.push_back(s);
  }
  return result;
}

// ====== STATS STORE ======
// Translates synapse/storage/databases/main/stats.py (789 lines)

json StatsStore::get_stats_txn(LoggingTransaction& txn) {
  json stats;
  
  auto total_users = txn.select_one("SELECT COUNT(*) FROM users");
  stats["total_users"] = total_users ? total_users->get<int64_t>(0) : 0;
  
  auto total_rooms = txn.select_one("SELECT COUNT(*) FROM rooms");
  stats["total_rooms"] = total_rooms ? total_rooms->get<int64_t>(0) : 0;
  
  auto total_events = txn.select_one("SELECT COUNT(*) FROM events");
  stats["total_events"] = total_events ? total_events->get<int64_t>(0) : 0;
  
  auto daily_active = txn.select_one(
      "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits WHERE timestamp > ?",
      {std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count() - 86400000});
  stats["daily_active_users"] = daily_active ? daily_active->get<int64_t>(0) : 0;
  
  auto monthly_active = txn.select_one(
      "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits WHERE timestamp > ?",
      {std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count() - 2592000000});
  stats["monthly_active_users"] = monthly_active ? monthly_active->get<int64_t>(0) : 0;
  
  auto total_non_guest = txn.select_one(
      "SELECT COUNT(*) FROM users WHERE is_guest = 0 AND deactivated = 0");
  stats["total_non_guest_users"] = total_non_guest ? total_non_guest->get<int64_t>(0) : 0;
  
  auto total_deactivated = txn.select_one(
      "SELECT COUNT(*) FROM users WHERE deactivated = 1");
  stats["total_deactivated_users"] = total_deactivated ? total_deactivated->get<int64_t>(0) : 0;
  
  auto private_rooms = txn.select_one(
      "SELECT COUNT(*) FROM rooms WHERE is_public = 0");
  stats["total_private_rooms"] = private_rooms ? private_rooms->get<int64_t>(0) : 0;
  
  auto db_size = txn.select_one(
      "SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()");
  if (db_size && !db_size->is_null()) {
    stats["database_size_bytes"] = db_size->get<int64_t>(0);
  }
  
  return stats;
}

json StatsStore::get_room_stats_txn(LoggingTransaction& txn, 
                                     const std::string& room_id) {
  json stats;
  
  auto members = txn.select(
      "SELECT membership, COUNT(*) as cnt FROM room_memberships "
      "WHERE room_id = ? GROUP BY membership", {room_id});
  for (auto& row : members) {
    stats[row.get<std::string>(0)] = row.get<int64_t>(1);
  }
  
  auto state_count = txn.select_one(
      "SELECT COUNT(*) FROM current_state_events WHERE room_id = ?", {room_id});
  stats["state_events"] = state_count ? state_count->get<int64_t>(0) : 0;
  
  auto forward_ext = txn.select_one(
      "SELECT COUNT(*) FROM event_forward_extremities WHERE room_id = ?", {room_id});
  stats["forward_extremities"] = forward_ext ? forward_ext->get<int64_t>(0) : 0;
  
  auto backward_ext = txn.select_one(
      "SELECT COUNT(*) FROM event_backward_extremities WHERE room_id = ?", {room_id});
  stats["backward_extremities"] = backward_ext ? backward_ext->get<int64_t>(0) : 0;
  
  auto depth = txn.select_one(
      "SELECT MIN(depth), MAX(depth) FROM events WHERE room_id = ?", {room_id});
  if (depth && !depth->is_null()) {
    stats["min_depth"] = depth->get<int64_t>(0);
    stats["max_depth"] = depth->get<int64_t>(1);
  }
  
  return stats;
}

void StatsStore::update_room_stats_txn(LoggingTransaction& txn,
                                        const std::string& room_id) {
  // Recalculate room stats from current data
  auto joined = txn.select_one(
      "SELECT COUNT(*) FROM room_memberships WHERE room_id = ? AND membership = 'join'",
      {room_id});
  auto invited = txn.select_one(
      "SELECT COUNT(*) FROM room_memberships WHERE room_id = ? AND membership = 'invite'",
      {room_id});
  auto left = txn.select_one(
      "SELECT COUNT(*) FROM room_memberships WHERE room_id = ? AND membership = 'leave'",
      {room_id});
  auto banned = txn.select_one(
      "SELECT COUNT(*) FROM room_memberships WHERE room_id = ? AND membership = 'ban'",
      {room_id});
  
  int64_t j = joined ? joined->get<int64_t>(0) : 0;
  int64_t i = invited ? invited->get<int64_t>(0) : 0;
  int64_t l = left ? left->get<int64_t>(0) : 0;
  int64_t b = banned ? banned->get<int64_t>(0) : 0;
  
  txn.execute(
      "INSERT INTO room_stats_state (room_id, joined_members, invited_members, "
      "left_members, banned_members, total_members) VALUES (?, ?, ?, ?, ?, ?) "
      "ON CONFLICT (room_id) DO UPDATE SET "
      "joined_members = excluded.joined_members, "
      "invited_members = excluded.invited_members, "
      "left_members = excluded.left_members, "
      "banned_members = excluded.banned_members, "
      "total_members = j + i + l + b",
      {room_id, j, i, l, b, j + i + l + b});
}

// ====== USER DIRECTORY STORE ======
// Translates synapse/storage/databases/main/user_directory.py (1330 lines)

void UserDirectoryStore::update_user_directory_txn(
    LoggingTransaction& txn,
    const std::string& user_id,
    const std::string& display_name,
    const std::string& avatar_url) {
  txn.execute(
      "INSERT INTO user_directory (user_id, display_name, avatar_url) "
      "VALUES (?, ?, ?) "
      "ON CONFLICT (user_id) DO UPDATE SET "
      "display_name = COALESCE(excluded.display_name, user_directory.display_name), "
      "avatar_url = COALESCE(excluded.avatar_url, user_directory.avatar_url)",
      {user_id, display_name, avatar_url});
}

void UserDirectoryStore::remove_from_user_directory_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  txn.execute("DELETE FROM user_directory WHERE user_id = ?", {user_id});
}

std::vector<json> UserDirectoryStore::search_users_in_directory_txn(
    LoggingTransaction& txn,
    const std::string& search_term,
    int limit) {
  std::vector<json> result;
  auto rows = txn.select(
      "SELECT ud.user_id, ud.display_name, ud.avatar_url, "
      "COUNT(rum.room_id) as shared_rooms "
      "FROM user_directory ud "
      "LEFT JOIN room_memberships rum ON ud.user_id = rum.user_id AND rum.membership = 'join' "
      "WHERE ud.display_name LIKE ? "
      "GROUP BY ud.user_id "
      "ORDER BY shared_rooms DESC LIMIT ?",
      {"%" + search_term + "%", limit});
  for (auto& row : rows) {
    json u;
    u["user_id"] = row.get<std::string>(0);
    u["display_name"] = row.get<std::string>(1);
    if (!row.is_null(2)) u["avatar_url"] = row.get<std::string>(2);
    result.push_back(u);
  }
  return result;
}

std::vector<json> UserDirectoryStore::search_users_in_public_rooms_txn(
    LoggingTransaction& txn, const std::string& search_term, int limit) {
  std::vector<json> result;
  auto rows = txn.select(
      "SELECT DISTINCT u.name, u.display_name, u.avatar_url "
      "FROM users u "
      "JOIN local_current_membership m ON u.name = m.user_id "
      "JOIN rooms r ON m.room_id = r.room_id "
      "WHERE r.is_public = 1 AND u.deactivated = 0 "
      "AND (u.display_name LIKE ? OR u.name LIKE ?) "
      "LIMIT ?",
      {"%" + search_term + "%", "%" + search_term + "%", limit});
  for (auto& row : rows) {
    json u;
    u["user_id"] = row.get<std::string>(0);
    u["display_name"] = row.get<std::string>(1);
    if (!row.is_null(2)) u["avatar_url"] = row.get<std::string>(2);
    result.push_back(u);
  }
  return result;
}

std::vector<json> UserDirectoryStore::get_users_in_room_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  std::vector<json> result;
  auto rows = txn.select(
      "SELECT u.name, u.display_name, u.avatar_url "
      "FROM users u "
      "JOIN local_current_membership m ON u.name = m.user_id "
      "WHERE m.room_id = ? AND m.membership = 'join' AND u.deactivated = 0",
      {room_id});
  for (auto& row : rows) {
    json u;
    u["user_id"] = row.get<std::string>(0);
    u["display_name"] = row.get<std::string>(1);
    if (!row.is_null(2)) u["avatar_url"] = row.get<std::string>(2);
    result.push_back(u);
  }
  return result;
}

std::vector<json> UserDirectoryStore::get_users_in_public_rooms_txn(
    LoggingTransaction& txn, int limit) {
  std::vector<json> result;
  auto rows = txn.select(
      "SELECT u.name, u.display_name, u.avatar_url, COUNT(m.room_id) as room_count "
      "FROM users u "
      "JOIN local_current_membership m ON u.name = m.user_id "
      "JOIN rooms r ON m.room_id = r.room_id "
      "WHERE r.is_public = 1 AND u.deactivated = 0 "
      "GROUP BY u.name ORDER BY room_count DESC LIMIT ?",
      {limit});
  for (auto& row : rows) {
    json u;
    u["user_id"] = row.get<std::string>(0);
    u["display_name"] = row.get<std::string>(1);
    if (!row.is_null(2)) u["avatar_url"] = row.get<std::string>(2);
    u["shared_rooms"] = row.get<int64_t>(3);
    result.push_back(u);
  }
  return result;
}

// ====== STATE DELTAS STORE ======

std::vector<json> StateDeltasStore::get_all_state_deltas_txn(
    LoggingTransaction& txn, int64_t from_stream_id, int64_t to_stream_id) {
  std::vector<json> result;
  auto rows = txn.select(
      "SELECT stream_id, room_id, type, state_key, event_id, prev_event_id "
      "FROM current_state_delta_stream "
      "WHERE stream_id > ? AND stream_id <= ? ORDER BY stream_id ASC",
      {from_stream_id, to_stream_id});
  for (auto& row : rows) {
    json d;
    d["stream_id"] = row.get<int64_t>(0);
    d["room_id"] = row.get<std::string>(1);
    d["type"] = row.get<std::string>(2);
    d["state_key"] = row.get<std::string>(3);
    if (!row.is_null(4) && !row.get<std::string>(4).empty())
      d["event_id"] = row.get<std::string>(4);
    if (!row.is_null(5) && !row.get<std::string>(5).empty())
      d["prev_event_id"] = row.get<std::string>(5);
    result.push_back(d);
  }
  return result;
}

// ====== OPENID STORE ======

void OpenIdStore::store_open_id_token_txn(
    LoggingTransaction& txn,
    const std::string& token,
    const std::string& user_id,
    int64_t expiry_ts) {
  txn.execute(
      "INSERT INTO open_id_tokens (token, user_id, expiry_ts) VALUES (?, ?, ?)",
      {token, user_id, expiry_ts});
}

std::optional<std::string> OpenIdStore::get_user_id_for_open_id_token_txn(
    LoggingTransaction& txn, const std::string& token) {
  int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  auto row = txn.select_one(
      "SELECT user_id FROM open_id_tokens WHERE token = ? AND expiry_ts > ?",
      {token, now});
  if (row && !row->is_null()) return row->get<std::string>(0);
  return std::nullopt;
}

// ====== SESSION STORE ======

void SessionStore::create_session_txn(
    LoggingTransaction& txn,
    const std::string& session_id,
    const json& session_data,
    int64_t expiry_ms) {
  int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  txn.execute(
      "INSERT INTO ui_auth_sessions (session_id, creation_time_ms, expiry_time_ms, "
      "server_data) VALUES (?, ?, ?, ?)",
      {session_id, now, now + expiry_ms, session_data.dump()});
}

std::optional<json> SessionStore::get_session_txn(
    LoggingTransaction& txn, const std::string& session_id) {
  int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  auto row = txn.select_one(
      "SELECT server_data FROM ui_auth_sessions "
      "WHERE session_id = ? AND expiry_time_ms > ?",
      {session_id, now});
  if (row && !row->is_null()) return json::parse(row->get<std::string>(0));
  return std::nullopt;
}

void SessionStore::update_session_txn(
    LoggingTransaction& txn,
    const std::string& session_id,
    const json& session_data) {
  txn.execute(
      "UPDATE ui_auth_sessions SET server_data = ? WHERE session_id = ?",
      {session_data.dump(), session_id});
}

void SessionStore::delete_session_txn(
    LoggingTransaction& txn, const std::string& session_id) {
  txn.execute("DELETE FROM ui_auth_sessions WHERE session_id = ?", {session_id});
}

// ====== UI AUTH STORE ======

void UiAuthStore::set_ui_auth_session_data_txn(
    LoggingTransaction& txn,
    const std::string& session_id,
    const std::string& key,
    const json& value) {
  json data = json::object();
  auto existing = txn.select_one(
      "SELECT server_data FROM ui_auth_sessions WHERE session_id = ?", {session_id});
  if (existing && !existing->is_null()) {
    data = json::parse(existing->get<std::string>(0));
  }
  data[key] = value;
  txn.execute(
      "INSERT INTO ui_auth_sessions (session_id, server_data) VALUES (?, ?) "
      "ON CONFLICT (session_id) DO UPDATE SET server_data = excluded.server_data",
      {session_id, data.dump()});
}

void UiAuthStore::mark_ui_auth_stage_complete_txn(
    LoggingTransaction& txn,
    const std::string& session_id,
    const std::string& stage_type,
    const std::string& result) {
  json data = json::object();
  auto existing = txn.select_one(
      "SELECT server_data FROM ui_auth_sessions WHERE session_id = ?", {session_id});
  if (existing && !existing->is_null()) {
    data = json::parse(existing->get<std::string>(0));
  }
  
  if (!data.contains("completed")) data["completed"] = json::array();
  data["completed"].push_back(stage_type);
  data["result_" + stage_type] = result;
  
  txn.execute(
      "UPDATE ui_auth_sessions SET server_data = ? WHERE session_id = ?",
      {data.dump(), session_id});
}

// ====== COMBINED REMAINING STORES ======

RemainingStores::RemainingStores(DatabasePool& db_pool)
    : sliding_sync_store(db_pool),
      stats_store(db_pool),
      state_deltas_store(db_pool),
      openid_store(db_pool),
      session_store(db_pool),
      ui_auth_store(db_pool),
      user_directory_store(db_pool) {}

} // namespace progressive::storage
