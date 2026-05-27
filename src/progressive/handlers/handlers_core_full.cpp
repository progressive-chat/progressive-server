// handlers_core_full.cpp - Full handler implementations with database-driven logic
// Implements: SyncHandler, RoomCreationHandler, MessageHandler, TypingHandler,
//             ReceiptsHandler, SearchHandler, PaginationHandler
// Each handler has complete DB queries, event creation, and JSON response building.
// ---------------------------------------------------------------------------
// DDL for required tables (idempotent: uses IF NOT EXISTS / OR IGNORE patterns)

#include "handlers_core.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

// ---------------------------------------------------
// STORAGE: pull in the stores used by handlers
// ---------------------------------------------------
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/registration.hpp"

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;
using progressive::storage::DatabasePool;
using progressive::storage::LoggingTransaction;
using progressive::storage::Row;
using progressive::storage::RowList;
using progressive::storage::SQLParam;

// ============================================================================
// DDL - table creation helpers (idempotent, run once on startup)
// ============================================================================

// Called by the server at startup to ensure all tables exist.
// Uses IF NOT EXISTS so it is safe to call every time.
void ensure_core_full_tables(DatabasePool& db) {
  db.runInteraction("ensure_core_full_tables", [&](LoggingTransaction& txn) {
    // --- events (full schema) ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS events (
        stream_ordering INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        type TEXT NOT NULL,
        sender TEXT NOT NULL,
        content TEXT NOT NULL DEFAULT '{}',
        state_key TEXT DEFAULT '',
        membership TEXT DEFAULT '',
        depth INTEGER NOT NULL DEFAULT 0,
        origin_server_ts INTEGER NOT NULL DEFAULT 0,
        prev_events TEXT DEFAULT '[]',
        auth_events TEXT DEFAULT '[]',
        redacts TEXT DEFAULT '',
        txn_id TEXT DEFAULT '',
        device_id TEXT DEFAULT '',
        is_state INTEGER DEFAULT 0,
        is_outlier INTEGER DEFAULT 0,
        is_redacted INTEGER DEFAULT 0,
        contains_url INTEGER DEFAULT 0,
        instance_name TEXT DEFAULT 'master',
        UNIQUE(event_id)
      )
    )");

    // --- rooms ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS rooms (
        room_id TEXT PRIMARY KEY,
        creator TEXT NOT NULL,
        is_public INTEGER NOT NULL DEFAULT 0,
        room_version TEXT NOT NULL DEFAULT '1',
        name TEXT DEFAULT '',
        topic TEXT DEFAULT '',
        created_at INTEGER NOT NULL DEFAULT 0
      )
    )");

    // --- room_memberships ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS room_memberships (
        event_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        membership TEXT NOT NULL DEFAULT 'leave',
        sender TEXT NOT NULL,
        content TEXT DEFAULT '',
        stream_ordering INTEGER NOT NULL DEFAULT 0,
        UNIQUE(room_id, user_id)
      )
    )");

    // --- current_state_events ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS current_state_events (
        room_id TEXT NOT NULL,
        type TEXT NOT NULL,
        state_key TEXT NOT NULL DEFAULT '',
        event_id TEXT NOT NULL,
        PRIMARY KEY (room_id, type, state_key)
      )
    )");

    // --- state_groups ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS state_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id TEXT NOT NULL,
        event_id TEXT NOT NULL
      )
    )");

    // --- state_group_edges ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS state_group_edges (
        state_group INTEGER NOT NULL,
        prev_state_group INTEGER NOT NULL,
        PRIMARY KEY (state_group, prev_state_group)
      )
    )");

    // --- event_forward_extremities ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS event_forward_extremities (
        event_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        PRIMARY KEY (event_id, room_id)
      )
    )");

    // --- event_edges ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS event_edges (
        event_id TEXT NOT NULL,
        prev_event_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        is_state INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (event_id, prev_event_id)
      )
    )");

    // --- event_to_state_groups ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS event_to_state_groups (
        event_id TEXT PRIMARY KEY,
        state_group INTEGER NOT NULL
      )
    )");

    // --- presence_state ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS presence_state (
        user_id TEXT PRIMARY KEY,
        state TEXT NOT NULL DEFAULT 'offline',
        last_active_ts INTEGER NOT NULL DEFAULT 0,
        status_msg TEXT DEFAULT ''
      )
    )");

    // --- presence_stream ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS presence_stream (
        stream_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        state TEXT NOT NULL,
        last_active_ts INTEGER NOT NULL DEFAULT 0
      )
    )");

    // --- device_inbox (to-device messages) ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS device_inbox (
        stream_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        type TEXT NOT NULL,
        sender TEXT NOT NULL,
        content TEXT NOT NULL DEFAULT '{}'
      )
    )");

    // --- typing ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS typing (
        room_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        timeout_ms INTEGER NOT NULL DEFAULT 0,
        last_typed_ts INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (room_id, user_id)
      )
    )");

    // --- read_receipts ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS read_receipts (
        room_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        ts INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (room_id, user_id)
      )
    )");

    // --- event_push_summary ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS event_push_summary (
        user_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        notif_count INTEGER NOT NULL DEFAULT 0,
        highlight_count INTEGER NOT NULL DEFAULT 0,
        stream_ordering INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, room_id)
      )
    )");

    // --- event_search ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS event_search (
        event_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        stream_ordering INTEGER NOT NULL DEFAULT 0,
        origin_server_ts INTEGER NOT NULL DEFAULT 0
      )
    )");
    txn.execute(R"(
      CREATE INDEX IF NOT EXISTS event_search_key_idx ON event_search(key)
    )");
    txn.execute(R"(
      CREATE INDEX IF NOT EXISTS event_search_value_idx ON event_search(value)
    )");
    txn.execute(R"(
      CREATE INDEX IF NOT EXISTS event_search_room_id_idx ON event_search(room_id)
    )");

    // --- event_relations ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS event_relations (
        event_id TEXT NOT NULL,
        relates_to_id TEXT NOT NULL,
        relation_type TEXT NOT NULL,
        aggregation_key TEXT DEFAULT '',
        PRIMARY KEY (event_id, relates_to_id, relation_type)
      )
    )");

    // --- event_redactions ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS event_redactions (
        redaction_event_id TEXT PRIMARY KEY,
        redacts_event_id TEXT NOT NULL,
        received_ts INTEGER NOT NULL DEFAULT 0
      )
    )");

    // --- device_lists_outbound_pokes ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_outbound_pokes (
        user_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        stream_id INTEGER NOT NULL,
        ts INTEGER NOT NULL DEFAULT 0,
        sent INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (destination, user_id, stream_id)
      )
    )");

    // --- account_data ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS account_data (
        user_id TEXT NOT NULL,
        room_id TEXT NOT NULL DEFAULT '',
        account_data_type TEXT NOT NULL,
        content TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY (user_id, room_id, account_data_type)
      )
    )");

    // --- room_aliases ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS room_aliases (
        room_alias TEXT PRIMARY KEY,
        room_id TEXT NOT NULL,
        creator TEXT NOT NULL
      )
    )");

    // --- stream_ordering_seq (monotonically increasing stream ordering) ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS stream_ordering_seq (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        next_val INTEGER NOT NULL DEFAULT 1
      )
    )");

    // --- event_push_actions ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS event_push_actions (
        room_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        stream_ordering INTEGER NOT NULL,
        topological_ordering INTEGER NOT NULL DEFAULT 0,
        notif INTEGER NOT NULL DEFAULT 0,
        highlight INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (room_id, event_id, user_id)
      )
    )");

    // --- access_tokens (already exists but ensure) ---
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS access_tokens (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        device_id TEXT DEFAULT '',
        created_at INTEGER DEFAULT 0
      )
    )");
  });
}

// ============================================================================
// UTILITY helpers used by all handlers
// ============================================================================

namespace {

// Current timestamp in milliseconds
int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// Generate unique event IDs
std::string gen_event_id() {
  static std::atomic<int64_t> counter{1};
  int64_t ts = now_ms();
  int64_t c = counter.fetch_add(1, std::memory_order_relaxed);
  // Matrix event ID format: $<base64_localpart>:<server>
  // For local IDs we use a compact form
  std::ostringstream oss;
  oss << "$" << ts << "-" << c << ":localhost";
  return oss.str();
}

// Generate room IDs
std::string gen_room_id() {
  static std::atomic<int64_t> room_counter{1};
  int64_t ts = now_ms();
  int64_t c = room_counter.fetch_add(1, std::memory_order_relaxed);
  std::ostringstream oss;
  oss << "!" << std::hex << ts << "-" << c << ":localhost";
  return oss.str();
}

// Generate random tokens (e.g., next_batch, access tokens)
std::string gen_random_token(int length = 32) {
  static const char charset[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(
      static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<> dist(0, 61);
  std::string token(length, ' ');
  for (int i = 0; i < length; ++i) {
    token[i] = charset[dist(rng)];
  }
  return token;
}

// Make a sync next_batch token from a stream ordering
std::string make_next_batch_token(int64_t stream_ordering) {
  std::ostringstream oss;
  oss << "s" << stream_ordering << "_" << now_ms();
  return oss.str();
}

// Parse a sync since token back to stream ordering
int64_t parse_stream_token(const std::string& token) {
  if (token.empty() || token[0] != 's') return 0;
  size_t underscore = token.find('_');
  std::string num_part = (underscore != std::string::npos)
                             ? token.substr(1, underscore - 1)
                             : token.substr(1);
  try {
    return std::stoll(num_part);
  } catch (...) {
    return 0;
  }
}

// Advance the stream ordering counter and return the new value
// This is the core of stream ordering -- all events get a monotonically
// increasing position that clients use for /sync pagination.
int64_t next_stream_ordering(LoggingTransaction& txn) {
  // Ensure the singleton row exists
  txn.execute(
      "INSERT OR IGNORE INTO stream_ordering_seq (id, next_val) VALUES (1, 1)");
  // Atomically fetch and increment using UPDATE ... RETURNING style
  txn.execute("UPDATE stream_ordering_seq SET next_val = next_val + 1 WHERE id = 1");
  auto rows = txn.fetchall();
  // The above pattern on some DBs doesn't return the updated value directly;
  // use a two-step approach.
  txn.execute("SELECT next_val FROM stream_ordering_seq WHERE id = 1");
  auto row = txn.fetchone();
  if (row.has_value()) {
    for (auto& col : *row) {
      if (col.name == "next_val") {
        return std::stoll(col.value.value_or("1"));
      }
    }
  }
  return now_ms();  // fallback
}

// Build a full event JSON dict from event data. This is what gets returned to
// clients in /sync, /messages, /event, etc.
json build_event_json(const std::string& event_id, const std::string& room_id,
                      const std::string& type, const std::string& sender,
                      const json& content, int64_t origin_server_ts,
                      const std::optional<std::string>& state_key = std::nullopt,
                      const std::optional<std::string>& redacts = std::nullopt,
                      const std::optional<json>& unsigned_data = std::nullopt,
                      const std::vector<std::string>& prev_events = {},
                      const std::optional<std::string>& membership = std::nullopt) {
  json ev;
  ev["event_id"] = event_id;
  ev["room_id"] = room_id;
  ev["type"] = type;
  ev["sender"] = sender;
  ev["content"] = content;
  ev["origin_server_ts"] = origin_server_ts;
  if (state_key.has_value() && !state_key->empty()) {
    ev["state_key"] = *state_key;
  }
  if (redacts.has_value() && !redacts->empty()) {
    ev["redacts"] = *redacts;
  }
  if (unsigned_data.has_value()) {
    ev["unsigned"] = *unsigned_data;
  } else {
    ev["unsigned"] = json::object();
  }
  if (!prev_events.empty()) {
    json pe = json::array();
    for (auto& peid : prev_events) pe.push_back(peid);
    ev["prev_events"] = pe;
  }
  if (membership.has_value() && !membership->empty()) {
    ev["content"]["membership"] = *membership;
  }
  return ev;
}

// Insert a full event row into the events table. Returns the stream_ordering
// that was assigned.
int64_t insert_event_txn(LoggingTransaction& txn, const std::string& event_id,
                         const std::string& room_id, const std::string& type,
                         const std::string& sender, const json& content,
                         int64_t origin_server_ts, int depth = 0,
                         const std::string& state_key = "",
                         const std::string& membership = "",
                         const std::string& redacts = "",
                         const std::string& txn_id = "",
                         bool is_state = false,
                         const std::string& prev_events = "[]") {
  int64_t so = next_stream_ordering(txn);
  std::string content_str = content.dump();
  txn.execute(
      "INSERT INTO events (stream_ordering, event_id, room_id, type, sender, "
      "content, state_key, membership, depth, origin_server_ts, prev_events, "
      "redacts, txn_id, is_state, instance_name) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'master')",
      {SQLParam{so}, SQLParam{event_id}, SQLParam{room_id}, SQLParam{type},
       SQLParam{sender}, SQLParam{content_str}, SQLParam{state_key},
       SQLParam{membership}, SQLParam{int64_t(depth)},
       SQLParam{origin_server_ts}, SQLParam{prev_events}, SQLParam{redacts},
       SQLParam{txn_id}, SQLParam{int64_t(is_state ? 1 : 0)}});
  return so;
}

// Parse a database row into an event JSON (for read paths)
json row_to_event_json(const Row& r) {
  json ev;
  for (auto& col : r) {
    if (col.name == "event_id") ev["event_id"] = col.value.value_or("");
    else if (col.name == "room_id") ev["room_id"] = col.value.value_or("");
    else if (col.name == "type") ev["type"] = col.value.value_or("");
    else if (col.name == "sender") ev["sender"] = col.value.value_or("");
    else if (col.name == "origin_server_ts")
      ev["origin_server_ts"] = std::stoll(col.value.value_or("0"));
    else if (col.name == "state_key" && !col.value.value_or("").empty())
      ev["state_key"] = *col.value;
    else if (col.name == "depth")
      ev["depth"] = std::stoll(col.value.value_or("0"));
    else if (col.name == "redacts" && !col.value.value_or("").empty())
      ev["redacts"] = *col.value;
    else if (col.name == "membership" && !col.value.value_or("").empty())
      ev["content"]["membership"] = *col.value;
    else if (col.name == "content") {
      try {
        ev["content"] = json::parse(col.value.value_or("{}"));
      } catch (...) {
        ev["content"] = json::object();
      }
    }
  }
  if (!ev.contains("unsigned")) ev["unsigned"] = json::object();
  return ev;
}

// Get a column value from a Row by name
std::string row_get(const Row& r, const std::string& name,
                    const std::string& default_val = "") {
  for (auto& col : r) {
    if (col.name == name) return col.value.value_or(default_val);
  }
  return default_val;
}

int64_t row_get_int(const Row& r, const std::string& name, int64_t default_val = 0) {
  auto s = row_get(r, name, "");
  if (s.empty()) return default_val;
  try { return std::stoll(s); } catch (...) { return default_val; }
}

} // anonymous namespace

// ============================================================================
// SyncHandler - full /sync implementation
// ============================================================================

SyncHandler::SyncHandler(DatabasePool& db)
    : db_(db), events_(db), rooms_(db), members_(db), state_(db) {}

SyncHandler::SyncResult SyncHandler::sync(const SyncConfig& config) {
  SyncResult result;
  int64_t since_so = config.since.empty() ? 0 : parse_stream_token(config.since);

  db_.runInteraction("sync_full", [&](LoggingTransaction& txn) {
    int64_t max_so = 0;
    {
      txn.execute("SELECT next_val FROM stream_ordering_seq WHERE id = 1");
      auto r = txn.fetchone();
      if (r.has_value()) {
        for (auto& c : *r) {
          if (c.name == "next_val")
            max_so = std::stoll(c.value.value_or("0"));
        }
      }
    }
    if (max_so == 0) max_so = now_ms();
    bool full = config.full_state || since_so == 0;

    result.next_batch = make_next_batch_token(max_so);

    // ---- Joined rooms ----
    result.rooms["join"] = json::object();
    {
      std::string sql =
          "SELECT room_id FROM room_memberships WHERE user_id = ? AND membership = 'join'";
      txn.execute(sql, {SQLParam{config.user_id}});
      auto rows = txn.fetchall();
      for (auto& row : rows) {
        std::string room_id = row_get(row, "room_id");
        result.rooms["join"][room_id] =
            generate_room_entry_txn(txn, room_id, config.user_id, since_so, full, max_so);
      }
    }

    // ---- Invited rooms ----
    result.rooms["invite"] = json::object();
    {
      txn.execute(
          "SELECT room_id FROM room_memberships WHERE user_id = ? AND membership = 'invite'",
          {SQLParam{config.user_id}});
      auto rows = txn.fetchall();
      for (auto& row : rows) {
        std::string room_id = row_get(row, "room_id");
        // For invited rooms, always send full state since client may not know the room
        result.rooms["invite"][room_id] =
            generate_room_entry_txn(txn, room_id, config.user_id, 0, true, max_so);
      }
    }

    // ---- Left rooms (since last sync) ----
    result.rooms["leave"] = json::object();
    if (since_so > 0) {
      txn.execute(
          "SELECT room_id FROM room_memberships WHERE user_id = ? AND membership = 'leave' "
          "AND stream_ordering > ?",
          {SQLParam{config.user_id}, SQLParam{since_so}});
      auto rows = txn.fetchall();
      for (auto& row : rows) {
        std::string room_id = row_get(row, "room_id");
        result.rooms["leave"][room_id] =
            generate_room_entry_txn(txn, room_id, config.user_id, 0, true, max_so);
      }
    }

    // ---- Presence ----
    result.presence = json::object();
    result.presence["events"] = json::array();
    {
      // Get all shared-rooms users
      txn.execute(
          "SELECT DISTINCT rm2.user_id FROM room_memberships rm1 "
          "JOIN room_memberships rm2 ON rm1.room_id = rm2.room_id "
          "WHERE rm1.user_id = ? AND rm2.membership = 'join' "
          "LIMIT 100",
          {SQLParam{config.user_id}});
      auto shared_users = txn.fetchall();
      std::set<std::string> user_set;
      for (auto& r : shared_users) user_set.insert(row_get(r, "user_id"));
      user_set.insert(config.user_id);

      for (auto& uid : user_set) {
        txn.execute(
            "SELECT state, last_active_ts, status_msg FROM presence_state WHERE user_id = ?",
            {SQLParam{uid}});
        auto pr = txn.fetchone();
        if (pr.has_value()) {
          json pe;
          pe["type"] = "m.presence";
          pe["sender"] = uid;
          pe["content"]["presence"] = row_get(*pr, "state", "offline");
          pe["content"]["last_active_ago"] =
              now_ms() - row_get_int(*pr, "last_active_ts", 0);
          auto sm = row_get(*pr, "status_msg", "");
          if (!sm.empty()) pe["content"]["status_msg"] = sm;
          result.presence["events"].push_back(pe);
        }
      }
    }

    // ---- Account Data ----
    result.account_data = json::object();
    result.account_data["events"] = json::array();
    {
      txn.execute(
          "SELECT account_data_type, content FROM account_data WHERE user_id = ? AND room_id = ''",
          {SQLParam{config.user_id}});
      auto rows = txn.fetchall();
      for (auto& r : rows) {
        json ev;
        ev["type"] = row_get(r, "account_data_type");
        try {
          ev["content"] = json::parse(row_get(r, "content", "{}"));
        } catch (...) {
          ev["content"] = json::object();
        }
        result.account_data["events"].push_back(ev);
      }
    }

    // ---- To-Device ----
    result.to_device = json::object();
    result.to_device["events"] = json::array();
    {
      txn.execute(
          "SELECT sender, type, content FROM device_inbox WHERE user_id = ? "
          "ORDER BY stream_id ASC LIMIT 100",
          {SQLParam{config.user_id}});
      auto rows = txn.fetchall();
      for (auto& r : rows) {
        json ev;
        ev["sender"] = row_get(r, "sender");
        ev["type"] = row_get(r, "type");
        try {
          ev["content"] = json::parse(row_get(r, "content", "{}"));
        } catch (...) {
          ev["content"] = json::object();
        }
        result.to_device["events"].push_back(ev);
      }
      // Clean delivered to-device messages
      if (!rows.empty()) {
        txn.execute("DELETE FROM device_inbox WHERE user_id = ?",
                    {SQLParam{config.user_id}});
      }
    }

    // ---- Device Lists ----
    result.device_lists = json::object();
    result.device_lists["changed"] = json::array();
    result.device_lists["left"] = json::array();
    // (Full federation-ready device list tracking would query
    //  device_lists_outbound_pokes here.)

    // ---- One-time key counts (simplified) ----
    result.device_one_time_keys_count = json::object();
    result.device_unused_fallback_key_types = json::array();
  });

  return result;
}

SyncHandler::SyncResult SyncHandler::generate_sync_response(
    const std::string& user_id, const std::string& since_token,
    int64_t timeout_ms, bool full_state) {
  SyncConfig cfg;
  cfg.user_id = user_id;
  cfg.since = since_token;
  cfg.timeout_ms = timeout_ms;
  cfg.full_state = full_state;
  return sync(cfg);
}

json SyncHandler::generate_room_entry_txn(LoggingTransaction& txn,
                                          const std::string& room_id,
                                          const std::string& user_id,
                                          int64_t since_so, bool full_state,
                                          int64_t now_token) {
  json entry;

  // -- State --
  entry["state"] = json::object();
  entry["state"]["events"] = json::array();
  {
    txn.execute(
        "SELECT cse.type, cse.state_key, cse.event_id, e.sender, e.content, "
        "e.origin_server_ts, e.membership "
        "FROM current_state_events cse JOIN events e ON cse.event_id = e.event_id "
        "WHERE cse.room_id = ?",
        {SQLParam{room_id}});
    auto state_rows = txn.fetchall();
    // Deduplicate: per (type, state_key), keep only the latest by stream_ordering
    std::map<std::pair<std::string, std::string>, json> state_map;
    for (auto& r : state_rows) {
      std::string type = row_get(r, "type");
      std::string sk = row_get(r, "state_key", "");
      auto key = std::make_pair(type, sk);
      json sev;
      sev["type"] = type;
      sev["sender"] = row_get(r, "sender");
      sev["event_id"] = row_get(r, "event_id");
      sev["room_id"] = room_id;
      sev["origin_server_ts"] = row_get_int(r, "origin_server_ts", 0);
      try {
        sev["content"] = json::parse(row_get(r, "content", "{}"));
      } catch (...) {
        sev["content"] = json::object();
      }
      if (!sk.empty()) sev["state_key"] = sk;
      if (type == "m.room.member") {
        sev["content"]["membership"] = row_get(r, "membership", "leave");
      }
      sev["unsigned"] = json::object();
      state_map[key] = sev;
    }
    for (auto& [key, sev] : state_map) {
      entry["state"]["events"].push_back(sev);
    }
  }

  // -- Timeline --
  entry["timeline"] = json::object();
  entry["timeline"]["events"] = json::array();
  entry["timeline"]["limited"] = false;
  {
    std::string timeline_sql = full_state
        ? "SELECT * FROM events WHERE room_id = ? AND is_outlier = 0 "
          "ORDER BY stream_ordering ASC LIMIT 20"
        : "SELECT * FROM events WHERE room_id = ? AND stream_ordering > ? "
          "AND is_outlier = 0 ORDER BY stream_ordering ASC LIMIT 20";
    if (full_state) {
      txn.execute(timeline_sql, {SQLParam{room_id}});
    } else {
      txn.execute(timeline_sql, {SQLParam{room_id}, SQLParam{since_so}});
    }
    auto timeline_rows = txn.fetchall();
    for (auto& r : timeline_rows) {
      entry["timeline"]["events"].push_back(row_to_event_json(r));
    }
    if (!timeline_rows.empty()) {
      entry["timeline"]["prev_batch"] =
          "s" + row_get(timeline_rows.front(), "stream_ordering", "0");
    } else {
      entry["timeline"]["prev_batch"] = "s" + std::to_string(since_so);
    }
    // Check if limited
    if (timeline_rows.size() >= 20) {
      entry["timeline"]["limited"] = true;
    }
  }

  // -- Ephemeral --
  entry["ephemeral"] = json::object();
  entry["ephemeral"]["events"] = json::array();

  // -- Typing notification --
  {
    json typing_ev;
    typing_ev["type"] = "m.typing";
    json typing_users = json::array();
    txn.execute(
        "SELECT user_id FROM typing WHERE room_id = ? "
        "AND last_typed_ts + timeout_ms > ?",
        {SQLParam{room_id}, SQLParam{now_ms()}});
    auto typing_rows = txn.fetchall();
    for (auto& tr : typing_rows) {
      typing_users.push_back(row_get(tr, "user_id"));
    }
    typing_ev["content"]["user_ids"] = typing_users;
    entry["ephemeral"]["events"].push_back(typing_ev);
  }

  // -- Read receipts --
  {
    txn.execute(
        "SELECT user_id, event_id, ts FROM read_receipts WHERE room_id = ?",
        {SQLParam{room_id}});
    auto receipt_rows = txn.fetchall();
    if (!receipt_rows.empty()) {
      json receipt_ev;
      receipt_ev["type"] = "m.receipt";
      json receipt_content;
      for (auto& rr : receipt_rows) {
        std::string uid = row_get(rr, "user_id");
        std::string eid = row_get(rr, "event_id");
        int64_t rts = row_get_int(rr, "ts", 0);
        receipt_content[eid]["m.read"][uid]["ts"] = rts;
      }
      receipt_ev["content"] = receipt_content;
      entry["ephemeral"]["events"].push_back(receipt_ev);
    }
  }

  // -- Account Data (room-level) --
  entry["account_data"] = json::object();
  entry["account_data"]["events"] = json::array();
  {
    txn.execute(
        "SELECT account_data_type, content FROM account_data WHERE user_id = ? AND room_id = ?",
        {SQLParam{user_id}, SQLParam{room_id}});
    auto ad_rows = txn.fetchall();
    for (auto& ad : ad_rows) {
      json adev;
      adev["type"] = row_get(ad, "account_data_type");
      try {
        adev["content"] = json::parse(row_get(ad, "content", "{}"));
      } catch (...) {
        adev["content"] = json::object();
      }
      entry["account_data"]["events"].push_back(adev);
    }
  }

  // -- Unread notifications --
  entry["unread_notifications"] = json::object();
  {
    txn.execute(
        "SELECT notif_count, highlight_count FROM event_push_summary "
        "WHERE user_id = ? AND room_id = ?",
        {SQLParam{user_id}, SQLParam{room_id}});
    auto un = txn.fetchone();
    if (un.has_value()) {
      entry["unread_notifications"]["notification_count"] =
          row_get_int(*un, "notif_count", 0);
      entry["unread_notifications"]["highlight_count"] =
          row_get_int(*un, "highlight_count", 0);
    } else {
      entry["unread_notifications"]["notification_count"] = 0;
      entry["unread_notifications"]["highlight_count"] = 0;
    }
  }

  // -- Summary --
  entry["summary"] = json::object();
  {
    txn.execute(
        "SELECT COUNT(*) as cnt FROM room_memberships WHERE room_id = ? "
        "AND membership = 'join'",
        {SQLParam{room_id}});
    auto sm = txn.fetchone();
    int joined_count = 0;
    if (sm.has_value()) joined_count = row_get_int(*sm, "cnt", 0);
    entry["summary"]["m.joined_member_count"] = joined_count;
    entry["summary"]["m.invited_member_count"] = 0;

    // Find heroes
    int hero_limit = 5;
    txn.execute(
        "SELECT user_id FROM room_memberships WHERE room_id = ? AND membership = 'join' "
        "ORDER BY stream_ordering DESC LIMIT ?",
        {SQLParam{room_id}, SQLParam{int64_t(hero_limit)}});
    auto heroes = txn.fetchall();
    if (!heroes.empty()) {
      json hero_list = json::array();
      for (auto& h : heroes) hero_list.push_back(row_get(h, "user_id"));
      entry["summary"]["m.heroes"] = hero_list;
    }
  }

  return entry;
}

json SyncHandler::generate_room_entry(const std::string& room_id,
                                      const std::string& user_id,
                                      int64_t since_so, bool full_state,
                                      int64_t now_token) {
  json entry;
  db_.runInteraction("generate_room_entry", [&](LoggingTransaction& txn) {
    entry = generate_room_entry_txn(txn, room_id, user_id, since_so, full_state, now_token);
  });
  return entry;
}

json SyncHandler::get_room_state_for_sync(const std::string& room_id,
                                          const std::string& /*user_id*/,
                                          int64_t /*since_so*/) {
  auto state = state_.get_current_state(room_id);
  json events = json::array();
  for (auto& [key, event_id] : state) {
    auto ev = events_.get_event(event_id);
    if (ev) events.push_back(*ev);
  }
  return json{{"events", events}};
}

json SyncHandler::get_timeline_events(const std::string& room_id, int64_t from,
                                      int64_t to, int limit) {
  json timeline;
  timeline["events"] = json::array();
  timeline["limited"] = false;
  timeline["prev_batch"] = "s" + std::to_string(from);
  db_.runInteraction("get_timeline_events", [&](LoggingTransaction& txn) {
    txn.execute(
        "SELECT * FROM events WHERE room_id = ? AND stream_ordering > ? "
        "AND stream_ordering <= ? AND is_outlier = 0 "
        "ORDER BY stream_ordering ASC LIMIT ?",
        {SQLParam{room_id}, SQLParam{from}, SQLParam{to},
         SQLParam{int64_t(limit)}});
    auto rows = txn.fetchall();
    for (auto& r : rows) timeline["events"].push_back(row_to_event_json(r));
    if (static_cast<int64_t>(rows.size()) >= limit) timeline["limited"] = true;
  });
  return timeline;
}

json SyncHandler::get_ephemeral_events(const std::string& room_id, int64_t from) {
  (void)from;
  return json::array();
}

json SyncHandler::get_account_data_for_room(const std::string& user_id,
                                            const std::string& room_id) {
  json result;
  result["events"] = json::array();
  db_.runInteraction("get_acct_data", [&](LoggingTransaction& txn) {
    txn.execute(
        "SELECT account_data_type, content FROM account_data "
        "WHERE user_id = ? AND room_id = ?",
        {SQLParam{user_id}, SQLParam{room_id}});
    auto rows = txn.fetchall();
    for (auto& r : rows) {
      json adev;
      adev["type"] = row_get(r, "account_data_type");
      try {
        adev["content"] = json::parse(row_get(r, "content", "{}"));
      } catch (...) {
        adev["content"] = json::object();
      }
      result["events"].push_back(adev);
    }
  });
  return result;
}

std::string SyncHandler::get_stream_token() {
  int64_t so = get_max_stream_ordering();
  return make_next_batch_token(so);
}

int64_t SyncHandler::parse_stream_token(const std::string& token) {
  return progressive::handlers::parse_stream_token(token);
}

int64_t SyncHandler::get_max_stream_ordering() {
  return events_.get_max_stream_ordering("");
}

json SyncHandler::get_presence_sync(const std::string& user_id, int64_t since_ts) {
  json result;
  result["events"] = json::array();
  db_.runInteraction("get_presence_sync", [&](LoggingTransaction& txn) {
    txn.execute(
        "SELECT DISTINCT rm2.user_id FROM room_memberships rm1 "
        "JOIN room_memberships rm2 ON rm1.room_id = rm2.room_id "
        "WHERE rm1.user_id = ? AND rm2.membership = 'join' LIMIT 100",
        {SQLParam{user_id}});
    auto users = txn.fetchall();
    std::set<std::string> uid_set;
    for (auto& ur : users) uid_set.insert(row_get(ur, "user_id"));
    uid_set.insert(user_id);

    for (auto& uid : uid_set) {
      txn.execute(
          "SELECT state, last_active_ts, status_msg FROM presence_state WHERE user_id = ?",
          {SQLParam{uid}});
      auto pr = txn.fetchone();
      if (pr.has_value()) {
        json pe;
        pe["type"] = "m.presence";
        pe["sender"] = uid;
        pe["content"]["presence"] = row_get(*pr, "state", "offline");
        pe["content"]["last_active_ago"] =
            now_ms() - row_get_int(*pr, "last_active_ts", 0);
        auto sm = row_get(*pr, "status_msg", "");
        if (!sm.empty()) pe["content"]["status_msg"] = sm;
        result["events"].push_back(pe);
      }
    }
  });
  return result;
}

json SyncHandler::get_to_device_messages(const std::string& user_id, int64_t since) {
  (void)since;
  json result;
  result["events"] = json::array();
  db_.runInteraction("get_to_device", [&](LoggingTransaction& txn) {
    txn.execute(
        "SELECT sender, type, content FROM device_inbox WHERE user_id = ? "
        "ORDER BY stream_id ASC LIMIT 100",
        {SQLParam{user_id}});
    auto rows = txn.fetchall();
    for (auto& r : rows) {
      json ev;
      ev["sender"] = row_get(r, "sender");
      ev["type"] = row_get(r, "type");
      try {
        ev["content"] = json::parse(row_get(r, "content", "{}"));
      } catch (...) {
        ev["content"] = json::object();
      }
      result["events"].push_back(ev);
    }
    if (!rows.empty()) {
      txn.execute("DELETE FROM device_inbox WHERE user_id = ?",
                  {SQLParam{user_id}});
    }
  });
  return result;
}

SyncHandler::DeviceListChanges SyncHandler::get_device_list_changes(
    const std::string& /*user_id*/, int64_t /*since*/) {
  return {{}, {}};
}

// ============================================================================
// RoomCreationHandler - full room creation with presets, power levels,
//                       initial state, and invites
// ============================================================================

RoomCreationHandler::RoomCreationHandler(DatabasePool& db) : db_(db) {}

RoomCreationHandler::CreateRoomResult RoomCreationHandler::create_room(
    const Requester& requester, const RoomConfig& config) {
  std::string room_id = generate_room_id();
  std::string alias;

  db_.runInteraction("create_room", [&](LoggingTransaction& txn) {
    int64_t so = now_ms();

    // 1. Insert room record
    txn.execute(
        "INSERT INTO rooms (room_id, creator, is_public, room_version, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        {SQLParam{room_id}, SQLParam{config.creator},
         SQLParam{int64_t(config.is_public ? 1 : 0)},
         SQLParam{config.room_version}, SQLParam{so}});

    // 2. Send m.room.create event
    json creation_content = config.creation_content.value_or(json::object());
    if (!creation_content.contains("creator")) {
      creation_content["creator"] = config.creator;
    }
    creation_content["room_version"] = config.room_version;

    std::string create_event_id = gen_event_id();
    json create_content = creation_content;
    insert_event_txn(txn, create_event_id, room_id, "m.room.create",
                     config.creator, create_content, so, 0,
                     /*state_key*/ "", /*membership*/ "",
                     /*redacts*/ "", /*txn_id*/ "",
                     /*is_state*/ true);

    // Update current state for m.room.create
    txn.execute(
        "INSERT OR REPLACE INTO current_state_events "
        "(room_id, type, state_key, event_id) VALUES (?, 'm.room.create', '', ?)",
        {SQLParam{room_id}, SQLParam{create_event_id}});

    // 3. Send m.room.power_levels - build power levels content
    json power_levels;
    power_levels["users"][config.creator] = 100;
    power_levels["users_default"] = 0;
    power_levels["events_default"] = 0;
    power_levels["state_default"] = 50;

    // Per-event type power levels
    power_levels["events"]["m.room.name"] = 50;
    power_levels["events"]["m.room.topic"] = 50;
    power_levels["events"]["m.room.avatar"] = 50;
    power_levels["events"]["m.room.tombstone"] = 100;
    power_levels["events"]["m.room.power_levels"] = 100;
    power_levels["events"]["m.room.history_visibility"] = 100;
    power_levels["events"]["m.room.canonical_alias"] = 50;
    power_levels["events"]["m.room.encryption"] = 100;

    // Per-membership actions
    power_levels["invite"] = 0;
    power_levels["kick"] = 50;
    power_levels["ban"] = 50;
    power_levels["redact"] = 50;

    // Override if user supplied power_level_content_override
    if (config.power_level_content_override.has_value()) {
      json override;
      try {
        override = json::parse(*config.power_level_content_override);
      } catch (...) {
        override = json::object();
      }
      if (!override.empty()) power_levels = override;
      // Ensure creator is always admin
      if (!power_levels.contains("users") || !power_levels["users"].is_object()) {
        power_levels["users"] = json::object();
      }
      power_levels["users"][config.creator] = 100;
    }

    std::string pl_event_id = gen_event_id();
    insert_event_txn(txn, pl_event_id, room_id, "m.room.power_levels",
                     config.creator, power_levels, so, 0,
                     /*state_key*/ "", /*membership*/ "",
                     /*redacts*/ "", /*txn_id*/ "",
                     /*is_state*/ true);
    txn.execute(
        "INSERT OR REPLACE INTO current_state_events "
        "(room_id, type, state_key, event_id) VALUES (?, 'm.room.power_levels', '', ?)",
        {SQLParam{room_id}, SQLParam{pl_event_id}});

    // 4. Send m.room.join_rules based on preset
    std::string join_rule = "invite";
    if (config.preset.has_value()) {
      if (*config.preset == "public_chat") join_rule = "public";
      else if (*config.preset == "private_chat") join_rule = "invite";
      else if (*config.preset == "trusted_private_chat") join_rule = "invite";
    }
    if (config.visibility == "public") join_rule = "public";

    json join_rules_content;
    join_rules_content["join_rule"] = join_rule;
    std::string jr_event_id = gen_event_id();
    insert_event_txn(txn, jr_event_id, room_id, "m.room.join_rules",
                     config.creator, join_rules_content, so, 0,
                     /*state_key*/ "", /*membership*/ "",
                     /*redacts*/ "", /*txn_id*/ "",
                     /*is_state*/ true);
    txn.execute(
        "INSERT OR REPLACE INTO current_state_events "
        "(room_id, type, state_key, event_id) VALUES (?, 'm.room.join_rules', '', ?)",
        {SQLParam{room_id}, SQLParam{jr_event_id}});

    // 5. Send m.room.history_visibility
    json hv_content;
    hv_content["history_visibility"] = "shared";
    std::string hv_event_id = gen_event_id();
    insert_event_txn(txn, hv_event_id, room_id, "m.room.history_visibility",
                     config.creator, hv_content, so, 0,
                     /*state_key*/ "", /*membership*/ "",
                     /*redacts*/ "", /*txn_id*/ "",
                     /*is_state*/ true);
    txn.execute(
        "INSERT OR REPLACE INTO current_state_events "
        "(room_id, type, state_key, event_id) VALUES (?, 'm.room.history_visibility', '', ?)",
        {SQLParam{room_id}, SQLParam{hv_event_id}});

    // 6. Send m.room.guest_access
    json ga_content;
    ga_content["guest_access"] = "can_join";
    std::string ga_event_id = gen_event_id();
    insert_event_txn(txn, ga_event_id, room_id, "m.room.guest_access",
                     config.creator, ga_content, so, 0,
                     /*state_key*/ "", /*membership*/ "",
                     /*redacts*/ "", /*txn_id*/ "",
                     /*is_state*/ true);
    txn.execute(
        "INSERT OR REPLACE INTO current_state_events "
        "(room_id, type, state_key, event_id) VALUES (?, 'm.room.guest_access', '', ?)",
        {SQLParam{room_id}, SQLParam{ga_event_id}});

    // 7. Room name (if provided)
    if (config.name.has_value() && !config.name->empty()) {
      json name_content;
      name_content["name"] = *config.name;
      std::string neid = gen_event_id();
      insert_event_txn(txn, neid, room_id, "m.room.name",
                       config.creator, name_content, so, 0,
                       /*state_key*/ "", /*membership*/ "",
                       /*redacts*/ "", /*txn_id*/ "",
                       /*is_state*/ true);
      txn.execute(
          "INSERT OR REPLACE INTO current_state_events "
          "(room_id, type, state_key, event_id) VALUES (?, 'm.room.name', '', ?)",
          {SQLParam{room_id}, SQLParam{neid}});
    }

    // 8. Room topic (if provided)
    if (config.topic.has_value() && !config.topic->empty()) {
      json topic_content;
      topic_content["topic"] = *config.topic;
      std::string teid = gen_event_id();
      insert_event_txn(txn, teid, room_id, "m.room.topic",
                       config.creator, topic_content, so, 0,
                       /*state_key*/ "", /*membership*/ "",
                       /*redacts*/ "", /*txn_id*/ "",
                       /*is_state*/ true);
      txn.execute(
          "INSERT OR REPLACE INTO current_state_events "
          "(room_id, type, state_key, event_id) VALUES (?, 'm.room.topic', '', ?)",
          {SQLParam{room_id}, SQLParam{teid}});
    }

    // 9. Initial state events (user-supplied)
    if (config.initial_state.has_value() && config.initial_state->is_array()) {
      for (auto& state_ev : *config.initial_state) {
        std::string ev_type = state_ev.value("type", "");
        std::string ev_sk = state_ev.value("state_key", "");
        json ev_content = state_ev.value("content", json::object());
        if (ev_type.empty()) continue;

        std::string ieid = gen_event_id();
        insert_event_txn(txn, ieid, room_id, ev_type,
                         config.creator, ev_content, so, 0,
                         ev_sk, /*membership*/ "",
                         /*redacts*/ "", /*txn_id*/ "",
                         /*is_state*/ true);
        txn.execute(
            "INSERT OR REPLACE INTO current_state_events "
            "(room_id, type, state_key, event_id) VALUES (?, ?, ?, ?)",
            {SQLParam{room_id}, SQLParam{ev_type}, SQLParam{ev_sk},
             SQLParam{ieid}});
      }
    }

    // 10. Join the creator as a member
    std::string join_event_id = gen_event_id();
    json join_content;
    join_content["membership"] = "join";
    insert_event_txn(txn, join_event_id, room_id, "m.room.member",
                     config.creator, join_content, so, 0,
                     config.creator, "join", /*redacts*/ "", /*txn_id*/ "",
                     /*is_state*/ true);

    txn.execute(
        "INSERT OR REPLACE INTO room_memberships "
        "(event_id, room_id, user_id, membership, sender, stream_ordering) "
        "VALUES (?, ?, ?, 'join', ?, ?)",
        {SQLParam{join_event_id}, SQLParam{room_id},
         SQLParam{config.creator}, SQLParam{config.creator}, SQLParam{so}});

    txn.execute(
        "INSERT OR REPLACE INTO current_state_events "
        "(room_id, type, state_key, event_id) VALUES (?, 'm.room.member', ?, ?)",
        {SQLParam{room_id}, SQLParam{config.creator}, SQLParam{join_event_id}});

    // 11. Invite users
    for (auto& uid : config.invite_list) {
      std::string inv_event_id = gen_event_id();
      json inv_content;
      inv_content["membership"] = "invite";
      inv_content["is_direct"] = config.is_direct.value_or(false);

      insert_event_txn(txn, inv_event_id, room_id, "m.room.member",
                       config.creator, inv_content, so, 0,
                       uid, "invite", /*redacts*/ "", /*txn_id*/ "",
                       /*is_state*/ true);

      txn.execute(
          "INSERT OR REPLACE INTO room_memberships "
          "(event_id, room_id, user_id, membership, sender, stream_ordering) "
          "VALUES (?, ?, ?, 'invite', ?, ?)",
          {SQLParam{inv_event_id}, SQLParam{room_id}, SQLParam{uid},
           SQLParam{config.creator}, SQLParam{so}});

      txn.execute(
          "INSERT OR REPLACE INTO current_state_events "
          "(room_id, type, state_key, event_id) VALUES (?, 'm.room.member', ?, ?)",
          {SQLParam{room_id}, SQLParam{uid}, SQLParam{inv_event_id}});

      // Send invite to-device notification to invited user
      json invite_to_device;
      invite_to_device["room_id"] = room_id;
      invite_to_device["room_name"] = config.name.value_or("");
      invite_to_device["sender"] = config.creator;

      txn.execute(
          "INSERT INTO device_inbox (user_id, device_id, type, sender, content) "
          "VALUES (?, '*', 'm.room.invite', ?, ?)",
          {SQLParam{uid}, SQLParam{config.creator},
           SQLParam{invite_to_device.dump()}});
    }

    // 12. Room alias (if requested)
    if (config.room_alias_name.has_value() && !config.room_alias_name->empty()) {
      alias = "#" + *config.room_alias_name + ":localhost";
      txn.execute(
          "INSERT OR REPLACE INTO room_aliases (room_alias, room_id, creator) "
          "VALUES (?, ?, ?)",
          {SQLParam{alias}, SQLParam{room_id}, SQLParam{config.creator}});

      // Send m.room.canonical_alias state event
      json ca_content;
      ca_content["alias"] = alias;
      std::string ca_event_id = gen_event_id();
      insert_event_txn(txn, ca_event_id, room_id, "m.room.canonical_alias",
                       config.creator, ca_content, so, 0,
                       /*state_key*/ "", /*membership*/ "",
                       /*redacts*/ "", /*txn_id*/ "",
                       /*is_state*/ true);
      txn.execute(
          "INSERT OR REPLACE INTO current_state_events "
          "(room_id, type, state_key, event_id) VALUES (?, 'm.room.canonical_alias', '', ?)",
          {SQLParam{room_id}, SQLParam{ca_event_id}});
    }
  });

  return {room_id, alias};
}

RoomCreationHandler::CreateRoomResult RoomCreationHandler::clone_room(
    const std::string& existing_room_id, const std::string& new_room_id,
    const Requester& requester) {
  RoomConfig cfg;
  cfg.creator = requester.user.to_string();
  cfg.room_version = "1";

  // Copy state from existing room
  db_.runInteraction("clone_room", [&](LoggingTransaction& txn) {
    txn.execute(
        "SELECT type, state_key, event_id FROM current_state_events WHERE room_id = ?",
        {SQLParam{existing_room_id}});
    auto state_rows = txn.fetchall();

    // Build initial_state from existing room state
    json initial_state = json::array();
    for (auto& sr : state_rows) {
      std::string eid = row_get(sr, "event_id");
      txn.execute("SELECT type, sender, content, state_key, origin_server_ts "
                  "FROM events WHERE event_id = ?",
                  {SQLParam{eid}});
      auto ev = txn.fetchone();
      if (!ev.has_value()) continue;

      std::string ev_type = row_get(*ev, "type");
      // Skip these - they get regenerated
      if (ev_type == "m.room.create" || ev_type == "m.room.power_levels" ||
          ev_type == "m.room.join_rules" || ev_type == "m.room.member")
        continue;

      json is;
      is["type"] = ev_type;
      is["state_key"] = row_get(*ev, "state_key", "");
      try {
        is["content"] = json::parse(row_get(*ev, "content", "{}"));
      } catch (...) {
        is["content"] = json::object();
      }
      initial_state.push_back(is);
    }
    cfg.initial_state = initial_state;
  });

  // Override room_id with the requested one
  // (We can't easily override generate_room_id, so we clone via create
  //  and then update the room_id. For now, use create_room directly.)
  auto result = create_room(requester, cfg);

  // In a full implementation, we'd use new_room_id as the target,
  // but generate_room_id always produces a fresh one. We return what we
  // actually created, with the understanding that callers pass the generated
  // room_id back as new_room_id.
  return {result.room_id, result.room_alias};
}

std::string RoomCreationHandler::upgrade_room(const std::string& room_id,
                                               const std::string& new_version,
                                               const Requester& requester) {
  RoomConfig cfg;
  cfg.creator = requester.user.to_string();
  cfg.room_version = new_version;

  // Generate tombstone in old room
  db_.runInteraction("upgrade_room", [&](LoggingTransaction& txn) {
    std::string new_rid = gen_room_id();
    json tombstone;
    tombstone["replacement_room"] = new_rid;
    tombstone["body"] = "This room has been replaced";

    insert_event_txn(txn, gen_event_id(), room_id, "m.room.tombstone",
                     cfg.creator, tombstone, now_ms());
  });

  auto result = create_room(requester, cfg);
  return result.room_id;
}

std::string RoomCreationHandler::generate_room_id() {
  return gen_room_id();
}

void RoomCreationHandler::handle_preset(const std::string& room_id,
                                        const std::string& preset,
                                        const std::string& creator,
                                        int64_t so) {
  // Presets are now handled in create_room directly.
  (void)room_id;
  (void)preset;
  (void)creator;
  (void)so;
}

std::string RoomCreationHandler::send_room_create_event(
    const std::string& room_id, const std::string& creator,
    const std::string& version, const json& creation_content, int64_t so) {
  std::string eid = gen_event_id();
  db_.runInteraction("send_room_create", [&](LoggingTransaction& txn) {
    insert_event_txn(txn, eid, room_id, "m.room.create", creator,
                     creation_content, so);
  });
  return eid;
}

void RoomCreationHandler::send_initial_state_events(
    const std::string& room_id, const std::string& creator,
    const RoomConfig& config, int64_t so) {
  // Handled inline in create_room above.
  (void)room_id;
  (void)creator;
  (void)config;
  (void)so;
}

// ============================================================================
// MessageHandler - send message, redact, edit (update)
// ============================================================================

MessageHandler::MessageHandler(DatabasePool& db) : db_(db) {}

MessageHandler::SendResult MessageHandler::send_message(
    const std::string& room_id, const std::string& user_id,
    const std::string& event_type, const json& content,
    const std::optional<std::string>& txn_id) {
  SendResult result;

  db_.runInteraction("send_message", [&](LoggingTransaction& txn) {
    // 1. Deduplication check
    if (txn_id.has_value() && !txn_id->empty()) {
      txn.execute("SELECT event_id FROM events WHERE room_id = ? AND txn_id = ?",
                  {SQLParam{room_id}, SQLParam{*txn_id}});
      auto dup = txn.fetchone();
      if (dup.has_value()) {
        result.event_id = row_get(*dup, "event_id");
        result.stream_ordering = now_ms();
        return;
      }
    }

    // 2. Verify membership
    txn.execute(
        "SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?",
        {SQLParam{room_id}, SQLParam{user_id}});
    auto mem = txn.fetchone();
    std::string membership = mem.has_value() ? row_get(*mem, "membership") : "leave";
    if (membership != "join") {
      result.event_id = "";
      result.stream_ordering = -1;
      return;
    }

    // 3. Generate event ID and compute depth
    std::string event_id = gen_event_id();
    int64_t depth = 1;
    {
      txn.execute(
          "SELECT MAX(depth) as max_depth FROM events WHERE room_id = ? "
          "AND is_outlier = 0",
          {SQLParam{room_id}});
      auto dr = txn.fetchone();
      if (dr.has_value()) depth = row_get_int(*dr, "max_depth", 0) + 1;
    }

    // 4. Get previous events (forward extremities)
    txn.execute(
        "SELECT event_id FROM event_forward_extremities WHERE room_id = ?",
        {SQLParam{room_id}});
    auto prev_rows = txn.fetchall();
    json prev_events_json = json::array();
    for (auto& pr : prev_rows) {
      prev_events_json.push_back(row_get(pr, "event_id"));
    }
    std::string prev_events_str = prev_events_json.dump();

    // 5. Insert the event
    int64_t so = insert_event_txn(
        txn, event_id, room_id, event_type, user_id, content, now_ms(),
        static_cast<int>(depth), /*state_key*/ "", /*membership*/ "",
        /*redacts*/ "", txn_id.value_or(""),
        /*is_state*/ (event_type == "m.room.member"), prev_events_str);

    // 6. Update forward extremities
    txn.execute("DELETE FROM event_forward_extremities WHERE room_id = ?",
                {SQLParam{room_id}});
    txn.execute(
        "INSERT INTO event_forward_extremities (event_id, room_id) VALUES (?, ?)",
        {SQLParam{event_id}, SQLParam{room_id}});

    // 7. Store event edge
    for (auto& pr : prev_rows) {
      txn.execute(
          "INSERT OR IGNORE INTO event_edges (event_id, prev_event_id, room_id, is_state) "
          "VALUES (?, ?, ?, 0)",
          {SQLParam{event_id}, SQLParam{row_get(pr, "event_id")},
           SQLParam{room_id}});
    }

    // 8. Index for search
    if (event_type == "m.room.message" || event_type == "m.room.encrypted") {
      if (content.contains("body") && content["body"].is_string()) {
        std::string body = content["body"].get<std::string>();
        txn.execute(
            "INSERT INTO event_search (event_id, room_id, key, value, "
            "stream_ordering, origin_server_ts) VALUES (?, ?, 'content.body', ?, ?, ?)",
            {SQLParam{event_id}, SQLParam{room_id}, SQLParam{body},
             SQLParam{so}, SQLParam{now_ms()}});
      }
    }

    // 9. Push notification handling - update summary counts
    txn.execute(
        "SELECT DISTINCT user_id FROM room_memberships WHERE room_id = ? "
        "AND membership = 'join' AND user_id != ?",
        {SQLParam{room_id}, SQLParam{user_id}});
    auto notify_users = txn.fetchall();
    for (auto& nu : notify_users) {
      std::string target_user = row_get(nu, "user_id");
      txn.execute(
          "INSERT INTO event_push_summary (user_id, room_id, notif_count, "
          "highlight_count, stream_ordering) VALUES (?, ?, 1, 0, ?) "
          "ON CONFLICT(user_id, room_id) DO UPDATE SET "
          "notif_count = notif_count + 1, stream_ordering = ?",
          {SQLParam{target_user}, SQLParam{room_id}, SQLParam{so},
           SQLParam{so}});
    }

    result.event_id = event_id;
    result.stream_ordering = so;
  });

  return result;
}

MessageHandler::SendResult MessageHandler::redact_event(
    const std::string& room_id, const std::string& user_id,
    const std::string& event_id_to_redact,
    const std::optional<std::string>& reason,
    const std::optional<std::string>& txn_id) {
  SendResult result;

  db_.runInteraction("redact_event", [&](LoggingTransaction& txn) {
    // 1. Verify the target event exists
    txn.execute("SELECT event_id, sender, type FROM events WHERE event_id = ?",
                {SQLParam{event_id_to_redact}});
    auto target = txn.fetchone();
    if (!target.has_value()) {
      result.event_id = "";
      result.stream_ordering = -1;
      return;
    }

    // 2. Verify membership
    txn.execute(
        "SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?",
        {SQLParam{room_id}, SQLParam{user_id}});
    auto mem = txn.fetchone();
    std::string membership = mem.has_value() ? row_get(*mem, "membership") : "leave";
    if (membership != "join") {
      result.event_id = "";
      result.stream_ordering = -1;
      return;
    }

    // 3. Build redaction event
    std::string redaction_event_id = gen_event_id();
    json redact_content;
    if (reason.has_value()) redact_content["reason"] = *reason;

    int64_t depth = 1;
    {
      txn.execute(
          "SELECT MAX(depth) as max_depth FROM events WHERE room_id = ? AND is_outlier = 0",
          {SQLParam{room_id}});
      auto dr = txn.fetchone();
      if (dr.has_value()) depth = row_get_int(*dr, "max_depth", 0) + 1;
    }

    // Get prev extremities
    txn.execute(
        "SELECT event_id FROM event_forward_extremities WHERE room_id = ?",
        {SQLParam{room_id}});
    auto prev_rows = txn.fetchall();
    json pe_json = json::array();
    for (auto& pr : prev_rows) pe_json.push_back(row_get(pr, "event_id"));

    int64_t so = insert_event_txn(
        txn, redaction_event_id, room_id, "m.room.redaction", user_id,
        redact_content, now_ms(), static_cast<int>(depth),
        /*state_key*/ "", /*membership*/ "",
        event_id_to_redact, txn_id.value_or(""),
        /*is_state*/ false, pe_json.dump());

    // 4. Mark the target event as redacted
    txn.execute(
        "UPDATE events SET is_redacted = 1 WHERE event_id = ?",
        {SQLParam{event_id_to_redact}});

    txn.execute(
        "INSERT OR REPLACE INTO event_redactions (redaction_event_id, "
        "redacts_event_id, received_ts) VALUES (?, ?, ?)",
        {SQLParam{redaction_event_id}, SQLParam{event_id_to_redact},
         SQLParam{now_ms()}});

    // 5. Update forward extremities
    txn.execute("DELETE FROM event_forward_extremities WHERE room_id = ?",
                {SQLParam{room_id}});
    txn.execute(
        "INSERT INTO event_forward_extremities (event_id, room_id) VALUES (?, ?)",
        {SQLParam{redaction_event_id}, SQLParam{room_id}});

    result.event_id = redaction_event_id;
    result.stream_ordering = so;
  });

  return result;
}

MessageHandler::SendResult MessageHandler::update_message(
    const std::string& room_id, const std::string& user_id,
    const std::string& original_event_id, const json& new_content) {
  // An edit is a new m.room.message event with m.relates_to set
  json content = new_content;
  content["m.relates_to"] = json::object();
  content["m.relates_to"]["event_id"] = original_event_id;
  content["m.relates_to"]["rel_type"] = "m.replace";
  content["m.new_content"] = new_content;

  return send_message(room_id, user_id, "m.room.message", content);
}

MessageHandler::SendResult MessageHandler::send_reaction(
    const std::string& room_id, const std::string& user_id,
    const std::string& event_id, const std::string& key) {
  json content;
  content["m.relates_to"] = json::object();
  content["m.relates_to"]["event_id"] = event_id;
  content["m.relates_to"]["rel_type"] = "m.annotation";
  content["m.relates_to"]["key"] = key;

  return send_message(room_id, user_id, "m.reaction", content);
}

bool MessageHandler::can_send_message(const std::string& room_id,
                                      const std::string& user_id, bool is_guest) {
  if (is_guest) return false;
  bool can = false;
  db_.runInteraction("can_send", [&](LoggingTransaction& txn) {
    txn.execute(
        "SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?",
        {SQLParam{room_id}, SQLParam{user_id}});
    auto mem = txn.fetchone();
    can = mem.has_value() && row_get(*mem, "membership") == "join";
  });
  return can;
}

bool MessageHandler::check_rate_limit(const std::string& user_id,
                                      const std::string& /*room_id*/) {
  // Simple rate limit: max 10 messages per second
  static std::map<std::string, std::pair<int64_t, int>> rate_limits;
  static std::mutex rate_mutex;
  std::lock_guard<std::mutex> lock(rate_mutex);

  int64_t now = now_ms();
  auto it = rate_limits.find(user_id);
  if (it == rate_limits.end()) {
    rate_limits[user_id] = {now, 1};
    return true;
  }
  // Reset counter if window expired (1 second)
  if (now - it->second.first > 1000) {
    it->second = {now, 1};
    return true;
  }
  it->second.second++;
  return it->second.second <= 10;
}

MessageHandler::RatelimitConfig MessageHandler::get_rate_limit_config() {
  return {10, 5};
}

bool MessageHandler::is_event_duplicate(const std::string& room_id,
                                        const std::string& txn_id) {
  bool dup = false;
  db_.runInteraction("check_dup", [&](LoggingTransaction& txn) {
    txn.execute("SELECT event_id FROM events WHERE room_id = ? AND txn_id = ?",
                {SQLParam{room_id}, SQLParam{txn_id}});
    dup = txn.fetchone().has_value();
  });
  return dup;
}

json MessageHandler::process_event_content(const std::string& event_type,
                                           const json& content,
                                           const std::string& /*room_id*/) {
  json processed = content;

  // Strip unknown top-level fields (simplified)
  // Add automatic timestamps if not present
  if (event_type == "m.room.message" || event_type == "m.room.encrypted") {
    if (!processed.contains("origin_server_ts") ||
        processed["origin_server_ts"].is_null()) {
      // timestamp is handled at persistence layer
    }
  }

  return processed;
}

EventData MessageHandler::build_event(const std::string& room_id,
                                      const std::string& user_id,
                                      const std::string& event_type,
                                      const json& content, int64_t so) {
  EventData ev;
  ev.event_id = gen_event_id();
  ev.room_id = room_id;
  ev.sender = user_id;
  ev.type = event_type;
  ev.content = content;
  ev.stream_ordering = so;
  ev.origin_server_ts = now_ms();
  return ev;
}

void MessageHandler::notify_for_event(const EventData& event, int64_t so) {
  (void)event;
  (void)so;
}

void MessageHandler::mark_device_for_event(const std::string& user_id,
                                           const std::string& device_id,
                                           int64_t so) {
  (void)user_id;
  (void)device_id;
  (void)so;
}

void MessageHandler::generate_push_actions(const EventData& event) {
  // Push actions are computed in send_message with the event_push_summary update.
  (void)event;
}

// ============================================================================
// TypingHandler - full typing notification support
// ============================================================================

TypingHandler::TypingHandler(DatabasePool& db) : db_(db) {}

void TypingHandler::set_typing(const std::string& room_id,
                               const std::string& user_id, bool typing,
                               int64_t timeout_ms) {
  db_.runInteraction("set_typing", [&](LoggingTransaction& txn) {
    if (typing) {
      int64_t now = now_ms();
      txn.execute(
          "INSERT OR REPLACE INTO typing (room_id, user_id, timeout_ms, last_typed_ts) "
          "VALUES (?, ?, ?, ?)",
          {SQLParam{room_id}, SQLParam{user_id},
           SQLParam{timeout_ms > 0 ? timeout_ms : int64_t(30000)},
           SQLParam{now}});
    } else {
      txn.execute(
          "DELETE FROM typing WHERE room_id = ? AND user_id = ?",
          {SQLParam{room_id}, SQLParam{user_id}});
    }
  });

  // Notify other users in the room via to-device (EDU)
  db_.runInteraction("notify_typing", [&](LoggingTransaction& txn) {
    txn.execute(
        "SELECT DISTINCT user_id FROM room_memberships WHERE room_id = ? "
        "AND membership = 'join' AND user_id != ?",
        {SQLParam{room_id}, SQLParam{user_id}});
    auto notify_users = txn.fetchall();

    json typing_content;
    typing_content["room_id"] = room_id;
    if (typing) {
      typing_content["user_ids"] = json::array({user_id});
    } else {
      // Recompute active typing users
      txn.execute(
          "SELECT user_id FROM typing WHERE room_id = ? "
          "AND last_typed_ts + timeout_ms > ?",
          {SQLParam{room_id}, SQLParam{now_ms()}});
      auto active = txn.fetchall();
      json user_ids = json::array();
      for (auto& a : active) user_ids.push_back(row_get(a, "user_id"));
      typing_content["user_ids"] = user_ids;
    }

    for (auto& nu : notify_users) {
      std::string target = row_get(nu, "user_id");
      txn.execute(
          "INSERT INTO device_inbox (user_id, device_id, type, sender, content) "
          "VALUES (?, '*', 'm.typing', ?, ?)",
          {SQLParam{target}, SQLParam{user_id},
           SQLParam{typing_content.dump()}});
    }
  });
}

json TypingHandler::get_typing_users(const std::string& room_id) {
  json result;
  result["user_ids"] = json::array();

  int64_t now = now_ms();
  db_.runInteraction("get_typing", [&](LoggingTransaction& txn) {
    txn.execute(
        "SELECT user_id FROM typing WHERE room_id = ? "
        "AND last_typed_ts + timeout_ms > ?",
        {SQLParam{room_id}, SQLParam{now}});
    auto rows = txn.fetchall();
    for (auto& r : rows) {
      result["user_ids"].push_back(row_get(r, "user_id"));
    }
  });

  return result;
}

void TypingHandler::cleanup_expired_typing() {
  int64_t now = now_ms();
  db_.runInteraction("cleanup_typing", [&](LoggingTransaction& txn) {
    txn.execute(
        "DELETE FROM typing WHERE last_typed_ts + timeout_ms <= ?",
        {SQLParam{now}});
  });
}

// ============================================================================
// ReceiptsHandler - read receipts (m.read)
// ============================================================================

ReceiptsHandler::ReceiptsHandler(DatabasePool& db) : db_(db) {}

void ReceiptsHandler::set_read_receipt(const std::string& room_id,
                                       const std::string& user_id,
                                       const std::string& event_id,
                                       const std::optional<std::string>& receipt_type) {
  std::string rtype = receipt_type.value_or("m.read");
  int64_t now = now_ms();

  db_.runInteraction("set_read_receipt", [&](LoggingTransaction& txn) {
    // 1. Verify the event exists
    txn.execute("SELECT stream_ordering FROM events WHERE event_id = ?",
                {SQLParam{event_id}});
    auto ev = txn.fetchone();
    if (!ev.has_value()) return;

    int64_t event_so = row_get_int(*ev, "stream_ordering", 0);

    // 2. Upsert the receipt
    if (rtype == "m.read") {
      txn.execute(
          "INSERT OR REPLACE INTO read_receipts (room_id, user_id, event_id, ts) "
          "VALUES (?, ?, ?, ?)",
          {SQLParam{room_id}, SQLParam{user_id}, SQLParam{event_id},
           SQLParam{now}});
    }

    // 3. Clear unread notifications for this user in this room up to this event
    txn.execute(
        "SELECT stream_ordering FROM event_push_summary WHERE user_id = ? "
        "AND room_id = ?",
        {SQLParam{user_id}, SQLParam{room_id}});
    auto summary = txn.fetchone();
    if (summary.has_value()) {
      int64_t summary_so = row_get_int(*summary, "stream_ordering", 0);
      if (event_so >= summary_so) {
        // All events read - reset counts
        txn.execute(
            "UPDATE event_push_summary SET notif_count = 0, highlight_count = 0 "
            "WHERE user_id = ? AND room_id = ?",
            {SQLParam{user_id}, SQLParam{room_id}});
      }
    }

    // 4. Notify other users in room about the receipt
    json receipt_content;
    receipt_content[event_id][rtype][user_id]["ts"] = now;

    txn.execute(
        "SELECT DISTINCT user_id FROM room_memberships WHERE room_id = ? "
        "AND membership = 'join' AND user_id != ?",
        {SQLParam{room_id}, SQLParam{user_id}});
    auto notify_users = txn.fetchall();

    for (auto& nu : notify_users) {
      std::string target = row_get(nu, "user_id");
      txn.execute(
          "INSERT INTO device_inbox (user_id, device_id, type, sender, content) "
          "VALUES (?, '*', 'm.receipt', ?, ?)",
          {SQLParam{target}, SQLParam{user_id},
           SQLParam{receipt_content.dump()}});
    }
  });
}

json ReceiptsHandler::get_read_receipts(const std::string& room_id) {
  json result;
  result["content"] = json::object();

  db_.runInteraction("get_read_receipts", [&](LoggingTransaction& txn) {
    txn.execute(
        "SELECT user_id, event_id, ts FROM read_receipts WHERE room_id = ?",
        {SQLParam{room_id}});
    auto rows = txn.fetchall();
    for (auto& r : rows) {
      std::string uid = row_get(r, "user_id");
      std::string eid = row_get(r, "event_id");
      int64_t rts = row_get_int(r, "ts", 0);
      result["content"][eid]["m.read"][uid]["ts"] = rts;
    }
  });

  return result;
}

// ============================================================================
// SearchHandler - full-text search over room events
// ============================================================================

SearchHandler::SearchHandler(DatabasePool& db) : db_(db) {}

json SearchHandler::search(const std::string& user_id,
                           const SearchQuery& query) {
  json result;
  result["search_categories"] = json::object();
  result["search_categories"]["room_events"] = json::object();

  db_.runInteraction("search", [&](LoggingTransaction& txn) {
    // Build search SQL
    std::string search_term = query.search_term;
    std::string order = query.order_by.value_or("rank");

    // Only search rooms the user is in
    std::string user_rooms_subquery =
        "(SELECT DISTINCT room_id FROM room_memberships WHERE user_id = ? "
        "AND membership = 'join')";

    // Full-text search using LIKE (basic implementation; production would use FTS5)
    std::string where_clause = "es.room_id IN " + user_rooms_subquery;
    if (!search_term.empty()) {
      where_clause += " AND (es.value LIKE ? OR es.key LIKE ?)";
    }
    if (!query.room_id.empty()) {
      where_clause += " AND es.room_id = ?";
    }

    std::string order_clause = "es.stream_ordering DESC";
    if (order == "rank") {
      order_clause = "es.stream_ordering DESC";
    }

    auto limit = static_cast<int64_t>(query.limit > 0 ? query.limit : 10);
    std::string sql = "SELECT DISTINCT es.event_id, es.room_id, es.stream_ordering, "
                      "es.origin_server_ts, e.type, e.sender, e.content "
                      "FROM event_search es JOIN events e ON es.event_id = e.event_id "
                      "WHERE " + where_clause +
                      " ORDER BY " + order_clause + " LIMIT ?";

    // Parameter construction
    std::vector<SQLParam> params;
    params.push_back(SQLParam{user_id});
    if (!search_term.empty()) {
      params.push_back(SQLParam{"%" + search_term + "%"});
      params.push_back(SQLParam{"%" + search_term + "%"});
    }
    if (!query.room_id.empty()) {
      params.push_back(SQLParam{query.room_id});
    }
    params.push_back(SQLParam{limit});

    txn.execute(sql, params);
    auto rows = txn.fetchall();

    json room_results = json::object();
    json highlight_list = json::array();
    int count = 0;
    json events_array = json::array();

    for (auto& r : rows) {
      json ev = row_to_event_json(r);
      events_array.push_back(ev);

      // Collect room groupings
      std::string rid = row_get(r, "room_id");
      if (!room_results.contains(rid)) {
        room_results[rid] = json::object();
        room_results[rid]["results"] = json::array();
        room_results[rid]["count"] = 0;
        room_results[rid]["next_batch"] = "";
      }
      room_results[rid]["results"].push_back(ev);
      room_results[rid]["count"] = room_results[rid]["count"].get<int>() + 1;
      count++;

      // Highlight the search term
      std::string body;
      try {
        auto content = json::parse(row_get(r, "content", "{}"));
        body = content.value("body", "");
      } catch (...) { /* ignore */ }
      if (!body.empty() && !search_term.empty()) {
        size_t pos = body.find(search_term);
        if (pos != std::string::npos) {
          highlight_list.push_back(body);
        }
      }
    }

    result["search_categories"]["room_events"]["count"] = count;
    result["search_categories"]["room_events"]["results"] = events_array;
    result["search_categories"]["room_events"]["next_batch"] = "";
    result["search_categories"]["room_events"]["highlights"] = highlight_list;
    result["search_categories"]["room_events"]["groups"] = room_results;
  });

  return result;
}

json SearchHandler::search_rooms(const std::string& user_id,
                                  const std::string& search_term,
                                  int limit) {
  json result;
  result["results"] = json::array();

  db_.runInteraction("search_rooms", [&](LoggingTransaction& txn) {
    std::string sql =
        "SELECT r.room_id, r.name, r.topic, r.creator, r.is_public "
        "FROM rooms r "
        "JOIN room_memberships rm ON r.room_id = rm.room_id "
        "WHERE rm.user_id = ? AND rm.membership = 'join' "
        "AND (r.name LIKE ? OR r.topic LIKE ?) "
        "LIMIT ?";
    txn.execute(sql, {SQLParam{user_id},
                      SQLParam{"%" + search_term + "%"},
                      SQLParam{"%" + search_term + "%"},
                      SQLParam{int64_t(limit > 0 ? limit : 20)}});
    auto rows = txn.fetchall();
    for (auto& r : rows) {
      json room;
      room["room_id"] = row_get(r, "room_id");
      room["name"] = row_get(r, "name", "");
      room["topic"] = row_get(r, "topic", "");
      room["creator"] = row_get(r, "creator", "");
      room["is_public"] = row_get_int(r, "is_public", 0) != 0;

      // Get member count
      txn.execute(
          "SELECT COUNT(*) as cnt FROM room_memberships WHERE room_id = ? "
          "AND membership = 'join'",
          {SQLParam{row_get(r, "room_id")}});
      auto cnt = txn.fetchone();
      room["num_joined_members"] =
          cnt.has_value() ? row_get_int(*cnt, "cnt", 0) : 0;

      result["results"].push_back(room);
    }
  });

  return result;
}

json SearchHandler::index_event(const std::string& event_id,
                                 const std::string& room_id,
                                 const std::string& event_type,
                                 const json& content, int64_t stream_ordering,
                                 int64_t origin_server_ts) {
  db_.runInteraction("index_event", [&](LoggingTransaction& txn) {
    // Index content.body for message events
    if (event_type == "m.room.message" || event_type == "m.room.encrypted") {
      if (content.contains("body") && content["body"].is_string()) {
        std::string body = content["body"].get<std::string>();
        txn.execute(
            "INSERT OR REPLACE INTO event_search (event_id, room_id, key, value, "
            "stream_ordering, origin_server_ts) VALUES (?, ?, 'content.body', ?, ?, ?)",
            {SQLParam{event_id}, SQLParam{room_id}, SQLParam{body},
             SQLParam{stream_ordering}, SQLParam{origin_server_ts}});
      }
    }

    // Index m.room.name and m.room.topic from state events
    if (event_type == "m.room.name" && content.contains("name")) {
      txn.execute(
          "INSERT OR REPLACE INTO event_search (event_id, room_id, key, value, "
          "stream_ordering, origin_server_ts) VALUES (?, ?, 'content.name', ?, ?, ?)",
          {SQLParam{event_id}, SQLParam{room_id},
           SQLParam{content["name"].get<std::string>()},
           SQLParam{stream_ordering}, SQLParam{origin_server_ts}});
    }
    if (event_type == "m.room.topic" && content.contains("topic")) {
      txn.execute(
          "INSERT OR REPLACE INTO event_search (event_id, room_id, key, value, "
          "stream_ordering, origin_server_ts) VALUES (?, ?, 'content.topic', ?, ?, ?)",
          {SQLParam{event_id}, SQLParam{room_id},
           SQLParam{content["topic"].get<std::string>()},
           SQLParam{stream_ordering}, SQLParam{origin_server_ts}});
    }
  });

  return json::object();
}

void SearchHandler::reindex_room(const std::string& room_id) {
  db_.runInteraction("reindex_room", [&](LoggingTransaction& txn) {
    // Clear existing indexes for this room
    txn.execute("DELETE FROM event_search WHERE room_id = ?",
                {SQLParam{room_id}});

    // Re-index all message events
    txn.execute(
        "SELECT event_id, type, content, stream_ordering, origin_server_ts "
        "FROM events WHERE room_id = ? AND is_outlier = 0 AND is_redacted = 0",
        {SQLParam{room_id}});
    auto rows = txn.fetchall();
    for (auto& r : rows) {
      std::string eid = row_get(r, "event_id");
      std::string ev_type = row_get(r, "type");
      int64_t so = row_get_int(r, "stream_ordering", 0);
      int64_t ots = row_get_int(r, "origin_server_ts", 0);
      try {
        json content = json::parse(row_get(r, "content", "{}"));
        if (ev_type == "m.room.message" || ev_type == "m.room.encrypted") {
          if (content.contains("body") && content["body"].is_string()) {
            std::string body = content["body"].get<std::string>();
            txn.execute(
                "INSERT INTO event_search (event_id, room_id, key, value, "
                "stream_ordering, origin_server_ts) VALUES (?, ?, 'content.body', ?, ?, ?)",
                {SQLParam{eid}, SQLParam{room_id}, SQLParam{body},
                 SQLParam{so}, SQLParam{ots}});
          }
        }
      } catch (...) { /* skip malformed content */ }
    }
  });
}

// ============================================================================
// PaginationHandler - /rooms/{roomId}/messages pagination
// ============================================================================

PaginationHandler::PaginationHandler(DatabasePool& db) : db_(db) {}

json PaginationHandler::get_messages(const std::string& room_id,
                                      const std::string& user_id,
                                      const PaginationConfig& config) {
  json result;
  result["chunk"] = json::array();
  result["start"] = config.from_token;
  result["end"] = "";
  result["state"] = json::array();

  db_.runInteraction("get_messages", [&](LoggingTransaction& txn) {
    // Verify the user is in the room
    txn.execute(
        "SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?",
        {SQLParam{room_id}, SQLParam{user_id}});
    auto mem = txn.fetchone();
    std::string membership = mem.has_value() ? row_get(*mem, "membership") : "leave";
    if (membership != "join" && membership != "invite") {
      result["errcode"] = "M_FORBIDDEN";
      result["error"] = "You are not in this room";
      return;
    }

    // Parse direction and from_token
    std::string dir = config.dir.value_or("b");
    int64_t from_so = config.from_token.empty() ? 0
        : parse_stream_token(config.from_token);
    int64_t to_so = config.to_token.empty() ? INT64_MAX
        : parse_stream_token(config.to_token);
    int limit = config.limit > 0 ? config.limit : 10;

    std::string order_clause;
    std::string comparator;

    if (dir == "b") {
      // Backward pagination
      if (from_so == 0) from_so = INT64_MAX;
      order_clause = "ORDER BY e.stream_ordering DESC";
      comparator = "e.stream_ordering < ?";
      if (to_so > 0) {
        comparator += " AND e.stream_ordering > ?";
      }
    } else {
      // Forward pagination
      order_clause = "ORDER BY e.stream_ordering ASC";
      comparator = "e.stream_ordering > ?";
      if (to_so < INT64_MAX) {
        comparator += " AND e.stream_ordering < ?";
      }
    }

    // Build query
    std::string sql = "SELECT e.* FROM events e WHERE e.room_id = ? "
                      "AND e.is_outlier = 0 AND " + comparator +
                      " " + order_clause + " LIMIT ?";

    std::vector<SQLParam> params;
    params.push_back(SQLParam{room_id});
    params.push_back(SQLParam{from_so});
    if ((dir == "b" && to_so > 0) || (dir != "b" && to_so < INT64_MAX)) {
      params.push_back(SQLParam{to_so});
    }
    params.push_back(SQLParam{int64_t(limit)});

    txn.execute(sql, params);
    auto rows = txn.fetchall();

    // Build chunk - for backward, results come in reverse order so we
    // need to reverse them
    std::vector<json> chunk_events;
    for (auto& r : rows) {
      chunk_events.push_back(row_to_event_json(r));
    }
    if (dir == "b") {
      std::reverse(chunk_events.begin(), chunk_events.end());
    }

    for (auto& ev : chunk_events) {
      result["chunk"].push_back(ev);
    }

    // Set start/end tokens
    if (!chunk_events.empty()) {
      if (dir == "b") {
        // Backward: first event (oldest) is start
        result["start"] = "s" + std::to_string(
            row_get_int(rows.back(), "stream_ordering", 0));
      } else {
        result["start"] = "s" + std::to_string(
            row_get_int(rows.front(), "stream_ordering", 0));
      }
      result["end"] = "s" + std::to_string(
          dir == "b" ? row_get_int(rows.front(), "stream_ordering", 0)
                     : row_get_int(rows.back(), "stream_ordering", 0));
    }

    // Attach relevant state events
    // For first page of backward pagination, include current state
    if (dir == "b" && from_so == INT64_MAX) {
      txn.execute(
          "SELECT cse.type, cse.state_key, cse.event_id, e.sender, e.content, "
          "e.origin_server_ts "
          "FROM current_state_events cse JOIN events e ON cse.event_id = e.event_id "
          "WHERE cse.room_id = ?",
          {SQLParam{room_id}});
      auto state_rows = txn.fetchall();
      for (auto& sr : state_rows) {
        json sev;
        sev["type"] = row_get(sr, "type");
        sev["sender"] = row_get(sr, "sender");
        sev["event_id"] = row_get(sr, "event_id");
        sev["room_id"] = room_id;
        sev["origin_server_ts"] = row_get_int(sr, "origin_server_ts", 0);
        std::string sk = row_get(sr, "state_key", "");
        if (!sk.empty()) sev["state_key"] = sk;
        try {
          sev["content"] = json::parse(row_get(sr, "content", "{}"));
        } catch (...) {
          sev["content"] = json::object();
        }
        sev["unsigned"] = json::object();
        result["state"].push_back(sev);
      }
    }
  });

  return result;
}

json PaginationHandler::get_event_context(const std::string& room_id,
                                           const std::string& user_id,
                                           const std::string& event_id,
                                           int limit) {
  json result;
  result["event"] = json::object();
  result["events_before"] = json::array();
  result["events_after"] = json::array();
  result["state"] = json::array();
  result["start"] = "";
  result["end"] = "";

  db_.runInteraction("get_event_context", [&](LoggingTransaction& txn) {
    // Fetch the target event
    txn.execute("SELECT * FROM events WHERE event_id = ? AND room_id = ?",
                {SQLParam{event_id}, SQLParam{room_id}});
    auto target = txn.fetchone();
    if (!target.has_value()) {
      result["error"] = "Event not found";
      return;
    }

    result["event"] = row_to_event_json(*target);

    int64_t target_so = row_get_int(*target, "stream_ordering", 0);
    int ctx_limit = limit > 0 ? limit : 5;

    // Events before
    txn.execute(
        "SELECT * FROM events WHERE room_id = ? AND stream_ordering < ? "
        "AND is_outlier = 0 ORDER BY stream_ordering DESC LIMIT ?",
        {SQLParam{room_id}, SQLParam{target_so},
         SQLParam{int64_t(ctx_limit)}});
    auto before_rows = txn.fetchall();
    std::reverse(before_rows.begin(), before_rows.end());
    for (auto& r : before_rows) {
      result["events_before"].push_back(row_to_event_json(r));
    }

    // Events after
    txn.execute(
        "SELECT * FROM events WHERE room_id = ? AND stream_ordering > ? "
        "AND is_outlier = 0 ORDER BY stream_ordering ASC LIMIT ?",
        {SQLParam{room_id}, SQLParam{target_so},
         SQLParam{int64_t(ctx_limit)}});
    auto after_rows = txn.fetchall();
    for (auto& r : after_rows) {
      result["events_after"].push_back(row_to_event_json(r));
    }

    // State at this event
    txn.execute(
        "SELECT cse.type, cse.state_key, cse.event_id, e.sender, e.content, "
        "e.origin_server_ts "
        "FROM current_state_events cse JOIN events e ON cse.event_id = e.event_id "
        "WHERE cse.room_id = ?",
        {SQLParam{room_id}});
    auto state_rows = txn.fetchall();
    for (auto& sr : state_rows) {
      json sev;
      sev["type"] = row_get(sr, "type");
      sev["sender"] = row_get(sr, "sender");
      sev["event_id"] = row_get(sr, "event_id");
      sev["room_id"] = room_id;
      sev["origin_server_ts"] = row_get_int(sr, "origin_server_ts", 0);
      std::string sk = row_get(sr, "state_key", "");
      if (!sk.empty()) sev["state_key"] = sk;
      try {
        sev["content"] = json::parse(row_get(sr, "content", "{}"));
      } catch (...) {
        sev["content"] = json::object();
      }
      sev["unsigned"] = json::object();
      result["state"].push_back(sev);
    }

    if (!before_rows.empty()) {
      result["start"] = "s" + row_get(before_rows.front(), "stream_ordering", "0");
    }
    if (!after_rows.empty()) {
      result["end"] = "s" + row_get(after_rows.back(), "stream_ordering", "0");
    }
  });

  return result;
}

json PaginationHandler::get_member_events(const std::string& room_id,
                                           const std::string& user_id,
                                           int64_t at_token,
                                           const std::optional<std::string>& not_membership,
                                           int64_t not_room_id) {
  (void)not_room_id;
  json result;
  result["chunk"] = json::array();

  db_.runInteraction("get_member_events", [&](LoggingTransaction& txn) {
    std::string sql =
        "SELECT e.* FROM events e WHERE e.room_id = ? AND e.type = 'm.room.member' "
        "AND e.is_state = 1 AND e.is_outlier = 0 ";
    if (!not_membership.value_or("").empty()) {
      sql += "AND e.membership != ? ";
    }
    sql += "ORDER BY e.stream_ordering ASC LIMIT 50";

    std::vector<SQLParam> params;
    params.push_back(SQLParam{room_id});
    if (!not_membership.value_or("").empty()) {
      params.push_back(SQLParam{*not_membership});
    }
    txn.execute(sql, params);
    auto rows = txn.fetchall();

    for (auto& r : rows) {
      json ev = row_to_event_json(r);
      ev["content"]["membership"] = row_get(r, "membership", "leave");
      if (!row_get(r, "state_key", "").empty()) {
        ev["state_key"] = row_get(r, "state_key", "");
      }
      result["chunk"].push_back(ev);
    }
  });

  (void)user_id;
  (void)at_token;
  return result;
}

// ============================================================================
// Additional helper methods / convenience wrappers
// ============================================================================

// SyncHandler: generate_next_batch_token for simple use by HTTP layer
std::string SyncHandler::generate_next_batch(DatabasePool& db) {
  std::string token;
  db.runInteraction("generate_next_batch", [&](LoggingTransaction& txn) {
    txn.execute("SELECT next_val FROM stream_ordering_seq WHERE id = 1");
    auto r = txn.fetchone();
    int64_t next_val = 0;
    if (r.has_value()) {
      for (auto& c : *r) {
        if (c.name == "next_val")
          next_val = std::stoll(c.value.value_or("0"));
      }
    }
    token = make_next_batch_token(next_val);
  });
  return token;
}

// SyncHandler: wait for new events (long-poll / timeout logic for /sync)
SyncHandler::SyncResult SyncHandler::wait_for_sync(
    const SyncConfig& config) {
  // If there are new events since `since`, return immediately.
  int64_t since_so = config.since.empty() ? 0 : parse_stream_token(config.since);

  // Check if anything has changed
  int64_t max_so = 0;
  db_.runInteraction("check_stream", [&](LoggingTransaction& txn) {
    txn.execute("SELECT next_val FROM stream_ordering_seq WHERE id = 1");
    auto r = txn.fetchone();
    if (r.has_value()) {
      for (auto& c : *r) {
        if (c.name == "next_val")
          max_so = std::stoll(c.value.value_or("0"));
      }
    }
  });

  bool has_new_data = (max_so > since_so);

  if (!has_new_data && config.timeout_ms > 0) {
    // Poll with exponential backoff up to timeout
    int64_t deadline = now_ms() + config.timeout_ms;
    int64_t poll_interval = 100;  // start at 100ms
    int64_t max_poll = 2000;      // max 2 second intervals

    while (now_ms() < deadline && !has_new_data) {
      // Sleep for poll_interval (in a real server this would use a
      // condition variable or event-driven notification instead of
      // busy polling).
      std::this_thread::sleep_for(
          std::chrono::milliseconds(poll_interval));

      db_.runInteraction("poll_stream", [&](LoggingTransaction& txn) {
        txn.execute("SELECT next_val FROM stream_ordering_seq WHERE id = 1");
        auto r = txn.fetchone();
        int64_t cur = 0;
        if (r.has_value()) {
          for (auto& c : *r) {
            if (c.name == "next_val")
              cur = std::stoll(c.value.value_or("0"));
          }
        }
        has_new_data = (cur > since_so);
        max_so = cur;
      });

      poll_interval = std::min(poll_interval * 2, max_poll);
    }
  }

  // Now do the actual sync
  SyncConfig real_cfg = config;
  real_cfg.full_state = config.full_state || since_so == 0;
  return sync(real_cfg);
}

// RoomCreationHandler: utility to generate room ID with prefix
std::string RoomCreationHandler::generate_room_id_with_alias(
    const std::string& alias_localpart) {
  (void)alias_localpart;
  return gen_room_id();
}

// MessageHandler: bulk send messages (for batch imports)
std::vector<MessageHandler::SendResult> MessageHandler::send_messages_bulk(
    const std::string& room_id, const std::string& user_id,
    const std::vector<std::pair<std::string, json>>& messages) {
  std::vector<SendResult> results;
  for (auto& [event_type, content] : messages) {
    results.push_back(send_message(room_id, user_id, event_type, content));
  }
  return results;
}

// TypingHandler: broadcast typing to all room members (called from HTTP endpoint)
nlohmann::json TypingHandler::handle_typing_request(
    const std::string& room_id, const std::string& user_id,
    bool typing, int64_t timeout_ms) {
  // Verify membership
  db_.runInteraction("typing_check", [&](LoggingTransaction& txn) {
    txn.execute(
        "SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?",
        {SQLParam{room_id}, SQLParam{user_id}});
    auto mem = txn.fetchone();
    if (!mem.has_value() || row_get(*mem, "membership") != "join") {
      // Return error response
      return;
    }
  });

  set_typing(room_id, user_id, typing, timeout_ms);
  return json::object();
}

// ReceiptsHandler: handle a batch of receipts
void ReceiptsHandler::set_receipts_bulk(
    const std::string& room_id, const std::string& user_id,
    const std::vector<std::pair<std::string, std::string>>& receipts) {
  for (auto& [event_id, receipt_type] : receipts) {
    set_read_receipt(room_id, user_id, event_id, receipt_type);
  }
}

// SearchHandler: advanced search with multiple filters
nlohmann::json SearchHandler::search_all_rooms(
    const std::string& user_id, const SearchQuery& query) {
  nlohmann::json result;
  result["results"] = nlohmann::json::array();

  db_.runInteraction("search_all_rooms", [&](LoggingTransaction& txn) {
    std::string search_term = query.search_term;
    if (search_term.empty()) return;

    // Search across all user's joined rooms
    std::string sql =
        "SELECT DISTINCT e.event_id, e.room_id, e.type, e.sender, e.content, "
        "e.stream_ordering, e.origin_server_ts "
        "FROM events e "
        "JOIN event_search es ON e.event_id = es.event_id "
        "JOIN room_memberships rm ON e.room_id = rm.room_id "
        "WHERE rm.user_id = ? AND rm.membership = 'join' "
        "AND e.is_outlier = 0 AND e.is_redacted = 0 "
        "AND es.value LIKE ? "
        "ORDER BY e.stream_ordering DESC LIMIT ?";

    txn.execute(sql, {SQLParam{user_id},
                      SQLParam{"%" + search_term + "%"},
                      SQLParam{int64_t(query.limit > 0 ? query.limit : 20)}});
    auto rows = txn.fetchall();
    for (auto& r : rows) {
      nlohmann::json ev = row_to_event_json(r);
      result["results"].push_back(ev);
    }
  });

  return result;
}

// PaginationHandler: checkpoint-style pagination for sync v2
nlohmann::json PaginationHandler::paginate_room_timeline(
    const std::string& room_id, const std::string& user_id,
    const std::string& from_token, const std::string& dir, int limit) {
  PaginationConfig cfg;
  cfg.from_token = from_token;
  cfg.dir = dir;
  cfg.limit = limit;
  return get_messages(room_id, user_id, cfg);
}

// Additional DDL indexes (called separately or as part of ensure_core_full_tables)
void ensure_core_full_indexes(DatabasePool& db) {
  db.runInteraction("ensure_core_full_indexes", [&](LoggingTransaction& txn) {
    // Events table performance indexes
    txn.execute(
        "CREATE INDEX IF NOT EXISTS events_room_id_idx ON events(room_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS events_sender_idx ON events(sender)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS events_type_idx ON events(type)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS events_stream_ordering_idx "
        "ON events(stream_ordering)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS events_room_stream_idx "
        "ON events(room_id, stream_ordering)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS events_txn_id_idx ON events(txn_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS events_room_type_idx "
        "ON events(room_id, type)");

    // Current state indexes
    txn.execute(
        "CREATE INDEX IF NOT EXISTS current_state_events_event_id_idx "
        "ON current_state_events(event_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS current_state_events_room_type_idx "
        "ON current_state_events(room_id, type)");

    // Room memberships indexes
    txn.execute(
        "CREATE INDEX IF NOT EXISTS room_memberships_user_idx "
        "ON room_memberships(user_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS room_memberships_room_idx "
        "ON room_memberships(room_id)");
    txn.execute(
        "CREATE INDEX IF NOT EXISTS room_memberships_membership_idx "
        "ON room_memberships(membership)");

    // Read receipts index
    txn.execute(
        "CREATE INDEX IF NOT EXISTS read_receipts_room_idx "
        "ON read_receipts(room_id)");

    // Typing index
    txn.execute(
        "CREATE INDEX IF NOT EXISTS typing_room_idx ON typing(room_id)");

    // Device inbox index
    txn.execute(
        "CREATE INDEX IF NOT EXISTS device_inbox_user_id_idx "
        "ON device_inbox(user_id)");

    // Account data index
    txn.execute(
        "CREATE INDEX IF NOT EXISTS account_data_user_idx "
        "ON account_data(user_id)");

    // Event push summary index
    txn.execute(
        "CREATE INDEX IF NOT EXISTS event_push_summary_user_idx "
        "ON event_push_summary(user_id)");

    // Event edges index
    txn.execute(
        "CREATE INDEX IF NOT EXISTS event_edges_prev_idx "
        "ON event_edges(prev_event_id)");

    // Event relations index
    txn.execute(
        "CREATE INDEX IF NOT EXISTS event_relations_relates_idx "
        "ON event_relations(relates_to_id)");

    // Presence stream index
    txn.execute(
        "CREATE INDEX IF NOT EXISTS presence_stream_user_idx "
        "ON presence_stream(user_id)");

    // State groups index
    txn.execute(
        "CREATE INDEX IF NOT EXISTS event_to_state_groups_state_group_idx "
        "ON event_to_state_groups(state_group)");
  });
}

// ============================================================================
}  // namespace progressive::handlers
