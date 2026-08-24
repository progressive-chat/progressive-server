// data.hpp — translation of Conduit commit fa322689's src/data.rs
//
// Data now wraps a Database (the named-tree struct from database.rs) and
// caches the hostname in memory:
//
//   pub struct Data { hostname: String, db: Database }
//
// NEW PDU storage — the event graph in three trees:
//
//   pub fn pdu_get(&self, event_id: &EventId) -> Option<RoomV3Pdu>
//       // eventid_pduid -> pduid_pdus
//   pub fn pdu_leaves_replace(&self, room_id, event_id) -> Vec<EventId>
//       // old leaves out, new leaf in
//   pub fn pdu_append(&self, event_id, room_id, event)
//       // prev_events = leaves; depth = max(prev)+1; fills origin/auth_events/
//       // hashes/signatures TODOs; pdu_id = 'd' + room_id + '#' + counter
//   pub fn pdus_all(&self) / pdus_since(since)

#pragma once

#include "database.hpp"
#include "json_value.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

class Data {
 public:
  /// Load an existing database or create a new one.
  static Data load_or_create(const std::filesystem::path& dir);

  /// Set the hostname of the server.
  void set_hostname(const std::string& hostname);
  /// Get the hostname of the server.
  const std::string& hostname() const;

  bool user_exists(const std::string& user_id) const;
  void user_add(const std::string& user_id, const std::optional<std::string>& password);
  std::optional<std::string> user_from_token(const std::string& token) const;
  std::optional<std::string> password_get(const std::string& user_id) const;
  void device_add(const std::string& user_id, const std::string& device_id);
  void token_replace(const std::string& user_id, const std::string& device_id,
                     const std::string& token);

  // --- PDU graph (NEW in fa322689) ------------------------------------------

  // Stored PDU by event id, or nullopt.
  std::optional<std::string> pdu_get(const std::string& event_id) const;

  // Returns the previous leaves and makes event_id the only one.
  std::vector<std::string> pdu_leaves_replace(const std::string& room_id,
                                              const std::string& event_id);

  // Append an event (as JSON object Value) to the room's DAG.
  void pdu_append(const std::string& event_id, const std::string& room_id,
                  json::Value event);

  // All stored PDUs, oldest first.
  std::vector<std::string> pdus_all() const;

 private:
  explicit Data(const std::filesystem::path& dir)
      : db_storage_(stubdb::Db::open(dir)),
        db_(stubdb::Database::open(&db_storage_)) {}

  // OWNERSHIP NOTE: Database's trees point into db_storage_'s maps, so
  // db_storage_ must be declared first and never move afterwards. (Upstream
  // sidesteps this with Rust ownership: Database owns its sled::Db.)
  std::string hostname_;
  stubdb::Db db_storage_;
  stubdb::Database db_;
};
