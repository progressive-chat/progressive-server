#pragma once
// ============================================================================
// room.hpp - C++ translation of Synapse room storage module
// Original: synapse/storage/databases/main/room.py (3,240 lines)
// ============================================================================
// Copyright 2024 The Matrix.org Foundation C.I.C.
// Licensed under AGPLv3
// ============================================================================

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"

namespace progressive::storage {

// ============================================================================
// Forward declarations
// ============================================================================
class DatabasePool;
class LoggingTransaction;
class HomeServer;

// ============================================================================
// RatelimitOverride (room.py lines 80-85)
// ============================================================================
struct RatelimitOverride {
  int64_t messages_per_second = 0;
  int64_t burst_count = 0;
};

// ============================================================================
// LargestRoomStats (room.py lines 88-100)
// ============================================================================
struct LargestRoomStats {
  std::string room_id;
  std::optional<std::string> name;
  std::optional<std::string> canonical_alias;
  int64_t joined_members = 0;
  std::optional<std::string> join_rules;
  std::optional<std::string> guest_access;
  std::optional<std::string> history_visibility;
  int64_t state_events = 0;
  std::optional<std::string> avatar;
  std::optional<std::string> topic;
  std::optional<std::string> room_type;
};

// ============================================================================
// RoomStats (room.py lines 103-111)
// ============================================================================
struct RoomStats : public LargestRoomStats {
  int64_t joined_local_members = 0;
  std::optional<std::string> version;
  std::optional<std::string> creator;
  std::optional<std::string> encryption;
  bool federatable = false;
  bool is_public = false;
};

// ============================================================================
// QuarantinedMediaUpdate (room.py lines 113-118)
// ============================================================================
struct QuarantinedMediaUpdate {
  int64_t stream_id = 0;
  std::string origin;
  std::string media_id;
  bool quarantined = false;
};

// ============================================================================
// RoomSortOrder (room.py lines 121-146)
// ============================================================================
enum class RoomSortOrder {
  ALPHABETICAL,
  SIZE,
  NAME,
  CANONICAL_ALIAS,
  JOINED_MEMBERS,
  JOINED_LOCAL_MEMBERS,
  VERSION,
  CREATOR,
  ENCRYPTION,
  FEDERATABLE,
  PUBLIC,
  JOIN_RULES,
  GUEST_ACCESS,
  HISTORY_VISIBILITY,
  STATE_EVENTS
};

inline RoomSortOrder room_sort_order_from_string(const std::string& s) {
  if (s == "alphabetical") return RoomSortOrder::ALPHABETICAL;
  if (s == "size") return RoomSortOrder::SIZE;
  if (s == "name") return RoomSortOrder::NAME;
  if (s == "canonical_alias") return RoomSortOrder::CANONICAL_ALIAS;
  if (s == "joined_members") return RoomSortOrder::JOINED_MEMBERS;
  if (s == "joined_local_members") return RoomSortOrder::JOINED_LOCAL_MEMBERS;
  if (s == "version") return RoomSortOrder::VERSION;
  if (s == "creator") return RoomSortOrder::CREATOR;
  if (s == "encryption") return RoomSortOrder::ENCRYPTION;
  if (s == "federatable") return RoomSortOrder::FEDERATABLE;
  if (s == "public") return RoomSortOrder::PUBLIC;
  if (s == "join_rules") return RoomSortOrder::JOIN_RULES;
  if (s == "guest_access") return RoomSortOrder::GUEST_ACCESS;
  if (s == "history_visibility") return RoomSortOrder::HISTORY_VISIBILITY;
  if (s == "state_events") return RoomSortOrder::STATE_EVENTS;
  throw std::invalid_argument("Incorrect value for order_by: " + s);
}

// ============================================================================
// PartialStateResyncInfo (room.py lines 149-152)
// ============================================================================
struct PartialStateResyncInfo {
  std::optional<std::string> joined_via;
  std::set<std::string> servers_in_room;
};

// ============================================================================
// RetentionPolicy - simplified for room store usage
// ============================================================================
struct RetentionPolicy {
  std::optional<int64_t> min_lifetime;
  std::optional<int64_t> max_lifetime;
};

// ============================================================================
// Direction enum
// ============================================================================
enum class Direction { FORWARDS, BACKWARDS };

// ============================================================================
// join_rules constants (used inline)
// ============================================================================
namespace JoinRules {
  constexpr const char* PUBLIC = "public";
  constexpr const char* KNOCK = "knock";
  constexpr const char* KNOCK_RESTRICTED = "knock_restricted";
}  // namespace JoinRules

// ============================================================================
// EventTypes constants used by this module
// ============================================================================
namespace EventTypes {
  constexpr const char* Create = "m.room.create";
  constexpr const char* Retention = "m.room.retention";
  constexpr const char* Tombstone = "m.room.tombstone";
}  // namespace EventTypes

// ============================================================================
// EventContentFields constants
// ============================================================================
namespace EventContentFields {
  constexpr const char* ROOM_CREATOR = "creator";
  constexpr const char* ROOM_TYPE = "room_type";
}  // namespace EventContentFields

// ============================================================================
// PublicRoomsFilterFields constants
// ============================================================================
namespace PublicRoomsFilterFields {
  constexpr const char* GENERIC_SEARCH_TERM = "generic_search_term";
  constexpr const char* ROOM_TYPES = "room_types";
}  // namespace PublicRoomsFilterFields

// ============================================================================
// ThirdPartyInstanceID - simplified
// ============================================================================
struct ThirdPartyInstanceID {
  std::optional<std::string> appservice_id;
  std::optional<std::string> network_id;
};

// ============================================================================
// RoomVersion - simplified
// ============================================================================
struct RoomVersion {
  std::string identifier;
};

// ============================================================================
// RoomWorkerStore (room.py lines 155-2456)
// Base class for room-related storage operations (read-only + quarantine)
// ============================================================================
class RoomWorkerStore {
public:
  RoomWorkerStore(DatabasePool& database, const std::string& server_name,
                  const std::string& instance_name);
  virtual ~RoomWorkerStore() = default;

  // ---- Room CRUD ----

  // store_room (line 346)
  void store_room(const std::string& room_id,
                  const std::string& room_creator_user_id, bool is_public,
                  const RoomVersion& room_version);

  // get_room (line 380)
  std::optional<std::tuple<bool, bool>> get_room(const std::string& room_id);

  // get_room_with_stats (line 406)
  std::optional<RoomStats> get_room_with_stats(const std::string& room_id);

  // get_public_room_ids (line 458)
  std::vector<std::string> get_public_room_ids();

  // count_public_rooms (line 493)
  int64_t count_public_rooms(
      const std::optional<ThirdPartyInstanceID>& network_tuple,
      bool ignore_non_federatable,
      const nlohmann::json& search_filter = nlohmann::json{});

  // get_room_count (line 564)
  int64_t get_room_count();

  // get_largest_public_rooms (line 575)
  std::vector<LargestRoomStats> get_largest_public_rooms(
      const std::optional<ThirdPartyInstanceID>& network_tuple,
      const nlohmann::json& search_filter, std::optional<int64_t> limit,
      std::optional<std::tuple<int64_t, std::string>> bounds, bool forwards,
      bool ignore_non_federatable = false);

  // is_room_blocked (line 749)
  std::optional<bool> is_room_blocked(const std::string& room_id);

  // room_is_blocked_by (line 759)
  std::optional<std::string> room_is_blocked_by(const std::string& room_id);

  // get_rooms_paginate (line 773)
  std::tuple<std::vector<nlohmann::json>, int64_t> get_rooms_paginate(
      int64_t start, int64_t limit, const std::string& order_by,
      bool reverse_order, const std::optional<std::string>& search_term,
      const std::optional<bool>& public_rooms,
      const std::optional<bool>& empty_rooms);

  // ---- Rate limiting ----

  // get_ratelimit_for_user (line 974)
  std::optional<RatelimitOverride> get_ratelimit_for_user(
      const std::string& user_id);

  // set_ratelimit_for_user (line 998)
  void set_ratelimit_for_user(const std::string& user_id,
                               int64_t messages_per_second,
                               int64_t burst_count);

  // delete_ratelimit_for_user (line 1025)
  void delete_ratelimit_for_user(const std::string& user_id);

  // ---- Retention ----

  // get_retention_policy_for_room (line 1054)
  RetentionPolicy get_retention_policy_for_room(const std::string& room_id);

  // get_rooms_for_retention_period_in_range (line 1675)
  std::unordered_map<std::string, RetentionPolicy>
  get_rooms_for_retention_period_in_range(
      const std::optional<int64_t>& min_ms,
      const std::optional<int64_t>& max_ms, bool include_null = false);

  // ---- Media quarantine ----

  // get_media_mxcs_in_room (line 1122)
  std::tuple<std::vector<std::string>, std::vector<std::string>>
  get_media_mxcs_in_room(const std::string& room_id);

  // quarantine_media_ids_in_room (line 1151)
  int64_t quarantine_media_ids_in_room(const std::string& room_id,
                                        const std::string& quarantined_by);

  // quarantine_media_by_id (line 1229)
  int64_t quarantine_media_by_id(const std::string& server_name,
                                  const std::string& media_id,
                                  const std::optional<std::string>& quarantined_by);

  // quarantine_media_ids_by_user (line 1258)
  int64_t quarantine_media_ids_by_user(const std::string& user_id,
                                        const std::string& quarantined_by);

  // get_quarantined_media_changes (line 1329)
  std::vector<QuarantinedMediaUpdate> get_quarantined_media_changes(
      int64_t from_id, int64_t to_id, int64_t limit);

  // ---- Room blocking ----

  // block_room (line 1631)
  void block_room(const std::string& room_id, const std::string& user_id);

  // unblock_room (line 1657)
  void unblock_room(const std::string& room_id);

  // ---- Partial state rooms ----

  // get_partial_state_servers_at_join (line 1754)
  std::optional<std::set<std::string>> get_partial_state_servers_at_join(
      const std::string& room_id);

  // get_partial_state_room_resync_info (line 1785)
  std::unordered_map<std::string, PartialStateResyncInfo>
  get_partial_state_room_resync_info();

  // is_partial_state_room (line 1833)
  bool is_partial_state_room(const std::string& room_id);

  // is_partial_state_room_batched (line 1852)
  std::unordered_map<std::string, bool> is_partial_state_room_batched(
      const std::vector<std::string>& room_ids);

  // get_partial_rooms (line 1876)
  std::set<std::string> get_partial_rooms();

  // get_join_event_id_and_device_lists_stream_id_for_partial_state (line 1900)
  std::tuple<std::string, int64_t>
  get_join_event_id_and_device_lists_stream_id_for_partial_state(
      const std::string& room_id);

  // get_un_partial_stated_rooms_between (line 1931)
  std::set<std::string> get_un_partial_stated_rooms_between(
      int64_t last_id, int64_t current_id,
      const std::vector<std::string>& room_ids);

  // get_un_partial_stated_rooms_from_stream (line 1965)
  std::tuple<std::vector<std::tuple<int64_t, std::tuple<std::string>>>,
             int64_t, bool>
  get_un_partial_stated_rooms_from_stream(const std::string& instance_name,
                                           int64_t last_id, int64_t current_id,
                                           int64_t limit);

  // ---- Event reports read-only ----

  // get_event_report (line 2017)
  std::optional<nlohmann::json> get_event_report(int64_t report_id);

  // get_event_reports_paginate (line 2078)
  std::tuple<std::vector<nlohmann::json>, int64_t> get_event_reports_paginate(
      int64_t start, int64_t limit, Direction direction = Direction::BACKWARDS,
      const std::optional<std::string>& user_id = std::nullopt,
      const std::optional<std::string>& room_id = std::nullopt,
      const std::optional<std::string>& event_sender_user_id = std::nullopt);

  // ---- User reports ----

  // get_user_report (line 2220)
  std::optional<std::tuple<int64_t, int64_t, std::string, std::string,
                            std::string>>
  get_user_report(int64_t report_id);

  // get_user_reports_paginate (line 2240)
  std::tuple<std::vector<nlohmann::json>, int64_t> get_user_reports_paginate(
      int64_t start, int64_t limit, Direction direction = Direction::BACKWARDS,
      const std::optional<std::string>& user_id = std::nullopt,
      const std::optional<std::string>& target_user_id = std::nullopt);

  // ---- Room public status ----

  // set_room_is_public (line 2346)
  void set_room_is_public(const std::string& room_id, bool is_public);

  // set_room_is_public_appservice (line 2354)
  void set_room_is_public_appservice(const std::string& room_id,
                                      const std::string& appservice_id,
                                      const std::string& network_id,
                                      bool is_public);

  // has_auth_chain_index (line 2398)
  bool has_auth_chain_index(const std::string& room_id);

  // maybe_store_room_on_outlier_membership (line 2429)
  void maybe_store_room_on_outlier_membership(const std::string& room_id,
                                               const RoomVersion& room_version);

protected:
  // ---- Protected helpers ----

  // _construct_room_type_where_clause (line 466)
  std::tuple<std::optional<std::string>, std::vector<SQLParam>>
  construct_room_type_where_clause(
      const std::optional<std::vector<std::optional<std::string>>>&
          room_types);

  // _get_media_mxcs_in_room_txn (line 1170)
  std::tuple<std::vector<std::string>,
             std::vector<std::tuple<std::string, std::string>>>
  get_media_mxcs_in_room_txn(LoggingTransaction& txn,
                              const std::string& room_id);

  // _get_media_ids_by_user_txn (line 1276)
  std::vector<std::string> get_media_ids_by_user_txn(
      LoggingTransaction& txn, const std::string& user_id,
      bool filter_quarantined = true);

  // _get_quarantined_media_changes_txn (line 1360)
  std::vector<QuarantinedMediaUpdate> get_quarantined_media_changes_txn(
      LoggingTransaction& txn, int64_t from_id, int64_t to_id, int64_t limit);

  // _insert_quarantine_changes_txn (line 1383)
  void insert_quarantine_changes_txn(
      LoggingTransaction& txn,
      const std::vector<std::tuple<std::optional<std::string>, std::string>>&
          origins_and_media_ids,
      bool quarantined);

  // _quarantine_local_media_txn (line 1427)
  int64_t quarantine_local_media_txn(
      LoggingTransaction& txn, std::set<std::string>& hashes,
      std::set<std::string>& media_ids,
      const std::optional<std::string>& quarantined_by);

  // _quarantine_remote_media_txn (line 1505)
  int64_t quarantine_remote_media_txn(
      LoggingTransaction& txn, std::set<std::string>& hashes,
      std::set<std::tuple<std::string, std::string>>& media,
      const std::optional<std::string>& quarantined_by);

  // _quarantine_media_txn (line 1568)
  int64_t quarantine_media_txn(
      LoggingTransaction& txn, const std::vector<std::string>& local_mxcs,
      const std::vector<std::tuple<std::string, std::string>>& remote_mxcs,
      const std::optional<std::string>& quarantined_by);

  // _flag_existing_quarantined_media (line 208)
  int64_t flag_existing_quarantined_media(nlohmann::json& progress,
                                           int64_t batch_size);

  // ---- Member access ----
  DatabasePool& db_pool_;
  std::string server_name_;
  std::string instance_name_;
  std::string hostname_;  // equivalent to hs.hostname

  // Helper: db_to_json equivalent
  static nlohmann::json db_to_json(const std::string& blob);

  // Helper: make_in_list_sql_clause - generates "col IN (?,?,...)" clauses
  static std::tuple<std::string, std::vector<SQLParam>> make_in_list_sql_clause(
      BaseDatabaseEngine& engine, const std::string& column,
      const std::set<std::string>& values);
  template <typename T>
  static std::tuple<std::string, std::vector<SQLParam>>
  make_in_list_sql_clause_generic(BaseDatabaseEngine& engine,
                                   const std::string& column,
                                   const std::set<T>& values);

  // Helper: make_tuple_in_list_sql_clause
  static std::tuple<std::string, std::vector<SQLParam>>
  make_tuple_in_list_sql_clause(
      BaseDatabaseEngine& engine,
      const std::tuple<std::string, std::string>& columns,
      const std::set<std::tuple<std::string, std::string>>& values);

  // Retention config access
  bool retention_enabled_ = false;
  std::optional<int64_t> retention_default_min_lifetime_;
  std::optional<int64_t> retention_default_max_lifetime_;
};

// ============================================================================
// RoomBackgroundUpdateStore (room.py lines 2476-2899)
// Background update handlers for room store
// ============================================================================
class RoomBackgroundUpdateStore : public RoomWorkerStore {
public:
  RoomBackgroundUpdateStore(DatabasePool& database,
                             const std::string& server_name,
                             const std::string& instance_name);

  // Register background update handlers (called in constructor)
  void register_background_updates();

  // ---- Background update handlers ----

  // _background_insert_retention (line 2520)
  int64_t background_insert_retention(nlohmann::json& progress,
                                       int64_t batch_size);

  // _background_add_rooms_room_version_column (line 2590)
  int64_t background_add_rooms_room_version_column(nlohmann::json& progress,
                                                    int64_t batch_size);

  // _remove_tombstoned_rooms_from_directory (line 2661)
  int64_t remove_tombstoned_rooms_from_directory(nlohmann::json& progress,
                                                   int64_t batch_size);

  // _background_populate_room_depth_min_depth2 (line 2709)
  int64_t background_populate_room_depth_min_depth2(nlohmann::json& progress,
                                                     int64_t batch_size);

  // _background_replace_room_depth_min_depth (line 2756)
  int64_t background_replace_room_depth_min_depth(nlohmann::json& progress,
                                                    int64_t batch_size);

  // _background_populate_rooms_creator_column (line 2774)
  int64_t background_populate_rooms_creator_column(nlohmann::json& progress,
                                                    int64_t batch_size);

  // _background_add_room_type_column (line 2838)
  int64_t background_add_room_type_column(nlohmann::json& progress,
                                           int64_t batch_size);
};

// ============================================================================
// RoomStore (room.py lines 2902-3240)
// Full room store with write operations
// ============================================================================
class RoomStore : public RoomBackgroundUpdateStore {
public:
  RoomStore(DatabasePool& database, const std::string& server_name,
            const std::string& instance_name);

  // ---- Room creation/write ----

  // upsert_room_on_join (line 2917)
  void upsert_room_on_join(const std::string& room_id,
                            const RoomVersion& room_version,
                            const nlohmann::json& state_events);

  // store_partial_state_room (line 2964)
  void store_partial_state_room(const std::string& room_id,
                                 const std::set<std::string>& servers,
                                 int64_t device_lists_stream_id,
                                 const std::string& joined_via);

  // _store_partial_state_room_txn (line 2998)
  void store_partial_state_room_txn(LoggingTransaction& txn,
                                     const std::string& room_id,
                                     const std::set<std::string>& servers,
                                     int64_t device_lists_stream_id,
                                     const std::string& joined_via);

  // write_partial_state_rooms_join_event_id (line 3029)
  void write_partial_state_rooms_join_event_id(const std::string& room_id,
                                                 const std::string& join_event_id);

  // _write_partial_state_rooms_join_event_id (line 3046)
  void write_partial_state_rooms_join_event_id_txn(
      LoggingTransaction& txn, const std::string& room_id,
      const std::string& join_event_id);

  // add_event_report (line 3059)
  int64_t add_event_report(const std::string& room_id,
                            const std::string& event_id,
                            const std::string& user_id,
                            const std::optional<std::string>& reason,
                            const nlohmann::json& content,
                            int64_t received_ts);

  // add_room_report (line 3096)
  int64_t add_room_report(const std::string& room_id,
                           const std::string& user_id,
                           const std::string& reason, int64_t received_ts);

  // add_user_report (line 3127)
  int64_t add_user_report(const std::string& target_user_id,
                           const std::string& user_id,
                           const std::string& reason, int64_t received_ts);

  // delete_event_report (line 2199)
  bool delete_event_report(int64_t report_id);

  // delete_user_report (line 2325)
  bool delete_user_report(int64_t report_id);

  // clear_partial_state_room (line 3158)
  std::optional<int64_t> clear_partial_state_room(const std::string& room_id);

  // _clear_partial_state_room_txn (line 3190)
  void clear_partial_state_room_txn(LoggingTransaction& txn,
                                     const std::string& room_id,
                                     int64_t un_partial_state_room_stream_id);

private:
  // ID generators (line 2911-2913)
  int64_t next_event_report_id_ = 1;
  int64_t next_room_report_id_ = 1;
  int64_t next_user_report_id_ = 1;
};

// ============================================================================
// _BackgroundUpdates (room.py lines 2458-2465)
// ============================================================================
namespace BackgroundUpdates {
  constexpr const char* REMOVE_TOMESTONED_ROOMS_BG_UPDATE =
      "remove_tombstoned_rooms_from_directory";
  constexpr const char* ADD_ROOMS_ROOM_VERSION_COLUMN =
      "add_rooms_room_version_column";
  constexpr const char* POPULATE_ROOM_DEPTH_MIN_DEPTH2 =
      "populate_room_depth_min_depth2";
  constexpr const char* REPLACE_ROOM_DEPTH_MIN_DEPTH =
      "replace_room_depth_min_depth";
  constexpr const char* POPULATE_ROOMS_CREATOR_COLUMN =
      "populate_rooms_creator_column";
  constexpr const char* ADD_ROOM_TYPE_COLUMN = "add_room_type_column";
  constexpr const char* FLAG_EXISTING_QUARANTINED_MEDIA =
      "flag_existing_quarantined_media";
}  // namespace BackgroundUpdates

// ============================================================================
// _REPLACE_ROOM_DEPTH_SQL_COMMANDS (room.py lines 2468-2473)
// ============================================================================
inline const std::vector<std::string> REPLACE_ROOM_DEPTH_SQL_COMMANDS = {
    "DROP TRIGGER populate_min_depth2_trigger ON room_depth",
    "DROP FUNCTION populate_min_depth2()",
    "ALTER TABLE room_depth DROP COLUMN min_depth",
    "ALTER TABLE room_depth RENAME COLUMN min_depth2 TO min_depth",
};

}  // namespace progressive::storage
