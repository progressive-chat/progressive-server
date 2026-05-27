#pragma once

// ============================================================================
// events.hpp - C++ translation of synapse/storage/databases/main/events.py
// ============================================================================
// Original Python Copyright: 2019-2021 The Matrix.org Foundation C.I.C.
//                           2014-2016 OpenMarket Ltd
//                           (C) 2023 New Vector, Ltd
// Licensed under AGPL v3
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
#include <unordered_set>
#include <vector>

#include "progressive/storage/database.hpp"
#include "progressive/storage/engine.hpp"
#include "progressive/storage/types.hpp"

// Forward declare nlohmann::json
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace progressive::storage {

// Forward declarations
class DatabasePool;
class LoggingTransaction;
class LoggingDatabaseConnection;

// ============================================================================
// DeltaState - Deltas to use to update the current_state_events table.
// Equivalent to Python attr.s class DeltaState at line 136
// ============================================================================
struct DeltaState {
  // List of (type, state_key) pairs to delete from current state
  std::vector<std::pair<std::string, std::string>> to_delete;

  // Map of (type, state_key) -> event_id to upsert into current state
  std::map<std::pair<std::string, std::string>, std::string> to_insert;

  // The server is no longer in the room
  bool no_longer_in_room{false};

  // Whether this state delta is actually empty
  bool is_noop() const {
    return to_delete.empty() && to_insert.empty() && !no_longer_in_room;
  }
};

// ============================================================================
// SlidingSyncStateInsertValues
// Equivalent to Python TypedDict SlidingSyncStateInsertValues at line 157
// ============================================================================
struct SlidingSyncStateInsertValues {
  std::optional<std::string> room_type;
  std::optional<bool> is_encrypted;
  std::optional<std::string> room_name;
  std::optional<std::string> tombstone_successor_room_id;

  bool empty() const {
    return !room_type && !is_encrypted && !room_name &&
           !tombstone_successor_room_id;
  }

  std::vector<std::string> keys() const {
    std::vector<std::string> result;
    if (room_type) result.push_back("room_type");
    if (is_encrypted) result.push_back("is_encrypted");
    if (room_name) result.push_back("room_name");
    if (tombstone_successor_room_id)
      result.push_back("tombstone_successor_room_id");
    return result;
  }

  std::vector<std::string> values() const {
    std::vector<std::string> result;
    if (room_type) result.push_back(*room_type);
    if (is_encrypted) result.push_back(*is_encrypted ? "1" : "0");
    if (room_name) result.push_back(*room_name);
    if (tombstone_successor_room_id)
      result.push_back(*tombstone_successor_room_id);
    return result;
  }
};

// ============================================================================
// SlidingSyncMembershipSnapshotSharedInsertValues
// Equivalent to Python TypedDict at line 169
// ============================================================================
struct SlidingSyncMembershipSnapshotSharedInsertValues
    : public SlidingSyncStateInsertValues {
  std::optional<bool> has_known_state;

  std::vector<std::string> keys() const {
    auto result = SlidingSyncStateInsertValues::keys();
    if (has_known_state) result.push_back("has_known_state");
    return result;
  }

  std::vector<std::string> values() const {
    auto result = SlidingSyncStateInsertValues::values();
    if (has_known_state) result.push_back(*has_known_state ? "1" : "0");
    return result;
  }
};

// ============================================================================
// SlidingSyncMembershipInfo - Values unique to each membership
// Equivalent to Python attr.s class at line 180
// ============================================================================
struct SlidingSyncMembershipInfo {
  std::string user_id;
  std::string sender;
  std::string membership_event_id;
  std::string membership;
};

// ============================================================================
// SlidingSyncMembershipInfoWithEventPos
// Equivalent to Python attr.s class at line 192
// ============================================================================
struct SlidingSyncMembershipInfoWithEventPos : public SlidingSyncMembershipInfo {
  int64_t membership_event_stream_ordering{0};
  std::string membership_event_instance_name;
};

// ============================================================================
// SlidingSyncTableChanges
// Equivalent to Python attr.s class at line 203
// ============================================================================
struct SlidingSyncTableChanges {
  std::string room_id;

  // If the row doesn't exist in the sliding_sync_joined_rooms table
  std::optional<int64_t> joined_room_bump_stamp_to_fully_insert;

  // Values to upsert into sliding_sync_joined_rooms
  SlidingSyncStateInsertValues joined_room_updates;

  // Shared values to upsert into sliding_sync_membership_snapshots
  SlidingSyncMembershipSnapshotSharedInsertValues
      membership_snapshot_shared_insert_values;

  // List of membership to insert into sliding_sync_membership_snapshots
  std::vector<SlidingSyncMembershipInfo> to_insert_membership_snapshots;

  // List of user_id to delete from sliding_sync_membership_snapshots
  std::vector<std::string> to_delete_membership_snapshots;
};

// ============================================================================
// NewEventChainLinks - Information about new auth chain links
// Equivalent to Python attr.s class at line 230
// ============================================================================
struct NewEventChainLinks {
  int64_t chain_id{0};
  int64_t sequence_number{0};
  std::vector<std::pair<int64_t, int64_t>> links;
};

// ============================================================================
// _LinkMap - Helper type for tracking links between chains
// Equivalent to Python attr.s class at line 3738
// ============================================================================
class LinkMap {
public:
  // Stores the set of links as nested maps: source chain ID -> target chain ID
  // -> source sequence number -> target sequence number.
  using InnerMap = std::map<int64_t, int64_t>;
  using MiddleMap = std::map<int64_t, InnerMap>;
  using OuterMap = std::map<int64_t, MiddleMap>;
  using LinkTuple = std::tuple<int64_t, int64_t, int64_t, int64_t>;

  // Add a new link between two chains, ensuring no redundant links
  bool add_link(std::pair<int64_t, int64_t> src_tuple,
                std::pair<int64_t, int64_t> target_tuple,
                bool is_new = true);

  // Gets any newly added links
  std::vector<LinkTuple> get_additions() const;

  // Checks if there is a path between source and target
  bool exists_path_from(std::pair<int64_t, int64_t> src_tuple,
                        std::pair<int64_t, int64_t> target_tuple) const;

private:
  OuterMap maps_;
  std::set<LinkTuple> additions_;
};

// ============================================================================
// EventPersistencePair - (event, context) pair
// Simplified for C++: stores event data and context data
// ============================================================================
struct EventContext {
  bool rejected{false};
  bool partial_state{false};
  std::optional<int64_t> state_group;
  std::optional<int64_t> state_group_before_event;
  std::string app_service;  // empty if not app service
};

struct EventData {
  std::string event_id;
  std::string room_id;
  std::string type;
  std::string sender;
  std::optional<std::string> state_key;
  std::string membership;  // for member events
  int64_t depth{0};
  int64_t origin_server_ts{0};
  int64_t stream_ordering{0};
  std::string instance_name;
  int format_version{0};
  bool is_outlier{false};
  bool is_redacted{false};
  bool is_out_of_band_membership{false};
  bool is_state_event{false};
  bool is_notifiable{false};
  bool contains_url{false};
  std::optional<std::string> redacts;
  std::optional<std::string> txn_id;
  std::optional<std::string> device_id;
  json content;
  json internal_metadata_dict;
  std::string internal_metadata_json;
  json unsigned_data;
  std::vector<std::string> prev_event_ids;
  std::vector<std::string> auth_event_ids;
  std::vector<std::string> prev_state_events;
  std::string room_version_id;
  int64_t sticky_duration_ms{0};

  bool is_state() const { return is_state_event; }
  std::optional<std::string> get_state_key() const { return state_key; }
  std::vector<std::string> prev_event_ids_list() const { return prev_event_ids; }
  std::vector<std::string> auth_event_ids_list() const {
    return auth_event_ids;
  }
};

struct EventPersistencePair {
  EventData event;
  EventContext context;
};

// ============================================================================
// EventCacheEntry - Simplified for C++
// Equivalent to EventCacheEntry from events_worker.py
// ============================================================================
struct EventCacheEntry {
  EventData event;
  std::optional<EventData> redacted_event;
};

// ============================================================================
// SearchEntry - Simplified for C++
// Equivalent to SearchEntry from search.py
// ============================================================================
struct SearchEntry {
  std::string key;
  std::string value;
  std::string event_id;
  std::string room_id;
  int64_t stream_ordering{0};
  int64_t origin_server_ts{0};
};

// ============================================================================
// Event Types Constants (from synapse.api.constants)
// ============================================================================
namespace EventTypes {
inline constexpr const char* Message = "m.room.message";
inline constexpr const char* Encrypted = "m.room.encrypted";
inline constexpr const char* Member = "m.room.member";
inline constexpr const char* ThirdPartyInvite = "m.room.third_party_invite";
inline constexpr const char* Redaction = "m.room.redaction";
inline constexpr const char* Create = "m.room.create";
inline constexpr const char* Tombstone = "m.room.tombstone";
inline constexpr const char* Name = "m.room.name";
inline constexpr const char* Topic = "m.room.topic";
inline constexpr const char* RoomEncryption = "m.room.encryption";
inline constexpr const char* PowerLevels = "m.room.power_levels";
inline constexpr const char* Retention = "m.room.retention";
}  // namespace EventTypes

// ============================================================================
// Membership Constants
// ============================================================================
namespace Membership {
inline constexpr const char* JOIN = "join";
inline constexpr const char* LEAVE = "leave";
inline constexpr const char* INVITE = "invite";
inline constexpr const char* KNOCK = "knock";
inline constexpr const char* BAN = "ban";
}  // namespace Membership

// ============================================================================
// RelationTypes Constants
// ============================================================================
namespace RelationTypes {
inline constexpr const char* THREAD = "m.thread";
inline constexpr const char* REFERENCE = "m.reference";
inline constexpr const char* REPLACE = "m.replace";
}  // namespace RelationTypes

// ============================================================================
// EventContentFields Constants
// ============================================================================
namespace EventContentFields {
inline constexpr const char* ROOM_TYPE = "type";
inline constexpr const char* ROOM_NAME = "name";
inline constexpr const char* ENCRYPTION_ALGORITHM = "algorithm";
inline constexpr const char* TOMBSTONE_SUCCESSOR_ROOM = "replacement_room";
inline constexpr const char* LABELS = "org.matrix.labels";
inline constexpr const char* SELF_DESTRUCT_AFTER = "org.matrix.self_destruct_after";
}  // namespace EventContentFields

// ============================================================================
// RoomVersions Constants
// ============================================================================
namespace RoomVersions {
inline constexpr const char* V1 = "1";
inline constexpr const char* V2 = "2";
inline constexpr const char* V3 = "3";
inline constexpr const char* V4 = "4";
inline constexpr const char* V5 = "5";
inline constexpr const char* V6 = "6";
inline constexpr const char* V7 = "7";
inline constexpr const char* V8 = "8";
inline constexpr const char* V9 = "9";
inline constexpr const char* V10 = "10";
inline constexpr const char* V11 = "11";
}  // namespace RoomVersions

// ============================================================================
// SLIDING_SYNC_DEFAULT_BUMP_EVENT_TYPES
// Equivalent to Python constant at line 80 import
// ============================================================================
inline const std::set<std::string> SLIDING_SYNC_DEFAULT_BUMP_EVENT_TYPES = {
    EventTypes::Message,
    EventTypes::Encrypted,
    "m.room.sticker",
    "m.room.poll",
    "m.room.call",
    "org.matrix.rageshake_request",
};

// ============================================================================
// TRACKED_EVENT_TYPES - Event types tracked in the events_counter metric
// Equivalent to Python set at line 112
// ============================================================================
inline const std::set<std::string> TRACKED_EVENT_TYPES = {
    EventTypes::Message,       EventTypes::Encrypted,
    EventTypes::Member,        EventTypes::ThirdPartyInvite,
    EventTypes::Redaction,     EventTypes::Create,
    EventTypes::Tombstone,
};

// ============================================================================
// SLIDING_SYNC_RELEVANT_STATE_SET - State event type/key pairs for sliding sync
// Equivalent to Python tuple constant at line 124
// ============================================================================
inline const std::set<std::pair<std::string, std::string>>
    SLIDING_SYNC_RELEVANT_STATE_SET = {
        {EventTypes::Create, ""},
        {EventTypes::RoomEncryption, ""},
        {EventTypes::Name, ""},
        {EventTypes::Tombstone, ""},
};

// ============================================================================
// PersistEventsStore - Contains all functions for writing events to the DB.
// Equivalent to Python class PersistEventsStore at line 247
// ============================================================================
class PersistEventsStore {
public:
  PersistEventsStore(const std::string& server_name,
                     const std::string& instance_name,
                     DatabasePool& db_pool,
                     bool is_mine_id_func(const std::string&),
                     int64_t(*time_msec)(),
                     bool msc4354_enabled = false,
                     bool ephemeral_messages_enabled = false,
                     bool msc4293_enabled = false);

  virtual ~PersistEventsStore() = default;

  // ==========================================================================
  // Public async methods (translated as synchronous for C++ transactions)
  // ==========================================================================

  // _persist_events_and_state_updates (line 290)
  void persist_events_and_state_updates(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::vector<EventPersistencePair>& events_and_contexts,
      const DeltaState* state_delta_for_room,
      const std::set<std::string>* new_forward_extremities,
      const std::map<std::string, NewEventChainLinks>& new_event_links,
      bool use_negative_stream_ordering = false,
      bool inhibit_local_membership_updates = false,
      const std::set<std::string>* new_state_dag_forward_extremities = nullptr);

  // can_sender_redact (line 501) - C++ equivalent is txn-based
  bool can_sender_redact_txn(LoggingTransaction& txn, const EventData& event);

  // calculate_sliding_sync_table_changes (line 554)
  SlidingSyncTableChanges calculate_sliding_sync_table_changes_txn(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::vector<EventPersistencePair>& events_and_contexts,
      const DeltaState& delta_state);

  // calculate_chain_cover_index_for_events (line 849)
  std::map<std::string, NewEventChainLinks>
  calculate_chain_cover_index_for_events_txn(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::vector<EventData>& events,
      int64_t (*event_chain_id_gen_get_next_mult)(LoggingTransaction&, int64_t));

  // get_events_which_are_prevs (line 930)
  std::vector<std::string> get_events_which_are_prevs_txn(
      LoggingTransaction& txn, const std::vector<std::string>& event_ids);

  // get_prevs_before_rejected (line 971)
  std::set<std::string> get_prevs_before_rejected_txn(
      LoggingTransaction& txn, const std::vector<std::string>& event_ids,
      bool include_soft_failed = true);

  // persist_events_txn (line 1039) - main event persistence transaction
  void persist_events_txn(
      LoggingTransaction& txn, const std::string& room_id,
      const std::vector<EventPersistencePair>& events_and_contexts,
      bool inhibit_local_membership_updates,
      const DeltaState* state_delta_for_room,
      const std::set<std::string>* new_forward_extremities,
      const std::map<std::string, NewEventChainLinks>& new_event_links,
      const SlidingSyncTableChanges* sliding_sync_table_changes,
      const std::set<std::string>* new_state_dag_forward_extremities = nullptr);

  // update_current_state (line 1744)
  void update_current_state_txn(
      LoggingTransaction& txn, const std::string& room_id,
      const DeltaState& delta_state, int64_t stream_id,
      const SlidingSyncTableChanges& sliding_sync_table_changes);

  // ==========================================================================
  // Static/class methods
  // ==========================================================================

  // _add_chain_cover_index (line 1246)
  static void add_chain_cover_index_txn(
      LoggingTransaction& txn, DatabasePool& db_pool,
      int64_t (*event_chain_id_gen_get_next_mult)(LoggingTransaction&, int64_t),
      const std::map<std::string, std::string>& event_to_room_id,
      const std::map<std::string, std::pair<std::string, std::string>>&
          event_to_types,
      const std::map<std::string, std::vector<std::string>>&
          event_to_auth_chain);

  // _calculate_chain_cover_index (line 1275)
  static std::map<std::string, NewEventChainLinks>
  calculate_chain_cover_index_txn(
      LoggingTransaction& txn, DatabasePool& db_pool,
      int64_t (*event_chain_id_gen_get_next_mult)(LoggingTransaction&, int64_t),
      const std::map<std::string, std::string>& event_to_room_id,
      const std::map<std::string, std::pair<std::string, std::string>>&
          event_to_types,
      const std::map<std::string, std::vector<std::string>>&
          event_to_auth_chain);

  // _persist_chain_cover_index (line 1525)
  static void persist_chain_cover_index_txn(
      LoggingTransaction& txn, DatabasePool& db_pool,
      const std::map<std::string, NewEventChainLinks>& new_event_links);

  // _allocate_chain_ids (line 1571)
  static std::map<std::string, std::pair<int64_t, int64_t>>
  allocate_chain_ids_txn(
      LoggingTransaction& txn, DatabasePool& db_pool,
      int64_t (*event_chain_id_gen_get_next_mult)(LoggingTransaction&, int64_t),
      const std::map<std::string, std::string>& event_to_room_id,
      const std::map<std::string, std::pair<std::string, std::string>>&
          event_to_types,
      const std::map<std::string, std::vector<std::string>>&
          event_to_auth_chain,
      const std::set<std::string>& events_to_calc_chain_id_for,
      std::map<std::string, std::pair<int64_t, int64_t>>& chain_map);

  // _filter_events_and_contexts_for_duplicates (line 2517)
  static std::vector<EventPersistencePair>
  filter_events_and_contexts_for_duplicates(
      const std::vector<EventPersistencePair>& events_and_contexts);

  // _get_relevant_sliding_sync_current_state_event_ids_txn (line 2120)
  static std::map<std::pair<std::string, std::string>, std::string>
  get_relevant_sliding_sync_current_state_event_ids_txn(
      LoggingTransaction& txn, const std::string& room_id);

  // _get_sliding_sync_insert_values_from_state_map (line 2164)
  static SlidingSyncStateInsertValues
  get_sliding_sync_insert_values_from_state_map(
      const std::map<std::pair<std::string, std::string>, EventData>&
          state_map);

  // _get_sliding_sync_insert_values_from_stripped_state (line 2234)
  static SlidingSyncMembershipSnapshotSharedInsertValues
  get_sliding_sync_insert_values_from_stripped_state(
      const json* unsigned_stripped_state_events);

private:
  // ==========================================================================
  // Private methods
  // ==========================================================================

  // persist_events_and_state_updates helpers
  bool can_sender_redact_txn_impl(LoggingTransaction& txn,
                                  const EventData& event);

  // _persist_events_txn helper sub-methods
  void persist_event_auth_chain_txn(
      LoggingTransaction& txn, const std::vector<EventData>& events,
      const std::map<std::string, NewEventChainLinks>& new_event_links);

  void persist_transaction_ids_txn(
      LoggingTransaction& txn,
      const std::vector<EventPersistencePair>& events_and_contexts);

  void update_room_depths_txn(
      LoggingTransaction& txn, const std::string& room_id,
      const std::vector<EventPersistencePair>& events_and_contexts);

  std::vector<EventPersistencePair> update_outliers_txn(
      LoggingTransaction& txn,
      const std::vector<EventPersistencePair>& events_and_contexts,
      bool msc4354_enabled);

  void store_event_txn(
      LoggingTransaction& txn,
      const std::vector<EventPersistencePair>& events_and_contexts);

  std::vector<EventPersistencePair> store_rejected_events_txn(
      LoggingTransaction& txn,
      const std::vector<EventPersistencePair>& events_and_contexts);

  void update_metadata_tables_txn(
      LoggingTransaction& txn,
      const std::vector<EventPersistencePair>& events_and_contexts,
      const std::vector<EventPersistencePair>& all_events_and_contexts,
      bool inhibit_local_membership_updates = false);

  void add_to_cache_txn(
      LoggingTransaction& txn,
      const std::vector<EventPersistencePair>& events_and_contexts);

  void store_state_dag_edges_txn(LoggingTransaction& txn,
                                 const EventData& event);

  void store_redaction_txn(LoggingTransaction& txn, const EventData& event);

  void insert_labels_for_event_txn(LoggingTransaction& txn,
                                   const std::string& event_id,
                                   const std::vector<std::string>& labels,
                                   const std::string& room_id,
                                   int64_t topological_ordering);

  void insert_event_expiry_txn(LoggingTransaction& txn,
                               const std::string& event_id, int64_t expiry_ts);

  void store_room_members_txn(
      LoggingTransaction& txn, const std::vector<EventData>& events,
      bool inhibit_local_membership_updates = false);

  void handle_event_relations_txn(LoggingTransaction& txn,
                                  const EventData& event);

  void handle_redact_relations_txn(LoggingTransaction& txn,
                                   const std::string& room_id,
                                   const std::string& redacted_event_id);

  void store_room_topic_txn(LoggingTransaction& txn, const EventData& event);

  void store_room_name_txn(LoggingTransaction& txn, const EventData& event);

  void store_room_message_txn(LoggingTransaction& txn, const EventData& event);

  void store_retention_policy_for_room_txn(LoggingTransaction& txn,
                                           const EventData& event);

  void store_event_search_txn(LoggingTransaction& txn, const EventData& event,
                              const std::string& key,
                              const std::string& value);

  void set_push_actions_for_event_and_users_txn(
      LoggingTransaction& txn,
      const std::vector<EventPersistencePair>& events_and_contexts,
      const std::vector<EventPersistencePair>& all_events_and_contexts);

  void remove_push_actions_for_event_id_txn(LoggingTransaction& txn,
                                            const std::string& room_id,
                                            const std::string& event_id);

  void store_rejections_txn(LoggingTransaction& txn,
                            const std::string& event_id,
                            const std::string& reason);

  void store_event_state_mappings_txn(
      LoggingTransaction& txn,
      const std::vector<EventPersistencePair>& events_and_contexts);

  void update_min_depth_for_room_txn(LoggingTransaction& txn,
                                     const std::string& room_id,
                                     int64_t depth);

  void handle_mult_prev_events_txn(LoggingTransaction& txn,
                                   const std::vector<EventData>& events);

  void update_backward_extremeties_txn(LoggingTransaction& txn,
                                       const std::vector<EventData>& events);

  void update_forward_extremities_txn(
      LoggingTransaction& txn, const std::string& room_id,
      const std::set<std::string>& new_forward_extremities,
      int64_t max_stream_order);

  void set_state_dag_extremities_txn(
      LoggingTransaction& txn, const std::string& room_id,
      const std::set<std::string>& new_extrems);

  void upsert_room_version_txn(LoggingTransaction& txn,
                               const std::string& room_id);

  void update_sliding_sync_tables_with_new_persisted_events_txn(
      LoggingTransaction& txn, const std::string& room_id,
      const std::vector<EventPersistencePair>& events_and_contexts);

  void update_current_state_txn_impl(
      LoggingTransaction& txn, const std::string& room_id,
      const DeltaState& delta_state, int64_t stream_id,
      const SlidingSyncTableChanges& sliding_sync_table_changes);

  // ==========================================================================
  // SQL helper: make_in_list_sql_clause
  // Equivalent to Python: synapse.storage._base.make_in_list_sql_clause
  // ==========================================================================
  static std::pair<std::string, std::vector<SQLParam>>
  make_in_list_sql_clause(const std::string& column,
                          const std::vector<std::string>& items);

  // ==========================================================================
  // SQL helper: make_tuple_in_list_sql_clause
  // Equivalent to Python: synapse.storage.database.make_tuple_in_list_sql_clause
  // ==========================================================================
  static std::pair<std::string, std::vector<SQLParam>>
  make_tuple_in_list_sql_clause(
      const std::vector<std::string>& columns,
      const std::set<std::pair<std::string, std::string>>& tuples);

  // ==========================================================================
  // Utility: batch_iter - split a collection into chunks
  // ==========================================================================
  template <typename T>
  static std::vector<std::vector<T>> batch_iter(const std::vector<T>& items,
                                                 size_t batch_size) {
    std::vector<std::vector<T>> result;
    for (size_t i = 0; i < items.size(); i += batch_size) {
      auto end = std::min(i + batch_size, items.size());
      result.emplace_back(items.begin() + i, items.begin() + end);
    }
    return result;
  }

  // ==========================================================================
  // Utility: db_to_json - parse JSON from a DB column
  // ==========================================================================
  static json db_to_json(const std::string& db_value);

  // ==========================================================================
  // Utility: json_encoder - serialize to JSON string
  // ==========================================================================
  static std::string json_encode(const json& obj);

  // ==========================================================================
  // Utility: non_null_str_or_none
  // ==========================================================================
  static std::optional<std::string> non_null_str_or_none(
      const std::optional<std::string>& val);

  // ==========================================================================
  // Utility: sorted_topologically
  // ==========================================================================
  static std::vector<std::string> sorted_topologically(
      const std::set<std::string>& nodes,
      const std::map<std::string, std::vector<std::string>>& edges);

  // ==========================================================================
  // Utility: get_plain_text_topic_from_event_content
  // ==========================================================================
  static std::string get_plain_text_topic_from_event_content(
      const json& content);

  // ==========================================================================
  // Utility: relation_from_event
  // ==========================================================================
  struct RelationInfo {
    std::string parent_id;
    std::string rel_type;
    std::optional<std::string> aggregation_key;
  };
  static std::optional<RelationInfo> relation_from_event(
      const EventData& event);

  // ==========================================================================
  // Utility: is_creator - check if sender is the room creator
  // ==========================================================================
  static bool is_creator(const EventData& create_event,
                         const std::string& sender);

  // ==========================================================================
  // Utility: event_exists_in_state_dag
  // ==========================================================================
  static bool event_exists_in_state_dag(const EventData& event);

  // ==========================================================================
  // Utility: supports_msc4242_state_dag
  // ==========================================================================
  static bool supports_msc4242_state_dag(const EventData& event);

  // ==========================================================================
  // Member variables
  // ==========================================================================
  std::string server_name_;
  std::string instance_name_;
  DatabasePool& db_pool_;
  std::function<bool(const std::string&)> is_mine_id_;
  std::function<int64_t()> time_msec_;
  bool msc4354_enabled_;
  bool ephemeral_messages_enabled_;
  bool msc4293_enabled_;

  // Database engine reference
  BaseDatabaseEngine& engine_;
};

// ============================================================================
// EventsStore - High-level store that wraps PersistEventsStore
// Equivalent to the EventsStore mixin used in Synapse's DataStore
// ============================================================================
class EventsStore : public PersistEventsStore {
public:
  EventsStore(const std::string& server_name,
              const std::string& instance_name, DatabasePool& db_pool,
              bool is_mine_id_func(const std::string&),
              int64_t (*time_msec)(),
              bool msc4354_enabled = false,
              bool ephemeral_messages_enabled = false,
              bool msc4293_enabled = false);

  ~EventsStore() override = default;

  // ==========================================================================
  // Additional convenience methods
  // ==========================================================================

  // Get min depth for a room
  std::optional<int64_t> get_min_depth_txn(LoggingTransaction& txn,
                                            const std::string& room_id);

  // Get cached event (would be implemented with actual cache logic)
  std::optional<EventCacheEntry> get_event_cache_entry(
      const std::string& event_id);

  // Invalidate event caches
  void invalidate_get_event_cache_after_txn(LoggingTransaction& txn,
                                             const std::string& event_id);

  // Get events by IDs
  std::map<std::string, EventData> get_events_txn(
      LoggingTransaction& txn,
      const std::set<std::string>& event_ids);

  // Get partial filtered current state IDs
  std::map<std::pair<std::string, std::string>, std::string>
  get_partial_filtered_current_state_ids_txn(
      LoggingTransaction& txn, const std::string& room_id,
      const std::set<std::pair<std::string, std::string>>& state_filter);

  // Get last event pos in room
  struct EventPosResult {
    std::string event_id;
    int64_t stream{0};
  };
  std::optional<EventPosResult> get_last_event_pos_in_room_txn(
      LoggingTransaction& txn, const std::string& room_id,
      const std::set<std::string>& event_types);

  // Get users in room
  std::vector<std::string> get_users_in_room_txn(LoggingTransaction& txn,
                                                  const std::string& room_id);

  // Get current token from stream ID gen
  int64_t get_current_stream_token();

  // Invalidate caches for event
  void invalidate_caches_for_event(int64_t stream_ordering,
                                   const std::string& event_id,
                                   const std::string& room_id,
                                   const std::string& event_type,
                                   const std::optional<std::string>& state_key,
                                   const std::optional<std::string>& redacts,
                                   const std::optional<std::string>& relates_to,
                                   bool backfilled);

  // Invalidate state caches and stream
  void invalidate_state_caches_and_stream(
      LoggingTransaction& txn, const std::string& room_id,
      const std::set<std::string>& members_to_cache_bust);

  // Handle potentially left users
  void handle_potentially_left_users_txn(
      LoggingTransaction& txn,
      const std::set<std::string>& potentially_left_users);

  // Insert sticky events
  void insert_sticky_events_txn(LoggingTransaction& txn,
                                const std::vector<EventData>& events);

  // Store search entries
  void store_search_entries_txn(LoggingTransaction& txn,
                                const std::vector<SearchEntry>& entries);

private:
  // Cache prefill helpers (simplified)
  std::optional<int64_t> get_min_depth_interaction(LoggingTransaction& txn,
                                                    const std::string& room_id);

  // Event cache (simplified in-memory for now)
  std::unordered_map<std::string, EventCacheEntry> event_cache_;
};

}  // namespace progressive::storage
