#pragma once
// ============================================================================
// stream.hpp - StreamWorkerStore: stream ordering, pagination, current_state_deltas
// Translated from synapse/storage/databases/main/stream.py
// ============================================================================

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "events_worker.hpp"

namespace progressive::storage {

// ============================================================================
// Constants
// ============================================================================
static constexpr int MAX_STREAM_SIZE = 1000;
static constexpr const char* STREAM_TOKEN = "stream";
static constexpr const char* TOPOLOGICAL_TOKEN = "topological";

// ============================================================================
// RoomsForUserStateReset (simplified equivalent)
// ============================================================================
struct RoomsForUserStateReset {
  std::string room_id;
  std::optional<std::string> sender;
  std::string membership;
  std::optional<std::string> event_id;
  PersistedEventPosition event_pos;
  std::optional<std::string> room_version_id;
};

// ============================================================================
// Free functions (translated from stream.py module-level functions)
// ============================================================================

// generate_pagination_where_clause
std::string generate_pagination_where_clause(
    Direction direction,
    const std::tuple<std::string, std::string>& column_names,
    const std::optional<std::tuple<std::optional<int64_t>, int64_t>>& from_token,
    const std::optional<std::tuple<std::optional<int64_t>, int64_t>>& to_token,
    BaseDatabaseEngine& engine);

// generate_pagination_bounds
std::tuple<std::string,
           std::optional<std::tuple<std::optional<int64_t>, int64_t>>,
           std::optional<std::tuple<std::optional<int64_t>, int64_t>>>
generate_pagination_bounds(Direction direction,
                             const std::optional<RoomStreamToken>& from_token,
                             const std::optional<RoomStreamToken>& to_token);

// generate_next_token
RoomStreamToken generate_next_token(Direction direction,
                                      std::optional<int64_t> last_topo_ordering,
                                      int64_t last_stream_ordering);

// _make_generic_sql_bound
std::string _make_generic_sql_bound(
    const std::string& bound,
    const std::tuple<std::string, std::string>& column_names,
    const std::tuple<std::optional<int64_t>, int64_t>& values,
    BaseDatabaseEngine& engine);

// _filter_results
bool _filter_results(const std::optional<RoomStreamToken>& lower_token,
                      const std::optional<RoomStreamToken>& upper_token,
                      const std::optional<std::string>& instance_name,
                      int64_t topological_ordering,
                      int64_t stream_ordering);

// _filter_results_by_stream
bool _filter_results_by_stream(const std::optional<RoomStreamToken>& lower_token,
                                 const std::optional<RoomStreamToken>& upper_token,
                                 const std::optional<std::string>& instance_name,
                                 int64_t stream_ordering);

// filter_to_clause
std::pair<std::string, std::vector<std::string>> filter_to_clause(
    const std::optional<Filter>& event_filter);

// ============================================================================
// StreamWorkerStore
// Inherits from EventsWorkerStore for all event CRUD operations
// ============================================================================
class StreamWorkerStore : public EventsWorkerStore {
public:
  StreamWorkerStore(std::shared_ptr<DatabasePool> database,
                     std::shared_ptr<LoggingDatabaseConnection> db_conn,
                     const std::string& server_name,
                     const std::string& instance_name,
                     bool send_federation = false);

  ~StreamWorkerStore() override = default;

  // =========================================================================
  // Stream token / ordering accessors
  // =========================================================================

  int64_t get_room_max_stream_ordering();

  int64_t get_room_min_stream_ordering();

  RoomStreamToken get_room_max_token();

  // =========================================================================
  // Room events stream for multiple rooms
  // =========================================================================

  std::map<std::string, std::tuple<std::vector<nlohmann::json>,
                                     RoomStreamToken, bool>>
  get_room_events_stream_for_rooms(
      const std::vector<std::string>& room_ids,
      const RoomStreamToken& from_key,
      std::optional<RoomStreamToken> to_key = std::nullopt,
      Direction direction = Direction::BACKWARDS,
      int64_t limit = 0);

  std::set<std::string> get_rooms_that_changed(
      const std::vector<std::string>& room_ids,
      const RoomStreamToken& from_key);

  std::vector<std::string> get_rooms_that_have_updates_since_sliding_sync_table(
      const std::vector<std::string>& room_ids,
      const RoomStreamToken& from_key);

  // =========================================================================
  // Pagination by stream ordering
  // =========================================================================

  std::tuple<std::vector<nlohmann::json>, RoomStreamToken, bool>
  paginate_room_events_by_stream_ordering(
      const std::string& room_id,
      const RoomStreamToken& from_key,
      std::optional<RoomStreamToken> to_key = std::nullopt,
      Direction direction = Direction::BACKWARDS,
      int64_t limit = 0);

  // =========================================================================
  // Pagination by topological ordering
  // =========================================================================

  std::tuple<std::vector<nlohmann::json>, RoomStreamToken, bool>
  paginate_room_events_by_topological_ordering(
      const std::string& room_id,
      const RoomStreamToken& from_key,
      std::optional<RoomStreamToken> to_key = std::nullopt,
      Direction direction = Direction::BACKWARDS,
      int64_t limit = 0,
      std::optional<Filter> event_filter = std::nullopt);

  // Transaction-level topological pagination
  std::tuple<std::vector<EventDictReturn>, RoomStreamToken, bool>
  _paginate_room_events_by_topological_ordering_txn(
      LoggingTransaction& txn,
      const std::string& room_id,
      const RoomStreamToken& from_token,
      std::optional<RoomStreamToken> to_token = std::nullopt,
      Direction direction = Direction::BACKWARDS,
      int64_t limit = 0,
      std::optional<Filter> event_filter = std::nullopt);

  // =========================================================================
  // Current state delta membership changes
  // =========================================================================

  std::vector<CurrentStateDeltaMembership>
  get_current_state_delta_membership_changes_for_user(
      const std::string& user_id,
      const RoomStreamToken& from_key,
      const RoomStreamToken& to_key,
      std::optional<std::vector<std::string>> excluded_room_ids = std::nullopt);

  // =========================================================================
  // Sliding sync membership changes
  // =========================================================================

  std::map<std::string, RoomsForUserStateReset>
  get_sliding_sync_membership_changes(
      const std::string& user_id,
      const RoomStreamToken& from_key,
      const RoomStreamToken& to_key,
      std::optional<std::vector<std::string>> excluded_room_ids = std::nullopt);

  // =========================================================================
  // Membership changes for user (simple)
  // =========================================================================

  std::vector<nlohmann::json> get_membership_changes_for_user(
      const std::string& user_id,
      const RoomStreamToken& from_key,
      const RoomStreamToken& to_key,
      std::optional<std::vector<std::string>> excluded_rooms = std::nullopt);

  // =========================================================================
  // Recent events
  // =========================================================================

  std::tuple<std::vector<nlohmann::json>, RoomStreamToken>
  get_recent_events_for_room(const std::string& room_id,
                               int64_t limit,
                               const RoomStreamToken& end_token);

  std::tuple<std::vector<EventDictReturn>, RoomStreamToken>
  get_recent_event_ids_for_room(const std::string& room_id,
                                  int64_t limit,
                                  const RoomStreamToken& end_token);

  // =========================================================================
  // Event position queries
  // =========================================================================

  std::optional<std::tuple<int64_t, int64_t, std::string>>
  get_room_event_before_stream_ordering(const std::string& room_id,
                                          int64_t stream_ordering);

  std::optional<std::string>
  get_last_event_id_in_room_before_stream_ordering(
      const std::string& room_id,
      const RoomStreamToken& end_token);

  std::optional<std::tuple<std::string, PersistedEventPosition>>
  get_last_event_pos_in_room(
      const std::string& room_id,
      std::optional<std::vector<std::string>> event_types = std::nullopt);

  std::optional<std::tuple<std::string, PersistedEventPosition>>
  get_last_event_pos_in_room_before_stream_ordering(
      const std::string& room_id,
      const RoomStreamToken& end_token,
      std::optional<std::vector<std::string>> event_types = std::nullopt);

  // =========================================================================
  // Bulk max event position
  // =========================================================================

  std::map<std::string, int64_t>
  bulk_get_last_event_pos_in_room_before_stream_ordering(
      const std::vector<std::string>& room_ids,
      const RoomStreamToken& end_token);

  std::map<std::string, std::optional<int64_t>>
  _bulk_get_max_event_pos(const std::vector<std::string>& room_ids);

  // =========================================================================
  // Stream token for event
  // =========================================================================

  RoomStreamToken get_current_room_stream_token_for_room_id(
      const std::string& room_id);

  std::optional<int64_t> get_stream_id_for_event_txn(
      LoggingTransaction& txn,
      const std::string& event_id,
      bool allow_none = false);

  PersistedEventPosition get_position_for_event(const std::string& event_id);

  RoomStreamToken get_topological_token_for_event(const std::string& event_id);

  int64_t get_current_topological_token(const std::string& room_id,
                                          int64_t stream_key);

  int64_t _get_max_topological_txn(LoggingTransaction& txn,
                                      const std::string& room_id);

  // =========================================================================
  // Events around a given event
  // =========================================================================

  EventsAround get_events_around(
      const std::string& room_id,
      const std::string& event_id,
      int64_t before_limit,
      int64_t after_limit,
      std::optional<Filter> event_filter = std::nullopt);

  std::map<std::string, nlohmann::json> _get_events_around_txn(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::string& event_id,
      int64_t before_limit,
      int64_t after_limit,
      std::optional<Filter> event_filter = std::nullopt);

  // =========================================================================
  // All new event IDs stream
  // =========================================================================

  std::tuple<int64_t, std::map<std::string, std::optional<int64_t>>>
  get_all_new_event_ids_stream(int64_t from_id, int64_t current_id, int64_t limit);

  // =========================================================================
  // Federation stream position
  // =========================================================================

  int64_t get_federation_out_pos(const std::string& typ);

  void update_federation_out_pos(const std::string& typ, int64_t stream_id);

  void _reset_federation_positions_txn(LoggingTransaction& txn);

  // =========================================================================
  // Room changes
  // =========================================================================

  bool has_room_changed_since(const std::string& room_id, int64_t stream_id);

  // =========================================================================
  // Instance map
  // =========================================================================

  int64_t get_id_for_instance(const std::string& instance_name);

  std::string get_name_from_instance_id(int64_t instance_id);

  // =========================================================================
  // Timeline gaps
  // =========================================================================

  std::optional<RoomStreamToken> get_timeline_gaps(
      const std::string& room_id,
      std::optional<RoomStreamToken> from_token,
      const RoomStreamToken& to_token);

  // =========================================================================
  // Rooms that might have updates
  // =========================================================================

  std::vector<std::string> get_rooms_that_might_have_updates(
      const std::vector<std::string>& room_ids,
      const RoomStreamToken& from_token);

protected:
  // Instance info
  bool send_federation_ = false;
  std::vector<std::string> federation_shard_instances_;
  bool need_to_reset_federation_stream_positions_ = false;

  // Stream caches
  std::shared_ptr<StreamChangeCache> events_stream_cache_;
  std::shared_ptr<StreamChangeCache> membership_stream_cache_;

  // Stream positions at startup
  int64_t stream_order_on_start_ = 0;
  int64_t min_stream_order_on_start_ = 0;

  // Cache dict initial values
  int64_t events_max_ = 0;
  int64_t min_curr_state_delta_id_ = 0;
};

// ============================================================================
// StreamStore - Alias for StreamWorkerStore (mirrors Python inheritance chain)
// In Python: class StreamStore(StreamWorkerStore)
// ============================================================================
using StreamStore = StreamWorkerStore;

}  // namespace progressive::storage
