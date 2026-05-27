#pragma once
// ============================================================================
// events_worker.hpp - EventsWorkerStore: event fetching, caching, redaction
// Translated from synapse/storage/databases/main/events_worker.py
// ============================================================================

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/types.hpp"
#include "progressive/util/cache.hpp"
#include "progressive/util/stream_cache.hpp"

namespace progressive::storage {

// Forward declarations
class DatabasePool;
class StreamWorkerStore;

// ============================================================================
// Enums and constants from events_worker.py
// ============================================================================

enum class EventRedactBehaviour {
  AS_IS,
  REDACT,
  BLOCK,
};

enum class Direction {
  FORWARDS,
  BACKWARDS,
};

// Event fetch threading constants
static constexpr int EVENT_QUEUE_THREADS = 3;
static constexpr int EVENT_QUEUE_ITERATIONS = 3;
static constexpr double EVENT_QUEUE_TIMEOUT_S = 0.1;
static constexpr int ITERATIONS_BEFORE_YIELDING = 500;

// Known event types
namespace EventTypes {
  static constexpr const char* MEMBER = "m.room.member";
  static constexpr const char* CREATE = "m.room.create";
  static constexpr const char* REDACTION = "m.room.redaction";
  static constexpr const char* MESSAGE = "m.room.message";
}  // namespace EventTypes

namespace Membership {
  static constexpr const char* JOIN = "join";
  static constexpr const char* LEAVE = "leave";
  static constexpr const char* INVITE = "invite";
  static constexpr const char* BAN = "ban";
  static constexpr const char* KNOCK = "knock";
}  // namespace Membership

// ============================================================================
// Event format versions
// ============================================================================
namespace EventFormatVersions {
  static constexpr int ROOM_V1_V2 = 1;
  static constexpr int ROOM_V3 = 2;
  static constexpr int ROOM_V4_PLUS = 3;
}  // namespace EventFormatVersions

// ============================================================================
// Exception types
// ============================================================================
class DatabaseCorruptionError : public std::runtime_error {
public:
  std::string room_id;
  std::string persisted_event_id;
  std::string computed_event_id;

  DatabaseCorruptionError(const std::string& room_id_,
                           const std::string& persisted_event_id_,
                           const std::string& computed_event_id_)
      : std::runtime_error(
            "Database corruption: Event " + persisted_event_id_ +
            " in room " + room_id_ +
            " appears to have been modified (calculated event id " +
            computed_event_id_ + ")"),
        room_id(room_id_),
        persisted_event_id(persisted_event_id_),
        computed_event_id(computed_event_id_) {}
};

class InvalidEventError : public std::runtime_error {
public:
  explicit InvalidEventError(const std::string& msg)
      : std::runtime_error(msg) {}
};

class NotFoundError : public std::runtime_error {
public:
  explicit NotFoundError(const std::string& msg)
      : std::runtime_error(msg) {}
};

class SynapseError : public std::runtime_error {
public:
  int code = 500;
  SynapseError(int c, const std::string& msg)
      : std::runtime_error(msg), code(c) {}
};

// ============================================================================
// Data structures
// ============================================================================

// Equivalent to _EventRow in events_worker.py
struct EventRow {
  std::string event_id;
  int64_t stream_ordering = 0;
  std::string instance_name = "master";
  std::string json_data;
  std::string internal_metadata;
  std::optional<int> format_version;
  std::optional<std::string> room_version_id;
  std::optional<std::string> rejected_reason;
  std::vector<std::string> unconfirmed_redactions;
  std::vector<std::string> confirmed_redactions;
  bool outlier = false;
};

// Equivalent to EventCacheEntry in events_worker.py
struct EventCacheEntry {
  nlohmann::json event;
  std::optional<nlohmann::json> redacted_event;
};

// Equivalent to EventMetadata in events_worker.py
struct EventMetadata {
  std::string sender;
  int64_t received_ts = 0;
};

// Equivalent to PersistedEventPosition
struct PersistedEventPosition {
  std::string instance_name = "master";
  int64_t stream = 0;

  PersistedEventPosition() = default;
  PersistedEventPosition(const std::string& inst, int64_t s)
      : instance_name(inst), stream(s) {}

  bool persisted_after(const PersistedEventPosition& other) const;
  bool operator==(const PersistedEventPosition& other) const;
  bool operator!=(const PersistedEventPosition& other) const;
  bool operator<(const PersistedEventPosition& other) const;
};

// Equivalent to RoomStreamToken
class RoomStreamToken {
public:
  std::optional<int64_t> topological;
  int64_t stream = 0;

  RoomStreamToken() = default;
  RoomStreamToken(std::optional<int64_t> topo, int64_t s)
      : topological(topo), stream(s) {}
  explicit RoomStreamToken(int64_t s) : topological(std::nullopt), stream(s) {}

  std::tuple<std::optional<int64_t>, int64_t> as_historical_tuple() const {
    return {topological, stream};
  }

  int64_t get_max_stream_pos() const { return stream; }
  int64_t get_stream_pos_for_instance(const std::string& /*instance*/) const {
    return stream;
  }

  bool is_before_or_eq(const RoomStreamToken& other) const;
  bool operator==(const RoomStreamToken& other) const;
  bool operator!=(const RoomStreamToken& other) const;

  std::string to_string() const;
};

// Equivalent to _EventDictReturn in stream.py
struct EventDictReturn {
  std::string event_id;
  std::optional<int64_t> topological_ordering;
  int64_t stream_ordering = 0;

  EventDictReturn() = default;
  EventDictReturn(const std::string& eid, std::optional<int64_t> topo, int64_t stream)
      : event_id(eid), topological_ordering(topo), stream_ordering(stream) {}
};

// Equivalent to _EventsAround in stream.py
struct EventsAround {
  std::vector<nlohmann::json> events_before;
  std::vector<nlohmann::json> events_after;
  RoomStreamToken start;
  RoomStreamToken end;
};

// Equivalent to CurrentStateDeltaMembership in stream.py
struct CurrentStateDeltaMembership {
  std::string room_id;
  std::optional<std::string> event_id;
  PersistedEventPosition event_pos;
  std::string membership;
  std::optional<std::string> sender;
  std::optional<std::string> prev_event_id;
  std::optional<PersistedEventPosition> prev_event_pos;
  std::optional<std::string> prev_membership;
  std::optional<std::string> prev_sender;
};

// ============================================================================
// Filter class (simplified equivalent of synapse.api.filtering.Filter)
// ============================================================================
class Filter {
public:
  std::vector<std::string> types;
  std::vector<std::string> not_types;
  std::vector<std::string> senders;
  std::vector<std::string> not_senders;
  std::vector<std::string> rooms;
  std::vector<std::string> not_rooms;
  std::optional<bool> contains_url;
  std::vector<std::string> labels;
  std::vector<std::string> not_labels;
  std::vector<std::string> related_by_senders;
  std::vector<std::string> related_by_rel_types;
  std::vector<std::string> rel_types;
  std::vector<std::string> not_rel_types;

  Filter() = default;
};

// ============================================================================
// EventsWorkerStore - Main event fetching and caching
// Equivalent to EventsWorkerStore in events_worker.py
// ============================================================================
class EventsWorkerStore {
public:
  EventsWorkerStore(std::shared_ptr<DatabasePool> database,
                     std::shared_ptr<LoggingDatabaseConnection> db_conn,
                     const std::string& server_name,
                     const std::string& instance_name);

  virtual ~EventsWorkerStore() = default;

  // =========================================================================
  // Event fetching (get_event, get_events, get_events_as_list)
  // =========================================================================

  std::optional<nlohmann::json> get_event(
      const std::string& event_id,
      EventRedactBehaviour redact_behaviour = EventRedactBehaviour::REDACT,
      bool get_prev_content = false,
      bool allow_rejected = false,
      bool allow_none = false,
      std::optional<std::string> check_room_id = std::nullopt);

  std::map<std::string, nlohmann::json> get_events(
      const std::vector<std::string>& event_ids,
      EventRedactBehaviour redact_behaviour = EventRedactBehaviour::REDACT,
      bool get_prev_content = false,
      bool allow_rejected = false);

  std::vector<nlohmann::json> get_events_as_list(
      const std::vector<std::string>& event_ids,
      EventRedactBehaviour redact_behaviour = EventRedactBehaviour::REDACT,
      bool get_prev_content = false,
      bool allow_rejected = false);

  // =========================================================================
  // Cache-based event fetching
  // =========================================================================

  std::map<std::string, EventCacheEntry> get_unredacted_events_from_cache_or_db(
      const std::set<std::string>& event_ids,
      bool allow_rejected = false);

  void invalidate_get_event_cache_after_txn(LoggingTransaction& txn,
                                              const std::string& event_id);

  void _invalidate_local_get_event_cache(const std::string& event_id);

  void _invalidate_local_get_event_cache_room_id(const std::string& room_id);

  // =========================================================================
  // Database event fetching
  // =========================================================================

  std::map<std::string, EventCacheEntry> _get_events_from_db(
      const std::set<std::string>& event_ids);

  std::map<std::string, EventRow> _fetch_event_rows(
      LoggingTransaction& txn,
      const std::vector<std::string>& event_ids);

  std::optional<nlohmann::json> _maybe_redact_event_row(
      const nlohmann::json& original_ev,
      const std::vector<std::string>& unconfirmed_redactions,
      const std::vector<std::string>& confirmed_redactions,
      const std::map<std::string, nlohmann::json>& event_map);

  // =========================================================================
  // Event presence checks
  // =========================================================================

  std::set<std::string> have_events_in_timeline(
      const std::vector<std::string>& event_ids);

  std::set<std::string> have_seen_events(
      const std::string& room_id,
      const std::vector<std::string>& event_ids);

  std::map<std::string, bool> _have_seen_events_dict(
      const std::string& room_id,
      const std::vector<std::string>& event_ids);

  bool have_seen_event(const std::string& room_id,
                        const std::string& event_id);

  // =========================================================================
  // Redaction / censoring
  // =========================================================================

  bool have_censored_event(const std::string& event_id);

  // =========================================================================
  // Stream management (from events worker)
  // =========================================================================

  int64_t get_room_max_stream_ordering();

  int64_t get_room_min_stream_ordering();

  RoomStreamToken get_room_max_token();

  // =========================================================================
  // Replication stream methods
  // =========================================================================

  struct EventStreamRow {
    int64_t stream_ordering = 0;
    std::string event_id;
    std::string room_id;
    std::string type;
    std::string state_key;
    std::string redacts;
    std::string relates_to_id;
    std::string membership;
    bool rejected = false;
    bool outlier = false;
  };

  std::vector<EventStreamRow> get_all_new_forward_event_rows(
      const std::string& instance_name,
      int64_t last_id, int64_t current_id, int64_t limit);

  std::vector<EventStreamRow> get_ex_outlier_stream_rows(
      const std::string& instance_name,
      int64_t last_id, int64_t current_id);

  using BackfillRow = std::tuple<int64_t, std::string, std::string, std::string,
                                   std::string, std::string, std::string>;
  struct BackfillResult {
    std::vector<std::tuple<int64_t, BackfillRow>> updates;
    int64_t upper_bound = 0;
    bool limited = false;
  };
  BackfillResult get_all_new_backfill_event_rows(
      const std::string& instance_name,
      int64_t last_id, int64_t current_id, int64_t limit);

  // =========================================================================
  // Current state delta stream
  // =========================================================================

  struct CurrentStateDeltaRow {
    int64_t stream_id = 0;
    std::string room_id;
    std::string type;
    std::string state_key;
    std::string event_id;
  };

  struct CurrentStateDeltaResult {
    std::vector<CurrentStateDeltaRow> updates;
    int64_t new_last_token = 0;
    bool limited = false;
  };
  CurrentStateDeltaResult get_all_updated_current_state_deltas(
      const std::string& instance_name,
      int64_t from_token, int64_t to_token, int64_t target_row_count);

  // =========================================================================
  // Partial state events
  // =========================================================================

  std::map<std::string, bool> get_partial_state_events(
      const std::vector<std::string>& event_ids);

  bool is_partial_state_event(const std::string& event_id);

  std::vector<std::string> get_partial_state_events_batch(
      const std::string& room_id);

  static std::vector<std::string> _get_partial_state_events_batch_txn(
      LoggingTransaction& txn, const std::string& room_id);

  // =========================================================================
  // Event metadata queries
  // =========================================================================

  std::optional<EventMetadata> get_metadata_for_event(
      const std::string& room_id, const std::string& event_id);

  std::map<std::string, std::optional<std::string>> get_senders_for_event_ids(
      const std::vector<std::string>& event_ids);

  std::tuple<int64_t, int64_t> get_event_ordering(
      const std::string& event_id, const std::string& room_id);

  // =========================================================================
  // Event expiry and transaction IDs
  // =========================================================================

  std::optional<std::tuple<std::string, int64_t>> get_next_event_to_expire();

  std::optional<std::string> get_event_id_from_transaction_id_and_device_id(
      const std::string& room_id, const std::string& user_id,
      const std::string& device_id, const std::string& txn_id);

  std::map<std::string, std::string> get_already_persisted_events(
      const std::vector<nlohmann::json>& events);

  void _cleanup_old_transaction_ids();

  // =========================================================================
  // Gap detection
  // =========================================================================

  bool is_event_next_to_backward_gap(const nlohmann::json& event);

  bool is_event_next_to_forward_gap(const nlohmann::json& event);

  // =========================================================================
  // Timestamp-based event lookup
  // =========================================================================

  std::optional<std::string> get_event_id_for_timestamp(
      const std::string& room_id, int64_t timestamp, Direction direction);

  // =========================================================================
  // User events in room
  // =========================================================================

  std::optional<std::vector<std::string>> get_events_sent_by_user_in_room(
      const std::string& user_id, const std::string& room_id,
      int64_t limit, std::optional<std::vector<std::string>> filter = std::nullopt);

  // =========================================================================
  // Sent invite count
  // =========================================================================

  int64_t get_sent_invite_count_by_user(const std::string& user_id, int64_t from_ts);

  // =========================================================================
  // Room complexity
  // =========================================================================

  int64_t _get_current_state_event_counts_txn(LoggingTransaction& txn,
                                                const std::string& room_id);

  int64_t get_current_state_event_counts(const std::string& room_id);

  std::map<std::string, double> get_room_complexity(const std::string& room_id);

  // =========================================================================
  // Sliding sync background jobs
  // =========================================================================

  bool have_finished_sliding_sync_background_jobs();

  // =========================================================================
  // Rejection marking
  // =========================================================================

  void mark_event_rejected_txn(LoggingTransaction& txn,
                                 const std::string& event_id,
                                 std::optional<std::string> rejection_reason);

  // =========================================================================
  // Un-partial-stated events stream
  // =========================================================================

  int64_t get_un_partial_stated_events_token(const std::string& instance_name);

  using UnPartialRow = std::tuple<int64_t, std::string, bool>;
  struct UnPartialResult {
    std::vector<UnPartialRow> updates;
    int64_t upto_token = 0;
    bool limited = false;
  };
  UnPartialResult get_un_partial_stated_events_from_stream(
      const std::string& instance_name,
      int64_t last_id, int64_t current_id, int64_t limit);

  // =========================================================================
  // Cache helpers
  // =========================================================================

  std::map<std::string, EventCacheEntry> _get_events_from_cache(
      const std::vector<std::string>& event_ids,
      bool update_metrics = true);

  std::map<std::string, EventCacheEntry> _get_events_from_local_cache(
      const std::vector<std::string>& event_ids,
      bool update_metrics = true);

  std::map<std::string, EventCacheEntry> _get_events_from_external_cache(
      const std::vector<std::string>& event_ids,
      bool update_metrics = true);

  // =========================================================================
  // Event fetch threading
  // =========================================================================

  void _maybe_start_fetch_thread();

  void _fetch_thread();

  void _fetch_loop(LoggingDatabaseConnection& conn);

  void _fetch_event_list(
      LoggingDatabaseConnection& conn,
      std::vector<std::pair<std::vector<std::string>,
                            std::function<void(std::map<std::string, EventRow>)>>>&
          event_list);

protected:
  // Database components
  std::shared_ptr<DatabasePool> db_pool_;
  std::shared_ptr<LoggingDatabaseConnection> db_conn_;
  std::string server_name_;
  std::string instance_name_;

  // ID generators
  int64_t stream_id_gen_current_ = 0;
  int64_t backfill_id_gen_current_ = 0;

  // Caches
  using EventCache = BaseCache<std::string, EventCacheEntry>;
  std::shared_ptr<EventCache> event_cache_;
  std::unordered_map<std::string, nlohmann::json> event_ref_;

  // Current event fetches tracking
  std::mutex event_fetch_mutex_;
  std::condition_variable event_fetch_cv_;
  struct EventFetchEntry {
    std::vector<std::string> event_ids;
    std::function<void(std::map<std::string, EventRow>)> deferred;
  };
  std::vector<EventFetchEntry> event_fetch_list_;
  int32_t event_fetch_ongoing_ = 0;

  // Stream change caches
  std::shared_ptr<StreamChangeCache> curr_state_delta_stream_cache_;

  // Sliding sync
  bool has_finished_sliding_sync_bg_jobs_ = false;

  // Utility
  std::string make_in_list_sql_clause(const std::string& column,
                                        const std::vector<std::string>& items,
                                        bool negative = false);
};

}  // namespace progressive::storage
