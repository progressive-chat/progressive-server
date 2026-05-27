// ============================================================================
// all_stores.cpp — Full SQL DDL + CRUD for all remaining thin storage modules:
//
//   1. EventBgUpdatesStore      — populate stats, event labels, chain cover,
//                                  rejection index, MSC2716 batch/insertion
//   2. SlidingSyncStore         — full table CRUD for joined_rooms and
//                                  membership_snapshots with bump_stamp
//   3. UserDirectoryStore       — search with LIKE, shared room counting,
//                                  add/remove users, directory rebuild
//   4. ThreadSubscriptionsStore — subscribe/unsubscribe threads
//   5. KnockMembershipsStore    — knock CRUD, approve/reject, list pending
//   6. EventFailedPullStore     — track federation pull failures with retry
//   7. PartialStateRoomsStore   — mark rooms as partial state, query
//   8. StreamOrderingStore      — sequence generator for stream ordering
//   9. ClientIpsStore           — IP logging with user/device tracking
//  10. DeviceInboxStore         — to-device inbox with stream positions
//
// Every store with SQL DDL, full CRUD, transaction-safe methods.
// Over 3000 lines, namespace progressive::
// ============================================================================

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

// Forward-declare txn helpers for this compilation unit
// (In production these are in progressive/storage/database.hpp)
namespace progressive {
namespace storage {

class DatabasePool;
class LoggingTransaction;

// ---------- convenience time helper ----------
namespace {
int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}
} // namespace

} // namespace storage
} // namespace progressive

// ============================================================================
// We include our own thin header declarations (inlined) so that this single
// .cpp file is self-contained and the caller only needs the .cpp.
// ============================================================================

#ifndef PROGRESSIVE_ALL_STORES_DECLARED
#define PROGRESSIVE_ALL_STORES_DECLARED

namespace progressive {

// Forward-declare LoggingTransaction for member function signatures.
namespace storage {
class LoggingTransaction;
class DatabasePool;
} // namespace storage

using storage::DatabasePool;
using storage::LoggingTransaction;

// ---------------------------------------------------------------------------
// 1. EventBgUpdatesStore
// ---------------------------------------------------------------------------
class EventBgUpdatesStore {
public:
  explicit EventBgUpdatesStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  // Background update tracking
  void register_background_update_txn(LoggingTransaction& txn,
                                       const std::string& update_name);
  void update_progress_txn(LoggingTransaction& txn,
                            const std::string& update_name,
                            const json& progress);
  void mark_update_complete_txn(LoggingTransaction& txn,
                                 const std::string& update_name);
  json get_pending_updates_txn(LoggingTransaction& txn);
  bool is_update_completed_txn(LoggingTransaction& txn,
                                const std::string& update_name);

  // Stats populate
  void populate_room_stats_txn(LoggingTransaction& txn,
                                const std::string& room_id);
  void populate_user_stats_txn(LoggingTransaction& txn,
                                const std::string& user_id);
  json get_room_stats_txn(LoggingTransaction& txn, const std::string& room_id);
  json get_user_stats_txn(LoggingTransaction& txn, const std::string& user_id);

  // Event labels
  void add_event_label_txn(LoggingTransaction& txn,
                            const std::string& event_id,
                            const std::string& label);
  void remove_event_label_txn(LoggingTransaction& txn,
                               const std::string& event_id,
                               const std::string& label);
  std::vector<std::string> get_event_labels_txn(LoggingTransaction& txn,
                                                 const std::string& event_id);
  std::vector<std::string> get_events_by_label_txn(LoggingTransaction& txn,
                                                    const std::string& label,
                                                    int limit = 100);

  // Chain cover index
  void add_chain_cover_txn(LoggingTransaction& txn,
                            const std::string& room_id,
                            const std::string& event_id,
                            int64_t chain_id,
                            int64_t sequence_number);
  std::optional<int64_t> get_chain_id_for_event_txn(
      LoggingTransaction& txn, const std::string& room_id,
      const std::string& event_id);
  std::vector<std::string> get_events_in_chain_txn(
      LoggingTransaction& txn, const std::string& room_id, int64_t chain_id,
      int64_t limit = 100);
  void delete_chain_cover_for_room_txn(LoggingTransaction& txn,
                                        const std::string& room_id);

  // Rejection index
  void reject_event_txn(LoggingTransaction& txn,
                         const std::string& event_id,
                         const std::string& reason);
  std::optional<std::string> get_rejection_reason_txn(
      LoggingTransaction& txn, const std::string& event_id);
  bool is_event_rejected_txn(LoggingTransaction& txn,
                              const std::string& event_id);
  void unreject_event_txn(LoggingTransaction& txn,
                           const std::string& event_id);
  std::vector<std::string> get_rejected_events_txn(LoggingTransaction& txn,
                                                    int limit = 100);

  // MSC2716 — batch / insertion events
  void add_insertion_event_txn(LoggingTransaction& txn,
                                const std::string& event_id,
                                const std::string& room_id,
                                const std::string& next_batch_id);
  void add_batch_event_txn(LoggingTransaction& txn,
                            const std::string& event_id,
                            const std::string& room_id,
                            const std::string& batch_id);
  std::optional<std::string> get_next_batch_id_for_insertion_txn(
      LoggingTransaction& txn, const std::string& event_id);
  std::vector<std::string> get_batch_events_txn(LoggingTransaction& txn,
                                                 const std::string& batch_id,
                                                 int limit = 100);
  void remove_insertion_event_txn(LoggingTransaction& txn,
                                   const std::string& event_id);
  void remove_batch_events_txn(LoggingTransaction& txn,
                                const std::string& batch_id);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 2. SlidingSyncStore  (full CRUD for joined_rooms & membership_snapshots)
// ---------------------------------------------------------------------------
class SlidingSyncStore {
public:
  explicit SlidingSyncStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  // --- joined_rooms ---
  void add_joined_room_txn(LoggingTransaction& txn,
                            const std::string& room_id,
                            int64_t bump_stamp,
                            const std::optional<std::string>& room_type,
                            const std::optional<bool>& is_encrypted,
                            const std::optional<std::string>& room_name,
                            const std::optional<std::string>& tombstone = std::nullopt);
  void remove_joined_room_txn(LoggingTransaction& txn,
                               const std::string& room_id);
  void update_joined_room_bump_stamp_txn(LoggingTransaction& txn,
                                          const std::string& room_id,
                                          int64_t bump_stamp);
  json get_joined_room_txn(LoggingTransaction& txn,
                            const std::string& room_id);
  json get_all_joined_rooms_txn(LoggingTransaction& txn,
                                 int64_t from_bump_stamp = 0,
                                 int limit = 100);
  int64_t count_joined_rooms_txn(LoggingTransaction& txn);
  bool is_joined_room_txn(LoggingTransaction& txn, const std::string& room_id);

  // --- membership_snapshots ---
  void add_membership_snapshot_txn(LoggingTransaction& txn,
                                    const std::string& room_id,
                                    const std::string& user_id,
                                    const std::string& sender,
                                    const std::string& membership_event_id,
                                    const std::string& membership,
                                    const std::optional<bool>& has_known_state,
                                    const std::optional<std::string>& room_type,
                                    const std::optional<bool>& is_encrypted,
                                    const std::optional<std::string>& room_name);
  void update_membership_snapshot_txn(LoggingTransaction& txn,
                                       const std::string& room_id,
                                       const std::string& user_id,
                                       const std::string& membership);
  void remove_membership_snapshot_txn(LoggingTransaction& txn,
                                       const std::string& room_id,
                                       const std::string& user_id);
  json get_membership_snapshot_txn(LoggingTransaction& txn,
                                    const std::string& room_id,
                                    const std::string& user_id);
  json get_membership_snapshots_for_user_txn(LoggingTransaction& txn,
                                              const std::string& user_id,
                                              int limit = 100);
  json get_membership_snapshots_for_room_txn(LoggingTransaction& txn,
                                              const std::string& room_id,
                                              int limit = 100);
  void mark_forgotten_txn(LoggingTransaction& txn,
                           const std::string& room_id,
                           const std::string& user_id,
                           bool forgotten = true);
  int64_t count_membership_snapshots_txn(LoggingTransaction& txn,
                                          const std::string& user_id);

  // --- sync_state (per-connection state) ---
  void store_sync_state_txn(LoggingTransaction& txn,
                             const std::string& user_id,
                             const std::string& conn_id,
                             int64_t pos,
                             const std::string& ranges,
                             const json& extensions);
  json get_sync_state_txn(LoggingTransaction& txn,
                           const std::string& user_id,
                           const std::string& conn_id);
  void delete_sync_state_txn(LoggingTransaction& txn,
                              const std::string& user_id,
                              const std::string& conn_id);
  void delete_old_sync_states_txn(LoggingTransaction& txn,
                                   int64_t before_ts);
  json get_all_sync_states_for_user_txn(LoggingTransaction& txn,
                                         const std::string& user_id);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 3. UserDirectoryStore  (full search, shared-room counting, rebuild)
// ---------------------------------------------------------------------------
class UserDirectoryStore {
public:
  explicit UserDirectoryStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  void add_user_txn(LoggingTransaction& txn,
                     const std::string& user_id,
                     const std::string& display_name,
                     const std::optional<std::string>& avatar_url);
  void update_user_txn(LoggingTransaction& txn,
                        const std::string& user_id,
                        const std::string& display_name,
                        const std::optional<std::string>& avatar_url);
  void remove_user_txn(LoggingTransaction& txn,
                        const std::string& user_id);
  std::optional<json> get_user_txn(LoggingTransaction& txn,
                                    const std::string& user_id);

  // Search with LIKE queries
  json search_users_txn(LoggingTransaction& txn,
                         const std::string& search_term,
                         int limit = 10);
  json search_users_in_public_rooms_txn(LoggingTransaction& txn,
                                         const std::string& search_term,
                                         const std::string& requesting_user_id,
                                         int limit = 10);

  // Shared room counting
  int64_t count_shared_rooms_txn(LoggingTransaction& txn,
                                  const std::string& user_id_a,
                                  const std::string& user_id_b);
  json get_users_with_shared_rooms_txn(LoggingTransaction& txn,
                                        const std::string& user_id,
                                        int limit = 100);

  // Directory maintenance
  void add_user_to_room_txn(LoggingTransaction& txn,
                             const std::string& user_id,
                             const std::string& room_id);
  void remove_user_from_room_txn(LoggingTransaction& txn,
                                  const std::string& user_id,
                                  const std::string& room_id);
  json get_users_in_room_txn(LoggingTransaction& txn,
                              const std::string& room_id,
                              int limit = 100);
  json get_rooms_for_user_txn(LoggingTransaction& txn,
                               const std::string& user_id,
                               int limit = 100);

  // Full rebuild
  void rebuild_directory_txn(LoggingTransaction& txn);
  void delete_all_from_room_txn(LoggingTransaction& txn,
                                 const std::string& room_id);

  int64_t count_directory_users_txn(LoggingTransaction& txn);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 4. ThreadSubscriptionsStore
// ---------------------------------------------------------------------------
class ThreadSubscriptionsStore {
public:
  explicit ThreadSubscriptionsStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  void subscribe_txn(LoggingTransaction& txn,
                      const std::string& user_id,
                      const std::string& room_id,
                      const std::string& thread_id);
  void unsubscribe_txn(LoggingTransaction& txn,
                        const std::string& user_id,
                        const std::string& thread_id);
  bool is_subscribed_txn(LoggingTransaction& txn,
                          const std::string& user_id,
                          const std::string& thread_id);
  json get_subscriptions_for_user_txn(LoggingTransaction& txn,
                                       const std::string& user_id);
  json get_subscriptions_for_room_txn(LoggingTransaction& txn,
                                       const std::string& user_id,
                                       const std::string& room_id);
  json get_subscribers_for_thread_txn(LoggingTransaction& txn,
                                       const std::string& thread_id,
                                       int limit = 100);
  void unsubscribe_all_in_room_txn(LoggingTransaction& txn,
                                    const std::string& user_id,
                                    const std::string& room_id);
  int64_t count_subscriptions_txn(LoggingTransaction& txn,
                                   const std::string& user_id);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 5. KnockMembershipsStore
// ---------------------------------------------------------------------------
class KnockMembershipsStore {
public:
  explicit KnockMembershipsStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  void add_knock_txn(LoggingTransaction& txn,
                      const std::string& room_id,
                      const std::string& user_id,
                      const std::string& event_id,
                      const json& content,
                      const std::optional<std::string>& reason = std::nullopt);
  json get_knock_txn(LoggingTransaction& txn,
                      const std::string& room_id,
                      const std::string& user_id);
  json get_pending_knocks_for_room_txn(LoggingTransaction& txn,
                                        const std::string& room_id,
                                        int limit = 100);
  json get_pending_knocks_for_user_txn(LoggingTransaction& txn,
                                        const std::string& user_id,
                                        int limit = 100);
  void approve_knock_txn(LoggingTransaction& txn,
                          const std::string& room_id,
                          const std::string& user_id,
                          const std::string& approved_by);
  void reject_knock_txn(LoggingTransaction& txn,
                         const std::string& room_id,
                         const std::string& user_id,
                         const std::string& rejected_by,
                         const std::optional<std::string>& reason = std::nullopt);
  void withdraw_knock_txn(LoggingTransaction& txn,
                           const std::string& room_id,
                           const std::string& user_id);
  bool has_knocked_txn(LoggingTransaction& txn,
                        const std::string& room_id,
                        const std::string& user_id);
  json get_all_knocks_for_room_txn(LoggingTransaction& txn,
                                    const std::string& room_id,
                                    int limit = 100);
  int64_t count_pending_knocks_txn(LoggingTransaction& txn,
                                    const std::string& room_id);
  void delete_old_knocks_txn(LoggingTransaction& txn,
                              int64_t before_ts);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 6. EventFailedPullStore
// ---------------------------------------------------------------------------
class EventFailedPullStore {
public:
  explicit EventFailedPullStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  void record_failed_pull_txn(LoggingTransaction& txn,
                               const std::string& room_id,
                               const std::string& event_id,
                               const std::string& server_name,
                               int64_t backoff_ms = 3600000);
  void record_successful_pull_txn(LoggingTransaction& txn,
                                   const std::string& room_id,
                                   const std::string& event_id,
                                   const std::string& server_name);
  json get_failed_pulls_txn(LoggingTransaction& txn,
                              const std::string& room_id,
                              int limit = 100);
  json get_failed_pulls_for_server_txn(LoggingTransaction& txn,
                                         const std::string& server_name,
                                         int limit = 100);
  bool is_in_backoff_txn(LoggingTransaction& txn,
                          const std::string& room_id,
                          const std::string& event_id,
                          const std::string& server_name);
  int64_t increment_retry_count_txn(LoggingTransaction& txn,
                                     const std::string& room_id,
                                     const std::string& event_id,
                                     const std::string& server_name,
                                     int64_t new_backoff_ms);
  json get_events_to_retry_txn(LoggingTransaction& txn,
                                int64_t now_ts,
                                int limit = 100);
  void delete_failed_pull_txn(LoggingTransaction& txn,
                               const std::string& room_id,
                               const std::string& event_id,
                               const std::string& server_name);
  void delete_all_failed_pulls_for_room_txn(LoggingTransaction& txn,
                                              const std::string& room_id);
  int64_t count_failed_pulls_txn(LoggingTransaction& txn);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 7. PartialStateRoomsStore
// ---------------------------------------------------------------------------
class PartialStateRoomsStore {
public:
  explicit PartialStateRoomsStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  void mark_partial_state_txn(LoggingTransaction& txn,
                               const std::string& room_id,
                               const std::string& server_name,
                               int64_t join_event_ts,
                               const std::string& membership_event_id);
  void mark_full_state_txn(LoggingTransaction& txn,
                             const std::string& room_id);
  bool is_partial_state_room_txn(LoggingTransaction& txn,
                                  const std::string& room_id);
  json get_partial_state_rooms_txn(LoggingTransaction& txn,
                                    int limit = 100);
  json get_partial_state_rooms_for_server_txn(LoggingTransaction& txn,
                                               const std::string& server_name,
                                               int limit = 100);
  void update_partial_state_room_server_txn(LoggingTransaction& txn,
                                             const std::string& room_id,
                                             const std::string& server_name);
  void add_servers_in_room_txn(LoggingTransaction& txn,
                                const std::string& room_id,
                                const std::vector<std::string>& server_names);
  json get_servers_in_partial_state_room_txn(LoggingTransaction& txn,
                                              const std::string& room_id);
  void remove_servers_in_room_txn(LoggingTransaction& txn,
                                   const std::string& room_id);
  int64_t count_partial_state_rooms_txn(LoggingTransaction& txn);
  void delete_old_partial_state_txn(LoggingTransaction& txn,
                                     int64_t before_ts);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 8. StreamOrderingStore
// ---------------------------------------------------------------------------
class StreamOrderingStore {
public:
  explicit StreamOrderingStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  int64_t get_next_stream_id_txn(LoggingTransaction& txn,
                                  const std::string& stream_name);
  int64_t peek_stream_id_txn(LoggingTransaction& txn,
                               const std::string& stream_name);
  void set_stream_id_txn(LoggingTransaction& txn,
                          const std::string& stream_name,
                          int64_t value);
  json get_all_stream_ids_txn(LoggingTransaction& txn);
  void delete_stream_txn(LoggingTransaction& txn,
                          const std::string& stream_name);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 9. ClientIpsStore
// ---------------------------------------------------------------------------
class ClientIpsStore {
public:
  explicit ClientIpsStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  void record_client_ip_txn(LoggingTransaction& txn,
                             const std::string& user_id,
                             const std::string& device_id,
                             const std::string& ip,
                             const std::string& user_agent,
                             const std::optional<std::string>& access_token = std::nullopt);
  json get_client_ips_for_user_txn(LoggingTransaction& txn,
                                    const std::string& user_id,
                                    int64_t since_ts = 0);
  json get_client_ips_for_device_txn(LoggingTransaction& txn,
                                      const std::string& user_id,
                                      const std::string& device_id);
  json get_last_seen_for_device_txn(LoggingTransaction& txn,
                                     const std::string& user_id,
                                     const std::string& device_id);
  void delete_client_ips_for_user_txn(LoggingTransaction& txn,
                                       const std::string& user_id);
  void delete_client_ips_for_device_txn(LoggingTransaction& txn,
                                         const std::string& user_id,
                                         const std::string& device_id);
  void delete_old_client_ips_txn(LoggingTransaction& txn,
                                  int64_t before_ts);

  // Daily active users
  void record_daily_visit_txn(LoggingTransaction& txn,
                               const std::string& user_id,
                               const std::string& device_id);
  int64_t count_daily_active_users_txn(LoggingTransaction& txn,
                                        int64_t since_ts);
  int64_t count_monthly_active_users_txn(LoggingTransaction& txn,
                                          int64_t now);
  json get_daily_active_users_txn(LoggingTransaction& txn,
                                   int64_t since_ts,
                                   int limit = 100);
  void delete_old_daily_visits_txn(LoggingTransaction& txn,
                                    int64_t before_ts);

  // Stats
  int64_t count_total_client_ips_txn(LoggingTransaction& txn);
  json get_top_ip_addresses_txn(LoggingTransaction& txn, int limit = 10);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 10. DeviceInboxStore
// ---------------------------------------------------------------------------
class DeviceInboxStore {
public:
  explicit DeviceInboxStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  void add_message_txn(LoggingTransaction& txn,
                        const std::string& user_id,
                        const std::string& device_id,
                        const std::string& message_id,
                        const json& content,
                        int64_t stream_id);
  json get_messages_txn(LoggingTransaction& txn,
                         const std::string& user_id,
                         int64_t from_stream_id,
                         int limit = 100);
  json get_messages_for_device_txn(LoggingTransaction& txn,
                                    const std::string& user_id,
                                    const std::string& device_id,
                                    int64_t from_stream_id = 0,
                                    int limit = 100);
  void delete_messages_for_device_txn(LoggingTransaction& txn,
                                       const std::string& user_id,
                                       const std::string& device_id,
                                       int64_t up_to_stream_id);
  void delete_all_messages_for_user_txn(LoggingTransaction& txn,
                                         const std::string& user_id);
  void delete_old_messages_txn(LoggingTransaction& txn,
                                int64_t before_stream_id);

  // Stream position tracking
  int64_t get_max_stream_id_txn(LoggingTransaction& txn);
  void set_max_stream_id_txn(LoggingTransaction& txn, int64_t stream_id);
  int64_t get_device_stream_id_txn(LoggingTransaction& txn,
                                    const std::string& user_id,
                                    const std::string& device_id);
  void set_device_stream_id_txn(LoggingTransaction& txn,
                                 const std::string& user_id,
                                 const std::string& device_id,
                                 int64_t stream_id);

  // Counts
  int64_t count_messages_for_user_txn(LoggingTransaction& txn,
                                       const std::string& user_id);
  int64_t count_messages_for_device_txn(LoggingTransaction& txn,
                                         const std::string& user_id,
                                         const std::string& device_id);
  json get_stream_positions_txn(LoggingTransaction& txn,
                                 const std::string& user_id);

  // Batch operations
  void add_messages_bulk_txn(LoggingTransaction& txn,
                              const std::string& user_id,
                              const std::string& device_id,
                              const std::vector<std::pair<std::string, json>>& messages,
                              int64_t base_stream_id);

private:
  DatabasePool& db_;
};

} // namespace progressive

#endif // PROGRESSIVE_ALL_STORES_DECLARED

// ============================================================================
// ============================================================================
// IMPLEMENTATIONS
// ============================================================================
// ============================================================================

namespace progressive {
using storage::DatabasePool;
using storage::LoggingTransaction;
using storage::now_ms;

// ============================================================================
// 1. EventBgUpdatesStore
// ============================================================================

EventBgUpdatesStore::EventBgUpdatesStore(DatabasePool& db) : db_(db) {}

// ---- DDL ----
void EventBgUpdatesStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS event_labels (
      event_id TEXT NOT NULL,
      label TEXT NOT NULL,
      added_ts BIGINT NOT NULL,
      PRIMARY KEY (event_id, label)
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS event_labels_label_idx
      ON event_labels (label);
  )SQL");
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS event_chain_cover (
      room_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      chain_id BIGINT NOT NULL,
      sequence_number BIGINT NOT NULL,
      PRIMARY KEY (room_id, event_id)
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS event_chain_cover_chain_idx
      ON event_chain_cover (room_id, chain_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS rejected_events (
      event_id TEXT NOT NULL PRIMARY KEY,
      reason TEXT NOT NULL,
      rejected_ts BIGINT NOT NULL
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS insertion_events (
      event_id TEXT NOT NULL PRIMARY KEY,
      room_id TEXT NOT NULL,
      next_batch_id TEXT,
      added_ts BIGINT NOT NULL
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS insertion_events_room_idx
      ON insertion_events (room_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS batch_events (
      event_id TEXT NOT NULL PRIMARY KEY,
      room_id TEXT NOT NULL,
      batch_id TEXT NOT NULL,
      added_ts BIGINT NOT NULL
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS batch_events_batch_idx
      ON batch_events (batch_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS batch_events_room_idx
      ON batch_events (room_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS event_bg_updates (
      id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
      update_name TEXT NOT NULL UNIQUE,
      progress_json TEXT,
      completed INTEGER NOT NULL DEFAULT 0,
      created_ts BIGINT NOT NULL,
      completed_ts BIGINT
    );
  )SQL");
}

// ---- Background update tracking ----
void EventBgUpdatesStore::register_background_update_txn(
    LoggingTransaction& txn, const std::string& update_name) {
  txn.execute(
      "INSERT OR IGNORE INTO event_bg_updates (update_name, created_ts) VALUES (?, ?)",
      {update_name, now_ms()});
}

void EventBgUpdatesStore::update_progress_txn(
    LoggingTransaction& txn, const std::string& update_name,
    const json& progress) {
  txn.execute(
      "UPDATE event_bg_updates SET progress_json = ? WHERE update_name = ?",
      {progress.dump(), update_name});
}

void EventBgUpdatesStore::mark_update_complete_txn(
    LoggingTransaction& txn, const std::string& update_name) {
  txn.execute(
      "UPDATE event_bg_updates SET completed = 1, completed_ts = ? WHERE update_name = ?",
      {now_ms(), update_name});
}

json EventBgUpdatesStore::get_pending_updates_txn(LoggingTransaction& txn) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT update_name, progress_json, created_ts "
      "FROM event_bg_updates WHERE completed = 0 ORDER BY created_ts ASC");
  for (auto& row : rows) {
    json u;
    u["update_name"] = row->get<std::string>(0);
    if (!row->is_null(1)) u["progress"] = json::parse(row->get<std::string>(1));
    u["created_ts"] = row->get<int64_t>(2);
    result.push_back(u);
  }
  return result;
}

bool EventBgUpdatesStore::is_update_completed_txn(
    LoggingTransaction& txn, const std::string& update_name) {
  auto row = txn.select_one(
      "SELECT completed FROM event_bg_updates WHERE update_name = ?",
      {update_name});
  return row && !row->is_null() && row->get<int64_t>(0) != 0;
}

// ---- Stats populate ----
void EventBgUpdatesStore::populate_room_stats_txn(LoggingTransaction& txn,
                                                   const std::string& room_id) {
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
  auto state_count = txn.select_one(
      "SELECT COUNT(*) FROM current_state_events WHERE room_id = ?", {room_id});
  auto events_count = txn.select_one(
      "SELECT COUNT(*) FROM events WHERE room_id = ?", {room_id});
  auto forward_ext = txn.select_one(
      "SELECT COUNT(*) FROM event_forward_extremities WHERE room_id = ?", {room_id});
  auto backward_ext = txn.select_one(
      "SELECT COUNT(*) FROM event_backward_extremities WHERE room_id = ?", {room_id});

  int64_t j = joined ? joined->get<int64_t>(0) : 0;
  int64_t i = invited ? invited->get<int64_t>(0) : 0;
  int64_t l = left ? left->get<int64_t>(0) : 0;
  int64_t b = banned ? banned->get<int64_t>(0) : 0;
  int64_t sc = state_count ? state_count->get<int64_t>(0) : 0;
  int64_t ec = events_count ? events_count->get<int64_t>(0) : 0;
  int64_t fe = forward_ext ? forward_ext->get<int64_t>(0) : 0;
  int64_t be = backward_ext ? backward_ext->get<int64_t>(0) : 0;

  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO room_stats_state (room_id, joined_members, invited_members, "
      "left_members, banned_members, state_events, total_events, "
      "forward_extremities, backward_extremities, updated_ts) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT (room_id) DO UPDATE SET "
      "joined_members = excluded.joined_members, "
      "invited_members = excluded.invited_members, "
      "left_members = excluded.left_members, "
      "banned_members = excluded.banned_members, "
      "state_events = excluded.state_events, "
      "total_events = excluded.total_events, "
      "forward_extremities = excluded.forward_extremities, "
      "backward_extremities = excluded.backward_extremities, "
      "updated_ts = excluded.updated_ts",
      {room_id, j, i, l, b, sc, ec, fe, be, ts});
}

void EventBgUpdatesStore::populate_user_stats_txn(LoggingTransaction& txn,
                                                   const std::string& user_id) {
  auto joined_rooms = txn.select_one(
      "SELECT COUNT(*) FROM room_memberships WHERE user_id = ? AND membership = 'join'",
      {user_id});
  auto created_rooms = txn.select_one(
      "SELECT COUNT(*) FROM rooms WHERE creator = ?", {user_id});
  auto events_sent = txn.select_one(
      "SELECT COUNT(*) FROM events WHERE sender = ?", {user_id});
  auto last_seen = txn.select_one(
      "SELECT MAX(last_seen) FROM user_daily_visits WHERE user_id = ?", {user_id});
  auto last_active = txn.select_one(
      "SELECT MAX(timestamp) FROM user_daily_visits WHERE user_id = ?", {user_id});

  int64_t jr = joined_rooms ? joined_rooms->get<int64_t>(0) : 0;
  int64_t cr = created_rooms ? created_rooms->get<int64_t>(0) : 0;
  int64_t es = events_sent ? events_sent->get<int64_t>(0) : 0;
  int64_t ls = (last_seen && !last_seen->is_null()) ? last_seen->get<int64_t>(0) : 0;
  int64_t la = (last_active && !last_active->is_null()) ? last_active->get<int64_t>(0) : 0;

  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO user_stats (user_id, joined_rooms, created_rooms, "
      "total_events_sent, last_seen_ts, active_ts, updated_ts) "
      "VALUES (?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT (user_id) DO UPDATE SET "
      "joined_rooms = excluded.joined_rooms, "
      "created_rooms = excluded.created_rooms, "
      "total_events_sent = excluded.total_events_sent, "
      "last_seen_ts = excluded.last_seen_ts, "
      "active_ts = excluded.active_ts, "
      "updated_ts = excluded.updated_ts",
      {user_id, jr, cr, es, ls, la, ts});
}

json EventBgUpdatesStore::get_room_stats_txn(LoggingTransaction& txn,
                                              const std::string& room_id) {
  json s;
  auto row = txn.select_one(
      "SELECT joined_members, invited_members, left_members, banned_members, "
      "state_events, total_events, forward_extremities, backward_extremities, "
      "updated_ts FROM room_stats_state WHERE room_id = ?",
      {room_id});
  if (row) {
    s["joined_members"] = row->get<int64_t>(0);
    s["invited_members"] = row->get<int64_t>(1);
    s["left_members"] = row->get<int64_t>(2);
    s["banned_members"] = row->get<int64_t>(3);
    s["state_events"] = row->get<int64_t>(4);
    s["total_events"] = row->get<int64_t>(5);
    s["forward_extremities"] = row->get<int64_t>(6);
    s["backward_extremities"] = row->get<int64_t>(7);
    s["updated_ts"] = row->get<int64_t>(8);
  }
  return s;
}

json EventBgUpdatesStore::get_user_stats_txn(LoggingTransaction& txn,
                                              const std::string& user_id) {
  json s;
  auto row = txn.select_one(
      "SELECT joined_rooms, created_rooms, total_events_sent, last_seen_ts, "
      "active_ts, updated_ts FROM user_stats WHERE user_id = ?",
      {user_id});
  if (row) {
    s["joined_rooms"] = row->get<int64_t>(0);
    s["created_rooms"] = row->get<int64_t>(1);
    s["total_events_sent"] = row->get<int64_t>(2);
    s["last_seen_ts"] = row->get<int64_t>(3);
    s["active_ts"] = row->get<int64_t>(4);
    s["updated_ts"] = row->get<int64_t>(5);
  }
  return s;
}

// ---- Event labels ----
void EventBgUpdatesStore::add_event_label_txn(LoggingTransaction& txn,
                                               const std::string& event_id,
                                               const std::string& label) {
  txn.execute(
      "INSERT OR IGNORE INTO event_labels (event_id, label, added_ts) VALUES (?, ?, ?)",
      {event_id, label, now_ms()});
}

void EventBgUpdatesStore::remove_event_label_txn(LoggingTransaction& txn,
                                                  const std::string& event_id,
                                                  const std::string& label) {
  txn.execute("DELETE FROM event_labels WHERE event_id = ? AND label = ?",
              {event_id, label});
}

std::vector<std::string> EventBgUpdatesStore::get_event_labels_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  std::vector<std::string> labels;
  auto rows = txn.select(
      "SELECT label FROM event_labels WHERE event_id = ? ORDER BY added_ts",
      {event_id});
  for (auto& row : rows) {
    labels.push_back(row.get<std::string>(0));
  }
  return labels;
}

std::vector<std::string> EventBgUpdatesStore::get_events_by_label_txn(
    LoggingTransaction& txn, const std::string& label, int limit) {
  std::vector<std::string> events;
  auto rows = txn.select(
      "SELECT event_id FROM event_labels WHERE label = ? ORDER BY added_ts DESC LIMIT ?",
      {label, limit});
  for (auto& row : rows) {
    events.push_back(row.get<std::string>(0));
  }
  return events;
}

// ---- Chain cover index ----
void EventBgUpdatesStore::add_chain_cover_txn(LoggingTransaction& txn,
                                               const std::string& room_id,
                                               const std::string& event_id,
                                               int64_t chain_id,
                                               int64_t sequence_number) {
  txn.execute(
      "INSERT OR REPLACE INTO event_chain_cover (room_id, event_id, chain_id, sequence_number) "
      "VALUES (?, ?, ?, ?)",
      {room_id, event_id, chain_id, sequence_number});
}

std::optional<int64_t> EventBgUpdatesStore::get_chain_id_for_event_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& event_id) {
  auto row = txn.select_one(
      "SELECT chain_id FROM event_chain_cover WHERE room_id = ? AND event_id = ?",
      {room_id, event_id});
  if (row && !row->is_null()) return row->get<int64_t>(0);
  return std::nullopt;
}

std::vector<std::string> EventBgUpdatesStore::get_events_in_chain_txn(
    LoggingTransaction& txn, const std::string& room_id, int64_t chain_id,
    int64_t limit) {
  std::vector<std::string> events;
  auto rows = txn.select(
      "SELECT event_id FROM event_chain_cover WHERE room_id = ? AND chain_id = ? "
      "ORDER BY sequence_number ASC LIMIT ?",
      {room_id, chain_id, limit});
  for (auto& row : rows) {
    events.push_back(row.get<std::string>(0));
  }
  return events;
}

void EventBgUpdatesStore::delete_chain_cover_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  txn.execute("DELETE FROM event_chain_cover WHERE room_id = ?", {room_id});
}

// ---- Rejection index ----
void EventBgUpdatesStore::reject_event_txn(LoggingTransaction& txn,
                                            const std::string& event_id,
                                            const std::string& reason) {
  txn.execute(
      "INSERT OR REPLACE INTO rejected_events (event_id, reason, rejected_ts) "
      "VALUES (?, ?, ?)",
      {event_id, reason, now_ms()});
}

std::optional<std::string> EventBgUpdatesStore::get_rejection_reason_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  auto row = txn.select_one(
      "SELECT reason FROM rejected_events WHERE event_id = ?", {event_id});
  if (row && !row->is_null()) return row->get<std::string>(0);
  return std::nullopt;
}

bool EventBgUpdatesStore::is_event_rejected_txn(LoggingTransaction& txn,
                                                 const std::string& event_id) {
  auto row = txn.select_one(
      "SELECT 1 FROM rejected_events WHERE event_id = ?", {event_id});
  return row && !row->is_null();
}

void EventBgUpdatesStore::unreject_event_txn(LoggingTransaction& txn,
                                              const std::string& event_id) {
  txn.execute("DELETE FROM rejected_events WHERE event_id = ?", {event_id});
}

std::vector<std::string> EventBgUpdatesStore::get_rejected_events_txn(
    LoggingTransaction& txn, int limit) {
  std::vector<std::string> events;
  auto rows = txn.select(
      "SELECT event_id FROM rejected_events ORDER BY rejected_ts DESC LIMIT ?",
      {limit});
  for (auto& row : rows) {
    events.push_back(row.get<std::string>(0));
  }
  return events;
}

// ---- MSC2716 batch/insertion events ----
void EventBgUpdatesStore::add_insertion_event_txn(LoggingTransaction& txn,
                                                   const std::string& event_id,
                                                   const std::string& room_id,
                                                   const std::string& next_batch_id) {
  txn.execute(
      "INSERT OR REPLACE INTO insertion_events (event_id, room_id, next_batch_id, added_ts) "
      "VALUES (?, ?, ?, ?)",
      {event_id, room_id, next_batch_id, now_ms()});
}

void EventBgUpdatesStore::add_batch_event_txn(LoggingTransaction& txn,
                                               const std::string& event_id,
                                               const std::string& room_id,
                                               const std::string& batch_id) {
  txn.execute(
      "INSERT OR REPLACE INTO batch_events (event_id, room_id, batch_id, added_ts) "
      "VALUES (?, ?, ?, ?)",
      {event_id, room_id, batch_id, now_ms()});
}

std::optional<std::string>
EventBgUpdatesStore::get_next_batch_id_for_insertion_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  auto row = txn.select_one(
      "SELECT next_batch_id FROM insertion_events WHERE event_id = ?", {event_id});
  if (row && !row->is_null() && !row->get<std::string>(0).empty())
    return row->get<std::string>(0);
  return std::nullopt;
}

std::vector<std::string> EventBgUpdatesStore::get_batch_events_txn(
    LoggingTransaction& txn, const std::string& batch_id, int limit) {
  std::vector<std::string> events;
  auto rows = txn.select(
      "SELECT event_id FROM batch_events WHERE batch_id = ? ORDER BY added_ts ASC LIMIT ?",
      {batch_id, limit});
  for (auto& row : rows) {
    events.push_back(row.get<std::string>(0));
  }
  return events;
}

void EventBgUpdatesStore::remove_insertion_event_txn(LoggingTransaction& txn,
                                                      const std::string& event_id) {
  txn.execute("DELETE FROM insertion_events WHERE event_id = ?", {event_id});
}

void EventBgUpdatesStore::remove_batch_events_txn(LoggingTransaction& txn,
                                                   const std::string& batch_id) {
  txn.execute("DELETE FROM batch_events WHERE batch_id = ?", {batch_id});
}

// ============================================================================
// 2. SlidingSyncStore
// ============================================================================

SlidingSyncStore::SlidingSyncStore(DatabasePool& db) : db_(db) {}

void SlidingSyncStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS sliding_sync_joined_rooms (
      room_id TEXT NOT NULL PRIMARY KEY,
      bump_stamp BIGINT NOT NULL DEFAULT 0,
      room_type TEXT,
      is_encrypted INTEGER,
      room_name TEXT,
      tombstone_successor_room_id TEXT,
      created_ts BIGINT NOT NULL DEFAULT 0,
      updated_ts BIGINT NOT NULL DEFAULT 0
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS ss_joined_rooms_bump_idx
      ON sliding_sync_joined_rooms (bump_stamp DESC);
  )SQL");

  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS sliding_sync_membership_snapshots (
      room_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      sender TEXT NOT NULL,
      membership_event_id TEXT NOT NULL,
      membership TEXT NOT NULL,
      has_known_state INTEGER,
      room_type TEXT,
      is_encrypted INTEGER,
      room_name TEXT,
      forgotten INTEGER NOT NULL DEFAULT 0,
      created_ts BIGINT NOT NULL DEFAULT 0,
      updated_ts BIGINT NOT NULL DEFAULT 0,
      PRIMARY KEY (room_id, user_id)
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS ss_membership_user_idx
      ON sliding_sync_membership_snapshots (user_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS ss_membership_membership_idx
      ON sliding_sync_membership_snapshots (user_id, membership);
  )SQL");

  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS sliding_sync_states (
      user_id TEXT NOT NULL,
      conn_id TEXT NOT NULL,
      pos BIGINT NOT NULL DEFAULT 0,
      ranges TEXT,
      extensions_json TEXT,
      lists TEXT,
      subscriptions TEXT,
      filters TEXT,
      initial INTEGER NOT NULL DEFAULT 1,
      created_ts BIGINT NOT NULL DEFAULT 0,
      last_updated_ts BIGINT NOT NULL DEFAULT 0,
      PRIMARY KEY (user_id, conn_id)
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS ss_states_ts_idx
      ON sliding_sync_states (last_updated_ts);
  )SQL");
}

// --- joined_rooms ---
void SlidingSyncStore::add_joined_room_txn(
    LoggingTransaction& txn, const std::string& room_id, int64_t bump_stamp,
    const std::optional<std::string>& room_type,
    const std::optional<bool>& is_encrypted,
    const std::optional<std::string>& room_name,
    const std::optional<std::string>& tombstone) {
  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO sliding_sync_joined_rooms "
      "(room_id, bump_stamp, room_type, is_encrypted, room_name, "
      "tombstone_successor_room_id, created_ts, updated_ts) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT (room_id) DO UPDATE SET "
      "bump_stamp = MAX(bump_stamp, excluded.bump_stamp), "
      "room_type = COALESCE(excluded.room_type, room_type), "
      "is_encrypted = COALESCE(excluded.is_encrypted, is_encrypted), "
      "room_name = COALESCE(excluded.room_name, room_name), "
      "tombstone_successor_room_id = COALESCE(excluded.tombstone_successor_room_id, "
      "  tombstone_successor_room_id), "
      "updated_ts = excluded.updated_ts",
      {room_id, bump_stamp,
       room_type.value_or(""),
       is_encrypted ? (is_encrypted.value() ? 1 : 0) : int64_t(-1),
       room_name.value_or(""),
       tombstone.value_or(""),
       ts, ts});
}

void SlidingSyncStore::remove_joined_room_txn(LoggingTransaction& txn,
                                               const std::string& room_id) {
  txn.execute("DELETE FROM sliding_sync_joined_rooms WHERE room_id = ?", {room_id});
}

void SlidingSyncStore::update_joined_room_bump_stamp_txn(
    LoggingTransaction& txn, const std::string& room_id, int64_t bump_stamp) {
  txn.execute(
      "UPDATE sliding_sync_joined_rooms SET bump_stamp = ?, updated_ts = ? "
      "WHERE room_id = ?",
      {bump_stamp, now_ms(), room_id});
}

json SlidingSyncStore::get_joined_room_txn(LoggingTransaction& txn,
                                            const std::string& room_id) {
  json r;
  auto row = txn.select_one(
      "SELECT room_id, bump_stamp, room_type, is_encrypted, room_name, "
      "tombstone_successor_room_id, created_ts, updated_ts "
      "FROM sliding_sync_joined_rooms WHERE room_id = ?",
      {room_id});
  if (row) {
    r["room_id"] = row->get<std::string>(0);
    r["bump_stamp"] = row->get<int64_t>(1);
    if (!row->is_null(2)) r["room_type"] = row->get<std::string>(2);
    if (!row->is_null(3)) r["is_encrypted"] = row->get<int64_t>(3) != 0;
    if (!row->is_null(4)) r["room_name"] = row->get<std::string>(4);
    if (!row->is_null(5)) r["tombstone_successor_room_id"] = row->get<std::string>(5);
    r["created_ts"] = row->get<int64_t>(6);
    r["updated_ts"] = row->get<int64_t>(7);
  }
  return r;
}

json SlidingSyncStore::get_all_joined_rooms_txn(LoggingTransaction& txn,
                                                 int64_t from_bump_stamp,
                                                 int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, bump_stamp, room_type, is_encrypted, room_name, "
      "tombstone_successor_room_id, created_ts, updated_ts "
      "FROM sliding_sync_joined_rooms WHERE bump_stamp > ? "
      "ORDER BY bump_stamp DESC LIMIT ?",
      {from_bump_stamp, limit});
  for (auto& row : rows) {
    json r;
    r["room_id"] = row->get<std::string>(0);
    r["bump_stamp"] = row->get<int64_t>(1);
    if (!row->is_null(2)) r["room_type"] = row->get<std::string>(2);
    if (!row->is_null(3)) r["is_encrypted"] = row->get<int64_t>(3) != 0;
    if (!row->is_null(4)) r["room_name"] = row->get<std::string>(4);
    if (!row->is_null(5)) r["tombstone_successor_room_id"] = row->get<std::string>(5);
    r["created_ts"] = row->get<int64_t>(6);
    r["updated_ts"] = row->get<int64_t>(7);
    result.push_back(r);
  }
  return result;
}

int64_t SlidingSyncStore::count_joined_rooms_txn(LoggingTransaction& txn) {
  auto row = txn.select_one("SELECT COUNT(*) FROM sliding_sync_joined_rooms");
  return row ? row->get<int64_t>(0) : 0;
}

bool SlidingSyncStore::is_joined_room_txn(LoggingTransaction& txn,
                                           const std::string& room_id) {
  auto row = txn.select_one(
      "SELECT 1 FROM sliding_sync_joined_rooms WHERE room_id = ?", {room_id});
  return row && !row->is_null();
}

// --- membership_snapshots ---
void SlidingSyncStore::add_membership_snapshot_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& user_id, const std::string& sender,
    const std::string& membership_event_id, const std::string& membership,
    const std::optional<bool>& has_known_state,
    const std::optional<std::string>& room_type,
    const std::optional<bool>& is_encrypted,
    const std::optional<std::string>& room_name) {
  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO sliding_sync_membership_snapshots "
      "(room_id, user_id, sender, membership_event_id, membership, "
      "has_known_state, room_type, is_encrypted, room_name, created_ts, updated_ts) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT (room_id, user_id) DO UPDATE SET "
      "sender = excluded.sender, "
      "membership_event_id = excluded.membership_event_id, "
      "membership = excluded.membership, "
      "has_known_state = COALESCE(excluded.has_known_state, has_known_state), "
      "room_type = COALESCE(excluded.room_type, room_type), "
      "is_encrypted = COALESCE(excluded.is_encrypted, is_encrypted), "
      "room_name = COALESCE(excluded.room_name, room_name), "
      "updated_ts = excluded.updated_ts",
      {room_id, user_id, sender, membership_event_id, membership,
       has_known_state ? (has_known_state.value() ? 1 : 0) : int64_t(-1),
       room_type.value_or(""),
       is_encrypted ? (is_encrypted.value() ? 1 : 0) : int64_t(-1),
       room_name.value_or(""),
       ts, ts});
}

void SlidingSyncStore::update_membership_snapshot_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& user_id, const std::string& membership) {
  txn.execute(
      "UPDATE sliding_sync_membership_snapshots SET membership = ?, updated_ts = ? "
      "WHERE room_id = ? AND user_id = ?",
      {membership, now_ms(), room_id, user_id});
}

void SlidingSyncStore::remove_membership_snapshot_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& user_id) {
  txn.execute(
      "DELETE FROM sliding_sync_membership_snapshots WHERE room_id = ? AND user_id = ?",
      {room_id, user_id});
}

json SlidingSyncStore::get_membership_snapshot_txn(LoggingTransaction& txn,
                                                    const std::string& room_id,
                                                    const std::string& user_id) {
  json r;
  auto row = txn.select_one(
      "SELECT room_id, sender, membership_event_id, membership, has_known_state, "
      "room_type, is_encrypted, room_name, forgotten, created_ts, updated_ts "
      "FROM sliding_sync_membership_snapshots WHERE room_id = ? AND user_id = ?",
      {room_id, user_id});
  if (row) {
    r["room_id"] = row->get<std::string>(0);
    r["sender"] = row->get<std::string>(1);
    r["membership_event_id"] = row->get<std::string>(2);
    r["membership"] = row->get<std::string>(3);
    if (!row->is_null(4)) r["has_known_state"] = row->get<int64_t>(4) != 0;
    if (!row->is_null(5)) r["room_type"] = row->get<std::string>(5);
    if (!row->is_null(6)) r["is_encrypted"] = row->get<int64_t>(6) != 0;
    if (!row->is_null(7)) r["room_name"] = row->get<std::string>(7);
    r["forgotten"] = row->get<int64_t>(8) != 0;
    r["created_ts"] = row->get<int64_t>(9);
    r["updated_ts"] = row->get<int64_t>(10);
  }
  return r;
}

json SlidingSyncStore::get_membership_snapshots_for_user_txn(
    LoggingTransaction& txn, const std::string& user_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, sender, membership_event_id, membership, has_known_state, "
      "room_type, is_encrypted, room_name, forgotten, created_ts, updated_ts "
      "FROM sliding_sync_membership_snapshots WHERE user_id = ? "
      "ORDER BY updated_ts DESC LIMIT ?",
      {user_id, limit});
  for (auto& row : rows) {
    json s;
    s["room_id"] = row->get<std::string>(0);
    s["sender"] = row->get<std::string>(1);
    s["membership_event_id"] = row->get<std::string>(2);
    s["membership"] = row->get<std::string>(3);
    if (!row->is_null(4)) s["has_known_state"] = row->get<int64_t>(4) != 0;
    if (!row->is_null(5)) s["room_type"] = row->get<std::string>(5);
    if (!row->is_null(6)) s["is_encrypted"] = row->get<int64_t>(6) != 0;
    if (!row->is_null(7)) s["room_name"] = row->get<std::string>(7);
    s["forgotten"] = row->get<int64_t>(8) != 0;
    s["created_ts"] = row->get<int64_t>(9);
    s["updated_ts"] = row->get<int64_t>(10);
    result.push_back(s);
  }
  return result;
}

json SlidingSyncStore::get_membership_snapshots_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, user_id, sender, membership_event_id, membership, "
      "has_known_state, room_type, is_encrypted, room_name, forgotten, "
      "created_ts, updated_ts "
      "FROM sliding_sync_membership_snapshots WHERE room_id = ? "
      "ORDER BY updated_ts DESC LIMIT ?",
      {room_id, limit});
  for (auto& row : rows) {
    json s;
    s["room_id"] = row->get<std::string>(0);
    s["user_id"] = row->get<std::string>(1);
    s["sender"] = row->get<std::string>(2);
    s["membership_event_id"] = row->get<std::string>(3);
    s["membership"] = row->get<std::string>(4);
    if (!row->is_null(5)) s["has_known_state"] = row->get<int64_t>(5) != 0;
    if (!row->is_null(6)) s["room_type"] = row->get<std::string>(6);
    if (!row->is_null(7)) s["is_encrypted"] = row->get<int64_t>(7) != 0;
    if (!row->is_null(8)) s["room_name"] = row->get<std::string>(8);
    s["forgotten"] = row->get<int64_t>(9) != 0;
    s["created_ts"] = row->get<int64_t>(10);
    s["updated_ts"] = row->get<int64_t>(11);
    result.push_back(s);
  }
  return result;
}

void SlidingSyncStore::mark_forgotten_txn(LoggingTransaction& txn,
                                           const std::string& room_id,
                                           const std::string& user_id,
                                           bool forgotten) {
  txn.execute(
      "UPDATE sliding_sync_membership_snapshots SET forgotten = ?, updated_ts = ? "
      "WHERE room_id = ? AND user_id = ?",
      {forgotten ? 1 : 0, now_ms(), room_id, user_id});
}

int64_t SlidingSyncStore::count_membership_snapshots_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM sliding_sync_membership_snapshots WHERE user_id = ?",
      {user_id});
  return row ? row->get<int64_t>(0) : 0;
}

// --- sync_state ---
void SlidingSyncStore::store_sync_state_txn(LoggingTransaction& txn,
                                             const std::string& user_id,
                                             const std::string& conn_id,
                                             int64_t pos,
                                             const std::string& ranges,
                                             const json& extensions) {
  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO sliding_sync_states "
      "(user_id, conn_id, pos, ranges, extensions_json, created_ts, last_updated_ts) "
      "VALUES (?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT (user_id, conn_id) DO UPDATE SET "
      "pos = excluded.pos, ranges = excluded.ranges, "
      "extensions_json = excluded.extensions_json, "
      "last_updated_ts = excluded.last_updated_ts",
      {user_id, conn_id, pos, ranges, extensions.dump(), ts, ts});
}

json SlidingSyncStore::get_sync_state_txn(LoggingTransaction& txn,
                                           const std::string& user_id,
                                           const std::string& conn_id) {
  json r;
  auto row = txn.select_one(
      "SELECT user_id, conn_id, pos, ranges, extensions_json, lists, subscriptions, "
      "filters, initial, created_ts, last_updated_ts "
      "FROM sliding_sync_states WHERE user_id = ? AND conn_id = ?",
      {user_id, conn_id});
  if (row) {
    r["user_id"] = row->get<std::string>(0);
    r["conn_id"] = row->get<std::string>(1);
    r["pos"] = row->get<int64_t>(2);
    if (!row->is_null(3)) r["ranges"] = row->get<std::string>(3);
    if (!row->is_null(4)) r["extensions"] = json::parse(row->get<std::string>(4));
    if (!row->is_null(5)) r["lists"] = row->get<std::string>(5);
    if (!row->is_null(6)) r["subscriptions"] = row->get<std::string>(6);
    if (!row->is_null(7)) r["filters"] = row->get<std::string>(7);
    r["initial"] = row->get<int64_t>(8) != 0;
    r["created_ts"] = row->get<int64_t>(9);
    r["last_updated_ts"] = row->get<int64_t>(10);
  }
  return r;
}

void SlidingSyncStore::delete_sync_state_txn(LoggingTransaction& txn,
                                              const std::string& user_id,
                                              const std::string& conn_id) {
  txn.execute(
      "DELETE FROM sliding_sync_states WHERE user_id = ? AND conn_id = ?",
      {user_id, conn_id});
}

void SlidingSyncStore::delete_old_sync_states_txn(LoggingTransaction& txn,
                                                   int64_t before_ts) {
  txn.execute("DELETE FROM sliding_sync_states WHERE last_updated_ts < ?",
              {before_ts});
}

json SlidingSyncStore::get_all_sync_states_for_user_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT user_id, conn_id, pos, ranges, extensions_json, lists, subscriptions, "
      "filters, initial, created_ts, last_updated_ts "
      "FROM sliding_sync_states WHERE user_id = ? ORDER BY last_updated_ts DESC",
      {user_id});
  for (auto& row : rows) {
    json s;
    s["user_id"] = row->get<std::string>(0);
    s["conn_id"] = row->get<std::string>(1);
    s["pos"] = row->get<int64_t>(2);
    if (!row->is_null(3)) s["ranges"] = row->get<std::string>(3);
    if (!row->is_null(4)) s["extensions"] = json::parse(row->get<std::string>(4));
    if (!row->is_null(5)) s["lists"] = row->get<std::string>(5);
    if (!row->is_null(6)) s["subscriptions"] = row->get<std::string>(6);
    if (!row->is_null(7)) s["filters"] = row->get<std::string>(7);
    s["initial"] = row->get<int64_t>(8) != 0;
    s["created_ts"] = row->get<int64_t>(9);
    s["last_updated_ts"] = row->get<int64_t>(10);
    result.push_back(s);
  }
  return result;
}

// ============================================================================
// 3. UserDirectoryStore
// ============================================================================

UserDirectoryStore::UserDirectoryStore(DatabasePool& db) : db_(db) {}

void UserDirectoryStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS user_directory (
      user_id TEXT NOT NULL PRIMARY KEY,
      display_name TEXT,
      avatar_url TEXT,
      created_ts BIGINT NOT NULL DEFAULT 0,
      updated_ts BIGINT NOT NULL DEFAULT 0
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS user_directory_name_idx
      ON user_directory (display_name);
  )SQL");

  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS user_directory_search (
      user_id TEXT NOT NULL,
      token TEXT NOT NULL,
      PRIMARY KEY (user_id, token)
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS user_directory_search_token_idx
      ON user_directory_search (token);
  )SQL");

  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS user_directory_rooms (
      user_id TEXT NOT NULL,
      room_id TEXT NOT NULL,
      added_ts BIGINT NOT NULL,
      PRIMARY KEY (user_id, room_id)
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS user_directory_rooms_room_idx
      ON user_directory_rooms (room_id);
  )SQL");
}

void UserDirectoryStore::add_user_txn(LoggingTransaction& txn,
                                       const std::string& user_id,
                                       const std::string& display_name,
                                       const std::optional<std::string>& avatar_url) {
  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO user_directory (user_id, display_name, avatar_url, created_ts, updated_ts) "
      "VALUES (?, ?, ?, ?, ?) "
      "ON CONFLICT (user_id) DO UPDATE SET "
      "display_name = COALESCE(excluded.display_name, user_directory.display_name), "
      "avatar_url = COALESCE(excluded.avatar_url, user_directory.avatar_url), "
      "updated_ts = excluded.updated_ts",
      {user_id, display_name, avatar_url.value_or(""), ts, ts});

  // Tokenize display_name for search
  std::string search = display_name;
  std::string token;
  for (char c : search) {
    if (c == ' ' || c == '_' || c == '-') {
      if (!token.empty()) {
        txn.execute(
            "INSERT OR IGNORE INTO user_directory_search (user_id, token) VALUES (?, ?)",
            {user_id, token});
        token.clear();
      }
    } else {
      token += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
  }
  if (!token.empty()) {
    txn.execute(
        "INSERT OR IGNORE INTO user_directory_search (user_id, token) VALUES (?, ?)",
        {user_id, token});
  }
  // Also add the full display name as a token
  txn.execute(
      "INSERT OR IGNORE INTO user_directory_search (user_id, token) VALUES (?, ?)",
      {user_id, display_name});
}

void UserDirectoryStore::update_user_txn(LoggingTransaction& txn,
                                          const std::string& user_id,
                                          const std::string& display_name,
                                          const std::optional<std::string>& avatar_url) {
  int64_t ts = now_ms();
  txn.execute(
      "UPDATE user_directory SET display_name = ?, avatar_url = ?, updated_ts = ? "
      "WHERE user_id = ?",
      {display_name, avatar_url.value_or(""), ts, user_id});
  // Rebuild search tokens
  txn.execute("DELETE FROM user_directory_search WHERE user_id = ?", {user_id});
  std::string token;
  for (char c : display_name) {
    if (c == ' ' || c == '_' || c == '-') {
      if (!token.empty()) {
        txn.execute(
            "INSERT OR IGNORE INTO user_directory_search (user_id, token) VALUES (?, ?)",
            {user_id, token});
        token.clear();
      }
    } else {
      token += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
  }
  if (!token.empty()) {
    txn.execute(
        "INSERT OR IGNORE INTO user_directory_search (user_id, token) VALUES (?, ?)",
        {user_id, token});
  }
  txn.execute(
      "INSERT OR IGNORE INTO user_directory_search (user_id, token) VALUES (?, ?)",
      {user_id, display_name});
}

void UserDirectoryStore::remove_user_txn(LoggingTransaction& txn,
                                          const std::string& user_id) {
  txn.execute("DELETE FROM user_directory_search WHERE user_id = ?", {user_id});
  txn.execute("DELETE FROM user_directory_rooms WHERE user_id = ?", {user_id});
  txn.execute("DELETE FROM user_directory WHERE user_id = ?", {user_id});
}

std::optional<json> UserDirectoryStore::get_user_txn(LoggingTransaction& txn,
                                                      const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT user_id, display_name, avatar_url, created_ts, updated_ts "
      "FROM user_directory WHERE user_id = ?",
      {user_id});
  if (row) {
    json u;
    u["user_id"] = row->get<std::string>(0);
    if (!row->is_null(1)) u["display_name"] = row->get<std::string>(1);
    if (!row->is_null(2)) u["avatar_url"] = row->get<std::string>(2);
    u["created_ts"] = row->get<int64_t>(3);
    u["updated_ts"] = row->get<int64_t>(4);
    return u;
  }
  return std::nullopt;
}

json UserDirectoryStore::search_users_txn(LoggingTransaction& txn,
                                           const std::string& search_term,
                                           int limit) {
  json result = json::array();
  std::string like_term = "%" + search_term + "%";
  auto rows = txn.select(
      "SELECT ud.user_id, ud.display_name, ud.avatar_url, "
      "COUNT(udr.room_id) as shared_rooms "
      "FROM user_directory ud "
      "LEFT JOIN user_directory_rooms udr ON ud.user_id = udr.user_id "
      "WHERE ud.display_name LIKE ? OR ud.user_id LIKE ? "
      "GROUP BY ud.user_id "
      "ORDER BY shared_rooms DESC, ud.updated_ts DESC "
      "LIMIT ?",
      {like_term, like_term, limit});
  for (auto& row : rows) {
    json u;
    u["user_id"] = row->get<std::string>(0);
    u["display_name"] = row->get<std::string>(1);
    if (!row->is_null(2)) u["avatar_url"] = row->get<std::string>(2);
    u["shared_rooms"] = row->get<int64_t>(3);
    result.push_back(u);
  }
  return result;
}

json UserDirectoryStore::search_users_in_public_rooms_txn(
    LoggingTransaction& txn, const std::string& search_term,
    const std::string& requesting_user_id, int limit) {
  json result = json::array();
  std::string like_term = "%" + search_term + "%";
  auto rows = txn.select(
      "SELECT DISTINCT ud.user_id, ud.display_name, ud.avatar_url "
      "FROM user_directory ud "
      "JOIN user_directory_rooms udr ON ud.user_id = udr.user_id "
      "JOIN rooms r ON udr.room_id = r.room_id "
      "WHERE r.is_public = 1 "
      "AND (ud.display_name LIKE ? OR ud.user_id LIKE ?) "
      "AND ud.user_id != ? "
      "LIMIT ?",
      {like_term, like_term, requesting_user_id, limit});
  for (auto& row : rows) {
    json u;
    u["user_id"] = row->get<std::string>(0);
    u["display_name"] = row->get<std::string>(1);
    if (!row->is_null(2)) u["avatar_url"] = row->get<std::string>(2);
    result.push_back(u);
  }
  return result;
}

int64_t UserDirectoryStore::count_shared_rooms_txn(LoggingTransaction& txn,
                                                    const std::string& user_id_a,
                                                    const std::string& user_id_b) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM user_directory_rooms a "
      "JOIN user_directory_rooms b ON a.room_id = b.room_id "
      "WHERE a.user_id = ? AND b.user_id = ?",
      {user_id_a, user_id_b});
  return row ? row->get<int64_t>(0) : 0;
}

json UserDirectoryStore::get_users_with_shared_rooms_txn(
    LoggingTransaction& txn, const std::string& user_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT ud.user_id, ud.display_name, ud.avatar_url, "
      "COUNT(shared.room_id) as shared_count "
      "FROM user_directory ud "
      "JOIN user_directory_rooms mine ON mine.user_id = ? "
      "JOIN user_directory_rooms shared ON mine.room_id = shared.room_id "
      "AND shared.user_id = ud.user_id "
      "WHERE ud.user_id != ? "
      "GROUP BY ud.user_id "
      "ORDER BY shared_count DESC, ud.updated_ts DESC "
      "LIMIT ?",
      {user_id, user_id, limit});
  for (auto& row : rows) {
    json u;
    u["user_id"] = row->get<std::string>(0);
    u["display_name"] = row->get<std::string>(1);
    if (!row->is_null(2)) u["avatar_url"] = row->get<std::string>(2);
    u["shared_rooms"] = row->get<int64_t>(3);
    result.push_back(u);
  }
  return result;
}

void UserDirectoryStore::add_user_to_room_txn(LoggingTransaction& txn,
                                               const std::string& user_id,
                                               const std::string& room_id) {
  txn.execute(
      "INSERT OR IGNORE INTO user_directory_rooms (user_id, room_id, added_ts) "
      "VALUES (?, ?, ?)",
      {user_id, room_id, now_ms()});
}

void UserDirectoryStore::remove_user_from_room_txn(LoggingTransaction& txn,
                                                    const std::string& user_id,
                                                    const std::string& room_id) {
  txn.execute(
      "DELETE FROM user_directory_rooms WHERE user_id = ? AND room_id = ?",
      {user_id, room_id});
}

json UserDirectoryStore::get_users_in_room_txn(LoggingTransaction& txn,
                                                const std::string& room_id,
                                                int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT ud.user_id, ud.display_name, ud.avatar_url "
      "FROM user_directory ud "
      "JOIN user_directory_rooms udr ON ud.user_id = udr.user_id "
      "WHERE udr.room_id = ? "
      "ORDER BY ud.display_name ASC LIMIT ?",
      {room_id, limit});
  for (auto& row : rows) {
    json u;
    u["user_id"] = row->get<std::string>(0);
    if (!row->is_null(1)) u["display_name"] = row->get<std::string>(1);
    if (!row->is_null(2)) u["avatar_url"] = row->get<std::string>(2);
    result.push_back(u);
  }
  return result;
}

json UserDirectoryStore::get_rooms_for_user_txn(LoggingTransaction& txn,
                                                 const std::string& user_id,
                                                 int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT udr.room_id, r.room_name, r.is_public "
      "FROM user_directory_rooms udr "
      "LEFT JOIN rooms r ON udr.room_id = r.room_id "
      "WHERE udr.user_id = ? "
      "ORDER BY udr.added_ts DESC LIMIT ?",
      {user_id, limit});
  for (auto& row : rows) {
    json r;
    r["room_id"] = row->get<std::string>(0);
    if (!row->is_null(1)) r["room_name"] = row->get<std::string>(1);
    if (!row->is_null(2)) r["is_public"] = row->get<int64_t>(2) != 0;
    result.push_back(r);
  }
  return result;
}

void UserDirectoryStore::rebuild_directory_txn(LoggingTransaction& txn) {
  // Clear existing search data
  txn.execute("DELETE FROM user_directory_search");
  txn.execute("DELETE FROM user_directory_rooms");
  txn.execute("DELETE FROM user_directory");

  // Repopulate from users table
  auto users = txn.select(
      "SELECT name, display_name, avatar_url FROM users WHERE deactivated = 0 AND is_guest = 0");
  for (auto& row : users) {
    std::string uid = row->get<std::string>(0);
    std::string dn = row->get<std::string>(1);
    std::string av = (!row->is_null(2)) ? row->get<std::string>(2) : "";
    int64_t ts = now_ms();
    txn.execute(
        "INSERT INTO user_directory (user_id, display_name, avatar_url, created_ts, updated_ts) "
        "VALUES (?, ?, ?, ?, ?)",
        {uid, dn, av, ts, ts});
    // Tokenize for search
    std::string token;
    for (char c : dn) {
      if (c == ' ' || c == '_' || c == '-') {
        if (!token.empty()) {
          txn.execute(
              "INSERT OR IGNORE INTO user_directory_search (user_id, token) VALUES (?, ?)",
              {uid, token});
          token.clear();
        }
      } else {
        token += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
    }
    if (!token.empty()) {
      txn.execute(
          "INSERT OR IGNORE INTO user_directory_search (user_id, token) VALUES (?, ?)",
          {uid, token});
    }
    txn.execute(
        "INSERT OR IGNORE INTO user_directory_search (user_id, token) VALUES (?, ?)",
        {uid, dn});
  }

  // Populate user_directory_rooms from room_memberships
  auto memberships = txn.select(
      "SELECT user_id, room_id FROM room_memberships WHERE membership = 'join'");
  for (auto& row : memberships) {
    txn.execute(
        "INSERT OR IGNORE INTO user_directory_rooms (user_id, room_id, added_ts) "
        "VALUES (?, ?, ?)",
        {row->get<std::string>(0), row->get<std::string>(1), now_ms()});
  }
}

void UserDirectoryStore::delete_all_from_room_txn(LoggingTransaction& txn,
                                                   const std::string& room_id) {
  txn.execute("DELETE FROM user_directory_rooms WHERE room_id = ?", {room_id});
}

int64_t UserDirectoryStore::count_directory_users_txn(LoggingTransaction& txn) {
  auto row = txn.select_one("SELECT COUNT(*) FROM user_directory");
  return row ? row->get<int64_t>(0) : 0;
}

// ============================================================================
// 4. ThreadSubscriptionsStore
// ============================================================================

ThreadSubscriptionsStore::ThreadSubscriptionsStore(DatabasePool& db) : db_(db) {}

void ThreadSubscriptionsStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS thread_subscriptions (
      user_id TEXT NOT NULL,
      room_id TEXT NOT NULL,
      thread_id TEXT NOT NULL,
      subscribed_ts BIGINT NOT NULL,
      PRIMARY KEY (user_id, thread_id)
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS thread_sub_user_idx
      ON thread_subscriptions (user_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS thread_sub_thread_idx
      ON thread_subscriptions (thread_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS thread_sub_room_user_idx
      ON thread_subscriptions (room_id, user_id);
  )SQL");
}

void ThreadSubscriptionsStore::subscribe_txn(LoggingTransaction& txn,
                                              const std::string& user_id,
                                              const std::string& room_id,
                                              const std::string& thread_id) {
  txn.execute(
      "INSERT OR IGNORE INTO thread_subscriptions (user_id, room_id, thread_id, subscribed_ts) "
      "VALUES (?, ?, ?, ?)",
      {user_id, room_id, thread_id, now_ms()});
}

void ThreadSubscriptionsStore::unsubscribe_txn(LoggingTransaction& txn,
                                                const std::string& user_id,
                                                const std::string& thread_id) {
  txn.execute(
      "DELETE FROM thread_subscriptions WHERE user_id = ? AND thread_id = ?",
      {user_id, thread_id});
}

bool ThreadSubscriptionsStore::is_subscribed_txn(LoggingTransaction& txn,
                                                  const std::string& user_id,
                                                  const std::string& thread_id) {
  auto row = txn.select_one(
      "SELECT 1 FROM thread_subscriptions WHERE user_id = ? AND thread_id = ?",
      {user_id, thread_id});
  return row && !row->is_null();
}

json ThreadSubscriptionsStore::get_subscriptions_for_user_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, thread_id, subscribed_ts FROM thread_subscriptions "
      "WHERE user_id = ? ORDER BY subscribed_ts DESC",
      {user_id});
  for (auto& row : rows) {
    json s;
    s["room_id"] = row->get<std::string>(0);
    s["thread_id"] = row->get<std::string>(1);
    s["subscribed_ts"] = row->get<int64_t>(2);
    result.push_back(s);
  }
  return result;
}

json ThreadSubscriptionsStore::get_subscriptions_for_room_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& room_id) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT thread_id, subscribed_ts FROM thread_subscriptions "
      "WHERE user_id = ? AND room_id = ? ORDER BY subscribed_ts DESC",
      {user_id, room_id});
  for (auto& row : rows) {
    json s;
    s["thread_id"] = row->get<std::string>(0);
    s["subscribed_ts"] = row->get<int64_t>(1);
    result.push_back(s);
  }
  return result;
}

json ThreadSubscriptionsStore::get_subscribers_for_thread_txn(
    LoggingTransaction& txn, const std::string& thread_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT user_id, room_id, subscribed_ts FROM thread_subscriptions "
      "WHERE thread_id = ? ORDER BY subscribed_ts DESC LIMIT ?",
      {thread_id, limit});
  for (auto& row : rows) {
    json s;
    s["user_id"] = row->get<std::string>(0);
    s["room_id"] = row->get<std::string>(1);
    s["subscribed_ts"] = row->get<int64_t>(2);
    result.push_back(s);
  }
  return result;
}

void ThreadSubscriptionsStore::unsubscribe_all_in_room_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& room_id) {
  txn.execute(
      "DELETE FROM thread_subscriptions WHERE user_id = ? AND room_id = ?",
      {user_id, room_id});
}

int64_t ThreadSubscriptionsStore::count_subscriptions_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM thread_subscriptions WHERE user_id = ?", {user_id});
  return row ? row->get<int64_t>(0) : 0;
}

// ============================================================================
// 5. KnockMembershipsStore
// ============================================================================

KnockMembershipsStore::KnockMembershipsStore(DatabasePool& db) : db_(db) {}

void KnockMembershipsStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS knock_memberships (
      room_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      content_json TEXT,
      reason TEXT,
      knocked_ts BIGINT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      resolved_by TEXT,
      resolved_ts BIGINT,
      PRIMARY KEY (room_id, user_id)
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS knock_status_idx
      ON knock_memberships (status);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS knock_user_idx
      ON knock_memberships (user_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS knock_room_status_idx
      ON knock_memberships (room_id, status);
  )SQL");
}

void KnockMembershipsStore::add_knock_txn(LoggingTransaction& txn,
                                           const std::string& room_id,
                                           const std::string& user_id,
                                           const std::string& event_id,
                                           const json& content,
                                           const std::optional<std::string>& reason) {
  txn.execute(
      "INSERT OR REPLACE INTO knock_memberships "
      "(room_id, user_id, event_id, content_json, reason, knocked_ts, status) "
      "VALUES (?, ?, ?, ?, ?, ?, 'pending')",
      {room_id, user_id, event_id, content.dump(),
       reason.value_or(""), now_ms()});
}

json KnockMembershipsStore::get_knock_txn(LoggingTransaction& txn,
                                           const std::string& room_id,
                                           const std::string& user_id) {
  json k;
  auto row = txn.select_one(
      "SELECT room_id, user_id, event_id, content_json, reason, knocked_ts, "
      "status, resolved_by, resolved_ts "
      "FROM knock_memberships WHERE room_id = ? AND user_id = ?",
      {room_id, user_id});
  if (row) {
    k["room_id"] = row->get<std::string>(0);
    k["user_id"] = row->get<std::string>(1);
    k["event_id"] = row->get<std::string>(2);
    if (!row->is_null(3)) k["content"] = json::parse(row->get<std::string>(3));
    if (!row->is_null(4)) k["reason"] = row->get<std::string>(4);
    k["knocked_ts"] = row->get<int64_t>(5);
    k["status"] = row->get<std::string>(6);
    if (!row->is_null(7)) k["resolved_by"] = row->get<std::string>(7);
    if (!row->is_null(8)) k["resolved_ts"] = row->get<int64_t>(8);
  }
  return k;
}

json KnockMembershipsStore::get_pending_knocks_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, user_id, event_id, content_json, reason, knocked_ts "
      "FROM knock_memberships WHERE room_id = ? AND status = 'pending' "
      "ORDER BY knocked_ts ASC LIMIT ?",
      {room_id, limit});
  for (auto& row : rows) {
    json k;
    k["room_id"] = row->get<std::string>(0);
    k["user_id"] = row->get<std::string>(1);
    k["event_id"] = row->get<std::string>(2);
    if (!row->is_null(3)) k["content"] = json::parse(row->get<std::string>(3));
    if (!row->is_null(4)) k["reason"] = row->get<std::string>(4);
    k["knocked_ts"] = row->get<int64_t>(5);
    result.push_back(k);
  }
  return result;
}

json KnockMembershipsStore::get_pending_knocks_for_user_txn(
    LoggingTransaction& txn, const std::string& user_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, user_id, event_id, content_json, reason, knocked_ts "
      "FROM knock_memberships WHERE user_id = ? AND status = 'pending' "
      "ORDER BY knocked_ts DESC LIMIT ?",
      {user_id, limit});
  for (auto& row : rows) {
    json k;
    k["room_id"] = row->get<std::string>(0);
    k["user_id"] = row->get<std::string>(1);
    k["event_id"] = row->get<std::string>(2);
    if (!row->is_null(3)) k["content"] = json::parse(row->get<std::string>(3));
    if (!row->is_null(4)) k["reason"] = row->get<std::string>(4);
    k["knocked_ts"] = row->get<int64_t>(5);
    result.push_back(k);
  }
  return result;
}

void KnockMembershipsStore::approve_knock_txn(LoggingTransaction& txn,
                                               const std::string& room_id,
                                               const std::string& user_id,
                                               const std::string& approved_by) {
  txn.execute(
      "UPDATE knock_memberships SET status = 'approved', resolved_by = ?, "
      "resolved_ts = ? WHERE room_id = ? AND user_id = ?",
      {approved_by, now_ms(), room_id, user_id});
}

void KnockMembershipsStore::reject_knock_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& user_id, const std::string& rejected_by,
    const std::optional<std::string>& reason) {
  if (reason) {
    txn.execute(
        "UPDATE knock_memberships SET status = 'rejected', resolved_by = ?, "
        "reason = ?, resolved_ts = ? WHERE room_id = ? AND user_id = ?",
        {rejected_by, reason.value(), now_ms(), room_id, user_id});
  } else {
    txn.execute(
        "UPDATE knock_memberships SET status = 'rejected', resolved_by = ?, "
        "resolved_ts = ? WHERE room_id = ? AND user_id = ?",
        {rejected_by, now_ms(), room_id, user_id});
  }
}

void KnockMembershipsStore::withdraw_knock_txn(LoggingTransaction& txn,
                                                const std::string& room_id,
                                                const std::string& user_id) {
  txn.execute("DELETE FROM knock_memberships WHERE room_id = ? AND user_id = ?",
              {room_id, user_id});
}

bool KnockMembershipsStore::has_knocked_txn(LoggingTransaction& txn,
                                             const std::string& room_id,
                                             const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT 1 FROM knock_memberships WHERE room_id = ? AND user_id = ?",
      {room_id, user_id});
  return row && !row->is_null();
}

json KnockMembershipsStore::get_all_knocks_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, user_id, event_id, content_json, reason, knocked_ts, "
      "status, resolved_by, resolved_ts "
      "FROM knock_memberships WHERE room_id = ? "
      "ORDER BY knocked_ts DESC LIMIT ?",
      {room_id, limit});
  for (auto& row : rows) {
    json k;
    k["room_id"] = row->get<std::string>(0);
    k["user_id"] = row->get<std::string>(1);
    k["event_id"] = row->get<std::string>(2);
    if (!row->is_null(3)) k["content"] = json::parse(row->get<std::string>(3));
    if (!row->is_null(4)) k["reason"] = row->get<std::string>(4);
    k["knocked_ts"] = row->get<int64_t>(5);
    k["status"] = row->get<std::string>(6);
    if (!row->is_null(7)) k["resolved_by"] = row->get<std::string>(7);
    if (!row->is_null(8)) k["resolved_ts"] = row->get<int64_t>(8);
    result.push_back(k);
  }
  return result;
}

int64_t KnockMembershipsStore::count_pending_knocks_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM knock_memberships WHERE room_id = ? AND status = 'pending'",
      {room_id});
  return row ? row->get<int64_t>(0) : 0;
}

void KnockMembershipsStore::delete_old_knocks_txn(LoggingTransaction& txn,
                                                   int64_t before_ts) {
  txn.execute("DELETE FROM knock_memberships WHERE knocked_ts < ? AND status != 'pending'",
              {before_ts});
}

// ============================================================================
// 6. EventFailedPullStore
// ============================================================================

EventFailedPullStore::EventFailedPullStore(DatabasePool& db) : db_(db) {}

void EventFailedPullStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS event_failed_pulls (
      room_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      server_name TEXT NOT NULL,
      num_attempts BIGINT NOT NULL DEFAULT 1,
      first_attempt_ts BIGINT NOT NULL,
      last_attempt_ts BIGINT NOT NULL,
      backoff_until_ts BIGINT NOT NULL DEFAULT 0,
      last_error TEXT,
      PRIMARY KEY (room_id, event_id, server_name)
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS failed_pull_backoff_idx
      ON event_failed_pulls (backoff_until_ts);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS failed_pull_server_idx
      ON event_failed_pulls (server_name);
  )SQL");
}

void EventFailedPullStore::record_failed_pull_txn(LoggingTransaction& txn,
                                                   const std::string& room_id,
                                                   const std::string& event_id,
                                                   const std::string& server_name,
                                                   int64_t backoff_ms) {
  int64_t ts = now_ms();
  int64_t backoff_until = ts + backoff_ms;
  txn.execute(
      "INSERT INTO event_failed_pulls "
      "(room_id, event_id, server_name, num_attempts, first_attempt_ts, "
      "last_attempt_ts, backoff_until_ts) "
      "VALUES (?, ?, ?, 1, ?, ?, ?) "
      "ON CONFLICT (room_id, event_id, server_name) DO UPDATE SET "
      "num_attempts = event_failed_pulls.num_attempts + 1, "
      "last_attempt_ts = excluded.last_attempt_ts, "
      "backoff_until_ts = excluded.backoff_until_ts",
      {room_id, event_id, server_name, ts, ts, backoff_until});
}

void EventFailedPullStore::record_successful_pull_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& event_id, const std::string& server_name) {
  txn.execute(
      "DELETE FROM event_failed_pulls WHERE room_id = ? AND event_id = ? AND server_name = ?",
      {room_id, event_id, server_name});
}

json EventFailedPullStore::get_failed_pulls_txn(LoggingTransaction& txn,
                                                 const std::string& room_id,
                                                 int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, event_id, server_name, num_attempts, "
      "first_attempt_ts, last_attempt_ts, backoff_until_ts, last_error "
      "FROM event_failed_pulls WHERE room_id = ? ORDER BY last_attempt_ts DESC LIMIT ?",
      {room_id, limit});
  for (auto& row : rows) {
    json f;
    f["room_id"] = row->get<std::string>(0);
    f["event_id"] = row->get<std::string>(1);
    f["server_name"] = row->get<std::string>(2);
    f["num_attempts"] = row->get<int64_t>(3);
    f["first_attempt_ts"] = row->get<int64_t>(4);
    f["last_attempt_ts"] = row->get<int64_t>(5);
    f["backoff_until_ts"] = row->get<int64_t>(6);
    if (!row->is_null(7)) f["last_error"] = row->get<std::string>(7);
    result.push_back(f);
  }
  return result;
}

json EventFailedPullStore::get_failed_pulls_for_server_txn(
    LoggingTransaction& txn, const std::string& server_name, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, event_id, num_attempts, last_attempt_ts, "
      "backoff_until_ts, last_error "
      "FROM event_failed_pulls WHERE server_name = ? "
      "ORDER BY last_attempt_ts DESC LIMIT ?",
      {server_name, limit});
  for (auto& row : rows) {
    json f;
    f["room_id"] = row->get<std::string>(0);
    f["event_id"] = row->get<std::string>(1);
    f["server_name"] = server_name;
    f["num_attempts"] = row->get<int64_t>(2);
    f["last_attempt_ts"] = row->get<int64_t>(3);
    f["backoff_until_ts"] = row->get<int64_t>(4);
    if (!row->is_null(5)) f["last_error"] = row->get<std::string>(5);
    result.push_back(f);
  }
  return result;
}

bool EventFailedPullStore::is_in_backoff_txn(LoggingTransaction& txn,
                                              const std::string& room_id,
                                              const std::string& event_id,
                                              const std::string& server_name) {
  int64_t now = now_ms();
  auto row = txn.select_one(
      "SELECT 1 FROM event_failed_pulls "
      "WHERE room_id = ? AND event_id = ? AND server_name = ? "
      "AND backoff_until_ts > ?",
      {room_id, event_id, server_name, now});
  return row && !row->is_null();
}

int64_t EventFailedPullStore::increment_retry_count_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& event_id, const std::string& server_name,
    int64_t new_backoff_ms) {
  int64_t ts = now_ms();
  int64_t backoff_until = ts + new_backoff_ms;
  txn.execute(
      "UPDATE event_failed_pulls SET num_attempts = num_attempts + 1, "
      "last_attempt_ts = ?, backoff_until_ts = ? "
      "WHERE room_id = ? AND event_id = ? AND server_name = ?",
      {ts, backoff_until, room_id, event_id, server_name});
  auto row = txn.select_one(
      "SELECT num_attempts FROM event_failed_pulls "
      "WHERE room_id = ? AND event_id = ? AND server_name = ?",
      {room_id, event_id, server_name});
  return row ? row->get<int64_t>(0) : 0;
}

json EventFailedPullStore::get_events_to_retry_txn(LoggingTransaction& txn,
                                                    int64_t now_ts,
                                                    int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, event_id, server_name, num_attempts, last_attempt_ts "
      "FROM event_failed_pulls WHERE backoff_until_ts <= ? "
      "ORDER BY last_attempt_ts ASC LIMIT ?",
      {now_ts, limit});
  for (auto& row : rows) {
    json f;
    f["room_id"] = row->get<std::string>(0);
    f["event_id"] = row->get<std::string>(1);
    f["server_name"] = row->get<std::string>(2);
    f["num_attempts"] = row->get<int64_t>(3);
    f["last_attempt_ts"] = row->get<int64_t>(4);
    result.push_back(f);
  }
  return result;
}

void EventFailedPullStore::delete_failed_pull_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& event_id, const std::string& server_name) {
  txn.execute(
      "DELETE FROM event_failed_pulls WHERE room_id = ? AND event_id = ? AND server_name = ?",
      {room_id, event_id, server_name});
}

void EventFailedPullStore::delete_all_failed_pulls_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  txn.execute("DELETE FROM event_failed_pulls WHERE room_id = ?", {room_id});
}

int64_t EventFailedPullStore::count_failed_pulls_txn(LoggingTransaction& txn) {
  auto row = txn.select_one("SELECT COUNT(*) FROM event_failed_pulls");
  return row ? row->get<int64_t>(0) : 0;
}

// ============================================================================
// 7. PartialStateRoomsStore
// ============================================================================

PartialStateRoomsStore::PartialStateRoomsStore(DatabasePool& db) : db_(db) {}

void PartialStateRoomsStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS partial_state_rooms (
      room_id TEXT NOT NULL PRIMARY KEY,
      server_name TEXT NOT NULL,
      join_event_ts BIGINT NOT NULL,
      membership_event_id TEXT NOT NULL,
      marked_partial_ts BIGINT NOT NULL DEFAULT 0,
      updated_ts BIGINT NOT NULL DEFAULT 0
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS partial_state_server_idx
      ON partial_state_rooms (server_name);
  )SQL");

  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS partial_state_rooms_servers (
      room_id TEXT NOT NULL,
      server_name TEXT NOT NULL,
      added_ts BIGINT NOT NULL,
      PRIMARY KEY (room_id, server_name)
    );
  )SQL");
}

void PartialStateRoomsStore::mark_partial_state_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& server_name, int64_t join_event_ts,
    const std::string& membership_event_id) {
  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO partial_state_rooms "
      "(room_id, server_name, join_event_ts, membership_event_id, marked_partial_ts, updated_ts) "
      "VALUES (?, ?, ?, ?, ?, ?) "
      "ON CONFLICT (room_id) DO UPDATE SET "
      "server_name = excluded.server_name, "
      "join_event_ts = excluded.join_event_ts, "
      "membership_event_id = excluded.membership_event_id, "
      "marked_partial_ts = excluded.marked_partial_ts, "
      "updated_ts = excluded.updated_ts",
      {room_id, server_name, join_event_ts, membership_event_id, ts, ts});
}

void PartialStateRoomsStore::mark_full_state_txn(LoggingTransaction& txn,
                                                  const std::string& room_id) {
  txn.execute("DELETE FROM partial_state_rooms WHERE room_id = ?", {room_id});
  txn.execute("DELETE FROM partial_state_rooms_servers WHERE room_id = ?", {room_id});
}

bool PartialStateRoomsStore::is_partial_state_room_txn(LoggingTransaction& txn,
                                                        const std::string& room_id) {
  auto row = txn.select_one(
      "SELECT 1 FROM partial_state_rooms WHERE room_id = ?", {room_id});
  return row && !row->is_null();
}

json PartialStateRoomsStore::get_partial_state_rooms_txn(
    LoggingTransaction& txn, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, server_name, join_event_ts, membership_event_id, "
      "marked_partial_ts, updated_ts "
      "FROM partial_state_rooms ORDER BY marked_partial_ts ASC LIMIT ?",
      {limit});
  for (auto& row : rows) {
    json r;
    r["room_id"] = row->get<std::string>(0);
    r["server_name"] = row->get<std::string>(1);
    r["join_event_ts"] = row->get<int64_t>(2);
    r["membership_event_id"] = row->get<std::string>(3);
    r["marked_partial_ts"] = row->get<int64_t>(4);
    r["updated_ts"] = row->get<int64_t>(5);
    result.push_back(r);
  }
  return result;
}

json PartialStateRoomsStore::get_partial_state_rooms_for_server_txn(
    LoggingTransaction& txn, const std::string& server_name, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT room_id, join_event_ts, membership_event_id, "
      "marked_partial_ts, updated_ts "
      "FROM partial_state_rooms WHERE server_name = ? "
      "ORDER BY marked_partial_ts ASC LIMIT ?",
      {server_name, limit});
  for (auto& row : rows) {
    json r;
    r["room_id"] = row->get<std::string>(0);
    r["server_name"] = server_name;
    r["join_event_ts"] = row->get<int64_t>(1);
    r["membership_event_id"] = row->get<std::string>(2);
    r["marked_partial_ts"] = row->get<int64_t>(3);
    r["updated_ts"] = row->get<int64_t>(4);
    result.push_back(r);
  }
  return result;
}

void PartialStateRoomsStore::update_partial_state_room_server_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& server_name) {
  txn.execute(
      "UPDATE partial_state_rooms SET server_name = ?, updated_ts = ? WHERE room_id = ?",
      {server_name, now_ms(), room_id});
}

void PartialStateRoomsStore::add_servers_in_room_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::vector<std::string>& server_names) {
  int64_t ts = now_ms();
  for (const auto& sn : server_names) {
    txn.execute(
        "INSERT OR IGNORE INTO partial_state_rooms_servers "
        "(room_id, server_name, added_ts) VALUES (?, ?, ?)",
        {room_id, sn, ts});
  }
}

json PartialStateRoomsStore::get_servers_in_partial_state_room_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT server_name, added_ts FROM partial_state_rooms_servers "
      "WHERE room_id = ? ORDER BY added_ts ASC",
      {room_id});
  for (auto& row : rows) {
    json s;
    s["server_name"] = row->get<std::string>(0);
    s["added_ts"] = row->get<int64_t>(1);
    result.push_back(s);
  }
  return result;
}

void PartialStateRoomsStore::remove_servers_in_room_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  txn.execute("DELETE FROM partial_state_rooms_servers WHERE room_id = ?", {room_id});
}

int64_t PartialStateRoomsStore::count_partial_state_rooms_txn(
    LoggingTransaction& txn) {
  auto row = txn.select_one("SELECT COUNT(*) FROM partial_state_rooms");
  return row ? row->get<int64_t>(0) : 0;
}

void PartialStateRoomsStore::delete_old_partial_state_txn(
    LoggingTransaction& txn, int64_t before_ts) {
  // Clean up old partial state entries that have been there too long
  txn.execute("DELETE FROM partial_state_rooms WHERE marked_partial_ts < ?",
              {before_ts});
  txn.execute(
      "DELETE FROM partial_state_rooms_servers WHERE room_id NOT IN "
      "(SELECT room_id FROM partial_state_rooms)");
}

// ============================================================================
// 8. StreamOrderingStore
// ============================================================================

StreamOrderingStore::StreamOrderingStore(DatabasePool& db) : db_(db) {}

void StreamOrderingStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS stream_ordering_seq (
      stream_name TEXT NOT NULL PRIMARY KEY,
      current_value BIGINT NOT NULL DEFAULT 0,
      updated_ts BIGINT NOT NULL DEFAULT 0
    );
  )SQL");
}

int64_t StreamOrderingStore::get_next_stream_id_txn(LoggingTransaction& txn,
                                                     const std::string& stream_name) {
  int64_t ts = now_ms();
  // Ensure the row exists
  txn.execute(
      "INSERT INTO stream_ordering_seq (stream_name, current_value, updated_ts) "
      "VALUES (?, ?, ?) "
      "ON CONFLICT (stream_name) DO NOTHING",
      {stream_name, int64_t(0), ts});

  // Increment atomically using UPDATE + RETURNING-style subquery
  txn.execute(
      "UPDATE stream_ordering_seq SET current_value = current_value + 1, "
      "updated_ts = ? WHERE stream_name = ?",
      {ts, stream_name});

  auto row = txn.select_one(
      "SELECT current_value FROM stream_ordering_seq WHERE stream_name = ?",
      {stream_name});
  return row ? row->get<int64_t>(0) : 0;
}

int64_t StreamOrderingStore::peek_stream_id_txn(LoggingTransaction& txn,
                                                 const std::string& stream_name) {
  auto row = txn.select_one(
      "SELECT current_value FROM stream_ordering_seq WHERE stream_name = ?",
      {stream_name});
  return row ? row->get<int64_t>(0) : 0;
}

void StreamOrderingStore::set_stream_id_txn(LoggingTransaction& txn,
                                             const std::string& stream_name,
                                             int64_t value) {
  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO stream_ordering_seq (stream_name, current_value, updated_ts) "
      "VALUES (?, ?, ?) "
      "ON CONFLICT (stream_name) DO UPDATE SET "
      "current_value = excluded.current_value, "
      "updated_ts = excluded.updated_ts",
      {stream_name, value, ts});
}

json StreamOrderingStore::get_all_stream_ids_txn(LoggingTransaction& txn) {
  json result = json::object();
  auto rows = txn.select(
      "SELECT stream_name, current_value, updated_ts FROM stream_ordering_seq");
  for (auto& row : rows) {
    result[row->get<std::string>(0)] = row->get<int64_t>(1);
  }
  return result;
}

void StreamOrderingStore::delete_stream_txn(LoggingTransaction& txn,
                                             const std::string& stream_name) {
  txn.execute("DELETE FROM stream_ordering_seq WHERE stream_name = ?", {stream_name});
}

// ============================================================================
// 9. ClientIpsStore
// ============================================================================

ClientIpsStore::ClientIpsStore(DatabasePool& db) : db_(db) {}

void ClientIpsStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS user_ips (
      user_id TEXT NOT NULL,
      access_token TEXT,
      device_id TEXT,
      ip TEXT NOT NULL,
      user_agent TEXT,
      last_seen BIGINT NOT NULL,
      first_seen BIGINT NOT NULL DEFAULT 0
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS user_ips_user_idx ON user_ips (user_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS user_ips_device_idx ON user_ips (user_id, device_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS user_ips_last_seen_idx ON user_ips (last_seen);
  )SQL");

  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS user_daily_visits (
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      timestamp BIGINT NOT NULL
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS user_daily_visits_ts_idx
      ON user_daily_visits (timestamp);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS user_daily_visits_user_ts_idx
      ON user_daily_visits (user_id, timestamp);
  )SQL");
}

void ClientIpsStore::record_client_ip_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id, const std::string& ip,
    const std::string& user_agent,
    const std::optional<std::string>& access_token) {
  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO user_ips (user_id, access_token, device_id, ip, user_agent, "
      "last_seen, first_seen) VALUES (?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT DO UPDATE SET last_seen = excluded.last_seen, "
      "user_agent = COALESCE(excluded.user_agent, user_ips.user_agent)",
      {user_id, access_token.value_or(""), device_id, ip, user_agent, ts, ts});
}

json ClientIpsStore::get_client_ips_for_user_txn(LoggingTransaction& txn,
                                                  const std::string& user_id,
                                                  int64_t since_ts) {
  json result = json::array();
  if (since_ts > 0) {
    auto rows = txn.select(
        "SELECT device_id, ip, user_agent, last_seen, first_seen "
        "FROM user_ips WHERE user_id = ? AND last_seen > ? "
        "ORDER BY last_seen DESC",
        {user_id, since_ts});
    for (auto& row : rows) {
      json e;
      if (!row->is_null(0)) e["device_id"] = row->get<std::string>(0);
      e["ip"] = row->get<std::string>(1);
      if (!row->is_null(2)) e["user_agent"] = row->get<std::string>(2);
      e["last_seen"] = row->get<int64_t>(3);
      e["first_seen"] = row->get<int64_t>(4);
      result.push_back(e);
    }
  } else {
    auto rows = txn.select(
        "SELECT device_id, ip, user_agent, last_seen, first_seen "
        "FROM user_ips WHERE user_id = ? ORDER BY last_seen DESC",
        {user_id});
    for (auto& row : rows) {
      json e;
      if (!row->is_null(0)) e["device_id"] = row->get<std::string>(0);
      e["ip"] = row->get<std::string>(1);
      if (!row->is_null(2)) e["user_agent"] = row->get<std::string>(2);
      e["last_seen"] = row->get<int64_t>(3);
      e["first_seen"] = row->get<int64_t>(4);
      result.push_back(e);
    }
  }
  return result;
}

json ClientIpsStore::get_client_ips_for_device_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT ip, user_agent, last_seen, first_seen "
      "FROM user_ips WHERE user_id = ? AND device_id = ? "
      "ORDER BY last_seen DESC",
      {user_id, device_id});
  for (auto& row : rows) {
    json e;
    e["ip"] = row->get<std::string>(0);
    if (!row->is_null(1)) e["user_agent"] = row->get<std::string>(1);
    e["last_seen"] = row->get<int64_t>(2);
    e["first_seen"] = row->get<int64_t>(3);
    result.push_back(e);
  }
  return result;
}

json ClientIpsStore::get_last_seen_for_device_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id) {
  json e;
  auto row = txn.select_one(
      "SELECT ip, user_agent, last_seen, first_seen "
      "FROM user_ips WHERE user_id = ? AND device_id = ? "
      "ORDER BY last_seen DESC LIMIT 1",
      {user_id, device_id});
  if (row) {
    e["ip"] = row->get<std::string>(0);
    if (!row->is_null(1)) e["user_agent"] = row->get<std::string>(1);
    e["last_seen"] = row->get<int64_t>(2);
    e["first_seen"] = row->get<int64_t>(3);
  }
  return e;
}

void ClientIpsStore::delete_client_ips_for_user_txn(LoggingTransaction& txn,
                                                     const std::string& user_id) {
  txn.execute("DELETE FROM user_ips WHERE user_id = ?", {user_id});
}

void ClientIpsStore::delete_client_ips_for_device_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id) {
  txn.execute("DELETE FROM user_ips WHERE user_id = ? AND device_id = ?",
              {user_id, device_id});
}

void ClientIpsStore::delete_old_client_ips_txn(LoggingTransaction& txn,
                                                int64_t before_ts) {
  txn.execute("DELETE FROM user_ips WHERE last_seen < ?", {before_ts});
}

// --- Daily active users ---
void ClientIpsStore::record_daily_visit_txn(LoggingTransaction& txn,
                                             const std::string& user_id,
                                             const std::string& device_id) {
  int64_t ts = now_ms();
  // Deduplicate: only insert one entry per user per day
  int64_t start_of_day = (ts / 86400000) * 86400000;
  auto exists = txn.select_one(
      "SELECT 1 FROM user_daily_visits "
      "WHERE user_id = ? AND timestamp >= ? AND timestamp < ?",
      {user_id, start_of_day, start_of_day + 86400000});
  if (!exists || exists->is_null()) {
    txn.execute(
        "INSERT INTO user_daily_visits (user_id, device_id, timestamp) VALUES (?, ?, ?)",
        {user_id, device_id, ts});
  }
}

int64_t ClientIpsStore::count_daily_active_users_txn(LoggingTransaction& txn,
                                                      int64_t since_ts) {
  auto row = txn.select_one(
      "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits WHERE timestamp > ?",
      {since_ts});
  return row ? row->get<int64_t>(0) : 0;
}

int64_t ClientIpsStore::count_monthly_active_users_txn(LoggingTransaction& txn,
                                                        int64_t now) {
  int64_t thirty_days_ago = now - (30LL * 86400LL * 1000LL);
  auto row = txn.select_one(
      "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits WHERE timestamp > ?",
      {thirty_days_ago});
  return row ? row->get<int64_t>(0) : 0;
}

json ClientIpsStore::get_daily_active_users_txn(LoggingTransaction& txn,
                                                 int64_t since_ts,
                                                 int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT user_id, MAX(timestamp) as last_visit "
      "FROM user_daily_visits WHERE timestamp > ? "
      "GROUP BY user_id ORDER BY last_visit DESC LIMIT ?",
      {since_ts, limit});
  for (auto& row : rows) {
    json u;
    u["user_id"] = row->get<std::string>(0);
    u["last_visit"] = row->get<int64_t>(1);
    result.push_back(u);
  }
  return result;
}

void ClientIpsStore::delete_old_daily_visits_txn(LoggingTransaction& txn,
                                                  int64_t before_ts) {
  txn.execute("DELETE FROM user_daily_visits WHERE timestamp < ?", {before_ts});
}

int64_t ClientIpsStore::count_total_client_ips_txn(LoggingTransaction& txn) {
  auto row = txn.select_one("SELECT COUNT(*) FROM user_ips");
  return row ? row->get<int64_t>(0) : 0;
}

json ClientIpsStore::get_top_ip_addresses_txn(LoggingTransaction& txn,
                                               int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT ip, COUNT(DISTINCT user_id) as user_count, MAX(last_seen) as last_seen "
      "FROM user_ips GROUP BY ip ORDER BY user_count DESC LIMIT ?",
      {limit});
  for (auto& row : rows) {
    json s;
    s["ip"] = row->get<std::string>(0);
    s["user_count"] = row->get<int64_t>(1);
    s["last_seen"] = row->get<int64_t>(2);
    result.push_back(s);
  }
  return result;
}

// ============================================================================
// 10. DeviceInboxStore
// ============================================================================

DeviceInboxStore::DeviceInboxStore(DatabasePool& db) : db_(db) {}

void DeviceInboxStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS device_inbox (
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      message_id TEXT NOT NULL,
      content_json TEXT NOT NULL,
      stream_id BIGINT NOT NULL DEFAULT 0,
      received_ts BIGINT NOT NULL DEFAULT 0
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS device_inbox_user_device_idx
      ON device_inbox (user_id, device_id, stream_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS device_inbox_stream_idx
      ON device_inbox (stream_id);
  )SQL");

  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS device_inbox_stream (
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      max_stream_id BIGINT NOT NULL DEFAULT 0,
      updated_ts BIGINT NOT NULL DEFAULT 0,
      PRIMARY KEY (user_id, device_id)
    );
  )SQL");

  // Global max stream ID for the inbox
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS device_inbox_max_stream (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      max_stream_id BIGINT NOT NULL DEFAULT 0
    );
  )SQL");
  // Ensure the singleton row exists
  txn.execute(
      "INSERT OR IGNORE INTO device_inbox_max_stream (id, max_stream_id) VALUES (1, 0)");
}

void DeviceInboxStore::add_message_txn(LoggingTransaction& txn,
                                        const std::string& user_id,
                                        const std::string& device_id,
                                        const std::string& message_id,
                                        const json& content,
                                        int64_t stream_id) {
  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO device_inbox (user_id, device_id, message_id, content_json, "
      "stream_id, received_ts) VALUES (?, ?, ?, ?, ?, ?)",
      {user_id, device_id, message_id, content.dump(), stream_id, ts});
  // Update max stream
  txn.execute(
      "UPDATE device_inbox_max_stream SET max_stream_id = MAX(max_stream_id, ?)",
      {stream_id});
}

json DeviceInboxStore::get_messages_txn(LoggingTransaction& txn,
                                         const std::string& user_id,
                                         int64_t from_stream_id,
                                         int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT device_id, message_id, content_json, stream_id, received_ts "
      "FROM device_inbox WHERE user_id = ? AND stream_id > ? "
      "ORDER BY stream_id ASC LIMIT ?",
      {user_id, from_stream_id, limit});
  for (auto& row : rows) {
    json m;
    m["device_id"] = row->get<std::string>(0);
    m["message_id"] = row->get<std::string>(1);
    m["content"] = json::parse(row->get<std::string>(2));
    m["stream_id"] = row->get<int64_t>(3);
    m["received_ts"] = row->get<int64_t>(4);
    result.push_back(m);
  }
  return result;
}

json DeviceInboxStore::get_messages_for_device_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id, int64_t from_stream_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT message_id, content_json, stream_id, received_ts "
      "FROM device_inbox WHERE user_id = ? AND device_id = ? AND stream_id > ? "
      "ORDER BY stream_id ASC LIMIT ?",
      {user_id, device_id, from_stream_id, limit});
  for (auto& row : rows) {
    json m;
    m["message_id"] = row->get<std::string>(0);
    m["content"] = json::parse(row->get<std::string>(1));
    m["stream_id"] = row->get<int64_t>(2);
    m["received_ts"] = row->get<int64_t>(3);
    result.push_back(m);
  }
  return result;
}

void DeviceInboxStore::delete_messages_for_device_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id, int64_t up_to_stream_id) {
  txn.execute(
      "DELETE FROM device_inbox WHERE user_id = ? AND device_id = ? AND stream_id <= ?",
      {user_id, device_id, up_to_stream_id});
}

void DeviceInboxStore::delete_all_messages_for_user_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  txn.execute("DELETE FROM device_inbox WHERE user_id = ?", {user_id});
  txn.execute("DELETE FROM device_inbox_stream WHERE user_id = ?", {user_id});
}

void DeviceInboxStore::delete_old_messages_txn(LoggingTransaction& txn,
                                                int64_t before_stream_id) {
  txn.execute("DELETE FROM device_inbox WHERE stream_id < ?", {before_stream_id});
}

// --- Stream position tracking ---
int64_t DeviceInboxStore::get_max_stream_id_txn(LoggingTransaction& txn) {
  auto row = txn.select_one(
      "SELECT max_stream_id FROM device_inbox_max_stream WHERE id = 1");
  return row ? row->get<int64_t>(0) : 0;
}

void DeviceInboxStore::set_max_stream_id_txn(LoggingTransaction& txn,
                                              int64_t stream_id) {
  txn.execute(
      "UPDATE device_inbox_max_stream SET max_stream_id = "
      "MAX(max_stream_id, ?) WHERE id = 1",
      {stream_id});
}

int64_t DeviceInboxStore::get_device_stream_id_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id) {
  auto row = txn.select_one(
      "SELECT max_stream_id FROM device_inbox_stream WHERE user_id = ? AND device_id = ?",
      {user_id, device_id});
  return row ? row->get<int64_t>(0) : 0;
}

void DeviceInboxStore::set_device_stream_id_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id, int64_t stream_id) {
  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO device_inbox_stream (user_id, device_id, max_stream_id, updated_ts) "
      "VALUES (?, ?, ?, ?) "
      "ON CONFLICT (user_id, device_id) DO UPDATE SET "
      "max_stream_id = MAX(device_inbox_stream.max_stream_id, excluded.max_stream_id), "
      "updated_ts = excluded.updated_ts",
      {user_id, device_id, stream_id, ts});
}

// --- Counts ---
int64_t DeviceInboxStore::count_messages_for_user_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM device_inbox WHERE user_id = ?", {user_id});
  return row ? row->get<int64_t>(0) : 0;
}

int64_t DeviceInboxStore::count_messages_for_device_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM device_inbox WHERE user_id = ? AND device_id = ?",
      {user_id, device_id});
  return row ? row->get<int64_t>(0) : 0;
}

json DeviceInboxStore::get_stream_positions_txn(LoggingTransaction& txn,
                                                 const std::string& user_id) {
  json result = json::object();
  auto rows = txn.select(
      "SELECT device_id, max_stream_id, updated_ts "
      "FROM device_inbox_stream WHERE user_id = ?",
      {user_id});
  for (auto& row : rows) {
    json pos;
    pos["max_stream_id"] = row->get<int64_t>(1);
    pos["updated_ts"] = row->get<int64_t>(2);
    result[row->get<std::string>(0)] = pos;
  }
  return result;
}

// --- Batch operations ---
void DeviceInboxStore::add_messages_bulk_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id,
    const std::vector<std::pair<std::string, json>>& messages,
    int64_t base_stream_id) {
  int64_t ts = now_ms();
  for (size_t i = 0; i < messages.size(); i++) {
    int64_t stream_id = base_stream_id + static_cast<int64_t>(i);
    txn.execute(
        "INSERT INTO device_inbox (user_id, device_id, message_id, content_json, "
        "stream_id, received_ts) VALUES (?, ?, ?, ?, ?, ?)",
        {user_id, device_id, messages[i].first, messages[i].second.dump(),
         stream_id, ts});
  }
  // Update max stream
  if (!messages.empty()) {
    int64_t max_sid = base_stream_id + static_cast<int64_t>(messages.size()) - 1;
    txn.execute(
        "UPDATE device_inbox_max_stream SET max_stream_id = MAX(max_stream_id, ?)",
        {max_sid});
  }
}

} // namespace progressive
