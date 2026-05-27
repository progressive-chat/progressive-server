// ============================================================================
// more_stores_batch.cpp — 10 advanced storage modules with full SQL DDL + CRUD:
//
//   1. EventBatchingStore  (MSC2716) — historical message batch import,
//      insertion_events & batch_events CRUD, chunk storage, batch metadata
//      tracking, next_batch_id generation, batch importing for bridging
//   2. EventExpiryStore     — per-event TTL, auto-expire queries, cleanup
//      of expired events, configurable expiry scheduling
//   3. StickyEventsStore    — sticky events per room, mark/unmark, list,
//      reorder, pinned/featured message semantics
//   4. TaskSchedulerStore   — scheduled tasks with priority queues, get next
//      pending sorted by priority/time, mark complete/failed, retry tracking
//   5. UserErasureStore     — GDPR/user erasure requests, full status
//      lifecycle (pending→in_progress→completed/failed), purge all user data
//   6. SessionStore         — generic session CRUD (distinct from
//      ui_auth_sessions), arbitrary key/value, expiry, lookup
//   7. OpenIdStore          — OpenID token generation, validation, revocation
//      for third-party integrations (Matrix OpenID Connect)
//   8. AccountDataSyncStore — per-user stream position tracking for
//      account data incremental sync, position get/set/advance
//   9. ToDeviceSyncStore    — to-device message delivery tracking per
//      (user, device_id), stream positions, delivery status, cleanup
//  10. PushRuleEvalCache    — push rule evaluation result cache per
//      (event_id, user_id), TTL-based eviction, cache hit/miss tracking
//
// Every store with explicit SQL DDL, full CRUD, transaction-safe methods.
// All in namespace progressive:: (with progressive::storage helpers).
// Over 3000 lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Forward-declare txn helpers for this compilation unit
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

// Generate a random token string for OpenID tokens
std::string generate_random_token(size_t length = 64) {
  static const char charset[] =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";
  static std::mt19937 rng(std::random_device{}());
  static std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);
  std::string token;
  token.reserve(length);
  for (size_t i = 0; i < length; ++i) {
    token += charset[dist(rng)];
  }
  return token;
}

// Compute expiry timestamp from now + ttl_seconds
int64_t compute_expiry_ts(int64_t ttl_seconds) {
  return now_ms() + (ttl_seconds * 1000);
}

} // namespace

} // namespace storage
} // namespace progressive

// ============================================================================
// Inlined header declarations — self-contained compilation unit
// ============================================================================

#ifndef PROGRESSIVE_MORE_STORES_BATCH_DECLARED
#define PROGRESSIVE_MORE_STORES_BATCH_DECLARED

namespace progressive {

// Forward-declare LoggingTransaction for member function signatures.
namespace storage {
class LoggingTransaction;
class DatabasePool;
} // namespace storage

using storage::DatabasePool;
using storage::LoggingTransaction;

// ---------------------------------------------------------------------------
// 1. EventBatchingStore — MSC2716 batch import for historical messages
// ---------------------------------------------------------------------------
class EventBatchingStore {
public:
  explicit EventBatchingStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  // --- Insertion events ---
  void add_insertion_event_txn(LoggingTransaction& txn,
                                const std::string& event_id,
                                const std::string& room_id,
                                const std::string& next_batch_id,
                                const std::optional<json>& chunk_content = std::nullopt);
  std::optional<json> get_insertion_event_txn(LoggingTransaction& txn,
                                               const std::string& event_id);
  std::optional<std::string> get_next_batch_id_for_insertion_txn(
      LoggingTransaction& txn, const std::string& event_id);
  json get_insertion_events_for_room_txn(LoggingTransaction& txn,
                                          const std::string& room_id,
                                          int limit = 100);
  void update_insertion_next_batch_txn(LoggingTransaction& txn,
                                        const std::string& event_id,
                                        const std::string& next_batch_id);
  void remove_insertion_event_txn(LoggingTransaction& txn,
                                   const std::string& event_id);
  void remove_insertion_events_for_room_txn(LoggingTransaction& txn,
                                              const std::string& room_id);
  int64_t count_insertion_events_for_room_txn(LoggingTransaction& txn,
                                                const std::string& room_id);

  // --- Batch events ---
  void add_batch_event_txn(LoggingTransaction& txn,
                            const std::string& event_id,
                            const std::string& room_id,
                            const std::string& batch_id,
                            const std::optional<int64_t>& index_in_batch = std::nullopt,
                            const std::optional<json>& chunk_data = std::nullopt);
  json get_batch_event_txn(LoggingTransaction& txn,
                            const std::string& event_id);
  json get_batch_events_txn(LoggingTransaction& txn,
                             const std::string& batch_id,
                             int64_t limit = 100,
                             int64_t offset = 0);
  json get_batch_events_for_room_txn(LoggingTransaction& txn,
                                      const std::string& room_id,
                                      const std::string& batch_id,
                                      int limit = 100);
  void remove_batch_events_txn(LoggingTransaction& txn,
                                const std::string& batch_id);
  int64_t count_batch_events_txn(LoggingTransaction& txn,
                                  const std::string& batch_id);

  // --- Batch metadata ---
  void set_batch_metadata_txn(LoggingTransaction& txn,
                               const std::string& batch_id,
                               const json& metadata);
  std::optional<json> get_batch_metadata_txn(LoggingTransaction& txn,
                                              const std::string& batch_id);
  json get_all_batches_for_room_txn(LoggingTransaction& txn,
                                     const std::string& room_id,
                                     int limit = 50);
  void mark_batch_complete_txn(LoggingTransaction& txn,
                                const std::string& batch_id);
  bool is_batch_complete_txn(LoggingTransaction& txn,
                              const std::string& batch_id);

  // --- next_batch_id generation ---
  std::string generate_next_batch_id_txn(LoggingTransaction& txn);

  // --- Batch import transaction ---
  void import_batch_txn(LoggingTransaction& txn,
                         const std::string& room_id,
                         const std::string& batch_id,
                         const json& events,
                         const json& metadata);

  // --- Chunk storage for large payloads ---
  void store_chunk_txn(LoggingTransaction& txn,
                        const std::string& chunk_id,
                        const std::string& event_id,
                        const json& chunk_content,
                        int chunk_index,
                        int total_chunks);
  json get_chunks_for_event_txn(LoggingTransaction& txn,
                                 const std::string& event_id);
  void delete_chunks_for_event_txn(LoggingTransaction& txn,
                                    const std::string& event_id);

private:
  DatabasePool& db_;
  std::string generate_unique_batch_id();
};

// ---------------------------------------------------------------------------
// 2. EventExpiryStore — per-event TTL and auto-expiration
// ---------------------------------------------------------------------------
class EventExpiryStore {
public:
  explicit EventExpiryStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  // Set TTL for an event (in seconds from now)
  void set_event_expiry_txn(LoggingTransaction& txn,
                             const std::string& event_id,
                             int64_t ttl_seconds,
                             const std::optional<std::string>& reason = std::nullopt);
  // Set absolute expiry timestamp
  void set_event_expiry_at_txn(LoggingTransaction& txn,
                                const std::string& event_id,
                                int64_t expiry_ts,
                                const std::optional<std::string>& reason = std::nullopt);
  // Get expiry info for an event
  std::optional<json> get_event_expiry_txn(LoggingTransaction& txn,
                                            const std::string& event_id);
  // Remove expiry (keep event forever)
  void remove_event_expiry_txn(LoggingTransaction& txn,
                                const std::string& event_id);
  // Get all expired events (expiry_ts <= now)
  json get_expired_events_txn(LoggingTransaction& txn,
                               int limit = 100);
  // Get events expiring before a specific time
  json get_events_expiring_before_txn(LoggingTransaction& txn,
                                       int64_t before_ts,
                                       int limit = 100);
  // Count expired events
  int64_t count_expired_events_txn(LoggingTransaction& txn);
  // Check if an event has expired
  bool is_event_expired_txn(LoggingTransaction& txn,
                             const std::string& event_id);
  // Extend expiry for an event
  void extend_event_expiry_txn(LoggingTransaction& txn,
                                const std::string& event_id,
                                int64_t additional_seconds);
  // Batch set expiry for multiple events
  void batch_set_expiry_txn(LoggingTransaction& txn,
                              const std::vector<std::string>& event_ids,
                              int64_t ttl_seconds);
  // Cleanup all expired events in a transaction
  int64_t cleanup_expired_events_txn(LoggingTransaction& txn,
                                      int batch_size = 100);
  // Get expiry statistics
  json get_expiry_stats_txn(LoggingTransaction& txn);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 3. StickyEventsStore — sticky/pinned events per room
// ---------------------------------------------------------------------------
class StickyEventsStore {
public:
  explicit StickyEventsStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  // Mark an event as sticky in a room
  void mark_sticky_txn(LoggingTransaction& txn,
                        const std::string& room_id,
                        const std::string& event_id,
                        const std::optional<std::string>& label = std::nullopt);
  // Unmark an event as sticky
  void unmark_sticky_txn(LoggingTransaction& txn,
                          const std::string& room_id,
                          const std::string& event_id);
  // Unmark all sticky events in a room
  void unmark_all_sticky_in_room_txn(LoggingTransaction& txn,
                                      const std::string& room_id);
  // Check if an event is sticky
  bool is_sticky_txn(LoggingTransaction& txn,
                      const std::string& room_id,
                      const std::string& event_id);
  // List all sticky events for a room (ordered by position)
  json list_sticky_events_txn(LoggingTransaction& txn,
                               const std::string& room_id,
                               int limit = 50);
  // Get a specific sticky event
  std::optional<json> get_sticky_event_txn(LoggingTransaction& txn,
                                            const std::string& room_id,
                                            const std::string& event_id);
  // Reorder sticky events (swap positions)
  void reorder_sticky_events_txn(LoggingTransaction& txn,
                                  const std::string& room_id,
                                  const std::vector<std::string>& ordered_event_ids);
  // Set position for a specific sticky event
  void set_sticky_position_txn(LoggingTransaction& txn,
                                const std::string& room_id,
                                const std::string& event_id,
                                int position);
  // Count sticky events in a room
  int64_t count_sticky_events_txn(LoggingTransaction& txn,
                                   const std::string& room_id);
  // Count sticky events across all rooms
  int64_t count_all_sticky_events_txn(LoggingTransaction& txn);
  // Shift positions in a room to make room for a new event at a position
  void shift_positions_for_insert_txn(LoggingTransaction& txn,
                                       const std::string& room_id,
                                       int from_position);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 4. TaskSchedulerStore — scheduled tasks with priority queues
// ---------------------------------------------------------------------------
class TaskSchedulerStore {
public:
  explicit TaskSchedulerStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  // Schedule a new task
  int64_t schedule_task_txn(LoggingTransaction& txn,
                             const std::string& task_type,
                             const json& payload,
                             int priority = 0,
                             int64_t scheduled_at_ts = 0,
                             const std::optional<std::string>& task_group = std::nullopt);
  // Get pending tasks sorted by priority (desc) and scheduled_at (asc)
  json get_pending_tasks_txn(LoggingTransaction& txn,
                              int limit = 10,
                              const std::optional<std::string>& task_type = std::nullopt);
  // Get next n highest-priority pending tasks
  json get_next_tasks_txn(LoggingTransaction& txn,
                           int count = 1);
  // Claim tasks for processing (atomic select + mark as in_progress)
  json claim_tasks_txn(LoggingTransaction& txn,
                        int count = 1,
                        const std::string& claimed_by = "worker");
  // Mark task as completed
  void mark_task_completed_txn(LoggingTransaction& txn,
                                int64_t task_id);
  // Mark task as failed
  void mark_task_failed_txn(LoggingTransaction& txn,
                             int64_t task_id,
                             const std::optional<std::string>& error = std::nullopt);
  // Retry a failed task
  void retry_task_txn(LoggingTransaction& txn,
                       int64_t task_id,
                       int64_t retry_delay_seconds = 60);
  // Get retry tracking info
  json get_task_retry_info_txn(LoggingTransaction& txn,
                                int64_t task_id);
  // Get task by ID
  std::optional<json> get_task_txn(LoggingTransaction& txn,
                                    int64_t task_id);
  // Delete a task
  void delete_task_txn(LoggingTransaction& txn,
                        int64_t task_id);
  // Delete completed tasks older than N seconds
  int64_t cleanup_completed_tasks_txn(LoggingTransaction& txn,
                                       int64_t older_than_seconds = 86400);
  // Count tasks by status
  int64_t count_tasks_by_status_txn(LoggingTransaction& txn,
                                     const std::string& status);
  // Count pending tasks
  int64_t count_pending_tasks_txn(LoggingTransaction& txn);
  // Fetch stale in-progress tasks (claimed but never completed)
  json get_stale_in_progress_tasks_txn(LoggingTransaction& txn,
                                        int64_t stale_after_seconds = 300,
                                        int limit = 100);
  // Bulk schedule tasks
  std::vector<int64_t> schedule_tasks_bulk_txn(LoggingTransaction& txn,
                                                 const std::string& task_type,
                                                 const std::vector<json>& payloads,
                                                 int priority = 0);

private:
  DatabasePool& db_;
  static constexpr int64_t kMaxRetries = 5;
};

// ---------------------------------------------------------------------------
// 5. UserErasureStore — GDPR/user erasure request management
// ---------------------------------------------------------------------------
class UserErasureStore {
public:
  explicit UserErasureStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  // Create a new erasure request
  int64_t create_erasure_request_txn(LoggingTransaction& txn,
                                      const std::string& user_id,
                                      const std::optional<std::string>& requested_by = std::nullopt);
  // Get erasure request by ID
  std::optional<json> get_erasure_request_txn(LoggingTransaction& txn,
                                               int64_t request_id);
  // Get erasure request for a user (most recent)
  std::optional<json> get_erasure_request_for_user_txn(LoggingTransaction& txn,
                                                        const std::string& user_id);
  // Update erasure request status
  void update_erasure_status_txn(LoggingTransaction& txn,
                                  int64_t request_id,
                                  const std::string& status,
                                  const std::optional<std::string>& status_detail = std::nullopt);
  // Mark erasure as in progress
  void mark_erasure_in_progress_txn(LoggingTransaction& txn,
                                     int64_t request_id);
  // Mark erasure as completed
  void mark_erasure_completed_txn(LoggingTransaction& txn,
                                   int64_t request_id,
                                   const std::optional<int64_t>& items_purged = std::nullopt);
  // Mark erasure as failed
  void mark_erasure_failed_txn(LoggingTransaction& txn,
                                int64_t request_id,
                                const std::string& error);
  // Cancel an erasure request
  void cancel_erasure_request_txn(LoggingTransaction& txn,
                                   int64_t request_id,
                                   const std::string& reason);
  // List erasure requests by status
  json list_erasure_requests_txn(LoggingTransaction& txn,
                                  const std::optional<std::string>& status = std::nullopt,
                                  int limit = 50,
                                  int64_t offset = 0);
  // List all erasure requests for a user
  json list_user_erasure_requests_txn(LoggingTransaction& txn,
                                       const std::string& user_id,
                                       int limit = 20);
  // Get count of erasure requests by status
  int64_t count_erasure_requests_txn(LoggingTransaction& txn,
                                      const std::optional<std::string>& status = std::nullopt);
  // Check if user has a pending erasure request
  bool has_pending_erasure_txn(LoggingTransaction& txn,
                                const std::string& user_id);
  // --- Purge operations ---
  // Record data that was purged
  void record_purge_action_txn(LoggingTransaction& txn,
                                int64_t request_id,
                                const std::string& data_type,
                                const std::string& data_id,
                                const json& purge_details);
  // Get all purge actions for a request
  json get_purge_actions_for_request_txn(LoggingTransaction& txn,
                                          int64_t request_id,
                                          int limit = 200);
  // Get total items purged for a request
  int64_t count_purged_items_txn(LoggingTransaction& txn,
                                  int64_t request_id);
  // Get erasure statistics
  json get_erasure_stats_txn(LoggingTransaction& txn);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 6. SessionStore — generic session CRUD (key/value with expiry)
// ---------------------------------------------------------------------------
class SessionStore {
public:
  explicit SessionStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  // Create or update a session
  void set_session_txn(LoggingTransaction& txn,
                        const std::string& session_id,
                        const std::string& session_type,
                        const std::string& user_id,
                        const json& data,
                        int64_t ttl_seconds = 3600,
                        const std::optional<std::string>& device_id = std::nullopt);
  // Get a session
  std::optional<json> get_session_txn(LoggingTransaction& txn,
                                       const std::string& session_id);
  // Get sessions for a user
  json get_sessions_for_user_txn(LoggingTransaction& txn,
                                  const std::string& user_id,
                                  const std::optional<std::string>& session_type = std::nullopt,
                                  int limit = 100);
  // Get sessions for a user's device
  json get_sessions_for_device_txn(LoggingTransaction& txn,
                                    const std::string& user_id,
                                    const std::string& device_id);
  // Update session data
  void update_session_data_txn(LoggingTransaction& txn,
                                const std::string& session_id,
                                const json& data);
  // Extend session expiry
  void extend_session_txn(LoggingTransaction& txn,
                           const std::string& session_id,
                           int64_t additional_seconds);
  // Refresh session (set new expiry from now)
  void refresh_session_txn(LoggingTransaction& txn,
                            const std::string& session_id,
                            int64_t ttl_seconds = 3600);
  // Check if session exists and is valid (not expired)
  bool is_session_valid_txn(LoggingTransaction& txn,
                             const std::string& session_id);
  // Delete a session
  void delete_session_txn(LoggingTransaction& txn,
                           const std::string& session_id);
  // Delete all sessions for a user
  void delete_user_sessions_txn(LoggingTransaction& txn,
                                 const std::string& user_id);
  // Delete all sessions for a user's device
  void delete_device_sessions_txn(LoggingTransaction& txn,
                                   const std::string& user_id,
                                   const std::string& device_id);
  // Cleanup expired sessions
  int64_t cleanup_expired_sessions_txn(LoggingTransaction& txn,
                                        int batch_size = 100);
  // Count active sessions
  int64_t count_active_sessions_txn(LoggingTransaction& txn,
                                     const std::optional<std::string>& user_id = std::nullopt);
  // Count sessions by type
  int64_t count_sessions_by_type_txn(LoggingTransaction& txn,
                                      const std::string& session_type);
  // Get session statistics
  json get_session_stats_txn(LoggingTransaction& txn);

  // --- Batch session operations ---
  void set_sessions_bulk_txn(LoggingTransaction& txn,
                              const std::vector<std::tuple<std::string, std::string, std::string, json, int64_t>>& sessions);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 7. OpenIdStore — OpenID token management for third-party integration
// ---------------------------------------------------------------------------
class OpenIdStore {
public:
  explicit OpenIdStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  // Generate a new OpenID token for a user
  std::string generate_token_txn(LoggingTransaction& txn,
                                  const std::string& user_id,
                                  int64_t ttl_seconds = 3600,
                                  const std::optional<std::string>& matrix_server_name = std::nullopt);
  // Validate an OpenID token and return user_id if valid
  std::optional<json> validate_token_txn(LoggingTransaction& txn,
                                          const std::string& token);
  // Revoke (delete) a token
  void revoke_token_txn(LoggingTransaction& txn,
                         const std::string& token);
  // Revoke all tokens for a user
  int64_t revoke_user_tokens_txn(LoggingTransaction& txn,
                                  const std::string& user_id);
  // Get token information (without consuming)
  std::optional<json> get_token_info_txn(LoggingTransaction& txn,
                                          const std::string& token);
  // Get all active tokens for a user
  json get_user_tokens_txn(LoggingTransaction& txn,
                            const std::string& user_id,
                            int limit = 50);
  // Check if a token has been used
  bool is_token_used_txn(LoggingTransaction& txn,
                          const std::string& token);
  // Mark token as used (for one-time-use tokens)
  void mark_token_used_txn(LoggingTransaction& txn,
                            const std::string& token);
  // Cleanup expired tokens
  int64_t cleanup_expired_tokens_txn(LoggingTransaction& txn,
                                      int batch_size = 100);
  // Count active tokens
  int64_t count_active_tokens_txn(LoggingTransaction& txn,
                                   const std::optional<std::string>& user_id = std::nullopt);
  // Verify a token matches a specific user
  bool verify_token_for_user_txn(LoggingTransaction& txn,
                                  const std::string& token,
                                  const std::string& user_id);
  // Get token statistics
  json get_token_stats_txn(LoggingTransaction& txn);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 8. AccountDataSyncStore — incremental account data sync positions
// ---------------------------------------------------------------------------
class AccountDataSyncStore {
public:
  explicit AccountDataSyncStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  // Set account data for a user
  void set_account_data_txn(LoggingTransaction& txn,
                             const std::string& user_id,
                             const std::string& data_type,
                             const std::string& data_key,
                             const json& content);
  // Get account data for a user
  std::optional<json> get_account_data_txn(LoggingTransaction& txn,
                                            const std::string& user_id,
                                            const std::string& data_type,
                                            const std::string& data_key);
  // Get all account data of a type for a user
  json get_account_data_by_type_txn(LoggingTransaction& txn,
                                     const std::string& user_id,
                                     const std::string& data_type,
                                     bool include_global = false);
  // Get global account data
  json get_global_account_data_txn(LoggingTransaction& txn,
                                    const std::string& user_id);
  // Get account data for a specific room
  json get_room_account_data_txn(LoggingTransaction& txn,
                                  const std::string& user_id,
                                  const std::string& room_id,
                                  const std::string& data_type);
  // Delete account data
  void delete_account_data_txn(LoggingTransaction& txn,
                                const std::string& user_id,
                                const std::string& data_type,
                                const std::string& data_key);
  // Delete all account data for a user
  void delete_all_user_account_data_txn(LoggingTransaction& txn,
                                         const std::string& user_id);

  // --- Stream position tracking ---
  // Get current stream position for a user
  int64_t get_stream_position_txn(LoggingTransaction& txn,
                                   const std::string& user_id);
  // Set stream position for a user
  void set_stream_position_txn(LoggingTransaction& txn,
                                const std::string& user_id,
                                int64_t position);
  // Advance stream position (only if new > current)
  void advance_stream_position_txn(LoggingTransaction& txn,
                                    const std::string& user_id,
                                    int64_t new_position);
  // Get account data changed since position (for incremental sync)
  json get_account_data_since_txn(LoggingTransaction& txn,
                                   const std::string& user_id,
                                   int64_t since_position,
                                   int limit = 100);
  // Get global account data changed since position
  json get_global_account_data_since_txn(LoggingTransaction& txn,
                                          const std::string& user_id,
                                          int64_t since_position,
                                          int limit = 100);
  // Get room account data changed since position
  json get_room_account_data_since_txn(LoggingTransaction& txn,
                                        const std::string& user_id,
                                        const std::string& room_id,
                                        int64_t since_position,
                                        int limit = 50);
  // Get the maximum stream position across all users
  int64_t get_max_stream_position_txn(LoggingTransaction& txn);
  // Reset stream position for a user
  void reset_stream_position_txn(LoggingTransaction& txn,
                                  const std::string& user_id);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 9. ToDeviceSyncStore — to-device message delivery tracking
// ---------------------------------------------------------------------------
class ToDeviceSyncStore {
public:
  explicit ToDeviceSyncStore(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  // --- Message storage ---
  // Send a to-device message to a user's device
  int64_t send_to_device_msg_txn(LoggingTransaction& txn,
                                  const std::string& user_id,
                                  const std::string& device_id,
                                  const std::string& sender_user_id,
                                  const std::string& message_type,
                                  const json& content);
  // Send to-device message to all devices of a user
  void send_to_all_user_devices_txn(LoggingTransaction& txn,
                                     const std::string& target_user_id,
                                     const std::string& sender_user_id,
                                     const std::string& message_type,
                                     const json& content,
                                     const std::vector<std::string>& device_ids);
  // Get pending messages for a device
  json get_pending_messages_txn(LoggingTransaction& txn,
                                 const std::string& user_id,
                                 const std::string& device_id,
                                 int limit = 100);
  // Get messages since a stream position
  json get_messages_since_txn(LoggingTransaction& txn,
                               const std::string& user_id,
                               const std::string& device_id,
                               int64_t since_stream_id,
                               int limit = 100);

  // --- Delivery tracking ---
  // Mark messages as delivered to a device (up to stream_id)
  void mark_delivered_txn(LoggingTransaction& txn,
                           const std::string& user_id,
                           const std::string& device_id,
                           int64_t up_to_stream_id);
  // Mark a single message as delivered
  void mark_message_delivered_txn(LoggingTransaction& txn,
                                   int64_t message_id);
  // Mark a message as failed
  void mark_message_failed_txn(LoggingTransaction& txn,
                                int64_t message_id,
                                const std::string& error);
  // Get delivery status for a message
  std::optional<json> get_delivery_status_txn(LoggingTransaction& txn,
                                               int64_t message_id);
  // Get undelivered message count for a device
  int64_t count_undelivered_for_device_txn(LoggingTransaction& txn,
                                            const std::string& user_id,
                                            const std::string& device_id);

  // --- Stream tracking ---
  // Get current stream position for a device
  int64_t get_device_stream_position_txn(LoggingTransaction& txn,
                                          const std::string& user_id,
                                          const std::string& device_id);
  // Set stream position for a device
  void set_device_stream_position_txn(LoggingTransaction& txn,
                                       const std::string& user_id,
                                       const std::string& device_id,
                                       int64_t position);
  // Get maximum stream position across all devices
  int64_t get_max_stream_position_txn(LoggingTransaction& txn);

  // --- Cleanup ---
  // Delete delivered messages older than N seconds
  int64_t cleanup_delivered_messages_txn(LoggingTransaction& txn,
                                          int64_t older_than_seconds = 86400);
  // Delete all messages for a user's device
  void delete_device_messages_txn(LoggingTransaction& txn,
                                   const std::string& user_id,
                                   const std::string& device_id);
  // Delete all messages for a user (across all devices)
  void delete_all_user_messages_txn(LoggingTransaction& txn,
                                     const std::string& user_id);

  // --- Statistics ---
  json get_to_device_stats_txn(LoggingTransaction& txn);
  int64_t count_pending_messages_txn(LoggingTransaction& txn);
  json get_pending_counts_by_user_txn(LoggingTransaction& txn,
                                       int limit = 100);

private:
  DatabasePool& db_;
};

// ---------------------------------------------------------------------------
// 10. PushRuleEvalCache — push rule evaluation result caching
// ---------------------------------------------------------------------------
class PushRuleEvalCache {
public:
  explicit PushRuleEvalCache(DatabasePool& db);

  // DDL
  static void create_tables(LoggingTransaction& txn);

  // Cache a push rule evaluation result
  void cache_result_txn(LoggingTransaction& txn,
                         const std::string& event_id,
                         const std::string& user_id,
                         const json& eval_result,
                         const std::string& rule_id,
                         int64_t ttl_seconds = 300);
  // Get cached result for (event_id, user_id)
  std::optional<json> get_cached_result_txn(LoggingTransaction& txn,
                                             const std::string& event_id,
                                             const std::string& user_id);
  // Get cached results for an event (across all users)
  json get_cached_results_for_event_txn(LoggingTransaction& txn,
                                         const std::string& event_id,
                                         int limit = 100);
  // Get cached results for a user (across all events)
  json get_cached_results_for_user_txn(LoggingTransaction& txn,
                                        const std::string& user_id,
                                        int limit = 100);
  // Invalidate cache for a specific event (for all users)
  void invalidate_event_cache_txn(LoggingTransaction& txn,
                                   const std::string& event_id);
  // Invalidate cache for a specific (event, user) pair
  void invalidate_cache_txn(LoggingTransaction& txn,
                             const std::string& event_id,
                             const std::string& user_id);
  // Invalidate all cache for a user
  void invalidate_user_cache_txn(LoggingTransaction& txn,
                                  const std::string& user_id);
  // Invalidate cache for all events matching a rule
  void invalidate_rule_cache_txn(LoggingTransaction& txn,
                                  const std::string& rule_id);
  // Check if a cached result exists and is valid (not expired)
  bool has_valid_cache_txn(LoggingTransaction& txn,
                            const std::string& event_id,
                            const std::string& user_id);
  // Cleanup expired cache entries
  int64_t cleanup_expired_cache_txn(LoggingTransaction& txn,
                                     int batch_size = 100);
  // Cleanup cache entries older than N seconds (regardless of TTL)
  int64_t cleanup_old_cache_txn(LoggingTransaction& txn,
                                 int64_t older_than_seconds = 86400);
  // Get cache statistics
  json get_cache_stats_txn(LoggingTransaction& txn);
  // Get cache hit/miss counters
  json get_cache_performance_txn(LoggingTransaction& txn);
  // Reset cache counters
  void reset_cache_counters_txn(LoggingTransaction& txn);
  // Bulk cache results for multiple users
  void bulk_cache_results_txn(LoggingTransaction& txn,
                               const std::string& event_id,
                               const json& user_results, // {user_id: {result, rule_id}}
                               int64_t ttl_seconds = 300);
  // Pre-warm cache for an event
  void warm_cache_txn(LoggingTransaction& txn,
                       const std::string& event_id,
                       const json& eval_lookup);

private:
  DatabasePool& db_;
  // Track hit/miss counts in-memory (sync'd periodically)
  mutable int64_t hit_count_ = 0;
  mutable int64_t miss_count_ = 0;
};

} // namespace progressive

#endif // PROGRESSIVE_MORE_STORES_BATCH_DECLARED

// ============================================================================
// ============================================================================
// IMPLEMENTATIONS
// ============================================================================
// ============================================================================

namespace progressive {
using storage::DatabasePool;
using storage::LoggingTransaction;
using storage::now_ms;
using storage::generate_random_token;
using storage::compute_expiry_ts;

// ============================================================================
// 1. EventBatchingStore — MSC2716 historical message batch import
// ============================================================================

EventBatchingStore::EventBatchingStore(DatabasePool& db) : db_(db) {}

// ---- DDL ----
void EventBatchingStore::create_tables(LoggingTransaction& txn) {
  // Main insertion events table: tracks MSC2716 insertion points
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS msc2716_insertion_events (
      event_id TEXT NOT NULL PRIMARY KEY,
      room_id TEXT NOT NULL,
      next_batch_id TEXT NOT NULL,
      chunk_content_json TEXT,
      added_ts BIGINT NOT NULL,
      updated_ts BIGINT NOT NULL
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS msc2716_insertion_room_idx
      ON msc2716_insertion_events (room_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS msc2716_insertion_next_batch_idx
      ON msc2716_insertion_events (next_batch_id);
  )SQL");

  // Batch events table: individual events belonging to a batch
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS msc2716_batch_events (
      event_id TEXT NOT NULL PRIMARY KEY,
      room_id TEXT NOT NULL,
      batch_id TEXT NOT NULL,
      index_in_batch INTEGER,
      chunk_data_json TEXT,
      added_ts BIGINT NOT NULL
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS msc2716_batch_events_batch_idx
      ON msc2716_batch_events (batch_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS msc2716_batch_events_room_idx
      ON msc2716_batch_events (room_id, batch_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS msc2716_batch_events_index_idx
      ON msc2716_batch_events (batch_id, index_in_batch);
  )SQL");

  // Batch metadata table: per-batch metadata (creator, timestamps, status)
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS msc2716_batch_metadata (
      batch_id TEXT NOT NULL PRIMARY KEY,
      room_id TEXT NOT NULL,
      metadata_json TEXT,
      is_complete INTEGER NOT NULL DEFAULT 0,
      created_ts BIGINT NOT NULL,
      completed_ts BIGINT
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS msc2716_batch_meta_room_idx
      ON msc2716_batch_metadata (room_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS msc2716_batch_meta_complete_idx
      ON msc2716_batch_metadata (room_id, is_complete);
  )SQL");

  // Batch ID sequence for generating unique batch IDs
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS msc2716_batch_id_seq (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      next_val BIGINT NOT NULL DEFAULT 0
    );
  )SQL");
  txn.execute(
      "INSERT OR IGNORE INTO msc2716_batch_id_seq (id, next_val) VALUES (1, 0)");

  // Chunk storage for large event payloads split across chunks
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS msc2716_event_chunks (
      chunk_id TEXT NOT NULL PRIMARY KEY,
      event_id TEXT NOT NULL,
      chunk_index INTEGER NOT NULL,
      total_chunks INTEGER NOT NULL,
      chunk_content_json TEXT NOT NULL,
      added_ts BIGINT NOT NULL
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS msc2716_chunks_event_idx
      ON msc2716_event_chunks (event_id, chunk_index);
  )SQL");
}

// ---- Insertion events ----
void EventBatchingStore::add_insertion_event_txn(
    LoggingTransaction& txn,
    const std::string& event_id,
    const std::string& room_id,
    const std::string& next_batch_id,
    const std::optional<json>& chunk_content) {
  int64_t ts = now_ms();
  std::string chunk_str = chunk_content.has_value() ? chunk_content->dump() : "";
  txn.execute(
      "INSERT OR REPLACE INTO msc2716_insertion_events "
      "(event_id, room_id, next_batch_id, chunk_content_json, added_ts, updated_ts) "
      "VALUES (?, ?, ?, ?, ?, ?)",
      {event_id, room_id, next_batch_id, chunk_str, ts, ts});
}

std::optional<json> EventBatchingStore::get_insertion_event_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  auto row = txn.select_one(
      "SELECT event_id, room_id, next_batch_id, chunk_content_json, added_ts, updated_ts "
      "FROM msc2716_insertion_events WHERE event_id = ?",
      {event_id});
  if (!row || row->is_null()) return std::nullopt;
  json result;
  result["event_id"] = row->get<std::string>(0);
  result["room_id"] = row->get<std::string>(1);
  result["next_batch_id"] = row->get<std::string>(2);
  std::string chunk = row->get<std::string>(3);
  if (!chunk.empty()) result["chunk_content"] = json::parse(chunk);
  result["added_ts"] = row->get<int64_t>(4);
  result["updated_ts"] = row->get<int64_t>(5);
  return result;
}

std::optional<std::string> EventBatchingStore::get_next_batch_id_for_insertion_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  auto row = txn.select_one(
      "SELECT next_batch_id FROM msc2716_insertion_events WHERE event_id = ?",
      {event_id});
  if (!row || row->is_null() || row->get<std::string>(0).empty())
    return std::nullopt;
  return row->get<std::string>(0);
}

json EventBatchingStore::get_insertion_events_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT event_id, next_batch_id, added_ts "
      "FROM msc2716_insertion_events WHERE room_id = ? "
      "ORDER BY added_ts DESC LIMIT ?",
      {room_id, limit});
  for (auto& row : rows) {
    json ev;
    ev["event_id"] = row->get<std::string>(0);
    ev["next_batch_id"] = row->get<std::string>(1);
    ev["added_ts"] = row->get<int64_t>(2);
    result.push_back(ev);
  }
  return result;
}

void EventBatchingStore::update_insertion_next_batch_txn(
    LoggingTransaction& txn, const std::string& event_id,
    const std::string& next_batch_id) {
  txn.execute(
      "UPDATE msc2716_insertion_events SET next_batch_id = ?, updated_ts = ? "
      "WHERE event_id = ?",
      {next_batch_id, now_ms(), event_id});
}

void EventBatchingStore::remove_insertion_event_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  txn.execute("DELETE FROM msc2716_insertion_events WHERE event_id = ?",
              {event_id});
}

void EventBatchingStore::remove_insertion_events_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  txn.execute("DELETE FROM msc2716_insertion_events WHERE room_id = ?",
              {room_id});
}

int64_t EventBatchingStore::count_insertion_events_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM msc2716_insertion_events WHERE room_id = ?",
      {room_id});
  return row ? row->get<int64_t>(0) : 0;
}

// ---- Batch events ----
void EventBatchingStore::add_batch_event_txn(
    LoggingTransaction& txn,
    const std::string& event_id,
    const std::string& room_id,
    const std::string& batch_id,
    const std::optional<int64_t>& index_in_batch,
    const std::optional<json>& chunk_data) {
  int64_t ts = now_ms();
  std::string chunk_str = chunk_data.has_value() ? chunk_data->dump() : "";
  if (index_in_batch.has_value()) {
    txn.execute(
        "INSERT OR REPLACE INTO msc2716_batch_events "
        "(event_id, room_id, batch_id, index_in_batch, chunk_data_json, added_ts) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        {event_id, room_id, batch_id, index_in_batch.value(), chunk_str, ts});
  } else {
    txn.execute(
        "INSERT OR REPLACE INTO msc2716_batch_events "
        "(event_id, room_id, batch_id, chunk_data_json, added_ts) "
        "VALUES (?, ?, ?, ?, ?)",
        {event_id, room_id, batch_id, chunk_str, ts});
  }
}

json EventBatchingStore::get_batch_event_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  json result;
  auto row = txn.select_one(
      "SELECT event_id, room_id, batch_id, index_in_batch, chunk_data_json, added_ts "
      "FROM msc2716_batch_events WHERE event_id = ?",
      {event_id});
  if (!row || row->is_null()) return result;
  result["event_id"] = row->get<std::string>(0);
  result["room_id"] = row->get<std::string>(1);
  result["batch_id"] = row->get<std::string>(2);
  if (!row->is_null(3)) result["index_in_batch"] = row->get<int64_t>(3);
  std::string chunk = row->get<std::string>(4);
  if (!chunk.empty()) result["chunk_data"] = json::parse(chunk);
  result["added_ts"] = row->get<int64_t>(5);
  return result;
}

json EventBatchingStore::get_batch_events_txn(
    LoggingTransaction& txn, const std::string& batch_id,
    int64_t limit, int64_t offset) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT event_id, room_id, index_in_batch, chunk_data_json, added_ts "
      "FROM msc2716_batch_events WHERE batch_id = ? "
      "ORDER BY index_in_batch ASC NULLS LAST, added_ts ASC "
      "LIMIT ? OFFSET ?",
      {batch_id, limit, offset});
  for (auto& row : rows) {
    json ev;
    ev["event_id"] = row->get<std::string>(0);
    ev["room_id"] = row->get<std::string>(1);
    if (!row->is_null(2)) ev["index_in_batch"] = row->get<int64_t>(2);
    std::string chunk = row->get<std::string>(3);
    if (!chunk.empty()) ev["chunk_data"] = json::parse(chunk);
    ev["added_ts"] = row->get<int64_t>(4);
    result.push_back(ev);
  }
  return result;
}

json EventBatchingStore::get_batch_events_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& batch_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT event_id, index_in_batch, added_ts "
      "FROM msc2716_batch_events WHERE room_id = ? AND batch_id = ? "
      "ORDER BY index_in_batch ASC NULLS LAST, added_ts ASC LIMIT ?",
      {room_id, batch_id, limit});
  for (auto& row : rows) {
    json ev;
    ev["event_id"] = row->get<std::string>(0);
    if (!row->is_null(1)) ev["index_in_batch"] = row->get<int64_t>(1);
    ev["added_ts"] = row->get<int64_t>(2);
    result.push_back(ev);
  }
  return result;
}

void EventBatchingStore::remove_batch_events_txn(
    LoggingTransaction& txn, const std::string& batch_id) {
  txn.execute("DELETE FROM msc2716_batch_events WHERE batch_id = ?",
              {batch_id});
}

int64_t EventBatchingStore::count_batch_events_txn(
    LoggingTransaction& txn, const std::string& batch_id) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM msc2716_batch_events WHERE batch_id = ?",
      {batch_id});
  return row ? row->get<int64_t>(0) : 0;
}

// ---- Batch metadata ----
void EventBatchingStore::set_batch_metadata_txn(
    LoggingTransaction& txn, const std::string& batch_id,
    const json& metadata) {
  int64_t ts = now_ms();
  std::string room_id = metadata.value("room_id", "");
  txn.execute(
      "INSERT INTO msc2716_batch_metadata "
      "(batch_id, room_id, metadata_json, is_complete, created_ts) "
      "VALUES (?, ?, ?, 0, ?) "
      "ON CONFLICT (batch_id) DO UPDATE SET "
      "metadata_json = excluded.metadata_json, "
      "room_id = excluded.room_id",
      {batch_id, room_id, metadata.dump(), ts});
}

std::optional<json> EventBatchingStore::get_batch_metadata_txn(
    LoggingTransaction& txn, const std::string& batch_id) {
  auto row = txn.select_one(
      "SELECT batch_id, room_id, metadata_json, is_complete, created_ts, completed_ts "
      "FROM msc2716_batch_metadata WHERE batch_id = ?",
      {batch_id});
  if (!row || row->is_null()) return std::nullopt;
  json result;
  result["batch_id"] = row->get<std::string>(0);
  result["room_id"] = row->get<std::string>(1);
  std::string meta = row->get<std::string>(2);
  if (!meta.empty()) result["metadata"] = json::parse(meta);
  result["is_complete"] = (row->get<int64_t>(3) != 0);
  result["created_ts"] = row->get<int64_t>(4);
  if (!row->is_null(5)) result["completed_ts"] = row->get<int64_t>(5);
  return result;
}

json EventBatchingStore::get_all_batches_for_room_txn(
    LoggingTransaction& txn, const std::string& room_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT batch_id, is_complete, created_ts, completed_ts "
      "FROM msc2716_batch_metadata WHERE room_id = ? "
      "ORDER BY created_ts DESC LIMIT ?",
      {room_id, limit});
  for (auto& row : rows) {
    json b;
    b["batch_id"] = row->get<std::string>(0);
    b["is_complete"] = (row->get<int64_t>(1) != 0);
    b["created_ts"] = row->get<int64_t>(2);
    if (!row->is_null(3)) b["completed_ts"] = row->get<int64_t>(3);
    result.push_back(b);
  }
  return result;
}

void EventBatchingStore::mark_batch_complete_txn(
    LoggingTransaction& txn, const std::string& batch_id) {
  txn.execute(
      "UPDATE msc2716_batch_metadata SET is_complete = 1, completed_ts = ? "
      "WHERE batch_id = ?",
      {now_ms(), batch_id});
}

bool EventBatchingStore::is_batch_complete_txn(
    LoggingTransaction& txn, const std::string& batch_id) {
  auto row = txn.select_one(
      "SELECT is_complete FROM msc2716_batch_metadata WHERE batch_id = ?",
      {batch_id});
  return row && !row->is_null() && row->get<int64_t>(0) != 0;
}

// ---- next_batch_id generation ----
std::string EventBatchingStore::generate_next_batch_id_txn(
    LoggingTransaction& txn) {
  txn.execute(
      "UPDATE msc2716_batch_id_seq SET next_val = next_val + 1 WHERE id = 1");
  auto row = txn.select_one(
      "SELECT next_val FROM msc2716_batch_id_seq WHERE id = 1");
  int64_t val = row ? row->get<int64_t>(0) : 1;
  return "batch_" + std::to_string(val) + "_" + std::to_string(now_ms());
}

std::string EventBatchingStore::generate_unique_batch_id() {
  return generate_random_token(16) + "_" + std::to_string(now_ms());
}

// ---- Batch import transaction ----
void EventBatchingStore::import_batch_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::string& batch_id,
    const json& events,
    const json& metadata) {
  // Create batch metadata
  json meta = metadata;
  meta["room_id"] = room_id;
  meta["event_count"] = events.size();
  set_batch_metadata_txn(txn, batch_id, meta);

  // Import each event
  for (size_t i = 0; i < events.size(); i++) {
    const auto& ev = events[i];
    std::string event_id = ev.value("event_id", "");
    json chunk_data = ev.value("chunk_data", json::object());
    add_batch_event_txn(txn, event_id, room_id, batch_id,
                         static_cast<int64_t>(i),
                         chunk_data.is_null() ? std::nullopt
                                               : std::optional<json>(chunk_data));
  }
  // Mark batch as complete
  mark_batch_complete_txn(txn, batch_id);
}

// ---- Chunk storage ----
void EventBatchingStore::store_chunk_txn(
    LoggingTransaction& txn,
    const std::string& chunk_id,
    const std::string& event_id,
    const json& chunk_content,
    int chunk_index,
    int total_chunks) {
  txn.execute(
      "INSERT OR REPLACE INTO msc2716_event_chunks "
      "(chunk_id, event_id, chunk_index, total_chunks, chunk_content_json, added_ts) "
      "VALUES (?, ?, ?, ?, ?, ?)",
      {chunk_id, event_id, chunk_index, total_chunks, chunk_content.dump(),
       now_ms()});
}

json EventBatchingStore::get_chunks_for_event_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT chunk_id, chunk_index, total_chunks, chunk_content_json, added_ts "
      "FROM msc2716_event_chunks WHERE event_id = ? "
      "ORDER BY chunk_index ASC",
      {event_id});
  for (auto& row : rows) {
    json ch;
    ch["chunk_id"] = row->get<std::string>(0);
    ch["chunk_index"] = row->get<int>(1);
    ch["total_chunks"] = row->get<int>(2);
    ch["content"] = json::parse(row->get<std::string>(3));
    ch["added_ts"] = row->get<int64_t>(4);
    result.push_back(ch);
  }
  return result;
}

void EventBatchingStore::delete_chunks_for_event_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  txn.execute("DELETE FROM msc2716_event_chunks WHERE event_id = ?",
              {event_id});
}

// ============================================================================
// 2. EventExpiryStore — per-event TTL and auto-expiration
// ============================================================================

EventExpiryStore::EventExpiryStore(DatabasePool& db) : db_(db) {}

// ---- DDL ----
void EventExpiryStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS event_expiry (
      event_id TEXT NOT NULL PRIMARY KEY,
      expiry_ts BIGINT NOT NULL,
      ttl_seconds BIGINT NOT NULL,
      reason TEXT,
      is_expired INTEGER NOT NULL DEFAULT 0,
      cleanup_ts BIGINT,
      created_ts BIGINT NOT NULL,
      updated_ts BIGINT NOT NULL
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS event_expiry_expiry_ts_idx
      ON event_expiry (expiry_ts);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS event_expiry_expired_idx
      ON event_expiry (is_expired, expiry_ts);
  )SQL");

  // Expiry event log for auditing
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS event_expiry_log (
      id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
      event_id TEXT NOT NULL,
      action TEXT NOT NULL,
      detail TEXT,
      action_ts BIGINT NOT NULL
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS event_expiry_log_event_idx
      ON event_expiry_log (event_id);
  )SQL");
}

// ---- Set TTL ----
void EventExpiryStore::set_event_expiry_txn(
    LoggingTransaction& txn, const std::string& event_id,
    int64_t ttl_seconds, const std::optional<std::string>& reason) {
  int64_t ts = now_ms();
  int64_t expiry_ts = ts + (ttl_seconds * 1000);
  std::string reason_str = reason.value_or("");
  txn.execute(
      "INSERT INTO event_expiry "
      "(event_id, expiry_ts, ttl_seconds, reason, is_expired, created_ts, updated_ts) "
      "VALUES (?, ?, ?, ?, 0, ?, ?) "
      "ON CONFLICT (event_id) DO UPDATE SET "
      "expiry_ts = excluded.expiry_ts, "
      "ttl_seconds = excluded.ttl_seconds, "
      "reason = COALESCE(excluded.reason, event_expiry.reason), "
      "updated_ts = excluded.updated_ts, "
      "is_expired = 0, "
      "cleanup_ts = NULL",
      {event_id, expiry_ts, ttl_seconds, reason_str, ts, ts});
  // Log the action
  txn.execute(
      "INSERT INTO event_expiry_log (event_id, action, detail, action_ts) "
      "VALUES (?, 'set_ttl', ?, ?)",
      {event_id, "ttl_seconds=" + std::to_string(ttl_seconds), ts});
}

void EventExpiryStore::set_event_expiry_at_txn(
    LoggingTransaction& txn, const std::string& event_id,
    int64_t expiry_ts, const std::optional<std::string>& reason) {
  int64_t ts = now_ms();
  int64_t ttl_ms = expiry_ts - ts;
  int64_t ttl_sec = (ttl_ms > 0) ? (ttl_ms / 1000) : 0;
  std::string reason_str = reason.value_or("");
  txn.execute(
      "INSERT INTO event_expiry "
      "(event_id, expiry_ts, ttl_seconds, reason, is_expired, created_ts, updated_ts) "
      "VALUES (?, ?, ?, ?, 0, ?, ?) "
      "ON CONFLICT (event_id) DO UPDATE SET "
      "expiry_ts = excluded.expiry_ts, "
      "ttl_seconds = excluded.ttl_seconds, "
      "reason = COALESCE(excluded.reason, event_expiry.reason), "
      "updated_ts = excluded.updated_ts, "
      "is_expired = 0, "
      "cleanup_ts = NULL",
      {event_id, expiry_ts, ttl_sec, reason_str, ts, ts});
  txn.execute(
      "INSERT INTO event_expiry_log (event_id, action, detail, action_ts) "
      "VALUES (?, 'set_expiry_at', ?, ?)",
      {event_id, "expiry_ts=" + std::to_string(expiry_ts), ts});
}

// ---- Get expiry info ----
std::optional<json> EventExpiryStore::get_event_expiry_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  auto row = txn.select_one(
      "SELECT event_id, expiry_ts, ttl_seconds, reason, is_expired, "
      "cleanup_ts, created_ts, updated_ts "
      "FROM event_expiry WHERE event_id = ?",
      {event_id});
  if (!row || row->is_null()) return std::nullopt;
  json result;
  result["event_id"] = row->get<std::string>(0);
  result["expiry_ts"] = row->get<int64_t>(1);
  result["ttl_seconds"] = row->get<int64_t>(2);
  if (!row->is_null(3)) result["reason"] = row->get<std::string>(3);
  result["is_expired"] = (row->get<int64_t>(4) != 0);
  if (!row->is_null(5)) result["cleanup_ts"] = row->get<int64_t>(5);
  result["created_ts"] = row->get<int64_t>(6);
  result["updated_ts"] = row->get<int64_t>(7);
  return result;
}

// ---- Remove expiry ----
void EventExpiryStore::remove_event_expiry_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  int64_t ts = now_ms();
  txn.execute("DELETE FROM event_expiry WHERE event_id = ?", {event_id});
  txn.execute(
      "INSERT INTO event_expiry_log (event_id, action, detail, action_ts) "
      "VALUES (?, 'remove_expiry', 'permanent', ?)",
      {event_id, ts});
}

// ---- Get expired events ----
json EventExpiryStore::get_expired_events_txn(
    LoggingTransaction& txn, int limit) {
  int64_t ts = now_ms();
  json result = json::array();
  auto rows = txn.select(
      "SELECT event_id, expiry_ts, ttl_seconds, reason "
      "FROM event_expiry WHERE expiry_ts <= ? AND is_expired = 0 "
      "ORDER BY expiry_ts ASC LIMIT ?",
      {ts, limit});
  for (auto& row : rows) {
    json ev;
    ev["event_id"] = row->get<std::string>(0);
    ev["expiry_ts"] = row->get<int64_t>(1);
    ev["ttl_seconds"] = row->get<int64_t>(2);
    if (!row->is_null(3)) ev["reason"] = row->get<std::string>(3);
    result.push_back(ev);
  }
  return result;
}

json EventExpiryStore::get_events_expiring_before_txn(
    LoggingTransaction& txn, int64_t before_ts, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT event_id, expiry_ts, ttl_seconds, reason "
      "FROM event_expiry WHERE expiry_ts <= ? AND is_expired = 0 "
      "ORDER BY expiry_ts ASC LIMIT ?",
      {before_ts, limit});
  for (auto& row : rows) {
    json ev;
    ev["event_id"] = row->get<std::string>(0);
    ev["expiry_ts"] = row->get<int64_t>(1);
    ev["ttl_seconds"] = row->get<int64_t>(2);
    if (!row->is_null(3)) ev["reason"] = row->get<std::string>(3);
    result.push_back(ev);
  }
  return result;
}

int64_t EventExpiryStore::count_expired_events_txn(LoggingTransaction& txn) {
  int64_t ts = now_ms();
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM event_expiry WHERE expiry_ts <= ? AND is_expired = 0",
      {ts});
  return row ? row->get<int64_t>(0) : 0;
}

bool EventExpiryStore::is_event_expired_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  int64_t ts = now_ms();
  auto row = txn.select_one(
      "SELECT 1 FROM event_expiry WHERE event_id = ? AND expiry_ts <= ?",
      {event_id, ts});
  return row && !row->is_null();
}

void EventExpiryStore::extend_event_expiry_txn(
    LoggingTransaction& txn, const std::string& event_id,
    int64_t additional_seconds) {
  int64_t ts = now_ms();
  txn.execute(
      "UPDATE event_expiry SET expiry_ts = expiry_ts + ?, "
      "ttl_seconds = ttl_seconds + ?, updated_ts = ? "
      "WHERE event_id = ?",
      {additional_seconds * 1000, additional_seconds, ts, event_id});
  txn.execute(
      "INSERT INTO event_expiry_log (event_id, action, detail, action_ts) "
      "VALUES (?, 'extend', ?, ?)",
      {event_id, "additional_seconds=" + std::to_string(additional_seconds), ts});
}

void EventExpiryStore::batch_set_expiry_txn(
    LoggingTransaction& txn, const std::vector<std::string>& event_ids,
    int64_t ttl_seconds) {
  int64_t ts = now_ms();
  int64_t expiry_ts = ts + (ttl_seconds * 1000);
  for (const auto& event_id : event_ids) {
    txn.execute(
        "INSERT INTO event_expiry "
        "(event_id, expiry_ts, ttl_seconds, is_expired, created_ts, updated_ts) "
        "VALUES (?, ?, ?, 0, ?, ?) "
        "ON CONFLICT (event_id) DO UPDATE SET "
        "expiry_ts = excluded.expiry_ts, "
        "ttl_seconds = excluded.ttl_seconds, "
        "updated_ts = excluded.updated_ts, "
        "is_expired = 0, "
        "cleanup_ts = NULL",
        {event_id, expiry_ts, ttl_seconds, ts, ts});
  }
}

int64_t EventExpiryStore::cleanup_expired_events_txn(
    LoggingTransaction& txn, int batch_size) {
  int64_t ts = now_ms();
  // Find expired events
  auto rows = txn.select(
      "SELECT event_id FROM event_expiry WHERE expiry_ts <= ? AND is_expired = 0 "
      "LIMIT ?",
      {ts, batch_size});
  int64_t cleaned = 0;
  for (auto& row : rows) {
    std::string event_id = row->get<std::string>(0);
    // Mark as expired with cleanup timestamp
    txn.execute(
        "UPDATE event_expiry SET is_expired = 1, cleanup_ts = ? "
        "WHERE event_id = ?",
        {ts, event_id});
    txn.execute(
        "INSERT INTO event_expiry_log (event_id, action, detail, action_ts) "
        "VALUES (?, 'cleanup', 'expired_event_cleaned', ?)",
        {event_id, ts});
    cleaned++;
  }
  return cleaned;
}

json EventExpiryStore::get_expiry_stats_txn(LoggingTransaction& txn) {
  json stats;
  int64_t ts = now_ms();
  auto total = txn.select_one("SELECT COUNT(*) FROM event_expiry");
  auto expired = txn.select_one(
      "SELECT COUNT(*) FROM event_expiry WHERE expiry_ts <= ? AND is_expired = 0",
      {ts});
  auto cleaned = txn.select_one(
      "SELECT COUNT(*) FROM event_expiry WHERE is_expired = 1");
  auto expiring_soon = txn.select_one(
      "SELECT COUNT(*) FROM event_expiry "
      "WHERE expiry_ts > ? AND expiry_ts <= ? AND is_expired = 0",
      {ts, ts + 3600000}); // within next hour
  stats["total_expiry_entries"] = total ? total->get<int64_t>(0) : 0;
  stats["expired_uncleaned"] = expired ? expired->get<int64_t>(0) : 0;
  stats["cleaned"] = cleaned ? cleaned->get<int64_t>(0) : 0;
  stats["expiring_within_hour"] = expiring_soon ? expiring_soon->get<int64_t>(0) : 0;
  return stats;
}

// ============================================================================
// 3. StickyEventsStore — sticky/pinned events per room
// ============================================================================

StickyEventsStore::StickyEventsStore(DatabasePool& db) : db_(db) {}

// ---- DDL ----
void StickyEventsStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS sticky_events (
      id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
      room_id TEXT NOT NULL,
      event_id TEXT NOT NULL,
      position INTEGER NOT NULL DEFAULT 0,
      label TEXT,
      sticky_since BIGINT NOT NULL,
      updated_ts BIGINT NOT NULL,
      UNIQUE (room_id, event_id)
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS sticky_events_room_pos_idx
      ON sticky_events (room_id, position);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS sticky_events_room_label_idx
      ON sticky_events (room_id, label);
  )SQL");
  txn.execute(R"SQL(
    CREATE UNIQUE INDEX IF NOT EXISTS sticky_events_room_event_idx
      ON sticky_events (room_id, event_id);
  )SQL");
}

// ---- Mark/unmark sticky ----
void StickyEventsStore::mark_sticky_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& event_id, const std::optional<std::string>& label) {
  int64_t ts = now_ms();
  // Determine next position: count existing sticky events + 1
  auto cnt = txn.select_one(
      "SELECT COALESCE(MAX(position), 0) + 1 FROM sticky_events WHERE room_id = ?",
      {room_id});
  int next_pos = cnt ? static_cast<int>(cnt->get<int64_t>(0)) : 1;
  std::string label_str = label.value_or("");
  txn.execute(
      "INSERT INTO sticky_events "
      "(room_id, event_id, position, label, sticky_since, updated_ts) "
      "VALUES (?, ?, ?, ?, ?, ?) "
      "ON CONFLICT (room_id, event_id) DO UPDATE SET "
      "label = COALESCE(excluded.label, sticky_events.label), "
      "updated_ts = excluded.updated_ts",
      {room_id, event_id, next_pos, label_str, ts, ts});
}

void StickyEventsStore::unmark_sticky_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& event_id) {
  // Get current position before deleting
  auto pos_row = txn.select_one(
      "SELECT position FROM sticky_events WHERE room_id = ? AND event_id = ?",
      {room_id, event_id});
  int removed_pos = pos_row ? static_cast<int>(pos_row->get<int64_t>(0)) : -1;

  txn.execute(
      "DELETE FROM sticky_events WHERE room_id = ? AND event_id = ?",
      {room_id, event_id});

  // Shift positions of remaining sticky events down
  if (removed_pos >= 0) {
    txn.execute(
        "UPDATE sticky_events SET position = position - 1 "
        "WHERE room_id = ? AND position > ?",
        {room_id, removed_pos});
  }
}

void StickyEventsStore::unmark_all_sticky_in_room_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  txn.execute("DELETE FROM sticky_events WHERE room_id = ?", {room_id});
}

bool StickyEventsStore::is_sticky_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& event_id) {
  auto row = txn.select_one(
      "SELECT 1 FROM sticky_events WHERE room_id = ? AND event_id = ?",
      {room_id, event_id});
  return row && !row->is_null();
}

// ---- List sticky events ----
json StickyEventsStore::list_sticky_events_txn(
    LoggingTransaction& txn, const std::string& room_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT event_id, position, label, sticky_since, updated_ts "
      "FROM sticky_events WHERE room_id = ? "
      "ORDER BY position ASC LIMIT ?",
      {room_id, limit});
  for (auto& row : rows) {
    json ev;
    ev["event_id"] = row->get<std::string>(0);
    ev["position"] = row->get<int64_t>(1);
    if (!row->is_null(2)) ev["label"] = row->get<std::string>(2);
    ev["sticky_since"] = row->get<int64_t>(3);
    ev["updated_ts"] = row->get<int64_t>(4);
    result.push_back(ev);
  }
  return result;
}

std::optional<json> StickyEventsStore::get_sticky_event_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& event_id) {
  auto row = txn.select_one(
      "SELECT event_id, position, label, sticky_since, updated_ts "
      "FROM sticky_events WHERE room_id = ? AND event_id = ?",
      {room_id, event_id});
  if (!row || row->is_null()) return std::nullopt;
  json ev;
  ev["event_id"] = row->get<std::string>(0);
  ev["position"] = row->get<int64_t>(1);
  if (!row->is_null(2)) ev["label"] = row->get<std::string>(2);
  ev["sticky_since"] = row->get<int64_t>(3);
  ev["updated_ts"] = row->get<int64_t>(4);
  return ev;
}

// ---- Reorder sticky events ----
void StickyEventsStore::reorder_sticky_events_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::vector<std::string>& ordered_event_ids) {
  int64_t ts = now_ms();
  for (size_t i = 0; i < ordered_event_ids.size(); i++) {
    txn.execute(
        "UPDATE sticky_events SET position = ?, updated_ts = ? "
        "WHERE room_id = ? AND event_id = ?",
        {static_cast<int>(i + 1), ts, room_id, ordered_event_ids[i]});
  }
}

void StickyEventsStore::set_sticky_position_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& event_id, int position) {
  int64_t ts = now_ms();
  // Get current position
  auto cur = txn.select_one(
      "SELECT position FROM sticky_events WHERE room_id = ? AND event_id = ?",
      {room_id, event_id});
  if (!cur || cur->is_null()) return;

  int cur_pos = static_cast<int>(cur->get<int64_t>(0));
  if (cur_pos == position) return;

  if (position > cur_pos) {
    // Moving down: shift positions in between
    txn.execute(
        "UPDATE sticky_events SET position = position - 1 "
        "WHERE room_id = ? AND position > ? AND position <= ?",
        {room_id, cur_pos, position});
  } else {
    // Moving up: shift positions in between
    txn.execute(
        "UPDATE sticky_events SET position = position + 1 "
        "WHERE room_id = ? AND position >= ? AND position < ?",
        {room_id, position, cur_pos});
  }
  txn.execute(
      "UPDATE sticky_events SET position = ?, updated_ts = ? "
      "WHERE room_id = ? AND event_id = ?",
      {position, ts, room_id, event_id});
}

void StickyEventsStore::shift_positions_for_insert_txn(
    LoggingTransaction& txn, const std::string& room_id, int from_position) {
  txn.execute(
      "UPDATE sticky_events SET position = position + 1 "
      "WHERE room_id = ? AND position >= ?",
      {room_id, from_position});
}

// ---- Counts ----
int64_t StickyEventsStore::count_sticky_events_txn(
    LoggingTransaction& txn, const std::string& room_id) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM sticky_events WHERE room_id = ?", {room_id});
  return row ? row->get<int64_t>(0) : 0;
}

int64_t StickyEventsStore::count_all_sticky_events_txn(LoggingTransaction& txn) {
  auto row = txn.select_one("SELECT COUNT(*) FROM sticky_events");
  return row ? row->get<int64_t>(0) : 0;
}

// ============================================================================
// 4. TaskSchedulerStore — scheduled tasks with priority queues
// ============================================================================

TaskSchedulerStore::TaskSchedulerStore(DatabasePool& db) : db_(db) {}

// ---- DDL ----
void TaskSchedulerStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS scheduled_tasks (
      id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
      task_type TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      priority INTEGER NOT NULL DEFAULT 0,
      scheduled_at_ts BIGINT NOT NULL,
      claimed_at_ts BIGINT,
      claimed_by TEXT,
      completed_at_ts BIGINT,
      error_json TEXT,
      task_group TEXT,
      retry_count INTEGER NOT NULL DEFAULT 0,
      max_retries INTEGER NOT NULL DEFAULT 5,
      next_retry_at_ts BIGINT,
      created_ts BIGINT NOT NULL
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS scheduled_tasks_status_prio_idx
      ON scheduled_tasks (status, priority DESC, scheduled_at_ts ASC);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS scheduled_tasks_type_idx
      ON scheduled_tasks (task_type, status);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS scheduled_tasks_group_idx
      ON scheduled_tasks (task_group);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS scheduled_tasks_next_retry_idx
      ON scheduled_tasks (status, next_retry_at_ts);
  )SQL");
}

// ---- Schedule a task ----
int64_t TaskSchedulerStore::schedule_task_txn(
    LoggingTransaction& txn, const std::string& task_type,
    const json& payload, int priority, int64_t scheduled_at_ts,
    const std::optional<std::string>& task_group) {
  int64_t ts = now_ms();
  if (scheduled_at_ts == 0) scheduled_at_ts = ts;
  std::string group_str = task_group.value_or("");
  txn.execute(
      "INSERT INTO scheduled_tasks "
      "(task_type, payload_json, status, priority, scheduled_at_ts, "
      "task_group, created_ts) "
      "VALUES (?, ?, 'pending', ?, ?, ?, ?)",
      {task_type, payload.dump(), priority, scheduled_at_ts, group_str, ts});
  auto row = txn.select_one("SELECT last_insert_rowid()");
  return row ? row->get<int64_t>(0) : -1;
}

// ---- Get pending tasks ----
json TaskSchedulerStore::get_pending_tasks_txn(
    LoggingTransaction& txn, int limit,
    const std::optional<std::string>& task_type) {
  int64_t ts = now_ms();
  json result = json::array();
  std::string sql =
      "SELECT id, task_type, payload_json, priority, scheduled_at_ts, "
      "retry_count, task_group, created_ts "
      "FROM scheduled_tasks WHERE status = 'pending' "
      "AND scheduled_at_ts <= ? ";
  std::vector<std::any> params = {ts};
  if (task_type.has_value()) {
    sql += "AND task_type = ? ";
    params.push_back(task_type.value());
  }
  sql += "ORDER BY priority DESC, scheduled_at_ts ASC LIMIT ?";
  params.push_back(limit);

  // NOTE: In the real codebase, txn.select() takes a vector of variant/any.
  // We inline the common case using string building.
  auto rows = txn.select(sql, params);
  for (auto& row : rows) {
    json t;
    t["id"] = row->get<int64_t>(0);
    t["task_type"] = row->get<std::string>(1);
    t["payload"] = json::parse(row->get<std::string>(2));
    t["priority"] = row->get<int64_t>(3);
    t["scheduled_at_ts"] = row->get<int64_t>(4);
    t["retry_count"] = row->get<int64_t>(5);
    if (!row->is_null(6)) t["task_group"] = row->get<std::string>(6);
    t["created_ts"] = row->get<int64_t>(7);
    result.push_back(t);
  }
  return result;
}

json TaskSchedulerStore::get_next_tasks_txn(
    LoggingTransaction& txn, int count) {
  return get_pending_tasks_txn(txn, count, std::nullopt);
}

// ---- Claim tasks ----
json TaskSchedulerStore::claim_tasks_txn(
    LoggingTransaction& txn, int count, const std::string& claimed_by) {
  int64_t ts = now_ms();
  // Get pending tasks
  auto tasks = get_pending_tasks_txn(txn, count, std::nullopt);
  json claimed = json::array();
  for (auto& task : tasks) {
    int64_t task_id = task["id"].get<int64_t>();
    txn.execute(
        "UPDATE scheduled_tasks SET status = 'in_progress', "
        "claimed_at_ts = ?, claimed_by = ? WHERE id = ? AND status = 'pending'",
        {ts, claimed_by, task_id});
    task["status"] = "in_progress";
    task["claimed_at_ts"] = ts;
    task["claimed_by"] = claimed_by;
    claimed.push_back(task);
  }
  return claimed;
}

// ---- Mark complete/failed ----
void TaskSchedulerStore::mark_task_completed_txn(
    LoggingTransaction& txn, int64_t task_id) {
  txn.execute(
      "UPDATE scheduled_tasks SET status = 'completed', completed_at_ts = ? "
      "WHERE id = ?",
      {now_ms(), task_id});
}

void TaskSchedulerStore::mark_task_failed_txn(
    LoggingTransaction& txn, int64_t task_id,
    const std::optional<std::string>& error) {
  int64_t ts = now_ms();
  std::string error_str = error.value_or("");
  txn.execute(
      "UPDATE scheduled_tasks SET status = 'failed', error_json = ?, "
      "completed_at_ts = ? WHERE id = ?",
      {error_str, ts, task_id});
}

// ---- Retry ----
void TaskSchedulerStore::retry_task_txn(
    LoggingTransaction& txn, int64_t task_id, int64_t retry_delay_seconds) {
  int64_t ts = now_ms();
  auto task = get_task_txn(txn, task_id);
  if (!task.has_value()) return;

  int64_t retry_count = (*task).value("retry_count", 0);
  int64_t max_retries = (*task).value("max_retries", kMaxRetries);
  if (retry_count >= max_retries) {
    // Exceeded max retries
    mark_task_failed_txn(txn, task_id,
                          "exceeded_max_retries (" + std::to_string(max_retries) + ")");
    return;
  }
  int64_t next_retry_at = ts + (retry_delay_seconds * 1000);
  txn.execute(
      "UPDATE scheduled_tasks SET status = 'pending', retry_count = retry_count + 1, "
      "next_retry_at_ts = ?, claimed_at_ts = NULL, claimed_by = NULL, "
      "completed_at_ts = NULL, error_json = NULL WHERE id = ?",
      {next_retry_at, task_id});
}

json TaskSchedulerStore::get_task_retry_info_txn(
    LoggingTransaction& txn, int64_t task_id) {
  json info;
  auto row = txn.select_one(
      "SELECT retry_count, max_retries, next_retry_at_ts, error_json "
      "FROM scheduled_tasks WHERE id = ?",
      {task_id});
  if (row && !row->is_null()) {
    info["retry_count"] = row->get<int64_t>(0);
    info["max_retries"] = row->get<int64_t>(1);
    if (!row->is_null(2)) info["next_retry_at_ts"] = row->get<int64_t>(2);
    if (!row->is_null(3)) info["error"] = row->get<std::string>(3);
  }
  return info;
}

std::optional<json> TaskSchedulerStore::get_task_txn(
    LoggingTransaction& txn, int64_t task_id) {
  auto row = txn.select_one(
      "SELECT id, task_type, payload_json, status, priority, scheduled_at_ts, "
      "claimed_at_ts, claimed_by, completed_at_ts, error_json, task_group, "
      "retry_count, max_retries, next_retry_at_ts, created_ts "
      "FROM scheduled_tasks WHERE id = ?",
      {task_id});
  if (!row || row->is_null()) return std::nullopt;
  json t;
  t["id"] = row->get<int64_t>(0);
  t["task_type"] = row->get<std::string>(1);
  t["payload"] = json::parse(row->get<std::string>(2));
  t["status"] = row->get<std::string>(3);
  t["priority"] = row->get<int64_t>(4);
  t["scheduled_at_ts"] = row->get<int64_t>(5);
  if (!row->is_null(6)) t["claimed_at_ts"] = row->get<int64_t>(6);
  if (!row->is_null(7)) t["claimed_by"] = row->get<std::string>(7);
  if (!row->is_null(8)) t["completed_at_ts"] = row->get<int64_t>(8);
  if (!row->is_null(9)) t["error"] = row->get<std::string>(9);
  if (!row->is_null(10)) t["task_group"] = row->get<std::string>(10);
  t["retry_count"] = row->get<int64_t>(11);
  t["max_retries"] = row->get<int64_t>(12);
  if (!row->is_null(13)) t["next_retry_at_ts"] = row->get<int64_t>(13);
  t["created_ts"] = row->get<int64_t>(14);
  return t;
}

void TaskSchedulerStore::delete_task_txn(
    LoggingTransaction& txn, int64_t task_id) {
  txn.execute("DELETE FROM scheduled_tasks WHERE id = ?", {task_id});
}

int64_t TaskSchedulerStore::cleanup_completed_tasks_txn(
    LoggingTransaction& txn, int64_t older_than_seconds) {
  int64_t cutoff = now_ms() - (older_than_seconds * 1000);
  txn.execute(
      "DELETE FROM scheduled_tasks WHERE status IN ('completed', 'failed') "
      "AND completed_at_ts < ?",
      {cutoff});
  auto row = txn.select_one("SELECT changes()");
  return row ? row->get<int64_t>(0) : 0;
}

int64_t TaskSchedulerStore::count_tasks_by_status_txn(
    LoggingTransaction& txn, const std::string& status) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM scheduled_tasks WHERE status = ?", {status});
  return row ? row->get<int64_t>(0) : 0;
}

int64_t TaskSchedulerStore::count_pending_tasks_txn(LoggingTransaction& txn) {
  return count_tasks_by_status_txn(txn, "pending");
}

json TaskSchedulerStore::get_stale_in_progress_tasks_txn(
    LoggingTransaction& txn, int64_t stale_after_seconds, int limit) {
  int64_t cutoff = now_ms() - (stale_after_seconds * 1000);
  json result = json::array();
  auto rows = txn.select(
      "SELECT id, task_type, claimed_by, claimed_at_ts "
      "FROM scheduled_tasks WHERE status = 'in_progress' "
      "AND claimed_at_ts < ? ORDER BY claimed_at_ts ASC LIMIT ?",
      {cutoff, limit});
  for (auto& row : rows) {
    json t;
    t["id"] = row->get<int64_t>(0);
    t["task_type"] = row->get<std::string>(1);
    if (!row->is_null(2)) t["claimed_by"] = row->get<std::string>(2);
    t["claimed_at_ts"] = row->get<int64_t>(3);
    result.push_back(t);
  }
  return result;
}

std::vector<int64_t> TaskSchedulerStore::schedule_tasks_bulk_txn(
    LoggingTransaction& txn, const std::string& task_type,
    const std::vector<json>& payloads, int priority) {
  std::vector<int64_t> ids;
  for (const auto& payload : payloads) {
    int64_t id = schedule_task_txn(txn, task_type, payload, priority);
    if (id >= 0) ids.push_back(id);
  }
  return ids;
}

// ============================================================================
// 5. UserErasureStore — GDPR/user erasure request management
// ============================================================================

UserErasureStore::UserErasureStore(DatabasePool& db) : db_(db) {}

// ---- DDL ----
void UserErasureStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS user_erasure_requests (
      id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      status_detail TEXT,
      requested_by TEXT,
      items_purged BIGINT,
      created_ts BIGINT NOT NULL,
      updated_ts BIGINT NOT NULL,
      completed_ts BIGINT
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS user_erasure_user_idx
      ON user_erasure_requests (user_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS user_erasure_status_idx
      ON user_erasure_requests (status);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS user_erasure_user_status_idx
      ON user_erasure_requests (user_id, status);
  )SQL");

  // Purge action log
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS user_erasure_purge_log (
      id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
      request_id BIGINT NOT NULL,
      data_type TEXT NOT NULL,
      data_id TEXT NOT NULL,
      purge_details_json TEXT,
      purge_ts BIGINT NOT NULL,
      FOREIGN KEY (request_id) REFERENCES user_erasure_requests(id)
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS user_erasure_purge_request_idx
      ON user_erasure_purge_log (request_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS user_erasure_purge_type_idx
      ON user_erasure_purge_log (data_type);
  )SQL");
}

// ---- Create erasure request ----
int64_t UserErasureStore::create_erasure_request_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::optional<std::string>& requested_by) {
  int64_t ts = now_ms();
  std::string req_by = requested_by.value_or(user_id);
  txn.execute(
      "INSERT INTO user_erasure_requests "
      "(user_id, status, requested_by, created_ts, updated_ts) "
      "VALUES (?, 'pending', ?, ?, ?)",
      {user_id, req_by, ts, ts});
  auto row = txn.select_one("SELECT last_insert_rowid()");
  return row ? row->get<int64_t>(0) : -1;
}

// ---- Get erasure request ----
std::optional<json> UserErasureStore::get_erasure_request_txn(
    LoggingTransaction& txn, int64_t request_id) {
  auto row = txn.select_one(
      "SELECT id, user_id, status, status_detail, requested_by, "
      "items_purged, created_ts, updated_ts, completed_ts "
      "FROM user_erasure_requests WHERE id = ?",
      {request_id});
  if (!row || row->is_null()) return std::nullopt;
  json r;
  r["id"] = row->get<int64_t>(0);
  r["user_id"] = row->get<std::string>(1);
  r["status"] = row->get<std::string>(2);
  if (!row->is_null(3)) r["status_detail"] = row->get<std::string>(3);
  if (!row->is_null(4)) r["requested_by"] = row->get<std::string>(4);
  if (!row->is_null(5)) r["items_purged"] = row->get<int64_t>(5);
  r["created_ts"] = row->get<int64_t>(6);
  r["updated_ts"] = row->get<int64_t>(7);
  if (!row->is_null(8)) r["completed_ts"] = row->get<int64_t>(8);
  return r;
}

std::optional<json> UserErasureStore::get_erasure_request_for_user_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT id, user_id, status, status_detail, requested_by, "
      "items_purged, created_ts, updated_ts, completed_ts "
      "FROM user_erasure_requests WHERE user_id = ? "
      "ORDER BY created_ts DESC LIMIT 1",
      {user_id});
  if (!row || row->is_null()) return std::nullopt;
  json r;
  r["id"] = row->get<int64_t>(0);
  r["user_id"] = row->get<std::string>(1);
  r["status"] = row->get<std::string>(2);
  if (!row->is_null(3)) r["status_detail"] = row->get<std::string>(3);
  if (!row->is_null(4)) r["requested_by"] = row->get<std::string>(4);
  if (!row->is_null(5)) r["items_purged"] = row->get<int64_t>(5);
  r["created_ts"] = row->get<int64_t>(6);
  r["updated_ts"] = row->get<int64_t>(7);
  if (!row->is_null(8)) r["completed_ts"] = row->get<int64_t>(8);
  return r;
}

// ---- Update status ----
void UserErasureStore::update_erasure_status_txn(
    LoggingTransaction& txn, int64_t request_id,
    const std::string& status, const std::optional<std::string>& status_detail) {
  int64_t ts = now_ms();
  std::string detail = status_detail.value_or("");
  if (status == "completed" || status == "failed") {
    txn.execute(
        "UPDATE user_erasure_requests SET status = ?, status_detail = ?, "
        "updated_ts = ?, completed_ts = ? WHERE id = ?",
        {status, detail, ts, ts, request_id});
  } else {
    txn.execute(
        "UPDATE user_erasure_requests SET status = ?, status_detail = ?, "
        "updated_ts = ? WHERE id = ?",
        {status, detail, ts, request_id});
  }
}

void UserErasureStore::mark_erasure_in_progress_txn(
    LoggingTransaction& txn, int64_t request_id) {
  update_erasure_status_txn(txn, request_id, "in_progress",
                             "Erasure processing started");
}

void UserErasureStore::mark_erasure_completed_txn(
    LoggingTransaction& txn, int64_t request_id,
    const std::optional<int64_t>& items_purged) {
  int64_t ts = now_ms();
  if (items_purged.has_value()) {
    txn.execute(
        "UPDATE user_erasure_requests SET status = 'completed', "
        "status_detail = 'Erasure completed successfully', "
        "items_purged = ?, updated_ts = ?, completed_ts = ? WHERE id = ?",
        {items_purged.value(), ts, ts, request_id});
  } else {
    update_erasure_status_txn(txn, request_id, "completed",
                               "Erasure completed successfully");
  }
}

void UserErasureStore::mark_erasure_failed_txn(
    LoggingTransaction& txn, int64_t request_id, const std::string& error) {
  update_erasure_status_txn(txn, request_id, "failed", error);
}

void UserErasureStore::cancel_erasure_request_txn(
    LoggingTransaction& txn, int64_t request_id, const std::string& reason) {
  update_erasure_status_txn(txn, request_id, "cancelled", reason);
}

// ---- List erasure requests ----
json UserErasureStore::list_erasure_requests_txn(
    LoggingTransaction& txn, const std::optional<std::string>& status,
    int limit, int64_t offset) {
  json result = json::array();
  std::string sql =
      "SELECT id, user_id, status, status_detail, requested_by, "
      "items_purged, created_ts, updated_ts, completed_ts "
      "FROM user_erasure_requests ";
  std::vector<std::any> params;
  if (status.has_value()) {
    sql += "WHERE status = ? ";
    params.push_back(status.value());
  }
  sql += "ORDER BY created_ts DESC LIMIT ? OFFSET ?";
  params.push_back(limit);
  params.push_back(offset);

  auto rows = txn.select(sql, params);
  for (auto& row : rows) {
    json r;
    r["id"] = row->get<int64_t>(0);
    r["user_id"] = row->get<std::string>(1);
    r["status"] = row->get<std::string>(2);
    if (!row->is_null(3)) r["status_detail"] = row->get<std::string>(3);
    if (!row->is_null(4)) r["requested_by"] = row->get<std::string>(4);
    if (!row->is_null(5)) r["items_purged"] = row->get<int64_t>(5);
    r["created_ts"] = row->get<int64_t>(6);
    r["updated_ts"] = row->get<int64_t>(7);
    if (!row->is_null(8)) r["completed_ts"] = row->get<int64_t>(8);
    result.push_back(r);
  }
  return result;
}

json UserErasureStore::list_user_erasure_requests_txn(
    LoggingTransaction& txn, const std::string& user_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT id, status, status_detail, requested_by, items_purged, "
      "created_ts, updated_ts, completed_ts "
      "FROM user_erasure_requests WHERE user_id = ? "
      "ORDER BY created_ts DESC LIMIT ?",
      {user_id, limit});
  for (auto& row : rows) {
    json r;
    r["id"] = row->get<int64_t>(0);
    r["status"] = row->get<std::string>(1);
    if (!row->is_null(2)) r["status_detail"] = row->get<std::string>(2);
    if (!row->is_null(3)) r["requested_by"] = row->get<std::string>(3);
    if (!row->is_null(4)) r["items_purged"] = row->get<int64_t>(4);
    r["created_ts"] = row->get<int64_t>(5);
    r["updated_ts"] = row->get<int64_t>(6);
    if (!row->is_null(7)) r["completed_ts"] = row->get<int64_t>(7);
    result.push_back(r);
  }
  return result;
}

int64_t UserErasureStore::count_erasure_requests_txn(
    LoggingTransaction& txn, const std::optional<std::string>& status) {
  if (status.has_value()) {
    auto row = txn.select_one(
        "SELECT COUNT(*) FROM user_erasure_requests WHERE status = ?",
        {status.value()});
    return row ? row->get<int64_t>(0) : 0;
  }
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM user_erasure_requests");
  return row ? row->get<int64_t>(0) : 0;
}

bool UserErasureStore::has_pending_erasure_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT 1 FROM user_erasure_requests "
      "WHERE user_id = ? AND status IN ('pending', 'in_progress') LIMIT 1",
      {user_id});
  return row && !row->is_null();
}

// ---- Purge operations ----
void UserErasureStore::record_purge_action_txn(
    LoggingTransaction& txn, int64_t request_id,
    const std::string& data_type, const std::string& data_id,
    const json& purge_details) {
  txn.execute(
      "INSERT INTO user_erasure_purge_log "
      "(request_id, data_type, data_id, purge_details_json, purge_ts) "
      "VALUES (?, ?, ?, ?, ?)",
      {request_id, data_type, data_id, purge_details.dump(), now_ms()});
}

json UserErasureStore::get_purge_actions_for_request_txn(
    LoggingTransaction& txn, int64_t request_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT id, data_type, data_id, purge_details_json, purge_ts "
      "FROM user_erasure_purge_log WHERE request_id = ? "
      "ORDER BY purge_ts ASC LIMIT ?",
      {request_id, limit});
  for (auto& row : rows) {
    json a;
    a["id"] = row->get<int64_t>(0);
    a["data_type"] = row->get<std::string>(1);
    a["data_id"] = row->get<std::string>(2);
    if (!row->is_null(3)) {
      a["purge_details"] = json::parse(row->get<std::string>(3));
    }
    a["purge_ts"] = row->get<int64_t>(4);
    result.push_back(a);
  }
  return result;
}

int64_t UserErasureStore::count_purged_items_txn(
    LoggingTransaction& txn, int64_t request_id) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM user_erasure_purge_log WHERE request_id = ?",
      {request_id});
  return row ? row->get<int64_t>(0) : 0;
}

json UserErasureStore::get_erasure_stats_txn(LoggingTransaction& txn) {
  json stats;
  auto pending = txn.select_one(
      "SELECT COUNT(*) FROM user_erasure_requests WHERE status = 'pending'");
  auto in_progress = txn.select_one(
      "SELECT COUNT(*) FROM user_erasure_requests WHERE status = 'in_progress'");
  auto completed = txn.select_one(
      "SELECT COUNT(*) FROM user_erasure_requests WHERE status = 'completed'");
  auto failed = txn.select_one(
      "SELECT COUNT(*) FROM user_erasure_requests WHERE status = 'failed'");
  auto cancelled = txn.select_one(
      "SELECT COUNT(*) FROM user_erasure_requests WHERE status = 'cancelled'");
  auto total_purged = txn.select_one(
      "SELECT COUNT(*) FROM user_erasure_purge_log");

  stats["pending"] = pending ? pending->get<int64_t>(0) : 0;
  stats["in_progress"] = in_progress ? in_progress->get<int64_t>(0) : 0;
  stats["completed"] = completed ? completed->get<int64_t>(0) : 0;
  stats["failed"] = failed ? failed->get<int64_t>(0) : 0;
  stats["cancelled"] = cancelled ? cancelled->get<int64_t>(0) : 0;
  stats["total_items_purged"] = total_purged ? total_purged->get<int64_t>(0) : 0;
  return stats;
}

// ============================================================================
// 6. SessionStore — generic session CRUD
// ============================================================================

SessionStore::SessionStore(DatabasePool& db) : db_(db) {}

// ---- DDL ----
void SessionStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS generic_sessions (
      session_id TEXT NOT NULL PRIMARY KEY,
      session_type TEXT NOT NULL,
      user_id TEXT NOT NULL,
      device_id TEXT,
      data_json TEXT NOT NULL,
      expires_at_ts BIGINT,
      created_ts BIGINT NOT NULL,
      updated_ts BIGINT NOT NULL,
      last_accessed_ts BIGINT NOT NULL
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS generic_sessions_user_idx
      ON generic_sessions (user_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS generic_sessions_type_idx
      ON generic_sessions (session_type);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS generic_sessions_expiry_idx
      ON generic_sessions (expires_at_ts);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS generic_sessions_user_device_idx
      ON generic_sessions (user_id, device_id);
  )SQL");
}

// ---- Set session ----
void SessionStore::set_session_txn(
    LoggingTransaction& txn, const std::string& session_id,
    const std::string& session_type, const std::string& user_id,
    const json& data, int64_t ttl_seconds,
    const std::optional<std::string>& device_id) {
  int64_t ts = now_ms();
  int64_t expires_at = ttl_seconds > 0 ? ts + (ttl_seconds * 1000) : 0;
  std::string dev_id = device_id.value_or("");
  txn.execute(
      "INSERT INTO generic_sessions "
      "(session_id, session_type, user_id, device_id, data_json, "
      "expires_at_ts, created_ts, updated_ts, last_accessed_ts) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT (session_id) DO UPDATE SET "
      "session_type = excluded.session_type, "
      "user_id = excluded.user_id, "
      "device_id = COALESCE(excluded.device_id, generic_sessions.device_id), "
      "data_json = excluded.data_json, "
      "expires_at_ts = excluded.expires_at_ts, "
      "updated_ts = excluded.updated_ts, "
      "last_accessed_ts = excluded.last_accessed_ts",
      {session_id, session_type, user_id, dev_id, data.dump(),
       expires_at, ts, ts, ts});
}

// ---- Get session ----
std::optional<json> SessionStore::get_session_txn(
    LoggingTransaction& txn, const std::string& session_id) {
  auto row = txn.select_one(
      "SELECT session_id, session_type, user_id, device_id, data_json, "
      "expires_at_ts, created_ts, updated_ts, last_accessed_ts "
      "FROM generic_sessions WHERE session_id = ?",
      {session_id});
  if (!row || row->is_null()) return std::nullopt;

  // Check if expired
  if (!row->is_null(5)) {
    int64_t expires_at = row->get<int64_t>(5);
    if (expires_at > 0 && expires_at <= now_ms()) {
      return std::nullopt; // Expired
    }
  }

  // Update last_accessed
  txn.execute(
      "UPDATE generic_sessions SET last_accessed_ts = ? WHERE session_id = ?",
      {now_ms(), session_id});

  json s;
  s["session_id"] = row->get<std::string>(0);
  s["session_type"] = row->get<std::string>(1);
  s["user_id"] = row->get<std::string>(2);
  if (!row->is_null(3)) s["device_id"] = row->get<std::string>(3);
  s["data"] = json::parse(row->get<std::string>(4));
  if (!row->is_null(5)) s["expires_at_ts"] = row->get<int64_t>(5);
  s["created_ts"] = row->get<int64_t>(6);
  s["updated_ts"] = row->get<int64_t>(7);
  s["last_accessed_ts"] = row->get<int64_t>(8);
  return s;
}

// ---- Get sessions for a user ----
json SessionStore::get_sessions_for_user_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::optional<std::string>& session_type, int limit) {
  int64_t ts = now_ms();
  json result = json::array();
  std::string sql =
      "SELECT session_id, session_type, device_id, data_json, "
      "expires_at_ts, created_ts, updated_ts, last_accessed_ts "
      "FROM generic_sessions WHERE user_id = ? "
      "AND (expires_at_ts IS NULL OR expires_at_ts > ?) ";
  std::vector<std::any> params = {user_id, ts};
  if (session_type.has_value()) {
    sql += "AND session_type = ? ";
    params.push_back(session_type.value());
  }
  sql += "ORDER BY last_accessed_ts DESC LIMIT ?";
  params.push_back(limit);

  auto rows = txn.select(sql, params);
  for (auto& row : rows) {
    json s;
    s["session_id"] = row->get<std::string>(0);
    s["session_type"] = row->get<std::string>(1);
    if (!row->is_null(2)) s["device_id"] = row->get<std::string>(2);
    s["data"] = json::parse(row->get<std::string>(3));
    if (!row->is_null(4)) s["expires_at_ts"] = row->get<int64_t>(4);
    s["created_ts"] = row->get<int64_t>(5);
    s["updated_ts"] = row->get<int64_t>(6);
    s["last_accessed_ts"] = row->get<int64_t>(7);
    result.push_back(s);
  }
  return result;
}

json SessionStore::get_sessions_for_device_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id) {
  int64_t ts = now_ms();
  json result = json::array();
  auto rows = txn.select(
      "SELECT session_id, session_type, data_json, expires_at_ts, "
      "created_ts, updated_ts, last_accessed_ts "
      "FROM generic_sessions WHERE user_id = ? AND device_id = ? "
      "AND (expires_at_ts IS NULL OR expires_at_ts > ?) "
      "ORDER BY last_accessed_ts DESC",
      {user_id, device_id, ts});
  for (auto& row : rows) {
    json s;
    s["session_id"] = row->get<std::string>(0);
    s["session_type"] = row->get<std::string>(1);
    s["data"] = json::parse(row->get<std::string>(2));
    if (!row->is_null(3)) s["expires_at_ts"] = row->get<int64_t>(3);
    s["created_ts"] = row->get<int64_t>(4);
    s["updated_ts"] = row->get<int64_t>(5);
    s["last_accessed_ts"] = row->get<int64_t>(6);
    result.push_back(s);
  }
  return result;
}

// ---- Update/Extend/Refresh ----
void SessionStore::update_session_data_txn(
    LoggingTransaction& txn, const std::string& session_id,
    const json& data) {
  txn.execute(
      "UPDATE generic_sessions SET data_json = ?, updated_ts = ? "
      "WHERE session_id = ?",
      {data.dump(), now_ms(), session_id});
}

void SessionStore::extend_session_txn(
    LoggingTransaction& txn, const std::string& session_id,
    int64_t additional_seconds) {
  int64_t ts = now_ms();
  txn.execute(
      "UPDATE generic_sessions SET "
      "expires_at_ts = COALESCE(expires_at_ts, ?) + ?, "
      "updated_ts = ? WHERE session_id = ?",
      {ts, additional_seconds * 1000, ts, session_id});
}

void SessionStore::refresh_session_txn(
    LoggingTransaction& txn, const std::string& session_id,
    int64_t ttl_seconds) {
  int64_t ts = now_ms();
  int64_t expires_at = ttl_seconds > 0 ? ts + (ttl_seconds * 1000) : 0;
  txn.execute(
      "UPDATE generic_sessions SET expires_at_ts = ?, "
      "updated_ts = ?, last_accessed_ts = ? WHERE session_id = ?",
      {expires_at, ts, ts, session_id});
}

// ---- Check valid ----
bool SessionStore::is_session_valid_txn(
    LoggingTransaction& txn, const std::string& session_id) {
  int64_t ts = now_ms();
  auto row = txn.select_one(
      "SELECT 1 FROM generic_sessions WHERE session_id = ? "
      "AND (expires_at_ts IS NULL OR expires_at_ts > ?)",
      {session_id, ts});
  return row && !row->is_null();
}

// ---- Delete ----
void SessionStore::delete_session_txn(
    LoggingTransaction& txn, const std::string& session_id) {
  txn.execute("DELETE FROM generic_sessions WHERE session_id = ?",
              {session_id});
}

void SessionStore::delete_user_sessions_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  txn.execute("DELETE FROM generic_sessions WHERE user_id = ?", {user_id});
}

void SessionStore::delete_device_sessions_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id) {
  txn.execute(
      "DELETE FROM generic_sessions WHERE user_id = ? AND device_id = ?",
      {user_id, device_id});
}

// ---- Cleanup ----
int64_t SessionStore::cleanup_expired_sessions_txn(
    LoggingTransaction& txn, int batch_size) {
  int64_t ts = now_ms();
  txn.execute(
      "DELETE FROM generic_sessions WHERE expires_at_ts IS NOT NULL "
      "AND expires_at_ts <= ? LIMIT ?",
      {ts, batch_size});
  auto row = txn.select_one("SELECT changes()");
  return row ? row->get<int64_t>(0) : 0;
}

// ---- Counts ----
int64_t SessionStore::count_active_sessions_txn(
    LoggingTransaction& txn, const std::optional<std::string>& user_id) {
  int64_t ts = now_ms();
  if (user_id.has_value()) {
    auto row = txn.select_one(
        "SELECT COUNT(*) FROM generic_sessions WHERE user_id = ? "
        "AND (expires_at_ts IS NULL OR expires_at_ts > ?)",
        {user_id.value(), ts});
    return row ? row->get<int64_t>(0) : 0;
  }
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM generic_sessions "
      "WHERE expires_at_ts IS NULL OR expires_at_ts > ?",
      {ts});
  return row ? row->get<int64_t>(0) : 0;
}

int64_t SessionStore::count_sessions_by_type_txn(
    LoggingTransaction& txn, const std::string& session_type) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM generic_sessions WHERE session_type = ?",
      {session_type});
  return row ? row->get<int64_t>(0) : 0;
}

// ---- Stats ----
json SessionStore::get_session_stats_txn(LoggingTransaction& txn) {
  int64_t ts = now_ms();
  json stats;
  auto total = txn.select_one("SELECT COUNT(*) FROM generic_sessions");
  auto active = txn.select_one(
      "SELECT COUNT(*) FROM generic_sessions "
      "WHERE expires_at_ts IS NULL OR expires_at_ts > ?",
      {ts});
  auto expired = txn.select_one(
      "SELECT COUNT(*) FROM generic_sessions "
      "WHERE expires_at_ts IS NOT NULL AND expires_at_ts <= ?",
      {ts});

  stats["total_sessions"] = total ? total->get<int64_t>(0) : 0;
  stats["active_sessions"] = active ? active->get<int64_t>(0) : 0;
  stats["expired_sessions"] = expired ? expired->get<int64_t>(0) : 0;
  return stats;
}

// ---- Batch operations ----
void SessionStore::set_sessions_bulk_txn(
    LoggingTransaction& txn,
    const std::vector<std::tuple<std::string, std::string, std::string, json, int64_t>>& sessions) {
  for (const auto& [session_id, session_type, user_id, data, ttl_seconds] : sessions) {
    set_session_txn(txn, session_id, session_type, user_id, data, ttl_seconds);
  }
}

// ============================================================================
// 7. OpenIdStore — OpenID token management
// ============================================================================

OpenIdStore::OpenIdStore(DatabasePool& db) : db_(db) {}

// ---- DDL ----
void OpenIdStore::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS open_id_tokens (
      token TEXT NOT NULL PRIMARY KEY,
      user_id TEXT NOT NULL,
      matrix_server_name TEXT,
      expires_at_ts BIGINT NOT NULL,
      is_used INTEGER NOT NULL DEFAULT 0,
      used_at_ts BIGINT,
      created_ts BIGINT NOT NULL
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS open_id_tokens_user_idx
      ON open_id_tokens (user_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS open_id_tokens_expiry_idx
      ON open_id_tokens (expires_at_ts);
  )SQL");
}

// ---- Generate token ----
std::string OpenIdStore::generate_token_txn(
    LoggingTransaction& txn, const std::string& user_id,
    int64_t ttl_seconds, const std::optional<std::string>& matrix_server_name) {
  int64_t ts = now_ms();
  int64_t expires_at = ts + (ttl_seconds * 1000);
  std::string token = generate_random_token(64);
  std::string server = matrix_server_name.value_or("");

  txn.execute(
      "INSERT INTO open_id_tokens "
      "(token, user_id, matrix_server_name, expires_at_ts, created_ts) "
      "VALUES (?, ?, ?, ?, ?)",
      {token, user_id, server, expires_at, ts});
  return token;
}

// ---- Validate token ----
std::optional<json> OpenIdStore::validate_token_txn(
    LoggingTransaction& txn, const std::string& token) {
  int64_t ts = now_ms();
  auto row = txn.select_one(
      "SELECT token, user_id, matrix_server_name, expires_at_ts, is_used, "
      "used_at_ts, created_ts "
      "FROM open_id_tokens WHERE token = ? "
      "AND expires_at_ts > ? AND is_used = 0",
      {token, ts});
  if (!row || row->is_null()) return std::nullopt;

  json result;
  result["token"] = row->get<std::string>(0);
  result["user_id"] = row->get<std::string>(1);
  if (!row->is_null(2)) result["matrix_server_name"] = row->get<std::string>(2);
  result["expires_at_ts"] = row->get<int64_t>(3);
  result["is_used"] = (row->get<int64_t>(4) != 0);
  if (!row->is_null(5)) result["used_at_ts"] = row->get<int64_t>(5);
  result["created_ts"] = row->get<int64_t>(6);
  return result;
}

// ---- Revoke ----
void OpenIdStore::revoke_token_txn(
    LoggingTransaction& txn, const std::string& token) {
  txn.execute("DELETE FROM open_id_tokens WHERE token = ?", {token});
}

int64_t OpenIdStore::revoke_user_tokens_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  txn.execute("DELETE FROM open_id_tokens WHERE user_id = ?", {user_id});
  auto row = txn.select_one("SELECT changes()");
  return row ? row->get<int64_t>(0) : 0;
}

// ---- Get token info ----
std::optional<json> OpenIdStore::get_token_info_txn(
    LoggingTransaction& txn, const std::string& token) {
  auto row = txn.select_one(
      "SELECT token, user_id, matrix_server_name, expires_at_ts, is_used, "
      "used_at_ts, created_ts "
      "FROM open_id_tokens WHERE token = ?",
      {token});
  if (!row || row->is_null()) return std::nullopt;

  json result;
  result["token"] = row->get<std::string>(0);
  result["user_id"] = row->get<std::string>(1);
  if (!row->is_null(2)) result["matrix_server_name"] = row->get<std::string>(2);
  result["expires_at_ts"] = row->get<int64_t>(3);
  result["is_used"] = (row->get<int64_t>(4) != 0);
  if (!row->is_null(5)) result["used_at_ts"] = row->get<int64_t>(5);
  result["created_ts"] = row->get<int64_t>(6);
  return result;
}

// ---- Get user tokens ----
json OpenIdStore::get_user_tokens_txn(
    LoggingTransaction& txn, const std::string& user_id, int limit) {
  int64_t ts = now_ms();
  json result = json::array();
  auto rows = txn.select(
      "SELECT token, matrix_server_name, expires_at_ts, is_used, used_at_ts, created_ts "
      "FROM open_id_tokens WHERE user_id = ? AND expires_at_ts > ? "
      "ORDER BY created_ts DESC LIMIT ?",
      {user_id, ts, limit});
  for (auto& row : rows) {
    json t;
    t["token"] = row->get<std::string>(0);
    if (!row->is_null(1)) t["matrix_server_name"] = row->get<std::string>(1);
    t["expires_at_ts"] = row->get<int64_t>(2);
    t["is_used"] = (row->get<int64_t>(3) != 0);
    if (!row->is_null(4)) t["used_at_ts"] = row->get<int64_t>(4);
    t["created_ts"] = row->get<int64_t>(5);
    result.push_back(t);
  }
  return result;
}

// ---- Mark used ----
bool OpenIdStore::is_token_used_txn(
    LoggingTransaction& txn, const std::string& token) {
  auto row = txn.select_one(
      "SELECT is_used FROM open_id_tokens WHERE token = ?", {token});
  return row && !row->is_null() && row->get<int64_t>(0) != 0;
}

void OpenIdStore::mark_token_used_txn(
    LoggingTransaction& txn, const std::string& token) {
  txn.execute(
      "UPDATE open_id_tokens SET is_used = 1, used_at_ts = ? WHERE token = ?",
      {now_ms(), token});
}

// ---- Cleanup ----
int64_t OpenIdStore::cleanup_expired_tokens_txn(
    LoggingTransaction& txn, int batch_size) {
  int64_t ts = now_ms();
  txn.execute(
      "DELETE FROM open_id_tokens WHERE expires_at_ts <= ? LIMIT ?",
      {ts, batch_size});
  auto row = txn.select_one("SELECT changes()");
  return row ? row->get<int64_t>(0) : 0;
}

// ---- Counts ----
int64_t OpenIdStore::count_active_tokens_txn(
    LoggingTransaction& txn, const std::optional<std::string>& user_id) {
  int64_t ts = now_ms();
  if (user_id.has_value()) {
    auto row = txn.select_one(
        "SELECT COUNT(*) FROM open_id_tokens "
        "WHERE user_id = ? AND expires_at_ts > ? AND is_used = 0",
        {user_id.value(), ts});
    return row ? row->get<int64_t>(0) : 0;
  }
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM open_id_tokens "
      "WHERE expires_at_ts > ? AND is_used = 0",
      {ts});
  return row ? row->get<int64_t>(0) : 0;
}

// ---- Verify token for user ----
bool OpenIdStore::verify_token_for_user_txn(
    LoggingTransaction& txn, const std::string& token,
    const std::string& user_id) {
  int64_t ts = now_ms();
  auto row = txn.select_one(
      "SELECT 1 FROM open_id_tokens "
      "WHERE token = ? AND user_id = ? AND expires_at_ts > ? AND is_used = 0",
      {token, user_id, ts});
  return row && !row->is_null();
}

// ---- Stats ----
json OpenIdStore::get_token_stats_txn(LoggingTransaction& txn) {
  int64_t ts = now_ms();
  json stats;
  auto total = txn.select_one("SELECT COUNT(*) FROM open_id_tokens");
  auto active = txn.select_one(
      "SELECT COUNT(*) FROM open_id_tokens "
      "WHERE expires_at_ts > ? AND is_used = 0",
      {ts});
  auto used = txn.select_one(
      "SELECT COUNT(*) FROM open_id_tokens WHERE is_used = 1");
  auto expired = txn.select_one(
      "SELECT COUNT(*) FROM open_id_tokens WHERE expires_at_ts <= ?",
      {ts});
  auto unique_users = txn.select_one(
      "SELECT COUNT(DISTINCT user_id) FROM open_id_tokens");

  stats["total_tokens"] = total ? total->get<int64_t>(0) : 0;
  stats["active_tokens"] = active ? active->get<int64_t>(0) : 0;
  stats["used_tokens"] = used ? used->get<int64_t>(0) : 0;
  stats["expired_tokens"] = expired ? expired->get<int64_t>(0) : 0;
  stats["unique_users"] = unique_users ? unique_users->get<int64_t>(0) : 0;
  return stats;
}

// ============================================================================
// 8. AccountDataSyncStore — incremental account data sync
// ============================================================================

AccountDataSyncStore::AccountDataSyncStore(DatabasePool& db) : db_(db) {}

// ---- DDL ----
void AccountDataSyncStore::create_tables(LoggingTransaction& txn) {
  // Account data storage
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS account_data (
      id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      data_type TEXT NOT NULL,
      data_key TEXT NOT NULL,
      room_id TEXT,
      content_json TEXT NOT NULL,
      stream_id BIGINT NOT NULL,
      created_ts BIGINT NOT NULL,
      updated_ts BIGINT NOT NULL,
      UNIQUE (user_id, data_type, data_key)
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS account_data_user_type_idx
      ON account_data (user_id, data_type);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS account_data_stream_idx
      ON account_data (stream_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS account_data_user_stream_idx
      ON account_data (user_id, stream_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS account_data_room_idx
      ON account_data (room_id);
  )SQL");

  // Stream position tracking
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS account_data_stream_positions (
      user_id TEXT NOT NULL PRIMARY KEY,
      stream_position BIGINT NOT NULL DEFAULT 0,
      updated_ts BIGINT NOT NULL
    );
  )SQL");

  // Global max stream ID (for generating stream IDs)
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS account_data_max_stream (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      max_stream_id BIGINT NOT NULL DEFAULT 0
    );
  )SQL");
  txn.execute(
      "INSERT OR IGNORE INTO account_data_max_stream (id, max_stream_id) VALUES (1, 0)");
}

// ---- Set account data ----
void AccountDataSyncStore::set_account_data_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& data_type, const std::string& data_key,
    const json& content) {
  int64_t ts = now_ms();

  // Get next stream ID
  txn.execute(
      "UPDATE account_data_max_stream SET max_stream_id = max_stream_id + 1 WHERE id = 1");
  auto stream_row = txn.select_one(
      "SELECT max_stream_id FROM account_data_max_stream WHERE id = 1");
  int64_t stream_id = stream_row ? stream_row->get<int64_t>(0) : 1;

  // Extract room_id from data_key if it looks like a room ID
  std::string room_id;
  if (data_key.size() > 0 && data_key[0] == '!') {
    room_id = data_key;
  }

  txn.execute(
      "INSERT INTO account_data "
      "(user_id, data_type, data_key, room_id, content_json, stream_id, "
      "created_ts, updated_ts) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT (user_id, data_type, data_key) DO UPDATE SET "
      "content_json = excluded.content_json, "
      "stream_id = excluded.stream_id, "
      "updated_ts = excluded.updated_ts",
      {user_id, data_type, data_key, room_id, content.dump(), stream_id, ts, ts});

  // Update stream position for user
  advance_stream_position_txn(txn, user_id, stream_id);
}

// ---- Get account data ----
std::optional<json> AccountDataSyncStore::get_account_data_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& data_type, const std::string& data_key) {
  auto row = txn.select_one(
      "SELECT data_type, data_key, room_id, content_json, stream_id, "
      "created_ts, updated_ts "
      "FROM account_data WHERE user_id = ? AND data_type = ? AND data_key = ?",
      {user_id, data_type, data_key});
  if (!row || row->is_null()) return std::nullopt;
  json result;
  result["data_type"] = row->get<std::string>(0);
  result["data_key"] = row->get<std::string>(1);
  if (!row->is_null(2)) result["room_id"] = row->get<std::string>(2);
  result["content"] = json::parse(row->get<std::string>(3));
  result["stream_id"] = row->get<int64_t>(4);
  result["created_ts"] = row->get<int64_t>(5);
  result["updated_ts"] = row->get<int64_t>(6);
  return result;
}

json AccountDataSyncStore::get_account_data_by_type_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& data_type, bool include_global) {
  json result = json::object();
  std::string sql =
      "SELECT data_key, content_json, room_id, stream_id, updated_ts "
      "FROM account_data WHERE user_id = ? AND data_type = ? ";
  if (!include_global) {
    sql += "AND room_id IS NOT NULL ";
  }
  sql += "ORDER BY updated_ts DESC";
  auto rows = txn.select(sql, {user_id, data_type});
  for (auto& row : rows) {
    json entry;
    if (!row->is_null(2)) entry["room_id"] = row->get<std::string>(2);
    entry["content"] = json::parse(row->get<std::string>(1));
    entry["stream_id"] = row->get<int64_t>(3);
    entry["updated_ts"] = row->get<int64_t>(4);
    result[row->get<std::string>(0)] = entry;
  }
  return result;
}

json AccountDataSyncStore::get_global_account_data_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  json result = json::object();
  auto rows = txn.select(
      "SELECT data_type, content_json, stream_id, updated_ts "
      "FROM account_data WHERE user_id = ? AND room_id IS NULL "
      "ORDER BY updated_ts DESC",
      {user_id});
  json by_type;
  for (auto& row : rows) {
    std::string dtype = row->get<std::string>(0);
    by_type[dtype] = json::parse(row->get<std::string>(1));
  }
  result["global"] = by_type;
  return result;
}

json AccountDataSyncStore::get_room_account_data_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& room_id, const std::string& data_type) {
  json result = json::object();
  auto rows = txn.select(
      "SELECT data_type, data_key, content_json, stream_id, updated_ts "
      "FROM account_data WHERE user_id = ? AND room_id = ? AND data_type = ? "
      "ORDER BY updated_ts DESC",
      {user_id, room_id, data_type});
  for (auto& row : rows) {
    json entry;
    entry["content"] = json::parse(row->get<std::string>(2));
    entry["stream_id"] = row->get<int64_t>(3);
    entry["updated_ts"] = row->get<int64_t>(4);
    result[row->get<std::string>(1)] = entry;
  }
  return result;
}

// ---- Delete ----
void AccountDataSyncStore::delete_account_data_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& data_type, const std::string& data_key) {
  txn.execute(
      "DELETE FROM account_data WHERE user_id = ? AND data_type = ? AND data_key = ?",
      {user_id, data_type, data_key});
}

void AccountDataSyncStore::delete_all_user_account_data_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  txn.execute("DELETE FROM account_data WHERE user_id = ?", {user_id});
  txn.execute("DELETE FROM account_data_stream_positions WHERE user_id = ?",
              {user_id});
}

// ---- Stream position tracking ----
int64_t AccountDataSyncStore::get_stream_position_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  auto row = txn.select_one(
      "SELECT stream_position FROM account_data_stream_positions WHERE user_id = ?",
      {user_id});
  return row ? row->get<int64_t>(0) : 0;
}

void AccountDataSyncStore::set_stream_position_txn(
    LoggingTransaction& txn, const std::string& user_id, int64_t position) {
  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO account_data_stream_positions "
      "(user_id, stream_position, updated_ts) VALUES (?, ?, ?) "
      "ON CONFLICT (user_id) DO UPDATE SET "
      "stream_position = excluded.stream_position, "
      "updated_ts = excluded.updated_ts",
      {user_id, position, ts});
}

void AccountDataSyncStore::advance_stream_position_txn(
    LoggingTransaction& txn, const std::string& user_id, int64_t new_position) {
  int64_t current = get_stream_position_txn(txn, user_id);
  if (new_position > current) {
    set_stream_position_txn(txn, user_id, new_position);
  }
}

json AccountDataSyncStore::get_account_data_since_txn(
    LoggingTransaction& txn, const std::string& user_id,
    int64_t since_position, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT data_type, data_key, room_id, content_json, stream_id, updated_ts "
      "FROM account_data WHERE user_id = ? AND stream_id > ? "
      "ORDER BY stream_id ASC LIMIT ?",
      {user_id, since_position, limit});
  for (auto& row : rows) {
    json entry;
    entry["type"] = row->get<std::string>(0);
    entry["key"] = row->get<std::string>(1);
    if (!row->is_null(2)) entry["room_id"] = row->get<std::string>(2);
    entry["content"] = json::parse(row->get<std::string>(3));
    entry["stream_id"] = row->get<int64_t>(4);
    entry["updated_ts"] = row->get<int64_t>(5);
    result.push_back(entry);
  }
  return result;
}

json AccountDataSyncStore::get_global_account_data_since_txn(
    LoggingTransaction& txn, const std::string& user_id,
    int64_t since_position, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT data_type, data_key, content_json, stream_id, updated_ts "
      "FROM account_data WHERE user_id = ? AND room_id IS NULL AND stream_id > ? "
      "ORDER BY stream_id ASC LIMIT ?",
      {user_id, since_position, limit});
  for (auto& row : rows) {
    json entry;
    entry["type"] = row->get<std::string>(0);
    entry["key"] = row->get<std::string>(1);
    entry["content"] = json::parse(row->get<std::string>(2));
    entry["stream_id"] = row->get<int64_t>(3);
    entry["updated_ts"] = row->get<int64_t>(4);
    result.push_back(entry);
  }
  return result;
}

json AccountDataSyncStore::get_room_account_data_since_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& room_id, int64_t since_position, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT data_type, data_key, content_json, stream_id, updated_ts "
      "FROM account_data WHERE user_id = ? AND room_id = ? AND stream_id > ? "
      "ORDER BY stream_id ASC LIMIT ?",
      {user_id, room_id, since_position, limit});
  for (auto& row : rows) {
    json entry;
    entry["type"] = row->get<std::string>(0);
    entry["key"] = row->get<std::string>(1);
    entry["content"] = json::parse(row->get<std::string>(2));
    entry["stream_id"] = row->get<int64_t>(3);
    entry["updated_ts"] = row->get<int64_t>(4);
    result.push_back(entry);
  }
  return result;
}

int64_t AccountDataSyncStore::get_max_stream_position_txn(
    LoggingTransaction& txn) {
  auto row = txn.select_one(
      "SELECT max_stream_id FROM account_data_max_stream WHERE id = 1");
  return row ? row->get<int64_t>(0) : 0;
}

void AccountDataSyncStore::reset_stream_position_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  set_stream_position_txn(txn, user_id, 0);
}

// ============================================================================
// 9. ToDeviceSyncStore — to-device message delivery tracking
// ============================================================================

ToDeviceSyncStore::ToDeviceSyncStore(DatabasePool& db) : db_(db) {}

// ---- DDL ----
void ToDeviceSyncStore::create_tables(LoggingTransaction& txn) {
  // Main to-device messages table
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS to_device_messages (
      id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      sender_user_id TEXT NOT NULL,
      message_type TEXT NOT NULL,
      content_json TEXT NOT NULL,
      stream_id BIGINT NOT NULL,
      delivery_status TEXT NOT NULL DEFAULT 'pending',
      delivered_at_ts BIGINT,
      error_message TEXT,
      created_ts BIGINT NOT NULL
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS to_device_user_device_stream_idx
      ON to_device_messages (user_id, device_id, stream_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS to_device_delivery_status_idx
      ON to_device_messages (user_id, device_id, delivery_status);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS to_device_stream_idx
      ON to_device_messages (stream_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS to_device_created_idx
      ON to_device_messages (created_ts);
  )SQL");

  // Delivery tracking per user+device
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS to_device_delivery_tracking (
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      last_delivered_stream_id BIGINT NOT NULL DEFAULT 0,
      last_stream_position BIGINT NOT NULL DEFAULT 0,
      pending_count INTEGER NOT NULL DEFAULT 0,
      failed_count INTEGER NOT NULL DEFAULT 0,
      updated_ts BIGINT NOT NULL,
      PRIMARY KEY (user_id, device_id)
    );
  )SQL");

  // Stream position for to-device messages (global)
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS to_device_max_stream (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      max_stream_id BIGINT NOT NULL DEFAULT 0
    );
  )SQL");
  txn.execute(
      "INSERT OR IGNORE INTO to_device_max_stream (id, max_stream_id) VALUES (1, 0)");
}

// ---- Send to-device message ----
int64_t ToDeviceSyncStore::send_to_device_msg_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id, const std::string& sender_user_id,
    const std::string& message_type, const json& content) {
  int64_t ts = now_ms();

  // Get next stream ID
  txn.execute(
      "UPDATE to_device_max_stream SET max_stream_id = max_stream_id + 1 WHERE id = 1");
  auto stream_row = txn.select_one(
      "SELECT max_stream_id FROM to_device_max_stream WHERE id = 1");
  int64_t stream_id = stream_row ? stream_row->get<int64_t>(0) : 1;

  txn.execute(
      "INSERT INTO to_device_messages "
      "(user_id, device_id, sender_user_id, message_type, content_json, "
      "stream_id, delivery_status, created_ts) "
      "VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)",
      {user_id, device_id, sender_user_id, message_type, content.dump(),
       stream_id, ts});

  // Update delivery tracking
  txn.execute(
      "INSERT INTO to_device_delivery_tracking "
      "(user_id, device_id, last_stream_position, pending_count, updated_ts) "
      "VALUES (?, ?, ?, 1, ?) "
      "ON CONFLICT (user_id, device_id) DO UPDATE SET "
      "last_stream_position = excluded.last_stream_position, "
      "pending_count = to_device_delivery_tracking.pending_count + 1, "
      "updated_ts = excluded.updated_ts",
      {user_id, device_id, stream_id, ts});

  return stream_id;
}

void ToDeviceSyncStore::send_to_all_user_devices_txn(
    LoggingTransaction& txn, const std::string& target_user_id,
    const std::string& sender_user_id, const std::string& message_type,
    const json& content, const std::vector<std::string>& device_ids) {
  for (const auto& device_id : device_ids) {
    send_to_device_msg_txn(txn, target_user_id, device_id,
                            sender_user_id, message_type, content);
  }
}

// ---- Get pending messages ----
json ToDeviceSyncStore::get_pending_messages_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT id, sender_user_id, message_type, content_json, stream_id, created_ts "
      "FROM to_device_messages "
      "WHERE user_id = ? AND device_id = ? AND delivery_status = 'pending' "
      "ORDER BY stream_id ASC LIMIT ?",
      {user_id, device_id, limit});
  for (auto& row : rows) {
    json msg;
    msg["id"] = row->get<int64_t>(0);
    msg["sender"] = row->get<std::string>(1);
    msg["type"] = row->get<std::string>(2);
    msg["content"] = json::parse(row->get<std::string>(3));
    msg["stream_id"] = row->get<int64_t>(4);
    msg["created_ts"] = row->get<int64_t>(5);
    result.push_back(msg);
  }
  return result;
}

json ToDeviceSyncStore::get_messages_since_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id, int64_t since_stream_id, int limit) {
  json result = json::array();
  auto rows = txn.select(
      "SELECT id, sender_user_id, message_type, content_json, stream_id, "
      "delivery_status, created_ts "
      "FROM to_device_messages "
      "WHERE user_id = ? AND device_id = ? AND stream_id > ? "
      "ORDER BY stream_id ASC LIMIT ?",
      {user_id, device_id, since_stream_id, limit});
  for (auto& row : rows) {
    json msg;
    msg["id"] = row->get<int64_t>(0);
    msg["sender"] = row->get<std::string>(1);
    msg["type"] = row->get<std::string>(2);
    msg["content"] = json::parse(row->get<std::string>(3));
    msg["stream_id"] = row->get<int64_t>(4);
    msg["delivery_status"] = row->get<std::string>(5);
    msg["created_ts"] = row->get<int64_t>(6);
    result.push_back(msg);
  }
  return result;
}

// ---- Delivery tracking ----
void ToDeviceSyncStore::mark_delivered_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id, int64_t up_to_stream_id) {
  int64_t ts = now_ms();
  txn.execute(
      "UPDATE to_device_messages SET delivery_status = 'delivered', "
      "delivered_at_ts = ? "
      "WHERE user_id = ? AND device_id = ? AND stream_id <= ? "
      "AND delivery_status = 'pending'",
      {ts, user_id, device_id, up_to_stream_id});

  // Update tracking
  int64_t delivered_count = count_undelivered_for_device_txn(txn, user_id, device_id);
  // Actually we need to count how many we just marked - use changes()
  auto changes = txn.select_one("SELECT changes()");
  int64_t just_delivered = changes ? changes->get<int64_t>(0) : 0;

  txn.execute(
      "UPDATE to_device_delivery_tracking SET "
      "last_delivered_stream_id = MAX(last_delivered_stream_id, ?), "
      "pending_count = MAX(0, pending_count - ?), "
      "updated_ts = ? "
      "WHERE user_id = ? AND device_id = ?",
      {up_to_stream_id, just_delivered, ts, user_id, device_id});
}

void ToDeviceSyncStore::mark_message_delivered_txn(
    LoggingTransaction& txn, int64_t message_id) {
  int64_t ts = now_ms();
  txn.execute(
      "UPDATE to_device_messages SET delivery_status = 'delivered', "
      "delivered_at_ts = ? WHERE id = ?",
      {ts, message_id});
}

void ToDeviceSyncStore::mark_message_failed_txn(
    LoggingTransaction& txn, int64_t message_id,
    const std::string& error) {
  int64_t ts = now_ms();
  txn.execute(
      "UPDATE to_device_messages SET delivery_status = 'failed', "
      "error_message = ?, delivered_at_ts = ? WHERE id = ?",
      {error, ts, message_id});
}

std::optional<json> ToDeviceSyncStore::get_delivery_status_txn(
    LoggingTransaction& txn, int64_t message_id) {
  auto row = txn.select_one(
      "SELECT id, user_id, device_id, delivery_status, delivered_at_ts, error_message "
      "FROM to_device_messages WHERE id = ?",
      {message_id});
  if (!row || row->is_null()) return std::nullopt;
  json result;
  result["id"] = row->get<int64_t>(0);
  result["user_id"] = row->get<std::string>(1);
  result["device_id"] = row->get<std::string>(2);
  result["delivery_status"] = row->get<std::string>(3);
  if (!row->is_null(4)) result["delivered_at_ts"] = row->get<int64_t>(4);
  if (!row->is_null(5)) result["error_message"] = row->get<std::string>(5);
  return result;
}

int64_t ToDeviceSyncStore::count_undelivered_for_device_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM to_device_messages "
      "WHERE user_id = ? AND device_id = ? AND delivery_status = 'pending'",
      {user_id, device_id});
  return row ? row->get<int64_t>(0) : 0;
}

// ---- Stream tracking ----
int64_t ToDeviceSyncStore::get_device_stream_position_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id) {
  auto row = txn.select_one(
      "SELECT last_stream_position FROM to_device_delivery_tracking "
      "WHERE user_id = ? AND device_id = ?",
      {user_id, device_id});
  return row ? row->get<int64_t>(0) : 0;
}

void ToDeviceSyncStore::set_device_stream_position_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id, int64_t position) {
  int64_t ts = now_ms();
  txn.execute(
      "INSERT INTO to_device_delivery_tracking "
      "(user_id, device_id, last_stream_position, updated_ts) "
      "VALUES (?, ?, ?, ?) "
      "ON CONFLICT (user_id, device_id) DO UPDATE SET "
      "last_stream_position = MAX(to_device_delivery_tracking.last_stream_position, "
      "excluded.last_stream_position), "
      "updated_ts = excluded.updated_ts",
      {user_id, device_id, position, ts});
}

int64_t ToDeviceSyncStore::get_max_stream_position_txn(LoggingTransaction& txn) {
  auto row = txn.select_one(
      "SELECT max_stream_id FROM to_device_max_stream WHERE id = 1");
  return row ? row->get<int64_t>(0) : 0;
}

// ---- Cleanup ----
int64_t ToDeviceSyncStore::cleanup_delivered_messages_txn(
    LoggingTransaction& txn, int64_t older_than_seconds) {
  int64_t cutoff = now_ms() - (older_than_seconds * 1000);
  txn.execute(
      "DELETE FROM to_device_messages WHERE delivery_status = 'delivered' "
      "AND delivered_at_ts < ?",
      {cutoff});
  auto row = txn.select_one("SELECT changes()");
  return row ? row->get<int64_t>(0) : 0;
}

void ToDeviceSyncStore::delete_device_messages_txn(
    LoggingTransaction& txn, const std::string& user_id,
    const std::string& device_id) {
  txn.execute(
      "DELETE FROM to_device_messages WHERE user_id = ? AND device_id = ?",
      {user_id, device_id});
  txn.execute(
      "DELETE FROM to_device_delivery_tracking WHERE user_id = ? AND device_id = ?",
      {user_id, device_id});
}

void ToDeviceSyncStore::delete_all_user_messages_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  txn.execute("DELETE FROM to_device_messages WHERE user_id = ?", {user_id});
  txn.execute("DELETE FROM to_device_delivery_tracking WHERE user_id = ?",
              {user_id});
}

// ---- Statistics ----
json ToDeviceSyncStore::get_to_device_stats_txn(LoggingTransaction& txn) {
  json stats;
  auto total = txn.select_one("SELECT COUNT(*) FROM to_device_messages");
  auto pending = txn.select_one(
      "SELECT COUNT(*) FROM to_device_messages WHERE delivery_status = 'pending'");
  auto delivered = txn.select_one(
      "SELECT COUNT(*) FROM to_device_messages WHERE delivery_status = 'delivered'");
  auto failed = txn.select_one(
      "SELECT COUNT(*) FROM to_device_messages WHERE delivery_status = 'failed'");
  auto max_stream = txn.select_one(
      "SELECT max_stream_id FROM to_device_max_stream WHERE id = 1");

  stats["total_messages"] = total ? total->get<int64_t>(0) : 0;
  stats["pending_messages"] = pending ? pending->get<int64_t>(0) : 0;
  stats["delivered_messages"] = delivered ? delivered->get<int64_t>(0) : 0;
  stats["failed_messages"] = failed ? failed->get<int64_t>(0) : 0;
  stats["max_stream_id"] = max_stream ? max_stream->get<int64_t>(0) : 0;
  return stats;
}

int64_t ToDeviceSyncStore::count_pending_messages_txn(LoggingTransaction& txn) {
  auto row = txn.select_one(
      "SELECT COUNT(*) FROM to_device_messages WHERE delivery_status = 'pending'");
  return row ? row->get<int64_t>(0) : 0;
}

json ToDeviceSyncStore::get_pending_counts_by_user_txn(
    LoggingTransaction& txn, int limit) {
  json result;
  auto rows = txn.select(
      "SELECT user_id, COUNT(*) as cnt FROM to_device_messages "
      "WHERE delivery_status = 'pending' "
      "GROUP BY user_id ORDER BY cnt DESC LIMIT ?",
      {limit});
  for (auto& row : rows) {
    result[row->get<std::string>(0)] = row->get<int64_t>(1);
  }
  return result;
}

// ============================================================================
// 10. PushRuleEvalCache — push rule evaluation result caching
// ============================================================================

PushRuleEvalCache::PushRuleEvalCache(DatabasePool& db) : db_(db) {}

// ---- DDL ----
void PushRuleEvalCache::create_tables(LoggingTransaction& txn) {
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS push_rule_eval_cache (
      id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
      event_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      eval_result_json TEXT NOT NULL,
      expires_at_ts BIGINT NOT NULL,
      created_ts BIGINT NOT NULL,
      accessed_ts BIGINT NOT NULL,
      UNIQUE (event_id, user_id)
    );
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS push_eval_cache_expiry_idx
      ON push_rule_eval_cache (expires_at_ts);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS push_eval_cache_event_idx
      ON push_rule_eval_cache (event_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS push_eval_cache_user_idx
      ON push_rule_eval_cache (user_id);
  )SQL");
  txn.execute(R"SQL(
    CREATE INDEX IF NOT EXISTS push_eval_cache_rule_idx
      ON push_rule_eval_cache (rule_id);
  )SQL");

  // Cache performance tracking
  txn.execute(R"SQL(
    CREATE TABLE IF NOT EXISTS push_eval_cache_stats (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      total_hits BIGINT NOT NULL DEFAULT 0,
      total_misses BIGINT NOT NULL DEFAULT 0,
      total_cached BIGINT NOT NULL DEFAULT 0,
      total_invalidated BIGINT NOT NULL DEFAULT 0,
      total_expired BIGINT NOT NULL DEFAULT 0,
      updated_ts BIGINT NOT NULL
    );
  )SQL");
  txn.execute(
      "INSERT OR IGNORE INTO push_eval_cache_stats "
      "(id, updated_ts) VALUES (1, 0)");
}

// ---- Cache result ----
void PushRuleEvalCache::cache_result_txn(
    LoggingTransaction& txn, const std::string& event_id,
    const std::string& user_id, const json& eval_result,
    const std::string& rule_id, int64_t ttl_seconds) {
  int64_t ts = now_ms();
  int64_t expires_at = ts + (ttl_seconds * 1000);

  txn.execute(
      "INSERT INTO push_rule_eval_cache "
      "(event_id, user_id, rule_id, eval_result_json, expires_at_ts, "
      "created_ts, accessed_ts) "
      "VALUES (?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT (event_id, user_id) DO UPDATE SET "
      "rule_id = excluded.rule_id, "
      "eval_result_json = excluded.eval_result_json, "
      "expires_at_ts = excluded.expires_at_ts, "
      "accessed_ts = excluded.accessed_ts",
      {event_id, user_id, rule_id, eval_result.dump(), expires_at, ts, ts});

  // Update stats
  txn.execute(
      "UPDATE push_eval_cache_stats SET "
      "total_cached = total_cached + 1, updated_ts = ? WHERE id = 1",
      {ts});
}

// ---- Get cached result ----
std::optional<json> PushRuleEvalCache::get_cached_result_txn(
    LoggingTransaction& txn, const std::string& event_id,
    const std::string& user_id) {
  int64_t ts = now_ms();
  auto row = txn.select_one(
      "SELECT rule_id, eval_result_json, expires_at_ts, created_ts, accessed_ts "
      "FROM push_rule_eval_cache WHERE event_id = ? AND user_id = ? "
      "AND expires_at_ts > ?",
      {event_id, user_id, ts});
  if (!row || row->is_null()) {
    miss_count_++;
    // Update miss stats
    txn.execute(
        "UPDATE push_eval_cache_stats SET "
        "total_misses = total_misses + 1, updated_ts = ? WHERE id = 1",
        {ts});
    return std::nullopt;
  }

  // Cache hit — update access time and stats
  hit_count_++;
  txn.execute(
      "UPDATE push_rule_eval_cache SET accessed_ts = ? "
      "WHERE event_id = ? AND user_id = ?",
      {ts, event_id, user_id});
  txn.execute(
      "UPDATE push_eval_cache_stats SET "
      "total_hits = total_hits + 1, updated_ts = ? WHERE id = 1",
      {ts});

  json result;
  result["rule_id"] = row->get<std::string>(0);
  result["eval_result"] = json::parse(row->get<std::string>(1));
  result["expires_at_ts"] = row->get<int64_t>(2);
  result["created_ts"] = row->get<int64_t>(3);
  result["accessed_ts"] = row->get<int64_t>(4);
  return result;
}

// ---- Get cached results for an event ----
json PushRuleEvalCache::get_cached_results_for_event_txn(
    LoggingTransaction& txn, const std::string& event_id, int limit) {
  int64_t ts = now_ms();
  json result = json::array();
  auto rows = txn.select(
      "SELECT user_id, rule_id, eval_result_json, expires_at_ts, created_ts, accessed_ts "
      "FROM push_rule_eval_cache WHERE event_id = ? AND expires_at_ts > ? "
      "ORDER BY created_ts DESC LIMIT ?",
      {event_id, ts, limit});
  for (auto& row : rows) {
    json entry;
    entry["user_id"] = row->get<std::string>(0);
    entry["rule_id"] = row->get<std::string>(1);
    entry["eval_result"] = json::parse(row->get<std::string>(2));
    entry["expires_at_ts"] = row->get<int64_t>(3);
    entry["created_ts"] = row->get<int64_t>(4);
    entry["accessed_ts"] = row->get<int64_t>(5);
    result.push_back(entry);
  }
  return result;
}

// ---- Get cached results for a user ----
json PushRuleEvalCache::get_cached_results_for_user_txn(
    LoggingTransaction& txn, const std::string& user_id, int limit) {
  int64_t ts = now_ms();
  json result = json::array();
  auto rows = txn.select(
      "SELECT event_id, rule_id, eval_result_json, expires_at_ts, created_ts, accessed_ts "
      "FROM push_rule_eval_cache WHERE user_id = ? AND expires_at_ts > ? "
      "ORDER BY created_ts DESC LIMIT ?",
      {user_id, ts, limit});
  for (auto& row : rows) {
    json entry;
    entry["event_id"] = row->get<std::string>(0);
    entry["rule_id"] = row->get<std::string>(1);
    entry["eval_result"] = json::parse(row->get<std::string>(2));
    entry["expires_at_ts"] = row->get<int64_t>(3);
    entry["created_ts"] = row->get<int64_t>(4);
    entry["accessed_ts"] = row->get<int64_t>(5);
    result.push_back(entry);
  }
  return result;
}

// ---- Invalidation ----
void PushRuleEvalCache::invalidate_event_cache_txn(
    LoggingTransaction& txn, const std::string& event_id) {
  int64_t ts = now_ms();
  auto cnt = txn.select_one(
      "SELECT COUNT(*) FROM push_rule_eval_cache WHERE event_id = ?",
      {event_id});
  int64_t count = cnt ? cnt->get<int64_t>(0) : 0;

  txn.execute(
      "DELETE FROM push_rule_eval_cache WHERE event_id = ?", {event_id});
  txn.execute(
      "UPDATE push_eval_cache_stats SET "
      "total_invalidated = total_invalidated + ?, updated_ts = ? WHERE id = 1",
      {count, ts});
}

void PushRuleEvalCache::invalidate_cache_txn(
    LoggingTransaction& txn, const std::string& event_id,
    const std::string& user_id) {
  int64_t ts = now_ms();
  txn.execute(
      "DELETE FROM push_rule_eval_cache WHERE event_id = ? AND user_id = ?",
      {event_id, user_id});
  txn.execute(
      "UPDATE push_eval_cache_stats SET "
      "total_invalidated = total_invalidated + 1, updated_ts = ? WHERE id = 1",
      {ts});
}

void PushRuleEvalCache::invalidate_user_cache_txn(
    LoggingTransaction& txn, const std::string& user_id) {
  int64_t ts = now_ms();
  auto cnt = txn.select_one(
      "SELECT COUNT(*) FROM push_rule_eval_cache WHERE user_id = ?",
      {user_id});
  int64_t count = cnt ? cnt->get<int64_t>(0) : 0;

  txn.execute(
      "DELETE FROM push_rule_eval_cache WHERE user_id = ?", {user_id});
  txn.execute(
      "UPDATE push_eval_cache_stats SET "
      "total_invalidated = total_invalidated + ?, updated_ts = ? WHERE id = 1",
      {count, ts});
}

void PushRuleEvalCache::invalidate_rule_cache_txn(
    LoggingTransaction& txn, const std::string& rule_id) {
  int64_t ts = now_ms();
  auto cnt = txn.select_one(
      "SELECT COUNT(*) FROM push_rule_eval_cache WHERE rule_id = ?",
      {rule_id});
  int64_t count = cnt ? cnt->get<int64_t>(0) : 0;

  txn.execute(
      "DELETE FROM push_rule_eval_cache WHERE rule_id = ?", {rule_id});
  txn.execute(
      "UPDATE push_eval_cache_stats SET "
      "total_invalidated = total_invalidated + ?, updated_ts = ? WHERE id = 1",
      {count, ts});
}

// ---- Check validity ----
bool PushRuleEvalCache::has_valid_cache_txn(
    LoggingTransaction& txn, const std::string& event_id,
    const std::string& user_id) {
  int64_t ts = now_ms();
  auto row = txn.select_one(
      "SELECT 1 FROM push_rule_eval_cache "
      "WHERE event_id = ? AND user_id = ? AND expires_at_ts > ?",
      {event_id, user_id, ts});
  return row && !row->is_null();
}

// ---- Cleanup ----
int64_t PushRuleEvalCache::cleanup_expired_cache_txn(
    LoggingTransaction& txn, int batch_size) {
  int64_t ts = now_ms();
  auto cnt = txn.select_one(
      "SELECT COUNT(*) FROM push_rule_eval_cache WHERE expires_at_ts <= ?",
      {ts});
  int64_t count = cnt ? cnt->get<int64_t>(0) : 0;

  txn.execute(
      "DELETE FROM push_rule_eval_cache WHERE expires_at_ts <= ? LIMIT ?",
      {ts, batch_size});
  auto deleted = txn.select_one("SELECT changes()");
  int64_t num_deleted = deleted ? deleted->get<int64_t>(0) : 0;

  txn.execute(
      "UPDATE push_eval_cache_stats SET "
      "total_expired = total_expired + ?, updated_ts = ? WHERE id = 1",
      {num_deleted, ts});
  return num_deleted;
}

int64_t PushRuleEvalCache::cleanup_old_cache_txn(
    LoggingTransaction& txn, int64_t older_than_seconds) {
  int64_t cutoff = now_ms() - (older_than_seconds * 1000);
  int64_t ts = now_ms();

  txn.execute(
      "DELETE FROM push_rule_eval_cache WHERE created_ts < ?", {cutoff});
  auto row = txn.select_one("SELECT changes()");
  int64_t deleted = row ? row->get<int64_t>(0) : 0;

  txn.execute(
      "UPDATE push_eval_cache_stats SET "
      "total_invalidated = total_invalidated + ?, updated_ts = ? WHERE id = 1",
      {deleted, ts});
  return deleted;
}

// ---- Stats ----
json PushRuleEvalCache::get_cache_stats_txn(LoggingTransaction& txn) {
  json stats;
  int64_t ts = now_ms();
  auto total = txn.select_one("SELECT COUNT(*) FROM push_rule_eval_cache");
  auto valid = txn.select_one(
      "SELECT COUNT(*) FROM push_rule_eval_cache WHERE expires_at_ts > ?",
      {ts});
  auto expired = txn.select_one(
      "SELECT COUNT(*) FROM push_rule_eval_cache WHERE expires_at_ts <= ?",
      {ts});
  auto unique_events = txn.select_one(
      "SELECT COUNT(DISTINCT event_id) FROM push_rule_eval_cache");
  auto unique_users = txn.select_one(
      "SELECT COUNT(DISTINCT user_id) FROM push_rule_eval_cache");
  auto unique_rules = txn.select_one(
      "SELECT COUNT(DISTINCT rule_id) FROM push_rule_eval_cache");

  stats["total_entries"] = total ? total->get<int64_t>(0) : 0;
  stats["valid_entries"] = valid ? valid->get<int64_t>(0) : 0;
  stats["expired_entries"] = expired ? expired->get<int64_t>(0) : 0;
  stats["unique_events"] = unique_events ? unique_events->get<int64_t>(0) : 0;
  stats["unique_users"] = unique_users ? unique_users->get<int64_t>(0) : 0;
  stats["unique_rules"] = unique_rules ? unique_rules->get<int64_t>(0) : 0;
  return stats;
}

json PushRuleEvalCache::get_cache_performance_txn(LoggingTransaction& txn) {
  json perf;
  auto row = txn.select_one(
      "SELECT total_hits, total_misses, total_cached, total_invalidated, "
      "total_expired, updated_ts FROM push_eval_cache_stats WHERE id = 1");
  if (row && !row->is_null()) {
    perf["total_hits"] = row->get<int64_t>(0);
    perf["total_misses"] = row->get<int64_t>(1);
    perf["total_cached"] = row->get<int64_t>(2);
    perf["total_invalidated"] = row->get<int64_t>(3);
    perf["total_expired"] = row->get<int64_t>(4);
    perf["updated_ts"] = row->get<int64_t>(5);

    int64_t total = perf["total_hits"].get<int64_t>() + perf["total_misses"].get<int64_t>();
    if (total > 0) {
      perf["hit_ratio"] = static_cast<double>(perf["total_hits"].get<int64_t>()) / total;
    } else {
      perf["hit_ratio"] = 0.0;
    }
  }
  // Also report in-memory counters
  perf["in_memory_hits"] = hit_count_;
  perf["in_memory_misses"] = miss_count_;
  return perf;
}

void PushRuleEvalCache::reset_cache_counters_txn(LoggingTransaction& txn) {
  hit_count_ = 0;
  miss_count_ = 0;
  txn.execute(
      "UPDATE push_eval_cache_stats SET total_hits = 0, total_misses = 0, "
      "total_cached = 0, total_invalidated = 0, total_expired = 0, "
      "updated_ts = ? WHERE id = 1",
      {now_ms()});
}

// ---- Bulk operations ----
void PushRuleEvalCache::bulk_cache_results_txn(
    LoggingTransaction& txn, const std::string& event_id,
    const json& user_results, int64_t ttl_seconds) {
  int64_t ts = now_ms();
  int64_t expires_at = ts + (ttl_seconds * 1000);

  for (auto it = user_results.begin(); it != user_results.end(); ++it) {
    const std::string& user_id = it.key();
    const json& entry = it.value();
    std::string rule_id = entry.value("rule_id", "");
    const json& eval_result = entry.value("result", json::object());

    txn.execute(
        "INSERT INTO push_rule_eval_cache "
        "(event_id, user_id, rule_id, eval_result_json, expires_at_ts, "
        "created_ts, accessed_ts) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (event_id, user_id) DO UPDATE SET "
        "rule_id = excluded.rule_id, "
        "eval_result_json = excluded.eval_result_json, "
        "expires_at_ts = excluded.expires_at_ts, "
        "accessed_ts = excluded.accessed_ts",
        {event_id, user_id, rule_id, eval_result.dump(), expires_at, ts, ts});
  }

  // Update stats
  int64_t num_cached = static_cast<int64_t>(user_results.size());
  txn.execute(
      "UPDATE push_eval_cache_stats SET "
      "total_cached = total_cached + ?, updated_ts = ? WHERE id = 1",
      {num_cached, ts});
}

void PushRuleEvalCache::warm_cache_txn(
    LoggingTransaction& txn, const std::string& event_id,
    const json& eval_lookup) {
  // eval_lookup is a map of user_id -> {rule_id, result}
  bulk_cache_results_txn(txn, event_id, eval_lookup, 900); // 15 min default TTL for warm
}

} // namespace progressive
