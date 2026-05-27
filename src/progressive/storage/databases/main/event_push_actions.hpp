#pragma once
// event_push_actions.hpp - C++ translation of event_push_actions.py (1,936 lines)
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"
namespace progressive::storage {
using json = nlohmann::json;

struct PushAction {
  std::string user_id;
  std::string room_id;
  std::string event_id;
  int64_t topological_ordering{0};
  int64_t stream_ordering{0};
  std::string action; // "notify", "dont_notify", "coalesce"
  std::optional<std::string> highlight_tag;
  int64_t notif{0};
};

// Worker store
class EventPushActionsWorkerStore {
public:
  explicit EventPushActionsWorkerStore(DatabasePool& db);
  // Get unread notification counts for a user
  struct UnreadCount {
    int64_t highlight_count{0};
    int64_t notify_count{0};
  };
  UnreadCount get_unread_event_push_actions_by_room(
      const std::string& user_id, const std::string& room_id,
      int64_t stream_ordering);
  // Get push actions for a user since a given token
  std::vector<PushAction> get_push_actions_for_user(
      const std::string& user_id, int64_t from_stream,
      int64_t to_stream, int limit);
  // Get notification counts by room
  std::map<std::string, UnreadCount> get_unread_counts_by_room(
      const std::string& user_id);
  // Get push actions for an event
  std::vector<PushAction> get_push_actions_for_event(
      const std::string& event_id);
  // Get whether a user has push actions for a room
  bool has_push_actions(const std::string& user_id, const std::string& room_id);
  // Get the last push action stream ordering
  int64_t get_last_push_action_stream_ordering();
  // Get users who should be notified for an event
  std::vector<std::string> get_users_with_pending_notifs(
      const std::string& room_id, int limit);
  // Remove all push actions for a user in a room
  void remove_push_actions_for_user_in_room_txn(
      LoggingTransaction& txn, const std::string& user_id,
      const std::string& room_id);
protected:
  DatabasePool& db_;
};

// Background update store
class EventPushActionsBackgroundUpdateStore : public EventPushActionsWorkerStore {
public:
  explicit EventPushActionsBackgroundUpdateStore(DatabasePool& db);
  void run_background_event_push_summary();
  void run_background_event_push_actions_stream_ordering();
};

// Full store
class EventPushActionsStore : public EventPushActionsBackgroundUpdateStore {
public:
  explicit EventPushActionsStore(DatabasePool& db);
  // Add push actions for an event targeting specific users
  void add_push_actions_to_staging(
      const std::string& event_id,
      const std::string& room_id,
      int64_t topological_ordering,
      int64_t stream_ordering,
      const std::vector<std::string>& user_ids,
      const std::vector<std::string>& profile_tags);
  // Remove push actions for an event
  void remove_push_actions_for_event_id(const std::string& event_id);
  // Rotate push actions (move from staging to summary)
  void rotate_push_actions();
  // Mark push actions as read for a user
  void mark_push_actions_as_read(const std::string& user_id,
      const std::string& room_id, int64_t stream_ordering);
  // Update push action summary for a room/user
  void update_push_summary(const std::string& user_id,
      const std::string& room_id, int64_t stream_ordering);
  // Get event push summary for room/user
  struct PushSummary {
    int64_t unread_count{0};
    int64_t stream_ordering{0};
    int64_t last_receipt_stream_ordering{0};
    std::optional<std::string> notif_highlight;
  };
  PushSummary get_push_summary(const std::string& user_id,
      const std::string& room_id);
  // Add an email push action for deferred delivery
  void add_email_push_action(const std::string& user_id,
      const std::string& room_id, const std::string& event_id,
      int64_t stream_ordering);
  // Get email push actions for a user
  struct EmailPushAction {
    std::string room_id;
    std::string event_id;
    int64_t stream_ordering{0};
    int64_t received_at{0};
  };
  std::vector<EmailPushAction> get_email_push_actions(
      const std::string& user_id, int limit);
  // Delete old email push actions
  void delete_old_email_push_actions(int64_t before_timestamp);
  // Get the stream ordering of the last push processed
  int64_t get_push_action_stream_ordering();
  // Count notifiable events
  int64_t count_notifiable_events(const std::string& event_id);
private:
  void update_unread_counts_txn(LoggingTransaction& txn,
      const std::string& user_id, const std::string& room_id);
};
} // namespace progressive::storage
