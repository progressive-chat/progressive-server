#pragma once
// presence.hpp - C++ translation of presence.py (829 lines)
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"
namespace progressive::storage { using json = nlohmann::json;

struct PresenceState {
  std::string user_id;
  std::string state; // online, offline, unavailable, busy
  std::optional<std::string> status_msg;
  int64_t last_active_ts{0};
  int64_t last_user_sync_ts{0};
  bool currently_active{false};
};

struct UserPresence {
  std::string user_id;
  PresenceState state;
  int64_t last_federation_update_ts{0};
  int64_t last_update_ts{0};
};

class PresenceStore {
public:
  explicit PresenceStore(DatabasePool& db);
  // Get presence for a user
  std::optional<UserPresence> get_presence(const std::string& user_id);
  // Get presence for multiple users
  std::map<std::string, UserPresence> get_presence_for_users(
      const std::set<std::string>& user_ids);
  // Update presence
  void update_presence(const PresenceState& state);
  // Set presence state
  void set_presence_state(const std::string& user_id,
      const std::string& state, const std::string& status_msg,
      int64_t last_active_ts, bool currently_active);
  // Mark user as syncing
  void update_presence_last_sync(const std::string& user_id, int64_t ts);
  // Get all local presence for federation
  std::vector<PresenceState> get_all_presence_for_federation(
      int64_t from_ts, int64_t limit);
  // Get presence changes since timestamp
  std::vector<PresenceState> get_presence_changes(int64_t from_ts);
  // Mark federation update sent
  void mark_federation_update_sent(const std::string& user_id, int64_t ts);
  // Get users with stale presence (to time out)
  std::vector<std::string> get_stale_presence(int64_t timeout_ms, int limit);
  // Clear stale presence
  void clear_stale_presence(const std::vector<std::string>& user_ids);
  // Get currently active users in a room
  std::vector<std::string> get_active_users_in_room(const std::string& room_id);
  // Allow presence from a specific user to be visible to another
  void add_presence_list_pending(const std::string& observer_user,
      const std::string& observed_user);
  // Get pending presence list entries
  std::vector<std::string> get_presence_list_pending(
      const std::string& observer_user);
  // Accept/deny presence sharing
  void set_presence_list_accepted(const std::string& observer_user,
      const std::string& observed_user);
  // Get accepted presence observers
  std::vector<std::string> get_presence_list_observers(
      const std::string& observed_user);
  // Count currently online users
  int64_t count_online_users();
  // Get user's last presence update
  int64_t get_last_presence_update(const std::string& user_id);
private:
  DatabasePool& db_;
};
} // namespace progressive::storage
