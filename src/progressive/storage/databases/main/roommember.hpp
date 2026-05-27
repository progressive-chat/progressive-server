#pragma once
// roommember.hpp - C++ translation of roommember.py (2,132 lines)
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

struct RoomMember {
  std::string room_id;
  std::string user_id;
  std::string sender;
  std::string membership; // "join","leave","invite","ban","knock"
  std::optional<std::string> display_name;
  std::optional<std::string> avatar_url;
  std::optional<std::string> event_id;
  int64_t event_stream_ordering{0};
};

struct RoomMemberSummary {
  int64_t joined_members{0};
  int64_t invited_members{0};
  int64_t banned_members{0};
  std::vector<std::string> heroes;
};

// Worker store
class RoomMemberWorkerStore {
public:
  explicit RoomMemberWorkerStore(DatabasePool& db);
  // Get members of a room
  struct GetMembersResult {
    std::vector<RoomMember> members;
    std::optional<int64_t> total;
  };
  GetMembersResult get_members(const std::string& room_id,
      const std::optional<std::string>& membership = std::nullopt,
      const std::optional<std::string>& not_membership = std::nullopt,
      int64_t limit = 100, int64_t offset = 0);
  // Get joined members
  std::vector<RoomMember> get_joined_members(const std::string& room_id);
  // Get invited members
  std::vector<RoomMember> get_invited_members(const std::string& room_id);
  // Get banned members
  std::vector<RoomMember> get_banned_members(const std::string& room_id);
  // Get knocked members
  std::vector<RoomMember> get_knocked_members(const std::string& room_id);
  // Get membership for a specific user in a room
  std::optional<RoomMember> get_member(const std::string& room_id,
      const std::string& user_id);
  // Get all rooms a user is a member of
  std::vector<std::string> get_rooms_for_user(const std::string& user_id);
  // Get rooms a user is joined to
  std::vector<std::string> get_rooms_for_user_with_membership(
      const std::string& user_id, const std::string& membership);
  // Get users in a room
  std::vector<std::string> get_users_in_room(const std::string& room_id);
  // Count members in room by type
  RoomMemberSummary get_room_member_summary(const std::string& room_id);
  // Get member counts for multiple rooms
  std::map<std::string, int64_t> get_joined_member_counts(
      const std::set<std::string>& room_ids);
  // Check if user is in room
  bool is_user_in_room(const std::string& room_id, const std::string& user_id);
  // Check if user has been in room
  bool user_has_been_in_room(const std::string& room_id,
      const std::string& user_id);
  // Get forgotten status
  std::map<std::string, bool> get_forgotten_statuses(
      const std::string& user_id,
      const std::vector<std::string>& room_ids);
  // Get host of room members
  struct HostCount { std::string host; int64_t count; };
  std::vector<HostCount> get_room_member_hosts(const std::string& room_id);
  // Get room summary with heroes
  RoomMemberSummary get_room_summary_with_heroes(const std::string& room_id,
      int hero_limit = 5);
protected:
  DatabasePool& db_;
};

// Background update
class RoomMemberBackgroundUpdateStore : public RoomMemberWorkerStore {
public:
  explicit RoomMemberBackgroundUpdateStore(DatabasePool& db);
  void run_background_room_member_idx();
  void run_background_room_member_count_update();
  void run_background_room_member_profile_update();
};

// Full store
class RoomMemberStore : public RoomMemberBackgroundUpdateStore {
public:
  explicit RoomMemberStore(DatabasePool& db);
  // Update room membership
  void update_membership(const std::string& room_id,
      const std::string& user_id, const std::string& sender,
      const std::string& membership, const std::string& event_id,
      int64_t event_stream_ordering);
  // Add member to room
  void add_member(const std::string& room_id, const std::string& user_id,
      const std::string& sender, const std::string& membership,
      const std::string& event_id, int64_t stream_ordering);
  // Remove member from room
  void remove_member(const std::string& room_id, const std::string& user_id);
  // Forget room membership for user
  void forget_membership(const std::string& user_id,
      const std::string& room_id, bool forget);
  // Update room member profile
  void update_member_profile(const std::string& room_id,
      const std::string& user_id, const std::string& display_name,
      const std::string& avatar_url);
  // Bulk update membership
  void bulk_update_membership(
      const std::string& room_id,
      const std::vector<std::tuple<std::string, std::string, std::string, std::string, int64_t>>& memberships);
  // Lookup members by display name prefix (for completion)
  struct MemberMatch {
    std::string user_id;
    std::string display_name;
    std::optional<std::string> avatar_url;
  };
  std::vector<MemberMatch> lookup_members_by_prefix(
      const std::string& room_id, const std::string& prefix, int limit);
  // Update hero status
  void update_hero(const std::string& room_id, const std::string& user_id,
      bool is_hero);
  // Get the local current membership for user in room
  std::optional<std::string> get_local_current_membership(
      const std::string& room_id, const std::string& user_id);
  // Check if a user should be able to see the room
  bool can_user_see_room(const std::string& room_id, const std::string& user_id);
private:
  void update_counts_txn(LoggingTransaction& txn, const std::string& room_id);
  void update_summary_txn(LoggingTransaction& txn, const std::string& room_id);
};
} // namespace progressive::storage
