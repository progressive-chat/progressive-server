#pragma once
// remaining_stores.hpp - sliding_sync, stats, state_deltas, ui_auth, session, openid, user_directory
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"
namespace progressive::storage { using json = nlohmann::json;

// ---- SlidingSyncStore (sliding_sync.py) ----
struct SlidingSyncState {
  std::string user_id; std::string conn_id; std::string room_id;
  int64_t pos{0}; std::string ranges; std::string sort_order; json extensions;
  std::string lists; std::string subscriptions; std::string filters;
  bool initial{true}; int64_t created_ts{0}; int64_t last_pos_update_ts{0};
};
class SlidingSyncStore { public:
  explicit SlidingSyncStore(DatabasePool& db);
  void store_sync_state(const SlidingSyncState& state);
  std::optional<SlidingSyncState> get_sync_state(const std::string& user_id, const std::string& conn_id);
  void delete_sync_state(const std::string& user_id, const std::string& conn_id);
  std::vector<SlidingSyncState> get_all_sync_states(const std::string& user_id);
  void update_sync_pos(const std::string& user_id, const std::string& conn_id, int64_t pos);
  void store_room_sync_data(const std::string& user_id, const std::string& conn_id,
      const std::string& room_id, const json& data);
  std::optional<json> get_room_sync_data(const std::string& user_id,
      const std::string& conn_id, const std::string& room_id);
  void delete_old_sync_states(int64_t before_ts);
private: DatabasePool& db_;
};

// ---- StatsStore (stats.py) ----
struct RoomStats { std::string room_id; int64_t current_state_events{0}; int64_t joined_members{0};
  int64_t invited_members{0}; int64_t left_members{0}; int64_t banned_members{0};
  int64_t total_events{0}; int64_t total_event_bytes{0}; std::optional<std::string> name;
  std::optional<std::string> topic; std::optional<std::string> canonical_alias;
  std::optional<std::string> join_rules; std::optional<std::string> history_visibility;
  std::optional<std::string> encryption; std::optional<int64_t> avatar; int64_t forward_extremities{0};
  int64_t backward_extremities{0}; int64_t state_events{0}; bool is_federatable{true};
};
struct UserStats { std::string user_id; int64_t joined_rooms{0}; int64_t created_rooms{0};
  int64_t total_events_sent{0}; int64_t total_event_bytes_sent{0}; int64_t last_seen_ts{0};
  int64_t active_ts{0}; std::optional<std::string> display_name;
};
class StatsStore { public:
  explicit StatsStore(DatabasePool& db);
  void update_room_stats(const std::string& room_id);
  RoomStats get_room_stats(const std::string& room_id);
  std::vector<RoomStats> get_all_room_stats(int64_t limit=100, int64_t offset=0);
  std::vector<RoomStats> get_largest_rooms(int64_t limit=10);
  void update_user_stats(const std::string& user_id);
  UserStats get_user_stats(const std::string& user_id);
  std::vector<UserStats> get_all_user_stats(int64_t limit=100, int64_t offset=0);
  void delete_room_stats(const std::string& room_id);
  void delete_user_stats(const std::string& user_id);
  void regen_room_stats();
  void regen_user_stats();
  int64_t get_total_rooms();
  int64_t get_total_users();
  int64_t get_total_events();
  int64_t get_daily_active_users();
  int64_t get_monthly_active_users();
  std::map<std::string,int64_t> get_daily_messages(int days=7);
  std::vector<std::string> get_rooms_by_member_count(int64_t min_members=2, int64_t limit=100);
private: DatabasePool& db_;
};

// ---- StateDeltasStore (state_deltas.py) ----
struct StateDelta { std::string room_id; std::string event_id; std::string type; std::string state_key;
  std::string prev_event_id; int64_t stream_id{0}; };
class StateDeltasStore { public:
  explicit StateDeltasStore(DatabasePool& db);
  void add_state_delta(const StateDelta& delta);
  std::vector<StateDelta> get_state_deltas(int64_t from_stream, int64_t to_stream, int64_t limit=100);
  int64_t get_max_stream_id();
  void delete_old_deltas(int64_t before_stream_id);
private: DatabasePool& db_;
};

// ---- UIAuthStore (ui_auth.py) ----
struct UIAuthSession { std::string session_id; std::string user_id; std::string client_secret;
  std::string auth_type; json session_data; int64_t creation_ts{0}; int64_t last_updated_ts{0}; };
class UIAuthStore { public:
  explicit UIAuthStore(DatabasePool& db);
  void create_session(const UIAuthSession& session);
  std::optional<UIAuthSession> get_session(const std::string& session_id);
  void update_session(const std::string& session_id, const json& data);
  void delete_session(const std::string& session_id);
  void delete_old_sessions(int64_t before_ts);
  std::vector<UIAuthSession> get_sessions_for_user(const std::string& user_id);
private: DatabasePool& db_;
};

// ---- SessionStore (session.py) ----
class SessionStore { public:
  explicit SessionStore(DatabasePool& db);
  void add_user_session(const std::string& user_id, const std::string& session_id, const json& session_data);
  std::vector<json> get_user_sessions(const std::string& user_id);
  void delete_user_session(const std::string& user_id, const std::string& session_id);
  void delete_all_user_sessions(const std::string& user_id);
  void update_session_data(const std::string& user_id, const std::string& session_id, const json& data);
private: DatabasePool& db_;
};

// ---- OpenIDStore (openid.py) ----
class OpenIDStore { public:
  explicit OpenIDStore(DatabasePool& db);
  void create_openid_token(const std::string& token, const std::string& user_id, int64_t expires_ts);
  std::optional<std::string> get_user_for_token(const std::string& token, int64_t now);
  void delete_expired_tokens(int64_t now);
private: DatabasePool& db_;
};

// ---- UserDirectoryStore (user_directory.py) ----
class UserDirectoryStore { public:
  explicit UserDirectoryStore(DatabasePool& db);
  void add_user(const std::string& user_id, const std::string& display_name, const std::optional<std::string>& avatar_url);
  void update_user(const std::string& user_id, const std::string& display_name, const std::optional<std::string>& avatar_url);
  void remove_user(const std::string& user_id);
  std::vector<std::pair<std::string,std::string>> search_users(const std::string& term, int limit=10);
  void update_user_in_public_rooms(const std::string& user_id);
  void update_user_in_all_public_rooms(const std::string& user_id);
  void delete_user_from_all_public_rooms(const std::string& user_id);
private: DatabasePool& db_;
};

} // namespace
