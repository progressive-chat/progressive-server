#pragma once
// Combined storage modules: pusher.hpp, search.hpp, tags.hpp, account_data.hpp, relations.hpp
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

// ---- Pusher Store (pusher.py) ----
struct Pusher { std::string user_id; std::string pushkey; std::string app_id;
  std::string kind; std::string app_display_name; std::string device_display_name;
  std::string profile_tag; std::string lang; json data; std::optional<std::string> last_stream_ordering; };
class PusherStore { public:
  explicit PusherStore(DatabasePool& db);
  void add_pusher(const std::string& user_id, const Pusher& p);
  void update_pusher(const std::string& user_id, const Pusher& p);
  void delete_pusher(const std::string& user_id, const std::string& pushkey, const std::string& app_id);
  std::vector<Pusher> get_pushers(const std::string& user_id);
  std::vector<Pusher> get_all_pushers();
  std::vector<Pusher> get_pushers_by_app(const std::string& app_id);
  void update_pusher_last_stream_ordering(const std::string& user_id, const std::string& pushkey, const std::string& app_id, const std::string& so);
  void update_pusher_last_success(const std::string& user_id, const std::string& pushkey, const std::string& app_id, int64_t ts);
  int64_t get_pusher_count();
private: DatabasePool& db_;
};

// ---- Search Store (search.py) ----
struct SearchEntry { std::string event_id; std::string room_id; std::string key; std::string value; int64_t stream_ordering{0}; int64_t origin_server_ts{0}; };
class SearchStore { public:
  explicit SearchStore(DatabasePool& db);
  void store_search_entries(const std::vector<SearchEntry>& entries);
  std::vector<std::string> search_events(const std::string& room_id, const std::string& term, int limit=50);
  std::vector<std::string> search_all_rooms(const std::string& term, int limit=50, const std::vector<std::string>& room_ids={});
  std::vector<std::string> search_events_by_key(const std::string& room_id, const std::string& key, int limit=50);
  void delete_search_entries(const std::string& event_id);
  void reindex_event(const std::string& event_id, const std::string& room_id, const json& content, int64_t origin_server_ts);
  void add_search_index(const std::string& room_id);
private: DatabasePool& db_;
};

// ---- Tags Store (tags.py) ----
struct RoomTag { std::string user_id; std::string room_id; std::string tag; json content; double order{0}; };
class TagsStore { public:
  explicit TagsStore(DatabasePool& db);
  void add_tag(const std::string& user_id, const std::string& room_id, const std::string& tag, const json& content);
  void remove_tag(const std::string& user_id, const std::string& room_id, const std::string& tag);
  std::vector<RoomTag> get_tags(const std::string& user_id, const std::string& room_id);
  std::map<std::string, std::vector<RoomTag>> get_tags_for_user(const std::string& user_id);
  void update_tag_order(const std::string& user_id, const std::string& room_id, const std::vector<std::pair<std::string,double>>& orders);
  void delete_all_tags_for_room(const std::string& room_id);
private: DatabasePool& db_;
};

// ---- Account Data Store (account_data.py) ----
class AccountDataStore { public:
  explicit AccountDataStore(DatabasePool& db);
  void add_account_data(const std::string& user_id, const std::string& type, const json& content);
  void add_room_account_data(const std::string& user_id, const std::string& room_id, const std::string& type, const json& content);
  std::optional<json> get_account_data(const std::string& user_id, const std::string& type);
  std::optional<json> get_room_account_data(const std::string& user_id, const std::string& room_id, const std::string& type);
  std::map<std::string, json> get_all_account_data(const std::string& user_id);
  std::map<std::string, json> get_all_room_account_data(const std::string& user_id, const std::string& room_id);
  void delete_account_data(const std::string& user_id, const std::string& type);
private: DatabasePool& db_;
};

// ---- Relations Store (relations.py) ----
struct Relation { std::string event_id; std::string relates_to_id; std::string relation_type; std::optional<std::string> aggregation_key; };
class RelationsStore { public:
  explicit RelationsStore(DatabasePool& db);
  void add_relation(const Relation& rel);
  void remove_relation(const std::string& event_id);
  std::vector<Relation> get_relations_for_event(const std::string& relates_to_id);
  std::vector<Relation> get_relations_by_type(const std::string& relates_to_id, const std::string& relation_type);
  std::map<std::string, int64_t> get_aggregation_counts(const std::string& relates_to_id, const std::string& relation_type);
  std::optional<Relation> get_relation(const std::string& event_id);
  void delete_relations_for_event(const std::string& event_id);
  std::vector<std::string> get_events_with_relations(const std::string& relates_to_id, const std::string& relation_type, int limit=100);
private: DatabasePool& db_;
};

} // namespace
