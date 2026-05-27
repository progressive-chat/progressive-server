#pragma once
// final_stores.hpp - cache, client_ips, censor_events, delayed_events, deviceinbox, e2e_room_keys, events_forward_extremities, experimental_features, lock, metrics, monthly_active_users, purge_events, rejections, sticky_events, task_scheduler, thread_subscriptions, user_erasure_store
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

class CacheInvalidationStore { public:
  explicit CacheInvalidationStore(DatabasePool& db);
  void invalidate_cache(const std::string& cache_name, const std::vector<std::string>& keys);
  bool is_cache_valid(const std::string& cache_name, const std::string& key, int64_t generation);
  int64_t get_cache_generation(const std::string& cache_name);
  void increment_cache_generation(const std::string& cache_name);
  void invalidate_all_caches();
private: DatabasePool& db_; };

class ClientIPsStore { public:
  explicit ClientIPsStore(DatabasePool& db);
  void store_client_ip(const std::string& user_id, const std::string& device_id, const std::string& ip, const std::string& user_agent, int64_t ts);
  std::vector<std::string> get_client_ips(const std::string& user_id, int64_t since_ts=0);
  std::vector<std::string> get_user_ips_and_agents(const std::string& user_id);
  void delete_old_client_ips(int64_t before_ts);
  void delete_client_ips_for_user(const std::string& user_id);
private: DatabasePool& db_; };

class CensorEventsStore { public:
  explicit CensorEventsStore(DatabasePool& db);
  void add_censored_event(const std::string& event_id, const std::string& reason);
  bool is_censored(const std::string& event_id);
  void remove_censored_event(const std::string& event_id);
private: DatabasePool& db_; };

class DelayedEventsStore { public:
  explicit DelayedEventsStore(DatabasePool& db);
  void add_delayed_event(const std::string& event_id, const std::string& action, int64_t delayed_until_ts);
  std::vector<std::string> get_expired_delayed_events(int64_t now, int limit=100);
  void delete_delayed_event(const std::string& event_id);
private: DatabasePool& db_; };

class DeviceInboxStore { public:
  explicit DeviceInboxStore(DatabasePool& db);
  void add_to_device_message(const std::string& user_id, const std::string& device_id, const std::string& message_type, const json& content, int64_t stream_id);
  std::vector<json> get_to_device_messages(const std::string& user_id, int64_t from_stream, int limit=100);
  void delete_to_device_messages(const std::string& user_id, int64_t up_to_stream);
  void delete_all_to_device_messages(const std::string& user_id);
  int64_t get_max_stream_id();
private: DatabasePool& db_; };

class E2ERoomKeysStore { public:
  explicit E2ERoomKeysStore(DatabasePool& db);
  void set_e2e_room_key(const std::string& user_id, const std::string& room_id, const std::string& session_id, const json& key_data, int64_t ts);
  std::optional<json> get_e2e_room_key(const std::string& user_id, const std::string& room_id, const std::string& session_id);
  std::vector<json> get_e2e_room_keys(const std::string& user_id, const std::optional<std::string>& room_id=std::nullopt);
  void delete_e2e_room_key(const std::string& user_id, const std::string& room_id, const std::string& session_id);
  void delete_e2e_room_keys_for_room(const std::string& user_id, const std::string& room_id);
  void delete_all_e2e_room_keys(const std::string& user_id);
  int64_t count_e2e_room_keys(const std::string& user_id);
  std::optional<int64_t> get_e2e_room_key_version(const std::string& user_id, int64_t version);
  void set_e2e_room_key_version(const std::string& user_id, int64_t version, const json& version_data, int64_t ts);
  void delete_e2e_room_key_version(const std::string& user_id, int64_t version);
private: DatabasePool& db_; };

class EventsForwardExtremitiesStore { public:
  explicit EventsForwardExtremitiesStore(DatabasePool& db);
  void add_forward_extremity(const std::string& room_id, const std::string& event_id);
  void remove_forward_extremity(const std::string& room_id, const std::string& event_id);
  std::vector<std::string> get_forward_extremities(const std::string& room_id);
private: DatabasePool& db_; };

class ExperimentalFeaturesStore { public:
  explicit ExperimentalFeaturesStore(DatabasePool& db);
  void set_feature_enabled(const std::string& user_id, const std::string& feature, bool enabled);
  std::map<std::string,bool> get_features(const std::string& user_id);
  bool is_feature_enabled(const std::string& user_id, const std::string& feature);
private: DatabasePool& db_; };

class LockStore { public:
  explicit LockStore(DatabasePool& db);
  bool try_acquire_lock(const std::string& lock_name, const std::string& lock_key, int64_t timeout_ms);
  void release_lock(const std::string& lock_name, const std::string& lock_key);
  bool is_locked(const std::string& lock_name);
  void cleanup_expired_locks();
private: DatabasePool& db_; };

class MetricsStore { public:
  explicit MetricsStore(DatabasePool& db);
  void record_metric(const std::string& name, double value, int64_t ts);
  std::vector<std::pair<int64_t,double>> get_metric(const std::string& name, int64_t from_ts, int64_t to_ts);
  void delete_old_metrics(int64_t before_ts);
private: DatabasePool& db_; };

class MonthlyActiveUsersStore { public:
  explicit MonthlyActiveUsersStore(DatabasePool& db);
  void record_active_user(const std::string& user_id, int64_t ts);
  int64_t count_monthly_active_users(int64_t now);
  int64_t count_active_users_since(int64_t since_ts);
  std::vector<std::string> get_active_users(int64_t since_ts);
  void populate_monthly_active_users(int64_t since_ts);
  void delete_old_records(int64_t before_ts);
private: DatabasePool& db_; };

class PurgeEventsStore { public:
  explicit PurgeEventsStore(DatabasePool& db);
  void mark_events_for_purge(const std::string& room_id, const std::vector<std::string>& event_ids);
  void purge_events(const std::string& room_id);
  int64_t get_purge_count(const std::string& room_id);
private: DatabasePool& db_; };

class RejectionsStore { public:
  explicit RejectionsStore(DatabasePool& db);
  void reject_event(const std::string& event_id, const std::string& reason);
  std::optional<std::string> get_rejection_reason(const std::string& event_id);
  void unreject_event(const std::string& event_id);
private: DatabasePool& db_; };

class StickyEventsStore { public:
  explicit StickyEventsStore(DatabasePool& db);
  void add_sticky_event(const std::string& room_id, const std::string& event_id, const std::string& event_type);
  std::vector<std::string> get_sticky_events(const std::string& room_id, const std::optional<std::string>& event_type=std::nullopt);
  void remove_sticky_event(const std::string& room_id, const std::string& event_id);
  void remove_all_sticky_events(const std::string& room_id);
private: DatabasePool& db_; };

class TaskSchedulerStore { public:
  explicit TaskSchedulerStore(DatabasePool& db);
  int64_t schedule_task(const std::string& task_name, const json& params, int64_t scheduled_at);
  std::vector<std::pair<int64_t,json>> get_due_tasks(int64_t now, int limit=100);
  void complete_task(int64_t task_id);
  void delete_task(int64_t task_id);
private: DatabasePool& db_; };

class ThreadSubscriptionsStore { public:
  explicit ThreadSubscriptionsStore(DatabasePool& db);
  void subscribe(const std::string& user_id, const std::string& room_id, const std::string& thread_id);
  void unsubscribe(const std::string& user_id, const std::string& room_id, const std::string& thread_id);
  bool is_subscribed(const std::string& user_id, const std::string& room_id, const std::string& thread_id);
  std::vector<std::string> get_subscriptions(const std::string& user_id, const std::string& room_id);
private: DatabasePool& db_; };

class UserErasureStore { public:
  explicit UserErasureStore(DatabasePool& db);
  void mark_user_erased(const std::string& user_id, int64_t ts);
  bool is_user_erased(const std::string& user_id);
  void erase_user_data(const std::string& user_id);
  std::vector<std::string> get_erased_users(int64_t since_ts=0);
private: DatabasePool& db_; };

} // namespace
