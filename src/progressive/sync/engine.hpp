#pragma once
#include <atomic>
#include <map>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <string_view>

#include "../storage/database.hpp"
#include "../util/time.hpp"

namespace progressive::sync {

class SlidingSyncEngine {
public:
  SlidingSyncEngine(storage::DatabasePool& db);

  nlohmann::json handle_request(std::string_view conn_id, std::string_view user_id,
                                const nlohmann::json& request);
  nlohmann::json compute_room_data(std::string_view room_id, std::string_view user_id,
                                   const nlohmann::json& required_state,
                                   const nlohmann::json& timeline_limit);

  void add_subscription(std::string_view conn_id, std::string_view room_id,
                        const nlohmann::json& required_state);
  void remove_subscription(std::string_view conn_id, std::string_view room_id);

  std::string new_connection(std::string_view user_id);

private:
  struct Connection {
    std::string conn_id, user_id, pos;
    int64_t created_ts, updated_ts;
    std::map<std::string, nlohmann::json, std::less<>> subscriptions;  // room_id -> config
    std::set<std::string> known_rooms;
  };

  storage::DatabasePool& db_;
  std::map<std::string, Connection, std::less<>> connections_;
  nlohmann::json compute_delta(std::string_view room_id, std::string_view since_token,
                               const nlohmann::json& required_state);
};

class PrometheusExporter {
public:
  PrometheusExporter();

  void record_http_request(std::string_view method, std::string_view path, int status,
                           double duration_ms);
  void record_event_processed();
  void record_push_sent();
  void record_db_query(double duration_ms);
  void record_irc_connection();
  void record_xmpp_stream();
  void record_lemmy_post();

  std::string render() const;

private:
  struct Metrics {
    std::atomic<uint64_t> http_requests_total{0};
    std::atomic<uint64_t> events_processed{0};
    std::atomic<uint64_t> push_sent{0};
    std::atomic<uint64_t> db_queries{0};
    std::atomic<double> db_query_duration_sum{0};
    std::atomic<uint64_t> irc_connections{0};
    std::atomic<uint64_t> xmpp_streams{0};
    std::atomic<uint64_t> lemmy_posts{0};
    std::atomic<uint64_t> rate_limited{0};
  };
  Metrics m_;
};

extern PrometheusExporter g_metrics;

}  // namespace progressive::sync
