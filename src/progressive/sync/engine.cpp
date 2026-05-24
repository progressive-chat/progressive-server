#include "engine.hpp"

#include "../util/random.hpp"

namespace progressive::sync {

// SlidingSyncEngine
SlidingSyncEngine::SlidingSyncEngine(storage::DatabasePool& db) : db_(db) {}

std::string SlidingSyncEngine::new_connection(std::string_view user_id) {
  std::string cid = "c_" + util::random_token(16);
  int64_t now = util::now_ms();
  Connection conn{cid, std::string(user_id), std::to_string(now), now, now};
  connections_[cid] = conn;
  db_.execute(
      "INSERT INTO sliding_sync_connections (connection_id,user_id,pos,created_ts,updated_ts) "
      "VALUES ('" +
      cid + "','" + std::string(user_id) + "',''," + std::to_string(now) + "," +
      std::to_string(now) + ")");
  return cid;
}

nlohmann::json SlidingSyncEngine::handle_request(std::string_view conn_id, std::string_view user_id,
                                                 const nlohmann::json& request) {
  if (connections_.find(std::string(conn_id)) == connections_.end())
    new_connection(user_id);

  auto& conn = connections_[std::string(conn_id)];
  conn.updated_ts = util::now_ms();
  conn.pos = std::to_string(util::now_ms());

  // Process room subscriptions
  if (request.contains("room_subscriptions") && request["room_subscriptions"].is_object()) {
    for (auto& [room_id, config] : request["room_subscriptions"].items())
      add_subscription(conn_id, room_id, config);
  }

  nlohmann::json resp;
  resp["conn_id"] = conn.conn_id;
  resp["pos"] = conn.pos;
  resp["rooms"] = nlohmann::json::object();
  resp["extensions"] = nlohmann::json::object();

  // Compute per-room data
  for (auto& [rid, cfg] : conn.subscriptions) {
    auto required_state = cfg.value("required_state", nlohmann::json::array());
    auto tl_limit = cfg.value("timeline_limit", 20);
    resp["rooms"][rid] = compute_room_data(rid, user_id, required_state, tl_limit);
  }

  return resp;
}

nlohmann::json SlidingSyncEngine::compute_room_data(std::string_view room_id,
                                                    std::string_view user_id,
                                                    const nlohmann::json& required_state,
                                                    const nlohmann::json& timeline_limit) {
  nlohmann::json room;
  int limit = timeline_limit.is_number() ? timeline_limit.get<int>() : 20;

  // Timeline events
  auto rows = db_.query("SELECT * FROM events WHERE room_id='" + std::string(room_id) +
                        "' ORDER BY depth DESC LIMIT " + std::to_string(limit));
  room["timeline"] = nlohmann::json::array();
  for (auto& r : rows) {
    nlohmann::json ev;
    ev["event_id"] = r["event_id"];
    ev["type"] = r["type"];
    ev["sender"] = r["sender"];
    try {
      ev["content"] = nlohmann::json::parse(r["content"].template get<std::string>());
    } catch (...) {
      ev["content"] = nlohmann::json::object();
    }
    room["timeline"].push_back(ev);
  }

  // Required state
  room["required_state"] = nlohmann::json::array();
  for (auto& rs : required_state) {
    std::string type = rs.value("type", "");
    std::string key = rs.value("state_key", "");
    auto sr =
        db_.query("SELECT * FROM events WHERE room_id='" + std::string(room_id) + "' AND type='" +
                  type + "' AND state_key='" + key + "' ORDER BY depth DESC LIMIT 1");
    if (!sr.empty()) {
      nlohmann::json se;
      se["event_id"] = sr[0]["event_id"];
      se["type"] = sr[0]["type"];
      se["sender"] = sr[0]["sender"];
      se["state_key"] = sr[0].value("state_key", "");
      try {
        se["content"] = nlohmann::json::parse(sr[0]["content"].template get<std::string>());
      } catch (...) {
        se["content"] = nlohmann::json::object();
      }
      room["required_state"].push_back(se);
    }
  }

  // Unread counts
  auto unreads = db_.query(
      "SELECT notif_count,highlight_count FROM event_push_summary "
      "WHERE user_id='" +
      std::string(user_id) + "' AND room_id='" + std::string(room_id) + "'");
  if (!unreads.empty()) {
    room["notification_count"] = unreads[0].value("notif_count", 0);
    room["highlight_count"] = unreads[0].value("highlight_count", 0);
  }

  // Member count
  auto cnt = db_.query("SELECT COUNT(*) as c FROM room_memberships WHERE room_id='" +
                       std::string(room_id) + "' AND membership='join'");
  room["joined_count"] =
      (!cnt.empty() && cnt[0]["c"].is_number()) ? cnt[0]["c"].template get<int>() : 0;

  return room;
}

void SlidingSyncEngine::add_subscription(std::string_view conn_id, std::string_view room_id,
                                         const nlohmann::json& required_state) {
  connections_[std::string(conn_id)].subscriptions[std::string(room_id)] = required_state;
  db_.execute("INSERT OR REPLACE INTO sliding_sync_joined_rooms (connection_id,room_id) VALUES ('" +
              std::string(conn_id) + "','" + std::string(room_id) + "')");
}

void SlidingSyncEngine::remove_subscription(std::string_view conn_id, std::string_view room_id) {
  connections_[std::string(conn_id)].subscriptions.erase(std::string(room_id));
}

nlohmann::json SlidingSyncEngine::compute_delta(std::string_view room_id,
                                                std::string_view since_token,
                                                const nlohmann::json& required_state) {
  nlohmann::json delta;
  return delta;
}

// PrometheusExporter
PrometheusExporter::PrometheusExporter() = default;
PrometheusExporter g_metrics;

void PrometheusExporter::record_http_request(std::string_view, std::string_view, int, double) {
  m_.http_requests_total++;
}
void PrometheusExporter::record_event_processed() {
  m_.events_processed++;
}
void PrometheusExporter::record_push_sent() {
  m_.push_sent++;
}
void PrometheusExporter::record_db_query(double ms) {
  m_.db_queries++;
  m_.db_query_duration_sum.store(m_.db_query_duration_sum.load() + ms);
}
void PrometheusExporter::record_irc_connection() {
  m_.irc_connections++;
}
void PrometheusExporter::record_xmpp_stream() {
  m_.xmpp_streams++;
}
void PrometheusExporter::record_lemmy_post() {
  m_.lemmy_posts++;
}

std::string PrometheusExporter::render() const {
  std::stringstream s;
  s << "# HELP progressive_http_requests_total Total HTTP requests\n"
    << "# TYPE progressive_http_requests_total counter\n"
    << "progressive_http_requests_total " << m_.http_requests_total.load() << "\n"
    << "# HELP progressive_events_processed_total Total events\n"
    << "# TYPE progressive_events_processed_total counter\n"
    << "progressive_events_processed_total " << m_.events_processed.load() << "\n"
    << "# HELP progressive_push_sent_total Total push notifications\n"
    << "# TYPE progressive_push_sent_total counter\n"
    << "progressive_push_sent_total " << m_.push_sent.load() << "\n"
    << "# HELP progressive_db_queries_total Total DB queries\n"
    << "# TYPE progressive_db_queries_total counter\n"
    << "progressive_db_queries_total " << m_.db_queries.load() << "\n"
    << "# HELP progressive_irc_connections IRC connections\n"
    << "# TYPE progressive_irc_connections gauge\n"
    << "progressive_irc_connections " << m_.irc_connections.load() << "\n"
    << "# HELP progressive_xmpp_streams XMPP streams\n"
    << "# TYPE progressive_xmpp_streams gauge\n"
    << "progressive_xmpp_streams " << m_.xmpp_streams.load() << "\n"
    << "# HELP progressive_lemmy_post_count Lemmy posts\n"
    << "# TYPE progressive_lemmy_post_count gauge\n"
    << "progressive_lemmy_post_count " << m_.lemmy_posts.load() << "\n"
    << "# HELP progressive_rate_limited_total Rate limit hits\n"
    << "# TYPE progressive_rate_limited_total counter\n"
    << "progressive_rate_limited_total " << m_.rate_limited.load() << "\n";
  return s.str();
}

}  // namespace progressive::sync
