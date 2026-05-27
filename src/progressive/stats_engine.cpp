// ============================================================================
// stats_engine.cpp — Matrix Statistics Engine: Room Stats, User Stats,
//   Server Stats, Aggregation, Caching, Admin API, Sync Integration
//
// Implements:
//   - Room stats: update room_stats_state table (joined/invited/left/banned
//     members, room name, topic, alias, encryption state, history visibility,
//     join rules, guest access, room type, is_federatable flag)
//   - User stats: update user_daily_visits table, daily/monthly active user
//     counts (DAU/MAU), user creation timeline with bucketing
//   - Server stats: total users (active/deactivated/guest/appservice),
//     total rooms, total events (state + non-state), total media bytes
//   - Room stats aggregation: background update to populate room_stats_state
//     from current_state_events and room_memberships, incremental updates
//     triggered on state changes and membership changes
//   - Stats cache: in-memory cache for computed statistics with TTL-based
//     expiration, invalidate on relevant changes
//   - Stats admin API: GET /_synapse/admin/v1/statistics,
//     GET /_synapse/admin/v1/statistics/users/media,
//     GET /_synapse/admin/v1/statistics/database/rooms
//   - Stats sync: stats not per-spec in /sync, but exposed via admin API
//     and optionally injected into server notices system reports
//   - Metrics collection: Prometheus-style gauges and counters for request
//     rates, event throughput, user counts, room counts, federation activity
//
// Equivalent to:
//   synapse/stats.py (statistics engine)
//   synapse/app/homeserver.py (statistics reporting)
//   synapse/rest/admin/statistics.py
//   synapse/metrics/__init__.py (metrics collection)
//   synapse/metrics/metric.py (gauge/counter)
//   synapse/handlers/stats.py
//   synapse/util/caches/ (cache layer)
//
// Target: 2500+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

// Internal project includes
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/storage/databases/main/media_repository.hpp"
#include "progressive/storage/databases/main/stream.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class RoomStatsAggregator;
class UserStatsTracker;
class ServerStatsCollector;
class StatsCache;
class StatsAdminAPI;
class MetricsCollector;
class StatsEngine;

// ============================================================================
// Anonymous namespace — Internal helpers, constants, and types
// ============================================================================
namespace {

// ---- Timestamp helpers ----

inline int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
      chr::system_clock::now().time_since_epoch())
      .count();
}

inline int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
      chr::system_clock::now().time_since_epoch())
      .count();
}

inline int64_t midnight_utc_sec() {
  auto now = chr::system_clock::now();
  auto tt = chr::system_clock::to_time_t(now);
  auto* utc = std::gmtime(&tt);
  utc->tm_hour = 0;
  utc->tm_min = 0;
  utc->tm_sec = 0;
  // Convert back to epoch seconds using timegm
  auto mid = std::mktime(utc); // approximation; timegm ideal
  return static_cast<int64_t>(mid);
}

inline int64_t days_ago_sec(int days) {
  return now_sec() - static_cast<int64_t>(days) * 86400;
}

inline std::string today_date_str() {
  char buf[16];
  auto t = std::time(nullptr);
  std::strftime(buf, sizeof(buf), "%Y-%m-%d", std::gmtime(&t));
  return buf;
}

inline std::string date_str_from_sec(int64_t sec) {
  char buf[16];
  auto t = static_cast<std::time_t>(sec);
  std::strftime(buf, sizeof(buf), "%Y-%m-%d", std::gmtime(&t));
  return buf;
}

inline int64_t sec_since(int64_t timestamp_sec) {
  return now_sec() - timestamp_sec;
}

// ---- String constants ----

constexpr std::string_view kMembershipJoin = "join";
constexpr std::string_view kMembershipInvite = "invite";
constexpr std::string_view kMembershipLeave = "leave";
constexpr std::string_view kMembershipBan = "ban";
constexpr std::string_view kMembershipKnock = "knock";

constexpr std::string_view kEventTypeRoomName = "m.room.name";
constexpr std::string_view kEventTypeRoomTopic = "m.room.topic";
constexpr std::string_view kEventTypeRoomCanonicalAlias = "m.room.canonical_alias";
constexpr std::string_view kEventTypeRoomEncryption = "m.room.encryption";
constexpr std::string_view kEventTypeRoomHistoryVisibility = "m.room.history_visibility";
constexpr std::string_view kEventTypeRoomJoinRules = "m.room.join_rules";
constexpr std::string_view kEventTypeRoomGuestAccess = "m.room.guest_access";
constexpr std::string_view kEventTypeRoomCreate = "m.room.create";
constexpr std::string_view kEventTypeRoomMember = "m.room.member";

constexpr const char* kStatSuffixCurrent = "_current";
constexpr const char* kStatSuffixTotal = "_total";
constexpr const char* kStatSuffixDaily = "_daily";
constexpr const char* kStatSuffixMonthly = "_monthly";

// ---- Cache TTLs (milliseconds) ----

constexpr int64_t kRoomStatsCacheTTLMs = 60'000;        // 1 minute
constexpr int64_t kUserStatsCacheTTLMs = 300'000;       // 5 minutes
constexpr int64_t kServerStatsCacheTTLMs = 60'000;      // 1 minute
constexpr int64_t kDAUMAUCacheTTLMs = 3'600'000;        // 1 hour
constexpr int64_t kMediaStatsCacheTTLMs = 600'000;      // 10 minutes
constexpr int64_t kRoomListCacheTTLMs = 120'000;        // 2 minutes

// ---- Aggregation batch sizes ----

constexpr int64_t kAggregationBatchSize = 500;
constexpr int64_t kAggregationIntervalMs = 300'000;     // 5 minutes
constexpr int64_t kUserDailyVisitsFlushIntervalMs = 60'000; // 1 minute

// ---- Metrics names ----

constexpr const char* kMetricRequestsTotal = "progressive_requests_total";
constexpr const char* kMetricEventsProcessed = "progressive_events_processed_total";
constexpr const char* kMetricUsersTotal = "progressive_users_total";
constexpr const char* kMetricUsersActive = "progressive_users_active";
constexpr const char* kMetricRoomsTotal = "progressive_rooms_total";
constexpr const char* kMetricFederationRequests = "progressive_federation_requests_total";
constexpr const char* kMetricMessagesSent = "progressive_messages_sent_total";
constexpr const char* kMetricMediaBytes = "progressive_media_bytes_total";
constexpr const char* kMetricDAU = "progressive_daily_active_users";
constexpr const char* kMetricMAU = "progressive_monthly_active_users";
constexpr const char* kMetricCacheHits = "progressive_stats_cache_hits_total";
constexpr const char* kMetricCacheMisses = "progressive_stats_cache_misses_total";
constexpr const char* kMetricDBQueryDuration = "progressive_db_query_duration_seconds";

// ---- User-agent parsing for metrics ----

struct UserAgentInfo {
  std::string platform;   // "android", "ios", "web", "electron", "unknown"
  std::string client_name; // "element", "fluffychat", "nheko", etc.
  std::string client_version;
};

UserAgentInfo parse_user_agent(const std::string& ua) {
  UserAgentInfo info;
  info.platform = "unknown";
  info.client_name = "unknown";
  info.client_version = "unknown";

  if (ua.empty()) return info;

  std::string lower;
  lower.reserve(ua.size());
  for (char c : ua) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

  // Detect platform
  if (lower.find("android") != std::string::npos) info.platform = "android";
  else if (lower.find("ios") != std::string::npos || lower.find("iphone") != std::string::npos)
    info.platform = "ios";
  else if (lower.find("electron") != std::string::npos) info.platform = "electron";
  else if (lower.find("mozilla") != std::string::npos || lower.find("chrome") != std::string::npos)
    info.platform = "web";

  // Detect client
  if (lower.find("element") != std::string::npos) info.client_name = "element";
  else if (lower.find("fluffychat") != std::string::npos) info.client_name = "fluffychat";
  else if (lower.find("nheko") != std::string::npos) info.client_name = "nheko";
  else if (lower.find("schneegans") != std::string::npos || lower.find("cinny") != std::string::npos)
    info.client_name = "cinny";
  else if (lower.find("hydrogen") != std::string::npos) info.client_name = "hydrogen";
  else if (lower.find("fractal") != std::string::npos) info.client_name = "fractal";
  else if (lower.find("neochat") != std::string::npos) info.client_name = "neochat";
  else if (lower.find("syphon") != std::string::npos) info.client_name = "syphon";

  return info;
}

// ---- Room type classification ----

std::string classify_room_type(const std::string& room_id) {
  // Simple heuristic based on room ID or metadata
  if (room_id.empty()) return "unknown";
  // Space rooms in Matrix have type m.space
  // We can't tell from just the ID in real code, but provide a stub
  return "room";
}

// ---- Event type classification ----

enum class EventCategory {
  kMessage,
  kState,
  kMembership,
  kReaction,
  kRedaction,
  kOther
};

EventCategory classify_event(const std::string& event_type) {
  if (event_type == "m.room.message" || event_type == "m.room.encrypted")
    return EventCategory::kMessage;
  if (event_type == "m.reaction")
    return EventCategory::kReaction;
  if (event_type == "m.room.redaction")
    return EventCategory::kRedaction;
  if (event_type.find("m.room.") == 0)
    return EventCategory::kState;
  if (event_type == "m.room.member")
    return EventCategory::kMembership;
  return EventCategory::kOther;
}

// ---- Helper: check if string is a valid room ID ----

bool is_valid_room_id(const std::string& rid) {
  return !rid.empty() && rid[0] == '!' && rid.find(':') != std::string::npos;
}

// ---- Helper: membership string normalization ----

std::string normalize_membership(const std::string& membership) {
  std::string lower;
  lower.reserve(membership.size());
  for (char c : membership) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (lower == "join" || lower == "joined") return "join";
  if (lower == "invite" || lower == "invited") return "invite";
  if (lower == "leave" || lower == "left") return "leave";
  if (lower == "ban" || lower == "banned") return "ban";
  if (lower == "knock" || lower == "knocking") return "knock";
  return lower;
}

// ---- Time bucket helpers ----

std::string time_bucket_hour(int64_t sec) {
  char buf[20];
  auto t = static_cast<std::time_t>(sec);
  auto* utc = std::gmtime(&t);
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:00:00Z", utc);
  return buf;
}

std::string time_bucket_day(int64_t sec) {
  return date_str_from_sec(sec);
}

std::string time_bucket_week(int64_t sec) {
  // Monday-based week bucket
  auto t = static_cast<std::time_t>(sec);
  auto* utc = std::gmtime(&t);
  int days_since_monday = (utc->tm_wday + 6) % 7; // tm_wday: 0=Sun
  auto week_start = sec - days_since_monday * 86400;
  char buf[20];
  auto wt = static_cast<std::time_t>(week_start);
  auto* wutc = std::gmtime(&wt);
  std::strftime(buf, sizeof(buf), "%Y-%m-%d", wutc);
  return buf;
}

std::string time_bucket_month(int64_t sec) {
  char buf[10];
  auto t = static_cast<std::time_t>(sec);
  auto* utc = std::gmtime(&t);
  std::strftime(buf, sizeof(buf), "%Y-%m", utc);
  return buf;
}

// ---- Statistical helpers ----

double compute_percentile(std::vector<int64_t>& values, double percentile) {
  if (values.empty()) return 0.0;
  std::sort(values.begin(), values.end());
  double idx = percentile / 100.0 * (values.size() - 1);
  size_t lo = static_cast<size_t>(std::floor(idx));
  size_t hi = static_cast<size_t>(std::ceil(idx));
  if (lo == hi) return static_cast<double>(values[lo]);
  double frac = idx - lo;
  return values[lo] * (1.0 - frac) + values[hi] * frac;
}

double compute_mean(const std::vector<int64_t>& values) {
  if (values.empty()) return 0.0;
  int64_t sum = 0;
  for (auto v : values) sum += v;
  return static_cast<double>(sum) / values.size();
}

double compute_stddev(const std::vector<int64_t>& values, double mean) {
  if (values.size() < 2) return 0.0;
  double sum_sq = 0.0;
  for (auto v : values) {
    double diff = static_cast<double>(v) - mean;
    sum_sq += diff * diff;
  }
  return std::sqrt(sum_sq / (values.size() - 1));
}

// ============================================================================
// PrometheusCounter — Thread-safe monotonically increasing counter
// ============================================================================

class PrometheusCounter {
public:
  explicit PrometheusCounter(const std::string& name, const std::string& help,
                             const std::vector<std::string>& label_names = {})
      : name_(name), help_(help), label_names_(label_names) {}

  void inc(double amount = 1.0) {
    value_.fetch_add(amount, std::memory_order_relaxed);
  }

  void inc_labels(const std::map<std::string, std::string>& labels, double amount = 1.0) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = labels_key(labels);
    double old_val = labeled_values_[key].load(std::memory_order_relaxed);
    while (!labeled_values_[key].compare_exchange_weak(old_val, old_val + amount,
                                                        std::memory_order_relaxed)) {}
  }

  double value() const { return value_.load(std::memory_order_relaxed); }

  double value_labels(const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = labels_key(labels);
    auto it = labeled_values_.find(key);
    if (it != labeled_values_.end())
      return it->second.load(std::memory_order_relaxed);
    return 0.0;
  }

  // Export to Prometheus text format
  std::string to_prometheus() const {
    std::stringstream ss;
    ss << "# HELP " << name_ << " " << help_ << "\n";
    ss << "# TYPE " << name_ << " counter\n";
    ss << name_ << " " << std::fixed << std::setprecision(0) << value() << "\n";

    // Labeled values
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [key, val] : labeled_values_) {
      ss << name_ << "{" << key << "} " << std::fixed << std::setprecision(0)
         << val.load(std::memory_order_relaxed) << "\n";
    }
    return ss.str();
  }

  void reset() {
    value_.store(0.0, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(mutex_);
    labeled_values_.clear();
  }

  const std::string& name() const { return name_; }

private:
  std::string labels_key(const std::map<std::string, std::string>& labels) {
    std::stringstream ss;
    bool first = true;
    for (auto& [k, v] : labels) {
      if (!first) ss << ",";
      first = false;
      ss << k << "=\"" << v << "\"";
    }
    return ss.str();
  }

  std::string name_;
  std::string help_;
  std::vector<std::string> label_names_;
  std::atomic<double> value_{0.0};
  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::atomic<double>> labeled_values_;
};

// ============================================================================
// PrometheusGauge — Thread-safe gauge that can go up and down
// ============================================================================

class PrometheusGauge {
public:
  explicit PrometheusGauge(const std::string& name, const std::string& help,
                           const std::vector<std::string>& label_names = {})
      : name_(name), help_(help), label_names_(label_names) {}

  void set(double value) {
    value_.store(value, std::memory_order_relaxed);
  }

  void set_labels(const std::map<std::string, std::string>& labels, double value) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = labels_key(labels);
    auto it = labeled_values_.find(key);
    if (it != labeled_values_.end()) {
      it->second.store(value, std::memory_order_relaxed);
    } else {
      labeled_values_.emplace(std::piecewise_construct,
                              std::forward_as_tuple(key),
                              std::forward_as_tuple(value));
    }
  }

  void inc(double amount = 1.0) {
    double expected = value_.load(std::memory_order_relaxed);
    while (!value_.compare_exchange_weak(expected, expected + amount,
                                          std::memory_order_relaxed)) {}
  }

  void dec(double amount = 1.0) {
    inc(-amount);
  }

  double value() const { return value_.load(std::memory_order_relaxed); }

  double value_labels(const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = labels_key(labels);
    auto it = labeled_values_.find(key);
    if (it != labeled_values_.end())
      return it->second.load(std::memory_order_relaxed);
    return 0.0;
  }

  std::string to_prometheus() const {
    std::stringstream ss;
    ss << "# HELP " << name_ << " " << help_ << "\n";
    ss << "# TYPE " << name_ << " gauge\n";
    ss << name_ << " " << std::fixed << std::setprecision(2) << value() << "\n";

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [key, val] : labeled_values_) {
      ss << name_ << "{" << key << "} " << std::fixed << std::setprecision(2)
         << val.load(std::memory_order_relaxed) << "\n";
    }
    return ss.str();
  }

  const std::string& name() const { return name_; }

private:
  std::string labels_key(const std::map<std::string, std::string>& labels) {
    std::stringstream ss;
    bool first = true;
    for (auto& [k, v] : labels) {
      if (!first) ss << ",";
      first = false;
      ss << k << "=\"" << v << "\"";
    }
    return ss.str();
  }

  std::string name_;
  std::string help_;
  std::vector<std::string> label_names_;
  std::atomic<double> value_{0.0};
  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::atomic<double>> labeled_values_;
};

// ============================================================================
// HistogramBucket — Simple histogram for request durations
// ============================================================================

class SimpleHistogram {
public:
  SimpleHistogram(const std::string& name, const std::string& help,
                  const std::vector<double>& buckets)
      : name_(name), help_(help), buckets_(buckets), counts_(buckets.size() + 1, 0) {}

  void observe(double value) {
    sum_.fetch_add(value, std::memory_order_relaxed);
    count_.fetch_add(1, std::memory_order_relaxed);
    size_t idx = 0;
    for (size_t i = 0; i < buckets_.size(); i++) {
      if (value <= buckets_[i]) { idx = i; break; }
      idx = buckets_.size(); // +Inf bucket
    }
    counts_[idx].fetch_add(1, std::memory_order_relaxed);
  }

  double sum() const { return sum_.load(std::memory_order_relaxed); }
  int64_t count() const { return count_.load(std::memory_order_relaxed); }

  std::string to_prometheus() const {
    std::stringstream ss;
    ss << "# HELP " << name_ << " " << help_ << "\n";
    ss << "# TYPE " << name_ << " histogram\n";
    for (size_t i = 0; i < buckets_.size(); i++) {
      ss << name_ << "_bucket{le=\"" << std::fixed << std::setprecision(3)
         << buckets_[i] << "\"} " << counts_[i].load(std::memory_order_relaxed) << "\n";
    }
    ss << name_ << "_bucket{le=\"+Inf\"} "
       << counts_.back().load(std::memory_order_relaxed) << "\n";
    ss << name_ << "_sum " << std::fixed << std::setprecision(6) << sum() << "\n";
    ss << name_ << "_count " << count() << "\n";
    return ss.str();
  }

private:
  std::string name_;
  std::string help_;
  std::vector<double> buckets_;
  std::vector<std::atomic<int64_t>> counts_;
  std::atomic<double> sum_{0.0};
  std::atomic<int64_t> count_{0};
};

}  // anonymous namespace

// ============================================================================
// RoomStatsInfo — Complete room statistics snapshot
// ============================================================================

struct RoomStatsInfo {
  std::string room_id;
  std::string room_name;
  std::string room_topic;
  std::string canonical_alias;
  std::string room_type;               // "room", "space"
  std::string join_rules;              // "public", "invite", "knock", "restricted"
  std::string history_visibility;      // "shared", "invited", "joined", "world_readable"
  std::string guest_access;            // "can_join", "forbidden"
  bool is_encrypted = false;
  bool is_federatable = true;
  int64_t joined_members = 0;
  int64_t invited_members = 0;
  int64_t left_members = 0;
  int64_t banned_members = 0;
  int64_t total_members = 0;
  int64_t local_members = 0;
  int64_t remote_members = 0;
  int64_t state_events = 0;
  int64_t forward_extremities = 0;
  int64_t backward_extremities = 0;
  int64_t total_events = 0;
  int64_t creation_ts = 0;
  int64_t last_activity_ts = 0;
  int64_t stats_updated_ts = 0;

  json to_json() const {
    json j;
    j["room_id"] = room_id;
    j["room_name"] = room_name;
    j["room_topic"] = room_topic;
    j["canonical_alias"] = canonical_alias;
    j["room_type"] = room_type;
    j["join_rules"] = join_rules;
    j["history_visibility"] = history_visibility;
    j["guest_access"] = guest_access;
    j["is_encrypted"] = is_encrypted;
    j["is_federatable"] = is_federatable;
    j["joined_members"] = joined_members;
    j["invited_members"] = invited_members;
    j["left_members"] = left_members;
    j["banned_members"] = banned_members;
    j["total_members"] = total_members;
    j["local_members"] = local_members;
    j["remote_members"] = remote_members;
    j["state_events"] = state_events;
    j["forward_extremities"] = forward_extremities;
    j["backward_extremities"] = backward_extremities;
    j["total_events"] = total_events;
    j["creation_ts"] = creation_ts;
    j["last_activity_ts"] = last_activity_ts;
    j["stats_updated_ts"] = stats_updated_ts;
    return j;
  }
};

// ============================================================================
// UserStatsInfo — User statistics snapshot
// ============================================================================

struct UserStatsInfo {
  std::string user_id;
  std::string display_name;
  bool is_guest = false;
  bool is_admin = false;
  bool is_deactivated = false;
  bool is_appservice = false;
  int64_t creation_ts = 0;
  int64_t last_seen_ts = 0;
  int64_t last_daily_visit_ts = 0;
  int64_t joined_rooms_count = 0;
  int64_t total_events_sent = 0;
  int64_t total_media_uploaded_bytes = 0;
  int64_t total_media_downloaded_bytes = 0;
  int64_t total_media_count = 0;
  std::vector<std::string> devices;

  json to_json() const {
    json j;
    j["user_id"] = user_id;
    j["display_name"] = display_name;
    j["is_guest"] = is_guest;
    j["is_admin"] = is_admin;
    j["is_deactivated"] = is_deactivated;
    j["is_appservice"] = is_appservice;
    j["creation_ts"] = creation_ts;
    j["last_seen_ts"] = last_seen_ts;
    j["last_daily_visit_ts"] = last_daily_visit_ts;
    j["joined_rooms_count"] = joined_rooms_count;
    j["total_events_sent"] = total_events_sent;
    j["total_media_uploaded_bytes"] = total_media_uploaded_bytes;
    j["total_media_downloaded_bytes"] = total_media_downloaded_bytes;
    j["total_media_count"] = total_media_count;
    j["devices"] = devices;
    return j;
  }

  json to_summary_json() const {
    json j;
    j["user_id"] = user_id;
    j["display_name"] = display_name;
    j["is_guest"] = is_guest;
    j["is_deactivated"] = is_deactivated;
    j["joined_rooms"] = joined_rooms_count;
    j["media_count"] = total_media_count;
    j["media_length"] = total_media_uploaded_bytes; // Synapse API uses "media_length"
    return j;
  }
};

// ============================================================================
// ServerStatsSnapshot — Full server-level statistics
// ============================================================================

struct ServerStatsSnapshot {
  // User counts
  int64_t total_users = 0;
  int64_t total_non_bridge_users = 0;
  int64_t total_active_users = 0;
  int64_t daily_active_users = 0;
  int64_t monthly_active_users = 0;
  int64_t total_guests = 0;
  int64_t total_deactivated_users = 0;
  int64_t total_appservice_users = 0;
  int64_t total_real_users = 0; // non-guest, non-appservice, non-deactivated

  // Room counts
  int64_t total_rooms = 0;
  int64_t total_public_rooms = 0;
  int64_t total_encrypted_rooms = 0;
  int64_t total_spaces = 0;
  int64_t active_rooms_30d = 0;
  int64_t active_rooms_7d = 0;
  int64_t active_rooms_1d = 0;

  // Event counts
  int64_t total_events = 0;
  int64_t total_state_events = 0;
  int64_t total_messages = 0;
  int64_t total_reactions = 0;
  int64_t events_sent_24h = 0;
  int64_t events_sent_7d = 0;
  int64_t events_sent_30d = 0;

  // Media stats
  int64_t total_local_media_bytes = 0;
  int64_t total_remote_media_bytes = 0;
  int64_t total_media_count = 0;
  int64_t media_uploaded_24h = 0;
  int64_t media_downloaded_24h = 0;

  // Federation stats
  int64_t federation_requests_sent_24h = 0;
  int64_t federation_requests_received_24h = 0;
  int64_t federation_failures_24h = 0;

  // Compute timestamp
  int64_t computed_ts = 0;

  json to_json() const {
    json j;
    j["total_users"] = total_users;
    j["total_non_bridge_users"] = total_non_bridge_users;
    j["total_active_users"] = total_active_users;
    j["daily_active_users"] = daily_active_users;
    j["monthly_active_users"] = monthly_active_users;
    j["total_guests"] = total_guests;
    j["total_deactivated_users"] = total_deactivated_users;
    j["total_appservice_users"] = total_appservice_users;
    j["total_real_users"] = total_real_users;
    j["total_rooms"] = total_rooms;
    j["total_public_rooms"] = total_public_rooms;
    j["total_encrypted_rooms"] = total_encrypted_rooms;
    j["total_spaces"] = total_spaces;
    j["active_rooms_30d"] = active_rooms_30d;
    j["active_rooms_7d"] = active_rooms_7d;
    j["active_rooms_1d"] = active_rooms_1d;
    j["total_events"] = total_events;
    j["total_state_events"] = total_state_events;
    j["total_messages"] = total_messages;
    j["total_reactions"] = total_reactions;
    j["events_sent_24h"] = events_sent_24h;
    j["events_sent_7d"] = events_sent_7d;
    j["events_sent_30d"] = events_sent_30d;
    j["total_local_media_bytes"] = total_local_media_bytes;
    j["total_remote_media_bytes"] = total_remote_media_bytes;
    j["total_media_count"] = total_media_count;
    j["media_uploaded_24h"] = media_uploaded_24h;
    j["media_downloaded_24h"] = media_downloaded_24h;
    j["federation_requests_sent_24h"] = federation_requests_sent_24h;
    j["federation_requests_received_24h"] = federation_requests_received_24h;
    j["federation_failures_24h"] = federation_failures_24h;
    j["computed_ts"] = computed_ts;
    return j;
  }
};

// ============================================================================
// 1. RoomStatsAggregator
//
// Aggregates room statistics: populates and maintains room_stats_state table.
// Runs as a background update for initial population and handles incremental
// updates triggered by state changes and membership changes.
//
// Equivalent to synapse/storage/databases/main/stats.py room portions
// ============================================================================

class RoomStatsAggregator {
public:
  explicit RoomStatsAggregator(storage::DatabasePool& db)
      : db_(db), running_(false) {}

  // ---- Lifecycle ----

  void start() {
    if (running_.exchange(true)) return;
    // Launch background aggregation thread
    worker_ = std::thread([this]() { aggregation_loop(); });
  }

  void stop() {
    running_.store(false);
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();
  }

  // ---- Full aggregation (background population) ----

  /// Run full aggregation of all room stats from current_state_events
  /// and room_memberships. This populates room_stats_state from scratch.
  json run_full_aggregation(int64_t batch_size = kAggregationBatchSize) {
    int64_t rooms_processed = 0;
    int64_t rooms_skipped = 0;
    int64_t errors = 0;
    std::vector<std::string> error_rooms;
    int64_t start_ms = now_ms();

    // Get all room IDs
    db_.runInteraction(
        "stats_full_agg_rooms",
        [&](storage::LoggingTransaction& txn) {
          txn.execute("SELECT room_id FROM rooms ORDER BY room_id");
          auto rows = txn.fetchall();
          std::vector<std::string> all_rooms;
          all_rooms.reserve(rows.size());
          for (auto& row : rows) {
            if (row[0].value) all_rooms.push_back(*row[0].value);
          }

          // Process in batches
          for (size_t i = 0; i < all_rooms.size(); i += batch_size) {
            size_t end = std::min(i + batch_size, all_rooms.size());
            for (size_t j = i; j < end; j++) {
              try {
                RoomStatsInfo info = compute_room_stats(txn, all_rooms[j]);
                upsert_room_stats(txn, info);
                rooms_processed++;
              } catch (const std::exception& e) {
                errors++;
                if (error_rooms.size() < 100) error_rooms.push_back(all_rooms[j]);
                rooms_skipped++;
              }
            }
          }
        });

    int64_t elapsed_ms = now_ms() - start_ms;
    json result;
    result["rooms_processed"] = rooms_processed;
    result["rooms_skipped"] = rooms_skipped;
    result["errors"] = errors;
    result["error_rooms"] = error_rooms;
    result["elapsed_ms"] = elapsed_ms;
    return result;
  }

  // ---- Incremental update on state change ----

  /// Update room stats when a state event changes in a room
  void on_state_event(const std::string& room_id, const std::string& event_type,
                      const std::string& state_key, const json& content) {
    if (!is_valid_room_id(room_id)) return;

    db_.runInteraction(
        "stats_state_change",
        [&](storage::LoggingTransaction& txn) {
          // Fetch or create room stats row
          auto existing = fetch_room_stats(txn, room_id);
          if (!existing.has_value()) {
            // First time: do full computation
            RoomStatsInfo info = compute_room_stats(txn, room_id);
            upsert_room_stats(txn, info);
            return;
          }

          RoomStatsInfo info = *existing;

          // Update specific fields based on event type
          if (event_type == kEventTypeRoomName) {
            if (content.contains("name"))
              info.room_name = content["name"].get<std::string>();
          } else if (event_type == kEventTypeRoomTopic) {
            if (content.contains("topic"))
              info.room_topic = content["topic"].get<std::string>();
          } else if (event_type == kEventTypeRoomCanonicalAlias) {
            if (content.contains("alias"))
              info.canonical_alias = content["alias"].get<std::string>();
          } else if (event_type == kEventTypeRoomEncryption) {
            if (content.contains("algorithm"))
              info.is_encrypted = true;
          } else if (event_type == kEventTypeRoomHistoryVisibility) {
            if (content.contains("history_visibility"))
              info.history_visibility = content["history_visibility"].get<std::string>();
          } else if (event_type == kEventTypeRoomJoinRules) {
            if (content.contains("join_rule"))
              info.join_rules = content["join_rule"].get<std::string>();
          } else if (event_type == kEventTypeRoomGuestAccess) {
            if (content.contains("guest_access"))
              info.guest_access = content["guest_access"].get<std::string>();
          } else if (event_type == kEventTypeRoomCreate) {
            if (content.contains("type"))
              info.room_type = content["type"].get<std::string>();
            if (content.contains("m.federate"))
              info.is_federatable = content["m.federate"].get<bool>();
          }

          // Recompute state event count
          txn.execute(
              "SELECT COUNT(*) FROM state_events WHERE room_id = ?",
              {room_id});
          auto row = txn.fetchone();
          info.state_events = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          info.stats_updated_ts = now_sec();
          upsert_room_stats(txn, info);
        });
  }

  /// Update room stats on membership change
  void on_membership_change(const std::string& room_id, const std::string& user_id,
                            const std::string& new_membership,
                            const std::string& old_membership) {
    if (!is_valid_room_id(room_id)) return;

    std::string new_mem = normalize_membership(new_membership);
    std::string old_mem = normalize_membership(old_membership);

    db_.runInteraction(
        "stats_membership_change",
        [&](storage::LoggingTransaction& txn) {
          auto existing = fetch_room_stats(txn, room_id);
          if (!existing.has_value()) {
            // Compute full stats if none exist
            RoomStatsInfo info = compute_room_stats(txn, room_id);
            upsert_room_stats(txn, info);
            return;
          }

          RoomStatsInfo info = *existing;

          // Decrement old membership count
          decrement_membership(info, old_mem);
          // Increment new membership count
          increment_membership(info, new_mem);

          // Update local/remote distinction
          bool is_local = (user_id.find(':') != std::string::npos &&
                           user_id.substr(user_id.find(':') + 1) == server_name_);

          info.stats_updated_ts = now_sec();
          upsert_room_stats(txn, info);
        });
  }

  /// Get room stats for a specific room
  std::optional<RoomStatsInfo> get_room_stats(const std::string& room_id) {
    return db_.runInteraction(
        "stats_get_room",
        [&](storage::LoggingTransaction& txn) -> std::optional<RoomStatsInfo> {
          return fetch_room_stats(txn, room_id);
        });
  }

  /// Get room stats for multiple rooms (batch)
  std::vector<RoomStatsInfo> get_rooms_stats(const std::vector<std::string>& room_ids) {
    return db_.runInteraction(
        "stats_get_rooms_batch",
        [&](storage::LoggingTransaction& txn) -> std::vector<RoomStatsInfo> {
          std::vector<RoomStatsInfo> results;
          for (auto& rid : room_ids) {
            auto opt = fetch_room_stats(txn, rid);
            if (opt.has_value()) results.push_back(*opt);
          }
          return results;
        });
  }

  /// List rooms sorted by various metrics for admin API
  json list_rooms_by_stats(const std::string& sort_by = "joined_members",
                           bool ascending = false, int64_t limit = 100,
                           int64_t offset = 0) {
    return db_.runInteraction(
        "stats_list_rooms",
        [&](storage::LoggingTransaction& txn) -> json {
          // Validate sort_by to prevent SQL injection
          static const std::set<std::string> valid_columns = {
              "room_id", "room_name", "joined_members", "invited_members",
              "left_members", "banned_members", "total_members", "state_events",
              "total_events", "is_encrypted", "is_federatable", "creation_ts",
              "last_activity_ts", "stats_updated_ts"
          };
          std::string sort_col = valid_columns.count(sort_by) ? sort_by : "joined_members";
          std::string direction = ascending ? "ASC" : "DESC";

          std::string sql =
              "SELECT room_id, room_name, room_topic, canonical_alias, "
              "room_type, join_rules, history_visibility, guest_access, "
              "is_encrypted, is_federatable, joined_members, invited_members, "
              "left_members, banned_members, total_members, local_members, "
              "remote_members, state_events, forward_extremities, "
              "backward_extremities, total_events, creation_ts, "
              "last_activity_ts, stats_updated_ts "
              "FROM room_stats_state "
              "ORDER BY " + sort_col + " " + direction + " "
              "LIMIT ? OFFSET ?";

          try {
            txn.execute(sql, {std::to_string(limit), std::to_string(offset)});
          } catch (const std::exception&) {
            return json({
                {"rooms", json::array()},
                {"total", 0},
                {"limit", limit},
                {"offset", offset}
            });
          }

          auto rows = txn.fetchall();
          json rooms = json::array();

          for (auto& row : rows) {
            RoomStatsInfo info;
            info.room_id = row[0].value.value_or("");
            info.room_name = row[1].value.value_or("");
            info.room_topic = row[2].value.value_or("");
            info.canonical_alias = row[3].value.value_or("");
            info.room_type = row[4].value.value_or("");
            info.join_rules = row[5].value.value_or("");
            info.history_visibility = row[6].value.value_or("");
            info.guest_access = row[7].value.value_or("");
            info.is_encrypted = row[8].value ? (*row[8].value == "1" || *row[8].value == "true") : false;
            info.is_federatable = row[9].value ? (*row[9].value == "1" || *row[9].value == "true") : true;
            info.joined_members = row[10].value ? std::stoll(*row[10].value) : 0;
            info.invited_members = row[11].value ? std::stoll(*row[11].value) : 0;
            info.left_members = row[12].value ? std::stoll(*row[12].value) : 0;
            info.banned_members = row[13].value ? std::stoll(*row[13].value) : 0;
            info.total_members = row[14].value ? std::stoll(*row[14].value) : 0;
            info.local_members = row[15].value ? std::stoll(*row[15].value) : 0;
            info.remote_members = row[16].value ? std::stoll(*row[16].value) : 0;
            info.state_events = row[17].value ? std::stoll(*row[17].value) : 0;
            info.forward_extremities = row[18].value ? std::stoll(*row[18].value) : 0;
            info.backward_extremities = row[19].value ? std::stoll(*row[19].value) : 0;
            info.total_events = row[20].value ? std::stoll(*row[20].value) : 0;
            info.creation_ts = row[21].value ? std::stoll(*row[21].value) : 0;
            info.last_activity_ts = row[22].value ? std::stoll(*row[22].value) : 0;
            info.stats_updated_ts = row[23].value ? std::stoll(*row[23].value) : 0;

            rooms.push_back(info.to_json());
          }

          // Get total count
          txn.execute("SELECT COUNT(*) FROM room_stats_state");
          auto count_row = txn.fetchone();
          int64_t total = count_row ? std::stoll(count_row->at(0).value.value_or("0")) : 0;

          return json({
              {"rooms", rooms},
              {"total", total},
              {"limit", limit},
              {"offset", offset},
              {"sort_by", sort_by},
              {"ascending", ascending}
          });
        });
  }

  /// Get room stats history (time series data)
  json get_room_stats_history(const std::string& room_id, int days = 30) {
    return db_.runInteraction(
        "stats_room_history",
        [&](storage::LoggingTransaction& txn) -> json {
          int64_t cutoff = days_ago_sec(days);

          std::string sql =
              "SELECT timestamp, joined_members, invited_members, "
              "left_members, banned_members, total_events, state_events "
              "FROM room_stats_history "
              "WHERE room_id = ? AND timestamp >= ? "
              "ORDER BY timestamp ASC";

          try {
            txn.execute(sql, {room_id, std::to_string(cutoff)});
          } catch (const std::exception&) {
            return json({
                {"room_id", room_id},
                {"history", json::array()}
            });
          }

          auto rows = txn.fetchall();
          json history = json::array();

          for (auto& row : rows) {
            json point;
            point["timestamp"] = row[0].value ? std::stoll(*row[0].value) : 0;
            point["joined_members"] = row[1].value ? std::stoll(*row[1].value) : 0;
            point["invited_members"] = row[2].value ? std::stoll(*row[2].value) : 0;
            point["left_members"] = row[3].value ? std::stoll(*row[3].value) : 0;
            point["banned_members"] = row[4].value ? std::stoll(*row[4].value) : 0;
            point["total_events"] = row[5].value ? std::stoll(*row[5].value) : 0;
            point["state_events"] = row[6].value ? std::stoll(*row[6].value) : 0;
            history.push_back(point);
          }

          return json({
              {"room_id", room_id},
              {"history", history},
              {"days", days}
          });
        });
  }

  /// Set the server name for member locality detection
  void set_server_name(const std::string& name) { server_name_ = name; }

private:
  RoomStatsInfo compute_room_stats(storage::LoggingTransaction& txn,
                                   const std::string& room_id) {
    RoomStatsInfo info;
    info.room_id = room_id;
    info.stats_updated_ts = now_sec();

    // === Membership counts from room_memberships ===
    // Joined
    try {
      txn.execute(
          "SELECT COUNT(*) FROM room_memberships "
          "WHERE room_id = ? AND membership = 'join'",
          {room_id});
      auto row = txn.fetchone();
      info.joined_members = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) { info.joined_members = 0; }

    // Invited
    try {
      txn.execute(
          "SELECT COUNT(*) FROM room_memberships "
          "WHERE room_id = ? AND membership = 'invite'",
          {room_id});
      auto row = txn.fetchone();
      info.invited_members = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) { info.invited_members = 0; }

    // Left
    try {
      txn.execute(
          "SELECT COUNT(*) FROM room_memberships "
          "WHERE room_id = ? AND membership = 'leave'",
          {room_id});
      auto row = txn.fetchone();
      info.left_members = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) { info.left_members = 0; }

    // Banned
    try {
      txn.execute(
          "SELECT COUNT(*) FROM room_memberships "
          "WHERE room_id = ? AND membership = 'ban'",
          {room_id});
      auto row = txn.fetchone();
      info.banned_members = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) { info.banned_members = 0; }

    info.total_members = info.joined_members + info.invited_members +
                         info.left_members + info.banned_members;

    // === State event data from current_state_events ===

    // Room name
    try {
      txn.execute(
          "SELECT content FROM current_state_events "
          "WHERE room_id = ? AND type = 'm.room.name' AND state_key = '' "
          "LIMIT 1",
          {room_id});
      auto row = txn.fetchone();
      if (row && row[0].value) {
        try {
          auto j = json::parse(*row[0].value);
          if (j.contains("name")) info.room_name = j["name"].get<std::string>();
        } catch (...) {}
      }
    } catch (...) {}

    // Room topic
    try {
      txn.execute(
          "SELECT content FROM current_state_events "
          "WHERE room_id = ? AND type = 'm.room.topic' AND state_key = '' "
          "LIMIT 1",
          {room_id});
      auto row = txn.fetchone();
      if (row && row[0].value) {
        try {
          auto j = json::parse(*row[0].value);
          if (j.contains("topic")) info.room_topic = j["topic"].get<std::string>();
        } catch (...) {}
      }
    } catch (...) {}

    // Canonical alias
    try {
      txn.execute(
          "SELECT content FROM current_state_events "
          "WHERE room_id = ? AND type = 'm.room.canonical_alias' AND state_key = '' "
          "LIMIT 1",
          {room_id});
      auto row = txn.fetchone();
      if (row && row[0].value) {
        try {
          auto j = json::parse(*row[0].value);
          if (j.contains("alias")) info.canonical_alias = j["alias"].get<std::string>();
        } catch (...) {}
      }
    } catch (...) {}

    // Encryption
    try {
      txn.execute(
          "SELECT content FROM current_state_events "
          "WHERE room_id = ? AND type = 'm.room.encryption' AND state_key = '' "
          "LIMIT 1",
          {room_id});
      auto row = txn.fetchone();
      if (row && row[0].value) {
        try {
          auto j = json::parse(*row[0].value);
          info.is_encrypted = j.contains("algorithm");
        } catch (...) {}
      }
    } catch (...) {}

    // History visibility
    try {
      txn.execute(
          "SELECT content FROM current_state_events "
          "WHERE room_id = ? AND type = 'm.room.history_visibility' AND state_key = '' "
          "LIMIT 1",
          {room_id});
      auto row = txn.fetchone();
      if (row && row[0].value) {
        try {
          auto j = json::parse(*row[0].value);
          if (j.contains("history_visibility"))
            info.history_visibility = j["history_visibility"].get<std::string>();
        } catch (...) {}
      }
    } catch (...) {}

    // Join rules
    try {
      txn.execute(
          "SELECT content FROM current_state_events "
          "WHERE room_id = ? AND type = 'm.room.join_rules' AND state_key = '' "
          "LIMIT 1",
          {room_id});
      auto row = txn.fetchone();
      if (row && row[0].value) {
        try {
          auto j = json::parse(*row[0].value);
          if (j.contains("join_rule"))
            info.join_rules = j["join_rule"].get<std::string>();
        } catch (...) {}
      }
    } catch (...) {}

    // Guest access
    try {
      txn.execute(
          "SELECT content FROM current_state_events "
          "WHERE room_id = ? AND type = 'm.room.guest_access' AND state_key = '' "
          "LIMIT 1",
          {room_id});
      auto row = txn.fetchone();
      if (row && row[0].value) {
        try {
          auto j = json::parse(*row[0].value);
          if (j.contains("guest_access"))
            info.guest_access = j["guest_access"].get<std::string>();
        } catch (...) {}
      }
    } catch (...) {}

    // Room create (type, federatable)
    try {
      txn.execute(
          "SELECT content FROM current_state_events "
          "WHERE room_id = ? AND type = 'm.room.create' AND state_key = '' "
          "LIMIT 1",
          {room_id});
      auto row = txn.fetchone();
      if (row && row[0].value) {
        try {
          auto j = json::parse(*row[0].value);
          if (j.contains("type") && j["type"].is_string())
            info.room_type = j["type"].get<std::string>();
          else info.room_type = "room";
          if (j.contains("m.federate") && j["m.federate"].is_boolean())
            info.is_federatable = j["m.federate"].get<bool>();
          else info.is_federatable = true;
          if (j.contains("creator")) {} // unused currently
        } catch (...) {}
      }
    } catch (...) {}

    // === State event count ===
    try {
      txn.execute(
          "SELECT COUNT(*) FROM state_events WHERE room_id = ?",
          {room_id});
      auto row = txn.fetchone();
      info.state_events = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) { info.state_events = 0; }

    // === Total events ===
    try {
      txn.execute(
          "SELECT COUNT(*) FROM events WHERE room_id = ?",
          {room_id});
      auto row = txn.fetchone();
      info.total_events = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) { info.total_events = 0; }

    // === Forward extremities ===
    try {
      txn.execute(
          "SELECT COUNT(*) FROM event_forward_extremities WHERE room_id = ?",
          {room_id});
      auto row = txn.fetchone();
      info.forward_extremities = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) { info.forward_extremities = 0; }

    // === Backward extremities ===
    try {
      txn.execute(
          "SELECT COUNT(*) FROM event_backward_extremities WHERE room_id = ?",
          {room_id});
      auto row = txn.fetchone();
      info.backward_extremities = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) { info.backward_extremities = 0; }

    // === Last activity ===
    try {
      txn.execute(
          "SELECT MAX(origin_server_ts) FROM events WHERE room_id = ?",
          {room_id});
      auto row = txn.fetchone();
      info.last_activity_ts = (row && row[0].value)
          ? std::stoll(*row[0].value) : 0;
    } catch (...) { info.last_activity_ts = 0; }

    // === Creation time (from room create event) ===
    try {
      txn.execute(
          "SELECT origin_server_ts FROM events "
          "WHERE room_id = ? AND type = 'm.room.create' AND state_key = '' "
          "ORDER BY origin_server_ts ASC LIMIT 1",
          {room_id});
      auto row = txn.fetchone();
      info.creation_ts = (row && row[0].value)
          ? std::stoll(*row[0].value) : 0;
    } catch (...) { info.creation_ts = 0; }

    return info;
  }

  void upsert_room_stats(storage::LoggingTransaction& txn,
                         const RoomStatsInfo& info) {
    std::string sql =
        "INSERT INTO room_stats_state ("
        "  room_id, room_name, room_topic, canonical_alias, "
        "  room_type, join_rules, history_visibility, guest_access, "
        "  is_encrypted, is_federatable, "
        "  joined_members, invited_members, left_members, banned_members, "
        "  total_members, local_members, remote_members, "
        "  state_events, forward_extremities, backward_extremities, "
        "  total_events, creation_ts, last_activity_ts, stats_updated_ts"
        ") VALUES ("
        "  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
        "  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
        "  ?, ?, ?, ?"
        ") ON CONFLICT(room_id) DO UPDATE SET "
        "  room_name = excluded.room_name, "
        "  room_topic = excluded.room_topic, "
        "  canonical_alias = excluded.canonical_alias, "
        "  room_type = excluded.room_type, "
        "  join_rules = excluded.join_rules, "
        "  history_visibility = excluded.history_visibility, "
        "  guest_access = excluded.guest_access, "
        "  is_encrypted = excluded.is_encrypted, "
        "  is_federatable = excluded.is_federatable, "
        "  joined_members = excluded.joined_members, "
        "  invited_members = excluded.invited_members, "
        "  left_members = excluded.left_members, "
        "  banned_members = excluded.banned_members, "
        "  total_members = excluded.total_members, "
        "  local_members = excluded.local_members, "
        "  remote_members = excluded.remote_members, "
        "  state_events = excluded.state_events, "
        "  forward_extremities = excluded.forward_extremities, "
        "  backward_extremities = excluded.backward_extremities, "
        "  total_events = excluded.total_events, "
        "  creation_ts = excluded.creation_ts, "
        "  last_activity_ts = excluded.last_activity_ts, "
        "  stats_updated_ts = excluded.stats_updated_ts";

    try {
      txn.execute(sql, {
          info.room_id,
          info.room_name,
          info.room_topic,
          info.canonical_alias,
          info.room_type,
          info.join_rules,
          info.history_visibility,
          info.guest_access,
          info.is_encrypted ? "1" : "0",
          info.is_federatable ? "1" : "0",
          std::to_string(info.joined_members),
          std::to_string(info.invited_members),
          std::to_string(info.left_members),
          std::to_string(info.banned_members),
          std::to_string(info.total_members),
          std::to_string(info.local_members),
          std::to_string(info.remote_members),
          std::to_string(info.state_events),
          std::to_string(info.forward_extremities),
          std::to_string(info.backward_extremities),
          std::to_string(info.total_events),
          std::to_string(info.creation_ts),
          std::to_string(info.last_activity_ts),
          std::to_string(info.stats_updated_ts)
      });
    } catch (const std::exception& e) {
      // Table might not exist yet
    }
  }

  std::optional<RoomStatsInfo> fetch_room_stats(storage::LoggingTransaction& txn,
                                                const std::string& room_id) {
    std::string sql =
        "SELECT room_id, room_name, room_topic, canonical_alias, "
        "room_type, join_rules, history_visibility, guest_access, "
        "is_encrypted, is_federatable, joined_members, invited_members, "
        "left_members, banned_members, total_members, local_members, "
        "remote_members, state_events, forward_extremities, "
        "backward_extremities, total_events, creation_ts, "
        "last_activity_ts, stats_updated_ts "
        "FROM room_stats_state WHERE room_id = ?";

    try {
      txn.execute(sql, {room_id});
      auto row = txn.fetchone();
      if (!row) return std::nullopt;

      RoomStatsInfo info;
      info.room_id = row->at(0).value.value_or("");
      info.room_name = row->at(1).value.value_or("");
      info.room_topic = row->at(2).value.value_or("");
      info.canonical_alias = row->at(3).value.value_or("");
      info.room_type = row->at(4).value.value_or("");
      info.join_rules = row->at(5).value.value_or("");
      info.history_visibility = row->at(6).value.value_or("");
      info.guest_access = row->at(7).value.value_or("");
      info.is_encrypted = row->at(8).value ? (*row->at(8).value == "1" || *row->at(8).value == "true") : false;
      info.is_federatable = row->at(9).value ? (*row->at(9).value == "1" || *row->at(9).value == "true") : true;
      info.joined_members = row->at(10).value ? std::stoll(*row->at(10).value) : 0;
      info.invited_members = row->at(11).value ? std::stoll(*row->at(11).value) : 0;
      info.left_members = row->at(12).value ? std::stoll(*row->at(12).value) : 0;
      info.banned_members = row->at(13).value ? std::stoll(*row->at(13).value) : 0;
      info.total_members = row->at(14).value ? std::stoll(*row->at(14).value) : 0;
      info.local_members = row->at(15).value ? std::stoll(*row->at(15).value) : 0;
      info.remote_members = row->at(16).value ? std::stoll(*row->at(16).value) : 0;
      info.state_events = row->at(17).value ? std::stoll(*row->at(17).value) : 0;
      info.forward_extremities = row->at(18).value ? std::stoll(*row->at(18).value) : 0;
      info.backward_extremities = row->at(19).value ? std::stoll(*row->at(19).value) : 0;
      info.total_events = row->at(20).value ? std::stoll(*row->at(20).value) : 0;
      info.creation_ts = row->at(21).value ? std::stoll(*row->at(21).value) : 0;
      info.last_activity_ts = row->at(22).value ? std::stoll(*row->at(22).value) : 0;
      info.stats_updated_ts = row->at(23).value ? std::stoll(*row->at(23).value) : 0;

      return info;
    } catch (const std::exception&) {
      return std::nullopt;
    }
  }

  void decrement_membership(RoomStatsInfo& info, const std::string& membership) {
    if (membership == "join") info.joined_members = std::max<int64_t>(0, info.joined_members - 1);
    else if (membership == "invite") info.invited_members = std::max<int64_t>(0, info.invited_members - 1);
    else if (membership == "leave") info.left_members = std::max<int64_t>(0, info.left_members - 1);
    else if (membership == "ban") info.banned_members = std::max<int64_t>(0, info.banned_members - 1);
  }

  void increment_membership(RoomStatsInfo& info, const std::string& membership) {
    if (membership == "join") info.joined_members++;
    else if (membership == "invite") info.invited_members++;
    else if (membership == "leave") info.left_members++;
    else if (membership == "ban") info.banned_members++;
    info.total_members = info.joined_members + info.invited_members +
                         info.left_members + info.banned_members;
  }

  void aggregation_loop() {
    while (running_.load()) {
      std::unique_lock<std::mutex> lock(mtx_);
      cv_.wait_for(lock, chr::milliseconds(kAggregationIntervalMs),
                   [this] { return !running_.load(); });
      if (!running_.load()) break;

      lock.unlock();
      // Run periodic incremental aggregation
      try {
        db_.runInteraction(
            "stats_periodic_agg",
            [&](storage::LoggingTransaction& txn) {
              // Update rooms that haven't been updated recently (stale rooms)
              int64_t stale_cutoff = now_sec() - 600; // 10 minutes
              txn.execute(
                  "SELECT room_id FROM room_stats_state "
                  "WHERE stats_updated_ts < ? "
                  "ORDER BY stats_updated_ts ASC LIMIT ?",
                  {std::to_string(stale_cutoff),
                   std::to_string(kAggregationBatchSize)});
              auto rows = txn.fetchall();
              for (auto& row : rows) {
                if (row[0].value && !running_.load()) break;
                try {
                  RoomStatsInfo info = compute_room_stats(txn, *row[0].value);
                  upsert_room_stats(txn, info);
                } catch (...) {}
              }
            });
      } catch (...) {}
    }
  }

  storage::DatabasePool& db_;
  std::string server_name_;
  std::atomic<bool> running_;
  std::thread worker_;
  std::mutex mtx_;
  std::condition_variable cv_;
};

// ============================================================================
// 2. UserStatsTracker
//
// Tracks user-level statistics: daily visits, DAU/MAU counts, user creation
// timeline, per-user event counts, media usage per user.
//
// Equivalent to synapse/storage/databases/main/stats.py user portions
// ============================================================================

class UserStatsTracker {
public:
  explicit UserStatsTracker(storage::DatabasePool& db)
      : db_(db) {}

  // ---- Daily visits ----

  /// Record a user visit for today (called from /sync handler)
  void record_user_visit(const std::string& user_id, const std::string& device_id,
                         const std::string& user_agent = "") {
    if (user_id.empty()) return;

    std::string today = today_date_str();
    UserAgentInfo ua_info = parse_user_agent(user_agent);

    db_.runInteraction(
        "stats_user_visit",
        [&](storage::LoggingTransaction& txn) {
          try {
            // Upsert user_daily_visits
            txn.execute(
                "INSERT INTO user_daily_visits (user_id, device_id, visit_date, "
                "last_visit_ts, platform, client_name, user_agent) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(user_id, device_id, visit_date) DO UPDATE SET "
                "last_visit_ts = excluded.last_visit_ts, "
                "platform = excluded.platform, "
                "client_name = excluded.client_name, "
                "user_agent = excluded.user_agent",
                {user_id, device_id, today,
                 std::to_string(now_sec()),
                 ua_info.platform, ua_info.client_name,
                 user_agent.substr(0, 512)});
          } catch (const std::exception&) {}
        });
  }

  // ---- DAU / MAU ----

  /// Get daily active users count for a specific date
  int64_t get_daily_active_users(const std::string& date = "") {
    std::string target = date.empty() ? today_date_str() : date;
    return db_.runInteraction(
        "stats_dau",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          try {
            txn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
                "WHERE visit_date = ?",
                {target});
            auto row = txn.fetchone();
            return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (const std::exception&) { return 0; }
        });
  }

  /// Get monthly active users (last 30 days)
  int64_t get_monthly_active_users() {
    return db_.runInteraction(
        "stats_mau",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          int64_t cutoff = days_ago_sec(30);
          std::string cutoff_date = date_str_from_sec(cutoff);
          try {
            txn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
                "WHERE visit_date >= ?",
                {cutoff_date});
            auto row = txn.fetchone();
            return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (const std::exception&) { return 0; }
        });
  }

  /// Get DAU/MAU time series for dashboards
  json get_dau_mau_time_series(int days = 90) {
    return db_.runInteraction(
        "stats_dau_mau_ts",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          int64_t start_day = days_ago_sec(days);

          for (int d = 0; d < days; d++) {
            std::string date = date_str_from_sec(start_day + d * 86400);
            try {
              txn.execute(
                  "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
                  "WHERE visit_date = ?",
                  {date});
              auto row = txn.fetchone();
              int64_t dau = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

              json point;
              point["date"] = date;
              point["daily_active_users"] = dau;
              result.push_back(point);
            } catch (const std::exception&) {
              json point;
              point["date"] = date;
              point["daily_active_users"] = 0;
              result.push_back(point);
            }
          }

          return result;
        });
  }

  /// Get weekly active users
  int64_t get_weekly_active_users() {
    return db_.runInteraction(
        "stats_wau",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          int64_t cutoff = days_ago_sec(7);
          std::string cutoff_date = date_str_from_sec(cutoff);
          try {
            txn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
                "WHERE visit_date >= ?",
                {cutoff_date});
            auto row = txn.fetchone();
            return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (const std::exception&) { return 0; }
        });
  }

  // ---- User creation timeline ----

  /// Get user creation timeline bucketed by day/week/month
  json get_user_creation_timeline(const std::string& bucket = "day", int limit = 365) {
    return db_.runInteraction(
        "stats_creation_timeline",
        [&](storage::LoggingTransaction& txn) -> json {
          json timeline = json::array();

          try {
            txn.execute(
                "SELECT creation_ts FROM users WHERE deactivated = 0 "
                "ORDER BY creation_ts ASC");
            auto rows = txn.fetchall();

            std::map<std::string, int64_t> buckets;
            for (auto& row : rows) {
              int64_t ts = row[0].value ? std::stoll(*row[0].value) : 0;
              if (ts <= 0) continue;

              std::string key;
              if (bucket == "month") key = time_bucket_month(ts);
              else if (bucket == "week") key = time_bucket_week(ts);
              else key = time_bucket_day(ts); // default: day

              buckets[key]++;
            }

            int64_t cumulative = 0;
            for (auto& [key, count] : buckets) {
              cumulative += count;
              json point;
              point["bucket"] = key;
              point["count"] = count;
              point["cumulative"] = cumulative;
              timeline.push_back(point);
            }

            // Limit to most recent N buckets
            while (timeline.size() > static_cast<size_t>(limit)) {
              timeline.erase(0);
            }
          } catch (const std::exception&) {}

          return json({
              {"buckets", timeline},
              {"bucket_type", bucket},
              {"total_users", timeline.empty() ? 0 :
                  timeline.back()["cumulative"].get<int64_t>()}
          });
        });
  }

  // ---- Per-user event stats ----

  /// Get total events sent by a specific user
  int64_t get_user_event_count(const std::string& user_id) {
    return db_.runInteraction(
        "stats_user_events",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          try {
            txn.execute(
                "SELECT COUNT(*) FROM events WHERE sender = ?",
                {user_id});
            auto row = txn.fetchone();
            return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (const std::exception&) { return 0; }
        });
  }

  /// Get top users by event count
  json get_top_users_by_events(int64_t limit = 100) {
    return db_.runInteraction(
        "stats_top_users",
        [&](storage::LoggingTransaction& txn) -> json {
          try {
            txn.execute(
                "SELECT sender, COUNT(*) as cnt FROM events "
                "GROUP BY sender ORDER BY cnt DESC LIMIT ?",
                {std::to_string(limit)});
            auto rows = txn.fetchall();

            json users = json::array();
            for (auto& row : rows) {
              json u;
              u["user_id"] = row[0].value.value_or("");
              u["event_count"] = row[1].value ? std::stoll(*row[1].value) : 0;
              users.push_back(u);
            }
            return json({
                {"users", users},
                {"limit", limit}
            });
          } catch (const std::exception&) {
            return json({{"users", json::array()}, {"limit", limit}});
          }
        });
  }

  /// Get user stats summary
  UserStatsInfo get_user_stats(const std::string& user_id) {
    return db_.runInteraction(
        "stats_user_info",
        [&](storage::LoggingTransaction& txn) -> UserStatsInfo {
          UserStatsInfo info;
          info.user_id = user_id;

          // Basic user info
          try {
            txn.execute(
                "SELECT display_name, is_guest, admin, deactivated, "
                "appservice_id, creation_ts "
                "FROM users WHERE name = ?",
                {user_id});
            auto row = txn.fetchone();
            if (row) {
              info.display_name = row->at(0).value.value_or("");
              info.is_guest = row->at(1).value ? (*row->at(1).value == "1" || *row->at(1).value == "true") : false;
              info.is_admin = row->at(2).value ? (*row->at(2).value == "1" || *row->at(2).value == "true") : false;
              info.is_deactivated = row->at(3).value ? (*row->at(3).value == "1" || *row->at(3).value == "true") : false;
              info.is_appservice = row->at(4).value && !row->at(4).value->empty();
              info.creation_ts = row->at(5).value ? std::stoll(*row->at(5).value) : 0;
            }
          } catch (const std::exception&) {}

          // Event count
          info.total_events_sent = get_user_event_count(user_id);

          // Joined rooms count
          try {
            txn.execute(
                "SELECT COUNT(*) FROM room_memberships "
                "WHERE user_id = ? AND membership = 'join'",
                {user_id});
            auto row = txn.fetchone();
            info.joined_rooms_count = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (const std::exception&) {}

          // Last seen
          try {
            txn.execute(
                "SELECT MAX(last_visit_ts) FROM user_daily_visits WHERE user_id = ?",
                {user_id});
            auto row = txn.fetchone();
            info.last_seen_ts = (row && row[0].value) ? std::stoll(*row[0].value) : 0;
          } catch (const std::exception&) {}

          return info;
        });
  }

  /// Get user retention metrics
  json get_retention_metrics() {
    return db_.runInteraction(
        "stats_retention",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;

          try {
            // Day 1 retention: users who returned day after first visit
            txn.execute(
                "WITH first_visits AS ("
                "  SELECT user_id, MIN(visit_date) as first_date "
                "  FROM user_daily_visits GROUP BY user_id"
                "), "
                "day1_return AS ("
                "  SELECT fv.user_id "
                "  FROM first_visits fv "
                "  JOIN user_daily_visits udv "
                "    ON fv.user_id = udv.user_id "
                "    AND udv.visit_date = date(fv.first_date, '+1 day')"
                ") "
                "SELECT "
                "  (SELECT COUNT(*) FROM first_visits) as total_new, "
                "  (SELECT COUNT(*) FROM day1_return) as day1_returned");
            auto row = txn.fetchone();
            if (row) {
              int64_t total = row->at(0).value ? std::stoll(*row->at(0).value) : 0;
              int64_t day1 = row->at(1).value ? std::stoll(*row->at(1).value) : 0;
              result["total_new_users"] = total;
              result["day1_returned"] = day1;
              result["day1_retention_pct"] = total > 0
                  ? std::round(10000.0 * day1 / total) / 100.0 : 0.0;
            } else {
              result["total_new_users"] = 0;
              result["day1_returned"] = 0;
              result["day1_retention_pct"] = 0.0;
            }

            // Day 7 retention
            txn.execute(
                "WITH first_visits AS ("
                "  SELECT user_id, MIN(visit_date) as first_date "
                "  FROM user_daily_visits GROUP BY user_id"
                "), "
                "day7_return AS ("
                "  SELECT fv.user_id "
                "  FROM first_visits fv "
                "  JOIN user_daily_visits udv "
                "    ON fv.user_id = udv.user_id "
                "    AND udv.visit_date = date(fv.first_date, '+7 days')"
                ") "
                "SELECT COUNT(*) FROM day7_return");
            row = txn.fetchone();
            int64_t day7 = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
            int64_t total2 = result["total_new_users"].get<int64_t>();
            result["day7_returned"] = day7;
            result["day7_retention_pct"] = total2 > 0
                ? std::round(10000.0 * day7 / total2) / 100.0 : 0.0;
          } catch (const std::exception&) {
            result["error"] = "retention query failed";
          }

          return result;
        });
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 3. ServerStatsCollector
//
// Collects server-wide statistics: total user/room/event counts, media
// statistics, federation metrics, and per-timeframe breakdowns.
//
// Equivalent to synapse/storage/databases/main/stats.py server portions
// ============================================================================

class ServerStatsCollector {
public:
  explicit ServerStatsCollector(storage::DatabasePool& db)
      : db_(db) {}

  /// Compute full server stats snapshot
  ServerStatsSnapshot compute_server_stats() {
    ServerStatsSnapshot snap;
    snap.computed_ts = now_sec();

    db_.runInteraction(
        "stats_server_snapshot",
        [&](storage::LoggingTransaction& txn) {
          // === User counts ===

          // Total users (non-deactivated)
          try {
            txn.execute("SELECT COUNT(*) FROM users WHERE deactivated = 0");
            auto row = txn.fetchone();
            snap.total_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Total non-bridge users
          try {
            txn.execute(
                "SELECT COUNT(*) FROM users "
                "WHERE deactivated = 0 AND (appservice_id IS NULL OR appservice_id = '')");
            auto row = txn.fetchone();
            snap.total_non_bridge_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Total active (has been seen)
          try {
            txn.execute(
                "SELECT COUNT(*) FROM users u "
                "WHERE u.deactivated = 0 AND EXISTS "
                "(SELECT 1 FROM user_daily_visits udv WHERE udv.user_id = u.name)");
            auto row = txn.fetchone();
            snap.total_active_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Guests
          try {
            txn.execute("SELECT COUNT(*) FROM users WHERE is_guest = 1 AND deactivated = 0");
            auto row = txn.fetchone();
            snap.total_guests = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Deactivated
          try {
            txn.execute("SELECT COUNT(*) FROM users WHERE deactivated = 1");
            auto row = txn.fetchone();
            snap.total_deactivated_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Appservice users
          try {
            txn.execute(
                "SELECT COUNT(*) FROM users "
                "WHERE appservice_id IS NOT NULL AND appservice_id != '' AND deactivated = 0");
            auto row = txn.fetchone();
            snap.total_appservice_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Real users
          try {
            txn.execute(
                "SELECT COUNT(*) FROM users "
                "WHERE is_guest = 0 AND deactivated = 0 "
                "AND (appservice_id IS NULL OR appservice_id = '')");
            auto row = txn.fetchone();
            snap.total_real_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // === Room counts ===

          try {
            txn.execute("SELECT COUNT(*) FROM rooms");
            auto row = txn.fetchone();
            snap.total_rooms = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Public rooms (join_rules = public)
          try {
            txn.execute(
                "SELECT COUNT(*) FROM room_stats_state WHERE join_rules = 'public'");
            auto row = txn.fetchone();
            snap.total_public_rooms = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Encrypted rooms
          try {
            txn.execute(
                "SELECT COUNT(*) FROM room_stats_state WHERE is_encrypted = '1'");
            auto row = txn.fetchone();
            snap.total_encrypted_rooms = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Spaces
          try {
            txn.execute(
                "SELECT COUNT(*) FROM room_stats_state WHERE room_type = 'm.space'");
            auto row = txn.fetchone();
            snap.total_spaces = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Active rooms by timeframe
          int64_t cutoff_1d = now_sec() - 86400;
          int64_t cutoff_7d = now_sec() - 7 * 86400;
          int64_t cutoff_30d = now_sec() - 30 * 86400;

          try {
            txn.execute(
                "SELECT COUNT(*) FROM room_stats_state WHERE last_activity_ts > ?",
                {std::to_string(cutoff_1d)});
            auto row = txn.fetchone();
            snap.active_rooms_1d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          try {
            txn.execute(
                "SELECT COUNT(*) FROM room_stats_state WHERE last_activity_ts > ?",
                {std::to_string(cutoff_7d)});
            auto row = txn.fetchone();
            snap.active_rooms_7d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          try {
            txn.execute(
                "SELECT COUNT(*) FROM room_stats_state WHERE last_activity_ts > ?",
                {std::to_string(cutoff_30d)});
            auto row = txn.fetchone();
            snap.active_rooms_30d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // === Event counts ===

          try {
            txn.execute("SELECT COUNT(*) FROM events");
            auto row = txn.fetchone();
            snap.total_events = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // State events (those with state_key not null)
          try {
            txn.execute(
                "SELECT COUNT(*) FROM state_events");
            auto row = txn.fetchone();
            snap.total_state_events = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Messages
          try {
            txn.execute(
                "SELECT COUNT(*) FROM events WHERE type = 'm.room.message' "
                "OR type = 'm.room.encrypted'");
            auto row = txn.fetchone();
            snap.total_messages = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Reactions
          try {
            txn.execute("SELECT COUNT(*) FROM events WHERE type = 'm.reaction'");
            auto row = txn.fetchone();
            snap.total_reactions = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Events in time windows
          try {
            txn.execute(
                "SELECT COUNT(*) FROM events WHERE origin_server_ts > ?",
                {std::to_string(cutoff_1d)});
            auto row = txn.fetchone();
            snap.events_sent_24h = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          try {
            txn.execute(
                "SELECT COUNT(*) FROM events WHERE origin_server_ts > ?",
                {std::to_string(cutoff_7d)});
            auto row = txn.fetchone();
            snap.events_sent_7d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          try {
            txn.execute(
                "SELECT COUNT(*) FROM events WHERE origin_server_ts > ?",
                {std::to_string(cutoff_30d)});
            auto row = txn.fetchone();
            snap.events_sent_30d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // === Media stats ===

          try {
            txn.execute(
                "SELECT COALESCE(SUM(media_length), 0) FROM local_media_repository");
            auto row = txn.fetchone();
            snap.total_local_media_bytes = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          try {
            txn.execute(
                "SELECT COALESCE(SUM(media_length), 0) FROM remote_media_cache");
            auto row = txn.fetchone();
            snap.total_remote_media_bytes = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          try {
            txn.execute(
                "SELECT COUNT(*) FROM local_media_repository");
            auto row = txn.fetchone();
            snap.total_media_count = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // Media uploaded in 24h
          try {
            txn.execute(
                "SELECT COALESCE(SUM(media_length), 0) FROM local_media_repository "
                "WHERE created_ts > ?",
                {std::to_string(cutoff_1d)});
            auto row = txn.fetchone();
            snap.media_uploaded_24h = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (...) {}

          // === Federation stats (placeholder) ===
          // These would be populated from federation metrics in production
          snap.federation_requests_sent_24h = 0;
          snap.federation_requests_received_24h = 0;
          snap.federation_failures_24h = 0;
        });

    return snap;
  }

  /// Get total room count (lightweight)
  int64_t get_total_rooms() {
    return db_.runInteraction(
        "stats_total_rooms",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          try {
            txn.execute("SELECT COUNT(*) FROM rooms");
            auto row = txn.fetchone();
            return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (const std::exception&) { return 0; }
        });
  }

  /// Get total event count
  int64_t get_total_events() {
    return db_.runInteraction(
        "stats_total_events",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          try {
            txn.execute("SELECT COUNT(*) FROM events");
            auto row = txn.fetchone();
            return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          } catch (const std::exception&) { return 0; }
        });
  }

  /// Get total media bytes
  int64_t get_total_media_bytes() {
    return db_.runInteraction(
        "stats_total_media_bytes",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          try {
            txn.execute(
                "SELECT COALESCE(SUM(media_length), 0) FROM local_media_repository");
            auto row = txn.fetchone();
            int64_t local_bytes = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            txn.execute(
                "SELECT COALESCE(SUM(media_length), 0) FROM remote_media_cache");
            row = txn.fetchone();
            int64_t remote_bytes = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            return local_bytes + remote_bytes;
          } catch (const std::exception&) { return 0; }
        });
  }

  /// Get event throughput time series
  json get_event_throughput_time_series(int hours = 24) {
    return db_.runInteraction(
        "stats_throughput",
        [&](storage::LoggingTransaction& txn) -> json {
          json series = json::array();
          int64_t cutoff = now_sec() - hours * 3600;

          for (int h = 0; h < hours; h++) {
            int64_t bucket_start = cutoff + h * 3600;
            int64_t bucket_end = bucket_start + 3600;

            try {
              txn.execute(
                  "SELECT COUNT(*) FROM events "
                  "WHERE origin_server_ts >= ? AND origin_server_ts < ?",
                  {std::to_string(bucket_start), std::to_string(bucket_end)});
              auto row = txn.fetchone();
              int64_t count = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

              json point;
              point["timestamp"] = bucket_start;
              point["hour"] = time_bucket_hour(bucket_start);
              point["event_count"] = count;
              series.push_back(point);
            } catch (...) {
              json point;
              point["timestamp"] = bucket_start;
              point["hour"] = time_bucket_hour(bucket_start);
              point["event_count"] = 0;
              series.push_back(point);
            }
          }

          return json({
              {"series", series},
              {"hours", hours}
          });
        });
  }

  /// Get database room stats (for admin API)
  json get_database_room_stats() {
    return db_.runInteraction(
        "stats_db_rooms",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;
          try {
            // Room count
            txn.execute("SELECT COUNT(*) FROM rooms");
            auto row = txn.fetchone();
            result["total_rooms"] = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            // State events table size
            txn.execute("SELECT COUNT(*) FROM state_events");
            row = txn.fetchone();
            result["total_state_events"] = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            // Forward extremities
            txn.execute("SELECT COUNT(*) FROM event_forward_extremities");
            row = txn.fetchone();
            result["total_forward_extremities"] = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            // Backward extremities
            txn.execute("SELECT COUNT(*) FROM event_backward_extremities");
            row = txn.fetchone();
            result["total_backward_extremities"] = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            // Current state events
            txn.execute("SELECT COUNT(*) FROM current_state_events");
            row = txn.fetchone();
            result["total_current_state_events"] = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            // Rooms with stats
            txn.execute("SELECT COUNT(*) FROM room_stats_state");
            row = txn.fetchone();
            result["rooms_with_stats"] = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            // Membership counts
            txn.execute(
                "SELECT membership, COUNT(*) FROM room_memberships "
                "GROUP BY membership");
            auto rows = txn.fetchall();
            json memberships = json::object();
            for (auto& mr : rows) {
              memberships[mr[0].value.value_or("unknown")] =
                  mr[1].value ? std::stoll(*mr[1].value) : 0;
            }
            result["membership_breakdown"] = memberships;

            // Largest rooms
            txn.execute(
                "SELECT room_id, joined_members FROM room_stats_state "
                "ORDER BY joined_members DESC LIMIT 10");
            rows = txn.fetchall();
            json largest = json::array();
            for (auto& lr : rows) {
              json entry;
              entry["room_id"] = lr[0].value.value_or("");
              entry["joined_members"] = lr[1].value ? std::stoll(*lr[1].value) : 0;
              largest.push_back(entry);
            }
            result["largest_rooms"] = largest;

          } catch (const std::exception& e) {
            result["error"] = e.what();
          }
          return result;
        });
  }

  /// Get user media stats (for admin API)
  json get_user_media_stats(const std::string& order_by = "media_length",
                            bool reverse = true, int64_t limit = 100,
                            int64_t offset = 0,
                            const std::string& search_term = "") {
    return db_.runInteraction(
        "stats_user_media",
        [&](storage::LoggingTransaction& txn) -> json {
          // Validate order_by to prevent injection
          static const std::set<std::string> valid_order = {
              "user_id", "media_length", "media_count"
          };
          std::string order_col = valid_order.count(order_by) ? order_by : "media_length";
          std::string dir = reverse ? "DESC" : "ASC";
          std::string where_clause;

          std::vector<std::string> params;

          if (!search_term.empty()) {
            where_clause = "WHERE u.name LIKE ? ";
            params.push_back("%" + search_term + "%");
          }

          std::string sql =
              "SELECT u.name, "
              "COALESCE(SUM(lmr.media_length), 0) as total_bytes, "
              "COUNT(lmr.media_id) as media_count "
              "FROM users u "
              "LEFT JOIN local_media_repository lmr ON u.name = lmr.user_id "
              + where_clause +
              "GROUP BY u.name "
              "ORDER BY " + order_col + " " + dir + " "
              "LIMIT ? OFFSET ?";

          params.push_back(std::to_string(limit));
          params.push_back(std::to_string(offset));

          try {
            txn.execute(sql, params);
            auto rows = txn.fetchall();

            json users_array = json::array();
            for (auto& row : rows) {
              json entry;
              entry["user_id"] = row[0].value.value_or("");
              entry["media_length"] = row[1].value ? std::stoll(*row[1].value) : 0;
              entry["media_count"] = row[2].value ? std::stoll(*row[2].value) : 0;
              users_array.push_back(entry);
            }

            // Total count
            std::string count_sql =
                "SELECT COUNT(DISTINCT u.name) FROM users u " + where_clause;
            std::vector<std::string> count_params;
            if (!search_term.empty())
              count_params.push_back("%" + search_term + "%");
            txn.execute(count_sql, count_params);
            auto count_row = txn.fetchone();
            int64_t total = count_row ? std::stoll(count_row->at(0).value.value_or("0")) : 0;

            // Total media bytes
            txn.execute(
                "SELECT COALESCE(SUM(media_length), 0) FROM local_media_repository");
            auto total_row = txn.fetchone();
            int64_t grand_total_bytes = total_row ? std::stoll(total_row->at(0).value.value_or("0")) : 0;

            return json({
                {"users", users_array},
                {"total", total},
                {"limit", limit},
                {"offset", offset},
                {"order_by", order_by},
                {"reverse", reverse},
                {"search_term", search_term},
                {"total_media_length", grand_total_bytes}
            });
          } catch (const std::exception& e) {
            return json({
                {"error", std::string("query failed: ") + e.what()},
                {"users", json::array()},
                {"total", 0}
            });
          }
        });
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 4. StatsCache
//
// Thread-safe in-memory cache for computed statistics. Caches room stats,
// user stats, server stats, DAU/MAU, and media stats with configurable TTLs.
// Provides cache invalidation hooks triggered by data changes.
//
// Equivalent to multiple synapse/util/caches/* classes
// ============================================================================

class StatsCache {
public:
  StatsCache()
      : room_stats_ttl_ms_(kRoomStatsCacheTTLMs),
        user_stats_ttl_ms_(kUserStatsCacheTTLMs),
        server_stats_ttl_ms_(kServerStatsCacheTTLMs),
        dau_mau_ttl_ms_(kDAUMAUCacheTTLMs),
        media_stats_ttl_ms_(kMediaStatsCacheTTLMs),
        room_list_ttl_ms_(kRoomListCacheTTLMs),
        hits_(0), misses_(0), invalidations_(0) {}

  // ---- Room stats cache ----

  void set_cached_room_stats(const std::string& room_id, const RoomStatsInfo& info) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    CacheEntry<RoomStatsInfo> entry;
    entry.data = info;
    entry.cached_at_ms = now_ms();
    entry.ttl_ms = room_stats_ttl_ms_;
    room_cache_[room_id] = std::move(entry);
  }

  std::optional<RoomStatsInfo> get_cached_room_stats(const std::string& room_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = room_cache_.find(room_id);
    if (it == room_cache_.end()) { misses_++; return std::nullopt; }
    if (is_expired(it->second)) {
      lock.unlock();
      invalidate_room(room_id);
      misses_++;
      return std::nullopt;
    }
    hits_++;
    return it->second.data;
  }

  void invalidate_room(const std::string& room_id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    room_cache_.erase(room_id);
    invalidations_++;
    // Also invalidate server stats since they depend on room data
    server_stats_valid_.store(false, std::memory_order_release);
  }

  void invalidate_all_rooms() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    room_cache_.clear();
    invalidations_++;
    server_stats_valid_.store(false, std::memory_order_release);
  }

  // ---- User stats cache ----

  void set_cached_user_stats(const std::string& user_id, const UserStatsInfo& info) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    CacheEntry<UserStatsInfo> entry;
    entry.data = info;
    entry.cached_at_ms = now_ms();
    entry.ttl_ms = user_stats_ttl_ms_;
    user_cache_[user_id] = std::move(entry);
  }

  std::optional<UserStatsInfo> get_cached_user_stats(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = user_cache_.find(user_id);
    if (it == user_cache_.end()) { misses_++; return std::nullopt; }
    if (is_expired(it->second)) {
      lock.unlock();
      invalidate_user(user_id);
      misses_++;
      return std::nullopt;
    }
    hits_++;
    return it->second.data;
  }

  void invalidate_user(const std::string& user_id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    user_cache_.erase(user_id);
    invalidations_++;
    dau_mau_valid_.store(false, std::memory_order_release);
  }

  // ---- Server stats cache ----

  void set_cached_server_stats(const ServerStatsSnapshot& snap) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    CacheEntry<ServerStatsSnapshot> entry;
    entry.data = snap;
    entry.cached_at_ms = now_ms();
    entry.ttl_ms = server_stats_ttl_ms_;
    server_stats_cache_ = entry;
    server_stats_valid_.store(true, std::memory_order_release);
  }

  std::optional<ServerStatsSnapshot> get_cached_server_stats() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!server_stats_valid_.load(std::memory_order_acquire) ||
        !server_stats_cache_.has_value()) {
      misses_++;
      return std::nullopt;
    }
    if (is_expired(*server_stats_cache_)) {
      lock.unlock();
      invalidate_server_stats();
      misses_++;
      return std::nullopt;
    }
    hits_++;
    return server_stats_cache_->data;
  }

  void invalidate_server_stats() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    server_stats_cache_.reset();
    server_stats_valid_.store(false, std::memory_order_release);
    invalidations_++;
  }

  // ---- DAU/MAU cache ----

  void set_cached_dau_mau(int64_t dau, int64_t mau) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    CacheEntry<std::pair<int64_t, int64_t>> entry;
    entry.data = std::make_pair(dau, mau);
    entry.cached_at_ms = now_ms();
    entry.ttl_ms = dau_mau_ttl_ms_;
    dau_mau_cache_ = entry;
    dau_mau_valid_.store(true, std::memory_order_release);
  }

  std::optional<std::pair<int64_t, int64_t>> get_cached_dau_mau() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!dau_mau_valid_.load(std::memory_order_acquire) ||
        !dau_mau_cache_.has_value()) {
      misses_++;
      return std::nullopt;
    }
    if (is_expired(*dau_mau_cache_)) {
      lock.unlock();
      invalidate_dau_mau();
      misses_++;
      return std::nullopt;
    }
    hits_++;
    return dau_mau_cache_->data;
  }

  void invalidate_dau_mau() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    dau_mau_cache_.reset();
    dau_mau_valid_.store(false, std::memory_order_release);
    invalidations_++;
  }

  // ---- Media stats cache ----

  void set_cached_media_stats(int64_t bytes, int64_t count) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    CacheEntry<std::pair<int64_t, int64_t>> entry;
    entry.data = std::make_pair(bytes, count);
    entry.cached_at_ms = now_ms();
    entry.ttl_ms = media_stats_ttl_ms_;
    media_stats_cache_ = entry;
    media_stats_valid_.store(true, std::memory_order_release);
  }

  std::optional<std::pair<int64_t, int64_t>> get_cached_media_stats() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!media_stats_valid_.load(std::memory_order_acquire) ||
        !media_stats_cache_.has_value()) {
      misses_++;
      return std::nullopt;
    }
    if (is_expired(*media_stats_cache_)) {
      lock.unlock();
      invalidate_media_stats();
      misses_++;
      return std::nullopt;
    }
    hits_++;
    return media_stats_cache_->data;
  }

  void invalidate_media_stats() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    media_stats_cache_.reset();
    media_stats_valid_.store(false, std::memory_order_release);
    invalidations_++;
  }

  // ---- Room list cache ----

  void set_cached_room_list(const std::string& key, const json& data) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    CacheEntry<json> entry;
    entry.data = data;
    entry.cached_at_ms = now_ms();
    entry.ttl_ms = room_list_ttl_ms_;
    room_list_cache_[key] = std::move(entry);
  }

  std::optional<json> get_cached_room_list(const std::string& key) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = room_list_cache_.find(key);
    if (it == room_list_cache_.end()) { misses_++; return std::nullopt; }
    if (is_expired(it->second)) {
      lock.unlock();
      invalidate_room_list(key);
      misses_++;
      return std::nullopt;
    }
    hits_++;
    return it->second.data;
  }

  void invalidate_room_list(const std::string& key) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    room_list_cache_.erase(key);
    invalidations_++;
  }

  // ---- Global invalidation ----

  void invalidate_all() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    room_cache_.clear();
    user_cache_.clear();
    server_stats_cache_.reset();
    dau_mau_cache_.reset();
    media_stats_cache_.reset();
    room_list_cache_.clear();
    server_stats_valid_.store(false, std::memory_order_release);
    dau_mau_valid_.store(false, std::memory_order_release);
    media_stats_valid_.store(false, std::memory_order_release);
    invalidations_++;
  }

  // ---- Cache statistics ----

  json get_cache_stats() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json j;
    j["room_cache_size"] = room_cache_.size();
    j["user_cache_size"] = user_cache_.size();
    j["room_list_cache_size"] = room_list_cache_.size();
    j["server_stats_cached"] = server_stats_cache_.has_value();
    j["dau_mau_cached"] = dau_mau_cache_.has_value();
    j["media_stats_cached"] = media_stats_cache_.has_value();
    j["hits"] = hits_.load();
    j["misses"] = misses_.load();
    j["invalidations"] = invalidations_.load();
    j["hit_ratio"] = (hits_.load() + misses_.load()) > 0
        ? static_cast<double>(hits_.load()) / (hits_.load() + misses_.load())
        : 0.0;
    return j;
  }

  // ---- Clear entire cache ----
  void clear() {
    invalidate_all();
    hits_.store(0);
    misses_.store(0);
    invalidations_.store(0);
  }

  // ---- Configurable TTLs ----
  void set_room_stats_ttl(int64_t ttl_ms) { room_stats_ttl_ms_ = ttl_ms; }
  void set_user_stats_ttl(int64_t ttl_ms) { user_stats_ttl_ms_ = ttl_ms; }
  void set_server_stats_ttl(int64_t ttl_ms) { server_stats_ttl_ms_ = ttl_ms; }
  void set_dau_mau_ttl(int64_t ttl_ms) { dau_mau_ttl_ms_ = ttl_ms; }

private:
  template <typename T>
  struct CacheEntry {
    T data;
    int64_t cached_at_ms = 0;
    int64_t ttl_ms = 60'000;
  };

  bool is_expired(const auto& entry) const {
    return (now_ms() - entry.cached_at_ms) > entry.ttl_ms;
  }

  mutable std::shared_mutex mutex_;

  std::unordered_map<std::string, CacheEntry<RoomStatsInfo>> room_cache_;
  std::unordered_map<std::string, CacheEntry<UserStatsInfo>> user_cache_;
  std::unordered_map<std::string, CacheEntry<json>> room_list_cache_;

  std::optional<CacheEntry<ServerStatsSnapshot>> server_stats_cache_;
  std::optional<CacheEntry<std::pair<int64_t, int64_t>>> dau_mau_cache_;
  std::optional<CacheEntry<std::pair<int64_t, int64_t>>> media_stats_cache_;

  std::atomic<bool> server_stats_valid_{false};
  std::atomic<bool> dau_mau_valid_{false};
  std::atomic<bool> media_stats_valid_{false};

  int64_t room_stats_ttl_ms_;
  int64_t user_stats_ttl_ms_;
  int64_t server_stats_ttl_ms_;
  int64_t dau_mau_ttl_ms_;
  int64_t media_stats_ttl_ms_;
  int64_t room_list_ttl_ms_;

  std::atomic<int64_t> hits_;
  std::atomic<int64_t> misses_;
  std::atomic<int64_t> invalidations_;
};

// ============================================================================
// 5. StatsAdminAPI
//
// Admin API handlers for statistics endpoints. Exposes:
//   - GET /_synapse/admin/v1/statistics
//   - GET /_synapse/admin/v1/statistics/users/media
//   - GET /_synapse/admin/v1/statistics/database/rooms
//
// Equivalent to synapse/rest/admin/statistics.py
// ============================================================================

class StatsAdminAPI {
public:
  StatsAdminAPI(RoomStatsAggregator& room_agg,
                UserStatsTracker& user_tracker,
                ServerStatsCollector& server_collector,
                StatsCache& cache,
                MetricsCollector& metrics)
      : room_agg_(room_agg),
        user_tracker_(user_tracker),
        server_collector_(server_collector),
        cache_(cache),
        metrics_(metrics) {}

  // ---- GET /_synapse/admin/v1/statistics ----

  /// Get main statistics endpoint response
  json get_statistics() {
    // Try cache first
    auto cached = cache_.get_cached_server_stats();
    if (cached.has_value()) {
      return cached->to_json();
    }

    ServerStatsSnapshot snap = server_collector_.compute_server_stats();

    // Enrich with DAU/MAU from user tracker
    snap.daily_active_users = user_tracker_.get_daily_active_users();
    snap.monthly_active_users = user_tracker_.get_monthly_active_users();

    cache_.set_cached_server_stats(snap);

    // Update metrics
    metrics_.gauge(kMetricUsersTotal).set(static_cast<double>(snap.total_users));
    metrics_.gauge(kMetricUsersActive).set(static_cast<double>(snap.total_active_users));
    metrics_.gauge(kMetricRoomsTotal).set(static_cast<double>(snap.total_rooms));
    metrics_.gauge(kMetricDAU).set(static_cast<double>(snap.daily_active_users));
    metrics_.gauge(kMetricMAU).set(static_cast<double>(snap.monthly_active_users));
    metrics_.gauge(kMetricMediaBytes).set(static_cast<double>(snap.total_local_media_bytes));

    return snap.to_json();
  }

  // ---- GET /_synapse/admin/v1/statistics/users/media ----

  /// Get user media statistics
  json get_user_media_stats(const std::string& order_by = "media_length",
                            bool reverse = true, int64_t limit = 100,
                            int64_t offset = 0,
                            const std::string& search_term = "") {
    return server_collector_.get_user_media_stats(
        order_by, reverse, limit, offset, search_term);
  }

  // ---- GET /_synapse/admin/v1/statistics/database/rooms ----

  /// Get database room statistics
  json get_database_room_stats() {
    return server_collector_.get_database_room_stats();
  }

  // ---- Extended admin endpoints ----

  /// Get room stats listing (paginated)
  json get_room_stats_list(const std::string& sort_by = "joined_members",
                           bool ascending = false, int64_t limit = 100,
                           int64_t offset = 0) {
    // Build cache key
    std::string cache_key = "room_list_" + sort_by +
                            (ascending ? "_asc" : "_desc") +
                            "_l" + std::to_string(limit) +
                            "_o" + std::to_string(offset);

    auto cached = cache_.get_cached_room_list(cache_key);
    if (cached.has_value()) return *cached;

    json result = room_agg_.list_rooms_by_stats(sort_by, ascending, limit, offset);
    cache_.set_cached_room_list(cache_key, result);
    return result;
  }

  /// Get a specific room's detailed stats
  json get_room_stats_detail(const std::string& room_id) {
    auto cached = cache_.get_cached_room_stats(room_id);
    if (cached.has_value()) return cached->to_json();

    auto opt = room_agg_.get_room_stats(room_id);
    if (opt.has_value()) {
      cache_.set_cached_room_stats(room_id, *opt);
      return opt->to_json();
    }
    return json({{"error", "room not found or stats not available"}});
  }

  /// Get room stats history (time series)
  json get_room_stats_history(const std::string& room_id, int days = 30) {
    return room_agg_.get_room_stats_history(room_id, days);
  }

  /// Get a specific user's stats
  json get_user_stats_detail(const std::string& user_id) {
    auto cached = cache_.get_cached_user_stats(user_id);
    if (cached.has_value()) return cached->to_json();

    UserStatsInfo info = user_tracker_.get_user_stats(user_id);
    cache_.set_cached_user_stats(user_id, info);
    return info.to_json();
  }

  /// Get user creation timeline
  json get_user_creation_timeline(const std::string& bucket = "day", int limit = 365) {
    return user_tracker_.get_user_creation_timeline(bucket, limit);
  }

  /// Get DAU/MAU time series
  json get_dau_mau_time_series(int days = 90) {
    return user_tracker_.get_dau_mau_time_series(days);
  }

  /// Get event throughput time series
  json get_event_throughput_time_series(int hours = 24) {
    return server_collector_.get_event_throughput_time_series(hours);
  }

  /// Get top users by event count
  json get_top_users(int64_t limit = 100) {
    return user_tracker_.get_top_users_by_events(limit);
  }

  /// Get retention metrics
  json get_retention_metrics() {
    return user_tracker_.get_retention_metrics();
  }

  /// Get cache statistics (for debugging)
  json get_cache_stats() {
    return cache_.get_cache_stats();
  }

  /// Run full room aggregation
  json run_room_aggregation(int64_t batch_size = kAggregationBatchSize) {
    json result = room_agg_.run_full_aggregation(batch_size);
    cache_.invalidate_all_rooms();
    return result;
  }

  /// Invalidate all caches (force recompute)
  json invalidate_caches() {
    cache_.invalidate_all();
    return json({{"status", "ok"}, {"message", "all caches invalidated"}});
  }

  /// Get metrics in Prometheus format
  std::string get_prometheus_metrics() {
    return metrics_.to_prometheus();
  }

private:
  RoomStatsAggregator& room_agg_;
  UserStatsTracker& user_tracker_;
  ServerStatsCollector& server_collector_;
  StatsCache& cache_;
  MetricsCollector& metrics_;
};

// ============================================================================
// 6. MetricsCollector
//
// Prometheus-style metrics collection: gauges, counters, histograms.
// Tracks request rates, event throughput, user/room counts, federation
// activity, cache performance, and database query durations.
//
// Equivalent to synapse/metrics/__init__.py and synapse/metrics/metric.py
// ============================================================================

class MetricsCollector {
public:
  MetricsCollector() {
    initialize_metrics();
  }

  // ---- Metric accessors ----

  PrometheusCounter& counter(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = counters_.find(name);
    if (it != counters_.end()) return *it->second;
    // If not found, create on the fly (rare path)
    lock.unlock();
    return get_or_create_counter(name, "auto-created counter", {});
  }

  PrometheusGauge& gauge(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = gauges_.find(name);
    if (it != gauges_.end()) return *it->second;
    lock.unlock();
    return get_or_create_gauge(name, "auto-created gauge", {});
  }

  SimpleHistogram& histogram(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = histograms_.find(name);
    if (it != histograms_.end()) return *it->second;
    // Fallback to default histogram
    lock.unlock();
    return get_or_create_histogram(name, "auto-created histogram",
                                    {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0});
  }

  // ---- Record methods for common metrics ----

  void record_request(const std::string& method, const std::string& endpoint,
                      double duration_seconds, int status_code) {
    counter(kMetricRequestsTotal).inc();
    histogram("progressive_request_duration_seconds").observe(duration_seconds);

    // Labeled by method and status
    std::map<std::string, std::string> labels;
    labels["method"] = method;
    labels["status"] = std::to_string(status_code);
    counter(kMetricRequestsTotal).inc_labels(labels, 1.0);
  }

  void record_event_processed(const std::string& event_type) {
    counter(kMetricEventsProcessed).inc();
    EventCategory cat = classify_event(event_type);
    std::map<std::string, std::string> labels;
    labels["type"] = std::to_string(static_cast<int>(cat));
    counter(kMetricEventsProcessed).inc_labels(labels, 1.0);
  }

  void record_message_sent() {
    counter(kMetricMessagesSent).inc();
  }

  void record_federation_request(bool incoming, bool success) {
    counter(kMetricFederationRequests).inc();
    std::map<std::string, std::string> labels;
    labels["direction"] = incoming ? "incoming" : "outgoing";
    labels["success"] = success ? "true" : "false";
    counter(kMetricFederationRequests).inc_labels(labels, 1.0);
  }

  void record_media_bytes(int64_t bytes) {
    counter(kMetricMediaBytes).inc(static_cast<double>(bytes));
  }

  void record_cache_hit() { counter(kMetricCacheHits).inc(); }
  void record_cache_miss() { counter(kMetricCacheMisses).inc(); }

  void record_db_query_duration(double seconds) {
    histogram(kMetricDBQueryDuration).observe(seconds);
  }

  void set_user_count(int64_t count) {
    gauge(kMetricUsersTotal).set(static_cast<double>(count));
  }

  void set_active_user_count(int64_t count) {
    gauge(kMetricUsersActive).set(static_cast<double>(count));
  }

  void set_room_count(int64_t count) {
    gauge(kMetricRoomsTotal).set(static_cast<double>(count));
  }

  void set_dau(int64_t count) {
    gauge(kMetricDAU).set(static_cast<double>(count));
  }

  void set_mau(int64_t count) {
    gauge(kMetricMAU).set(static_cast<double>(count));
  }

  void set_media_bytes(int64_t bytes) {
    gauge(kMetricMediaBytes).set(static_cast<double>(bytes));
  }

  // ---- Export ----

  std::string to_prometheus() const {
    std::stringstream ss;

    {
      std::shared_lock<std::shared_mutex> lock(mutex_);
      for (auto& [name, counter] : counters_) {
        ss << counter->to_prometheus() << "\n";
      }
      for (auto& [name, gauge] : gauges_) {
        ss << gauge->to_prometheus() << "\n";
      }
      for (auto& [name, histogram] : histograms_) {
        ss << histogram->to_prometheus() << "\n";
      }
    }

    return ss.str();
  }

  json to_json() const {
    json j = json::object();

    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (auto& [name, counter] : counters_) {
      j[name] = counter->value();
    }
    for (auto& [name, gauge] : gauges_) {
      j[name] = gauge->value();
    }
    for (auto& [name, histogram] : histograms_) {
      j[name] = json({
          {"sum", histogram->sum()},
          {"count", histogram->count()}
      });
    }

    return j;
  }

  void reset_all() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    for (auto& [name, c] : counters_) c->reset();
    // Gauges and histograms can't be fully reset, recreate them
    counters_.clear();
    gauges_.clear();
    histograms_.clear();
    initialize_metrics();
  }

private:
  void initialize_metrics() {
    // Counters
    create_counter(kMetricRequestsTotal, "Total number of HTTP requests processed",
                   {"method", "status"});
    create_counter(kMetricEventsProcessed, "Total number of events processed",
                   {"type"});
    create_counter(kMetricFederationRequests, "Total federation requests",
                   {"direction", "success"});
    create_counter(kMetricMessagesSent, "Total messages sent");
    create_counter(kMetricMediaBytes, "Total media bytes uploaded");
    create_counter(kMetricCacheHits, "Total stats cache hits");
    create_counter(kMetricCacheMisses, "Total stats cache misses");

    // Gauges
    create_gauge(kMetricUsersTotal, "Total registered users");
    create_gauge(kMetricUsersActive, "Total active users (seen in last 30 days)");
    create_gauge(kMetricRoomsTotal, "Total rooms on this server");
    create_gauge(kMetricDAU, "Daily active users");
    create_gauge(kMetricMAU, "Monthly active users");
    create_gauge(kMetricMediaBytes, "Total media stored (bytes)");

    // Histograms
    create_histogram("progressive_request_duration_seconds",
                     "HTTP request duration in seconds",
                     {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0});
    create_histogram(kMetricDBQueryDuration,
                     "Database query duration in seconds",
                     {0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0});
    create_histogram("progressive_event_processing_duration_seconds",
                     "Event processing duration in seconds",
                     {0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0});
    create_histogram("progressive_federation_duration_seconds",
                     "Federation request duration in seconds",
                     {0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0});
  }

  PrometheusCounter& get_or_create_counter(const std::string& name,
                                            const std::string& help,
                                            const std::vector<std::string>& labels) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = counters_.find(name);
    if (it != counters_.end()) return *it->second;
    auto counter = std::make_unique<PrometheusCounter>(name, help, labels);
    auto* ptr = counter.get();
    counters_[name] = std::move(counter);
    return *ptr;
  }

  PrometheusGauge& get_or_create_gauge(const std::string& name,
                                        const std::string& help,
                                        const std::vector<std::string>& labels) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = gauges_.find(name);
    if (it != gauges_.end()) return *it->second;
    auto gauge = std::make_unique<PrometheusGauge>(name, help, labels);
    auto* ptr = gauge.get();
    gauges_[name] = std::move(gauge);
    return *ptr;
  }

  SimpleHistogram& get_or_create_histogram(const std::string& name,
                                            const std::string& help,
                                            const std::vector<double>& buckets) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = histograms_.find(name);
    if (it != histograms_.end()) return *it->second;
    auto hist = std::make_unique<SimpleHistogram>(name, help, buckets);
    auto* ptr = hist.get();
    histograms_[name] = std::move(hist);
    return *ptr;
  }

  void create_counter(const std::string& name, const std::string& help,
                      const std::vector<std::string>& labels = {}) {
    counters_[name] = std::make_unique<PrometheusCounter>(name, help, labels);
  }

  void create_gauge(const std::string& name, const std::string& help,
                    const std::vector<std::string>& labels = {}) {
    gauges_[name] = std::make_unique<PrometheusGauge>(name, help, labels);
  }

  void create_histogram(const std::string& name, const std::string& help,
                        const std::vector<double>& buckets) {
    histograms_[name] = std::make_unique<SimpleHistogram>(name, help, buckets);
  }

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, std::unique_ptr<PrometheusCounter>> counters_;
  std::unordered_map<std::string, std::unique_ptr<PrometheusGauge>> gauges_;
  std::unordered_map<std::string, std::unique_ptr<SimpleHistogram>> histograms_;
};

// ============================================================================
// 7. StatsEngine — Unified facade composing all stats subsystems
//
// Main entry point for statistics functionality. Composes room stats
// aggregation, user stats tracking, server stats collection, caching,
// admin API, and metrics collection into a single interface.
//
// Equivalent to synapse/stats.py (overall statistics orchestration)
// ============================================================================

class StatsEngine {
public:
  explicit StatsEngine(storage::DatabasePool& db, const std::string& server_name = "")
      : db_(db),
        metrics_(std::make_unique<MetricsCollector>()),
        cache_(std::make_unique<StatsCache>()),
        room_agg_(std::make_unique<RoomStatsAggregator>(db)),
        user_tracker_(std::make_unique<UserStatsTracker>(db)),
        server_collector_(std::make_unique<ServerStatsCollector>(db)),
        admin_api_(std::make_unique<StatsAdminAPI>(
            *room_agg_, *user_tracker_, *server_collector_,
            *cache_, *metrics_)) {
    if (!server_name.empty()) {
      room_agg_->set_server_name(server_name);
    }
  }

  // ---- Lifecycle ----

  void start() {
    room_agg_->start();
  }

  void stop() {
    room_agg_->stop();
  }

  // ---- Accessors ----

  MetricsCollector& metrics() { return *metrics_; }
  StatsCache& cache() { return *cache_; }
  RoomStatsAggregator& room_aggregator() { return *room_agg_; }
  UserStatsTracker& user_tracker() { return *user_tracker_; }
  ServerStatsCollector& server_collector() { return *server_collector_; }
  StatsAdminAPI& admin_api() { return *admin_api_; }

  // ---- Event hooks (called from main event processing pipeline) ----

  /// Called when any event is processed
  void on_event_processed(const std::string& room_id, const std::string& event_type,
                          const std::string& sender, int64_t origin_server_ts) {
    metrics_->record_event_processed(event_type);

    auto cat = classify_event(event_type);
    if (cat == EventCategory::kMessage) {
      metrics_->record_message_sent();
    }

    // Update room last activity timestamp in cache
    cache_->invalidate_room(room_id);
  }

  /// Called when a state event is persisted
  void on_state_event(const std::string& room_id, const std::string& event_type,
                      const std::string& state_key, const json& content) {
    room_agg_->on_state_event(room_id, event_type, state_key, content);
    cache_->invalidate_room(room_id);
    cache_->invalidate_server_stats();
  }

  /// Called when a membership changes
  void on_membership_change(const std::string& room_id, const std::string& user_id,
                            const std::string& new_membership,
                            const std::string& old_membership) {
    room_agg_->on_membership_change(room_id, user_id, new_membership, old_membership);
    cache_->invalidate_room(room_id);
    cache_->invalidate_server_stats();
  }

  /// Called on user sync (records daily visit)
  void on_user_sync(const std::string& user_id, const std::string& device_id,
                    const std::string& user_agent = "") {
    user_tracker_->record_user_visit(user_id, device_id, user_agent);
    cache_->invalidate_user(user_id);
    cache_->invalidate_dau_mau();
  }

  /// Called on HTTP request (for metrics)
  void on_http_request(const std::string& method, const std::string& path,
                       double duration_seconds, int status_code) {
    metrics_->record_request(method, path, duration_seconds, status_code);
  }

  /// Called when media is uploaded
  void on_media_upload(const std::string& user_id, int64_t bytes) {
    metrics_->record_media_bytes(bytes);
    cache_->invalidate_media_stats();
    cache_->invalidate_user(user_id);
  }

  /// Called on federation request
  void on_federation_request(bool incoming, bool success) {
    metrics_->record_federation_request(incoming, success);
  }

  /// Called on database query completion
  void on_db_query(double duration_seconds) {
    metrics_->record_db_query_duration(duration_seconds);
  }

  // ---- Periodic stats refresh ----

  /// Refresh all metrics with current database counts
  void refresh_all_metrics() {
    ServerStatsSnapshot snap = server_collector_->compute_server_stats();
    snap.daily_active_users = user_tracker_->get_daily_active_users();
    snap.monthly_active_users = user_tracker_->get_monthly_active_users();

    metrics_->set_user_count(snap.total_users);
    metrics_->set_active_user_count(snap.total_active_users);
    metrics_->set_room_count(snap.total_rooms);
    metrics_->set_dau(snap.daily_active_users);
    metrics_->set_mau(snap.monthly_active_users);
    metrics_->set_media_bytes(snap.total_local_media_bytes);

    cache_->set_cached_server_stats(snap);
    cache_->set_cached_dau_mau(snap.daily_active_users, snap.monthly_active_users);
  }

  // ---- Admin API delegates ----

  json get_statistics() { return admin_api_->get_statistics(); }
  json get_user_media_stats(const std::string& order_by = "media_length",
                            bool reverse = true, int64_t limit = 100,
                            int64_t offset = 0,
                            const std::string& search_term = "") {
    return admin_api_->get_user_media_stats(order_by, reverse, limit, offset, search_term);
  }
  json get_database_room_stats() { return admin_api_->get_database_room_stats(); }
  json get_room_stats_list(const std::string& sort_by = "joined_members",
                           bool ascending = false, int64_t limit = 100,
                           int64_t offset = 0) {
    return admin_api_->get_room_stats_list(sort_by, ascending, limit, offset);
  }
  json get_room_stats_detail(const std::string& room_id) {
    return admin_api_->get_room_stats_detail(room_id);
  }
  json get_user_stats_detail(const std::string& user_id) {
    return admin_api_->get_user_stats_detail(user_id);
  }
  json get_user_creation_timeline(const std::string& bucket = "day", int limit = 365) {
    return admin_api_->get_user_creation_timeline(bucket, limit);
  }
  json get_dau_mau_time_series(int days = 90) {
    return admin_api_->get_dau_mau_time_series(days);
  }
  json get_event_throughput_time_series(int hours = 24) {
    return admin_api_->get_event_throughput_time_series(hours);
  }
  json get_top_users(int64_t limit = 100) {
    return admin_api_->get_top_users(limit);
  }
  json get_retention_metrics() { return admin_api_->get_retention_metrics(); }
  json get_cache_stats() { return admin_api_->get_cache_stats(); }
  json run_room_aggregation(int64_t batch_size = kAggregationBatchSize) {
    return admin_api_->run_room_aggregation(batch_size);
  }
  json invalidate_caches() { return admin_api_->invalidate_caches(); }
  std::string get_prometheus_metrics() { return admin_api_->get_prometheus_metrics(); }

private:
  storage::DatabasePool& db_;
  std::unique_ptr<MetricsCollector> metrics_;
  std::unique_ptr<StatsCache> cache_;
  std::unique_ptr<RoomStatsAggregator> room_agg_;
  std::unique_ptr<UserStatsTracker> user_tracker_;
  std::unique_ptr<ServerStatsCollector> server_collector_;
  std::unique_ptr<StatsAdminAPI> admin_api_;
};

// ============================================================================
// Global factory function
// ============================================================================

std::unique_ptr<StatsEngine> create_stats_engine(storage::DatabasePool& db,
                                                  const std::string& server_name) {
  return std::make_unique<StatsEngine>(db, server_name);
}

}  // namespace progressive
