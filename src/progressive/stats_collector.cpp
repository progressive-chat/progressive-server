// ============================================================================
// stats_collector.cpp — Matrix Statistics Collector: Room/User/Server Stats,
//   SQL-driven Aggregation, DAU/MAU Tracking, Registration Timeline,
//   Prometheus Export, Admin REST API, Background Update Worker
//
// Implements:
//   - Room stats aggregation: member breakdown (join/invite/leave/ban/knock),
//     event counts (message/state/redaction/reaction), room activity timeline,
//     room growth rates, per-room message velocity
//   - User stats: DAU/MAU computation via SQL windowed queries,
//     registration timeline with daily/weekly/monthly bucketing,
//     user activity heatmap, user cohort analysis, retention curves
//   - Server stats: total users/rooms/events/media, federation throughput,
//     event throughput time series, peak load tracking, growth trends
//   - Stats caching: TTL-based in-memory cache with LRU eviction,
//     segmented caches per stat category, cache warming, invalidation hooks
//   - Stats API endpoints: GET /_progressive/stats/v1/rooms,
//     GET /_progressive/stats/v1/users, GET /_progressive/stats/v1/server,
//     GET /_progressive/stats/v1/activity, GET /_progressive/stats/v1/media,
//     GET /_progressive/stats/v1/federation
//   - Prometheus metrics export: /metrics endpoint with all gauges,
//     counters, histograms, summaries for Matrix-specific metrics
//   - Stats background updates: periodic aggregation worker that recomputes
//     cached stats from raw database tables, incremental delta updates
//   - Stats admin endpoints: GET/POST /_progressive/admin/v1/stats/*,
//     manual aggregation triggers, cache control, stats export
//
// Equivalent to:
//   synapse/storage/databases/main/stats.py
//   synapse/rest/admin/statistics.py
//   synapse/handlers/stats.py
//   synapse/metrics/__init__.py
//   synapse/app/homeserver.py (statistics module)
//
// Target: 3000+ lines of production-grade C++ with full SQL coverage.
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
#include <regex>
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
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/devices.hpp"
#include "progressive/storage/databases/main/receipts.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class RoomStatsCollector;
class UserActivityTracker;
class ServerStatsAggregator;
class StatsDataCache;
class PrometheusExporter;
class StatsBackgroundWorker;
class StatsAdminHandler;
class StatsCollectorEngine;

// ============================================================================
// Anonymous namespace — Internal helpers, constants, and utility types
// ============================================================================
namespace {

// ---- Timestamp utilities ----

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
  return static_cast<int64_t>(std::mktime(utc));
}

inline int64_t days_ago_sec(int days) {
  return now_sec() - static_cast<int64_t>(days) * 86400;
}

inline int64_t hours_ago_sec(int hours) {
  return now_sec() - static_cast<int64_t>(hours) * 3600;
}

inline std::string iso_date(int64_t sec) {
  char buf[16];
  auto t = static_cast<std::time_t>(sec);
  std::strftime(buf, sizeof(buf), "%Y-%m-%d", std::gmtime(&t));
  return buf;
}

inline std::string iso_datetime(int64_t sec) {
  char buf[32];
  auto t = static_cast<std::time_t>(sec);
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

inline std::string iso_month_str(int64_t sec) {
  char buf[10];
  auto t = static_cast<std::time_t>(sec);
  std::strftime(buf, sizeof(buf), "%Y-%m", std::gmtime(&t));
  return buf;
}

inline std::string iso_week_str(int64_t sec) {
  auto t = static_cast<std::time_t>(sec);
  auto* utc = std::gmtime(&t);
  int days_since_monday = (utc->tm_wday + 6) % 7;
  auto week_start = sec - days_since_monday * 86400;
  return iso_date(week_start);
}

// ---- String constants ----

constexpr std::string_view kMembershipJoin = "join";
constexpr std::string_view kMembershipInvite = "invite";
constexpr std::string_view kMembershipLeave = "leave";
constexpr std::string_view kMembershipBan = "ban";
constexpr std::string_view kMembershipKnock = "knock";

constexpr const char* kBucketDaily = "daily";
constexpr const char* kBucketWeekly = "weekly";
constexpr const char* kBucketMonthly = "monthly";
constexpr const char* kBucketHourly = "hourly";

// ---- Cache TTLs (milliseconds) ----

constexpr int64_t kCacheTTLRoomStats = 60'000;          // 1 min
constexpr int64_t kCacheTTLUserStats = 300'000;         // 5 min
constexpr int64_t kCacheTTLServerStats = 60'000;        // 1 min
constexpr int64_t kCacheTTLDAUMAU = 600'000;            // 10 min
constexpr int64_t kCacheTTLMediaStats = 300'000;        // 5 min
constexpr int64_t kCacheTTLRegistrationTimeline = 3'600'000; // 1 hour
constexpr int64_t kCacheTTLActivityHeatmap = 900'000;   // 15 min
constexpr int64_t kCacheTTLFederationStats = 120'000;   // 2 min
constexpr int64_t kCacheTTLTopRooms = 600'000;          // 10 min
constexpr int64_t kCacheTTLTopUsers = 600'000;          // 10 min

// ---- Background update intervals (ms) ----

constexpr int64_t kBgUpdateIntervalMs = 300'000;        // 5 min
constexpr int64_t kDAUFlushIntervalMs = 60'000;         // 1 min
constexpr int64_t kLongRunningIntervalMs = 3'600'000;   // 1 hour

// ---- Batch sizes ----

constexpr int64_t kRoomBatchSize = 200;
constexpr int64_t kUserBatchSize = 500;
constexpr int64_t kEventBatchSize = 1000;

// ---- Prometheus metric names ----

constexpr const char* kMetricRequestsTotal = "progressive_collector_requests_total";
constexpr const char* kMetricEventsTotal = "progressive_collector_events_total";
constexpr const char* kMetricUsersTotal = "progressive_collector_users_total";
constexpr const char* kMetricRoomsTotal = "progressive_collector_rooms_total";
constexpr const char* kMetricMessagesTotal = "progressive_collector_messages_total";
constexpr const char* kMetricMediaBytes = "progressive_collector_media_bytes_total";
constexpr const char* kMetricDAU = "progressive_collector_daily_active_users";
constexpr const char* kMetricMAU = "progressive_collector_monthly_active_users";
constexpr const char* kMetricFederationIn = "progressive_collector_federation_requests_in_total";
constexpr const char* kMetricFederationOut = "progressive_collector_federation_requests_out_total";
constexpr const char* kMetricCacheHits = "progressive_collector_cache_hits_total";
constexpr const char* kMetricCacheMisses = "progressive_collector_cache_misses_total";
constexpr const char* kMetricBGUpdates = "progressive_collector_bg_updates_total";
constexpr const char* kMetricQueryLatency = "progressive_collector_query_latency_seconds";
constexpr const char* kMetricActiveRooms = "progressive_collector_active_rooms";
constexpr const char* kMetricRegistrations = "progressive_collector_registrations_total";
constexpr const char* kMetricDeactivations = "progressive_collector_deactivations_total";
constexpr const char* kMetricPeakConnections = "progressive_collector_peak_connections";
constexpr const char* kMetricQueueDepth = "progressive_collector_queue_depth";

// ---- Membership string normalization ----

std::string normalize_membership(const std::string& membership) {
  std::string lower;
  lower.reserve(membership.size());
  for (char c : membership) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (lower == "join" || lower == "joined") return std::string(kMembershipJoin);
  if (lower == "invite" || lower == "invited") return std::string(kMembershipInvite);
  if (lower == "leave" || lower == "left") return std::string(kMembershipLeave);
  if (lower == "ban" || lower == "banned") return std::string(kMembershipBan);
  if (lower == "knock" || lower == "knocking") return std::string(kMembershipKnock);
  return lower;
}

// ---- Room/event classification helpers ----

enum class EventFamily {
  kMessage,
  kState,
  kMembership,
  kRedaction,
  kReaction,
  kEncrypted,
  kOther
};

EventFamily classify_event_family(const std::string& event_type) {
  if (event_type == "m.room.message") return EventFamily::kMessage;
  if (event_type == "m.room.encrypted") return EventFamily::kEncrypted;
  if (event_type == "m.reaction") return EventFamily::kReaction;
  if (event_type == "m.room.redaction") return EventFamily::kRedaction;
  if (event_type == "m.room.member") return EventFamily::kMembership;
  if (event_type.find("m.room.") == 0) return EventFamily::kState;
  if (event_type.find("m.") == 0) return EventFamily::kOther;
  return EventFamily::kOther;
}

const char* event_family_name(EventFamily f) {
  switch (f) {
    case EventFamily::kMessage: return "message";
    case EventFamily::kState: return "state";
    case EventFamily::kMembership: return "membership";
    case EventFamily::kRedaction: return "redaction";
    case EventFamily::kReaction: return "reaction";
    case EventFamily::kEncrypted: return "encrypted";
    default: return "other";
  }
}

// ---- Statistical helpers ----

double compute_median(std::vector<int64_t>& values) {
  if (values.empty()) return 0.0;
  std::sort(values.begin(), values.end());
  size_t n = values.size();
  if (n % 2 == 0) {
    return (static_cast<double>(values[n / 2 - 1]) + static_cast<double>(values[n / 2])) / 2.0;
  }
  return static_cast<double>(values[n / 2]);
}

double compute_p95(std::vector<int64_t>& values) {
  if (values.empty()) return 0.0;
  std::sort(values.begin(), values.end());
  size_t idx = static_cast<size_t>(std::ceil(0.95 * values.size())) - 1;
  if (idx >= values.size()) idx = values.size() - 1;
  return static_cast<double>(values[idx]);
}

double compute_p99(std::vector<int64_t>& values) {
  if (values.empty()) return 0.0;
  std::sort(values.begin(), values.end());
  size_t idx = static_cast<size_t>(std::ceil(0.99 * values.size())) - 1;
  if (idx >= values.size()) idx = values.size() - 1;
  return static_cast<double>(values[idx]);
}

int64_t compute_sum(const std::vector<int64_t>& values) {
  int64_t total = 0;
  for (auto v : values) total += v;
  return total;
}

double compute_avg(const std::vector<int64_t>& values) {
  if (values.empty()) return 0.0;
  return static_cast<double>(compute_sum(values)) / values.size();
}

int64_t compute_min(const std::vector<int64_t>& values) {
  if (values.empty()) return 0;
  return *std::min_element(values.begin(), values.end());
}

int64_t compute_max(const std::vector<int64_t>& values) {
  if (values.empty()) return 0;
  return *std::max_element(values.begin(), values.end());
}

// ---- LRU Cache node for stats caching ----

template<typename K, typename V>
struct LRUNode {
  K key;
  V value;
  int64_t expiry_ms;
  LRUNode* prev = nullptr;
  LRUNode* next = nullptr;
};

// ---- Time-bucket helper for timeline data ----

json build_time_buckets(int64_t from_sec, int64_t to_sec,
                         const std::string& bucket_type) {
  json buckets = json::array();
  int64_t step;
  if (bucket_type == "hourly") step = 3600;
  else if (bucket_type == "daily") step = 86400;
  else if (bucket_type == "weekly") step = 604800;
  else if (bucket_type == "monthly") step = 2592000; // ~30 days
  else step = 86400; // default daily

  for (int64_t t = from_sec; t <= to_sec; t += step) {
    json b;
    b["ts"] = t;
    b["label"] = (bucket_type == "monthly" ? iso_month_str(t) :
                  bucket_type == "weekly" ? iso_week_str(t) : iso_date(t));
    b["count"] = 0;
    buckets.push_back(b);
  }
  return buckets;
}

// ============================================================================
// PrometheusMetric — Base class for a single Prometheus metric
// ============================================================================

class PrometheusMetric {
public:
  enum class Type { kCounter, kGauge, kHistogram, kSummary };

  PrometheusMetric(const std::string& name, const std::string& help, Type type,
                   const std::vector<std::string>& labels = {})
      : name_(name), help_(help), type_(type), label_names_(labels) {}

  virtual ~PrometheusMetric() = default;

  const std::string& name() const { return name_; }
  const std::string& help() const { return help_; }
  Type type() const { return type_; }

  virtual std::string render() const = 0;
  virtual void reset() = 0;

protected:
  std::string render_labels(const std::map<std::string, std::string>& labels) const {
    if (labels.empty()) return "";
    std::stringstream ss;
    ss << "{";
    bool first = true;
    for (auto& [k, v] : labels) {
      if (!first) ss << ",";
      first = false;
      ss << k << "=\"" << v << "\"";
    }
    ss << "}";
    return ss.str();
  }

  std::string type_str() const {
    switch (type_) {
      case Type::kCounter: return "counter";
      case Type::kGauge: return "gauge";
      case Type::kHistogram: return "histogram";
      case Type::kSummary: return "summary";
    }
    return "untyped";
  }

  std::string name_;
  std::string help_;
  Type type_;
  std::vector<std::string> label_names_;
};

// ============================================================================
// CounterMetric — Thread-safe monotonically increasing counter
// ============================================================================

class CounterMetric : public PrometheusMetric {
public:
  CounterMetric(const std::string& name, const std::string& help,
                const std::vector<std::string>& labels = {})
      : PrometheusMetric(name, help, Type::kCounter, labels) {}

  void inc(double amount = 1.0) {
    value_.fetch_add(amount, std::memory_order_relaxed);
  }

  void inc_labels(const std::map<std::string, std::string>& labels, double amount = 1.0) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = labels_key(labels);
    labeled_[key].fetch_add(amount, std::memory_order_relaxed);
  }

  double value() const { return value_.load(std::memory_order_relaxed); }

  std::string render() const override {
    std::stringstream ss;
    ss << "# HELP " << name_ << " " << help_ << "\n";
    ss << "# TYPE " << name_ << " counter\n";
    ss << name_ << " " << std::fixed << std::setprecision(0) << value() << "\n";
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [k, v] : labeled_) {
      ss << name_ << "{" << k << "} " << std::fixed << std::setprecision(0)
         << v.load(std::memory_order_relaxed) << "\n";
    }
    return ss.str();
  }

  void reset() override {
    value_.store(0.0, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(mutex_);
    labeled_.clear();
  }

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

  std::atomic<double> value_{0.0};
  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::atomic<double>> labeled_;
};

// ============================================================================
// GaugeMetric — Thread-safe gauge (can go up and down)
// ============================================================================

class GaugeMetric : public PrometheusMetric {
public:
  GaugeMetric(const std::string& name, const std::string& help,
              const std::vector<std::string>& labels = {})
      : PrometheusMetric(name, help, Type::kGauge, labels) {}

  void set(double val) { value_.store(val, std::memory_order_relaxed); }
  void inc(double amount = 1.0) {
    double expected = value_.load(std::memory_order_relaxed);
    while (!value_.compare_exchange_weak(expected, expected + amount,
                                          std::memory_order_relaxed)) {}
  }
  void dec(double amount = 1.0) { inc(-amount); }

  void set_labels(const std::map<std::string, std::string>& labels, double val) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = labels_key(labels);
    labeled_[key].store(val, std::memory_order_relaxed);
  }

  double value() const { return value_.load(std::memory_order_relaxed); }

  std::string render() const override {
    std::stringstream ss;
    ss << "# HELP " << name_ << " " << help_ << "\n";
    ss << "# TYPE " << name_ << " gauge\n";
    ss << name_ << " " << std::fixed << std::setprecision(2) << value() << "\n";
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [k, v] : labeled_) {
      ss << name_ << "{" << k << "} " << std::fixed << std::setprecision(2)
         << v.load(std::memory_order_relaxed) << "\n";
    }
    return ss.str();
  }

  void reset() override {
    value_.store(0.0, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(mutex_);
    labeled_.clear();
  }

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

  std::atomic<double> value_{0.0};
  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::atomic<double>> labeled_;
};

// ============================================================================
// HistogramMetric — Histogram for duration/response-size tracking
// ============================================================================

class HistogramMetric : public PrometheusMetric {
public:
  HistogramMetric(const std::string& name, const std::string& help,
                  const std::vector<double>& buckets,
                  const std::vector<std::string>& labels = {})
      : PrometheusMetric(name, help, Type::kHistogram, labels),
        buckets_(buckets), counts_(buckets.size() + 1, 0) {}

  void observe(double value) {
    sum_.fetch_add(value, std::memory_order_relaxed);
    total_.fetch_add(1, std::memory_order_relaxed);
    size_t idx = buckets_.size(); // +Inf
    for (size_t i = 0; i < buckets_.size(); i++) {
      if (value <= buckets_[i]) { idx = i; break; }
    }
    counts_[idx].fetch_add(1, std::memory_order_relaxed);
  }

  std::string render() const override {
    std::stringstream ss;
    ss << "# HELP " << name_ << " " << help_ << "\n";
    ss << "# TYPE " << name_ << " histogram\n";
    for (size_t i = 0; i < buckets_.size(); i++) {
      ss << name_ << "_bucket{le=\"" << std::fixed << std::setprecision(3)
         << buckets_[i] << "\"} " << counts_[i].load(std::memory_order_relaxed) << "\n";
    }
    ss << name_ << "_bucket{le=\"+Inf\"} "
       << counts_.back().load(std::memory_order_relaxed) << "\n";
    ss << name_ << "_sum " << std::fixed << std::setprecision(6)
       << sum_.load(std::memory_order_relaxed) << "\n";
    ss << name_ << "_count " << total_.load(std::memory_order_relaxed) << "\n";
    return ss.str();
  }

  void reset() override {
    sum_.store(0.0, std::memory_order_relaxed);
    total_.store(0, std::memory_order_relaxed);
    for (auto& c : counts_) c.store(0, std::memory_order_relaxed);
  }

private:
  std::vector<double> buckets_;
  std::vector<std::atomic<int64_t>> counts_;
  std::atomic<double> sum_{0.0};
  std::atomic<int64_t> total_{0};
};

// ============================================================================
// SummaryMetric — Summary with quantiles
// ============================================================================

class SummaryMetric : public PrometheusMetric {
public:
  SummaryMetric(const std::string& name, const std::string& help,
                const std::vector<double>& quantiles,
                const std::vector<std::string>& labels = {})
      : PrometheusMetric(name, help, Type::kSummary, labels),
        quantiles_(quantiles) {}

  void observe(double value) {
    std::lock_guard<std::mutex> lock(mutex_);
    values_.push_back(value);
    sum_ += value;
    total_++;
    // Keep a sliding window of last 10000 observations
    if (values_.size() > 10000) {
      sum_ -= values_.front();
      values_.pop_front();
    }
  }

  std::string render() const override {
    std::stringstream ss;
    ss << "# HELP " << name_ << " " << help_ << "\n";
    ss << "# TYPE " << name_ << " summary\n";

    std::lock_guard<std::mutex> lock(mutex_);
    if (!values_.empty()) {
      std::vector<double> sorted(values_.begin(), values_.end());
      std::sort(sorted.begin(), sorted.end());
      for (auto q : quantiles_) {
        size_t idx = static_cast<size_t>(q * (sorted.size() - 1));
        if (idx >= sorted.size()) idx = sorted.size() - 1;
        ss << name_ << "{quantile=\"" << std::fixed << std::setprecision(2)
           << q << "\"} " << sorted[idx] << "\n";
      }
    }
    ss << name_ << "_sum " << std::fixed << std::setprecision(6) << sum_ << "\n";
    ss << name_ << "_count " << total_ << "\n";
    return ss.str();
  }

  void reset() override {
    std::lock_guard<std::mutex> lock(mutex_);
    values_.clear();
    sum_ = 0.0;
    total_ = 0;
  }

private:
  std::vector<double> quantiles_;
  mutable std::mutex mutex_;
  std::deque<double> values_;
  double sum_ = 0.0;
  int64_t total_ = 0;
};

}  // anonymous namespace

// ============================================================================
// RoomStatsSnapshot — Complete room statistics data transfer object
// ============================================================================

struct RoomStatsSnapshot {
  std::string room_id;
  std::string room_name;
  std::string room_topic;
  std::string canonical_alias;
  std::string room_version;
  std::string join_rules;
  std::string history_visibility;
  std::string guest_access;
  std::string room_type;               // "room", "space"
  bool is_encrypted = false;
  bool is_federatable = true;

  // Membership breakdown
  int64_t joined_count = 0;
  int64_t invited_count = 0;
  int64_t left_count = 0;
  int64_t banned_count = 0;
  int64_t knock_count = 0;
  int64_t total_members = 0;
  int64_t local_members = 0;
  int64_t remote_members = 0;

  // Event breakdown
  int64_t message_events = 0;
  int64_t state_events = 0;
  int64_t redaction_events = 0;
  int64_t reaction_events = 0;
  int64_t total_events = 0;
  int64_t events_24h = 0;
  int64_t events_7d = 0;
  int64_t events_30d = 0;

  // Activity
  int64_t creation_ts = 0;
  int64_t last_activity_ts = 0;
  int64_t last_message_ts = 0;
  int64_t forward_extremities = 0;
  int64_t backward_extremities = 0;

  // Growth
  double growth_rate_7d = 0.0;  // avg new members/day over last 7 days
  double growth_rate_30d = 0.0;

  // Metadata
  int64_t stats_computed_ts = 0;

  json to_json() const {
    json j;
    j["room_id"] = room_id;
    j["room_name"] = room_name;
    j["room_topic"] = room_topic;
    j["canonical_alias"] = canonical_alias;
    j["room_version"] = room_version;
    j["join_rules"] = join_rules;
    j["history_visibility"] = history_visibility;
    j["guest_access"] = guest_access;
    j["room_type"] = room_type;
    j["is_encrypted"] = is_encrypted;
    j["is_federatable"] = is_federatable;

    json members;
    members["joined"] = joined_count;
    members["invited"] = invited_count;
    members["left"] = left_count;
    members["banned"] = banned_count;
    members["knock"] = knock_count;
    members["total"] = total_members;
    members["local"] = local_members;
    members["remote"] = remote_members;
    j["members"] = members;

    json events;
    events["messages"] = message_events;
    events["state"] = state_events;
    events["redactions"] = redaction_events;
    events["reactions"] = reaction_events;
    events["total"] = total_events;
    events["last_24h"] = events_24h;
    events["last_7d"] = events_7d;
    events["last_30d"] = events_30d;
    j["events"] = events;

    j["creation_ts"] = creation_ts;
    j["last_activity_ts"] = last_activity_ts;
    j["last_message_ts"] = last_message_ts;
    j["forward_extremities"] = forward_extremities;
    j["backward_extremities"] = backward_extremities;
    j["growth_rate_7d"] = growth_rate_7d;
    j["growth_rate_30d"] = growth_rate_30d;
    j["stats_computed_ts"] = stats_computed_ts;
    return j;
  }
};

// ============================================================================
// UserStatsData — User statistics data transfer object
// ============================================================================

struct UserStatsData {
  std::string user_id;
  std::string display_name;
  std::string avatar_url;
  bool is_guest = false;
  bool is_deactivated = false;
  bool is_appservice = false;
  bool is_admin = false;

  // Registration
  int64_t creation_ts = 0;
  std::string creation_date;

  // Activity
  int64_t last_seen_ts = 0;
  int64_t last_daily_visit_ts = 0;
  bool active_today = false;
  bool active_this_week = false;
  bool active_this_month = false;
  int64_t days_active_last_30 = 0;
  int64_t days_active_last_90 = 0;

  // Engagement
  int64_t joined_rooms = 0;
  int64_t total_messages_sent = 0;
  int64_t messages_sent_30d = 0;
  int64_t total_reactions = 0;
  int64_t total_redactions = 0;
  int64_t devices_count = 0;

  // Media
  int64_t media_uploaded_bytes = 0;
  int64_t media_uploaded_count = 0;
  int64_t media_downloaded_bytes = 0;
  int64_t media_downloaded_count = 0;

  // Computed
  int64_t stats_computed_ts = 0;

  json to_json() const {
    json j;
    j["user_id"] = user_id;
    j["display_name"] = display_name;
    j["is_guest"] = is_guest;
    j["is_deactivated"] = is_deactivated;
    j["is_appservice"] = is_appservice;
    j["is_admin"] = is_admin;

    json reg;
    reg["creation_ts"] = creation_ts;
    reg["creation_date"] = creation_date;
    j["registration"] = reg;

    json activity;
    activity["last_seen_ts"] = last_seen_ts;
    activity["last_daily_visit_ts"] = last_daily_visit_ts;
    activity["active_today"] = active_today;
    activity["active_this_week"] = active_this_week;
    activity["active_this_month"] = active_this_month;
    activity["days_active_last_30"] = days_active_last_30;
    activity["days_active_last_90"] = days_active_last_90;
    j["activity"] = activity;

    json engagement;
    engagement["joined_rooms"] = joined_rooms;
    engagement["total_messages_sent"] = total_messages_sent;
    engagement["messages_sent_30d"] = messages_sent_30d;
    engagement["total_reactions"] = total_reactions;
    engagement["total_redactions"] = total_redactions;
    engagement["devices"] = devices_count;
    j["engagement"] = engagement;

    json media;
    media["uploaded_bytes"] = media_uploaded_bytes;
    media["uploaded_count"] = media_uploaded_count;
    media["downloaded_bytes"] = media_downloaded_bytes;
    media["downloaded_count"] = media_downloaded_count;
    j["media"] = media;

    j["stats_computed_ts"] = stats_computed_ts;
    return j;
  }

  json to_summary_json() const {
    json j;
    j["user_id"] = user_id;
    j["display_name"] = display_name;
    j["joined_rooms"] = joined_rooms;
    j["messages_sent_30d"] = messages_sent_30d;
    j["media_uploaded_count"] = media_uploaded_count;
    j["media_uploaded_bytes"] = media_uploaded_bytes;
    j["active_today"] = active_today;
    return j;
  }
};

// ============================================================================
// ServerStatsData — Server-wide statistics snapshot
// ============================================================================

struct ServerStatsData {
  // User counts
  int64_t total_users = 0;
  int64_t real_users = 0;
  int64_t guest_users = 0;
  int64_t deactivated_users = 0;
  int64_t appservice_users = 0;
  int64_t admin_users = 0;
  int64_t daily_active_users = 0;
  int64_t weekly_active_users = 0;
  int64_t monthly_active_users = 0;
  int64_t users_created_24h = 0;
  int64_t users_created_7d = 0;
  int64_t users_created_30d = 0;
  int64_t users_deactivated_24h = 0;

  // Room counts
  int64_t total_rooms = 0;
  int64_t public_rooms = 0;
  int64_t private_rooms = 0;
  int64_t encrypted_rooms = 0;
  int64_t space_rooms = 0;
  int64_t rooms_created_24h = 0;
  int64_t rooms_created_7d = 0;
  int64_t rooms_active_24h = 0;
  int64_t rooms_active_7d = 0;
  int64_t rooms_active_30d = 0;

  // Event counts
  int64_t total_events = 0;
  int64_t total_state_events = 0;
  int64_t total_messages = 0;
  int64_t total_reactions = 0;
  int64_t total_redactions = 0;
  int64_t events_24h = 0;
  int64_t events_7d = 0;
  int64_t events_30d = 0;
  double events_per_second_peak = 0.0;
  double events_per_minute_avg = 0.0;

  // Media stats
  int64_t total_local_media_bytes = 0;
  int64_t total_remote_media_bytes = 0;
  int64_t total_media_count = 0;
  int64_t local_media_count = 0;
  int64_t remote_media_count = 0;
  int64_t media_uploaded_24h = 0;
  int64_t media_uploaded_bytes_24h = 0;
  int64_t media_downloaded_24h = 0;
  int64_t media_downloaded_bytes_24h = 0;

  // Federation
  int64_t sent_transactions_24h = 0;
  int64_t received_transactions_24h = 0;
  int64_t sent_pdus_24h = 0;
  int64_t received_pdus_24h = 0;
  int64_t federation_failures_24h = 0;
  int64_t known_destinations = 0;
  int64_t reachable_destinations = 0;

  // Database
  int64_t db_total_size_bytes = 0;
  int64_t db_rows_approx = 0;

  int64_t computed_ts = 0;

  json to_json() const {
    json j;

    json users;
    users["total"] = total_users;
    users["real"] = real_users;
    users["guests"] = guest_users;
    users["deactivated"] = deactivated_users;
    users["appservice"] = appservice_users;
    users["admins"] = admin_users;
    users["daily_active"] = daily_active_users;
    users["weekly_active"] = weekly_active_users;
    users["monthly_active"] = monthly_active_users;
    users["created_24h"] = users_created_24h;
    users["created_7d"] = users_created_7d;
    users["created_30d"] = users_created_30d;
    users["deactivated_24h"] = users_deactivated_24h;
    j["users"] = users;

    json rooms;
    rooms["total"] = total_rooms;
    rooms["public"] = public_rooms;
    rooms["private"] = private_rooms;
    rooms["encrypted"] = encrypted_rooms;
    rooms["spaces"] = space_rooms;
    rooms["created_24h"] = rooms_created_24h;
    rooms["created_7d"] = rooms_created_7d;
    rooms["active_24h"] = rooms_active_24h;
    rooms["active_7d"] = rooms_active_7d;
    rooms["active_30d"] = rooms_active_30d;
    j["rooms"] = rooms;

    json events;
    events["total"] = total_events;
    events["state"] = total_state_events;
    events["messages"] = total_messages;
    events["reactions"] = total_reactions;
    events["redactions"] = total_redactions;
    events["last_24h"] = events_24h;
    events["last_7d"] = events_7d;
    events["last_30d"] = events_30d;
    events["peak_eps"] = events_per_second_peak;
    events["avg_epm"] = events_per_minute_avg;
    j["events"] = events;

    json media;
    media["total_local_bytes"] = total_local_media_bytes;
    media["total_remote_bytes"] = total_remote_media_bytes;
    media["total_count"] = total_media_count;
    media["local_count"] = local_media_count;
    media["remote_count"] = remote_media_count;
    media["uploaded_24h"] = media_uploaded_24h;
    media["uploaded_bytes_24h"] = media_uploaded_bytes_24h;
    media["downloaded_24h"] = media_downloaded_24h;
    media["downloaded_bytes_24h"] = media_downloaded_bytes_24h;
    j["media"] = media;

    json fed;
    fed["sent_transactions_24h"] = sent_transactions_24h;
    fed["received_transactions_24h"] = received_transactions_24h;
    fed["sent_pdus_24h"] = sent_pdus_24h;
    fed["received_pdus_24h"] = received_pdus_24h;
    fed["failures_24h"] = federation_failures_24h;
    fed["known_destinations"] = known_destinations;
    fed["reachable_destinations"] = reachable_destinations;
    j["federation"] = fed;

    json db;
    db["total_size_bytes"] = db_total_size_bytes;
    db["rows_approx"] = db_rows_approx;
    j["database"] = db;

    j["computed_ts"] = computed_ts;
    return j;
  }
};

// ============================================================================
// 1. RoomStatsCollector
//
// Collects and aggregates per-room statistics using full SQL queries.
// Computes membership breakdowns, event type breakdowns, activity windows,
// and growth rates. Supports both full table scans and targeted room queries.
//
// Equivalent to synapse/storage/databases/main/stats.py room portions
// ============================================================================

class RoomStatsCollector {
public:
  explicit RoomStatsCollector(storage::DatabasePool& db)
      : db_(db) {}

  // ---- Full collection of a single room's stats ----

  RoomStatsSnapshot collect_room_stats(const std::string& room_id) {
    RoomStatsSnapshot snap;
    snap.room_id = room_id;
    snap.stats_computed_ts = now_sec();

    db_.runInteraction(
        "stats_collect_room",
        [&](storage::LoggingTransaction& txn) {
          collect_room_metadata(txn, room_id, snap);
          collect_room_membership(txn, room_id, snap);
          collect_room_events(txn, room_id, snap);
          collect_room_activity(txn, room_id, snap);
        });

    return snap;
  }

  // ---- Batch collection of all rooms ----

  json collect_all_room_stats(int64_t batch_size = kRoomBatchSize,
                               int64_t offset = 0, int64_t limit = -1) {
    json result;
    std::vector<json> room_list;
    int64_t total_processed = 0;
    int64_t errors = 0;

    db_.runInteraction(
        "stats_collect_all_rooms",
        [&](storage::LoggingTransaction& txn) {
          txn.execute("SELECT room_id FROM rooms ORDER BY room_id");
          auto rows = txn.fetchall();
          std::vector<std::string> all_rooms;
          for (auto& row : rows) {
            if (row[0].value) all_rooms.push_back(*row[0].value);
          }

          int64_t end_idx = (limit > 0) ? std::min<int64_t>(offset + limit, all_rooms.size())
                                        : static_cast<int64_t>(all_rooms.size());
          for (int64_t i = offset; i < end_idx; i += batch_size) {
            int64_t batch_end = std::min(i + batch_size, end_idx);
            for (int64_t j = i; j < batch_end; j++) {
              try {
                RoomStatsSnapshot snap = collect_room_stats(all_rooms[j]);
                room_list.push_back(snap.to_json());
                total_processed++;
              } catch (const std::exception&) {
                errors++;
              }
            }
          }
        });

    result["rooms"] = room_list;
    result["total_processed"] = total_processed;
    result["errors"] = errors;
    result["offset"] = offset;
    result["limit"] = limit;
    return result;
  }

  // ---- SQL: Room metadata collection ----

  void collect_room_metadata(storage::LoggingTransaction& txn,
                              const std::string& room_id,
                              RoomStatsSnapshot& snap) {
    // Get room version and basic info
    try {
      txn.execute(
          "SELECT room_version, is_public FROM rooms WHERE room_id = ?",
          {room_id});
      auto row = txn.fetchone();
      if (row) {
        snap.room_version = row->at(0).value.value_or("1");
      }
    } catch (...) {}

    // Get current state: name, topic, alias, join_rules, etc.
    try {
      txn.execute(
          "SELECT type, state_key, content FROM current_state_events "
          "WHERE room_id = ? AND type IN ("
          "'m.room.name', 'm.room.topic', 'm.room.canonical_alias', "
          "'m.room.join_rules', 'm.room.history_visibility', "
          "'m.room.guest_access', 'm.room.encryption', 'm.room.create')",
          {room_id});
      auto rows = txn.fetchall();
      for (auto& row : rows) {
        std::string etype = row[0].value.value_or("");
        std::string content_str = row[2].value.value_or("{}");
        try {
          json content = json::parse(content_str);
          if (etype == "m.room.name" && content.contains("name")) {
            snap.room_name = content["name"].get<std::string>();
          } else if (etype == "m.room.topic" && content.contains("topic")) {
            snap.room_topic = content["topic"].get<std::string>();
          } else if (etype == "m.room.canonical_alias" && content.contains("alias")) {
            snap.canonical_alias = content["alias"].get<std::string>();
          } else if (etype == "m.room.join_rules" && content.contains("join_rule")) {
            snap.join_rules = content["join_rule"].get<std::string>();
          } else if (etype == "m.room.history_visibility" && content.contains("history_visibility")) {
            snap.history_visibility = content["history_visibility"].get<std::string>();
          } else if (etype == "m.room.guest_access" && content.contains("guest_access")) {
            snap.guest_access = content["guest_access"].get<std::string>();
          } else if (etype == "m.room.encryption") {
            snap.is_encrypted = true;
          } else if (etype == "m.room.create") {
            if (content.contains("type")) snap.room_type = content["type"].get<std::string>();
            if (content.contains("m.federate")) snap.is_federatable = content["m.federate"].get<bool>();
            else snap.is_federatable = true;
          }
        } catch (...) {}
      }
    } catch (...) {}

    if (snap.room_type.empty()) snap.room_type = "room";
    if (snap.join_rules.empty()) snap.join_rules = "invite";
  }

  // ---- SQL: Membership breakdown ----

  void collect_room_membership(storage::LoggingTransaction& txn,
                                const std::string& room_id,
                                RoomStatsSnapshot& snap) {
    // Count by membership type
    try {
      txn.execute(
          "SELECT membership, COUNT(*) FROM room_memberships "
          "WHERE room_id = ? AND membership IN ('join','invite','leave','ban','knock') "
          "GROUP BY membership",
          {room_id});
      auto rows = txn.fetchall();
      for (auto& row : rows) {
        std::string m = row[0].value.value_or("");
        int64_t cnt = row[1].value ? std::stoll(*row[1].value) : 0;
        if (m == "join") snap.joined_count = cnt;
        else if (m == "invite") snap.invited_count = cnt;
        else if (m == "leave") snap.left_count = cnt;
        else if (m == "ban") snap.banned_count = cnt;
        else if (m == "knock") snap.knock_count = cnt;
      }
    } catch (...) {}

    snap.total_members = snap.joined_count + snap.invited_count +
                         snap.left_count + snap.banned_count + snap.knock_count;

    // Count local vs remote members
    try {
      txn.execute(
          "SELECT COUNT(*) FROM room_memberships rm "
          "JOIN users u ON rm.user_id = u.name "
          "WHERE rm.room_id = ? AND rm.membership = 'join' "
          "AND (u.appservice_id IS NULL OR u.appservice_id = '')",
          {room_id});
      auto row = txn.fetchone();
      snap.local_members = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    snap.remote_members = snap.joined_count - snap.local_members;
    if (snap.remote_members < 0) snap.remote_members = 0;
  }

  // ---- SQL: Event breakdown ----

  void collect_room_events(storage::LoggingTransaction& txn,
                            const std::string& room_id,
                            RoomStatsSnapshot& snap) {
    // Total events by type
    try {
      txn.execute(
          "SELECT COUNT(*) FROM events WHERE room_id = ?",
          {room_id});
      auto row = txn.fetchone();
      snap.total_events = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // State events count
    try {
      txn.execute(
          "SELECT COUNT(*) FROM state_events WHERE room_id = ?",
          {room_id});
      auto row = txn.fetchone();
      snap.state_events = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Messages count
    try {
      txn.execute(
          "SELECT COUNT(*) FROM events WHERE room_id = ? AND type = 'm.room.message'",
          {room_id});
      auto row = txn.fetchone();
      snap.message_events = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Redactions
    try {
      txn.execute(
          "SELECT COUNT(*) FROM events WHERE room_id = ? AND type = 'm.room.redaction'",
          {room_id});
      auto row = txn.fetchone();
      snap.redaction_events = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Reactions
    try {
      txn.execute(
          "SELECT COUNT(*) FROM events WHERE room_id = ? AND type = 'm.reaction'",
          {room_id});
      auto row = txn.fetchone();
      snap.reaction_events = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Events in last 24h
    int64_t cutoff_24h = hours_ago_sec(24);
    try {
      txn.execute(
          "SELECT COUNT(*) FROM events WHERE room_id = ? AND origin_server_ts >= ?",
          {room_id, std::to_string(cutoff_24h)});
      auto row = txn.fetchone();
      snap.events_24h = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Events in last 7d
    int64_t cutoff_7d = days_ago_sec(7);
    try {
      txn.execute(
          "SELECT COUNT(*) FROM events WHERE room_id = ? AND origin_server_ts >= ?",
          {room_id, std::to_string(cutoff_7d)});
      auto row = txn.fetchone();
      snap.events_7d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Events in last 30d
    int64_t cutoff_30d = days_ago_sec(30);
    try {
      txn.execute(
          "SELECT COUNT(*) FROM events WHERE room_id = ? AND origin_server_ts >= ?",
          {room_id, std::to_string(cutoff_30d)});
      auto row = txn.fetchone();
      snap.events_30d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}
  }

  // ---- SQL: Activity and growth metrics ----

  void collect_room_activity(storage::LoggingTransaction& txn,
                              const std::string& room_id,
                              RoomStatsSnapshot& snap) {
    // Creation time from m.room.create event
    try {
      txn.execute(
          "SELECT origin_server_ts FROM events "
          "WHERE room_id = ? AND type = 'm.room.create' AND state_key = '' "
          "ORDER BY origin_server_ts ASC LIMIT 1",
          {room_id});
      auto row = txn.fetchone();
      snap.creation_ts = (row && row[0].value) ? std::stoll(*row[0].value) : 0;
    } catch (...) {}

    // Last activity
    try {
      txn.execute(
          "SELECT MAX(origin_server_ts) FROM events WHERE room_id = ?",
          {room_id});
      auto row = txn.fetchone();
      snap.last_activity_ts = (row && row[0].value) ? std::stoll(*row[0].value) : 0;
    } catch (...) {}

    // Last message
    try {
      txn.execute(
          "SELECT MAX(origin_server_ts) FROM events "
          "WHERE room_id = ? AND type = 'm.room.message'",
          {room_id});
      auto row = txn.fetchone();
      snap.last_message_ts = (row && row[0].value) ? std::stoll(*row[0].value) : 0;
    } catch (...) {}

    // Forward extremities
    try {
      txn.execute(
          "SELECT COUNT(*) FROM event_forward_extremities WHERE room_id = ?",
          {room_id});
      auto row = txn.fetchone();
      snap.forward_extremities = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Backward extremities
    try {
      txn.execute(
          "SELECT COUNT(*) FROM event_backward_extremities WHERE room_id = ?",
          {room_id});
      auto row = txn.fetchone();
      snap.backward_extremities = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Growth rate: avg new join events per day over last 7 days
    int64_t cutoff_7d = days_ago_sec(7);
    try {
      txn.execute(
          "SELECT COUNT(*) FROM room_memberships "
          "WHERE room_id = ? AND membership = 'join' AND event_stream_ordering > "
          "(SELECT COALESCE(MIN(stream_ordering), 0) FROM events "
          "WHERE room_id = ? AND origin_server_ts >= ?)",
          {room_id, room_id, std::to_string(cutoff_7d)});
      auto row = txn.fetchone();
      int64_t joins_7d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
      snap.growth_rate_7d = joins_7d / 7.0;
    } catch (...) { snap.growth_rate_7d = 0.0; }

    // Growth rate over 30 days
    int64_t cutoff_30d = days_ago_sec(30);
    try {
      txn.execute(
          "SELECT COUNT(*) FROM room_memberships "
          "WHERE room_id = ? AND membership = 'join' AND event_stream_ordering > "
          "(SELECT COALESCE(MIN(stream_ordering), 0) FROM events "
          "WHERE room_id = ? AND origin_server_ts >= ?)",
          {room_id, room_id, std::to_string(cutoff_30d)});
      auto row = txn.fetchone();
      int64_t joins_30d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
      snap.growth_rate_30d = joins_30d / 30.0;
    } catch (...) { snap.growth_rate_30d = 0.0; }
  }

  // ---- Top rooms by activity ----

  json get_top_rooms_by_events(int64_t limit = 50) {
    return db_.runInteraction(
        "stats_top_rooms_events",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          txn.execute(
              "SELECT room_id, COUNT(*) as event_count "
              "FROM events "
              "WHERE origin_server_ts >= ? "
              "GROUP BY room_id ORDER BY event_count DESC LIMIT ?",
              {std::to_string(days_ago_sec(30)), std::to_string(limit)});
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            json r;
            r["room_id"] = row[0].value.value_or("");
            r["event_count"] = row[1].value ? std::stoll(*row[1].value) : 0;
            result.push_back(r);
          }
          return result;
        });
  }

  json get_top_rooms_by_members(int64_t limit = 50) {
    return db_.runInteraction(
        "stats_top_rooms_members",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          txn.execute(
              "SELECT room_id, COUNT(*) as member_count "
              "FROM room_memberships WHERE membership = 'join' "
              "GROUP BY room_id ORDER BY member_count DESC LIMIT ?",
              {std::to_string(limit)});
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            json r;
            r["room_id"] = row[0].value.value_or("");
            r["member_count"] = row[1].value ? std::stoll(*row[1].value) : 0;
            result.push_back(r);
          }
          return result;
        });
  }

  // ---- Room stats time series (event volume over time) ----

  json get_room_event_timeline(const std::string& room_id,
                                const std::string& bucket = "daily",
                                int64_t days = 30) {
    return db_.runInteraction(
        "stats_room_timeline",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          int64_t from_ts = days_ago_sec(days);
          std::string date_func;
          if (bucket == "hourly") date_func = "strftime('%Y-%m-%dT%H:00:00', datetime(origin_server_ts, 'unixepoch'))";
          else if (bucket == "weekly") date_func = "strftime('%Y-%W', datetime(origin_server_ts, 'unixepoch'))";
          else if (bucket == "monthly") date_func = "strftime('%Y-%m', datetime(origin_server_ts, 'unixepoch'))";
          else date_func = "strftime('%Y-%m-%d', datetime(origin_server_ts, 'unixepoch'))";

          std::string query =
              "SELECT " + date_func + " as bucket, COUNT(*) as cnt "
              "FROM events WHERE room_id = ? AND origin_server_ts >= ? "
              "GROUP BY bucket ORDER BY bucket ASC";

          txn.execute(query, {room_id, std::to_string(from_ts)});
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            json point;
            point["bucket"] = row[0].value.value_or("");
            point["count"] = row[1].value ? std::stoll(*row[1].value) : 0;
            result.push_back(point);
          }
          return result;
        });
  }

  // ---- Room list with pagination and filtering ----

  json list_rooms_with_stats(const std::string& order_by = "total_events",
                              const std::string& direction = "DESC",
                              int64_t limit = 100, int64_t offset = 0,
                              const std::string& search = "") {
    return db_.runInteraction(
        "stats_list_rooms",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;
          std::string where_clause;
          std::vector<std::string> params;

          if (!search.empty()) {
            where_clause = "WHERE (r.room_id LIKE ? OR rss.room_name LIKE ?) ";
            params.push_back("%" + search + "%");
            params.push_back("%" + search + "%");
          }

          std::string count_sql =
              "SELECT COUNT(*) FROM rooms r "
              "LEFT JOIN room_stats_state rss ON r.room_id = rss.room_id " +
              where_clause;

          txn.execute(count_sql, params);
          auto crow = txn.fetchone();
          int64_t total = crow ? std::stoll(crow->at(0).value.value_or("0")) : 0;
          result["total"] = total;
          result["offset"] = offset;
          result["limit"] = limit;

          std::string valid_order;
          if (order_by == "total_events") valid_order = "COALESCE(rss.total_events,0)";
          else if (order_by == "joined_members") valid_order = "COALESCE(rss.joined_members,0)";
          else if (order_by == "last_activity") valid_order = "COALESCE(rss.last_activity_ts,0)";
          else if (order_by == "creation_ts") valid_order = "COALESCE(rss.creation_ts,0)";
          else valid_order = "r.room_id";

          std::string sql =
              "SELECT r.room_id, rss.room_name, rss.joined_members, rss.total_events, "
              "rss.last_activity_ts, rss.is_encrypted, rss.join_rules "
              "FROM rooms r "
              "LEFT JOIN room_stats_state rss ON r.room_id = rss.room_id " +
              where_clause +
              "ORDER BY " + valid_order + " " + direction + " "
              "LIMIT ? OFFSET ?";

          params.push_back(std::to_string(limit));
          params.push_back(std::to_string(offset));

          txn.execute(sql, params);
          auto rows = txn.fetchall();
          json rooms = json::array();
          for (auto& row : rows) {
            json r;
            r["room_id"] = row[0].value.value_or("");
            r["room_name"] = row[1].value.value_or("");
            r["joined_members"] = row[2].value ? std::stoll(*row[2].value) : 0;
            r["total_events"] = row[3].value ? std::stoll(*row[3].value) : 0;
            r["last_activity_ts"] = row[4].value ? std::stoll(*row[4].value) : 0;
            r["is_encrypted"] = row[5].value ? (*row[5].value == "1") : false;
            r["join_rules"] = row[6].value.value_or("");
            rooms.push_back(r);
          }
          result["rooms"] = rooms;
          return result;
        });
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 2. UserActivityTracker
//
// Tracks user activity metrics: DAU/MAU, registration timeline, user
// cohort analysis, retention curves, engagement scoring, and top users.
//
// Equivalent to synapse/storage/databases/main/stats.py user portions
// ============================================================================

class UserActivityTracker {
public:
  explicit UserActivityTracker(storage::DatabasePool& db)
      : db_(db) {}

  // ---- Collect single user stats ----

  UserStatsData collect_user_stats(const std::string& user_id) {
    UserStatsData data;
    data.user_id = user_id;
    data.stats_computed_ts = now_sec();

    db_.runInteraction(
        "stats_collect_user",
        [&](storage::LoggingTransaction& txn) {
          collect_user_profile(txn, user_id, data);
          collect_user_activity(txn, user_id, data);
          collect_user_engagement(txn, user_id, data);
          collect_user_media(txn, user_id, data);
        });

    return data;
  }

  // ---- User profile from database ----

  void collect_user_profile(storage::LoggingTransaction& txn,
                             const std::string& user_id,
                             UserStatsData& data) {
    try {
      txn.execute(
          "SELECT display_name, avatar_url, is_guest, deactivated, "
          "admin, appservice_id, creation_ts "
          "FROM users WHERE name = ?",
          {user_id});
      auto row = txn.fetchone();
      if (row) {
        data.display_name = row->at(0).value.value_or("");
        data.avatar_url = row->at(1).value.value_or("");
        data.is_guest = row->at(2).value ? (*row->at(2).value == "1") : false;
        data.is_deactivated = row->at(3).value ? (*row->at(3).value == "1") : false;
        data.is_admin = row->at(4).value ? (*row->at(4).value == "1") : false;
        data.is_appservice = row->at(5).value && !row->at(5).value->empty();
        data.creation_ts = row->at(6).value ? std::stoll(*row->at(6).value) : 0;
        data.creation_date = iso_date(data.creation_ts);
      }
    } catch (...) {}

    try {
      txn.execute(
          "SELECT COUNT(*) FROM devices WHERE user_id = ?",
          {user_id});
      auto row = txn.fetchone();
      data.devices_count = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}
  }

  // ---- User activity (DAU/MAU basis) ----

  void collect_user_activity(storage::LoggingTransaction& txn,
                              const std::string& user_id,
                              UserStatsData& data) {
    // Last seen from user_daily_visits
    try {
      txn.execute(
          "SELECT MAX(last_visit_ts) FROM user_daily_visits WHERE user_id = ?",
          {user_id});
      auto row = txn.fetchone();
      data.last_seen_ts = (row && row[0].value) ? std::stoll(*row[0].value) : 0;
    } catch (...) {}

    // Last daily visit date
    try {
      txn.execute(
          "SELECT MAX(visit_date) FROM user_daily_visits WHERE user_id = ?",
          {user_id});
      auto row = txn.fetchone();
      if (row && row[0].value) {
        data.last_daily_visit_ts = now_sec(); // approximate
      }
    } catch (...) {}

    // Active today
    std::string today = iso_date(now_sec());
    try {
      txn.execute(
          "SELECT COUNT(*) FROM user_daily_visits "
          "WHERE user_id = ? AND visit_date = ?",
          {user_id, today});
      auto row = txn.fetchone();
      data.active_today = row && row[0].value && *row[0].value != "0";
    } catch (...) {}

    // Active this week (past 7 days)
    std::string week_ago = iso_date(days_ago_sec(7));
    try {
      txn.execute(
          "SELECT COUNT(DISTINCT visit_date) FROM user_daily_visits "
          "WHERE user_id = ? AND visit_date >= ?",
          {user_id, week_ago});
      auto row = txn.fetchone();
      int64_t days = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
      data.active_this_week = days > 0;
      data.days_active_last_30 = days; // approximate, proper query below
    } catch (...) {}

    // Active this month
    std::string month_ago = iso_date(days_ago_sec(30));
    try {
      txn.execute(
          "SELECT COUNT(DISTINCT visit_date) FROM user_daily_visits "
          "WHERE user_id = ? AND visit_date >= ?",
          {user_id, month_ago});
      auto row = txn.fetchone();
      int64_t days = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
      data.active_this_month = days > 0;
      data.days_active_last_30 = days;
    } catch (...) {}

    // Days active last 90
    std::string d90_ago = iso_date(days_ago_sec(90));
    try {
      txn.execute(
          "SELECT COUNT(DISTINCT visit_date) FROM user_daily_visits "
          "WHERE user_id = ? AND visit_date >= ?",
          {user_id, d90_ago});
      auto row = txn.fetchone();
      data.days_active_last_90 = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}
  }

  // ---- User engagement metrics ----

  void collect_user_engagement(storage::LoggingTransaction& txn,
                                const std::string& user_id,
                                UserStatsData& data) {
    // Joined rooms
    try {
      txn.execute(
          "SELECT COUNT(*) FROM room_memberships "
          "WHERE user_id = ? AND membership = 'join'",
          {user_id});
      auto row = txn.fetchone();
      data.joined_rooms = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Total messages sent
    try {
      txn.execute(
          "SELECT COUNT(*) FROM events "
          "WHERE sender = ? AND type = 'm.room.message'",
          {user_id});
      auto row = txn.fetchone();
      data.total_messages_sent = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Messages sent last 30d
    try {
      txn.execute(
          "SELECT COUNT(*) FROM events "
          "WHERE sender = ? AND type = 'm.room.message' AND origin_server_ts >= ?",
          {user_id, std::to_string(days_ago_sec(30))});
      auto row = txn.fetchone();
      data.messages_sent_30d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Total reactions
    try {
      txn.execute(
          "SELECT COUNT(*) FROM events "
          "WHERE sender = ? AND type = 'm.reaction'",
          {user_id});
      auto row = txn.fetchone();
      data.total_reactions = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Total redactions
    try {
      txn.execute(
          "SELECT COUNT(*) FROM events "
          "WHERE sender = ? AND type = 'm.room.redaction'",
          {user_id});
      auto row = txn.fetchone();
      data.total_redactions = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}
  }

  // ---- User media stats ----

  void collect_user_media(storage::LoggingTransaction& txn,
                           const std::string& user_id,
                           UserStatsData& data) {
    try {
      txn.execute(
          "SELECT SUM(media_length), COUNT(*) FROM local_media_repository "
          "WHERE user_id = ?",
          {user_id});
      auto row = txn.fetchone();
      data.media_uploaded_bytes = (row && row[0].value) ? std::stoll(*row[0].value) : 0;
      data.media_uploaded_count = (row && row[1].value) ? std::stoll(*row[1].value) : 0;
    } catch (...) {}

    try {
      txn.execute(
          "SELECT SUM(media_length), COUNT(*) FROM remote_media_cache "
          "WHERE user_id = ?",
          {user_id});
      auto row = txn.fetchone();
      data.media_downloaded_bytes = (row && row[0].value) ? std::stoll(*row[0].value) : 0;
      data.media_downloaded_count = (row && row[1].value) ? std::stoll(*row[1].value) : 0;
    } catch (...) {}
  }

  // ---- DAU computation with SQL ----

  int64_t compute_daily_active_users() {
    std::string today = iso_date(now_sec());
    return db_.runInteraction(
        "stats_dau",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          txn.execute(
              "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
              "WHERE visit_date = ?",
              {today});
          auto row = txn.fetchone();
          return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
        });
  }

  // ---- MAU computation with SQL ----

  int64_t compute_monthly_active_users() {
    std::string month_ago = iso_date(days_ago_sec(30));
    return db_.runInteraction(
        "stats_mau",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          txn.execute(
              "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
              "WHERE visit_date >= ?",
              {month_ago});
          auto row = txn.fetchone();
          return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
        });
  }

  // ---- Weekly Active Users ----

  int64_t compute_weekly_active_users() {
    std::string week_ago = iso_date(days_ago_sec(7));
    return db_.runInteraction(
        "stats_wau",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          txn.execute(
              "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
              "WHERE visit_date >= ?",
              {week_ago});
          auto row = txn.fetchone();
          return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
        });
  }

  // ---- DAU/MAU time series ----

  json get_dau_time_series(int64_t days = 90) {
    return db_.runInteraction(
        "stats_dau_series",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          std::string from_date = iso_date(days_ago_sec(days));
          txn.execute(
              "SELECT visit_date, COUNT(DISTINCT user_id) as dau "
              "FROM user_daily_visits "
              "WHERE visit_date >= ? "
              "GROUP BY visit_date ORDER BY visit_date ASC",
              {from_date});
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            json point;
            point["date"] = row[0].value.value_or("");
            point["dau"] = row[1].value ? std::stoll(*row[1].value) : 0;
            result.push_back(point);
          }
          return result;
        });
  }

  // ---- Registration timeline ----

  json get_registration_timeline(const std::string& bucket = "daily",
                                  int64_t days = 365) {
    return db_.runInteraction(
        "stats_reg_timeline",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          std::string date_func;
          if (bucket == "monthly") {
            date_func = "strftime('%Y-%m', datetime(creation_ts, 'unixepoch'))";
          } else if (bucket == "weekly") {
            date_func = "strftime('%Y-%W', datetime(creation_ts, 'unixepoch'))";
          } else {
            date_func = "strftime('%Y-%m-%d', datetime(creation_ts, 'unixepoch'))";
          }

          int64_t from_ts = days_ago_sec(days);
          std::string query =
              "SELECT " + date_func + " as bucket, COUNT(*) as cnt "
              "FROM users "
              "WHERE creation_ts >= ? AND deactivated = 0 "
              "GROUP BY bucket ORDER BY bucket ASC";

          txn.execute(query, {std::to_string(from_ts)});
          auto rows = txn.fetchall();
          int64_t cumulative = 0;
          for (auto& row : rows) {
            json point;
            point["bucket"] = row[0].value.value_or("");
            int64_t cnt = row[1].value ? std::stoll(*row[1].value) : 0;
            cumulative += cnt;
            point["new_users"] = cnt;
            point["cumulative"] = cumulative;
            result.push_back(point);
          }
          return result;
        });
  }

  // ---- User cohort analysis ----

  json get_cohort_analysis(const std::string& cohort_period = "monthly",
                            int64_t lookback = 12) {
    return db_.runInteraction(
        "stats_cohort",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          // Cohort: users who registered in a given month
          // Retention: active in subsequent months
          std::string date_func = "strftime('%Y-%m', datetime(creation_ts, 'unixepoch'))";

          for (int64_t i = lookback; i >= 0; i--) {
            int64_t cohort_start = days_ago_sec((i + 1) * 30);
            int64_t cohort_end = days_ago_sec(i * 30);
            std::string cohort_label = iso_month_str(cohort_start);

            // Count users in this cohort
            txn.execute(
                "SELECT COUNT(*) FROM users "
                "WHERE creation_ts >= ? AND creation_ts < ? AND deactivated = 0",
                {std::to_string(cohort_start), std::to_string(cohort_end)});
            auto row = txn.fetchone();
            int64_t cohort_size = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            if (cohort_size == 0) continue;

            json cohort;
            cohort["cohort"] = cohort_label;
            cohort["size"] = cohort_size;
            json retention = json::array();

            // Check retention for subsequent months
            for (int64_t m = 0; m < lookback - i && m < 12; m++) {
              int64_t month_start = cohort_end + m * 2592000;
              int64_t month_end = month_start + 2592000;
              txn.execute(
                  "SELECT COUNT(DISTINCT u.name) FROM users u "
                  "JOIN user_daily_visits udv ON u.name = udv.user_id "
                  "WHERE u.creation_ts >= ? AND u.creation_ts < ? "
                  "AND udv.visit_date >= ? AND udv.visit_date < ?",
                  {std::to_string(cohort_start), std::to_string(cohort_end),
                   iso_date(month_start), iso_date(month_end)});
              row = txn.fetchone();
              int64_t retained = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
              json r;
              r["month"] = m + 1;
              r["retained"] = retained;
              r["pct"] = cohort_size > 0
                  ? std::round(10000.0 * retained / cohort_size) / 100.0 : 0.0;
              retention.push_back(r);
            }
            cohort["retention"] = retention;
            result.push_back(cohort);
          }
          return result;
        });
  }

  // ---- Top users by activity ----

  json get_top_users_by_messages(int64_t limit = 100, int64_t days = 30) {
    return db_.runInteraction(
        "stats_top_users",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          int64_t cutoff = days_ago_sec(days);
          txn.execute(
              "SELECT sender, COUNT(*) as msg_count "
              "FROM events "
              "WHERE type = 'm.room.message' AND origin_server_ts >= ? "
              "GROUP BY sender ORDER BY msg_count DESC LIMIT ?",
              {std::to_string(cutoff), std::to_string(limit)});
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            json r;
            r["user_id"] = row[0].value.value_or("");
            r["message_count"] = row[1].value ? std::stoll(*row[1].value) : 0;
            result.push_back(r);
          }
          return result;
        });
  }

  json get_top_users_by_media(int64_t limit = 100) {
    return db_.runInteraction(
        "stats_top_users_media",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          txn.execute(
              "SELECT user_id, SUM(media_length) as total_bytes, COUNT(*) as media_count "
              "FROM local_media_repository "
              "GROUP BY user_id ORDER BY total_bytes DESC LIMIT ?",
              {std::to_string(limit)});
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            json r;
            r["user_id"] = row[0].value.value_or("");
            r["total_bytes"] = row[1].value ? std::stoll(*row[1].value) : 0;
            r["media_count"] = row[2].value ? std::stoll(*row[2].value) : 0;
            result.push_back(r);
          }
          return result;
        });
  }

  // ---- User search ----

  json search_users(const std::string& term, int64_t limit = 50) {
    return db_.runInteraction(
        "stats_search_users",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          txn.execute(
              "SELECT name, display_name, creation_ts FROM users "
              "WHERE (name LIKE ? OR display_name LIKE ?) AND deactivated = 0 "
              "ORDER BY name LIMIT ?",
              {"%" + term + "%", "%" + term + "%", std::to_string(limit)});
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            json r;
            r["user_id"] = row[0].value.value_or("");
            r["display_name"] = row[1].value.value_or("");
            r["creation_ts"] = row[2].value ? std::stoll(*row[2].value) : 0;
            result.push_back(r);
          }
          return result;
        });
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 3. ServerStatsAggregator
//
// Aggregates server-wide statistics: total user/room/event/media counts,
// federation statistics, database sizing, and time-windowed breakdowns.
//
// Equivalent to synapse/storage/databases/main/stats.py server portions
// and synapse/app/homeserver.py statistics reporting
// ============================================================================

class ServerStatsAggregator {
public:
  explicit ServerStatsAggregator(storage::DatabasePool& db)
      : db_(db) {}

  // ---- Full server stats snapshot ----

  ServerStatsData compute_server_stats() {
    ServerStatsData snap;
    snap.computed_ts = now_sec();

    db_.runInteraction(
        "stats_server_snapshot",
        [&](storage::LoggingTransaction& txn) {
          compute_user_counts(txn, snap);
          compute_room_counts(txn, snap);
          compute_event_counts(txn, snap);
          compute_media_counts(txn, snap);
          compute_federation_counts(txn, snap);
          compute_db_stats(txn, snap);
        });

    return snap;
  }

  // ---- User counts ----

  void compute_user_counts(storage::LoggingTransaction& txn,
                            ServerStatsData& snap) {
    try {
      txn.execute("SELECT COUNT(*) FROM users WHERE deactivated = 0");
      auto row = txn.fetchone();
      snap.total_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute(
          "SELECT COUNT(*) FROM users "
          "WHERE is_guest = 0 AND deactivated = 0 "
          "AND (appservice_id IS NULL OR appservice_id = '')");
      auto row = txn.fetchone();
      snap.real_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute("SELECT COUNT(*) FROM users WHERE is_guest = 1 AND deactivated = 0");
      auto row = txn.fetchone();
      snap.guest_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute("SELECT COUNT(*) FROM users WHERE deactivated = 1");
      auto row = txn.fetchone();
      snap.deactivated_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute(
          "SELECT COUNT(*) FROM users "
          "WHERE appservice_id IS NOT NULL AND appservice_id != '' AND deactivated = 0");
      auto row = txn.fetchone();
      snap.appservice_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute("SELECT COUNT(*) FROM users WHERE admin = 1 AND deactivated = 0");
      auto row = txn.fetchone();
      snap.admin_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Users created in time windows
    int64_t cutoff_24h = hours_ago_sec(24);
    int64_t cutoff_7d = days_ago_sec(7);
    int64_t cutoff_30d = days_ago_sec(30);

    try {
      txn.execute("SELECT COUNT(*) FROM users WHERE creation_ts >= ?",
                  {std::to_string(cutoff_24h)});
      auto row = txn.fetchone();
      snap.users_created_24h = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute("SELECT COUNT(*) FROM users WHERE creation_ts >= ?",
                  {std::to_string(cutoff_7d)});
      auto row = txn.fetchone();
      snap.users_created_7d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute("SELECT COUNT(*) FROM users WHERE creation_ts >= ?",
                  {std::to_string(cutoff_30d)});
      auto row = txn.fetchone();
      snap.users_created_30d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Recently deactivated
    try {
      txn.execute(
          "SELECT COUNT(*) FROM users WHERE deactivated = 1 AND creation_ts >= ?",
          {std::to_string(cutoff_24h)});
      auto row = txn.fetchone();
      snap.users_deactivated_24h = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}
  }

  // ---- Room counts ----

  void compute_room_counts(storage::LoggingTransaction& txn,
                            ServerStatsData& snap) {
    try {
      txn.execute("SELECT COUNT(*) FROM rooms");
      auto row = txn.fetchone();
      snap.total_rooms = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Public vs private
    int64_t cutoff_24h = hours_ago_sec(24);
    int64_t cutoff_7d = days_ago_sec(7);

    try {
      txn.execute(
          "SELECT COUNT(DISTINCT r.room_id) FROM rooms r "
          "JOIN current_state_events cse ON r.room_id = cse.room_id "
          "WHERE cse.type = 'm.room.join_rules' "
          "AND json_extract(cse.content, '$.join_rule') = 'public'");
      auto row = txn.fetchone();
      snap.public_rooms = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    snap.private_rooms = snap.total_rooms - snap.public_rooms;
    if (snap.private_rooms < 0) snap.private_rooms = 0;

    // Encrypted rooms
    try {
      txn.execute(
          "SELECT COUNT(DISTINCT r.room_id) FROM rooms r "
          "JOIN current_state_events cse ON r.room_id = cse.room_id "
          "WHERE cse.type = 'm.room.encryption'");
      auto row = txn.fetchone();
      snap.encrypted_rooms = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Space rooms
    try {
      txn.execute(
          "SELECT COUNT(DISTINCT r.room_id) FROM rooms r "
          "JOIN current_state_events cse ON r.room_id = cse.room_id "
          "WHERE cse.type = 'm.room.create' "
          "AND json_extract(cse.content, '$.type') = 'm.space'");
      auto row = txn.fetchone();
      snap.space_rooms = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Rooms created recently
    try {
      txn.execute("SELECT COUNT(*) FROM rooms WHERE creation_ts >= ?",
                  {std::to_string(cutoff_24h)});
      auto row = txn.fetchone();
      snap.rooms_created_24h = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute("SELECT COUNT(*) FROM rooms WHERE creation_ts >= ?",
                  {std::to_string(cutoff_7d)});
      auto row = txn.fetchone();
      snap.rooms_created_7d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Active rooms (had events in time window)
    try {
      txn.execute(
          "SELECT COUNT(DISTINCT room_id) FROM events "
          "WHERE origin_server_ts >= ?", {std::to_string(cutoff_24h)});
      auto row = txn.fetchone();
      snap.rooms_active_24h = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute(
          "SELECT COUNT(DISTINCT room_id) FROM events "
          "WHERE origin_server_ts >= ?", {std::to_string(cutoff_7d)});
      auto row = txn.fetchone();
      snap.rooms_active_7d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute(
          "SELECT COUNT(DISTINCT room_id) FROM events "
          "WHERE origin_server_ts >= ?", {std::to_string(days_ago_sec(30))});
      auto row = txn.fetchone();
      snap.rooms_active_30d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}
  }

  // ---- Event counts ----

  void compute_event_counts(storage::LoggingTransaction& txn,
                             ServerStatsData& snap) {
    try {
      txn.execute("SELECT COUNT(*) FROM events");
      auto row = txn.fetchone();
      snap.total_events = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute("SELECT COUNT(*) FROM state_events");
      auto row = txn.fetchone();
      snap.total_state_events = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute("SELECT COUNT(*) FROM events WHERE type = 'm.room.message'");
      auto row = txn.fetchone();
      snap.total_messages = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute("SELECT COUNT(*) FROM events WHERE type = 'm.reaction'");
      auto row = txn.fetchone();
      snap.total_reactions = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute("SELECT COUNT(*) FROM events WHERE type = 'm.room.redaction'");
      auto row = txn.fetchone();
      snap.total_redactions = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Time-windowed event counts
    int64_t cutoff_24h = hours_ago_sec(24);
    int64_t cutoff_7d = days_ago_sec(7);
    int64_t cutoff_30d = days_ago_sec(30);

    try {
      txn.execute("SELECT COUNT(*) FROM events WHERE origin_server_ts >= ?",
                  {std::to_string(cutoff_24h)});
      auto row = txn.fetchone();
      snap.events_24h = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute("SELECT COUNT(*) FROM events WHERE origin_server_ts >= ?",
                  {std::to_string(cutoff_7d)});
      auto row = txn.fetchone();
      snap.events_7d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute("SELECT COUNT(*) FROM events WHERE origin_server_ts >= ?",
                  {std::to_string(cutoff_30d)});
      auto row = txn.fetchone();
      snap.events_30d = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    // Compute derived metrics
    snap.events_per_second_peak = snap.events_24h > 0
        ? static_cast<double>(snap.events_24h) / 86400.0 : 0.0;
    snap.events_per_minute_avg = snap.events_7d > 0
        ? static_cast<double>(snap.events_7d) / (7.0 * 1440.0) : 0.0;
  }

  // ---- Media counts ----

  void compute_media_counts(storage::LoggingTransaction& txn,
                             ServerStatsData& snap) {
    try {
      txn.execute(
          "SELECT COALESCE(SUM(media_length), 0), COUNT(*) FROM local_media_repository");
      auto row = txn.fetchone();
      snap.total_local_media_bytes = (row && row[0].value) ? std::stoll(*row[0].value) : 0;
      snap.local_media_count = (row && row[1].value) ? std::stoll(*row[1].value) : 0;
    } catch (...) {}

    try {
      txn.execute(
          "SELECT COALESCE(SUM(media_length), 0), COUNT(*) FROM remote_media_cache");
      auto row = txn.fetchone();
      snap.total_remote_media_bytes = (row && row[0].value) ? std::stoll(*row[0].value) : 0;
      snap.remote_media_count = (row && row[1].value) ? std::stoll(*row[1].value) : 0;
    } catch (...) {}

    snap.total_media_count = snap.local_media_count + snap.remote_media_count;

    // 24h media activity
    int64_t cutoff_24h = hours_ago_sec(24);
    try {
      txn.execute(
          "SELECT COALESCE(SUM(media_length), 0), COUNT(*) FROM local_media_repository "
          "WHERE created_ts >= ?", {std::to_string(cutoff_24h)});
      auto row = txn.fetchone();
      snap.media_uploaded_bytes_24h = (row && row[0].value) ? std::stoll(*row[0].value) : 0;
      snap.media_uploaded_24h = (row && row[1].value) ? std::stoll(*row[1].value) : 0;
    } catch (...) {}

    try {
      txn.execute(
          "SELECT COALESCE(SUM(media_length), 0), COUNT(*) FROM remote_media_cache "
          "WHERE created_ts >= ?", {std::to_string(cutoff_24h)});
      auto row = txn.fetchone();
      snap.media_downloaded_bytes_24h = (row && row[0].value) ? std::stoll(*row[0].value) : 0;
      snap.media_downloaded_24h = (row && row[1].value) ? std::stoll(*row[1].value) : 0;
    } catch (...) {}
  }

  // ---- Federation statistics ----

  void compute_federation_counts(storage::LoggingTransaction& txn,
                                  ServerStatsData& snap) {
    int64_t cutoff_24h = hours_ago_sec(24);

    try {
      txn.execute(
          "SELECT COUNT(*) FROM federation_stream_position WHERE type = 'sent' "
          "AND stream_id > (SELECT COALESCE(MAX(stream_ordering), 0) FROM events "
          "WHERE origin_server_ts >= ?)", {std::to_string(cutoff_24h)});
      auto row = txn.fetchone();
      snap.sent_pdus_24h = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) { snap.sent_pdus_24h = 0; }

    try {
      txn.execute(
          "SELECT COUNT(*) FROM events WHERE origin_server_ts >= ? "
          "AND sender NOT LIKE '%' || (SELECT server_name FROM server_keys LIMIT 1) || '%'",
          {std::to_string(cutoff_24h)});
      auto row = txn.fetchone();
      snap.received_pdus_24h = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) { snap.received_pdus_24h = 0; }

    try {
      txn.execute("SELECT COUNT(*) FROM destinations");
      auto row = txn.fetchone();
      snap.known_destinations = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}

    try {
      txn.execute("SELECT COUNT(*) FROM destinations WHERE reachable = 1");
      auto row = txn.fetchone();
      snap.reachable_destinations = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}
  }

  // ---- Database sizing (approximate) ----

  void compute_db_stats(storage::LoggingTransaction& txn,
                         ServerStatsData& snap) {
    // Approximate row count from major tables
    try {
      txn.execute(
          "SELECT SUM(cnt) FROM ("
          "  SELECT COUNT(*) as cnt FROM events UNION ALL "
          "  SELECT COUNT(*) FROM state_events UNION ALL "
          "  SELECT COUNT(*) FROM room_memberships UNION ALL "
          "  SELECT COUNT(*) FROM current_state_events UNION ALL "
          "  SELECT COUNT(*) FROM users UNION ALL "
          "  SELECT COUNT(*) FROM devices UNION ALL "
          "  SELECT COUNT(*) FROM local_media_repository UNION ALL "
          "  SELECT COUNT(*) FROM remote_media_cache"
          ")");
      auto row = txn.fetchone();
      snap.db_rows_approx = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
    } catch (...) {}
  }

  // ---- Event throughput time series ----

  json get_event_throughput_series(const std::string& bucket = "hourly",
                                    int64_t hours = 24) {
    return db_.runInteraction(
        "stats_event_throughput",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          std::string date_func;
          if (bucket == "daily") date_func = "strftime('%Y-%m-%d', datetime(origin_server_ts, 'unixepoch'))";
          else date_func = "strftime('%Y-%m-%dT%H:00:00', datetime(origin_server_ts, 'unixepoch'))";

          int64_t from_ts = hours_ago_sec(hours);
          std::string query =
              "SELECT " + date_func + " as bucket, type, COUNT(*) as cnt "
              "FROM events WHERE origin_server_ts >= ? "
              "GROUP BY bucket, type ORDER BY bucket ASC, type";

          txn.execute(query, {std::to_string(from_ts)});
          auto rows = txn.fetchall();

          // Pivot into structured output
          std::map<std::string, json> by_bucket;
          for (auto& row : rows) {
            std::string bucket_val = row[0].value.value_or("");
            std::string etype = row[1].value.value_or("");
            int64_t cnt = row[2].value ? std::stoll(*row[2].value) : 0;

            if (!by_bucket.count(bucket_val)) {
              by_bucket[bucket_val] = json::object();
              by_bucket[bucket_val]["bucket"] = bucket_val;
              by_bucket[bucket_val]["total"] = 0;
              by_bucket[bucket_val]["by_type"] = json::object();
            }
            by_bucket[bucket_val]["total"] = by_bucket[bucket_val]["total"].get<int64_t>() + cnt;
            by_bucket[bucket_val]["by_type"][etype] = cnt;
          }

          for (auto& [k, v] : by_bucket) {
            result.push_back(v);
          }
          return result;
        });
  }

  // ---- Federation stats time series ----

  json get_federation_stats() {
    return db_.runInteraction(
        "stats_federation",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;
          txn.execute("SELECT COUNT(*), SUM(retry_interval), AVG(failure_count) FROM destinations");
          auto row = txn.fetchone();
          if (row) {
            result["total_destinations"] = row[0].value ? std::stoll(*row[0].value) : 0;
            result["total_retry_ms"] = row[1].value ? std::stoll(*row[1].value) : 0;
            result["avg_failures"] = row[2].value ? std::stod(*row[2].value) : 0.0;
          }
          return result;
        });
  }

  // ---- Media type breakdown ----

  json get_media_type_breakdown() {
    return db_.runInteraction(
        "stats_media_types",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;
          txn.execute(
              "SELECT media_type, COUNT(*), SUM(media_length) "
              "FROM local_media_repository "
              "GROUP BY media_type ORDER BY SUM(media_length) DESC");
          auto rows = txn.fetchall();
          json breakdown = json::array();
          for (auto& row : rows) {
            json item;
            item["media_type"] = row[0].value.value_or("unknown");
            item["count"] = row[1].value ? std::stoll(*row[1].value) : 0;
            item["total_bytes"] = row[2].value ? std::stoll(*row[2].value) : 0;
            breakdown.push_back(item);
          }
          result["by_type"] = breakdown;
          return result;
        });
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 4. StatsDataCache
//
// Multi-segment TTL cache for statistics data. Each segment has its own
// TTL and stores a JSON value. Supports LRU eviction when capacity is
// exceeded, cache warming, segmented invalidation, and hit/miss tracking.
//
// Equivalent to synapse/util/caches/ patterns
// ============================================================================

class StatsDataCache {
public:
  struct CacheSegment {
    std::string name;
    int64_t ttl_ms;
    int64_t max_entries;
    int64_t hits = 0;
    int64_t misses = 0;
    std::mutex mtx;
    std::unordered_map<std::string, std::pair<json, int64_t>> data; // key -> {value, expiry_ms}
  };

  StatsDataCache() {
    // Initialize cache segments
    segments_.push_back({"room_stats", kCacheTTLRoomStats, 5000});
    segments_.push_back({"user_stats", kCacheTTLUserStats, 5000});
    segments_.push_back({"server_stats", kCacheTTLServerStats, 10});
    segments_.push_back({"dau_mau", kCacheTTLDAUMAU, 10});
    segments_.push_back({"media_stats", kCacheTTLMediaStats, 10});
    segments_.push_back({"reg_timeline", kCacheTTLRegistrationTimeline, 5});
    segments_.push_back({"activity_heatmap", kCacheTTLActivityHeatmap, 5});
    segments_.push_back({"federation_stats", kCacheTTLFederationStats, 10});
    segments_.push_back({"top_rooms", kCacheTTLTopRooms, 20});
    segments_.push_back({"top_users", kCacheTTLTopUsers, 20});
  }

  // ---- Generic get/set with segment ----

  std::optional<json> get(const std::string& segment_name,
                           const std::string& key) {
    auto* seg = find_segment(segment_name);
    if (!seg) return std::nullopt;

    std::lock_guard<std::mutex> lock(seg->mtx);
    auto it = seg->data.find(key);
    if (it != seg->data.end()) {
      if (now_ms() < it->second.second) {
        seg->hits++;
        total_hits_.fetch_add(1, std::memory_order_relaxed);
        return it->second.first;
      } else {
        // Expired
        seg->data.erase(it);
      }
    }
    seg->misses++;
    total_misses_.fetch_add(1, std::memory_order_relaxed);
    return std::nullopt;
  }

  void set(const std::string& segment_name, const std::string& key,
           const json& value, int64_t custom_ttl_ms = -1) {
    auto* seg = find_segment(segment_name);
    if (!seg) return;

    int64_t ttl = (custom_ttl_ms > 0) ? custom_ttl_ms : seg->ttl_ms;
    int64_t expiry = now_ms() + ttl;

    std::lock_guard<std::mutex> lock(seg->mtx);

    // Evict if needed
    if (static_cast<int64_t>(seg->data.size()) >= seg->max_entries) {
      evict_lru(*seg);
    }

    seg->data[key] = {value, expiry};
  }

  // ---- Invalidation methods ----

  void invalidate_segment(const std::string& segment_name) {
    auto* seg = find_segment(segment_name);
    if (!seg) return;
    std::lock_guard<std::mutex> lock(seg->mtx);
    seg->data.clear();
  }

  void invalidate_key(const std::string& segment_name, const std::string& key) {
    auto* seg = find_segment(segment_name);
    if (!seg) return;
    std::lock_guard<std::mutex> lock(seg->mtx);
    seg->data.erase(key);
  }

  void invalidate_all() {
    for (auto& seg : segments_) {
      std::lock_guard<std::mutex> lock(seg.mtx);
      seg.data.clear();
    }
  }

  // ---- Warmth/preload ----

  void warm_segment(const std::string& segment_name,
                    const std::vector<std::pair<std::string, json>>& entries) {
    for (auto& [key, val] : entries) {
      set(segment_name, key, val);
    }
  }

  // ---- Stats about the cache itself ----

  json get_cache_stats() const {
    json result;
    json segments = json::array();
    for (auto& seg : segments_) {
      std::lock_guard<std::mutex> lock(seg.mtx);
      json s;
      s["name"] = seg.name;
      s["ttl_ms"] = seg.ttl_ms;
      s["max_entries"] = seg.max_entries;
      s["current_entries"] = seg.data.size();
      s["hits"] = seg.hits;
      s["misses"] = seg.misses;
      segments.push_back(s);
    }
    result["segments"] = segments;
    result["total_hits"] = total_hits_.load(std::memory_order_relaxed);
    result["total_misses"] = total_misses_.load(std::memory_order_relaxed);
    return result;
  }

  int64_t total_hit_count() const { return total_hits_.load(std::memory_order_relaxed); }
  int64_t total_miss_count() const { return total_misses_.load(std::memory_order_relaxed); }

private:
  CacheSegment* find_segment(const std::string& name) {
    for (auto& seg : segments_) {
      if (seg.name == name) return &seg;
    }
    return nullptr;
  }

  void evict_lru(CacheSegment& seg) {
    // Simple strategy: evict the entry with the earliest expiry
    std::string oldest_key;
    int64_t oldest_expiry = std::numeric_limits<int64_t>::max();
    for (auto& [k, pair] : seg.data) {
      if (pair.second < oldest_expiry) {
        oldest_expiry = pair.second;
        oldest_key = k;
      }
    }
    if (!oldest_key.empty()) {
      seg.data.erase(oldest_key);
    }
  }

  std::vector<CacheSegment> segments_;
  std::atomic<int64_t> total_hits_{0};
  std::atomic<int64_t> total_misses_{0};
};

// ============================================================================
// 5. PrometheusExporter
//
// Manages all Prometheus metrics (counters, gauges, histograms, summaries),
// provides a /metrics endpoint renderer, and supports metric registration
// and periodic collection refresh.
//
// Equivalent to synapse/metrics/__init__.py and synapse/metrics/metric.py
// ============================================================================

class PrometheusExporter {
public:
  PrometheusExporter() {
    register_default_metrics();
  }

  // ---- Metric registration ----

  void register_counter(const std::string& name, const std::string& help,
                        const std::vector<std::string>& labels = {}) {
    std::lock_guard<std::shared_mutex> lock(metrics_mutex_);
    counters_[name] = std::make_shared<CounterMetric>(name, help, labels);
  }

  void register_gauge(const std::string& name, const std::string& help,
                      const std::vector<std::string>& labels = {}) {
    std::lock_guard<std::shared_mutex> lock(metrics_mutex_);
    gauges_[name] = std::make_shared<GaugeMetric>(name, help, labels);
  }

  void register_histogram(const std::string& name, const std::string& help,
                          const std::vector<double>& buckets,
                          const std::vector<std::string>& labels = {}) {
    std::lock_guard<std::shared_mutex> lock(metrics_mutex_);
    histograms_[name] = std::make_shared<HistogramMetric>(name, help, buckets, labels);
  }

  void register_summary(const std::string& name, const std::string& help,
                        const std::vector<double>& quantiles,
                        const std::vector<std::string>& labels = {}) {
    std::lock_guard<std::shared_mutex> lock(metrics_mutex_);
    summaries_[name] = std::make_shared<SummaryMetric>(name, help, quantiles, labels);
  }

  // ---- Counter operations ----

  void inc_counter(const std::string& name, double amount = 1.0) {
    auto c = get_counter(name);
    if (c) c->inc(amount);
  }

  void inc_counter_labels(const std::string& name,
                           const std::map<std::string, std::string>& labels,
                           double amount = 1.0) {
    auto c = get_counter(name);
    if (c) c->inc_labels(labels, amount);
  }

  // ---- Gauge operations ----

  void set_gauge(const std::string& name, double val) {
    auto g = get_gauge(name);
    if (g) g->set(val);
  }

  void inc_gauge(const std::string& name, double amount = 1.0) {
    auto g = get_gauge(name);
    if (g) g->inc(amount);
  }

  void dec_gauge(const std::string& name, double amount = 1.0) {
    auto g = get_gauge(name);
    if (g) g->dec(amount);
  }

  // ---- Histogram operations ----

  void observe_histogram(const std::string& name, double value) {
    auto h = get_histogram(name);
    if (h) h->observe(value);
  }

  // ---- Summary operations ----

  void observe_summary(const std::string& name, double value) {
    auto s = get_summary(name);
    if (s) s->observe(value);
  }

  // ---- Render all metrics to Prometheus text format ----

  std::string render_all() {
    std::stringstream ss;
    std::shared_lock<std::shared_mutex> lock(metrics_mutex_);

    for (auto& [name, counter] : counters_) {
      ss << counter->render() << "\n";
    }
    for (auto& [name, gauge] : gauges_) {
      ss << gauge->render() << "\n";
    }
    for (auto& [name, hist] : histograms_) {
      ss << hist->render() << "\n";
    }
    for (auto& [name, summary] : summaries_) {
      ss << summary->render() << "\n";
    }

    return ss.str();
  }

  // ---- Reset all metrics ----

  void reset_all() {
    std::lock_guard<std::shared_mutex> lock(metrics_mutex_);
    for (auto& [_, c] : counters_) c->reset();
    for (auto& [_, g] : gauges_) g->reset();
    for (auto& [_, h] : histograms_) h->reset();
    for (auto& [_, s] : summaries_) s->reset();
  }

  // ---- Refresh gauges from server stats ----

  void refresh_server_gauges(const ServerStatsData& snap) {
    set_gauge(kMetricUsersTotal, static_cast<double>(snap.total_users));
    set_gauge(kMetricRoomsTotal, static_cast<double>(snap.total_rooms));
    set_gauge(kMetricEventsTotal, static_cast<double>(snap.total_events));
    set_gauge(kMetricMediaBytes, static_cast<double>(snap.total_local_media_bytes));
    set_gauge(kMetricDAU, static_cast<double>(snap.daily_active_users));
    set_gauge(kMetricMAU, static_cast<double>(snap.monthly_active_users));
    set_gauge(kMetricActiveRooms, static_cast<double>(snap.rooms_active_24h));
    set_gauge(kMetricRegistrations, static_cast<double>(snap.users_created_24h));
    set_gauge(kMetricDeactivations, static_cast<double>(snap.users_deactivated_24h));
  }

private:
  void register_default_metrics() {
    register_counter(kMetricRequestsTotal, "Total HTTP requests processed");
    register_counter(kMetricEventsTotal, "Total events processed");
    register_counter(kMetricMessagesTotal, "Total messages sent");
    register_counter(kMetricFederationIn, "Total incoming federation requests");
    register_counter(kMetricFederationOut, "Total outgoing federation requests");
    register_counter(kMetricCacheHits, "Total stats cache hits");
    register_counter(kMetricCacheMisses, "Total stats cache misses");
    register_counter(kMetricBGUpdates, "Total background update runs");

    register_gauge(kMetricUsersTotal, "Total registered users");
    register_gauge(kMetricRoomsTotal, "Total rooms");
    register_gauge(kMetricEventsTotal, "Total events (deprecated name, see counter)");
    register_gauge(kMetricMediaBytes, "Total local media bytes");
    register_gauge(kMetricDAU, "Daily active users");
    register_gauge(kMetricMAU, "Monthly active users");
    register_gauge(kMetricActiveRooms, "Rooms active in last 24h");
    register_gauge(kMetricRegistrations, "New registrations in last 24h");
    register_gauge(kMetricDeactivations, "Deactivations in last 24h");
    register_gauge(kMetricPeakConnections, "Peak concurrent connections");
    register_gauge(kMetricQueueDepth, "Event processing queue depth");

    register_histogram(kMetricQueryLatency, "Database query latency in seconds",
                       {0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0});

    register_summary("progressive_collector_request_duration_seconds",
                     "Request duration summary",
                     {0.5, 0.9, 0.95, 0.99});
  }

  std::shared_ptr<CounterMetric> get_counter(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(metrics_mutex_);
    auto it = counters_.find(name);
    return (it != counters_.end()) ? it->second : nullptr;
  }

  std::shared_ptr<GaugeMetric> get_gauge(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(metrics_mutex_);
    auto it = gauges_.find(name);
    return (it != gauges_.end()) ? it->second : nullptr;
  }

  std::shared_ptr<HistogramMetric> get_histogram(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(metrics_mutex_);
    auto it = histograms_.find(name);
    return (it != histograms_.end()) ? it->second : nullptr;
  }

  std::shared_ptr<SummaryMetric> get_summary(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(metrics_mutex_);
    auto it = summaries_.find(name);
    return (it != summaries_.end()) ? it->second : nullptr;
  }

  mutable std::shared_mutex metrics_mutex_;
  std::unordered_map<std::string, std::shared_ptr<CounterMetric>> counters_;
  std::unordered_map<std::string, std::shared_ptr<GaugeMetric>> gauges_;
  std::unordered_map<std::string, std::shared_ptr<HistogramMetric>> histograms_;
  std::unordered_map<std::string, std::shared_ptr<SummaryMetric>> summaries_;
};

// ============================================================================
// 6. StatsBackgroundWorker
//
// Runs periodic background aggregation tasks: updates room stats in batch,
// flushes DAU/MAU data, refreshes cached server snapshots, recomputes
// registration timelines, and emits Prometheus gauge updates.
//
// Equivalent to synapse/handlers/stats.py background tasks
// ============================================================================

class StatsBackgroundWorker {
public:
  StatsBackgroundWorker(storage::DatabasePool& db,
                         RoomStatsCollector& room_collector,
                         UserActivityTracker& user_tracker,
                         ServerStatsAggregator& server_aggregator,
                         StatsDataCache& cache,
                         PrometheusExporter& exporter)
      : db_(db),
        room_collector_(room_collector),
        user_tracker_(user_tracker),
        server_aggregator_(server_aggregator),
        cache_(cache),
        exporter_(exporter) {}

  // ---- Lifecycle ----

  void start() {
    if (running_.exchange(true)) return;
    worker_ = std::thread([this]() { run_loop(); });
  }

  void stop() {
    running_.store(false);
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();
  }

  // ---- Trigger immediate run ----

  void trigger_now() {
    cv_.notify_all();
  }

  // ---- Status ----

  json get_status() const {
    json status;
    status["running"] = running_.load();
    status["runs_completed"] = runs_completed_.load();
    status["last_run_ms"] = last_run_ms_.load();
    status["last_duration_ms"] = last_duration_ms_.load();
    return status;
  }

private:
  void run_loop() {
    while (running_.load()) {
      int64_t start = now_ms();
      run_once();
      int64_t duration = now_ms() - start;
      last_run_ms_.store(start, std::memory_order_relaxed);
      last_duration_ms_.store(duration, std::memory_order_relaxed);
      runs_completed_.fetch_add(1, std::memory_order_relaxed);
      exporter_.inc_counter(kMetricBGUpdates);

      // Wait for next interval
      std::unique_lock<std::mutex> lock(mutex_);
      cv_.wait_for(lock, std::chrono::milliseconds(kBgUpdateIntervalMs),
                   [this]() { return !running_.load(); });
    }
  }

  void run_once() {
    try {
      // 1. Compute server-wide snapshot
      ServerStatsData snap = server_aggregator_.compute_server_stats();

      // 2. Update DAU/MAU
      snap.daily_active_users = user_tracker_.compute_daily_active_users();
      snap.monthly_active_users = user_tracker_.compute_monthly_active_users();
      snap.weekly_active_users = user_tracker_.compute_weekly_active_users();

      // 3. Cache server stats
      cache_.set("server_stats", "current", snap.to_json());

      // 4. Cache DAU/MAU
      json dau_mau;
      dau_mau["dau"] = snap.daily_active_users;
      dau_mau["mau"] = snap.monthly_active_users;
      dau_mau["wau"] = snap.weekly_active_users;
      dau_mau["computed_ts"] = snap.computed_ts;
      cache_.set("dau_mau", "current", dau_mau);

      // 5. Update Prometheus gauges
      exporter_.refresh_server_gauges(snap);

      // 6. Cache top rooms
      json top_rooms = room_collector_.get_top_rooms_by_events(20);
      cache_.set("top_rooms", "by_events", top_rooms);

      json top_rooms_members = room_collector_.get_top_rooms_by_members(20);
      cache_.set("top_rooms", "by_members", top_rooms_members);

      // 7. Cache top users
      json top_users = user_tracker_.get_top_users_by_messages(20, 30);
      cache_.set("top_users", "by_messages", top_users);

      json top_users_media = user_tracker_.get_top_users_by_media(20);
      cache_.set("top_users", "by_media", top_users_media);

      // 8. Update cache hit/miss metrics
      exporter_.set_gauge("progressive_collector_cache_hits",
                          static_cast<double>(cache_.total_hit_count()));
      exporter_.set_gauge("progressive_collector_cache_misses",
                          static_cast<double>(cache_.total_miss_count()));

    } catch (const std::exception& e) {
      // Log error but don't crash the background thread
    }
  }

  storage::DatabasePool& db_;
  RoomStatsCollector& room_collector_;
  UserActivityTracker& user_tracker_;
  ServerStatsAggregator& server_aggregator_;
  StatsDataCache& cache_;
  PrometheusExporter& exporter_;

  std::atomic<bool> running_{false};
  std::thread worker_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::atomic<int64_t> runs_completed_{0};
  std::atomic<int64_t> last_run_ms_{0};
  std::atomic<int64_t> last_duration_ms_{0};
};

// ============================================================================
// 7. StatsAdminHandler
//
// REST API handler for admin statistics endpoints and user-facing stats
// endpoints. Exposes JSON APIs for room stats, user stats, server stats,
// activity data, media stats, and federation statistics.
//
// Equivalent to synapse/rest/admin/statistics.py
// ============================================================================

class StatsAdminHandler {
public:
  StatsAdminHandler(storage::DatabasePool& db,
                     RoomStatsCollector& room_collector,
                     UserActivityTracker& user_tracker,
                     ServerStatsAggregator& server_aggregator,
                     StatsDataCache& cache,
                     PrometheusExporter& exporter,
                     StatsBackgroundWorker& bg_worker)
      : db_(db),
        room_collector_(room_collector),
        user_tracker_(user_tracker),
        server_aggregator_(server_aggregator),
        cache_(cache),
        exporter_(exporter),
        bg_worker_(bg_worker) {}

  // ================================================================
  // Public Stats API Endpoints
  // ================================================================

  // GET /_progressive/stats/v1/server
  json handle_server_stats() {
    // Try cache first
    auto cached = cache_.get("server_stats", "current");
    if (cached.has_value()) {
      exporter_.inc_counter(kMetricCacheHits);
      return *cached;
    }
    exporter_.inc_counter(kMetricCacheMisses);

    ServerStatsData snap = server_aggregator_.compute_server_stats();
    snap.daily_active_users = user_tracker_.compute_daily_active_users();
    snap.monthly_active_users = user_tracker_.compute_monthly_active_users();

    json result = snap.to_json();
    cache_.set("server_stats", "current", result);
    return result;
  }

  // GET /_progressive/stats/v1/rooms
  json handle_room_stats_list(const std::string& order_by, const std::string& dir,
                               int64_t limit, int64_t offset, const std::string& search) {
    return room_collector_.list_rooms_with_stats(order_by, dir, limit, offset, search);
  }

  // GET /_progressive/stats/v1/rooms/:room_id
  json handle_room_detail(const std::string& room_id) {
    auto cached = cache_.get("room_stats", room_id);
    if (cached.has_value()) return *cached;

    RoomStatsSnapshot snap = room_collector_.collect_room_stats(room_id);
    json result = snap.to_json();
    cache_.set("room_stats", room_id, result);
    return result;
  }

  // GET /_progressive/stats/v1/rooms/:room_id/timeline
  json handle_room_timeline(const std::string& room_id, const std::string& bucket, int64_t days) {
    return room_collector_.get_room_event_timeline(room_id, bucket, days);
  }

  // GET /_progressive/stats/v1/rooms/top
  json handle_top_rooms(const std::string& metric, int64_t limit) {
    std::string key = "top_rooms:" + metric + ":" + std::to_string(limit);
    auto cached = cache_.get("top_rooms", key);
    if (cached.has_value()) return *cached;

    json result;
    if (metric == "members") {
      result = room_collector_.get_top_rooms_by_members(limit);
    } else {
      result = room_collector_.get_top_rooms_by_events(limit);
    }
    cache_.set("top_rooms", key, result);
    return result;
  }

  // GET /_progressive/stats/v1/users
  json handle_user_stats_list(const std::string& search, int64_t limit) {
    return user_tracker_.search_users(search, limit);
  }

  // GET /_progressive/stats/v1/users/:user_id
  json handle_user_detail(const std::string& user_id) {
    auto cached = cache_.get("user_stats", user_id);
    if (cached.has_value()) return *cached;

    UserStatsData data = user_tracker_.collect_user_stats(user_id);
    json result = data.to_json();
    cache_.set("user_stats", user_id, result);
    return result;
  }

  // GET /_progressive/stats/v1/users/top
  json handle_top_users(const std::string& metric, int64_t limit, int64_t days) {
    std::string key = "top_users:" + metric + ":" + std::to_string(limit) + ":" + std::to_string(days);
    auto cached = cache_.get("top_users", key);
    if (cached.has_value()) return *cached;

    json result;
    if (metric == "media") {
      result = user_tracker_.get_top_users_by_media(limit);
    } else {
      result = user_tracker_.get_top_users_by_messages(limit, days);
    }
    cache_.set("top_users", key, result);
    return result;
  }

  // GET /_progressive/stats/v1/activity/dau
  json handle_dau() {
    auto cached = cache_.get("dau_mau", "current");
    if (cached.has_value()) return *cached;

    json result;
    result["dau"] = user_tracker_.compute_daily_active_users();
    result["mau"] = user_tracker_.compute_monthly_active_users();
    result["wau"] = user_tracker_.compute_weekly_active_users();
    result["computed_ts"] = now_sec();

    cache_.set("dau_mau", "current", result);
    return result;
  }

  // GET /_progressive/stats/v1/activity/dau_series
  json handle_dau_series(int64_t days) {
    std::string key = "dau_series:" + std::to_string(days);
    auto cached = cache_.get("activity_heatmap", key);
    if (cached.has_value()) return *cached;

    json result = user_tracker_.get_dau_time_series(days);
    cache_.set("activity_heatmap", key, result);
    return result;
  }

  // GET /_progressive/stats/v1/activity/registrations
  json handle_registration_timeline(const std::string& bucket, int64_t days) {
    std::string key = "reg_timeline:" + bucket + ":" + std::to_string(days);
    auto cached = cache_.get("reg_timeline", key);
    if (cached.has_value()) return *cached;

    json result = user_tracker_.get_registration_timeline(bucket, days);
    cache_.set("reg_timeline", key, result);
    return result;
  }

  // GET /_progressive/stats/v1/activity/cohorts
  json handle_cohort_analysis(const std::string& period, int64_t lookback) {
    std::string key = "cohort:" + period + ":" + std::to_string(lookback);
    auto cached = cache_.get("reg_timeline", key);
    if (cached.has_value()) return *cached;

    json result = user_tracker_.get_cohort_analysis(period, lookback);
    cache_.set("reg_timeline", key, result, kCacheTTLRegistrationTimeline * 2);
    return result;
  }

  // GET /_progressive/stats/v1/activity/throughput
  json handle_event_throughput(const std::string& bucket, int64_t hours) {
    std::string key = "throughput:" + bucket + ":" + std::to_string(hours);
    auto cached = cache_.get("activity_heatmap", key);
    if (cached.has_value()) return *cached;

    json result = server_aggregator_.get_event_throughput_series(bucket, hours);
    cache_.set("activity_heatmap", key, result);
    return result;
  }

  // GET /_progressive/stats/v1/media
  json handle_media_stats() {
    auto cached = cache_.get("media_stats", "current");
    if (cached.has_value()) return *cached;

    json result = server_aggregator_.get_media_type_breakdown();
    cache_.set("media_stats", "current", result);
    return result;
  }

  // GET /_progressive/stats/v1/federation
  json handle_federation_stats() {
    auto cached = cache_.get("federation_stats", "current");
    if (cached.has_value()) return *cached;

    json result = server_aggregator_.get_federation_stats();
    cache_.set("federation_stats", "current", result);
    return result;
  }

  // ================================================================
  // Admin API Endpoints
  // ================================================================

  // GET /_progressive/admin/v1/stats/overview
  json admin_get_overview() {
    json result;

    // Server stats
    result["server"] = handle_server_stats();

    // DAU/MAU
    result["activity"] = handle_dau();

    // Top rooms
    json top_rooms;
    top_rooms["by_events"] = handle_top_rooms("events", 10);
    top_rooms["by_members"] = handle_top_rooms("members", 10);
    result["top_rooms"] = top_rooms;

    // Top users
    json top_users;
    top_users["by_messages"] = handle_top_users("messages", 10, 30);
    top_users["by_media"] = handle_top_users("media", 10, 30);
    result["top_users"] = top_users;

    // Cache stats
    result["cache"] = handle_cache_stats();

    // Background worker status
    result["background_worker"] = bg_worker_.get_status();

    result["computed_ts"] = now_sec();
    return result;
  }

  // POST /_progressive/admin/v1/stats/rooms/aggregate
  json admin_trigger_room_aggregation(int64_t batch_size) {
    json result;
    result["status"] = "started";
    result["batch_size"] = batch_size;

    json agg_result = room_collector_.collect_all_room_stats(batch_size);
    result["result"] = agg_result;

    // Invalidate room-related caches
    cache_.invalidate_segment("room_stats");
    cache_.invalidate_segment("top_rooms");
    cache_.invalidate_segment("server_stats");

    return result;
  }

  // POST /_progressive/admin/v1/stats/cache/clear
  json admin_clear_cache(const std::string& segment) {
    if (segment.empty() || segment == "all") {
      cache_.invalidate_all();
      return {{"status", "ok"}, {"cleared", "all"}};
    } else {
      cache_.invalidate_segment(segment);
      return {{"status", "ok"}, {"cleared", segment}};
    }
  }

  // GET /_progressive/admin/v1/stats/cache
  json handle_cache_stats() {
    return cache_.get_cache_stats();
  }

  // GET /_progressive/admin/v1/stats/background
  json admin_get_background_status() {
    return bg_worker_.get_status();
  }

  // POST /_progressive/admin/v1/stats/background/trigger
  json admin_trigger_background_run() {
    bg_worker_.trigger_now();
    return {{"status", "triggered"}};
  }

  // GET /_progressive/admin/v1/stats/metrics
  std::string admin_get_metrics() {
    return exporter_.render_all();
  }

  // POST /_progressive/admin/v1/stats/metrics/reset
  json admin_reset_metrics() {
    exporter_.reset_all();
    return {{"status", "ok"}, {"message", "All metrics reset"}};
  }

  // GET /_progressive/admin/v1/stats/database/rooms
  json admin_get_database_room_stats() {
    // Returns per-room database size estimate
    return db_.runInteraction(
        "admin_db_room_stats",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          try {
            txn.execute(
                "SELECT room_id, COUNT(*) as event_count, "
                "SUM(LENGTH(content)) as total_content_bytes "
                "FROM events GROUP BY room_id "
                "ORDER BY total_content_bytes DESC LIMIT 100");
            auto rows = txn.fetchall();
            for (auto& row : rows) {
              json r;
              r["room_id"] = row[0].value.value_or("");
              r["event_count"] = row[1].value ? std::stoll(*row[1].value) : 0;
              r["content_bytes"] = row[2].value ? std::stoll(*row[2].value) : 0;
              result.push_back(r);
            }
          } catch (...) {}
          return result;
        });
  }

  // GET /_progressive/admin/v1/stats/users/media
  json admin_get_user_media_stats(const std::string& order_by,
                                   bool reverse, int64_t limit,
                                   int64_t offset, const std::string& search) {
    return db_.runInteraction(
        "admin_user_media_stats",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;
          std::string where = "";
          std::vector<std::string> params;

          if (!search.empty()) {
            where = "WHERE u.name LIKE ? ";
            params.push_back("%" + search + "%");
          }

          // Count total
          std::string count_sql =
              "SELECT COUNT(*) FROM users u "
              "LEFT JOIN ("
              "  SELECT user_id, SUM(media_length) as media_length, COUNT(*) as media_count "
              "  FROM local_media_repository GROUP BY user_id"
              ") lm ON u.name = lm.user_id " + where;
          txn.execute(count_sql, params);
          auto crow = txn.fetchone();
          result["total"] = crow ? std::stoll(crow->at(0).value.value_or("0")) : 0;

          std::string valid_order;
          if (order_by == "media_length") valid_order = "COALESCE(lm.media_length, 0)";
          else if (order_by == "media_count") valid_order = "COALESCE(lm.media_count, 0)";
          else if (order_by == "user_id") valid_order = "u.name";
          else valid_order = "COALESCE(lm.media_length, 0)";

          std::string dir = reverse ? "DESC" : "ASC";

          std::string sql =
              "SELECT u.name, u.display_name, COALESCE(lm.media_length, 0), "
              "COALESCE(lm.media_count, 0) "
              "FROM users u "
              "LEFT JOIN ("
              "  SELECT user_id, SUM(media_length) as media_length, COUNT(*) as media_count "
              "  FROM local_media_repository GROUP BY user_id"
              ") lm ON u.name = lm.user_id " +
              where +
              "ORDER BY " + valid_order + " " + dir + " "
              "LIMIT ? OFFSET ?";

          params.push_back(std::to_string(limit));
          params.push_back(std::to_string(offset));

          txn.execute(sql, params);
          auto rows = txn.fetchall();
          json users = json::array();
          for (auto& row : rows) {
            json u;
            u["user_id"] = row[0].value.value_or("");
            u["display_name"] = row[1].value.value_or("");
            u["media_length"] = row[2].value ? std::stoll(*row[2].value) : 0;
            u["media_count"] = row[3].value ? std::stoll(*row[3].value) : 0;
            users.push_back(u);
          }
          result["users"] = users;
          result["offset"] = offset;
          result["limit"] = limit;
          return result;
        });
  }

private:
  storage::DatabasePool& db_;
  RoomStatsCollector& room_collector_;
  UserActivityTracker& user_tracker_;
  ServerStatsAggregator& server_aggregator_;
  StatsDataCache& cache_;
  PrometheusExporter& exporter_;
  StatsBackgroundWorker& bg_worker_;
};

// ============================================================================
// 8. StatsCollectorEngine — Facade class
//
// Top-level orchestration class that owns all sub-components and provides
// a unified API for stats collection, querying, and management.
//
// Equivalent to synapse/handlers/stats.py + synapse/app/homeserver.py
// ============================================================================

class StatsCollectorEngine {
public:
  StatsCollectorEngine(storage::DatabasePool& db, const std::string& server_name)
      : db_(db),
        server_name_(server_name),
        room_collector_(std::make_unique<RoomStatsCollector>(db)),
        user_tracker_(std::make_unique<UserActivityTracker>(db)),
        server_aggregator_(std::make_unique<ServerStatsAggregator>(db)),
        cache_(std::make_unique<StatsDataCache>()),
        exporter_(std::make_unique<PrometheusExporter>()) {
    bg_worker_ = std::make_unique<StatsBackgroundWorker>(
        db, *room_collector_, *user_tracker_, *server_aggregator_,
        *cache_, *exporter_);
    admin_handler_ = std::make_unique<StatsAdminHandler>(
        db, *room_collector_, *user_tracker_, *server_aggregator_,
        *cache_, *exporter_, *bg_worker_);
  }

  // ---- Lifecycle ----

  void start() {
    bg_worker_->start();
  }

  void stop() {
    bg_worker_->stop();
  }

  // ---- Hook: record a request for metrics ----

  void record_request(const std::string& method, const std::string& path,
                      double duration_seconds, int status_code) {
    exporter_->inc_counter(kMetricRequestsTotal);
    exporter_->inc_counter_labels(kMetricRequestsTotal,
                                   {{"method", method}, {"status", std::to_string(status_code)}});
    exporter_->observe_summary("progressive_collector_request_duration_seconds", duration_seconds);
  }

  // ---- Hook: record an event ----

  void record_event(const std::string& type, const std::string& room_id) {
    exporter_->inc_counter(kMetricEventsTotal);
    EventFamily family = classify_event_family(type);
    exporter_->inc_counter_labels(kMetricEventsTotal,
                                   {{"type", event_family_name(family)}});
    if (type == "m.room.message") {
      exporter_->inc_counter(kMetricMessagesTotal);
    }
  }

  // ---- Hook: record media upload ----

  void record_media_upload(int64_t bytes) {
    exporter_->inc_counter(kMetricMediaBytes, static_cast<double>(bytes));
    cache_->invalidate_segment("media_stats");
    cache_->invalidate_segment("server_stats");
  }

  // ---- Hook: record federation traffic ----

  void record_federation_request(bool incoming, bool success) {
    if (incoming) {
      exporter_->inc_counter(kMetricFederationIn);
    } else {
      exporter_->inc_counter(kMetricFederationOut);
    }
  }

  // ---- Hook: record database query ----

  void record_db_query(double duration_seconds) {
    exporter_->observe_histogram(kMetricQueryLatency, duration_seconds);
  }

  // ---- Periodic refresh ----

  void refresh_metrics() {
    ServerStatsData snap = server_aggregator_->compute_server_stats();
    snap.daily_active_users = user_tracker_->compute_daily_active_users();
    snap.monthly_active_users = user_tracker_->compute_monthly_active_users();
    snap.weekly_active_users = user_tracker_->compute_weekly_active_users();

    exporter_->refresh_server_gauges(snap);

    cache_->set("server_stats", "current", snap.to_json());
    json dm;
    dm["dau"] = snap.daily_active_users;
    dm["mau"] = snap.monthly_active_users;
    dm["wau"] = snap.weekly_active_users;
    cache_->set("dau_mau", "current", dm);
  }

  // ================================================================
  // Stats API Delegates
  // ================================================================

  json get_server_stats() { return admin_handler_->handle_server_stats(); }

  json get_room_list(const std::string& order_by = "total_events",
                     const std::string& dir = "DESC",
                     int64_t limit = 100, int64_t offset = 0,
                     const std::string& search = "") {
    return admin_handler_->handle_room_stats_list(order_by, dir, limit, offset, search);
  }

  json get_room_detail(const std::string& room_id) {
    return admin_handler_->handle_room_detail(room_id);
  }

  json get_room_timeline(const std::string& room_id,
                          const std::string& bucket = "daily", int64_t days = 30) {
    return admin_handler_->handle_room_timeline(room_id, bucket, days);
  }

  json get_top_rooms(const std::string& metric = "events", int64_t limit = 50) {
    return admin_handler_->handle_top_rooms(metric, limit);
  }

  json get_user_detail(const std::string& user_id) {
    return admin_handler_->handle_user_detail(user_id);
  }

  json get_user_list(const std::string& search = "", int64_t limit = 50) {
    return admin_handler_->handle_user_stats_list(search, limit);
  }

  json get_top_users(const std::string& metric = "messages",
                      int64_t limit = 50, int64_t days = 30) {
    return admin_handler_->handle_top_users(metric, limit, days);
  }

  json get_dau() { return admin_handler_->handle_dau(); }

  json get_dau_series(int64_t days = 90) {
    return admin_handler_->handle_dau_series(days);
  }

  json get_registration_timeline(const std::string& bucket = "daily",
                                  int64_t days = 365) {
    return admin_handler_->handle_registration_timeline(bucket, days);
  }

  json get_cohort_analysis(const std::string& period = "monthly",
                            int64_t lookback = 12) {
    return admin_handler_->handle_cohort_analysis(period, lookback);
  }

  json get_event_throughput(const std::string& bucket = "hourly",
                             int64_t hours = 24) {
    return admin_handler_->handle_event_throughput(bucket, hours);
  }

  json get_media_stats() { return admin_handler_->handle_media_stats(); }

  json get_federation_stats() { return admin_handler_->handle_federation_stats(); }

  // ================================================================
  // Admin API Delegates
  // ================================================================

  json admin_get_overview() { return admin_handler_->admin_get_overview(); }

  json admin_trigger_room_aggregation(int64_t batch_size = kRoomBatchSize) {
    return admin_handler_->admin_trigger_room_aggregation(batch_size);
  }

  json admin_clear_cache(const std::string& segment = "") {
    return admin_handler_->admin_clear_cache(segment);
  }

  json admin_get_cache_stats() { return admin_handler_->handle_cache_stats(); }

  json admin_get_background_status() { return admin_handler_->admin_get_background_status(); }

  json admin_trigger_background() { return admin_handler_->admin_trigger_background_run(); }

  std::string admin_get_metrics() { return admin_handler_->admin_get_metrics(); }

  json admin_reset_metrics() { return admin_handler_->admin_reset_metrics(); }

  json admin_get_database_room_stats() { return admin_handler_->admin_get_database_room_stats(); }

  json admin_get_user_media_stats(const std::string& order_by = "media_length",
                                   bool reverse = true, int64_t limit = 100,
                                   int64_t offset = 0,
                                   const std::string& search = "") {
    return admin_handler_->admin_get_user_media_stats(order_by, reverse, limit, offset, search);
  }

private:
  storage::DatabasePool& db_;
  std::string server_name_;

  std::unique_ptr<RoomStatsCollector> room_collector_;
  std::unique_ptr<UserActivityTracker> user_tracker_;
  std::unique_ptr<ServerStatsAggregator> server_aggregator_;
  std::unique_ptr<StatsDataCache> cache_;
  std::unique_ptr<PrometheusExporter> exporter_;
  std::unique_ptr<StatsBackgroundWorker> bg_worker_;
  std::unique_ptr<StatsAdminHandler> admin_handler_;
};

// ============================================================================
// Global factory function
// ============================================================================

std::unique_ptr<StatsCollectorEngine> create_stats_collector(
    storage::DatabasePool& db, const std::string& server_name) {
  return std::make_unique<StatsCollectorEngine>(db, server_name);
}

}  // namespace progressive
