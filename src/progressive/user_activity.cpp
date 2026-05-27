// ============================================================================
// user_activity.cpp — Matrix User Activity Tracking: DAU/MAU Computation,
//   Activity Timeline, User Session Tracking, Activity Heatmaps, Retention
//   Analysis, Engagement Scoring, Peak Usage Analysis, and Background
//   Activity Aggregation Engine
//
// Implements:
//   - Daily Active Users (DAU) computation: SQL-driven distinct user count
//     for the current day, time series across arbitrary date ranges,
//     DAU trend analysis with moving averages, YoY comparisons
//   - Monthly Active Users (MAU) computation: rolling 30-day window,
//     fixed calendar-month window, MAU growth rates, MAU/DAU stickiness
//     ratio, MAU forecast via linear regression
//   - Weekly Active Users (WAU) computation: rolling 7-day window,
//     week-over-week growth, WAU/MAU ratio, weekend vs weekday splits
//   - Activity Timeline: per-user daily visit tracking, user_daily_visits
//     table management with upsert logic, timeline bucketing (daily/
//     weekly/monthly/quarterly/yearly), cumulative activity curves
//   - User Session Tracking: session start/end timestamps, session duration
//     distribution, concurrent session counting, device-level activity
//     attribution, session idle timeout detection
//   - Activity Heatmaps: 7x24 hour-of-day vs day-of-week matrix,
//     52x7 week-of-year calendar heatmap, per-room activity heatmaps,
//     per-user activity pattern fingerprinting
//   - Retention Analysis: N-day retention curves (1d/3d/7d/14d/30d/90d),
//     cohort-based retention tables, churn prediction scoring,
//     new-user activation funnel, power-user curve analysis
//   - Engagement Scoring: per-user engagement score (0-100) from
//     weighted multi-factor model (messages, rooms, sessions, reactions,
//     days active, recency), engagement percentile ranking, engagement
//     tier classification (power/core/casual/dormant/ghost)
//   - Peak Usage Analysis: hourly traffic distribution, daily peak
//     detection, weekly cycle patterns, seasonal trend decomposition,
//     anomaly detection for traffic spikes/drops
//   - Activity-Based Notifications: inactivity alerts, re-engagement
//     triggers, milestone notifications, activity digest generation
//   - Activity Data Caching: TTL-based in-memory cache with segmented
//     buckets (DAU, MAU, timeline, heatmap, engagement), lazy refresh,
//     cache warming on startup, cache invalidation hooks
//   - Background Activity Aggregator: periodic worker that recalculates
//     activity metrics from raw events/user_daily_visits tables,
//     incremental delta updates, retry on database contention
//   - Admin API: GET /_progressive/admin/v1/activity/overview,
//     GET /_progressive/admin/v1/activity/dau[/:days],
//     GET /_progressive/admin/v1/activity/mau[/:months],
//     GET /_progressive/admin/v1/activity/timeline/:user_id,
//     GET /_progressive/admin/v1/activity/heatmap[/:period],
//     GET /_progressive/admin/v1/activity/retention[/:days],
//     GET /_progressive/admin/v1/activity/engagement[/:user_id],
//     GET /_progressive/admin/v1/activity/peaks[/:hours],
//     POST /_progressive/admin/v1/activity/aggregate,
//     POST /_progressive/admin/v1/activity/cache/refresh
//   - Prometheus metrics export: progressive_activity_dau,
//     progressive_activity_mau, progressive_activity_wau,
//     progressive_activity_stickiness_ratio,
//     progressive_activity_engagement_score,
//     progressive_activity_session_duration_seconds
//
// Equivalent to:
//   synapse/storage/databases/main/stats.py (DAU/MAU portions)
//   synapse/handlers/stats.py
//   synapse/storage/databases/main/user_daily_visits.py
//   synapse/handlers/user_activity.py
//   synapse/metrics/__init__.py (activity metrics)
//   synapse/rest/admin/statistics.py (activity endpoints)
//
// Namespace: progressive::
// Target: 3000+ lines of production-grade C++ with full SQL coverage.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
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
#include "progressive/storage/databases/main/event_push_actions.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class DailyActiveUsersEngine;
class MonthlyActiveUsersEngine;
class WeeklyActiveUsersEngine;
class ActivityTimelineTracker;
class UserSessionTracker;
class ActivityHeatmapBuilder;
class RetentionAnalyzer;
class EngagementScorer;
class PeakUsageAnalyzer;
class ActivityDataCache;
class BackgroundActivityAggregator;
class ActivityAdminHandler;
class ActivityMetricsExporter;
class ActivityTrackingOrchestrator;

// ============================================================================
// Anonymous namespace — Internal helpers, constants, and utility types
// ============================================================================
namespace {

// --------------------------------------------------------------------------
// Logging helper (matches project conventions)
// --------------------------------------------------------------------------
struct ActivityLogger {
  std::string name_;
  void debug(const std::string& msg) { std::cerr << "[DEBUG][Activity:" << name_ << "] " << msg << "\n"; }
  void info(const std::string& msg)  { std::cerr << "[INFO][Activity:" << name_ << "] " << msg << "\n"; }
  void warn(const std::string& msg)  { std::cerr << "[WARN][Activity:" << name_ << "] " << msg << "\n"; }
  void error(const std::string& msg) { std::cerr << "[ERROR][Activity:" << name_ << "] " << msg << "\n"; }
};

ActivityLogger& get_activity_logger(const std::string& name) {
  static thread_local std::map<std::string, ActivityLogger> loggers;
  if (loggers.find(name) == loggers.end()) {
    loggers[name].name_ = name;
  }
  return loggers[name];
}

// --------------------------------------------------------------------------
// Timestamp utilities
// --------------------------------------------------------------------------
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

inline int64_t now_us() {
  return chr::duration_cast<chr::microseconds>(
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

inline int64_t days_ago_ms(int days) {
  return now_ms() - static_cast<int64_t>(days) * 86400000LL;
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

inline int64_t parse_date_to_sec(const std::string& date_str) {
  struct tm tm = {};
  std::istringstream ss(date_str);
  ss >> std::get_time(&tm, "%Y-%m-%d");
  if (ss.fail()) return 0;
  return static_cast<int64_t>(timegm(&tm));
}

inline int day_of_week(int64_t sec) {
  auto t = static_cast<std::time_t>(sec);
  auto* utc = std::gmtime(&t);
  return utc->tm_wday; // 0=Sunday, 6=Saturday
}

inline int hour_of_day(int64_t sec) {
  auto t = static_cast<std::time_t>(sec);
  auto* utc = std::gmtime(&t);
  return utc->tm_hour;
}

inline int week_of_year(int64_t sec) {
  auto t = static_cast<std::time_t>(sec);
  auto* utc = std::gmtime(&t);
  char buf[4];
  std::strftime(buf, sizeof(buf), "%W", utc);
  return std::stoi(buf);
}

inline int day_of_year(int64_t sec) {
  auto t = static_cast<std::time_t>(sec);
  auto* utc = std::gmtime(&t);
  return utc->tm_yday;
}

inline int64_t start_of_day_sec(int64_t sec) {
  struct tm tm = {};
  auto t = static_cast<std::time_t>(sec);
  auto* utc = std::gmtime(&t);
  tm.tm_year = utc->tm_year;
  tm.tm_mon  = utc->tm_mon;
  tm.tm_mday = utc->tm_mday;
  tm.tm_hour = 0;
  tm.tm_min  = 0;
  tm.tm_sec  = 0;
  return static_cast<int64_t>(timegm(&tm));
}

inline int64_t start_of_week_sec(int64_t sec) {
  auto sod = start_of_day_sec(sec);
  int dow = day_of_week(sod);
  // Monday = start of week
  int days_since_monday = (dow + 6) % 7;
  return sod - days_since_monday * 86400;
}

inline int64_t start_of_month_sec(int64_t sec) {
  struct tm tm = {};
  auto t = static_cast<std::time_t>(sec);
  auto* utc = std::gmtime(&t);
  tm.tm_year = utc->tm_year;
  tm.tm_mon  = utc->tm_mon;
  tm.tm_mday = 1;
  tm.tm_hour = 0;
  tm.tm_min  = 0;
  tm.tm_sec  = 0;
  return static_cast<int64_t>(timegm(&tm));
}

// --------------------------------------------------------------------------
// String constants
// --------------------------------------------------------------------------
constexpr std::string_view kTableDailyVisits  = "user_daily_visits";
constexpr std::string_view kTableUserSessions = "user_activity_sessions";
constexpr std::string_view kTableActivityLog  = "user_activity_log";
constexpr std::string_view kTableActivityAgg  = "user_activity_aggregated";
constexpr std::string_view kTableEngagement   = "user_engagement_scores";

constexpr std::string_view kBucketDaily     = "daily";
constexpr std::string_view kBucketWeekly    = "weekly";
constexpr std::string_view kBucketMonthly   = "monthly";
constexpr std::string_view kBucketQuarterly = "quarterly";
constexpr std::string_view kBucketYearly    = "yearly";

constexpr std::string_view kActivityTypeMessage   = "message";
constexpr std::string_view kActivityTypeReaction   = "reaction";
constexpr std::string_view kActivityTypeRedaction  = "redaction";
constexpr std::string_view kActivityTypePresence   = "presence";
constexpr std::string_view kActivityTypeSync       = "sync";
constexpr std::string_view kActivityTypeJoin       = "join";
constexpr std::string_view kActivityTypeLeave      = "leave";
constexpr std::string_view kActivityTypeInvite     = "invite";
constexpr std::string_view kActivityTypeMediaUpload = "media_upload";

constexpr int64_t kDefaultCacheTTLSeconds   = 300;   // 5 minutes
constexpr int64_t kDAUCacheTTLSeconds       = 120;   // 2 minutes
constexpr int64_t kMAUCacheTTLSeconds       = 600;   // 10 minutes
constexpr int64_t kTimelineCacheTTLSeconds  = 3600;  // 1 hour
constexpr int64_t kHeatmapCacheTTLSeconds   = 7200;  // 2 hours
constexpr int64_t kEngagementCacheTTLSeconds = 900;  // 15 minutes

constexpr int64_t kDefaultAggregationIntervalSec = 300;  // 5 minutes
constexpr int64_t kSessionIdleTimeoutMs          = 900000; // 15 minutes
constexpr int64_t kMaxRetentionDays              = 365;
constexpr int64_t kMaxHeatmapDays               = 365;
constexpr int64_t kMaxTimelineDays              = 730;

constexpr double kEngagementWeightMessages   = 0.25;
constexpr double kEngagementWeightRooms      = 0.15;
constexpr double kEngagementWeightSessions   = 0.10;
constexpr double kEngagementWeightReactions  = 0.10;
constexpr double kEngagementWeightDaysActive = 0.20;
constexpr double kEngagementWeightRecency    = 0.15;
constexpr double kEngagementWeightMedia      = 0.05;

// --------------------------------------------------------------------------
// Math / stats helpers
// --------------------------------------------------------------------------
inline double safe_divide(int64_t num, int64_t den) {
  return den > 0 ? static_cast<double>(num) / static_cast<double>(den) : 0.0;
}

inline double compute_linear_trend(const std::vector<int64_t>& values) {
  if (values.size() < 2) return 0.0;
  double n = static_cast<double>(values.size());
  double sum_x = 0.0, sum_y = 0.0, sum_xy = 0.0, sum_xx = 0.0;
  for (size_t i = 0; i < values.size(); i++) {
    double x = static_cast<double>(i);
    double y = static_cast<double>(values[i]);
    sum_x += x;
    sum_y += y;
    sum_xy += x * y;
    sum_xx += x * x;
  }
  double denom = n * sum_xx - sum_x * sum_x;
  return std::abs(denom) > 1e-9
      ? (n * sum_xy - sum_x * sum_y) / denom
      : 0.0;
}

inline double compute_moving_average(const std::vector<int64_t>& values, int window) {
  if (values.empty() || window <= 0) return 0.0;
  int actual = std::min(window, static_cast<int>(values.size()));
  double sum = 0.0;
  for (int i = static_cast<int>(values.size()) - actual; i < static_cast<int>(values.size()); i++) {
    sum += static_cast<double>(values[i]);
  }
  return sum / actual;
}

inline std::vector<double> compute_z_scores(const std::vector<int64_t>& values) {
  if (values.size() < 2) return {};
  double mean = 0.0;
  for (auto v : values) mean += static_cast<double>(v);
  mean /= values.size();
  double variance = 0.0;
  for (auto v : values) {
    double diff = static_cast<double>(v) - mean;
    variance += diff * diff;
  }
  variance /= values.size();
  double stddev = std::sqrt(variance);
  if (stddev < 1e-9) return std::vector<double>(values.size(), 0.0);
  std::vector<double> z;
  z.reserve(values.size());
  for (auto v : values) {
    z.push_back((static_cast<double>(v) - mean) / stddev);
  }
  return z;
}

inline double compute_percentile(const std::vector<int64_t>& sorted, double pct) {
  if (sorted.empty()) return 0.0;
  double idx = pct * (sorted.size() - 1);
  size_t lo = static_cast<size_t>(std::floor(idx));
  size_t hi = static_cast<size_t>(std::ceil(idx));
  if (lo >= sorted.size()) lo = sorted.size() - 1;
  if (hi >= sorted.size()) hi = sorted.size() - 1;
  double frac = idx - std::floor(idx);
  return static_cast<double>(sorted[lo]) * (1.0 - frac) + static_cast<double>(sorted[hi]) * frac;
}

// --------------------------------------------------------------------------
// Thread-safe atomic counter for metrics
// --------------------------------------------------------------------------
class AtomicCounter {
public:
  void inc(int64_t delta = 1) { value_.fetch_add(delta, std::memory_order_relaxed); }
  void set(int64_t val) { value_.store(val, std::memory_order_relaxed); }
  int64_t get() const { return value_.load(std::memory_order_relaxed); }
private:
  std::atomic<int64_t> value_{0};
};

class AtomicGauge {
public:
  void set(double val) { value_.store(val, std::memory_order_relaxed); }
  double get() const { return value_.load(std::memory_order_relaxed); }
  void inc(double delta = 1.0) {
    double expected = value_.load(std::memory_order_relaxed);
    while (!value_.compare_exchange_weak(expected, expected + delta,
           std::memory_order_relaxed)) {}
  }
private:
  std::atomic<double> value_{0.0};
};

// --------------------------------------------------------------------------
// Prometheus metric types
// --------------------------------------------------------------------------
enum class MetricType { kGauge, kCounter, kHistogram, kSummary };

struct PromMetricDef {
  std::string name;
  std::string help;
  MetricType type;
};

const std::vector<PromMetricDef> kActivityMetrics = {
  {"progressive_activity_dau",           "Daily Active Users",                 MetricType::kGauge},
  {"progressive_activity_mau",           "Monthly Active Users",               MetricType::kGauge},
  {"progressive_activity_wau",           "Weekly Active Users",                MetricType::kGauge},
  {"progressive_activity_stickiness",    "DAU/MAU stickiness ratio",           MetricType::kGauge},
  {"progressive_activity_wau_mau",       "WAU/MAU ratio",                      MetricType::kGauge},
  {"progressive_activity_new_users_24h", "New users in last 24 hours",         MetricType::kGauge},
  {"progressive_activity_sessions_active","Currently active sessions",         MetricType::kGauge},
  {"progressive_activity_engagement_avg", "Average engagement score",          MetricType::kGauge},
  {"progressive_activity_peak_hour_ts",  "Peak activity hour timestamp",       MetricType::kGauge},
  {"progressive_activity_events_per_min","Events per minute (recent)",         MetricType::kGauge},
  {"progressive_activity_retention_d7",  "7-day retention rate",               MetricType::kGauge},
  {"progressive_activity_retention_d30", "30-day retention rate",              MetricType::kGauge},
  {"progressive_activity_dau_growth",    "DAU growth rate (7d avg)",           MetricType::kGauge},
};

class SimplePromMetric {
public:
  SimplePromMetric(const std::string& name, const std::string& help,
                   MetricType type)
      : name_(name), help_(help), type_(type) {}

  virtual ~SimplePromMetric() = default;
  virtual std::string render() const = 0;
  virtual void reset() = 0;

  const std::string& name() const { return name_; }
  const std::string& help() const { return help_; }
  MetricType type() const { return type_; }

protected:
  std::string name_, help_;
  MetricType type_;
};

class ActivityGaugeMetric : public SimplePromMetric {
public:
  ActivityGaugeMetric(const std::string& name, const std::string& help)
      : SimplePromMetric(name, help, MetricType::kGauge) {}

  void set(double val) { value_.store(val, std::memory_order_relaxed); }
  double value() const { return value_.load(std::memory_order_relaxed); }

  std::string render() const override {
    std::stringstream ss;
    ss << "# HELP " << name_ << " " << help_ << "\n";
    ss << "# TYPE " << name_ << " gauge\n";
    ss << name_ << " " << std::fixed << std::setprecision(2) << value() << "\n";
    std::lock_guard<std::mutex> lock(labels_mutex_);
    for (auto& [k, v] : labeled_) {
      ss << name_ << "{" << k << "} " << std::fixed << std::setprecision(2)
         << v.load(std::memory_order_relaxed) << "\n";
    }
    return ss.str();
  }

  void set_label(const std::string& labels, double val) {
    std::lock_guard<std::mutex> lock(labels_mutex_);
    labeled_[labels].store(val, std::memory_order_relaxed);
  }

  void reset() override {
    value_.store(0.0, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(labels_mutex_);
    labeled_.clear();
  }

private:
  std::atomic<double> value_{0.0};
  mutable std::mutex labels_mutex_;
  std::unordered_map<std::string, std::atomic<double>> labeled_;
};

class ActivityCounterMetric : public SimplePromMetric {
public:
  ActivityCounterMetric(const std::string& name, const std::string& help)
      : SimplePromMetric(name, help, MetricType::kCounter) {}

  void inc(double delta = 1.0) { value_.fetch_add(delta, std::memory_order_relaxed); }
  double value() const { return value_.load(std::memory_order_relaxed); }

  std::string render() const override {
    std::stringstream ss;
    ss << "# HELP " << name_ << " " << help_ << "\n";
    ss << "# TYPE " << name_ << " counter\n";
    ss << name_ << " " << std::fixed << std::setprecision(2) << value() << "\n";
    return ss.str();
  }

  void reset() override { value_.store(0.0, std::memory_order_relaxed); }

private:
  std::atomic<double> value_{0.0};
};

}  // anonymous namespace

// ============================================================================
// ActivitySnapshot — Core data transfer object for user activity
// ============================================================================

struct ActivitySnapshot {
  std::string user_id;
  std::string activity_date;
  int64_t last_activity_ts = 0;
  int64_t first_activity_ts = 0;

  // Activity counts
  int64_t message_count = 0;
  int64_t reaction_count = 0;
  int64_t redaction_count = 0;
  int64_t presence_updates = 0;
  int64_t sync_count = 0;
  int64_t rooms_joined = 0;
  int64_t rooms_left = 0;
  int64_t media_uploads = 0;

  // Device / session info
  int64_t devices_used = 0;
  int64_t session_count = 0;
  int64_t total_session_duration_sec = 0;

  // Computed fields
  bool is_active_today = false;
  bool is_active_this_week = false;
  bool is_active_this_month = false;
  int64_t streak_days = 0;
  int64_t consecutive_active_days = 0;

  json to_json() const {
    json j;
    j["user_id"] = user_id;
    j["activity_date"] = activity_date;
    j["last_activity_ts"] = last_activity_ts;
    j["first_activity_ts"] = first_activity_ts;

    json counts;
    counts["messages"] = message_count;
    counts["reactions"] = reaction_count;
    counts["redactions"] = redaction_count;
    counts["presence_updates"] = presence_updates;
    counts["syncs"] = sync_count;
    counts["rooms_joined"] = rooms_joined;
    counts["rooms_left"] = rooms_left;
    counts["media_uploads"] = media_uploads;
    j["counts"] = counts;

    json dev;
    dev["devices_used"] = devices_used;
    dev["sessions"] = session_count;
    dev["total_session_duration_sec"] = total_session_duration_sec;
    j["devices"] = dev;

    json flags;
    flags["active_today"] = is_active_today;
    flags["active_this_week"] = is_active_this_week;
    flags["active_this_month"] = is_active_this_month;
    flags["streak_days"] = streak_days;
    flags["consecutive_active_days"] = consecutive_active_days;
    j["flags"] = flags;

    return j;
  }
};

// ============================================================================
// DAU/MAU Data Transfer Objects
// ============================================================================

struct DAUSnapshot {
  std::string date;
  int64_t dau_count = 0;
  int64_t new_users = 0;
  int64_t returning_users = 0;
  int64_t churned_users = 0;
  double dau_growth_7d = 0.0;
  double dau_growth_30d = 0.0;

  json to_json() const {
    json j;
    j["date"] = date;
    j["dau"] = dau_count;
    j["new_users"] = new_users;
    j["returning_users"] = returning_users;
    j["churned_users"] = churned_users;
    j["dau_growth_7d"] = dau_growth_7d;
    j["dau_growth_30d"] = dau_growth_30d;
    return j;
  }
};

struct MAUSnapshot {
  std::string period_start;
  std::string period_end;
  int64_t mau_count = 0;
  int64_t new_mau = 0;
  int64_t retained_mau = 0;
  int64_t resurrected_mau = 0;
  int64_t churned_mau = 0;
  double mau_growth = 0.0;
  double dau_mau_stickiness = 0.0;

  json to_json() const {
    json j;
    j["period_start"] = period_start;
    j["period_end"] = period_end;
    j["mau"] = mau_count;
    j["new"] = new_mau;
    j["retained"] = retained_mau;
    j["resurrected"] = resurrected_mau;
    j["churned"] = churned_mau;
    j["growth"] = mau_growth;
    j["dau_mau_stickiness"] = dau_mau_stickiness;
    return j;
  }
};

// ============================================================================
// Session Data Objects
// ============================================================================

struct UserSession {
  std::string session_id;
  std::string user_id;
  std::string device_id;
  std::string ip_address;
  std::string user_agent;
  int64_t start_ts_ms = 0;
  int64_t end_ts_ms = 0;
  int64_t last_activity_ts_ms = 0;
  int64_t duration_ms = 0;
  int64_t event_count = 0;
  bool is_active = false;
  bool is_idle = false;

  json to_json() const {
    json j;
    j["session_id"] = session_id;
    j["user_id"] = user_id;
    j["device_id"] = device_id;
    j["ip_address"] = ip_address;
    j["user_agent"] = user_agent;
    j["start_ts_ms"] = start_ts_ms;
    j["end_ts_ms"] = end_ts_ms;
    j["last_activity_ts_ms"] = last_activity_ts_ms;
    j["duration_ms"] = duration_ms;
    j["event_count"] = event_count;
    j["is_active"] = is_active;
    j["is_idle"] = is_idle;
    return j;
  }
};

// ============================================================================
// Engagement Score Data Object
// ============================================================================

struct EngagementScore {
  std::string user_id;
  double score = 0.0;         // 0-100
  double percentile = 0.0;    // 0-100
  std::string tier;           // "power", "core", "casual", "dormant", "ghost"
  double message_score = 0.0;
  double room_score = 0.0;
  double session_score = 0.0;
  double reaction_score = 0.0;
  double days_active_score = 0.0;
  double recency_score = 0.0;
  double media_score = 0.0;
  int64_t days_since_last_active = 0;
  int64_t computed_ts = 0;

  json to_json() const {
    json j;
    j["user_id"] = user_id;
    j["score"] = score;
    j["percentile"] = percentile;
    j["tier"] = tier;
    j["message_score"] = message_score;
    j["room_score"] = room_score;
    j["session_score"] = session_score;
    j["reaction_score"] = reaction_score;
    j["days_active_score"] = days_active_score;
    j["recency_score"] = recency_score;
    j["media_score"] = media_score;
    j["days_since_last_active"] = days_since_last_active;
    j["computed_ts"] = computed_ts;
    return j;
  }

  json to_summary_json() const {
    return json{{"user_id", user_id}, {"score", score},
                {"percentile", percentile}, {"tier", tier}};
  }
};

// ============================================================================
// Activity Heatmap Data Object
// ============================================================================

struct ActivityHeatmap {
  // day_of_week (0=Mon..6=Sun) -> hour (0-23) -> count
  std::vector<std::vector<int64_t>> dow_hour; // 7x24
  // date_str -> count (for calendar heatmap)
  std::map<std::string, int64_t> date_counts;
  int64_t max_count = 0;
  int64_t total_count = 0;
  std::string period_start;
  std::string period_end;

  json to_json() const {
    json j;
    json dwh = json::array();
    for (int d = 0; d < 7 && static_cast<size_t>(d) < dow_hour.size(); d++) {
      json day = json::array();
      for (int h = 0; h < 24 && static_cast<size_t>(h) < dow_hour[d].size(); h++) {
        day.push_back(dow_hour[d][h]);
      }
      dwh.push_back(day);
    }
    j["dow_hour"] = dwh;
    j["date_counts"] = date_counts;
    j["max_count"] = max_count;
    j["total_count"] = total_count;
    j["period_start"] = period_start;
    j["period_end"] = period_end;
    return j;
  }
};

// ============================================================================
// Retention Data Object
// ============================================================================

struct RetentionCurve {
  int64_t cohort_size = 0;
  std::string cohort_label;
  std::vector<double> retention_rates;  // day 0,1,3,7,14,30,60,90
  std::vector<int64_t> retained_counts;

  json to_json() const {
    json j;
    j["cohort_size"] = cohort_size;
    j["cohort_label"] = cohort_label;
    j["retention_rates"] = retention_rates;
    j["retained_counts"] = retained_counts;
    return j;
  }
};

// ============================================================================
// Peak Usage Data Object
// ============================================================================

struct PeakUsageData {
  int64_t peak_hour_ts = 0;
  int64_t peak_count = 0;
  int64_t avg_hourly = 0;
  int64_t min_hourly = std::numeric_limits<int64_t>::max();
  std::vector<int64_t> hourly_distribution;  // 24 hours
  std::vector<int64_t> daily_distribution;   // 7 days
  std::vector<std::pair<std::string, int64_t>> top_peak_days;
  double seasonality_strength = 0.0;

  json to_json() const {
    json j;
    j["peak_hour_ts"] = peak_hour_ts;
    j["peak_hour_iso"] = iso_datetime(peak_hour_ts);
    j["peak_count"] = peak_count;
    j["avg_hourly"] = avg_hourly;
    j["min_hourly"] = min_hourly;
    j["hourly_distribution"] = hourly_distribution;
    j["daily_distribution"] = daily_distribution;
    json top_days = json::array();
    for (auto& [date, cnt] : top_peak_days) {
      top_days.push_back({{"date", date}, {"count", cnt}});
    }
    j["top_peak_days"] = top_days;
    j["seasonality_strength"] = seasonality_strength;
    return j;
  }
};

// ============================================================================
// Activity Timeline Bucket Data Object
// ============================================================================

struct ActivityTimelineBucket {
  std::string bucket_label;  // date, week, month, etc.
  int64_t active_users = 0;
  int64_t new_users = 0;
  int64_t messages = 0;
  int64_t reactions = 0;
  int64_t sessions = 0;
  double avg_session_duration_sec = 0.0;

  json to_json() const {
    json j;
    j["bucket"] = bucket_label;
    j["active_users"] = active_users;
    j["new_users"] = new_users;
    j["messages"] = messages;
    j["reactions"] = reactions;
    j["sessions"] = sessions;
    j["avg_session_duration_sec"] = avg_session_duration_sec;
    return j;
  }
};

// ============================================================================
// 1. DailyActiveUsersEngine — DAU computation with trends, series, growth
// ============================================================================

class DailyActiveUsersEngine {
public:
  explicit DailyActiveUsersEngine(storage::DatabasePool& db, ActivityDataCache& cache)
      : db_(db), cache_(cache), logger_(get_activity_logger("DAU")) {}

  // ---- Current DAU value ----
  int64_t compute_current_dau() {
    std::string today = iso_date(now_sec());
    int64_t cached = cache_.get_dau(today);
    if (cached >= 0) return cached;

    int64_t dau = db_.runInteraction(
        "activity_current_dau",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          txn.execute(
              "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
              "WHERE visit_date = ? AND user_id NOT LIKE '@appservice:%'",
              {today});
          auto row = txn.fetchone();
          return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
        });

    cache_.set_dau(today, dau);
    metrics_.dau_current.set(static_cast<double>(dau));
    return dau;
  }

  // ---- DAU time series ----
  std::vector<DAUSnapshot> get_dau_time_series(int64_t days = 90) {
    std::string cache_key = "dau_series_" + std::to_string(days);
    auto cached = cache_.get_json(cache_key);
    if (!cached.empty()) {
      std::vector<DAUSnapshot> result;
      for (auto& item : cached) {
        DAUSnapshot snap;
        snap.date = item.value("date", "");
        snap.dau_count = item.value("dau", 0);
        snap.new_users = item.value("new_users", 0);
        snap.returning_users = item.value("returning_users", 0);
        snap.churned_users = item.value("churned_users", 0);
        snap.dau_growth_7d = item.value("dau_growth_7d", 0.0);
        snap.dau_growth_30d = item.value("dau_growth_30d", 0.0);
        result.push_back(snap);
      }
      if (!result.empty()) return result;
    }

    auto result = db_.runInteraction(
        "activity_dau_series",
        [&](storage::LoggingTransaction& txn) -> std::vector<DAUSnapshot> {
          std::vector<DAUSnapshot> series;
          std::string from_date = iso_date(days_ago_sec(days));

          txn.execute(
              "SELECT visit_date, COUNT(DISTINCT user_id) as dau "
              "FROM user_daily_visits "
              "WHERE visit_date >= ? "
              "AND user_id NOT LIKE '@appservice:%' "
              "GROUP BY visit_date ORDER BY visit_date ASC",
              {from_date});

          auto rows = txn.fetchall();
          std::vector<int64_t> dau_values;
          for (auto& row : rows) {
            DAUSnapshot snap;
            snap.date = row[0].value.value_or("");
            snap.dau_count = row[1].value ? std::stoll(*row[1].value) : 0;
            dau_values.push_back(snap.dau_count);
            series.push_back(snap);
          }

          // Compute new/returning/churned for each day
          for (size_t i = 0; i < series.size(); i++) {
            if (i > 0) {
              int64_t prev_dau = series[i-1].dau_count;
              series[i].returning_users = std::min(series[i].dau_count, prev_dau);
              series[i].churned_users = std::max(int64_t(0), prev_dau - series[i].dau_count);
            }
            // New users registered on that day
            txn.execute(
                "SELECT COUNT(*) FROM users "
                "WHERE strftime('%Y-%m-%d', datetime(creation_ts, 'unixepoch')) = ? "
                "AND deactivated = 0",
                {series[i].date});
            auto r2 = txn.fetchone();
            series[i].new_users = (r2 && r2[0].value) ? std::stoll(*r2[0].value) : 0;
          }

          // Growth rates
          for (size_t i = 0; i < series.size(); i++) {
            if (i >= 7) {
              int64_t prev = series[i-7].dau_count;
              series[i].dau_growth_7d = safe_divide(
                  series[i].dau_count - prev, prev) * 100.0;
            }
            if (i >= 30) {
              int64_t prev = series[i-30].dau_count;
              series[i].dau_growth_30d = safe_divide(
                  series[i].dau_count - prev, prev) * 100.0;
            }
          }

          return series;
        });

    // Cache the result
    json arr = json::array();
    for (auto& s : result) arr.push_back(s.to_json());
    cache_.set_json(cache_key, arr, kDAUCacheTTLSeconds);

    if (!result.empty()) {
      metrics_.dau_current.set(static_cast<double>(result.back().dau_count));
    }
    return result;
  }

  // ---- DAU trend analysis ----
  json get_dau_trend_analysis(int64_t days = 30) {
    auto series = get_dau_time_series(days);
    if (series.empty()) return json{{"error", "no_data"}};

    std::vector<int64_t> values;
    for (auto& s : series) values.push_back(s.dau_count);

    double trend = compute_linear_trend(values);
    double avg_7d = compute_moving_average(values, 7);
    double avg_30d = compute_moving_average(values, std::min(30, (int)values.size()));

    json result;
    result["current_dau"] = values.back();
    result["trend_slope"] = trend;
    result["trend_direction"] = trend > 0.5 ? "growing" : trend < -0.5 ? "declining" : "stable";
    result["avg_7d"] = avg_7d;
    result["avg_30d"] = avg_30d;
    result["min_7d"] = values.size() >= 7
        ? *std::min_element(values.end() - 7, values.end())
        : *std::min_element(values.begin(), values.end());
    result["max_7d"] = values.size() >= 7
        ? *std::max_element(values.end() - 7, values.end())
        : *std::max_element(values.begin(), values.end());

    // Anomaly detection
    auto z_scores = compute_z_scores(values);
    json anomalies = json::array();
    for (size_t i = 0; i < z_scores.size(); i++) {
      if (std::abs(z_scores[i]) > 2.0) {
        anomalies.push_back({{"index", i}, {"z_score", z_scores[i]},
                             {"date", series[i].date}, {"value", values[i]}});
      }
    }
    result["anomalies"] = anomalies;

    return result;
  }

  // ---- DAU forecast (simple linear) ----
  json forecast_dau(int64_t forecast_days = 7) {
    auto series = get_dau_time_series(std::max(int64_t(60), forecast_days * 4));
    if (series.empty()) return json{{"error", "no_data"}};

    std::vector<int64_t> values;
    for (auto& s : series) values.push_back(s.dau_count);

    double trend = compute_linear_trend(values);
    double last = static_cast<double>(values.back());

    json result;
    result["current"] = values.back();
    result["trend_per_day"] = trend;
    json forecast = json::array();
    for (int64_t i = 1; i <= forecast_days; i++) {
      double predicted = last + trend * i;
      int64_t ts = now_sec() + i * 86400;
      forecast.push_back({{"date", iso_date(ts)}, {"predicted_dau", std::max(0.0, predicted)}});
    }
    result["forecast"] = forecast;
    return result;
  }

  // ---- DAU by device type ----
  json get_dau_by_device_type(const std::string& date = "") {
    std::string target_date = date.empty() ? iso_date(now_sec()) : date;
    return db_.runInteraction(
        "activity_dau_devices",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;
          txn.execute(
              "SELECT d.user_agent, COUNT(DISTINCT udv.user_id) "
              "FROM user_daily_visits udv "
              "JOIN devices d ON udv.user_id = d.user_id "
              "WHERE udv.visit_date = ? AND udv.user_id NOT LIKE '@appservice:%' "
              "GROUP BY "
              "CASE "
              "  WHEN d.user_agent LIKE '%Electron%' OR d.user_agent LIKE '%Element%' THEN 'desktop' "
              "  WHEN d.user_agent LIKE '%Android%' OR d.user_agent LIKE '%iOS%' THEN 'mobile' "
              "  WHEN d.user_agent LIKE '%Web%' OR d.user_agent LIKE '%Mozilla%' THEN 'web' "
              "  ELSE 'other' "
              "END",
              {target_date});
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            result[row[0].value.value_or("unknown")] = row[1].value
                ? std::stoll(*row[1].value) : 0;
          }
          return result;
        });
  }

  // ---- DAU growth rate ----
  double get_dau_growth_rate(int64_t days = 7) {
    auto series = get_dau_time_series(std::max(days + 1, int64_t(8)));
    if (series.size() < static_cast<size_t>(days + 1)) return 0.0;
    auto current = series.back().dau_count;
    auto previous = series[series.size() - 1 - days].dau_count;
    return safe_divide(current - previous, previous) * 100.0;
  }

  // ---- DAU YoY comparison ----
  json get_dau_yoy_comparison() {
    std::string today = iso_date(now_sec());
    std::string year_ago = iso_date(now_sec() - 365 * 86400);
    std::string year_ago_end = iso_date(now_sec() - 364 * 86400);

    return db_.runInteraction(
        "activity_dau_yoy",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;

          txn.execute(
              "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
              "WHERE visit_date = ? AND user_id NOT LIKE '@appservice:%'",
              {today});
          auto row = txn.fetchone();
          int64_t current = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          // Approximate last year same day (within a week for robustness)
          txn.execute(
              "SELECT AVG(daily_dau) FROM ("
              "  SELECT COUNT(DISTINCT user_id) as daily_dau FROM user_daily_visits "
              "  WHERE visit_date BETWEEN ? AND ? "
              "  AND user_id NOT LIKE '@appservice:%' "
              "  GROUP BY visit_date"
              ")",
              {year_ago, year_ago_end});
          row = txn.fetchone();
          double prev_avg = row ? std::stod(row->at(0).value.value_or("0")) : 0.0;

          result["current_dau"] = current;
          result["yoy_dau"] = prev_avg;
          result["yoy_change_pct"] = safe_divide(current - prev_avg, prev_avg) * 100.0;
          return result;
        });
  }

private:
  storage::DatabasePool& db_;
  ActivityDataCache& cache_;
  ActivityLogger& logger_;

  struct DAUMetrics {
    ActivityGaugeMetric dau_current{"progressive_activity_dau",
                                     "Daily Active Users"};
  };
  DAUMetrics metrics_;
};

// ============================================================================
// 2. MonthlyActiveUsersEngine — MAU computation with rolling/fixed windows
// ============================================================================

class MonthlyActiveUsersEngine {
public:
  explicit MonthlyActiveUsersEngine(storage::DatabasePool& db, ActivityDataCache& cache)
      : db_(db), cache_(cache), logger_(get_activity_logger("MAU")) {}

  // ---- Current MAU (rolling 30-day) ----
  int64_t compute_current_mau() {
    int64_t cached = cache_.get_mau("current");
    if (cached >= 0) return cached;

    std::string thirty_days_ago = iso_date(days_ago_sec(30));
    int64_t mau = db_.runInteraction(
        "activity_current_mau",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          txn.execute(
              "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
              "WHERE visit_date >= ? AND user_id NOT LIKE '@appservice:%'",
              {thirty_days_ago});
          auto row = txn.fetchone();
          return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
        });

    cache_.set_mau("current", mau);
    metrics_.mau_current.set(static_cast<double>(mau));
    return mau;
  }

  // ---- Calendar-month MAU ----
  int64_t compute_calendar_month_mau(int year = 0, int month = 0) {
    if (year == 0 || month == 0) {
      auto now = chr::system_clock::now();
      auto tt = chr::system_clock::to_time_t(now);
      auto* utc = std::gmtime(&tt);
      year = utc->tm_year + 1900;
      month = utc->tm_mon + 1;
    }

    std::string month_str = (month < 10 ? "0" : "") + std::to_string(month);
    std::string start_date = std::to_string(year) + "-" + month_str + "-01";
    std::string end_date = (month == 12)
        ? std::to_string(year + 1) + "-01-01"
        : std::to_string(year) + "-" + (month < 9 ? "0" : "")
            + std::to_string(month + 1) + "-01";

    return db_.runInteraction(
        "activity_calendar_mau",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          txn.execute(
              "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
              "WHERE visit_date >= ? AND visit_date < ? "
              "AND user_id NOT LIKE '@appservice:%'",
              {start_date, end_date});
          auto row = txn.fetchone();
          return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
        });
  }

  // ---- MAU time series ----
  std::vector<MAUSnapshot> get_mau_time_series(int64_t months = 12) {
    std::string cache_key = "mau_series_" + std::to_string(months);
    auto cached = cache_.get_json(cache_key);
    if (!cached.empty()) {
      std::vector<MAUSnapshot> result;
      for (auto& item : cached) {
        MAUSnapshot snap;
        snap.period_start = item.value("period_start", "");
        snap.period_end = item.value("period_end", "");
        snap.mau_count = item.value("mau", 0);
        snap.new_mau = item.value("new", 0);
        snap.retained_mau = item.value("retained", 0);
        snap.resurrected_mau = item.value("resurrected", 0);
        snap.churned_mau = item.value("churned", 0);
        snap.mau_growth = item.value("growth", 0.0);
        snap.dau_mau_stickiness = item.value("dau_mau_stickiness", 0.0);
        result.push_back(snap);
      }
      if (!result.empty()) return result;
    }

    auto result = db_.runInteraction(
        "activity_mau_series",
        [&](storage::LoggingTransaction& txn) -> std::vector<MAUSnapshot> {
          std::vector<MAUSnapshot> series;

          for (int64_t m = months; m >= 0; m--) {
            int64_t period_end   = days_ago_sec(m * 30);
            int64_t period_start = days_ago_sec((m + 1) * 30);

            MAUSnapshot snap;
            snap.period_start = iso_date(period_start);
            snap.period_end   = iso_date(period_end);

            txn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
                "WHERE visit_date >= ? AND visit_date < ? "
                "AND user_id NOT LIKE '@appservice:%'",
                {snap.period_start, snap.period_end});
            auto row = txn.fetchone();
            snap.mau_count = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            // New users in period
            txn.execute(
                "SELECT COUNT(*) FROM users "
                "WHERE creation_ts >= ? AND creation_ts < ? AND deactivated = 0 "
                "AND name NOT LIKE '@appservice:%'",
                {std::to_string(period_start), std::to_string(period_end)});
            row = txn.fetchone();
            snap.new_mau = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            // Growth compared to previous month
            if (!series.empty()) {
              int64_t prev = series.back().mau_count;
              snap.mau_growth = safe_divide(snap.mau_count - prev, prev) * 100.0;
            }

            series.push_back(snap);
          }

          return series;
        });

    // Add DAU/MAU stickiness
    auto dau_engine = DailyActiveUsersEngine(db_, cache_);
    int64_t current_dau = dau_engine.compute_current_dau();
    int64_t current_mau = result.empty() ? 0 : result.back().mau_count;
    if (current_mau > 0) {
      for (auto& snap : result) {
        if (snap.mau_count > 0 && &snap == &result.back()) {
          snap.dau_mau_stickiness = std::round(
              safe_divide(current_dau, current_mau) * 10000.0) / 100.0;
        }
      }
    }

    // Cache
    json arr = json::array();
    for (auto& s : result) arr.push_back(s.to_json());
    cache_.set_json(cache_key, arr, kMAUCacheTTLSeconds);

    if (!result.empty()) {
      metrics_.mau_current.set(static_cast<double>(result.back().mau_count));
      metrics_.stickiness.set(result.back().dau_mau_stickiness);
    }
    return result;
  }

  // ---- MAU breakdown by activity type ----
  json get_mau_by_activity_type(int64_t days = 30) {
    std::string from_date = iso_date(days_ago_sec(days));
    return db_.runInteraction(
        "activity_mau_breakdown",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;
          std::vector<std::pair<std::string, std::string>> types = {
            {"m.room.message", "messaging"},
            {"m.reaction", "reacting"},
            {"m.room.redaction", "redacting"},
            {"m.room.member", "room_actions"},
            {"m.presence", "presence"},
          };
          for (auto& [event_type, label] : types) {
            txn.execute(
                "SELECT COUNT(DISTINCT sender) FROM events "
                "WHERE type = ? AND origin_server_ts >= ? "
                "AND sender NOT LIKE '@appservice:%'",
                {event_type, std::to_string(days_ago_sec(days))});
            auto row = txn.fetchone();
            result[label] = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          }
          return result;
        });
  }

  // ---- MAU trend ----
  json get_mau_trend(int64_t months = 12) {
    auto series = get_mau_time_series(months);
    if (series.size() < 3) return json{{"error", "insufficient_data"}};

    std::vector<int64_t> values;
    for (auto& s : series) values.push_back(s.mau_count);

    double trend = compute_linear_trend(values);
    json result;
    result["current_mau"] = values.back();
    result["trend_per_month"] = trend * 30; // convert to monthly
    result["trend_direction"] = trend > 1.0 ? "growing"
        : trend < -1.0 ? "declining" : "stable";
    result["series"] = json::array();
    for (auto& s : series) result["series"].push_back(s.to_json());
    return result;
  }

  // ---- DAU/MAU stickiness ratio ----
  double get_stickiness_ratio() {
    int64_t dau = dau_engine_->compute_current_dau();
    int64_t mau = compute_current_mau();
    double ratio = mau > 0 ? (static_cast<double>(dau) / static_cast<double>(mau)) * 100.0 : 0.0;
    metrics_.stickiness.set(ratio);
    return ratio;
  }

  void set_dau_engine(DailyActiveUsersEngine* dau_engine) {
    dau_engine_ = dau_engine;
  }

private:
  storage::DatabasePool& db_;
  ActivityDataCache& cache_;
  ActivityLogger& logger_;
  DailyActiveUsersEngine* dau_engine_ = nullptr;

  struct MAUMetrics {
    ActivityGaugeMetric mau_current{"progressive_activity_mau",
                                     "Monthly Active Users"};
    ActivityGaugeMetric stickiness{"progressive_activity_stickiness",
                                    "DAU/MAU stickiness ratio"};
  };
  MAUMetrics metrics_;
};

// ============================================================================
// 3. WeeklyActiveUsersEngine — WAU with week-over-week analysis
// ============================================================================

class WeeklyActiveUsersEngine {
public:
  explicit WeeklyActiveUsersEngine(storage::DatabasePool& db, ActivityDataCache& cache)
      : db_(db), cache_(cache), logger_(get_activity_logger("WAU")) {}

  // ---- Current WAU (rolling 7-day) ----
  int64_t compute_current_wau() {
    std::string seven_days_ago = iso_date(days_ago_sec(7));
    return db_.runInteraction(
        "activity_current_wau",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          txn.execute(
              "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
              "WHERE visit_date >= ? AND user_id NOT LIKE '@appservice:%'",
              {seven_days_ago});
          auto row = txn.fetchone();
          return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
        });
  }

  // ---- WAU time series ----
  json get_wau_time_series(int64_t weeks = 52) {
    return db_.runInteraction(
        "activity_wau_series",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();

          for (int64_t w = weeks; w >= 0; w--) {
            int64_t week_end   = days_ago_sec(w * 7);
            int64_t week_start = days_ago_sec((w + 1) * 7);

            txn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
                "WHERE visit_date >= ? AND visit_date < ? "
                "AND user_id NOT LIKE '@appservice:%'",
                {iso_date(week_start), iso_date(week_end)});
            auto row = txn.fetchone();
            int64_t wau = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            json point;
            point["week_start"] = iso_week_str(week_start);
            point["wau"] = wau;
            result.push_back(point);
          }

          // Add WoW growth
          for (size_t i = 1; i < result.size(); i++) {
            int64_t prev = result[i-1]["wau"];
            int64_t curr = result[i]["wau"];
            result[i]["wow_growth_pct"] = safe_divide(curr - prev, prev) * 100.0;
          }

          return result;
        });
  }

  // ---- WAU/MAU ratio ----
  double get_wau_mau_ratio(int64_t mau) {
    int64_t wau = compute_current_wau();
    return mau > 0 ? (static_cast<double>(wau) / static_cast<double>(mau)) * 100.0 : 0.0;
  }

  // ---- Weekend vs Weekday activity ----
  json get_weekend_weekday_split() {
    return db_.runInteraction(
        "activity_weekend_split",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;
          std::string week_start = iso_date(days_ago_sec(30));

          // Weekday average (Mon-Fri)
          txn.execute(
              "SELECT AVG(daily_dau) FROM ("
              "  SELECT visit_date, COUNT(DISTINCT user_id) as daily_dau "
              "  FROM user_daily_visits "
              "  WHERE visit_date >= ? AND CAST(strftime('%w', visit_date) AS INTEGER) "
              "  BETWEEN 1 AND 5 "
              "  AND user_id NOT LIKE '@appservice:%' "
              "  GROUP BY visit_date"
              ")",
              {week_start});
          auto row = txn.fetchone();
          result["weekday_avg"] = row ? std::stod(row->at(0).value.value_or("0")) : 0.0;

          // Weekend average (Sat-Sun)
          txn.execute(
              "SELECT AVG(daily_dau) FROM ("
              "  SELECT visit_date, COUNT(DISTINCT user_id) as daily_dau "
              "  FROM user_daily_visits "
              "  WHERE visit_date >= ? AND (CAST(strftime('%w', visit_date) AS INTEGER) = 0 "
              "  OR CAST(strftime('%w', visit_date) AS INTEGER) = 6) "
              "  AND user_id NOT LIKE '@appservice:%' "
              "  GROUP BY visit_date"
              ")",
              {week_start});
          row = txn.fetchone();
          result["weekend_avg"] = row ? std::stod(row->at(0).value.value_or("0")) : 0.0;

          return result;
        });
  }

private:
  storage::DatabasePool& db_;
  ActivityDataCache& cache_;
  ActivityLogger& logger_;
};

// ============================================================================
// 4. ActivityTimelineTracker — Per-user and server-wide activity timelines
// ============================================================================

class ActivityTimelineTracker {
public:
  explicit ActivityTimelineTracker(storage::DatabasePool& db, ActivityDataCache& cache)
      : db_(db), cache_(cache), logger_(get_activity_logger("Timeline")) {}

  // ---- Record user daily visit ----
  void record_daily_visit(const std::string& user_id,
                          const std::string& device_id = "",
                          const std::string& activity_type = "sync") {
    std::string today = iso_date(now_sec());
    int64_t ts = now_sec();

    db_.runInteraction(
        "activity_record_visit",
        [&](storage::LoggingTransaction& txn) {
          // UPSERT into user_daily_visits
          txn.execute(
              "INSERT INTO user_daily_visits (user_id, visit_date, last_visit_ts, "
              "device_id, activity_count) "
              "VALUES (?, ?, ?, ?, 1) "
              "ON CONFLICT(user_id, visit_date) DO UPDATE SET "
              "last_visit_ts = MAX(last_visit_ts, excluded.last_visit_ts), "
              "activity_count = activity_count + 1, "
              "device_id = CASE WHEN excluded.device_id != '' "
              "  THEN excluded.device_id ELSE device_id END",
              {user_id, today, std::to_string(ts), device_id});
        });

    // Invalidate related caches
    cache_.invalidate("dau_current");
    cache_.invalidate("timeline_" + user_id);
    logger_.debug("Recorded daily visit for user " + user_id);
  }

  // ---- Record activity event ----
  void record_activity_event(const std::string& user_id,
                              const std::string& room_id,
                              const std::string& event_type,
                              const std::string& device_id = "",
                              const std::string& event_id = "") {
    int64_t ts = now_ms();

    db_.runInteraction(
        "activity_record_event",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "INSERT INTO user_activity_log (user_id, room_id, event_type, "
              "device_id, event_id, timestamp_ms, hour_bucket, dow, date_str) "
              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
              {user_id, room_id, event_type, device_id, event_id,
               std::to_string(ts),
               std::to_string(hour_of_day(ts / 1000)),
               std::to_string(day_of_week(ts / 1000)),
               iso_date(ts / 1000)});
        });

    // Also record the daily visit
    record_daily_visit(user_id, device_id, event_type);
  }

  // ---- Get per-user activity timeline ----
  json get_user_timeline(const std::string& user_id,
                          const std::string& bucket = "daily",
                          int64_t days = 90) {
    std::string cache_key = "timeline_" + user_id + "_" + bucket + "_"
        + std::to_string(days);
    auto cached = cache_.get_json(cache_key);
    if (!cached.empty()) return cached;

    auto result = db_.runInteraction(
        "activity_user_timeline",
        [&](storage::LoggingTransaction& txn) -> json {
          std::string date_func;
          if (bucket == "monthly") {
            date_func = "strftime('%Y-%m', datetime(timestamp_ms/1000, 'unixepoch'))";
          } else if (bucket == "weekly") {
            date_func = "strftime('%Y-%W', datetime(timestamp_ms/1000, 'unixepoch'))";
          } else {
            date_func = "strftime('%Y-%m-%d', datetime(timestamp_ms/1000, 'unixepoch'))";
          }

          int64_t from_ts = days_ago_ms(days);
          std::string query =
              "SELECT " + date_func + " as bucket, "
              "COUNT(*) as total_events, "
              "COUNT(DISTINCT room_id) as rooms_active, "
              "SUM(CASE WHEN event_type = 'message' THEN 1 ELSE 0 END) as messages, "
              "SUM(CASE WHEN event_type = 'reaction' THEN 1 ELSE 0 END) as reactions, "
              "COUNT(DISTINCT device_id) as devices "
              "FROM user_activity_log "
              "WHERE user_id = ? AND timestamp_ms >= ? "
              "GROUP BY bucket ORDER BY bucket ASC";

          txn.execute(query, {user_id, std::to_string(from_ts)});
          json result = json::array();
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            json point;
            point["bucket"] = row[0].value.value_or("");
            point["total_events"] = row[1].value ? std::stoll(*row[1].value) : 0;
            point["rooms_active"] = row[2].value ? std::stoll(*row[2].value) : 0;
            point["messages"] = row[3].value ? std::stoll(*row[3].value) : 0;
            point["reactions"] = row[4].value ? std::stoll(*row[4].value) : 0;
            point["devices"] = row[5].value ? std::stoll(*row[5].value) : 0;
            result.push_back(point);
          }
          return result;
        });

    cache_.set_json(cache_key, result, kTimelineCacheTTLSeconds);
    return result;
  }

  // ---- Get server-wide activity timeline ----
  std::vector<ActivityTimelineBucket> get_server_timeline(
      const std::string& bucket = "daily", int64_t periods = 90) {
    std::string cache_key = "server_timeline_" + bucket + "_" + std::to_string(periods);
    auto cached = cache_.get_json(cache_key);
    if (!cached.empty()) {
      std::vector<ActivityTimelineBucket> result;
      for (auto& item : cached) {
        ActivityTimelineBucket b;
        b.bucket_label = item.value("bucket", "");
        b.active_users = item.value("active_users", 0);
        b.new_users = item.value("new_users", 0);
        b.messages = item.value("messages", 0);
        b.reactions = item.value("reactions", 0);
        b.sessions = item.value("sessions", 0);
        b.avg_session_duration_sec = item.value("avg_session_duration_sec", 0.0);
        result.push_back(b);
      }
      if (!result.empty()) return result;
    }

    auto result = db_.runInteraction(
        "activity_server_timeline",
        [&](storage::LoggingTransaction& txn) -> std::vector<ActivityTimelineBucket> {
          std::vector<ActivityTimelineBucket> buckets;

          std::string date_func;
          int64_t period_sec;
          if (bucket == "monthly") {
            date_func = "strftime('%Y-%m', datetime(timestamp_ms/1000, 'unixepoch'))";
            period_sec = 2592000;
          } else if (bucket == "weekly") {
            date_func = "strftime('%Y-%W', datetime(timestamp_ms/1000, 'unixepoch'))";
            period_sec = 604800;
          } else {
            date_func = "strftime('%Y-%m-%d', datetime(timestamp_ms/1000, 'unixepoch'))";
            period_sec = 86400;
          }

          int64_t from_ts = days_ago_ms(static_cast<int>(periods * period_sec / 86400));
          std::string query =
              "SELECT " + date_func + " as bucket, "
              "COUNT(DISTINCT user_id) as active_users, "
              "COUNT(*) as total_events, "
              "SUM(CASE WHEN event_type = 'message' THEN 1 ELSE 0 END) as messages, "
              "SUM(CASE WHEN event_type = 'reaction' THEN 1 ELSE 0 END) as reactions "
              "FROM user_activity_log "
              "WHERE timestamp_ms >= ? AND user_id NOT LIKE '@appservice:%' "
              "GROUP BY bucket ORDER BY bucket ASC";

          txn.execute(query, {std::to_string(from_ts)});
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            ActivityTimelineBucket b;
            b.bucket_label = row[0].value.value_or("");
            b.active_users = row[1].value ? std::stoll(*row[1].value) : 0;
            b.messages = row[3].value ? std::stoll(*row[3].value) : 0;
            b.reactions = row[4].value ? std::stoll(*row[4].value) : 0;
            buckets.push_back(b);
          }

          // Add new users per period
          for (auto& bucket : buckets) {
            int64_t start = parse_date_to_sec(bucket.bucket_label);
            int64_t end = start + period_sec;
            txn.execute(
                "SELECT COUNT(*) FROM users "
                "WHERE creation_ts >= ? AND creation_ts < ? AND deactivated = 0",
                {std::to_string(start), std::to_string(end)});
            auto row = txn.fetchone();
            bucket.new_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          }

          return buckets;
        });

    json arr = json::array();
    for (auto& b : result) arr.push_back(b.to_json());
    cache_.set_json(cache_key, arr, kTimelineCacheTTLSeconds);

    return result;
  }

  // ---- Cumulative activity curve ----
  json get_cumulative_activity_curve(int64_t days = 90) {
    std::string cache_key = "cumulative_curve_" + std::to_string(days);
    auto cached = cache_.get_json(cache_key);
    if (!cached.empty()) return cached;

    auto result = db_.runInteraction(
        "activity_cumulative",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          int64_t cumulative = 0;

          for (int64_t d = days; d >= 0; d--) {
            std::string date = iso_date(days_ago_sec(d));
            txn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
                "WHERE visit_date = ? AND user_id NOT LIKE '@appservice:%'",
                {date});
            auto row = txn.fetchone();
            int64_t day_users = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
            cumulative += day_users;

            json point;
            point["date"] = date;
            point["day_users"] = day_users;
            point["cumulative"] = cumulative;
            result.push_back(point);
          }
          return result;
        });

    cache_.set_json(cache_key, result, kTimelineCacheTTLSeconds);
    return result;
  }

private:
  storage::DatabasePool& db_;
  ActivityDataCache& cache_;
  ActivityLogger& logger_;
};

// ============================================================================
// 5. UserSessionTracker — Session start/end, duration, concurrency
// ============================================================================

class UserSessionTracker {
public:
  explicit UserSessionTracker(storage::DatabasePool& db, ActivityDataCache& cache)
      : db_(db), cache_(cache), logger_(get_activity_logger("Session")) {}

  // ---- Start a new session ----
  std::string start_session(const std::string& user_id,
                             const std::string& device_id,
                             const std::string& ip_address = "",
                             const std::string& user_agent = "") {
    std::string session_id = generate_session_id(user_id, device_id);
    int64_t ts_ms = now_ms();

    {
      std::lock_guard<std::mutex> lock(sessions_mutex_);
      UserSession session;
      session.session_id = session_id;
      session.user_id = user_id;
      session.device_id = device_id;
      session.ip_address = ip_address;
      session.user_agent = user_agent;
      session.start_ts_ms = ts_ms;
      session.last_activity_ts_ms = ts_ms;
      session.is_active = true;
      active_sessions_[session_id] = session;
    }

    db_.runInteraction(
        "activity_session_start",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "INSERT INTO user_activity_sessions "
              "(session_id, user_id, device_id, ip_address, user_agent, "
              "start_ts_ms, last_activity_ts_ms, is_active) "
              "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
              {session_id, user_id, device_id, ip_address, user_agent,
               std::to_string(ts_ms), std::to_string(ts_ms)});
        });

    metrics_.active_sessions.inc();
    logger_.debug("Session started: " + session_id + " for " + user_id);
    return session_id;
  }

  // ---- Update session activity ----
  void update_session_activity(const std::string& session_id) {
    int64_t ts_ms = now_ms();
    {
      std::lock_guard<std::mutex> lock(sessions_mutex_);
      auto it = active_sessions_.find(session_id);
      if (it != active_sessions_.end()) {
        it->second.last_activity_ts_ms = ts_ms;
        it->second.event_count++;
        it->second.is_idle = false;
      }
    }
    db_.runInteraction(
        "activity_session_update",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "UPDATE user_activity_sessions SET "
              "last_activity_ts_ms = ?, event_count = event_count + 1 "
              "WHERE session_id = ? AND is_active = 1",
              {std::to_string(ts_ms), session_id});
        });
  }

  // ---- End a session ----
  void end_session(const std::string& session_id) {
    int64_t ts_ms = now_ms();
    {
      std::lock_guard<std::mutex> lock(sessions_mutex_);
      auto it = active_sessions_.find(session_id);
      if (it != active_sessions_.end()) {
        it->second.end_ts_ms = ts_ms;
        it->second.is_active = false;
        it->second.duration_ms = ts_ms - it->second.start_ts_ms;
      }
    }

    db_.runInteraction(
        "activity_session_end",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "UPDATE user_activity_sessions SET "
              "end_ts_ms = ?, is_active = 0, "
              "duration_ms = end_ts_ms - start_ts_ms "
              "WHERE session_id = ?",
              {std::to_string(ts_ms), session_id});
        });

    metrics_.active_sessions.inc(-1);
    metrics_.session_duration.observe(
        static_cast<double>(ts_ms - get_session_start(session_id)) / 1000.0);
    logger_.debug("Session ended: " + session_id);
  }

  // ---- Get active session count ----
  int64_t get_active_session_count() {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    return static_cast<int64_t>(active_sessions_.size());
  }

  // ---- Get sessions for user ----
  std::vector<UserSession> get_user_sessions(const std::string& user_id,
                                               int64_t limit = 50) {
    return db_.runInteraction(
        "activity_user_sessions",
        [&](storage::LoggingTransaction& txn) -> std::vector<UserSession> {
          std::vector<UserSession> sessions;
          txn.execute(
              "SELECT session_id, user_id, device_id, ip_address, user_agent, "
              "start_ts_ms, end_ts_ms, last_activity_ts_ms, duration_ms, "
              "event_count, is_active "
              "FROM user_activity_sessions "
              "WHERE user_id = ? ORDER BY start_ts_ms DESC LIMIT ?",
              {user_id, std::to_string(limit)});
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            UserSession s;
            s.session_id = row[0].value.value_or("");
            s.user_id = row[1].value.value_or("");
            s.device_id = row[2].value.value_or("");
            s.ip_address = row[3].value.value_or("");
            s.user_agent = row[4].value.value_or("");
            s.start_ts_ms = row[5].value ? std::stoll(*row[5].value) : 0;
            s.end_ts_ms = row[6].value ? std::stoll(*row[6].value) : 0;
            s.last_activity_ts_ms = row[7].value ? std::stoll(*row[7].value) : 0;
            s.duration_ms = row[8].value ? std::stoll(*row[8].value) : 0;
            s.event_count = row[9].value ? std::stoll(*row[9].value) : 0;
            s.is_active = row[10].value && *row[10].value != "0";
            sessions.push_back(s);
          }
          return sessions;
        });
  }

  // ---- Session duration distribution ----
  json get_session_duration_distribution(int64_t days = 30) {
    return db_.runInteraction(
        "activity_session_dist",
        [&](storage::LoggingTransaction& txn) -> json {
          int64_t from_ts = days_ago_ms(days);
          json result;

          // Average duration
          txn.execute(
              "SELECT AVG(duration_ms), MEDIAN(duration_ms), "
              "MIN(duration_ms), MAX(duration_ms), COUNT(*) "
              "FROM user_activity_sessions "
              "WHERE start_ts_ms >= ? AND duration_ms > 0",
              {std::to_string(from_ts)});
          auto row = txn.fetchone();
          result["avg_duration_ms"] = row && row[0].value ? std::stod(*row[0].value) : 0.0;
          result["median_duration_ms"] = row && row[1].value ? std::stod(*row[1].value) : 0.0;
          result["min_duration_ms"] = row && row[2].value ? std::stoll(*row[2].value) : 0;
          result["max_duration_ms"] = row && row[3].value ? std::stoll(*row[3].value) : 0;
          result["total_sessions"] = row && row[4].value ? std::stoll(*row[4].value) : 0;

          // Bucketed distribution
          std::vector<std::pair<std::string, std::pair<int64_t, int64_t>>> buckets = {
            {"under_1min", {0, 60000}},
            {"1_5min", {60000, 300000}},
            {"5_15min", {300000, 900000}},
            {"15_30min", {900000, 1800000}},
            {"30_60min", {1800000, 3600000}},
            {"1_4hr", {3600000, 14400000}},
            {"4_8hr", {14400000, 28800000}},
            {"over_8hr", {28800000, std::numeric_limits<int64_t>::max()}},
          };

          for (auto& [label, range] : buckets) {
            txn.execute(
                "SELECT COUNT(*) FROM user_activity_sessions "
                "WHERE start_ts_ms >= ? AND duration_ms >= ? AND duration_ms < ?",
                {std::to_string(from_ts),
                 std::to_string(range.first), std::to_string(range.second)});
            row = txn.fetchone();
            result[label] = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          }

          return result;
        });
  }

  // ---- Cleanup idle sessions ----
  int64_t cleanup_idle_sessions() {
    int64_t cutoff = now_ms() - kSessionIdleTimeoutMs;
    int64_t closed = 0;

    {
      std::lock_guard<std::mutex> lock(sessions_mutex_);
      auto it = active_sessions_.begin();
      while (it != active_sessions_.end()) {
        if (it->second.last_activity_ts_ms < cutoff) {
          it->second.is_idle = true;
          it->second.is_active = false;
          it->second.end_ts_ms = now_ms();
          it->second.duration_ms = it->second.end_ts_ms - it->second.start_ts_ms;
          closed++;
          it = active_sessions_.erase(it);
        } else {
          ++it;
        }
      }
    }

    if (closed > 0) {
      db_.runInteraction(
          "activity_session_cleanup",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "UPDATE user_activity_sessions SET is_active = 0, "
                "end_ts_ms = last_activity_ts_ms, "
                "duration_ms = end_ts_ms - start_ts_ms "
                "WHERE is_active = 1 AND last_activity_ts_ms < ?",
                {std::to_string(cutoff)});
          });
      metrics_.active_sessions.inc(-closed);
    }

    return closed;
  }

  // ---- Concurrent session peak ----
  json get_concurrent_session_peak(int64_t days = 7) {
    return db_.runInteraction(
        "activity_concurrent_peak",
        [&](storage::LoggingTransaction& txn) -> json {
          int64_t from_ts = days_ago_ms(days);
          json result;

          // Approximate concurrency by counting overlapping sessions per hour
          txn.execute(
              "SELECT "
              "  strftime('%Y-%m-%dT%H:00:00Z', datetime(start_ts_ms/1000, 'unixepoch')) as hour, "
              "  COUNT(*) as concurrent_sessions "
              "FROM user_activity_sessions "
              "WHERE start_ts_ms >= ? AND is_active = 0 "
              "  AND end_ts_ms > start_ts_ms "
              "GROUP BY hour "
              "ORDER BY concurrent_sessions DESC LIMIT 10",
              {std::to_string(from_ts)});
          auto rows = txn.fetchall();
          json peaks = json::array();
          for (auto& row : rows) {
            peaks.push_back({
              {"hour", row[0].value.value_or("")},
              {"concurrent", row[1].value ? std::stoll(*row[1].value) : 0}
            });
          }
          result["peak_hours"] = peaks;
          return result;
        });
  }

private:
  std::string generate_session_id(const std::string& user_id,
                                   const std::string& device_id) {
    static std::atomic<int64_t> counter{0};
    int64_t seq = counter.fetch_add(1, std::memory_order_relaxed);
    std::stringstream ss;
    ss << user_id << ":" << device_id << ":"
       << now_ms() << ":" << seq;
    return ss.str();
  }

  int64_t get_session_start(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = active_sessions_.find(session_id);
    return it != active_sessions_.end() ? it->second.start_ts_ms : 0;
  }

  storage::DatabasePool& db_;
  ActivityDataCache& cache_;
  ActivityLogger& logger_;

  std::mutex sessions_mutex_;
  std::unordered_map<std::string, UserSession> active_sessions_;

  struct SessionMetrics {
    ActivityGaugeMetric active_sessions{"progressive_activity_sessions_active",
                                         "Currently active sessions"};
    class SessionDurationHistogram {
    public:
      void observe(double seconds) {
        total_.fetch_add(seconds, std::memory_order_relaxed);
        count_.fetch_add(1, std::memory_order_relaxed);
      }
      double avg() const {
        int64_t c = count_.load(std::memory_order_relaxed);
        return c > 0 ? total_.load(std::memory_order_relaxed) / c : 0.0;
      }
    private:
      std::atomic<double> total_{0.0};
      std::atomic<int64_t> count_{0};
    };
    SessionDurationHistogram session_duration;
  };
  SessionMetrics metrics_;
};

// ============================================================================
// 6. ActivityHeatmapBuilder — Heatmap generation (dow×hour, calendar)
// ============================================================================

class ActivityHeatmapBuilder {
public:
  explicit ActivityHeatmapBuilder(storage::DatabasePool& db, ActivityDataCache& cache)
      : db_(db), cache_(cache), logger_(get_activity_logger("Heatmap")) {}

  // ---- Day-of-week × Hour heatmap ----
  ActivityHeatmap build_dow_hour_heatmap(int64_t days = 30) {
    std::string cache_key = "heatmap_dow_hour_" + std::to_string(days);
    auto cached = cache_.get_json(cache_key);
    if (!cached.empty() && cached.contains("dow_hour")) {
      return deserialize_heatmap(cached);
    }

    ActivityHeatmap heatmap;
    heatmap.dow_hour.resize(7, std::vector<int64_t>(24, 0));
    heatmap.period_start = iso_date(days_ago_sec(days));
    heatmap.period_end = iso_date(now_sec());

    db_.runInteraction(
        "activity_heatmap_dow_hour",
        [&](storage::LoggingTransaction& txn) {
          std::string query =
              "SELECT dow, hour_bucket, COUNT(*) as cnt "
              "FROM user_activity_log "
              "WHERE date_str >= ? AND user_id NOT LIKE '@appservice:%' "
              "GROUP BY dow, hour_bucket";

          txn.execute(query, {heatmap.period_start});
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            int d = std::stoi(row[0].value.value_or("0"));
            int h = std::stoi(row[1].value.value_or("0"));
            int64_t cnt = row[2].value ? std::stoll(*row[2].value) : 0;
            if (d >= 0 && d < 7 && h >= 0 && h < 24) {
              heatmap.dow_hour[d][h] += cnt;
              heatmap.total_count += cnt;
              heatmap.max_count = std::max(heatmap.max_count, heatmap.dow_hour[d][h]);
            }
          }
        });

    cache_.set_json(cache_key, heatmap.to_json(), kHeatmapCacheTTLSeconds);
    return heatmap;
  }

  // ---- Calendar heatmap (date -> count) ----
  ActivityHeatmap build_calendar_heatmap(int64_t days = 365) {
    std::string cache_key = "heatmap_calendar_" + std::to_string(days);
    auto cached = cache_.get_json(cache_key);
    if (!cached.empty() && cached.contains("date_counts")) {
      return deserialize_heatmap(cached);
    }

    ActivityHeatmap heatmap;
    heatmap.period_start = iso_date(days_ago_sec(days));
    heatmap.period_end = iso_date(now_sec());

    db_.runInteraction(
        "activity_heatmap_calendar",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "SELECT date_str, COUNT(*) as cnt "
              "FROM user_activity_log "
              "WHERE date_str >= ? AND user_id NOT LIKE '@appservice:%' "
              "GROUP BY date_str ORDER BY date_str",
              {heatmap.period_start});
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            std::string date = row[0].value.value_or("");
            int64_t cnt = row[1].value ? std::stoll(*row[1].value) : 0;
            heatmap.date_counts[date] = cnt;
            heatmap.total_count += cnt;
            heatmap.max_count = std::max(heatmap.max_count, cnt);
          }
        });

    cache_.set_json(cache_key, heatmap.to_json(), kHeatmapCacheTTLSeconds);
    return heatmap;
  }

  // ---- Per-room activity heatmap ----
  ActivityHeatmap build_room_heatmap(const std::string& room_id, int64_t days = 30) {
    std::string cache_key = "heatmap_room_" + room_id + "_" + std::to_string(days);
    auto cached = cache_.get_json(cache_key);
    if (!cached.empty() && cached.contains("dow_hour")) {
      return deserialize_heatmap(cached);
    }

    ActivityHeatmap heatmap;
    heatmap.dow_hour.resize(7, std::vector<int64_t>(24, 0));
    heatmap.period_start = iso_date(days_ago_sec(days));
    heatmap.period_end = iso_date(now_sec());

    db_.runInteraction(
        "activity_heatmap_room",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "SELECT dow, hour_bucket, COUNT(*) as cnt "
              "FROM user_activity_log "
              "WHERE room_id = ? AND date_str >= ? "
              "GROUP BY dow, hour_bucket",
              {room_id, heatmap.period_start});
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            int d = std::stoi(row[0].value.value_or("0"));
            int h = std::stoi(row[1].value.value_or("0"));
            int64_t cnt = row[2].value ? std::stoll(*row[2].value) : 0;
            if (d >= 0 && d < 7 && h >= 0 && h < 24) {
              heatmap.dow_hour[d][h] += cnt;
              heatmap.total_count += cnt;
              heatmap.max_count = std::max(heatmap.max_count, heatmap.dow_hour[d][h]);
            }
          }
        });

    cache_.set_json(cache_key, heatmap.to_json(), kHeatmapCacheTTLSeconds);
    return heatmap;
  }

  // ---- Per-user activity fingerprint ----
  json build_user_fingerprint(const std::string& user_id, int64_t days = 90) {
    return db_.runInteraction(
        "activity_user_fingerprint",
        [&](storage::LoggingTransaction& txn) -> json {
          json fingerprint;
          std::string from_date = iso_date(days_ago_sec(days));

          // Hourly distribution
          json hourly = json::array();
          for (int h = 0; h < 24; h++) {
            txn.execute(
                "SELECT COUNT(*) FROM user_activity_log "
                "WHERE user_id = ? AND date_str >= ? AND hour_bucket = ?",
                {user_id, from_date, std::to_string(h)});
            auto row = txn.fetchone();
            hourly.push_back(row ? std::stoll(row->at(0).value.value_or("0")) : 0);
          }
          fingerprint["hourly_distribution"] = hourly;

          // Daily distribution
          json daily = json::array();
          for (int d = 0; d < 7; d++) {
            txn.execute(
                "SELECT COUNT(*) FROM user_activity_log "
                "WHERE user_id = ? AND date_str >= ? AND dow = ?",
                {user_id, from_date, std::to_string(d)});
            auto row = txn.fetchone();
            daily.push_back(row ? std::stoll(row->at(0).value.value_or("0")) : 0);
          }
          fingerprint["daily_distribution"] = daily;

          // Peak hour
          int peak_hour = 0;
          int64_t peak_val = 0;
          for (int h = 0; h < 24; h++) {
            if (hourly[h] > peak_val) {
              peak_val = hourly[h];
              peak_hour = h;
            }
          }
          fingerprint["peak_hour"] = peak_hour;
          fingerprint["peak_day"] = std::max_element(daily.begin(), daily.end())
              - daily.begin();

          // Active days count
          txn.execute(
              "SELECT COUNT(DISTINCT date_str) FROM user_activity_log "
              "WHERE user_id = ? AND date_str >= ?",
              {user_id, from_date});
          auto row = txn.fetchone();
          fingerprint["active_days"] = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          return fingerprint;
        });
  }

private:
  ActivityHeatmap deserialize_heatmap(const json& j) {
    ActivityHeatmap h;
    if (j.contains("dow_hour") && j["dow_hour"].is_array()) {
      h.dow_hour.resize(7, std::vector<int64_t>(24, 0));
      for (size_t d = 0; d < j["dow_hour"].size() && d < 7; d++) {
        for (size_t hr = 0; hr < j["dow_hour"][d].size() && hr < 24; hr++) {
          h.dow_hour[d][hr] = j["dow_hour"][d][hr];
        }
      }
    }
    if (j.contains("date_counts")) {
      for (auto& [key, val] : j["date_counts"].items()) {
        h.date_counts[key] = val;
      }
    }
    h.max_count = j.value("max_count", 0);
    h.total_count = j.value("total_count", 0);
    h.period_start = j.value("period_start", "");
    h.period_end = j.value("period_end", "");
    return h;
  }

  storage::DatabasePool& db_;
  ActivityDataCache& cache_;
  ActivityLogger& logger_;
};

// ============================================================================
// 7. RetentionAnalyzer — N-day retention curves, cohort analysis
// ============================================================================

class RetentionAnalyzer {
public:
  explicit RetentionAnalyzer(storage::DatabasePool& db, ActivityDataCache& cache)
      : db_(db), cache_(cache), logger_(get_activity_logger("Retention")) {}

  // ---- N-day retention curve ----
  RetentionCurve compute_n_day_retention(int64_t cohort_start_days_ago,
                                          const std::vector<int64_t>& day_markers = {1,3,7,14,30,60,90}) {
    int64_t cohort_start_sec = days_ago_sec(cohort_start_days_ago);
    int64_t cohort_end_sec = cohort_start_sec + 86400;

    return db_.runInteraction(
        "activity_retention",
        [&](storage::LoggingTransaction& txn) -> RetentionCurve {
          RetentionCurve curve;
          curve.cohort_label = iso_date(cohort_start_sec);

          // Cohort size: users who first appeared on that day
          txn.execute(
              "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
              "WHERE visit_date = ? AND user_id NOT LIKE '@appservice:%'",
              {curve.cohort_label});
          auto row = txn.fetchone();
          curve.cohort_size = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          if (curve.cohort_size == 0) return curve;

          for (auto marker : day_markers) {
            int64_t target_sec = cohort_start_sec + marker * 86400;
            std::string target_date = iso_date(target_sec);

            txn.execute(
                "SELECT COUNT(DISTINCT udv2.user_id) "
                "FROM user_daily_visits udv1 "
                "JOIN user_daily_visits udv2 ON udv1.user_id = udv2.user_id "
                "WHERE udv1.visit_date = ? AND udv2.visit_date = ? "
                "AND udv2.user_id NOT LIKE '@appservice:%'",
                {curve.cohort_label, target_date});
            row = txn.fetchone();
            int64_t retained = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            curve.retained_counts.push_back(retained);
            curve.retention_rates.push_back(
                std::round(safe_divide(retained, curve.cohort_size) * 10000.0) / 100.0);
          }

          return curve;
        });
  }

  // ---- Full cohort analysis ----
  json get_cohort_analysis(int64_t lookback_months = 12) {
    std::string cache_key = "cohort_analysis_" + std::to_string(lookback_months);
    auto cached = cache_.get_json(cache_key);
    if (!cached.empty()) return cached;

    json result = json::array();
    std::vector<int64_t> markers = {1, 3, 7, 14, 30, 60, 90};

    for (int64_t m = lookback_months; m >= 0; m--) {
      auto curve = compute_n_day_retention(m * 30, markers);
      if (curve.cohort_size > 0) {
        json cohort;
        cohort["cohort_label"] = curve.cohort_label;
        cohort["size"] = curve.cohort_size;
        json retention = json::array();
        for (size_t i = 0; i < markers.size(); i++) {
          retention.push_back({
            {"day", markers[i]},
            {"retained", curve.retained_counts[i]},
            {"rate_pct", curve.retention_rates[i]}
          });
        }
        cohort["retention"] = retention;
        result.push_back(cohort);
      }
    }

    cache_.set_json(cache_key, result, kHeatmapCacheTTLSeconds);
    return result;
  }

  // ---- Churn prediction ----
  json predict_churn_risk(const std::string& user_id) {
    return db_.runInteraction(
        "activity_churn_prediction",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;
          std::string d14 = iso_date(days_ago_sec(14));
          std::string d7  = iso_date(days_ago_sec(7));

          // Activity in last 14 days
          txn.execute(
              "SELECT COUNT(DISTINCT visit_date) FROM user_daily_visits "
              "WHERE user_id = ? AND visit_date >= ?",
              {user_id, d14});
          auto row = txn.fetchone();
          int64_t days_active_14 = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          // Activity in last 7 days
          txn.execute(
              "SELECT COUNT(DISTINCT visit_date) FROM user_daily_visits "
              "WHERE user_id = ? AND visit_date >= ?",
              {user_id, d7});
          row = txn.fetchone();
          int64_t days_active_7 = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          // Days since last activity
          txn.execute(
              "SELECT MAX(visit_date) FROM user_daily_visits WHERE user_id = ?",
              {user_id});
          row = txn.fetchone();
          std::string last_date = row ? row->at(0).value.value_or("") : "";
          int64_t days_since = 0;
          if (!last_date.empty()) {
            int64_t last_ts = parse_date_to_sec(last_date);
            days_since = (now_sec() - last_ts) / 86400;
          }

          // Churn risk score (0-100)
          double risk = 0.0;
          if (days_since > 30) risk = 90.0;
          else if (days_since > 14) risk = 70.0;
          else if (days_since > 7) risk = 50.0;
          else risk = std::max(0.0, 30.0 - days_active_14 * 5.0);

          result["user_id"] = user_id;
          result["days_since_last_active"] = days_since;
          result["days_active_last_7"] = days_active_7;
          result["days_active_last_14"] = days_active_14;
          result["churn_risk_pct"] = std::round(risk * 100.0) / 100.0;
          result["risk_level"] = risk > 70 ? "high" : risk > 30 ? "medium" : "low";

          return result;
        });
  }

  // ---- New user activation funnel ----
  json get_activation_funnel(int64_t days = 90) {
    return db_.runInteraction(
        "activity_activation_funnel",
        [&](storage::LoggingTransaction& txn) -> json {
          json funnel;
          int64_t since_ts = days_ago_sec(days);

          // Step 1: Registered
          txn.execute(
              "SELECT COUNT(*) FROM users WHERE creation_ts >= ? AND deactivated = 0",
              {std::to_string(since_ts)});
          auto row = txn.fetchone();
          int64_t registered = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          funnel["registered"] = registered;

          if (registered == 0) return funnel;

          // Step 2: Logged in at least once (has a session)
          txn.execute(
              "SELECT COUNT(DISTINCT uas.user_id) FROM user_activity_sessions uas "
              "JOIN users u ON u.name = uas.user_id "
              "WHERE u.creation_ts >= ?",
              {std::to_string(since_ts)});
          row = txn.fetchone();
          int64_t logged_in = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          funnel["logged_in"] = logged_in;
          funnel["login_rate_pct"] = safe_divide(logged_in, registered) * 100.0;

          // Step 3: Joined a room
          txn.execute(
              "SELECT COUNT(DISTINCT rm.user_id) FROM room_memberships rm "
              "JOIN users u ON u.name = rm.user_id "
              "WHERE u.creation_ts >= ? AND rm.membership = 'join'",
              {std::to_string(since_ts)});
          row = txn.fetchone();
          int64_t joined_room = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          funnel["joined_room"] = joined_room;
          funnel["join_rate_pct"] = safe_divide(joined_room, registered) * 100.0;

          // Step 4: Sent a message
          txn.execute(
              "SELECT COUNT(DISTINCT e.sender) FROM events e "
              "JOIN users u ON u.name = e.sender "
              "WHERE u.creation_ts >= ? AND e.type = 'm.room.message'",
              {std::to_string(since_ts)});
          row = txn.fetchone();
          int64_t sent_message = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          funnel["sent_message"] = sent_message;
          funnel["message_rate_pct"] = safe_divide(sent_message, registered) * 100.0;

          // Step 5: Active on day 7
          int64_t active_d7 = 0;
          // Approximate: users who registered 7+ days ago who visited on their 7th day
          txn.execute(
              "SELECT COUNT(DISTINCT udv.user_id) FROM user_daily_visits udv "
              "JOIN users u ON u.name = udv.user_id "
              "WHERE u.creation_ts >= ? AND u.creation_ts <= ? "
              "AND udv.visit_date = strftime('%Y-%m-%d', "
              "  datetime(u.creation_ts + 604800, 'unixepoch'))",
              {std::to_string(since_ts), std::to_string(now_sec() - 604800)});
          row = txn.fetchone();
          active_d7 = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          funnel["active_day_7"] = active_d7;
          funnel["d7_retention_pct"] = safe_divide(active_d7,
              std::max(int64_t(1), registered)) * 100.0;

          return funnel;
        });
  }

  // ---- Power user curve ----
  json get_power_user_curve(int64_t days = 30) {
    return db_.runInteraction(
        "activity_power_curve",
        [&](storage::LoggingTransaction& txn) -> json {
          std::string from_date = iso_date(days_ago_sec(days));
          json result;

          // Message count distribution per user
          txn.execute(
              "SELECT user_id, COUNT(*) as msg_count "
              "FROM user_activity_log "
              "WHERE date_str >= ? AND event_type = 'message' "
              "GROUP BY user_id ORDER BY msg_count DESC",
              {from_date});
          auto rows = txn.fetchall();

          std::vector<int64_t> counts;
          for (auto& row : rows) {
            counts.push_back(row[1].value ? std::stoll(*row[1].value) : 0);
          }
          std::sort(counts.begin(), counts.end(), std::greater<int64_t>());

          int64_t total_msgs = 0;
          for (auto c : counts) total_msgs += c;

          // Cumulative distribution
          json curve = json::array();
          int64_t cumulative = 0;
          for (size_t i = 0; i < counts.size() && i < 100; i++) {
            cumulative += counts[i];
            double user_pct = safe_divide(i + 1, counts.size()) * 100.0;
            double msg_pct = safe_divide(cumulative, total_msgs) * 100.0;
            curve.push_back({
              {"top_n", i + 1},
              {"cumulative_user_pct", user_pct},
              {"cumulative_msg_pct", msg_pct}
            });
          }

          result["total_users"] = counts.size();
          result["total_messages"] = total_msgs;
          result["power_curve"] = curve;

          // Percentiles
          std::vector<int64_t> sorted = counts;
          std::sort(sorted.begin(), sorted.end());
          result["p50"] = compute_percentile(sorted, 0.50);
          result["p75"] = compute_percentile(sorted, 0.75);
          result["p90"] = compute_percentile(sorted, 0.90);
          result["p95"] = compute_percentile(sorted, 0.95);
          result["p99"] = compute_percentile(sorted, 0.99);

          return result;
        });
  }

private:
  storage::DatabasePool& db_;
  ActivityDataCache& cache_;
  ActivityLogger& logger_;
};

// ============================================================================
// 8. EngagementScorer — User engagement scoring and tiering
// ============================================================================

class EngagementScorer {
public:
  explicit EngagementScorer(storage::DatabasePool& db, ActivityDataCache& cache)
      : db_(db), cache_(cache), logger_(get_activity_logger("Engagement")) {}

  // ---- Compute engagement score for a single user ----
  EngagementScore compute_user_engagement(const std::string& user_id) {
    EngagementScore score;
    score.user_id = user_id;
    score.computed_ts = now_sec();

    db_.runInteraction(
        "activity_engagement",
        [&](storage::LoggingTransaction& txn) {
          // Messages in last 30 days
          txn.execute(
              "SELECT COUNT(*) FROM user_activity_log "
              "WHERE user_id = ? AND date_str >= ? AND event_type = 'message'",
              {user_id, iso_date(days_ago_sec(30))});
          auto row = txn.fetchone();
          int64_t messages = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          // Rooms joined
          txn.execute(
              "SELECT COUNT(*) FROM room_memberships "
              "WHERE user_id = ? AND membership = 'join'",
              {user_id});
          row = txn.fetchone();
          int64_t rooms = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          // Sessions in last 30 days
          txn.execute(
              "SELECT COUNT(*) FROM user_activity_sessions "
              "WHERE user_id = ? AND start_ts_ms >= ?",
              {user_id, std::to_string(days_ago_ms(30))});
          row = txn.fetchone();
          int64_t sessions = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          // Reactions
          txn.execute(
              "SELECT COUNT(*) FROM user_activity_log "
              "WHERE user_id = ? AND date_str >= ? AND event_type = 'reaction'",
              {user_id, iso_date(days_ago_sec(30))});
          row = txn.fetchone();
          int64_t reactions = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          // Days active
          txn.execute(
              "SELECT COUNT(DISTINCT date_str) FROM user_activity_log "
              "WHERE user_id = ? AND date_str >= ?",
              {user_id, iso_date(days_ago_sec(30))});
          row = txn.fetchone();
          int64_t days_active = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          // Recency (days since last activity)
          txn.execute(
              "SELECT MAX(date_str) FROM user_activity_log WHERE user_id = ?",
              {user_id});
          row = txn.fetchone();
          std::string last_date = row ? row->at(0).value.value_or("") : "";
          int64_t days_since = 0;
          if (!last_date.empty()) {
            days_since = (now_sec() - parse_date_to_sec(last_date)) / 86400;
          }
          score.days_since_last_active = days_since;

          // Media uploads
          txn.execute(
              "SELECT COUNT(*) FROM local_media_repository WHERE user_id = ?",
              {user_id});
          row = txn.fetchone();
          int64_t media_count = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          // Normalize each factor to 0-100
          double msg_norm = std::min(100.0, static_cast<double>(messages) / 50.0 * 100.0);
          double room_norm = std::min(100.0, static_cast<double>(rooms) / 10.0 * 100.0);
          double sess_norm = std::min(100.0, static_cast<double>(sessions) / 20.0 * 100.0);
          double react_norm = std::min(100.0, static_cast<double>(reactions) / 10.0 * 100.0);
          double days_norm = std::min(100.0, static_cast<double>(days_active) / 30.0 * 100.0);
          double recency_norm = std::max(0.0, 100.0 - static_cast<double>(days_since) / 30.0 * 100.0);
          double media_norm = std::min(100.0, static_cast<double>(media_count) / 5.0 * 100.0);

          score.message_score = msg_norm;
          score.room_score = room_norm;
          score.session_score = sess_norm;
          score.reaction_score = react_norm;
          score.days_active_score = days_norm;
          score.recency_score = recency_norm;
          score.media_score = media_norm;

          // Weighted sum
          score.score = msg_norm * kEngagementWeightMessages
              + room_norm * kEngagementWeightRooms
              + sess_norm * kEngagementWeightSessions
              + react_norm * kEngagementWeightReactions
              + days_norm * kEngagementWeightDaysActive
              + recency_norm * kEngagementWeightRecency
              + media_norm * kEngagementWeightMedia;

          score.score = std::min(100.0, score.score);
          score.score = std::round(score.score * 100.0) / 100.0;

          // Assign tier
          if (score.score >= 75.0) score.tier = "power";
          else if (score.score >= 50.0) score.tier = "core";
          else if (score.score >= 25.0) score.tier = "casual";
          else if (score.score >= 5.0) score.tier = "dormant";
          else score.tier = "ghost";

          // Store engagement score
          try {
            txn.execute(
                "INSERT OR REPLACE INTO user_engagement_scores "
                "(user_id, score, tier, days_since_last_active, computed_ts) "
                "VALUES (?, ?, ?, ?, ?)",
                {user_id, std::to_string(score.score), score.tier,
                 std::to_string(score.days_since_last_active),
                 std::to_string(score.computed_ts)});
          } catch (...) {}
        });

    return score;
  }

  // ---- Compute percentile ----
  void compute_percentile(EngagementScore& score) {
    db_.runInteraction(
        "activity_engagement_pct",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "SELECT COUNT(*) FROM user_engagement_scores WHERE score < ?",
              {std::to_string(score.score)});
          auto row = txn.fetchone();
          int64_t below = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          txn.execute("SELECT COUNT(*) FROM user_engagement_scores");
          row = txn.fetchone();
          int64_t total = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

          score.percentile = total > 0
              ? std::round(safe_divide(below, total) * 10000.0) / 100.0
              : 0.0;
        });
  }

  // ---- Engagement distribution ----
  json get_engagement_distribution() {
    std::string cache_key = "engagement_distribution";
    auto cached = cache_.get_json(cache_key);
    if (!cached.empty()) return cached;

    json result = db_.runInteraction(
        "activity_engagement_dist",
        [&](storage::LoggingTransaction& txn) -> json {
          json dist;

          // Count by tier
          txn.execute(
              "SELECT tier, COUNT(*) FROM user_engagement_scores GROUP BY tier");
          auto rows = txn.fetchall();
          json tiers;
          for (auto& row : rows) {
            tiers[row[0].value.value_or("unknown")] = row[1].value
                ? std::stoll(*row[1].value) : 0;
          }
          dist["by_tier"] = tiers;

          // Average score
          txn.execute("SELECT AVG(score) FROM user_engagement_scores");
          auto row = txn.fetchone();
          dist["avg_score"] = row ? std::stod(row->at(0).value.value_or("0")) : 0.0;

          // Score distribution buckets
          std::vector<std::pair<std::string, std::pair<int, int>>> buckets = {
            {"0-10", {0, 10}}, {"10-25", {10, 25}}, {"25-50", {25, 50}},
            {"50-75", {50, 75}}, {"75-90", {75, 90}}, {"90-100", {90, 101}}
          };
          json score_buckets;
          for (auto& [label, range] : buckets) {
            txn.execute(
                "SELECT COUNT(*) FROM user_engagement_scores "
                "WHERE score >= ? AND score < ?",
                {std::to_string(range.first), std::to_string(range.second)});
            row = txn.fetchone();
            score_buckets[label] = row ? std::stoll(row->at(0).value.value_or("0")) : 0;
          }
          dist["score_buckets"] = score_buckets;

          // Top 10 most engaged users
          txn.execute(
              "SELECT user_id, score, tier FROM user_engagement_scores "
              "ORDER BY score DESC LIMIT 10");
          rows = txn.fetchall();
          json top10 = json::array();
          for (auto& r : rows) {
            top10.push_back({
              {"user_id", r[0].value.value_or("")},
              {"score", r[1].value ? std::stod(*r[1].value) : 0.0},
              {"tier", r[2].value.value_or("")}
            });
          }
          dist["top_10"] = top10;

          return dist;
        });

    cache_.set_json(cache_key, result, kEngagementCacheTTLSeconds);
    return result;
  }

  // ---- Batch score computation ----
  int64_t batch_compute_all_scores(int64_t batch_size = 1000) {
    return db_.runInteraction(
        "activity_engagement_batch",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          txn.execute(
              "SELECT name FROM users WHERE deactivated = 0 "
              "AND name NOT LIKE '@appservice:%' "
              "LIMIT ?",
              {std::to_string(batch_size)});
          auto rows = txn.fetchall();
          int64_t count = 0;
          for (auto& row : rows) {
            std::string user_id = row[0].value.value_or("");
            if (user_id.empty()) continue;
            compute_user_engagement(user_id);
            count++;
          }
          return count;
        });
  }

  // ---- Engagement trend over time ----
  json get_engagement_trend(int64_t days = 90) {
    return db_.runInteraction(
        "activity_engagement_trend",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          for (int64_t d = days; d >= 0; d -= 7) {
            std::string date = iso_date(days_ago_sec(d));
            txn.execute(
                "SELECT AVG(score) FROM user_engagement_scores "
                "WHERE computed_ts >= ? AND computed_ts < ?",
                {std::to_string(days_ago_sec(d + 7)),
                 std::to_string(days_ago_sec(d))});
            auto row = txn.fetchone();
            double avg = row ? std::stod(row->at(0).value.value_or("0")) : 0.0;
            result.push_back({{"week", date}, {"avg_score", std::round(avg * 100.0) / 100.0}});
          }
          return result;
        });
  }

private:
  storage::DatabasePool& db_;
  ActivityDataCache& cache_;
  ActivityLogger& logger_;
};

// ============================================================================
// 9. PeakUsageAnalyzer — Peak activity detection and traffic distribution
// ============================================================================

class PeakUsageAnalyzer {
public:
  explicit PeakUsageAnalyzer(storage::DatabasePool& db, ActivityDataCache& cache)
      : db_(db), cache_(cache), logger_(get_activity_logger("Peaks")) {}

  // ---- Current peak usage analysis ----
  PeakUsageData analyze_peaks(int64_t days = 30) {
    PeakUsageData data;
    data.hourly_distribution.resize(24, 0);
    data.daily_distribution.resize(7, 0);

    db_.runInteraction(
        "activity_peaks",
        [&](storage::LoggingTransaction& txn) {
          std::string from_date = iso_date(days_ago_sec(days));

          // Hourly distribution
          txn.execute(
              "SELECT hour_bucket, COUNT(*) as cnt "
              "FROM user_activity_log "
              "WHERE date_str >= ? "
              "GROUP BY hour_bucket ORDER BY hour_bucket",
              {from_date});
          auto rows = txn.fetchall();
          int64_t total = 0;
          for (auto& row : rows) {
            int h = std::stoi(row[0].value.value_or("0"));
            int64_t cnt = row[1].value ? std::stoll(*row[1].value) : 0;
            if (h >= 0 && h < 24) {
              data.hourly_distribution[h] = cnt;
              total += cnt;
              if (cnt > data.peak_count) {
                data.peak_count = cnt;
                data.peak_hour_ts = now_sec(); // approximate
              }
              if (cnt < data.min_hourly) {
                data.min_hourly = cnt;
              }
            }
          }
          data.avg_hourly = total > 0 ? total / 24 : 0;

          // Daily distribution
          txn.execute(
              "SELECT dow, COUNT(*) as cnt "
              "FROM user_activity_log "
              "WHERE date_str >= ? "
              "GROUP BY dow ORDER BY dow",
              {from_date});
          rows = txn.fetchall();
          for (auto& row : rows) {
            int d = std::stoi(row[0].value.value_or("0"));
            int64_t cnt = row[1].value ? std::stoll(*row[1].value) : 0;
            if (d >= 0 && d < 7) {
              data.daily_distribution[d] = cnt;
            }
          }

          // Top peak days
          txn.execute(
              "SELECT date_str, COUNT(*) as cnt "
              "FROM user_activity_log "
              "WHERE date_str >= ? "
              "GROUP BY date_str ORDER BY cnt DESC LIMIT 10",
              {from_date});
          rows = txn.fetchall();
          for (auto& row : rows) {
            data.top_peak_days.push_back({
              row[0].value.value_or(""),
              row[1].value ? std::stoll(*row[1].value) : 0
            });
          }

          // Seasonality strength (ratio of max to min day)
          int64_t max_day = *std::max_element(data.daily_distribution.begin(),
                                               data.daily_distribution.end());
          int64_t min_day = *std::min_element(data.daily_distribution.begin(),
                                               data.daily_distribution.end());
          data.seasonality_strength = min_day > 0
              ? static_cast<double>(max_day) / static_cast<double>(min_day)
              : 0.0;
        });

    return data;
  }

  // ---- Real-time events per minute ----
  double get_events_per_minute() {
    int64_t one_min_ago_ms = now_ms() - 60000;
    return db_.runInteraction(
        "activity_events_per_min",
        [&](storage::LoggingTransaction& txn) -> double {
          txn.execute(
              "SELECT COUNT(*) FROM user_activity_log "
              "WHERE timestamp_ms >= ?",
              {std::to_string(one_min_ago_ms)});
          auto row = txn.fetchone();
          return row ? std::stod(row->at(0).value.value_or("0")) : 0.0;
        });
  }

  // ---- Traffic anomaly detection ----
  json detect_traffic_anomalies(int64_t days = 30) {
    auto data = analyze_peaks(days);
    json result;

    // Hourly z-scores
    std::vector<double> z_scores = compute_z_scores(data.hourly_distribution);
    json hourly_anomalies = json::array();
    for (size_t h = 0; h < z_scores.size(); h++) {
      if (std::abs(z_scores[h]) > 2.0) {
        hourly_anomalies.push_back({
          {"hour", h},
          {"value", data.hourly_distribution[h]},
          {"z_score", z_scores[h]},
          {"type", z_scores[h] > 0 ? "spike" : "drop"}
        });
      }
    }
    result["hourly_anomalies"] = hourly_anomalies;
    result["peak_hour"] = std::max_element(data.hourly_distribution.begin(),
                                            data.hourly_distribution.end())
        - data.hourly_distribution.begin();
    result["quietest_hour"] = std::min_element(data.hourly_distribution.begin(),
                                                data.hourly_distribution.end())
        - data.hourly_distribution.begin();

    return result;
  }

  // ---- Weekly cycle pattern ----
  json get_weekly_cycle(int64_t weeks = 4) {
    return db_.runInteraction(
        "activity_weekly_cycle",
        [&](storage::LoggingTransaction& txn) -> json {
          json result = json::array();
          std::string from_date = iso_date(days_ago_sec(weeks * 7));

          for (int d = 0; d < 7; d++) {
            json day_data;
            static const char* day_names[] = {"Sunday","Monday","Tuesday",
                "Wednesday","Thursday","Friday","Saturday"};
            day_data["day"] = day_names[d];
            json hourly = json::array();
            for (int h = 0; h < 24; h++) {
              txn.execute(
                  "SELECT AVG(cnt) FROM ("
                  "  SELECT date_str, hour_bucket, COUNT(*) as cnt "
                  "  FROM user_activity_log "
                  "  WHERE date_str >= ? AND dow = ? AND hour_bucket = ? "
                  "  GROUP BY date_str"
                  ")",
                  {from_date, std::to_string(d), std::to_string(h)});
              auto row = txn.fetchone();
              hourly.push_back(row ? std::stod(row->at(0).value.value_or("0")) : 0.0);
            }
            day_data["hourly_avg"] = hourly;
            result.push_back(day_data);
          }
          return result;
        });
  }

private:
  storage::DatabasePool& db_;
  ActivityDataCache& cache_;
  ActivityLogger& logger_;
};

// ============================================================================
// 10. ActivityDataCache — In-memory TTL cache for activity data
// ============================================================================

class ActivityDataCache {
public:
  explicit ActivityDataCache(int64_t default_ttl_sec = kDefaultCacheTTLSeconds)
      : default_ttl_sec_(default_ttl_sec) {}

  // ---- DAU cache ----
  int64_t get_dau(const std::string& key) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = dau_cache_.find(key);
    if (it != dau_cache_.end() && now_sec() < it->second.expiry) {
      return it->second.int_value;
    }
    return -1;
  }

  void set_dau(const std::string& key, int64_t value) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    dau_cache_[key] = {value, now_sec() + kDAUCacheTTLSeconds};
    prune_cache(dau_cache_, kDAUCacheTTLSeconds);
  }

  // ---- MAU cache ----
  int64_t get_mau(const std::string& key) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = mau_cache_.find(key);
    if (it != mau_cache_.end() && now_sec() < it->second.expiry) {
      return it->second.int_value;
    }
    return -1;
  }

  void set_mau(const std::string& key, int64_t value) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    mau_cache_[key] = {value, now_sec() + kMAUCacheTTLSeconds};
    prune_cache(mau_cache_, kMAUCacheTTLSeconds);
  }

  // ---- JSON cache ----
  json get_json(const std::string& key) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = json_cache_.find(key);
    if (it != json_cache_.end() && now_sec() < it->second.expiry) {
      return it->second.json_value;
    }
    return json{};
  }

  void set_json(const std::string& key, const json& value,
                int64_t ttl_sec = 0) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    int64_t ttl = ttl_sec > 0 ? ttl_sec : default_ttl_sec_;
    json_cache_[key] = {value, now_sec() + ttl};
    prune_cache(json_cache_, ttl);
  }

  // ---- Session cache ----
  void cache_session(const std::string& session_id, const UserSession& session) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    session_cache_[session_id] = {session, now_sec() + 3600};
  }

  std::optional<UserSession> get_cached_session(const std::string& session_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = session_cache_.find(session_id);
    if (it != session_cache_.end() && now_sec() < it->second.expiry) {
      return it->second.session_value;
    }
    return std::nullopt;
  }

  // ---- Invalidation ----
  void invalidate(const std::string& prefix) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    invalidate_prefix(dau_cache_, prefix);
    invalidate_prefix(mau_cache_, prefix);
    invalidate_prefix(json_cache_, prefix);
  }

  void invalidate_all() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    dau_cache_.clear();
    mau_cache_.clear();
    json_cache_.clear();
    session_cache_.clear();
    logger_.info("All activity caches invalidated");
  }

  // ---- Cache stats ----
  json get_cache_stats() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json stats;
    stats["dau_entries"] = dau_cache_.size();
    stats["mau_entries"] = mau_cache_.size();
    stats["json_entries"] = json_cache_.size();
    stats["session_entries"] = session_cache_.size();
    return stats;
  }

  // ---- Warm up common caches ----
  void warmup(storage::DatabasePool& db) {
    logger_.info("Warming up activity caches...");

    // Pre-compute current DAU
    std::string today = iso_date(now_sec());
    int64_t dau = db.runInteraction(
        "cache_warmup_dau",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          txn.execute(
              "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
              "WHERE visit_date = ?",
              {today});
          auto row = txn.fetchone();
          return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
        });
    set_dau(today, dau);
    logger_.info("Cache warming complete, DAU = " + std::to_string(dau));
  }

private:
  template<typename CacheMap>
  void prune_cache(CacheMap& cache, int64_t ttl) {
    // Only prune if cache has grown large
    if (cache.size() < 10000) return;
    int64_t now = now_sec();
    auto it = cache.begin();
    while (it != cache.end()) {
      if (now >= it->second.expiry) {
        it = cache.erase(it);
      } else {
        ++it;
      }
    }
  }

  template<typename CacheMap>
  void invalidate_prefix(CacheMap& cache, const std::string& prefix) {
    auto it = cache.begin();
    while (it != cache.end()) {
      if (it->first.find(prefix) == 0) {
        it = cache.erase(it);
      } else {
        ++it;
      }
    }
  }

  struct IntCacheEntry {
    int64_t int_value = 0;
    int64_t expiry = 0;
  };

  struct JsonCacheEntry {
    json json_value;
    int64_t expiry = 0;
  };

  struct SessionCacheEntry {
    UserSession session_value;
    int64_t expiry = 0;
  };

  int64_t default_ttl_sec_;
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, IntCacheEntry> dau_cache_;
  std::unordered_map<std::string, IntCacheEntry> mau_cache_;
  std::unordered_map<std::string, JsonCacheEntry> json_cache_;
  std::unordered_map<std::string, SessionCacheEntry> session_cache_;
  ActivityLogger& logger_ = get_activity_logger("Cache");
};

// ============================================================================
// 11. BackgroundActivityAggregator — Periodic background aggregation worker
// ============================================================================

class BackgroundActivityAggregator {
public:
  BackgroundActivityAggregator(storage::DatabasePool& db,
                                ActivityDataCache& cache,
                                DailyActiveUsersEngine& dau,
                                MonthlyActiveUsersEngine& mau,
                                EngagementScorer& engagement,
                                UserSessionTracker& sessions)
      : db_(db), cache_(cache), dau_(dau), mau_(mau),
        engagement_(engagement), sessions_(sessions),
        logger_(get_activity_logger("Aggregator")) {}

  // ---- Start background worker ----
  void start() {
    if (running_.load(std::memory_order_acquire)) return;

    running_.store(true, std::memory_order_release);
    worker_thread_ = std::thread([this]() {
      logger_.info("Background activity aggregator started");
      while (running_.load(std::memory_order_acquire)) {
        auto start = chr::steady_clock::now();

        try {
          run_aggregation_cycle();
        } catch (const std::exception& ex) {
          logger_.error(std::string("Aggregation cycle failed: ") + ex.what());
        }

        auto elapsed = chr::steady_clock::now() - start;
        auto remaining = chr::seconds(kDefaultAggregationIntervalSec) - elapsed;
        if (remaining > chr::seconds(0)) {
          std::unique_lock<std::mutex> lock(stop_mutex_);
          stop_cv_.wait_for(lock, remaining, [this]() {
            return !running_.load(std::memory_order_acquire);
          });
        }
      }
      logger_.info("Background activity aggregator stopped");
    });
  }

  // ---- Stop background worker ----
  void shutdown() {
    running_.store(false, std::memory_order_release);
    stop_cv_.notify_all();
    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }
  }

  // ---- Check if running ----
  bool is_running() const {
    return running_.load(std::memory_order_acquire);
  }

  // ---- Status ----
  json get_status() const {
    json status;
    status["running"] = is_running();
    status["last_run_ts"] = last_run_ts_.load(std::memory_order_relaxed);
    status["last_run_iso"] = iso_datetime(last_run_ts_.load(std::memory_order_relaxed));
    status["cycles_completed"] = cycles_completed_.load(std::memory_order_relaxed);
    status["aggregation_interval_sec"] = kDefaultAggregationIntervalSec;
    return status;
  }

  // ---- Force a cycle ----
  json force_cycle() {
    json result;
    try {
      auto start = chr::steady_clock::now();
      run_aggregation_cycle();
      auto elapsed = chr::duration_cast<chr::milliseconds>(
          chr::steady_clock::now() - start).count();
      result["status"] = "completed";
      result["elapsed_ms"] = elapsed;
    } catch (const std::exception& ex) {
      result["status"] = "error";
      result["error"] = ex.what();
    }
    return result;
  }

private:
  void run_aggregation_cycle() {
    auto& log = logger_;
    log.info("Starting aggregation cycle...");

    // Recompute DAU
    int64_t dau = dau_.compute_current_dau();
    log.debug("DAU computed: " + std::to_string(dau));

    // Recompute MAU
    int64_t mau = mau_.compute_current_mau();
    log.debug("MAU computed: " + std::to_string(mau));

    // Cleanup idle sessions
    int64_t closed = sessions_.cleanup_idle_sessions();
    if (closed > 0) {
      log.debug("Cleaned up " + std::to_string(closed) + " idle sessions");
    }

    // Prune old activity log entries (keep last 90 days)
    int64_t cutoff_ms = days_ago_ms(90);
    db_.runInteraction(
        "activity_prune_log",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "DELETE FROM user_activity_log WHERE timestamp_ms < ?",
              {std::to_string(cutoff_ms)});
        });

    // Cache invalidation to force refresh
    cache_.invalidate("dau_series");
    cache_.invalidate("mau_series");
    cache_.invalidate("server_timeline");
    cache_.invalidate("heatmap");
    cache_.invalidate("engagement");

    last_run_ts_.store(now_sec(), std::memory_order_relaxed);
    cycles_completed_.fetch_add(1, std::memory_order_relaxed);
    log.info("Aggregation cycle completed (cycle #"
             + std::to_string(cycles_completed_.load()) + ")");
  }

  storage::DatabasePool& db_;
  ActivityDataCache& cache_;
  DailyActiveUsersEngine& dau_;
  MonthlyActiveUsersEngine& mau_;
  EngagementScorer& engagement_;
  UserSessionTracker& sessions_;
  ActivityLogger& logger_;

  std::atomic<bool> running_{false};
  std::thread worker_thread_;
  std::mutex stop_mutex_;
  std::condition_variable stop_cv_;
  std::atomic<int64_t> last_run_ts_{0};
  std::atomic<int64_t> cycles_completed_{0};
};

// ============================================================================
// 12. ActivityAdminHandler — Admin API endpoints
// ============================================================================

class ActivityAdminHandler {
public:
  ActivityAdminHandler(DailyActiveUsersEngine& dau,
                        MonthlyActiveUsersEngine& mau,
                        WeeklyActiveUsersEngine& wau,
                        ActivityTimelineTracker& timeline,
                        UserSessionTracker& sessions,
                        ActivityHeatmapBuilder& heatmap,
                        RetentionAnalyzer& retention,
                        EngagementScorer& engagement,
                        PeakUsageAnalyzer& peaks,
                        ActivityDataCache& cache,
                        BackgroundActivityAggregator& aggregator)
      : dau_(dau), mau_(mau), wau_(wau), timeline_(timeline),
        sessions_(sessions), heatmap_(heatmap), retention_(retention),
        engagement_(engagement), peaks_(peaks), cache_(cache),
        aggregator_(aggregator),
        logger_(get_activity_logger("Admin")) {}

  // ---- GET /activity/overview ----
  json handle_overview() {
    json overview;
    int64_t dau = dau_.compute_current_dau();
    int64_t mau = mau_.compute_current_mau();
    int64_t wau = wau_.compute_current_wau();
    double stickiness = mau > 0 ? (static_cast<double>(dau) / mau) * 100.0 : 0.0;
    double events_per_min = peaks_.get_events_per_min();
    int64_t active_sessions = sessions_.get_active_session_count();

    overview["dau"] = dau;
    overview["mau"] = mau;
    overview["wau"] = wau;
    overview["dau_mau_stickiness_pct"] = std::round(stickiness * 100.0) / 100.0;
    overview["wau_mau_ratio_pct"] = std::round(wau_.get_wau_mau_ratio(mau) * 100.0) / 100.0;
    overview["events_per_minute"] = events_per_min;
    overview["active_sessions"] = active_sessions;
    overview["dau_growth_7d_pct"] = dau_.get_dau_growth_rate(7);
    overview["dau_growth_30d_pct"] = dau_.get_dau_growth_rate(30);
    overview["timestamp"] = iso_datetime(now_sec());

    return overview;
  }

  // ---- GET /activity/dau[/:days] ----
  json handle_dau(int64_t days = 90) {
    auto series = dau_.get_dau_time_series(days);
    json result = json::array();
    for (auto& s : series) result.push_back(s.to_json());
    return result;
  }

  // ---- GET /activity/dau/trend[/:days] ----
  json handle_dau_trend(int64_t days = 30) {
    return dau_.get_dau_trend_analysis(days);
  }

  // ---- GET /activity/dau/forecast[/:days] ----
  json handle_dau_forecast(int64_t days = 7) {
    return dau_.forecast_dau(days);
  }

  // ---- GET /activity/dau/devices[/:date] ----
  json handle_dau_devices(const std::string& date = "") {
    return dau_.get_dau_by_device_type(date);
  }

  // ---- GET /activity/dau/yoy ----
  json handle_dau_yoy() {
    return dau_.get_dau_yoy_comparison();
  }

  // ---- GET /activity/mau[/:months] ----
  json handle_mau(int64_t months = 12) {
    auto series = mau_.get_mau_time_series(months);
    json result = json::array();
    for (auto& s : series) result.push_back(s.to_json());
    return result;
  }

  // ---- GET /activity/mau/trend[/:months] ----
  json handle_mau_trend(int64_t months = 12) {
    return mau_.get_mau_trend(months);
  }

  // ---- GET /activity/mau/breakdown ----
  json handle_mau_breakdown() {
    return mau_.get_mau_by_activity_type();
  }

  // ---- GET /activity/wau[/:weeks] ----
  json handle_wau(int64_t weeks = 52) {
    return wau_.get_wau_time_series(weeks);
  }

  // ---- GET /activity/wau/weekend_split ----
  json handle_weekend_split() {
    return wau_.get_weekend_weekday_split();
  }

  // ---- GET /activity/timeline/:user_id[/:bucket/:days] ----
  json handle_user_timeline(const std::string& user_id,
                             const std::string& bucket = "daily",
                             int64_t days = 90) {
    return timeline_.get_user_timeline(user_id, bucket, days);
  }

  // ---- GET /activity/timeline/server[/:bucket/:periods] ----
  json handle_server_timeline(const std::string& bucket = "daily",
                               int64_t periods = 90) {
    auto buckets = timeline_.get_server_timeline(bucket, periods);
    json result = json::array();
    for (auto& b : buckets) result.push_back(b.to_json());
    return result;
  }

  // ---- GET /activity/timeline/cumulative[/:days] ----
  json handle_cumulative_curve(int64_t days = 90) {
    return timeline_.get_cumulative_activity_curve(days);
  }

  // ---- GET /activity/sessions/:user_id ----
  json handle_user_sessions(const std::string& user_id, int64_t limit = 50) {
    auto sessions = sessions_.get_user_sessions(user_id, limit);
    json result = json::array();
    for (auto& s : sessions) result.push_back(s.to_json());
    return result;
  }

  // ---- GET /activity/sessions/distribution[/:days] ----
  json handle_session_distribution(int64_t days = 30) {
    return sessions_.get_session_duration_distribution(days);
  }

  // ---- GET /activity/sessions/concurrent_peak ----
  json handle_concurrent_peak() {
    return sessions_.get_concurrent_session_peak();
  }

  // ---- GET /activity/heatmap[/:period] ----
  json handle_heatmap(const std::string& period = "dow_hour", int64_t days = 30) {
    if (period == "calendar") {
      return heatmap_.build_calendar_heatmap(std::min(days, kMaxHeatmapDays)).to_json();
    }
    return heatmap_.build_dow_hour_heatmap(days).to_json();
  }

  // ---- GET /activity/heatmap/room/:room_id[/:days] ----
  json handle_room_heatmap(const std::string& room_id, int64_t days = 30) {
    return heatmap_.build_room_heatmap(room_id, days).to_json();
  }

  // ---- GET /activity/heatmap/user/:user_id ----
  json handle_user_fingerprint(const std::string& user_id, int64_t days = 90) {
    return heatmap_.build_user_fingerprint(user_id, days);
  }

  // ---- GET /activity/retention[/:days] ----
  json handle_retention(int64_t cohort_age_days = 30) {
    auto curve = retention_.compute_n_day_retention(cohort_age_days);
    return curve.to_json();
  }

  // ---- GET /activity/retention/cohorts[/:months] ----
  json handle_cohorts(int64_t months = 12) {
    return retention_.get_cohort_analysis(months);
  }

  // ---- GET /activity/retention/churn/:user_id ----
  json handle_churn_risk(const std::string& user_id) {
    return retention_.predict_churn_risk(user_id);
  }

  // ---- GET /activity/retention/funnel ----
  json handle_activation_funnel() {
    return retention_.get_activation_funnel();
  }

  // ---- GET /activity/retention/power_curve ----
  json handle_power_curve() {
    return retention_.get_power_user_curve();
  }

  // ---- GET /activity/engagement/:user_id ----
  json handle_user_engagement(const std::string& user_id) {
    auto score = engagement_.compute_user_engagement(user_id);
    engagement_.compute_percentile(score);
    return score.to_json();
  }

  // ---- GET /activity/engagement/distribution ----
  json handle_engagement_distribution() {
    return engagement_.get_engagement_distribution();
  }

  // ---- GET /activity/engagement/trend ----
  json handle_engagement_trend() {
    return engagement_.get_engagement_trend();
  }

  // ---- POST /activity/engagement/compute ----
  json handle_compute_engagement(int64_t batch_size = 1000) {
    int64_t count = engagement_.batch_compute_all_scores(batch_size);
    return json{{"status", "completed"}, {"users_processed", count}};
  }

  // ---- GET /activity/peaks[/:days] ----
  json handle_peaks(int64_t days = 30) {
    return peaks_.analyze_peaks(days).to_json();
  }

  // ---- GET /activity/peaks/anomalies ----
  json handle_anomalies() {
    return peaks_.detect_traffic_anomalies();
  }

  // ---- GET /activity/peaks/weekly_cycle ----
  json handle_weekly_cycle() {
    return peaks_.get_weekly_cycle();
  }

  // ---- GET /activity/cache/stats ----
  json handle_cache_stats() {
    return cache_.get_cache_stats();
  }

  // ---- POST /activity/cache/refresh ----
  json handle_cache_refresh() {
    cache_.invalidate_all();
    return json{{"status", "cache_invalidated"}};
  }

  // ---- POST /activity/cache/warmup ----
  json handle_cache_warmup(storage::DatabasePool& db) {
    cache_.warmup(db);
    return json{{"status", "cache_warmed"}};
  }

  // ---- GET /activity/aggregator/status ----
  json handle_aggregator_status() {
    return aggregator_.get_status();
  }

  // ---- POST /activity/aggregator/start ----
  json handle_aggregator_start() {
    aggregator_.start();
    return json{{"status", "started"}};
  }

  // ---- POST /activity/aggregator/stop ----
  json handle_aggregator_stop() {
    aggregator_.shutdown();
    return json{{"status", "stopped"}};
  }

  // ---- POST /activity/aggregator/force ----
  json handle_aggregator_force() {
    return aggregator_.force_cycle();
  }

  // ---- POST /activity/record/visit ----
  json handle_record_visit(const std::string& user_id,
                            const std::string& device_id = "",
                            const std::string& activity_type = "sync") {
    timeline_.record_daily_visit(user_id, device_id, activity_type);
    return json{{"status", "recorded"}, {"user_id", user_id}};
  }

  // ---- POST /activity/record/event ----
  json handle_record_event(const std::string& user_id,
                            const std::string& room_id,
                            const std::string& event_type,
                            const std::string& device_id = "",
                            const std::string& event_id = "") {
    timeline_.record_activity_event(user_id, room_id, event_type, device_id, event_id);
    return json{{"status", "recorded"}};
  }

  // ---- POST /activity/session/start ----
  json handle_session_start(const std::string& user_id,
                              const std::string& device_id,
                              const std::string& ip = "",
                              const std::string& ua = "") {
    std::string sid = sessions_.start_session(user_id, device_id, ip, ua);
    return json{{"status", "started"}, {"session_id", sid}};
  }

  // ---- POST /activity/session/end ----
  json handle_session_end(const std::string& session_id) {
    sessions_.end_session(session_id);
    return json{{"status", "ended"}, {"session_id", session_id}};
  }

private:
  DailyActiveUsersEngine& dau_;
  MonthlyActiveUsersEngine& mau_;
  WeeklyActiveUsersEngine& wau_;
  ActivityTimelineTracker& timeline_;
  UserSessionTracker& sessions_;
  ActivityHeatmapBuilder& heatmap_;
  RetentionAnalyzer& retention_;
  EngagementScorer& engagement_;
  PeakUsageAnalyzer& peaks_;
  ActivityDataCache& cache_;
  BackgroundActivityAggregator& aggregator_;
  ActivityLogger& logger_;
};

// ============================================================================
// 13. ActivityMetricsExporter — Prometheus /metrics export for activity
// ============================================================================

class ActivityMetricsExporter {
public:
  explicit ActivityMetricsExporter(DailyActiveUsersEngine& dau,
                                    MonthlyActiveUsersEngine& mau,
                                    WeeklyActiveUsersEngine& wau,
                                    UserSessionTracker& sessions,
                                    EngagementScorer& engagement,
                                    PeakUsageAnalyzer& peaks,
                                    RetentionAnalyzer& retention)
      : dau_(dau), mau_(mau), wau_(wau), sessions_(sessions),
        engagement_(engagement), peaks_(peaks), retention_(retention) {

    // Initialize all metrics
    for (auto& def : kActivityMetrics) {
      switch (def.type) {
        case MetricType::kGauge:
          metrics_.emplace_back(std::make_unique<ActivityGaugeMetric>(def.name, def.help));
          break;
        case MetricType::kCounter:
          metrics_.emplace_back(std::make_unique<ActivityCounterMetric>(def.name, def.help));
          break;
        default:
          break;
      }
    }
  }

  // ---- Render all metrics in Prometheus format ----
  std::string render_metrics() {
    refresh_metrics();
    std::stringstream ss;
    for (auto& metric : metrics_) {
      ss << metric->render();
    }
    return ss.str();
  }

  // ---- Refresh metric values ----
  void refresh_metrics() {
    int64_t dau = dau_.compute_current_dau();
    int64_t mau = mau_.compute_current_mau();
    int64_t wau = wau_.compute_current_wau();
    double stickiness = mau > 0 ? safe_divide(dau, mau) * 100.0 : 0.0;
    double wau_mau = mau > 0 ? safe_divide(wau, mau) * 100.0 : 0.0;
    double events_per_min = peaks_.get_events_per_minute();
    int64_t active_sessions = sessions_.get_active_session_count();
    double dau_growth_7d = dau_.get_dau_growth_rate(7);

    set_gauge("progressive_activity_dau", static_cast<double>(dau));
    set_gauge("progressive_activity_mau", static_cast<double>(mau));
    set_gauge("progressive_activity_wau", static_cast<double>(wau));
    set_gauge("progressive_activity_stickiness", stickiness);
    set_gauge("progressive_activity_wau_mau", wau_mau);
    set_gauge("progressive_activity_sessions_active",
              static_cast<double>(active_sessions));
    set_gauge("progressive_activity_events_per_min", events_per_min);
    set_gauge("progressive_activity_dau_growth", dau_growth_7d);

    // Retention metrics
    auto curve_7 = retention_.compute_n_day_retention(7, {7});
    auto curve_30 = retention_.compute_n_day_retention(30, {30});
    if (!curve_7.retention_rates.empty()) {
      set_gauge("progressive_activity_retention_d7", curve_7.retention_rates[0]);
    }
    if (!curve_30.retention_rates.empty()) {
      set_gauge("progressive_activity_retention_d30", curve_30.retention_rates[0]);
    }

    // Engagement average
    auto dist = engagement_.get_engagement_distribution();
    if (dist.contains("avg_score")) {
      set_gauge("progressive_activity_engagement_avg", dist["avg_score"]);
    }
  }

  // ---- Reset all metrics ----
  void reset_all() {
    for (auto& metric : metrics_) {
      metric->reset();
    }
  }

private:
  void set_gauge(const std::string& name, double value) {
    for (auto& metric : metrics_) {
      if (metric->name() == name && metric->type() == MetricType::kGauge) {
        auto* g = static_cast<ActivityGaugeMetric*>(metric.get());
        g->set(value);
        return;
      }
    }
  }

  DailyActiveUsersEngine& dau_;
  MonthlyActiveUsersEngine& mau_;
  WeeklyActiveUsersEngine& wau_;
  UserSessionTracker& sessions_;
  EngagementScorer& engagement_;
  PeakUsageAnalyzer& peaks_;
  RetentionAnalyzer& retention_;

  std::vector<std::unique_ptr<SimplePromMetric>> metrics_;
};

// ============================================================================
// 14. ActivityTrackingOrchestrator — Top-level orchestrator/facade
//
// This is the primary public interface that ties all activity tracking
// subsystems together. It owns the engines and provides a unified API
// for the rest of the server to interact with.
// ============================================================================

class ActivityTrackingOrchestrator {
public:
  explicit ActivityTrackingOrchestrator(storage::DatabasePool& db)
      : db_(db),
        cache_(std::make_unique<ActivityDataCache>()),
        dau_(std::make_unique<DailyActiveUsersEngine>(db, *cache_)),
        mau_(std::make_unique<MonthlyActiveUsersEngine>(db, *cache_)),
        wau_(std::make_unique<WeeklyActiveUsersEngine>(db, *cache_)),
        timeline_(std::make_unique<ActivityTimelineTracker>(db, *cache_)),
        sessions_(std::make_unique<UserSessionTracker>(db, *cache_)),
        heatmap_(std::make_unique<ActivityHeatmapBuilder>(db, *cache_)),
        retention_(std::make_unique<RetentionAnalyzer>(db, *cache_)),
        engagement_(std::make_unique<EngagementScorer>(db, *cache_)),
        peaks_(std::make_unique<PeakUsageAnalyzer>(db, *cache_)),
        logger_(get_activity_logger("Orchestrator")) {

    // Wire up cross-dependencies
    mau_->set_dau_engine(dau_.get());

    aggregator_ = std::make_unique<BackgroundActivityAggregator>(
        db, *cache_, *dau_, *mau_, *engagement_, *sessions_);

    admin_ = std::make_unique<ActivityAdminHandler>(
        *dau_, *mau_, *wau_, *timeline_, *sessions_, *heatmap_,
        *retention_, *engagement_, *peaks_, *cache_, *aggregator_);

    exporter_ = std::make_unique<ActivityMetricsExporter>(
        *dau_, *mau_, *wau_, *sessions_, *engagement_, *peaks_, *retention_);
  }

  // ---- Initialization ----
  void initialize() {
    logger_.info("Initializing activity tracking system...");

    // Warm up caches
    cache_->warmup(db_);

    // Start background aggregation
    aggregator_->start();

    logger_.info("Activity tracking system initialized");
  }

  // ---- Shutdown ----
  void shutdown() {
    logger_.info("Shutting down activity tracking system...");
    aggregator_->shutdown();
    logger_.info("Activity tracking system shut down");
  }

  // ---- Activity recording (called from event handlers) ----
  void on_user_activity(const std::string& user_id,
                         const std::string& room_id,
                         const std::string& event_type,
                         const std::string& device_id = "",
                         const std::string& event_id = "") {
    timeline_->record_activity_event(user_id, room_id, event_type,
                                      device_id, event_id);
  }

  void on_user_sync(const std::string& user_id,
                     const std::string& device_id = "") {
    timeline_->record_daily_visit(user_id, device_id, "sync");
  }

  void on_session_start(const std::string& user_id,
                         const std::string& device_id,
                         const std::string& ip = "",
                         const std::string& ua = "") {
    sessions_->start_session(user_id, device_id, ip, ua);
  }

  void on_session_end(const std::string& session_id) {
    sessions_->end_session(session_id);
  }

  // ---- DAU/MAU Queries ----
  int64_t get_dau() { return dau_->compute_current_dau(); }
  int64_t get_mau() { return mau_->compute_current_mau(); }
  int64_t get_wau() { return wau_->compute_current_wau(); }
  double get_stickiness() { return mau_->get_stickiness_ratio(); }
  double get_dau_growth() { return dau_->get_dau_growth_rate(7); }

  // ---- Admin API ----
  json admin_overview() { return admin_->handle_overview(); }
  json admin_dau_series(int64_t days = 90) { return admin_->handle_dau(days); }
  json admin_dau_trend(int64_t days = 30) { return admin_->handle_dau_trend(days); }
  json admin_dau_forecast(int64_t days = 7) { return admin_->handle_dau_forecast(days); }
  json admin_dau_devices(const std::string& date = "") { return admin_->handle_dau_devices(date); }
  json admin_dau_yoy() { return admin_->handle_dau_yoy(); }
  json admin_mau_series(int64_t months = 12) { return admin_->handle_mau(months); }
  json admin_mau_trend(int64_t months = 12) { return admin_->handle_mau_trend(months); }
  json admin_mau_breakdown() { return admin_->handle_mau_breakdown(); }
  json admin_wau_series(int64_t weeks = 52) { return admin_->handle_wau(weeks); }
  json admin_weekend_split() { return admin_->handle_weekend_split(); }
  json admin_user_timeline(const std::string& uid, const std::string& b = "daily",
                            int64_t d = 90) { return admin_->handle_user_timeline(uid, b, d); }
  json admin_server_timeline(const std::string& b = "daily", int64_t p = 90) {
    return admin_->handle_server_timeline(b, p); }
  json admin_cumulative_curve(int64_t d = 90) { return admin_->handle_cumulative_curve(d); }
  json admin_user_sessions(const std::string& uid, int64_t l = 50) {
    return admin_->handle_user_sessions(uid, l); }
  json admin_session_distribution(int64_t d = 30) { return admin_->handle_session_distribution(d); }
  json admin_concurrent_peak() { return admin_->handle_concurrent_peak(); }
  json admin_heatmap(const std::string& p = "dow_hour", int64_t d = 30) {
    return admin_->handle_heatmap(p, d); }
  json admin_room_heatmap(const std::string& rid, int64_t d = 30) {
    return admin_->handle_room_heatmap(rid, d); }
  json admin_user_fingerprint(const std::string& uid, int64_t d = 90) {
    return admin_->handle_user_fingerprint(uid, d); }
  json admin_retention(int64_t days = 30) { return admin_->handle_retention(days); }
  json admin_cohorts(int64_t months = 12) { return admin_->handle_cohorts(months); }
  json admin_churn_risk(const std::string& uid) { return admin_->handle_churn_risk(uid); }
  json admin_activation_funnel() { return admin_->handle_activation_funnel(); }
  json admin_power_curve() { return admin_->handle_power_curve(); }
  json admin_user_engagement(const std::string& uid) { return admin_->handle_user_engagement(uid); }
  json admin_engagement_distribution() { return admin_->handle_engagement_distribution(); }
  json admin_engagement_trend() { return admin_->handle_engagement_trend(); }
  json admin_compute_engagement(int64_t bs = 1000) { return admin_->handle_compute_engagement(bs); }
  json admin_peaks(int64_t d = 30) { return admin_->handle_peaks(d); }
  json admin_anomalies() { return admin_->handle_anomalies(); }
  json admin_weekly_cycle() { return admin_->handle_weekly_cycle(); }
  json admin_cache_stats() { return admin_->handle_cache_stats(); }
  json admin_cache_refresh() { return admin_->handle_cache_refresh(); }
  json admin_cache_warmup() { return admin_->handle_cache_warmup(db_); }
  json admin_aggregator_status() { return admin_->handle_aggregator_status(); }
  json admin_aggregator_start() { return admin_->handle_aggregator_start(); }
  json admin_aggregator_stop() { return admin_->handle_aggregator_stop(); }
  json admin_aggregator_force() { return admin_->handle_aggregator_force(); }
  json admin_record_visit(const std::string& uid, const std::string& did = "",
                           const std::string& at = "sync") {
    return admin_->handle_record_visit(uid, did, at); }
  json admin_record_event(const std::string& uid, const std::string& rid,
                           const std::string& et, const std::string& did = "",
                           const std::string& eid = "") {
    return admin_->handle_record_event(uid, rid, et, did, eid); }
  json admin_session_start(const std::string& uid, const std::string& did,
                            const std::string& ip = "", const std::string& ua = "") {
    return admin_->handle_session_start(uid, did, ip, ua); }
  json admin_session_end(const std::string& sid) {
    return admin_->handle_session_end(sid); }

  // ---- Prometheus metrics ----
  std::string get_prometheus_metrics() { return exporter_->render_metrics(); }

  // ---- Direct engine access (for integration) ----
  DailyActiveUsersEngine& dau_engine() { return *dau_; }
  MonthlyActiveUsersEngine& mau_engine() { return *mau_; }
  WeeklyActiveUsersEngine& wau_engine() { return *wau_; }
  ActivityTimelineTracker& timeline() { return *timeline_; }
  UserSessionTracker& sessions() { return *sessions_; }
  ActivityHeatmapBuilder& heatmap() { return *heatmap_; }
  RetentionAnalyzer& retention() { return *retention_; }
  EngagementScorer& engagement() { return *engagement_; }
  PeakUsageAnalyzer& peaks() { return *peaks_; }
  ActivityDataCache& cache() { return *cache_; }
  BackgroundActivityAggregator& aggregator() { return *aggregator_; }

private:
  storage::DatabasePool& db_;
  std::unique_ptr<ActivityDataCache> cache_;
  std::unique_ptr<DailyActiveUsersEngine> dau_;
  std::unique_ptr<MonthlyActiveUsersEngine> mau_;
  std::unique_ptr<WeeklyActiveUsersEngine> wau_;
  std::unique_ptr<ActivityTimelineTracker> timeline_;
  std::unique_ptr<UserSessionTracker> sessions_;
  std::unique_ptr<ActivityHeatmapBuilder> heatmap_;
  std::unique_ptr<RetentionAnalyzer> retention_;
  std::unique_ptr<EngagementScorer> engagement_;
  std::unique_ptr<PeakUsageAnalyzer> peaks_;
  std::unique_ptr<BackgroundActivityAggregator> aggregator_;
  std::unique_ptr<ActivityAdminHandler> admin_;
  std::unique_ptr<ActivityMetricsExporter> exporter_;
  ActivityLogger& logger_;
};

// ============================================================================
// Public factory function — creates the activity tracking system
// ============================================================================

std::shared_ptr<ActivityTrackingOrchestrator> create_activity_tracking(
    storage::DatabasePool& db) {
  auto orchestrator = std::make_shared<ActivityTrackingOrchestrator>(db);
  orchestrator->initialize();
  return orchestrator;
}

}  // namespace progressive
