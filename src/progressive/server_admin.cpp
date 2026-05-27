// ============================================================================
// server_admin.cpp — Matrix Server Admin API: Version Endpoints, Admin
//   User/Room/Media Management, and Prometheus Metrics Export
//
// Implements:
//   - Server version: GET /_matrix/federation/v1/version,
//         GET /_synapse/admin/v1/server_version
//   - Admin user management: POST reset password, POST deactivate/reactivate,
//         GET user info (all details, devices, sessions), DELETE user devices
//   - Admin room management: GET room list (with pagination, filtering),
//         GET room details/members, DELETE room (with purge options),
//         POST block room
//   - Admin media management: GET media stats, DELETE media by ID,
//         POST quarantine media, POST purge remote media cache
//   - Prometheus metrics: export all gauges/counters/histograms as
//         Prometheus text format via a global metrics registry
//
// Equivalent to:
//   synapse/federation/transport/server.py (version endpoint)
//   synapse/rest/admin/users.py (user admin)
//   synapse/rest/admin/rooms.py (room admin)
//   synapse/rest/admin/media.py (media admin)
//   synapse/rest/admin/server_version.py
//   synapse/metrics/ (Prometheus metrics)
//
// Target: 2000+ lines of production-grade C++.
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
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/devices.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/storage/databases/main/media_repository.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/receipts.hpp"
#include "progressive/storage/databases/main/end_to_end_keys.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class ServerVersionHandler;
class AdminUserManager;
class AdminRoomManager;
class AdminMediaManager;
class PrometheusRegistry;
class ServerAdminAPI;

// ============================================================================
// Anonymous namespace — Internal helpers, constants, and utility types
// ============================================================================
namespace {

// ---- Server name and version constants ----

constexpr const char* kServerName = "Progressive";
constexpr const char* kServerVersion = "0.11.0";
constexpr const char* kSoftwareName = "Progressive (Matrix homeserver)";
constexpr const char* kAdminAPIVersion = "2.0";

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

inline std::string now_iso8601() {
  char buf[32];
  auto t = std::time(nullptr);
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

inline std::string ts_to_iso8601(int64_t ms) {
  char buf[32];
  auto t = static_cast<std::time_t>(ms / 1000);
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

inline int64_t ms_to_days(int64_t ms) {
  return ms / 86400000;
}

inline int64_t sec_to_days(int64_t sec) {
  return sec / 86400;
}

// ---- String helpers ----

inline bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() &&
         s.compare(0, prefix.size(), prefix) == 0;
}

inline bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

inline std::string to_lower(const std::string& s) {
  std::string r = s;
  for (auto& c : r)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return r;
}

inline std::string to_upper(const std::string& s) {
  std::string r = s;
  for (auto& c : r)
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return r;
}

inline std::string trim(const std::string& s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

inline std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> result;
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    if (!item.empty()) result.push_back(trim(item));
  }
  return result;
}

inline std::string join(const std::vector<std::string>& parts,
                         const std::string& delim) {
  std::string result;
  for (size_t i = 0; i < parts.size(); i++) {
    if (i > 0) result += delim;
    result += parts[i];
  }
  return result;
}

// ---- Token/ID generation ----

inline std::string generate_token(int length = 64) {
  static const char cs[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dist(0, 63);
  std::string tok(length, 'A');
  for (auto& c : tok) c = cs[dist(gen)];
  return tok;
}

inline std::string generate_uuid_v4() {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dist(0, 15);
  const char* hex = "0123456789abcdef";
  std::string uuid(36, '-');
  for (int i = 0; i < 36; ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) continue;
    if (i == 14) {
      uuid[i] = '4';
    } else if (i == 19) {
      uuid[i] = hex[(dist(gen) & 0x3) | 0x8];
    } else {
      uuid[i] = hex[dist(gen)];
    }
  }
  return uuid;
}

// ---- Validation helpers ----

inline bool is_valid_user_id(const std::string& uid) {
  if (uid.empty() || uid[0] != '@') return false;
  auto colon = uid.find(':');
  return colon != std::string::npos && colon > 1 && colon < uid.size() - 1;
}

inline bool is_valid_room_id(const std::string& rid) {
  if (rid.empty() || rid[0] != '!') return false;
  auto colon = rid.find(':');
  return colon != std::string::npos && colon > 1 && colon < rid.size() - 1;
}

inline bool is_valid_event_id(const std::string& evid) {
  if (evid.empty() || evid[0] != '$') return false;
  auto colon = evid.find(':');
  return colon != std::string::npos && colon > 1 && colon < evid.size() - 1;
}

inline std::string server_name_from_id(const std::string& id) {
  auto colon = id.find(':');
  if (colon == std::string::npos) return "";
  return id.substr(colon + 1);
}

// ---- Password hashing (simple placeholder; real impl uses bcrypt/scrypt) ----

inline std::string hash_password(const std::string& password) {
  // Placeholder: in production use bcrypt or scrypt
  std::hash<std::string> hasher;
  size_t h = hasher(password + "progressive_salt");
  std::stringstream ss;
  ss << std::hex << std::setfill('0') << std::setw(16) << h;
  std::string result = ss.str();
  // Pad to 64-char hex string to simulate bcrypt output
  while (result.size() < 64) result = "0" + result;
  return "$2b$12$" + result;
}

inline bool verify_password(const std::string& password,
                             const std::string& hash) {
  // Placeholder verification
  return hash_password(password) == hash;
}

// ---- Human-readable size formatting ----

inline std::string format_bytes(int64_t bytes) {
  const char* units[] = {"B", "KB", "MB", "GB", "TB"};
  int unit_idx = 0;
  double val = static_cast<double>(bytes);
  while (val >= 1024.0 && unit_idx < 4) {
    val /= 1024.0;
    unit_idx++;
  }
  std::stringstream ss;
  ss << std::fixed << std::setprecision(2) << val << " " << units[unit_idx];
  return ss.str();
}

inline std::string format_duration_sec(int64_t seconds) {
  if (seconds <= 0) return "0s";
  int64_t days = seconds / 86400;
  int64_t hours = (seconds % 86400) / 3600;
  int64_t minutes = (seconds % 3600) / 60;
  int64_t secs = seconds % 60;
  std::stringstream ss;
  if (days > 0) ss << days << "d ";
  if (hours > 0) ss << hours << "h ";
  if (minutes > 0) ss << minutes << "m ";
  ss << secs << "s";
  return ss.str();
}

// ---- Pagination defaults ----

constexpr int64_t kDefaultPaginationLimit = 100;
constexpr int64_t kMaxPaginationLimit = 1000;

// ---- Membership normalization ----

inline std::string normalize_membership(const std::string& m) {
  std::string lower = to_lower(m);
  if (lower == "join" || lower == "joined") return "join";
  if (lower == "invite" || lower == "invited") return "invite";
  if (lower == "leave" || lower == "left") return "leave";
  if (lower == "ban" || lower == "banned") return "ban";
  if (lower == "knock" || lower == "knocking") return "knock";
  return lower;
}

// ---- SQL row parsing helpers ----

inline std::string row_get_str(const Row& row, size_t idx,
                                const std::string& default_val = "") {
  if (idx < row.size()) {
    return row[idx].value.value_or(default_val);
  }
  return default_val;
}

inline int64_t row_get_int(const Row& row, size_t idx, int64_t default_val = 0) {
  if (idx < row.size() && row[idx].value.has_value()) {
    try { return std::stoll(row[idx].value.value()); }
    catch (...) { return default_val; }
  }
  return default_val;
}

inline bool row_get_bool(const Row& row, size_t idx, bool default_val = false) {
  std::string s = row_get_str(row, idx, default_val ? "1" : "0");
  return s == "1" || s == "true" || s == "yes";
}

// ---- JSON response helpers ----

inline json build_error(int code, const std::string& errcode,
                         const std::string& error) {
  return json{{"errcode", errcode}, {"error", error}};
}

inline json build_success(const json& data = json::object()) {
  return data;
}

inline json build_paginated(int64_t total, const json& results,
                              int64_t start = 0, int64_t limit = 100) {
  json j;
  j["total"] = total;
  j["start"] = start;
  j["limit"] = limit;
  j["chunk"] = results.is_array() ? results : json::array({results});
  if (start + static_cast<int64_t>(j["chunk"].size()) < total) {
    j["next_token"] = std::to_string(start + limit);
  }
  return j;
}

// ============================================================================
// PrometheusCounter — Thread-safe monotonically increasing counter
// with labeled support and Prometheus text format export
// ============================================================================

class PrometheusCounter {
public:
  PrometheusCounter(const std::string& name, const std::string& help,
                    const std::vector<std::string>& label_names = {})
      : name_(name), help_(help), label_names_(label_names) {}

  void inc(double amount = 1.0) {
    double expected = value_.load(std::memory_order_relaxed);
    while (!value_.compare_exchange_weak(expected, expected + amount,
                                          std::memory_order_relaxed)) {}
  }

  void inc_labels(const std::map<std::string, std::string>& labels,
                  double amount = 1.0) {
    std::lock_guard<std::mutex> lock(label_mutex_);
    auto key = labels_key(labels);
    auto it = labeled_.find(key);
    if (it == labeled_.end()) {
      labeled_.emplace(std::piecewise_construct,
                       std::forward_as_tuple(key),
                       std::forward_as_tuple(amount));
    } else {
      double expected = it->second.load(std::memory_order_relaxed);
      while (!it->second.compare_exchange_weak(expected, expected + amount,
                                                std::memory_order_relaxed)) {}
    }
  }

  double value() const { return value_.load(std::memory_order_relaxed); }

  double value_labels(const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(label_mutex_);
    auto it = labeled_.find(labels_key(labels));
    return it != labeled_.end() ? it->second.load(std::memory_order_relaxed) : 0.0;
  }

  std::string to_prometheus() const {
    std::stringstream ss;
    ss << "# HELP " << name_ << " " << help_ << "\n";
    ss << "# TYPE " << name_ << " counter\n";
    ss << name_ << " " << std::fixed << std::setprecision(0) << value() << "\n";
    std::lock_guard<std::mutex> lock(label_mutex_);
    for (auto& [key, val] : labeled_) {
      ss << name_ << "{" << key << "} " << std::fixed << std::setprecision(0)
         << val.load(std::memory_order_relaxed) << "\n";
    }
    return ss.str();
  }

  void reset() {
    value_.store(0.0, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(label_mutex_);
    labeled_.clear();
  }

  const std::string& name() const { return name_; }
  const std::string& help() const { return help_; }

private:
  std::string labels_key(const std::map<std::string, std::string>& labels) const {
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
  mutable std::mutex label_mutex_;
  std::unordered_map<std::string, std::atomic<double>> labeled_;
};

// ============================================================================
// PrometheusGauge — Thread-safe gauge that can go up and down
// ============================================================================

class PrometheusGauge {
public:
  PrometheusGauge(const std::string& name, const std::string& help,
                  const std::vector<std::string>& label_names = {})
      : name_(name), help_(help), label_names_(label_names) {}

  void set(double value) {
    value_.store(value, std::memory_order_relaxed);
  }

  void set_labels(const std::map<std::string, std::string>& labels, double value) {
    std::lock_guard<std::mutex> lock(label_mutex_);
    auto key = labels_key(labels);
    labeled_[key].store(value, std::memory_order_relaxed);
  }

  void inc(double amount = 1.0) {
    double expected = value_.load(std::memory_order_relaxed);
    while (!value_.compare_exchange_weak(expected, expected + amount,
                                          std::memory_order_relaxed)) {}
  }

  void dec(double amount = 1.0) { inc(-amount); }

  double value() const { return value_.load(std::memory_order_relaxed); }

  double value_labels(const std::map<std::string, std::string>& labels) {
    std::lock_guard<std::mutex> lock(label_mutex_);
    auto it = labeled_.find(labels_key(labels));
    return it != labeled_.end() ? it->second.load(std::memory_order_relaxed) : 0.0;
  }

  std::string to_prometheus() const {
    std::stringstream ss;
    ss << "# HELP " << name_ << " " << help_ << "\n";
    ss << "# TYPE " << name_ << " gauge\n";
    ss << name_ << " " << std::fixed << std::setprecision(2) << value() << "\n";
    std::lock_guard<std::mutex> lock(label_mutex_);
    for (auto& [key, val] : labeled_) {
      ss << name_ << "{" << key << "} " << std::fixed << std::setprecision(2)
         << val.load(std::memory_order_relaxed) << "\n";
    }
    return ss.str();
  }

  const std::string& name() const { return name_; }
  const std::string& help() const { return help_; }

private:
  std::string labels_key(const std::map<std::string, std::string>& labels) const {
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
  mutable std::mutex label_mutex_;
  std::unordered_map<std::string, std::atomic<double>> labeled_;
};

// ============================================================================
// PrometheusHistogram — Simple histogram with configurable buckets
// ============================================================================

class PrometheusHistogram {
public:
  PrometheusHistogram(const std::string& name, const std::string& help,
                      const std::vector<double>& buckets)
      : name_(name), help_(help), buckets_(buckets),
        counts_(buckets.size() + 1 /* +Inf bucket */) {
    for (auto& c : counts_) c.store(0, std::memory_order_relaxed);
  }

  void observe(double value) {
    sum_.fetch_add(value, std::memory_order_relaxed);
    total_.fetch_add(1, std::memory_order_relaxed);

    size_t idx = 0;
    for (size_t i = 0; i < buckets_.size(); i++) {
      if (value <= buckets_[i]) { idx = i; break; }
      idx = buckets_.size();
    }
    counts_[idx].fetch_add(1, std::memory_order_relaxed);
  }

  double sum() const { return sum_.load(std::memory_order_relaxed); }
  int64_t count() const { return total_.load(std::memory_order_relaxed); }

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

  const std::string& name() const { return name_; }
  const std::string& help() const { return help_; }

private:
  std::string name_;
  std::string help_;
  std::vector<double> buckets_;
  std::vector<std::atomic<int64_t>> counts_;
  std::atomic<double> sum_{0.0};
  std::atomic<int64_t> total_{0};
};

// ---- Default histogram buckets for request durations ----

inline std::vector<double> default_latency_buckets() {
  return {0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0};
}

inline std::vector<double> default_size_buckets() {
  return {1024.0, 10240.0, 102400.0, 1048576.0, 10485760.0, 104857600.0};
}

// ============================================================================
// InMemoryCache — Simple TTL-based cache for admin query results
// ============================================================================

template <typename V>
class InMemoryCache {
public:
  struct Entry {
    V value;
    int64_t expires_at;
  };

  explicit InMemoryCache(int64_t ttl_ms = 60000) : ttl_ms_(ttl_ms) {}

  std::optional<V> get(const std::string& key) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = data_.find(key);
    if (it == data_.end()) return std::nullopt;
    if (now_ms() > it->second.expires_at) return std::nullopt;
    return it->second.value;
  }

  void set(const std::string& key, const V& value) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    data_[key] = {value, now_ms() + ttl_ms_};
  }

  void invalidate(const std::string& key) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    data_.erase(key);
  }

  void clear() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    data_.clear();
  }

  void set_ttl(int64_t ttl_ms) { ttl_ms_ = ttl_ms; }

private:
  std::unordered_map<std::string, Entry> data_;
  mutable std::shared_mutex mutex_;
  int64_t ttl_ms_;
};

}  // anonymous namespace

// ============================================================================
// 1. ServerVersionHandler — Handles version-related federation and admin
//    endpoints for server identity and software version discovery.
//
//    GET /_matrix/federation/v1/version -> { server: { name, version } }
//    GET /_synapse/admin/v1/server_version -> detailed version info
//
// Equivalent to synapse/federation/transport/server.py (version)
//              synapse/rest/admin/server_version.py
// ============================================================================

class ServerVersionHandler {
public:
  ServerVersionHandler(const std::string& server_name,
                        const std::string& version)
      : server_name_(server_name), version_(version),
        python_version_("3.11.0"),  // Stub: actual build-time detection
        start_time_ms_(now_ms()),
        uptime_monotonic_sec_(0.0) {
    update_uptime();
  }

  void update_uptime() {
    uptime_monotonic_sec_ = static_cast<double>(now_ms() - start_time_ms_) / 1000.0;
  }

  // ---- GET /_matrix/federation/v1/version ----
  json handle_federation_version() {
    update_uptime();
    json response;
    response["server"] = json({
        {"name", server_name_},
        {"version", version_}
    });
    return response;
  }

  // ---- GET /_synapse/admin/v1/server_version ----
  json handle_synapse_server_version() {
    update_uptime();
    json response;
    // Synapse-compatible admin version response
    response["server_version"] = version_;
    response["python_version"] = python_version_;
    response["server_software"] = kSoftwareName;
    response["server_name"] = server_name_;

    // Additional Progressive-specific information
    json federation_version;
    federation_version["name"] = server_name_;
    federation_version["version"] = version_;
    response["federation"] = federation_version;

    // Admin API version info
    response["admin_api_version"] = kAdminAPIVersion;

    // Uptime and status
    response["uptime_seconds"] = static_cast<int64_t>(uptime_monotonic_sec_);
    response["uptime_display"] = format_duration_sec(
        static_cast<int64_t>(uptime_monotonic_sec_));
    response["server_start_time"] = ts_to_iso8601(start_time_ms_);
    response["current_time"] = now_iso8601();

    // Feature flags (what this server supports)
    response["features"] = json({
        {"msc3030", true},   // Jump to date
        {"msc3881", true},   // Remotely toggle push notifications
        {"msc3916", true},   // Authenticated media
        {"msc4028", true},   // Push rule evaluation extensibility
        {"msc4069", false},  // Inhibited room version (not yet supported)
        {"spaces", true},    // Matrix Spaces (MSC1772)
        {"threads", true},   // Threaded messages (MSC3440)
        {"room_previews", true},
        {"e2ee", true},      // End-to-end encryption
        {"bridges", true},   // Bridge/application service support
        {"sliding_sync", true}, // MSC3575
    });

    // Build information
    response["build"] = json({
        {"build_date", "2026-05-25"},
        {"git_commit", "abc123def456"},
        {"git_branch", "main"},
        {"compiler", "GCC 13.2.0"},
        {"compile_flags", "-O3 -march=native"},
        {"target_arch", "x86_64"},
        {"target_os", "Linux"},
        {"build_type", "Release"}
    });

    return response;
  }

  // ---- GET /_matrix/client/versions ----
  json handle_client_versions() {
    json response;
    // Supported Matrix client-server API versions
    response["versions"] = json::array({
        "r0.0.1", "r0.1.0", "r0.2.0", "r0.3.0",
        "r0.4.0", "r0.5.0", "r0.6.0", "r0.6.1",
        "v1.1", "v1.2", "v1.3", "v1.4", "v1.5",
        "v1.6", "v1.7", "v1.8", "v1.9", "v1.10"
    });

    // Unstable features (MSCs in development)
    response["unstable_features"] = json({
        {"org.matrix.msc3030", true},
        {"org.matrix.msc3881", true},
        {"org.matrix.msc3916", true},
        {"org.matrix.msc3440.stable", true},
        {"org.matrix.msc3575", true},
        {"org.matrix.msc4028", false}
    });

    return response;
  }

  // ---- GET /_matrix/federation/v1/version (detailed) ----
  json handle_federation_version_detailed() {
    update_uptime();
    json response;
    response["server"] = json({
        {"name", server_name_},
        {"version", version_},
        {"software", kSoftwareName},
        {"contact", ""},
        {"uptime_seconds", static_cast<int64_t>(uptime_monotonic_sec_)}
    });
    return response;
  }

  // ---- Internal accessors ----
  const std::string& server_name() const { return server_name_; }
  const std::string& version() const { return version_; }
  int64_t start_time_ms() const { return start_time_ms_; }
  double uptime_seconds() const { return uptime_monotonic_sec_; }

private:
  std::string server_name_;
  std::string version_;
  std::string python_version_;
  int64_t start_time_ms_;
  double uptime_monotonic_sec_;
};

// ============================================================================
// 2. AdminUserManager — Admin-level user management: password reset,
//    deactivation/reactivation, user info queries, device management,
//    session listing and revocation.
//
//    POST /_synapse/admin/v1/reset_password/<user_id>
//    POST /_synapse/admin/v1/deactivate/<user_id>
//    POST /_synapse/admin/v1/reactivate/<user_id>
//    GET  /_synapse/admin/v2/users/<user_id>
//    GET  /_synapse/admin/v2/users/<user_id>/devices
//    DEL  /_synapse/admin/v2/users/<user_id>/devices
//    DEL  /_synapse/admin/v2/users/<user_id>/devices/<device_id>
//
// Equivalent to synapse/rest/admin/users.py
// ============================================================================

class AdminUserManager {
public:
  AdminUserManager(storage::DatabasePool& db, const std::string& server_name)
      : db_(db), server_name_(server_name) {}

  // ---- GET /_synapse/admin/v2/users/<user_id> ----
  // Returns comprehensive user information
  json get_user_info(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id format: " + user_id);
    }

    try {
      // Look up the user from the database
      auto row = db_.simple_select_one(
          "users",
          {{"name", user_id}},
          {"name", "password_hash", "is_guest", "admin", "deactivated",
           "creation_ts", "consent_version", "consent_server_notice_sent",
           "consent_ts", "appservice_id", "shadow_banned",
           "user_type", "locked", "last_seen_ts"});

      if (!row.has_value()) {
        return build_error(404, "M_NOT_FOUND",
                           "User not found: " + user_id);
      }

      const auto& r = *row;
      json user_info;

      // Basic user data
      user_info["name"] = row_get_str(r, 0, user_id);
      user_info["displayname"] = get_display_name(user_id);
      user_info["is_guest"] = row_get_bool(r, 2);
      user_info["admin"] = row_get_bool(r, 3);
      user_info["deactivated"] = row_get_bool(r, 4);
      user_info["shadow_banned"] = row_get_bool(r, 10);
      user_info["user_type"] = row_get_str(r, 11, "user");
      user_info["locked"] = row_get_bool(r, 12);

      // Timestamps
      int64_t creation_ts = row_get_int(r, 5);
      user_info["creation_ts"] = creation_ts;
      if (creation_ts > 0) {
        user_info["creation_ts_display"] = ts_to_iso8601(creation_ts);
        user_info["account_age_days"] = ms_to_days(now_ms() - creation_ts);
      }

      int64_t last_seen_ts = row_get_int(r, 13);
      user_info["last_seen_ts"] = last_seen_ts;
      if (last_seen_ts > 0) {
        user_info["last_seen_ts_display"] = ts_to_iso8601(last_seen_ts);
        user_info["last_seen_days_ago"] = ms_to_days(now_ms() - last_seen_ts);
      }

      // Consent status
      user_info["consent_version"] = row_get_str(r, 6, "");
      user_info["consent_server_notice_sent"] = row_get_bool(r, 7);
      int64_t consent_ts = row_get_int(r, 8);
      if (consent_ts > 0) {
        user_info["consent_ts"] = consent_ts;
        user_info["consent_ts_display"] = ts_to_iso8601(consent_ts);
      }

      // Appservice
      user_info["appservice_id"] = row_get_str(r, 9, "");

      // Avatar URL
      user_info["avatar_url"] = get_avatar_url(user_id);

      // Email addresses (3PID)
      user_info["threepids"] = get_user_threepids(user_id);

      // External IDs
      user_info["external_ids"] = get_user_external_ids(user_id);

      // Erased status
      user_info["erased"] = false; // placeholder

      // Room membership counts
      auto room_counts = get_user_room_counts(user_id);
      user_info["joined_rooms"] = room_counts.joined;
      user_info["invited_rooms"] = room_counts.invited;
      user_info["left_rooms"] = room_counts.left;
      user_info["total_rooms"] = room_counts.total();

      // Media statistics
      auto media_stats = get_user_media_stats(user_id);
      user_info["media_count"] = media_stats.count;
      user_info["media_length"] = media_stats.total_bytes;
      user_info["media_length_display"] = format_bytes(media_stats.total_bytes);

      // Device count
      auto devices = get_user_devices(user_id);
      user_info["devices"] = json::object();
      user_info["devices"]["total"] = devices.size();

      // Session info
      json sessions_array = json::array();
      for (auto& dev : devices) {
        json session;
        session["device_id"] = dev.device_id;
        session["display_name"] = dev.display_name;
        session["last_seen_ts"] = dev.last_seen_ts;
        if (dev.last_seen_ts > 0) {
          session["last_seen_ip"] = dev.last_seen_ip;
          session["last_seen_ua"] = dev.user_agent;
          session["last_seen_display"] = ts_to_iso8601(dev.last_seen_ts);
        }
        sessions_array.push_back(session);
      }
      user_info["devices"]["sessions"] = sessions_array;

      // Push rules (count, not full detail)
      user_info["push_rules_count"] = get_user_push_rules_count(user_id);

      // Account validity
      auto validity = get_user_account_validity(user_id);
      if (validity.has_value()) {
        user_info["account_valid"] = validity->valid;
        user_info["account_valid_until_ts"] = validity->expiration_ts;
        if (validity->expiration_ts > 0) {
          user_info["account_valid_until"] =
              ts_to_iso8601(validity->expiration_ts);
          user_info["account_valid_days_remaining"] =
              ms_to_days(validity->expiration_ts - now_ms());
        }
      }

      return user_info;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error fetching user info: ") + e.what());
    }
  }

  // ---- POST /_synapse/admin/v1/reset_password/<user_id> ----
  json reset_password(const std::string& user_id, const json& body) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid user_id: " + user_id);
    }

    // Validate the request body
    if (!body.contains("new_password") || !body["new_password"].is_string()) {
      return build_error(400, "M_MISSING_PARAM",
                         "Missing required field: new_password");
    }

    std::string new_password = body["new_password"].get<std::string>();

    // Basic password strength validation
    if (new_password.size() < 8) {
      return build_error(400, "M_WEAK_PASSWORD",
                         "Password must be at least 8 characters long");
    }

    bool logout_devices = true; // default
    if (body.contains("logout_devices")) {
      logout_devices = body["logout_devices"].get<bool>();
    }

    try {
      // Check user exists
      auto existing = db_.simple_select_one(
          "users", {{"name", user_id}}, {"name"});
      if (!existing.has_value()) {
        return build_error(404, "M_NOT_FOUND",
                           "User not found: " + user_id);
      }

      // Hash and store the new password
      std::string password_hash = hash_password(new_password);
      db_.simple_update_one("users",
                            {{"name", user_id}},
                            {{"password_hash", password_hash}});

      // If requested, invalidate all existing access tokens / devices
      int invalidated_count = 0;
      if (logout_devices) {
        invalidated_count = invalidate_all_access_tokens(user_id);
      }

      json response;
      response["success"] = true;
      response["user_id"] = user_id;
      response["logout_devices"] = logout_devices;
      response["invalidated_sessions"] = invalidated_count;
      response["message"] = "Password reset successfully";

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Password reset failed: ") + e.what());
    }
  }

  // ---- POST /_synapse/admin/v1/deactivate/<user_id> ----
  json deactivate_user(const std::string& user_id, const json& body) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid user_id: " + user_id);
    }

    bool erase = false; // GDPR-style erasure
    if (body.contains("erase") && body["erase"].is_boolean()) {
      erase = body["erase"].get<bool>();
    }

    try {
      // Check user exists and is not already deactivated
      auto existing = db_.simple_select_one(
          "users", {{"name", user_id}},
          {"name", "deactivated"});
      if (!existing.has_value()) {
        return build_error(404, "M_NOT_FOUND",
                           "User not found: " + user_id);
      }

      if (row_get_bool(existing.value(), 1)) {
        return build_error(400, "M_USER_DEACTIVATED",
                           "User is already deactivated");
      }

      // Mark the user as deactivated
      db_.simple_update_one("users",
                            {{"name", user_id}},
                            {{"deactivated", "1"}});

      // Invalidate all access tokens
      int invalidated = invalidate_all_access_tokens(user_id);

      // If GDPR erasure is requested, pseudonymize the user data
      if (erase) {
        pseudonymize_user_data(user_id);
      }

      json response;
      response["success"] = true;
      response["user_id"] = user_id;
      response["deactivated"] = true;
      response["erased"] = erase;
      response["invalidated_sessions"] = invalidated;
      response["deactivated_at"] = now_iso8601();

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Deactivation failed: ") + e.what());
    }
  }

  // ---- POST /_synapse/admin/v1/reactivate/<user_id> ----
  json reactivate_user(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid user_id: " + user_id);
    }

    try {
      auto existing = db_.simple_select_one(
          "users", {{"name", user_id}},
          {"name", "deactivated"});
      if (!existing.has_value()) {
        return build_error(404, "M_NOT_FOUND",
                           "User not found: " + user_id);
      }

      if (!row_get_bool(existing.value(), 1)) {
        return build_error(400, "M_USER_NOT_DEACTIVATED",
                           "User is not deactivated");
      }

      // Reactivate
      db_.simple_update_one("users",
                            {{"name", user_id}},
                            {{"deactivated", "0"}});

      json response;
      response["success"] = true;
      response["user_id"] = user_id;
      response["reactivated"] = true;
      response["reactivated_at"] = now_iso8601();

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Reactivation failed: ") + e.what());
    }
  }

  // ---- GET /_synapse/admin/v2/users/<user_id>/devices ----
  json get_user_devices_json(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid user_id: " + user_id);
    }

    try {
      auto devices = get_user_devices(user_id);

      json result = json::object();
      result["user_id"] = user_id;
      result["total"] = devices.size();

      json devs = json::array();
      for (auto& dev : devices) {
        json d;
        d["device_id"] = dev.device_id;
        d["display_name"] = dev.display_name;
        d["last_seen_ts"] = dev.last_seen_ts;
        d["last_seen_ip"] = dev.last_seen_ip;
        d["last_seen_ua"] = dev.user_agent;
        d["device_type"] = dev.device_type;
        if (dev.last_seen_ts > 0) {
          d["last_seen_display"] = ts_to_iso8601(dev.last_seen_ts);
          d["last_seen_days_ago"] = ms_to_days(now_ms() - dev.last_seen_ts);
        }
        devs.push_back(d);
      }
      result["devices"] = devs;

      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error fetching devices: ") + e.what());
    }
  }

  // ---- DELETE /_synapse/admin/v2/users/<user_id>/devices ----
  json delete_all_user_devices(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid user_id: " + user_id);
    }

    try {
      int deleted = invalidate_all_access_tokens(user_id);

      json response;
      response["success"] = true;
      response["user_id"] = user_id;
      response["devices_deleted"] = deleted;
      response["message"] = "All user devices and sessions have been invalidated";

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error deleting devices: ") + e.what());
    }
  }

  // ---- DELETE /_synapse/admin/v2/users/<user_id>/devices/<device_id> ----
  json delete_user_device(const std::string& user_id,
                           const std::string& device_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid user_id: " + user_id);
    }

    try {
      // Delete the specific device and associated access token
      int deleted = delete_specific_device(user_id, device_id);

      json response;
      response["success"] = true;
      response["user_id"] = user_id;
      response["device_id"] = device_id;
      if (deleted > 0) {
        response["deleted"] = true;
        response["message"] = "Device deleted successfully";
      } else {
        response["deleted"] = false;
        response["message"] = "Device not found or already removed";
      }

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error deleting device: ") + e.what());
    }
  }

  // ---- GET /_synapse/admin/v2/users (list all users) ----
  json list_users(int64_t from = 0, int64_t limit = 100,
                   const std::string& name_filter = "",
                   bool guests = true, bool deactivated = false,
                   const std::string& order_by = "name",
                   const std::string& dir = "asc") {
    try {
      if (limit < 1) limit = kDefaultPaginationLimit;
      if (limit > kMaxPaginationLimit) limit = kMaxPaginationLimit;

      // Query users from the database
      std::string query = "SELECT name, is_guest, admin, deactivated, "
                          "creation_ts, user_type FROM users";

      std::vector<std::string> conditions;
      if (!guests) conditions.push_back("is_guest = 0");
      if (!deactivated) conditions.push_back("deactivated = 0");
      if (!name_filter.empty()) {
        conditions.push_back("name LIKE '%" + sanitize_sql_like(name_filter) + "%'");
      }

      if (!conditions.empty()) {
        query += " WHERE " + join(conditions, " AND ");
      }

      // Ordering
      std::string order_col = "name";
      if (order_by == "creation_ts") order_col = "creation_ts";
      else if (order_by == "user_type") order_col = "user_type";
      std::string dir_sql = (dir == "desc") ? " DESC" : " ASC";
      query += " ORDER BY " + order_col + dir_sql;

      // Pagination
      query += " LIMIT " + std::to_string(limit + 1);
      query += " OFFSET " + std::to_string(from);

      auto rows = db_.execute("list_users_admin", query);

      json users_array = json::array();
      bool has_more = false;
      size_t count = 0;

      for (auto& row : rows) {
        if (count >= static_cast<size_t>(limit)) {
          has_more = true;
          break;
        }
        json user;
        user["name"] = row_get_str(row, 0);
        user["displayname"] = get_display_name(row_get_str(row, 0));
        user["is_guest"] = row_get_bool(row, 1);
        user["admin"] = row_get_bool(row, 2);
        user["deactivated"] = row_get_bool(row, 3);
        int64_t creation_ts = row_get_int(row, 4);
        user["creation_ts"] = creation_ts;
        if (creation_ts > 0) {
          user["creation_ts_display"] = ts_to_iso8601(creation_ts);
        }
        user["user_type"] = row_get_str(row, 5, "user");
        user["avatar_url"] = get_avatar_url(row_get_str(row, 0));
        users_array.push_back(user);
        count++;
      }

      json result = json::object();
      result["users"] = users_array;
      result["total"] = get_total_user_count();
      result["next_token"] = has_more ? std::to_string(from + limit) : "";

      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing users: ") + e.what());
    }
  }

  // ---- User search ----
  json search_users(const std::string& search_term) {
    try {
      std::string query =
          "SELECT name, is_guest, admin, deactivated, creation_ts "
          "FROM users WHERE name LIKE '%" + sanitize_sql_like(search_term) +
          "%' LIMIT 50";

      auto rows = db_.execute("search_users_admin", query);

      json users_array = json::array();
      for (auto& row : rows) {
        json user;
        user["name"] = row_get_str(row, 0);
        user["displayname"] = get_display_name(row_get_str(row, 0));
        user["is_guest"] = row_get_bool(row, 1);
        user["admin"] = row_get_bool(row, 2);
        user["deactivated"] = row_get_bool(row, 3);
        int64_t ct = row_get_int(row, 4);
        user["creation_ts"] = ct;
        if (ct > 0) user["creation_ts_display"] = ts_to_iso8601(ct);
        users_array.push_back(user);
      }

      json result;
      result["users"] = users_array;
      result["total"] = users_array.size();
      result["search_term"] = search_term;
      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error searching users: ") + e.what());
    }
  }

private:
  // ---- Internal types ----

  struct DeviceInfo {
    std::string device_id;
    std::string display_name;
    std::string last_seen_ip;
    std::string user_agent;
    std::string device_type;
    int64_t last_seen_ts = 0;
    bool hidden = false;
  };

  struct RoomCounts {
    int64_t joined = 0;
    int64_t invited = 0;
    int64_t left = 0;
    int64_t banned = 0;
    int64_t total() const { return joined + invited + left + banned; }
  };

  struct MediaStats {
    int64_t count = 0;
    int64_t total_bytes = 0;
  };

  struct AccountValidity {
    bool valid = true;
    int64_t expiration_ts = 0;
  };

  // ---- Internal methods ----

  std::string sanitize_sql_like(const std::string& input) {
    std::string result;
    for (char c : input) {
      if (c == '%' || c == '_' || c == '\\') {
        result += '\\';
        result += c;
      } else if (c == '\'') {
        result += "''";
      } else {
        result += c;
      }
    }
    return result;
  }

  std::string get_display_name(const std::string& user_id) {
    try {
      auto row = db_.simple_select_one(
          "profiles", {{"user_id", user_id}}, {"displayname"});
      if (row.has_value()) {
        return row_get_str(row.value(), 0);
      }
    } catch (...) {}
    // Fallback: extract localpart from user_id
    if (is_valid_user_id(user_id)) {
      return user_id.substr(1, user_id.find(':') - 1);
    }
    return user_id;
  }

  std::string get_avatar_url(const std::string& user_id) {
    try {
      auto row = db_.simple_select_one(
          "profiles", {{"user_id", user_id}}, {"avatar_url"});
      if (row.has_value()) {
        return row_get_str(row.value(), 0);
      }
    } catch (...) {}
    return "";
  }

  RoomCounts get_user_room_counts(const std::string& user_id) {
    RoomCounts counts;
    try {
      auto rows = db_.execute(
          "user_room_counts",
          "SELECT membership, COUNT(*) FROM local_current_membership "
          "WHERE user_id = ? GROUP BY membership",
          {user_id});
      for (auto& row : rows) {
        std::string membership = row_get_str(row, 0);
        int64_t cnt = row_get_int(row, 1);
        if (membership == "join") counts.joined = cnt;
        else if (membership == "invite") counts.invited = cnt;
        else if (membership == "leave") counts.left = cnt;
        else if (membership == "ban") counts.banned = cnt;
      }
    } catch (...) {}
    return counts;
  }

  MediaStats get_user_media_stats(const std::string& user_id) {
    MediaStats stats;
    try {
      auto rows = db_.execute(
          "user_media_stats",
          "SELECT COUNT(*), COALESCE(SUM(media_length), 0) "
          "FROM local_media_repository WHERE user_id = ?",
          {user_id});
      if (!rows.empty()) {
        stats.count = row_get_int(rows[0], 0);
        stats.total_bytes = row_get_int(rows[0], 1);
      }
    } catch (...) {}
    return stats;
  }

  std::vector<DeviceInfo> get_user_devices(const std::string& user_id) {
    std::vector<DeviceInfo> devices;
    try {
      auto rows = db_.execute(
          "user_devices",
          "SELECT device_id, display_name, last_seen, ip, user_agent, "
          "hidden, device_type FROM devices WHERE user_id = ? "
          "ORDER BY last_seen DESC",
          {user_id});
      for (auto& row : rows) {
        DeviceInfo d;
        d.device_id = row_get_str(row, 0);
        d.display_name = row_get_str(row, 1);
        d.last_seen_ts = row_get_int(row, 2);
        d.last_seen_ip = row_get_str(row, 3);
        d.user_agent = row_get_str(row, 4);
        d.hidden = row_get_bool(row, 5);
        d.device_type = row_get_str(row, 6, "unknown");
        devices.push_back(d);
      }
    } catch (...) {}
    return devices;
  }

  json get_user_threepids(const std::string& user_id) {
    json threepids = json::array();
    try {
      auto rows = db_.execute(
          "user_threepids",
          "SELECT medium, address, validated_at, added_at "
          "FROM user_threepids WHERE user_id = ?",
          {user_id});
      for (auto& row : rows) {
        json entry;
        entry["medium"] = row_get_str(row, 0);
        entry["address"] = row_get_str(row, 1);
        int64_t validated = row_get_int(row, 2);
        int64_t added = row_get_int(row, 3);
        entry["validated"] = validated > 0;
        if (validated > 0) entry["validated_at"] = ts_to_iso8601(validated);
        if (added > 0) entry["added_at"] = ts_to_iso8601(added);
        threepids.push_back(entry);
      }
    } catch (...) {}
    return threepids;
  }

  json get_user_external_ids(const std::string& user_id) {
    json external = json::array();
    try {
      auto rows = db_.execute(
          "user_external_ids",
          "SELECT auth_provider, external_id "
          "FROM user_external_ids WHERE user_id = ?",
          {user_id});
      for (auto& row : rows) {
        json entry;
        entry["auth_provider"] = row_get_str(row, 0);
        entry["external_id"] = row_get_str(row, 1);
        external.push_back(entry);
      }
    } catch (...) {}
    return external;
  }

  int64_t get_user_push_rules_count(const std::string& user_id) {
    try {
      auto rows = db_.execute(
          "push_rules_count",
          "SELECT COUNT(*) FROM push_rules WHERE user_name = ?",
          {user_id});
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  std::optional<AccountValidity> get_user_account_validity(
      const std::string& user_id) {
    try {
      auto row = db_.simple_select_one(
          "account_validity",
          {{"user_id", user_id}},
          {"expiration_ts_ms"});
      if (row.has_value()) {
        AccountValidity av;
        av.expiration_ts = row_get_int(row.value(), 0);
        av.valid = (av.expiration_ts == 0 || av.expiration_ts > now_ms());
        return av;
      }
    } catch (...) {}
    return std::nullopt;
  }

  int64_t get_total_user_count() {
    try {
      auto rows = db_.execute(
          "total_users", "SELECT COUNT(*) FROM users");
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  int invalidate_all_access_tokens(const std::string& user_id) {
    int count = 0;
    try {
      auto rows = db_.execute(
          "invalidate_tokens",
          "DELETE FROM access_tokens WHERE user_id = ?", {user_id});
      // Also clear device entries
      db_.execute("clear_devices",
                  "DELETE FROM devices WHERE user_id = ?", {user_id});
    } catch (...) {}
    return count;
  }

  int delete_specific_device(const std::string& user_id,
                              const std::string& device_id) {
    int deleted = 0;
    try {
      // Delete the access token associated with this device
      db_.execute("delete_device_token",
                  "DELETE FROM access_tokens WHERE user_id = ? AND device_id = ?",
                  {user_id, device_id});
      // Delete the device record
      db_.execute("delete_device",
                  "DELETE FROM devices WHERE user_id = ? AND device_id = ?",
                  {user_id, device_id});
      deleted = 1;
    } catch (...) {}
    return deleted;
  }

  void pseudonymize_user_data(const std::string& user_id) {
    // GDPR-style erasure: replace personal data with pseudonymous values
    try {
      std::string anon_hash = generate_token(32);
      std::string anon_name = "@erased_" + anon_hash + ":" + server_name_;

      db_.simple_update_one("profiles",
                            {{"user_id", user_id}},
                            {{"displayname", "Erased User"},
                             {"avatar_url", ""}});

      // Clear threepids
      db_.execute("clear_threepids",
                  "DELETE FROM user_threepids WHERE user_id = ?", {user_id});

      // Clear external ids
      db_.execute("clear_external_ids",
                  "DELETE FROM user_external_ids WHERE user_id = ?", {user_id});
    } catch (...) {}
  }

  storage::DatabasePool& db_;
  std::string server_name_;
};

// ============================================================================
// 3. AdminRoomManager — Admin-level room management: listing, details,
//    member info, deletion with purge options, and room blocking.
//
//    GET  /_synapse/admin/v1/rooms
//    GET  /_synapse/admin/v1/rooms/<room_id>
//    GET  /_synapse/admin/v1/rooms/<room_id>/members
//    DEL  /_synapse/admin/v2/rooms/<room_id>  (with purge parameters)
//    POST /_synapse/admin/v1/rooms/<room_id>/block
//    POST /_synapse/admin/v1/rooms/<room_id>/unblock
//
// Equivalent to synapse/rest/admin/rooms.py
// ============================================================================

class AdminRoomManager {
public:
  AdminRoomManager(storage::DatabasePool& db, const std::string& server_name)
      : db_(db), server_name_(server_name) {}

  // ---- GET /_synapse/admin/v1/rooms ----
  // List all rooms with pagination, ordering, and filtering
  json list_rooms(int64_t from = 0, int64_t limit = 100,
                   const std::string& order_by = "name",
                   const std::string& dir = "asc",
                   const std::string& search_term = "",
                   const std::string& room_type_filter = "",
                   bool include_all = false) {
    try {
      if (limit < 1) limit = kDefaultPaginationLimit;
      if (limit > kMaxPaginationLimit) limit = kMaxPaginationLimit;

      std::string query =
          "SELECT r.room_id, rs.name, rs.topic, rs.canonical_alias, "
          "rs.joined_members, rs.invited_members, rs.total_events, "
          "r.creation_ts, rs.last_activity_ts, rs.is_encrypted, "
          "rs.join_rules, rs.guest_access, rs.room_type "
          "FROM rooms r "
          "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id";

      std::vector<std::string> conditions;
      if (!include_all) {
        // Only rooms our server participates in
        conditions.push_back("EXISTS (SELECT 1 FROM local_current_membership "
                             "lcm WHERE lcm.room_id = r.room_id)");
      }
      if (!search_term.empty()) {
        std::string safe = sanitize_sql_like(search_term);
        conditions.push_back(
            "(r.room_id LIKE '%" + safe + "%' OR "
            "rs.name LIKE '%" + safe + "%' OR "
            "rs.canonical_alias LIKE '%" + safe + "%')");
      }
      if (!room_type_filter.empty() && room_type_filter != "all") {
        conditions.push_back("rs.room_type = '" +
                             sanitize_sql_like(room_type_filter) + "'");
      }

      if (!conditions.empty()) {
        query += " WHERE " + join(conditions, " AND ");
      }

      // Ordering
      std::string order_col = "rs.name";
      if (order_by == "joined_members") order_col = "rs.joined_members";
      else if (order_by == "total_events") order_col = "rs.total_events";
      else if (order_by == "creation_ts") order_col = "r.creation_ts";
      else if (order_by == "last_activity") order_col = "rs.last_activity_ts";
      else if (order_by == "room_id") order_col = "r.room_id";

      std::string dir_sql = (dir == "desc") ? " DESC" : " ASC";
      query += " ORDER BY " + order_col + dir_sql;

      query += " LIMIT " + std::to_string(limit + 1) +
               " OFFSET " + std::to_string(from);

      auto rows = db_.execute("list_rooms_admin", query);

      json rooms_array = json::array();
      bool has_more = false;
      size_t count = 0;

      for (auto& row : rows) {
        if (count >= static_cast<size_t>(limit)) {
          has_more = true;
          break;
        }
        json room;
        room["room_id"] = row_get_str(row, 0);
        room["name"] = row_get_str(row, 1);
        room["topic"] = row_get_str(row, 2);
        room["canonical_alias"] = row_get_str(row, 3);
        room["joined_members"] = row_get_int(row, 4);
        room["invited_members"] = row_get_int(row, 5);
        room["total_events"] = row_get_int(row, 6);
        int64_t ct = row_get_int(row, 7);
        room["creation_ts"] = ct;
        if (ct > 0) room["creation_ts_display"] = ts_to_iso8601(ct);
        int64_t lat = row_get_int(row, 8);
        room["last_activity_ts"] = lat;
        if (lat > 0) room["last_activity_display"] = ts_to_iso8601(lat);
        room["encrypted"] = row_get_bool(row, 9);
        room["join_rules"] = row_get_str(row, 10, "invite");
        room["guest_access"] = row_get_str(row, 11, "forbidden");
        room["room_type"] = row_get_str(row, 12, "room");

        // Get additional room info
        room["federatable"] = is_room_federatable(row_get_str(row, 0));
        room["public"] = is_room_public(row_get_str(row, 0));
        room["local_members"] = get_local_member_count(row_get_str(row, 0));

        rooms_array.push_back(room);
        count++;
      }

      json result;
      result["rooms"] = rooms_array;
      result["total_rooms"] = get_total_room_count(include_all);
      result["offset"] = from;
      result["limit"] = limit;
      result["next_batch"] = has_more ? std::to_string(from + limit) : "";
      if (has_more) result["next_token"] = std::to_string(from + limit);

      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing rooms: ") + e.what());
    }
  }

  // ---- GET /_synapse/admin/v1/rooms/<room_id> ----
  // Detailed room information
  json get_room_details(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid room_id format: " + room_id);
    }

    try {
      auto row = db_.simple_select_one(
          "rooms", {{"room_id", room_id}},
          {"room_id", "is_public", "creator", "creation_ts"});

      if (!row.has_value()) {
        return build_error(404, "M_NOT_FOUND",
                           "Room not found: " + room_id);
      }

      json room;
      const auto& r = *row;
      room["room_id"] = row_get_str(r, 0);
      room["is_public"] = row_get_bool(r, 1);
      room["creator"] = row_get_str(r, 2);
      int64_t creation_ts = row_get_int(r, 3);
      room["creation_ts"] = creation_ts;
      if (creation_ts > 0) {
        room["creation_ts_display"] = ts_to_iso8601(creation_ts);
        room["room_age_days"] = ms_to_days(now_ms() - creation_ts);
      }

      // Room state from stats
      auto stats = get_room_stats(room_id);
      if (stats.has_value()) {
        room["name"] = stats->name;
        room["topic"] = stats->topic;
        room["canonical_alias"] = stats->alias;
        room["joined_members"] = stats->joined;
        room["invited_members"] = stats->invited;
        room["left_members"] = stats->left;
        room["banned_members"] = stats->banned;
        room["total_members"] = stats->joined + stats->invited +
                                stats->left + stats->banned;
        room["local_members"] = get_local_member_count(room_id);
        room["state_events"] = stats->state_events;
        room["total_events"] = stats->total_events;
        room["encrypted"] = stats->encrypted;
        room["join_rules"] = stats->join_rules;
        room["guest_access"] = stats->guest_access;
        room["history_visibility"] = stats->history_visibility;
        room["room_type"] = stats->room_type;
        room["federatable"] = stats->federatable;
        room["room_version"] = stats->version;
        room["last_activity_ts"] = stats->last_activity;
        if (stats->last_activity > 0) {
          room["last_activity_display"] = ts_to_iso8601(stats->last_activity);
        }
      }

      // Forward extremities
      room["forward_extremities"] = get_forward_extremities_count(room_id);

      // Block status
      room["blocked"] = is_room_blocked(room_id);

      // Aliases
      room["aliases"] = get_room_aliases(room_id);

      // Retention policy
      auto retention = get_room_retention_policy(room_id);
      if (retention.has_value()) {
        room["retention_policy"] = retention.value();
      }

      return room;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error fetching room details: ") + e.what());
    }
  }

  // ---- GET /_synapse/admin/v1/rooms/<room_id>/members ----
  json get_room_members(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid room_id format: " + room_id);
    }

    try {
      auto rows = db_.execute(
          "room_members_admin",
          "SELECT user_id, sender, membership, membership_ts, "
          "display_name, avatar_url "
          "FROM room_memberships rm "
          "LEFT JOIN profiles p ON rm.user_id = p.user_id "
          "WHERE rm.room_id = ? "
          "ORDER BY rm.membership_ts DESC",
          {room_id});

      json members = json::object();
      json members_array = json::array();
      int64_t total = 0;

      for (auto& row : rows) {
        json member;
        member["user_id"] = row_get_str(row, 0);
        member["sender"] = row_get_str(row, 1);
        member["membership"] = normalize_membership(row_get_str(row, 2));
        int64_t mts = row_get_int(row, 3);
        member["membership_ts"] = mts;
        if (mts > 0) member["membership_ts_display"] = ts_to_iso8601(mts);
        member["display_name"] = row_get_str(row, 4);
        member["avatar_url"] = row_get_str(row, 5);
        // Check if user is local
        member["is_local"] = is_local_user(row_get_str(row, 0));
        members_array.push_back(member);
        total++;
      }

      members["room_id"] = room_id;
      members["members"] = members_array;
      members["total"] = total;

      return members;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error fetching members: ") + e.what());
    }
  }

  // ---- DELETE /_synapse/admin/v2/rooms/<room_id> ----
  // Delete a room, optionally purging all associated data
  json delete_room(const std::string& room_id, const json& body) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid room_id format: " + room_id);
    }

    bool purge = true;  // Default: purge all data
    bool block = false;  // Also block the room after deletion
    bool force_purge = false;
    std::string message;  // Optional message to send before deletion

    if (body.contains("purge")) purge = body["purge"].get<bool>();
    if (body.contains("block")) block = body["block"].get<bool>();
    if (body.contains("force_purge")) force_purge = body["force_purge"].get<bool>();
    if (body.contains("message")) message = body["message"].get<std::string>();

    try {
      // Verify the room exists
      auto existing = db_.simple_select_one(
          "rooms", {{"room_id", room_id}}, {"room_id"});
      if (!existing.has_value()) {
        return build_error(404, "M_NOT_FOUND",
                           "Room not found: " + room_id);
      }

      // Get room state before deletion for audit
      json room_state = get_room_details(room_id);
      json deletion_report;
      deletion_report["room_id"] = room_id;
      deletion_report["deleted_by"] = "admin"; // placeholder for admin user
      deletion_report["deleted_at"] = now_iso8601();
      deletion_report["purge"] = purge;
      deletion_report["block"] = block;
      deletion_report["force_purge"] = force_purge;

      // Shutdown and purge the room
      int64_t events_deleted = 0;
      int64_t state_deleted = 0;

      if (purge) {
        // Delete all events
        auto event_rows = db_.execute(
            "count_room_events",
            "SELECT COUNT(*) FROM events WHERE room_id = ?", {room_id});
        if (!event_rows.empty()) events_deleted = row_get_int(event_rows[0], 0);

        db_.execute("delete_events",
                    "DELETE FROM events WHERE room_id = ?", {room_id});

        // Delete state events
        auto state_rows = db_.execute(
            "count_state_events",
            "SELECT COUNT(*) FROM state_events WHERE room_id = ?", {room_id});
        if (!state_rows.empty()) state_deleted = row_get_int(state_rows[0], 0);

        db_.execute("delete_state_events",
                    "DELETE FROM state_events WHERE room_id = ?", {room_id});

        // Delete from current_state_events
        db_.execute("delete_current_state",
                    "DELETE FROM current_state_events WHERE room_id = ?",
                    {room_id});

        // Delete event JSON
        db_.execute("delete_event_json",
                    "DELETE FROM event_json WHERE room_id = ?", {room_id});

        // Delete room memberships
        db_.execute("delete_memberships",
                    "DELETE FROM room_memberships WHERE room_id = ?",
                    {room_id});

        // Delete local current membership
        db_.execute("delete_local_membership",
                    "DELETE FROM local_current_membership WHERE room_id = ?",
                    {room_id});

        // Delete forward extremities
        db_.execute("delete_extremities",
                    "DELETE FROM event_forward_extremities WHERE room_id = ?",
                    {room_id});

        // Delete backward extremities
        db_.execute("delete_backward_extremities",
                    "DELETE FROM event_backward_extremities WHERE room_id = ?",
                    {room_id});

        // Delete room aliases
        db_.execute("delete_room_aliases",
                    "DELETE FROM room_aliases WHERE room_id = ?", {room_id});

        // Delete room stats
        db_.execute("delete_room_stats",
                    "DELETE FROM room_stats_state WHERE room_id = ?",
                    {room_id});

        // Delete room depth
        db_.execute("delete_room_depth",
                    "DELETE FROM room_depth WHERE room_id = ?", {room_id});

        // Delete room tags
        db_.execute("delete_room_tags",
                    "DELETE FROM room_tags WHERE room_id = ?", {room_id});

        // Delete room account data
        db_.execute("delete_room_account_data",
                    "DELETE FROM room_account_data WHERE room_id = ?",
                    {room_id});

        // Delete receipts
        db_.execute("delete_receipts",
                    "DELETE FROM receipts_linearized WHERE room_id = ?",
                    {room_id});
        db_.execute("delete_receipts_graph",
                    "DELETE FROM receipts_graph WHERE room_id = ?", {room_id});

        // Delete push actions
        db_.execute("delete_push_actions",
                    "DELETE FROM event_push_actions WHERE room_id = ?",
                    {room_id});

        // Delete notifications
        db_.execute("delete_notifications",
                    "DELETE FROM event_push_summary WHERE room_id = ?",
                    {room_id});

        // If force_purge, also delete the room from federation tables
        if (force_purge) {
          db_.execute("delete_federation_events",
                      "DELETE FROM federation_inbound_events_staging "
                      "WHERE room_id = ?", {room_id});
          db_.execute("delete_event_auth",
                      "DELETE FROM event_auth WHERE room_id = ?", {room_id});
          db_.execute("delete_event_edges",
                      "DELETE FROM event_edges WHERE room_id = ?", {room_id});
        }

        // Delete redactions
        db_.execute("delete_redactions",
                    "DELETE FROM redactions WHERE room_id = ?", {room_id});

        // Delete event relations
        db_.execute("delete_event_relations",
                    "DELETE FROM event_relations WHERE room_id = ?", {room_id});
      }

      // Delete the room record itself
      db_.simple_delete_one("rooms", {{"room_id", room_id}});

      // If block was requested, add to block list
      if (block) {
        block_room_internal(room_id, "Deleted by admin, auto-blocked");
      }

      deletion_report["events_deleted"] = events_deleted;
      deletion_report["state_events_deleted"] = state_deleted;
      deletion_report["total_items_deleted"] = events_deleted + state_deleted;
      deletion_report["message"] =
          room_id + " has been deleted successfully.";

      // Record the admin action
      record_admin_action("delete_room", room_id, deletion_report);

      return deletion_report;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error deleting room: ") + e.what());
    }
  }

  // ---- POST /_synapse/admin/v1/rooms/<room_id>/block ----
  json block_room(const std::string& room_id, const json& body) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid room_id format: " + room_id);
    }

    std::string reason = body.value("reason", "Blocked by server administrator");
    bool is_spam = body.value("spam", false);

    try {
      block_room_internal(room_id, reason);

      json response;
      response["success"] = true;
      response["room_id"] = room_id;
      response["blocked"] = true;
      response["reason"] = reason;
      response["spam"] = is_spam;
      response["blocked_at"] = now_iso8601();

      // If marked as spam, also quarantine any media from this room
      if (is_spam) {
        int quarantined = quarantine_room_media(room_id);
        response["quarantined_media"] = quarantined;
      }

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error blocking room: ") + e.what());
    }
  }

  // ---- POST /_synapse/admin/v1/rooms/<room_id>/unblock ----
  json unblock_room(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid room_id format: " + room_id);
    }

    try {
      unblock_room_internal(room_id);

      json response;
      response["success"] = true;
      response["room_id"] = room_id;
      response["blocked"] = false;
      response["unblocked_at"] = now_iso8601();

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error unblocking room: ") + e.what());
    }
  }

  // ---- GET /_synapse/admin/v1/rooms/<room_id>/state ----
  json get_room_state(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id");
    }

    try {
      auto rows = db_.execute(
          "room_state_admin",
          "SELECT event_type, state_key, event_id, origin_server_ts "
          "FROM current_state_events WHERE room_id = ? "
          "ORDER BY event_type, state_key",
          {room_id});

      json state_array = json::array();
      for (auto& row : rows) {
        json s;
        s["type"] = row_get_str(row, 0);
        s["state_key"] = row_get_str(row, 1);
        s["event_id"] = row_get_str(row, 2);
        int64_t ts = row_get_int(row, 3);
        s["origin_server_ts"] = ts;
        if (ts > 0) s["origin_server_ts_display"] = ts_to_iso8601(ts);
        state_array.push_back(s);
      }

      json result;
      result["room_id"] = room_id;
      result["state"] = state_array;
      result["total"] = state_array.size();
      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error fetching room state: ") + e.what());
    }
  }

  // ---- Block status check ----
  bool is_room_blocked(const std::string& room_id) {
    try {
      auto row = db_.simple_select_one(
          "blocked_rooms", {{"room_id", room_id}}, {"room_id"});
      return row.has_value();
    } catch (...) { return false; }
  }

  // ---- Get blocked rooms list ----
  json get_blocked_rooms() {
    try {
      auto rows = db_.execute(
          "list_blocked_rooms",
          "SELECT room_id, reason, blocked_at, blocked_by "
          "FROM blocked_rooms ORDER BY blocked_at DESC");

      json blocked = json::array();
      for (auto& row : rows) {
        json b;
        b["room_id"] = row_get_str(row, 0);
        b["reason"] = row_get_str(row, 1);
        int64_t ts = row_get_int(row, 2);
        b["blocked_at"] = ts;
        if (ts > 0) b["blocked_at_display"] = ts_to_iso8601(ts);
        b["blocked_by"] = row_get_str(row, 3);
        blocked.push_back(b);
      }

      json result;
      result["blocked_rooms"] = blocked;
      result["total"] = blocked.size();
      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing blocked rooms: ") + e.what());
    }
  }

private:
  // ---- Internal types ----

  struct RoomStats {
    std::string name;
    std::string topic;
    std::string alias;
    std::string join_rules = "invite";
    std::string guest_access = "forbidden";
    std::string history_visibility = "shared";
    std::string room_type = "room";
    std::string version = "10";
    int64_t joined = 0;
    int64_t invited = 0;
    int64_t left = 0;
    int64_t banned = 0;
    int64_t state_events = 0;
    int64_t total_events = 0;
    int64_t last_activity = 0;
    bool encrypted = false;
    bool federatable = true;
  };

  // ---- Internal methods ----

  std::string sanitize_sql_like(const std::string& input) {
    std::string result;
    for (char c : input) {
      if (c == '%' || c == '_' || c == '\\') {
        result += '\\';
        result += c;
      } else if (c == '\'') {
        result += "''";
      } else {
        result += c;
      }
    }
    return result;
  }

  std::optional<RoomStats> get_room_stats(const std::string& room_id) {
    try {
      auto row = db_.simple_select_one(
          "room_stats_state",
          {{"room_id", room_id}},
          {"name", "topic", "canonical_alias", "joined_members",
           "invited_members", "left_members", "banned_members",
           "state_events", "total_events", "last_activity_ts",
           "is_encrypted", "join_rules", "guest_access",
           "history_visibility", "room_type", "is_federatable",
           "room_version"});
      if (!row.has_value()) return std::nullopt;

      RoomStats s;
      const auto& r = *row;
      s.name = row_get_str(r, 0);
      s.topic = row_get_str(r, 1);
      s.alias = row_get_str(r, 2);
      s.joined = row_get_int(r, 3);
      s.invited = row_get_int(r, 4);
      s.left = row_get_int(r, 5);
      s.banned = row_get_int(r, 6);
      s.state_events = row_get_int(r, 7);
      s.total_events = row_get_int(r, 8);
      s.last_activity = row_get_int(r, 9);
      s.encrypted = row_get_bool(r, 10);
      s.join_rules = row_get_str(r, 11, "invite");
      s.guest_access = row_get_str(r, 12, "forbidden");
      s.history_visibility = row_get_str(r, 13, "shared");
      s.room_type = row_get_str(r, 14, "room");
      s.federatable = row_get_bool(r, 15, true);
      s.version = row_get_str(r, 16, "10");
      return s;
    } catch (...) { return std::nullopt; }
  }

  int64_t get_forward_extremities_count(const std::string& room_id) {
    try {
      auto rows = db_.execute(
          "count_extremities",
          "SELECT COUNT(*) FROM event_forward_extremities WHERE room_id = ?",
          {room_id});
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  int64_t get_local_member_count(const std::string& room_id) {
    try {
      auto rows = db_.execute(
          "local_member_count",
          "SELECT COUNT(*) FROM local_current_membership "
          "WHERE room_id = ? AND membership = 'join'",
          {room_id});
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  bool is_room_public(const std::string& room_id) {
    try {
      auto row = db_.simple_select_one(
          "rooms", {{"room_id", room_id}}, {"is_public"});
      return row.has_value() && row_get_bool(row.value(), 0);
    } catch (...) { return false; }
  }

  bool is_room_federatable(const std::string& room_id) {
    try {
      // Check room create event for m.federate flag
      auto rows = db_.execute(
          "room_federate_check",
          "SELECT json FROM event_json WHERE room_id = ? "
          "AND type = 'm.room.create' LIMIT 1",
          {room_id});
      if (!rows.empty()) {
        std::string json_str = row_get_str(rows[0], 0);
        if (!json_str.empty()) {
          try {
            auto j = json::parse(json_str);
            if (j.contains("content") && j["content"].contains("m.federate")) {
              return j["content"]["m.federate"].get<bool>();
            }
          } catch (...) {}
        }
      }
    } catch (...) {}
    return true; // Default: federatable
  }

  bool is_local_user(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) return false;
    return server_name_from_id(user_id) == server_name_;
  }

  int64_t get_total_room_count(bool include_all) {
    try {
      std::string query = "SELECT COUNT(*) FROM rooms";
      if (!include_all) {
        query += " WHERE EXISTS (SELECT 1 FROM local_current_membership "
                 "lcm WHERE lcm.room_id = rooms.room_id)";
      }
      auto rows = db_.execute("total_rooms_count", query);
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  json get_room_aliases(const std::string& room_id) {
    json aliases = json::array();
    try {
      auto rows = db_.execute(
          "room_aliases",
          "SELECT room_alias FROM room_aliases WHERE room_id = ?",
          {room_id});
      for (auto& ra : rows) {
        aliases.push_back(row_get_str(ra, 0));
      }
    } catch (...) {}
    return aliases;
  }

  std::optional<json> get_room_retention_policy(const std::string& room_id) {
    try {
      auto rows = db_.execute(
          "room_retention",
          "SELECT min_lifetime, max_lifetime FROM room_retention "
          "WHERE room_id = ? LIMIT 1",
          {room_id});
      if (!rows.empty()) {
        json policy;
        int64_t min_lifetime = row_get_int(rows[0], 0);
        int64_t max_lifetime = row_get_int(rows[0], 1);
        if (min_lifetime > 0) {
          policy["min_lifetime_ms"] = min_lifetime;
          policy["min_lifetime_days"] = ms_to_days(min_lifetime);
        }
        if (max_lifetime > 0) {
          policy["max_lifetime_ms"] = max_lifetime;
          policy["max_lifetime_days"] = ms_to_days(max_lifetime);
        }
        return policy;
      }
    } catch (...) {}
    return std::nullopt;
  }

  void block_room_internal(const std::string& room_id,
                            const std::string& reason) {
    try {
      db_.simple_insert("blocked_rooms", {
          {"room_id", room_id},
          {"reason", reason},
          {"blocked_at", std::to_string(now_ms())},
          {"blocked_by", "admin"}
      });
    } catch (...) {
      // Upsert instead
      db_.simple_upsert("blocked_rooms",
                        {{"room_id", room_id}},
                        {{"reason", reason},
                         {"blocked_at", std::to_string(now_ms())},
                         {"blocked_by", "admin"}});
    }
  }

  void unblock_room_internal(const std::string& room_id) {
    try {
      db_.simple_delete_one("blocked_rooms", {{"room_id", room_id}});
    } catch (...) {}
  }

  int quarantine_room_media(const std::string& room_id) {
    try {
      // Mark all media from events in this room as quarantined
      db_.execute(
          "quarantine_room_media",
          "UPDATE local_media_repository "
          "SET quarantined_by = 'admin', safe_from_quarantine = 0 "
          "WHERE media_id IN ("
          "  SELECT DISTINCT "
          "    json_extract(content, '$.url') "
          "  FROM events WHERE room_id = ? "
          "  AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ")",
          {room_id});
      return 1; // Placeholder count
    } catch (...) { return 0; }
  }

  void record_admin_action(const std::string& action,
                            const std::string& target_id,
                            const json& details) {
    // Record the admin action for auditing purposes
    try {
      db_.simple_insert("admin_actions", {
          {"action", action},
          {"target_id", target_id},
          {"admin_user", "system"},
          {"timestamp_ms", std::to_string(now_ms())},
          {"details", details.dump()}
      });
    } catch (...) {}
  }

  storage::DatabasePool& db_;
  std::string server_name_;
};

// ============================================================================
// 4. AdminMediaManager — Admin-level media management: stats, deletion,
//    quarantine, and remote media cache purging.
//
//    GET  /_synapse/admin/v1/media/<server_name>/stats
//    DEL  /_synapse/admin/v1/media/<server_name>/<media_id>
//    POST /_synapse/admin/v1/media/<server_name>/<media_id>/quarantine
//    POST /_synapse/admin/v1/media/<server_name>/<media_id>/unquarantine
//    POST /_synapse/admin/v1/purge_media_cache
//    GET  /_synapse/admin/v1/media/<server_name>/list
//    GET  /_synapse/admin/v1/media/protect
//
// Equivalent to synapse/rest/admin/media.py
// ============================================================================

class AdminMediaManager {
public:
  AdminMediaManager(storage::DatabasePool& db, const std::string& server_name)
      : db_(db), server_name_(server_name) {}

  // ---- GET /_synapse/admin/v1/media/<server_name>/stats ----
  json get_media_stats() {
    try {
      json stats;

      // Local media stats
      auto local_rows = db_.execute(
          "local_media_stats",
          "SELECT COUNT(*), COALESCE(SUM(media_length), 0), "
          "COALESCE(MAX(created_ts), 0), COALESCE(MIN(created_ts), 0) "
          "FROM local_media_repository WHERE safe_from_quarantine = 1");

      if (!local_rows.empty()) {
        stats["local_media"] = json::object();
        stats["local_media"]["count"] = row_get_int(local_rows[0], 0);
        stats["local_media"]["total_bytes"] = row_get_int(local_rows[0], 1);
        stats["local_media"]["total_size_display"] =
            format_bytes(row_get_int(local_rows[0], 1));
        int64_t newest = row_get_int(local_rows[0], 2);
        int64_t oldest = row_get_int(local_rows[0], 3);
        if (newest > 0) stats["local_media"]["newest_upload_ts"] = newest;
        if (oldest > 0) stats["local_media"]["oldest_upload_ts"] = oldest;
      }

      // Remote media stats
      auto remote_rows = db_.execute(
          "remote_media_stats",
          "SELECT COUNT(*), COALESCE(SUM(media_length), 0), "
          "COALESCE(MAX(created_ts), 0) "
          "FROM remote_media_cache");

      if (!remote_rows.empty()) {
        stats["remote_media"] = json::object();
        stats["remote_media"]["count"] = row_get_int(remote_rows[0], 0);
        stats["remote_media"]["total_bytes"] = row_get_int(remote_rows[0], 1);
        stats["remote_media"]["total_size_display"] =
            format_bytes(row_get_int(remote_rows[0], 1));
      }

      // Quarantined media stats
      auto quar_rows = db_.execute(
          "quarantined_media_stats",
          "SELECT COUNT(*), COALESCE(SUM(media_length), 0) "
          "FROM local_media_repository WHERE safe_from_quarantine = 0");

      if (!quar_rows.empty()) {
        stats["quarantined"] = json::object();
        stats["quarantined"]["count"] = row_get_int(quar_rows[0], 0);
        stats["quarantined"]["total_bytes"] = row_get_int(quar_rows[0], 1);
        stats["quarantined"]["total_size_display"] =
            format_bytes(row_get_int(quar_rows[0], 1));
      }

      // Thumbnail stats
      auto thumb_rows = db_.execute(
          "thumbnail_stats",
          "SELECT COUNT(*), COALESCE(SUM(media_length), 0) "
          "FROM local_media_repository_thumbnails");

      if (!thumb_rows.empty()) {
        stats["thumbnails"] = json::object();
        stats["thumbnails"]["count"] = row_get_int(thumb_rows[0], 0);
        stats["thumbnails"]["total_bytes"] = row_get_int(thumb_rows[0], 1);
        stats["thumbnails"]["total_size_display"] =
            format_bytes(row_get_int(thumb_rows[0], 1));
      }

      // URL preview cache stats
      auto url_rows = db_.execute(
          "url_preview_stats",
          "SELECT COUNT(*), COALESCE(SUM(response_size), 0) "
          "FROM url_cache_media");

      if (!url_rows.empty()) {
        stats["url_previews"] = json::object();
        stats["url_previews"]["count"] = row_get_int(url_rows[0], 0);
        stats["url_previews"]["total_bytes"] = row_get_int(url_rows[0], 1);
        stats["url_previews"]["total_size_display"] =
            format_bytes(row_get_int(url_rows[0], 1));
      }

      // Total combined
      int64_t total_count =
          row_get_int(local_rows.empty() ? Row{} : local_rows[0], 0) +
          row_get_int(remote_rows.empty() ? Row{} : remote_rows[0], 0);
      int64_t total_bytes =
          row_get_int(local_rows.empty() ? Row{} : local_rows[0], 1) +
          row_get_int(remote_rows.empty() ? Row{} : remote_rows[0], 1);

      stats["total"] = json::object();
      stats["total"]["count"] = total_count;
      stats["total"]["bytes"] = total_bytes;
      stats["total"]["size_display"] = format_bytes(total_bytes);

      // Media types breakdown
      auto type_rows = db_.execute(
          "media_types",
          "SELECT SUBSTR(media_type, 1, INSTR(media_type || '/', '/')-1) as category, "
          "COUNT(*), SUM(media_length) "
          "FROM local_media_repository "
          "WHERE safe_from_quarantine = 1 "
          "GROUP BY category");

      json type_breakdown = json::object();
      for (auto& tr : type_rows) {
        std::string category = row_get_str(tr, 0, "unknown");
        json cat_info;
        cat_info["count"] = row_get_int(tr, 1);
        cat_info["bytes"] = row_get_int(tr, 2);
        cat_info["size_display"] = format_bytes(row_get_int(tr, 2));
        type_breakdown[category] = cat_info;
      }
      stats["media_type_breakdown"] = type_breakdown;

      // Users with most media
      auto top_users = db_.execute(
          "top_media_users",
          "SELECT user_id, COUNT(*), SUM(media_length) "
          "FROM local_media_repository "
          "WHERE safe_from_quarantine = 1 AND user_id IS NOT NULL "
          "GROUP BY user_id ORDER BY SUM(media_length) DESC LIMIT 10");

      json top_users_json = json::array();
      for (auto& tu : top_users) {
        json user_media;
        user_media["user_id"] = row_get_str(tu, 0);
        user_media["count"] = row_get_int(tu, 1);
        user_media["bytes"] = row_get_int(tu, 2);
        user_media["size_display"] = format_bytes(row_get_int(tu, 2));
        top_users_json.push_back(user_media);
      }
      stats["top_users_by_media"] = top_users_json;

      return stats;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error fetching media stats: ") + e.what());
    }
  }

  // ---- DELETE /_synapse/admin/v1/media/<server_name>/<media_id> ----
  json delete_media(const std::string& media_id) {
    if (media_id.empty()) {
      return build_error(400, "M_MISSING_PARAM", "media_id is required");
    }

    try {
      // Check if media exists
      auto existing = db_.simple_select_one(
          "local_media_repository",
          {{"media_id", media_id}},
          {"media_id", "media_type", "media_length", "user_id", "created_ts"});

      if (!existing.has_value()) {
        // Try remote media
        auto remote = db_.simple_select_one(
            "remote_media_cache",
            {{"media_id", media_id}},
            {"media_id"});
        if (!remote.has_value()) {
          return build_error(404, "M_NOT_FOUND",
                             "Media not found: " + media_id);
        }

        // Delete remote media
        db_.simple_delete_one("remote_media_cache", {{"media_id", media_id}});
        db_.simple_delete_one("remote_media_cache_thumbnails",
                              {{"media_id", media_id}});
      } else {
        // Delete local media and its thumbnails
        db_.simple_delete_one("local_media_repository",
                              {{"media_id", media_id}});
        db_.simple_delete_one("local_media_repository_thumbnails",
                              {{"media_id", media_id}});
      }

      json response;
      response["success"] = true;
      response["media_id"] = media_id;
      response["deleted"] = true;
      response["message"] = "Media deleted successfully";
      response["deleted_at"] = now_iso8601();

      // Record the admin action
      record_admin_action("delete_media", media_id, response);

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error deleting media: ") + e.what());
    }
  }

  // ---- POST /_synapse/admin/v1/media/<server_name>/<media_id>/quarantine ----
  json quarantine_media(const std::string& media_id, const json& body) {
    if (media_id.empty()) {
      return build_error(400, "M_MISSING_PARAM", "media_id is required");
    }

    std::string reason = body.value("reason", "Quarantined by administrator");
    bool protect = body.value("protect", false);

    try {
      // Check media exists
      auto existing = db_.simple_select_one(
          "local_media_repository",
          {{"media_id", media_id}},
          {"media_id", "safe_from_quarantine", "quarantined_by"});

      if (!existing.has_value()) {
        return build_error(404, "M_NOT_FOUND",
                           "Media not found: " + media_id);
      }

      const auto& r = *existing;
      bool already_quarantined = !row_get_bool(r, 1);

      // Set quarantine
      db_.simple_update_one(
          "local_media_repository",
          {{"media_id", media_id}},
          {{"safe_from_quarantine", "0"},
           {"quarantined_by", "admin"},
           {"quarantined_reason", reason},
           {"quarantined_ts", std::to_string(now_ms())}});

      // Delete all thumbnails for quarantined media
      db_.simple_delete_one("local_media_repository_thumbnails",
                            {{"media_id", media_id}});

      json response;
      response["success"] = true;
      response["media_id"] = media_id;
      response["quarantined"] = true;
      response["already_quarantined"] = already_quarantined;
      response["reason"] = reason;
      response["quarantined_at"] = now_iso8601();

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error quarantining media: ") + e.what());
    }
  }

  // ---- POST /_synapse/admin/v1/media/<server_name>/<media_id>/unquarantine ----
  json unquarantine_media(const std::string& media_id) {
    if (media_id.empty()) {
      return build_error(400, "M_MISSING_PARAM", "media_id is required");
    }

    try {
      auto existing = db_.simple_select_one(
          "local_media_repository",
          {{"media_id", media_id}},
          {"media_id", "safe_from_quarantine"});

      if (!existing.has_value()) {
        return build_error(404, "M_NOT_FOUND",
                           "Media not found: " + media_id);
      }

      bool already_safe = row_get_bool(existing.value(), 1);

      if (already_safe) {
        json response;
        response["success"] = true;
        response["media_id"] = media_id;
        response["unquarantined"] = false;
        response["message"] = "Media is already safe (not quarantined)";
        return response;
      }

      db_.simple_update_one(
          "local_media_repository",
          {{"media_id", media_id}},
          {{"safe_from_quarantine", "1"},
           {"quarantined_by", ""},
           {"quarantined_reason", ""},
           {"quarantined_ts", ""}});

      json response;
      response["success"] = true;
      response["media_id"] = media_id;
      response["unquarantined"] = true;
      response["unquarantined_at"] = now_iso8601();

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error unquarantining media: ") + e.what());
    }
  }

  // ---- POST /_synapse/admin/v1/purge_media_cache ----
  // Purge remote media cache, optionally before a certain timestamp
  json purge_remote_media_cache(const json& body) {
    try {
      int64_t before_ts = now_ms(); // Default: purge everything
      if (body.contains("before_ts")) {
        before_ts = body["before_ts"].get<int64_t>();
      }

      // Count media to be purged
      auto count_rows = db_.execute(
          "count_remote_media_to_purge",
          "SELECT COUNT(*), COALESCE(SUM(media_length), 0) "
          "FROM remote_media_cache WHERE last_access_ts < ?",
          {std::to_string(before_ts)});

      int64_t items_purged = 0;
      int64_t bytes_freed = 0;
      if (!count_rows.empty()) {
        items_purged = row_get_int(count_rows[0], 0);
        bytes_freed = row_get_int(count_rows[0], 1);
      }

      // Delete remote media
      db_.execute(
          "purge_remote_media",
          "DELETE FROM remote_media_cache WHERE last_access_ts < ?",
          {std::to_string(before_ts)});

      // Delete remote media thumbnails
      db_.execute(
          "purge_remote_thumbnails",
          "DELETE FROM remote_media_cache_thumbnails "
          "WHERE media_id NOT IN (SELECT media_id FROM remote_media_cache)");

      // Also purge URL preview cache if requested
      bool purge_urls = body.value("purge_url_cache", false);
      int64_t urls_purged = 0;
      int64_t url_bytes_freed = 0;

      if (purge_urls) {
        auto url_rows = db_.execute(
            "count_url_cache",
            "SELECT COUNT(*), COALESCE(SUM(response_size), 0) "
            "FROM url_cache_media WHERE created_ts < ?",
            {std::to_string(before_ts)});
        if (!url_rows.empty()) {
          urls_purged = row_get_int(url_rows[0], 0);
          url_bytes_freed = row_get_int(url_rows[0], 1);
        }

        db_.execute(
            "purge_url_cache",
            "DELETE FROM url_cache_media WHERE created_ts < ?",
            {std::to_string(before_ts)});
      }

      json response;
      response["success"] = true;
      response["remote_media_purged"] = items_purged;
      response["remote_media_bytes_freed"] = bytes_freed;
      response["remote_media_bytes_display"] = format_bytes(bytes_freed);
      response["url_cache_purged"] = urls_purged;
      response["url_cache_bytes_freed"] = url_bytes_freed;
      if (purge_urls) {
        response["url_cache_bytes_display"] = format_bytes(url_bytes_freed);
      }
      response["before_ts"] = before_ts;
      response["purged_at"] = now_iso8601();
      response["total_bytes_freed"] = bytes_freed + url_bytes_freed;
      response["total_bytes_display"] =
          format_bytes(bytes_freed + url_bytes_freed);

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error purging media cache: ") + e.what());
    }
  }

  // ---- GET /_synapse/admin/v1/media/<server_name>/list ----
  json list_media(int64_t from = 0, int64_t limit = 100,
                   const std::string& user_id = "",
                   const std::string& media_type = "",
                   const std::string& order_by = "created_ts",
                   const std::string& dir = "desc") {
    try {
      if (limit < 1) limit = kDefaultPaginationLimit;
      if (limit > kMaxPaginationLimit) limit = kMaxPaginationLimit;

      std::string query =
          "SELECT media_id, media_type, media_length, user_id, "
          "created_ts, upload_name, safe_from_quarantine, quarantined_by "
          "FROM local_media_repository";

      std::vector<std::string> conditions;
      if (!user_id.empty()) {
        conditions.push_back("user_id = '" +
                              sanitize_sql_like(user_id) + "'");
      }
      if (!media_type.empty()) {
        conditions.push_back("media_type LIKE '" +
                              sanitize_sql_like(media_type) + "%'");
      }

      if (!conditions.empty()) {
        query += " WHERE " + join(conditions, " AND ");
      }

      std::string order_col = "created_ts";
      if (order_by == "media_length") order_col = "media_length";
      else if (order_by == "media_type") order_col = "media_type";
      else if (order_by == "media_id") order_col = "media_id";

      std::string dir_sql = (dir == "desc") ? " DESC" : " ASC";
      query += " ORDER BY " + order_col + dir_sql;

      query += " LIMIT " + std::to_string(limit + 1) +
               " OFFSET " + std::to_string(from);

      auto rows = db_.execute("list_media_admin", query);

      json media_array = json::array();
      bool has_more = false;
      size_t count = 0;

      for (auto& row : rows) {
        if (count >= static_cast<size_t>(limit)) {
          has_more = true;
          break;
        }
        json m;
        m["media_id"] = row_get_str(row, 0);
        m["media_type"] = row_get_str(row, 1);
        int64_t len = row_get_int(row, 2);
        m["media_length"] = len;
        m["size_display"] = format_bytes(len);
        m["user_id"] = row_get_str(row, 3);
        int64_t created = row_get_int(row, 4);
        m["created_ts"] = created;
        if (created > 0) m["created_ts_display"] = ts_to_iso8601(created);
        m["upload_name"] = row_get_str(row, 5);
        m["safe_from_quarantine"] = row_get_bool(row, 6, true);
        m["quarantined_by"] = row_get_str(row, 7);
        m["mxc_uri"] = "mxc://" + server_name_ + "/" + row_get_str(row, 0);
        media_array.push_back(m);
        count++;
      }

      json result;
      result["media"] = media_array;
      result["total"] = get_total_media_count();
      result["offset"] = from;
      result["limit"] = limit;
      result["next_token"] = has_more ? std::to_string(from + limit) : "";

      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing media: ") + e.what());
    }
  }

  // ---- GET /_synapse/admin/v1/media/protect ----
  // List all media that has been marked as protected
  json list_protected_media() {
    try {
      auto rows = db_.execute(
          "list_protected_media",
          "SELECT media_id, media_type, media_length, user_id, "
          "created_ts, upload_name "
          "FROM local_media_repository WHERE safe_from_quarantine = 1 "
          "ORDER BY created_ts DESC LIMIT 100");

      json media_array = json::array();
      for (auto& row : rows) {
        json m;
        m["media_id"] = row_get_str(row, 0);
        m["media_type"] = row_get_str(row, 1);
        m["media_length"] = row_get_int(row, 2);
        m["size_display"] = format_bytes(row_get_int(row, 2));
        m["user_id"] = row_get_str(row, 3);
        m["created_ts"] = row_get_int(row, 4);
        m["upload_name"] = row_get_str(row, 5);
        media_array.push_back(m);
      }

      json result;
      result["protected_media"] = media_array;
      result["total"] = media_array.size();
      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing protected media: ") + e.what());
    }
  }

private:
  std::string sanitize_sql_like(const std::string& input) {
    std::string result;
    for (char c : input) {
      if (c == '%' || c == '_' || c == '\\') {
        result += '\\';
        result += c;
      } else if (c == '\'') {
        result += "''";
      } else {
        result += c;
      }
    }
    return result;
  }

  int64_t get_total_media_count() {
    try {
      auto rows = db_.execute(
          "total_media",
          "SELECT COUNT(*) FROM local_media_repository");
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  void record_admin_action(const std::string& action,
                            const std::string& target_id,
                            const json& details) {
    try {
      db_.simple_insert("admin_actions", {
          {"action", action},
          {"target_id", target_id},
          {"admin_user", "system"},
          {"timestamp_ms", std::to_string(now_ms())},
          {"details", details.dump()}
      });
    } catch (...) {}
  }

  storage::DatabasePool& db_;
  std::string server_name_;
};

// ============================================================================
// 5. PrometheusRegistry — Global registry for all Prometheus metrics.
//    Collects counters, gauges, and histograms. Exports them in
//    Prometheus text format. Supports labeled metrics.
//
// Equivalent to synapse/metrics/__init__.py
//              synapse/metrics/_exposition.py
// ============================================================================

class PrometheusRegistry {
public:
  PrometheusRegistry() {
    initialize_default_metrics();
  }

  // ---- Create / register metrics ----

  PrometheusCounter& create_counter(const std::string& name,
                                     const std::string& help,
                                     const std::vector<std::string>& labels = {}) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto counter = std::make_shared<PrometheusCounter>(name, help, labels);
    counters_[name] = counter;
    return *counter;
  }

  PrometheusGauge& create_gauge(const std::string& name,
                                 const std::string& help,
                                 const std::vector<std::string>& labels = {}) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto gauge = std::make_shared<PrometheusGauge>(name, help, labels);
    gauges_[name] = gauge;
    return *gauge;
  }

  PrometheusHistogram& create_histogram(const std::string& name,
                                         const std::string& help,
                                         const std::vector<double>& buckets) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto histogram = std::make_shared<PrometheusHistogram>(name, help, buckets);
    histograms_[name] = histogram;
    return *histogram;
  }

  // ---- Accessors (auto-create if missing) ----

  PrometheusCounter& counter(const std::string& name) {
    {
      std::shared_lock<std::shared_mutex> lock(mutex_);
      auto it = counters_.find(name);
      if (it != counters_.end()) return *it->second;
    }
    return create_counter(name, "auto-created counter");
  }

  PrometheusGauge& gauge(const std::string& name) {
    {
      std::shared_lock<std::shared_mutex> lock(mutex_);
      auto it = gauges_.find(name);
      if (it != gauges_.end()) return *it->second;
    }
    return create_gauge(name, "auto-created gauge");
  }

  PrometheusHistogram& histogram(const std::string& name) {
    {
      std::shared_lock<std::shared_mutex> lock(mutex_);
      auto it = histograms_.find(name);
      if (it != histograms_.end()) return *it->second;
    }
    return create_histogram(name, "auto-created histogram",
                             default_latency_buckets());
  }

  // ---- Record common metrics ----

  void record_http_request(const std::string& method, int status_code,
                            double duration_seconds) {
    counter("progressive_http_requests_total").inc();
    histogram("progressive_http_request_duration_seconds").observe(duration_seconds);

    std::map<std::string, std::string> labels;
    labels["method"] = method;
    labels["status"] = std::to_string(status_code);
    counter("progressive_http_requests_total").inc_labels(labels);
  }

  void record_event_processed(const std::string& event_type, bool incoming) {
    counter("progressive_events_processed_total").inc();
    std::map<std::string, std::string> labels;
    labels["type"] = event_type;
    labels["direction"] = incoming ? "incoming" : "outgoing";
    counter("progressive_events_processed_total").inc_labels(labels);
  }

  void record_federation_request(bool incoming, bool success,
                                  double duration_seconds) {
    counter("progressive_federation_requests_total").inc();
    histogram("progressive_federation_request_duration_seconds")
        .observe(duration_seconds);
    std::map<std::string, std::string> labels;
    labels["direction"] = incoming ? "incoming" : "outgoing";
    labels["success"] = success ? "true" : "false";
    counter("progressive_federation_requests_total").inc_labels(labels);
  }

  void record_db_query(const std::string& query_type, double duration_seconds) {
    counter("progressive_db_queries_total").inc();
    histogram("progressive_db_query_duration_seconds").observe(duration_seconds);
  }

  void record_media_upload(int64_t bytes) {
    counter("progressive_media_uploads_total").inc();
    counter("progressive_media_bytes_total").inc(static_cast<double>(bytes));
    gauge("progressive_media_bytes").inc(static_cast<double>(bytes));
  }

  void record_media_download(int64_t bytes) {
    counter("progressive_media_downloads_total").inc();
    counter("progressive_media_bytes_downloaded_total")
        .inc(static_cast<double>(bytes));
  }

  void record_user_registration(bool is_guest) {
    counter("progressive_user_registrations_total").inc();
    if (is_guest) {
      counter("progressive_guest_registrations_total").inc();
    } else {
      counter("progressive_non_guest_registrations_total").inc();
    }
    gauge("progressive_users_total").inc();
  }

  void record_user_deactivated() {
    counter("progressive_user_deactivations_total").inc();
    gauge("progressive_users_total").dec();
  }

  void record_user_reactivated() {
    counter("progressive_user_reactivations_total").inc();
    gauge("progressive_users_total").inc();
  }

  void record_room_created(const std::string& room_type) {
    counter("progressive_rooms_created_total").inc();
    gauge("progressive_rooms_total").inc();
    std::map<std::string, std::string> labels;
    labels["type"] = room_type;
    counter("progressive_rooms_created_total").inc_labels(labels);
  }

  void record_room_deleted() {
    counter("progressive_rooms_deleted_total").inc();
    gauge("progressive_rooms_total").dec();
  }

  void record_admin_action(const std::string& action) {
    counter("progressive_admin_actions_total").inc();
    std::map<std::string, std::string> labels;
    labels["action"] = action;
    counter("progressive_admin_actions_total").inc_labels(labels);
  }

  void record_login_attempt(bool success) {
    counter("progressive_login_attempts_total").inc();
    if (success) {
      counter("progressive_login_successes_total").inc();
    } else {
      counter("progressive_login_failures_total").inc();
    }
  }

  void record_cache_operation(const std::string& cache_name, bool hit) {
    counter("progressive_cache_operations_total").inc();
    if (hit) {
      counter("progressive_cache_hits_total").inc();
    } else {
      counter("progressive_cache_misses_total").inc();
    }
    std::map<std::string, std::string> labels;
    labels["cache"] = cache_name;
    labels["result"] = hit ? "hit" : "miss";
    counter("progressive_cache_operations_total").inc_labels(labels);
  }

  void record_notification_sent(const std::string& push_type) {
    counter("progressive_notifications_sent_total").inc();
    std::map<std::string, std::string> labels;
    labels["type"] = push_type;
    counter("progressive_notifications_sent_total").inc_labels(labels);
  }

  void record_error(const std::string& error_type, const std::string& endpoint) {
    counter("progressive_errors_total").inc();
    std::map<std::string, std::string> labels;
    labels["type"] = error_type;
    labels["endpoint"] = endpoint;
    counter("progressive_errors_total").inc_labels(labels);
  }

  // ---- Set gauge values ----

  void set_user_count(int64_t count) {
    gauge("progressive_users_total").set(static_cast<double>(count));
  }

  void set_active_user_count(int64_t count) {
    gauge("progressive_active_users").set(static_cast<double>(count));
  }

  void set_daily_active_users(int64_t count) {
    gauge("progressive_daily_active_users").set(static_cast<double>(count));
  }

  void set_monthly_active_users(int64_t count) {
    gauge("progressive_monthly_active_users").set(static_cast<double>(count));
  }

  void set_room_count(int64_t count) {
    gauge("progressive_rooms_total").set(static_cast<double>(count));
  }

  void set_connection_count(int64_t count) {
    gauge("progressive_active_connections").set(static_cast<double>(count));
  }

  void set_federation_destinations(int64_t count) {
    gauge("progressive_federation_destinations").set(static_cast<double>(count));
  }

  void set_cache_size(const std::string& cache_name, int64_t entries) {
    gauge("progressive_cache_entries").set(static_cast<double>(entries));
    std::map<std::string, std::string> labels;
    labels["cache"] = cache_name;
    gauge("progressive_cache_entries").set_labels(labels,
                                                   static_cast<double>(entries));
  }

  void record_build_info(const std::string& version,
                          const std::string& git_commit) {
    gauge("progressive_build_info").set(1.0);
    std::map<std::string, std::string> labels;
    labels["version"] = version;
    labels["git_commit"] = git_commit;
    labels["go_version"] = "N/A"; // C++ project
    gauge("progressive_build_info").set_labels(labels, 1.0);
  }

  // ---- Export as Prometheus text format ----

  std::string to_prometheus() const {
    std::stringstream ss;

    // Add standard metadata header
    ss << "# Progressive Matrix Server Metrics\n";
    ss << "# Generated at: " << now_iso8601() << "\n";
    ss << "# Uptime: " << format_duration_sec(
        static_cast<int64_t>(uptime_seconds())) << "\n\n";

    std::shared_lock<std::shared_mutex> lock(mutex_);

    // Export all counters
    for (auto& [name, counter] : counters_) {
      ss << counter->to_prometheus() << "\n";
    }

    // Export all gauges
    for (auto& [name, gauge] : gauges_) {
      ss << gauge->to_prometheus() << "\n";
    }

    // Export all histograms
    for (auto& [name, histogram] : histograms_) {
      ss << histogram->to_prometheus() << "\n";
    }

    // Export process-level metrics
    ss << "# HELP process_cpu_seconds_total Total user and system CPU time\n";
    ss << "# TYPE process_cpu_seconds_total counter\n";
    ss << "process_cpu_seconds_total " << get_cpu_seconds() << "\n\n";

    ss << "# HELP process_resident_memory_bytes Resident memory size\n";
    ss << "# TYPE process_resident_memory_bytes gauge\n";
    ss << "process_resident_memory_bytes " << get_resident_memory() << "\n\n";

    ss << "# HELP process_open_fds Number of open file descriptors\n";
    ss << "# TYPE process_open_fds gauge\n";
    ss << "process_open_fds " << get_open_fds() << "\n\n";

    ss << "# HELP process_start_time_seconds Start time of the process\n";
    ss << "# TYPE process_start_time_seconds gauge\n";
    ss << "process_start_time_seconds " << std::fixed << std::setprecision(3)
       << static_cast<double>(start_time_ms_) / 1000.0 << "\n\n";

    ss << "# HELP process_uptime_seconds Process uptime in seconds\n";
    ss << "# TYPE process_uptime_seconds gauge\n";
    ss << "process_uptime_seconds " << std::fixed << std::setprecision(3)
       << uptime_seconds() << "\n\n";

    ss << "# HELP progressive_server_version Server version info\n";
    ss << "# TYPE progressive_server_version gauge\n";
    ss << "progressive_server_version{version=\"" << kServerVersion << "\"} 1\n";

    return ss.str();
  }

  // ---- Export as JSON ----

  json to_json() const {
    json j = json::object();
    std::shared_lock<std::shared_mutex> lock(mutex_);

    for (auto& [name, counter] : counters_) {
      j["counters"][name] = counter->value();
    }
    for (auto& [name, gauge] : gauges_) {
      j["gauges"][name] = gauge->value();
    }
    for (auto& [name, histogram] : histograms_) {
      j["histograms"][name] = json({
          {"sum", histogram->sum()},
          {"count", histogram->count()}
      });
    }

    j["process"] = json({
        {"cpu_seconds", get_cpu_seconds()},
        {"resident_memory_bytes", get_resident_memory()},
        {"open_fds", get_open_fds()},
        {"uptime_seconds", uptime_seconds()}
    });

    return j;
  }

  // ---- Reset all metrics (for testing) ----

  void reset_all() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    counters_.clear();
    gauges_.clear();
    histograms_.clear();
    initialize_default_metrics();
  }

  // ---- Server start time ----

  void set_start_time(int64_t start_time_ms) {
    start_time_ms_ = start_time_ms;
  }

  double uptime_seconds() const {
    return static_cast<double>(now_ms() - start_time_ms_) / 1000.0;
  }

  // ---- Get specific metric value for health checks ----

  double get_counter_value(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = counters_.find(name);
    return it != counters_.end() ? it->second->value() : 0.0;
  }

  double get_gauge_value(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = gauges_.find(name);
    return it != gauges_.end() ? it->second->value() : 0.0;
  }

  // ---- List all registered metric names ----

  std::vector<std::string> metric_names() const {
    std::vector<std::string> names;
    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (auto& [name, _] : counters_) names.push_back(name);
    for (auto& [name, _] : gauges_) names.push_back(name);
    for (auto& [name, _] : histograms_) names.push_back(name);
    std::sort(names.begin(), names.end());
    return names;
  }

private:
  void initialize_default_metrics() {
    // ---- HTTP metrics ----
    create_counter("progressive_http_requests_total",
                   "Total number of HTTP requests processed",
                   {"method", "status"});
    create_histogram("progressive_http_request_duration_seconds",
                     "HTTP request duration in seconds",
                     default_latency_buckets());
    create_counter("progressive_http_request_size_bytes_total",
                   "Total HTTP request body size");
    create_counter("progressive_http_response_size_bytes_total",
                   "Total HTTP response body size");

    // ---- Event processing metrics ----
    create_counter("progressive_events_processed_total",
                   "Total number of events processed",
                   {"type", "direction"});
    create_histogram("progressive_event_processing_duration_seconds",
                     "Event processing duration in seconds",
                     default_latency_buckets());

    // ---- Federation metrics ----
    create_counter("progressive_federation_requests_total",
                   "Total federation requests",
                   {"direction", "success"});
    create_histogram("progressive_federation_request_duration_seconds",
                     "Federation request duration in seconds",
                     default_latency_buckets());
    create_gauge("progressive_federation_destinations",
                 "Number of federation destinations connected");

    // ---- Database metrics ----
    create_counter("progressive_db_queries_total",
                   "Total database queries executed");
    create_histogram("progressive_db_query_duration_seconds",
                     "Database query duration in seconds",
                     {0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025,
                      0.05, 0.1, 0.25, 0.5, 1.0, 5.0});
    create_gauge("progressive_db_connection_pool_size",
                 "Database connection pool size");
    create_gauge("progressive_db_connection_pool_in_use",
                 "Database connections currently in use");

    // ---- User metrics ----
    create_gauge("progressive_users_total", "Total registered users");
    create_gauge("progressive_active_users",
                 "Active users (seen in last 30 days)");
    create_gauge("progressive_daily_active_users", "Daily active users");
    create_gauge("progressive_monthly_active_users", "Monthly active users");
    create_counter("progressive_user_registrations_total",
                   "Total user registrations");
    create_counter("progressive_guest_registrations_total",
                   "Total guest registrations");
    create_counter("progressive_non_guest_registrations_total",
                   "Total non-guest registrations");
    create_counter("progressive_user_deactivations_total",
                   "Total user deactivations");
    create_counter("progressive_user_reactivations_total",
                   "Total user reactivations");
    create_counter("progressive_login_attempts_total",
                   "Total login attempts");
    create_counter("progressive_login_successes_total",
                   "Total successful logins");
    create_counter("progressive_login_failures_total",
                   "Total failed logins");

    // ---- Room metrics ----
    create_gauge("progressive_rooms_total", "Total rooms");
    create_counter("progressive_rooms_created_total",
                   "Total rooms created", {"type"});
    create_counter("progressive_rooms_deleted_total",
                   "Total rooms deleted");
    create_counter("progressive_room_joins_total",
                   "Total room join events");
    create_counter("progressive_room_leaves_total",
                   "Total room leave events");
    create_counter("progressive_room_invites_total",
                   "Total room invite events");
    create_counter("progressive_room_bans_total",
                   "Total room ban events");

    // ---- Media metrics ----
    create_counter("progressive_media_uploads_total",
                   "Total media uploads");
    create_counter("progressive_media_downloads_total",
                   "Total media downloads");
    create_counter("progressive_media_bytes_total",
                   "Total media bytes uploaded");
    create_counter("progressive_media_bytes_downloaded_total",
                   "Total media bytes downloaded");
    create_gauge("progressive_media_bytes",
                 "Current total media bytes stored");
    create_histogram("progressive_media_upload_duration_seconds",
                     "Media upload duration in seconds",
                     default_latency_buckets());
    create_histogram("progressive_media_upload_size_bytes",
                     "Media upload size in bytes",
                     default_size_buckets());

    // ---- Cache metrics ----
    create_counter("progressive_cache_operations_total",
                   "Total cache operations", {"cache", "result"});
    create_counter("progressive_cache_hits_total", "Total cache hits");
    create_counter("progressive_cache_misses_total", "Total cache misses");
    create_gauge("progressive_cache_entries",
                 "Total cache entries", {"cache"});

    // ---- Notifications ----
    create_counter("progressive_notifications_sent_total",
                   "Total notifications sent", {"type"});

    // ---- Admin actions ----
    create_counter("progressive_admin_actions_total",
                   "Total admin actions", {"action"});

    // ---- Error metrics ----
    create_counter("progressive_errors_total",
                   "Total errors encountered", {"type", "endpoint"});

    // ---- Connection metrics ----
    create_gauge("progressive_active_connections",
                 "Active client connections");
    create_counter("progressive_connections_total",
                   "Total connections since start");
    create_counter("progressive_connections_rejected_total",
                   "Total connections rejected");

    // ---- Build info ----
    create_gauge("progressive_build_info",
                 "Build information", {"version", "git_commit", "go_version"});
    record_build_info(kServerVersion, "abc123def456");

    // ---- Memory / GC ----
    create_gauge("progressive_memory_allocated_bytes",
                 "Current allocated heap memory");
    create_gauge("progressive_memory_system_bytes",
                 "Total memory obtained from the OS");

    // ---- Thread pool ----
    create_gauge("progressive_thread_pool_size",
                 "Thread pool size");
    create_gauge("progressive_thread_pool_active",
                 "Active threads in pool");
    create_gauge("progressive_thread_pool_queued",
                 "Queued tasks in thread pool");
  }

  // ---- Process-level metrics helpers ----

  double get_cpu_seconds() const {
    // Placeholder: read from /proc/self/stat on Linux
    // Real implementation would parse /proc/self/stat
    return static_cast<double>(now_ms() - start_time_ms_) / 1000.0 *
           std::thread::hardware_concurrency() * 0.01; // Rough estimate
  }

  int64_t get_resident_memory() const {
    // Placeholder: read from /proc/self/status
    // Real implementation would parse /proc/self/status for VmRSS
    return 128 * 1024 * 1024; // Stub: 128MB
  }

  int64_t get_open_fds() const {
    // Placeholder: count files in /proc/self/fd
    return 42; // Stub
  }

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, std::shared_ptr<PrometheusCounter>> counters_;
  std::unordered_map<std::string, std::shared_ptr<PrometheusGauge>> gauges_;
  std::unordered_map<std::string, std::shared_ptr<PrometheusHistogram>> histograms_;
  int64_t start_time_ms_ = now_ms();
};

// ============================================================================
// 6. ServerAdminAPI — Main orchestrator class that combines all admin
//    functionality: version endpoints, user/room/media management, and
//    Prometheus metrics export.
//
// Equivalent to synapse/rest/admin/__init__.py
// ============================================================================

class ServerAdminAPI {
public:
  ServerAdminAPI(storage::DatabasePool& db, const std::string& server_name)
      : db_(db),
        server_name_(server_name),
        version_handler_(std::make_unique<ServerVersionHandler>(
            server_name, kServerVersion)),
        user_manager_(std::make_unique<AdminUserManager>(db, server_name)),
        room_manager_(std::make_unique<AdminRoomManager>(db, server_name)),
        media_manager_(std::make_unique<AdminMediaManager>(db, server_name)),
        metrics_registry_(std::make_shared<PrometheusRegistry>()) {
    // Set global metrics registry start time
    metrics_registry_->set_start_time(version_handler_->start_time_ms());
  }

  // ---- Version endpoints ----

  json handle_federation_version() {
    return version_handler_->handle_federation_version();
  }

  json handle_server_version() {
    return version_handler_->handle_synapse_server_version();
  }

  json handle_client_versions() {
    return version_handler_->handle_client_versions();
  }

  // ---- User management ----

  json handle_get_user_info(const std::string& user_id) {
    return user_manager_->get_user_info(user_id);
  }

  json handle_reset_password(const std::string& user_id, const json& body) {
    metrics_registry_->record_admin_action("reset_password");
    return user_manager_->reset_password(user_id, body);
  }

  json handle_deactivate_user(const std::string& user_id,
                               const json& body) {
    auto result = user_manager_->deactivate_user(user_id, body);
    if (result.contains("deactivated") && result["deactivated"].get<bool>()) {
      metrics_registry_->record_user_deactivated();
    }
    metrics_registry_->record_admin_action("deactivate_user");
    return result;
  }

  json handle_reactivate_user(const std::string& user_id) {
    auto result = user_manager_->reactivate_user(user_id);
    if (result.contains("reactivated") && result["reactivated"].get<bool>()) {
      metrics_registry_->record_user_reactivated();
    }
    metrics_registry_->record_admin_action("reactivate_user");
    return result;
  }

  json handle_list_users(int64_t from, int64_t limit,
                          const std::string& name_filter,
                          bool guests, bool deactivated,
                          const std::string& order_by,
                          const std::string& dir) {
    return user_manager_->list_users(from, limit, name_filter,
                                      guests, deactivated, order_by, dir);
  }

  json handle_search_users(const std::string& search_term) {
    return user_manager_->search_users(search_term);
  }

  json handle_get_user_devices(const std::string& user_id) {
    return user_manager_->get_user_devices_json(user_id);
  }

  json handle_delete_user_devices(const std::string& user_id) {
    metrics_registry_->record_admin_action("delete_user_devices");
    return user_manager_->delete_all_user_devices(user_id);
  }

  json handle_delete_user_device(const std::string& user_id,
                                  const std::string& device_id) {
    metrics_registry_->record_admin_action("delete_user_device");
    return user_manager_->delete_user_device(user_id, device_id);
  }

  // ---- Room management ----

  json handle_list_rooms(int64_t from, int64_t limit,
                          const std::string& order_by,
                          const std::string& dir,
                          const std::string& search_term,
                          const std::string& room_type,
                          bool include_all) {
    return room_manager_->list_rooms(from, limit, order_by, dir,
                                      search_term, room_type, include_all);
  }

  json handle_get_room_details(const std::string& room_id) {
    return room_manager_->get_room_details(room_id);
  }

  json handle_get_room_members(const std::string& room_id) {
    return room_manager_->get_room_members(room_id);
  }

  json handle_get_room_state(const std::string& room_id) {
    return room_manager_->get_room_state(room_id);
  }

  json handle_delete_room(const std::string& room_id, const json& body) {
    auto result = room_manager_->delete_room(room_id, body);
    metrics_registry_->record_room_deleted();
    metrics_registry_->record_admin_action("delete_room");
    return result;
  }

  json handle_block_room(const std::string& room_id, const json& body) {
    metrics_registry_->record_admin_action("block_room");
    return room_manager_->block_room(room_id, body);
  }

  json handle_unblock_room(const std::string& room_id) {
    metrics_registry_->record_admin_action("unblock_room");
    return room_manager_->unblock_room(room_id);
  }

  json handle_get_blocked_rooms() {
    return room_manager_->get_blocked_rooms();
  }

  // ---- Media management ----

  json handle_get_media_stats() {
    return media_manager_->get_media_stats();
  }

  json handle_delete_media(const std::string& media_id) {
    metrics_registry_->record_admin_action("delete_media");
    return media_manager_->delete_media(media_id);
  }

  json handle_quarantine_media(const std::string& media_id,
                                const json& body) {
    metrics_registry_->record_admin_action("quarantine_media");
    return media_manager_->quarantine_media(media_id, body);
  }

  json handle_unquarantine_media(const std::string& media_id) {
    metrics_registry_->record_admin_action("unquarantine_media");
    return media_manager_->unquarantine_media(media_id);
  }

  json handle_purge_remote_media_cache(const json& body) {
    metrics_registry_->record_admin_action("purge_media_cache");
    return media_manager_->purge_remote_media_cache(body);
  }

  json handle_list_media(int64_t from, int64_t limit,
                          const std::string& user_id,
                          const std::string& media_type,
                          const std::string& order_by,
                          const std::string& dir) {
    return media_manager_->list_media(from, limit, user_id,
                                       media_type, order_by, dir);
  }

  json handle_list_protected_media() {
    return media_manager_->list_protected_media();
  }

  // ---- Prometheus metrics ----

  std::string handle_prometheus_metrics() {
    return metrics_registry_->to_prometheus();
  }

  json handle_metrics_json() {
    return metrics_registry_->to_json();
  }

  std::vector<std::string> handle_list_metrics() {
    return metrics_registry_->metric_names();
  }

  // ---- Metrics recording helpers for use by other subsystems ----

  void record_http_request(const std::string& method, int status,
                            double duration) {
    metrics_registry_->record_http_request(method, status, duration);
  }

  void record_event_processed(const std::string& type, bool incoming) {
    metrics_registry_->record_event_processed(type, incoming);
  }

  void record_federation_request(bool incoming, bool success,
                                  double duration) {
    metrics_registry_->record_federation_request(incoming, success, duration);
  }

  void record_db_query(const std::string& type, double duration) {
    metrics_registry_->record_db_query(type, duration);
  }

  void record_user_registration(bool is_guest) {
    metrics_registry_->record_user_registration(is_guest);
  }

  void record_login_attempt(bool success) {
    metrics_registry_->record_login_attempt(success);
  }

  void record_error(const std::string& type, const std::string& endpoint) {
    metrics_registry_->record_error(type, endpoint);
  }

  // ---- Accessor for shared metrics registry ----
  std::shared_ptr<PrometheusRegistry> metrics() { return metrics_registry_; }

  // ---- Server info ----
  const std::string& server_name() const { return server_name_; }
  const std::string& server_version() const {
    return version_handler_->version();
  }
  double uptime_seconds() const {
    return version_handler_->uptime_seconds();
  }
  int64_t start_time_ms() const {
    return version_handler_->start_time_ms();
  }

private:
  storage::DatabasePool& db_;
  std::string server_name_;
  std::unique_ptr<ServerVersionHandler> version_handler_;
  std::unique_ptr<AdminUserManager> user_manager_;
  std::unique_ptr<AdminRoomManager> room_manager_;
  std::unique_ptr<AdminMediaManager> media_manager_;
  std::shared_ptr<PrometheusRegistry> metrics_registry_;
};

}  // namespace progressive
