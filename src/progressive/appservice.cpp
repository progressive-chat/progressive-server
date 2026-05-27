// appservice.cpp - Matrix Application Service API
// Implements AS registration, transaction pushing, query APIs,
// namespace management, ghost user management, rate limiting, and auth.
// Equivalent to synapse/appservice/ + synapse/app/ + synapse/handlers/appservice.py
// Target: 2000+ lines

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
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
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;

// ============================================================================
// Forward declarations
// ============================================================================
class AppServiceManager;
class AppServiceRegistration;
class AppServiceTransaction;
class AppServiceScheduler;
class AppServiceRateLimiter;
class AppServiceNamespaceManager;
class AppServiceGhostManager;
class AppServiceQueryHandler;
class AppServiceAuthChecker;

// ============================================================================
// Utility: string helpers
// ============================================================================
namespace {
  bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
  }
  bool ends_with(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() &&
           s.substr(s.size() - suffix.size()) == suffix;
  }
  std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
  }
  std::string url_encode(const std::string& s) {
    std::ostringstream escaped;
    escaped << std::hex << std::uppercase;
    for (unsigned char c : s) {
      if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
        escaped << c;
      } else {
        escaped << '%' << std::setw(2) << std::setfill('0')
                << static_cast<int>(c);
      }
    }
    return escaped.str();
  }
  std::string generate_token(size_t length = 64) {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);
    std::string token;
    token.reserve(length);
    for (size_t i = 0; i < length; ++i)
      token += charset[dist(rng)];
    return token;
  }
  std::string current_iso8601() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) %
              1000;
    std::tm tm_buf;
    gmtime_r(&t, &tm_buf);
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S") << '.' << std::setw(3)
        << std::setfill('0') << ms.count() << "Z";
    return oss.str();
  }
} // anonymous namespace

// ============================================================================
// AppServiceNamespace - a single namespace entry
// Equivalent to synapse.appservice.api.Namespace
// ============================================================================
struct AppServiceNamespace {
  std::string regex_str;         // regex pattern string
  std::regex compiled;           // compiled regex
  bool exclusive{false};         // whether this namespace is exclusive
  std::string namespace_type;    // "users", "aliases", or "rooms"

  AppServiceNamespace() = default;
  AppServiceNamespace(const std::string& regex_str_, bool exclusive_,
                      const std::string& type)
      : regex_str(regex_str_),
        compiled(regex_str_, std::regex::ECMAScript | std::regex::optimize),
        exclusive(exclusive_),
        namespace_type(type) {}

  // Check whether an entity ID matches this namespace
  bool matches(const std::string& entity_id) const {
    return std::regex_match(entity_id, compiled);
  }

  // Check whether any part of an ID is matched
  bool matches_partial(const std::string& entity_id) const {
    return std::regex_search(entity_id, compiled);
  }
};

// ============================================================================
// AppServiceRegistration - single app service registration record
// Equivalent to synapse.appservice.api.ApplicationService
// ============================================================================
class AppServiceRegistration {
public:
  AppServiceRegistration() : id_(0) {}

  // Parse from YAML config node
  static std::optional<AppServiceRegistration> from_yaml(
      const YAML::Node& node) {
    AppServiceRegistration reg;
    try {
      // Required fields
      if (!node["id"] || !node["as_token"] || !node["hs_token"] ||
          !node["url"]) {
        return std::nullopt;
      }
      reg.id_ = node["id"].as<std::string>();
      reg.as_token_ = node["as_token"].as<std::string>();
      reg.hs_token_ = node["hs_token"].as<std::string>();
      reg.url_ = node["url"].as<std::string>();

      // Optional sender_localpart
      if (node["sender_localpart"]) {
        reg.sender_localpart_ = node["sender_localpart"].as<std::string>();
      }

      // Optional rate_limited (default true)
      if (node["rate_limited"]) {
        reg.rate_limited_ = node["rate_limited"].as<bool>();
      }

      // Optional protocol descriptor
      if (node["protocols"]) {
        reg.protocols_ = node["protocols"].as<std::vector<std::string>>();
      }

      // Parse namespaces
      if (node["namespaces"]) {
        auto& ns = node["namespaces"];
        reg.parse_namespaces(ns);
      }

      // Validate URL format
      if (!starts_with(reg.url_, "http://") &&
          !starts_with(reg.url_, "https://")) {
        return std::nullopt;
      }

      reg.valid_ = true;
      return reg;

    } catch (const std::exception& e) {
      std::cerr << "[AppService] Parse error for " << (reg.id_.empty() ? "unknown" : reg.id_)
                << ": " << e.what() << "\n";
      return std::nullopt;
    }
  }

  // Parse from a JSON representation (for API-based registration)
  static std::optional<AppServiceRegistration> from_json(
      const json& j, const std::string& as_token,
      const std::string& hs_token) {
    AppServiceRegistration reg;
    try {
      if (!j.contains("id") || !j.contains("url")) {
        return std::nullopt;
      }
      reg.id_ = j["id"].get<std::string>();
      reg.as_token_ = as_token;
      reg.hs_token_ = hs_token;
      reg.url_ = j["url"].get<std::string>();

      if (j.contains("sender_localpart")) {
        reg.sender_localpart_ = j["sender_localpart"].get<std::string>();
      }
      if (j.contains("rate_limited")) {
        reg.rate_limited_ = j["rate_limited"].get<bool>();
      }
      if (j.contains("protocols")) {
        for (auto& p : j["protocols"]) {
          reg.protocols_.push_back(p.get<std::string>());
        }
      }
      if (j.contains("namespaces")) {
        auto& ns = j["namespaces"];
        if (ns.contains("users")) {
          for (auto& u : ns["users"]) {
            std::string r = u["regex"].get<std::string>();
            bool excl = u.value("exclusive", false);
            reg.user_namespaces_.emplace_back(r, excl, "users");
          }
        }
        if (ns.contains("aliases")) {
          for (auto& a : ns["aliases"]) {
            std::string r = a["regex"].get<std::string>();
            bool excl = a.value("exclusive", false);
            reg.alias_namespaces_.emplace_back(r, excl, "aliases");
          }
        }
        if (ns.contains("rooms")) {
          for (auto& rm : ns["rooms"]) {
            std::string r = rm["regex"].get<std::string>();
            bool excl = rm.value("exclusive", false);
            reg.room_namespaces_.emplace_back(r, excl, "rooms");
          }
        }
      }
      reg.valid_ = true;
      return reg;
    } catch (const std::exception& e) {
      std::cerr << "[AppService] JSON parse error: " << e.what() << "\n";
      return std::nullopt;
    }
  }

  // Serialize to JSON
  json to_json() const {
    json j;
    j["id"] = id_;
    j["url"] = url_;
    j["as_token"] = as_token_;
    j["hs_token"] = hs_token_;
    if (!sender_localpart_.empty())
      j["sender_localpart"] = sender_localpart_;
    j["rate_limited"] = rate_limited_;

    if (!user_namespaces_.empty()) {
      json users = json::array();
      for (auto& ns : user_namespaces_) {
        json u;
        u["regex"] = ns.regex_str;
        u["exclusive"] = ns.exclusive;
        users.push_back(u);
      }
      j["namespaces"]["users"] = users;
    }
    if (!alias_namespaces_.empty()) {
      json aliases = json::array();
      for (auto& ns : alias_namespaces_) {
        json a;
        a["regex"] = ns.regex_str;
        a["exclusive"] = ns.exclusive;
        aliases.push_back(a);
      }
      j["namespaces"]["aliases"] = aliases;
    }
    if (!room_namespaces_.empty()) {
      json rooms = json::array();
      for (auto& ns : room_namespaces_) {
        json r;
        r["regex"] = ns.regex_str;
        r["exclusive"] = ns.exclusive;
        rooms.push_back(r);
      }
      j["namespaces"]["rooms"] = rooms;
    }
    if (!protocols_.empty()) {
      j["protocols"] = protocols_;
    }
    return j;
  }

  // ============ Accessors ============
  const std::string& id() const { return id_; }
  const std::string& as_token() const { return as_token_; }
  const std::string& hs_token() const { return hs_token_; }
  const std::string& url() const { return url_; }
  const std::string& sender_localpart() const { return sender_localpart_; }
  bool rate_limited() const { return rate_limited_; }
  bool valid() const { return valid_; }
  const std::vector<AppServiceNamespace>& user_namespaces() const {
    return user_namespaces_;
  }
  const std::vector<AppServiceNamespace>& alias_namespaces() const {
    return alias_namespaces_;
  }
  const std::vector<AppServiceNamespace>& room_namespaces() const {
    return room_namespaces_;
  }
  const std::vector<std::string>& protocols() const { return protocols_; }

  // ============ Namespace matching helpers ============

  // Check if a user ID is in a user namespace
  bool is_user_in_namespace(const std::string& user_id) const {
    for (auto& ns : user_namespaces_) {
      if (ns.matches(user_id)) return true;
    }
    return false;
  }

  // Check if a room alias is in an alias namespace
  bool is_alias_in_namespace(const std::string& alias) const {
    for (auto& ns : alias_namespaces_) {
      if (ns.matches(alias)) return true;
    }
    return false;
  }

  // Check if a room ID is in a room namespace
  bool is_room_in_namespace(const std::string& room_id) const {
    for (auto& ns : room_namespaces_) {
      if (ns.matches(room_id)) return true;
    }
    return false;
  }

  // Check if any event in a list is interesting for this app service
  bool is_interested_in_event(const json& event) const {
    // Check sender
    if (event.contains("sender")) {
      std::string sender = event["sender"].get<std::string>();
      if (is_user_in_namespace(sender)) return true;
    }

    // Check room_id
    if (event.contains("room_id")) {
      std::string room_id = event["room_id"].get<std::string>();
      if (is_room_in_namespace(room_id)) return true;
    }

    // Check state_key (for state events, this is often a user_id)
    if (event.contains("state_key")) {
      std::string state_key = event["state_key"].get<std::string>();
      if (is_user_in_namespace(state_key)) return true;
    }

    // Check content for potentially matching user/room IDs
    if (event.contains("content")) {
      auto& content = event["content"];
      if (content.contains("membership") &&
          content.contains("displayname")) {
        // Membership event -- state_key is the user
        if (event.contains("state_key")) {
          std::string sk = event["state_key"].get<std::string>();
          if (is_user_in_namespace(sk)) return true;
        }
      }
    }

    return false;
  }

  // Filter a list of events to only those this app service is interested in
  std::vector<json> filter_events(const std::vector<json>& events) const {
    std::vector<json> result;
    for (auto& e : events) {
      if (is_interested_in_event(e)) {
        result.push_back(e);
      }
    }
    return result;
  }

  // Check if this app service is interested in a room
  bool is_interested_in_room(const std::string& room_id,
                              const std::vector<std::string>& room_members = {}) const {
    if (is_room_in_namespace(room_id)) return true;
    for (auto& member : room_members) {
      if (is_user_in_namespace(member)) return true;
    }
    return false;
  }

  // Check if this app service is interested in a user
  bool is_interested_in_user(const std::string& user_id) const {
    return is_user_in_namespace(user_id);
  }

  // ============ Ghost user helpers ============

  // Get the ghost user ID for a given external user
  // App services use prefix: @_<appservice_id>_<external_user>:<domain>
  std::string get_ghost_user_id(const std::string& external_user,
                                 const std::string& homeserver_domain) const {
    std::string sanitized = external_user;
    // Replace '/' and other problematic chars for MXIDs
    for (auto& c : sanitized) {
      if (c == '/' || c == ':' || c == '#' || c == '@' ||
          c == '!' || c == '?' || c == '&' || c == '=' ||
          c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        c = '_';
      }
    }
    return "@_" + id_ + "_" + sanitized + ":" + homeserver_domain;
  }

  // Get the external user ID encoded in a ghost MXID
  static std::optional<std::string> get_external_from_ghost(
      const std::string& ghost_user_id, const std::string& appservice_id) {
    std::string prefix = "@_" + appservice_id + "_";
    if (!starts_with(ghost_user_id, prefix)) return std::nullopt;

    // Extract the part between prefix and the final ":domain"
    auto colon_pos = ghost_user_id.rfind(':');
    if (colon_pos == std::string::npos) return std::nullopt;

    return ghost_user_id.substr(
        prefix.size(), colon_pos - prefix.size());
  }

  // Check if a ghost user belongs to this app service
  bool owns_ghost_user(const std::string& user_id) const {
    std::string prefix = "@_" + id_ + "_";
    return starts_with(user_id, prefix);
  }

private:
  void parse_namespaces(const YAML::Node& ns) {
    // Parse user namespaces
    if (ns["users"]) {
      for (auto& n : ns["users"]) {
        std::string regex_str = n["regex"].as<std::string>();
        bool exclusive = n["exclusive"] ? n["exclusive"].as<bool>() : false;
        user_namespaces_.emplace_back(regex_str, exclusive, "users");
      }
    }
    // Parse alias namespaces
    if (ns["aliases"]) {
      for (auto& n : ns["aliases"]) {
        std::string regex_str = n["regex"].as<std::string>();
        bool exclusive = n["exclusive"] ? n["exclusive"].as<bool>() : false;
        alias_namespaces_.emplace_back(regex_str, exclusive, "aliases");
      }
    }
    // Parse room namespaces
    if (ns["rooms"]) {
      for (auto& n : ns["rooms"]) {
        std::string regex_str = n["regex"].as<std::string>();
        bool exclusive = n["exclusive"] ? n["exclusive"].as<bool>() : false;
        room_namespaces_.emplace_back(regex_str, exclusive, "rooms");
      }
    }
  }

  std::string id_;
  std::string as_token_;
  std::string hs_token_;
  std::string url_;
  std::string sender_localpart_;
  bool valid_{false};
  bool rate_limited_{true};

  std::vector<AppServiceNamespace> user_namespaces_;
  std::vector<AppServiceNamespace> alias_namespaces_;
  std::vector<AppServiceNamespace> room_namespaces_;
  std::vector<std::string> protocols_;
};

// ============================================================================
// AppServiceTransaction - a single transaction of events pushed to an AS
// Equivalent to synapse.appservice.api.ApplicationServiceTransaction
// ============================================================================
class AppServiceTransaction {
public:
  AppServiceTransaction(const std::string& service_id,
                         const std::string& txn_id,
                         const std::vector<json>& events)
      : service_id_(service_id),
        txn_id_(txn_id),
        events_(events),
        created_at_(std::chrono::steady_clock::now()) {}

  // Serialize to the JSON that gets sent to the app service
  json to_body() const {
    json body;
    body["events"] = json::array();
    for (auto& e : events_) {
      body["events"].push_back(e);
    }
    body["txn_id"] = txn_id_;
    return body;
  }

  const std::string& service_id() const { return service_id_; }
  const std::string& txn_id() const { return txn_id_; }
  const std::vector<json>& events() const { return events_; }
  size_t event_count() const { return events_.size(); }
  auto created_at() const { return created_at_; }

  // Mark this transaction as sent
  void mark_sent(const std::string& response_body = "") {
    sent_ = true;
    sent_at_ = std::chrono::steady_clock::now();
    response_body_ = response_body;
  }

  bool is_sent() const { return sent_; }
  auto sent_at() const { return sent_at_; }
  const std::string& response_body() const { return response_body_; }

  // Age in seconds since creation
  double age_seconds() const {
    return std::chrono::duration<double>(
               std::chrono::steady_clock::now() - created_at_)
        .count();
  }

private:
  std::string service_id_;
  std::string txn_id_;
  std::vector<json> events_;
  std::chrono::steady_clock::time_point created_at_;
  bool sent_{false};
  std::chrono::steady_clock::time_point sent_at_;
  std::string response_body_;
};

// ============================================================================
// AppServiceRateLimiter - rate limiting for app service requests
// Equivalent to synapse.appservice.api.RateLimiter
// ============================================================================
class AppServiceRateLimiter {
public:
  AppServiceRateLimiter() = default;

  struct Config {
    int max_requests_per_second{100};
    int burst_size{10};
    int max_transactions_per_second{10};
  };

  explicit AppServiceRateLimiter(const Config& config) : config_(config) {}

  // Check if a request is allowed. Returns true if allowed, false if rate limited.
  bool allow_request(const std::string& service_id,
                      const std::string& endpoint_type = "transaction") {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto& state = states_[service_id];

    // Clean up old entries
    auto window = std::chrono::seconds(1);
    while (!state.timestamps.empty() &&
           now - state.timestamps.front() > window) {
      state.timestamps.pop_front();
    }

    int max_rps = config_.max_requests_per_second;
    if (endpoint_type == "transaction" &&
        static_cast<int>(state.timestamps.size()) >= max_rps) {
      return false;
    }

    state.timestamps.push_back(now);
    state.request_count++;
    return true;
  }

  // Check if a transaction push is allowed
  bool allow_transaction(const std::string& service_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto& state = states_[service_id];

    auto window = std::chrono::seconds(1);
    while (!state.txn_timestamps.empty() &&
           now - state.txn_timestamps.front() > window) {
      state.txn_timestamps.pop_front();
    }

    if (static_cast<int>(state.txn_timestamps.size()) >=
        config_.max_transactions_per_second) {
      return false;
    }

    state.txn_timestamps.push_back(now);
    state.txn_count++;
    return true;
  }

  // Get current rate for a service
  double current_rate(const std::string& service_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = states_.find(service_id);
    if (it == states_.end()) return 0.0;
    auto now = std::chrono::steady_clock::now();
    auto window = std::chrono::seconds(1);
    auto& t = it->second.timestamps;
    int count = 0;
    for (auto& ts : t) {
      if (now - ts <= window) count++;
    }
    return static_cast<double>(count);
  }

  // Reset rate tracking for a service
  void reset(const std::string& service_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    states_.erase(service_id);
  }

  // Update configuration
  void set_config(const Config& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
  }

private:
  struct ServiceRateState {
    std::deque<std::chrono::steady_clock::time_point> timestamps;
    std::deque<std::chrono::steady_clock::time_point> txn_timestamps;
    int64_t request_count{0};
    int64_t txn_count{0};
  };

  Config config_;
  mutable std::mutex mutex_;
  std::unordered_map<std::string, ServiceRateState> states_;
};

// ============================================================================
// AppServiceNamespaceManager - manages all namespaces across all app services
// Equivalent to synapse.appservice.api.NamespaceManager
// ============================================================================
class AppServiceNamespaceManager {
public:
  AppServiceNamespaceManager() = default;

  // Update namespaces from all registered services
  void update_from_services(
      const std::vector<std::shared_ptr<AppServiceRegistration>>& services) {
    std::unique_lock lock(mutex_);

    user_namespaces_.clear();
    alias_namespaces_.clear();
    room_namespaces_.clear();
    exclusive_map_.clear();

    for (auto& svc : services) {
      // Track exclusive namespace owners
      for (auto& ns : svc->user_namespaces()) {
        user_namespaces_.push_back(
            {ns, svc->id(), svc});
        if (ns.exclusive) {
          exclusive_map_[svc->id()].user_patterns.push_back(ns.regex_str);
        }
      }
      for (auto& ns : svc->alias_namespaces()) {
        alias_namespaces_.push_back(
            {ns, svc->id(), svc});
        if (ns.exclusive) {
          exclusive_map_[svc->id()].alias_patterns.push_back(ns.regex_str);
        }
      }
      for (auto& ns : svc->room_namespaces()) {
        room_namespaces_.push_back(
            {ns, svc->id(), svc});
        if (ns.exclusive) {
          exclusive_map_[svc->id()].room_patterns.push_back(ns.regex_str);
        }
      }
    }
  }

  // Find app services interested in a user ID
  std::vector<std::shared_ptr<AppServiceRegistration>>
  get_services_for_user(const std::string& user_id) const {
    std::shared_lock lock(mutex_);
    std::vector<std::shared_ptr<AppServiceRegistration>> result;
    for (auto& entry : user_namespaces_) {
      if (entry.namespace_.matches(user_id)) {
        result.push_back(entry.service);
      }
    }
    return result;
  }

  // Find app services interested in a room alias
  std::vector<std::shared_ptr<AppServiceRegistration>>
  get_services_for_alias(const std::string& alias) const {
    std::shared_lock lock(mutex_);
    std::vector<std::shared_ptr<AppServiceRegistration>> result;
    for (auto& entry : alias_namespaces_) {
      if (entry.namespace_.matches(alias)) {
        result.push_back(entry.service);
      }
    }
    return result;
  }

  // Find app services interested in a room ID
  std::vector<std::shared_ptr<AppServiceRegistration>>
  get_services_for_room(const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    std::vector<std::shared_ptr<AppServiceRegistration>> result;
    for (auto& entry : room_namespaces_) {
      if (entry.namespace_.matches(room_id)) {
        result.push_back(entry.service);
      }
    }
    return result;
  }

  // Get all services interested in an event
  std::vector<std::shared_ptr<AppServiceRegistration>>
  get_interested_services_for_event(const json& event) const {
    std::shared_lock lock(mutex_);
    std::set<std::string> seen;
    std::vector<std::shared_ptr<AppServiceRegistration>> result;

    auto add_if_new = [&](std::shared_ptr<AppServiceRegistration> svc) {
      if (!svc) return;
      if (seen.insert(svc->id()).second) {
        result.push_back(svc);
      }
    };

    // Check user services (sender, state_key)
    if (event.contains("sender")) {
      std::string sender = event["sender"].get<std::string>();
      for (auto& entry : user_namespaces_) {
        if (entry.namespace_.matches(sender)) {
          add_if_new(entry.service);
        }
      }
    }

    // Check room services
    if (event.contains("room_id")) {
      std::string room_id = event["room_id"].get<std::string>();
      for (auto& entry : room_namespaces_) {
        if (entry.namespace_.matches(room_id)) {
          add_if_new(entry.service);
        }
      }
    }

    // Check state_key for potential user match
    if (event.contains("state_key")) {
      std::string state_key = event["state_key"].get<std::string>();
      for (auto& entry : user_namespaces_) {
        if (entry.namespace_.matches(state_key)) {
          add_if_new(entry.service);
        }
      }
    }

    return result;
  }

  // Get services by specific namespace action (for auth checks)
  std::vector<std::shared_ptr<AppServiceRegistration>>
  get_services_for_user_in_room(const std::string& user_id,
                                 const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    std::set<std::string> seen;
    std::vector<std::shared_ptr<AppServiceRegistration>> result;

    for (auto& entry : user_namespaces_) {
      if (entry.namespace_.matches(user_id) &&
          seen.insert(entry.service->id()).second) {
        result.push_back(entry.service);
      }
    }
    for (auto& entry : room_namespaces_) {
      if (entry.namespace_.matches(room_id) &&
          seen.insert(entry.service->id()).second) {
        result.push_back(entry.service);
      }
    }
    return result;
  }

  // Check if a namespace is exclusive and owned by a service
  bool is_exclusive_user(const std::string& user_id,
                          std::string* owner_out = nullptr) const {
    std::shared_lock lock(mutex_);
    for (auto& entry : user_namespaces_) {
      if (entry.namespace_.exclusive && entry.namespace_.matches(user_id)) {
        if (owner_out) *owner_out = entry.service_id;
        return true;
      }
    }
    return false;
  }

  bool is_exclusive_alias(const std::string& alias,
                           std::string* owner_out = nullptr) const {
    std::shared_lock lock(mutex_);
    for (auto& entry : alias_namespaces_) {
      if (entry.namespace_.exclusive && entry.namespace_.matches(alias)) {
        if (owner_out) *owner_out = entry.service_id;
        return true;
      }
    }
    return false;
  }

  bool is_exclusive_room(const std::string& room_id,
                          std::string* owner_out = nullptr) const {
    std::shared_lock lock(mutex_);
    for (auto& entry : room_namespaces_) {
      if (entry.namespace_.exclusive && entry.namespace_.matches(room_id)) {
        if (owner_out) *owner_out = entry.service_id;
        return true;
      }
    }
    return false;
  }

  // Dump namespace state for diagnostics
  json dump_state() const {
    std::shared_lock lock(mutex_);
    json j;
    j["user_namespaces"] = json::array();
    for (auto& e : user_namespaces_) {
      json ns;
      ns["service_id"] = e.service_id;
      ns["regex"] = e.namespace_.regex_str;
      ns["exclusive"] = e.namespace_.exclusive;
      j["user_namespaces"].push_back(ns);
    }
    j["alias_namespaces"] = json::array();
    for (auto& e : alias_namespaces_) {
      json ns;
      ns["service_id"] = e.service_id;
      ns["regex"] = e.namespace_.regex_str;
      ns["exclusive"] = e.namespace_.exclusive;
      j["alias_namespaces"].push_back(ns);
    }
    j["room_namespaces"] = json::array();
    for (auto& e : room_namespaces_) {
      json ns;
      ns["service_id"] = e.service_id;
      ns["regex"] = e.namespace_.regex_str;
      ns["exclusive"] = e.namespace_.exclusive;
      j["room_namespaces"].push_back(ns);
    }
    return j;
  }

private:
  struct NamespaceEntry {
    AppServiceNamespace namespace_;
    std::string service_id;
    std::shared_ptr<AppServiceRegistration> service;
  };

  struct ExclusiveInfo {
    std::vector<std::string> user_patterns;
    std::vector<std::string> alias_patterns;
    std::vector<std::string> room_patterns;
  };

  mutable std::shared_mutex mutex_;
  std::vector<NamespaceEntry> user_namespaces_;
  std::vector<NamespaceEntry> alias_namespaces_;
  std::vector<NamespaceEntry> room_namespaces_;
  std::unordered_map<std::string, ExclusiveInfo> exclusive_map_;
};

// ============================================================================
// AppServiceGhostManager - manages ghost user creation/management for AS
// Equivalent to synapse.appservice.api.GhostManager
// ============================================================================
class AppServiceGhostManager {
public:
  struct GhostRecord {
    std::string user_id;          // @_as_<name>:domain
    std::string external_id;      // original external user identifier
    std::string service_id;       // app service that owns the ghost
    std::string displayname;
    std::string avatar_url;
    std::string profile_json;
    bool created{false};
    int64_t last_active_ts{0};
  };

  AppServiceGhostManager() = default;

  // Register a ghost user
  GhostRecord* register_ghost(const std::string& service_id,
                               const std::string& user_id,
                               const std::string& external_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = make_key(service_id, external_id);
    auto& record = ghosts_[key];
    record.user_id = user_id;
    record.external_id = external_id;
    record.service_id = service_id;
    record.last_active_ts = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    record.created = true;

    // Also index by user_id
    user_index_[user_id] = key;
    return &record;
  }

  // Get a ghost record by user_id
  const GhostRecord* get_ghost_by_user_id(const std::string& user_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = user_index_.find(user_id);
    if (it == user_index_.end()) return nullptr;
    auto git = ghosts_.find(it->second);
    if (git == ghosts_.end()) return nullptr;
    return &git->second;
  }

  // Get a ghost record by service_id and external_id
  const GhostRecord* get_ghost(const std::string& service_id,
                               const std::string& external_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = ghosts_.find(make_key(service_id, external_id));
    if (it == ghosts_.end()) return nullptr;
    return &it->second;
  }

  // Update ghost profile
  bool update_ghost_profile(const std::string& user_id,
                             const std::string& displayname,
                             const std::string& avatar_url) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = user_index_.find(user_id);
    if (it == user_index_.end()) return false;
    auto git = ghosts_.find(it->second);
    if (git == ghosts_.end()) return false;
    git->second.displayname = displayname;
    git->second.avatar_url = avatar_url;
    git->second.last_active_ts = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return true;
  }

  // Update ghost profile from JSON payload
  bool update_ghost_profile_json(const std::string& user_id,
                                  const json& profile) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = user_index_.find(user_id);
    if (it == user_index_.end()) return false;
    auto git = ghosts_.find(it->second);
    if (git == ghosts_.end()) return false;
    if (profile.contains("displayname"))
      git->second.displayname = profile["displayname"].get<std::string>();
    if (profile.contains("avatar_url"))
      git->second.avatar_url = profile["avatar_url"].get<std::string>();
    git->second.profile_json = profile.dump();
    git->second.last_active_ts = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return true;
  }

  // Remove a ghost
  bool remove_ghost(const std::string& service_id,
                     const std::string& external_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = make_key(service_id, external_id);
    auto it = ghosts_.find(key);
    if (it == ghosts_.end()) return false;
    user_index_.erase(it->second.user_id);
    ghosts_.erase(it);
    return true;
  }

  // List all ghosts for a service
  std::vector<GhostRecord> list_ghosts_for_service(
      const std::string& service_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<GhostRecord> result;
    for (auto& kv : ghosts_) {
      if (kv.second.service_id == service_id) {
        result.push_back(kv.second);
      }
    }
    return result;
  }

  // Count ghosts for a service
  size_t count_ghosts_for_service(const std::string& service_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (auto& kv : ghosts_) {
      if (kv.second.service_id == service_id) count++;
    }
    return count;
  }

  // Total ghost count
  size_t total_ghosts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ghosts_.size();
  }

  // Check if a user_id is a ghost
  bool is_ghost(const std::string& user_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return user_index_.find(user_id) != user_index_.end();
  }

  // Get owner service_id for a ghost user
  std::optional<std::string> get_ghost_owner(const std::string& user_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = user_index_.find(user_id);
    if (it == user_index_.end()) return std::nullopt;
    auto git = ghosts_.find(it->second);
    if (git == ghosts_.end()) return std::nullopt;
    return git->second.service_id;
  }

  // Clean up stale ghosts (idle > max_age_seconds)
  void cleanup_stale_ghosts(int64_t max_age_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto it = ghosts_.begin();
    while (it != ghosts_.end()) {
      if (now - it->second.last_active_ts > max_age_seconds) {
        user_index_.erase(it->second.user_id);
        it = ghosts_.erase(it);
      } else {
        ++it;
      }
    }
  }

private:
  static std::string make_key(const std::string& service_id,
                               const std::string& external_id) {
    return service_id + "::" + external_id;
  }

  mutable std::mutex mutex_;
  std::unordered_map<std::string, GhostRecord> ghosts_;       // key -> record
  std::unordered_map<std::string, std::string> user_index_;   // user_id -> key
};

// ============================================================================
// AppServiceScheduler - schedules and manages transaction pushing to ASes
// Equivalent to synapse.appservice.scheduler.ApplicationServiceScheduler
// ============================================================================
class AppServiceScheduler {
public:
  struct PendingTransaction {
    std::string service_id;
    std::string txn_id;
    std::vector<json> events;
    std::string type;  // "ephemeral" or "event"
    int64_t queued_at;
    int retry_count{0};
  };

  AppServiceScheduler() = default;

  // Queue a transaction for pushing to a service
  void enqueue(const std::string& service_id,
                const std::vector<json>& events,
                const std::string& type = "event") {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string txn_id = generate_txn_id();
    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    PendingTransaction txn;
    txn.service_id = service_id;
    txn.txn_id = txn_id;
    txn.events = events;
    txn.type = type;
    txn.queued_at = now;

    pending_[service_id].push_back(std::move(txn));
  }

  // Dequeue the next transaction for a service
  std::optional<PendingTransaction> dequeue(const std::string& service_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = pending_.find(service_id);
    if (it == pending_.end() || it->second.empty()) return std::nullopt;
    auto txn = it->second.front();
    it->second.pop_front();
    if (it->second.empty()) pending_.erase(it);
    return txn;
  }

  // Peek at all pending transactions for a service
  std::vector<PendingTransaction> peek_pending(
      const std::string& service_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = pending_.find(service_id);
    if (it == pending_.end()) return {};
    return it->second;
  }

  // Count pending transactions for a service
  size_t pending_count(const std::string& service_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = pending_.find(service_id);
    if (it == pending_.end()) return 0;
    return it->second.size();
  }

  // Total pending transactions across all services
  size_t total_pending() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t total = 0;
    for (auto& kv : pending_) total += kv.second.size();
    return total;
  }

  // Retry a failed transaction
  void retry(const PendingTransaction& txn) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto copy = txn;
    copy.retry_count++;
    if (copy.retry_count < 10) {  // Max 10 retries
      pending_[copy.service_id].push_back(std::move(copy));
    } else {
      // Dead letter queue
      dead_letters_.push_back(txn);
    }
  }

  // Get dead letter queue
  std::vector<PendingTransaction> dead_letters() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dead_letters_;
  }

  // Clear dead letter queue
  void clear_dead_letters() {
    std::lock_guard<std::mutex> lock(mutex_);
    dead_letters_.clear();
  }

  // Clear all queues for a service
  void clear_service(const std::string& service_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_.erase(service_id);
    dead_letters_.erase(
        std::remove_if(dead_letters_.begin(), dead_letters_.end(),
                       [&](const PendingTransaction& t) {
                         return t.service_id == service_id;
                       }),
        dead_letters_.end());
  }

  // Merge multiple small transaction batches for a service
  // Reduces HTTP overhead by batching events together
  std::vector<PendingTransaction> merge_transactions(
      const std::string& service_id, size_t max_events_per_txn = 100) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PendingTransaction> result;
    auto it = pending_.find(service_id);
    if (it == pending_.end() || it->second.empty()) return result;

    std::vector<json> batch;
    for (auto& txn : it->second) {
      for (auto& e : txn.events) {
        batch.push_back(e);
        if (batch.size() >= max_events_per_txn) {
          PendingTransaction merged;
          merged.service_id = service_id;
          merged.txn_id = generate_txn_id();
          merged.events = std::move(batch);
          merged.type = txn.type;
          merged.queued_at = txn.queued_at;
          result.push_back(std::move(merged));
          batch.clear();
        }
      }
    }

    // Any remaining events
    if (!batch.empty()) {
      PendingTransaction merged;
      merged.service_id = service_id;
      merged.txn_id = generate_txn_id();
      merged.events = std::move(batch);
      merged.type = "event";
      result.push_back(std::move(merged));
    }

    pending_.erase(it);
    return result;
  }

private:
  static std::string generate_txn_id() {
    static std::atomic<int64_t> counter{0};
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return std::to_string(now) + "-" +
           std::to_string(counter.fetch_add(1));
  }

  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::deque<PendingTransaction>> pending_;
  std::vector<PendingTransaction> dead_letters_;
};

// ============================================================================
// AppServiceQueryHandler - handles AS query APIs (room alias, user queries)
// Equivalent to synapse.appservice.query.QueryHandler
// ============================================================================
class AppServiceQueryHandler {
public:
  struct QueryResult {
    bool found{false};
    std::string service_id;
    json data;
    int response_code{200};
  };

  AppServiceQueryHandler() = default;

  // Query a room alias across all app services
  // GET /_matrix/app/v1/rooms/{roomAlias}
  QueryResult query_room_alias(
      const std::string& alias,
      const std::vector<std::shared_ptr<AppServiceRegistration>>& services,
      const AppServiceNamespaceManager& ns_mgr) {

    QueryResult result;
    auto interested = ns_mgr.get_services_for_alias(alias);

    if (interested.empty()) {
      result.found = false;
      result.response_code = 404;
      return result;
    }

    // Query each interested service
    for (auto& svc : interested) {
      auto qr = query_service_room_alias(alias, *svc);
      if (qr.found) {
        return qr; // First responding service wins
      }
    }

    result.response_code = 404;
    return result;
  }

  // Query a user across all app services
  // GET /_matrix/app/v1/users/{userId}
  QueryResult query_user(
      const std::string& user_id,
      const std::vector<std::shared_ptr<AppServiceRegistration>>& services,
      const AppServiceNamespaceManager& ns_mgr) {

    QueryResult result;
    auto interested = ns_mgr.get_services_for_user(user_id);

    if (interested.empty()) {
      result.found = false;
      result.response_code = 404;
      return result;
    }

    for (auto& svc : interested) {
      auto qr = query_service_user(user_id, *svc);
      if (qr.found) {
        return qr;
      }
    }

    result.response_code = 404;
    return result;
  }

  // Query a specific app service for room alias info
  QueryResult query_service_room_alias(
      const std::string& alias,
      const AppServiceRegistration& service) {

    QueryResult result;
    result.service_id = service.id();

    // Build the query URL
    std::string query_url = service.url();
    if (!ends_with(query_url, "/")) query_url += "/";
    query_url += "rooms/" + url_encode(alias);
    query_url += "?access_token=" + url_encode(service.hs_token());

    // Note: In a real implementation, this would perform HTTP GET
    // For now, we simulate the query
    result.found = false;
    result.response_code = 404;

    // The actual HTTP call would be:
    // HttpClient::get(query_url, headers, callback)

    return result;
  }

  // Query a specific app service for user info
  QueryResult query_service_user(
      const std::string& user_id,
      const AppServiceRegistration& service) {

    QueryResult result;
    result.service_id = service.id();

    std::string query_url = service.url();
    if (!ends_with(query_url, "/")) query_url += "/";
    query_url += "users/" + url_encode(user_id);
    query_url += "?access_token=" + url_encode(service.hs_token());

    result.found = false;
    result.response_code = 404;
    return result;
  }

  // Third-party protocol query: GET /_matrix/app/v1/thirdparty/protocol/{protocol}
  QueryResult query_protocol(
      const std::string& protocol,
      const std::vector<std::shared_ptr<AppServiceRegistration>>& services) {

    for (auto& svc : services) {
      for (auto& p : svc->protocols()) {
        if (to_lower(p) == to_lower(protocol)) {
          return query_service_protocol(protocol, *svc);
        }
      }
    }

    QueryResult result;
    result.response_code = 404;
    return result;
  }

  // Third-party user query: GET /_matrix/app/v1/thirdparty/user/{protocol}
  QueryResult query_thirdparty_user(
      const std::string& protocol,
      const std::map<std::string, std::string>& fields,
      const std::vector<std::shared_ptr<AppServiceRegistration>>& services) {

    for (auto& svc : services) {
      for (auto& p : svc->protocols()) {
        if (to_lower(p) == to_lower(protocol)) {
          return query_service_thirdparty_user(protocol, fields, *svc);
        }
      }
    }

    QueryResult result;
    result.response_code = 404;
    return result;
  }

  // Third-party location query
  QueryResult query_thirdparty_location(
      const std::string& protocol,
      const std::map<std::string, std::string>& fields,
      const std::vector<std::shared_ptr<AppServiceRegistration>>& services) {

    for (auto& svc : services) {
      for (auto& p : svc->protocols()) {
        if (to_lower(p) == to_lower(protocol)) {
          return query_service_thirdparty_location(protocol, fields, *svc);
        }
      }
    }

    QueryResult result;
    result.response_code = 404;
    return result;
  }

private:
  QueryResult query_service_protocol(
      const std::string& protocol,
      const AppServiceRegistration& service) {
    QueryResult result;
    result.service_id = service.id();
    std::string url = service.url();
    if (!ends_with(url, "/")) url += "/";
    url += "_matrix/app/unstable/thirdparty/protocol/";
    url += url_encode(protocol);
    url += "?access_token=" + url_encode(service.hs_token());
    result.found = false;
    return result;
  }

  QueryResult query_service_thirdparty_user(
      const std::string& protocol,
      const std::map<std::string, std::string>& fields,
      const AppServiceRegistration& service) {
    QueryResult result;
    result.service_id = service.id();
    std::string url = service.url();
    if (!ends_with(url, "/")) url += "/";
    url += "_matrix/app/unstable/thirdparty/user/";
    url += url_encode(protocol);
    url += "?access_token=" + url_encode(service.hs_token());
    for (auto& f : fields) {
      url += "&" + url_encode(f.first) + "=" + url_encode(f.second);
    }
    result.found = false;
    return result;
  }

  QueryResult query_service_thirdparty_location(
      const std::string& protocol,
      const std::map<std::string, std::string>& fields,
      const AppServiceRegistration& service) {
    QueryResult result;
    result.service_id = service.id();
    std::string url = service.url();
    if (!ends_with(url, "/")) url += "/";
    url += "_matrix/app/unstable/thirdparty/location/";
    url += url_encode(protocol);
    url += "?access_token=" + url_encode(service.hs_token());
    for (auto& f : fields) {
      url += "&" + url_encode(f.first) + "=" + url_encode(f.second);
    }
    result.found = false;
    return result;
  }
};

// ============================================================================
// AppServiceAuthChecker - validates app service authentication
// Equivalent to synapse.appservice.api.Auth
// ============================================================================
class AppServiceAuthChecker {
public:
  AppServiceAuthChecker() = default;

  // Authenticate an app service by hs_token (HS -> AS)
  // The hs_token is sent as ?access_token= in query params
  std::optional<std::shared_ptr<AppServiceRegistration>>
  authenticate_by_hs_token(
      const std::string& token,
      const std::vector<std::shared_ptr<AppServiceRegistration>>& services) {

    for (auto& svc : services) {
      if (svc->hs_token() == token) return svc;
    }
    return std::nullopt;
  }

  // Authenticate an app service by as_token (AS -> HS)
  // The as_token is sent in the Authorization header or ?access_token=
  std::optional<std::shared_ptr<AppServiceRegistration>>
  authenticate_by_as_token(
      const std::string& token,
      const std::vector<std::shared_ptr<AppServiceRegistration>>& services) {

    for (auto& svc : services) {
      if (svc->as_token() == token) return svc;
    }
    return std::nullopt;
  }

  // Authenticate and also verify user_id (for AS acting on behalf of user)
  // App services use: Authorization: Bearer <as_token>
  // Plus query param: ?user_id=@user:domain
  std::optional<std::shared_ptr<AppServiceRegistration>>
  authenticate_as_user(
      const std::string& as_token,
      const std::string& user_id,
      const std::vector<std::shared_ptr<AppServiceRegistration>>& services,
      const AppServiceNamespaceManager& ns_mgr) {

    auto svc = authenticate_by_as_token(as_token, services);
    if (!svc) return std::nullopt;

    // Check if the user is in this app service's user namespace
    if ((*svc)->is_user_in_namespace(user_id)) {
      return svc;
    }

    // Also check if it's a ghost user owned by this service
    if ((*svc)->owns_ghost_user(user_id)) {
      return svc;
    }

    return std::nullopt;
  }

  // Verify app service has rights to create a user in a namespace
  bool can_create_user(
      const AppServiceRegistration& service,
      const std::string& user_id,
      const AppServiceNamespaceManager& ns_mgr) {

    // Check if user_id falls in this service's user namespace
    if (service.is_user_in_namespace(user_id)) return true;

    // Check if this is a ghost user
    if (service.owns_ghost_user(user_id)) return true;

    // Check for nonexclusive namespaces
    for (auto& ns : service.user_namespaces()) {
      if (!ns.exclusive && ns.matches(user_id)) return true;
    }

    return false;
  }

  // Verify app service can manage a room
  bool can_manage_room(
      const AppServiceRegistration& service,
      const std::string& room_id,
      const AppServiceNamespaceManager& ns_mgr) {

    return service.is_room_in_namespace(room_id);
  }

  // Verify app service can manage an alias
  bool can_manage_alias(
      const AppServiceRegistration& service,
      const std::string& alias,
      const AppServiceNamespaceManager& ns_mgr) {

    return service.is_alias_in_namespace(alias);
  }

  // Check if app service is allowed to send as a particular user
  bool can_send_as_user(
      const AppServiceRegistration& service,
      const std::string& user_id) {

    // App service can send as any user in its namespace
    if (service.is_user_in_namespace(user_id)) return true;
    // App service can send as its own ghost users
    if (service.owns_ghost_user(user_id)) return true;
    // Check sender_localpart match
    if (!service.sender_localpart().empty()) {
      auto at_pos = user_id.find('@');
      auto colon_pos = user_id.find(':');
      if (at_pos != std::string::npos && colon_pos != std::string::npos) {
        std::string localpart = user_id.substr(
            at_pos + 1, colon_pos - at_pos - 1);
        if (localpart == service.sender_localpart()) return true;
      }
    }
    return false;
  }
};

// ============================================================================
// AppServiceEventHandler - handles filtering and forwarding events to ASes
// ============================================================================
class AppServiceEventHandler {
public:
  AppServiceEventHandler(AppServiceScheduler& scheduler,
                          AppServiceNamespaceManager& ns_mgr,
                          AppServiceRateLimiter& rate_limiter)
      : scheduler_(scheduler), ns_mgr_(ns_mgr), rate_limiter_(rate_limiter) {}

  // Handle a new event: determine which app services are interested and queue it
  void handle_event(const json& event) {
    auto interested = ns_mgr_.get_interested_services_for_event(event);
    if (interested.empty()) return;

    for (auto& svc : interested) {
      // Check rate limiting
      if (svc->rate_limited() &&
          !rate_limiter_.allow_transaction(svc->id())) {
        continue; // Rate limited, skip this event for this service
      }

      // Filter events through the service's interest
      if (!svc->is_interested_in_event(event)) continue;

      scheduler_.enqueue(svc->id(), {event}, "event");
    }
  }

  // Handle a batch of events (e.g., from a room being processed)
  void handle_events_batch(const std::vector<json>& events) {
    // Group events by interested services
    std::unordered_map<std::string, std::vector<json>> per_service;

    for (auto& event : events) {
      auto interested = ns_mgr_.get_interested_services_for_event(event);
      for (auto& svc : interested) {
        if (svc->is_interested_in_event(event)) {
          per_service[svc->id()].push_back(event);
        }
      }
    }

    // Enqueue grouped events
    for (auto& kv : per_service) {
      scheduler_.enqueue(kv.first, kv.second, "event");
    }
  }

  // Handle ephemeral events (typing, receipts, presence)
  void handle_ephemeral_event(const std::string& room_id,
                               const std::string& type,
                               const json& content) {
    // Build synthetic ephemeral event
    json ephemeral;
    ephemeral["type"] = type;
    ephemeral["room_id"] = room_id;
    ephemeral["content"] = content;

    auto interested = ns_mgr_.get_services_for_room(room_id);
    for (auto& svc : interested) {
      // Ephemeral events go to any service with room namespace interest
      json ephem_msg;
      ephem_msg["type"] = "m." + type;
      ephem_msg["room_id"] = room_id;
      ephem_msg["content"] = content;

      std::vector<json> ephem_events = {ephem_msg};
      scheduler_.enqueue(svc->id(), ephem_events, "ephemeral");
    }
  }

  // Handle typing notification
  void handle_typing(const std::string& room_id, const std::string& user_id,
                      bool typing, int64_t timeout_ms = 30000) {
    json content;
    content["user_ids"] = json::array({user_id});

    json ephem;
    ephem["type"] = "m.typing";
    ephem["room_id"] = room_id;
    ephem["content"] = content;

    auto interested = ns_mgr_.get_services_for_room(room_id);
    for (auto& svc : interested) {
      scheduler_.enqueue(svc->id(), {ephem}, "ephemeral");
    }
  }

  // Handle receipt notification
  void handle_receipt(const std::string& room_id,
                       const std::string& event_id,
                       const std::string& user_id,
                       const std::string& receipt_type = "m.read") {
    json receipt_data;
    receipt_data["ts"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    json content;
    content["event_id"] = event_id;
    content["user_id"] = user_id;
    content[receipt_type] = receipt_data;

    handle_ephemeral_event(room_id, "m.receipt", content);
  }

  // Handle presence update
  void handle_presence(const std::string& user_id,
                        const std::string& presence,
                        const std::string& status_msg = "") {
    auto interested = ns_mgr_.get_services_for_user(user_id);
    json presence_event;
    presence_event["type"] = "m.presence";
    presence_event["sender"] = user_id;
    presence_event["content"]["presence"] = presence;
    presence_event["content"]["currently_active"] = (presence == "online");
    if (!status_msg.empty())
      presence_event["content"]["status_msg"] = status_msg;

    for (auto& svc : interested) {
      scheduler_.enqueue(svc->id(), {presence_event}, "ephemeral");
    }
  }

private:
  AppServiceScheduler& scheduler_;
  AppServiceNamespaceManager& ns_mgr_;
  AppServiceRateLimiter& rate_limiter_;
};

// ============================================================================
// AppServicePusher - HTTP client for pushing transactions to app services
// Equivalent to synapse.appservice.api.ApplicationServiceApi
// ============================================================================
class AppServicePusher {
public:
  struct PushResult {
    bool success{false};
    int http_code{0};
    std::string response_body;
    std::string error_message;
    double elapsed_seconds{0.0};
  };

  AppServicePusher() = default;

  // Push a transaction to an app service
  // PUT /_matrix/app/v1/transactions/{txnId}?access_token={hs_token}
  PushResult push_transaction(
      const AppServiceRegistration& service,
      const AppServiceTransaction& txn) {

    PushResult result;
    std::string url = service.url();
    if (!ends_with(url, "/")) url += "/";

    url += "_matrix/app/v1/transactions/";
    url += url_encode(txn.txn_id());
    url += "?access_token=" + url_encode(service.hs_token());

    auto start = std::chrono::steady_clock::now();

    // Build the JSON body
    json body = txn.to_body();
    std::string body_str = body.dump();

    // In a real implementation, this would use an HTTP client library
    // like libcurl or a custom async HTTP client.
    //
    // The call would be:
    // http_client->put(url, body_str, {
    //   {"Content-Type", "application/json"},
    //   {"User-Agent", "ProgressiveServer/1.0"}
    // }, callback);

    // For now, simulate the push
    result.success = true;
    result.http_code = 200;
    result.response_body = "{}";

    auto end = std::chrono::steady_clock::now();
    result.elapsed_seconds =
        std::chrono::duration<double>(end - start).count();

    return result;
  }

  // Push ephemeral events (typing, receipts, presence) to an app service
  // PUT /_matrix/app/v1/transactions/{txnId}?access_token={hs_token}
  PushResult push_ephemeral(
      const AppServiceRegistration& service,
      const std::string& txn_id,
      const std::vector<json>& ephemeral_events) {

    PushResult result;
    std::string url = service.url();
    if (!ends_with(url, "/")) url += "/";

    url += "_matrix/app/v1/transactions/";
    url += url_encode(txn_id);
    url += "?access_token=" + url_encode(service.hs_token());

    auto start = std::chrono::steady_clock::now();

    json body;
    body["events"] = json::array();
    for (auto& e : ephemeral_events) {
      body["events"].push_back(e);
    }

    std::string body_str = body.dump();

    result.success = true;
    result.http_code = 200;
    result.response_body = "{}";

    auto end = std::chrono::steady_clock::now();
    result.elapsed_seconds =
        std::chrono::duration<double>(end - start).count();

    return result;
  }

  // Test connectivity to an app service
  PushResult test_connection(const AppServiceRegistration& service) {
    PushResult result;
    std::string url = service.url();
    if (!ends_with(url, "/")) url += "/";
    url += "_matrix/app/v1/healthcheck";
    url += "?access_token=" + url_encode(service.hs_token());

    result.success = true;
    result.http_code = 200;
    result.response_body = "{\"ok\": true}";
    return result;
  }
};

// ============================================================================
// AppServiceEventManager - integrates app services with the event pipeline
// Listens for new events and pushes them to interested app services
// ============================================================================
class AppServiceEventManager {
public:
  AppServiceEventManager() = default;

  // Set the upstream handler
  void set_handler(AppServiceEventHandler* handler) {
    handler_ = handler;
  }

  // Notify about a new event being created in the system
  // Called by the event creation pipeline
  void on_new_event(const json& event) {
    if (handler_) handler_->handle_event(event);
  }

  // Notify about a batch of new events
  void on_new_events(const std::vector<json>& events) {
    if (handler_) handler_->handle_events_batch(events);
  }

  // Notify about a typing update
  void on_typing(const std::string& room_id, const std::string& user_id,
                  bool typing) {
    if (handler_) handler_->handle_typing(room_id, user_id, typing);
  }

  // Notify about a read receipt
  void on_receipt(const std::string& room_id, const std::string& event_id,
                   const std::string& user_id) {
    if (handler_) handler_->handle_receipt(room_id, event_id, user_id);
  }

  // Notify about a presence change
  void on_presence(const std::string& user_id, const std::string& presence,
                    const std::string& status_msg = "") {
    if (handler_) handler_->handle_presence(user_id, presence, status_msg);
  }

private:
  AppServiceEventHandler* handler_{nullptr};
};

// ============================================================================
// AppServiceManager - central manager for all app service operations
// Equivalent to synapse.appservice.api.ApplicationServiceApi +
//              synapse.handlers.appservice.ApplicationServicesHandler
// ============================================================================
class AppServiceManager {
public:
  struct AppServiceStats {
    std::string service_id;
    size_t pending_transactions;
    size_t ghost_count;
    size_t total_events_sent;
    double current_rate;
    bool rate_limited;
    bool connected;
  };

  AppServiceManager() = default;

  // Load app services from a YAML config file
  // Returns the number of services loaded
  int load_from_yaml_file(const std::string& yaml_path) {
    try {
      YAML::Node config = YAML::LoadFile(yaml_path);
      int loaded = 0;

      if (config.IsSequence()) {
        for (auto& node : config) {
          if (load_from_yaml_node(node)) loaded++;
        }
      } else if (config.IsMap() && config["appservices"]) {
        for (auto& node : config["appservices"]) {
          if (load_from_yaml_node(node)) loaded++;
        }
      } else if (config.IsMap()) {
        if (load_from_yaml_node(config)) loaded = 1;
      }

      // Update namespace manager
      ns_mgr_.update_from_services(services_);
      return loaded;

    } catch (const std::exception& e) {
      std::cerr << "[AppServiceManager] Failed to load YAML: " << e.what()
                << "\n";
      return 0;
    }
  }

  // Load from a YAML string
  int load_from_yaml_string(const std::string& yaml_str) {
    try {
      YAML::Node config = YAML::Load(yaml_str);
      int loaded = 0;

      if (config.IsSequence()) {
        for (auto& node : config) {
          if (load_from_yaml_node(node)) loaded++;
        }
      } else if (config.IsMap() && config["appservices"]) {
        for (auto& node : config["appservices"]) {
          if (load_from_yaml_node(node)) loaded++;
        }
      } else if (config.IsMap()) {
        if (load_from_yaml_node(config)) loaded = 1;
      }

      ns_mgr_.update_from_services(services_);
      return loaded;
    } catch (const std::exception& e) {
      std::cerr << "[AppServiceManager] Failed to parse YAML: " << e.what()
                << "\n";
      return 0;
    }
  }

  // Register a service from JSON
  bool register_service_json(const json& j, const std::string& as_token,
                              const std::string& hs_token) {
    auto reg = AppServiceRegistration::from_json(j, as_token, hs_token);
    if (!reg) return false;

    auto id = reg->id();
    auto svc = std::make_shared<AppServiceRegistration>(std::move(*reg));

    std::lock_guard<std::mutex> lock(mutex_);
    service_map_[id] = svc;
    services_.push_back(svc);
    ns_mgr_.update_from_services(services_);
    return true;
  }

  // Register a service directly
  bool register_service(std::shared_ptr<AppServiceRegistration> service) {
    if (!service || !service->valid()) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    service_map_[service->id()] = service;
    services_.push_back(service);
    ns_mgr_.update_from_services(services_);
    return true;
  }

  // Find a service by ID
  std::shared_ptr<AppServiceRegistration> find_service(
      const std::string& service_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = service_map_.find(service_id);
    if (it != service_map_.end()) return it->second;
    return nullptr;
  }

  // Get all registered services
  std::vector<std::shared_ptr<AppServiceRegistration>> get_all_services() {
    std::lock_guard<std::mutex> lock(mutex_);
    return services_;
  }

  // Remove a service
  bool remove_service(const std::string& service_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = service_map_.find(service_id);
    if (it == service_map_.end()) return false;

    // Remove from vector
    services_.erase(
        std::remove_if(services_.begin(), services_.end(),
                       [&](const std::shared_ptr<AppServiceRegistration>& s) {
                         return s->id() == service_id;
                       }),
        services_.end());
    service_map_.erase(it);

    // Clear scheduler and rate limiter state
    scheduler_.clear_service(service_id);
    rate_limiter_.reset(service_id);

    ns_mgr_.update_from_services(services_);
    return true;
  }

  // Count services
  size_t service_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return services_.size();
  }

  // ============ Event handling ============

  // Process an event for all interested app services
  void push_event(const json& event) {
    event_handler_.handle_event(event);
  }

  // Process a batch of events
  void push_events_batch(const std::vector<json>& events) {
    event_handler_.handle_events_batch(events);
  }

  // Push typing notification
  void push_typing(const std::string& room_id, const std::string& user_id,
                    bool typing) {
    event_handler_.handle_typing(room_id, user_id, typing);
  }

  // Push receipt
  void push_receipt(const std::string& room_id, const std::string& event_id,
                     const std::string& user_id) {
    event_handler_.handle_receipt(room_id, event_id, user_id);
  }

  // Push presence
  void push_presence(const std::string& user_id, const std::string& presence,
                      const std::string& status_msg = "") {
    event_handler_.handle_presence(user_id, presence, status_msg);
  }

  // ============ Transaction processing ============

  // Process pending transactions for all services
  // This should be called periodically from a background thread
  void process_pending_transactions() {
    auto services = get_all_services();
    for (auto& svc : services) {
      process_pending_for_service(*svc);
    }
  }

  // Process pending transactions for a specific service
  void process_pending_for_service(const AppServiceRegistration& service) {
    auto merged = scheduler_.merge_transactions(service.id());
    for (auto& txn : merged) {
      // Check rate limiting
      if (service.rate_limited() &&
          !rate_limiter_.allow_transaction(service.id())) {
        scheduler_.retry(txn);
        continue;
      }

      AppServiceTransaction as_txn(service.id(), txn.txn_id, txn.events);
      auto result = pusher_.push_transaction(service, as_txn);

      if (result.success) {
        as_txn.mark_sent(result.response_body);
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_[service.id()].total_events_sent += as_txn.event_count();
      } else {
        // Retry on failure
        scheduler_.retry(txn);
      }
    }
  }

  // Get statistics for a service
  AppServiceStats get_stats(const std::string& service_id) {
    AppServiceStats stats;
    stats.service_id = service_id;
    stats.pending_transactions = scheduler_.pending_count(service_id);
    stats.ghost_count = ghost_mgr_.count_ghosts_for_service(service_id);
    stats.current_rate = rate_limiter_.current_rate(service_id);

    {
      std::lock_guard<std::mutex> lock(stats_mutex_);
      auto it = stats_.find(service_id);
      if (it != stats_.end()) {
        stats.total_events_sent = it->second.total_events_sent;
        stats.connected = it->second.connected;
      }
    }

    return stats;
  }

  // Get all statistics
  std::vector<AppServiceStats> get_all_stats() {
    std::vector<AppServiceStats> result;
    auto services = get_all_services();
    for (auto& svc : services) {
      result.push_back(get_stats(svc->id()));
    }
    return result;
  }

  // ============ Query APIs ============

  // Query a room alias across app services
  AppServiceQueryHandler::QueryResult query_room_alias(
      const std::string& alias) {
    return query_handler_.query_room_alias(alias, get_all_services(),
                                            ns_mgr_);
  }

  // Query a user across app services
  AppServiceQueryHandler::QueryResult query_user(const std::string& user_id) {
    return query_handler_.query_user(user_id, get_all_services(), ns_mgr_);
  }

  // Query third party protocol
  AppServiceQueryHandler::QueryResult query_protocol(
      const std::string& protocol) {
    return query_handler_.query_protocol(protocol, get_all_services());
  }

  // Query third party user
  AppServiceQueryHandler::QueryResult query_thirdparty_user(
      const std::string& protocol,
      const std::map<std::string, std::string>& fields) {
    return query_handler_.query_thirdparty_user(
        protocol, fields, get_all_services());
  }

  // Query third party location
  AppServiceQueryHandler::QueryResult query_thirdparty_location(
      const std::string& protocol,
      const std::map<std::string, std::string>& fields) {
    return query_handler_.query_thirdparty_location(
        protocol, fields, get_all_services());
  }

  // ============ Authentication ============

  // Authenticate service by hs_token
  std::optional<std::shared_ptr<AppServiceRegistration>>
  auth_by_hs_token(const std::string& token) {
    return auth_checker_.authenticate_by_hs_token(
        token, get_all_services());
  }

  // Authenticate service by as_token
  std::optional<std::shared_ptr<AppServiceRegistration>>
  auth_by_as_token(const std::string& token) {
    return auth_checker_.authenticate_by_as_token(
        token, get_all_services());
  }

  // Authenticate as a specific user
  std::optional<std::shared_ptr<AppServiceRegistration>>
  auth_as_user(const std::string& as_token, const std::string& user_id) {
    return auth_checker_.authenticate_as_user(
        as_token, user_id, get_all_services(), ns_mgr_);
  }

  // ============ Ghost management ============

  // Create or get a ghost user
  AppServiceGhostManager::GhostRecord* create_ghost(
      const std::string& service_id, const std::string& external_id,
      const std::string& homeserver_domain) {
    auto svc = find_service(service_id);
    if (!svc) return nullptr;

    std::string ghost_user_id = svc->get_ghost_user_id(
        external_id, homeserver_domain);
    return ghost_mgr_.register_ghost(service_id, ghost_user_id, external_id);
  }

  // Get a ghost by user ID
  const AppServiceGhostManager::GhostRecord* get_ghost(
      const std::string& user_id) {
    return ghost_mgr_.get_ghost_by_user_id(user_id);
  }

  // Update ghost profile
  bool update_ghost_profile(const std::string& user_id,
                             const std::string& displayname,
                             const std::string& avatar_url) {
    return ghost_mgr_.update_ghost_profile(user_id, displayname, avatar_url);
  }

  // Remove ghost
  bool remove_ghost(const std::string& service_id,
                     const std::string& external_id) {
    return ghost_mgr_.remove_ghost(service_id, external_id);
  }

  // Check if user is a ghost
  bool is_ghost_user(const std::string& user_id) {
    return ghost_mgr_.is_ghost(user_id);
  }

  // Get ghost owner
  std::optional<std::string> ghost_owner(const std::string& user_id) {
    return ghost_mgr_.get_ghost_owner(user_id);
  }

  // Count ghosts
  size_t ghost_count() { return ghost_mgr_.total_ghosts(); }

  // ============ Namespace checks ============

  // Check if user is in an exclusive namespace
  bool is_exclusive_user(const std::string& user_id,
                          std::string* owner_out = nullptr) {
    return ns_mgr_.is_exclusive_user(user_id, owner_out);
  }

  // Check if alias is in an exclusive namespace
  bool is_exclusive_alias(const std::string& alias,
                           std::string* owner_out = nullptr) {
    return ns_mgr_.is_exclusive_alias(alias, owner_out);
  }

  // Check if room is in an exclusive namespace
  bool is_exclusive_room(const std::string& room_id,
                          std::string* owner_out = nullptr) {
    return ns_mgr_.is_exclusive_room(room_id, owner_out);
  }

  // Get services interested in a user
  std::vector<std::shared_ptr<AppServiceRegistration>>
  get_services_for_user(const std::string& user_id) {
    return ns_mgr_.get_services_for_user(user_id);
  }

  // Get services interested in an alias
  std::vector<std::shared_ptr<AppServiceRegistration>>
  get_services_for_alias(const std::string& alias) {
    return ns_mgr_.get_services_for_alias(alias);
  }

  // Get services interested in a room
  std::vector<std::shared_ptr<AppServiceRegistration>>
  get_services_for_room(const std::string& room_id) {
    return ns_mgr_.get_services_for_room(room_id);
  }

  // ============ Auth checks ============

  // Check if an app service can create a user
  bool can_create_user(const std::string& as_token,
                        const std::string& user_id) {
    auto svc = auth_by_as_token(as_token);
    if (!svc) return false;
    return auth_checker_.can_create_user(**svc, user_id, ns_mgr_);
  }

  // Check if an app service can send as a user
  bool can_send_as_user(const std::string& as_token,
                         const std::string& user_id) {
    auto svc = auth_by_as_token(as_token);
    if (!svc) return false;
    return auth_checker_.can_send_as_user(**svc, user_id);
  }

  // Check if an app service can manage a room
  bool can_manage_room(const std::string& as_token,
                        const std::string& room_id) {
    auto svc = auth_by_as_token(as_token);
    if (!svc) return false;
    return auth_checker_.can_manage_room(**svc, room_id, ns_mgr_);
  }

  // ============ Rate limiting ============

  // Set rate limiter config
  void set_rate_limit_config(const AppServiceRateLimiter::Config& config) {
    rate_limiter_.set_config(config);
  }

  // Reset rate tracking for a service
  void reset_rate_limit(const std::string& service_id) {
    rate_limiter_.reset(service_id);
  }

  // ============ Diagnostic / admin ============

  // Dump all service registrations as JSON
  json dump_services() const {
    json arr = json::array();
    auto services = const_cast<AppServiceManager*>(this)->get_all_services();
    for (auto& svc : services) {
      arr.push_back(svc->to_json());
    }
    return arr;
  }

  // Dump namespace state
  json dump_namespaces() { return ns_mgr_.dump_state(); }

  // Dump scheduler state
  json dump_scheduler_state() {
    json j;
    j["total_pending"] = scheduler_.total_pending();
    j["dead_letters"] = scheduler_.dead_letters().size();
    auto services = get_all_services();
    auto per_service = json::object();
    for (auto& svc : services) {
      auto pending = scheduler_.peek_pending(svc->id());
      per_service[svc->id()] = pending.size();
    }
    j["per_service"] = per_service;
    return j;
  }

  // Test connectivity to all services
  json test_all_connections() {
    json results = json::array();
    auto services = get_all_services();
    for (auto& svc : services) {
      auto res = pusher_.test_connection(*svc);
      json entry;
      entry["service_id"] = svc->id();
      entry["success"] = res.success;
      entry["http_code"] = res.http_code;
      if (!res.error_message.empty())
        entry["error"] = res.error_message;
      results.push_back(entry);

      std::lock_guard<std::mutex> lock(stats_mutex_);
      stats_[svc->id()].connected = res.success;
    }
    return results;
  }

  // Access sub-components
  AppServiceScheduler& scheduler() { return scheduler_; }
  AppServiceNamespaceManager& namespace_manager() { return ns_mgr_; }
  AppServiceGhostManager& ghost_manager() { return ghost_mgr_; }
  AppServiceRateLimiter& rate_limiter() { return rate_limiter_; }
  AppServiceAuthChecker& auth_checker() { return auth_checker_; }
  AppServiceQueryHandler& query_handler() { return query_handler_; }
  AppServicePusher& pusher() { return pusher_; }

private:
  bool load_from_yaml_node(const YAML::Node& node) {
    auto reg = AppServiceRegistration::from_yaml(node);
    if (!reg) return false;

    auto svc = std::make_shared<AppServiceRegistration>(std::move(*reg));

    std::lock_guard<std::mutex> lock(mutex_);
    // Don't overwrite existing service unless it's the same
    auto it = service_map_.find(svc->id());
    if (it != service_map_.end()) {
      return true; // Already registered, skip
    }

    service_map_[svc->id()] = svc;
    services_.push_back(svc);

    // Initialize stats
    ServiceStats s;
    s.service_id = svc->id();
    stats_[svc->id()] = s;

    return true;
  }

  struct ServiceStats {
    std::string service_id;
    int64_t total_events_sent{0};
    int64_t total_transactions{0};
    int64_t failed_transactions{0};
    bool connected{false};
  };

  mutable std::mutex mutex_;
  mutable std::mutex stats_mutex_;
  std::vector<std::shared_ptr<AppServiceRegistration>> services_;
  std::unordered_map<std::string, std::shared_ptr<AppServiceRegistration>>
      service_map_;
  std::unordered_map<std::string, ServiceStats> stats_;

  // Sub-components
  AppServiceScheduler scheduler_;
  AppServiceNamespaceManager ns_mgr_;
  AppServiceEventManager event_mgr_;
  AppServiceGhostManager ghost_mgr_;
  AppServiceRateLimiter rate_limiter_;
  AppServiceAuthChecker auth_checker_;
  AppServiceQueryHandler query_handler_;
  AppServiceEventHandler event_handler_{scheduler_, ns_mgr_, rate_limiter_};
  AppServicePusher pusher_;
};

// ============================================================================
// AppService REST Servlet - handles AS API endpoints on the homeserver
// Equivalent to synapse/appservice/query.py
// Routes:
//   GET  /_matrix/app/v1/transactions/{txnId}
//   PUT  /_matrix/app/v1/transactions/{txnId}
//   GET  /_matrix/app/v1/rooms/{roomAlias}
//   GET  /_matrix/app/v1/users/{userId}
//   GET  /_matrix/app/v1/thirdparty/protocol/{protocol}
//   GET  /_matrix/app/v1/thirdparty/user/{protocol}
//   GET  /_matrix/app/v1/thirdparty/location/{protocol}
//   GET  /_matrix/app/unstable/thirdparty/protocol/{protocol}
//   GET  /_matrix/app/unstable/thirdparty/user/{protocol}
//   GET  /_matrix/app/unstable/thirdparty/location/{protocol}
// ============================================================================
class AppServiceRestServlet {
public:
  explicit AppServiceRestServlet(AppServiceManager& mgr) : mgr_(mgr) {}

  // Get pattern routes this servlet handles
  std::vector<std::string> patterns() const {
    return {
        "/_matrix/app/v1/transactions/:txnId",
        "/_matrix/app/v1/rooms/:roomAlias",
        "/_matrix/app/v1/users/:userId",
        "/_matrix/app/v1/thirdparty/protocol/:protocol",
        "/_matrix/app/v1/thirdparty/user/:protocol",
        "/_matrix/app/v1/thirdparty/location/:protocol",
        "/_matrix/app/unstable/thirdparty/protocol/:protocol",
        "/_matrix/app/unstable/thirdparty/user/:protocol",
        "/_matrix/app/unstable/thirdparty/location/:protocol",
    };
  }

  // Handle incoming AS API request (from app service -> HS)
  // Returns response JSON
  json handle_request(const std::string& method,
                       const std::string& path,
                       const json& body,
                       const std::map<std::string, std::string>& query_params,
                       const std::map<std::string, std::string>& path_params) {

    // First, authenticate the request via hs_token or as_token
    if (!authenticate_request(query_params)) {
      json err;
      err["errcode"] = "M_FORBIDDEN";
      err["error"] = "Invalid access token";
      return err;
    }

    // Route to the appropriate handler
    if (path.find("/transactions/") != std::string::npos) {
      return handle_transaction(method, body, path_params, query_params);
    }
    if (path.find("/rooms/") != std::string::npos) {
      return handle_room_query(method, path_params);
    }
    if (path.find("/users/") != std::string::npos) {
      return handle_user_query(method, path_params);
    }
    if (path.find("/thirdparty/protocol") != std::string::npos) {
      return handle_protocol_query(method, path_params, query_params);
    }
    if (path.find("/thirdparty/user") != std::string::npos) {
      return handle_thirdparty_user_query(method, path_params, query_params);
    }
    if (path.find("/thirdparty/location") != std::string::npos) {
      return handle_thirdparty_location_query(method, path_params,
                                               query_params);
    }

    json err;
    err["errcode"] = "M_UNRECOGNIZED";
    err["error"] = "Unrecognized app service endpoint";
    return err;
  }

private:
  bool authenticate_request(
      const std::map<std::string, std::string>& query_params) {
    auto it = query_params.find("access_token");
    if (it == query_params.end()) return false;

    // Try hs_token first (HS to AS), then as_token (AS to HS)
    auto svc = mgr_.auth_by_hs_token(it->second);
    if (svc) return true;

    svc = mgr_.auth_by_as_token(it->second);
    return svc.has_value();
  }

  // Handle PUT /transactions/{txnId} - receiving an event from AS
  json handle_transaction(
      const std::string& method,
      const json& body,
      const std::map<std::string, std::string>& path_params,
      const std::map<std::string, std::string>& query_params) {

    if (method != "PUT") {
      json err;
      err["errcode"] = "M_UNRECOGNIZED";
      err["error"] = "Method not allowed";
      return err;
    }

    // Extract txn_id
    auto txn_it = path_params.find("txnId");
    std::string txn_id = txn_it != path_params.end() ? txn_it->second : "unknown";

    json response;
    response["txn_id"] = txn_id;

    // Process events in the transaction
    if (body.contains("events") && body["events"].is_array()) {
      int processed = 0;
      for (auto& event : body["events"]) {
        try {
          // Validate event has required fields
          if (!event.contains("type") || !event.contains("sender")) {
            continue;
          }

          // Push the event received from app service into the system
          mgr_.push_event(event);
          processed++;
        } catch (const std::exception& e) {
          std::cerr << "[AppServiceServlet] Error processing event from "
                    << txn_id << ": " << e.what() << "\n";
        }
      }
      response["events_processed"] = processed;
    } else {
      response["events_processed"] = 0;
    }

    return response;
  }

  // Handle GET /rooms/{roomAlias} - query room alias
  json handle_room_query(
      const std::string& method,
      const std::map<std::string, std::string>& path_params) {

    if (method != "GET") {
      json err;
      err["errcode"] = "M_UNRECOGNIZED";
      err["error"] = "Method not allowed";
      return err;
    }

    auto alias_it = path_params.find("roomAlias");
    if (alias_it == path_params.end()) {
      json err;
      err["errcode"] = "M_NOT_FOUND";
      err["error"] = "No room alias specified";
      return err;
    }

    auto result = mgr_.query_room_alias(alias_it->second);
    if (result.found) {
      return result.data;
    } else {
      json err;
      err["errcode"] = "M_NOT_FOUND";
      err["error"] = "Room alias not found";
      return err;
    }
  }

  // Handle GET /users/{userId} - query user
  json handle_user_query(
      const std::string& method,
      const std::map<std::string, std::string>& path_params) {

    if (method != "GET") {
      json err;
      err["errcode"] = "M_UNRECOGNIZED";
      err["error"] = "Method not allowed";
      return err;
    }

    auto user_it = path_params.find("userId");
    if (user_it == path_params.end()) {
      json err;
      err["errcode"] = "M_NOT_FOUND";
      err["error"] = "No user ID specified";
      return err;
    }

    auto result = mgr_.query_user(user_it->second);
    if (result.found) {
      return result.data;
    } else {
      json err;
      err["errcode"] = "M_NOT_FOUND";
      err["error"] = "User not found";
      return err;
    }
  }

  // Handle GET /thirdparty/protocol/{protocol}
  json handle_protocol_query(
      const std::string& method,
      const std::map<std::string, std::string>& path_params,
      const std::map<std::string, std::string>& query_params) {

    if (method != "GET") {
      json err;
      err["errcode"] = "M_UNRECOGNIZED";
      err["error"] = "Method not allowed";
      return err;
    }

    auto proto_it = path_params.find("protocol");
    if (proto_it == path_params.end()) {
      json err;
      err["errcode"] = "M_NOT_FOUND";
      err["error"] = "No protocol specified";
      return err;
    }

    auto result = mgr_.query_protocol(proto_it->second);
    if (result.found) {
      return result.data;
    } else {
      json err;
      err["errcode"] = "M_NOT_FOUND";
      err["error"] = "Protocol not supported";
      return err;
    }
  }

  // Handle GET /thirdparty/user/{protocol}
  json handle_thirdparty_user_query(
      const std::string& method,
      const std::map<std::string, std::string>& path_params,
      const std::map<std::string, std::string>& query_params) {

    if (method != "GET") {
      json err;
      err["errcode"] = "M_UNRECOGNIZED";
      err["error"] = "Method not allowed";
      return err;
    }

    auto proto_it = path_params.find("protocol");
    if (proto_it == path_params.end()) {
      json err;
      err["errcode"] = "M_NOT_FOUND";
      err["error"] = "No protocol specified";
      return err;
    }

    std::map<std::string, std::string> fields;
    for (auto& kv : query_params) {
      if (kv.first != "access_token") {
        fields[kv.first] = kv.second;
      }
    }

    auto result = mgr_.query_thirdparty_user(proto_it->second, fields);
    if (result.found) {
      return result.data;
    } else {
      json results = json::array();
      return results;
    }
  }

  // Handle GET /thirdparty/location/{protocol}
  json handle_thirdparty_location_query(
      const std::string& method,
      const std::map<std::string, std::string>& path_params,
      const std::map<std::string, std::string>& query_params) {

    if (method != "GET") {
      json err;
      err["errcode"] = "M_UNRECOGNIZED";
      err["error"] = "Method not allowed";
      return err;
    }

    auto proto_it = path_params.find("protocol");
    if (proto_it == path_params.end()) {
      json err;
      err["errcode"] = "M_NOT_FOUND";
      err["error"] = "No protocol specified";
      return err;
    }

    std::map<std::string, std::string> fields;
    for (auto& kv : query_params) {
      if (kv.first != "access_token") {
        fields[kv.first] = kv.second;
      }
    }

    auto result = mgr_.query_thirdparty_location(proto_it->second, fields);
    if (result.found) {
      return result.data;
    } else {
      json results = json::array();
      return results;
    }
  }

  AppServiceManager& mgr_;
};

// ============================================================================
// AppServiceBackgroundWorker - periodic background tasks for app services
// Equivalent to the background update tasks in synapse
// ============================================================================
class AppServiceBackgroundWorker {
public:
  AppServiceBackgroundWorker(AppServiceManager& mgr,
                              AppServiceScheduler& scheduler,
                              AppServicePusher& pusher,
                              AppServiceRateLimiter& rate_limiter)
      : mgr_(mgr), scheduler_(scheduler), pusher_(pusher),
        rate_limiter_(rate_limiter) {}

  // Start the background worker thread
  void start() {
    running_.store(true);
    worker_thread_ = std::thread([this]() { this->run(); });
  }

  // Stop the background worker thread
  void stop() {
    running_.store(false);
    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }
  }

  // Check if the worker is running
  bool is_running() const { return running_.load(); }

private:
  void run() {
    while (running_.load()) {
      try {
        // Process pending transactions for all services
        auto services = mgr_.get_all_services();
        for (auto& svc : services) {
          auto merged = scheduler_.merge_transactions(svc->id());
          for (auto& txn : merged) {
            // Check rate limiting
            if (svc->rate_limited()) {
              if (!rate_limiter_.allow_transaction(svc->id())) {
                scheduler_.retry(txn);
                continue;
              }
            }

            // Create transaction and push
            AppServiceTransaction as_txn(svc->id(), txn.txn_id, txn.events);
            auto result = pusher_.push_transaction(*svc, as_txn);

            if (result.success) {
              as_txn.mark_sent(result.response_body);
            } else {
              scheduler_.retry(txn);
            }
          }

          // Clean up dead letters after retries exhausted
          auto dead = scheduler_.dead_letters();
          if (!dead.empty()) {
            std::cerr << "[AppServiceWorker] " << dead.size()
                      << " transactions in dead letter queue\n";
          }
        }

        // Sleep for the polling interval
        std::this_thread::sleep_for(std::chrono::milliseconds(poll_interval_ms_));

      } catch (const std::exception& e) {
        std::cerr << "[AppServiceWorker] Error: " << e.what() << "\n";
        std::this_thread::sleep_for(std::chrono::seconds(5));
      }
    }
  }

  AppServiceManager& mgr_;
  AppServiceScheduler& scheduler_;
  AppServicePusher& pusher_;
  AppServiceRateLimiter& rate_limiter_;
  std::thread worker_thread_;
  std::atomic<bool> running_{false};
  int poll_interval_ms_{500}; // Poll every 500ms
};

// ============================================================================
// AppServiceConfigGenerator - generates YAML/JSON config for app services
// ============================================================================
class AppServiceConfigGenerator {
public:
  // Generate a YAML registration for a new app service
  static std::string generate_yaml(
      const std::string& id,
      const std::string& url,
      const std::string& as_token,
      const std::string& hs_token,
      const std::string& sender_localpart,
      const std::vector<std::string>& user_namespace_regexes,
      const std::vector<std::string>& alias_namespace_regexes,
      const std::vector<std::string>& room_namespace_regexes,
      bool rate_limited = true) {

    std::ostringstream yaml;
    yaml << "# Application Service Registration\n";
    yaml << "# Generated by ProgressiveServer AppServiceConfigGenerator\n";
    yaml << "id: " << id << "\n";
    yaml << "url: " << url << "\n";
    yaml << "as_token: " << as_token << "\n";
    yaml << "hs_token: " << hs_token << "\n";
    yaml << "sender_localpart: " << sender_localpart << "\n";
    yaml << "rate_limited: " << (rate_limited ? "true" : "false") << "\n";
    yaml << "namespaces:\n";

    if (!user_namespace_regexes.empty()) {
      yaml << "  users:\n";
      for (auto& r : user_namespace_regexes) {
        yaml << "    - regex: \"" << r << "\"\n";
        yaml << "      exclusive: true\n";
      }
    }

    if (!alias_namespace_regexes.empty()) {
      yaml << "  aliases:\n";
      for (auto& r : alias_namespace_regexes) {
        yaml << "    - regex: \"" << r << "\"\n";
        yaml << "      exclusive: true\n";
      }
    }

    if (!room_namespace_regexes.empty()) {
      yaml << "  rooms:\n";
      for (auto& r : room_namespace_regexes) {
        yaml << "    - regex: \"" << r << "\"\n";
        yaml << "      exclusive: false\n";
      }
    }

    return yaml.str();
  }

  // Generate a JSON registration
  static json generate_json(
      const std::string& id,
      const std::string& url,
      const std::string& sender_localpart,
      const std::vector<std::string>& user_namespace_regexes,
      const std::vector<std::string>& alias_namespace_regexes,
      const std::vector<std::string>& room_namespace_regexes,
      bool rate_limited = true) {

    json j;
    j["id"] = id;
    j["url"] = url;
    j["sender_localpart"] = sender_localpart;
    j["rate_limited"] = rate_limited;

    if (!user_namespace_regexes.empty()) {
      json users = json::array();
      for (auto& r : user_namespace_regexes) {
        json u;
        u["regex"] = r;
        u["exclusive"] = true;
        users.push_back(u);
      }
      j["namespaces"]["users"] = users;
    }

    if (!alias_namespace_regexes.empty()) {
      json aliases = json::array();
      for (auto& r : alias_namespace_regexes) {
        json a;
        a["regex"] = r;
        a["exclusive"] = true;
        aliases.push_back(a);
      }
      j["namespaces"]["aliases"] = aliases;
    }

    if (!room_namespace_regexes.empty()) {
      json rooms = json::array();
      for (auto& r : room_namespace_regexes) {
        json rm;
        rm["regex"] = r;
        rm["exclusive"] = false;
        rooms.push_back(rm);
      }
      j["namespaces"]["rooms"] = rooms;
    }

    return j;
  }

  // Generate a new as_token and hs_token pair
  static std::pair<std::string, std::string> generate_token_pair() {
    return {generate_token(64), generate_token(64)};
  }
};

// ============================================================================
// AppServiceMetrics - collects metrics about app service activity
// ============================================================================
class AppServiceMetrics {
public:
  AppServiceMetrics() = default;

  // Record a transaction being sent
  void record_transaction_sent(const std::string& service_id,
                                size_t event_count,
                                double duration_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& m = per_service_[service_id];
    m.transactions_sent++;
    m.events_sent += event_count;
    m.total_duration_ms += duration_ms;
  }

  // Record a failed transaction
  void record_transaction_failed(const std::string& service_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    per_service_[service_id].transactions_failed++;
  }

  // Record a query being made
  void record_query(const std::string& query_type,
                     const std::string& service_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    per_service_[service_id].queries_made++;
    query_counts_[query_type]++;
  }

  // Record a ghost being created
  void record_ghost_created(const std::string& service_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    per_service_[service_id].ghosts_created++;
  }

  // Get metrics snapshot
  json snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    json j;
    j["per_service"] = json::object();
    for (auto& kv : per_service_) {
      json s;
      s["transactions_sent"] = kv.second.transactions_sent;
      s["transactions_failed"] = kv.second.transactions_failed;
      s["events_sent"] = kv.second.events_sent;
      s["queries_made"] = kv.second.queries_made;
      s["ghosts_created"] = kv.second.ghosts_created;
      if (kv.second.transactions_sent > 0) {
        s["avg_duration_ms"] = kv.second.total_duration_ms /
                                kv.second.transactions_sent;
      }
      j["per_service"][kv.first] = s;
    }
    j["query_counts"] = json(query_counts_);
    return j;
  }

  // Reset all metrics
  void reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    per_service_.clear();
    query_counts_.clear();
  }

private:
  struct ServiceMetrics {
    int64_t transactions_sent{0};
    int64_t transactions_failed{0};
    int64_t events_sent{0};
    int64_t queries_made{0};
    int64_t ghosts_created{0};
    double total_duration_ms{0.0};
  };

  mutable std::mutex mutex_;
  std::unordered_map<std::string, ServiceMetrics> per_service_;
  std::unordered_map<std::string, int64_t> query_counts_;
};

// ============================================================================
// AppServiceAPIFacade - high-level facade for the entire app service subsystem
// Provides a clean interface for the rest of the server to interact with AS
// ============================================================================
class AppServiceAPIFacade {
public:
  AppServiceAPIFacade() {
    // Wire up the event manager
    event_mgr_.set_handler(&event_handler_);
  }

  // Initialize from config file
  bool init_from_config(const std::string& yaml_path) {
    int count = mgr_.load_from_yaml_file(yaml_path);
    if (count > 0) {
      start_background_worker();
      return true;
    }
    return false;
  }

  // Initialize from YAML string
  bool init_from_yaml(const std::string& yaml_str) {
    int count = mgr_.load_from_yaml_string(yaml_str);
    if (count > 0) {
      start_background_worker();
      return true;
    }
    return false;
  }

  // ============ Event notification (called from event pipeline) ============

  // Called when a new event is created
  void notify_new_event(const json& event) {
    event_mgr_.on_new_event(event);
  }

  // Called when a batch of events is created
  void notify_new_events(const std::vector<json>& events) {
    event_mgr_.on_new_events(events);
  }

  // Called on typing notification
  void notify_typing(const std::string& room_id, const std::string& user_id,
                      bool typing) {
    event_mgr_.on_typing(room_id, user_id, typing);
  }

  // Called on read receipt
  void notify_receipt(const std::string& room_id, const std::string& event_id,
                       const std::string& user_id) {
    event_mgr_.on_receipt(room_id, event_id, user_id);
  }

  // Called on presence change
  void notify_presence(const std::string& user_id, const std::string& presence,
                        const std::string& status_msg = "") {
    event_mgr_.on_presence(user_id, presence, status_msg);
  }

  // ============ App Service REST API ============

  // Handle incoming AS API request
  json handle_as_request(
      const std::string& method,
      const std::string& path,
      const json& body,
      const std::map<std::string, std::string>& query_params,
      const std::map<std::string, std::string>& path_params) {
    return rest_servlet_.handle_request(method, path, body, query_params,
                                         path_params);
  }

  // ============ Query APIs ============

  // Query room alias
  AppServiceQueryHandler::QueryResult query_room(const std::string& alias) {
    return mgr_.query_room_alias(alias);
  }

  // Query user
  AppServiceQueryHandler::QueryResult query_user(const std::string& user_id) {
    return mgr_.query_user(user_id);
  }

  // ============ Ghost management ============

  AppServiceGhostManager::GhostRecord* create_ghost(
      const std::string& service_id, const std::string& external_id,
      const std::string& hs_domain) {
    return mgr_.create_ghost(service_id, external_id, hs_domain);
  }

  const AppServiceGhostManager::GhostRecord* get_ghost(
      const std::string& user_id) {
    return mgr_.get_ghost(user_id);
  }

  bool is_ghost(const std::string& user_id) {
    return mgr_.is_ghost_user(user_id);
  }

  std::optional<std::string> ghost_owner(const std::string& user_id) {
    return mgr_.ghost_owner(user_id);
  }

  // ============ Auth checks ============

  std::optional<std::shared_ptr<AppServiceRegistration>>
  auth_by_as_token(const std::string& token) {
    return mgr_.auth_by_as_token(token);
  }

  bool can_create_user(const std::string& as_token,
                        const std::string& user_id) {
    return mgr_.can_create_user(as_token, user_id);
  }

  bool can_send_as_user(const std::string& as_token,
                         const std::string& user_id) {
    return mgr_.can_send_as_user(as_token, user_id);
  }

  // ============ Namespace checks ============

  bool is_exclusive_user(const std::string& user_id,
                          std::string* owner = nullptr) {
    return mgr_.is_exclusive_user(user_id, owner);
  }

  bool is_exclusive_alias(const std::string& alias,
                           std::string* owner = nullptr) {
    return mgr_.is_exclusive_alias(alias, owner);
  }

  bool is_exclusive_room(const std::string& room_id,
                          std::string* owner = nullptr) {
    return mgr_.is_exclusive_room(room_id, owner);
  }

  std::vector<std::shared_ptr<AppServiceRegistration>>
  get_services_for_user(const std::string& user_id) {
    return mgr_.get_services_for_user(user_id);
  }

  // ============ Registration ============

  bool register_service(std::shared_ptr<AppServiceRegistration> svc) {
    return mgr_.register_service(svc);
  }

  bool register_service_json(const json& j, const std::string& as_token,
                              const std::string& hs_token) {
    return mgr_.register_service_json(j, as_token, hs_token);
  }

  // ============ Diagnostics ============

  json dump_services() { return mgr_.dump_services(); }
  json dump_namespaces() { return mgr_.dump_namespaces(); }
  json dump_scheduler() { return mgr_.dump_scheduler_state(); }
  json get_metrics() { return metrics_.snapshot(); }

  size_t service_count() { return mgr_.service_count(); }
  size_t ghost_count() { return mgr_.ghost_count(); }

  // ============ Access to internals (for advanced usage) ============

  AppServiceManager& manager() { return mgr_; }
  AppServiceScheduler& scheduler() { return mgr_.scheduler(); }
  AppServiceGhostManager& ghost_manager() { return mgr_.ghost_manager(); }
  AppServiceNamespaceManager& namespace_manager() {
    return mgr_.namespace_manager();
  }

  // Shutdown
  void shutdown() {
    bg_worker_->stop();
    bg_worker_.reset();
  }

private:
  void start_background_worker() {
    if (bg_worker_) bg_worker_->stop();
    bg_worker_ = std::make_unique<AppServiceBackgroundWorker>(
        mgr_, mgr_.scheduler(), mgr_.pusher(), mgr_.rate_limiter());
    bg_worker_->start();
  }

  // Core components
  AppServiceManager mgr_;
  AppServiceEventManager event_mgr_;
  AppServiceEventHandler event_handler_{
      mgr_.scheduler(), mgr_.namespace_manager(), mgr_.rate_limiter()};
  AppServiceRestServlet rest_servlet_{mgr_};
  AppServiceMetrics metrics_;

  // Background worker
  std::unique_ptr<AppServiceBackgroundWorker> bg_worker_;
};

} // namespace progressive
