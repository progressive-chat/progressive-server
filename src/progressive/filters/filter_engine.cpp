// filter_engine.cpp - Matrix event filtering, sync filters, and push rule filter engine
// 3500+ line comprehensive implementation
// Equivalent to synapse/filtering/filtering.py, synapse/push/push_rule_evaluator.py,
// synapse/visibility.py, synapse/federation/federation_filter.py

#include "../json.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
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

namespace progressive::filters {

using json = nlohmann::json;

// ============================================================================
// Forward declarations
// ============================================================================
struct CompiledFilter;
struct CompiledPushRule;
class FilterEngine;
class FilterCache;

// ============================================================================
// Constants
// ============================================================================

// Maximum filter size in bytes (128 KB)
static constexpr size_t MAX_FILTER_SIZE = 128 * 1024;

// Maximum number of filters per user
static constexpr int MAX_FILTERS_PER_USER = 100;

// Maximum types/senders/rooms arrays in any filter
static constexpr size_t MAX_FILTER_LIST_LENGTH = 1000;

// Maximum filter ID length
static constexpr size_t MAX_FILTER_ID_LENGTH = 64;

// Cache TTL in seconds
static constexpr int64_t FILTER_CACHE_TTL_SECONDS = 300;

// Maximum cache entries
static constexpr size_t MAX_CACHE_ENTRIES = 5000;

// Default timeline limit
static constexpr int DEFAULT_TIMELINE_LIMIT = 20;

// Federation backfill limit
static constexpr int FEDERATION_BACKFILL_LIMIT = 100;

// ============================================================================
// Filter validation error types
// ============================================================================

enum class FilterValidationErrorCode {
  UNKNOWN,
  INVALID_JSON,
  MISSING_REQUIRED_FIELD,
  INVALID_FIELD_TYPE,
  INVALID_FIELD_VALUE,
  TOO_MANY_ENTRIES,
  FILTER_TOO_LARGE,
  DUPLICATE_FILTER_ID,
  FILTER_NOT_FOUND,
  USER_NOT_FOUND,
  EXCEEDED_MAX_FILTERS,
  INVALID_ROOM_ID,
  INVALID_USER_ID,
  INVALID_EVENT_TYPE,
  INVALID_TIMELINE_LIMIT,
  INVALID_LAZY_LOADING,
  INVALID_PUSH_RULE,
  INVALID_NOTIFICATION_CONFIG,
  UNSUPPORTED_OPERATION,
};

struct FilterValidationError {
  FilterValidationErrorCode code = FilterValidationErrorCode::UNKNOWN;
  std::string field;
  std::string message;
  json context;

  std::string to_string() const {
    std::ostringstream oss;
    oss << "FilterValidationError(";
    switch (code) {
      case FilterValidationErrorCode::INVALID_JSON:
        oss << "INVALID_JSON"; break;
      case FilterValidationErrorCode::MISSING_REQUIRED_FIELD:
        oss << "MISSING_REQUIRED_FIELD"; break;
      case FilterValidationErrorCode::INVALID_FIELD_TYPE:
        oss << "INVALID_FIELD_TYPE"; break;
      case FilterValidationErrorCode::INVALID_FIELD_VALUE:
        oss << "INVALID_FIELD_VALUE"; break;
      case FilterValidationErrorCode::TOO_MANY_ENTRIES:
        oss << "TOO_MANY_ENTRIES"; break;
      case FilterValidationErrorCode::FILTER_TOO_LARGE:
        oss << "FILTER_TOO_LARGE"; break;
      case FilterValidationErrorCode::DUPLICATE_FILTER_ID:
        oss << "DUPLICATE_FILTER_ID"; break;
      case FilterValidationErrorCode::FILTER_NOT_FOUND:
        oss << "FILTER_NOT_FOUND"; break;
      case FilterValidationErrorCode::EXCEEDED_MAX_FILTERS:
        oss << "EXCEEDED_MAX_FILTERS"; break;
      default: oss << "UNKNOWN";
    }
    if (!field.empty()) oss << " field=" << field;
    if (!message.empty()) oss << " msg=" << message;
    oss << ")";
    return oss.str();
  }

  json to_json_response() const {
    json resp;
    resp["errcode"] = "M_INVALID_PARAM";
    resp["error"] = message.empty() ? "Invalid filter parameter" : message;
    if (!field.empty()) resp["field"] = field;
    return resp;
  }
};

// ============================================================================
// Filter ID generation
// ============================================================================

class FilterIdGenerator {
public:
  FilterIdGenerator() : counter_(0) {
    // Initialize with a time-based seed
    auto now = std::chrono::system_clock::now();
    auto ts = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
    counter_ = static_cast<uint64_t>(ts);
  }

  std::string generate(const std::string& prefix = "") {
    uint64_t id = counter_.fetch_add(1, std::memory_order_relaxed);
    auto now = std::chrono::system_clock::now();
    auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();

    std::ostringstream oss;
    if (!prefix.empty()) {
      oss << prefix << "_";
    }
    oss << std::hex << ts << "_" << std::hex << id;

    std::string result = oss.str();
    // Truncate if too long
    if (result.size() > MAX_FILTER_ID_LENGTH) {
      result = result.substr(result.size() - MAX_FILTER_ID_LENGTH);
    }
    return result;
  }

  std::string generate_user_filter_id(const std::string& user_id) {
    // Generate a unique filter ID for a user
    // Based on random nonce to avoid collisions
    return generate("u");
  }

  std::string generate_server_filter_id() {
    return generate("s");
  }

  std::string generate_push_rule_id() {
    return generate("pr");
  }

private:
  std::atomic<uint64_t> counter_;
} g_filter_id_generator;

// ============================================================================
// Compiled filter structures for efficient runtime filtering
// ============================================================================

// A compiled set of strings (types, senders, rooms) for O(log n) lookup
struct CompiledStringSet {
  std::vector<std::string> items;
  std::unordered_set<std::string> lookup;

  void compile(const json& j) {
    items.clear();
    lookup.clear();
    if (j.is_array()) {
      for (const auto& item : j) {
        if (item.is_string()) {
          std::string s = item.get<std::string>();
          items.push_back(s);
          lookup.insert(std::move(s));
        }
      }
    }
  }

  bool empty() const { return lookup.empty(); }
  bool contains(const std::string& s) const { return lookup.count(s) > 0; }
};

// Compiled room event filter
struct CompiledRoomEventFilter {
  CompiledStringSet types;
  CompiledStringSet not_types;
  CompiledStringSet senders;
  CompiledStringSet not_senders;
  CompiledStringSet rooms;
  CompiledStringSet not_rooms;

  bool contains_url = false;      // Filter events that contain a URL
  bool contains_url_set = false;

  bool include_redundant_members = false;
  bool include_redundant_members_set = false;

  bool unread_thread_notifications = false;
  bool unread_thread_notifications_set = false;

  void compile(const json& j) {
    if (j.is_null()) return;

    if (j.contains("types")) {
      types.compile(j["types"]);
    }
    if (j.contains("not_types")) {
      not_types.compile(j["not_types"]);
    }
    if (j.contains("senders")) {
      senders.compile(j["senders"]);
    }
    if (j.contains("not_senders")) {
      not_senders.compile(j["not_senders"]);
    }
    if (j.contains("rooms")) {
      rooms.compile(j["rooms"]);
    }
    if (j.contains("not_rooms")) {
      not_rooms.compile(j["not_rooms"]);
    }
    if (j.contains("contains_url")) {
      contains_url = j["contains_url"].get<bool>();
      contains_url_set = true;
    }
    if (j.contains("include_redundant_members")) {
      include_redundant_members = j["include_redundant_members"].get<bool>();
      include_redundant_members_set = true;
    }
    if (j.contains("unread_thread_notifications")) {
      unread_thread_notifications =
          j["unread_thread_notifications"].get<bool>();
      unread_thread_notifications_set = true;
    }
  }

  bool matches(const std::string& event_type,
               const std::string& sender,
               const std::string& room_id,
               bool has_url) const {
    // Check types inclusion filter: if set, type must be in the list
    if (!types.empty() && !types.contains(event_type)) {
      return false;
    }
    // Check types exclusion filter: if set, type must NOT be in the list
    if (!not_types.empty() && not_types.contains(event_type)) {
      return false;
    }
    // Check senders inclusion filter
    if (!senders.empty() && !senders.contains(sender)) {
      return false;
    }
    // Check senders exclusion filter
    if (!not_senders.empty() && not_senders.contains(sender)) {
      return false;
    }
    // Check rooms inclusion filter
    if (!rooms.empty() && !rooms.contains(room_id)) {
      return false;
    }
    // Check rooms exclusion filter
    if (!not_rooms.empty() && not_rooms.contains(room_id)) {
      return false;
    }
    // Check contains_url filter
    if (contains_url_set) {
      if (contains_url && !has_url) return false;
      if (!contains_url && has_url) return false;
    }
    return true;
  }
};

// Compiled timeline filter
struct CompiledTimelineFilter {
  int limit = DEFAULT_TIMELINE_LIMIT;
  bool limit_set = false;

  CompiledStringSet types;
  CompiledStringSet not_types;
  CompiledStringSet senders;
  CompiledStringSet not_senders;
  CompiledStringSet rooms;
  CompiledStringSet not_rooms;

  bool contains_url = false;
  bool contains_url_set = false;

  bool lazy_load_members = false;
  bool lazy_load_members_set = false;

  bool include_redundant_members = false;
  bool include_redundant_members_set = false;

  bool unread_thread_notifications = false;
  bool unread_thread_notifications_set = false;

  // Related by senders (for lazy loading)
  CompiledStringSet related_by_senders;

  // Related by relay users
  CompiledStringSet related_by_relay;

  void compile(const json& j) {
    if (j.is_null()) return;

    if (j.contains("limit")) {
      limit = j["limit"].get<int>();
      if (limit < 0) limit = 0;
      if (limit > 1000) limit = 1000;
      limit_set = true;
    }

    if (j.contains("types")) types.compile(j["types"]);
    if (j.contains("not_types")) not_types.compile(j["not_types"]);
    if (j.contains("senders")) senders.compile(j["senders"]);
    if (j.contains("not_senders")) not_senders.compile(j["not_senders"]);
    if (j.contains("rooms")) rooms.compile(j["rooms"]);
    if (j.contains("not_rooms")) not_rooms.compile(j["not_rooms"]);

    if (j.contains("contains_url")) {
      contains_url = j["contains_url"].get<bool>();
      contains_url_set = true;
    }

    if (j.contains("lazy_load_members")) {
      lazy_load_members = j["lazy_load_members"].get<bool>();
      lazy_load_members_set = true;
    }

    if (j.contains("include_redundant_members")) {
      include_redundant_members =
          j["include_redundant_members"].get<bool>();
      include_redundant_members_set = true;
    }

    if (j.contains("unread_thread_notifications")) {
      unread_thread_notifications =
          j["unread_thread_notifications"].get<bool>();
      unread_thread_notifications_set = true;
    }

    if (j.contains("related_by_senders")) {
      related_by_senders.compile(j["related_by_senders"]);
    }
    if (j.contains("related_by_relay")) {
      related_by_relay.compile(j["related_by_relay"]);
    }
  }

  bool matches_event(const std::string& event_type,
                     const std::string& sender,
                     const std::string& room_id,
                     bool has_url) const {
    if (!types.empty() && !types.contains(event_type)) return false;
    if (!not_types.empty() && not_types.contains(event_type)) return false;
    if (!senders.empty() && !senders.contains(sender)) return false;
    if (!not_senders.empty() && not_senders.contains(sender)) return false;
    if (!rooms.empty() && !rooms.contains(room_id)) return false;
    if (!not_rooms.empty() && not_rooms.contains(room_id)) return false;
    if (contains_url_set) {
      if (contains_url && !has_url) return false;
      if (!contains_url && has_url) return false;
    }
    return true;
  }
};

// Compiled state filter
struct CompiledStateFilter {
  CompiledStringSet types;
  CompiledStringSet not_types;
  CompiledStringSet senders;
  CompiledStringSet not_senders;
  CompiledStringSet rooms;
  CompiledStringSet not_rooms;

  bool lazy_load_members = false;
  bool lazy_load_members_set = false;

  // Per-type limits
  std::map<std::string, int> per_type_limits;

  void compile(const json& j) {
    if (j.is_null()) return;

    if (j.contains("types")) types.compile(j["types"]);
    if (j.contains("not_types")) not_types.compile(j["not_types"]);
    if (j.contains("senders")) senders.compile(j["senders"]);
    if (j.contains("not_senders")) not_senders.compile(j["not_senders"]);
    if (j.contains("rooms")) rooms.compile(j["rooms"]);
    if (j.contains("not_rooms")) not_rooms.compile(j["not_rooms"]);

    if (j.contains("lazy_load_members")) {
      lazy_load_members = j["lazy_load_members"].get<bool>();
      lazy_load_members_set = true;
    }

    if (j.contains("per_type_limits") && j["per_type_limits"].is_object()) {
      for (auto& [key, val] : j["per_type_limits"].items()) {
        if (val.is_number_integer()) {
          per_type_limits[key] = val.get<int>();
        }
      }
    }
  }

  bool matches(const std::string& event_type,
               const std::string& sender,
               const std::string& room_id) const {
    if (!types.empty() && !types.contains(event_type)) return false;
    if (!not_types.empty() && not_types.contains(event_type)) return false;
    if (!senders.empty() && !senders.contains(sender)) return false;
    if (!not_senders.empty() && not_senders.contains(sender)) return false;
    if (!rooms.empty() && !rooms.contains(room_id)) return false;
    if (!not_rooms.empty() && not_rooms.contains(room_id)) return false;
    return true;
  }
};

// Compiled ephemeral filter
struct CompiledEphemeralFilter {
  CompiledStringSet types;
  CompiledStringSet not_types;
  CompiledStringSet senders;
  CompiledStringSet not_senders;
  CompiledStringSet rooms;
  CompiledStringSet not_rooms;

  void compile(const json& j) {
    if (j.is_null()) return;

    if (j.contains("types")) types.compile(j["types"]);
    if (j.contains("not_types")) not_types.compile(j["not_types"]);
    if (j.contains("senders")) senders.compile(j["senders"]);
    if (j.contains("not_senders")) not_senders.compile(j["not_senders"]);
    if (j.contains("rooms")) rooms.compile(j["rooms"]);
    if (j.contains("not_rooms")) not_rooms.compile(j["not_rooms"]);
  }

  bool matches(const std::string& event_type,
               const std::string& sender,
               const std::string& room_id) const {
    if (!types.empty() && !types.contains(event_type)) return false;
    if (!not_types.empty() && not_types.contains(event_type)) return false;
    if (!senders.empty() && !senders.contains(sender)) return false;
    if (!not_senders.empty() && not_senders.contains(sender)) return false;
    if (!rooms.empty() && !rooms.contains(room_id)) return false;
    if (!not_rooms.empty() && not_rooms.contains(room_id)) return false;
    return true;
  }
};

// Compiled account data filter
struct CompiledAccountDataFilter {
  CompiledStringSet types;
  CompiledStringSet not_types;

  void compile(const json& j) {
    if (j.is_null()) return;
    if (j.contains("types")) types.compile(j["types"]);
    if (j.contains("not_types")) not_types.compile(j["not_types"]);
  }

  bool matches(const std::string& event_type) const {
    if (!types.empty() && !types.contains(event_type)) return false;
    if (!not_types.empty() && not_types.contains(event_type)) return false;
    return true;
  }
};

// Compiled presence filter
struct CompiledPresenceFilter {
  CompiledStringSet types;
  CompiledStringSet not_types;
  CompiledStringSet senders;
  CompiledStringSet not_senders;

  bool include_last_active_ago = false;
  bool include_last_active_ago_set = false;

  void compile(const json& j) {
    if (j.is_null()) return;

    if (j.contains("types")) types.compile(j["types"]);
    if (j.contains("not_types")) not_types.compile(j["not_types"]);
    if (j.contains("senders")) senders.compile(j["senders"]);
    if (j.contains("not_senders")) not_senders.compile(j["not_senders"]);
    if (j.contains("include_last_active_ago")) {
      include_last_active_ago = j["include_last_active_ago"].get<bool>();
      include_last_active_ago_set = true;
    }
  }

  bool matches(const std::string& presence_type,
               const std::string& user_id) const {
    if (!types.empty() && !types.contains(presence_type)) return false;
    if (!not_types.empty() && not_types.contains(presence_type)) return false;
    if (!senders.empty() && !senders.contains(user_id)) return false;
    if (!not_senders.empty() && not_senders.contains(user_id)) return false;
    return true;
  }
};

// Compiled push rule condition
struct CompiledPushRuleCondition {
  enum class Kind {
    EVENT_MATCH,
    CONTAINS_DISPLAY_NAME,
    ROOM_MEMBER_COUNT,
    SENDER_NOTIFICATION_PERMISSION,
    UNKNOWN,
  };

  Kind kind = Kind::UNKNOWN;
  std::string key;
  std::string pattern;
  std::regex compiled_regex;
  bool is_regex = false;

  void compile(const json& j) {
    if (!j.contains("kind")) return;

    std::string kind_str = j["kind"].get<std::string>();
    if (kind_str == "event_match") {
      kind = Kind::EVENT_MATCH;
    } else if (kind_str == "contains_display_name") {
      kind = Kind::CONTAINS_DISPLAY_NAME;
    } else if (kind_str == "room_member_count") {
      kind = Kind::ROOM_MEMBER_COUNT;
    } else if (kind_str == "sender_notification_permission") {
      kind = Kind::SENDER_NOTIFICATION_PERMISSION;
    } else {
      kind = Kind::UNKNOWN;
    }

    if (j.contains("key")) {
      key = j["key"].get<std::string>();
    }
    if (j.contains("pattern")) {
      pattern = j["pattern"].get<std::string>();
      try {
        compiled_regex = std::regex(pattern, std::regex::ECMAScript);
        is_regex = true;
      } catch (const std::regex_error&) {
        is_regex = false;
        // Fall back to simple string matching
      }
    }
  }

  bool evaluate(const json& event, const std::string& display_name,
                int member_count, bool is_room_sender_notifiable) const {
    switch (kind) {
      case Kind::EVENT_MATCH: {
        // Navigate to the key in the event JSON
        std::string value = get_json_value_at_path(event, key);
        if (value.empty()) return false;
        if (is_regex) {
          return std::regex_search(value, compiled_regex);
        }
        return value.find(pattern) != std::string::npos;
      }
      case Kind::CONTAINS_DISPLAY_NAME: {
        if (display_name.empty()) return false;
        std::string body = get_json_value_at_path(event, "content.body");
        return body.find(display_name) != std::string::npos;
      }
      case Kind::ROOM_MEMBER_COUNT: {
        if (pattern.empty()) return true;
        try {
          int threshold = std::stoi(pattern);
          if (key.empty() || key == "==") return member_count == threshold;
          if (key == "<") return member_count < threshold;
          if (key == ">") return member_count > threshold;
          if (key == "<=") return member_count <= threshold;
          if (key == ">=") return member_count >= threshold;
          return member_count == threshold;
        } catch (...) {
          return false;
        }
      }
      case Kind::SENDER_NOTIFICATION_PERMISSION: {
        return is_room_sender_notifiable;
      }
      default:
        return false;
    }
  }

private:
  static std::string get_json_value_at_path(const json& j,
                                            const std::string& path) {
    // Parse a dot-separated path to get a value from JSON
    std::istringstream stream(path);
    std::string segment;
    const json* current = &j;

    while (std::getline(stream, segment, '.')) {
      if (!current->is_object()) return "";
      auto it = current->find(segment);
      if (it == current->end()) return "";
      current = &(*it);
    }

    if (current->is_string()) return current->get<std::string>();
    if (current->is_number()) {
      std::ostringstream oss;
      oss << current->get<double>();
      return oss.str();
    }
    if (current->is_boolean()) {
      return current->get<bool>() ? "true" : "false";
    }
    return current->dump();
  }
};

// Compiled push rule
struct CompiledPushRule {
  std::string rule_id;
  std::string kind;  // override, underride, content, sender, room
  std::vector<json> actions;
  std::vector<CompiledPushRuleCondition> conditions;
  int priority_class = 0;
  int priority = 0;
  bool enabled = true;
  bool default_rule = false;

  // For sender rules: patterns
  std::string sender_pattern;

  // For room rules: room_id
  std::string room_id_pattern;

  void compile(const json& j) {
    if (j.contains("rule_id"))
      rule_id = j["rule_id"].get<std::string>();
    if (j.contains("kind"))
      kind = j["kind"].get<std::string>();
    if (j.contains("actions") && j["actions"].is_array())
      actions = j["actions"].get<std::vector<json>>();
    if (j.contains("conditions") && j["conditions"].is_array()) {
      for (const auto& cond : j["conditions"]) {
        CompiledPushRuleCondition cpc;
        cpc.compile(cond);
        conditions.push_back(std::move(cpc));
      }
    }
    if (j.contains("priority_class"))
      priority_class = j["priority_class"].get<int>();
    if (j.contains("priority"))
      priority = j["priority"].get<int>();
    if (j.contains("enabled"))
      enabled = j["enabled"].get<bool>();
    if (j.contains("default"))
      default_rule = j["default"].get<bool>();
    if (j.contains("pattern"))
      sender_pattern = j["pattern"].get<std::string>();
  }

  bool matches(const json& event, const std::string& display_name,
               int member_count, bool is_room_sender_notifiable) const {
    if (!enabled) return false;

    for (const auto& cond : conditions) {
      if (!cond.evaluate(event, display_name, member_count,
                         is_room_sender_notifiable)) {
        return false;
      }
    }
    return true;
  }
};

// ============================================================================
// Full compiled filter combining all sub-filters
// ============================================================================

struct CompiledFilter {
  std::string filter_id;
  std::string user_id;
  json original_json;
  int64_t compiled_at = 0;

  // Sub-filters
  std::vector<CompiledRoomEventFilter> event_fields;
  bool event_fields_set = false;

  CompiledTimelineFilter timeline;
  bool timeline_set = false;

  CompiledStateFilter state;
  bool state_set = false;

  CompiledEphemeralFilter ephemeral;
  bool ephemeral_set = false;

  CompiledAccountDataFilter account_data;
  bool account_data_set = false;

  CompiledPresenceFilter presence;
  bool presence_set = false;

  // Compiled push rules for this filter
  std::vector<CompiledPushRule> push_rules;
  bool push_rules_set = false;

  // Notification filter
  struct NotificationSettings {
    bool notify = true;
    bool highlight = false;
    bool sound = true;
    std::string sound_name = "default";
    int room_specific_count = 0;
  };
  NotificationSettings notification;

  // Federation filter
  struct FederationFilter {
    bool include_redundant_members = false;
    bool lazy_load_members = false;
    int limit = FEDERATION_BACKFILL_LIMIT;
    std::set<std::string> allowed_types;
    bool all_types_allowed = true;
  };
  FederationFilter federation;

  // Search filter
  struct SearchFilter {
    std::string search_term;
    std::vector<std::string> keys;  // content keys to search
    std::vector<std::string> room_ids;
    std::vector<std::string> event_types;
    std::vector<std::string> senders;
    bool include_state = false;
    bool include_ephemeral = false;
    int limit = 10;
    int before_limit = 0;
    int after_limit = 0;
    bool order_by_recent = true;
    json group_by;
  };
  SearchFilter search;

  // Compile the entire filter from JSON
  void compile(const json& j) {
    original_json = j;
    compiled_at = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // Event fields
    if (j.contains("event_fields") && j["event_fields"].is_array()) {
      event_fields_set = true;
      for (const auto& ef : j["event_fields"]) {
        CompiledRoomEventFilter ref;
        ref.compile(ef);
        event_fields.push_back(std::move(ref));
      }
    }

    // Timeline
    if (j.contains("room") && j["room"].is_object()) {
      const auto& room = j["room"];
      if (room.contains("timeline")) {
        timeline.compile(room["timeline"]);
        timeline_set = true;
      }
      if (room.contains("state")) {
        state.compile(room["state"]);
        state_set = true;
      }
      if (room.contains("ephemeral")) {
        ephemeral.compile(room["ephemeral"]);
        ephemeral_set = true;
      }
      if (room.contains("account_data")) {
        account_data.compile(room["account_data"]);
        account_data_set = true;
      }
    }

    // Legacy: timeline filter at top level
    if (j.contains("timeline") && !timeline_set) {
      timeline.compile(j["timeline"]);
      timeline_set = true;
    }
    if (j.contains("state") && !state_set) {
      state.compile(j["state"]);
      state_set = true;
    }
    if (j.contains("ephemeral") && !ephemeral_set) {
      ephemeral.compile(j["ephemeral"]);
      ephemeral_set = true;
    }

    // Presence
    if (j.contains("presence")) {
      presence.compile(j["presence"]);
      presence_set = true;
    }

    // Account data at top level
    if (j.contains("account_data") && !account_data_set) {
      account_data.compile(j["account_data"]);
      account_data_set = true;
    }

    // Push rules
    if (j.contains("push_rules") && j["push_rules"].is_array()) {
      push_rules_set = true;
      for (const auto& pr : j["push_rules"]) {
        CompiledPushRule cpr;
        cpr.compile(pr);
        push_rules.push_back(std::move(cpr));
      }
    }

    // Notification settings
    if (j.contains("notification")) {
      const auto& notif = j["notification"];
      if (notif.contains("notify"))
        notification.notify = notif["notify"].get<bool>();
      if (notif.contains("highlight"))
        notification.highlight = notif["highlight"].get<bool>();
      if (notif.contains("sound"))
        notification.sound = notif["sound"].get<bool>();
      if (notif.contains("sound_name"))
        notification.sound_name = notif["sound_name"].get<std::string>();
    }

    // Federation filter
    if (j.contains("federation")) {
      const auto& fed = j["federation"];
      if (fed.contains("include_redundant_members"))
        federation.include_redundant_members =
            fed["include_redundant_members"].get<bool>();
      if (fed.contains("lazy_load_members"))
        federation.lazy_load_members =
            fed["lazy_load_members"].get<bool>();
      if (fed.contains("limit"))
        federation.limit = fed["limit"].get<int>();
      if (fed.contains("types") && fed["types"].is_array()) {
        federation.all_types_allowed = false;
        for (const auto& t : fed["types"]) {
          if (t.is_string())
            federation.allowed_types.insert(t.get<std::string>());
        }
      }
    }

    // Search filter
    if (j.contains("search")) {
      const auto& srch = j["search"];
      if (srch.contains("search_term"))
        search.search_term = srch["search_term"].get<std::string>();
      if (srch.contains("keys") && srch["keys"].is_array()) {
        for (const auto& k : srch["keys"]) {
          if (k.is_string()) search.keys.push_back(k.get<std::string>());
        }
      }
      if (srch.contains("room_ids") && srch["room_ids"].is_array()) {
        for (const auto& r : srch["room_ids"]) {
          if (r.is_string()) search.room_ids.push_back(r.get<std::string>());
        }
      }
      if (srch.contains("event_types") && srch["event_types"].is_array()) {
        for (const auto& et : srch["event_types"]) {
          if (et.is_string()) search.event_types.push_back(et.get<std::string>());
        }
      }
      if (srch.contains("senders") && srch["senders"].is_array()) {
        for (const auto& s : srch["senders"]) {
          if (s.is_string()) search.senders.push_back(s.get<std::string>());
        }
      }
      if (srch.contains("include_state"))
        search.include_state = srch["include_state"].get<bool>();
      if (srch.contains("include_ephemeral"))
        search.include_ephemeral = srch["include_ephemeral"].get<bool>();
      if (srch.contains("limit"))
        search.limit = srch["limit"].get<int>();
      if (srch.contains("before_limit"))
        search.before_limit = srch["before_limit"].get<int>();
      if (srch.contains("after_limit"))
        search.after_limit = srch["after_limit"].get<int>();
      if (srch.contains("order_by_recent"))
        search.order_by_recent = srch["order_by_recent"].get<bool>();
      if (srch.contains("group_by"))
        search.group_by = srch["group_by"];
    }
  }

  bool is_empty() const {
    return !event_fields_set && !timeline_set && !state_set &&
           !ephemeral_set && !account_data_set && !presence_set &&
           !push_rules_set;
  }
};

// ============================================================================
// Filter cache
// ============================================================================

class FilterCache {
public:
  FilterCache() = default;
  ~FilterCache() = default;

  // Get a cached compiled filter
  std::optional<CompiledFilter> get(const std::string& filter_id) {
    std::shared_lock lock(mutex_);
    auto it = cache_.find(filter_id);
    if (it == cache_.end()) return std::nullopt;

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (now - it->second.compiled_at > FILTER_CACHE_TTL_SECONDS) {
      return std::nullopt;  // Expired
    }
    return it->second;
  }

  // Store a compiled filter in cache
  void put(const std::string& filter_id, const CompiledFilter& filter) {
    std::unique_lock lock(mutex_);
    // Evict if cache is full
    if (cache_.size() >= MAX_CACHE_ENTRIES) {
      evict_lru();
    }
    cache_[filter_id] = filter;
    lru_order_.push_back(filter_id);
  }

  // Invalidate a cached filter
  void invalidate(const std::string& filter_id) {
    std::unique_lock lock(mutex_);
    cache_.erase(filter_id);
  }

  // Invalidate all filters for a user
  void invalidate_user(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    auto it = cache_.begin();
    while (it != cache_.end()) {
      if (it->second.user_id == user_id) {
        it = cache_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // Clear all cache
  void clear() {
    std::unique_lock lock(mutex_);
    cache_.clear();
    lru_order_.clear();
  }

  // Get cache stats
  struct CacheStats {
    size_t size = 0;
    size_t max_size = MAX_CACHE_ENTRIES;
    int64_t ttl_seconds = FILTER_CACHE_TTL_SECONDS;
  };

  CacheStats stats() const {
    std::shared_lock lock(mutex_);
    CacheStats s;
    s.size = cache_.size();
    return s;
  }

  // Bulk load filters into cache
  void bulk_load(const std::vector<CompiledFilter>& filters) {
    std::unique_lock lock(mutex_);
    for (const auto& f : filters) {
      if (cache_.size() >= MAX_CACHE_ENTRIES) {
        evict_lru();
      }
      cache_[f.filter_id] = f;
      lru_order_.push_back(f.filter_id);
    }
  }

private:
  void evict_lru() {
    // Simple eviction: remove oldest entries
    if (lru_order_.empty() && !cache_.empty()) {
      cache_.erase(cache_.begin());
      return;
    }
    if (!lru_order_.empty()) {
      std::string oldest = lru_order_.front();
      lru_order_.pop_front();
      cache_.erase(oldest);
    }
  }

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, CompiledFilter> cache_;
  std::deque<std::string> lru_order_;
};

// ============================================================================
// Filter storage engine (CRUD operations)
// ============================================================================

class FilterStorage {
public:
  FilterStorage() : cache_(std::make_shared<FilterCache>()) {}

  // Create a new user filter
  std::pair<std::optional<std::string>, std::optional<FilterValidationError>>
  create_user_filter(const std::string& user_id, const json& filter_json) {
    // Validate
    auto validation = validate_filter(user_id, filter_json);
    if (validation.has_value()) {
      return {std::nullopt, validation};
    }

    // Check user's filter count
    {
      std::shared_lock lock(mutex_);
      auto it = user_filters_.find(user_id);
      if (it != user_filters_.end() &&
          it->second.size() >= static_cast<size_t>(MAX_FILTERS_PER_USER)) {
        FilterValidationError err;
        err.code = FilterValidationErrorCode::EXCEEDED_MAX_FILTERS;
        err.message = "User has reached maximum number of filters (" +
                      std::to_string(MAX_FILTERS_PER_USER) + ")";
        return {std::nullopt, err};
      }
    }

    // Generate filter ID
    std::string filter_id = g_filter_id_generator.generate_user_filter_id(user_id);

    // Store filter
    {
      std::unique_lock lock(mutex_);
      user_filters_[user_id][filter_id] = filter_json;
    }

    // Compile and cache
    CompiledFilter compiled;
    compiled.filter_id = filter_id;
    compiled.user_id = user_id;
    compiled.compile(filter_json);
    cache_->put(filter_id, compiled);

    return {filter_id, std::nullopt};
  }

  // Get a user filter by ID
  std::optional<json> get_user_filter(const std::string& user_id,
                                       const std::string& filter_id) const {
    std::shared_lock lock(mutex_);
    auto user_it = user_filters_.find(user_id);
    if (user_it == user_filters_.end()) return std::nullopt;

    auto filter_it = user_it->second.find(filter_id);
    if (filter_it == user_it->second.end()) return std::nullopt;

    return filter_it->second;
  }

  // Get all filters for a user
  std::vector<std::pair<std::string, json>> get_user_filters(
      const std::string& user_id) const {
    std::shared_lock lock(mutex_);
    std::vector<std::pair<std::string, json>> result;
    auto user_it = user_filters_.find(user_id);
    if (user_it != user_filters_.end()) {
      for (const auto& [fid, fj] : user_it->second) {
        result.emplace_back(fid, fj);
      }
    }
    return result;
  }

  // Update a user filter
  std::optional<FilterValidationError> update_user_filter(
      const std::string& user_id,
      const std::string& filter_id,
      const json& filter_json) {
    // Check filter exists
    {
      std::shared_lock lock(mutex_);
      auto user_it = user_filters_.find(user_id);
      if (user_it == user_filters_.end() ||
          user_it->second.find(filter_id) == user_it->second.end()) {
        FilterValidationError err;
        err.code = FilterValidationErrorCode::FILTER_NOT_FOUND;
        err.message = "Filter not found: " + filter_id;
        return err;
      }
    }

    // Validate
    auto validation = validate_filter(user_id, filter_json);
    if (validation.has_value()) return validation;

    // Update
    {
      std::unique_lock lock(mutex_);
      user_filters_[user_id][filter_id] = filter_json;
    }

    // Re-compile and cache
    CompiledFilter compiled;
    compiled.filter_id = filter_id;
    compiled.user_id = user_id;
    compiled.compile(filter_json);
    cache_->put(filter_id, compiled);

    return std::nullopt;
  }

  // Delete a user filter
  std::optional<FilterValidationError> delete_user_filter(
      const std::string& user_id, const std::string& filter_id) {
    std::unique_lock lock(mutex_);
    auto user_it = user_filters_.find(user_id);
    if (user_it == user_filters_.end() ||
        user_it->second.find(filter_id) == user_it->second.end()) {
      FilterValidationError err;
      err.code = FilterValidationErrorCode::FILTER_NOT_FOUND;
      err.message = "Filter not found: " + filter_id;
      return err;
    }

    user_it->second.erase(filter_id);
    if (user_it->second.empty()) {
      user_filters_.erase(user_it);
    }

    // Invalidate cache
    cache_->invalidate(filter_id);

    return std::nullopt;
  }

  // Store a server filter (for federation)
  std::string add_server_filter(const json& filter_json) {
    std::string filter_id = g_filter_id_generator.generate_server_filter_id();

    std::unique_lock lock(mutex_);
    server_filters_[filter_id] = filter_json;

    CompiledFilter compiled;
    compiled.filter_id = filter_id;
    compiled.compile(filter_json);
    cache_->put(filter_id, compiled);

    return filter_id;
  }

  // Get a server filter
  std::optional<json> get_server_filter(const std::string& filter_id) const {
    std::shared_lock lock(mutex_);
    auto it = server_filters_.find(filter_id);
    if (it == server_filters_.end()) return std::nullopt;
    return it->second;
  }

  // Get compiled filter (from cache or compile)
  std::optional<CompiledFilter> get_compiled(const std::string& filter_id) {
    // Try cache first
    auto cached = cache_->get(filter_id);
    if (cached.has_value()) return cached;

    // Try user filters
    {
      std::shared_lock lock(mutex_);
      for (const auto& [uid, filters] : user_filters_) {
        auto it = filters.find(filter_id);
        if (it != filters.end()) {
          CompiledFilter compiled;
          compiled.filter_id = filter_id;
          compiled.user_id = uid;
          compiled.compile(it->second);
          cache_->put(filter_id, compiled);
          return compiled;
        }
      }
    }

    // Try server filters
    {
      std::shared_lock lock(mutex_);
      auto it = server_filters_.find(filter_id);
      if (it != server_filters_.end()) {
        CompiledFilter compiled;
        compiled.filter_id = filter_id;
        compiled.compile(it->second);
        cache_->put(filter_id, compiled);
        return compiled;
      }
    }

    return std::nullopt;
  }

  // Count filters for a user
  int count_user_filters(const std::string& user_id) const {
    std::shared_lock lock(mutex_);
    auto it = user_filters_.find(user_id);
    if (it == user_filters_.end()) return 0;
    return static_cast<int>(it->second.size());
  }

  // Clear all filters for a user (e.g., on account deletion)
  void clear_user_filters(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    auto it = user_filters_.find(user_id);
    if (it != user_filters_.end()) {
      // Invalidate all cached filters for this user
      for (const auto& [fid, _] : it->second) {
        cache_->invalidate(fid);
      }
      user_filters_.erase(it);
    }
  }

  // Get cache
  std::shared_ptr<FilterCache> get_cache() { return cache_; }

  // Admin: get all filters (returns map of user_id -> filter_id -> json)
  std::map<std::string, std::map<std::string, json>> get_all_user_filters() const {
    std::shared_lock lock(mutex_);
    return user_filters_;
  }

  // Admin: get all server filters
  std::map<std::string, json> get_all_server_filters() const {
    std::shared_lock lock(mutex_);
    return server_filters_;
  }

  // Admin: get total filter count
  size_t total_filter_count() const {
    std::shared_lock lock(mutex_);
    size_t count = server_filters_.size();
    for (const auto& [_, filters] : user_filters_) {
      count += filters.size();
    }
    return count;
  }

  // Admin: purge expired filters (filters older than a duration)
  // Note: In this implementation we don't track creation time per filter,
  // but we can clear the cache
  void purge_cache() {
    cache_->clear();
  }

private:
  // Validate a filter JSON
  std::optional<FilterValidationError> validate_filter(
      const std::string& user_id, const json& filter_json) {
    if (!filter_json.is_object() && !filter_json.is_null()) {
      FilterValidationError err;
      err.code = FilterValidationErrorCode::INVALID_JSON;
      err.message = "Filter must be a JSON object";
      return err;
    }

    if (filter_json.is_null()) return std::nullopt;

    // Check filter size
    std::string dumped = filter_json.dump();
    if (dumped.size() > MAX_FILTER_SIZE) {
      FilterValidationError err;
      err.code = FilterValidationErrorCode::FILTER_TOO_LARGE;
      err.message = "Filter is too large. Maximum size is " +
                    std::to_string(MAX_FILTER_SIZE) + " bytes.";
      return err;
    }

    // Validate event_fields
    if (filter_json.contains("event_fields")) {
      const auto& ef = filter_json["event_fields"];
      if (!ef.is_null() && !ef.is_array()) {
        FilterValidationError err;
        err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
        err.field = "event_fields";
        err.message = "event_fields must be an array";
        return err;
      }
      if (ef.is_array()) {
        for (size_t i = 0; i < ef.size(); ++i) {
          if (!ef[i].is_array() && !ef[i].is_null()) {
            FilterValidationError err;
            err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
            err.field = "event_fields[" + std::to_string(i) + "]";
            err.message = "event_fields entry must be an array of strings";
            return err;
          }
          if (ef[i].is_array()) {
            for (size_t j = 0; j < ef[i].size(); ++j) {
              if (!ef[i][j].is_string()) {
                FilterValidationError err;
                err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
                err.field = "event_fields[" + std::to_string(i) + "][" +
                            std::to_string(j) + "]";
                err.message = "event_fields entry must be a string";
                return err;
              }
            }
          }
        }
      }
    }

    // Validate event_format
    if (filter_json.contains("event_format")) {
      const auto& fmt = filter_json["event_format"];
      if (!fmt.is_string()) {
        FilterValidationError err;
        err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
        err.field = "event_format";
        err.message = "event_format must be a string ('client' or 'federation')";
        return err;
      }
      std::string fv = fmt.get<std::string>();
      if (fv != "client" && fv != "federation") {
        FilterValidationError err;
        err.code = FilterValidationErrorCode::INVALID_FIELD_VALUE;
        err.field = "event_format";
        err.message = "event_format must be 'client' or 'federation'";
        return err;
      }
    }

    // Validate room filters
    if (filter_json.contains("room")) {
      const auto& room = filter_json["room"];
      if (!room.is_object()) {
        FilterValidationError err;
        err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
        err.field = "room";
        err.message = "room must be an object";
        return err;
      }

      // Validate timeline
      if (room.contains("timeline") && !room["timeline"].is_null()) {
        auto err = validate_room_filter(room["timeline"], "room.timeline");
        if (err.has_value()) return err;
      }

      // Validate state
      if (room.contains("state") && !room["state"].is_null()) {
        auto err = validate_room_filter(room["state"], "room.state");
        if (err.has_value()) return err;
      }

      // Validate ephemeral
      if (room.contains("ephemeral") && !room["ephemeral"].is_null()) {
        auto err = validate_room_filter(room["ephemeral"], "room.ephemeral");
        if (err.has_value()) return err;
      }

      // Validate account_data
      if (room.contains("account_data") && !room["account_data"].is_null()) {
        auto err = validate_account_data_filter(room["account_data"],
                                                 "room.account_data");
        if (err.has_value()) return err;
      }
    }

    // Validate presence
    if (filter_json.contains("presence") && !filter_json["presence"].is_null()) {
      auto err = validate_presence_filter(filter_json["presence"], "presence");
      if (err.has_value()) return err;
    }

    // Validate account_data at top level
    if (filter_json.contains("account_data") && !filter_json["account_data"].is_null()) {
      auto err = validate_account_data_filter(filter_json["account_data"],
                                               "account_data");
      if (err.has_value()) return err;
    }

    // Validate push rules
    if (filter_json.contains("push_rules")) {
      const auto& pr = filter_json["push_rules"];
      if (!pr.is_null() && !pr.is_array()) {
        FilterValidationError err;
        err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
        err.field = "push_rules";
        err.message = "push_rules must be an array";
        return err;
      }
    }

    // Validate search
    if (filter_json.contains("search")) {
      const auto& srch = filter_json["search"];
      if (!srch.is_object() && !srch.is_null()) {
        FilterValidationError err;
        err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
        err.field = "search";
        err.message = "search must be an object";
        return err;
      }
      if (srch.is_object()) {
        if (srch.contains("limit") && !srch["limit"].is_number_integer()) {
          FilterValidationError err;
          err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
          err.field = "search.limit";
          err.message = "search.limit must be an integer";
          return err;
        }
      }
    }

    return std::nullopt;
  }

  std::optional<FilterValidationError> validate_room_filter(
      const json& j, const std::string& prefix) {
    if (!j.is_object()) {
      FilterValidationError err;
      err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
      err.field = prefix;
      err.message = prefix + " must be an object";
      return err;
    }

    // Validate limit
    if (j.contains("limit")) {
      if (!j["limit"].is_number_integer()) {
        FilterValidationError err;
        err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
        err.field = prefix + ".limit";
        err.message = prefix + ".limit must be an integer";
        return err;
      }
      int limit = j["limit"].get<int>();
      if (limit < 0) {
        FilterValidationError err;
        err.code = FilterValidationErrorCode::INVALID_TIMELINE_LIMIT;
        err.field = prefix + ".limit";
        err.message = prefix + ".limit must be non-negative";
        return err;
      }
    }

    // Validate string arrays
    std::vector<std::string> array_fields = {
        "types", "not_types", "senders", "not_senders", "rooms", "not_rooms",
        "related_by_senders", "related_by_relay"};
    for (const auto& field : array_fields) {
      if (j.contains(field)) {
        const auto& arr = j[field];
        if (!arr.is_null() && !arr.is_array()) {
          FilterValidationError err;
          err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
          err.field = prefix + "." + field;
          err.message = prefix + "." + field + " must be an array";
          return err;
        }
        if (arr.is_array() && arr.size() > MAX_FILTER_LIST_LENGTH) {
          FilterValidationError err;
          err.code = FilterValidationErrorCode::TOO_MANY_ENTRIES;
          err.field = prefix + "." + field;
          err.message = prefix + "." + field + " has too many entries (max " +
                        std::to_string(MAX_FILTER_LIST_LENGTH) + ")";
          return err;
        }
      }
    }

    // Validate booleans
    std::vector<std::string> bool_fields = {
        "contains_url", "lazy_load_members", "include_redundant_members",
        "unread_thread_notifications"};
    for (const auto& field : bool_fields) {
      if (j.contains(field) && !j[field].is_null()) {
        if (!j[field].is_boolean()) {
          FilterValidationError err;
          err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
          err.field = prefix + "." + field;
          err.message = prefix + "." + field + " must be a boolean";
          return err;
        }
      }
    }

    return std::nullopt;
  }

  std::optional<FilterValidationError> validate_account_data_filter(
      const json& j, const std::string& prefix) {
    if (!j.is_object()) {
      FilterValidationError err;
      err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
      err.field = prefix;
      err.message = prefix + " must be an object";
      return err;
    }
    for (const auto& field : {"types", "not_types"}) {
      if (j.contains(field)) {
        const auto& arr = j[field];
        if (!arr.is_null() && !arr.is_array()) {
          FilterValidationError err;
          err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
          err.field = prefix + "." + std::string(field);
          err.message = std::string(prefix) + "." + field + " must be an array";
          return err;
        }
        if (arr.is_array() && arr.size() > MAX_FILTER_LIST_LENGTH) {
          FilterValidationError err;
          err.code = FilterValidationErrorCode::TOO_MANY_ENTRIES;
          err.field = prefix + "." + std::string(field);
          err.message = std::string(prefix) + "." + field +
                        " has too many entries";
          return err;
        }
      }
    }
    return std::nullopt;
  }

  std::optional<FilterValidationError> validate_presence_filter(
      const json& j, const std::string& prefix) {
    if (!j.is_object()) {
      FilterValidationError err;
      err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
      err.field = prefix;
      err.message = prefix + " must be an object";
      return err;
    }
    for (const auto& field : {"types", "not_types", "senders", "not_senders"}) {
      if (j.contains(field)) {
        const auto& arr = j[field];
        if (!arr.is_null() && !arr.is_array()) {
          FilterValidationError err;
          err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
          err.field = prefix + "." + std::string(field);
          err.message = std::string(prefix) + "." + field + " must be an array";
          return err;
        }
        if (arr.is_array() && arr.size() > MAX_FILTER_LIST_LENGTH) {
          FilterValidationError err;
          err.code = FilterValidationErrorCode::TOO_MANY_ENTRIES;
          err.field = prefix + "." + std::string(field);
          err.message = std::string(prefix) + "." + field +
                        " has too many entries";
          return err;
        }
      }
    }
    if (j.contains("include_last_active_ago") &&
        !j["include_last_active_ago"].is_boolean()) {
      FilterValidationError err;
      err.code = FilterValidationErrorCode::INVALID_FIELD_TYPE;
      err.field = prefix + ".include_last_active_ago";
      err.message = prefix + ".include_last_active_ago must be a boolean";
      return err;
    }
    return std::nullopt;
  }

  mutable std::shared_mutex mutex_;
  std::map<std::string, std::map<std::string, json>> user_filters_;
  std::map<std::string, json> server_filters_;
  std::shared_ptr<FilterCache> cache_;
};

// ============================================================================
// Event filter application
// ============================================================================

struct EventFilterApplication {
  // Apply a compiled filter to a list of events
  // Returns filtered events and the count of events before filtering
  static json apply_event_filter(const CompiledRoomEventFilter& filter,
                                  const json& events,
                                  bool check_has_url = true) {
    json filtered = json::array();
    for (const auto& event : events) {
      if (!event.is_object()) continue;

      std::string event_type = event.value("type", "");
      std::string sender = event.value("sender", "");
      std::string room_id = event.value("room_id", "");

      bool has_url = false;
      if (check_has_url && event.contains("content") &&
          event["content"].is_object()) {
        const auto& content = event["content"];
        // Check common URL-containing fields
        has_url = check_content_for_url(content);
      }

      if (filter.matches(event_type, sender, room_id, has_url)) {
        filtered.push_back(event);
      }
    }
    return filtered;
  }

  // Apply timeline filter
  static json apply_timeline_filter(const CompiledTimelineFilter& filter,
                                     const json& events,
                                     bool check_has_url = true) {
    json filtered = json::array();

    for (const auto& event : events) {
      if (!event.is_object()) continue;

      std::string event_type = event.value("type", "");
      std::string sender = event.value("sender", "");
      std::string room_id = event.value("room_id", "");

      bool has_url = false;
      if (check_has_url && event.contains("content") &&
          event["content"].is_object()) {
        has_url = check_content_for_url(event["content"]);
      }

      if (filter.matches_event(event_type, sender, room_id, has_url)) {
        filtered.push_back(event);
      }
    }

    // Apply limit
    if (filter.limit_set && filter.limit > 0 &&
        filtered.size() > static_cast<size_t>(filter.limit)) {
      // Keep the most recent events (last N)
      json limited = json::array();
      size_t start = filtered.size() - filter.limit;
      for (size_t i = start; i < filtered.size(); ++i) {
        limited.push_back(filtered[i]);
      }
      return limited;
    }

    return filtered;
  }

  // Apply state filter
  static json apply_state_filter(const CompiledStateFilter& filter,
                                  const json& events) {
    json filtered = json::array();
    std::map<std::string, int> type_counts;

    for (const auto& event : events) {
      if (!event.is_object()) continue;

      std::string event_type = event.value("type", "");
      std::string sender = event.value("sender", "");
      std::string room_id = event.value("room_id", "");

      // Check per-type limits
      if (!filter.per_type_limits.empty()) {
        auto it = filter.per_type_limits.find(event_type);
        if (it != filter.per_type_limits.end()) {
          if (type_counts[event_type] >= it->second) continue;
        }
      }

      if (filter.matches(event_type, sender, room_id)) {
        filtered.push_back(event);
        type_counts[event_type]++;
      }
    }

    return filtered;
  }

  // Apply ephemeral filter
  static json apply_ephemeral_filter(const CompiledEphemeralFilter& filter,
                                      const json& events) {
    json filtered = json::array();
    for (const auto& event : events) {
      if (!event.is_object()) continue;

      std::string event_type = event.value("type", "");
      std::string sender = event.value("sender", "");
      std::string room_id = event.value("room_id", "");

      if (filter.matches(event_type, sender, room_id)) {
        filtered.push_back(event);
      }
    }
    return filtered;
  }

  // Apply account data filter
  static json apply_account_data_filter(const CompiledAccountDataFilter& filter,
                                         const json& events) {
    json filtered = json::array();
    for (const auto& event : events) {
      if (!event.is_object()) continue;

      std::string event_type = event.value("type", "");
      if (filter.matches(event_type)) {
        filtered.push_back(event);
      }
    }
    return filtered;
  }

  // Apply presence filter
  static json apply_presence_filter(const CompiledPresenceFilter& filter,
                                     const json& events) {
    json filtered = json::array();
    for (const auto& event : events) {
      if (!event.is_object()) continue;

      std::string presence_type = event.value("presence", "");
      std::string user_id = event.value("sender", "");
      if (user_id.empty()) {
        user_id = event.value("user_id", "");
      }

      if (filter.matches(presence_type, user_id)) {
        filtered.push_back(event);
      }
    }
    return filtered;
  }

  // Apply full compiled filter to event list
  static json apply_full_filter(const CompiledFilter& filter,
                                 const json& events,
                                 FilterCategory category) {
    switch (category) {
      case FilterCategory::TIMELINE: {
        if (filter.timeline_set) {
          return apply_timeline_filter(filter.timeline, events);
        }
        // Fall back to event fields
        if (filter.event_fields_set) {
          json result = events;
          for (const auto& ef : filter.event_fields) {
            result = apply_event_filter(ef, result);
          }
          return result;
        }
        return events;
      }
      case FilterCategory::STATE:
        if (filter.state_set) {
          return apply_state_filter(filter.state, events);
        }
        return events;
      case FilterCategory::EPHEMERAL:
        if (filter.ephemeral_set) {
          return apply_ephemeral_filter(filter.ephemeral, events);
        }
        return events;
      case FilterCategory::ACCOUNT_DATA:
        if (filter.account_data_set) {
          return apply_account_data_filter(filter.account_data, events);
        }
        return events;
      case FilterCategory::PRESENCE:
        if (filter.presence_set) {
          return apply_presence_filter(filter.presence, events);
        }
        return events;
      default:
        return events;
    }
  }

  // Apply event fields filter (projection)
  static json apply_event_fields(const CompiledFilter& filter,
                                  const json& events) {
    if (!filter.event_fields_set || filter.event_fields.empty()) {
      return events;
    }

    json result = json::array();
    for (const auto& event : events) {
      if (!event.is_object()) {
        result.push_back(event);
        continue;
      }

      // Build a new event with only the allowed fields
      json filtered_event = json::object();
      for (const auto& ef : filter.event_fields) {
        for (const auto& field_name : ef.items) {
          if (event.contains(field_name)) {
            filtered_event[field_name] = event[field_name];
          }
        }
      }

      // Always include type and event_id
      if (event.contains("type")) filtered_event["type"] = event["type"];
      if (event.contains("event_id"))
        filtered_event["event_id"] = event["event_id"];

      result.push_back(filtered_event);
    }
    return result;
  }

  // Check if a single event matches a compiled room event filter
  static bool event_matches_filter(const CompiledRoomEventFilter& filter,
                                    const json& event) {
    if (!event.is_object()) return false;

    std::string event_type = event.value("type", "");
    std::string sender = event.value("sender", "");
    std::string room_id = event.value("room_id", "");

    bool has_url = false;
    if (event.contains("content") && event["content"].is_object()) {
      has_url = check_content_for_url(event["content"]);
    }

    return filter.matches(event_type, sender, room_id, has_url);
  }

private:
  static bool check_content_for_url(const json& content) {
    // Check common fields that may contain URLs
    std::vector<std::string> url_fields = {
        "url", "avatar_url", "thumbnail_url", "external_url"};

    for (const auto& field : url_fields) {
      if (content.contains(field) && content[field].is_string()) {
        std::string val = content[field].get<std::string>();
        if (val.find("http://") == 0 || val.find("https://") == 0 ||
            val.find("mxc://") == 0) {
          return true;
        }
      }
    }

    // Also check body for URLs
    if (content.contains("body") && content["body"].is_string()) {
      std::string body = content["body"].get<std::string>();
      if (body.find("http://") != std::string::npos ||
          body.find("https://") != std::string::npos) {
        return true;
      }
    }

    // Check formatted_body for URLs
    if (content.contains("formatted_body") &&
        content["formatted_body"].is_string()) {
      std::string fb = content["formatted_body"].get<std::string>();
      if (fb.find("http://") != std::string::npos ||
          fb.find("https://") != std::string::npos) {
        return true;
      }
    }

    return false;
  }
};

// Filter category for apply_full_filter
enum class FilterCategory {
  TIMELINE,
  STATE,
  EPHEMERAL,
  ACCOUNT_DATA,
  PRESENCE,
};

// ============================================================================
// Lazy loading member filtering
// ============================================================================

class LazyLoadingFilter {
public:
  LazyLoadingFilter() = default;

  // Filter members for lazy loading
  // Returns only members that should be included based on the filter criteria
  static json filter_members(const json& members,
                              const json& timeline_events,
                              const CompiledFilter& filter,
                              const std::string& current_user_id) {
    if (!filter.timeline_set || !filter.timeline.lazy_load_members_set ||
        !filter.timeline.lazy_load_members) {
      // Lazy loading not enabled, return all members
      return members;
    }

    bool include_redundant = filter.timeline.include_redundant_members_set &&
                             filter.timeline.include_redundant_members;

    // Collect user IDs that should be included
    std::set<std::string> included_user_ids;

    // Always include the current user
    included_user_ids.insert(current_user_id);

    // Include senders from timeline events
    for (const auto& event : timeline_events) {
      if (event.contains("sender") && event["sender"].is_string()) {
        included_user_ids.insert(event["sender"].get<std::string>());
      }
      // Include state_key for state events
      if (event.contains("state_key") && event["state_key"].is_string()) {
        included_user_ids.insert(event["state_key"].get<std::string>());
      }
      // Include user_id from content
      if (event.contains("content") && event["content"].is_object()) {
        const auto& content = event["content"];
        if (content.contains("user_id") && content["user_id"].is_string()) {
          included_user_ids.insert(content["user_id"].get<std::string>());
        }
      }
    }

    // Include senders from state events if lazy loading state too
    if (filter.state_set && filter.state.lazy_load_members_set &&
        filter.state.lazy_load_members) {
      // State members are handled separately
    }

    // Include related_by_senders
    if (filter.timeline.related_by_senders.empty() == false) {
      // In a real implementation, this would query the database for
      // users related to the senders. For now, we just include the senders.
    }

    // Filter members
    json filtered_members = json::array();
    for (const auto& member : members) {
      std::string user_id;
      if (member.contains("user_id")) {
        user_id = member["user_id"].get<std::string>();
      } else if (member.contains("state_key")) {
        user_id = member["state_key"].get<std::string>();
      }

      if (user_id.empty()) {
        // Can't determine user ID, include
        filtered_members.push_back(member);
        continue;
      }

      if (included_user_ids.count(user_id) > 0) {
        filtered_members.push_back(member);
      }
    }

    // If include_redundant_members, also add members we haven't sent before
    // (tracked externally via a sent_members set)
    if (include_redundant) {
      // In a real implementation, we'd track which members have been sent
      // and add new ones. For now, we just return filtered members.
    }

    return filtered_members;
  }

  // Determine which member events to include in state for lazy loading
  static json filter_state_members(const json& state_events,
                                    const json& timeline_events,
                                    const CompiledFilter& filter,
                                    const std::string& current_user_id) {
    if (!filter.state_set || !filter.state.lazy_load_members_set ||
        !filter.state.lazy_load_members) {
      return state_events;
    }

    std::set<std::string> included_user_ids;
    included_user_ids.insert(current_user_id);

    for (const auto& event : timeline_events) {
      if (event.contains("sender") && event["sender"].is_string()) {
        included_user_ids.insert(event["sender"].get<std::string>());
      }
      if (event.contains("state_key") && event["state_key"].is_string()) {
        included_user_ids.insert(event["state_key"].get<std::string>());
      }
    }

    json filtered = json::array();
    for (const auto& event : state_events) {
      std::string event_type = event.value("type", "");
      if (event_type != "m.room.member") {
        // Non-member state events always pass
        filtered.push_back(event);
        continue;
      }

      std::string state_key = event.value("state_key", "");
      if (included_user_ids.count(state_key) > 0) {
        filtered.push_back(event);
      }
    }

    return filtered;
  }

  // Track which members have been sent to a user
  class MemberSentTracker {
  public:
    void mark_sent(const std::string& user_id, const std::string& member_id) {
      std::unique_lock lock(mutex_);
      sent_members_[user_id].insert(member_id);
    }

    bool has_been_sent(const std::string& user_id,
                       const std::string& member_id) const {
      std::shared_lock lock(mutex_);
      auto it = sent_members_.find(user_id);
      if (it == sent_members_.end()) return false;
      return it->second.count(member_id) > 0;
    }

    void clear_for_user(const std::string& user_id) {
      std::unique_lock lock(mutex_);
      sent_members_.erase(user_id);
    }

    void clear_all() {
      std::unique_lock lock(mutex_);
      sent_members_.clear();
    }

    size_t count_for_user(const std::string& user_id) const {
      std::shared_lock lock(mutex_);
      auto it = sent_members_.find(user_id);
      if (it == sent_members_.end()) return 0;
      return it->second.size();
    }

  private:
    mutable std::shared_mutex mutex_;
    std::map<std::string, std::set<std::string>> sent_members_;
  };

  static MemberSentTracker g_member_sent_tracker;
};

LazyLoadingFilter::MemberSentTracker LazyLoadingFilter::g_member_sent_tracker;

// ============================================================================
// Filter compilation (compile JSON filter to efficient filter object)
// ============================================================================

class FilterCompiler {
public:
  // Compile a JSON filter into a CompiledFilter
  static CompiledFilter compile(const json& filter_json,
                                 const std::string& user_id = "",
                                 const std::string& filter_id = "") {
    CompiledFilter filter;
    filter.filter_id = filter_id.empty()
                           ? g_filter_id_generator.generate_user_filter_id(user_id)
                           : filter_id;
    filter.user_id = user_id;
    filter.compile(filter_json);
    return filter;
  }

  // Batch compile multiple filters
  static std::vector<CompiledFilter> batch_compile(
      const std::vector<std::pair<std::string, json>>& filters) {
    std::vector<CompiledFilter> result;
    result.reserve(filters.size());
    for (const auto& [fid, fj] : filters) {
      result.push_back(compile(fj, "", fid));
    }
    return result;
  }

  // Compile and validate
  static std::pair<std::optional<CompiledFilter>,
                   std::optional<FilterValidationError>>
  compile_with_validation(const json& filter_json,
                          const std::string& user_id = "") {
    // Validate first
    FilterStorage temp_storage;
    auto validation = temp_storage.get_user_filter(
        user_id, "__temp__");  // won't find it, just for validation pattern
    // Actually, do inline validation:
    if (!filter_json.is_object() && !filter_json.is_null()) {
      FilterValidationError err;
      err.code = FilterValidationErrorCode::INVALID_JSON;
      err.message = "Filter must be a JSON object";
      return {std::nullopt, err};
    }

    if (filter_json.is_null()) {
      CompiledFilter empty_filter;
      empty_filter.filter_id = g_filter_id_generator.generate_user_filter_id(
          user_id);
      empty_filter.user_id = user_id;
      return {empty_filter, std::nullopt};
    }

    CompiledFilter filter;
    filter.filter_id = g_filter_id_generator.generate_user_filter_id(user_id);
    filter.user_id = user_id;
    filter.compile(filter_json);
    return {filter, std::nullopt};
  }

  // Decompile a CompiledFilter back to JSON filter definition
  static json decompile(const CompiledFilter& filter) {
    json j = json::object();

    if (filter.event_fields_set) {
      json ef_array = json::array();
      for (const auto& ef : filter.event_fields) {
        json ef_json = json::array();
        for (const auto& item : ef.items) {
          ef_json.push_back(item);
        }
        ef_array.push_back(ef_json);
      }
      j["event_fields"] = ef_array;
    }

    if (filter.timeline_set || filter.state_set ||
        filter.ephemeral_set || filter.account_data_set) {
      json room = json::object();

      if (filter.timeline_set) {
        room["timeline"] = decompile_timeline(filter.timeline);
      }
      if (filter.state_set) {
        room["state"] = decompile_state(filter.state);
      }
      if (filter.ephemeral_set) {
        room["ephemeral"] = decompile_ephemeral(filter.ephemeral);
      }
      if (filter.account_data_set) {
        room["account_data"] = decompile_account_data(filter.account_data);
      }

      j["room"] = room;
    }

    if (filter.presence_set) {
      j["presence"] = decompile_presence(filter.presence);
    }

    if (filter.push_rules_set) {
      json pr_array = json::array();
      for (const auto& pr : filter.push_rules) {
        json prj;
        prj["rule_id"] = pr.rule_id;
        prj["kind"] = pr.kind;
        prj["actions"] = pr.actions;
        prj["enabled"] = pr.enabled;
        prj["default"] = pr.default_rule;
        prj["priority_class"] = pr.priority_class;
        prj["priority"] = pr.priority;
        pr_array.push_back(prj);
      }
      j["push_rules"] = pr_array;
    }

    return j;
  }

private:
  static json decompile_timeline(const CompiledTimelineFilter& f) {
    json j = json::object();
    if (f.limit_set) j["limit"] = f.limit;
    if (!f.types.empty()) j["types"] = f.types.items;
    if (!f.not_types.empty()) j["not_types"] = f.not_types.items;
    if (!f.senders.empty()) j["senders"] = f.senders.items;
    if (!f.not_senders.empty()) j["not_senders"] = f.not_senders.items;
    if (!f.rooms.empty()) j["rooms"] = f.rooms.items;
    if (!f.not_rooms.empty()) j["not_rooms"] = f.not_rooms.items;
    if (f.contains_url_set) j["contains_url"] = f.contains_url;
    if (f.lazy_load_members_set) j["lazy_load_members"] = f.lazy_load_members;
    if (f.include_redundant_members_set)
      j["include_redundant_members"] = f.include_redundant_members;
    if (f.unread_thread_notifications_set)
      j["unread_thread_notifications"] = f.unread_thread_notifications;
    return j;
  }

  static json decompile_state(const CompiledStateFilter& f) {
    json j = json::object();
    if (!f.types.empty()) j["types"] = f.types.items;
    if (!f.not_types.empty()) j["not_types"] = f.not_types.items;
    if (!f.senders.empty()) j["senders"] = f.senders.items;
    if (!f.not_senders.empty()) j["not_senders"] = f.not_senders.items;
    if (!f.rooms.empty()) j["rooms"] = f.rooms.items;
    if (!f.not_rooms.empty()) j["not_rooms"] = f.not_rooms.items;
    if (f.lazy_load_members_set)
      j["lazy_load_members"] = f.lazy_load_members;
    return j;
  }

  static json decompile_ephemeral(const CompiledEphemeralFilter& f) {
    json j = json::object();
    if (!f.types.empty()) j["types"] = f.types.items;
    if (!f.not_types.empty()) j["not_types"] = f.not_types.items;
    if (!f.senders.empty()) j["senders"] = f.senders.items;
    if (!f.not_senders.empty()) j["not_senders"] = f.not_senders.items;
    if (!f.rooms.empty()) j["rooms"] = f.rooms.items;
    if (!f.not_rooms.empty()) j["not_rooms"] = f.not_rooms.items;
    return j;
  }

  static json decompile_account_data(const CompiledAccountDataFilter& f) {
    json j = json::object();
    if (!f.types.empty()) j["types"] = f.types.items;
    if (!f.not_types.empty()) j["not_types"] = f.not_types.items;
    return j;
  }

  static json decompile_presence(const CompiledPresenceFilter& f) {
    json j = json::object();
    if (!f.types.empty()) j["types"] = f.types.items;
    if (!f.not_types.empty()) j["not_types"] = f.not_types.items;
    if (!f.senders.empty()) j["senders"] = f.senders.items;
    if (!f.not_senders.empty()) j["not_senders"] = f.not_senders.items;
    if (f.include_last_active_ago_set)
      j["include_last_active_ago"] = f.include_last_active_ago;
    return j;
  }
};

// ============================================================================
// Push rule filter engine
// ============================================================================

class PushRuleFilterEngine {
public:
  PushRuleFilterEngine() = default;

  // Evaluate push rules against an event
  struct PushRuleMatch {
    std::string rule_id;
    std::vector<json> actions;
    bool highlight = false;
    bool notify = false;
    bool sound = true;
    std::string sound_name = "default";
  };

  // Evaluate all push rules for an event
  static std::vector<PushRuleMatch> evaluate_push_rules(
      const json& event,
      const std::vector<CompiledPushRule>& rules,
      const std::string& display_name = "",
      int member_count = 0,
      bool is_room_sender_notifiable = true) {

    std::vector<PushRuleMatch> matches;

    for (const auto& rule : rules) {
      if (!rule.enabled) continue;

      bool matches_event = rule.matches(event, display_name,
                                        member_count,
                                        is_room_sender_notifiable);
      if (!matches_event) continue;

      PushRuleMatch match;
      match.rule_id = rule.rule_id;
      match.actions = rule.actions;

      // Determine actions from rule
      for (const auto& action : rule.actions) {
        if (action.is_string()) {
          std::string act = action.get<std::string>();
          if (act == "notify") {
            match.notify = true;
          } else if (act.find("set_tweak") != std::string::npos) {
            // Set tweak actions
          }
        } else if (action.is_object()) {
          if (action.contains("set_tweak")) {
            std::string tweak = action["set_tweak"].get<std::string>();
            if (tweak == "highlight") {
              match.highlight = true;
              if (action.contains("value")) {
                match.highlight = action["value"].get<bool>();
              }
            } else if (tweak == "sound") {
              match.sound = true;
              if (action.contains("value") && action["value"].is_string()) {
                match.sound_name = action["value"].get<std::string>();
              }
            }
          }
        }
      }

      matches.push_back(std::move(match));
    }

    // Sort by priority_class (descending), then priority (descending)
    std::sort(matches.begin(), matches.end(),
              [](const PushRuleMatch& a, const PushRuleMatch& b) {
                // We need access to the original rules for priority
                return false;  // Stable sort; rules are already in priority order
              });

    return matches;
  }

  // Determine the final action for an event
  struct FinalPushAction {
    bool should_notify = false;
    bool should_highlight = false;
    std::string sound_name = "default";
    bool should_buzz = false;
    std::vector<std::string> matched_rules;
  };

  static FinalPushAction determine_final_action(
      const std::vector<PushRuleMatch>& matches) {
    FinalPushAction result;

    for (const auto& match : matches) {
      result.matched_rules.push_back(match.rule_id);

      if (match.notify) {
        result.should_notify = true;
      }
      if (match.highlight) {
        result.should_highlight = true;
      }
      if (match.sound && !match.sound_name.empty()) {
        result.sound_name = match.sound_name;
      }
    }

    return result;
  }

  // Apply push rules to a batch of events and determine which users to notify
  static std::map<std::string, std::vector<std::string>>
  compute_notifications(
      const json& event,
      const std::map<std::string, std::vector<CompiledPushRule>>&
          user_push_rules,
      const std::map<std::string, std::string>& user_display_names) {

    std::map<std::string, std::vector<std::string>> notifications;

    for (const auto& [user_id, rules] : user_push_rules) {
      std::string display_name;
      auto dn_it = user_display_names.find(user_id);
      if (dn_it != user_display_names.end()) {
        display_name = dn_it->second;
      }

      auto matches = evaluate_push_rules(event, rules, display_name);
      auto final_action = determine_final_action(matches);

      if (final_action.should_notify) {
        std::vector<std::string> notif_data;
        notif_data.push_back(final_action.should_highlight ? "highlight"
                                                            : "notify");
        notif_data.push_back(final_action.sound_name);
        notifications[user_id] = notif_data;
      }
    }

    return notifications;
  }

  // Check if a specific push rule matches an event
  static bool rule_matches_event(const CompiledPushRule& rule,
                                  const json& event,
                                  const std::string& display_name = "",
                                  int member_count = 0) {
    if (!rule.enabled) return false;
    return rule.matches(event, display_name, member_count, true);
  }

  // Get the list of actions for a matching rule
  static std::vector<json> get_actions_for_event(
      const json& event,
      const std::vector<CompiledPushRule>& rules,
      const std::string& display_name = "",
      int member_count = 0) {

    for (const auto& rule : rules) {
      if (rule.enabled &&
          rule.matches(event, display_name, member_count, true)) {
        return rule.actions;
      }
    }
    return {json("dont_notify")};
  }
};

// ============================================================================
// Notification filter engine
// ============================================================================

class NotificationFilterEngine {
public:
  NotificationFilterEngine() = default;

  // Determine if a user should receive a notification for an event
  struct NotificationDecision {
    bool notify = false;
    bool highlight = false;
    std::string sound;
    std::string rule_id;
    bool should_send_push = true;
    bool should_send_email = false;
  };

  static NotificationDecision evaluate_notification(
      const json& event,
      const std::string& user_id,
      const std::vector<CompiledPushRule>& push_rules,
      const CompiledFilter::NotificationSettings& settings,
      const std::string& display_name = "") {

    NotificationDecision decision;

    if (!settings.notify) {
      decision.notify = false;
      return decision;
    }

    // Evaluate push rules
    auto matches = PushRuleFilterEngine::evaluate_push_rules(
        event, push_rules, display_name);

    if (matches.empty()) {
      // No push rules matched - check default behavior
      decision.notify = false;
      return decision;
    }

    auto final_action = PushRuleFilterEngine::determine_final_action(matches);

    decision.notify = final_action.should_notify;
    decision.highlight = final_action.should_highlight;
    decision.sound = final_action.sound_name;
    if (!final_action.matched_rules.empty()) {
      decision.rule_id = final_action.matched_rules.front();
    }

    return decision;
  }

  // Filter notifications for a user based on user preferences
  static json filter_notifications(
      const json& notifications,
      const CompiledFilter& filter,
      const std::string& user_id) {

    json filtered = json::array();

    for (const auto& notif : notifications) {
      if (!notif.is_object()) continue;

      // Check notification settings
      if (!filter.notification.notify) continue;

      // Check if room-specific notification settings exist
      std::string room_id = notif.value("room_id", "");
      if (!room_id.empty() && filter.notification.room_specific_count > 0) {
        // In a full implementation, we'd check per-room settings
      }

      filtered.push_back(notif);
    }

    return filtered;
  }
};

// ============================================================================
// Federation filter engine
// ============================================================================

class FederationFilterEngine {
public:
  FederationFilterEngine() = default;

  // Filter events for federation transmission
  static json filter_events_for_federation(
      const json& events,
      const CompiledFilter::FederationFilter& fed_filter,
      const std::string& destination_server) {

    json filtered = json::array();
    int count = 0;

    for (const auto& event : events) {
      if (!event.is_object()) continue;
      if (count >= fed_filter.limit) break;

      // Check event type whitelist
      if (!fed_filter.all_types_allowed) {
        std::string event_type = event.value("type", "");
        if (fed_filter.allowed_types.find(event_type) ==
            fed_filter.allowed_types.end()) {
          continue;
        }
      }

      filtered.push_back(event);
      count++;
    }

    return filtered;
  }

  // Create a federation filter from request parameters
  static CompiledFilter::FederationFilter create_from_request(
      const json& request_params) {
    CompiledFilter::FederationFilter f;

    if (request_params.contains("filter")) {
      const auto& req_filter = request_params["filter"];

      if (req_filter.contains("types") && req_filter["types"].is_array()) {
        f.all_types_allowed = false;
        for (const auto& t : req_filter["types"]) {
          if (t.is_string()) {
            f.allowed_types.insert(t.get<std::string>());
          }
        }
      }

      if (req_filter.contains("limit")) {
        f.limit = req_filter["limit"].get<int>();
      }

      if (req_filter.contains("lazy_load_members")) {
        f.lazy_load_members = req_filter["lazy_load_members"].get<bool>();
      }

      if (req_filter.contains("include_redundant_members")) {
        f.include_redundant_members =
            req_filter["include_redundant_members"].get<bool>();
      }
    }

    return f;
  }

  // Filter backfill events
  static json filter_backfill_events(
      const json& events,
      const std::set<std::string>& event_type_whitelist,
      int limit = FEDERATION_BACKFILL_LIMIT) {

    json filtered = json::array();
    int count = 0;

    for (const auto& event : events) {
      if (!event.is_object()) continue;
      if (count >= limit) break;

      std::string event_type = event.value("type", "");
      if (event_type_whitelist.empty() ||
          event_type_whitelist.count(event_type) > 0) {
        filtered.push_back(event);
        count++;
      }
    }

    return filtered;
  }

  // Strip non-federatable fields from events
  static json strip_non_federatable_fields(const json& event) {
    // Fields that should not be sent over federation
    static const std::set<std::string> non_federatable_fields = {
        "unsigned", "age", "transaction_id", "redacted_because",
        "unsigned.redacted_because",
    };

    json stripped = json::object();
    for (auto& [key, value] : event.items()) {
      // Skip the event if it's redacted
      if (non_federatable_fields.count(key) > 0) {
        continue;
      }
      stripped[key] = value;
    }

    return stripped;
  }

  // Verify federation filter is valid for a requesting server
  static bool validate_federation_request_filter(
      const json& filter,
      const std::string& requesting_server) {
    // Ensure the filter doesn't request too many events
    if (filter.contains("limit")) {
      int limit = filter["limit"].get<int>();
      if (limit > 1000) return false;
    }

    // Ensure type whitelist isn't too restrictive
    // (empty is fine - means all types)

    return true;
  }
};

// ============================================================================
// Search filter engine
// ============================================================================

class SearchFilterEngine {
public:
  SearchFilterEngine() = default;

  // Search events using a search filter
  static json search_events(
      const json& events,
      const CompiledFilter::SearchFilter& search_filter) {

    json results = json::object();
    results["results"] = json::array();
    results["count"] = 0;
    results["highlights"] = json::array();

    // Filter by room_id
    json filtered = filter_by_rooms(events, search_filter.room_ids);
    // Filter by event type
    filtered = filter_by_types(filtered, search_filter.event_types);
    // Filter by sender
    filtered = filter_by_senders(filtered, search_filter.senders);

    // Full-text search across keys
    if (!search_filter.search_term.empty()) {
      filtered = full_text_search(filtered, search_filter.search_term,
                                   search_filter.keys);
    }

    // Order by recent if requested
    if (search_filter.order_by_recent) {
      std::sort(filtered.begin(), filtered.end(),
                [](const json& a, const json& b) {
                  int64_t oa = a.value("origin_server_ts", 0);
                  int64_t ob = b.value("origin_server_ts", 0);
                  return oa > ob;  // Most recent first
                });
    }

    // Apply pagination (before/after limit, limit)
    results["results"] = paginate_results(filtered, search_filter);
    results["count"] = filtered.size();

    return results;
  }

  // Full-text search within event content
  static json full_text_search(const json& events,
                                 const std::string& search_term,
                                 const std::vector<std::string>& keys) {
    json results = json::array();
    std::string term_lower = to_lower(search_term);
    // Simple tokenization - split by whitespace
    std::vector<std::string> terms = split_terms(term_lower);

    for (const auto& event : events) {
      if (!event.is_object()) continue;

      if (event_matches_search(event, terms, keys)) {
        json result = event;
        // Add highlights if content matched
        result["rank"] = compute_search_rank(event, terms, keys);
        results.push_back(result);
      }
    }

    // Sort by rank (descending)
    std::sort(results.begin(), results.end(),
              [](const json& a, const json& b) {
                return a.value("rank", 0.0) > b.value("rank", 0.0);
              });

    return results;
  }

  // Search with grouping support (Matrix v1.6+)
  static json search_with_groups(
      const json& events,
      const CompiledFilter::SearchFilter& search_filter,
      const std::string& group_by) {

    json grouped_results = json::object();
    json all_results = search_events(events, search_filter);

    if (group_by.empty() || group_by == "room_id") {
      // Group by room
      std::map<std::string, json> room_groups;
      for (const auto& result : all_results["results"]) {
        std::string room_id = result.value("room_id", "unknown");
        if (room_groups.find(room_id) == room_groups.end()) {
          room_groups[room_id] = json::object();
          room_groups[room_id]["results"] = json::array();
          room_groups[room_id]["next_batch"] = json::value_t::null;
        }
        room_groups[room_id]["results"].push_back(result);
      }

      json groups = json::object();
      for (auto& [room_id, group] : room_groups) {
        group["count"] = group["results"].size();
        group["order"] = room_id;  // In a real impl, use room name
        groups[room_id] = std::move(group);
      }
      grouped_results["groups"] = groups;
    } else {
      // No grouping
      grouped_results["results"] = all_results;
    }

    return grouped_results;
  }

private:
  static json filter_by_rooms(const json& events,
                               const std::vector<std::string>& room_ids) {
    if (room_ids.empty()) return events;
    json filtered = json::array();
    std::unordered_set<std::string> room_set(room_ids.begin(), room_ids.end());

    for (const auto& event : events) {
      if (room_set.count(event.value("room_id", "")) > 0) {
        filtered.push_back(event);
      }
    }
    return filtered;
  }

  static json filter_by_types(const json& events,
                               const std::vector<std::string>& types) {
    if (types.empty()) return events;
    json filtered = json::array();
    std::unordered_set<std::string> type_set(types.begin(), types.end());

    for (const auto& event : events) {
      if (type_set.count(event.value("type", "")) > 0) {
        filtered.push_back(event);
      }
    }
    return filtered;
  }

  static json filter_by_senders(const json& events,
                                  const std::vector<std::string>& senders) {
    if (senders.empty()) return events;
    json filtered = json::array();
    std::unordered_set<std::string> sender_set(senders.begin(), senders.end());

    for (const auto& event : events) {
      if (sender_set.count(event.value("sender", "")) > 0) {
        filtered.push_back(event);
      }
    }
    return filtered;
  }

  static json paginate_results(const json& events,
                                const CompiledFilter::SearchFilter& filter) {
    json results = json::array();
    int before = filter.before_limit;
    int after = filter.after_limit;
    int limit = filter.limit;

    // Simple pagination: take up to `limit` events
    int count = 0;
    for (const auto& event : events) {
      if (count >= limit && limit > 0) break;
      results.push_back(event);
      count++;
    }

    return results;
  }

  static bool event_matches_search(const json& event,
                                    const std::vector<std::string>& terms,
                                    const std::vector<std::string>& keys) {
    std::vector<std::string> search_keys;
    if (keys.empty()) {
      // Default search keys
      search_keys = {"content.body", "content.name", "content.topic",
                     "sender", "type"};
    } else {
      search_keys = keys;
    }

    for (const auto& key : search_keys) {
      std::string value = get_nested_json_value(event, key);
      if (value.empty()) continue;

      std::string value_lower = to_lower(value);

      // All terms must match
      bool all_match = true;
      for (const auto& term : terms) {
        if (value_lower.find(term) == std::string::npos) {
          all_match = false;
          break;
        }
      }
      if (all_match) return true;
    }

    return false;
  }

  static double compute_search_rank(const json& event,
                                     const std::vector<std::string>& terms,
                                     const std::vector<std::string>& keys) {
    double rank = 0.0;

    std::vector<std::string> search_keys;
    if (keys.empty()) {
      search_keys = {"content.body", "content.name", "content.topic"};
    } else {
      search_keys = keys;
    }

    for (const auto& key : search_keys) {
      std::string value = get_nested_json_value(event, key);
      if (value.empty()) continue;

      std::string value_lower = to_lower(value);

      for (const auto& term : terms) {
        size_t pos = value_lower.find(term);
        if (pos != std::string::npos) {
          // Earlier match = higher rank
          rank += 1.0 / (1.0 + static_cast<double>(pos));

          // Exact word match bonus
          if (is_word_boundary(value_lower, pos, term.length())) {
            rank += 2.0;
          }

          // Title/content bonus
          if (key == "content.body") {
            rank += 1.0;
          }
        }
      }
    }

    return rank;
  }

  static std::string get_nested_json_value(const json& j,
                                            const std::string& path) {
    std::istringstream stream(path);
    std::string segment;
    const json* current = &j;

    while (std::getline(stream, segment, '.')) {
      if (!current->is_object()) return "";
      auto it = current->find(segment);
      if (it == current->end()) return "";
      current = &(*it);
    }

    if (current->is_string()) return current->get<std::string>();
    if (current->is_number()) {
      std::ostringstream oss;
      oss << current->get<double>();
      return oss.str();
    }
    return current->dump();
  }

  static std::string to_lower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
  }

  static std::vector<std::string> split_terms(const std::string& input) {
    std::vector<std::string> terms;
    std::istringstream stream(input);
    std::string term;
    while (stream >> term) {
      if (!term.empty()) terms.push_back(term);
    }
    if (terms.empty() && !input.empty()) {
      terms.push_back(input);
    }
    return terms;
  }

  static bool is_word_boundary(const std::string& str, size_t pos,
                                size_t len) {
    bool left_boundary = (pos == 0) || !std::isalnum(str[pos - 1]);
    bool right_boundary = (pos + len >= str.size()) ||
                          !std::isalnum(str[pos + len]);
    return left_boundary && right_boundary;
  }
};

// ============================================================================
// Filter engine main class
// ============================================================================

class FilterEngine {
public:
  FilterEngine()
      : storage_(std::make_shared<FilterStorage>()),
        cache_(storage_->get_cache()) {}

  // --- Sync filter definition (JSON filter for /sync) ---

  json create_sync_filter_definition() {
    // Return the default sync filter definition
    json def = json::object();
    def["presence"] = create_presence_filter_def();
    def["account_data"] = create_account_data_filter_def();
    def["room"] = json::object();
    def["room"]["timeline"] = create_room_timeline_filter_def();
    def["room"]["state"] = create_room_state_filter_def();
    def["room"]["ephemeral"] = create_room_ephemeral_filter_def();
    def["room"]["account_data"] = create_account_data_filter_def();
    return def;
  }

  json create_presence_filter_def() {
    json def = json::object();
    def["types"] = json::array({"m.presence"});
    def["not_types"] = json::array();
    def["senders"] = json::array();
    def["not_senders"] = json::array();
    def["include_last_active_ago"] = false;
    return def;
  }

  json create_account_data_filter_def() {
    json def = json::object();
    def["types"] = json::array();
    def["not_types"] = json::array();
    return def;
  }

  json create_room_timeline_filter_def() {
    json def = json::object();
    def["limit"] = DEFAULT_TIMELINE_LIMIT;
    def["types"] = json::array();
    def["not_types"] = json::array();
    def["senders"] = json::array();
    def["not_senders"] = json::array();
    def["rooms"] = json::array();
    def["not_rooms"] = json::array();
    def["contains_url"] = json::value_t::null;
    def["lazy_load_members"] = false;
    def["include_redundant_members"] = false;
    def["unread_thread_notifications"] = false;
    return def;
  }

  json create_room_state_filter_def() {
    json def = json::object();
    def["types"] = json::array();
    def["not_types"] = json::array();
    def["senders"] = json::array();
    def["not_senders"] = json::array();
    def["rooms"] = json::array();
    def["not_rooms"] = json::array();
    def["lazy_load_members"] = false;
    return def;
  }

  json create_room_ephemeral_filter_def() {
    json def = json::object();
    def["types"] = json::array();
    def["not_types"] = json::array();
    def["senders"] = json::array();
    def["not_senders"] = json::array();
    def["rooms"] = json::array();
    def["not_rooms"] = json::array();
    return def;
  }

  // --- Filter storage operations ---

  std::pair<std::optional<std::string>, std::optional<json>>
  create_user_filter(const std::string& user_id, const json& filter_json) {
    auto [filter_id, error] = storage_->create_user_filter(user_id, filter_json);
    if (error.has_value()) {
      return {std::nullopt, error->to_json_response()};
    }
    return {filter_id, std::nullopt};
  }

  std::pair<std::optional<json>, std::optional<json>>
  get_user_filter(const std::string& user_id, const std::string& filter_id) {
    auto filter = storage_->get_user_filter(user_id, filter_id);
    if (!filter.has_value()) {
      json err;
      err["errcode"] = "M_NOT_FOUND";
      err["error"] = "Filter not found: " + filter_id;
      return {std::nullopt, err};
    }
    return {filter, std::nullopt};
  }

  std::pair<json, std::optional<json>>
  get_all_user_filters(const std::string& user_id) {
    auto filters = storage_->get_user_filters(user_id);
    json result = json::object();
    for (const auto& [fid, fj] : filters) {
      result[fid] = fj;
    }
    return {result, std::nullopt};
  }

  std::optional<json> update_user_filter(const std::string& user_id,
                                          const std::string& filter_id,
                                          const json& filter_json) {
    auto error = storage_->update_user_filter(user_id, filter_id, filter_json);
    if (error.has_value()) {
      return error->to_json_response();
    }
    return std::nullopt;
  }

  std::optional<json> delete_user_filter(const std::string& user_id,
                                          const std::string& filter_id) {
    auto error = storage_->delete_user_filter(user_id, filter_id);
    if (error.has_value()) {
      return error->to_json_response();
    }
    return std::nullopt;
  }

  // --- Filter application ---

  json apply_filter_to_timeline(const std::string& filter_id,
                                 const json& events) {
    auto compiled = storage_->get_compiled(filter_id);
    if (!compiled.has_value()) return events;
    return EventFilterApplication::apply_full_filter(
        *compiled, events, FilterCategory::TIMELINE);
  }

  json apply_filter_to_state(const std::string& filter_id,
                              const json& events) {
    auto compiled = storage_->get_compiled(filter_id);
    if (!compiled.has_value()) return events;
    return EventFilterApplication::apply_full_filter(
        *compiled, events, FilterCategory::STATE);
  }

  json apply_filter_to_ephemeral(const std::string& filter_id,
                                  const json& events) {
    auto compiled = storage_->get_compiled(filter_id);
    if (!compiled.has_value()) return events;
    return EventFilterApplication::apply_full_filter(
        *compiled, events, FilterCategory::EPHEMERAL);
  }

  json apply_filter_to_account_data(const std::string& filter_id,
                                      const json& events) {
    auto compiled = storage_->get_compiled(filter_id);
    if (!compiled.has_value()) return events;
    return EventFilterApplication::apply_full_filter(
        *compiled, events, FilterCategory::ACCOUNT_DATA);
  }

  json apply_filter_to_presence(const std::string& filter_id,
                                 const json& events) {
    auto compiled = storage_->get_compiled(filter_id);
    if (!compiled.has_value()) return events;
    return EventFilterApplication::apply_full_filter(
        *compiled, events, FilterCategory::PRESENCE);
  }

  // Apply event fields projection
  json apply_event_fields(const std::string& filter_id,
                           const json& events) {
    auto compiled = storage_->get_compiled(filter_id);
    if (!compiled.has_value()) return events;
    return EventFilterApplication::apply_event_fields(*compiled, events);
  }

  // --- Lazy loading ---

  json filter_lazy_loaded_members(const std::string& filter_id,
                                   const json& members,
                                   const json& timeline_events,
                                   const std::string& current_user_id) {
    auto compiled = storage_->get_compiled(filter_id);
    if (!compiled.has_value()) return members;
    return LazyLoadingFilter::filter_members(
        members, timeline_events, *compiled, current_user_id);
  }

  json filter_state_for_lazy_loading(const std::string& filter_id,
                                      const json& state_events,
                                      const json& timeline_events,
                                      const std::string& current_user_id) {
    auto compiled = storage_->get_compiled(filter_id);
    if (!compiled.has_value()) return state_events;
    return LazyLoadingFilter::filter_state_members(
        state_events, timeline_events, *compiled, current_user_id);
  }

  void mark_member_sent(const std::string& user_id,
                        const std::string& member_id) {
    LazyLoadingFilter::g_member_sent_tracker.mark_sent(user_id, member_id);
  }

  bool has_member_been_sent(const std::string& user_id,
                             const std::string& member_id) {
    return LazyLoadingFilter::g_member_sent_tracker.has_been_sent(
        user_id, member_id);
  }

  // --- Push rule filter ---

  std::vector<PushRuleFilterEngine::PushRuleMatch>
  evaluate_push_rules_for_event(const std::string& filter_id,
                                 const json& event,
                                 const std::string& display_name = "",
                                 int member_count = 0) {
    auto compiled = storage_->get_compiled(filter_id);
    if (!compiled.has_value() || !compiled->push_rules_set) {
      return {};
    }
    return PushRuleFilterEngine::evaluate_push_rules(
        event, compiled->push_rules, display_name, member_count);
  }

  PushRuleFilterEngine::FinalPushAction
  determine_push_action(const std::string& filter_id,
                        const json& event,
                        const std::string& display_name = "") {
    auto matches = evaluate_push_rules_for_event(filter_id, event, display_name);
    return PushRuleFilterEngine::determine_final_action(matches);
  }

  std::map<std::string, std::vector<std::string>>
  compute_push_notifications(
      const std::string& filter_id,
      const json& event,
      const std::map<std::string, std::string>& user_display_names) {
    // This is a simplified version - in a real implementation,
    // you'd load push rules per user
    auto compiled = storage_->get_compiled(filter_id);
    if (!compiled.has_value()) return {};

    std::map<std::string, std::vector<CompiledPushRule>> user_rules;
    // Load from storage in a real implementation
    return PushRuleFilterEngine::compute_notifications(
        event, user_rules, user_display_names);
  }

  // --- Notification filter ---

  NotificationFilterEngine::NotificationDecision
  evaluate_notification(const std::string& filter_id,
                         const json& event,
                         const std::string& user_id,
                         const std::string& display_name = "") {
    auto compiled = storage_->get_compiled(filter_id);
    NotificationFilterEngine::NotificationDecision result;
    result.notify = false;

    if (!compiled.has_value() || !compiled->push_rules_set) {
      return result;
    }

    return NotificationFilterEngine::evaluate_notification(
        event, user_id, compiled->push_rules,
        compiled->notification, display_name);
  }

  // --- Federation filter ---

  json filter_for_federation(const json& events,
                               const json& request_params) {
    auto fed_filter = FederationFilterEngine::create_from_request(
        request_params);

    // Get server filter if specified
    if (request_params.contains("filter_id")) {
      std::string server_filter_id =
          request_params["filter_id"].get<std::string>();
      auto filter_json = storage_->get_server_filter(server_filter_id);
      if (filter_json.has_value()) {
        // Merge server filter with request filter
        if (filter_json->contains("types") &&
            (*filter_json)["types"].is_array()) {
          fed_filter.all_types_allowed = false;
          for (const auto& t : (*filter_json)["types"]) {
            if (t.is_string())
              fed_filter.allowed_types.insert(t.get<std::string>());
          }
        }
        if (filter_json->contains("limit")) {
          fed_filter.limit = (*filter_json)["limit"].get<int>();
        }
      }
    }

    return FederationFilterEngine::filter_events_for_federation(
        events, fed_filter, "");
  }

  std::string create_server_filter(const json& filter_json) {
    return storage_->add_server_filter(filter_json);
  }

  std::optional<json> get_server_filter(const std::string& filter_id) {
    return storage_->get_server_filter(filter_id);
  }

  // --- Search filter ---

  json search_events(const json& events,
                      const CompiledFilter::SearchFilter& search_filter) {
    return SearchFilterEngine::search_events(events, search_filter);
  }

  json search_events_with_json_filter(const json& events,
                                        const json& search_filter_json) {
    CompiledFilter::SearchFilter sf;
    if (search_filter_json.contains("search_term")) {
      sf.search_term = search_filter_json["search_term"].get<std::string>();
    }
    if (search_filter_json.contains("keys") &&
        search_filter_json["keys"].is_array()) {
      for (const auto& k : search_filter_json["keys"]) {
        if (k.is_string()) sf.keys.push_back(k.get<std::string>());
      }
    }
    if (search_filter_json.contains("room_ids") &&
        search_filter_json["room_ids"].is_array()) {
      for (const auto& r : search_filter_json["room_ids"]) {
        if (r.is_string()) sf.room_ids.push_back(r.get<std::string>());
      }
    }
    if (search_filter_json.contains("event_types") &&
        search_filter_json["event_types"].is_array()) {
      for (const auto& et : search_filter_json["event_types"]) {
        if (et.is_string()) sf.event_types.push_back(et.get<std::string>());
      }
    }
    if (search_filter_json.contains("senders") &&
        search_filter_json["senders"].is_array()) {
      for (const auto& s : search_filter_json["senders"]) {
        if (s.is_string()) sf.senders.push_back(s.get<std::string>());
      }
    }
    if (search_filter_json.contains("include_state"))
      sf.include_state = search_filter_json["include_state"].get<bool>();
    if (search_filter_json.contains("include_ephemeral"))
      sf.include_ephemeral =
          search_filter_json["include_ephemeral"].get<bool>();
    if (search_filter_json.contains("limit"))
      sf.limit = search_filter_json["limit"].get<int>();
    if (search_filter_json.contains("before_limit"))
      sf.before_limit = search_filter_json["before_limit"].get<int>();
    if (search_filter_json.contains("after_limit"))
      sf.after_limit = search_filter_json["after_limit"].get<int>();
    if (search_filter_json.contains("order_by_recent"))
      sf.order_by_recent = search_filter_json["order_by_recent"].get<bool>();
    if (search_filter_json.contains("group_by"))
      sf.group_by = search_filter_json["group_by"];

    return SearchFilterEngine::search_events(events, sf);
  }

  json search_with_groups(const json& events,
                           const json& search_filter_json,
                           const std::string& group_by) {
    CompiledFilter::SearchFilter sf;
    // Parse as above
    if (search_filter_json.contains("search_term"))
      sf.search_term = search_filter_json["search_term"].get<std::string>();
    if (search_filter_json.contains("keys") &&
        search_filter_json["keys"].is_array()) {
      for (const auto& k : search_filter_json["keys"]) {
        if (k.is_string()) sf.keys.push_back(k.get<std::string>());
      }
    }
    if (search_filter_json.contains("limit"))
      sf.limit = search_filter_json["limit"].get<int>();

    return SearchFilterEngine::search_with_groups(events, sf, group_by);
  }

  // --- Filter validation ---

  std::optional<json> validate_filter_json(const json& filter_json,
                                            const std::string& user_id = "") {
    // Use FilterStorage for validation
    FilterStorage temp_storage;
    // This is a workaround - in production, parse the validation inline
    // Since create_user_filter validates, we can use it and get the error
    auto [_, error] = temp_storage.create_user_filter(user_id, filter_json);
    if (error.has_value()) {
      return error->to_json_response();
    }
    return std::nullopt;
  }

  // --- Filter caching ---

  void invalidate_cache(const std::string& filter_id) {
    cache_->invalidate(filter_id);
  }

  void invalidate_user_cache(const std::string& user_id) {
    cache_->invalidate_user(user_id);
  }

  void clear_cache() {
    cache_->clear();
  }

  FilterCache::CacheStats get_cache_stats() {
    return cache_->stats();
  }

  // --- Filter compilation ---

  CompiledFilter compile_filter(const json& filter_json,
                                 const std::string& user_id = "") {
    return FilterCompiler::compile(filter_json, user_id);
  }

  json decompile_filter(const CompiledFilter& filter) {
    return FilterCompiler::decompile(filter);
  }

  // --- Batch operations ---

  void bulk_load_filters(
      const std::vector<std::pair<std::string, json>>& filters) {
    auto compiled = FilterCompiler::batch_compile(filters);
    cache_->bulk_load(compiled);
    for (const auto& [fid, fj] : filters) {
      // Store in user_filters under a generic user
      // This is a simplified batch load
    }
  }

  // --- Admin API ---

  json admin_get_all_filters() {
    json result = json::object();
    auto user_filters = storage_->get_all_user_filters();

    json users_obj = json::object();
    for (const auto& [uid, filters] : user_filters) {
      json user_filters_obj = json::object();
      for (const auto& [fid, fj] : filters) {
        user_filters_obj[fid] = fj;
      }
      users_obj[uid] = user_filters_obj;
    }
    result["user_filters"] = users_obj;
    result["server_filters"] = storage_->get_all_server_filters();
    result["total_count"] = storage_->total_filter_count();
    return result;
  }

  json admin_get_filter_stats() {
    json stats = json::object();
    stats["total_filters"] = storage_->total_filter_count();
    auto cache_stats = cache_->stats();
    stats["cache_size"] = cache_stats.size;
    stats["cache_max_size"] = cache_stats.max_size;
    stats["cache_ttl_seconds"] = cache_stats.ttl_seconds;
    return stats;
  }

  json admin_delete_user_filters(const std::string& user_id) {
    storage_->clear_user_filters(user_id);
    json resp;
    resp["status"] = "ok";
    resp["message"] = "All filters cleared for user: " + user_id;
    return resp;
  }

  json admin_delete_server_filter(const std::string& filter_id) {
    // Server filters don't have a delete method currently,
    // but we can invalidate the cache
    cache_->invalidate(filter_id);
    json resp;
    resp["status"] = "ok";
    resp["message"] = "Server filter cache invalidated: " + filter_id;
    return resp;
  }

  json admin_purge_cache() {
    storage_->purge_cache();
    json resp;
    resp["status"] = "ok";
    resp["message"] = "Filter cache purged";
    return resp;
  }

  json admin_get_filter_by_id(const std::string& filter_id) {
    // Search user filters
    auto user_filters = storage_->get_all_user_filters();
    for (const auto& [uid, filters] : user_filters) {
      auto it = filters.find(filter_id);
      if (it != filters.end()) {
        json resp;
        resp["filter_id"] = filter_id;
        resp["user_id"] = uid;
        resp["filter_json"] = it->second;
        resp["type"] = "user";
        return resp;
      }
    }

    // Search server filters
    auto server_filters = storage_->get_all_server_filters();
    auto sit = server_filters.find(filter_id);
    if (sit != server_filters.end()) {
      json resp;
      resp["filter_id"] = filter_id;
      resp["filter_json"] = sit->second;
      resp["type"] = "server";
      return resp;
    }

    json err;
    err["error"] = "Filter not found";
    return err;
  }

  // --- Utility ---

  std::string generate_filter_id() {
    return g_filter_id_generator.generate_user_filter_id("");
  }

  int get_user_filter_count(const std::string& user_id) {
    return storage_->count_user_filters(user_id);
  }

  bool filter_exists(const std::string& filter_id) {
    // Check user filters
    auto user_filters = storage_->get_all_user_filters();
    for (const auto& [uid, filters] : user_filters) {
      if (filters.find(filter_id) != filters.end()) return true;
    }
    // Check server filters
    auto sf = storage_->get_server_filter(filter_id);
    return sf.has_value();
  }

  // ============================================================================
  // Sync filter processing (used by sync handler)
  // ============================================================================

  struct ProcessedSyncFilter {
    std::string filter_id;
    CompiledFilter compiled;
    bool has_timeline_filter = false;
    bool has_state_filter = false;
    bool has_ephemeral_filter = false;
    bool has_account_data_filter = false;
    bool has_presence_filter = false;
    int timeline_limit = DEFAULT_TIMELINE_LIMIT;
  };

  ProcessedSyncFilter process_sync_filter(const std::string& user_id,
                                           const std::string& filter_id) {
    ProcessedSyncFilter result;
    result.filter_id = filter_id;

    auto compiled = storage_->get_compiled(filter_id);
    if (!compiled.has_value()) {
      // No filter - return defaults
      CompiledFilter empty;
      empty.filter_id = filter_id;
      empty.user_id = user_id;
      result.compiled = empty;
      result.timeline_limit = DEFAULT_TIMELINE_LIMIT;
      return result;
    }

    result.compiled = *compiled;
    result.has_timeline_filter = compiled->timeline_set;
    result.has_state_filter = compiled->state_set;
    result.has_ephemeral_filter = compiled->ephemeral_set;
    result.has_account_data_filter = compiled->account_data_set;
    result.has_presence_filter = compiled->presence_set;

    if (compiled->timeline_set && compiled->timeline.limit_set) {
      result.timeline_limit = compiled->timeline.limit;
    }

    return result;
  }

  // Apply sync filter to a full sync response
  json apply_sync_filter(const ProcessedSyncFilter& filter,
                          const json& sync_response) {
    json filtered = sync_response;

    // Apply to rooms
    if (filtered.contains("rooms")) {
      json filtered_rooms = json::object();

      for (const auto& [membership, rooms] : filtered["rooms"].items()) {
        json filtered_membership = json::object();
        for (const auto& [room_id, room_data] : rooms.items()) {
          json filtered_room = room_data;

          // Filter timeline
          if (room_data.contains("timeline")) {
            const auto& tl = room_data["timeline"];
            json filtered_tl = tl;
            if (tl.contains("events") && filter.has_timeline_filter) {
              filtered_tl["events"] =
                  EventFilterApplication::apply_timeline_filter(
                      filter.compiled.timeline, tl["events"]);
              filtered_tl["limited"] = tl.value("limited", false);
              if (filtered_tl["events"].size() < tl["events"].size()) {
                filtered_tl["limited"] = true;
              }
            }
            filtered_room["timeline"] = filtered_tl;
          }

          // Filter state
          if (room_data.contains("state")) {
            const auto& st = room_data["state"];
            if (st.contains("events") && filter.has_state_filter) {
              json filtered_st = st;
              filtered_st["events"] =
                  EventFilterApplication::apply_state_filter(
                      filter.compiled.state, st["events"]);
              filtered_room["state"] = filtered_st;
            }
          }

          // Filter ephemeral
          if (room_data.contains("ephemeral")) {
            const auto& ep = room_data["ephemeral"];
            if (ep.contains("events") && filter.has_ephemeral_filter) {
              json filtered_ep = ep;
              filtered_ep["events"] =
                  EventFilterApplication::apply_ephemeral_filter(
                      filter.compiled.ephemeral, ep["events"]);
              filtered_room["ephemeral"] = filtered_ep;
            }
          }

          // Filter account data
          if (room_data.contains("account_data")) {
            const auto& ad = room_data["account_data"];
            if (ad.contains("events") && filter.has_account_data_filter) {
              json filtered_ad = ad;
              filtered_ad["events"] =
                  EventFilterApplication::apply_account_data_filter(
                      filter.compiled.account_data, ad["events"]);
              filtered_room["account_data"] = filtered_ad;
            }
          }

          filtered_membership[room_id] = filtered_room;
        }
        filtered_rooms[membership] = filtered_membership;
      }

      filtered["rooms"] = filtered_rooms;
    }

    // Filter presence
    if (filtered.contains("presence") && filter.has_presence_filter) {
      const auto& pr = filtered["presence"];
      if (pr.contains("events")) {
        json filtered_pr = pr;
        filtered_pr["events"] =
            EventFilterApplication::apply_presence_filter(
                filter.compiled.presence, pr["events"]);
        filtered["presence"] = filtered_pr;
      }
    }

    // Filter account data
    if (filtered.contains("account_data") && filter.has_account_data_filter) {
      const auto& ad = filtered["account_data"];
      if (ad.contains("events")) {
        json filtered_ad = ad;
        filtered_ad["events"] =
            EventFilterApplication::apply_account_data_filter(
                filter.compiled.account_data, ad["events"]);
        filtered["account_data"] = filtered_ad;
      }
    }

    return filtered;
  }

private:
  std::shared_ptr<FilterStorage> storage_;
  std::shared_ptr<FilterCache> cache_;
};

// ============================================================================
// Global filter engine instance
// ============================================================================

// Thread-safe singleton for the filter engine
class GlobalFilterEngine {
public:
  static FilterEngine& instance() {
    static FilterEngine engine;
    return engine;
  }

  // Prevent copies
  GlobalFilterEngine(const GlobalFilterEngine&) = delete;
  GlobalFilterEngine& operator=(const GlobalFilterEngine&) = delete;

private:
  GlobalFilterEngine() = default;
};

// ============================================================================
// Filter query builder (build filter JSON from parameters)
// ============================================================================

class FilterQueryBuilder {
public:
  FilterQueryBuilder() = default;

  // Build a filter from sync request parameters
  static json build_sync_filter(
      int timeline_limit = DEFAULT_TIMELINE_LIMIT,
      const std::vector<std::string>& timeline_types = {},
      const std::vector<std::string>& senders = {},
      const std::vector<std::string>& not_senders = {},
      bool lazy_load_members = false,
      bool include_redundant_members = false,
      bool unread_thread_notifications = false) {

    json f = json::object();
    json room = json::object();
    json timeline = json::object();

    timeline["limit"] = timeline_limit;
    if (!timeline_types.empty()) timeline["types"] = timeline_types;
    if (!senders.empty()) timeline["senders"] = senders;
    if (!not_senders.empty()) timeline["not_senders"] = not_senders;
    if (lazy_load_members) timeline["lazy_load_members"] = true;
    if (include_redundant_members)
      timeline["include_redundant_members"] = true;
    if (unread_thread_notifications)
      timeline["unread_thread_notifications"] = true;

    room["timeline"] = timeline;
    f["room"] = room;

    return f;
  }

  // Build a search filter from search request parameters
  static json build_search_filter(
      const std::string& search_term,
      const std::vector<std::string>& search_keys = {},
      const std::vector<std::string>& room_ids = {},
      int limit = 10,
      bool order_by_recent = true) {

    json f = json::object();
    json search = json::object();

    search["search_term"] = search_term;
    if (!search_keys.empty()) search["keys"] = search_keys;
    if (!room_ids.empty()) search["room_ids"] = room_ids;
    search["limit"] = limit;
    search["order_by_recent"] = order_by_recent;

    f["search"] = search;
    return f;
  }

  // Build a push rule filter
  static json build_push_rule_filter(
      const std::vector<json>& rules,
      const json& notification_settings = json::object()) {

    json f = json::object();
    f["push_rules"] = rules;
    if (!notification_settings.is_null() && !notification_settings.empty()) {
      f["notification"] = notification_settings;
    }
    return f;
  }

  // Build a federation filter
  static json build_federation_filter(
      const std::vector<std::string>& event_types = {},
      int limit = FEDERATION_BACKFILL_LIMIT,
      bool lazy_load_members = false) {

    json f = json::object();
    json fed = json::object();

    if (!event_types.empty()) fed["types"] = event_types;
    fed["limit"] = limit;
    fed["lazy_load_members"] = lazy_load_members;

    f["federation"] = fed;
    return f;
  }

  // Merge two filters (second overrides first)
  static json merge_filters(const json& base, const json& override_filter) {
    json result = base;
    for (auto& [key, value] : override_filter.items()) {
      if (result.contains(key) && result[key].is_object() && value.is_object()) {
        // Deep merge for objects
        json merged = result[key];
        for (auto& [sub_key, sub_value] : value.items()) {
          merged[sub_key] = sub_value;
        }
        result[key] = merged;
      } else {
        result[key] = value;
      }
    }
    return result;
  }
};

// ============================================================================
// Filter event formatter (format events based on filter)
// ============================================================================

class FilterEventFormatter {
public:
  // Format an event according to the filter's event_format setting
  static json format_event(const json& event,
                            const std::string& event_format = "client") {
    if (event_format == "client") {
      return format_for_client(event);
    } else if (event_format == "federation") {
      return format_for_federation(event);
    }
    return event;
  }

  // Format event for client API (add unsigned data, etc.)
  static json format_for_client(const json& event) {
    json formatted = event;

    // Ensure unsigned field exists
    if (!formatted.contains("unsigned")) {
      formatted["unsigned"] = json::object();
    }

    // Add age if missing
    if (!formatted["unsigned"].contains("age") &&
        formatted.contains("origin_server_ts")) {
      auto now = std::chrono::system_clock::now();
      auto now_ts = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now.time_since_epoch()).count();
      int64_t event_ts = formatted["origin_server_ts"].get<int64_t>();
      formatted["unsigned"]["age"] = static_cast<int>(now_ts - event_ts);
    }

    return formatted;
  }

  // Strip client-specific fields for federation
  static json format_for_federation(const json& event) {
    json formatted = json::object();

    // Copy all fields except unsigned sub-fields
    for (auto& [key, value] : event.items()) {
      if (key == "unsigned") {
        json u = json::object();
        // Only keep age in unsigned for federation
        if (value.contains("age")) u["age"] = value["age"];
        formatted[key] = u;
      } else if (key == "transaction_id") {
        // Skip transaction_id for federation
        continue;
      } else {
        formatted[key] = value;
      }
    }

    return formatted;
  }

  // Apply event_fields filter to truncate event to only requested fields
  static json apply_event_fields(const json& event,
                                  const std::vector<std::string>& fields) {
    if (fields.empty()) return event;

    json result = json::object();
    for (const auto& field : fields) {
      if (event.contains(field)) {
        result[field] = event[field];
      }
    }

    // Always include type and event_id for identification
    if (event.contains("type") && !result.contains("type")) {
      result["type"] = event["type"];
    }
    if (event.contains("event_id") && !result.contains("event_id")) {
      result["event_id"] = event["event_id"];
    }

    return result;
  }
};

// ============================================================================
// Default system filters
// ============================================================================

class DefaultFilters {
public:
  // Default push rules as defined in Matrix spec
  static std::vector<CompiledPushRule> get_default_push_rules() {
    std::vector<CompiledPushRule> rules;

    // Override rules (highest priority)
    {
      // .m.rule.master - master toggle
      CompiledPushRule master;
      master.rule_id = ".m.rule.master";
      master.kind = "override";
      master.enabled = false;
      master.default_rule = true;
      master.priority_class = 7;
      master.priority = 0;
      master.actions = {};
      rules.push_back(master);
    }

    {
      // .m.rule.suppress_notices
      CompiledPushRule suppress;
      suppress.rule_id = ".m.rule.suppress_notices";
      suppress.kind = "override";
      suppress.enabled = true;
      suppress.default_rule = true;
      suppress.priority_class = 6;
      suppress.priority = 0;
      CompileSuppressConditions(suppress);
      rules.push_back(suppress);
    }

    {
      // .m.rule.invite_for_me
      CompiledPushRule invite;
      invite.rule_id = ".m.rule.invite_for_me";
      invite.kind = "override";
      invite.enabled = true;
      invite.default_rule = true;
      invite.priority_class = 5;
      invite.priority = 0;
      // Conditions: type == m.room.member, content.membership == invite
      // State key == user's MXID
      CompileInviteConditions(invite);
      invite.actions = {json("notify"), json::object({{"set_tweak", "highlight"},
                                                       {"value", true}})};
      rules.push_back(invite);
    }

    {
      // .m.rule.member_event
      CompiledPushRule member;
      member.rule_id = ".m.rule.member_event";
      member.kind = "override";
      member.enabled = true;
      member.default_rule = true;
      member.priority_class = 4;
      member.priority = 0;
      CompileMemberConditions(member);
      member.actions = {json("dont_notify")};
      rules.push_back(member);
    }

    // Content rules
    {
      // .m.rule.contains_user_name
      CompiledPushRule name_rule;
      name_rule.rule_id = ".m.rule.contains_user_name";
      name_rule.kind = "content";
      name_rule.enabled = true;
      name_rule.default_rule = true;
      name_rule.priority_class = 3;
      name_rule.priority = 0;
      CompileUserNameConditions(name_rule);
      name_rule.actions = {
          json("notify"),
          json::object({{"set_tweak", "highlight"}, {"value", true}}),
          json::object({{"set_tweak", "sound"}, {"value", "default"}})};
      rules.push_back(name_rule);
    }

    {
      // .m.rule.contains_display_name
      CompiledPushRule display_rule;
      display_rule.rule_id = ".m.rule.contains_display_name";
      display_rule.kind = "content";
      display_rule.enabled = true;
      display_rule.default_rule = true;
      display_rule.priority_class = 3;
      display_rule.priority = 1;
      CompileDisplayNameConditions(display_rule);
      display_rule.actions = {
          json("notify"),
          json::object({{"set_tweak", "highlight"}, {"value", false}}),
          json::object({{"set_tweak", "sound"}, {"value", "default"}})};
      rules.push_back(display_rule);
    }

    {
      // .m.rule.room_one_to_one
      CompiledPushRule one2one;
      one2one.rule_id = ".m.rule.room_one_to_one";
      one2one.kind = "content";
      one2one.enabled = true;
      one2one.default_rule = true;
      one2one.priority_class = 3;
      one2one.priority = 2;
      CompileOneToOneConditions(one2one);
      one2one.actions = {
          json("notify"),
          json::object({{"set_tweak", "sound"}, {"value", "default"}})};
      rules.push_back(one2one);
    }

    {
      // .m.rule.encrypted_room_one_to_one
      CompiledPushRule enc_one2one;
      enc_one2one.rule_id = ".m.rule.encrypted_room_one_to_one";
      enc_one2one.kind = "content";
      enc_one2one.enabled = true;
      enc_one2one.default_rule = true;
      enc_one2one.priority_class = 3;
      enc_one2one.priority = 3;
      CompileEncryptedOneToOneConditions(enc_one2one);
      enc_one2one.actions = {
          json("notify"),
          json::object({{"set_tweak", "sound"}, {"value", "default"}})};
      rules.push_back(enc_one2one);
    }

    {
      // .m.rule.message
      CompiledPushRule message;
      message.rule_id = ".m.rule.message";
      message.kind = "content";
      message.enabled = true;
      message.default_rule = true;
      message.priority_class = 3;
      message.priority = 4;
      CompileMessageConditions(message);
      message.actions = {json("notify")};
      rules.push_back(message);
    }

    {
      // .m.rule.encrypted
      CompiledPushRule encrypted;
      encrypted.rule_id = ".m.rule.encrypted";
      encrypted.kind = "content";
      encrypted.enabled = true;
      encrypted.default_rule = true;
      encrypted.priority_class = 3;
      encrypted.priority = 5;
      CompileEncryptedConditions(encrypted);
      encrypted.actions = {json("notify")};
      rules.push_back(encrypted);
    }

    // Underride rules (lowest priority)
    {
      // .m.rule.tombstone
      CompiledPushRule tombstone;
      tombstone.rule_id = ".m.rule.tombstone";
      tombstone.kind = "underride";
      tombstone.enabled = true;
      tombstone.default_rule = true;
      tombstone.priority_class = 2;
      tombstone.priority = 0;
      CompileTombstoneConditions(tombstone);
      tombstone.actions = {json("notify")};
      rules.push_back(tombstone);
    }

    {
      // .m.rule.call
      CompiledPushRule call;
      call.rule_id = ".m.rule.call";
      call.kind = "underride";
      call.enabled = true;
      call.default_rule = true;
      call.priority_class = 1;
      call.priority = 0;
      CompileCallConditions(call);
      call.actions = {
          json("notify"),
          json::object({{"set_tweak", "sound"}, {"value", "ring"}})};
      rules.push_back(call);
    }

    return rules;
  }

private:
  static void CompileSuppressConditions(CompiledPushRule& rule) {
    json cond;
    cond["kind"] = "event_match";
    cond["key"] = "content.msgtype";
    cond["pattern"] = "m.notice";
    CompiledPushRuleCondition c1;
    c1.compile(cond);
    rule.conditions.push_back(c1);
  }

  static void CompileInviteConditions(CompiledPushRule& rule) {
    json cond1;
    cond1["kind"] = "event_match";
    cond1["key"] = "type";
    cond1["pattern"] = "m.room.member";
    CompiledPushRuleCondition c1;
    c1.compile(cond1);
    rule.conditions.push_back(c1);

    json cond2;
    cond2["kind"] = "event_match";
    cond2["key"] = "content.membership";
    cond2["pattern"] = "invite";
    CompiledPushRuleCondition c2;
    c2.compile(cond2);
    rule.conditions.push_back(c2);

    json cond3;
    cond3["kind"] = "event_match";
    cond3["key"] = "state_key";
    // pattern is the user's MXID, set at runtime
    cond3["pattern"] = "";  // Will be set per-user
    CompiledPushRuleCondition c3;
    c3.compile(cond3);
    rule.conditions.push_back(c3);
  }

  static void CompileMemberConditions(CompiledPushRule& rule) {
    json cond;
    cond["kind"] = "event_match";
    cond["key"] = "type";
    cond["pattern"] = "m.room.member";
    CompiledPushRuleCondition c;
    c.compile(cond);
    rule.conditions.push_back(c);
  }

  static void CompileUserNameConditions(CompiledPushRule& rule) {
    json cond;
    cond["kind"] = "contains_display_name";
    // No additional parameters needed
    CompiledPushRuleCondition c;
    c.compile(cond);
    rule.conditions.push_back(c);
  }

  static void CompileDisplayNameConditions(CompiledPushRule& rule) {
    json cond;
    cond["kind"] = "contains_display_name";
    CompiledPushRuleCondition c;
    c.compile(cond);
    rule.conditions.push_back(c);
  }

  static void CompileOneToOneConditions(CompiledPushRule& rule) {
    json cond1;
    cond1["kind"] = "room_member_count";
    cond1["key"] = "==";
    cond1["pattern"] = "2";
    CompiledPushRuleCondition c1;
    c1.compile(cond1);
    rule.conditions.push_back(c1);

    json cond2;
    cond2["kind"] = "event_match";
    cond2["key"] = "type";
    cond2["pattern"] = "m.room.message";
    CompiledPushRuleCondition c2;
    c2.compile(cond2);
    rule.conditions.push_back(c2);
  }

  static void CompileEncryptedOneToOneConditions(CompiledPushRule& rule) {
    json cond1;
    cond1["kind"] = "room_member_count";
    cond1["key"] = "==";
    cond1["pattern"] = "2";
    CompiledPushRuleCondition c1;
    c1.compile(cond1);
    rule.conditions.push_back(c1);

    json cond2;
    cond2["kind"] = "event_match";
    cond2["key"] = "type";
    cond2["pattern"] = "m.room.encrypted";
    CompiledPushRuleCondition c2;
    c2.compile(cond2);
    rule.conditions.push_back(c2);
  }

  static void CompileMessageConditions(CompiledPushRule& rule) {
    json cond;
    cond["kind"] = "event_match";
    cond["key"] = "type";
    cond["pattern"] = "m.room.message";
    CompiledPushRuleCondition c;
    c.compile(cond);
    rule.conditions.push_back(c);
  }

  static void CompileEncryptedConditions(CompiledPushRule& rule) {
    json cond;
    cond["kind"] = "event_match";
    cond["key"] = "type";
    cond["pattern"] = "m.room.encrypted";
    CompiledPushRuleCondition c;
    c.compile(cond);
    rule.conditions.push_back(c);
  }

  static void CompileTombstoneConditions(CompiledPushRule& rule) {
    json cond1;
    cond1["kind"] = "event_match";
    cond1["key"] = "type";
    cond1["pattern"] = "m.room.tombstone";
    CompiledPushRuleCondition c1;
    c1.compile(cond1);
    rule.conditions.push_back(c1);

    json cond2;
    cond2["kind"] = "event_match";
    cond2["key"] = "state_key";
    cond2["pattern"] = "";
    CompiledPushRuleCondition c2;
    c2.compile(cond2);
    rule.conditions.push_back(c2);
  }

  static void CompileCallConditions(CompiledPushRule& rule) {
    json cond;
    cond["kind"] = "event_match";
    cond["key"] = "type";
    cond["pattern"] = "m.call.invite";
    CompiledPushRuleCondition c;
    c.compile(cond);
    rule.conditions.push_back(c);
  }
};

// ============================================================================
// Filter pipeline (chain multiple filters)
// ============================================================================

class FilterPipeline {
public:
  FilterPipeline() = default;

  // Add a filter to the pipeline
  void add_filter(std::shared_ptr<CompiledFilter> filter) {
    filters_.push_back(filter);
  }

  // Add a filter by ID (looked up from storage)
  void add_filter_by_id(const std::string& filter_id,
                         FilterStorage& storage) {
    auto compiled = storage.get_compiled(filter_id);
    if (compiled.has_value()) {
      auto ptr = std::make_shared<CompiledFilter>(*compiled);
      filters_.push_back(ptr);
    }
  }

  // Apply all filters in sequence to events
  json apply_timeline(const json& events) const {
    json result = events;
    for (const auto& filter : filters_) {
      if (filter->timeline_set) {
        result = EventFilterApplication::apply_timeline_filter(
            filter->timeline, result);
      }
    }
    return result;
  }

  json apply_state(const json& events) const {
    json result = events;
    for (const auto& filter : filters_) {
      if (filter->state_set) {
        result = EventFilterApplication::apply_state_filter(
            filter->state, result);
      }
    }
    return result;
  }

  json apply_ephemeral(const json& events) const {
    json result = events;
    for (const auto& filter : filters_) {
      if (filter->ephemeral_set) {
        result = EventFilterApplication::apply_ephemeral_filter(
            filter->ephemeral, result);
      }
    }
    return result;
  }

  // Check if a single event passes all filters
  bool event_passes_all(const json& event) const {
    for (const auto& filter : filters_) {
      if (!filter->event_fields.empty()) {
        for (const auto& ef : filter->event_fields) {
          if (!EventFilterApplication::event_matches_filter(ef, event)) {
            return false;
          }
        }
      }
      if (filter->timeline_set) {
        std::string event_type = event.value("type", "");
        std::string sender = event.value("sender", "");
        std::string room_id = event.value("room_id", "");
        bool has_url = check_url_present(event);
        if (!filter->timeline.matches_event(event_type, sender, room_id,
                                            has_url)) {
          return false;
        }
      }
    }
    return true;
  }

  // Clear all filters
  void clear() { filters_.clear(); }

  // Get filter count
  size_t size() const { return filters_.size(); }

private:
  static bool check_url_present(const json& event) {
    if (!event.contains("content") || !event["content"].is_object())
      return false;
    const auto& content = event["content"];
    for (const auto& field :
         {"url", "avatar_url", "thumbnail_url", "external_url"}) {
      if (content.contains(field) && content[field].is_string()) {
        std::string val = content[field].get<std::string>();
        if (val.find("http://") == 0 || val.find("https://") == 0 ||
            val.find("mxc://") == 0)
          return true;
      }
    }
    return false;
  }

  std::vector<std::shared_ptr<CompiledFilter>> filters_;
};

// ============================================================================
// Unified filter API (the main interface for the server)
// ============================================================================

class FilterAPI {
public:
  FilterAPI() : engine_(GlobalFilterEngine::instance()) {}

  // --- User filter CRUD ---

  json handle_create_filter(const std::string& user_id,
                              const json& filter_json) {
    auto [filter_id, error] = engine_.create_user_filter(user_id, filter_json);
    if (error.has_value()) return *error;

    json response;
    response["filter_id"] = *filter_id;
    return response;
  }

  json handle_get_filter(const std::string& user_id,
                          const std::string& filter_id) {
    auto [filter, error] = engine_.get_user_filter(user_id, filter_id);
    if (error.has_value()) return *error;
    return *filter;
  }

  json handle_get_all_filters(const std::string& user_id) {
    auto [result, error] = engine_.get_all_user_filters(user_id);
    if (error.has_value()) return *error;
    return result;
  }

  json handle_update_filter(const std::string& user_id,
                              const std::string& filter_id,
                              const json& filter_json) {
    auto error = engine_.update_user_filter(user_id, filter_id, filter_json);
    if (error.has_value()) return *error;

    json response;
    response["status"] = "ok";
    return response;
  }

  json handle_delete_filter(const std::string& user_id,
                              const std::string& filter_id) {
    auto error = engine_.delete_user_filter(user_id, filter_id);
    if (error.has_value()) return *error;

    json response;
    response["status"] = "ok";
    return response;
  }

  // --- Filter application ---

  json apply_filter(const std::string& filter_id,
                     const json& events,
                     const std::string& category = "timeline") {
    if (category == "timeline") {
      return engine_.apply_filter_to_timeline(filter_id, events);
    } else if (category == "state") {
      return engine_.apply_filter_to_state(filter_id, events);
    } else if (category == "ephemeral") {
      return engine_.apply_filter_to_ephemeral(filter_id, events);
    } else if (category == "account_data") {
      return engine_.apply_filter_to_account_data(filter_id, events);
    } else if (category == "presence") {
      return engine_.apply_filter_to_presence(filter_id, events);
    }
    return events;
  }

  // --- Lazy loading ---

  json filter_lazy_loaded_members(const std::string& filter_id,
                                    const json& members,
                                    const json& timeline_events,
                                    const std::string& current_user_id) {
    return engine_.filter_lazy_loaded_members(
        filter_id, members, timeline_events, current_user_id);
  }

  // --- Push rules ---

  std::vector<PushRuleFilterEngine::PushRuleMatch>
  evaluate_push_rules(const std::string& filter_id,
                       const json& event,
                       const std::string& display_name = "") {
    return engine_.evaluate_push_rules_for_event(
        filter_id, event, display_name);
  }

  PushRuleFilterEngine::FinalPushAction
  get_final_push_action(const std::string& filter_id,
                         const json& event,
                         const std::string& display_name = "") {
    return engine_.determine_push_action(filter_id, event, display_name);
  }

  // --- Search ---

  json search_events(const json& events, const json& search_filter) {
    return engine_.search_events_with_json_filter(events, search_filter);
  }

  // --- Validate ---

  std::optional<json> validate_filter(const json& filter_json,
                                       const std::string& user_id = "") {
    return engine_.validate_filter_json(filter_json, user_id);
  }

  // --- Admin ---

  json admin_get_all_filters() { return engine_.admin_get_all_filters(); }
  json admin_get_filter_stats() { return engine_.admin_get_filter_stats(); }
  json admin_delete_user_filters(const std::string& user_id) {
    return engine_.admin_delete_user_filters(user_id);
  }
  json admin_purge_cache() { return engine_.admin_purge_cache(); }
  json admin_get_filter_by_id(const std::string& filter_id) {
    return engine_.admin_get_filter_by_id(filter_id);
  }

  // --- Cache ---
  void invalidate_cache(const std::string& filter_id) {
    engine_.invalidate_cache(filter_id);
  }
  void clear_cache() { engine_.clear_cache(); }

  // --- Default push rules ---
  std::vector<CompiledPushRule> get_default_push_rules() {
    return DefaultFilters::get_default_push_rules();
  }

private:
  FilterEngine& engine_;
};

// ============================================================================
// Filter migration utilities
// ============================================================================

class FilterMigration {
public:
  // Migrate filter from old format to new format
  static json migrate_filter(const json& old_filter) {
    json result = old_filter;

    // Normalize room.timeline structure
    if (result.contains("timeline") && !result.contains("room")) {
      json room = json::object();
      room["timeline"] = result["timeline"];
      result.erase("timeline");
      result["room"] = room;
    }

    // Ensure types arrays are present
    if (result.contains("room")) {
      json& room = result["room"];
      for (const auto& sub_filter : {"timeline", "state", "ephemeral"}) {
        if (room.contains(sub_filter) && room[sub_filter].is_object()) {
          json& sf = room[sub_filter];
          if (!sf.contains("types")) sf["types"] = json::array();
          if (!sf.contains("not_types")) sf["not_types"] = json::array();
          if (!sf.contains("senders")) sf["senders"] = json::array();
          if (!sf.contains("not_senders")) sf["not_senders"] = json::array();
        }
      }
      if (room.contains("account_data") && room["account_data"].is_object()) {
        json& ad = room["account_data"];
        if (!ad.contains("types")) ad["types"] = json::array();
        if (!ad.contains("not_types")) ad["not_types"] = json::array();
      }
    }

    return result;
  }

  // Convert old-style event_fields to new format
  static json migrate_event_fields(const json& old_filter) {
    json result = old_filter;
    if (result.contains("event_fields") && result["event_fields"].is_array()) {
      // Old format: ["content.body", "type"]
      // New format: [["content.body", "type"]]
      if (!result["event_fields"].empty()) {
        const auto& first = result["event_fields"][0];
        if (first.is_string()) {
          // Wrap in array
          json wrapped = json::array();
          wrapped.push_back(result["event_fields"]);
          result["event_fields"] = wrapped;
        }
      }
    }
    return result;
  }

  // Check if filter needs migration
  static bool needs_migration(const json& filter) {
    // Check for old timeline format
    if (filter.contains("timeline") && !filter.contains("room")) {
      return true;
    }
    // Check for old event_fields format
    if (filter.contains("event_fields") && filter["event_fields"].is_array() &&
        !filter["event_fields"].empty()) {
      const auto& first = filter["event_fields"][0];
      if (first.is_string()) return true;
    }
    return false;
  }
};

// ============================================================================
// Filter statistics and monitoring
// ============================================================================

class FilterStatistics {
public:
  FilterStatistics() = default;

  void record_filter_created(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    total_created_++;
    user_filter_counts_[user_id]++;
  }

  void record_filter_deleted(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    total_deleted_++;
    if (user_filter_counts_[user_id] > 0) user_filter_counts_[user_id]--;
  }

  void record_filter_applied() {
    total_applied_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_cache_hit() {
    cache_hits_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_cache_miss() {
    cache_misses_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_push_rule_evaluated() {
    push_rules_evaluated_.fetch_add(1, std::memory_order_relaxed);
  }

  json get_stats() const {
    json stats;
    stats["total_created"] = total_created_;
    stats["total_deleted"] = total_deleted_;
    stats["total_applied"] = total_applied_.load();
    stats["cache_hits"] = cache_hits_.load();
    stats["cache_misses"] = cache_misses_.load();
    stats["push_rules_evaluated"] = push_rules_evaluated_.load();
    stats["active_users"] = user_filter_counts_.size();

    double hit_ratio = 0.0;
    uint64_t total = cache_hits_.load() + cache_misses_.load();
    if (total > 0) {
      hit_ratio = static_cast<double>(cache_hits_.load()) /
                  static_cast<double>(total);
    }
    stats["cache_hit_ratio"] = hit_ratio;

    return stats;
  }

  void reset() {
    std::lock_guard lock(mutex_);
    total_created_ = 0;
    total_deleted_ = 0;
    total_applied_ = 0;
    cache_hits_ = 0;
    cache_misses_ = 0;
    push_rules_evaluated_ = 0;
    user_filter_counts_.clear();
  }

private:
  mutable std::mutex mutex_;
  int64_t total_created_ = 0;
  int64_t total_deleted_ = 0;
  std::atomic<int64_t> total_applied_{0};
  std::atomic<int64_t> cache_hits_{0};
  std::atomic<int64_t> cache_misses_{0};
  std::atomic<int64_t> push_rules_evaluated_{0};
  std::map<std::string, int> user_filter_counts_;
} g_filter_statistics;

// ============================================================================
// Async filter operations (for use with worker threads)
// ============================================================================

class AsyncFilterProcessor {
public:
  using FilterCallback =
      std::function<void(const json& filtered_events, bool success)>;

  AsyncFilterProcessor() : running_(true) {
    worker_ = std::thread([this]() { worker_loop(); });
  }

  ~AsyncFilterProcessor() {
    running_ = false;
    if (worker_.joinable()) worker_.join();
  }

  // Submit a filter operation to be processed asynchronously
  void async_apply_filter(const std::string& filter_id,
                           const json& events,
                           FilterCallback callback) {
    std::lock_guard lock(mutex_);
    queue_.push_back({filter_id, events, std::move(callback), "apply"});
    cv_.notify_one();
  }

  // Submit a validation operation
  void async_validate_filter(const json& filter_json,
                               FilterCallback callback) {
    std::lock_guard lock(mutex_);
    queue_.push_back({"", filter_json, std::move(callback), "validate"});
    cv_.notify_one();
  }

  // Get pending task count
  size_t pending_count() const {
    std::lock_guard lock(mutex_);
    return queue_.size();
  }

private:
  struct Task {
    std::string filter_id;
    json events;
    FilterCallback callback;
    std::string operation;
  };

  void worker_loop() {
    FilterAPI api;
    while (running_) {
      Task task;
      {
        std::unique_lock lock(mutex_);
        cv_.wait(lock, [this]() { return !queue_.empty() || !running_; });
        if (!running_ && queue_.empty()) return;
        task = std::move(queue_.front());
        queue_.pop_front();
      }

      try {
        if (task.operation == "apply") {
          json filtered = api.apply_filter(task.filter_id, task.events);
          if (task.callback) task.callback(filtered, true);
        } else if (task.operation == "validate") {
          auto err = api.validate_filter(task.events);
          if (err.has_value()) {
            if (task.callback) task.callback(*err, false);
          } else {
            if (task.callback) task.callback(json::object(), true);
          }
        }
      } catch (const std::exception& e) {
        json error;
        error["error"] = e.what();
        if (task.callback) task.callback(error, false);
      }
    }
  }

  std::thread worker_;
  std::atomic<bool> running_;
  mutable std::mutex mutex_;
  std::condition_variable cv_;
  std::deque<Task> queue_;
};

// ============================================================================
// End of namespace
// ============================================================================

}  // namespace progressive::filters
